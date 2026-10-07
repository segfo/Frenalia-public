//! [決定68] Spawn Daemon が**許可して起こした生成の記録**（`spawn-audit.jsonl`）の書き手
//! （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2「許可した生成の記録」。行の形と読み方は`harness_policy::spawn_audit`）。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタのパス2で断られたファイル操作を、操作したプロセスを Daemon が起こしたドメインへ振り分けるため
//! （決定68の前例の(1)）。Daemon は子を起こすたびに（通し番号, ドメイン）を1行書く。
//!
//! # パスを受け取らない
//!
//! Hello が運ぶのは**記録のディレクトリの名前**（パスの1要素）だけで、置き場は`workspace_root`から組み立てる
//! （`<workspace_root>\.harness\sandbox\<名前>\spawn-audit.jsonl`。拒否の待ち行列が`workspace_root`から導くのと同じ作法、§10.2）。
//! 名前に区切りや`.`で始まる綴りがあれば断る（[`record_dir_name_problem`]）。**ファイルは作らない**——在るファイルにしか
//! 追記しない（作るのはホスト。`process-audit.jsonl`の BUG-109 の作法と同じで、書き手にファイルを作らせない）。
//!
//! # 記録は境界ではない
//!
//! 書けなくても生成の可否は1ビットも変えない（`P-07`）。ただし黙らせない——Daemon の標準エラーへ出す。
//! 通し番号を取れなかった子は欄を空のまま書く（読む側はその子の拒否を「どのドメインにも引けない」として数える）。
//!
//! # 限界
//!
//! - `harness.exe`の Daemon は名前を送らないので何も書かない（決定68の前例の(4)。暫定）。
//! - 通し番号は`NtQueryInformationProcess`（情報クラス`ProcessSequenceNumber`＝92）で取る。ETW の値との一致を測ったのは
//!   試験プロセス自身の値だけで（決定65の追記）、Daemon が起こした子の値は P6 の昇格E2Eで測る。

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use harness_policy::spawn_audit::{
    SpawnAuditRecord, SPAWN_AUDIT_FILE, SPAWN_AUDIT_MAX_LINES, SPAWN_AUDIT_SCHEMA_VERSION,
};
use windows::Win32::Foundation::HANDLE;

/// 記録のディレクトリの名前として受け付けない理由（受け付けるなら`None`）。純粋な関数。
///
/// 名前はパスの1要素でなければならない——区切り（`\` `/`）・ドライブの`:`・制御文字を含む名前、`.`で始まる名前
/// （`..`を含む）、空の名前は断る。断らないと、ホストが指定した任意の場所へ Daemon が追記できる。
pub(crate) fn record_dir_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("the name is empty");
    }
    if name.starts_with('.') {
        return Some("the name starts with a dot");
    }
    if name
        .chars()
        .any(|c| matches!(c, '\\' | '/' | ':') || c.is_control())
    {
        return Some("the name contains a path separator, a drive colon or a control character");
    }
    None
}

/// Daemon の書き手。`Shared`が1つ持つ。
pub(super) struct SpawnAudit {
    /// 置き場。**`None`なら何も書かない**（Hello が名前を運ばなかった）。
    sink: Option<PathBuf>,
    max_lines: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    written: usize,
    dropped: u64,
}

impl SpawnAudit {
    /// 記録を開く。`record`が`None`なら何もしない書き手を返す。名前が不正・ファイルが無いなら`Err`——Hello ごと失敗させる
    /// （記録を頼まれたのに書けない状態で走らない。`B-10`）。開けたら版の行を1行書く。
    pub(super) fn open(workspace_root: &str, record: Option<&str>) -> Result<Self, String> {
        Self::open_with_limit(workspace_root, record, SPAWN_AUDIT_MAX_LINES)
    }

    pub(super) fn open_with_limit(
        workspace_root: &str,
        record: Option<&str>,
        max_lines: usize,
    ) -> Result<Self, String> {
        let Some(record) = record else {
            return Ok(Self {
                sink: None,
                max_lines,
                state: Mutex::default(),
            });
        };
        if let Some(problem) = record_dir_name_problem(record) {
            return Err(format!(
                "refusing the spawn audit record name {record:?}: {problem}"
            ));
        }
        let path = Path::new(workspace_root)
            .join(".harness")
            .join("sandbox")
            .join(record)
            .join(SPAWN_AUDIT_FILE);
        if !path.is_file() {
            return Err(format!(
                "the spawn audit {} does not exist (the host creates it before asking; the daemon \
                 does not create files)",
                path.display()
            ));
        }
        let audit = Self {
            sink: Some(path),
            max_lines,
            state: Mutex::default(),
        };
        audit.append(&SpawnAuditRecord::Header {
            schema_version: SPAWN_AUDIT_SCHEMA_VERSION,
        })?;
        Ok(audit)
    }

    /// 起こした子1人を書く。**Resume より前**（子がファイルに触る前）に呼ぶ。
    pub(super) fn spawned(&self, pid: u32, process: HANDLE, domain: &str, exe: &str, top_level: bool) {
        if self.sink.is_none() {
            return;
        }
        let seq = match process_sequence_number(process) {
            Ok(seq) => Some(seq),
            Err(e) => {
                eprintln!("[spawnd] could not read the sequence number of pid {pid}: {e}");
                None
            }
        };
        self.spawned_with(pid, seq, domain, exe, top_level);
    }

    /// [`Self::spawned`]の通し番号を取った後の部分（試験はここを測る）。
    pub(super) fn spawned_with(
        &self,
        pid: u32,
        process_sequence_number: Option<u64>,
        domain: &str,
        exe: &str,
        top_level: bool,
    ) {
        self.record(SpawnAuditRecord::Spawned {
            ts_unix_ms: now_unix_ms(),
            pid,
            process_sequence_number,
            domain: domain.to_string(),
            exe: exe.to_string(),
            top_level,
        });
    }

    /// コンソールの保持プロセスを立て直した（§7.1.2 決定4）。
    pub(super) fn console_holder_restarted(
        &self,
        domain: &str,
        old_pid: u32,
        old_exit_code: Option<u32>,
        new_pid: u32,
    ) {
        self.record(SpawnAuditRecord::ConsoleHolderRestarted {
            ts_unix_ms: now_unix_ms(),
            domain: domain.to_string(),
            old_pid,
            old_exit_code,
            new_pid,
        });
    }

    /// Daemon が畳むときに呼ぶ。上限を超えて書かなかった行があれば、その数を1行書く（2回呼んでも1回だけ）。
    pub(super) fn finish(&self) {
        let dropped = match self.state.lock() {
            Ok(mut state) => std::mem::take(&mut state.dropped),
            Err(_) => return,
        };
        if dropped == 0 {
            return;
        }
        if let Err(e) = self.append(&SpawnAuditRecord::Overflow {
            ts_unix_ms: now_unix_ms(),
            dropped,
        }) {
            eprintln!("[spawnd] {e}");
        }
    }

    fn record(&self, record: SpawnAuditRecord) {
        if self.sink.is_none() {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.written >= self.max_lines {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }
        match self.append(&record) {
            Ok(()) => state.written += 1,
            Err(e) => eprintln!("[spawnd] {e}"),
        }
    }

    fn append(&self, record: &SpawnAuditRecord) -> Result<(), String> {
        let Some(path) = self.sink.as_ref() else {
            return Ok(());
        };
        let line = record
            .to_jsonl_line()
            .map_err(|e| format!("could not serialize a spawn audit line: {e}"))?;
        // **在るファイルにだけ追記する**（`create(false)`）。消されていたら書かずに理由を出す。
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| format!("could not open the spawn audit {}: {e}", path.display()))?;
        writeln!(file, "{line}")
            .map_err(|e| format!("could not append to the spawn audit {}: {e}", path.display()))
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    u32,
    *mut core::ffi::c_void,
    u32,
    *mut u32,
) -> i32;

/// プロセスの`ProcessSequenceNumber`（`NtQueryInformationProcess`の情報クラス92）。
///
/// P1 の測定の試験（`d628838`で消した`policy_learnd/etw/process_lineage_spike_tests.rs`の`own_sequence_number`）を
/// **そのまま写した**——ntdll から`GetProcAddress`で引く（`windows`クレートの`Wdk_System_Threading`機能をこのためだけに
/// 足さない）。あちらは自分のプロセスに使い、ETW の値と 621/621 一致した（決定65の追記）。
pub(crate) fn process_sequence_number(process: HANDLE) -> Result<u64, String> {
    use windows::core::{s, w};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    const PROCESS_SEQUENCE_NUMBER: u32 = 92;

    let query_fn: NtQueryInformationProcessFn = unsafe {
        match GetModuleHandleW(w!("ntdll.dll")) {
            Err(error) => return Err(format!("GetModuleHandleW(ntdll.dll): {error}")),
            Ok(ntdll) => match GetProcAddress(ntdll, s!("NtQueryInformationProcess")) {
                None => return Err("GetProcAddress(NtQueryInformationProcess) returned NULL".into()),
                Some(address) => std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    NtQueryInformationProcessFn,
                >(address),
            },
        }
    };
    let mut value = 0u64;
    let mut returned = 0u32;
    let status = unsafe {
        query_fn(
            process,
            PROCESS_SEQUENCE_NUMBER,
            &mut value as *mut u64 as *mut core::ffi::c_void,
            std::mem::size_of::<u64>() as u32,
            &mut returned,
        )
    };
    if status >= 0 {
        Ok(value)
    } else {
        Err(format!("NTSTATUS {status:#010x}"))
    }
}

#[cfg(test)]
#[path = "spawn_audit_tests.rs"]
mod spawn_audit_tests;
