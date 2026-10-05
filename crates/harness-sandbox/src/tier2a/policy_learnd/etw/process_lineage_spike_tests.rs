//! **親の通し番号（`ParentProcessSequenceNumber`）は親を指すかの実測スパイク**
//! （ポリシーエディタの決定65、`plans/PLAN-POLICY-EDITOR-POSITION-DOMAINS.md` P1b）。
//!
//! 決定65は、記録したプロセスの木の「位置」ごとに別のドメインを割り当てる。深さを組むには
//! 「この子の親はどのプロセスか」を、使い回されない通し番号で引く必要がある。
//! `Microsoft-Windows-Kernel-Process`の`ProcessStart`（v3以降）は`ProcessSequenceNumber`
//! （`plans/etw-spike/RESULTS.md` §23.1で601件すべて一意・時刻に単調と確定）に加えて
//! `ParentProcessSequenceNumber`の欄を持つ（`Get-WinEvent -ListProvider`のテンプレート）。
//! **この欄はこのリポジトリで一度も読まれておらず、実機で値が入るか・親自身の番号と一致するかを
//! 測った記録が無い。** pidで親を引くと、pidが使い回されたときに別の親を指す（`B-17`の型）。
//!
//! # 測るもの（判定の規則は走らせる前に`plans/etw-spike/RESULTS.md` §24.2へ書いた）
//!
//! | 項目 | 問い |
//! |---|---|
//! | A1 | 目印つきの`cmd /c cmd /c cmd /c cmd /c echo <目印>`の各段で、子の欄が親の段の番号と一致するか |
//! | A2 | 試験プロセス自身が直接起こした子の欄が、試験プロセス自身の番号と一致するか |
//! | A3 | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`で別の親を指定した起動で、`ParentProcessID`と欄に入るのは作った側か指定した側か（対照。採否を変えない） |
//! | A4 | 600組の短命な親子（`cmd /c cmd /c rem <目印>`）でpidが使い回される中、欄で引いた親とpidで引いた親が、本当の親とそれぞれ何件食い違うか |
//! | A5 | `ProcessStop`（event id 2）に`ProcessSequenceNumber`が入り、開始の番号と一致するか |
//! | A6 | 同じプロセスについて、2つの購読（マニフェスト／MOF）の通知の時刻差の分布 |
//!
//! # 計器の検算（§18.5・§21.4の規律）
//!
//! - **2つの購読を同時に張り、同じプロセスを両方で観測する。** 連鎖の先頭（このテストが起こし、
//!   pidを自分で知っているプロセス）を、MOF側はコマンドラインの目印で・マニフェスト側はpidで
//!   見たことを`assert`する。見ていなければ、以降の数字は「測れていない」であって結論ではない
//! - 「取れなかった」の3つの意味（通知が来ない／欄の無い版が届いた／欄が0）を分けて印字する
//! - **本当の親は、欄ともpidとも独立に決める**——A4の組の番号はMOF側のコマンドラインの目印から取る。
//!   欄の正しさを欄で確かめない（`measurement-review`の検問10: 同じ源から出た2つは突き合わせにならない）。
//!   MOFの各件をマニフェストの開始へ結び付けるのも「pidが同じで時刻が最も近い1件」であって、欄は使わない
//! - 撤収: 最後に`logman query -ets`で自分の接頭辞（[`SESSION_PREFIX`]）のセッションが0件であることを
//!   `assert`する——外部コマンドの見た目の成功を信用しない（`logger_slot_spike_tests`と同じ形）
//!
//! マニフェスト側に本番の`EtwFsSession`を使わないのは、本番の構造体（`session::ProcessStartInfo`）に
//! 親の番号の欄が無く、`session.rs`は本体が1,000行を超えているので欄を足せないためである。
//! [`ProviderProbeSession`]は任意のプロパティを名前で引け、イベントのタイムスタンプも持つ（A6に要る）。
//! セッションの種類（通常のリアルタイムセッション）は`EtwFsSession`と同じである。
//!
//! 実行には管理者権限が要る（ETWリアルタイムセッション＋private system logger）。
//! 昇格キーは`spike-etw-process-lineage`（`KNOWN_TARGETS`）。**キーのフィルタはこのモジュールのパス
//! `policy_learnd::etw::process_lineage_spike_tests`と一致していなければならない**（ずれるとBUG-056と同じ
//! 「0件マッチ」になる）。
//!
//! 使い捨てスパイクの位置付け（`docs/CODE-STRUCTURE-RULES.md`規則2）——P2で収集プロセスが
//! プロセスの木を書くところまで済んだら（作業の一覧のP2f）、このファイルとキーを消し、
//! 実測値は`plans/etw-spike/RESULTS.md` §24（測定の正本）へ残す。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::mof::{MofFsSession, MofProcessStart, EVENT_TYPE_PROCESS_START};
use super::session::{
    ProbedEvent, ProviderProbeSession, EVENT_ID_PROCESS_START, KERNEL_PROCESS_KEYWORD_PROCESS,
    KERNEL_PROCESS_PROVIDER_GUID,
};

/// A1の連鎖の本数。
const CHAINS: usize = 20;
/// A1の連鎖の段数（`cmd /c cmd /c cmd /c cmd /c echo <目印>`＝4段）。
const CHAIN_DEPTH: usize = 4;
/// A4の短命な親子の組の数（`argv_capture_spike_tests`の`SHORT_LIVED_BATCH`と同じ数。§23.1では
/// この本数でpidの使い回しが実際に起きた）。
const PAIRS: usize = 600;

/// セッションを張ってから配送が始まるまでの待ち（既存スパイクの実測値と同じ）。
const WARMUP: Duration = Duration::from_millis(1500);
/// 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上）。
const DRAIN: Duration = Duration::from_secs(4);

/// 自分が張ったセッションだけを識別するための接頭辞（撤収の確認に使う）。
const SESSION_PREFIX: &str = "harness-lineage-spike-";
/// `Microsoft-Windows-Kernel-Process`の`ProcessStop`のevent id（v2以降に`ProcessSequenceNumber`）。
/// `session.rs`は`ProcessStart`の定数しか持たないので、測定側でだけ持つ。
const EVENT_ID_PROCESS_STOP: u16 = 2;
/// MOFの1件をマニフェストへ結び付けるとき、**候補が何件あったか**を数える範囲。結び付け自体は
/// 「時刻が最も近い1件」であり、この範囲は曖昧さ（A6の窓の幅を決める材料）を数えるためだけに使う。
const JOIN_PROBE_WINDOW_MS: u64 = 1_000;

/// マニフェスト側の`ProcessStart`1件（[`ProbedEvent`]から要る欄だけ抜いたもの）。
#[derive(Debug, Clone)]
struct ManifestStart {
    /// コールバックが貯めた順（＝届いた順）。「その時点で見えていた表」でpidを引く再現に使う。
    order: usize,
    version: u8,
    /// ETWヘッダのpid＝この通知を出した側（A3で「作った側」かを見る）。
    header_pid: u32,
    ts_ms: u64,
    pid: u32,
    parent_pid: Option<u32>,
    seq: Option<u64>,
    /// **測る欄。**
    parent_seq: Option<u64>,
    image: Option<String>,
}

/// マニフェスト側の`ProcessStop`1件。
#[derive(Debug, Clone)]
struct ManifestStop {
    version: u8,
    ts_ms: u64,
    pid: Option<u32>,
    seq: Option<u64>,
}

/// 届いた順のまま開始と終了に分ける。3つ目の戻り値は`ProcessID`を引けなかった開始の件数。
fn split_manifest(events: &[ProbedEvent]) -> (Vec<ManifestStart>, Vec<ManifestStop>, u64) {
    let mut starts = Vec::new();
    let mut stops = Vec::new();
    let mut starts_without_pid = 0u64;
    for (order, event) in events.iter().enumerate() {
        let number = |name: &str| event.numbers.get(name).copied();
        match event.event_id {
            EVENT_ID_PROCESS_START => match number("ProcessID") {
                Some(pid) => starts.push(ManifestStart {
                    order,
                    version: event.version,
                    header_pid: event.process_id,
                    ts_ms: event.timestamp_unix_ms,
                    pid: pid as u32,
                    parent_pid: number("ParentProcessID").map(|v| v as u32),
                    seq: number("ProcessSequenceNumber"),
                    parent_seq: number("ParentProcessSequenceNumber"),
                    image: event.strings.get("ImageName").cloned(),
                }),
                None => starts_without_pid += 1,
            },
            EVENT_ID_PROCESS_STOP => stops.push(ManifestStop {
                version: event.version,
                ts_ms: event.timestamp_unix_ms,
                pid: number("ProcessID").map(|v| v as u32),
                seq: number("ProcessSequenceNumber"),
            }),
            _ => {}
        }
    }
    (starts, stops, starts_without_pid)
}

/// MOFの1件とマニフェストの開始1件の結び付け。
#[derive(Debug, Clone, Copy)]
struct Join {
    /// `starts`の添字。
    manifest: usize,
    /// マニフェスト − MOF（ms）。
    dt_ms: i64,
    /// 同じpidで[`JOIN_PROBE_WINDOW_MS`]以内にあった候補の数（1なら曖昧さなし）。
    candidates: usize,
}

/// MOFの実起動1件を、マニフェストの開始へ結び付ける——**pidが同じで時刻が最も近い1件**。
/// 欄（`ParentProcessSequenceNumber`）は使わない（モジュールdocの「独立に決める」）。
fn join(
    mof: &MofProcessStart,
    by_pid: &HashMap<u32, Vec<usize>>,
    starts: &[ManifestStart],
) -> Option<Join> {
    let pid = mof.pid?;
    let mut best: Option<(usize, i64)> = None;
    let mut candidates = 0usize;
    for &index in by_pid.get(&pid)? {
        let dt = starts[index].ts_ms as i64 - mof.timestamp_unix_ms as i64;
        if dt.unsigned_abs() <= JOIN_PROBE_WINDOW_MS {
            candidates += 1;
        }
        if best.is_none_or(|(_, b)| dt.abs() < b.abs()) {
            best = Some((index, dt));
        }
    }
    let (manifest, dt_ms) = best?;
    Some(Join {
        manifest,
        dt_ms,
        candidates,
    })
}

/// `<tag><width桁の数字>`の数字を返す（目印の組番号・連鎖番号）。
fn tagged_index(command_line: &str, tag: &str, width: usize) -> Option<usize> {
    let start = command_line.find(tag)? + tag.len();
    command_line.get(start..start + width)?.parse().ok()
}

/// コマンドラインに含まれる`/c`の数。連鎖の段は「残っている`/c`の数」で決まる
/// （1段目は4つ、cmdが渡す2段目は3つ……）。目印・パスに`/c`は含まれない。
fn slash_c_count(command_line: &str) -> usize {
    command_line.to_ascii_lowercase().matches("/c").count()
}

/// 欄（または欄に相当する値）が、期待する値と何件一致したか。
#[derive(Debug, Default)]
struct LinkTally {
    matched: usize,
    mismatched: usize,
    /// 欄そのものが引けなかった（欄の無い版／プロパティが無い）。
    missing: usize,
    /// 欄はあるが0。
    zero: usize,
    /// 比べる相手（親の番号）の側が取れなかった。
    reference_missing: usize,
    /// MOFでは見つけたがマニフェストへ結び付かなかった（分母から外した件数）。
    unjoined: usize,
}

impl LinkTally {
    fn record(&mut self, field: Option<u64>, expected: Option<u64>) {
        let Some(expected) = expected else {
            self.reference_missing += 1;
            return;
        };
        match field {
            None => self.missing += 1,
            Some(0) => self.zero += 1,
            Some(value) if value == expected => self.matched += 1,
            Some(_) => self.mismatched += 1,
        }
    }

    fn compared(&self) -> usize {
        self.matched + self.mismatched + self.missing + self.zero
    }

    fn all_matched(&self) -> bool {
        self.compared() > 0 && self.matched == self.compared() && self.reference_missing == 0
    }

    fn render(&self) -> String {
        format!(
            "match {} / mismatch {} / field missing {} / field 0 {} (compared {}; reference missing {}; not joined {})",
            self.matched,
            self.mismatched,
            self.missing,
            self.zero,
            self.compared(),
            self.reference_missing,
            self.unjoined,
        )
    }
}

/// pidで親を引いた結果が、本当の親と何件一致したか。
#[derive(Debug, Default)]
struct PidTally {
    correct: usize,
    wrong: usize,
    /// 引いても何も見つからなかった。
    none: usize,
    /// 候補が2つ以上で決められなかった（時間窓の引き方だけが返す）。
    ambiguous: usize,
}

impl PidTally {
    fn record(&mut self, found: Option<Option<u64>>, truth: Option<u64>) {
        match found {
            None => self.none += 1,
            Some(seq) if seq.is_some() && seq == truth => self.correct += 1,
            Some(_) => self.wrong += 1,
        }
    }

    fn render(&self) -> String {
        format!(
            "correct {} / wrong {} / not found {} / ambiguous {}",
            self.correct, self.wrong, self.none, self.ambiguous
        )
    }
}

/// 時間窓つきのpid引き: 子の`ParentProcessID`と同じpidで、**子の開始より前に始まり、子の開始時点で
/// まだ終わっていない**（終了が子の開始以後か、終了の通知が無い）開始を候補にする。
/// 終了は`ProcessSequenceNumber`で開始へ結び付ける（A5が成り立つ前提。成り立たなければ終了で
/// 窓を閉じられず、候補が増えて`ambiguous`に出る）。
enum WindowLookup {
    Resolved(Option<u64>),
    NoCandidate,
    Ambiguous,
}

fn window_lookup(
    child: &ManifestStart,
    starts: &[ManifestStart],
    by_pid: &HashMap<u32, Vec<usize>>,
    stop_ts_by_seq: &HashMap<u64, u64>,
) -> WindowLookup {
    let Some(parent_pid) = child.parent_pid else {
        return WindowLookup::NoCandidate;
    };
    let candidates: Vec<&ManifestStart> = by_pid
        .get(&parent_pid)
        .into_iter()
        .flatten()
        .map(|&index| &starts[index])
        .filter(|start| start.ts_ms <= child.ts_ms && start.order != child.order)
        .filter(
            |start| match start.seq.and_then(|seq| stop_ts_by_seq.get(&seq)) {
                Some(&stopped) => stopped >= child.ts_ms,
                None => true,
            },
        )
        .collect();
    match candidates.as_slice() {
        [] => WindowLookup::NoCandidate,
        [only] => WindowLookup::Resolved(only.seq),
        _ => WindowLookup::Ambiguous,
    }
}

/// 試験プロセス自身の`ProcessSequenceNumber`。**2つの別の口で取る**——片方だけでは、
/// 情報クラスの番号や構造体の配置を取り違えていても気付けない（検問10）。
struct OwnSequence {
    /// `NtQueryInformationProcess(ProcessSequenceNumber = 92)`。
    query: Result<u64, String>,
    /// `NtQueryInformationProcess(ProcessTelemetryIdInformation = 64)`の（ProcessId, ProcessSequenceNumber）。
    /// ProcessIdが自分のpidと一致することが、構造体の配置を読み違えていない検算になる。
    telemetry: Result<(u32, u64), String>,
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    windows::Win32::Foundation::HANDLE,
    u32,
    *mut core::ffi::c_void,
    u32,
    *mut u32,
) -> i32;

/// ntdllから`NtQueryInformationProcess`を引いて自身の番号を取る（`windows`クレートの
/// `Wdk_System_Threading`機能をこの測定のためだけに足さないよう、`GetProcAddress`で引く）。
fn own_sequence_number() -> OwnSequence {
    use windows::core::{s, w};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Threading::GetCurrentProcess;

    const PROCESS_TELEMETRY_ID_INFORMATION: u32 = 64;
    const PROCESS_SEQUENCE_NUMBER: u32 = 92;

    let resolved: Result<NtQueryInformationProcessFn, String> = unsafe {
        match GetModuleHandleW(w!("ntdll.dll")) {
            Err(error) => Err(format!("GetModuleHandleW(ntdll.dll): {error}")),
            Ok(ntdll) => match GetProcAddress(ntdll, s!("NtQueryInformationProcess")) {
                None => Err("GetProcAddress(NtQueryInformationProcess) returned NULL".into()),
                Some(address) => Ok(std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    NtQueryInformationProcessFn,
                >(address)),
            },
        }
    };
    let query_fn = match resolved {
        Ok(function) => function,
        Err(error) => {
            return OwnSequence {
                query: Err(error.clone()),
                telemetry: Err(error),
            }
        }
    };
    let process = unsafe { GetCurrentProcess() };

    let query = {
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
    };

    // PROCESS_TELEMETRY_ID_INFORMATION: HeaderSize(u32) ProcessId(u32) ProcessStartKey(u64)
    // CreateTime(u64) CreateInterruptTime(u64) CreateUnbiasedInterruptTime(u64)
    // ProcessSequenceNumber(u64) ... の後ろに可変長の文字列が続く。u64の配列で受けて8バイト境界に揃える。
    let telemetry = {
        let mut buffer = vec![0u64; 1024];
        let mut returned = 0u32;
        let status = unsafe {
            query_fn(
                process,
                PROCESS_TELEMETRY_ID_INFORMATION,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                (buffer.len() * std::mem::size_of::<u64>()) as u32,
                &mut returned,
            )
        };
        if status >= 0 {
            Ok(((buffer[0] >> 32) as u32, buffer[5]))
        } else {
            Err(format!("NTSTATUS {status:#010x} (returned length {returned})"))
        }
    };
    OwnSequence { query, telemetry }
}

/// A3: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`で`parent`を親に指定して`cmd.exe /c echo <marker>`を起こし、
/// 終わるまで待ってpidを返す。
///
/// 属性リストの組み方は`win_appcontainer/mac_spike_tests.rs`の`spawn_suspended`と同じ順
/// （サイズを問う→初期化→`UpdateProcThreadAttribute`→`CreateProcessW`→`DeleteProcThreadAttributeList`）。
/// リポジトリにPARENT_PROCESSを使う既存のコードは無い。**値（親のハンドル）は`CreateProcessW`が返るまで
/// 生かしておく**——`UpdateProcThreadAttribute`はポインタを覚えるだけで中身を写さない。
fn spawn_with_designated_parent(
    parent: &std::process::Child,
    marker: &str,
) -> Result<u32, String> {
    use std::os::windows::io::AsRawHandle;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTUPINFOEXW, STARTUPINFOW,
    };

    let step = |label: &str, error: windows::core::Error| format!("{label}: {error}");
    let mut parent_handle = HANDLE(parent.as_raw_handle());
    let mut command_line =
        crate::win_common::wide(&format!(r#""C:\Windows\System32\cmd.exe" /c echo {marker}"#));

    unsafe {
        let mut size: usize = 0;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut size,
        );
        let mut list_buffer = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(list_buffer.as_mut_ptr() as *mut core::ffi::c_void);
        InitializeProcThreadAttributeList(list, 1, 0, &mut size)
            .map_err(|e| step("InitializeProcThreadAttributeList", e))?;

        let outcome = (|| -> Result<u32, String> {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                Some(&mut parent_handle as *mut HANDLE as *const core::ffi::c_void),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .map_err(|e| step("UpdateProcThreadAttribute(PARENT_PROCESS)", e))?;
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    ..Default::default()
                },
                lpAttributeList: list,
            };
            let mut info = PROCESS_INFORMATION::default();
            CreateProcessW(
                None,
                PWSTR(command_line.as_mut_ptr()),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut info,
            )
            .map_err(|e| step("CreateProcessW", e))?;
            let _ = WaitForSingleObject(info.hProcess, 10_000);
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
            Ok(info.dwProcessId)
        })();

        DeleteProcThreadAttributeList(list);
        outcome
    }
}

/// `logman query -ets`の生出力。
fn logman_query() -> String {
    match Command::new("logman").args(["query", "-ets"]).output() {
        Ok(output) => format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("(failed to run `logman query -ets`: {error})"),
    }
}

/// `logman query -ets`の出力に残っている自分のセッション名。
fn leftover_sessions(query: &str) -> Vec<String> {
    query
        .lines()
        .filter(|line| line.contains(SESSION_PREFIX))
        .map(|line| line.trim().to_string())
        .collect()
}

/// 分布の要約（min/p50/p99/max）。
fn distribution(values: &mut [i64]) -> String {
    if values.is_empty() {
        return "(no samples)".into();
    }
    values.sort_unstable();
    let at = |q: f64| values[((values.len() - 1) as f64 * q).round() as usize];
    format!(
        "n={} min={} p50={} p99={} max={}",
        values.len(),
        values[0],
        at(0.5),
        at(0.99),
        values[values.len() - 1]
    )
}

fn short(text: Option<&str>, keep: usize) -> String {
    let text = text.unwrap_or("(none)");
    let count = text.chars().count();
    if count <= keep {
        text.to_string()
    } else {
        format!("…{}", text.chars().skip(count - keep).collect::<String>())
    }
}

fn dump(tag: &str, start: &ManifestStart, mof: Option<&MofProcessStart>) {
    println!(
        "[{tag}] pid={} parent_pid={:?} seq={:?} parent_seq={:?} header_pid={} v{} ts={} image={} | MOF cmdline={}",
        start.pid,
        start.parent_pid,
        start.seq,
        start.parent_seq,
        start.header_pid,
        start.version,
        start.ts_ms,
        short(start.image.as_deref(), 40),
        short(mof.and_then(|m| m.command_line.as_deref()), 70),
    );
}

/// MOF側で目印から同定した、このテストが起こしたプロセス1件。
struct Ours<'a> {
    mof: &'a MofProcessStart,
    join: Option<Join>,
}

/// **本命**: `ParentProcessSequenceNumber`が親自身の`ProcessSequenceNumber`を指すか（A1〜A6）。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (two ETW sessions); run via `dev-elevated-run.exe spike-etw-process-lineage`"]
fn does_the_parent_sequence_number_point_at_the_parent() {
    let own_pid = std::process::id();
    let marker = format!("lineagespike-{own_pid}");
    let chain_tag = format!("{marker}-c");
    let pair_tag = format!("{marker}-p");
    let a3_marker = format!("{marker}-a3child");

    // --- 0. 基準線（前回の残りがあると、撤収の確認が意味を持たない） ---
    let baseline = logman_query();
    assert!(
        leftover_sessions(&baseline).is_empty(),
        "a previous run left sessions behind: {:?} -- stop them with `logman stop <name> -ets` \
         (only names starting with {SESSION_PREFIX}) before measuring",
        leftover_sessions(&baseline)
    );

    // --- 1. 自身の番号（A2の比べる相手） ---
    let own = own_sequence_number();
    println!(
        "[A2] own pid={own_pid}; NtQueryInformationProcess(ProcessSequenceNumber=92) = {:?}; \
         ProcessTelemetryIdInformation(64) (pid, seq) = {:?}",
        own.query, own.telemetry
    );
    let telemetry_pid_ok = matches!(own.telemetry, Ok((pid, _)) if pid == own_pid);
    let own_apis_agree = match (&own.query, &own.telemetry) {
        (Ok(query), Ok((_, telemetry))) => Some(query == telemetry),
        _ => None,
    };
    println!(
        "[A2] telemetry ProcessId == own pid: {telemetry_pid_ok}; the two APIs agree: {own_apis_agree:?}"
    );
    let own_reference: Option<u64> = match (&own.query, &own.telemetry) {
        (Ok(query), _) if own_apis_agree != Some(false) => Some(*query),
        (_, Ok((_, telemetry))) if telemetry_pid_ok && own_apis_agree != Some(false) => {
            Some(*telemetry)
        }
        _ => None,
    };

    // --- 2. 2つの購読を同時に張る ---
    let manifest = ProviderProbeSession::start(
        &format!("{SESSION_PREFIX}manifest"),
        KERNEL_PROCESS_PROVIDER_GUID,
        KERNEL_PROCESS_KEYWORD_PROCESS,
        &[EVENT_ID_PROCESS_START, EVENT_ID_PROCESS_STOP],
        &["ImageName"],
        // **`ProbedEvent.process_id`（ETWヘッダのpid）は生まれたプロセスのpidではない**
        // ——生まれたプロセスは`ProcessID`プロパティから引く（手本と同じ）。
        &[
            "ProcessID",
            "ParentProcessID",
            "ProcessSequenceNumber",
            "ParentProcessSequenceNumber",
        ],
    )
    .expect("manifest (Kernel-Process) probe session");
    let mof = MofFsSession::start_process_only(&format!("{SESSION_PREFIX}mof"))
        .expect("private system logger (Classic ETW / MOF), PROCESS flag only");
    // 対象を起こす前に配送が始まるのを待つ（省くとProcessStartごと取りこぼす。実測済み）。
    std::thread::sleep(WARMUP);

    // --- 3a. A1: 目印つきの4段の連鎖（連鎖の先頭が正の対照を兼ねる） ---
    let mut chain_heads: Vec<u32> = Vec::with_capacity(CHAINS);
    for chain in 0..CHAINS {
        let tagged = format!("{chain_tag}{chain:02}");
        let mut args: Vec<&str> = Vec::new();
        for _ in 1..CHAIN_DEPTH {
            args.extend(["/c", "cmd"]);
        }
        args.extend(["/c", "echo", tagged.as_str()]);
        let mut child = Command::new("cmd.exe")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a chain head");
        chain_heads.push(child.id());
        let _ = child.wait();
    }

    // --- 3b. A3: 別の親（ping）を指定した起動 ---
    let mut designated = Command::new("ping.exe")
        .args(["-n", "60", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the designated parent (ping)");
    let designated_pid = designated.id();
    std::thread::sleep(Duration::from_millis(300));
    let a3_child = spawn_with_designated_parent(&designated, &a3_marker);
    let _ = designated.kill();
    let _ = designated.wait();
    println!("[A3] designated parent (ping) pid={designated_pid}; child launch = {a3_child:?}");

    // --- 3c. A4: 短命な親子を600組（pidの使い回しを起こす） ---
    let pairs_started = Instant::now();
    let mut pair_outers: Vec<u32> = Vec::with_capacity(PAIRS);
    for pair in 0..PAIRS {
        let tagged = format!("{pair_tag}{pair:04}");
        match Command::new("cmd.exe")
            .args(["/c", "cmd", "/c", "rem", tagged.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                pair_outers.push(child.id());
                let _ = child.wait();
            }
            Err(error) => {
                println!("[A4] spawn failed (continuing): {error}");
                pair_outers.push(0);
            }
        }
    }
    let pairs_elapsed = pairs_started.elapsed();
    // **起動側の台帳で使い回しを判定する**（観測側ではなく自分が知っている事実。§23.1と同じ）。
    let launched_outer_pids: Vec<u32> = pair_outers.iter().copied().filter(|p| *p != 0).collect();
    let launcher_distinct: BTreeSet<u32> = launched_outer_pids.iter().copied().collect();
    println!(
        "[A4] launched {} pair(s) in {pairs_elapsed:?}; outer pids: {} distinct / {} launched \
         (launcher-side pid reuse = {})",
        launched_outer_pids.len(),
        launcher_distinct.len(),
        launched_outer_pids.len(),
        launcher_distinct.len() < launched_outer_pids.len(),
    );

    std::thread::sleep(DRAIN);
    let mof_outcome = mof.stop();
    let manifest_outcome = manifest.stop();
    let after = logman_query();
    let leftovers = leftover_sessions(&after);

    // ---------------- 生の観測量 ----------------
    let (starts, stops, starts_without_pid) = split_manifest(&manifest_outcome.events);
    println!(
        "=== manifest (Kernel-Process): {} event(s) captured = {} ProcessStart + {} ProcessStop \
         ({starts_without_pid} start(s) without ProcessID); {} reached the session; {} dropped by \
         capacity; {} events lost; {} rt buffers lost ===",
        manifest_outcome.events.len(),
        starts.len(),
        stops.len(),
        manifest_outcome.seen_events,
        manifest_outcome.dropped,
        manifest_outcome.events_lost,
        manifest_outcome.realtime_buffers_lost,
    );
    let live: Vec<&MofProcessStart> = mof_outcome
        .process_starts
        .iter()
        .filter(|s| s.event_type == EVENT_TYPE_PROCESS_START)
        .collect();
    println!(
        "=== MOF (Process class): {} raw event(s); {} start(s) captured ({} live EventType=1); {} dropped ===",
        mof_outcome.process_events,
        mof_outcome.process_starts.len(),
        live.len(),
        mof_outcome.process_dropped,
    );

    // 「取れなかった」の3つの意味（欄）。マシン全体の開始について数える。
    let mut start_versions: BTreeMap<u8, usize> = BTreeMap::new();
    let (mut field_present, mut field_zero, mut field_missing, mut seq_missing) = (0, 0, 0, 0);
    for start in &starts {
        *start_versions.entry(start.version).or_insert(0) += 1;
        match start.parent_seq {
            None => field_missing += 1,
            Some(0) => field_zero += 1,
            Some(_) => field_present += 1,
        }
        if start.seq.is_none() {
            seq_missing += 1;
        }
    }
    println!(
        "[field] ProcessStart versions {start_versions:?}; ParentProcessSequenceNumber: present(non-zero) \
         {field_present} / zero {field_zero} / missing {field_missing}; ProcessSequenceNumber missing {seq_missing}"
    );
    for start in starts.iter().filter(|s| s.parent_seq.is_none_or(|v| v == 0)).take(5) {
        dump("field-absent-or-zero", start, None);
    }
    let out_of_order = starts.windows(2).filter(|w| w[1].ts_ms < w[0].ts_ms).count();
    println!(
        "[order] ProcessStart delivered out of timestamp order: {out_of_order} time(s) out of {} \
         (the 'pid table at delivery time' lookup depends on this)",
        starts.len().saturating_sub(1)
    );

    // ---------------- 目印で、自分が起こしたプロセスを MOF 側で同定する ----------------
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, start) in starts.iter().enumerate() {
        by_pid.entry(start.pid).or_default().push(index);
    }
    let mut chain_levels: BTreeMap<(usize, usize), Ours> = BTreeMap::new();
    let mut pair_outer_m: BTreeMap<usize, Ours> = BTreeMap::new();
    let mut pair_inner_m: BTreeMap<usize, Ours> = BTreeMap::new();
    let mut a3_mof: Option<Ours> = None;
    let mut anomalies: Vec<String> = Vec::new();
    for &start in &live {
        let Some(command_line) = start.command_line.as_deref() else {
            continue;
        };
        let ours = || Ours {
            mof: start,
            join: join(start, &by_pid, &starts),
        };
        if let Some(chain) = tagged_index(command_line, &chain_tag, 2) {
            let count = slash_c_count(command_line);
            if (1..=CHAIN_DEPTH).contains(&count) {
                let level = CHAIN_DEPTH + 1 - count;
                if chain_levels.insert((chain, level), ours()).is_some() {
                    anomalies.push(format!("chain {chain} level {level} seen twice"));
                }
            } else {
                anomalies.push(format!("chain {chain}: unexpected /c count {count}: {command_line:?}"));
            }
        } else if let Some(pair) = tagged_index(command_line, &pair_tag, 4) {
            let slot = match slash_c_count(command_line) {
                2 => &mut pair_outer_m,
                1 => &mut pair_inner_m,
                count => {
                    anomalies.push(format!("pair {pair}: unexpected /c count {count}: {command_line:?}"));
                    continue;
                }
            };
            if slot.insert(pair, ours()).is_some() {
                anomalies.push(format!("pair {pair} seen twice at the same level"));
            }
        } else if command_line.contains(&a3_marker) {
            a3_mof = Some(ours());
        }
    }
    println!(
        "[identify] MOF: chain levels {} (expected {}), pair outers {} / inners {} (expected {PAIRS} each), \
         A3 child {}; anomalies {}",
        chain_levels.len(),
        CHAINS * CHAIN_DEPTH,
        pair_outer_m.len(),
        pair_inner_m.len(),
        a3_mof.is_some(),
        anomalies.len()
    );
    for anomaly in anomalies.iter().take(10) {
        println!("[identify]   {anomaly}");
    }
    let manifest_of = |ours: &Ours| ours.join.map(|j| &starts[j.manifest]);

    // ---------------- 計器の検算 G1: 両方の購読が連鎖の先頭を見たか ----------------
    let mut g1_ok = 0usize;
    for (chain, head_pid) in chain_heads.iter().enumerate() {
        let mof_saw = chain_levels
            .get(&(chain, 1))
            .is_some_and(|o| o.mof.pid == Some(*head_pid));
        let manifest_saw = by_pid.contains_key(head_pid);
        if mof_saw && manifest_saw {
            g1_ok += 1;
        } else {
            println!("[G1] chain {chain} head pid {head_pid}: MOF saw marker = {mof_saw}, manifest saw pid = {manifest_saw}");
        }
    }
    let chain_joined = chain_levels.values().filter(|o| o.join.is_some()).count();
    let g2_ok = manifest_outcome.events_lost == 0
        && manifest_outcome.realtime_buffers_lost == 0
        && manifest_outcome.dropped == 0
        && mof_outcome.process_dropped == 0;
    let chain_anomalies = anomalies.iter().filter(|a| a.starts_with("chain")).count();
    let g3_ok = chain_levels.len() == CHAINS * CHAIN_DEPTH
        && chain_joined == CHAINS * CHAIN_DEPTH
        && chain_anomalies == 0;

    // ---------------- A1: 連鎖の各段 ----------------
    let mut a1 = LinkTally::default();
    let mut a1_parent_pid_consistent = 0usize;
    for chain in 0..CHAINS {
        for level in 2..=CHAIN_DEPTH {
            let parent = chain_levels.get(&(chain, level - 1)).and_then(manifest_of);
            let child = chain_levels.get(&(chain, level)).and_then(manifest_of);
            let (Some(parent), Some(child)) = (parent, child) else {
                a1.unjoined += 1;
                continue;
            };
            a1.record(child.parent_seq, parent.seq);
            if child.parent_pid == Some(parent.pid) {
                a1_parent_pid_consistent += 1;
            }
            if child.parent_seq != parent.seq && a1.mismatched + a1.missing + a1.zero <= 5 {
                dump("A1-disagree parent", parent, None);
                dump("A1-disagree child ", child, None);
            }
        }
    }
    for level in 1..=CHAIN_DEPTH {
        if let Some(ours) = chain_levels.get(&(0, level)) {
            if let Some(start) = manifest_of(ours) {
                dump(&format!("A1 chain0 L{level}"), start, Some(ours.mof));
            }
        }
    }

    // ---------------- A2: 試験プロセスが直接起こした子 ----------------
    let mut direct: Vec<&ManifestStart> = Vec::new();
    direct.extend(chain_levels.iter().filter(|((_, l), _)| *l == 1).filter_map(|(_, o)| manifest_of(o)));
    direct.extend(pair_outer_m.values().filter_map(manifest_of));
    let designated_start = by_pid
        .get(&designated_pid)
        .into_iter()
        .flatten()
        .map(|&i| &starts[i])
        .find(|s| s.parent_pid == Some(own_pid));
    direct.extend(designated_start);
    let mut a2 = LinkTally::default();
    let mut a2_values: BTreeMap<Option<u64>, usize> = BTreeMap::new();
    let mut a2_parent_pid_is_own = 0usize;
    for start in &direct {
        a2.record(start.parent_seq, own_reference);
        *a2_values.entry(start.parent_seq).or_insert(0) += 1;
        if start.parent_pid == Some(own_pid) {
            a2_parent_pid_is_own += 1;
        }
    }
    let direct_min_seq = direct.iter().filter_map(|s| s.seq).min();
    println!(
        "[A2] direct children compared {}; their ParentProcessSequenceNumber values: {a2_values:?}; \
         smallest child seq {direct_min_seq:?}; ParentProcessID == own pid for {a2_parent_pid_is_own}",
        direct.len()
    );
    let by_parent_pid_own: BTreeMap<Option<u64>, usize> =
        starts.iter().filter(|s| s.parent_pid == Some(own_pid)).fold(BTreeMap::new(), |mut m, s| {
            *m.entry(s.parent_seq).or_insert(0) += 1;
            m
        });
    println!(
        "[A2] every ProcessStart in the trace whose ParentProcessID is own pid: ParentProcessSequenceNumber -> count {by_parent_pid_own:?}"
    );

    // ---------------- A3: 別の親を指定した起動（対照） ----------------
    let a3_start = match (&a3_child, &a3_mof) {
        (Ok(child_pid), _) => by_pid
            .get(child_pid)
            .into_iter()
            .flatten()
            .map(|&i| &starts[i])
            .max_by_key(|s| s.ts_ms),
        (Err(_), Some(ours)) => manifest_of(ours),
        (Err(_), None) => None,
    };
    let classify_pid = |pid: Option<u32>| match pid {
        Some(p) if p == own_pid => "creator (this test)",
        Some(p) if p == designated_pid => "designated (ping)",
        Some(_) => "other",
        None => "missing",
    };
    let designated_seq = designated_start.and_then(|s| s.seq);
    let classify_seq = |seq: Option<u64>| match seq {
        None => "missing",
        Some(0) => "zero",
        Some(s) if Some(s) == designated_seq => "designated (ping)",
        Some(s) if Some(s) == own_reference => "creator (this test)",
        Some(_) => "other",
    };
    let a3_summary = match a3_start {
        Some(start) => {
            dump("A3 child", start, a3_mof.as_ref().map(|o| o.mof));
            if let Some(parent) = designated_start {
                dump("A3 designated", parent, None);
            }
            format!(
                "ParentProcessID -> {}; ParentProcessSequenceNumber -> {}; ETW header pid -> {}; MOF parent pid -> {}",
                classify_pid(start.parent_pid),
                classify_seq(start.parent_seq),
                classify_pid(Some(start.header_pid)),
                classify_pid(a3_mof.as_ref().and_then(|o| o.mof.parent_pid)),
            )
        }
        None => format!("not measured (launch: {a3_child:?}; MOF saw marker: {})", a3_mof.is_some()),
    };
    println!("[A3] {a3_summary}");

    // ---------------- A5: 終了の通知 ----------------
    let mut stop_versions: BTreeMap<u8, usize> = BTreeMap::new();
    let mut stops_with_seq = 0usize;
    let mut stop_ts_by_seq: HashMap<u64, u64> = HashMap::new();
    let mut stop_pid_by_seq: HashMap<u64, Option<u32>> = HashMap::new();
    for stop in &stops {
        *stop_versions.entry(stop.version).or_insert(0) += 1;
        if let Some(seq) = stop.seq {
            stops_with_seq += 1;
            stop_ts_by_seq.insert(seq, stop.ts_ms);
            stop_pid_by_seq.insert(seq, stop.pid);
        }
    }
    let ours_starts: Vec<&ManifestStart> = chain_levels
        .values()
        .chain(pair_outer_m.values())
        .chain(pair_inner_m.values())
        .chain(a3_mof.iter())
        .filter_map(manifest_of)
        .chain(designated_start)
        .collect();
    let (mut a5_found, mut a5_missing, mut a5_pid_match, mut a5_no_start_seq) = (0, 0, 0, 0);
    for start in &ours_starts {
        let Some(seq) = start.seq else {
            a5_no_start_seq += 1;
            continue;
        };
        match stop_pid_by_seq.get(&seq) {
            Some(pid) => {
                a5_found += 1;
                if *pid == Some(start.pid) {
                    a5_pid_match += 1;
                }
            }
            None => a5_missing += 1,
        }
    }
    println!(
        "[A5] ProcessStop: {} captured, versions {stop_versions:?}, with ProcessSequenceNumber {stops_with_seq}; \
         our {} process(es): stop with the same seq found {a5_found} (ProcessID also equal {a5_pid_match}) / \
         not found {a5_missing} / start had no seq {a5_no_start_seq}",
        stops.len(),
        ours_starts.len(),
    );

    // ---------------- A4: 短命な親子 ----------------
    let mut final_by_pid: HashMap<u32, Option<u64>> = HashMap::new();
    let mut at_delivery: Vec<Option<Option<u64>>> = vec![None; starts.len()];
    for (index, start) in starts.iter().enumerate() {
        at_delivery[index] = start
            .parent_pid
            .and_then(|parent_pid| final_by_pid.get(&parent_pid).copied());
        final_by_pid.insert(start.pid, start.seq);
    }
    let mut a4_field = LinkTally::default();
    let (mut a4_at_delivery, mut a4_final, mut a4_window) =
        (PidTally::default(), PidTally::default(), PidTally::default());
    let mut a4_parent_pid_ok = 0usize;
    let mut a4_outer_pid_is_launcher = 0usize;
    let mut a4_shown = 0usize;
    for pair in 0..PAIRS {
        let outer = pair_outer_m.get(&pair);
        let inner = pair_inner_m.get(&pair);
        let (Some(outer), Some(inner)) = (outer, inner) else {
            a4_field.unjoined += 1;
            continue;
        };
        let (Some(outer_join), Some(inner_join)) = (outer.join, inner.join) else {
            a4_field.unjoined += 1;
            continue;
        };
        let parent = &starts[outer_join.manifest];
        let child = &starts[inner_join.manifest];
        if pair_outers.get(pair).copied() == Some(parent.pid) {
            a4_outer_pid_is_launcher += 1;
        }
        let truth = parent.seq;
        a4_field.record(child.parent_seq, truth);
        a4_at_delivery.record(at_delivery[inner_join.manifest], truth);
        a4_final.record(
            child.parent_pid.and_then(|pp| final_by_pid.get(&pp).copied()),
            truth,
        );
        match window_lookup(child, &starts, &by_pid, &stop_ts_by_seq) {
            WindowLookup::Resolved(seq) => a4_window.record(Some(seq), truth),
            WindowLookup::NoCandidate => a4_window.none += 1,
            WindowLookup::Ambiguous => a4_window.ambiguous += 1,
        }
        if child.parent_pid == Some(parent.pid) {
            a4_parent_pid_ok += 1;
        }
        let disagrees = child.parent_seq != truth || at_delivery[inner_join.manifest] != Some(truth);
        if (pair < 2 || disagrees) && a4_shown < 8 {
            dump(&format!("A4 pair{pair} outer"), parent, Some(outer.mof));
            dump(&format!("A4 pair{pair} inner"), child, Some(inner.mof));
            a4_shown += 1;
        }
    }
    // 観測側の使い回し: 組のプロセス（外側・内側）のpidのうち、マニフェストに2回以上の開始があるもの。
    let pair_pids: BTreeSet<u32> = pair_outer_m
        .values()
        .chain(pair_inner_m.values())
        .filter_map(manifest_of)
        .map(|s| s.pid)
        .collect();
    let reused_pair_pids: Vec<(&u32, Vec<Option<u64>>)> = pair_pids
        .iter()
        .filter_map(|pid| {
            let seqs: Vec<Option<u64>> = by_pid.get(pid)?.iter().map(|&i| starts[i].seq).collect();
            (seqs.len() > 1).then_some((pid, seqs))
        })
        .collect();
    println!(
        "[A4] observed pid reuse among pair processes: {} pid(s) with 2+ ProcessStart in this trace \
         (0 means reuse was NOT exercised -- record it as untested)",
        reused_pair_pids.len()
    );
    for (pid, seqs) in reused_pair_pids.iter().take(5) {
        println!("[A4]   pid {pid}: seqs {seqs:?}");
    }

    // ---------------- A6: 2つの購読の時刻差 ----------------
    let joins: Vec<Join> = chain_levels
        .values()
        .chain(pair_outer_m.values())
        .chain(pair_inner_m.values())
        .chain(a3_mof.iter())
        .filter_map(|o| o.join)
        .collect();
    let mut deltas: Vec<i64> = joins.iter().map(|j| j.dt_ms).collect();
    let nonzero = deltas.iter().filter(|d| **d != 0).count();
    let ambiguous_joins = joins.iter().filter(|j| j.candidates > 1).count();
    let delta_summary = distribution(&mut deltas);
    let max_abs_dt = deltas.iter().map(|d| d.unsigned_abs()).max();
    let mut min_reuse_gap: Option<u64> = None;
    for indices in by_pid.values().filter(|v| v.len() > 1) {
        let mut times: Vec<u64> = indices.iter().map(|&i| starts[i].ts_ms).collect();
        times.sort_unstable();
        for pair in times.windows(2) {
            let gap = pair[1] - pair[0];
            min_reuse_gap = Some(min_reuse_gap.map_or(gap, |m| m.min(gap)));
        }
    }
    println!(
        "[A6] dt(manifest - MOF) ms over {} joined process(es): {delta_summary}; non-zero {nonzero}; \
         joins with 2+ same-pid candidates within ±{JOIN_PROBE_WINDOW_MS}ms: {ambiguous_joins}; \
         shortest gap between two ProcessStart of the same pid (whole trace): {min_reuse_gap:?} ms",
        joins.len()
    );

    // ---------------- 表（RESULTS §24 へ写す） ----------------
    println!("\n=== P1 process lineage: results (copy into plans/etw-spike/RESULTS.md §24) ===");
    println!("| item | result |");
    println!("|---|---|");
    println!(
        "| G1 both sessions saw every chain head | {g1_ok}/{CHAINS} |"
    );
    println!(
        "| G2 no loss | manifest lost {} / rt buffers lost {} / dropped {}; MOF dropped {} -> {} |",
        manifest_outcome.events_lost,
        manifest_outcome.realtime_buffers_lost,
        manifest_outcome.dropped,
        mof_outcome.process_dropped,
        if g2_ok { "ok" } else { "FAILED" }
    );
    println!(
        "| G3 chain levels identified and joined | identified {}/{} joined {chain_joined} anomalies {chain_anomalies} -> {} |",
        chain_levels.len(),
        CHAINS * CHAIN_DEPTH,
        if g3_ok { "ok" } else { "FAILED" }
    );
    println!(
        "| field | ProcessStart versions {start_versions:?}; ParentProcessSequenceNumber present {field_present} / zero {field_zero} / missing {field_missing} (whole trace, {} starts) |",
        starts.len()
    );
    println!(
        "| A1 child's field == parent level's seq | {} ; ParentProcessID == parent pid {a1_parent_pid_consistent} -> all matched = {} |",
        a1.render(),
        a1.all_matched()
    );
    println!(
        "| A2 direct child's field == own seq | own seq {own_reference:?} (query {:?}, telemetry {:?}); {} -> all matched = {} |",
        own.query,
        own.telemetry,
        a2.render(),
        a2.all_matched()
    );
    println!("| A3 designated parent (control) | {a3_summary} |");
    println!(
        "| A4 parent of {PAIRS} short-lived pairs | pid reuse: launcher {} distinct/{} launched, observed {} reused pid(s); \
         by field: {} ; by pid table at delivery: {} ; by final pid table: {} ; by pid + start/stop window: {} ; \
         ParentProcessID == true parent pid {a4_parent_pid_ok}; outer pid == launcher record {a4_outer_pid_is_launcher} |",
        launcher_distinct.len(),
        launched_outer_pids.len(),
        reused_pair_pids.len(),
        a4_field.render(),
        a4_at_delivery.render(),
        a4_final.render(),
        a4_window.render(),
    );
    println!(
        "| A5 ProcessStop carries ProcessSequenceNumber | stops {} (versions {stop_versions:?}, with seq {stops_with_seq}); ours {}: found {a5_found} (pid equal {a5_pid_match}) / missing {a5_missing} / no start seq {a5_no_start_seq} |",
        stops.len(),
        ours_starts.len(),
    );
    println!(
        "| A6 dt(manifest - MOF) | {delta_summary}; non-zero {nonzero}; ambiguous joins {ambiguous_joins}; max |dt| {max_abs_dt:?} ms; shortest same-pid gap {min_reuse_gap:?} ms; out-of-order deliveries {out_of_order} |"
    );
    println!(
        "| cleanup | `logman query -ets` sessions starting with {SESSION_PREFIX}: {} |",
        leftovers.len()
    );

    // ---------------- 歯（測定が成立していること） ----------------
    assert!(
        leftovers.is_empty(),
        "ETW sessions were left behind: {leftovers:?} -- stop them with `logman stop <name> -ets`"
    );
    assert_eq!(
        g1_ok, CHAINS,
        "G1 failed: both subscriptions must have observed every chain head (MOF by its marker, the \
         manifest by its pid); without this a missing or mismatching field cannot be told apart from \
         a process that one session never saw. The numbers above are NOT a result"
    );
    assert!(
        g2_ok,
        "G2 failed: events were lost or dropped (manifest lost {} / rt buffers lost {} / dropped {}; \
         MOF dropped {}); a missing parent could be a lost event rather than a property of the field",
        manifest_outcome.events_lost,
        manifest_outcome.realtime_buffers_lost,
        manifest_outcome.dropped,
        mof_outcome.process_dropped
    );
    assert!(
        g3_ok,
        "G3 failed: every chain level must be identified on the MOF side and joined to one manifest \
         ProcessStart (identified {}/{}, joined {chain_joined}, anomalies {chain_anomalies}); A1's \
         denominator is otherwise not the chains we launched",
        chain_levels.len(),
        CHAINS * CHAIN_DEPTH
    );
}
