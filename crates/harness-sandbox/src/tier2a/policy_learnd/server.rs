//! **管理者権限側**（`harness-policy-learnd.exe`として昇格起動されたプロセス）の実装。
//!
//! `client.rs`とファイルを分けているのは`docs/CODE-STRUCTURE-RULES.md`規則3
//! （「信頼境界は必ず分割線にする」）による。どのコードが昇格した権限で動くのかを
//! ファイル単位で判別できないと、セキュリティレビューが成立しない。
//!
//! # 昇格側が親を信じない点
//!
//! 親（harness本体）は非特権で、攻撃者と同じ権限で動きうる（P-01）。したがって受け取った
//! 要求は**すべて受信側で検証する**:
//!
//! - `session_profile` — `is_session_profile_name`で形を検証（任意のAppContainerを対象にさせない）
//! - `fs_audit_log_path` — `validate_audit_sink_path`で`<workspace>/.harness/sandbox/`配下に限定
//!   （管理者権限での任意パス追記プリミティブにしない）
//!
//! # fail-openは「失敗を隠さない」形で行う（D-43）
//!
//! ETWが張れなくてもharnessは止めない。ただし**張れなかった事実・取りこぼした件数は
//! 制御レコードとして`fs-audit.jsonl`へ必ず書く**。「黙って空」と「本当に拒否が無かった」を
//! 読む側が区別できなければ、fail-openは単なる隠蔽になる。

use std::io::Write;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING,
};

use harness_policy::event::{FsAuditEvent, FsAuditKind};

use super::etw::parse::{to_settings_path, AccessRecord, Denial};
use super::etw::scope::{ScopeTracker, ScopeVerdict};
use super::etw::session::EtwFsSession;
use super::etw::volumes::drive_letter_map;
use super::{LearnError, LearnPolicy, LearnRequest, LearnResponse};
use crate::elevated_launch::validate_audit_sink_path;
use crate::win_common::wide;
use crate::win_pipe_ipc::{read_framed_timeout, write_framed_timeout};

/// `StartCollect`を待つタイムアウト。
const START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// 応答書込のタイムアウト。
const RESPONSE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 収集中の1回のドレイン間隔。短すぎるとロック競合、長すぎるとクラッシュ時の損失が増える。
const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// daemon側エントリポイント（`harness-policy-learnd.exe`のmainから呼ぶ、昇格トークンで実行される）。
pub fn serve(pipe_name: &str) -> Result<(), LearnError> {
    let pipe = unsafe {
        let pipe_name_w = wide(pipe_name);
        CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
        .map_err(LearnError::from)?
    };
    let result = serve_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

fn serve_inner(pipe: HANDLE) -> Result<(), LearnError> {
    // 1回目: StartCollect を待つ。
    let request_bytes = read_framed_timeout(pipe, START_TIMEOUT)
        .map_err(|e| LearnError::Ipc(format!("waiting for StartCollect: {e}")))?;
    let policy = match serde_json::from_slice::<LearnRequest>(&request_bytes) {
        Ok(LearnRequest::StartCollect(policy)) => policy,
        Ok(LearnRequest::Teardown) => {
            let _ = send(pipe, &LearnResponse::Err("expected StartCollect first".into()));
            return Err(LearnError::Ipc("protocol violation".into()));
        }
        Err(e) => {
            let _ = send(pipe, &LearnResponse::Err(format!("malformed request: {e}")));
            return Err(LearnError::Ipc(format!("malformed request: {e}")));
        }
    };

    let sink_path = match validate_request(&policy) {
        Ok(path) => path,
        Err(message) => {
            let _ = send(pipe, &LearnResponse::Err(message.clone()));
            return Err(LearnError::Rejected(message));
        }
    };

    // ETWセッションを張る。失敗しても**止めない**（D-43）——事実を制御レコードへ書いて
    // 「収集できていない」ことを読む側へ伝えたうえで、Teardownまで待つ。
    let session_name = format!("harness-policy-learn-{}", policy.session_profile);
    let start_result = if policy.record_all {
        EtwFsSession::start_record_all(&session_name)
    } else {
        EtwFsSession::start(&session_name)
    };
    let session = match start_result {
        Ok(session) => Some(session),
        Err(e) => {
            append_control(&sink_path, &format!("etw_session_start_failed: {e}"));
            None
        }
    };
    if let Some(session) = session.as_ref() {
        if !session.kernel_process_enabled() {
            append_control(
                &sink_path,
                "kernel_process_provider_unavailable: scoping falls back to per-PID token \
                 queries, which cannot resolve processes that already exited",
            );
        }
    }
    send(
        pipe,
        &LearnResponse::Started {
            etw_available: session.is_some(),
        },
    )?;

    // 2回目（Teardown、または親のクラッシュによるパイプ切断）を待ちながら、定期的にドレインする。
    let mut tracker =
        ScopeTracker::new(policy.session_profile.clone()).with_harness_pid(policy.harness_pid);
    let volumes = drive_letter_map();
    let mut written = 0u64;
    let mut unconvertible = 0u64;
    // record-allのツリー表示用。**ループの外**に置く（プロセスはあるバッチで起動し、
    // 別のバッチでアクセスする）。deny-onlyモードでは使わない。
    let mut tree = ProcessTree::new();

    let teardown_result = loop {
        match read_framed_timeout(pipe, DRAIN_INTERVAL) {
            Ok(bytes) => break Ok(bytes),
            Err(e) => {
                let message = e.to_string();
                // タイムアウトはドレインの合図。それ以外（パイプ切断＝親の死）は撤収へ。
                if !message.contains("timed out") && !message.contains("timeout") {
                    break Err(message);
                }
            }
        }
        if let Some(session) = session.as_ref() {
            written += if policy.record_all {
                let (starts, records) = session.drain_records();
                flush_batch_record_all(
                    &sink_path,
                    &mut tracker,
                    &mut tree,
                    &volumes,
                    starts,
                    records,
                    &mut unconvertible,
                )
            } else {
                let (starts, denials) = session.drain();
                flush_batch(
                    &sink_path,
                    &mut tracker,
                    &volumes,
                    starts,
                    denials,
                    &mut unconvertible,
                )
            };
        }
    };

    // 最後の取り残しを回収し、統計を制御レコードとして残す。
    if let Some(session) = session {
        written += if policy.record_all {
            let (starts, records) = session.drain_records();
            flush_batch_record_all(
                &sink_path,
                &mut tracker,
                &mut tree,
                &volumes,
                starts,
                records,
                &mut unconvertible,
            )
        } else {
            let (starts, denials) = session.drain();
            flush_batch(
                &sink_path,
                &mut tracker,
                &volumes,
                starts,
                denials,
                &mut unconvertible,
            )
        };
        let outcome = session.stop();
        record_collection_stats(&sink_path, &outcome, &tracker, unconvertible);
    }

    let is_explicit_teardown = matches!(
        &teardown_result,
        Ok(bytes) if matches!(
            serde_json::from_slice::<LearnRequest>(bytes),
            Ok(LearnRequest::Teardown)
        )
    );
    if is_explicit_teardown {
        // 応答送信の失敗はここでは致命的としない（親が既に読み取りを諦めている可能性がある）。
        let _ = send(
            pipe,
            &LearnResponse::TornDown {
                denials_written: written,
            },
        );
    }
    Ok(())
}

/// 親から受け取った要求を、昇格側の責任で検証する。
fn validate_request(policy: &LearnPolicy) -> Result<std::path::PathBuf, String> {
    if !crate::tier2a::session_profile::is_session_profile_name(&policy.session_profile) {
        return Err(format!(
            "rejected malformed session profile name: {:?}",
            policy.session_profile
        ));
    }
    validate_audit_sink_path(&policy.fs_audit_log_path, &policy.workspace_root)
        .map_err(|e| format!("rejected audit sink path: {e}"))
}

/// 1バッチ分を判定して書き出し、書けた件数を返す。
///
/// `ProcessStart`を**先に**食わせるのは、スコープ判定の「親が対象なら子も対象」が
/// その情報に依存するため（同じバッチ内で子の拒否が先に来ても解決できるようにする）。
fn flush_batch(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    denials: Vec<Denial>,
    unconvertible: &mut u64,
) -> u64 {
    for start in &starts {
        // **ProcessStart時にprobeする**（拒否イベント時ではなく）。実測でharnessのAppContainerは
        // `PackageFullName`を報告しないと判明したため、第1世代を識別できるのはこのprobeだけで、
        // かつ`ProcessStart`の時点ならそのプロセスはまだ生きている（RESULTS.md §11）。
        tracker.on_process_start_probing(start, probe_pid_in_container);
    }

    let mut written = 0u64;
    for denial in denials {
        let verdict = tracker.classify(denial.pid, probe_pid_in_container);
        if verdict != ScopeVerdict::InScope {
            continue;
        }
        let Some(path) = to_settings_path(&denial.file_name, volumes) else {
            // 設定へ書けない形（名前付きパイプ・未知のボリューム）。件数だけ数えて捨てる。
            *unconvertible = unconvertible.saturating_add(1);
            continue;
        };
        let event = FsAuditEvent::denied(
            FsAuditKind::Etw,
            path,
            denial.access,
            format!("STATUS_ACCESS_DENIED ({:#010X})", denial.status),
            denial.timestamp_unix_ms,
        )
        .with_process(denial.pid, None);
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
}

/// [`flush_batch`]のrecord-all版（`LearnPolicy.record_all`、ポリシー定義モードのTier1パス）。
/// 拒否だけでなく許可も含めて全アクセスを書き出す。
///
/// **スコープprobeに`probe_pid_in_container`を使わない**——Tier1（制限トークン）には
/// AppContainerのpackage SIDが無いため、`TokenIsAppContainer`照会は生存中のTier1プロセスに
/// 対しても確定的に`Some(false)`（「AppContainerではない」）を返してしまい、対象を
/// 永久に除外してしまう（`LearnPolicy.record_all`のdoc参照）。代わりに常に`None`を返す
/// クロージャを渡し、`harness_pid`起点の親子継承（signal 2＋フォールバック）だけで
/// スコープを決めさせる。
///
/// `tree`は**呼び出しをまたいで生き残る**（`serve_inner`が所有する）。プロセスは
/// バッチNの`ProcessStart`で現れ、バッチN+1以降のアクセスを行うため、この関数の
/// ローカルに置くと親PID・画像名がほぼ全件で欠落する。
fn flush_batch_record_all(
    sink_path: &Path,
    tracker: &mut ScopeTracker,
    tree: &mut ProcessTree,
    volumes: &[(String, String)],
    starts: Vec<super::etw::session::ProcessStartInfo>,
    records: Vec<AccessRecord>,
    unconvertible: &mut u64,
) -> u64 {
    for start in &starts {
        tracker.on_process_start_probing(start, |_pid| None);
        tree.insert(
            start.pid,
            ProcessIdentity {
                parent_pid: start.parent_pid,
                image_name: start.image_name.clone(),
            },
        );
    }

    let mut written = 0u64;
    for record in records {
        let verdict = tracker.classify(record.pid, |_pid| None);
        if verdict != ScopeVerdict::InScope {
            continue;
        }
        let Some(path) = to_settings_path(&record.file_name, volumes) else {
            // 設定へ書けない形（名前付きパイプ・未知のボリューム）。件数だけ数えて捨てる。
            *unconvertible = unconvertible.saturating_add(1);
            continue;
        };
        let reason = if record.allowed {
            "observed".to_string()
        } else {
            format!("STATUS_ACCESS_DENIED ({:#010X})", record.status)
        };
        let identity = tree.get(&record.pid);
        let mut event = FsAuditEvent::observed(
            FsAuditKind::Etw,
            path,
            record.access,
            record.allowed,
            reason,
            record.timestamp_unix_ms,
        )
        .with_process(
            record.pid,
            identity.and_then(|i| i.image_name.clone()),
        );
        // 親PIDが分かるのは`ProcessStart`を観測できた世代だけ。分からないものは
        // `None`のまま残す（推測で埋めない——ツリー表示が嘘の親子関係を描くため）。
        if let Some(parent_pid) = identity.and_then(|i| i.parent_pid) {
            event = event.with_parent_process(parent_pid);
        }
        if append_event(sink_path, &event) {
            written += 1;
        }
    }
    written
}

/// `ProcessStart`から拾ったプロセスの素性（record-allのツリー表示用）。
///
/// スコープ判定（[`ScopeTracker`]）とは別に持つ。あちらが答えるのは「対象か」だけで、
/// 「誰の子か・何の実行ファイルか」は保持しない——判定に不要な情報を判定器へ足すと、
/// 判定の単体テストがツリー表示の都合で壊れるようになる。
#[derive(Debug, Clone)]
struct ProcessIdentity {
    parent_pid: Option<u32>,
    image_name: Option<String>,
}

/// PID → 素性。**PID再利用は上書きで扱う**（新しい`ProcessStart`が来たら古い素性を捨てる）。
/// [`ScopeTracker`]が`ProcessSequenceNumber`で行っている扱いと同じ方針だが、
/// こちらは表示用なので順序の逆転までは追わない。
type ProcessTree = std::collections::HashMap<u32, ProcessIdentity>;

/// **取りこぼしを隠さない**（D-43）。収集の統計を制御レコードとして残す。
fn record_collection_stats(
    sink_path: &Path,
    outcome: &super::etw::session::EtwFsOutcome,
    tracker: &ScopeTracker,
    unconvertible: u64,
) {
    if outcome.events_lost > 0 || outcome.realtime_buffers_lost > 0 {
        append_control(
            sink_path,
            &format!(
                "etw_events_lost: {} event(s), {} realtime buffer(s) -- the collection is \
                 incomplete for this session",
                outcome.events_lost, outcome.realtime_buffers_lost
            ),
        );
    }
    if unconvertible > 0 {
        append_control(
            sink_path,
            &format!(
                "unconvertible_paths: {unconvertible} event(s) had a path that cannot be \
                 expressed in settings (named pipes, unmapped volumes) and were dropped"
            ),
        );
    }
    let unresolved = tracker.unresolved_count();
    if unresolved > 0 {
        append_control(
            sink_path,
            &format!(
                // record-allでは拒否以外も流れるので「denial」とは言えない（B-32: 文言は
                // ユーザーがその瞬間に取る行動を決める唯一の入力）。両モード共通の語にする。
                "unresolved_process_scope: {unresolved} event(s) came from a process that had \
                 already exited, so it could not be attributed to this sandbox and was dropped"
            ),
        );
    }
    if tracker.attributed_by_parentage_count() > 0 {
        append_control(
            sink_path,
            &format!(
                "attributed_by_parentage: {} process(es) were treated as in-scope because \
                 their parent was harness and the token query did not complete in time (they \
                 had already exited). This is an inference, not a proof.",
                tracker.attributed_by_parentage_count()
            ),
        );
    }
    if !tracker.package_name_ever_matched() {
        append_control(
            sink_path,
            "package_identity_never_matched: scoping relied entirely on per-PID token queries \
             (ProcessStart did not report a matching PackageFullName for this session)",
        );
    }
}

fn append_event(sink_path: &Path, event: &FsAuditEvent) -> bool {
    let Ok(mut line) = event.to_jsonl_line() else {
        return false;
    };
    line.push('\n');
    if let Some(parent) = sink_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sink_path)
    {
        Ok(mut f) => f.write_all(line.as_bytes()).is_ok(),
        Err(_) => false,
    }
}

fn append_control(sink_path: &Path, reason: &str) {
    let event = FsAuditEvent::control(reason, harness_policy::event::now_unix_ms());
    let _ = append_event(sink_path, &event);
}

/// signal 3（`crate::tier2a::policy_learnd::etw::scope`）: PIDのトークンがAppContainerかを照会する。
///
/// **プロセスが既に終了していると失敗する**（`None`）。これは仕様であって欠陥ではない——
/// 取りこぼしは境界の欠落を意味しない（P-07）。件数は`ScopeTracker`が数え、制御レコードへ出る。
pub(crate) fn probe_pid_in_container(pid: u32) -> Option<bool> {
    use windows::Win32::Foundation::HANDLE as WinHandle;
    use windows::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut token = WinHandle::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        if !opened {
            let _ = CloseHandle(process);
            return None;
        }
        let mut is_app_container: u32 = 0;
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenIsAppContainer,
            Some(&mut is_app_container as *mut u32 as *mut core::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
        if !ok {
            return None;
        }
        // NOTE: ここではAppContainerであることまでしか見ていない。**このセッションの**
        // package SIDと一致するかの照合は`TokenAppContainerSid`が要るが、それは
        // A-4dの実測でどちらの経路が主になるかを確定してから足す（現状は
        // `ProcessStart`経由の判定が主で、こちらは補助）。
        Some(is_app_container != 0)
    }
}

fn send(pipe: HANDLE, response: &LearnResponse) -> Result<(), LearnError> {
    let bytes = serde_json::to_vec(response)
        .map_err(|e| LearnError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, RESPONSE_WRITE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))
}

#[cfg(test)]
mod flush_batch_record_all_tests {
    use super::*;
    use super::super::etw::session::ProcessStartInfo;
    use harness_config::FsAccess;

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// `harness_pid`起点のブートストラップ（`ScopeTracker`のsignal 2フォールバック）で
    /// 第1世代が対象と判定され、その後の許可・拒否どちらのアクセスも書き出される。
    /// Tier1にはAppContainer signalが無いため、probeクロージャは常に`None`を返す
    /// （`flush_batch_record_all`のdoc参照）——それでもこの経路だけで拾えることを確認する。
    #[test]
    fn writes_both_allowed_and_denied_records_for_in_scope_processes() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let volumes = drive_letter_map();
        let mut unconvertible = 0u64;

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some("cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![
            AccessRecord {
                file_name: r"C:\work\Cargo.toml".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0,
                allowed: true,
                timestamp_unix_ms: 1,
                create_options: 0,
            },
            AccessRecord {
                file_name: r"C:\Windows\System32\secret.dll".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0xC000_0022,
                allowed: false,
                timestamp_unix_ms: 2,
                create_options: 0,
            },
        ];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            starts,
            records,
            &mut unconvertible,
        );

        assert_eq!(written, 2);
        let lines = read_lines(&sink_path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["allowed"], true);
        assert_eq!(lines[0]["reason"], "observed");
        assert_eq!(lines[1]["allowed"], false);
        assert!(lines[1]["reason"]
            .as_str()
            .unwrap()
            .contains("STATUS_ACCESS_DENIED"));
        assert_eq!(unconvertible, 0);
    }

    /// `harness_pid`のブートストラップに繋がらないPID（親子関係が一切分からない）は
    /// `Unknown`判定になり、書き出されない——`InScope`を確認できないものを無条件で
    /// 拾わないことが記録モードの正しさの前提。
    #[test]
    fn unresolved_processes_are_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("");
        let volumes = drive_letter_map();
        let mut unconvertible = 0u64;

        let records = vec![AccessRecord {
            file_name: r"C:\work\Cargo.toml".to_string(),
            pid: 999,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            Vec::new(),
            records,
            &mut unconvertible,
        );

        assert_eq!(written, 0);
        assert!(!sink_path.exists());
    }

    /// 設定へ書けないパス（未知のボリューム）は書かず、件数だけ数える。
    #[test]
    fn unconvertible_paths_are_counted_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let volumes = drive_letter_map();
        let mut unconvertible = 0u64;

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: None,
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![AccessRecord {
            file_name: r"\Device\HarddiskVolume999\unknown.txt".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        let written = flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut ProcessTree::new(),
            &volumes,
            starts,
            records,
            &mut unconvertible,
        );

        assert_eq!(written, 0);
        assert_eq!(unconvertible, 1);
    }

    /// **`parent_process_id`/`image_path`に実際に書き手が居ることの回帰テスト。**
    /// この2つはプロセスツリー表示のために足されたが、当初は代入箇所が本番に1つも無く、
    /// 永久に`None`のままだった（B-01「対の片方だけ実装」）。
    #[test]
    fn records_carry_the_parent_pid_and_image_name_from_process_start() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut unconvertible = 0u64;

        let starts = vec![ProcessStartInfo {
            pid: 200,
            parent_pid: Some(100),
            image_name: Some("cargo.exe".to_string()),
            package_full_name: None,
            process_sequence_number: Some(1),
        }];
        let records = vec![AccessRecord {
            file_name: r"C:\work\Cargo.toml".to_string(),
            pid: 200,
            access: FsAccess::Read,
            status: 0,
            allowed: true,
            timestamp_unix_ms: 1,
            create_options: 0,
        }];

        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            starts,
            records,
            &mut unconvertible,
        );

        let lines = read_lines(&sink_path);
        assert_eq!(lines[0]["process_id"], 200);
        assert_eq!(lines[0]["parent_process_id"], 100);
        assert_eq!(lines[0]["image_path"], "cargo.exe");
    }

    /// **素性はバッチをまたいで生き残る。** プロセスはあるバッチの`ProcessStart`で現れ、
    /// 別のバッチでファイルを触る——`ProcessTree`を関数のローカルにすると、実運用では
    /// ほぼ全件で親PID・画像名が欠落する（`flush_batch_record_all`のdoc参照）。
    #[test]
    fn identities_survive_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("fs-audit.jsonl");
        let mut tracker = ScopeTracker::new("").with_harness_pid(Some(100));
        let mut tree = ProcessTree::new();
        let volumes = drive_letter_map();
        let mut unconvertible = 0u64;

        // バッチ1: ProcessStartだけが届く（アクセスはまだ無い）。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            vec![ProcessStartInfo {
                pid: 200,
                parent_pid: Some(100),
                image_name: Some("rustc.exe".to_string()),
                package_full_name: None,
                process_sequence_number: Some(1),
            }],
            Vec::new(),
            &mut unconvertible,
        );

        // バッチ2: そのプロセスのアクセスだけが届く。
        flush_batch_record_all(
            &sink_path,
            &mut tracker,
            &mut tree,
            &volumes,
            Vec::new(),
            vec![AccessRecord {
                file_name: r"C:\work\src\lib.rs".to_string(),
                pid: 200,
                access: FsAccess::Read,
                status: 0,
                allowed: true,
                timestamp_unix_ms: 2,
                create_options: 0,
            }],
            &mut unconvertible,
        );

        let lines = read_lines(&sink_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["parent_process_id"], 100);
        assert_eq!(lines[0]["image_path"], "rustc.exe");
    }

    /// 記録モードが実際に送る`session_profile`は、昇格側の`validate_request`が使う
    /// `is_session_profile_name`を通らなければならない（通らなければ収集は一度も
    /// 始まらない）。ワイヤ形式テストが提示する名前と、この検証を突き合わせる。
    #[test]
    fn the_profile_name_the_record_mode_sends_passes_the_elevated_side_validation() {
        let name = crate::tier2a::session_profile::current_profile_name();
        assert!(
            crate::tier2a::session_profile::is_session_profile_name(&name),
            "record mode would be rejected by the collector: {name}"
        );
    }
}
