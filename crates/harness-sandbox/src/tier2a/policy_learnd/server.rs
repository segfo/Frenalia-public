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

use super::etw::parse::{to_settings_path, Denial};
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
    let session = match EtwFsSession::start(&session_name) {
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
            let (starts, denials) = session.drain();
            written += flush_batch(
                &sink_path,
                &mut tracker,
                &volumes,
                starts,
                denials,
                &mut unconvertible,
            );
        }
    };

    // 最後の取り残しを回収し、統計を制御レコードとして残す。
    if let Some(session) = session {
        let (starts, denials) = session.drain();
        written += flush_batch(
            &sink_path,
            &mut tracker,
            &volumes,
            starts,
            denials,
            &mut unconvertible,
        );
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
                "unconvertible_paths: {unconvertible} denial(s) had a path that cannot be \
                 expressed in settings (named pipes, unmapped volumes) and were dropped"
            ),
        );
    }
    let unresolved = tracker.unresolved_count();
    if unresolved > 0 {
        append_control(
            sink_path,
            &format!(
                "unresolved_process_scope: {unresolved} denial(s) came from a process that had \
                 already exited, so it could not be attributed to this sandbox and was dropped"
            ),
        );
    }
    if tracker.attributed_by_parentage_count() > 0 {
        append_control(
            sink_path,
            &format!(
                "attributed_by_parentage: {} process(es) were treated as in-scope because their                  parent was harness and the token query did not complete in time (they had                  already exited). This is an inference, not a proof.",
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
