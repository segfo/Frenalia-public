//! Tier3専用の常駐デーモン制御（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.2）。
//!
//! `harness_sandbox::tier2a::netfilterd`と同じ理由で別プロセス・別モジュールにしている: Hyper-V VM + Incus
//! コンテナは`harness`本体プロセスと独立に生存し続けるため（WFPの`FWPM_SESSION_FLAG_DYNAMIC`
//! とは逆の性質）、ゲスト⇄ホストのブローカー役はharnessセッション全体の生存期間中
//! 昇格トークンのまま常駐する必要がある。IPCの配線（named pipe + JSON、
//! `user_only_security_attributes`、`ShellExecuteExW runas`昇格起動、タイムアウト付き
//! overlapped I/O）は`netfilterd.rs`と同一パターンを複製する（要求ライフサイクルが
//! 異なる——2往復固定か、`Exec`を何度でも反復するか——ため汎用化はせず素直に複製する、
//! `netfilterd.rs`モジュールdocと同じ判断）。
//!
//! **プロトコル**（netfilterdの2往復固定とは異なり可変長）:
//! 1. 親→daemon: [`VmRequest::StartSession`] → daemon: [`VmResponse::Ready`]
//!    （VM起動・静的IP疎通待ち・Incus mTLS確認・コンテナ作成/起動・ワークスペースcopy-inまで
//!    完了した状態）
//! 2. 親→daemon: [`VmRequest::Exec`] → daemon: [`VmResponse::ExecResult`]
//!    （`run_shell`が呼ばれるたびに反復。1セッション内で何度でも送れる）
//! 3. 親→daemon: [`VmRequest::Teardown`] → daemon: [`VmResponse::TornDown`] → daemon終了
//!    （ワークスペースcopy-out・コンテナ削除・VM停止/削除・差分VHDX削除まで完了させてから
//!    daemonが自分自身を終了する）
//!
//! **フェイルセーフ**: 親（本体）がクラッシュ等でパイプを閉じずに消えた場合、daemon側の
//! 次のメッセージ待ちが`ERROR_BROKEN_PIPE`で失敗する。これを「親死亡」のシグナルとして扱い、
//! Teardownと同じ撤収シーケンスを実行してから終了する（VM/コンテナ/差分VHDXは`harness`本体と
//! 独立に生存し続けるため、この能動的クリーンアップが唯一の後始末経路——netfilterdの
//! BFE自動削除に相当する保険が無い、`DESIGN-SANDBOX-VMISOLATION.md` §2.2参照）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
    HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AccessCheck, DuplicateToken, SecurityImpersonation, DACL_SECURITY_INFORMATION, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, WaitForSingleObject,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::vmsandbox::{VmSandboxConfig, VmSession};
use harness_sandbox::win_common::wide;

/// 親→daemonへ送るメッセージ。`StartSession`→`Exec`(N回)→`Teardown`の順に送る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmRequest {
    StartSession {
        workspace_root: String,
        /// 出口許可リスト（SNIプロキシ+nftables DNAT、Phase 2）の対象ドメイン。空なら
        /// Phase 1と同じ無制限出口のまま（`--net-allow-domain`未指定時の既定挙動、
        /// `plans/vm-spike/RESULTS.md`§3.8）。
        allow_domains: Vec<String>,
        /// ウォームスタート（`--tier3-warm`、フェーズB）を使うか。既定はfalse（旧クライアント
        /// との後方互換、コールドブートのまま）。
        #[serde(default)]
        warm: bool,
    },
    Exec {
        cmd: String,
        cwd: String,
        env: Vec<(String, String)>,
        timeout_secs: u64,
    },
    Teardown,
    /// GC専用モード（`harness tier3 gc`、A9）でのみ送られる1回きりのリクエスト。
    /// `StartSession`を経由せず、`crate::vmsandbox::gc_orphan_sessions`を実行して
    /// 即座に終了する（D-24、`serve_gc_only`参照）。
    Gc,
    /// [BUG-029] `harness tier3 gc`が常駐daemon（`serve_resident`）へ「本当にセッションが
    /// 実行中か」を問い合わせるための軽量リクエスト。BUG-027対策として`run_gc_only`が
    /// 元々使っていた「固定パイプへ接続できるか」だけの判定は、Phase Bでdaemonが
    /// セッション0件でも無期限に常駐するようになったことで「daemon生存」と「セッション
    /// 実行中」が別の状態になり、常駐daemon運用下でGCが恒久的に拒否される欠陥になっていた
    /// （`docs/bugs/BUG-029.md`）。`StartSession`を経由せず、現在の`SessionRegistry`の
    /// アクティブスロット数を`VmResponse::ActiveSessions`で返すだけの1回きりのリクエスト。
    QueryActiveSessions,
    /// アクティブセッションが無い場合だけ常駐daemonを終了する保守リクエスト。
    ShutdownIfIdle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmResponse {
    Ready,
    ExecResult {
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    TornDown,
    /// `VmRequest::Gc`への応答。撤収を試みたVM名（=session_id）の一覧。
    GcReport {
        reaped_vm_names: Vec<String>,
    },
    /// [BUG-029] `VmRequest::QueryActiveSessions`への応答。このクエリ自身の接続を除いた、
    /// 現在アクティブな`StartSession`セッション数。
    ActiveSessions {
        count: usize,
    },
    ShuttingDown,
    Err(String),
}

#[derive(Debug, thiserror::Error)]
pub enum VmSandboxIpcError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("daemon rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
}

impl From<windows::core::Error> for VmSandboxIpcError {
    fn from(e: windows::core::Error) -> Self {
        VmSandboxIpcError::Win32(e.to_string())
    }
}

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// `StartSession`応答（VM起動+コンテナ起動+workspace copy-in完了）を待つタイムアウト。
/// コールドブート+パッケージ取得を含むため長めに取る（spike実測: VM起動<1分、
/// コンテナ作成初回<15秒程度、`RESULTS.md`参照）。
const START_SESSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// `Teardown`応答（copy-out+VM/コンテナ撤収）を待つタイムアウト。
const TEARDOWN_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// [BUG-029] `QueryActiveSessions`は「本当にセッションが動いているか」を素早く確認するための
/// 軽量な往復専用。`START_SESSION_TIMEOUT`（300秒）をそのまま使うと、daemonが応答しない
/// 異常系（プロトコル不一致・ハング等）で`harness tier3 gc`が最大5分ブロックしてしまうため、
/// 短いタイムアウトを別に用意し、タイムアウト時は安全側（セッション実行中の可能性あり＝拒否）
/// に倒す。
const QUERY_ACTIVE_SESSIONS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// daemon側が次のメッセージ（`Exec`/`Teardown`、または親のクラッシュによるパイプ切断）を
/// 待つ時間。harnessセッションの生存期間そのものに依存するため実質無期限に近い値にする。
const DAEMON_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(u32::MAX as u64);
/// resident daemonがアクティブセッション0件のまま次の接続を待つ時間。期限に達したら
/// 昇格済みdaemonプロセスを終了し、次回Tier3利用時に必要なら再起動する。
const DAEMON_IDLE_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

// 名前付きパイプIPCの下回り（DACL・オーバーラップドI/O・フレーミング）は
// `harness_sandbox::win_pipe_ipc`が持つ。以前はこのファイル・`tier2a/privhelper.rs`・
// `tier2a/netfilterd.rs`の3箇所に同じ一式がコピーされていた。
use harness_sandbox::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout, sid_string_from_token,
    user_only_security_attributes, write_framed_timeout,
};

/// このモジュール用の使い捨てパイプ名（GC経路専用。常駐daemonは`session_daemon_pipe_name`の
/// 固定名を使う）。
fn unique_pipe_name() -> String {
    harness_sandbox::win_pipe_ipc::unique_pipe_name("vmsandboxd")
}

impl From<harness_sandbox::win_pipe_ipc::PipeIpcError> for VmSandboxIpcError {
    fn from(e: harness_sandbox::win_pipe_ipc::PipeIpcError) -> Self {
        VmSandboxIpcError::Ipc(e.into_message())
    }
}
// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則3） ---
//
// 信頼境界をファイル境界に一致させ、「どのコードが昇格した権限で動くのか」「daemonが誰の
// 要求を受け付けるのか」をファイル単位で判別できるようにする。上のワイヤプロトコル型・
// エラー型・タイムアウト定数は3者が共有するためこのモジュールルートに置く。

mod authz;
#[cfg(test)]
use authz::{
    access_check_write, authorize_workspace_root, duplicate_client_token_for_access_check,
    paths_equal_ci, query_process_image_path, query_process_token_sid,
    reject_dangerous_workspace_root, system_root_canonical, verify_pipe_client_identity,
};
mod client;
#[cfg(test)]
use client::{connect_to_pipe_as_client, create_first_pipe_instance, session_daemon_pipe_name};
mod daemon;

pub use client::{
    max_sessions, prepare_pipe, run_gc_only, set_max_sessions, stop_resident_daemon_if_idle,
    PreparedPipe, VmSandboxHandle,
};
pub use daemon::{serve_gc, serve_resident};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_session_request_roundtrips_through_json() {
        let req = VmRequest::StartSession {
            workspace_root: r"C:\work\project".to_string(),
            allow_domains: vec!["example.com".to_string()],
            warm: false,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            VmRequest::StartSession {
                workspace_root,
                allow_domains,
                warm,
            } => {
                assert_eq!(workspace_root, r"C:\work\project");
                assert_eq!(allow_domains, vec!["example.com".to_string()]);
                assert!(!warm);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn start_session_request_with_empty_allow_domains_roundtrips() {
        let req = VmRequest::StartSession {
            workspace_root: r"C:\work\project".to_string(),
            allow_domains: vec![],
            warm: false,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            VmRequest::StartSession { allow_domains, .. } => {
                assert!(allow_domains.is_empty());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn start_session_request_without_warm_field_deserializes_as_not_warm() {
        // 旧クライアント（`warm`未対応）との後方互換: フィールド自体が無いJSONでも
        // `#[serde(default)]`によりfalse扱いでパースできる。
        let legacy =
            r#"{"StartSession":{"workspace_root":"C:\\work\\project","allow_domains":[]}}"#;
        let decoded: VmRequest = serde_json::from_str(legacy).expect("legacy request must parse");
        match decoded {
            VmRequest::StartSession { warm, .. } => assert!(!warm),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn start_session_request_with_warm_true_roundtrips() {
        let req = VmRequest::StartSession {
            workspace_root: r"C:\work\project".to_string(),
            allow_domains: vec![],
            warm: true,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            VmRequest::StartSession { warm, .. } => assert!(warm),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn exec_request_roundtrips_through_json() {
        let req = VmRequest::Exec {
            cmd: "echo hi".to_string(),
            cwd: "/workspace".to_string(),
            env: vec![("FOO".to_string(), "bar".to_string())],
            timeout_secs: 30,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            VmRequest::Exec {
                cmd,
                cwd,
                env,
                timeout_secs,
            } => {
                assert_eq!(cmd, "echo hi");
                assert_eq!(cwd, "/workspace");
                assert_eq!(env, vec![("FOO".to_string(), "bar".to_string())]);
                assert_eq!(timeout_secs, 30);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn teardown_request_roundtrips_through_json() {
        let bytes = serde_json::to_vec(&VmRequest::Teardown).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, VmRequest::Teardown));
    }

    #[test]
    fn responses_roundtrip_through_json() {
        for resp in [
            VmResponse::Ready,
            VmResponse::ExecResult {
                stdout: "out".to_string(),
                stderr: "err".to_string(),
                exit_code: Some(0),
            },
            VmResponse::TornDown,
            VmResponse::Err("boom".to_string()),
        ] {
            let bytes = serde_json::to_vec(&resp).unwrap();
            let decoded: VmResponse = serde_json::from_slice(&bytes).unwrap();
            match (&resp, &decoded) {
                (VmResponse::Ready, VmResponse::Ready) => {}
                (
                    VmResponse::ExecResult {
                        stdout: a,
                        stderr: b,
                        exit_code: c,
                    },
                    VmResponse::ExecResult {
                        stdout: x,
                        stderr: y,
                        exit_code: z,
                    },
                ) => {
                    assert_eq!(a, x);
                    assert_eq!(b, y);
                    assert_eq!(c, z);
                }
                (VmResponse::TornDown, VmResponse::TornDown) => {}
                (VmResponse::Err(a), VmResponse::Err(b)) => assert_eq!(a, b),
                _ => panic!("roundtrip mismatch: {resp:?} vs {decoded:?}"),
            }
        }
    }

    #[test]
    fn malformed_bytes_are_rejected_not_panicking() {
        let garbage = b"{\"not\":\"a valid VmRequest\"}";
        let result = serde_json::from_slice::<VmRequest>(garbage);
        assert!(result.is_err());
    }

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// パイプの配線を、昇格・別プロセス起動・実際のVM/Incus呼び出しなしで検証する
    /// （`netfilterd.rs`の同名テストと同じ手法）。
    #[test]
    fn framed_message_roundtrips_over_a_real_named_pipe() {
        let pipe_name = unique_pipe_name();
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let mut sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");

        let server = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let pipe_name_for_client = pipe_name.clone();
        let client_thread = std::thread::spawn(move || unsafe {
            let pipe_name_w = wide(&pipe_name_for_client);
            CreateFileW(
                PCWSTR(pipe_name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
            .expect("client CreateFileW")
            .0 as usize
        });

        connect_with_timeout(server, short_timeout()).expect("connect_with_timeout");
        let client = HANDLE(client_thread.join().unwrap() as *mut _);

        write_framed_timeout(client, b"hello from client", short_timeout())
            .expect("write_framed_timeout");
        let received = read_framed_timeout(server, short_timeout()).expect("read_framed_timeout");
        assert_eq!(received, b"hello from client");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// (server, client)ともにこのテストプロセス自身が両端を持つ、SID制限付きの接続済み
    /// named pipeを作る（`framed_message_roundtrips_over_a_real_named_pipe`と同じ手法、
    /// S-2の`verify_pipe_client_identity`テスト用）。
    fn make_connected_test_pipe(sid: &str) -> (HANDLE, HANDLE) {
        let pipe_name = unique_pipe_name();
        let mut sa = user_only_security_attributes(sid).expect("user_only_security_attributes");
        let server = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let pipe_name_for_client = pipe_name.clone();
        let client_thread = std::thread::spawn(move || unsafe {
            let pipe_name_w = wide(&pipe_name_for_client);
            CreateFileW(
                PCWSTR(pipe_name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
            .expect("client CreateFileW")
            .0 as usize
        });

        connect_with_timeout(server, short_timeout()).expect("connect_with_timeout");
        let client = HANDLE(client_thread.join().unwrap() as *mut _);
        (server, client)
    }

    /// S2スパイク成功条件1: 「daemonより先にパイプを作った偽サーバがいる場合にクライアントが
    /// 接続を拒否すること」に対応する下位レベルの検証。`create_first_pipe_instance`
    /// （`FILE_FLAG_FIRST_PIPE_INSTANCE`付き）は、同名パイプが既に存在する場合
    /// （＝スクワッティング済み、または正規daemonが既に生存中）は必ず失敗することを確認する。
    #[test]
    fn create_first_pipe_instance_fails_when_name_already_taken() {
        let pipe_name = format!(
            r"\\.\pipe\harness-vmsandboxd-test-squat-{}",
            std::process::id()
        );
        let sid = current_user_sid_string().expect("current_user_sid_string");

        // 「先に同名パイプを作った偽サーバ」を、通常の（FIRST_PIPE_INSTANCEなしの）
        // CreateNamedPipeWで再現する。
        let mut squatter_sa =
            user_only_security_attributes(&sid).expect("user_only_security_attributes");
        let squatter = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut squatter_sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(squatter_sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let mut sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");
        let result = create_first_pipe_instance(&pipe_name, &mut sa);
        unsafe {
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        }
        assert!(
            result.is_err(),
            "expected FIRST_PIPE_INSTANCE creation to fail because the name is already taken"
        );

        unsafe {
            let _ = CloseHandle(squatter);
        }
    }

    /// BUG-027対策（層2）の回帰テスト: 固定の常駐セッションdaemonパイプ
    /// （`session_daemon_pipe_name()`）へ実際に接続できるリスナーを立てた状態で
    /// `run_gc_only()`を呼ぶと、UAC昇格すら発生させずに早期拒否されることを確認する
    /// （`docs/bugs/BUG-027.md`参照）。実VM/Incus/PowerShell呼び出しは一切発生しない
    /// 純粋なIPCテストのため、`#[ignore]`にしない。
    #[test]
    fn run_gc_only_is_rejected_when_a_session_daemon_pipe_is_listening() {
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let mut sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");
        let listener = unsafe {
            let pipe_name_w = wide(session_daemon_pipe_name());
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(
                !handle.is_invalid(),
                "CreateNamedPipeW for the fixed session pipe name"
            );
            handle
        };

        let result = run_gc_only();

        unsafe {
            let _ = CloseHandle(listener);
        }

        match result {
            Err(VmSandboxIpcError::Rejected(msg)) => {
                assert!(
                    msg.contains("session daemon is currently running"),
                    "unexpected rejection message: {msg}"
                );
            }
            other => panic!(
                "expected run_gc_only() to reject with VmSandboxIpcError::Rejected while a \
                 session daemon pipe is listening, got: {other:?}"
            ),
        }
    }

    /// S2スパイク成功条件3の下位レベル検証の一部: SDDLで許可されていないSIDに対しては
    /// 固定パイプへの接続自体がACLレベルで拒否されることを確認する（`user_only_security_attributes`
    /// が組むSDDLが実際に機能していることの回帰テスト）。
    #[test]
    fn connecting_client_is_denied_when_pipe_sddl_grants_a_different_sid() {
        let pipe_name = unique_pipe_name();
        // LocalSystemのwell-known SID。テスト実行ユーザー（管理者で実行していても、
        // トークンのUser SIDは人間のユーザーアカウントのままでLocalSystemとは異なる）とは
        // 常に別物になる。
        let foreign_sid = "S-1-5-18";
        let mut sa =
            user_only_security_attributes(foreign_sid).expect("user_only_security_attributes");
        let server = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let result =
            connect_to_pipe_as_client(&pipe_name, std::time::Duration::from_millis(200), false);
        assert!(
            result.is_err(),
            "expected the current process (different SID) to be denied access by the pipe ACL"
        );

        unsafe {
            let _ = CloseHandle(server);
        }
    }

    #[test]
    fn paths_equal_ci_normalizes_case_and_prefix() {
        assert!(paths_equal_ci(
            std::path::Path::new(r"C:\Foo\Bar.exe"),
            std::path::Path::new(r"c:\foo\bar.exe")
        ));
        assert!(paths_equal_ci(
            std::path::Path::new(r"\\?\C:\Foo\Bar.exe"),
            std::path::Path::new(r"C:\Foo\Bar.exe")
        ));
        assert!(!paths_equal_ci(
            std::path::Path::new(r"C:\Foo\Bar.exe"),
            std::path::Path::new(r"C:\Foo\Baz.exe")
        ));
    }

    #[test]
    fn query_process_image_path_and_token_sid_resolve_for_current_process() {
        let pid = std::process::id();
        let image = query_process_image_path(pid).expect("query_process_image_path");
        let expected = std::env::current_exe().expect("current_exe");
        assert!(paths_equal_ci(&image, &expected));

        let sid = query_process_token_sid(pid).expect("query_process_token_sid");
        let own_sid = current_user_sid_string().expect("current_user_sid_string");
        assert_eq!(sid, own_sid);
    }

    /// S2スパイク成功条件2の下位レベル検証: 正しいSID・正しいイメージパスの相手からの
    /// 接続は`verify_pipe_client_identity`を通過する（このテストプロセス自身がクライアント・
    /// サーバ両方を演じるため、イメージパス・SIDともに一致する）。
    #[test]
    fn verify_pipe_client_identity_accepts_matching_sid_and_image_path() {
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let (server, client) = make_connected_test_pipe(&sid);
        let own_exe = std::env::current_exe().expect("current_exe");

        let result = verify_pipe_client_identity(server, &sid, &own_exe);
        assert!(
            result.is_ok(),
            "expected verification to succeed: {result:?}"
        );
        assert_eq!(result.unwrap(), std::process::id());

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// S2スパイク成功条件2: 「非harnessプロセスからのStartSessionが拒否されること」の
    /// 下位レベル検証。接続元プロセスのイメージパスが期待値（`--owner-exe`で渡された
    /// harness.exeのパス）と一致しない場合は拒否する。
    #[test]
    fn verify_pipe_client_identity_rejects_image_path_mismatch() {
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let (server, client) = make_connected_test_pipe(&sid);
        let unrelated_exe = std::path::Path::new(r"C:\nonexistent\not-harness.exe");

        let result = verify_pipe_client_identity(server, &sid, unrelated_exe);
        assert!(result.is_err(), "expected rejection on image path mismatch");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// S2スパイク成功条件2の下位レベル検証（SID側）: イメージパスが一致していても、
    /// 期待するowner_sidと接続元のトークンSIDが食い違えば拒否する。
    #[test]
    fn verify_pipe_client_identity_rejects_sid_mismatch() {
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let (server, client) = make_connected_test_pipe(&sid);
        let own_exe = std::env::current_exe().expect("current_exe");

        let result = verify_pipe_client_identity(server, "S-1-5-18", &own_exe);
        assert!(result.is_err(), "expected rejection on SID mismatch");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// S-2段階4の拒否リスト: ドライブルートは`parent()`が`None`になるため拒否される。
    #[test]
    fn reject_dangerous_workspace_root_rejects_drive_root() {
        let canonical = std::fs::canonicalize(r"C:\").expect("canonicalize C:\\");
        let result = reject_dangerous_workspace_root(&canonical);
        assert!(
            result.is_err(),
            "expected drive root to be rejected: {result:?}"
        );
    }

    /// S-2段階4の拒否リスト: `%SystemRoot%`配下（`C:\Windows`）は拒否される。
    #[test]
    fn reject_dangerous_workspace_root_rejects_system_root() {
        let system_root = system_root_canonical().expect("SystemRoot must resolve on Windows CI");
        let result = reject_dangerous_workspace_root(&system_root);
        assert!(
            result.is_err(),
            "expected system root to be rejected: {result:?}"
        );

        let system32 = system_root.join("System32");
        if system32.exists() {
            let canonical = std::fs::canonicalize(&system32).expect("canonicalize System32");
            let result = reject_dangerous_workspace_root(&canonical);
            assert!(
                result.is_err(),
                "expected a path under the system root to be rejected: {result:?}"
            );
        }
    }

    /// S-2段階4の拒否リスト: 通常の一時ディレクトリ配下は拒否リストを通過する
    /// （`AccessCheck`側の判定はこのテストの対象外）。
    #[test]
    fn reject_dangerous_workspace_root_allows_ordinary_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");
        let result = reject_dangerous_workspace_root(&canonical);
        assert!(
            result.is_ok(),
            "expected an ordinary directory to be allowed: {result:?}"
        );
    }

    /// S-2段階4の拒否リスト: UNCパス（`canonicalize`後は`\\?\UNC\...`）は拒否される。
    #[test]
    fn reject_dangerous_workspace_root_rejects_unc_path() {
        let unc = std::path::PathBuf::from(r"\\?\UNC\server\share\workspace");
        let result = reject_dangerous_workspace_root(&unc);
        assert!(
            result.is_err(),
            "expected a UNC path to be rejected: {result:?}"
        );
    }

    /// S-2段階4の`AccessCheck`本体: 自プロセス自身のトークン（複製）は、自分が書き込める
    /// 一時ディレクトリへの書き込みアクセスを持つと判定されるべき。
    #[test]
    fn access_check_write_allows_own_process_for_own_temp_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = std::fs::canonicalize(dir.path()).expect("canonicalize tempdir");

        let imp_token = duplicate_client_token_for_access_check(std::process::id())
            .expect("duplicate_client_token_for_access_check");
        let allowed = access_check_write(&canonical, imp_token).expect("access_check_write");
        unsafe {
            let _ = CloseHandle(imp_token);
        }
        assert!(
            allowed,
            "expected own process to have write access to its own temp dir"
        );
    }

    /// S-2段階4の`AccessCheck`本体: 自プロセス自身のトークンは、書き込み権を持たない
    /// `%SystemRoot%`への書き込みアクセスを持たないと判定されるべき（非管理者実行を想定。
    /// 管理者権限でテストを実行している場合はこのテストをスキップする）。
    #[test]
    fn access_check_write_denies_system_root_for_non_admin() {
        if harness_sandbox::tier2a::privhelper::is_elevated() {
            eprintln!("skipping: test process is elevated, System32 write would be allowed");
            return;
        }
        let system_root = system_root_canonical().expect("SystemRoot must resolve on Windows CI");

        let imp_token = duplicate_client_token_for_access_check(std::process::id())
            .expect("duplicate_client_token_for_access_check");
        let allowed = access_check_write(&system_root, imp_token).expect("access_check_write");
        unsafe {
            let _ = CloseHandle(imp_token);
        }
        assert!(
            !allowed,
            "expected a non-admin process to lack write access to SystemRoot"
        );
    }

    /// S-2段階4の統合テスト: 実在する一時ディレクトリは認可を通過する。
    #[test]
    fn authorize_workspace_root_allows_own_temp_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = authorize_workspace_root(std::process::id(), dir.path());
        assert!(
            result.is_ok(),
            "expected own temp dir to be authorized: {result:?}"
        );
    }

    /// S-2段階4の統合テスト: ドライブルートは拒否リストで即座に落ちる。
    #[test]
    fn authorize_workspace_root_rejects_drive_root() {
        let result = authorize_workspace_root(std::process::id(), std::path::Path::new(r"C:\"));
        assert!(
            result.is_err(),
            "expected drive root to be rejected: {result:?}"
        );
    }

    /// S-2段階4の統合テスト: 存在しないパスは`canonicalize`の時点で拒否される。
    #[test]
    fn authorize_workspace_root_rejects_nonexistent_path() {
        let result = authorize_workspace_root(
            std::process::id(),
            std::path::Path::new(r"C:\this-path-should-not-exist-harness-test-12345"),
        );
        assert!(
            result.is_err(),
            "expected a nonexistent path to be rejected: {result:?}"
        );
    }
}
