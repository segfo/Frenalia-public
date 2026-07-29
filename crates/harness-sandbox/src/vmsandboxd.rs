//! Tier3専用の常駐デーモン制御（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.2）。
//!
//! `crate::netfilterd`と同じ理由で別プロセス・別モジュールにしている: Hyper-V VM + Incus
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
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AccessCheck, DuplicateToken, GetTokenInformation, SecurityImpersonation, TokenUser,
    DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::vmsandbox::{VmSandboxConfig, VmSession};
use crate::win_common::wide;

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

/// トークンハンドルからSDDL文字列表現のSIDを取り出す共通ロジック（`current_user_sid_string`・
/// `query_process_token_sid`（S-2、クライアント身元検証）の両方が使う）。
fn sid_string_from_token(token: HANDLE) -> windows::core::Result<String> {
    unsafe {
        let mut ret_len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        )?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = crate::win_common::pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
}

fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )?;
        let result = sid_string_from_token(token);
        let _ = CloseHandle(token);
        result
    }
}

/// 指定PIDのプロセスのトークンSIDを取得する（S-2、`verify_pipe_client_identity`専用）。
/// `process_is_alive`（`vmsandbox.rs`）と同じ`PROCESS_QUERY_LIMITED_INFORMATION`で
/// `OpenProcess`する（daemonは昇格済みトークンで動作しており、同一ユーザーの他プロセスを
/// 開くのに十分な権限を持つ）。
fn query_process_token_sid(pid: u32) -> Result<String, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut token = HANDLE::default();
        let open_result =
            OpenProcessToken(process, windows::Win32::Security::TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        open_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcessToken({pid}) failed: {e}")))?;
        let result = sid_string_from_token(token).map_err(|e| {
            VmSandboxIpcError::Ipc(format!("sid_string_from_token({pid}) failed: {e}"))
        });
        let _ = CloseHandle(token);
        result
    }
}

/// 指定PIDのプロセスの実行イメージの絶対パスを取得する（S-2、`verify_pipe_client_identity`・
/// `verify_pipe_server_identity`共用）。
fn query_process_image_path(pid: u32) -> Result<PathBuf, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(process);
        result.map_err(|e| {
            VmSandboxIpcError::Ipc(format!("QueryFullProcessImageNameW({pid}) failed: {e}"))
        })?;
        buf.truncate(len as usize);
        Ok(PathBuf::from(String::from_utf16_lossy(&buf)))
    }
}

/// `\\?\`プレフィックスの有無・大文字小文字ゆれを無視してパスを比較する（S-2、
/// `QueryFullProcessImageNameW`は`PROCESS_NAME_WIN32`指定時プレフィックス無しの
/// パスを返すが、`std::env::current_exe()`側が付ける可能性もあるため両対応する）。
fn paths_equal_ci(a: &Path, b: &Path) -> bool {
    fn normalize(p: &Path) -> String {
        let s = p.to_string_lossy();
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_lowercase()
    }
    normalize(a) == normalize(b)
}

/// daemon側(サーバ)が、`ConnectNamedPipe`成功後に接続してきたクライアントの身元を検証する
/// （S-2）。固定パイプ名化により「パイプ名を知っている」こと自体は認可根拠として機能しなく
/// なるため、(a)対向プロセスの実行イメージパスが起動元harness.exeと一致すること、
/// (b)対向プロセスのトークンSIDが起動元ユーザーのSID(`owner_sid`)と一致すること、の両方を
/// 確認する。(b)はパイプのSDDLと独立した二重チェック（defense-in-depth）。
/// `ImpersonateNamedPipeClient`は意図的に使わない: daemonは既に昇格済みトークンで動作して
/// おり、クライアント側権限へ降格する理由も必要もない。
fn verify_pipe_client_identity(
    pipe: HANDLE,
    owner_sid: &str,
    expected_owner_exe: &Path,
) -> Result<u32, VmSandboxIpcError> {
    let mut client_pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) }
        .map_err(|e| VmSandboxIpcError::Ipc(format!("GetNamedPipeClientProcessId failed: {e}")))?;

    let image_path = query_process_image_path(client_pid)?;
    if !paths_equal_ci(&image_path, expected_owner_exe) {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} image path mismatch: got {image_path:?}, expected \
             {expected_owner_exe:?}"
        )));
    }

    let client_sid = query_process_token_sid(client_pid)?;
    if client_sid != owner_sid {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} sid mismatch: got {client_sid}, expected {owner_sid}"
        )));
    }

    Ok(client_pid)
}

/// 親側(クライアント)が、固定パイプへの接続先が本当に正規daemonかをbest-effortで確認する
/// （S-2、パイプスクワッティングへの第一関門）。named pipeにはクライアントがサーバの正当性を
/// 検証する標準APIが無いため、これは診断的な早期拒否に留まる——真の防御は
/// [`verify_pipe_client_identity`]側（daemonが接続してきたクライアントを検証する）にある。
fn verify_pipe_server_identity(
    pipe: HANDLE,
    expected_daemon_exe: &Path,
) -> Result<(), VmSandboxIpcError> {
    let mut server_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) }
        .map_err(|e| VmSandboxIpcError::Ipc(format!("GetNamedPipeServerProcessId failed: {e}")))?;
    let image_path = query_process_image_path(server_pid)?;
    if !paths_equal_ci(&image_path, expected_daemon_exe) {
        return Err(VmSandboxIpcError::Rejected(format!(
            "pipe server pid {server_pid} image path mismatch (possible squatting): got \
             {image_path:?}, expected {expected_daemon_exe:?}"
        )));
    }
    Ok(())
}

/// `%SystemRoot%`（通常`C:\Windows`）を正規化して返す（S-2段階4、
/// [`reject_dangerous_workspace_root`]専用）。環境変数が読めない場合は`None`を返し、
/// この一件だけで拒否判定をスキップする（`AccessCheck`側が最終防衛線であるため）。
fn system_root_canonical() -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot")?;
    std::fs::canonicalize(root).ok()
}

/// `\\?\`プレフィックスを剥がした文字列表現（[`paths_equal_ci`]のnormalizeと同じ考え方、
/// 拒否リストの判定・エラーメッセージ用）。
fn strip_verbatim_prefix(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// `workspace_root`がドライブルート・システムディレクトリ・UNC/ネットワークパスでないことを
/// 確認する（S-2段階4、拒否リスト。`DESIGN-SANDBOX-VMISOLATION.md`7-a参照）。
/// 認可の本体は[`authorize_workspace_root`]の`AccessCheck`側であり、この関数は
/// 「`AccessCheck`が通ってしまう病的なDACLのマシン」に備えた belt-and-braces に過ぎない。
fn reject_dangerous_workspace_root(canonical: &Path) -> Result<(), VmSandboxIpcError> {
    let stripped = strip_verbatim_prefix(canonical);

    // `canonicalize`はUNCパスを`\\?\UNC\server\share`へ正規化する。
    if stripped.starts_with(r"UNC\") || stripped.starts_with(r"\\") {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root must not be a UNC/network path: {stripped}"
        )));
    }

    // ドライブルート（`C:\`等）は`parent()`が`None`になる（プレフィックス+ルート以外の
    // 構成要素を持たないパス）。
    if canonical.parent().is_none() {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root must not be a drive root: {stripped}"
        )));
    }

    if let Some(system_root) = system_root_canonical() {
        if canonical.starts_with(&system_root) {
            return Err(VmSandboxIpcError::Rejected(format!(
                "workspace_root must not be inside the Windows system directory: {stripped}"
            )));
        }
    }

    Ok(())
}

/// クライアントプロセスのトークンを複製し、`AccessCheck`専用のimpersonationレベルトークンを
/// 得る（S-2段階4）。**`ImpersonateNamedPipeClient`は使わない**——ここで作るトークンは
/// [`access_check_write`]（`AccessCheck`Win32 APIの入力）としてのみ渡し、daemon自身の
/// スレッドをクライアント権限へ実際に偽装することはしない。段階3で明記した方針
/// （`verify_pipe_client_identity`のdoc参照）と同じ理由。
fn duplicate_client_token_for_access_check(pid: u32) -> Result<HANDLE, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut token = HANDLE::default();
        let open_result = OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token);
        let _ = CloseHandle(process);
        open_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcessToken({pid}) failed: {e}")))?;

        let mut imp_token = HANDLE::default();
        let dup_result = DuplicateToken(token, SecurityImpersonation, &mut imp_token);
        let _ = CloseHandle(token);
        dup_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("DuplicateToken({pid}) failed: {e}")))?;
        Ok(imp_token)
    }
}

/// `path`（ファイルオブジェクト）に対して、`token`（impersonationレベル）が書き込みアクセス
/// （`FILE_GENERIC_WRITE`）を持つかを`AccessCheck`で判定する（S-2段階4本体）。
fn access_check_write(path: &Path, token: HANDLE) -> Result<bool, VmSandboxIpcError> {
    unsafe {
        let path_w = wide(&path.to_string_lossy());
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
        .ok()
        .map_err(|e| {
            VmSandboxIpcError::Ipc(format!("GetNamedSecurityInfoW({path:?}) failed: {e}"))
        })?;

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ.0,
            GenericWrite: FILE_GENERIC_WRITE.0,
            GenericExecute: FILE_GENERIC_EXECUTE.0,
            GenericAll: FILE_ALL_ACCESS.0,
        };

        let mut privilege_set_buf = [0u8; 1024];
        let mut privilege_set_len = privilege_set_buf.len() as u32;
        let mut granted_access = 0u32;
        let mut access_status = windows::Win32::Foundation::BOOL(0);

        let result = AccessCheck(
            sd,
            token,
            FILE_GENERIC_WRITE.0,
            &mapping,
            Some(privilege_set_buf.as_mut_ptr() as *mut PRIVILEGE_SET),
            &mut privilege_set_len,
            &mut granted_access,
            &mut access_status,
        );
        let _ = LocalFree(HLOCAL(sd.0));
        result.map_err(|e| VmSandboxIpcError::Ipc(format!("AccessCheck({path:?}) failed: {e}")))?;
        Ok(access_status.as_bool())
    }
}

/// `workspace_root`が (a) 実在するディレクトリで、(b) ドライブルート・システムディレクトリ・
/// UNC/ネットワークパスでなく、(c) 接続元クライアントのトークンが既に書き込み権を持つ、
/// の3点を満たすことを確認する（S-2段階4、`DESIGN-SANDBOX-VMISOLATION.md`7-a）。
///
/// [`verify_pipe_client_identity`]が「接続してきたのが正規`harness.exe`である」ことを
/// 検証するのに対し、本関数は「その`harness.exe`が要求している`workspace_root`へ既に
/// アクセス権を持っているか」を検証する——別の不変条件であり、互いを代替しない。固定パイプ名化
/// により同一ユーザーの任意の`harness.exe`起動から`StartSession`が送られ得るようになった以上、
/// 「呼び出し元が既に持つ権限を超えさせない」という不変条件がここでの唯一の実質的な認可点になる
/// （nonceハンドシェイクを不採用とした根拠、同文書7-b参照）。
fn authorize_workspace_root(
    client_pid: u32,
    workspace_root: &Path,
) -> Result<(), VmSandboxIpcError> {
    let canonical = std::fs::canonicalize(workspace_root).map_err(|e| {
        VmSandboxIpcError::Rejected(format!(
            "workspace_root does not exist or is not accessible: {workspace_root:?}: {e}"
        ))
    })?;
    if !canonical.is_dir() {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root is not a directory: {canonical:?}"
        )));
    }

    reject_dangerous_workspace_root(&canonical)?;

    let imp_token = duplicate_client_token_for_access_check(client_pid)?;
    let allowed = access_check_write(&canonical, imp_token);
    unsafe {
        let _ = CloseHandle(imp_token);
    }
    if !allowed? {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} does not have write access to workspace_root: {canonical:?}"
        )));
    }
    Ok(())
}

fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
    let sddl = format!("D:(A;;GA;;;{sid})");
    unsafe {
        let sddl_w = wide(&sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        Ok(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        })
    }
}

/// 常駐セッションdaemonの固定named pipe名（S-2）。パイプの向きを反転させ常駐daemonが
/// サーバになるため、GC専用の使い捨て名（[`unique_pipe_name`]、GC経路は変更なし）とは別に
/// 固定名を用意する。同一ユーザーの誰でも名前を知り得る前提で、
/// [`user_only_security_attributes`]のSDDL・[`verify_pipe_client_identity`]の身元検証と
/// あわせて認可を成立させる。
fn session_daemon_pipe_name() -> &'static str {
    r"\\.\pipe\harness-vmsandboxd-session"
}

fn unique_pipe_name() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        r"\\.\pipe\harness-vmsandboxd-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

fn run_overlapped<F>(
    handle: HANDLE,
    timeout: std::time::Duration,
    op_name: &str,
    start: F,
) -> Result<u32, VmSandboxIpcError>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, PCWSTR::null())
            .map_err(|e| VmSandboxIpcError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };

        let pending = match start(&mut overlapped as *mut _) {
            Ok(()) => false,
            Err(e) => {
                let code = e.code();
                if code == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) {
                    true
                } else if code == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                    // クライアントが`ConnectNamedPipe`呼び出し前に既に接続済みだった場合。
                    // `netfilterd.rs`で実機発見・修正した既知の競合と同じ（モジュールdoc参照）。
                    let _ = CloseHandle(event);
                    return Ok(0);
                } else {
                    let _ = CloseHandle(event);
                    return Err(VmSandboxIpcError::Ipc(format!(
                        "{op_name} failed to start: {e}"
                    )));
                }
            }
        };

        if pending {
            let wait = WaitForSingleObject(event, timeout.as_millis().min(u32::MAX as u128) as u32);
            if wait != WAIT_OBJECT_0 {
                let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                let mut transferred = 0u32;
                let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                let _ = CloseHandle(event);
                return Err(VmSandboxIpcError::Ipc(format!(
                    "{op_name} timed out after {timeout:?}"
                )));
            }
        }

        let mut transferred = 0u32;
        let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
        let _ = CloseHandle(event);
        result.map_err(|e| {
            VmSandboxIpcError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}"))
        })?;
        Ok(transferred)
    }
}

fn connect_with_timeout(
    pipe: HANDLE,
    timeout: std::time::Duration,
) -> Result<(), VmSandboxIpcError> {
    run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
        ConnectNamedPipe(pipe, Some(ov))
    })?;
    Ok(())
}

fn write_all_timeout(
    handle: HANDLE,
    buf: &[u8],
    timeout: std::time::Duration,
) -> Result<(), VmSandboxIpcError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &buf[offset..];
        let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
            WriteFile(handle, Some(slice), None, Some(ov))
        })?;
        if written == 0 {
            return Err(VmSandboxIpcError::Ipc(
                "WriteFile wrote 0 bytes".to_string(),
            ));
        }
        offset += written as usize;
    }
    Ok(())
}

fn read_exact_timeout(
    handle: HANDLE,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> Result<(), VmSandboxIpcError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &mut buf[offset..];
        let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
            ReadFile(handle, Some(slice), None, Some(ov))
        })?;
        if read == 0 {
            return Err(VmSandboxIpcError::Ipc(
                "ReadFile read 0 bytes (pipe closed?)".to_string(),
            ));
        }
        offset += read as usize;
    }
    Ok(())
}

fn write_framed_timeout(
    handle: HANDLE,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<(), VmSandboxIpcError> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all_timeout(handle, &len, timeout)?;
    write_all_timeout(handle, payload, timeout)?;
    Ok(())
}

fn read_framed_timeout(
    handle: HANDLE,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, VmSandboxIpcError> {
    let mut len_buf = [0u8; 4];
    read_exact_timeout(handle, &mut len_buf, timeout)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_timeout(handle, &mut payload, timeout)?;
    }
    Ok(payload)
}

fn daemon_exe_path() -> Result<PathBuf, VmSandboxIpcError> {
    let current = std::env::current_exe()
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| VmSandboxIpcError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-vmsandboxd.exe"))
}

unsafe fn launch_daemon_elevated(
    daemon_path: &std::path::Path,
    params: &str,
) -> Result<HANDLE, VmSandboxIpcError> {
    let verb_w = wide("runas");
    let file_w = wide(&daemon_path.to_string_lossy());
    let params_w = wide(params);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let ok = ShellExecuteExW(&mut info);
    if ok.is_err() {
        let err = GetLastError();
        if err == ERROR_CANCELLED {
            return Err(VmSandboxIpcError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(VmSandboxIpcError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }

    Ok(info.hProcess)
}

/// 常駐daemonへの接続を表す。`stop`を呼ぶまでパイプ・プロセスハンドルを保持し続ける
/// （＝VM+コンテナが起動し続ける）。呼び出し側（`harness-cli`）はharnessセッション全体
/// （複数の`run_shell`呼び出しにまたがる）の生存期間中これを保持し、セッション終了時に
/// `stop`を呼ぶ。
pub struct VmSandboxHandle {
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    /// `harness_core::VmShellExecutor::exec`（`cwd: &Path`が絶対ホストパス）を、IPC上の
    /// 相対パス文字列（daemon側が`workspace_root.join(..)`で復元する）へ変換するために保持する。
    workspace_root: PathBuf,
    /// [`Self::stop`]が完了済みかを示すフラグ（`&self`で複数回呼ばれても実際のIPC
    /// ラウンドトリップとハンドルクローズは1回だけに抑える、[`Self::stop`]のdoc参照）。
    stopped: std::sync::atomic::AtomicBool,
}

unsafe impl Send for VmSandboxHandle {}
unsafe impl Sync for VmSandboxHandle {}

impl std::fmt::Debug for VmSandboxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmSandboxHandle").finish_non_exhaustive()
    }
}

/// [`prepare_pipe`]の返り値。`netfilterd::PreparedPipe`と同じ役割（呼び出し元が`windows`
/// クレートへ直接依存せずに済む、未消費のままドロップされたら自動的にパイプを閉じる）。
pub struct PreparedPipe {
    handle: HANDLE,
    name: String,
}

unsafe impl Send for PreparedPipe {}

impl PreparedPipe {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn into_handle(self) -> HANDLE {
        let handle = self.handle;
        std::mem::forget(self);
        handle
    }
}

impl Drop for PreparedPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

pub fn prepare_pipe() -> Result<PreparedPipe, VmSandboxIpcError> {
    let pipe_name = unique_pipe_name();
    let sid = current_user_sid_string()?;
    let mut sa = user_only_security_attributes(&sid)?;

    let pipe = unsafe {
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
        if handle.is_invalid() {
            return Err(VmSandboxIpcError::from(windows::core::Error::from_win32()));
        }
        handle
    };
    Ok(PreparedPipe {
        handle: pipe,
        name: pipe_name,
    })
}

/// 常駐セッションdaemon用の固定パイプの最初のインスタンスを作る（S-2）。
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`により、既に同名パイプが存在する場合（正規daemonが
/// 既に生存中、または同一ユーザーの別プロセスによるスクワッティング）は`ERROR_ACCESS_DENIED`
/// で確実に失敗する——`CreateNamedPipeW`単体では名前の衝突があっても新規インスタンスとして
/// 静かに成功してしまう場合があるため、このフラグが「自分が最初の所有者である」ことを
/// OSに強制させる唯一の手段。
fn create_first_pipe_instance(
    pipe_name: &str,
    sa: &mut SECURITY_ATTRIBUTES,
) -> windows::core::Result<HANDLE> {
    unsafe {
        let pipe_name_w = wide(pipe_name);
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            Some(sa as *mut _),
        );
        if handle.is_invalid() {
            Err(windows::core::Error::from_win32())
        } else {
            Ok(handle)
        }
    }
}

/// 最初のインスタンス確立後、後続セッションを受け付けるための追加インスタンスを作る（S-2）。
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`は付けない（最初の1回で一意性は既に確定済みのため）。
fn create_additional_pipe_instance(
    pipe_name: &str,
    sa: &mut SECURITY_ATTRIBUTES,
) -> windows::core::Result<HANDLE> {
    unsafe {
        let pipe_name_w = wide(pipe_name);
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            Some(sa as *mut _),
        );
        if handle.is_invalid() {
            Err(windows::core::Error::from_win32())
        } else {
            Ok(handle)
        }
    }
}

/// 親側(クライアント)が固定パイプへ接続する（S-2、パイプの向き反転後の接続方向）。
/// `ERROR_PIPE_BUSY`（daemonは生存しているが全インスタンスが埋まっている、複数クライアントの
/// レース）は`WaitNamedPipeW`で空きを待って自動リトライする。
///
/// `ERROR_FILE_NOT_FOUND`（パイプ自体が存在しない）の扱いは`retry_on_not_found`で分岐する。
/// **Phase B実機E2Eで発見したバグ**: 従来は`ERROR_FILE_NOT_FOUND`を即座に呼び出し元へ返して
/// いたが、これは「daemon起動待ちの30秒（`CONNECT_TIMEOUT`）」呼び出しでは誤りだった——
/// `launch_daemon_elevated`直後、昇格daemonが実際に`create_first_pipe_instance`へ到達する
/// までの間（UAC操作・プロセス起動・アンチウイルススキャン等）はパイプ自体がまだ存在しない
/// ため`ERROR_FILE_NOT_FOUND`になり、`CONNECT_TIMEOUT`が謳う「30秒待つ」を実質1回の即時失敗に
/// 縮退させていた。2つの`harness.exe`をほぼ同時に起動するE2Eで実際に踏んだ（一方の昇格daemon
/// が`FILE_FLAG_FIRST_PIPE_INSTANCE`で敗れて即終了する一方、勝った側のdaemonがまだパイプを
/// 作り切っていないタイミングで負けた側のクライアントがこの関数を呼ぶと、即座に諦めてしまう）。
/// `retry_on_not_found: true`ならポーリング（200ms間隔）で`timeout`まで待つ。`false`
/// （daemon未起動かどうかを即座に判定したい200msのクイックチェック用）は従来通り即座に返す。
fn connect_to_pipe_as_client(
    pipe_name: &str,
    timeout: std::time::Duration,
    retry_on_not_found: bool,
) -> Result<HANDLE, VmSandboxIpcError> {
    let pipe_name_w = wide(pipe_name);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let attempt = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
        };
        match attempt {
            Ok(h) => return Ok(h),
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_PIPE_BUSY.0) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(VmSandboxIpcError::from(e));
                }
                let remaining = deadline - now;
                unsafe {
                    let _ = WaitNamedPipeW(
                        PCWSTR(pipe_name_w.as_ptr()),
                        remaining.as_millis().min(u32::MAX as u128) as u32,
                    );
                }
            }
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
                if !retry_on_not_found {
                    return Err(VmSandboxIpcError::from(e));
                }
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(VmSandboxIpcError::from(e));
                }
                std::thread::sleep(std::time::Duration::from_millis(200).min(deadline - now));
            }
            Err(e) => return Err(VmSandboxIpcError::from(e)),
        }
    }
}

fn connect_and_start_session(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    workspace_root_str: String,
    allow_domains: Vec<String>,
    warm: bool,
) -> Result<VmSandboxHandle, VmSandboxIpcError> {
    // S-2でパイプの向きが反転して以降、親側は`CreateFileW`（クライアント）で既に接続済みの
    // 状態でここへ来る。旧モデル（親=サーバ）の`ConnectNamedPipe`待ちはもう不要。
    let workspace_root = PathBuf::from(&workspace_root_str);

    let req = VmRequest::StartSession {
        workspace_root: workspace_root_str,
        allow_domains,
        warm,
    };
    let start_result = (|| -> Result<(), VmSandboxIpcError> {
        let bytes = serde_json::to_vec(&req)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize request: {e}")))?;
        write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
        let response: VmResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse response: {e}")))?;
        match response {
            VmResponse::Ready => Ok(()),
            VmResponse::Err(msg) => Err(VmSandboxIpcError::Rejected(msg)),
            other => Err(VmSandboxIpcError::Ipc(format!(
                "unexpected response for StartSession: {other:?}"
            ))),
        }
    })();

    match start_result {
        Ok(()) => Ok(VmSandboxHandle {
            pipe,
            daemon_process,
            workspace_root,
            stopped: std::sync::atomic::AtomicBool::new(false),
        }),
        Err(e) => {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
                if let Some(h) = daemon_process {
                    let _ = CloseHandle(h);
                }
            }
            Err(e)
        }
    }
}

impl VmSandboxHandle {
    /// 常駐daemonの固定パイプへ接続し、（未起動なら昇格起動してから）`StartSession`を送って
    /// 応答を待つ（親側、非管理者本体から呼ぶ、S-2でパイプの向きが反転）。`allow_domains`は
    /// 既存の`net_proxy.allow_domains`（`--net-allow-domain`+`.harness/settings.json`
    /// 統合済み、WFPが既に使っているのと同じ値）をそのまま渡す。`warm`は`--tier3-warm`
    /// （フェーズB）の値をそのまま渡す。`max_sessions`は**daemon未起動時の昇格起動にのみ
    /// 使われる**（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）——既に常駐daemonが生きている
    /// 場合、この値は無視される（後から接続する2本目以降が上限を書き換えられては意味が
    /// 無いため、daemon起動時の引数としてのみ受け付ける設計）。
    pub fn start(
        workspace_root: &std::path::Path,
        allow_domains: &[String],
        warm: bool,
        max_sessions: u8,
    ) -> Result<Self, VmSandboxIpcError> {
        let owner_sid = current_user_sid_string().map_err(|e| {
            VmSandboxIpcError::Ipc(format!("failed to resolve current user SID: {e}"))
        })?;
        let owner_exe = std::env::current_exe()
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to resolve current exe: {e}")))?;
        let daemon_path = daemon_exe_path()?;
        let pipe_name = session_daemon_pipe_name();

        // まず既に常駐daemonが生きているか、短いタイムアウトで試す（複数セッション目は
        // これで即座に繋がる想定）。`ERROR_FILE_NOT_FOUND`ならdaemon未起動とみなし、
        // 昇格起動してから改めて接続を待つ。
        let (pipe, daemon_process) = match connect_to_pipe_as_client(
            pipe_name,
            std::time::Duration::from_millis(200),
            false,
        ) {
            Ok(pipe) => (pipe, None),
            Err(_) => {
                let params = format!(
                        "{pipe_name} --owner-sid {owner_sid} --owner-exe \"{}\" --max-sessions {max_sessions}",
                        owner_exe.display()
                    );
                let daemon_process = unsafe { launch_daemon_elevated(&daemon_path, &params) }?;
                // `retry_on_not_found: true`——ここは昇格daemonの起動を待つ経路であり、
                // パイプがまだ存在しない（`ERROR_FILE_NOT_FOUND`）ことも起動途中の正常な
                // 状態として`CONNECT_TIMEOUT`いっぱいまでポーリングする（バグ修正、
                // モジュール内`connect_to_pipe_as_client`のdoc参照）。
                match connect_to_pipe_as_client(pipe_name, CONNECT_TIMEOUT, true) {
                    Ok(pipe) => (pipe, Some(daemon_process)),
                    Err(e) => {
                        unsafe {
                            let _ = CloseHandle(daemon_process);
                        }
                        return Err(VmSandboxIpcError::Ipc(format!(
                            "waiting for vmsandboxd to accept the connection: {e} (daemon \
                                 may not have launched, or UAC is still pending user \
                                 interaction)"
                        )));
                    }
                }
            }
        };

        // パイプスクワッティング対策の第一関門（S-2）: 接続先が本当に正規daemonかを
        // best-effortで確認する。失敗時はフォールバック再接続をしない（攻撃者にリトライの
        // 余地を与えるだけなので、ここで明示エラーを返して止める）。
        if let Err(e) = verify_pipe_server_identity(pipe, &daemon_path) {
            unsafe {
                let _ = CloseHandle(pipe);
                if let Some(h) = daemon_process {
                    let _ = CloseHandle(h);
                }
            }
            return Err(e);
        }

        connect_and_start_session(
            pipe,
            daemon_process,
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
            warm,
        )
    }

    /// 既に（特権分離ヘルパー経由で）daemonへの接続が確立済みのパイプで`StartSession`を送る
    /// （`netfilterd::NetfilterHandle::connect_after_chain_launch`と同型。Phase 1では
    /// `harness-cli`から未使用だが、`privhelper`連鎖起動シナリオへ将来組み込む余地を残す）。
    /// S-2でパイプの向きが反転したため、渡す`pipe`は呼び出し側が`connect_to_pipe_as_client`
    /// 相当で既に接続済みであることが前提（本関数はもう`ConnectNamedPipe`を待たない）。
    pub fn connect_after_chain_launch(
        pipe: HANDLE,
        workspace_root: &std::path::Path,
        allow_domains: &[String],
        warm: bool,
    ) -> Result<Self, VmSandboxIpcError> {
        connect_and_start_session(
            pipe,
            None,
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
            warm,
        )
    }

    /// `harness_core::VmShellExecutor::exec`（`ToolCtx.vm_sandbox`経由の呼び出し）専用の内部関数。
    /// `cwd`（絶対ホストパス）をワークスペースルート相対の文字列へ変換してから[`Self::exec_ipc`]
    /// を呼ぶ。トレイト実装から共有するためここに切り出す。
    fn exec_for_trait(
        &self,
        cmd: &str,
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        let rel = cwd
            .strip_prefix(&self.workspace_root)
            .unwrap_or(std::path::Path::new(""));
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        self.exec_ipc(cmd, &rel_str, env.to_vec(), timeout)
            .map_err(|e| e.to_string())
    }

    /// `Exec`を送って応答を待つ（`run_shell`呼び出しのたびに反復）。`cwd`はワークスペース
    /// ルートからの相対パス文字列（daemon側で`workspace_root.join(..)`により復元される）。
    /// `harness_core::VmShellExecutor`実装（下記`impl`）はこれを、絶対ホストパスからの
    /// 変換込みで呼び出す。
    pub fn exec_ipc(
        &self,
        cmd: &str,
        cwd: &str,
        env: Vec<(String, String)>,
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), VmSandboxIpcError> {
        let req = VmRequest::Exec {
            cmd: cmd.to_string(),
            cwd: cwd.to_string(),
            env,
            timeout_secs: timeout.as_secs(),
        };
        let bytes = serde_json::to_vec(&req).map_err(|e| {
            VmSandboxIpcError::Ipc(format!("failed to serialize exec request: {e}"))
        })?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        // execのタイムアウト自体はdaemon側（`vmsandbox::VmSession::exec`）が守る。IPC応答待ちは
        // それより少し長めに取り、daemon側タイムアウト超過を先に検知できるようにする。
        let response_bytes =
            read_framed_timeout(self.pipe, timeout + std::time::Duration::from_secs(30))?;
        let response: VmResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse exec response: {e}")))?;
        match response {
            VmResponse::ExecResult {
                stdout,
                stderr,
                exit_code,
            } => Ok((stdout, stderr, exit_code)),
            VmResponse::Err(msg) => Err(VmSandboxIpcError::Rejected(msg)),
            other => Err(VmSandboxIpcError::Ipc(format!(
                "unexpected response for Exec: {other:?}"
            ))),
        }
    }

    /// `Teardown`を送ってdaemonの終了を待つ（harnessセッション終了時、正常系）。`&self`を
    /// 取る（`netfilterd::NetfilterHandle::stop`とは異なり所有権を消費しない）: `ToolCtx`が
    /// `Arc<dyn VmShellExecutor>`として共有する都合上、`harness-cli`側は`Arc<VmSandboxHandle>`
    /// （具象型、`Arc<dyn Trait>`は`Arc::try_unwrap`が使えず所有権を取り戻せないため）を
    /// 別途保持してteardownを呼ぶ。`stopped`フラグで多重呼び出し・`Drop`との競合を防ぐ
    /// （ハンドルのクローズ自体は`Drop`に一本化し、ここではIPCラウンドトリップのみ行う）。
    pub fn stop(&self) -> Result<(), VmSandboxIpcError> {
        if self.stopped.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Ok(()); // 既にstop済み（Dropもこのフラグを見て二重終了操作を避ける）。
        }

        let result = (|| -> Result<(), VmSandboxIpcError> {
            let bytes = serde_json::to_vec(&VmRequest::Teardown).map_err(|e| {
                VmSandboxIpcError::Ipc(format!("failed to serialize teardown: {e}"))
            })?;
            write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
            let response_bytes = read_framed_timeout(self.pipe, TEARDOWN_RESPONSE_TIMEOUT)?;
            let response: VmResponse = serde_json::from_slice(&response_bytes)
                .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse response: {e}")))?;
            match response {
                VmResponse::TornDown => Ok(()),
                VmResponse::Err(msg) => Err(VmSandboxIpcError::Rejected(msg)),
                other => Err(VmSandboxIpcError::Ipc(format!(
                    "unexpected response for Teardown: {other:?}"
                ))),
            }
        })();

        unsafe {
            let _ = DisconnectNamedPipe(self.pipe);
            // S-2でdaemonが常駐化して以降、`Teardown`後もdaemonプロセス自体は終了せず
            // 次のセッションの接続を待ち続ける（`serve_resident`参照）。旧モデル（1セッション=
            // 1回きりのdaemon起動）ではTeardown後にプロセスが自然終了する前提で
            // `TerminateProcess`フォールバックが要ったが、常駐化後はこの待機/強制終了が
            // 他セッションを誤って巻き添えにするリスクの方が大きいため撤去する。
            if let Some(daemon_process) = self.daemon_process {
                let _ = CloseHandle(daemon_process);
            }
        }

        result
    }
}

impl Drop for VmSandboxHandle {
    /// ハンドルのクローズを一手に引き受ける（[`VmSandboxHandle::stop`]は`&self`で呼べる都合上、
    /// パイプ/プロセスハンドルの所有権を手放せないため）。`stop`を呼ばずにドロップされた場合
    /// （異常系）は、パイプを閉じるだけでdaemonへ通知したことになる——daemon側は次の
    /// メッセージ待ちが`ERROR_BROKEN_PIPE`で失敗し、フェイルセーフのteardown経路
    /// （モジュールdoc参照）へ入る。`stop`が既に呼ばれていた場合は`DisconnectNamedPipe`が
    /// 二重に呼ばれるだけ（無害、既に切断済みのパイプに対しては単にエラーを返すのみ）。
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe);
            let _ = CloseHandle(self.pipe);
            if let Some(daemon_process) = self.daemon_process {
                let _ = CloseHandle(daemon_process);
            }
        }
    }
}

/// [BUG-029] 常駐セッションdaemonへ接続済みのパイプ経由で`VmRequest::QueryActiveSessions`を
/// 送り、応答のアクティブセッション数を返す。
fn query_active_sessions(pipe: HANDLE) -> Result<usize, VmSandboxIpcError> {
    let bytes = serde_json::to_vec(&VmRequest::QueryActiveSessions)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize query request: {e}")))?;
    write_framed_timeout(pipe, &bytes, QUERY_ACTIVE_SESSIONS_TIMEOUT)?;
    let response_bytes = read_framed_timeout(pipe, QUERY_ACTIVE_SESSIONS_TIMEOUT)?;
    let response: VmResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse query response: {e}")))?;
    match response {
        VmResponse::ActiveSessions { count } => Ok(count),
        other => Err(VmSandboxIpcError::Ipc(format!(
            "unexpected response to QueryActiveSessions: {other:?}"
        ))),
    }
}

/// `harness tier3 gc`（A9、`harness-cli`）が呼ぶGC専用のワンショットdaemon起動。
/// `VmSandboxHandle::start`とは異なりセッションを開始せず、`--gc-only`引数付きで起動した
/// daemon（`serve_gc`）が[`VmRequest::Gc`]を1件処理して即座に終了するのを待つだけの
/// 軽量な経路。ウォームVM・現在セッション（gc-only起動時は存在しない）は台帳側の
/// 選定ロジック（`crate::vm_ledger::select_orphan_vm_names`・`daemon_pid`生存判定）で
/// GC対象から除外される。
///
/// **BUG-027対策（2層防御の1層目）**: `gc_orphan_sessions`側の`daemon_pid`生存判定
/// （2層目、こちらが最終防御線）とは別に、ここでは固定の常駐セッションdaemonパイプへ
/// 接続を試みることで「セッション実行中かどうか」を早期に、UAC昇格すら発生させずに
/// 判定する。
///
/// [BUG-029修正] 当初は「接続できた＝常駐daemonが稼働中」を「セッション実行中」の代理
/// 指標として使い、接続できただけで即座に拒否していた。Phase Bでdaemonがセッション0件でも
/// セッション0件でも常駐するようになったため、この代理指標は常駐daemon
/// 運用下で常に真になり、GCが恒久的に拒否される欠陥になっていた（`docs/bugs/BUG-029.md`）。
/// 接続できた場合は`VmRequest::QueryActiveSessions`を送り、実際のアクティブセッション数を
/// 問い合わせてから判定する（0件なら続行、1件以上なら拒否）。
pub fn run_gc_only() -> Result<Vec<String>, VmSandboxIpcError> {
    if let Ok(query_pipe) = connect_to_pipe_as_client(
        session_daemon_pipe_name(),
        std::time::Duration::from_millis(200),
        false,
    ) {
        let active = query_active_sessions(query_pipe);
        unsafe {
            let _ = CloseHandle(query_pipe);
        }
        match active {
            Ok(0) => {}
            Ok(_) | Err(_) => {
                // クエリ自体が失敗した場合（プロトコル不一致・タイムアウト等）も、
                // 安全側に倒して「セッション実行中の可能性あり」として拒否する
                // （BUG-027の防御を弱めない）。
                return Err(VmSandboxIpcError::Rejected(
                    "a Tier3 session daemon is currently running with at least one active \
                     session; refusing to run GC to avoid tearing down its VM/containers/SMB \
                     shares. Wait for the session to finish, or stop it first."
                        .to_string(),
                ));
            }
        }
    }

    let prepared = prepare_pipe()?;
    let pipe_name = prepared.name().to_string();
    let pipe = prepared.into_handle();

    let daemon_path = daemon_exe_path()?;
    let params = format!("{pipe_name} --gc-only");
    let daemon_process = match unsafe { launch_daemon_elevated(&daemon_path, &params) } {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };

    if let Err(e) = connect_with_timeout(pipe, CONNECT_TIMEOUT) {
        unsafe {
            let _ = CloseHandle(pipe);
            let _ = CloseHandle(daemon_process);
        }
        return Err(VmSandboxIpcError::Ipc(format!(
            "waiting for vmsandboxd (gc-only mode) to connect: {e} (daemon may not have \
             launched, or UAC is still pending user interaction)"
        )));
    }

    let result = (|| -> Result<Vec<String>, VmSandboxIpcError> {
        let bytes = serde_json::to_vec(&VmRequest::Gc)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize gc request: {e}")))?;
        write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
        let response: VmResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse gc response: {e}")))?;
        match response {
            VmResponse::GcReport { reaped_vm_names } => Ok(reaped_vm_names),
            VmResponse::Err(msg) => Err(VmSandboxIpcError::Rejected(msg)),
            other => Err(VmSandboxIpcError::Ipc(format!(
                "unexpected response for Gc: {other:?}"
            ))),
        }
    })();

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
        let wait = WaitForSingleObject(daemon_process, 30_000);
        if wait != WAIT_OBJECT_0 {
            let _ = windows::Win32::System::Threading::TerminateProcess(daemon_process, 1);
            let _ = WaitForSingleObject(daemon_process, 5000);
        }
        let _ = CloseHandle(daemon_process);
    }

    result
}

/// アクティブセッションが無い場合だけ常駐Tier3 daemonを終了する。
pub fn stop_resident_daemon_if_idle() -> Result<bool, VmSandboxIpcError> {
    let pipe = match connect_to_pipe_as_client(
        session_daemon_pipe_name(),
        std::time::Duration::from_millis(500),
        false,
    ) {
        Ok(pipe) => pipe,
        Err(_) => return Ok(false),
    };
    let result = (|| {
        let bytes = serde_json::to_vec(&VmRequest::ShutdownIfIdle).map_err(|e| {
            VmSandboxIpcError::Ipc(format!("failed to serialize shutdown request: {e}"))
        })?;
        write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(pipe, QUERY_ACTIVE_SESSIONS_TIMEOUT)?;
        let response: VmResponse = serde_json::from_slice(&response_bytes).map_err(|e| {
            VmSandboxIpcError::Ipc(format!("failed to parse shutdown response: {e}"))
        })?;
        match response {
            VmResponse::ShuttingDown => Ok(true),
            VmResponse::Err(msg) => Err(VmSandboxIpcError::Rejected(msg)),
            other => Err(VmSandboxIpcError::Ipc(format!(
                "unexpected response to ShutdownIfIdle: {other:?}"
            ))),
        }
    })();
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

/// `ToolCtx.vm_sandbox`（`harness-core`の「重い依存ゼロ」原則を保ったtrait境界、
/// `harness_core::VmShellExecutor`参照）の実体。`harness-tools::shell::run_windows_tier3`は
/// `Arc<dyn VmShellExecutor>`越しにこれを呼ぶ（同期メソッドのため`tokio::task::spawn_blocking`
/// 経由、`netfilterd`のstart/stop呼び出しと同じくブロッキングIPCである点に注意）。
impl harness_core::VmShellExecutor for VmSandboxHandle {
    fn exec(
        &self,
        cmd: &str,
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        self.exec_for_trait(cmd, cwd, env, timeout)
    }
}

/// daemon側エントリポイント（`harness-vmsandboxd.exe`のmainから呼ぶ、昇格トークンで実行、
/// S-2でパイプの向きが反転したため常駐daemon自身がサーバになる）。`owner_sid`/`owner_exe`は
/// 親（非昇格harness本体）が起動時にコマンドラインで明示的に渡した値（`--owner-sid`/
/// `--owner-exe`、[`VmSandboxHandle::start`]参照）。daemon自身のトークンSIDは使わない
/// （over-the-shoulder elevationでは起動元ユーザーと異なり得るため、
/// [`user_only_security_attributes`]のdoc参照）。
///
/// `StartSession`→`Exec`(N回)→`Teardown`の1セッションを処理したら、パイプを切断してから
/// 次の接続を待ち続ける（＝daemonプロセス自体は`Teardown`後も終了しない）。**Phase Bで
/// thread-per-session化済み**: `serve_resident`は各接続を`std::thread::spawn`で並行処理し、
/// `SessionRegistry`が同時セッション数上限（既定4・`--max-sessions`）を管理する
/// （`plans/DESIGN-SANDBOX-VMISOLATION.md`「実装確定サマリー」項目6・8参照）。
/// `HANDLE`（`windows`クレート、実体はポインタサイズの不透明値）を`std::thread::spawn`の
/// クロージャへ移すためのラッパー。`PreparedPipe`と同じ理由で`unsafe impl Send`を明示する
/// （named pipeハンドルはスレッド間で受け渡して使う分には安全、Win32 API自体の契約）。
struct SendableHandle(HANDLE);
unsafe impl Send for SendableHandle {}

/// 同時実行中のTier3セッションの登録簿（daemonプロセス内メモリのみ）。S-2段階5
/// （thread-per-session化）の要——接続受理ループはこれのエントリ数で同時実行数上限
/// （既定4・設定可能、`--max-sessions`）を判定し、超過時は新規スレッドを立てずその場で
/// 明示的に拒否する（現行の「2本目が300秒沈黙する」バグの直接の修正、
/// `DESIGN-SANDBOX-VMISOLATION.md`項目6-a参照）。**カウント対象はTier3セッション（本registry
/// のエントリ）だけ**——Tier0/Tier2a/Tier1/Tier2bはこのdaemonへ一切接続しないため対象外。
struct SessionRegistry {
    max_sessions: u8,
    active_slots: std::sync::Mutex<std::collections::HashSet<u8>>,
}

impl SessionRegistry {
    fn new(max_sessions: u8) -> Self {
        Self {
            max_sessions,
            active_slots: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// 空いているslot番号（`0..max_sessions`）を確保する。上限に達していれば`None`。
    /// `slot`はコンテナの静的IP・SNIプロキシポートの衝突回避に使われる
    /// （`crate::vmsandbox::container_static_ip_cidr`/`sni_proxy_port_for_slot`）。
    fn try_acquire_slot(&self) -> Option<u8> {
        let mut slots = self.active_slots.lock().unwrap();
        for slot in 0..self.max_sessions {
            if !slots.contains(&slot) {
                slots.insert(slot);
                return Some(slot);
            }
        }
        None
    }

    fn release_slot(&self, slot: u8) {
        self.active_slots.lock().unwrap().remove(&slot);
    }

    /// [BUG-029] 現在アクティブなスロット数。`QueryActiveSessions`の応答生成に使う。
    fn active_count(&self) -> usize {
        self.active_slots.lock().unwrap().len()
    }
}

/// daemon側エントリポイント（`harness-vmsandboxd.exe`のmainから呼ぶ、昇格トークンで実行）。
/// **Phase B（S-2段階5）**: 接続受理ループとセッション処理（`serve_inner`）を分離し、受理した
/// 接続を`std::thread::spawn`へ渡して即座に次の`ConnectNamedPipe`へ戻る——旧実装は
/// `serve_inner`（1セッション丸ごと）をループ内で直接呼んでいたため、2本目の接続は
/// `ERROR_PIPE_BUSY`にならず`CreateFileW`は成功するのに誰も`ConnectNamedPipe`を呼ばず、
/// 1本目の`Teardown`まで無応答になる既知のバグがあった（`DESIGN-SANDBOX-VMISOLATION.md`
/// 項目6-a）。`max_sessions`（既定4）は`SessionRegistry`のエントリ数だけで判定する。
pub fn serve_resident(
    owner_sid: &str,
    owner_exe: &Path,
    max_sessions: u8,
) -> Result<(), VmSandboxIpcError> {
    let pipe_name = session_daemon_pipe_name();
    let mut sa = user_only_security_attributes(owner_sid)?;
    let first = create_first_pipe_instance(pipe_name, &mut sa);
    unsafe {
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
    }
    let mut pipe = first.map_err(|e| {
        VmSandboxIpcError::Ipc(format!(
            "failed to create the fixed session pipe as its first instance (already in use? \
             possible squatting, or another resident daemon is already running): {e}"
        ))
    })?;

    let registry = std::sync::Arc::new(SessionRegistry::new(max_sessions.max(1)));
    let owner_sid_owned = owner_sid.to_string();
    let owner_exe_owned = owner_exe.to_path_buf();

    loop {
        if let Err(e) = connect_with_timeout(pipe, DAEMON_IDLE_ACCEPT_TIMEOUT) {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }

        let client_pid = match verify_pipe_client_identity(pipe, &owner_sid_owned, &owner_exe_owned)
        {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("harness-vmsandboxd: rejecting connection: {e}");
                unsafe {
                    let _ = DisconnectNamedPipe(pipe);
                }
                // このパイプインスタンスは拒否した相手との接続を切断するだけで使い回し、次の
                // 接続を待つ（インスタンス自体を作り直す必要はない——`FIRST_PIPE_INSTANCE`は
                // 最初の`CreateNamedPipeW`にしか関係しない）。
                continue;
            }
        };

        // 後続クライアント（次のセッション）を待たせないよう、この接続の処理に入る前に
        // 追加インスタンスを用意しておく。
        let mut extra_sa = user_only_security_attributes(&owner_sid_owned)?;
        let next_instance = create_additional_pipe_instance(pipe_name, &mut extra_sa);
        unsafe {
            let _ = LocalFree(HLOCAL(extra_sa.lpSecurityDescriptor));
        }

        match registry.try_acquire_slot() {
            Some(slot) => {
                let registry = std::sync::Arc::clone(&registry);
                let sendable_pipe = SendableHandle(pipe);
                std::thread::spawn(move || {
                    // Rust 2021のdisjoint closure captureは`sendable_pipe.0`という直接の
                    // フィールドアクセスがあると`SendableHandle`全体ではなく`HANDLE`
                    // フィールド単体をキャプチャしてしまい、ラッパーの`unsafe impl Send`を
                    // 素通りしてコンパイルエラーになる。値全体を先に束縛し直すことで
                    // `SendableHandle`まるごとがムーブされるよう強制する（定石の回避策）。
                    let sendable_pipe = sendable_pipe;
                    let pipe = sendable_pipe.0;
                    let result = serve_inner(pipe, client_pid, slot, &registry);
                    unsafe {
                        // **実機E2Eで発見したバグ**: `WriteFile`の完了はOSのパイプバッファへ
                        // 書き込みが受理されたことしか意味せず、クライアントが実際に読み終えた
                        // ことは保証しない。直後に`DisconnectNamedPipe`するとクライアントの
                        // 読み取りが完了する前にバッファが破棄され、クライアント側で
                        // 「ReadFile failed: パイプの他端にプロセスがありません」という
                        // 断線エラーになる（`Teardown`応答直後に実際に発生した）。
                        // `FlushFileBuffers`はクライアントが読み切るまでブロックするため、
                        // これを`Disconnect`の前に挟むことで確実に応答を届けてから切断する。
                        let _ = FlushFileBuffers(pipe);
                        let _ = DisconnectNamedPipe(pipe);
                        let _ = CloseHandle(pipe);
                    }
                    registry.release_slot(slot);
                    if let Err(e) = result {
                        eprintln!("harness-vmsandboxd: session ended with an error: {e}");
                    }
                });
            }
            None => {
                eprintln!(
                    "harness-vmsandboxd: rejecting connection: max_sessions ({max_sessions}) \
                     already reached"
                );
                let resp = VmResponse::Err(format!(
                    "too many concurrent Tier3 sessions (limit: {max_sessions})"
                ));
                let _ = send_response(pipe, &resp);
                unsafe {
                    let _ = DisconnectNamedPipe(pipe);
                    let _ = CloseHandle(pipe);
                }
            }
        }

        pipe = next_instance.map_err(|e| {
            VmSandboxIpcError::Ipc(format!(
                "failed to create the next session pipe instance: {e}"
            ))
        })?;
    }
}

fn serve_inner(
    pipe: HANDLE,
    client_pid: u32,
    slot: u8,
    registry: &SessionRegistry,
) -> Result<(), VmSandboxIpcError> {
    // 1件目: StartSession を待つ。ただし[BUG-029] `QueryActiveSessions`（`harness tier3 gc`が
    // 「本当にセッションが実行中か」を確認するための軽量リクエスト）も1件目として受理する。
    let request_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    let (workspace_root, allow_domains, warm) =
        match serde_json::from_slice::<VmRequest>(&request_bytes) {
            Ok(VmRequest::StartSession {
                workspace_root,
                allow_domains,
                warm,
            }) => (workspace_root, allow_domains, warm),
            Ok(VmRequest::QueryActiveSessions) => {
                // このクエリ自身が`try_acquire_slot`で1スロット消費している（呼び出し元の
                // `serve_resident`参照）ため、自分自身を除いた数を返す。
                let count = registry.active_count().saturating_sub(1);
                let resp = VmResponse::ActiveSessions { count };
                send_response(pipe, &resp)?;
                return Ok(());
            }
            Ok(VmRequest::ShutdownIfIdle) => {
                let count = registry.active_count().saturating_sub(1);
                if count == 0 {
                    send_response(pipe, &VmResponse::ShuttingDown)?;
                    std::thread::spawn(|| {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        std::process::exit(0);
                    });
                    return Ok(());
                }
                let resp = VmResponse::Err(format!(
                    "refusing to stop Tier3 daemon because {count} active session(s) are running"
                ));
                send_response(pipe, &resp)?;
                return Err(VmSandboxIpcError::Rejected(
                    "active Tier3 sessions are running".to_string(),
                ));
            }
            Ok(_) => {
                let resp =
                    VmResponse::Err("expected StartSession as the first message".to_string());
                send_response(pipe, &resp)?;
                return Err(VmSandboxIpcError::Ipc("protocol violation".to_string()));
            }
            Err(e) => {
                let resp = VmResponse::Err(format!("malformed StartSession request: {e}"));
                send_response(pipe, &resp)?;
                return Err(VmSandboxIpcError::Ipc(format!("malformed request: {e}")));
            }
        };
    let workspace_root = PathBuf::from(workspace_root);

    // S-2段階4（`DESIGN-SANDBOX-VMISOLATION.md`7-a）: `verify_pipe_client_identity`は
    // 「正規harness.exeである」ことしか検証しない。固定パイプ名化で同一ユーザーの任意の
    // harness.exe起動から`StartSession`が送られ得るようになった以上、「そのharness.exeが
    // 要求しているworkspace_rootへ既にアクセス権を持っているか」を別途検証しないと、
    // `C:\`等を渡すだけの実質UAC越えLPEが成立する。
    if let Err(e) = authorize_workspace_root(client_pid, &workspace_root) {
        let resp = VmResponse::Err(format!("workspace_root rejected: {e}"));
        send_response(pipe, &resp)?;
        return Err(e);
    }

    let config = VmSandboxConfig::default();

    // **Phase B**: 孤児VM/差分VHDXの撤収（旧D-24、`gc_orphan_sessions`）はもう本関数の
    // 呼び出しごとには行わない。VM自体が`crate::vm_host::VmHost`の参照カウントで管理される
    // 共有resident資源になったため、GCは「daemonが今から初めてVMを起動しようとする瞬間
    // （`VmHost::attach`のStopped→Running遷移）」にのみ実行される——セッション途中で
    // 誤って現在生存中のVMを孤児扱いしてしまう事故を構造的に防ぐため。
    let start_result = VmSession::start(&workspace_root, &config, &allow_domains, warm, slot);
    let session = match start_result {
        Ok(s) => s,
        Err(e) => {
            let resp = VmResponse::Err(format!("VM session start failed: {e}"));
            send_response(pipe, &resp)?;
            return Err(VmSandboxIpcError::Ipc(e.to_string()));
        }
    };
    send_response(pipe, &VmResponse::Ready)?;

    // 2件目以降: Exec を何度でも反復し、Teardown（または親のクラッシュによるパイプ切断）を待つ。
    loop {
        let next = read_framed_timeout(pipe, DAEMON_WAIT_TIMEOUT);
        let request = match next {
            Ok(bytes) => match serde_json::from_slice::<VmRequest>(&bytes) {
                Ok(req) => req,
                Err(e) => {
                    let _ =
                        send_response(pipe, &VmResponse::Err(format!("malformed request: {e}")));
                    continue;
                }
            },
            Err(_) => {
                // フェイルセーフ経路（パイプ切断・タイムアウト）。応答は送らず撤収する。
                let _ = session.teardown(&workspace_root, &config);
                return Ok(());
            }
        };

        match request {
            VmRequest::Exec {
                cmd,
                cwd,
                env,
                timeout_secs,
            } => {
                let cwd_path = workspace_root.join(cwd.trim_start_matches('/'));
                let result = session.exec(
                    &cmd,
                    &cwd_path,
                    &workspace_root,
                    &env,
                    std::time::Duration::from_secs(timeout_secs.max(1)),
                );
                let resp = match result {
                    Ok((stdout, stderr, exit_code)) => VmResponse::ExecResult {
                        stdout,
                        stderr,
                        exit_code,
                    },
                    Err(e) => VmResponse::Err(format!("exec failed: {e}")),
                };
                send_response(pipe, &resp)?;
            }
            VmRequest::Teardown => {
                let teardown_result = session.teardown(&workspace_root, &config);
                let resp = match &teardown_result {
                    Ok(()) => VmResponse::TornDown,
                    Err(e) => VmResponse::Err(format!("teardown failed: {e}")),
                };
                let _ = send_response(pipe, &resp);
                return teardown_result.map_err(|e| VmSandboxIpcError::Ipc(e.to_string()));
            }
            VmRequest::StartSession { .. } => {
                let _ = send_response(
                    pipe,
                    &VmResponse::Err("StartSession already handled for this session".to_string()),
                );
            }
            VmRequest::Gc => {
                // `Gc`はgc-onlyモード（`serve_gc`）専用のリクエストであり、通常のセッション
                // ループ（本関数）では受理しない。
                let _ = send_response(
                    pipe,
                    &VmResponse::Err(
                        "Gc is only valid in gc-only mode (harness tier3 gc)".to_string(),
                    ),
                );
            }
            VmRequest::QueryActiveSessions => {
                // `QueryActiveSessions`はStartSession前（`serve_inner`冒頭）にのみ受理する
                // 軽量リクエストであり、既にセッションが開始済みのこのループでは想定しない。
                let _ = send_response(
                    pipe,
                    &VmResponse::Err(
                        "QueryActiveSessions is only valid before StartSession".to_string(),
                    ),
                );
            }
            VmRequest::ShutdownIfIdle => {
                let _ = send_response(
                    pipe,
                    &VmResponse::Err(
                        "ShutdownIfIdle is only valid before StartSession".to_string(),
                    ),
                );
            }
        }
    }
}

fn send_response(pipe: HANDLE, resp: &VmResponse) -> Result<(), VmSandboxIpcError> {
    let bytes = serde_json::to_vec(resp)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, TEARDOWN_RESPONSE_TIMEOUT)
}

/// daemon側のGC専用エントリポイント（`harness-vmsandboxd.exe <pipe> --gc-only`から呼ぶ）。
/// `serve`（`StartSession`起点の長期常駐ループ）とは別経路: [`VmRequest::Gc`]を1件受けて
/// `crate::vmsandbox::gc_orphan_sessions`を実行し、結果を返してすぐ終了する（`run_gc_only`
/// のdoc参照）。
pub fn serve_gc(pipe_name: &str) -> Result<(), VmSandboxIpcError> {
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
        .map_err(VmSandboxIpcError::from)?
    };

    let result = serve_gc_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

fn serve_gc_inner(pipe: HANDLE) -> Result<(), VmSandboxIpcError> {
    let request_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    match serde_json::from_slice::<VmRequest>(&request_bytes) {
        Ok(VmRequest::Gc) => {
            let config = VmSandboxConfig::default();
            let reaped = crate::vmsandbox::gc_orphan_sessions(&config, "");
            send_response(
                pipe,
                &VmResponse::GcReport {
                    reaped_vm_names: reaped,
                },
            )
        }
        Ok(_) => {
            let resp =
                VmResponse::Err("expected Gc as the only message in gc-only mode".to_string());
            send_response(pipe, &resp)?;
            Err(VmSandboxIpcError::Ipc(
                "protocol violation (gc-only mode)".to_string(),
            ))
        }
        Err(e) => {
            let resp = VmResponse::Err(format!("malformed Gc request: {e}"));
            send_response(pipe, &resp)?;
            Err(VmSandboxIpcError::Ipc(format!("malformed request: {e}")))
        }
    }
}

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
        if crate::privhelper::is_elevated() {
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
