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

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    HLOCAL, LocalFree, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::win_common::wide;
use crate::vmsandbox::{VmSandboxConfig, VmSession};

/// 親→daemonへ送るメッセージ。`StartSession`→`Exec`(N回)→`Teardown`の順に送る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmRequest {
    StartSession {
        workspace_root: String,
        /// egress許可リスト（SNIプロキシ+nftables DNAT、Phase 2）の対象ドメイン。空なら
        /// Phase 1と同じ無制限egressのまま（`--net-allow-domain`未指定時の既定挙動、
        /// `plans/vm-spike/RESULTS.md`§3.8）。
        allow_domains: Vec<String>,
    },
    Exec {
        cmd: String,
        cwd: String,
        env: Vec<(String, String)>,
        timeout_secs: u64,
    },
    Teardown,
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
/// daemon側が次のメッセージ（`Exec`/`Teardown`、または親のクラッシュによるパイプ切断）を
/// 待つ時間。harnessセッションの生存期間そのものに依存するため実質無期限に近い値にする。
const DAEMON_WAIT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(u32::MAX as u64);

fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), windows::Win32::Security::TOKEN_QUERY, &mut token)?;

        let mut ret_len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        let get_result = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        get_result?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = crate::win_common::pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
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
                    return Err(VmSandboxIpcError::Ipc(format!("{op_name} failed to start: {e}")));
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

fn connect_with_timeout(pipe: HANDLE, timeout: std::time::Duration) -> Result<(), VmSandboxIpcError> {
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
            return Err(VmSandboxIpcError::Ipc("WriteFile wrote 0 bytes".to_string()));
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
    pipe_name: &str,
) -> Result<HANDLE, VmSandboxIpcError> {
    let verb_w = wide("runas");
    let file_w = wide(&daemon_path.to_string_lossy());
    let params_w = wide(pipe_name);

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
        return Err(VmSandboxIpcError::Win32(format!("ShellExecuteExW failed: {err:?}")));
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

fn connect_and_start_session(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    workspace_root_str: String,
    allow_domains: Vec<String>,
) -> Result<VmSandboxHandle, VmSandboxIpcError> {
    let workspace_root = PathBuf::from(&workspace_root_str);
    let connect_result = connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        VmSandboxIpcError::Ipc(format!(
            "waiting for vmsandboxd to connect: {e} (daemon may not have launched, or UAC \
             is still pending user interaction)"
        ))
    });
    if let Err(e) = connect_result {
        unsafe {
            let _ = CloseHandle(pipe);
            if let Some(h) = daemon_process {
                let _ = CloseHandle(h);
            }
        }
        return Err(e);
    }

    let req = VmRequest::StartSession {
        workspace_root: workspace_root_str,
        allow_domains,
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
    /// daemonを昇格起動し、`StartSession`を送って応答を待つ（親側、非管理者本体から呼ぶ）。
    /// `allow_domains`は既存の`net_proxy.allow_domains`（`--net-allow-domain`+
    /// `.harness/settings.json`統合済み、WFPが既に使っているのと同じ値）をそのまま渡す。
    pub fn start(
        workspace_root: &std::path::Path,
        allow_domains: &[String],
    ) -> Result<Self, VmSandboxIpcError> {
        let prepared = prepare_pipe()?;
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();

        let daemon_path = daemon_exe_path()?;
        let daemon_process = match unsafe { launch_daemon_elevated(&daemon_path, &pipe_name) } {
            Ok(h) => h,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(e);
            }
        };

        connect_and_start_session(
            pipe,
            Some(daemon_process),
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
        )
    }

    /// 既に（特権分離ヘルパー経由で）daemonの起動を依頼済みのパイプへ接続する
    /// （`netfilterd::NetfilterHandle::connect_after_chain_launch`と同型。Phase 1では
    /// `harness-cli`から未使用だが、`privhelper`連鎖起動シナリオへ将来組み込む余地を残す）。
    pub fn connect_after_chain_launch(
        pipe: HANDLE,
        workspace_root: &std::path::Path,
        allow_domains: &[String],
    ) -> Result<Self, VmSandboxIpcError> {
        connect_and_start_session(
            pipe,
            None,
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
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
        let rel = cwd.strip_prefix(&self.workspace_root).unwrap_or(std::path::Path::new(""));
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
        let bytes = serde_json::to_vec(&req)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize exec request: {e}")))?;
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
            let bytes = serde_json::to_vec(&VmRequest::Teardown)
                .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize teardown: {e}")))?;
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
            if let Some(daemon_process) = self.daemon_process {
                let wait = WaitForSingleObject(daemon_process, 30_000);
                if wait != WAIT_OBJECT_0 {
                    let _ =
                        windows::Win32::System::Threading::TerminateProcess(daemon_process, 1);
                    let _ = WaitForSingleObject(daemon_process, 5000);
                }
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

/// daemon側エントリポイント（`harness-vmsandboxd.exe`のmainから呼ぶ、昇格トークンで実行）。
pub fn serve(pipe_name: &str) -> Result<(), VmSandboxIpcError> {
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

    let result = serve_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

fn serve_inner(pipe: HANDLE) -> Result<(), VmSandboxIpcError> {
    // 1件目: StartSession を待つ。
    let request_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    let (workspace_root, allow_domains) = match serde_json::from_slice::<VmRequest>(&request_bytes) {
        Ok(VmRequest::StartSession { workspace_root, allow_domains }) => (workspace_root, allow_domains),
        Ok(_) => {
            let resp = VmResponse::Err(
                "expected StartSession as the first message".to_string(),
            );
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

    let config = VmSandboxConfig::default();
    let session = match VmSession::start(&workspace_root, &config, &allow_domains) {
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
                    let _ = send_response(pipe, &VmResponse::Err(format!("malformed request: {e}")));
                    continue;
                }
            },
            Err(_) => {
                // フェイルセーフ経路（パイプ切断・タイムアウト）。応答は送らず撤収する。
                let _ = session.teardown(&workspace_root);
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
                let teardown_result = session.teardown(&workspace_root);
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
        }
    }
}

fn send_response(pipe: HANDLE, resp: &VmResponse) -> Result<(), VmSandboxIpcError> {
    let bytes = serde_json::to_vec(resp)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, TEARDOWN_RESPONSE_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_session_request_roundtrips_through_json() {
        let req = VmRequest::StartSession {
            workspace_root: r"C:\work\project".to_string(),
            allow_domains: vec!["example.com".to_string()],
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: VmRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            VmRequest::StartSession { workspace_root, allow_domains } => {
                assert_eq!(workspace_root, r"C:\work\project");
                assert_eq!(allow_domains, vec!["example.com".to_string()]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn start_session_request_with_empty_allow_domains_roundtrips() {
        let req = VmRequest::StartSession {
            workspace_root: r"C:\work\project".to_string(),
            allow_domains: vec![],
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
                    VmResponse::ExecResult { stdout: a, stderr: b, exit_code: c },
                    VmResponse::ExecResult { stdout: x, stderr: y, exit_code: z },
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
}
