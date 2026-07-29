//! WFP専用の常駐デーモン制御（Layer2、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`
//! 付録C「アーキテクチャ決定」参照）。
//!
//! `harness-privhelper`（`crate::privhelper`）とは意図的に別プロセス・別モジュールにしている。
//! `FWPM_SESSION_FLAG_DYNAMIC`のフィルタは、エンジンハンドルを保持するプロセスが生きている
//! 間だけ有効（`crate::wfp`参照）であり、これは「1起動=1操作で即終了、常駐しない」という
//! `harness-privhelper`の設計原則（D-16）と本質的に相容れない。そのため`harness-netfilterd`は
//! **harnessセッション全体**（`harness`本体プロセス1回の起動、複数の`run_shell`呼び出しに
//! またがる）の生存期間中だけ昇格トークンのまま常駐する専用バイナリとして新設した。
//! セッションにつき最大1回だけ起動する session-scoped singleton として扱う（UAC起動回数の
//! 最小化、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。
//!
//! IPCの配線（named pipe + JSON、`user_only_security_attributes`、`ShellExecuteExW runas`
//! 昇格起動、タイムアウト付きoverlapped I/O）自体は`privhelper.rs`と同じパターンを踏襲する
//! （要求ライフサイクルが異なる——1往復で終わるか、2回目のメッセージを常駐待ちするか——ため
//! 汎用化はせず複製する）。
//!
//! **プロトコル**: 1回のセッションで2往復のメッセージをやり取りする。
//! 1. 親→daemon: [`NetfilterRequest::ApplyRules`] → daemon: [`NetfilterResponse::Applied`]
//!    （ここでdaemonはパイプを閉じずに待機を続ける。以降harnessセッションが終わるまで、
//!    Tier1aの`run_shell`は何度呼ばれてもこの1つのdaemonが引き続き宛先を強制する）
//! 2. 親→daemon: [`NetfilterRequest::Teardown`] → daemon: [`NetfilterResponse::TornDown`] → daemon終了
//!    （`harness`本体プロセスの終了時に1回だけ送る、`crates/harness-cli/src/main.rs`参照）
//!
//! **2つの起動シナリオ**（付録D）: (A) `--fs-allow`のシステム保護パス等で特権分離ヘルパー
//! （`privhelper`）が既に昇格起動される場合、そのヘルパーが自分の昇格済みトークンを引き継いで
//! `CreateProcessW`（`runas`は使わない）でdaemonを連鎖起動する（[`NetfilterHandle::connect_after_chain_launch`]）。
//! (B) それ以外の場合、`harness`本体が直接`runas`で起動する（[`NetfilterHandle::start`]）。
//! いずれもUACは最大1回に抑えられる。
//!
//! **フェイルセーフ**: 親（本体）がクラッシュ等でパイプを閉じずに消えた場合、daemon側の
//! 2回目の`ReadFile`が`ERROR_BROKEN_PIPE`で失敗する。これを「親死亡」のシグナルとして扱い、
//! 同じteardown経路を実行してから終了する。daemonプロセス自体が強制終了された場合の最終防波堤は
//! 引き続き`FWPM_SESSION_FLAG_DYNAMIC`のBFE自動削除に委ねる（`wfp::WfpSession`のDrop実装）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
    HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::wfp::{WfpOptions, WfpSession};
use crate::win_appcontainer::{self, CONTAINER_NAME};
use crate::win_common::wide;

/// 親→daemonへ送るメッセージ。1セッションで`ApplyRules`→`Teardown`の順に2回送る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetfilterRequest {
    ApplyRules {
        allow_domains: Vec<String>,
        allow_loopback: bool,
        #[serde(default)]
        allow_loopback_ports: Vec<u16>,
        #[serde(default)]
        allow_loopback_tcp_ports: Vec<u16>,
        #[serde(default)]
        allow_loopback_udp_ports: Vec<u16>,
        allow_direct_dns: bool,
        #[serde(default)]
        audit_log_path: Option<PathBuf>,
    },
    Teardown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetfilterResponse {
    Applied,
    TornDown,
    Err(String),
}

#[derive(Debug, thiserror::Error)]
pub enum NetfilterError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("daemon rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
}

impl From<windows::core::Error> for NetfilterError {
    fn from(e: windows::core::Error) -> Self {
        NetfilterError::Win32(e.to_string())
    }
}

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// `ApplyRules`応答（WFPルール投入完了）を待つタイムアウト。ドメイン解決を含むため
/// `privhelper.rs`のACL操作と同程度の余裕を持たせる。
const APPLY_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// `Teardown`応答を待つタイムアウト。
const TEARDOWN_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// daemon側が2件目のメッセージ（`Teardown`、または親のクラッシュによるパイプ切断）を
/// 待つ時間。対象アプリの実行時間そのものに依存するため実質無期限に近い値にする
/// （`WaitForSingleObject`の最大値、約49.7日）。
const DAEMON_WAIT_FOR_TEARDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(u32::MAX as u64);

fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )?;

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
        r"\\.\pipe\harness-netfilterd-{}-{}-{}",
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
) -> Result<u32, NetfilterError>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, PCWSTR::null())
            .map_err(|e| NetfilterError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
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
                    // クライアントが`ConnectNamedPipe`呼び出し前に既に接続済みだった（synchronous
                    // completion）。MSDNの既知の注意点: このケースではOVERLAPPEDのイベントは
                    // シグナルされないため、後続の`GetOverlappedResult`を呼んではいけない
                    // （呼ぶと`ERROR_IO_INCOMPLETE`で失敗する）。ここで即座に成功として返す。
                    // 【2026-07-25実機E2Eで発見・修正】シナリオA（`privhelper`経由の連鎖起動、
                    // UAC待ちが無いぶん子が即座に接続してくる）でこの競合が実際に発生し発覚した
                    // （`privhelper.rs`の同名関数にも同じバグがコピーされていたため同時に修正）。
                    let _ = CloseHandle(event);
                    return Ok(0);
                } else {
                    let _ = CloseHandle(event);
                    return Err(NetfilterError::Ipc(format!(
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
                return Err(NetfilterError::Ipc(format!(
                    "{op_name} timed out after {timeout:?}"
                )));
            }
        }

        let mut transferred = 0u32;
        let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
        let _ = CloseHandle(event);
        result.map_err(|e| {
            NetfilterError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}"))
        })?;
        Ok(transferred)
    }
}

fn connect_with_timeout(pipe: HANDLE, timeout: std::time::Duration) -> Result<(), NetfilterError> {
    run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
        ConnectNamedPipe(pipe, Some(ov))
    })?;
    Ok(())
}

fn write_all_timeout(
    handle: HANDLE,
    buf: &[u8],
    timeout: std::time::Duration,
) -> Result<(), NetfilterError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &buf[offset..];
        let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
            WriteFile(handle, Some(slice), None, Some(ov))
        })?;
        if written == 0 {
            return Err(NetfilterError::Ipc("WriteFile wrote 0 bytes".to_string()));
        }
        offset += written as usize;
    }
    Ok(())
}

fn read_exact_timeout(
    handle: HANDLE,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> Result<(), NetfilterError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &mut buf[offset..];
        let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
            ReadFile(handle, Some(slice), None, Some(ov))
        })?;
        if read == 0 {
            return Err(NetfilterError::Ipc(
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
) -> Result<(), NetfilterError> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all_timeout(handle, &len, timeout)?;
    write_all_timeout(handle, payload, timeout)?;
    Ok(())
}

fn read_framed_timeout(
    handle: HANDLE,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, NetfilterError> {
    let mut len_buf = [0u8; 4];
    read_exact_timeout(handle, &mut len_buf, timeout)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_timeout(handle, &mut payload, timeout)?;
    }
    Ok(payload)
}

fn daemon_exe_path() -> Result<PathBuf, NetfilterError> {
    let current = std::env::current_exe()
        .map_err(|e| NetfilterError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| NetfilterError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-netfilterd.exe"))
}

unsafe fn launch_daemon_elevated(
    daemon_path: &std::path::Path,
    pipe_name: &str,
) -> Result<HANDLE, NetfilterError> {
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
            return Err(NetfilterError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(NetfilterError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }

    Ok(info.hProcess)
}

/// 常駐daemonへの接続を表す。`stop`を呼ぶまでパイプ・プロセスハンドルを保持し続ける
/// （＝WFPフィルタが有効であり続ける）。呼び出し側（`run_shell`のTier1a起動経路）は
/// harnessセッション全体（複数の`run_shell`呼び出しにまたがる）の生存期間中これを保持し、
/// セッション終了時に`stop`を呼ぶ（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。
///
/// `daemon_process`は`start`（シナリオB、本体が直接`runas`起動）でのみ`Some`になる。
/// シナリオA（`privhelper`が連鎖起動、[`prepare_pipe`]→特権分離ヘルパー経由の起動→
/// [`connect_and_apply`]という流れ）では、起動したのが本体ではなくprivhelperのため
/// プロセスハンドルを持たず`None`のままになる——`stop`時の強制終了フォールバックが
/// 使えない（IPC経由のTeardownのみに頼る）点が唯一の違い。
pub struct NetfilterHandle {
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
}

unsafe impl Send for NetfilterHandle {}

/// [`prepare_pipe`]の返り値。呼び出し元（`harness-cli`）が`windows`クレートに直接依存せずに
/// 済むよう、生の`HANDLE`をラップし「未消費のままドロップされたら自動的に閉じる」動作を持つ
/// （シナリオ(B)/(C)で結局このパイプを使わなかった場合の後始末を、呼び出し元に`CloseHandle`を
/// 書かせずに済ませる）。実際に使う場合（シナリオ(A)、`NetfilterHandle::connect_after_chain_launch`
/// へ渡す）は[`PreparedPipe::into_handle`]で中身を取り出す。
pub struct PreparedPipe {
    handle: HANDLE,
    name: String,
}

unsafe impl Send for PreparedPipe {}

impl PreparedPipe {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 生ハンドルを取り出す（`NetfilterHandle::connect_after_chain_launch`専用）。以後の
    /// 自動クローズは行われなくなる（呼び出し先がハンドルの所有権を引き継ぐ）。
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

/// パイプ作成だけを行う（シナリオA/B共通の前段）。返り値の[`PreparedPipe::name`]は、
/// シナリオBなら[`NetfilterHandle::start`]相当の続きへ、シナリオAなら特権分離ヘルパーの
/// `chain_netfilterd_pipe`引数へそのまま渡す。
pub fn prepare_pipe() -> Result<PreparedPipe, NetfilterError> {
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
            return Err(NetfilterError::from(windows::core::Error::from_win32()));
        }
        handle
    };
    Ok(PreparedPipe {
        handle: pipe,
        name: pipe_name,
    })
}

/// 既に接続待ち可能な状態のパイプへ、daemonの接続を待ってから`ApplyRules`を送り応答を待つ
/// （シナリオA/B共通の後段）。`daemon_process`は呼び出し元が既に把握しているプロセス
/// ハンドル（シナリオBのみ、[`NetfilterHandle::start`]参照）。
fn connect_and_apply(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    allow_domains: Vec<String>,
    allow_loopback: bool,
    allow_loopback_ports: Vec<u16>,
    allow_loopback_tcp_ports: Vec<u16>,
    allow_loopback_udp_ports: Vec<u16>,
    allow_direct_dns: bool,
    audit_log_path: Option<PathBuf>,
) -> Result<NetfilterHandle, NetfilterError> {
    let connect_result = connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        NetfilterError::Ipc(format!(
            "waiting for netfilterd to connect: {e} (daemon may not have launched, or UAC \
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

    let req = NetfilterRequest::ApplyRules {
        allow_domains,
        allow_loopback,
        allow_loopback_ports,
        allow_loopback_tcp_ports,
        allow_loopback_udp_ports,
        allow_direct_dns,
        audit_log_path,
    };
    let apply_result = (|| -> Result<(), NetfilterError> {
        let bytes = serde_json::to_vec(&req)
            .map_err(|e| NetfilterError::Ipc(format!("failed to serialize request: {e}")))?;
        write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
        let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
        match response {
            NetfilterResponse::Applied => Ok(()),
            NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
            NetfilterResponse::TornDown => Err(NetfilterError::Ipc(
                "unexpected TornDown response for an ApplyRules request".to_string(),
            )),
        }
    })();

    match apply_result {
        Ok(()) => Ok(NetfilterHandle {
            pipe,
            daemon_process,
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

impl NetfilterHandle {
    /// daemonを昇格起動し、`ApplyRules`を送って応答を待つ（親側、非管理者本体から呼ぶ、
    /// シナリオB＝特権分離ヘルパーが不要なケース）。
    pub fn start(
        allow_domains: Vec<String>,
        allow_loopback: bool,
        allow_loopback_ports: Vec<u16>,
        allow_loopback_tcp_ports: Vec<u16>,
        allow_loopback_udp_ports: Vec<u16>,
        allow_direct_dns: bool,
        audit_log_path: Option<PathBuf>,
    ) -> Result<Self, NetfilterError> {
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

        connect_and_apply(
            pipe,
            Some(daemon_process),
            allow_domains,
            allow_loopback,
            allow_loopback_ports,
            allow_loopback_tcp_ports,
            allow_loopback_udp_ports,
            allow_direct_dns,
            audit_log_path,
        )
    }

    /// 既に（特権分離ヘルパー経由で）daemonの起動を依頼済みのパイプへ接続し、`ApplyRules`を
    /// 送って応答を待つ（親側、シナリオA＝`privhelper`が連鎖起動したケース）。呼び出し元は
    /// [`prepare_pipe`]で作った`pipe`を渡す。起動者がprivhelperであるため、ここでは
    /// プロセスハンドルを持たない（`daemon_process: None`、構造体docの注記参照）。
    pub fn connect_after_chain_launch(
        pipe: HANDLE,
        allow_domains: Vec<String>,
        allow_loopback: bool,
        allow_loopback_ports: Vec<u16>,
        allow_loopback_tcp_ports: Vec<u16>,
        allow_loopback_udp_ports: Vec<u16>,
        allow_direct_dns: bool,
        audit_log_path: Option<PathBuf>,
    ) -> Result<Self, NetfilterError> {
        connect_and_apply(
            pipe,
            None,
            allow_domains,
            allow_loopback,
            allow_loopback_ports,
            allow_loopback_tcp_ports,
            allow_loopback_udp_ports,
            allow_direct_dns,
            audit_log_path,
        )
    }

    /// `Teardown`を送ってdaemonの終了を待つ（対象アプリ終了を検知した親から呼ぶ、正常系）。
    pub fn stop(self) -> Result<(), NetfilterError> {
        let pipe = self.pipe;
        let daemon_process = self.daemon_process;
        std::mem::forget(self); // Dropで二重stopしないよう所有権をここで断つ。

        let result = (|| -> Result<(), NetfilterError> {
            let bytes = serde_json::to_vec(&NetfilterRequest::Teardown)
                .map_err(|e| NetfilterError::Ipc(format!("failed to serialize teardown: {e}")))?;
            write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
            let response_bytes = read_framed_timeout(pipe, TEARDOWN_RESPONSE_TIMEOUT)?;
            let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
                .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
            match response {
                NetfilterResponse::TornDown => Ok(()),
                NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
                NetfilterResponse::Applied => Err(NetfilterError::Ipc(
                    "unexpected Applied response for a Teardown request".to_string(),
                )),
            }
        })();

        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
            // daemon_processはシナリオB（本体が直接runas起動）のみ`Some`。シナリオA
            // （privhelperが連鎖起動）ではプロセスハンドルを持たないため、強制終了
            // フォールバックは使えず、IPC経由のTeardown応答（上のresult）のみに頼る
            // （NetfilterHandle構造体docの注記参照）。
            if let Some(daemon_process) = daemon_process {
                let wait = WaitForSingleObject(daemon_process, 5000);
                if wait != WAIT_OBJECT_0 {
                    let _ = windows::Win32::System::Threading::TerminateProcess(daemon_process, 1);
                    let _ = WaitForSingleObject(daemon_process, 2000);
                }
                let _ = CloseHandle(daemon_process);
            }
        }

        result
    }
}

impl Drop for NetfilterHandle {
    /// `stop`を呼ばずにドロップされた場合（異常系）でも、パイプを閉じてdaemonプロセスへ
    /// 通知する。daemon側は2件目のメッセージ待ちが`ERROR_BROKEN_PIPE`で失敗し、
    /// フェイルセーフのteardown経路（モジュールdoc参照）へ入る。
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

/// daemon側エントリポイント（`harness-netfilterd.exe`のmainから呼ぶ、昇格トークンで実行される）。
pub fn serve(pipe_name: &str) -> Result<(), NetfilterError> {
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
        .map_err(NetfilterError::from)?
    };

    let result = serve_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

fn serve_inner(pipe: HANDLE) -> Result<(), NetfilterError> {
    // 1回目: ApplyRules を待つ。
    let request_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
    let (
        allow_domains,
        allow_loopback,
        allow_loopback_ports,
        allow_loopback_tcp_ports,
        allow_loopback_udp_ports,
        allow_direct_dns,
        audit_log_path,
    ) = match serde_json::from_slice::<NetfilterRequest>(&request_bytes) {
        Ok(NetfilterRequest::ApplyRules {
            allow_domains,
            allow_loopback,
            allow_loopback_ports,
            allow_loopback_tcp_ports,
            allow_loopback_udp_ports,
            allow_direct_dns,
            audit_log_path,
        }) => (
            allow_domains,
            allow_loopback,
            allow_loopback_ports,
            allow_loopback_tcp_ports,
            allow_loopback_udp_ports,
            allow_direct_dns,
            audit_log_path,
        ),
        Ok(NetfilterRequest::Teardown) => {
            let resp = NetfilterResponse::Err(
                "expected ApplyRules as the first message, got Teardown".to_string(),
            );
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc("protocol violation".to_string()));
        }
        Err(e) => {
            let resp = NetfilterResponse::Err(format!("malformed ApplyRules request: {e}"));
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc(format!("malformed request: {e}")));
        }
    };

    let sid = match win_appcontainer::ensure_profile(CONTAINER_NAME) {
        Ok(sid) => sid,
        Err(e) => {
            let resp = NetfilterResponse::Err(format!("failed to resolve sandbox SID: {e}"));
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc(e.to_string()));
        }
    };

    let opts = WfpOptions {
        allow_domains,
        allow_loopback,
        allow_loopback_ports,
        allow_loopback_tcp_ports,
        allow_loopback_udp_ports,
        allow_direct_dns,
        audit_log_path,
    };
    let session = match WfpSession::apply(sid.as_psid(), &opts) {
        Ok(s) => s,
        Err(e) => {
            let resp = NetfilterResponse::Err(format!("WFP rule application failed: {e}"));
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc(e.to_string()));
        }
    };
    send_response(pipe, &NetfilterResponse::Applied)?;

    // 2回目: Teardown、または親のクラッシュによるパイプ切断を待つ。
    let teardown_result = read_framed_timeout(pipe, DAEMON_WAIT_FOR_TEARDOWN_TIMEOUT);
    let is_explicit_teardown = matches!(
        &teardown_result,
        Ok(bytes) if matches!(
            serde_json::from_slice::<NetfilterRequest>(bytes),
            Ok(NetfilterRequest::Teardown)
        )
    );

    let session_teardown = session.teardown();

    if is_explicit_teardown {
        let resp = match &session_teardown {
            Ok(()) => NetfilterResponse::TornDown,
            Err(e) => NetfilterResponse::Err(format!("teardown failed: {e}")),
        };
        // 応答送信の失敗はここでは致命的としない（親が既に読み取りを諦めている可能性がある）。
        let _ = send_response(pipe, &resp);
    }
    // フェイルセーフ経路（パイプ切断・タイムアウト）では応答を送らない
    // （送り先の親が既に存在しない可能性が高いため、送信を試みても無意味）。

    session_teardown.map_err(|e| NetfilterError::Ipc(e.to_string()))
}

fn send_response(pipe: HANDLE, resp: &NetfilterResponse) -> Result<(), NetfilterError> {
    let bytes = serde_json::to_vec(resp)
        .map_err(|e| NetfilterError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, TEARDOWN_RESPONSE_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_rules_request_roundtrips_through_json() {
        let req = NetfilterRequest::ApplyRules {
            allow_domains: vec!["github.com".to_string(), "api.anthropic.com".to_string()],
            allow_loopback: true,
            allow_loopback_ports: vec![18080, 18053],
            allow_loopback_tcp_ports: vec![18080, 18053],
            allow_loopback_udp_ports: vec![18053],
            allow_direct_dns: false,
            audit_log_path: Some(PathBuf::from(".harness/sandbox/session-x/net-audit.jsonl")),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: NetfilterRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            NetfilterRequest::ApplyRules {
                allow_domains,
                allow_loopback,
                allow_loopback_ports,
                allow_loopback_tcp_ports,
                allow_loopback_udp_ports,
                allow_direct_dns,
                audit_log_path,
            } => {
                assert_eq!(
                    allow_domains,
                    vec!["github.com".to_string(), "api.anthropic.com".to_string()]
                );
                assert!(allow_loopback);
                assert_eq!(allow_loopback_ports, vec![18080, 18053]);
                assert_eq!(allow_loopback_tcp_ports, vec![18080, 18053]);
                assert_eq!(allow_loopback_udp_ports, vec![18053]);
                assert!(!allow_direct_dns);
                assert_eq!(
                    audit_log_path,
                    Some(PathBuf::from(".harness/sandbox/session-x/net-audit.jsonl"))
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn teardown_request_roundtrips_through_json() {
        let bytes = serde_json::to_vec(&NetfilterRequest::Teardown).unwrap();
        let decoded: NetfilterRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, NetfilterRequest::Teardown));
    }

    #[test]
    fn responses_roundtrip_through_json() {
        for resp in [
            NetfilterResponse::Applied,
            NetfilterResponse::TornDown,
            NetfilterResponse::Err("boom".to_string()),
        ] {
            let bytes = serde_json::to_vec(&resp).unwrap();
            let decoded: NetfilterResponse = serde_json::from_slice(&bytes).unwrap();
            match (&resp, &decoded) {
                (NetfilterResponse::Applied, NetfilterResponse::Applied) => {}
                (NetfilterResponse::TornDown, NetfilterResponse::TornDown) => {}
                (NetfilterResponse::Err(a), NetfilterResponse::Err(b)) => assert_eq!(a, b),
                _ => panic!("roundtrip mismatch: {resp:?} vs {decoded:?}"),
            }
        }
    }

    #[test]
    fn malformed_bytes_are_rejected_not_panicking() {
        let garbage = b"{\"not\":\"a valid NetfilterRequest\"}";
        let result = serde_json::from_slice::<NetfilterRequest>(garbage);
        assert!(result.is_err());
    }

    #[test]
    fn apply_rules_request_accepts_legacy_json_without_loopback_ports() {
        let legacy =
            r#"{"ApplyRules":{"allow_domains":[],"allow_loopback":true,"allow_direct_dns":false}}"#;
        let decoded: NetfilterRequest = serde_json::from_str(legacy).unwrap();
        match decoded {
            NetfilterRequest::ApplyRules {
                allow_loopback_ports,
                allow_loopback_tcp_ports,
                allow_loopback_udp_ports,
                ..
            } => {
                assert!(allow_loopback_ports.is_empty());
                assert!(allow_loopback_tcp_ports.is_empty());
                assert!(allow_loopback_udp_ports.is_empty());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// パイプの配線を、昇格・別プロセス起動なしで検証する（`privhelper.rs`の同名テストと
    /// 同じ手法。WFP呼び出し自体は含まない、実機E2Eで別途検証する）。
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
