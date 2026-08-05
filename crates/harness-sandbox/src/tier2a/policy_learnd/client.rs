//! **非特権側**（harness本体の中で動く）。収集器を起こし、その生存を握る。
//!
//! `server.rs`とファイルを分けている理由は規則3（信頼境界＝ファイル境界）。
//!
//! # 生存期間の設計
//!
//! パイプを作るのはこちら（親）で、収集器は**クライアントとして接続してくる**。
//! [`PolicyLearnHandle`]をdropするとパイプが閉じ、収集器側の`ReadFile`が
//! `ERROR_BROKEN_PIPE`で失敗して自発的に撤収する。**つまりharnessが異常終了しても
//! 収集器は取り残されない**——この性質はタイマーでもファイルポーリングでもなく
//! OSハンドルから来ている（グローバル`CLAUDE.md`の常駐昇格キュー禁止に適合）。

use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use super::{LearnError, LearnPolicy, LearnRequest, LearnResponse};
use crate::win_common::wide;
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout,
    user_only_security_attributes, unique_pipe_name, write_framed_timeout,
};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const START_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const TEARDOWN_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 稼働中の収集器。dropするとパイプが閉じ、収集器は自発的に撤収する。
pub struct PolicyLearnHandle {
    pipe: HANDLE,
    process: HANDLE,
    /// ETWセッションが実際に張れたか。`false`なら収集は行われていない（D-43 fail-open）。
    etw_available: bool,
}

impl PolicyLearnHandle {
    /// ETWセッションが実際に張れたか。呼び出し側はこれが`false`のとき、
    /// 「収集器は起動したが観測できていない」ことをユーザーへ伝える。
    pub fn etw_available(&self) -> bool {
        self.etw_available
    }

    /// 明示的に撤収する。観測できた拒否の件数を返す。
    pub fn stop(mut self) -> Result<u64, LearnError> {
        let result = self.teardown();
        self.pipe = HANDLE::default();
        result
    }

    fn teardown(&mut self) -> Result<u64, LearnError> {
        if self.pipe.is_invalid() {
            return Ok(0);
        }
        let bytes = serde_json::to_vec(&LearnRequest::Teardown)
            .map_err(|e| LearnError::Ipc(format!("failed to serialize Teardown: {e}")))?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        let response = read_framed_timeout(self.pipe, TEARDOWN_RESPONSE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        match serde_json::from_slice::<LearnResponse>(&response) {
            Ok(LearnResponse::TornDown { denials_written }) => Ok(denials_written),
            Ok(LearnResponse::Err(message)) => Err(LearnError::Rejected(message)),
            Ok(other) => Err(LearnError::Ipc(format!("unexpected response: {other:?}"))),
            Err(e) => Err(LearnError::Ipc(format!("malformed response: {e}"))),
        }
    }
}

impl Drop for PolicyLearnHandle {
    /// `stop`を呼ばずに落ちた場合でも、パイプを閉じることで収集器へ撤収を伝える
    /// （収集器側の`ReadFile`が`ERROR_BROKEN_PIPE`になる）。ETWセッションは収集器が
    /// 自分で止めるので、ここでプロセスを殺す必要は無い——が、5秒待って消えなければ
    /// staleとみなして強制終了する（`privhelper`と同じ扱い）。
    fn drop(&mut self) {
        unsafe {
            if !self.pipe.is_invalid() {
                let _ = DisconnectNamedPipe(self.pipe);
                let _ = CloseHandle(self.pipe);
            }
            if !self.process.is_invalid() {
                if WaitForSingleObject(self.process, 5000) != WAIT_OBJECT_0 {
                    let _ = TerminateProcess(self.process, 1);
                    let _ = WaitForSingleObject(self.process, 2000);
                }
                let _ = CloseHandle(self.process);
            }
        }
    }
}

/// 連鎖起動用に**先にパイプだけ**作る（M15.7、netfilterdの`PreparedPipe`と同型）。
///
/// netfilterdが自分の昇格トークンのまま収集器を起こす経路では、収集器が接続してくる先の
/// パイプが**起動より前に**存在していなければならない。dropすればパイプは閉じる。
pub struct PreparedLearnPipe {
    handle: HANDLE,
    name: String,
}

unsafe impl Send for PreparedLearnPipe {}

impl PreparedLearnPipe {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 生ハンドルを取り出す（[`connect_after_chain_launch`]専用）。以後の自動クローズは
    /// 行われなくなる（呼び出し先が所有権を引き継ぐ）。
    pub fn into_handle(self) -> HANDLE {
        let handle = self.handle;
        std::mem::forget(self);
        handle
    }
}

impl Drop for PreparedLearnPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// 連鎖起動に使うパイプを用意する。**まだ収集器は起こさない**——起こすのは
/// netfilterd（昇格側）で、こちらはその接続先を先に作るだけ。
pub fn prepare_pipe() -> Result<PreparedLearnPipe, LearnError> {
    let name = unique_pipe_name("policy-learnd");
    let sid = current_user_sid_string()?;
    let mut sa = user_only_security_attributes(&sid)?;
    let handle = unsafe {
        let name_w = wide(&name);
        let handle = CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
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
            return Err(LearnError::from(windows::core::Error::from_win32()));
        }
        handle
    };
    Ok(PreparedLearnPipe { handle, name })
}

/// netfilterdが連鎖起動した収集器とハンドシェイクする（**追加UACなし**の経路）。
///
/// 収集器プロセスのハンドルは持たない——起こしたのはnetfilterdであってこちらではないため。
/// 撤収は`Teardown`（またはパイプ切断）で伝わるので、プロセスハンドルが無くても取り残されない。
pub fn connect_after_chain_launch(
    pipe: HANDLE,
    policy: LearnPolicy,
) -> Result<PolicyLearnHandle, LearnError> {
    match handshake(pipe, &policy) {
        Ok(etw_available) => Ok(PolicyLearnHandle {
            pipe,
            process: HANDLE::default(),
            etw_available,
        }),
        Err(e) => {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            Err(e)
        }
    }
}

/// 収集器を`runas`で昇格起動し、`StartCollect`まで済ませて[`PolicyLearnHandle`]を返す。
///
/// **UACが1回出る。** netfilterdからの連鎖起動（追加UACなし）はPhase Bで足す。
pub fn start(policy: LearnPolicy) -> Result<PolicyLearnHandle, LearnError> {
    let pipe_name = unique_pipe_name("policy-learnd");
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
            return Err(LearnError::from(windows::core::Error::from_win32()));
        }
        handle
    };

    let collector_path = collector_exe_path()?;
    let process = match unsafe { launch_elevated(&collector_path, &pipe_name) } {
        Ok(handle) => handle,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };

    match handshake(pipe, &policy) {
        Ok(etw_available) => Ok(PolicyLearnHandle {
            pipe,
            process,
            etw_available,
        }),
        Err(e) => {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
                if !process.is_invalid() {
                    let _ = TerminateProcess(process, 1);
                    let _ = CloseHandle(process);
                }
            }
            Err(e)
        }
    }
}

fn handshake(pipe: HANDLE, policy: &LearnPolicy) -> Result<bool, LearnError> {
    connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        LearnError::Ipc(format!(
            "waiting for the collector to connect: {e} (it may not have launched, or UAC is \
             still pending user interaction)"
        ))
    })?;
    let bytes = serde_json::to_vec(&LearnRequest::StartCollect(policy.clone()))
        .map_err(|e| LearnError::Ipc(format!("failed to serialize StartCollect: {e}")))?;
    write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))?;
    let response = read_framed_timeout(pipe, START_RESPONSE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))?;
    match serde_json::from_slice::<LearnResponse>(&response) {
        Ok(LearnResponse::Started { etw_available }) => Ok(etw_available),
        Ok(LearnResponse::Err(message)) => Err(LearnError::Rejected(message)),
        Ok(other) => Err(LearnError::Ipc(format!("unexpected response: {other:?}"))),
        Err(e) => Err(LearnError::Ipc(format!("malformed response: {e}"))),
    }
}

/// 収集器の実行ファイルを、**本体exeと同じディレクトリから**解決する
/// （`privhelper`/`netfilterd`と同じ方針。PATHからは探さない）。
fn collector_exe_path() -> Result<PathBuf, LearnError> {
    let current = std::env::current_exe()
        .map_err(|e| LearnError::Win32(format!("failed to resolve current exe path: {e}")))?;
    let dir = current.parent().ok_or_else(|| {
        LearnError::Win32("current exe has no parent directory".to_string())
    })?;
    Ok(dir.join("harness-policy-learnd.exe"))
}

unsafe fn launch_elevated(path: &std::path::Path, pipe_name: &str) -> Result<HANDLE, LearnError> {
    // T-21/D-44: 昇格する前に、その実行ファイルと置き場が非管理者から書けないことを確かめる。
    crate::elevated_launch::verify_elevation_target(path)
        .map_err(|e| LearnError::UnsafeLaunchTarget(e.to_string()))?;

    let verb_w = wide("runas");
    let file_w = wide(&path.to_string_lossy());
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
    if ShellExecuteExW(&mut info).is_err() {
        let err = GetLastError();
        if err == ERROR_CANCELLED {
            return Err(LearnError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(LearnError::Win32(format!("ShellExecuteExW failed: {err:?}")));
    }
    Ok(info.hProcess)
}
