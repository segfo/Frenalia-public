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
    connect_with_timeout, current_user_sid_string, read_framed_timeout, unique_pipe_name,
    user_only_security_attributes, write_framed_timeout,
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

/// ハンドルは所有権とともにスレッドを移動できる（`NetfilterHandle`と同じ扱い）。
///
/// 中身は`HANDLE`（生ポインタ）なので自動では`Send`にならないが、**この構造体は
/// 同時に2箇所から使われない**——[`CollectorSession`]が`Arc<Mutex<..>>`で包み、
/// 記録は`session_lock`により同時に1本しか走らない。TUIが記録を専用スレッドで回すために要る。
unsafe impl Send for PolicyLearnHandle {}

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

    /// 現世代の収集を止める。**daemonは残す**（D-56 段階2。次の`StartCollect`はUAC無し）。
    ///
    /// 失敗したら呼び出し側はこのハンドルを捨てること——「畳めたか分からない収集器」を
    /// 抱えたまま次の記録へ進むと、前の記録のETWセッションが生きているのか誰も言えなくなる
    /// （netfilterdの`clear`と同じ扱い）。
    pub fn stop_collect(&self) -> Result<u64, LearnError> {
        let bytes = serde_json::to_vec(&LearnRequest::StopCollect)
            .map_err(|e| LearnError::Ipc(format!("failed to serialize StopCollect: {e}")))?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        let response = read_framed_timeout(self.pipe, TEARDOWN_RESPONSE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        match serde_json::from_slice::<LearnResponse>(&response) {
            Ok(LearnResponse::Stopped { written }) => Ok(written),
            Ok(LearnResponse::Err(message)) => Err(LearnError::Rejected(message)),
            Ok(other) => Err(LearnError::Ipc(format!("unexpected response: {other:?}"))),
            Err(e) => Err(LearnError::Ipc(format!("malformed response: {e}"))),
        }
    }

    /// 生きているdaemonへ次の記録の`StartCollect`を送る（**UACは出ない**）。
    pub fn start_collect(&mut self, policy: &LearnPolicy) -> Result<(), LearnError> {
        let bytes = serde_json::to_vec(&LearnRequest::StartCollect(policy.clone()))
            .map_err(|e| LearnError::Ipc(format!("failed to serialize StartCollect: {e}")))?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        let response = read_framed_timeout(self.pipe, START_RESPONSE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        match serde_json::from_slice::<LearnResponse>(&response) {
            Ok(LearnResponse::Started { etw_available }) => {
                self.etw_available = etw_available;
                Ok(())
            }
            Ok(LearnResponse::Err(message)) => Err(LearnError::Rejected(message)),
            Ok(other) => Err(LearnError::Ipc(format!("unexpected response: {other:?}"))),
            Err(e) => Err(LearnError::Ipc(format!("malformed response: {e}"))),
        }
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

/// 収集器daemonを**プロセスの寿命で**持つ（D-56 段階2）。netfilterdの`NetfilterSession`と同型。
///
/// 「生きているなら`StartCollect`を再送、無ければ起こす」「記録の切れ目で`StopCollect`」
/// 「`Drop`で`Teardown`」の3つを持つ。**UACが出るのは最初の1回だけ**になる。
#[derive(Default)]
pub struct CollectorSession {
    handle: Option<PolicyLearnHandle>,
}

/// [`CollectorSession::start`]の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Collecting {
    /// ETWセッションが実際に張れたか（`false`なら何も観測できない、D-43）。
    pub etw_available: bool,
    /// 既存daemonを再利用したか。**表示に出すこと**——UACが出なかったことを
    /// 「収集器が動いていない」と読み違えられると、この記録の意味が正反対になる（B-32）。
    pub reused: bool,
}

impl CollectorSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// 生きているdaemonを持っているか。**呼び出し側はこれを見て、投機的パイプの用意と
    /// 連鎖起動の依頼を省く**（B-23(c) 二重起動ガード）。
    pub fn is_live(&self) -> bool {
        self.handle.is_some()
    }

    /// 収集を開始する。生きているdaemonがあれば`StartCollect`を再送するだけ、無ければ起こす。
    ///
    /// `prelude`/`chain_attempted`は**daemonを起こす場合にだけ**使う（netfilterdが連鎖起動を
    /// 試みたシナリオA／自分で`runas`するシナリオB）。再利用時は`prelude`をdropしてパイプを閉じる。
    pub fn start(
        &mut self,
        prelude: Option<PreparedLearnPipe>,
        chain_attempted: bool,
        policy: LearnPolicy,
    ) -> Result<Collecting, LearnError> {
        if let Some(mut handle) = self.handle.take() {
            drop(prelude);
            match handle.start_collect(&policy) {
                Ok(()) => {
                    let etw_available = handle.etw_available();
                    self.handle = Some(handle);
                    return Ok(Collecting {
                        etw_available,
                        reused: true,
                    });
                }
                // daemonは生きていて要求を拒んだ。起こし直しても同じ拒否になるだけで、
                // UACを1回増やして同じ場所に着く。**そのまま伝播する。**
                Err(e) if !daemon_is_dead(&e) => {
                    self.handle = Some(handle);
                    return Err(e);
                }
                // パイプが壊れた＝daemonが死んでいる。ここで1度だけ起こし直す
                // （再試行は1回に固定する——起こし直しの失敗は伝播させる）。
                Err(e) => {
                    // ハンドルを落とす＝パイプが閉じる＝死にかけのdaemonが残っていても撤収する。
                    drop(handle);
                    eprintln!(
                        "warning: the policy-learning collector stopped answering ({e}); \
                         restarting it (one UAC prompt)"
                    );
                    // 連鎖起動用のパイプはもう無いので、起こし直しは必ずシナリオB。
                    let handle = start(policy)?;
                    let etw_available = handle.etw_available();
                    self.handle = Some(handle);
                    return Ok(Collecting {
                        etw_available,
                        reused: false,
                    });
                }
            }
        }

        let handle = match (chain_attempted, prelude) {
            // シナリオA: netfilterdが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
            (true, Some(prepared)) => connect_after_chain_launch(prepared.into_handle(), policy)?,
            // シナリオB: 連鎖起動は発生しなかった。投機的パイプは使わない（`start`が自前で
            // 新規パイプを作る）、dropして自動的に閉じる。
            (_, prelude) => {
                drop(prelude);
                start(policy)?
            }
        };
        let etw_available = handle.etw_available();
        self.handle = Some(handle);
        Ok(Collecting {
            etw_available,
            reused: false,
        })
    }

    /// 現世代を畳む（**daemonは次の記録のために残す**）。書けた件数を返す。
    ///
    /// 失敗したらハンドルを捨てる——畳めたか分からない収集器を抱えたまま次の記録へ進むと、
    /// 「待機中はETWセッションを持たない」という不変条件を誰も言えなくなる。捨てた場合、
    /// 次の[`Self::start`]はdaemonを起こし直す（UACが1回）。
    pub fn stop(&mut self) -> Result<Option<u64>, LearnError> {
        let Some(handle) = self.handle.as_ref() else {
            return Ok(None);
        };
        match handle.stop_collect() {
            Ok(written) => Ok(Some(written)),
            Err(e) => {
                self.handle = None;
                Err(e)
            }
        }
    }
}

impl Drop for CollectorSession {
    /// プロセス終了時に`Teardown`を送る。送れなくても、パイプが閉じることで収集器側の
    /// `ReadFile`が`ERROR_BROKEN_PIPE`になり自発的に撤収する（最後の砦はOSハンドル）。
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.stop();
        }
    }
}

/// 再利用に失敗したとき、**daemonが死んでいる**と言えるか。
///
/// 死んでいるなら1度だけ起こし直す価値があり、生きていて拒んだだけなら起こし直しても
/// 同じ拒否に着く（UACが1回増えるだけ）。判定を純粋関数にしてあるのは、この表を
/// 実daemonなしで固定するためである（netfilterdの`daemon_is_dead`と同じ形）。
pub fn daemon_is_dead(error: &LearnError) -> bool {
    match error {
        // 受信側が答えを返した＝生きている。
        LearnError::Rejected(_) => false,
        // パイプが壊れた・応答が来ない＝死んでいる可能性が高い。
        LearnError::Ipc(_) | LearnError::Win32(_) => true,
        // 起動そのものに失敗した（そもそもdaemonが居ない）。
        LearnError::ElevationDeclined(_) | LearnError::UnsafeLaunchTarget(_) => true,
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
    let dir = current
        .parent()
        .ok_or_else(|| LearnError::Win32("current exe has no parent directory".to_string()))?;
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
        return Err(LearnError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }
    Ok(info.hProcess)
}
