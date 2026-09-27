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
        let bytes = start_collect_bytes(policy)?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        let response = read_framed_timeout(self.pipe, START_RESPONSE_TIMEOUT)
            .map_err(|e| LearnError::Ipc(e.to_string()))?;
        self.etw_available = accept_started(&response, policy)?;
        Ok(())
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

/// [BUG-098] 常駐WFP daemonへ「収集器をこのパイプ名で起こしてくれ」と頼む口。
///
/// パイプ名を渡し、成否を返すだけ。**依頼の実体は上位のクレートが持つ**（この`policy_learnd`は
/// netfilterdのセッション型を知らないし、知るべきでもない）ので、閉包で受け取る。
/// 失敗は人が読む文字列で返る——ここで分岐する側はおらず、警告に載せるだけである。
pub type ChainLaunch<'a> = dyn Fn(&str) -> Result<(), String> + 'a;

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
    /// 試みたシナリオA／自分で`runas`するシナリオB）。再利用に成功したときと、daemonが
    /// 生きていて要求を拒んだときは`prelude`をdropしてパイプを閉じる。
    ///
    /// # [BUG-098] 起こし直しも連鎖起動の経路を通る
    ///
    /// 旧実装は入口で無条件に`prelude`を落としていたので、**daemonが死んでいると分かった頃には
    /// 連鎖起動に使えるパイプが手元に無く**、起こし直しは必ず`runas`（＝UACが1回）になっていた。
    /// しかもそのために、下の「起こす」処理の**劣化した写し**をこの分岐の中に持っていた（`B-05`）。
    ///
    /// いまは落とす位置を「使わないと確定した分岐」へ移し、死んでいた場合は**下の共通処理へ
    /// 落ちる**。
    ///
    /// ## `chain_launch`が要る理由——呼び出し側は「生きているつもり」だった
    ///
    /// **落とす位置を直すだけでは足りない。** 呼び出し側は`is_live()`（＝ハンドルを持っているか）
    /// を見て`prelude`を用意するかどうかを決めるので、**daemonが黙って死んでいた場合は
    /// そもそも用意していない**。つまりこの経路には最初から`None`しか来ない。
    ///
    /// だから**死んだと分かった時点で、こちらから連鎖起動を依頼できる口**を受け取る。
    /// 連鎖起動の実体（常駐WFP daemonへの要求）は上位のクレートが持つので、
    /// **閉包で渡してもらう**——このクレートが上位の型に依存しないための形である。
    /// `None`なら従来どおり`runas`（UACが1回）へ倒れる。
    pub fn start(
        &mut self,
        prelude: Option<PreparedLearnPipe>,
        chain_attempted: bool,
        policy: LearnPolicy,
        chain_launch: Option<&ChainLaunch<'_>>,
    ) -> Result<Collecting, LearnError> {
        let mut prelude = prelude;
        let mut chain_attempted = chain_attempted;
        if let Some(mut handle) = self.handle.take() {
            match handle.start_collect(&policy) {
                Ok(()) => {
                    drop(prelude);
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
                    drop(prelude);
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
                         restarting it"
                    );
                    // [BUG-098] **ここで初めて連鎖起動を依頼する。** 呼び出し側は
                    // 「生きているつもり」だったので`prelude`を用意していない——
                    // 用意していたら（＝最初から死んでいると分かっていたら）そのまま使う。
                    if prelude.is_none() {
                        if let Some(chain) = chain_launch {
                            match prepare_pipe() {
                                Ok(prepared) => match chain(prepared.name()) {
                                    Ok(()) => {
                                        prelude = Some(prepared);
                                        chain_attempted = true;
                                    }
                                    // **落ちた理由を黙らせない。** ここで黙ると
                                    // 「なぜUACが出たのか」が誰にも分からなくなる（`B-10`）。
                                    Err(reason) => eprintln!(
                                        "warning: could not chain-launch the collector from the \
                                         resident WFP daemon ({reason}); falling back to a direct \
                                         elevated start (one UAC prompt)"
                                    ),
                                },
                                Err(e) => eprintln!(
                                    "warning: could not prepare a pipe for the chained restart \
                                     ({e}); falling back to a direct elevated start (one UAC \
                                     prompt)"
                                ),
                            }
                        }
                    }
                    // **`prelude`は落とさない。** 下の共通処理がシナリオA／Bを選ぶ。
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
        // **argv観測が張れなかった**（段階6d）。答えが返っている＝daemonは生きているし、
        // 足りないのはマシン全体のETWの枠なので、**起こし直しても同じ拒否に着く**
        // （UACが1回増えるだけ）。版ずれで欄を答えない古い収集器も同じで、
        // 直す手は「常駐を畳んで起こし直す」であって「もう1つ起こす」ではない。
        LearnError::ArgvCaptureUnavailable(_) => false,
        // パイプが壊れた・応答が来ない＝死んでいる可能性が高い。
        LearnError::Ipc(_) | LearnError::Win32(_) => true,
        // 起動そのものに失敗した（そもそもdaemonが居ない）。
        LearnError::ElevationDeclined(_) | LearnError::UnsafeLaunchTarget(_) => true,
    }
}

/// `StartCollect`のワイヤ表現を作る。
///
/// **シンクの先行作成をここに閉じ込める**（なぜ先に作るかは
/// [`crate::elevated_launch::precreate_audit_sink`]、[BUG-109](../../../../docs/bugs/BUG-109.md)）。
/// 送信点は2つある（生きているdaemonへの再送＝[`PolicyLearnHandle::start_collect`]と、
/// 起こした直後の[`handshake`]）ので、「送る前に作る」を各所へ書くと3つ目が生えたときに
/// 片方だけ漏れる（B-06: 選ぶ自由を奪う）。
fn start_collect_bytes(policy: &LearnPolicy) -> Result<Vec<u8>, LearnError> {
    crate::elevated_launch::precreate_audit_sink(
        &policy.fs_audit_log_path,
        "policy-learn audit sink",
    );
    if policy.capture_argv {
        // **候補の積み先も先に作る**（段階6d）。書き手は同じ昇格プロセスなので、
        // 先に作らなければ所有者が`BUILTIN\Administrators`になる——ここは
        // `.harness/`配下＝制御面なので、次の起動で`.harness/**`の保護が完成せず
        // Tier2aが丸ごと中止する（[BUG-109](../../../../docs/bugs/BUG-109.md)と同じ形）。
        //
        // **拒否の待ち行列（`pending.jsonl`）には要らない。** あちらの書き手は
        // Spawn Daemonで、**昇格していない**（§10.2の書き手の表）。
        crate::elevated_launch::precreate_audit_sink(
            &super::observed::observed_path(&policy.workspace_root),
            "observed transition candidates",
        );
    }
    serde_json::to_vec(&LearnRequest::StartCollect(policy.clone()))
        .map_err(|e| LearnError::Ipc(format!("failed to serialize StartCollect: {e}")))
}

fn handshake(pipe: HANDLE, policy: &LearnPolicy) -> Result<bool, LearnError> {
    connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        LearnError::Ipc(format!(
            "waiting for the collector to connect: {e} (it may not have launched, or UAC is \
             still pending user interaction)"
        ))
    })?;
    let bytes = start_collect_bytes(policy)?;
    write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))?;
    let response = read_framed_timeout(pipe, START_RESPONSE_TIMEOUT)
        .map_err(|e| LearnError::Ipc(e.to_string()))?;
    accept_started(&response, policy)
}

/// `StartCollect`の応答を受理してよいかを判定し、ETWセッションが張れたかを返す。
///
/// # なぜ関数にしてあるのか
///
/// **`StartCollect`を送る経路が2つあるからである**——収集器を起こして最初の記録を始める
/// [`handshake`]と、生きている収集器への[`PolicyLearnHandle::start_collect`]
/// （2回目以降。D-56段階2でUACを出さないために足した経路）。かつては同じ照合が両方へ
/// 複製されており、**新しい検問を足すときに片方だけへ足せてしまう形**だった（`B-06`）。
///
/// # 断る3つの理由（いずれも「この記録は始めさせない」）
///
/// 1. **Spawn Daemon PIDをechoしない**——Daemonが親になった子をスコープ判定が拾えない
/// 2. **argv観測を頼んだのに「張っていない」と答えた**——候補が1件も出ない記録になる（§10.3）
/// 3. **argv観測を頼んだのに何も答えない**——古い収集器が欄ごと捨てている
///
/// **2と3を同じ文面で断らない。** 運用者の打つ手が違う——2は枠を空ける、
/// 3は常駐している収集器を畳んで起こし直す。
fn accept_started(response: &[u8], policy: &LearnPolicy) -> Result<bool, LearnError> {
    match serde_json::from_slice::<LearnResponse>(response) {
        Ok(LearnResponse::Started {
            etw_available,
            spawn_daemon_pid,
            argv_capture,
        }) => {
            if spawn_daemon_pid != policy.spawn_daemon_pid {
                return Err(LearnError::Ipc(
                    "the collector did not echo the requested Spawn Daemon PID; it is an older \
                     build that ignores the field (stop the resident collector and let this \
                     session start a fresh one)"
                        .to_string(),
                ));
            }
            if policy.capture_argv {
                match argv_capture {
                    Some(true) => {}
                    Some(false) => {
                        return Err(LearnError::ArgvCaptureUnavailable(
                            "the collector started, but not the argv (command line) capture \
                             session, so this recording would observe no process-transition \
                             candidates; free a system logger slot and retry \
                             (logman query -ets lists the sessions holding them)"
                                .to_string(),
                        ))
                    }
                    None => {
                        return Err(LearnError::ArgvCaptureUnavailable(
                            "the collector did not report whether it captured argv; it is an \
                             older build that ignores the field (stop the resident collector and \
                             let this session start a fresh one)"
                                .to_string(),
                        ))
                    }
                }
            }
            Ok(etw_available)
        }
        Ok(LearnResponse::ArgvCaptureUnavailable { reason }) => {
            Err(LearnError::ArgvCaptureUnavailable(reason))
        }
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

#[cfg(test)]
mod client_tests {
    use super::*;

    fn policy(sink: PathBuf) -> LearnPolicy {
        LearnPolicy {
            session_profile: "harness.shell.sandbox.1-2".to_string(),
            workspace_root: PathBuf::from("C:/work"),
            fs_audit_log_path: sink,
            harness_pid: None,
            spawn_daemon_pid: None,
            record_all: false,
            capture_argv: false,
        }
    }

    /// **[BUG-109] 監査ログのシンクは、依頼する側（非昇格）が先に作る。**
    ///
    /// 昇格した収集器に作らせると所有者が`BUILTIN\Administrators`になり、非昇格のharnessは
    /// 以後そのファイルのDACLを書けない。シンクは`.harness/`配下＝制御面にあるので、
    /// 次の`preflight`が`.harness/**`を保護しきれず、Tier2aがfail-closedで中止する
    /// ——同じworkspaceでパス1を1回でも回すとパス2が二度と成立しなくなっていた。
    ///
    /// 所有者そのものはこのプロセスの昇格状態に依存するので断定しない。ここで固定するのは
    /// **依頼を送る前にファイルが存在すること**（＝収集器の`create(true)`が作成側に
    /// 回らないこと）である。
    ///
    /// **測る対象は`start_collect_bytes`**——送信点2つが実際に通る関数がここだからで、
    /// `precreate_audit_sink`を直接呼ぶと「配線されていなくても緑」になる。
    #[test]
    fn the_audit_sink_exists_before_the_collector_is_asked_to_open_it() {
        let tmp = tempfile::tempdir().unwrap();
        // 親ディレクトリも未作成の状態から始める（実際の記録セッションはこの形）。
        let sink = tmp
            .path()
            .join("sandbox")
            .join("s-1")
            .join("fs-audit.jsonl");
        assert!(!sink.exists());

        let bytes = start_collect_bytes(&policy(sink.clone())).expect("serialize StartCollect");

        assert!(
            sink.exists(),
            "収集器へ渡す前にシンクが無ければ、作るのは昇格側になる"
        );
        // 依頼そのものが壊れていないことも同時に見る（作るだけになっていないか）。
        assert!(String::from_utf8_lossy(&bytes).contains("StartCollect"));
    }

    fn started(etw: bool, argv_capture: Option<bool>) -> Vec<u8> {
        serde_json::to_vec(&LearnResponse::Started {
            etw_available: etw,
            spawn_daemon_pid: None,
            argv_capture,
        })
        .unwrap()
    }

    /// **[段階6d] fail-closedの本体**（§10.3）。argv観測を頼んだ記録は、
    /// 「張った」と答えられない限り始まらない。
    ///
    /// ここが`accept_started`を直接測るのは、**`StartCollect`を送る経路が2つある**
    /// （初回の`handshake`と、生きている収集器への`start_collect`）からである。
    /// 経路側で測ると、片方だけ検問を足した実装でも緑になる（`B-06`）。
    #[test]
    fn a_recording_that_asked_for_argv_is_refused_unless_the_collector_captured_it() {
        let mut asked = policy(PathBuf::from("C:/x/fs-audit.jsonl"));
        asked.capture_argv = true;

        // 張った → 通る。
        assert!(accept_started(&started(true, Some(true)), &asked).is_ok());

        // 張っていないと答えた → 断る（枠を空ける、が打つ手）。
        let refused = accept_started(&started(true, Some(false)), &asked).unwrap_err();
        assert!(
            matches!(refused, LearnError::ArgvCaptureUnavailable(_)),
            "{refused:?}"
        );

        // 版が古くて答えない → 断る（常駐を畳んで起こし直す、が打つ手）。
        let stale = accept_started(&started(true, None), &asked).unwrap_err();
        assert!(
            matches!(stale, LearnError::ArgvCaptureUnavailable(_)),
            "版ずれの収集器が「argvを観測した」ものとして通っている: {stale:?}"
        );
        // **2つの断りは文面が違う**——打つ手が違うので、同じ文面にすると運用者が迷う。
        assert_ne!(refused.to_string(), stale.to_string());
    }

    /// **対の側**（`B-35`）: argvを頼んでいない記録は、古い収集器でも通る。
    ///
    /// これが無いと「常に断る」実装でも上のテストは緑になり、**通常運用のFS拒否収集まで
    /// 止まる**（fail-closedの波及範囲はエディタのパス1だけ、という決定に反する）。
    #[test]
    fn a_recording_that_did_not_ask_for_argv_still_accepts_an_older_collector() {
        let not_asked = policy(PathBuf::from("C:/x/fs-audit.jsonl"));
        assert!(!not_asked.capture_argv);

        assert!(accept_started(&started(true, None), &not_asked).is_ok());
        assert!(accept_started(&started(false, None), &not_asked).is_ok());
    }

    /// 収集器が「張れなかったので始めなかった」と答えた場合も、同じ変種で伝わる。
    ///
    /// **文面ではなく変種で運ぶ**（`B-13`）——呼び出し側（エディタのパス1）はこの失敗だけ
    /// 記録を中止するので、文面で見分けると文面を直した日に静かにfail-openへ戻る。
    #[test]
    fn the_collectors_own_refusal_arrives_as_the_same_variant() {
        let mut asked = policy(PathBuf::from("C:/x/fs-audit.jsonl"));
        asked.capture_argv = true;
        let response = serde_json::to_vec(&LearnResponse::ArgvCaptureUnavailable {
            reason: "ERROR_NO_SYSTEM_RESOURCES".to_string(),
        })
        .unwrap();

        let error = accept_started(&response, &asked).unwrap_err();
        assert!(
            matches!(error, LearnError::ArgvCaptureUnavailable(_)),
            "{error:?}"
        );
        // **起こし直しても直らない**（答えが返っている＝daemonは生きている）。
        assert!(!daemon_is_dead(&error), "UACをもう1回出しても同じ拒否に着く");
    }

    /// **[段階6d] 候補の積み先も、依頼する側（非昇格）が先に作る。**
    ///
    /// `observed.jsonl`を書くのは**昇格した収集器**（`pending.jsonl`を書くSpawn Daemonとは
    /// 違って昇格している）。先に作らなければ所有者が`BUILTIN\Administrators`になり、
    /// `.harness/**`の保護が完成せずTier2aが丸ごと中止する——BUG-109と同じ形である。
    ///
    /// **測る対象は`start_collect_bytes`**（送信点2つが通る関数）。`precreate_sink`を
    /// 直接呼ぶと「配線されていなくても緑」になる。
    #[test]
    fn the_candidate_sink_exists_before_the_collector_is_asked_to_open_it() {
        let tmp = tempfile::tempdir().unwrap();
        let mut policy = policy(tmp.path().join("sandbox").join("s-1").join("fs-audit.jsonl"));
        policy.workspace_root = tmp.path().to_path_buf();
        policy.capture_argv = true;
        let observed = super::super::observed::observed_path(tmp.path());
        assert!(!observed.exists());

        start_collect_bytes(&policy).expect("serialize StartCollect");

        assert!(
            observed.exists(),
            "収集器へ渡す前に積み先が無ければ、作るのは昇格側になる: {}",
            observed.display()
        );
    }

    /// **対の側**（`B-35`）: argv観測を頼んでいない記録は、候補の積み先を作らない。
    ///
    /// 常に作ると、`.harness/transitions/`が**使われていないワークスペースにも**現れ、
    /// 「候補を集めた記録がある」と読めてしまう。
    #[test]
    fn a_recording_without_argv_capture_does_not_create_the_candidate_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let mut policy = policy(tmp.path().join("sandbox").join("s-1").join("fs-audit.jsonl"));
        policy.workspace_root = tmp.path().to_path_buf();
        policy.capture_argv = false;

        start_collect_bytes(&policy).expect("serialize StartCollect");

        assert!(!super::super::observed::observed_path(tmp.path()).exists());
    }

    /// **既にあるシンクの中身を消さない。** 収集器は`append`で開くので、こちらが
    /// `create(true).truncate(true)`のような開き方をすると、再接続のたびに前の観測が
    /// 消える（`start_collect`は生きているdaemonへ再送する経路でも通る）。
    #[test]
    fn precreating_an_existing_sink_keeps_what_was_already_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = tmp.path().join("fs-audit.jsonl");
        std::fs::write(&sink, "{\"already\":\"recorded\"}\n").unwrap();

        start_collect_bytes(&policy(sink.clone())).expect("serialize StartCollect");

        assert_eq!(
            std::fs::read_to_string(&sink).unwrap(),
            "{\"already\":\"recorded\"}\n"
        );
    }
}
