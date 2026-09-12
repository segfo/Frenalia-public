//! harness側から見たSpawn Daemon（§10.1・§12）。**制御パイプの持ち主**である。
//!
//! # 誰がどれを作るのか
//!
//! ```text
//!   harness                             Daemon
//!   ├─ 制御パイプ（サーバ側）  ──────▶  クライアントとして接続
//!   ├─ 系統Job               ──複製──▶  Process Tableが保持（§10.1.1）
//!   ├─ 子のstdioパイプ        ──複製──▶  CreateProcessWで子へ継承させる（§10.1）
//!   └─ 自分のプロセスハンドル ──複製──▶  子のハンドルを返すときの複製先
//!                             ◀──複製──  子のプロセスハンドル
//! ```
//!
//! **ハンドルの流れはほぼ一方向である。** 逆向きは1つだけ——Daemonが起こした子の
//! プロセスハンドルで、これは**Daemonしか持っていない**ので選択の余地が無い。
//! 逆向きを増やさないために、harnessは自分のプロセスハンドルを
//! `PROCESS_DUP_HANDLE`だけに絞って渡す（Daemonに`OpenProcess`させない）。
//!
//! # Daemonが落ちたときの姿勢（§10.1）
//!
//! **回復手段は用意しない。** Process TableはDaemonのメモリにしか無く、生存中のプロセスの
//! ドメインは「生成時にDaemonがポリシーから決めた」ものなので、後から観測して復元できない。
//! 空のTableで立て直すと**全プロセスがdenyに落ちた状態で動き続ける**——原因が見えないので、
//! それより識別可能なエラーで止まるほうがよい（`B-10`）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_CLOSE_SOURCE, DUPLICATE_HANDLE_OPTIONS,
    DUPLICATE_SAME_ACCESS, HANDLE, HLOCAL,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS, PROCESS_DUP_HANDLE, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use crate::win_common::wide;
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout, unique_pipe_name,
    user_only_security_attributes, write_framed_timeout,
};

use super::server::SpawnDaemonError;
use super::{
    protocol_version_mismatch, ChildHandles, ChildProcessPolicy, ConsoleNeed, ControlRequest,
    ControlResponse, DomainSpec, RedirectorSpec, SpawnFailureKind, SpawnTopLevelRequest,
    ACCEPT_TIMEOUT, IO_TIMEOUT, PROTOCOL_VERSION,
};

fn err(message: impl Into<String>) -> SpawnDaemonError {
    SpawnDaemonError {
        kind: SpawnFailureKind::Transport,
        message: message.into(),
    }
}

fn protocol_err(message: impl Into<String>) -> SpawnDaemonError {
    SpawnDaemonError {
        kind: SpawnFailureKind::Protocol,
        message: message.into(),
    }
}

/// harnessが頼むトップレベル生成。
///
/// # ハンドルの扱い（**読まずに渡すと閉じ漏れる**）
///
/// | 欄 | 誰が閉じるか |
/// |---|---|
/// | `job` | **harnessのまま。** Daemonへは複製が渡る（§10.1.1「Jobを作るプロセスはharness」） |
/// | `stdout_write`・`stderr_write`・`stdin_read` | **[`SpawnDaemonHandle::spawn_top_level`]が閉じる**（成否によらず） |
///
/// stdioを消費する側にしてあるのは、`create_suspended_in_job`が同じ契約を持つからである
/// ——「継承させる端は渡した先が閉じる」で揃えないと、経路ごとに規則が違うことになる。
pub struct TopLevelSpawn<'a> {
    pub exe: &'a str,
    pub args: &'a [&'a str],
    pub cwd: &'a Path,
    pub env: &'a [(String, String)],
    pub domain: DomainSpec,
    pub job: HANDLE,
    pub stdout_write: HANDLE,
    pub stderr_write: HANDLE,
    pub stdin_read: Option<HANDLE>,
    pub redirector: Option<RedirectorSpec>,
    /// [段階⑤] 起こすプログラムがコンソールを要るか。**既定値を持たせていない**ので、
    /// 呼び出し元は毎回選ぶ（同型のdocに、取り違えたときの壊れ方がある）。
    pub console: ConsoleNeed,
}

/// Daemonが起こした子。
///
/// `Debug`は**テストが「起こせなかったこと」を主張するために要る**（`expect_err`が
/// 成功側の`Debug`を要求する）。載るのはPIDとハンドル値だけで、秘密は含まない。
#[derive(Debug)]
pub struct SpawnedChild {
    pub pid: u32,
    /// **`SYNCHRONIZE`と`PROCESS_QUERY_LIMITED_INFORMATION`だけ**を持つハンドル（§14の姿勢）。
    /// 待つことと終了コードを読むことはできるが、書き込みも生成もできない。
    /// **閉じるのは受け取った側**である。
    pub process: HANDLE,
}

/// 常駐しているSpawn Daemonへの接続。
///
/// **落とすとDaemonも終わる**（制御パイプが閉じるため）。タイマーにも
/// クライアントからの完了メッセージにも依存しない（§10.1）。
pub struct SpawnDaemonHandle {
    control: HANDLE,
    /// 制御パイプの名前。**本番では誰も読まない**（`control_pipe_name()`が`#[cfg(test)]`）
    /// ——名前を渡さないこと自体は境界ではなく、境界はDACLである（§10.1）。
    /// 保持しているのは対の測定のためだけなので、非テストビルドでは未使用で正しい。
    #[cfg_attr(not(test), allow(dead_code))]
    control_pipe_name: String,
    daemon_process: HANDLE,
    request_pipe: String,
    daemon_pid: u32,
    stopped: bool,
}

// `HANDLE`はカーネルオブジェクトへのポインタ値で、別スレッドから使っても
// OSレベルでは安全（`RestrictedChild`のSend実装と同じ理由）。
unsafe impl Send for SpawnDaemonHandle {}

/// 1ホストプロセスが共有するSpawn Daemon接続。
///
/// 制御パイプは要求と応答が1対1で並ぶ1本のストリームなので、全トランザクションをMutexで
/// 直列化する。通信途中で壊れた接続はProcess Tableごと失われた可能性があるため、同じ
/// ホスト内で自動再起動しない。
#[derive(Clone)]
pub struct SharedSpawnDaemon {
    inner: Arc<Mutex<SharedState>>,
    request_pipe: Arc<str>,
    daemon_pid: u32,
}

struct SharedState {
    handle: Option<SpawnDaemonHandle>,
    broken: Option<String>,
}

/// 制御要求を送る前にDaemonへ複製したハンドルを、途中失敗時だけ回収するガード。
struct RemoteHandleGuard {
    daemon_process: HANDLE,
    handles: Vec<u64>,
    armed: bool,
}

impl RemoteHandleGuard {
    fn new(daemon_process: HANDLE) -> Self {
        Self {
            daemon_process,
            handles: Vec::new(),
            armed: true,
        }
    }

    fn track(&mut self, handle: u64) -> u64 {
        self.handles.push(handle);
        handle
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemoteHandleGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for remote in self.handles.drain(..) {
            let mut local = HANDLE::default();
            let result = unsafe {
                DuplicateHandle(
                    self.daemon_process,
                    HANDLE(remote as *mut _),
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    false,
                    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                )
            };
            if result.is_ok() {
                unsafe {
                    let _ = CloseHandle(local);
                }
            }
        }
    }
}

impl std::fmt::Debug for SharedSpawnDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSpawnDaemon")
            .field("daemon_pid", &self.daemon_pid)
            .field("request_pipe", &self.request_pipe)
            .finish_non_exhaustive()
    }
}

impl SharedSpawnDaemon {
    /// `child_process_policy`は**呼び出し元が必ず選ぶ**（[`ChildProcessPolicy`]のdoc）。
    /// 製品のホスト2つ（harness本体・ポリシーエディタ）は`Unrestricted`である。
    ///
    /// [段階6b] `policy`も**呼び出し元が必ず渡す**。既定を持たせないのは、
    /// 渡し忘れた経路のDaemonが**宣言を1本も持たないまま立ち上がり、
    /// 宣言してある遷移まで拒否する**ためである（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。
    pub fn start(
        policy: super::TransitionPolicy,
        child_process_policy: ChildProcessPolicy,
    ) -> Result<Self, SpawnDaemonError> {
        let handle = SpawnDaemonHandle::start(policy, child_process_policy)?;
        let request_pipe: Arc<str> = Arc::from(handle.request_pipe().to_string());
        let daemon_pid = handle.daemon_pid();
        Ok(Self {
            inner: Arc::new(Mutex::new(SharedState {
                handle: Some(handle),
                broken: None,
            })),
            request_pipe,
            daemon_pid,
        })
    }

    pub fn request_pipe(&self) -> &str {
        &self.request_pipe
    }

    pub fn daemon_pid(&self) -> u32 {
        self.daemon_pid
    }

    pub fn spawn_top_level(
        &self,
        request: TopLevelSpawn<'_>,
    ) -> Result<SpawnedChild, SpawnDaemonError> {
        let mut state = match self.inner.lock() {
            Ok(state) => state,
            Err(_) => {
                close_child_handles(&request);
                return Err(protocol_err(
                "spawn daemon connection mutex was poisoned during a control transaction; refusing to reuse it",
                ));
            }
        };
        if let Some(reason) = state.broken.as_ref() {
            close_child_handles(&request);
            return Err(err(format!(
                "spawn daemon connection is no longer usable and will not be restarted: {reason}"
            )));
        }
        let Some(handle) = state.handle.as_ref() else {
            close_child_handles(&request);
            return Err(err("spawn daemon connection is not available"));
        };
        let result = handle.spawn_top_level(request);
        if let Err(failure) = &result {
            if matches!(
                failure.kind,
                SpawnFailureKind::Transport | SpawnFailureKind::Protocol
            ) {
                let reason = failure.to_string();
                let handle = state.handle.take();
                state.broken = Some(reason);
                drop(handle);
            }
        }
        result
    }

    /// 共有cloneが残っていても接続を一度だけ畳み、以後の生成を拒否する。
    pub fn shutdown(&self) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        state.broken = Some("spawn daemon was shut down by its host".to_string());
        drop(state.handle.take());
    }
}

fn close_child_handles(request: &TopLevelSpawn<'_>) {
    unsafe {
        let _ = CloseHandle(request.stdout_write);
        let _ = CloseHandle(request.stderr_write);
        if let Some(handle) = request.stdin_read {
            let _ = CloseHandle(handle);
        }
    }
}

impl SpawnDaemonHandle {
    /// Daemonを起こし、ハンドシェイクまで済ませる。
    ///
    /// # `child_process_policy`を引数で受ける理由
    ///
    /// 生成禁止を積むかは**Daemon1本の姿勢**で、起動時に決まって以後変わらない
    /// （[`ChildProcessPolicy`]のdoc）。既定値を持つ`start()`を残すと、
    /// **将来Tier2aの全spawnへ常時積むと決めた日に、既定値を掴んでいる経路だけが
    /// 取り残される**——段階5bで`RedirectorInject::default()`を製品から消したのと同じ形である。
    ///
    /// # [段階6b] `policy`も同じ理由で引数である
    ///
    /// 既定を持たせると、渡し忘れた経路のDaemonが**宣言を1本も持たないまま立ち上がる**。
    /// 倒れる向きは拒否（fail-closed）だが、症状は「宣言してあるのに拒否される」なので、
    /// 原因が渡し忘れであることは画面からは分からない。
    pub fn start(
        policy: super::TransitionPolicy,
        child_process_policy: ChildProcessPolicy,
    ) -> Result<Self, SpawnDaemonError> {
        let pipe_name = unique_pipe_name("spawnd-control");
        let sid = current_user_sid_string().map_err(|e| err(format!("current_user_sid: {e}")))?;
        // **制御パイプはユーザーSID専有のまま**（§10.1）。ここへ到達できるのがharnessだけ
        // であることが、「harnessを特権クライアントとして扱う」の根拠そのものである。
        let mut sa =
            user_only_security_attributes(&sid).map_err(|e| err(format!("pipe sddl: {e}")))?;
        let control = unsafe {
            let name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(name_w.as_ptr()),
                // インスタンス占拠の防止（§10.1）。制御パイプは1本しか作らないので、
                // ここは常に「最初の1本」である。
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            if handle.is_invalid() {
                return Err(err(format!(
                    "CreateNamedPipeW({pipe_name}): {}",
                    windows::core::Error::from_win32()
                )));
            }
            handle
        };

        let daemon_process = match launch_daemon(&pipe_name, child_process_policy) {
            Ok(process) => process,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(control);
                }
                return Err(e);
            }
        };

        let mut handle = Self {
            control,
            control_pipe_name: pipe_name,
            daemon_process,
            request_pipe: String::new(),
            daemon_pid: 0,
            stopped: false,
        };
        handle.handshake(policy)?;
        Ok(handle)
    }

    fn handshake(&mut self, policy: super::TransitionPolicy) -> Result<(), SpawnDaemonError> {
        connect_with_timeout(self.control, ACCEPT_TIMEOUT).map_err(|e| err(e.into_message()))?;

        // **`PROCESS_DUP_HANDLE`だけに絞って渡す。** Daemonがこれでできるのは
        // 「harnessのプロセスへハンドルを複製する」ことだけで、読み書きも終了もできない。
        let mut for_daemon = HANDLE::default();
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                self.daemon_process,
                &mut for_daemon,
                PROCESS_DUP_HANDLE.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|e| err(format!("DuplicateHandle(harness process to daemon): {e}")))?;

        self.send(&hello_request(for_daemon.0 as u64, policy))?;
        match self.receive()? {
            ControlResponse::Ready {
                request_pipe,
                daemon_pid,
                protocol_version,
            } => {
                // **harnessとDaemonが同じ関数を通る**（`protocol_version_mismatch`のdoc）。
                if let Some(reason) = protocol_version_mismatch(protocol_version) {
                    return Err(protocol_err(reason));
                }
                self.request_pipe = request_pipe;
                self.daemon_pid = daemon_pid;
                Ok(())
            }
            other => Err(protocol_err(format!("expected Ready, got {other:?}"))),
        }
    }

    /// サンドボックスの子が繋ぐ先。**秘密ではない**（子から`\\.\pipe\`の一覧は取れる）。
    /// 守っているのはDACLだけである（§10.1）。
    pub fn request_pipe(&self) -> &str {
        &self.request_pipe
    }

    /// DaemonのPID。**観測側の配線に要る**——ETWのスコープ判定が「親がharnessか」を
    /// 手掛かりにしており、Daemonが親になると意味が変わる（`docs/STATUS.md`残課題#42）。
    pub fn daemon_pid(&self) -> u32 {
        self.daemon_pid
    }

    /// 制御パイプの名前。**対の測定のためだけに在る**（`#[cfg(test)]`）。
    ///
    /// 本番ではこの名前をどこへも渡さない。ただし**渡さないことは境界ではない**
    /// ——境界はユーザーSID専有のDACLで、パイプ名は秘密に数えていない（§10.1）。
    /// 「サンドボックスから制御パイプへ到達できない」を測るには**的の名前が要る**ので、
    /// テストにだけ口を開ける（`B-35`: 拒否側を測るには的が要る）。
    #[cfg(test)]
    pub(crate) fn control_pipe_name(&self) -> &str {
        &self.control_pipe_name
    }

    /// トップレベルのプロセスをDaemonに起こしてもらう（§12）。
    ///
    /// **`request`のstdioハンドルは、成否によらずこの関数が閉じる**（[`TopLevelSpawn`]のdoc）。
    pub fn spawn_top_level(
        &self,
        request: TopLevelSpawn<'_>,
    ) -> Result<SpawnedChild, SpawnDaemonError> {
        let result = self.spawn_top_level_inner(&request);
        // 子側の端はDaemonの複製が受け持つので、harness側の原本はもう要らない。
        // **閉じないと、読み手が永久にEOFを見られない**（親がまだ書き手を持っている扱いになる）。
        unsafe {
            let _ = CloseHandle(request.stdout_write);
            let _ = CloseHandle(request.stderr_write);
            if let Some(handle) = request.stdin_read {
                let _ = CloseHandle(handle);
            }
        }
        result
    }

    fn spawn_top_level_inner(
        &self,
        request: &TopLevelSpawn<'_>,
    ) -> Result<SpawnedChild, SpawnDaemonError> {
        let mut remote = RemoteHandleGuard::new(self.daemon_process);
        let job = remote.track(self.duplicate_to_daemon(request.job, false, "job")?);
        let stdout_write =
            remote.track(self.duplicate_to_daemon(request.stdout_write, true, "stdout")?);
        let stderr_write =
            remote.track(self.duplicate_to_daemon(request.stderr_write, true, "stderr")?);
        let stdin_read = match request.stdin_read {
            Some(handle) => Some(remote.track(self.duplicate_to_daemon(handle, true, "stdin")?)),
            None => None,
        };

        self.send(&ControlRequest::SpawnTopLevel(Box::new(
            SpawnTopLevelRequest {
                exe: request.exe.to_string(),
                args: request.args.iter().map(|a| a.to_string()).collect(),
                cwd: request.cwd.to_string_lossy().into_owned(),
                env: request.env.to_vec(),
                domain: request.domain.clone(),
                handles: ChildHandles {
                    job,
                    stdin_read,
                    stdout_write,
                    stderr_write,
                },
                redirector: request.redirector.clone(),
                console: request.console,
            },
        )))?;
        // 電文を渡し終えた時点から、複製の所有者はDaemon側のspawn処理になる。
        remote.disarm();

        match self.receive()? {
            ControlResponse::Spawned { pid, process } => Ok(SpawnedChild {
                pid,
                process: HANDLE(process as *mut _),
            }),
            ControlResponse::Failed {
                failure_kind,
                reason,
            } => Err(SpawnDaemonError {
                kind: failure_kind,
                message: reason,
            }),
            other => Err(protocol_err(format!("expected Spawned, got {other:?}"))),
        }
    }

    /// Daemonのプロセスへハンドルを複製し、**その値**を返す。
    ///
    /// `inheritable`は「Daemonがこのハンドルを子へ継承させるか」である——stdioは真、
    /// Jobは偽（Jobは子が持つものではない）。
    fn duplicate_to_daemon(
        &self,
        handle: HANDLE,
        inheritable: bool,
        what: &str,
    ) -> Result<u64, SpawnDaemonError> {
        let mut duplicate = HANDLE::default();
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                self.daemon_process,
                &mut duplicate,
                0,
                inheritable,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|e| err(format!("DuplicateHandle({what} to daemon): {e}")))?;
        Ok(duplicate.0 as u64)
    }

    fn send(&self, request: &ControlRequest) -> Result<(), SpawnDaemonError> {
        let bytes =
            serde_json::to_vec(request).map_err(|e| err(format!("serialize request: {e}")))?;
        write_framed_timeout(self.control, &bytes, IO_TIMEOUT).map_err(|e| err(e.into_message()))
    }

    fn receive(&self) -> Result<ControlResponse, SpawnDaemonError> {
        let bytes =
            read_framed_timeout(self.control, IO_TIMEOUT).map_err(|e| err(e.into_message()))?;
        serde_json::from_slice(&bytes).map_err(|e| err(format!("malformed response: {e}")))
    }

    /// Daemonを畳む。**二重に呼んでも壊れない**（`closed`フラグ。`AppContainerSession`と同じ形）。
    pub fn shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        // 行儀よく頼む。**届かなくてもよい**——次のパイプclose が同じ経路を通す。
        let _ = self.send(&ControlRequest::Shutdown);
        let _ = self.receive();
        unsafe {
            let _ = CloseHandle(self.control);
            // 畳み終わるのを少しだけ待つ。**待ち切れなくても強制終了はしない**
            // ——Daemonは走っている子のハンドルを持っており、強制終了すると
            // その複製が閉じてkill-on-closeが発火し得る（§10.1.1）。
            let _ = WaitForSingleObject(self.daemon_process, 5_000);
            let _ = CloseHandle(self.daemon_process);
        }
    }
}

impl Drop for SpawnDaemonHandle {
    /// **落とし忘れでDaemonを残さない**（`B-01`）。
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `harness.exe`の隣に置いた`harness-spawnd.exe`を解決する
/// （`netfilterd::daemon_exe_path`と同じ形）。
fn daemon_exe_path() -> Result<PathBuf, SpawnDaemonError> {
    let current =
        std::env::current_exe().map_err(|e| err(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| err("current exe has no parent directory"))?;
    let path = dir.join("harness-spawnd.exe");
    if path.is_file() {
        return Ok(path);
    }
    // **debug/testビルドだけ1つ上も見る。** テストバイナリは`target/debug/deps/`から走るが、
    // `harness-spawnd.exe`は`target/debug/`に出る。`test_support::harness_exe`が
    // 同じ理由で同じ登り方をしている。**本番の解決規則は変えない**——`harness.exe`の隣
    // 以外を探すと、置き場の取り違えが「動いてしまう」形で隠れる。release本番は隣だけを見る。
    #[cfg(any(test, debug_assertions))]
    if let Some(up) = dir.parent() {
        let candidate = up.join("harness-spawnd.exe");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(err(format!(
        "harness-spawnd.exe was not found next to the current exe ({}). \
         Build it with `cargo build -p harness-spawnd`.",
        path.display()
    )))
}

/// [段階6b/6c] `Hello`のワイヤ表現を作る。
///
/// # なぜ関数にしてあるのか——**待ち行列の先行作成をここに閉じ込めるため**
///
/// 拒否の待ち行列（`<workspace>/.harness/transitions/`）は、`workspace_root`を知っている側が
/// **送る前に**作る。「送る前に作る」を呼び出し各所へ書くと、送信点が2つ目に増えたとき
/// 片方だけ漏れる——これは`policy_learnd::client`の`start_collect_bytes`が
/// [BUG-109](../../../../../docs/bugs/BUG-109.md)の修正で採ったのと**同じ形**である。
///
/// # なぜ非特権側が先に作るのか
///
/// 昇格したプロセスが作ったノードは所有者が`BUILTIN\Administrators`になり、非昇格のharnessは
/// 以後そのノードのDACLを書けない（継承ACEが与えるのは`Modify`までで`WRITE_DAC`を含まない）。
/// 置き場は`.harness/`配下＝制御面にあり、`preflight`は起動のたびに`.harness/**`の全ノードへ
/// 保護DACLを書く。**1ノードでも書けなければTier2aは丸ごとfail-closedで中止する。**
///
/// **今日のSpawn Daemonは昇格しない**（[`launch_daemon`]）ので、この事故は今日は起きない。
/// それでも先に作るのは、§10.2が**昇格したカーネル拒否の購読者**を同じファイルへ追記させると
/// 決めているからである——その購読者が来る日に思い出す形にしない。
///
/// # サンドボックスからは届かない（**2026-09-12に実機で測った**）
///
/// ここが作るのは`.harness/transitions/`以下だけである——`.harness/`自体は
/// `harness-cli`の`stage_open_session`が`stage_prepare_sandbox`（`preflight`を含む）**より前**に
/// 作るので、保護DACLは必ずこのディレクトリに掛かってから来る。
///
/// **その保護済みの`.harness/`から継承するので、AppContainer宛のACEは1つも降りてこない。**
/// 実測: ワークスペースルートには継承つきのcapability SID宛ACE（`S-1-15-3-…`）が2本載っているが、
/// `.harness/`は継承を切ってある（`AreAccessRulesProtected=True`）ため、その配下に新しく作った
/// ディレクトリが継承するのは`SYSTEM`・`Administrators`・ユーザーだけだった。
///
/// **成立条件は「`.harness/`が`preflight`の時点で在ること」である。** 無ければ
/// ここの`create_dir_all`がワークスペースルートから継承して作ってしまい、
/// **その回だけサンドボックスから待ち行列が書ける**（＝拒否の記録を偽造・消去できる）。
/// 順序を変えるときはここも見ること。
///
/// # 失敗しても止めない
///
/// ここで作れないなら購読者も作れない見込みで、その失敗は購読者側の失敗として現れる。
/// **黙らせはしない**（警告を出す）。
fn hello_request(harness_process: u64, policy: super::TransitionPolicy) -> ControlRequest {
    precreate_transition_queue(&policy.workspace_root);
    ControlRequest::Hello {
        harness_process,
        protocol_version: PROTOCOL_VERSION,
        // [段階6b] **宣言はここで1回だけ渡す。** Daemonはこれを受け取ってから
        // 要求受付パイプの受付を始めるので、宣言を持たないまま要求を捌く瞬間が無い。
        policy: Box::new(policy.policy),
        workspace_root: policy.workspace_root,
    }
}

fn precreate_transition_queue(workspace_root: &str) {
    let path = super::transitions::pending_path(std::path::Path::new(workspace_root));
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        eprintln!(
            "warning: could not pre-create the transition denial queue {}: {e}. The elevated \
             kernel-denial subscriber will create it instead once it exists, which leaves it \
             owned by Administrators and makes the control-plane protection fail on later runs \
             (see docs/bugs/BUG-109.md)",
            path.display()
        );
    }
}

/// Daemonを起こす。**昇格しない**——AppContainerの子を起こすのに管理者権限は要らず、
/// 昇格すると子の整合性レベルが本番と変わる（`B-08`）。
fn launch_daemon(
    pipe_name: &str,
    child_process_policy: ChildProcessPolicy,
) -> Result<HANDLE, SpawnDaemonError> {
    let exe = daemon_exe_path()?;
    // **姿勢は引数で明示する。省略可能にしない**（`harness-spawnd`のusage）。
    // 省略を「今日の既定」に読み替える形にすると、常時適用へ切り替えた日に
    // 省略した経路だけが黙って旧い姿勢のまま残る。
    let policy_arg = child_process_policy.as_arg();
    let mut cmdline = wide(&format!(
        "\"{}\" \"{pipe_name}\" \"{policy_arg}\"",
        exe.display()
    ));

    // **コンソールを持たせない**（§7.1.1「Daemonはコンソール未接続が既定」）。
    // コンソールを借りるのはシェルを起こす瞬間だけで、そのときAttachConsoleする。
    // harness本体のコンソールを継承させてはいけない——`FreeConsole`でharnessの
    // 出力先ごと外れる。
    let mut info = PROCESS_INFORMATION::default();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    unsafe {
        CreateProcessW(
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            None,
            PCWSTR::null(),
            &startup,
            &mut info,
        )
        .map_err(|e| err(format!("CreateProcessW({}): {e}", exe.display())))?;
        let _ = CloseHandle(info.hThread);
    }
    Ok(info.hProcess)
}
