//! **非特権側**（harness本体プロセス）から常駐daemonを使うクライアント。
//!
//! daemonの起動（昇格が要る場合はUAC）・パイプ接続・`StartSession`/`Exec`/`Teardown`の
//! 送信と、`harness_core::VmShellExecutor`の実装を持つ。GC専用の使い捨てパイプ経路
//! （`run_gc_only`・`stop_resident_daemon_if_idle`）もここ。
//!
//! このファイルのコードは**昇格しない**。daemon側（昇格トークンで動く）の実装は`daemon`、
//! その認可判定は`authz`が持つ。

use super::authz::verify_pipe_server_identity;
use super::*;

/// 常駐セッションdaemonの固定named pipe名（S-2）。パイプの向きを反転させ常駐daemonが
/// サーバになるため、GC専用の使い捨て名（[`unique_pipe_name`]、GC経路は変更なし）とは別に
/// 固定名を用意する。同一ユーザーの誰でも名前を知り得る前提で、
/// [`user_only_security_attributes`]のSDDL・[`verify_pipe_client_identity`]の身元検証と
/// あわせて認可を成立させる。
pub(super) fn session_daemon_pipe_name() -> &'static str {
    r"\\.\pipe\harness-vmsandboxd-session"
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
    /// 相手が話せる要求の名前（D-108 の版の握手で受け取る）。**空は「握手できなかった」**
    /// ——古い常駐daemonに当たったということで、新しい要求は送らない。
    supports: Vec<String>,
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
pub(super) fn create_first_pipe_instance(
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
pub(super) fn create_additional_pipe_instance(
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
pub(super) fn connect_to_pipe_as_client(
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

/// 古い常駐daemonに当たったときに人へ返す案内（D-108）。
///
/// **直しようのないエラーにしない。** 常駐daemonは最後のセッションから15分生き残るので、
/// harnessを再ビルドして15分以内に走らせると必ずこれに当たる。何をすれば直るのかを書く。
pub const STALE_DAEMON_HINT: &str =
    "the resident Tier3 daemon is older than this harness and does not understand argument \
     arrays, so run_program cannot be used with it. Run `harness tier3 stop-if-idle` to stop it \
     (it also stops by itself 15 minutes after the last session), then try again. run_shell works \
     with the old daemon.";

/// 版の握手（D-108）。**接続の最初の1通**として送る。
///
/// 戻り値は3通り。`Ok(Some(supports))`は握手できた、`Ok(None)`は**相手が古くて`Hello`を
/// 知らない**（相手は応答を返して接続を切る）、`Err`はIPC自体の失敗である。
/// 古いときに落とさず`None`を返すのは、**`run_shell`は古いdaemonでもそのまま動く**からである
/// ——ここで止めると、再ビルドしてから15分の間 Tier3 が丸ごと使えなくなる。
fn hello(pipe: HANDLE) -> Result<Option<Vec<String>>, VmSandboxIpcError> {
    let req = VmRequest::Hello {
        client_build: env!("CARGO_PKG_VERSION").to_string(),
    };
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to serialize hello: {e}")))?;
    write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
    let response_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    let response: VmResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| VmSandboxIpcError::Ipc(format!("failed to parse hello response: {e}")))?;
    match response {
        VmResponse::Hello { supports, .. } => Ok(Some(supports)),
        // 古いdaemonは`Hello`を「知らない種類」として断る。それが版の答えである。
        VmResponse::Err(_) => Ok(None),
        other => Err(VmSandboxIpcError::Ipc(format!(
            "unexpected response for Hello: {other:?}"
        ))),
    }
}

fn connect_and_start_session(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    workspace_root_str: String,
    allow_domains: Vec<String>,
    warm: bool,
    supports: Vec<String>,
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
            supports,
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
    /// 統合済み、WFPが既に使っているのと同じ値）をそのまま渡す。`warm`は`--sandbox tier3-warm`
    /// の値をそのまま渡す。
    ///
    /// 同時セッション数の上限は**引数では受けず、台帳から読む**
    /// （[`crate::vm_ledger::max_sessions`]、`harness tier3 set-max-sessions`が置く値）。
    /// **呼び出し元を1つも経由させないのは、経路が2本あるからである**——ヘッドレス
    /// （`tier3_progress`）とTUI（`harness_tui::sandbox_prep`）の両方がここへ来るので、
    /// 引数で運ぶと同じ値を2経路に通す必要があり、片方だけ古くなり得る（B-06）。
    ///
    /// 上限が使われるのは**daemon未起動時の昇格起動だけ**である
    /// （`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）——既に常駐daemonが生きている場合、
    /// この値は無視される（後から接続する2本目以降が上限を書き換えられては意味が無いため、
    /// daemon起動時の引数としてのみ受け付ける設計）。
    pub fn start(
        workspace_root: &std::path::Path,
        allow_domains: &[String],
        warm: bool,
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
                // 台帳を読むのは**ここ**——起動しないと決まった後（＝上限が実際に効く瞬間）に
                // 読むので、置いた値と使う値の間に別のセッションが割り込む余地が小さい。
                let max_sessions = crate::vm_ledger::max_sessions();
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

        // パイプスクワッティング対策の第一ゲート（S-2）: 接続先が本当に正規daemonかを
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

        // D-108: 何を送ってよいかを先に確かめる。古い常駐daemonは`Hello`を断って接続を切るので、
        // そのときは張り直して握手なしで続ける——**`run_shell`は古いdaemonでもそのまま動く**ので、
        // ここで止めると再ビルドから15分の間 Tier3 が丸ごと使えなくなる。
        let supports = match hello(pipe) {
            Ok(Some(supports)) => supports,
            Ok(None) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                let pipe = match connect_to_pipe_as_client(pipe_name, CONNECT_TIMEOUT, true) {
                    Ok(pipe) => pipe,
                    Err(e) => {
                        unsafe {
                            if let Some(h) = daemon_process {
                                let _ = CloseHandle(h);
                            }
                        }
                        return Err(e);
                    }
                };
                return connect_and_start_session(
                    pipe,
                    daemon_process,
                    workspace_root.to_string_lossy().to_string(),
                    allow_domains.to_vec(),
                    warm,
                    Vec::new(),
                );
            }
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                    if let Some(h) = daemon_process {
                        let _ = CloseHandle(h);
                    }
                }
                return Err(e);
            }
        };

        connect_and_start_session(
            pipe,
            daemon_process,
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
            warm,
            supports,
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
        // D-108: 版の握手。**この経路は接続を張り直せない**（パイプ名を持たず、既に繋がった
        // ものを受け取る）ので、古いdaemonに当たったら止める。案内は[`STALE_DAEMON_HINT`]。
        let supports = match hello(pipe) {
            Ok(Some(supports)) => supports,
            Ok(None) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(VmSandboxIpcError::Rejected(STALE_DAEMON_HINT.to_string()));
            }
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(e);
            }
        };
        connect_and_start_session(
            pipe,
            None,
            workspace_root.to_string_lossy().to_string(),
            allow_domains.to_vec(),
            warm,
            supports,
        )
    }

    /// 相手がこの要求を話せるか（D-108）。
    pub fn supports(&self, capability: &str) -> bool {
        self.supports.iter().any(|c| c == capability)
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

    /// `harness_core::VmShellExecutor::exec_argv`専用の内部関数（D-108）。[`Self::exec_for_trait`]の
    /// 引数配列版で、cwdの変換だけを共有する。
    fn exec_argv_for_trait(
        &self,
        argv: &[String],
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        // **握手が取れていない相手へは送らない。** 送れば「知らない種類だ」という直しようのない
        // エラーが返るだけである。`sh -c`へ組み直す逃げ道も作らない（D-96）。
        if !self.supports(crate::vmsandboxd::CAP_EXEC_ARGV) {
            return Err(STALE_DAEMON_HINT.to_string());
        }
        let rel = cwd
            .strip_prefix(&self.workspace_root)
            .unwrap_or(std::path::Path::new(""));
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        self.exec_argv_ipc(argv, &rel_str, env.to_vec(), timeout)
            .map_err(|e| e.to_string())
    }

    /// `ExecArgv`を送って応答を待つ（D-108）。送る前に[`Self::supports`]を確かめること。
    pub fn exec_argv_ipc(
        &self,
        argv: &[String],
        cwd: &str,
        env: Vec<(String, String)>,
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), VmSandboxIpcError> {
        let req = VmRequest::ExecArgv {
            argv: argv.to_vec(),
            cwd: cwd.to_string(),
            env,
            timeout_secs: timeout.as_secs(),
        };
        self.round_trip_exec(&req, timeout)
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
        self.round_trip_exec(&req, timeout)
    }

    /// 実行要求を1往復させる（`Exec`・`ExecArgv`が共有する。**応答の扱いは1箇所**）。
    fn round_trip_exec(
        &self,
        req: &VmRequest,
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), VmSandboxIpcError> {
        let bytes = serde_json::to_vec(req).map_err(|e| {
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
/// `harness tier3 set-max-sessions <n>`の実体。**次にdaemonを起こすときから効く。**
///
/// 置き場（Tier3台帳）は`vm_ledger`が持つ。ここに口を置くのは、`run_gc_only`・
/// `stop_resident_daemon_if_idle`と**同じ公開面に揃える**ためである——`harness tier3`の
/// 3操作が別々の深さのモジュールを覗きに行くと、どれがクレートの契約なのかが読めなくなる。
///
/// 戻り値は**実際に置かれた値**（1未満は1へ丸める）。
pub fn set_max_sessions(n: u8) -> u8 {
    crate::vm_ledger::set_max_sessions(n);
    crate::vm_ledger::max_sessions()
}

/// 次のdaemon起動で使われる同時セッション数の上限（置かれていなければ既定値）。
pub fn max_sessions() -> u8 {
    crate::vm_ledger::max_sessions()
}

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

    fn exec_argv(
        &self,
        argv: &[String],
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        self.exec_argv_for_trait(argv, cwd, env, timeout)
    }
}
