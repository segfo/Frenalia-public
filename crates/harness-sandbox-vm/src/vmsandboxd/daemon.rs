//! **常駐daemon側**（`harness-vmsandboxd.exe`として昇格起動されたプロセス）のサーバ実装。
//!
//! `serve_resident`が固定名パイプで待ち受け、接続ごとに`std::thread::spawn`して
//! `StartSession`→`Exec`(N回)→`Teardown`の1セッションを処理する。同時セッション数の上限は
//! `SessionRegistry`が持つ（既定4・`--max-sessions`、D-25/D-26の「1VM+常駐daemon+
//! Incusコンテナ複数」構成）。
//!
//! このファイルのコードは**昇格したトークンで動く**。受け付ける相手の判定は`authz`が持つ。

use super::authz::{authorize_workspace_root, verify_pipe_client_identity};
use super::client::{
    create_additional_pipe_instance, create_first_pipe_instance, session_daemon_pipe_name,
};
use super::*;

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
            return Err(e.into());
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
    //
    // D-108: その手前に版の握手（`Hello`）が1通来ることがある。**握手は接続を消費しない**
    // ——応えたら同じ接続で`StartSession`を待ち続ける。
    let mut request_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    if let Ok(VmRequest::Hello { client_build }) =
        serde_json::from_slice::<VmRequest>(&request_bytes)
    {
        let _ = client_build;
        send_response(
            pipe,
            &VmResponse::Hello {
                daemon_build: env!("CARGO_PKG_VERSION").to_string(),
                supports: vec![crate::vmsandboxd::CAP_EXEC_ARGV.to_string()],
            },
        )?;
        request_bytes = read_framed_timeout(pipe, START_SESSION_TIMEOUT)?;
    }
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
            VmRequest::ExecArgv {
                argv,
                cwd,
                env,
                timeout_secs,
            } => {
                let cwd_path = workspace_root.join(cwd.trim_start_matches('/'));
                let result = session.exec_argv(
                    &argv,
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
            VmRequest::Hello { .. } => {
                // 握手は最初の1通だけ（`serve_inner`冒頭）。セッション中に来るのは配線の誤りである。
                let _ = send_response(
                    pipe,
                    &VmResponse::Err("Hello is only valid as the first message".to_string()),
                );
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
    write_framed_timeout(pipe, &bytes, TEARDOWN_RESPONSE_TIMEOUT)?;
    Ok(())
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
