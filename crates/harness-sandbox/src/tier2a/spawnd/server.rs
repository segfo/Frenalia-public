//! Spawn Daemon本体（§10.1・§12）。`harness-spawnd.exe`の中身。
//!
//! # 何をする常駐なのか
//!
//! **サンドボックスの中のプログラムに代わってプロセスを起こす、唯一の生成者**である。
//! 遷移MACは`CHILD_PROCESS_RESTRICTED`でサンドボックスから生成能力を取り上げるので、
//! 取り上げた後もCLIツールが動くためには「頼まれて代わりに起こす人」が要る。
//!
//! # 2本のパイプ（§10.1）
//!
//! ```text
//!   harness ──制御パイプ（ユーザーSID専有）──▶ Daemon
//!   サンドボックスの子 ──要求受付パイプ（＋spawn要求用capability SID）──▶ Daemon
//! ```
//!
//! **特権クライアントとサンドボックスの区別を、検証ロジックではなくDACLで引く**（P-01）。
//! harnessを信頼できるのは制御パイプへ到達できるのがharnessだけだからであって、
//! 電文の中身を信じているからではない。
//!
//! # このDaemonが昇格しない理由
//!
//! AppContainerの子を起こすのに管理者権限は要らない。むしろ昇格すると子の整合性レベルが
//! 本番と変わる（`B-08`）。`harness-netfilterd`から流用するのは**起動と寿命の形**であって、
//! `runas`の部分ではない。
//!
//! # 段階5の範囲（**ここが持っていないもの**）
//!
//! - **要求受付パイプの要求は実行しない。** 台帳の判定までを行い、その先は
//!   [`DenyReason::PolicyNotImplemented`]で断る。遷移ポリシーの評価は段階Eが持つ
//! - **`CHILD_PROCESS_RESTRICTED`を積まない**（段階⑤）。積むのは、ポリシー評価が
//!   着地した後である——いま積むとサンドボックスの中で子プロセスが1つも作れなくなる
//! - **コンソール保持プロセスを持たない**（§7.1.1）。あれが要るのは生成禁止を積んでから

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_HANDLE_OPTIONS, HANDLE, HLOCAL, WAIT_TIMEOUT,
};
use windows::Win32::Security::SID_AND_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::tier2a::win_appcontainer::{
    appcontainer_pipe, augment_redirector_env, create_suspended_in_job, inject_redirector,
    spawn_request_capability_sid, wait_cow_ready, CowInject, DomainIdentity, RedirectorInject,
    SuspendedSpawn,
};
use crate::win_common::{
    build_env_block, clear_inherit, sid_from_string, wide, OwnedSid, SendHandle,
};
use crate::win_pipe_ipc::{
    capability_reachable_security_attributes, current_user_sid_string, is_harness_pipe_name,
    read_framed_timeout, unique_pipe_name, write_framed_timeout,
};

use super::table::ProcessTable;
use super::{
    protocol_version_mismatch, ChildHandles, ControlRequest, ControlResponse, DenyReason,
    DomainIdentitySpec, DomainSpec, RedirectorSpec, SpawnFailureKind, SpawnRequest, SpawnResponse,
    SpawnTopLevelRequest, ACCEPT_TIMEOUT, IO_TIMEOUT, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};

/// `SECURITY_CAPABILITIES`へ積むときの属性（`spawn_with_workspace`と同じ値）。
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// 要求受付パイプのcapability SIDへ与えるアクセスマスク（§10.1）。
///
/// **`FILE_CREATE_PIPE_INSTANCE`（0x4）を含めない。** 含めると、サンドボックスの中の
/// プロセスが同名パイプの**追加インスタンス**を作って後続のクライアントを横取りできる
/// （サーバ偽装）。`FILE_GENERIC_WRITE`（0x120116）はこのビットを含むので、
/// **そのまま与えてはいけない**——ここが実測済みの値である
/// （`mac_spike_daemon_tests`のS7が同じ値で往復を確認している）。
const REQUEST_PIPE_ACCESS_WITHOUT_CREATE_INSTANCE: u32 = 0x0012_019B;

/// Daemonが返すエラー。
#[derive(Debug)]
pub struct SpawnDaemonError {
    pub kind: SpawnFailureKind,
    pub message: String,
}

impl std::fmt::Display for SpawnDaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SpawnDaemonError {}

fn err(message: impl Into<String>) -> SpawnDaemonError {
    SpawnDaemonError {
        kind: SpawnFailureKind::Spawn,
        message: message.into(),
    }
}

fn protocol_err(message: impl Into<String>) -> SpawnDaemonError {
    SpawnDaemonError {
        kind: SpawnFailureKind::Protocol,
        message: message.into(),
    }
}

fn redirector_err(message: impl Into<String>) -> SpawnDaemonError {
    SpawnDaemonError {
        kind: SpawnFailureKind::RedirectorInjection,
        message: message.into(),
    }
}

/// Daemonが持ち回る状態。
struct Shared {
    table: Mutex<ProcessTable>,
    stopping: AtomicBool,
}

/// 制御パイプへ接続し、`Shutdown`か切断まで要求を処理し続ける。
///
/// # パイプ名を検証する理由（P-01）
///
/// 名前を運んでくるのは親（harness）だが、**この実行ファイルは誰からでも起動できる**。
/// 検証せずに`CreateFileW`へ渡すと、「Daemonが攻撃者の選んだ先を開く」プリミティブになる
/// （named pipeに見えない普通のファイルパスも`CreateFileW`は開ける）。
/// `harness-netfilterd`／`privhelper`が同じ理由で同じ検証をしている。
pub fn serve(control_pipe_name: &str) -> Result<(), SpawnDaemonError> {
    if !is_harness_pipe_name(control_pipe_name) {
        return Err(err(format!(
            "refusing to open {control_pipe_name:?}: not a harness pipe name"
        )));
    }

    let control = unsafe {
        let name_w = wide(control_pipe_name);
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| err(format!("CreateFileW({control_pipe_name}): {e}")))?
    };
    let _control_guard = HandleGuard(control);

    // --- ハンドシェイク: harnessのプロセスハンドルを受け取る ---
    let harness_process = match read_control(control)? {
        ControlRequest::Hello {
            harness_process,
            protocol_version,
        } => {
            // **harnessと同じ関数を通る**（`protocol_version_mismatch`のdoc）。
            // 片側だけが検査すると、検査していない側から古いバイナリが入れる。
            if let Some(reason) = protocol_version_mismatch(protocol_version) {
                return Err(protocol_err(reason));
            }
            HANDLE(harness_process as *mut _)
        }
        other => {
            return Err(err(format!(
                "the first control request must be Hello, got {other:?}"
            )))
        }
    };

    let shared = Arc::new(Shared {
        table: Mutex::new(ProcessTable::new()),
        stopping: AtomicBool::new(false),
    });

    // --- 要求受付パイプを開く（サンドボックスから到達できる唯一の口） ---
    let request_pipe_name = unique_pipe_name("spawnd-request");
    let user =
        current_user_sid_string().map_err(|e| err(format!("current_user_sid_string: {e}")))?;
    let capability = spawn_request_capability_sid()
        .map_err(|e| err(format!("spawn_request_capability_sid: {e}")))?;
    let capability_string = crate::win_common::sid_to_string(capability.as_psid())
        .map_err(|e| err(format!("sid_to_string(spawn request capability): {e}")))?;
    // **最初の1本だけ`FILE_FLAG_FIRST_PIPE_INSTANCE`を付ける**（§10.1のインスタンス占拠対策）。
    // 2本目以降に付けると自分自身と衝突する——前例はTier3の`vmsandboxd/client.rs`で、
    // 同ファイルが「2回目以降は付けない」理由まで書いている。
    let first_instance = create_request_pipe(&request_pipe_name, &user, &capability_string, true)?;

    let accept = {
        let shared = Arc::clone(&shared);
        let pipe_name = request_pipe_name.clone();
        let user = user.clone();
        let capability_string = capability_string.clone();
        // `HANDLE`は`Send`ではないので、共有の最小ラッパで1回だけ渡す。
        let first = SendHandle(first_instance);
        std::thread::spawn(move || {
            // **まるごと束縛し直す。** Rust 2021のクロージャは使ったフィールドだけを捕まえるので、
            // いきなり`first.0`と書くと`SendHandle`で包んだ意味が消える
            // （`lazy_grant::broker::Broker::start`と同じ注意）。
            let first = first;
            accept_loop(first.0, pipe_name, user, capability_string, shared);
        })
    };

    write_control(
        control,
        &ControlResponse::Ready {
            request_pipe: request_pipe_name.clone(),
            daemon_pid: std::process::id(),
            protocol_version: PROTOCOL_VERSION,
        },
    )?;

    // --- 制御ループ ---
    //
    // 読取が切れる＝親（harness）が死んだかパイプを閉じた。**`Shutdown`を受けたときと
    // 同じ畳み方をする**（§10.1「Daemon自身の寿命は親が保持するハンドルに紐付ける」
    // ——タイマーにもクライアントからの完了メッセージにも依存しない）。
    while let Ok(request) = read_control(control) {
        match request {
            ControlRequest::Hello { .. } => {
                // 2度目のHelloはプロトコル違反。**黙って無視しない**（`B-10`）。
                write_control(
                    control,
                    &ControlResponse::Failed {
                        failure_kind: SpawnFailureKind::Protocol,
                        reason: "Hello was sent twice".to_string(),
                    },
                )?;
            }
            ControlRequest::SpawnTopLevel(request) => {
                let response = match spawn_top_level(&shared, &request, harness_process) {
                    Ok((pid, process)) => ControlResponse::Spawned { pid, process },
                    Err(e) => ControlResponse::Failed {
                        failure_kind: e.kind,
                        reason: e.message,
                    },
                };
                write_control(control, &response)?;
            }
            ControlRequest::Shutdown => {
                let _ = write_control(control, &ControlResponse::ShuttingDown);
                break;
            }
        }
    }

    // --- 畳む ---
    shared.stopping.store(true, Ordering::Release);
    wake_acceptor(&request_pipe_name);
    let _ = accept.join();

    // **保持していたハンドルを1つ残らず閉じる**（`B-01`）。系統Jobの複製を閉じ忘れると、
    // kill-on-closeの保険が二度と働かない（§10.1.1）。
    //
    // **`TerminateJobObject`は撃たない。** Daemonの死は「そのセッションのspawn機能の喪失」
    // であって、走っているコマンドの中止ではない（§10.1）。走っている子を巻き添えにすると、
    // Daemonの不具合がそのままユーザーの作業の中断になる。
    for reaped in shared.table.lock().unwrap().drain() {
        close_reaped(reaped);
    }
    Ok(())
}

/// [`ProcessTable`]が返した「閉じるべきハンドル」を閉じる。
///
/// # なぜ関数に切り出してあるのか
///
/// **Jobの取っ手を手放す箇所は数え上げの対象である**（§10.1.1）。同節の数え直しは
/// `rg`で綴りを探すので、**同じ意味の解放を2箇所へ散らすと片方が数えられない**
/// ——実際、この関数を作る前は`serve`の終了処理と[`reap_now`]の2箇所にあり、
/// どちらも`CloseHandle(HANDLE(job as *mut _))`という綴りだったため
/// 同節の`rg`に**1件も掛からなかった**（[BUG-156](../../../../docs/bugs/BUG-156.md)が
/// 「綴りで探すので、そもそも閉じていない経路は原理的に出ない」と書いた限界の、
/// 綴り違いの版である）。
///
/// **一度`HANDLE`の束縛へ戻してから閉じている**のは、その`rg`に掛かる綴りへ揃えるためである。
/// 見た目の冗長さより、**数えられることを採る。**
///
/// （この行に閉じる呼び出しの綴りをそのまま書かないのは、**doc自身が数え上げに
/// 引っ掛かる**ためである。1回実際に踏んだ。）
fn close_reaped(reaped: super::table::Reap) {
    unsafe {
        if let Some(process) = reaped.process {
            let process = HANDLE(process as *mut _);
            let _ = CloseHandle(process);
        }
        // **系統の最後の1人だったときだけ`Some`である。** 閉じないとJobが生き続け、
        // kill-on-closeの保険が働かない（§10.1.1）。
        if let Some(job) = reaped.lineage_job {
            let job = HANDLE(job as *mut _);
            let _ = CloseHandle(job);
        }
    }
}

/// 落とすと閉じるだけの最小ラッパ（`serve`が早期returnしてもパイプを残さない）。
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn read_control(pipe: HANDLE) -> Result<ControlRequest, SpawnDaemonError> {
    let bytes = read_framed_timeout(pipe, ACCEPT_TIMEOUT).map_err(|e| err(e.into_message()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(err(format!(
            "control frame of {} bytes exceeds the limit",
            bytes.len()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|e| err(format!("malformed control request: {e}")))
}

fn write_control(pipe: HANDLE, response: &ControlResponse) -> Result<(), SpawnDaemonError> {
    let bytes = serde_json::to_vec(response)
        .map_err(|e| err(format!("serialize control response: {e}")))?;
    write_framed_timeout(pipe, &bytes, IO_TIMEOUT).map_err(|e| err(e.into_message()))
}

/// 要求受付パイプのインスタンスを1本作る。
fn create_request_pipe(
    name: &str,
    user: &str,
    capability: &str,
    first: bool,
) -> Result<HANDLE, SpawnDaemonError> {
    let mut sa = capability_reachable_security_attributes(
        user,
        std::slice::from_ref(&capability.to_string()),
        REQUEST_PIPE_ACCESS_WITHOUT_CREATE_INSTANCE,
    )
    .map_err(|e| err(format!("capability_reachable_security_attributes: {e}")))?;
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    unsafe {
        let name_w = wide(name);
        let handle = CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        if handle.is_invalid() {
            return Err(err(format!(
                "CreateNamedPipeW({name}): {}",
                windows::core::Error::from_win32()
            )));
        }
        Ok(handle)
    }
}

/// 接続待ちを起こすためだけに、自分のパイプへ1回繋いですぐ切る
/// （`lazy_grant::broker::wake_acceptor`と同じ手）。
fn wake_acceptor(name: &str) {
    unsafe {
        let name_w = wide(name);
        if let Ok(handle) = CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        ) {
            let _ = CloseHandle(handle);
        }
    }
}

fn accept_loop(
    mut pipe: HANDLE,
    pipe_name: String,
    user: String,
    capability: String,
    shared: Arc<Shared>,
) {
    let mut handlers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    loop {
        let connected = crate::win_pipe_ipc::connect_with_timeout(pipe, ACCEPT_TIMEOUT).is_ok();
        if shared.stopping.load(Ordering::Acquire) {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            break;
        }
        if !connected {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            match create_request_pipe(&pipe_name, &user, &capability, false) {
                Ok(next) => pipe = next,
                Err(_) => break,
            }
            continue;
        }

        // 次の接続を受けられるよう、先に新しいインスタンスを用意する。
        let next = create_request_pipe(&pipe_name, &user, &capability, false).ok();
        let handler_shared = Arc::clone(&shared);
        let client = SendHandle(pipe);
        handlers.push(std::thread::spawn(move || {
            let client = client;
            let client = client.0;
            serve_request_connection(client, &handler_shared);
            unsafe {
                // **切る前に読み切らせる。** `DisconnectNamedPipe`はバッファに残っている応答ごと
                // 捨てるので、最後の1通（とくに接続直後の拒否）が届かず、子には
                // 「パイプの他端にプロセスがありません」としか見えない
                // （`lazy_grant::broker`が回帰テストで実際に踏んだ形）。
                let _ = FlushFileBuffers(client);
                let _ = DisconnectNamedPipe(client);
                let _ = CloseHandle(client);
            }
        }));
        // **終わったハンドラの取っ手をここで捨てる**（2026-09-07のT1測定で発覚）。
        //
        // かつてこの`Vec`は接続のたびに伸びるだけで、片付くのは**Daemonの終了時**だけだった。
        // 終わったスレッドの取っ手も`join`されるまで開いたままなので、**接続の総数だけ溜まる**
        // ——T1の掃引では1つのDaemonが約5,000接続を捌いた。段階⑤で「1要求＝1接続」を採ると、
        // 接続数＝生成要求数になる（実測で`cargo build`1回あたり765本、
        // [§S56](../../../../plans/mac-spike/RESULTS.md)）。
        //
        // **`join`は残す**（下の終了処理）。ここで足すのは回収だけで、
        // 「全部終わるのを待ってから畳む」という不変条件は変えない
        // ——回収だけ入れて終了時の`join`を消すと、**畳んでいる最中のハンドラを置き去りにする**
        // （`B-01`: 対の片方だけ実装する）。
        //
        // **終わっているものだけを`join`する**ので、ここでブロックしない
        // （`is_finished`が真なら`join`は即座に返る）。`join`は所有権を要求するので、
        // 一度取り出して2つに分ける。
        let (finished, running): (Vec<_>, Vec<_>) = std::mem::take(&mut handlers)
            .into_iter()
            .partition(|handler| handler.is_finished());
        for handler in finished {
            let _ = handler.join();
        }
        handlers = running;

        match next {
            Some(next) => pipe = next,
            None => break,
        }
    }
    for handler in handlers {
        let _ = handler.join();
    }
}

/// 要求受付パイプの1接続を、切れるまで処理する。
///
/// **段階5では必ず拒否する。** ただし**理由を分ける**——台帳に無いのか、PIDが再利用されたのか、
/// ポリシーがまだ無いのか。同じ値へ丸めると、受け入れテストが「常に拒否する」実装でも通る
/// （`B-35`）。
fn serve_request_connection(pipe: HANDLE, shared: &Shared) {
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        // 読取が切れる＝子が終わった。応答は送らない（送り先が既に居ない）。
        let Ok(bytes) = read_framed_timeout(pipe, IO_TIMEOUT) else {
            return;
        };
        let response = if bytes.len() > MAX_FRAME_BYTES {
            SpawnResponse::Denied {
                reason: DenyReason::MalformedRequest,
            }
        } else {
            match serde_json::from_slice::<SpawnRequest>(&bytes) {
                // **黙って無視しない**（`B-32`）。無視すると子は返事を待ち続ける。
                Err(_) => SpawnResponse::Denied {
                    reason: DenyReason::MalformedRequest,
                },
                Ok(SpawnRequest::Spawn { .. }) => SpawnResponse::Denied {
                    reason: classify_caller(pipe, shared),
                },
            }
        };
        let Ok(bytes) = serde_json::to_vec(&response) else {
            return;
        };
        if write_framed_timeout(pipe, &bytes, IO_TIMEOUT).is_err() {
            return;
        }
    }
}

/// 接続元PIDをProcess Tableで引き、**拒否の理由を決める**（§12）。
///
/// 台帳に居れば`PolicyNotImplemented`——「あなたが誰かは分かったが、
/// その遷移を許すかを判定する仕組みがまだ無い」である。
///
/// # `lazy_grant::broker`にある「AppContainerの中か」の検査が、ここには無い
///
/// **要らないからである。** あちらは「パスを実体化してよいか」を接続元の**種別**で
/// 早期に切るが、こちらの判定材料は**Process Tableに載っているか**であり、
/// 台帳へ載るのはDaemonが自分で起こしたAppContainerの子だけである。
/// AppContainerでない同一ユーザーのプロセスが繋いできても、台帳に居ないので
/// [`DenyReason::NotRegistered`]になる——**種別を別途見ても答えは変わらない。**
///
/// **判定を1つ減らすほうが、判定を足すより壊れにくい**（あちらのモジュールdocと同じ理屈）。
fn classify_caller(pipe: HANDLE, shared: &Shared) -> DenyReason {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.is_err() {
        return DenyReason::MalformedRequest;
    }
    let table = shared.table.lock().unwrap();
    match table.resolve(pid, process_is_alive) {
        Ok(_) => DenyReason::PolicyNotImplemented,
        Err(reason) => reason,
    }
}

/// そのプロセスハンドルが指すプロセスはまだ走っているか。
///
/// **`GetExitCodeProcess`で判定しない。** あれは「まだ走っている」を`STILL_ACTIVE`（259）で
/// 返すが、**259で正常終了したプロセスと見分けが付かない**。`WaitForSingleObject`の
/// タイムアウト0なら、シグナル済みかどうかをOSがそのまま答える（`B-29`: 代用しない）。
fn process_is_alive(handle: u64) -> bool {
    unsafe { WaitForSingleObject(HANDLE(handle as *mut _), 0) == WAIT_TIMEOUT }
}

fn close_received_handles(job: HANDLE, inherit_handles: &[HANDLE], also_stdio: bool) {
    unsafe {
        let _ = CloseHandle(job);
        if also_stdio {
            for handle in inherit_handles {
                let _ = CloseHandle(*handle);
            }
        }
    }
}

/// harnessが頼んだトップレベル生成を実行する（§12の固定順）。
///
/// 返すのは子のPIDと、**harnessのプロセスへ複製した**プロセスハンドルの値である。
fn spawn_top_level(
    shared: &Arc<Shared>,
    request: &SpawnTopLevelRequest,
    harness_process: HANDLE,
) -> Result<(u32, u64), SpawnDaemonError> {
    let ChildHandles {
        job,
        stdin_read,
        stdout_write,
        stderr_write,
    } = request.handles;
    let job = HANDLE(job as *mut _);
    let stdout_write = HANDLE(stdout_write as *mut _);
    let stderr_write = HANDLE(stderr_write as *mut _);
    let stdin_read = stdin_read.map(|h| HANDLE(h as *mut _));

    let mut inherit_handles = vec![stdout_write, stderr_write];
    if let Some(handle) = stdin_read {
        inherit_handles.push(handle);
    }

    // **ここから先で落ちたら、受け取った複製を閉じる。**
    //
    // Daemonが受け取ったハンドルは**Daemonのもの**である（harnessは自分の原本を別に持つ）。
    // 生成が成功すればJobの複製はProcess Tableが引き取り、stdioの複製は
    // `create_suspended_in_job`が消費する。**成功しなかったぶんは、ここで閉じるしかない**
    // ——閉じ忘れると系統Jobが1本残り、kill-on-closeの保険が二度と働かない（§10.1.1）。
    let domain = match resolve_domain(&request.domain) {
        Ok(domain) => domain,
        Err(e) => {
            // `create_suspended_in_job`まで届いていないので、stdioもまだ誰も消費していない。
            close_received_handles(job, &inherit_handles, true);
            return Err(e);
        }
    };
    let capability_attributes = domain.capability_attributes();

    let args: Vec<&str> = request.args.iter().map(String::as_str).collect();
    let mut env = request.env.clone();
    let ready_read = if let Some(spec) = request.redirector.as_ref() {
        let (read, write) = match appcontainer_pipe(domain.container.as_psid()) {
            Ok(pipe) => pipe,
            Err(e) => {
                close_received_handles(job, &inherit_handles, true);
                return Err(redirector_err(format!(
                    "appcontainer_pipe(redirector-ready): {e}"
                )));
            }
        };
        clear_inherit(read);
        match spec {
            RedirectorSpec::Cow {
                workspace_root,
                diff_layer_dir,
                ext_capture_roots,
            } => {
                let workspace = std::path::Path::new(workspace_root);
                let diff = std::path::Path::new(diff_layer_dir);
                let roots: Vec<std::path::PathBuf> = ext_capture_roots
                    .iter()
                    .map(std::path::PathBuf::from)
                    .collect();
                augment_redirector_env(
                    &mut env,
                    RedirectorInject {
                        workspace_root: Some(workspace),
                        cow: Some(CowInject {
                            workspace_root: workspace,
                            diff_layer_dir: diff,
                            ext_capture_roots: &roots,
                        }),
                        broker_pipe: None,
                    },
                    write,
                );
            }
            RedirectorSpec::Lazy {
                workspace_root,
                broker_pipe,
            } => augment_redirector_env(
                &mut env,
                RedirectorInject::lazy(std::path::Path::new(workspace_root), broker_pipe),
                write,
            ),
        }
        inherit_handles.push(write);
        Some(read)
    } else {
        None
    };
    let mut env_block = build_env_block(&env);

    // 「一時停止で起こす → Jobへ入れる → トークンの既定DACLを差し替える」までは
    // harnessの`spawn_impl`と**同じ本体**を通る（`create_suspended_in_job`）。
    // 写しを作らないので、失敗パスの後始末が2つの綴りに分かれない。
    let info = match create_suspended_in_job(SuspendedSpawn {
        exe: &request.exe,
        args: &args,
        cwd: std::path::Path::new(&request.cwd),
        env_block: &mut env_block,
        container_sid: domain.container.as_psid(),
        capabilities: &capability_attributes,
        inherit_handles: &inherit_handles,
        stdout_write,
        stderr_write,
        stdin_read,
        job,
        domain: domain.domain_identity(),
    }) {
        Ok(info) => info,
        Err(e) => {
            // **stdioはあちらが閉じた**（成否によらず、と同関数のdocが約束している）。
            // 残るのはJobの複製だけである。
            close_received_handles(job, &inherit_handles, false);
            if let Some(read) = ready_read {
                unsafe {
                    let _ = CloseHandle(read);
                }
            }
            return Err(err(e.to_string()));
        }
    };

    let pid = info.dwProcessId;

    // Redirectorが必要な構成では、子を一度もresumeせず、初期化完了を確認してから台帳へ載せる。
    // 失敗種別を保つことでlazyだけが呼び出し側で1回fallbackでき、CoWはfail-closedを維持する。
    if let Some(read) = ready_read {
        let injected = unsafe { inject_redirector(info.hProcess) }.and_then(|()| {
            wait_cow_ready(read, std::time::Duration::from_secs(5))
                .map_err(crate::tier2a::win_appcontainer::AppContainerError::Win32)
        });
        unsafe {
            let _ = CloseHandle(read);
        }
        if let Err(e) = injected {
            unsafe {
                let _ = TerminateProcess(info.hProcess, 1);
                let _ = CloseHandle(info.hThread);
                let _ = CloseHandle(info.hProcess);
            }
            close_received_handles(job, &inherit_handles, false);
            return Err(redirector_err(format!("redirector injection failed: {e}")));
        }
    }

    // **Resumeより前にProcess Tableへ登録する**（§12。締切が最も早い段である——
    // 子は起きた直後に生成を要求し得るのに、そのとき台帳に自分が載っていなければ
    // 「台帳に無いPIDは例外なく拒否」がそのまま効いて拒否される。BUG-116）。
    let registered = shared.table.lock().unwrap().register_top_level(
        pid,
        info.hProcess.0 as u64,
        job.0 as u64,
        request.domain.clone(),
    );
    if let Err(e) = registered {
        // **登録に失敗したら生成自体を失敗させる。** Resume前なので子はユーザーコードを
        // 1行も実行しておらず、作り直しても副作用が二重にならない（§12）。
        // 登録されていないので、Jobの複製を引き取る相手が居ない——ここで閉じる。
        unsafe {
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
        }
        close_received_handles(job, &inherit_handles, false);
        return Err(err(format!("process table registration failed: {e}")));
    }

    // harnessへ返すハンドル。**必要最小限に絞る**（§14と同じ姿勢）——harnessがこれで
    // したいのは「終わるまで待つ」と「終了コードを読む」だけである。
    let mut for_harness = HANDLE::default();
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            info.hProcess,
            harness_process,
            &mut for_harness,
            (PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION).0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    };
    if let Err(e) = duplicated {
        // ここまで来て返せないなら、起こしても呼び出し側が待てない。**動かす前に畳む。**
        //
        // **順序が効く。** `reap_now`はProcess Tableが持つプロセスハンドルを閉じるので、
        // 先に呼ぶと下の`TerminateProcess`が**閉じたハンドル**を撃つことになる
        // （子は一時停止のまま生き残る）。**終わらせてから回収する。**
        unsafe {
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hThread);
        }
        // 登録済みなので、プロセスハンドルとJobの複製は`reap_now`が閉じる
        // （系統の最後の1人なので、Jobも返る）。
        reap_now(shared, pid);
        return Err(err(format!(
            "DuplicateHandle(child process to harness): {e}"
        )));
    }

    // 子の終了を待ってエントリを回収する担当を立てる。**タイマーやポーリングは使わない**
    // （常駐プロセスの寿命はOSハンドルに紐付ける、§12）。`RegisterWaitForSingleObject`では
    // なくスレッドで待つのは、3Tierが共有する`win_common::stream_child_output`が
    // 既にこの形だからである（新しい待ち方をもう1つ持ち込まない）。
    spawn_reaper(Arc::clone(shared), pid, info.hProcess);

    unsafe {
        let _ = ResumeThread(info.hThread);
        let _ = CloseHandle(info.hThread);
    }

    Ok((pid, for_harness.0 as u64))
}

/// 子の終了を待ち、Process Tableのエントリを回収する。
fn spawn_reaper(shared: Arc<Shared>, pid: u32, process: HANDLE) {
    // 待つためだけの独立ハンドルを作る。台帳が持つハンドルは回収時に閉じられるので、
    // 同じ値を待ちに使うと**閉じた後のハンドルを待つ**ことになる。
    let mut waitable = HANDLE::default();
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            process,
            GetCurrentProcess(),
            &mut waitable,
            PROCESS_SYNCHRONIZE.0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    };
    if duplicated.is_err() {
        // 待てないなら回収も走らない。**エントリはDaemon終了時の`drain`が拾う**ので
        // ハンドルは漏れないが、その間この系統は「生きている」ままになる。
        return;
    }
    let waitable = SendHandle(waitable);
    std::thread::spawn(move || {
        let waitable = waitable;
        unsafe {
            let _ = WaitForSingleObject(waitable.0, u32::MAX);
            let _ = CloseHandle(waitable.0);
        }
        reap_now(&shared, pid);
    });
}

/// 1エントリを回収し、返ってきたハンドルを閉じる。
///
/// **知らないPIDでも壊れない**（[`ProcessTable::reap`]が`None`を返すだけ）——
/// 待機スレッドと失敗経路の両方から呼ばれるので、冪等でないと同じハンドルを2度閉じる。
fn reap_now(shared: &Arc<Shared>, pid: u32) {
    let reaped = shared.table.lock().unwrap().reap(pid);
    if let Some(reaped) = reaped {
        close_reaped(reaped);
    }
}

/// ワイヤ上のドメイン（文字列のSID）を、`CreateProcessW`へ渡せる形へ戻したもの。
///
/// **`OwnedSid`を持ち続けることに意味がある。** `PSID`は生ポインタなので、
/// 元の所有者が落ちた瞬間に宙を指す——`CreateProcessW`が終わるまでこの構造体を生かす。
struct ResolvedDomain {
    container: OwnedSid,
    capabilities: Vec<OwnedSid>,
    /// `None`＝package SIDそのものがドメイン（[`DomainIdentitySpec::OwnPackage`]）。
    ///
    /// **capability列とは別に持つ。** ここへ混ぜると、ドメインの宛先として指定しただけの
    /// SIDが**トークンへ積まれる**（＝黙って権限が1つ増える）。宛先に使うことと
    /// 名乗ることは別の決定である。
    identity: Option<OwnedSid>,
}

impl ResolvedDomain {
    /// トークンへ積むcapability（**`identity`は含めない**。上記）。
    fn capability_attributes(&self) -> Vec<SID_AND_ATTRIBUTES> {
        self.capabilities
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect()
    }

    fn domain_identity(&self) -> DomainIdentity {
        match &self.identity {
            Some(sid) => DomainIdentity::Capability(sid.as_psid()),
            None => DomainIdentity::OwnPackage,
        }
    }
}

fn resolve_domain(domain: &DomainSpec) -> Result<ResolvedDomain, SpawnDaemonError> {
    let container = sid_from_string(&domain.container_sid).map_err(|e| {
        err(format!(
            "sid_from_string(container {}): {e}",
            domain.container_sid
        ))
    })?;
    let mut capabilities = Vec::with_capacity(domain.capability_sids.len());
    for sid in &domain.capability_sids {
        capabilities.push(
            sid_from_string(sid)
                .map_err(|e| err(format!("sid_from_string(capability {sid}): {e}")))?,
        );
    }
    let identity = match &domain.identity {
        DomainIdentitySpec::OwnPackage => None,
        DomainIdentitySpec::Capability { sid } => Some(
            sid_from_string(sid)
                .map_err(|e| err(format!("sid_from_string(domain identity {sid}): {e}")))?,
        ),
    };
    Ok(ResolvedDomain {
        container,
        capabilities,
        identity,
    })
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    /// 実在の形をしたSID文字列（`ConvertStringSidToSidW`が受け付ければ何でもよい）。
    /// **実マシンのcapabilityである必要は無い**——ここで測るのは変換ではなく、
    /// 変換結果をどの欄へ入れるかである。
    fn spec(identity: DomainIdentitySpec) -> DomainSpec {
        DomainSpec {
            name: "test-domain".to_string(),
            container_sid: "S-1-15-2-1-2-3".to_string(),
            capability_sids: vec!["S-1-15-3-1024-1".to_string()],
            identity,
        }
    }

    /// **ドメインの宛先に指定したSIDが、トークンへ積まれてはいけない。**
    ///
    /// 宛先に使うこと（誰がこの子を開けるか）と名乗ること（この子が何を持っているか）は
    /// 別の決定である。混ぜると、**宛先を指定しただけで権限が1つ増える**——しかも
    /// 増えたことはどこにも出ない（`B-10`）。
    #[test]
    fn the_domain_identity_sid_is_not_added_to_the_token_capabilities() {
        let resolved = resolve_domain(&spec(DomainIdentitySpec::Capability {
            sid: "S-1-15-3-1024-9".to_string(),
        }))
        .expect("resolve");

        assert_eq!(
            resolved.capability_attributes().len(),
            1,
            "宣言していないcapabilityがトークンへ積まれている。\
             ドメインの宛先SIDを指定しただけで権限が1つ増える形になっている"
        );
        assert!(
            matches!(resolved.domain_identity(), DomainIdentity::Capability(_)),
            "宛先が capability として渡っていない"
        );
    }

    /// **対の側**（`B-35`）: package SIDそのものがドメインなら、宛先SIDは持たない。
    ///
    /// 片方だけだと、`identity`を常に`None`にする実装でも上のテストが通る。
    #[test]
    fn own_package_carries_no_extra_identity_sid() {
        let resolved = resolve_domain(&spec(DomainIdentitySpec::OwnPackage)).expect("resolve");
        assert_eq!(resolved.capability_attributes().len(), 1);
        assert!(
            matches!(resolved.domain_identity(), DomainIdentity::OwnPackage),
            "package SIDをドメインにする指定が capability に化けている"
        );
    }
}
