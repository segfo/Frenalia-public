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
//! # 段階6bで足したもの（2026-09-12）
//!
//! - **要求受付パイプの要求を評価して、許可されたものを実際に起こす。** 宣言は
//!   harnessが読んで`Hello`で渡す（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。
//!   Daemonはそれで[`harness_policy::transition::TransitionGraph`]を組み、
//!   接続元のドメインを台帳から引いて判定する
//! - **ここが持っていないもの（暫定）**: **遷移先が呼び出し元と別のドメインの辺は起こせない。**
//!   ドメイン単位のAppContainerプロファイル発行器が未実装なので、そのドメインの
//!   capabilityの組を作れない（[`DenyReason::TargetDomainNotProvisioned`]のdocに
//!   外すときの手順がある）
//!
//! # 段階⑤で足したもの（2026-09-11）
//!
//! - **生成禁止（`CHILD_PROCESS_RESTRICTED`）を指定できる。** 指定するかは
//!   このDaemon1本の姿勢で、起動引数で決まる（[`ChildProcessPolicy`]）。
//!   **製品の既定は指定しない側である**——遷移ポリシーの評価が無いまま指定すると、
//!   答えが常に「未実装なので断る」になり、サンドボックスの中で子プロセスが1つも作れない。
//!   **「機構を作る」と「既定へ入れる」は別の決定である**
//!   （`docs/guide/11a-mac-enforcement-map.md`§2）
//! - **コンソール保持プロセスを持つ**（§7.1.1）。生成禁止を指定したシェルにだけ、
//!   起こす瞬間だけコンソールを貸す。何をどう貸すかは[`super::console_holder`]が持つ

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_CLOSE_SOURCE, DUPLICATE_HANDLE_OPTIONS,
    DUPLICATE_SAME_ACCESS, HANDLE, HLOCAL, WAIT_TIMEOUT,
};
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
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME, THREAD_SYNCHRONIZE,
};

use crate::tier2a::win_appcontainer::{
    appcontainer_pipe, augment_redirector_env, command_line_for, create_suspended_in_job,
    inject_redirector, spawn_request_capability_sid, wait_cow_ready, CowInject, RedirectorInject,
    SuspendedSpawn,
};
use crate::win_common::{build_env_block, clear_inherit, wide, SendHandle};
use crate::win_pipe_ipc::{
    capability_reachable_security_attributes, current_user_sid_string, is_harness_pipe_name,
    read_framed_timeout, unique_pipe_name, write_framed_timeout,
};

use super::child_plan::ChildPlan;
use super::console_holder::ConsoleHolders;
use super::nested_inputs::{caller_handles_for, env_for_nested, force_request_pipe};
use super::table::ProcessTable;
use super::transitions::TransitionQueue;
use super::{
    protocol_version_mismatch, ChildHandles, ChildProcessPolicy, ConsoleNeed, ControlRequest,
    ControlResponse, DenyReason, DomainIdentitySpec, DomainSpec, RedirectorSpec, SpawnFailureKind,
    SpawnRequest, SpawnResponse, SpawnTopLevelRequest, ACCEPT_TIMEOUT, IO_TIMEOUT, MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
};

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
    /// [段階6b] 遷移ポリシーの判定器。**`Hello`で受け取った宣言から1回だけ組む。**
    ///
    /// **セッション内で固定である**（[§19.2](../../../../plans/DESIGN-MAC.md)
    /// 「Policy Generationはセッション内で固定する。起動時に読み、実行中は変えない」）。
    /// 実行中に差し替える口は持たない——辺の追加を実行中に反映するかは同節が未決のまま
    /// 残しており、6bでも決めていない。
    graph: harness_policy::transition::TransitionGraph,
    /// [#55] **このセッションで用意できた遷移先ドメインの実体**
    /// （`plans/DESIGN-MAC-BROKER.md` §22.9）。`Hello`で1回だけ受け取る。
    ///
    /// # ここに無いドメインへは起こさない
    ///
    /// 判定器（`graph`）が「Dへ移してよい」と答えても、**Dの実体がここに無ければ断る**。
    /// 用意できない理由はharness側にある（宣言が許可済みでない・通信を宣言している）ので、
    /// Daemonは**載っているかどうかだけ**を見る。
    ///
    /// **呼び出し元のcapabilityのまま名前だけ遷移先にする逃げ方は採らない**
    /// （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）——宣言では狭めたつもりの遷移が
    /// 1ビットも狭まらず、しかもその食い違いは症状として出ない。
    ///
    /// **セッション内で固定である**（`graph`と同じ理由。§19.2）。
    provisioned_domains: Vec<DomainSpec>,
    /// [段階⑤] このDaemonが起こす子へ、生成禁止を積むか。
    ///
    /// **Daemon1本につき1つで、要求ごとに切り替えられない。** 電文（[`SpawnTopLevelRequest`]）の
    /// 欄にしていないのは、同じファイルの`token_default_dacl_sddl`を2026-09-07に削除したのと
    /// 同じ理由である——**落とせる形の欄を置くと、いつか落とされる**。生成能力を取り上げるかは
    /// セッション全体の姿勢であって、要求ごとの設定ではない。
    ///
    /// 将来Tier2aの全spawnへ常時積むと決めたら、**この欄ごと消す**のが正しい畳み方である。
    child_process_policy: ChildProcessPolicy,
    /// [段階⑤] ドメインごとのコンソール保持プロセス（§7.1.1）。
    ///
    /// **生成禁止を積まない構成では1本も起こさない。** コンソールが要るのは
    /// 「生成禁止を積んだシェル」だけで、それ以外は今日どおり`CREATE_NO_WINDOW`で起きる。
    console_holders: ConsoleHolders,
    /// [段階6c] 拒否の待ち行列（§10.2）。**`Hello`の`workspace_root`から導出する。**
    ///
    /// **記録は境界ではない**（`P-07`）。ここへ書けなくても判定と生成は続ける
    /// ——ただし黙らせはしない（失敗はDaemonのstderrへ出す）。
    transitions: TransitionQueue,
    /// [段階6f-2] 要求受付パイプの名前。**起こす子のenvへDaemonが必ず入れる**ため。
    ///
    /// # なぜharnessではなくDaemonが入れるのか
    ///
    /// 生成禁止を積んだ子は、**この変数が無いと何も起動できない**
    /// （Redirector DLLのフックが窓口の名前をここからしか取らない）。しかも失敗の形は
    /// 「なぜか子プロセスが作れない」という遠い症状で、**入れ忘れた経路だけ**が静かに壊れる。
    ///
    /// 名前を知っているのはDaemon自身であり、**トップレベルを起こす経路は今後も増える**
    /// （今日は`run_shell`・ポリシーエディタ・MCPの3つ）。入れる責任を呼び出し側へ配ると、
    /// 4つ目を足す人が忘れられる形になる（`B-06`: 決定は経路の共通点へ置く）。
    /// nestedの子は`env_for_nested`が同じ名前を系統の基準envから強制するので、
    /// **ここを入口にすれば系統の全員が持つ**。
    request_pipe: String,
}

/// [段階6b・残課題 サンドボックス周辺 #65] `Hello`で受け取った入力から遷移のグラフを組む。
///
/// **harness側の`policy_file::load_for_session`と同じ3つの入力**（宣言・ワークスペースルート・
/// `policy.json`の外で書込を許した場所）で検査する。Daemonだけが一部を落とすと、
/// Daemonの判定だけが緩くなり、しかもharness側が先に通しているので症状が出ない。
/// 関数にしてあるのは、この3つが実際に検査へ届くことを単体で測るためである。
fn graph_from_hello(
    policy: &harness_policy::policy_file::PolicyFile,
    workspace_root: &str,
    writable_outside_policy: &[String],
) -> Result<harness_policy::transition::TransitionGraph, SpawnDaemonError> {
    let input = policy.transition_graph_input(Some(workspace_root), writable_outside_policy);
    harness_policy::transition::TransitionGraph::build(&input)
        .map_err(|e| protocol_err(format!("transition policy was rejected: {e}")))
}

/// 制御パイプへ接続し、`Shutdown`か切断まで要求を処理し続ける。
///
/// # パイプ名を検証する理由（P-01）
///
/// 名前を運んでくるのは親（harness）だが、**この実行ファイルは誰からでも起動できる**。
/// 検証せずに`CreateFileW`へ渡すと、「Daemonが攻撃者の選んだ先を開く」プリミティブになる
/// （named pipeに見えない普通のファイルパスも`CreateFileW`は開ける）。
/// `harness-netfilterd`／`privhelper`が同じ理由で同じ検証をしている。
pub fn serve(
    control_pipe_name: &str,
    child_process_policy: ChildProcessPolicy,
) -> Result<(), SpawnDaemonError> {
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

    // --- ハンドシェイク: harnessのプロセスハンドルと遷移ポリシーを受け取る ---
    let (harness_process, graph, transitions, provisioned_domains) = match read_control(control)? {
        ControlRequest::Hello {
            harness_process,
            protocol_version,
            policy,
            workspace_root,
            domains,
            writable_outside_policy,
        } => {
            // **harnessと同じ関数を通る**（`protocol_version_mismatch`のdoc）。
            // 片側だけが検査すると、検査していない側から古いバイナリが入れる。
            if let Some(reason) = protocol_version_mismatch(protocol_version) {
                return Err(protocol_err(reason));
            }
            // [段階6b] **受付スレッドを起こす前にグラフを組む。** ここで組めなければ
            // `Hello`ごと失敗させ、要求受付パイプを1本も作らない——宣言を持たないDaemonが
            // 要求を受け付ける瞬間を作らないのが、宣言を`Hello`に載せた理由そのものである
            // （`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。
            //
            // **通常はここで落ちない。** 同じ検査は`policy_file::load_for_session`に配線されており
            // harness側が同じ入力で先に落ちる。ここで落ちるのは版の食い違いを意味するので、
            // 黙って空のグラフへ倒さない（`B-10`）。
            let graph = graph_from_hello(&policy, &workspace_root, &writable_outside_policy)?;
            // [段階6c] 拒否の待ち行列も**同じ`workspace_root`から導出する**。
            // 置き場のパスを電文で受け取らないのは、昇格した書き手が後から来るためである
            // （§10.2・`P-01`。`client::hello_request`のdocが対になっている）。
            let transitions = TransitionQueue::new(std::path::Path::new(workspace_root.as_str()));
            (
                HANDLE(harness_process as *mut _),
                graph,
                transitions,
                domains,
            )
        }
        other => {
            return Err(err(format!(
                "the first control request must be Hello, got {other:?}"
            )))
        }
    };

    // --- 要求受付パイプを開く（サンドボックスから到達できる唯一の口） ---
    //
    // **名前を先に決める。** 起こす子のenvへDaemon自身が入れるので、
    // [`Shared`]がこの名前を持っている必要がある（[`Shared::request_pipe`]）。
    let request_pipe_name = unique_pipe_name("spawnd-request");

    let shared = Arc::new(Shared {
        table: Mutex::new(ProcessTable::new()),
        stopping: AtomicBool::new(false),
        graph,
        provisioned_domains,
        child_process_policy,
        console_holders: ConsoleHolders::default(),
        transitions,
        request_pipe: request_pipe_name.clone(),
    });

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
            // [段階6f-3] 覚えている分を待ち行列へ書き出す（§19.3.8）。
            //
            // **判定も応答も変えない**（`P-07`: 記録は境界ではない）。書けなくても
            // 生成の可否は1ビットも変わらない——ただし**黙らせない**（`B-10`）ので、
            // 失敗は`Failed`で返す。呼び出し元（`run_shell`）はそれを見て
            // **注記を出さない**（古い値を読んで「断られていない」と言わないため）。
            ControlRequest::FlushTransitionQueue => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let response = match shared.transitions.flush(now) {
                    Ok(lines) => ControlResponse::Flushed { lines },
                    Err(e) => ControlResponse::Failed {
                        failure_kind: SpawnFailureKind::Protocol,
                        reason: format!("could not flush the transition queue: {e}"),
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

    // [段階⑤] **コンソール保持プロセスは畳む。** 上の子プロセスとは扱いが逆である——
    // あれはユーザーの作業そのものなので巻き添えにしないが、保持プロセスは
    // 「Daemonがシェルを起こすためだけに居るもの」で、Daemonが終われば存在理由が消える。
    // Jobのkill-on-closeでも畳まれるが、**それは保険であって正面の畳み方ではない**
    // （§10.1.1がキャンセルについて採ったのと同じ形）。
    shared.console_holders.shutdown();

    // [段階6c] **畳み込みバッファに残った回数を書き切る**（§10.2）。
    //
    // 1件目はその場で書いてあるので、ここで失うのは**回数だけ**で「その拒否があった」事実は
    // 既にファイルに在る。それでも書くのは、**畳んだ回数が量の見積りに要る**からである
    // （どの遷移を先に宣言すべきかは、回数で決まる）。
    //
    // **書けなくてもDaemonの終了は成功のままにする。** 記録は境界ではない（`P-07`）。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    match shared.transitions.flush(now) {
        Ok(0) => {}
        Ok(written) => eprintln!("[spawnd] transition queue: flushed {written} folded record(s)"),
        Err(e) => eprintln!("[spawnd] could not flush the transition queue: {e}"),
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
/// **理由を分ける**——台帳に無いのか、PIDが再利用されたのか、遷移が宣言されていないのか。
/// 同じ値へ丸めると、受け入れテストが「常に拒否する」実装でも通る（`B-35`）。
fn serve_request_connection(pipe: HANDLE, shared: &Arc<Shared>) {
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        // 読取が切れる＝子が終わった。応答は送らない（送り先が既に居ない）。
        let Ok(bytes) = read_framed_timeout(pipe, IO_TIMEOUT) else {
            return;
        };
        let parsed: Result<SpawnRequest, String> = if bytes.len() > MAX_FRAME_BYTES {
            Err(format!("frame of {} bytes exceeds the limit", bytes.len()))
        } else {
            serde_json::from_slice::<SpawnRequest>(&bytes).map_err(|e| e.to_string())
        };
        let response = match parsed {
            // **黙って無視しない**（`B-32`）。無視すると子は返事を待ち続ける。
            //
            // [段階6c] **これは待ち行列へ積まない。** 何を起こそうとしたのかが1つも読めて
            // いないので、積めば`exe`も`argv`も既定値で埋めることになる（`P-11`:
            // 観測していない項目を既定値で埋めない）。**落としたことを黙らせない**ために
            // Daemonのstderrへ残す。
            Err(reason) => {
                eprintln!("[spawnd] unreadable spawn request from the sandbox: {reason}");
                SpawnResponse::Denied {
                    reason: DenyReason::MalformedRequest,
                }
            }
            Ok(SpawnRequest::Spawn {
                image,
                command_line,
                cwd,
                env,
                handles,
                console,
                suspended,
            }) => {
                let served = serve_spawn_request(
                    pipe,
                    shared,
                    &NestedRequest {
                        image: &image,
                        command_line: &command_line,
                        cwd: &cwd,
                        env,
                        handles,
                        console,
                        suspended,
                    },
                );
                // [段階6c] **積むのはここ1箇所だけ。** `serve_spawn_request`の返り道は
                // 5つあるので、返り道ごとに書くと6つ目が生えた日に片方だけ漏れる（`B-06`）。
                if let SpawnResponse::Denied { reason } = &served.response {
                    record_denial(shared, &served, &image, &cwd, reason);
                }
                served.response
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

/// [段階6b] 生成要求1件を評価し、許可されていれば実際に起こす。
///
/// # 順序（**この順でなければならない**）
///
/// 1. **接続元が誰か**をProcess Tableで確定する（[`classify_caller`]）。名乗らせない（§12）
/// 2. **コマンドラインを1回だけ組む**。§8.2が「評価に使った文字列と`CreateProcess`へ渡す
///    文字列は同一でなければならない」と定めている——別々に組むと、2つの間に呼び出し元が
///    割り込める窓（TOCTOU）ができる。ここで組んだ値を判定にも生成にもそのまま渡す
/// 3. **判定する**（`harness_policy::transition::TransitionGraph::resolve`）
/// 4. **遷移先ドメインの実体を決める**——自己ループなら呼び出し元の実体、別ドメインなら
///    `Hello`で受け取った用意済みの表から引く。表に無ければ
///    [`DenyReason::TargetDomainNotProvisioned`]で断る（§22.9の骨格。`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）
/// 5. 起こす（[`spawn_nested`]）
fn serve_spawn_request(pipe: HANDLE, shared: &Arc<Shared>, request: &NestedRequest<'_>) -> Served {
    // §8.2: **評価する文字列と起こす文字列を同一にする。**
    //
    // [段階6f-1] **組み立てない。呼び出し元が送ってきた逐語の値をそのまま使う**
    // （[`SpawnRequest::Spawn::command_line`]のdoc）。段階6bはここで`exe`＋`args`から
    // 組んでいたが、フックが横取りするのは**既に組み上がった1本の文字列**なので、
    // 分解して組み直すと引用符の付け方が変わる。
    let command_line = request.command_line.to_string();

    // [段階6f-1] **実行ファイルは絶対パスでなければならない**
    // （[`SpawnRequest::Spawn::image`]のdoc）。相対パスは`CreateProcessW`が
    // **Daemonのcwd**から解決するので、判定したのと別のファイルが起きる。
    //
    // **呼び出し元を確定する前に見る。** 誰であっても答えが変わらない検査である。
    if !image_is_absolute(request.image) {
        return Served::denied(DenyReason::MalformedRequest, None, command_line);
    }

    let caller = match classify_caller(pipe, shared) {
        Ok(caller) => caller,
        Err(reason) => {
            // ドメインは**観測できていない**（台帳に無い／PIDが再利用された）。
            // 既定名で埋めない（`P-11`）。
            return Served::denied(reason, None, command_line);
        }
    };

    let resolution = shared
        .graph
        .resolve(harness_policy::transition::SpawnAttempt {
            from_domain: &caller.domain.policy_domain,
            // [段階6f-1] **判定に使うこの値が、そのまま`lpApplicationName`になる**
            // （[`spawn_nested`]）。段階6bまでは判定が`exe`、起動はコマンドラインの
            // 先頭という**2つの値**だった。
            exe: request.image,
            command_line: &command_line,
            cwd: request.cwd,
        });
    let from_domain = Some(caller.domain.policy_domain.clone());
    let allowed = match resolution {
        harness_policy::transition::Resolution::Allowed(allowed) => allowed,
        harness_policy::transition::Resolution::Denied(denial) => {
            return Served::denied(
                DenyReason::Transition { denial },
                from_domain,
                command_line,
            )
        }
    };
    // [BUG-161] **判定器の指示を`..`無しで全部取り出す。**
    //
    // # なぜ分解するのか——これが無かったせいで欄を1つ読み落とした
    //
    // かつてここは`allowed.to`・`allowed.cwd`・`allowed.env`の3つを**点で**読んでいた。
    // 判定器は4つ目（`inherit_handles`）も計算していたのに、**誰も読まないままビルドが通り**、
    // 固定辺でも呼び出し元のstdioが子へ渡り続けた（BUG-161）。
    //
    // `..`を書かずに分解すると、判定器が欄を足した日に**このファイルがコンパイルできなくなる**。
    // `EnvironmentFacts`が同じ形の歯を持っている（`crates/harness-core/src/prompt.rs`）。
    // **欄を増やすときは、ここで受けてから使い道を決めること。**
    let harness_policy::transition::Allowed {
        to,
        cwd: declared_cwd,
        env: env_policy,
        output,
        // 向きは判定器の中で使い終わっている（規則(g)と表示に使う。標準入出力は向きで決めない、P5.4b）。
        // ここで再判定しない——同じ規則を2箇所に置くと、片方だけ直る。
        direction: _,
        strict,
    } = allowed;

    // [#55] **遷移先ドメインの実体を表から引く。**
    //
    // 判定器は「Dへ移してよい」までしか答えない。Dで実際に起こすには
    // Dのpackage SIDとcapabilityの組が要り、それはharnessが起動時に用意して
    // `Hello`で渡している（`Shared::provisioned_domains`）。
    //
    // **表に無ければ断る。** 用意できない理由はharness側にある（宣言が許可済みでない・
    // 通信を宣言している）ので、ここは載っているかどうかだけを見る。
    // **呼び出し元のcapabilityのまま名前だけ遷移先にする逃げ方は採らない**——
    // 宣言では狭めたつもりの遷移が1ビットも狭まらず、その食い違いは症状に出ない（§10.1.2）。
    let target_domain = if to == caller.domain.policy_domain {
        // 自己ループ。呼び出し元の実体をそのまま使う（表を引く必要が無い）。
        &caller.domain
    } else {
        match shared
            .provisioned_domains
            .iter()
            .find(|d| d.policy_domain == to)
        {
            Some(domain) => domain,
            None => {
                return Served::denied(
                    DenyReason::TargetDomainNotProvisioned { to: to.to_string() },
                    from_domain,
                    command_line,
                )
            }
        }
    };

    // §8.3: 辺が`cwd`を宣言していれば**その値を渡す**（検査するだけでは足りない）。
    // 宣言が無い辺は呼び出し元の実cwdをそのまま渡す（決定66(6)。広げる辺でも同じ——守る線は子のドメインの権限）。
    let effective_cwd = declared_cwd.unwrap_or(request.cwd);
    // [段階6f-1] 呼び出し元の申告を使うが、**harnessが所有する名前だけは系統の値で強制する**。
    let env = env_for_nested(&caller.base_env, request.env.as_deref(), env_policy);

    // [P5.4b] **呼び出し元の標準入出力は、判定器の2つの指示で絞ってから渡す**（[`caller_handles_for`]の表）。
    //
    // 標準入力は Strict の辺でだけ断つ——固定argvのシェルは、stdinが端末でなければ**そこからコマンドを読んで
    // 実行する**ので、引数を固定しても呼び出し元がスクリプトを流し込めばその辺の権限で任意コードが走る（BUG-161）。
    // 普通の辺では渡す（決定66(3)。守る線は子のドメインの権限）。標準出力・標準エラーは辺の出力の設定に従う
    // （決定66(4)。捨てる辺では`None`＝`pull_caller_stdio`が`NUL`を開く）。
    //
    // BUG-161〜P5.4a は`inherit_handles`が偽の辺で3本まとめて`CallerHandles::default()`へ差し替えていた。
    // **その代償だった「固定辺では子の出力が返らない」は、Strict の辺でも出力の設定に従う形で解けた。**
    let handles = caller_handles_for(output, strict, request.handles);

    // **Strict の辺なら、固定したファイルを呼び出し元が書き換えられないかをOSに聞く**（P5.4a で鍵を印へ。
    // 決定66の追記・`plans/DESIGN-MAC.md` §19.1）。読み込み時の検査は綴りで比べるので、8.3形式の短い名前・
    // リンク・ハードリンクを挟むと見逃す。ここは実体のアクセス制御リストを**呼び出し元のトークン**で
    // 評価するので、どの名前で書かれていても同じ答えになる（`fixed_inputs`のモジュールdoc）。
    //
    // 見るのは**実際に`CreateProcessW`へ渡す値**（`request.image`と呼び出し元のコマンドライン）で、
    // 宣言の綴りではない——判定したのと別のファイルが起きる形を作らない（B-21）。
    //
    // **理由はサンドボックスへ返さない**（パスと権利の名前を含むので、`SpawnFailed`と同じ扱い）。
    // Daemonの標準エラーにだけ出す（B-10）。
    if strict {
        if let Some(reason) = super::fixed_inputs::refusal(
            HANDLE(caller.process as *mut _),
            caller.pid,
            request.image,
            &command_line,
        ) {
            eprintln!(
                "[spawnd] refused a strict transition for pid {}: {reason}",
                caller.pid
            );
            return Served::denied(DenyReason::FixedInputWritable, from_domain, command_line);
        }
    }

    match spawn_nested(
        shared,
        &caller,
        target_domain,
        request,
        &handles,
        &command_line,
        effective_cwd,
        env,
    ) {
        Ok(spawned) => Served {
            response: spawned,
            from_domain,
            command_line,
        },
        Err(e) => {
            // **黙って拒否へ丸めない。** 「宣言が無い」と「起こそうとして失敗した」は
            // 別の事実で、混ぜると宣言を直しても直らない拒否が「未宣言」の顔で出る（`B-10`）。
            //
            // [段階6c] 理由は[`DenyReason::SpawnFailed`]である。6bはここを
            // `MalformedRequest`で返していたが、待ち行列が入った以上その嘘は
            // **消えずに残る記録**になる（同変種のdoc）。
            eprintln!("[spawnd] nested spawn failed for pid {}: {e}", caller.pid);
            Served::denied(DenyReason::SpawnFailed, from_domain, command_line)
        }
    }
}

/// [段階6f-1] サンドボックスの中から届いた生成要求1件を、**借りた形で**持ち回る。
///
/// [`SpawnRequest::Spawn`]の欄をそのまま写しただけの型である。**構造体にしてあるのは、
/// 引数が7つになって「どれがどれか」を取り違える形になったため**——とくに`image`と
/// `command_line`は両方とも文字列で、入れ替えてもコンパイルが通る。
struct NestedRequest<'a> {
    image: &'a str,
    command_line: &'a str,
    cwd: &'a str,
    /// **呼び出し元が申告した環境**。そのまま使わない（[`env_for_nested`]）。
    /// `None`は「申告していない」で、`Some(空)`（＝空だと申告した）とは別である。
    env: Option<Vec<(String, String)>>,
    handles: super::CallerHandles,
    console: ConsoleNeed,
    suspended: bool,
}

/// [段階6f-1] `CreateProcessW`の`lpApplicationName`として渡してよい綴りか。
///
/// # なぜ`Path::is_absolute`で済ませないのか
///
/// あれは`\foo`（ドライブを省いたルート相対）を**絶対と答える**。この綴りは
/// 「呼び出し側プロセスのカレントドライブ」で解決されるので、**Daemonのドライブ**から
/// 解決されてしまう——絶対に見えて、Daemonの文脈に依存する値である。
///
/// 通すのは `C:\...`／`C:/...`（ドライブ付き）と `\\server\share\...`（UNC）だけにする。
fn image_is_absolute(image: &str) -> bool {
    let bytes = image.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        // ドライブ文字の直後が区切りでなければ`C:foo`（ドライブ相対）である。
        return matches!(bytes.get(2), Some(b'\\') | Some(b'/'));
    }
    // UNC。`\\`でも`//`でも、その後に1文字以上あること。
    matches!(bytes.first(), Some(b'\\') | Some(b'/'))
        && matches!(bytes.get(1), Some(b'\\') | Some(b'/'))
        && bytes.len() > 2
}

/// [段階6c] 1件の生成要求について、**応答と、待ち行列へ積むために観測できた事実**。
///
/// # なぜ応答だけを返さないのか
///
/// 待ち行列へ積むには呼び出し元ドメインと、判定に使ったコマンドラインが要る。これを
/// 積む側（[`serve_request_connection`]）でもう一度求めると、**判定に使ったのとは別の値**を
/// 積み得る——2回目の`classify_caller`は同じ答えを返すとは限らず（PIDは再利用される）、
/// コマンドラインの組み立ても2箇所に分かれる（§8.2が禁じている形）。
/// **観測した本人が持ち帰る。**
struct Served {
    response: SpawnResponse,
    /// 判定に使った呼び出し元ドメイン（`policy.json`の`domains[].name`）。
    ///
    /// **`None`は「観測していない」**——呼び出し元が台帳に無い／PIDが再利用されていた
    /// ときは、そもそもドメインが決まらない。既定名で埋めない（`P-11`）。
    from_domain: Option<String>,
    /// 判定にも生成にも使った、ただ1つのコマンドライン（§8.2）。
    command_line: String,
}

impl Served {
    fn denied(reason: DenyReason, from_domain: Option<String>, command_line: String) -> Self {
        Self {
            response: SpawnResponse::Denied { reason },
            from_domain,
            command_line,
        }
    }
}

/// [段階6c] 拒否1件を待ち行列へ積む（§10.2）。
///
/// # 書けなくても応答を変えない
///
/// **記録は境界ではない**（`P-07`）。待ち行列へ書けないことを理由に生成の可否を変えると、
/// ディスクが一杯になっただけでサンドボックスの挙動が変わる。ただし**黙らせない**
/// （`B-10`）——失敗はDaemonのstderrへ出す。畳み込みのおかげで追記は回数の対数にしか
/// ならないので、失敗の報告も同じ回数までしか出ない。
fn record_denial(
    shared: &Arc<Shared>,
    served: &Served,
    exe: &str,
    cwd: &str,
    reason: &DenyReason,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Err(e) = shared.transitions.record_daemon_denial(
        super::transitions::Observation {
            from_domain: served.from_domain.as_deref(),
            exe,
            argv: &served.command_line,
            // Daemon経由なので**実cwdは観測できている**。カーネル拒否の側との差が
            // ここに出る（あちらは`None`になる）。
            cwd: Some(cwd),
            reason,
        },
        now,
    ) {
        eprintln!("[spawnd] could not record a denial in the transition queue: {e}");
    }
}

/// 接続元PIDをProcess Tableで引き、**誰かを確定する**（§12）。
///
/// 引けなければ拒否の理由を返す。**理由を分ける**——台帳に無いのかPIDが再利用されたのかで、
/// 直し方が違う。
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
fn classify_caller(pipe: HANDLE, shared: &Arc<Shared>) -> Result<super::table::Caller, DenyReason> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.is_err() {
        return Err(DenyReason::MalformedRequest);
    }
    let table = shared.table.lock().unwrap();
    table.resolve(pid, process_is_alive)
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

/// [段階⑤] そのドメインのコンソールを、生成の間だけ借りる（§7.1.1）。
///
/// # なぜ関数にしてあるのか（2026-09-17、段階6f-1）
///
/// **トップレベルとnestedの両方が借りる。** 段階6bではnestedが常に`NotNeeded`だったので
/// 借りる側は1箇所しか無かったが、6f-1で呼び出し元が要否を申告できるようになった。
/// 写すと、**借りる条件と鍵の作り方が2つの綴りに分かれる**——鍵がずれると、同じドメインに
/// 保持プロセスが2つ立ち、片方が誰にも回収されないまま残る。
///
/// `None`が返るのは「借りる必要が無い」ときだけで、**借りられなかったときは`Err`**である
/// （§7.1.2の決定4。コンソール無しで黙って起こすと、シェルは何も実行せず終了コード0で終わる）。
fn borrow_console_if_needed<'a>(
    shared: &'a Arc<Shared>,
    domain: &DomainSpec,
    console: ConsoleNeed,
) -> Result<Option<super::console_holder::ConsoleWindow<'a>>, SpawnDaemonError> {
    // 借りるのは「生成禁止を積む」かつ「コンソールが要る」の**両方**が立つときだけである。
    // - 生成禁止を積まない構成では、子は今日どおり`CREATE_NO_WINDOW`で起きるので借りる必要が無い
    // - コンソールが要らないプログラム（node・git・MCPサーバ）は`DETACHED_PROCESS`で動く
    if !shared.child_process_policy.is_restricted() || console != ConsoleNeed::Required {
        return Ok(None);
    }
    // ドメインごとに1本（§7.1.1の「分ける単位」）。**鍵は判定に使う値だけで作る**——
    // `DomainSpec::name`は記録と診断のためだけの欄なので鍵にしない。
    let domain_key = format!(
        "{}|{}",
        domain.container_sid,
        match &domain.identity {
            DomainIdentitySpec::Capability { sid } => sid.as_str(),
            DomainIdentitySpec::OwnPackage => "own-package",
        }
    );
    shared
        .console_holders
        .borrow(&domain_key)
        .map(Some)
        .map_err(|e| err(format!("console holder: {e}")))
}

/// [段階6f-1] Redirector DLLを注入するための、**生成をまたぐ2段の手続き**の前半が返すもの。
///
/// 後半（[`finish_redirector`]）を必ず通すこと——通さないと受付パイプの読み側が閉じられず、
/// 子が初期化を終えたかどうかも確かめられない。
struct RedirectorHandshake {
    /// 子の初期化完了を待つ側の端。**[`finish_redirector`]が閉じる。**
    ready_read: HANDLE,
}

/// 生成の**前**に、Redirectorの受付パイプを作り、設定を環境変数へ足す。
///
/// # なぜ共有しているのか（2026-09-17、段階6f-1）
///
/// 段階6bはトップレベルだけが注入しており、nestedの子は素のままだった。生成禁止を積むと
/// **その子は孫を起こすことも頼むこともできなくなる**（§10.1.2「6bが残した限界」）ので、
/// nestedも同じ手続きを通す必要がある。**写さずに共有する**——`inherit_handles`への
/// 追加と`clear_inherit`を片方だけ忘れると、症状は「たまに子が固まる」になる。
fn prepare_redirector(
    spec: &RedirectorSpec,
    container_sid: windows::Win32::Security::PSID,
    env: &mut Vec<(String, String)>,
    inherit_handles: &mut Vec<HANDLE>,
) -> Result<RedirectorHandshake, SpawnDaemonError> {
    let (read, write) = appcontainer_pipe(container_sid)
        .map_err(|e| redirector_err(format!("appcontainer_pipe(redirector-ready): {e}")))?;
    clear_inherit(read);
    write_redirector_env(spec, env, write);
    inherit_handles.push(write);
    Ok(RedirectorHandshake { ready_read: read })
}

/// 注入設定を、Redirector DLLが読む環境変数へ書く（[`prepare_redirector`]の、Win32を通らない側）。
///
/// **書くのは`spec`の値だけ**——系統の基準envからは戻さない（[`env_for_nested`]のdoc）。
/// だから別ドメインへ移る子へ外した設定（BUG-180）は、ここで書いた値がそのまま効く。
pub(super) fn write_redirector_env(spec: &RedirectorSpec, env: &mut Vec<(String, String)>, write: HANDLE) {
    match spec {
        RedirectorSpec::Cow {
            workspace_root,
            diff_layer_dir,
            ext_capture_roots,
            // [BUG-180] トークンの側の話で、環境変数へは載せない。積むのは`ChildPlan`である。
            diff_layer_capability_sid: _,
        } => {
            let workspace = std::path::Path::new(workspace_root);
            let diff = std::path::Path::new(diff_layer_dir);
            let roots: Vec<std::path::PathBuf> = ext_capture_roots
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
            augment_redirector_env(
                env,
                RedirectorInject::for_tier2a(
                    Some(workspace),
                    Some(CowInject {
                        workspace_root: workspace,
                        diff_layer_dir: diff,
                        ext_capture_roots: &roots,
                    }),
                    None,
                ),
                write,
            );
        }
        RedirectorSpec::Lazy {
            workspace_root,
            broker_pipe,
        } => augment_redirector_env(
            env,
            RedirectorInject::lazy(std::path::Path::new(workspace_root), broker_pipe),
            write,
        ),
        // [段階5b] 誘導も受付も無いが、プロセス生成フックのために注入する。
        RedirectorSpec::ProcessHooks { workspace_root } => augment_redirector_env(
            env,
            RedirectorInject::for_tier2a(
                workspace_root.as_deref().map(std::path::Path::new),
                None,
                None,
            ),
            write,
        ),
    }
}

/// 生成の**後**に注入し、子の初期化完了を待つ。**成否によらず読み側を閉じる。**
///
/// 子を一度もresumeしていない状態で呼ぶこと——注入が失敗したら畳む側が
/// 「ユーザーコードを1行も実行していない」ことに寄りかかっている（BUG-116）。
fn finish_redirector(
    handshake: RedirectorHandshake,
    process: HANDLE,
) -> Result<(), SpawnDaemonError> {
    let injected = unsafe { inject_redirector(process) }.and_then(|()| {
        wait_cow_ready(handshake.ready_read, std::time::Duration::from_secs(5))
            .map_err(crate::tier2a::win_appcontainer::AppContainerError::Win32)
    });
    unsafe {
        let _ = CloseHandle(handshake.ready_read);
    }
    injected.map_err(|e| redirector_err(format!("redirector injection failed: {e}")))
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
    // **持ち物は計画が決める**（[`ChildPlan`]のdoc。入れ子と同じ口を通す）。
    let plan = ChildPlan::top_level(&request.domain, request.redirector.as_ref());
    let domain = match plan.resolve() {
        Ok(domain) => domain,
        Err(e) => {
            // `create_suspended_in_job`まで届いていないので、stdioもまだ誰も消費していない。
            close_received_handles(job, &inherit_handles, true);
            return Err(err(e));
        }
    };
    let capability_attributes = domain.capability_attributes();

    let args: Vec<&str> = request.args.iter().map(String::as_str).collect();
    let mut env = request.env.clone();
    force_request_pipe(&mut env, &shared.request_pipe);
    let handshake = match plan.redirector() {
        Some(spec) => match prepare_redirector(
            spec,
            domain.container_psid(),
            &mut env,
            &mut inherit_handles,
        ) {
            Ok(handshake) => Some(handshake),
            Err(e) => {
                close_received_handles(job, &inherit_handles, true);
                return Err(e);
            }
        },
        None => None,
    };
    let mut env_block = build_env_block(&env);

    // [段階⑤] **シェルにだけ、保持プロセスのコンソールを借りる**（§7.1.1。条件と鍵の作り方は
    // [`borrow_console_if_needed`]が持つ——nestedと共有している）。
    //
    // **窓は`CreateProcessW`の前後だけに閉じる。** ガードを落とすとその場で`FreeConsole`が
    // 走り、Daemonはコンソールから離れる——繋がったままだと、同じコンソールに繋がった
    // サンドボックスの子が制御イベントでDaemonを落とせる（§7.1.1の「Daemonは繋いだままにしない」）。
    let console_window = match borrow_console_if_needed(shared, &request.domain, request.console) {
        Ok(window) => window,
        Err(e) => {
            close_received_handles(job, &inherit_handles, true);
            if let Some(handshake) = handshake {
                unsafe {
                    let _ = CloseHandle(handshake.ready_read);
                }
            }
            return Err(e);
        }
    };

    // 「一時停止で起こす → Jobへ入れる → トークンの既定DACLを差し替える」までは
    // harnessの`spawn_impl`と**同じ本体**を通る（`create_suspended_in_job`）。
    // 写しを作らないので、失敗パスの後始末が2つの綴りに分かれない。
    let command_line = command_line_for(&request.exe, &args);
    let info = match create_suspended_in_job(SuspendedSpawn {
        command_line: &command_line,
        // [段階6f-1] **トップレベルの送り手はharness自身**なので、実行ファイルの綴りは
        // コマンドライン任せのままでよい（[`SuspendedSpawn::application_name`]の表）。
        application_name: None,
        cwd: std::path::Path::new(&request.cwd),
        env_block: &mut env_block,
        container_sid: domain.container_psid(),
        capabilities: &capability_attributes,
        inherit_handles: &inherit_handles,
        stdout_write,
        stderr_write,
        stdin_read,
        job,
        domain: domain.domain_identity(),
        // [段階⑤] **Daemon全体の姿勢**であって、要求ごとの設定ではない（`Shared`の同名の欄）。
        child_process_policy: shared.child_process_policy,
        // 起こすプログラムがコンソールを要るかは**呼び出し元が知っている**ので電文で受け取る。
        // ここで実行ファイル名から推測しない——外すと、シェルが無言でexit 0する
        // （[`ConsoleNeed`]のdoc）。
        console: request.console,
    }) {
        Ok(info) => info,
        Err(e) => {
            // **stdioはあちらが閉じた**（成否によらず、と同関数のdocが約束している）。
            // 残るのはJobの複製だけである。
            close_received_handles(job, &inherit_handles, false);
            if let Some(handshake) = handshake {
                unsafe {
                    let _ = CloseHandle(handshake.ready_read);
                }
            }
            return Err(err(e.to_string()));
        }
    };

    // [段階⑤] **窓をここで閉じる。** 子は`CREATE_SUSPENDED`のまま起きているので、
    // 以後の注入・台帳登録・`ResumeThread`はコンソールを借りていない状態で走る。
    // **`ResumeThread`を窓の外へ置くのは設計の指定である**（§7.1.1。窓の内で動かすと、
    // サンドボックスのシェルが走っている間ずっとDaemonが同じコンソールに残る）。
    // 窓の外で子のDLL初期化が通ることは実測済みである（§S46b）。
    drop(console_window);

    let pid = info.dwProcessId;

    // Redirectorが必要な構成では、子を一度もresumeせず、初期化完了を確認してから台帳へ載せる。
    // 失敗種別を保つことでlazyだけが呼び出し側で1回fallbackでき、CoWはfail-closedを維持する。
    if let Some(handshake) = handshake {
        if let Err(e) = finish_redirector(handshake, info.hProcess) {
            unsafe {
                let _ = TerminateProcess(info.hProcess, 1);
                let _ = CloseHandle(info.hThread);
                let _ = CloseHandle(info.hProcess);
            }
            close_received_handles(job, &inherit_handles, false);
            return Err(e);
        }
    }

    // **Resumeより前にProcess Tableへ登録する**（§12。締切が最も早い段である——
    // 子は起きた直後に生成を要求し得るのに、そのとき台帳に自分が載っていなければ
    // 「台帳に無いPIDは例外なく拒否」がそのまま効いて拒否される。BUG-116）。
    let registered = shared.table.lock().unwrap().register_top_level(
        pid,
        info.hProcess.0 as u64,
        job.0 as u64,
        plan.domain().clone(),
        // [段階6b] この系統のbase env。**Redirectorの変数を足した後の`env`である**
        // ——nestedの子も同じ誘導の下で動かなければ、同じ系統に居る意味が無い。
        env,
        // [段階6f-1] この系統の注入設定。nestedの子へ**同じものを**注入する
        // （`Lineage::redirector`のdoc）。`None`ならnestedも素のままである。
        plan.redirector().cloned(),
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

/// [段階6b] **許可された遷移を実際に起こす**（サンドボックスからの要求に応えて起こす側）。
///
/// # [`spawn_top_level`]と何が違うのか
///
/// 持ち物の出どころが全部違う。**生成の本体（`create_suspended_in_job`）は共有する**ので、
/// 失敗パスの後始末が2つの綴りに分かれることはない。
///
/// | 何を | トップレベル | ここ（nested） |
/// |---|---|---|
/// | 系統Job | harnessが作って複製を渡す | **呼び出し元と同じ系統**（§10.1.1。別のJobを作ると「1コマンドの子孫だけ殺す」粒度が失われる） |
/// | ドメイン | 電文の`DomainSpec` | **辺が指す先を`Hello`の表から引いたもの**（[#55]。自己ループなら呼び出し元と同じ値、別ドメインならharnessが用意した実体。表に無ければ[`DenyReason::TargetDomainNotProvisioned`]） |
/// | トークンへ積むcapability | 電文の`DomainSpec`＋注入設定が要るもの | **遷移先のドメインの値＋注入設定が要るもの**（[`ChildPlan`]。CoWなら差分層のSID——`Hello`の表には入っていない。BUG-180） |
/// | Redirectorの注入設定 | 電文の`redirector` | **呼び出し元へ注入した設定**。ドメインを跨ぐならワークスペース外への誘導を外す（[`ChildPlan::nested`]） |
/// | env | 電文の`env` | **呼び出し元の申告**へ辺の差分を当て、harness所有の名前だけ系統の値で強制（[`env_for_nested`]）。Redirectorの設定の名前は注入設定から書く |
/// | stdio | harnessが作ったパイプの複製 | **呼び出し元のハンドルを引き抜いたもの**（申告が無い欄は`NUL`） |
/// | 実行ファイル | コマンドライン任せ | **判定に使った`image`を`lpApplicationName`へ渡す** |
/// | プロセスハンドル | harnessへ複製して返す | **呼び出し元へ複製して返す**（`CreateProcessW`の戻り値を組み立てられるように） |
///
/// # 段階6f-1で閉じた限界（**6bが残していた3つ**）
///
/// stdioの引き継ぎ・コンソール要否の申告・nestedへのDLL注入は、どれもこの回で入った。
/// **残っているのはフック側**（`CreateProcessW`を横取りしてここへ頼む）で、それが6f-2である。
// **引数は多いが、まとめない。** 出どころが全部違う（上の表）ので、1つの構造体へ畳むと
// 「誰が決めた値か」が呼び出し側からも見えなくなる。とくに`handles`は
// **判定の結果を当てたあとの値**で、`request.handles`と取り違えると辺ごとの約束が消える。
#[allow(clippy::too_many_arguments)]
fn spawn_nested(
    shared: &Arc<Shared>,
    caller: &super::table::Caller,
    // [#55] **起こす先のドメイン**。自己ループなら呼び出し元と同じ値だが、
    // 別ドメインへの遷移ではharnessが用意した実体である。
    // **`caller.domain`を直接読まない**——読むと、遷移先を決めた判断がここで消える。
    target_domain: &DomainSpec,
    request: &NestedRequest<'_>,
    // [BUG-161] **この子へ実際に渡すハンドル。** `request.handles`ではない
    // ——Strict の辺は標準入力を、捨てる辺は標準出力と標準エラーを渡さないので、絞ったあとの値が来る
    // （`serve_spawn_request`）。**`request.handles`を直接読まないこと**：読むと、
    // 「渡してよいか」の判断がここで消える。
    handles: &super::CallerHandles,
    command_line: &str,
    cwd: &str,
    mut env: Vec<(String, String)>,
) -> Result<SpawnResponse, SpawnDaemonError> {
    // **持ち物（トークンへ積むcapability・注入するRedirectorの設定・跨ぐか）は計画が決める**
    // （[`ChildPlan`]のdoc。トップレベルと同じ口を通す）。
    let plan = ChildPlan::nested(caller, target_domain);
    let domain = plan.resolve().map_err(err)?;
    let capability_attributes = domain.capability_attributes();
    let caller_process = HANDLE(caller.process as *mut _);
    // [#49] **ドメインを跨ぐか。** 跨ぐなら、呼び出し元へ返すハンドルの権限を絞る
    // （[`caller_handle_rights`]）。判断は[`ChildPlan::nested`]が1回だけ行う。
    let crosses_domains = plan.crosses_domains();

    // [段階6f-1] 呼び出し元のstdioを**引き抜く**（[`super::CallerHandles`]のdoc）。
    // 申告の無い欄は今までどおり`NUL`へ捨てる。
    let mut opened = OpenedStdio::default();
    let (stdin_read, stdout_write, stderr_write) =
        match pull_caller_stdio(&mut opened, caller_process, handles) {
            Ok(three) => three,
            Err(e) => {
                // **途中まで開いたぶんを閉じる**（`B-01`: 3本のうち2本目で落ちたら1本目が漏れる）。
                close_all(&opened.opened);
                return Err(e);
            }
        };
    let mut inherit_handles = opened.take_for_inherit();

    let job = HANDLE(caller.lineage_job as *mut _);

    // [段階6f-1] **系統と同じ誘導をこの子にも入れる**（`Lineage::redirector`のdoc）。
    // 入れないと、生成禁止を積んだ構成でこの子は孫を起こすことも頼むこともできない。
    let handshake = match plan.redirector() {
        Some(spec) => match prepare_redirector(
            spec,
            domain.container_psid(),
            &mut env,
            &mut inherit_handles,
        ) {
            Ok(handshake) => Some(handshake),
            Err(e) => {
                close_all(&inherit_handles);
                return Err(e);
            }
        },
        None => None,
    };
    let mut env_block = build_env_block(&env);

    // [段階6f-1] コンソールが要るかは**呼び出し元の申告**で決まる（決定2）。
    // トップレベルと同じ関数を通る。
    //
    // [#55] **借りる相手は起こす先のドメインである。** §7.1.1が「分ける単位はドメインごと」と
    // 決めており、根拠は可用性——同じコンソールを共有する子は`CTRL_BREAK_EVENT`で
    // **互いのシェルを落とせる**（§S48）。呼び出し元のドメインで借りると、
    // **package SIDを分けた意味がコンソールの側だけ残らない**。
    let console_window = match borrow_console_if_needed(shared, target_domain, request.console) {
        Ok(window) => window,
        Err(e) => {
            close_all(&inherit_handles);
            if let Some(handshake) = handshake {
                unsafe {
                    let _ = CloseHandle(handshake.ready_read);
                }
            }
            return Err(e);
        }
    };

    let info = create_suspended_in_job(SuspendedSpawn {
        command_line,
        // [段階6f-1] **判定した実行ファイルと、起きる実行ファイルを同一の値にする**
        // （[`SpawnRequest::Spawn::image`]のdoc）。
        application_name: Some(request.image),
        cwd: std::path::Path::new(cwd),
        env_block: &mut env_block,
        container_sid: domain.container_psid(),
        capabilities: &capability_attributes,
        inherit_handles: &inherit_handles,
        stdout_write,
        stderr_write,
        stdin_read,
        // **系統Jobは呼び出し元のものである。この関数は所有しない**（`SuspendedSpawn::job`のdoc）
        // ——閉じると他人のハンドルを閉じることになる。台帳が最後の1人で閉じる。
        job,
        domain: domain.domain_identity(),
        child_process_policy: shared.child_process_policy,
        console: request.console,
    });
    // **窓はここで閉じる**（トップレベルと同じ理由。§7.1.1）。
    drop(console_window);
    let info = match info {
        Ok(info) => info,
        Err(e) => {
            // **stdioはあちらが閉じた**（成否によらず、と同関数のdocが約束している）。
            if let Some(handshake) = handshake {
                unsafe {
                    let _ = CloseHandle(handshake.ready_read);
                }
            }
            return Err(err(e.to_string()));
        }
    };

    if let Some(handshake) = handshake {
        if let Err(e) = finish_redirector(handshake, info.hProcess) {
            unsafe {
                let _ = TerminateProcess(info.hProcess, 1);
                let _ = CloseHandle(info.hThread);
                let _ = CloseHandle(info.hProcess);
            }
            return Err(e);
        }
    }

    let pid = info.dwProcessId;

    // **Resumeより前に台帳へ載せる**（§12。トップレベルと同じ理由——子は起きた直後に
    // 自分も生成を要求し得るのに、そのとき載っていなければ「台帳に無い」で拒否される）。
    // [#55] **載せるのは起こす先のドメインである。**
    //
    // この欄は「**この子が次に何かを頼んだときの`from`ドメイン**」になる（`resolve`が
    // 台帳から引く）。呼び出し元のドメインを載せると、**子は遷移先のpackage SIDで走っているのに、
    // 自分の生成要求だけは呼び出し元のドメインとして判定される**——狭めたはずの子が
    // 呼び出し元の遷移権をそのまま持つ形で、「分けたつもりで分かれていない」ことが
    // 症状として出ない（§10.1.2が却下した形と同じ性質の食い違いである）。
    //
    // **系統（`caller.lineage`）は呼び出し元のままでよい**——あちらは「1コマンドの子孫を
    // まとめて殺す」粒度で、ドメインとは別の軸である（§10.1.1）。
    let registered = shared.table.lock().unwrap().register_in_lineage(
        pid,
        info.hProcess.0 as u64,
        caller.lineage,
        plan.domain().clone(),
        // [BUG-180] **この子へ実際に注入した設定**を載せる。この子が孫を頼むときの
        // 出発点になる——系統のトップレベルの設定を載せると、別ドメインへ移るときに外した
        // ワークスペース外への誘導が、孫の代で戻る（`table::Entry::redirector`のdoc）。
        plan.redirector().cloned(),
    );
    if let Err(e) = registered {
        // Resume前なので子はユーザーコードを1行も実行していない。**動かす前に畳む。**
        // 系統Jobは呼び出し元のものなので閉じない（閉じると走っている兄弟ごと保険が消える）。
        unsafe {
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
        }
        return Err(err(format!(
            "process table registration failed for the nested child: {e}"
        )));
    }

    // [段階6f-1] **呼び出し元へ返すハンドルを、動かす前に作る。**
    //
    // フックは`CreateProcessW`の`PROCESS_INFORMATION`を組み立てて返す義務があり、
    // 呼び出し元のプログラムはそこに入っているハンドルで**待ち・終了コードの読み取り・
    // （一時停止で頼んだなら）再開**を行う。作れないなら起こしても意味が無いので、
    // **その場で畳む**——resume前なので子はユーザーコードを1行も実行していない。
    let for_caller = duplicate_to_caller(
        caller_process,
        info.hProcess,
        info.hThread,
        caller_handle_rights(crosses_domains),
    );
    let (process, thread) = match for_caller {
        Ok(pair) => pair,
        Err(e) => {
            // **順序が効く**（トップレベル側と同じ）。`reap_now`は台帳が持つハンドルを
            // 閉じるので、先に呼ぶと`TerminateProcess`が閉じたハンドルを撃つことになる。
            unsafe {
                let _ = TerminateProcess(info.hProcess, 1);
                let _ = CloseHandle(info.hThread);
            }
            reap_now(shared, pid);
            return Err(e);
        }
    };

    // 回収はトップレベルと同じ担当を立てる（新しい待ち方を持ち込まない）。
    spawn_reaper(Arc::clone(shared), pid, info.hProcess);

    unsafe {
        // [段階6f-1] **呼び出し元が一時停止で頼んだなら、動かすのは呼び出し元である。**
        // 上で複製したスレッドハンドルが`ResumeThread`の相手になる。
        if !request.suspended {
            let _ = ResumeThread(info.hThread);
        }
        let _ = CloseHandle(info.hThread);
    }

    Ok(SpawnResponse::Spawned {
        pid,
        process: process.0 as u64,
        thread: thread.0 as u64,
    })
}

/// [#49] 呼び出し元へ返すハンドルに与える権限。
///
/// `None`は**呼び出し元の複製と同じ権限**（`DUPLICATE_SAME_ACCESS`）、
/// `Some`は**その値に絞る**。[`caller_handle_rights`]だけが作る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallerHandleRights {
    process: Option<u32>,
    thread: Option<u32>,
}

/// [#49] ドメインを跨ぐかで、返すハンドルの権限を決める。
///
/// # 跨がないなら今日のまま（完全アクセス）
///
/// 同じドメインの子に対してできることは、呼び出し元が**自分自身に対して既にできること**と
/// 変わらない（ドメインは`(package SID, capability SIDの組)`なので、同じ組なら同じ権限である）。
/// 絞ると**サンドボックスの中のビルドツールが自分の子を殺せなくなる**だけで、何も守らない。
///
/// # 跨ぐなら、注入に使える権限を落とす
///
/// [§19.3.4](../../../../plans/DESIGN-MAC-TRANSITION-POLICY.md)は、固定辺を到達閉包から
/// 除外する根拠を「**固定辺では呼び出し元がコードを1バイトも注入できない**」に置いている。
/// 完全アクセスのハンドルを返すと、`VirtualAllocEx`＋`WriteProcessMemory`＋
/// `CreateRemoteThread`で**その根拠が崩れる**——固定するのはプログラムと引数であって、
/// 走り始めた後の振る舞いではない。
///
/// **DACLでは止まらない。** [§22.1.1](../../../../plans/DESIGN-MAC-DOMAIN.md)（案A）が
/// 子のDACLを絞っているのは`OpenProcess`を防ぐためで、アクセス検査は**開く瞬間に1回だけ**
/// 行われる。**手渡したハンドルはその検査を経ない。**
///
/// | 残す | 何のために要るか |
/// |---|---|
/// | `SYNCHRONIZE` | `WaitForSingleObject`（子の終了を待つ） |
/// | `PROCESS_QUERY_LIMITED_INFORMATION` | `GetExitCodeProcess`・`GetProcessId` |
/// | `PROCESS_TERMINATE` | `taskkill`相当。**跨いでも落とさない**——起こしてもらった子を
/// |   | 止められないほうが実害が大きく、終了させることは注入ではない |
/// | `THREAD_QUERY_LIMITED_INFORMATION` | `GetThreadId`。**フック自身が呼ぶ**（`spawn_broker.rs`） |
/// | `THREAD_SUSPEND_RESUME` | `ResumeThread`（一時停止で頼んだ呼び出し元が動かす） |
///
/// 落とすのは`PROCESS_VM_WRITE`・`PROCESS_VM_OPERATION`・`PROCESS_VM_READ`・
/// `PROCESS_CREATE_THREAD`・`PROCESS_DUP_HANDLE`・`THREAD_SET_CONTEXT`などである
/// （列挙せず、**残す側だけを書いて他を落とす**——落とす側を列挙すると、
/// OSが新しい権限を足した日に無言で漏れる）。
///
/// # フックのDLL注入は壊れない
///
/// Redirector DLLは`VirtualAllocEx`＋`CreateRemoteThread`で孫へ注入するが、
/// **それはDaemonへ頼まなかった経路の話である**——頼んだ経路では`try_broker`が
/// 早期returnするので注入のコードを通らない（`harness-redirector`の`process_hooks.rs`）。
/// 頼んだ子へ注入するのは**Daemon自身**である（[`prepare_redirector`]）。
fn caller_handle_rights(crosses_domains: bool) -> CallerHandleRights {
    if !crosses_domains {
        return CallerHandleRights {
            process: None,
            thread: None,
        };
    }
    CallerHandleRights {
        process: Some(
            (PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE).0,
        ),
        thread: Some(
            (THREAD_SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME).0,
        ),
    }
}

/// [段階6f-1] 起こした子のプロセス／スレッドハンドルを、**要求元のプロセスへ**複製する。
///
/// # 与える権限は[`caller_handle_rights`]が決める
///
/// フックの目的は「呼び出し元から見て、素の`CreateProcessW`と同じに見えること」である。
/// 素の生成では親は子に対して完全なアクセスを得るので、**同じドメインの間では絞らない**。
/// **跨ぐときだけ絞る**——理由と残す権限の一覧はそちらのdocにある（#49）。
///
/// 片方だけ成功した状態を残さない——2本目で落ちたら1本目を閉じる（`B-01`）。
fn duplicate_to_caller(
    caller_process: HANDLE,
    process: HANDLE,
    thread: HANDLE,
    rights: CallerHandleRights,
) -> Result<(HANDLE, HANDLE), SpawnDaemonError> {
    let dup = |source: HANDLE,
               desired: Option<u32>,
               what: &'static str|
     -> Result<HANDLE, SpawnDaemonError> {
        let mut theirs = HANDLE::default();
        // **`DUPLICATE_SAME_ACCESS`を付けると`dwDesiredAccess`は無視される。**
        // 絞るときは付けない（トップレベルがharnessへ返すときと同じ書き方）。
        let (access, options) = match desired {
            Some(access) => (access, DUPLICATE_HANDLE_OPTIONS(0)),
            None => (0, DUPLICATE_SAME_ACCESS),
        };
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                caller_process,
                &mut theirs,
                access,
                false,
                options,
            )
        }
        .map_err(|e| err(format!("DuplicateHandle({what} to the caller): {e}")))?;
        Ok(theirs)
    };
    let their_process = dup(process, rights.process, "child process")?;
    match dup(thread, rights.thread, "child thread") {
        Ok(their_thread) => Ok((their_process, their_thread)),
        Err(e) => {
            // **相手のプロセスの中のハンドルなので、こちらからは`DuplicateHandle`の
            // 閉じる形でしか撤回できない。** `DUPLICATE_CLOSE_SOURCE`を使い、
            // 複製元として相手側の値を指す。
            let mut discard = HANDLE::default();
            unsafe {
                let _ = DuplicateHandle(
                    caller_process,
                    their_process,
                    GetCurrentProcess(),
                    &mut discard,
                    0,
                    false,
                    DUPLICATE_CLOSE_SOURCE,
                );
                let _ = CloseHandle(discard);
            }
            Err(e)
        }
    }
}

/// [段階6f-1] 申告が無かった欄の代わりに何を開くか。
///
/// **`Read`の側を作っていないのは意図である**——標準入力の申告が無い子は
/// 「標準入力を持たない」（`None`）であって、「空を読む」ではない。`NUL`を読ませると
/// **即EOF**になり、`None`とほぼ同じに見えるが、`isatty`相当の問い合わせの答えが変わる。
enum Nul {
    Write,
}

/// [段階6f-1] nestedの子へ渡すstdio一式を**集める**入れ物。
///
/// # なぜ入れ物が要るのか
///
/// 3本のうち2本目で失敗したとき、**1本目を閉じなければ漏れる**。返り道ごとに閉じる形にすると、
/// 4本目が生えた日に必ずどれかが漏れる（`B-01`・`B-06`）。集めておいて、
/// 失敗したら[`close_all`]へ渡す。
///
/// 成功した場合は`create_suspended_in_job`が**成否によらず全部閉じる**契約を持っているので、
/// こちら側で閉じるのは「あそこへ渡す前に落ちたとき」だけである。
#[derive(Default)]
struct OpenedStdio {
    opened: Vec<HANDLE>,
}

impl OpenedStdio {
    /// 呼び出し元のハンドルを引き抜く。申告が無ければ`fallback`（`None`ならハンドル無し）。
    ///
    /// **`DUPLICATE_SAME_ACCESS`で引き抜く。** アクセスを広げない——広げても得る物は無いが、
    /// 「Daemonを通すと権限が増える」形を1つも作らないためである（`P-01`）。
    fn pull(
        &mut self,
        caller_process: HANDLE,
        claimed: Option<u64>,
        fallback: Option<Nul>,
    ) -> Result<Option<HANDLE>, SpawnDaemonError> {
        let handle = match claimed {
            Some(value) => {
                let mut mine = HANDLE::default();
                unsafe {
                    DuplicateHandle(
                        caller_process,
                        HANDLE(value as *mut _),
                        GetCurrentProcess(),
                        &mut mine,
                        0,
                        // 子へ継承させる値なので、複製の時点で継承可にしておく。
                        true,
                        DUPLICATE_SAME_ACCESS,
                    )
                }
                .map_err(|e| {
                    // **嘘の値を送られただけのことがある。** 理由を具体的に残しておかないと、
                    // 「起こせなかった」としか分からない（`B-10`）。
                    err(format!("DuplicateHandle(caller stdio {value:#x}): {e}"))
                })?;
                Some(mine)
            }
            None => match fallback {
                Some(Nul::Write) => Some(open_nul_for_write()?),
                None => None,
            },
        };
        if let Some(handle) = handle {
            self.opened.push(handle);
        }
        Ok(handle)
    }

    /// 集めたハンドルを`inherit_handles`として取り出す。
    fn take_for_inherit(self) -> Vec<HANDLE> {
        self.opened
    }
}

/// 3本まとめて引き抜く。**途中で落ちたら、開いたぶんは呼び出し側が[`close_all`]で閉じる。**
///
/// 標準出力・標準エラーは`NUL`の逃げ道があるので必ず値が返る。標準入力だけは
/// 「持たない」があり得る（[`Nul`]のdoc）。
fn pull_caller_stdio(
    opened: &mut OpenedStdio,
    caller_process: HANDLE,
    handles: &super::CallerHandles,
) -> Result<(Option<HANDLE>, HANDLE, HANDLE), SpawnDaemonError> {
    let stdin_read = opened.pull(caller_process, handles.stdin, None)?;
    let stdout_write = opened
        .pull(caller_process, handles.stdout, Some(Nul::Write))?
        .expect("the NUL fallback always yields a handle");
    let stderr_write = opened
        .pull(caller_process, handles.stderr, Some(Nul::Write))?
        .expect("the NUL fallback always yields a handle");
    Ok((stdin_read, stdout_write, stderr_write))
}

/// 集めたハンドルを全部閉じる。**`create_suspended_in_job`へ渡す前に落ちたときだけ呼ぶ。**
fn close_all(handles: &[HANDLE]) {
    unsafe {
        for handle in handles {
            let _ = CloseHandle(*handle);
        }
    }
}

/// 継承させられる`NUL`（書き込み用）を1本開く。
///
/// # なぜ`NUL`なのか
///
/// [`create_suspended_in_job`]は`stdout_write`・`stderr_write`を**必ず**要求する
/// （`Option`ではない）。nestedの子の出力を運ぶ先が6bには無いので、捨てる先を渡す。
/// **パイプを作って読み捨てるスレッドを立てるより、OSに捨てさせるほうが部品が少ない。**
///
/// **継承させるハンドルなので`bInheritHandle`を立てる。** サンドボックスの子は`NUL`を
/// 自分で開くこともできるが、それは別の話である——ここで渡すのは
/// `STARTUPINFO`の`hStdOutput`に入れる値で、無効ハンドルを入れると子の起動自体が不安定になる。
fn open_nul_for_write() -> Result<HANDLE, SpawnDaemonError> {
    let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    unsafe {
        let name = wide("NUL");
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows::Win32::Storage::FileSystem::FILE_SHARE_READ,
            Some(&sa as *const _),
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .map_err(|e| err(format!("CreateFileW(NUL): {e}")))
    }
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

/// [段階6f-1] `lpApplicationName`として通してよい綴りか。**Win32を1行も通らない。**
#[cfg(test)]
mod image_path_tests {
    use super::*;

    /// **許可側**: ドライブ付きの絶対パスとUNCは通る（区切りはどちらの向きでもよい）。
    #[test]
    fn drive_rooted_and_unc_paths_are_accepted() {
        for image in [
            r"C:\Windows\System32\cmd.exe",
            "C:/Windows/System32/cmd.exe",
            r"\\server\share\tool.exe",
            "//server/share/tool.exe",
        ] {
            assert!(image_is_absolute(image), "絶対パスが弾かれている: {image}");
        }
    }

    /// **禁止側（対）**: 相対パスと**ルート相対**は弾く。
    ///
    /// `\foo`は`Path::is_absolute`が真と答える綴りだが、解決に使われるのは
    /// **呼び出し側プロセス（＝Daemon）のカレントドライブ**である。
    /// 通すと「絶対パスを渡したのに、Daemonの居るドライブの別のファイルが起きる」。
    #[test]
    fn relative_and_root_relative_paths_are_refused() {
        for image in [
            "git.exe",
            r"..\git.exe",
            "./git.exe",
            r"\Windows\System32\cmd.exe",
            "/usr/bin/git",
            r"C:git.exe",
            "",
            r"\\",
        ] {
            assert!(
                !image_is_absolute(image),
                "Daemonのcwd／カレントドライブから解決される綴りが通っている: {image:?}"
            );
        }
    }
}

/// [#49] 呼び出し元へ返すハンドルの権限。**実機を起こさずに固定する。**
///
/// 実機の受け入れ（`spawnd_e2e_tests`）は本当に注入を試すが、あれは`spawn-daemon`でしか
/// 回らない。**マスクの中身が変わったことは`cargo test`で赤くなるべき**である
/// ——権限が1つ増えるのは1文字の変更で、レビューで見落とす。
#[cfg(test)]
mod handle_rights_tests {
    use super::*;
    use windows::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
    };

    /// 同じドメインの間では**今日の振る舞いを1ビットも変えない**。
    ///
    /// # 壊れた状態を一文で
    ///
    /// **サンドボックスの中のビルドツールが自分の子を触れなくなる。** ここを一律に絞ると、
    /// `cargo`が`rustc`を殺せない・待てないといった形で、守る相手が居ない場所だけが壊れる。
    #[test]
    fn a_same_domain_child_is_handed_the_same_access_as_a_plain_create_process() {
        let rights = caller_handle_rights(false);
        assert_eq!(
            rights,
            CallerHandleRights {
                process: None,
                thread: None
            },
            "同一ドメインなのに権限を絞っている。絞っても何も守らない（同じ組なら同じ権限）"
        );
    }

    /// **対の側**（`B-35`）: 跨ぐときは注入に使える権限が**1つも載っていない**。
    ///
    /// # 壊れた状態を一文で
    ///
    /// **狭めたはずの子へ、呼び出し元がコードを書き込める。** §19.3.4が固定辺を到達閉包から
    /// 外す根拠は「呼び出し元がコードを1バイトも注入できない」なので、ここが緩むと
    /// **編集時検査が広げる辺を通した根拠ごと崩れる**。
    #[test]
    fn a_cross_domain_child_is_not_handed_anything_that_can_inject() {
        let rights = caller_handle_rights(true);
        let process = rights
            .process
            .expect("跨ぐときはプロセスハンドルの権限を絞らなければならない");
        let thread = rights
            .thread
            .expect("跨ぐときはスレッドハンドルの権限を絞らなければならない");

        for (label, bit) in [
            ("PROCESS_VM_WRITE", PROCESS_VM_WRITE),
            ("PROCESS_VM_OPERATION", PROCESS_VM_OPERATION),
            ("PROCESS_VM_READ", PROCESS_VM_READ),
            ("PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD),
            ("PROCESS_DUP_HANDLE", PROCESS_DUP_HANDLE),
        ] {
            assert_eq!(
                process & bit.0,
                0,
                "跨ぐ子へ{label}を渡している。これだけで別ドメインへコードを注入できる"
            );
        }
        assert_eq!(
            thread & THREAD_SET_CONTEXT.0,
            0,
            "跨ぐ子へTHREAD_SET_CONTEXTを渡している。実行位置を書き換えられる"
        );
    }

    /// **3本目**: 絞った結果、フックの契約に要る権限まで落としていないこと。
    ///
    /// 上の2本だけだと「跨ぐときは0を渡す」実装が両方緑になり、**呼び出し元が子を待てない・
    /// 終了コードを読めない・一時停止を解除できない**状態で出荷される。
    #[test]
    fn a_cross_domain_child_can_still_be_waited_on_and_resumed() {
        let rights = caller_handle_rights(true);
        let process = rights.process.expect("process rights");
        let thread = rights.thread.expect("thread rights");

        for (label, bit) in [
            ("PROCESS_SYNCHRONIZE", PROCESS_SYNCHRONIZE),
            (
                "PROCESS_QUERY_LIMITED_INFORMATION",
                PROCESS_QUERY_LIMITED_INFORMATION,
            ),
            ("PROCESS_TERMINATE", PROCESS_TERMINATE),
        ] {
            assert_ne!(
                process & bit.0,
                0,
                "{label}を落としている。呼び出し元は素の`CreateProcessW`と同じことができなくなる"
            );
        }
        for (label, bit) in [
            ("THREAD_SYNCHRONIZE", THREAD_SYNCHRONIZE),
            (
                "THREAD_QUERY_LIMITED_INFORMATION",
                THREAD_QUERY_LIMITED_INFORMATION,
            ),
            ("THREAD_SUSPEND_RESUME", THREAD_SUSPEND_RESUME),
        ] {
            assert_ne!(
                thread & bit.0,
                0,
                "{label}を落としている。フックは`GetThreadId`を呼び、\
                 一時停止で頼んだ呼び出し元は`ResumeThread`を撃つ"
            );
        }
    }
}

/// [残課題 サンドボックス周辺 #65] `Hello`の`writable_outside_policy`が**Daemonの検査へ届く**こと。
///
/// harness側の検査（`policy_file::load_for_session`）は`harness-policy`のテストが固定している。
/// ここで測るのはDaemon側の入口で、欄を受け取ったまま検査へ渡し忘れると、
/// **Daemonだけが緩い判定でグラフを組み、しかもharness側が先に通しているので症状が出ない**。
#[cfg(test)]
mod hello_graph_tests {
    use super::*;

    /// ワークスペースの外にあるプログラムを、引数と作業ディレクトリごと固定した辺を1本持つ宣言。
    ///
    /// [P5.4a] 遷移先に Strict の印を付ける——固定値の書込可否は Strict のドメインへ入る辺にだけ掛かる
    /// （決定66の追記）。かつての同じドメインへの自己ループでは、今は何も検査されない。
    fn fixed_edge_policy() -> harness_policy::policy_file::PolicyFile {
        serde_json::from_str(
            r#"{
              "schema_version": 3,
              "domains": [
                {
                  "name": "shell",
                  "process": {
                    "transitions": [
                      {
                        "exe":  { "literal": "C:\\tools\\gen.exe" },
                        "argv": { "literal": "\"C:\\tools\\gen.exe\" --check" },
                        "cwd":  "C:\\ws",
                        "to":   "sealed"
                      }
                    ]
                  }
                },
                { "name": "sealed", "strict": true }
              ]
            }"#,
        )
        .expect("the fixture is a valid policy.json")
    }

    /// **禁止側**: 固定したプログラムが`policy.json`の外で書込を許した場所の下にあれば、
    /// `Hello`ごと失敗させる（要求受付パイプを1本も作らない）。
    #[test]
    fn a_fixed_program_under_a_place_writable_outside_the_policy_fails_the_hello() {
        let error = graph_from_hello(&fixed_edge_policy(), r"C:\ws", &[r"C:\tools".to_string()])
            .expect_err("the daemon must see the same writable places as harness");
        let text = error.to_string();
        assert!(
            text.contains("which this domain can write") && text.contains("c:/tools"),
            "the rejection should name the writable place: {text}"
        );
    }

    /// **許可側（対）**: 同じ宣言は、その場所を渡さなければ組める——拒否したのは
    /// 渡した一覧であって、辺の形ではない。
    #[test]
    fn the_same_policy_builds_when_no_writable_place_covers_the_program() {
        graph_from_hello(&fixed_edge_policy(), r"C:\ws", &[]).expect(r"nothing covers C:\tools");
        graph_from_hello(&fixed_edge_policy(), r"C:\ws", &[r"C:\other".to_string()])
            .expect(r"a writable place elsewhere does not cover C:\tools\gen.exe");
    }
}
