//! fault要求の**受付**（設計書§5.1.3「Redirectorとbrokerの契約」）。
//!
//! # 何を受け取り、何を返すのか
//!
//! サンドボックスの子の中で動くフックは、**本来のopenを先に呼び**、`ACCESS_DENIED`が
//! 返ったときだけここへ「このパスを開こうとして断られた」と伝える。ここは、そのパスが
//! **D-54で既に許可済みの範囲か**を自分で確かめ、範囲内なら対象と未準備の祖先へACEを
//! 実体化して「同じopenをもう一度やってよい」と答える。
//!
//! # 子の言うことを信じない
//!
//! フック自身の「workspace内である」という主張は信頼しない。**付与するSIDとマスクは
//! brokerが自分の設定から導出し、子から受け取らない。** 子が送ってよいのはパスだけで、
//! そのパスも host 側で解決し直して登録workspaceと照合する。
//!
//! **子が嘘をついても権限は広がらない。** brokerが書くのは「D-54が最終的に同じ主体へ
//! 与えると決まっている範囲」を前倒しするACEだけなので、上限は増えない。**取り違えの
//! 代償は1往復である**（設計書§5.1.3の着手条件6の限界(a)と同じ理屈）。
//!
//! # ROの子が書けるようにならない理由は、brokerの判定ではない（[D-84]）
//!
//! 設計書§5.1.3は「RO capabilityではwrite/delete要求を拒否する」と書いているが、
//! **ここにその判定は無い。要らないからである。**
//!
//! [D-84]以降、ツリーへ配るACEは**常に全モードぶん**である（`rwx`宛と`ro`宛が同じDACLに
//! 並ぶ）。brokerが実体化するのもその同じ集合で、writerが持つ`ace_grants`がそれを運ぶ。
//! **安全性は主体の側が担保する**——`ro`のセッションの子は`ro`のcapability SIDしか
//! トークンに積んでいないので、隣に`rwx`宛のACEが載っていても書けない
//! （`plans/handoff/fs-boundary-cost/T-1.md`が実子プロセスで対の実測を持つ）。
//!
//! **つまり子は「書けるACEをくれ」と言う手段を持たない。** 言えないようにしてあるので、
//! 断る判定が要らない。**判定を1つ減らすほうが、判定を足すより壊れにくい。**
//!
//! # 境界ではない（D-01）
//!
//! ここが1件も応えられなくても、失われるのは速さだけである。境界はNTFSのDACLと
//! AppContainer tokenのままで、フックが迂回されても`ACCESS_DENIED`が残る。
//!
//! # ここが**まだ**やらないこと
//!
//! - **接続元がこのセッションのJobに属するかを見ていない。** 見ているのは
//!   「AppContainerの中で動いているか」までである（[`client_runs_in_an_appcontainer`]）。
//!   Job membershipの確認にはjobハンドルをspawnから運ぶ必要があり、そこは未配線である。
//!   **パイプのDACL（capability SID宛）が実際の関門**で、この検査はその内側の二重化である。
//! - **合流の鍵がパスである**（設計書はvolume serial＋file IDと言っている）。別名で
//!   来た同じ実体は合流せず、writerが2回目を「もう届いている」として省く形になる
//!   ——**多く書くことはあっても、少なく書くことはない**。

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::win_common::{wide, SendHandle};
use crate::win_pipe_ipc::{
    capability_reachable_security_attributes, current_user_sid_string, read_framed_timeout,
    unique_pipe_name, write_framed_timeout,
};

use super::writer::{Node, WriterHandle, WriterUnavailable};

/// 1往復のI/Oに掛ける上限。**既存の値を流用する**（設計書の着手条件5が
/// 「新しい数字を増やさない」と定めている）——`wait_cow_ready`のハンドシェイクと同じ5秒。
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// 接続を待つときの上限。**要求のタイムアウトではない**（居ない相手を待つだけの時間）。
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(3600);

/// 1つのbrokerが受け付けるfault要求の総数の上限（DoSの歯止め）。
///
/// **§S21の実測（1セッションのfault総数503件）に対して十分な余裕**を取ってある。
/// ここに当たるのは「背景walkを強制的に加速させようとしている」場合で、
/// 当たったあとも権限は広がらない——`Unavailable`になるので、子は barrier で待つ。
const MAX_FAULTS: usize = 200_000;

/// 子 → broker。**パスだけを送る。** SIDもマスクも送らない（送られても使わない）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FaultRequest {
    /// このパスを開こうとして拒否された。許可済みなら実体化してほしい。
    Grant { path: String },
}

/// broker → 子。**3つを混ぜないことが要点**である（設計書の着手条件5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FaultResponse {
    /// 付与した（または既に届いていた）。**同じopenを1回だけ**やり直してよい。
    Retry,
    /// ポリシー上の拒否。**全walkが終わっても変わらない**ので、元の拒否をそのまま返すこと。
    Denied { reason: String },
    /// こちら側の可用性の失敗。**拒否ではない**——そのパスは許可済みなので、
    /// 全walk barrierで待ってからやり直すこと。
    Unavailable { reason: String },
}

/// brokerが自分の設定として持つもの。**要求から作られる値は1つも無い。**
/// **モードを持たないのは意図である**（モジュールdocの[D-84]の節）。配るACEは常に全モードぶんで、
/// どのモードとして振る舞うかは子のトークンが決める。ここへ`mode`を持たせると
/// 「brokerがモードで判定している」という誤った読み方を招く。
pub(crate) struct FaultPolicy {
    /// 正規化済みのworkspace root。containment判定の基準。
    pub(crate) canonical_workspace: PathBuf,
    /// 触ってはいけない範囲（`.harness/`等）。準備ジョブの`skip`と**同じ集合**を渡すこと
    /// ——ずれると、走査が意図的に外した場所をbrokerが付け直す（`B-05`）。
    pub(crate) skip: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BrokerStats {
    /// `Retry`で答えた数。
    pub(crate) served: usize,
    /// `Denied`で答えた数（ポリシー拒否）。
    pub(crate) denied: usize,
    /// `Unavailable`で答えた数（可用性の失敗）。
    pub(crate) unavailable: usize,
    /// DACLで弾けずここで断った接続の数（AppContainerの外から来たもの）。
    pub(crate) rejected_clients: usize,
}

struct Shared {
    policy: FaultPolicy,
    writer: WriterHandle,
    stopping: AtomicBool,
    served: AtomicUsize,
    denied: AtomicUsize,
    unavailable: AtomicUsize,
    rejected_clients: AtomicUsize,
    /// 既に実体化したパス（合流の鍵。モジュールdocの限界を参照）。
    granted: Mutex<HashSet<String>>,
}

/// fault要求の受付口。落とすと受付を閉じ、accept スレッドを畳む。
pub(crate) struct Broker {
    pipe_name: String,
    shared: Arc<Shared>,
    accept: Option<std::thread::JoinHandle<()>>,
}

impl Broker {
    /// 受付を開く。**戻った時点でパイプは既に存在する**——子へ名前を渡す側が
    /// 「まだ出来ていないパイプ」を教えてしまう窓を作らないため、最初の1本は
    /// このスレッドで同期的に作る。
    pub(crate) fn start(
        policy: FaultPolicy,
        writer: WriterHandle,
        capability_sids: &[String],
    ) -> Result<Self, String> {
        let pipe_name = unique_pipe_name("lazy-ace-broker");
        let user = current_user_sid_string().map_err(|e| e.to_string())?;
        let first = create_instance(&pipe_name, &user, capability_sids)?;

        let shared = Arc::new(Shared {
            policy,
            writer,
            stopping: AtomicBool::new(false),
            served: AtomicUsize::new(0),
            denied: AtomicUsize::new(0),
            unavailable: AtomicUsize::new(0),
            rejected_clients: AtomicUsize::new(0),
            granted: Mutex::new(HashSet::new()),
        });

        let accept = {
            let shared = Arc::clone(&shared);
            let pipe_name = pipe_name.clone();
            let user = user.clone();
            let capability_sids = capability_sids.to_vec();
            // `HANDLE`は`Send`ではないので、共有の最小ラッパで1回だけ渡す
            // （`docs/CODE-STRUCTURE-RULES.md`規則5: 写しを作らない）。
            let first = SendHandle(first);
            std::thread::spawn(move || {
                // **`first`をまるごと束縛し直す。** Rust 2021のクロージャは使ったフィールドだけを
                // 捕まえるので、いきなり`first.0`と書くと**捕まるのは生の`HANDLE`**になり、
                // `SendHandle`で包んだ意味が消える（コンパイルが通らないので気付けるが、
                // 気付いたときに理由が分からないと`unsafe impl Send`を増やす方向へ行きやすい）。
                let first = first;
                accept_loop(first.0, pipe_name, user, capability_sids, shared);
            })
        };

        Ok(Self {
            pipe_name,
            shared,
            accept: Some(accept),
        })
    }

    /// 子へ渡す名前。**秘密ではない**（モジュールdoc）。
    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) fn stats(&self) -> BrokerStats {
        BrokerStats {
            served: self.shared.served.load(Ordering::Relaxed),
            denied: self.shared.denied.load(Ordering::Relaxed),
            unavailable: self.shared.unavailable.load(Ordering::Relaxed),
            rejected_clients: self.shared.rejected_clients.load(Ordering::Relaxed),
        }
    }

    /// 受付を閉じ、acceptスレッドを畳む。
    ///
    /// **自分のパイプへ1回繋いで起こす。** 接続待ちは長いタイムアウトで止まっているので、
    /// フラグを立てるだけでは最大1時間起きない。短いタイムアウトで回す形にしないのは、
    /// 取り消しの瞬間に繋いできた子の接続が壊れるためである（そちらは無言の
    /// `Unavailable`になり、barrier送りの原因が追えなくなる）。
    pub(crate) fn stop(&mut self) -> BrokerStats {
        self.shared.stopping.store(true, Ordering::Release);
        wake_acceptor(&self.pipe_name);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        self.stats()
    }
}

impl Drop for Broker {
    /// **落とし忘れでスレッドとパイプを残さない**（`B-01`）。
    fn drop(&mut self) {
        if self.accept.is_some() {
            let _ = self.stop();
        }
    }
}

fn create_instance(name: &str, user: &str, capabilities: &[String]) -> Result<HANDLE, String> {
    // 子に要るのは「書いて読む」だけなので、capability側へはフルアクセスを与えない。
    let child_access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
    let mut sa = capability_reachable_security_attributes(user, capabilities, child_access)
        .map_err(|e| e.to_string())?;
    unsafe {
        let name_w = wide(name);
        let handle = CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            // 子は孫を作るので、1本では足りない（設計書「子孫到達」）。
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        if handle.is_invalid() {
            return Err(windows::core::Error::from_win32().to_string());
        }
        Ok(handle)
    }
}

/// 接続待ちを起こすためだけに、自分のパイプへ1回繋いですぐ切る。
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
    capabilities: Vec<String>,
    shared: Arc<Shared>,
) {
    let mut handlers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    loop {
        let connected =
            crate::win_pipe_ipc::connect_with_timeout(pipe, ACCEPT_TIMEOUT).is_ok();
        if shared.stopping.load(Ordering::Acquire) {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            break;
        }
        if !connected {
            // タイムアウト＝この1時間、誰も来なかった。インスタンスを作り直して待ち直す。
            unsafe {
                let _ = CloseHandle(pipe);
            }
            match create_instance(&pipe_name, &user, &capabilities) {
                Ok(next) => pipe = next,
                Err(_) => break,
            }
            continue;
        }

        // 次の接続を受けられるよう、先に新しいインスタンスを用意する。作れなければ
        // **いま繋がっている1本は捨てない**（捨てると、その子は理由の分からない
        // `Unavailable`になる）。以後の接続だけが受けられなくなる。
        let next = create_instance(&pipe_name, &user, &capabilities).ok();
        let handler_shared = Arc::clone(&shared);
        let client = SendHandle(pipe);
        handlers.push(std::thread::spawn(move || {
            // まるごと束縛し直す理由は`Broker::start`のコメントと同じ（Rust 2021の
            // フィールド単位キャプチャ）。
            let client = client;
            let client = client.0;
            serve_connection(client, &handler_shared);
            unsafe {
                // **切る前に読み切らせる。** `DisconnectNamedPipe`はバッファに残っている
                // 応答ごと捨てるので、最後の1通（とくに接続直後の`Denied`）が届かず、
                // 子には「パイプの他端にプロセスがありません」としか見えない
                // ——回帰テストが実際にこれを捕まえた
                // （`a_client_outside_an_appcontainer_is_refused_by_the_broker`）。
                let _ = FlushFileBuffers(client);
                let _ = DisconnectNamedPipe(client);
                let _ = CloseHandle(client);
            }
        }));
        match next {
            Some(next) => pipe = next,
            None => break,
        }
    }
    for handler in handlers {
        let _ = handler.join();
    }
}

/// 1つの接続に張り付き、切れるまで要求を処理する。
///
/// **接続ごとに検証をやり直す。** 1回目に通ったからといって2回目のパスを信用しない
/// ——`policy_learnd`の`serve_inner`が同じ理由で同じ形にしてある（P-01）。
fn serve_connection(pipe: HANDLE, shared: &Shared) {
    if !client_runs_in_an_appcontainer(pipe) {
        shared.rejected_clients.fetch_add(1, Ordering::Relaxed);
        let _ = send(
            pipe,
            &FaultResponse::Denied {
                reason: "the lazy fault-in broker only answers processes inside an AppContainer"
                    .to_string(),
            },
        );
        return;
    }
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            let _ = send(
                pipe,
                &FaultResponse::Unavailable {
                    reason: "the workspace preparation lane is shutting down".to_string(),
                },
            );
            return;
        }
        // 読取が切れる＝子が終わった。**応答は送らない**（送り先が既に居ない）。
        let Ok(bytes) = read_framed_timeout(pipe, IO_TIMEOUT) else {
            return;
        };
        let response = match serde_json::from_slice::<FaultRequest>(&bytes) {
            Ok(FaultRequest::Grant { path }) => handle_grant(shared, &path),
            // **黙って無視しない**（`B-32`）。無視すると子は返事を待ち続ける。
            Err(e) => FaultResponse::Denied {
                reason: format!("malformed fault request: {e}"),
            },
        };
        match &response {
            FaultResponse::Retry => shared.served.fetch_add(1, Ordering::Relaxed),
            FaultResponse::Denied { .. } => shared.denied.fetch_add(1, Ordering::Relaxed),
            FaultResponse::Unavailable { .. } => {
                shared.unavailable.fetch_add(1, Ordering::Relaxed)
            }
        };
        if send(pipe, &response).is_err() {
            return;
        }
    }
}

fn send(pipe: HANDLE, response: &FaultResponse) -> Result<(), String> {
    let bytes = serde_json::to_vec(response).map_err(|e| e.to_string())?;
    write_framed_timeout(pipe, &bytes, IO_TIMEOUT).map_err(|e| e.into_message())
}

/// 1件のfault要求を処理する。**ここが判定の全てである。**
fn handle_grant(shared: &Shared, requested: &str) -> FaultResponse {
    let chain = match resolve_chain(&shared.policy, requested) {
        Ok(chain) => chain,
        Err(reason) => return FaultResponse::Denied { reason },
    };
    let key = chain
        .last()
        .map(|node| node.path.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    {
        // 同じ実体への2回目は writer を通さずに答える（合流。モジュールdocの限界も参照）。
        let granted = shared.granted.lock().unwrap();
        if granted.contains(&key) {
            return FaultResponse::Retry;
        }
        if granted.len() >= MAX_FAULTS {
            return FaultResponse::Unavailable {
                reason: format!("the lazy fault-in budget of {MAX_FAULTS} nodes is exhausted"),
            };
        }
    }
    match shared.writer.grant_now(chain) {
        Ok(Ok(_)) => {
            shared.granted.lock().unwrap().insert(key);
            FaultResponse::Retry
        }
        // 書けなかった（共有違反等）。**拒否ではない**——全walkでもう一度試す価値がある。
        Ok(Err(e)) => FaultResponse::Unavailable {
            reason: format!("the workspace ACL writer could not materialise the ace: {e}"),
        },
        Err(WriterUnavailable) => FaultResponse::Unavailable {
            reason: "the workspace ACL writer is not accepting requests".to_string(),
        },
    }
}

/// 要求されたパスを host 側で解決し、**workspace rootから対象まで**のノード列を返す。
///
/// # 存在しないパスは、いちばん深い実在の祖先まで遡る
///
/// ビルドは出力ファイルを**作る**。そのとき要るのは対象そのもののACEではなく
/// **親ディレクトリのACE**なので、存在しないパスを「対象が無い」と断ると
/// `cargo build`が最初の出力で止まる。
fn resolve_chain(policy: &FaultPolicy, requested: &str) -> Result<Vec<Node>, String> {
    let requested = PathBuf::from(requested);
    if !requested.is_absolute() {
        return Err("the fault request must carry an absolute path".to_string());
    }
    // 実在するいちばん深い祖先を正規化する。**`canonicalize`はリパースポイントを解決する**
    // ので、workspace外へ出る解決はこの後のcontainment判定で落ちる。
    let mut existing = requested.as_path();
    let target = loop {
        if let Ok(canonical) = existing.canonicalize() {
            break canonical;
        }
        match existing.parent() {
            Some(parent) => existing = parent,
            None => return Err("the fault request resolves to nothing that exists".to_string()),
        }
    };

    // **畳んでから比べる。** brokerは要求を`canonicalize`するので片側だけ`\\?\`が付き、
    // 素の成分比較では`.harness/`の`skip`が一致しない（`path_is_within_normalized`のdoc）。
    let within = super::super::acl_grant::path_is_within_normalized;
    let root = &policy.canonical_workspace;
    if !within(&target, root) {
        return Err(format!(
            "the fault request resolves outside the workspace: {}",
            target.display()
        ));
    }
    if policy.skip.iter().any(|s| within(&target, s)) {
        return Err(format!(
            "the fault request targets a path the workspace lane never grants: {}",
            target.display()
        ));
    }

    // rootから対象へ向かう順に並べる——祖先が先に付いていないと通過できない。
    let mut chain: Vec<Node> = Vec::new();
    let mut cursor = target.as_path();
    loop {
        chain.push(Node {
            path: cursor.to_path_buf(),
            is_dir: cursor.is_dir(),
        });
        if cursor == root {
            break;
        }
        match cursor.parent() {
            Some(parent) => cursor = parent,
            // `path_is_within`が真なのでrootへ着くはずだが、着かないなら祖先の
            // 綴りが想定と違う。**付けずに断る**（fail-closed）。
            None => return Err("the fault request has no path back to the workspace root".into()),
        }
    }
    chain.reverse();
    Ok(chain)
}

/// 接続してきたプロセスがAppContainerの中で動いているか。
///
/// **これは関門ではなく二重化である**（関門はパイプのDACL、モジュールdoc）。
/// 判定できなければ**通さない側へ倒す**——見えない相手を信用する理由が無い。
fn client_runs_in_an_appcontainer(pipe: HANDLE) -> bool {
    use windows::Win32::Security::{GetTokenInformation, TokenIsAppContainer, TOKEN_QUERY};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeClientProcessId(pipe, &mut pid).is_err() {
            return false;
        }
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        let mut is_appcontainer = 0u32;
        let mut len = 0u32;
        let result = opened
            && GetTokenInformation(
                token,
                TokenIsAppContainer,
                Some(&mut is_appcontainer as *mut _ as *mut _),
                std::mem::size_of::<u32>() as u32,
                &mut len,
            )
            .is_ok()
            && is_appcontainer != 0;
        if opened {
            let _ = CloseHandle(token);
        }
        let _ = CloseHandle(process);
        result
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod broker_tests;
