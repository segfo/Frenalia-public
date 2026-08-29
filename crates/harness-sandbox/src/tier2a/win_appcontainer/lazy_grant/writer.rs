//! workspace内の**全DACL書込を1本のスレッドへ直列化する** writer（設計書§5.1.3
//! 「背景walkとオンデマンド付与の直列化」の`single ACL writer`）。
//!
//! # なぜ1本なのか
//!
//! DACLの付与は「読む→ACEを足す→書き戻す」である。2つのスレッドが同じノードで交差すると
//! **片方のACEが黙って消える**。既存の背景ジョブがこれを避けていた方法は「そもそも他の書込を
//! 並行させない」（[`super::super::grant_job`]のモジュールdoc「約束」）だが、lazyレーンは
//! **割り込みを入れることが目的**なので、その手は使えない。代わりに**書く主体を1つに絞る**。
//!
//! 読取（「このノードにもう届いているか」）も同じスレッドで行う。判定と書込を別スレッドへ
//! 分けると read-modify-write が再び割れるためで、**ここでは速さより不可分性を採る**。
//!
//! # 優先度
//!
//! fault要求（[`WriterHandle::grant_now`]）は高優先度、走査の要求
//! （[`WriterHandle::grant_background`]）は低優先度である。writerは毎周回で**高優先度を
//! 先に空にする**ので、faultが待つのは最大でも処理中の1ノードぶんになる。
//!
//! **低優先度の待ち行列は深さ1に保つ**——[`WriterHandle::grant_background`]が完了まで
//! ブロックするためである。これは走査器への背圧（走査がwriterを追い越して無制限にキューを
//! 育てない）と、割り込み遅延の上限（常に「処理中の1件」だけ）を、**同じ1つの仕組みで**
//! 与える。
//!
//! # 計装ガードはこのスレッドで張る（着手条件2、`plans/mac-spike/RESULTS.md` §S13-0）
//!
//! [`crate::tier2a::grant_audit`]のガードは`thread_local!`である。**要求を出した側で
//! 張っても、書く側のスレッドには効かない。** 張り忘れると1件あたりが123 µsから1,180 µsへ
//! 跳ね、**ACLではなく計装を測ることになる**。だからガードは
//! [`spawn_writer_thread`]の**先頭**で、ACEの本数ぶん張る（本数ぶん張る理由は
//! [`super::super::fix_descendants_missing_aces`]と同じ——1本目だけ張ると2本目の子孫ぶんが
//! 全件「記録漏れ」として上がる、`B-06`）。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};

use crate::tier2a::win_appcontainer::{
    acl_dacl_write::grant_aces_single_object, acl_grant::IdempotentCheck,
    revoke::sid_effective_ace_masks, workspace_aces::inheritable_grants, AceGrant,
    AppContainerError, OwnedAceGrant,
};

/// writerが1件として扱う対象。`is_dir`は**継承フラグを決めるためだけ**に要る
/// （[`inheritable_grants`]がディレクトリにだけ`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`を
/// 立てる。着手条件1「継承ありで、伝播を起こさない書き方で置く」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) path: PathBuf,
    pub(crate) is_dir: bool,
}

impl Node {
    pub(crate) fn dir(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            is_dir: true,
        }
    }

    pub(crate) fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            is_dir: false,
        }
    }
}

/// 1ノードを処理した結果。**「書いた」と「もう届いていた」を分ける**のは、
/// 走査が実際に何件書いたかを数えるためである——既存の
/// [`super::super::DescendantFixReport::granted`]と同じ理由で、
/// この値が想定と違うことが伝播の退化を知る唯一の手がかりになる（`B-10`: 無言失敗を作らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeOutcome {
    /// 既に全ACEが届いていた（書込を省いた）。
    AlreadyReached,
    /// 足りないACEを1回の書込で置いた。
    Granted,
    /// 処理しようとしたらノードが消えていた（TOCTOU）。**失敗ではない。**
    Vanished,
}

/// writerが動いていないので要求を受け付けられない。
///
/// **呼び出し側はこれを「拒否」へ翻訳してはならない。** そのパスは既に許可済みで、届かない理由は
/// こちら側の可用性だからである（設計書§5.1.3の着手条件5）。fault経路の正しい倒し方は
/// 全walk barrierで待たせることである。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriterUnavailable;

/// writerがここまでに処理した量。表示ではなく**事後確認**のために持つ。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WriterStats {
    /// 見たノード数（`AlreadyReached`・`Granted`・`Vanished`の合計）。
    pub(crate) processed: usize,
    /// 実際に明示ACEを書いたノード数。
    pub(crate) granted: usize,
    /// DACLを読めなかったノード数（判定不能なので**付与側へ倒した**数）。
    pub(crate) probe_errors: usize,
    /// 消えていたノード数。
    pub(crate) vanished: usize,
    /// 高優先度（fault）として処理した要求の数。
    pub(crate) faults_served: usize,
}

/// writerへ渡す1件の仕事。
///
/// `nodes`が複数なのはfaultのためである——設計書§5.1.3が「fault要求は**対象と未準備祖先だけ**へ
/// 適用する」と定めており、祖先チェーンを**1つの高優先度単位**として処理しないと、
/// 途中に走査の低優先度要求が割り込んで「親はまだ無いのに子だけ付いた」状態を作り得る。
struct Job {
    nodes: Vec<Node>,
    is_fault: bool,
    reply: mpsc::Sender<Result<Vec<NodeOutcome>, String>>,
}

#[derive(Default)]
struct Queues {
    high: VecDeque<Job>,
    low: VecDeque<Job>,
    /// 受付を閉じた（[`AclWriter::stop_at_safe_point`]）。**処理中の1件は完了させる**——
    /// 設計書が「writerが処理中の1件を完了してから」と定めているのは、DACLの書込を
    /// 途中で捨てると読取と書込の間で終わるためである。
    closed: bool,
    stats: WriterStats,
}

struct Shared {
    queues: Mutex<Queues>,
    /// 仕事が積まれた／受付が閉じた、のどちらかで起こす。
    work: Condvar,
    /// スレッドが立ち上がって計装ガードを張り終えたか。**要求側の可用性判定に使わない**
    /// （[`WriterUnavailable`]は`closed`だけで決まる）。診断のためだけに持つ。
    running: AtomicBool,
}

/// 複製してscannerとbrokerへ配る要求口。
#[derive(Clone)]
pub(crate) struct WriterHandle {
    shared: Arc<Shared>,
}

impl WriterHandle {
    /// **割り込み**（fault）として処理させ、完了まで待つ。`nodes`はroot側から対象へ向かう順で
    /// 渡すこと——祖先が先に付いていないと、対象へACEを置いても通過できない。
    ///
    /// **製品からの呼び出しはbroker（段2）が繋ぐまで無い。** それまでは回帰テストだけが呼ぶ
    /// ——先に口と規則を固定しておき、繋ぐときに規則を決め直さないようにしてある。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn grant_now(
        &self,
        nodes: Vec<Node>,
    ) -> Result<Result<Vec<NodeOutcome>, String>, WriterUnavailable> {
        self.submit(nodes, true)
    }

    /// **背景の走査**として処理させ、完了まで待つ。待つのは背圧のためである（モジュールdoc）。
    pub(crate) fn grant_background(
        &self,
        node: Node,
    ) -> Result<Result<NodeOutcome, String>, WriterUnavailable> {
        let outcome = self.submit(vec![node], false)?;
        Ok(outcome.map(|mut v| v.pop().unwrap_or(NodeOutcome::Vanished)))
    }

    fn submit(
        &self,
        nodes: Vec<Node>,
        is_fault: bool,
    ) -> Result<Result<Vec<NodeOutcome>, String>, WriterUnavailable> {
        let (reply, wait) = mpsc::channel();
        {
            let mut queues = self.shared.queues.lock().unwrap();
            if queues.closed {
                return Err(WriterUnavailable);
            }
            let job = Job {
                nodes,
                is_fault,
                reply,
            };
            if is_fault {
                queues.high.push_back(job);
            } else {
                queues.low.push_back(job);
            }
        }
        self.shared.work.notify_one();
        // `recv`が切れるのは、writerが返事をせずに終わったときだけ（`closed`との競合）。
        // **そのときも拒否ではなく可用性の失敗として返す**——上のdoc（着手条件5）参照。
        wait.recv().map_err(|_| WriterUnavailable)
    }

    /// 診断用。writerスレッドが動いているか。**可用性の判定には使わない**
    /// （[`WriterUnavailable`]は受付が閉じたかだけで決まる）——2つの根拠で同じことを
    /// 判定すると、片方だけ真になる状態が生まれる（`B-13`）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::Acquire)
    }
}

/// このworkspaceツリーへのDACL書込を独占する単一writer。
pub(crate) struct AclWriter {
    shared: Arc<Shared>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl AclWriter {
    /// writerスレッドを起こす。`ace_grants`は**全モードぶん**（D-84）で、
    /// [`super::super::grant_job`]が背景ジョブへ渡すのと同じ集合でなければならない
    /// ——本数が食い違うと、片方のモードだけACEの無いツリーが出来る。
    pub(crate) fn start(root: PathBuf, ace_grants: Vec<OwnedAceGrant>) -> Self {
        let shared = Arc::new(Shared {
            queues: Mutex::new(Queues::default()),
            work: Condvar::new(),
            running: AtomicBool::new(false),
        });
        let join = spawn_writer_thread(Arc::clone(&shared), root, ace_grants);
        Self {
            shared,
            join: Some(join),
        }
    }

    pub(crate) fn handle(&self) -> WriterHandle {
        WriterHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// 受付を閉じ、**処理中の1件を完了させてから**スレッドを畳む（設計書の安全点）。
    ///
    /// 積まれたまま処理されなかった要求の送り主は、返事のチャネルが切れることで
    /// [`WriterUnavailable`]を受け取る——**拒否ではなく可用性の失敗**である。
    pub(crate) fn stop_at_safe_point(&mut self) -> WriterStats {
        {
            let mut queues = self.shared.queues.lock().unwrap();
            queues.closed = true;
        }
        self.shared.work.notify_all();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.stats()
    }

    pub(crate) fn stats(&self) -> WriterStats {
        self.shared.queues.lock().unwrap().stats
    }
}

impl Drop for AclWriter {
    /// **落とし忘れでスレッドを残さない。** `stop_at_safe_point`を呼んでいれば何もしない。
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.stop_at_safe_point();
        }
    }
}

/// **高優先度を先に空にする。** ここがレーンの目的そのもので、逆にすると
/// 「背景が終わるまで待つ」に戻る。
///
/// 待ち合わせから切り離して純粋な関数にしてあるのは、**この規則だけをスレッド無しで
/// 固定できるようにするため**である（順序をスレッドの走り方で測ると、実装が壊れていても
/// 実行順のゆらぎで緑になり得る）。
fn take_next(queues: &mut Queues) -> Option<Job> {
    if let Some(job) = queues.high.pop_front() {
        return Some(job);
    }
    queues.low.pop_front()
}

fn spawn_writer_thread(
    shared: Arc<Shared>,
    root: PathBuf,
    ace_grants: Vec<OwnedAceGrant>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // [着手条件2] **このスレッドで張る。** `thread_local!`なので要求側で張っても効かない
        // （モジュールdoc、§S13-0）。本数ぶん張るのは`fix_descendants_missing_aces`と同じ理由。
        let _audits: Vec<_> = ace_grants
            .iter()
            .map(|grant| crate::tier2a::grant_audit::note_root_grant(&root, grant.sid.as_psid()))
            .collect();
        // 借用版へ落とすのは**この1箇所**（全ノードが同じ集合を見ることを変数1つで保証する。
        // 別々に作ると片方だけACEが欠けても気付けない——`grant_job`の同じ注意書きと同型）。
        let grants = OwnedAceGrant::borrow_all(&ace_grants);
        shared.running.store(true, Ordering::Release);

        loop {
            let job = {
                let mut queues = shared.queues.lock().unwrap();
                loop {
                    if let Some(job) = take_next(&mut queues) {
                        break Some(job);
                    }
                    if queues.closed {
                        break None;
                    }
                    queues = shared.work.wait(queues).unwrap();
                }
            };
            let Some(job) = job else { break };

            let mut outcomes = Vec::with_capacity(job.nodes.len());
            let mut result = Ok(());
            let mut probe_errors = 0usize;
            for node in &job.nodes {
                match process_node(&grants, node, &mut probe_errors) {
                    Ok(outcome) => outcomes.push(outcome),
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }

            {
                let mut queues = shared.queues.lock().unwrap();
                let stats = &mut queues.stats;
                stats.processed += outcomes.len();
                stats.granted += outcomes
                    .iter()
                    .filter(|o| **o == NodeOutcome::Granted)
                    .count();
                stats.vanished += outcomes
                    .iter()
                    .filter(|o| **o == NodeOutcome::Vanished)
                    .count();
                stats.probe_errors += probe_errors;
                if job.is_fault {
                    stats.faults_served += 1;
                }
            }

            // 送り先が消えていても（要求側がキャンセルされた等）writerは止まらない。
            let _ = job.reply.send(result.map(|()| outcomes));
        }
        shared.running.store(false, Ordering::Release);
    })
}

/// 1ノードを read→判定→write する。**この関数だけがDACLを書く。**
///
/// 判定述語は[`sid_effective_ace_masks`]で、これは救済walk
/// （[`super::super::fix_descendants_missing_aces`]）と検算
/// （[`super::super::top_level_child_missing_aces`]）が使うのと**同じもの**である。
/// 別の述語で書くと「検算は欠けていると言うのに、修正側は足りていると言う」状態になる（`B-05`）。
fn process_node(
    grants: &[AceGrant],
    node: &Node,
    probe_errors: &mut usize,
) -> Result<NodeOutcome, String> {
    let sids: Vec<_> = grants.iter().map(|g| g.sid).collect();
    // **読めなければ届いていない側へ倒す**（読めない理由がACL不足のこともある）。
    // 既存の救済walkと同じ規則。
    let reached = match sid_effective_ace_masks(&node.path, &sids) {
        Ok(masks) => masks,
        Err(e) => {
            if vanished(&node.path) {
                return Ok(NodeOutcome::Vanished);
            }
            let _ = e;
            *probe_errors += 1;
            vec![None; sids.len()]
        }
    };
    let missing: Vec<AceGrant> = grants
        .iter()
        .zip(reached)
        .filter(|(_, mask)| mask.is_none())
        .map(|(grant, _)| *grant)
        .collect();
    if missing.is_empty() {
        return Ok(NodeOutcome::AlreadyReached);
    }
    // [着手条件1] 継承ありで、**伝播を起こさない書き方**で置く（`grant_aces_single_object`＝
    // `SetKernelObjectSecurity`）。伝播を起こす書き方だと既存の子孫へ86.5 µs/ノードを
    // 払い直し、事前配布に戻る（§S21-3）。
    //
    // `IdempotentCheck::Always`なのは、冪等判定を上の実効マスク読取で既に済ませているため
    // （明示ACEだけを見る`SkipIfSufficient`とは判定の基準が違うので、二重に掛けると噛み合わない）。
    match grant_aces_single_object(
        &node.path,
        &inheritable_grants(&missing, node.is_dir),
        IdempotentCheck::Always,
    ) {
        Ok(()) => Ok(NodeOutcome::Granted),
        Err(e) => {
            if vanished(&node.path) {
                Ok(NodeOutcome::Vanished)
            } else {
                Err(describe(e))
            }
        }
    }
}

/// **失敗してから**消えたかを見る（成功経路に`exists()`を1回足すと26万ノードで実測できる量に
/// なるため）。symlink自体の有無で見るのは、走査器がリパースポイントを辿らないのと同じ理由。
fn vanished(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

fn describe(e: AppContainerError) -> String {
    e.to_string()
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod writer_tests;
