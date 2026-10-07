//! 記録（パス1・パス2）を**専用スレッド**で回し、進行をチャネルでUIへ送る。
//!
//! [`crate::record`]・[`crate::record_net`]はどちらも呼び出しスレッドをブロックする同期関数
//! （それぞれのモジュールdocが明記している）。UIスレッドで呼ぶと描画もキー入力も止まるので、
//! ここでスレッドへ逃がす。UIは1フレームごとに[`RunHandle::poll`]で溜まった分を引き取るだけ。
//!
//! # キャンセルの実効範囲（B-23(b)・B-32）
//!
//! `cancel`クロージャが実際に読まれるのは`child_run::pump_child`のループの中だけである
//! （200ms間隔）。収集器の起動（UACの応答待ち）・ETWのウォームアップ・終了後のドレインは
//! `cancel`を見ない。したがって**押した瞬間に必ず止まるとは限らない**——立てたフラグは
//! 消えないので、まだ子プロセスが始まっていない段階で押した場合は「開始直後に打ち切られる」
//! という形になる。UIはこの違いをそのまま文言に出すこと（[`crate::tui::state::RunPhase`]）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use crate::record::{RecordError, RecordEvent, RecordOutcome, RecordRequest};
use crate::record_net::{NetRecordEvent, RecordNetError, RecordNetOutcome, RecordNetRequest};

/// workerからUIへ届くもの。
///
/// 結果は`Box`で包む——[`RecordOutcome`]は集計（`Aggregate`）ごと入るので、包まないと
/// enum全体がその大きさになり、進行イベント1件のたびに同じサイズを運ぶことになる。
pub enum WorkerMsg {
    Pass1(RecordEvent),
    Pass1Done(Box<Result<RecordOutcome, RecordError>>),
    Pass2(NetRecordEvent),
    Pass2Done(Box<Result<RecordNetOutcome, RecordNetError>>),
}

/// 実行中の記録1本。**UIはこれを持っている間だけ「実行中」である。**
pub struct RunHandle {
    cancel: Arc<AtomicBool>,
    rx: Receiver<WorkerMsg>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl RunHandle {
    /// 打ち切りを要求する（実効範囲はモジュールdocを参照）。
    pub fn request_stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn stop_requested(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// 溜まっているメッセージを全部引き取る。**UIスレッドをブロックしない。**
    pub fn poll(&self) -> Vec<WorkerMsg> {
        let mut out = Vec::new();
        while let Ok(msg) = self.rx.try_recv() {
            out.push(msg);
        }
        out
    }

    /// スレッドの終了を待つ。`*Done`を受け取った後に呼ぶ（記録の撤収まで終わっている）。
    pub fn join(&mut self) {
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

/// パス1（Tier0でのFS記録）の入力。**所有した値で渡す**——借用構造体
/// （[`RecordRequest`]）はスレッドの中で組み立てる。
pub struct Pass1Request {
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub timeout: Option<Duration>,
    /// ETW収集器。**TUI（`tui::run`）が持っているものを借りる**——記録のたびに起こし直すと
    /// そのたびUACが出る（D-56 段階2）。`SharedCollector`は`Arc<Mutex<..>>`なので、
    /// UIスレッドに所有権を置いたままこのスレッドへ渡せる。
    pub collector: crate::record::SharedCollector,
    /// 常駐netfilterd（あれば）。パス1はWFPを張らないが、**netfilterdが既に生きているなら
    /// そこから収集器を連鎖起動できる**（D-60の適用範囲。パス2にしかこの経路が無かった
    /// ことが、パス1実行のたびにpolicy-learndのUACが余分に出るバグの原因だった）。
    pub wfp: crate::record_net::SharedNetfilter,
}

/// パス2（Tier2aでのドメイン記録）の入力。[決定68(2)] ドメインは持たない（常に入口から始める）。
pub struct Pass2Request {
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub timeout: Option<Duration>,
    /// WFPの出口強制daemon。**TUI（`tui::run`）が持っているものを借りる**——実行のたびに
    /// 起こし直すとそのたびUACが出る（D-56）。`SharedNetfilter`は`Arc<Mutex<..>>`なので、
    /// UIスレッドに所有権を置いたままこのスレッドへ渡せる。
    pub wfp: crate::record_net::SharedNetfilter,
    /// ETW収集器（deny-only）。パス1と**同じdaemon**を使い回す（D-56 段階2）。
    pub collector: crate::record::SharedCollector,
    pub spawn_daemon: crate::record_net::SharedSpawnDaemon,
    /// [決定64] 通信をどう扱うか（記録画面の「パス」欄で選んだもの）。
    pub net_mode: crate::record_net::NetMode,
}

pub fn spawn_pass1(request: Pass1Request) -> RunHandle {
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = Arc::clone(&cancel);

    let join = std::thread::spawn(move || {
        let canceled = move || cancel_for_thread.load(Ordering::Relaxed);
        let req = RecordRequest {
            command: &request.command,
            cwd: &request.cwd,
            workspace_root: &request.workspace_root,
            timeout: request.timeout,
            cancel: &canceled,
            collector: &request.collector,
            wfp: Some(&request.wfp),
        };
        let tx_events: Sender<WorkerMsg> = tx.clone();
        let mut on_event = |event: RecordEvent| {
            // 受け手（UI）が居なくなっていても記録は最後まで走らせる——途中で投げ出すと
            // 収集器の撤収とマニフェストの確定を飛ばすことになる。
            let _ = tx_events.send(WorkerMsg::Pass1(event));
        };
        let outcome = crate::record::record(&req, &mut on_event);
        let _ = tx.send(WorkerMsg::Pass1Done(Box::new(outcome)));
    });

    RunHandle {
        cancel,
        rx,
        join: Some(join),
    }
}

pub fn spawn_pass2(request: Pass2Request) -> RunHandle {
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = Arc::clone(&cancel);

    let join = std::thread::spawn(move || {
        let canceled = move || cancel_for_thread.load(Ordering::Relaxed);
        let req = RecordNetRequest {
            command: &request.command,
            cwd: &request.cwd,
            workspace_root: &request.workspace_root,
            timeout: request.timeout,
            cancel: &canceled,
            wfp: &request.wfp,
            collector: &request.collector,
            spawn_daemon: &request.spawn_daemon,
            net_mode: request.net_mode,
        };
        let tx_events: Sender<WorkerMsg> = tx.clone();
        let mut on_event = |event: NetRecordEvent| {
            let _ = tx_events.send(WorkerMsg::Pass2(event));
        };
        let outcome = crate::record_net::record_net(&req, &mut on_event);
        let _ = tx.send(WorkerMsg::Pass2Done(Box::new(outcome)));
    });

    RunHandle {
        cancel,
        rx,
        join: Some(join),
    }
}
