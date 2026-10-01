//! TUIの状態と遷移。**描画も端末もここには無い**——キーイベントとworkerからの
//! メッセージを受けて状態を変えるだけなので、端末を用意せずにテストできる。
//!
//! # 副作用は`Action`として呼び出し側へ返す
//!
//! 記録の開始（スレッドの起動）と終了はイベントループが行う。状態機械が直接スレッドを
//! 起こすと、テストが毎回UACと実機のETWを要求することになる。
//!
//! # 画面の順序は強制しない（決定13）
//!
//! `F1`/`F2`でいつでも行き来できる。ガイド（パス1完了→編集へ、承認→パス2を提示）は
//! **次にやることの提案**であって、そこにしか行けない一方通行のウィザードではない。

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use harness_policy::RuleProposal;
use harness_sandbox::tier2a::win_appcontainer::passthrough_progress::ProgressCell as PassthroughProgressCell;

use crate::child_run::AbortReason;
use crate::policy_file::{self, PolicyDomain};
use crate::record::{RecordEvent, RecordOutcome};
use crate::record_net::NetRecordEvent;
use crate::session_dir::{self, RecordManifest, RecordSessionDir};
use crate::tui::proposal_tree::ProposalTree;
use crate::tui::text_input::TextInput;
use crate::tui::worker::{Pass1Request, Pass2Request, RunHandle, WorkerMsg};

/// 進行ログ・出力の保持上限（行）。**超えた分は捨てるが、捨てた件数は必ず出す**（B-09）。
const MAX_LINES: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Record,
    Edit,
    /// `policy.json`の承認済み宣言そのものを見て取り消す画面。
    ///
    /// **記録セッションを参照しない**ので、ログが1件も無くても・過去のログを消していても開ける。
    /// 編集画面（候補一覧）とは入力が違う——あちらは「今回の記録で何が観測されたか」、
    /// こちらは「いま何を許可し続けているか」である。
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// パス1: 隔離せず（Tier0）に触ったファイルを記録する。観測の器が対象の動きを変えないため。
    One,
    /// パス2: Tier2a（AppContainer＋WFP＋Proxy）で接続したドメインを記録する。
    Two,
}

impl Pass {
    pub fn label(self) -> &'static str {
        match self {
            Pass::One => "パス1: 隔離なし（Tier0）でFSアクセスを記録（UAC 1回）",
            Pass::Two => "パス2: Tier2aで接続ドメインを記録（UAC 最大2回・ACEが実際に付く）",
        }
    }

    /// 実行前に見せる前置き。**文言は実行する側が持つ**（表示側で書き写さない、B-05）。
    pub fn elevation_notice(self) -> String {
        match self {
            Pass::One => crate::record::ELEVATION_NOTICE.to_string(),
            // 実際の回数は`policy.json`のworkspace外の穴の有無で決まるので、実行前は上限を出す。
            Pass::Two => crate::record_net::elevation_notice(2),
        }
    }
}

/// 記録の進行段階。**停止操作が効くかどうかがここで決まる。**
///
/// `cancel`が読まれるのは`child_run::pump_child`のループの中だけなので、
/// [`RunPhase::Running`]以外で押された停止は「予約」にしかならない（フラグは立ったまま
/// 残るので、子プロセスが始まった直後に打ち切られる）。ドレイン以降は押しても何も起きない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    /// 収集器（昇格）の起動待ち。UACのダイアログはこの間に出る。
    StartingCollector,
    /// ETWの配送が始まるのを待っている（実測1500ms）。
    WarmingUp,
    /// パス2の準備（ACE付与・Proxy・Fake DNS・WFP）。
    Preparing,
    /// 対象コマンドが動いている。**停止がその場で効く唯一の区間。**
    Running,
    /// 監査ログの残りが届くのを待っている。
    Draining,
    /// 撤収中（収集器・WFP・AppContainerプロファイル）。
    Finishing,
}

impl RunPhase {
    pub fn label(self) -> &'static str {
        match self {
            RunPhase::StartingCollector => {
                "収集器を起動しています（UACのダイアログに応答してください）"
            }
            RunPhase::WarmingUp => "ETWの配送が始まるのを待っています",
            RunPhase::Preparing => "Tier2aの準備をしています（ACE付与・Proxy・WFP）",
            RunPhase::Running => "コマンドを実行しています",
            RunPhase::Draining => "監査ログの残りが届くのを待っています",
            RunPhase::Finishing => "撤収しています",
        }
    }

    /// 停止操作が**その場で**効くか。
    pub fn stop_takes_effect_now(self) -> bool {
        matches!(self, RunPhase::Running)
    }

    /// 停止を予約できるか（今は効かないが、コマンド開始直後に打ち切られる）。
    pub fn stop_can_be_queued(self) -> bool {
        matches!(
            self,
            RunPhase::StartingCollector | RunPhase::WarmingUp | RunPhase::Preparing
        )
    }

    /// その段階で何を待っているのか・どれくらいかかるのかの目安。
    ///
    /// **「なぜ止まって見えるのか」を言う。** 無言の待ちは「壊れた」と読まれる（B-32）。
    /// 所要時間の目安は、その待ちが**構造上必要**である理由とセットで書く。
    pub fn hint(self) -> &'static str {
        match self {
            RunPhase::StartingCollector => {
                "収集器はETWのリアルタイムセッションを張るため管理者権限が要ります。\
                 UACのダイアログが別画面に出ていないか確認してください"
            }
            RunPhase::WarmingUp => {
                "ここを省くとProcessStartごと取りこぼし、観測結果が0件になります（実測）"
            }
            RunPhase::Preparing => {
                "workspace外の穴はセッション固有のSID宛に毎回付け直します（D-37: \
                 穴がセッションを跨いで残らないようにするため）。.cargoのような大きな\
                 ツリーでは数十秒かかることがあります"
            }
            RunPhase::Running => "コマンドが終わるまで待ちます",
            RunPhase::Draining => {
                "ETWは配送が遅れて届くので、ここで待たないと最後のアクセスを取りこぼします"
            }
            RunPhase::Finishing => "収集器・WFP・AppContainerプロファイルを畳んでいます",
        }
    }

    /// 停止を押しても何も起きない区間で出す理由（**押せば止まると見せない**、B-32）。
    pub fn why_stop_does_nothing(self) -> Option<&'static str> {
        match self {
            RunPhase::Draining => {
                Some("いまは停止できません（ETWの残りイベントを取りこぼさないための待ちです）")
            }
            RunPhase::Finishing => Some("いまは停止できません（撤収中です）"),
            _ => None,
        }
    }
}

/// 件数で測れる作業の進み具合。**ACEの付与と撤収が同じ型・同じ描画を通る。**
///
/// # なぜ共通にするのか
///
/// 付与と撤収は対の操作で、ユーザーから見て知りたいことも同じ（あと何件か・いま何をしているか・
/// 何件が実質的な変更だったか）である。別々に持つと、片方にだけゲージが付き・片方は
/// ログ行だけ、という非対称が生まれる（実際に一度そうなった）。**対の操作は表示も対にする。**
///
/// 進捗の**取得元**は対称ではない——付与は`preflight`がイベントを流せない同期区間で走るので
/// プロセスグローバルなセル（`passthrough_progress`）から引き、撤収はworkerスレッドなので
/// イベントで届く。差はそこだけに閉じ、**状態と描画はここ1箇所**にまとめる。
pub struct PhaseWork {
    /// 何をしているか（ゲージの内訳に出す見出し）。
    pub label: &'static str,
    pub total: usize,
    pub done: usize,
    /// 内訳を出すか。付与は「新規／既存のまま」を必ず並べる——`668/668`だけだと、
    /// 1件もACEを書いていない2回目以降が1回目と区別できず「毎回付け直している」と読まれる。
    /// 撤収に内訳は無い（剥がしたか、剥がしていないかしかない）。
    pub breakdown: bool,
    /// 実際に書いた件数と、既に十分で触っていない件数（`breakdown`が真のときだけ意味を持つ）。
    pub written: usize,
    pub skipped: usize,
}

impl PhaseWork {
    /// ACE付与の進捗（内訳あり）。
    pub fn grants(total: usize) -> Self {
        Self {
            label: "ACE",
            total,
            done: 0,
            breakdown: true,
            written: 0,
            skipped: 0,
        }
    }

    /// ACE撤収の進捗（内訳なし）。
    pub fn revocations(total: usize) -> Self {
        Self {
            label: "撤収",
            total,
            done: 0,
            breakdown: false,
            written: 0,
            skipped: 0,
        }
    }

    /// [BUG-101] 付与したACEが台帳に載っているかの自己検証（内訳なし——1件も付与しない）。
    ///
    /// **付与と同じゲージを通す**。数百件のパスをDACLごとに読む同期区間なので、
    /// 出さないと「付与が終わったのにまだ固まっている」と読まれる（B-23(a)）。
    pub fn audit(total: usize) -> Self {
        Self {
            label: "自己検証",
            total,
            done: 0,
            breakdown: false,
            written: 0,
            skipped: 0,
        }
    }

    /// ゲージに出す内訳の文言。**付与と撤収で1つの関数**が持つ。
    pub fn detail(&self) -> String {
        if self.breakdown {
            format!(
                "{} {}/{}（新規{}・既存のまま{}）",
                self.label, self.done, self.total, self.written, self.skipped
            )
        } else {
            format!("{} {}/{}", self.label, self.done, self.total)
        }
    }
}

/// 実行中の記録1本ぶんの表示状態。
pub use harness_term::scrollback::Scrollback;

pub struct RunState {
    pub pass: Pass,
    pub phase: RunPhase,
    /// 記録を開始した時刻（経過時間の表示用）。
    pub started: Instant,
    /// いまの段階に入った時刻。**段階ごとの経過**を出すために別に持つ
    /// ——全体の経過だけだと「いま何秒待たされているのか」が分からない。
    pub phase_started: Instant,
    /// その段階の所要時間が**確定している**場合の値（ウォームアップ・ドレイン）。
    /// 分かっているものは進捗として出し、分からないものは経過だけ出す（合成しない）。
    pub phase_expected: Option<Duration>,
    /// 件数で測れる作業の進み具合（ACEの**付与**と**撤収**が共有する。[`PhaseWork`]）。
    pub work: Option<PhaseWork>,
    pub stop_requested: bool,
    /// 進行ログ（収集器・警告・撤収など）。
    pub log: VecDeque<String>,
    /// 対象コマンドの出力。
    pub output: VecDeque<String>,
    /// シェルがコマンドを走らせる**前**に吐いた出力。本体と混ぜない（BUG-086・B-33）。
    pub noise: VecDeque<String>,
    /// 3つの枠それぞれのスクロール位置（[`Scrollback`]）。既定は末尾追従。
    pub log_scroll: Scrollback,
    pub output_scroll: Scrollback,
    pub noise_scroll: Scrollback,
    /// 上限を超えて捨てた行数（黙って消さない）。
    pub dropped: u64,
    /// 観測した監査イベントの件数（速報。正本は監査JSONL）。
    pub events: u64,
    pub warnings: Vec<String>,
    pub exit_code: Option<i32>,
    pub aborted: Option<AbortReason>,
    /// 記録が終わったか。**終わっても`RunState`は捨てない**——捨てるとコマンドの出力も
    /// 進行ログも消え、ユーザーは結果を一度も読めない（それが記録の目的そのものなのに）。
    /// 次の記録を開始したときに、新しい`RunState`で置き換わる。
    pub finished: bool,
    /// 記録に要した時間（`finished`のときに固定する）。**終了後も`started.elapsed()`を
    /// 出すと、終わった記録の経過時間が増え続けて「まだ動いている」ように見える。**
    pub total_elapsed: Option<Duration>,
    /// ACE付与・自己検証の進捗を読むセル。既定は製品共有の1つ（[`RunState::new`]）。
    ///
    /// **フィールドで持つ理由**（[BUG-138](../../../../docs/bugs/BUG-138.md)）: 以前は
    /// `drain_worker`と[`RunState::finish`]がそれぞれプロセスグローバルなセルを直に読んでいた。
    /// 製品では書き手も読み手も1つずつなので正しく動くが、**テストバイナリは同じプロセスで
    /// 複数のテストを並行に走らせる**ので、共有セルを読んで断言するテストが2本目になった
    /// 瞬間に互いを踏む。ここを差し替え可能にしておくと、断言するテストは自分のセルを持てる。
    ///
    /// `App`ではなく`RunState`が持つ——読むのは`drain_worker`（`App`側）と`finish`
    /// （`RunState`側）の**両方**で、`App`に置くと後者へ届かない。
    pub progress: &'static PassthroughProgressCell,
}

impl RunState {
    pub(crate) fn new(pass: Pass) -> Self {
        Self::with_progress(
            pass,
            harness_sandbox::tier2a::win_appcontainer::passthrough_progress::global(),
        )
    }

    /// 進捗セルを指定して作る。**テスト専用の入口ではない**が、実際に別のセルを渡すのは
    /// 進捗表示を断言する回帰テストだけである（[`RunState::progress`]のdoc）。
    pub(crate) fn with_progress(pass: Pass, progress: &'static PassthroughProgressCell) -> Self {
        let now = Instant::now();
        Self {
            pass,
            phase: RunPhase::StartingCollector,
            started: now,
            phase_started: now,
            phase_expected: None,
            work: None,
            stop_requested: false,
            log: VecDeque::new(),
            output: VecDeque::new(),
            noise: VecDeque::new(),
            // 既定は末尾追従。ユーザーがホイールで上へ動かすまでは今までどおり流れる。
            log_scroll: Scrollback::default(),
            output_scroll: Scrollback::default(),
            noise_scroll: Scrollback::default(),
            dropped: 0,
            events: 0,
            warnings: Vec::new(),
            exit_code: None,
            aborted: None,
            finished: false,
            total_elapsed: None,
            progress,
        }
    }

    /// 記録が終わった。**バッファは残したまま**、経過時間だけ固定する。
    fn finish(&mut self) {
        self.finished = true;
        self.total_elapsed = Some(self.started.elapsed());
        // 進捗フェーズは終わっているので`snapshot()`は`None`になる。**マシンに何をしたかの
        // 事実は残す**——「今回ACEを何件書いたか」は結果として読めなければ意味が無い。
        // 内訳を持つ作業（＝付与）だけが対象。撤収は「剥がしたか」しかないので内訳は無い。
        if self.pass == Pass::Two && self.work.as_ref().is_some_and(|w| w.breakdown) {
            let totals = self.progress.last_totals();
            if let Some(work) = self.work.as_mut() {
                work.written = totals.granted;
                work.skipped = totals.already;
            }
            self.log_line(format!(
                "ACEの適用: 新規に書いた {}件／既に十分だったので触っていない {}件（対象 {}件）",
                totals.granted, totals.already, totals.total
            ));
        }
    }

    /// 表示に使う経過時間（終了後は固定値）。
    pub fn elapsed(&self) -> Duration {
        self.total_elapsed.unwrap_or_else(|| self.started.elapsed())
    }

    /// 1行積む。**スクロール位置には触らない。**
    ///
    /// [`Scrollback`]は「下端から何行さかのぼっているか」で位置を持つので、行が増えても
    /// その距離は変わらない——transcriptと同じ意味論である。ここで位置を足し引きすると
    /// 会話TUIと挙動が食い違う。
    fn push(buf: &mut VecDeque<String>, line: String, dropped: &mut u64) {
        buf.push_back(line);
        while buf.len() > MAX_LINES {
            buf.pop_front();
            *dropped += 1;
        }
    }

    pub(crate) fn log_line(&mut self, line: impl Into<String>) {
        let mut dropped = self.dropped;
        Self::push(&mut self.log, line.into(), &mut dropped);
        self.dropped = dropped;
    }

    /// 対象コマンドの出力を1行積む。
    pub(crate) fn output_line(&mut self, line: impl Into<String>) {
        let mut dropped = self.dropped;
        Self::push(&mut self.output, line.into(), &mut dropped);
        self.dropped = dropped;
    }

    /// シェルの起動時ノイズを1行積む（本体の出力と混ぜない、BUG-086）。
    fn noise_line(&mut self, line: impl Into<String>) {
        let mut dropped = self.dropped;
        Self::push(&mut self.noise, line.into(), &mut dropped);
        self.dropped = dropped;
    }

    /// 段階を進める。**経過の起点と所要見込みを同時に更新する**（別々に持つと、片方だけ
    /// 更新し忘れて「1分経過」と出続ける）。
    fn enter_phase(&mut self, phase: RunPhase, expected: Option<Duration>) {
        if self.phase != phase {
            self.phase_started = Instant::now();
        }
        self.phase = phase;
        self.phase_expected = expected;
    }

    /// いまの段階の進み具合（0.0〜1.0）。**測れるときだけ返す**——測れないものを
    /// 経過時間から合成すると、止まっているのに進んでいるように見える。
    ///
    /// 件数で測れる作業（[`PhaseWork`]＝ACEの付与・撤収）は**同じ経路**でゲージになる。
    pub fn phase_progress(&self) -> Option<f64> {
        if let Some(work) = self.work.as_ref().filter(|w| w.total > 0) {
            return Some(work.done as f64 / work.total as f64);
        }
        let expected = self.phase_expected?;
        if expected.is_zero() {
            return None;
        }
        Some((self.phase_started.elapsed().as_secs_f64() / expected.as_secs_f64()).min(1.0))
    }

    /// 進み具合の内訳（件数が分かるならその表示）。文言は[`PhaseWork::detail`]が1つだけ持つ。
    pub fn phase_detail(&self) -> Option<String> {
        if let Some(work) = self.work.as_ref().filter(|w| w.total > 0) {
            return Some(work.detail());
        }
        let expected = self.phase_expected?;
        Some(format!(
            "{:.1}/{:.1}秒",
            self.phase_started
                .elapsed()
                .as_secs_f64()
                .min(expected.as_secs_f64()),
            expected.as_secs_f64()
        ))
    }
}

/// 経過時間を`MM:SS`で出す（会話TUIの準備画面と同じ形）。
pub fn format_elapsed(elapsed: Duration) -> String {
    let total = elapsed.as_secs();
    format!("{:02}:{:02}", total / 60, total % 60)
}

/// スピナーの1コマ。会話TUI（`harness-tui`の`SPINNER_FRAMES`）と**同じ絵柄・同じ速さ**にする
/// ——同じ製品の待ち画面が別物に見える理由が無い。
pub fn spinner_frame(elapsed: Duration) -> char {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    FRAMES[(elapsed.as_millis() / 100) as usize % FRAMES.len()]
}

/// 進捗バー。`ratio`は0.0〜1.0。
pub fn progress_bar(ratio: f64, width: usize) -> String {
    let filled = ((ratio.clamp(0.0, 1.0)) * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// 記録画面のフォーカス。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordField {
    Pass,
    Command,
    Cwd,
    /// パス2のドメイン名（パス1では飛ばす）。
    Domain,
}

/// 編集画面のフォーカス。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditField {
    Sessions,
    Proposals,
    Domain,
}

/// 確認ダイアログ。**書く前に必ず差分を見せる**（`approve`のplan/commitの2段をUIで使う）。
///
/// 差分は一括選択で数百行になりうるので、**操作の案内は本文ではなく枠へ書く**
/// （本文の最後に置くと、収まらなかったときに`y`を押せばよいことが画面から消える）。
pub struct Modal {
    pub title: String,
    pub lines: Vec<String>,
    /// `y`を押したときに**何を書くのか**。
    pub confirm: Confirm,
}

/// 確認ダイアログの`y`が実行する操作。
///
/// # なぜ`bool`ではないのか
///
/// 以前は`confirm: bool`で、`y`は常に承認（`commit_approval`）を呼んでいた。書き込みの種類が
/// 2つ（承認と取り消し）になった時点で、`bool`では**どちらを書くのかがモーダルを開いた側の
/// 暗黙の文脈に消える**——取り消しの確認で`y`を押したら承認が走る、という取り違えが
/// 型では止まらなくなる。何を書くのかをモーダル自身に持たせる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// 読むだけ（エラー・報告）。`y`では何も起きず、Enterで閉じる。
    ReadOnly,
    /// 候補の承認（と、同時に予約された宣言の取り消し）を書く。編集画面の`a`。
    Approval,
    /// 宣言画面の`a`。**このマシンでの承認（`y`で予約した分）と宣言の取り消し（`Space`で予約した分）**を
    /// 書く。編集画面の`Approval`が承認と取り消しを1回で確定するのと同じ形にしてある。
    DeclaredChanges,
    /// [段階⑦] 遷移の宣言を足す／消す。承認待ち画面の遷移タブの`a`。
    ///
    /// **`Approval`と分けてあるのは、書く先も確認の文面も違うから**である
    /// （あちらは`fs`/`net`の宣言とACEの予告、こちらは`process`の辺と「ACLは変わらない」）。
    /// 1つにまとめると、確定の腕がどちらの意味だったか判別できなくなる。
    Transition,
}

impl Confirm {
    /// `y`/`n`を聞く形か（枠の色と案内文が使う）。
    pub fn asks(self) -> bool {
        !matches!(self, Confirm::ReadOnly)
    }
}

/// 記録セッション1件（一覧用）。
pub struct SessionEntry {
    pub dir: RecordSessionDir,
    pub manifest: RecordManifest,
}

/// 選択中セッションの中身。**候補の計算はJSONLから毎回やり直す**（B-13）。
///
/// # なぜ「FSかnetのどちらか」ではないのか
///
/// パス2の記録は**両方を持つ**（強制下のFS拒否と、記録のため全許可で観測したドメイン）。
/// かつてこれは`enum`で、パス2は`Net`だけを保持していた——一覧には両方を並べていたのに
/// 保持していたのは片方だけだったので、**`g`（一般化の度合い）を押した瞬間にFSの候補が
/// 全部消えていた**（`recompute_proposals`が保持している側からしか作り直せない）。
/// 「一覧に出したもの」と「作り直せるもの」がずれない形にしてある。
#[derive(Default)]
pub struct SessionData {
    pub fs: Option<Box<crate::aggregate::Aggregate>>,
    pub net: Option<Box<crate::net_aggregate::NetAggregate>>,
}

impl SessionData {
    /// **FSを先、ネットワークを後**（強制が効いているのはFSだけなので、「宣言を直せば直る」
    /// 情報はこちらにしか無い）。idは衝突しない（`generalize`がFSへ`fs-N`・netへ`net-N`を振る）。
    pub fn proposals(&self) -> Vec<RuleProposal> {
        let mut proposals = self
            .fs
            .as_ref()
            .map(|fs| fs.proposals())
            .unwrap_or_default();
        if let Some(net) = self.net.as_ref() {
            proposals.extend(net.proposals());
        }
        proposals
    }
}

/// 候補一覧に何を出すか。
///
/// 既定は**承認できるものだけ**。承認できない候補（広すぎる値）は観測の事実としては正しいので
/// 消さない（D-43）が、既定で混ぜると「選べないものが一覧の上位を占める」状態になる
/// ——実測では祖先チェーン由来の`C:`・`C:/`が先頭に並んだ。**隠した件数は必ず出す**（B-09）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateFilter {
    /// 承認できるものだけ（既定）。
    Approvable,
    /// 承認できないものだけ（なぜ選べないのかを確かめる用）。
    Blocked,
    /// 全部。
    All,
}

impl CandidateFilter {
    pub fn label(self) -> &'static str {
        match self {
            CandidateFilter::Approvable => "承認できるもの",
            CandidateFilter::Blocked => "承認できないもの",
            CandidateFilter::All => "全部",
        }
    }

    pub fn next(self) -> Self {
        match self {
            CandidateFilter::Approvable => CandidateFilter::Blocked,
            CandidateFilter::Blocked => CandidateFilter::All,
            CandidateFilter::All => CandidateFilter::Approvable,
        }
    }

    pub(crate) fn accepts(self, too_broad: bool) -> bool {
        match self {
            CandidateFilter::Approvable => !too_broad,
            CandidateFilter::Blocked => too_broad,
            CandidateFilter::All => true,
        }
    }
}

pub struct SessionView {
    pub data: SessionData,
    /// 候補一覧の手前に出す注記（`render_notes`。文言はCLIと共有）。
    pub notes: String,
    /// 観測したプロセスツリー（FSの記録のみ）。
    pub tree: String,
    pub proposals: Vec<RuleProposal>,
    /// 候補ごとの「幅が広すぎて承認できない」判定（`proposals`と同じ並び）。
    ///
    /// 描画のたびに`breadth::check`を呼ぶと、候補の数だけ拒否メッセージを組み立てることになる
    /// （実測849件×毎フレーム）。判定そのものは`breadth`の同じ関数で、結果だけ持っておく。
    pub too_broad: Vec<bool>,
    /// **全候補に共通の警告**（OS監査は読みと書きを区別できない、等）。
    ///
    /// 行ごとに出すと同じ文が候補の数だけ並び（実測849件）、個別の警告が埋もれる。
    /// 共通のものは注記として1度だけ出し、行には**その行に固有のもの**だけを残す。
    pub common_warnings: Vec<String>,
}

impl SessionView {
    /// 全候補が持っている警告（＝行ごとに出す価値が無いもの）を求める。
    ///
    /// 特定の文字列を名指しにしない——他クレートの文面を写すと、向こうが変わったときに
    /// 黙ってすり抜ける（B-05）。「全部に付いているか」だけで決める。
    fn common_warnings(proposals: &[RuleProposal]) -> Vec<String> {
        let Some(first) = proposals.first() else {
            return Vec::new();
        };
        first
            .warnings
            .iter()
            .filter(|warning| proposals.iter().all(|p| p.warnings.contains(warning)))
            .cloned()
            .collect()
    }

    pub fn new(
        data: SessionData,
        notes: String,
        tree: String,
        proposals: Vec<RuleProposal>,
    ) -> Self {
        let common_warnings = Self::common_warnings(&proposals);
        let too_broad = proposals
            .iter()
            .map(|p| harness_policy::breadth::check(p).is_too_broad())
            .collect();
        Self {
            data,
            notes,
            tree,
            proposals,
            too_broad,
            common_warnings,
        }
    }

    /// フィルタを通した候補の添字（`proposals`への添字）。
    pub fn visible(&self, filter: CandidateFilter) -> Vec<usize> {
        (0..self.proposals.len())
            .filter(|i| filter.accepts(self.too_broad[*i]))
            .collect()
    }

    /// 承認できない（広すぎる）候補の件数。**隠すなら件数は必ず出す**（B-09）。
    pub fn blocked_count(&self) -> usize {
        self.too_broad.iter().filter(|b| **b).count()
    }

    /// その候補に固有の警告（共通のものを除いたもの）。
    pub fn row_warnings<'a>(&'a self, proposal: &'a RuleProposal) -> impl Iterator<Item = &'a str> {
        proposal
            .warnings
            .iter()
            .filter(|w| !self.common_warnings.contains(w))
            .map(String::as_str)
    }
}

/// 状態機械が呼び出し側へ依頼する副作用。
pub enum Action {
    StartPass1(Box<Pass1Request>),
    StartPass2(Box<Pass2Request>),
    Quit,
}

pub struct App {
    pub workspace_root: PathBuf,
    /// 承認ゲート（D-42）へ渡す`--require-sandbox`の宣言。
    ///
    /// **`RequireSandbox::None`を既定値として黙って埋めない。**
    /// `None`は「ユーザーが何も要求していない」という正当な状態でもあるので、
    /// 渡し忘れとの区別がゲートから付かない——[BUG-127](../../../../docs/bugs/BUG-127.md)は
    /// まさにその形で、TUIの2箇所が定数`None`を書いていたためD-42の突き合わせが1件も効かなかった。
    /// **必須の引数にして、構築点をコンパイラに数えさせる。**
    pub require_sandbox: harness_core::RequireSandbox,
    pub screen: Screen,
    pub help: bool,
    pub status: String,
    pub modal: Option<Modal>,
    /// 確認ダイアログの表示開始行（長い差分を最後まで読めるようにするため）。
    pub modal_scroll: u16,

    // 記録画面
    pub pass: Pass,
    pub command: TextInput,
    pub cwd: TextInput,
    pub run_domain: TextInput,
    pub record_focus: RecordField,
    pub run: Option<RunState>,
    /// TUIの間に預かった、このプロセス自身の標準エラー出力（ライブラリの警告）。
    /// 記録中は進行ログへ流すので、ここに溜まるのは**待機中に出たもの**だけ。
    pub notices: VecDeque<String>,
    handle: Option<RunHandle>,
    /// 実行中に終了要求が来た。撤収まで待ってから抜ける。
    pub quit_after_run: bool,
    /// WFPの出口強制daemon（D-56）。**TUIを閉じるまで生かす**ので、2回目以降のパス2は
    /// `ApplyRules`の再送だけで済み、UACが出ない。実行の切れ目でフィルタは畳まれる
    /// （`record_net::teardown`）ので、待機中のdaemonは何も張っていない。
    ///
    /// `App`が持つのは`tui::run`のスコープで`SessionGrants`より**後**に作られるためで、
    /// これによりnetfilterdの`Teardown`がAppContainerプロファイルの削除より先に走る
    /// （`SharedNetfilter`のdoc「宣言順」）。
    /// 最初のパス2まで起動せず、その後はTUI終了まで再利用する。構造体fieldの宣言順で
    /// dropされるため、WFP・収集器より前に置いて生成者を先に畳む。
    pub spawn_daemon: crate::record_net::SharedSpawnDaemon,
    pub wfp: crate::record_net::SharedNetfilter,
    /// ETW収集器。**プロセスの寿命で持つ**（D-56 段階2、`SharedCollector`）。
    /// `wfp`と同じ理由でここに置く——記録のたびに起こし直すとそのたびUACが出る。
    pub collector: crate::record::SharedCollector,

    // 編集画面
    pub sessions: Vec<SessionEntry>,
    pub selected_session: usize,
    pub view: Option<SessionView>,
    pub filter: CandidateFilter,
    pub accepted: BTreeSet<String>,
    /// **`c`でaccessを手で変えた候補のid**（`view.proposals`の中身と対）。
    ///
    /// 承認の確認画面で件数を出すために持つ——観測が言っていることと、ユーザーが判断したことは
    /// 別で、**何を書くのかを読んでから`y`を押せる**必要がある（D-42）。
    /// 候補を作り直す操作（セッション移動など）では**必ず空にする**——idの指す先が
    /// 変わるので、残すと無関係な候補に「手で変えた」印が付く。
    pub hand_changed: BTreeSet<String>,
    /// [D-63] `R`で**再帰**を指定したノードのパス集合（木のノードパスそのもの）。
    ///
    /// ここに入っているノードは、承認時に`<path>/**`という値の宣言として合成される
    /// （[`super::edit::App::recursive_proposals`]）。**候補idではなくノードパスで持つ**のは、
    /// 印を付けられる対象が候補とは限らないため——`.rustup/toolchains`のように
    /// 「中のファイルだけが観測されていて、そのフォルダ自身は候補になっていない」構造ノードにも
    /// 付けられる必要がある（付けられないと、今回いちばん困る形が救えない）。
    ///
    /// **再帰は推論では付かない。** D-62でパスの一般化を廃止したので、`**`が現れるのは
    /// ユーザーがこのキーを押したときと、`settings.json`を手で書いたときだけである。
    pub recursive: HashSet<String>,
    /// 候補のパス木（フィルタ後の候補から組み立てる）。
    ///
    /// **`view`・`filter`のどちらかを変えたら`rebuild_tree`を呼ぶこと。**
    /// 呼ばないと、木が古い候補を指したまま操作されることになる。
    pub tree: ProposalTree,
    /// 展開しているノードのパス。**木を作り直しても残す**ので、フィルタや一般化の度合いを
    /// 変えても開いていた場所が閉じない。
    pub expanded: HashSet<String>,
    /// 木の**見えている行**での選択位置。
    pub selected_row: usize,
    /// 3つの一覧（セッション・候補・宣言）の**表示開始位置**。
    ///
    /// **フレームをまたいで保つことが要点である。** 以前は`ListState::default()`を
    /// 毎フレーム作り直しており、offsetが毎回0へ戻るためratatuiは
    /// 「0から最小限スクロールして選択を見せる」という計算をしていた。
    /// その結果**選択行が常に窓の端へ貼り付き**、カーソルが窓の中を動かず
    /// 一覧の方が滑るという、直感に反する動きになっていた。
    /// 保てばratatuiは**選択が窓から出るときだけ**offsetを動かす。
    pub session_list_offset: usize,
    pub candidate_list_offset: usize,
    pub declared_list_offset: usize,
    pub domain: TextInput,
    pub show_tree: bool,
    pub edit_focus: EditField,
    /// [段階⑦] 承認待ち画面のタブと、**遷移の2タブが持つ状態ひとまとめ**（決定62）。
    ///
    /// **1フィールドに閉じ込めてある。** このファイルは本体1,953行で
    /// `docs/CODE-STRUCTURE-RULES.md`規則1（1,000行）を既に超えているので、
    /// 新しい画面の状態をここへ広げない（中身は`tui::transition`が持つ）。
    pub pending: crate::tui::transition::PendingState,

    // 宣言画面（`Screen::Declared`）
    /// `policy.json`から読んだ宣言の一覧（`(ドメイン, キー, 値)`の平坦な集合）。
    /// **表示のたびに読み直さない**——読み直しは`reload_declared`（画面へ入る・確定した・`r`）だけ。
    pub declared: Vec<crate::unapprove::UnapproveTarget>,
    /// 宣言のパス木。**候補画面と同じ[`ProposalTree`]を使う**——`cargo`ドメインの宣言は
    /// 実測668件あり、平坦に並べると「この下をまとめて取り消す」判断ができない
    /// （`proposal_tree`のモジュールdocが候補側で解決した問題と同じもの）。
    pub declared_tree: ProposalTree,
    /// 宣言画面で展開しているノード（候補画面の`expanded`とは別に持つ——同じ集合を共有すると
    /// 片方で開いた場所がもう片方で勝手に開く）。
    pub declared_expanded: HashSet<String>,
    pub declared_row: usize,
    /// 取り消しを予約した宣言。**`(ドメイン, キー, 値)`で持つ**——提案idと違って
    /// 一般化の度合いやaccessの巡回で振り直されないので、画面をまたいでも意味が変わらない。
    /// 編集画面の`[x]`を外す操作もここへ入れる（両画面で同じ予約集合を共有する）。
    pub unapproved: BTreeSet<crate::unapprove::UnapproveTarget>,
    /// [D-112] 宣言画面の「このマシンでの承認」の状態（未承認の宣言と、承認の予約）。
    /// 中身は`tui::declared`が持つ（このファイルへ状態を広げない、上の`pending`と同じ理由）。
    pub declared_approval: crate::tui::declared::DeclaredApprovalState,
    /// 宣言画面の付け替え（`c`・`R`）の予約。中身は`tui::declared`の子が持つ（上と同じ理由）。
    pub declared_reassign: crate::tui::declared::declared_reassign::DeclaredReassignState,
    /// `Esc`を最後に押した時刻。**2回連続で押されたか**を判定するためだけに持つ
    /// （[`is_double_esc`]）。`Esc`以外のキーが来たら捨てる。
    pub last_esc: Option<std::time::Instant>,
    /// 編集画面の`[x]`重ねに使う、**いまドメイン欄に入っている名前**の宣言のスナップショット。
    ///
    /// # なぜキャッシュするのか
    ///
    /// 候補行を描くたびに`policy.json`を読むと、100msごとの再描画でファイルI/Oが走る。
    /// 一方で常に持ち歩くと古くなる——**`declared_domain`が古いと、外して確定したつもりの行が
    /// `[x]`のまま残る**（あるいはその逆）。作り直す点は[`App::refresh_declared_overlay`]に
    /// 集約してあり、ドメイン名の打ち替え・セッションを開く・確定した後に呼ぶ。
    pub declared_domain: Option<crate::PolicyDomain>,
}

/// 宣言画面の1行。ドメインの見出し行と、その配下の宣言1件を同じ列で表す。
///
/// 木にしない（`ProposalTree`を使わない）のは、この画面が見せるのは
/// **`policy.json`に書かれている行そのもの**であり、パスの階層は選択の単位ではないためである
/// ——取り消しは1エントリ単位で、畳み込みや一括選択の対象にならない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredRow {
    /// ドメインの見出し（`commands`と最終更新を添える）。
    Domain {
        name: String,
        command: Option<String>,
        entries: usize,
    },
    /// 宣言1件。
    Entry(crate::unapprove::UnapproveTarget),
}

/// `Esc`が「1秒以内に2回」押されたか。
///
/// # なぜ純粋関数にするのか
///
/// `Instant::now()`を直接読むと、しきい値の境界（1秒を超えたら終了しない）を確かめるのに
/// テストでsleepするしかなくなる。`checked_sub`で「古い前回」を作れる形にしておけば、
/// **待たずに3ケースとも固定できる**。
pub fn is_double_esc(previous: Option<std::time::Instant>, now: std::time::Instant) -> bool {
    previous.is_some_and(|last| now.duration_since(last) <= ESC_QUIT_WINDOW)
}

/// `Esc`の2回目をどれだけ待つか。**この値の持ち主は1つ**（案内文もここを参照する）。
pub const ESC_QUIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

impl App {
    /// `require_sandbox`はCLIのルート引数から解決した値を渡す（[BUG-127](../../../../docs/bugs/BUG-127.md)）。
    /// **解決点は`main.rs`の`resolve_require_sandbox`ただ1つ**で、CLI経路もTUI経路もそこから引く。
    pub fn new(workspace_root: PathBuf, require_sandbox: harness_core::RequireSandbox) -> Self {
        let mut app = Self {
            cwd: TextInput::new(workspace_root.display().to_string()),
            workspace_root,
            require_sandbox,
            screen: Screen::Record,
            help: false,
            status: String::new(),
            modal: None,
            modal_scroll: 0,
            pass: Pass::One,
            command: TextInput::default(),
            run_domain: TextInput::default(),
            record_focus: RecordField::Command,
            run: None,
            notices: VecDeque::new(),
            handle: None,
            quit_after_run: false,
            wfp: crate::record_net::SharedNetfilter::hold(),
            collector: crate::record::SharedCollector::hold(),
            spawn_daemon: crate::record_net::SharedSpawnDaemon::hold(),
            sessions: Vec::new(),
            selected_session: 0,
            view: None,
            filter: CandidateFilter::Approvable,
            accepted: BTreeSet::new(),
            hand_changed: BTreeSet::new(),
            recursive: HashSet::new(),
            tree: ProposalTree::default(),
            expanded: HashSet::new(),
            selected_row: 0,
            session_list_offset: 0,
            candidate_list_offset: 0,
            declared_list_offset: 0,
            domain: TextInput::default(),
            show_tree: false,
            edit_focus: EditField::Proposals,
            pending: crate::tui::transition::PendingState::default(),
            declared: Vec::new(),
            declared_tree: ProposalTree::default(),
            declared_expanded: HashSet::new(),
            declared_row: 0,
            unapproved: BTreeSet::new(),
            declared_approval: Default::default(),
            declared_reassign: Default::default(),
            last_esc: None,
            declared_domain: None,
        };
        app.reload_sessions();
        app
    }

    /// 記録が**動いている**か。終わった記録の`RunState`は結果を見せるために残るので、
    /// 「`run`が`Some`＝実行中」ではない（キーの案内・終了可否・再実行の可否がこれで決まる）。
    pub fn is_running(&self) -> bool {
        self.run.as_ref().is_some_and(|run| !run.finished)
    }

    /// 終わった記録の結果を表示中か（記録画面に結果が残っている状態）。
    pub fn has_finished_run(&self) -> bool {
        self.run.as_ref().is_some_and(|run| run.finished)
    }

    /// 終了してよいか。実行中に終了要求を受けた場合は**撤収が終わるまで真にならない**
    /// ——ここで抜けると収集器の撤収とマニフェストの確定を飛ばすことになる。
    pub fn should_exit(&self) -> bool {
        self.quit_after_run && !self.is_running()
    }

    pub fn attach_handle(&mut self, handle: RunHandle) {
        self.handle = Some(handle);
    }

    /// workerから届いた分を引き取る（イベントループが毎フレーム呼ぶ）。
    pub fn drain_worker(&mut self) {
        // 付与フェーズの進捗は**イベントではなく進捗セルから**引く。
        // `preflight`はイベントを流せない位置（`select_tier`の中の同期区間）で回っており、
        // `PassthroughGranted`が届くのは全件終わってからなので、これを読まないと
        // 「ACE付与 0/668」が最後まで0のまま張り付く（`passthrough_progress`のdoc）。
        //
        // **どのセルを読むかは`RunState`が持つ**（`RunState::progress`のdoc、BUG-138）。
        // `run`が無ければどのみち何もしないので、先に`run`を取り出してから読む。
        if let Some(run) = self.run.as_mut() {
            use harness_sandbox::tier2a::win_appcontainer::passthrough_progress::Phase;
            if let Some(progress) = run.progress.snapshot() {
                // **撤収の`PhaseWork`が立っている間はこのセルで上書きしない**——剥がしている
                // 最中に付与の件数が出る。撤収はこのセルを使わない（`SessionGrants::release`が
                // 直接`PhaseWork::revocations`を進める）ので、立っているかどうかで判別する。
                //
                // どのフェーズかは**セルが自分で名乗る**。以前は「内訳を出すか」から付与かを
                // 推測していたが、フェーズが3つ（付与・撤収・自己検証）になった時点で
                // その推測は成立しない（`Phase`のdoc、B-32）。
                // **自己検証だけは撤収中でもゲージを取る。** 撤収の最後（プロファイルを
                // 削除する直前）に走り、付与件数ぶんのDACLを読むので、ここを譲らないと
                // 「撤収 N/N」で止まったまま数十秒待たされる（B-23(a)）。
                let revoking = run.work.as_ref().is_some_and(|w| w.label == "撤収");
                if !revoking || progress.phase == Phase::Audit {
                    let expected: fn(usize) -> PhaseWork = match progress.phase {
                        Phase::Grant => PhaseWork::grants,
                        Phase::Audit => PhaseWork::audit,
                    };
                    // フェーズが替わったら作り直す（付与のゲージに検証の件数を流し込まない）。
                    let stale = run
                        .work
                        .as_ref()
                        .is_none_or(|w| w.label != expected(0).label);
                    if stale {
                        run.work = Some(expected(progress.total));
                    }
                    let work = run.work.as_mut().expect("just set above");
                    work.total = progress.total;
                    work.done = progress.done;
                    work.written = progress.granted;
                    work.skipped = progress.already;
                }
            }
        }
        let Some(messages) = self.handle.as_ref().map(|h| h.poll()) else {
            return;
        };
        for message in messages {
            self.on_worker(message);
        }
    }

    /// TUIが預かったこのプロセスの標準エラー出力を1行受け取る。
    ///
    /// **捨てない。** ライブラリ側の警告（D-44の「昇格ヘルパーの配置がユーザー書込可」等）は、
    /// 端末へ直接書かれると画面が壊れるので預かっているだけで、内容は判断材料そのものである。
    /// 記録中は進行ログへ、待機中は[`App::notices`]へ入れて記録画面に出す。
    pub fn note_external(&mut self, line: String) {
        self.notice(format!("[stderr] {line}"));
    }

    /// 待機中に出す1行（記録中なら進行ログへ流す）。
    pub fn notice(&mut self, line: String) {
        match self.run.as_mut() {
            Some(run) => run.log_line(line),
            None => {
                self.notices.push_back(line);
                while self.notices.len() > MAX_LINES {
                    self.notices.pop_front();
                }
            }
        }
    }

    /// **起動時にWFPの出口強制daemonを立てておく**（起動時前倒し）。
    ///
    /// # なぜ起動時なのか（実測が根拠）
    ///
    /// 遅延起動だと、UACの要求が**長い準備の後**に来る。2026-08-09の実測では、
    /// workspace外ルート668件のドメイン（`cargo`）でパス2を走らせたとき、UACが出るのは
    /// **約140秒の無音の後**だった。そこで見逃されて拒否になり、記録が丸ごと失敗した
    /// （`error_kind: "no_wfp"`／`elevation was declined or failed`）。
    /// 起動直後なら、ユーザーは必ず画面を見ている。
    ///
    /// # 失敗しても止めない
    ///
    /// 起こせなくても記録は使える（必要になった時点で`apply`が起こす。UACはそのとき出る）。
    /// ただし**理由は必ず残す**——黙って諦めると、後から出るUACの説明が付かなくなる（B-10）。
    pub fn prewarm_netfilterd(&mut self) {
        match self.wfp.standby() {
            Ok(true) => {
                self.notice(
                    "WFPの出口強制daemon（harness-netfilterd）を常駐させました。\
                     このセッション中の記録・承認・パス2では、もうUACは出ません。"
                        .to_string(),
                );
                self.status =
                    "起動時の昇格が完了しました（以後このセッションではUACは出ません）".to_string();
            }
            // 起動直後にここへ来ることは無いが、来たなら黙っていてよい（何も変わっていない）。
            Ok(false) => {}
            Err(e) => {
                self.notice(format!(
                    "WFPの出口強制daemonを起動時に立てられませんでした（{e}）。\
                     記録はこのまま使えますが、**パス2を実行したときにUACが出ます**\
                     ——そのときは準備が終わったあとに出るので、見逃さないでください。"
                ));
                self.status =
                    "起動時の昇格は行われませんでした（パス2の実行時にUACが出ます）".to_string();
            }
        }
    }

    /// 停止を要求する。**効き方は段階で違う**（[`RunPhase`]）。
    pub fn request_stop(&mut self) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        if let Some(reason) = run.phase.why_stop_does_nothing() {
            self.status = reason.to_string();
            return;
        }
        run.stop_requested = true;
        self.status = if run.phase.stop_takes_effect_now() {
            "停止を要求しました（コマンドを打ち切ります）".to_string()
        } else {
            "停止を予約しました（コマンドが始まった直後に打ち切ります）".to_string()
        };
        if let Some(handle) = self.handle.as_ref() {
            handle.request_stop();
        }
    }

    // --- workerイベント ------------------------------------------------------

    pub fn on_worker(&mut self, message: WorkerMsg) {
        match message {
            WorkerMsg::Pass1(event) => self.on_pass1_event(event),
            WorkerMsg::Pass1Done(result) => self.on_pass1_done(*result),
            WorkerMsg::Pass2(event) => self.on_pass2_event(event),
            WorkerMsg::Pass2Done(result) => self.on_pass2_done(*result),
        }
    }

    fn on_pass1_event(&mut self, event: RecordEvent) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        match event {
            RecordEvent::CollectorStarted {
                etw_available,
                reused,
            } => {
                // 文言は実行側（`record`）が1つだけ持つ（規則5）。**再利用の有無を出すのが要点**
                // ——UACが出なかったことを「収集器が動いていない」と読み違えられると、
                // この記録の意味が正反対になる（B-32）。
                run.log_line(crate::record::collector_started_line(etw_available, reused));
            }
            RecordEvent::CollectorUnavailable(reason) => {
                run.log_line(format!("収集器を起動できませんでした: {reason}"));
            }
            RecordEvent::WarmingUp(duration) => {
                run.enter_phase(RunPhase::WarmingUp, Some(duration));
                run.log_line(format!(
                    "ETWの配送が始まるのを待っています（{}ms）",
                    duration.as_millis()
                ));
            }
            RecordEvent::ChildStarted => {
                run.enter_phase(RunPhase::Running, None);
                run.log_line("コマンドを開始しました");
            }
            RecordEvent::StartupNoise(line) => {
                run.noise_line(trim_line(&line));
            }
            RecordEvent::Stdout(line) | RecordEvent::Stderr(line) => {
                run.output_line(trim_line(&line));
            }
            RecordEvent::Access(_) => run.events = run.events.saturating_add(1),
            RecordEvent::Exited(code) => {
                run.exit_code = Some(code);
                run.enter_phase(RunPhase::Draining, None);
                run.log_line(format!("コマンドが終了しました（exit {code}）"));
            }
            RecordEvent::Aborted(reason) => {
                run.aborted = Some(reason);
                run.log_line(match reason {
                    AbortReason::Canceled => "記録を中断しました（停止）",
                    AbortReason::TimedOut => "記録を中断しました（タイムアウト）",
                });
            }
            RecordEvent::Draining(duration) => {
                run.enter_phase(RunPhase::Draining, Some(duration));
                run.log_line(format!(
                    "ETWの残りのイベントが届くのを待っています（{}秒）",
                    duration.as_secs()
                ));
            }
            RecordEvent::CollectorStopped { written } => {
                run.enter_phase(RunPhase::Finishing, None);
                run.log_line(format!("収集器が撤収しました（{written}件を記録）"));
            }
            RecordEvent::Warning(message) => {
                run.log_line(format!("警告: {message}"));
                run.warnings.push(message);
            }
        }
    }

    fn on_pass2_event(&mut self, event: NetRecordEvent) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        match event {
            NetRecordEvent::ElevationExpected { max_prompts } => {
                run.log_line(format!(
                    "Tier2a（AppContainer＋WFP＋Local Proxy）。UACが最大{max_prompts}回出ます"
                ));
            }
            NetRecordEvent::GrantingPassthrough { outside_count } => {
                run.enter_phase(RunPhase::Preparing, None);
                // 撤収と**同じ型**で進捗を立てる（`PhaseWork`）。ゲージも内訳の文言も共通。
                run.work = Some(PhaseWork::grants(outside_count));
                run.log_line(if outside_count == 0 {
                    "workspace外の穴はありません（このマシンのACLは変わりません）".to_string()
                } else {
                    format!("workspace外の穴 {outside_count}件へACEを付けます")
                });
            }
            NetRecordEvent::PassthroughGranted { path, writable } => {
                // **カウンタはここでは触らない。** 進捗の正本は`passthrough_progress`の
                // セル（`drain_worker`が毎ティック読む）で、こちらのイベントは全件終わってから
                // まとめて届く。両方で数えると最後に「668/668」が「1336/668」になる（B-13）。
                run.log_line(format!(
                    "付与: {} ({})",
                    path.display(),
                    if writable { "rw" } else { "ro" }
                ));
            }
            NetRecordEvent::PassthroughDenied {
                path,
                access,
                reason,
            } => {
                // カウンタはここでは触らない（`PassthroughGranted`と同じ理由、B-13）。
                // 付与できなかった穴はパス2が途中で落ちる原因そのものなので、警告へも積む。
                let message = format!(
                    "**付与できませんでした**: {} ({access}): {reason}（この穴が要るコマンドは失敗します）",
                    path.display()
                );
                run.log_line(message.clone());
                run.warnings.push(message);
            }
            NetRecordEvent::RevokingUndeclared { total } => {
                // 取り消した宣言のぶんを剥がす（パス2開始時のreconcile）。**準備の一部として
                // 見せる**——ここは付与より前で、大きなツリーでは数十秒かかる（B-23a）。
                //
                // **付与とまったく同じ形で見せる**（`PhaseWork`）。対の操作なので、片方に
                // ゲージがあってもう片方はログ行だけ、という非対称を作らない。
                run.enter_phase(RunPhase::Preparing, None);
                run.work = Some(PhaseWork::revocations(total));
                run.log_line(format!(
                    "取り消された宣言 {total}件のACEを撤収します（宣言を外した分の後始末）"
                ));
            }
            NetRecordEvent::UndeclaredRevoked { path, done, total } => {
                // 撤収は`preflight`の外（workerスレッド）で走るのでイベントで数えられる
                // ——付与が`passthrough_progress`のセルを使うのは、あちらがイベントを流せない
                // 同期区間に居るからである。**差はここだけで、状態と描画は共通。**
                if let Some(work) = run.work.as_mut() {
                    work.done = done;
                    work.total = total;
                }
                run.log_line(format!("撤収 {done}/{total}: {}", path.display()));
            }
            NetRecordEvent::Tier2aReady => run.log_line("Tier2aへ着地しました"),
            NetRecordEvent::ExecReachability(reach) => {
                // 文言は`ExecReach`が持つ（表示側で書き写さない、規則5）。問題が無ければ
                // 何も出さない——毎回出る警告は読まれなくなる。
                if let Some(message) = reach.message() {
                    run.log_line(message.clone());
                    run.warnings.push(message);
                }
            }
            NetRecordEvent::CollectorStarted {
                etw_available,
                reused,
            } => {
                // 文言は実行側（`record`）が1つだけ持つ（規則5）。パス1と同じ文面になる
                // ——ユーザーから見て同じ機構だからである。
                run.log_line(crate::record::collector_started_line(etw_available, reused));
            }
            NetRecordEvent::WarmingUp(duration) => {
                run.enter_phase(RunPhase::WarmingUp, Some(duration));
                run.log_line(format!(
                    "ETWの配送が始まるのを待っています（{}ms）",
                    duration.as_millis()
                ));
            }
            NetRecordEvent::FsAccess(event) => {
                // 件数だけ数える（1件ずつ出すと出力に埋もれる）。**拒否は目立たせる**
                // ——パス2でのFS拒否は「なぜコマンドが失敗したか」の答えそのものである。
                run.events = run.events.saturating_add(1);
                if !event.allowed {
                    if let Some(path) = event.path.as_deref() {
                        run.log_line(format!("FS拒否: {path}"));
                    }
                }
            }
            NetRecordEvent::CollectorStopped { written } => {
                run.log_line(format!("収集器が畳みました（書込 {written}件）"));
            }
            NetRecordEvent::ProxyStarted(addr) => {
                run.log_line(format!("Local Proxy: {addr}（全許可・記録用）"))
            }
            NetRecordEvent::FakeDnsStarted(addr) => run.log_line(format!("Fake DNS: {addr}")),
            NetRecordEvent::WfpEnforced { reused } => {
                run.log_line(crate::record_net::wfp_enforced_line(reused))
            }
            NetRecordEvent::ChildStarted => {
                run.enter_phase(RunPhase::Running, None);
                run.log_line("コマンドを開始しました");
            }
            NetRecordEvent::StartupNoise(line) => {
                run.noise_line(trim_line(&line));
            }
            NetRecordEvent::Stdout(line) | NetRecordEvent::Stderr(line) => {
                run.output_line(trim_line(&line));
            }
            NetRecordEvent::NetAccess(_) => run.events = run.events.saturating_add(1),
            NetRecordEvent::Exited(code) => {
                run.exit_code = Some(code);
                run.enter_phase(RunPhase::Draining, None);
                run.log_line(format!("コマンドが終了しました（exit {code}）"));
            }
            NetRecordEvent::Aborted(reason) => {
                run.aborted = Some(reason);
                run.log_line(match reason {
                    AbortReason::Canceled => "記録を中断しました（停止）",
                    AbortReason::TimedOut => "記録を中断しました（タイムアウト）",
                });
            }
            NetRecordEvent::Draining(duration) => {
                run.enter_phase(RunPhase::Draining, Some(duration));
                run.log_line(format!(
                    "監査ログが書き切られるのを待っています（{}ms）",
                    duration.as_millis()
                ));
            }
            NetRecordEvent::TearingDown(what) => {
                run.enter_phase(RunPhase::Finishing, None);
                run.log_line(format!("撤収: {what}"));
            }
            NetRecordEvent::Warning(message) => {
                run.log_line(format!("警告: {message}"));
                run.warnings.push(message);
            }
        }
    }

    fn on_pass1_done(&mut self, result: Result<RecordOutcome, crate::record::RecordError>) {
        // **`run`は捨てない。** 捨てるとコマンドの出力も進行ログも消え、ユーザーは
        // 結果を一度も読めないまま次の操作へ進むことになる。
        if let Some(run) = self.run.as_mut() {
            run.finish();
            record_failure_in_warnings(
                run,
                result
                    .as_ref()
                    .err()
                    .map(|e| crate::session_dir::failure_note_text(e.kind(), e)),
            );
        }
        if let Some(handle) = self.handle.as_mut() {
            handle.join();
        }
        self.handle = None;
        match result {
            Ok(outcome) => {
                self.finish_and_suggest(&outcome.session_id, outcome.exit_code);
            }
            Err(e) => {
                self.status = format!("記録できませんでした: {e}");
                self.screen = Screen::Record;
            }
        }
    }

    fn on_pass2_done(
        &mut self,
        result: Result<crate::record_net::RecordNetOutcome, crate::record_net::RecordNetError>,
    ) {
        if let Some(run) = self.run.as_mut() {
            run.finish();
            record_failure_in_warnings(
                run,
                result
                    .as_ref()
                    .err()
                    .map(|e| crate::session_dir::failure_note_text(e.kind(), e)),
            );
            // **FSの拒否欄を結果として残す。** 文言は実行側（`record_net`）が1つだけ持つ
            // ——「ネットワークは全許可」という非対称もそこに書いてあり、表示側で書き写すと
            // 片方だけが更新される（規則5・B-05）。
            if let Ok(outcome) = result.as_ref() {
                for line in crate::record_net::render_fs_denials(
                    &outcome.fs_aggregate,
                    outcome.collector_started,
                    outcome.etw_available,
                )
                .lines()
                {
                    run.log_line(line.to_string());
                }
            }
        }
        if let Some(handle) = self.handle.as_mut() {
            handle.join();
        }
        self.handle = None;
        match result {
            Ok(outcome) => {
                self.finish_and_suggest(&outcome.session_id, outcome.exit_code);
            }
            Err(e) => {
                self.status = format!("記録できませんでした: {e}");
                self.screen = Screen::Record;
            }
        }
    }

    /// 記録が終わったら、**結果を出したまま**次にやることを案内する（決定24のガイドは
    /// 「提案」であって、画面を勝手に動かすことではない）。
    ///
    /// # なぜ編集画面へ自動で移らないのか
    ///
    /// 移ると**コマンドの実行結果を一度も読めない**。パス2は「そのコマンドがどのドメインへ
    /// 出たか」を見る道具で、コマンド自身が成功したか（`exit`・標準出力）は候補を読む前提に
    /// なる情報である。それを見せずに候補一覧へ飛ばすのは、判断材料を隠して判断を求めること
    /// になる。実際にユーザーから「実行結果が見られない」「勝手に入るのは良くない仕様」と
    /// 指摘された。
    ///
    /// 候補は**裏で開いておく**ので、`F2`/`Ctrl+N`を押した瞬間に読み込み無しで出る。
    /// 「進める準備は済ませるが、進むかどうかは操作した人が決める」形にしてある。
    fn finish_and_suggest(&mut self, session_id: &str, exit_code: Option<i32>) {
        self.reload_sessions();
        if let Some(index) = self
            .sessions
            .iter()
            .position(|s| s.manifest.id == session_id)
        {
            self.selected_session = index;
        }
        // 画面は動かさないが、開く準備だけ済ませておく。
        self.open_selected_session();
        self.edit_focus = EditField::Proposals;
        let candidates = self.view.as_ref().map(|v| v.proposals.len()).unwrap_or(0);
        let head = match exit_code {
            Some(0) | None => format!("記録しました（{session_id}）"),
            Some(code) => format!(
                "記録しました（{session_id}）。**コマンドは exit {code} で終了しています**\
                 ——候補は不完全かもしれません"
            ),
        };
        self.status = format!("{head}。候補{candidates}件。F2 / Ctrl+N で編集画面へ");
    }

    // --- キー入力 ------------------------------------------------------------

    /// **1フレーム描いて初めて分かったことを状態へ書き戻す**（[`crate::tui::DrawFeedback`]）。
    ///
    /// 描画時にしか決まらない値が2つある。さかのぼりの上限（折り返し後の行数は枠の幅に依存）と、
    /// 一覧の表示開始位置（ratatuiが「選択を見せる」ために動かした結果）である。
    /// **どちらも書き戻さないと壊れる**——前者を怠ると先頭で空回りし（BUG-076）、
    /// 後者を怠るとカーソルが窓の中を動かず一覧の方が滑る。
    pub fn apply_draw_feedback(&mut self, feedback: crate::tui::DrawFeedback) {
        self.clamp_scroll(feedback.scroll);
        if let Some(offset) = feedback.session_list_offset {
            self.session_list_offset = offset;
        }
        if let Some(offset) = feedback.candidate_list_offset {
            self.candidate_list_offset = offset;
        }
        if let Some(offset) = feedback.declared_list_offset {
            self.declared_list_offset = offset;
        }
    }

    /// 直近の描画で判明した上限まで各枠のさかのぼり位置を切り詰める。
    ///
    /// 上限は**折り返し後の行数**なので枠の幅に依存し、描画してみるまで分からない。
    /// これを怠ると、先頭まで遡った後もホイールを回した分だけ内部の値が伸び続け、
    /// 下へ戻すときに同じ回数だけ空回りする（BUG-076と同型）。
    pub fn clamp_scroll(&mut self, limits: crate::tui::record_screen::ScrollLimits) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        run.log_scroll.clamp(limits.log);
        run.output_scroll.clamp(limits.output);
        run.noise_scroll.clamp(limits.noise);
    }

    /// ホイールでポインタの下の枠をさかのぼる／戻す。
    ///
    /// 記録画面の3枠だけが対象で、他の画面や枠の外では**何もしない**——「反応しない」ことは
    /// 「壊れている」ではなく「そこはスクロールする対象ではない」であり、外した位置で
    /// 別の枠が動くほうが混乱する。
    ///
    /// 端末サイズを引数で受けるのは、状態に持ち越すとリサイズ直後に古い矩形で当たり判定を
    /// してしまうため（呼び出し側がその場で聞く）。
    pub fn on_scroll(&mut self, size: ratatui::layout::Size, column: u16, row: u16, up: bool) {
        use crate::tui::record_screen::{scroll_target, ScrollPane};

        if self.screen != Screen::Record {
            return;
        }
        let area = ratatui::layout::Rect::new(0, 0, size.width, size.height);
        let Some(pane) = scroll_target(area, self, column, row) else {
            return;
        };
        let Some(run) = self.run.as_mut() else {
            return;
        };
        let scroll = match pane {
            ScrollPane::Log => &mut run.log_scroll,
            ScrollPane::Output => &mut run.output_scroll,
            ScrollPane::Noise => &mut run.noise_scroll,
        };
        // 送り量は`harness_term::scrollback`が持つ（会話TUIと共通）。
        scroll.wheel(up);
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }

        // 終了要求。実行中なら**撤収まで待つ**（ここで抜けるとマニフェストが`Running`のまま残る）。
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            return self.request_quit();
        }
        // 画面切替の予備のキー。**F1/F2は端末に届かないことがある**——VS Codeの統合ターミナルは
        // F1をコマンドパレットに奪う。入力欄に文字が入ってしまわないよう修飾キー付きにする。
        // **`Esc`の連続判定は他のどのキーよりも先に捨てる。** 「連続で2回」を文字どおりにする
        // ——間に別のキーが挟まっても生き残る作りにすると、無関係な操作のあとの`Esc`1回で
        // 突然終了する（ドラッグ選択のアンカーを「明らかなキーだけ」でリセットして踏んだのと
        // 同型の穴）。ここで捨てて、`Esc`だった場合だけ後段で積み直す。
        if key.code != KeyCode::Esc {
            self.last_esc = None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('n') {
            self.screen = self.next_screen();
            self.on_enter_screen();
            return None;
        }

        if self.modal.is_some() {
            return self.on_modal_key(key);
        }
        if self.help {
            self.help = false;
            return None;
        }

        // **`Esc`を1秒以内に2回でプログラムを終了する。** 画面が3つになり`Esc`も`Ctrl+N`も
        // 画面遷移に使われるため、終了の口をここに置く。**判定はこの1箇所だけ**——画面ごとに
        // 書くと、画面を足した人が写し忘れる。
        //
        // モーダル・ヘルプの**後**に置いてある（上の早期returnを通っている）ので、
        // ダイアログを閉じる`Esc`の既存の意味は変わらない。
        // **記録中は数えない。** 記録中の`Esc`は「停止」で、止めたいときは連打されやすいキーである
        // ——そこで終了に転ぶと、止めたつもりがプログラムごと終わる。既存のテストが
        // 「止めたつもりが画面だけ変わる、が一番困る」と書いている判断の延長で、こちらの方が
        // 困る。記録中の終了は従来どおり`Ctrl+C`/`Ctrl+Q`（撤収を待つ経路）を使う。
        if key.code == KeyCode::Esc && !self.is_running() {
            let now = std::time::Instant::now();
            if is_double_esc(self.last_esc, now) {
                self.last_esc = None;
                // 終了は既存の経路へ合流させる（2つ目の終了経路を作らない）。
                return self.request_quit();
            }
            self.last_esc = Some(now);
            // 1回目はここで止めず、画面ごとの既存の意味（記録画面へ戻る等）へ流す。
        }

        // 画面は`F1`→`F2`→`F3`の**連番**で、ヘルプは`F4`である（決定62）。
        //
        // # なぜヘルプを`?`にしなかったのか（決定62の手段からの変更）
        //
        // 決定62は「ヘルプをF番号から外す（`F3`→`?`）」と書いたが、**記録画面は文字キーを
        // 全部入力欄が食う**（`on_record_key`の末尾が`edit_text`へ流す）。`?`を大域キーにすると
        // 記録したいコマンドに`?`が打てなくなり、**記録画面からヘルプへ行く口も無くなる**。
        // 決定62の目的（画面のF番号が連番になること）は`F4`でも達成されるので、
        // 手段だけを変えてある。
        match key.code {
            KeyCode::F(1) => {
                self.screen = Screen::Record;
                return None;
            }
            // **同じ画面に居るときは、タブを巡回する。**
            //
            // # なぜ`Tab`キーにしなかったのか（決定62の手段からの変更）
            //
            // 決定62の図は「Tabで切替」と書いているが、**承認待ち画面は既に`Tab`を
            // 項目移動に使っている**（セッション一覧 ⇄ 候補 ⇄ ドメイン欄）。しかも
            // ドメイン欄は文字入力なので、**`Tab`はそこから出る唯一のキー**である。
            // 奪うと入力欄に入ったまま出られなくなる。`F2`の連打なら文字入力と衝突せず、
            // タブの見出しが常に画面に出ているので見つけられる。
            KeyCode::F(2) => {
                if self.screen == Screen::Edit {
                    self.cycle_pending_tab(false);
                } else {
                    self.screen = Screen::Edit;
                    self.on_enter_screen();
                }
                return None;
            }
            KeyCode::F(3) => {
                self.screen = Screen::Declared;
                self.on_enter_screen();
                return None;
            }
            KeyCode::F(4) => {
                self.help = true;
                return None;
            }
            _ => {}
        }

        match self.screen {
            Screen::Record => self.on_record_key(key),
            // タブによって「何を承認する画面か」が変わる（決定62）。
            Screen::Edit if self.pending.tab.0.is_transition() => self.on_transition_key(key),
            Screen::Edit => self.on_edit_key(key),
            Screen::Declared => self.on_declared_key(key),
        }
    }

    /// `Ctrl+N`の巡回順。
    ///
    /// **F1〜F3だけでは足りない**——VS Codeの統合ターミナルはF1をコマンドパレットに奪うので、
    /// 修飾キー付きの予備がどの画面へも届かないと、その画面は実環境で開けないことがある
    /// （この予備キーが在る理由そのもの）。画面を足したらここにも足す。
    fn next_screen(&self) -> Screen {
        match self.screen {
            Screen::Record => Screen::Edit,
            Screen::Edit => Screen::Declared,
            Screen::Declared => Screen::Record,
        }
    }

    /// 画面へ入ったときの読み込み。**入口を1つにする**ので、F-キーと`Ctrl+N`のどちらで来ても
    /// 同じ準備が走る（片方だけ準備を書くと、もう片方から入ったとき空の画面が出る）。
    fn on_enter_screen(&mut self) {
        match self.screen {
            // 遷移のタブに居るなら、そちらを読み直す（`F2`は3つのタブを持つ。決定62）。
            Screen::Edit if self.pending.tab.0.is_transition() => self.reload_transitions(),
            Screen::Edit => {
                // **画面へ入るたびにセッション一覧を読み直す**（D-63で`r`＝読み直しを廃止した）。
                // 自分で記録したものは`finish_and_suggest`が拾うが、CLIや別プロセスが作った
                // 記録はそれでは現れない。「画面を戻って入り直せば読み直される」を本当にする。
                //
                // **開いている候補は作り直さない。** ここで`open_selected_session`まで走らせると、
                // 選択と手で変えたaccessが黙って消える（かつての`r`はそれを明示的に警告していた）。
                // 一覧だけ更新し、中身は`view`が無いときだけ開く。
                self.reload_sessions();
                if self.view.is_none() {
                    self.open_selected_session();
                }
                // 宣言画面で取り消した直後にこちらへ来ることがあるので、重ねを作り直す。
                self.refresh_declared_overlay();
            }
            Screen::Declared => self.reload_declared(),
            Screen::Record => {}
        }
    }

    /// 終了時の撤収を始める。**付与とまったく同じゲージ**（[`PhaseWork`]）で見せるため、
    /// 記録が無ければ表示用の`RunState`をここで作る。
    ///
    /// 撤収はイベントループを抜けた後に走るので、ここから先は`on_key`も`drain_worker`も
    /// 呼ばれない——画面は[`Self::on_teardown_progress`]が更新する。
    pub fn begin_teardown(&mut self) {
        // **ゲージがある画面へ移す。** 進捗は記録画面の枠が描くので、宣言画面や編集画面のまま
        // 撤収すると「何も出ないまま数十秒固まる」ことになる（付与と同じ部品を使う以上、
        // その部品が在る画面に居る必要がある）。
        self.screen = Screen::Record;
        self.modal = None;
        self.help = false;
        let run = self.run.get_or_insert_with(|| RunState::new(Pass::Two));
        run.finished = false;
        run.enter_phase(RunPhase::Finishing, None);
        // 件数はまだ分からない（最初の進捗で入る）。0件のままなら`phase_progress`は
        // 経過時間側へ落ちるので、ゲージが出ないだけで壊れない。
        run.work = Some(PhaseWork::revocations(0));
        run.log_line("終了します——AppContainerプロファイルとACEを撤収しています");
        self.status = "撤収しています（このウィンドウは撤収が終わると閉じます）".to_string();
    }

    /// 撤収1件ぶんの進捗。**ゲージは付与と共通**なので、更新するのは`PhaseWork`だけ。
    pub fn on_teardown_progress(&mut self, done: usize, total: usize, path: &std::path::Path) {
        let Some(run) = self.run.as_mut() else {
            return;
        };
        // **ラベルを撤収へ戻す。** 直前の1件で自己検証（BUG-101）のゲージが立っている場合が
        // あり、そのまま件数だけ入れると「自己検証 3/768」と出る——数は合っているのに
        // 何をしているかが嘘になる（B-32）。
        if run.work.as_ref().is_none_or(|w| w.label != "撤収") {
            run.work = Some(PhaseWork::revocations(total));
        }
        let work = run.work.as_mut().expect("just set above");
        work.done = done;
        work.total = total;
        // **1件ごとの行はログ欄へ入れる**（画面の中の枠なので流れても押し流されない）。
        // 端末へ`eprintln!`すると、TUIを閉じた後に全件が滝になって出る。
        run.log_line(format!("撤収 {done}/{total}: {}", path.display()));
    }

    /// 撤収が終わった。
    pub fn finish_teardown(&mut self, revoked: usize) {
        if let Some(run) = self.run.as_mut() {
            run.log_line(format!("撤収しました（{revoked}件）"));
        }
        self.status = format!("撤収しました（{revoked}件）。終了します");
    }

    /// この値が**もう宣言されている**なら、それを取り消すための対象を返す（空なら未宣言）。
    ///
    /// # なぜ宣言側のキーで作るのか
    ///
    /// 候補が`fs.read`でも宣言は`fs.read_exec`であり得る（ETWは読取と実行を区別しない）。
    /// 外したときに消すべきは**`policy.json`に書かれている行**なので、候補のキーではなく
    /// 宣言側のキーで対象を作らなければならない——候補のキーで作ると、存在しない行を
    /// 消そうとして「無かった」になり、`[x]`が外れないまま確定が通る。
    pub fn declared_targets_for(&self, value: &str) -> Vec<crate::unapprove::UnapproveTarget> {
        let Some(domain) = self.declared_domain.as_ref() else {
            return Vec::new();
        };
        domain
            .declared_keys_for_value(value)
            .into_iter()
            .map(|key| crate::unapprove::UnapproveTarget {
                domain: domain.name.clone(),
                key,
                value: value.to_string(),
            })
            .collect()
    }

    /// 候補1件が「確定後に許可されている状態か」＝チェックが入っているか。
    ///
    /// 承認予定（`accepted`）だけでなく**既に宣言されているもの**も入る。同じ場所へ二重に
    /// チェックを付けさせないためで、これが無いと承認済みの実行ファイルが毎回未選択で現れる。
    pub fn proposal_is_on(&self, proposal: &RuleProposal) -> bool {
        if self.accepted.contains(&proposal.id) {
            return true;
        }
        // 宣言が複数あるとき（`read`と`read_exec`など）は、**1つでも残るなら許可されている**。
        self.declared_targets_for(&proposal.value)
            .iter()
            .any(|target| !self.unapproved.contains(target))
    }

    /// 候補一覧へ重ねる宣言（[`Self::declared_domain`]）を、いまのドメイン名で作り直す。
    ///
    /// 読めなかった場合は`None`にする。**「宣言が無い」と「読めなかった」を同じ表示にしない**
    /// ため、読めなかったことは`status`へ出す（D-43）。
    pub fn refresh_declared_overlay(&mut self) {
        let name = self.domain.text().trim().to_string();
        if name.is_empty() {
            self.declared_domain = None;
            return;
        }
        match crate::policy_file::load(&self.workspace_root) {
            Ok(file) => self.declared_domain = file.domain(&name).cloned(),
            Err(e) => {
                self.declared_domain = None;
                self.status =
                    format!("policy.jsonを読めませんでした（宣言済みの重ねは出ません）: {e}");
            }
        }
    }

    fn request_quit(&mut self) -> Option<Action> {
        if self.is_running() {
            self.quit_after_run = true;
            self.request_stop();
            self.status =
                "終了します——記録の撤収（収集器・ACE・プロファイル）が終わるまで待っています"
                    .to_string();
            return None;
        }
        Some(Action::Quit)
    }

    fn on_modal_key(&mut self, key: KeyEvent) -> Option<Action> {
        let kind = self.modal.as_ref().map(|m| m.confirm);
        let confirm = kind.is_some_and(Confirm::asks);
        // 差分が長いと画面に収まらない。**最後まで読めないと確認にならない**ので送れるようにする。
        let last = self
            .modal
            .as_ref()
            .map(|m| m.lines.len().saturating_sub(1) as u16)
            .unwrap_or(0);
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') if confirm => {
                self.modal = None;
                self.modal_scroll = 0;
                // **何を書くのかはモーダルが持っている**（開いた画面を推測しない）。
                match kind {
                    Some(Confirm::Approval) => self.commit_approval(),
                    Some(Confirm::DeclaredChanges) => self.commit_declared_changes(),
                    Some(Confirm::Transition) => self.commit_transition(),
                    Some(Confirm::ReadOnly) | None => {}
                }
                None
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.modal = None;
                self.modal_scroll = 0;
                if confirm {
                    self.status = "中止しました。何も書いていません".to_string();
                }
                None
            }
            // 読むだけのダイアログはEnterで閉じる。**書き込みの確認では何も起きない**
            // ——「Enterを押したら消えた。書かれたのか？」を作らないため、y か n/Esc を選ばせる。
            KeyCode::Enter if !confirm => {
                self.modal = None;
                self.modal_scroll = 0;
                None
            }
            KeyCode::Down => {
                self.modal_scroll = (self.modal_scroll + 1).min(last);
                None
            }
            KeyCode::Up => {
                self.modal_scroll = self.modal_scroll.saturating_sub(1);
                None
            }
            KeyCode::PageDown => {
                self.modal_scroll = (self.modal_scroll + 10).min(last);
                None
            }
            KeyCode::PageUp => {
                self.modal_scroll = self.modal_scroll.saturating_sub(10);
                None
            }
            KeyCode::Home => {
                self.modal_scroll = 0;
                None
            }
            KeyCode::End => {
                self.modal_scroll = last;
                None
            }
            _ => None,
        }
    }

    fn on_record_key(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            // 記録中は停止が優先。そうでなければ画面切替に使う——**F1/F2は端末に届かないことが
            // ある**（VS Codeの統合ターミナルはF1をコマンドパレットに奪う）のに対し、Escは
            // 必ず届く。ここで何も割り当てていない状態を「行き来できない」にしない。
            KeyCode::Esc => {
                if self.is_running() {
                    self.request_stop();
                } else {
                    self.screen = Screen::Edit;
                    if self.view.is_none() {
                        self.open_selected_session();
                    }
                }
                return None;
            }
            KeyCode::Tab => {
                self.record_focus = self.next_record_field(false);
                return None;
            }
            KeyCode::BackTab => {
                self.record_focus = self.next_record_field(true);
                return None;
            }
            KeyCode::Enter => return self.start_recording(),
            _ => {}
        }

        if self.record_focus == RecordField::Pass {
            match key.code {
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') => {
                    self.pass = match self.pass {
                        Pass::One => Pass::Two,
                        Pass::Two => Pass::One,
                    };
                    if self.pass == Pass::Two && self.run_domain.is_empty() {
                        // 承認済みドメインが1件だけなら埋める（複数あるなら選ばせる）。
                        if let Ok(policy) = policy_file::load(&self.workspace_root) {
                            if let [only] = policy.domains.as_slice() {
                                self.run_domain.set_text(only.name.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
            return None;
        }

        // 実行中でも入力欄は触れる（次の記録の準備ができる）が、開始はできない。
        let input = match self.record_focus {
            RecordField::Command => &mut self.command,
            RecordField::Cwd => &mut self.cwd,
            RecordField::Domain => &mut self.run_domain,
            RecordField::Pass => unreachable!("上で返している"),
        };
        edit_text(input, key);
        None
    }

    fn next_record_field(&self, backward: bool) -> RecordField {
        let fields: &[RecordField] = if self.pass == Pass::Two {
            &[
                RecordField::Pass,
                RecordField::Command,
                RecordField::Cwd,
                RecordField::Domain,
            ]
        } else {
            &[RecordField::Pass, RecordField::Command, RecordField::Cwd]
        };
        let current = fields
            .iter()
            .position(|f| *f == self.record_focus)
            .unwrap_or(0);
        let next = if backward {
            (current + fields.len() - 1) % fields.len()
        } else {
            (current + 1) % fields.len()
        };
        fields[next]
    }

    /// 記録を開始する。**開始できない理由は必ず出す**（押しても無反応にしない、B-23(c)）。
    fn start_recording(&mut self) -> Option<Action> {
        if self.is_running() {
            self.status =
                "いま記録中です（記録は同時に1本だけ）。停止するには Esc を押してください"
                    .to_string();
            return None;
        }
        if self.command.is_empty() {
            self.status = "記録するコマンドを入力してください".to_string();
            self.record_focus = RecordField::Command;
            return None;
        }
        let command = self.command.text().trim().to_string();
        let cwd = PathBuf::from(self.cwd.text().trim());
        let cwd = harness_sandbox::session_scope::normalize_workspace_root(&cwd);

        match self.pass {
            Pass::One => {
                self.run = Some(RunState::new(Pass::One));
                self.status = String::new();
                Some(Action::StartPass1(Box::new(Pass1Request {
                    command,
                    cwd,
                    workspace_root: self.workspace_root.clone(),
                    timeout: None,
                    collector: self.collector.clone(),
                    wfp: self.wfp.clone(),
                })))
            }
            Pass::Two => {
                let name = self.run_domain.text().trim().to_string();
                // `load_domain`が`None`を返したときは、そこで理由をstatusへ書いている。
                let domain = self.load_domain(&name)?;
                self.run = Some(RunState::new(Pass::Two));
                self.status = String::new();
                Some(Action::StartPass2(Box::new(Pass2Request {
                    domain,
                    command,
                    cwd,
                    workspace_root: self.workspace_root.clone(),
                    timeout: None,
                    // D-56: TUIが持っているdaemonを貸す（`Arc`のクローン）。実行のたびに
                    // 起こし直すと、そのたびUACが出る。
                    wfp: self.wfp.clone(),
                    collector: self.collector.clone(),
                    spawn_daemon: self.spawn_daemon.clone(),
                })))
            }
        }
    }

    /// パス2で使うドメインを`policy.json`から読む。**無ければ開始しない**——承認していない
    /// ドメインで走らせても、開くべき穴が開いていない状態で失敗するだけである。
    fn load_domain(&mut self, name: &str) -> Option<PolicyDomain> {
        if name.is_empty() {
            self.status =
                "パス2にはドメイン名が要ります（編集画面で承認したときの名前）".to_string();
            self.record_focus = RecordField::Domain;
            return None;
        }
        let policy = match policy_file::load(&self.workspace_root) {
            Ok(policy) => policy,
            Err(e) => {
                self.status = e.to_string();
                return None;
            }
        };
        match policy.domain(name) {
            Some(domain) => Some(domain.clone()),
            None => {
                let known: Vec<&str> = policy.domains.iter().map(|d| d.name.as_str()).collect();
                self.status = if known.is_empty() {
                    format!(
                        "ドメイン `{name}` は {} にありません。先にパス1で記録して、\
                         編集画面で候補を承認してください",
                        policy_file::path(&self.workspace_root).display()
                    )
                } else {
                    format!(
                        "ドメイン `{name}` はありません。定義済み: {}",
                        known.join(", ")
                    )
                };
                self.record_focus = RecordField::Domain;
                None
            }
        }
    }

    // --- セッション ----------------------------------------------------------

    pub fn reload_sessions(&mut self) {
        self.sessions = session_dir::list_sessions(&self.workspace_root)
            .into_iter()
            .map(|(dir, manifest)| SessionEntry { dir, manifest })
            .collect();
        if self.selected_session >= self.sessions.len() {
            self.selected_session = self.sessions.len().saturating_sub(1);
        }
    }

    pub fn selected_session(&self) -> Option<&SessionEntry> {
        self.sessions.get(self.selected_session)
    }
}

/// 記録が失敗したとき、その理由を**⚠欄に残す**（パス1・パス2で共通）。
///
/// `self.status`（画面下の1行）にも同じ出来事が出るが、あれは次の操作で上書きされる。
/// 理由は「次に何をすればよいか」を決める材料そのものなので、**残る場所**にも要る
/// ——実行前診断が進行ログへ流れて見えなくなっていたのと同じ形である（BUG-093の(a)）。
///
/// 積むのは**末尾**。⚠欄は先頭から描くので、先に出た警告（たいてい原因そのもの）を
/// 押し出さない。文言は`session_dir`が1つだけ持つ（規則5）ので、マニフェストを読み直した
/// ときの表示と綴りが一致する。
fn record_failure_in_warnings(run: &mut RunState, note: Option<String>) {
    if let Some(note) = note {
        run.log_line(note.clone());
        run.warnings.push(note);
    }
}

/// 記録の出力・ログの行末を整える（末尾の改行だけ落とす。中身は変えない）。
fn trim_line(line: &str) -> String {
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// 単一行入力欄への編集キー（画面ごとに書き直さない）。
pub(crate) fn edit_text(input: &mut TextInput, key: KeyEvent) {
    match key.code {
        KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => input.insert(ch),
        KeyCode::Backspace => input.backspace(),
        KeyCode::Delete => input.delete(),
        KeyCode::Left => input.left(),
        KeyCode::Right => input.right(),
        KeyCode::Home => input.home(),
        KeyCode::End => input.end(),
        _ => {}
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
