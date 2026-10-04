//! 承認モーダルの状態とキー処理（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-106・D-107）。
//!
//! # なぜこの画面が要るのか
//!
//! 判定器は「この呼び出しを自動で通してよいか」を材料（[`PermissionSubject`]）で決めるが、
//! 決められないものは人に聞く。**聞くときに見せるものが、判定が実際に見たものと同じでなければ、
//! 人は自分が何を許したのか分からない。** 以前のモーダルはモデルが書いた JSON を1行出すだけで、
//! 縛ったファイルもハッシュも解決先も映していなかった。
//!
//! # ここが引き受ける3つの安全策（D-106）
//!
//! 1. **恒久承認は確認の一段を挟む**——1打鍵で消えない台帳へ書かない。次の依頼を打っている
//!    最中にモーダルが出ると、その打鍵がそのまま承認になる
//! 2. **モーダルを出した直後の入力は捨てる**（[`MODAL_INPUT_GRACE`]）——同じ理由
//! 3. **見えない文字は綴りで描く**（[`escape_for_display`]）——端末は双方向制御をそのまま
//!    解釈するので、人が見た並びと実際に渡る並びが違うものを承認させられる
//!
//! 描画そのものは[`crate::ui::approval`]が持つ。ここは**色を持たない**——どの行がどういう
//! 意味かだけを[`LineStyle`]で言い、画面の都合はすべて向こう側にある（審査パネルと同じ分け方）。

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use harness_core::{
    escape_for_display, hole_accepts, DecodeOutcome, DecodedLayer, EncodedSource,
    PermissionSubject, RiskClass, RiskLevel,
};
use harness_sandbox::textdiff::{diff_hunks, DiffKind};

use super::pointer::KeyHint;
use harness_engine::approval_risk::Severity;

#[path = "approval_risk.rs"]
mod risk;
pub use risk::RiskView;

/// モーダルを出してからこの時間の入力は捨てる（D-106）。
pub const MODAL_INPUT_GRACE: Duration = Duration::from_millis(300);

/// `PageUp`/`PageDown`で動く行数（審査パネルと同じ）。
const PAGE_LINES: u16 = 10;

/// ハッシュを一覧で見せる桁数。全部出しても読み比べられない。
const HASH_DIGEST_CHARS: usize = 12;

/// モーダルの段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStage {
    /// 選ぶ段（`[y]`/`[a]`/`[n]`/`[d]`）。
    Choose,
    /// 確認の一段（何が記録されるかを見せて Enter）。
    Confirm,
}

/// 開いている枠。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalPane {
    None,
    /// 縛ったファイルの中身。
    Content,
    /// 前回の承認で残した写しとの差分。
    Diff,
}

/// 画面が返す応答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalCommand {
    /// 一度だけ許可。
    Once,
    /// 恒久的に承認（確認の一段を通った）。中身は穴にする引数の位置。
    Remember(Vec<usize>),
    /// 一度だけ拒否。
    Deny,
    /// このセッション中は拒否。
    DenySession,
}

/// 要約（D-100）の状態。作るのは`crate::approvals`で、ここは器だけを持つ。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SummaryState {
    /// 作らない構成（設定で切った・要約する中身が無い）。
    #[default]
    Off,
    /// 作っている。待ちの行に、会話の「Thinking…」と同じ回る記号・経過秒・考えた量を出す。
    Running(SummaryWait),
    /// できた。`took`は待った時間で、見出しに残す（会話の「(thought for Ns)」と同じ）。前に作った要約を
    /// 使い回したときは待っていないので`None`。
    Done {
        text: String,
        took: Option<Duration>,
    },
    /// 作れなかった。`took`は`Done`と同じ。
    Failed {
        reason: String,
        took: Option<Duration>,
    },
}

/// 要約を待っている間の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SummaryWait {
    /// 要約を起こした時刻。経過秒と、終わった後の「待った時間」はここから測る。
    pub started: Instant,
    /// これまでに受けた出力（考える過程と本文）の文字数の累計。背景の要約から途中経過として届く
    /// （`crate::approvals::BackgroundEvent::SummaryProgress`）。
    pub output_chars: usize,
}

impl SummaryWait {
    pub fn new(started: Instant) -> Self {
        Self {
            started,
            output_chars: 0,
        }
    }
}

/// 待ちの行を描くときの、回る記号の位置といまの時刻。**回る記号は`AppState::spinner_frame`を渡す**——会話の
/// 「Thinking…」の行と同じ数で回す（2つが別々に回らないように）。時刻は外から渡す（試験は時刻を作って渡す）。
#[derive(Debug, Clone, Copy)]
pub struct WaitClock {
    pub spinner_frame: usize,
    pub now: Instant,
}

/// 行の意味。色はここで決めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStyle {
    Normal,
    /// 見出し。
    Heading,
    /// 補助的な説明。
    Dim,
    /// 注意（確かめられない・恒久承認できない・写しが壊れている）。
    Warn,
    /// 外の判定モデルが危険と見たコマンド（`harness_core::RiskLevel::Danger`）。画面は赤の太字で描く。
    Danger,
    /// 差分の追加行・削除行。
    Added,
    Removed,
    /// カーソルが載っている行。
    Selected,
}

/// 描く1行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalLine {
    pub text: String,
    pub style: LineStyle,
    /// 確認の段の「毎回変わってよい引数」の候補の行なら、何番目の候補か（押すとそこへ移って`Space`。
    /// `app::pointer`）。どの行が候補かを描画の側で数え直さないよう、行を作るここで印を付ける。
    pub candidate: Option<usize>,
}

impl ApprovalLine {
    fn new(style: LineStyle, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style,
            candidate: None,
        }
    }
}

/// 解読した1段を、人に見せる行にする。段の深さだけ字下げして、どの段がどの段の中にあったかを見せる。
///
/// **`match`は網羅で書く**——解読の結果や書き方に種類を足したら、ここがビルドで落ちて文言の追随漏れが
/// 分かる（`bug-pattern-rules` B-06 の「数えなくてよくする」）。要約へ回す英語の文言
/// （`approvals.rs`の`decoded_pieces`）も同じ形で網羅している。
fn decoded_layer_lines(layer: &DecodedLayer) -> Vec<ApprovalLine> {
    let indent = "  ".repeat(layer.depth as usize);
    let place = match layer.source {
        EncodedSource::EncodedCommand | EncodedSource::EncodedArguments => "の値",
        EncodedSource::FromBase64String => "の引数",
    };
    let head = format!(
        "{indent}{}段目: {} {place}",
        layer.depth,
        layer.source.spelling()
    );
    let reason = match &layer.outcome {
        DecodeOutcome::Text { encoding, text } => {
            let mut out = vec![ApprovalLine::new(
                LineStyle::Warn,
                format!("{head}（{}として読んだ）:", encoding.name()),
            )];
            out.extend(text.lines().map(|line| {
                ApprovalLine::new(
                    LineStyle::Normal,
                    format!("{indent}    {}", escape_for_display(line)),
                )
            }));
            return out;
        }
        DecodeOutcome::MissingValue => "値が続いていない（解読するものが無い）".to_string(),
        DecodeOutcome::NotBase64 => {
            "base64 として読めない（変数や式なら、中身は実行時に決まる）".to_string()
        }
        DecodeOutcome::NotText => {
            "base64 は読めたが文字にならない（圧縮・暗号化された中身かもしれない）".to_string()
        }
        DecodeOutcome::NotLiteral => {
            "引数が文字列そのものではない（中身は実行時に決まる）".to_string()
        }
        DecodeOutcome::DepthLimit { max_depth } => {
            format!("入れ子が深すぎるので{max_depth}段で止めた（ここから先は解読していない）")
        }
        DecodeOutcome::SizeLimit { max_bytes } => {
            format!(
                "解読した中身が{max_bytes}バイトを超えたので止めた（ここから先は解読していない）"
            )
        }
        DecodeOutcome::CountLimit { max_layers } => {
            format!("符号化された箇所が多すぎるので{max_layers}個で止めた（ここから先は解読していない）")
        }
    };
    vec![ApprovalLine::new(
        LineStyle::Warn,
        format!("{head}: {reason}"),
    )]
}

/// 前回の承認で残した写し1件（差分表示用）。読めなければ理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousCopy {
    pub rel_path: String,
    pub text: Result<String, String>,
}

/// 承認待ちの1件。
#[derive(Debug, Clone)]
pub struct PermissionView {
    pub id: String,
    pub tool: String,
    pub risk: RiskClass,
    /// 判定器が見た材料（D-101）。画面はこれを描く。
    pub subject: PermissionSubject,
    /// モデルが書いた入力そのもの（材料に写らない項目を見るための最後の手段）。
    pub input: String,
    /// `tool == "edit_file"`の場合の差分（M9 からの挙動。材料は書込先パスしか運ばない）。
    pub edit_diff: Option<Vec<harness_sandbox::textdiff::DiffLine>>,
    /// 今のワークスペース（記録に何が書かれるかを確認の一段で見せる）。
    pub workspace_root: String,
    /// モーダルが立った時刻。[`MODAL_INPUT_GRACE`]の間の入力は捨てる。
    pub opened_at: Instant,
    pub stage: ApprovalStage,
    pub pane: ApprovalPane,
    pub scroll: u16,
    /// 穴にする引数（`subject`が`Program`のときだけ意味を持つ。長さは引数の個数）。
    holes: Vec<bool>,
    /// 確認の一段での選択位置（穴の候補の何番目か）。
    cursor: usize,
    /// 前回の承認で残した写し（差分用）。`None`は「まだ読んでいない」。
    pub previous: Option<Vec<PreviousCopy>>,
    pub summary: SummaryState,
    /// 要約の出どころ（プロバイダ／モデル）。**どこへ中身が出たのかを画面に残す。**
    pub summary_source: Option<String>,
    /// 危険度（`危険度: 要確認／高`の行。D-100 の追記）。判定しない材料（書込先・その他）は`None`。
    /// 開いた時点で機械の判定が入り、判定モデルを使う設定ならその結果が届いたところで置き換わる。
    pub assessment: Option<RiskView>,
}

impl PermissionView {
    pub fn new(
        id: String,
        tool: String,
        risk: RiskClass,
        subject: PermissionSubject,
        input: String,
        edit_diff: Option<Vec<harness_sandbox::textdiff::DiffLine>>,
        workspace_root: String,
    ) -> Self {
        let arg_count = match &subject {
            PermissionSubject::Program(p) => p.args.len(),
            _ => 0,
        };
        Self {
            id,
            tool,
            risk,
            subject,
            input,
            edit_diff,
            workspace_root,
            opened_at: Instant::now(),
            stage: ApprovalStage::Choose,
            pane: ApprovalPane::None,
            scroll: 0,
            holes: vec![false; arg_count],
            cursor: 0,
            previous: None,
            summary: SummaryState::Off,
            summary_source: None,
            assessment: None,
        }
    }

    /// 枠の見出しと、危険度が高いときの段階（枠の色に使う）。**要確認・判定しない材料は今までと同じ
    /// 「承認が必要です」**で、安全だとも書かない。
    pub fn title(&self) -> (&'static str, Option<RiskLevel>) {
        match self.assessment.as_ref().map(RiskView::severity) {
            Some(Severity::High) => ("危険なコマンド — 承認が必要です", Some(RiskLevel::Danger)),
            _ => ("承認が必要です", None),
        }
    }

    /// 恒久的に承認できるか。**確かめられないものを含む呼び出しは覚えない**ので、
    /// 選択肢としても出さない（押せるのに何も起きない、を作らない）。
    pub fn can_remember(&self) -> bool {
        match &self.subject {
            PermissionSubject::Command(c) => !c.unverifiable,
            PermissionSubject::Program(p) => !(p.runs_code && p.one_shot_only),
            other => other.rule_text().is_some(),
        }
    }

    /// 恒久承認が台帳に残るか（`run_program`・`run_shell`）。残らないものは
    /// 「このセッション中だけ」と書く——**「恒久」と言って消えるものを作らない**。
    pub fn remember_is_recorded(&self) -> bool {
        matches!(
            self.subject,
            PermissionSubject::Command(_) | PermissionSubject::Program(_)
        )
    }

    /// 穴にできる引数の位置（D-105）。コードを走らせる呼び出しには開けられない。
    /// 今の値が穴に当たらない引数（`-n`・空・`"`を含む等）は、開けても二度と当たらないので候補にしない。
    pub fn hole_candidates(&self) -> Vec<usize> {
        match &self.subject {
            PermissionSubject::Program(p) if !p.runs_code => (0..p.args.len())
                .filter(|&i| hole_accepts(&p.args[i]))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// 選ばれている穴の位置。
    pub fn selected_holes(&self) -> Vec<usize> {
        self.holes
            .iter()
            .enumerate()
            .filter_map(|(i, &on)| on.then_some(i))
            .collect()
    }

    /// 縛ったファイルのうち、前回の写しをまだ読んでいないものがあるか（差分表示の準備）。
    pub fn wants_previous(&self) -> bool {
        self.previous.is_none() && !self.bound_files().is_empty()
    }

    pub fn bound_files(&self) -> &[harness_core::BoundFile] {
        match &self.subject {
            PermissionSubject::Command(c) => &c.files,
            PermissionSubject::Program(p) => &p.files,
            _ => &[],
        }
    }

    fn previews(&self) -> &[harness_core::FilePreview] {
        match &self.subject {
            PermissionSubject::Command(c) => &c.previews,
            PermissionSubject::Program(p) => &p.previews,
            _ => &[],
        }
    }

    /// 差分を出せるか（前回の写しが1つでも読めている）。
    pub fn has_diff(&self) -> bool {
        self.previous
            .as_ref()
            .is_some_and(|p| p.iter().any(|c| c.text.is_ok()))
    }

    /// いまキー（とキーを押すクリック）を受けるか。開いてから[`MODAL_INPUT_GRACE`]の間は受けない（D-106: モーダルを
    /// 出した直後の打鍵は、次の依頼を打っていた手が流れ込んだものかもしれない）。**キーを捨てる判定と、ボタンに押した
    /// 色を付けるかの判定（`app::pointer`）が同じこれを通る**——押しても捨てるボタンに押した色を付けない。
    pub fn accepts_input(&self) -> bool {
        self.opened_at.elapsed() >= MODAL_INPUT_GRACE
    }

    /// キー入力。返した`Some`が応答で、`None`は「この画面の中で処理した」。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<ApprovalCommand> {
        // [BUG-212] `Ctrl`・`Alt`付きの文字キーは選択肢のキーではない（`Ctrl+Y`が`y`=一度だけ許可として効いていた）。
        if !self.accepts_input() || harness_term::is_chorded_char(&key) {
            return None;
        }
        match self.stage {
            ApprovalStage::Choose => self.on_key_choose(key),
            ApprovalStage::Confirm => self.on_key_confirm(key),
        }
    }

    fn on_key_choose(&mut self, key: KeyEvent) -> Option<ApprovalCommand> {
        match key.code {
            KeyCode::Char('y') => Some(ApprovalCommand::Once),
            KeyCode::Char('a') if self.can_remember() => {
                self.stage = ApprovalStage::Confirm;
                self.scroll = 0;
                self.cursor = 0;
                None
            }
            KeyCode::Char('n') => Some(ApprovalCommand::Deny),
            // 枠を開いているときの`Esc`は枠を閉じる。開いていなければ拒否。
            KeyCode::Esc if self.pane != ApprovalPane::None => {
                self.set_pane(ApprovalPane::None);
                None
            }
            KeyCode::Esc => Some(ApprovalCommand::Deny),
            KeyCode::Char('d') => Some(ApprovalCommand::DenySession),
            KeyCode::Char('v') => {
                self.set_pane(match self.pane {
                    ApprovalPane::Content => ApprovalPane::None,
                    _ => ApprovalPane::Content,
                });
                None
            }
            KeyCode::Char('f') if self.has_diff() => {
                self.set_pane(match self.pane {
                    ApprovalPane::Diff => ApprovalPane::None,
                    _ => ApprovalPane::Diff,
                });
                None
            }
            _ => {
                self.scroll_by(key);
                None
            }
        }
    }

    fn on_key_confirm(&mut self, key: KeyEvent) -> Option<ApprovalCommand> {
        let candidates = self.hole_candidates();
        match key.code {
            KeyCode::Enter => Some(ApprovalCommand::Remember(self.selected_holes())),
            KeyCode::Esc => {
                self.stage = ApprovalStage::Choose;
                self.scroll = 0;
                None
            }
            KeyCode::Up if !candidates.is_empty() => {
                self.cursor = self.cursor.saturating_sub(1);
                None
            }
            KeyCode::Down if !candidates.is_empty() => {
                self.cursor = (self.cursor + 1).min(candidates.len() - 1);
                None
            }
            KeyCode::Char(' ') => {
                if let Some(&arg) = candidates.get(self.cursor) {
                    self.holes[arg] = !self.holes[arg];
                }
                None
            }
            _ => {
                self.scroll_by(key);
                None
            }
        }
    }

    fn set_pane(&mut self, pane: ApprovalPane) {
        self.pane = pane;
        self.scroll = 0;
    }

    fn scroll_by(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(PAGE_LINES),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(PAGE_LINES),
            KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Home => self.scroll = 0,
            _ => {}
        }
    }

    /// 描画のあとに、実際に描けた高さで切り詰める（審査パネルと違って折り返すので、
    /// 何行になるかは端末幅が決まるまで分からない。BUG-076 と同じ形）。
    pub fn clamp_scroll(&mut self, max: u16) {
        self.scroll = self.scroll.min(max);
    }

    /// ホイール1刻み（`up`が真なら先頭の向き）。送り量はtranscriptと同じ（`harness_term::scrollback`）。
    ///
    /// **開いた直後の窓（[`MODAL_INPUT_GRACE`]）でも捨てない**——送るだけで、何も決めないから（キーとクリックは
    /// 決める操作になり得るので捨てる）。上限はここでは掛けず、描いた後に[`Self::clamp_scroll`]で切り詰める。
    pub fn wheel(&mut self, up: bool) {
        let rows = harness_term::scrollback::WHEEL_SCROLL_LINES as u16;
        self.scroll = if up {
            self.scroll.saturating_sub(rows)
        } else {
            self.scroll.saturating_add(rows)
        };
    }

    /// 本文を送れる手段（枠の下辺の「N〜M/T行」の後ろに添える）。**効く手段だけを書く**（B-32）——
    /// 確認の段で候補があるときの`↑↓`は候補を移るので、本文は送らない（[`Self::on_key`]）。
    pub fn scroll_keys(&self) -> &'static str {
        if self.stage == ApprovalStage::Confirm && !self.hole_candidates().is_empty() {
            "PgUp/PgDn・ホイールで送る"
        } else {
            "↑↓ PgUp/PgDn・ホイールで送る"
        }
    }

    /// 確認の段で選んでいる候補（穴の候補の何番目か）。
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// 画面に描く本文。`clock`は要約の待ちの行（回る記号と経過秒）にだけ使う。
    pub fn body(&self, clock: WaitClock) -> Vec<ApprovalLine> {
        match self.stage {
            ApprovalStage::Choose => self.body_choose(clock),
            ApprovalStage::Confirm => self.body_confirm(),
        }
    }

    fn body_choose(&self, clock: WaitClock) -> Vec<ApprovalLine> {
        let mut out = vec![ApprovalLine::new(
            LineStyle::Heading,
            format!("{}（{:?}）", self.tool, self.risk),
        )];
        match &self.subject {
            PermissionSubject::Command(c) => {
                out.push(ApprovalLine::new(
                    LineStyle::Normal,
                    format!("実行対象のコマンド: {}", escape_for_display(&c.line)),
                ));
                if c.unverifiable {
                    out.push(ApprovalLine::new(
                        LineStyle::Warn,
                        "この行はワークスペース内のファイルを指しているが中身を確かめられない。\
                         恒久的には承認できない。",
                    ));
                }
                out.extend(self.risk_lines(clock));
            }
            PermissionSubject::Program(p) => {
                out.push(ApprovalLine::new(
                    LineStyle::Normal,
                    format!("program: {}", escape_for_display(&p.program)),
                ));
                match &p.resolved {
                    Some(r) => out.push(ApprovalLine::new(
                        LineStyle::Dim,
                        format!("  → {}", escape_for_display(r)),
                    )),
                    None => out.push(ApprovalLine::new(
                        LineStyle::Warn,
                        "  → 解決できない（起動も失敗する）",
                    )),
                }
                // **引数は1行1要素**（D-106）。1行に並べると、どこまでが1つの引数か分からない。
                for (i, a) in p.args.iter().enumerate() {
                    out.push(ApprovalLine::new(
                        LineStyle::Normal,
                        format!("  [{i}] {}", escape_for_display(a)),
                    ));
                }
                if p.args.is_empty() {
                    out.push(ApprovalLine::new(LineStyle::Dim, "  （引数なし）"));
                }
                if p.runs_code && p.one_shot_only {
                    out.push(ApprovalLine::new(
                        LineStyle::Warn,
                        "この呼び出しはコードを走らせるが、引数を中身で縛れない\
                         （その場のコード・ディレクトリ・ワークスペース外など）。一度だけ許可できる。",
                    ));
                }
                out.extend(self.risk_lines(clock));
            }
            PermissionSubject::WritePath(path) => out.push(ApprovalLine::new(
                LineStyle::Normal,
                format!("書込先: {}", escape_for_display(path)),
            )),
            PermissionSubject::Text(t) => {
                out.push(ApprovalLine::new(LineStyle::Normal, escape_for_display(t)))
            }
        }
        out.extend(self.decoded_lines());
        out.extend(self.bound_file_lines());
        out.extend(self.summary_lines(clock));
        out.extend(self.pane_lines());
        out
    }

    /// 符号化された中身を、ハーネスが解読したもの（§4.4。[BUG-224]）。**`run_shell`の行と
    /// `run_program`の引数の両方で同じ形で出す**——出す場所が片方だけだと、同じ中身を
    /// `run_shell`に書くだけで読めない塊のまま承認させられる。
    ///
    /// 解読できなかったこと・上限で止めたことも1行として出す（黙って落とすと、見る人には
    /// 「符号化された中身は無かった」と区別がつかない）。
    fn decoded_lines(&self) -> Vec<ApprovalLine> {
        let decoded = self.decoded();
        if decoded.is_empty() {
            return Vec::new();
        }
        let mut out = vec![ApprovalLine::new(
            LineStyle::Heading,
            "符号化された中身（ハーネスが機械的に解読した。照合には使わない）",
        )];
        out.extend(decoded.iter().flat_map(decoded_layer_lines));
        out
    }

    /// 解読した段（材料の変種によらず同じ欄を見る）。
    fn decoded(&self) -> &[DecodedLayer] {
        match &self.subject {
            PermissionSubject::Command(c) => &c.decoded,
            PermissionSubject::Program(p) => &p.decoded,
            _ => &[],
        }
    }

    fn bound_file_lines(&self) -> Vec<ApprovalLine> {
        let files = self.bound_files();
        if files.is_empty() {
            return Vec::new();
        }
        let mut out = vec![ApprovalLine::new(
            LineStyle::Heading,
            "承認に縛るファイル（中身が変われば次は聞かれる）",
        )];
        for f in files {
            let listing = match f.dir_listing_sha256.is_some() {
                true => "（隣の名前一覧も）",
                false => "",
            };
            out.push(ApprovalLine::new(
                LineStyle::Normal,
                format!(
                    "  {}  sha256 {}…{listing}",
                    escape_for_display(&f.rel_path),
                    &f.sha256[..f.sha256.len().min(HASH_DIGEST_CHARS)]
                ),
            ));
        }
        out
    }

    fn summary_lines(&self, clock: WaitClock) -> Vec<ApprovalLine> {
        match &self.summary {
            SummaryState::Off => Vec::new(),
            SummaryState::Running(wait) => {
                // 会話の「Thinking…」の行と同じ形（回る記号・考えた量・経過秒。`super::wait_figures`）。
                let glyph = super::spinner_glyph(clock.spinner_frame);
                let figures = super::wait_figures(
                    wait.output_chars as u64,
                    clock.now.saturating_duration_since(wait.started),
                );
                vec![ApprovalLine::new(
                    LineStyle::Dim,
                    match &self.summary_source {
                        Some(src) => {
                            format!("{glyph} 要約を作成中… {figures}（{src}へ中身を送っている）")
                        }
                        None => format!("{glyph} 要約を作成中… {figures}"),
                    },
                )]
            }
            SummaryState::Failed { reason, took } => vec![ApprovalLine::new(
                LineStyle::Warn,
                match took {
                    Some(took) => {
                        format!("要約を作れなかった（{:.1}s）: {reason}", took.as_secs_f32())
                    }
                    None => format!("要約を作れなかった: {reason}"),
                },
            )],
            SummaryState::Done { text, took } => {
                // 出どころと待った時間を見出しの括弧に並べる（どちらも無ければ括弧ごと出さない）。
                let tags: Vec<String> = self
                    .summary_source
                    .iter()
                    .cloned()
                    .chain(took.map(|t| format!("{:.1}s", t.as_secs_f32())))
                    .collect();
                let mut out = vec![ApprovalLine::new(
                    LineStyle::Heading,
                    match tags.is_empty() {
                        true => "要約（補助。中身と差分を必ず確認すること）".to_string(),
                        false => format!(
                            "要約（補助。中身と差分を必ず確認すること）［{}］",
                            tags.join("・")
                        ),
                    },
                )];
                out.extend(text.lines().map(|l| {
                    ApprovalLine::new(LineStyle::Dim, format!("  {}", escape_for_display(l)))
                }));
                out
            }
        }
    }

    fn pane_lines(&self) -> Vec<ApprovalLine> {
        match self.pane {
            ApprovalPane::None => Vec::new(),
            ApprovalPane::Content => self.content_lines(),
            ApprovalPane::Diff => self.diff_lines(),
        }
    }

    fn content_lines(&self) -> Vec<ApprovalLine> {
        let previews = self.previews();
        if previews.is_empty() {
            return vec![ApprovalLine::new(
                LineStyle::Dim,
                "（この呼び出しに縛られた中身は無い）",
            )];
        }
        let mut out = Vec::new();
        for p in previews {
            out.push(ApprovalLine::new(
                LineStyle::Heading,
                format!("--- {} ---", escape_for_display(&p.rel_path)),
            ));
            out.extend(
                p.text
                    .lines()
                    .map(|l| ApprovalLine::new(LineStyle::Normal, escape_for_display(l))),
            );
            if p.truncated {
                out.push(ApprovalLine::new(
                    LineStyle::Warn,
                    "（上限で切った。全部は見せていない）",
                ));
            }
        }
        out
    }

    fn diff_lines(&self) -> Vec<ApprovalLine> {
        let Some(previous) = &self.previous else {
            return vec![ApprovalLine::new(
                LineStyle::Dim,
                "（写しをまだ読んでいない）",
            )];
        };
        let mut out = Vec::new();
        for copy in previous {
            out.push(ApprovalLine::new(
                LineStyle::Heading,
                format!("--- {} ---", escape_for_display(&copy.rel_path)),
            ));
            let old = match &copy.text {
                Ok(text) => text,
                Err(reason) => {
                    out.push(ApprovalLine::new(LineStyle::Warn, reason.clone()));
                    continue;
                }
            };
            let new = self
                .previews()
                .iter()
                .find(|p| p.rel_path == copy.rel_path)
                .map(|p| p.text.as_str())
                .unwrap_or("");
            let hunks = diff_hunks(old, new);
            if hunks.is_empty() {
                out.push(ApprovalLine::new(
                    LineStyle::Dim,
                    "（前回承認したときと同じ中身）",
                ));
                continue;
            }
            for hunk in hunks {
                out.push(ApprovalLine::new(LineStyle::Dim, hunk.header()));
                for line in hunk.lines {
                    let (style, prefix) = match line.kind {
                        DiffKind::Context => (LineStyle::Normal, " "),
                        DiffKind::Removed => (LineStyle::Removed, "-"),
                        DiffKind::Added => (LineStyle::Added, "+"),
                    };
                    out.push(ApprovalLine::new(
                        style,
                        format!("{prefix} {}", escape_for_display(&line.text)),
                    ));
                }
            }
        }
        out
    }

    fn body_confirm(&self) -> Vec<ApprovalLine> {
        let recorded = self.remember_is_recorded();
        let mut out = vec![ApprovalLine::new(
            LineStyle::Heading,
            match recorded {
                true => "これを台帳へ記録する（Enter で確定、Esc で戻る）",
                false => "このセッション中だけ許可する（Enter で確定、Esc で戻る）",
            },
        )];
        let holes = self.selected_holes();
        match &self.subject {
            PermissionSubject::Command(c) => {
                out.push(ApprovalLine::new(
                    LineStyle::Normal,
                    format!("  run_shell {}", escape_for_display(&c.line)),
                ));
            }
            PermissionSubject::Program(p) => {
                out.push(ApprovalLine::new(
                    LineStyle::Normal,
                    format!("  run_program {}", escape_for_display(&p.program)),
                ));
                for (i, a) in p.args.iter().enumerate() {
                    let shown = match holes.contains(&i) {
                        true => "<穴——毎回変わってよい>".to_string(),
                        false => escape_for_display(a),
                    };
                    out.push(ApprovalLine::new(
                        LineStyle::Normal,
                        format!("    [{i}] {shown}"),
                    ));
                }
            }
            other => {
                if let Some(text) = other.rule_text() {
                    out.push(ApprovalLine::new(
                        LineStyle::Normal,
                        format!("  {} {}", self.tool, escape_for_display(text)),
                    ));
                }
            }
        }
        if recorded {
            out.push(ApprovalLine::new(
                LineStyle::Dim,
                format!(
                    "  このワークスペースだけ: {}",
                    escape_for_display(&self.workspace_root)
                ),
            ));
        }
        out.extend(self.bound_file_lines());

        let candidates = self.hole_candidates();
        if !candidates.is_empty() {
            out.push(ApprovalLine::new(
                LineStyle::Heading,
                "毎回変わってよい引数を選べる（↑↓ で移動、Space で切替）",
            ));
            for (row, &arg) in candidates.iter().enumerate() {
                let mark = match self.holes[arg] {
                    true => "[x]",
                    false => "[ ]",
                };
                let style = match row == self.cursor {
                    true => LineStyle::Selected,
                    false => LineStyle::Normal,
                };
                let value = match &self.subject {
                    PermissionSubject::Program(p) => escape_for_display(&p.args[arg]),
                    _ => String::new(),
                };
                out.push(ApprovalLine {
                    candidate: Some(row),
                    ..ApprovalLine::new(style, format!("  {mark} [{arg}] {value}"))
                });
            }
        }
        out
    }

    /// 枠の中の下に固定で出すキーの案内（**1要素が1つのまとまり**で、まとまりごとに行を改める）。
    /// 各項目はクリックでそのキーを押せる（`app::pointer`。押せないのは1つのキーに決まらない案内だけ）。
    ///
    /// 決めるキーと見るキーを行で分けるのは、決める側が見る側に押し出されて切れないようにするため。
    pub fn key_hints(&self) -> Vec<Vec<KeyHint>> {
        match self.stage {
            ApprovalStage::Confirm => {
                let mut rows = vec![vec![
                    KeyHint::press("Enter 確定", KeyCode::Enter),
                    KeyHint::press("Esc 戻る", KeyCode::Esc),
                ]];
                if !self.hole_candidates().is_empty() {
                    rows.push(vec![
                        KeyHint::shown("↑↓ 移動"),
                        KeyHint::press("Space 毎回変わってよい引数にする", KeyCode::Char(' ')),
                    ]);
                }
                rows
            }
            ApprovalStage::Choose => {
                let mut decide = vec![KeyHint::press("[y] 一度だけ許可", KeyCode::Char('y'))];
                if self.can_remember() {
                    decide.push(KeyHint::press(
                        match self.remember_is_recorded() {
                            true => "[a] 恒久的に承認（台帳へ）",
                            false => "[a] このセッション中は許可",
                        },
                        KeyCode::Char('a'),
                    ));
                }
                decide.push(KeyHint::press("[n] 拒否", KeyCode::Char('n')));
                decide.push(KeyHint::press(
                    "[d] このセッション中は拒否",
                    KeyCode::Char('d'),
                ));

                let mut look = Vec::new();
                if !self.previews().is_empty() {
                    look.push(KeyHint::press("[v] 中身", KeyCode::Char('v')));
                }
                if self.has_diff() {
                    look.push(KeyHint::press("[f] 差分", KeyCode::Char('f')));
                }
                look.push(KeyHint::shown("PageUp/PageDown スクロール"));

                vec![decide, look]
            }
        }
    }
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod approval_tests;
