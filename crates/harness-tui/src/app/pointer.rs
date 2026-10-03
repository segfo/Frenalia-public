//! マウスのクリックとホイール（2026-10-02、ユーザーの依頼「ポリシーエディタで作ったUI部品はハーネス側にも入れてほしい」）。
//! **押せる場所と送れる枠は、描くときに登録する**（土台はポリシーエディタと共有する`harness_term::pointer`）。
//!
//! # 当たり判定は、描いた矩形そのもの
//!
//! 描画（`crate::ui::render`）が、transcript・入力欄の見出しのキー案内・入力欄の右の枠付きのボタン・承認ダイアログ・
//! レビューパネル・それぞれの押せる項目を**描いたその矩形で**[`Targets`]へ登録し、[`DrawFeedback`]で状態へ書き戻す
//! （[`AppState::apply_draw_feedback`]）。マウスのイベントは、直前に描いたその登録で引く。以前はホイールが
//! 座標を見ずに必ずtranscriptを送っていた（どこで回しても同じ）。当たり判定のために割り付けを写さない
//! （ポリシーエディタの[BUG-194](../../../../docs/bugs/BUG-194.md)）。
//!
//! 直前に描いた画面で引いてよいのは、イベントループ（`crate::run`）が**イベントを1つ処理するたびに描き直す**
//! からである。描き直さないのは「何も変えないイベント」（キーを離した・ポインタが動いただけ。[`Step::Unchanged`]）
//! だけで、そのとき画面も登録も変わっていない。
//!
//! # クリックは、キーを押したのと同じ処理を呼ぶ
//!
//! クリック用の処理は書かない（同じ操作を2か所に持つと、片方だけ直る）。[`Click`]はどれも次のどれかで終わる。
//!
//! - **キーを押す**（[`AppState::on_key`]）——キー案内の項目・入力欄の「送信」「中断」のボタン・承認ダイアログの
//!   ボタン・レビューパネルの案内・ペイン（`Tab`）・取り込みの印（`Enter`）・確認の段の候補（`↑↓`で移って`Space`）。
//! - **キーが呼ぶのと同じ関数を、行で呼ぶ**——レビューパネルの一覧の行（`↑↓`が呼ぶ`select_row`）。
//! - **キーが変えるのと同じ状態を、押した場所の分だけ変える**——差分のハンクの見出し（フォーカスとハンクの
//!   カーソル）と、transcriptの「さかのぼり中」の案内（`Ctrl+O`・`/clear`が呼ぶのと同じ`Scrollback::reset`）。
//!   ハンクの見出しを`↑↓`で辿らないのは、`↑↓`がカーソルの見出しを枠の一番上まで送る（`follow_hunk_cursor`）
//!   からである——押せた見出しは見えているので、送ると押した場所の下にあるものが動く。
//!
//! # 承認ダイアログ・レビューパネルが開いている間も、外に見えているtranscriptはホイールで送れる
//!
//! **ポリシーエディタと違うのはここだけ**（エディタは重ねた枠が開いている間は後ろを送らない）。会話画面は
//! 基盤フェーズM09で、承認モーダルが出ている間もホイールでtranscriptを遡れるようにした（旧`on_mouse`のdoc
//! 「過去ログの閲覧を妨げないよう」と、M09の試験`mouse_scroll_works_even_while_permission_modal_is_pending`）。
//! 許可を判断するために前の会話を読み返す必要があるので、この形を残す（2026-10-02に決めた）。以前はポインタの
//! 位置を見ずに常にtranscriptを送っていたので、重ねた枠の上で回しても後ろが動いた。いまは**ポインタが重ねた枠の
//! 上ならその枠を、外に見えているtranscriptの上ならtranscriptを送る**。クリックは後ろへ届かない（キーも重ねた側
//! だけが受ける。後ろの入力欄の`Esc=中断`を押したつもりで承認ダイアログの`Esc`＝拒否にさせない）。
//!
//! # 押せないもの（決めたこと）
//!
//! - **`x=discard-all`（レビューパネルの全破棄）はキーだけで押せる。** オーバーレイの変更を確認なしに全部捨てる
//!   一括の操作で、ポリシーエディタが「一括の操作はクリックに付けない」と決めた（`plans/POLICY-EDITOR-TOMOYO-DIG.md`
//!   決定62の「マウスで操作できるようにした」の表の3）のと同じ理由——クリックは押し間違えやすい。
//! - `↑↓`・`PageUp/PageDown`の案内は1つのキーに決まらないので押せない（行や見出しを押す、ホイールで送る）。
//!   ボタンの形にもしない（押せそうに見えるので、案内の文字のまま。`crate::ui`の`HintLook`）。
//! - 入力欄の「送信」は、入力が空白だけの間は押せない（薄く描く。送信キーも何もしない）。「中断」は止めるものが
//!   走っている間だけ出る（[`AppState::input_buttons`]）。
//! - 入力欄の中を押しても、押した桁へカーソルは移らない（ポリシーエディタと同じ）。
//!
//! # 入力欄の右のボタンは、別のボタンが居た場所へ動いた直後の300msだけ押せない
//!
//! 「中断」はユーザーの図のとおり「送信」の**右**に並ぶ（2026-10-03）。だから応答が始まると「中断」が送信の居た
//! 右端に現れて「送信」が左へずれ、応答が終わると逆に「送信」が中断の居た右端へ戻る。そのままでは、送信を
//! ダブルクリックした2回目が「中断」に当たって送ったばかりのターンを止め、中断を押した瞬間に応答が終わると
//! 「送信」に当たって書きかけの入力を送る。押した人が狙ったのは動く前のボタンである。
//!
//! そこで、描いたボタンが**前の画面で別のボタンが居た場所と重なった**ら、その時刻を覚え（[`AppState::apply_draw_feedback`]）、
//! そこから[`BUTTON_SHIFT_GRACE`]の間は入力欄の右のボタンのクリックを捨てる。長さと考え方は承認ダイアログの
//! 開いた直後の窓（D-106。現れたものへ、別のものを狙った手の入力が流れ込む）と同じ。**キーは捨てない**——
//! `Esc`や送信キーは押す場所を狙わないので、ボタンが動いても押し間違いにならない。
//!
//! # 限界
//!
//! - クリックは左ボタンを押した瞬間に効く（離したときではない。`harness_term::pointer`）。
//! - **承認ダイアログを開いてから300ms未満のクリックは、キーと同じく捨てる**（D-106。クリックはキーを押すので、
//!   `PermissionView::on_key`の窓がそのまま効く）。ホイールは捨てない——送るだけで、何も決めないから。
//! - 入力欄の右のボタンの窓は、動いた後に描いた画面で数える。動く前の画面のうちに届いたクリックは、動く前の
//!   ボタンを押す（狙ったとおり）。
//! - セッションのピッカー（`crate::picker`）は自分のループで描いて引く（同じ部品・同じ形）。

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};
use harness_term::pointer::Pointer;
use ratatui::layout::Rect;

use super::{Action, AppState, ReviewFocus};

/// 1フレームで描いた、押せる場所と送れる枠。
pub type Targets = harness_term::pointer::Targets<Click, Wheel>;

/// 入力欄の右のボタンが、別のボタンの居た場所へ動いてからクリックを捨てる長さ（モジュールdoc）。
/// 承認ダイアログを開いた直後の窓（D-106）と同じ長さにする。
pub(crate) const BUTTON_SHIFT_GRACE: Duration = super::approval::MODAL_INPUT_GRACE;

/// クリックで起こすこと。どれもキーの処理を呼ぶ（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Click {
    /// キーを押す（入力欄の見出し・承認ダイアログ・レビューパネルの案内の項目）。
    Key(KeyEvent),
    /// 入力欄の右のボタン（「送信」「中断」）。キーを押すが、ボタンが動いた直後は捨てる（モジュールdoc）。
    InputButton(KeyEvent),
    /// transcriptの「さかのぼり中」の案内。末尾へ戻る。
    ScrollToLatest,
    /// 承認ダイアログの確認の段の、`n`番目の候補（毎回変わってよい引数）の行。そこへ移って`Space`。
    Candidate(usize),
    /// レビューパネルの一覧の行を選ぶ。
    ReviewRow(usize),
    /// レビューパネルの行の取り込みの印（`[x]`/`[ ]`/`[~]`）。その行を選んで`Enter`。
    ReviewMark(usize),
    /// レビューパネルのペイン（一覧か差分）。そちらへフォーカスを移す（`Tab`）。
    ReviewPane(ReviewFocus),
    /// 差分のハンクの見出し。そのハンクを選ぶ（フォーカスも差分へ）。
    Hunk(usize),
    /// 差分のハンクの見出しの印（`[x]`/`[ ]`）。そのハンクを選んで`Enter`。
    HunkMark(usize),
}

/// ホイールで送る枠。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    /// transcript（下端からの距離。`AppState::scroll`）。
    Transcript,
    /// 承認ダイアログの本文（`PermissionView::scroll`）。
    Approval,
    /// レビューパネルの一覧（選択を1行ずつ動かす）。
    ReviewList,
    /// レビューパネルの差分ペイン（`ReviewPanelState::diff_scroll`）。
    ReviewDiff,
}

/// キー案内の1項目。`key`があれば、押すとそのキーを押したのと同じ。**文言と押すキーを1つに並べて持つ**——
/// 文言だけを持ってキーを別の表で引くと、文言を変えたときに押すキーだけが古くなる（B-05。ポリシーエディタの
/// `KeyHint`と同じ形）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHint {
    pub label: String,
    /// 押したときのキー。`None`は押せない（1つのキーに決まらない案内・一括の操作）。
    pub key: Option<KeyEvent>,
}

impl KeyHint {
    /// 押せる項目（修飾キー無しの`code`）。
    pub fn press(label: impl Into<String>, code: KeyCode) -> Self {
        Self::press_key(label, KeyEvent::new(code, KeyModifiers::NONE))
    }

    /// 押せる項目（修飾キー付き）。
    pub fn press_key(label: impl Into<String>, key: KeyEvent) -> Self {
        Self {
            label: label.into(),
            key: Some(key),
        }
    }

    /// 押せない項目。
    pub fn shown(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            key: None,
        }
    }
}

/// 入力欄の右の枠付きのボタン1つ（[`AppState::input_buttons`]。`harness_term::button::Framed`で描く）。
/// **文言・下辺に添えるキーの綴り・押すキーを1つに並べて持つ**（[`KeyHint`]と同じ理由。B-05）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputButton {
    /// 枠の中の文言（`送信`）。
    pub label: &'static str,
    /// 枠の下辺に添えるキーの綴り（`Shift+Enter`）。幅が足りないときは添えない。
    pub key_label: &'static str,
    /// 押したときのキー。`None`なら**いまは押せない**——薄く描き、押す場所を登録しない。承認ダイアログの押せない
    /// 案内（1つのキーに決まらない`PageUp/PageDown`）とは意味が違う——こちらはボタンで、キーを押しても何も起きない
    /// 間だけ押せない。
    pub key: Option<KeyEvent>,
}

/// **1フレーム描いて初めて分かること。** 描画（`crate::ui::render`）が返し、[`AppState::apply_draw_feedback`]で
/// 状態へ書き戻す。どれも**書き戻さないと壊れる**——上限を怠ると端で空回りし（BUG-076）、一覧の表示を始める位置を
/// 怠るとカーソルが窓の中を動かず一覧の方が滑り、押せる場所を怠るとマウスが前の画面の場所で当たる。
#[derive(Debug, Default, Clone)]
pub struct DrawFeedback {
    /// transcriptをさかのぼれる上限（いつも描く）。
    pub transcript: u16,
    /// 承認ダイアログの本文を送れる上限。`None`＝描いていない（触らない）。
    pub approval: Option<u16>,
    /// レビューパネル。`None`＝描いていない（承認ダイアログの下に隠れている間も含む。触らない）。
    pub review: Option<ReviewDrawn>,
    /// この描画で描いた、押せる場所と送れる枠（重なりは描いた順。後が上）。
    pub targets: Targets,
    /// この描画で入力欄の右に描いたボタン（文言と矩形。押せないものも含む）。前の画面と比べて、ボタンが別のボタンの
    /// 居た場所へ動いたかを見る（モジュールdoc）。
    pub input_buttons: Vec<(&'static str, Rect)>,
}

/// レビューパネルを描いて分かったこと。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReviewDrawn {
    /// 差分ペインを送れる上限（最後の行が枠の一番下に来る位置。[BUG-204](../../../../docs/bugs/BUG-204.md)）。
    pub diff_max: u16,
    /// 一覧の表示を始める位置（ratatuiの`List`が選択を見せるために動かした結果）。
    pub list_offset: usize,
}

/// 端末のイベント1つを渡した結果。
#[derive(Debug)]
pub enum Step {
    /// 画面に出るものは何も変わっていない（キーを離した・ポインタが動いただけ）。描き直さなくてよい。
    Unchanged,
    /// 状態へ渡した（描き直す）。呼び出し側の処理が要るときは[`Action`]が返る。
    Handled(Option<Action>),
}

impl AppState {
    /// 端末のイベント1つを状態へ渡す。**イベントループ（`crate::run`）と試験が同じこれを通る**（製品の入口）。
    ///
    /// キーは[`Self::on_key`]（押下だけ。Windowsのコンソールは押下と離上の両方を送るので、離上も渡すと
    /// 1文字が2回入る）、マウスは[`Self::on_mouse`]（左クリックとホイールだけ。`harness_term::pointer::acts`）。
    /// リサイズは何もしないが描き直す（次の描画で反映される）。
    pub fn handle_event(&mut self, event: Event) -> Step {
        match event {
            Event::Key(key) => {
                // Shift+Enter等の修飾キーが端末/ConPTY越しに実際どう届いているか
                // 切り分けるための生イベントログ（`crate::init_file_logging`のログファイル参照）。
                tracing::debug!(code = ?key.code, modifiers = ?key.modifiers, kind = ?key.kind, "raw key event");
                // `HARNESS_KEY_DEBUG=1`時は画面にもecho（Press/Release両方を観測するため
                // Pressに絞る前に呼ぶ）。無効時は`note_key_event`が即returnする。
                self.note_key_event(key);
                if key.kind != KeyEventKind::Press {
                    return Step::Unchanged;
                }
                Step::Handled(self.on_key(key))
            }
            // ポインタの移動だけのイベントは何にも当たらない（`EnableMouseCapture`は移動もすべて報告する）。
            // 描き直すと、マウスを動かしている間ずっと描き続ける。
            Event::Mouse(mouse) if !harness_term::pointer::acts(mouse.kind) => Step::Unchanged,
            Event::Mouse(mouse) => Step::Handled(self.on_mouse(mouse)),
            _ => Step::Handled(None),
        }
    }

    /// マウスのイベント（左クリックとホイール）。直前に描いた画面の登録で引く。押せる場所・送れる枠の外では
    /// **何もしない**——外した位置で別のものが動くほうが混乱する。
    pub fn on_mouse(&mut self, event: MouseEvent) -> Option<Action> {
        match self.pointer.resolve(&event)? {
            Pointer::Wheel { target, up } => {
                self.on_wheel(target, up);
                None
            }
            Pointer::Click(click) => self.on_click(click),
        }
    }

    /// ポインタの下の枠をホイール1刻み送る（`up`が真なら先頭・過去の向き）。
    pub(crate) fn on_wheel(&mut self, target: Wheel, up: bool) {
        match target {
            Wheel::Transcript => self.scroll.wheel(up),
            Wheel::Approval => {
                if let Some(pending) = self.pending_permission.as_mut() {
                    pending.wheel(up);
                }
            }
            Wheel::ReviewList => {
                if let Some(panel) = self.review_panel.as_mut() {
                    panel.wheel_list(up);
                }
            }
            Wheel::ReviewDiff => {
                if let Some(panel) = self.review_panel.as_mut() {
                    panel.wheel_diff(up);
                }
            }
        }
    }

    fn on_click(&mut self, click: Click) -> Option<Action> {
        match click {
            Click::Key(pressed) => self.on_key(pressed),
            Click::InputButton(_)
                if self
                    .input_buttons_moved_at
                    .is_some_and(|moved| moved.elapsed() < BUTTON_SHIFT_GRACE) =>
            {
                None
            }
            Click::InputButton(pressed) => self.on_key(pressed),
            Click::ScrollToLatest => {
                self.scroll.reset();
                None
            }
            Click::Candidate(row) => {
                // 確認の段の`↑↓`は候補のカーソルを1つずつ動かすだけ（`PermissionView::on_key_confirm`）。
                // 開いた直後の窓（D-106）の間は、`↑↓`も`Space`も同じく捨てられる。
                let current = self.pending_permission.as_ref()?.cursor();
                let step = if row < current {
                    KeyCode::Up
                } else {
                    KeyCode::Down
                };
                for _ in 0..row.abs_diff(current) {
                    self.on_key(plain(step));
                }
                self.on_key(plain(KeyCode::Char(' ')))
            }
            Click::ReviewRow(row) => {
                self.focus_review(ReviewFocus::List);
                self.review_panel.as_mut()?.pick_row(row);
                None
            }
            Click::ReviewMark(row) => {
                self.focus_review(ReviewFocus::List);
                self.review_panel.as_mut()?.pick_row(row);
                self.on_key(plain(KeyCode::Enter))
            }
            Click::ReviewPane(focus) => {
                self.focus_review(focus);
                None
            }
            Click::Hunk(hunk) => {
                self.review_panel.as_mut()?.pick_hunk(hunk);
                None
            }
            Click::HunkMark(hunk) => {
                self.review_panel.as_mut()?.pick_hunk(hunk);
                self.on_key(plain(KeyCode::Enter))
            }
        }
    }

    /// レビューパネルのフォーカスを`focus`へ移す（違えば`Tab`を押す。`Tab`は2つのペインを行き来するだけ）。
    fn focus_review(&mut self, focus: ReviewFocus) {
        if self.review_panel.as_ref().is_some_and(|p| p.focus != focus) {
            self.on_key(plain(KeyCode::Tab));
        }
    }

    /// 1フレーム描いて分かったことを状態へ書き戻す（[`DrawFeedback`]のdoc）。
    pub(crate) fn apply_draw_feedback(&mut self, feedback: DrawFeedback) {
        self.scroll.clamp(feedback.transcript);
        if let (Some(pending), Some(max)) = (self.pending_permission.as_mut(), feedback.approval) {
            pending.clamp_scroll(max);
        }
        if let (Some(panel), Some(drawn)) = (self.review_panel.as_mut(), feedback.review) {
            panel.clamp_diff_scroll(drawn.diff_max);
            panel.list_offset = drawn.list_offset;
        }
        self.pointer = feedback.targets;
        if buttons_took_each_others_place(&self.input_buttons_drawn, &feedback.input_buttons) {
            self.input_buttons_moved_at = Some(Instant::now());
        }
        self.input_buttons_drawn = feedback.input_buttons;
    }
}

/// 今の画面の入力欄の右のボタンのどれかが、前の画面で**別の**ボタン（文言が違うもの）が居た場所と重なったか
/// （モジュールdoc）。同じボタンが動いただけ・押せるかどうかが変わっただけ・前の画面にボタンが無かったときは偽。
fn buttons_took_each_others_place(
    before: &[(&'static str, Rect)],
    now: &[(&'static str, Rect)],
) -> bool {
    now.iter().any(|(label, rect)| {
        before
            .iter()
            .any(|(was, place)| was != label && place.intersects(*rect))
    })
}

/// 修飾キー無しのキー。
fn plain(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[cfg(test)]
#[path = "pointer_tests.rs"]
mod pointer_tests;
