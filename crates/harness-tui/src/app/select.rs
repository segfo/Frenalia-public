//! 画面の文章をマウスで選んでクリップボードへ写す（2026-10-03、ユーザー「transcriptの中の文字列（それに限らず
//! テキストエリアUIの文字）のコピーをしたい」）。部品はポリシーエディタと共有する`harness_term::select`
//! （選ぶ）と`harness_term::clipboard`（写す）。決めたことの正本は`plans/POLICY-EDITOR-TOMOYO-DIG.md`の
//! 「画面の文章をマウスで選んでコピーできるようにした」。
//!
//! # 選べる枠
//!
//! 文章を出す送れる枠の全部——transcript・承認ダイアログの本文・レビューパネルの差分（どれも
//! `harness_term::scrollable`・`scrollback`で描くので、描くときに選べる場所として登録される）。枠の名前は
//! ホイールで送るときの名前（[`Wheel`]）をそのまま使う。**承認ダイアログ・レビューパネルが開いている間も、外に
//! 見えているtranscriptは選べる**（ホイールで送れるのと同じ扱い。`app::pointer`のモジュールdoc）。
//! レビューパネルの一覧（押すと行を選ぶ）・セッションのピッカー・入力欄はマウスでは選べない。
//!
//! # 選び方と写し方
//!
//! - 文章の上で左ボタンを押してずらすと、押した文字から今の文字までを選ぶ（選んだ文字は背景を青にする）。
//!   ずらさずに離したら今までどおりのクリック（押した瞬間に効いている）。押せる行（承認ダイアログの候補・差分の
//!   ハンクの見出し）やボタンの上で押してずらしても選び始めない。差分ペインの文章を押したときは、今までどおり
//!   差分ペインへフォーカスも移る。
//! - 枠の上下の外までずらすとその向きへ送る（ホイールと同じ送り方。止めていても100msごとに送り続ける）。
//!   ドラッグ中のホイールも効く。
//! - **選んでいるときの`Ctrl+C`と右クリックは写す**（VS Codeの統合ターミナルの既定と同じ。ただし VS Code の
//!   統合ターミナルは右クリックを自分で受けて貼り付けにするので、そこでは右クリックはアプリへ届かない——
//!   `harness_term::select`の限界）。写したら選択を外し、
//!   transcriptの枠の上辺に「N文字をコピーしました」を出す。**`Ctrl+C`は終了に使わない**（2026-10-03から。`app::quit`）
//!   ——選んでいないときは何も写さず、同じ上辺に「終了は Esc を2回」を出す。重ねた枠が開いていても同じ（どの枠も
//!   `Ctrl+C`を自分の文字のキーとして受けない。BUG-212）。右クリックは今までどおり何もしない。入力欄にキーボードの選択
//!   （`Shift+矢印`・`Ctrl+A`）があるときの`Ctrl+C`と右クリックは、入力欄の選択を写す。入力欄の見出しの案内は、写せる間だけ
//!   `Ctrl-C=コピー`になる。
//! - **選んでいる間の`Esc`は選択を外すだけ**（中断も、承認ダイアログの拒否も、レビューパネルを閉じることもしない。
//!   `Esc`の二度押しにも数えない）。`Esc`はいちばん内側のものから効く（承認ダイアログ→レビューパネル→中断→二度押しで
//!   終了）。選んだ範囲はそのどれよりも上に見えているので、先に外す。もう一度押せば今までどおり。
//! - 選択は**別の場所を押したとき**にも外れる。マウスの選択と入力欄の選択は同時に持たない（後から作ったほうが残る）。
//!
//! # 写すのはイベントループ
//!
//! 状態（[`AppState`]）は写す文章を[`Action::Copy`]で返すだけで、クリップボードへは触らない（`AppState`が
//! サンドボックスへ触らないのと同じ形）。書くのは`crate::run`のイベントループで、書けたかどうかを
//! [`AppState::note_copied`]で知らせる。だから試験は実物のクリップボードに書かない。
//!
//! # 知らせを出す場所
//!
//! 会話画面には知らせの行が無い。transcriptへ1行足す（[`TranscriptItem::Info`]）と、末尾に貼り付いている間は
//! 画面の文章が1行上へ動く（選んでいた文章の場所がずれる）ので、**transcriptの枠の上辺**に出す（「さかのぼり中」の
//! 案内を出しているのと同じ場所。中身を動かさない）。次にキーかマウスのボタンを押すと消える。
//!
//! # 限界
//!
//! - 実物のクリップボードへの書き込みは試験していない（試験は書く文章までを固定する）。
//! - 端末の大きさが小さく、重ねた枠がtranscriptの上辺まで覆っているときは、知らせが見えない。

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use super::{Action, AppState, EdgeNotice, NoticeTone, ReviewFocus, Step, Wheel};

/// 写すキー（`Ctrl+C`。選んでいないときは終了の仕方を知らせるだけ——[`AppState::on_selection_key`]）。
pub(crate) fn is_copy_key(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
}

impl AppState {
    /// 写せる選択があるか（マウスで選んだ文章か、入力欄のキーボードの選択）。入力欄の見出しの`Ctrl-C`の案内が使う。
    pub fn has_copyable_selection(&self) -> bool {
        self.selection.has_text() || self.selection_range().is_some()
    }

    /// 選んでいる文章を写す[`Action::Copy`]（マウスの選択が先、無ければ入力欄の選択）。写したら選択を外す。
    /// 写せる選択が無ければ`None`。`Ctrl+C`と右クリックがここを通る。
    pub(crate) fn copy_selection(&mut self) -> Option<Action> {
        if let Some(text) = self.selection.copy() {
            return Some(Action::Copy(text));
        }
        let (start, end) = self.selection_range()?;
        let text: String = self.input.chars().skip(start).take(end - start).collect();
        self.input_selection_anchor = None;
        Some(Action::Copy(harness_term::clipboard::crlf(&text)))
    }

    /// 写した結果（イベントループがクリップボードへ書いた後に呼ぶ。`text`は写した文章）。
    pub fn note_copied(&mut self, text: &str, result: Result<(), String>) {
        self.edge_notice = Some(EdgeNotice {
            text: harness_term::clipboard::notice(text, &result),
            tone: if result.is_ok() {
                NoticeTone::Done
            } else {
                NoticeTone::Failed
            },
        });
    }

    /// キーの前に、選択が先に受けるもの（`Ctrl+C`・`Esc`で外す）。受けたら`Some`（中身はキーの結果）。
    ///
    /// **`Ctrl+C`はいつもここで終わる**——選んでいれば写し、選んでいなければ終了の仕方を知らせる（`app::quit`。押しても
    /// 無反応にしない、B-23(c)）。重ねた枠より先に受けるので、どの状態でも`Ctrl+C`の意味は同じ。
    pub(super) fn on_selection_key(&mut self, key: KeyEvent) -> Option<Option<Action>> {
        if is_copy_key(&key) {
            let copied = self.copy_selection();
            if copied.is_none() {
                self.edge_notice = Some(EdgeNotice::hint(harness_term::double_esc::CTRL_C_NOTICE));
            }
            return Some(copied);
        }
        if key.code == KeyCode::Esc && self.selection.is_active() {
            self.selection.clear();
            return Some(None);
        }
        None
    }

    /// 選択が先に受けるマウスのイベント（押したままの移動と離上・右クリック）。受けたら`Some`。
    pub(super) fn on_selection_mouse(&mut self, mouse: MouseEvent, now: Instant) -> Option<Step> {
        match mouse.kind {
            MouseEventKind::Drag(MouseButton::Left) if self.selection.is_held() => {
                let dragged = self
                    .selection
                    .drag(&self.pointer, mouse.column, mouse.row, now);
                if dragged.started {
                    // 2つの選択を同時に持たない（モジュールdoc）。
                    self.input_selection_anchor = None;
                }
                if let Some(scroll) = dragged.scroll {
                    self.on_wheel(scroll.surface, scroll.up);
                }
                Some(Step::Handled(None))
            }
            MouseEventKind::Up(MouseButton::Left) if self.selection.is_held() => {
                self.selection.release();
                Some(Step::Handled(None))
            }
            MouseEventKind::Down(MouseButton::Right) => self
                .copy_selection()
                .map(|action| Step::Handled(Some(action))),
            _ => None,
        }
    }

    /// 枠`surface`の文章の上で左ボタンを押した（押せる場所ではない所。`harness_term::pointer::Pointer::Text`）。
    pub(super) fn press_text(&mut self, surface: Wheel, column: u16, row: u16) {
        // 差分ペインは、押すとフォーカスが移る場所でもある（文章を選べるようにする前と同じ）。
        if surface == Wheel::ReviewDiff {
            self.focus_review(ReviewFocus::Diff);
        }
        // 押したのは`Esc`ではない。二度押しの途中に挟まったら数え直す（クリックと同じ規則。`app::quit`）。
        self.double_esc.reset();
        self.selection.press(&self.pointer, surface, column, row);
    }
}
