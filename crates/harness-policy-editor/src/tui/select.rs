//! 画面の文章をマウスで選んでクリップボードへ写す（2026-10-03）。部品は会話TUIと共有する`harness_term::select`
//! （選ぶ）と`harness_term::clipboard`（写す）。決めたことの正本は`plans/POLICY-EDITOR-TOMOYO-DIG.md`の決定62の後ろの
//! 「画面の文章をマウスで選んでコピーできるようにした」。
//!
//! # 選べる枠
//!
//! 文章を出す送れる枠の全部——記録画面の「実行するとどうなるか」・見出し枠・警告枠・進行・コマンドの出力・起動時の
//! ノイズ、承認待ちと宣言画面の説明欄（プロセスツリーを含む）、ヘルプ、確認ダイアログの本文。どれも
//! `harness_term::scrollable`・`scrollback`で描くので、描くときに選べる場所として登録される。枠の名前はホイールで
//! 送るときの名前（[`Wheel`]）をそのまま使う。**押せる行を持つ一覧**（候補の木・記録セッション・遷移の一覧・宣言の木）と
//! 入力欄・キー案内・知らせの行は選べない。
//!
//! # 選び方と写し方
//!
//! - 文章の上で左ボタンを押してずらすと、押した文字から今の文字までを選ぶ。ずらさずに離したら今までどおり
//!   （**ヘルプの文章の上だけは、離したときに閉じる**——押した瞬間に閉じると選べないため。ヘルプの外を押したときは
//!   今までどおり押した瞬間に閉じる）。枠の上下の外までずらすとその向きへ送る（止めていても送り続ける）。
//! - **選んでいるときの`Ctrl+C`と右クリックは写す**。写したら選択を外し、知らせの行に「N文字をコピーしました」を出す
//!   （書けなければ理由を出す）。**`Ctrl+C`は終了に使わない**（2026-10-03から。会話画面と同じ——`harness_term::double_esc`）
//!   ——選んでいないときは何も写さず、知らせの行に「終了は Esc を2回」を出す。終了は`Esc`の二度押しと`Ctrl+Q`（記録中は
//!   撤収を待つ）。右クリックは何もしない。キー案内の`Ctrl+C コピー`は写せる間だけ出る。
//! - **選んでいる間の`Esc`は選択を外すだけ**（確認ダイアログ・ヘルプを閉じず、記録も止めず、`Esc`の二度押しにも
//!   数えない）。もう一度押せば今までどおり。
//! - 別の場所を押すと選択は外れる。
//!
//! # 写すのはイベントループ
//!
//! 状態（[`App`]）は写す文章を[`Action::Copy`]で返すだけで、クリップボードへは触らない。書くのは`tui::run`の
//! イベントループで、結果を[`App::note_copied`]で知らせの行へ出す。だから試験は実物のクリップボードに書かない。

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use crate::tui::pointer::key;
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::{Action, App};

impl App {
    /// 選んでいる文章を写す[`Action::Copy`]（写したら選択を外す）。写せる文章が無ければ`None`。
    /// `Ctrl+C`と右クリックがここを通る。
    pub(crate) fn copy_selection(&mut self) -> Option<Action> {
        self.selection.copy().map(Action::Copy)
    }

    /// 写した結果（イベントループがクリップボードへ書いた後に呼ぶ。`text`は写した文章）。知らせの行に出す。
    pub fn note_copied(&mut self, text: &str, result: Result<(), String>) {
        self.status = harness_term::clipboard::notice(text, &result);
    }

    /// キーの前に、選択が先に受けるもの（`Ctrl+C`・`Esc`で外す）。受けたら`Some`（中身はキーの結果）。
    ///
    /// **`Ctrl+C`はいつもここで終わる**——選んでいれば写し、選んでいなければ終了の仕方を知らせの行に出す（押しても
    /// 無反応にしない、B-23(c)）。確認ダイアログ・ヘルプより先に受けるので、どの状態でも意味は同じ。
    /// 選択を外した`Esc`は二度押しに数えない（呼び出し側`App::on_key_at`が1回目を捨てた状態で来るので、何もしなくてよい）。
    pub(super) fn on_selection_key(&mut self, pressed: KeyEvent) -> Option<Option<Action>> {
        if pressed.code == KeyCode::Char('c') && pressed.modifiers.contains(KeyModifiers::CONTROL) {
            let copied = self.copy_selection();
            if copied.is_none() {
                self.status = harness_term::double_esc::CTRL_C_NOTICE.to_string();
            }
            return Some(copied);
        }
        if pressed.code == KeyCode::Esc && self.selection.is_active() {
            self.selection.clear();
            return Some(None);
        }
        None
    }

    /// 選択が先に受けるマウスのイベント（押したままの移動と離上・右クリック）。受けたら`Some`。
    pub(super) fn on_selection_mouse(
        &mut self,
        event: MouseEvent,
        now: Instant,
    ) -> Option<Option<Action>> {
        match event.kind {
            MouseEventKind::Drag(MouseButton::Left) if self.selection.is_held() => {
                let dragged = self
                    .selection
                    .drag(&self.pointer, event.column, event.row, now);
                if let Some(scroll) = dragged.scroll {
                    self.on_wheel(scroll.surface, scroll.up);
                }
                Some(None)
            }
            MouseEventKind::Up(MouseButton::Left) if self.selection.is_held() => {
                // ヘルプの文章の上のただのクリックは、ヘルプを閉じる（モジュールdoc。閉じ方はヘルプの外を押したときと同じ）。
                if self.selection.release() == Some(Wheel::Panel(Panel::Help)) && self.help {
                    return Some(self.on_key(key(KeyCode::Null)));
                }
                Some(None)
            }
            MouseEventKind::Down(MouseButton::Right) => self.copy_selection().map(Some),
            _ => None,
        }
    }

    /// 枠`surface`の文章の上で左ボタンを押した（押せる場所ではない所。`harness_term::pointer::Pointer::Text`）。
    pub(super) fn press_text(&mut self, surface: Wheel, column: u16, row: u16) {
        // 押したのは`Esc`ではない。二度押しの途中に挟まったら続きを切る（クリックと同じ規則）。
        self.double_esc.reset();
        self.selection.press(&self.pointer, surface, column, row);
    }
}
