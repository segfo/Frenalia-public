//! マウスのクリックとホイール（2026-10-02）。**押せる場所と送れる枠は、描くときに登録する**
//! （土台は会話TUIと共有する`harness_term::pointer`）。
//!
//! # 当たり判定は、描いた矩形そのもの
//!
//! 各画面の描画が、タブ・一覧の行・`[x]`・`▾`/`▸`・入力欄・キー案内の項目・記録の枠のボタン・確認ダイアログのボタンを
//! **描いたその矩形で**[`Targets`]へ登録し、フレームごとに`App::pointer`へ書き戻す
//! （`App::apply_draw_feedback`）。マウスのイベントは、直前に描いたその登録で引く。
//! ホイールの当たり判定も同じ登録を通る——以前は画面の割り付けをイベントのたびに計算し直していたが
//! （`tui::scroll`のdoc）、クリックと同じ登録へ寄せた。当たり判定のために割り付けを写さない（BUG-194）。
//!
//! 直前に描いた画面で引いてよいのは、イベントループが**イベントを1つ処理するたびに描き直す**からである
//! （`tui::run`）。端末の大きさが変わったときも、`Resize`を受けた次の周回で描き直してから次のイベントを読む。
//!
//! # クリックは、キーを押したのと同じ処理を呼ぶ
//!
//! クリック用の処理は書かない（同じ操作を2か所に持つと、片方だけ直る）。[`Click`]はどれも、
//! 次のどちらかで終わる。
//!
//! - **キーを押す**（`App::on_key`）——キー案内の項目・記録の枠のボタン（記録の開始・停止）・確認ダイアログのボタン・`[x]`（`Space`）・
//!   `▾`/`▸`（`←`/`→`）・入力欄（`Tab`で入るのと同じ）・一番上のタブ（`F1`〜`F3`）。
//! - **キーが呼ぶのと同じ関数を、行の差だけ動かして呼ぶ**——一覧の行を選ぶとき。`↓`をN回押す形にしないのは、
//!   記録セッションの一覧では選択が動くたびにその記録を開き直す（`move_selection`）ので、途中の記録を全部
//!   読むことになるためである。
//!
//! 承認待ちのタブ（FS/ネット・遷移・観測から・遷移・拒否から）は、`F2`の巡回が使う
//! `App::select_pending_tab`を、選んだタブで呼ぶ。
//!
//! # 押せないもの（決めたこと）
//!
//! - **一括の操作**（宣言画面の`A 全件`・遷移タブの`X 表示中を却下`）はキーだけで押せる。クリックには付けない
//!   ——決定51は「一括承認は許さない」を、まとめての操作は読んでから押させる、という形で守っている。
//!   クリックは押し間違えやすく、1回で全件の予約が変わる操作をそこへ置かない。
//! - `↑↓ 選択`・`→← 展開/折畳`・`ホイール …`の案内は、1つのキーに決まらないので押せない（行や記号を押す）。
//! - 確認ダイアログの外側は押せない（書き込みの確認は`y`か`n`/`Esc`を選ばせる。決定32）。
//!
//! # 重ねた枠が開いている間は後ろを押せない
//!
//! 確認ダイアログとヘルプは、描くときに画面全体を覆ってから（`Targets::cover`）自分の場所を登録する
//! （`tui::open_overlay`）。キー入力もその間は重ねた側だけが受ける（`App::on_key`）のと同じ形である。
//! ヘルプは「何かキーを押すと閉じる」ので、クリックでも閉じる（どこを押しても、何でもないキーを
//! 押したのと同じ。[`Click::CloseHelp`]）。
//!
//! # 入力欄に居るときにキー案内を押したら
//!
//! 承認待ちのドメイン欄・遷移先の欄では、文字キーは名前の入力になる。キー案内の`a 承認`を押して
//! 名前に`a`が入るのは押した意図と違うので、**文字キーを押す項目は、先に欄から出る**（`Enter`。
//! 欄から一覧へ戻る既存のキー）。一覧の行を押したときも同じく欄から出る。
//!
//! # 限界
//!
//! - クリックは左ボタンを押した瞬間に効く（離したときではない）。押してから外へずらして取り消すことはできない。
//! - 入力欄を押しても、押した桁へカーソルは移らない（`Tab`で入ったときと同じく、カーソルはそのまま）。
//! - キーボードの`Esc`の後にクリックを挟むと、`Esc`の二度押し（終了）の続きは切れる（キーと同じ規則）。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use harness_term::pointer::Pointer;
use ratatui::layout::Rect;
use ratatui::text::Span;

use crate::tui::checkbox_tree;
use crate::tui::scroll::Wheel;
use crate::tui::state::{Action, App, EditField, RecordField, Screen};
use crate::tui::transition::PendingTab;

/// 1フレームで描いた、押せる場所と送れる枠。
pub type Targets = harness_term::pointer::Targets<Click, Wheel>;

/// クリックで起こすこと。どれもキーの処理を呼ぶ（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Click {
    /// 一番上のタブ。いまの画面なら何もしない。
    Screen(Screen),
    /// 承認待ちのタブ。いまのタブなら何もしない。
    PendingTab(PendingTab),
    /// 一覧の行を選ぶ。
    Row(ListId, usize),
    /// 行の`[x]`/`[ ]`。その行を選んで`Space`。
    Mark(ListId, usize),
    /// 行の`▾`/`▸`。その行を選んで、開いていたなら`←`、閉じていたなら`→`。`open`は描いたときの状態。
    Fold {
        list: ListId,
        row: usize,
        open: bool,
    },
    /// 入力欄（`Tab`で入るのと同じ状態にする）。
    Field(Field),
    /// キーを順に押す（キー案内の項目・記録の枠のボタン・確認ダイアログのボタン）。
    Keys(Vec<KeyEvent>),
    /// ヘルプを閉じる（何でもないキーを押す）。
    CloseHelp,
}

/// 押せる行を持つ一覧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListId {
    /// 承認待ち（FS/ネット）の記録セッション。
    Sessions,
    /// 承認待ち（FS/ネット）の候補の木。
    Proposals,
    /// 承認待ちの遷移タブの一覧。
    Transitions,
    /// 宣言画面の木。
    Declared,
}

/// 押せる入力欄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// 記録画面の欄（パス・コマンド・作業ディレクトリ・ドメイン）。
    Record(RecordField),
    /// 承認待ち（FS/ネット）のドメイン欄。
    Domain,
    /// 承認待ちの遷移タブの遷移先ドメインの欄。
    Destination,
}

/// 修飾キー無しのキー。
pub(crate) fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// 一覧の1項目の、押せる記号の位置（項目の1行目の左端から何桁目に、何桁）。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Hot {
    mark: Option<(u16, u16)>,
    /// 開閉の記号と、描いたときに開いていたか。
    fold: Option<(u16, u16, bool)>,
}

impl Hot {
    /// 項目の1行目`spans`のうち、`mark`番目のspanがチェック、`fold`番目のspanが開閉の記号（`bool`は開いているか）。
    /// 位置は`harness_term::row::spans_in`（ratatuiが行を描く規則）で求める。
    pub(crate) fn of(spans: &[Span], mark: Option<usize>, fold: Option<(usize, bool)>) -> Self {
        let columns = harness_term::row::spans_in(Rect::new(0, 0, u16::MAX, 1), spans);
        let at = |index: usize| columns.get(index).map(|rect| (rect.x, rect.width));
        Self {
            mark: mark.and_then(at),
            fold: fold.and_then(|(index, open)| at(index).map(|(x, width)| (x, width, open))),
        }
    }
}

/// 描かれた行を登録する。行全体＝その行を選ぶ、チェック＝`Space`、開閉＝`←`/`→`（後から登録した記号が行より上）。
/// `hot`は`items`の順（`Row::index`で引く）。
pub(crate) fn register_rows(
    targets: &mut Targets,
    list: ListId,
    rows: &[harness_term::list::Row],
    hot: &[Hot],
) {
    for row in rows {
        targets.click(row.area, Click::Row(list, row.index));
        let Some(hot) = hot.get(row.index) else {
            continue;
        };
        let cell = |x: u16, width: u16| {
            Rect::new(row.area.x.saturating_add(x), row.area.y, width, 1).intersection(row.area)
        };
        if let Some((x, width)) = hot.mark {
            targets.click(cell(x, width), Click::Mark(list, row.index));
        }
        if let Some((x, width, open)) = hot.fold {
            targets.click(
                cell(x, width),
                Click::Fold {
                    list,
                    row: row.index,
                    open,
                },
            );
        }
    }
}

impl App {
    /// マウスのイベント（左クリックとホイール）。直前に描いた画面の登録（`self.pointer`）で引く。
    /// 押せる場所・送れる枠の外では**何もしない**——外した位置で別のものが動くほうが混乱する。
    pub fn on_mouse(&mut self, event: MouseEvent) -> Option<Action> {
        match self.pointer.resolve(&event)? {
            Pointer::Wheel { target, up } => {
                self.on_wheel(target, up);
                None
            }
            Pointer::Click(click) => self.on_click(click),
        }
    }

    fn on_click(&mut self, click: Click) -> Option<Action> {
        // クリックは`Esc`ではない。`Esc`の二度押し（終了）の途中に挟まったら続きを切る
        // （`on_key`が`Esc`以外のキーで切るのと同じ規則。キーを押すクリックは`on_key`がもう一度判定する）。
        self.last_esc = None;
        match click {
            Click::Keys(keys) => {
                if keys.iter().any(types_text) {
                    self.leave_text_field();
                }
                self.press_all(&keys)
            }
            Click::Screen(screen) => {
                if self.screen == screen {
                    return None;
                }
                self.on_key(key(KeyCode::F(match screen {
                    Screen::Record => 1,
                    Screen::Edit => 2,
                    Screen::Declared => 3,
                })))
            }
            Click::PendingTab(tab) => {
                if self.pending.tab.0 != tab {
                    self.select_pending_tab(tab);
                }
                None
            }
            Click::Field(field) => {
                self.focus_field(field);
                None
            }
            Click::Row(list, row) => {
                self.select_row(list, row);
                None
            }
            Click::Mark(list, row) => {
                self.select_row(list, row);
                self.on_key(key(KeyCode::Char(' ')))
            }
            Click::Fold { list, row, open } => {
                self.select_row(list, row);
                self.on_key(key(if open { KeyCode::Left } else { KeyCode::Right }))
            }
            // ヘルプは「何かキーを押すと閉じる」（`on_key`）。閉じ方を2か所に持たないよう、何でもないキーを押す。
            Click::CloseHelp => self.on_key(key(KeyCode::Null)),
        }
    }

    /// キーを順に押す。途中で操作（記録の開始・終了）が返ったら、そこで止めて返す。
    fn press_all(&mut self, keys: &[KeyEvent]) -> Option<Action> {
        for &pressed in keys {
            if let Some(action) = self.on_key(pressed) {
                return Some(action);
            }
        }
        None
    }

    /// 承認待ちの入力欄（ドメイン欄・遷移先の欄）に居るなら、`Enter`で一覧へ戻る（モジュールdoc）。
    fn leave_text_field(&mut self) {
        if self.screen != Screen::Edit {
            return;
        }
        let in_field = if self.pending.tab.0.is_transition() {
            self.pending.destination.focused
        } else {
            self.edit_focus == EditField::Domain
        };
        if in_field {
            self.on_key(key(KeyCode::Enter));
        }
    }

    /// 承認待ち（FS/ネット）の項目を`Tab`で`target`まで送る（`Tab`は項目を巡回するだけで、ほかに何もしない）。
    fn focus_edit(&mut self, target: EditField) {
        for _ in 0..3 {
            if self.edit_focus == target {
                return;
            }
            self.on_key(key(KeyCode::Tab));
        }
    }

    /// 入力欄を押した——`Tab`で入るのと同じ状態にする。
    fn focus_field(&mut self, field: Field) {
        match field {
            Field::Record(target) => {
                // 記録画面の`Tab`は欄を巡回するだけ。描いた欄はどれも巡回に入っている（ドメイン欄はパス2でだけ描く）。
                for _ in 0..4 {
                    if self.record_focus == target {
                        return;
                    }
                    self.on_key(key(KeyCode::Tab));
                }
            }
            Field::Domain => self.focus_edit(EditField::Domain),
            Field::Destination => {
                if !self.pending.destination.focused {
                    self.on_key(key(KeyCode::Tab));
                }
            }
        }
    }

    /// 一覧の`row`行目を選ぶ。`↑↓`・`PgUp/PgDn`が呼ぶのと同じ関数を、行の差で呼ぶ（モジュールdoc）。
    fn select_row(&mut self, list: ListId, row: usize) {
        self.leave_text_field();
        let delta = |current: usize| row as isize - current as isize;
        match list {
            ListId::Sessions => {
                self.focus_edit(EditField::Sessions);
                self.move_selection(delta(self.selected_session));
            }
            ListId::Proposals => {
                self.focus_edit(EditField::Proposals);
                self.move_selection(delta(self.selected_row));
            }
            ListId::Transitions => {
                let rows = self.pending.visible().len();
                let current = self.pending.row();
                checkbox_tree::move_row(self.pending.row_mut(), rows, delta(current));
            }
            ListId::Declared => {
                let rows = self.declared_tree.rows(&self.declared_expanded).len();
                let by = delta(self.declared_row);
                checkbox_tree::move_row(&mut self.declared_row, rows, by);
            }
        }
    }
}

/// 入力欄に居ると文字として入ってしまうキーか。
fn types_text(pressed: &KeyEvent) -> bool {
    matches!(pressed.code, KeyCode::Char(_)) && !pressed.modifiers.contains(KeyModifiers::CONTROL)
}
