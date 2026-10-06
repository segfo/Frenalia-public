//! マウスのクリックとホイールの当たり判定（会話TUIとポリシーエディタが共有する土台）。
//!
//! # 何のためにあるのか——描いた場所を、描くついでに登録する
//!
//! 押せる場所（タブ・一覧の行・ボタン）とホイールで送れる枠を、**描くときに使った矩形そのもの**で
//! [`Targets`]へ登録し、マウスのイベントが来たらその座標で引く。当たり判定のために画面の割り付けを
//! もう一度計算しない——別々に計算すると、片方だけ直したときに「見えている枠と反応する枠がずれる」
//! （ポリシーエディタの[BUG-194](../../../docs/bugs/BUG-194.md)は実際にそうなっていた）。
//!
//! # 後から登録したものが上にある
//!
//! 描く順番がそのまま重なりの順番である（後から描いたものが上に見える）ので、引くときは
//! **後から登録したものから**見る。後ろの画面の上に枠を重ねるときは、先に[`Targets::cover`]で
//! 後ろを覆う——覆った範囲では、それより前に登録したものはクリックにもホイールにも反応しない。
//! 覆った後で、重ねた枠の中の押せる場所と送れる場所を登録する。
//!
//! クリックとホイールは別々に引く。クリックだけを受ける場所の上でホイールを回すと、その下の送れる枠へ
//! 届く（重ねた枠のボタンの上で回しても、枠そのものが送られる）。
//!
//! # 使い方
//!
//! 1フレーム描くたびに新しい[`Targets`]を作って登録し、**次に描くまで持っておいて**、その間に来た
//! マウスのイベントを[`Targets::resolve`]で引く。イベントを1つ処理するたびに描き直すイベントループなら、
//! 引くのはいつも「利用者がいま見ている画面」になる。
//!
//! # 文章を選べる場所（2026-10-03）
//!
//! 送れる枠は、描いた文章の各文字がどこに描かれたか（[`TextMap`]）を、ホイールで送るときと同じ名前`W`で登録する
//! （[`Targets::text`]。登録するのは枠の描画——`crate::scrollable`・`crate::scrollback`——で、呼び出し側は
//! [`crate::select::Selectable`]を渡すだけ）。左ボタンを押した所が押せる場所ではなく文章の上なら
//! [`Pointer::Text`]を返す。**押せる場所が上に登録されていれば、そちらが勝つ**（文章の中の押せる行・ボタンは
//! 今までどおりクリック。選び始めない）。
//!
//! # 文字の上にポインタがあるか（2026-10-07）
//!
//! [`Targets::text_at`]は、あるセルに**見えている**文字が、枠`W`の文章の何行目の何文字目か（[`Pos`]）を答える。
//! 会話TUIが、マウスの下の文字がリンクかを引いて吹き出しを出すのに使う（`plans/PLAN-TUI-IMPROVEMENTS.md`§3）。
//! 文章を選ぶときの引き方（`crate::select`）と違って**枠の端へ寄せない**——文字の無いセル（行の右の空き）は`None`。
//! 後から覆った範囲（[`Targets::cover`]）と、後から重ねた別の枠の文章の上も`None`（その文字は隠れている）。押せる場所は
//! 文字を隠さない（押せる行も文字として描いてある）。逆向きの[`Targets::text_cell`]は、位置からその文字を描いたセルを返す
//! （吹き出しをリンクの最後の文字の右に置くため）。
//!
//! # 限界
//!
//! - **左ボタンを押した瞬間**（`Down`）をクリックとする。離した瞬間（`Up`）・ドラッグ・右/中ボタン・横スクロールは
//!   何にも当たらない。押してから外へずらして取り消す、という操作は無い（ドラッグは文章を選ぶときだけ
//!   `crate::select::Selection`が見る）。
//! - 描いてから次に描くまでの間に状態が変わる作りでは、古い画面で引くことになる（1イベントごとに描き直すこと）。

use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};

use crate::select::{Pos, TextMap};

/// 登録した場所の1件。
#[derive(Debug, Clone)]
enum Entry<C, W> {
    /// クリックを受ける。
    Click(Rect, C),
    /// ホイールを受ける。
    Wheel(Rect, W),
    /// 文章を選べる（`W`はその枠をホイールで送るときの名前）。
    Text(TextMap, W),
    /// 後ろを覆う（重ねた枠）。ここより前に登録したものへは届かない。
    Cover(Rect),
}

/// 1フレームで描いた、押せる場所（`C`）とホイールで送れる場所（`W`）。モジュールdocを参照。
#[derive(Debug, Clone)]
pub struct Targets<C, W> {
    entries: Vec<Entry<C, W>>,
}

impl<C, W> Default for Targets<C, W> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// マウスのイベントを引いた結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer<C, W> {
    /// 押せる場所が左クリックされた。
    Click(C),
    /// 送れる場所の上でホイールが回された。`up`が真なら上（先頭の向き）。
    Wheel { target: W, up: bool },
    /// 文章を選べる枠の、押せる場所ではない所で左ボタンが押された（`crate::select::Selection::press`へ渡す）。
    Text(W),
}

impl<C: Clone, W: Clone> Targets<C, W> {
    /// `area`をクリックしたら`target`を返す。幅か高さが0の場所は登録しない（押せない）。
    pub fn click(&mut self, area: Rect, target: C) {
        if !area.is_empty() {
            self.entries.push(Entry::Click(area, target));
        }
    }

    /// `area`の上でホイールを回したら`target`を返す。
    pub fn wheel(&mut self, area: Rect, target: W) {
        if !area.is_empty() {
            self.entries.push(Entry::Wheel(area, target));
        }
    }

    /// `area`を覆う。**後ろの画面の上に枠を重ねるときは、その枠を登録する前にこれを呼ぶ**（モジュールdoc）。
    pub fn cover(&mut self, area: Rect) {
        if !area.is_empty() {
            self.entries.push(Entry::Cover(area));
        }
    }

    /// 文章を選べる場所として、描いた文字の場所`map`を登録する（`surface`はその枠をホイールで送るときの名前）。
    /// 描いた送れる枠が自分で呼ぶ（`crate::select::Selectable`）。文章を描く矩形が空なら登録しない。
    pub(crate) fn text(&mut self, map: TextMap, surface: W) {
        if !map.area().is_empty() {
            self.entries.push(Entry::Text(map, surface));
        }
    }

    /// `(column, row)`をクリックしたときの動き。押せる場所でなければ`None`（文章の上も`None`——[`Self::resolve`]が
    /// [`Pointer::Text`]を返す）。
    pub fn clicked(&self, column: u16, row: u16) -> Option<C> {
        match self.pressed(column, row)? {
            Pressed::Click(target) => Some(target),
            Pressed::Text(_) => None,
        }
    }

    /// `(column, row)`で左ボタンを押したときに当たるもの（いちばん上の押せる場所か文章）。
    fn pressed(&self, column: u16, row: u16) -> Option<Pressed<C, W>> {
        let at = Position::new(column, row);
        for entry in self.entries.iter().rev() {
            match entry {
                Entry::Click(area, target) if area.contains(at) => {
                    return Some(Pressed::Click(target.clone()))
                }
                Entry::Text(map, surface) if map.area().contains(at) => {
                    return Some(Pressed::Text(surface.clone()))
                }
                Entry::Cover(area) if area.contains(at) => return None,
                _ => {}
            }
        }
        None
    }

    /// `(column, row)`でホイールを回したときに送る場所。送れる場所でなければ`None`。
    pub fn wheeled(&self, column: u16, row: u16) -> Option<W> {
        let at = Position::new(column, row);
        for entry in self.entries.iter().rev() {
            match entry {
                Entry::Wheel(area, target) if area.contains(at) => return Some(target.clone()),
                Entry::Cover(area) if area.contains(at) => return None,
                _ => {}
            }
        }
        None
    }

    /// マウスのイベントを引く。左ボタンの押下とホイールの上下だけを扱う（[`acts`]。モジュールdocの限界）。
    pub fn resolve(&self, event: &MouseEvent) -> Option<Pointer<C, W>> {
        if !acts(event.kind) {
            return None;
        }
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.pressed(event.column, event.row)
                    .map(|pressed| match pressed {
                        Pressed::Click(target) => Pointer::Click(target),
                        Pressed::Text(surface) => Pointer::Text(surface),
                    })
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => self
                .wheeled(event.column, event.row)
                .map(|target| Pointer::Wheel {
                    target,
                    up: event.kind == MouseEventKind::ScrollUp,
                }),
            _ => None,
        }
    }
}

impl<C, W: Clone + PartialEq> Targets<C, W> {
    /// 枠`surface`に描いた文字の場所（いちばん後に登録したもの）。その枠を描いていなければ`None`。
    pub(crate) fn text_map(&self, surface: &W) -> Option<&TextMap> {
        self.entries.iter().rev().find_map(|entry| match entry {
            Entry::Text(map, s) if s == surface => Some(map),
            _ => None,
        })
    }

    /// 枠`surface`の文章のうち、`(column, row)`のセルに**見えている**文字の位置（描いた`Text`の何行目の何文字目か。
    /// モジュールdoc「文字の上にポインタがあるか」）。文字の描かれていないセル・覆った範囲・後から重ねた別の枠の文章の
    /// 上は`None`。押せる場所は文字を隠さない。
    pub fn text_at(&self, surface: &W, column: u16, row: u16) -> Option<Pos> {
        let at = Position::new(column, row);
        for entry in self.entries.iter().rev() {
            match entry {
                Entry::Cover(area) if area.contains(at) => return None,
                Entry::Text(map, s) if map.area().contains(at) => {
                    return if s == surface {
                        map.glyph_at(column, row)
                    } else {
                        None
                    };
                }
                _ => {}
            }
        }
        None
    }

    /// 枠`surface`の文章の位置`at`の文字を描いたセルの矩形（高さ1、幅はその文字の桁数。[`Self::text_at`]の逆）。
    /// 見えていない文字・描いていない枠は`None`。**覆われているかは見ない**（描いた場所を返すだけ）。
    pub fn text_cell(&self, surface: &W, at: Pos) -> Option<Rect> {
        self.text_map(surface)?.cell_of(at)
    }

    /// 前に登録した枠`surface`の文章を、**いまの重なりの一番上へ登録し直す**（後ろを覆った後でも、外に見えている部分を
    /// 選べるようにする。会話画面は承認ダイアログ・レビューパネルの外に見えているtranscriptを選ばせる）。
    /// 登録し直した後に覆ったもの（重ねた枠）は、今までどおりその上にある。
    pub fn lift_text(&mut self, surface: &W) {
        if let Some(map) = self.text_map(surface).cloned() {
            self.entries.push(Entry::Text(map, surface.clone()));
        }
    }
}

/// 左ボタンの押下が当たったもの。
enum Pressed<C, W> {
    Click(C),
    Text(W),
}

/// この種類のイベントが[`Targets::resolve`]で何かに当たり得るか（左ボタンの押下とホイールの上下）。
///
/// **当たり得ない種類（ポインタの移動・離す・ドラッグ・右/中ボタン・横スクロール）は、画面の何も変えない**
/// （文章を選んでいる途中のドラッグ・離上と、選んでいるときの右クリックだけは例外で、呼び出し側が
/// `crate::select::Selection`へ先に渡す）。
/// `EnableMouseCapture`はポインタの移動もすべて報告するので、イベントを1つ読むたびに描き直すループは、
/// これで描き直しを省ける（省かないと、マウスを動かすだけで描き直し続ける）。[`Targets::resolve`]も
/// 同じこれで絞るので、「描き直さなかったのに何かが変わった」は起きない。
pub fn acts(kind: MouseEventKind) -> bool {
    matches!(
        kind,
        MouseEventKind::Down(MouseButton::Left)
            | MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown
    )
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyModifiers;
    use ratatui::text::{Line, Text};

    use super::*;
    use crate::select::map::{prepare, Shape};

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn down(column: u16, row: u16) -> MouseEvent {
        mouse(MouseEventKind::Down(MouseButton::Left), column, row)
    }

    /// 押せる場所の中は当たり、外（右端・下端の1つ先を含む）は当たらない。
    #[test]
    fn a_click_hits_only_inside_the_registered_area() {
        let mut targets: Targets<&str, ()> = Targets::default();
        targets.click(Rect::new(2, 1, 3, 2), "button");
        assert_eq!(targets.clicked(2, 1), Some("button"));
        assert_eq!(targets.clicked(4, 2), Some("button"));
        for (x, y) in [(1, 1), (5, 1), (2, 0), (2, 3)] {
            assert_eq!(targets.clicked(x, y), None, "({x},{y})");
        }
    }

    /// **後から登録したものが上にある**（描く順番と同じ）。重なった場所では後のものが当たる。
    #[test]
    fn the_later_registration_wins_where_two_overlap() {
        let mut targets: Targets<&str, ()> = Targets::default();
        targets.click(Rect::new(0, 0, 10, 1), "row");
        targets.click(Rect::new(2, 0, 3, 1), "mark");
        assert_eq!(targets.clicked(3, 0), Some("mark"));
        assert_eq!(targets.clicked(0, 0), Some("row"));
        assert_eq!(targets.clicked(9, 0), Some("row"));
    }

    /// **覆った範囲では、後ろの押せる場所にも送れる場所にも届かない。** 覆った後に登録したものには届く。
    #[test]
    fn a_cover_hides_everything_registered_before_it() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.click(Rect::new(0, 0, 20, 10), "behind");
        targets.wheel(Rect::new(0, 0, 20, 10), "behind");
        targets.cover(Rect::new(5, 2, 10, 5));
        targets.click(Rect::new(6, 6, 3, 1), "button");
        // 覆った中: 後ろには届かない。
        assert_eq!(targets.clicked(7, 3), None);
        assert_eq!(targets.wheeled(7, 3), None);
        // 覆った後に登録したもの。
        assert_eq!(targets.clicked(7, 6), Some("button"));
        // 覆っていない外側は、今までどおり後ろに届く（許可側）。
        assert_eq!(targets.clicked(1, 1), Some("behind"));
        assert_eq!(targets.wheeled(19, 9), Some("behind"));
    }

    /// クリックとホイールは別々に引く。押せる場所の上で回すと、その下の送れる場所が送られる。
    #[test]
    fn the_wheel_passes_through_a_button_to_the_box_under_it() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.cover(Rect::new(0, 0, 20, 10));
        targets.wheel(Rect::new(0, 0, 20, 10), "modal");
        targets.click(Rect::new(1, 9, 5, 1), "yes");
        assert_eq!(targets.wheeled(2, 9), Some("modal"));
        assert_eq!(targets.clicked(2, 9), Some("yes"));
        assert_eq!(targets.clicked(10, 5), None, "ボタンの外は押せない");
    }

    /// 幅か高さが0の場所は登録しない（押せない）。
    #[test]
    fn an_empty_area_is_never_hit() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.click(Rect::new(3, 3, 0, 1), "zero-width");
        targets.cover(Rect::new(0, 0, 0, 0));
        targets.click(Rect::new(3, 3, 1, 1), "cell");
        assert_eq!(targets.clicked(3, 3), Some("cell"));
    }

    /// 左ボタンの押下はクリック、ホイールの上下は向き付きで返る。**離す・ドラッグ・移動・右ボタン・
    /// 横スクロールは何にも当たらない**（押して離すと2回押したことにならない）。
    #[test]
    fn only_a_left_press_and_the_vertical_wheel_resolve() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.click(Rect::new(0, 0, 5, 5), "button");
        targets.wheel(Rect::new(0, 0, 5, 5), "box");
        assert_eq!(targets.resolve(&down(1, 1)), Some(Pointer::Click("button")));
        assert_eq!(
            targets.resolve(&mouse(MouseEventKind::ScrollUp, 1, 1)),
            Some(Pointer::Wheel {
                target: "box",
                up: true
            })
        );
        assert_eq!(
            targets.resolve(&mouse(MouseEventKind::ScrollDown, 1, 1)),
            Some(Pointer::Wheel {
                target: "box",
                up: false
            })
        );
        for kind in [
            MouseEventKind::Up(MouseButton::Left),
            MouseEventKind::Drag(MouseButton::Left),
            MouseEventKind::Moved,
            MouseEventKind::Down(MouseButton::Right),
            MouseEventKind::Down(MouseButton::Middle),
            MouseEventKind::ScrollLeft,
            MouseEventKind::ScrollRight,
        ] {
            assert_eq!(targets.resolve(&mouse(kind, 1, 1)), None, "{kind:?}");
        }
        assert_eq!(targets.resolve(&down(9, 9)), None, "押せる場所の外");
    }

    /// **文章の上の押下は[`Pointer::Text`]**。上に登録した押せる場所が勝ち、覆った範囲では文章にも届かない。
    /// 押せる場所を引く`clicked`は、文章の上では何も返さない（クリックではない）。
    #[test]
    fn a_press_on_text_resolves_to_the_text_unless_something_is_on_top() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.click(Rect::new(0, 0, 20, 10), "pane");
        targets.text(TextMap::empty(Rect::new(1, 1, 18, 8)), "body");
        targets.click(Rect::new(1, 2, 18, 1), "candidate");
        assert_eq!(targets.resolve(&down(5, 4)), Some(Pointer::Text("body")));
        assert_eq!(targets.clicked(5, 4), None);
        assert_eq!(
            targets.resolve(&down(5, 2)),
            Some(Pointer::Click("candidate")),
            "上の押せる行が勝つ"
        );
        assert_eq!(
            targets.resolve(&down(0, 0)),
            Some(Pointer::Click("pane")),
            "文章の外（枠線）は下の押せる場所"
        );
        targets.cover(Rect::new(0, 0, 10, 10));
        assert_eq!(targets.resolve(&down(5, 4)), None, "覆った後ろの文章");
        // 覆った後で登録し直すと、外に見えている部分は選べる（覆った範囲は覆ったまま）。
        targets.lift_text(&"body");
        targets.cover(Rect::new(0, 0, 10, 10));
        assert_eq!(targets.resolve(&down(15, 4)), Some(Pointer::Text("body")));
        assert_eq!(targets.resolve(&down(5, 4)), None);
        assert_eq!(
            targets.text_map(&"body").map(TextMap::area),
            Some(Rect::new(1, 1, 18, 8))
        );
        assert_eq!(targets.text_map(&"other"), None);
    }

    /// `lines`を`area`へ折り返さずに上から描いたときの地図（`crate::select::map::prepare`。送れる枠が描くときと同じ部品）。
    fn map_of(lines: &[&str], area: Rect) -> TextMap {
        let lines: Vec<Line<'static>> = lines.iter().map(|l| Line::raw(l.to_string())).collect();
        let heights = vec![1; lines.len()];
        prepare(
            Text::from(lines),
            Shape {
                inner: area,
                heights: &heights,
                top: 0,
                wrapped: false,
                joins: &[],
            },
            None,
        )
        .1
    }

    fn at(line: usize, offset: usize) -> Pos {
        Pos { line, offset }
    }

    /// **[`Targets::text_at`]は、そのセルに見えている文字を答える**——文字の上なら何行目の何文字目か、文字の無いセル
    /// （行の右の空き）と別の枠の上は`None`。押せる場所は文字を隠さない（押せる行も文字として描いてある）。
    #[test]
    fn text_at_answers_the_character_drawn_on_the_cell() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.text(map_of(&["hello", "日本"], Rect::new(1, 1, 10, 3)), "body");
        targets.text(map_of(&["other"], Rect::new(1, 6, 10, 1)), "side");
        assert_eq!(targets.text_at(&"body", 1, 1), Some(at(0, 0)));
        assert_eq!(targets.text_at(&"body", 5, 1), Some(at(0, 4)));
        // 全角文字はどちらのセルでも同じ文字。
        assert_eq!(targets.text_at(&"body", 1, 2), Some(at(1, 0)));
        assert_eq!(targets.text_at(&"body", 2, 2), Some(at(1, 0)));
        assert_eq!(targets.text_at(&"body", 3, 2), Some(at(1, 1)));
        // 文字の無いセル・枠の外。
        assert_eq!(targets.text_at(&"body", 6, 1), None, "行の右の空き");
        assert_eq!(targets.text_at(&"body", 1, 3), None, "文章の無い行");
        assert_eq!(targets.text_at(&"body", 0, 1), None, "枠の外");
        // 別の枠の文字は、名前を合わせたときだけ答える。
        assert_eq!(targets.text_at(&"body", 1, 6), None);
        assert_eq!(targets.text_at(&"side", 1, 6), Some(at(0, 0)));
        // 押せる場所が上にあっても、文字はそこに描かれている。
        targets.click(Rect::new(1, 1, 10, 1), "row");
        assert_eq!(targets.text_at(&"body", 2, 1), Some(at(0, 1)));
    }

    /// **覆った範囲の文字は答えない**（重ねた枠の下に隠れている）。覆った後に[`Targets::lift_text`]で登録し直すと、
    /// 外に見えている部分は答え、後から覆った範囲は覆ったまま。後から別の枠の文章を重ねた所も答えない。
    #[test]
    fn text_at_does_not_answer_under_a_cover() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.text(map_of(&["0123456789"], Rect::new(0, 0, 10, 1)), "body");
        targets.cover(Rect::new(0, 0, 20, 5));
        assert_eq!(targets.text_at(&"body", 2, 0), None, "覆った後ろ");
        targets.lift_text(&"body");
        targets.cover(Rect::new(0, 0, 4, 1));
        assert_eq!(
            targets.text_at(&"body", 2, 0),
            None,
            "登録し直した後に覆った"
        );
        assert_eq!(
            targets.text_at(&"body", 6, 0),
            Some(at(0, 6)),
            "外に見えている"
        );
        targets.text(map_of(&["xx"], Rect::new(6, 0, 2, 1)), "modal");
        assert_eq!(
            targets.text_at(&"body", 6, 0),
            None,
            "上に重ねた別の枠の文章"
        );
        assert_eq!(targets.text_at(&"body", 8, 0), Some(at(0, 8)));
    }

    /// **[`Targets::text_cell`]は[`Targets::text_at`]の逆**——位置からその文字を描いたセルの矩形を返す
    /// （全角文字は2桁）。見えていない文字・描いていない枠は`None`。
    #[test]
    fn text_cell_is_the_inverse_of_text_at() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.text(map_of(&["ab", "日本"], Rect::new(3, 2, 10, 2)), "body");
        assert_eq!(
            targets.text_cell(&"body", at(0, 1)),
            Some(Rect::new(4, 2, 1, 1))
        );
        assert_eq!(
            targets.text_cell(&"body", at(1, 1)),
            Some(Rect::new(5, 3, 2, 1))
        );
        assert_eq!(
            targets.text_cell(&"body", at(0, 2)),
            None,
            "行の末尾より後ろ"
        );
        assert_eq!(targets.text_cell(&"body", at(5, 0)), None, "無い行");
        assert_eq!(
            targets.text_cell(&"other", at(0, 0)),
            None,
            "描いていない枠"
        );
        for (x, y) in [(3, 2), (4, 2), (5, 3), (6, 3)] {
            let pos = targets.text_at(&"body", x, y).expect("文字の上");
            let cell = targets.text_cell(&"body", pos).expect("描いたセル");
            assert!(
                cell.contains(Position::new(x, y)),
                "({x}, {y}) → {pos:?} → {cell:?}"
            );
        }
    }

    /// 文章を描く矩形が空なら登録しない（押せない）。
    #[test]
    fn an_empty_text_area_is_not_registered() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.text(TextMap::empty(Rect::new(1, 1, 0, 3)), "body");
        assert_eq!(targets.text_map(&"body"), None);
    }

    /// [`acts`]が偽の種類は、押せる場所と送れる場所の真上でも何にも当たらず、真の種類は当たる
    /// （イベントループが[`acts`]で描き直しを省いても、省いたイベントで変わるものが無い）。
    #[test]
    fn acts_is_exactly_the_kinds_that_resolve() {
        let mut targets: Targets<&str, &str> = Targets::default();
        targets.click(Rect::new(0, 0, 5, 5), "button");
        targets.wheel(Rect::new(0, 0, 5, 5), "box");
        for kind in [
            MouseEventKind::Down(MouseButton::Left),
            MouseEventKind::Down(MouseButton::Right),
            MouseEventKind::Down(MouseButton::Middle),
            MouseEventKind::Up(MouseButton::Left),
            MouseEventKind::Drag(MouseButton::Left),
            MouseEventKind::Moved,
            MouseEventKind::ScrollUp,
            MouseEventKind::ScrollDown,
            MouseEventKind::ScrollLeft,
            MouseEventKind::ScrollRight,
        ] {
            assert_eq!(
                acts(kind),
                targets.resolve(&mouse(kind, 1, 1)).is_some(),
                "{kind:?}"
            );
        }
    }
}
