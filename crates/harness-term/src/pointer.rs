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
//! # 限界
//!
//! - **左ボタンを押した瞬間**（`Down`）をクリックとする。離した瞬間（`Up`）・ドラッグ・右/中ボタン・横スクロールは
//!   何にも当たらない。押してから外へずらして取り消す、という操作は無い。
//! - 描いてから次に描くまでの間に状態が変わる作りでは、古い画面で引くことになる（1イベントごとに描き直すこと）。

use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};

/// 登録した場所の1件。
#[derive(Debug, Clone)]
enum Entry<C, W> {
    /// クリックを受ける。
    Click(Rect, C),
    /// ホイールを受ける。
    Wheel(Rect, W),
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

    /// `(column, row)`をクリックしたときの動き。押せる場所でなければ`None`。
    pub fn clicked(&self, column: u16, row: u16) -> Option<C> {
        let at = Position::new(column, row);
        for entry in self.entries.iter().rev() {
            match entry {
                Entry::Click(area, target) if area.contains(at) => return Some(target.clone()),
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
                self.clicked(event.column, event.row).map(Pointer::Click)
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

/// この種類のイベントが[`Targets::resolve`]で何かに当たり得るか（左ボタンの押下とホイールの上下）。
///
/// **当たり得ない種類（ポインタの移動・離す・ドラッグ・右/中ボタン・横スクロール）は、画面の何も変えない。**
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

    use super::*;

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
