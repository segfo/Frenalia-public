//! 末尾追従のスクロール表示。**会話TUIのtranscriptとポリシーエディタの記録画面が共有する。**
//!
//! # なぜ共有するのか
//!
//! ポリシーエディタ側に別実装を書いたところ、`Wrap`が効いている枠で**折り返し前の
//! バッファ行**を数えてしまい、長い行（cargoのビルドログ等）があるだけでスクロール量と
//! 見えているものがずれた。transcript側は最初からこの罠を避けており
//! （`Paragraph::line_count`で折り返し後の行を数える）、しかも
//! [`BUG-076`]の教訓——**クランプを描画側だけでやると状態が青天井に伸び続ける**——まで
//! 織り込まれている。同じものを2つ持つ理由が無い（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
//!
//! # 単位は「折り返し後の表示行」
//!
//! [`Scrollback::offset`]は**画面下端から何行さかのぼっているか**で、数えるのは
//! 折り返し後の行である。折り返し前のバッファ行で数えると、1行が3行に折り返される枠では
//! 「3行戻したのに9行動く」ことになり、末尾まで戻り切れない／行き過ぎる。
//!
//! # 上限は描画してみるまで分からない
//!
//! 総行数は枠の幅に依存する（折り返し）ので、入力を受け取る時点では上限を計算できない。
//! そこで[`render`]が**その描画で判明した上限**を返し、呼び出し側が
//! [`Scrollback::clamp`]で状態そのものを切り詰める。描画側だけでクランプすると、
//! 先頭まで遡った後もホイールを回した分だけ内部の値が伸び続け、戻すときに空回りする
//! （BUG-076の再発）。

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

/// ホイール1刻みで動かす行数（端末の既定送り量に合わせる）。
pub const WHEEL_SCROLL_LINES: i32 = 3;
/// PageUp/PageDownで動かす行数。
pub const PAGE_SCROLL_LINES: i32 = 10;

/// 末尾追従のスクロール位置。`0`＝下端に貼り付いている（新着に追従する）。
///
/// **持っているのは「下端からの距離」だけ**で、総行数も枠の大きさも知らない。
/// 上限は描画のたびに[`render`]から受け取って[`Self::clamp`]で切り詰める（モジュールdoc）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Scrollback {
    offset: u16,
}

impl Scrollback {
    /// 下端から何行さかのぼっているか（折り返し後の表示行）。
    pub fn offset(self) -> u16 {
        self.offset
    }

    /// 下端に貼り付いているか（＝新着に追従する状態か）。
    pub fn is_pinned(self) -> bool {
        self.offset == 0
    }

    /// 正で過去へ、負で末尾へ。0未満にはならない。
    ///
    /// **上限はここでは掛けない**——総行数を知らないため。行き過ぎた分は次の描画後の
    /// [`Self::clamp`]で切り詰める。
    pub fn scroll_lines(&mut self, delta: i32) {
        if delta >= 0 {
            self.offset = self.offset.saturating_add(delta as u16);
        } else {
            self.offset = self.offset.saturating_sub((-delta) as u16);
        }
    }

    pub fn scroll_page(&mut self, delta: i32) {
        self.scroll_lines(delta * PAGE_SCROLL_LINES);
    }

    /// ホイール1刻み。`up`が真なら過去へ。
    pub fn wheel(&mut self, up: bool) {
        self.scroll_lines(if up {
            WHEEL_SCROLL_LINES
        } else {
            -WHEEL_SCROLL_LINES
        });
    }

    /// 末尾へ戻して追従を再開する。
    pub fn reset(&mut self) {
        self.offset = 0;
    }

    /// 直近の描画で判明した上限まで切り詰める（[`render`]の戻り値を渡す）。
    ///
    /// **これを怠ると**、先頭まで遡った後もホイールを回した分だけ`offset`が伸び続け、
    /// 下へ戻すときに伸びた分だけ空回りする（BUG-076）。
    pub fn clamp(&mut self, max_offset: u16) {
        if self.offset > max_offset {
            self.offset = max_offset;
        }
    }
}

/// 末尾追従で`lines`を描き、**この描画で判明した`offset`の上限**を返す。
///
/// 呼び出し側は戻り値で[`Scrollback::clamp`]を呼ぶこと（モジュールdoc）。
pub fn render(
    frame: &mut Frame,
    area: Rect,
    lines: Vec<Line<'static>>,
    block: Block<'static>,
    scroll: Scrollback,
) -> u16 {
    // 折り返し後の行数で数える。ここをバッファ行にすると、長い行がある枠で
    // 末尾まで戻り切れなくなる（モジュールdoc）。
    let text_width = area.width.saturating_sub(2);
    let total = Paragraph::new(lines.clone())
        .wrap(Wrap { trim: false })
        .line_count(text_width)
        .min(u16::MAX as usize) as u16;
    let viewport = area.height.saturating_sub(2);
    let max_offset = total.saturating_sub(viewport);
    // 表示にはクランプ後の値を使う（状態そのものは呼び出し側が`clamp`で直す）。
    let offset = scroll.offset().min(max_offset);
    let top = max_offset.saturating_sub(offset);

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((top, 0)),
        area,
    );
    max_offset
}

/// さかのぼり中であることを枠のタイトルへ足す。
///
/// **言わないと「出力が止まった」と読まれる**——下端に貼り付いていないだけなのに、
/// 新しい行が見えなくなるため。戻し方も一緒に出す。
pub fn title_with_scroll(base: &str, scroll: Scrollback, hint: &str) -> String {
    if scroll.is_pinned() {
        base.to_string()
    } else {
        format!("{base}[{}行 さかのぼり中・{hint}] ", scroll.offset())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_scrollback_is_pinned_to_the_bottom() {
        let scroll = Scrollback::default();
        assert!(scroll.is_pinned());
        assert_eq!(scroll.offset(), 0);
    }

    #[test]
    fn scroll_lines_clamps_at_zero_and_saturates_upward() {
        let mut scroll = Scrollback::default();
        scroll.scroll_lines(-5);
        assert_eq!(scroll.offset(), 0, "下端より先へは行かない");
        scroll.scroll_lines(3);
        assert_eq!(scroll.offset(), 3);
        scroll.scroll_lines(-1);
        assert_eq!(scroll.offset(), 2);
        scroll.scroll_lines(i32::MAX);
        assert_eq!(scroll.offset(), u16::MAX, "飽和して折り返さない");
    }

    /// **BUG-076の回帰。** 上限を超えて遡ろうとした分を溜め込まない。
    /// 溜め込むと、下へ戻すときに溜まった分だけ空回りして「戻らない」ように見える。
    #[test]
    fn scrolling_past_the_top_does_not_bank_up_an_invisible_offset() {
        let mut scroll = Scrollback::default();
        scroll.scroll_lines(30);
        assert_eq!(scroll.offset(), 30, "入力の時点では素直に加算される");

        scroll.clamp(3); // 描画で上限が判明する
        assert_eq!(scroll.offset(), 3);

        // 3回下へ戻せば下端に着く（溜め込んでいれば着かない）。
        scroll.scroll_lines(-3);
        assert_eq!(scroll.offset(), 0);
        assert!(scroll.is_pinned());
    }

    /// 上限内なら`clamp`は何もしない（常時切り詰めて位置を失う、という逆の壊れ方をしない）。
    #[test]
    fn clamp_leaves_a_position_that_is_within_range() {
        let mut scroll = Scrollback::default();
        scroll.scroll_lines(5);
        scroll.clamp(100);
        assert_eq!(scroll.offset(), 5);
    }

    #[test]
    fn the_wheel_moves_by_the_terminal_notch_size() {
        let mut scroll = Scrollback::default();
        scroll.wheel(true);
        assert_eq!(scroll.offset(), WHEEL_SCROLL_LINES as u16);
        scroll.wheel(false);
        assert!(scroll.is_pinned());
    }

    /// タイトルは**さかのぼっている間だけ**変える。貼り付いている間に注記を出すと、
    /// 常に何かが起きているように見えて注意が鈍る。
    #[test]
    fn the_title_only_says_something_while_scrolled_back() {
        let mut scroll = Scrollback::default();
        assert_eq!(
            title_with_scroll(" 出力 ", scroll, "ホイールで戻る"),
            " 出力 "
        );

        scroll.scroll_lines(4);
        let title = title_with_scroll(" 出力 ", scroll, "ホイールで戻る");
        assert!(title.contains('4'), "何行さかのぼっているかを出す: {title}");
        assert!(
            title.contains("ホイールで戻る"),
            "戻し方も出す（出さないと止まったと読まれる）: {title}"
        );
    }
}
