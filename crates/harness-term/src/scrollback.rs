//! 末尾追従のスクロール表示。**会話TUIのtranscriptとポリシーエディタの記録画面が共有する。**
//!
//! # なぜ共有するのか
//!
//! ポリシーエディタ側に別実装を書いたところ、`Wrap`が効いている枠で**折り返し前の
//! バッファ行**を数えてしまい、長い行（cargoのビルドログ等）があるだけでスクロール量と
//! 見えているものがずれた。transcript側は最初からこの罠を避けており
//! （`Paragraph::line_count`で折り返し後の行を数える。いまは`crate::wrap::rows`）、しかも
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
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Block;
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
    render_inner(frame, area, lines, block, scroll, None)
}

/// [`render`]に加えて、本文が枠に収まらないときだけ右の枠線の上にスクロールバーを描く
/// （先頭から読ませる枠と同じ見た目。[`crate::scrollable::draw_scrollbar`]）。`bar`は枠線と同じ色を渡す。
///
/// 下端に貼り付いている間は、つまみが一番下に付いている。会話TUIのtranscriptが使う
/// （ポリシーエディタの記録画面の3枠は[`render`]のままで、スクロールバーを出さない）。
pub fn render_with_bar(
    frame: &mut Frame,
    area: Rect,
    lines: Vec<Line<'static>>,
    block: Block<'static>,
    scroll: Scrollback,
    bar: Style,
) -> u16 {
    render_inner(frame, area, lines, block, scroll, Some(bar))
}

fn render_inner(
    frame: &mut Frame,
    area: Rect,
    lines: Vec<Line<'static>>,
    block: Block<'static>,
    scroll: Scrollback,
    bar: Option<Style>,
) -> u16 {
    // 折り返し後の行数で数える。ここをバッファ行にすると、長い行がある枠で
    // 末尾まで戻り切れなくなる（モジュールdoc）。数える幅と描く幅は`crate::wrap`が揃える
    // （行末の全角文字が右の枠線を覆わないよう、どちらも右端の1桁を空ける。BUG-200）。
    let inner = block.inner(area);
    let rows = crate::wrap::rows(lines.clone(), inner.width);
    let total = u16::try_from(rows).unwrap_or(u16::MAX);
    let max_offset = total.saturating_sub(inner.height);
    // 表示にはクランプ後の値を使う（状態そのものは呼び出し側が`clamp`で直す）。
    let offset = scroll.offset().min(max_offset);
    let top = max_offset.saturating_sub(offset);

    crate::wrap::Wrapped::new(lines)
        .block(block)
        .scroll(top)
        .render(frame, area);
    if let Some(bar) = bar {
        // 末尾追従の位置（下端からの距離）を、上端からの位置へ直して渡す（同じ見た目のスクロールバー）。
        let window = crate::scrollable::Window::new(rows, usize::from(inner.height), top);
        crate::scrollable::draw_scrollbar(frame, area, window, bar);
    }
    max_offset
}

/// さかのぼり中であることを枠のタイトルへ足す。
///
/// **言わないと「出力が止まった」と読まれる**——下端に貼り付いていないだけなのに、
/// 新しい行が見えなくなるため。戻し方も一緒に出す。
pub fn title_with_scroll(base: &str, scroll: Scrollback, hint: &str) -> String {
    format!(
        "{base}{}",
        scrolled_notice(scroll, hint).unwrap_or_default()
    )
}

/// [`title_with_scroll`]が見出しへ足す「さかのぼり中」の注記だけ。下端に貼り付いていれば`None`。
///
/// 注記を押せる項目として見出しとは別に描くとき（会話TUIのtranscriptは、押すと末尾へ戻る）に使う。
pub fn scrolled_notice(scroll: Scrollback, hint: &str) -> Option<String> {
    (!scroll.is_pinned()).then(|| format!("[{}行 さかのぼり中・{hint}] ", scroll.offset()))
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

    /// [BUG-200] **行の最後の全角文字が、右の枠線を覆わない。** ratatuiの単語折り返しは、
    /// 語の最後の全角文字が行の最後の1桁から始まると、その行を1桁長くする。はみ出した後半が
    /// 右の枠線の桁に掛かると、枠線のセルは端末へ送られない（全角文字の後半として飛ばされる）。
    /// 会話TUIのtranscriptとポリシーエディタの記録画面の枠がここを通る。
    #[test]
    fn a_line_ending_in_a_wide_character_does_not_cover_the_right_border() {
        use ratatui::backend::TestBackend;
        use ratatui::widgets::Borders;
        use ratatui::Terminal;

        for width in [40u16, 41] {
            let lines = vec![Line::raw(crate::spilling_line(width - 2))];
            let mut term = Terminal::new(TestBackend::new(width, 6)).expect("test terminal");
            term.draw(|frame| {
                render(
                    frame,
                    frame.area(),
                    lines,
                    Block::default().borders(Borders::ALL),
                    Scrollback::default(),
                );
            })
            .expect("draw");
            let buffer = term.backend().buffer();
            let right: Vec<&str> = (0..6).map(|y| buffer[(width - 1, y)].symbol()).collect();
            assert_eq!(
                right,
                ["┐", "│", "│", "│", "│", "┘"],
                "幅{width}: 右の枠線が欠けた"
            );
        }
    }

    /// スクロールバーを描く版で、`n`行の本文を下端から`offset`行さかのぼって描き、右の枠線（角を除く）を返す。
    fn right_border_with_bar(n: usize, offset: i32) -> Vec<String> {
        use ratatui::backend::TestBackend;
        use ratatui::widgets::Borders;
        use ratatui::Terminal;

        let lines: Vec<Line<'static>> = (0..n).map(|i| Line::raw(format!("{i}"))).collect();
        let mut scroll = Scrollback::default();
        scroll.scroll_lines(offset);
        let mut term = Terminal::new(TestBackend::new(20, 8)).expect("test terminal");
        term.draw(|frame| {
            render_with_bar(
                frame,
                frame.area(),
                lines,
                Block::default().borders(Borders::ALL),
                scroll,
                Style::default(),
            );
        })
        .expect("draw");
        let buffer = term.backend().buffer();
        (1..7)
            .map(|y| buffer[(19, y)].symbol().to_string())
            .collect()
    }

    /// **スクロールバーは収まらないときだけ出て、つまみは下端追従なら一番下、先頭までさかのぼれば一番上に付く。**
    #[test]
    fn the_scrollbar_follows_the_bottom_and_appears_only_when_overflowing() {
        assert!(right_border_with_bar(6, 0).iter().all(|c| c == "│"));
        let pinned = right_border_with_bar(40, 0);
        assert_eq!(pinned.last().map(String::as_str), Some("█"), "{pinned:?}");
        assert_eq!(pinned.first().map(String::as_str), Some("│"), "{pinned:?}");
        let top = right_border_with_bar(40, 1000);
        assert_eq!(top.first().map(String::as_str), Some("█"), "{top:?}");
        assert_eq!(top.last().map(String::as_str), Some("│"), "{top:?}");
    }

    /// 見出しへ足す注記と、注記だけを返す関数は同じ文字列（注記を押せる項目として別に描く側とずれない）。
    #[test]
    fn the_scrolled_notice_is_what_the_title_appends() {
        let mut scroll = Scrollback::default();
        assert_eq!(scrolled_notice(scroll, "戻す"), None);
        scroll.scroll_lines(7);
        let notice = scrolled_notice(scroll, "戻す").expect("さかのぼり中");
        assert_eq!(
            title_with_scroll(" 出力 ", scroll, "戻す"),
            format!(" 出力 {notice}")
        );
    }
}
