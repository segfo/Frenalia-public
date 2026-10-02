//! 先頭から読ませる、送れる枠（会話TUIとポリシーエディタが共有する）。
//!
//! # 何のためにあるのか
//!
//! 本文が枠に入り切らないとき、どの枠も同じ形で送らせる——送る上限は「本文の最後の行が枠の一番下に
//! 来たところ」（[`Window`]。[BUG-196](../../../docs/bugs/BUG-196.md)）、右の枠線の上にスクロールバー、
//! 下辺の右に「N〜M/T行」と送り方。入り切る枠には何も足さない。もとはポリシーエディタの確認ダイアログ・
//! ヘルプ・説明欄が使っていた部品で、会話TUIの承認ダイアログも同じ形を要るので、ここへ移した
//! （`harness_term::scrollback`・`wrap`・`overlay`を移したのと同じ理由。`docs/CODE-STRUCTURE-RULES.md`§5.0）。
//!
//! 末尾に貼り付いて新着を追う枠（ログ）は[`crate::scrollback`]が持つ。こちらは**上端からの位置**で持ち、
//! 既定は先頭である（判断の材料を先に置いた本文を、頭から読ませるため）。
//!
//! # 上限は描くまで分からない
//!
//! 総行数は枠の幅で折り返した結果なので、キーやホイールを受けた時点では決まらない。だから受けた側は上限を
//! 掛けずに進め、[`draw`]が返す上限で呼び出し側が状態を切り詰める（[`crate::scrollback`]・会話TUIの
//! 承認ダイアログと同じ形。描画の側だけで切り詰めると、末尾で押した分が状態に溜まって戻すときに
//! 空回りする——BUG-076）。
//!
//! # 下辺の左にボタンを置ける（[`draw_with_buttons`]）
//!
//! 確認ダイアログは「何を押せば書くか」を枠の下辺に固定で置く（本文の最後に置くと、本文が長いときに
//! 枠の外へ消えるため）。それを押せるようにするため、ボタンを下辺の左に描いて**描いた位置を返す**
//! （[`crate::pointer`]へ登録する）。下辺の右の「N〜M/T行」はボタンの残りの幅に収まる形を選ぶので、
//! **ボタンには重ならない**（押すべきものが案内に覆われない）。
//!
//! # 本文の行が描かれた場所も返す（[`Drawn::lines`]）
//!
//! 本文の中の行を押せるようにする枠がある（会話TUIの承認ダイアログの「毎回変わってよい引数」の候補、
//! 差分ペインのハンクの見出し）。どの行が画面のどこに来たかは、折り返した行数と送り位置で決まるので、
//! 描いたここで求めて返す——呼び出し側が折り返しと送りを計算し直すと、描いた場所と押せる場所がずれる
//! （ポリシーエディタの[BUG-194](../../../docs/bugs/BUG-194.md)）。
//!
//! # 折り返さない枠もある（[`draw_unwrapped`]）
//!
//! 行の番号をそのまま表示行の番号として送る枠（会話TUIの差分ペイン。ハンクの見出しへ追従するとき、状態の側が
//! 本文の何行目を一番上に出すかを決める）は、折り返すと番号がずれる。そういう枠は折り返さずに描き、
//! 送る上限・スクロールバー・下辺の「N〜M/T行」だけを同じ形にする。
//!
//! # 限界
//!
//! - 折り返し方そのもの（空白で切り、日本語の禁則を見ない）は[`crate::wrap`]のまま。
//! - ボタンは枠に下辺の枠線があることを前提に、その線の上へ描く。

use ratatui::layout::{Margin, Rect};
use ratatui::style::Style;
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;

use crate::wrap::{line_rows, Wrapped};

/// 送れる枠の見せ方。入り切らないときにだけ使う（入り切る枠は何も変わらない）。
#[derive(Debug, Clone, Copy)]
pub struct Look {
    /// 下辺の「N〜M/T行」の後ろに添える送り方。**効く手段だけを書く**（B-32）。
    pub how: &'static str,
    /// 下辺の「N〜M/T行」の色。
    pub notice: Style,
    /// スクロールバーの色。**枠線と同じ色を渡す**（スクロールバーは右の枠線の上に描くので、
    /// 違う色にすると枠線の途中で色が変わる）。
    pub bar: Style,
}

/// [`draw_with_buttons`]・[`draw_unwrapped`]が描いた結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawn {
    /// この描画で分かった送れる上限（[`Window::max_top`]）。
    pub max_top: u16,
    /// ボタンが描かれた矩形（渡したボタンと同じ数・同じ順。入り切らなかったものは幅0）。
    pub buttons: Vec<Rect>,
    /// 本文の各行（渡した`Text`の行と同じ数・同じ順）が描かれた矩形。折り返した行は複数行の高さを持ち、
    /// 枠の上下で切れた行は見えている部分だけ、まったく見えていない行は高さ0（押せない）。
    /// 本文の中の行を押せるようにするとき（一覧の候補・ハンクの見出し）に、その行の場所として使う。
    pub lines: Vec<Rect>,
}

/// 送れる枠を描き、**この描画で分かった送れる上限**を返す。
///
/// `top`は状態が持つ送り量（枠の一番上に見せる、折り返した後の表示行）。上限を超えていても、描く位置だけを
/// 上限へ切り詰める。呼び出し側は戻り値で状態の側を切り詰める（モジュールdoc。BUG-076）。
///
/// 本文が入り切らないときだけ、下辺の右に「N〜M/T行  送り方」を出し、右の枠線の上にスクロールバーを出す。
/// 下辺が狭い枠では送り方を落とす（[`Window::notice`]）。
pub fn draw<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    top: u16,
    look: Look,
) -> u16 {
    draw_with_buttons(frame, area, text, block, top, look, &[]).max_top
}

/// [`draw`]に加えて、下辺の左に`buttons`を描き、それぞれが描かれた矩形を返す（モジュールdoc）。
/// 本文の各行が描かれた矩形も返す（[`Drawn::lines`]）。
pub fn draw_with_buttons<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    top: u16,
    look: Look,
    buttons: &[Span],
) -> Drawn {
    draw_text(frame, area, text.into(), block, top, look, buttons, true)
}

/// [`draw`]と同じ送れる枠を、**折り返さずに**描く（長い行は右で切る。1行は必ず1つの表示行）。
///
/// 行の番号がそのまま表示行の番号になるので、状態の側が「何行目を枠の一番上に出すか」を本文の行で決める枠
/// （会話TUIの差分ペインのハンクへの追従）に使う。送る上限・スクロールバー・下辺の「N〜M/T行」は[`draw`]と同じ。
/// 右で切った行の全角文字は、入り切らなければ描かれない（右の枠線を覆わない。ratatuiの切り方）。
pub fn draw_unwrapped<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    top: u16,
    look: Look,
) -> Drawn {
    draw_text(frame, area, text.into(), block, top, look, &[], false)
}

/// [`draw_with_buttons`]と[`draw_unwrapped`]の本体（違うのは行を折り返すかだけ）。
#[allow(clippy::too_many_arguments)]
fn draw_text<'a>(
    frame: &mut Frame,
    area: Rect,
    text: Text<'a>,
    block: Block<'a>,
    top: u16,
    look: Look,
    buttons: &[Span],
    wrapped: bool,
) -> Drawn {
    let inner = block.inner(area);
    // 行ごとの表示行の数。合計が本文全体の表示行の数（`crate::wrap::line_rows`のdoc）。
    let heights = if wrapped {
        line_rows(text.clone(), inner.width)
    } else {
        vec![1; text.lines.len()]
    };
    let window = Window::new(heights.iter().sum(), usize::from(inner.height), top);
    // 下辺のうち、左右の角とボタン（とその後ろの1桁）を除いた幅。
    let taken = if buttons.is_empty() {
        0
    } else {
        crate::row::width(buttons).saturating_add(1)
    };
    let room = area.width.saturating_sub(2).saturating_sub(taken);
    let block = match window.notice(look.how, room) {
        Some(notice) => block.title_bottom(Line::styled(notice, look.notice).right_aligned()),
        None => block,
    };
    let scroll = u16::try_from(window.top).unwrap_or(u16::MAX);
    if wrapped {
        Wrapped::new(text)
            .block(block)
            .scroll(scroll)
            .render(frame, area);
    } else {
        frame.render_widget(Paragraph::new(text).block(block).scroll((scroll, 0)), area);
    }
    draw_scrollbar(frame, area, window, look.bar);
    let buttons = if buttons.is_empty() || area.height == 0 {
        vec![Rect::default(); buttons.len()]
    } else {
        crate::row::draw(frame, crate::row::bottom_edge(area), buttons)
    };
    Drawn {
        max_top: u16::try_from(window.max_top()).unwrap_or(u16::MAX),
        buttons,
        lines: line_areas(inner, &heights, window),
    }
}

/// 行ごとの表示行の数`heights`と、いま見せている範囲`window`から、各行が描かれた矩形を求める
/// （`Paragraph::scroll`が「上から`top`表示行を飛ばして描く」のと同じ規則）。
fn line_areas(inner: Rect, heights: &[usize], window: Window) -> Vec<Rect> {
    let (shown_from, shown_to) = (window.top, window.top + window.visible);
    let mut start = 0usize;
    heights
        .iter()
        .map(|&height| {
            let (from, to) = (start.max(shown_from), (start + height).min(shown_to));
            start += height;
            let y = |row: usize| {
                inner
                    .y
                    .saturating_add(u16::try_from(row - shown_from).unwrap_or(u16::MAX))
            };
            if from < to {
                Rect::new(
                    inner.x,
                    y(from),
                    inner.width,
                    u16::try_from(to - from).unwrap_or(u16::MAX),
                )
            } else {
                Rect::new(inner.x, y(from.min(shown_to)), inner.width, 0)
            }
        })
        .collect()
}

/// 送れる枠で、いま見せている範囲（[BUG-196](../../../docs/bugs/BUG-196.md)）。
/// **数えるのはどれも折り返した後の表示行**で、[`crate::wrap::rows`]・`Paragraph::scroll`・下辺の「N〜M/T行」と同じ単位である。
///
/// # 送る上限は「本文の最後の行が枠の一番下の行に来たところ」
///
/// 上限は`total - visible`。最後の行が枠の一番上に来るまで送れると、末尾では枠がほぼ空になり、
/// どこまで読めば終わりかが分からない。本文が枠に収まるなら上限は0で、送れない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// 本文を折り返した後の行数。
    total: usize,
    /// 枠の中に見える行数。
    visible: usize,
    /// 枠の一番上に見せる表示行（0始まり）。**上限で切り詰め済み**。
    top: usize,
}

impl Window {
    /// `scroll`は状態が持つ送り量。上限を超えていても、ここでは描く位置だけを上限へ切り詰める。
    pub fn new(total: usize, visible: usize, scroll: u16) -> Self {
        let top = usize::from(scroll).min(total.saturating_sub(visible));
        Self {
            total,
            visible,
            top,
        }
    }

    /// 枠の一番上に見せる表示行（上限で切り詰め済み）。
    pub fn top(self) -> usize {
        self.top
    }

    /// 送れる上限（最後の行が枠の一番下の行に来るときの[`Self::top`]）。
    pub fn max_top(self) -> usize {
        self.total.saturating_sub(self.visible)
    }

    /// 本文が枠に収まらない（＝送れる）か。
    pub fn overflows(self) -> bool {
        self.total > self.visible
    }

    /// 下辺に出す「いま何行目から何行目を見ているか」と送り方。**残りがあることが分からないと、
    /// 読み切ったつもりで判断してしまう**（B-09）。本文が収まっていれば`None`（何も出さない）。
    ///
    /// `room`は下辺に使える桁数。**入らなければ送り方を落とし、それでも入らなければ出さない**——右寄せの見出しは
    /// 入り切らないと**左から**切れるので、「1〜3/10行」の頭の行番号が消えて別の範囲に読める。
    /// 落としてもスクロールバーは残る。
    pub fn notice(self, how: &str, room: u16) -> Option<String> {
        use unicode_width::UnicodeWidthStr;

        if !self.overflows() {
            return None;
        }
        let position = format!(
            "{}〜{}/{}行",
            (self.top + 1).min(self.total),
            (self.top + self.visible).min(self.total),
            self.total
        );
        [format!(" {position}  {how} "), format!(" {position} ")]
            .into_iter()
            .find(|notice| notice.width() <= usize::from(room))
    }
}

/// 右の枠線の上にスクロールバーを描く。
///
/// # スクロールバーは枠線の上に描く
///
/// 内側に描くと、本文の右端に空けてある1桁（行末の全角文字のはみ出し用。BUG-200）を潰すので、
/// 折り返しの幅をさらに減らし、[`crate::wrap::rows`]で数える幅もそれに合わせることになる。枠線の上なら本文の幅は
/// 変わらず、数えた行数と描いた行数の一致に触らない。線は枠線と同じ記号・同じ色にし、つまみだけを`█`にするので、
/// 収まらないときは右の枠線の一部がつまみに変わって見える。上下の矢印は付けない（つまみが端に付いたことで
/// 先頭・末尾を言うため。矢印を付けると、端に付いても矢印との間に線が残る）。
///
/// **送れることはスクロールバーだけでは伝わらない**（キーやホイールで送れることは絵から読めない）ので、
/// 下辺の「N〜M/T行」に送り方を添える（[`Look::how`]）。
///
/// この枠の外でも使う——末尾追従の枠（[`crate::scrollback::render_with_bar`]）と、行を押せる一覧
/// （会話TUIのレビューパネル。`window`は一覧の項目の数・見えている項目の数・表示を始める位置）が、同じ見た目の
/// スクロールバーをここで描く。`area`は枠全体（上下の角を除いた右の枠線の上に描く）。**本文が収まっていれば
/// （[`Window::overflows`]が偽）何も描かない**——送れない枠に「先頭に居る」つまみを出さない。
pub fn draw_scrollbar(frame: &mut Frame, area: Rect, window: Window, bar: Style) {
    if !window.overflows() {
        return;
    }
    // ratatuiの`ScrollbarState`は「送れる位置の数」と「見えている量」で数える。位置は0〜上限の
    // `上限+1`通り、見えている量は`visible`——こう渡すと、先頭でつまみが一番上、上限で一番下に付く。
    let mut state = ScrollbarState::new(window.max_top() + 1)
        .position(window.top)
        .viewport_content_length(window.visible);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some(symbols::line::VERTICAL))
            .thumb_symbol(symbols::block::FULL)
            .style(bar),
        // 右の枠線のうち、上下の角を除いた部分。
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::widgets::Borders;
    use ratatui::Terminal;

    use super::*;

    const LOOK: Look = Look {
        how: "↑↓ PgUp/PgDn・ホイールで送る",
        notice: Style::new(),
        bar: Style::new(),
    };

    fn bottom_row(buffer: &Buffer, area: Rect) -> String {
        (area.x..area.right())
            .map(|x| buffer[(x, area.bottom() - 1)].symbol())
            .collect()
    }

    /// 本文が`lines`行の枠を`width`桁で描き、ボタンの矩形と画面を返す。
    fn paint(width: u16, lines: usize, buttons: &[Span]) -> (Drawn, Buffer) {
        let text: Vec<Line> = (0..lines).map(|i| Line::raw(format!("{i}"))).collect();
        let mut term = Terminal::new(TestBackend::new(width, 8)).expect("test terminal");
        let mut result = None;
        term.draw(|f| {
            result = Some(draw_with_buttons(
                f,
                f.area(),
                text,
                Block::default().borders(Borders::ALL),
                0,
                LOOK,
                buttons,
            ));
        })
        .expect("draw");
        (result.expect("描いた"), term.backend().buffer().clone())
    }

    fn buttons() -> Vec<Span<'static>> {
        vec![
            Span::raw(" y=書く "),
            Span::raw(" "),
            Span::raw(" n / Esc=やめる "),
        ]
    }

    /// **ボタンは下辺の左（角の隣）に描かれ、返した矩形にその文字がある。**
    #[test]
    fn the_buttons_are_drawn_on_the_bottom_edge_where_they_are_returned() {
        let buttons = buttons();
        let (drawn, buffer) = paint(80, 20, &buttons);
        assert_eq!(drawn.buttons.len(), 3);
        assert_eq!(drawn.buttons[0].x, 1, "左の角の隣から");
        for (span, rect) in buttons.iter().zip(&drawn.buttons) {
            assert_eq!(rect.y, 7, "下辺");
            let text: String = (rect.x..rect.right())
                .map(|x| buffer[(x, rect.y)].symbol())
                .collect();
            assert_eq!(text.replace(' ', ""), span.content.replace(' ', ""));
        }
    }

    /// **下辺の右の「N〜M/T行」はボタンに重ならない。** 幅が足りなければ送り方を落とし、それでも足りなければ出さない
    /// ——ボタン（押すべきもの）が案内に覆われない。
    #[test]
    fn the_position_notice_never_covers_the_buttons() {
        let buttons = buttons();
        for width in [80u16, 50, 40, 30, 20] {
            let (drawn, buffer) = paint(width, 20, &buttons);
            let row = bottom_row(&buffer, Rect::new(0, 0, width, 8)).replace(' ', "");
            let wanted: String = buttons
                .iter()
                .map(|b| b.content.replace(' ', ""))
                .collect::<String>();
            let fits = drawn
                .buttons
                .iter()
                .zip(&buttons)
                .all(|(rect, button)| usize::from(rect.width) == button.width());
            if fits {
                assert!(row.contains(&wanted), "幅{width}: ボタンが覆われた: {row}");
            }
            if row.contains('〜') {
                assert!(
                    row.contains("1〜6/20行"),
                    "幅{width}: 行番号が切れた: {row}"
                );
            }
        }
        // 十分な幅なら、ボタンと送り方の両方が出る（許可側）。
        let (_, buffer) = paint(80, 20, &buttons);
        let row = bottom_row(&buffer, Rect::new(0, 0, 80, 8)).replace(' ', "");
        assert!(row.contains("ホイールで送る"), "{row}");
    }

    /// 本文が入り切るときは上限0で、下辺にはボタンだけ（位置の案内もスクロールバーも出ない）。
    #[test]
    fn a_text_that_fits_has_no_notice_and_cannot_scroll() {
        let (drawn, buffer) = paint(40, 3, &buttons());
        assert_eq!(drawn.max_top, 0);
        let row = bottom_row(&buffer, Rect::new(0, 0, 40, 8));
        assert!(!row.contains('〜'), "{row}");
        let (overflowing, _) = paint(40, 20, &[]);
        assert_eq!(
            overflowing.max_top,
            20 - 6,
            "上限は最後の行が枠の一番下に来るところ"
        );
        assert!(overflowing.buttons.is_empty());
    }

    /// 本文の行`i`は`<i>`で始まり、`width`に応じて折り返す長さを持つ（どの行が画面のどこに描かれたかを読めるように）。
    fn tagged_lines() -> Vec<Line<'static>> {
        (0..12)
            .map(|i| match i % 4 {
                0 => Line::raw(format!("<{i}>")),
                1 => Line::raw(format!("<{i}> {}", "word ".repeat(12))),
                2 => Line::raw(format!("<{i}> {}", "あ".repeat(30))),
                _ => Line::raw(format!("<{i}>")),
            })
            .collect()
    }

    /// 画面の各行に描かれている行の番号。**折り返した続きの行は、直前の番号を引き継ぐ**（`<i>`が無い行）。
    /// 枠線の行と、本文の何も描かれていない行は`None`。
    fn drawn_lines(buffer: &Buffer, inner: Rect) -> Vec<Option<usize>> {
        let mut current = None;
        (inner.top()..inner.bottom())
            .map(|y| {
                let line: String = (inner.left()..inner.right())
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
                if line.trim().is_empty() {
                    return None;
                }
                if let (Some(start), Some(end)) = (line.find('<'), line.find('>')) {
                    current = line[start + 1..end].parse().ok();
                }
                current
            })
            .collect()
    }

    /// **返した行の矩形には、その行が描かれている**——折り返した行・枠の上で切れた行・枠の外の行も含めて。
    /// 送り位置を変え、折り返す枠と折り返さない枠の両方で確かめる（行の場所は押せる候補・見出しの当たり判定になる）。
    #[test]
    fn the_line_areas_returned_are_where_the_lines_are_drawn() {
        for wrapped in [true, false] {
            for top in [0u16, 1, 4, 9, 40] {
                let mut term = Terminal::new(TestBackend::new(40, 10)).expect("test terminal");
                let mut drawn = None;
                let mut inner = Rect::default();
                term.draw(|f| {
                    let block = Block::default().borders(Borders::ALL);
                    inner = block.inner(f.area());
                    drawn = Some(if wrapped {
                        draw_with_buttons(f, f.area(), tagged_lines(), block, top, LOOK, &[])
                    } else {
                        draw_unwrapped(f, f.area(), tagged_lines(), block, top, LOOK)
                    });
                })
                .expect("draw");
                let drawn = drawn.expect("描いた");
                assert_eq!(drawn.lines.len(), tagged_lines().len());
                let mut expected = vec![None; usize::from(inner.height)];
                for (i, rect) in drawn.lines.iter().enumerate() {
                    for y in rect.top()..rect.bottom() {
                        expected[usize::from(y - inner.y)] = Some(i);
                    }
                }
                let screen = drawn_lines(term.backend().buffer(), inner);
                // 本文の無い行（`<i>`だけの短い行の後ろの空き）は画面から読めないので、描かれた行だけを突き合わせる。
                for (y, (want, got)) in expected.iter().zip(&screen).enumerate() {
                    if got.is_some() {
                        assert_eq!(want, got, "折り返し{wrapped} 位置{top}: {y}行目");
                    }
                }
                assert!(
                    expected.iter().all(Option::is_some),
                    "折り返し{wrapped} 位置{top}: 枠の中に、どの行の場所でもない行がある: {expected:?}"
                );
            }
        }
    }

    /// **折り返さない枠も、送る上限は「最後の行が枠の一番下」**（[BUG-196](../../../docs/bugs/BUG-196.md)と同じ形）。
    /// 長い行は右で切り、行の最後の全角文字が右の枠線を覆わない。
    #[test]
    fn an_unwrapped_box_stops_with_the_last_line_at_the_bottom_and_keeps_its_border() {
        let mut term = Terminal::new(TestBackend::new(21, 6)).expect("test terminal");
        let lines: Vec<Line> = (0..10)
            .map(|i| Line::raw(format!("{i} {}", "あ".repeat(20))))
            .collect();
        let mut drawn = None;
        term.draw(|f| {
            drawn = Some(draw_unwrapped(
                f,
                f.area(),
                lines,
                Block::default().borders(Borders::ALL),
                u16::MAX,
                LOOK,
            ));
        })
        .expect("draw");
        let drawn = drawn.expect("描いた");
        assert_eq!(drawn.max_top, 10 - 4);
        let buffer = term.backend().buffer();
        let last_row: String = (1..20).map(|x| buffer[(x, 4)].symbol()).collect();
        assert!(
            last_row.starts_with('9'),
            "一番下の行が最後の行でない: {last_row}"
        );
        // 右の枠線は線かスクロールバーのつまみのどちらか（全角文字に覆われていない）。
        for y in 1..5 {
            let cell = buffer[(20, y)].symbol();
            assert!(cell == "│" || cell == "█", "{y}行目の右の枠線: 「{cell}」");
        }
    }

    /// **スクロールバーは本文が収まらないときだけ出る**（収まる枠の右の枠線は全部が線のまま）。
    #[test]
    fn the_scrollbar_appears_only_when_the_text_overflows() {
        let right = |buffer: &Buffer| -> Vec<String> {
            (1..7)
                .map(|y| buffer[(39, y)].symbol().to_string())
                .collect()
        };
        let (_, fits) = paint(40, 6, &[]);
        assert!(right(&fits).iter().all(|c| c == "│"), "{:?}", right(&fits));
        let (_, overflows) = paint(40, 20, &[]);
        assert!(
            right(&overflows).iter().any(|c| c == "█"),
            "{:?}",
            right(&overflows)
        );
    }
}
