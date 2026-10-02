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
//! # 限界
//!
//! - 折り返し方そのもの（空白で切り、日本語の禁則を見ない）は[`crate::wrap`]のまま。
//! - ボタンは枠に下辺の枠線があることを前提に、その線の上へ描く。

use ratatui::layout::{Margin, Rect};
use ratatui::style::Style;
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;

use crate::wrap::{rows, Wrapped};

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

/// [`draw_with_buttons`]が描いた結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawn {
    /// この描画で分かった送れる上限（[`Window::max_top`]）。
    pub max_top: u16,
    /// ボタンが描かれた矩形（渡したボタンと同じ数・同じ順。入り切らなかったものは幅0）。
    pub buttons: Vec<Rect>,
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
pub fn draw_with_buttons<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    top: u16,
    look: Look,
    buttons: &[Span],
) -> Drawn {
    let text = text.into();
    let inner = block.inner(area);
    let window = Window::new(
        rows(text.clone(), inner.width),
        usize::from(inner.height),
        top,
    );
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
    Wrapped::new(text)
        .block(block)
        .scroll(u16::try_from(window.top).unwrap_or(u16::MAX))
        .render(frame, area);
    if window.overflows() {
        draw_scrollbar(frame, area, window, look.bar);
    }
    let buttons = if buttons.is_empty() || area.height == 0 {
        vec![Rect::default(); buttons.len()]
    } else {
        // 下辺の枠線のうち、左右の角を除いた部分（枠の見出しを左寄せで置くのと同じ場所）。
        let edge = Rect::new(
            area.x.saturating_add(1),
            area.bottom() - 1,
            area.width.saturating_sub(2),
            1,
        );
        crate::row::draw(frame, edge, buttons)
    };
    Drawn {
        max_top: u16::try_from(window.max_top()).unwrap_or(u16::MAX),
        buttons,
    }
}

/// 送れる枠で、いま見せている範囲（[BUG-196](../../../docs/bugs/BUG-196.md)）。
/// **数えるのはどれも折り返した後の表示行**で、[`rows`]・`Paragraph::scroll`・下辺の「N〜M/T行」と同じ単位である。
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
/// 折り返しの幅をさらに減らし、[`rows`]で数える幅もそれに合わせることになる。枠線の上なら本文の幅は
/// 変わらず、数えた行数と描いた行数の一致に触らない。線は枠線と同じ記号・同じ色にし、つまみだけを`█`にするので、
/// 収まらないときは右の枠線の一部がつまみに変わって見える。上下の矢印は付けない（つまみが端に付いたことで
/// 先頭・末尾を言うため。矢印を付けると、端に付いても矢印との間に線が残る）。
///
/// **送れることはスクロールバーだけでは伝わらない**（キーやホイールで送れることは絵から読めない）ので、
/// 下辺の「N〜M/T行」に送り方を添える（[`Look::how`]）。
fn draw_scrollbar(frame: &mut Frame, area: Rect, window: Window, bar: Style) {
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
}
