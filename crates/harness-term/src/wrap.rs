//! 折り返して描く本文の部品。**数える幅と描く幅を、ここ1か所で決める**
//! （会話TUIとポリシーエディタが共有する。[BUG-200](../../../docs/bugs/BUG-200.md)）。
//!
//! # 何のためにあるのか——右端の1桁を空けて描く
//!
//! ratatuiの単語折り返し（`Wrap`。`ratatui-widgets`の`WordWrapper`）は、行があふれるかどうかを
//! **いまの文字を足す前の幅**で判定する。そのため、空白で区切られた語（その行の最初の語を除く）の
//! 最後の文字が全角で、それが行の最後の1桁から始まると、その行は**1桁長く**なる。
//! はみ出した後半は描く場所の右隣——枠付きなら右の枠線の桁——に掛かり、ratatuiは端末へ差分を
//! 送るとき全角文字の後半に当たるセルを飛ばすので、**枠線が端末へ届かない**
//! （ポリシーエディタのヘルプの1行目は、端末が78桁以上あればいつもこうなっていた）。
//!
//! 折り返しはratatuiのものを使い続ける（自前で幅を足し算すると、空白で切る規則の分だけ描画と
//! ずれる——BUG-192で採らなかった形）。代わりに、**折り返す幅を描く場所より1桁狭くする**。
//! はみ出しは最大1桁（全角は2桁）なので、空けた1桁に収まり、場所の外へは出ない。
//! はみ出しが無い行では、その1桁は空白のままである。
//!
//! # 数える幅と描く幅は必ず同じ
//!
//! 行数（[`rows`]）も描画（[`Wrapped::render`]）も、同じ[`text_width`]で狭めた幅で同じ折り返し器を通す。
//! どちらか片方だけを狭めると、数えた行数と描いた行数が食い違い、枠の高さや「続きがあるか」が
//! ずれる（BUG-192が直した形の再発）。**`Wrap`と`Paragraph::line_count`はここ以外で使わない。**
//!
//! # 限界
//!
//! - 本文が使える幅は、どの枠でも1桁減る。今まで右端までちょうど埋まっていた行は、1文字早く折り返す。
//! - 折り返し方そのもの（空白で切り、日本語の禁則を見ない）は変えていない。

use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

/// `width`桁の場所に折り返して描くときに、本文へ使う幅。右端の1桁を空ける。
///
/// 1桁以下の場所は空けない（空けると何も描けなくなる。全角文字はそもそも入らない）。
pub fn text_width(width: u16) -> u16 {
    if width >= 2 {
        width - 1
    } else {
        width
    }
}

/// `text`を`width`桁の場所へ[`Wrapped::render`]で描いたときの行数。
///
/// 幅0は1桁として数える（幅0の場所には何も描かれない。会話TUIの承認ダイアログと同じ扱い）。
pub fn rows<'a>(text: impl Into<Text<'a>>, width: u16) -> usize {
    Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .line_count(text_width(width).max(1))
}

/// 折り返して描く本文。`Paragraph`に`Wrap`を付けて描く代わりにこれを使う（モジュールdoc）。
///
/// 枠（[`Self::block`]）を付けたときは、枠を描いてから枠の中へ本文を描く。`Paragraph`の`block`に
/// 渡すと、本文と一緒に枠まで狭い場所へ描かれてしまうので、枠は必ずここで受け取る。
pub struct Wrapped<'a> {
    text: Text<'a>,
    block: Option<Block<'a>>,
    top: u16,
}

impl<'a> Wrapped<'a> {
    pub fn new(text: impl Into<Text<'a>>) -> Self {
        Self {
            text: text.into(),
            block: None,
            top: 0,
        }
    }

    /// 本文を囲む枠。
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    /// 本文の何行目（折り返した後の表示行）から見せるか。
    pub fn scroll(mut self, top: u16) -> Self {
        self.top = top;
        self
    }

    /// `area`へ描く。本文は右端の1桁を空けた場所（[`text_width`]）へ折り返す。
    pub fn render(self, frame: &mut Frame, area: Rect) {
        let inner = match self.block {
            Some(block) => {
                let inner = block.inner(area);
                frame.render_widget(block, area);
                inner
            }
            None => area,
        };
        frame.render_widget(
            Paragraph::new(self.text)
                .wrap(Wrap { trim: false })
                .scroll((self.top, 0)),
            Rect {
                width: text_width(inner.width),
                ..inner
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::text::Line;
    use ratatui::widgets::Borders;
    use ratatui::Terminal;

    use super::*;

    /// `paint`だけを描いた端末の、`TestBackend`が受け取った画面（ratatuiが端末へ送った差分）。
    fn painted(width: u16, height: u16, paint: impl FnOnce(&mut Frame)) -> Buffer {
        let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        term.draw(paint).expect("draw");
        term.backend().buffer().clone()
    }

    /// 枠の右の枠線（上から下まで）。
    fn right_border(buffer: &Buffer) -> Vec<String> {
        let x = buffer.area.width - 1;
        (0..buffer.area.height)
            .map(|y| buffer[(x, y)].symbol().to_string())
            .collect()
    }

    fn expected_right_border(height: u16) -> Vec<String> {
        let mut want = vec!["┐".to_string()];
        want.extend((2..height).map(|_| "│".to_string()));
        want.push("┘".to_string());
        want
    }

    /// [BUG-200] **はみ出す形の行でも、右の枠線は残る。** 幅の偶奇で語の作り方が変わるので両方。
    #[test]
    fn a_line_ending_in_a_wide_character_does_not_cover_the_right_border() {
        for width in [40u16, 41] {
            let buffer = painted(width, 6, |frame| {
                Wrapped::new(crate::spilling_line(width - 2))
                    .block(Block::default().borders(Borders::ALL))
                    .render(frame, frame.area());
            });
            assert_eq!(
                right_border(&buffer),
                expected_right_border(6),
                "幅{width}: 右の枠線が欠けた"
            );
        }
    }

    /// [BUG-200] **試験の前提**: その形の行は、狭めずに描くと実際に右の枠線を覆う
    /// （ratatuiが直ったら、この試験が赤くなって知らせる。そのときは空けた1桁が要らなくなる）。
    #[test]
    fn without_the_spare_column_the_same_line_covers_the_right_border() {
        let width = 40u16;
        let buffer = painted(width, 6, |frame| {
            frame.render_widget(
                Paragraph::new(crate::spilling_line(width - 2))
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL)),
                frame.area(),
            );
        });
        assert_ne!(
            right_border(&buffer),
            expected_right_border(6),
            "ratatuiの折り返しがはみ出さなくなった——空けた1桁が要るかを見直す（モジュールdoc）"
        );
    }

    /// [BUG-200] **数えた行数と描いた行数が一致する。** 文字のある行の数を数える
    /// （本文に空行を含めない）。幅と本文をいくつか組み合わせる。
    #[test]
    fn the_counted_rows_match_the_drawn_rows() {
        let texts = [
            "short".to_string(),
            crate::spilling_line(30),
            crate::spilling_line(31),
            "あ".repeat(100),
            "word ".repeat(40),
            format!("{} {}", "x".repeat(29), "あいう".repeat(9)),
        ];
        for width in [10u16, 29, 30, 31, 32, 57] {
            for text in &texts {
                let counted = rows(text.as_str(), width);
                let buffer = painted(width, 200, |frame| {
                    Wrapped::new(text.as_str()).render(frame, frame.area());
                });
                let drawn = (0..200)
                    .filter(|&y| (0..width).any(|x| buffer[(x, y)].symbol() != " "))
                    .count();
                assert_eq!(counted, drawn, "幅{width}: {text}");
            }
        }
    }

    /// [BUG-200] **許可側**: 空けた1桁に届かない本文は、`Wrap`を付けた`Paragraph`で描いたときと
    /// 1セルも違わない（見た目が変わるのは、右端まで届く行だけ）。
    #[test]
    fn a_text_that_does_not_reach_the_spare_column_is_drawn_exactly_as_before() {
        let lines = vec![
            Line::raw("承認の確認"),
            Line::raw("  + fs.read = C:/x/0"),
            Line::raw(""),
            Line::raw("あ".repeat(18)),
        ];
        let block = || Block::default().borders(Borders::ALL).title(" 枠 ");
        let ours = painted(40, 8, |frame| {
            Wrapped::new(lines.clone())
                .block(block())
                .render(frame, frame.area());
        });
        let plain = painted(40, 8, |frame| {
            frame.render_widget(
                Paragraph::new(lines.clone())
                    .wrap(Wrap { trim: false })
                    .block(block()),
                frame.area(),
            );
        });
        assert_eq!(ours, plain);
    }

    /// 幅が1桁以下の場所でも落ちず、空けない（空けると何も描けない）。
    #[test]
    fn a_tiny_area_does_not_reserve_a_column() {
        assert_eq!(text_width(0), 0);
        assert_eq!(text_width(1), 1);
        assert_eq!(text_width(2), 1);
        assert_eq!(rows("abc", 0), 3);
        for width in [0u16, 1, 2] {
            painted(width.max(1), 3, |frame| {
                Wrapped::new("あいう")
                    .block(Block::default().borders(Borders::ALL))
                    .render(frame, Rect::new(0, 0, width, 3));
            });
        }
    }
}
