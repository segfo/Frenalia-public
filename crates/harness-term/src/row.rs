//! 1行に並べて描く項目（タブ・キー案内・ボタン）と、**それぞれが描かれた場所**（会話TUIとポリシーエディタが共有する）。
//!
//! # 何のためにあるのか
//!
//! 押せる項目を1行に並べるとき、どの項目がどの桁に描かれたかが分からないと、クリックをその項目へ
//! 結べない（[`crate::pointer`]）。[`draw`]は項目を1つずつ描き、**描いた結果の位置**を返す。
//! 当たり判定のために幅を足し算し直さない。
//!
//! ratatuiの`List`のように、行を描くのが自分ではない場合（一覧の行の中のチェックの記号など）は、
//! その行を左寄せで描いたときに各spanが来る位置を[`spans_in`]で求める。こちらは足し算だが、
//! ratatuiが`Line`を描く規則（spanを左から順に、文字の表示幅ずつ進める）と同じであることを
//! 試験が描いた結果と突き合わせて固定している。
//!
//! # 限界
//!
//! - 1行だけを扱う（折り返さない）。入り切らない項目は途中で切れ、切れた先は押せない。
//! - [`spans_in`]は右端に掛かる全角文字を半分だけ数える（ratatuiはその文字を描かない）。右端で切れる行の
//!   最後の1桁だけ、描かれていない桁が押せる側に入る。

use ratatui::layout::Rect;
use ratatui::text::Span;
use ratatui::Frame;

/// `spans`を`area`の1行目へ左から順に描き、**それぞれが実際に描かれた矩形**を返す（`spans`と同じ数・同じ順）。
///
/// 入り切らなかった項目は幅0の矩形になる（[`crate::pointer::Targets`]は幅0の場所を登録しないので、押せない）。
/// 途中で切れた項目は、描かれた桁だけの矩形になる。
pub fn draw(frame: &mut Frame, area: Rect, spans: &[Span]) -> Vec<Rect> {
    let buffer = frame.buffer_mut();
    let area = area.intersection(buffer.area);
    let right = area.right();
    let mut x = area.x;
    spans
        .iter()
        .map(|span| {
            if area.is_empty() || x >= right {
                return Rect::new(x.min(right), area.y, 0, 0);
            }
            let (end, _) = buffer.set_span(x, area.y, span, right - x);
            let drawn = Rect::new(x, area.y, end - x, 1);
            x = end;
            drawn
        })
        .collect()
}

/// `spans`を1つの`Line`にして`area`の1行目へ左寄せで描いたとき、各spanが来る矩形（`area`の外は切る）。
///
/// 自分で描かない行（ratatuiの`List`が描く一覧の行など）の中で、押せる記号の位置を求めるのに使う。
pub fn spans_in(area: Rect, spans: &[Span]) -> Vec<Rect> {
    let right = area.right();
    let height = area.height.min(1);
    let mut x = area.x;
    spans
        .iter()
        .map(|span| {
            let start = x.min(right);
            x = x.saturating_add(u16::try_from(span.width()).unwrap_or(u16::MAX));
            let end = x.min(right);
            Rect::new(
                start,
                area.y,
                end - start,
                if end > start { height } else { 0 },
            )
        })
        .collect()
}

/// `spans`を並べたときの幅（表示桁）。
pub fn width(spans: &[Span]) -> u16 {
    let total: usize = spans.iter().map(Span::width).sum();
    u16::try_from(total).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::text::Line;
    use ratatui::widgets::Paragraph;
    use ratatui::Terminal;

    use super::*;

    fn spans() -> Vec<Span<'static>> {
        vec![
            Span::raw(" F1 記録 "),
            Span::raw(" "),
            Span::raw(" F2 承認待ち "),
            Span::raw("x"),
        ]
    }

    /// 矩形の中に描かれている文字（全角の後半のセルは空白として入るので、比べる側で空白を落とす）。
    fn text_in(buffer: &Buffer, rect: Rect) -> String {
        (rect.x..rect.right())
            .map(|x| buffer[(x, rect.y)].symbol())
            .collect::<String>()
    }

    fn drawn(width: u16, spans: &[Span]) -> (Vec<Rect>, Buffer) {
        let mut term = Terminal::new(TestBackend::new(width, 2)).expect("test terminal");
        let mut rects = Vec::new();
        term.draw(|frame| rects = draw(frame, Rect::new(0, 1, width, 1), spans))
            .expect("draw");
        (rects, term.backend().buffer().clone())
    }

    /// **返した矩形には、そのspanの文字がちょうど描かれている**（全角を含む）。
    #[test]
    fn each_rect_holds_exactly_the_text_of_its_span() {
        let spans = spans();
        let (rects, buffer) = drawn(40, &spans);
        assert_eq!(rects.len(), spans.len());
        for (span, rect) in spans.iter().zip(&rects) {
            assert_eq!(rect.y, 1);
            assert_eq!(usize::from(rect.width), span.width(), "{span:?}");
            // 全角1文字は「文字＋空セル」の2セルなので、空白を落として比べる。
            assert_eq!(
                text_in(&buffer, *rect).replace(' ', ""),
                span.content.replace(' ', ""),
                "{span:?}"
            );
        }
        // 隣り合う項目は詰めて並ぶ（隙間も重なりも無い）。
        for pair in rects.windows(2) {
            assert_eq!(pair[0].right(), pair[1].x);
        }
    }

    /// 入り切らない項目は幅0（押せない）、途中で切れた項目は描かれた桁だけ。
    #[test]
    fn items_past_the_right_edge_get_no_width() {
        let spans = spans();
        let (rects, buffer) = drawn(14, &spans);
        assert_eq!(rects[0].width, 9);
        assert_eq!(rects[1].width, 1);
        // " F2 承認待ち "は4桁だけ描かれる（" F2 "）。
        assert_eq!(rects[2], Rect::new(10, 1, 4, 1));
        assert_eq!(text_in(&buffer, rects[2]), " F2 ");
        assert_eq!(rects[3].width, 0);
    }

    /// [`spans_in`]（足し算）は、ratatuiが`Line`を左寄せで描いた位置と一致する。収まる幅でも、切れる幅でも。
    #[test]
    fn spans_in_matches_where_a_line_is_drawn() {
        let spans = spans();
        for width in [40u16, 14, 9, 3] {
            let mut term = Terminal::new(TestBackend::new(width, 1)).expect("test terminal");
            term.draw(|frame| {
                frame.render_widget(Paragraph::new(Line::from(spans.clone())), frame.area());
            })
            .expect("draw");
            let buffer = term.backend().buffer().clone();
            let (exact, _) = drawn(width, &spans);
            let computed = spans_in(Rect::new(0, 0, width, 1), &spans);
            for ((span, rect), exact) in spans.iter().zip(&computed).zip(&exact) {
                assert_eq!(rect.width, exact.width, "幅{width}: {span:?}");
                assert_eq!(rect.x, exact.x, "幅{width}: {span:?}");
                let want: String = span.content.chars().take(usize::from(rect.width)).collect();
                assert!(
                    want.replace(' ', "")
                        .starts_with(&text_in(&buffer, *rect).replace(' ', "")),
                    "幅{width}: {span:?}"
                );
            }
        }
        assert_eq!(width(&spans), 9 + 1 + 13 + 1);
    }
}
