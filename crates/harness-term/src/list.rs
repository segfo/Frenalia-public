//! 行を押せる一覧。ratatuiの`List`で描き、**各項目が描かれた矩形**を返す（会話TUIとポリシーエディタが共有する）。
//!
//! # 何のためにあるのか
//!
//! 一覧の行をクリックで選ぶには、どの項目が画面のどの行に描かれたかが要る。`List`はそれを返さない
//! （表示を始める位置`offset`だけを`ListState`に書き戻す）ので、ここで求める。
//!
//! # 1回目で表示の位置を決め、2回目で描く
//!
//! `List`は、表示を始める位置から**入り切る項目だけ**を上から順に描く。ただし、選ばれた項目が窓の下へ
//! 出た直後の1フレームだけは例外で、選ばれた項目までしか描かない（その下に入る余地があっても空ける）。
//! 次のフレームでは同じ位置から入り切る分だけ描くので、空いて見えるのはその1フレームだけである。
//!
//! 返す矩形をこの例外まで写して計算すると、`List`の中の位置合わせを丸ごと写すことになる。そこで
//! **捨てる画面へ1回描いて表示の位置を落ち着かせてから、本物の画面へ同じ状態でもう1回描く**。
//! 2回目は例外に当たらず「表示を始める位置から入り切る項目だけ」を描くので、返す矩形はその規則だけで求まる
//! （見た目は、例外の1フレームが次のフレームと同じになるだけである）。
//!
//! # 限界
//!
//! - 項目1つが一覧の高さより背が高いと、その項目は描かれず、押せる行も返らない（`List`と同じ）。
//! - 強調の記号（`highlight_symbol`）・下から積む向き・選択の周りの余白（`scroll_padding`）は使えない
//!   （ここで`List`を組み立てるので、付けられない）。

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, List, ListItem, ListState, StatefulWidget};
use ratatui::Frame;

/// 描かれた項目1つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// 渡した`items`の中の位置。
    pub index: usize,
    /// その項目が描かれた矩形（枠の内側。項目の高さぶん）。
    pub area: Rect,
}

/// `items`を`List`で`area`へ描き（枠があれば`block`、選んだ行は`highlight`）、**描かれた項目**を上から順に返す。
///
/// `state`は呼び出し側が持つ表示の位置と選択（`List`と同じく、描いた後の位置が書き戻される）。
pub fn draw<'a>(
    frame: &mut Frame,
    area: Rect,
    items: Vec<ListItem<'a>>,
    block: Option<Block<'a>>,
    highlight: Style,
    state: &mut ListState,
) -> Vec<Row> {
    let heights: Vec<usize> = items.iter().map(ListItem::height).collect();
    let inner = block.as_ref().map_or(area, |block| block.inner(area));
    let mut list = List::new(items).highlight_style(highlight);
    if let Some(block) = block {
        list = list.block(block);
    }
    // 1回目は捨てる画面へ描いて、表示を始める位置を落ち着かせる（モジュールdoc）。
    let mut scratch = Buffer::empty(area);
    StatefulWidget::render(&list, area, &mut scratch, state);
    frame.render_stateful_widget(&list, area, state);
    if inner.is_empty() {
        return Vec::new();
    }
    visible_rows(inner, &heights, state.offset())
}

/// 表示を始める位置`offset`から、`inner`に入り切る項目を上から順に並べる（`List`の描き方と同じ規則）。
fn visible_rows(inner: Rect, heights: &[usize], offset: usize) -> Vec<Row> {
    let room = usize::from(inner.height);
    let mut used = 0usize;
    let mut rows = Vec::new();
    for (index, &height) in heights.iter().enumerate().skip(offset) {
        if used + height > room {
            break;
        }
        rows.push(Row {
            index,
            area: Rect::new(
                inner.x,
                inner.y + u16::try_from(used).unwrap_or(u16::MAX),
                inner.width,
                u16::try_from(height).unwrap_or(u16::MAX),
            ),
        });
        used += height;
    }
    rows
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::text::Line;
    use ratatui::widgets::Borders;
    use ratatui::Terminal;

    use super::*;

    /// 項目`i`は`heights[i]`行で、各行に`<i>`と書く（どの項目がどこに描かれたかを画面から読めるように）。
    fn items(heights: &[usize]) -> Vec<ListItem<'static>> {
        heights
            .iter()
            .enumerate()
            .map(|(i, &h)| ListItem::new(vec![Line::raw(format!("<{i}>")); h]))
            .collect()
    }

    /// 画面の各行に描かれている項目の番号（`<i>`）。項目が無い行は`None`。
    fn drawn_items(buffer: &ratatui::buffer::Buffer) -> Vec<Option<usize>> {
        (0..buffer.area.height)
            .map(|y| {
                let line: String = (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
                let start = line.find('<')?;
                let end = line[start..].find('>')? + start;
                line[start + 1..end].parse().ok()
            })
            .collect()
    }

    /// 1フレーム描いて、返した行と、画面から読んだ「各行に描かれた項目」を返す。
    fn frame(
        heights: &[usize],
        size: (u16, u16),
        block: bool,
        state: &mut ListState,
    ) -> (Vec<Row>, Vec<Option<usize>>) {
        let mut term = Terminal::new(TestBackend::new(size.0, size.1)).expect("test terminal");
        let mut rows = Vec::new();
        term.draw(|f| {
            rows = draw(
                f,
                f.area(),
                items(heights),
                block.then(|| Block::default().borders(Borders::ALL)),
                Style::default(),
                state,
            );
        })
        .expect("draw");
        (rows, drawn_items(term.backend().buffer()))
    }

    /// **返した矩形の行には、その項目が描かれている。返さなかった行には項目が無い。**
    fn assert_rows_match_the_screen(rows: &[Row], screen: &[Option<usize>], case: &str) {
        let mut expected = vec![None; screen.len()];
        for row in rows {
            for y in row.area.top()..row.area.bottom() {
                expected[usize::from(y)] = Some(row.index);
            }
        }
        assert_eq!(expected, screen, "{case}: 返した行と描かれた行が違う");
    }

    /// 高さがまちまちの項目でも、枠の有無にかかわらず、返す行は描かれた行と一致する。
    #[test]
    fn the_rows_returned_are_the_rows_drawn() {
        let heights = [1, 3, 2, 1, 4, 1, 1, 2];
        for block in [false, true] {
            for offset in [0usize, 2, 5] {
                for selected in [0usize, 3, 7] {
                    let mut state = ListState::default().with_offset(offset);
                    state.select(Some(selected));
                    let (rows, screen) = frame(&heights, (20, 8), block, &mut state);
                    assert_rows_match_the_screen(
                        &rows,
                        &screen,
                        &format!("枠{block} 位置{offset} 選択{selected}"),
                    );
                    assert!(
                        rows.iter().any(|r| r.index == selected),
                        "選んだ項目が描かれていない（枠{block} 位置{offset} 選択{selected}）"
                    );
                }
            }
        }
    }

    /// **選んだ項目が窓の下へ出た直後のフレームでも、返す行と描かれた行が一致する**（モジュールdoc）。
    ///
    /// 高さ5の窓・項目の高さ[3,1,1,1,1]・表示の位置0で項目3を選ぶと、`List`は1回描くだけでは
    /// 項目1〜3だけを描いて項目4の分を空ける。2回描いているので、項目1〜4が描かれる。
    #[test]
    fn the_frame_right_after_the_selection_moves_below_matches_too() {
        let heights = [3, 1, 1, 1, 1];
        let mut state = ListState::default().with_offset(0);
        state.select(Some(3));

        // 前提: `List`を1回だけ描くと、項目4の分が空く。
        let mut once = state;
        let mut term = Terminal::new(TestBackend::new(10, 5)).expect("test terminal");
        term.draw(|f| {
            f.render_stateful_widget(List::new(items(&heights)), f.area(), &mut once);
        })
        .expect("draw");
        assert_eq!(
            drawn_items(term.backend().buffer()),
            [Some(1), Some(2), Some(3), None, None],
            "試験の前提が崩れた（ratatuiの`List`の描き方が変わった）——2回描く必要があるか見直す"
        );

        let (rows, screen) = frame(&heights, (10, 5), false, &mut state);
        assert_eq!(screen, [Some(1), Some(2), Some(3), Some(4), None]);
        assert_rows_match_the_screen(&rows, &screen, "選択が窓の下へ出た直後");
        assert_eq!(state.offset(), 1);
    }

    /// 項目が無い・一覧の高さが0・項目が一覧より背が高い、のどれでも落ちず、押せる行を作らない。
    #[test]
    fn nothing_drawn_means_no_rows() {
        let mut state = ListState::default();
        assert!(frame(&[], (10, 5), true, &mut state).0.is_empty());
        let mut state = ListState::default();
        state.select(Some(0));
        let (rows, screen) = frame(&[2], (10, 2), true, &mut state);
        assert!(rows.is_empty());
        assert_eq!(screen, [None, None]);
        let mut state = ListState::default();
        state.select(Some(0));
        let (rows, screen) = frame(&[6, 1], (10, 4), false, &mut state);
        assert_rows_match_the_screen(&rows, &screen, "背の高い項目");
    }
}
