//! 後ろの画面の上に枠を重ねる場所を空ける部品（会話TUIとポリシーエディタが共有する。
//! [BUG-198](../../../docs/bugs/BUG-198.md)）。
//!
//! # 何のためにあるのか——枠線の桁に掛かる全角文字も消す
//!
//! ratatuiの画面は全角文字を「前半のセルに文字、後半のセルは空白」で持ち、端末へ差分を送るときは
//! **全角文字の後半に当たるセルを飛ばす**（`ratatui::buffer::Buffer::diff_iter`のdoc）。`Clear`は
//! 重ねる矩形の中しか消さないので、後ろの画面の全角文字が矩形の左隣の桁から始まっていると、
//! その後半に当たる左の枠線のセルが飛ばされて端末へ届かず、全角文字がそのまま見えて枠線が欠ける。
//! だから矩形より左にあって矩形の中まで届く文字（全角文字の前半）を空白に置き換えてから消す。
//!
//! 左右に1桁ずつ広く消す直し方は採らない。枠線に届かない半角や全角まで消え、ratatui自身も
//! 「入り切らない全角文字は描かずに空けておく」を選んでいる（`Buffer::set_stringn`）ので、それに揃える。
//! 右側は要らない——矩形の中から始まって右へはみ出す全角文字は、`Clear`が前半ごと消す
//! （重ねた枠の**中の**本文が右へはみ出す形は別の問題で、[`crate::wrap`]が受け持つ）。

use ratatui::buffer::CellWidth;
use ratatui::layout::Rect;
use ratatui::widgets::Clear;
use ratatui::Frame;

/// `area`を後ろの画面から切り離して消す。**後ろの画面の上に重ねて描く枠は、描く前に必ずこれを通す**
/// （`Clear`を直接使わない）。
pub fn clear(frame: &mut Frame, area: Rect) {
    let buffer = frame.buffer_mut();
    let area = area.intersection(buffer.area);
    for y in area.top()..area.bottom() {
        for x in buffer.area.left()..area.left() {
            let cell = &mut buffer[(x, y)];
            if x.saturating_add(cell.cell_width()) > area.left() {
                // 色は残す（選択行の背景色などが途中で切れないように）。
                cell.set_symbol(" ");
            }
        }
    }
    frame.render_widget(Clear, area);
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::text::Line;
    use ratatui::widgets::{Block, Borders, Paragraph};
    use ratatui::Terminal;

    use super::*;

    /// `symbol`を行ごとに1桁ずつずらして敷き詰めた上に、10桁目から幅10の枠を重ねる。
    fn overlay_over(symbol: &str) -> Buffer {
        let mut term = Terminal::new(TestBackend::new(30, 4)).expect("test terminal");
        term.draw(|frame| {
            let rows: Vec<Line> = (0..4)
                .map(|y| Line::raw(format!("{}{}", " ".repeat(y % 2), symbol.repeat(30))))
                .collect();
            frame.render_widget(Paragraph::new(rows), frame.area());
            let area = Rect::new(10, 0, 10, 4);
            clear(frame, area);
            frame.render_widget(Block::default().borders(Borders::ALL), area);
        })
        .expect("draw");
        term.backend().buffer().clone()
    }

    /// [BUG-198] **後ろに全角文字が並んでいても、重ねた枠の左の枠線はどの行でも端末へ届く。**
    #[test]
    fn the_left_border_survives_wide_characters_behind_it() {
        let buffer = overlay_over("あ");
        let left: Vec<&str> = (0..4).map(|y| buffer[(10, y)].symbol()).collect();
        assert_eq!(left, ["┌", "│", "│", "└"]);
    }

    /// [BUG-198] **許可側**: 枠の左の文字は、枠線に掛かる全角文字1つを除いて消さない。
    #[test]
    fn only_the_character_that_reaches_the_overlay_is_erased() {
        let narrow = overlay_over("x");
        let wide = overlay_over("あ");
        for y in 0..4u16 {
            let row = |buffer: &Buffer| -> String {
                (0..10).map(|x| buffer[(x, y)].symbol()).collect::<String>()
            };
            let offset = usize::from(y % 2);
            assert_eq!(
                row(&narrow),
                format!("{}{}", " ".repeat(offset), "x".repeat(10 - offset))
            );
            // 枠の左に丸ごと入る全角文字は残り、枠線の桁に掛かるものは空白になる。
            let kept: String = row(&wide).split_whitespace().collect();
            assert_eq!(kept, "あ".repeat((10 - offset) / 2), "{y}行目");
        }
    }
}
