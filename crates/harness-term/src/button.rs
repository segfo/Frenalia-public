//! ボタン——押せる項目を、注釈ではなく**押せるもの**として見せる見た目と、枠の辺へ並べる置き方
//! （会話TUIとポリシーエディタが共有する）。
//!
//! # 何のためにあるのか
//!
//! キー案内の文字（`Esc=中断`・`[y] 一度だけ許可`）は、クリックで押せても注釈にしか見えない——2026-10-03に
//! ユーザーが会話画面を実機で見て「括弧の中に注釈があるからその注釈としてしかとらえられない」と指摘した。
//! 押せることを形で見せるため、背景色・黒文字・太字に左右1桁の余白を付けた**ボタン**として描く。
//! 見た目はポリシーエディタの確認ダイアログの下辺のボタン（`y=書く`）が先に持っていたもので、会話TUIの入力欄と
//! 承認ダイアログも同じ見た目を要るので、ここへ置いた（`scrollable`・`overlay`を移したのと同じ理由。
//! `docs/CODE-STRUCTURE-RULES.md`§5.0）。
//!
//! # いまは押せないボタンは薄く描く（[`inactive`]）
//!
//! キーを押しても何も起きない間（入力欄が空のときの「送信」）は、背景を暗い灰色にし、太字をやめる。
//! 押す場所も登録しない（呼び出し側の責務）。消さずに残すのは、**ボタンの置き場所そのものを見せておく**ため
//! ——空の入力欄から送信ボタンが消えると、最初に画面を見たときに送り方が分からない（指摘の発端そのもの）。
//!
//! # 並べ方
//!
//! ボタンの間は[`GAP`]桁空け、**その桁には何も描かない**——枠線の上に並べれば、ボタンの間に枠線が見える
//! （隣り合うボタンが1本の帯に見えない）。[`draw_left`]・[`draw_right`]は**ボタンの途中で切らない**
//! （`row::draw_wrapped`・ポリシーエディタのキー案内の`fit_key_hints`と同じ規則）。途中で切れたボタンは、
//! 残った文字が別の操作に読める。
//!
//! # 限界
//!
//! - 色は呼び出し側が選ぶ。押せるかどうかは色ではなく形（背景と太字）で見せる——色を持たない端末では、
//!   押せるボタンと押せないボタンの違いは太字だけになる。
//! - 押したときの見た目の変化（押下中の反転など）は無い。クリックは押した瞬間に効く（`crate::pointer`）。

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::Frame;

/// ボタンの間の桁数（何も描かない）。
pub const GAP: u16 = 1;

/// 押せるボタン（`color`の背景に黒の太字。文言の左右に1桁ずつ余白を付ける）。
pub fn active(label: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

/// いまは押せないボタン（暗い灰色の背景。太字にしない）。形は[`active`]と同じ（同じ場所・同じ幅）。
pub fn inactive(label: &str) -> Span<'static> {
    Span::styled(
        format!(" {label} "),
        Style::default().fg(Color::Gray).bg(Color::DarkGray),
    )
}

/// `buttons`を[`GAP`]桁ずつ空けて並べたときの幅（ボタンが無ければ0）。
pub fn row_width(buttons: &[Span]) -> u16 {
    let gaps = u16::try_from(buttons.len().saturating_sub(1))
        .unwrap_or(u16::MAX)
        .saturating_mul(GAP);
    crate::row::width(buttons).saturating_add(gaps)
}

/// `buttons`を`area`の1行目へ左から[`GAP`]桁ずつ空けて描き、それぞれが描かれた矩形を返す（同じ数・同じ順）。
/// 入り切らないボタンは描かず、幅0の矩形を返す（押せない。モジュールdocの並べ方）。
pub fn draw_left(frame: &mut Frame, area: Rect, buttons: &[Span]) -> Vec<Rect> {
    let row = Rect {
        height: area.height.min(1),
        ..area
    };
    crate::row::draw_wrapped(frame, row, buttons, GAP)
}

/// `choices`（**同じボタンを、長い文言から順に**並べた候補）のうち、`area`の1行目に入り切る最初のものを
/// **右寄せで**描き、それぞれのボタンが描かれた矩形を返す（ボタンと同じ数・同じ順）。
///
/// どれも入り切らなければ何も描かず、幅0の矩形を返す（押せない）。右寄せで入り切らないものを描くと、
/// 左の端で切れて頭が消える（`scrollable::Window::notice`が「1〜3/10行」の頭を守るのと同じ理由）。
/// 候補どうしのボタンの数は揃えること（違えば、少ない方を満たさない分だけ幅0にする）。
pub fn draw_right(frame: &mut Frame, area: Rect, choices: &[&[Span]]) -> Vec<Rect> {
    let count = choices.iter().map(|c| c.len()).max().unwrap_or(0);
    let row = Rect {
        height: area.height.min(1),
        ..area
    };
    for buttons in choices {
        let width = row_width(buttons);
        if width > row.width || row.height == 0 {
            continue;
        }
        let placed = Rect {
            x: row.right() - width,
            width,
            ..row
        };
        let mut drawn = draw_left(frame, placed, buttons);
        drawn.resize(count, Rect::new(row.right(), row.y, 0, 0));
        return drawn;
    }
    vec![Rect::new(row.right(), row.y, 0, 0); count]
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::widgets::{Block, Borders};
    use ratatui::Terminal;

    use super::*;

    /// 全角1文字は「文字＋空セル」の2セルなので、空白を落として比べる。
    fn text_in(buffer: &Buffer, rect: Rect) -> String {
        (rect.x..rect.right())
            .map(|x| buffer[(x, rect.y)].symbol())
            .collect::<String>()
    }

    /// 幅`width`・高さ3の枠を描き、その下辺（角を除く）へ`choices`を右寄せで描く。
    fn bottom_right(width: u16, choices: &[&[Span]]) -> (Vec<Rect>, Buffer) {
        let mut term = Terminal::new(TestBackend::new(width, 3)).expect("test terminal");
        let mut rects = Vec::new();
        term.draw(|f| {
            f.render_widget(Block::default().borders(Borders::ALL), f.area());
            rects = draw_right(f, crate::row::bottom_edge(f.area()), choices);
        })
        .expect("draw");
        (rects, term.backend().buffer().clone())
    }

    fn long() -> Vec<Span<'static>> {
        vec![
            active("Esc=中断", Color::Cyan),
            active("Alt+Enter=送信", Color::Cyan),
        ]
    }

    fn short() -> Vec<Span<'static>> {
        vec![active("中断", Color::Cyan), active("送信", Color::Cyan)]
    }

    /// **右寄せのボタンは、右の角のすぐ左で終わり、間の1桁には枠線が残る。** 返した矩形にはそのボタンの文字がある。
    #[test]
    fn right_aligned_buttons_end_at_the_corner_with_the_border_between_them() {
        let (rects, buffer) = bottom_right(60, &[&long(), &short()]);
        assert_eq!(rects.len(), 2);
        assert_eq!(rects[1].right(), 59, "右の角（59桁目）のすぐ左で終わる");
        assert_eq!(rects[0].right() + GAP, rects[1].x);
        assert_eq!(buffer[(rects[0].right(), 2)].symbol(), "─", "間に枠線");
        assert_eq!(buffer[(59, 2)].symbol(), "┘", "右の角は覆わない");
        for (span, rect) in long().iter().zip(&rects) {
            assert_eq!(rect.y, 2);
            assert_eq!(usize::from(rect.width), span.width());
            assert_eq!(
                text_in(&buffer, *rect).replace(' ', ""),
                span.content.replace(' ', "")
            );
            // ボタンの見た目（背景と太字）が、描いたセルに載っている。
            let cell = &buffer[(rect.x, rect.y)];
            assert_eq!(cell.bg, Color::Cyan);
            assert!(cell.modifier.contains(Modifier::BOLD));
        }
    }

    /// **長い文言が入り切らなければ短い文言で、それも入り切らなければ描かない**（途中で切らない）。
    #[test]
    fn a_narrow_edge_falls_back_to_the_short_labels_and_then_to_nothing() {
        let long_width = row_width(&long());
        let short_width = row_width(&short());
        // 枠の下辺は幅-2。長い文言がちょうど入る幅では長い文言（許可側）。
        let (rects, _) = bottom_right(long_width + 2, &[&long(), &short()]);
        assert_eq!(rects[1].width, long()[1].width() as u16);
        // 1桁足りなければ短い文言。
        let (rects, buffer) = bottom_right(long_width + 1, &[&long(), &short()]);
        assert_eq!(rects[1].width, short()[1].width() as u16);
        assert_eq!(text_in(&buffer, rects[1]).replace(' ', ""), "送信");
        // 短い文言も入らなければ、1つも描かない（押せない）。下辺は枠線のまま。
        let (rects, buffer) = bottom_right(short_width + 1, &[&long(), &short()]);
        assert!(rects.iter().all(|r| r.width == 0), "{rects:?}");
        let edge: String = (1..short_width).map(|x| buffer[(x, 2)].symbol()).collect();
        assert!(edge.chars().all(|c| c == '─'), "{edge}");
    }

    /// 押せないボタンは同じ幅で、背景が暗い灰色・太字でない。
    #[test]
    fn an_inactive_button_has_the_same_shape_but_a_dim_look() {
        let on = active("Alt+Enter=送信", Color::Cyan);
        let off = inactive("Alt+Enter=送信");
        assert_eq!(on.width(), off.width());
        assert_eq!(on.content, off.content);
        assert_eq!(off.style.bg, Some(Color::DarkGray));
        assert!(!off.style.add_modifier.contains(Modifier::BOLD));
        assert!(on.style.add_modifier.contains(Modifier::BOLD));
    }

    /// 左寄せでも、入り切らないボタンは幅0（途中で切らない）。
    #[test]
    fn left_aligned_buttons_that_do_not_fit_are_not_drawn() {
        let buttons = long();
        let mut term = Terminal::new(TestBackend::new(20, 1)).expect("test terminal");
        let mut rects = Vec::new();
        term.draw(|f| rects = draw_left(f, f.area(), &buttons))
            .expect("draw");
        assert_eq!(rects[0], Rect::new(0, 0, buttons[0].width() as u16, 1));
        assert_eq!(rects[1].width, 0, "{rects:?}");
        assert_eq!(
            row_width(&buttons),
            rects[0].width + GAP + buttons[1].width() as u16
        );
        assert_eq!(row_width(&[]), 0);
    }
}
