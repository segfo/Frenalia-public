//! タブ——並んだ中から1つを選び、**いまどれを開いているかを示し続ける**部品（ポリシーエディタの一番上の画面のタブ
//! `F1 記録`・`F2 承認待ち`・`F3 宣言`と、承認待ちの中のタブ`FS/ネット`・`遷移・観測から`・`遷移・拒否から`が使う）。
//!
//! # ボタンとは別の部品にしてある
//!
//! 見た目はどちらも「押せる、色の付いた短い文言」だが、**画面の使い手にとっての意味が違う**（2026-10-03、ユーザーの
//! 指示「『タブ』と『ボタン』はUX的な意味合いは別」）。
//!
//! | 部品 | 押すと | 見た目の状態 | 押した後 |
//! |---|---|---|---|
//! | ボタン（[`crate::button`]） | 1回だけ動作が起きる（送信・中断・記録を開始・停止・確認ダイアログの選択肢） | 普通／押されている／押せない | 状態は残らない |
//! | タブ（ここ） | 並んだ中からそれを選ぶ | 選ばれている／選ばれていない | 選ばれた見た目が残る |
//!
//! だから1つの型にまとめず、見た目の状態も別々に持つ。**押した瞬間の色（[`crate::button::Press`]）はタブには付けない**
//! ——押したタブが選ばれた見た目に変わり、それが押した後も残ること自体が押した反応である。
//!
//! 共有するのは土台だけ——1行に並べて描き、**描いた場所を返す**[`crate::row::draw`]と、描いた場所を押せる場所として
//! 登録する[`crate::pointer::Targets`]（ボタンの呼び出し側も同じ2つを使う）。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタの画面のタブと承認待ちのタブは、同じ並べ方・同じ見た目のタブを`tui/mod.rs`の2つの関数で別々に
//! 組み立てていた（見た目だけは`tab_style`を共有していた）。並べ方が2か所にあると、片方だけ直したときに2つのタブの行の
//! 形がずれる。会話TUIの部品（[`crate::button`]・[`crate::scrollable`]・[`crate::overlay`]）と同じく、ratatuiの描き方に
//! 依存する見た目と置き方はここへ置き、**何を並べ、押すと何が起きるか**（タブの一覧・`Click`の値・後ろに添える案内の
//! 文言）は呼び出し側に残す（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
//!
//! # 並べ方
//!
//! ```text
//!  F1 記録   F2 承認待ち   F3 宣言   Ctrl+N で切替   workspace: …
//! └選ばれていない┘└選ばれている┘                └[`draw`]の`after`（押せない）
//! ```
//!
//! - 各タブは文言の左右に1桁ずつ余白を付けて描く（` F1 記録 `。余白も押せる）。タブの間は[`GAP`]桁の空白で、押せない。
//! - 選ばれているタブはシアンの背景に黒の太字、選ばれていないタブは灰色の文字（[`look`]）。
//! - タブの後ろに、押せない文（切り替えのキーの案内など）を続けて描ける。
//!
//! # 限界
//!
//! - 1行だけを扱う。入り切らないタブは右端で切れ、描かれた桁だけが押せる（切れた先は押せない。[`crate::row::draw`]）。
//!   どこで切れたかは見た目に出ない（`… 他N件`のような省略の印は付けない）。
//! - 選ばれているタブの色はシアンに決めてある（使う画面がポリシーエディタだけなので、色を引数にしていない）。

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::Frame;

use crate::pointer::Targets;

/// タブの間の桁数（空白。押せない）。
pub const GAP: u16 = 1;

/// タブ1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tab<'a, C> {
    /// 文言（`F1 記録`）。左右の1桁の余白は[`draw`]が付ける。
    pub label: &'a str,
    /// いま選ばれているか。
    pub selected: bool,
    /// 押したときの動き（[`Targets::click`]へ登録する値）。選ばれているタブも登録する——押しても何もしないかは
    /// 呼び出し側の動きが決める。
    pub target: C,
}

/// タブの見た目。選ばれているタブはシアンの背景に黒の太字、選ばれていないタブは灰色の文字。
pub fn look(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

/// `tabs`を`area`の1行目へ左から[`GAP`]桁ずつ空けて並べて描き、その後ろへ`after`（押せない文）を続けて描く。
/// 各タブを、押すとそのタブの`target`になる場所として`targets`へ登録し、各タブが描かれた矩形を返す
/// （`tabs`と同じ数・同じ順。入り切らなかったタブは幅0で、登録されない）。
pub fn draw<C: Clone, W: Clone>(
    frame: &mut Frame,
    area: Rect,
    tabs: &[Tab<C>],
    after: &[Span],
    targets: &mut Targets<C, W>,
) -> Vec<Rect> {
    let gap = " ".repeat(usize::from(GAP));
    let mut spans = Vec::with_capacity(tabs.len() * 2 + after.len());
    let mut at = Vec::with_capacity(tabs.len());
    for (i, tab) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(gap.clone()));
        }
        at.push(spans.len());
        spans.push(Span::styled(format!(" {} ", tab.label), look(tab.selected)));
    }
    spans.extend(after.iter().cloned());
    let drawn = crate::row::draw(frame, area, &spans);
    tabs.iter()
        .zip(at)
        .map(|(tab, index)| {
            targets.click(drawn[index], tab.target.clone());
            drawn[index]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;
    use unicode_width::UnicodeWidthStr;

    use super::*;

    fn tabs(selected: usize) -> Vec<Tab<'static, &'static str>> {
        ["F1 記録", "F2 承認待ち", "F3 宣言"]
            .into_iter()
            .enumerate()
            .map(|(i, label)| Tab {
                label,
                selected: i == selected,
                target: label,
            })
            .collect()
    }

    /// 1フレーム描いて、返した矩形・登録・画面を返す。
    fn drawn(
        width: u16,
        tabs: &[Tab<&'static str>],
    ) -> (Vec<Rect>, Targets<&'static str, ()>, Buffer) {
        let mut term = Terminal::new(TestBackend::new(width, 1)).expect("test terminal");
        let mut targets = Targets::default();
        let mut rects = Vec::new();
        let after = [Span::styled(
            "  Ctrl+N で切替",
            Style::default().fg(Color::DarkGray),
        )];
        term.draw(|f| rects = draw(f, f.area(), tabs, &after, &mut targets))
            .expect("draw");
        (rects, targets, term.backend().buffer().clone())
    }

    /// 矩形に描かれた文字（全角文字の後ろのセルは読まない）。
    fn text_in(buffer: &Buffer, rect: Rect) -> String {
        let mut text = String::new();
        let mut skip = false;
        for x in rect.x..rect.right() {
            let symbol = buffer[(x, rect.y)].symbol();
            if std::mem::take(&mut skip) {
                continue;
            }
            skip = symbol.width() == 2;
            text.push_str(symbol);
        }
        text
    }

    /// **各タブは文言の左右に1桁の余白を付けて1桁ずつ空けて並び、返した矩形にはそのタブがちょうど描かれている。**
    /// 選ばれているタブだけがシアンの背景に黒の太字、ほかは灰色。後ろの案内はタブの後ろに続く。
    /// 期待する文字は画面に見えるとおりに書いた（幅の計算から作らない）。
    #[test]
    fn tabs_are_padded_spaced_and_only_the_selected_one_is_highlighted() {
        let (rects, _, buffer) = drawn(60, &tabs(1));
        assert_eq!(
            rects
                .iter()
                .map(|r| text_in(&buffer, *r))
                .collect::<Vec<_>>(),
            [" F1 記録 ", " F2 承認待ち ", " F3 宣言 "]
        );
        assert_eq!(rects[0].x, 0);
        for pair in rects.windows(2) {
            assert_eq!(pair[0].right() + GAP, pair[1].x, "タブの間が1桁でない");
            assert_eq!(buffer[(pair[0].right(), 0)].symbol(), " ");
        }
        assert_eq!(
            text_in(&buffer, Rect::new(rects[2].right(), 0, 15, 1)),
            "  Ctrl+N で切替"
        );
        for (i, rect) in rects.iter().enumerate() {
            let style = buffer[(rect.x + 1, 0)].style();
            if i == 1 {
                assert_eq!(
                    (style.fg, style.bg),
                    (Some(Color::Black), Some(Color::Cyan))
                );
                assert!(style.add_modifier.contains(Modifier::BOLD));
            } else {
                assert_eq!(style.fg, Some(Color::Gray), "{i}番目");
                assert!(!style.add_modifier.contains(Modifier::BOLD), "{i}番目");
            }
        }
    }

    /// **描いたタブの桁を押すとそのタブの動き、間の空白と後ろの案内は押せない。**
    #[test]
    fn each_drawn_tab_is_pressable_and_the_gaps_and_the_trailing_text_are_not() {
        let (rects, targets, _) = drawn(60, &tabs(0));
        for (rect, want) in rects.iter().zip(["F1 記録", "F2 承認待ち", "F3 宣言"]) {
            for x in rect.x..rect.right() {
                assert_eq!(targets.clicked(x, 0), Some(want), "{x}桁");
            }
            assert_eq!(targets.clicked(rect.right(), 0), None, "{want}の右隣");
        }
        assert_eq!(targets.clicked(rects[2].right() + 3, 0), None, "後ろの案内");
    }

    /// **入り切らないタブは右端で切れ、描かれた桁だけが押せる。** 1桁も入らないタブは幅0で、押せない。
    #[test]
    fn a_tab_past_the_right_edge_is_cut_and_only_its_drawn_columns_are_pressable() {
        // " F1 記録 "は9桁、" F2 承認待ち "は13桁。16桁なら2つ目は6桁（" F2 承"）だけ描かれる。
        let (rects, targets, buffer) = drawn(16, &tabs(0));
        assert_eq!(rects[1], Rect::new(10, 0, 6, 1));
        assert_eq!(text_in(&buffer, rects[1]), " F2 承");
        assert_eq!(rects[2].width, 0);
        assert_eq!(targets.clicked(15, 0), Some("F2 承認待ち"));
        assert!((0..16).all(|x| targets.clicked(x, 0) != Some("F3 宣言")));
    }
}
