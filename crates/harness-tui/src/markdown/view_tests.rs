//! Facade（[`MarkdownView`]）の試験——実装へ渡す幅の決め方と、行と印の数の確かめ。

use super::*;

/// 受け取った幅を覚え、決めた数の行と印を返すだけの実装（Facadeが実装へ何桁を渡すかを見る）。
#[derive(Default)]
struct WidthProbe {
    seen: Vec<u16>,
    lines: usize,
    joins: usize,
}

impl StreamingMarkdown for WidthProbe {
    fn push(&mut self, _chunk: &str) {}
    fn finish(&mut self) {}
    fn reset(&mut self) {}
    fn render(&mut self, width: u16) -> Rendered {
        self.seen.push(width);
        Rendered {
            lines: vec![Line::from("x"); self.lines],
            joins: vec![LineJoin::Break; self.joins],
        }
    }
}

/// **実装へは、枠の内側の幅から右端の1桁を空けた幅を渡す**（`harness_term::wrap::text_width`と同じ規則。
/// 1桁以下は空けない）。数える幅・描く幅と同じ幅で、実装も行を分ける。
#[test]
fn the_engine_gets_the_inner_width_minus_the_right_edge_column() {
    let mut probe = WidthProbe {
        lines: 1,
        joins: 1,
        ..WidthProbe::default()
    };
    for inner in [98u16, 2, 1, 0] {
        render_in(&mut probe, inner);
    }
    assert_eq!(probe.seen, vec![97, 1, 1, 0]);
}

/// 行と印の数が違う結果を返す実装は、デバッグビルドでは描くときに止まる（[`Rendered`]の不変条件）。
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "行と印の数が違う")]
fn a_mismatch_between_lines_and_joins_stops_a_debug_build() {
    let mut probe = WidthProbe {
        lines: 2,
        joins: 1,
        ..WidthProbe::default()
    };
    render_in(&mut probe, 80);
}

/// Facadeは選んだ実装へ足す・終える・空に戻すをそのまま渡す（いまの実装は原文をそのまま描く）。
#[test]
fn the_view_draws_what_was_pushed_with_the_chosen_engine() {
    let mut view = MarkdownView::new();
    view.push("**a**\n");
    view.push("b");
    view.finish();
    assert_eq!(
        view.render(80).lines,
        vec![Line::from("**a**"), Line::from("b")]
    );
    view.reset();
    assert_eq!(view.render(80).lines, vec![Line::from("")]);
}
