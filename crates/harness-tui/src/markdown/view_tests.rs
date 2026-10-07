//! Facade（[`MarkdownView`]）の試験——実装へ渡す幅の決め方と、行と印の数・リンクの区間の確かめ。

use super::*;

/// 受け取った幅を覚え、決めた数の行と印とリンクの区間を返すだけの実装（Facadeが実装へ何桁を渡すかを見る）。
#[derive(Default)]
struct WidthProbe {
    seen: Vec<u16>,
    lines: usize,
    joins: usize,
    links: Vec<LinkSpan>,
}

impl StreamingMarkdown for WidthProbe {
    fn push(&mut self, _chunk: &str) {}
    fn finish(&mut self) {}
    fn reset(&mut self) {}
    fn render(&mut self, width: u16) -> Rendered {
        self.seen.push(width);
        Rendered {
            lines: vec![Line::from("xyz"); self.lines],
            joins: vec![LineJoin::Break; self.joins],
            links: self.links.clone(),
        }
    }
}

fn link(line: usize, start: usize, end: usize) -> LinkSpan {
    LinkSpan {
        line,
        start,
        end,
        url: "https://example.com".to_string(),
        continues: false,
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

/// Facadeは選んだ実装へ足す・終える・空に戻すをそのまま渡す——選んだ実装（[`Engine`]）へ同じことをして、狭めた幅で
/// 描いたのと同じになる。T9で選ぶ実装がビルドで変わるようになったので、見た目を書かずに選んだ実装と比べる形へ
/// 意図して書き換えた（どちらの実装を選んだビルドでも同じ試験が通る）。
#[test]
fn the_view_draws_what_was_pushed_with_the_chosen_engine() {
    let mut view = MarkdownView::new();
    view.push("**a**\n");
    view.push("b");
    view.finish();
    let mut engine = Engine::default();
    engine.push("**a**\nb");
    engine.finish();
    assert_eq!(view.render(80), engine.render(79));
    view.reset();
    assert_eq!(view.render(80).lines, vec![Line::from("")]);
}

/// 行の文字の中に収まるリンクの区間は、そのまま使用側へ渡る（3文字の行の`0..3`・`1..2`）。
#[test]
fn link_spans_inside_their_lines_pass_through() {
    let links = vec![link(0, 0, 3), link(1, 1, 2)];
    let mut probe = WidthProbe {
        lines: 2,
        joins: 2,
        links: links.clone(),
        ..WidthProbe::default()
    };
    assert_eq!(render_in(&mut probe, 80).links, links);
}

/// 行の外・文字の外・空の区間を返す実装は、デバッグビルドでは描くときに止まる（[`Rendered`]の不変条件）。
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "リンクの区間が行の文字の外を指す")]
fn a_link_span_outside_its_line_stops_a_debug_build() {
    let mut probe = WidthProbe {
        lines: 1,
        joins: 1,
        links: vec![link(0, 2, 4)],
        ..WidthProbe::default()
    };
    render_in(&mut probe, 80);
}

/// 区間が収まるかの判定（リリースビルドでは、収まらない区間をこれで捨てる——描画の経路は止めない）。
/// 行の外・文字の外・空の区間は収まらない。文字は`Line::styled_graphemes`で数える（描かれない制御文字は数えない）。
#[test]
fn a_link_span_fits_only_inside_the_characters_of_its_line() {
    let lines = vec![Line::from("xyz"), Line::from("a\u{7}b")];
    assert!(link_fits(&lines, &link(0, 0, 3)));
    assert!(link_fits(&lines, &link(1, 1, 2)));
    assert!(!link_fits(&lines, &link(0, 2, 4)), "文字の外");
    assert!(
        !link_fits(&lines, &link(1, 0, 3)),
        "制御文字は数えないので2文字"
    );
    assert!(!link_fits(&lines, &link(2, 0, 1)), "行の外");
    assert!(!link_fits(&lines, &link(0, 1, 1)), "空の区間");
}

/// **実装が1行も描かない返答は、空の1行として使用側へ渡す**（どの実装でも同じ。返答の場所を画面に残すため）。
/// 印は`Break`。1行でも描けば、そのまま渡す。
#[test]
fn an_engine_that_draws_nothing_is_shown_as_one_empty_line() {
    let mut nothing = WidthProbe::default();
    let rendered = render_in(&mut nothing, 80);
    assert_eq!(rendered.lines, vec![Line::from("")]);
    assert_eq!(rendered.joins, vec![LineJoin::Break]);

    let mut one = WidthProbe {
        lines: 1,
        joins: 1,
        ..WidthProbe::default()
    };
    assert_eq!(render_in(&mut one, 80).lines, vec![Line::from("xyz")]);
}
