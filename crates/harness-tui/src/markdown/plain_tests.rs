//! [`PlainText`]の試験。**付け替える前のtranscriptの描き方**（原文を`str::lines`で割り、1行ずつ飾りの無い`Line`に
//! する。空の文章は空の1行）と同じであることを固定する。画面全体での同じ確かめは
//! `app::pointer::pointer_tests::select_tests::markdown_looking_assistant_text_is_drawn_and_copied_verbatim`が持つ。

use super::*;

fn rendered(source: &str, width: u16) -> Rendered {
    let mut plain = PlainText::default();
    plain.push(source);
    plain.render(width)
}

/// 原文の1行が飾りの無い1つの`Line`になり（Markdownの記号も字下げもそのまま）、印は全部`Break`。
#[test]
fn each_source_line_becomes_one_unstyled_line_and_every_join_is_a_break() {
    let r = rendered("# 見出し\n**太字**\n\n  - 入れ子", 80);
    assert_eq!(
        r.lines,
        vec![
            Line::from("# 見出し"),
            Line::from("**太字**"),
            Line::from(""),
            Line::from("  - 入れ子"),
        ]
    );
    assert_eq!(r.joins, vec![LineJoin::Break; 4]);
}

/// 空の文章は0行（空の1行にするのはFacade。どの実装でも同じ規則にするため、T9でこの実装からFacadeへ移した——
/// 画面での見え方は`super::super::view_tests::an_engine_that_draws_nothing_is_shown_as_one_empty_line`が確かめる）。
#[test]
fn an_empty_text_draws_no_lines() {
    assert!(rendered("", 80).lines.is_empty());
    assert!(PlainText::default().render(80).lines.is_empty());
}

/// 行の割り方は`str::lines`と同じ——末尾の改行は空の行を足さず、`\r\n`も区切る。改行だけの文章は空の1行。
#[test]
fn lines_are_split_like_str_lines() {
    assert_eq!(rendered("a\n", 80).lines, vec![Line::from("a")]);
    assert_eq!(
        rendered("a\r\nb", 80).lines,
        vec![Line::from("a"), Line::from("b")]
    );
    assert_eq!(rendered("\n", 80).lines, vec![Line::from("")]);
}

/// 折り返さない（折り返しは`harness_term::wrap`が受け持つ）。どの幅でも長い行は1つの`Line`。
#[test]
fn a_long_line_is_not_wrapped_at_any_width() {
    let long = "あ".repeat(300);
    for width in [80, 10, 1, 0] {
        assert_eq!(rendered(&long, width).lines, vec![Line::from(long.clone())]);
    }
}

/// 終えても見た目は変わらない（確定させる未確定の部分が無い）。
#[test]
fn finishing_changes_nothing() {
    let mut plain = PlainText::default();
    plain.push("**途中");
    let before = plain.render(80);
    plain.finish();
    assert_eq!(plain.render(80), before);
}

/// 整形しないので、リンクの区間を1つも返さない（Markdownのリンクも原文の文字のまま描く）。
#[test]
fn no_link_spans_are_returned_even_for_a_markdown_link() {
    let r = rendered("[リンク](https://example.com) と https://example.com", 80);
    assert_eq!(
        r.lines,
        vec![Line::from(
            "[リンク](https://example.com) と https://example.com"
        )]
    );
    assert!(r.links.is_empty());
}
