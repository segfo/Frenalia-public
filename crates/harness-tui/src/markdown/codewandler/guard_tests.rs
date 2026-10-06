//! 解析器が落ちる行の書き換え（[`Guard`]）の試験。
//!
//! 書き換えるべき行（落ちる形）と、書き換えてはいけない行（落ちない形・フェンスの中・前の行に`|`が無い）を対で持つ。
//! 書き換えた行で解析器が落ちず、描く文字が書き換える前の意図（`:`の文字）のままであることも確かめる。

use super::super::render::{render_lines, Theme};
use super::super::wrap_tests::plain;
use super::{defused, Guard, GUARD_MISSES};

/// `text`を1行ずつ[`Guard`]に通した結果。
fn through(text: &str) -> String {
    let mut guard = Guard::default();
    text.split_inclusive('\n')
        .map(|line| guard.line(line).into_owned())
        .collect()
}

/// **見張り**: 解析器は今も、`|`を含む1行だけの段落の次の`|:`で落ちる。この試験が赤くなったら（落ちなくなったら）、
/// 解析器が直ったので[`Guard`]は要らない——`guard.rs`と、`super::parse`での呼び出しと、この試験を消す。
/// （落ちたときの解析器のメッセージが試験の出力に1行出るのは想定どおり。）
#[test]
fn the_parser_still_panics_on_a_lone_colon_delimiter_cell() {
    let raw = std::panic::catch_unwind(|| markdown_stream::parse_gfm("| a |\n|:|\n"));
    assert!(
        raw.is_err(),
        "解析器が`|:`で落ちなくなった。書き換え（guard.rs）を外す（この試験のdoc）"
    );
}

/// 落ちる形の行は`:`の前に`\`が入る。書き換えた全文は解析器が落ちずに解析でき、`:`の文字として描かれる。
#[test]
fn a_line_that_would_crash_the_parser_gets_an_escaped_colon() {
    for (text, expected) in [
        ("| a |\n|:|\n", "| a |\n|\\:|\n"),
        ("| a |\n|:", "| a |\n|\\:"),
        ("| a |\n:|\n", "| a |\n\\:|\n"),
        ("| a | b |\n|---|:\n", "| a | b |\n|---|\\:\n"),
        ("| a | b |\n| :--- | : |\n", "| a | b |\n| :--- | \\: |\n"),
        ("> | a |\n> |:|\n", "> | a |\n> |\\:|\n"),
        ("- | a |\n  |:|\n", "- | a |\n  |\\:|\n"),
    ] {
        let out = through(text);
        assert_eq!(out, expected, "{text:?}");
        let events = std::panic::catch_unwind(|| markdown_stream::parse_gfm(&out))
            .unwrap_or_else(|_| panic!("書き換えた後も解析器が落ちた: {out:?}"));
        let drawn: Vec<String> = render_lines(&events, &Theme::no_color(), 80)
            .lines
            .iter()
            .map(plain)
            .collect();
        assert!(
            drawn.iter().any(|line| line.contains(':'))
                && !drawn.iter().any(|line| line.contains('\\')),
            "`:`の文字として描かれていない: {drawn:?}"
        );
    }
}

/// 書き換えてはいけない行: 落ちない形（正しい区切り行・手前に区切りでないセルがある・`:`だけでない）、
/// 前の行に`|`が無い、コードフェンスの中。
#[test]
fn a_line_that_would_not_crash_the_parser_is_left_alone() {
    for text in [
        "| a |\n|:-|\n",
        "| a |\n|:---:|\n",
        "| a | b |\n| x | : |\n",
        "| a |\n| :: |\n",
        "| a |\nnote: done\n",
        "a\n|:|\n",
        "\n|:|\n",
        "```\n| a |\n|:|\n```\n",
        "~~~\n| a |\n|:|\n~~~\n",
        "| a |\n\\|:|\n",
    ] {
        assert_eq!(through(text), text, "{text:?}");
    }
}

/// フェンスが閉じた後は、また書き換える。
#[test]
fn lines_after_a_closed_fence_are_guarded_again() {
    let text = "```\n|:|\n```\n| a |\n|:|\n";
    assert_eq!(through(text), "```\n|:|\n```\n| a |\n|\\:|\n");
}

/// **見張り**: 書き換えの部品がフェンスの中と見て、解析器はフェンスと見ない行の後ろは、今も書き換えずに解析器が落ちる
/// （[`GUARD_MISSES`]。`guard.rs`のモジュールdocの限界）。この試験が赤くなったら（どれかが落ちなくなったら）、
/// 書き換えか解析器が変わったので、限界の記述と[`GUARD_MISSES`]を直す。
///
/// 落ちたときにその返答を原文のまま描くことは`super::super::fallback_tests`が確かめる。
#[test]
fn the_guard_still_misses_fences_that_the_parser_does_not_see() {
    for text in GUARD_MISSES {
        let out = defused(text);
        assert_eq!(out, text, "書き換えた（試験の前提が崩れた）: {text:?}");
        assert!(
            std::panic::catch_unwind(|| markdown_stream::parse_gfm(&out)).is_err(),
            "書き換えが届かない形で、解析器が落ちなくなった（この試験のdoc）: {text:?}"
        );
    }
}
