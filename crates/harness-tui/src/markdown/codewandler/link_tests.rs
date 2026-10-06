//! 写した描画部品（[`super::render`]）が返す**リンクの位置**（`Rendered::links`）の試験（計画書
//! `plans/PLAN-TUI-IMPROVEMENTS.md`§0のT7b・§1.5の6・§3）。
//!
//! # 何のためにあるのか
//!
//! リンクの文字は青の下線で描き、URLは文中に出さない（計画書§0.1の決定）。URLは後の段（計画書のT11）で、マウスが
//! リンクの文字の上に来たときの吹き出しと、Ctrl＋クリックで開くのに使う。そのとき「マウスの下の文字が何行目の
//! 何文字目か」は範囲選択の地図（`harness_term::select`の`Pos { line, offset }`）から引くので、**リンクの位置も
//! 同じ数え方でないと、指した文字とリンクがずれる**。
//!
//! # 決めたこと（試験で固定する）
//!
//! - 位置は`lines`の行番号と、その行の中の文字（書記素）の半開区間`start..end`。数え方は`Line::styled_graphemes`と
//!   同じ——描かれない制御文字は数えない
//! - 折り返しをまたぐリンクは、**行ごとに1つずつ**分かれる。英語の語の切れ目で分けたときに前の行の末尾に残した
//!   空白は、リンクが次の行へ続くならリンクの区間に含める（各行の区間の文字をつなぐと、リンクの文字に戻る）
//! - 隣り合う2つのリンクは、URLが同じでも別の区間になる。リンクの中の書式（太字・コード）とソフト改行（空白1つ）は
//!   1つの区間に収まる
//! - 裸のURL（GFMの自動リンク）と`<…>`の自動リンクも同じ扱い
//! - **画像は区間を返さない**。代わりの文字（alt）は素の描画部品と同じくリンクの書式で描く（計画書§1.5は画像に
//!   触れていない）
//!
//! # 限界
//!
//! - 区間は描画部品が描いた行についてのもの。transcriptの中で何行目になるか（ほかの項目の行を足した位置）は、
//!   使う側（計画書のT11）が足し直す

use harness_term::wrap::text_width;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};

use super::characterization_tests::{describe, CASES, INLINE_STYLES_AND_LINK};
use super::render::Theme;
use super::wrap_tests::{all_inputs, draw, plain};
use crate::markdown::{LinkSpan, Rendered};

/// 確かめる枠の内側の幅（1行に1文字しか置けない狭さを含む）。
const ANY_INNER_WIDTHS: [u16; 10] = [0, 1, 2, 3, 6, 10, 21, 40, 80, 120];

/// どこでも分けない十分に広い幅。
const WIDE: usize = 10_000;

fn link(line: usize, start: usize, end: usize, url: &str) -> LinkSpan {
    LinkSpan {
        line,
        start,
        end,
        url: url.to_string(),
    }
}

/// 行の文字（書記素）。範囲選択の地図と同じ数え方（`Line::styled_graphemes`）。
fn graphemes<'a>(line: &'a Line<'_>) -> Vec<(&'a str, Style)> {
    line.styled_graphemes(Style::default())
        .map(|grapheme| (grapheme.symbol, grapheme.style))
        .collect()
}

/// `span`の区間に描かれた文字。
fn drawn(rendered: &Rendered, span: &LinkSpan) -> String {
    graphemes(&rendered.lines[span.line])[span.start..span.end]
        .iter()
        .map(|(symbol, _)| *symbol)
        .collect()
}

/// リンクの書式（青の前景色と下線）か。太字・斜体等が重なっていても真。
fn is_link_style(style: Style) -> bool {
    style.fg == Some(Color::Blue) && style.add_modifier.contains(Modifier::UNDERLINED)
}

/// リンクの文字は青の前景色と下線で、背景は付けない（範囲選択の色と見分けが付かなくなるため。計画書§1.5の6）。
/// URLは文中に出さず、位置とURLを返す。
#[test]
fn a_link_is_drawn_blue_and_underlined_and_its_url_is_returned_not_drawn() {
    let theme = Theme::default();
    assert!(is_link_style(theme.link));
    assert_eq!(theme.link.bg, None);

    let rendered = draw("see [here](https://example.com) now\n", 40);
    assert_eq!(
        describe(&Text::from(rendered.lines.clone())),
        ["see «link|here» now"]
    );
    assert!(!plain(&rendered.lines[0]).contains("example"));
    assert_eq!(rendered.links, [link(0, 4, 8, "https://example.com")]);
    assert_eq!(drawn(&rendered, &rendered.links[0]), "here");
}

/// **対照**: リンクの無い文章は区間を1つも返さない（特性化試験の入力のうち、リンクを含まないもの全部）。
/// リンクを含む入力は区間を返す。
#[test]
fn only_text_with_links_returns_link_spans() {
    for (name, src) in CASES {
        let links = draw(src, 80).links;
        if src == INLINE_STYLES_AND_LINK {
            assert_eq!(links, [link(0, 24, 28, "https://example.com")], "{name}");
        } else {
            assert!(links.is_empty(), "{name}: {links:?}");
        }
    }
}

/// 英語の語の切れ目で折り返すリンクは、行ごとに1つずつ区間を返す。前の行の末尾に残した空白は、リンクが次の行へ
/// 続くので前の行の区間に含める。リンクの後ろの語（`end`）との間の空白は含めない。
#[test]
fn a_link_wrapped_over_lines_yields_one_span_per_line() {
    let rendered = draw("see [alpha beta gamma](https://e.x) end\n", 12);
    assert_eq!(
        rendered.lines.iter().map(plain).collect::<Vec<_>>(),
        ["see alpha ", "beta gamma ", "end"]
    );
    assert_eq!(
        rendered.links,
        [link(0, 4, 10, "https://e.x"), link(1, 0, 10, "https://e.x")]
    );
    let texts: Vec<String> = rendered
        .links
        .iter()
        .map(|span| drawn(&rendered, span))
        .collect();
    assert_eq!(texts, ["alpha ", "beta gamma"]);
}

/// 全角文字のリンクも、区間は桁ではなく文字（書記素）の数で数える。全角文字の間で分けた所には何も残らない。
#[test]
fn a_link_with_wide_characters_counts_characters_not_columns() {
    let rendered = draw("前[日本語のリンク](https://e.x)後\n", 10);
    assert_eq!(
        rendered.lines.iter().map(plain).collect::<Vec<_>>(),
        ["前日本語の", "リンク後"]
    );
    assert_eq!(
        rendered.links,
        [link(0, 1, 5, "https://e.x"), link(1, 0, 3, "https://e.x")]
    );
}

/// 位置は`Line::styled_graphemes`と同じく、描かれない制御文字を数えない。結合文字は前の文字と合わせて1文字。
#[test]
fn offsets_skip_control_characters_and_count_combined_characters_once() {
    let rendered = draw("a\u{7}b [link](https://e.x)\n", 40);
    assert!(
        plain(&rendered.lines[0]).contains('\u{7}'),
        "前提: 制御文字が描画部品まで届いている"
    );
    assert_eq!(rendered.links, [link(0, 3, 7, "https://e.x")]);

    let rendered = draw("e\u{301}x [l](https://e.x)\n", 40);
    assert_eq!(rendered.links, [link(0, 3, 4, "https://e.x")]);
}

/// リストの記号・引用の縦線・入れ子の字下げも文字として数える。
#[test]
fn a_link_in_a_list_item_or_a_quote_counts_the_prefix() {
    assert_eq!(
        draw("- [a](https://e.x)\n", 40).links,
        [link(0, 2, 3, "https://e.x")]
    );
    assert_eq!(
        draw("> [a](https://e.x)\n", 40).links,
        [link(0, 2, 3, "https://e.x")]
    );
    assert_eq!(
        draw("- x\n  - [a](https://e.x)\n", 40).links,
        [link(1, 4, 5, "https://e.x")]
    );
    assert_eq!(
        draw("- [ ] [a](https://e.x)\n", 40).links,
        [link(0, 6, 7, "https://e.x")]
    );
}

/// 見出しと表のセルの中のリンクも区間を返す。
#[test]
fn a_link_in_a_heading_and_in_a_table_cell_is_returned() {
    assert_eq!(
        draw("# [h](https://e.x)\n", 40).links,
        [link(0, 0, 1, "https://e.x")]
    );
    let rendered = draw("| a | [l](https://e.x) |\n|---|---|\n| 1 | 2 |\n", 40);
    assert_eq!(plain(&rendered.lines[0]), "│ a │ l │ ");
    assert_eq!(rendered.links, [link(0, 6, 7, "https://e.x")]);
}

/// 裸のURL（GFMの自動リンク）と`<…>`の自動リンクは、描いたURLの文字そのものが区間になる。
#[test]
fn autolinks_are_returned_with_their_url() {
    assert_eq!(
        draw("see https://example.com/path now\n", 40).links,
        [link(0, 4, 28, "https://example.com/path")]
    );
    assert_eq!(
        draw("<https://x.y>\n", 40).links,
        [link(0, 0, 11, "https://x.y")]
    );
}

/// 画像は区間を返さない。代わりの文字はリンクの書式のまま描く（モジュールdoc）。
#[test]
fn an_image_keeps_its_alt_text_and_returns_no_link_span() {
    let rendered = draw("![alt](https://e.x/a.png)\n", 40);
    assert_eq!(
        describe(&Text::from(rendered.lines.clone())),
        ["«link|alt»"]
    );
    assert!(rendered.links.is_empty());
}

/// 隣り合う2つのリンクは、URLが同じでも別の区間。間の空白はどちらにも含めない。
#[test]
fn two_adjacent_links_are_separate_spans() {
    assert_eq!(
        draw("[a](https://e.x) [b](https://e.x)\n", 40).links,
        [link(0, 0, 1, "https://e.x"), link(0, 2, 3, "https://e.x")]
    );
}

/// リンクの中の太字・コードと、ソフト改行（空白1つになる）は、1つの区間に収まる。
#[test]
fn a_link_containing_styles_and_a_soft_break_is_one_span() {
    let rendered = draw("[**a** `c` d\ne](https://e.x)\n", 40);
    assert_eq!(plain(&rendered.lines[0]), "a c d e");
    assert_eq!(rendered.links, [link(0, 0, 7, "https://e.x")]);
}

/// **どの入力をどの幅で描いても**、区間は行の中に収まり、区間の中の空白でない文字はどれもリンクの書式で描かれ、
/// リンクの書式で描いた文字はどれも区間に入る（画像を含む入力は後者から外す）。各区間の文字をつなぐと、
/// どこでも分けない広い幅で描いたときの区間の文字と同じになり、URLの並びも同じ。
#[test]
fn every_link_span_matches_the_drawn_link_text_at_every_width() {
    let mut spans_checked = 0;
    let mut split_links = 0;
    for src in all_inputs() {
        let wide = draw(&src, WIDE);
        let wide_text: String = wide.links.iter().map(|span| drawn(&wide, span)).collect();
        let mut wide_urls: Vec<&str> = wide.links.iter().map(|span| span.url.as_str()).collect();
        wide_urls.dedup();
        for inner in ANY_INNER_WIDTHS {
            let width = usize::from(text_width(inner));
            let rendered = draw(&src, width);
            for span in &rendered.links {
                let line = rendered
                    .lines
                    .get(span.line)
                    .unwrap_or_else(|| panic!("行の外の区間 {span:?}（幅{width}）: {src:?}"));
                let cells = graphemes(line);
                assert!(
                    span.start < span.end && span.end <= cells.len(),
                    "行の文字の外の区間 {span:?}（{}文字・幅{width}）: {src:?}",
                    cells.len()
                );
                assert!(
                    is_link_style(cells[span.start].1),
                    "区間の最初の文字がリンクの書式でない {span:?}（幅{width}）: {src:?}"
                );
                for (symbol, style) in &cells[span.start..span.end] {
                    assert!(
                        symbol.trim().is_empty() || is_link_style(*style),
                        "区間の中にリンクでない文字{symbol:?}がある {span:?}（幅{width}）: {src:?}"
                    );
                }
                spans_checked += 1;
            }
            if !src.contains("![") {
                for (index, line) in rendered.lines.iter().enumerate() {
                    for (offset, (symbol, style)) in graphemes(line).into_iter().enumerate() {
                        if is_link_style(style) {
                            assert!(
                                rendered.links.iter().any(|span| span.line == index
                                    && (span.start..span.end).contains(&offset)),
                                "リンクの書式の文字{symbol:?}（{index}行目の{offset}文字目・幅{width}）が区間に無い: {src:?}"
                            );
                        }
                    }
                }
            }
            let text: String = rendered
                .links
                .iter()
                .map(|span| drawn(&rendered, span))
                .collect();
            assert_eq!(text, wide_text, "幅{width}: {src:?}");
            let mut urls: Vec<&str> = rendered
                .links
                .iter()
                .map(|span| span.url.as_str())
                .collect();
            urls.dedup();
            assert_eq!(urls, wide_urls, "幅{width}: {src:?}");
            split_links += rendered.links.len().saturating_sub(wide.links.len());
        }
    }
    // 試験が空回りしていないこと（区間があり、折り返しで分かれた区間もある）。
    assert!(
        spans_checked > 200,
        "確かめた区間が{spans_checked}個しか無い"
    );
    assert!(
        split_links > 50,
        "折り返しで分かれた区間が{split_links}個しか無い"
    );
}
