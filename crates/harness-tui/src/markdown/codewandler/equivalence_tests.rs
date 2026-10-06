//! 写した描画部品（[`super::render`]）が、写す前の描画部品（`codewandler-markdown-ratatui` 0.2.1の
//! `markdown_ratatui`）と**同じ出力を返す**ことを確かめる試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT6）。
//!
//! # 何のためにあるのか
//!
//! 描画部品は「既存の動く実装を機械的に写してから直す」（計画書§1.3の結論。グローバル規約の「既存のリファレンス
//! 実装をテンプレートにする」）。写す途中で1か所でも変わっていたら、それはT7で直す前から別物になっている。
//! だから写した直後に、元と出力が**1つも違わない**ことを、文字だけでなく書式と`Span`の切れ目まで含めて
//! （`ratatui::text::Text`同士の`==`で）確かめる。
//!
//! 入力は3組。
//!
//! | 組 | 何のためか |
//! |---|---|
//! | 特性化試験の入力（`super::characterization_tests::CASES`）×幅40・80 | 計画書§1.9のユーザー指定の8ケースと既知の不具合 |
//! | [`BRANCH_INPUTS`]×[`BRANCH_WIDTHS`]×既定の書式と書式なし | 描画部品の分岐を全部通す（表・区切り線・字下げのコード・ハードな改行・引用の入れ子・幅の切り上げ等）。全部通ることは[`branch_inputs_reach_every_kind_of_event_the_renderer_handles`]が確かめる |
//! | 書式（`Theme`）の各役割 | 使われない役割（コードの色分け用に予約されたもの）まで同じか |
//!
//! # 限界
//!
//! - 同じであることを確かめるのは**ここに並べた入力についてだけ**。分岐を全部通しても、値の組み合わせを全部
//!   試したことにはならない。写した手順（変えたのは冒頭の表記・`pub`の範囲・モジュールの宣言だけ）は
//!   `render.rs`の冒頭に書いてある。
//! - **計画書のT7で写しを直したら、この試験は役目を終える**（直した箇所で元と違うのが正しくなる）。T7では消すか、
//!   直さない入力に絞る。

use std::collections::BTreeSet;

use markdown_stream::{Alignment, BlockKind, Event};
use ratatui::text::Text;

use super::characterization_tests::{describe, CASES, WIDTHS};
use super::render;

/// 描画部品の分岐を全部通すための入力（モジュールdoc）。
const BRANCH_INPUTS: [&str; 23] = [
    "",
    "Para one\nsoft line.  \nhard by two spaces\\\nhard by a backslash\nlast\n\nPara two\n",
    "## Sub *heading* with `code`, **bold** and [a link](http://x.y \"t\")\n",
    "***bold italic*** ~~strike~~ [link](http://x.y \"title\") ![img](a.png) <span>raw</span> https://bare.example.com\n",
    "3. three\n4. four\n\n5. five after a blank line\n",
    "> outer\n>\n> > inner quote\n> > second line\n>\n> back to outer\n",
    "- a\n\n  b paragraph in the same item\n- c\n",
    "    indented code\n    line 2\n\nafter\n",
    "---\n\n***\n\n> ---\n",
    "| left | center | right | none |\n|:-----|:------:|------:|------|\n| a | bb | ccc | d |\n| longer cell | x | y |\n| `code` | **b** | z | w |\n",
    "> - quoted list item that is long enough to wrap around at narrow widths\n>   continued line\n",
    "- item with a very long English sentence that keeps going and going beyond the width\n  - nested item also long enough to wrap around the narrow width for sure\n",
    "Averyveryveryverylongwordwithoutanyspacesthatexceedsthewidthforsure and more words\n",
    "```\ncode with no language\n\n  indented inside\n```\n\n~~~python\nprint('x')\n~~~\n",
    "- [ ] task in list\n- [x] done task\n\n1. [ ] ordered task\n",
    "# H1\n## H2\n### H3\ntext under\n",
    "- item\n\n  | a | b |\n  |---|---|\n  | 1 | 2 |\n",
    "Line with\ttab\tseparated words\n",
    "日本語とEnglish wordsが混ざった文章です。 スペースの後も続きます。とても長い日本語の文が続いていきます。\n",
    "> quote with code\n>\n> ```\n> inside quote\n> ```\n",
    "Text with a hard break at the end  \n\n- tight\n- list\n\n1) paren\n2) ordered\n",
    "<!-- comment -->\n\n<div>\n*not emphasis*\n</div>\n",
    "Setext Heading\n==============\n\nAnother\n-------\n",
];

/// [`BRANCH_INPUTS`]を描く幅。20桁未満を20桁へ切り上げる分岐（`width.max(20)`）と、字下げで使える幅が
/// 20桁を割る分岐を通すため、狭い幅を多めに入れる。
const BRANCH_WIDTHS: [usize; 8] = [0, 10, 20, 24, 40, 60, 80, 120];

/// `src`を、写した描画部品と元の描画部品の両方で、既定の書式（`no_color`なら書式なし）・`width`桁で描く。
fn both(src: &str, width: usize, no_color: bool) -> (Text<'static>, Text<'static>) {
    let events = markdown_stream::parse_gfm(src);
    let (copied_theme, original_theme) = if no_color {
        (
            render::Theme::no_color(),
            markdown_ratatui::Theme::no_color(),
        )
    } else {
        (render::Theme::default(), markdown_ratatui::Theme::default())
    };
    (
        render::render_with(&events, &copied_theme, width),
        markdown_ratatui::render_with(&events, &original_theme, width),
    )
}

/// `copied`と`original`が`Text`として等しいことを確かめる。違ったら、どの入力のどの幅かと、両方の見え方を出す。
fn assert_same(copied: &Text<'_>, original: &Text<'_>, what: &str) {
    assert!(
        copied == original,
        "写した描画部品の出力が元と違う（{what}）\n写し: {:#?}\n元:   {:#?}",
        describe(copied),
        describe(original)
    );
}

/// 特性化試験の入力を幅40・80で描いた結果が、元と同じ。
#[test]
fn the_copy_renders_every_characterization_case_exactly_like_the_original() {
    let mut compared = 0;
    for (name, src) in CASES {
        for width in WIDTHS {
            let (copied, original) = both(src, width, false);
            assert_same(&copied, &original, &format!("{name}・幅{width}"));
            compared += 1;
        }
    }
    assert_eq!(compared, CASES.len() * WIDTHS.len());
}

/// 分岐を通す入力を、どの幅・どちらの書式で描いても、元と同じ。
#[test]
fn the_copy_renders_every_branch_input_exactly_like_the_original() {
    let mut compared = 0;
    for src in BRANCH_INPUTS {
        for width in BRANCH_WIDTHS {
            for no_color in [false, true] {
                let (copied, original) = both(src, width, no_color);
                assert_same(
                    &copied,
                    &original,
                    &format!("{src:?}・幅{width}・書式なし={no_color}"),
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, BRANCH_INPUTS.len() * BRANCH_WIDTHS.len() * 2);
}

/// 既定の書式と幅で描く入口（`render`）も、元と同じ。
#[test]
fn the_default_entry_point_renders_like_the_original() {
    for src in CASES.iter().map(|(_, src)| *src).chain(BRANCH_INPUTS) {
        let events = markdown_stream::parse_gfm(src);
        assert_same(
            &render::render(&events),
            &markdown_ratatui::render(&events),
            &format!("{src:?}・既定の入口"),
        );
    }
}

/// 書式の役割が全部同じ。描画に使われない役割（コードの色分け用に予約された`kw`・`str`・`comment`・`num`）も含める。
/// `..`を使わずに分解するので、写しの側に役割が増えたり減ったりするとここでビルドが落ちる。
#[test]
fn the_copied_theme_has_the_same_style_for_every_role() {
    for no_color in [false, true] {
        let (copied, original) = if no_color {
            (
                render::Theme::no_color(),
                markdown_ratatui::Theme::no_color(),
            )
        } else {
            (render::Theme::default(), markdown_ratatui::Theme::default())
        };
        let render::Theme {
            heading,
            code,
            link,
            muted,
            bold,
            italic,
            strike,
            kw,
            str,
            comment,
            num,
        } = copied;
        let pairs = [
            ("heading", heading, original.heading),
            ("code", code, original.code),
            ("link", link, original.link),
            ("muted", muted, original.muted),
            ("bold", bold, original.bold),
            ("italic", italic, original.italic),
            ("strike", strike, original.strike),
            ("kw", kw, original.kw),
            ("str", str, original.str),
            ("comment", comment, original.comment),
            ("num", num, original.num),
        ];
        for (role, copied, original) in pairs {
            assert_eq!(copied, original, "{role}（書式なし={no_color}）");
        }
    }
}

/// [`BRANCH_INPUTS`]が、描画部品が扱う出来事を**全種類**含む（ブロックの種類13・表の寄せ4・改行2・文中の書式5・
/// 番号付きリストの開始番号が1以外）。入力を減らしたり書き換えたりして、分岐の一部が通らなくなったら落ちる。
#[test]
fn branch_inputs_reach_every_kind_of_event_the_renderer_handles() {
    let mut seen = BTreeSet::new();
    for src in BRANCH_INPUTS {
        for event in markdown_stream::parse_gfm(src) {
            match event {
                Event::EnterBlock { block, data, .. } => {
                    seen.insert(format!("{block:?}"));
                    for align in &data.alignment {
                        seen.insert(format!("align {align:?}"));
                    }
                    if let Some(list) = &data.list {
                        if list.ordered && list.start != 1 {
                            seen.insert("ordered list not starting at 1".to_string());
                        }
                    }
                }
                Event::Text { style, .. } => {
                    for (flag, on) in [
                        ("strong", style.strong),
                        ("emphasis", style.emphasis),
                        ("strikethrough", style.strikethrough),
                        ("code", style.code),
                        ("link", style.link.is_some()),
                    ] {
                        if on {
                            seen.insert(format!("inline {flag}"));
                        }
                    }
                }
                Event::SoftBreak => {
                    seen.insert("SoftBreak".to_string());
                }
                Event::LineBreak => {
                    seen.insert("LineBreak".to_string());
                }
                Event::ExitBlock { .. } | Event::EnterInline { .. } | Event::ExitInline { .. } => {}
            }
        }
    }
    let blocks = [
        BlockKind::Document,
        BlockKind::Paragraph,
        BlockKind::Heading,
        BlockKind::BlockQuote,
        BlockKind::List,
        BlockKind::ListItem,
        BlockKind::FencedCode,
        BlockKind::IndentedCode,
        BlockKind::ThematicBreak,
        BlockKind::HtmlBlock,
        BlockKind::Table,
        BlockKind::TableRow,
        BlockKind::TableCell,
    ]
    .map(|block| format!("{block:?}"));
    let aligns = [
        Alignment::None,
        Alignment::Left,
        Alignment::Center,
        Alignment::Right,
    ]
    .map(|align| format!("align {align:?}"));
    let others = [
        "SoftBreak",
        "LineBreak",
        "inline strong",
        "inline emphasis",
        "inline strikethrough",
        "inline code",
        "inline link",
        "ordered list not starting at 1",
    ]
    .map(str::to_string);
    let missing: Vec<&String> = blocks
        .iter()
        .chain(&aligns)
        .chain(&others)
        .filter(|kind| !seen.contains(*kind))
        .collect();
    assert!(
        missing.is_empty(),
        "分岐を通す入力に、この出来事が無い: {missing:?}"
    );
}
