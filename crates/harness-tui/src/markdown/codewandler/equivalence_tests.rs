//! 写した描画部品（[`super::render`]）が、写す前の描画部品（`codewandler-markdown-ratatui` 0.2.1の
//! `markdown_ratatui`）と**同じ出力を返す**ことを確かめる試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT6・T7a）。
//!
//! # 何のためにあるのか
//!
//! 描画部品は「既存の動く実装を機械的に写してから直す」（計画書§1.3の結論。グローバル規約の「既存のリファレンス
//! 実装をテンプレートにする」）。写す途中で1か所でも変わっていたら、それは直す前から別物になっている。
//! だから写した直後に、元と出力が**1つも違わない**ことを、文字だけでなく書式と`Span`の切れ目まで含めて
//! （`ratatui::text::Text`同士の`==`で）確かめた（T6）。
//!
//! # T7a（折り返しを直した）の後に比べるもの
//!
//! T7aで直したのは**幅に合わせて行を分けるところだけ**である（全角文字の間で分ける・長い語を文字の間で切る・
//! 幅の下限20をやめる・分けた所の空白を前の行の末尾に残す・コードと表の行を幅で切る・区切り線を字下げの後ろの幅に
//! 収める）。だから、**元の描画部品の出力が幅に左右されない**入力と幅の組では、写しも元と1つも違ってはいけない。
//! 「幅に左右されない」は[`original_ignores_width`]で決める——その幅で描いた結果が、どこでも分けない広い幅で
//! 描いた結果と同じで、どの行もその幅に収まっている（元が折り返した・はみ出した・下限20へ切り上げた組を除く）。
//! 外れた組の見え方は`super::characterization_tests`と`super::wrap_tests`が固定する。
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
//!   試したことにはならない。写した手順と、写した後に変えたものは`render.rs`の冒頭に書いてある。
//! - 比べる組は[`original_ignores_width`]で選ぶので、選ばれる組が減っても試験は緑のまま残り得る。比べた組の数の
//!   下限と、必ず比べる組（[`MUST_COMPARE`]）を確かめて、選び方が空回りしていないことを見る。
//! - 計画書のT7bで構造の不具合（入れ子のリスト・タスクリスト・HTMLブロック・コードの字下げ・リンク）を直すと、
//!   それらの入力は幅に関係なく元と違うのが正しくなる。T7bでさらに絞る。

use std::collections::BTreeSet;

use markdown_stream::{Alignment, BlockKind, Event};
use ratatui::text::Text;

use super::characterization_tests::{describe, CASES, WIDTHS};
use super::render;

/// 描画部品の分岐を全部通すための入力（モジュールdoc）。`super::wrap_tests`も使う。
pub(super) const BRANCH_INPUTS: [&str; 23] = [
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

/// どこでも分けない十分に広い幅（[`original_ignores_width`]）。
const WIDE: usize = 10_000;

/// 元の描画部品の出力が、`width`桁で描いても幅に左右されないか（モジュールdoc）。`width`で描いた結果が
/// どこでも分けない広い幅で描いた結果と同じで、どの行も`width`桁に収まっていれば真。
fn original_ignores_width(src: &str, width: usize) -> bool {
    let events = markdown_stream::parse_gfm(src);
    let theme = markdown_ratatui::Theme::default();
    let at_width = markdown_ratatui::render_with(&events, &theme, width);
    at_width == markdown_ratatui::render_with(&events, &theme, WIDE)
        && at_width.lines.iter().all(|line| line.width() <= width)
}

/// 選び方が空回りしていないことを見るために、**必ず比べる**組（入力・幅）。T7aで変えてはいけない書式を並べる——
/// 短い箇条書き・番号付きリスト・見出し・コード・文中の書式とリンク・収まる表・引用の入れ子。
const MUST_COMPARE: [(&str, usize); 9] = [
    (super::characterization_tests::HEADING, 40),
    (super::characterization_tests::BULLET_LIST, 40),
    (super::characterization_tests::ORDERED_LIST, 40),
    (super::characterization_tests::RUST_CODE_BLOCK, 40),
    (super::characterization_tests::INLINE_STYLES_AND_LINK, 80),
    (super::characterization_tests::TASK_LIST, 80),
    (BRANCH_INPUTS[9], 40),
    (BRANCH_INPUTS[5], 40),
    (BRANCH_INPUTS[3], 120),
];

/// 特性化試験の入力を幅40・80で描いた結果が、元の出力が幅に左右されない組では元と同じ。
#[test]
fn the_copy_renders_every_characterization_case_the_original_draws_regardless_of_width() {
    let mut compared = 0;
    for (name, src) in CASES {
        for width in WIDTHS {
            if !original_ignores_width(src, width) {
                continue;
            }
            let (copied, original) = both(src, width, false);
            assert_same(&copied, &original, &format!("{name}・幅{width}"));
            compared += 1;
        }
    }
    // 14入力×2幅のうち、折り返す・はみ出すのは普通の文章（両方の幅）・日本語の2つ（両方の幅）・タスクリスト（幅40）。
    assert_eq!(compared, CASES.len() * WIDTHS.len() - 7);
}

/// 分岐を通す入力を、どちらの書式で描いても、元の出力が幅に左右されない組では元と同じ。
#[test]
fn the_copy_renders_every_branch_input_the_original_draws_regardless_of_width() {
    let mut compared = 0;
    for src in BRANCH_INPUTS {
        for width in BRANCH_WIDTHS {
            if !original_ignores_width(src, width) {
                continue;
            }
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
    // 23入力×8幅×2書式のうち、半分を下回るほど外れたら選び方を疑う。
    assert!(
        compared >= BRANCH_INPUTS.len() * BRANCH_WIDTHS.len(),
        "比べたのが{compared}組しか無い"
    );
}

/// 既定の書式と幅（80桁）で描く入口（`render`）も、元の出力が幅に左右されない入力では元と同じ。
#[test]
fn the_default_entry_point_renders_like_the_original_when_the_width_does_not_matter() {
    let mut compared = 0;
    for src in CASES.iter().map(|(_, src)| *src).chain(BRANCH_INPUTS) {
        if !original_ignores_width(src, 80) {
            continue;
        }
        let events = markdown_stream::parse_gfm(src);
        assert_same(
            &render::render(&events),
            &markdown_ratatui::render(&events),
            &format!("{src:?}・既定の入口"),
        );
        compared += 1;
    }
    assert!(compared >= 20, "比べたのが{compared}入力しか無い");
}

/// **選び方の対照**: 必ず比べる組（[`MUST_COMPARE`]）は選ばれ、元が折り返した組・はみ出した組は外れる。
/// 外れた組では、写しは実際に元と違う（T7aの直しが効いていて、外すのが必要だった）。
#[test]
fn the_comparison_keeps_the_formats_t7a_must_not_change_and_skips_the_wrapped_ones() {
    for (src, width) in MUST_COMPARE {
        assert!(
            original_ignores_width(src, width),
            "比べるはずの組が外れた: {src:?}・幅{width}"
        );
    }
    let wrapped = [
        (super::characterization_tests::PARAGRAPH, 40),
        (super::characterization_tests::PARAGRAPH, 80),
        (super::characterization_tests::LONG_JAPANESE_LIST_ITEM, 80),
        (super::characterization_tests::LONG_JAPANESE_BLOCKQUOTE, 40),
        (BRANCH_INPUTS[9], 24),
    ];
    for (src, width) in wrapped {
        assert!(
            !original_ignores_width(src, width),
            "元が折り返す組なのに比べる側に入った: {src:?}・幅{width}"
        );
        let (copied, original) = both(src, width, false);
        assert!(
            copied != original,
            "元が折り返す組で、写しが元と同じに描いた: {src:?}・幅{width}"
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
