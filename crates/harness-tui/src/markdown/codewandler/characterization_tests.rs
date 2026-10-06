//! **写した**描画部品（[`super::render`]。出典は`codewandler-markdown-ratatui` 0.2.1）が、今どう描くかを固定する試験
//! （特性化試験。計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT6で作り、T7a・T7bで期待値を書き換えた）。
//!
//! # 何のためにあるのか
//!
//! 描画部品は写して直す（計画書§1.3の結論・§1.5）。見え方を、**良いものも悪いものも「今はこう描く」として**
//! 記録しておく——直したときに何が変わったのかを、この記録の書き換えとして言えるようにするため。
//! T6で作ったときは素の描画部品（`markdown_ratatui::render_with`）を描かせていた。写しが素のものと同じに描くことを
//! 確かめてから（`super::equivalence_tests`。ここに並べた入力をそのまま使う）、直す相手である写しへ向け替えた。
//!
//! 入力は2組。
//!
//! | 組 | 入力 |
//! |---|---|
//! | ユーザーが指定した8つ（計画書§1.9） | 普通の文章／見出し／箇条書き／幅を超える日本語のリスト項目／幅を超える日本語の引用／番号付きリスト／3段の入れ子／Rustのコードブロック |
//! | 計画書§1.3が挙げた既知の不具合が出ていた入力（T7bで直した） | 詰めたリスト項目の中のコードブロック／リスト直後の引用／タスクリスト／HTMLブロック（末尾と、段落の前）／文中の書式とリンク |
//!
//! 幅は40と80。日本語の2つは**どちらの幅も超える**長さにしてある（記号を含めて、リスト項目は120桁・引用は104桁）。
//!
//! 期待値は1行を1つの文字列にしたもの（[`describe`]）。既定の書式でない区間を`«書式の名前|文字»`で囲む。
//!
//! # 解析は`parse_gfm`で行う
//!
//! この解析器の`parse`と`parse_gfm`の違いは、**タスクリスト（`- [ ]`）と、`<>`で囲まない裸のURLのリンク化**の2つだけで、
//! 表と打ち消し線はどちらでも効く（`markdown_stream::parse_gfm`のdoc。[`gfm_changes_only_task_lists_and_bare_urls`]が
//! 確かめる）。モデルの返答にはどちらも普通に出るうえ、計画書§1.5の3（タスクリストを`[ ]`／`[x]`で描く）は解析器が
//! タスクリストを見分けないと直しようがないので、GFMで解析する。**解析器の`reset`はGFMの設定まで消す**
//! （`StreamParser::reset`が`*self = Self::default()`。計画書§1.3）ので、Adapter（計画書のT8）は解析器を作り直すときに
//! `StreamParser::new_gfm`を使うこと。
//!
//! # T7aで直したもの（折り返し）
//!
//! - **日本語を折り返す**: 素の描画部品は単語の区切りがASCIIの空白・タブ・改行だけ（関数`atoms`）で、日本語の段落を
//!   丸ごと1語として幅を超えたまま1行で出していた。全角文字の間でも分けるようにし、リストの続きの行は記号の幅だけ
//!   字下げし、引用の続きの行にも縦線を付ける（[`a_long_japanese_list_item_wraps_under_the_text_after_the_bullet`]・
//!   [`a_long_japanese_blockquote_repeats_the_bar_on_continuation_lines`]）
//! - **英語の語の切れ目で分けた行は、末尾に空白を1つ残す**（コピーで1行に戻したとき、語の間に空白が残るように。
//!   計画書§2）。分ける位置そのものは素の描画部品と同じ（[`a_plain_paragraph_wraps_at_ascii_spaces_and_a_soft_break_becomes_a_space`]）
//!
//! 折り返しの約束（画面で1行に収まる・印でつなぐと元に戻る）は`super::wrap_tests`が確かめる。
//!
//! # T7bで直したもの（構造）
//!
//! T6で「既知の不具合」として固定した入力は、すべて直した後の形へ書き換えた（素の描画部品の見え方は、各試験のdocに
//! 1行ずつ残す）。
//!
//! - **入れ子のリスト**は、各段の項目が自分の記号を自分の字下げで持つ（素の描画部品は`• • • parent`と記号を1行目に
//!   重ね、子と孫は記号を失った）。詰めたリストの項目の本文を、中のブロック（入れ子のリスト・コード等）より先に出す
//! - **詰めたリスト項目の中のコードブロック**は、項目の本文の後ろに、項目の字下げで出る（素の描画部品は本文より前に
//!   出し、後ろに空白だけの行を残した）
//! - **リスト直後の引用**は、リストの後ろの別のブロックとして、ほかのブロックと同じく空行を1つ挟んで出る
//!   （解析器が引用を`List`の中——最後の`ListItem`の後、`ExitBlock(List)`の前——へ出すのを、描画部品の側で読み替える）
//! - **タスクリスト**は`• [ ] `／`• [x] `の印になる（素の描画部品は`<input disabled="" type="checkbox">`の文字列を出した）
//! - **HTMLブロック**は、中の文字を1行ずつそのまま薄い書式で出し、前後のブロックとは空行で分ける（素の描画部品は
//!   末尾のものを落とし、後ろに段落があればその段落に空行なしでつないだ）
//! - **コードブロック**の2桁の字下げを外した（コピーしたコードに余分な空白が入らないように）
//! - **リンク**は今までどおり文字だけを青の下線で描き、URLは文中に出さない。位置とURLは`Rendered::links`で返す
//!   （試験は`super::link_tests`）
//!
//! 構造ごとの細かい形（入れ子の深さ・ゆるいリスト・空の項目・タブ等）は`super::structure_tests`が固定する。
//!
//! # 限界
//!
//! - [`describe`]は書式を名前で書くだけで、`Span`の切れ目（単語ごとに別の`Span`になっていること）は残さない。
//!   切れ目まで含めた一致は`super::equivalence_tests`が`Text`同士の比較で見る。

use super::render::{self, Theme};
use ratatui::style::Style;
use ratatui::text::Text;
use unicode_width::UnicodeWidthStr;

// ユーザーが指定した8つ（計画書§1.9）。
pub(super) const PARAGRAPH: &str = "The quick brown fox jumps over the lazy dog, and then\nit keeps running far beyond the edge of the screen.\n";
pub(super) const HEADING: &str = "# Heading\n";
pub(super) const BULLET_LIST: &str = "- item 1\n- item 2\n";
pub(super) const LONG_JAPANESE_LIST_ITEM: &str = "- これは画面幅を超える長い日本語のリスト項目です。描画部品が自分で折り返すなら、二行目以降は記号の幅だけ字下げされます。\n";
pub(super) const LONG_JAPANESE_BLOCKQUOTE: &str = "> これは画面幅を超える長い日本語の引用です。描画部品が自分で折り返すなら、二行目以降にも縦線が付きます。\n";
pub(super) const ORDERED_LIST: &str = "1. item 1\n2. item 2\n";
pub(super) const NESTED_LIST: &str = "- parent\n  - child\n    - grandchild\n";
pub(super) const RUST_CODE_BLOCK: &str = "```rust\nfn main() {\n    println!(\"hello\");\n}\n```\n";

// 計画書§1.3が挙げた既知の不具合が出る入力。
pub(super) const CODE_BLOCK_IN_TIGHT_LIST_ITEM: &str = "- item\n  ```\n  code\n  ```\n";
pub(super) const QUOTE_AFTER_LIST: &str = "- item\n\n> quote\n";
pub(super) const TASK_LIST: &str = "- [ ] todo\n- [x] done\n";
pub(super) const HTML_BLOCK_AT_THE_END: &str = "<div>\nhello\n</div>\n";
pub(super) const HTML_BLOCK_BEFORE_A_PARAGRAPH: &str = "<div>\nhello\n</div>\n\nafter\n";
pub(super) const INLINE_STYLES_AND_LINK: &str =
    "**bold** *italic* `code` ~~strike~~ [link](https://example.com)\n";

/// この試験の入力の全部（`super::equivalence_tests`が同じものを使う）。
pub(super) const CASES: [(&str, &str); 14] = [
    ("PARAGRAPH", PARAGRAPH),
    ("HEADING", HEADING),
    ("BULLET_LIST", BULLET_LIST),
    ("LONG_JAPANESE_LIST_ITEM", LONG_JAPANESE_LIST_ITEM),
    ("LONG_JAPANESE_BLOCKQUOTE", LONG_JAPANESE_BLOCKQUOTE),
    ("ORDERED_LIST", ORDERED_LIST),
    ("NESTED_LIST", NESTED_LIST),
    ("RUST_CODE_BLOCK", RUST_CODE_BLOCK),
    (
        "CODE_BLOCK_IN_TIGHT_LIST_ITEM",
        CODE_BLOCK_IN_TIGHT_LIST_ITEM,
    ),
    ("QUOTE_AFTER_LIST", QUOTE_AFTER_LIST),
    ("TASK_LIST", TASK_LIST),
    ("HTML_BLOCK_AT_THE_END", HTML_BLOCK_AT_THE_END),
    (
        "HTML_BLOCK_BEFORE_A_PARAGRAPH",
        HTML_BLOCK_BEFORE_A_PARAGRAPH,
    ),
    ("INLINE_STYLES_AND_LINK", INLINE_STYLES_AND_LINK),
];

/// 描く幅（モジュールdoc）。
pub(super) const WIDTHS: [usize; 2] = [40, 80];

/// 写した描画部品で、既定の書式のまま`width`桁で描く。
fn drawn(src: &str, width: usize) -> Text<'static> {
    render::render_with(&markdown_stream::parse_gfm(src), &Theme::default(), width)
}

/// `Theme::default()`の役割ごとの書式と、その名前。
fn style_names() -> [(&'static str, Style); 7] {
    let t = Theme::default();
    [
        ("heading", t.heading),
        ("code", t.code),
        ("link", t.link),
        ("muted", t.muted),
        ("bold", t.bold),
        ("italic", t.italic),
        ("strike", t.strike),
    ]
}

/// 書式の名前。役割のどれとも一致しない書式（組み合わせ等）は`Debug`のまま書く——見たことの無い書式が出たら、
/// 期待値の文字列に現れて気づけるように。
fn style_name(style: Style) -> String {
    style_names()
        .into_iter()
        .find(|(_, s)| *s == style)
        .map_or_else(|| format!("{style:?}"), |(name, _)| name.to_string())
}

/// `text`を1行ずつ読める文字列にする。隣り合う同じ書式の`Span`はまとめ、既定でない書式の区間を`«名前|文字»`で囲む。
/// 行そのものに書式や寄せが付いていたら、行末に`⟦line …⟧`で書く（今の描画部品は付けない）。
pub(super) fn describe(text: &Text<'_>) -> Vec<String> {
    text.lines
        .iter()
        .map(|line| {
            let mut runs: Vec<(Style, String)> = Vec::new();
            for span in &line.spans {
                match runs.last_mut() {
                    Some((style, content)) if *style == span.style => {
                        content.push_str(&span.content);
                    }
                    _ => runs.push((span.style, span.content.to_string())),
                }
            }
            let mut out = String::new();
            for (style, content) in runs {
                if style == Style::default() {
                    out.push_str(&content);
                } else {
                    out.push_str(&format!("«{}|{content}»", style_name(style)));
                }
            }
            if line.style != Style::default() || line.alignment.is_some() {
                out.push_str(&format!("⟦line {:?} {:?}⟧", line.style, line.alignment));
            }
            out
        })
        .collect()
}

/// `src`を両方の幅で描いて、どちらも`expected`になることを確かめる（幅で見え方が変わらない入力用）。
fn assert_same_at_both_widths(src: &str, expected: &[&str]) {
    for width in WIDTHS {
        assert_eq!(describe(&drawn(src, width)), expected, "幅{width}");
    }
}

/// 一番広い行の表示幅（桁）。
fn widest(text: &Text<'_>) -> usize {
    text.lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
                .sum()
        })
        .max()
        .unwrap_or(0)
}

/// 普通の文章。ASCIIの空白で折り返し、分けた所の空白は前の行の末尾に残す（T7a）。段落の途中の改行（ソフト改行）は
/// 空白1つになる（`then it`）。
#[test]
fn a_plain_paragraph_wraps_at_ascii_spaces_and_a_soft_break_becomes_a_space() {
    assert_eq!(
        describe(&drawn(PARAGRAPH, 40)),
        [
            "The quick brown fox jumps over the lazy ",
            "dog, and then it keeps running far ",
            "beyond the edge of the screen.",
        ]
    );
    assert_eq!(
        describe(&drawn(PARAGRAPH, 80)),
        [
            "The quick brown fox jumps over the lazy dog, and then it keeps running far ",
            "beyond the edge of the screen.",
        ]
    );
}

/// 見出し。`#`は出さず、文字に見出しの書式（シアンの太字）を付ける。
#[test]
fn a_heading_is_drawn_without_the_hash_in_the_heading_style() {
    assert_same_at_both_widths(HEADING, &["«heading|Heading»"]);
}

/// 箇条書き。記号は`• `。
#[test]
fn a_bullet_list_uses_a_bullet_marker() {
    assert_same_at_both_widths(BULLET_LIST, &["• item 1", "• item 2"]);
}

/// 幅を超える日本語のリスト項目は全角文字の間で折り返し、続きの行は記号`• `の幅だけ字下げする（T7a。素の描画部品は
/// 折り返さず、どちらの幅でも120桁の1行で出していた）。行頭の`、`は禁則を見ないため（共有の折り返し部品と同じ限界）。
#[test]
fn a_long_japanese_list_item_wraps_under_the_text_after_the_bullet() {
    assert_eq!(
        describe(&drawn(LONG_JAPANESE_LIST_ITEM, 40)),
        [
            "• これは画面幅を超える長い日本語のリスト",
            "  項目です。描画部品が自分で折り返すなら",
            "  、二行目以降は記号の幅だけ字下げされま",
            "  す。",
        ]
    );
    assert_eq!(
        describe(&drawn(LONG_JAPANESE_LIST_ITEM, 80)),
        [
            "• これは画面幅を超える長い日本語のリスト項目です。描画部品が自分で折り返すなら、",
            "  二行目以降は記号の幅だけ字下げされます。",
        ]
    );
    for width in WIDTHS {
        assert!(widest(&drawn(LONG_JAPANESE_LIST_ITEM, width)) <= width);
    }
}

/// 幅を超える日本語の引用は全角文字の間で折り返し、続きの行にも縦線`│ `（薄い書式）を付ける（T7a。素の描画部品は
/// 折り返さず、どちらの幅でも104桁の1行で出していた）。
#[test]
fn a_long_japanese_blockquote_repeats_the_bar_on_continuation_lines() {
    assert_eq!(
        describe(&drawn(LONG_JAPANESE_BLOCKQUOTE, 40)),
        [
            "«muted|│ »これは画面幅を超える長い日本語の引用で",
            "«muted|│ »す。描画部品が自分で折り返すなら、二行",
            "«muted|│ »目以降にも縦線が付きます。",
        ]
    );
    assert_eq!(
        describe(&drawn(LONG_JAPANESE_BLOCKQUOTE, 80)),
        [
            "«muted|│ »これは画面幅を超える長い日本語の引用です。描画部品が自分で折り返すなら、二行目",
            "«muted|│ »以降にも縦線が付きます。",
        ]
    );
    for width in WIDTHS {
        assert!(widest(&drawn(LONG_JAPANESE_BLOCKQUOTE, width)) <= width);
    }
}

/// 番号付きリスト。記号は`1. `・`2. `。
#[test]
fn an_ordered_list_uses_numbers() {
    assert_same_at_both_widths(ORDERED_LIST, &["1. item 1", "2. item 2"]);
}

/// 3段の入れ子は、各段の項目が自分の記号を自分の字下げ（親の記号の幅ずつ深くなる）で持つ。段の間に空行は入らない
/// （T7b。素の描画部品は`• • • parent`と記号を1行目に重ね、子と孫は記号を失って6桁の字下げの続きの行になった）。
#[test]
fn a_three_level_nested_list_gives_each_item_its_own_marker_at_its_own_indent() {
    assert_same_at_both_widths(NESTED_LIST, &["• parent", "  • child", "    • grandchild"]);
}

/// Rustのコードブロック。フェンスと言語名は出さず、字下げを付けずにコードの書式で描く（色分けは無い）
/// （T7b。素の描画部品は各行に2桁の字下げを付けた——コピーしたコードに余分な空白が入る）。
#[test]
fn a_rust_code_block_is_drawn_without_an_indent_in_the_code_style() {
    assert_same_at_both_widths(
        RUST_CODE_BLOCK,
        &[
            "«code|fn main() {»",
            "«code|    println!(\"hello\");»",
            "«code|}»",
        ],
    );
}

/// 詰めたリスト項目の中のコードブロックは、項目の本文の後ろに、項目の字下げ（記号の幅）で出る。空白だけの行は残らない
/// （T7b。素の描画部品は`["    code", "", "• item", "  "]`と本文より前に出した）。
#[test]
fn a_code_block_in_a_tight_list_item_follows_the_item_text_at_the_item_indent() {
    assert_same_at_both_widths(CODE_BLOCK_IN_TIGHT_LIST_ITEM, &["• item", "  «code|code»"]);
}

/// リスト直後の引用は、リストの後ろの別のブロックとして、空行を1つ挟んで字下げなしで出る（モジュールdoc。T7b。
/// 素の描画部品は空行を挟まなかった）。
#[test]
fn a_blockquote_after_a_list_comes_after_a_blank_line_at_the_top_level() {
    assert_same_at_both_widths(QUOTE_AFTER_LIST, &["• item", "", "«muted|│ »quote"]);
}

/// タスクリストの印は`[ ]`／`[x]`で、項目の記号の後ろに付く（T7b。素の描画部品はHTMLの文字列
/// `<input disabled="" type="checkbox">`のまま出し、幅40ではそれを折り返した）。
#[test]
fn a_task_list_shows_the_checkbox_as_brackets() {
    assert_same_at_both_widths(TASK_LIST, &["• [ ] todo", "• [x] done"]);
}

/// 末尾のHTMLブロックは、中の文字を1行ずつそのまま薄い書式で出す（T7b。素の描画部品は1行も出さなかった）。
#[test]
fn an_html_block_at_the_end_is_drawn_as_its_literal_lines() {
    assert_same_at_both_widths(
        HTML_BLOCK_AT_THE_END,
        &["«muted|<div>»", "«muted|hello»", "«muted|</div>»"],
    );
}

/// 段落の前のHTMLブロックは、ほかのブロックと同じく空行を1つ挟んで段落と分かれる（T7b。素の描画部品は
/// `["<div>", "hello", "</div>", "after"]`と段落に空行なしでつないだ——中の文字を段落の文字として溜めていた）。
#[test]
fn an_html_block_before_a_paragraph_is_separated_from_it_by_a_blank_line() {
    assert_same_at_both_widths(
        HTML_BLOCK_BEFORE_A_PARAGRAPH,
        &[
            "«muted|<div>»",
            "«muted|hello»",
            "«muted|</div>»",
            "",
            "after",
        ],
    );
}

/// 文中の書式は単語ごとに付き、間の空白には付かない。**リンクは文字だけ**を青の下線で描き、URLは文中に出さない
/// （URLと位置は`Rendered::links`で返す。`super::link_tests`）。
#[test]
fn inline_styles_are_applied_and_a_link_shows_only_its_text() {
    assert_same_at_both_widths(
        INLINE_STYLES_AND_LINK,
        &["«bold|bold» «italic|italic» «code|code» «strike|strike» «link|link»"],
    );
}

/// `parse`と`parse_gfm`の違い（モジュールdoc）。ここに並べた入力では**タスクリストだけ**が変わり、裸のURLも変わる。
/// 他の入力（表と打ち消し線を含む）は同じ出来事になる。
#[test]
fn gfm_changes_only_task_lists_and_bare_urls() {
    for (name, src) in CASES {
        let same = markdown_stream::parse(src) == markdown_stream::parse_gfm(src);
        assert_eq!(same, src != TASK_LIST, "{name}");
    }
    let table_and_strike = "| a | b |\n|---|---|\n| ~~x~~ | y |\n";
    assert_eq!(
        markdown_stream::parse(table_and_strike),
        markdown_stream::parse_gfm(table_and_strike)
    );
    let bare_url = "see https://example.com now\n";
    assert_ne!(
        markdown_stream::parse(bare_url),
        markdown_stream::parse_gfm(bare_url)
    );
}
