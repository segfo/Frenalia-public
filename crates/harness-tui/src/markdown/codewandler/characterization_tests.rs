//! **素の**描画部品（`codewandler-markdown-ratatui` 0.2.1の`markdown_ratatui::render_with`。手を入れる前のもの）が、
//! 今どう描くかを固定する試験（特性化試験。計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT6）。
//!
//! # 何のためにあるのか
//!
//! 描画部品は写して直す（計画書§1.3の結論・§1.5）。直す前の見え方を、**良いものも悪いものも「今はこう描く」として**
//! 記録しておく——直した後に何が変わったのかを、この記録との差として言えるようにするため。
//! 写した描画部品が元と同じに描くことは`super::equivalence_tests`が確かめ、ここに並べた入力をそのまま使う。
//!
//! 入力は2組。
//!
//! | 組 | 入力 |
//! |---|---|
//! | ユーザーが指定した8つ（計画書§1.9） | 普通の文章／見出し／箇条書き／幅を超える日本語のリスト項目／幅を超える日本語の引用／番号付きリスト／3段の入れ子／Rustのコードブロック |
//! | 計画書§1.3が挙げた既知の不具合が出る入力 | 詰めたリスト項目の中のコードブロック／リスト直後の引用／タスクリスト／HTMLブロック（末尾と、段落の前）／文中の書式とリンク |
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
//! # 今の見え方で、直すもの（計画書のT7）
//!
//! - **日本語は折り返さない**: 単語の区切りがASCIIの空白・タブ・改行だけ（描画部品の関数`atoms`）なので、日本語の
//!   段落は丸ごと1語になり、幅を超えたまま1行で出る（[`a_long_japanese_list_item_is_not_wrapped`]・
//!   [`a_long_japanese_blockquote_is_not_wrapped`]）
//! - **入れ子のリスト**は記号が1行目に重なって`• • • parent`になり、子と孫は記号を失って続きの行として出る
//! - **詰めたリスト項目の中のコードブロック**は、項目の本文より前に出る（後ろに空白だけの行が残る）
//! - **リスト直後の引用**は、リストとの間に空行が入らない（解析器が引用を`List`の中——最後の`ListItem`の後、
//!   `ExitBlock(List)`の前——へ出し、描画部品はリストが閉じたときに付ける空行を付けない）
//! - **タスクリスト**は`<input disabled="" type="checkbox">`の文字列のまま出る
//! - **HTMLブロック**は、末尾にあると落ちる（1行も出ない）。後ろに段落があると、その段落に空行なしでつながる
//!   （描画部品が`HtmlBlock`を扱わず、中の文字を次の段落の文字として溜めるため）
//! - **リンク**はURLを捨て、文字だけを描く
//! - コードブロックに2桁の字下げが付く
//!
//! 直したら、この試験の期待値を直した後の形へ書き換える（計画書§0のT7）。
//!
//! # 限界
//!
//! - [`describe`]は書式を名前で書くだけで、`Span`の切れ目（単語ごとに別の`Span`になっていること）は残さない。
//!   切れ目まで含めた一致は`super::equivalence_tests`が`Text`同士の比較で見る。

use markdown_ratatui::Theme;
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

/// 素の描画部品で、既定の書式のまま`width`桁で描く。
fn original(src: &str, width: usize) -> Text<'static> {
    markdown_ratatui::render_with(&markdown_stream::parse_gfm(src), &Theme::default(), width)
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
        assert_eq!(describe(&original(src, width)), expected, "幅{width}");
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

/// 普通の文章。ASCIIの空白で折り返す。段落の途中の改行（ソフト改行）は空白1つになる（`then it`）。
#[test]
fn a_plain_paragraph_wraps_at_ascii_spaces_and_a_soft_break_becomes_a_space() {
    assert_eq!(
        describe(&original(PARAGRAPH, 40)),
        [
            "The quick brown fox jumps over the lazy",
            "dog, and then it keeps running far",
            "beyond the edge of the screen.",
        ]
    );
    assert_eq!(
        describe(&original(PARAGRAPH, 80)),
        [
            "The quick brown fox jumps over the lazy dog, and then it keeps running far",
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

/// **既知の不具合**: 幅を超える日本語のリスト項目を折り返さない。どちらの幅でも1行のまま出る（120桁）。
#[test]
fn a_long_japanese_list_item_is_not_wrapped() {
    assert_same_at_both_widths(
        LONG_JAPANESE_LIST_ITEM,
        &["• これは画面幅を超える長い日本語のリスト項目です。描画部品が自分で折り返すなら、二行目以降は記号の幅だけ字下げされます。"],
    );
    for width in WIDTHS {
        assert_eq!(widest(&original(LONG_JAPANESE_LIST_ITEM, width)), 120);
    }
}

/// **既知の不具合**: 幅を超える日本語の引用を折り返さない。縦線`│ `は薄い書式で、1行のまま出る（104桁）。
#[test]
fn a_long_japanese_blockquote_is_not_wrapped() {
    assert_same_at_both_widths(
        LONG_JAPANESE_BLOCKQUOTE,
        &["«muted|│ »これは画面幅を超える長い日本語の引用です。描画部品が自分で折り返すなら、二行目以降にも縦線が付きます。"],
    );
    for width in WIDTHS {
        assert_eq!(widest(&original(LONG_JAPANESE_BLOCKQUOTE, width)), 104);
    }
}

/// 番号付きリスト。記号は`1. `・`2. `。
#[test]
fn an_ordered_list_uses_numbers() {
    assert_same_at_both_widths(ORDERED_LIST, &["1. item 1", "2. item 2"]);
}

/// **既知の不具合**: 3段の入れ子は、記号が1行目に3つ重なり、子と孫は記号を失って続きの行（6桁の字下げ）になる。
#[test]
fn a_three_level_nested_list_stacks_the_markers_on_the_first_line() {
    assert_same_at_both_widths(
        NESTED_LIST,
        &["• • • parent", "      child", "      grandchild"],
    );
}

/// Rustのコードブロック。フェンスと言語名は出さず、各行に2桁の字下げとコードの書式を付ける（色分けは無い）。
#[test]
fn a_rust_code_block_is_indented_by_two_columns_in_the_code_style() {
    assert_same_at_both_widths(
        RUST_CODE_BLOCK,
        &[
            "  «code|fn main() {»",
            "  «code|    println!(\"hello\");»",
            "  «code|}»",
        ],
    );
}

/// **既知の不具合**: 詰めたリスト項目の中のコードブロックが、項目の本文より前に出る。最後に空白だけの行が残る。
#[test]
fn a_code_block_in_a_tight_list_item_comes_before_the_item_text() {
    assert_same_at_both_widths(
        CODE_BLOCK_IN_TIGHT_LIST_ITEM,
        &["    «code|code»", "", "• item", "  "],
    );
}

/// **既知の不具合**: リスト直後の引用が、リストとの間に空行なしで続く（モジュールdoc）。
#[test]
fn a_blockquote_after_a_list_has_no_blank_line_before_it() {
    assert_same_at_both_widths(QUOTE_AFTER_LIST, &["• item", "«muted|│ »quote"]);
}

/// **既知の不具合**: タスクリストの印がHTMLの文字列のまま出る。その文字列もASCIIの空白で折り返す。
#[test]
fn a_task_list_shows_the_checkbox_as_an_html_string() {
    assert_eq!(
        describe(&original(TASK_LIST, 40)),
        [
            "• <input disabled=\"\" type=\"checkbox\">",
            "  todo",
            "• <input checked=\"\" disabled=\"\"",
            "  type=\"checkbox\"> done",
        ]
    );
    assert_eq!(
        describe(&original(TASK_LIST, 80)),
        [
            "• <input disabled=\"\" type=\"checkbox\"> todo",
            "• <input checked=\"\" disabled=\"\" type=\"checkbox\"> done",
        ]
    );
}

/// **既知の不具合**: 末尾のHTMLブロックは1行も出ない。
#[test]
fn an_html_block_at_the_end_is_dropped() {
    assert_same_at_both_widths(HTML_BLOCK_AT_THE_END, &[]);
}

/// **既知の不具合**: 段落の前のHTMLブロックは、その段落に空行なしでつながる。
#[test]
fn an_html_block_before_a_paragraph_is_glued_to_it() {
    assert_same_at_both_widths(
        HTML_BLOCK_BEFORE_A_PARAGRAPH,
        &["<div>", "hello", "</div>", "after"],
    );
}

/// 文中の書式は単語ごとに付き、間の空白には付かない。**リンクはURLを捨てて文字だけ**を描く（青の下線）。
#[test]
fn inline_styles_are_applied_and_a_link_drops_its_url() {
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
