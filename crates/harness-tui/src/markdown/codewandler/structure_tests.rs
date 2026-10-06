//! 写した描画部品（[`super::render`]）が、入れ子のリスト・リストの中のブロック・タスクリスト・HTMLブロック・
//! コードブロックを**どの順序・どの字下げで**描くかを固定する試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT7b・
//! §1.5の2〜5）。
//!
//! # 何のためにあるのか
//!
//! 素の描画部品は、解析器が出す出来事の並びのうち、いくつかの形を取り違えていた（`super::characterization_tests`の
//! モジュールdoc）。直した後の形を、特性化試験の入力より細かく——入れ子の深さ・詰めたリストとゆるいリスト・空の項目・
//! タブ——ここで固定する。
//!
//! # 決めたこと（試験で固定する）
//!
//! - **項目の記号は、その項目の最初の行に1回だけ出る**。最初の行がコード・表・区切り線・HTMLの行でも同じ
//!   （素の描画部品は本文の段落でしか記号を出さず、コードから始まる項目は記号を失った）
//! - **詰めたリストの項目の中では、ブロックの間に空行を入れない**（項目の本文・入れ子のリスト・コード・引用の間。
//!   次の項目との間も）。ゆるいリストでは、ほかのブロックと同じく空行を1つ挟む
//! - **中身の無い項目も記号だけの1行として出す**（落とさない。行末の空白は付けない）
//! - **タスクリストの印は記号の一部**——続きの行は`[ ] `の後ろの文字に揃い、印が行の途中で分かれることは無い。
//!   `[X]`も`[x]`で描く。印として扱うのは、解析器がタスクリストの印として出す文字だけで、文中にモデルが書いた
//!   同じ形のHTMLは文字のまま出す
//! - **HTMLブロックとコードブロックの行のタブは、行の頭から数えて次の4桁の倍数の桁まで空白に置き換える**。
//!   ratatuiは制御文字を描かないので、置き換えないとタブが画面にもコピーにも出ない（計画書§0のT7bの注記）
//!
//! # 限界
//!
//! - **タブはコピーしても空白のまま**で、元のタブには戻らない。タブに意味のあるコード（Makefile等）をコピーして
//!   貼ると、そのままでは動かない
//! - 文中のHTML（`<span>`等）は、素の描画部品と同じく文字のまま書式なしで出す。HTMLとして解釈しない

use harness_term::select::LineJoin;
use ratatui::text::Text;

use super::characterization_tests::describe;
use super::wrap_tests::{draw, joined, lines_and_joins};

const CONTINUES_2: LineJoin = LineJoin::Continues { indent: 2 };
const CONTINUES_4: LineJoin = LineJoin::Continues { indent: 4 };
const CONTINUES_6: LineJoin = LineJoin::Continues { indent: 6 };

/// `src`を`width`桁で描いて、[`describe`]の形にする。
fn described(src: &str, width: usize) -> Vec<String> {
    describe(&Text::from(draw(src, width).lines))
}

/// 3段の入れ子で、どの段も幅を超える長い日本語の項目。各段の続きの行は、その段の記号の後ろの文字に揃う
/// （字下げは段ごとに2桁ずつ深くなり、印の`indent`も2・4・6）。つなぐと各項目が1行に戻る。
#[test]
fn nested_long_japanese_items_keep_their_hanging_indent_at_every_level() {
    let src = "- 親あいうえおかきくけこさしすせそ\n  - 子あいうえおかきくけこさしすせそ\n    - 孫あいうえおかきくけこさしすせそ\n";
    let (lines, joins) = lines_and_joins(src, 20);
    assert_eq!(
        lines,
        [
            "• 親あいうえおかきく",
            "  けこさしすせそ",
            "  • 子あいうえおかき",
            "    くけこさしすせそ",
            "    • 孫あいうえおか",
            "      きくけこさしす",
            "      せそ",
        ]
    );
    assert_eq!(
        joins,
        [
            LineJoin::Break,
            CONTINUES_2,
            LineJoin::Break,
            CONTINUES_4,
            LineJoin::Break,
            CONTINUES_6,
            CONTINUES_6,
        ]
    );
    assert_eq!(
        joined(&draw(src, 20)),
        [
            "• 親あいうえおかきくけこさしすせそ",
            "  • 子あいうえおかきくけこさしすせそ",
            "    • 孫あいうえおかきくけこさしすせそ",
        ]
    );
}

/// 箇条書きの中の番号付きリストは、親の記号の幅だけ字下げした所に番号を出す。入れ子のリストの後ろに続く親の項目
/// との間に空行は入らない（詰めたリスト）。
#[test]
fn an_ordered_list_nested_in_a_bullet_list_is_numbered_under_the_parent_text() {
    assert_eq!(
        described("- a\n  1. one\n  2. two\n- b\n", 40),
        ["• a", "  1. one", "  2. two", "• b"]
    );
}

/// 詰めたリストの項目の中のコードの後ろに次の項目が続くとき、間に空行は入らない（コードの前にも入らない）。
#[test]
fn a_code_block_in_a_tight_item_and_the_next_item_have_no_blank_line_between() {
    assert_eq!(
        described("- item\n  ```\n  code\n  ```\n- next\n", 40),
        ["• item", "  «code|code»", "• next"]
    );
}

/// 詰めたリストの項目の中の引用・入れ子のゆるいリストの後ろに次の項目が続くときも、間に空行は入らない
/// （引用の中の段落・内側のゆるいリストの段落が置こうとした空行は、外側の詰めたリストが打ち消す）。
/// 対照として、内側のゆるいリストの中の段落の間には空行が入る。
#[test]
fn a_quote_or_a_loose_nested_list_in_a_tight_item_and_the_next_item_have_no_blank_line_between() {
    assert_eq!(
        described("- a\n  > q\n- b\n", 40),
        ["• a", "  «muted|│ »q", "• b"]
    );
    assert_eq!(
        described("- a\n  - b\n\n  - c\n- d\n", 40),
        ["• a", "  • b", "", "  • c", "• d"]
    );
}

/// ゆるいリストの項目の中のコードは、本文の段落との間に空行を1つ挟む（ほかのブロックと同じ）。字下げは項目の字下げ。
#[test]
fn a_code_block_in_a_loose_item_is_separated_from_the_text_by_a_blank_line() {
    assert_eq!(
        described("- item\n\n  ```\n  code\n  ```\n", 40),
        ["• item", "", "  «code|code»"]
    );
}

/// コードから始まる項目は、コードの最初の行に項目の記号を出す（素の描画部品は記号を出さなかった）。
#[test]
fn an_item_that_starts_with_a_code_block_puts_the_marker_on_the_first_code_line() {
    assert_eq!(described("- ```\n  code\n  ```\n", 40), ["• «code|code»"]);
}

/// リストの中の長いコードの行は、続きの行も項目の字下げから始まる（`indent`は字下げの2文字）。つなぐと元の1行に戻る。
#[test]
fn a_long_code_line_in_a_list_continues_at_the_item_indent() {
    let src = "- a\n  ```\n  xxxxxxxxxxxx\n  ```\n";
    let (lines, joins) = lines_and_joins(src, 8);
    assert_eq!(lines, ["• a", "  xxxxxx", "  xxxxxx"]);
    assert_eq!(joins, [LineJoin::Break, LineJoin::Break, CONTINUES_2]);
    assert_eq!(joined(&draw(src, 8)), ["• a", "  xxxxxxxxxxxx"]);
}

/// 入れ子のリストの直後の引用（解析器は内側のリストの中へ出す）は、内側のリストの後ろのブロックとして、外側の項目の
/// 字下げで空行を1つ挟んで出る。
#[test]
fn a_blockquote_after_a_nested_list_stays_in_the_outer_item_after_a_blank_line() {
    assert_eq!(
        described("- a\n  - b\n\n  > q\n", 40),
        ["• a", "  • b", "", "  «muted|│ »q"]
    );
}

/// 長いタスクの項目は、続きの行が`[ ] `の後ろの文字に揃う（印の`indent`は記号と印の6文字）。
#[test]
fn a_long_task_item_wraps_under_the_text_after_the_checkbox() {
    let (lines, joins) = lines_and_joins("- [ ] あいうえおかきくけこ\n", 14);
    assert_eq!(lines, ["• [ ] あいうえ", "      おかきく", "      けこ"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_6, CONTINUES_6]);
}

/// ゆるいタスクリスト（項目の間に空行）でも印になる。番号付きリストのタスクも同じ。`[X]`は`[x]`で描く。
#[test]
fn loose_ordered_and_capital_x_task_items_also_show_brackets() {
    assert_eq!(
        described("- [ ] a\n\n- [x] b\n", 40),
        ["• [ ] a", "", "• [x] b"]
    );
    assert_eq!(
        described("1. [ ] ordered task\n", 40),
        ["1. [ ] ordered task"]
    );
    assert_eq!(described("- [X] done\n", 40), ["• [x] done"]);
}

/// **対照**: タスクリストの印として扱うのは、解析器が印として出した文字だけ。モデルが項目の本文に書いた同じ形の
/// HTMLは、文字のまま出す（`[ ]`に化けない）。
#[test]
fn an_input_tag_written_in_the_item_text_stays_literal() {
    assert_eq!(
        described("- <input disabled=\"\" type=\"checkbox\"> lit\n", 80),
        ["• <input disabled=\"\" type=\"checkbox\"> lit"]
    );
}

/// 中身の無い項目は記号だけの1行になる（落とさない。行末の空白は付けない）。中身の無いタスクも同じ。
#[test]
fn an_empty_item_is_drawn_as_its_marker_alone() {
    assert_eq!(described("-\n- b\n", 40), ["•", "• b"]);
    assert_eq!(described("- [ ]\n", 40), ["• [ ]"]);
}

/// 段落の間のHTMLブロックは、前後とも空行を1つ挟み、中の文字を1行ずつ薄い書式で出す。
#[test]
fn an_html_block_between_paragraphs_has_a_blank_line_on_each_side() {
    assert_eq!(
        described("before\n\n<div>\nhello\n</div>\n\nafter\n", 40),
        [
            "before",
            "",
            "«muted|<div>»",
            "«muted|hello»",
            "«muted|</div>»",
            "",
            "after",
        ]
    );
}

/// 解析器はHTMLのコメントのブロックを閉じずに次の段落を始める（`ExitBlock(HtmlBlock)`を出さない）。それでもコメントは
/// 文字のまま出て、次の段落とは空行で分かれる（段落の文字に混ざらない）。
#[test]
fn an_html_comment_block_the_parser_leaves_open_is_still_separated_from_the_next_paragraph() {
    assert_eq!(
        described("<!-- c -->\npara\n", 40),
        ["«muted|<!-- c -->»", "", "para"]
    );
}

/// 引用の中のHTMLブロックは、各行に縦線を付ける。幅を超える行は文字の間で切り、続きの行にも縦線を付ける。
#[test]
fn an_html_block_in_a_quote_keeps_the_bar_and_is_cut_at_the_width() {
    let src = "> <div>\n> abcdefghij\n> </div>\n";
    assert_eq!(
        described(src, 8),
        [
            "«muted|│ <div>»",
            "«muted|│ abcdef»",
            "«muted|│ ghij»",
            "«muted|│ </div>»",
        ]
    );
    assert_eq!(
        draw(src, 8).joins,
        [
            LineJoin::Break,
            LineJoin::Break,
            CONTINUES_2,
            LineJoin::Break
        ]
    );
}

/// 文中のHTMLは文字のまま、書式なしで出す（素の描画部品と同じ。HTMLとして解釈しない）。
#[test]
fn inline_raw_html_is_drawn_as_plain_text() {
    assert_eq!(
        described("a <span>raw</span> b\n", 40),
        ["a <span>raw</span> b"]
    );
}

/// コードブロックのタブは、行の頭から数えて次の4桁の倍数の桁まで空白にする（全角文字は2桁と数える）。
/// **コピーしても空白のまま**（モジュールdocの限界）。
#[test]
fn tabs_in_a_code_block_become_spaces_up_to_the_next_multiple_of_four_columns() {
    let src = "```\n\tx\nab\tc\nあ\tb\nabcd\te\n```\n";
    assert_eq!(
        described(src, 40),
        [
            "«code|    x»",
            "«code|ab  c»",
            "«code|あ  b»",
            "«code|abcd    e»",
        ]
    );
    assert_eq!(
        joined(&draw(src, 40)),
        ["    x", "ab  c", "あ  b", "abcd    e"]
    );
}

/// リストの中のコードのタブも、コードの行の頭（項目の字下げの後ろ）から数える。
#[test]
fn tabs_in_a_code_block_in_a_list_count_from_the_start_of_the_code() {
    assert_eq!(
        described("- a\n  ```\n  x\ty\n  ```\n", 40),
        ["• a", "  «code|x   y»"]
    );
}

/// HTMLブロックのタブも同じく空白にする。
#[test]
fn tabs_in_an_html_block_become_spaces() {
    assert_eq!(
        described("<div>\n\tx\n</div>\n", 40),
        ["«muted|<div>»", "«muted|    x»", "«muted|</div>»"]
    );
}
