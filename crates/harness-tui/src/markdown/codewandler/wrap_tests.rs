//! 写した描画部品（[`super::render`]）が自分で行を分ける（折り返す）ときの約束を確かめる試験
//! （計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT7a・§1.5の1と7・§2）。
//!
//! # 何のためにあるのか
//!
//! 描画部品は、長い1行を渡された幅に合わせて自分で複数の行へ分ける。リストの2行目以降の字下げ（継続インデント）を
//! 保つためである（計画書§1.2）。分けた行は、次の2つの約束を守らないといけない。
//!
//! 1. **画面で1行に収まる。** transcriptは描くときに、共有の折り返し部品（`harness_term::wrap`）をもう一度通す。
//!    描画部品の出した行が幅を超えていると、そこで折り返し直されて継続インデントが消える（計画書§1.9の不変条件）。
//!    行末が全角の行は、共有の部品では1行と数えられたまま右へ1桁はみ出す（BUG-200）ので、行数だけでなく
//!    **桁数でも**確かめる
//! 2. **コピーで元の1行に戻る。** 自分で分けた行には`LineJoin::Continues { indent }`を付ける。範囲選択のコピーは、
//!    その行の前に改行を入れず、行の頭の`indent`文字（続きの行に付けた字下げ）を写さない（`harness_term::select`。
//!    計画書§2）。英語の語の切れ目で分けたときは、空白を**前の行の末尾に残す**——つないだときに語の間の空白が
//!    1つだけ残る
//!
//! # 決めたこと（試験で固定する）
//!
//! - 分けてよい所は、ASCIIの空白・全角文字（`unicode-width`で幅2）とその隣の文字の間・幅を超える語の文字
//!   （書記素）の間。禁則（句読点を行頭に置かない等）は見ない——共有の折り返し部品と同じ限界
//! - 空白の後ろで分ける語は、**その空白の1桁まで含めて**行に収める。行をちょうど埋める語の後ろで分けると、
//!   残した空白が幅を超えるため。その語が行の頭から置いても空白の1桁ぶん入らないときは、文字の間で切る
//! - 字下げの後に1文字（と、その語の後ろに残す空白）も入らないほど狭いときだけ、**1行に1文字を置いて幅を超える**
//!   （何も描けない形にはしない）
//! - コードの行・表の行・HTMLブロックの行も、幅を超えたら文字の間で切る。続きの行には、最初の行と同じ字下げ
//!   （入れ子の字下げ。入れ子でなければ0）を付け、その文字数を`indent`にする——コピーすると元の1行に戻る
//!
//! # 限界
//!
//! - コピーの戻り方は、`harness_term::select::map::extract`と同じつなぎ方を[`joined`]で真似て確かめる
//!   （`extract`は`harness-term`の外から呼べない）。本物の範囲選択とコピーを通して確かめるのは計画書のT9
//! - 区切り線（`---`）は幅に合わせて長さを変える（最大60桁）ので、「つなぐと元に戻る」の対象から外す。
//!   長さは[`a_thematic_break_inside_a_quote_fits_the_width`]が固定する

use harness_term::select::LineJoin;
use harness_term::wrap::{line_rows, text_width};
use markdown_stream::{BlockKind, Event};
use ratatui::buffer::CellWidth;
use ratatui::style::Style;
use ratatui::text::{Line, Text};

use super::characterization_tests::{describe, CASES};
use super::equivalence_tests::BRANCH_INPUTS;
use super::render::{self, Theme};
use crate::markdown::Rendered;

/// どこでも分けない十分に広い幅。この幅で描いた行が「論理行」（分ける前の1行）になる。
const WIDE: usize = 10_000;

/// 不変条件を確かめる、transcriptの枠の内側の幅。描画部品へ渡すのは`text_width`で狭めた幅（`MarkdownView`と同じ）。
/// 一番狭い10桁でも、入力の一番深い字下げ（6桁）の後ろに3桁残る——1行に1文字だけ置く狭さにはしない。
const INNER_WIDTHS: [u16; 5] = [10, 21, 40, 80, 120];

/// 狭すぎて1行に1文字しか置けない幅も含めた幅（コピーで元に戻ることだけを確かめる）。
const ANY_INNER_WIDTHS: [u16; 9] = [0, 1, 2, 3, 10, 21, 40, 80, 120];

/// 折り返しを試すための長い入力（特性化試験と同等性の試験の入力に足す）。
const LONG_INPUTS: [&str; 23] = [
    // 長い日本語の段落と、英語の混ざった段落
    "日本語の長い段落です。画面の幅を超えても、全角文字の間で折り返されて、次の行へ続いていきます。さらに続きます。\n",
    "日本語とEnglishが混ざった文章です。The quick brown fox jumps over the lazy dog、そして日本語に戻ります。\n",
    // 長い英語の段落（ソフト改行を含む）
    "The quick brown fox jumps over the lazy dog, and then it keeps running far beyond the edge of the screen,\nwhile the dog keeps sleeping in the warm afternoon sun without noticing anything at all.\n",
    // 長いURL・パス・識別子
    "See https://example.com/a/very/long/path/that/never/ends/and/keeps/going/index.html?query=1&other=2 for details.\n",
    "Path: C:/Users/segfo/Documents/AI/harness/crates/harness-tui/src/markdown/codewandler/render.rs is long.\n",
    "Identifier `a_really_long_identifier_name_that_goes_on_and_on_without_any_break` here.\n",
    // 3段の入れ子で、どの段も長い
    "- 親の項目です。長い説明が続いて、画面の幅を超えて折り返されます。\n  - 子の項目です。こちらも長い説明が続いて、画面の幅を超えて折り返されます。\n    - 孫の項目です。the grandchild item has a long English sentence that wraps too.\n",
    // 番号が2桁の番号付きリスト
    "10. 二桁の番号の項目です。字下げは記号の幅の4桁になります。長いので折り返されます。\n11. next item with English words that also wrap around the narrow width.\n",
    // 入れ子の引用
    "> > 入れ子の引用です。縦線が2本付いて、長い文章は折り返されても縦線を保ちます。\n",
    // 長いコードの行（英語・日本語・タブ）、引用の中のコード
    "```\nlet value = some_function_with_a_long_name(argument_one, argument_two, argument_three);\n\tlet 日本語の変数 = \"全角の文字列がコードの中で長く続いて画面の幅を超える\";\n```\n",
    "> ```\n> quoted code line that is long enough to be cut at narrow widths for sure\n> ```\n",
    // 幅の広い表（日本語のセルを含む）
    "| 名前 | 説明 | 備考 |\n|---|:---:|---:|\n| 長い名前の列 | とても長い説明の文章がこの列に入ります | right aligned note |\n| x | y | z |\n",
    // 長い見出し・文中の書式をまたぐ折り返し
    "# とても長い見出しです。見出しも画面の幅を超えたら折り返されて、続きの行になります。\n",
    "**太字の長い文章がここで続きます**と*斜体の文章*と`コード`と~~打ち消し~~が混ざった長い段落です。\n",
    // ハードな改行の後ろに長い行
    "first line with a hard break  \nsecond line is very long and keeps going beyond the narrow width of the screen\n",
    // 語の途中で書式が変わる（空白の無い所で書式が切り替わる）
    "foo**bar**baz qux**quux**corge grault garply waldo fred plugh xyzzy thud\n",
    // 番号付きリストを入れ子にした箇条書き（T7b）。どの段も長い日本語
    "- 箇条書きの親の項目です。長い説明が続いて、画面の幅を超えて折り返されます。\n  1. 番号付きの子の項目です。こちらも長い説明が続いて折り返されます。\n  2. 二つ目の子の項目です。\n- 次の親の項目です。\n",
    // 詰めたリスト・ゆるいリストの項目の中の長いコードの行（T7b。タブで始まる行を含む）
    "- 項目の本文です。長い説明が続いて、画面の幅を超えて折り返されます。\n  ```\n  let value = some_function_with_a_long_name(argument_one, argument_two);\n  ```\n- 次の項目\n",
    "- ゆるいリストの項目です。\n\n  ```\n  \tlet 日本語 = \"タブで始まる長いコードの行が、画面の幅を超えて続きます\";\n  ```\n",
    // 長いタスクリスト（T7b）
    "- [ ] まだ終わっていない長いタスクです。説明が続いて、画面の幅を超えて折り返されます。\n- [x] done task with a long English sentence that wraps around the narrow width.\n",
    // 長い行を含むHTMLブロック（T7b。タブで始まる行を含む）
    "<div class=\"a-very-long-class-name-that-keeps-going\">\n\t日本語の長い文字列がHTMLブロックの中で続いて、画面の幅を超えます\n</div>\n\nafter\n",
    // 折り返しをまたぐリンク（文字が長い日本語・英語・裸のURL。T7b）
    "前置き [折り返しをまたぐ長いリンクの文字がここに続いて画面の幅を超えます](https://example.com/a) の後ろ。\n",
    "See [a link whose text is long enough to wrap](https://example.com/very/long/path) and https://bare.example.com/also/a/long/path/to/cut here.\n",
];

/// `src`をGFMで解析し、既定の書式のまま`width`桁で描く。
pub(super) fn draw(src: &str, width: usize) -> Rendered {
    render::render_lines(&markdown_stream::parse_gfm(src), &Theme::default(), width)
}

/// 行の文字（書式を見ない）。
pub(super) fn plain(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

/// 行の桁数。共有の折り返し部品（ratatuiの`WordWrapper`）と同じ数え方——描かれる書記素ごとの`cell_width`の和。
fn columns(line: &Line<'_>) -> usize {
    line.styled_graphemes(Style::default())
        .map(|grapheme| usize::from(grapheme.symbol.cell_width()))
        .sum()
}

/// 行と印を、印に従ってつなぐ（`harness_term::select::map::extract`で全体を選んだときと同じつなぎ方）。
/// `Break`の行で新しい論理行を始め、`Continues { indent }`の行は前の論理行へ、頭の`indent`文字を除いてつなぐ。
/// 描かれない文字（幅0）は入れない（`extract`と同じ）。
pub(super) fn joined(rendered: &Rendered) -> Vec<String> {
    assert_eq!(
        rendered.lines.len(),
        rendered.joins.len(),
        "行と印の数が違う"
    );
    let mut out: Vec<String> = Vec::new();
    for (index, (line, join)) in rendered.lines.iter().zip(&rendered.joins).enumerate() {
        let skip = match join {
            LineJoin::Break => {
                out.push(String::new());
                0
            }
            LineJoin::Continues { indent } => *indent,
        };
        let target = out
            .last_mut()
            .unwrap_or_else(|| panic!("最初の行（{index}行目）が続きの行になっている"));
        for grapheme in line.styled_graphemes(Style::default()).skip(skip) {
            if grapheme.symbol.cell_width() > 0 {
                target.push_str(grapheme.symbol);
            }
        }
    }
    out
}

/// 行の文字と印。
pub(super) fn lines_and_joins(src: &str, width: usize) -> (Vec<String>, Vec<LineJoin>) {
    let rendered = draw(src, width);
    (rendered.lines.iter().map(plain).collect(), rendered.joins)
}

/// 区切り線（`---`）を含むか（[`joining_the_lines_by_their_marks_gives_back_the_logical_lines`]から外す。モジュールdoc）。
fn has_thematic_break(src: &str) -> bool {
    markdown_stream::parse_gfm(src).iter().any(|event| {
        matches!(
            event,
            Event::EnterBlock {
                block: BlockKind::ThematicBreak,
                ..
            }
        )
    })
}

/// 行末が全角の行（BUG-200の形）。`x`の数で全角文字の始まる桁の偶奇が変わるので、3通り。
fn lines_ending_in_a_wide_character() -> Vec<String> {
    let mut inputs = Vec::new();
    for head in 1..=3 {
        let body = format!("{} {}", "x".repeat(head), "あ".repeat(60));
        inputs.push(format!("{body}\n"));
        inputs.push(format!("- {body}\n"));
        inputs.push(format!("> {body}\n"));
    }
    inputs
}

/// 不変条件を確かめる入力の全部（`super::link_tests`も使う）。
pub(super) fn all_inputs() -> Vec<String> {
    CASES
        .iter()
        .map(|(_, src)| *src)
        .chain(BRANCH_INPUTS)
        .chain(LONG_INPUTS)
        .map(str::to_string)
        .chain(lines_ending_in_a_wide_character())
        .collect()
}

const CONTINUES_0: LineJoin = LineJoin::Continues { indent: 0 };
const CONTINUES_2: LineJoin = LineJoin::Continues { indent: 2 };
const CONTINUES_4: LineJoin = LineJoin::Continues { indent: 4 };

/// **不変条件（計画書§1.9）**: 描画部品が出した行は、どれも共有の折り返し部品で**1行**に数えられ、
/// 桁数も渡した幅を超えない（行末が全角の行・長いURL・長いコード行・幅の広い表・3段の入れ子を含む）。
#[test]
fn every_line_the_renderer_emits_takes_exactly_one_row_of_the_shared_wrapper() {
    let mut lines_checked = 0;
    let mut continued = 0;
    for src in all_inputs() {
        for inner in INNER_WIDTHS {
            let width = usize::from(text_width(inner));
            let rendered = draw(&src, width);
            assert_eq!(
                rendered.lines.len(),
                rendered.joins.len(),
                "{src:?}・幅{width}"
            );
            for line in &rendered.lines {
                assert!(
                    columns(line) <= width,
                    "幅{width}を超える行（{}桁）: {:?}\n入力: {src:?}",
                    columns(line),
                    plain(line)
                );
            }
            let rows = line_rows(Text::from(rendered.lines.clone()), inner);
            for (line, rows) in rendered.lines.iter().zip(rows) {
                assert_eq!(
                    rows,
                    1,
                    "共有の折り返し部品が折り返し直す行（枠の内側{inner}桁）: {:?}\n入力: {src:?}",
                    plain(line)
                );
            }
            lines_checked += rendered.lines.len();
            continued += rendered
                .joins
                .iter()
                .filter(|join| matches!(join, LineJoin::Continues { .. }))
                .count();
        }
    }
    // 試験が空回りしていないこと（入力が描かれていて、実際に分けた行がある）。2026-10-06の実測は1,827行・分けた行1,147。
    assert!(
        lines_checked > 1_500,
        "確かめた行が{lines_checked}行しか無い"
    );
    assert!(continued > 900, "分けた行が{continued}行しか無い");
}

/// **コピーで元に戻る（計画書§2）**: どの幅で描いても、印に従ってつなぐと、どこでも分けない広い幅で描いた行
/// （論理行）と同じになる。英語の語の間の空白はちょうど1つ残り、全角文字の間には何も入らない。
/// 1行に1文字しか置けない狭さ（幅0〜2）でも同じ。
#[test]
fn joining_the_lines_by_their_marks_gives_back_the_logical_lines() {
    let mut compared = 0;
    for src in all_inputs() {
        if has_thematic_break(&src) {
            continue;
        }
        let logical = draw(&src, WIDE);
        assert!(
            logical.joins.iter().all(|join| *join == LineJoin::Break),
            "どこでも分けない幅なのに分けた: {src:?}"
        );
        let want = joined(&logical);
        for inner in ANY_INNER_WIDTHS {
            let width = usize::from(text_width(inner));
            assert_eq!(
                joined(&draw(&src, width)),
                want,
                "幅{width}で描いてつなぐと元に戻らない: {src:?}"
            );
            compared += 1;
        }
    }
    assert!(compared > 400, "比べたのが{compared}回しか無い");
}

/// **幅を状態として持たない（計画書§1.2）**: 120→80→120と描くと、最初と同じ。80の結果も、80だけで描いたものと同じ。
#[test]
fn drawing_at_another_width_and_back_gives_the_same_result() {
    for src in all_inputs() {
        let first = draw(&src, 120);
        let narrow = draw(&src, 80);
        let again = draw(&src, 120);
        assert_eq!(first, again, "{src:?}");
        assert_eq!(narrow, draw(&src, 80), "{src:?}");
    }
    // 試験の前提: 幅で描き方が変わる入力が含まれている（全部が幅に左右されないなら、この試験は何も見ていない）。
    let long = super::characterization_tests::LONG_JAPANESE_LIST_ITEM;
    assert_ne!(draw(long, 120), draw(long, 80));
}

/// ユーザーが示した例（計画書§1.2）: 2行目以降は`• `の後ろの文字の位置に揃う。枠の内側30桁（描く幅29桁）。
#[test]
fn the_users_example_wraps_under_the_text_after_the_bullet() {
    let src = "- これは長い文章です。画面幅を超えて折り返されます。さらに文章が続きます。\n";
    let width = usize::from(text_width(30));
    let (lines, joins) = lines_and_joins(src, width);
    assert_eq!(
        lines,
        [
            "• これは長い文章です。画面幅",
            "  を超えて折り返されます。さ",
            "  らに文章が続きます。",
        ]
    );
    assert_eq!(joins, [LineJoin::Break, CONTINUES_2, CONTINUES_2]);
    assert_eq!(
        joined(&draw(src, width)),
        ["• これは長い文章です。画面幅を超えて折り返されます。さらに文章が続きます。"]
    );
}

/// ユーザーが示した例の図（計画書§1.2）は1行14文字で、枠の内側31桁（描く幅30桁）のときの形と1文字も違わない。
#[test]
fn the_users_example_matches_the_picture_in_the_requirement() {
    let src = "- これは長い文章です。画面幅を超えて折り返されます。さらに文章が続きます。\n";
    let (lines, joins) = lines_and_joins(src, usize::from(text_width(31)));
    assert_eq!(
        lines,
        [
            "• これは長い文章です。画面幅を",
            "  超えて折り返されます。さらに",
            "  文章が続きます。",
        ]
    );
    assert_eq!(joins, [LineJoin::Break, CONTINUES_2, CONTINUES_2]);
}

/// 英語の語の切れ目で分けると、空白は前の行の末尾に残る（その空白も幅に収まる）。つなぐと空白が1つだけ残る。
#[test]
fn a_space_at_a_word_break_stays_at_the_end_of_the_earlier_line() {
    let (lines, joins) = lines_and_joins("alpha beta gamma\n", 11);
    assert_eq!(lines, ["alpha beta ", "gamma"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0]);
    assert_eq!(
        joined(&draw("alpha beta gamma\n", 11)),
        ["alpha beta gamma"]
    );
}

/// 全角文字の間で分ける。つないでも何も入らない。
#[test]
fn wide_characters_break_between_themselves_and_join_with_nothing_between() {
    let (lines, joins) = lines_and_joins("あいうえお\n", 4);
    assert_eq!(lines, ["あい", "うえ", "お"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0, CONTINUES_0]);
    assert_eq!(joined(&draw("あいうえお\n", 4)), ["あいうえお"]);
}

/// 空白の後ろの全角文字の並びは、行の残りを埋めてから次の行へ続く（並び全体を次の行へ送らない）。
#[test]
fn wide_characters_after_a_space_fill_the_rest_of_the_line() {
    let (lines, joins) = lines_and_joins("abc あいうえお\n", 8);
    assert_eq!(lines, ["abc あい", "うえお"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0]);
    assert_eq!(joined(&draw("abc あいうえお\n", 8)), ["abc あいうえお"]);
}

/// 全角文字と、その隣の半角の語の間でも分ける（半角の語の中では分けない）。
#[test]
fn a_wide_character_and_an_adjacent_narrow_word_can_break_apart() {
    let src = "日本語とEnglishが混ざる\n";
    let (lines, joins) = lines_and_joins(src, 10);
    assert_eq!(lines, ["日本語と", "Englishが", "混ざる"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0, CONTINUES_0]);
    assert_eq!(joined(&draw(src, 10)), ["日本語とEnglishが混ざる"]);
}

/// 幅を超える長い語（URL）は文字の間で切る。切った所には何も足さない。最後の切れ端は、後ろの空白の1桁まで収める。
#[test]
fn a_long_url_is_cut_between_characters() {
    let url = format!("https://example.com/{}", "a".repeat(30));
    let src = format!("see {url} now\n");
    let (lines, joins) = lines_and_joins(&src, 20);
    assert_eq!(
        lines,
        [
            "see ".to_string(),
            "https://example.com/".to_string(),
            "a".repeat(20),
            format!("{} now", "a".repeat(10)),
        ]
    );
    assert_eq!(
        joins,
        [LineJoin::Break, CONTINUES_0, CONTINUES_0, CONTINUES_0]
    );
    assert_eq!(joined(&draw(&src, 20)), [format!("see {url} now")]);
}

/// 行の頭から置いても後ろの空白の1桁が入らない語は、空白が収まるように文字の間で切る
/// （語の後ろで分けると、残す空白が幅を超えるため。モジュールdoc）。
#[test]
fn a_word_that_leaves_no_room_for_the_space_after_it_is_cut_so_the_space_still_fits() {
    let (lines, joins) = lines_and_joins("abcdef x\n", 6);
    assert_eq!(lines, ["abcde", "f x"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0]);
    assert_eq!(joined(&draw("abcdef x\n", 6)), ["abcdef x"]);
}

/// 幅の下限（元の描画部品の20桁）は無い。渡した幅で分ける。
#[test]
fn the_floor_of_twenty_columns_is_gone() {
    let (lines, joins) = lines_and_joins("abc def ghi\n", 5);
    assert_eq!(lines, ["abc ", "def ", "ghi"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0, CONTINUES_0]);
}

/// **狭すぎる幅だけの例外**: 字下げの後に1文字も入らないときは、1行に1文字を置いて幅を超える
/// （何も描けない形にはしない）。つなぐと元に戻ることは変わらない。
#[test]
fn when_the_indent_leaves_no_room_each_line_takes_one_character_and_may_exceed_the_width() {
    let (lines, joins) = lines_and_joins("- あいう\n", 2);
    assert_eq!(lines, ["• あ", "  い", "  う"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_2, CONTINUES_2]);

    let (lines, joins) = lines_and_joins("- a b\n", 2);
    assert_eq!(lines, ["• a ", "  b"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_2]);

    let (lines, joins) = lines_and_joins("ab\n", 0);
    assert_eq!(lines, ["a", "b"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0]);
}

/// 番号が2桁のリストは、続きの行の字下げが4文字になる（印の`indent`も4）。
#[test]
fn a_two_digit_ordered_item_continues_under_its_text() {
    let (lines, joins) = lines_and_joins("10. あいうえおかきくけこ\n", 10);
    assert_eq!(lines, ["10. あいう", "    えおか", "    きくけ", "    こ"]);
    assert_eq!(
        joins,
        [LineJoin::Break, CONTINUES_4, CONTINUES_4, CONTINUES_4]
    );
}

/// 入れ子の引用は、続きの行にも縦線を2本付ける。`indent`は縦線と空白の文字の数（4）で、桁や`│`のバイト数ではない。
#[test]
fn a_nested_quote_repeats_both_bars_on_continuation_lines() {
    let src = "> > あいうえおかきくけこ\n";
    assert_eq!(
        describe(&Text::from(draw(src, 10).lines)),
        [
            "«muted|│ │ »あいう",
            "«muted|│ │ »えおか",
            "«muted|│ │ »きくけ",
            "«muted|│ │ »こ",
        ]
    );
    assert_eq!(
        draw(src, 10).joins,
        [LineJoin::Break, CONTINUES_4, CONTINUES_4, CONTINUES_4]
    );
    assert_eq!(joined(&draw(src, 10)), ["│ │ あいうえおかきくけこ"]);
}

/// 書式は切った後の行にも付く。
#[test]
fn a_style_carries_over_to_the_continuation_lines() {
    let src = "**あいうえおかきくけこ**\n";
    assert_eq!(
        describe(&Text::from(draw(src, 6).lines)),
        [
            "«bold|あいう»",
            "«bold|えおか»",
            "«bold|きくけ»",
            "«bold|こ»",
        ]
    );
}

/// ハードな改行（行末の空白2つ）は、元の文章にある改行なので`Break`（コピーで改行が入る）。
#[test]
fn a_hard_break_starts_a_new_logical_line() {
    let (lines, joins) = lines_and_joins("first  \nsecond\n", 40);
    assert_eq!(lines, ["first", "second"]);
    assert_eq!(joins, [LineJoin::Break, LineJoin::Break]);
}

/// 幅を超えるコードの行は文字の間で切る。入れ子でないコードは字下げを持たないので、続きの行も字下げ0（`indent`は0）
/// ——コピーすると元の1行に、余分な空白なしで戻る（T7b。2桁の字下げを外す前は、どの行にも2桁が付き`indent`は2だった）。
#[test]
fn a_code_line_wider_than_the_width_is_cut_and_copies_back_whole() {
    let src = format!("```\n{}\n```\n", "x".repeat(25));
    assert_eq!(
        describe(&Text::from(draw(&src, 12).lines)),
        [
            format!("«code|{}»", "x".repeat(12)),
            format!("«code|{}»", "x".repeat(12)),
            "«code|x»".to_string(),
        ]
    );
    assert_eq!(
        draw(&src, 12).joins,
        [LineJoin::Break, CONTINUES_0, CONTINUES_0]
    );
    assert_eq!(joined(&draw(&src, 12)), ["x".repeat(25)]);
}

/// 全角文字がコードの行の切れ目に掛かるときは、その文字を次の行へ送る（行は幅を超えない）。
#[test]
fn a_wide_character_at_the_cut_of_a_code_line_moves_to_the_next_line() {
    let (lines, joins) = lines_and_joins("```\nabcdefghijkあ\n```\n", 12);
    assert_eq!(lines, ["abcdefghijk", "あ"]);
    assert_eq!(joins, [LineJoin::Break, CONTINUES_0]);
}

/// 引用の中のコードの行は、続きの行にも縦線を付ける（`indent`は縦線と空白の2文字。T7b。コードの2桁の字下げを
/// 外す前は4文字だった）。
#[test]
fn a_code_line_in_a_quote_continues_with_the_bar() {
    let src = format!("> ```\n> {}\n> ```\n", "y".repeat(10));
    assert_eq!(
        describe(&Text::from(draw(&src, 10).lines)),
        ["«muted|│ »«code|yyyyyyyy»", "«muted|│ »«code|yy»"]
    );
    assert_eq!(draw(&src, 10).joins, [LineJoin::Break, CONTINUES_2]);
}

/// 幅を超える表の行（区切りの行を含む）は文字の間で切る。入れ子でない表の続きの行は字下げ0。
#[test]
fn a_table_row_wider_than_the_width_is_cut_with_no_indent() {
    let src = format!("| a | b |\n|---|---|\n| {} | y |\n", "x".repeat(20));
    let (lines, joins) = lines_and_joins(&src, 15);
    assert_eq!(
        lines,
        [
            format!("│ a{}", " ".repeat(12)),
            format!("{}│ b │ ", " ".repeat(8)),
            format!("├{}", "─".repeat(14)),
            format!("{}┼───┤", "─".repeat(8)),
            format!("│ {}", "x".repeat(13)),
            format!("{} │ y │ ", "x".repeat(7)),
        ]
    );
    assert_eq!(
        joins,
        [
            LineJoin::Break,
            CONTINUES_0,
            LineJoin::Break,
            CONTINUES_0,
            LineJoin::Break,
            CONTINUES_0,
        ]
    );
}

/// 区切り線は、字下げの後ろに残る幅（最大60桁）で引く。引用の中でも幅を超えない。
#[test]
fn a_thematic_break_inside_a_quote_fits_the_width() {
    assert_eq!(
        lines_and_joins("> ---\n", 20).0,
        [format!("│ {}", "─".repeat(18))]
    );
    assert_eq!(
        lines_and_joins("> ---\n", 80).0,
        [format!("│ {}", "─".repeat(60))]
    );
    assert_eq!(lines_and_joins("---\n", 10).0, ["─".repeat(10)]);
}
