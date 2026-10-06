//! [`CodewandlerMarkdown`]（codewandlerで整形して描くAdapter）の試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT8・
//! §1.4(3)・§1.9）。
//!
//! # 何を確かめるか
//!
//! | 性質 | 壊れたら何が見えるか | 試験 |
//! |---|---|---|
//! | Portの契約（どう区切っても同じ・幅は状態でない・`reset`・`finish`の冪等と再開・行と印の数・リンクの区間） | 差し替えの合格条件を満たさない | [`codewandler_markdown_keeps_the_port_contract`] |
//! | 流入中の描画が、その時点の全文を1回で解析して描いたもの（**基準**）と同じ | 確定の境界を置いてはいけない所に置いた（コードブロックが切れる・リストの番号やゆるさが変わる）／塊の間の空行やリンクの行がずれた | [`streaming_renders_like_the_reference_at_every_step`]・[`streaming_renders_like_the_reference_for_every_document`] |
//! | 2つに分けて足しても、1回で足したのと同じ | 状態が届き方に依存した／キャッシュが古いまま使われた | [`splitting_anywhere_in_two_renders_like_one_push`] |
//! | 幅を変えて戻すと最初と同じ。描いた行はどれも画面1行 | 幅のキャッシュが古い／つないだ結果が二重に折り返される | [`a_width_change_and_back_gives_the_first_result_and_every_line_takes_one_row`] |
//! | 確定した塊は解析し直さない・長さが変わらなければ末尾も解析し直さない・`finish`の2回目は何もしない | 毎フレーム全文を解析する（長い返答で遅くなる。計画書§1.2） | `*_parses_*`・`*_renders_*`の試験 |
//! | 流入中と`finish`の後で見た目が変わるもの（境界を2つ以上またぐ参照リンク） | 知らないうちに増える／減る | [`a_reference_across_sealed_chunks_resolves_only_after_finish`] |
//! | 揃えの`:`がある表を流しても落ちない（解析器は書きかけの`|:`で落ちる。`guard`） | TUIごと終わる | [`streaming_a_table_with_alignment_colons_does_not_crash`] |
//!
//! 基準（[`reference`]）は、**解析器へ全文を1回で渡し**、写した描画部品で描いたもの——Adapterの経路（行ごとに渡す・
//! 塊に分ける・つなぐ）を1つも通らないので、Adapterが空を返しても、つなぎ方を間違えても一致しない。

use harness_term::select::LineJoin;
use harness_term::wrap::{line_rows, text_width};
use ratatui::buffer::CellWidth;
use ratatui::style::Style;
use ratatui::text::{Line, Text};

use super::guard::defused;
use super::render::{self, Theme};
use super::wrap_tests::{all_inputs, plain};
use super::{CodewandlerMarkdown, Scanner};
use crate::markdown::contract_tests::port_contract;
use crate::markdown::{Rendered, StreamingMarkdown};

/// 確定の境界を何度もまたぐ、ふつうの返答の形の文書。どれも参照リンクの定義を含まない
/// （定義が別の塊にあるものだけが、流入中と`finish`の後で変わる。[`a_reference_across_sealed_chunks_resolves_only_after_finish`]）。
const DOCUMENTS: [&str; 11] = [
    // ユーザーの例（計画書§1.9）
    "# Hello\n\nThis is **bold**",
    // フェンスの中の空行の次に行頭の行
    "Intro paragraph.\n\n```rust\nfn main() {\n\nlet x = 1;\n\n}\n```\n\nAfter the code.\n",
    // `~~~`のフェンスの中の```` ``` ````と空行
    "~~~\n```\n\nnot a fence end\n```\n~~~\n\nText after.\n",
    // 3段の入れ子と、空行を挟んだ項目の続き
    "- parent\n  - child\n    - grandchild\n\n  continued paragraph of parent\n\nNext paragraph.\n",
    // リストの項目の中の、空行を含むコード
    "1. Step one:\n\n   ```bash\n   cargo build\n\n   cargo test\n   ```\n\nDone.\n",
    // 表・リンク・見出しのリンク（後ろの塊のリンクの行がずれないこと）
    "| a | b |\n|---|---|\n| 1 | 2 |\n\nAfter the table with a [link](https://example.com/a).\n\n## Heading with [another](https://example.com/b)\n",
    // 未定義の`[label]`（解析器はそこから後ろの出力を止める）を含む段落が、塊をまたいで続く
    "Index arr[0] and map[key] are literal.\n\nNext paragraph mentions [x] too.\n\n- [ ] task\n- [x] done\n",
    // 日本語
    "日本語の段落です。長い文章が続いて、画面の幅を超えて折り返されます。\n\n> 引用の日本語です。こちらも長く続いて折り返されます。\n\n最後の段落。\n",
    // 引用・区切り線・HTMLブロック
    "> quote\n> more\n\n---\n\n<div>\nhtml\n</div>\n\nend\n",
    // 空行を挟んで続くリスト（ゆるいリスト・同じ番号）。境界の候補を解析器が退ける
    "- a\n- b\n\n- c\n\n1. one\n\n1. two\n\nafter the lists\n",
    // 字句だけ見ると境界に見えるが、解析器ではそうでない所（リストの中のフェンスが行頭の行で閉じた後のフェンス・
    // 空行を含むHTMLのコメント・```` ``` ````を含むHTMLブロック）
    "1. step\n   ```\n   code\n\nnot code\n   ```\n\nstill code\n\n<!--\nnote\n\nmore\n-->\n\n<div>\n```\n</div>\n\npara\n\n```\ncode\n\nstill code\n```\n\nend\n",
];

/// 描く幅（Adapterへ渡す幅。折り返す狭い幅と、広い幅）。
const WIDTHS: [u16; 2] = [30, 80];

/// 基準: `text`を解析器へ1回で渡し、写した描画部品で`width`桁で描いたもの（モジュールdoc）。
fn reference(text: &str, width: u16) -> Rendered {
    render::render_lines(
        &markdown_stream::parse_gfm(text),
        &Theme::default(),
        usize::from(width),
    )
}

/// `chunks`を順に足し、足すたびに`width`で描いたもの（画面が描くのと同じ流れ）。
fn streamed(chunks: &[&str], width: u16) -> CodewandlerMarkdown {
    let mut m = CodewandlerMarkdown::default();
    for chunk in chunks {
        m.push(chunk);
        m.render(width);
    }
    m
}

/// `text`を1回で足したもの。
fn pushed(text: &str) -> CodewandlerMarkdown {
    let mut m = CodewandlerMarkdown::default();
    m.push(text);
    m
}

/// 行の文字だけ。
fn texts(rendered: &Rendered) -> Vec<String> {
    rendered.lines.iter().map(plain).collect()
}

/// 行の桁数（描かれる書記素の`cell_width`の和）。
fn columns(line: &Line<'_>) -> usize {
    line.styled_graphemes(Style::default())
        .map(|grapheme| usize::from(grapheme.symbol.cell_width()))
        .sum()
}

/// `DOCUMENTS`を空行でつないだ1つの長い文書。
fn joined_documents() -> String {
    DOCUMENTS
        .iter()
        .map(|doc| doc.trim_end().to_string())
        .collect::<Vec<_>>()
        .join("\n\n")
        + "\n"
}

#[test]
fn codewandler_markdown_keeps_the_port_contract() {
    port_contract(CodewandlerMarkdown::default);
}

/// ユーザーの例（計画書§1.9）: 細切れに流しても、1回で渡したのと同じ最終の描画。終えた後も同じ。
#[test]
fn the_users_streaming_example_renders_like_one_push() {
    let chunks = ["# He", "llo\n", "\nThis ", "is **bo", "ld**"];
    let whole: String = chunks.concat();
    for width in WIDTHS {
        let mut m = streamed(&chunks, width);
        let expected = reference(&whole, width);
        assert_eq!(
            texts(&expected),
            ["Hello", "", "This is bold"],
            "基準の形が想定と違う"
        );
        assert_eq!(m.render(width), expected, "流入中（幅{width}）");
        assert_eq!(m.render(width), pushed(&whole).render(width));
        m.finish();
        assert_eq!(m.render(width), expected, "終えた後（幅{width}）");
    }
}

/// **1文字ずつ足し、足すたびに描いた結果が、その時点の全文の基準と同じ**——どの途中の状態でも。
/// 確定の境界を置いてはいけない所に置いたり、キャッシュを古いまま使ったりすると、どこかの1文字で食い違う。
/// 確定した塊が実際にできていることも確かめる（できていなければ、この試験は末尾を描いているだけになる）。
#[test]
fn streaming_renders_like_the_reference_at_every_step() {
    let text = joined_documents();
    let width = 30;
    let mut m = CodewandlerMarkdown::default();
    for (at, ch) in text.char_indices() {
        let end = at + ch.len_utf8();
        m.push(&text[at..end]);
        assert_eq!(
            m.render(width),
            reference(&text[..end], width),
            "{end}バイト目まで足したところで、基準と違う"
        );
    }
    assert!(
        m.sealed_chunks() >= 20,
        "確定した塊が{}個しか無い",
        m.sealed_chunks()
    );
}

/// どの文書も、全部を流し終えた（`finish`の前の）描画が基準と同じ。試験の入力の全部（`wrap_tests::all_inputs`）と、
/// それを空行でつないだ文書を含める。
#[test]
fn streaming_renders_like_the_reference_for_every_document() {
    let mut documents: Vec<String> = DOCUMENTS.iter().map(|doc| doc.to_string()).collect();
    documents.extend(all_inputs());
    documents.push(joined_documents());
    documents.push(all_inputs().join("\n"));
    let mut sealed = 0;
    for doc in &documents {
        for width in WIDTHS {
            // 7バイトごとに分けて足す（文字の途中で切らないよう、文字の境界まで延ばす）。足すたびに描く。
            let mut m = CodewandlerMarkdown::default();
            let mut start = 0;
            while start < doc.len() {
                let mut end = (start + 7).min(doc.len());
                while !doc.is_char_boundary(end) {
                    end += 1;
                }
                m.push(&doc[start..end]);
                m.render(width);
                start = end;
            }
            assert_eq!(
                m.render(width),
                reference(doc, width),
                "流し終えた描画が基準と違う（幅{width}）: {doc:?}"
            );
            sealed += m.sealed_chunks();
        }
    }
    assert!(sealed >= 100, "確定した塊が全部で{sealed}個しか無い");
}

/// **どの文字の境界で2つに分けて足しても、1回で足したのと同じ**（間に描いても）。終えれば基準と同じ。
#[test]
fn splitting_anywhere_in_two_renders_like_one_push() {
    let documents: Vec<String> = DOCUMENTS
        .iter()
        .map(|doc| doc.to_string())
        .chain(REFERENCES.iter().map(|doc| doc.to_string()))
        .collect();
    for doc in &documents {
        for width in WIDTHS {
            let one = pushed(doc).render(width);
            let boundaries = doc.char_indices().map(|(at, _)| at).chain([doc.len()]);
            for at in boundaries {
                let (head, tail) = doc.split_at(at);
                let mut m = CodewandlerMarkdown::default();
                m.push(head);
                m.render(width);
                m.push(tail);
                assert_eq!(
                    m.render(width),
                    one,
                    "{at}バイト目で分けると違う（幅{width}）: {doc:?}"
                );
                m.finish();
                assert_eq!(
                    m.render(width),
                    reference(doc, width),
                    "{at}バイト目で分けて終えると基準と違う（幅{width}）: {doc:?}"
                );
            }
        }
    }
}

/// 幅を変えて戻すと最初と同じ（流入中も終えた後も）。どの幅でも基準と同じで、描いた行はどれも共有の折り返し部品で
/// 1行に数えられ、桁数も渡した幅を超えない（計画書§1.9の不変条件。つないだ結果にも成り立つこと）。
#[test]
fn a_width_change_and_back_gives_the_first_result_and_every_line_takes_one_row() {
    let text = all_inputs().join("\n");
    for finish in [false, true] {
        let mut m = streamed(&[&text], 120);
        if finish {
            m.finish();
        }
        let first = m.render(120);
        let narrow = m.render(80);
        assert_eq!(
            m.render(120),
            first,
            "80桁で描いた後に120桁へ戻すと違う（終えた後={finish}）"
        );
        assert_eq!(
            narrow,
            reference(&text, 80),
            "80桁の描画が基準と違う（終えた後={finish}）"
        );
        assert!(m.sealed_chunks() > 10 || finish, "確定した塊が少なすぎる");

        let mut lines = 0;
        for inner in [10u16, 21, 40, 80, 120] {
            let width = text_width(inner);
            let rendered = m.render(width);
            assert_eq!(
                rendered,
                reference(&text, width),
                "幅{width}（終えた後={finish}）"
            );
            for line in &rendered.lines {
                assert!(
                    columns(line) <= usize::from(width),
                    "幅{width}を超える行: {:?}",
                    plain(line)
                );
            }
            let rows = line_rows(Text::from(rendered.lines.clone()), inner);
            assert!(
                rows.iter().all(|&rows| rows == 1),
                "共有の折り返し部品が折り返し直す行がある（枠の内側{inner}桁・終えた後={finish}）"
            );
            lines += rendered.lines.len();
        }
        assert!(lines > 1_000, "確かめた行が{lines}行しか無い");
    }
}

/// 境界の候補の数（`text`を1回で走査したとき）。
fn candidate_count(text: &str) -> usize {
    Scanner::default().advance(text).len()
}

/// 4つの段落（境界の候補が3つで、3つとも境界になる）。
const FOUR_PARAGRAPHS: &str =
    "first paragraph\n\nsecond paragraph\n\nthird paragraph\n\nfourth paragraph\n";

/// 1文字ずつ流して毎回描くと、**境界の候補はそれぞれ1回だけ確かめ、確定した塊はそれぞれ1回の解析の結果を持ち続け、
/// それぞれ1回だけ描く**。末尾は、文章の長さが変わった回だけ解析する。
#[test]
fn streaming_parses_each_candidate_once_and_keeps_each_sealed_chunk_from_one_parse() {
    let text = joined_documents();
    let mut m = CodewandlerMarkdown::default();
    let mut lengths_changed = 0;
    for (at, ch) in text.char_indices() {
        m.push(&text[at..at + ch.len_utf8()]);
        lengths_changed += 1;
        m.render(30);
        m.render(30);
    }
    let counts = m.counts();
    assert_eq!(counts.checks, candidate_count(&text), "候補を確かめた回数");
    assert_eq!(
        counts.sealed_parses,
        m.sealed_chunks(),
        "確定した塊を解析した回数"
    );
    assert_eq!(
        counts.chunk_renders,
        m.sealed_chunks(),
        "確定した塊を描いた回数"
    );
    assert_eq!(counts.tail_parses, lengths_changed, "末尾を解析した回数");
    assert_eq!(counts.whole_parses, 0, "流入中に全文を解析した");
    assert!(
        m.sealed_chunks() >= 20,
        "確定した塊が{}個しか無い",
        m.sealed_chunks()
    );

    let mut four = streamed(&[FOUR_PARAGRAPHS], 30);
    four.render(30);
    assert_eq!(
        four.sealed_chunks(),
        3,
        "4つの段落が3つの塊と末尾に分かれていない"
    );
}

/// 文章が変わらないフレームは、何も解析せず何も描き直さない。
#[test]
fn an_unchanged_frame_renders_nothing_again() {
    let mut m = streamed(&[FOUR_PARAGRAPHS], 30);
    let before = m.counts();
    let first = m.render(30);
    for _ in 0..3 {
        assert_eq!(m.render(30), first);
    }
    assert_eq!(
        m.counts(),
        before,
        "文章も幅も変わらないのに、解析か描画をした"
    );
}

/// 幅を変えると、持っている解析の結果から描き直す（解析し直さない）。
#[test]
fn a_width_change_rerenders_from_kept_events_without_parsing() {
    let mut m = streamed(&[FOUR_PARAGRAPHS], 30);
    let before = m.counts();
    m.render(80);
    let after = m.counts();
    assert_eq!(
        (
            after.checks,
            after.sealed_parses,
            after.tail_parses,
            after.whole_parses
        ),
        (
            before.checks,
            before.sealed_parses,
            before.tail_parses,
            before.whole_parses
        ),
        "幅を変えただけで解析した"
    );
    assert_eq!(
        after.chunk_renders,
        before.chunk_renders + 3,
        "確定した3つの塊を描き直していない"
    );
    assert_eq!(
        after.tail_renders,
        before.tail_renders + 1,
        "末尾を描き直していない"
    );
}

/// **`finish`の2回目以降は何もしない**（画面は流入中でない返答の全部へ、描くたびに`finish`を呼ぶ。計画書§0のT8の条件）。
/// 終えた後の描画も、幅が変わらなければ描き直さない。足して終え直せば、もう1回だけ解析する。
#[test]
fn repeated_finish_parses_the_whole_text_once() {
    let mut m = streamed(&[FOUR_PARAGRAPHS], 30);
    m.finish();
    let done = m.render(30);
    for _ in 0..10 {
        m.finish();
        assert_eq!(m.render(30), done);
    }
    let counts = m.counts();
    assert_eq!((counts.whole_parses, counts.whole_renders), (1, 1));

    m.push("more\n");
    m.render(30);
    m.finish();
    m.finish();
    m.render(30);
    assert_eq!(
        m.counts().whole_parses,
        2,
        "足して終え直したときに解析し直していない"
    );
}

/// 終えた後に足すと流入を再開する——確定した塊を作り直し、基準と同じに描く。
#[test]
fn a_push_after_finish_resumes_streaming_with_sealed_chunks() {
    let (head, tail) = FOUR_PARAGRAPHS.split_at(FOUR_PARAGRAPHS.find("third").unwrap_or(0));
    let mut m = streamed(&[head], 30);
    m.finish();
    m.render(30);
    m.push(tail);
    assert_eq!(m.render(30), reference(FOUR_PARAGRAPHS, 30));
    assert_eq!(m.sealed_chunks(), 3);
}

/// 確定の境界を2つ以上またぐ参照リンク（定義が使う所と別の塊にあり、その間に別の塊がある）。
const REFERENCES: [&str; 2] = [
    "See [the docs][ref].\n\nMore text.\n\n[ref]: https://example.com/docs\n",
    "[ref]: https://example.com/docs\n\nIntro.\n\nSee [the docs][ref].\n",
];

/// **知っている違い（計画書§1.7）**: 参照リンクの定義と使う所が別の塊にあると、流入中は定義が見えず、リンクにならずに
/// `[the docs][ref]`の文字のまま描く。`finish`で全文を解析し直すとリンクになる。定義が使う所のすぐ次（または前）の
/// 塊にあるときは、境界の候補を解析器が退けるので、流入中からリンクになる（対照）。
#[test]
fn a_reference_across_sealed_chunks_resolves_only_after_finish() {
    for doc in REFERENCES {
        let mut m = streamed(&[doc], 80);
        let streaming = m.render(80);
        assert!(
            streaming.links.is_empty()
                && texts(&streaming)
                    .iter()
                    .any(|line| line.contains("[the docs][ref]")),
            "流入中にリンクになった（知っている違いが消えた。計画書§1.7と試験を直す）: {:?}",
            texts(&streaming)
        );
        m.finish();
        let done = m.render(80);
        assert_eq!(done, reference(doc, 80));
        assert_eq!(
            done.links
                .iter()
                .map(|link| link.url.as_str())
                .collect::<Vec<_>>(),
            ["https://example.com/docs"]
        );
    }
    for doc in [
        "See [the docs][ref].\n\n[ref]: https://example.com/docs\n",
        "[ref]: https://example.com/docs\n\nSee [the docs][ref].\n",
    ] {
        let mut m = streamed(&[doc], 80);
        assert_eq!(m.render(80), reference(doc, 80), "隣の塊の参照: {doc:?}");
        assert_eq!(m.render(80).links.len(), 1);
    }
}

/// 塊の間の空行は、描画部品が最上位のブロックの間に置く空行と同じ（印は`Break`）。後ろの塊のリンクの行は、
/// 前の塊の行の数と空行のぶんずれる。
#[test]
fn sealed_chunks_are_joined_with_the_renderers_blank_line_and_shifted_links() {
    let text = "first\n\nsecond [link](https://example.com/x)\n\nthird\n";
    let mut m = streamed(&[text], 80);
    let rendered = m.render(80);
    assert_eq!(m.sealed_chunks(), 2);
    assert_eq!(texts(&rendered), ["first", "", "second link", "", "third"]);
    assert_eq!(rendered.joins, vec![LineJoin::Break; 5]);
    assert_eq!(rendered.links.len(), 1);
    assert_eq!(
        (
            rendered.links[0].line,
            rendered.links[0].start,
            rendered.links[0].end
        ),
        (2, 7, 11)
    );
}

/// 揃えの`:`がある表を1文字ずつ流すと、書きかけの区切り行が`|:`で終わる瞬間がある——解析器はそこで落ちる
/// （`guard`のモジュールdoc）。落ちずに描き、どの途中でも、同じ書き換えを通した全文の基準と同じ。崩れた表
/// （`:`だけのセル）で終わっても落ちない。
#[test]
fn streaming_a_table_with_alignment_colons_does_not_crash() {
    let text = "Intro.\n\n| left | center | right |\n|:-----|:------:|------:|\n| a | b | c |\n| : | x | y |\n\nafter\n\n| a |\n|:|\n";
    let mut m = CodewandlerMarkdown::default();
    for (at, ch) in text.char_indices() {
        let end = at + ch.len_utf8();
        m.push(&text[at..end]);
        assert_eq!(
            m.render(40),
            reference(&defused(&text[..end]), 40),
            "{end}バイト目"
        );
    }
    m.finish();
    assert_eq!(m.render(40), reference(&defused(text), 40));
}

/// 空の文章と空行だけの文章は0行（描画部品が描くものが無い）。行と印の数は揃う。
#[test]
fn empty_text_renders_no_lines() {
    for text in ["", "\n", "\n\n\n"] {
        let rendered = streamed(&[text], 80).render(80);
        assert_eq!(rendered, reference(text, 80));
        assert!(
            rendered.lines.is_empty() && rendered.joins.is_empty(),
            "{text:?}"
        );
    }
}
