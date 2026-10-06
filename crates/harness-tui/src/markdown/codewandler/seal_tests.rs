//! 確定の境界の**候補**（[`Scanner`]）を探す規則の試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4(3)の1）。
//!
//! # 何を確かめるか
//!
//! 候補は「コードフェンスの外の空行の次の、行頭（字下げなし）から始まる行」。候補を境界として採るかは、Adapterが
//! 解析器に確かめて決める（`super`のモジュールdoc「確定した部分と書きかけの末尾」）。ここで確かめるのは、
//! **確かめるまでもなく境界にならない行を候補から外す**こと——とくにフェンスの中の空行の次の行を候補にすると、
//! コードブロックの中で空行が現れるたびに、確かめるための解析が走る。
//!
//! - 候補にする: 段落・見出し・引用・表・区切り線の間の空行の次。フェンスが閉じた後
//! - 候補にしない: フェンスの中（```` ``` ````・`~~~`・長いフェンス・3桁までの字下げのフェンス）・字下げした
//!   続きの行・空行でない行の次・まだ改行が届いていない行
//!
//! 候補が、文章をどう区切って渡しても同じであること（[`the_candidates_do_not_depend_on_how_the_text_arrives`]）も
//! 確かめる——流入中の描画が区切りに依存しない（Portの契約）のは、これが前提になっているため。

use super::Scanner;

/// `text`を1回で渡したときの候補の行の頭（バイト位置）。行の範囲が行末の改行までを含むことも確かめる。
fn candidates(text: &str) -> Vec<usize> {
    Scanner::default()
        .advance(text)
        .into_iter()
        .map(|line| {
            assert!(
                text[line.clone()].ends_with('\n')
                    && !text[line.start..line.end - 1].contains('\n'),
                "候補の行の範囲{line:?}が、改行で終わる1行になっていない: {text:?}"
            );
            line.start
        })
        .collect()
}

/// `text`の中で`marker`が始まるバイト位置（期待値を、数えずに書くため）。
fn at(text: &str, marker: &str) -> usize {
    text.find(marker)
        .unwrap_or_else(|| panic!("{marker:?}が{text:?}に無い"))
}

#[test]
fn a_line_at_column_zero_after_a_blank_line_is_a_candidate() {
    let text = "first paragraph\n\n# heading\n\n> quote\n\nlast\n";
    assert_eq!(
        candidates(text),
        vec![at(text, "# heading"), at(text, "> quote"), at(text, "last")]
    );
}

#[test]
fn several_blank_lines_give_one_candidate_at_the_next_line() {
    let text = "a\n\n\n\nb\n";
    assert_eq!(candidates(text), vec![at(text, "b")]);
}

#[test]
fn a_line_without_a_blank_line_before_it_is_not_a_candidate() {
    assert_eq!(candidates("a\nb\n# c\n- d\n"), Vec::<usize>::new());
}

#[test]
fn the_first_line_is_not_a_candidate() {
    assert_eq!(candidates("\n\nfirst\n"), vec![2]);
    assert_eq!(candidates("first\n"), Vec::<usize>::new());
}

/// まだ改行が届いていない行は候補にしない（その行の残りが届くまで、行の種類が決まらない）。届けば候補にする。
#[test]
fn a_line_whose_newline_has_not_arrived_is_not_a_candidate_yet() {
    assert_eq!(candidates("a\n\nb"), Vec::<usize>::new());
    assert_eq!(candidates("a\n\nb\n"), vec![3]);
}

/// リストの項目の続き（字下げした行）は、空行を挟んでも同じ項目の中——候補にしない。タブで始まる行も字下げ。
#[test]
fn an_indented_line_after_a_blank_line_is_not_a_candidate() {
    let text =
        "- item\n\n  continued in the item\n\n\talso indented\n\n    indented code\n\nnext\n";
    assert_eq!(candidates(text), vec![at(text, "next")]);
}

/// 空白とタブだけの行は空行（解析器と同じ）。全角の空白だけの行は空行ではない（解析器はそれを段落の文字として読む）。
#[test]
fn only_spaces_and_tabs_make_a_blank_line() {
    let text = "a\n \t \nb\n";
    assert_eq!(candidates(text), vec![at(text, "b")]);
    assert_eq!(candidates("a\n\u{3000}\nb\n"), Vec::<usize>::new());
}

#[test]
fn crlf_line_endings_are_read_like_lf() {
    let text = "a\r\n\r\nb\r\n";
    assert_eq!(candidates(text), vec![at(text, "b")]);
    let text = "```\r\n\r\ninside\r\n```\r\n\r\nafter\r\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
}

/// フェンスの中の空行の次の行頭の行は候補にしない。フェンスを開く行そのものは（その前が空行なら）候補。
#[test]
fn a_blank_line_inside_a_backtick_fence_gives_no_candidate() {
    let text = "intro\n\n```rust\nfn main() {\n\nlet x = 1;\n\n}\n```\n\nafter\n";
    assert_eq!(
        candidates(text),
        vec![at(text, "```rust"), at(text, "after")]
    );
}

/// `~~~`のフェンスは`~~~`でだけ閉じる（中の```` ``` ````では閉じない）。
#[test]
fn a_tilde_fence_is_closed_only_by_tildes() {
    let text = "~~~\n```\n\nnot the end\n```\n\nstill code\n~~~\n\nafter\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
}

/// 閉じるフェンスは開いたフェンスと同じ記号で、同じ長さ以上（短いものは中身）。閉じる行の後ろに文字があれば中身。
#[test]
fn a_fence_is_closed_only_by_a_run_at_least_as_long_with_nothing_after_it() {
    let text = "````\n```\n\nstill code\n```` not closing\n\nstill code\n````\n\nafter\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
}

/// バッククォートのフェンスの情報文字列にバッククォートがあれば、フェンスではない（解析器と同じ。行内のコード）。
#[test]
fn a_backtick_line_whose_info_has_a_backtick_does_not_open_a_fence() {
    let text = "```a`b\n\nnext\n";
    assert_eq!(candidates(text), vec![at(text, "next")]);
}

/// 字下げが3桁までのフェンスも数える（最上位で字下げしたフェンス・リストの項目の中のコード）。
#[test]
fn a_fence_indented_up_to_three_columns_is_tracked() {
    let text = "   ```\ncode\n\ncol0 line inside the fence\n   ```\n\nafter\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
    let text = "1. step\n\n   ```bash\n   cargo build\n\n   cargo test\n   ```\n\nafter\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
}

/// 4桁以上の字下げはフェンスではない（字下げのコードか、段落の続き）。
#[test]
fn a_fence_indented_four_columns_is_not_a_fence() {
    let text = "    ```\n\nnext\n";
    assert_eq!(candidates(text), vec![at(text, "next")]);
}

/// 閉じていないフェンスの後ろは、空行があっても候補にしない。
#[test]
fn nothing_after_an_unclosed_fence_is_a_candidate() {
    assert_eq!(
        candidates("```\ncode\n\nmore\n\nmore\n"),
        Vec::<usize>::new()
    );
}

/// 閉じるフェンスの字下げは問わない（解析器は閉じるフェンスの前の空白を全部読み飛ばす）。
#[test]
fn a_closing_fence_may_be_indented_any_amount() {
    let text = "```\ncode\n        ```\n\nafter\n";
    assert_eq!(candidates(text), vec![at(text, "after")]);
}

/// **候補は、文章をどう区切って渡しても同じ**（毎回の`advance`は、前回より長くなっただけの全文を受け取る）。
/// 1文字ずつでも、どこか1か所で2つに分けても、1回で渡したのと同じ候補が同じ順で見つかる。
#[test]
fn the_candidates_do_not_depend_on_how_the_text_arrives() {
    let text =
        "para\n\n```\ncode\n\nmore\n```\n\n- item\n\n  cont\n\n~~~\n\n~~~\n\n日本語\r\n\r\nend\n";
    let whole = Scanner::default().advance(text);
    assert!(
        whole.len() >= 4,
        "候補が少なすぎて試験にならない: {whole:?}"
    );

    let mut scanner = Scanner::default();
    let mut found = Vec::new();
    for (at, ch) in text.char_indices() {
        found.extend(scanner.advance(&text[..at + ch.len_utf8()]));
    }
    assert_eq!(found, whole, "1文字ずつ渡すと候補が変わった");

    for (at, _) in text.char_indices() {
        let mut scanner = Scanner::default();
        let mut found = scanner.advance(&text[..at]);
        found.extend(scanner.advance(text));
        assert_eq!(found, whole, "{at}バイト目で分けて渡すと候補が変わった");
    }
}
