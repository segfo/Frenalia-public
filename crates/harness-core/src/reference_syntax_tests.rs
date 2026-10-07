use std::collections::BTreeMap;

use serde_json::json;

use super::*;

/// 試験用の置き場: `(K, N)`→中身。中身は長い16進の並び（害の無い値）。
fn book(entries: &[(usize, usize, char)]) -> BTreeMap<ValueRef, String> {
    entries
        .iter()
        .map(|&(back, number, seed)| {
            (
                ValueRef { back, number },
                std::iter::repeat_n(seed, 64).collect(),
            )
        })
        .collect()
}

fn resolve_from(book: &BTreeMap<ValueRef, String>) -> impl FnMut(ValueRef) -> Option<String> + '_ {
    |r| book.get(&r).cloned()
}

/// **`{{back:K:N}}`は K 個前の文の N 番目を指す。** `{{val:N}}`・`{{user:N}}`は直近の文（K=0）。
#[test]
fn back_references_are_read_and_substituted() {
    let values = book(&[(0, 2, 'a'), (2, 3, 'b')]);
    let (a, b) = (
        &values[&ValueRef::current(2)],
        &values[&ValueRef { back: 2, number: 3 }],
    );
    assert_eq!(
        substitute_text(
            "x {{back:2:3}} y {{val:2}} {{user:2}}",
            &mut resolve_from(&values)
        ),
        format!("x {b} y {a} {a}")
    );
    assert_eq!(
        pieces("{{back:2:3}}"),
        vec![Piece::Reference {
            reference: ValueRef { back: 2, number: 3 },
            written: "{{back:2:3}}",
        }]
    );
}

/// **読めない綴りは、1文字も変えずに残す。** 読み手にも渡らない（置き場を引かない）。
#[test]
fn malformed_references_are_left_exactly_as_written() {
    for text in [
        "pwsh --enc {{back:2}}",                      // N が無い
        "pwsh --enc {{back:0:1}}",                    // 0 個前は {{val:N}} で書く
        "pwsh --enc {{back:1:0}}",                    // 番号は1始まり
        "pwsh --enc {{back:1:x}}",                    // 数でない
        "pwsh --enc {{back::1}}",                     // K が無い
        "pwsh --enc {{back:-1:1}}",                   // 負の数は書けない
        "pwsh --enc {{back:1:1",                      // 閉じていない
        "pwsh --enc {{val:1",                         // 閉じていない
        "pwsh --enc {{val:}}",                        // 番号が無い
        "pwsh --enc {{val:0}}",                       // 0は使わない
        "pwsh --enc {{val:+1}}",                      // 数字だけで書く
        "pwsh --enc {{val:99999999999999999999999}}", // 桁あふれ
        "pwsh --enc {{notval:1}}",                    // 知らない頭
    ] {
        let mut asked = Vec::new();
        let out = substitute_text(text, &mut |r| {
            asked.push(r);
            Some("VALUE".to_string())
        });
        assert_eq!(out, text, "{text}");
        assert!(
            asked.is_empty(),
            "{text}: 読めない綴りで置き場を引いた {asked:?}"
        );
    }
}

/// 対: **読めても置き場に無い番号**も、書いた綴りのまま残す（範囲外の K・N）。
#[test]
fn an_out_of_range_reference_is_left_visible() {
    let values = book(&[(0, 1, 'a'), (1, 1, 'b')]);
    for text in ["{{back:2:1}}", "{{back:1:2}}", "{{val:2}}"] {
        assert_eq!(substitute_text(text, &mut resolve_from(&values)), text);
    }
    // 同じ文字列の中の読める参照は置き換わる（範囲外のものだけが残る）。
    let b = &values[&ValueRef { back: 1, number: 1 }];
    assert_eq!(
        substitute_text("{{back:1:1}} {{back:9:1}}", &mut resolve_from(&values)),
        format!("{b} {{{{back:9:1}}}}")
    );
}

/// 読めない綴りのすぐ隣にある読める参照は、読める（`{`1文字ずつ探し直す）。
#[test]
fn a_valid_reference_next_to_a_broken_one_still_resolves() {
    let values = book(&[(0, 1, 'a')]);
    let a = &values[&ValueRef::current(1)];
    assert_eq!(
        substitute_text("{{{val:1}}", &mut resolve_from(&values)),
        format!("{{{a}")
    );
    assert_eq!(
        substitute_text("{{back:1:1{{val:1}}", &mut resolve_from(&values)),
        format!("{{{{back:1:1{a}")
    );
}

/// 入れ子（配列・オブジェクト）の中の文字列も読む。文字列でない値は変えない。
#[test]
fn nested_strings_are_substituted() {
    let values = book(&[(1, 1, 'c')]);
    let c = values[&ValueRef { back: 1, number: 1 }].clone();
    assert_eq!(
        substitute(
            &json!({ "program": "pwsh", "args": ["-enc", "{{back:1:1}}"], "n": 3, "ok": true }),
            &mut resolve_from(&values)
        ),
        json!({ "program": "pwsh", "args": ["-enc", c], "n": 3, "ok": true })
    );
}

/// **`rewrite_relative`は全部の参照を k 個前へずらす。** 読めない綴りと、参照の無い文字列は変えない。
#[test]
fn rewrite_relative_shifts_every_reference() {
    assert_eq!(
        rewrite_relative(
            "a {{val:1}} b {{user:2}} c {{back:1:3}} d {{back:0:1}} e {{val:x}}",
            2
        ),
        "a {{back:2:1}} b {{back:2:2}} c {{back:3:3}} d {{back:0:1}} e {{val:x}}"
    );
    // 対: 参照の無い文字列は1文字も変わらない。
    assert_eq!(rewrite_relative("git status {{x}}", 3), "git status {{x}}");
    // 0 個ずらすと、綴りを正の形へ揃えるだけ。
    assert_eq!(
        rewrite_relative("{{user:1}} {{back:1:1}}", 0),
        "{{val:1}} {{back:1:1}}"
    );
}

/// 正の綴りは読み手がそのまま読める（書く側と読む側が食い違わない）。モデルへ伝える例も同じ。
#[test]
fn spellings_round_trip_through_the_reader() {
    for reference in [ValueRef::current(3), ValueRef { back: 2, number: 1 }] {
        let spelling = reference.spelling();
        assert_eq!(
            pieces(&spelling),
            vec![Piece::Reference {
                reference,
                written: &spelling
            }]
        );
    }
    assert_eq!(ValueRef::current(3).spelling(), "{{val:3}}");
    assert_eq!(ValueRef { back: 2, number: 1 }.spelling(), "{{back:2:1}}");
    for example in [crate::user_reference::SYNTAX_EXAMPLE, BACK_SYNTAX_EXAMPLE] {
        assert!(
            matches!(&pieces(example)[..], [Piece::Reference { .. }]),
            "モデルへ伝える例 {example} を読み手が読めない"
        );
    }
}
