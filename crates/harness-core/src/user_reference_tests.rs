use serde_json::json;

use super::*;
use crate::ContentBlock;

/// 実測で写し損じが起きた値（308文字の base64。`plans/risk-judge-spike/RESULTS.md`）と同じ長さの塊。
fn blob(seed: char) -> String {
    std::iter::repeat_n(seed, 308).collect()
}

fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

fn assistant(text: &str) -> Message {
    Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

/// **長い値だけを、出てきた順に参照できる。** 短い語（コマンド名・スイッチ）は番号を取らない。
#[test]
fn only_long_values_get_a_number_and_they_keep_their_order() {
    let (a, b) = (blob('a'), blob('b'));
    let values = values_in(&[user(&format!("実行して pwsh --enc {a} と {b} -Force"))]);
    assert_eq!(values, vec![a, b]);
    assert!(values_in(&[user("ls -la して")]).is_empty());
    // ちょうど境目の長さ。
    let short: String = std::iter::repeat_n('x', MIN_REFERENCE_CHARS - 1).collect();
    let just: String = std::iter::repeat_n('y', MIN_REFERENCE_CHARS).collect();
    assert_eq!(values_in(&[user(&format!("{short} {just}"))]), vec![just]);
}

/// **長い値を含む直近のユーザーの文1つだけ**を見る（モデルの文は見ない。前の文まで通して数えない）。
#[test]
fn the_newest_user_message_that_has_long_values_wins() {
    let (old, new) = (blob('o'), blob('n'));
    let messages = vec![
        user(&format!("これを使って {old}")),
        // モデルの文にも長い値があるが、**参照元にしない**（モデルが書いた値を差し込むと、写し損じを拾う）。
        assistant(&format!("こう書きます {new}")),
        user("さっきのを実行して"), // 長い値が無いので、1つ前のユーザーの文まで遡る
    ];
    assert_eq!(values_in(&messages), vec![old.clone()]);

    let messages = vec![
        user(&format!("これを使って {old}")),
        assistant(&format!("こう書きます {new}")),
        user(&format!("今度はこれ {new}")),
    ];
    assert_eq!(values_in(&messages), vec![new]);
}

/// **ハーネスが差し込む。** モデルが書くのは番号だけで、値そのものは書かない。
#[test]
fn the_harness_substitutes_the_value_the_model_only_wrote_a_number() {
    let value = blob('a');
    let input = json!({ "command": "pwsh --enc {{user:1}}" });
    assert_eq!(
        substitute(&input, std::slice::from_ref(&value)),
        json!({ "command": format!("pwsh --enc {value}") })
    );
    // 入れ子（配列・オブジェクト）の中の文字列も差し込む（`run_program`の引数など）。
    let input = json!({ "program": "pwsh", "args": ["-enc", "{{user:1}}"], "n": 3, "ok": true });
    assert_eq!(
        substitute(&input, std::slice::from_ref(&value)),
        json!({ "program": "pwsh", "args": ["-enc", value], "n": 3, "ok": true })
    );
}

/// 1つの文字列に何度でも、別々の番号を差し込める。
#[test]
fn several_references_in_one_string_are_all_substituted() {
    let (a, b) = (blob('a'), blob('b'));
    let input = json!({ "command": "cmp {{user:1}} {{user:2}} {{user:1}}" });
    assert_eq!(
        substitute(&input, &[a.clone(), b.clone()]),
        json!({ "command": format!("cmp {a} {b} {a}") })
    );
}

/// **差し込めない参照は、書いた綴りをそのまま残す**（黙って消さない）。人は承認画面でそれを見て断れる。
#[test]
fn a_reference_that_resolves_to_nothing_is_left_visible() {
    let value = blob('a');
    for command in [
        "pwsh --enc {{user:2}}", // 番号が無い
        "pwsh --enc {{user:0}}", // 0は使わない（1始まり）
        "pwsh --enc {{user:x}}", // 数でない
        "pwsh --enc {{user:1",   // 閉じていない
        "pwsh --enc {{user:}}",  // 番号が無い
    ] {
        let out = substitute(&json!({ "command": command }), std::slice::from_ref(&value));
        assert_eq!(out, json!({ "command": command }), "{command}");
        assert!(
            !out.to_string().contains(&value),
            "{command}: 差し込んではいけない参照で差し込んだ"
        );
    }
    // 参照できる値が1つも無いときも、綴りが残る。
    assert_eq!(
        substitute(&json!({ "command": "pwsh --enc {{user:1}}" }), &[]),
        json!({ "command": "pwsh --enc {{user:1}}" })
    );
}

/// 参照の書き方を含まない入力は、1文字も変えない。
#[test]
fn input_without_references_is_untouched() {
    let input = json!({ "command": "git status", "args": ["a", "{{notuser:1}}"], "n": 1 });
    assert_eq!(substitute(&input, &[blob('a')]), input);
}

/// **参照を使わずに書き写した1文字違いを、ユーザーの値へ直す。**
///
/// 実測（2026-10-04）と同じ形: 308文字のうち1文字だけが違う値をモデルが書いた。
#[test]
fn a_transcribed_value_with_one_wrong_character_is_repaired() {
    let value = blob('a');
    let mut written: Vec<char> = value.chars().collect();
    written[100] = 'Z';
    let written: String = written.into_iter().collect();

    let input = json!({ "command": format!("pwsh --enc {written}") });
    let (out, repairs) = repair(&input, std::slice::from_ref(&value));
    assert_eq!(out, json!({ "command": format!("pwsh --enc {value}") }));
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].differences, 1);
    assert_eq!(repairs[0].written, written);
    assert_eq!(repairs[0].user_value, value);
}

/// 入れ子（配列・オブジェクト）の中も直し、**空白の並びは崩さない**。
#[test]
fn repair_reaches_nested_strings_and_keeps_the_spacing() {
    let value = blob('a');
    let written = format!("{}Z", &value[..value.len() - 1]);

    let input = json!({ "program": "pwsh", "args": ["-enc", written], "n": 3 });
    let (out, repairs) = repair(&input, std::slice::from_ref(&value));
    assert_eq!(
        out,
        json!({ "program": "pwsh", "args": ["-enc", value], "n": 3 })
    );
    assert_eq!(repairs.len(), 1);

    // 前後と語の間の空白（連なり・改行・タブ）がそのまま残る。
    let written = format!("{}Z", &value[..value.len() - 1]);
    let input = json!({ "command": format!("  a\n\t{written}  b\n") });
    let (out, _) = repair(&input, std::slice::from_ref(&value));
    assert_eq!(out, json!({ "command": format!("  a\n\t{value}  b\n") }));
}

/// **別物は直さない。** 短い語・長さが違う塊・違いが大きい塊は、書いた綴りのまま残す。
#[test]
fn values_that_are_not_transcription_slips_are_left_alone() {
    let value = blob('a');
    let one = std::slice::from_ref(&value);

    // (1) 短い語（コマンド名・スイッチ）。
    let input = json!({ "command": "ls -la --force" });
    assert_eq!(repair(&input, one), (input.clone(), vec![]));

    // (2) 長さが違う（実測の「64文字短い」型。**切り詰めは直さない**——どこが落ちたか決められない）。
    let short: String = value.chars().take(244).collect();
    let input = json!({ "command": format!("pwsh --enc {short}") });
    assert_eq!(repair(&input, one), (input.clone(), vec![]));

    // (3) 長さは同じだが違いが大きい（別の値を書いた）。
    let other = blob('b');
    let input = json!({ "command": format!("pwsh --enc {other}") });
    assert_eq!(repair(&input, one), (input.clone(), vec![]));

    // (4) 完全に一致している（直す必要が無いので知らせない）。
    let input = json!({ "command": format!("pwsh --enc {value}") });
    assert_eq!(repair(&input, one), (input.clone(), vec![]));

    // (5) 参照できる値が1つも無い。
    let written = format!("{}Z", &value[..value.len() - 1]);
    let input = json!({ "command": format!("pwsh --enc {written}") });
    assert_eq!(repair(&input, &[]), (input.clone(), vec![]));
}

/// 違いの上限はちょうど[`MAX_REPAIR_RATIO`]で切る（境目の両側を固定する）。
#[test]
fn the_difference_limit_is_fixed_on_both_sides() {
    let value = blob('a');
    let length = value.chars().count(); // 308。上限は 308 * 0.05 = 15.4 文字
    let limit = (length as f32 * MAX_REPAIR_RATIO) as usize; // 15

    for (differences, repaired) in [(limit, true), (limit + 1, false)] {
        let mut written: Vec<char> = value.chars().collect();
        for c in written.iter_mut().take(differences) {
            *c = 'Z';
        }
        let written: String = written.into_iter().collect();
        let input = json!({ "command": format!("pwsh --enc {written}") });
        let (out, repairs) = repair(&input, std::slice::from_ref(&value));
        assert_eq!(
            repairs.len(),
            usize::from(repaired),
            "{differences}文字違い"
        );
        assert_eq!(
            out == json!({ "command": format!("pwsh --enc {value}") }),
            repaired,
            "{differences}文字違い"
        );
    }
}

/// 候補が2つとも上限の内側に入るときは、**違いがいちばん少ないもの**を選ぶ。
#[test]
fn the_closest_user_value_wins() {
    let a = blob('a');
    // `b`は`a`と5文字だけ違う値。書き写した塊は`b`と1文字違い（`a`とは6文字違い）。
    let mut b: Vec<char> = a.chars().collect();
    for c in b.iter_mut().take(5) {
        *c = 'b';
    }
    let mut written = b.clone();
    written[100] = 'Z';
    let (b, written): (String, String) = (b.into_iter().collect(), written.into_iter().collect());

    let input = json!({ "command": format!("pwsh --enc {written}") });
    let (out, repairs) = repair(&input, &[a, b.clone()]);
    assert_eq!(out, json!({ "command": format!("pwsh --enc {b}") }));
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].differences, 1);
    assert_eq!(repairs[0].user_value, b);
}
