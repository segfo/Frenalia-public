use serde_json::json;

use super::*;
use crate::ContentBlock;

/// 実測で写し損じが起きた値（308文字の base64。`plans/risk-judge-spike/RESULTS.md`）と同じ長さの塊。
///
/// **seedはhex文字に限る**（0-9・a-f）。形フィルタ（[`looks_like_payload`]）は、
/// Base64形か hex形に合う語だけを候補にするので、試験の塊もその形で作る。
fn blob(seed: char) -> String {
    debug_assert!(
        seed.is_ascii_hexdigit(),
        "blob の seed は hex 文字（0-9・a-f）に限る。形フィルタに合わないとそもそも候補にならない。"
    );
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
    // ちょうど境目の長さ。形フィルタに合わせて hex 文字で作る。
    let short: String = std::iter::repeat_n('a', MIN_REFERENCE_CHARS - 1).collect();
    let just: String = std::iter::repeat_n('b', MIN_REFERENCE_CHARS).collect();
    assert_eq!(values_in(&[user(&format!("{short} {just}"))]), vec![just]);
}

/// **長い値を含む直近のユーザーの文1つだけ**を見る（モデルの文は見ない。前の文まで通して数えない）。
#[test]
fn the_newest_user_message_that_has_long_values_wins() {
    // hex 文字で作らないと形フィルタに弾かれて候補にならない。
    let (old, new) = (blob('c'), blob('d'));
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

/// **散文・識別子・URL は候補にしない**（2026-10-06の無限ループ事故の再発防止）。
///
/// 「空白なしで40字以上」だけだと日本語の普通の文がまるごと候補になり、`edit_file`の`old_string`等と
/// Levenshtein 距離で近く見えて拒否が無限に続く。[`looks_like_payload`]で形を見て、
/// Base64 形か hex形に合うものだけ候補にする。
#[test]
fn prose_and_identifiers_are_not_candidates() {
    // ちょうど無限ループを起こした形。日本語の文、仮名漢字あり。
    let prose = "Harnessを使ったモデルとの会話の中で「Markdownの修正を依頼」するとハーネス側のリトライが走り無限ループする。";
    assert!(values_in(&[user(prose)]).is_empty());

    // ハイフン付きの英識別子。長さは40字以上だが Base64 文字集合に`-`が無い。
    let identifier = "premise-first-explanation-is-a-skill-that-tells-you-how";
    assert!(identifier.chars().count() >= MIN_REFERENCE_CHARS);
    assert!(values_in(&[user(identifier)]).is_empty());

    // URL。`:` `/` `.` があるのでどちらの形にも合わない。
    let url = "https://example.com/very/long/path/to/some/resource.html";
    assert!(url.chars().count() >= MIN_REFERENCE_CHARS);
    assert!(values_in(&[user(url)]).is_empty());

    // 数字も記号も無い長い純英単語（camelCase 等）。Base64 文字集合には収まるが、数字／記号が無いので脱落。
    let camel = "UltraSuperAwesomeProductNameEditionWithExtendedCapabilities";
    assert!(camel.chars().count() >= MIN_REFERENCE_CHARS);
    assert!(values_in(&[user(camel)]).is_empty());
}

/// **本来の守備範囲（Base64形・hex形）はちゃんと候補になる。**
#[test]
fn genuine_payloads_remain_candidates() {
    // UTF-16 BOM 付き Base64（PowerShell `-enc` の実測形）。数字`3`・`0`・`8`が含まれる。
    let utf16_b64 = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQBnAEEAQwAwADA=";
    assert!(utf16_b64.chars().count() >= MIN_REFERENCE_CHARS);
    assert_eq!(values_in(&[user(utf16_b64)]), vec![utf16_b64.to_string()]);

    // SHA-1（40字 hex）。
    let sha1 = "abcdef0123456789abcdef0123456789abcdef01";
    assert!(sha1.chars().count() == 40);
    assert_eq!(values_in(&[user(sha1)]), vec![sha1.to_string()]);

    // SHA-256（64字 hex）。
    let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(sha256.chars().count() == 64);
    assert_eq!(values_in(&[user(sha256)]), vec![sha256.to_string()]);
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

// --- 書き写しの審査（D-115。`review`） ---

/// **一字一句同じ写しは走らせるが、黙ってはいない。** 決まりが守られていない回数がここに現れる。
#[test]
fn an_exact_transcription_is_reported_but_allowed() {
    let value = blob('a');
    let found = review(
        &json!({ "command": format!("pwsh --enc {value}") }),
        std::slice::from_ref(&value),
    );
    assert_eq!(found.len(), 1);
    assert!(found[0].is_exact());
    assert_eq!(found[0].differences, 0);
    assert_eq!(found[0].number, 1);
    assert_eq!(found[0].value_chars, 308);
}

/// **参照の書き方を正しく使った呼び出しは、審査に何も引っかからない。**
///
/// `review`は差し込みの**前**に通すので、ここには値そのものが無い。差し込んだ後に見ると、
/// 正しく書いた呼び出しも「書き写した」に見えてしまう。
#[test]
fn a_call_that_uses_the_reference_is_not_flagged() {
    let value = blob('a');
    let found = review(
        &json!({ "command": "pwsh --enc {{user:1}}" }),
        std::slice::from_ref(&value),
    );
    assert!(found.is_empty(), "{found:?}");
}

/// **実測そのものを固定する。** 2026-10-04、ローカルの`qwen3.6-35b`が同じ308文字を2回書き写し、
/// 2回とも損じた。値は会話の記録（`<workspace>\.harness\sessions\session-*.jsonl`）から写した。
///
/// 1回目は307文字（1文字消して1文字書き換え＝2回違い、0.6%）、2回目は244文字（2か所まとめて
/// 64文字落ち＝64回違い、20.8%）。**どちらも実行しない。**
#[test]
fn both_measured_transcriptions_are_refused() {
    const USER_VALUE: &str = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQBnAEEAQwAwAEEATABRAEIAbABBAEcANABBAFkAdwBBAGcAQQBHAE0AQQBkAHcAQgBDAEEARABVAEEAUQBRAEIASQBBAEUAMABBAFEAUQBCAGsAQQBFAEUAQQBRAGcAQgBzAEEARQBFAEEAUgB3AEEAdwBBAEUARQBBAFkAUQBCAFIAQQBFAEkAQQBkAFEAQgBCAEEARQBjAEEAVwBRAEIAQgBBAEcASQBBAGQAdwBCAEIAQQBEADAAQQA=";
    const SLIP_2: &str = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQBnAEEAQwAwAEEATABRAEIAbABBAEcANABBAFkAdwBBAGcAQQBHAE0AQBkAHcAQgBDAEEARQBVAEEAUQBRAEIASQBBAEUAMABBAFEAUQBCAGsAQQBFAEUAQQBRAGcAQgBzAEEARQBFAEEAUgB3AEEAdwBBAEUARQBBAFkAUQBCAFIAQQBFAEkAQQBkAFEAQgBCAEEARQBjAEEAVwBRAEIAQgBBAEcASQBBAGQAdwBCAEIAQQBEADAAQQA=";
    const SLIP_64: &str = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQBnAEEAQwAwAEEATABRAEIAbABBAEcANABBAFkAdwBBAGcAQQBHAE0AQQBkAHcAQgBDAEEARQBBAEEAUgB3AEEAdwBBAEUARQBBAFkAUQBCAFIAQQBFAEkAQQBkAFEAQgBCAEEARQBjAEEAVwBRAEIAQgBBAEcASQBBAGQAdwBCAEIAQQBEADAAQQA=";

    let value = USER_VALUE.to_string();
    for (written, differences, chars) in [(SLIP_2, 2, 307), (SLIP_64, 64, 244)] {
        assert_eq!(written.chars().count(), chars);
        let found = review(
            &json!({ "command": format!("pwsh --enc {written}") }),
            std::slice::from_ref(&value),
        );
        assert_eq!(found.len(), 1, "{differences}文字違い");
        assert!(!found[0].is_exact(), "{differences}文字違い");
        assert_eq!(found[0].differences, differences);
        assert_eq!(found[0].number, 1);
    }
}

/// 2回目の実測は、値を**別のコマンドの引数として埋め込んだ**形だった。飾りが付いていても見つける。
#[test]
fn a_transcription_embedded_in_another_command_is_still_found() {
    let value = blob('a');
    let mut slipped: Vec<char> = value.chars().collect();
    slipped[100] = 'Z';
    let slipped: String = slipped.into_iter().collect();

    for (before, after) in [("payload=", ""), ("--enc=", ""), ("\"", "\""), ("(", ")")] {
        let found = review(
            &json!({ "command": format!("{before}{slipped}{after}") }),
            std::slice::from_ref(&value),
        );
        assert_eq!(found.len(), 1, "{before}|{after}");
        assert_eq!(found[0].differences, 1, "{before}|{after}");
        // 飾りは違いに数えない——数えると、短い値では写しを見落とす。
        assert_eq!(found[0].written_chars, 308, "{before}|{after}");
    }
}

/// 入れ子（配列・オブジェクト）の中も審査する。
#[test]
fn nested_strings_are_reviewed() {
    let value = blob('a');
    let mut slipped: Vec<char> = value.chars().collect();
    slipped[7] = 'Z';
    let slipped: String = slipped.into_iter().collect();

    let found = review(
        &json!({ "program": "pwsh", "args": ["-enc", slipped], "n": 3, "ok": true }),
        std::slice::from_ref(&value),
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].differences, 1);
}

/// **写しでないものは素通りさせる。** 短い語・無関係な長い値・値が1つも無いとき。
#[test]
fn things_that_are_not_transcriptions_are_ignored() {
    let value = blob('a');
    let one = std::slice::from_ref(&value);

    // 短い語（コマンド名・スイッチ）。
    assert!(review(&json!({ "command": "ls -la --force" }), one).is_empty());
    // 無関係な長い値（モデルが自分で作ったもの）。
    assert!(review(&json!({ "command": blob('b') }), one).is_empty());
    // 参照できる値が1つも無い。
    assert!(review(&json!({ "command": blob('a') }), &[]).is_empty());
    // 文字列でない項目。
    assert!(review(&json!({ "n": 3, "ok": true, "nothing": null }), one).is_empty());
}

/// 写しとみなす違いの上限は、ちょうど[`MAX_TRANSCRIPTION_RATIO`]で切る（境目の両側を固定する）。
#[test]
fn the_transcription_limit_is_fixed_on_both_sides() {
    let value = blob('a');
    let length = value.chars().count(); // 308。上限は 308 * 0.5 = 154 回
    let limit = (length as f32 * MAX_TRANSCRIPTION_RATIO) as usize;

    for (differences, seen) in [(limit, true), (limit + 1, false)] {
        let mut written: Vec<char> = value.chars().collect();
        for c in written.iter_mut().take(differences) {
            *c = 'Z';
        }
        let written: String = written.into_iter().collect();
        let found = review(&json!({ "command": written }), std::slice::from_ref(&value));
        assert_eq!(found.len(), usize::from(seen), "{differences}回違い");
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

    let found = review(&json!({ "command": written }), &[a, b]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].number, 2, "`b`の方が近い");
    assert_eq!(found[0].differences, 1);
}

/// **断る文は一覧をそのまま渡し、どの番号を指すかはモデルに選ばせる。**
///
/// ハーネスは「どれに近いか」までしか言えない——実測（2026-10-04）では、ユーザーの値を途中まで
/// 書き写した語が、その値を解読して得た別の値の方に近く出た。1つに決めて返したところ、モデルは
/// その番号を素直に使い、`pwsh --enc pwsh --enc …` という走らない行を組み立てた。
///
/// **文字を数え直させない**ことも固定する——実測ではモデルが数を合わせようとして手で数え始め、
/// 1往復をまるごと使った。
#[test]
fn the_refusal_hands_over_the_whole_list_and_does_not_pick_for_the_model() {
    let value = blob('a');
    let mut slipped: Vec<char> = value.chars().collect();
    slipped[100] = 'Z';
    let slipped: String = slipped.into_iter().collect();

    let found = review(&json!({ "command": slipped }), std::slice::from_ref(&value));
    let mut store = crate::ValueStore::from_user_values(vec![value]);
    store.push_decoded(1, "base64", "systeminfo".to_string());
    let menu = store.render().unwrap();
    let message = found[0].refusal_ja(&menu);

    // 一覧がそのまま入っている（番号を1つに決めていない）。
    assert!(message.contains("{{val:1}}"), "{message}");
    assert!(message.contains("{{val:2}}"), "{message}");
    assert!(message.contains("実行しませんでした"), "{message}");
    assert!(message.contains("数え直す必要はありません"), "{message}");
    assert!(message.contains('1'), "違いの回数を言っていない: {message}");
    assert_eq!(found[0].reference(), "{{val:1}}");
}

/// **古い綴り`{{user:N}}`も読み続ける。** 置き場が`value_store`へ移る前にモデルへ伝えていた書き方なので、
/// 文脈に残っているものを無言で落とさない（落とすと、その綴りが残ったコマンドが走る）。
#[test]
fn the_old_spelling_still_substitutes() {
    let value = blob('a');
    let one = std::slice::from_ref(&value);
    for command in ["pwsh --enc {{val:1}}", "pwsh --enc {{user:1}}"] {
        assert_eq!(
            substitute(&json!({ "command": command }), one),
            json!({ "command": format!("pwsh --enc {value}") }),
            "{command}"
        );
    }
    // 1つの文字列に両方が出ても、出てきた順に差し込む。
    let (a, b) = (blob('a'), blob('b'));
    assert_eq!(
        substitute(
            &json!({ "command": "cmp {{user:2}} {{val:1}}" }),
            &[a.clone(), b.clone()]
        ),
        json!({ "command": format!("cmp {b} {a}") })
    );
}
