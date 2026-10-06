use harness_core::{ContentBlock, Role, ValueRef};

use super::*;

/// `pwsh --enc <塊>`の形の値（UTF-16LE で読むと`pwsh --enc <さらに塊>`、その中は`systeminfo`）。
/// `tests/user_reference.rs`の`decoded_layers_get_their_own_numbers`と同じ、害の無い実測の形。
const NESTED: &str = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAdwBCADUAQQBIAE0AQQBkAEEAQgBsAEEARwAwAEEAYQBRAEIAdQBBAEcAWQBBAGIAdwBBAD0A";

fn hex(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
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

fn tool_result(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::ToolResult {
            tool_use_id: "1".into(),
            content: text.to_string(),
            is_error: false,
        }],
    }
}

/// **人の文1つにつき置き場1つ、新しい方から**（直近が`{{val:N}}`、1つ前が`{{back:1:N}}`）。
/// ツールの結果の文と畳んだ要約の文は数えない。前の文の置き場にも解読した段が入る。
#[test]
fn one_store_per_human_message_counted_from_the_newest() {
    let messages = vec![
        user(&format!(
            "{}2 earlier messages]\n要約 {}",
            harness_core::human_turns::FOLD_SUMMARY_PREFIX,
            hex('f')
        )),
        user(&format!("これを実行して pwsh --enc {NESTED}")),
        assistant("実行します"),
        tool_result(&format!("出力 {}", hex('e'))),
        user("ありがとう"),
        user(&format!("次はこれ {}", hex('a'))),
    ];
    let book = References::from_messages(&messages).book;

    assert_eq!(book.current.texts(), vec![hex('a')]);
    assert_eq!(book.back.len(), 2, "要約とツールの結果は数えない");
    assert!(
        book.back[0].is_empty(),
        "1つ前の文（ありがとう）には値が無い"
    );
    let two_back = book.back[1].texts();
    assert_eq!(two_back[0], NESTED);
    assert!(
        two_back.iter().any(|t| t == "systeminfo"),
        "前の文の置き場にも解読した段が入る: {two_back:?}"
    );
    assert_eq!(
        book.resolve(ValueRef { back: 2, number: 1 })
            .map(|v| v.text.as_str()),
        Some(NESTED)
    );

    // `value_store_for`は直近の文の置き場そのもの（2つの入口で番号が食い違わない）。
    assert_eq!(value_store_for(&messages), book.current);
}

/// **一覧は送り直す前提の塊（`cache: false`）で、直近の文の値と、前の文がある旨の1行だけ。中身は出ない。**
#[test]
fn the_menu_block_lists_current_values_only_and_never_the_contents() {
    let messages = vec![
        user(&format!("これを実行して pwsh --enc {NESTED}")),
        assistant("実行しました"),
        user(&format!("次はこれ {}", hex('a'))),
    ];
    let block = References::from_messages(&messages)
        .menu_block()
        .expect("値がある");
    assert!(!block.cache);
    assert!(block.text.contains("{{val:1}} 64文字"), "{}", block.text);
    assert!(
        block
            .text
            .contains(harness_core::value_store::BACK_REFERENCE_LINE),
        "{}",
        block.text
    );
    for content in [NESTED, "systeminfo", hex('a').as_str()] {
        assert!(!block.text.contains(content), "{}", block.text);
    }

    // 対: 人の文が1つだけなら前の文の1行は無い。値が1つも無ければ塊ごと送らない。
    let only = References::from_messages(&messages[2..])
        .menu_block()
        .unwrap();
    assert!(!only.text.contains("{{back:"), "{}", only.text);
    assert_eq!(
        References::from_messages(&[user("短い文")]).menu_block(),
        None
    );
}
