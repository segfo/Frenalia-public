use super::*;

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

fn tool_call() -> Message {
    Message {
        role: Role::Assistant,
        content: vec![ContentBlock::ToolUse {
            id: "1".into(),
            name: "run_shell".into(),
            input: serde_json::json!({ "command": "ls" }),
        }],
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

fn fold_summary(text: &str) -> Message {
    user(&format!("{FOLD_SUMMARY_PREFIX}3 earlier messages]\n{text}"))
}

/// **形だけを見る判定と、人の文の判定の違いは「畳んだ要約」1つだけ。**
#[test]
fn the_two_checks_differ_only_on_the_fold_summary() {
    let cases = [
        (user("依頼"), true, true),
        (fold_summary("要約"), true, false),
        (tool_result("出力"), false, false),
        (assistant("返事"), false, false),
        (tool_call(), false, false),
        // 文字の塊が2つある`Role::User`は、どちらにも数えない（積む経路が無い形）。
        (
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text("a".into()), ContentBlock::Text("b".into())],
            },
            false,
            false,
        ),
    ];
    for (message, single_text, human) in cases {
        assert_eq!(is_single_text_user(&message), single_text, "{message:?}");
        assert_eq!(is_human_message(&message), human, "{message:?}");
    }
}

/// 古い順に並び、位置（添字）が付く。ツールの結果・要約・モデルの文は入らない。
#[test]
fn human_turns_are_oldest_first_with_their_index() {
    let messages = vec![
        fold_summary("昔の話"),
        user("1つ目"),
        tool_call(),
        tool_result("出力"),
        assistant("返事"),
        user("2つ目"),
    ];
    assert_eq!(
        human_turns(&messages),
        vec![
            HumanTurn {
                index: 1,
                text: "1つ目"
            },
            HumanTurn {
                index: 5,
                text: "2つ目"
            },
        ]
    );
}

/// **`k`は新しい方から数える**（0が直近）。範囲の外は`None`。
#[test]
fn nth_back_counts_from_the_newest() {
    let messages = vec![
        user("古い"),
        tool_call(),
        tool_result("出力"),
        user("新しい"),
        tool_call(),
        tool_result("また出力"),
    ];
    assert_eq!(nth_back(&messages, 0).map(|t| t.text), Some("新しい"));
    assert_eq!(nth_back(&messages, 1).map(|t| t.text), Some("古い"));
    assert_eq!(nth_back(&messages, 1).map(|t| t.index), Some(0));
    assert_eq!(nth_back(&messages, 2), None);
    assert_eq!(nth_back(&[], 0), None);
}

/// **会話を古い側から畳んでも、残った文の`k`は変わらない**（要約の文は数えないので、数がずれない）。
#[test]
fn folding_the_old_side_keeps_k_of_the_surviving_messages() {
    let before = vec![
        user("消える文"),
        assistant("返事"),
        user("残る文A"),
        assistant("返事"),
        user("残る文B"),
    ];
    let after = vec![
        fold_summary("消える文の要約"),
        user("残る文A"),
        assistant("返事"),
        user("残る文B"),
    ];
    for k in 0..2 {
        assert_eq!(
            nth_back(&before, k).map(|t| t.text),
            nth_back(&after, k).map(|t| t.text),
            "k={k}"
        );
    }
    // 畳まれた文は数えられない（要約は人の文ではない）。
    assert_eq!(nth_back(&before, 2).map(|t| t.text), Some("消える文"));
    assert_eq!(nth_back(&after, 2), None);
}
