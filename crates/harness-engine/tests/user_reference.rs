//! ユーザーが書いた長い値を、モデルに**書き写させず参照させる**仕組みの通し試験
//! （`harness_core::user_reference`。D-100 の追記）。
//!
//! 守りたいのは2つ。**モデルが番号だけを書いたとき、判定も実行もユーザーの文の値そのものを見る**ことと、
//! **差し込めない番号を書いたら、その綴りがそのまま残る**（黙って別のものを走らせない）こと。
//!
//! 実測の背景（2026-10-04、ローカルの`qwen3.6-35b`・4回）: 308文字の base64 を4回とも写し損じ、1文字違った値は
//! `systeminfo`ではなく`sDsteminfo`を走らせる命令になっていた。

use harness_core::{BlockKind, ContentBlock, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

/// 写し損じが起きた実測と同じ長さ（308文字）の値。
fn long_value() -> String {
    "cAB3AHMAaAAgAC0ALQBlAG4AYwAg".repeat(11) + "QQA="
}

fn tool_use_turn(input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: "write_file".to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

fn end_turn() -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: "done".to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

/// ユーザーの文を`user_text`にして`write_file`を1回撃ち、書かれたファイルの中身を返す（書けなければ`None`）。
///
/// **`write_file`で測る**——書いた中身を読み返せば、判定と実行が見た文字列がそのまま分かる。
async fn run_write(user_text: &str, input: serde_json::Value) -> (Option<String>, String) {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![tool_use_turn(input), end_turn()]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text(user_text);

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![], dir.path());

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
        },
        None,
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");

    let result = state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("the write_file call must produce a tool_result");
    (
        std::fs::read_to_string(dir.path().join("out.txt")).ok(),
        result,
    )
}

/// **モデルが書くのは番号だけ。実際に書かれるのはユーザーの文の値そのもの。**
#[tokio::test]
async fn the_harness_substitutes_the_value_so_the_model_never_transcribes_it() {
    let value = long_value();
    let (written, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:1}}" }),
    )
    .await;
    assert_eq!(
        written.as_deref(),
        Some(format!("payload={value}").as_str())
    );
}

/// **差し込めない番号は、綴りのまま残る**（黙って空にして別のものを走らせない）。
#[tokio::test]
async fn an_unresolvable_reference_stays_visible() {
    let value = long_value();
    let (written, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:2}}" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("payload={{user:2}}"));

    // ユーザーの文に長い値が無いときも同じ。
    let (written, _) = run_write(
        "短い文です",
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:1}}" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("payload={{user:1}}"));
}

/// 対照: 参照を書かない入力は、1文字も変わらない（この仕組みが普通の呼び出しに触らない）。
#[tokio::test]
async fn input_without_a_reference_is_untouched() {
    let value = long_value();
    let (written, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "plain text" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("plain text"));
}
