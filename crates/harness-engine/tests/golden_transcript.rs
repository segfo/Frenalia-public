//! `plans/DESIGN.md` §実装マイルストーン M6検証条件「mockプロバイダのgolden-transcriptテスト」。
//!
//! `harness_providers::MockProvider`（ワイヤ形式を一切経由しないテスト用スクリプトプロバイダ、
//! §ワークスペース構成）で決定的に1往復のツール呼び出しループを駆動し、`run_agent_loop`完了後の
//! `ConversationState::messages`が期待する固定トランスクリプトと**構造的に完全一致**することを
//! 確認する。プロバイダのワイヤ形式差異（OpenAI引数文字列断片 / Anthropic部分JSON等）を経由せず
//! `StreamEvent`を直接スクリプトするため、`run_agent_loop`自体のブロック蓄積・ツールディスパッチ・
//! `tool_result`往復ロジックのみを対象にした回帰テストになる。

use harness_core::{BlockKind, ContentBlock, Message, Role, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
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

fn end_turn(text: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: text.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

#[tokio::test]
async fn read_file_tool_loop_produces_expected_transcript() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();

    let provider = MockProvider::new(vec![
        tool_use_turn("call_1", "read_file", serde_json::json!({ "path": "greeting.txt" })),
        end_turn("The file says: hello world"),
    ]);

    let mut state = ConversationState::new();
    state.push_user_text("read greeting.txt and tell me what it says");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx {
        workspace_root: dir.path().to_path_buf(),
    };
    // read_file はReadOnlyなのでヘッドレス既定（allowlist未登録）でも自動許可される
    // （§パーミッション「Default」モード）。
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let outcome = run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
        },
        None,
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "The file says: hello world");
    assert_eq!(outcome.stop_reason, StopReason::EndTurn);

    let expected = vec![
        Message {
            role: Role::User,
            content: vec![ContentBlock::Text(
                "read greeting.txt and tell me what it says".to_string(),
            )],
        },
        Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "call_1".to_string(),
                name: "read_file".to_string(),
                input: serde_json::json!({ "path": "greeting.txt" }),
            }],
        },
        Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: "     1\thello world".to_string(),
                is_error: false,
            }],
        },
        Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text("The file says: hello world".to_string())],
        },
    ];

    assert_eq!(state.messages, expected, "golden transcript mismatch");
}
