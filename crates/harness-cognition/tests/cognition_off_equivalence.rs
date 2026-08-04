//! `CognitionLevel::Off`が素朴ループ（`harness_engine::run_agent_loop`）と**等価**であることの
//! 契約テスト。`docs/INDEX.md` M13の完了条件「既存mockテスト全緑（バイト等価）」の、
//! 認知レイヤー側から見た担保。
//!
//! 同一シナリオを (a) `CognitiveOrchestrator`経由 と (b) `run_agent_loop`直接 で流し、
//! 会話履歴と`AgentEvent`の列が一致することを確認する。M14以降で`Off`の経路に何かを
//! 挟み込んでしまった場合、ここが落ちる。

use harness_cognition::{CognitiveOrchestrator, PhaseBudgets};
use harness_core::{
    AgentEvent, BlockKind, CognitionLevel, ContentBlock, Message, StopReason, StreamEvent, ToolCtx,
    Usage,
};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
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

fn scripted_turns() -> Vec<Vec<StreamEvent>> {
    vec![
        tool_use_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "greeting.txt" }),
        ),
        end_turn("The file says: hello world"),
    ]
}

/// `AgentEvent`は`PartialEq`を導出していないため、JSON表現で比較する。ここでは
/// `estimated_input_tokens`のような数値も含めて完全一致を要求する——2経路は同一の
/// リクエストを組むはずで、ずれたらそれ自体が等価性の破れだから。
fn drain_events(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AgentEvent>,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(serde_json::to_value(&ev).unwrap());
    }
    out
}

struct RunResult {
    messages: Vec<Message>,
    events: Vec<serde_json::Value>,
    text: String,
    deltas: String,
}

#[tokio::test]
async fn cognition_off_matches_the_naive_loop_exactly() {
    let through_orchestrator = run_scenario(true).await;
    let through_naive_loop = run_scenario(false).await;

    assert_eq!(
        through_orchestrator.messages, through_naive_loop.messages,
        "conversation transcript diverged between CognitionLevel::Off and the naive loop"
    );
    assert_eq!(
        through_orchestrator.events, through_naive_loop.events,
        "agent event stream diverged between CognitionLevel::Off and the naive loop"
    );
    assert_eq!(through_orchestrator.text, through_naive_loop.text);
    assert_eq!(through_orchestrator.deltas, through_naive_loop.deltas);

    // シナリオ自体が期待通り動いていること（両方が同じように壊れていても気付けるように）。
    assert_eq!(through_orchestrator.text, "The file says: hello world");
    assert_eq!(through_orchestrator.messages.len(), 4);
    assert!(through_orchestrator
        .messages
        .iter()
        .any(|m| m.content.iter().any(|b| matches!(
            b,
            ContentBlock::ToolResult { content, .. } if content == "     1\thello world"
        ))));
}

async fn run_scenario(via_orchestrator: bool) -> RunResult {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();

    let provider = MockProvider::new(scripted_turns());
    let tools = ToolRegistry::with_builtin_tools();
    // `ToolCtx::new`はworkspace_rootを埋めるだけなので、`system`は空にしてtempdirパスが
    // `estimated_input_tokens`へ混ざらないようにする（2経路で同じ値になる必要がある）。
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("read greeting.txt and tell me what it says");

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut deltas = String::new();
    let config = AgentLoopConfig {
        model: "mock".into(),
        max_tokens: 100,
        max_turns: 5,
        compaction: Default::default(),
        degeneracy: None,
    };

    let outcome = if via_orchestrator {
        let orchestrator =
            CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap();
        orchestrator
            .run(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                config,
                Some(&events_tx),
                None,
                |d: &str| deltas.push_str(d),
            )
            .await
            .unwrap()
    } else {
        run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            config,
            Some(&events_tx),
            None,
            |d: &str| deltas.push_str(d),
        )
        .await
        .unwrap()
    };

    RunResult {
        messages: state.messages.clone(),
        events: drain_events(&mut events_rx),
        text: outcome.text,
        deltas,
    }
}
