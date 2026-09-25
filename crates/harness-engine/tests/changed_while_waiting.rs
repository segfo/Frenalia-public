//! 承認画面で待っている間に書き換えられた中身を、承認済みとして走らせない
//! （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-106）。
//!
//! ゲートが「承認した」と答える**前に**、行に出てくるファイルを書き換える。ディスパッチは承認の直後に
//! 判定の材料を計算し直し、承認したときと違えば実行しない。対照として、書き換えないゲートでは
//! 同じ呼び出しが実行されることを確かめる（「何も実行しない」実装でも禁止側は緑になるため）。

use async_trait::async_trait;
use harness_core::{
    AgentEvent, BlockKind, ContentBlock, PermissionSubject, RiskClass, StopReason, StreamEvent,
    ToolCtx, Usage,
};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, Decision, PermissionGate,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

fn tool_use_turn(command: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: "run_shell".to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: serde_json::json!({ "command": command }).to_string(),
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

/// 承認すると答えるゲート。`tamper`が`Some`なら、答える前にそのファイルを書き換える
/// （人が承認画面を見ている間に、別のプロセスが書き換えた状況を作る）。
struct ApprovingGate {
    tamper: Option<std::path::PathBuf>,
}

#[async_trait]
impl PermissionGate for ApprovingGate {
    async fn resolve(
        &self,
        _tool: &str,
        _risk: RiskClass,
        subject: &PermissionSubject,
        _input: &serde_json::Value,
    ) -> Decision {
        // 承認した材料が、実際にそのファイルを縛っていること（縛っていなければ検出しようがない）。
        match subject {
            PermissionSubject::Command(c) => assert_eq!(c.files.len(), 1, "{c:?}"),
            other => panic!("expected a run_shell subject, got {other:?}"),
        }
        if let Some(path) = &self.tamper {
            std::fs::write(path, "tampered while waiting").unwrap();
        }
        Decision::Allow
    }
}

async fn run(gate: &ApprovingGate, ws: &std::path::Path) -> (String, bool) {
    let provider = MockProvider::new(vec![tool_use_turn("Get-Content notes.txt"), end_turn()]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("show the notes");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(ws.to_path_buf());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        gate,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&tx),
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");
    let mut started = false;
    while let Ok(e) = rx.try_recv() {
        started |= matches!(e, AgentEvent::ToolStarted { .. });
    }
    let (content, _) = state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                content, is_error, ..
            } => Some((content.clone(), *is_error)),
            _ => None,
        })
        .expect("a tool_result");
    (content, started)
}

#[tokio::test]
async fn a_file_rewritten_while_waiting_for_approval_is_not_run() {
    let ws = tempfile::tempdir().unwrap();
    let notes = ws.path().join("notes.txt");
    std::fs::write(&notes, "original").unwrap();

    let (content, started) = run(
        &ApprovingGate {
            tamper: Some(notes.clone()),
        },
        ws.path(),
    )
    .await;
    assert!(!started, "the tool must not start: {content}");
    assert!(
        content.contains("changed while it was being approved"),
        "{content}"
    );

    // 対照: 書き換えなければ、同じ呼び出しは実行される。
    std::fs::write(&notes, "original").unwrap();
    let (content, started) = run(&ApprovingGate { tamper: None }, ws.path()).await;
    assert!(
        started,
        "the tool must start when nothing changed: {content}"
    );
    assert!(
        !content.contains("changed while it was being approved"),
        "{content}"
    );
}
