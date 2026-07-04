//! `plans/DESIGN.md` §実装マイルストーン M8検証条件
//! 「`harness -p ... --output-format json | jq` が安定スキーマ」に対応する統合テスト。
//!
//! 実プロセスを起動せず、`harness_providers::MockProvider`で`harness_cli::run_headless`を
//! 直接駆動する（§ワークスペース構成の慣例。`M06-openai-family-lmstudio.md`の
//! golden-transcriptテストと同じ方針）。stdoutは`Vec<u8>`へ差し替えてキャプチャする。

use harness_core::{BlockKind, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

use harness_cli::{run_headless, JsonOutcome, OutputFormat};

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
            usage: Usage {
                input: 10,
                output: 5,
                ..Default::default()
            },
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
            usage: Usage {
                input: 20,
                output: 8,
                ..Default::default()
            },
        },
    ]
}

/// read_fileはReadOnlyなのでDefaultモード・allowlist未登録でも許可される
/// （§パーミッション「Default」モード）→ `tool_calls[0].decision == "allowed"`を確認する。
#[tokio::test]
async fn json_output_has_stable_schema_and_allowed_tool_call() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();

    let provider = MockProvider::new(vec![
        tool_use_turn("call_1", "read_file", serde_json::json!({ "path": "a.txt" })),
        end_turn("the file says hello"),
    ]);
    let mut state = ConversationState::new();
    state.push_user_text("read a.txt");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx {
        workspace_root: dir.path().to_path_buf(),
    };
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
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
        OutputFormat::Json,
        &mut out,
    )
    .await;

    assert_eq!(exit, std::process::ExitCode::SUCCESS);

    let stdout = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "json output must be exactly one line: {stdout:?}");

    let parsed: JsonOutcome = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed.result, "the file says hello");
    assert_eq!(parsed.stop_reason, Some(StopReason::EndTurn));
    assert_eq!(parsed.turns, 2);
    assert_eq!(parsed.usage.input, 20);
    assert_eq!(parsed.usage.output, 8);
    assert!(parsed.error.is_none());
    assert_eq!(parsed.tool_calls.len(), 1);
    assert_eq!(parsed.tool_calls[0].name, "read_file");
    assert_eq!(parsed.tool_calls[0].decision, "allowed");
    assert!(parsed.tool_calls[0].result.contains("hello"));
}

/// allowlist未登録の`run_shell`（Exec）はDefaultモード・ヘッドレスで拒否される
/// （§パーミッション「ヘッドレス時: モード+allowlistのみで判定」）→
/// `tool_calls[0].decision == "denied"`かつループ自体は`EndTurn`まで正常継続することを確認する。
#[tokio::test]
async fn json_output_records_denied_tool_call() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![
        tool_use_turn("call_1", "run_shell", serde_json::json!({ "command": "echo hi" })),
        end_turn("done"),
    ]);
    let mut state = ConversationState::new();
    state.push_user_text("run a shell command");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx {
        workspace_root: dir.path().to_path_buf(),
    };
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
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
        OutputFormat::Json,
        &mut out,
    )
    .await;

    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    let parsed: JsonOutcome = serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
    assert_eq!(parsed.tool_calls.len(), 1);
    assert_eq!(parsed.tool_calls[0].decision, "denied");
}

/// §非対話モード「`jsonl`: `AgentEvent`を1行1イベントでライブ出力」。各行が単独で
/// `AgentEvent`としてパース可能であること、`TurnCompleted`が含まれることを確認する。
#[tokio::test]
async fn jsonl_output_emits_one_agent_event_per_line() {
    let provider = MockProvider::new(vec![end_turn("hi there")]);
    let mut state = ConversationState::new();
    state.push_user_text("say hi");
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx {
        workspace_root: dir.path().to_path_buf(),
    };
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
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
        OutputFormat::Jsonl,
        &mut out,
    )
    .await;

    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    let stdout = String::from_utf8(out).unwrap();
    let events: Vec<harness_core::AgentEvent> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each jsonl line must be a valid AgentEvent"))
        .collect();
    assert!(!events.is_empty());
    assert!(matches!(events[0], harness_core::AgentEvent::TurnStarted { .. }));
    assert!(events
        .iter()
        .any(|e| matches!(e, harness_core::AgentEvent::TurnCompleted { .. })));
}

/// プロバイダエラー（`max_turns`超過）でも`json`モードは`error`フィールドを持つ
/// 安定オブジェクトを1行出力し、非0で終了する（§非対話モード「終了コード」）。
#[tokio::test]
async fn json_output_surfaces_provider_error_with_nonzero_exit() {
    // MockProviderのターンを1つしか用意しないのに2ターン目のstreamを要求させるため、
    // max_turnsを1に絞ってあえて`agent loop exceeded max_turns`エラーを起こす。
    let provider = MockProvider::new(vec![tool_use_turn(
        "call_1",
        "read_file",
        serde_json::json!({ "path": "missing.txt" }),
    )]);
    let mut state = ConversationState::new();
    state.push_user_text("read missing.txt");
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx {
        workspace_root: dir.path().to_path_buf(),
    };
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 1,
        },
        OutputFormat::Json,
        &mut out,
    )
    .await;

    assert_eq!(exit, std::process::ExitCode::FAILURE);
    let parsed: JsonOutcome = serde_json::from_str(String::from_utf8(out).unwrap().trim()).unwrap();
    assert!(parsed.error.is_some());
    assert!(parsed.stop_reason.is_none());
    // 1ターン目までに発行された`ToolCallProposed`/`ToolFinished`は捕捉されている。
    assert_eq!(parsed.tool_calls.len(), 1);
}
