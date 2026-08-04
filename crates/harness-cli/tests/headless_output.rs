//! `plans/DESIGN.md` §実装マイルストーン M8検証条件
//! 「`harness -p ... --output-format json | jq` が安定スキーマ」に対応する統合テスト。
//!
//! 実プロセスを起動せず、`harness_providers::MockProvider`で`harness_cli::run_headless`を
//! 直接駆動する（§ワークスペース構成の慣例。`M06-openai-family-lmstudio.md`の
//! golden-transcriptテストと同じ方針）。stdoutは`Vec<u8>`へ差し替えてキャプチャする。

use harness_cognition::{CognitiveOrchestrator, PhaseBudgets};
use harness_core::{BlockKind, CognitionLevel, StopReason, StreamEvent, ToolCtx, Usage};
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
        tool_use_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "a.txt" }),
        ),
        end_turn("the file says hello"),
    ]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("read a.txt");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
        },
        OutputFormat::Json,
        &mut out,
    )
    .await;

    assert_eq!(exit, std::process::ExitCode::SUCCESS);

    let stdout = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "json output must be exactly one line: {stdout:?}"
    );

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
        tool_use_turn(
            "call_1",
            "run_shell",
            serde_json::json!({ "command": "echo hi" }),
        ),
        end_turn("done"),
    ]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("run a shell command");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
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
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("say hi");
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
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
    assert!(matches!(
        events[0],
        harness_core::AgentEvent::TurnStarted { .. }
    ));
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
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("read missing.txt");
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    let exit = run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 1,
            compaction: Default::default(),
            degeneracy: None,
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

// --- 縮退ガードと出力契約（M21、`plans/DESIGN-COGNITION.md` §11.4） ---

/// `？`の反復で`MaxTokens`に達する縮退ストリーム（LMStudio実機で観測した形）。
fn degenerate_turn() -> Vec<StreamEvent> {
    let mut events = vec![StreamEvent::BlockStart {
        index: 0,
        kind: BlockKind::Thinking,
    }];
    for _ in 0..16 {
        events.push(StreamEvent::ThinkingDelta {
            index: 0,
            text: "\u{ff1f}".repeat(64),
        });
    }
    events.push(StreamEvent::BlockStop { index: 0 });
    events.push(StreamEvent::Done {
        stop_reason: StopReason::MaxTokens,
        usage: Usage::default(),
    });
    events
}

fn guarded_config() -> AgentLoopConfig {
    AgentLoopConfig {
        model: "mock".into(),
        max_tokens: 100,
        max_turns: 5,
        compaction: Default::default(),
        degeneracy: Some(harness_engine::degeneracy::DegeneracyDetector::new(
            Default::default(),
        )),
    }
}

async fn run_guarded(turns: Vec<Vec<StreamEvent>>, format: OutputFormat) -> String {
    let provider = MockProvider::new(turns);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("やって");
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut out = Vec::new();
    run_headless(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        guarded_config(),
        format,
        &mut out,
    )
    .await;
    String::from_utf8(out).unwrap()
}

/// **正常時の`text`出力は1バイトも変わらない**（§11.4）。ガードを有効にしても、
/// 縮退が起きない限り区切りマーカーは一切現れない。
#[tokio::test]
async fn the_text_format_is_byte_identical_when_nothing_degenerates() {
    let with_guard = run_guarded(vec![end_turn("hi there")], OutputFormat::Text).await;
    assert_eq!(with_guard, "hi there\n");
    assert!(!with_guard.contains('\x1e'), "{with_guard:?}");
}

/// 縮退時だけ区切りマーカーが出て、`bytes=`で下流が末尾を切り詰められる。
#[tokio::test]
async fn the_text_format_emits_a_rewind_marker_only_when_a_turn_is_discarded() {
    let stdout = run_guarded(
        vec![degenerate_turn(), end_turn("最終回答")],
        OutputFormat::Text,
    )
    .await;

    // thinkingだけが流れて本文は0バイトだったので`bytes=0`。マーカーは行として完結する。
    assert_eq!(
        stdout,
        "\x1e[harness:discarded bytes=0 reason=short_period_repeat]\n最終回答\n"
    );
}

/// `jsonl`は`TurnDiscarded`行がそのまま出る（既に機械可読なので加工しない）。
#[tokio::test]
async fn jsonl_emits_the_turn_discarded_event_verbatim() {
    let stdout = run_guarded(
        vec![degenerate_turn(), end_turn("最終回答")],
        OutputFormat::Jsonl,
    )
    .await;

    let events: Vec<harness_core::AgentEvent> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each jsonl line must be a valid AgentEvent"))
        .collect();
    let discarded: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            harness_core::AgentEvent::TurnDiscarded {
                kind, next_rung, ..
            } => Some((*kind, next_rung.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(discarded.len(), 1, "{events:?}");
    assert_eq!(discarded[0].0, harness_core::DegenerateKind::ShortPeriodRepeat);
    assert_eq!(discarded[0].1.as_deref(), Some("jitter"));
}

/// `json`は`discarded_turns`へ集計される。**`turns`とは独立**——梯子は1つの
/// `TurnStarted`の内側で回るので、捨てた回はターン数に現れない。
#[tokio::test]
async fn json_counts_discarded_turns_separately_from_turns() {
    let stdout = run_guarded(
        vec![degenerate_turn(), end_turn("最終回答")],
        OutputFormat::Json,
    )
    .await;
    let parsed: JsonOutcome = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(parsed.discarded_turns, 1);
    assert_eq!(parsed.turns, 1, "捨てた回はターン数に現れない");
    assert_eq!(parsed.result, "最終回答");

    // 正常時は常に0。
    let healthy = run_guarded(vec![end_turn("hi")], OutputFormat::Json).await;
    let parsed: JsonOutcome = serde_json::from_str(healthy.trim()).unwrap();
    assert_eq!(parsed.discarded_turns, 0);
}
