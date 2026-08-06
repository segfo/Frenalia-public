//! `plans/DESIGN.md` §実装マイルストーン M6検証条件「mockプロバイダのgolden-transcriptテスト」。
//!
//! `harness_providers::MockProvider`（ワイヤ形式を一切経由しないテスト用スクリプトプロバイダ、
//! §ワークスペース構成）で決定的に1往復のツール呼び出しループを駆動し、`run_agent_loop`完了後の
//! `ConversationState::messages`が期待する固定トランスクリプトと**構造的に完全一致**することを
//! 確認する。プロバイダのワイヤ形式差異（OpenAI引数文字列断片 / Anthropic部分JSON等）を経由せず
//! `StreamEvent`を直接スクリプトするため、`run_agent_loop`自体のブロック蓄積・ツールディスパッチ・
//! `tool_result`往復ロジックのみを対象にした回帰テストになる。

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError,
    Role, StopReason, StreamEvent, ToolCtx, Usage,
};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, Executor, PermissionArbiter,
    PermissionMode, RawTurnRequest, RawTurnResult, ToolCallDecision, TurnExecutor,
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

#[tokio::test]
async fn read_file_tool_loop_produces_expected_transcript() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();

    let provider = MockProvider::new(vec![
        tool_use_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "greeting.txt" }),
        ),
        end_turn("The file says: hello world"),
    ]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("read greeting.txt and tell me what it says");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
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
            compaction: Default::default(),
            degeneracy: None,
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

// ---------------------------------------------------------------------------
// characterization test（M13: `raw_turn`抽出のリファクタ回帰ガード）
//
// 上の golden transcript が固定しているのは`state.messages`だけで、`AgentEvent`の**列**と
// `ContextTooLong`のリアクティブ圧縮経路はこれまでどこでも固定されていなかった。
// `run_agent_loop`を「1ステップ＝`raw_turn`」の上へ再構築する際、どのイベントを1ステップの
// 内側で出しどれをループ側で出すかを取り違えると、順序・回数が静かに変わる。ここで固定する。
// ---------------------------------------------------------------------------

/// 認知レイヤー（M14以降）が使う形での1ステップ実行。`&dyn Executor`へ落とせること自体が
/// 検証対象で、`RawTurnRequest`/`RawTurnResult`がdyn-safeなシグネチャに収まっているかを見る
/// （`on_text_delta`のジェネリクスをtrait側へ漏らすとここでコンパイルが通らなくなる）。
#[tokio::test]
async fn executor_trait_drives_one_step_through_dyn() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();

    let provider = MockProvider::new(vec![tool_use_turn(
        "call_1",
        "read_file",
        serde_json::json!({ "path": "greeting.txt" }),
    )]);
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None, None);
    let executor: &dyn Executor = &executor;

    let result = executor
        .raw_turn(RawTurnRequest::user_facing(minimal_request(
            &tools,
            &ctx,
            "read greeting.txt",
        )))
        .await
        .unwrap();

    let RawTurnResult::Completed(raw) = result else {
        panic!("expected a completed turn");
    };
    assert_eq!(raw.tool_calls.len(), 1);
    assert_eq!(raw.tool_calls[0].name, "read_file");
    assert_eq!(raw.tool_calls[0].decision, ToolCallDecision::Executed);
    assert_eq!(raw.tool_calls[0].output.content, "     1\thello world");
    assert!(!raw.cancelled_mid_tool);
    // 1ステップは会話履歴を持たない。積むかどうかは呼び出し側（素朴ループ／認知層）の判断。
    assert_eq!(raw.content.len(), 1);
}

/// 認知レイヤーが`PermissionGate`を**構造的に迂回できない**ことの確認。ツール実行が
/// `raw_turn`の内側にあるため、`Executor`経由で直接1ステップを回しても未許可の
/// `run_shell`は実行されず、拒否理由が`tool_result`として返る。
#[tokio::test]
async fn executor_trait_cannot_bypass_the_permission_gate() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![tool_use_turn(
        "call_1",
        "run_shell",
        serde_json::json!({ "command": "echo should-not-run" }),
    )]);
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None, None);
    let executor: &dyn Executor = &executor;

    let result = executor
        .raw_turn(RawTurnRequest::user_facing(minimal_request(
            &tools,
            &ctx,
            "run a shell command",
        )))
        .await
        .unwrap();

    let RawTurnResult::Completed(raw) = result else {
        panic!("expected a completed turn");
    };
    assert_eq!(raw.tool_calls.len(), 1);
    assert_eq!(raw.tool_calls[0].decision, ToolCallDecision::DeniedByPolicy);
    assert!(raw.tool_calls[0].output.is_error);
    assert!(
        raw.tool_calls[0]
            .output
            .content
            .starts_with("permission denied by policy"),
        "{}",
        raw.tool_calls[0].output.content
    );
}

fn minimal_request(
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    prompt: &str,
) -> harness_core::CompletionRequest {
    harness_core::CompletionRequest {
        system: Vec::new(),
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text(prompt.to_string())],
        }],
        tools: tools.to_specs_for_ctx(ctx),
        tool_choice: harness_core::ToolChoice::Auto,
        output: None,
        parallel_tool_calls: Some(false),
        max_tokens: 100,
        sampling: harness_core::Sampling::default(),
        model: "mock".to_string(),
    }
}

/// `AgentEvent`のバリアント名だけを取り出す。`AgentEvent`は`PartialEq`を導出しておらず直接
/// 比較できないうえ、`TurnStarted.estimated_input_tokens`のようにツールspecやシステム
/// プロンプトの文言変更で揺れるフィールドを持つ。ここで固定したいのは「どの種類のイベントが
/// 何回・どの順に出るか」なので、externally taggedなJSON表現のタグ名だけを使う。
fn event_kind(ev: &AgentEvent) -> String {
    match serde_json::to_value(ev).expect("AgentEvent is serializable") {
        serde_json::Value::Object(map) => map
            .keys()
            .next()
            .cloned()
            .expect("externally tagged variant has exactly one key"),
        // `Cancelled`のようなユニットバリアントはタグ名の文字列そのものになる。
        serde_json::Value::String(s) => s,
        other => panic!("unexpected AgentEvent encoding: {other}"),
    }
}

fn drain_event_kinds(rx: &mut tokio::sync::mpsc::UnboundedReceiver<AgentEvent>) -> Vec<String> {
    let mut kinds = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        kinds.push(event_kind(&ev));
    }
    kinds
}

/// `provider.stream()`の呼び出し1回分の台本。「ストリーム開始**前**の失敗」と
/// 「開始**後**の失敗」を区別できることが要点で、圧縮リトライがどちらに効くかを固定する。
enum ScriptedCall {
    CallFails(ProviderError),
    Streams(Vec<StreamEvent>),
    StreamsThenFails(Vec<StreamEvent>, ProviderError),
}

/// 呼び出し回数ごとに違う結果を返すテスト専用プロバイダ。`ContextTooLong`のリアクティブ
/// 圧縮経路は「1回目=本題（失敗）／2回目=圧縮の要約コール／3回目=再試行」と、同じ
/// プロバイダが3回別々の役割で呼ばれるため、`MockProvider`のターン列では表現できない。
struct ScriptedProvider {
    calls: std::sync::Mutex<std::collections::VecDeque<ScriptedCall>>,
    made: std::sync::atomic::AtomicUsize,
}

impl ScriptedProvider {
    fn new(calls: Vec<ScriptedCall>) -> Self {
        Self {
            calls: std::sync::Mutex::new(calls.into_iter().collect()),
            made: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls_made(&self) -> usize {
        self.made.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl LlmProvider for ScriptedProvider {
    fn id(&self) -> &str {
        "scripted"
    }

    async fn stream(
        &self,
        _req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        self.made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let next = self.calls.lock().unwrap().pop_front();
        match next {
            None => Err(ProviderError::InvalidRequest {
                msg: "scripted provider ran out of calls".to_string(),
            }),
            Some(ScriptedCall::CallFails(e)) => Err(e),
            Some(ScriptedCall::Streams(events)) => {
                Ok(Box::pin(stream::iter(events.into_iter().map(Ok))))
            }
            Some(ScriptedCall::StreamsThenFails(events, e)) => {
                let head: Vec<Result<StreamEvent, ProviderError>> =
                    events.into_iter().map(Ok).collect();
                Ok(Box::pin(
                    stream::iter(head).chain(stream::once(async move { Err(e) })),
                ))
            }
        }
    }
}

/// 固定する性質:
/// - `TurnStarted`はプロバイダ呼び出しごとに1回（ツール継続ターンも含めて計2回）
/// - `TurnCompleted`は**ツール呼び出しが無かった最終ターンでだけ**1回（継続ターンでは出ない）
/// - `ToolCallProposed`→`ToolStarted`→`ToolFinished`がこの順で対になる
#[tokio::test]
async fn agent_event_sequence_for_tool_turn_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();

    let provider = MockProvider::new(vec![
        tool_use_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "greeting.txt" }),
        ),
        end_turn("The file says: hello world"),
    ]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("read greeting.txt and tell me what it says");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec![
            "TurnStarted",
            "ToolCallProposed",
            "ToolStarted",
            "ToolFinished",
            "TurnStarted",
            "TextDelta",
            "TurnCompleted",
        ],
        "agent event sequence changed"
    );
}

/// `ContextTooLong`のリアクティブ圧縮（`run_agent_loop`のみが持つ経路）。
/// 固定する性質: 圧縮を挟んで再試行しても`TurnStarted`は**1回だけ**で、`ContextCompacted`が
/// その間に1回出る。プロバイダは「本題→要約→再試行」の3回呼ばれる。
#[tokio::test]
async fn context_too_long_compacts_once_without_second_turn_started() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![
        ScriptedCall::CallFails(ProviderError::ContextTooLong),
        ScriptedCall::Streams(end_turn("summary of earlier turns")),
        ScriptedCall::Streams(end_turn("done")),
    ]);

    // 圧縮できるだけの外部ユーザターン境界（3件）を用意する。既定の`keep_recent_turns`=2 で
    // 先頭2メッセージが要約1件へ置き換わる。
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("turn1");
    state.messages.push(Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text("reply1".to_string())],
    });
    state.push_user_text("turn2");
    state.messages.push(Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text("reply2".to_string())],
    });
    state.push_user_text("turn3");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "done");
    assert_eq!(provider.calls_made(), 3);
    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec![
            "TurnStarted",
            "ContextCompacted",
            "TextDelta",
            "TurnCompleted"
        ],
        "compaction retry must not re-emit TurnStarted"
    );
}

/// 上の対照。`ContextTooLong`がストリーム開始**後**（受信中）に届いた場合は圧縮せず、
/// `Error`を出してそのまま`Err`で返る。リファクタ後もこの非対称性を保つ必要がある
/// （圧縮リトライはストリーム開始前の失敗にだけ効く）。
#[tokio::test]
async fn context_too_long_mid_stream_does_not_compact() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![ScriptedCall::StreamsThenFails(
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text,
            },
            StreamEvent::TextDelta {
                index: 0,
                text: "partial".to_string(),
            },
        ],
        ProviderError::ContextTooLong,
    )]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("turn1");
    state.messages.push(Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text("reply1".to_string())],
    });
    state.push_user_text("turn2");
    state.messages.push(Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text("reply2".to_string())],
    });
    state.push_user_text("turn3");
    let messages_before = state.messages.len();

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

    let result = run_agent_loop(
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
        Some(&events_tx),
        None,
        |_| {},
    )
    .await;

    assert!(matches!(result, Err(ProviderError::ContextTooLong)));
    assert_eq!(
        provider.calls_made(),
        1,
        "mid-stream failure must not trigger the compaction summary call"
    );
    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec!["TurnStarted", "TextDelta", "Error"],
    );
    assert_eq!(
        state.messages.len(),
        messages_before,
        "a failed turn must not push a partial assistant message"
    );
}

// --- 予防的縮約（使用率トリガ、`plans/PLAN-COMPACTION.md`） ---

/// `tool_use`と対になる`tool_result`を持つ1ターン分のメッセージ列。
fn tool_round(id: &str, result_chars: usize) -> Vec<Message> {
    vec![
        Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: id.to_string(),
                name: "read_file".to_string(),
                input: serde_json::json!({}),
            }],
        },
        Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: id.to_string(),
                content: "x".repeat(result_chars),
                is_error: false,
            }],
        },
    ]
}

fn tool_result_lengths(state: &ConversationState) -> Vec<usize> {
    state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolResult { content, .. } => Some(content.chars().count()),
            _ => None,
        })
        .collect()
}

/// 予防的縮約は**ターン開始前**に走る。固定する性質は2つ。
///
/// 1. イベント順が `ContextShrunk` → `ContextCompacted` → `TurnStarted`。①（切詰め）を②（要約）
///    より先に試し、どちらも`TurnStarted`より前に出る（`estimated_input_tokens`が縮約後の値に
///    なり、TUI表示と実送信量が一致する）。
/// 2. リアクティブ経路（`ContextTooLong`捕捉）とは順序が逆になる——あちらは`TurnStarted`の**後**。
#[tokio::test]
async fn the_usage_trigger_shrinks_then_summarizes_before_the_turn_starts() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![
        // ②ローリング要約のコール（①だけでは目標に届かない）。
        ScriptedCall::Streams(end_turn("summary of earlier turns")),
        // 本題のターン。
        ScriptedCall::Streams(end_turn("done")),
    ]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("t1");
    state.messages.extend(tool_round("call_1", 8_000));
    state.push_user_text("t2");
    state.messages.extend(tool_round("call_2", 8_000));
    state.push_user_text("t3");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
            // 実`n_ctx`が小さいローカルモデル相当。閾値500トークン・目標300トークン。
            compaction: harness_engine::compaction::CompactionPolicy {
                trigger_ratio: 0.5,
                target_ratio: 0.3,
                context_window: 1_000,
            },
            degeneracy: None,
        },
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "done");
    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec![
            "ContextShrunk",
            "ContextCompacted",
            "TurnStarted",
            "TextDelta",
            "TurnCompleted"
        ],
        "preventive compaction must run (and be reported) before the turn starts"
    );
}

/// 後方互換。既定ポリシー（クラウド既定 0.85/0.6・200,000）では、通常サイズの履歴で
/// 使用率トリガが**発火しない**。M13で固定したバイト等価性がこの機構の追加で崩れないこと。
#[tokio::test]
async fn the_default_policy_does_not_fire_on_an_ordinary_history() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![ScriptedCall::Streams(end_turn("done"))]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("t1");
    state.messages.extend(tool_round("call_1", 8_000));
    state.push_user_text("t2");
    state.messages.extend(tool_round("call_2", 8_000));
    state.push_user_text("t3");
    let before = state.messages.len();

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(
        provider.calls_made(),
        1,
        "no summary call may be made when the trigger does not fire"
    );
    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec!["TurnStarted", "TextDelta", "TurnCompleted"],
    );
    assert_eq!(
        tool_result_lengths(&state),
        vec![8_000, 8_000],
        "history must be left byte-identical"
    );
    // 追加されたのはassistantの応答1件だけ。
    assert_eq!(state.messages.len(), before + 1);
}

/// リアクティブ経路のフォールバック。要約できる形でない（外部ユーザターンが1件しか無い）ため
/// `compact`は0を返すが、**諦める前に保護なしの深い切詰めを1回だけ試す**。
/// これが無いと「直近ターンだけで超過している」状況で必ずエラーになっていた。
#[tokio::test]
async fn a_reactive_failure_that_cannot_be_summarized_falls_back_to_shrinking() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![
        ScriptedCall::CallFails(ProviderError::ContextTooLong),
        ScriptedCall::Streams(end_turn("done")),
    ]);

    // 外部ユーザターンは1件だけ＝`compact`は要約コールを打たずに0を返す。
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("t1");
    state.messages.extend(tool_round("call_1", 8_000));

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "done");
    assert_eq!(
        provider.calls_made(),
        2,
        "the summary call must be skipped when there is nothing to summarize"
    );
    assert_eq!(
        drain_event_kinds(&mut events_rx),
        vec!["TurnStarted", "ContextShrunk", "TextDelta", "TurnCompleted"],
        "the reactive fallback reports the truncation and retries without a second TurnStarted"
    );
    let lengths = tool_result_lengths(&state);
    assert!(lengths[0] < 8_000, "tool_result must have been truncated");
}

/// 振動防止。閾値を超えたまま複数ターン回っても、**②ローリング要約は1回の`run_agent_loop`で
/// 高々1回**しか打たれない。
///
/// `plans/PLAN-COMPACTION.md`が当初指定していた「削減量が0なら履歴が伸びるまで再試行しない」と
/// いう長さベースのクールダウンは、このループが毎周回で必ずメッセージを増やす（assistant応答＋
/// `tool_result`）ため構造的に一度も成立しない。実際に止めたいのは「①が少しだけ削って目標に
/// 届かず、毎ターン②の要約コールを打つ」形の振動であり、①が成功している限り長さでは止まらない。
#[tokio::test]
async fn the_rolling_summary_runs_at_most_once_per_agent_loop() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), "x".repeat(20_000)).unwrap();

    let provider = ScriptedProvider::new(vec![
        // ターン1の縮約で打たれる②の要約コール。
        ScriptedCall::Streams(end_turn("summary")),
        // ターン1本体（ツールを呼ぶのでループが続く）。
        ScriptedCall::Streams(tool_use_turn(
            "call_x",
            "read_file",
            serde_json::json!({ "path": "f.txt" }),
        )),
        // ターン2本体。ここで②が再び打たれるなら、この台本は使い切られて panic する。
        ScriptedCall::Streams(end_turn("done")),
    ]);

    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("t1");
    state.messages.extend(tool_round("call_1", 8_000));
    state.push_user_text("t2");
    state.messages.extend(tool_round("call_2", 8_000));
    state.push_user_text("t3");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

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
            // 何をどう削っても閾値を下回れない、極端に小さいウィンドウ。
            compaction: harness_engine::compaction::CompactionPolicy {
                trigger_ratio: 0.5,
                target_ratio: 0.3,
                context_window: 1_000,
            },
            degeneracy: None,
        },
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "done");
    assert_eq!(
        provider.calls_made(),
        3,
        "1 summary call + 2 turns; a second summary call would mean oscillation"
    );
    let kinds = drain_event_kinds(&mut events_rx);
    assert_eq!(
        kinds.iter().filter(|k| *k == "ContextCompacted").count(),
        1,
        "the rolling summary must not repeat: {kinds:?}"
    );
}

// --- 縮退ガード（M21、`plans/DESIGN-COGNITION.md` §11） ---
//
// 検知器・ゲート・梯子の判定式そのものは`harness-engine`の`degeneracy`モジュール内の
// 単体テストが固定している。ここで固定するのは**エージェントループとの繋がり**——
// 捨てた出力が履歴に残らないこと、再送で正常完了できること、使い切ったら畳むこと、
// そして**正常な応答では一切発火しないこと**。

/// 縮退したストリーム（`？`の反復で`MaxTokens`到達）。`forced-repeat`プロンプトに対して
/// LMStudio実機が返したのと同じ形（`tools/lmstudio_mgmt_probe.py`の実測結果、2026-08-04）。
fn degenerate_turn() -> Vec<StreamEvent> {
    let mut events = vec![StreamEvent::BlockStart {
        index: 0,
        kind: BlockKind::Thinking,
    }];
    // 1デルタ64文字 × 16 = 1,024文字。①の窓（512）と評価の刻みを確実に跨ぐ。
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

fn drain_events(rx: &mut tokio::sync::mpsc::UnboundedReceiver<AgentEvent>) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn discard_rungs(events: &[AgentEvent]) -> Vec<Option<String>> {
    events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::TurnDiscarded { next_rung, .. } => Some(next_rung.clone()),
            _ => None,
        })
        .collect()
}

/// **M21の受入条件**: 縮退した回は履歴に残らず、再送で正常完了する。
#[tokio::test]
async fn a_degenerate_turn_is_discarded_and_the_retry_completes_normally() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![degenerate_turn(), end_turn("落ち着いて答えます")]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("こんにちは");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

    let outcome = run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        guarded_config(),
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(outcome.text, "落ち着いて答えます");
    assert_eq!(outcome.stop_reason, StopReason::EndTurn);

    // 縮退分の痕跡が履歴に一切残らない（user発話 + 再送のassistantのみ）。
    assert_eq!(state.messages.len(), 2, "{:?}", state.messages);
    let history = serde_json::to_string(&state.messages).unwrap();
    assert!(
        !history.contains('\u{ff1f}'),
        "捨てた本文が履歴に残っている: {history}"
    );

    let events = drain_events(&mut events_rx);
    let discards = discard_rungs(&events);
    assert_eq!(discards, vec![Some("jitter".to_string())], "{events:?}");
    assert!(events.iter().any(|e| matches!(
        e,
        AgentEvent::TurnDiscarded {
            kind: harness_core::DegenerateKind::ShortPeriodRepeat,
            ..
        }
    )));
}

/// 梯子を使い切ったら fail-closed で畳む。履歴は呼び出し前と同一のまま。
#[tokio::test]
async fn exhausting_the_ladder_folds_the_turn_without_touching_history() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new((0..8).map(|_| degenerate_turn()).collect());
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("こんにちは");
    let before = state.messages.clone();
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

    let outcome = run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        guarded_config(),
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.stop_reason,
        StopReason::Other("degenerate_output".to_string())
    );
    assert!(outcome.text.is_empty());
    assert!(!outcome.cancelled, "縮退はキャンセルとは別の畳み方");
    assert_eq!(state.messages, before, "履歴を一切触らない");

    let events = drain_events(&mut events_rx);
    // (b)を2回・(c)を2回試して諦める。`auto_recycle`は既定OFFなので (d) を飛ばして (f) へ。
    assert_eq!(
        discard_rungs(&events),
        vec![
            Some("jitter".to_string()),
            Some("jitter_with_notice".to_string()),
            Some("jitter_with_notice".to_string()),
            None,
        ],
        "{events:?}"
    );
    // `max_turns`超過のエラーにはならない（回復予算と進捗予算を混ぜない、§11.3）。
    assert!(
        !events.iter().any(|e| matches!(e, AgentEvent::Error { .. })),
        "{events:?}"
    );
}

/// **誤検知してはならない**: 正常な応答では`TurnDiscarded`が1件も出ず、
/// 出力も履歴もガード無しのときと変わらない。
#[tokio::test]
async fn a_healthy_turn_is_untouched_by_the_guard() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("greeting.txt"), "hello world").unwrap();
    let script = || {
        vec![
            tool_use_turn(
                "call_1",
                "read_file",
                serde_json::json!({ "path": "greeting.txt" }),
            ),
            end_turn("The file says: hello world"),
        ]
    };
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut with_guard = ConversationState::new(Vec::new());
    with_guard.push_user_text("read greeting.txt");
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    let guarded = run_agent_loop(
        &MockProvider::new(script()),
        &mut with_guard,
        &tools,
        &ctx,
        &arbiter,
        guarded_config(),
        Some(&events_tx),
        None,
        |_| {},
    )
    .await
    .unwrap();

    let mut without_guard = ConversationState::new(Vec::new());
    without_guard.push_user_text("read greeting.txt");
    let plain = run_agent_loop(
        &MockProvider::new(script()),
        &mut without_guard,
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
    .unwrap();

    assert_eq!(guarded.text, plain.text);
    assert_eq!(guarded.stop_reason, plain.stop_reason);
    assert_eq!(
        with_guard.messages, without_guard.messages,
        "履歴もガード無しと等価"
    );
    assert!(
        !drain_events(&mut events_rx)
            .iter()
            .any(|e| matches!(e, AgentEvent::TurnDiscarded { .. })),
        "正常な応答で発火してはならない"
    );
}

/// text形式の区切りマーカーが「捨てた可視バイト数」を正しく運ぶ
/// （§11.4「下流は自分のバッファを末尾から`n`バイト切り詰めよ」）。
#[tokio::test]
async fn the_text_marker_lets_the_downstream_rewind_exactly() {
    let dir = tempfile::tempdir().unwrap();
    // 本文を流してから縮退する台本（可視バイトが0でないケース）。
    let mut degenerate_with_text = vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: "途中まで書いた".to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::Thinking,
        },
    ];
    for _ in 0..16 {
        degenerate_with_text.push(StreamEvent::ThinkingDelta {
            index: 1,
            text: "\u{ff1f}".repeat(64),
        });
    }
    degenerate_with_text.push(StreamEvent::Done {
        stop_reason: StopReason::MaxTokens,
        usage: Usage::default(),
    });

    let provider = MockProvider::new(vec![degenerate_with_text, end_turn("最終回答")]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("やって");
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

    let mut sink = String::new();
    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        guarded_config(),
        None,
        None,
        |d| sink.push_str(d),
    )
    .await
    .unwrap();

    let discarded = "途中まで書いた";
    let marker = harness_core::discarded_marker(
        harness_core::DegenerateKind::ShortPeriodRepeat.as_str(),
        discarded.len() as u64,
    );
    assert_eq!(sink, format!("{discarded}{marker}最終回答"));

    // 下流の復元手順そのもの: マーカーを取り除き、`bytes`ぶん末尾を切り詰める。
    let (head, rest) = sink.split_once('\x1e').unwrap();
    let (m, tail) = rest.split_once('\n').unwrap();
    let bytes: usize = m
        .split("bytes=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        &head[..head.len() - bytes],
        "",
        "捨てた範囲を過不足なく復元できる"
    );
    assert_eq!(tail, "最終回答");
}

/// BUG-075: ターンの最中に圧縮が走ると`state.messages`の**先頭が畳まれる**ため、
/// ターン前に控えた生の添字は`messages`の長さを超えてスライスをパニックさせる。
/// `ConversationState::mark`/`since`はその読み替えを行い、**このターンで増えた分だけ**を返す。
///
/// 修正前の`&state.messages[before..]`は実測で
/// `range start index 11 out of range for slice of length 5`でパニックした
/// （TUIではengineタスクが死んでイベント経路が閉じ、TUIごと落ちる）。
#[tokio::test]
async fn a_compaction_inside_the_turn_does_not_break_the_session_append_slice() {
    let dir = tempfile::tempdir().unwrap();
    let provider = ScriptedProvider::new(vec![
        ScriptedCall::CallFails(ProviderError::ContextTooLong),
        ScriptedCall::Streams(end_turn("summary of earlier turns")),
        ScriptedCall::Streams(end_turn("done")),
    ]);

    // 圧縮で大きく畳めるだけの履歴（5往復）を用意する。
    let mut state = ConversationState::new(Vec::new());
    for i in 0..5 {
        state.push_user_text(format!("turn{i}"));
        state.messages.push(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text(format!("reply{i}"))],
        });
    }
    // 呼び出し側（`harness-tui::engine`・`harness-cli::run_agent`）と同じ順序:
    // 新しい発話をpushして永続化し、そこへ栞を挟んでからターンを回す。
    state.push_user_text("the new prompt");
    let mark = state.mark();
    assert_eq!(state.messages.len(), 11);

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

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
    .unwrap();

    // 圧縮で履歴は縮んでいる（＝控えた添字11はもう使えない）。
    assert!(
        state.messages.len() < 11,
        "この検証は圧縮が実際に起きることが前提: {}",
        state.messages.len()
    );

    // セッションJSONLへ追記されるのはこのターンで増えた分だけ——assistantの応答1件。
    let appended = state.since(mark);
    assert_eq!(appended.len(), 1, "{appended:?}");
    assert_eq!(appended[0].role, Role::Assistant);
    assert_eq!(
        appended[0].content,
        vec![ContentBlock::Text("done".to_string())]
    );
}

/// 圧縮が起きなければ`since`は素直に「控えた位置以降」を返す（読み替えが常時働いて
/// 余計にずらす、という逆向きの壊れ方をしないこと）。
#[test]
fn without_compaction_the_mark_behaves_like_a_plain_index() {
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("a");
    let mark = state.mark();
    assert!(state.since(mark).is_empty());

    state.push_user_text("b");
    state.push_user_text("c");
    let since = state.since(mark);
    assert_eq!(since.len(), 2);
    assert_eq!(since[0].content, vec![ContentBlock::Text("b".to_string())]);
}
