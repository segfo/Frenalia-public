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

    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None);
    let executor: &dyn Executor = &executor;

    let result = executor
        .raw_turn(RawTurnRequest {
            req: minimal_request(&tools, &ctx, "read greeting.txt"),
        })
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

    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None);
    let executor: &dyn Executor = &executor;

    let result = executor
        .raw_turn(RawTurnRequest {
            req: minimal_request(&tools, &ctx, "run a shell command"),
        })
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
