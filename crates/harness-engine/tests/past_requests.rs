//! 前の文を読む道具 `past_requests` の通し試験（D-127 の3）。
//!
//! 守りたいのは、ユーザーが「もう一度」と頼んだときの道筋がエンジンを通して成り立つこと——
//! モデルが一覧と詳細を読み（**値の中身は出ない**）、そこで見た`{{back:1:1}}`を書くと、
//! ハーネスが**1つ前の文の値**へ置き換える。対として、認知レイヤーの経路（組み直した文を送るターン）では
//! 会話が渡らないので「使えない」と返る。

use std::sync::Arc;

use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, Message, Role, Sampling, StopReason,
    StreamEvent, ToolChoice, ToolCtx, Usage,
};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, Executor, PastRequestsTool,
    PermissionArbiter, PermissionMode, RawTurnRequest, RawTurnResult, ToolCallDecision,
    TurnExecutor,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

/// 害の無い長い値（16進64文字）。1つ前の文に貼られていたもの。
const OLD_VALUE: &str = "68a6c881d3b8c53b6993df896c90fe4a5883c2043af594280274a09f5ed14a3d";

fn tool_call(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
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

fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

/// 1つ前の文で値を貼って走らせ、いまの文は「もう一度」だけの会話（D-127 の決定の例と同じ形）。
/// モデルの前の呼び出しは書いたまま（`{{val:1}}`）履歴に残っている（D-113）。
fn history() -> Vec<Message> {
    vec![
        user(&format!("これを実行して echo {OLD_VALUE}")),
        Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "old".into(),
                name: "run_shell".into(),
                input: serde_json::json!({ "command": "echo {{val:1}}" }),
            }],
        },
        Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "old".into(),
                content: "ok".into(),
                is_error: false,
            }],
        },
        Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text("実行しました".into())],
        },
        user("もう一度撃って"),
    ]
}

fn tools() -> ToolRegistry {
    let mut tools = ToolRegistry::with_builtin_tools();
    tools.register(Arc::new(PastRequestsTool));
    tools
}

/// `id`のツールの結果（会話に積まれたもの）。
fn result_of(messages: &[Message], id: &str) -> (String, bool) {
    messages
        .iter()
        .flat_map(|m| &m.content)
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } if tool_use_id == id => Some((content.clone(), *is_error)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no tool_result for {id}"))
}

/// 素朴ループ: 一覧 → 詳細 → `{{back:1:1}}`で撃つ。**撃った行には1つ前の文の値が入り、道具の出力には値が出ない。**
/// 既定のモード（承認を聞かない読むだけの道具は通り、`run_shell`はヘッドレスの判定で止まる）で回すので、何も実行されない。
#[tokio::test]
async fn the_model_reads_past_requests_then_points_at_the_old_value() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![
        tool_call("list", "past_requests", serde_json::json!({})),
        tool_call("detail", "past_requests", serde_json::json!({ "back": 1 })),
        tool_call(
            "again",
            "run_shell",
            serde_json::json!({ "command": "echo {{back:1:1}}" }),
        ),
        end_turn(),
    ]);
    let mut state = ConversationState::new(Vec::new());
    state.messages = history();
    let tools = tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![], dir.path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 6,
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&tx),
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");
    drop(tx);
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }

    // 読むだけの道具は承認なしで走り、値の中身を出さない。
    let (listing, listing_error) = result_of(&state.messages, "list");
    assert!(!listing_error, "{listing}");
    assert!(
        listing.contains("K=1: 「これを実行して echo {{back:1:1}}」"),
        "{listing}"
    );
    let (detail, detail_error) = result_of(&state.messages, "detail");
    assert!(!detail_error, "{detail}");
    // 当時`{{val:1}}`と書いた呼び出しは、今から見た綴りで出る。
    assert!(
        detail.contains(r#"{"command":"echo {{back:1:1}}"}"#),
        "{detail}"
    );
    for output in [&listing, &detail] {
        assert!(!output.contains(&OLD_VALUE[..20]), "{output}");
        assert!(!output.contains(&OLD_VALUE[40..]), "{output}");
    }

    // 撃った行は1つ前の文の値へ置き換わって判定へ回った（`ToolCallProposed`は差し込んだ後の入力）。
    let proposed: Vec<&serde_json::Value> = events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::ToolCallProposed { name, input, .. } if name == "run_shell" => Some(input),
            _ => None,
        })
        .collect();
    assert_eq!(
        proposed,
        vec![&serde_json::json!({ "command": format!("echo {OLD_VALUE}") })]
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            AgentEvent::BackReferenceUsed {
                back: 1,
                number: 1,
                ..
            }
        )),
        "前の文の値を差し込んだ記録が無い"
    );
}

/// 対: 認知レイヤーの経路（送る文は組み直したもの・置き場を渡していない）では、会話が渡らないので「使えない」と返す。
#[tokio::test]
async fn an_internal_turn_gets_the_unavailable_error() {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![tool_call(
        "list",
        "past_requests",
        serde_json::json!({}),
    )]);
    let tools = tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![], dir.path());
    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None, None);
    let executor: &dyn Executor = &executor;

    let request = CompletionRequest {
        system: Vec::new(),
        messages: history(),
        tools: Vec::new(),
        tool_choice: ToolChoice::Auto,
        output: None,
        parallel_tool_calls: Some(false),
        max_tokens: 100,
        sampling: Sampling::default(),
        model: "mock".into(),
    };
    let RawTurnResult::Completed(raw) = executor
        .raw_turn(RawTurnRequest::internal(request))
        .await
        .unwrap()
    else {
        panic!("expected a completed turn");
    };
    let call = &raw.tool_calls[0];
    // 判定は通っている（読むだけ）。道具が会話を受け取れずに断った。
    assert_eq!(call.decision, ToolCallDecision::Executed);
    assert!(call.output.is_error, "{}", call.output.content);
    assert!(
        call.output.content.contains("まだ使えません"),
        "{}",
        call.output.content
    );
}
