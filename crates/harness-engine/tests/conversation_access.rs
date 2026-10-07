//! 道具が会話を読む口（`Tool::call_in_conversation`）の通し試験（D-127）。
//!
//! 守りたいのは、**会話が道具へ渡るのは、値の置き場が本物の会話から組まれたときだけ**であること。
//! 素朴ループのターン（送る文がそのまま会話）と、呼び出し側が会話から組んだ置き場を渡したターンでは渡り、
//! 認知レイヤーのように組み直した文を送るターンでは渡らない。あわせて、口を足しても**判定が先に走る**ことを見る。

use std::sync::Arc;

use async_trait::async_trait;
use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, Message, PermissionSubject, RiskClass, Role,
    Sampling, StopReason, StreamEvent, Tool, ToolChoice, ToolCtx, ToolError, ToolOutput, Usage,
};
use harness_engine::{
    Executor, PermissionArbiter, PermissionMode, RawTurnRequest, RawTurnResult, References,
    ToolCallDecision, TurnExecutor,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

/// 渡された会話の長さを返すだけの道具。会話が渡らなければ`NO_CONVERSATION`。
struct ConversationProbe;

const PROBE: &str = "conversation_probe";
const NO_CONVERSATION: &str = "no conversation";

#[async_trait]
impl Tool for ConversationProbe {
    fn name(&self) -> &str {
        PROBE
    }
    fn description(&self) -> &str {
        "test probe"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {}, "additionalProperties": false })
    }
    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::ReadOnly
    }
    async fn permission_subject(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        Ok(PermissionSubject::Text(PROBE.to_string()))
    }
    async fn call(
        &self,
        _input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: NO_CONVERSATION.to_string(),
            is_error: false,
        })
    }
    async fn call_in_conversation(
        &self,
        input: serde_json::Value,
        ctx: &ToolCtx,
        conversation: Option<&[Message]>,
    ) -> Result<ToolOutput, ToolError> {
        match conversation {
            Some(messages) => Ok(ToolOutput {
                content: format!("conversation of {} messages", messages.len()),
                is_error: false,
            }),
            None => self.call(input, ctx).await,
        }
    }
}

fn probe_call() -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: PROBE.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: "{}".to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
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

fn request(messages: Vec<Message>) -> CompletionRequest {
    CompletionRequest {
        system: Vec::new(),
        messages,
        tools: Vec::new(),
        tool_choice: ToolChoice::Auto,
        output: None,
        parallel_tool_calls: Some(false),
        max_tokens: 100,
        sampling: Sampling::default(),
        model: "mock".into(),
    }
}

/// `make`で組んだ1ステップを回し、探り道具の結果（と顛末）を返す。
async fn probe_output(
    mode: PermissionMode,
    make: impl FnOnce(CompletionRequest) -> RawTurnRequest,
) -> (String, ToolCallDecision) {
    let dir = tempfile::tempdir().unwrap();
    let provider = MockProvider::new(vec![probe_call()]);
    let mut tools = ToolRegistry::with_builtin_tools();
    tools.register(Arc::new(ConversationProbe));
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(mode, vec![], dir.path());
    let executor = TurnExecutor::new(&provider, &tools, &ctx, &arbiter, None, None, None);
    let executor: &dyn Executor = &executor;

    let result = executor
        .raw_turn(make(request(vec![user("送る文")])))
        .await
        .unwrap();
    let RawTurnResult::Completed(raw) = result else {
        panic!("expected a completed turn");
    };
    let call = &raw.tool_calls[0];
    (call.output.content.clone(), call.decision)
}

/// 素朴ループのターン: 送る文がそのまま会話なので、会話が渡る。
#[tokio::test]
async fn a_user_facing_turn_hands_the_conversation_to_the_tool() {
    let (output, decision) =
        probe_output(PermissionMode::Default, RawTurnRequest::user_facing).await;
    assert_eq!(decision, ToolCallDecision::Executed);
    assert_eq!(output, "conversation of 1 messages");
}

/// 対: 認知レイヤーのターン（組み直した文を送る）は、送る文を会話として渡さない。
#[tokio::test]
async fn an_internal_turn_does_not_pass_its_request_off_as_the_conversation() {
    let (output, decision) = probe_output(PermissionMode::Default, RawTurnRequest::internal).await;
    assert_eq!(decision, ToolCallDecision::Executed);
    assert_eq!(output, NO_CONVERSATION);
}

/// 認知レイヤーのターンでも、呼び出し側が**会話から**組んだ置き場を渡したなら、その会話が渡る
/// （送る文ではなく、渡した会話——長さで見分ける）。
#[tokio::test]
async fn an_internal_turn_with_references_built_from_the_conversation_passes_that_conversation() {
    let conversation = vec![user("1つ目"), user("2つ目"), user("3つ目")];
    let references = Arc::new(References::from_conversation(&conversation));
    let (output, _) = probe_output(PermissionMode::Default, |req| {
        RawTurnRequest::internal(req).with_references(references)
    })
    .await;
    assert_eq!(output, "conversation of 3 messages");

    // 対: 送る文から組んだだけの置き場を渡しても、会話は渡らない。
    let from_request = Arc::new(References::from_messages(&conversation));
    let (output, _) = probe_output(PermissionMode::Default, |req| {
        RawTurnRequest::internal(req).with_references(from_request)
    })
    .await;
    assert_eq!(output, NO_CONVERSATION);
}

/// 口を足しても**判定が先に走る**: 拒否のモードでは、読むだけの道具でも呼ばれない。
#[tokio::test]
async fn the_permission_gate_still_runs_before_the_tool() {
    let (output, decision) = probe_output(PermissionMode::Deny, RawTurnRequest::user_facing).await;
    assert_eq!(decision, ToolCallDecision::DeniedByPolicy);
    assert!(
        output.starts_with(harness_engine::DENIAL_PREFIX),
        "{output}"
    );
}
