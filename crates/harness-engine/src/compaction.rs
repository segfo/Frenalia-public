//! コンテキスト圧縮（M9）。`plans/DESIGN.md` L349「コンテキスト圧縮（tool_useとtool_resultの
//! ペアを絶対に分割しない・直近ターンは逐語保持・thinking/redacted_thinkingは改変しない・
//! `/compact`で手動起動、`ProviderError::ContextTooLong`のリアクティブ経路も）」を実装する。
//!
//! **スコープ判断**: プロアクティブ（トークン使用率ベースの自動発火）圧縮は見送り、
//! `/compact`手動起動とリアクティブ経路（`run_agent_loop`が`ContextTooLong`を受け取った際）の
//! 2経路のみをサポートする（設計書の「手動起動、...のリアクティブ経路も」の字義通り）。

use futures::StreamExt;

use harness_core::{
    CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role, Sampling,
    StreamEvent, ToolChoice,
};

use crate::ConversationState;

/// `/compact`が特に指定しない場合の既定値: 直近2つの外部ユーザターンは逐語保持する。
pub const DEFAULT_KEEP_RECENT_TURNS: usize = 2;

const COMPACTION_MAX_TOKENS: u32 = 1024;
const COMPACTION_INSTRUCTION: &str = "Summarize the conversation so far concisely, \
preserving all facts, decisions, file paths, and open tasks that would be needed to continue \
the work. Output only the summary text.";

/// `messages`中で「外部ユーザプロンプトの開始点」であるインデックス列を返す。
/// ツール結果を運ぶ`Role::User`メッセージは`ContentBlock::ToolResult`を含み、
/// `push_user_text`が積む純粋なテキスト1ブロックのメッセージとは形が異なるため区別できる
/// （`ConversationState`にターン境界メタデータを別途持たせる必要がない）。
pub fn turn_boundaries(messages: &[Message]) -> Vec<usize> {
    messages
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let is_external_prompt = m.role == Role::User
                && m.content.len() == 1
                && matches!(m.content[0], ContentBlock::Text(_));
            is_external_prompt.then_some(i)
        })
        .collect()
}

/// 直近`keep_recent_turns`件の外部ユーザターンより前のメッセージを、provider呼び出し1回で
/// 生成した要約1メッセージに置き換える。カット位置は必ずターン境界（=ターン先頭）なので、
/// ターン内部のtool_use/tool_resultペアが分割されることはない。保持される直近ターンの内容は
/// 一切改変しない（thinking/redacted_thinkingも含め無傷のまま残る）。カットされる側の
/// thinking/redacted_thinkingは要約に取り込まず単純に破棄する（要約後は二度とプロバイダへ
/// 送らないため「無改変で往復」の対象外）。
///
/// 圧縮対象が無ければ（ターン境界が`keep_recent_turns`件以下）何もせず`Ok(0)`を返す。
pub async fn compact(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    model: &str,
    keep_recent_turns: usize,
) -> Result<usize, ProviderError> {
    let boundaries = turn_boundaries(&state.messages);
    if boundaries.len() <= keep_recent_turns {
        return Ok(0);
    }
    let cut = boundaries[boundaries.len() - keep_recent_turns];
    if cut == 0 {
        return Ok(0);
    }

    let mut to_summarize = state.messages[..cut].to_vec();
    to_summarize.push(Message {
        role: Role::User,
        content: vec![ContentBlock::Text(COMPACTION_INSTRUCTION.to_string())],
    });

    let mut req = CompletionRequest {
        system: state.system.clone(),
        messages: to_summarize,
        tools: Vec::new(),
        tool_choice: ToolChoice::None,
        output: None,
        parallel_tool_calls: None,
        max_tokens: COMPACTION_MAX_TOKENS,
        sampling: Sampling::default(),
        model: model.to_string(),
    };
    if req
        .system
        .iter()
        .any(|s| s.text.contains("Tier3のLinuxコンテナ実行環境"))
    {
        crate::sanitize_completion_request_for_tier3(&mut req);
    }

    let mut stream = provider.stream(req).await?;
    let mut summary = String::new();
    while let Some(event) = stream.next().await {
        if let StreamEvent::TextDelta { text, .. } = event? {
            summary.push_str(&text);
        }
    }
    if summary.trim().is_empty() {
        summary = "(summary unavailable)".to_string();
    }

    let removed = cut;
    let mut new_messages = vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text(format!(
            "[compacted summary of {removed} earlier messages]\n{summary}"
        ))],
    }];
    new_messages.extend(state.messages.drain(cut..));
    state.messages = new_messages;

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConversationState;
    use harness_core::{BlockKind, StopReason, Usage};
    use std::sync::Mutex;

    struct MockProvider {
        turns: Mutex<Vec<Vec<StreamEvent>>>,
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }
        async fn stream(
            &self,
            _req: CompletionRequest,
        ) -> Result<futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>
        {
            let mut turns = self.turns.lock().unwrap();
            let events = turns.remove(0);
            Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
        }
    }

    fn summary_turn(text: &str) -> Vec<StreamEvent> {
        vec![
            StreamEvent::BlockStart { index: 0, kind: BlockKind::Text },
            StreamEvent::TextDelta { index: 0, text: text.to_string() },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done { stop_reason: StopReason::EndTurn, usage: Usage::default() },
        ]
    }

    fn user_turn(text: &str) -> Message {
        Message { role: Role::User, content: vec![ContentBlock::Text(text.to_string())] }
    }

    fn assistant_text(text: &str) -> Message {
        Message { role: Role::Assistant, content: vec![ContentBlock::Text(text.to_string())] }
    }

    #[tokio::test]
    async fn compacts_old_turns_and_keeps_recent_verbatim() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("turn1"));
        state.messages.push(assistant_text("reply1"));
        state.messages.push(user_turn("turn2"));
        state.messages.push(assistant_text("reply2"));
        state.messages.push(user_turn("turn3"));
        state.messages.push(assistant_text("reply3"));

        let provider = MockProvider { turns: Mutex::new(vec![summary_turn("summary of turn1/turn2")]) };

        let removed = compact(&provider, &mut state, "mock-model", 1).await.unwrap();

        assert_eq!(removed, 4);
        assert_eq!(state.messages.len(), 3);
        match &state.messages[0].content[0] {
            ContentBlock::Text(t) => assert!(t.contains("summary of turn1/turn2")),
            other => panic!("expected summary text, got {other:?}"),
        }
        // 直近ターン（turn3/reply3）は逐語のまま残る。
        assert_eq!(state.messages[1], user_turn("turn3"));
        assert_eq!(state.messages[2], assistant_text("reply3"));
    }

    #[tokio::test]
    async fn no_op_when_not_enough_turns_to_compact() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("turn1"));
        state.messages.push(assistant_text("reply1"));

        let provider = MockProvider { turns: Mutex::new(vec![]) };
        let removed = compact(&provider, &mut state, "mock-model", 2).await.unwrap();

        assert_eq!(removed, 0);
        assert_eq!(state.messages.len(), 2);
    }

    #[test]
    fn turn_boundaries_ignores_tool_result_user_messages() {
        let messages = vec![
            user_turn("hi"),
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({}),
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            },
            assistant_text("done"),
            user_turn("next"),
        ];
        assert_eq!(turn_boundaries(&messages), vec![0, 4]);
    }
}
