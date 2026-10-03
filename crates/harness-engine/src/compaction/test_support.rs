//! 縮約モジュールのテストが共有するスクリプトproviderとメッセージ組み立て（`#[cfg(test)]`のみ）。
//!
//! [`summarize`](super::summarize)と[`manual`](super::manual)の両方が同じ形のモックを要るため、
//! `docs/CODE-STRUCTURE-RULES.md`規則5に従いコピーを作らずここへ置く。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use futures::stream::BoxStream;
use tokio_util::sync::CancellationToken;

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role,
    StopReason, StreamEvent, Usage,
};

/// 用意した応答を順に返すprovider。失敗・キャンセルの差し込みもできる。
pub struct MockProvider {
    turns: Mutex<Vec<Vec<StreamEvent>>>,
    calls: AtomicUsize,
    /// `Some(n)`なら`n`回目（0始まり）以降のコールを[`ProviderError::Overloaded`]で失敗させる。
    fail_from: Option<usize>,
    /// `n`回目のコールを処理する時点でこのトークンを発火させる（Escを押した瞬間の再現）。
    cancel_at: Option<(CancellationToken, usize)>,
    /// 受け取った要求の`max_tokens`（呼ばれた順）。
    max_tokens_seen: Mutex<Vec<u32>>,
}

impl MockProvider {
    pub fn new(turns: Vec<Vec<StreamEvent>>) -> Self {
        Self {
            turns: Mutex::new(turns),
            calls: AtomicUsize::new(0),
            fail_from: None,
            cancel_at: None,
            max_tokens_seen: Mutex::new(Vec::new()),
        }
    }

    pub fn failing_from(turns: Vec<Vec<StreamEvent>>, fail_from: usize) -> Self {
        Self {
            fail_from: Some(fail_from),
            ..Self::new(turns)
        }
    }

    pub fn cancelling_at(
        turns: Vec<Vec<StreamEvent>>,
        token: CancellationToken,
        call: usize,
    ) -> Self {
        Self {
            cancel_at: Some((token, call)),
            ..Self::new(turns)
        }
    }

    pub fn calls_made(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// 受け取った要求の`max_tokens`を呼ばれた順に返す。
    pub fn max_tokens_seen(&self) -> Vec<u32> {
        self.max_tokens_seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        self.max_tokens_seen.lock().unwrap().push(req.max_tokens);
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((token, at)) = &self.cancel_at {
            if n == *at {
                token.cancel();
            }
        }
        if self.fail_from.is_some_and(|f| n >= f) {
            return Err(ProviderError::Overloaded);
        }
        let mut turns = self.turns.lock().unwrap();
        let events = turns.remove(0);
        Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
    }
}

/// テキスト1ブロックを返して終わるストリーム（要約コール1本ぶんの応答）。
pub fn summary_turn(text: &str) -> Vec<StreamEvent> {
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

/// 外部ユーザプロンプト（`turn_boundaries`が境界と見なす形）。
pub fn user_turn(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

pub fn assistant_text(text: &str) -> Message {
    Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

/// `tool_use`（assistant）と`tool_result`（user）の対。`chars`文字のツール出力を持つ。
pub fn tool_round(id: &str, chars: usize) -> Vec<Message> {
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
                content: "x".repeat(chars),
                is_error: false,
            }],
        },
    ]
}

/// 履歴中の`tool_result`の文字数を並び順に返す。
pub fn tool_result_lengths(messages: &[Message]) -> Vec<usize> {
    messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolResult { content, .. } => Some(content.chars().count()),
            _ => None,
        })
        .collect()
}
