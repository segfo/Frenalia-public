//! テスト用スクリプトプロバイダ。`plans/DESIGN.md` §ワークスペース構成
//! 「mock/（テスト用スクリプトプロバイダ）」参照。
//!
//! `stream()`が呼ばれるたびに、あらかじめ用意した`StreamEvent`列を1ターン分ずつ順番に返す。
//! ワイヤ形式（HTTP/SSE）を一切経由しないため、`harness-engine`のエージェントループを
//! 決定的に駆動できる（§実装マイルストーン M6検証条件「mockプロバイダのgolden-transcriptテスト」）。

use std::sync::Mutex;

use async_trait::async_trait;
use futures::stream::{self, BoxStream};

use harness_core::{CompletionRequest, LlmProvider, ProviderCapabilities, ProviderError, StreamEvent};

pub struct MockProvider {
    turns: Mutex<Vec<Vec<StreamEvent>>>,
    capabilities: ProviderCapabilities,
}

impl MockProvider {
    /// `turns[i]`が`stream()`のi回目の呼び出しで返される`StreamEvent`列。
    pub fn new(turns: Vec<Vec<StreamEvent>>) -> Self {
        Self {
            turns: Mutex::new(turns),
            capabilities: ProviderCapabilities {
                native_json_schema: true,
                forced_tool_choice: true,
                schema_with_thinking: true,
                schema_with_tools: true,
                prompt_caching: false,
                context_window: 200_000,
            },
        }
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    async fn stream(
        &self,
        _req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        let mut turns = self.turns.lock().unwrap();
        if turns.is_empty() {
            return Err(ProviderError::InvalidRequest {
                msg: "mock provider ran out of scripted turns".to_string(),
            });
        }
        let events = turns.remove(0);
        Ok(Box::pin(stream::iter(events.into_iter().map(Ok))))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }
}
