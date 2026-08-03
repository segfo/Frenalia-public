//! テスト用スクリプトプロバイダ。`plans/DESIGN.md` §ワークスペース構成
//! 「mock/（テスト用スクリプトプロバイダ）」参照。
//!
//! `stream()`が呼ばれるたびに、あらかじめ用意した`StreamEvent`列を1ターン分ずつ順番に返す。
//! ワイヤ形式（HTTP/SSE）を一切経由しないため、`harness-engine`のエージェントループを
//! 決定的に駆動できる（§実装マイルストーン M6検証条件「mockプロバイダのgolden-transcriptテスト」）。

use std::path::PathBuf;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::stream::{self, BoxStream};

use harness_core::{
    CompletionRequest, LlmProvider, ProviderCapabilities, ProviderError, StreamEvent,
};

pub struct MockProvider {
    turns: Mutex<Vec<Vec<StreamEvent>>>,
    capabilities: ProviderCapabilities,
    /// `stream()`が受け取った`CompletionRequest`をJSONL(1行1リクエスト)で追記する先。
    /// out-of-process E2Eテスト（`tier2a_e2e.rs`）が、モデルへ実際に何が送信されたかを
    /// 直接assertするための記録経路（BUG-030型のシステムプロンプト未送信を検出する）。
    record_path: Option<PathBuf>,
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
            record_path: None,
        }
    }

    /// `turns`のJSON表現（`Vec<Vec<StreamEvent>>`をそのままシリアライズしたもの）を
    /// ファイルから読んで構築する。CLI（`--mock-turns <path>`）が使う。
    pub fn from_turns_file(path: &std::path::Path) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let turns: Vec<Vec<StreamEvent>> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(turns))
    }

    /// `stream()`が受け取った`CompletionRequest`をこのパスへJSONL追記するようにする。
    pub fn with_request_record_path(mut self, path: PathBuf) -> Self {
        self.record_path = Some(path);
        self
    }

    /// 能力表明を差し替える。`OutputContract`の写像（`harness_core::schema`）は
    /// `ProviderCapabilities`で分岐するため、3戦略（native / ツール強制 / プロンプト埋込）を
    /// テストから踏み分けるのに使う。
    pub fn with_capabilities(mut self, capabilities: ProviderCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    fn id(&self) -> &str {
        "mock"
    }

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        if let Some(path) = &self.record_path {
            if let Ok(line) = serde_json::to_string(&req) {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    use std::io::Write;
                    let _ = writeln!(file, "{line}");
                }
            }
        }

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
