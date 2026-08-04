use std::time::Duration;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::message::Message;
use crate::tool::ToolSpec;

/// 変動点（LLMとのバイト列）を隠す唯一のtrait境界。
/// 開いた集合（プロバイダ）なので trait object（`Box<dyn LlmProvider>`）で第三者拡張可能にする。
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn id(&self) -> &str;

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>;

    async fn count_tokens(&self, _req: &CompletionRequest) -> Option<u64> {
        None
    }

    /// モデルの内部状態をリセットする（縮退ガードの回復の梯子 (d) 段、
    /// `plans/DESIGN-COGNITION.md` §11.5）。**対応しないプロバイダは`false`を返し、梯子はその段を飛ばす。**
    ///
    /// 実装しているのはLM Studio（`OpenAiFamily::LmStudio`）だけで、Anthropic・OpenAIクラウド・
    /// mockはこの既定のまま。呼ぶかどうかは`degeneracy.auto_recycle`（既定`false`）が決める——
    /// **推論サーバは複数のharnessセッションで共有され得るため、再ロードはもう片方の進行中の推論を
    /// 巻き添えで殺す**。他者に影響する操作を暗黙の既定にはできない。
    async fn recycle(&self, _model: &str) -> Result<bool, ProviderError> {
        Ok(false)
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }
}

/// cache_control を運べる system 表現（単一Stringだと prompt caching を表現できないため）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemBlock {
    pub text: String,
    pub cache: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Tool(String),
}

/// 出力スキーマ強制の契約。アダプタが各プロバイダのネイティブ機構へ写像する。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OutputContract {
    JsonSchema {
        name: String,
        schema: serde_json::Value,
        strict: bool,
    },
    /// スキーマ無しの緩いJSONモード。
    JsonObject,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Sampling {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<u32>,
    /// 既出トークンへのペナルティ（縮退ガードの回復の梯子 (b) 段、
    /// `plans/DESIGN-COGNITION.md` §11.3）。**OpenAI系にしか写らない**——Anthropic Messages API に
    /// 対応するパラメタが無いため、そちらのアダプタでは落とす（(b)段は温度の揺らぎだけになる）。
    pub frequency_penalty: Option<f32>,
    /// 同上。話題の反復を抑える側。
    pub presence_penalty: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub tool_choice: ToolChoice,
    pub output: Option<OutputContract>,
    pub parallel_tool_calls: Option<bool>,
    /// IRで必須化 → Anthropicが400にならない。
    pub max_tokens: u32,
    pub sampling: Sampling,
    /// 素のmodel-id文字列。
    pub model: String,
}

/// ブロック単位に一般化 → text→tool_use→text や interleaved thinking の順序・境界を復元できる。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StreamEvent {
    BlockStart {
        index: usize,
        kind: BlockKind,
    },
    TextDelta {
        index: usize,
        text: String,
    },
    ThinkingDelta {
        index: usize,
        text: String,
    },
    /// thinkingブロックの署名（Anthropic）。
    SignatureDelta {
        index: usize,
        sig: String,
    },
    /// OpenAIは引数文字列断片 / Anthropicは input_json_delta。
    ToolInputDelta {
        index: usize,
        json_fragment: String,
    },
    BlockStop {
        index: usize,
    },
    Done {
        stop_reason: StopReason,
        usage: Usage,
    },
    // SSEの error イベント（Anthropic overloaded 等）は StreamEvent にせず、
    // stream() を Err(ProviderError) で畳む。
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockKind {
    Text,
    Thinking,
    RedactedThinking,
    ToolUse { id: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    StopSequence,
    Refusal,
    Other(String),
}

/// 分類を確定。外周の共通リトライラッパがこれを見てリトライ可否・待機を決める。
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProviderError {
    #[error("rate limited")]
    RateLimited { retry_after: Option<Duration> },
    #[error("overloaded")]
    Overloaded,
    #[error("context too long")]
    ContextTooLong,
    #[error("authentication failed")]
    Auth,
    #[error("quota exhausted")]
    QuotaExhausted,
    #[error("invalid request: {msg}")]
    InvalidRequest { msg: String },
    #[error("transport error (retriable={retriable})")]
    Transport { retriable: bool },
    #[error("api error: status={status} code={code:?}")]
    Api { status: u16, code: Option<String> },
}

/// 能力表明。ModelRouter/ContextAssembler が写像・降格・キャッシュ戦略を選ぶ材料。
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub native_json_schema: bool,
    pub forced_tool_choice: bool,
    pub schema_with_thinking: bool,
    /// 【T7】スキーマ強制と実ツール呼び出しの同時可否はプロバイダ依存。
    pub schema_with_tools: bool,
    pub prompt_caching: bool,
    /// コンテキスト圧縮の発火分母。
    pub context_window: u32,
    /// ローカル推論サーバ（LMStudio等）か。クラウドAPIなら`false`。
    ///
    /// 縮約の既定閾値をローカルだけ大幅に低くする（`plans/PLAN-COMPACTION.md`「既定値と
    /// ローカル判定」）ための分岐に使う。理由は3つあり、いずれもクラウドには当てはまらない:
    /// 宣言された`context_window`がRoPEスケーリング等で名目上伸ばした値であることが多く後半の
    /// 文脈が実質参照されないこと、実`n_ctx`がサーバのロード設定依存でモデルカードの最大値とは
    /// 別なこと、超過時に400を返さず黙って古いトークンを捨てる実装がありリアクティブ経路が
    /// 当てにならないこと。
    pub local: bool,
}

/// cache_read/creation を分離保持 → 圧縮判定は合算、コスト表示は分別。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input: u32,
    pub output: u32,
    pub cache_read: u32,
    pub cache_creation: u32,
}
