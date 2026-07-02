//! Anthropic Messages API を `LlmProvider` へ正規化するアダプタ。
//! `plans/DESIGN.md` §プロバイダ抽象「Anthropic（自前）」参照。
//!
//! M2時点では `stream:true` で名前付きSSE（`message_start`/`content_block_start`/
//! `content_block_delta`/`content_block_stop`/`message_delta`/`message_stop`、`ping`無視）を
//! `eventsource-stream` で逐次パースし、`StreamEvent` へ変換する。ストリーム途中の `error`
//! イベントは `Done` を送らずに `ProviderError` へ写像してストリームを終端する
//! （§ストリーミングのエラー処理・リトライの不変条件）。

use std::time::Duration;

use async_stream::try_stream;
use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures::stream::{BoxStream, StreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderCapabilities,
    ProviderError, Role, StopReason, StreamEvent, Usage,
};

const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

pub struct AnthropicProvider {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_base_url(api_key, DEFAULT_BASE_URL.to_string())
    }

    pub fn with_base_url(api_key: impl Into<String>, base_url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.into(),
            base_url,
        }
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn id(&self) -> &str {
        "anthropic"
    }

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        let body = to_wire_request(&req);
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));

        let resp = self
            .http
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Transport {
                retriable: e.is_timeout() || e.is_connect(),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);
            let text = resp.text().await.unwrap_or_default();
            return Err(map_error_response(status.as_u16(), &text, retry_after));
        }

        let mut events = resp.bytes_stream().eventsource();

        let s = try_stream! {
            let mut stop_reason = StopReason::Other("missing".to_string());
            let mut usage = Usage::default();

            while let Some(ev) = events.next().await {
                let ev = ev.map_err(|_| ProviderError::Transport { retriable: true })?;
                if ev.data.is_empty() {
                    continue;
                }

                match ev.event.as_str() {
                    "message_start" => {
                        let msg: WireMessageStart = parse_wire(&ev.data)?;
                        usage.input = msg.message.usage.input_tokens;
                        usage.cache_read = msg.message.usage.cache_read_input_tokens;
                        usage.cache_creation = msg.message.usage.cache_creation_input_tokens;
                    }
                    "content_block_start" => {
                        let e: WireContentBlockStart = parse_wire(&ev.data)?;
                        yield StreamEvent::BlockStart {
                            index: e.index,
                            kind: to_block_kind(&e.content_block),
                        };
                    }
                    "content_block_delta" => {
                        let e: WireContentBlockDelta = parse_wire(&ev.data)?;
                        match e.delta {
                            WireDelta::TextDelta { text } => {
                                yield StreamEvent::TextDelta { index: e.index, text };
                            }
                            WireDelta::InputJsonDelta { partial_json } => {
                                yield StreamEvent::ToolInputDelta {
                                    index: e.index,
                                    json_fragment: partial_json,
                                };
                            }
                            WireDelta::ThinkingDelta { thinking } => {
                                yield StreamEvent::ThinkingDelta { index: e.index, text: thinking };
                            }
                            WireDelta::SignatureDelta { signature } => {
                                yield StreamEvent::SignatureDelta { index: e.index, sig: signature };
                            }
                        }
                    }
                    "content_block_stop" => {
                        let e: WireIndexOnly = parse_wire(&ev.data)?;
                        yield StreamEvent::BlockStop { index: e.index };
                    }
                    "message_delta" => {
                        let e: WireMessageDelta = parse_wire(&ev.data)?;
                        stop_reason = map_stop_reason(e.delta.stop_reason.as_deref());
                        usage.output = e.usage.output_tokens;
                    }
                    "message_stop" => {
                        yield StreamEvent::Done { stop_reason: stop_reason.clone(), usage };
                    }
                    "ping" => {}
                    "error" => {
                        let e: WireErrorEvent = parse_wire(&ev.data)?;
                        Err(map_stream_error(&e.error))?;
                    }
                    _ => {
                        // 未知のイベント種別は将来のAPI拡張に備えて無視する。
                    }
                }
            }
        };

        Ok(Box::pin(s))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: false,
            forced_tool_choice: true,
            schema_with_thinking: false,
            schema_with_tools: false,
            prompt_caching: true,
            context_window: 200_000,
        }
    }
}

fn parse_wire<T: DeserializeOwned>(data: &str) -> Result<T, ProviderError> {
    serde_json::from_str(data).map_err(|_| ProviderError::Transport { retriable: false })
}

// --- ワイヤ形式（リクエスト） ---

#[derive(Serialize)]
struct WireRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    system: Vec<WireSystemBlock>,
    messages: Vec<WireMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<u32>,
}

#[derive(Serialize)]
struct WireSystemBlock {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<WireCacheControl>,
}

#[derive(Serialize)]
struct WireCacheControl {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: Vec<WireContentBlock>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireContentBlock {
    Text {
        text: String,
    },
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    RedactedThinking {
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
    Image {
        source: WireImageSource,
    },
}

#[derive(Serialize)]
struct WireImageSource {
    #[serde(rename = "type")]
    kind: &'static str,
    media_type: String,
    data: String,
}

fn to_wire_request(req: &CompletionRequest) -> WireRequest {
    WireRequest {
        model: req.model.clone(),
        max_tokens: req.max_tokens,
        system: req
            .system
            .iter()
            .map(|s| WireSystemBlock {
                kind: "text",
                text: s.text.clone(),
                cache_control: s.cache.then_some(WireCacheControl { kind: "ephemeral" }),
            })
            .collect(),
        messages: req.messages.iter().map(to_wire_message).collect(),
        stream: true,
        temperature: req.sampling.temperature,
        top_p: req.sampling.top_p,
        top_k: req.sampling.top_k,
    }
}

fn to_wire_message(msg: &Message) -> WireMessage {
    WireMessage {
        role: match msg.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        },
        content: msg.content.iter().map(to_wire_content_block).collect(),
    }
}

fn to_wire_content_block(block: &ContentBlock) -> WireContentBlock {
    match block {
        ContentBlock::Text(text) => WireContentBlock::Text { text: text.clone() },
        ContentBlock::Thinking { text, signature } => WireContentBlock::Thinking {
            thinking: text.clone(),
            signature: signature.clone(),
        },
        ContentBlock::RedactedThinking { data } => WireContentBlock::RedactedThinking {
            data: data.clone(),
        },
        ContentBlock::ToolUse { id, name, input } => WireContentBlock::ToolUse {
            id: id.clone(),
            name: name.clone(),
            input: input.clone(),
        },
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => WireContentBlock::ToolResult {
            tool_use_id: tool_use_id.clone(),
            content: content.clone(),
            is_error: *is_error,
        },
        ContentBlock::Image { media_type, data } => WireContentBlock::Image {
            source: WireImageSource {
                kind: "base64",
                media_type: media_type.clone(),
                data: data.clone(),
            },
        },
    }
}

// --- ワイヤ形式（SSEイベント） ---

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    #[serde(default)]
    cache_read_input_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: u32,
}

#[derive(Deserialize)]
struct WireMessageStart {
    message: WireMessageStartInner,
}

#[derive(Deserialize)]
struct WireMessageStartInner {
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireContentBlockStart {
    index: usize,
    content_block: WireBlockStartInner,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireBlockStartInner {
    Text {},
    Thinking {},
    RedactedThinking {},
    ToolUse { id: String, name: String },
}

fn to_block_kind(inner: &WireBlockStartInner) -> BlockKind {
    match inner {
        WireBlockStartInner::Text {} => BlockKind::Text,
        WireBlockStartInner::Thinking {} => BlockKind::Thinking,
        WireBlockStartInner::RedactedThinking {} => BlockKind::RedactedThinking,
        WireBlockStartInner::ToolUse { id, name } => BlockKind::ToolUse {
            id: id.clone(),
            name: name.clone(),
        },
    }
}

#[derive(Deserialize)]
struct WireContentBlockDelta {
    index: usize,
    delta: WireDelta,
}

// バリアント名はAnthropic API上の `delta.type` 値（`text_delta`等）にそのまま対応させている。
#[allow(clippy::enum_variant_names)]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireDelta {
    TextDelta { text: String },
    InputJsonDelta { partial_json: String },
    ThinkingDelta { thinking: String },
    SignatureDelta { signature: String },
}

#[derive(Deserialize)]
struct WireIndexOnly {
    index: usize,
}

#[derive(Deserialize)]
struct WireMessageDelta {
    delta: WireMessageDeltaInner,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireMessageDeltaInner {
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct WireErrorEvent {
    error: WireErrorDetail,
}

fn map_stop_reason(reason: Option<&str>) -> StopReason {
    match reason {
        Some("end_turn") => StopReason::EndTurn,
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        Some("stop_sequence") => StopReason::StopSequence,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::Other("missing".to_string()),
    }
}

// --- エラー写像 ---

#[derive(Deserialize)]
struct WireErrorBody {
    error: WireErrorDetail,
}

#[derive(Deserialize)]
struct WireErrorDetail {
    #[serde(rename = "type")]
    kind: String,
    message: String,
}

/// HTTPレベル（ストリーム開始前）のエラー写像。
fn map_error_response(status: u16, body: &str, retry_after: Option<Duration>) -> ProviderError {
    let detail: Option<WireErrorBody> = serde_json::from_str(body).ok();
    let (kind, message) = match detail {
        Some(d) => (d.error.kind, d.error.message),
        None => ("unknown".to_string(), body.to_string()),
    };

    match status {
        401 | 403 => ProviderError::Auth,
        429 => ProviderError::RateLimited { retry_after },
        529 => ProviderError::Overloaded,
        400 if kind == "invalid_request_error"
            && (message.contains("too long") || message.contains("context_length")) =>
        {
            ProviderError::ContextTooLong
        }
        400 => ProviderError::InvalidRequest { msg: message },
        _ => ProviderError::Api {
            status,
            code: Some(kind),
        },
    }
}

/// mid-stream の SSE `error` イベント写像。HTTPステータス/Retry-Afterヘッダは無い。
fn map_stream_error(detail: &WireErrorDetail) -> ProviderError {
    match detail.kind.as_str() {
        "overloaded_error" => ProviderError::Overloaded,
        "rate_limit_error" => ProviderError::RateLimited { retry_after: None },
        "authentication_error" | "permission_error" => ProviderError::Auth,
        "invalid_request_error" => ProviderError::InvalidRequest {
            msg: detail.message.clone(),
        },
        other => ProviderError::Api {
            status: 0,
            code: Some(other.to_string()),
        },
    }
}
