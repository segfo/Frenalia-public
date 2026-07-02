//! Anthropic Messages API を `LlmProvider` へ正規化するアダプタ。
//! `plans/DESIGN.md` §プロバイダ抽象「Anthropic（自前）」参照。
//!
//! M1時点では非ストリーム実装（`stream:false` で1回POSTし、全文を受け取ってから
//! `StreamEvent` 列へ変換する）。名前付きSSEの逐次パースはM2で追加する。

use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use serde::{Deserialize, Serialize};

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

        let parsed: WireResponse = resp.json().await.map_err(|_| ProviderError::Transport {
            retriable: false,
        })?;

        let events = to_stream_events(parsed);
        Ok(stream::iter(events.into_iter().map(Ok)).boxed())
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
        stream: false,
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

// --- ワイヤ形式（レスポンス） ---

#[derive(Deserialize)]
struct WireResponse {
    content: Vec<WireResponseBlock>,
    stop_reason: Option<String>,
    #[serde(default)]
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireResponseBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
    id: Option<String>,
    name: Option<String>,
    thinking: Option<String>,
    signature: Option<String>,
}

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

fn to_stream_events(resp: WireResponse) -> Vec<StreamEvent> {
    let mut events = Vec::new();

    for (index, block) in resp.content.into_iter().enumerate() {
        match block.kind.as_str() {
            "text" => {
                let text = block.text.unwrap_or_default();
                events.push(StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::Text,
                });
                events.push(StreamEvent::TextDelta { index, text });
                events.push(StreamEvent::BlockStop { index });
            }
            "thinking" => {
                events.push(StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::Thinking,
                });
                events.push(StreamEvent::ThinkingDelta {
                    index,
                    text: block.thinking.unwrap_or_default(),
                });
                if let Some(sig) = block.signature {
                    events.push(StreamEvent::SignatureDelta { index, sig });
                }
                events.push(StreamEvent::BlockStop { index });
            }
            "tool_use" => {
                // ツール呼び出しの実処理はM3以降。ここではブロックの往復のみ成立させる。
                events.push(StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::ToolUse {
                        id: block.id.unwrap_or_default(),
                        name: block.name.unwrap_or_default(),
                    },
                });
                events.push(StreamEvent::BlockStop { index });
            }
            _ => {
                // redacted_thinking等、M1で未使用のブロック種別はスキップする。
            }
        }
    }

    events.push(StreamEvent::Done {
        stop_reason: map_stop_reason(resp.stop_reason.as_deref()),
        usage: Usage {
            input: resp.usage.input_tokens,
            output: resp.usage.output_tokens,
            cache_read: resp.usage.cache_read_input_tokens,
            cache_creation: resp.usage.cache_creation_input_tokens,
        },
    });

    events
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
