//! OpenAI Chat Completions API を `LlmProvider` へ正規化するアダプタ。
//! `plans/DESIGN.md` §プロバイダ抽象「OpenAI Chat Completions / LMStudio」参照。
//!
//! **設計書との差分（M1時点でのスコープ拡張、M2で継続）**: `plans/DESIGN.md` の実装マイルストーンでは
//! OpenAIファミリは本来M6（`async-openai` 経由、tool_call文字列引数正規化・LMStudio互換・
//! Responses variant込み）のスコープである。本ファイルはユーザの指示により、M1の時点で
//! Anthropicと並行して**ツール無し・自前reqwest実装**の最小疎通のみを先行実装したもの。M2では
//! `stream:true`+`data:`フレーム逐次パース（末尾`data:[DONE]`）へ拡張した。`async-openai`
//! 採用可否（§プロバイダ抽象 L134のA/B）・tool_call引数正規化・LMStudio base_url差し替え・
//! Responses variantはM6で改めて設計通りに実装する。

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

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";

pub struct OpenAiProvider {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OpenAiProvider {
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
impl LlmProvider for OpenAiProvider {
    fn id(&self) -> &str {
        "openai"
    }

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        let body = to_wire_request(&req);
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.api_key)
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
            let mut block_open = false;
            let mut stop_reason = StopReason::EndTurn;
            let mut usage = Usage::default();

            while let Some(ev) = events.next().await {
                let ev = ev.map_err(|_| ProviderError::Transport { retriable: true })?;
                if ev.data.is_empty() {
                    continue;
                }
                if ev.data == "[DONE]" {
                    break;
                }

                let chunk: WireChunk = parse_wire(&ev.data)?;

                if let Some(u) = chunk.usage {
                    usage.input = u.prompt_tokens;
                    usage.output = u.completion_tokens;
                }

                if let Some(choice) = chunk.choices.into_iter().next() {
                    if !block_open {
                        yield StreamEvent::BlockStart { index: 0, kind: BlockKind::Text };
                        block_open = true;
                    }
                    if let Some(text) = choice.delta.content {
                        if !text.is_empty() {
                            yield StreamEvent::TextDelta { index: 0, text };
                        }
                    }
                    if let Some(fr) = choice.finish_reason {
                        stop_reason = map_stop_reason(Some(&fr));
                    }
                }
            }

            if block_open {
                yield StreamEvent::BlockStop { index: 0 };
            }
            yield StreamEvent::Done { stop_reason, usage };
        };

        Ok(Box::pin(s))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: true,
            forced_tool_choice: true,
            schema_with_thinking: true,
            schema_with_tools: true,
            prompt_caching: true,
            context_window: 128_000,
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
    messages: Vec<WireMessage>,
    stream: bool,
    stream_options: WireStreamOptions,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
}

#[derive(Serialize)]
struct WireStreamOptions {
    include_usage: bool,
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    content: String,
}

fn to_wire_request(req: &CompletionRequest) -> WireRequest {
    let mut messages = Vec::new();

    if !req.system.is_empty() {
        let text = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        messages.push(WireMessage {
            role: "system",
            content: text,
        });
    }

    for m in &req.messages {
        messages.push(to_wire_message(m));
    }

    WireRequest {
        model: req.model.clone(),
        messages,
        stream: true,
        stream_options: WireStreamOptions { include_usage: true },
        max_tokens: req.max_tokens,
        temperature: req.sampling.temperature,
        top_p: req.sampling.top_p,
    }
}

fn to_wire_message(msg: &Message) -> WireMessage {
    // M1/M2時点はテキストのみを送信する単発ターン専用。tool_use/tool_result/thinking等の
    // OpenAI固有ワイヤ形式（tool_calls配列・role:tool分離）への正規化はM3/M6で追加する。
    let text = msg
        .content
        .iter()
        .filter_map(|c| match c {
            ContentBlock::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    WireMessage {
        role: match msg.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        },
        content: text,
    }
}

// --- ワイヤ形式（SSEチャンク） ---

#[derive(Deserialize)]
struct WireChunk {
    #[serde(default)]
    choices: Vec<WireChunkChoice>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
struct WireChunkChoice {
    #[serde(default)]
    delta: WireChunkDelta,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireChunkDelta {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

fn map_stop_reason(reason: Option<&str>) -> StopReason {
    match reason {
        Some("stop") => StopReason::EndTurn,
        Some("length") => StopReason::MaxTokens,
        Some("tool_calls") => StopReason::ToolUse,
        Some("content_filter") => StopReason::Refusal,
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
    message: String,
    #[serde(default)]
    code: Option<String>,
}

fn map_error_response(status: u16, body: &str, retry_after: Option<Duration>) -> ProviderError {
    let detail: Option<WireErrorBody> = serde_json::from_str(body).ok();
    let (code, message) = match detail {
        Some(d) => (d.error.code, d.error.message),
        None => (None, body.to_string()),
    };

    match (status, code.as_deref()) {
        (401, _) => ProviderError::Auth,
        (429, Some("insufficient_quota")) => ProviderError::QuotaExhausted,
        (429, _) => ProviderError::RateLimited { retry_after },
        (400, Some("context_length_exceeded")) => ProviderError::ContextTooLong,
        (400, _) => ProviderError::InvalidRequest { msg: message },
        _ => ProviderError::Api { status, code },
    }
}
