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
    ProviderError, Role, StopReason, StreamEvent, ToolChoice, Usage,
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
        // 構造化出力の写像はここで決まる（`harness_core::schema`が唯一の判断点）。
        // Anthropicは`native_json_schema:false`なので、スキーマ強制は「スキーマを
        // input_schemaとする単一ツール + tool_choice強制」へ降格し、`req.output`は消える。
        // `req.output`が`None`のときは`req`を一切書き換えないので、既存の全経路は不変。
        //
        // `schema_with_thinking:false`（thinking有効時はtool_choice強制が400）への対応は
        // 不要。このアダプタはthinkingを一切リクエストへ載せていないため、強制と衝突しない。
        let mut req = req;
        let strategy = harness_core::apply_schema_strategy(&mut req, &self.capabilities());
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

        let stream: BoxStream<'static, Result<StreamEvent, ProviderError>> = Box::pin(s);
        // ツール強制降格を採った場合だけ、応答の`tool_use`ブロックをテキストへ戻す
        // （認知レイヤーからはnative経路と同じ形に見える）。
        Ok(match strategy {
            harness_core::SchemaStrategy::ForcedTool { name } => {
                harness_core::unwrap_forced_tool_stream(stream, name)
            }
            _ => stream,
        })
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: false,
            forced_tool_choice: true,
            schema_with_thinking: false,
            schema_with_tools: false,
            prompt_caching: true,
            context_window: 200_000,
            local: false,
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
    // `Sampling.frequency_penalty`/`presence_penalty`はここに写さない。Anthropic Messages APIに
    // 対応するパラメタが無く、送れば400になる。これらは縮退ガードの回復の梯子 (b) 段
    // （`plans/DESIGN-COGNITION.md` §11.3）だけが載せる値で、Anthropic経由では (b) は
    // 温度の揺らぎだけになる（設計上許容している降格）。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireToolSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<WireToolChoice>,
}

#[derive(Serialize)]
struct WireToolSpec {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireToolChoice {
    Auto,
    Any,
    Tool { name: String },
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
    let tools: Vec<WireToolSpec> = req
        .tools
        .iter()
        .map(|t| WireToolSpec {
            name: t.name.clone(),
            description: t.description.clone(),
            input_schema: t.input_schema.clone(),
        })
        .collect();

    // tool_choice は tools が空だと Anthropic 側が 400 を返すため、tools がある時のみ載せる。
    // Anthropicに "none" 相当は無いため ToolChoice::None はそのまま省略する。
    let tool_choice = if tools.is_empty() {
        None
    } else {
        match &req.tool_choice {
            ToolChoice::Auto => Some(WireToolChoice::Auto),
            ToolChoice::Required => Some(WireToolChoice::Any),
            ToolChoice::Tool(name) => Some(WireToolChoice::Tool { name: name.clone() }),
            ToolChoice::None => None,
        }
    };

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
        tools,
        tool_choice,
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
        ContentBlock::RedactedThinking { data } => {
            WireContentBlock::RedactedThinking { data: data.clone() }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_blocks_are_sent_as_anthropic_system_array() {
        let req = CompletionRequest {
            system: vec![harness_core::SystemBlock {
                text: "system facts".to_string(),
                cache: true,
            }],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "claude-test".to_string(),
        };

        let wire = to_wire_request(&req);
        let value = serde_json::to_value(&wire).unwrap();

        assert_eq!(value["system"][0]["type"], "text");
        assert_eq!(value["system"][0]["text"], "system facts");
        assert_eq!(value["system"][0]["cache_control"]["type"], "ephemeral");
    }

    /// 契約テスト（`plans/DESIGN.md` §主なリスクと対策「structured output の3プロバイダ写像」の
    /// **tool強制**経路）。Anthropicは`native_json_schema:false`なので、スキーマ強制は
    /// 「スキーマを`input_schema`とする単一ツール + `tool_choice:{type:tool}`」へ降格し、
    /// その結果がワイヤ形式まで通ることを確認する。
    #[test]
    fn json_schema_contract_degrades_to_a_single_forced_tool() {
        let mut req = CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: Some(harness_core::OutputContract::JsonSchema {
                name: "verify_output".to_string(),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": { "verdict": { "type": "string" } },
                    "required": ["verdict"],
                    "additionalProperties": false
                }),
                strict: true,
            }),
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "claude-test".to_string(),
        };

        let caps = AnthropicProvider::new("k").capabilities();
        let strategy = harness_core::apply_schema_strategy(&mut req, &caps);
        assert_eq!(
            strategy,
            harness_core::SchemaStrategy::ForcedTool {
                name: "verify_output".to_string()
            }
        );

        let value = serde_json::to_value(to_wire_request(&req)).unwrap();
        assert_eq!(value["tools"][0]["name"], "verify_output");
        assert_eq!(
            value["tools"][0]["input_schema"]["properties"]["verdict"]["type"],
            "string"
        );
        assert_eq!(value["tool_choice"]["type"], "tool");
        assert_eq!(value["tool_choice"]["name"], "verify_output");
    }
}
