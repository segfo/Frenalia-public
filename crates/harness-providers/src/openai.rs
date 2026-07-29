//! OpenAI Chat Completions API を `LlmProvider` へ正規化するアダプタ。
//! `plans/DESIGN.md` §プロバイダ抽象「OpenAI Chat Completions / LMStudio」参照。
//!
//! **M6でツール呼び出しに対応**: `tools`/`tool_choice`のリクエスト側正規化、`delta.tool_calls[]`
//! （indexごとに分割された`function.arguments`のJSON文字列断片）のレスポンス側正規化を実装した。
//! LMStudioは`base_url`を`http://localhost:1234/v1`へ差し替えるだけの同一ワイヤ形式（openai-family、
//! §設定「ProviderProfile」）だが、実機の応答には`usage:null`・`tool_calls`チャンクでの`index`省略
//! といった揺れがあるため、該当フィールドは`#[serde(default)]`で欠落を許容している
//! （§実装マイルストーン M6 受入条件【E10】）。
//!
//! OpenAI Responses API（stateless variant、`encrypted_content`往復）はDESIGN.md §プロバイダ抽象が
//! 明示的に「M6とは別の後続マイルストーンへ切り出す」と定めているため、本ファイルのスコープ外。

use std::path::PathBuf;
use std::time::Duration;

use async_stream::try_stream;
use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures::stream::{BoxStream, StreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderCapabilities,
    ProviderError, Role, StopReason, StreamEvent, ToolChoice, ToolSpec, Usage,
};

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_LMSTUDIO_BASE_URL: &str = "http://localhost:1234/v1";

/// `HARNESS_WIRE_LOG=<path>`が設定されているときだけ、送信リクエストボディと受信SSEチャンクを
/// そのままJSONL追記する（`run_shell`不安定性調査、Phase 2観測基盤）。未設定時はゼロコスト
/// （`std::env::var_os`1回のみ）。1行1JSONオブジェクト、`kind`フィールドで種別を区別する。
fn wire_log_path() -> Option<PathBuf> {
    std::env::var_os("HARNESS_WIRE_LOG").map(PathBuf::from)
}

fn wire_log_append(path: &std::path::Path, value: &serde_json::Value) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{value}");
    }
}

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

    /// §設定「LMStudio は単に `base_url=http://localhost:1234/v1` の openai-family プロファイル」。
    /// LMStudioは認証不要のため空キーで構わない（§プロバイダ抽象「LMStudioは空キー可」）。
    pub fn lmstudio() -> Self {
        Self::with_base_url(String::new(), DEFAULT_LMSTUDIO_BASE_URL.to_string())
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

        let wire_log = wire_log_path();
        if let Some(path) = &wire_log {
            wire_log_append(
                path,
                &serde_json::json!({ "kind": "request", "body": &body }),
            );
        }

        let mut request = self.http.post(url).json(&body);
        if !self.api_key.is_empty() {
            request = request.bearer_auth(&self.api_key);
        }

        let resp = request.send().await.map_err(|e| ProviderError::Transport {
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
            if let Some(path) = &wire_log {
                wire_log_append(
                    path,
                    &serde_json::json!({ "kind": "error_response", "status": status.as_u16(), "body": &text }),
                );
            }
            return Err(map_error_response(status.as_u16(), &text, retry_after));
        }

        let mut events = resp.bytes_stream().eventsource();

        let s = try_stream! {
            let mut st = StreamAccumState::new();

            while let Some(ev) = events.next().await {
                let ev = ev.map_err(|_| ProviderError::Transport { retriable: true })?;
                if ev.data.is_empty() {
                    continue;
                }
                if let Some(path) = &wire_log {
                    wire_log_append(path, &serde_json::json!({ "kind": "sse_chunk", "data": &ev.data }));
                }
                if ev.data == "[DONE]" {
                    break;
                }

                let chunk: WireChunk = parse_wire(&ev.data)?;
                for event in st.handle_chunk(chunk) {
                    yield event;
                }
            }

            for event in st.finish() {
                yield event;
            }
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
}

#[derive(Serialize)]
struct WireStreamOptions {
    include_usage: bool,
}

#[derive(Serialize)]
struct WireMessage {
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<WireToolCallOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
struct WireToolCallOut {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireFunctionCallOut,
}

#[derive(Serialize)]
struct WireFunctionCallOut {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct WireTool {
    #[serde(rename = "type")]
    kind: &'static str,
    function: WireFunctionDef,
}

#[derive(Serialize)]
struct WireFunctionDef {
    name: String,
    description: String,
    parameters: serde_json::Value,
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
            content: Some(text),
            tool_calls: None,
            tool_call_id: None,
        });
    }

    for m in &req.messages {
        append_wire_messages(m, &mut messages);
    }

    let tools: Vec<WireTool> = req.tools.iter().map(to_wire_tool).collect();
    // tool_choice はAnthropicアダプタと同様、toolsが無いのに送るとプロバイダによっては
    // 400になりうるため、toolsがある時のみ載せる（§プロバイダ抽象 Anthropicアダプタと対称）。
    let tool_choice = if tools.is_empty() {
        None
    } else {
        Some(tool_choice_to_wire(&req.tool_choice))
    };

    WireRequest {
        model: req.model.clone(),
        messages,
        stream: true,
        stream_options: WireStreamOptions {
            include_usage: true,
        },
        max_tokens: req.max_tokens,
        temperature: req.sampling.temperature,
        top_p: req.sampling.top_p,
        tools,
        tool_choice,
        parallel_tool_calls: req.parallel_tool_calls,
    }
}

fn to_wire_tool(spec: &ToolSpec) -> WireTool {
    WireTool {
        kind: "function",
        function: WireFunctionDef {
            name: spec.name.clone(),
            description: spec.description.clone(),
            parameters: spec.input_schema.clone(),
        },
    }
}

fn tool_choice_to_wire(tc: &ToolChoice) -> serde_json::Value {
    match tc {
        ToolChoice::Auto => serde_json::json!("auto"),
        ToolChoice::None => serde_json::json!("none"),
        ToolChoice::Required => serde_json::json!("required"),
        ToolChoice::Tool(name) => {
            serde_json::json!({ "type": "function", "function": { "name": name } })
        }
    }
}

/// 1つのIRメッセージを0〜複数のOpenAIワイヤメッセージへ展開する。
/// `ToolResult`ブロックはAnthropicと異なり`role:"tool"`+`tool_call_id`の**別メッセージ**になる
/// （§プロバイダ抽象 OpenAI「結果はrole:tool+tool_call_id」）ため、1:1写像にならない。
fn append_wire_messages(msg: &Message, out: &mut Vec<WireMessage>) {
    match msg.role {
        Role::User => {
            let mut text_parts = Vec::new();
            for block in &msg.content {
                match block {
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } => {
                        out.push(WireMessage {
                            role: "tool",
                            content: Some(content.clone()),
                            tool_calls: None,
                            tool_call_id: Some(tool_use_id.clone()),
                        });
                    }
                    ContentBlock::Text(t) => text_parts.push(t.clone()),
                    // Image/Thinking/RedactedThinkingはOpenAI Chat Completionsのuser側には
                    // 未対応（Imageは将来対応、ThinkingはAnthropic固有概念のためM6スコープ外）。
                    _ => {}
                }
            }
            if !text_parts.is_empty() {
                out.push(WireMessage {
                    role: "user",
                    content: Some(text_parts.join("\n")),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
        }
        Role::Assistant => {
            let mut text_parts = Vec::new();
            let mut tool_calls = Vec::new();
            for block in &msg.content {
                match block {
                    ContentBlock::Text(t) => text_parts.push(t.clone()),
                    ContentBlock::ToolUse { id, name, input } => {
                        tool_calls.push(WireToolCallOut {
                            id: id.clone(),
                            kind: "function",
                            function: WireFunctionCallOut {
                                name: name.clone(),
                                arguments: input.to_string(),
                            },
                        });
                    }
                    _ => {}
                }
            }
            out.push(WireMessage {
                role: "assistant",
                content: if text_parts.is_empty() {
                    None
                } else {
                    Some(text_parts.join("\n"))
                },
                tool_calls: if tool_calls.is_empty() {
                    None
                } else {
                    Some(tool_calls)
                },
                tool_call_id: None,
            });
        }
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
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireChunkDelta {
    #[serde(default)]
    content: Option<String>,
    /// reasoning（thinking）内容。OpenAI本家の`content`とは別フィールドで送られる
    /// （DeepSeek API由来で広く模倣されている`reasoning_content`。LM Studio等の実装違いで
    /// `reasoning`という別名で送られることもあるため`alias`で同じフィールドへ吸収する）。
    /// 未宣言のままだと`deny_unknown_fields`が無いserdeはこのキーを黙って無視するため、
    /// reasoning対応モデルの thinking トークンが一切`StreamEvent`化されずTUIのライブ
    /// トークン表示（`AgentEvent::ThinkingDelta`）に反映されないバグになっていた。
    #[serde(default, alias = "reasoning")]
    reasoning_content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<WireToolCallDelta>>,
}

/// `index`はOpenAI本家では常に付与されるが、LMStudioの実応答では継続チャンク
/// （2個目以降の`arguments`断片）で省略されることがある（§実装マイルストーン M6【E10】）。
/// **`0`へフォールバックしない**（Phase5-D、`run_shell`不安定性調査）: 複数tool_callが
/// 同時に開いている状態で`index`省略チャンクを常に先頭ブロック（index 0）へ結合すると、
/// 2件目以降のtool_callの引数JSONが1件目へ混入し確実に壊れる。`Option<usize>`のまま保持し、
/// 呼び出し側（`StreamAccumState::handle_chunk`）で「直近に開いたブロックへ倒す」フォールバックを
/// 行う（当時1件のtool_callしか無い運用ではこれで従来と同じ挙動になる）。
#[derive(Deserialize, Default)]
struct WireToolCallDelta {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<WireFunctionDelta>,
}

#[derive(Deserialize, Default)]
struct WireFunctionDelta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Deserialize, Default)]
struct WireUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

/// SSEチャンク列から`StreamEvent`列を組み立てる作業用状態。
/// テキストブロックはローカルindex 0固定、各tool_callはOpenAI側`index`+1をローカルindexとして
/// 割り当てる（0はテキスト用に予約）。`stream()`本体から切り出してあるのは、実HTTPを起こさず
/// 録画済み/合成JSONチャンクだけで単体テストできるようにするため（下記tests参照）。
struct StreamAccumState {
    text_open: bool,
    thinking_open: bool,
    tool_open: Vec<usize>,
    stop_reason: StopReason,
    usage: Usage,
}

/// reasoning（thinking）ブロック用の予約index。テキスト=0固定・tool_call=`OpenAI側index+1`
/// という既存の割当規約と衝突しない値として、tool_callが現実的に到達し得ない大きな値を使う。
const THINKING_INDEX: usize = usize::MAX;

impl StreamAccumState {
    fn new() -> Self {
        Self {
            text_open: false,
            thinking_open: false,
            tool_open: Vec::new(),
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        }
    }

    fn handle_chunk(&mut self, chunk: WireChunk) -> Vec<StreamEvent> {
        let mut out = Vec::new();

        if let Some(u) = chunk.usage {
            self.usage.input = u.prompt_tokens;
            self.usage.output = u.completion_tokens;
        }

        if let Some(choice) = chunk.choices.into_iter().next() {
            if let Some(text) = choice.delta.reasoning_content {
                if !text.is_empty() {
                    if !self.thinking_open {
                        out.push(StreamEvent::BlockStart {
                            index: THINKING_INDEX,
                            kind: BlockKind::Thinking,
                        });
                        self.thinking_open = true;
                    }
                    out.push(StreamEvent::ThinkingDelta {
                        index: THINKING_INDEX,
                        text,
                    });
                }
            }

            if let Some(text) = choice.delta.content {
                if !text.is_empty() {
                    if !self.text_open {
                        out.push(StreamEvent::BlockStart {
                            index: 0,
                            kind: BlockKind::Text,
                        });
                        self.text_open = true;
                    }
                    out.push(StreamEvent::TextDelta { index: 0, text });
                }
            }

            if let Some(tool_calls) = choice.delta.tool_calls {
                for tc in tool_calls {
                    // Phase5-D: `index`が省略された継続チャンクは、先頭固定（旧: 0）ではなく
                    // 「直近に開いたtool_useブロック」へ倒す（`WireToolCallDelta`のdocコメント
                    // 参照）。単一tool_call運用では従来と同じ挙動、複数tool_call運用でも
                    // 最後に開いたブロックへ結合されるため誤結合のリスクを最小化できる。
                    let local_index = match tc.index {
                        Some(idx) => idx + 1,
                        None => self.tool_open.last().copied().unwrap_or(1),
                    };
                    if !self.tool_open.contains(&local_index) {
                        let id = tc.id.clone().unwrap_or_default();
                        let name = tc
                            .function
                            .as_ref()
                            .and_then(|f| f.name.clone())
                            .unwrap_or_default();
                        out.push(StreamEvent::BlockStart {
                            index: local_index,
                            kind: BlockKind::ToolUse { id, name },
                        });
                        self.tool_open.push(local_index);
                    }
                    if let Some(args) = tc.function.and_then(|f| f.arguments) {
                        if !args.is_empty() {
                            out.push(StreamEvent::ToolInputDelta {
                                index: local_index,
                                json_fragment: args,
                            });
                        }
                    }
                }
            }

            if let Some(fr) = choice.finish_reason {
                self.stop_reason = map_stop_reason(Some(&fr));
            }
        }

        out
    }

    fn finish(self) -> Vec<StreamEvent> {
        let mut out = Vec::new();
        if self.thinking_open {
            out.push(StreamEvent::BlockStop {
                index: THINKING_INDEX,
            });
        }
        if self.text_open {
            out.push(StreamEvent::BlockStop { index: 0 });
        }
        for idx in self.tool_open {
            out.push(StreamEvent::BlockStop { index: idx });
        }
        out.push(StreamEvent::Done {
            stop_reason: self.stop_reason,
            usage: self.usage,
        });
        out
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_blocks_are_sent_as_first_openai_system_message() {
        let req = CompletionRequest {
            system: vec![
                harness_core::SystemBlock {
                    text: "system facts".to_string(),
                    cache: true,
                },
                harness_core::SystemBlock {
                    text: "more facts".to_string(),
                    cache: false,
                },
            ],
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text("hello".to_string())],
            }],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "gpt-test".to_string(),
        };

        let wire = to_wire_request(&req);
        let value = serde_json::to_value(&wire).unwrap();
        let messages = value["messages"].as_array().unwrap();

        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "system facts\n\nmore facts");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "hello");
    }

    /// 標準的なOpenAI Chat Completionsのtool_callチャンク（`index`が毎回明示される）。
    /// §実装マイルストーン M6検証条件「同一プロンプトが3プロバイダで動く」のワイヤ層に相当する
    /// 部分を、実HTTP無しで確認する。
    #[test]
    fn openai_style_tool_call_chunks_produce_matching_block_events() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();

        let chunk1: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[
                {"index":0,"id":"call_abc","type":"function","function":{"name":"read_file","arguments":""}}
            ]},"finish_reason":null}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));

        let chunk2: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"index":0,"function":{"arguments":"{\"path\":"}}
            ]},"finish_reason":null}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk2));

        let chunk3: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"index":0,"function":{"arguments":"\"a.txt\"}"}}
            ]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk3));

        events.extend(st.finish());

        assert_eq!(
            events,
            vec![
                StreamEvent::BlockStart {
                    index: 1,
                    kind: BlockKind::ToolUse {
                        id: "call_abc".to_string(),
                        name: "read_file".to_string(),
                    },
                },
                StreamEvent::ToolInputDelta {
                    index: 1,
                    json_fragment: "{\"path\":".to_string(),
                },
                StreamEvent::ToolInputDelta {
                    index: 1,
                    json_fragment: "\"a.txt\"}".to_string(),
                },
                StreamEvent::BlockStop { index: 1 },
                StreamEvent::Done {
                    stop_reason: StopReason::ToolUse,
                    usage: Usage {
                        input: 10,
                        output: 5,
                        cache_read: 0,
                        cache_creation: 0,
                    },
                },
            ]
        );
    }

    /// §実装マイルストーン M6受入条件【E10】: LMStudio実応答フィクスチャ（`usage:null`・
    /// tool_callチャンクの`index`省略込み）のデシリアライズテスト。継続チャンクが`index`を
    /// 省略しても（単一tool_call運用では）0へフォールバックし同じブロックへ集約されることを確認する。
    #[test]
    fn lmstudio_quirk_fixture_with_null_usage_and_missing_index_deserializes() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();

        // 1個目のチャンクはid/nameを伴い明示indexあり（LMStudioでもここは省略されない）。
        let chunk1: WireChunk = parse_wire(
            r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,
                "model":"qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp",
                "choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[
                    {"index":0,"id":"call_1","type":"function","function":{"name":"glob","arguments":""}}
                ]},"finish_reason":null}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));

        // 継続チャンクは実機で"index"キー自体が省略されることがある（【E10】が明記する揺れ）。
        let chunk2: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"function":{"arguments":"{\"pattern\":"}}
            ]},"finish_reason":null}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk2));

        let chunk3: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"function":{"arguments":"\"*.rs\"}"}}
            ]},"finish_reason":"tool_calls"}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk3));

        events.extend(st.finish());

        let fragments: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ToolInputDelta { json_fragment, .. } => Some(json_fragment.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(fragments.join(""), r#"{"pattern":"*.rs"}"#);

        assert!(events
            .iter()
            .any(|e| matches!(e, StreamEvent::BlockStart { index: 1, kind: BlockKind::ToolUse { id, name } } if id == "call_1" && name == "glob")));
        assert_eq!(
            events.last(),
            Some(&StreamEvent::Done {
                stop_reason: StopReason::ToolUse,
                usage: Usage::default(),
            })
        );
    }

    /// Phase5-D回帰テスト: 2件の並列tool_callが開いている状態で、2件目の継続チャンクが
    /// `index`を省略した場合に「直近に開いたブロック（2件目）」へ結合されること
    /// （0固定にすると2件目の引数が1件目のブロックへ混入し、両方のJSONが壊れる）。
    #[test]
    fn missing_index_on_second_of_two_concurrent_tool_calls_attaches_to_last_opened() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();

        // 1件目・2件目とも最初のチャンクは明示indexありでオープンする。
        let chunk1: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.txt\"}"}}
            ]},"finish_reason":null}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));

        let chunk2: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"index":1,"id":"call_2","type":"function","function":{"name":"read_file","arguments":""}}
            ]},"finish_reason":null}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk2));

        // 2件目の継続チャンクが`index`を省略。最後に開いたのは2件目（local_index=2）なので
        // そちらへ結合されるべきで、1件目（local_index=1）へ混入してはならない。
        let chunk3: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[
                {"function":{"arguments":"{\"path\":\"b.txt\"}"}}
            ]},"finish_reason":"tool_calls"}],"usage":null}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk3));
        events.extend(st.finish());

        let call1_fragments: String = events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ToolInputDelta {
                    index: 1,
                    json_fragment,
                } => Some(json_fragment.as_str()),
                _ => None,
            })
            .collect();
        let call2_fragments: String = events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ToolInputDelta {
                    index: 2,
                    json_fragment,
                } => Some(json_fragment.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(call1_fragments, r#"{"path":"a.txt"}"#);
        assert_eq!(call2_fragments, r#"{"path":"b.txt"}"#);
    }

    #[test]
    fn text_only_chunks_still_work_without_tool_calls() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();

        let chunk1: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));

        let chunk2: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk2));

        events.extend(st.finish());

        assert_eq!(
            events,
            vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::TextDelta {
                    index: 0,
                    text: "hello".to_string(),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::Done {
                    stop_reason: StopReason::EndTurn,
                    usage: Usage {
                        input: 3,
                        output: 1,
                        cache_read: 0,
                        cache_creation: 0,
                    },
                },
            ]
        );
    }

    /// `reasoning_content`（DeepSeek API由来で広く模倣されているreasoning用フィールド）が
    /// `BlockStart{Thinking}`→`ThinkingDelta`→（本文へ切り替わったら）`BlockStop`という
    /// 正しい順序で`StreamEvent`化されることを確認する（LMStudio等reasoning対応モデルの
    /// thinkingトークンがTUIのライブ表示に反映されないバグの回帰防止）。
    #[test]
    fn reasoning_content_becomes_thinking_delta_events() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();

        let chunk1: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"reasoning_content":"Let me "},"finish_reason":null}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));

        let chunk2: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"reasoning_content":"think..."},"finish_reason":null}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk2));

        let chunk3: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"content":"answer"},"finish_reason":"stop"}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk3));
        events.extend(st.finish());

        assert_eq!(
            events,
            vec![
                StreamEvent::BlockStart {
                    index: THINKING_INDEX,
                    kind: BlockKind::Thinking
                },
                StreamEvent::ThinkingDelta {
                    index: THINKING_INDEX,
                    text: "Let me ".to_string()
                },
                StreamEvent::ThinkingDelta {
                    index: THINKING_INDEX,
                    text: "think...".to_string()
                },
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text
                },
                StreamEvent::TextDelta {
                    index: 0,
                    text: "answer".to_string()
                },
                StreamEvent::BlockStop {
                    index: THINKING_INDEX
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::Done {
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default()
                },
            ]
        );
    }

    /// LM Studio等で観測される別名`reasoning`フィールドでも同じく`ThinkingDelta`になること。
    #[test]
    fn reasoning_alias_field_also_becomes_thinking_delta() {
        let mut st = StreamAccumState::new();
        let chunk: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"reasoning":"hmm"},"finish_reason":null}]}"#,
        )
        .unwrap();
        let events = st.handle_chunk(chunk);

        assert_eq!(
            events,
            vec![
                StreamEvent::BlockStart {
                    index: THINKING_INDEX,
                    kind: BlockKind::Thinking
                },
                StreamEvent::ThinkingDelta {
                    index: THINKING_INDEX,
                    text: "hmm".to_string()
                },
            ]
        );
    }

    /// reasoningフィールドを含まない既存の応答は、引き続き`ThinkingDelta`を一切生成しない
    /// （回帰防止）。
    #[test]
    fn no_reasoning_field_produces_no_thinking_delta() {
        let mut st = StreamAccumState::new();
        let mut events = Vec::new();
        let chunk1: WireChunk = parse_wire(
            r#"{"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#,
        )
        .unwrap();
        events.extend(st.handle_chunk(chunk1));
        events.extend(st.finish());

        assert!(!events
            .iter()
            .any(|e| matches!(e, StreamEvent::ThinkingDelta { .. })));
        assert!(!events.iter().any(|e| matches!(
            e,
            StreamEvent::BlockStart {
                kind: BlockKind::Thinking,
                ..
            }
        )));
    }

    /// 1つのToolSpecがOpenAIの外部タグ形式（`{type:function,function:{...}}`）へ正しく展開されること。
    #[test]
    fn tool_spec_expands_to_external_function_tag() {
        let req = CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![ToolSpec {
                name: "read_file".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            tool_choice: ToolChoice::Auto,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "gpt-test".to_string(),
        };
        let wire = to_wire_request(&req);
        let value = serde_json::to_value(&wire).unwrap();
        assert_eq!(value["tools"][0]["type"], "function");
        assert_eq!(value["tools"][0]["function"]["name"], "read_file");
        assert_eq!(value["tool_choice"], "auto");
    }

    /// assistantのtool_use + 後続userのtool_resultが、OpenAIの
    /// `role:assistant,tool_calls` / `role:tool,tool_call_id` へ正しく分解されること
    /// （§プロバイダ抽象「結果はrole:tool+tool_call_id」）。
    #[test]
    fn tool_use_and_tool_result_expand_to_separate_wire_messages() {
        let req = CompletionRequest {
            system: vec![],
            messages: vec![
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "read_file".to_string(),
                        input: serde_json::json!({"path": "a.txt"}),
                    }],
                },
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call_1".to_string(),
                        content: "file contents".to_string(),
                        is_error: false,
                    }],
                },
            ],
            tools: vec![ToolSpec {
                name: "read_file".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            tool_choice: ToolChoice::Auto,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "gpt-test".to_string(),
        };
        let wire = to_wire_request(&req);
        let value = serde_json::to_value(&wire).unwrap();
        let messages = value["messages"].as_array().unwrap();

        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["tool_calls"][0]["id"], "call_1");
        assert_eq!(
            messages[0]["tool_calls"][0]["function"]["name"],
            "read_file"
        );
        assert_eq!(
            messages[0]["tool_calls"][0]["function"]["arguments"],
            r#"{"path":"a.txt"}"#
        );

        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "call_1");
        assert_eq!(messages[1]["content"], "file contents");
    }
}
