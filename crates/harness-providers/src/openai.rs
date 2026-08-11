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

use std::time::Duration;

use async_stream::try_stream;
use async_trait::async_trait;
use eventsource_stream::Eventsource;
use futures::stream::{BoxStream, StreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, OutputContract,
    ProviderCapabilities, ProviderError, Role, StopReason, StreamEvent, ToolChoice, ToolSpec,
    Usage,
};

const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_LMSTUDIO_BASE_URL: &str = "http://localhost:1234/v1";

/// `HARNESS_WIRE_LOG=<path>`が設定されているときだけ、送信リクエストボディと受信SSEチャンクを
/// そのままJSONL追記する（`run_shell`不安定性調査、Phase 2観測基盤）。実体は
/// `harness_core::wire_log`が持つ（3箇所で同じ追記処理を持たないため、規則5）。
use harness_core::wire_log::{append as wire_log_append, path as wire_log_path};

/// 同じChat Completionsワイヤ形式を話すが、**能力表明が違う**系統。
///
/// `plans/DESIGN.md` §構造化出力: LMStudioのスキーマ強制はllama.cppのgrammar制約デコードで
/// 実現されるため`tools`と併用できない（`schema xor tools`）。一方OpenAI Chat Completionsは
/// 【T7】の通り`tools`と`response_format:json_schema`を併用できる。`ContextAssembler`は
/// この差を`ProviderCapabilities.schema_with_tools`で見てコール分割の要否を決めるので、
/// 同一アダプタでも系統を区別する必要がある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAiFamily {
    OpenAi,
    LmStudio,
}

pub struct OpenAiProvider {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
    family: OpenAiFamily,
    /// LM Studio 管理REST API（`/api/v1/`）のBearerトークン。`harness-cli`の起動処理が
    /// `LM_API_TOKEN`環境変数から読んで渡す（§設定とシークレット「シークレットはenv優先、
    /// 設定ファイルでは扱わない」）。
    ///
    /// この開発機のLM Studioでは`/api/v1/`も`/v1/`も認証不要だったため（2026-08-04実測、
    /// `tools/lmstudio_mgmt_probe.py`）、通常は`None`のまま動く。トークンを要求する構成の
    /// ために口だけ用意してある。
    mgmt_token: Option<String>,
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
            family: OpenAiFamily::OpenAi,
            mgmt_token: None,
        }
    }

    /// LM Studio 管理APIのトークンを設定する（`harness-cli`が`LM_API_TOKEN`から読む）。
    pub fn with_mgmt_token(mut self, token: Option<String>) -> Self {
        self.mgmt_token = token.filter(|t| !t.is_empty());
        self
    }

    /// 管理REST APIのbase URL。`base_url`末尾の`/v1`を`/api/v1`へ置換して導出する
    /// （`plans/DESIGN-COGNITION.md` §11.5）。OpenAI互換の`/v1/`とは別系統。
    fn mgmt_base_url(&self) -> String {
        let trimmed = self.base_url.trim_end_matches('/');
        match trimmed.strip_suffix("/v1") {
            Some(root) => format!("{root}/api/v1"),
            // `/v1`で終わらない形の`base_url`が渡されたら、素直に足す。
            None => format!("{trimmed}/api/v1"),
        }
    }

    /// §設定「LMStudio は単に `base_url=http://localhost:1234/v1` の openai-family プロファイル」。
    /// LMStudioは認証不要のため空キーで構わない（§プロバイダ抽象「LMStudioは空キー可」）。
    ///
    /// `id()`は`"openai"`のまま変えない（`--provider`の解決・既存ログの互換）。違うのは
    /// [`OpenAiFamily`]に基づく能力表明だけ。
    pub fn lmstudio() -> Self {
        Self {
            family: OpenAiFamily::LmStudio,
            ..Self::with_base_url(String::new(), DEFAULT_LMSTUDIO_BASE_URL.to_string())
        }
    }

    /// LMStudioのbase_urlを差し替える（実機テスト用）。系統は`LmStudio`のまま。
    pub fn lmstudio_with_base_url(base_url: String) -> Self {
        Self {
            family: OpenAiFamily::LmStudio,
            ..Self::with_base_url(String::new(), base_url)
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
        // 構造化出力の写像はここで決まる（`harness_core::schema`が唯一の判断点）。
        // `req.output`が`None`のときは`req`を一切書き換えないので、既存の全経路は不変。
        let mut req = req;
        let strategy = harness_core::apply_schema_strategy(&mut req, &self.capabilities());
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

    /// 縮退ガードの回復の梯子 (d) 段（`plans/DESIGN-COGNITION.md` §11.5）。
    /// **LM Studio 系統でのみ実装**し、OpenAIクラウドでは`false`を返して段を飛ばさせる。
    ///
    /// LM Studio 公式REST API（`/api/v1/`、OpenAI互換の`/v1/`とは別系統）で
    /// models → unload → load を行う。**外部プロセスは一切起動しない**——プロバイダが既に
    /// 喋っている同じ host:port へのHTTPコールが増えるだけなので、`settings.json`の
    /// 権限クラスもプロセス起動経路も変わらない。
    ///
    /// # ロード設定を捕捉して復元する理由
    ///
    /// `load`のボディには`context_length`/`eval_batch_size`/`flash_attention`/`num_experts`/
    /// `offload_kv_cache_to_gpu`がある。`model`だけ渡すと LM Studio 側の既定・プリセットで
    /// 静かに別設定になり得る。**「縮退から回復したはずが、以後ずっとコンテキスト長が違う」
    /// という追跡困難な二次故障**になるため、捕捉した設定をそのまま送り、エコーと照合して
    /// 食い違えば`Err`で止める（fail-closed。梯子は最終段へ落ちる）。
    ///
    /// これは縮約側（`plans/PLAN-COMPACTION.md`）との責務境界そのものでもある——
    /// **分母（`context_window`）の正しさは縮約側、その不変性はここ**。
    async fn recycle(&self, model: &str) -> Result<bool, ProviderError> {
        if self.family != OpenAiFamily::LmStudio {
            return Ok(false);
        }
        let mgmt = self.mgmt_base_url();
        let captured = self.capture_load_config(&mgmt, model).await?;
        let Some((instance_id, load_config)) = captured else {
            // ロードされていないモデルは再ロードのしようがない（JITロード構成）。
            // 段を飛ばして次へ進ませる。
            return Ok(false);
        };

        self.mgmt_post(
            &mgmt,
            "models/unload",
            &serde_json::json!({ "instance_id": instance_id }),
        )
        .await?;

        let mut body = match &load_config {
            // 捕捉できた設定をそのまま復元する。
            Some(cfg) => cfg.clone(),
            // 取得できない場合は`model`のみでロードし、エコーの結果をログへ出す
            // （保証はできないが沈黙はしない、§11.5）。
            None => serde_json::Map::new().into(),
        };
        let obj = body
            .as_object_mut()
            .ok_or_else(|| ProviderError::InvalidRequest {
                msg: "lmstudio load config was not a JSON object".to_string(),
            })?;
        obj.insert("model".to_string(), serde_json::Value::String(model.into()));
        obj.insert(
            "echo_load_config".to_string(),
            serde_json::Value::Bool(true),
        );

        let echoed = self.mgmt_post(&mgmt, "models/load", &body).await?;
        let echoed_config = echoed.get("load_config");
        harness_core::wire_log::record(|| {
            serde_json::json!({
                "kind": "lmstudio_recycle",
                "model": model,
                "captured_load_config": load_config,
                "echoed_load_config": echoed_config,
            })
        });

        if let (Some(want), Some(got)) = (&load_config, echoed_config) {
            if let Some(diff) = first_load_config_mismatch(want, got) {
                return Err(ProviderError::InvalidRequest {
                    msg: format!(
                        "lmstudio reloaded `{model}` with a different load config ({diff}); \
                         refusing to continue because the context window would silently diverge \
                         from what compaction assumes (plans/DESIGN-COGNITION.md §11.5)"
                    ),
                });
            }
        }
        Ok(true)
    }

    /// 実`n_ctx`をLM Studioの管理REST APIから取る（縮約の分母、`plans/PLAN-COMPACTION.md`）。
    ///
    /// 見るのは`GET /api/v1/models`の`loaded_instances[].config.context_length`——(d)段の
    /// [`OpenAiProvider::recycle`]が「再ロードで変わってはいけない値」として捕捉・照合している
    /// のと**同じフィールド**である。同じ値を2つの経路が別々に取りに行かないよう、取得は
    /// [`OpenAiProvider::capture_load_config`]を共用する（規則5）。
    ///
    /// fail-soft: 到達できない・ロードされていない・形が違うなら`None`を返し、呼び出し側は
    /// `capabilities().context_window`へ落ちる。
    async fn detect_context_window(&self, model: &str) -> Option<u32> {
        if self.family != OpenAiFamily::LmStudio {
            return None;
        }
        let mgmt = self.mgmt_base_url();
        // `Err`（到達不能・`models`配列が無い等）も「分からない」に畳む。
        let (_, config) = self.capture_load_config(&mgmt, model).await.ok()??;
        context_length_of(config.as_ref()?)
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: true,
            forced_tool_choice: true,
            schema_with_thinking: true,
            // LMStudio（llama.cppのgrammar制約デコード）はスキーマとツールを併用できない。
            schema_with_tools: self.family == OpenAiFamily::OpenAi,
            prompt_caching: true,
            context_window: 128_000,
            // LMStudioの実`n_ctx`はロード設定依存でこの128,000とは一致しない。実測値へ寄せるのは
            // `settings.json`の`compaction.context_window`／`--context-window`の役目で、ここは
            // 「ローカルである」ことの表明だけを担う（`plans/PLAN-COMPACTION.md`）。
            local: self.family == OpenAiFamily::LmStudio,
        }
    }
}

// --- LM Studio 管理REST API（§11.5、(d)段） ---

/// ロード設定から実`n_ctx`を読む。
///
/// **`config.context_length`は「1リクエストが使えるコンテキスト長」として扱う。** 同じconfigには
/// `parallel`（同時スロット数）もあり、LM Studioがこの2つを掛けてKVを確保するのか割るのかは
/// 実測していない。掛け算を推測で入れると分母が実態と2倍以上ずれるので**そのまま使い**、
/// 検出値は起動時に出す（違っていればユーザーが`compaction.context_window`で上書きできる）。
fn context_length_of(config: &serde_json::Value) -> Option<u32> {
    let n = config.get("context_length")?.as_u64()?;
    u32::try_from(n).ok().filter(|n| *n > 0)
}

/// `load`のエコーと照合しないキー。
///
/// `prompt_template`は`GET /api/v1/models`の`loaded_instances[].config`には**含まれないが**、
/// `POST /models/load`の`echo_load_config`応答には含まれる（2026-08-04実測、
/// `tools/lmstudio_mgmt_probe.py`）。捕捉できない値を照合対象にすると必ず食い違うため除外する。
const UNCOMPARED_LOAD_KEYS: &[&str] = &["prompt_template"];

impl OpenAiProvider {
    /// 対象モデルのロード済みインスタンスIDと現在のロード設定を取る。
    /// ロードされていなければ`None`。
    async fn capture_load_config(
        &self,
        mgmt: &str,
        model: &str,
    ) -> Result<Option<(String, Option<serde_json::Value>)>, ProviderError> {
        let body = self.mgmt_get(mgmt, "models").await?;
        let models = body
            .get("models")
            .and_then(|m| m.as_array())
            .ok_or_else(|| ProviderError::InvalidRequest {
                msg: "lmstudio management API returned no `models` array".to_string(),
            })?;
        for m in models {
            if m.get("key").and_then(|k| k.as_str()) != Some(model) {
                continue;
            }
            let Some(instances) = m.get("loaded_instances").and_then(|i| i.as_array()) else {
                continue;
            };
            let Some(first) = instances.first() else {
                continue;
            };
            let id = first
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or(model)
                .to_string();
            return Ok(Some((id, first.get("config").cloned())));
        }
        Ok(None)
    }

    async fn mgmt_get(&self, mgmt: &str, path: &str) -> Result<serde_json::Value, ProviderError> {
        let mut req = self.http.get(format!("{mgmt}/{path}"));
        if let Some(t) = &self.mgmt_token {
            req = req.bearer_auth(t);
        }
        Self::mgmt_send(req).await
    }

    async fn mgmt_post(
        &self,
        mgmt: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        let mut req = self.http.post(format!("{mgmt}/{path}")).json(body);
        if let Some(t) = &self.mgmt_token {
            req = req.bearer_auth(t);
        }
        Self::mgmt_send(req).await
    }

    async fn mgmt_send(req: reqwest::RequestBuilder) -> Result<serde_json::Value, ProviderError> {
        let resp = req
            .send()
            .await
            .map_err(|_| ProviderError::Transport { retriable: false })?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ProviderError::Api {
                status: status.as_u16(),
                code: Some(truncate_for_message(&text)),
            });
        }
        // `unload`のように本文が空の応答もある。空はnullとして扱う。
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| ProviderError::Transport { retriable: false })
    }
}

/// 捕捉したロード設定とエコーされた設定の**最初の食い違い**を人間可読な1行で返す。
///
/// 等値比較ではなく**捕捉したキーだけの部分比較**にしているのは、エコー側にしか無いキーが
/// 実在するため（[`UNCOMPARED_LOAD_KEYS`]のコメント参照）。エコー側の追加キーは無視し、
/// 「こちらが指定した設定が守られたか」だけを見る。
fn first_load_config_mismatch(want: &serde_json::Value, got: &serde_json::Value) -> Option<String> {
    let want = want.as_object()?;
    let got = got.as_object()?;
    for (k, v) in want {
        if UNCOMPARED_LOAD_KEYS.contains(&k.as_str()) {
            continue;
        }
        match got.get(k) {
            Some(actual) if actual == v => {}
            Some(actual) => return Some(format!("{k}: requested {v}, got {actual}")),
            None => return Some(format!("{k}: requested {v}, missing from the echo")),
        }
    }
    None
}

fn truncate_for_message(s: &str) -> String {
    harness_core::text::truncate_head_tail(s, 200)
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
    /// 縮退ガードの回復の梯子 (b) 段だけが載せる（`plans/DESIGN-COGNITION.md` §11.3）。
    /// 通常のターンでは`Sampling`が`None`のままなので、送信ボディは1バイトも変わらない。
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<WireTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    /// 構造化出力のネイティブ強制（`plans/DESIGN.md` §構造化出力）。降格経路
    /// （ツール強制・プロンプト埋込）では`harness_core::apply_schema_strategy`が
    /// `req.output`を`None`にしてから来るので、ここは常に`None`になる。
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<serde_json::Value>,
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
        frequency_penalty: req.sampling.frequency_penalty,
        presence_penalty: req.sampling.presence_penalty,
        tools,
        tool_choice,
        parallel_tool_calls: req.parallel_tool_calls,
        response_format: req.output.as_ref().map(output_contract_to_wire),
    }
}

/// `OutputContract`をChat Completionsの`response_format`へ写す
/// （`plans/DESIGN.md` §構造化出力「OpenAI / LMStudio」行）。
fn output_contract_to_wire(output: &OutputContract) -> serde_json::Value {
    match output {
        OutputContract::JsonSchema {
            name,
            schema,
            strict,
        } => serde_json::json!({
            "type": "json_schema",
            "json_schema": { "name": name, "strict": strict, "schema": schema },
        }),
        OutputContract::JsonObject => serde_json::json!({ "type": "json_object" }),
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

    fn schema_request(output: Option<OutputContract>) -> CompletionRequest {
        CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "gpt-test".to_string(),
        }
    }

    /// 契約テスト（`plans/DESIGN.md` §主なリスクと対策「structured output の3プロバイダ写像」の
    /// native経路）。`OutputContract::JsonSchema`が`response_format`のネイティブ形式になる。
    #[test]
    fn json_schema_contract_becomes_native_response_format() {
        let req = schema_request(Some(OutputContract::JsonSchema {
            name: "hypothesize_output".to_string(),
            schema: serde_json::json!({ "type": "object", "additionalProperties": false }),
            strict: true,
        }));
        let value = serde_json::to_value(to_wire_request(&req)).unwrap();

        assert_eq!(value["response_format"]["type"], "json_schema");
        assert_eq!(
            value["response_format"]["json_schema"]["name"],
            "hypothesize_output"
        );
        assert_eq!(value["response_format"]["json_schema"]["strict"], true);
        assert_eq!(
            value["response_format"]["json_schema"]["schema"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn json_object_contract_becomes_loose_json_mode() {
        let req = schema_request(Some(OutputContract::JsonObject));
        let value = serde_json::to_value(to_wire_request(&req)).unwrap();
        assert_eq!(
            value["response_format"],
            serde_json::json!({"type": "json_object"})
        );
    }

    /// 契約が無いリクエストには`response_format`キー自体が現れない（既存の全経路が
    /// ワイヤ形式レベルで不変であることの担保）。
    #[test]
    fn no_contract_omits_response_format_entirely() {
        let value = serde_json::to_value(to_wire_request(&schema_request(None))).unwrap();
        assert!(
            value.get("response_format").is_none(),
            "response_format must be absent, got {value}"
        );
    }

    /// LMStudioはgrammar制約デコードのためスキーマとツールを併用できない
    /// （`plans/DESIGN.md` §構造化出力）。`ContextAssembler`がコール分割の要否を
    /// この能力表明で決めるので、系統ごとの差をここで固定する。
    #[test]
    fn lmstudio_declares_that_schema_and_tools_cannot_be_combined() {
        assert!(!OpenAiProvider::lmstudio().capabilities().schema_with_tools);
        assert!(OpenAiProvider::new("k").capabilities().schema_with_tools);
        // 併用不可なだけで、スキーマ強制自体は使える（llama.cppのgrammar）。
        assert!(OpenAiProvider::lmstudio().capabilities().native_json_schema);
        // id()は系統で変えない（`--provider`解決・既存ログの互換）。
        assert_eq!(OpenAiProvider::lmstudio().id(), "openai");
    }

    /// 実機E2E（LMStudio）: `response_format:json_schema`が**実際に効いているか**を確かめる。
    ///
    /// llama.cppのgrammar制約デコードはトークン生成そのものを縛るため、プロンプトでお願いする
    /// 場合と違い小型モデルでもスキーマから外れられない。認知レイヤーの全フェーズがこれに
    /// 依存する（`plans/DESIGN-COGNITION.md` §3.4）ので、cheap層にローカルモデルを割り当てる
    /// M17の前提として一度は実機で確認しておく。
    ///
    /// 実行: LMStudioサーバを起動した状態で
    /// `cargo test -p harness-providers -- --ignored --nocapture lmstudio_enforces`
    #[tokio::test]
    #[ignore = "requires a running LMStudio server on localhost:1234"]
    async fn lmstudio_enforces_json_schema_natively() {
        use futures::StreamExt as _;

        let provider = OpenAiProvider::lmstudio();
        let req = CompletionRequest {
            system: vec![],
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text(
                    "テストが落ちる原因の仮説を1つ立てよ。".to_string(),
                )],
            }],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: Some(OutputContract::JsonSchema {
                name: "hypothesize_output".to_string(),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "statement": { "type": "string" },
                        "predicts": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["statement", "predicts"],
                    "additionalProperties": false
                }),
                strict: true,
            }),
            parallel_tool_calls: None,
            max_tokens: 512,
            sampling: Default::default(),
            model: String::new(), // LMStudioはロード済みモデルへフォールバックする
        };

        let mut stream = provider.stream(req).await.expect("stream");
        let mut text = String::new();
        while let Some(ev) = stream.next().await {
            if let StreamEvent::TextDelta { text: t, .. } = ev.expect("stream event") {
                text.push_str(&t);
            }
        }

        println!("LMStudio raw output: {text}");
        let value: serde_json::Value =
            serde_json::from_str(text.trim()).expect("output must be parseable JSON");
        assert!(value["statement"].is_string(), "{value}");
        assert!(value["predicts"].is_array(), "{value}");
        assert_eq!(
            value.as_object().map(|o| o.len()),
            Some(2),
            "additionalProperties:false should keep the object to the declared keys: {value}"
        );
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

    // --- 実`n_ctx`の自動検出（縮約の分母、`plans/PLAN-COMPACTION.md`） ---

    /// この開発機のLM Studio 0.4.20が実際に返した`GET /api/v1/models`の該当部分
    /// （2026-08-06実測。`parallel`が同居していることも含めて写してある）。
    fn loaded_instance_config() -> serde_json::Value {
        serde_json::json!({
            "context_length": 262_144,
            "eval_batch_size": 2_048,
            "physical_batch_size": 512,
            "parallel": 4,
            "flash_attention": true,
            "num_experts": 8,
            "offload_kv_cache_to_gpu": true
        })
    }

    #[test]
    fn the_context_length_comes_from_the_load_config() {
        assert_eq!(context_length_of(&loaded_instance_config()), Some(262_144));
    }

    /// `parallel`は**掛けも割りもしない**。LM Studioがこの2つをどう使ってKVを確保するかは
    /// 未実測で、推測で係数を入れると分母が2倍以上ずれる（`context_length_of`のdoc参照）。
    #[test]
    fn the_parallel_slot_count_does_not_scale_the_denominator() {
        let mut config = loaded_instance_config();
        config["parallel"] = serde_json::json!(8);
        assert_eq!(context_length_of(&config), Some(262_144));
    }

    /// 形が違う・欠けている・0はすべて「分からない」に畳む（呼び出し側がcapabilityへ落ちる）。
    #[test]
    fn a_missing_or_unusable_context_length_is_not_guessed() {
        assert_eq!(context_length_of(&serde_json::json!({})), None);
        assert_eq!(
            context_length_of(&serde_json::json!({ "context_length": 0 })),
            None
        );
        assert_eq!(
            context_length_of(&serde_json::json!({ "context_length": "262144" })),
            None,
            "文字列は数として読まない（黙って0や巨大値へ化けるより分からない方が安全）"
        );
        assert_eq!(
            context_length_of(&serde_json::json!({ "context_length": 5_000_000_000u64 })),
            None,
            "u32に収まらない値も拒否する"
        );
    }

    /// クラウドのOpenAIでは問い合わせに行かない（管理APIが無いので毎起動で無駄な失敗をする）。
    #[tokio::test]
    async fn the_openai_family_never_probes_for_a_context_window() {
        let provider = OpenAiProvider::new("key");
        assert_eq!(provider.detect_context_window("gpt-4o").await, None);
    }

    // --- 縮退ガードの (d) 段（`plans/DESIGN-COGNITION.md` §11.5） ---

    /// 管理APIのbase URLは`base_url`末尾の`/v1`を`/api/v1`へ置換して導く。
    /// OpenAI互換の`/v1/`とは別系統であることの固定。
    #[test]
    fn the_management_base_url_is_derived_from_the_openai_compatible_one() {
        assert_eq!(
            OpenAiProvider::lmstudio().mgmt_base_url(),
            "http://localhost:1234/api/v1"
        );
        assert_eq!(
            OpenAiProvider::lmstudio_with_base_url("http://host:9999/v1/".into()).mgmt_base_url(),
            "http://host:9999/api/v1"
        );
        // `/v1`で終わらない形でも壊れない。
        assert_eq!(
            OpenAiProvider::lmstudio_with_base_url("http://host:9999".into()).mgmt_base_url(),
            "http://host:9999/api/v1"
        );
    }

    /// **ロード設定の照合は部分比較**。`prompt_template`は`GET /models`側に含まれず
    /// `load`のエコー側にしか無いため（2026-08-04実測）、等値比較にすると必ず食い違う。
    #[test]
    fn the_load_config_check_ignores_keys_that_only_the_echo_carries() {
        let captured = serde_json::json!({ "context_length": 262144, "num_experts": 8 });
        let echoed = serde_json::json!({
            "context_length": 262144,
            "num_experts": 8,
            "prompt_template": { "type": "jinja", "template": "..." },
            "physical_batch_size": 512,
        });
        assert_eq!(first_load_config_mismatch(&captured, &echoed), None);
    }

    /// **食い違いは fail-closed**。再ロードでコンテキスト長が変われば、縮約の分母が実態と
    /// 乖離して「追跡困難な二次故障」になるため、黙って進めない。
    #[test]
    fn a_changed_context_length_is_reported_as_a_mismatch() {
        let captured = serde_json::json!({ "context_length": 262144 });
        let echoed = serde_json::json!({ "context_length": 8192 });
        let diff = first_load_config_mismatch(&captured, &echoed).expect("mismatch");
        assert!(diff.contains("context_length"), "{diff}");
        assert!(diff.contains("262144"), "{diff}");
        assert!(diff.contains("8192"), "{diff}");

        // エコーからキーごと落ちた場合も食い違いとして扱う（守られた保証が無い）。
        let dropped = first_load_config_mismatch(&captured, &serde_json::json!({}))
            .expect("a missing key is a mismatch");
        assert!(dropped.contains("missing from the echo"), "{dropped}");
    }

    /// 非LMStudio系統では (d) 段を持たない＝`false`を返して梯子に飛ばさせる。
    #[tokio::test]
    async fn recycling_is_not_supported_outside_lmstudio() {
        let p = OpenAiProvider::new("key");
        assert!(!p.recycle("gpt-4o").await.unwrap());
    }

    /// **実機E2E**（`docs/DEV-ENVIRONMENT.md`のLMStudioサーバが要る、`#[ignore]`）。
    ///
    /// `plans/DESIGN-COGNITION.md` §11.5 の手順（models → unload → load + echo照合）を
    /// 実サーバに対して1往復させ、**再ロードの前後でロード設定が変わらない**ことを確認する。
    /// これがM21の実機E2E受入条件の3番目（`docs/INDEX.md`）。
    ///
    /// ```bash
    /// cargo test -p harness-providers -- --ignored lmstudio_recycle
    /// ```
    ///
    /// 対象モデルがロードされていない場合は`Ok(false)`（段を飛ばす）が正しい挙動なので、
    /// そのときはテストを成立させずに理由を出して終える。
    #[tokio::test]
    #[ignore = "requires a running LM Studio server with the model loaded"]
    async fn lmstudio_recycle_preserves_the_load_config() {
        const MODEL: &str = "luffythefox/qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp-gguf/qwen3.6-35b-a3b-uncensored-genesis-mtp-apex.gguf";
        let p = OpenAiProvider::lmstudio();
        let mgmt = p.mgmt_base_url();

        let Some((_, before)) = p.capture_load_config(&mgmt, MODEL).await.unwrap() else {
            eprintln!("skipped: `{MODEL}` is not loaded in LM Studio");
            return;
        };
        let before = before.expect("the management API should report the load config");

        // 照合に失敗すれば`Err`になる（fail-closed）。成功＝設定が守られた。
        assert!(
            p.recycle(MODEL).await.unwrap(),
            "reload should be supported"
        );

        let (_, after) = p
            .capture_load_config(&mgmt, MODEL)
            .await
            .unwrap()
            .expect("the model must be loaded again after a recycle");
        let after = after.expect("the management API should report the load config");
        assert_eq!(
            first_load_config_mismatch(&before, &after),
            None,
            "before={before}\nafter={after}"
        );
        // 縮約の分母そのもの。ここが変わると使用率判定が実態と乖離する
        // （`plans/PLAN-COMPACTION.md`「M21との接点」の責務境界）。
        assert_eq!(before["context_length"], after["context_length"]);
    }

    /// (b) 段が載せるペナルティはOpenAI系のワイヤへ写る。**通常のターンでは
    /// `Sampling`が`None`のままなので、送信ボディは1バイトも変わらない**。
    #[test]
    fn the_recovery_penalties_map_to_the_wire_only_when_set() {
        let mut req = CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Default::default(),
            model: "m".into(),
        };
        let plain = serde_json::to_value(to_wire_request(&req)).unwrap();
        assert!(plain.get("frequency_penalty").is_none(), "{plain}");
        assert!(plain.get("presence_penalty").is_none(), "{plain}");

        req.sampling.frequency_penalty = Some(0.4);
        req.sampling.presence_penalty = Some(0.4);
        let jittered = serde_json::to_value(to_wire_request(&req)).unwrap();
        // f32→JSON数値の丸めがあるので値そのものではなく近さで見る。
        for key in ["frequency_penalty", "presence_penalty"] {
            let v = jittered[key]
                .as_f64()
                .unwrap_or_else(|| panic!("{key}: {jittered}"));
            assert!((v - 0.4).abs() < 1e-6, "{key} = {v}");
        }
    }
}
