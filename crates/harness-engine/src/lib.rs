//! harness-engine: 中核ループの入口。`plans/DESIGN.md` §エージェントループ参照。
//!
//! M3で `run_single_turn`（単発ターン、M2まで）に加え `run_agent_loop` を追加した。
//! M4で `PermissionArbiter`（§パーミッション（承認）システム）を実装し、`run_agent_loop`が
//! 各`ToolUse`の実行前に必ず問い合わせるようにした（§エージェントループ「唯一の強制点」）。
//! 拒否されたツール呼び出しは実行されず、エラーの`ToolResult`を合成して履歴へ積み戻す
//! （§エージェントループ 手順4「拒否→エラーToolResultを合成」）。
//! **M4時点のスコープ外**: cap-stdによる読取スコープ反転モード（whitelist/blacklist、M11）・
//! 対話TUIの承認モーダル（M7、そのため`decide`は常にヘッドレス相当で決定的に判定する）。
//! M9で キャンセル整合・コンテキスト圧縮（`compaction`モジュール）・大出力切詰め・
//! リトライ/リアクティブ圧縮・JSONLセッション永続化（`session`モジュール）を追加した。

pub mod compaction;
pub mod permission;
pub mod session;

use std::time::Duration;

use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError,
    Role, Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, ToolCtx, ToolOutput, Usage,
};
use harness_tools::ToolRegistry;

pub use permission::{
    arg_repr, parse_allowlist_rule, AllowlistRule, Classification, Decision, PermissionArbiter,
    PermissionGate, PermissionMode,
};
pub use session::{SessionStore, SessionSummary};

/// TUI等のフロントエンドへ`AgentEvent`を流すための送信口。ヘッドレスCLIは`None`を渡し
/// 従来通り`on_text_delta`コールバックのみでstdout出力する（§非対話モード、既存挙動を維持）。
pub type EventSink = tokio::sync::mpsc::UnboundedSender<AgentEvent>;

fn emit(events: Option<&EventSink>, ev: AgentEvent) {
    if let Some(tx) = events {
        let _ = tx.send(ev);
    }
}

/// ツール出力がこれを超える文字数なら頭尾切詰めする（M9、DESIGN.md L349「大出力 head+tail
/// 切詰め」）。会話履歴に積む前に適用するため、モデルへ送るコンテキスト自体を圧迫しない。
const MAX_TOOL_OUTPUT_CHARS: usize = 8_000;

/// `content`が`max_chars`文字を超える場合、先頭/末尾を残し中間を省略記号に置き換える。
fn truncate_head_tail(content: &str, max_chars: usize) -> String {
    let total = content.chars().count();
    if total <= max_chars {
        return content.to_string();
    }
    let half = max_chars / 2;
    let head: String = content.chars().take(half).collect();
    let tail: String = content.chars().skip(total - half).collect();
    let omitted = total - 2 * half;
    format!("{head}\n... [{omitted} chars truncated] ...\n{tail}")
}

/// リクエスト全体（system+messages+tools）をJSONシリアライズした文字数からの粗い近似
/// （chars/4）。`AgentEvent::TurnStarted.estimated_input_tokens`用（TUIのリアルタイム表示、
/// §リッチTUI「ライブ表示」）。プロバイダの正確なinputトークン数は`TurnCompleted`の
/// `usage.input`でしか分からないため、送信直後にひとまず出す概算値に過ぎない。
fn estimate_tokens(req: &CompletionRequest) -> u64 {
    serde_json::to_string(req)
        .map(|s| (s.chars().count() as u64) / 4)
        .unwrap_or(0)
}

pub(crate) fn sanitize_completion_request_for_tier3(req: &mut CompletionRequest) {
    for block in &mut req.system {
        sanitize_string(&mut block.text);
    }
    sanitize_messages_for_tier3(&mut req.messages);
    for tool in &mut req.tools {
        sanitize_string(&mut tool.description);
        sanitize_json_value(&mut tool.input_schema);
    }
}

fn sanitize_messages_for_tier3(messages: &mut [Message]) {
    for msg in messages {
        sanitize_content_blocks_for_tier3(&mut msg.content);
    }
}

fn sanitize_content_blocks_for_tier3(blocks: &mut Vec<ContentBlock>) {
    blocks.retain_mut(|block| match block {
        ContentBlock::Text(text) => {
            sanitize_string(text);
            true
        }
        ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. } => false,
        ContentBlock::ToolUse {
            id: _,
            name: _,
            input,
        } => {
            sanitize_json_value(input);
            true
        }
        ContentBlock::ToolResult { content, .. } => {
            sanitize_string(content);
            true
        }
        ContentBlock::Image { .. } => true,
    });
}

fn sanitize_tool_output_for_tier3(output: &mut ToolOutput) {
    sanitize_string(&mut output.content);
}

fn sanitize_visible_delta_for_tier3(text: &str, ctx: &ToolCtx) -> String {
    if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
        redact_windows_absolute_paths(text)
    } else {
        text.to_string()
    }
}

fn sanitize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => sanitize_string(s),
        serde_json::Value::Array(items) => {
            for item in items {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_key, value) in map {
                sanitize_json_value(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn sanitize_string(s: &mut String) {
    *s = redact_windows_absolute_paths(s);
}

fn redact_windows_absolute_paths(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if is_windows_drive_path_at(&chars, i) {
            out.push_str("/workspace");
            i += 3;
            while i < chars.len() && is_windows_path_char(chars[i]) {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn is_windows_drive_path_at(chars: &[char], i: usize) -> bool {
    i + 2 < chars.len()
        && chars[i].is_ascii_alphabetic()
        && chars[i + 1] == ':'
        && is_windows_separator(chars[i + 2])
}

fn is_windows_separator(c: char) -> bool {
    c == '\\' || c == '/' || c == '¥'
}

fn is_windows_path_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '"' | '\'' | '`' | ')' | '）' | ']' | '】' | '}' | '。' | '、' | ',' | ';' | '|'
        )
}

/// リトライ可能な`ProviderError`（`RateLimited`/`Overloaded`/`Transport{retriable:true}`）かどうか。
/// `ContextTooLong`はここに含めない（呼び出し側でコンテキスト圧縮を挟んでから明示的に再試行する、
/// §主なリスクと対策「分類を確定。外周の共通リトライラッパがこれを見てリトライ可否・待機を決める」）。
fn is_retriable(e: &ProviderError) -> bool {
    matches!(
        e,
        ProviderError::RateLimited { .. }
            | ProviderError::Overloaded
            | ProviderError::Transport { retriable: true }
    )
}

fn retry_delay(e: &ProviderError, attempt: u32) -> Duration {
    if let ProviderError::RateLimited {
        retry_after: Some(d),
    } = e
    {
        return *d;
    }
    Duration::from_millis(200 * 2u64.saturating_pow(attempt))
}

const MAX_RETRIES: u32 = 3;

/// `provider.stream`をリトライ可能なエラーに対して指数バックオフで最大`MAX_RETRIES`回まで
/// 再試行する。`ContextTooLong`はここでは扱わず、そのまま呼び出し側へ伝播する
/// （`run_agent_loop`側でコンテキスト圧縮を挟んだ1回限りの再試行を行う）。
async fn stream_with_retry(
    provider: &dyn LlmProvider,
    req: &CompletionRequest,
) -> Result<futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>
{
    let mut attempt = 0;
    loop {
        match provider.stream(req.clone()).await {
            Ok(s) => return Ok(s),
            Err(e) if attempt < MAX_RETRIES && is_retriable(&e) => {
                tokio::time::sleep(retry_delay(&e, attempt)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// 会話のIR履歴。
///
/// `system`は`ConversationState::new`で必ず渡す（`Default`は導出しない）。かつては
/// 引数無しの`ConversationState::new()`が空`system`を暗黙に作れてしまい、`harness-cli`/
/// `harness-tui`のどこからも実際にsystemを埋めていなかった（`run_shell`不安定性調査で
/// 発覚。モデルがOS・シェル種別・workspace root・シェル隔離Tierの制約を一切知らされて
/// いなかった）。`new`にシグネチャ変更したのは、今後この抜けを黙って再発させないため
/// （`harness_core::prompt`のゲート1/2と同じ「フィールド追加/呼び出し追加を強制コンパイル
/// エラーで検出する」設計方針）。
#[derive(Debug, Clone)]
pub struct ConversationState {
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
}

impl ConversationState {
    pub fn new(system: Vec<SystemBlock>) -> Self {
        Self {
            system,
            messages: Vec::new(),
        }
    }

    pub fn push_user_text(&mut self, text: impl Into<String>) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.into())],
        });
    }
}

/// `ToolCtx`が運ぶ環境事実（`harness_core::EnvironmentFacts`）から`SystemBlock`列を組み立てる。
/// `ConversationState::new`へ渡すsystemの、`harness-cli`/`harness-tui`共通の唯一の組み立て元
/// （個々のフロントエンドが独自にプロンプト文字列を書かないようにするため）。
pub fn system_blocks_for(ctx: &ToolCtx) -> Vec<SystemBlock> {
    let facts = harness_core::EnvironmentFacts::from_tool_ctx(ctx);
    vec![SystemBlock {
        text: harness_core::render_environment_prompt(&facts),
        cache: true,
    }]
}

/// 1ターン分の結果。テキスト・停止理由・使用トークン量を蓄積したもの。
#[derive(Debug, Clone)]
pub struct TurnOutcome {
    pub text: String,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

/// 1プロバイダターンを実行する。ツール呼び出しへのディスパッチ・継続ループは
/// `run_agent_loop` が担う（§エージェントループの「1回のステップ」のうち、
/// ここではステップ1〜3のみを担う）。
/// `on_text_delta` は `StreamEvent::TextDelta` 受信の都度呼ばれる（トークン逐次表示用）。
pub async fn run_single_turn<F>(
    provider: &dyn LlmProvider,
    state: &ConversationState,
    model: String,
    max_tokens: u32,
    mut on_text_delta: F,
) -> Result<TurnOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let req = CompletionRequest {
        system: state.system.clone(),
        messages: state.messages.clone(),
        tools: Vec::new(),
        tool_choice: ToolChoice::Auto,
        output: None,
        parallel_tool_calls: None,
        max_tokens,
        sampling: Sampling::default(),
        model,
    };

    let mut stream = provider.stream(req).await?;
    let mut text = String::new();
    let mut stop_reason = StopReason::EndTurn;
    let mut usage = Usage::default();

    while let Some(event) = stream.next().await {
        match event? {
            StreamEvent::TextDelta { text: delta, .. } => {
                on_text_delta(&delta);
                text.push_str(&delta);
            }
            StreamEvent::Done {
                stop_reason: sr,
                usage: u,
            } => {
                stop_reason = sr;
                usage = u;
            }
            _ => {}
        }
    }

    Ok(TurnOutcome {
        text,
        stop_reason,
        usage,
    })
}

/// `run_agent_loop` の結果。複数ターンにまたがる最終的なテキスト・停止理由・
/// 直近ターンの使用トークン量を返す。
#[derive(Debug, Clone)]
pub struct AgentLoopOutcome {
    pub text: String,
    pub stop_reason: StopReason,
    pub usage: Usage,
    /// キャンセルされて終了した場合`true`（M9）。この場合`text`は空、`stop_reason`は
    /// `StopReason::Other("cancelled")`になる。`state`自体は次の`run_agent_loop`呼び出しが
    /// 400にならない形（tool_use/tool_resultの対応が崩れていない状態）に保たれている。
    pub cancelled: bool,
}

/// ストリーム受信中のブロックを蓄積する作業用構造体。
/// `StreamEvent`はブロック単位に一般化されているため、`BlockStart`〜`BlockStop`の間に届く
/// デルタをindexごとに蓄積し、ストリーム完了後に`ContentBlock`へ組み立てる
/// （§プロバイダ抽象「ブロック単位に一般化」）。
struct BlockAccum {
    index: usize,
    kind: BlockKind,
    text: String,
    signature: Option<String>,
    tool_input_raw: String,
}

/// 引数JSONの連結・パースに失敗した`tool_use`（Phase5-B）。ターン全体を落とさず、
/// `content`へは空入力の`ToolUse`を積んだ上でこの理由を控え、実行はスキップして
/// `is_error`な`tool_result`を合成する（`run_agent_loop`「unknown tool」と同じ扱い）。
struct MalformedToolInput {
    id: String,
    name: String,
    raw: String,
}

impl BlockAccum {
    fn into_content_block(self) -> Result<ContentBlock, MalformedToolInput> {
        match self.kind {
            BlockKind::Text => Ok(ContentBlock::Text(self.text)),
            BlockKind::Thinking => Ok(ContentBlock::Thinking {
                text: self.text,
                signature: self.signature,
            }),
            BlockKind::RedactedThinking => Ok(ContentBlock::RedactedThinking { data: self.text }),
            BlockKind::ToolUse { id, name } => {
                // OpenAIは引数文字列断片・Anthropicは部分JSONオブジェクト断片だが、
                // いずれも連結すれば1つのJSONテキストになるため、BlockStop相当の
                // このタイミングで一度だけパースする（§プロバイダ抽象「ツール引数の正規化」）。
                let input = if self.tool_input_raw.trim().is_empty() {
                    serde_json::Value::Object(Default::default())
                } else {
                    match serde_json::from_str(&self.tool_input_raw) {
                        Ok(v) => v,
                        Err(_) => {
                            return Err(MalformedToolInput {
                                id,
                                name,
                                raw: self.tool_input_raw,
                            })
                        }
                    }
                };
                Ok(ContentBlock::ToolUse { id, name, input })
            }
        }
    }
}

/// `HARNESS_WIRE_LOG=<path>`設定時のみ、ブロック組み立て結果（`tool_input_raw`の連結後文字列と
/// パース成否）をJSONL追記する（`harness-providers::openai`の同名フックと対をなす、
/// `run_shell`不安定性調査のPhase2観測基盤）。未設定時はゼロコスト。
fn wire_log_block_assembly(kind: &str, id: &str, name: &str, raw: &str, ok: bool) {
    let Some(path) = std::env::var_os("HARNESS_WIRE_LOG") else {
        return;
    };
    use std::io::Write as _;
    let value = serde_json::json!({
        "kind": kind,
        "tool_use_id": id,
        "name": name,
        "tool_input_raw": raw,
        "parse_ok": ok,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::path::PathBuf::from(path))
    {
        let _ = writeln!(f, "{value}");
    }
}

/// `run_agent_loop` のターン単位パラメータ。素の引数列だと `clippy::too_many_arguments` に
/// 触れるため1つにまとめた（値自体の意味は各フィールドのコメント通り）。
pub struct AgentLoopConfig {
    pub model: String,
    pub max_tokens: u32,
    /// 暴走ループの保険（`--max-turns` としての正式な設定化はM9のスコープ）。
    pub max_turns: usize,
}

/// 1回のステップ = 1プロバイダターン + 承認済みツール実行（§エージェントループ）を
/// `stop_reason != ToolUse` になるまで繰り返す。`gate`が全ツール呼び出しの実行前に
/// 必ず参照される唯一の強制点で（§パーミッション（承認）システム）、`Decision::Deny`の場合は
/// ツールを実行せずエラーの`ToolResult`を合成する（§エージェントループ 手順4）。
/// `events`が`Some`なら`AgentEvent`をその都度発行する（M7、`harness-tui`の`AppState`が
/// これを畳み込んで描画する。§リッチTUI「`AppState`は`AgentEvent`を畳み込んで更新」）。
#[allow(clippy::too_many_arguments)]
pub async fn run_agent_loop<F>(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    gate: &dyn PermissionGate,
    config: AgentLoopConfig,
    events: Option<&EventSink>,
    cancel: Option<&CancellationToken>,
    mut on_text_delta: F,
) -> Result<AgentLoopOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let tool_specs = tools.to_specs_for_ctx(ctx);

    /// キャンセルによる早期returnの共通形。§エージェントループ「ストリーム途中は部分assistant
    /// 破棄／ツール実行中は全tool_useへcancelled合成」のいずれの経路も、この形の
    /// `AgentLoopOutcome`を返す（`state`は呼び出し側で既に整合が取れる形に調整済み）。
    fn cancelled_outcome() -> AgentLoopOutcome {
        AgentLoopOutcome {
            text: String::new(),
            stop_reason: StopReason::Other("cancelled".to_string()),
            usage: Usage::default(),
            cancelled: true,
        }
    }

    for _ in 0..config.max_turns {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }

        let mut req = CompletionRequest {
            system: state.system.clone(),
            messages: state.messages.clone(),
            tools: tool_specs.clone(),
            tool_choice: if tool_specs.is_empty() {
                ToolChoice::None
            } else {
                ToolChoice::Auto
            },
            output: None,
            // Phase5-D（run_shell不安定性調査）: 並列tool_callを明示的に抑止する。LMStudio実機
            // 観測で、2件目以降の`arguments`断片チャンクが`index`を省略することがあり
            // （`harness-providers::openai::WireToolCallDelta`のコメント参照）、複数tool_callが
            // 同時に開いていると引数JSONの取り違えが起きる。`parallel_tool_calls:false`は
            // プロバイダに1回のターンで最大1個のtool_callしか出させないための一次防御であり、
            // 二次防御としてopenai.rs側も`index`省略時は「直近に開いたブロック」へ倒す
            // （0固定より安全）。
            parallel_tool_calls: Some(false),
            max_tokens: config.max_tokens,
            sampling: Sampling::default(),
            model: config.model.clone(),
        };
        if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
            sanitize_completion_request_for_tier3(&mut req);
        }
        emit(
            events,
            AgentEvent::TurnStarted {
                estimated_input_tokens: estimate_tokens(&req),
            },
        );

        let mut stream = match stream_with_retry(provider, &req).await {
            Ok(s) => s,
            Err(ProviderError::ContextTooLong) => {
                let removed = compaction::compact(
                    provider,
                    state,
                    &config.model,
                    compaction::DEFAULT_KEEP_RECENT_TURNS,
                )
                .await?;
                if removed == 0 {
                    let e = ProviderError::ContextTooLong;
                    emit(
                        events,
                        AgentEvent::Error {
                            message: e.to_string(),
                        },
                    );
                    return Err(e);
                }
                emit(
                    events,
                    AgentEvent::ContextCompacted {
                        removed_messages: removed,
                    },
                );
                let retry_req = CompletionRequest {
                    messages: state.messages.clone(),
                    ..req
                };
                let mut retry_req = retry_req;
                if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
                    sanitize_completion_request_for_tier3(&mut retry_req);
                }
                match stream_with_retry(provider, &retry_req).await {
                    Ok(s) => s,
                    Err(e) => {
                        emit(
                            events,
                            AgentEvent::Error {
                                message: e.to_string(),
                            },
                        );
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                emit(
                    events,
                    AgentEvent::Error {
                        message: e.to_string(),
                    },
                );
                return Err(e);
            }
        };
        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();

        loop {
            let next = match cancel {
                Some(c) => tokio::select! {
                    _ = c.cancelled() => None,
                    ev = stream.next() => Some(ev),
                },
                None => Some(stream.next().await),
            };
            let Some(event) = next else {
                // ストリーム途中でキャンセルされた: 蓄積中のblocksはstateへ一切pushせず破棄する
                // （§エージェントループ キャンセル整合「ストリーム途中は部分assistant破棄」）。
                emit(events, AgentEvent::Cancelled);
                return Ok(cancelled_outcome());
            };
            let Some(event) = event else {
                break;
            };
            let event = match event {
                Ok(e) => e,
                Err(e) => {
                    emit(
                        events,
                        AgentEvent::Error {
                            message: e.to_string(),
                        },
                    );
                    return Err(e);
                }
            };
            match event {
                StreamEvent::BlockStart { index, kind } => blocks.push(BlockAccum {
                    index,
                    kind,
                    text: String::new(),
                    signature: None,
                    tool_input_raw: String::new(),
                }),
                StreamEvent::TextDelta { index, text } => {
                    let visible_text = sanitize_visible_delta_for_tier3(&text, ctx);
                    on_text_delta(&visible_text);
                    emit(events, AgentEvent::TextDelta { text: visible_text });
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::ThinkingDelta { index, text } => {
                    let visible_text = sanitize_visible_delta_for_tier3(&text, ctx);
                    emit(events, AgentEvent::ThinkingDelta { text: visible_text });
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::SignatureDelta { index, sig } => {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.signature = Some(sig);
                    }
                }
                StreamEvent::ToolInputDelta {
                    index,
                    json_fragment,
                } => {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.tool_input_raw.push_str(&json_fragment);
                    }
                }
                StreamEvent::BlockStop { .. } => {}
                StreamEvent::Done {
                    stop_reason: sr,
                    usage: u,
                } => {
                    stop_reason = sr;
                    usage = u;
                }
            }
        }

        // Phase5-B: 引数JSONパース失敗は`?`でターン全体を落とさない。空入力の`ToolUse`として
        // contentへは積んだ上で、当該idを`malformed`へ控え、後段の実行ループでスキップして
        // is_errorなtool_resultを合成する（tool_use/tool_result対応を崩さないため）。
        let mut content = Vec::with_capacity(blocks.len());
        let mut malformed: std::collections::HashMap<String, MalformedToolInput> =
            std::collections::HashMap::new();
        for b in blocks {
            match b.into_content_block() {
                Ok(block) => {
                    if let ContentBlock::ToolUse { id, name, .. } = &block {
                        wire_log_block_assembly("tool_input_assembled", id, name, "", true);
                    }
                    content.push(block);
                }
                Err(m) => {
                    wire_log_block_assembly("tool_input_assembled", &m.id, &m.name, &m.raw, false);
                    content.push(ContentBlock::ToolUse {
                        id: m.id.clone(),
                        name: m.name.clone(),
                        input: serde_json::Value::Object(Default::default()),
                    });
                    malformed.insert(m.id.clone(), m);
                }
            }
        }
        if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
            sanitize_content_blocks_for_tier3(&mut content);
        }

        state.messages.push(Message {
            role: Role::Assistant,
            content: content.clone(),
        });

        // Phase5-C: `stop_reason`（プロバイダの`finish_reason`）ではなく、実際に`content`へ
        // `ToolUse`ブロックが積まれたかどうかで分岐する。LMStudio実機観測で、tool_callが
        // 積まれているのに`finish_reason:"stop"`が返る揺れがあったため（Phase1候補C）。
        let has_tool_use = content
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
        if !has_tool_use {
            emit(
                events,
                AgentEvent::TurnCompleted {
                    stop_reason: stop_reason.clone(),
                    usage,
                },
            );
            let text = content
                .into_iter()
                .filter_map(|b| match b {
                    ContentBlock::Text(t) => Some(t),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            return Ok(AgentLoopOutcome {
                text,
                stop_reason,
                usage,
                cancelled: false,
            });
        }

        let mut results = Vec::new();
        let mut cancelled_mid_tool = false;
        for block in &content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                if !cancelled_mid_tool && cancel.is_some_and(|c| c.is_cancelled()) {
                    cancelled_mid_tool = true;
                }
                if cancelled_mid_tool {
                    // 残り全てのtool_useへcancelledなtool_resultを合成する
                    // （§エージェントループ キャンセル整合「ツール実行中は全tool_useへ
                    // cancelled合成 → 続行で400にならない」、実際にツールは呼ばない）。
                    results.push(ContentBlock::ToolResult {
                        tool_use_id: id.clone(),
                        content: "cancelled by user".to_string(),
                        is_error: true,
                    });
                    continue;
                }
                emit(
                    events,
                    AgentEvent::ToolCallProposed {
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    },
                );
                let output = if let Some(m) = malformed.get(id) {
                    // Phase5-B: 引数JSONが壊れていたtool_use。ツールは呼ばず、モデルへ
                    // 差し戻して自己修正させる（`unknown tool`と同じ「エラーの説明を
                    // tool_resultとして返す」パターン）。
                    ToolOutput {
                        content: format!(
                            "malformed tool_use input for {name}: arguments did not parse as \
                             JSON (raw: {})",
                            truncate_head_tail(&m.raw, 500)
                        ),
                        is_error: true,
                    }
                } else {
                    match tools.get(name) {
                        Some(tool) => {
                            let risk = tool.risk(input);
                            let decision = gate.resolve(name, risk, &arg_repr(input), input).await;
                            if decision.is_allow() {
                                emit(
                                    events,
                                    AgentEvent::ToolStarted {
                                        id: id.clone(),
                                        name: name.clone(),
                                    },
                                );
                                tool.call(input.clone(), ctx)
                                    .await
                                    .unwrap_or_else(|e| ToolOutput {
                                        content: e.to_string(),
                                        is_error: true,
                                    })
                            } else {
                                ToolOutput {
                                    content: format!(
                                        "permission denied by policy: {name} ({risk:?})"
                                    ),
                                    is_error: true,
                                }
                            }
                        }
                        None => ToolOutput {
                            content: format!("unknown tool: {name}"),
                            is_error: true,
                        },
                    }
                };
                let mut output = output;
                if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
                    sanitize_tool_output_for_tier3(&mut output);
                }
                let truncated_content = truncate_head_tail(&output.content, MAX_TOOL_OUTPUT_CHARS);
                emit(
                    events,
                    AgentEvent::ToolFinished {
                        id: id.clone(),
                        output: ToolOutput {
                            content: truncated_content.clone(),
                            is_error: output.is_error,
                        },
                    },
                );
                results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: truncated_content,
                    is_error: output.is_error,
                });
            }
        }

        state.messages.push(Message {
            role: Role::User,
            content: results,
        });

        if cancelled_mid_tool {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }
    }

    Err(ProviderError::InvalidRequest {
        msg: format!("agent loop exceeded max_turns ({})", config.max_turns),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::stream;

    #[test]
    fn estimate_tokens_grows_with_request_size() {
        let small = CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Sampling::default(),
            model: "mock".into(),
        };
        let mut large = small.clone();
        large.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text("x".repeat(4000))],
        });

        assert!(estimate_tokens(&large) > estimate_tokens(&small));
    }

    /// あらかじめ用意したターンごとの`StreamEvent`列を順番に返すテスト用プロバイダ。
    /// §実装マイルストーン M6で導入予定の本物のmockプロバイダ（golden-transcript向け）とは別に、
    /// M4はこの最小限のローカルmockでパーミッション判定の統合テストのみを行う。
    struct MockProvider {
        turns: Mutex<Vec<Vec<StreamEvent>>>,
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }

        async fn stream(
            &self,
            _req: CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
            let mut turns = self.turns.lock().unwrap();
            let events = turns.remove(0);
            Ok(Box::pin(stream::iter(events.into_iter().map(Ok))))
        }
    }

    fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: input.to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::ToolUse,
                usage: Usage::default(),
            },
        ]
    }

    fn end_turn(text: &str) -> Vec<StreamEvent> {
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

    struct RecordingProvider {
        seen_requests: std::sync::Arc<Mutex<Vec<CompletionRequest>>>,
    }

    #[async_trait]
    impl LlmProvider for RecordingProvider {
        fn id(&self) -> &str {
            "recording"
        }

        async fn stream(
            &self,
            req: CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
            self.seen_requests.lock().unwrap().push(req);
            Ok(Box::pin(stream::iter(end_turn("done").into_iter().map(Ok))))
        }
    }

    #[tokio::test]
    async fn run_agent_loop_sends_tier3_specific_run_shell_tool_spec() {
        let dir = tempfile::tempdir().unwrap();
        let seen_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let provider = RecordingProvider {
            seen_requests: std::sync::Arc::clone(&seen_requests),
        };
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.workspace_root = std::path::PathBuf::from(r"C:\Users\me\project");
        ctx.shell_tier = harness_core::ShellTierSelection::direct(harness_core::ShellTier::Tier3);
        let mut state = ConversationState::new(system_blocks_for(&ctx));
        state.messages.push(Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text(r"old thought mentioned C:\Users\me\project".to_string()),
                ContentBlock::Thinking {
                    text: r"signed thought mentioned C:\Users\me\project".to_string(),
                    signature: Some("signed".to_string()),
                },
                ContentBlock::RedactedThinking {
                    data: r"redacted thought mentioned C:\Users\me\project".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "old_call".to_string(),
                    name: "run_shell".to_string(),
                    input: serde_json::json!({
                        "command": r#"Get-ChildItem "C:\Users\me\project""#,
                    }),
                },
            ],
        });
        state.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "old_call".to_string(),
                content: r"old result mentioned C:\Users\me\project".to_string(),
                is_error: true,
            }],
        });
        state.push_user_text("list files");
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

        run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        let requests = seen_requests.lock().unwrap();
        let run_shell = requests[0]
            .tools
            .iter()
            .find(|spec| spec.name == "run_shell")
            .expect("run_shell spec should be sent");
        assert!(
            run_shell.description.contains("`sh -c`"),
            "{}",
            run_shell.description
        );
        assert!(!run_shell.description.contains("PowerShell"));
        assert_eq!(requests[0].system.len(), 1);
        let system = &requests[0].system[0].text;
        assert!(
            system.contains("ワークスペースルート: /workspace"),
            "{system}"
        );
        assert!(!system.contains(r"C:\Users"), "{system}");
        let request_json = serde_json::to_string(&requests[0]).unwrap();
        assert!(!request_json.contains(r"C:\Users"), "{request_json}");
        assert!(!request_json.contains("Windowsホスト"), "{request_json}");
        assert!(!request_json.contains("ホスト側"), "{request_json}");
        assert!(!request_json.contains("ホストOS"), "{request_json}");
        assert!(!request_json.contains("signed thought"), "{request_json}");
        assert!(!request_json.contains("redacted thought"), "{request_json}");
        assert!(request_json.contains("/workspace"), "{request_json}");
    }

    #[tokio::test]
    async fn tier3_text_deltas_are_sanitized_before_display() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![end_turn(r"checking C:\Users\me\project")]),
        };
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = harness_core::ShellTierSelection::direct(harness_core::ShellTier::Tier3);
        let mut state = ConversationState::new(system_blocks_for(&ctx));
        state.push_user_text("hi");
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let visible = std::sync::Arc::new(Mutex::new(String::new()));
        let visible_for_callback = std::sync::Arc::clone(&visible);

        let outcome = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            Some(&events_tx),
            None,
            |delta| visible_for_callback.lock().unwrap().push_str(delta),
        )
        .await
        .unwrap();

        let callback_text = visible.lock().unwrap().clone();
        let mut event_text = String::new();
        while let Ok(event) = events_rx.try_recv() {
            if let AgentEvent::TextDelta { text } = event {
                event_text.push_str(&text);
            }
        }

        assert!(!outcome.text.contains(r"C:\Users"), "{}", outcome.text);
        assert!(!callback_text.contains(r"C:\Users"), "{callback_text}");
        assert!(!event_text.contains(r"C:\Users"), "{event_text}");
        assert!(outcome.text.contains("/workspace"), "{}", outcome.text);
        assert!(callback_text.contains("/workspace"), "{callback_text}");
        assert!(event_text.contains("/workspace"), "{event_text}");
    }

    fn find_tool_result(state: &ConversationState) -> (String, bool) {
        state
            .messages
            .iter()
            .rev()
            .find_map(|m| {
                m.content.iter().find_map(|b| match b {
                    ContentBlock::ToolResult {
                        content, is_error, ..
                    } => Some((content.clone(), *is_error)),
                    _ => None,
                })
            })
            .expect("tool_result should be present")
    }

    /// §実装マイルストーン M4 検証条件「未許可shellが拒否されるユニットテスト」。
    /// allowlist未登録の`run_shell`（RiskClass=Exec）がDefaultモード・ヘッドレス相当の判定で
    /// 拒否され、`RunShellTool::call`が一度も呼ばれない（=実際にコマンドが実行されない）ことを、
    /// 拒否理由を含むエラーtool_resultが積まれ`EndTurn`まで正常にループが継続することで確認する。
    #[tokio::test]
    async fn denies_unauthorized_run_shell_without_executing() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn(
                    "call_1",
                    "run_shell",
                    serde_json::json!({ "command": "echo should-not-run" }),
                ),
                end_turn("done"),
            ]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run a shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

        let outcome = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(outcome.stop_reason, StopReason::EndTurn);
        let (content, is_error) = find_tool_result(&state);
        assert!(is_error, "denied tool call should be recorded as an error");
        assert!(content.contains("permission denied"));
    }

    /// §実装マイルストーン M4 検証条件のもう一方「ジェイル脱出が拒否される」に対する、
    /// パーミッション層側の対照テスト: allowlist未登録でもread-onlyの`read_file`は
    /// Defaultモードで自動許可され、実際にファイル内容が読めることを確認する
    /// （fsジェイル自体のユニットテストは`harness-sandbox`側に別途ある）。
    #[tokio::test]
    async fn allows_read_only_tool_without_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn(
                    "call_1",
                    "read_file",
                    serde_json::json!({ "path": "a.txt" }),
                ),
                end_turn("summarized"),
            ]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("read a.txt");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

        let outcome = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(outcome.text, "summarized");
        let (content, is_error) = find_tool_result(&state);
        assert!(!is_error);
        assert!(content.contains("hello"));
    }

    /// allowlistで`run_shell:echo*`を明示した場合は、Defaultモードのヘッドレス既定拒否を
    /// 上書きして許可される（§パーミッション「allowlist: closed-by-default」）。
    #[tokio::test]
    async fn allowlisted_run_shell_executes() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn(
                    "call_1",
                    "run_shell",
                    serde_json::json!({ "command": "echo allowed" }),
                ),
                end_turn("done"),
            ]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run an allowed shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(
            PermissionMode::Default,
            vec![AllowlistRule::new("run_shell", "echo*")],
        );

        run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        let (content, is_error) = find_tool_result(&state);
        assert!(!is_error);
        assert!(content.contains("allowed"));
    }

    /// ストリーム開始後、応答が完了する前に応答が返らないプロバイダ
    /// （キャンセルによる中断を`tokio::select!`で確実に踏ませるためのテスト専用実装）。
    struct HangingProvider;

    #[async_trait]
    impl LlmProvider for HangingProvider {
        fn id(&self) -> &str {
            "hanging"
        }
        async fn stream(
            &self,
            _req: CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
            let partial = vec![
                Ok(StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                }),
                Ok(StreamEvent::TextDelta {
                    index: 0,
                    text: "partial".to_string(),
                }),
            ];
            Ok(Box::pin(stream::iter(partial).chain(stream::pending())))
        }
    }

    /// §エージェントループ キャンセル整合「ストリーム途中は部分assistant破棄」。
    /// ストリーム受信中にキャンセルすると、蓄積中だったテキストは`state.messages`へ一切
    /// pushされず（呼び出し前と後でメッセージ数が変わらない）、`AgentLoopOutcome.cancelled`が
    /// `true`になることを確認する。
    #[tokio::test]
    async fn cancel_mid_stream_discards_partial_assistant() {
        let dir = tempfile::tempdir().unwrap();
        let provider = HangingProvider;
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("hi");
        let messages_before = state.messages.len();
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig {
                    model: "mock".into(),
                    max_tokens: 100,
                    max_turns: 5,
                },
                None,
                Some(&cancel),
                |_| {},
            );
            tokio::pin!(run_fut);
            let cancel_after_delay = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            };
            let (outcome, ()) = tokio::join!(run_fut, cancel_after_delay);
            outcome.unwrap()
        };

        assert!(outcome.cancelled);
        assert_eq!(state.messages.len(), messages_before);
    }

    /// キャンセルされるまで`call()`内で意図的にsleepするテスト専用ツール。
    struct SlowTool;

    #[async_trait]
    impl harness_core::Tool for SlowTool {
        fn name(&self) -> &str {
            "slow_tool"
        }
        fn description(&self) -> &str {
            "test-only slow tool"
        }
        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object" })
        }
        fn risk(&self, _input: &serde_json::Value) -> harness_core::RiskClass {
            harness_core::RiskClass::ReadOnly
        }
        async fn call(
            &self,
            _input: serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, harness_core::ToolError> {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(ToolOutput {
                content: "slow-done".to_string(),
                is_error: false,
            })
        }
    }

    fn multi_tool_use_turn(calls: &[(&str, &str, serde_json::Value)]) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for (index, (id, name, input)) in calls.iter().enumerate() {
            events.push(StreamEvent::BlockStart {
                index,
                kind: BlockKind::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            });
            events.push(StreamEvent::ToolInputDelta {
                index,
                json_fragment: input.to_string(),
            });
            events.push(StreamEvent::BlockStop { index });
        }
        events.push(StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        });
        events
    }

    /// §エージェントループ キャンセル整合「ツール実行中は全tool_useへcancelled合成 →
    /// 続行で400にならない」の契約テスト。1回目のツール呼び出し中にキャンセルすると、
    /// (a) 既に実行が始まっていた1件目は正常完了扱いのまま、(b) まだ手を付けていない2件目は
    /// 実行されず`cancelled by user`なtool_resultが合成され、(c) assistantのtool_use 2件と
    /// tool_result 2件が過不足なく対応した状態で会話が終わるため、(d) 続けて次のプロンプトを
    /// 送っても（=もう一度`run_agent_loop`を呼んでも）プロバイダ層のエラーにならないことを
    /// 確認する。
    #[tokio::test]
    async fn cancel_mid_tool_execution_synthesizes_cancelled_results_and_continuation_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                multi_tool_use_turn(&[
                    ("call_1", "slow_tool", serde_json::json!({})),
                    ("call_2", "slow_tool", serde_json::json!({})),
                ]),
                end_turn("continued fine"),
            ]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run two slow tools");
        let mut tools = harness_tools::ToolRegistry::new();
        tools.register(std::sync::Arc::new(SlowTool));
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig {
                    model: "mock".into(),
                    max_tokens: 100,
                    max_turns: 5,
                },
                None,
                Some(&cancel),
                |_| {},
            );
            tokio::pin!(run_fut);
            // 1件目の`SlowTool::call`（30ms sleep）が始まった後、2件目に手を付ける前にキャンセルする。
            let cancel_after_delay = async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                cancel.cancel();
            };
            let (outcome, ()) = tokio::join!(run_fut, cancel_after_delay);
            outcome.unwrap()
        };
        assert!(outcome.cancelled);

        let tool_results: Vec<(String, String, bool)> = state
            .messages
            .last()
            .unwrap()
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => Some((tool_use_id.clone(), content.clone(), *is_error)),
                _ => None,
            })
            .collect();
        assert_eq!(
            tool_results.len(),
            2,
            "both tool_use blocks must have a matching tool_result"
        );
        let call1 = tool_results.iter().find(|(id, ..)| id == "call_1").unwrap();
        assert_eq!(call1.1, "slow-done");
        assert!(!call1.2);
        let call2 = tool_results.iter().find(|(id, ..)| id == "call_2").unwrap();
        assert_eq!(call2.1, "cancelled by user");
        assert!(call2.2);

        // 続行: 新しいCancellationTokenでもう一度呼んでも、tool_use/tool_resultの対応が
        // 崩れていないため`ProviderError`にならず正常終了する（M9受入条件そのもの）。
        let outcome2 = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(outcome2.text, "continued fine");
    }
}
