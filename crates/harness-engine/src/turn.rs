//! 1ステップ（`RawTurn`）= **1回のスコープ付きLLMコール + そのターンのツール実行**。
//! `plans/DESIGN-COGNITION.md` §1「`harness-engine` ← 「1回のスコープ付きLLMコール + ツール実行」」。
//!
//! [`crate::run_agent_loop`]（素朴ループ）はこのプリミティブを`ToolUse`が出なくなるまで
//! 繰り返すだけの薄い層になり、認知レイヤー（`harness-cognition`、M14以降）は
//! `ConversationState`の代わりに自前の作業記憶から組んだ最小コンテキストを渡して
//! **1ステップだけ**回す。どちらも入口はこの[`TurnExecutor`]1つ。
//!
//! # なぜツール実行までこの中に置くか
//!
//! ツール実行を呼び出し側へ出すと、認知レイヤーが`PermissionGate`を通さずに
//! `Tool::call`を直接叩く経路が作れてしまう。ここに閉じ込めることで、
//! 「パーミッションの強制点は1箇所」（`plans/DESIGN.md` §パーミッション、
//! `docs/SECURITY-PRINCIPLES.md`）が**構造的に**保たれる —— 認知層は
//! [`Executor`]越しにしかツールへ触れられず、迂回路が型として存在しない。
//!
//! # 責務の境界（呼び出し側に残すもの）
//!
//! ここは**会話履歴を持たない**。`ConversationState`への追記・ターン予算・
//! コンテキスト圧縮・ターン境界のイベント（`TurnStarted`/`TurnCompleted`/`Cancelled`/`Error`）は
//! すべて呼び出し側の責務。ここが発行するのは1ステップ内部の
//! `TextDelta`/`ThinkingDelta`/`ToolCallProposed`/`ToolStarted`/`ToolFinished`だけ。

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, LlmProvider, ProviderError, StopReason,
    StreamEvent, ToolCtx, ToolOutput, Usage,
};
use harness_tools::ToolRegistry;

use crate::permission::{arg_repr, PermissionGate};
use crate::{emit, sanitize, EventSink};
use harness_core::text::truncate_head_tail;

/// ツール出力がこれを超える文字数なら頭尾切詰めする（M9、DESIGN.md L349「大出力 head+tail
/// 切詰め」）。会話履歴に積む前に適用するため、モデルへ送るコンテキスト自体を圧迫しない。
const MAX_TOOL_OUTPUT_CHARS: usize = 8_000;

const MAX_RETRIES: u32 = 3;

/// このターンのassistantテキストが**ユーザ向けの応答**なのか、**認知レイヤー内部の機構**なのか。
///
/// 認知レイヤーの各フェーズ（`plans/DESIGN-COGNITION.md` §3.3）はスキーマ強制された
/// JSONを返させる解釈コールで、その中身はユーザへ見せる文章ではない。`Internal`のターンで
/// `TextDelta`/`ThinkingDelta`を流すと、TUIのトランスクリプトとヘッドレスのtext出力へ
/// 生JSONが垂れ流される。**どのターンの本文が最終回答かを知っているのは認知層だけ**なので、
/// 判断をここで受け取り、発行するかどうかをこの1箇所で決める。
///
/// ツール関連イベント（`ToolCallProposed`/`ToolStarted`/`ToolFinished`）は`Internal`でも
/// 発行する——実際にワークスペースを触る操作はフェーズの内外を問わずユーザに見えるべきで、
/// TUIの承認モーダル・ヘッドレスJSONの`tool_calls`集計もこれを前提にしている。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TurnVisibility {
    /// 本文をそのままユーザへ見せる（素朴ループの全ターン）。
    #[default]
    UserFacing,
    /// 本文は認知レイヤーが解釈する構造化出力。デルタを一切流さない。
    Internal,
}

/// 1ステップの入力。認知レイヤー（M14以降）は`ContextAssembler`が組んだ最小コンテキストを、
/// 素朴ループは`ConversationState`全体を、それぞれここへ載せる。
///
/// `plans/DESIGN-COGNITION.md` §1のスケッチにある`allowed: ToolGate`（フェーズ毎の許可ツール
/// 制限、§7.3）は`ContextAssembler`が渡すツールspecを絞ることで実現しており（M14）、
/// ここには持たない。`budget: TokenBudget`（§6）も同様に`max_tokens`と組立側の縮約へ
/// 落ちているため、常に全許可の値を運ぶだけのフィールドは置いていない。
pub struct RawTurnRequest {
    pub req: CompletionRequest,
    pub visibility: TurnVisibility,
}

impl RawTurnRequest {
    /// 素朴ループのターン（本文をユーザへ流す）。
    pub fn user_facing(req: CompletionRequest) -> Self {
        Self {
            req,
            visibility: TurnVisibility::UserFacing,
        }
    }

    /// 認知レイヤーのフェーズコール（本文は構造化出力なので流さない）。
    pub fn internal(req: CompletionRequest) -> Self {
        Self {
            req,
            visibility: TurnVisibility::Internal,
        }
    }
}

/// そのツール呼び出しが**実際に実行されたか**、されなかったなら何故か。
///
/// `Executed`以外はいずれも「`Tool::call`を呼んでいない」ことを意味し、`output`には
/// モデルへ差し戻す説明文が入る（モデルに自己修正させるため、ターン自体は落とさない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallDecision {
    Executed,
    /// `PermissionGate`が拒否した。
    DeniedByPolicy,
    /// `ToolRegistry`に無い名前だった。
    UnknownTool,
    /// 引数JSONの連結結果がパースできなかった。
    MalformedInput,
    /// 先行するツールの実行中にキャンセルされ、この呼び出しには手を付けていない。
    CancelledBeforeStart,
}

/// 1件のツール呼び出しと、その顛末。`output`は**履歴へ積むそのもの**
/// （Tier3伏字化・頭尾切詰め適用済み）。
#[derive(Debug, Clone)]
pub struct CompletedToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
    pub output: ToolOutput,
    pub decision: ToolCallDecision,
}

impl CompletedToolCall {
    /// 会話履歴へ積む`tool_result`ブロックへ変換する。`tool_use`との1対1対応を保つのは
    /// 呼び出し側の責務（`plans/DESIGN.md` §エージェントループ「続行で400にならない」）。
    pub fn to_tool_result(&self) -> ContentBlock {
        ContentBlock::ToolResult {
            tool_use_id: self.id.clone(),
            content: self.output.content.clone(),
            is_error: self.output.is_error,
        }
    }
}

/// 完走した1ステップの結果。
#[derive(Debug, Clone)]
pub struct RawTurn {
    /// assistantメッセージの中身（Tier3伏字化済み）。
    pub content: Vec<ContentBlock>,
    /// `content`中の`Text`ブロックの連結。
    pub text: String,
    /// `content`中の`ToolUse`ブロックと1対1で対応する（順序も同じ）。
    pub tool_calls: Vec<CompletedToolCall>,
    pub stop_reason: StopReason,
    pub usage: Usage,
    /// ツール実行の途中でキャンセルされた。`tool_calls`自体は`tool_use`と対応が取れた
    /// 状態で埋まっているので、呼び出し側は**通常どおり履歴へ積んでから**終了すること。
    pub cancelled_mid_tool: bool,
}

/// 1ステップの結果。「ストリーム途中でキャンセルされた場合は会話履歴を一切触ってはならない」
/// という整合性の不変条件（`plans/DESIGN.md` §エージェントループ「ストリーム途中は部分
/// assistant破棄」）を、見落とし得るフラグではなく**型**で強制するために2値にしている。
#[derive(Debug, Clone)]
pub enum RawTurnResult {
    Completed(RawTurn),
    /// 部分的に蓄積していたassistantブロックは破棄済み。呼び出し側は履歴へ何も積まない。
    CancelledMidStream,
}

/// 1ステップの失敗。**ストリーム開始前**（プロバイダ呼び出し自体の失敗）と**開始後**
/// （受信中の失敗）を区別する。`run_agent_loop`のコンテキスト圧縮リトライは前者にだけ
/// 効く仕様で、これまでこの非対称性はコードの配置に暗黙的に埋まっていた。
#[derive(Debug)]
pub enum EngineError {
    Call(ProviderError),
    Stream(ProviderError),
}

impl EngineError {
    pub fn into_provider_error(self) -> ProviderError {
        match self {
            EngineError::Call(e) | EngineError::Stream(e) => e,
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Call(e) | EngineError::Stream(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// 認知レイヤーがLLM／ツールへ触れる唯一の口（`plans/DESIGN-COGNITION.md` §1
/// 「認知層は provider を知らず、RawTurn 経由でのみ LLM/ツールに触れる」）。
#[async_trait]
pub trait Executor: Send + Sync {
    async fn raw_turn(&self, r: RawTurnRequest) -> Result<RawTurnResult, EngineError>;
}

/// [`Executor`]の実装。1ステップに必要な参照だけを束ねた、状態を持たない実行器。
pub struct TurnExecutor<'a> {
    provider: &'a dyn LlmProvider,
    tools: &'a ToolRegistry,
    ctx: &'a ToolCtx,
    gate: &'a dyn PermissionGate,
    events: Option<&'a EventSink>,
    cancel: Option<&'a CancellationToken>,
}

impl<'a> TurnExecutor<'a> {
    pub fn new(
        provider: &'a dyn LlmProvider,
        tools: &'a ToolRegistry,
        ctx: &'a ToolCtx,
        gate: &'a dyn PermissionGate,
        events: Option<&'a EventSink>,
        cancel: Option<&'a CancellationToken>,
    ) -> Self {
        Self {
            provider,
            tools,
            ctx,
            gate,
            events,
            cancel,
        }
    }

    fn is_tier3(&self) -> bool {
        self.ctx.shell_tier.tier == harness_core::ShellTier::Tier3
    }

    /// [`Executor::raw_turn`]の本体。`on_text_delta`はヘッドレスのtext出力
    /// （`harness-cli`が`&mut W`をキャプチャする＝`Send`でないクロージャ）専用の経路で、
    /// trait側は`&dyn Executor`にするためジェネリクスを持てない。そのため
    /// **inherentメソッドを本体、trait実装をno-op委譲**の2段構えにしている。
    /// 認知レイヤーは`AgentEvent`を消費するのでこのコールバックを必要としない。
    pub async fn raw_turn_with_deltas<F>(
        &self,
        request: RawTurnRequest,
        on_text_delta: &mut F,
    ) -> Result<RawTurnResult, EngineError>
    where
        F: FnMut(&str),
    {
        let RawTurnRequest {
            mut req,
            visibility,
        } = request;
        let visible = visibility == TurnVisibility::UserFacing;
        // 呼び出し側が伏字化済みのリクエストを渡してくる経路（`run_agent_loop`）もあるが、
        // ここを choke point にするため無条件に適用する（[`crate::sanitize`]は冪等）。
        if self.is_tier3() {
            sanitize::completion_request(&mut req);
        }

        let mut stream = stream_with_retry(self.provider, &req)
            .await
            .map_err(EngineError::Call)?;

        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();

        loop {
            let next = match self.cancel {
                Some(c) => tokio::select! {
                    _ = c.cancelled() => None,
                    ev = stream.next() => Some(ev),
                },
                None => Some(stream.next().await),
            };
            let Some(event) = next else {
                // 蓄積中の`blocks`は呼び出し側へ渡さず破棄する。
                return Ok(RawTurnResult::CancelledMidStream);
            };
            let Some(event) = event else {
                break;
            };
            let event = event.map_err(EngineError::Stream)?;
            match event {
                StreamEvent::BlockStart { index, kind } => blocks.push(BlockAccum {
                    index,
                    kind,
                    text: String::new(),
                    signature: None,
                    tool_input_raw: String::new(),
                }),
                StreamEvent::TextDelta { index, text } => {
                    if visible {
                        let visible_text = sanitize::visible_delta(&text, self.ctx);
                        on_text_delta(&visible_text);
                        emit(self.events, AgentEvent::TextDelta { text: visible_text });
                    }
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::ThinkingDelta { index, text } => {
                    if visible {
                        let visible_text = sanitize::visible_delta(&text, self.ctx);
                        emit(
                            self.events,
                            AgentEvent::ThinkingDelta { text: visible_text },
                        );
                    }
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

        let (mut content, malformed) = assemble_content(blocks);
        if self.is_tier3() {
            sanitize::content_blocks(&mut content);
        }

        let text = content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");

        let (tool_calls, cancelled_mid_tool) = self.execute_tool_calls(&content, &malformed).await;

        Ok(RawTurnResult::Completed(RawTurn {
            content,
            text,
            tool_calls,
            stop_reason,
            usage,
            cancelled_mid_tool,
        }))
    }

    /// `content`中の`ToolUse`を順に処理する。戻り値の`Vec`は`ToolUse`ブロックと1対1で対応する
    /// （拒否・未知ツール・引数不正・キャンセルでも必ず1件返す＝`tool_result`の欠落を防ぐ）。
    async fn execute_tool_calls(
        &self,
        content: &[ContentBlock],
        malformed: &std::collections::HashMap<String, MalformedToolInput>,
    ) -> (Vec<CompletedToolCall>, bool) {
        let mut tool_calls = Vec::new();
        let mut cancelled_mid_tool = false;

        for block in content {
            let ContentBlock::ToolUse { id, name, input } = block else {
                continue;
            };
            if !cancelled_mid_tool && self.cancel.is_some_and(|c| c.is_cancelled()) {
                cancelled_mid_tool = true;
            }
            if cancelled_mid_tool {
                // 残り全てへcancelledな結果を合成する（実際にツールは呼ばない）。
                // ここでは`AgentEvent`を一切発行しない —— 実行されていない呼び出しが
                // フロントエンドの集計へ混じらないようにするため。
                tool_calls.push(CompletedToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                    output: ToolOutput {
                        content: "cancelled by user".to_string(),
                        is_error: true,
                    },
                    decision: ToolCallDecision::CancelledBeforeStart,
                });
                continue;
            }

            emit(
                self.events,
                AgentEvent::ToolCallProposed {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                },
            );

            let (output, decision) = self.dispatch_one(id, name, input, malformed).await;

            let mut output = output;
            if self.is_tier3() {
                sanitize::tool_output(&mut output);
            }
            let output = ToolOutput {
                content: truncate_head_tail(&output.content, MAX_TOOL_OUTPUT_CHARS),
                is_error: output.is_error,
            };
            emit(
                self.events,
                AgentEvent::ToolFinished {
                    id: id.clone(),
                    output: output.clone(),
                },
            );
            tool_calls.push(CompletedToolCall {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
                output,
                decision,
            });
        }

        (tool_calls, cancelled_mid_tool)
    }

    /// 1件のツール呼び出しをディスパッチする。**`PermissionGate`を通す唯一の場所**。
    async fn dispatch_one(
        &self,
        id: &str,
        name: &str,
        input: &serde_json::Value,
        malformed: &std::collections::HashMap<String, MalformedToolInput>,
    ) -> (ToolOutput, ToolCallDecision) {
        if let Some(m) = malformed.get(id) {
            // 引数JSONが壊れていた`tool_use`。ツールは呼ばず、モデルへ差し戻して自己修正させる
            // （`unknown tool`と同じ「エラーの説明を`tool_result`として返す」パターン）。
            return (
                ToolOutput {
                    content: format!(
                        "malformed tool_use input for {name}: arguments did not parse as JSON \
                         (raw: {})",
                        truncate_head_tail(&m.raw, 500)
                    ),
                    is_error: true,
                },
                ToolCallDecision::MalformedInput,
            );
        }

        let Some(tool) = self.tools.get(name) else {
            return (
                ToolOutput {
                    content: format!("unknown tool: {name}"),
                    is_error: true,
                },
                ToolCallDecision::UnknownTool,
            );
        };

        let risk = tool.risk(input);
        let verdict = self.gate.resolve(name, risk, &arg_repr(input), input).await;
        if !verdict.is_allow() {
            return (
                ToolOutput {
                    content: format!("permission denied by policy: {name} ({risk:?})"),
                    is_error: true,
                },
                ToolCallDecision::DeniedByPolicy,
            );
        }

        emit(
            self.events,
            AgentEvent::ToolStarted {
                id: id.to_string(),
                name: name.to_string(),
            },
        );
        let output = tool
            .call(input.clone(), self.ctx)
            .await
            .unwrap_or_else(|e| ToolOutput {
                content: e.to_string(),
                is_error: true,
            });
        (output, ToolCallDecision::Executed)
    }
}

#[async_trait]
impl Executor for TurnExecutor<'_> {
    async fn raw_turn(&self, r: RawTurnRequest) -> Result<RawTurnResult, EngineError> {
        self.raw_turn_with_deltas(r, &mut |_: &str| {}).await
    }
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
/// `is_error`な`tool_result`を合成する（「unknown tool」と同じ扱い）。
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

/// 蓄積したブロック列を`content`へ組み立てる。引数JSONパース失敗はターン全体を落とさず、
/// 空入力の`ToolUse`として`content`へ積んだ上で理由を控える（`tool_use`/`tool_result`の
/// 対応を崩さないため）。
fn assemble_content(
    blocks: Vec<BlockAccum>,
) -> (
    Vec<ContentBlock>,
    std::collections::HashMap<String, MalformedToolInput>,
) {
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
    (content, malformed)
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
