//! 1回のストリーム受信 —— プロバイダ呼び出し・`StreamEvent`の消費・ブロック組み立て・
//! 縮退検知器への供給。
//!
//! [`super`]（型・パーミッション・ツール実行・回復の梯子）から切り離してあるのは
//! `docs/CODE-STRUCTURE-RULES.md`規則3の軸1（どの外部システムと話すか）による分割で、
//! **ここだけが`LlmProvider`のストリームと話す**。梯子はこれを何度も呼ぶだけの層になる。

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;

use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, LlmProvider, ProviderError, StopReason,
    StreamEvent, Usage,
};

use super::{EngineError, TurnExecutor};
use crate::degeneracy::{CallWatch, Degenerate};
use crate::{emit, sanitize};

const MAX_RETRIES: u32 = 3;

/// 1回のストリーム受信の顛末。
pub(super) enum Attempt {
    /// ストリームが最後まで届いた。ツール実行はまだ**していない**。
    Completed {
        content: Vec<ContentBlock>,
        malformed: HashMap<String, MalformedToolInput>,
        stop_reason: StopReason,
        usage: Usage,
    },
    /// 受信中にキャンセルされた。蓄積中のブロックは破棄済み。
    Cancelled,
    /// 縮退を検知して受信を打ち切った。蓄積中のブロックは破棄済み。
    ///
    /// **ここに来た時点でツールは1つも実行されていない**——検知は受信中（①②④）か
    /// ストリーム完了直後（③、`ToolUse`ゼロが発火条件）に起きるため、ツール実行へ到達しない。
    /// したがって捨てたコールは副作用を持たない（`plans/DESIGN-COGNITION.md` §11.4）。
    Degenerate(Degenerate),
}

/// [`TurnExecutor::stream_once`]の戻り値。
pub(super) struct StreamOutcome {
    pub attempt: Attempt,
    /// このコールで下流（`on_text_delta`）へ実際に流した可視テキストのUTF-8バイト数。
    /// `--output-format text`の区切りマーカーが運ぶ`bytes=`はこの値。
    pub emitted_bytes: u64,
}

impl TurnExecutor<'_> {
    /// リクエストを1回投げ、ストリームを最後まで（または打ち切りまで）消費する。
    ///
    /// `watch`が`Some`なら、届いたデルタを種別ごとに検知器へ供給する。`None`なら
    /// 縮退ガードは無効で、[`Attempt::Degenerate`]は決して返らない（M21以前と同じ経路）。
    pub(super) async fn stream_once<F>(
        &self,
        req: &CompletionRequest,
        on_text_delta: &mut F,
        mut watch: Option<&mut CallWatch<'_>>,
        visible: bool,
    ) -> Result<StreamOutcome, EngineError>
    where
        F: FnMut(&str),
    {
        let mut stream = stream_with_retry(self.provider, req)
            .await
            .map_err(EngineError::Call)?;

        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();
        let mut emitted_bytes = 0u64;

        macro_rules! bail {
            ($attempt:expr) => {
                return Ok(StreamOutcome {
                    attempt: $attempt,
                    emitted_bytes,
                })
            };
        }

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
                bail!(Attempt::Cancelled);
            };
            let Some(event) = event else {
                break;
            };
            let event = event.map_err(EngineError::Stream)?;
            match event {
                StreamEvent::BlockStart { index, kind } => {
                    if let (BlockKind::ToolUse { .. }, Some(w)) = (&kind, watch.as_deref_mut()) {
                        // 産出があった＝③④の前提が崩れる。
                        w.on_tool_use_block();
                    }
                    blocks.push(BlockAccum {
                        index,
                        kind,
                        text: String::new(),
                        signature: None,
                        tool_input_raw: String::new(),
                    })
                }
                StreamEvent::TextDelta { index, text } => {
                    if visible {
                        let visible_text = sanitize::visible_delta(&text, self.ctx);
                        emitted_bytes += visible_text.len() as u64;
                        on_text_delta(&visible_text);
                        emit(self.events, AgentEvent::TextDelta { text: visible_text });
                    }
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                    if let Some(hit) = watch.as_deref_mut().and_then(|w| w.on_text(&text)) {
                        bail!(Attempt::Degenerate(hit));
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
                    if let Some(hit) = watch.as_deref_mut().and_then(|w| w.on_thinking(&text)) {
                        bail!(Attempt::Degenerate(hit));
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
                    if let Some(hit) = watch
                        .as_deref_mut()
                        .and_then(|w| w.on_tool_args(&json_fragment))
                    {
                        bail!(Attempt::Degenerate(hit));
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

        // ③（完走時の無産出）と、評価の刻みで取りこぼした末尾ぶんの①②。
        if let Some(hit) = watch.as_mut().and_then(|w| w.on_done(&stop_reason)) {
            bail!(Attempt::Degenerate(hit));
        }

        let (content, malformed) = assemble_content(blocks);
        Ok(StreamOutcome {
            attempt: Attempt::Completed {
                content,
                malformed,
                stop_reason,
                usage,
            },
            emitted_bytes,
        })
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
pub(super) struct MalformedToolInput {
    pub id: String,
    pub name: String,
    pub raw: String,
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
) -> (Vec<ContentBlock>, HashMap<String, MalformedToolInput>) {
    let mut content = Vec::with_capacity(blocks.len());
    let mut malformed: HashMap<String, MalformedToolInput> = HashMap::new();
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
    harness_core::wire_log::record(|| {
        serde_json::json!({
            "kind": kind,
            "tool_use_id": id,
            "name": name,
            "tool_input_raw": raw,
            "parse_ok": ok,
        })
    });
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
///
/// **縮退の回復（§11.3）とは別の層**である。ここはリクエストが受理されなかったときの
/// 再試行で、あちらは受理されて壊れた応答が返ったときの再試行。
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
