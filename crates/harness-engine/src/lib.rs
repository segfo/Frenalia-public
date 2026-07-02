//! harness-engine: 中核ループの入口。`plans/DESIGN.md` §エージェントループ参照。
//!
//! M3では `run_single_turn`（単発ターン、M2まで）に加え、`run_agent_loop` を追加した。
//! `ToolRegistry` に登録済みのツールを `stop_reason==ToolUse` の間ディスパッチし、
//! `tool_result` を履歴へ投入して次ターンへ継続する（§実装マイルストーン M3）。
//! **M3時点のスコープ外**: `PermissionArbiter`（M4）・cap-stdジェイル（M4/M11）・
//! キャンセル整合（M9）・コンテキスト圧縮（M9）。ツールは登録されていれば無条件で
//! 実行する「一旦allow-all」（§実装マイルストーン M3）で、承認フローはまだ無い。

use futures::StreamExt;

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role,
    Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, ToolCtx, ToolOutput, Usage,
};
use harness_tools::ToolRegistry;

/// 会話のIR履歴。
#[derive(Debug, Clone, Default)]
pub struct ConversationState {
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
}

impl ConversationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_user_text(&mut self, text: impl Into<String>) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.into())],
        });
    }
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

impl BlockAccum {
    fn into_content_block(self) -> Result<ContentBlock, ProviderError> {
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
                    serde_json::from_str(&self.tool_input_raw).map_err(|_| {
                        ProviderError::InvalidRequest {
                            msg: format!("malformed tool_use input for {name}"),
                        }
                    })?
                };
                Ok(ContentBlock::ToolUse { id, name, input })
            }
        }
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
/// `stop_reason != ToolUse` になるまで繰り返す。M3時点は `PermissionArbiter` が無いため、
/// `tools` に登録済みのツールは無条件で実行する（§実装マイルストーン M3「一旦allow-all」）。
pub async fn run_agent_loop<F>(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    config: AgentLoopConfig,
    mut on_text_delta: F,
) -> Result<AgentLoopOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let tool_specs = tools.to_specs();

    for _ in 0..config.max_turns {
        let req = CompletionRequest {
            system: state.system.clone(),
            messages: state.messages.clone(),
            tools: tool_specs.clone(),
            tool_choice: if tool_specs.is_empty() {
                ToolChoice::None
            } else {
                ToolChoice::Auto
            },
            output: None,
            parallel_tool_calls: None,
            max_tokens: config.max_tokens,
            sampling: Sampling::default(),
            model: config.model.clone(),
        };

        let mut stream = provider.stream(req).await?;
        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();

        while let Some(event) = stream.next().await {
            match event? {
                StreamEvent::BlockStart { index, kind } => blocks.push(BlockAccum {
                    index,
                    kind,
                    text: String::new(),
                    signature: None,
                    tool_input_raw: String::new(),
                }),
                StreamEvent::TextDelta { index, text } => {
                    on_text_delta(&text);
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::ThinkingDelta { index, text } => {
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

        let mut content = Vec::with_capacity(blocks.len());
        for b in blocks {
            content.push(b.into_content_block()?);
        }

        state.messages.push(Message {
            role: Role::Assistant,
            content: content.clone(),
        });

        if stop_reason != StopReason::ToolUse {
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
            });
        }

        let mut results = Vec::new();
        for block in &content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                let output = match tools.get(name) {
                    Some(tool) => tool.call(input.clone(), ctx).await.unwrap_or_else(|e| {
                        ToolOutput {
                            content: e.to_string(),
                            is_error: true,
                        }
                    }),
                    None => ToolOutput {
                        content: format!("unknown tool: {name}"),
                        is_error: true,
                    },
                };
                results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: output.content,
                    is_error: output.is_error,
                });
            }
        }

        state.messages.push(Message {
            role: Role::User,
            content: results,
        });
    }

    Err(ProviderError::InvalidRequest {
        msg: format!("agent loop exceeded max_turns ({})", config.max_turns),
    })
}
