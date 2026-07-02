//! harness-engine: 中核ループの入口。`plans/DESIGN.md` §エージェントループ参照。
//!
//! M2時点ではツール呼び出し・パーミッション・継続ループを持たない単発ターンのみ。
//! `ConversationState` は以降のフェーズ（M3〜）で蓄積・継続に使うためここに置く。
//! `run_single_turn` は `StreamEvent::TextDelta` を受信の都度 `on_text_delta` へ通知し、
//! ヘッドレスフロントエンドがトークン単位で逐次表示できるようにする（§実装マイルストーン M2）。

use futures::StreamExt;

use harness_core::{
    CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role, Sampling,
    StopReason, StreamEvent, SystemBlock, ToolChoice, Usage,
};

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

/// 1プロバイダターンを実行する。ツール呼び出しへのディスパッチ・継続ループはM3以降で追加する
/// （§エージェントループの「1回のステップ」のうち、ここではステップ1〜3のみを担う）。
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
