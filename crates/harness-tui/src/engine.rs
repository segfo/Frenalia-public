//! バックグラウンドの「engineアクター」。`ConversationState`を1タスクに閉じ込め、
//! ユーザ入力（プロンプト）をmpscで受け取ってターンを1つずつ`run_agent_loop`へ渡し、
//! `AgentEvent`を別のmpscでTUI側へ流す（§リッチTUI「非同期ループ」）。
//! `PermissionArbiter`は`InteractiveGate`越しに参照されるため、承認待ちの間もTUIの描画
//! ループ（別タスク）は動き続けられる。

use std::sync::Arc;

use harness_core::{AgentEvent, LlmProvider, ToolCtx};
use harness_engine::{run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter};
use harness_tools::ToolRegistry;
use tokio::sync::mpsc;

use crate::gate::InteractiveGate;

pub struct EngineHandle {
    prompt_tx: mpsc::UnboundedSender<String>,
    pub events_rx: mpsc::UnboundedReceiver<AgentEvent>,
    pub gate: Arc<InteractiveGate>,
}

impl EngineHandle {
    pub fn submit(&self, prompt: String) {
        let _ = self.prompt_tx.send(prompt);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_engine(
    provider: Box<dyn LlmProvider>,
    tools: ToolRegistry,
    ctx: ToolCtx,
    arbiter: PermissionArbiter,
    model: String,
    max_tokens: u32,
    max_turns: usize,
) -> EngineHandle {
    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<String>();
    let (events_tx, events_rx) = mpsc::unbounded_channel::<AgentEvent>();
    let gate = Arc::new(InteractiveGate::new(arbiter, events_tx.clone()));
    let gate_for_task = gate.clone();

    tokio::spawn(async move {
        let mut state = ConversationState::new();
        while let Some(prompt) = prompt_rx.recv().await {
            state.push_user_text(prompt);
            let result = run_agent_loop(
                provider.as_ref(),
                &mut state,
                &tools,
                &ctx,
                gate_for_task.as_ref(),
                AgentLoopConfig {
                    model: model.clone(),
                    max_tokens,
                    max_turns,
                },
                Some(&events_tx),
                // TextDelta は`events`側で既に発行されるため、ここでの二重出力は不要
                // （§リッチTUI: TUIは`AgentEvent`のみを消費する）。
                |_delta| {},
            )
            .await;
            if let Err(e) = result {
                let _ = events_tx.send(AgentEvent::Error {
                    message: e.to_string(),
                });
            }
        }
    });

    EngineHandle {
        prompt_tx,
        events_rx,
        gate,
    }
}
