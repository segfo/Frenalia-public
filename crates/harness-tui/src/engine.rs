//! バックグラウンドの「engineアクター」。`ConversationState`を1タスクに閉じ込め、
//! ユーザ入力（プロンプト）をmpscで受け取ってターンを1つずつ`run_agent_loop`へ渡し、
//! `AgentEvent`を別のmpscでTUI側へ流す（§リッチTUI「非同期ループ」）。
//! `PermissionArbiter`は`InteractiveGate`越しに参照されるため、承認待ちの間もTUIの描画
//! ループ（別タスク）は動き続けられる。
//!
//! M9で以下を追加した:
//! - `cancel_current()`: 進行中ターンを`CancellationToken`でキャンセルする（Escキー、
//!   §エージェントループ キャンセル整合）。ターンごとに使い捨てトークンを生成し
//!   `cancel_slot`へ差し替えるため、キャンセル済みトークンが次のターンへ持ち越されない。
//! - `EngineCommand`（`SetModel`/`Compact`/`Clear`）: `state`はこのタスク内に閉じているため、
//!   スラッシュコマンドのうち`state`に触れるものは`prompt_tx`と同様mpsc経由で処理する
//!   （`/mode`/`/allow`は`InteractiveGate`が直接持つため`gate`経由、engineタスクを介さない）。
//! - JSONL セッション永続化: プロンプト送信直後・ターン完了直後の両方で増分メッセージを
//!   `SessionStore`へ追記する。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use harness_core::{AgentEvent, LlmProvider, ToolCtx};
use harness_engine::{
    compaction, run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, SessionStore,
};
use harness_tools::ToolRegistry;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::gate::InteractiveGate;

enum EngineCommand {
    SetModel(String),
    Compact,
    Clear,
    /// 現在のセッションをForkし、以降の追記を新しいファイルへ切り替える（`/fork`）。
    /// 元IDと新IDを`AgentEvent::Info`で通知する。
    Fork,
    /// 既存セッションへ切り替える（`/sessions`のピッカーで選択された結果）。
    SwitchSession {
        session: SessionStore,
        messages: Vec<harness_core::Message>,
    },
}

pub struct EngineHandle {
    prompt_tx: mpsc::UnboundedSender<String>,
    command_tx: mpsc::UnboundedSender<EngineCommand>,
    pub events_rx: mpsc::UnboundedReceiver<AgentEvent>,
    pub gate: Arc<InteractiveGate>,
    cancel_slot: Arc<Mutex<CancellationToken>>,
}

impl EngineHandle {
    pub fn submit(&self, prompt: String) {
        let _ = self.prompt_tx.send(prompt);
    }

    pub fn set_model(&self, model: String) {
        let _ = self.command_tx.send(EngineCommand::SetModel(model));
    }

    pub fn compact(&self) {
        let _ = self.command_tx.send(EngineCommand::Compact);
    }

    pub fn clear(&self) {
        let _ = self.command_tx.send(EngineCommand::Clear);
    }

    pub fn fork(&self) {
        let _ = self.command_tx.send(EngineCommand::Fork);
    }

    pub fn switch_session(&self, session: SessionStore, messages: Vec<harness_core::Message>) {
        let _ = self
            .command_tx
            .send(EngineCommand::SwitchSession { session, messages });
    }

    /// 現在進行中のターンをキャンセルする（Escキー、M9）。進行中のターンが無ければ無害。
    pub fn cancel_current(&self) {
        self.cancel_slot.lock().unwrap().cancel();
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
    mut state: ConversationState,
    mut session: SessionStore,
    sessions_dir: PathBuf,
) -> EngineHandle {
    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<String>();
    let (command_tx, mut command_rx) = mpsc::unbounded_channel::<EngineCommand>();
    let (events_tx, events_rx) = mpsc::unbounded_channel::<AgentEvent>();
    let gate = Arc::new(InteractiveGate::new(arbiter, events_tx.clone()));
    let gate_for_task = gate.clone();
    let cancel_slot: Arc<Mutex<CancellationToken>> = Arc::new(Mutex::new(CancellationToken::new()));
    let cancel_for_task = cancel_slot.clone();
    let mut model = model;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                prompt = prompt_rx.recv() => {
                    let Some(prompt) = prompt else { break };
                    state.push_user_text(prompt);
                    let _ = session.append_messages(&state.messages[state.messages.len() - 1..]);
                    let before_turn = state.messages.len();

                    let turn_cancel = CancellationToken::new();
                    *cancel_for_task.lock().unwrap() = turn_cancel.clone();

                    let result = run_agent_loop(
                        provider.as_ref(),
                        &mut state,
                        &tools,
                        &ctx,
                        gate_for_task.as_ref(),
                        AgentLoopConfig { model: model.clone(), max_tokens, max_turns },
                        Some(&events_tx),
                        Some(&turn_cancel),
                        // TextDelta は`events`側で既に発行されるため、ここでの二重出力は不要
                        // （§リッチTUI: TUIは`AgentEvent`のみを消費する）。
                        |_delta| {},
                    )
                    .await;
                    let _ = session.append_messages(&state.messages[before_turn..]);
                    if let Err(e) = result {
                        let _ = events_tx.send(AgentEvent::Error {
                            message: e.to_string(),
                        });
                    }
                }
                cmd = command_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        EngineCommand::SetModel(m) => {
                            model = m;
                        }
                        EngineCommand::Compact => {
                            match compaction::compact(
                                provider.as_ref(),
                                &mut state,
                                &model,
                                compaction::DEFAULT_KEEP_RECENT_TURNS,
                            )
                            .await
                            {
                                Ok(removed) => {
                                    let _ = events_tx.send(AgentEvent::ContextCompacted {
                                        removed_messages: removed,
                                    });
                                }
                                Err(e) => {
                                    let _ = events_tx.send(AgentEvent::Error {
                                        message: e.to_string(),
                                    });
                                }
                            }
                        }
                        EngineCommand::Clear => {
                            state = ConversationState::new();
                            if let Ok(fresh) = SessionStore::create_new(&sessions_dir) {
                                session = fresh;
                            }
                        }
                        EngineCommand::Fork => {
                            let source_id = session.id();
                            match SessionStore::fork_from(&sessions_dir, session.path()) {
                                Ok(forked) => {
                                    let new_id = forked.id();
                                    let message_count = state.messages.len();
                                    session = forked;
                                    let _ = events_tx.send(AgentEvent::SessionSwitched {
                                        source_id: Some(source_id),
                                        new_id,
                                        message_count,
                                    });
                                }
                                Err(e) => {
                                    let _ = events_tx.send(AgentEvent::Error {
                                        message: format!("failed to fork session: {e}"),
                                    });
                                }
                            }
                        }
                        EngineCommand::SwitchSession { session: new_session, messages } => {
                            let new_id = new_session.id();
                            let message_count = messages.len();
                            state = ConversationState { messages, ..ConversationState::new() };
                            session = new_session;
                            let _ = events_tx.send(AgentEvent::SessionSwitched {
                                source_id: None,
                                new_id,
                                message_count,
                            });
                        }
                    }
                }
            }
        }
    });

    EngineHandle {
        prompt_tx,
        command_tx,
        events_rx,
        gate,
        cancel_slot,
    }
}
