//! 認知オーケストレータ。`plans/DESIGN-COGNITION.md` §1「`CognitiveOrchestrator`: 認知の
//! 唯一の強制点」・§2「Effortスイッチ」。

use harness_core::{
    AgentEvent, CognitionLevel, ContentBlock, LlmProvider, Message, ProviderError, Role,
    StopReason, ToolCtx,
};
use harness_engine::{
    emit_event, run_agent_loop, AgentLoopConfig, AgentLoopOutcome, ConversationState, EventSink,
    PermissionGate, TurnExecutor,
};
use harness_tools::ToolRegistry;
use tokio_util::sync::CancellationToken;

use crate::context::ContextAssembler;
use crate::hiv::{HivContext, HivEngine, HivLimits, HivStop};
use crate::phase::PhaseBudgets;
use crate::scratch::ScratchStore;

/// まだ実装されていない`CognitionLevel`が要求された。
///
/// 黙って`Off`へ降格させない理由: 認知レイヤーの有無はモデルの振る舞いを大きく変えるため、
/// 「`--cognition auto`を指定したのに素朴ループで走っていた」という取り違えは、
/// 出力を見ても気付けない。起動時に止める（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedLevel {
    pub level: CognitionLevel,
}

impl std::fmt::Display for UnsupportedLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let milestone = match self.level {
            CognitionLevel::Auto => "M17（難易度ルータ）",
            CognitionLevel::Off | CognitionLevel::Always => {
                return write!(f, "cognition level `{}` is supported", self.level)
            }
        };
        write!(
            f,
            "cognition level `{}` is not implemented yet (planned for {milestone}; see \
             docs/INDEX.md). Use `--cognition off` or `--cognition always` for now.",
            self.level
        )
    }
}

impl std::error::Error for UnsupportedLevel {}

/// 認知レイヤーの入口。フロントエンドはエージェントループを直接呼ばず、必ずここを通す。
///
/// M15時点で実行できるのは`Off`（素朴ループ）と`Always`（HIVループのライト構成）。
/// `Auto`は難易度ルータ（M17）が無いため[`CognitiveOrchestrator::new`]が拒否する。
#[derive(Debug, Clone)]
pub struct CognitiveOrchestrator {
    level: CognitionLevel,
    budgets: PhaseBudgets,
    limits: HivLimits,
    /// scratch（生出力の退避先）をセッションディレクトリへ向けるためのID。
    /// 未設定なら退避せずインメモリで進む（調査自体は止めない）。
    session_id: Option<String>,
}

impl CognitiveOrchestrator {
    /// 実行できない段階が要求されたら[`UnsupportedLevel`]を返す。呼び出し側（`harness-cli`の
    /// `stage_configure`）はこれを起動時のfail-fastに使う。
    ///
    /// `budgets`は`settings.json`の`cognition.budgets`を反映した表（§3.3・§6.1）。
    pub fn new(level: CognitionLevel, budgets: PhaseBudgets) -> Result<Self, UnsupportedLevel> {
        match level {
            CognitionLevel::Off | CognitionLevel::Always => Ok(Self {
                level,
                budgets,
                limits: HivLimits::default(),
                session_id: None,
            }),
            CognitionLevel::Auto => Err(UnsupportedLevel { level }),
        }
    }

    /// 生出力の退避先を`<workspace_root>/.harness/cognition/<session-id>/`にする（§5）。
    /// 会話履歴と同じIDを使うことで、M20の`--resume`が両方を同じ鍵で復元できる。
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn level(&self) -> CognitionLevel {
        self.level
    }

    /// 1回のユーザ発話に対する処理を最後まで進める。
    ///
    /// `on_text_delta`はヘッドレスのtext出力専用（`harness-cli`が`&mut W`をキャプチャする）で、
    /// TUIは`events`から`AgentEvent`を受け取るため空クロージャを渡す。
    #[allow(clippy::too_many_arguments)]
    pub async fn run<F>(
        &self,
        provider: &dyn LlmProvider,
        state: &mut ConversationState,
        tools: &ToolRegistry,
        ctx: &ToolCtx,
        gate: &dyn PermissionGate,
        config: AgentLoopConfig,
        events: Option<&EventSink>,
        cancel: Option<&CancellationToken>,
        on_text_delta: F,
    ) -> Result<AgentLoopOutcome, ProviderError>
    where
        F: FnMut(&str),
    {
        match self.level {
            CognitionLevel::Off => {
                run_agent_loop(
                    provider,
                    state,
                    tools,
                    ctx,
                    gate,
                    config,
                    events,
                    cancel,
                    on_text_delta,
                )
                .await
            }
            CognitionLevel::Always => {
                self.run_hiv(
                    provider,
                    state,
                    tools,
                    ctx,
                    gate,
                    config,
                    events,
                    cancel,
                    on_text_delta,
                )
                .await
            }
            // `new`が弾いているため到達しない。`unreachable!()`でパニックさせず、
            // 実装漏れが本番で表面化しても停止だけで済むようエラーで返す
            // （到達経路が新設されたときの保険）。
            level @ CognitionLevel::Auto => Err(ProviderError::InvalidRequest {
                msg: UnsupportedLevel { level }.to_string(),
            }),
        }
    }

    /// HIVループ（ライト）の1ゴール分。
    ///
    /// 会話履歴（`ConversationState`）はLLMコールには使わず（各フェーズは台帳スライスから
    /// 組む、§5）、**ゴール文の取得と最終回答の追記にだけ**使う。こうすることで、
    /// セッション永続化・`--resume`・ヘッドレスのtext/json出力は素朴ループと同じ経路のまま動く。
    #[allow(clippy::too_many_arguments)]
    async fn run_hiv<F>(
        &self,
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
        let Some(goal) = last_user_text(state) else {
            return Err(ProviderError::InvalidRequest {
                msg: "cognition layer needs a user message to derive the goal from".to_string(),
            });
        };

        let executor = TurnExecutor::new(
            provider,
            tools,
            ctx,
            gate,
            events,
            cancel,
            config.degeneracy.as_ref(),
        );
        let assembler = ContextAssembler::new(config.model.clone(), self.budgets.clone());
        let scratch = self.open_scratch(ctx);
        let limits = HivLimits {
            // `--max-turns`を認知層へ拡張する（§3.5）。フェーズ1つ＝1コールなので、
            // 素朴ループの「ターン」と同じ単位で数えられる。
            max_phase_calls: config.max_turns,
            ..self.limits
        };
        let mut engine = HivEngine::new(assembler, scratch, limits);

        let cx = HivContext {
            exec: &executor,
            ctx,
            tools,
            caps: provider.capabilities(),
            events,
            cancel,
        };
        let outcome = engine.run_goal(&goal, &cx).await;

        if let Some(e) = outcome.provider_error {
            emit_event(
                events,
                AgentEvent::Error {
                    message: e.to_string(),
                },
            );
            return Err(e);
        }

        if outcome.stop == HivStop::Cancelled {
            emit_event(events, AgentEvent::Cancelled);
            return Ok(AgentLoopOutcome {
                text: String::new(),
                stop_reason: StopReason::Other("cancelled".to_string()),
                usage: outcome.usage,
                cancelled: true,
            });
        }

        // 最終回答は台帳から決定的に組んだもの（追加のLLMコールは使わない）。フェーズ中の
        // デルタは`TurnVisibility::Internal`で抑止しているので、ユーザに見える本文はこれだけ。
        on_text_delta(&outcome.answer);
        emit_event(
            events,
            AgentEvent::TextDelta {
                text: outcome.answer.clone(),
            },
        );
        state.messages.push(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text(outcome.answer.clone())],
        });

        let stop_reason = match &outcome.stop {
            HivStop::Decided => StopReason::EndTurn,
            // 確証に至らなかったことを終了コードにも出す（ヘッドレスの`exit_code_for`は
            // `Other`を4にする）。「答えは返ったが確証はしていない」を呼び出し側の
            // スクリプトが区別できるようにするため。
            HivStop::Blocked { .. } => StopReason::Other("cognition_blocked".to_string()),
            HivStop::BudgetExhausted => StopReason::Other("cognition_budget_exhausted".to_string()),
            HivStop::Cancelled => StopReason::Other("cancelled".to_string()),
        };
        emit_event(
            events,
            AgentEvent::TurnCompleted {
                stop_reason: stop_reason.clone(),
                usage: outcome.usage,
            },
        );

        Ok(AgentLoopOutcome {
            text: outcome.answer,
            stop_reason,
            usage: outcome.usage,
            cancelled: false,
        })
    }

    /// scratchを開く。**失敗しても`None`で続行する**——生出力の退避はコンテキストを
    /// 小さく保つための最適化であって、調査そのものの前提ではない（開けなければ
    /// 蒸留コールへ手元の出力をそのまま渡す）。
    fn open_scratch(&self, ctx: &ToolCtx) -> Option<ScratchStore> {
        let session_id = self.session_id.as_ref()?;
        let dir = ScratchStore::dir_for_session(&ctx.workspace_root, session_id);
        ScratchStore::open(&dir).ok()
    }
}

/// 直近のユーザ発話（＝このターンのゴール）。ツール結果だけのuserメッセージは飛ばす。
fn last_user_text(state: &ConversationState) -> Option<String> {
    state.messages.iter().rev().find_map(|m| {
        if m.role != Role::User {
            return None;
        }
        let text: String = m
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                // ツール結果だけのuserメッセージ（素朴ループが積むもの）はゴールにしない。
                ContentBlock::Thinking { .. }
                | ContentBlock::RedactedThinking { .. }
                | ContentBlock::ToolUse { .. }
                | ContentBlock::ToolResult { .. }
                | ContentBlock::Image { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        (!text.trim().is_empty()).then_some(text)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orchestrator(level: CognitionLevel) -> CognitiveOrchestrator {
        CognitiveOrchestrator::new(level, PhaseBudgets::default()).unwrap()
    }

    #[test]
    fn off_and_always_are_constructible() {
        assert_eq!(
            orchestrator(CognitionLevel::Off).level(),
            CognitionLevel::Off
        );
        assert_eq!(
            orchestrator(CognitionLevel::Always).level(),
            CognitionLevel::Always
        );
    }

    /// 未実装の段階は起動時に止まる（黙って`Off`へ降格しない）。M15時点では`Auto`だけ。
    #[test]
    fn auto_is_rejected_until_the_router_exists() {
        let err =
            CognitiveOrchestrator::new(CognitionLevel::Auto, PhaseBudgets::default()).unwrap_err();
        assert_eq!(err.level, CognitionLevel::Auto);
        let msg = err.to_string();
        assert!(msg.contains("not implemented yet"), "{msg}");
        assert!(msg.contains("M17"), "{msg}");
    }

    #[test]
    fn the_goal_is_the_latest_user_utterance() {
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("最初の依頼");
        state.messages.push(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text("応答".to_string())],
        });
        // ツール結果だけのuserメッセージはゴールにしない。
        state.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: "result".to_string(),
                is_error: false,
            }],
        });
        state.push_user_text("次の依頼");

        assert_eq!(last_user_text(&state).as_deref(), Some("次の依頼"));
    }

    #[test]
    fn a_conversation_without_user_text_has_no_goal() {
        let state = ConversationState::new(Vec::new());
        assert!(last_user_text(&state).is_none());
    }
}
