//! 認知オーケストレータ。`plans/DESIGN-COGNITION.md` §1「`CognitiveOrchestrator`: 認知の
//! 唯一の強制点」・§2「Effortスイッチ」。

use harness_core::{CognitionLevel, LlmProvider, ProviderError, ToolCtx};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, AgentLoopOutcome, ConversationState, EventSink, PermissionGate,
};
use harness_tools::ToolRegistry;
use tokio_util::sync::CancellationToken;

/// まだ実装されていない`CognitionLevel`が要求された。
///
/// 黙って`Off`へ降格させない理由: 認知レイヤーの有無はモデルの振る舞いを大きく変えるため、
/// 「`--cognition always`を指定したのに素朴ループで走っていた」という取り違えは、
/// 出力を見ても気付けない。起動時に止める（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedLevel {
    pub level: CognitionLevel,
}

impl std::fmt::Display for UnsupportedLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let milestone = match self.level {
            CognitionLevel::Auto => "M17（難易度ルータ）",
            CognitionLevel::Always => "M15–M19（HIVループ・Planner・Critic）",
            CognitionLevel::Off => return write!(f, "cognition level `off` is supported"),
        };
        write!(
            f,
            "cognition level `{}` is not implemented yet (planned for {milestone}; see \
             docs/INDEX.md). Use `--cognition off` for now.",
            self.level
        )
    }
}

impl std::error::Error for UnsupportedLevel {}

/// 認知レイヤーの入口。フロントエンドはエージェントループを直接呼ばず、必ずここを通す。
///
/// M13時点では`Off`（素朴ループへの委譲）のみを実装しており、実質的な通過層である。
/// この段階でフロントエンドの経路をここへ寄せておくことで、M14以降は
/// [`CognitiveOrchestrator::run`]の内側を埋めるだけで済む。
#[derive(Debug, Clone, Copy)]
pub struct CognitiveOrchestrator {
    level: CognitionLevel,
}

impl CognitiveOrchestrator {
    /// 実行できない段階が要求されたら[`UnsupportedLevel`]を返す。呼び出し側（`harness-cli`の
    /// `stage_configure`）はこれを起動時のfail-fastに使う。
    pub fn new(level: CognitionLevel) -> Result<Self, UnsupportedLevel> {
        match level {
            CognitionLevel::Off => Ok(Self { level }),
            CognitionLevel::Auto | CognitionLevel::Always => Err(UnsupportedLevel { level }),
        }
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
            // `new`が弾いているため到達しない。`unreachable!()`でパニックさせず、
            // 実装漏れが本番で表面化しても停止だけで済むようエラーで返す
            // （到達経路が新設されたときの保険）。
            level @ (CognitionLevel::Auto | CognitionLevel::Always) => {
                Err(ProviderError::InvalidRequest {
                    msg: UnsupportedLevel { level }.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_is_constructible() {
        let orchestrator = CognitiveOrchestrator::new(CognitionLevel::Off).unwrap();
        assert_eq!(orchestrator.level(), CognitionLevel::Off);
    }

    /// 未実装の段階は起動時に止まる（黙って`Off`へ降格しない）。
    #[test]
    fn auto_and_always_are_rejected_until_implemented() {
        for level in [CognitionLevel::Auto, CognitionLevel::Always] {
            let err = CognitiveOrchestrator::new(level).unwrap_err();
            assert_eq!(err.level, level);
            let msg = err.to_string();
            assert!(msg.contains("not implemented yet"), "{msg}");
            assert!(msg.contains(level.as_str()), "{msg}");
        }
    }
}
