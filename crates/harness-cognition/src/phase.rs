//! フェーズ仕様表。`plans/DESIGN-COGNITION.md` §3.3の表を**1対1でコードへ写した**もの。
//!
//! 表の各列（入力コンテキスト・出力スキーマ・予算目安・許可ツール）が、それぞれ
//! [`PhaseSpec`]のフィールドになる。設計文書と実装が1対1なので、片方だけ変わったときに
//! 差分が読める。

use std::collections::BTreeMap;

use harness_core::{Phase, RiskClass, TokenBudget};

use crate::memory::render::MemoryView;
use crate::memory::types::{GoalId, HypId};

/// そのフェーズがモデルへ渡すツールの候補集合（§7.3 ToolGateの、候補を絞る側）。
///
/// **候補集合を絞るだけで、最終強制は`PermissionArbiter`のまま**である。ここで
/// read-onlyに絞っても、実行時のパーミッション判定は`harness-engine`の1箇所を必ず通る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSelection {
    /// ツールを一切渡さない（純粋な解釈コール）。
    None,
    /// `RiskClass::ReadOnly`のツールだけ。
    ReadOnly,
    /// 全ツール（最終強制はパーミッションゲート）。
    All,
}

impl ToolSelection {
    pub fn admits(self, risk: RiskClass) -> bool {
        match self {
            ToolSelection::None => false,
            ToolSelection::ReadOnly => risk == RiskClass::ReadOnly,
            ToolSelection::All => true,
        }
    }
}

/// 1フェーズの仕様。
#[derive(Debug, Clone, Copy)]
pub struct PhaseSpec {
    /// 台帳のどのスライスを入力にするか。
    pub view: MemoryView,
    /// モデルへ渡すツールの候補集合。
    pub tools: ToolSelection,
    /// 出力スキーマを要求するか。`false`はツール実行のためのコール。
    pub wants_schema: bool,
}

/// フェーズ仕様を引く。`target`は対象仮説（Investigate/Verify/Critic）、`goal`は
/// 対象ゴール（Decide）。指定が無い場合はビューが空になり、組み立ては失敗せず
/// 「台帳スライス無し」のコールになる。
pub fn spec(phase: Phase, target: Option<HypId>, goal: Option<GoalId>) -> PhaseSpec {
    match phase {
        Phase::Orient => PhaseSpec {
            view: MemoryView::GoalSummary,
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Hypothesize => PhaseSpec {
            view: MemoryView::Unknowns,
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Investigate => PhaseSpec {
            view: target.map_or(MemoryView::None, MemoryView::HypothesisPlan),
            // §3.3「read-only + 指定MCPのみ」。write/execを候補から物理的に外す。
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Distill => PhaseSpec {
            // 入力は生出力（scratchから注入）だけで、台帳スライスは要らない。
            view: MemoryView::None,
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Verify => PhaseSpec {
            view: target.map_or(MemoryView::None, MemoryView::EvidenceFor),
            // §3.3「検証系のみ（test/typecheck/re-read）」。M14の内蔵ツールでは
            // read-onlyがその最も近い候補集合になる（`run_shell`でのテスト実行を
            // 検証系として通すのはM15のRunCheckサブループの仕事）。
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Critic => PhaseSpec {
            view: target.map_or(MemoryView::None, MemoryView::VerificationOf),
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Decide => PhaseSpec {
            view: goal.map_or(MemoryView::None, MemoryView::ConfirmedForGoal),
            // ゴール達成に必要なwrite/exec。承認ゲートは従来通り必ず通る。
            tools: ToolSelection::All,
            wants_schema: true,
        },
    }
}

/// フェーズ別トークン予算の表（§3.3「予算目安」列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseBudgets {
    budgets: BTreeMap<Phase, TokenBudget>,
}

impl Default for PhaseBudgets {
    /// `plans/DESIGN-COGNITION.md` §3.3の数値そのもの。
    fn default() -> Self {
        let budgets = BTreeMap::from([
            (
                Phase::Orient,
                TokenBudget {
                    max_in: 2_000,
                    max_out: 500,
                },
            ),
            (
                Phase::Hypothesize,
                TokenBudget {
                    max_in: 3_000,
                    max_out: 1_000,
                },
            ),
            (
                Phase::Investigate,
                TokenBudget {
                    max_in: 3_000,
                    max_out: 1_000,
                },
            ),
            (
                Phase::Distill,
                TokenBudget {
                    max_in: 4_000,
                    max_out: 500,
                },
            ),
            (
                Phase::Verify,
                TokenBudget {
                    max_in: 4_000,
                    max_out: 500,
                },
            ),
            (
                Phase::Critic,
                TokenBudget {
                    max_in: 2_000,
                    max_out: 500,
                },
            ),
            (
                Phase::Decide,
                TokenBudget {
                    max_in: 2_000,
                    max_out: 500,
                },
            ),
        ]);
        Self { budgets }
    }
}

impl PhaseBudgets {
    /// `settings.json`の`cognition.budgets`で既定表を上書きする。
    ///
    /// 指定されなかったフェーズは既定のまま（部分上書き）。設定に無いフェーズが
    /// 予算ゼロになると、そのフェーズだけ台帳スライスが空になって静かに壊れるため。
    pub fn with_overrides(mut self, overrides: &BTreeMap<Phase, TokenBudget>) -> Self {
        for (phase, budget) in overrides {
            self.budgets.insert(*phase, *budget);
        }
        self
    }

    /// そのフェーズの予算。`Default`が全フェーズを埋めるので必ず値がある。
    pub fn get(&self, phase: Phase) -> TokenBudget {
        self.budgets
            .get(&phase)
            .copied()
            // `Default`と`with_overrides`の不変条件により到達しないが、
            // パニックさせるほどの事でもないので保守的な小さい値へ倒す。
            .unwrap_or(TokenBudget {
                max_in: 2_000,
                max_out: 500,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表が全フェーズを埋めていること（`Phase`にバリアントを足したら落ちる）。
    #[test]
    fn every_phase_has_a_spec_and_a_budget() {
        let budgets = PhaseBudgets::default();
        for phase in Phase::ALL {
            let b = budgets.get(phase);
            assert!(b.max_in > 0 && b.max_out > 0, "{phase}");
            let _ = spec(phase, None, None);
        }
    }

    /// §3.3の予算目安と一致していること（設計文書の数値が正本）。
    #[test]
    fn default_budgets_match_the_design_table() {
        let b = PhaseBudgets::default();
        assert_eq!(
            b.get(Phase::Orient),
            TokenBudget {
                max_in: 2_000,
                max_out: 500
            }
        );
        assert_eq!(
            b.get(Phase::Hypothesize),
            TokenBudget {
                max_in: 3_000,
                max_out: 1_000
            }
        );
        assert_eq!(
            b.get(Phase::Distill),
            TokenBudget {
                max_in: 4_000,
                max_out: 500
            }
        );
        assert_eq!(
            b.get(Phase::Verify),
            TokenBudget {
                max_in: 4_000,
                max_out: 500
            }
        );
    }

    #[test]
    fn overrides_are_partial_and_leave_other_phases_at_the_default() {
        let overrides = BTreeMap::from([(
            Phase::Distill,
            TokenBudget {
                max_in: 1_234,
                max_out: 42,
            },
        )]);
        let b = PhaseBudgets::default().with_overrides(&overrides);
        assert_eq!(
            b.get(Phase::Distill),
            TokenBudget {
                max_in: 1_234,
                max_out: 42
            }
        );
        assert_eq!(
            b.get(Phase::Orient),
            TokenBudget {
                max_in: 2_000,
                max_out: 500
            }
        );
    }

    /// §7.3: Investigateはread-onlyしか候補に入れない（write/execを物理的に外す）。
    #[test]
    fn investigate_admits_read_only_tools_only() {
        let s = spec(Phase::Investigate, None, None);
        assert!(s.tools.admits(RiskClass::ReadOnly));
        assert!(!s.tools.admits(RiskClass::Write));
        assert!(!s.tools.admits(RiskClass::Exec));
        assert!(!s.tools.admits(RiskClass::Network));
    }

    /// 解釈フェーズはツールを一切渡さない（選択肢が無ければ誤用も無い）。
    #[test]
    fn interpretation_phases_get_no_tools_at_all() {
        for phase in [
            Phase::Orient,
            Phase::Hypothesize,
            Phase::Distill,
            Phase::Critic,
        ] {
            let s = spec(phase, None, None);
            for risk in [
                RiskClass::ReadOnly,
                RiskClass::Write,
                RiskClass::Exec,
                RiskClass::Network,
            ] {
                assert!(!s.tools.admits(risk), "{phase} admitted {risk:?}");
            }
        }
    }

    /// Decideだけがwrite/execを候補に持つ（承認ゲートは別途必ず通る）。
    #[test]
    fn decide_admits_write_and_exec_candidates() {
        let s = spec(Phase::Decide, None, None);
        assert!(s.tools.admits(RiskClass::Write));
        assert!(s.tools.admits(RiskClass::Exec));
    }

    /// 対象仮説が指定されなければビューは空になる（組み立て自体は失敗しない）。
    #[test]
    fn missing_target_degrades_to_an_empty_view_rather_than_failing() {
        assert_eq!(spec(Phase::Verify, None, None).view, MemoryView::None);
        assert_eq!(
            spec(Phase::Verify, Some(HypId(2)), None).view,
            MemoryView::EvidenceFor(HypId(2))
        );
    }
}
