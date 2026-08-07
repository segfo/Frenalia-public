//! フェーズ仕様表。`plans/DESIGN-COGNITION.md` §3.3の表を**1対1でコードへ写した**もの。
//!
//! 表の各列（入力コンテキスト・出力スキーマ・予算目安・許可ツール）が、それぞれ
//! [`PhaseSpec`]のフィールドになる。設計文書と実装が1対1なので、片方だけ変わったときに
//! 差分が読める。

use std::collections::BTreeMap;

use harness_core::{Phase, RiskClass, TokenBudget};

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
    /// モデルへ渡すツールの候補集合。
    pub tools: ToolSelection,
    /// 出力スキーマを要求するか。`false`はツール実行のためのコール。
    pub wants_schema: bool,
}

/// フェーズ仕様を引く。`tools`/`wants_schema`はフェーズだけで決まる（対象仮説・対象ゴールの
/// 値には依存しない）。台帳のどのスライスを見せるか（旧`view: MemoryView`）は
/// [`crate::ledger::LedgerView`]の実装側（`WorkingMemory::render_slice`）が持つ——
/// `target`/`goal`に依存する部分はそちらへ移した（`plans/PLAN-SURVEY-ENGINE.md`段階1）。
pub fn spec(phase: Phase) -> PhaseSpec {
    match phase {
        Phase::Orient => PhaseSpec {
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Hypothesize => PhaseSpec {
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Investigate => PhaseSpec {
            // §3.3「read-only + 指定MCPのみ」。write/execを候補から物理的に外す。
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Distill => PhaseSpec {
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Verify => PhaseSpec {
            // §3.3「検証系のみ（test/typecheck/re-read）」。M14の内蔵ツールでは
            // read-onlyがその最も近い候補集合になる（`run_shell`でのテスト実行を
            // 検証系として通すのはM15のRunCheckサブループの仕事）。
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Critic => PhaseSpec {
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Decide => PhaseSpec {
            // ゴール達成に必要なwrite/exec。承認ゲートは従来通り必ず通る。
            tools: ToolSelection::All,
            wants_schema: true,
        },
        Phase::Recall => PhaseSpec {
            // 候補の要約だけを見る解釈コール（`PhaseInput.raw_output`で運ぶ）。
            // ツールは渡さない——検索そのものはbigramで済ませており、このコールは
            // 関連性・信頼性判定に徹する。
            tools: ToolSelection::None,
            wants_schema: true,
        },
        Phase::Plan => PhaseSpec {
            // 列挙自体はツール（`glob`等）で行う。モデルに数えさせない
            // （`plans/PLAN-SURVEY-ENGINE.md`「列挙自体はツール」）。
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Collect => PhaseSpec {
            tools: ToolSelection::ReadOnly,
            wants_schema: true,
        },
        Phase::Join => PhaseSpec {
            tools: ToolSelection::None,
            wants_schema: true,
        },
    }
}

/// クランプ後もこれ以上は下げない`max_in`の下限。ここを割ると台帳スライスが
/// [`crate::context`]の`MIN_BODY_CHARS`まで削られても収まらず、組み立てが必ず超過して返る。
/// 縮小再試行（§6.6 規則3、[`crate::call`]）も同じ下限で止まる。
pub(crate) const MIN_CLAMPED_MAX_IN: u32 = 512;

/// クランプ後もこれ以上は下げない`max_out`の下限。構造化出力1件分が入らないと、
/// どのフェーズもスキーマ検証に通らず`SchemaRejected`で必ず止まる。
const MIN_CLAMPED_MAX_OUT: u32 = 256;

/// フェーズ別トークン予算の表（§3.3「予算目安」列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseBudgets {
    budgets: BTreeMap<Phase, TokenBudget>,
}

/// [`PhaseBudgets::clamped_to_window`]が実際に縮めた1フェーズ分の記述子
/// （`plans/DESIGN-COGNITION.md` §6.6 規則1「黙って弱めない」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetClamp {
    pub phase: Phase,
    pub before: TokenBudget,
    pub after: TokenBudget,
    /// 下限まで削ってもコンテキスト窓に収まらなかった。この状態のフェーズは
    /// 送信前ゲート（§6.6 規則2）で止まる可能性が高い。
    pub still_too_large: bool,
}

impl std::fmt::Display for BudgetClamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: max_in {}→{}, max_out {}→{}{}",
            self.phase,
            self.before.max_in,
            self.after.max_in,
            self.before.max_out,
            self.after.max_out,
            if self.still_too_large {
                "（下限まで削っても窓に収まらない）"
            } else {
                ""
            }
        )
    }
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
            // `plans/PLAN-RECALL-MEMORY.md`。候補要約だけを見る小さな解釈コール。
            (
                Phase::Recall,
                TokenBudget {
                    max_in: 2_000,
                    max_out: 500,
                },
            ),
            // `plans/PLAN-SURVEY-ENGINE.md`段階2。Plan/CollectはInvestigate準拠。
            (
                Phase::Plan,
                TokenBudget {
                    max_in: 3_000,
                    max_out: 1_000,
                },
            ),
            (
                Phase::Collect,
                TokenBudget {
                    max_in: 3_000,
                    max_out: 1_000,
                },
            ),
            // Joinは多数のnotesを1度に読むため既定より大きめ。`cognition.budgets.join`で
            // 上書き可能。
            (
                Phase::Join,
                TokenBudget {
                    max_in: 6_000,
                    max_out: 1_500,
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

    /// 実コンテキスト窓に収まらないフェーズ予算を縮める（§6.6 規則1、予防）。
    ///
    /// 1コールは会話履歴を持たない独立した`max_in + max_out`なので、この和が窓を超える
    /// 予算は**必ず**超過する。既定表（最大4,000+1,000）はクラウドモデルでは問題にならないが、
    /// ローカル推論サーバの実`n_ctx`は4k–8kで、しかも推論を出すモデルでは
    /// `cognition.budgets`の`max_out`を3,000–4,000へ引き上げる運用になる
    /// （`docs/STATUS.md`認知レイヤー残課題#9）。この2つが噛み合うと起動直後から全コールが超過する。
    ///
    /// **`max_in`から先に削る**のは、`max_out`を削ると本文が出力枠を使い切って0文字になり、
    /// 縮退ガードが毎コール発火して回復の梯子を登り切る（＝fail-closedで止まる）ためである。
    /// 入力側は[`crate::context::ContextAssembler`]が段階的に縮約できるので、削っても
    /// 「情報が減る」だけで壊れない。
    ///
    /// 戻り値の`Vec`は実際に縮めたフェーズだけ。空なら何も変えていない。
    pub fn clamped_to_window(mut self, context_window: u32) -> (Self, Vec<BudgetClamp>) {
        let mut clamps = Vec::new();
        for phase in Phase::ALL {
            let before = self.get(phase);
            if u64::from(before.max_in) + u64::from(before.max_out) <= u64::from(context_window) {
                continue;
            }
            // `max_out`を保ったまま`max_in`を下限まで削る。
            let max_in = context_window
                .saturating_sub(before.max_out)
                .max(MIN_CLAMPED_MAX_IN);
            // それでも収まらなければ`max_out`も下限まで削る。
            let max_out = if u64::from(max_in) + u64::from(before.max_out)
                > u64::from(context_window)
            {
                context_window.saturating_sub(max_in).max(MIN_CLAMPED_MAX_OUT)
            } else {
                before.max_out
            };
            let after = TokenBudget { max_in, max_out };
            self.budgets.insert(phase, after);
            clamps.push(BudgetClamp {
                phase,
                before,
                after,
                still_too_large: u64::from(after.max_in) + u64::from(after.max_out)
                    > u64::from(context_window),
            });
        }
        (self, clamps)
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
            let _ = spec(phase);
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

    /// §6.6 規則1: 収まる構成では1つも触らない（クラウド既定の200,000窓）。
    #[test]
    fn a_window_that_fits_leaves_every_budget_untouched() {
        let before = PhaseBudgets::default();
        let (after, clamps) = before.clone().clamped_to_window(200_000);
        assert_eq!(after, before);
        assert!(clamps.is_empty(), "{clamps:?}");
    }

    /// §6.6 規則1: 収まらないフェーズだけを、`max_in`から先に削る。
    #[test]
    fn a_narrow_window_shrinks_max_in_first_and_only_where_needed() {
        // 4,096なら既定表のうちDistill/Verify（4,000+500）とJoin（6,000+1,500、
        // `plans/PLAN-SURVEY-ENGINE.md`段階2）が超える。
        let (after, clamps) = PhaseBudgets::default().clamped_to_window(4_096);
        let touched: Vec<Phase> = clamps.iter().map(|c| c.phase).collect();
        assert_eq!(
            touched,
            vec![Phase::Distill, Phase::Verify, Phase::Join],
            "{clamps:?}"
        );
        for phase in [Phase::Distill, Phase::Verify] {
            let b = after.get(phase);
            // `max_out`は保たれ、`max_in`だけが窓に収まる値へ落ちる。
            assert_eq!(b.max_out, 500, "{phase}");
            assert_eq!(b.max_in, 4_096 - 500, "{phase}");
        }
        let join = after.get(Phase::Join);
        assert_eq!(join.max_out, 1_500);
        assert_eq!(join.max_in, 4_096 - 1_500);
        // 触られていないフェーズは既定のまま。
        assert_eq!(
            after.get(Phase::Hypothesize),
            TokenBudget {
                max_in: 3_000,
                max_out: 1_000
            }
        );
    }

    /// §6.6 規則1: `max_in`の下限に当たったら`max_out`も削る。
    /// 「推論を出すモデル向けに`max_out`を大きくしたまま、実`n_ctx`が小さい」構成がこれ。
    #[test]
    fn max_out_is_shrunk_only_after_max_in_hits_its_floor() {
        let overrides = BTreeMap::from([(
            Phase::Distill,
            TokenBudget {
                max_in: 4_000,
                max_out: 3_500,
            },
        )]);
        let (after, clamps) = PhaseBudgets::default()
            .with_overrides(&overrides)
            .clamped_to_window(2_048);
        let b = after.get(Phase::Distill);
        assert_eq!(b.max_in, MIN_CLAMPED_MAX_IN);
        assert_eq!(b.max_out, 2_048 - MIN_CLAMPED_MAX_IN);
        let clamp = clamps
            .iter()
            .find(|c| c.phase == Phase::Distill)
            .expect("Distill was clamped");
        assert_eq!(clamp.before.max_out, 3_500);
        assert!(!clamp.still_too_large);
    }

    /// §6.6 規則1: 両方の下限を足しても入らない窓は、**黙って辻褄を合わせない**。
    /// `still_too_large`を立てて、送信前ゲート（規則2）へ判断を渡す。
    #[test]
    fn a_window_smaller_than_both_floors_is_reported_as_still_too_large() {
        let (after, clamps) = PhaseBudgets::default().clamped_to_window(600);
        let b = after.get(Phase::Distill);
        assert_eq!(b.max_in, MIN_CLAMPED_MAX_IN);
        assert_eq!(b.max_out, MIN_CLAMPED_MAX_OUT);
        assert!(clamps.iter().all(|c| c.still_too_large), "{clamps:?}");
        // 記述子は前後の値を持つので、警告1行で何が起きたかを説明できる。
        let text = clamps[0].to_string();
        assert!(text.contains("max_in"), "{text}");
        assert!(text.contains("窓に収まらない"), "{text}");
    }

    /// §7.3: Investigateはread-onlyしか候補に入れない（write/execを物理的に外す）。
    #[test]
    fn investigate_admits_read_only_tools_only() {
        let s = spec(Phase::Investigate);
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
            let s = spec(phase);
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
        let s = spec(Phase::Decide);
        assert!(s.tools.admits(RiskClass::Write));
        assert!(s.tools.admits(RiskClass::Exec));
    }

    // 「対象仮説/ゴールによってどのMemoryViewを見せるか」の検証は`memory::render`側の
    // `view_for`が持つ（段階1で`spec()`から切り離した。旧テスト
    // `investigate_and_distill_look_at_the_target_hypothesis_through_different_views`・
    // `missing_target_degrades_to_an_empty_view_rather_than_failing`はそちらへ移設）。
}
