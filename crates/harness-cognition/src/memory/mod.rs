//! 構造化作業記憶（Evidence Ledger）。`plans/DESIGN-COGNITION.md` §5。
//!
//! **台帳が「理解の現状」の唯一の真実**であり、LLMコールへ渡すのは会話履歴（`ConversationState`）
//! ではなく[`WorkingMemory::render`]が返す縮約済みスライスだけ。これが§0の弱点1
//! 「文脈の肥大」への構造的な答えで、ターンが伸びても送信量が伸びない理由そのもの。
//!
//! # 生出力を持たない
//!
//! ツール/MCPの生出力はここへ**入れない**。[`crate::scratch::ScratchStore`]へ退避し、
//! 台帳は[`types::RawRef`]ポインタだけ持つ（§6.3の遅延展開に使う）。
//!
//! # 永続化はM20
//!
//! `ledger.jsonl`への追記と`--resume`での復元は`plans/DESIGN-COGNITION.md` §10のM20が持つ。
//! M14の`WorkingMemory`はインメモリで、プロセスをまたがない。

pub mod render;
pub mod types;

use types::{
    Decision, Evidence, EvidenceId, Goal, GoalId, GoalStatus, HypId, HypStatus, Hypothesis,
    OpenQuestion, Verdict, Verification,
};

pub use render::MemoryView;

/// 台帳本体。IDの採番権はここだけが持つ（[`types`]モジュールのdoc参照）。
#[derive(Debug, Clone, Default)]
pub struct WorkingMemory {
    goals: Vec<Goal>,
    hypotheses: Vec<Hypothesis>,
    evidence: Vec<Evidence>,
    verifications: Vec<Verification>,
    decisions: Vec<Decision>,
    open_questions: Vec<OpenQuestion>,
    /// Orientフェーズが洗い出した未知事項。Hypothesizeの入力になる（§3.3）。
    unknowns: Vec<String>,
    next_id: u32,
}

impl WorkingMemory {
    pub fn new() -> Self {
        Self::default()
    }

    fn take_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    // --- 追記 ---

    pub fn add_goal(&mut self, statement: impl Into<String>, done_criteria: Vec<String>) -> GoalId {
        let id = GoalId(self.take_id());
        self.goals.push(Goal {
            id,
            statement: statement.into(),
            status: GoalStatus::Open,
            done_criteria,
        });
        id
    }

    /// 仮説を追加する。`predicts`（反証条件）が空でも構造上は積めるが、M15の状態機械は
    /// スキーマ検証で空を弾いて再実行させる（§3.4「仮説なしに調査へ進めない」）。
    pub fn add_hypothesis(
        &mut self,
        goal: GoalId,
        statement: impl Into<String>,
        predicts: Vec<String>,
        confidence: f32,
    ) -> HypId {
        let id = HypId(self.take_id());
        self.hypotheses.push(Hypothesis {
            id,
            goal,
            statement: statement.into(),
            status: HypStatus::Proposed,
            confidence,
            predicts,
            supporting: Vec::new(),
            refuting: Vec::new(),
        });
        id
    }

    /// 蒸留済みの証拠を追加し、対象仮説の`supporting`/`refuting`へ結び付ける。
    ///
    /// `supports`が`None`ならどの仮説にも紐付かない独立した観測として積む（Orientの
    /// 状況把握など）。紐付けを`Evidence`側ではなく`Hypothesis`側に持たせるのは、
    /// 「この仮説を支持する証拠は何か」がVerifyフェーズの主な問い合わせ方向だから。
    pub fn add_evidence(
        &mut self,
        evidence: impl FnOnce(EvidenceId) -> Evidence,
        supports: Option<(HypId, bool)>,
    ) -> EvidenceId {
        let id = EvidenceId(self.take_id());
        self.evidence.push(evidence(id));
        if let Some((hyp, is_supporting)) = supports {
            if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == hyp) {
                if is_supporting {
                    h.supporting.push(id);
                } else {
                    h.refuting.push(id);
                }
            }
        }
        id
    }

    /// 検証結果を記録し、仮説の状態を更新する。
    ///
    /// **`Confirmed`への遷移はここでは行わない。** §3.4の遷移条件（接地種別の下限・Critic通過・
    /// 未決着Conflictingなし）は機械チェックで、その判定材料（`Validity`）はM16、判定を行う
    /// 状態機械はM15にある。ここが更新するのは`Verdict`から一意に決まる範囲だけ。
    pub fn record_verification(&mut self, verification: Verification) {
        if let Some(h) = self
            .hypotheses
            .iter_mut()
            .find(|h| h.id == verification.hyp)
        {
            h.status = match verification.verdict {
                // Confirmsでも`Confirmed`へは上げない（上記の理由）。調査は続く。
                Verdict::Confirms => HypStatus::Investigating,
                Verdict::Refutes => HypStatus::Refuted,
                Verdict::Inconclusive => HypStatus::Inconclusive,
            };
        }
        self.verifications.push(verification);
    }

    pub fn set_hypothesis_status(&mut self, hyp: HypId, status: HypStatus) {
        if let Some(h) = self.hypotheses.iter_mut().find(|h| h.id == hyp) {
            h.status = status;
        }
    }

    pub fn set_goal_status(&mut self, goal: GoalId, status: GoalStatus) {
        if let Some(g) = self.goals.iter_mut().find(|g| g.id == goal) {
            g.status = status;
        }
    }

    pub fn add_decision(&mut self, decision: Decision) {
        self.decisions.push(decision);
    }

    pub fn add_open_question(&mut self, text: impl Into<String>, blocking: bool) {
        self.open_questions.push(OpenQuestion {
            text: text.into(),
            blocking,
        });
    }

    pub fn set_unknowns(&mut self, unknowns: Vec<String>) {
        self.unknowns = unknowns;
    }

    // --- 参照 ---

    pub fn goals(&self) -> &[Goal] {
        &self.goals
    }

    pub fn hypotheses(&self) -> &[Hypothesis] {
        &self.hypotheses
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    pub fn verifications(&self) -> &[Verification] {
        &self.verifications
    }

    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    pub fn open_questions(&self) -> &[OpenQuestion] {
        &self.open_questions
    }

    pub fn unknowns(&self) -> &[String] {
        &self.unknowns
    }

    pub fn goal(&self, id: GoalId) -> Option<&Goal> {
        self.goals.iter().find(|g| g.id == id)
    }

    pub fn hypothesis(&self, id: HypId) -> Option<&Hypothesis> {
        self.hypotheses.iter().find(|h| h.id == id)
    }

    pub fn evidence_by_id(&self, id: EvidenceId) -> Option<&Evidence> {
        self.evidence.iter().find(|e| e.id == id)
    }

    /// 直近の検証結果（Criticフェーズが「この結論を反証せよ」と問うための材料）。
    pub fn latest_verification(&self, hyp: HypId) -> Option<&Verification> {
        self.verifications.iter().rev().find(|v| v.hyp == hyp)
    }

    /// 次に調査すべき仮説。未決着のものを`confidence`降順で返す
    /// （§3.4「confidenceは調査の優先順位付け専用」の唯一の用途）。
    pub fn investigation_order(&self) -> Vec<HypId> {
        let mut open: Vec<&Hypothesis> = self
            .hypotheses
            .iter()
            .filter(|h| {
                matches!(
                    h.status,
                    HypStatus::Proposed | HypStatus::Investigating | HypStatus::Inconclusive
                )
            })
            .collect();
        // 同値のときは追記順（＝ID昇順）で安定させる。
        open.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.id.cmp(&b.id))
        });
        open.into_iter().map(|h| h.id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::types::{RawRef, SourceRef, VerifyMethod};
    use super::*;

    fn file_evidence(claim: &str) -> impl FnOnce(EvidenceId) -> Evidence + '_ {
        move |id| Evidence {
            id,
            claim: claim.to_string(),
            source: SourceRef::File {
                path: "src/lib.rs".to_string(),
                lines: (1, 5),
            },
            raw_ref: Some(RawRef {
                tool_call_id: "call_1".to_string(),
                chars: 8_000,
            }),
        }
    }

    #[test]
    fn ids_are_unique_across_entity_kinds() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix the bug", vec![]);
        let h = mem.add_hypothesis(g, "cause is X", vec!["test fails".into()], 0.6);
        let e = mem.add_evidence(file_evidence("X is called here"), Some((h, true)));
        // 採番は台帳全体で1本なので、種別が違っても数値は衝突しない。
        assert_ne!(g.label(), h.label());
        assert_eq!(
            (g.label(), h.label(), e.label()),
            ("G1".into(), "H2".into(), "E3".into())
        );
    }

    #[test]
    fn evidence_is_linked_to_the_hypothesis_it_supports_or_refutes() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix", vec![]);
        let h = mem.add_hypothesis(g, "cause is X", vec![], 0.5);
        let supporting = mem.add_evidence(file_evidence("supports"), Some((h, true)));
        let refuting = mem.add_evidence(file_evidence("refutes"), Some((h, false)));
        mem.add_evidence(file_evidence("unrelated"), None);

        let hyp = mem.hypothesis(h).unwrap();
        assert_eq!(hyp.supporting, vec![supporting]);
        assert_eq!(hyp.refuting, vec![refuting]);
        assert_eq!(mem.evidence().len(), 3);
    }

    /// **§3.4の要**: `verdict==Confirms`が来ても`Confirmed`へは上げない。遷移条件
    /// （接地種別の下限・Critic通過）の判定材料はM16、判定する状態機械はM15にあるため、
    /// M14の台帳が勝手に確証済みへ昇格させてはならない。
    #[test]
    fn confirms_verdict_does_not_promote_the_hypothesis_to_confirmed() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix", vec![]);
        let h = mem.add_hypothesis(g, "cause is X", vec![], 0.9);
        mem.record_verification(Verification {
            hyp: h,
            method: VerifyMethod::RunTest,
            verdict: Verdict::Confirms,
            missing: vec![],
            note: "test reproduces".into(),
        });
        assert_eq!(mem.hypothesis(h).unwrap().status, HypStatus::Investigating);
    }

    #[test]
    fn refutes_verdict_marks_the_hypothesis_refuted() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix", vec![]);
        let h = mem.add_hypothesis(g, "cause is X", vec![], 0.9);
        mem.record_verification(Verification {
            hyp: h,
            method: VerifyMethod::RunTest,
            verdict: Verdict::Refutes,
            missing: vec![],
            note: "test passes".into(),
        });
        assert_eq!(mem.hypothesis(h).unwrap().status, HypStatus::Refuted);
        assert!(mem.hypothesis(h).unwrap().status.is_discardable());
    }

    /// confidenceの唯一の用途（調査の優先順位付け）。決着済みは並ばない。
    #[test]
    fn investigation_order_is_confidence_descending_over_undecided_hypotheses() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix", vec![]);
        let low = mem.add_hypothesis(g, "low", vec![], 0.2);
        let high = mem.add_hypothesis(g, "high", vec![], 0.8);
        let refuted = mem.add_hypothesis(g, "refuted", vec![], 0.99);
        mem.set_hypothesis_status(refuted, HypStatus::Refuted);

        assert_eq!(mem.investigation_order(), vec![high, low]);
    }

    #[test]
    fn latest_verification_returns_the_most_recent_one() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("fix", vec![]);
        let h = mem.add_hypothesis(g, "cause is X", vec![], 0.5);
        for note in ["first", "second"] {
            mem.record_verification(Verification {
                hyp: h,
                method: VerifyMethod::ReRead,
                verdict: Verdict::Inconclusive,
                missing: vec![],
                note: note.into(),
            });
        }
        assert_eq!(mem.latest_verification(h).unwrap().note, "second");
    }
}
