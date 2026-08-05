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
pub mod validity;

use std::collections::BTreeSet;

use types::{
    Decision, Evidence, EvidenceId, Goal, GoalId, GoalStatus, HypId, HypStatus, Hypothesis,
    OpenQuestion, SourceKind, Verdict, Verification,
};
use validity::{EvidenceStrength, Grade, GradeInput, Resolution, Validity};

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
        self.recompute_validity();
        id
    }

    /// 新しい証拠が既存の証拠と矛盾することを記録する（§4.3の矛盾検出）。
    ///
    /// 相手のIDは呼び出し側（`crate::hiv::parse`）が**台帳に実在することを検証済み**で渡す。
    /// ここで自己参照だけは弾く——同じ証拠が自分と矛盾する状態は台帳の不変条件を壊す。
    pub fn record_conflict(&mut self, a: EvidenceId, b: EvidenceId) {
        if a == b {
            return;
        }
        for (own, other) in [(a, b), (b, a)] {
            if let Some(e) = self.evidence.iter_mut().find(|e| e.id == own) {
                if !e.validity.conflicts.contains(&other) {
                    e.validity.conflicts.push(other);
                }
            }
        }
        self.recompute_validity();
    }

    /// 未決着の矛盾を§4.3の規則（信頼度 → 鮮度）で決着させる。
    ///
    /// 戻り値は**決着できなかった組**。呼び出し側（`crate::hiv`）がこれを`OpenQuestion`にする
    /// ——台帳自身が問いを立てないのは、「ユーザへ何を返すか」の判断が状態機械の側にあるため。
    pub fn resolve_conflicts(&mut self) -> Vec<(EvidenceId, EvidenceId)> {
        let pairs: BTreeSet<(EvidenceId, EvidenceId)> = self
            .evidence
            .iter()
            .flat_map(|e| {
                e.validity
                    .conflicts
                    .iter()
                    .map(move |other| (e.id.min(*other), e.id.max(*other)))
            })
            .collect();

        let mut undecided = Vec::new();
        for (a, b) in pairs {
            let (Some(ea), Some(eb)) = (self.evidence_by_id(a), self.evidence_by_id(b)) else {
                continue;
            };
            let loser = match validity::resolve_conflict(
                (ea.validity.trust, ea.validity.freshness),
                (eb.validity.trust, eb.validity.freshness),
            ) {
                Resolution::First => b,
                Resolution::Second => a,
                Resolution::Undecided => {
                    undecided.push((a, b));
                    continue;
                }
            };
            // 決着したので両者から相手を外す。**負けた側の証拠は消さない**——台帳は
            // 「何を観測したか」の記録であり、決着の結果は`superseded_by`として残る。
            let winner = if loser == a { b } else { a };
            for (own, other) in [(a, b), (b, a)] {
                if let Some(e) = self.evidence.iter_mut().find(|e| e.id == own) {
                    e.validity.conflicts.retain(|c| *c != other);
                    if own == loser {
                        e.validity.superseded_by = Some(winner);
                    }
                }
            }
        }
        self.recompute_validity();
        undecided
    }

    /// 台帳の全証拠について`Validity.grade`を引き直す（§4.3）。
    ///
    /// **派生値が陳腐化しないことの担保はこの1関数**であり、証拠の追加・矛盾の記録・決着の
    /// すべてがここを通る。`grade`をアクセサ側で都度計算する形にしなかったのは、設計（§3.4・
    /// §4.3）が「各EvidenceはSourceRefとValidityを保持する」と定めており、監査ログや
    /// `--resume`（M20）でそのまま直列化できる必要があるため。
    fn recompute_validity(&mut self) {
        let linked: Vec<(EvidenceId, bool, BTreeSet<SourceKind>)> = self
            .evidence
            .iter()
            .map(|e| {
                // その証拠を支持として持つ仮説の、他の支持証拠の種別を集める。
                let siblings: BTreeSet<SourceKind> = self
                    .hypotheses
                    .iter()
                    .filter(|h| h.supporting.contains(&e.id))
                    .flat_map(|h| h.supporting.iter())
                    .filter(|id| **id != e.id)
                    .filter_map(|id| self.evidence_by_id(*id))
                    // 決着で退けられた観測は裏取りに使わない。
                    .filter(|other| other.validity.superseded_by.is_none())
                    .map(|other| other.source.kind())
                    .collect();
                let is_linked = self
                    .hypotheses
                    .iter()
                    .any(|h| h.supporting.contains(&e.id) || h.refuting.contains(&e.id));
                (e.id, is_linked, siblings)
            })
            .collect();

        for (id, is_linked, siblings) in linked {
            let Some(e) = self.evidence.iter_mut().find(|e| e.id == id) else {
                continue;
            };
            let kind = e.source.kind();
            e.validity.grade = validity::grade_for(GradeInput {
                kind,
                has_unresolved_conflict: !e.validity.conflicts.is_empty(),
                superseded: e.validity.superseded_by.is_some(),
                // **裏取りとして数えるのは接地種別だけ**。web証拠が2件並んでも
                // `Corroborated`にはしない（§4.2でwebは補助扱い）。
                corroborated_by_other_kind: siblings
                    .iter()
                    .any(|k| *k != kind && k.is_grounding()),
                linked_to_hypothesis: is_linked,
            });
        }
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

    /// 仮説の根拠の強さ（§3.4 `evidence_strength`）。**ハーネスが決定的に算出する**ので、
    /// 自己申告の`Hypothesis.confidence`と違い監査で再現できる。
    pub fn evidence_strength(&self, hyp: HypId) -> EvidenceStrength {
        let Some(h) = self.hypothesis(hyp) else {
            return EvidenceStrength::Ungrounded;
        };
        let validities = |ids: &'_ [EvidenceId]| -> Vec<&Validity> {
            ids.iter()
                .filter_map(|id| self.evidence_by_id(*id))
                .map(|e| &e.validity)
                .collect()
        };
        let supporting = validities(&h.supporting);
        let refuting = validities(&h.refuting);
        validity::evidence_strength(supporting.into_iter(), refuting.into_iter())
    }

    /// §3.4【E1】の接地が支持証拠にあるか（`File`/`Shell`/`Mcp`のいずれか1件以上）。
    /// 矛盾の決着で退けられた観測は数えない。
    pub fn has_grounded_support(&self, hyp: HypId) -> bool {
        self.hypothesis(hyp).is_some_and(|h| {
            h.supporting.iter().any(|id| {
                self.evidence_by_id(*id)
                    .is_some_and(|e| e.validity.counts_as_grounding(e.source.kind()))
            })
        })
    }

    /// 支持証拠のうち、まだ決着していない矛盾を抱えているもの（§3.4の遷移条件
    /// 「未決着Conflictingなし」の判定材料）。
    pub fn unresolved_conflicts(&self, hyp: HypId) -> Vec<EvidenceId> {
        self.hypothesis(hyp)
            .into_iter()
            .flat_map(|h| h.supporting.iter())
            .filter(|id| {
                self.evidence_by_id(**id)
                    .is_some_and(|e| e.validity.grade == Grade::Conflicting)
            })
            .copied()
            .collect()
    }

    /// 支持証拠に現れた接地種別の集合（§4.2のCrossSource判定・カタログからの示唆に使う）。
    pub fn grounded_kinds(&self, hyp: HypId) -> BTreeSet<SourceKind> {
        self.hypothesis(hyp)
            .into_iter()
            .flat_map(|h| h.supporting.iter())
            .filter_map(|id| self.evidence_by_id(*id))
            .filter(|e| e.validity.superseded_by.is_none())
            .map(|e| e.source.kind())
            .collect()
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
    use super::validity::{Freshness, TrustLevel};
    use super::*;

    fn file_evidence(claim: &str) -> impl FnOnce(EvidenceId) -> Evidence + '_ {
        source_evidence(
            claim,
            SourceRef::File {
                path: "src/lib.rs".to_string(),
                lines: (1, 5),
            },
            TrustLevel::High,
        )
    }

    fn source_evidence(
        claim: &str,
        source: SourceRef,
        trust: TrustLevel,
    ) -> impl FnOnce(EvidenceId) -> Evidence + '_ {
        move |id| Evidence {
            id,
            claim: claim.to_string(),
            source,
            validity: Validity::seed(trust, Freshness::Fresh),
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

    /// **M16の要**: `grade`は派生値であり、証拠が増えるたびに引き直される。
    /// 「再計算し忘れた台帳」が観測できないことを固定する。
    #[test]
    fn grades_are_recomputed_on_every_mutation() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec!["Yが見える".into()], 0.5);

        // webだけの観測は単独では確証の根拠にならない（§4.2でwebは補助扱い）。
        let web = mem.add_evidence(
            source_evidence(
                "ドキュメントにそう書いてある",
                SourceRef::Web {
                    url: "https://example.com".into(),
                    fetched_at: "0".into(),
                },
                TrustLevel::Medium,
            ),
            Some((h, true)),
        );
        assert_eq!(mem.evidence_by_id(web).unwrap().validity.grade, Grade::Unverified);
        assert!(!mem.has_grounded_support(h));

        // ローカルファイルで裏取りできた瞬間、**既存のweb証拠のgradeも**引き直される。
        let file = mem.add_evidence(file_evidence("実装がそうなっている"), Some((h, true)));
        assert_eq!(
            mem.evidence_by_id(web).unwrap().validity.grade,
            Grade::Corroborated,
            "追加された別種の接地が既存証拠の妥当性へ反映されなければならない"
        );
        // 逆向き（file側）はwebを裏取りに数えない——webは補助なので接地扱いしない。
        assert_eq!(
            mem.evidence_by_id(file).unwrap().validity.grade,
            Grade::SingleSource
        );
        assert!(mem.has_grounded_support(h));
    }

    /// 矛盾は両者に記録され、決着するまで`Conflicting`のまま（§4.3）。
    #[test]
    fn a_recorded_conflict_marks_both_sides_until_it_is_decided() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec![], 0.5);
        let weak = mem.add_evidence(
            source_evidence(
                "旧仕様ではAを呼ぶ",
                SourceRef::Web {
                    url: "https://example.com".into(),
                    fetched_at: "0".into(),
                },
                TrustLevel::Low,
            ),
            Some((h, true)),
        );
        let strong = mem.add_evidence(file_evidence("実装はBを呼ぶ"), Some((h, true)));

        mem.record_conflict(weak, strong);
        for id in [weak, strong] {
            assert_eq!(mem.evidence_by_id(id).unwrap().validity.grade, Grade::Conflicting);
        }
        assert_eq!(mem.unresolved_conflicts(h), vec![weak, strong]);
        // 未決着の矛盾を抱えた接地は確証の根拠に数えない。
        assert!(mem.has_grounded_support(h), "接地種別であること自体は変わらない");

        // 信頼度差で決着し、負けた側だけが根拠から外れる。
        assert!(mem.resolve_conflicts().is_empty());
        assert!(mem.unresolved_conflicts(h).is_empty());
        assert_eq!(
            mem.evidence_by_id(weak).unwrap().validity.superseded_by,
            Some(strong)
        );
        assert_eq!(mem.evidence_by_id(weak).unwrap().validity.grade, Grade::Unverified);
        assert_eq!(
            mem.evidence_by_id(strong).unwrap().validity.grade,
            Grade::SingleSource
        );
        // 負けた観測も台帳からは消えない（監査性）。
        assert_eq!(mem.evidence().len(), 2);
    }

    /// 信頼度も鮮度も同じ矛盾は決着させず、呼び出し側へ返す（§4.3「決着不能ならOpenQuestion」）。
    #[test]
    fn an_evenly_matched_conflict_is_reported_back_unresolved() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec![], 0.5);
        let a = mem.add_evidence(file_evidence("Aと書いてある"), Some((h, true)));
        let b = mem.add_evidence(file_evidence("Bと書いてある"), Some((h, true)));
        mem.record_conflict(a, b);

        assert_eq!(mem.resolve_conflicts(), vec![(a, b)]);
        assert_eq!(mem.unresolved_conflicts(h), vec![a, b]);
    }

    /// 自己参照の矛盾は記録しない（台帳の不変条件）。
    #[test]
    fn an_evidence_cannot_conflict_with_itself() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec![], 0.5);
        let e = mem.add_evidence(file_evidence("観測"), Some((h, true)));
        mem.record_conflict(e, e);
        assert!(mem.evidence_by_id(e).unwrap().validity.conflicts.is_empty());
    }

    /// `evidence_strength`は台帳から決定的に決まる（§3.4）。
    #[test]
    fn evidence_strength_is_derived_from_the_ledger() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec![], 0.5);
        assert_eq!(mem.evidence_strength(h), EvidenceStrength::Ungrounded);

        mem.add_evidence(file_evidence("観測1"), Some((h, true)));
        let with_one = mem.evidence_strength(h);
        assert!(with_one > EvidenceStrength::Ungrounded);

        mem.add_evidence(
            source_evidence(
                "MCPでも同じ",
                SourceRef::Mcp {
                    server: "docs".into(),
                    tool: "search".into(),
                    args_digest: "d".into(),
                },
                TrustLevel::High,
            ),
            Some((h, true)),
        );
        assert!(
            mem.evidence_strength(h) > with_one,
            "別種ソースでの裏取りは根拠を強くする"
        );
        assert_eq!(
            mem.grounded_kinds(h),
            BTreeSet::from([SourceKind::File, SourceKind::Mcp])
        );
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
