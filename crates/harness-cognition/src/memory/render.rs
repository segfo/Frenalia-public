//! 台帳スライスのレンダリング。`plans/DESIGN-COGNITION.md` §5「`WorkingMemory::render(view)`が
//! 用途別にMarkdown/JSONへ縮約」。
//!
//! フェーズごとに**必要な項目だけ**をMarkdownへ落とす。全履歴を渡さないのが要点なので、
//! ここで「何を渡さないか」が決まる。どのビューを使うかは[`crate::phase`]の表が持つ。

use super::types::{HypStatus, Hypothesis};
use super::WorkingMemory;
use crate::memory::types::{GoalId, HypId};

/// フェーズごとの台帳スライス（閉じた語彙）。`plans/DESIGN-COGNITION.md` §3.3の
/// 「入力コンテキスト（最小化済み）」列と1対1で対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryView {
    /// ゴール + 台帳サマリ（確証済み事実の箇条書き） + open questions。Orient用。
    GoalSummary,
    /// ゴール + unknowns + 既存仮説の要旨。Hypothesize用。
    Unknowns,
    /// 対象仮説1本 + その`predicts`。Investigate用。
    HypothesisPlan(HypId),
    /// 対象仮説 + supporting/refuting evidenceの**claimだけ**。Verify用。
    EvidenceFor(HypId),
    /// 対象仮説 + 直近のVerifyの結論。Critic用。
    VerificationOf(HypId),
    /// ゴール + 確証済み仮説。Decide用。
    ConfirmedForGoal(GoalId),
    /// 台帳を一切参照しない（Distillのように生出力だけを見るフェーズ）。
    None,
}

/// 予算超過時の縮約段階。**上へ行くほど攻撃的**で、下位段階の縮約を含む。
///
/// 順序を型で固定するのは、「どの情報から捨てるか」が毎回同じでないと、同じ台帳から
/// 組んだリクエストが実行ごとに変わってしまい、golden testも再現も成立しないため。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reduction {
    /// 縮約なし。
    Full,
    /// 反証済み（`Refuted`）の仮説を落とす。決着済みで支持もされなかったもの。
    DropRefuted,
    /// さらに、対象仮説に紐付かない証拠を落とす。
    DropUnlinkedEvidence,
    /// さらに、仮説を対象1本（無ければ最優先1本）に絞る。
    TargetOnly,
}

impl Reduction {
    /// 弱い順。[`crate::context::ContextAssembler`]がこの順で試し、予算に収まった段階で止める。
    pub const LEVELS: [Reduction; 4] = [
        Reduction::Full,
        Reduction::DropRefuted,
        Reduction::DropUnlinkedEvidence,
        Reduction::TargetOnly,
    ];
}

impl WorkingMemory {
    /// 用途別の縮約済みスライスをMarkdownで返す。
    ///
    /// 生出力は**決して**含まれない（台帳が持っていないため構造的に不可能）。
    pub fn render(&self, view: MemoryView, reduction: Reduction) -> String {
        match view {
            MemoryView::None => String::new(),
            MemoryView::GoalSummary => self.render_goal_summary(),
            MemoryView::Unknowns => self.render_unknowns(reduction),
            MemoryView::HypothesisPlan(hyp) => self.render_hypothesis_plan(hyp),
            MemoryView::EvidenceFor(hyp) => self.render_evidence_for(hyp, reduction),
            MemoryView::VerificationOf(hyp) => self.render_verification_of(hyp),
            MemoryView::ConfirmedForGoal(goal) => self.render_confirmed_for_goal(goal),
        }
    }

    fn render_goal_summary(&self) -> String {
        let mut out = String::new();
        push_section(
            &mut out,
            "ゴール",
            self.goals().iter().map(|g| {
                let criteria = if g.done_criteria.is_empty() {
                    String::new()
                } else {
                    format!("（完了条件: {}）", g.done_criteria.join(" / "))
                };
                format!("{} [{:?}] {}{criteria}", g.id, g.status, g.statement)
            }),
        );

        // 「確証済み事実」＝Confirmedな仮説と、それを支持する証拠のclaim。
        push_section(
            &mut out,
            "確証済みの事実",
            self.hypotheses()
                .iter()
                .filter(|h| h.status == HypStatus::Confirmed)
                .map(|h| format!("{} {}", h.id, h.statement)),
        );

        push_section(
            &mut out,
            "未解決の問い",
            self.open_questions().iter().map(|q| {
                let mark = if q.blocking { "**[blocking]** " } else { "" };
                format!("{mark}{}", q.text)
            }),
        );
        out
    }

    fn render_unknowns(&self, reduction: Reduction) -> String {
        let mut out = self.render_goal_summary();
        push_section(&mut out, "未知の事項", self.unknowns().iter().cloned());
        push_section(
            &mut out,
            "既存の仮説",
            self.visible_hypotheses(None, reduction)
                .into_iter()
                .map(digest_hypothesis),
        );
        out
    }

    fn render_hypothesis_plan(&self, hyp: HypId) -> String {
        let Some(h) = self.hypothesis(hyp) else {
            return String::new();
        };
        let mut out = format!("## 調査対象の仮説\n\n{} {}\n", h.id, h.statement);
        push_section(
            &mut out,
            "反証条件（これが見えれば偽）",
            h.predicts.iter().cloned(),
        );
        out
    }

    fn render_evidence_for(&self, hyp: HypId, reduction: Reduction) -> String {
        let Some(h) = self.hypothesis(hyp) else {
            return String::new();
        };
        let mut out = format!("## 検証対象の仮説\n\n{} {}\n", h.id, h.statement);
        push_section(
            &mut out,
            "反証条件（これが見えれば偽）",
            h.predicts.iter().cloned(),
        );
        // claimだけを渡す（§3.3）。生出力どころか、生出力へのポインタも渡さない
        // ——必要になったフェーズが`zoom`で明示的に取りに行く（§6.3）。
        push_section(
            &mut out,
            "支持する証拠",
            h.supporting.iter().filter_map(|id| self.claim_line(*id)),
        );
        push_section(
            &mut out,
            "反証する証拠",
            h.refuting.iter().filter_map(|id| self.claim_line(*id)),
        );
        if reduction < Reduction::DropUnlinkedEvidence {
            push_section(
                &mut out,
                "その他の観測",
                self.unlinked_evidence()
                    .filter_map(|id| self.claim_line(id)),
            );
        }
        out
    }

    fn render_verification_of(&self, hyp: HypId) -> String {
        let Some(h) = self.hypothesis(hyp) else {
            return String::new();
        };
        let mut out = format!("## 批判対象の仮説\n\n{} {}\n", h.id, h.statement);
        if let Some(v) = self.latest_verification(hyp) {
            out.push_str(&format!(
                "\n## 検証の結論\n\n- 判定: {:?}（手段: {:?}）\n- 補足: {}\n",
                v.verdict, v.method, v.note
            ));
            push_section(&mut out, "不足している観測", v.missing.iter().cloned());
        }
        push_section(
            &mut out,
            "支持しているとされる証拠",
            h.supporting.iter().filter_map(|id| self.claim_line(*id)),
        );
        out
    }

    fn render_confirmed_for_goal(&self, goal: GoalId) -> String {
        let mut out = String::new();
        if let Some(g) = self.goal(goal) {
            out.push_str(&format!("## ゴール\n\n{} {}\n", g.id, g.statement));
            push_section(&mut out, "完了条件", g.done_criteria.iter().cloned());
        }
        push_section(
            &mut out,
            "確証済みの仮説",
            self.hypotheses()
                .iter()
                .filter(|h| h.goal == goal && h.status == HypStatus::Confirmed)
                .map(|h| format!("{} {}", h.id, h.statement)),
        );
        out
    }

    // --- 補助 ---

    fn claim_line(&self, id: crate::memory::types::EvidenceId) -> Option<String> {
        self.evidence_by_id(id)
            .map(|e| format!("{} {}（出典: {}）", e.id, e.claim, e.source.describe()))
    }

    /// どの仮説にも紐付いていない証拠。
    fn unlinked_evidence(&self) -> impl Iterator<Item = crate::memory::types::EvidenceId> + '_ {
        self.evidence().iter().filter_map(move |e| {
            let linked = self
                .hypotheses()
                .iter()
                .any(|h| h.supporting.contains(&e.id) || h.refuting.contains(&e.id));
            (!linked).then_some(e.id)
        })
    }

    /// 縮約段階に応じて、スライスへ載せる仮説を選ぶ。
    fn visible_hypotheses(&self, target: Option<HypId>, reduction: Reduction) -> Vec<&Hypothesis> {
        let mut visible: Vec<&Hypothesis> = self
            .hypotheses()
            .iter()
            .filter(|h| reduction < Reduction::DropRefuted || !h.status.is_discardable())
            .collect();
        if reduction >= Reduction::TargetOnly {
            // 対象が指定されていればそれ、無ければ調査優先度が最も高い1本。
            let keep = target.or_else(|| self.investigation_order().first().copied());
            visible.retain(|h| Some(h.id) == keep);
            // それでも0本なら、追記順で先頭の1本だけ残す（空スライスは情報ゼロで無意味）。
            if visible.is_empty() {
                visible = self.hypotheses().iter().take(1).collect();
            }
        }
        visible
    }
}

fn digest_hypothesis(h: &Hypothesis) -> String {
    format!(
        "{} [{:?}] {}（支持{} / 反証{}）",
        h.id,
        h.status,
        h.statement,
        h.supporting.len(),
        h.refuting.len()
    )
}

/// 見出し + 箇条書き。**項目が空なら見出しごと出さない**（空節はトークンを食うだけで
/// 情報を持たない）。
fn push_section(out: &mut String, title: &str, items: impl Iterator<Item = String>) {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("## {title}\n\n"));
    for item in items {
        out.push_str(&format!("- {item}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{
        Evidence, EvidenceId, RawRef, SourceRef, Verdict, Verification, VerifyMethod,
    };

    fn evidence(claim: &str) -> impl FnOnce(EvidenceId) -> Evidence + '_ {
        move |id| Evidence {
            id,
            claim: claim.to_string(),
            source: SourceRef::File {
                path: "src/lib.rs".to_string(),
                lines: (1, 5),
            },
            raw_ref: Some(RawRef {
                tool_call_id: "call_1".to_string(),
                chars: 12_000,
            }),
        }
    }

    fn memory_with_two_hypotheses() -> (WorkingMemory, HypId, HypId) {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("テストの失敗を直す", vec!["cargo testが緑".into()]);
        let alive = mem.add_hypothesis(g, "原因はロック順序", vec!["並列時のみ失敗".into()], 0.7);
        let dead = mem.add_hypothesis(g, "原因はタイムアウト値", vec![], 0.3);
        mem.set_hypothesis_status(dead, HypStatus::Refuted);
        mem.add_evidence(evidence("並列実行時だけ失敗する"), Some((alive, true)));
        mem.add_evidence(evidence("シングルスレッドでは緑"), Some((alive, false)));
        mem.add_evidence(evidence("無関係な観測"), None);
        (mem, alive, dead)
    }

    /// **生出力は台帳に無いのでレンダリングにも現れ得ない**が、生出力への
    /// ポインタ（`RawRef`）まで漏らしていないことを固定する（§6.3の遅延展開は
    /// 「必要になったフェーズが明示的に取りに行く」ものなので、既定では出さない）。
    #[test]
    fn evidence_view_shows_claims_only_not_raw_pointers() {
        let (mem, alive, _) = memory_with_two_hypotheses();
        let out = mem.render(MemoryView::EvidenceFor(alive), Reduction::Full);
        assert!(out.contains("並列実行時だけ失敗する"), "{out}");
        assert!(out.contains("src/lib.rs:1-5"), "{out}");
        assert!(!out.contains("call_1"), "raw pointer leaked: {out}");
        assert!(!out.contains("12000"), "raw size leaked: {out}");
    }

    #[test]
    fn evidence_view_separates_supporting_and_refuting() {
        let (mem, alive, _) = memory_with_two_hypotheses();
        let out = mem.render(MemoryView::EvidenceFor(alive), Reduction::Full);
        let supporting_at = out.find("## 支持する証拠").unwrap();
        let refuting_at = out.find("## 反証する証拠").unwrap();
        assert!(supporting_at < refuting_at);
        assert!(out[supporting_at..refuting_at].contains("並列実行時だけ失敗する"));
        assert!(out[refuting_at..].contains("シングルスレッドでは緑"));
    }

    #[test]
    fn investigate_view_carries_the_target_hypothesis_and_its_falsifiers_only() {
        let (mem, alive, _) = memory_with_two_hypotheses();
        let out = mem.render(MemoryView::HypothesisPlan(alive), Reduction::Full);
        assert!(out.contains("原因はロック順序"), "{out}");
        assert!(out.contains("並列時のみ失敗"), "{out}");
        // 他の仮説も、既に集めた証拠も入れない（§3.3「対象仮説1本 + その predicts」）。
        assert!(!out.contains("原因はタイムアウト値"), "{out}");
        assert!(!out.contains("並列実行時だけ失敗する"), "{out}");
    }

    #[test]
    fn goal_summary_lists_only_confirmed_facts_and_open_questions() {
        let (mut mem, alive, _) = memory_with_two_hypotheses();
        mem.set_hypothesis_status(alive, HypStatus::Confirmed);
        mem.add_open_question("再現条件が不明", true);
        let out = mem.render(MemoryView::GoalSummary, Reduction::Full);
        assert!(out.contains("原因はロック順序"), "{out}");
        assert!(out.contains("**[blocking]** 再現条件が不明"), "{out}");
        // 未確証の仮説と個々の証拠は出さない（サマリなので）。
        assert!(!out.contains("原因はタイムアウト値"), "{out}");
        assert!(!out.contains("並列実行時だけ失敗する"), "{out}");
    }

    /// 縮約は決定的な順序で効く（§6.1「予算超過時は台帳スライスをさらに縮約」）。
    #[test]
    fn reduction_levels_drop_information_in_a_fixed_order() {
        let (mem, alive, _) = memory_with_two_hypotheses();

        let full = mem.render(MemoryView::Unknowns, Reduction::Full);
        assert!(full.contains("原因はタイムアウト値"), "{full}");

        // 段階1: 反証済みの仮説が消える
        let dropped = mem.render(MemoryView::Unknowns, Reduction::DropRefuted);
        assert!(!dropped.contains("原因はタイムアウト値"), "{dropped}");
        assert!(dropped.contains("原因はロック順序"), "{dropped}");

        // 段階2: 紐付かない証拠が消える（Verifyビュー）
        let with_unlinked = mem.render(MemoryView::EvidenceFor(alive), Reduction::DropRefuted);
        assert!(with_unlinked.contains("無関係な観測"), "{with_unlinked}");
        let without = mem.render(
            MemoryView::EvidenceFor(alive),
            Reduction::DropUnlinkedEvidence,
        );
        assert!(!without.contains("無関係な観測"), "{without}");
        // 対象仮説に紐付く証拠は最後まで残る。
        assert!(without.contains("並列実行時だけ失敗する"), "{without}");

        // 各段階で単調に短くなる。
        assert!(dropped.len() < full.len());
    }

    /// 縮約が最大でも、仮説が1本も無いスライス（情報ゼロ）にはならない。
    #[test]
    fn target_only_reduction_always_keeps_at_least_one_hypothesis() {
        let (mut mem, alive, dead) = memory_with_two_hypotheses();
        mem.set_hypothesis_status(alive, HypStatus::Refuted);
        let _ = dead;
        let out = mem.render(MemoryView::Unknowns, Reduction::TargetOnly);
        assert!(out.contains("原因は"), "{out}");
    }

    #[test]
    fn critic_view_carries_the_verification_conclusion() {
        let (mut mem, alive, _) = memory_with_two_hypotheses();
        mem.record_verification(Verification {
            hyp: alive,
            method: VerifyMethod::RunTest,
            verdict: Verdict::Confirms,
            missing: vec!["Linuxでの再現".into()],
            note: "並列時のみ再現した".into(),
        });
        let out = mem.render(MemoryView::VerificationOf(alive), Reduction::Full);
        assert!(out.contains("Confirms"), "{out}");
        assert!(out.contains("RunTest"), "{out}");
        assert!(out.contains("並列時のみ再現した"), "{out}");
        assert!(out.contains("Linuxでの再現"), "{out}");
    }

    #[test]
    fn none_view_renders_nothing() {
        let (mem, _, _) = memory_with_two_hypotheses();
        assert_eq!(mem.render(MemoryView::None, Reduction::Full), "");
    }

    /// 空の節は見出しごと出ない（トークンを食うだけで情報を持たないため）。
    #[test]
    fn empty_sections_are_omitted_entirely() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("何かする", vec![]);
        let h = mem.add_hypothesis(g, "仮説", vec![], 0.5);
        let out = mem.render(MemoryView::EvidenceFor(h), Reduction::Full);
        assert!(!out.contains("支持する証拠"), "{out}");
        assert!(!out.contains("反証条件"), "{out}");
    }
}
