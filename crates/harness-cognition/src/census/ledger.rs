//! `CensusEngine`の台帳（`WorkingMemory`は使わない）。`plans/PLAN-CENSUS-ENGINE.md`段階2。

use harness_core::Phase;

use crate::census::plan::WorklistItem;
use crate::ledger::LedgerView;
use crate::memory::render::Reduction;

/// worklistとゴール文だけを持つ最小の台帳。仮説・証拠・妥当性評価は一切持たない
/// ——網羅で終わる仕事に判定は要らない（`plans/PLAN-CENSUS-ENGINE.md`「判定」節）。
pub(crate) struct CensusLedger {
    goal_text: String,
    worklist: Vec<WorklistItem>,
}

impl CensusLedger {
    pub(crate) fn new() -> Self {
        Self {
            goal_text: String::new(),
            worklist: Vec::new(),
        }
    }

    /// `HivEngine::run_goal`の`self.mem.add_goal(goal_text, ..)`に相当。構築時ではなく
    /// `CensusEngine::run_goal`の先頭で1回だけ呼ぶ。
    pub(crate) fn set_goal_text(&mut self, goal_text: String) {
        self.goal_text = goal_text;
    }

    pub(crate) fn set_worklist(&mut self, worklist: Vec<WorklistItem>) {
        self.worklist = worklist;
    }

    pub(crate) fn len(&self) -> usize {
        self.worklist.len()
    }

    pub(crate) fn item(&self, index: usize) -> Option<&WorklistItem> {
        self.worklist.get(index)
    }
}

impl LedgerView for CensusLedger {
    /// `reduction`は無視する。Censusのスライスは（ゴール文1本／対象item1件）ともに元々
    /// 小さく、予算超過が起きるとすれば固定費側なので、`ContextAssembler::assemble`の
    /// 機械的切詰め（catalog drop → raw truncate → slice truncate）が安全網になる。
    fn render_slice(
        &self,
        phase: Phase,
        target: Option<&str>,
        _goal: Option<&str>,
        _reduction: Reduction,
    ) -> String {
        match phase {
            Phase::Plan => format!("## 依頼\n\n{}\n", self.goal_text),
            Phase::Collect => target
                .and_then(|id| self.worklist.iter().find(|i| i.id == id))
                .map(|item| format!("## 対象\n\n{} — {}\n", item.id, item.query))
                .unwrap_or_default(),
            // Distill/Joinの主入力は`PhaseInput.raw_output`（生出力の抜粋／notesの連結）で
            // 運ぶので、台帳スライスは要らない。
            Phase::Distill | Phase::Join => String::new(),
            // HIV専用フェーズ。`CensusLedger`はこれらを扱わない。
            Phase::Orient
            | Phase::Hypothesize
            | Phase::Investigate
            | Phase::Verify
            | Phase::Critic
            | Phase::Decide => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_slice_carries_the_goal_text() {
        let mut ledger = CensusLedger::new();
        ledger.set_goal_text("バグカタログの傾向を分析して".to_string());
        let slice = (&ledger as &dyn LedgerView).render_slice(
            Phase::Plan,
            None,
            None,
            Reduction::Full,
        );
        assert!(slice.contains("バグカタログの傾向を分析して"), "{slice}");
    }

    #[test]
    fn collect_slice_carries_only_the_target_item() {
        let mut ledger = CensusLedger::new();
        ledger.set_worklist(vec![
            WorklistItem {
                id: "a".to_string(),
                query: "Aを読む".to_string(),
            },
            WorklistItem {
                id: "b".to_string(),
                query: "Bを読む".to_string(),
            },
        ]);
        let slice = (&ledger as &dyn LedgerView).render_slice(
            Phase::Collect,
            Some("b"),
            None,
            Reduction::Full,
        );
        assert!(slice.contains("Bを読む"), "{slice}");
        assert!(!slice.contains("Aを読む"), "{slice}");
    }

    #[test]
    fn distill_and_join_slices_are_empty() {
        let ledger = CensusLedger::new();
        for phase in [Phase::Distill, Phase::Join] {
            let slice =
                (&ledger as &dyn LedgerView).render_slice(phase, None, None, Reduction::Full);
            assert_eq!(slice, "", "{phase}");
        }
    }
}
