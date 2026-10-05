//! 選択中の記録セッションの候補と、その表示用の判定（[`SessionView`]）。
//!
//! 2026-10-05に`state.rs`から**そのまま**移した（`plans/position-domains/P4.md`のP4.1の準備）。
//! `state.rs`は本体1,000行を超えているので、位置ごとのドメインの欄を足す前に置き場を分けた。
//! 外からの綴りは今までどおり`crate::tui::state::{SessionData, CandidateFilter, SessionView}`（再公開）。

use harness_policy::RuleProposal;

/// 選択中セッションの中身。**候補の計算はJSONLから毎回やり直す**（B-13）。
///
/// # なぜ「FSかnetのどちらか」ではないのか
///
/// パス2の記録は**両方を持つ**（強制下のFS拒否と、記録のため全許可で観測したドメイン）。
/// かつてこれは`enum`で、パス2は`Net`だけを保持していた——一覧には両方を並べていたのに
/// 保持していたのは片方だけだったので、**`g`（一般化の度合い）を押した瞬間にFSの候補が
/// 全部消えていた**（`recompute_proposals`が保持している側からしか作り直せない）。
/// 「一覧に出したもの」と「作り直せるもの」がずれない形にしてある。
#[derive(Default)]
pub struct SessionData {
    pub fs: Option<Box<crate::aggregate::Aggregate>>,
    pub net: Option<Box<crate::net_aggregate::NetAggregate>>,
}

impl SessionData {
    /// **FSを先、ネットワークを後**（強制が効いているのはFSだけなので、「宣言を直せば直る」
    /// 情報はこちらにしか無い）。idは衝突しない（`generalize`がFSへ`fs-N`・netへ`net-N`を振る）。
    pub fn proposals(&self) -> Vec<RuleProposal> {
        let mut proposals = self
            .fs
            .as_ref()
            .map(|fs| fs.proposals())
            .unwrap_or_default();
        if let Some(net) = self.net.as_ref() {
            proposals.extend(net.proposals());
        }
        proposals
    }
}

/// 候補一覧に何を出すか。
///
/// 既定は**承認できるものだけ**。承認できない候補（広すぎる値）は観測の事実としては正しいので
/// 消さない（D-43）が、既定で混ぜると「選べないものが一覧の上位を占める」状態になる
/// ——実測では祖先チェーン由来の`C:`・`C:/`が先頭に並んだ。**隠した件数は必ず出す**（B-09）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateFilter {
    /// 承認できるものだけ（既定）。
    Approvable,
    /// 承認できないものだけ（なぜ選べないのかを確かめる用）。
    Blocked,
    /// 全部。
    All,
}

impl CandidateFilter {
    pub fn label(self) -> &'static str {
        match self {
            CandidateFilter::Approvable => "承認できるもの",
            CandidateFilter::Blocked => "承認できないもの",
            CandidateFilter::All => "全部",
        }
    }

    pub fn next(self) -> Self {
        match self {
            CandidateFilter::Approvable => CandidateFilter::Blocked,
            CandidateFilter::Blocked => CandidateFilter::All,
            CandidateFilter::All => CandidateFilter::Approvable,
        }
    }

    pub(crate) fn accepts(self, too_broad: bool) -> bool {
        match self {
            CandidateFilter::Approvable => !too_broad,
            CandidateFilter::Blocked => too_broad,
            CandidateFilter::All => true,
        }
    }
}

pub struct SessionView {
    pub data: SessionData,
    /// 候補一覧の手前に出す注記（`render_notes`。文言はCLIと共有）。
    pub notes: String,
    /// 観測したプロセスツリー（FSの記録のみ）。
    pub tree: String,
    pub proposals: Vec<RuleProposal>,
    /// 候補ごとの「幅が広すぎて承認できない」判定（`proposals`と同じ並び）。
    ///
    /// 描画のたびに`breadth::check`を呼ぶと、候補の数だけ拒否メッセージを組み立てることになる
    /// （実測849件×毎フレーム）。判定そのものは`breadth`の同じ関数で、結果だけ持っておく。
    pub too_broad: Vec<bool>,
    /// **全候補に共通の警告**（OS監査は読みと書きを区別できない、等）。
    ///
    /// 行ごとに出すと同じ文が候補の数だけ並び（実測849件）、個別の警告が埋もれる。
    /// 共通のものは注記として1度だけ出し、行には**その行に固有のもの**だけを残す。
    pub common_warnings: Vec<String>,
}

impl SessionView {
    /// 全候補が持っている警告（＝行ごとに出す価値が無いもの）を求める。
    ///
    /// 特定の文字列を名指しにしない——他クレートの文面を写すと、向こうが変わったときに
    /// 黙ってすり抜ける（B-05）。「全部に付いているか」だけで決める。
    fn common_warnings(proposals: &[RuleProposal]) -> Vec<String> {
        let Some(first) = proposals.first() else {
            return Vec::new();
        };
        first
            .warnings
            .iter()
            .filter(|warning| proposals.iter().all(|p| p.warnings.contains(warning)))
            .cloned()
            .collect()
    }

    pub fn new(
        data: SessionData,
        notes: String,
        tree: String,
        proposals: Vec<RuleProposal>,
    ) -> Self {
        let common_warnings = Self::common_warnings(&proposals);
        let too_broad = proposals
            .iter()
            .map(|p| harness_policy::breadth::check(p).is_too_broad())
            .collect();
        Self {
            data,
            notes,
            tree,
            proposals,
            too_broad,
            common_warnings,
        }
    }

    /// フィルタを通した候補の添字（`proposals`への添字）。
    pub fn visible(&self, filter: CandidateFilter) -> Vec<usize> {
        (0..self.proposals.len())
            .filter(|i| filter.accepts(self.too_broad[*i]))
            .collect()
    }

    /// 承認できない（広すぎる）候補の件数。**隠すなら件数は必ず出す**（B-09）。
    pub fn blocked_count(&self) -> usize {
        self.too_broad.iter().filter(|b| **b).count()
    }

    /// その候補に固有の警告（共通のものを除いたもの）。
    pub fn row_warnings<'a>(&'a self, proposal: &'a RuleProposal) -> impl Iterator<Item = &'a str> {
        proposal
            .warnings
            .iter()
            .filter(|w| !self.common_warnings.contains(w))
            .map(String::as_str)
    }
}
