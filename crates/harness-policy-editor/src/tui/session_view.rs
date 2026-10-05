//! 選択中の記録セッションの候補と、その表示用の判定（[`SessionView`]）。
//!
//! 2026-10-05に`state.rs`から**そのまま**移した（`plans/position-domains/P4.md`のP4.1の準備）。
//! `state.rs`は本体1,000行を超えているので、位置ごとのドメインの欄を足す前に置き場を分けた。
//! 外からの綴りは今までどおり`crate::tui::state::{SessionData, CandidateFilter, SessionView}`（再公開）。

use harness_policy::RuleProposal;

use crate::tui::proposal_tree::TreeItem;

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
    /// 候補ごとに書く先のドメイン（`proposals`と同じ並び）。**位置ごとのドメインの記録だけ`Some`**
    /// （決定65。P4.4 が入れる）。全部`None`なら、候補の木は今までどおりドメインの段を持たない。
    pub domains: Vec<Option<String>>,
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

    /// `domains`は`proposals`と同じ長さ（候補ごとに書く先のドメイン）。**引数にしてあるのは、候補を
    /// 作り直す経路（accessの巡回など）が黙って`None`へ戻さないため**——呼び出し側の全部をコンパイラが数える。
    pub fn new(
        data: SessionData,
        notes: String,
        tree: String,
        proposals: Vec<RuleProposal>,
        domains: Vec<Option<String>>,
    ) -> Self {
        debug_assert_eq!(domains.len(), proposals.len());
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
            domains,
        }
    }

    /// 候補の木（[`crate::tui::proposal_tree::ProposalTree::from_items`]）へ渡す行。宣言画面と同じ形で、
    /// 候補ごとのドメインを添える（2つ以上のドメインが出ると木がドメインの見出しで分かれる）。
    pub fn tree_items(&self) -> Vec<TreeItem<'_>> {
        self.proposals
            .iter()
            .zip(&self.domains)
            .map(|(proposal, domain)| TreeItem {
                key: proposal.key,
                value: &proposal.value,
                domain: domain.as_deref(),
            })
            .collect()
    }

    /// フィルタを通した候補の添字（`proposals`への添字）。
    pub fn visible(&self, filter: CandidateFilter) -> Vec<usize> {
        (0..self.proposals.len())
            .filter(|i| filter.accepts(self.too_broad[*i]))
            .collect()
    }

    /// 承認できない（広すぎる）候補の件数。**隠すなら件数は必ず出す**（B-09）。
    /// 位置ごとのドメインの記録か（候補の書く先が候補ごとに決まっている。P4.4）。
    pub fn by_position(&self) -> bool {
        self.domains.iter().any(Option::is_some)
    }

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

// 候補一覧へ重ねる宣言（`[x]`）。2026-10-05に`state.rs`から移した（`plans/position-domains/P4.md`の P4.4。
// `state.rs`は本体1,000行を超えているので、候補ごとのドメインで引くように直す前に置き場を分けた）。
impl crate::tui::state::App {
    /// 候補（`view.proposals`の添字）を書く先のドメイン。**位置ごとのドメインの記録なら候補ごとの名前**
    /// （[`SessionView::domains`]）、そうでなければドメイン欄の名前（今までどおり）。
    pub fn candidate_domain(&self, index: usize) -> String {
        self.view
            .as_ref()
            .and_then(|view| view.domains.get(index).cloned().flatten())
            .unwrap_or_else(|| self.domain.text().trim().to_string())
    }

    /// ドメイン`domain`でこの値が**もう宣言されている**なら、それを取り消すための対象を返す（空なら未宣言）。
    ///
    /// # なぜ宣言側のキーで作るのか
    ///
    /// 候補が`fs.read`でも宣言は`fs.read_exec`であり得る（ETWは読取と実行を区別しない）。
    /// 外したときに消すべきは**`policy.json`に書かれている行**なので、候補のキーではなく
    /// 宣言側のキーで対象を作らなければならない——候補のキーで作ると、存在しない行を
    /// 消そうとして「無かった」になり、`[x]`が外れないまま確定が通る。
    pub fn declared_targets_for(
        &self,
        domain: &str,
        value: &str,
    ) -> Vec<crate::unapprove::UnapproveTarget> {
        let Some(domain) = self.declared_policy.as_ref().and_then(|f| f.domain(domain)) else {
            return Vec::new();
        };
        domain
            .declared_keys_for_value(value)
            .into_iter()
            .map(|key| crate::unapprove::UnapproveTarget {
                domain: domain.name.clone(),
                key,
                value: value.to_string(),
            })
            .collect()
    }

    /// 候補1件（`view.proposals`の添字）が「確定後に許可されている状態か」＝チェックが入っているか。
    ///
    /// 承認予定（`accepted`）だけでなく**既に宣言されているもの**も入る。同じ場所へ二重に
    /// チェックを付けさせないためで、これが無いと承認済みの実行ファイルが毎回未選択で現れる。
    /// 宣言は**その候補を書く先のドメイン**（[`Self::candidate_domain`]）で引く。
    pub fn candidate_is_on(&self, index: usize) -> bool {
        let Some(proposal) = self.view.as_ref().and_then(|v| v.proposals.get(index)) else {
            return false;
        };
        if self.accepted.contains(&proposal.id) {
            return true;
        }
        // 宣言が複数あるとき（`read`と`read_exec`など）は、**1つでも残るなら許可されている**。
        self.declared_targets_for(&self.candidate_domain(index), &proposal.value)
            .iter()
            .any(|target| !self.unapproved.contains(target))
    }

    /// [`Self::candidate_is_on`]を候補そのもので引く（番号で`view.proposals`の添字を探す）。
    pub fn proposal_is_on(&self, proposal: &RuleProposal) -> bool {
        let index = self
            .view
            .as_ref()
            .and_then(|v| v.proposals.iter().position(|p| p.id == proposal.id));
        match index {
            Some(index) => self.candidate_is_on(index),
            None => self.accepted.contains(&proposal.id),
        }
    }

    /// 候補一覧へ重ねる宣言（[`Self::declared_policy`]）を読み直す。**`policy.json`全体を持つ**——位置ごとの
    /// ドメインの記録では候補ごとに別のドメインを引くため（P4.4）。
    ///
    /// 読めなかった場合は`None`にする。**「宣言が無い」と「読めなかった」を同じ表示にしない**
    /// ため、読めなかったことは`status`へ出す（D-43）。
    pub fn refresh_declared_overlay(&mut self) {
        match crate::policy_file::load(&self.workspace_root) {
            Ok(file) => self.declared_policy = Some(file),
            Err(e) => {
                self.declared_policy = None;
                self.status =
                    format!("policy.jsonを読めませんでした（宣言済みの重ねは出ません）: {e}");
            }
        }
    }
}
