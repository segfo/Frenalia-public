//! 候補をパスの木として組み立てる（表示と一括選択のため）。
//!
//! # なぜ平坦な一覧では読めないのか
//!
//! `C:/`・`C:/Users/segfo/.cargo`・`C:/Users/segfo/.cargo/bin`…が同じ深さで並ぶと、どれが
//! どれの配下なのかが読み取れない。実測849件ではこれが致命的で、「この下をまとめて許す」
//! という判断そのものができなかった。
//!
//! # 1本道は畳む（path compression）
//!
//! `C:` → `Users` → `segfo` のように**子が1つしかなく、それ自身は候補でもない**ノードは、
//! 子と1行にまとめる（`C:/Users/segfo`）。畳まないと、意味の無い中間ノードを何度も展開する
//! ことになる。**候補を持つノードは畳まない**——そこは選択の対象なので、行として独立している
//! 必要がある。
//!
//! # このモジュールは状態を持たない
//!
//! 展開/折り畳みの状態は呼び出し側（`App`）がパス文字列の集合として持ち、[`ProposalTree::rows`]へ
//! 渡す。木を作り直しても展開状態が消えないのはこのためで、フィルタや一般化の度合いを
//! 変えたときに「開いていた場所が閉じる」のを避けられる。

use std::collections::HashSet;

use harness_policy::{generalize::SettingsKey, RuleProposal};

/// 木の1ノード。
///
/// `Default`は`compress`が子を取り出すときの置き換え用（`std::mem::take`）。
#[derive(Debug, Clone, Default)]
pub struct Node {
    /// 表示するラベル（1本道を畳んだ結果、複数のセグメントを含みうる）。
    pub label: String,
    /// このノードが表すパス全体（展開状態のキーでもある）。
    pub path: String,
    /// このノード自身が候補である場合の`proposals`への添字。
    /// 同じパスに`fs.read`と`fs.read_write`が並ぶことがあるので複数持つ。
    pub proposals: Vec<usize>,
    pub children: Vec<usize>,
    /// 配下（自分自身を含む）の候補の総数。
    pub total: usize,
    /// うち承認できるもの（広すぎる値を除く）。
    pub approvable: usize,
}

/// 候補のパス木。
#[derive(Debug, Default)]
pub struct ProposalTree {
    nodes: Vec<Node>,
    roots: Vec<usize>,
}

/// 画面に出す1行。
#[derive(Debug, Clone)]
pub struct Row {
    pub node: usize,
    pub depth: usize,
}

/// 木を組み立てるのに必要な最小の情報＝**キーと値**。
///
/// # なぜ`RuleProposal`を要求しないのか
///
/// 木が使うのは値（パスの分割）とキー（同じパスに複数ある場合の並び）だけで、観測回数や
/// 根拠は使っていない。`RuleProposal`を要求すると、**宣言（`policy.json`の行）を同じ木で
/// 見せられない**——宣言には観測も根拠も無いので、偽の`RuleProposal`を作るしかなくなる。
/// キーと値だけを要求すれば、候補と宣言の両方が同じ木・同じ操作を通れる
/// （`docs/CODE-STRUCTURE-RULES.md`§5.1: 対になる操作は流用できるロジックを流用する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeItem<'a> {
    pub key: SettingsKey,
    pub value: &'a str,
}

impl ProposalTree {
    /// `visible`（フィルタ後の`proposals`への添字）から木を組み立てる。
    pub fn build(proposals: &[RuleProposal], visible: &[usize], too_broad: &[bool]) -> Self {
        let items: Vec<TreeItem<'_>> = proposals
            .iter()
            .map(|p| TreeItem {
                key: p.key,
                value: &p.value,
            })
            .collect();
        Self::from_items(&items, visible, too_broad)
    }

    /// キーと値の一覧から木を組み立てる（[`Self::build`]の一般形）。
    ///
    /// `visible`は`items`への添字で、木のノードが持つ`proposals`もその添字である
    /// （呼び出し側が候補一覧を指すか宣言一覧を指すかを決める）。
    pub fn from_items(items: &[TreeItem<'_>], visible: &[usize], too_broad: &[bool]) -> Self {
        let mut tree = ProposalTree::default();
        for index in visible {
            let Some(item) = items.get(*index) else {
                continue;
            };
            let node = tree.ensure_path(&segments(item.value));
            tree.nodes[node].proposals.push(*index);
        }
        tree.compress();
        tree.sort_children(items);
        tree.count(too_broad);
        tree
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    /// 展開されているノードだけを、上から見える順に並べる。
    pub fn rows(&self, expanded: &HashSet<String>) -> Vec<Row> {
        let mut out = Vec::new();
        for root in &self.roots {
            self.walk(*root, 0, expanded, &mut out);
        }
        out
    }

    fn walk(&self, index: usize, depth: usize, expanded: &HashSet<String>, out: &mut Vec<Row>) {
        out.push(Row { node: index, depth });
        if !expanded.contains(&self.nodes[index].path) {
            return;
        }
        for child in &self.nodes[index].children {
            self.walk(*child, depth + 1, expanded, out);
        }
    }

    /// 配下（自分自身を含む）の候補すべて（`proposals`への添字）。
    pub fn subtree_proposals(&self, index: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![index];
        while let Some(node) = stack.pop() {
            out.extend(self.nodes[node].proposals.iter().copied());
            stack.extend(self.nodes[node].children.iter().copied());
        }
        out.sort_unstable();
        out
    }

    /// このノードを開いたときに最初に見える子（`→`で降りる先）。
    pub fn first_child(&self, index: usize) -> Option<usize> {
        self.nodes[index].children.first().copied()
    }

    pub fn has_children(&self, index: usize) -> bool {
        !self.nodes[index].children.is_empty()
    }

    /// 親（`←`で戻る先）。木は小さいので線形に探す。
    pub fn parent(&self, index: usize) -> Option<usize> {
        self.nodes
            .iter()
            .position(|node| node.children.contains(&index))
    }

    /// 全ノードのパス（起動時に既定で開いておく範囲を決めるのに使う）。
    pub fn paths_at_depth(&self, max_depth: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack: Vec<(usize, usize)> = self.roots.iter().map(|r| (*r, 0usize)).collect();
        while let Some((index, depth)) = stack.pop() {
            if depth >= max_depth {
                continue;
            }
            out.push(self.nodes[index].path.clone());
            for child in &self.nodes[index].children {
                stack.push((*child, depth + 1));
            }
        }
        out
    }

    // --- 組み立て ------------------------------------------------------------

    fn ensure_path(&mut self, segments: &[String]) -> usize {
        let mut current: Option<usize> = None;
        let mut path = String::new();
        for segment in segments {
            if !path.is_empty() && !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(segment);

            let siblings: &[usize] = match current {
                Some(index) => &self.nodes[index].children,
                None => &self.roots,
            };
            let existing = siblings
                .iter()
                .copied()
                .find(|i| self.nodes[*i].label == *segment);

            let node = match existing {
                Some(index) => index,
                None => {
                    let index = self.nodes.len();
                    self.nodes.push(Node {
                        label: segment.clone(),
                        path: path.clone(),
                        proposals: Vec::new(),
                        children: Vec::new(),
                        total: 0,
                        approvable: 0,
                    });
                    match current {
                        Some(parent) => self.nodes[parent].children.push(index),
                        None => self.roots.push(index),
                    }
                    index
                }
            };
            current = Some(node);
        }
        current.expect("segments is never empty")
    }

    /// 1本道（子が1つ・自分は候補でない）を1行へ畳む。
    fn compress(&mut self) {
        let all: Vec<usize> = (0..self.nodes.len()).collect();
        for index in all {
            loop {
                let node = &self.nodes[index];
                if node.proposals.is_empty() && node.children.len() == 1 {
                    let child = node.children[0];
                    let merged_label = format!("{}/{}", node.label, self.nodes[child].label);
                    let child_node = std::mem::take(&mut self.nodes[child]);
                    let node = &mut self.nodes[index];
                    node.label = merged_label;
                    node.path = child_node.path;
                    node.proposals = child_node.proposals;
                    node.children = child_node.children;
                    continue;
                }
                break;
            }
        }
        // 畳んだ結果、孤立した（誰の子でもなくなった）ノードは`rows`から辿られないだけなので
        // 掃除は要らない——木の走査は`roots`と`children`しか見ない。
    }

    fn sort_children(&mut self, items: &[TreeItem<'_>]) {
        let key = |tree: &Self, index: usize| tree.nodes[index].label.to_ascii_lowercase();
        let mut roots = std::mem::take(&mut self.roots);
        roots.sort_by_key(|i| key(self, *i));
        self.roots = roots;
        for index in 0..self.nodes.len() {
            let mut children = std::mem::take(&mut self.nodes[index].children);
            children.sort_by_key(|i| key(self, *i));
            self.nodes[index].children = children;
            // 同じパスに複数のkeyがある場合は、表示順をkeyで固定する。
            let mut own = std::mem::take(&mut self.nodes[index].proposals);
            own.sort_by_key(|i| items[*i].key);
            self.nodes[index].proposals = own;
        }
    }

    fn count(&mut self, too_broad: &[bool]) {
        for index in 0..self.nodes.len() {
            self.count_node(index, too_broad);
        }
    }

    fn count_node(&mut self, index: usize, too_broad: &[bool]) -> (usize, usize) {
        let children = self.nodes[index].children.clone();
        let mut total = self.nodes[index].proposals.len();
        let mut approvable = self.nodes[index]
            .proposals
            .iter()
            .filter(|i| !too_broad.get(**i).copied().unwrap_or(false))
            .count();
        for child in children {
            let (child_total, child_approvable) = self.count_node(child, too_broad);
            total += child_total;
            approvable += child_approvable;
        }
        self.nodes[index].total = total;
        self.nodes[index].approvable = approvable;
        (total, approvable)
    }
}

/// パス（または`net.allow_domains`のドメイン）を木のセグメントへ割る。
///
/// UNC（`//host/share/...`）は先頭2つの空要素をまとめて`//host`にする——`//`を落とすと
/// ローカルパスと区別できなくなる。ドメイン（`api.example.com`）は分割しないので1本の根になる。
fn segments(value: &str) -> Vec<String> {
    if let Some(rest) = value.strip_prefix("//") {
        let mut parts = rest.split('/').filter(|s| !s.is_empty());
        let host = parts.next().unwrap_or_default();
        let mut out = vec![format!("//{host}")];
        out.extend(parts.map(str::to_string));
        return out;
    }
    let parts: Vec<String> = value
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        vec![value.to_string()]
    } else {
        parts
    }
}

#[cfg(test)]
#[path = "proposal_tree_tests.rs"]
mod proposal_tree_tests;
