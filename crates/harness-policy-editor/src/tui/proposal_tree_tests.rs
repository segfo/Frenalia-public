//! [`ProposalTree`]の単体テスト（端末も記録も要らない純粋な組み立て）。

use super::*;

use harness_policy::generalize::SettingsKey;

fn proposal(value: &str) -> RuleProposal {
    RuleProposal {
        id: format!("fs-{value}"),
        key: SettingsKey::FsRead,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }
}

fn build(values: &[&str]) -> (Vec<RuleProposal>, ProposalTree) {
    let proposals: Vec<RuleProposal> = values.iter().map(|v| proposal(v)).collect();
    let visible: Vec<usize> = (0..proposals.len()).collect();
    let too_broad = vec![false; proposals.len()];
    let tree = ProposalTree::build(&proposals, &visible, &too_broad);
    (proposals, tree)
}

fn all_expanded(tree: &ProposalTree) -> HashSet<String> {
    tree.paths_at_depth(usize::MAX).into_iter().collect()
}

fn labels(tree: &ProposalTree, expanded: &HashSet<String>) -> Vec<(usize, String)> {
    tree.rows(expanded)
        .into_iter()
        .map(|row| (row.depth, tree.node(row.node).label.clone()))
        .collect()
}

/// **1本道は1行に畳む。** `C:` → `Users` → `segfo` を3行に分けても、展開の手間が増えるだけで
/// 何も分からない。
#[test]
fn a_chain_with_no_branching_collapses_into_one_row() {
    let (_, tree) = build(&[
        "C:/Users/segfo/.cargo/registry",
        "C:/Users/segfo/.cargo/bin",
    ]);

    let rows = labels(&tree, &all_expanded(&tree));

    assert_eq!(
        rows,
        vec![
            (0, "C:/Users/segfo/.cargo".to_string()),
            (1, "bin".to_string()),
            (1, "registry".to_string()),
        ],
        "分岐するところまでは1行"
    );
}

/// **候補を持つノードは畳まない**（そこは選択の対象なので、独立した行でなければ選べない）。
#[test]
fn a_node_that_is_itself_a_candidate_is_not_merged_into_its_child() {
    let (_, tree) = build(&["C:/.cargo", "C:/.cargo/bin"]);

    let rows = labels(&tree, &all_expanded(&tree));

    assert_eq!(
        rows,
        vec![(0, "C:/.cargo".to_string()), (1, "bin".to_string()),]
    );
}

/// 折り畳んでいる間は子が出ない（展開状態は呼び出し側が持つ）。
#[test]
fn children_are_hidden_until_the_node_is_expanded() {
    let (_, tree) = build(&["C:/a/x", "C:/a/y", "C:/b/z"]);

    let collapsed = labels(&tree, &HashSet::new());

    assert_eq!(collapsed.len(), 1, "根だけが見える: {collapsed:?}");
    assert_eq!(collapsed[0].1, "C:");
}

/// 配下の候補をまとめて数える（「この下に何件あるか」が選択の判断材料になる）。
#[test]
fn each_node_counts_the_candidates_below_it() {
    let proposals: Vec<RuleProposal> = ["C:/a/x", "C:/a/y", "C:/b/z"]
        .iter()
        .map(|v| proposal(v))
        .collect();
    let visible: Vec<usize> = (0..proposals.len()).collect();
    // `C:/b/z`だけ承認できない値だとする。
    let too_broad = vec![false, false, true];

    let tree = ProposalTree::build(&proposals, &visible, &too_broad);

    let root = tree.rows(&HashSet::new())[0].node;
    assert_eq!(tree.node(root).total, 3);
    assert_eq!(tree.node(root).approvable, 2, "承認できるものだけ数える");
}

/// 配下の候補を全部集められる（スペースキーでの一括選択の材料）。
#[test]
fn a_subtree_yields_every_candidate_under_it() {
    let (proposals, tree) = build(&["C:/a/x", "C:/a/y", "C:/b/z"]);
    let expanded = all_expanded(&tree);
    let rows = tree.rows(&expanded);

    // `C:/a`にあたる行を探す（畳み込みで`C:`が根、その子が`a`と`b`）。
    let a = rows
        .iter()
        .find(|row| tree.node(row.node).path == "C:/a")
        .expect("C:/a の行がある");

    let under: Vec<&str> = tree
        .subtree_proposals(a.node)
        .into_iter()
        .map(|i| proposals[i].value.as_str())
        .collect();

    assert_eq!(under, vec!["C:/a/x", "C:/a/y"]);
}

/// 同じパスに複数のkey（`fs.read`と`fs.read_write`）があっても1ノードにまとまる。
#[test]
fn several_access_kinds_on_the_same_path_share_one_node() {
    let proposals = vec![
        RuleProposal {
            id: "fs-1".to_string(),
            key: SettingsKey::FsRead,
            value: "C:/tools/bin".to_string(),
            evidence: Vec::new(),
            warnings: Vec::new(),
        },
        RuleProposal {
            id: "fs-2".to_string(),
            key: SettingsKey::FsReadWrite,
            value: "C:/tools/bin".to_string(),
            evidence: Vec::new(),
            warnings: Vec::new(),
        },
    ];
    let visible = vec![0, 1];
    let tree = ProposalTree::build(&proposals, &visible, &[false, false]);

    let rows = tree.rows(&all_expanded(&tree));
    assert_eq!(rows.len(), 1, "行は1つ: {rows:?}");
    assert_eq!(tree.node(rows[0].node).proposals.len(), 2);
}

/// UNCは`//host`を1つの根として扱う（`//`を落とすとローカルパスと区別できない）。
#[test]
fn a_unc_path_keeps_its_host_as_the_root() {
    let (_, tree) = build(&["//fileserver/team/a", "//fileserver/team/b"]);

    let rows = labels(&tree, &all_expanded(&tree));

    assert_eq!(rows[0].1, "//fileserver/team");
}

/// ドメイン（`net.allow_domains`）は分割せず1行になる。
#[test]
fn a_domain_candidate_is_a_single_row() {
    let proposals = vec![RuleProposal {
        id: "net-1".to_string(),
        key: SettingsKey::NetAllowDomains,
        value: "api.github.com".to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }];
    let tree = ProposalTree::build(&proposals, &[0], &[false]);

    let rows = tree.rows(&HashSet::new());
    assert_eq!(rows.len(), 1);
    assert_eq!(tree.node(rows[0].node).label, "api.github.com");
}

/// 親子の行き来ができる（`←`で親へ、`→`で最初の子へ）。
#[test]
fn the_tree_can_be_walked_up_and_down() {
    let (_, tree) = build(&["C:/a/x", "C:/b/y"]);
    let root = tree.rows(&HashSet::new())[0].node;

    let first = tree.first_child(root).expect("子がある");
    // `a`は子が1つ（`x`）で自身は候補ではないので`a/x`へ畳まれている。
    assert_eq!(tree.node(first).label, "a/x");
    assert_eq!(tree.parent(first), Some(root));
    assert_eq!(tree.parent(root), None, "根の親は無い");
}
