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

// ---------------------------------------------------------------------------
// ドメインの段（2026-10-05、決定65。`plans/position-domains/P4.md`のP4.1）
// ---------------------------------------------------------------------------

fn item<'a>(domain: &'a str, value: &'a str) -> TreeItem<'a> {
    TreeItem {
        key: SettingsKey::FsRead,
        value,
        domain: Some(domain),
    }
}

/// 全件を見せて組み立てる。
fn tree_of(items: &[TreeItem<'_>]) -> ProposalTree {
    let visible: Vec<usize> = (0..items.len()).collect();
    ProposalTree::from_items(items, &visible, &vec![false; items.len()])
}

/// **ドメインの見出しは、子が1つでも畳まない。** 畳むとドメイン名がパスの一部に見え、見出しの行
/// （その下をまとめて選ぶ・取り消す行）が消える。
#[test]
fn a_domain_header_is_not_merged_into_its_only_child() {
    let tree = tree_of(&[item("alpha", "C:/a/b"), item("beta", "C:/c")]);

    let rows = labels(&tree, &all_expanded(&tree));

    assert_eq!(
        rows,
        vec![
            (0, "[alpha]".to_string()),
            (1, "C:/a/b".to_string()),
            (0, "[beta]".to_string()),
            (1, "C:/c".to_string()),
        ]
    );
}

/// **ドメインが1つなら見出しを出さない**——今までの木と1文字も変わらない（展開の鍵もパスのまま）。
/// 対の側: 2つ目のドメインが出ると見出しが出る。
#[test]
fn one_domain_keeps_the_tree_without_headers() {
    let tree = tree_of(&[item("alpha", "C:/x/a"), item("alpha", "C:/x/b")]);

    let rows = labels(&tree, &all_expanded(&tree));
    assert_eq!(
        rows,
        vec![
            (0, "C:/x".to_string()),
            (1, "a".to_string()),
            (1, "b".to_string()),
        ]
    );
    assert!(!tree.has_domain_tier());
    for row in tree.rows(&all_expanded(&tree)) {
        let node = tree.node(row.node);
        assert_eq!(node.key, node.path, "段の無い木では鍵はパスそのもの");
        assert_eq!(node.domain, None);
        assert!(!node.is_domain_header);
    }

    let split = tree_of(&[item("alpha", "C:/x/a"), item("beta", "C:/x/b")]);
    assert!(split.has_domain_tier(), "2つ目のドメインが出たら見出しを出す");
}

/// **同じパスを2つのドメインが持っても、片方を開いたらもう片方も開く、を起こさない**
/// （`App::declared_expanded`を候補画面の`expanded`と分けたのと同じ理由）。
#[test]
fn the_same_path_in_two_domains_opens_separately() {
    let tree = tree_of(&[
        item("alpha", "C:/s/d1"),
        item("alpha", "C:/s/d2"),
        item("beta", "C:/s/d1"),
        item("beta", "C:/s/d2"),
    ]);
    let shared: Vec<usize> = tree
        .rows(&all_expanded(&tree))
        .iter()
        .map(|row| row.node)
        .filter(|node| tree.node(*node).path == "C:/s")
        .collect();
    assert_eq!(shared.len(), 2, "C:/s はドメインごとに1行");
    let (alpha, beta) = (tree.node(shared[0]), tree.node(shared[1]));
    assert_eq!(alpha.domain.as_deref(), Some("alpha"));
    assert_eq!(beta.domain.as_deref(), Some("beta"));
    assert_eq!(alpha.path, beta.path);
    assert_ne!(alpha.key, beta.key, "鍵はドメインで分かれる");

    // 見出しの2つと alpha の C:/s だけを開く。
    let mut expanded: HashSet<String> = tree.initially_open().into_iter().collect();
    expanded.remove(&beta.key);
    expanded.insert(alpha.key.clone());
    assert_eq!(
        labels(&tree, &expanded),
        vec![
            (0, "[alpha]".to_string()),
            (1, "C:/s".to_string()),
            (2, "d1".to_string()),
            (2, "d2".to_string()),
            (0, "[beta]".to_string()),
            (1, "C:/s".to_string()),
        ]
    );
}

/// **段の有無は木へ渡す全件で決める**——見えている行だけで数えると、フィルタを変えるたびに段が出たり
/// 消えたりし、展開の鍵も変わって開いていた場所が閉じる。
#[test]
fn headers_are_decided_by_every_item_not_only_the_visible_ones() {
    let items = [item("alpha", "C:/a"), item("beta", "C:/b")];
    let only_alpha = ProposalTree::from_items(&items, &[0], &[false, false]);
    assert_eq!(
        labels(&only_alpha, &all_expanded(&only_alpha)),
        vec![(0, "[alpha]".to_string()), (1, "C:/a".to_string())],
        "隠れた beta も数えるので見出しが出る"
    );

    let both = tree_of(&items);
    let key_of = |tree: &ProposalTree| {
        tree.rows(&all_expanded(tree))
            .into_iter()
            .map(|row| tree.node(row.node))
            .find(|node| node.path == "C:/a")
            .map(|node| node.key.clone())
            .expect("C:/a の行がある")
    };
    assert_eq!(key_of(&only_alpha), key_of(&both), "見え方が変わっても鍵は同じ");
}
