//! 1つのドメインから見た遷移の形（[`shape`]）と自己ループ辺の一覧（[`self_loops`]）の単体試験。
//!
//! 入力は`PolicyFile`を組んで`transition_graph_input`で作る（判定器の試験の借用の束の補助を写さない）。
//! **権限の要約は毎回`rights_summary`と比べる**——モデル向けのツールと同じ値であることが
//! この機構の約束である（§19.3.8: 2つ作るとモデルとユーザーで見えるものがずれる）。

use super::*;

use crate::policy_file::{PolicyDomain, PolicyFile};
use crate::transition::{
    check_all, rights_summary, AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge, TransitionGraph,
};

/// 任意の引数で`exe`を起こすと`to`へ移る辺（エディタが書く形）。
fn edge_to(exe: &str, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: to.to_string(),
        env: None,
    }
}

/// 固定辺（argv がリテラル・cwd を宣言。§19.3.4 で到達閉包から外れる）。
fn fixed_edge_to(exe: &str, argv: &str, cwd: &str, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv: ArgvMatcher::Literal(argv.to_string()),
        cwd: Some(cwd.to_string()),
        to: to.to_string(),
        env: None,
    }
}

fn domain(name: &str, read: &[&str], edges: Vec<TransitionEdge>) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.fs.read = read.iter().map(|v| v.to_string()).collect();
    domain.process.transitions = edges;
    domain
}

fn file(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        domains,
        ..PolicyFile::default()
    }
}

fn shape_of(file: &PolicyFile, from: &str) -> TransitionShape {
    shape(&file.transition_graph_input(None, &[]), from).expect("同じ名前のドメインは無い")
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn has_read(shape: &TransitionShape, value: &str) -> bool {
    shape
        .rights
        .fs
        .iter()
        .any(|(declared, access)| declared == value && *access == "read")
}

/// 非閉路なら最長路の段数と経路を答える。届くドメインは到達閉包、権限は`rights_summary`と同じ値。
#[test]
fn longest_chain_of_a_dag() {
    let policy = file(vec![
        domain(
            "a",
            &[],
            vec![
                edge_to("C:/t/b.exe", "b"),
                edge_to("C:/t/c.exe", "c"),
                edge_to("C:/t/d.exe", "d"),
            ],
        ),
        domain("b", &[], vec![edge_to("C:/t/c.exe", "c")]),
        domain("c", &["C:/data/**"], vec![]),
        domain("d", &[], vec![]),
    ]);
    let input = policy.transition_graph_input(None, &[]);

    let from_a = shape_of(&policy, "a");
    assert_eq!(
        from_a.longest_chain,
        LongestChain::Finite {
            steps: 2,
            path: names(&["a", "b", "c"]),
        }
    );
    assert_eq!(from_a.reachable, names(&["b", "c", "d"]));
    assert_eq!(from_a.rights, rights_summary(&input, "a").unwrap());
    assert!(has_read(&from_a, "C:/data/**"), "{:?}", from_a.rights);

    // 対の側: 辺を持たないドメインから見ると0段。
    assert_eq!(
        shape_of(&policy, "d").longest_chain,
        LongestChain::Finite {
            steps: 0,
            path: names(&["d"]),
        }
    );
}

/// 自己ループ辺に届けば連鎖の段数に上限が無い。自己ループ辺は一覧に出る。
#[test]
fn a_self_loop_makes_the_chain_unbounded() {
    let looping = file(vec![
        domain("a", &[], vec![edge_to("C:/t/b.exe", "b")]),
        domain("b", &[], vec![edge_to("C:/t/b.exe", "b")]),
    ]);
    assert_eq!(
        shape_of(&looping, "a").longest_chain,
        LongestChain::Unbounded {
            cycle: names(&["b"]),
        }
    );
    assert_eq!(
        self_loops(&looping.transition_graph_input(None, &[])),
        vec![SelfLoop {
            domain: "b".to_string(),
            edge_index: 0,
        }]
    );

    // 対の側: 自己ループ辺を外すと上限があり、一覧は空。
    let plain = file(vec![
        domain("a", &[], vec![edge_to("C:/t/b.exe", "b")]),
        domain("b", &[], vec![]),
    ]);
    assert_eq!(
        shape_of(&plain, "a").longest_chain,
        LongestChain::Finite {
            steps: 1,
            path: names(&["a", "b"]),
        }
    );
    assert!(self_loops(&plain.transition_graph_input(None, &[])).is_empty());
}

/// 2つのドメインの閉路でも上限が無い（閉路を禁じる検査は置かない、§19.3.1 の限定詞）。
/// 2つのドメインの閉路は自己ループ辺ではない。
#[test]
fn a_two_domain_cycle_is_unbounded() {
    let policy = file(vec![
        domain("a", &[], vec![edge_to("C:/t/b.exe", "b")]),
        domain("b", &[], vec![edge_to("C:/t/c.exe", "c")]),
        domain("c", &[], vec![edge_to("C:/t/b.exe", "b")]),
    ]);
    assert_eq!(
        shape_of(&policy, "a").longest_chain,
        LongestChain::Unbounded {
            cycle: names(&["b", "c"]),
        }
    );
    assert!(self_loops(&policy.transition_graph_input(None, &[])).is_empty());
}

/// 固定辺の先の権限は届く範囲に数えない（§19.3.4。権限が渡らない）が、連鎖の段数には数える
/// （起こせることに変わりはない）。
#[test]
fn a_fixed_edge_is_excluded_from_rights_but_counted_in_the_chain() {
    let fixed = file(vec![
        domain(
            "a",
            &[],
            vec![fixed_edge_to(
                "C:/tools/py.exe",
                "py.exe C:/scripts/d.py",
                "C:/scripts",
                "b",
            )],
        ),
        domain("b", &["C:/secret/**"], vec![]),
    ]);
    let input = fixed.transition_graph_input(None, &[]);
    let from_a = shape_of(&fixed, "a");
    assert!(!has_read(&from_a, "C:/secret/**"), "{:?}", from_a.rights);
    assert!(from_a.reachable.is_empty(), "{:?}", from_a.reachable);
    assert_eq!(
        from_a.longest_chain,
        LongestChain::Finite {
            steps: 1,
            path: names(&["a", "b"]),
        }
    );
    assert_eq!(from_a.rights, rights_summary(&input, "a").unwrap());

    // 対の側: 同じ辺を任意の引数にすると、権限が届き、届くドメインに入る。
    let open = file(vec![
        domain("a", &[], vec![edge_to("C:/tools/py.exe", "b")]),
        domain("b", &["C:/secret/**"], vec![]),
    ]);
    let input = open.transition_graph_input(None, &[]);
    let from_a = shape_of(&open, "a");
    assert!(has_read(&from_a, "C:/secret/**"), "{:?}", from_a.rights);
    assert_eq!(from_a.reachable, names(&["b"]));
    assert_eq!(from_a.rights, rights_summary(&input, "a").unwrap());
}

/// 編集時検査に落ちる宣言でも答える——エディタは直す前の宣言を見せる。
#[test]
fn shape_answers_for_a_policy_that_fails_the_check() {
    // `exe.literal`が葉の名前だけ（フルパスでない）で、しかも b は a より広い（広げる遷移）。
    let policy = file(vec![
        domain("a", &[], vec![edge_to("calc.exe", "b")]),
        domain("b", &["C:/secret/**"], vec![]),
    ]);
    let input = policy.transition_graph_input(None, &[]);
    assert!(
        !check_all(&input).unwrap().is_empty(),
        "この宣言は検査に落ちるはず"
    );
    assert!(TransitionGraph::build(&input).is_err());

    let from_a = shape(&input, "a").expect("検査に落ちても答える");
    assert_eq!(
        from_a.longest_chain,
        LongestChain::Finite {
            steps: 1,
            path: names(&["a", "b"]),
        }
    );
    assert!(has_read(&from_a, "C:/secret/**"), "{:?}", from_a.rights);
    assert_eq!(from_a.rights, rights_summary(&input, "a").unwrap());
}
