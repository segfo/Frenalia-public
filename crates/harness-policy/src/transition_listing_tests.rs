//! [段階6e] 「いま何を起こせるか」の一覧のテスト（§19.3.8）。
//!
//! **Win32もETWも触らないので昇格は要らない。** ここで固定するのは、モデルへ見せる
//! 4つのこと——宣言の綴りがそのまま出ること・到達閉包で権限を数えること・
//! **起こせない辺に印が付くこと**・並べ替えが決定的であることである。

use super::*;

use crate::transition::{AnyMarker, DomainView, TransitionEdge, TransitionRules};
use harness_config::FsAccess;

// ---------------------------------------------------------------------------
// 組み立ての補助（`transition_tests`と同じ形。借用の束を生かしておくために所有型を持つ）
// ---------------------------------------------------------------------------

struct DeclaredDomain {
    name: String,
    fs: Vec<(String, FsAccess)>,
    net: Vec<String>,
    process: TransitionRules,
}

#[derive(Default)]
struct Declared {
    domains: Vec<DeclaredDomain>,
}

impl Declared {
    fn domain(mut self, name: &str, edges: Vec<TransitionEdge>) -> Self {
        self.domains.push(DeclaredDomain {
            name: name.to_string(),
            fs: Vec::new(),
            net: Vec::new(),
            process: TransitionRules { transitions: edges },
        });
        self
    }

    fn domain_with(
        mut self,
        name: &str,
        fs: Vec<(&str, FsAccess)>,
        net: Vec<&str>,
        edges: Vec<TransitionEdge>,
    ) -> Self {
        self.domains.push(DeclaredDomain {
            name: name.to_string(),
            fs: fs.into_iter().map(|(p, a)| (p.to_string(), a)).collect(),
            net: net.into_iter().map(|d| d.to_string()).collect(),
            process: TransitionRules { transitions: edges },
        });
        self
    }

    fn input(&self) -> GraphInput<'_> {
        GraphInput {
            domains: self
                .domains
                .iter()
                .map(|domain| DomainView {
                    name: domain.name.as_str(),
                    fs: domain.fs.iter().map(|(p, a)| (p.as_str(), *a)).collect(),
                    net: domain.net.iter().map(|d| d.as_str()).collect(),
                    process: &domain.process,
                })
                .collect(),
            caller_writable_roots: Vec::new(),
        }
    }
}

fn edge(exe: ExeMatcher, argv: ArgvMatcher, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe,
        argv,
        cwd: None,
        to: to.to_string(),
        env: None,
    }
}

fn lit(path: &str) -> ExeMatcher {
    ExeMatcher::Literal(path.to_string())
}

fn any() -> ArgvMatcher {
    ArgvMatcher::Any(AnyMarker)
}

// ---------------------------------------------------------------------------

/// 行は**宣言の綴りそのまま**で、宣言順に並ぶ。
///
/// 畳んだ値（比較用に小文字へ寄せたもの）を出すと、モデルが見る綴りと`policy.json`の
/// 綴りが食い違い、**そのまま打ったのに一致しない**ことになる。
#[test]
fn rows_carry_the_declared_spelling_in_declaration_order() {
    let declared = Declared::default().domain(
        "shell",
        vec![
            edge(lit(r"C:\Program Files\Git\bin\git.exe"), any(), "shell"),
            edge(
                ExeMatcher::Pattern(r"C:\\tools\\.*\.exe".to_string()),
                ArgvMatcher::Literal("--version".to_string()),
                "shell",
            ),
        ],
    );

    let rows = rows(&declared.input(), "shell").expect("list");

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].exe, r"C:\Program Files\Git\bin\git.exe");
    assert!(!rows[0].exe_is_pattern);
    assert_eq!(rows[0].argv, ANY_ARGV, "anyは「任意の引数」として出す");
    assert_eq!(rows[1].exe, r"C:\\tools\\.*\.exe");
    assert!(
        rows[1].exe_is_pattern,
        "パターンをそのまま打てる名前として見せている"
    );
    assert_eq!(rows[1].argv, "--version");
}

/// 宣言されていないドメインからは1行も出ない。
#[test]
fn an_undeclared_domain_has_no_rows() {
    let declared = Declared::default().domain("shell", vec![]);
    assert!(rows(&declared.input(), "nowhere").expect("list").is_empty());
}

/// **【暫定】遷移先が別ドメインの辺には「いまは起こせない」印が付く**
/// （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の撤去一覧5点目）。
///
/// 印を落とすと、一覧に出ているのに撃つと拒否される——**モデルへ嘘を言う**ことになる。
/// §22.9が着地したらこのテストごと消す（暫定が残っていることを固定するためだけに在る）。
#[test]
fn an_edge_to_another_domain_is_marked_as_not_runnable_yet() {
    let declared = Declared::default()
        .domain(
            "shell",
            vec![
                edge(lit(r"C:\git.exe"), any(), "shell"),
                edge(lit(r"C:\node.exe"), any(), "tools"),
            ],
        )
        .domain("tools", vec![]);

    let rows = rows(&declared.input(), "shell").expect("list");

    assert!(rows[0].runnable_now, "同じドメイン行きは起こせる");
    assert!(
        !rows[1].runnable_now,
        "別ドメイン行きが「起こせる」と出ている。一覧に出したものが撃つと拒否される"
    );
}

/// 権限の要約は**到達閉包**で数える（§19.3.4）。
///
/// 中継を1枚挟んで広い権限へ届く形で、**直接の宣言だけを見た値とは違う**ことを固定する。
/// 直接の宣言だけを見る実装でも、中継が無い宣言では同じ答えになるので**この形でしか判別できない**。
#[test]
fn rights_are_counted_over_the_reachable_closure_not_just_the_direct_declaration() {
    let declared = Declared::default()
        .domain_with(
            "shell",
            vec![],
            vec![],
            vec![edge(lit(r"C:\git.exe"), any(), "relay")],
        )
        // 中継自身は何も持たないが、そこから先の`wide`へ渡っていける。
        .domain_with(
            "relay",
            vec![],
            vec![],
            vec![edge(lit(r"C:\sh.exe"), any(), "wide")],
        )
        .domain_with(
            "wide",
            vec![(r"C:\secrets", FsAccess::ReadWrite)],
            vec!["example.com"],
            vec![],
        );

    let rows = rows(&declared.input(), "shell").expect("list");

    assert_eq!(rows.len(), 1);
    let rights = &rows[0].rights;
    assert!(
        rights
            .fs
            .iter()
            .any(|(path, access)| path == r"C:\secrets" && *access == "read_write"),
        "中継の先の権限が要約に出ていない（直接の宣言だけを見ている）: {rights:?}"
    );
    assert!(rights.net.iter().any(|d| d == "example.com"), "{rights:?}");
}

/// 何も宣言していないドメインへの辺は、**空の要約**を持つ（`Err`にしない）。
#[test]
fn a_target_that_declares_nothing_has_an_empty_summary() {
    let declared = Declared::default()
        .domain("shell", vec![edge(lit(r"C:\git.exe"), any(), "bare")])
        .domain("bare", vec![]);

    let rows = rows(&declared.input(), "shell").expect("list");
    assert!(rows[0].rights.is_empty());
}

// ---------------------------------------------------------------------------
// 並べ替え（**LLMを1本も呼ばない**。決定的な関数だけ）
// ---------------------------------------------------------------------------

fn row_of(exe: &str) -> Row {
    Row {
        exe: exe.to_string(),
        exe_is_pattern: false,
        argv: ANY_ARGV.to_string(),
        argv_is_pattern: false,
        to_domain: "shell".to_string(),
        rights: Rights::default(),
        runnable_now: true,
    }
}

/// 名前一致が前方一致より先、前方一致が部分一致より先。
#[test]
fn ranking_puts_the_exact_name_first() {
    assert_eq!(
        match_rank("git", &row_of(r"C:\Program Files\Git\bin\git.exe")),
        Some(Rank::ExactName),
        "末尾の要素が一致しているのに一致と見なしていない"
    );
    assert_eq!(
        match_rank("gi", &row_of(r"C:\bin\git.exe")),
        Some(Rank::PrefixName)
    );
    assert_eq!(
        match_rank("bin", &row_of(r"C:\bin\git.exe")),
        Some(Rank::Contains)
    );
    assert_eq!(match_rank("svn", &row_of(r"C:\bin\git.exe")), None);
}

/// 大文字小文字を区別しない（Windowsのパスは綴りが揺れる）。
#[test]
fn ranking_ignores_case() {
    assert_eq!(
        match_rank("GIT.EXE", &row_of(r"C:\bin\git.exe")),
        Some(Rank::ExactName)
    );
}

/// **問い合わせが空なら、宣言順のまま全部返す。**
///
/// 並べ替えが順序を壊すと、ユーザーが`policy.json`で並べた意図（よく使うものを先に書く）が
/// 消える。
#[test]
fn an_empty_query_keeps_the_declaration_order() {
    let rows = vec![row_of(r"C:\z.exe"), row_of(r"C:\a.exe")];
    let ordered = filter_and_rank(rows, "  ");
    assert_eq!(ordered[0].exe, r"C:\z.exe");
    assert_eq!(ordered[1].exe, r"C:\a.exe");
}

/// **同じ近さの行も宣言順のまま**（安定ソート）。近い順に並べ替えても、
/// 同順位の中で勝手に並び替えない。
#[test]
fn equal_ranks_keep_the_declaration_order() {
    let rows = vec![
        row_of(r"C:\tools\git-lfs.exe"),
        row_of(r"C:\bin\git.exe"),
        row_of(r"C:\other\git-crypt.exe"),
    ];
    let ordered = filter_and_rank(rows, "git");

    // `git.exe`だけが名前一致で先頭。残り2件は前方一致で、宣言順のまま。
    assert_eq!(ordered[0].exe, r"C:\bin\git.exe");
    assert_eq!(ordered[1].exe, r"C:\tools\git-lfs.exe");
    assert_eq!(ordered[2].exe, r"C:\other\git-crypt.exe");
}

/// argvにしか現れない語でも引ける（`--version`のような形）。
#[test]
fn a_query_can_match_the_declared_arguments() {
    let mut row = row_of(r"C:\bin\tool.exe");
    row.argv = "--version".to_string();
    assert_eq!(match_rank("version", &row), Some(Rank::Contains));
}
