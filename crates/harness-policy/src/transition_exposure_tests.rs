//! 遷移で呼び出し元が子を通して新しく使えるようになる権限（[`newly_usable`]）と、
//! 組み合わせの対（[`exposure_delta`]）の単体試験（2026-10-06、`plans/position-domains/P5.md` P5.2）。
//!
//! 入力は`PolicyFile`を組んで`transition_graph_input`で作る（`transition_shape_tests`と同じ。
//! 判定器の試験の借用の束の補助を写さない）。
//!
//! **数える側と数えない側を対で測る**（`bug-pattern-rules` B-35）——「新しく使える権限がある」だけを
//! 測ると、何でも広げると答える実装でも緑になる。

use crate::transition::ChildOutput;
use super::*;

use crate::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use crate::transition::{AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};
use crate::transition_listing::Rights;

/// 宣言1件を組む補助。
struct Decl(PolicyDomain);

impl Decl {
    fn new(name: &str) -> Self {
        Self(PolicyDomain::new(name))
    }

    fn read(mut self, value: &str) -> Self {
        self.0.fs.read.push(value.to_string());
        self
    }

    fn read_write(mut self, value: &str) -> Self {
        self.0.fs.read_write.push(value.to_string());
        self
    }

    fn read_exec(mut self, value: &str) -> Self {
        self.0.fs.read_exec.push(value.to_string());
        self
    }

    fn net(mut self, domain: &str) -> Self {
        self.0.net.allow_domains.push(domain.to_string());
        self
    }

    /// Strict の印（決定66の追記）。
    fn strict(mut self) -> Self {
        self.0.strict = true;
        self
    }

    /// 引数をリテラルにし、作業ディレクトリを宣言した辺（Strict の束を満たす形）。
    fn fixed_edge(mut self, exe: &str, to: &str) -> Self {
        self.0.process.transitions.push(TransitionEdge {
            exe: ExeMatcher::Literal(exe.to_string()),
            argv: ArgvMatcher::Literal(format!("\"{exe}\" --run")),
            cwd: Some("C:/t".to_string()),
            to: to.to_string(),
            env: None,
            output: ChildOutput::Return,
        });
        self
    }

    /// 任意の引数で`exe`を起こすと`to`へ移る辺（エディタが書く形）。
    fn edge(mut self, exe: &str, to: &str) -> Self {
        self.0.process.transitions.push(TransitionEdge {
            exe: ExeMatcher::Literal(exe.to_string()),
            argv: ArgvMatcher::Any(AnyMarker),
            cwd: None,
            to: to.to_string(),
            env: None,
            output: ChildOutput::Return,
        });
        self
    }
}

fn file(domains: Vec<Decl>) -> PolicyFile {
    PolicyFile {
        domains: domains.into_iter().map(|d| d.0).collect(),
        ..PolicyFile::default()
    }
}

fn newly(file: &PolicyFile, from: &str, to: &str) -> Rights {
    newly_usable(&file.transition_graph_input(None, &[]), from, to)
        .expect("同じ名前のドメインは無い")
}

fn delta(
    before: &PolicyFile,
    after: &PolicyFile,
    net_capable: impl Fn(&DomainView<'_>) -> bool,
) -> ExposureDelta {
    exposure_delta(
        &before.transition_graph_input(None, &[]),
        &after.transition_graph_input(None, &[]),
        net_capable,
    )
    .expect("同じ名前のドメインは無い")
}

fn rights(fs: &[(&str, &'static str)], net: &[&str]) -> Rights {
    Rights {
        fs: fs.iter().map(|(v, a)| (v.to_string(), *a)).collect(),
        net: net.iter().map(|d| d.to_string()).collect(),
    }
}

fn pair(
    writer: &str,
    writer_place: &str,
    reader: &str,
    reader_place: &str,
    use_: PairUse,
) -> CombinationPair {
    CombinationPair {
        writer: writer.to_string(),
        writer_place: writer_place.to_string(),
        reader: reader.to_string(),
        reader_place: reader_place.to_string(),
        use_,
    }
}

// ---------------------------------------------------------------------------
// 1. 新しく使える権限＝遷移先の届く範囲の権限 − 遷移元が自分で宣言している権限
// ---------------------------------------------------------------------------

/// 遷移先の側は**届く範囲**（到達閉包。`b → c`の先の通信も入る）で、遷移元の側は**自分の宣言だけ**で数える。
///
/// - `b`の`C:/a/x.txt`（読む）は`a`自身の`C:/a/**`（読む）が覆うので数えない
/// - `b`の`C:/a/w.txt`（書く）は、`a`が読むだけなので数える（アクセスが強い）
/// - `a`は別の辺で`d`（`C:/b/**`を読む）へも移れるが、**それは`a`自身の宣言ではない**ので引かない
///   （決定65(5)＝親は自分が触った分だけを持つ）
#[test]
fn newly_usable_compares_the_destination_closure_with_the_sources_own_rights() {
    let policy = file(vec![
        Decl::new("a")
            .read("C:/a/**")
            .edge("C:/t/b.exe", "b")
            .edge("C:/t/d.exe", "d"),
        Decl::new("b")
            .read("C:/a/x.txt")
            .read_write("C:/a/w.txt")
            .read("C:/b/**")
            .edge("C:/t/c.exe", "c"),
        Decl::new("c").net("Example.com"),
        Decl::new("d").read("C:/b/**"),
    ]);

    assert_eq!(
        newly(&policy, "a", "b"),
        rights(
            &[("C:/a/w.txt", "read_write"), ("C:/b/**", "read")],
            &["example.com"]
        ),
    );
}

/// 遷移元が自分で宣言している権限に覆われる遷移先は、何も渡さない（許可側の対）。
/// 覆い方は判定器と同じ（`**`の宣言が配下を覆う・通信先は大文字小文字を区別しない）。
#[test]
fn an_edge_whose_destination_the_source_already_covers_hands_over_nothing() {
    let policy = file(vec![
        Decl::new("a")
            .read("C:/data/**")
            .net("example.com")
            .edge("C:/t/b.exe", "b"),
        Decl::new("b").read("C:/data/sub/x.txt").net("EXAMPLE.com"),
    ]);

    assert!(
        newly(&policy, "a", "b").is_empty(),
        "{:?}",
        newly(&policy, "a", "b")
    );
}

/// 自己ループ辺は何も渡さない——子は呼び出し元と同じドメインで、子が辿れる辺は呼び出し元も
/// 自分で辿れる（その辺がそれぞれ自分の分を数える）。**届く範囲には広い`w`が入っている**ので、
/// 定義を字面どおりに当てるとここが空にならない。
#[test]
fn a_self_loop_hands_over_nothing_new() {
    let policy = file(vec![
        Decl::new("a")
            .edge("C:/t/a.exe", "a")
            .edge("C:/t/w.exe", "w"),
        Decl::new("w").read_write("C:/secret/**"),
    ]);

    assert!(
        newly(&policy, "a", "a").is_empty(),
        "{:?}",
        newly(&policy, "a", "a")
    );
    assert!(!newly(&policy, "a", "w").is_empty());
}

/// 同じ遷移先への辺が2本あっても、**互いを正当化しない**（決定66の表示用の向きの定義）。
///
/// 閉包から当の辺だけを除いて数えると、もう1本の辺が遷移元の閉包に`b`を入れるので
/// 「どちらも広げない」と出てしまう。遷移元の側を**自分の宣言**で数えるので、2本とも同じ権限を渡す。
#[test]
fn two_parallel_edges_do_not_justify_each_other() {
    let before = file(vec![
        Decl::new("a"),
        Decl::new("b").read_write("C:/secret/**"),
    ]);
    let after = file(vec![
        Decl::new("a")
            .edge("C:/t/one.exe", "b")
            .edge("C:/t/two.exe", "b"),
        Decl::new("b").read_write("C:/secret/**"),
    ]);
    let handed = rights(&[("C:/secret/**", "read_write")], &[]);

    assert_eq!(newly(&after, "a", "b"), handed);
    assert_eq!(
        delta(&before, &after, net_capable).edges,
        vec![
            EdgeExposure {
                from: "a".to_string(),
                edge_index: 0,
                to: "b".to_string(),
                newly_usable: handed.clone(),
            },
            EdgeExposure {
                from: "a".to_string(),
                edge_index: 1,
                to: "b".to_string(),
                newly_usable: handed,
            },
        ],
    );
}

/// 前からあった辺は**今回の変更で増えた分だけ**を出し、増えていない辺は出さない。新しい辺は全部を出す。
///
/// 辺はそのままでも、遷移先のファイルの宣言を足すと渡る権限が増える（P5.md のリスク・注意
/// 「ファイルの宣言の承認・付け替え・取り消しでも辺は広がり得る」）。
#[test]
fn an_edge_that_existed_before_reports_only_what_the_edit_added() {
    let before = file(vec![
        Decl::new("a")
            .edge("C:/t/b.exe", "b")
            .edge("C:/t/d.exe", "d"),
        Decl::new("b").read("C:/b/one.txt"),
        Decl::new("c").read("C:/c/**"),
        Decl::new("d").read("C:/d/x.txt"),
    ]);
    let after = file(vec![
        Decl::new("a")
            .edge("C:/t/b.exe", "b")
            .edge("C:/t/d.exe", "d")
            .edge("C:/t/c.exe", "c"),
        Decl::new("b").read("C:/b/one.txt").read("C:/b/two.txt"),
        Decl::new("c").read("C:/c/**"),
        Decl::new("d").read("C:/d/x.txt"),
    ]);

    assert_eq!(
        delta(&before, &after, net_capable).edges,
        vec![
            EdgeExposure {
                from: "a".to_string(),
                edge_index: 0,
                to: "b".to_string(),
                newly_usable: rights(&[("C:/b/two.txt", "read")], &[]),
            },
            EdgeExposure {
                from: "a".to_string(),
                edge_index: 2,
                to: "c".to_string(),
                newly_usable: rights(&[("C:/c/**", "read")], &[]),
            },
        ],
    );
}

/// **Strict のドメインへ入る辺は、呼び出し元が子を通して使える権限に数えない**（決定66の追記。入力が固定されて
/// いて、呼び出し元は子に決めた操作しかさせられない）。同じ形でも印が無ければ全部を数える（対）。
#[test]
fn an_edge_entering_a_strict_domain_hands_nothing_to_the_caller() {
    let before = |logs: Decl| file(vec![Decl::new("a"), logs]);
    let after = |logs: Decl| file(vec![Decl::new("a").fixed_edge("C:/t/analyze.exe", "logs"), logs]);
    let logs = || Decl::new("logs").read("C:/logs/**");

    let strict_after = after(logs().strict());
    assert_eq!(newly(&strict_after, "a", "logs"), Rights::default());
    assert!(delta(&before(logs().strict()), &strict_after, net_capable)
        .edges
        .is_empty());

    let plain_after = after(logs());
    let handed = rights(&[("C:/logs/**", "read")], &[]);
    assert_eq!(newly(&plain_after, "a", "logs"), handed);
    assert_eq!(
        delta(&before(logs()), &plain_after, net_capable).edges,
        vec![EdgeExposure {
            from: "a".to_string(),
            edge_index: 0,
            to: "logs".to_string(),
            newly_usable: handed,
        }],
    );
}

/// 遷移先の**先にある** Strict の辺も、届く範囲に数えない（閉包が Strict の辺を辿らない。§19.3.4 の付け替え）。
/// 印が無ければ、固定してあるだけの辺の先も届く範囲に入る（対）。
#[test]
fn a_strict_edge_behind_the_destination_hands_nothing_behind_it() {
    let policy = |logs: Decl| {
        file(vec![
            Decl::new("a").edge("C:/t/relay.exe", "relay"),
            Decl::new("relay").fixed_edge("C:/t/analyze.exe", "logs"),
            logs,
        ])
    };
    let logs = || Decl::new("logs").read("C:/logs/**");

    assert_eq!(newly(&policy(logs().strict()), "a", "relay"), Rights::default());
    assert_eq!(
        newly(&policy(logs()), "a", "relay"),
        rights(&[("C:/logs/**", "read")], &[])
    );
}

// ---------------------------------------------------------------------------
// 2. 組み合わせの対（Limit 1）＝あるドメインが書ける場所を、外部通信できる別のドメインが読む／実行する
// ---------------------------------------------------------------------------

/// 書く側の`**`の範囲の中のファイルを、通信できる別のドメインが読むと対になる。
#[test]
fn a_writer_and_a_net_capable_reader_of_one_place_form_a_pair() {
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt").net("example.com"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![pair(
            "w",
            "C:/shared/**",
            "r",
            "C:/shared/in.txt",
            PairUse::Read
        )],
    );
}

/// 実行できる重なりも対になる（書いたものが通信できるドメインで**走る**）。
/// 重なりは両方向で見る——読む側の範囲が書く側の範囲の中にあっても、書く側の1ファイルが
/// 読む側の`**`の範囲の中にあっても重なる。
#[test]
fn an_exec_overlap_is_a_pair() {
    let after = file(vec![
        Decl::new("w")
            .read_write("C:/shared/**")
            .read_write("C:/drop/run.ps1"),
        Decl::new("r")
            .read_exec("C:/shared/tools/**")
            .read_exec("C:/drop/**")
            .net("example.com"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![
            pair("w", "C:/drop/run.ps1", "r", "C:/drop/**", PairUse::Execute),
            pair(
                "w",
                "C:/shared/**",
                "r",
                "C:/shared/tools/**",
                PairUse::Execute
            ),
        ],
    );
}

/// 読む側が外部と通信できなければ対にしない。**同じ形に通信先を1つ足すと対になる**（対照）。
#[test]
fn a_pair_without_a_net_capable_reader_is_not_reported() {
    let offline = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt"),
    ]);
    let online = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt").net("example.com"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &offline, net_capable).pairs,
        vec![]
    );
    assert_eq!(
        delta(&file(vec![]), &online, net_capable)
            .pairs
            .len(),
        1
    );
}

/// 暫定の判定（P7 で差し替える）では、入口のドメインは通信の宣言が無くても通信できるとみなす。
#[test]
fn the_entry_domain_counts_as_net_capable_until_p7() {
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new(ENTRY_DOMAIN).read("C:/shared/in.txt"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![pair(
            "w",
            "C:/shared/**",
            ENTRY_DOMAIN,
            "C:/shared/in.txt",
            PairUse::Read
        )],
    );
}

/// [P5.4a] 宣言の外で書ける場所（[`GraphInput::caller_writable_roots`]＝ワークスペースと、`policy.json`の外で書込を
/// 許した場所）は、**入口のドメインが書ける場所**として対に数える——ファイルの宣言に書込が1つも無くても、入口の
/// コードがそこへ置いたものを通信できる別のドメインが読む／実行すれば持ち出しの経路になる。根は**配下全部**を書ける
/// 場所として重なりを見る（規則(i)が根を同じく配下ごとに数えるのと揃える）。
///
/// 対照: 同じ宣言でも根を渡さなければ対は無い（宣言の`read_write`だけを数えていた P5.2 の形）。
#[test]
fn places_writable_outside_the_declarations_are_written_by_the_entry_domain() {
    let after = file(vec![Decl::new("r")
        .read("C:/ws/out/report.txt")
        .read_exec("C:/tools/**")
        .net("example.com")]);
    let roots = ["C:/tools".to_string()];
    let with_roots = exposure_delta(
        &file(vec![]).transition_graph_input(Some("C:/ws"), &roots),
        &after.transition_graph_input(Some("C:/ws"), &roots),
        net_capable,
    )
    .expect("同じ名前のドメインは無い");

    assert_eq!(
        with_roots.pairs,
        vec![
            pair(
                ENTRY_DOMAIN,
                "C:/tools",
                "r",
                "C:/tools/**",
                PairUse::Execute
            ),
            pair(
                ENTRY_DOMAIN,
                "C:/ws",
                "r",
                "C:/ws/out/report.txt",
                PairUse::Read
            ),
        ],
    );
    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![],
        "根を渡さなければ、宣言に書込が無いので対は無い"
    );
}

/// 通信できるかは**呼び出し側が渡す関数だけ**で決める（宣言の`net`を自分で見ない）。
#[test]
fn the_net_capable_judgement_is_the_callers() {
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt").net("example.com"),
        Decl::new("q").read("C:/shared/in.txt"),
    ]);

    assert_eq!(delta(&file(vec![]), &after, |_| false).pairs, vec![]);
    assert_eq!(
        delta(&file(vec![]), &after, |view| view.name == "q").pairs,
        vec![pair(
            "w",
            "C:/shared/**",
            "q",
            "C:/shared/in.txt",
            PairUse::Read
        )],
    );
}

/// 重ならない場所は対にしない——名前の先頭が同じだけの隣の場所（`C:/sharedx`）と、
/// 同じドメインの中の読み書き（**別の**ドメインの組ではない）。
#[test]
fn neighbouring_places_and_a_domain_alone_are_not_pairs() {
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/sharedx/in.txt").net("example.com"),
        Decl::new("both")
            .read_write("C:/own/**")
            .read("C:/own/in.txt")
            .net("example.com"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![]
    );
}

/// 変更の前からあった対は出さず、変更で生まれた対だけを出す。
#[test]
fn pairs_that_existed_before_are_not_new() {
    let before = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt").net("example.com"),
    ]);
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/**"),
        Decl::new("r").read("C:/shared/in.txt").net("example.com"),
        Decl::new("r2")
            .read_exec("C:/shared/bin/**")
            .net("example.org"),
    ]);

    assert_eq!(
        delta(&before, &after, net_capable).pairs,
        vec![pair(
            "w",
            "C:/shared/**",
            "r2",
            "C:/shared/bin/**",
            PairUse::Execute
        )],
    );
}

/// 付与層が受け付けない形（`**`以外のワイルドカードが残る値）は、ACEが1本も付かず何も開かないので重ならない。
///
/// `C:/shared/*/**`は末尾が`**`なので、書かれた形だけを見ると「`C:/shared`の配下全部」に見える
/// （確定部分が`C:/shared`まで戻る）。それを再帰の範囲として数えると、ここが対になってしまう。
#[test]
fn a_value_the_grant_layer_refuses_opens_no_place() {
    let after = file(vec![
        Decl::new("w").read_write("C:/shared/*/**"),
        Decl::new("r").read("C:/shared/x/out").net("example.com"),
    ]);

    assert_eq!(
        delta(&file(vec![]), &after, net_capable).pairs,
        vec![]
    );
}

// ---------------------------------------------------------------------------
// [P5.6] Strict の辺を明細に出す（辺のモードを示す）
// ---------------------------------------------------------------------------

/// [P5.6] **変更で新しく Strict になった辺**（入る先に印が付いた・印の付いたドメインへ新しく入った）を返す——明細はそれを
/// 「入力を固定するので呼び出し元は子を操れない（広がる遷移に数えない）」と1行で言う（辺のモードを示す。P5.md の P5.6）。
///
/// 対（`B-35`）: 前から Strict だった辺・自己ループ・印の無いドメインへ入る辺は出さない。
#[test]
fn edges_that_newly_enter_a_strict_domain_are_reported_but_old_ones_are_not() {
    let plain = file(vec![
        Decl::new(ENTRY_DOMAIN).fixed_edge("C:/t/report.exe", "logs"),
        Decl::new("logs").read("C:/logs/**"),
    ]);
    let marked = file(vec![
        Decl::new(ENTRY_DOMAIN).fixed_edge("C:/t/report.exe", "logs"),
        Decl::new("logs").read("C:/logs/**").strict(),
    ]);
    let d = delta(&plain, &marked, net_capable);
    assert_eq!(
        d.strict_edges,
        vec![StrictEdge {
            from: ENTRY_DOMAIN.to_string(),
            edge_index: 0,
            to: "logs".to_string(),
        }]
    );
    assert!(d.edges.is_empty(), "Strict の辺は何も渡さない: {:?}", d.edges);

    // 前から Strict だった辺は新しくない。
    assert!(delta(&marked, &marked, net_capable).strict_edges.is_empty());
    // 印の無いドメインへ入る辺・Strict のドメインの中の自己ループは Strict の辺ではない。
    let self_loop = file(vec![
        Decl::new(ENTRY_DOMAIN),
        Decl::new("logs").fixed_edge("C:/t/report.exe", "logs").strict(),
    ]);
    assert!(delta(&plain, &plain, net_capable).strict_edges.is_empty());
    assert!(delta(&file(vec![]), &self_loop, net_capable).strict_edges.is_empty());
}
