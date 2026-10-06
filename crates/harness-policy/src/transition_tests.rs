//! 遷移MACの判定器（段階⑥a）のテスト。
//!
//! **許可側と拒否側を対で測る**（`bug-pattern-rules` B-35）。拒否側だけを測ると、
//! 「全部拒否する」実装でも全部緑になる——この機構は拒否が既定なので、その形の
//! 取り違えがいちばん起きやすい。

use super::*;

// ---------------------------------------------------------------------------
// 組み立ての補助
// ---------------------------------------------------------------------------

fn literal_exe(path: &str) -> ExeMatcher {
    ExeMatcher::Literal(path.to_string())
}

fn any_argv() -> ArgvMatcher {
    ArgvMatcher::Any(AnyMarker)
}

fn literal_argv(value: &str) -> ArgvMatcher {
    ArgvMatcher::Literal(value.to_string())
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

fn rules(edges: Vec<TransitionEdge>) -> TransitionRules {
    TransitionRules { transitions: edges }
}

/// 宣言1件ぶんの持ち物。[`DomainView`]は借用の束なので、テスト中に借り先を生かしておくために
/// **所有する形**を別に持つ。
struct DeclaredDomain {
    name: String,
    fs: Vec<(String, FsAccess)>,
    net: Vec<String>,
    process: TransitionRules,
    strict: bool,
}

/// テスト中に借りっぱなしにできる形でドメインを並べるための持ち物。
struct Declared {
    domains: Vec<DeclaredDomain>,
}

impl Declared {
    fn new() -> Self {
        Self {
            domains: Vec::new(),
        }
    }

    fn domain(self, name: &str, rules: TransitionRules) -> Self {
        self.push(name, Vec::new(), Vec::new(), rules)
    }

    fn domain_with_fs(self, name: &str, fs: Vec<(&str, FsAccess)>, rules: TransitionRules) -> Self {
        let fs = fs.into_iter().map(|(p, a)| (p.to_string(), a)).collect();
        self.push(name, fs, Vec::new(), rules)
    }

    fn domain_with_net(self, name: &str, net: Vec<&str>, rules: TransitionRules) -> Self {
        let net = net.into_iter().map(|d| d.to_string()).collect();
        self.push(name, Vec::new(), net, rules)
    }

    fn push(
        mut self,
        name: &str,
        fs: Vec<(String, FsAccess)>,
        net: Vec<String>,
        process: TransitionRules,
    ) -> Self {
        self.domains.push(DeclaredDomain {
            name: name.to_string(),
            fs,
            net,
            process,
            strict: false,
        });
        self
    }

    /// 既に並べた`name`のドメインに Strict の印を付ける（決定66の追記）。
    fn mark_strict(mut self, name: &str) -> Self {
        self.domains
            .iter_mut()
            .find(|d| d.name == name)
            .expect("mark a domain that was declared")
            .strict = true;
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
                    strict: domain.strict,
                })
                .collect(),
            caller_writable_roots: Vec::new(),
        }
    }
}

fn reasons(input: &GraphInput<'_>) -> Vec<String> {
    check_all(input)
        .expect("the shape itself is valid")
        .into_iter()
        .map(|r| r.reason)
        .collect()
}

fn assert_rejects(input: &GraphInput<'_>, needle: &str) {
    let found = reasons(input);
    assert!(
        found.iter().any(|r| r.contains(needle)),
        "expected a rejection containing {needle:?}, got {found:#?}"
    );
}

fn assert_accepts(input: &GraphInput<'_>) {
    let found = reasons(input);
    assert!(found.is_empty(), "expected no rejection, got {found:#?}");
}

/// `from`の`index`番目の辺の向き（[`edge_direction`]）。
fn direction_of(input: &GraphInput<'_>, from: &str, index: usize) -> Direction {
    edge_direction(input, from, index)
        .expect("the shape itself is valid")
        .expect("the edge exists")
}

// ---------------------------------------------------------------------------
// 1. 宣言した辺は通り、宣言していない辺は拒否される（対）
// ---------------------------------------------------------------------------

#[test]
fn a_declared_transition_resolves_and_an_undeclared_one_is_denied() {
    let declared = Declared::new()
        .domain(
            "shell",
            rules(vec![edge(
                literal_exe(r"C:\Program Files\Git\cmd\git.exe"),
                any_argv(),
                "shell",
            )]),
        )
        .domain("other", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).expect("valid declaration");

    let allowed = graph.resolve(SpawnAttempt {
        from_domain: "shell",
        exe: r"C:\Program Files\Git\cmd\git.exe",
        command_line: r#""git" status"#,
        cwd: r"C:\ws",
    });
    assert!(
        allowed.is_allowed(),
        "declared edge should resolve: {allowed:?}"
    );

    let denied = graph.resolve(SpawnAttempt {
        from_domain: "shell",
        exe: r"C:\Windows\System32\cmd.exe",
        command_line: r#""cmd" /c dir"#,
        cwd: r"C:\ws",
    });
    assert_eq!(
        denied,
        Resolution::Denied(TransitionDenial::NoMatchingEdge),
        "an undeclared executable must be denied"
    );
}

/// 呼び出し元のドメインそのものが宣言に無いときは、「一致する辺が無い」とは**別の理由**で断る。
/// 同じ値へ丸めると、ドメイン名の綴り間違いと未宣言の区別が付かない。
#[test]
fn an_unknown_source_domain_is_denied_with_its_own_reason() {
    let declared = Declared::new().domain("shell", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).unwrap();

    assert_eq!(
        graph.resolve(SpawnAttempt {
            from_domain: "typo",
            exe: r"C:\x\git.exe",
            command_line: "git",
            cwd: r"C:\ws",
        }),
        Resolution::Denied(TransitionDenial::UnknownSourceDomain)
    );
}

// ---------------------------------------------------------------------------
// 2. 解決規則（リテラル優先／パターン2本一致は拒否）
// ---------------------------------------------------------------------------

#[test]
fn a_literal_edge_wins_over_a_pattern_edge_that_also_matches() {
    let declared = Declared::new()
        .domain(
            "cmd",
            rules(vec![
                TransitionEdge {
                    exe: literal_exe(r"C:\python\python.exe"),
                    argv: ArgvMatcher::Pattern(r#""c:/python/python\.exe" .*\.py"#.to_string()),
                    cwd: None,
                    to: "py-any".to_string(),
                    env: None,
                },
                TransitionEdge {
                    exe: literal_exe(r"C:\python\python.exe"),
                    argv: literal_argv(r#""C:\python\python.exe" a.py"#),
                    cwd: Some(r"C:\ws".to_string()),
                    to: "py-a".to_string(),
                    env: None,
                },
            ]),
        )
        .domain("py-any", rules(vec![]))
        .domain("py-a", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).expect("valid declaration");

    let resolved = graph.resolve(SpawnAttempt {
        from_domain: "cmd",
        exe: r"C:\python\python.exe",
        command_line: r#""C:\python\python.exe" a.py"#,
        cwd: r"C:\ws",
    });
    match resolved {
        Resolution::Allowed(allowed) => assert_eq!(
            allowed.to, "py-a",
            "the literal edge must win over the pattern edge"
        ),
        other => panic!("expected the literal edge to win, got {other:?}"),
    }

    // 特化辺に当たらないargvは、汎用のパターン辺のほうへ落ちる（対）。
    let resolved = graph.resolve(SpawnAttempt {
        from_domain: "cmd",
        exe: r"C:\python\python.exe",
        command_line: r#""c:/python/python.exe" b.py"#,
        cwd: r"C:\ws",
    });
    match resolved {
        Resolution::Allowed(allowed) => assert_eq!(allowed.to, "py-any"),
        other => panic!("expected the pattern edge to match, got {other:?}"),
    }
}

#[test]
fn two_matching_pattern_edges_are_refused_instead_of_picking_one() {
    let declared = Declared::new()
        .domain(
            "cmd",
            rules(vec![
                TransitionEdge {
                    exe: ExeMatcher::Pattern(r"c:/tools/.*\.exe".to_string()),
                    argv: any_argv(),
                    cwd: None,
                    to: "tools".to_string(),
                    env: None,
                },
                TransitionEdge {
                    exe: ExeMatcher::Pattern(r"c:/tools/gi.*".to_string()),
                    argv: any_argv(),
                    cwd: None,
                    to: "git".to_string(),
                    env: None,
                },
            ]),
        )
        .domain("tools", rules(vec![]))
        .domain("git", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).expect("valid declaration");

    assert_eq!(
        graph.resolve(SpawnAttempt {
            from_domain: "cmd",
            exe: r"C:\tools\git.exe",
            command_line: "git status",
            cwd: r"C:\ws",
        }),
        Resolution::Denied(TransitionDenial::AmbiguousPattern { matched: 2 }),
        "two matching patterns must be refused (we cannot tell which rights to grant)"
    );

    // 1本しか当たらないなら通る（対）。
    let resolved = graph.resolve(SpawnAttempt {
        from_domain: "cmd",
        exe: r"C:\tools\node.exe",
        command_line: "node",
        cwd: r"C:\ws",
    });
    match resolved {
        Resolution::Allowed(allowed) => assert_eq!(allowed.to, "tools"),
        other => panic!("a single matching pattern must resolve, got {other:?}"),
    }
}

/// 同じリテラルの組が2本あると、解決規則の段1が1本に定まらない。編集時に落とす。
#[test]
fn two_identical_literal_edges_are_rejected_at_edit_time() {
    let one = || TransitionEdge {
        exe: literal_exe(r"C:\x\git.exe"),
        argv: literal_argv(r#""git" status"#),
        cwd: Some(r"C:\ws".to_string()),
        to: "git".to_string(),
        env: None,
    };
    let declared = Declared::new()
        .domain("shell", rules(vec![one(), one()]))
        .domain("git", rules(vec![]));
    assert_rejects(&declared.input(), "duplicates the literal edge");
}

// ---------------------------------------------------------------------------
// 3. 向きと Strict の印（決定66とその追記: 広げる辺は固定なしで通る／Strict のドメインへ入る辺は固定必須）
// ---------------------------------------------------------------------------

/// **広げる辺も入力を固定せずに書ける**（決定66。守る線は子のドメインの権限）。印の付いていないドメインへ入る辺には
/// 固定の束が掛からない。向きは「広げる」と答え続ける（表示と規則(g)が使う）。
#[test]
fn a_widening_edge_needs_no_fixing_unless_it_enters_a_strict_domain() {
    // 同値（collapse）。自己ループ辺であり、閉路があっても計算が止まることも同時に見ている。
    let same = Declared::new().domain(
        "shell",
        rules(vec![edge(
            literal_exe(r"C:\x\pwsh.exe"),
            any_argv(),
            "shell",
        )]),
    );
    assert_accepts(&same.input());
    assert_eq!(direction_of(&same.input(), "shell", 0), Direction::Same);

    // 広げる: 遷移先だけが`C:/secret`を読める。普通のモードでは書ける。
    let widening = Declared::new()
        .domain(
            "narrow",
            rules(vec![edge(
                literal_exe(r"C:\x\pwsh.exe"),
                any_argv(),
                "wide",
            )]),
        )
        .domain_with_fs("wide", vec![("C:/secret", FsAccess::Read)], rules(vec![]));
    assert_accepts(&widening.input());
    assert_eq!(
        direction_of(&widening.input(), "narrow", 0),
        Direction::WiderOrUnknown
    );

    // 対: 同じ辺でも、遷移先に Strict の印があれば固定の束（引数のリテラル・作業ディレクトリ）が要る。
    let strict = widening.mark_strict("wide");
    assert_rejects(&strict.input(), "is strict");
}

/// **Strict の束の鍵は「広げるか」ではなく印である**（決定66の追記）。狭める辺でも、印の付いたドメインへ入るなら
/// 引数のリテラルと作業ディレクトリの宣言が両方要る。両方あれば通り、片方だけでは落ちる。
#[test]
fn an_edge_entering_a_strict_domain_must_fix_argv_and_cwd_whatever_its_direction() {
    let declared = |argv: ArgvMatcher, cwd: Option<&str>| {
        Declared::new()
            .domain_with_fs(
                "wide",
                vec![("C:/logs/**", FsAccess::Read)],
                rules(vec![TransitionEdge {
                    exe: literal_exe(r"C:\tools\analyze.exe"),
                    argv,
                    cwd: cwd.map(str::to_string),
                    to: "logs".to_string(),
                    env: None,
                }]),
            )
            .domain_with_fs("logs", vec![("C:/logs/**", FsAccess::Read)], rules(vec![]))
            .mark_strict("logs")
    };
    let fixed_argv = || literal_argv(r#""C:\tools\analyze.exe" --summary"#);

    let any = declared(any_argv(), None);
    assert_eq!(direction_of(&any.input(), "wide", 0), Direction::Narrower);
    assert_rejects(&any.input(), "is strict");
    assert_rejects(&declared(fixed_argv(), None).input(), "is strict");
    assert_rejects(&declared(any_argv(), Some(r"C:\tools")).input(), "is strict");
    assert_accepts(&declared(fixed_argv(), Some(r"C:\tools")).input());
}

/// 自己ループ辺は Strict のドメインへ「入る」辺ではない——呼び出し元が既にそのドメインに居て、印が守る権利を
/// 自分で持っている（決定66の追記が掛ける相手は、印の付いたドメインへ入る辺）。
#[test]
fn a_self_loop_inside_a_strict_domain_is_not_an_entering_edge() {
    let declared = Declared::new()
        .domain_with_fs(
            "logs",
            vec![("C:/logs/**", FsAccess::Read)],
            rules(vec![edge(literal_exe(r"C:\x\pwsh.exe"), any_argv(), "logs")]),
        )
        .mark_strict("logs");
    assert_accepts(&declared.input());
}

/// 狭める向きは証明できたときだけ。**遷移先の届く範囲が、遷移元が自分で宣言している権限に覆われている**ことを見る。
#[test]
fn a_narrowing_edge_is_accepted_when_containment_can_be_proven() {
    let declared = Declared::new()
        .domain_with_fs(
            "wide",
            vec![("C:/ws/**", FsAccess::ReadWrite)],
            rules(vec![edge(
                literal_exe(r"C:\x\git.exe"),
                any_argv(),
                "narrow",
            )]),
        )
        .domain_with_fs("narrow", vec![("C:/ws/src", FsAccess::Read)], rules(vec![]));
    assert_accepts(&declared.input());
    assert_eq!(direction_of(&declared.input(), "wide", 0), Direction::Narrower);
}

/// **並行する2本の辺は互いを正当化しない**（決定66の「表示用の向きの定義」）。`a`は`wide`と、その一部しか持たない
/// `part`への辺を持つ。旧来の「その辺を除いた遷移元の閉包」で数えると、`a → part`は`a → wide`に覆われて「狭める」に
/// 見えた。いまは遷移元の**自分の宣言**と比べるので、どちらも「広げる」。
#[test]
fn two_parallel_edges_do_not_justify_each_other_in_the_direction() {
    let declared = Declared::new()
        .domain(
            "a",
            rules(vec![
                edge(literal_exe(r"C:\x\wide.exe"), any_argv(), "wide"),
                edge(literal_exe(r"C:\x\part.exe"), any_argv(), "part"),
            ]),
        )
        .domain_with_fs("wide", vec![("C:/secret/**", FsAccess::Read)], rules(vec![]))
        .domain_with_fs("part", vec![("C:/secret/a", FsAccess::Read)], rules(vec![]));
    let input = declared.input();
    assert_eq!(direction_of(&input, "a", 0), Direction::WiderOrUnknown);
    assert_eq!(direction_of(&input, "a", 1), Direction::WiderOrUnknown);
}

/// **この1本が閉包の歯である。** 中継ドメインを1枚挟むと、辺ごとに比べる実装では素通りする。
///
/// `cmd`自身は何も持たず、`relay`も何も持たないが、`relay`は`wide`への辺を持つ。
/// したがって`cmd → relay`を許すことは、`cmd`へ`wide`の権限を渡すことと等価である。決定66で書けるようになったが、
/// 向きは「広げる」のままで、呼び出し元が子を通して使えるようになる権限に`wide`の分が入る。
#[test]
fn a_relay_domain_cannot_launder_wider_rights_through_an_empty_middle() {
    let declared = Declared::new()
        .domain(
            "cmd",
            rules(vec![edge(
                literal_exe(r"C:\x\pwsh.exe"),
                any_argv(),
                "relay",
            )]),
        )
        // relay自身は権限ゼロ。辺ごとに比べると`cmd → relay`は「狭める」に見える。
        .domain(
            "relay",
            rules(vec![edge(
                literal_exe(r"C:\x\node.exe"),
                any_argv(),
                "wide",
            )]),
        )
        .domain_with_fs(
            "wide",
            vec![("C:/secret/**", FsAccess::ReadWrite)],
            rules(vec![]),
        );
    let input = declared.input();
    assert_accepts(&input);
    assert_eq!(direction_of(&input, "cmd", 0), Direction::WiderOrUnknown);
    let handed = newly_usable(&input, "cmd", "relay").unwrap();
    assert!(
        handed
            .fs
            .contains(&("C:/secret/**".to_string(), "read_write")),
        "{handed:?}"
    );
}

/// **Strict の辺は閉包から辿らない**ので、その先の広さは手前へ染み上がらない（§19.3.4 の但し書きを、決定66の追記で
/// 「書き方の形」から「Strict の辺」へ付け替えた）。
///
/// **上のテストと同じ形で、中継から先の辺だけを固定してある。** 遷移先に印が無い（固定してあるだけの辺）なら
/// 閉包に入って`cmd → relay`は「広げる」、印があれば辿らず「狭める」——鍵が書き方ではなく印であることの対。
#[test]
fn a_strict_edge_does_not_propagate_the_width_behind_it_but_a_merely_fixed_one_does() {
    let declared = Declared::new()
        .domain(
            "cmd",
            rules(vec![edge(
                literal_exe(r"C:\x\pwsh.exe"),
                any_argv(),
                "relay",
            )]),
        )
        .domain(
            "relay",
            rules(vec![TransitionEdge {
                exe: literal_exe(r"C:\tools\fixed.exe"),
                argv: literal_argv(r#""C:\tools\fixed.exe" --run"#),
                cwd: Some(r"C:\tools".to_string()),
                to: "wide".to_string(),
                env: None,
            }]),
        )
        .domain_with_fs(
            "wide",
            vec![("C:/secret/**", FsAccess::ReadWrite)],
            rules(vec![]),
        );
    assert_eq!(
        direction_of(&declared.input(), "cmd", 0),
        Direction::WiderOrUnknown,
        "a fixed edge into an unmarked domain is an ordinary edge: its width counts"
    );

    let strict = declared.mark_strict("wide");
    let input = strict.input();
    assert_accepts(&input);
    assert_eq!(direction_of(&input, "cmd", 0), Direction::Narrower);
    assert!(newly_usable(&input, "cmd", "relay").unwrap().fs.is_empty());
}

/// 通信の宣言も権限として数える（FSだけ見ていると、外へ出られるドメインへの遷移が素通りする）。
#[test]
fn network_declarations_count_as_rights_too() {
    let declared = Declared::new()
        .domain(
            "offline",
            rules(vec![edge(
                literal_exe(r"C:\x\curl.exe"),
                any_argv(),
                "online",
            )]),
        )
        .domain_with_net("online", vec!["example.com"], rules(vec![]));
    assert_eq!(
        direction_of(&declared.input(), "offline", 0),
        Direction::WiderOrUnknown
    );
}

/// 規則(g): **実行ファイルのパターンは広げる辺で断り続ける**（決定66(7)。パターンが覆う場所に呼び出し元が exe を
/// 置けると、広い遷移先で任意のコードが走る）。**引数のパターンは広げる辺でも許す**（決定66(2)）。狭める辺なら
/// 実行ファイルのパターンも通る（対）。
#[test]
fn an_exe_pattern_may_only_narrow_but_an_argv_pattern_may_widen() {
    let with_edge = |edge: TransitionEdge, target_fs: Vec<(&str, FsAccess)>| {
        Declared::new()
            .domain_with_fs("src", vec![("C:/ws/**", FsAccess::Read)], rules(vec![edge]))
            .domain_with_fs("dst", target_fs, rules(vec![]))
    };
    let exe_pattern = || TransitionEdge {
        exe: ExeMatcher::Pattern(r"c:/tools/[a-z]+\.exe".to_string()),
        argv: any_argv(),
        cwd: None,
        to: "dst".to_string(),
        env: None,
    };
    let argv_pattern = || TransitionEdge {
        exe: literal_exe(r"C:\python\python.exe"),
        argv: ArgvMatcher::Pattern(r#""c:/python/python\.exe" .*\.py"#.to_string()),
        cwd: None,
        to: "dst".to_string(),
        env: None,
    };
    let wider = || vec![("C:/secret/**", FsAccess::Read)];
    let narrower = || vec![("C:/ws/src", FsAccess::Read)];

    assert_rejects(
        &with_edge(exe_pattern(), wider()).input(),
        "an executable pattern may only narrow",
    );
    assert_accepts(&with_edge(exe_pattern(), narrower()).input());
    assert_accepts(&with_edge(argv_pattern(), wider()).input());
}

/// Strict の辺でも、遷移先の権限が広いなら**実行ファイルのパターンは断る**——Strict の束は引数を固定するが、
/// パターンが覆う場所に置かれた別の exe が Strict のドメインで走るのは止めない（決定66(7)の理由はそのまま残る）。
#[test]
fn an_exe_pattern_into_a_wider_strict_domain_is_still_refused() {
    let declared = Declared::new()
        .domain(
            "src",
            rules(vec![TransitionEdge {
                exe: ExeMatcher::Pattern(r"c:/tools/[a-z]+\.exe".to_string()),
                argv: literal_argv("analyze --summary"),
                cwd: Some(r"C:\tools".to_string()),
                to: "logs".to_string(),
                env: None,
            }]),
        )
        .domain_with_fs("logs", vec![("C:/logs/**", FsAccess::Read)], rules(vec![]))
        .mark_strict("logs");
    assert_rejects(&declared.input(), "an executable pattern may only narrow");
}

/// **ハンドルの引き継ぎの式はこの段では据え置く**（`plans/position-domains/P5.md` の P5.3。安全側）。広げる辺は
/// 固定しなくても書けるようになったが、Daemon は呼び出し元の標準入出力を子へ渡さない（P5.4b で辺ごとの出力の設定へ
/// 付け替える）。固定の検査も、固定していない辺には掛からない。
#[test]
fn a_widening_edge_does_not_inherit_the_callers_handles_until_p5_4b() {
    let declared = Declared::new()
        .domain(
            "narrow",
            rules(vec![edge(literal_exe(r"C:\x\pwsh.exe"), any_argv(), "wide")]),
        )
        .domain_with_fs("wide", vec![("C:/secret", FsAccess::Read)], rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).expect("a widening edge is valid now");
    let Resolution::Allowed(allowed) = graph.resolve(SpawnAttempt {
        from_domain: "narrow",
        exe: r"C:\x\pwsh.exe",
        command_line: "pwsh -NoProfile",
        cwd: r"C:\ws",
    }) else {
        panic!("the widening edge should resolve");
    };
    assert_eq!(allowed.to, "wide");
    assert_eq!(allowed.direction, Direction::WiderOrUnknown);
    assert!(!allowed.inherit_handles);
    assert!(!allowed.fixed);
}

// ---------------------------------------------------------------------------
// 4. argvの粒度とenvの扱い
// ---------------------------------------------------------------------------

#[test]
fn an_any_argv_edge_passes_the_environment_through_and_a_literal_one_fixes_it() {
    let declared = Declared::new()
        .domain(
            "shell",
            rules(vec![
                edge(literal_exe(r"C:\x\git.exe"), any_argv(), "shell"),
                TransitionEdge {
                    exe: literal_exe(r"C:\python\python.exe"),
                    argv: literal_argv(r#""C:\python\python.exe" C:\ws\a.py"#),
                    cwd: Some(r"C:\ws".to_string()),
                    to: "shell".to_string(),
                    env: None,
                },
            ]),
        )
        .domain("py-a", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).expect("valid declaration");

    let Resolution::Allowed(passed) = graph.resolve(SpawnAttempt {
        from_domain: "shell",
        exe: r"C:\x\git.exe",
        command_line: "git status",
        cwd: r"C:\ws",
    }) else {
        panic!("the any-argv edge should resolve");
    };
    assert_eq!(passed.env, &EnvPolicy::PassThrough);
    assert!(
        passed.inherit_handles,
        "an any-argv narrowing edge keeps the caller's stdio"
    );
    assert!(
        !passed.fixed,
        "an any-argv edge fixes nothing, so the daemon has no fixed file to check"
    );

    let Resolution::Allowed(fixed) = graph.resolve(SpawnAttempt {
        from_domain: "shell",
        exe: r"C:\python\python.exe",
        command_line: r#""C:\python\python.exe" C:\ws\a.py"#,
        cwd: r"C:\ws",
    }) else {
        panic!("the literal edge should resolve");
    };
    assert!(
        matches!(fixed.env, EnvPolicy::Fixed(_)),
        "an argv-selector edge must not pass the caller's environment through"
    );
    assert!(
        !fixed.inherit_handles,
        "a fully fixed edge must not inherit the caller's handles (stdin can carry code)"
    );
    assert!(
        fixed.fixed,
        "a fully fixed edge must tell the daemon to check its fixed files before spawning"
    );
}

/// 固定したファイルの候補は、**書かれた綴りのまま**（大小も区切りも変えずに）返る
/// ——Daemonはこの値でファイルを実際に開く。相対トークンとスイッチは候補にしない（対）。
#[test]
fn fixed_file_paths_are_the_image_and_absolute_arguments_as_written() {
    let paths = fixed_file_paths(
        r"C:\Tools\Gen.exe",
        r#""C:\Tools\Gen.exe" --in C:\Data\In.txt /c rel.txt --out "D:\Out Dir\x.bin""#,
    );
    assert_eq!(
        paths,
        vec![
            r"C:\Tools\Gen.exe".to_string(),
            r"C:\Data\In.txt".to_string(),
            r"D:\Out Dir\x.bin".to_string(),
        ],
        "the image first, then only the absolute path-like arguments, spelled as written"
    );
}

/// 呼び出し元のenvを通す辺にenv差分を書いても効かない。**無言で効かない**のが最悪なので落とす。
#[test]
fn an_env_diff_on_a_pass_through_edge_is_rejected_instead_of_silently_ignored() {
    let declared = Declared::new().domain(
        "shell",
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\x\git.exe"),
            argv: any_argv(),
            cwd: None,
            to: "shell".to_string(),
            env: Some(EnvOverride {
                set: BTreeMap::from([("GIT_PAGER".to_string(), "cat".to_string())]),
                unset: Vec::new(),
            }),
        }]),
    );
    assert_rejects(&declared.input(), "would never be applied");
}

// ---------------------------------------------------------------------------
// 5. 綴りの検査
// ---------------------------------------------------------------------------

#[test]
fn an_exe_literal_must_be_a_full_path() {
    let full = Declared::new().domain(
        "shell",
        rules(vec![edge(
            literal_exe(r"C:\Program Files\Git\cmd\git.exe"),
            any_argv(),
            "shell",
        )]),
    );
    assert_accepts(&full.input());

    let leaf = Declared::new().domain(
        "shell",
        rules(vec![edge(literal_exe("git.exe"), any_argv(), "shell")]),
    );
    assert_rejects(&leaf.input(), "is not a full path");
}

#[test]
fn the_catch_all_pattern_is_refused_in_favour_of_the_single_any_spelling() {
    let declared = Declared::new().domain(
        "shell",
        rules(vec![edge(
            ExeMatcher::Pattern(".*".to_string()),
            any_argv(),
            "shell",
        )]),
    );
    assert_rejects(&declared.input(), "write it as the one spelling");
}

#[test]
fn patterns_must_be_lowercase_outside_escapes_but_escapes_may_carry_uppercase() {
    let upper = Declared::new().domain(
        "shell",
        rules(vec![edge(
            ExeMatcher::Pattern(r"c:/Tools/.*\.exe".to_string()),
            any_argv(),
            "shell",
        )]),
    );
    assert_rejects(&upper.input(), "contains the uppercase");

    // `\D`（非数字）のような大文字のescape列は通す——機械的に小文字化すると意味が反転する。
    let escaped = Declared::new().domain(
        "shell",
        rules(vec![edge(
            ExeMatcher::Pattern(r"c:/tools/\D+\.exe".to_string()),
            any_argv(),
            "shell",
        )]),
    );
    assert_accepts(&escaped.input());
}

#[test]
fn patterns_must_use_forward_slashes_and_must_not_turn_on_unicode_case_folding() {
    let backslash = Declared::new().domain(
        "shell",
        rules(vec![edge(
            ExeMatcher::Pattern(r"c:\\tools\\.*".to_string()),
            any_argv(),
            "shell",
        )]),
    );
    assert_rejects(&backslash.input(), "separators in patterns are always");

    let folding = Declared::new().domain(
        "shell",
        rules(vec![edge(
            ExeMatcher::Pattern("(?i)c:/tools/.+".to_string()),
            any_argv(),
            "shell",
        )]),
    );
    assert_rejects(&folding.input(), "case folding");
}

/// パターンは**完全一致**に固定する。固定しないと`c:/x`が`z:/evil/c:/x`に当たる。
#[test]
fn patterns_are_anchored_so_a_prefix_match_does_not_count() {
    let declared = Declared::new()
        .domain(
            "shell",
            rules(vec![edge(
                ExeMatcher::Pattern(r"c:/tools/[a-z]+\.exe".to_string()),
                any_argv(),
                "shell",
            )]),
        )
        .domain("tools", rules(vec![]));
    let input = declared.input();
    let graph = TransitionGraph::build(&input).unwrap();

    assert!(graph
        .resolve(SpawnAttempt {
            from_domain: "shell",
            exe: r"C:\tools\git.exe",
            command_line: "git",
            cwd: r"C:\ws",
        })
        .is_allowed());
    assert_eq!(
        graph.resolve(SpawnAttempt {
            from_domain: "shell",
            exe: r"Z:\evil\C:\tools\git.exe",
            command_line: "git",
            cwd: r"C:\ws",
        }),
        Resolution::Denied(TransitionDenial::NoMatchingEdge),
        "an unanchored pattern would have matched the embedded path"
    );
}

/// 入力側は畳んでから照合する（大小・区切り・verbatim接頭辞の揺れを吸収する）。
#[test]
fn the_input_spelling_is_folded_before_matching() {
    let declared = Declared::new().domain(
        "shell",
        rules(vec![edge(
            literal_exe(r"C:\Tools\Git.exe"),
            any_argv(),
            "shell",
        )]),
    );
    let input = declared.input();
    let graph = TransitionGraph::build(&input).unwrap();

    for spelling in [
        r"C:\Tools\Git.exe",
        r"c:/tools/git.exe",
        r"\\?\C:\TOOLS\GIT.EXE",
    ] {
        assert!(
            graph
                .resolve(SpawnAttempt {
                    from_domain: "shell",
                    exe: spelling,
                    command_line: "git",
                    cwd: r"C:\ws",
                })
                .is_allowed(),
            "spelling {spelling:?} should have matched the same edge"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. cwd
// ---------------------------------------------------------------------------

#[test]
fn a_relative_argument_requires_a_declared_cwd_but_an_absolute_one_does_not() {
    let relative = Declared::new().domain(
        "cmd",
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" a.py"#),
            cwd: None,
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    assert_rejects(&relative.input(), "but the edge declares no cwd");

    let absolute = Declared::new().domain(
        "cmd",
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" C:\ws\a.py"#),
            cwd: None,
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    assert_accepts(&absolute.input());
}

/// 宣言と違うcwdから撃たれたら拒否する（§8.3の2番目）。**渡すだけでは足りない。**
#[test]
fn a_declared_cwd_must_match_the_caller_and_a_matching_one_resolves() {
    let declared = Declared::new().domain(
        "cmd",
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" C:\ws\a.py"#),
            cwd: Some(r"C:\ws".to_string()),
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    let input = declared.input();
    let graph = TransitionGraph::build(&input).unwrap();

    let ok = graph.resolve(SpawnAttempt {
        from_domain: "cmd",
        exe: r"C:\python\python.exe",
        command_line: r#""C:\python\python.exe" C:\ws\a.py"#,
        cwd: r"c:/ws",
    });
    match ok {
        Resolution::Allowed(allowed) => assert_eq!(allowed.cwd, Some("c:/ws")),
        other => panic!("the matching cwd should resolve, got {other:?}"),
    }

    let mismatched = graph.resolve(SpawnAttempt {
        from_domain: "cmd",
        exe: r"C:\python\python.exe",
        command_line: r#""C:\python\python.exe" C:\ws\a.py"#,
        cwd: r"C:\elsewhere",
    });
    assert!(
        matches!(
            mismatched,
            Resolution::Denied(TransitionDenial::CwdMismatch { .. })
        ),
        "a different cwd must be denied, got {mismatched:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. 固定値が指すファイルの置き場
// ---------------------------------------------------------------------------

#[test]
fn a_fixed_value_that_the_caller_can_rewrite_is_rejected() {
    let writable_by_declaration = Declared::new().domain_with_fs(
        "cmd",
        vec![("C:/ws/**", FsAccess::ReadWrite)],
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" C:\ws\a.py"#),
            cwd: Some(r"C:\ws".to_string()),
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    assert_rejects(
        &writable_by_declaration.input(),
        "which this domain can write",
    );

    // 呼び出し元から書けない場所にあれば通る（対）。
    let elsewhere = Declared::new().domain_with_fs(
        "cmd",
        vec![("C:/ws/**", FsAccess::ReadWrite)],
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" C:\tools\a.py"#),
            cwd: Some(r"C:\ws".to_string()),
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    assert_accepts(&elsewhere.input());
}

/// 宣言の外から渡した「呼び出し元が書ける場所」も同じ検査に掛かる
/// （ワークスペースは`policy.json`に宣言として現れないことがある）。
#[test]
fn caller_writable_roots_supplied_from_outside_the_declaration_are_honoured() {
    let declared = Declared::new().domain(
        "cmd",
        rules(vec![TransitionEdge {
            exe: literal_exe(r"C:\python\python.exe"),
            argv: literal_argv(r#""C:\python\python.exe" C:\ws\a.py"#),
            cwd: Some(r"C:\ws".to_string()),
            to: "cmd".to_string(),
            env: None,
        }]),
    );
    let mut input = declared.input();
    assert_accepts(&input);

    input.caller_writable_roots = vec![r"C:\ws"];
    assert_rejects(&input, "which this domain can write");
}

// ---------------------------------------------------------------------------
// 8. ドメイン名
// ---------------------------------------------------------------------------

#[test]
fn a_domain_name_at_the_limit_is_accepted_and_one_past_it_is_not() {
    let at_limit = "a".repeat(MAX_DOMAIN_NAME_LEN);
    let over = "a".repeat(MAX_DOMAIN_NAME_LEN + 1);

    let ok = Declared::new()
        .domain(
            "shell",
            rules(vec![edge(
                literal_exe(r"C:\x\git.exe"),
                any_argv(),
                &at_limit,
            )]),
        )
        .domain(&at_limit, rules(vec![]));
    assert_accepts(&ok.input());

    let bad = Declared::new()
        .domain(
            "shell",
            rules(vec![edge(literal_exe(r"C:\x\git.exe"), any_argv(), &over)]),
        )
        .domain(&over, rules(vec![]));
    assert_rejects(&bad.input(), "leaves at most");
}

#[test]
fn a_transition_to_an_undeclared_domain_is_rejected_so_typos_are_loud() {
    let declared = Declared::new().domain(
        "shell",
        rules(vec![edge(
            literal_exe(r"C:\x\git.exe"),
            any_argv(),
            "gti", // typo
        )]),
    );
    assert_rejects(&declared.input(), "is not declared");
}

#[test]
fn a_domain_name_with_characters_the_profile_name_cannot_carry_is_rejected() {
    let declared = Declared::new()
        .domain(
            "shell",
            rules(vec![edge(
                literal_exe(r"C:\x\git.exe"),
                any_argv(),
                "git workspace",
            )]),
        )
        .domain("git workspace", rules(vec![]));
    assert_rejects(&declared.input(), "may only contain ASCII letters");
}

// ---------------------------------------------------------------------------
// 9. 綴りが1つしか無いこと（`{"any": true}`）
// ---------------------------------------------------------------------------

#[test]
fn the_only_spelling_of_any_is_true() {
    let ok: ArgvMatcher = serde_json::from_str(r#"{"any": true}"#).expect("`any: true` parses");
    assert_eq!(ok, ArgvMatcher::Any(AnyMarker));

    let err = serde_json::from_str::<ArgvMatcher>(r#"{"any": false}"#)
        .expect_err("`any: false` must not parse");
    assert!(
        err.to_string().contains("must be true"),
        "the error should say what to write instead, got {err}"
    );
}

/// `policy.json`へ書かれる綴りが設計書の形と一致していること（§5.1の例）。
#[test]
fn the_json_shape_matches_the_declared_schema() {
    let json = r#"{
      "transitions": [
        {
          "exe":  { "literal": "C:\\Windows\\System32\\python.exe" },
          "argv": { "literal": "\"C:\\Windows\\System32\\python.exe\" a.py" },
          "cwd":  "C:\\ws",
          "to":   "py-a"
        },
        {
          "exe":  { "pattern": "c:/ws/target/debug/build/.*/build-script-build\\.exe" },
          "argv": { "any": true },
          "to":   "buildscript"
        }
      ]
    }"#;
    let parsed: TransitionRules = serde_json::from_str(json).expect("the documented shape parses");
    assert_eq!(parsed.transitions.len(), 2);
    assert_eq!(parsed.transitions[1].to, "buildscript");

    // 往復しても形が変わらない（空のキーは出さない）。
    let written = serde_json::to_string(&parsed).unwrap();
    assert!(
        !written.contains("\"env\""),
        "an absent env must not be written back as null: {written}"
    );
    assert_eq!(
        serde_json::from_str::<TransitionRules>(&written).unwrap(),
        parsed
    );
}

/// 空の宣言は`policy.json`に1文字も足さない（既存のファイルが差分だらけにならない）。
#[test]
fn empty_rules_serialise_to_nothing() {
    let written = serde_json::to_string(&TransitionRules::default()).unwrap();
    assert_eq!(written, "{}");
}

// ---------------------------------------------------------------------------
// 10. グラフの外形
// ---------------------------------------------------------------------------

#[test]
fn a_duplicated_domain_name_is_refused_before_anything_else_is_judged() {
    let declared = Declared::new()
        .domain("shell", rules(vec![]))
        .domain("shell", rules(vec![]));
    assert_eq!(
        TransitionGraph::build(&declared.input()).unwrap_err(),
        GraphError::DuplicateDomain("shell".to_string())
    );
}

/// 1本でも落ちたらグラフは作られない——一部だけ有効にすると、
/// 「拒否されたはずの辺が効いていない」と「そもそも宣言していない」が区別できなくなる。
#[test]
fn one_rejected_edge_prevents_the_whole_graph_from_being_built() {
    let declared = Declared::new().domain(
        "shell",
        rules(vec![
            edge(literal_exe(r"C:\x\git.exe"), any_argv(), "shell"),
            edge(literal_exe("leaf-only.exe"), any_argv(), "shell"),
        ]),
    );
    assert!(matches!(
        TransitionGraph::build(&declared.input()),
        Err(GraphError::RejectedEdges(_))
    ));
}
