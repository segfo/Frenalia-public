//! 位置ごとのドメインの割り当て（[`assign_domains`]）とファイル操作の振り分け（[`partition_fs`]）の単体試験。
//!
//! **ユーザーの例は、割り当て→辺を`PolicyFile`へ書く→Spawn Daemon と同じ判定器（`TransitionGraph::build`と
//! `resolve`）で引く、の一周で確かめる**——割り当ての形だけを見ると、書いた辺が判定器で本当に通る／断られるかを
//! 誰も見ていないことになる。辺は P4 のエディタが使う[`Assignment::edges_to_add`]・
//! [`Assignment::domains_to_add`]で書く（P4 が通る道と同じ）。
//!
//! 名前の検査は偽物（[`limit_27`]）を渡す。`harness-policy`は`harness-sandbox`に依存できない（依存は逆向き）。

use crate::transition::ChildOutput;
use std::path::Path;

use harness_config::FsAccess;

use super::*;
use crate::event::{FsAuditEvent, FsAuditKind};
use crate::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use crate::process_event::{
    ArgvBinding, ArgvMissingReason, ArgvTruncation, ParentSeqSource, ProcessAuditLog,
    ProcessInstance,
};
use crate::transition::{
    AnyMarker, ArgvMatcher, ExeMatcher, Resolution, SpawnAttempt, TransitionDenial, TransitionEdge,
    TransitionGraph,
};

const WS: &str = "C:/work";
const CMD: &str = "C:/Windows/System32/cmd.exe";
const PWSH: &str = "C:/Program Files/PowerShell/7/pwsh.exe";
const CALC: &str = "C:/Windows/System32/calc.exe";
const MSPAINT: &str = "C:/Windows/System32/mspaint.exe";
const NOTEPAD: &str = "C:/Windows/System32/notepad.exe";
/// 記録に無い親（harness 本体）。
const HARNESS_SEQ: u64 = 9_000;

/// 親の番号を欄から取り、引数が結び付いた子（コマンドラインは実行ファイルを引用符で囲んだだけ）。
fn child(seq: u64, parent: u64, image: &str) -> ProcessInstance {
    ProcessInstance {
        seq,
        parent_seq: Some(parent),
        parent_seq_source: ParentSeqSource::EtwField,
        pid: seq as u32,
        parent_pid: Some(parent as u32),
        image_path: Some(image.to_string()),
        argv: ArgvBinding::Exact {
            command_line: format!("\"{image}\""),
            truncation: ArgvTruncation::None,
        },
        is_scope_root: false,
        timestamp_unix_ms: 1_700_000_000_000 + seq,
    }
}

/// 記録の根（親は harness 本体で、記録に無い）。
fn root(seq: u64, image: &str) -> ProcessInstance {
    ProcessInstance {
        is_scope_root: true,
        ..child(seq, HARNESS_SEQ, image)
    }
}

fn log(instances: Vec<ProcessInstance>) -> ProcessAuditLog {
    ProcessAuditLog {
        instances,
        controls: Vec::new(),
        skipped_lines: 0,
    }
}

/// 名前の検査の偽物。本物（`harness_sandbox::tier2a::domain_profile_name_problem`）と同じ規則
/// （英数字と`-`・`.`、27文字以内）。27 は本物の試験`the_longest_destination_name_is_the_27_of_decision_65`が
/// 固定している——あちらが赤くなったら、ここの27も直すこと。
fn limit_27(name: &str) -> Option<String> {
    let ok = !name.is_empty()
        && name.len() <= 27
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    (!ok).then(|| format!("入れ物の名前にできません（英数字と「-」「.」だけ、27文字まで）: {name}"))
}

fn assign(log: &ProcessAuditLog, policy: &PolicyFile) -> Assignment {
    assign_split(log, policy, &[])
}

/// `split`の（遷移元, 実行ファイル）の位置をコマンドラインごとに分けて割り当てる（決定67(1)）。実行ファイルは
/// 判定器と同じ畳み方で鍵にする（[`split_key`]と同じ）。
fn assign_split(log: &ProcessAuditLog, policy: &PolicyFile, split: &[(&str, &str)]) -> Assignment {
    let split: SplitPositions = split
        .iter()
        .map(|(from, exe)| (from.to_string(), fold_for_pattern_comparison(exe)))
        .collect();
    assign_domains(log, policy, Path::new(WS), &limit_27, &split).expect("検査に通る policy.json")
}

/// 提案した位置を辺として書く（P4 のエディタと同じく[`Assignment::domains_to_add`]・
/// [`Assignment::edges_to_add`]を通す）。
fn write_proposals(policy: &mut PolicyFile, assignment: &Assignment) {
    for name in assignment.domains_to_add(policy) {
        policy.domains.push(PolicyDomain::new(name));
    }
    for add in assignment.edges_to_add() {
        policy
            .domains
            .iter_mut()
            .find(|d| d.name == add.from_domain)
            .expect("遷移元は宣言済みか domains_to_add が作った")
            .process
            .transitions
            .push(add.edge);
    }
}

/// Spawn Daemon と同じ判定器（検査を必ず通る）。
fn graph(policy: &PolicyFile) -> TransitionGraph {
    TransitionGraph::build(&policy.transition_graph_input(Some(WS), &[]))
        .expect("書いた辺は検査に通る")
}

/// `from`のドメインから`exe`を（引数なしで）起こしたときの判定。許可なら遷移先。
fn resolve_to(graph: &TransitionGraph, from: &str, exe: &str) -> Result<String, TransitionDenial> {
    let command_line = format!("\"{exe}\"");
    match graph.resolve(SpawnAttempt {
        from_domain: from,
        exe,
        command_line: &command_line,
        cwd: WS,
    }) {
        Resolution::Allowed(allowed) => Ok(allowed.to.to_string()),
        Resolution::Denied(denial) => Err(denial),
    }
}

/// 入口のドメインから`exes`を順に起こしたときの各段の判定（Spawn Daemon が段ごとに聞くのと同じ）。
/// 断られた段で止まる。
fn walk_chain(graph: &TransitionGraph, exes: &[&str]) -> Vec<Result<String, TransitionDenial>> {
    let mut out = Vec::new();
    let mut from = ENTRY_DOMAIN.to_string();
    for exe in exes {
        let step = resolve_to(graph, &from, exe);
        let denied = step.is_err();
        if let Ok(to) = &step {
            from = to.clone();
        }
        out.push(step);
        if denied {
            break;
        }
    }
    out
}

fn ok(to: &str) -> Result<String, TransitionDenial> {
    Ok(to.to_string())
}

const NO_EDGE: Result<String, TransitionDenial> = Err(TransitionDenial::NoMatchingEdge);

/// 位置を (depth, from, exe, to, source) に写す（seq に依らない比較用）。
fn shape_of(assignment: &Assignment) -> Vec<(usize, String, String, String, PositionSource)> {
    assignment
        .positions
        .iter()
        .map(|p| {
            (
                p.depth,
                p.from_domain.clone(),
                p.exe.clone(),
                p.to_domain.clone(),
                p.source,
            )
        })
        .collect()
}

fn pos(
    depth: usize,
    from: &str,
    exe: &str,
    to: &str,
    source: PositionSource,
) -> (usize, String, String, String, PositionSource) {
    (
        depth,
        from.to_string(),
        exe.to_string(),
        to.to_string(),
        source,
    )
}

/// ユーザーの例: cmd → pwsh → calc と cmd → pwsh → mspaint。
fn users_example() -> Vec<ProcessInstance> {
    vec![
        root(10, CMD),
        child(11, 10, PWSH),
        child(12, 11, CALC),
        root(20, CMD),
        child(21, 20, PWSH),
        child(22, 21, MSPAINT),
    ]
}

/// 任意の引数で`exe`を起こすと`to`へ移る辺（エディタが書く形）。
fn any_edge(exe: &str, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: to.to_string(),
        env: None,
        output: ChildOutput::Return,
    }
}

fn domain(name: &str, edges: Vec<TransitionEdge>) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.process.transitions = edges;
    domain
}

fn file(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        domains,
        ..PolicyFile::default()
    }
}

fn unassigned(seq: u64, reason: Unassigned) -> UnassignedInstance {
    UnassignedInstance { seq, reason }
}

/// **この段の一番大事な完了条件。** ユーザーの例を割り当て、提案を辺として書き、Spawn Daemon と同じ判定器で
/// 引くと、記録した2本の連鎖の各段だけが通り、記録に無い連鎖は外れた段で`NoMatchingEdge`になる。
#[test]
fn the_users_example_allows_only_the_recorded_chains() {
    let assignment = assign(&log(users_example()), &PolicyFile::default());
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, PWSH, "pwsh", PositionSource::Proposed),
            pos(2, "pwsh", CALC, "calc", PositionSource::Proposed),
            pos(2, "pwsh", MSPAINT, "mspaint", PositionSource::Proposed),
        ]
    );
    let instances: Vec<Vec<u64>> = assignment
        .positions
        .iter()
        .map(|p| p.instances.clone())
        .collect();
    assert_eq!(instances, vec![vec![11, 21], vec![12], vec![22]]);

    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &assignment);
    let graph = graph(&policy);

    // 通る: cmd→pwsh→calc / cmd→pwsh→mspaint（cmd は入口のドメインに居る根）。
    assert_eq!(
        walk_chain(&graph, &[PWSH, CALC]),
        vec![ok("pwsh"), ok("calc")]
    );
    assert_eq!(
        walk_chain(&graph, &[PWSH, MSPAINT]),
        vec![ok("pwsh"), ok("mspaint")]
    );

    // 断る（対の側）: cmd→cmd→calc / cmd→pwsh→pwsh / cmd→cmd→notepad。
    assert_eq!(walk_chain(&graph, &[CMD, CALC]), vec![NO_EDGE]);
    assert_eq!(walk_chain(&graph, &[PWSH, PWSH]), vec![ok("pwsh"), NO_EDGE]);
    assert_eq!(walk_chain(&graph, &[CMD, NOTEPAD]), vec![NO_EDGE]);
    // 入口から直接 notepad も、pwsh のドメインから直接 notepad も通らない。
    assert_eq!(resolve_to(&graph, ENTRY_DOMAIN, NOTEPAD), NO_EDGE);
    assert_eq!(resolve_to(&graph, "pwsh", NOTEPAD), NO_EDGE);
}

/// 記録の根（`is_scope_root`）は親の番号を見ない——親が記録に在っても、その子として位置を作らない。
/// 根の辺は観測から作らず、起動する当のコードから合成する（§19.3.12）。
///
/// 根の親は普通 harness 本体か Spawn Daemon で記録に無いので、ユーザーの例ではこの違いが出ない
/// （親が記録に無ければ`walk`は根として返す）。親が記録に在る根でだけ見える。
#[test]
fn a_scope_root_does_not_look_at_its_parent() {
    let nested_root = ProcessInstance {
        is_scope_root: true,
        ..child(20, 10, CMD)
    };
    let assignment = assign(
        &log(vec![root(10, CMD), nested_root, child(30, 10, PWSH)]),
        &PolicyFile::default(),
    );
    let roots: Vec<u64> = assignment.roots.iter().map(|r| r.seq).collect();
    assert_eq!(roots, vec![10, 20]);
    assert_eq!(assignment.domain_of(20), Some(ENTRY_DOMAIN));
    // 対の側: 根でない子は、同じ親の下で位置になる。
    assert_eq!(
        shape_of(&assignment),
        vec![pos(1, ENTRY_DOMAIN, PWSH, "pwsh", PositionSource::Proposed)]
    );
    assert_eq!(assignment.positions[0].instances, vec![30]);
}

/// 同じ実行ファイルが連鎖に再登場したら、深さごとに別のドメインになる（§19.3.2 の unroll）。
#[test]
fn a_repeated_exe_is_split_by_depth() {
    let assignment = assign(
        &log(vec![root(10, CMD), child(11, 10, CMD), child(12, 11, CMD)]),
        &PolicyFile::default(),
    );
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, CMD, "cmd", PositionSource::Proposed),
            pos(2, "cmd", CMD, "cmd-2", PositionSource::Proposed),
        ]
    );
    assert_eq!(
        [10, 11, 12].map(|seq| assignment.domain_of(seq)),
        [Some(ENTRY_DOMAIN), Some("cmd"), Some("cmd-2")]
    );

    // 書いた後: 記録した3段は通り、記録に無い4段目は断られる。
    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &assignment);
    assert_eq!(
        walk_chain(&graph(&policy), &[CMD, CMD, CMD]),
        vec![ok("cmd"), ok("cmd-2"), NO_EDGE]
    );
}

/// 葉名が同じ名前に寄る2つの実行ファイル（`a.b`→`a-b`、`a-b`→`a-b`）。どちらが`a-b`を取るかが
/// 通し番号や入力の順で決まっていると、2回目の記録で入れ替わる。
const A_DOT_B: &str = "C:/t/a.b.exe";
const A_DASH_B: &str = "C:/u/a-b.exe";

fn run_a() -> Vec<ProcessInstance> {
    let mut instances = users_example();
    instances.extend([
        root(30, CMD),
        child(31, 30, A_DOT_B),
        child(32, 30, A_DASH_B),
    ]);
    instances
}

/// 同じ木を、通し番号の大小を逆にし（`5_000 - seq`）、並びも逆にし、pid も変えて記録し直したもの。
fn run_b() -> Vec<ProcessInstance> {
    let remap = |seq: u64| 5_000 - seq;
    run_a()
        .into_iter()
        .rev()
        .map(|mut instance| {
            instance.seq = remap(instance.seq);
            instance.parent_seq =
                instance
                    .parent_seq
                    .map(|p| if p == HARNESS_SEQ { p } else { remap(p) });
            instance.pid += 77;
            instance
        })
        .collect()
}

/// 名前は通し番号・入力の順・pid に依らない（2回目の記録でも同じ名前になる）。
#[test]
fn names_are_stable_across_runs() {
    let a = assign(&log(run_a()), &PolicyFile::default());
    let b = assign(&log(run_b()), &PolicyFile::default());
    assert_eq!(shape_of(&a), shape_of(&b));
    // 葉名の衝突は（遷移元, 葉名, 畳んだ exe）の順で解く: `c:/t/…` が `c:/u/…` より先に`a-b`を取る。
    assert!(shape_of(&a).contains(&pos(
        1,
        ENTRY_DOMAIN,
        A_DOT_B,
        "a-b",
        PositionSource::Proposed
    )));
    assert!(shape_of(&a).contains(&pos(
        1,
        ENTRY_DOMAIN,
        A_DASH_B,
        "a-b-2",
        PositionSource::Proposed
    )));

    // 対の側: 1回目の提案を書いた policy.json で2回目を割り当てると、同じ位置が全部「既にある辺」で出る。
    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &a);
    let again = assign(&log(run_b()), &policy);
    let routes = |x: &Assignment| -> Vec<(String, String, String)> {
        x.positions
            .iter()
            .map(|p| (p.from_domain.clone(), p.exe.clone(), p.to_domain.clone()))
            .collect()
    };
    assert_eq!(routes(&again), routes(&a));
    assert!(again
        .positions
        .iter()
        .all(|p| p.source == PositionSource::ExistingEdge));
    assert!(again.edges_to_add().is_empty());
}

/// 既にある自己ループ辺（`(入口, pwsh) → 入口`）に新しい位置を吸わせない（決定65 Q7）。
/// 置き換えるかは P4.5 のダイアログでユーザーが決めるので、出どころで知らせる。
#[test]
fn an_existing_self_loop_is_reported_not_absorbed() {
    let recorded = log(vec![root(10, CMD), child(11, 10, PWSH)]);

    let policy = file(vec![domain(
        ENTRY_DOMAIN,
        vec![any_edge(PWSH, ENTRY_DOMAIN)],
    )]);
    let assignment = assign(&recorded, &policy);
    assert_eq!(
        shape_of(&assignment),
        vec![pos(
            1,
            ENTRY_DOMAIN,
            PWSH,
            "pwsh",
            PositionSource::ReplacesSelfLoop
        )]
    );
    assert_eq!(assignment.positions[0].instances, vec![11]);
    assert_eq!(assignment.domain_of(11), Some("pwsh"));
    let adds = assignment.edges_to_add();
    assert_eq!(adds.len(), 1);
    assert_eq!(adds[0].source, PositionSource::ReplacesSelfLoop);

    // 対の側: 自己ループでない既にある辺なら、その遷移先をそのまま使い、何も足さない。
    let policy = file(vec![
        domain(ENTRY_DOMAIN, vec![any_edge(PWSH, "ps")]),
        domain("ps", vec![]),
    ]);
    let assignment = assign(&recorded, &policy);
    assert_eq!(
        shape_of(&assignment),
        vec![pos(
            1,
            ENTRY_DOMAIN,
            PWSH,
            "ps",
            PositionSource::ExistingEdge
        )]
    );
    assert!(assignment.edges_to_add().is_empty());
}

/// 同じ位置（遷移元・実行ファイルが同じ）のインスタンスの一部だけが自己ループ辺に当たっても、
/// 位置の出どころは`ReplacesSelfLoop`——書く前に自己ループ辺の扱いをユーザーに確かめる必要があるのは
/// 1つでも当たったときだから。名前は引数で分けないので1つ（決定65 Q1）。
#[test]
fn a_position_partly_on_a_self_loop_reports_the_self_loop() {
    let self_loop_for_one_argv = TransitionEdge {
        exe: ExeMatcher::Literal(PWSH.to_string()),
        argv: ArgvMatcher::Literal(format!("\"{PWSH}\"")),
        cwd: None,
        to: ENTRY_DOMAIN.to_string(),
        env: None,
        output: ChildOutput::Return,
    };
    let policy = file(vec![domain(ENTRY_DOMAIN, vec![self_loop_for_one_argv])]);
    let other_argv = ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: "pwsh -NoProfile".to_string(),
            truncation: ArgvTruncation::None,
        },
        ..child(12, 10, PWSH)
    };
    let assignment = assign(
        &log(vec![root(10, CMD), child(11, 10, PWSH), other_argv]),
        &policy,
    );
    assert_eq!(
        shape_of(&assignment),
        vec![pos(
            1,
            ENTRY_DOMAIN,
            PWSH,
            "pwsh",
            PositionSource::ReplacesSelfLoop
        )]
    );
    assert_eq!(assignment.positions[0].instances, vec![11, 12]);
}

/// 名前の検査を通らない名前は短く切って通さず、断る（決定65 Q9）。その子孫も割り当てない。
#[test]
fn a_name_longer_than_the_limit_is_refused() {
    let a28 = "a".repeat(28);
    let long = format!("C:/t/{a28}.exe");
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            child(11, 10, &long),
            child(12, 11, CALC),
        ]),
        &PolicyFile::default(),
    );
    assert!(assignment.positions.is_empty());
    assert_eq!(
        assignment.unassigned,
        vec![
            unassigned(
                11,
                Unassigned::NameRefused {
                    proposed: a28.clone(),
                    reason: limit_27(&a28).expect("28文字は断る"),
                }
            ),
            unassigned(12, Unassigned::ParentUnassigned),
        ]
    );

    // 対の側: 27文字の葉名は割り当てられる。
    let a27 = "a".repeat(27);
    let fits = format!("C:/t/{a27}.exe");
    let assignment = assign(
        &log(vec![root(10, CMD), child(11, 10, &fits)]),
        &PolicyFile::default(),
    );
    assert_eq!(
        shape_of(&assignment),
        vec![pos(1, ENTRY_DOMAIN, &fits, &a27, PositionSource::Proposed)]
    );

    // 27文字の葉名が2段続くと、2段目は`<27>-2`（29文字）になって断られる。
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            child(11, 10, &fits),
            child(12, 11, &fits),
        ]),
        &PolicyFile::default(),
    );
    assert_eq!(assignment.positions.len(), 1);
    let second = format!("{a27}-2");
    assert_eq!(
        assignment.unassigned,
        vec![unassigned(
            12,
            Unassigned::NameRefused {
                reason: limit_27(&second).expect("29文字は断る"),
                proposed: second,
            }
        )]
    );
}

fn fs_event(seq: Option<u64>) -> FsAuditEvent {
    let event = FsAuditEvent::observed(
        FsAuditKind::Etw,
        "C:/data/x.txt",
        FsAccess::Read,
        true,
        "",
        1,
    );
    match seq {
        Some(seq) => event.with_process_sequence_number(seq),
        None => event,
    }
}

fn seqs(events: &[&FsAuditEvent]) -> Vec<Option<u64>> {
    events.iter().map(|e| e.process_sequence_number).collect()
}

/// どのドメインにも引けないファイル操作は、入口のドメインへ寄せずに理由ごとに数える（決定65 Q4）。
#[test]
fn unattributed_fs_events_are_counted_not_assigned() {
    let mut instances = users_example();
    instances.push(child(40, 777, NOTEPAD)); // 親が記録に無い＝割り当てない
    let assignment = assign(&log(instances), &PolicyFile::default());
    assert_eq!(assignment.domain_of(40), None);

    let events = vec![
        fs_event(Some(10)),
        fs_event(Some(11)),
        fs_event(None),
        fs_event(Some(999)),
        fs_event(Some(40)),
        // 制御の行は番号が付いていても振り分けない（数えもしない）。
        FsAuditEvent::control("collector started", 1).with_process_sequence_number(10),
    ];
    let partition = partition_fs(&events, &assignment);
    assert_eq!(
        seqs(&partition.by_domain[ENTRY_DOMAIN].events),
        vec![Some(10)]
    );
    assert_eq!(seqs(&partition.by_domain["pwsh"].events), vec![Some(11)]);
    assert!(partition.by_domain["calc"].events.is_empty());
    assert!(partition.by_domain["mspaint"].events.is_empty());
    assert_eq!(
        partition.unattributed,
        Unattributed {
            without_sequence_number: 1,
            unknown_sequence_number: 1,
            unassigned_instance: 1,
        }
    );

    // 対の側: 割り当てた行はどれも数えた側に入らない（合計が、制御の行を除いた行の数と一致する）。
    let attributed: usize = partition.by_domain.values().map(|s| s.events.len()).sum();
    assert_eq!(attributed + 3, events.len() - 1);
}

/// 親を決められない子（出どころが`unresolved`・親の番号が記録に無い）とその子孫は割り当てず、理由ごとに数える
/// （決定65の追記(2)）。**出どころが`unresolved`なら、番号が書いてあっても使わない。**
#[test]
fn unresolved_parents_are_counted_not_assigned() {
    let unresolved = |seq: u64, parent_seq: Option<u64>, image: &str| ProcessInstance {
        parent_seq,
        parent_seq_source: ParentSeqSource::Unresolved,
        ..child(seq, 0, image)
    };
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            unresolved(30, None, PWSH),
            child(31, 30, CALC),
            child(40, 777, NOTEPAD),
            unresolved(50, Some(10), PWSH),
        ]),
        &PolicyFile::default(),
    );
    assert!(assignment.positions.is_empty());
    assert_eq!(
        assignment.unassigned,
        vec![
            unassigned(30, Unassigned::ParentUnresolved),
            unassigned(31, Unassigned::ParentUnassigned),
            unassigned(40, Unassigned::ParentNotRecorded { parent_seq: 777 }),
            unassigned(50, Unassigned::ParentUnresolved),
        ]
    );
    assert_eq!(
        assignment.unassigned_counts(),
        BTreeMap::from([
            ("parent_not_recorded", 1),
            ("parent_unassigned", 1),
            ("parent_unresolved", 2),
        ])
    );

    // 対の側: 記録の根は割り当てる（入口のドメイン）。
    assert_eq!(
        assignment.roots,
        vec![RootInstance {
            seq: 10,
            image_path: Some(CMD.to_string()),
        }]
    );
    assert_eq!(assignment.domain_of(10), Some(ENTRY_DOMAIN));
}

/// 子の実行ファイル自身の実行権は子のドメインへ（決定65 Q8）。親のドメインには入らない。
#[test]
fn a_childs_own_image_goes_to_the_childs_domain() {
    let assignment = assign(&log(users_example()), &PolicyFile::default());
    let partition = partition_fs(&[], &assignment);
    let images = |domain: &str| -> Vec<&str> {
        partition.by_domain[domain]
            .exec_images
            .iter()
            .map(String::as_str)
            .collect()
    };
    assert_eq!(images(ENTRY_DOMAIN), vec![CMD]);
    assert_eq!(images("pwsh"), vec![PWSH]);
    assert_eq!(images("calc"), vec![CALC]);
    assert_eq!(images("mspaint"), vec![MSPAINT]);
}

/// 引数が結び付かなかった起動・切り詰められた疑いのある起動は数え、コマンドラインの一覧に入れない
/// （§19.3.11。リテラルの辺の候補にしない）。位置は引数で分けない（決定65 Q1）。
#[test]
fn missing_or_truncated_argv_is_counted_and_left_out_of_the_command_lines() {
    let with_argv = |seq: u64, argv: ArgvBinding| ProcessInstance {
        argv,
        ..child(seq, 10, PWSH)
    };
    let exact = |command_line: &str, truncation: ArgvTruncation| ArgvBinding::Exact {
        command_line: command_line.to_string(),
        truncation,
    };
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            with_argv(
                11,
                ArgvBinding::Missing {
                    reason: ArgvMissingReason::NoArgvObserved,
                },
            ),
            with_argv(12, exact("pwsh -c long", ArgvTruncation::Suspected)),
            with_argv(13, exact("pwsh -NoProfile", ArgvTruncation::None)),
            with_argv(14, exact("pwsh -c cut", ArgvTruncation::Certain)),
            with_argv(15, exact("pwsh -NoProfile", ArgvTruncation::None)),
        ]),
        &PolicyFile::default(),
    );
    assert_eq!(assignment.positions.len(), 1);
    let position = &assignment.positions[0];
    assert_eq!(position.instances, vec![11, 12, 13, 14, 15]);
    assert_eq!(position.argv_missing, 1);
    assert_eq!(position.argv_truncated, 2);
    assert_eq!(position.command_lines, vec!["pwsh -NoProfile".to_string()]);
}

/// `policy.json`が遷移の検査に落ちるなら割り当てない（判定器で既にある辺を引けないので）。
#[test]
fn a_policy_that_fails_the_check_is_an_error() {
    let recorded = log(vec![root(10, CMD), child(11, 10, PWSH)]);
    let broken = file(vec![domain(
        ENTRY_DOMAIN,
        vec![any_edge("calc.exe", ENTRY_DOMAIN)],
    )]);
    match assign_domains(&recorded, &broken, Path::new(WS), &limit_27, &SplitPositions::new()) {
        Err(AssignError::PolicyRejected(_)) => {}
        other => panic!("検査に落ちる policy.json は割り当てない: {other:?}"),
    }

    // 対の側: 空の policy.json なら割り当てる。
    assert!(assign_domains(
        &recorded,
        &PolicyFile::default(),
        Path::new(WS),
        &limit_27,
        &SplitPositions::new()
    ).is_ok());
}

/// [P5.10.1] **作業ディレクトリを宣言した既にある辺（Strict の辺・相対パスの引数の辺）に当たる起動は、その辺の位置に
/// なる**（決定67(3)）。記録は作業ディレクトリを持たないので、判定器へはワークスペースを渡して`CwdMismatch`になる。
/// その辺だけが実行ファイルと引数で当たっているので、**宣言の作業ディレクトリで起きたものとみなして引き直す**——
/// 直さないと、エディタが Strict の辺を書いた直後に同じ記録を読み直したとき、その起動が「既にある辺と食い違う起動」に
/// なり、そのファイル操作がどのドメインにも引けなくなる（P5.10.1 の前は`ExistingEdgeUnresolvable`だった）。
/// 同じ実行ファイルでも、その辺に当たらない引数の起動は今までどおり新しい名前で提案する（対の側）。
#[test]
fn an_existing_edge_with_a_declared_cwd_takes_its_launch() {
    let fixed = TransitionEdge {
        exe: ExeMatcher::Literal(PWSH.to_string()),
        argv: ArgvMatcher::Literal(format!("\"{PWSH}\"")),
        cwd: Some("C:/elsewhere".to_string()),
        to: "fixed".to_string(),
        env: None,
        output: ChildOutput::Return,
    };
    let policy = file(vec![
        domain(ENTRY_DOMAIN, vec![fixed]),
        domain("fixed", vec![]),
    ]);
    let other_argv = ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: "pwsh -NoProfile".to_string(),
            truncation: ArgvTruncation::None,
        },
        ..child(12, 10, PWSH)
    };
    let assignment = assign(
        &log(vec![root(10, CMD), child(11, 10, PWSH), other_argv]),
        &policy,
    );
    assert_eq!(assignment.unassigned, vec![]);
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, PWSH, "fixed", PositionSource::ExistingEdge),
            pos(1, ENTRY_DOMAIN, PWSH, "pwsh", PositionSource::Proposed),
        ]
    );
    assert_eq!(assignment.positions[0].instances, vec![11]);
    assert_eq!(assignment.positions[1].instances, vec![12]);
}

/// 既にある辺に当たったが判定器が許可を答えない（パターンの辺が2本当たる）なら、提案もしない
/// ——足すと既にある辺と食い違う。同じ実行ファイルでも、その辺に当たらない引数の起動は提案する。
#[test]
fn an_existing_edge_the_resolver_cannot_answer_is_left_unassigned() {
    let pattern = |pattern: &str, to: &str| TransitionEdge {
        exe: ExeMatcher::Pattern(pattern.to_string()),
        argv: ArgvMatcher::Literal(format!("\"{PWSH}\"")),
        cwd: None,
        to: to.to_string(),
        env: None,
        output: ChildOutput::Return,
    };
    let policy = file(vec![
        domain(
            ENTRY_DOMAIN,
            vec![
                pattern(r"c:/program files/powershell/7/pwsh\.exe", "one"),
                pattern(r"c:/program files/.*/pwsh\.exe", "two"),
            ],
        ),
        domain("one", vec![]),
        domain("two", vec![]),
    ]);
    let other_argv = ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: "pwsh -NoProfile".to_string(),
            truncation: ArgvTruncation::None,
        },
        ..child(12, 10, PWSH)
    };
    let assignment = assign(
        &log(vec![root(10, CMD), child(11, 10, PWSH), other_argv]),
        &policy,
    );
    assert_eq!(
        assignment.unassigned,
        vec![unassigned(
            11,
            Unassigned::ExistingEdgeUnresolvable(TransitionDenial::AmbiguousPattern { matched: 2 })
        )]
    );
    // 対の側: その辺に当たらない引数の起動は、新しい名前で提案する。
    assert_eq!(
        shape_of(&assignment),
        vec![pos(1, ENTRY_DOMAIN, PWSH, "pwsh", PositionSource::Proposed)]
    );
    assert_eq!(assignment.positions[0].instances, vec![12]);
}

/// 壊れた記録（同じ番号が2回・実行ファイルのパスが無い・親子の閉路）は割り当てず、理由ごとに数える。
#[test]
fn broken_records_are_counted_by_reason() {
    let no_image = ProcessInstance {
        image_path: None,
        ..child(11, 10, PWSH)
    };
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            root(10, CMD), // 同じ番号の2つ目
            no_image,
            child(20, 21, CMD), // 20 と 21 が互いの親
            child(21, 20, CMD),
            child(30, 30, CMD), // 自分が自分の親
        ]),
        &PolicyFile::default(),
    );
    assert!(assignment.positions.is_empty());
    assert_eq!(
        assignment.unassigned,
        vec![
            unassigned(10, Unassigned::DuplicateSequenceNumber),
            unassigned(11, Unassigned::NoImagePath),
            unassigned(20, Unassigned::InCycle),
            unassigned(21, Unassigned::ParentUnassigned),
            unassigned(30, Unassigned::InCycle),
        ]
    );
    assert_eq!(
        assignment.unassigned_counts(),
        BTreeMap::from([
            ("duplicate_sequence_number", 1),
            ("in_cycle", 2),
            ("no_image_path", 1),
            ("parent_unassigned", 1),
        ])
    );
    // 対の側: 1つ目の根は割り当てる（2回は数えない）。
    assert_eq!(assignment.roots.len(), 1);
    assert_eq!(assignment.domain_of(10), Some(ENTRY_DOMAIN));
}

/// 提案する名前は`policy.json`に既にあるドメイン名を使わない（大小だけ違う名前も）——同じ名前にすると、
/// 無関係なドメインの宣言と辺を引き継いでしまう。
#[test]
fn a_proposed_name_does_not_reuse_a_declared_domain() {
    let policy = file(vec![domain("pwsh", vec![]), domain("CALC", vec![])]);
    let assignment = assign(
        &log(vec![
            root(10, CMD),
            child(11, 10, PWSH),
            child(12, 11, CALC),
        ]),
        &policy,
    );
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, PWSH, "pwsh-2", PositionSource::Proposed),
            pos(2, "pwsh-2", CALC, "calc-2", PositionSource::Proposed),
        ]
    );
    // 書くときに足すドメインは、宣言の無い3つだけ（既にある`pwsh`・`CALC`は作り直さない）。
    assert_eq!(
        assignment.domains_to_add(&policy),
        vec![
            "calc-2".to_string(),
            "pwsh-2".to_string(),
            ENTRY_DOMAIN.to_string()
        ]
    );
}

// ---------------------------------------------------------------------------
// [P5.10.1] 引数を固定した位置をコマンドラインごとに分ける（決定67）
// ---------------------------------------------------------------------------

const PYTHON: &str = "C:/Python312/python.exe";
const MV: &str = r"python C:\tools\mv.py C:\data\test.txt C:\data\test1.txt";
const REMOVE: &str = r"python C:\tools\remove.py C:\data\test1.txt";

/// 引数`command_line`が結び付いた子。
fn ran(seq: u64, parent: u64, image: &str, command_line: &str) -> ProcessInstance {
    ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: command_line.to_string(),
            truncation: ArgvTruncation::None,
        },
        ..child(seq, parent, image)
    }
}

/// 決定67の発端の例: 同じ`python.exe`で`mv.py`と`remove.py`を動かす。
fn two_scripts() -> Vec<ProcessInstance> {
    vec![
        root(10, CMD),
        ran(11, 10, PYTHON, MV),
        ran(12, 10, PYTHON, REMOVE),
    ]
}

/// `seq`の起動が`path`へ書いた行。
fn wrote(seq: u64, path: &str) -> FsAuditEvent {
    FsAuditEvent::observed(FsAuditKind::Etw, path, FsAccess::ReadWrite, true, "", 1)
        .with_process_sequence_number(seq)
}

fn paths(events: &[&FsAuditEvent]) -> Vec<String> {
    events.iter().filter_map(|e| e.path.clone()).collect()
}

/// `from`のドメインから`exe`をコマンドライン`command_line`で起こしたときの判定（許可なら遷移先）。
fn resolve_line(
    graph: &TransitionGraph,
    from: &str,
    exe: &str,
    command_line: &str,
) -> Result<String, TransitionDenial> {
    match graph.resolve(SpawnAttempt {
        from_domain: from,
        exe,
        command_line,
        cwd: WS,
    }) {
        Resolution::Allowed(allowed) => Ok(allowed.to.to_string()),
        Resolution::Denied(denial) => Err(denial),
    }
}

/// **決定67の発端。** 分けなければ（今まで・引数が任意の位置）、`mv.py`と`remove.py`は1つのドメインを共有し、
/// `remove.py`のドメインが`mv.py`の書いたファイルの権限も持つ。分けると、各スクリプトのドメインは自分の起動が
/// 触った分だけを持ち、Spawn Daemon と同じ判定器は各コマンドラインを各ドメインへ送り、記録に無いコマンドラインは
/// 断る（`NoMatchingEdge`）。辺は`edges_to_add`（エディタが書く形）のリテラルの引数。
#[test]
fn splitting_a_script_runner_gives_each_script_its_own_domain() {
    let events = vec![wrote(11, "C:/data/test.txt"), wrote(12, "C:/data/test1.txt")];

    // 分けない（空の集合）: 1つの位置に2つの起動、ドメイン python が両方の書込を持つ（穴の再現）。
    let joined = assign(&log(two_scripts()), &PolicyFile::default());
    assert_eq!(
        shape_of(&joined),
        vec![pos(1, ENTRY_DOMAIN, PYTHON, "python", PositionSource::Proposed)]
    );
    assert_eq!(joined.positions[0].fixed_command_line, None);
    assert_eq!(
        paths(&partition_fs(&events, &joined).by_domain["python"].events),
        vec!["C:/data/test.txt".to_string(), "C:/data/test1.txt".to_string()]
    );

    // 分ける: コマンドラインごとの位置・ドメイン。
    let split = assign_split(&log(two_scripts()), &PolicyFile::default(), &[(ENTRY_DOMAIN, PYTHON)]);
    assert_eq!(
        shape_of(&split),
        vec![
            pos(1, ENTRY_DOMAIN, PYTHON, "python-mv", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, PYTHON, "python-remove", PositionSource::Proposed),
        ]
    );
    assert_eq!(split.positions[0].fixed_command_line.as_deref(), Some(MV));
    assert_eq!(split.positions[1].fixed_command_line.as_deref(), Some(REMOVE));
    assert_eq!(split.positions[0].instances, vec![11]);
    assert_eq!(split.positions[1].instances, vec![12]);
    assert_eq!(split.split_refused, vec![]);
    let partition = partition_fs(&events, &split);
    assert_eq!(
        paths(&partition.by_domain["python-remove"].events),
        vec!["C:/data/test1.txt".to_string()],
        "remove.py のドメインに mv.py の書いた test.txt の権限が入ってはいけない"
    );
    assert_eq!(
        paths(&partition.by_domain["python-mv"].events),
        vec!["C:/data/test.txt".to_string()]
    );

    // 書く辺は引数のリテラル（形は editor_edge）。判定器が各コマンドラインを各ドメインへ送る。
    let edges = split.edges_to_add();
    assert_eq!(
        edges.iter().map(|e| e.edge.argv.clone()).collect::<Vec<_>>(),
        vec![
            ArgvMatcher::Literal(MV.to_string()),
            ArgvMatcher::Literal(REMOVE.to_string())
        ]
    );
    assert!(edges.iter().all(|e| e.edge.cwd.is_none()), "作業ディレクトリは割り当てが決めない（エディタが足す）");
    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &split);
    let graph = graph(&policy);
    assert_eq!(resolve_line(&graph, ENTRY_DOMAIN, PYTHON, MV), ok("python-mv"));
    assert_eq!(resolve_line(&graph, ENTRY_DOMAIN, PYTHON, REMOVE), ok("python-remove"));
    assert_eq!(
        resolve_line(&graph, ENTRY_DOMAIN, PYTHON, r"python C:\tools\other.py"),
        NO_EDGE,
        "記録に無いコマンドラインは通さない"
    );
    // 判定器と同じ畳み方で束ねる: 大小・区切りだけ違う綴りは同じ辺に当たる。
    assert_eq!(
        resolve_line(&graph, ENTRY_DOMAIN, PYTHON, &MV.to_uppercase()),
        ok("python-mv")
    );
}

/// **欠けたコマンドラインが1つでもあれば分けない**（決定67(2)。今の`u`と同じ前例）。分けなかった位置と理由の件数を
/// `split_refused`に出し、位置は1つ（任意の引数）のまま。切り詰めの疑いも同じ。分けない位置は他の位置の分け方に
/// 影響しない（対の側: 同じ記録の別の遷移元の位置は分ける）。
#[test]
fn a_position_with_a_missing_or_truncated_command_line_is_not_split() {
    let missing = ProcessInstance {
        argv: ArgvBinding::Missing {
            reason: ArgvMissingReason::NoArgvObserved,
        },
        ..child(13, 10, PYTHON)
    };
    let truncated = ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: "pwsh -c long".to_string(),
            truncation: ArgvTruncation::Suspected,
        },
        ..child(22, 20, PWSH)
    };
    let mut instances = two_scripts();
    instances.push(missing);
    instances.extend([
        root(20, CMD),
        ran(21, 20, PWSH, "pwsh -NoProfile"),
        truncated,
        root(30, NOTEPAD),
        ran(31, 30, CALC, "calc"),
        ran(32, 30, CALC, "calc -x"),
    ]);
    // NOTEPAD を根にした記録の根の位置は入口のドメインなので、calc の鍵も入口のドメインで書く。
    let assignment = assign_split(
        &log(instances),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON), (ENTRY_DOMAIN, PWSH), (ENTRY_DOMAIN, CALC)],
    );
    assert_eq!(
        assignment.split_refused,
        vec![
            SplitRefused {
                from_domain: ENTRY_DOMAIN.to_string(),
                exe: PWSH.to_string(),
                argv_missing: 0,
                argv_truncated: 1,
            },
            SplitRefused {
                from_domain: ENTRY_DOMAIN.to_string(),
                exe: PYTHON.to_string(),
                argv_missing: 1,
                argv_truncated: 0,
            },
        ]
    );
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, CALC, "calc", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, CALC, "calc-2", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, PWSH, "pwsh", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, PYTHON, "python", PositionSource::Proposed),
        ]
    );
    let python = &assignment.positions[3];
    assert_eq!(python.fixed_command_line, None);
    assert_eq!(python.instances, vec![11, 12, 13]);
    assert!(!python.can_split(), "欠けがある位置は分けられない");
    assert!(!assignment.positions[2].can_split(), "切り詰めの疑いがある位置は分けられない");
    // 対の側: 欠けの無い位置は分けられる（分けた後の位置も）。
    assert!(assign(&log(two_scripts()), &PolicyFile::default()).positions[0].can_split());
    assert!(assignment.positions[0].can_split());
}

/// **分けた位置の名前**（決定67の「分けた位置のドメイン名」）: スクリプトの拡張子を持つ語があれば
/// `<葉名>-<語幹>`、無ければ`<葉名>`（使われていれば`<葉名>-2`から）。語幹の形が名前の検査に落ちたら、切らずに
/// `<葉名>`の形へ倒す。語幹は葉名と同じく`[a-z0-9-]`へ寄せる。どの名前も名前の検査を通る。
#[test]
fn split_names_use_the_script_stem_or_fall_back_to_the_leaf() {
    let long = r"python C:\tools\a_script_whose_name_is_far_too_long.py";
    let assignment = assign_split(
        &log(vec![
            root(10, CMD),
            ran(11, 10, PYTHON, r#"python "C:\My Tools\Log_Report.PY" --since today"#),
            ran(12, 10, PYTHON, "python -c print(1)"),
            ran(13, 10, PYTHON, "python -V"),
            ran(14, 10, PYTHON, long),
        ]),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON)],
    );
    let names: BTreeMap<String, String> = assignment
        .positions
        .iter()
        .map(|p| {
            (
                p.fixed_command_line.clone().expect("分けた位置"),
                p.to_domain.clone(),
            )
        })
        .collect();
    assert_eq!(
        names[r#"python "C:\My Tools\Log_Report.PY" --since today"#],
        "python-log-report"
    );
    // 語幹の無い2つと、長すぎる語幹から倒した1つが`<葉名>`・`<葉名>-N`を分け合う（順は名前の元と綴りで決まる）。
    let mut leaf_names: Vec<&str> = [long, "python -V", "python -c print(1)"]
        .iter()
        .map(|line| names[*line].as_str())
        .collect();
    leaf_names.sort();
    assert_eq!(leaf_names, vec!["python", "python-2", "python-3"]);
    assert!(assignment.unassigned.is_empty(), "長い語幹で断らない");
    assert!(names.values().all(|name| limit_27(name).is_none()));
}

/// **2回の記録で名前が同じ**——通し番号と並びを変えても、同じコマンドラインの位置は同じ名前になる
/// （名前は遷移元・名前の元・実行ファイル・コマンドラインの順で決まる）。
#[test]
fn split_names_are_stable_across_runs() {
    let a = assign_split(
        &log(two_scripts()),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON)],
    );
    let b = assign_split(
        &log(vec![
            root(50, CMD),
            ran(51, 50, PYTHON, REMOVE),
            ran(52, 50, PYTHON, MV),
            ran(53, 50, PYTHON, REMOVE),
        ]),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON)],
    );
    assert_eq!(shape_of(&a), shape_of(&b));
    assert_eq!(b.positions[1].instances, vec![51, 53]);
}

/// **子孫は分けた後のドメインを遷移元にする**（決定67(1)。親を先に解く割り当てのまま）。分けたドメインを遷移元に
/// した位置もさらに分けられる（鍵は分けた後のドメイン名）。
#[test]
fn the_descendants_of_a_split_position_start_from_the_split_domain() {
    let instances = vec![
        root(10, CMD),
        ran(11, 10, PYTHON, MV),
        ran(12, 11, CMD, "cmd /c dir"),
        ran(13, 11, CMD, "cmd /c ver"),
        ran(14, 10, PYTHON, REMOVE),
        ran(15, 14, CMD, "cmd /c dir"),
    ];
    let assignment = assign_split(
        &log(instances.clone()),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON)],
    );
    assert_eq!(
        shape_of(&assignment),
        vec![
            pos(1, ENTRY_DOMAIN, PYTHON, "python-mv", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, PYTHON, "python-remove", PositionSource::Proposed),
            pos(2, "python-mv", CMD, "cmd", PositionSource::Proposed),
            pos(2, "python-remove", CMD, "cmd-2", PositionSource::Proposed),
        ]
    );
    let nested = assign_split(
        &log(instances),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON), ("python-mv", CMD)],
    );
    let under_mv: Vec<(String, Option<String>)> = nested
        .positions
        .iter()
        .filter(|p| p.from_domain == "python-mv")
        .map(|p| (p.to_domain.clone(), p.fixed_command_line.clone()))
        .collect();
    assert_eq!(
        under_mv,
        vec![
            ("cmd".to_string(), Some("cmd /c dir".to_string())),
            ("cmd-2".to_string(), Some("cmd /c ver".to_string())),
        ]
    );
    // 対の側: python-remove の下の cmd は分けていない。
    assert!(nested
        .positions
        .iter()
        .any(|p| p.from_domain == "python-remove" && p.fixed_command_line.is_none()));
}

/// **書いた後の記録では、分けた辺は既にある辺として引かれる**（判定器のリテラルの辺。分ける集合を渡さなくてよい）。
/// 記録に無い新しいコマンドラインだけが新しい位置になる。
#[test]
fn split_edges_once_written_are_found_as_existing_edges() {
    let split = assign_split(&log(two_scripts()), &PolicyFile::default(), &[(ENTRY_DOMAIN, PYTHON)]);
    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &split);

    let mut next = two_scripts();
    next.push(ran(13, 10, PYTHON, r"python C:\tools\other.py"));
    let again = assign(&log(next), &policy);
    assert_eq!(
        shape_of(&again),
        vec![
            pos(1, ENTRY_DOMAIN, PYTHON, "python", PositionSource::Proposed),
            pos(1, ENTRY_DOMAIN, PYTHON, "python-mv", PositionSource::ExistingEdge),
            pos(1, ENTRY_DOMAIN, PYTHON, "python-remove", PositionSource::ExistingEdge),
        ]
    );
    assert_eq!(again.positions[0].instances, vec![13]);
}

/// **相対パスの引数を持つ分けた辺は、作業ディレクトリを宣言しないと検査に落ちる**（規則(d)、`plans/DESIGN-MAC.md`
/// §5.1(5)）。割り当ては作業ディレクトリを決めない（記録に無い）——エディタが`with_cwd`で宣言すると通る。
#[test]
fn a_split_edge_with_a_relative_argument_needs_a_declared_cwd() {
    let assignment = assign_split(
        &log(vec![root(10, CMD), ran(11, 10, PYTHON, "python mv.py test.txt")]),
        &PolicyFile::default(),
        &[(ENTRY_DOMAIN, PYTHON)],
    );
    assert_eq!(assignment.positions[0].to_domain, "python-mv");
    let mut policy = PolicyFile::default();
    write_proposals(&mut policy, &assignment);
    let input = policy.transition_graph_input(Some(WS), &[]);
    let rejections = crate::transition::check_all(&input).expect("外形は壊れていない");
    assert_eq!(rejections.len(), 1);
    assert!(rejections[0].reason.contains("relative path"), "{rejections:?}");

    // 対の側: 作業ディレクトリを宣言すると通る。
    let edge = &mut policy
        .domains
        .iter_mut()
        .find(|d| d.name == ENTRY_DOMAIN)
        .expect("入口")
        .process
        .transitions[0];
    *edge = edge.clone().with_cwd(Some(r"C:\tools".to_string()));
    let input = policy.transition_graph_input(Some(WS), &[]);
    assert_eq!(crate::transition::check_all(&input).expect("外形"), vec![]);
}

/// コマンドラインの中のスクリプト（名前と、エディタの作業ディレクトリの候補が同じこれを通る）: `argv[0]`の後ろで、
/// 拡張子が`harness_core::SCRIPT_EXTENSIONS`のどれかである最初の語。引用符は外す。絶対パスかどうかを持つ。
#[test]
fn the_script_argument_is_the_first_word_after_argv0_with_a_script_extension() {
    let script = |line: &str| script_argument(line).map(|s| (s.token, s.absolute));
    assert_eq!(
        script(r#"python "C:\My Tools\a.py" b.py"#),
        Some((r"C:\My Tools\a.py".to_string(), true))
    );
    assert_eq!(
        script("powershell.exe -File run.PS1"),
        Some(("run.PS1".to_string(), false))
    );
    // argv[0] は数えない（呼び出し元が書いた綴りそのもの）。
    assert_eq!(script(r"C:\tools\x.py --flag"), None);
    assert_eq!(script("python -c print(1)"), None);
    assert_eq!(script(""), None);
}
