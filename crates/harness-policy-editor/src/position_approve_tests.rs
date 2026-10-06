//! 位置ごとのドメインの確定（[`plan`]・[`commit`]）の単体試験（P4.5）。
//!
//! **書く前に断ったら`policy.json`が1バイトも変わらない**ことと、**通った確定は1回の保存で全部のドメインを書き、
//! 保存の後にだけ承認台帳へ記録する**ことを固定する。台帳は試験ごとの一時ファイル（`approval_store`のdoc）で、
//! 実マシンの台帳は触らない。保存の回数は`commit`へ渡す保存の関数で数える（`plans/position-domains/P4.md`の
//! 前例の表の11）。
//!
//! データのパスは`C:/Users/x/...`の架空の場所（`C:/Windows`・`C:/Program Files`は既定で実行できる場所として
//! 候補から外れる。D-58）。

use harness_policy::transition::ChildOutput;
use std::cell::Cell;
use std::path::Path;

use harness_config::FsAccess;
use harness_policy::generalize::SettingsKey;
use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};
use harness_policy::RuleProposal;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use super::*;
use crate::position_view::position_view_tests::{CALC, PWSH};
use crate::transition_approve::TransitionApproveError;

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn proposal(id: &str, key: SettingsKey, value: &str) -> RuleProposal {
    RuleProposal {
        id: id.to_string(),
        key,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }
}

/// `domain`へ`proposals`を全部承認する選択。
fn select(domain: &str, proposals: Vec<RuleProposal>) -> DomainSelection {
    DomainSelection {
        domain: domain.to_string(),
        accept_ids: proposals.iter().map(|p| p.id.clone()).collect(),
        proposals,
    }
}

/// `from`から`exe`（任意の引数）を起こすと`to`へ移る辺（エディタが書く形）。
fn edge(from: &str, exe: &str, to: &str) -> EdgeWrite {
    EdgeWrite {
        from_domain: from.to_string(),
        edge: editor_edge(exe, ArgvMatcher::Any(AnyMarker), to),
        replaces_self_loop: false,
    }
}

fn request(ws: &Path, fs: Vec<DomainSelection>, edges: Vec<EdgeWrite>) -> PositionRequest<'_> {
    PositionRequest {
        workspace_root: ws,
        require_sandbox: harness_core::RequireSandbox::None,
        command: Some("cmd /c pwsh"),
        cwd: Some(ws),
        record_session: Some("s1"),
        now_unix_ms: 1_700_000_000_000,
        fs,
        edges,
        remove_edges: Vec::new(),
        unapprove: Vec::new(),
        replace_self_loops: false,
    }
}

/// `policy.json`にドメインを足して保存する（`save`は検査に通るものしか書かない）。
fn seed(ws: &Path, domains: Vec<PolicyDomain>) {
    let mut file = PolicyFile {
        domains,
        ..PolicyFile::default()
    };
    file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    policy_file::save(ws, &file).expect("setup");
}

fn domain_reading(name: &str, value: &str) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.fs.read.push(value.to_string());
    domain
}

/// `policy.json`のバイト列（無ければ`None`）。
fn bytes(ws: &Path) -> Option<Vec<u8>> {
    std::fs::read(policy_file::path(ws)).ok()
}

fn approved(ws: &Path, domain: &str, value: &str) -> bool {
    crate::approval_store::approval_store().load().is_approved(
        ws,
        DeclarationRef {
            domain,
            value,
            access: FsAccess::Read,
        },
    )
}

/// 3つのドメインのファイルの宣言（呼び出し元が子の届く範囲を覆う＝どの辺も狭める向き）と辺2本。
/// `pwsh`は自分の`p.txt`と、子の`calc`が読む`c.txt`を持つ（狭めるかは直接の呼び出し元と比べる）。
fn three_domains(ws: &Path) -> PositionRequest<'_> {
    request(
        ws,
        vec![
            select(
                ENTRY_DOMAIN,
                vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/proj/**")],
            ),
            select(
                "pwsh",
                vec![
                    proposal("fs-2", SettingsKey::FsRead, "C:/Users/x/proj/p.txt"),
                    proposal("fs-4", SettingsKey::FsRead, "C:/Users/x/proj/c.txt"),
                ],
            ),
            select(
                "calc",
                vec![proposal(
                    "fs-3",
                    SettingsKey::FsRead,
                    "C:/Users/x/proj/c.txt",
                )],
            ),
        ],
        vec![edge(ENTRY_DOMAIN, PWSH, "pwsh"), edge("pwsh", CALC, "calc")],
    )
}

/// **広がる辺も書ける**（決定66。守る線は子のドメインの権限）。書ける辺・ファイルの宣言と一緒に1回で書き、確認の明細に
/// 「広がる遷移N本」と、その辺で呼び出し元が子を通して使えるようになる権限が出る（狭める辺は出ない）。
///
/// 対の側（禁止側）: **書けない辺が1本でもあれば全体を断る**（部分適用しない）——いま書けない辺を作るのは Strict の印
/// （このエディタは入力を固定した辺を書かない）。書ける辺とファイルの宣言が一緒でも何も書かず、`policy.json`は
/// 1バイトも変わらない。
#[test]
fn a_widening_edge_is_written_and_the_confirmation_lists_what_it_hands_over() {
    let fs = || {
        vec![select(
            ENTRY_DOMAIN,
            vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/a.txt")],
        )]
    };
    let edges = || {
        vec![
            edge(ENTRY_DOMAIN, CALC, "calc"),
            edge(ENTRY_DOMAIN, "C:/Users/x/tools/peek.exe", "secret"),
        ]
    };

    // 禁止側: 遷移先 secret に Strict の印。
    let ws = workspace();
    let mut strict = domain_reading("secret", "C:/Users/x/secret/**");
    strict.strict = true;
    seed(ws.path(), vec![strict]);
    let before = bytes(ws.path());
    match plan(&request(ws.path(), fs(), edges())) {
        Err(PositionApproveError::Transition(TransitionApproveError::Rejected(detail))) => {
            assert!(detail.contains("is strict"), "{detail}")
        }
        other => panic!("Strict のドメインへの辺が全体を断っていない: {other:?}"),
    }
    assert_eq!(
        bytes(ws.path()),
        before,
        "断った確定で policy.json が変わった"
    );

    // 許可側: 印が無ければ、広げる辺も一緒に書ける。
    let ws = workspace();
    seed(
        ws.path(),
        vec![domain_reading("secret", "C:/Users/x/secret/**")],
    );
    let ok = plan(&request(ws.path(), fs(), edges())).expect("広げる辺が断られた");
    assert_eq!(ok.widening.edges.len(), 1, "{:?}", ok.widening);
    assert_eq!(ok.widening.edges[0].to, "secret");
    assert_eq!(
        ok.widening.edges[0].newly_usable.fs,
        vec![("C:/Users/x/secret/**".to_string(), "read")]
    );
    let lines = confirmation_lines(ws.path(), &ok, &BTreeSet::new()).join("\n");
    assert!(lines.contains("広がる遷移 1本"), "{lines}");
    assert!(lines.contains("C:/Users/x/secret/**"), "{lines}");
    assert!(!lines.contains("→ calc（"), "狭める辺まで広がる遷移に出た: {lines}");
    assert!(commit(ws.path(), &ok, &policy_file::save).expect("書けるはず"));
    let file = policy_file::load(ws.path()).expect("load");
    let entry = file.domain(ENTRY_DOMAIN).expect("入口のドメイン");
    assert_eq!(entry.fs.read, vec!["C:/Users/x/a.txt".to_string()]);
    assert_eq!(entry.process.transitions.len(), 2);
}

/// **1回の確定は、何ドメイン分でも`save`をちょうど1回だけ呼ぶ**（別々に書くと片方だけ書けた状態が残る）。
/// 読み直した`policy.json`に3ドメインのファイルの宣言と辺2本が全部ある。
/// 対の側: 書くものが無い確定（既にある宣言だけ）では`save`を呼ばない。
#[test]
fn one_confirmation_writes_every_domain_with_one_save() {
    let ws = workspace();
    let saves = Cell::new(0usize);
    let counting = |root: &Path, file: &PolicyFile| {
        saves.set(saves.get() + 1);
        policy_file::save(root, file)
    };

    let plan_ = plan(&three_domains(ws.path())).expect("plan");
    assert!(commit(ws.path(), &plan_, &counting).expect("commit"));
    assert_eq!(saves.get(), 1, "保存は1回だけのはず");

    let file = policy_file::load(ws.path()).expect("load");
    let read = |name: &str| {
        file.domain(name)
            .map(|d| d.fs.read.clone())
            .unwrap_or_default()
    };
    assert_eq!(read(ENTRY_DOMAIN), vec!["C:/Users/x/proj/**".to_string()]);
    assert_eq!(
        read("pwsh"),
        vec![
            "C:/Users/x/proj/c.txt".to_string(),
            "C:/Users/x/proj/p.txt".to_string()
        ]
    );
    assert_eq!(read("calc"), vec!["C:/Users/x/proj/c.txt".to_string()]);
    let to = |name: &str| -> Vec<String> {
        file.domain(name)
            .map(|d| d.process.transitions.iter().map(|e| e.to.clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(to(ENTRY_DOMAIN), vec!["pwsh".to_string()]);
    assert_eq!(to("pwsh"), vec!["calc".to_string()]);

    // 対の側: もう全部ある。書くものが無いので保存しない。
    let again = plan(&request(
        ws.path(),
        vec![select(
            ENTRY_DOMAIN,
            vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/proj/**")],
        )],
        Vec::new(),
    ))
    .expect("plan");
    assert!(again.is_empty(), "{again:?}");
    assert!(!commit(ws.path(), &again, &counting).expect("commit"));
    assert_eq!(saves.get(), 1, "書くものが無いのに保存した");
}

/// **通った確定の後、承認台帳に全ドメイン分の宣言がそれぞれのドメイン名で載る**（D-112。台帳は保存の後）。
/// 対の側: 保存が落ちたら台帳は変わらない（保存の前に記録すると、無い宣言の承認が残る）。
#[test]
fn the_ledger_records_every_domain_after_save() {
    let failed = workspace();
    let plan_ = plan(&three_domains(failed.path())).expect("plan");
    let refusing = |_: &Path, _: &PolicyFile| -> Result<(), policy_file::PolicyFileError> {
        Err(policy_file::PolicyFileError::Write {
            path: policy_file::path(failed.path()),
            source: std::io::Error::other("書けない（試験）"),
        })
    };
    assert!(matches!(
        commit(failed.path(), &plan_, &refusing),
        Err(PositionApproveError::PolicyFile(_))
    ));
    assert!(!approved(failed.path(), ENTRY_DOMAIN, "C:/Users/x/proj/**"));
    assert!(!approved(failed.path(), "pwsh", "C:/Users/x/proj/p.txt"));
    assert!(!approved(failed.path(), "calc", "C:/Users/x/proj/c.txt"));

    let ws = workspace();
    let plan_ = plan(&three_domains(ws.path())).expect("plan");
    commit(ws.path(), &plan_, &policy_file::save).expect("commit");
    assert!(approved(ws.path(), ENTRY_DOMAIN, "C:/Users/x/proj/**"));
    assert!(approved(ws.path(), "pwsh", "C:/Users/x/proj/p.txt"));
    assert!(approved(ws.path(), "calc", "C:/Users/x/proj/c.txt"));
    // ドメインを取り違えていない（ある値を別のドメインの承認として載せていない）。
    assert!(!approved(ws.path(), "pwsh", "C:/Users/x/proj/**"));
    assert!(!approved(ws.path(), "calc", "C:/Users/x/proj/p.txt"));
}

/// **同じ確定で取り消した宣言は、このマシンの承認も台帳から消える**（`unapprove::commit`と同じ。`B-01`）。
#[test]
fn unapproving_in_the_same_confirmation_revokes_the_ledger() {
    let ws = workspace();
    let first = plan(&three_domains(ws.path())).expect("plan");
    commit(ws.path(), &first, &policy_file::save).expect("commit");
    assert!(approved(ws.path(), "calc", "C:/Users/x/proj/c.txt"));

    let mut req = request(ws.path(), Vec::new(), Vec::new());
    req.unapprove = vec![crate::unapprove::UnapproveTarget {
        domain: "calc".to_string(),
        key: SettingsKey::FsRead,
        value: "C:/Users/x/proj/c.txt".to_string(),
    }];
    let second = plan(&req).expect("plan");
    assert_eq!(second.unapproved.len(), 1);
    assert!(commit(ws.path(), &second, &policy_file::save).expect("commit"));
    let file = policy_file::load(ws.path()).expect("load");
    assert!(file.domain("calc").unwrap().fs.read.is_empty());
    assert!(!approved(ws.path(), "calc", "C:/Users/x/proj/c.txt"));
    assert!(
        approved(ws.path(), "pwsh", "C:/Users/x/proj/p.txt"),
        "他の承認まで消した"
    );
}

fn self_loop(exe: ExeMatcher) -> TransitionEdge {
    TransitionEdge {
        exe,
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: ENTRY_DOMAIN.to_string(),
        env: None,
        output: ChildOutput::Return,
    }
}

/// **エディタが前に書いた自己ループ辺は、ユーザーが確認の画面で読んで`y`を押したときだけ置き換える**（決定65 Q7・D-42）。
/// 確認していない要求は何も書かずに断り、確認した要求は自己ループ辺を取り除いてから位置の辺を足す（取り除かないと同じ
/// 実行ファイルに2本当たる）。対の側: 自己ループ辺がパターンなら置き換えない（この記録に無いプログラムも起こせなくなる）。
#[test]
fn a_self_loop_is_replaced_only_when_confirmed() {
    let ws = workspace();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(self_loop(ExeMatcher::Literal(PWSH.to_string())));
    seed(ws.path(), vec![entry]);
    let before = bytes(ws.path());
    let replacing = || {
        let mut write = edge(ENTRY_DOMAIN, PWSH, "pwsh");
        write.replaces_self_loop = true;
        request(ws.path(), Vec::new(), vec![write])
    };

    match plan(&replacing()) {
        Err(PositionApproveError::SelfLoopNeedsConfirmation { from }) => {
            assert_eq!(from, ENTRY_DOMAIN)
        }
        other => panic!("確認していない置き換えが通った: {other:?}"),
    }
    assert_eq!(bytes(ws.path()), before);

    let mut confirmed = replacing();
    confirmed.replace_self_loops = true;
    let plan_ = plan(&confirmed).expect("確認した置き換えは通るはず");
    assert_eq!(
        plan_.self_loops_replaced,
        vec![(
            ENTRY_DOMAIN.to_string(),
            self_loop(ExeMatcher::Literal(PWSH.to_string()))
        )]
    );
    assert!(commit(ws.path(), &plan_, &policy_file::save).expect("commit"));
    let file = policy_file::load(ws.path()).expect("load");
    let edges = &file.domain(ENTRY_DOMAIN).unwrap().process.transitions;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_eq!(edges[0].to, "pwsh");

    // 対の側: パターンの自己ループ辺は置き換えない。
    let other = workspace();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(self_loop(ExeMatcher::Pattern(
            "c:/program files/.*".to_string(),
        )));
    seed(other.path(), vec![entry]);
    let mut write = edge(ENTRY_DOMAIN, PWSH, "pwsh");
    write.replaces_self_loop = true;
    let mut req = request(other.path(), Vec::new(), vec![write]);
    req.replace_self_loops = true;
    match plan(&req) {
        Err(PositionApproveError::PatternSelfLoop { from }) => assert_eq!(from, ENTRY_DOMAIN),
        other => panic!("パターンの自己ループ辺を置き換えた: {other:?}"),
    }
}

/// **書いた後の宣言で、足した辺の起動が辺の遷移先に着かないなら断る**（既にあるパターンの辺と重なって判定器が
/// 曖昧と答える。P3b の注意2）。対の側: パターンの辺が無ければ通る。
#[test]
fn an_edge_that_resolves_elsewhere_after_writing_is_refused() {
    let ws = workspace();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions.push(TransitionEdge {
        // 照合は畳んだ（小文字の）綴りへの正規表現（`harness_policy::transition`）。
        exe: ExeMatcher::Pattern(r"c:/users/x/tools/.*\.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: "tools".to_string(),
        env: None,
        output: ChildOutput::Return,
    });
    seed(ws.path(), vec![entry, PolicyDomain::new("tools")]);
    let before = bytes(ws.path());

    match plan(&request(
        ws.path(),
        Vec::new(),
        vec![edge(ENTRY_DOMAIN, "C:/Users/x/tools/a.exe", "a")],
    )) {
        Err(PositionApproveError::ResolvesElsewhere { from, exe, .. }) => {
            assert_eq!(from, ENTRY_DOMAIN);
            assert_eq!(exe, "C:/Users/x/tools/a.exe");
        }
        other => panic!("重なる辺が通った: {other:?}"),
    }
    assert_eq!(bytes(ws.path()), before);

    let clean = workspace();
    plan(&request(
        clean.path(),
        Vec::new(),
        vec![edge(ENTRY_DOMAIN, "C:/Users/x/tools/a.exe", "a")],
    ))
    .expect("パターンの辺が無ければ通るはず");
}

/// **そこへ届く辺がこの確定にも`policy.json`にも無いドメインへは、ファイルの宣言を書かない**（届かないドメインの
/// 宣言は誰にも使われず、承認だけが残る）。対の側: そのドメインが既に`policy.json`にあれば書ける。
#[test]
fn fs_for_a_domain_without_an_edge_is_refused() {
    let ws = workspace();
    let fs = || {
        vec![select(
            "pwsh",
            vec![proposal("fs-2", SettingsKey::FsRead, "C:/Users/x/b.txt")],
        )]
    };
    match plan(&request(ws.path(), fs(), Vec::new())) {
        Err(PositionApproveError::MissingEdgeForDomain { domain }) => assert_eq!(domain, "pwsh"),
        other => panic!("届かないドメインへ書いた: {other:?}"),
    }
    assert!(bytes(ws.path()).is_none());

    seed(ws.path(), vec![PolicyDomain::new("pwsh")]);
    let ok = plan(&request(ws.path(), fs(), Vec::new())).expect("既にあるドメインには書けるはず");
    assert!(commit(ws.path(), &ok, &policy_file::save).expect("commit"));
}

/// **CLI の`approve`は、位置の情報がある記録では候補ごとのドメインへファイルの宣言だけを書く**（前例の表の12）。
/// 番号は画面と同じ（同じ`position_candidates::from_session`を通る）。`--domain`を付けたら断る。
/// 対の側: まだ`policy.json`に無いドメイン（辺が要る）の候補は「TUI（F2）で遷移と一緒に」と言って断る。
#[test]
fn the_cli_approves_a_position_record_into_each_candidates_domain() {
    use crate::position_candidates::position_candidates_tests::{fs_event, write_fs_events};
    use crate::position_view::position_view_tests::{seed_position_record, user_example, CMD};

    let ws = crate::position_view::position_view_tests::workspace();
    // 入口のドメインが子の分を覆い、`pwsh`は既にある（入口のドメインからの辺つき）。`calc`はまだ無い。
    let mut entry = domain_reading(ENTRY_DOMAIN, "C:/Users/x/**");
    entry
        .process
        .transitions
        .push(editor_edge(PWSH, ArgvMatcher::Any(AnyMarker), "pwsh"));
    seed(ws.path(), vec![entry, PolicyDomain::new("pwsh")]);
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    write_fs_events(
        &dir,
        &[
            fs_event("C:/Users/x/a.txt", Some(1), CMD),
            fs_event("C:/Users/x/b.txt", Some(2), PWSH),
            fs_event("C:/Users/x/c.txt", Some(3), CALC),
        ],
    );
    let candidates = crate::position_candidates::load(&dir, &manifest, ws.path());
    assert!(candidates.by_position());
    let id_of = |value: &str| -> (String, Option<String>) {
        let index = candidates
            .proposals
            .iter()
            .position(|p| p.value == value)
            .expect("候補");
        (
            candidates.proposals[index].id.clone(),
            candidates.domains[index].clone(),
        )
    };
    let (a, a_domain) = id_of("C:/Users/x/a.txt");
    let (b, b_domain) = id_of("C:/Users/x/b.txt");
    let (c, _) = id_of("C:/Users/x/c.txt");
    assert_eq!(a_domain.as_deref(), Some(ENTRY_DOMAIN));
    assert_eq!(b_domain.as_deref(), Some("pwsh"));
    let none = harness_core::RequireSandbox::None;

    match cli_plan(
        ws.path(),
        &manifest,
        &candidates,
        std::slice::from_ref(&a),
        Some("cmd"),
        none,
        1,
    ) {
        Err(PositionApproveError::DomainFlagWithPositions) => {}
        other => panic!("--domain を断っていない: {other:?}"),
    }
    match cli_plan(
        ws.path(),
        &manifest,
        &candidates,
        &[a.clone(), c.clone()],
        None,
        none,
        1,
    ) {
        Err(e @ PositionApproveError::NeedsTransition { .. }) => {
            assert!(e.to_string().contains("TUI（F2）"), "{e}");
            assert!(e.to_string().contains("calc"), "{e}");
        }
        other => panic!("辺が要る候補を CLI で書いた: {other:?}"),
    }

    let plan_ = cli_plan(ws.path(), &manifest, &candidates, &[a, b], None, none, 1).expect("plan");
    assert!(plan_.edges_added.is_empty(), "CLI は辺を書かない");
    assert!(commit(ws.path(), &plan_, &policy_file::save).expect("commit"));
    let file = policy_file::load(ws.path()).expect("load");
    assert!(file
        .domain(ENTRY_DOMAIN)
        .unwrap()
        .fs
        .read
        .contains(&"C:/Users/x/a.txt".to_string()));
    assert_eq!(
        file.domain("pwsh").unwrap().fs.read,
        vec!["C:/Users/x/b.txt".to_string()]
    );
    assert!(file.domain("calc").is_none());
    assert!(approved(ws.path(), "pwsh", "C:/Users/x/b.txt"));
}
