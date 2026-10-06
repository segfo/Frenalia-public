//! [段階⑦] 遷移の承認・取り消しの単体テスト。
//!
//! **端末もWin32も要らない**（`cargo test -p harness-policy-editor`に入る）。
//! 実際に`policy.json`をtempdirへ書いて読み直すので、**書いたものが読めること**まで測る。

use harness_policy::transition::ChildOutput;
use super::*;

use harness_policy::policy_file::ENTRY_DOMAIN;
use harness_policy::transition_listing;

fn any(exe: &str) -> EdgeRef {
    EdgeRef {
        exe: exe.to_string(),
        argv: ArgvChoice::Any,
    }
}

fn literal(exe: &str, argv: &str) -> EdgeRef {
    EdgeRef {
        exe: exe.to_string(),
        argv: ArgvChoice::Literal(argv.to_string()),
    }
}

/// 承認・取り消しの要求（遷移先は[`CHILD`]。自己ループ辺は凍結中で書けない）。
fn request<'a>(
    ws: &'a Path,
    approve: &'a [EdgeRef],
    remove: &'a [EdgeRef],
) -> TransitionRequest<'a> {
    request_to(ws, CHILD, approve, remove)
}

/// 遷移先を選んだ要求（[`request`]は[`CHILD`]へ向ける）。
fn request_to<'a>(
    ws: &'a Path,
    to_domain: &'a str,
    approve: &'a [EdgeRef],
    remove: &'a [EdgeRef],
) -> TransitionRequest<'a> {
    TransitionRequest {
        workspace_root: ws,
        from_domain: ENTRY_DOMAIN,
        to_domain,
        approve,
        remove,
        record_session: Some("session-1"),
        now_unix_ms: 1_700_000_000_000,
    }
}

/// 一覧を作る（別ドメインの用意は「何も用意されていない」で渡す——ここで見るのは辺の形だけ）。
fn listed(ws: &Path) -> Vec<transition_listing::Row> {
    let file = policy_file::load(ws).expect("書いたものが読めない");
    let ws_text = ws.to_string_lossy().into_owned();
    let input = file.transition_graph_input(Some(&ws_text), &[]);
    transition_listing::rows(&input, ENTRY_DOMAIN, &Default::default()).expect("一覧が作れない")
}

/// 承認して書き、**読み直して同じ辺が出る**ところまで見る。
///
/// 読み直しは`policy_file::load`を通るので、**編集時検査も一緒に掛かっている**。
fn approve_and_reload(ws: &Path, edges: &[EdgeRef]) -> Vec<transition_listing::Row> {
    let plan = plan(&request(ws, edges, &[])).expect("承認できない");
    assert!(
        commit(ws, &plan).expect("書けない"),
        "書く必要が無いと判定された"
    );
    listed(ws)
}

/// 試験で使う遷移先（宣言の無いドメイン。呼び出し元より狭いので検査を通る）。
///
/// **自己ループ辺は書けない**（決定65(3)で凍結）ので、承認する試験はこのドメインへ向ける。
const CHILD: &str = "child";

/// **禁止側**: 遷移先が遷移元と同じ（自己ループ辺）なら、**書く前に**断る。
///
/// 自己ループ辺は深さを区別しなくなる書き方で、ユーザーの明示操作として設計するまで凍結している
/// （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65(3)）。既に`policy.json`があっても1バイトも変えない。
#[test]
fn a_self_loop_is_refused_before_writing() {
    let tmp = tempfile::tempdir().unwrap();
    declare_domain_with_read(tmp.path(), ENTRY_DOMAIN, "C:/x/**");
    let before = std::fs::read(policy_file::path(tmp.path())).unwrap();

    match plan(&request_to(tmp.path(), ENTRY_DOMAIN, &[any("C:/git.exe")], &[])) {
        Err(TransitionApproveError::SelfLoopFrozen { domain }) => {
            assert_eq!(domain, ENTRY_DOMAIN)
        }
        other => panic!("自己ループ辺が断られなかった: {other:?}"),
    }
    assert_eq!(
        std::fs::read(policy_file::path(tmp.path())).unwrap(),
        before,
        "断ったのにpolicy.jsonが変わった"
    );
}

/// **対の側**（`B-01`）: 手で書いた自己ループ辺は、凍結の後も取り消せる。
///
/// 書くのを止めて消すのまで止めると、凍結前に書かれた自己ループ辺を手でJSONを編集しないと外せなくなる。
#[test]
fn an_existing_self_loop_can_still_be_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut file = policy_file::PolicyFile::default();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions.push(TransitionEdge {
        exe: ExeMatcher::Literal("C:/git.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: ENTRY_DOMAIN.to_string(),
        env: None,
        output: ChildOutput::Return,
    });
    file.domains.push(entry);
    policy_file::save(tmp.path(), &file).expect("手で書いた自己ループ辺が保存できない");

    // 遷移先の欄が呼び出し元のままでも、取り消しだけの確定は遷移先を使わないので通る。
    let plan = plan(&request_to(tmp.path(), ENTRY_DOMAIN, &[], &[any("C:/git.exe")]))
        .expect("自己ループ辺を取り消せない");
    assert_eq!(plan.removed, vec![any("C:/git.exe")]);
    assert!(commit(tmp.path(), &plan).expect("書けない"));
    assert!(listed(tmp.path()).is_empty(), "取り消したのに自己ループ辺が残っている");
}

// --- 承認 -------------------------------------------------------------------

/// 承認した辺が`policy.json`へ届き、**モデルが見るのと同じ一覧**に出る。
#[test]
fn an_approved_edge_shows_up_in_the_same_listing_the_model_sees() {
    let tmp = tempfile::tempdir().unwrap();
    let rows = approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].exe, "C:/git.exe");
    assert!(
        !rows[0].exe_is_pattern,
        "観測の綴りがパターンとして書かれている"
    );
    assert_eq!(rows[0].argv, transition_listing::ANY_ARGV);
    assert_eq!(rows[0].to_domain, CHILD);
}

/// [2026-10-01] **別のドメインへの遷移が書ける**（§10.1.2の撤去一覧6つ目を外した）。
///
/// `policy.json`に無い遷移先は**宣言の無いドメインとして作り**、作ったことを返す
/// （編集時検査は宣言されていないドメインへの遷移を断るので、作らないと書けない）。
/// 宣言の無い遷移先は呼び出し元より狭いので、作業ディレクトリを固定しない辺でも検査を通る。
#[test]
fn an_edge_to_another_domain_is_written_and_a_missing_destination_is_created_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan(&request_to(tmp.path(), "iso", &[any("C:/curl.exe")], &[])).expect("承認できない");
    assert_eq!(plan.to_domain, "iso");
    assert!(plan.created_to_domain, "作ったのに作ったと言っていない（B-09）");
    assert!(commit(tmp.path(), &plan).expect("書けない"));

    let rows = listed(tmp.path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].to_domain, "iso", "選んだ遷移先ではなく別の値が書かれた");
    let file = policy_file::load(tmp.path()).unwrap();
    let iso = file.domain("iso").expect("遷移先のドメインが作られていない");
    assert!(iso.fs.entries().is_empty() && iso.net.allow_domains.is_empty());

    // 2本目は既にある遷移先へ書くので、作り直さない。
    let again =
        super::plan(&request_to(tmp.path(), "iso", &[any("C:/wget.exe")], &[])).expect("2本目が落ちた");
    assert!(!again.created_to_domain);
}

/// 取り消しだけ・既にある辺だけの確定では、**遷移先のドメインを作らない**（見覚えの無い空のドメインを増やさない）。
#[test]
fn a_destination_is_not_created_when_no_edge_is_added() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let plan = plan(&request_to(tmp.path(), "never", &[any("C:/git.exe")], &[])).expect("plan");
    assert!(plan.added.is_empty());
    assert!(!plan.created_to_domain);
    assert!(plan.file.domain("never").is_none());
}

/// 遷移先にファイル宣言を1つ持たせて書く（手で書いたのと同じ形。`save`は検査を通るものしか書かない）。
fn declare_domain_with_read(ws: &Path, name: &str, value: &str) {
    let mut file = policy_file::load(ws).unwrap();
    let mut domain = PolicyDomain::new(name);
    domain.fs.read.push(value.to_string());
    file.domains.push(domain);
    policy_file::save(ws, &file).expect("setup");
}

/// **許可側**: 遷移先が呼び出し元より広い権限に届く遷移（広げる遷移）も、入力を固定せずに書ける（決定66。守る線は
/// 子のドメインの権限）。書くと呼び出し元が子を通して何を使えるようになるかは、確定の明細と同じ部品
/// （[`crate::exposure_view::widening`]）で列挙できる。
#[test]
fn a_widening_destination_can_be_written_and_what_it_hands_over_is_listed() {
    let tmp = tempfile::tempdir().unwrap();
    declare_domain_with_read(tmp.path(), "wide", "C:/secrets/**");
    let before = policy_file::load(tmp.path()).unwrap();

    let plan = plan(&request_to(tmp.path(), "wide", &[any("C:/curl.exe")], &[]))
        .expect("広げる遷移が断られた");
    let widening = crate::exposure_view::widening(&before, &plan.file, tmp.path());
    assert_eq!(widening.edges.len(), 1, "{widening:?}");
    assert_eq!(widening.edges[0].to, "wide");
    assert_eq!(
        widening.edges[0].newly_usable.fs,
        vec![("C:/secrets/**".to_string(), "read")]
    );
    assert!(commit(tmp.path(), &plan).expect("書けない"));
    assert_eq!(listed(tmp.path())[0].to_domain, "wide");
}

/// **禁止側（対）**: 遷移先に Strict の印があれば、入る辺は引数と作業ディレクトリを固定しなければ書けない（決定66の
/// 追記）。このエディタは作業ディレクトリを宣言しない（[`edge_for`]）ので書けず、検査の理由をそのまま出して何も書かない。
#[test]
fn a_strict_destination_is_refused_because_this_editor_does_not_fix_inputs() {
    let tmp = tempfile::tempdir().unwrap();
    declare_domain_with_read(tmp.path(), "wide", "C:/secrets/**");
    let mut file = policy_file::load(tmp.path()).unwrap();
    file.domains.iter_mut().find(|d| d.name == "wide").unwrap().strict = true;
    policy_file::save(tmp.path(), &file).expect("setup");
    let before = std::fs::read_to_string(policy_file::path(tmp.path())).unwrap();

    match plan(&request_to(tmp.path(), "wide", &[any("C:/curl.exe")], &[])) {
        Err(TransitionApproveError::Rejected(detail)) => {
            assert!(detail.contains("is strict"), "検査の理由が落ちている: {detail}");
            // [P5.5] このエディタで取れる直し方で先に言い直す（検査の英文は「cwd を宣言せよ」で、この画面では取れない）。
            assert!(
                detail.contains("遷移先「wide」は Strict です") && detail.contains("Strict を外す"),
                "直し方を言っていない: {detail}"
            );
        }
        other => panic!("Strict のドメインへの辺が別の形で返った: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(policy_file::path(tmp.path())).unwrap(),
        before,
        "planが書いた"
    );
}

/// **許可側（対）**: 遷移先の宣言が呼び出し元の宣言の範囲に収まる（狭める）なら書ける。
/// 「別ドメインは全部断る」実装でも禁止側は緑になるので、対にする（`B-35`）。
#[test]
fn a_narrowing_destination_with_declarations_can_be_written() {
    let tmp = tempfile::tempdir().unwrap();
    declare_domain_with_read(tmp.path(), ENTRY_DOMAIN, "C:/secrets/**");
    declare_domain_with_read(tmp.path(), "narrow", "C:/secrets/a.txt");

    let plan = plan(&request_to(tmp.path(), "narrow", &[any("C:/curl.exe")], &[]))
        .expect("狭める遷移が断られた");
    assert!(commit(tmp.path(), &plan).expect("書けない"));
    assert_eq!(listed(tmp.path())[0].to_domain, "narrow");
}

/// **禁止側**: 入れ物（AppContainerプロファイル）の名前にできない遷移先は、**書く前に**断る。
///
/// 編集時検査は50文字で通すが、`harness.exe`はセッションの印を足した名前で入れ物を作るので、
/// 長い名前は起動時に用意できない（`harness_sandbox::tier2a::domain_profile_name_problem`のdoc）。`.`を含む名前はここに入らない
/// ——持ち主の判定が最初の`.`で切るようになって通る（BUG-189。許可側は`harness-sandbox`の`tier2a::domain_profile`の試験）。
#[test]
fn a_destination_that_cannot_become_a_profile_name_is_refused_before_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let too_long = "x".repeat(40);
    for bad in ["a/b", too_long.as_str(), "bad name", ""] {
        match plan(&request_to(tmp.path(), bad, &[any("C:/curl.exe")], &[])) {
            Err(TransitionApproveError::DestinationName { to_domain, .. }) => {
                assert_eq!(to_domain, bad)
            }
            other => panic!("{bad:?} が断られなかった: {other:?}"),
        }
    }
    assert!(
        !policy_file::path(tmp.path()).exists(),
        "断ったのにpolicy.jsonを書いた"
    );
}

/// 取り消しだけの確定は遷移先を使わないので、**遷移先の欄に何が入っていても通る**
/// （打ちかけの名前が、無関係な取り消しを止めない）。
#[test]
fn removing_alone_does_not_look_at_the_destination() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let plan = plan(&request_to(tmp.path(), "bad name", &[], &[any("C:/git.exe")]))
        .expect("取り消しが遷移先の名前で止まった");
    assert_eq!(plan.removed.len(), 1);
}

/// **引き継ぎ資料Aの注意を確かめる**: このエディタが書く別ドメイン行きの辺は、`harness.exe`が
/// 「呼び出し元から書ける場所」を足しても（`settings.json`の`fs.read_write`・`--fs-allow :rw`）
/// 起動時に落ちない——作業ディレクトリを宣言しないので固定した遷移にならず、その検査の対象外だからである。
///
/// **歯の確認（対）**: 同じ場所の下を指す**固定した**辺（手で書いたもの）を **Strict のドメインへ**向けると、
/// 同じ入力で落ちる。これが落ちなければ、上の「落ちない」は何も測っていない。
///
/// [P5.4a] 固定値の書込可否（規則(i)）は Strict の印が付いたドメインへ入る辺にだけ掛かる（決定66の追記）ので、
/// 対の辺の遷移先には印を付ける（かつては同じドメインへの自己ループで作っていたが、自己ループは入る辺ではない）。
#[test]
fn an_edge_this_editor_writes_survives_the_writable_places_harness_adds() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan(&request_to(
        tmp.path(),
        "iso",
        &[literal("C:/tools/gen.exe", "\"C:/tools/gen.exe\" --check")],
        &[],
    ))
    .expect("承認できない");
    assert!(commit(tmp.path(), &plan).expect("書けない"));
    let writable_outside = ["C:/tools".to_string()];

    policy_file::load_for_session(tmp.path(), &writable_outside)
        .expect("このエディタが書いた辺がharness.exeの起動時の検査で落ちた");

    // 対: 同じ実行ファイルを、作業ディレクトリまで固定した辺（手で書いたもの）で Strict のドメインへ足す。
    // [P5.4d] 作業ディレクトリは書けない場所に置く——ワークスペースに置くと、作業ディレクトリのせいでエディタの
    // 保存が先に落ちる（作業ディレクトリも規則(i)の候補になった）。測りたいのはプログラムの置き場である。
    let mut file = policy_file::load(tmp.path()).unwrap();
    let cwd = "C:/work".to_string();
    let mut sealed = PolicyDomain::new("sealed");
    sealed.strict = true;
    file.domains.push(sealed);
    let entry = file
        .domains
        .iter_mut()
        .find(|d| d.name == ENTRY_DOMAIN)
        .unwrap();
    entry.process.transitions.push(TransitionEdge {
        exe: ExeMatcher::Literal("C:/tools/gen.exe".to_string()),
        argv: ArgvMatcher::Literal("\"C:/tools/gen.exe\" --fixed".to_string()),
        cwd: Some(cwd),
        to: "sealed".to_string(),
        env: None,
        output: ChildOutput::Return,
    });
    policy_file::save(tmp.path(), &file).expect("エディタの検査（書ける場所を知らない）は通る");
    assert!(
        policy_file::load_for_session(tmp.path(), &writable_outside).is_err(),
        "固定した辺も落ちない——この試験は書ける場所の検査を測れていない"
    );
}

/// [2026-10-01] **ファイル宣言の承認が、遷移の宣言を壊す`policy.json`を書かない。**
///
/// 遷移先へ許可を足すと、そこへの遷移が「広げる遷移」に変わる。かつては`policy_file::save`が検査せずに
/// 書いたので、承認した直後から`harness.exe`もエディタも`policy.json`を読めなくなった——別ドメインへの
/// 遷移を書けるようにした回に、この画面の操作だけで踏める形になった（BUG-188）。
///
/// [2026-10-06、P5.3] 決定66で広げる遷移そのものは書けるようになった。いま壊す形を作るのは、実行ファイルを
/// パターンで書いた辺（手で書いたもの）——広げる向きになると規則(g)が断る（決定66(7)）。エディタが書く辺の先へ
/// 足す承認は書け、**その承認で辺が呼び出し元へ新しく渡す権限が明細の材料（`ApprovePlan::widening`）に出る**。
#[test]
fn approving_a_file_declaration_into_the_destination_cannot_break_the_transitions() {
    use harness_policy::{generalize::SettingsKey, RuleProposal};

    let tmp = tempfile::tempdir().unwrap();
    let mut file = policy_file::load(tmp.path()).unwrap();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions.push(TransitionEdge {
        exe: ExeMatcher::Pattern("c:/tools/[a-z]+\\.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: "iso".to_string(),
        env: None,
        output: ChildOutput::Return,
    });
    file.domains.push(entry);
    file.domains.push(PolicyDomain::new("iso"));
    policy_file::save(tmp.path(), &file).expect("setup: 遷移先が空なら狭める向きで書ける");

    let proposals = vec![RuleProposal {
        id: "fs-1".to_string(),
        key: SettingsKey::FsRead,
        value: "C:/Users/x/.cargo/**".to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }];
    let accept = vec!["fs-1".to_string()];
    let approve_into = |domain: &'static str| crate::approve::ApproveRequest {
        workspace_root: tmp.path(),
        proposals: &proposals,
        accept_ids: &accept,
        require_sandbox: harness_core::RequireSandbox::None,
        domain,
        command: None,
        cwd: None,
        record_session: None,
        now_unix_ms: 1,
    };

    // 禁止側: 実行ファイルをパターンで書いた辺の先にだけ足す → 規則(g)に落ちるので書かない。
    let widening = crate::approve::plan(&approve_into("iso")).expect("plan");
    match crate::approve::commit(tmp.path(), &widening) {
        Err(crate::approve::ApproveError::PolicyFile(
            policy_file::PolicyFileError::WouldRejectTransitions { reason, .. },
        )) => assert!(reason.contains("executable pattern"), "{reason}"),
        other => panic!("遷移を壊す承認が書かれた: {other:?}"),
    }
    let file = policy_file::load(tmp.path()).expect("policy.jsonが読めなくなった");
    assert!(file.domain("iso").unwrap().fs.read.is_empty());

    // 許可側（対）: 呼び出し元にも同じ宣言があれば狭める遷移のままなので、書ける。広がる遷移も出ない。
    let into_entry = crate::approve::plan(&approve_into(ENTRY_DOMAIN)).expect("plan");
    crate::approve::commit(tmp.path(), &into_entry).expect("呼び出し元への承認が書けない");
    let narrowing = crate::approve::plan(&approve_into("iso")).expect("plan");
    assert!(narrowing.widening.is_empty(), "{:?}", narrowing.widening);
    crate::approve::commit(tmp.path(), &narrowing).expect("狭める遷移のままの承認が書けない");

    // 許可側2（決定66）: エディタが書く辺（リテラルの exe）の先へ、呼び出し元の持たない宣言を足す承認は書ける。
    // その承認で辺が呼び出し元へ新しく渡す権限が、明細の材料に出る。
    let edge_plan = plan(&request_to(tmp.path(), "lit", &[any("C:/curl.exe")], &[])).expect("setup");
    commit(tmp.path(), &edge_plan).expect("setup");
    let secret = vec![RuleProposal {
        id: "fs-2".to_string(),
        key: SettingsKey::FsRead,
        value: "C:/Users/x/secret/**".to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }];
    let accept_secret = vec!["fs-2".to_string()];
    let into_lit = crate::approve::plan(&crate::approve::ApproveRequest {
        proposals: &secret,
        accept_ids: &accept_secret,
        ..approve_into("lit")
    })
    .expect("plan");
    assert_eq!(into_lit.widening.edges.len(), 1, "{:?}", into_lit.widening);
    assert_eq!(into_lit.widening.edges[0].from, ENTRY_DOMAIN);
    assert_eq!(into_lit.widening.edges[0].to, "lit");
    assert_eq!(
        into_lit.widening.edges[0].newly_usable.fs,
        vec![("C:/Users/x/secret/**".to_string(), "read")]
    );
    crate::approve::commit(tmp.path(), &into_lit).expect("広げる承認が書けない");
}

/// 引数を絞る承認もできる（観測された引数のときだけ通る辺）。
#[test]
fn an_edge_can_be_narrowed_to_one_command_line() {
    let tmp = tempfile::tempdir().unwrap();
    let rows = approve_and_reload(tmp.path(), &[literal("C:/git.exe", "git config --list")]);

    assert_eq!(rows[0].argv, "git config --list");
    assert!(!rows[0].argv_is_pattern);
}

/// **同じ綴りを2本書かない。** 重複した辺は編集時検査に落ち、`policy.json`が丸ごと効かなくなる。
///
/// 「既にある」と「足した」を区別して返す（`B-09`）——区別しないと、
/// 何も増えていないのに「承認しました」と言うことになる。
#[test]
fn approving_the_same_edge_twice_reports_it_as_already_declared() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let again = plan(&request(tmp.path(), &[any("C:/git.exe")], &[])).expect("2回目が落ちた");
    assert!(again.added.is_empty());
    assert_eq!(again.already_declared, vec![any("C:/git.exe")]);
    assert!(again.is_empty(), "書く必要が無いのに書こうとしている");
    assert!(
        !commit(tmp.path(), &again).expect("commit"),
        "何も無いのに書いた"
    );
}

/// 同じexeでも、argvの照合方法が違えば別の辺である。
#[test]
fn the_same_exe_with_a_different_argv_matcher_is_a_different_edge() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);
    let rows = approve_and_reload(tmp.path(), &[literal("C:/git.exe", "git status")]);

    assert_eq!(rows.len(), 2, "argvの違う辺が同じものとして畳まれている");
}

// --- 取り消し（承認の対） ---------------------------------------------------

/// **対の側**（`B-01`）: 承認した辺はその場で外せる。
///
/// 外せないと、間違えて承認したものを直すのに**手でJSONを編集する**しかなくなる。
#[test]
fn an_approved_edge_can_be_removed_again() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let plan = plan(&request(tmp.path(), &[], &[any("C:/git.exe")])).expect("取り消せない");
    assert_eq!(plan.removed, vec![any("C:/git.exe")]);
    assert!(commit(tmp.path(), &plan).expect("書けない"));

    let file = policy_file::load(tmp.path()).expect("読めない");
    let ws_text = tmp.path().to_string_lossy().into_owned();
    let input = file.transition_graph_input(Some(&ws_text), &[]);
    let rows = transition_listing::rows(&input, ENTRY_DOMAIN, &Default::default()).expect("一覧");
    assert!(rows.is_empty(), "取り消したのに辺が残っている");
    // **ドメインは残す**（`crate::unapprove`と同じ理由——宣言を全部外した状態で
    // 本当に断られるかを確かめられるようにするため）。
    assert!(
        policy_file::load(tmp.path())
            .unwrap()
            .domain(ENTRY_DOMAIN)
            .is_some(),
        "宣言が空になったドメインごと消している"
    );
}

/// 無い辺を消そうとしたら、**「消した」と言わない**（`B-09`）。
#[test]
fn removing_an_edge_that_is_not_declared_is_reported_as_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let plan = plan(&request(tmp.path(), &[], &[any("C:/cargo.exe")])).expect("plan");
    assert!(plan.removed.is_empty());
    assert_eq!(plan.not_found, vec![any("C:/cargo.exe")]);
}

/// 綴りの揺れ（大文字小文字・区切り）は同じ辺として扱う。
///
/// 判定器が比較の前に畳んでいるので、**ここだけ畳まないと**画面から消せない辺ができる。
#[test]
fn removal_matches_the_declared_edge_regardless_of_spelling_case() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/Git/bin/git.exe")]);

    let plan = plan(&request(tmp.path(), &[], &[any("c:\\git\\bin\\GIT.EXE")])).expect("plan");
    assert_eq!(plan.removed.len(), 1, "同じ辺を別物として扱っている");
}

/// 1回の確定で「消してから足し直す」ができる（引数の絞り方を変える操作がこれになる）。
#[test]
fn one_commit_can_replace_an_edge_with_a_narrower_one() {
    let tmp = tempfile::tempdir().unwrap();
    approve_and_reload(tmp.path(), &[any("C:/git.exe")]);

    let approve = [literal("C:/git.exe", "git status")];
    let remove = [any("C:/git.exe")];
    let plan = plan(&request(tmp.path(), &approve, &remove)).expect("plan");
    assert_eq!(plan.added.len(), 1);
    assert_eq!(plan.removed.len(), 1);
    assert!(commit(tmp.path(), &plan).expect("書けない"));

    let file = policy_file::load(tmp.path()).expect("読めない");
    let ws_text = tmp.path().to_string_lossy().into_owned();
    let input = file.transition_graph_input(Some(&ws_text), &[]);
    let rows = transition_listing::rows(&input, ENTRY_DOMAIN, &Default::default()).expect("一覧");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].argv, "git status");
}

// --- 何も選ばれていない -----------------------------------------------------

/// 1件も選ばずに確定したら、**理由を言って何も書かない**（`B-32`: 何も起きない理由を言う）。
#[test]
fn committing_with_nothing_selected_says_why() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(matches!(
        plan(&request(tmp.path(), &[], &[])),
        Err(TransitionApproveError::NothingSelected)
    ));
}

// --- 辺の形は1か所 ---------------------------------------------------------

/// **エディタが書く辺の形は`harness_policy::transition::editor_edge`の1か所**（P3b の注意4、`B-05`）。
/// 遷移タブの承認（[`edge_for`]）と位置ごとの割り当て（`Assignment::edges_to_add`）が、同じ exe・引数・遷移先で
/// 同じ辺を作る。対の側: 引数の照合方法が違えば別の辺になる（比べているのが中身であって、常に等しいのではない）。
#[test]
fn editor_edge_is_the_only_shape_the_editor_writes() {
    use harness_policy::position_domains::{Assignment, Position, PositionSource};
    const EXE: &str = "C:/Program Files/PowerShell/7/pwsh.exe";
    let assignment = Assignment {
        positions: vec![Position {
            depth: 1,
            from_domain: ENTRY_DOMAIN.to_string(),
            exe: EXE.to_string(),
            to_domain: "pwsh".to_string(),
            source: PositionSource::Proposed,
            instances: vec![2],
            command_lines: Vec::new(),
            argv_missing: 0,
            argv_truncated: 0,
        }],
        roots: Vec::new(),
        unassigned: Vec::new(),
    };
    let expected =
        transition::editor_edge(EXE, ArgvMatcher::Any(transition::AnyMarker), "pwsh");

    let from_positions = assignment.edges_to_add();
    assert_eq!(from_positions.len(), 1);
    assert_eq!(from_positions[0].edge, expected, "位置ごとの割り当ての辺の形が違う");
    assert_eq!(edge_for(&any(EXE), "pwsh"), expected, "遷移タブの承認の辺の形が違う");

    // 対の側: リテラルの引数で作った辺は、任意の引数の辺と等しくない。
    assert_ne!(edge_for(&literal(EXE, "pwsh -c x"), "pwsh"), expected);
    assert_eq!(
        edge_for(&literal(EXE, "pwsh -c x"), "pwsh"),
        transition::editor_edge(EXE, ArgvMatcher::Literal("pwsh -c x".to_string()), "pwsh")
    );
}
