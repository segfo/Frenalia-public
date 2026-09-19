//! [段階⑦] 遷移の承認・取り消しの単体テスト。
//!
//! **端末もWin32も要らない**（`cargo test -p harness-policy-editor`に入る）。
//! 実際に`policy.json`をtempdirへ書いて読み直すので、**書いたものが読めること**まで測る。

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

fn request<'a>(
    ws: &'a Path,
    approve: &'a [EdgeRef],
    remove: &'a [EdgeRef],
) -> TransitionRequest<'a> {
    TransitionRequest {
        workspace_root: ws,
        from_domain: ENTRY_DOMAIN,
        approve,
        remove,
        record_session: Some("session-1"),
        now_unix_ms: 1_700_000_000_000,
    }
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
    let file = policy_file::load(ws).expect("書いたものが読めない");
    let ws_text = ws.to_string_lossy().into_owned();
    let input = file.transition_graph_input(Some(&ws_text));
    transition_listing::rows(&input, ENTRY_DOMAIN).expect("一覧が作れない")
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
    assert_eq!(rows[0].to_domain, ENTRY_DOMAIN);
}

/// **暫定を固定する**（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の撤去一覧6つ目）。
///
/// いま書ける辺は**自己ループだけ**である。別ドメインで起こすにはそのドメインの
/// プロファイルが要るが、ドメインを鍵にした発行器がまだ無い（§22.9）。
///
/// # このテストが赤くなったら
///
/// §22.9（ドメインごとのプロファイル発行器）が着地したということである。**そのときは
/// `provisional_destination`とこのテストと`SELF_LOOP_NOTICE`を消し、遷移先を選べるように
/// すること**（辺を組む`edge_for`は遷移先を引数で受けているので、渡す値を変えるだけでよい）。
/// あわせて§10.1.2の撤去一覧から6つ目を消す。
#[test]
fn only_self_loop_edges_are_written_today() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan(&request(tmp.path(), &[any("C:/git.exe")], &[])).expect("承認できない");

    assert_eq!(
        plan.to_domain, ENTRY_DOMAIN,
        "遷移元と違うドメインへの辺を書いている。\
         §22.9が着地したのなら、provisional_destination・SELF_LOOP_NOTICE・\
         このテスト・§10.1.2の撤去一覧6つ目をまとめて消すこと"
    );

    let rows = approve_and_reload(tmp.path(), &[any("C:/git.exe")]);
    assert!(
        rows[0].runnable_now,
        "自己ループなのに「いまは起こせない」になっている"
    );
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
    let input = file.transition_graph_input(Some(&ws_text));
    let rows = transition_listing::rows(&input, ENTRY_DOMAIN).expect("一覧");
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
    let input = file.transition_graph_input(Some(&ws_text));
    let rows = transition_listing::rows(&input, ENTRY_DOMAIN).expect("一覧");
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
