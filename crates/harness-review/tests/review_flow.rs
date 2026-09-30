//! 許可側: エージェントのコミットが、レビュー用の名前空間へちょうど取り込まれ、
//! レビュー用 worktree で読めること。本物の枝・タグは1本も動かないこと。

mod support;

use std::path::Path;

use harness_review::{discard_review_artifacts, prepare_review};
use support::{write, Fixture, SimOptions};

/// 新しい枝を作って1コミットする（エージェントの見え方で）。
fn commit_on(fx: &Fixture, agent: &Path, branch: &str) {
    fx.git(agent, &["switch", "-q", "-c", branch]);
    write(&agent.join(format!("{branch}.txt")), "x\n");
    fx.git(agent, &["add", "-A"]);
    fx.git(agent, &["commit", "-q", "-m", branch]);
}

/// 合格基準 P3 の形: `git log <base>..refs/harness/review/<sid>/heads/<枝>` が
/// エージェントのコミットとちょうど一致する。本体層の pack のコピー（copy-up）が混ざっていても同じ。
#[test]
fn agent_commits_land_exactly_under_the_review_namespace() {
    let fx = Fixture::new();
    let before = fx.real_refs();
    let (dl, agent) = fx.session(
        "session-flow1",
        SimOptions {
            copy_up_base_packs: true,
        },
        |a| {
            fx.git(a, &["switch", "-q", "-c", "feature"]);
            write(&a.join("src/lib.txt"), "fn original() {}\nfn added() {}\n");
            fx.git(a, &["commit", "-q", "-am", "agent 1"]);
            write(&a.join("src/new.txt"), "new\n");
            fx.git(a, &["add", "-A"]);
            fx.git(a, &["commit", "-q", "-m", "agent 2"]);
            fx.git(a, &["tag", "v1"]);
            fx.git(a, &["tag", "-a", "-m", "annotated", "v2"]);
        },
    );

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");

    let names: Vec<&str> = report.imported.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        ["refs/heads/feature", "refs/tags/v1", "refs/tags/v2"]
    );
    assert!(
        report.imported.iter().all(|r| r.base.is_none()),
        "all three are new"
    );
    assert!(report.not_imported.is_empty(), "{:?}", report.not_imported);
    assert!(
        report.objects.packs_already_present >= 1,
        "{:?}",
        report.objects
    );
    assert!(
        report.objects.loose_rejected.is_empty(),
        "{:?}",
        report.objects
    );

    let expected = fx.git(&agent, &["log", "--format=%H", "main..feature"]);
    let review_ref = "refs/harness/review/session-flow1/heads/feature";
    let actual = fx.git(
        &fx.ws,
        &["log", "--format=%H", &format!("main..{review_ref}")],
    );
    assert_eq!(actual, expected);
    assert_eq!(actual.lines().count(), 2);

    // worktree はエージェントの HEAD（feature）の先端で、ファイルの中身も同じ。
    assert_eq!(report.agent_head.as_deref(), Some("refs/heads/feature"));
    assert_eq!(
        report.worktree_tip,
        fx.git(&agent, &["rev-parse", "feature"])
    );
    assert_eq!(
        std::fs::read_to_string(report.worktree.join("src/new.txt")).unwrap(),
        "new\n"
    );
    assert!(fx
        .git(&report.worktree, &["status", "--porcelain"])
        .is_empty());

    // 本物の枝とタグは1本も動いていない（増えたのはレビュー用の名前空間だけ）。
    let after: Vec<_> = fx
        .real_refs()
        .into_iter()
        .filter(|(n, _)| !n.starts_with("refs/harness/review/"))
        .collect();
    assert_eq!(after, before);
}

/// 本物の枝を進めたセッション: `base` が本物の元の値になり、取り込むのは差分だけ。
/// 変えていない枝（`old`）とタグ（`v0`）は取り込まない。
#[test]
fn a_branch_that_already_exists_is_imported_with_its_base() {
    let fx = Fixture::new();
    let main_before = fx.git(&fx.ws, &["rev-parse", "main"]);
    let (dl, _agent) = fx.session("session-flow2", SimOptions::default(), |a| {
        write(&a.join("README.md"), "hello again\n");
        fx.git(a, &["commit", "-q", "-am", "agent on main"]);
    });
    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert_eq!(report.imported.len(), 1, "{:?}", report.imported);
    assert_eq!(report.imported[0].name, "refs/heads/main");
    assert_eq!(
        report.imported[0].base.as_deref(),
        Some(main_before.as_str())
    );
    assert_eq!(fx.git(&fx.ws, &["rev-parse", "main"]), main_before);
    assert_eq!(
        std::fs::read_to_string(report.worktree.join("README.md")).unwrap(),
        "hello again\n"
    );
}

/// エージェントが消した枝は報告するだけで、本物からは消さない（消すかは承認の側が決める）。
/// 本体層では `gc` で `packed-refs` に入っているので、消すと差分層の `packed-refs` が書き換わる。
#[test]
fn a_branch_the_agent_deleted_is_reported_but_left_alone() {
    let fx = Fixture::new();
    let (dl, _agent) = fx.session("session-flow3", SimOptions::default(), |a| {
        fx.git(a, &["branch", "-q", "-D", "old"]);
    });
    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert_eq!(report.deleted_in_session, ["refs/heads/old"]);
    assert!(report.imported.is_empty());
    assert!(fx.git(&fx.ws, &["branch", "--list", "old"]).contains("old"));
}

/// git に触れなかったセッションにも worktree はできる（未コミットの変更を並べる土台。
/// 並べる手順は段6の後半）。worktree は本物の HEAD。
#[test]
fn a_session_that_never_touched_git_still_gets_a_worktree_of_the_real_head() {
    let fx = Fixture::new();
    let dl = fx.cow_root.join("session-flow4");
    write(&dl.join("scratch.txt"), "side effect\n");
    std::fs::write(
        dl.join(".harness-cow-ops.jsonl"),
        "{\"op\":\"create\",\"path\":\"scratch.txt\",\"baseline_hash\":null,\"ts_unix_millis\":1}\n",
    )
    .unwrap();
    #[cfg(windows)]
    harness_sandbox::tier2a::workspace_ledger::write_cow_session_meta(&dl, &fx.ws, "session-flow4");

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert!(report.imported.is_empty());
    assert_eq!(report.worktree_tip, fx.git(&fx.ws, &["rev-parse", "HEAD"]));
    assert!(report.worktree.join("docs/guide.txt").is_file());
}

/// 同じセッションで2回呼んでよい（前回の ref と worktree を消してから作り直す）。
#[test]
fn reviewing_the_same_session_twice_rebuilds_the_artifacts() {
    let fx = Fixture::new();
    let (dl, _agent) = fx.session("session-flow5", SimOptions::default(), |a| {
        commit_on(&fx, a, "topic")
    });
    let first = prepare_review(&fx.launcher, &fx.request(&dl)).expect("first");
    let second = prepare_review(&fx.launcher, &fx.request(&dl)).expect("second");
    assert_eq!(first.imported, second.imported);
    assert_eq!(first.worktree, second.worktree);
    assert!(second.worktree.join("topic.txt").is_file());
}

/// 後始末（合格基準 P4 のうちレビュー用 ref・worktree の側）: このセッションのものだけが消え、
/// 名前の似た別のセッション（`session-aa` と `session-aab`）には触れない。2回呼んでもよい。
#[test]
fn discarding_removes_only_this_sessions_refs_and_worktree() {
    let fx = Fixture::new();
    let (dl_a, _) = fx.session("session-aa", SimOptions::default(), |a| {
        commit_on(&fx, a, "ta")
    });
    let (dl_b, _) = fx.session("session-aab", SimOptions::default(), |a| {
        commit_on(&fx, a, "tb")
    });
    let a = prepare_review(&fx.launcher, &fx.request(&dl_a)).expect("a");
    let b = prepare_review(&fx.launcher, &fx.request(&dl_b)).expect("b");

    let roots = [fx.review_root.clone()];
    let cleaned = discard_review_artifacts(&fx.launcher, &fx.ws, &dl_a, &roots).unwrap();
    assert!(cleaned.problems.is_empty(), "{:?}", cleaned.problems);
    assert_eq!(
        cleaned.refs_deleted,
        ["refs/harness/review/session-aa/heads/ta"]
    );
    assert_eq!(cleaned.worktrees_removed.len(), 1);
    assert!(!a.worktree.exists());
    assert!(b.worktree.is_dir());
    let refs = fx.real_refs();
    assert!(!refs
        .iter()
        .any(|(n, _)| n.starts_with("refs/harness/review/session-aa/")));
    assert!(refs
        .iter()
        .any(|(n, _)| n == "refs/harness/review/session-aab/heads/tb"));
    let listed = fx.git(&fx.ws, &["worktree", "list", "--porcelain"]);
    assert!(
        !listed.contains("session-aa\n") && listed.contains("session-aab"),
        "{listed}"
    );

    let again = discard_review_artifacts(&fx.launcher, &fx.ws, &dl_a, &roots).unwrap();
    assert!(
        again.problems.is_empty() && again.refs_deleted.is_empty(),
        "{again:?}"
    );
}

/// まだ扱えない形のワークスペースは、理由付きで断り、何も書かない（レビュー状態も変えない）。
/// 許可側（ルートに `.git` ディレクトリがある SHA-1 のリポジトリ）は他のテストが通している。
#[test]
fn repositories_this_cannot_handle_yet_are_refused_with_a_reason() {
    let fx = Fixture::new();
    let refuse = |ws: &Path, sid: &str| {
        let dl = fx.cow_root.join(sid);
        std::fs::create_dir_all(&dl).unwrap();
        #[cfg(windows)]
        harness_sandbox::tier2a::workspace_ledger::write_cow_session_meta(&dl, ws, sid);
        let req = harness_review::ReviewRequest {
            workspace_root: ws,
            diff_layer_dir: &dl,
            review_root: &fx.review_root,
            scratch_parent: &fx.scratch,
        };
        let err = prepare_review(&fx.launcher, &req).expect_err("must be refused");
        assert!(
            matches!(err, harness_review::ReviewError::Unsupported(_)),
            "{err}"
        );
        #[cfg(windows)]
        assert_eq!(
            harness_sandbox::tier2a::workspace_ledger::read_cow_session_meta(&dl)
                .ok()
                .unwrap()
                .review,
            None
        );
        err.to_string()
    };

    let plain = fx.base.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    assert!(refuse(&plain, "session-un1").contains("not a git repository"));

    let linked = fx.base.join("linked");
    write(
        &linked.join(".git"),
        "gitdir: ../elsewhere/.git/worktrees/x\n",
    );
    assert!(refuse(&linked, "session-un2").contains(".git is a file"));

    let sha256 = fx.base.join("sha256");
    std::fs::create_dir_all(&sha256).unwrap();
    fx.git(&sha256, &["init", "-q", "--object-format=sha256"]);
    write(&sha256.join("a.txt"), "a\n");
    fx.git(&sha256, &["add", "-A"]);
    fx.git(&sha256, &["commit", "-q", "-m", "a"]);
    assert!(refuse(&sha256, "session-un3").contains("only SHA-1"));
}
