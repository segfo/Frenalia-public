//! 禁止側: エージェントが差分層の `.git` に仕込んだものが、ハーネスの git に効かないこと
//! （D-110 (vi) の不変条件）と、危険パスが worktree のディスクへ出ないこと（D-110 (i)）。
//!
//! どの仕掛けにも**陽性対照**を付ける——同じ仕掛けを、エージェントの見え方の側で素の git に
//! 踏ませると実際に発火することを確かめる。対照が無いと「仕掛けがそもそも動かない」ときにも
//! 緑になる。

mod support;

use harness_review::{discard_review_artifacts, prepare_review};
use support::{sh_path, write, Fixture, SimOptions};

/// エージェントが書いた `.git/config`（フィルタ・外部 diff）とフックは、レビューの間に
/// 1つも動かない。対照: 同じ見え方で素の git を回すと4つとも動く。
#[test]
fn the_agents_git_configuration_and_hooks_never_run() {
    let fx = Fixture::new();
    let m = fx.markers();
    let (dl, agent) = fx.session("session-adv1", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join(".gitattributes"), "*.txt filter=x diff=x\n");
        write(&a.join("data.txt"), "data\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "with attributes"]);
        // コミットの後に仕込む（仕込んだ後にこの見え方で git を回すと、ここで発火してしまう）。
        let config = a.join(".git/config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(&format!(
            "[filter \"x\"]\n\tsmudge = \"{}\"\n\tclean = \"{}\"\n[diff]\n\texternal = \"{}\"\n\
             [core]\n\tfsmonitor = \"{}\"\n",
            m.command("smudge"),
            m.command("clean"),
            m.command("diff-external"),
            m.command("fsmonitor"),
        ));
        std::fs::write(&config, text).unwrap();
        for hook in [
            "post-checkout",
            "reference-transaction",
            "post-index-change",
            "pre-auto-gc",
        ] {
            write(&a.join(".git/hooks").join(hook), &m.hook(hook));
        }
    });

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert_eq!(report.imported.len(), 1, "{:?}", report.imported);
    let cleaned = discard_review_artifacts(
        &fx.launcher,
        &fx.ws,
        &dl,
        std::slice::from_ref(&fx.review_root),
    )
    .unwrap();
    assert!(cleaned.problems.is_empty(), "{:?}", cleaned.problems);
    assert_eq!(
        m.fired(),
        "",
        "something the agent planted ran during the review"
    );

    // 陽性対照。
    fx.git(&agent, &["switch", "-q", "-c", "control"]);
    std::fs::remove_file(agent.join("data.txt")).unwrap();
    fx.git(&agent, &["checkout", "--", "data.txt"]);
    let _ = fx.git_raw(&agent, &["diff", "HEAD~1", "HEAD"]);
    let _ = fx.git_raw(&agent, &["status", "--porcelain"]);
    let fired = m.fired();
    for name in [
        "post-checkout",
        "reference-transaction",
        "smudge",
        "diff-external",
        "fsmonitor",
    ] {
        assert!(
            fired.contains(name),
            "the control did not fire {name}: {fired:?}"
        );
    }
}

/// 利用者のグローバル設定にあるフィルタを、エージェントの `.gitattributes` が選んでも、
/// レビュー用 worktree を作る間は動かない（属性を空の tree から読むため）。
/// 対照: 同じ worktree で、属性の読み元を指定しない素の git を回すと動く
/// （`.gitattributes` はディスクに無くても index から読まれる）。
#[test]
fn the_users_own_filter_is_not_selected_by_the_agents_attributes() {
    let fx = Fixture::new();
    let m = fx.markers();
    let (dl, _agent) = fx.session("session-adv2", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join(".gitattributes"), "*.txt filter=userfilter\n");
        write(&a.join("notes.txt"), "notes\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "select the user's filter"]);
    });
    // 利用者の設定（セッションの後に足す。器を組む git に踏ませないため）。
    let gitconfig = fx.home.join(".gitconfig");
    let mut text = std::fs::read_to_string(&gitconfig).unwrap();
    text.push_str(&format!(
        "[filter \"userfilter\"]\n\tsmudge = \"{}\"\n\tclean = \"{}\"\n",
        m.command("user-smudge"),
        m.command("user-clean"),
    ));
    std::fs::write(&gitconfig, text).unwrap();

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert!(report
        .withheld_from_disk
        .contains(&".gitattributes".to_string()));
    assert_eq!(
        std::fs::read_to_string(report.worktree.join("notes.txt")).unwrap(),
        "notes\n"
    );
    assert_eq!(m.fired(), "", "the user's filter ran during the review");

    // 陽性対照。
    std::fs::remove_file(report.worktree.join("notes.txt")).unwrap();
    fx.git(
        &report.worktree,
        &["checkout-index", "-f", "--", "notes.txt"],
    );
    assert!(
        m.fired().contains("user-smudge"),
        "the control did not fire: {:?}",
        m.fired()
    );
}

/// エージェントが書いた alternates は辿らない。第三のリポジトリにしか無いコミットを指す枝は
/// 取り込まれず、理由付きで報告される。他の枝の取り込みは止まらない。
/// 対照: エージェントの見え方では、その alternates でコミットが見えている。
#[test]
fn alternates_written_by_the_agent_are_never_followed() {
    let fx = Fixture::new();
    let third = fx.base.join("third");
    std::fs::create_dir_all(&third).unwrap();
    fx.git(&third, &["init", "-q"]);
    write(&third.join("elsewhere.txt"), "from another repository\n");
    fx.git(&third, &["add", "-A"]);
    fx.git(&third, &["commit", "-q", "-m", "elsewhere"]);
    let foreign = fx.git(&third, &["rev-parse", "HEAD"]);

    let (dl, agent) = fx.session("session-adv3", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join("ok.txt"), "ok\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "ok"]);
        write(
            &a.join(".git/objects/info/alternates"),
            &format!("{}\n", sh_path(&third.join(".git/objects"))),
        );
        fx.git(a, &["update-ref", "refs/heads/fromthird", &foreign]);
    });
    assert!(fx
        .git_raw(&agent, &["cat-file", "-e", &foreign])
        .status
        .success());

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    let imported: Vec<&str> = report.imported.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(imported, ["refs/heads/feature"]);
    let skipped = report
        .not_imported
        .iter()
        .find(|s| s.name == "refs/heads/fromthird")
        .expect("reported");
    assert!(
        skipped
            .reason
            .contains("neither among the verified objects"),
        "{skipped:?}"
    );
    assert!(
        report
            .objects
            .ignored_samples
            .iter()
            .any(|s| s == "objects/info/alternates"),
        "{:?}",
        report.objects
    );
    assert!(!fx
        .git_raw(&fx.ws, &["cat-file", "-e", &foreign])
        .status
        .success());
}

/// 名前と中身の違うゆるいオブジェクトは一時リポジトリへ入れない。そのオブジェクトが要る枝は
/// 取り込めないので、レビューごと失敗し、**途中まで作ったものは残らない**。
#[test]
fn a_forged_object_fails_the_review_and_nothing_is_left_behind() {
    let fx = Fixture::new();
    let (dl, agent) = fx.session("session-adv4", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join("secret.txt"), "the real content\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "carry a blob"]);
    });
    let blob = fx.git(&agent, &["rev-parse", "feature:secret.txt"]);
    let commit = fx.git(&agent, &["rev-parse", "feature"]);
    let object_path = |oid: &str| dl.join(".git/objects").join(&oid[..2]).join(&oid[2..]);
    // 別のオブジェクト（コミット）のバイト列を、blob の名前の置き場へ置く＝名前と中身が違う。
    std::fs::copy(object_path(&commit), object_path(&blob)).unwrap();

    let err = prepare_review(&fx.launcher, &fx.request(&dl)).expect_err("must fail");
    let message = err.to_string();
    assert!(!message.contains("undoing it also failed"), "{message}");
    assert!(
        !fx.real_refs()
            .iter()
            .any(|(n, _)| n.starts_with("refs/harness/review/")),
        "review refs were left behind"
    );
    let name = harness_review::worktree_dir_name(
        &fx.ws,
        &harness_review::SessionId::parse("session-adv4").unwrap(),
    );
    assert!(
        !fx.review_root.join(name).exists(),
        "the worktree was left behind"
    );
    #[cfg(windows)]
    {
        use harness_sandbox::tier2a::workspace_ledger::read_cow_session_meta;
        let meta = read_cow_session_meta(&dl);
        assert_eq!(
            meta.ok().unwrap().review,
            None,
            "the review state was not restored"
        );
    }
}

/// 検算そのものの歯: どこからも参照されない偽装オブジェクトは、取り込みを止めずに
/// 「落とした」と名指しされる。**要らないオブジェクトは fetch で運ばれないので、fetch の側の
/// fsck はこれを見ない**——上の「要る偽装」のテストは検算を外しても fsck で落ちるので、
/// 検算の有無はこのテストでしか分からない。
#[test]
fn a_forged_object_nobody_needs_is_dropped_and_named() {
    let fx = Fixture::new();
    let (dl, agent) = fx.session("session-adv8", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join("f.txt"), "f\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "f"]);
    });
    let commit = fx.git(&agent, &["rev-parse", "feature"]);
    let forged = "ab".to_string() + &"c".repeat(38);
    let forged_path = dl.join(".git/objects/ab").join(&forged[2..]);
    std::fs::create_dir_all(forged_path.parent().unwrap()).unwrap();
    std::fs::copy(
        dl.join(".git/objects")
            .join(&commit[..2])
            .join(&commit[2..]),
        &forged_path,
    )
    .unwrap();

    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    assert_eq!(report.imported.len(), 1);
    let rejected = report
        .objects
        .loose_rejected
        .iter()
        .find(|(oid, _)| oid == &forged)
        .unwrap_or_else(|| panic!("not named: {:?}", report.objects));
    assert!(rejected.1.contains("not to its name"), "{rejected:?}");
    assert!(!fx
        .git_raw(&fx.ws, &["cat-file", "-e", &forged])
        .status
        .success());
}

/// 名前と中身は一致していても、形式が不正なオブジェクト（`.git` という名前を持つ tree）は
/// fetch の側の fsck が落とす。対照: fsck を立てない素の fetch は通してしまう。
#[test]
fn a_tree_carrying_a_dot_git_entry_is_stopped_by_fsck() {
    let fx = Fixture::new();
    let (dl, agent) = fx.session("session-adv5", SimOptions::default(), |a| {
        let blob = fx.git_stdin(a, &["hash-object", "-w", "--stdin"], b"[core]\n");
        let mut tree = b"100644 .git\0".to_vec();
        tree.extend((0..20).map(|i| u8::from_str_radix(&blob[i * 2..i * 2 + 2], 16).unwrap()));
        let tree = fx.git_stdin(
            a,
            &["hash-object", "-w", "-t", "tree", "--literally", "--stdin"],
            &tree,
        );
        let head = fx.git(a, &["rev-parse", "HEAD"]);
        let commit = fx.git(a, &["commit-tree", &tree, "-p", &head, "-m", "evil"]);
        fx.git(a, &["update-ref", "refs/heads/evil", &commit]);
    });

    let err = prepare_review(&fx.launcher, &fx.request(&dl)).expect_err("fsck must stop it");
    assert!(!err.to_string().contains("undoing it also failed"), "{err}");
    assert!(!fx
        .real_refs()
        .iter()
        .any(|(n, _)| n.starts_with("refs/harness/review/")));

    // 対照: fsck 無しの fetch は通り、fsck 付きなら落ちる（落としているのが fsck であること）。
    let control = fx.base.join("control.git");
    fx.git(&fx.base, &["init", "-q", "--bare", &sh_path(&control)]);
    let src = sh_path(&agent);
    let without = fx.git_raw(
        &control,
        &["fetch", "-q", &src, "refs/heads/evil:refs/heads/evil"],
    );
    assert!(
        without.status.success(),
        "{}",
        String::from_utf8_lossy(&without.stderr)
    );
    let control2 = fx.base.join("control2.git");
    fx.git(&fx.base, &["init", "-q", "--bare", &sh_path(&control2)]);
    let with = fx.git_raw(
        &control2,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "-q",
            &src,
            "refs/heads/evil:refs/heads/evil",
        ],
    );
    assert!(!with.status.success());
}

/// 合格基準 P5 の片側（D-110 (i)）: 危険パスは worktree のディスクへ出ない。`git diff` では
/// 文字として見える。普通のファイルは出る。
#[test]
fn danger_paths_are_withheld_from_the_review_worktree() {
    let fx = Fixture::new();
    let (dl, _agent) = fx.session("session-adv6", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        write(&a.join(".github/workflows/x.yml"), "on: push\n");
        write(
            &a.join(".vscode/tasks.json"),
            "{\"runOn\": \"folderOpen\"}\n",
        );
        write(
            &a.join(".gitmodules"),
            "[submodule \"x\"]\n\tpath = x\n\turl = https://example.invalid/x\n",
        );
        write(&a.join("src/ok.txt"), "ok\n");
        fx.git(a, &["add", "-A"]);
        fx.git(a, &["commit", "-q", "-m", "danger"]);
    });
    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    let danger = [
        ".github/workflows/x.yml",
        ".gitmodules",
        ".vscode/tasks.json",
    ];
    assert_eq!(report.withheld_from_disk, danger);
    for p in danger {
        assert!(!report.worktree.join(p).exists(), "{p} was written to disk");
    }
    assert_eq!(
        std::fs::read_to_string(report.worktree.join("src/ok.txt")).unwrap(),
        "ok\n"
    );
    let flags = fx.git(&report.worktree, &["ls-files", "-v"]);
    for p in danger {
        assert!(
            flags.contains(&format!("S {p}")),
            "{p} is not skip-worktree: {flags}"
        );
    }
    let diff = fx.git(
        &fx.ws,
        &[
            "diff",
            "--name-only",
            "main",
            "refs/harness/review/session-adv6/heads/feature",
        ],
    );
    for p in danger {
        assert!(diff.contains(p), "{p} is not visible to git diff: {diff}");
    }
}

/// `refs/heads/*`・`refs/tags/*` の外の ref（replace・notes）と、形の崩れた ref（symref・
/// `.lock`）は取り込まず、名前と理由を報告する。`shallow`・`info/grafts`・commit-graph を
/// 置かれても、取り込んだ枝の履歴は切り詰められない。
#[test]
fn refs_that_must_not_be_imported_are_reported_and_history_is_not_truncated() {
    let fx = Fixture::new();
    let mut expected = String::new();
    let (dl, _agent) = fx.session("session-adv7", SimOptions::default(), |a| {
        fx.git(a, &["switch", "-q", "-c", "feature"]);
        for i in 1..=2 {
            write(&a.join(format!("f{i}.txt")), "x\n");
            fx.git(a, &["add", "-A"]);
            fx.git(a, &["commit", "-q", "-m", &format!("f{i}")]);
        }
        // 仕込む前に取る（仕込んだ後はエージェントの見え方の履歴そのものが変わる）。
        expected = fx.git(a, &["log", "--format=%H", "main..feature"]);
        let head = fx.git(a, &["rev-parse", "HEAD"]);
        let parent = fx.git(a, &["rev-parse", "HEAD~1"]);
        fx.git(a, &["replace", &parent, &head]);
        fx.git(a, &["notes", "add", "-m", "note", "HEAD"]);
        write(&a.join(".git/refs/heads/sym"), "ref: refs/heads/main\n");
        write(&a.join(".git/refs/heads/bad.lock"), &format!("{head}\n"));
        write(&a.join(".git/shallow"), &format!("{parent}\n"));
        write(&a.join(".git/info/grafts"), &format!("{head}\n"));
        write(
            &a.join(".git/objects/info/commit-graph"),
            "not a commit graph",
        );
    });
    let report = prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    let imported: Vec<&str> = report.imported.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(imported, ["refs/heads/feature"]);
    let skipped: Vec<&str> = report
        .not_imported
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    for expected in [
        "refs/heads/sym",
        "refs/heads/bad.lock",
        "refs/notes/commits",
    ] {
        assert!(
            skipped.contains(&expected),
            "{expected} not reported: {skipped:?}"
        );
    }
    assert!(
        skipped.iter().any(|n| n.starts_with("refs/replace/")),
        "{skipped:?}"
    );

    let actual = fx.git(
        &fx.ws,
        &[
            "log",
            "--format=%H",
            "main..refs/harness/review/session-adv7/heads/feature",
        ],
    );
    assert_eq!(actual, expected);
    assert_eq!(actual.lines().count(), 2);
}
