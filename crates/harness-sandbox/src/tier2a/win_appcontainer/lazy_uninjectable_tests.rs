//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）受入1「状態機械」のfault injection]
//! **DLLを注入できないプロセスがどうなるか**を、注入を意図的に外して実機で測る。
//!
//! # なぜこれを測るのか
//!
//! レーンを既定に上げてよい理由が「注入できないプロセスは待たされるだけだから安全」だからで、
//! **それが本当に全部のプロセスで成り立つか**をここで測る。場所は2つあり、
//! 待たせ方が違うので2本に分けてある。
//!
//! ```text
//! 起動側（最上位のシェル）を外す → レーンに乗せない → 全walkを待って起動 → 成功
//! 子孫を外す                     → 一時停止のまま準備の完了を待ってから動かす → 成功
//! ```
//!
//! # なぜ場所によって待たせ方が違うのか
//!
//! **待てるのは、まだ1行も実行していないプロセスだけ**である。最上位は起こす前に判断でき、
//! 子孫は`CREATE_SUSPENDED`で作られた直後に判断できる——どちらもまだ何も起きていない。
//! **走り出した後は待てない**（`ls`が半分読んだところで巻き戻せない）ので、そこで
//! 許可を付けられなかった場合だけは別の手当てになる（受付側の掛け金。
//! `lazy_grant::lane_is_distrusted`）。
//!
//! # どちらも境界の穴ではない（D-01）
//!
//! 外したプロセスが失うのは透過性だけで、ACLの拒否はそのまま残る。**失敗する方向へ倒れる**
//! ので、権限が広がることはない。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 lazy_uninjectable
//! ```

use super::test_support::{
    cleanup_workspace, make_unreachable, scopeguard, workspace_grants, TestDirGuard,
};
use super::*;

const TARGET_REL: &str = r"late\deep\target.txt";
const MARKER: &str = "lazy-uninjectable-marker";

/// `label`のworkspaceを作り、`preflight`まで通して「対象1件だけが未準備」の状態にする。
///
/// 戻り値は`(guard, workspace, canonical, grants, cleanup)`。**cleanupは受け取り側が
/// 生かしておくこと**（落とすとその場で撤収が走る）。
fn prepared_workspace_with_one_unreachable_file(
    label: &str,
) -> (
    TestDirGuard,
    std::path::PathBuf,
    std::path::PathBuf,
    Vec<OwnedAceGrant>,
    impl Drop,
) {
    let guard = TestDirGuard::create(label);
    let workspace = guard.path().to_path_buf();
    let target = workspace.join(TARGET_REL);
    std::fs::create_dir_all(target.parent().expect("target has a parent"))
        .expect("create target dirs");
    std::fs::write(&target, MARKER).expect("create the target");
    for i in 0..64 {
        std::fs::write(workspace.join(format!("f{i:03}.txt")), b"x").expect("fill the tree");
    }

    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed ({e:?})"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("the initial preparation must finish");

    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let cleanup = scopeguard({
        let canonical = canonical.clone();
        move || cleanup_workspace(&canonical)
    });
    let grants = workspace_grants(&canonical);
    make_unreachable(&target, &grants);
    (guard, workspace, canonical, grants, cleanup)
}

/// **最上位のシェルに注入できないときは、レーンに乗せず全walkを待って起動する。**
///
/// ここが「注入できないプロセスは待たされるので既定にしてよい」の根拠そのものである。
/// 測るのは2つ——**コマンドが成功すること**と、**割り込みが1件も起きていないこと**。
/// 後者を見ないと、「実はレーンに乗っていた」場合と区別できない（`B-35`）。
#[test]
#[ignore = "spawns a real AppContainer child and changes real ACLs; run NON-elevated with --test-threads=1"]
fn an_uninjectable_top_level_shell_waits_for_the_full_walk_instead_of_faulting() {
    let (_guard, workspace, canonical, grants, _cleanup) =
        prepared_workspace_with_one_unreachable_file("lazy-noinject-top");

    // 背景ジョブをlazyレーンで起こす（受付が開く）。
    let started = grant_job::start(grant_job::GrantJobRequest {
        root: &canonical,
        ace_grants: grants.clone(),
        protect_sids: Vec::new(),
        skip: vec![canonical.join(".harness")],
        workspace: &canonical,
        mode: "rwx",
        capability_generation: "noinject-top-generation",
        lane: grant_job::PreparationLane::Lazy,
    });
    assert!(started, "the lazy job must start");
    assert!(
        grant_job::lazy_broker_pipe_for(&canonical, "rwx").is_some(),
        "the receiver must be open, otherwise this test would pass for the wrong reason"
    );

    // **シェルそのものを注入の対象外にする。** これが「注入できないプロセス」の作り方。
    let (shell, _) = resolve_shell();
    let shell = shell.to_string();
    let shell_name = std::path::Path::new(&shell)
        .file_name()
        .expect("the shell has a file name")
        .to_string_lossy()
        .into_owned();
    std::env::set_var(lazy_grant::NO_INJECT_ENV, &shell_name);
    let _restore = scopeguard(|| std::env::remove_var(lazy_grant::NO_INJECT_ENV));

    let request = WorkspaceSpawn {
        cwd: workspace.clone(),
        env: crate::secret_env::build_child_env(),
        workspace_root: workspace.clone(),
        cow_diff_layer_dir: None,
        granted_passthrough: Vec::new(),
        net_capability: NetworkCapability::Deny,
    };
    let (child, _) = spawn_shell_in_workspace(request).expect("the production launch path");
    let command = format!("Get-Content -Raw '{}\\{TARGET_REL}'", workspace.display());
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(Some(command.as_bytes()))
        .expect("read the child output");
    eprintln!("[no-inject top] exit={code}\nstdout={stdout}\nstderr={stderr}");

    grant_job::wait_until_done().expect("the lazy job must finish");
    let progress = grant_job::progress().expect("the job leaves progress behind");

    assert!(
        stdout.contains(MARKER),
        "the command must still succeed -- it just waits instead of faulting \
         (exit={code}, stderr={stderr})"
    );
    assert_eq!(
        progress.broker_faults_served,
        Some(0),
        "the receiver was open but must have served nothing: the shell was excluded from \
         injection, so the launcher must have waited for the full walk instead of taking \
         the lane. Some(n>0) would mean it took the lane after all: {progress:?}"
    );
}

/// **子孫に注入できないときも、待ってから動くので失敗しない。**
///
/// # ここで「待った」と言い切れる理由（時間を測っていないのに）
///
/// 注入されなかった子孫は**フックを持たない**。フックが無ければ受付へ要求を出す手段が
/// 無いので、**割り込みで許可を付けてもらうことは原理的にできない**。それでも
/// ファイルが読めたなら、読めた理由は1つしかない——**動き出す前にツリーが配り終わっていた**、
/// つまり待ったからである。
///
/// 対で見る（`B-35`）——同じ子孫を**注入の対象外にしなければ読める**ことも確かめる。
/// そうしないと「そもそも読めないツリーだった」場合と区別できない。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn an_uninjectable_descendant_waits_for_the_preparation_instead_of_being_denied() {
    let (_guard, workspace, canonical, grants, _cleanup) =
        prepared_workspace_with_one_unreachable_file("lazy-noinject-desc");

    // **受付とwriterを自分で持つ。** 背景ジョブに任せると走査が数ミリ秒で終わってしまい、
    // 子が「待つ」ところへ来る前に受付が閉じる——それでは**待ちを測れない**
    // （最初にこの形で書いて、実際に測れていなかった）。
    let mut writer = lazy_grant::writer::AclWriter::start(canonical.clone(), grants.clone());
    let capabilities: Vec<String> = grants
        .iter()
        .filter_map(|g| crate::win_common::sid_to_string(g.sid.as_psid()).ok())
        .collect();
    let mut broker = lazy_grant::broker::Broker::start(
        lazy_grant::broker::FaultPolicy {
            canonical_workspace: canonical.clone(),
            skip: vec![canonical.join(".harness")],
            mode: "rwx".to_string(),
        },
        writer.handle(),
        &capabilities,
    )
    .expect("the receiver must open");
    let pipe = broker.pipe_name().to_string();

    let session = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("the session profile must exist");
    let workspace_cap =
        workspace_capability_sid(&canonical, "rwx").expect("the rwx capability must exist");
    let (shell, _) = resolve_shell();
    let shell = shell.to_string();

    // 子孫（cmd.exe）に未準備のファイルを読ませる。親は注入されている。
    let script = format!(
        r#"$ErrorActionPreference='SilentlyContinue'
$out = & cmd.exe /c "type ""{}\{TARGET_REL}"""
if ("$out" -match '{MARKER}') {{ Write-Output 'descendant=ok' }} else {{ Write-Output 'descendant=denied' }}"#,
        workspace.display()
    );
    let run = |excluded: Option<&str>| -> String {
        match excluded {
            Some(name) => std::env::set_var(lazy_grant::NO_INJECT_ENV, name),
            None => std::env::remove_var(lazy_grant::NO_INJECT_ENV),
        }
        let child = spawn_with_workspace(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            &workspace,
            &crate::secret_env::build_child_env(),
            false,
            session.as_psid(),
            NetworkCapability::Deny,
            RedirectorInject::lazy(&canonical, &pipe),
            &[workspace_cap.as_psid()],
            DomainIdentity::Capability(workspace_cap.as_psid()),
        )
        .expect("spawn the probe");
        let (stdout, stderr, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("read the probe output");
        eprintln!("[no-inject desc excluded={excluded:?}] exit={code}\n{stdout}\n{stderr}");
        stdout
    };

    // 許可側を先に（`B-35`）——外さなければ子孫は読める。
    let allowed = run(None);
    assert!(
        allowed.contains("descendant=ok"),
        "without the exclusion the descendant must be able to fault in the file; \
         otherwise the denial below proves nothing:\n{allowed}"
    );

    // 対象の1件はもう付与されてしまったので、測り直すために剥がし直す。
    make_unreachable(&workspace.join(TARGET_REL), &grants);

    // --- 本題: 外した子孫が「待つ」こと ---
    //
    // **順序が測定そのものである。** 子を起こしてから十分に待ち、その間に
    // 対象へACEを付ける。**待たない実装なら、付ける前に読んで拒否される。**
    // 待つ実装なら、`release_waiters`まで動き出さないので、付いた後に読んで成功する。
    std::env::set_var(lazy_grant::NO_INJECT_ENV, "cmd.exe");
    let probe = {
        let script = script.clone();
        let workspace = workspace.clone();
        let canonical = canonical.clone();
        let pipe = pipe.clone();
        let shell = shell.clone();
        let session = session.as_psid();
        let cap = workspace_cap.as_psid();
        // `PSID`は`Send`ではないが、値は単なるポインタで、指す先はこの関数のスコープが
        // 生かしている。スレッドはこの関数を出る前にjoinする。
        let session = crate::win_common::SendHandle(windows::Win32::Foundation::HANDLE(session.0));
        let cap = crate::win_common::SendHandle(windows::Win32::Foundation::HANDLE(cap.0));
        std::thread::spawn(move || {
            let session = session;
            let cap = cap;
            let child = spawn_with_workspace(
                &shell,
                &["-NoProfile", "-NonInteractive", "-Command", &script],
                &workspace,
                &crate::secret_env::build_child_env(),
                false,
                PSID(session.0 .0),
                NetworkCapability::Deny,
                RedirectorInject::lazy(&canonical, &pipe),
                &[PSID(cap.0 .0)],
                DomainIdentity::Capability(PSID(cap.0 .0)),
            )
            .expect("spawn the excluded probe");
            child
                .write_stdin_read_output_and_wait(None)
                .map(|(stdout, _, _)| stdout)
                .unwrap_or_default()
        })
    };

    // **待たない実装なら、この間に読み終えて拒否されている。**
    std::thread::sleep(std::time::Duration::from_secs(5));
    // 走査が対象へ到達したのと同じことを手で行い、待ち手を起こす。
    writer
        .handle()
        .grant_now(vec![lazy_grant::writer::Node::file(
            workspace.join(TARGET_REL),
        )])
        .expect("the writer is available")
        .expect("the target must be granted");
    broker.release_waiters(true);

    let excluded = probe.join().expect("the probe thread must not panic");
    std::env::remove_var(lazy_grant::NO_INJECT_ENV);
    let _ = broker.stop();
    let _ = writer.stop_at_safe_point();

    assert!(
        excluded.contains("descendant=ok"),
        "an excluded descendant has no hook, so it cannot fault anything in. It only reads the \
         file if it was still suspended when we granted it -- that is, if it waited. \
         A denial means it was resumed too early:\n{excluded}"
    );
}
