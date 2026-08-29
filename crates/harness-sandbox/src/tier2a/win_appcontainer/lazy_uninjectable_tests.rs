//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）受入1「状態機械」のfault injection]
//! **DLLを注入できないプロセスがどうなるか**を、注入を意図的に外して実機で測る。
//!
//! # なぜこれを測るのか
//!
//! レーンを既定に上げてよい理由として「注入できないプロセスは待たされるだけだから安全」と
//! 言えるかどうかが、ここで決まる。**言えるのは半分だけ**である——起動側で決まる話と、
//! 子孫で起きる話が別だからで、それを2本のテストに分けて固定する。
//!
//! ```text
//! 起動側（最上位のシェル）を外す  → レーンに乗せない → 全walkを待って起動 → 成功
//! 子孫を外す                      → その子孫にはフックが無い → 未準備アクセスは拒否
//! ```
//!
//! **この非対称は機構から来ている。** 待つかどうかを決めるのは起動側であり、
//! **子孫が起きる頃には起動側の判断はもう終わっている**。あとから「やっぱり待つ」へは戻れない。
//!
//! # どちらも境界の穴ではない（D-01）
//!
//! 外したプロセスが失うのは透過性だけで、ACLの拒否はそのまま残る。**失敗する方向へ倒れる**
//! ので、権限が広がることはない。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 lazy_uninjectable
//! ```

use super::test_support::{scopeguard, TestDirGuard};
use super::*;
use crate::tier2a::workspace_ledger::WorkspaceMode;

const TARGET_REL: &str = r"late\deep\target.txt";
const MARKER: &str = "lazy-uninjectable-marker";

fn workspace_grants(canonical_ws: &std::path::Path) -> Vec<OwnedAceGrant> {
    WorkspaceMode::ALL
        .iter()
        .map(|mode| OwnedAceGrant {
            sid: workspace_capability_sid(canonical_ws, mode.as_str())
                .expect("the workspace capability must exist after preflight"),
            mask: workspace_mode_mask(*mode),
        })
        .collect()
}

fn make_unreachable(path: &std::path::Path, grants: &[OwnedAceGrant]) {
    super::test_support::protect_dacl_preserve_inherited(path).expect("protect the node's dacl");
    let sids: Vec<PSID> = grants.iter().map(|g| g.sid.as_psid()).collect();
    revoke::revoke_sids_from_node(path, &sids).expect("strip the capability aces");
    assert!(
        revoke::sid_effective_ace_masks(path, &sids)
            .expect("read back the dacl")
            .iter()
            .all(Option::is_none),
        "the setup must actually make {} unreachable",
        path.display()
    );
}

fn cleanup_workspace(canonical_ws: &std::path::Path) {
    let sids: Vec<crate::win_common::OwnedSid> = WorkspaceMode::ALL
        .iter()
        .filter_map(|mode| workspace_capability_sid(canonical_ws, mode.as_str()).ok())
        .collect();
    if canonical_ws.exists() {
        let psids: Vec<PSID> = sids.iter().map(|s| s.as_psid()).collect();
        let _ = revoke::revoke_workspace_sids_recursive(canonical_ws, &psids, &|_, _| {});
    }
    let _ = crate::tier2a::workspace_capability::forget_capability(canonical_ws, "");
}

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

/// **子孫に注入できないときは、待たされるのではなく拒否される。**
///
/// これは欠陥ではなく機構の帰結で、**既定へ上げる判断のときに知っておくべき限界**である
/// （モジュールdocの非対称）。ここを「いつか直す」と書かずに固定しておくのは、
/// 直っていないことを緑のテストで隠さないためである。
///
/// 対で見る（`B-35`）——同じ子孫を**注入の対象外にしなければ読める**ことを先に確かめる。
/// そうしないと、「そもそも読めないツリーだった」場合と区別できない。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn an_uninjectable_descendant_is_denied_rather_than_made_to_wait() {
    let (_guard, workspace, canonical, grants, _cleanup) =
        prepared_workspace_with_one_unreachable_file("lazy-noinject-desc");

    let started = grant_job::start(grant_job::GrantJobRequest {
        root: &canonical,
        ace_grants: grants.clone(),
        protect_sids: Vec::new(),
        skip: vec![canonical.join(".harness")],
        workspace: &canonical,
        mode: "rwx",
        capability_generation: "noinject-desc-generation",
        lane: grant_job::PreparationLane::Lazy,
    });
    assert!(started, "the lazy job must start");
    let pipe = grant_job::lazy_broker_pipe_for(&canonical, "rwx").expect("the receiver must open");

    let session = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("the session profile must exist");
    let workspace_cap =
        workspace_capability_sid(&canonical, "rwx").expect("the rwx capability must exist");
    let (shell, _) = resolve_shell();

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

    let excluded = run(Some("cmd.exe"));
    std::env::remove_var(lazy_grant::NO_INJECT_ENV);
    assert!(
        excluded.contains("descendant=denied"),
        "an excluded descendant has no hook, so its unprepared access must be DENIED \
         -- it is not made to wait. This is the documented asymmetry, not a bug:\n{excluded}"
    );
}
