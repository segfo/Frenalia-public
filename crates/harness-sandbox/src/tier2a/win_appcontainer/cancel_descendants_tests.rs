//! 段階5cのTier2a実機安全網。実ACLを変更するため昇格ランナーから直列実行する。

use super::test_support::{cleanup_workspace, spawn_in_workspace, TestDirGuard};
use super::*;
use crate::cancel_descendants::{
    assert_cancel_completes, prepare_descendant, DescendantOutput, DescendantProbe,
};

struct Tier2Case {
    child: Option<AppContainerChild>,
    descendant: Option<DescendantProbe>,
    canonical_workspace: std::path::PathBuf,
    dir: Option<TestDirGuard>,
}

impl Drop for Tier2Case {
    fn drop(&mut self) {
        // 失敗時もこの順で落とす。子と孫がworkspaceを使い終えてからACE・台帳・実体を消す。
        drop(self.child.take());
        drop(self.descendant.take());
        cleanup_workspace(&self.canonical_workspace);
        drop(self.dir.take());
    }
}

fn setup(output: DescendantOutput, session: bool) -> Tier2Case {
    let label = match (session, output) {
        (false, DescendantOutput::RedirectedToFile) => "cancel-t3a",
        (false, DescendantOutput::Inherited) => "cancel-t3b",
        (true, DescendantOutput::RedirectedToFile) => "cancel-t4a",
        (true, DescendantOutput::Inherited) => "cancel-t4b",
    };
    let guard = TestDirGuard::create(label);
    let workspace = guard.path().to_path_buf();
    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed: {e:?}"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("workspace preparation must finish");
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let profile = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile must exist");
    let shell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string();
    let (script, pid_file) = prepare_descendant(&workspace, output, true);
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        &workspace,
        &crate::secret_env::build_child_env(),
        session,
        profile.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn Tier2a parent");
    let descendant = DescendantProbe::wait_for_pid_file(&pid_file);
    descendant.assert_alive();
    Tier2Case {
        child: Some(child),
        descendant: Some(descendant),
        canonical_workspace: canonical,
        dir: Some(guard),
    }
}

fn run_one_shot(output: DescendantOutput) {
    let mut case = setup(output, false);
    let child = case.child.take().expect("case owns its child");
    let kill = child.kill_token().expect("duplicate Tier2a Job handle");
    assert_cancel_completes("Tier2a one-shot cancellation", move || {
        kill.kill();
        let _ = child.write_stdin_read_output_and_wait(None);
    });
    case.descendant
        .as_ref()
        .expect("case owns its descendant probe")
        .assert_exited_after_cancel();
}

fn run_session(output: DescendantOutput) {
    let mut case = setup(output, true);
    let child = case.child.take().expect("case owns its child");
    let mut session = child.into_session().expect("convert child into session");
    assert_cancel_completes("Tier2a session shutdown", move || session.shutdown());
    case.descendant
        .as_ref()
        .expect("case owns its descendant probe")
        .assert_exited_after_cancel();
}

#[test]
#[ignore = "changes real ACLs and spawns a real AppContainer descendant; run through cancel-descendants"]
fn t3a_tier2a_one_shot_cancel_kills_descendant_with_redirected_output() {
    run_one_shot(DescendantOutput::RedirectedToFile);
}

#[test]
#[ignore = "changes real ACLs and spawns a real AppContainer descendant; run through cancel-descendants"]
fn t3b_tier2a_one_shot_cancel_kills_descendant_with_inherited_output() {
    run_one_shot(DescendantOutput::Inherited);
}

#[test]
#[ignore = "changes real ACLs and spawns a real AppContainer descendant; run through cancel-descendants"]
fn t4a_tier2a_session_shutdown_kills_descendant_with_redirected_output() {
    run_session(DescendantOutput::RedirectedToFile);
}

#[test]
#[ignore = "changes real ACLs and spawns a real AppContainer descendant; run through cancel-descendants"]
fn t4b_tier2a_session_shutdown_kills_descendant_with_inherited_output() {
    run_session(DescendantOutput::Inherited);
}
