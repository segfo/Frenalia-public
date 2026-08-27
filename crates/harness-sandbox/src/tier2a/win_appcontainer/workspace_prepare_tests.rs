//! 明示的workspace準備の実Win32回帰。RWX/ROの許可側と`.harness`拒否側、初回と再利用を対で測る。

use super::test_support::{scopeguard, TestDirGuard};
use super::*;

fn exercise(mode: WorkspaceAclMode, label: &str) {
    let tree = TestDirGuard::create(label);
    let root = tree.path().canonicalize().expect("canonical workspace");
    let ordinary = root.join("src").join("existing.txt");
    let control = root.join(".harness").join("settings.json");
    std::fs::create_dir_all(ordinary.parent().unwrap()).expect("create ordinary branch");
    std::fs::create_dir_all(control.parent().unwrap()).expect("create control branch");
    std::fs::write(&ordinary, b"ordinary").expect("write ordinary fixture");
    std::fs::write(&control, b"control").expect("write control fixture");

    assert_eq!(
        workspace_preparation_state(&root, mode).expect("initial state"),
        WorkspacePreparationState::Unprepared
    );
    let first = start_workspace_preparation(&root, mode).expect("start first preparation");
    assert_eq!(first.state_before, WorkspacePreparationState::Unprepared);
    assert!(
        first.job_started,
        "fresh workspace must start one background job"
    );
    grant_job::wait_for_workspace(&root, mode.as_str()).expect("wait first preparation");

    let cap = workspace_capability_sid(&root, mode.as_str()).expect("resolve prepared capability");
    let cleanup_root = root.clone();
    let cleanup_cap = cap.clone();
    let cleanup_mode = mode.as_str();
    let _cleanup = scopeguard(move || {
        let _ = revoke_ace_recursive(&cleanup_root, cleanup_cap.as_psid());
        crate::tier2a::workspace_capability::forget_capability(&cleanup_root, cleanup_mode);
        crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_root);
    });

    assert_eq!(
        workspace_preparation_state(&root, mode).expect("ready state"),
        WorkspacePreparationState::Ready
    );
    let actual = sid_effective_ace_mask(&ordinary, cap.as_psid())
        .expect("read ordinary DACL")
        .expect("ordinary node must carry capability");
    let required = match mode {
        WorkspaceAclMode::Rwx => workspace_rwx_mask(),
        WorkspaceAclMode::ReadOnly => fs_access_mask(FsAccess::ReadExec),
    };
    assert_eq!(
        actual & required,
        required,
        "the declared access must be present"
    );
    if mode == WorkspaceAclMode::ReadOnly {
        let write_only_bits = workspace_rwx_mask() & !required;
        assert_eq!(
            actual & write_only_bits,
            0,
            "RO preparation must not grant write bits"
        );
    }
    assert_eq!(
        sid_effective_ace_mask(&control, cap.as_psid()).expect("read control DACL"),
        None,
        ".harness must stay outside the workspace capability"
    );

    let second = start_workspace_preparation(&root, mode).expect("repeat preparation");
    assert_eq!(second.state_before, WorkspacePreparationState::Ready);
    assert_eq!(second.state, WorkspacePreparationState::Ready);
    assert!(
        !second.job_started,
        "ready workspace must not start a second tree walk"
    );
}

#[test]
#[ignore = "実NTFS DACLとworkspace capability台帳を使う。非昇格・--test-threads=1で実行する"]
fn explicit_workspace_preparation_is_fail_closed_and_reusable_for_rwx_and_ro() {
    exercise(WorkspaceAclMode::Rwx, "prepare-rwx");
    exercise(WorkspaceAclMode::ReadOnly, "prepare-ro");
}
