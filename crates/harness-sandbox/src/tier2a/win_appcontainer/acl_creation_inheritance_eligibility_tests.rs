//! 作成時継承案の適用範囲を、実 `git worktree add`・cargo生成物・move-in・保護DACL・
//! reparse pointで確かめる。費用測定とは分け、ここでは真偽だけを固定する。

use std::path::Path;
use std::process::Command;

use super::test_support::{protect_dacl_preserve_inherited, scopeguard, TestDirGuard};
use super::*;

fn run(program: &str, args: &[&str], cwd: &Path) {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn has_complete_mask(
    path: &Path,
    sid: windows::Win32::Security::PSID,
    required: u32,
) -> bool {
    sid_effective_ace_mask(path, sid)
        .expect("read effective ACE")
        .is_some_and(|mask| mask & required == required)
}

fn assert_tree_reached(
    root: &Path,
    sid: windows::Win32::Security::PSID,
    required: u32,
) -> usize {
    let mut pending = vec![root.to_path_buf()];
    let mut checked = 0usize;
    while let Some(path) = pending.pop() {
        assert!(
            has_complete_mask(&path, sid, required),
            "{} did not inherit the complete workspace capability",
            path.display()
        );
        checked += 1;
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("read generated tree") {
                let entry = entry.expect("read generated entry");
                if !entry.file_type().expect("entry type").is_symlink() {
                    pending.push(entry.path());
                }
            }
        }
    }
    checked
}

#[test]
#[ignore = "実git worktree addとcargo buildを使う作成時継承の適用範囲テスト。非昇格で実行する"]
fn acl_creation_inheritance_handles_generated_worktrees_but_not_move_in() {
    let source = TestDirGuard::create("creation-source");
    let allowed = TestDirGuard::create("creation-allowed");
    let outside = TestDirGuard::create("creation-outside");
    let source_root = source.path();
    let allowed_root = allowed.path();
    let worktree = allowed_root.join("worktree");
    let sid = super::capability_sid_from_name(&format!(
        "harness-creation-eligibility-{}",
        std::process::id()
    ))
    .expect("derive capability");
    let mask = workspace_rwx_mask();

    run("git", &["init", "--quiet"], source_root);
    run("git", &["config", "user.email", "harness-test@example.invalid"], source_root);
    run("git", &["config", "user.name", "Harness Test"], source_root);
    std::fs::create_dir_all(source_root.join("src")).expect("create source dir");
    std::fs::write(
        source_root.join("Cargo.toml"),
        "[package]\nname='acl-inheritance-probe'\nversion='0.0.0'\nedition='2021'\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(source_root.join("src/main.rs"), "fn main() {}\n")
        .expect("write main.rs");
    for index in 0..128 {
        std::fs::write(source_root.join(format!("fixture-{index:03}.txt")), b"x")
            .expect("write fixture");
    }
    run("git", &["add", "."], source_root);
    run("git", &["commit", "--quiet", "-m", "fixture"], source_root);

    grant_workspace_root_rw_fast(allowed_root, sid.as_psid()).expect("grant empty allowed root");
    let cleanup_source = source_root.to_path_buf();
    let cleanup_worktree = worktree.clone();
    let cleanup_root = allowed_root.to_path_buf();
    let cleanup_sid = sid.clone();
    let _cleanup = scopeguard(move || {
        let _ = Command::new("git")
            .args([
                "worktree",
                "remove",
                "--force",
                &cleanup_worktree.to_string_lossy(),
            ])
            .current_dir(&cleanup_source)
            .output();
        let _ = Command::new("git")
            .args(["worktree", "prune"])
            .current_dir(&cleanup_source)
            .output();
        let _ = revoke_ace_recursive(&cleanup_root, cleanup_sid.as_psid());
    });

    run(
        "git",
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            &worktree.to_string_lossy(),
            "HEAD",
        ],
        source_root,
    );
    let worktree_nodes = assert_tree_reached(&worktree, sid.as_psid(), mask);

    run(
        "cargo",
        &[
            "build",
            "--quiet",
            "--manifest-path",
            &worktree.join("Cargo.toml").to_string_lossy(),
            "--target-dir",
            &worktree.join("target").to_string_lossy(),
        ],
        &worktree,
    );
    let after_build_nodes = assert_tree_reached(&worktree, sid.as_psid(), mask);
    assert!(after_build_nodes > worktree_nodes, "cargo must create build artifacts");

    let protected = worktree.join("protected-after-grant");
    std::fs::create_dir_all(&protected).expect("create protected branch");
    protect_dacl_preserve_inherited(&protected).expect("protect branch DACL");
    let protected_child = protected.join("created-after-protection.txt");
    std::fs::write(&protected_child, b"x").expect("create under protected branch");
    assert!(
        has_complete_mask(&protected_child, sid.as_psid(), mask),
        "a protected branch that already carries the capability must pass it to new children"
    );

    let payload = outside.path().join("payload");
    std::fs::create_dir_all(&payload).expect("create move-in payload");
    std::fs::write(payload.join("old.txt"), b"old").expect("write move-in payload");
    let moved = worktree.join("moved-in");
    std::fs::rename(&payload, &moved).expect("same-volume move-in");
    let moved_in_reached = has_complete_mask(&moved.join("old.txt"), sid.as_psid(), mask);
    assert!(
        !moved_in_reached,
        "move-in unexpectedly gained the capability; re-evaluate the documented exclusion"
    );

    let outside_target = outside.path().join("reparse-target");
    std::fs::create_dir_all(&outside_target).expect("create reparse target");
    std::fs::write(outside_target.join("secret.txt"), b"outside").expect("write outside target");
    let reparse_result = std::os::windows::fs::symlink_dir(
        &outside_target,
        worktree.join("outside-link"),
    );
    if reparse_result.is_ok() {
        assert!(
            !has_complete_mask(&outside_target.join("secret.txt"), sid.as_psid(), mask),
            "creating a reparse point must not grant its out-of-tree target"
        );
    }

    println!(
        "{}",
        serde_json::json!({
            "git_worktree_nodes": worktree_nodes,
            "nodes_after_cargo_build": after_build_nodes,
            "protected_branch_new_child_inherited": true,
            "move_in_inherited": moved_in_reached,
            "reparse_point_created": reparse_result.is_ok(),
            "conclusion": "generated-in-place is eligible; same-volume move-in is excluded",
        })
    );
}
