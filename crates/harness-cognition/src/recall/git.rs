//! Recallの記憶ディレクトリのgit履歴化。`plans/PLAN-RECALL-MEMORY.md`「git履歴化」。
//!
//! **ここで起動するgitは必ず[`harness_core::git::hardening_env`]を経由する**
//! （設計変更A）。記憶ディレクトリは`data_dir()`配下（ワークスペース外）にあるが、
//! Tier0/Tier1（隔離なし）では`run_shell`の子プロセスがharnessと同一ユーザー権限で動くため、
//! ワークスペース内に`.git/hooks/post-commit`を仕込まれたリポジトリをモデルに操作させれば
//! （あるいは記憶ディレクトリへ直接到達できれば）、次のcheckpoint書込みのたびに任意コードが
//! 実行される経路になり得る。ハードニングenvはこの経路を構造的に塞ぐ。

use std::path::Path;
use std::process::Command;

/// このマシンに`git`があるか（`PATH`解決）。
pub(crate) fn git_available() -> bool {
    which::which("git").is_ok()
}

/// `dir`が`.git/`を持たなければ`git init`する。
pub(crate) fn ensure_repo(dir: &Path) -> Result<(), String> {
    if dir.join(".git").exists() {
        return Ok(());
    }
    run(dir, &["init", "--quiet"])
}

/// `git add -A && git commit`。**変更が無い場合は成功扱い**（初回オープン直後の空リポジトリ等）。
pub(crate) fn commit_all(dir: &Path, message: &str) -> Result<(), String> {
    run(dir, &["add", "-A"])?;
    match run(dir, &["commit", "--quiet", "-m", message]) {
        Ok(()) => Ok(()),
        Err(e) if e.contains("nothing to commit") => Ok(()),
        Err(e) => Err(e),
    }
}

fn run(dir: &Path, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).args(args);
    // allowlist方式のクリーンenv + gitハードニング（設計変更A）。`run_shell`のモデル実行・
    // `resolve.rs`の内部`git merge-file`と同じ定義を共有する（`harness_core::git`のdoc参照）。
    for (k, v) in harness_core::git::hardening_env() {
        cmd.env(k, v);
    }
    cmd.env(
        "GIT_AUTHOR_NAME",
        std::env::var("GIT_AUTHOR_NAME").unwrap_or_else(|_| "harness".to_string()),
    );
    cmd.env(
        "GIT_AUTHOR_EMAIL",
        std::env::var("GIT_AUTHOR_EMAIL").unwrap_or_else(|_| "harness@localhost".to_string()),
    );
    cmd.env("GIT_COMMITTER_NAME", "harness");
    cmd.env("GIT_COMMITTER_EMAIL", "harness@localhost");

    let output = cmd.output().map_err(|e| format!("failed to run git: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} failed: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skip_if_no_git() -> bool {
        if !git_available() {
            eprintln!("skipping: git not found in PATH");
            return true;
        }
        false
    }

    #[test]
    fn ensure_repo_is_idempotent() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        assert!(dir.path().join(".git").exists());
        // 2回目も成功する（既に`.git`があれば何もしない）。
        ensure_repo(dir.path()).unwrap();
    }

    #[test]
    fn commit_all_records_a_new_file() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        commit_all(dir.path(), "checkpoint: test").unwrap();

        let log = Command::new("git")
            .current_dir(dir.path())
            .args(["log", "--oneline"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&log.stdout).contains("checkpoint: test"));
    }

    /// commit対象が無いとき（2回連続で同じ状態でcommit）もエラーにしない。
    #[test]
    fn commit_all_is_a_no_op_when_there_is_nothing_to_commit() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        commit_all(dir.path(), "first").unwrap();
        commit_all(dir.path(), "second").unwrap();
    }

    /// `.git/hooks/post-commit`を仕込んでも実行されない（設計変更A、`core.hooksPath`を
    /// 存在しないパスへ向けるハードニング）。
    #[test]
    fn hooks_do_not_fire() {
        if skip_if_no_git() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        ensure_repo(dir.path()).unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let marker = dir.path().join("HOOK_FIRED");
        #[cfg(windows)]
        let hook_body = format!(
            "#!/bin/sh\necho fired > \"{}\"\n",
            marker.to_string_lossy().replace('\\', "/")
        );
        #[cfg(not(windows))]
        let hook_body = format!("#!/bin/sh\necho fired > '{}'\n", marker.display());
        let hook_path = hooks_dir.join("post-commit");
        std::fs::write(&hook_path, hook_body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&hook_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&hook_path, perms).unwrap();
        }

        std::fs::write(dir.path().join("b.txt"), "x").unwrap();
        commit_all(dir.path(), "checkpoint: hook test").unwrap();

        assert!(!marker.exists(), "post-commit hook fired despite hardening env");
    }
}
