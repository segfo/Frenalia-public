//! git認識型のステージングモード既定判定。`StagingConfig.explicit == false`の場合、
//! 書込先パス毎に「gitで追跡済みかつ現在変更点ゼロ」を判定し、真なら`live`（`git checkout --
//! <file>`で即座に元へ戻せるため安全）、それ以外は呼び出し側の既定モード
//! （headless=Staged/TUI=WorkspaceCommit）を使う。DESIGN.md本文には明記が無いユーザ確定仕様。

use std::path::Path;
use std::process::Command;

/// `rel`（`workspace_root`からの相対パス）が、gitで追跡済みかつ現在変更点が無い場合のみ
/// `true`を返す。git未導入・非リポジトリ・コマンド失敗はすべて`false`
/// （安全側フォールバック：判定できなければオーバーレイ経由とみなす）。
pub fn is_clean_tracked(workspace_root: &Path, rel: &Path) -> bool {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if rel_str.is_empty() {
        return false;
    }

    let tracked = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg("--")
        .arg(&rel_str)
        .output();
    let Ok(tracked) = tracked else {
        return false;
    };
    if !tracked.status.success() {
        return false;
    }

    let status = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .arg("status")
        .arg("--porcelain")
        .arg("--")
        .arg(&rel_str)
        .output();
    let Ok(status) = status else {
        return false;
    };
    status.status.success() && status.stdout.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command as Cmd;

    fn run(dir: &Path, args: &[&str]) {
        let status = Cmd::new("git").arg("-C").arg(dir).args(args).status();
        if let Ok(s) = status {
            assert!(s.success(), "git {args:?} failed");
        }
    }

    fn git_available() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    #[test]
    fn non_git_directory_is_never_clean_tracked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "1").unwrap();
        assert!(!is_clean_tracked(dir.path(), &PathBuf::from("a.txt")));
    }

    #[test]
    fn tracked_clean_file_is_live_dirty_or_untracked_is_not() {
        if !git_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        run(dir.path(), &["init", "-q"]);
        run(dir.path(), &["config", "user.email", "test@example.com"]);
        run(dir.path(), &["config", "user.name", "test"]);
        std::fs::write(dir.path().join("tracked.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("untracked.txt"), "u").unwrap();
        run(dir.path(), &["add", "tracked.txt"]);
        run(dir.path(), &["commit", "-q", "-m", "init"]);

        assert!(is_clean_tracked(dir.path(), &PathBuf::from("tracked.txt")));
        assert!(!is_clean_tracked(dir.path(), &PathBuf::from("untracked.txt")));

        std::fs::write(dir.path().join("tracked.txt"), "changed").unwrap();
        assert!(!is_clean_tracked(dir.path(), &PathBuf::from("tracked.txt")));
    }
}
