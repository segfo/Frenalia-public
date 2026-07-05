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

    let tracked = hardened_git_command(workspace_root)
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

    let status = hardened_git_command(workspace_root)
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

/// harnessが内部的に起動する全`git`が経由するハードニング済みコマンドビルダ（D-06、
/// `plans/DESIGN-SANDBOX.md` §7）。TB5（悪意ある`.git/config`/hooks/`.gitattributes`を
/// 含むリポジトリ）に対し、注入されたhooks/alias/pagerを無効化する:
/// `GIT_CONFIG_NOSYSTEM=1`+空のglobal/systemconfig+`-c core.hooksPath=<空dir>`+
/// `-c core.fsmonitor=false`+`--no-pager`。envはallowlist方式のクリーンenv
/// （`secret_env::build_child_env`、D-07）に統一する。
fn hardened_git_command(workspace_root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.env_clear();
    for (k, v) in crate::secret_env::build_child_env() {
        cmd.env(k, v);
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", empty_config_path());
    cmd.env("GIT_CONFIG_SYSTEM", empty_config_path());
    cmd.arg("--no-pager")
        .arg("-c")
        .arg(format!("core.hooksPath={}", empty_hooks_dir().display()))
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-C")
        .arg(workspace_root);
    cmd
}

/// 空の（存在しない）configファイルパス。`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`へ向けることで
/// ユーザ/システムconfigの読み込みを無効化する（gitは存在しないconfigパスを黙って無視する）。
fn empty_config_path() -> std::path::PathBuf {
    std::env::temp_dir().join("harness-empty-git-config")
}

/// 空のhooksディレクトリ。存在しなければ作成する（作成失敗時もgitがhooksPath不在を無視して
/// 続行するため致命的ではない）。
fn empty_hooks_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("harness-empty-git-hooks");
    let _ = std::fs::create_dir_all(&dir);
    dir
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
