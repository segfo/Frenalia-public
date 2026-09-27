//! レビュー用 worktree の置き場・作成・後始末（D-110 (i)）。
//!
//! # 置き場
//!
//! ハーネスのデータ置き場に置く: 既定は `%LOCALAPPDATA%\harness\data\review\<repo>-<session-id>`、
//! ワークスペースが別のボリュームならそのボリュームの `.harness-review\<repo>-<session-id>`
//! （D-81 の差分層と同じ追従。規則は `harness_sandbox::session_scope::plan_per_volume_root` の
//! 1本を共有する）。**差分層の根（`.harness-cow`・`data\cow`）の下には置かない**——
//! `list_cow_sessions` は根の下のディレクトリを全部セッションと見なす。リポジトリの隣にも
//! 置かない——エディタの「信頼済みフォルダ」は親から継承されるので、開いた瞬間に
//! エージェントが書いた `tasks.json` や `build.rs` が走り得る。
//!
//! # 開いただけで走る設定はディスクへ出さない
//!
//! 追跡パスのうち危険パス（[`is_review_danger_path`]: `harness_core` の10 prefix と
//! `.gitmodules`）は、`update-index --skip-worktree` を立ててから checkout するので、ディスクへ
//! 書き出されない。中身は `git diff` で文字としてだけ見える。
//!
//! 属性は空の tree から読む（`launcher::EMPTY_TREE`）。`.gitattributes` はディスクに無くても
//! index から読まれ、利用者の設定にあるフィルタをエージェントが選べてしまうため。
//!
//! # この機構の限界
//!
//! - skip-worktree は、利用者がこの worktree で別のコミットを checkout すると外れ得る。
//!   そのときに危険パスがディスクへ出るのを止めるものは、エディタ側の制限（VS Code の
//!   Restricted Mode）しか無い。
//! - 利用者が自分の git でこの worktree を操作するとき、属性は index の `.gitattributes`
//!   から読まれる（ハーネスが固定できるのは、ハーネス自身が回す git だけ）。

use std::path::{Path, PathBuf};

use harness_sandbox::session_scope::{
    choose_per_volume_root, per_volume_root_for_workspace, PerVolumePlacement, PerVolumeRoot,
};

use crate::launcher::{GitAt, GitLauncher, RealRepo, ReviewWorktree};
use crate::lifecycle::SessionId;
use crate::ReviewError;

/// レビュー用 worktree の置き場の種類（D-81 の規則へ渡す）。
pub const REVIEW_PLACEMENT: PerVolumePlacement<'static> = PerVolumePlacement {
    per_volume_dirname: ".harness-review",
    what: "review worktree",
    refusal_prefix: "harness review: ",
};

/// `%LOCALAPPDATA%\harness\data\review`。
pub fn review_profile_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.data_local_dir().join("review"))
}

/// このワークスペースのレビュー用 worktree を置く根を選び、作る（本番の入口）。
/// 降格したら理由が `fell_back` に入る——**呼び出し側は必ず表示する**。
pub fn review_root_for_workspace(workspace_root: &Path) -> Result<PerVolumeRoot, String> {
    let profile = review_profile_root()
        .ok_or_else(|| "harness review: could not resolve %LOCALAPPDATA%".to_string())?;
    per_volume_root_for_workspace(workspace_root, profile, REVIEW_PLACEMENT)
}

/// 後始末のときに見る根の候補（何も作らない）。作ったときにボリューム側へ置けたか降格したかは
/// その時点でしか分からないので、両方を見る。
pub fn review_root_candidates(workspace_root: &Path) -> Vec<PathBuf> {
    let Some(profile) = review_profile_root() else {
        return Vec::new();
    };
    let mut roots = vec![profile.clone()];
    if let Ok(chosen) = choose_per_volume_root(workspace_root, &profile, REVIEW_PLACEMENT) {
        if chosen.root != profile {
            roots.push(chosen.root);
        }
    }
    roots
}

/// worktree のフォルダ名（`<repo>-<session-id>`）。作る側と消す側が同じこの関数を使う。
pub fn worktree_dir_name(workspace_root: &Path, sid: &SessionId) -> String {
    const MAX_REPO_CHARS: usize = 40;
    let repo: String = workspace_root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(MAX_REPO_CHARS)
        .collect();
    let repo = if repo.is_empty() {
        "workspace".to_string()
    } else {
        repo
    };
    format!("{repo}-{}", sid.as_str())
}

/// worktree のディスクへ書き出さないパスか（D-110 (i)）。
///
/// 判定は `harness_core::is_config_injection_path`（層3 hard-deny と同じ10 prefix。
/// 大小・区切り・8.3 短縮名の別名まで扱い、判定できない形は「危険」へ倒す）に、
/// `.gitmodules` を足したもの。
pub fn is_review_danger_path(path: &str) -> bool {
    harness_core::is_config_injection_path(path, Path::new(""))
        || path.eq_ignore_ascii_case(".gitmodules")
}

/// `tip` を checkout したレビュー用 worktree を `path` に作る。書き出さなかった危険パスを返す。
pub(crate) fn create_review_worktree(
    launcher: &GitLauncher,
    real: &RealRepo,
    path: &Path,
    tip: &str,
) -> Result<(ReviewWorktree, Vec<String>), ReviewError> {
    if path.exists() {
        return Err(ReviewError::Refused(format!(
            "{} already exists and is not a review worktree of this repository; remove it first",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ReviewError::io(parent, e))?;
    }
    let mut add: Vec<std::ffi::OsString> = vec![
        "worktree".into(),
        "add".into(),
        "--quiet".into(),
        "--no-checkout".into(),
        "--detach".into(),
    ];
    add.push(path.as_os_str().to_os_string());
    add.push(tip.into());
    launcher.run_ok(GitAt::Real(real), &add, None)?;
    let worktree = ReviewWorktree {
        path: path.to_path_buf(),
    };
    let at = || GitAt::Worktree(&worktree);

    // index だけを作る（ファイルはまだ書かない）。
    launcher.run_ok(at(), &["read-tree", tip], None)?;
    let listed = launcher.run_ok(at(), &["ls-files", "-z", "-s"], None)?;
    let withheld: Vec<String> = listed
        .stdout
        .split(|b| *b == 0)
        .filter_map(|entry| {
            let (_, path) = entry.split_at(entry.iter().position(|b| *b == b'\t')? + 1);
            Some(String::from_utf8_lossy(path).into_owned())
        })
        .filter(|p| is_review_danger_path(p))
        .collect();
    if !withheld.is_empty() {
        let mut input = Vec::new();
        for p in &withheld {
            input.extend_from_slice(p.as_bytes());
            input.push(0);
        }
        launcher.run_ok(
            at(),
            &["update-index", "-z", "--skip-worktree", "--stdin"],
            Some(&input),
        )?;
    }
    // skip-worktree の項目は書き出されない（`--ignore-skip-worktree-bits` を付けない限り）。
    launcher.run_ok(at(), &["checkout-index", "-a", "-u"], None)?;

    // 検算: 書き出した状態がコミットと一致している（ずれていれば、見せているものが嘘になる）。
    let status = launcher.run_ok(
        at(),
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
        None,
    )?;
    if !status.stdout.is_empty() {
        return Err(ReviewError::Mismatch(format!(
            "the review worktree does not match {tip}: {}",
            String::from_utf8_lossy(&status.stdout).replace('\0', " | ")
        )));
    }
    for p in &withheld {
        if path.join(p).exists() {
            return Err(ReviewError::Mismatch(format!(
                "{p} was written into the review worktree although it is withheld"
            )));
        }
    }
    Ok((worktree, withheld))
}

/// 本物に登録された worktree のうち、`candidates` のどれかと同じ場所のもの。
///
/// 突き合わせは**計算した場所との完全一致**（大小・区切り・`\\?\` を揃えたうえで）で行い、
/// フォルダ名だけでは選ばない——利用者自身の worktree を巻き込まないため。
pub(crate) fn registered_worktrees(
    launcher: &GitLauncher,
    real: &RealRepo,
    candidates: &[PathBuf],
) -> Result<Vec<PathBuf>, ReviewError> {
    let out = launcher.run_ok(
        GitAt::Real(real),
        &["worktree", "list", "--porcelain", "-z"],
        None,
    )?;
    let wanted: Vec<String> = candidates.iter().map(|p| path_key(p)).collect();
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter_map(|line| line.strip_prefix(b"worktree "))
        .map(|p| PathBuf::from(String::from_utf8_lossy(p).into_owned()))
        .filter(|p| wanted.contains(&path_key(p)))
        .collect())
}

/// 登録された worktree を消す。フォルダが既に無ければ、登録だけを掃除する。
pub(crate) fn remove_worktree(
    launcher: &GitLauncher,
    real: &RealRepo,
    path: &Path,
) -> Result<(), ReviewError> {
    if path.exists() {
        let mut args: Vec<std::ffi::OsString> = vec![
            "worktree".into(),
            "remove".into(),
            "--force".into(),
            "--force".into(),
        ];
        args.push(path.as_os_str().to_os_string());
        launcher.run_ok(GitAt::Real(real), &args, None)?;
    } else {
        // フォルダが無い登録だけを掃く。`prune` はフォルダの無い登録にしか触れない。
        launcher.run_ok(GitAt::Real(real), &["worktree", "prune"], None)?;
    }
    if path.exists() {
        return Err(ReviewError::Mismatch(format!(
            "{} is still present after removing the worktree (is a file open in an editor?)",
            path.display()
        )));
    }
    if !registered_worktrees(launcher, real, &[path.to_path_buf()])?.is_empty() {
        return Err(ReviewError::Mismatch(format!(
            "{} is still registered as a worktree after removing it",
            path.display()
        )));
    }
    Ok(())
}

fn path_key(path: &Path) -> String {
    let s = path.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.replace('\\', "/").trim_end_matches('/').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn danger_paths_cover_the_injection_prefixes_and_gitmodules_only() {
        for danger in [
            ".github/workflows/x.yml",
            ".vscode/tasks.json",
            ".VSCODE/settings.json",
            ".gitattributes",
            ".gitmodules",
            ".GitModules",
            ".devcontainer/devcontainer.json",
            ".harness/x",
            ".gitlab-ci.yml",
        ] {
            assert!(is_review_danger_path(danger), "{danger}");
        }
        for ordinary in [
            "src/main.rs",
            "README.md",
            "docs/.gitmodules",
            "vscode/x",
            ".github/CODEOWNERS",
        ] {
            assert!(!is_review_danger_path(ordinary), "{ordinary}");
        }
    }

    #[test]
    fn the_worktree_name_keeps_the_session_id_and_tames_the_repo_name() {
        let sid = SessionId::parse("session-0199aaaa-bbbb").unwrap();
        assert_eq!(
            worktree_dir_name(Path::new(r"C:\work\my repo.v2"), &sid),
            "my_repo_v2-session-0199aaaa-bbbb"
        );
        assert_eq!(
            worktree_dir_name(Path::new(r"C:\work\プロジェクト"), &sid),
            "______-session-0199aaaa-bbbb"
        );
    }

    #[test]
    fn worktree_paths_are_compared_after_normalising_their_spelling() {
        assert_eq!(
            path_key(Path::new(r"\\?\C:\Users\X\review\a-session-1\")),
            path_key(Path::new("c:/users/x/review/a-session-1"))
        );
        assert_ne!(
            path_key(Path::new("c:/review/a-session-1")),
            path_key(Path::new("c:/review/a-session-11"))
        );
    }
}
