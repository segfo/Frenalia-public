//! コンフリクト解消コマンド（`harness resolve`/TUI`/fsstage resolve`共有ロジック）。
//!
//! `apply()`がbaseline照合の相違で拒否したパス（`ApplyReport.conflicts`）を、`git merge-file`
//! （gitリポジトリを必要としない3ファイル単体の3-way merge）へ橋渡しする。自動マージできない
//! 箇所には標準的なconflict markerが残るので、それをユーザーのエディタで開いて手で解消させる。
//! `plans/e2e-1-2-async-harp.md`「コンフリクト解消コマンド」設計方針参照。
//!
//! CLI（`crates/harness-cli`）とTUI（`crates/harness-tui`）の両方から呼ばれる想定のため、
//! エディタプロセスの起動そのもの（TUIは端末の中断・復帰を挟む必要がある）はこのモジュールの
//! 責務にしない——`prepare_resolve`が3-way mergeまで済ませた`MergeAttempt`一覧を返し、
//! 呼び出し側が`needs_edit`なものだけ`editor_command()`で組み立てたコマンドを自前で起動・待機し、
//! 終了後に`MergeAttempt::finalize`を呼ぶ、という分担にする。

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::changes::ChangeSource;
use crate::manifest::ManifestTarget;
use crate::overlay::{ApplyOptions, ApplyReport, SandboxError, SandboxFs};

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error(
        "git not found in PATH (required for `git merge-file`); resolve these conflicts manually"
    )]
    GitNotFound,
    #[error(
        "no editor configured: set $VISUAL or $EDITOR (Windows falls back to notepad.exe)"
    )]
    NoEditor,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 1件のコンフリクトについて3-way mergeを試みた結果。`needs_edit`が`false`なら完全自動
/// マージ済み（`merged_path`をそのまま`finalize`してよい）。`true`なら`merged_path`に
/// conflict markerが残っているので、呼び出し側がエディタで開いて保存させてから`finalize`
/// すること。
pub struct MergeAttempt {
    pub source: ChangeSource,
    pub target: ManifestTarget,
    /// staged: workspace相対パス（Tree）または絶対パス（Ext）。CoW: workspace相対パス。
    pub path: String,
    /// stagedのみ意味を持つ（オーバーレイ実体の除去・マニフェストprune用）。CoWは空文字列。
    overlay_path: String,
    pub merged_path: PathBuf,
    pub needs_edit: bool,
}

/// baselineミラーが無い等、3-way mergeの材料が揃わずスキップしたコンフリクト。
pub struct SkippedConflict {
    pub source: ChangeSource,
    pub path: String,
    pub reason: String,
}

/// `prepare_resolve`の結果。`_tmp_dir`は`mine`/`base`/`theirs`/`merged`の一時ファイル置き場で、
/// この構造体がdropされる時に自動削除される（設計「一時ファイルを削除する」）。
pub struct PreparedResolve {
    pub attempts: Vec<MergeAttempt>,
    pub skipped: Vec<SkippedConflict>,
    _tmp_dir: tempfile::TempDir,
}

/// `apply()`と同じ経路でコンフリクトを求める（実際に非コンフリクト分はここで実FSへ反映される、
/// 設計「まずapplyと同じ経路でコンフリクト一覧を求める」）。コンフリクトした各パスについて
/// `mine`/`base`/`theirs`を集め`git merge-file`を試みる。`git`がPATHに無ければ、実際に何かを
/// 書く前に`ResolveError::GitNotFound`で即座に失敗する。
pub fn prepare_resolve(
    staged_fs: Option<&SandboxFs>,
    cow: Option<(&Path, &Path)>,
) -> Result<(ApplyReport, PreparedResolve), ResolveError> {
    let report = crate::changes::apply_unified_changes(
        staged_fs,
        cow,
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
        },
    )?;
    if report.conflicts.is_empty() {
        return Ok((
            report,
            PreparedResolve {
                attempts: Vec::new(),
                skipped: Vec::new(),
                _tmp_dir: tempfile::tempdir()?,
            },
        ));
    }

    let git = which::which("git").map_err(|_| ResolveError::GitNotFound)?;
    let tmp_dir = tempfile::tempdir()?;
    let mut attempts = Vec::new();
    let mut skipped = Vec::new();

    if let Some(fs) = staged_fs {
        for e in fs.change_set()? {
            if !report.conflicts.iter().any(|p| p == &e.path) {
                continue;
            }
            match (
                fs.baseline_mirror_content(&e.overlay_path),
                fs.real_content(e.target, &e.path),
            ) {
                (Some(base), Some(theirs)) => {
                    let mine = fs.overlay_content(&e.overlay_path)?;
                    attempts.push(build_merge_attempt(
                        &git,
                        ChangeSource::Staged,
                        e.target,
                        &e.path,
                        &e.overlay_path,
                        &mine,
                        &base,
                        &theirs,
                        tmp_dir.path(),
                    )?);
                }
                _ => skipped.push(no_baseline_skip(ChangeSource::Staged, &e.path)),
            }
        }
    }

    #[cfg(windows)]
    if let Some((upper_dir, workspace_root)) = cow {
        for c in crate::workspace_ledger::read_cow_ledger(upper_dir) {
            if !report.conflicts.iter().any(|p| p == &c.path) {
                continue;
            }
            let base_path = upper_dir
                .join(harness_change_ledger::COW_BASELINE_DIRNAME)
                .join(c.path.replace('/', "\\"));
            let mine_path = upper_dir.join(c.path.replace('/', "\\"));
            let theirs_path = workspace_root.join(c.path.replace('/', "\\"));
            match (
                std::fs::read_to_string(&base_path),
                std::fs::read_to_string(&mine_path),
                std::fs::read_to_string(&theirs_path),
            ) {
                (Ok(base), Ok(mine), Ok(theirs)) => {
                    attempts.push(build_merge_attempt(
                        &git,
                        ChangeSource::Cow,
                        ManifestTarget::Tree,
                        &c.path,
                        "",
                        &mine,
                        &base,
                        &theirs,
                        tmp_dir.path(),
                    )?);
                }
                _ => skipped.push(no_baseline_skip(ChangeSource::Cow, &c.path)),
            }
        }
    }

    Ok((
        report,
        PreparedResolve {
            attempts,
            skipped,
            _tmp_dir: tmp_dir,
        },
    ))
}

fn no_baseline_skip(source: ChangeSource, path: &str) -> SkippedConflict {
    SkippedConflict {
        source,
        path: path.to_string(),
        reason: "no baseline recorded for this path (predates `resolve` support, or created \
                  outside this session); resolve manually (--only to exclude from apply, or \
                  discard it)"
            .to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_merge_attempt(
    git: &Path,
    source: ChangeSource,
    target: ManifestTarget,
    path: &str,
    overlay_path: &str,
    mine: &str,
    base: &str,
    theirs: &str,
    tmp_dir: &Path,
) -> Result<MergeAttempt, ResolveError> {
    let key = sanitize_for_filename(path);
    let mine_path = tmp_dir.join(format!("{key}.mine"));
    let base_path = tmp_dir.join(format!("{key}.base"));
    let theirs_path = tmp_dir.join(format!("{key}.theirs"));
    let merged_path = tmp_dir.join(format!("{key}.merged"));
    std::fs::write(&mine_path, mine)?;
    std::fs::write(&base_path, base)?;
    std::fs::write(&theirs_path, theirs)?;

    // `-p`は結果を標準出力へ出すオプションで、`mine`ファイル自体を書き換えない。
    // D-14b/D-06: harnessが内部起動するgitにもhooks/fsmonitor/pager無効化を適用する
    // （`crate::git_hardening_env`のdoc参照）。envはallowlist方式のクリーンenvへ合成する。
    let mut env = crate::secret_env::build_child_env();
    env.extend(crate::secret_env::git_hardening_env());
    let output = Command::new(git)
        .env_clear()
        .envs(env)
        .arg("merge-file")
        .arg("-p")
        .arg("--diff3")
        .arg(&mine_path)
        .arg(&base_path)
        .arg(&theirs_path)
        .output()?;
    std::fs::write(&merged_path, &output.stdout)?;
    let needs_edit = !output.status.success();

    Ok(MergeAttempt {
        source,
        target,
        path: path.to_string(),
        overlay_path: overlay_path.to_string(),
        merged_path,
        needs_edit,
    })
}

fn sanitize_for_filename(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// `$VISUAL`→`$EDITOR`→（Windowsは`notepad.exe`）の順でエディタコマンドを組み立てる。
/// `$EDITOR`に`"code --wait"`のような引数付き指定が入っている場合は空白区切りで分解する
/// （シェルクォート解釈まではしない——それが必要な変則的な設定はユーザー側の責務とする）。
pub fn editor_command() -> Result<Command, ResolveError> {
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("EDITOR").ok().filter(|s| !s.trim().is_empty()))
        .or_else(|| {
            if cfg!(windows) {
                Some("notepad.exe".to_string())
            } else {
                None
            }
        })
        .ok_or(ResolveError::NoEditor)?;
    let mut parts = editor.split_whitespace();
    let program = parts.next().ok_or(ResolveError::NoEditor)?;
    let mut cmd = Command::new(program);
    cmd.args(parts);
    Ok(cmd)
}

impl MergeAttempt {
    /// エディタでの編集後（または`needs_edit`が`false`ならそのまま）、`merged_path`を読み直し、
    /// 実workspaceへ確定・オーバーレイ/台帳エントリを除去する。`<<<<<<<`等のconflict markerが
    /// まだ残っていても、ユーザーが明示的に保存した内容を最終判断として尊重しそのまま書く
    /// （設計方針4）——ただし残っていた場合はstderrへ警告だけ出す。
    pub fn finalize(
        &self,
        staged_fs: Option<&SandboxFs>,
        cow: Option<(&Path, &Path)>,
    ) -> Result<(), ResolveError> {
        let content = std::fs::read_to_string(&self.merged_path)?;
        if content.contains("<<<<<<<") || content.contains(">>>>>>>") {
            eprintln!(
                "warning: conflict markers remain in {} after edit; applying as-is",
                self.path
            );
        }
        match self.source {
            ChangeSource::Staged => {
                let fs = staged_fs.expect("staged MergeAttempt requires staged_fs");
                fs.finalize_resolved(self.target, &self.path, &self.overlay_path, &content)?;
            }
            ChangeSource::Cow => finalize_cow(cow, &self.path, &content)?,
        }
        Ok(())
    }
}

#[cfg(windows)]
fn finalize_cow(cow: Option<(&Path, &Path)>, path: &str, content: &str) -> Result<(), ResolveError> {
    let (upper_dir, workspace_root) = cow.expect("cow MergeAttempt requires cow upper/workspace");
    let real_abs = workspace_root.join(path.replace('/', "\\"));
    if let Some(parent) = real_abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&real_abs, content)?;
    let _ = crate::workspace_ledger::prune_cow_ledger(upper_dir, std::slice::from_ref(&path.to_string()));
    Ok(())
}

#[cfg(not(windows))]
fn finalize_cow(_cow: Option<(&Path, &Path)>, _path: &str, _content: &str) -> Result<(), ResolveError> {
    unreachable!("CoW MergeAttempt is only constructed under #[cfg(windows)] in prepare_resolve")
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::{StagingConfig, StagingMode};

    fn staged_config(sandbox_dir: &str) -> StagingConfig {
        StagingConfig {
            mode: StagingMode::Staged,
            sandbox_dir: Some(PathBuf::from(sandbox_dir)),
        }
    }

    #[test]
    fn non_overlapping_edits_auto_merge_without_edit() {
        // `git merge-file`のdiff3は隣接する行の変更を1つのhunkとみなし自動マージできない
        // ため、mine/theirsの変更行の間に非変更のcontext行を複数挟む必要がある。
        let dir = tempfile::tempdir().unwrap();
        let base = "line1\nline2\nline3\nline4\nline5\n";
        std::fs::write(dir.path().join("a.txt"), base).unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("a.txt", "line1-mine\nline2\nline3\nline4\nline5\n").unwrap();
        // 外部から実workspaceを直接編集（apply/resolveが検知するTOCTOU相違）。
        std::fs::write(
            dir.path().join("a.txt"),
            "line1\nline2\nline3\nline4\nline5-theirs\n",
        )
        .unwrap();

        let (report, prepared) = prepare_resolve(Some(&fs), None).unwrap();
        assert_eq!(report.conflicts, vec!["a.txt".to_string()]);
        assert!(prepared.skipped.is_empty());
        assert_eq!(prepared.attempts.len(), 1);
        let attempt = &prepared.attempts[0];
        assert!(!attempt.needs_edit, "non-overlapping edits should auto-merge");

        let merged = std::fs::read_to_string(&attempt.merged_path).unwrap();
        assert_eq!(merged, "line1-mine\nline2\nline3\nline4\nline5-theirs\n");

        attempt.finalize(Some(&fs), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "line1-mine\nline2\nline3\nline4\nline5-theirs\n"
        );
        assert!(fs.change_set().unwrap().is_empty());
    }

    #[test]
    fn overlapping_edits_need_manual_edit_with_conflict_markers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "line1\n").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("a.txt", "line1-mine\n").unwrap();
        std::fs::write(dir.path().join("a.txt"), "line1-theirs\n").unwrap();

        let (_report, prepared) = prepare_resolve(Some(&fs), None).unwrap();
        assert_eq!(prepared.attempts.len(), 1);
        let attempt = &prepared.attempts[0];
        assert!(attempt.needs_edit, "overlapping edits must not auto-apply");
        let merged = std::fs::read_to_string(&attempt.merged_path).unwrap();
        assert!(merged.contains("<<<<<<<"));

        // ユーザーがエディタで保存したものと見なして、そのまま確定させる。
        attempt.finalize(Some(&fs), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            merged
        );
    }

    #[test]
    fn missing_baseline_mirror_is_skipped_not_erred() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "original\n").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("a.txt", "mine\n").unwrap();
        // 本機能導入前に発生したコンフリクトを模して、baselineミラーだけを消す。
        std::fs::remove_file(dir.path().join(".harness/sandbox/s1/baseline/a.txt")).unwrap();
        std::fs::write(dir.path().join("a.txt"), "theirs\n").unwrap();

        let (report, prepared) = prepare_resolve(Some(&fs), None).unwrap();
        assert_eq!(report.conflicts, vec!["a.txt".to_string()]);
        assert!(prepared.attempts.is_empty());
        assert_eq!(prepared.skipped.len(), 1);
        assert_eq!(prepared.skipped[0].path, "a.txt");
    }

    #[test]
    fn editor_command_falls_back_through_visual_editor_env() {
        // $VISUAL/$EDITORをテスト間で共有するグローバル環境変数への書込は、他のテストと
        // 並行実行されると競合するため、この1テスト内で明示的に完結させる。
        std::env::set_var("VISUAL", "myvisual --flag");
        let cmd = editor_command().unwrap();
        assert_eq!(cmd.get_program(), "myvisual");
        std::env::remove_var("VISUAL");
    }
}
