//! staged方式（`overlay::SandboxFs`のマニフェスト）とCoW方式（`--cow`の操作台帳）を
//! 1つの一覧・適用・破棄として扱う統合層。`harness changes`/`apply`/`discard`・TUIの
//! `/fsstage`が`--source <staged|cow|all>`で両方式を横断できるようにする
//! （`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §19、Phase 2）。

use std::path::Path;

use crate::manifest::ManifestOp;
use crate::overlay::{simple_glob_match, ApplyOptions, ApplyReport, SandboxError, SandboxFs};

/// どちらの機構由来の変更かを表す（表示専用、適用ロジックの分岐には使わない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeSource {
    Staged,
    Cow,
}

/// `harness changes --source <...>`が返す1件。stagedの`overlay::ChangeEntry`とCoWの
/// `harness_change_ledger::CowChange`を同じ形へ正規化する（両者とも`op`は
/// `harness_change_ledger::ChangeOp`＝`ManifestOp`で共通）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct UnifiedChangeEntry {
    pub source: ChangeSource,
    pub op: ManifestOp,
    pub path: String,
    pub baseline_hash: Option<String>,
}

/// stagedの`SandboxFs`（`Some`なら列挙対象）とCoWの`upper_dir`（`Some`なら列挙対象）を
/// 横断して一覧を返す。呼び出し側（CLI/TUI）が`--source`に応じてどちらを`Some`にするか決める。
pub fn list_unified_changes(
    staged_fs: Option<&SandboxFs>,
    cow_upper_dir: Option<&Path>,
) -> Result<Vec<UnifiedChangeEntry>, SandboxError> {
    let mut out = Vec::new();
    if let Some(fs) = staged_fs {
        for e in fs.change_set()? {
            out.push(UnifiedChangeEntry {
                source: ChangeSource::Staged,
                op: e.op,
                path: e.path,
                baseline_hash: e.baseline_hash,
            });
        }
    }
    #[cfg(windows)]
    if let Some(dir) = cow_upper_dir {
        for c in crate::workspace_ledger::read_cow_ledger(dir) {
            out.push(UnifiedChangeEntry {
                source: ChangeSource::Cow,
                op: c.op,
                path: c.path,
                baseline_hash: c.baseline_hash,
            });
        }
    }
    #[cfg(not(windows))]
    let _ = cow_upper_dir;
    Ok(out)
}

/// staged/CoW両方の変更を実FSへ選択適用する。戻り値は`overlay::ApplyReport`をそのまま
/// 使い回す（`applied`/`conflicts`/`ext_blocked`/`hard_denied`の4分類はCoW側でもそのまま
/// 意味が通る。`ext_blocked`はCoWでは常に空——CoWはworkspace内操作しか記録しないため）。
/// `cow`は`(upper_dir, workspace_root)`のペア。
pub fn apply_unified_changes(
    staged_fs: Option<&SandboxFs>,
    cow: Option<(&Path, &Path)>,
    opts: &ApplyOptions,
) -> Result<ApplyReport, SandboxError> {
    let mut report = ApplyReport::default();
    if let Some(fs) = staged_fs {
        let r = fs.apply(opts)?;
        report.applied.extend(r.applied);
        report.conflicts.extend(r.conflicts);
        report.ext_blocked.extend(r.ext_blocked);
        report.hard_denied.extend(r.hard_denied);
    }
    #[cfg(windows)]
    if let Some((upper_dir, workspace_root)) = cow {
        apply_cow_changes(upper_dir, workspace_root, opts, &mut report)?;
    }
    #[cfg(not(windows))]
    let _ = cow;
    Ok(report)
}

/// CoW側のapply本体。**D-05ハードデニー**（`.git/config`・`.harness/**`等の設定注入パス）を
/// staged側（`overlay.rs::apply`）と同じ`harness_core::is_config_injection_path`で必ず通す
/// ——現状のCoWにはこのチェックが無く、エージェントが`.git/config`をupperへ書き込んで
/// `apply`で実workspaceへ書き戻せてしまうセキュリティホールがあったため（設計書§19、
/// Phase 2で発見・修正）。
#[cfg(windows)]
fn apply_cow_changes(
    upper_dir: &Path,
    workspace_root: &Path,
    opts: &ApplyOptions,
    report: &mut ApplyReport,
) -> Result<(), SandboxError> {
    let changes = crate::workspace_ledger::read_cow_ledger(upper_dir);
    let mut applied_paths: Vec<String> = Vec::new();

    for c in &changes {
        if let Some(glob) = opts.only_glob {
            if !simple_glob_match(glob, &c.path) {
                continue;
            }
        }
        if let Some(paths) = opts.only_paths {
            if !paths.iter().any(|p| p == &c.path) {
                continue;
            }
        }
        if harness_core::is_config_injection_path(&c.path) {
            report.hard_denied.push(c.path.clone());
            continue;
        }

        let workspace_abs = workspace_root.join(c.path.replace('/', "\\"));
        let current_hash = std::fs::read(&workspace_abs)
            .ok()
            .map(|b| harness_change_ledger::hash_bytes(&b));
        if current_hash != c.baseline_hash {
            // baseline照合の相違（TOCTOU防止、設計書§19.5）。適用せず再レビューを促す。
            report.conflicts.push(c.path.clone());
            continue;
        }

        let result: std::io::Result<()> = match c.op {
            ManifestOp::Delete => {
                if workspace_abs.exists() {
                    std::fs::remove_file(&workspace_abs)
                } else {
                    Ok(())
                }
            }
            ManifestOp::Create | ManifestOp::Modify => {
                let upper_abs = upper_dir.join(c.path.replace('/', "\\"));
                if let Some(parent) = workspace_abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let copied = std::fs::copy(&upper_abs, &workspace_abs).map(|_| ());
                if copied.is_ok() {
                    // upper側の実体を消しておかないと、Redirectorの`copy_up`が
                    // 「既にupperにある＝このセッションで一度触った」と誤認して、次の
                    // 変更を台帳へ記録しなくなる（BUG-034）。ベストエフォート、失敗しても
                    // commit自体は成功扱いにする（`overlay.rs::apply()`と同じ扱い）。
                    let _ = std::fs::remove_file(&upper_abs);
                }
                copied
            }
        };
        result.map_err(SandboxError::Io)?;
        report.applied.push(c.path.clone());
        applied_paths.push(c.path.clone());
    }

    if !applied_paths.is_empty() {
        let _ = crate::workspace_ledger::prune_cow_ledger(upper_dir, &applied_paths);
    }
    Ok(())
}

/// staged/CoW両方の変更を破棄する。CoW側は呼び出し元（CLI）が「セッションがまだ動作中でない
/// か」を`workspace_ledger::cow_session_is_live`で確認してから呼ぶこと（このモジュールは
/// その確認をしない、既存の`harness cow discard`のガードをそのまま活かすため）。
pub fn discard_unified_changes(
    staged_fs: Option<&SandboxFs>,
    cow_upper_dir: Option<&Path>,
) -> Result<(), SandboxError> {
    if let Some(fs) = staged_fs {
        fs.discard()?;
    }
    #[cfg(windows)]
    if let Some(dir) = cow_upper_dir {
        std::fs::remove_dir_all(dir).map_err(SandboxError::Io)?;
    }
    #[cfg(not(windows))]
    let _ = cow_upper_dir;
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use harness_change_ledger::{hash_bytes, now_millis, ChangeOp, CowOpEntry, COW_OPS_LEDGER_FILENAME};

    fn write_ledger(upper_dir: &Path, entries: &[CowOpEntry]) {
        let mut out = String::new();
        for e in entries {
            out.push_str(&serde_json::to_string(e).unwrap());
            out.push('\n');
        }
        std::fs::write(upper_dir.join(COW_OPS_LEDGER_FILENAME), out).unwrap();
    }

    fn no_filter_opts() -> ApplyOptions<'static> {
        ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
        }
    }

    /// BUG-034回帰テスト: commit（`apply_cow_changes`）はupper側の実体を消し忘れると、
    /// Redirectorの`copy_up`（`upper_path.exists()`で「既に触った」と判定する冪等ガード）が
    /// 次の変更を台帳へ記録しなくなる。ここでは`copy_up`自体は動かさず、その代わりに
    /// 「1回目のcommit後、2回目の変更が正しく新規エントリとして台帳経由で適用できるか」を
    /// 直接検証する（`copy_up`が正しく動く前提＝upper側の実体が残っていないことが必要）。
    #[test]
    fn commit_removes_upper_copy_so_next_edit_is_tracked_again() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();

        std::fs::write(upper.path().join("a.txt"), "first").unwrap();
        write_ledger(
            upper.path(),
            &[CowOpEntry {
                op: ChangeOp::Create,
                path: "a.txt".to_string(),
                baseline_hash: None,
                ts_unix_millis: now_millis(),
            }],
        );

        let report1 =
            apply_unified_changes(None, Some((upper.path(), workspace.path())), &no_filter_opts())
                .unwrap();
        assert_eq!(report1.applied, vec!["a.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("a.txt")).unwrap(),
            "first"
        );
        assert!(
            !upper.path().join("a.txt").exists(),
            "commit後はupper側の実体が削除されているべき（BUG-034）"
        );

        // 2回目の変更。`copy_up`は実workspace側の現在内容（"first"）をbaselineとして
        // 記録するはずなので、そのハッシュを使う。
        let baseline_hash = hash_bytes(b"first");
        std::fs::write(upper.path().join("a.txt"), "second").unwrap();
        write_ledger(
            upper.path(),
            &[CowOpEntry {
                op: ChangeOp::Modify,
                path: "a.txt".to_string(),
                baseline_hash: Some(baseline_hash),
                ts_unix_millis: now_millis(),
            }],
        );

        let report2 =
            apply_unified_changes(None, Some((upper.path(), workspace.path())), &no_filter_opts())
                .unwrap();
        assert_eq!(
            report2.applied,
            vec!["a.txt".to_string()],
            "2回目の変更も検知・適用されるべき（BUG-034の再発防止）"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("a.txt")).unwrap(),
            "second"
        );
        assert!(!upper.path().join("a.txt").exists());
    }
}
