//! `harness cow`サブコマンド。CoW upper_dirの一覧と、ACLで拒否された書込試行の監査ログ表示。

use super::*;

#[cfg(windows)]
pub(crate) fn run_cow_subcommand(action: CowAction) -> ExitCode {
    match action {
        CowAction::List => cow_list(),
        CowAction::Audit {
            session,
            output_format,
        } => cow_audit(session.as_deref(), output_format),
    }
}

#[cfg(not(windows))]
pub(crate) fn run_cow_subcommand(_action: CowAction) -> ExitCode {
    eprintln!("error: harness cow is Windows-only (Tier2a --cow specific)");
    ExitCode::FAILURE
}

#[cfg(windows)]
pub(crate) fn cow_upper_dir_for(session_id: &str) -> Option<PathBuf> {
    harness_sandbox::tier2a::workspace_ledger::cow_upper_root().map(|root| root.join(session_id))
}

/// `harness cow audit`: `.harness-cow-denied.jsonl`（Phase 4、設計書§19.8）を表示する。
#[cfg(windows)]
pub(crate) fn cow_audit(session: Option<&str>, output_format: OutputFormat) -> ExitCode {
    let Some(upper_dir) = resolve_cow_upper_dir(session) else {
        eprintln!("no CoW upper directory found (nothing to show)");
        return ExitCode::FAILURE;
    };
    let entries = harness_change_ledger::store::read_denied_log(&upper_dir);
    match output_format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string(&entries) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for e in &entries {
                if let Ok(s) = serde_json::to_string(e) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(no denied write attempts recorded)");
            }
            // BUG-066: workspace内への拒否は意味が正反対（封じ込めではなく**透過性の失敗**＝
            // その変更は失われている）なので、1件ずつ区別して見せる。
            let workspace_root = crate::cli::workspace_cmd::cow_session_workspace_root(&upper_dir);
            let mut inside = 0usize;
            for e in &entries {
                let is_inside = workspace_root.as_deref().is_some_and(|root| {
                    harness_change_ledger::path_rules::relative_under_root(&e.path, root).is_some()
                });
                if is_inside {
                    inside += 1;
                }
                println!(
                    "denied: {} (access_mask={:#x}, pid={}){}",
                    e.path,
                    e.access_mask,
                    e.pid,
                    if is_inside {
                        "  <-- INSIDE the workspace: the CoW redirect failed here, this change was lost"
                    } else {
                        ""
                    }
                );
            }
            if inside > 0 {
                println!(
                    "WARNING: {inside} of {} denied attempt(s) targeted the workspace itself. \
                     Those writes should have been redirected to the CoW upper directory; see \
                     docs/bugs/BUG-066.md.",
                    entries.len()
                );
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(windows)]
pub(crate) fn cow_list() -> ExitCode {
    let sessions = harness_sandbox::tier2a::workspace_ledger::list_cow_sessions();
    if sessions.is_empty() {
        println!("(no CoW upper directories found)");
        return ExitCode::SUCCESS;
    }
    for session_id in sessions {
        let Some(upper_dir) = cow_upper_dir_for(&session_id) else {
            continue;
        };
        let live = harness_sandbox::tier2a::workspace_ledger::cow_session_is_live(&session_id);
        let files = harness_sandbox::tier2a::workspace_ledger::list_cow_upper_files(&upper_dir);
        let workspace_root =
            harness_sandbox::tier2a::workspace_ledger::read_cow_session_meta(&upper_dir)
                .map(|m| m.workspace_root)
                .unwrap_or_else(|| "(unknown, meta file missing)".to_string());
        println!(
            "{session_id}\tworkspace={workspace_root}\t{}\tchanged_files={}",
            if live { "live" } else { "orphaned" },
            files.len()
        );
    }
    ExitCode::SUCCESS
}

/// `resolve_session_overlay`のCoW側解決に使う。セッションIDまたは「最も新しいCoW
/// upper置き場」からupper_dirを解決する。`resolve_sandbox_dir`のstaged版と同じ
/// 「最新セッションを選ぶ」考え方をCoW側にも適用する。
#[cfg(windows)]
pub(crate) fn resolve_cow_upper_dir(session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        let dir = cow_upper_dir_for(id)?;
        return if dir.exists() { Some(dir) } else { None };
    }
    let root = harness_sandbox::tier2a::workspace_ledger::cow_upper_root()?;
    let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
            newest = Some((path, modified));
        }
    }
    newest.map(|(p, _)| p)
}
