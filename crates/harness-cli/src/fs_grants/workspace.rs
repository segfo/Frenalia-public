//! preflightがworkspace本体へ付与した継承ACEの撤収（`harness fs revoke-workspace` /
//! `revoke-workspace-all`）。生存中のセッションが使っているworkspaceは撤収しない
//! （判定は`workspace_ledger`の名前付きmutex）。

use super::*;

/// workspace本体のACE（`preflight`が毎回付与するRWX/RO）を撤収する。名前付きmutexで
/// 「今もこのworkspaceを使っている他のharnessセッションが無いか」を確認してから撤収する
/// （`harness_sandbox::tier2a::workspace_ledger`参照）。CoWのupper_dirには一切触れない。
#[cfg(windows)]
pub(crate) fn fs_revoke_workspace(path: &Path) -> ExitCode {
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to canonicalize {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&canonical);
    if !live.is_empty() {
        eprintln!(
            "workspace {} is still in use by another harness session (mode(s): {}); refusing \
             to revoke",
            canonical.display(),
            live.join(", ")
        );
        return ExitCode::FAILURE;
    }
    let sid = match harness_sandbox::tier2a::win_appcontainer::ensure_profile(
        harness_sandbox::tier2a::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    match harness_sandbox::tier2a::win_appcontainer::revoke_ace_recursive(&canonical, sid.as_psid()) {
        Ok(()) => {
            harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&canonical);
            println!("revoked workspace access: {}", canonical.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "failed to revoke workspace access for {}: {e}",
                canonical.display()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_workspace(_path: &Path) -> ExitCode {
    eprintln!("error: workspace revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 記録済みの全workspaceに対して`fs_revoke_workspace`を試みる。使用中のworkspaceは
/// スキップし、それ以外を撤収する。
#[cfg(windows)]
pub(crate) fn fs_revoke_workspace_all() -> ExitCode {
    let ledger = harness_sandbox::tier2a::workspace_ledger::load_workspace_ledger();
    if ledger.entries.is_empty() {
        println!("(no workspace grants recorded)");
        return ExitCode::SUCCESS;
    }
    let mut any_failed = false;
    for entry in &ledger.entries {
        let path = PathBuf::from(&entry.path);
        let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&path);
        if !live.is_empty() {
            println!(
                "skipping {} (in use by another harness session, mode(s): {})",
                path.display(),
                live.join(", ")
            );
            continue;
        }
        if fs_revoke_workspace(&path) != ExitCode::SUCCESS {
            any_failed = true;
        }
    }
    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_workspace_all() -> ExitCode {
    eprintln!("error: workspace revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}
