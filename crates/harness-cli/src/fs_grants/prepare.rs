//! `harness fs prepare-workspace`: workspace ACL の明示的な前払い。

use std::io::Write;
use std::time::Instant;

use super::*;

#[cfg(windows)]
pub(crate) fn fs_prepare_workspace(path: &Path, mode: WorkspacePrepareMode) -> ExitCode {
    use grant_job::JobPhase;
    use harness_sandbox::tier2a::workspace_ledger::WorkspaceMode;
use harness_sandbox::tier2a::win_appcontainer::{
        grant_job, start_workspace_preparation, WorkspacePreparationState,
    };

    let acl_mode = match mode {
        WorkspacePrepareMode::Rwx => WorkspaceMode::Rwx,
        WorkspacePrepareMode::Ro => WorkspaceMode::Ro,
    };
    eprintln!(
        "harness: preparing workspace access for {} (mode={})...",
        path.display(),
        acl_mode.as_str()
    );
    let launch = match start_workspace_preparation(path, acl_mode) {
        Ok(launch) => launch,
        Err(error) => {
            eprintln!("failed to prepare workspace access: {error}");
            return ExitCode::FAILURE;
        }
    };

    if launch.state == WorkspacePreparationState::Ready {
        println!(
            "workspace access is ready for {} (mode={}; reused persistent capability, no tree walk)",
            launch.canonical_workspace.display(),
            acl_mode.as_str()
        );
        return ExitCode::SUCCESS;
    }

    let mut last_line = String::new();
    let waiting_since = Instant::now();
    let waited = grant_job::wait_for_workspace_reporting(
        &launch.canonical_workspace,
        acl_mode.as_str(),
        |progress| {
            let line = match progress.phase {
                JobPhase::Propagating => {
                    format!(
                        "harness: propagating the workspace ACE (OS call; progress count unavailable; {}s elapsed)",
                        waiting_since.elapsed().as_secs()
                    )
                }
                JobPhase::Walking if progress.total > 0 => format!(
                    "harness: verifying protected descendants: {}/{} ({}%; {}s elapsed)",
                    progress.done,
                    progress.total,
                    progress.percent(),
                    waiting_since.elapsed().as_secs()
                ),
                JobPhase::Walking => {
                    format!(
                        "harness: scanning protected descendants (total not known yet; {}s elapsed)",
                        waiting_since.elapsed().as_secs()
                    )
                }
                // [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] このCLIは常に既定のレーンで走る
                // （`workspace_prepare.rs`が`FullWalk`を渡す）ので、通常ここへは来ない。
                // **それでも`unreachable!`にはしない**——レーンの選び方が変わったときに
                // 落ちるのではなく、正しい行が出るほうがよい。母数は出ない（走査器は
                // 母数を先に数えない、`JobPhase::Scanning`のdoc）。
                JobPhase::Scanning => {
                    format!(
                        "harness: granting the workspace tree node by node: {} done \
                         (total not known yet; {}s elapsed)",
                        progress.done,
                        waiting_since.elapsed().as_secs()
                    )
                }
            };
            if line != last_line {
                eprint!("\r{line}   ");
                let _ = std::io::stderr().flush();
                last_line = line;
            }
        },
    );
    eprintln!();

    match waited {
        Ok(()) => {
            let final_state =
                harness_sandbox::tier2a::win_appcontainer::workspace_preparation_state(
                    &launch.canonical_workspace,
                    acl_mode,
                );
            if !matches!(final_state, Ok(WorkspacePreparationState::Ready)) {
                eprintln!(
                    "failed to prepare workspace access: the job finished but readiness verification returned {final_state:?}"
                );
                return ExitCode::FAILURE;
            }
            println!(
                "workspace access is ready for {} (mode={}; background_job={})",
                launch.canonical_workspace.display(),
                acl_mode.as_str(),
                if launch.job_started {
                    "started"
                } else {
                    "joined"
                }
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to prepare workspace access: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_prepare_workspace(_path: &Path, _mode: WorkspacePrepareMode) -> ExitCode {
    eprintln!("error: workspace preparation is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}
