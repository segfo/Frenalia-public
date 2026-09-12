//! Task Scheduler integration. Only an explicitly absent task permits runas.
//! Registration and task-name ownership live in the same script used by humans.

use std::os::windows::process::CommandExt;

pub fn start_if_registered() -> Result<bool, String> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("runner crate is under crates/");
    let shell =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let output = std::process::Command::new(shell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(repo.join("tools/dev-elevated-task.ps1"))
        .args(["-Action", "Start"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("failed to query/start scheduled task: {e}"))?;
    classify_exit(output.status.code()).map_err(|e| {
        format!(
            "{e}\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn classify_exit(code: Option<i32>) -> Result<bool, String> {
    match code {
        Some(0) => Ok(true),
        Some(3) => Ok(false), // script contract: task lookup returned FILE_NOT_FOUND
        _ => Err(format!(
            "scheduled task failed (exit {code:?}); refusing UAC fallback"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::classify_exit;

    #[test]
    fn only_explicit_absence_allows_uac_fallback() {
        assert!(!classify_exit(Some(3)).unwrap());
        assert!(classify_exit(Some(0)).unwrap());
        for code in [Some(1), Some(2), Some(5), Some(-1), None] {
            assert!(
                classify_exit(code).is_err(),
                "unexpected fallback: {code:?}"
            );
        }
    }
}
