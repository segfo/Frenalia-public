//! `harness tier3`サブコマンド（A9、D-24）。常駐daemonの状態確認とGC。

use super::*;

pub(crate) fn run_tier3_subcommand(action: Tier3Action) -> ExitCode {
    match action {
        Tier3Action::Gc => match harness_sandbox_vm::vmsandboxd::run_gc_only() {
            Ok(reaped) => {
                if reaped.is_empty() {
                    println!("(no orphaned Tier3 VMs found)");
                } else {
                    println!("reaped orphaned Tier3 VMs:");
                    for vm_name in &reaped {
                        println!("  {vm_name}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tier3 gc failed: {e}");
                ExitCode::FAILURE
            }
        },
        Tier3Action::SetMaxSessions { n } => {
            let effective = harness_sandbox_vm::vmsandboxd::set_max_sessions(n);
            println!("Tier3 max concurrent sessions: {effective}");
            // **効かない条件を同じ場所で言う**（B-11）。置いただけでは走っているdaemonは
            // 古い上限のままで、しかもその食い違いは実行時には何も告げずに現れる
            // （「上限を上げたのに拒否される」）。
            println!(
                "note: this takes effect the next time the daemon starts. A daemon that is \
                 already running keeps its own limit -- run `harness tier3 stop-daemon` first \
                 (it only stops when no Tier3 session is active)."
            );
            ExitCode::SUCCESS
        }
        Tier3Action::StopDaemon => {
            match harness_sandbox_vm::vmsandboxd::stop_resident_daemon_if_idle() {
                Ok(true) => {
                    println!("Tier3 daemon is stopping");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("(Tier3 daemon is not running)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tier3 stop-daemon failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn run_tier3_subcommand(_action: Tier3Action) -> ExitCode {
    eprintln!("error: Tier3 (Hyper-V VM isolation) is Windows-only");
    ExitCode::FAILURE
}
