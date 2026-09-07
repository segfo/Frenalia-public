//! 段階5c: キャンセル時に直接の子だけでなくJob配下の子孫まで終了する安全網。
//!
//! PIDは再利用され得るため、PIDファイルを読んだ直後にプロセスハンドルを開き、以後の
//! 生存判定と後始末はその同じハンドルだけで行う。テスト自身は製品のJobハンドルを保持しない。

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

pub(crate) const PID_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// 子スクリプトが起動する孫の出力形態。
#[derive(Clone, Copy)]
pub(crate) enum DescendantOutput {
    RedirectedToFile,
    Inherited,
}

/// 孫用スクリプトを作り、直接の子へ渡すPowerShellスクリプトとPIDファイルを返す。
pub(crate) fn prepare_descendant(
    root: &Path,
    output: DescendantOutput,
    force_output_inheritance: bool,
) -> (String, PathBuf) {
    let pid_file = root.join("descendant.pid");
    let output_file = root.join("descendant.log");
    let loop_command =
        "/d /c for /L %i in (0,0,1) do @powershell.exe -NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 1\"";
    let (file_name, arguments) = match output {
        DescendantOutput::Inherited => (r"C:\Windows\System32\cmd.exe", loop_command.to_string()),
        DescendantOutput::RedirectedToFile => (
            r"C:\Windows\System32\cmd.exe",
            format!("{loop_command} > \"{}\" 2>&1", output_file.display()),
        ),
    };
    let common = format!(
        "$ErrorActionPreference='Stop';$psi=[Diagnostics.ProcessStartInfo]::new();\
         $psi.FileName={};$psi.Arguments={};\
         $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;",
        ps_literal(file_name),
        ps_literal(&arguments),
    );
    let start = format!(
        "try {{$p=[Diagnostics.Process]::Start($psi);\
         [IO.File]::WriteAllText({},[string]$p.Id)}} catch {{\
         [IO.File]::WriteAllText({},($_|Out-String));throw }};",
        ps_literal(&pid_file.to_string_lossy()),
        ps_literal(&pid_file.with_extension("error").to_string_lossy()),
    );
    let script = match output {
        DescendantOutput::RedirectedToFile => format!(
            "{common}$psi.UseShellExecute=$true;$psi.WindowStyle='Hidden';{start}\
             while ($true) {{ Start-Sleep -Milliseconds 100 }}"
        ),
        DescendantOutput::Inherited if force_output_inheritance => format!(
            "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;\
             public static class HarnessInheritOutput {{\
             [DllImport(\"kernel32.dll\")] public static extern IntPtr GetCurrentProcess();\
             [DllImport(\"kernel32.dll\")] public static extern IntPtr GetStdHandle(int n);\
             [DllImport(\"kernel32.dll\")] public static extern bool SetStdHandle(int n,IntPtr h);\
             [DllImport(\"kernel32.dll\")] public static extern bool CloseHandle(IntPtr h);\
             [DllImport(\"kernel32.dll\",SetLastError=true)] public static extern bool DuplicateHandle(\
             IntPtr sp,IntPtr sh,IntPtr tp,out IntPtr th,uint access,bool inherit,uint options);}}';\
             {common}$source=[HarnessInheritOutput]::GetStdHandle(-11);\
             [IntPtr]$held=[IntPtr]::Zero;try {{\
             if (![HarnessInheritOutput]::DuplicateHandle(\
             [HarnessInheritOutput]::GetCurrentProcess(),[HarnessInheritOutput]::GetStdHandle(-11),\
             [HarnessInheritOutput]::GetCurrentProcess(),[ref]$held,0,$true,2)) {{\
             throw [ComponentModel.Win32Exception]::new() }};\
             if (![HarnessInheritOutput]::SetStdHandle(-11,$held)) {{\
             throw [ComponentModel.Win32Exception]::new() }};\
             $psi.RedirectStandardInput=$true;$p=[Diagnostics.Process]::Start($psi);\
             [HarnessInheritOutput]::SetStdHandle(-11,$source)|Out-Null;\
             [HarnessInheritOutput]::CloseHandle($held)|Out-Null;$held=[IntPtr]::Zero;\
             [IO.File]::WriteAllText({},[string]$p.Id)\
             }} catch {{ [HarnessInheritOutput]::SetStdHandle(-11,$source)|Out-Null;\
             if ($held -ne [IntPtr]::Zero) {{\
             [HarnessInheritOutput]::CloseHandle($held)|Out-Null }};\
             [IO.File]::WriteAllText({},($_|Out-String));throw }};\
             while ($true) {{ Start-Sleep -Milliseconds 100 }}",
            ps_literal(&pid_file.to_string_lossy()),
            ps_literal(&pid_file.with_extension("error").to_string_lossy()),
        ),
        DescendantOutput::Inherited => {
            format!("{common}{start}while ($true) {{ Start-Sleep -Milliseconds 100 }}")
        }
    };
    (script, pid_file)
}

fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// PID再利用を避けるため、PIDファイルが現れた時点のプロセスをハンドルで固定する。
pub(crate) struct DescendantProbe(HANDLE);

unsafe impl Send for DescendantProbe {}

impl DescendantProbe {
    pub(crate) fn wait_for_pid_file(pid_file: &Path) -> Self {
        let deadline = Instant::now() + PID_TIMEOUT;
        loop {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    let handle =
                        unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, false, pid) }
                            .unwrap_or_else(|e| {
                                panic!("OpenProcess({pid}) after PID publication: {e}")
                            });
                    return Self(handle);
                }
            }
            assert!(
                Instant::now() < deadline,
                "descendant PID file did not appear within {PID_TIMEOUT:?}: {}; start error: {}",
                pid_file.display(),
                std::fs::read_to_string(pid_file.with_extension("error"))
                    .unwrap_or_else(|_| "<no error file>".to_string())
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    pub(crate) fn assert_alive(&self) {
        assert_eq!(
            unsafe { WaitForSingleObject(self.0, 0) },
            WAIT_TIMEOUT,
            "the descendant must be alive before cancellation"
        );
    }

    pub(crate) fn assert_exited_after_cancel(&self) {
        let deadline = Instant::now() + CANCEL_TIMEOUT;
        loop {
            let state = unsafe { WaitForSingleObject(self.0, 0) };
            if state == WAIT_OBJECT_0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the descendant remained alive for {CANCEL_TIMEOUT:?} after cancellation"
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for DescendantProbe {
    fn drop(&mut self) {
        unsafe {
            if WaitForSingleObject(self.0, 0) != WAIT_OBJECT_0 {
                let _ = TerminateProcess(self.0, 1);
                let _ = WaitForSingleObject(self.0, CANCEL_TIMEOUT.as_millis() as u32);
            }
            let _ = CloseHandle(self.0);
        }
    }
}

/// ブロックし得るキャンセル完了処理を専用スレッドへ隔離し、上限時間を固定する。
pub(crate) fn assert_cancel_completes(label: &'static str, work: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        work();
        let _ = tx.send(());
    });
    rx.recv_timeout(CANCEL_TIMEOUT)
        .unwrap_or_else(|_| panic!("{label} did not complete within {CANCEL_TIMEOUT:?}"));
}

fn run_tier0(output: DescendantOutput) {
    let dir = tempfile::tempdir().expect("create Tier0 test dir");
    let (script, pid_file) = prepare_descendant(dir.path(), output, false);
    let child = crate::tier0::win_plain::spawn(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        dir.path(),
        &crate::secret_env::build_child_env(),
        false,
    )
    .expect("spawn Tier0 parent");
    let kill = child.kill_token().expect("duplicate Tier0 Job handle");
    let mut events = child.spawn_streaming(None);
    let descendant = DescendantProbe::wait_for_pid_file(&pid_file);
    descendant.assert_alive();

    kill.kill();
    assert_cancel_completes("Tier0 streaming cancellation", move || {
        while events.blocking_recv().is_some() {}
    });
    descendant.assert_exited_after_cancel();
}

fn run_tier1(output: DescendantOutput) {
    let dir = tempfile::tempdir().expect("create Tier1 test dir");
    let (script, pid_file) = prepare_descendant(dir.path(), output, false);
    crate::tier1::win_restricted::set_low_integrity_label(dir.path())
        .expect("label Tier1 test dir Low IL");
    let child = crate::tier1::win_restricted::spawn(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        dir.path(),
        &crate::secret_env::build_child_env(),
        false,
    )
    .expect("spawn Tier1 parent");
    let kill = child.kill_token().expect("duplicate Tier1 Job handle");
    let descendant = DescendantProbe::wait_for_pid_file(&pid_file);
    descendant.assert_alive();

    assert_cancel_completes("Tier1 one-shot cancellation", move || {
        kill.kill();
        let _ = child.write_stdin_read_output_and_wait(None);
    });
    descendant.assert_exited_after_cancel();
}

#[test]
fn t1a_tier0_streaming_cancel_kills_descendant_with_redirected_output() {
    run_tier0(DescendantOutput::RedirectedToFile);
}

#[test]
fn t1b_tier0_streaming_cancel_kills_descendant_with_inherited_output() {
    run_tier0(DescendantOutput::Inherited);
}

#[test]
fn t2a_tier1_one_shot_cancel_kills_descendant_with_redirected_output() {
    run_tier1(DescendantOutput::RedirectedToFile);
}

#[test]
fn t2b_tier1_one_shot_cancel_kills_descendant_with_inherited_output() {
    run_tier1(DescendantOutput::Inherited);
}
