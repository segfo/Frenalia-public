//! Tier2a残課題#5（`CreateProcessA`/`WinExec`直接フック）のE2E専用モード。通常のプローブ
//! 動作（FS検査・脱走試行・ネット到達性・再帰spawn）は一切行わず、指定されたコマンドラインを
//! `kernel32!CreateProcessA`または`kernel32!WinExec`で直接起動して完了を待ち、結果をJSONで
//! 報告するだけの短絡モード（`try_runas`と同じ位置付け）。
//!
//! `cow_containment_tests`（旧称`cow_diagnostics`、`crates/harness-sandbox/src/tier2a/win_appcontainer/`）が、このプローブ自身を
//! Redirector DLL注入済みの孫プロセスとして起動し、このプローブが`CreateProcessA`/`WinExec`
//! 経由でひ孫プロセスを起動したときにもDLLが再注入され、ひ孫の書込がCoW 差分層へ透過
//! リダイレクトされることを確認するために使う。

use serde_json::{json, Value};

#[cfg(windows)]
pub fn run(mode: &str, cmdline: &str) -> Value {
    use std::iter::once;
    use windows::core::{PCSTR, PSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessA, GetExitCodeProcess, WaitForSingleObject, WinExec, INFINITE,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA,
    };

    match mode {
        "createprocessa" => {
            let mut buf: Vec<u8> = cmdline.bytes().chain(once(0)).collect();
            let startup_info = STARTUPINFOA {
                cb: std::mem::size_of::<STARTUPINFOA>() as u32,
                ..Default::default()
            };
            let mut process_info = PROCESS_INFORMATION::default();
            let ok = unsafe {
                CreateProcessA(
                    PCSTR::null(),
                    PSTR(buf.as_mut_ptr()),
                    None,
                    None,
                    false,
                    PROCESS_CREATION_FLAGS(0),
                    None,
                    PCSTR::null(),
                    &startup_info,
                    &mut process_info,
                )
            };
            match ok {
                Ok(()) => {
                    let exit_code = unsafe {
                        let _ = WaitForSingleObject(process_info.hProcess, INFINITE);
                        let mut code = 0u32;
                        let _ = GetExitCodeProcess(process_info.hProcess, &mut code);
                        let _ = CloseHandle(process_info.hThread);
                        let _ = CloseHandle(process_info.hProcess);
                        code
                    };
                    json!({"mode": mode, "cmdline": cmdline, "ok": true, "exit_code": exit_code})
                }
                Err(e) => {
                    json!({"mode": mode, "cmdline": cmdline, "ok": false, "error": e.to_string()})
                }
            }
        }
        "winexec" => {
            let mut buf: Vec<u8> = cmdline.bytes().chain(once(0)).collect();
            let result = unsafe { WinExec(PCSTR(buf.as_mut_ptr()), 0) };
            // WinExecは起動確認のみで完了を待たないため、ひ孫の（ごく短時間で終わる）書込が
            // 終わるのを一定時間待つ。プロセスハンドルを取得できないため、これしか手段が無い。
            std::thread::sleep(std::time::Duration::from_millis(1500));
            json!({"mode": mode, "cmdline": cmdline, "ok": result > 31, "win_exec_result": result})
        }
        other => {
            json!({"mode": other, "cmdline": cmdline, "ok": false, "error": "unknown --spawn-via mode"})
        }
    }
}

#[cfg(not(windows))]
pub fn run(mode: &str, cmdline: &str) -> Value {
    json!({"mode": mode, "cmdline": cmdline, "ok": false, "error": "windows-only"})
}
