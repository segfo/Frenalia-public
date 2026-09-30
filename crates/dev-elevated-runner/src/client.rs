//! `dev-elevated-run`: `dev-elevated-runnerd`（開発用の昇格コマンドランナー）へ1件だけ
//! 要求を送るクライアント。デーモンが起動していなければ登録済みタスクで起動し、
//! タスクが未登録のときだけ`runas`（UAC 1回）を使う。
//!
//! 使い方: `dev-elevated-run.exe <target>`（`target`は`dev_elevated_runner::KNOWN_TARGETS`の
//! キーのいずれか）。それ以外の引数は受け付けない——複数コマンドの連結や任意のcargo引数を
//! 渡す経路は無い。

#[cfg(windows)]
mod scheduled_task;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use dev_elevated_runner::win::pipe_name_for_current_user;
    // 名前付きパイプIPCの下回りは`harness_sandbox::win_pipe_ipc`が持つ（デーモンと同じ実装）。
    use harness_sandbox::win_common::wide;
    use harness_sandbox::win_pipe_ipc::{
        current_user_sid_string, read_framed_timeout, write_framed_timeout,
    };
    use dev_elevated_runner::{check_tests_actually_ran, validate_target, RunRequest, RunResponse};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const RESPONSE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 20);

    let Some(target) = std::env::args().nth(1) else {
        eprintln!("usage: dev-elevated-run.exe <target>");
        eprintln!(
            "known targets: {:?}",
            dev_elevated_runner::KNOWN_TARGETS
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
        );
        return std::process::ExitCode::FAILURE;
    };
    if std::env::args().count() != 2 {
        eprintln!("dev-elevated-run.exe accepts exactly one argument (the target name), got extra arguments");
        return std::process::ExitCode::FAILURE;
    }
    if let Err(e) = validate_target(&target) {
        eprintln!("dev-elevated-run: {e}");
        return std::process::ExitCode::FAILURE;
    }

    let pipe_name = match pipe_name_for_current_user() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dev-elevated-run: failed to resolve pipe name: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let connect_once = || -> Option<windows::Win32::Foundation::HANDLE> {
        let wide_name = wide(&pipe_name);
        unsafe {
            CreateFileW(
                PCWSTR(wide_name.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
            .ok()
        }
    };

    let pipe = match connect_once() {
        Some(p) => p,
        None => {
            let scheduled = match scheduled_task::start_if_registered() {
                Ok(started) => started,
                Err(e) => {
                    eprintln!("dev-elevated-run: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            if scheduled {
                eprintln!("dev-elevated-run: starting daemon through registered scheduled task");
            } else {
                eprintln!(
                    "dev-elevated-run: task not registered, launching dev-elevated-runnerd.exe \
                 (this will prompt for UAC once)"
                );
                let daemon_path = match std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("dev-elevated-runnerd.exe")))
                {
                    Some(p) => p,
                    None => {
                        eprintln!("dev-elevated-run: failed to resolve daemon exe path");
                        return std::process::ExitCode::FAILURE;
                    }
                };
                let verb_w = wide("runas");
                let file_w = wide(&daemon_path.to_string_lossy());
                let mut info = SHELLEXECUTEINFOW {
                    cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                    fMask: SEE_MASK_NOCLOSEPROCESS,
                    lpVerb: PCWSTR(verb_w.as_ptr()),
                    lpFile: PCWSTR(file_w.as_ptr()),
                    nShow: SW_HIDE.0,
                    ..Default::default()
                };
                let ok = unsafe { ShellExecuteExW(&mut info) };
                if ok.is_err() {
                    eprintln!("dev-elevated-run: failed to launch daemon: {:?}", unsafe {
                        windows::Win32::Foundation::GetLastError()
                    });
                    return std::process::ExitCode::FAILURE;
                }
                unsafe {
                    let _ = CloseHandle(info.hProcess);
                }
            }
            // デーモンが名前付きパイプを作り終えるまで短くリトライする。
            let mut connected = None;
            for _ in 0..100 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Some(p) = connect_once() {
                    connected = Some(p);
                    break;
                }
            }
            match connected {
                Some(p) => p,
                None => {
                    eprintln!("dev-elevated-run: daemon did not become ready in time");
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
    };
    // このプロセス自身のSIDが正しいことをログに残す（デーモン側は既にDACLで強制済みだが、
    // クライアント側の診断用）。
    let _ = current_user_sid_string();

    // このCLIが送れるのは`Target`だけである。もう1つの要求（`LaunchPrivhelper`）は
    // 非昇格のharness本体が直接送るもので、人間が撃つ口を持たない（`privhelper_broker`）。
    let request = RunRequest::Target {
        target: target.clone(),
    };
    let request_bytes = serde_json::to_vec(&request).expect("serialize request");
    if let Err(e) = write_framed_timeout(pipe, &request_bytes, REQUEST_WRITE_TIMEOUT) {
        eprintln!("dev-elevated-run: failed to send request: {e}");
        unsafe {
            let _ = CloseHandle(pipe);
        }
        return std::process::ExitCode::FAILURE;
    }
    let response_bytes = match read_framed_timeout(pipe, RESPONSE_READ_TIMEOUT) {
        Ok(b) => b,
        Err(e) => {
            // 電文の型が変わった後に**古いデーモンが生きている**と、要求が解釈されずに
            // ここへ落ちる。次に踏む人が原因へ最短で行けるように名指しする。
            eprintln!(
                "dev-elevated-run: failed to read response: {e}\n  \
                 If a dev-elevated-runnerd from an older build is still running, it cannot parse \
                 this request. Stop it (see docs/DEV-ENVIRONMENT.md) and retry."
            );
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return std::process::ExitCode::FAILURE;
        }
    };
    unsafe {
        let _ = CloseHandle(pipe);
    }
    let response: RunResponse = match serde_json::from_slice(&response_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dev-elevated-run: failed to parse response: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    print!("{}", response.stdout);
    eprint!("{}", response.stderr);
    if response.exit_code != 0 {
        return std::process::ExitCode::FAILURE;
    }
    // 成功したときだけ「本当に走ったのか」を見る。`cargo test`はフィルタが1件も
    // マッチしなくてもexit 0を返すので、ここを見ないと壊れたフィルタが緑に見える
    // （BUG-056）。非0のときは既に失敗しているので二重に判定しない。
    if let Err(e) = check_tests_actually_ran(&target, &response.stdout) {
        eprintln!("dev-elevated-run: {e}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("dev-elevated-run is Windows-only");
    std::process::ExitCode::FAILURE
}
