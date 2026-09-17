//! **[段階6f-2] ただ`CreateProcessW`を呼ぶだけ**のモード。
//!
//! # 何のためにあるのか
//!
//! [`crate::spawn_via_daemon`]は**プローブがフックの役を演じて**電文を組む。こちらは
//! **電文を1つも知らない**——普通のプログラムと同じように`CreateProcessW`を呼ぶだけで、
//! 組み替えるのはRedirector DLLのフックである。
//!
//! ```text
//!   spawn_via_daemon   : プローブ ──電文──→ Daemon          （6f-1の受け入れ）
//!   spawn_transparently: プローブ ─CreateProcessW→ フック ─電文→ Daemon （6f-2の受け入れ）
//! ```
//!
//! **報告の欄は2つの腕で同じ**（[`crate::spawn_report`]）なので、同じ判定で比べられる。
//!
//! # 生成禁止を積んでいない構成でも使える
//!
//! そのときフックは横取りせず、**本物の`CreateProcessW`がそのまま走る**。
//! つまりこのモードは「頼む形になっているか」の**対照**にもなる——
//! 積まない回で子が生まれることを見れば、今日の挙動が変わっていないことが測れる。

use serde_json::{json, Value};

/// 1回の「起こして、待って、終了コードを読む」の設定。
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Spec<'a> {
    /// `lpApplicationName`へ渡す値。**`None`なら`NULL`を渡す**
    /// ——実行ファイルの解決をフック（とOS）に任せる腕である。
    pub image: Option<&'a str>,
    /// `lpCommandLine`へ逐語で渡す文字列。
    pub command_line: &'a str,
    /// `lpCurrentDirectory`。`None`なら`NULL`（呼び出し元と同じ）。
    pub cwd: Option<&'a str>,
    /// 子の標準出力／標準エラーにするファイル。
    pub stdout_file: Option<&'a str>,
    /// 生成フラグの選び方。**コンソール要否の導出を撃ち分けるためにある。**
    ///
    /// | 綴り | 渡すフラグ | フックが導く`console` |
    /// |---|---|---|
    /// | `none` | 0 | `required` |
    /// | `no-window` | `CREATE_NO_WINDOW` | `not_needed` |
    /// | `detached` | `DETACHED_PROCESS` | `not_needed` |
    /// | `suspended` | `CREATE_SUSPENDED` | `required`（**動かすのは呼び出し元**） |
    pub flags: &'a str,
    /// 起こす前に**自分の**環境へ置く値（`NAME=VALUE`）。
    ///
    /// `lpEnvironment`には`NULL`を渡すので、これが子へ届けば
    /// 「フックが自分の環境を読んで載せた」ことになる。
    pub set_env: &'a [String],
    pub report_file: Option<&'a str>,
}

#[cfg(windows)]
pub fn run(spec: &Spec) -> Value {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    use windows::Win32::System::Threading::{
        CreateProcessW, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    for entry in spec.set_env {
        if let Some((name, value)) = entry.split_once('=') {
            // **自分のプロセス内に置く。** 子のenv blockは組まない（`lpEnvironment`は`NULL`）。
            std::env::set_var(name, value);
        }
    }

    let mut stdout = crate::spawn_report::open_inheritable(spec.stdout_file);
    let mut startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    if let Some(handle) = stdout.handle {
        // **3本とも埋める。** `STARTF_USESTDHANDLES`を立てて一部だけ埋めると、
        // 残りが無効ハンドルとして子へ渡る。
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdOutput = handle;
        startup.hStdError = handle;
        startup.hStdInput = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.unwrap_or_default();
    }

    let mut command_line: Vec<u16> = spec
        .command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let image: Option<Vec<u16>> = spec
        .image
        .map(|i| i.encode_utf16().chain(std::iter::once(0)).collect());
    let cwd: Option<Vec<u16>> = spec
        .cwd
        .map(|c| c.encode_utf16().chain(std::iter::once(0)).collect());

    let mut info = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            image
                .as_ref()
                .map(|i| PCWSTR(i.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            // 継承する。生成禁止を積んでいない構成では、これが無いと標準出力が子へ渡らない。
            true,
            creation_flags(spec.flags),
            None,
            cwd.as_ref()
                .map(|c| PCWSTR(c.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut info,
        )
    };
    let last_error = unsafe { GetLastError() }.0;
    let stdout_opened = stdout.handle.is_some();
    stdout.close();

    let mut report = json!({
        "mode": "spawn-transparently",
        "image": spec.image,
        "command_line": spec.command_line,
        "flags": spec.flags,
        "created": created.is_ok(),
        "last_error": if created.is_ok() { 0 } else { last_error },
        "create_error": created.as_ref().err().map(|e| e.to_string()),
        "stdout_handle_opened": stdout_opened,
        "stdout_open_error": stdout.open_error.clone(),
    });

    if created.is_ok() {
        report["child_pid"] = json!(info.dwProcessId);
        report["child_thread_id"] = json!(info.dwThreadId);
        // 一時停止で頼んだ腕は**呼び出し元が動かす**（`SpawnRequest::Spawn::suspended`）。
        // 動かさずに待つと30秒待って諦めるだけになる。
        if spec.flags == "suspended" {
            unsafe {
                let _ = windows::Win32::System::Threading::ResumeThread(info.hThread);
            }
        }
        unsafe {
            let _ = CloseHandle(info.hThread);
        }
        crate::spawn_report::wait_and_record(
            &mut report,
            Some(info.hProcess.0 as usize as u64),
            Some(info.hThread.0 as usize as u64),
        );
    }

    if let Some(path) = spec.report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

/// 綴りから生成フラグへ。**知らない綴りは0**（＝コンソールを継承させるつもり）。
#[cfg(windows)]
fn creation_flags(flags: &str) -> windows::Win32::System::Threading::PROCESS_CREATION_FLAGS {
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, DETACHED_PROCESS, PROCESS_CREATION_FLAGS,
    };
    match flags {
        "no-window" => CREATE_NO_WINDOW,
        "detached" => DETACHED_PROCESS,
        "suspended" => CREATE_SUSPENDED,
        _ => PROCESS_CREATION_FLAGS(0),
    }
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({ "mode": "spawn-transparently", "error": "windows only" })
}
