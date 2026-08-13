//! **MAC/Spawn Daemon設計 §22.6.2「改A」・§20項目3/5/6の実現性スパイク専用モード**
//! （`plans/mac-spike/RESULTS.md`）。
//!
//! Daemon（＝AppContainerの外にいるフルトラスト側）が、サンドボックス内の呼び出し元から
//! ハンドルを`DuplicateHandle`で引き取り、`GetFinalPathNameByHandleW`で実体のパスを解決し、
//! 権限を絞って子へ渡す——という6手順が実機で成立するかを測るために、サンドボックス側で
//! 必要な役を演じる。
//!
//! | モード | 役 |
//! |---|---|
//! | `--hold-file` | 呼び出し元。ファイルを開いてハンドル値を申告し、Daemon役が複製し終わるまで生きている |
//! | `--emit` | 遷移先の子。自分のstdout（＝Daemon役が絞って渡したハンドル）へ書くだけ |
//! | `--use-process-handle` | §20項目3。最小権限のプロセスハンドルで`WaitForSingleObject`＋`GetExitCodeProcess`ができるか |
//! | `--idle-secs` | §10.1.1のJob試験で「生きているだけ」の子として使う |
//!
//! **申告するのはハンドル値（数値）だけである**（§22.6.2）。パス・型・アクセス権を
//! 呼び出し元に申告させると、`secret.txt`のハンドルに`out.txt`と名乗らせるだけで
//! 照合を通過してしまう——このプローブはその設計をそのまま写している。

use serde_json::{json, Value};

/// 結果をファイルへも落とす（stdoutはドライバがプロセス終了まで読み切れないため）。
/// **失敗しても黙らない**（B-10）——書けなかった事実をstdoutへ残す。
fn write_report(report_file: Option<&str>, report: &Value) {
    let Some(path) = report_file else {
        return;
    };
    let body = serde_json::to_string(report).expect("report must serialize");
    if let Err(e) = std::fs::write(path, body.as_bytes()) {
        println!(
            "{}",
            json!({"report_file_error": e.to_string(), "path": path})
        );
    }
}

/// 呼び出し元役: `path`を書込で開き、**ハンドル値**を申告してから`idle_secs`だけ生きている。
#[cfg(windows)]
pub fn hold_file(path: &str, report_file: Option<&str>, idle_secs: u64) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
    };

    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    let report = match handle {
        Ok(h) => json!({
            "mode": "hold-file",
            "path": path,
            "pid": std::process::id(),
            "handle": h.0 as usize,
            "ok": true,
        }),
        Err(e) => json!({
            "mode": "hold-file",
            "path": path,
            "pid": std::process::id(),
            "handle": Value::Null,
            "ok": false,
            "last_error": unsafe { GetLastError() }.0,
            "error": e.to_string(),
        }),
    };
    write_report(report_file, &report);
    println!("{report}");
    // Daemon役が複製し終わるまで生きている（ハンドルは開いたまま）。
    std::thread::sleep(std::time::Duration::from_secs(idle_secs));
    report
}

/// 遷移先の子役: 自分のstdoutへ`text`を書く。ドライバはこのstdoutを
/// 「呼び出し元が開いたファイルを絞って複製したハンドル」に差し替えて起動する。
pub fn emit(text: &str) -> Value {
    use std::io::Write;
    let mut out = std::io::stdout();
    let ok = out
        .write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .is_ok();
    json!({"mode": "emit", "wrote": text, "ok": ok})
}

/// §20項目3: `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`だけのプロセスハンドルで、
/// 一般的なCLIがやること（待つ・終了コードを取る）ができるか。
#[cfg(windows)]
pub fn use_process_handle(raw: usize, report_file: Option<&str>) -> Value {
    use windows::Win32::Foundation::{GetLastError, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessId, WaitForSingleObject,
    };

    let handle = HANDLE(raw as *mut std::ffi::c_void);
    let wait = unsafe { WaitForSingleObject(handle, 15_000) };
    let mut exit_code = 0u32;
    let exit_ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    let pid = unsafe { GetProcessId(handle) };
    let report = json!({
        "mode": "use-process-handle",
        "handle": raw,
        "wait_result": wait.0,
        "waited_ok": wait == WAIT_OBJECT_0,
        "exit_code_ok": exit_ok.is_ok(),
        "exit_code": exit_code,
        "get_process_id": pid,
        "last_error": unsafe { GetLastError() }.0,
    });
    write_report(report_file, &report);
    report
}

#[cfg(not(windows))]
pub fn hold_file(path: &str, _report_file: Option<&str>, _idle_secs: u64) -> Value {
    json!({"mode": "hold-file", "path": path, "ok": false, "error": "windows-only"})
}

#[cfg(not(windows))]
pub fn use_process_handle(raw: usize, _report_file: Option<&str>) -> Value {
    json!({"mode": "use-process-handle", "handle": raw, "ok": false, "error": "windows-only"})
}
