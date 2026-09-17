//! **[段階6f-1] フックの役を演じるモード**——サンドボックスの中から、呼び出し元の持ち物
//! （標準出力のハンドル）を載せてSpawn Daemonへ生成を頼み、**返ってきたハンドルで待つ**。
//!
//! # 何のためにあるのか
//!
//! 段階6f-1はDaemon側だけを仕上げる回で、Redirector DLLのフックは1行も変えていない。
//! だが「呼び出し元のstdioが子へ渡るか」「返ったプロセスハンドルで待てるか」は、
//! **頼む側が居なければ測れない**。そこでプローブがその役を演じる
//! （`--pipe-client`が窓口への到達だけを測るのと同じ位置付けで、こちらは1往復の**中身**を測る）。
//!
//! # 既存の`--pipe-client`と何が違うのか
//!
//! 接続と1往復そのものは[`crate::pipe_client`]をそのまま使う（**写さない**）。
//! ここが足すのは前後の2つだけである。
//!
//! 1. **前**: 子の標準出力にするファイルを継承可で開き、そのハンドル値を電文へ載せる
//! 2. **後**: 応答の`process`ハンドルで`WaitForSingleObject`し、終了コードを読む
//!
//! # 測れないことを測れたことにしない
//!
//! 待てなかった・終了コードが読めなかったときは、**その旨を欄に残す**（`B-10`）。
//! 「子が走らなかった」と「待てなかった」は別の事実で、混ぜるとDaemon側の不具合が
//! プローブ側の不具合に見える。

use serde_json::{json, Value};

/// 1回の「頼んで、待って、終了コードを読む」の設定。
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Spec<'a> {
    /// 要求受付パイプの名前。
    pub pipe_name: &'a str,
    /// 起こす実行ファイルの**絶対パス**（電文の`image`）。
    pub image: &'a str,
    /// `lpCommandLine`へ逐語で渡る文字列（電文の`command_line`）。
    pub command_line: &'a str,
    pub cwd: &'a str,
    /// 子の標準出力を落とす先。**ここを開いたハンドルを電文へ載せる。**
    pub stdout_file: Option<&'a str>,
    /// 電文の`console`欄。**`"required"`か`"not_needed"`の綴りをそのまま運ぶ**
    /// ——ここで真偽値へ畳むと、取り違えたときにどちらを送ったのか報告から読めなくなる。
    pub console: &'a str,
    /// 応答のJSONの置き場（テスト側が読む）。
    pub report_file: Option<&'a str>,
}

#[cfg(windows)]
pub fn run(spec: &Spec) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE};
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut stdout_handle: Option<HANDLE> = None;
    let mut open_error: Option<String> = None;
    if let Some(path) = spec.stdout_file {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        // **継承可で開く。** Daemonはこのハンドルを引き抜いて子の`hStdOutput`へ入れるので、
        // 複製の時点で継承可になっていなくてもよい（Daemon側が`bInheritHandle: true`で
        // 複製する）が、こちら側でも立てておくと「なぜ継承されないのか」を切り分けやすい。
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&sa as *const _),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(handle) => stdout_handle = Some(handle),
            // **開けなかったことを黙らせない。** 黙ると「子が何も書かなかった」に見える。
            Err(e) => open_error = Some(format!("CreateFileW({path}): {e}")),
        }
    }

    let payload = json!({
        "kind": "spawn",
        "image": spec.image,
        "command_line": spec.command_line,
        "cwd": spec.cwd,
        // **`null`は「申告していない」。** `[]`（空だと申告した）を送ると、子は
        // `SystemRoot`の無い環境ブロックで起こされ、`CreateProcessW`が
        // `ERROR_ENVVAR_NOT_FOUND`で落ちる（電文側のdocに経緯がある）。
        // フックの本番（6f-2）はここで呼び出し元の環境を`Some`で載せる。
        "env": Value::Null,
        "handles": {
            "stdin": Value::Null,
            "stdout": stdout_handle.map(|h| h.0 as usize as u64),
            "stderr": Value::Null,
        },
        "console": spec.console,
        "suspended": false,
    })
    .to_string();

    let round_trip = crate::pipe_client::run_spec(&crate::pipe_client::Spec {
        pipe_name: spec.pipe_name,
        payload_override: Some(&payload),
        // **往復の報告はここでは書き出さない**（下で自分の報告に畳んでから書く）。
        report_file: None,
        repeat: 1,
        start_at_epoch_ms: None,
    });

    // 子側の端はもう要らない。**閉じないと、子が終わってもファイルが掴まれたままになる。**
    if let Some(handle) = stdout_handle {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }

    let reply: Option<Value> = round_trip
        .get("reply")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str(s).ok());

    let mut report = json!({
        "mode": "spawn-via-daemon",
        "connected": round_trip.get("connected").cloned().unwrap_or(Value::Null),
        "last_error": round_trip.get("last_error").cloned().unwrap_or(Value::Null),
        "sent": payload,
        "reply": round_trip.get("reply").cloned().unwrap_or(Value::Null),
        "reply_kind": reply.as_ref().and_then(|r| r.get("kind")).cloned(),
        "stdout_handle_opened": stdout_handle.is_some(),
        "stdout_open_error": open_error,
    });

    if let Some(reply) = reply.as_ref() {
        if reply.get("kind").and_then(Value::as_str) == Some("spawned") {
            report["child_pid"] = reply.get("pid").cloned().unwrap_or(Value::Null);
            let process = reply.get("process").and_then(Value::as_u64);
            let thread = reply.get("thread").and_then(Value::as_u64);
            report["got_process_handle"] = json!(process.is_some_and(|h| h != 0));
            report["got_thread_handle"] = json!(thread.is_some_and(|h| h != 0));
            if let Some(process) = process {
                let (waited, exit_code, error) = wait_for(process);
                report["waited_ok"] = json!(waited);
                report["child_exit_code"] = exit_code.map(Value::from).unwrap_or(Value::Null);
                report["wait_error"] = error.map(Value::from).unwrap_or(Value::Null);
            }
        } else {
            report["deny_reason"] = reply.get("reason").cloned().unwrap_or(Value::Null);
        }
    }

    if let Some(path) = spec.report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

/// 返ってきたプロセスハンドルで待ち、終了コードを読む。
///
/// **`GetExitCodeProcess`だけで「終わったか」を判定しない**——`STILL_ACTIVE`(259)と
/// 「259で終了した」が区別できない（`harness-sandbox`の`process_is_alive`と同じ理屈）。
/// 先に`WaitForSingleObject`でシグナルを待つ。
#[cfg(windows)]
fn wait_for(process: u64) -> (bool, Option<u32>, Option<String>) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

    let handle = HANDLE(process as usize as *mut _);
    let waited = unsafe { WaitForSingleObject(handle, 30_000) };
    if waited != WAIT_OBJECT_0 {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return (
            false,
            None,
            Some(format!("WaitForSingleObject returned {}", waited.0)),
        );
    }
    let mut code = 0u32;
    let read = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    match read {
        Ok(()) => (true, Some(code), None),
        Err(e) => (true, None, Some(format!("GetExitCodeProcess: {e}"))),
    }
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({ "mode": "spawn-via-daemon", "error": "windows only" })
}
