//! **MAC/Spawn Daemon設計 §10.1（要求受付パイプ）の実現性スパイク専用モード**
//! （`plans/mac-spike/RESULTS.md`）。
//!
//! 既存のtier2aのIPC（netfilterd・privhelper・policy_learnd）は「**ユーザー専有DACL**＝
//! サンドボックスから到達不能」を前提にしている。Spawn Daemonの**要求受付パイプは、その前提を
//! 初めて意図的に破る**（spawn要求用capability SID宛ACEで到達可能にする）。
//!
//! **一意名は防御に数えない**（2026-08-26の実測で訂正。当初この行は「ユーザー専有DACL＋一意名」と
//! 書いていた）。AppContainerの子から`\\.\pipe\`の一覧は取れ、**生きたprivhelperのパイプ名が
//! その中に見える**。到達不能という結論は変わらない——DACLだけで足りている
//! （同じ子からの`CreateFileW`はアクセス拒否）。`unique_pipe_name`の一意性は衝突回避が目的で、
//! 秘匿ではない。測定は`plans/handoff-issue-20/T4.md`。
//!
//! このモードはAppContainerの中からクライアントとして接続し、
//! `crates/harness-sandbox/src/win_pipe_ipc.rs`と**同じフレーム形式**
//! （`[4バイトのリトルエンディアン長][ペイロード]`）で1往復する。
//!
//! 測るのは次の対である（B-35）。
//!
//! - spawn要求用capabilityを**積んだ**トークンでは往復できること
//! - **積まない**トークン、および別プロファイル（MCPサーバのpackage SID）では到達できないこと
//!
//! フレーム形式は`win_pipe_ipc`の実装をこの1ファイルへ写している（プローブは
//! `harness-sandbox`に依存できない——i686でもビルドできる最小依存が要件）。**写しである以上、
//! 長さプレフィックスの綴りがずれたら往復が黙って壊れる**ので、ドライバ側は
//! 「往復した内容が一致すること」まで確かめる。

use serde_json::{json, Value};

#[cfg(windows)]
pub fn run(pipe_name: &str, payload_override: Option<&str>, report_file: Option<&str>) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;

    let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

    // **`ERROR_PIPE_BUSY`は「拒否された」ではない。**
    //
    // 名前付きパイプのサーバは、いつでも受付中のインスタンスを持っているとは限らない
    // （1本を受理してから次を作るまでの窓がある）。その窓に当たったクライアントは
    // `ERROR_PIPE_BUSY`(231)を受け取る。**再試行しないと、これが「到達できなかった」に
    // 化ける**——そして`connected:false`は「DACLで拒否された」と同じ見た目になるので、
    // **拒否側の測定が正しい理由で緑になっているか誰にも分からなくなる**（`B-35`の逆向き:
    // 対の拒否側が、測りたかったのとは別の理由で成立してしまう）。
    //
    // 空きを待って撃ち直すのが名前付きパイプのクライアント側の作法で、綴りは
    // `harness-sandbox-vm`の`vmsandboxd/client.rs`が既に持っている（あちらのdocに経緯がある）。
    // **プローブは`harness-sandbox`に依存できない**（i686でもビルドできる最小依存が要件）ので、
    // ここは写しである。
    const BUSY_RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let deadline = std::time::Instant::now() + BUSY_RETRY_BUDGET;
    let mut busy_retries = 0u32;
    let handle = loop {
        let attempt = unsafe {
            CreateFileW(
                PCWSTR(name_w.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let last_error = unsafe { GetLastError() }.0;
        match attempt {
            Ok(h) => break h,
            Err(_) if last_error == ERROR_PIPE_BUSY.0 => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    // 予算を使い切ったことは**報告に残す**。「拒否された」と読まれないように、
                    // `last_error`をそのまま載せる（231なら混雑、5ならDACL）。
                    let report = json!({
                        "mode": "pipe-client",
                        "pipe": pipe_name,
                        "connected": false,
                        "last_error": last_error,
                        "busy_retries": busy_retries,
                        "error": "the pipe stayed busy for the whole retry budget",
                    });
                    if let Some(path) = report_file {
                        let _ = std::fs::write(path, report.to_string());
                    }
                    return report;
                }
                busy_retries += 1;
                let remaining = deadline - now;
                unsafe {
                    let _ = WaitNamedPipeW(
                        PCWSTR(name_w.as_ptr()),
                        remaining.as_millis().min(u32::MAX as u128) as u32,
                    );
                }
            }
            Err(e) => {
                let report = json!({
                    "mode": "pipe-client",
                    "pipe": pipe_name,
                    "connected": false,
                    "last_error": last_error,
                    "busy_retries": busy_retries,
                    "error": e.to_string(),
                });
                if let Some(path) = report_file {
                    let _ = std::fs::write(path, report.to_string());
                }
                return report;
            }
        }
    };

    // **既定の綴りは変えられない。** スパイクS7がこの文字列をassertしている
    // （`mac_spike_daemon_tests`）。段階5の受け入れテストは本物の要求電文（JSON）を
    // 送る必要があるので、そこだけ`--pipe-payload`で差し替える。
    let payload = match payload_override {
        Some(custom) => custom.to_string(),
        None => format!("spawn-request-from-pid-{}", std::process::id()),
    };
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload.as_bytes());

    let mut written = 0u32;
    let write_ok = unsafe { WriteFile(handle, Some(&frame), Some(&mut written), None) }.is_ok();

    // 応答も同じフレーム形式で読む（長さ4バイト → 本体）。
    let mut len_buf = [0u8; 4];
    let mut read_bytes = 0u32;
    let len_ok =
        unsafe { ReadFile(handle, Some(&mut len_buf), Some(&mut read_bytes), None) }.is_ok();
    let reply_len = u32::from_le_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len.min(4096)];
    let body_ok = if len_ok && read_bytes == 4 && !reply.is_empty() {
        unsafe { ReadFile(handle, Some(&mut reply), Some(&mut read_bytes), None) }.is_ok()
    } else {
        false
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    let report = json!({
        "mode": "pipe-client",
        "pipe": pipe_name,
        "connected": true,
        "busy_retries": busy_retries,
        "sent": payload,
        "write_ok": write_ok,
        "wrote_bytes": written,
        "reply_len": reply_len,
        "reply_ok": body_ok,
        "reply": String::from_utf8_lossy(&reply[..read_bytes.min(reply.len() as u32) as usize]),
    });
    if let Some(path) = report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

#[cfg(not(windows))]
pub fn run(pipe_name: &str, _payload_override: Option<&str>, _report_file: Option<&str>) -> Value {
    json!({"mode": "pipe-client", "pipe": pipe_name, "connected": false, "error": "windows-only"})
}
