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
//!
//! # 混雑を測る側（2026-09-07、T1で追加）
//!
//! **当初この計器は「何回撃ち直したか」（`busy_retries`）しか報告しなかった。**
//! 回数だけでは、1回の待ちが1msでも1秒でも同じ数字になる——`docs/STATUS.md`残課題#43が
//! 問うているのは**待ち時間**なので、回数は答えになっていない。そこで時間の欄を足した
//! （[`Attempt`]）。**成功した回にも失敗した回にも同じ欄を載せる**——片方だけに載せると、
//! 予算を使い切った回（＝最も長く待った回）の待ち時間が結果から消える。
//!
//! あわせて、**同時到着を作るための2つ**を持たせた。
//!
//! - 集合時刻（`--pipe-client-at`）: N個の子が同じ壁時計時刻まで待ってから一斉に撃つ。
//!   **そろったかどうかは後から確かめる**ので、実際に撃った時刻（`start_epoch_us`）を毎回報告する
//! - 繰り返し（`--pipe-client-repeat`）: 接続と1往復をM回繰り返す。混雑は**接続のたびに**
//!   起こるので、1プロセス1回では標本が足りない

use serde_json::{json, Value};

/// 混雑で撃ち直すときの予算。**使い切ったら諦めて報告する**（黙って失敗しない、`B-10`）。
#[cfg(windows)]
const BUSY_RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// 1回の「接続 → 1往復」の記録。
///
/// **`connect_elapsed_us`と`busy_wait_us`を別々に持つ。** 前者は接続ループ全体の実時間で、
/// 混雑が無くても掛かる分（`CreateFileW`のアクセスチェック等）を含む。後者は
/// **混雑で待たされた分だけ**である。1つにまとめると、「待たされた」と「元々それくらい掛かる」を
/// 区別できない。
#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Attempt {
    /// 何回目の試行か（0起点）。
    pub index: u32,
    /// 接続ループへ入った時刻（UNIXエポックからのマイクロ秒）。**到着がそろったかの検算用。**
    pub start_epoch_us: u128,
    /// 接続ループへ入ってから抜けるまで（成功・失敗どちらでも）。
    pub connect_elapsed_us: u128,
    /// 1往復を終えた時刻（UNIXエポックからのマイクロ秒）。
    ///
    /// **毎秒何本を捌けたかは、これが無いと出せない**——開始時刻だけでは、
    /// 最後の1本が終わった時刻が分からず、母数の「実時間」が決まらない。
    pub end_epoch_us: u128,
    /// `ERROR_PIPE_BUSY`で撃ち直した回数。
    pub busy_retries: u32,
    /// 混雑で待った時間の合計。**混雑しなければ0**（観測した結果の0であって、既定値ではない）。
    pub busy_wait_us: u128,
    /// 最初に混雑を踏んだのが、接続ループへ入ってから何マイクロ秒後か。踏んでいなければ`None`。
    pub first_busy_at_us: Option<u128>,
    /// 繋がったか。**`false`を「拒否された」と読まないこと**——混雑の予算切れでも`false`になる。
    pub connected: bool,
    /// 最後の`GetLastError`。**231なら混雑、5ならDACL**（この区別を落とすと、拒否側の
    /// 測定が別の理由で緑になる。§10.1）。
    pub last_error: u32,
    /// 応答本文（往復できたときだけ）。
    pub reply: Option<String>,
    /// 応答が読めたか。
    pub reply_ok: bool,
    /// 送った本文の長さ（往復の検算用）。
    pub wrote_bytes: u32,
    /// 失敗の説明（`connected: false`のときだけ）。
    pub error: Option<String>,
}

impl Attempt {
    fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "start_epoch_us": self.start_epoch_us,
            "end_epoch_us": self.end_epoch_us,
            "connect_elapsed_us": self.connect_elapsed_us,
            "busy_retries": self.busy_retries,
            "busy_wait_us": self.busy_wait_us,
            "first_busy_at_us": self.first_busy_at_us,
            "connected": self.connected,
            "last_error": self.last_error,
            "reply": self.reply,
            "reply_ok": self.reply_ok,
            "wrote_bytes": self.wrote_bytes,
            "error": self.error,
        })
    }
}

/// UNIXエポックからのマイクロ秒。**集合時刻の合わせと、到着のばらつきの検算に使う。**
#[cfg_attr(not(windows), allow(dead_code))]
pub fn epoch_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0)
}

/// 集合時刻（UNIXエポックms）まで待つ。**過ぎていれば即座に戻る。**
///
/// 粗く眠ってから最後だけ回して待つ。`Sleep`の分解能（既定15.6ms）でそろえると、
/// **測りたい混雑と同じ桁のばらつきが到着側に乗る**ためである。
#[cfg_attr(not(windows), allow(dead_code))]
fn wait_until_epoch_ms(target_ms: u128) {
    let target_us = target_ms * 1_000;
    loop {
        let now = epoch_us();
        if now >= target_us {
            return;
        }
        let remaining_us = target_us - now;
        if remaining_us > 30_000 {
            std::thread::sleep(std::time::Duration::from_micros(
                (remaining_us - 20_000).min(u64::MAX as u128) as u64,
            ));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// 1往復ぶんの設定。
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Spec<'a> {
    pub pipe_name: &'a str,
    pub payload_override: Option<&'a str>,
    pub report_file: Option<&'a str>,
    /// 何回繰り返すか（既定1）。
    pub repeat: u32,
    /// 集合時刻（UNIXエポックms）。**1回目の接続だけがこれを待つ**——
    /// 2回目以降まで待たせると、測っているのは「そろえた到着」ではなく待ちの精度になる。
    pub start_at_epoch_ms: Option<u128>,
}

#[cfg(windows)]
pub fn run_spec(spec: &Spec) -> Value {
    let repeat = spec.repeat.max(1);
    if let Some(at) = spec.start_at_epoch_ms {
        wait_until_epoch_ms(at);
    }

    let mut attempts = Vec::with_capacity(repeat as usize);
    for index in 0..repeat {
        attempts.push(one_round_trip(spec, index));
    }

    // **1回だけの実行では、従来の綴りをそのまま残す。** S7（`mac_spike_daemon_tests`）と
    // 段階③の受け入れテストが`connected`・`reply`・`busy_retries`をトップレベルで読んでいるので、
    // 欄を配列の中へ引っ越すと、それらが**欄を見失ったまま緑になる**（`serde_json`の
    // `get`は無い欄を`None`で返すだけで、誰も落ちない）。
    let first = attempts.first().expect("repeat >= 1");
    let mut report = json!({
        "mode": "pipe-client",
        "pipe": spec.pipe_name,
        "connected": first.connected,
        "busy_retries": first.busy_retries,
        "busy_wait_us": first.busy_wait_us,
        "connect_elapsed_us": first.connect_elapsed_us,
        "first_busy_at_us": first.first_busy_at_us,
        "start_epoch_us": first.start_epoch_us,
        "last_error": first.last_error,
        "attempts": attempts.iter().map(Attempt::to_json).collect::<Vec<_>>(),
        "attempt_count": attempts.len(),
    });
    if let Some(error) = &first.error {
        report["error"] = json!(error);
    }
    if first.connected {
        report["sent"] = json!(payload_for(spec));
        report["write_ok"] = json!(first.wrote_bytes > 0);
        report["wrote_bytes"] = json!(first.wrote_bytes);
        report["reply_ok"] = json!(first.reply_ok);
        report["reply"] = json!(first.reply.clone().unwrap_or_default());
        report["reply_len"] = json!(first.reply.as_ref().map(|r| r.len()).unwrap_or(0));
    }

    if let Some(path) = spec.report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

/// **既定の綴りは変えられない。** スパイクS7がこの文字列をassertしている
/// （`mac_spike_daemon_tests`）。段階5の受け入れテストは本物の要求電文（JSON）を
/// 送る必要があるので、そこだけ`--pipe-payload`で差し替える。
#[cfg(windows)]
fn payload_for(spec: &Spec) -> String {
    match spec.payload_override {
        Some(custom) => custom.to_string(),
        None => format!("spawn-request-from-pid-{}", std::process::id()),
    }
}

#[cfg(windows)]
fn one_round_trip(spec: &Spec, index: u32) -> Attempt {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;

    let name_w: Vec<u16> = spec
        .pipe_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

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
    let mut attempt = Attempt {
        index,
        start_epoch_us: epoch_us(),
        ..Attempt::default()
    };
    let started = std::time::Instant::now();
    let deadline = started + BUSY_RETRY_BUDGET;
    let handle = loop {
        let opened = unsafe {
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
        match opened {
            Ok(h) => {
                attempt.connect_elapsed_us = started.elapsed().as_micros();
                break h;
            }
            Err(_) if last_error == ERROR_PIPE_BUSY.0 => {
                let now = std::time::Instant::now();
                if attempt.first_busy_at_us.is_none() {
                    attempt.first_busy_at_us = Some((now - started).as_micros());
                }
                if now >= deadline {
                    // 予算を使い切ったことは**報告に残す**。「拒否された」と読まれないように、
                    // `last_error`をそのまま載せる（231なら混雑、5ならDACL）。
                    attempt.connect_elapsed_us = started.elapsed().as_micros();
                    attempt.busy_wait_us = attempt.connect_elapsed_us;
                    attempt.last_error = last_error;
                    attempt.error = Some("the pipe stayed busy for the whole retry budget".into());
                    attempt.end_epoch_us = epoch_us();
                    return attempt;
                }
                attempt.busy_retries += 1;
                let waited_from = std::time::Instant::now();
                let remaining = deadline - now;
                unsafe {
                    let _ = WaitNamedPipeW(
                        PCWSTR(name_w.as_ptr()),
                        remaining.as_millis().min(u32::MAX as u128) as u32,
                    );
                }
                // **待った実時間を足す。** `WaitNamedPipeW`が「空いた」と言って戻っても、
                // 他のクライアントに先を越されて次の`CreateFileW`がまた231を返すことがある
                // ——そのぶんもここに積み上がる。
                attempt.busy_wait_us += waited_from.elapsed().as_micros();
            }
            Err(e) => {
                attempt.connect_elapsed_us = started.elapsed().as_micros();
                attempt.last_error = last_error;
                attempt.error = Some(e.to_string());
                attempt.end_epoch_us = epoch_us();
                return attempt;
            }
        }
    };

    attempt.connected = true;
    let payload = payload_for(spec);
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload.as_bytes());

    let mut written = 0u32;
    let _ = unsafe { WriteFile(handle, Some(&frame), Some(&mut written), None) };
    attempt.wrote_bytes = written;

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

    attempt.reply_ok = body_ok;
    attempt.reply = Some(
        String::from_utf8_lossy(&reply[..read_bytes.min(reply.len() as u32) as usize]).to_string(),
    );
    attempt.end_epoch_us = epoch_us();
    attempt
}

#[cfg(not(windows))]
pub fn run_spec(spec: &Spec) -> Value {
    json!({"mode": "pipe-client", "pipe": spec.pipe_name, "connected": false, "error": "windows-only"})
}

#[cfg(all(windows, test))]
#[path = "pipe_client_tests.rs"]
mod pipe_client_tests;
