//! **T-5: ブローカーが「開いたハンドル」を手渡す形はいくらか**（測定の子役）。
//! 結果の正本は`plans/handoff/fs-boundary-cost/T-5.md`、
//! ドライバは`harness-sandbox`の`broker_handoff_cost_tests`。
//!
//! ## なぜこのモードが要るのか（既存の`--pipe-client`で足りない理由）
//!
//! 既存の`--pipe-client`は**1往復して終わる**到達性の的で、往復回数も、返ってきた値の
//! 使い道も持たない。ここで測るのは「N回の往復にいくら掛かるか」と「渡されたハンドルが
//! **実際に使えるか**」なので、**回数**と**受け取ったハンドルの利用**の2つが要る。
//! フレーム形式・接続の作法は`pipe_client`と同じものを踏襲する（写しではなく同形）。
//!
//! ## 何を測るか
//!
//! 親（フルトラストのharness役）とAppContainerの子の間に、capability SID宛ACEを付けた
//! 名前付きパイプを1本張る（設計§10.1の要求受付パイプと同じ形）。子は「このパスを
//! 開いてほしい」と頼み、親は腕ごとに違う仕事をして返す。**腕の切り替えは子が宣言する**
//! （`ARM:<名前>`フレーム）ので、両側の腕がずれることがない。
//!
//! | 腕 | 親がやること | 子に返るもの |
//! |---|---|---|
//! | `warmup` | 何もしない | `0` |
//! | `rtt` | 何もしない | `0` |
//! | `open` | `CreateFileW`して即`CloseHandle` | `0` |
//! | `handoff` | `CreateFileW` → `DuplicateHandle`で子へ複製 | ハンドル値（子が閉じる） |
//! | `dacl` | そのパスへ非継承ACEを1本書く（＝§S13の腕Cと同じ仕事） | `0` |
//!
//! ## 「渡した」と「使える」は別の事実なので、分けて確かめる
//!
//! 最後に`verify`の腕を撃つ。ここでは**まず子が自力で同じパスを開こうとして失敗する**ことを
//! 記録してから（この対が無いと、ハンドルが効いたのか元から開けたのかが区別できない、B-35）、
//! 渡されたハンドルで読取と追記を行い、その結果を報告する。**追記が実際に効いたかは親が
//! 読み返して判定する**——子の自己申告は根拠にしない。
//!
//! ## 計器そのものが測定対象を汚していないか
//!
//! 時刻の採取は**1反復につき1回**（ループ開始からの経過ナノ秒）で、JSON化・統計はループの
//! 外で行う。パスの一覧はループ前にファイルから読み込む。**ループの中でO(n)の走査を
//! 一つも回さない**——`plans/mac-spike/RESULTS.md` §S13-0 が踏んだ罠（付与記録の計装が
//! プロセス内一覧を毎回線形走査し、1件あたりが9.6倍に膨らんだ）と同じ形を避けるため。
//!
//! ## 判定が出たらこのファイルは削除する
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして残さない）。

use serde_json::{json, Value};

/// 腕1本ぶんの計画。`paths`の順に1件ずつ要求を送る。
struct Arm {
    name: String,
    paths: Vec<String>,
}

/// 統計。**平均だけでは分布が見えない**ので、中央値と裾（p90/p99）と両端を出す。
fn summarize(name: &str, samples: &[u64], total_ns: u128, handle_ok: usize, errors: usize) -> Value {
    let n = samples.len().max(1);
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let at = |q: f64| -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
        sorted[idx]
    };
    json!({
        "arm": name,
        "items": samples.len(),
        "total_ms": (total_ns as f64) / 1.0e6,
        // 1件あたりは**ループ全体の実測時間÷件数**（§S13と同じ出し方）。
        "us_per_item": (total_ns as f64) / 1000.0 / (n as f64),
        "us_min": sorted.first().copied().unwrap_or(0) as f64 / 1000.0,
        "us_p50": at(0.50) as f64 / 1000.0,
        "us_p90": at(0.90) as f64 / 1000.0,
        "us_p99": at(0.99) as f64 / 1000.0,
        "us_max": sorted.last().copied().unwrap_or(0) as f64 / 1000.0,
        "handles_received": handle_ok,
        "server_errors": errors,
    })
}

#[cfg(windows)]
pub fn run(pipe_name: &str, plan_path: &str, report_file: Option<&str>) -> Value {
    use std::time::{Duration, Instant};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, SetFilePointer, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN,
        FILE_END, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let plan: Value = match std::fs::read_to_string(plan_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            return json!({
                "mode": "broker-bench",
                "ok": false,
                "error": format!("could not read the plan at {plan_path}"),
            })
        }
    };

    let arms: Vec<Arm> = plan
        .get("arms")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|arm| Arm {
                    name: arm
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("?")
                        .to_string(),
                    paths: arm
                        .get("paths")
                        .and_then(|p| p.as_array())
                        .map(|p| {
                            p.iter()
                                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    // --- パイプを開く（サーバが`ConnectNamedPipe`を呼ぶ前でも成立する。少しの間だけ待つ）---
    let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + Duration::from_secs(30);
    let pipe = loop {
        let attempt = unsafe {
            CreateFileW(
                PCWSTR(name_w.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match attempt {
            Ok(h) => break h,
            Err(e) => {
                if Instant::now() >= deadline {
                    return json!({
                        "mode": "broker-bench",
                        "ok": false,
                        "connected": false,
                        "last_error": unsafe { GetLastError() }.0,
                        "error": e.to_string(),
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };

    // --- `win_pipe_ipc`と同じフレーム形式（`[4バイトLE長][本体]`）。写しである以上、
    // 綴りがずれれば往復が黙って壊れるので、ドライバ側が中身の一致まで確かめる。---
    let send = |payload: &str| -> bool {
        let bytes = payload.as_bytes();
        let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(bytes);
        let mut written = 0u32;
        unsafe { WriteFile(pipe, Some(&frame), Some(&mut written), None) }.is_ok()
            && written as usize == frame.len()
    };
    let recv = || -> Option<String> {
        let mut len_buf = [0u8; 4];
        let mut read = 0u32;
        if unsafe { ReadFile(pipe, Some(&mut len_buf), Some(&mut read), None) }.is_err() || read != 4
        {
            return None;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 {
            return Some(String::new());
        }
        let mut body = vec![0u8; len.min(4096)];
        let mut got = 0u32;
        if unsafe { ReadFile(pipe, Some(&mut body), Some(&mut got), None) }.is_err() {
            return None;
        }
        Some(String::from_utf8_lossy(&body[..got as usize]).into_owned())
    };

    let mut results: Vec<Value> = Vec::new();
    let mut fatal: Option<String> = None;

    for arm in &arms {
        if !send(&format!("ARM:{}", arm.name)) || recv().as_deref() != Some("ok") {
            fatal = Some(format!("arm handshake failed: {}", arm.name));
            break;
        }
        let mut samples: Vec<u64> = Vec::with_capacity(arm.paths.len());
        let mut handle_ok = 0usize;
        let mut errors = 0usize;
        let started = Instant::now();
        for path in &arm.paths {
            if !send(path) {
                errors += 1;
                break;
            }
            match recv() {
                Some(reply) => {
                    // 返答は10進のハンドル値。`0`＝ハンドル無し、`E…`＝サーバ側の失敗。
                    if let Ok(raw) = reply.parse::<usize>() {
                        if raw != 0 {
                            handle_ok += 1;
                            unsafe {
                                let _ = CloseHandle(HANDLE(raw as *mut core::ffi::c_void));
                            }
                        }
                    } else {
                        errors += 1;
                    }
                }
                None => {
                    errors += 1;
                    break;
                }
            }
            samples.push(started.elapsed().as_nanos() as u64);
        }
        let total_ns = started.elapsed().as_nanos();
        // 累積値の差分を取って1件ずつの所要へ直す（時刻採取はループ内で1回だけ）。
        let mut per_item = Vec::with_capacity(samples.len());
        let mut prev = 0u64;
        for s in &samples {
            per_item.push(s.saturating_sub(prev));
            prev = *s;
        }
        results.push(summarize(&arm.name, &per_item, total_ns, handle_ok, errors));
    }

    // --- 「渡した」と「使える」を分ける腕 ---
    let mut verify = json!({"ran": false});
    if fatal.is_none() {
        if let Some(spec) = plan.get("verify") {
            let path = spec
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_string();
            let append = spec
                .get("append")
                .and_then(|p| p.as_str())
                .unwrap_or("T5-CHILD-WROTE")
                .to_string();

            // 対照（B-35）: 子が**自力で**同じパスを開けてしまうなら、後段の成功は
            // ハンドル手渡しの手柄ではない。
            let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let own = unsafe {
                CreateFileW(
                    PCWSTR(path_w.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            let own_open_ok = own.is_ok();
            let own_open_error = unsafe { GetLastError() }.0;
            if let Ok(h) = own {
                unsafe {
                    let _ = CloseHandle(h);
                }
            }

            let handshake = send("ARM:verify") && recv().as_deref() == Some("ok");
            let mut handed: usize = 0;
            let mut read_text = String::new();
            let mut read_ok = false;
            let mut write_ok = false;
            let mut write_error = 0u32;
            if handshake && send(&path) {
                if let Some(reply) = recv() {
                    handed = reply.parse::<usize>().unwrap_or(0);
                }
            }
            if handed != 0 {
                let h = HANDLE(handed as *mut core::ffi::c_void);
                let mut buf = vec![0u8; 256];
                let mut got = 0u32;
                unsafe {
                    let _ = SetFilePointer(h, 0, None, FILE_BEGIN);
                }
                read_ok =
                    unsafe { ReadFile(h, Some(&mut buf), Some(&mut got), None) }.is_ok() && got > 0;
                read_text = String::from_utf8_lossy(&buf[..got as usize]).into_owned();
                unsafe {
                    let _ = SetFilePointer(h, 0, None, FILE_END);
                }
                let mut written = 0u32;
                write_ok = unsafe { WriteFile(h, Some(append.as_bytes()), Some(&mut written), None) }
                    .is_ok()
                    && written as usize == append.len();
                write_error = unsafe { GetLastError() }.0;
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
            verify = json!({
                "ran": true,
                "path": path,
                "child_own_open_ok": own_open_ok,
                "child_own_open_last_error": own_open_error,
                "handle_received": handed != 0,
                "read_ok": read_ok,
                "read_text": read_text,
                "write_ok": write_ok,
                "write_last_error": write_error,
                "appended": append,
            });
        }
    }

    let _ = send("ARM:done");
    let _ = recv();
    unsafe {
        let _ = CloseHandle(pipe);
    }

    let report = json!({
        "mode": "broker-bench",
        "ok": fatal.is_none(),
        "connected": true,
        "pid": std::process::id(),
        "fatal": fatal,
        "arms": results,
        "verify": verify,
    });
    if let Some(path) = report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

#[cfg(not(windows))]
pub fn run(pipe_name: &str, _plan_path: &str, _report_file: Option<&str>) -> Value {
    json!({"mode": "broker-bench", "ok": false, "pipe": pipe_name, "error": "windows-only"})
}
