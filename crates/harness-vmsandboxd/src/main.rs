//! harness-vmsandboxd: Tier3（Hyper-V外層VM + Incusコンテナ）用の常駐デーモン
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.2参照）。
//!
//! `harness.exe`が`runas`で昇格起動する別バイナリ。S-2でパイプの向きが反転したため、この
//! daemon自身が固定named pipe名（[`harness_sandbox::vmsandboxd::serve_resident`]内で定義）の
//! サーバとなり、`StartSession`でVM+コンテナを起動したら**常駐を続け**、`run_shell`呼び出しの
//! たびに送られる`Exec`を反復処理する。`Teardown`（または親のクラッシュによるパイプ切断）を
//! 受けても、daemonプロセス自体は終了せず次のセッションの接続を待ち続ける
//! （`serve_resident`のdoc参照）。`harness-netfilterd`と同じ理由で常駐する（Hyper-V VMは
//! 起動元プロセスと独立に生存し続けるため、能動的な撤収が唯一の後始末経路）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let pipe_name = match args.next() {
        Some(p) => p,
        None => {
            eprintln!(
                "usage: harness-vmsandboxd.exe <named-pipe-name> --owner-sid <SID> --owner-exe \
                 <path>\n       harness-vmsandboxd.exe <named-pipe-name> --gc-only"
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let rest: Vec<String> = args.collect();

    // `--gc-only`（`harness tier3 gc`、A9）: 通常のセッション常駐ループ（`serve_resident`）
    // ではなく、1件の`Gc`リクエストだけを処理して即終了する（`vmsandboxd::serve_gc`参照）。
    // この経路は使い捨てパイプ名のままなのでS-2の対象外（`--owner-sid`/`--owner-exe`は不要）。
    if rest.first().map(String::as_str) == Some("--gc-only") {
        return run_result(harness_sandbox::vmsandboxd::serve_gc(&pipe_name));
    }

    let (owner_sid, owner_exe, max_sessions) = match parse_owner_args(&rest) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("harness-vmsandboxd: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    run_result(harness_sandbox::vmsandboxd::serve_resident(
        &owner_sid,
        &owner_exe,
        max_sessions,
    ))
}

/// `--owner-sid <SID> --owner-exe <path> [--max-sessions <n>]`をコマンドライン残余引数から
/// 取り出す（S-2・Phase B）。起動元（親、非昇格harness本体）を明示的に伝えるための引数で、
/// daemon自身のトークンSIDや`current_exe()`は使わない（`serve_resident`のdoc参照）。
/// `--max-sessions`省略時は既定4（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）。
#[cfg(windows)]
fn parse_owner_args(rest: &[String]) -> Result<(String, std::path::PathBuf, u8), String> {
    let mut owner_sid = None;
    let mut owner_exe = None;
    let mut max_sessions: u8 = 4;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--owner-sid" => {
                owner_sid = rest.get(i + 1).cloned();
                i += 2;
            }
            "--owner-exe" => {
                owner_exe = rest.get(i + 1).cloned();
                i += 2;
            }
            "--max-sessions" => {
                max_sessions = rest
                    .get(i + 1)
                    .and_then(|s| s.parse::<u8>().ok())
                    .filter(|n| *n >= 1)
                    .unwrap_or(4);
                i += 2;
            }
            _ => i += 1,
        }
    }
    let owner_sid = owner_sid.ok_or_else(|| "missing --owner-sid".to_string())?;
    let owner_exe = owner_exe.ok_or_else(|| "missing --owner-exe".to_string())?;
    Ok((owner_sid, std::path::PathBuf::from(owner_exe), max_sessions))
}

#[cfg(windows)]
fn run_result(
    result: Result<(), harness_sandbox::vmsandboxd::VmSandboxIpcError>,
) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("harness-vmsandboxd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("harness-vmsandboxd is Windows-only (Tier3 VM sandbox daemon)");
    std::process::ExitCode::FAILURE
}
