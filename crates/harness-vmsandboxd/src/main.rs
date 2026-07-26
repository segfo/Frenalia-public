//! harness-vmsandboxd: Tier3（Hyper-V外層VM + Incusコンテナ）用の常駐デーモン
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.2参照）。
//!
//! `harness.exe`が`runas`で昇格起動する別バイナリ。引数に受け取った named pipe名へclientとして
//! 接続し、`StartSession`でVM+コンテナを起動したら**常駐を続け**、`run_shell`呼び出しのたびに
//! 送られる`Exec`を反復処理する。`Teardown`（または親のクラッシュによるパイプ切断）を受けて
//! VM+コンテナ+差分VHDXを撤収してから終了する。`harness-netfilterd`と同じ理由で常駐する
//! （Hyper-V VMは起動元プロセスと独立に生存し続けるため、能動的な撤収が唯一の後始末経路）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: harness-vmsandboxd.exe <named-pipe-name> [--gc-only]");
            return std::process::ExitCode::FAILURE;
        }
    };
    // `--gc-only`（`harness tier3 gc`、A9）: 通常のセッション常駐ループ（`serve`）ではなく、
    // 1件の`Gc`リクエストだけを処理して即終了する（`vmsandboxd::serve_gc`参照）。
    let gc_only = std::env::args().nth(2).as_deref() == Some("--gc-only");
    let result = if gc_only {
        harness_sandbox::vmsandboxd::serve_gc(&pipe_name)
    } else {
        harness_sandbox::vmsandboxd::serve(&pipe_name)
    };
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
