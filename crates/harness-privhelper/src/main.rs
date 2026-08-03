//! harness-privhelper: 特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5）。
//!
//! harness本体（`harness.exe`）が`runas`で昇格起動する極小の別バイナリ。引数に受け取った
//! named pipe名へclientとして接続し、1件の固定スキーマ要求（`harness_sandbox::tier2a::privhelper::
//! PrivilegedRequest`）を処理して応答したら終了する（常駐しない）。LLMループ・ツール
//! ディスパッチを一切含まない、独立にビルド・監査可能な最小コード（§5.1）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: harness-privhelper.exe <named-pipe-name>");
            return std::process::ExitCode::FAILURE;
        }
    };
    match harness_sandbox::tier2a::privhelper::serve(&pipe_name) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("harness-privhelper: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("harness-privhelper is Windows-only (Tier2a D-16 privilege-separation helper)");
    std::process::ExitCode::FAILURE
}
