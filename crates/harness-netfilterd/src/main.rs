//! harness-netfilterd: WFP 出口強制フィルタ用の常駐デーモン（Layer2、
//! `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md` §6参照）。
//!
//! `harness.exe`が`runas`で昇格起動する別バイナリ。引数に受け取った named pipe名へclientとして
//! 接続し、`ApplyRules`でWFPフィルタを投入したら**常駐を続け**、`Teardown`（または親のクラッシュ
//! によるパイプ切断）を受けてフィルタを撤収してから終了する。`harness-privhelper`
//! （1起動=1操作で即終了）とは異なり、対象アプリの生存期間中だけ意図的に常駐する
//! （`FWPM_SESSION_FLAG_DYNAMIC`の性質上、エンジンハンドルを保持するプロセスが常駐しないと
//! フィルタが維持できないため）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: harness-netfilterd.exe <named-pipe-name>");
            return std::process::ExitCode::FAILURE;
        }
    };
    match harness_sandbox::netfilterd::serve(&pipe_name) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("harness-netfilterd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("harness-netfilterd is Windows-only (WFP egress guard daemon, Layer2)");
    std::process::ExitCode::FAILURE
}
