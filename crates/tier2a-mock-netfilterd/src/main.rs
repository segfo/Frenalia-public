//! Tier2a WFP fail-closed E2E専用のフォールト注入バイナリ。本物の`harness-netfilterd.exe`と
//! 同じ引数規約（argv[1] = named pipe名）だけを真似るが、`ApplyRules`には一切応答せず、
//! 接続後すぐにハンドルを閉じて終了する。`crates/harness-sandbox/src/netfilterd.rs`の
//! `connect_and_apply`は、クライアント接続直後にパイプが切断されるため
//! `ERROR_BROKEN_PIPE`で即座に失敗する（30秒の`CONNECT_TIMEOUT`を待たない）。
//!
//! 本物の`harness-netfilterd`（`crates/harness-netfilterd`）は変更しない。このバイナリは
//! `docs/DEV-ENVIRONMENT.md`が指示する通常のharnessビルド成果物には含まれず、E2Eテストが
//! 明示的にビルドし、一時ディレクトリへ`harness-netfilterd.exe`という名前で配置して使う。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::iter::once;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    let Some(pipe_name) = std::env::args().nth(1) else {
        eprintln!("usage: tier2a-mock-netfilterd.exe <named-pipe-name>");
        return std::process::ExitCode::FAILURE;
    };
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(once(0)).collect();

    // サーバ側(`prepare_pipe`)が`launch_daemon_elevated`より先にパイプを作っているため、
    // 通常は初回で接続できる。念のため数回だけ短い間隔でリトライする(それでも「即座に
    // 終了する」という設計意図は保たれる、待つのは最大でも数十ミリ秒)。
    for _ in 0..5 {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )
        };
        if let Ok(h) = handle {
            // 何も送受信せず即座に閉じる。サーバ側の次のI/Oが`ERROR_BROKEN_PIPE`で
            // すぐ失敗するようにするのが目的。
            unsafe {
                let _ = CloseHandle(h);
            }
            return std::process::ExitCode::SUCCESS;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    eprintln!("tier2a-mock-netfilterd: failed to connect to {pipe_name}");
    std::process::ExitCode::FAILURE
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("tier2a-mock-netfilterd is Windows-only");
    std::process::ExitCode::FAILURE
}
