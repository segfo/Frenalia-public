//! `dev-elevated-runnerd`: 開発用の昇格コマンドランナー・デーモン（本物のharness製品とは
//! 無関係、`Cargo.toml`のコメント参照）。`sudo`で起動し、以後は現在ユーザSID限定DACLの
//! 名前付きパイプで`dev-elevated-run`クライアントからの要求を順番に受ける。
//!
//! クライアントが送るのは`dev_elevated_runner::KNOWN_TARGETS`のキー名1つだけで、実際に
//! 実行する`cargo`引数列はこのバイナリにハードコードされた固定テーブルから引く
//! （`resolve_target_args`）。クライアント由来の文字列が引数配列へ混入する経路は無い。
//!
//! 最終要求から`IDLE_SHUTDOWN`（30分）操作が無ければ自動終了する。この判定は「次の
//! クライアント接続を待つ`ConnectNamedPipe`のタイムアウト」として実装し、タイマー
//! スレッドは使わない（退役した%TEMP%キューデーモンの教訓、`docs/bugs/BUG-046.md`）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use dev_elevated_runner::win::{
        connect_with_timeout, pipe_name_for_current_user, read_framed_timeout,
        user_only_security_attributes, wide, write_framed_timeout,
    };
    use dev_elevated_runner::{resolve_target_args, IDLE_SHUTDOWN, RunRequest, RunResponse};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HLOCAL};
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const RESPONSE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    let pipe_name = match pipe_name_for_current_user() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dev-elevated-runnerd: failed to resolve pipe name: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let sid = match dev_elevated_runner::win::current_user_sid_string() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("dev-elevated-runnerd: failed to resolve current user SID: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // repo root（このクレートの2つ上の階層）を全ターゲット共通のcwdにする。クライアントは
    // cwdを一切指定できない（KNOWN_TARGETSと同じく固定値、任意パスの実行を防ぐ）。
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/dev-elevated-runner has two ancestor dirs (crates/, repo root)")
        .to_path_buf();

    eprintln!(
        "dev-elevated-runnerd: listening on {pipe_name} (cwd={}, idle shutdown after {IDLE_SHUTDOWN:?})",
        repo_root.display()
    );

    loop {
        let mut sa = match user_only_security_attributes(&sid) {
            Ok(sa) => sa,
            Err(e) => {
                eprintln!("dev-elevated-runnerd: user_only_security_attributes failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let pipe_name_w = wide(&pipe_name);
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                1 << 20,
                1 << 20,
                0,
                Some(&mut sa as *mut _),
            )
        };
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        }
        if pipe.is_invalid() {
            eprintln!(
                "dev-elevated-runnerd: CreateNamedPipeW failed: {:?}",
                unsafe { windows::Win32::Foundation::GetLastError() }
            );
            return std::process::ExitCode::FAILURE;
        }

        match connect_with_timeout(pipe, IDLE_SHUTDOWN) {
            Ok(()) => {}
            Err(_) => {
                eprintln!("dev-elevated-runnerd: idle for {IDLE_SHUTDOWN:?}, shutting down");
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return std::process::ExitCode::SUCCESS;
            }
        }

        let result: Result<(), String> = (|| {
            let request_bytes = read_framed_timeout(pipe, REQUEST_READ_TIMEOUT)
                .map_err(|e| format!("read request: {e}"))?;
            let request: RunRequest =
                serde_json::from_slice(&request_bytes).map_err(|e| format!("parse request: {e}"))?;

            eprintln!("dev-elevated-runnerd: request target={:?}", request.target);

            let response = match resolve_target_args(&request.target) {
                None => RunResponse {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!(
                        "unknown target {:?} (this daemon only runs a fixed, hardcoded set of \
                         cargo invocations, see KNOWN_TARGETS in crates/dev-elevated-runner/src/lib.rs)",
                        request.target
                    ),
                },
                Some(args) => {
                    eprintln!("dev-elevated-runnerd: running `cargo {}`", args.join(" "));
                    match std::process::Command::new("cargo")
                        .args(args)
                        // M15.7 / D-44: 昇格ヘルパーの起動時DACLゲートは既定で拒否だが、
                        // 開発ビルドは`target\debug`が必ずユーザー書込可なので必ず引っ掛かる。
                        // ここで逃がし弁を注入しないと、E2Eが1本も走らなくなる。
                        // **ゲート自体の検証は`elevated_launch`の専用テストが担う**ので、
                        // ここで通してもゲートが未検証になることは無い。
                        .env(
                            harness_sandbox::elevated_launch::ALLOW_USER_WRITABLE_HELPERS_ENV,
                            "1",
                        )
                        .current_dir(&repo_root)
                        .output()
                    {
                        Ok(output) => RunResponse {
                            exit_code: output.status.code().unwrap_or(-1),
                            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                        },
                        Err(e) => RunResponse {
                            exit_code: -1,
                            stdout: String::new(),
                            stderr: format!("failed to spawn cargo: {e}"),
                        },
                    }
                }
            };

            let response_bytes =
                serde_json::to_vec(&response).map_err(|e| format!("serialize response: {e}"))?;
            write_framed_timeout(pipe, &response_bytes, RESPONSE_WRITE_TIMEOUT)
                .map_err(|e| format!("write response: {e}"))?;
            Ok(())
        })();

        if let Err(e) = result {
            eprintln!("dev-elevated-runnerd: request failed: {e}");
        }

        unsafe {
            // `DisconnectNamedPipe`はクライアントがまだ読んでいないデータを破棄して即座に
            // 切断するため、直前の`write_framed_timeout`（応答送信）が「OSバッファへ書けた」
            // ことしか保証しない状態でこれを呼ぶと、クライアント側の`ReadFile`が
            // ERROR_PIPE_NOT_CONNECTEDで失敗する競合が起きる（実機で発生を確認）。
            // `FlushFileBuffers`はクライアントが全データを読み終えるまで待つ、名前付き
            // パイプサーバの標準的な同期パターン。
            let _ = windows::Win32::Storage::FileSystem::FlushFileBuffers(pipe);
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("dev-elevated-runnerd is Windows-only");
    std::process::ExitCode::FAILURE
}
