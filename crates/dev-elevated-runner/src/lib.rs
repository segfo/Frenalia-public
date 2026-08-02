//! `dev-elevated-runner`の共有部分（プロトコル型・入力検証・パイプIPCヘルパー）。
//! IPCヘルパーは`crates/harness-sandbox/src/netfilterd.rs`と同型のパターン（overlapped I/O・
//! タイムアウト付きread/write・現在ユーザSID限定DACL）を複製したもの。ライフサイクルが
//! 異なる（本クレートは多数のクライアント接続を順番に受け続ける、netfilterdは1セッション
//! 2往復で終了）ため、netfilterd.rs自身のdocコメントに倣い汎用化せず複製する。

use serde::{Deserialize, Serialize};

pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\dev-elevated-runner-";

/// 最終要求からこの時間操作が無ければサーバは自動終了する（タイマーではなく、
/// 「次のクライアント接続を待つ`ConnectNamedPipe`のタイムアウト」として実装する。
/// 退役した%TEMP%キューデーモンの教訓＝生存期間をOSの待機プリミティブに紐付ける、
/// を踏まえたもの。無期限の常駐にはしない）。
pub const IDLE_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// クライアントは自由なコマンドラインを一切送らない。送るのは下表のキー名（記号を含まない
/// 識別子）だけで、実際に実行される`cargo`の引数列はサーバ側にハードコードされた固定値
/// （このテーブル）から引く。クライアント由来の文字列が引数配列へ混入する経路が無いため、
/// 「`&&`/`;`等のシェルメタ文字を拒否する」を個別チェックする必要すらない——キーが完全一致
/// しない時点で拒否される（ユーザー指示: 「どのテストケースを実行するか」だけを送る設計）。
/// 新しいテストターゲットが必要になったら、このテーブルへ1行追加する（コード変更が要る、
/// 実行時の任意入力では増やせない）。
pub const KNOWN_TARGETS: &[(&str, &[&str])] = &[
    (
        "e2e-all",
        &["test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture"],
    ),
    (
        "e2e-cow-matrix",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_cow_commit_matrix",
        ],
    ),
    (
        "e2e-net-matrix",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_net_policy_matrix",
        ],
    ),
    (
        "cow-diagnostics",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "win_appcontainer::cow_diagnostics",
        ],
    ),
    // `dev-elevated-runner`自身は除外する。デーモン(`dev-elevated-runnerd.exe`)がこの
    // コマンドを実行している間、自分自身の実行ファイルは起動中でロックされておりリンクし
    // 直せない（実機で`error: failed to remove file ...dev-elevated-runnerd.exe: アクセスが
    // 拒否されました`を確認済み）。本セッションで再ビルドが必要な対象はharness本体側だけ。
    ("workspace-build", &["build", "--workspace", "--exclude", "dev-elevated-runner"]),
    (
        "workspace-clippy",
        &["clippy", "--workspace", "--exclude", "dev-elevated-runner", "--all-targets"],
    ),
    ("workspace-test", &["test", "--workspace", "--exclude", "dev-elevated-runner"]),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    /// `KNOWN_TARGETS`のキーのいずれかと完全一致する必要がある。
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// サーバ側が権威的に検証する（クライアント側でも同じ関数を使うが、クライアントを
/// 信用しない——実際にコマンドを起動するのはサーバ側の`resolve_target`であり、
/// そちらも独立に`KNOWN_TARGETS`の完全一致を要求する）。
pub fn validate_target(target: &str) -> Result<(), String> {
    if KNOWN_TARGETS.iter().any(|(name, _)| *name == target) {
        Ok(())
    } else {
        let known: Vec<&str> = KNOWN_TARGETS.iter().map(|(name, _)| *name).collect();
        Err(format!("unknown target {target:?} (known targets: {known:?})"))
    }
}

/// `target`に対応する固定引数列を返す。`validate_target`と同じ完全一致判定を独立に
/// 行うため、こちらを呼ぶだけでも安全（`validate_target`を呼び忘れても任意引数は
/// 実行されない）。
pub fn resolve_target_args(target: &str) -> Option<&'static [&'static str]> {
    KNOWN_TARGETS
        .iter()
        .find(|(name, _)| *name == target)
        .map(|(_, args)| *args)
}

#[cfg(windows)]
pub mod win {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::IO::OVERLAPPED;

    #[derive(Debug)]
    pub enum IpcError {
        Ipc(String),
        Win32(String),
    }

    impl std::fmt::Display for IpcError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                IpcError::Ipc(s) => write!(f, "ipc error: {s}"),
                IpcError::Win32(s) => write!(f, "win32 error: {s}"),
            }
        }
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn current_user_sid_string() -> windows::core::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            let mut ret_len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
            let mut buf = vec![0u8; ret_len as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                ret_len,
                &mut ret_len,
            )?;
            let _ = CloseHandle(token);
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str = windows::core::PWSTR::null();
            ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str)?;
            let s = sid_str.to_string()?;
            let _ = windows::Win32::Foundation::LocalFree(HLOCAL(sid_str.0 as *mut _));
            Ok(s)
        }
    }

    pub fn pipe_name_for_current_user() -> windows::core::Result<String> {
        Ok(format!("{PIPE_NAME_PREFIX}{}", current_user_sid_string()?))
    }

    pub fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
        let sddl = format!("D:(A;;GA;;;{sid})");
        unsafe {
            let sddl_w = wide(&sddl);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
            Ok(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            })
        }
    }

    pub fn run_overlapped<F>(
        handle: HANDLE,
        timeout: std::time::Duration,
        op_name: &str,
        start: F,
    ) -> Result<u32, IpcError>
    where
        F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
    {
        use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
        unsafe {
            let event = CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|e| IpcError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };
            let pending = match start(&mut overlapped as *mut _) {
                Ok(()) => false,
                Err(e) => {
                    let code = e.code();
                    if code == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) {
                        true
                    } else if code == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                        let _ = CloseHandle(event);
                        return Ok(0);
                    } else {
                        let _ = CloseHandle(event);
                        return Err(IpcError::Ipc(format!("{op_name} failed to start: {e}")));
                    }
                }
            };
            if pending {
                let wait =
                    WaitForSingleObject(event, timeout.as_millis().min(u32::MAX as u128) as u32);
                if wait != WAIT_OBJECT_0 {
                    let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                    let mut transferred = 0u32;
                    let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                    let _ = CloseHandle(event);
                    return Err(IpcError::Ipc(format!("{op_name} timed out after {timeout:?}")));
                }
            }
            let mut transferred = 0u32;
            let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
            let _ = CloseHandle(event);
            result.map_err(|e| IpcError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}")))?;
            Ok(transferred)
        }
    }

    pub fn write_all_timeout(
        handle: HANDLE,
        buf: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &buf[offset..];
            let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
                WriteFile(handle, Some(slice), None, Some(ov))
            })?;
            if written == 0 {
                return Err(IpcError::Ipc("WriteFile wrote 0 bytes".to_string()));
            }
            offset += written as usize;
        }
        Ok(())
    }

    pub fn read_exact_timeout(
        handle: HANDLE,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &mut buf[offset..];
            let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
                ReadFile(handle, Some(slice), None, Some(ov))
            })?;
            if read == 0 {
                return Err(IpcError::Ipc("ReadFile read 0 bytes (pipe closed?)".to_string()));
            }
            offset += read as usize;
        }
        Ok(())
    }

    pub fn write_framed_timeout(
        handle: HANDLE,
        payload: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        let len = (payload.len() as u32).to_le_bytes();
        write_all_timeout(handle, &len, timeout)?;
        write_all_timeout(handle, payload, timeout)
    }

    pub fn read_framed_timeout(
        handle: HANDLE,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, IpcError> {
        let mut len_buf = [0u8; 4];
        read_exact_timeout(handle, &mut len_buf, timeout)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_exact_timeout(handle, &mut payload, timeout)?;
        }
        Ok(payload)
    }

    pub fn connect_with_timeout(pipe: HANDLE, timeout: std::time::Duration) -> Result<(), IpcError> {
        use windows::Win32::System::Pipes::ConnectNamedPipe;
        run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
            ConnectNamedPipe(pipe, Some(ov))
        })?;
        Ok(())
    }
}
