//! 特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5・§6）。
//!
//! harness本体（LLMループ・ツールディスパッチを含む）は常に非管理者トークンで動作し続ける。
//! `WRITE_DAC`が要る管理者操作（現時点ではドライブルートへのtraverse ACE付与/撤収、D10）だけを、
//! 本体から切り出した極小の別バイナリ（`harness-privhelper.exe`、`crates/harness-privhelper`）へ
//! 委譲する。IPCは名前付きパイプ＋固定enumスキーマに限定し、自由形式のコマンド文字列は受理しない
//! （§5.1）。
//!
//! **役割分担**: 親（本体、非管理者）がパイプserverを開いてから`runas`でヘルパーを昇格起動し、
//! ヘルパーはclientとして接続する（順序が逆だと、ヘルパー起動前に接続待ちする側が要らない
//! ポーリングを持つことになる）。パイプのDACLは現在ユーザのSIDへ限定するため、`runas`で
//! 昇格したヘルパーのトークンも「同一ユーザの別integrity level」であり接続できる一方、
//! 他ユーザのプロセスからは接続できない。
//!
//! **SIDは受け渡さない**: 要求スキーマにPSIDを含めない。ヘルパー自身が`ensure_profile`で
//! `CONTAINER_NAME`（安定定数）からSIDを導出する。生ポインタをプロセス境界・特権境界を越えて
//! IPCで渡す必要自体を無くす設計判断。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::win_appcontainer::{self, AppContainerError, CONTAINER_NAME};
use crate::win_common::wide;

/// ヘルパーへ委譲する操作。自由形式のコマンド文字列ではなく固定スキーマに限定する（D-16）。
/// 将来の特権操作（WFPフィルタ設置・VHDXマウント等、`DESIGN-SANDBOX-PRIVSEP.md` §5.2）は
/// ここへvariantを追加する形で拡張する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedRequest {
    /// `target`とその全祖先（ドライブルートまで）へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
    /// 連鎖付与する（`harness fs grant-traverse`、`win_appcontainer::grant_traverse_chain`、
    /// `TIER1A-OPEN-ISSUES.md`項目6の連鎖化。旧`drive`フィールドから`target`へ改称——
    /// ドライブルート単体に限らない任意パスを受け付けるようになったため）。
    GrantTraverse { target: PathBuf },
    /// `GrantTraverse`で付与したACEを1件撤収する（`harness fs revoke-traverse`）。
    RevokeTraverse { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedResponse {
    /// データを返す必要がない操作の単純成功（`RevokeTraverse`）。
    Ok,
    /// `GrantTraverse`の結果。祖先チェーンのうち実際にACE付与が成功したノードの一覧を、
    /// 成否に関わらず必ず返す。`error`が`Some`なら途中のノードで付与が失敗し、それ以降は
    /// 未処理。`granted`に含まれるノードは実際にディスク上でACEが変更済みなので、呼び出し側は
    /// `error`の有無に関わらず`granted`の全ノードを台帳へ記録しなければならない（孤立ACE防止）。
    GrantChain {
        granted: Vec<PathBuf>,
        error: Option<String>,
    },
    /// 要求全体を拒否した場合の単純な失敗（スキーマ不一致等、部分適用の概念が無い操作）。
    Err(String),
}

#[derive(Debug, thiserror::Error)]
pub enum PrivHelperError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("helper rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
    /// `GrantTraverse`（連鎖付与）が途中のノードで失敗した場合。`granted`には失敗するまでに
    /// 実際にACEが付与された（=ディスク上で変更済みの）ノードが入る。呼び出し側は、この
    /// エラーを受け取っても`granted`を台帳へ記録しなければならない（孤立ACE防止）。
    #[error("grant-traverse chain partially failed after granting {granted:?}: {reason}")]
    PartialGrantChain {
        granted: Vec<PathBuf>,
        reason: String,
    },
}

impl From<windows::core::Error> for PrivHelperError {
    fn from(e: windows::core::Error) -> Self {
        PrivHelperError::Win32(e.to_string())
    }
}

/// 呼び出し元プロセスのトークンが昇格済み（管理者）かどうかを判定する（§5.3）。
/// 判定に失敗した場合は`false`を返す（fail-safe: 誤って「昇格済み」と扱い直接特権操作へ
/// 倒れることを避け、判定不能時はヘルパー経由の遅い経路へ寄せる）。
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        match ok {
            Ok(()) => elevation.TokenIsElevated != 0,
            Err(_) => false,
        }
    }
}

/// 現在プロセスのユーザSIDを`S-1-...`形式の文字列で取得する（named pipeのDACLを
/// このユーザへ限定するため）。
fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        let mut ret_len = 0u32;
        // 1回目は必要バッファサイズを問い合わせるだけの呼び出し（ERROR_INSUFFICIENT_BUFFERを
        // 無視する、Win32の定型パターン）。
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        let get_result = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        get_result?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = crate::win_common::pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
}

/// 現在ユーザのSIDのみへフルアクセスを許可するセキュリティ記述子を作る（named pipe用）。
/// 他ユーザ（Administrators含む、`sid`以外の全て）は既定拒否（DACLに列挙されないtrusteeへの
/// 暗黙deny）。
fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
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

/// 一意なパイプ名を作る（PID + 単調増加カウンタで衝突回避、暗号論的乱数は不要 — 名前の
/// 推測可能性はDACLで既に閉じているため、名前自体の秘匿性には依存しない設計）。
fn unique_pipe_name() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        r"\\.\pipe\harness-privhelper-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// `len(u32 LE) || payload`形式でメッセージを1件書き込む。
fn write_framed(handle: HANDLE, payload: &[u8]) -> windows::core::Result<()> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all_bytes(handle, &len)?;
    write_all_bytes(handle, payload)?;
    Ok(())
}

fn write_all_bytes(handle: HANDLE, mut buf: &[u8]) -> windows::core::Result<()> {
    unsafe {
        while !buf.is_empty() {
            let mut written = 0u32;
            WriteFile(handle, Some(buf), Some(&mut written), None)?;
            if written == 0 {
                return Err(windows::core::Error::from_win32());
            }
            buf = &buf[written as usize..];
        }
    }
    Ok(())
}

/// `write_framed`で書かれたメッセージを1件読み取る。
fn read_framed(handle: HANDLE) -> windows::core::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    read_exact_bytes(handle, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_bytes(handle, &mut payload)?;
    }
    Ok(payload)
}

fn read_exact_bytes(handle: HANDLE, mut buf: &mut [u8]) -> windows::core::Result<()> {
    unsafe {
        while !buf.is_empty() {
            let mut read = 0u32;
            ReadFile(handle, Some(buf), Some(&mut read), None)?;
            if read == 0 {
                return Err(windows::core::Error::from_win32());
            }
            let (_, rest) = std::mem::take(&mut buf).split_at_mut(read as usize);
            buf = rest;
        }
    }
    Ok(())
}

/// ヘルパー実行ファイル（`harness-privhelper.exe`）のパスを、本体exeと同じディレクトリから
/// 解決する（PATH検索に頼らない固定ロケーション、D-16の「小さく独立にビルド・監査可能な
/// 別バイナリ」を確実に本体と対で配布する前提）。
fn helper_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current.parent().ok_or_else(|| {
        PrivHelperError::Ipc("current exe has no parent directory".to_string())
    })?;
    Ok(dir.join("harness-privhelper.exe"))
}

/// 特権操作をヘルパーへ委譲し、完了まで待つ（client側、非管理者本体から呼ぶ）。
/// 1. 現在ユーザSID限定DACLでnamed pipe serverを作る。
/// 2. `runas`でヘルパーをパイプ名引数付きで昇格起動する（UACが表示される）。
/// 3. ヘルパーの接続を待ち、要求を送信し、応答を受け取る。
///
/// 返り値は「実際にACEが付与されたノードの一覧」（`GrantTraverse`のみ意味を持つ。
/// `RevokeTraverse`成功時は常に空`Vec`）。`Err(PrivHelperError::PartialGrantChain { granted, .. })`
/// の場合も`granted`に途中まで成功したノードが入るため、呼び出し側は`Err`だからと無視せず
/// 中身を確認して台帳へ反映する必要がある（孤立ACE防止）。
pub fn run_privileged(req: &PrivilegedRequest) -> Result<Vec<PathBuf>, PrivHelperError> {
    let pipe_name = unique_pipe_name();
    let sid = current_user_sid_string()?;
    let mut sa = user_only_security_attributes(&sid)?;

    let pipe = unsafe {
        let pipe_name_w = wide(&pipe_name);
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        if handle.is_invalid() {
            return Err(PrivHelperError::from(windows::core::Error::from_win32()));
        }
        handle
    };

    let helper_path = helper_exe_path()?;
    // 【重要】ここでヘルパープロセスの終了を待ってはいけない。ヘルパー（`serve`）は
    // 「親から要求を受信する」ことを待っており、親はまだ要求を送っていない。もしここで
    // ヘルパーの終了を待つと、親は「ヘルパー終了待ち」・ヘルパーは「親からの送信待ち」の
    // 循環待機（デッドロック）に陥る（実機のUACテストで実際に発生を確認、`launch_helper_elevated`
    // 内部で`WaitForSingleObject(INFINITE)`していた旧実装のバグ）。プロセスハンドルは
    // IPC完了後に回収する。
    let helper_process = match unsafe { launch_helper_elevated(&helper_path, &pipe_name) } {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };

    let result = run_ipc_exchange(pipe, req);

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
        if !helper_process.is_invalid() {
            // ヘルパーは応答送信直後に終了するはずなので、短いタイムアウトで待つ
            // （既にIPCが完了した後の後始末であり、ここでの待機はデッドロックを起こさない）。
            let _ = WaitForSingleObject(helper_process, 5000);
            let _ = CloseHandle(helper_process);
        }
    }

    result
}

/// パイプ接続・要求送信・応答受信の本体（ヘルパープロセスの生死待ちとは独立させる、
/// デッドロック回避のため`run_privileged`から分離）。
fn run_ipc_exchange(pipe: HANDLE, req: &PrivilegedRequest) -> Result<Vec<PathBuf>, PrivHelperError> {
    let connect_result = unsafe { ConnectNamedPipe(pipe, None) };
    if let Err(e) = connect_result {
        // ERROR_PIPE_CONNECTED: ヘルパーが`ConnectNamedPipe`呼び出し前に既に接続していた
        // という正常系（Win32の既知の競合、MSDN記載）。
        if e.code() != windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
            return Err(PrivHelperError::from(e));
        }
    }

    let request_bytes = serde_json::to_vec(req)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize request: {e}")))?;
    write_framed(pipe, &request_bytes).map_err(PrivHelperError::from)?;

    let response_bytes = read_framed(pipe).map_err(PrivHelperError::from)?;
    let response: PrivilegedResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to parse helper response: {e}")))?;
    match response {
        PrivilegedResponse::Ok => Ok(Vec::new()),
        PrivilegedResponse::GrantChain {
            granted,
            error: None,
        } => Ok(granted),
        PrivilegedResponse::GrantChain {
            granted,
            error: Some(reason),
        } => Err(PrivHelperError::PartialGrantChain { granted, reason }),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `runas`でヘルパーを昇格起動する。ユーザがUACを拒否した場合は`ERROR_CANCELLED`が返るため
/// `ElevationDeclined`へ変換する（親側がハングせず即座にエラーを返せる）。起動した
/// プロセスのハンドルを返すのみで、終了は待たない（呼び出し側がIPC完了後に待つ、
/// デッドロック回避）。
unsafe fn launch_helper_elevated(
    helper_path: &std::path::Path,
    pipe_name: &str,
) -> Result<HANDLE, PrivHelperError> {
    let verb_w = wide("runas");
    let file_w = wide(&helper_path.to_string_lossy());
    let params_w = wide(pipe_name);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let ok = ShellExecuteExW(&mut info);
    if ok.is_err() {
        let err = GetLastError();
        if err == ERROR_CANCELLED {
            return Err(PrivHelperError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(PrivHelperError::Win32(format!("ShellExecuteExW failed: {err:?}")));
    }

    Ok(info.hProcess)
}

/// ヘルパー側エントリポイント（`harness-privhelper.exe`のmainから呼ぶ、昇格トークンで実行される）。
/// 親が開いたパイプへclientとして接続し、1件の要求を処理して応答を返し終了する
/// （1起動=1操作、常駐しない）。
pub fn serve(pipe_name: &str) -> Result<(), PrivHelperError> {
    let pipe = unsafe {
        let pipe_name_w = wide(pipe_name);
        CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };

    let request_bytes = read_framed(pipe).map_err(PrivHelperError::from)?;
    let response = match serde_json::from_slice::<PrivilegedRequest>(&request_bytes) {
        Ok(req) => dispatch(req),
        Err(e) => PrivilegedResponse::Err(format!(
            "malformed or unknown request (schema mismatch): {e}"
        )),
    };
    let response_bytes = serde_json::to_vec(&response)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize response: {e}")))?;
    let write_result = write_framed(pipe, &response_bytes).map_err(PrivHelperError::from);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    write_result
}

/// 固定スキーマの要求だけを実行する（D-16の核: ここに到達する時点でスキーマ検証済み、
/// 自由形式のコマンド文字列は一切扱わない）。SIDはIPCで受け取らず、安定定数
/// `CONTAINER_NAME`から`ensure_profile`で自ら導出する。
fn dispatch(req: PrivilegedRequest) -> PrivilegedResponse {
    let sid = match win_appcontainer::ensure_profile(CONTAINER_NAME) {
        Ok(sid) => sid,
        Err(e) => return PrivilegedResponse::Err(format!("failed to resolve sandbox SID: {e}")),
    };
    match req {
        PrivilegedRequest::GrantTraverse { target } => {
            let (granted, result) = win_appcontainer::grant_traverse_chain(&target, sid.as_psid());
            PrivilegedResponse::GrantChain {
                granted,
                error: result.err().map(|e| e.to_string()),
            }
        }
        PrivilegedRequest::RevokeTraverse { path } => {
            let result: Result<(), AppContainerError> =
                win_appcontainer::revoke_ace(&path, sid.as_psid())
                    .and_then(|()| win_appcontainer::assert_no_sid_ace(&path, sid.as_psid()));
            match result {
                Ok(()) => PrivilegedResponse::Ok,
                Err(e) => PrivilegedResponse::Err(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_through_json() {
        let req = PrivilegedRequest::GrantTraverse {
            target: PathBuf::from(r"C:\Users\example\.cargo"),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantTraverse { target } => {
                assert_eq!(target, PathBuf::from(r"C:\Users\example\.cargo"))
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let req = PrivilegedRequest::RevokeTraverse {
            path: PathBuf::from(r"C:\Users"),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::RevokeTraverse { path } => {
                assert_eq!(path, PathBuf::from(r"C:\Users"))
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn malformed_bytes_are_rejected_not_panicking() {
        let garbage = b"{\"not\":\"a valid PrivilegedRequest\"}";
        let result = serde_json::from_slice::<PrivilegedRequest>(garbage);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_variant_is_rejected() {
        let unknown = br#"{"NukeSystem":{}}"#;
        let result = serde_json::from_slice::<PrivilegedRequest>(unknown);
        assert!(result.is_err());
    }

    /// `GrantChain`応答が、成功（`error: None`）・部分失敗（`error: Some`）のどちらでも
    /// `granted`一覧を失わずラウンドトリップできることを確認する（孤立ACE防止の前提）。
    #[test]
    fn grant_chain_response_roundtrips_with_partial_failure() {
        let resp = PrivilegedResponse::GrantChain {
            granted: vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\Users")],
            error: Some("access denied on C:\\Users\\example".to_string()),
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::GrantChain { granted, error } => {
                assert_eq!(granted, vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\Users")]);
                assert!(error.is_some());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn is_elevated_returns_a_bool_without_panicking() {
        let _: bool = is_elevated();
    }

    /// パイプの配線（DACL作成・`CreateNamedPipeW`・`ConnectNamedPipe`・`write_framed`/
    /// `read_framed`のフレーミング）を、昇格・別プロセス起動なしで検証する。同一プロセス内で
    /// server端（`CreateNamedPipeW`）とclient端（`CreateFileW`）の両方を開き、実際に
    /// `run_privileged`/`serve`が使うのと同じ`write_framed`/`read_framed`でメッセージを
    /// 1往復させる。特権操作（`WRITE_DAC`）自体はテストしない（`dispatch`の中身は別途、
    /// 実機の手動E2Eで検証する。`docs/phases/foundation/M12-shell-isolation-tiers.md`参照）。
    #[test]
    fn framed_message_roundtrips_over_a_real_named_pipe() {
        let pipe_name = unique_pipe_name();
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let mut sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");

        let server = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let pipe_name_for_client = pipe_name.clone();
        let client_thread = std::thread::spawn(move || unsafe {
            let pipe_name_w = wide(&pipe_name_for_client);
            CreateFileW(
                PCWSTR(pipe_name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .expect("client CreateFileW")
            .0 as usize
        });

        let connect_result = unsafe { ConnectNamedPipe(server, None) };
        if let Err(e) = connect_result {
            assert_eq!(e.code(), windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0));
        }
        let client = HANDLE(client_thread.join().unwrap() as *mut _);

        write_framed(client, b"hello from client").expect("write_framed");
        let received = read_framed(server).expect("read_framed");
        assert_eq!(received, b"hello from client");

        write_framed(server, b"hello from server").expect("write_framed");
        let received = read_framed(client).expect("read_framed");
        assert_eq!(received, b"hello from server");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }
}
