//! 名前付きパイプIPCの下回り（Windows）。呼び出しユーザー専有のDACL・オーバーラップドI/O・
//! タイムアウト付きの長さプレフィックス・フレーミング。
//!
//! `tier2a::privhelper`（特権分離ヘルパー）・`tier2a::netfilterd`（WFP daemon）・
//! `tier3::vmsandboxd`（VM daemon）が共有する。いずれも「非特権の本体プロセスが、
//! 別プロセス（多くは昇格済み）と名前付きパイプで会話する」という同じ形をしており、
//! **この層は信頼境界そのものではないが、境界を越える通信路の実装**である。
//!
//! ## なぜ共通化するか
//!
//! 統合前はこの一式が上記3モジュールにコピーとして存在していた。実際に次の劣化が起きていた
//! （`docs/refactor/`および`docs/CODE-STRUCTURE-RULES.md`規則5）。
//!
//! - `run_overlapped`の`WaitForSingleObject`へ渡すタイムアウトのクランプ
//!   （`.min(u32::MAX as u128)`）が、3コピー中2つにしか無かった。`Duration::as_millis()`は
//!   `u128`を返すため、クランプ無しの`as u32`は約49.7日を超えるタイムアウトを黙って切り詰める。
//! - `ERROR_PIPE_CONNECTED`（クライアントが`ConnectNamedPipe`前に既に接続済みだった場合の
//!   synchronous completion）の取り扱い漏れは、2026-07-25の実機E2Eで発覚した際に
//!   「もう片方にも同じバグがコピーされていたため同時に修正」する必要があった。
//!
//! ## フレーム形式
//!
//! `[4バイトのリトルエンディアン長][ペイロード]`。長さ0のフレームはプレフィックスのみを書く。
//! バイトストリームモードのパイプ上で、この長さプレフィックスがフレーム境界を担う。
//! 別プロセスと交換する形なので、`pipe_ipc_characterization`（`tier2a::privhelper`）が
//! ワイヤ上のバイト列を固定している。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::win_common::wide;

/// この層が返すエラー。各呼び出し側は自前のエラー型へ`From`で変換する
/// （`PrivHelperError`・`NetfilterError`・`VmSandboxIpcError`）。
///
/// 統合前は3コピーがそれぞれの`*::Ipc(String)`を直接構築しており、メッセージ文字列も
/// 同一だった。変換を1段挟むことで文字列は保たれる。
#[derive(Debug, thiserror::Error)]
pub enum PipeIpcError {
    #[error("{0}")]
    Ipc(String),
}

impl PipeIpcError {
    /// 呼び出し側のエラー型へ移すときにメッセージだけを取り出す。
    pub fn into_message(self) -> String {
        match self {
            PipeIpcError::Ipc(m) => m,
        }
    }
}

/// トークンが指すユーザーのSIDを文字列（`S-1-5-21-...`）で返す。
pub fn sid_string_from_token(token: HANDLE) -> windows::core::Result<String> {
    unsafe {
        let mut ret_len = 0u32;
        // 1回目は必要バッファサイズを問い合わせるだけの呼び出し（`ERROR_INSUFFICIENT_BUFFER`を
        // 無視する、Win32の定型パターン）。
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        )?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = crate::win_common::pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
}

/// 自プロセスのユーザーSIDを文字列で返す。
pub fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let result = sid_string_from_token(token);
        let _ = CloseHandle(token);
        result
    }
}

/// `sid`のみへフルアクセスを許可するセキュリティ記述子を作る（名前付きパイプ用）。
///
/// 他ユーザ（**Administratorsを含む**、`sid`以外の全て）は、DACLに列挙されないtrusteeへの
/// 暗黙denyで拒否される。`P`（protected）は付けない——名前付きパイプは継承元のコンテナを
/// 持たないため実効的な差が無い。ハンドル自体も継承させない（`bInheritHandle: false`）。
///
/// 呼び出し側は使用後に`LocalFree(lpSecurityDescriptor)`する責任を持つ。
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

/// `\\.\pipe\harness-<component>-<pid>-<連番>-<ナノ秒>`という一意なパイプ名を作る。
///
/// `component`は機構ごとの識別子（`privhelper`・`netfilterd`・`vmsandboxd`）。統合前は
/// この接頭辞だけが違う3つのコピーだった。
pub fn unique_pipe_name(component: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        r"\\.\pipe\harness-{}-{}-{}-{}",
        component,
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// オーバーラップドI/O操作を`timeout`付きで実行し、転送バイト数を返す。
///
/// `start`は`OVERLAPPED`を受け取って実際のWin32呼び出し（`ConnectNamedPipe`/`ReadFile`/
/// `WriteFile`）を開始するクロージャ。タイムアウトした場合は`CancelIoEx`で取り消し、
/// **取り消し完了まで待ってから**返る（`bWait=true`）——呼び出し側がこの直後にハンドルを
/// 閉じても`OVERLAPPED`がstaleにならないようにするため。
pub fn run_overlapped<F>(
    handle: HANDLE,
    timeout: std::time::Duration,
    op_name: &str,
    start: F,
) -> Result<u32, PipeIpcError>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, PCWSTR::null())
            .map_err(|e| PipeIpcError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
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
                    // クライアントが`ConnectNamedPipe`呼び出し前に既に接続済みだった
                    // （synchronous completion）。MSDNの既知の注意点: このケースでは
                    // OVERLAPPEDのイベントはシグナルされないため、後続の
                    // `GetOverlappedResult`を呼んではいけない（呼ぶと`ERROR_IO_INCOMPLETE`で
                    // 失敗する）。ここで即座に成功として返す。
                    //
                    // 【2026-07-25実機E2Eで発見・修正】UAC待ちの無い連鎖起動経路
                    // （privhelperがnetfilterdを起動し、子が即座に接続してくる）でこの競合が
                    // 実際に発生した。当時この関数は3箇所にコピーされていたため、同じ修正を
                    // 手で複数箇所へ適用する必要があった。共通化はその再発防止でもある。
                    let _ = CloseHandle(event);
                    return Ok(0);
                } else {
                    let _ = CloseHandle(event);
                    return Err(PipeIpcError::Ipc(format!("{op_name} failed to start: {e}")));
                }
            }
        };

        if pending {
            // `as_millis()`は`u128`を返す。クランプ無しの`as u32`は約49.7日を超える
            // タイムアウトを黙って切り詰めるため、`u32::MAX`（=`INFINITE`）で頭打ちにする。
            let wait = WaitForSingleObject(event, timeout.as_millis().min(u32::MAX as u128) as u32);
            if wait != WAIT_OBJECT_0 {
                // タイムアウトまたは待機自体の失敗。取り消して、取り消し完了(bWait=true)まで
                // 待ってから返る — ハンドルをこの後すぐ閉じても`OVERLAPPED`がstaleに
                // ならないようにするため。
                let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                let mut transferred = 0u32;
                let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                let _ = CloseHandle(event);
                return Err(PipeIpcError::Ipc(format!(
                    "{op_name} timed out after {timeout:?}"
                )));
            }
        }

        let mut transferred = 0u32;
        let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
        let _ = CloseHandle(event);
        result
            .map_err(|e| PipeIpcError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}")))?;
        Ok(transferred)
    }
}

/// サーバ側でクライアントの接続を`timeout`付きで待つ。
pub fn connect_with_timeout(
    pipe: HANDLE,
    timeout: std::time::Duration,
) -> Result<(), PipeIpcError> {
    run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
        windows::Win32::System::Pipes::ConnectNamedPipe(pipe, Some(ov))
    })?;
    Ok(())
}

/// `buf`を全て書き切る（部分書込があれば残りを繰り返す）。
pub fn write_all_timeout(
    handle: HANDLE,
    buf: &[u8],
    timeout: std::time::Duration,
) -> Result<(), PipeIpcError> {
    let mut written_total = 0usize;
    while written_total < buf.len() {
        let chunk = &buf[written_total..];
        let n = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
            WriteFile(handle, Some(chunk), None, Some(ov))
        })?;
        if n == 0 {
            return Err(PipeIpcError::Ipc("WriteFile wrote 0 bytes".to_string()));
        }
        written_total += n as usize;
    }
    Ok(())
}

/// `buf`をちょうど埋めるまで読む。途中でEOF（0バイト読取）になったらエラー。
pub fn read_exact_timeout(
    handle: HANDLE,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> Result<(), PipeIpcError> {
    let mut read_total = 0usize;
    while read_total < buf.len() {
        let chunk = &mut buf[read_total..];
        let n = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
            ReadFile(handle, Some(chunk), None, Some(ov))
        })?;
        if n == 0 {
            return Err(PipeIpcError::Ipc(
                "ReadFile returned 0 bytes (pipe closed?)".to_string(),
            ));
        }
        read_total += n as usize;
    }
    Ok(())
}

/// 1フレーム書く（`[4バイトLE長][ペイロード]`、モジュールdoc参照）。
pub fn write_framed_timeout(
    handle: HANDLE,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<(), PipeIpcError> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all_timeout(handle, &len, timeout)?;
    write_all_timeout(handle, payload, timeout)?;
    Ok(())
}

/// 1フレーム読む。長さ0のフレームは空の`Vec`を返す。
pub fn read_framed_timeout(
    handle: HANDLE,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, PipeIpcError> {
    let mut len_buf = [0u8; 4];
    read_exact_timeout(handle, &mut len_buf, timeout)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_timeout(handle, &mut payload, timeout)?;
    }
    Ok(payload)
}
