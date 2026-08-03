//! Windows Tier1: Restricted Token + 低Integrity Level + Job Object。
//! `plans/DESIGN-SANDBOX.md` §6.3/§4.3参照。
//!
//! 自プロセスのトークンを複製し`CreateRestrictedToken`で全特権を無効化した上、
//! `TokenIntegrityLevel`を低ILへ落とした「自トークン由来」の制限トークンを作る。
//! これは他ユーザを偽装するのではなく自分の権限を絞る操作なので
//! `SeAssignPrimaryTokenPrivilege`を要求しない（Chromiumサンドボックス等と同じ確立手法、
//! §4.3「同一信頼ドメイン」の裏返し＝自ドメイン内で絞る分には特権が要らない）。
//!
//! **既知の限界（正直に明記する）**: 低ILは既定で中IL（Medium、通常ファイルの既定）オブジェクトを
//! read可（No-Read-Upは既定でない）＝機密性は守らない（T-04残存、§9-1）。書込は、spawn直前に
//! 呼び出し側が`cwd`ディレクトリ**1つだけ**へ継承可能な低ILラベルを明示的に付与するため、
//! **そのcwd配下に新規作成されるファイル/ディレクトリのみ**書込可能になる。cwd配下に
//! 既にMedium ILで存在する既存ファイル（過去の非隔離buildの成果物等）への上書きは失敗し得る
//! （既存ファイルへ遡ってラベルを再帰付与するのは、ユーザの実リポジトリのACLを広範囲に変更する
//! 破壊的操作になるため意図的に行わない）。cwd外への書込は既定Mediumラベルのため一貫して拒否
//! される（範囲外書込拒否＝Tier1の本来の保証、T-05）。
//!
//! この機密性・network遮断の欠落を埋める実験的Tier2a（AppContainer）は`win_appcontainer`参照。
//! 低レベルのパイプ/HANDLE/env補助関数は`win_common`に共通化されている。

use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    CreateRestrictedToken, GetSecurityDescriptorSacl, SetTokenInformation, TokenIntegrityLevel,
    DISABLE_MAX_PRIVILEGE, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::win_common::{
    build_env_block, clear_inherit, create_job_object, create_pipe_with_sddl,
    read_two_pipes_to_strings, wide, write_all,
};

#[derive(Debug, thiserror::Error)]
pub enum RestrictedError {
    #[error("win32 call failed: {0}")]
    Win32(String),
}

impl From<windows::core::Error> for RestrictedError {
    fn from(e: windows::core::Error) -> Self {
        RestrictedError::Win32(e.to_string())
    }
}

/// 低Integrity LevelのSDDL文字列（`S-1-16-4096`、Windowsの既定Low IL SID）。
const LOW_IL_SDDL: &str = "S-1-16-4096";

/// `dir`1つだけに、配下へ継承する低ILの必須ラベルACEを設定する（非再帰・冪等）。
/// 既存の子孫には遡って効かない（モジュールdocコメントの既知の限界を参照）。
pub fn set_low_integrity_label(dir: &Path) -> Result<(), RestrictedError> {
    // SDDL: "S:(ML;NI;NW;;;LW)" = SACL(mandatory label)、no-inherit（子孫へ伝播させない）、
    // no-write-up、対象SIDはLow mandatory level。
    // CIOI（container+object inherit）だと .harness/sandbox/Tier2a-tmp にもラベルが継承され、
    // Low IL 相当の AppContainer プロセスからの書込みが PRIVILEGE NOT HELD で拒否される（BUG-018）。
    const SDDL_LOW_LABEL: &str = "S:(ML;NI;NW;;;LW)";
    unsafe {
        let sddl = wide(SDDL_LOW_LABEL);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;

        let mut sacl_present = windows::Win32::Foundation::BOOL(0);
        let mut sacl_ptr: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        let mut sacl_defaulted = windows::Win32::Foundation::BOOL(0);
        let sacl_result =
            GetSecurityDescriptorSacl(sd, &mut sacl_present, &mut sacl_ptr, &mut sacl_defaulted);
        if let Err(e) = sacl_result {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(RestrictedError::from(e));
        }

        let path_w = wide(&dir.to_string_lossy());
        let err = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            None,
            Some(sacl_ptr as *const _),
        );
        let _ = LocalFree(HLOCAL(sd.0));
        if err.0 != 0 {
            return Err(RestrictedError::Win32(format!(
                "SetNamedSecurityInfoW failed: {err:?}"
            )));
        }
    }
    Ok(())
}

/// spawn済みの子プロセス。読み取り・待機はブロッキングAPIのため`tokio::task::spawn_blocking`
/// から呼ぶ想定（`harness-tools::shell`側の責務）。
pub struct RestrictedChild {
    process: HANDLE,
    job: HANDLE,
    stdin_write: Option<HANDLE>,
    stdout_read: HANDLE,
    stderr_read: HANDLE,
}

// HANDLEは単なるカーネルオブジェクトへのポインタ値であり、複数スレッドからの
// TerminateProcess/ReadFile呼び出し自体はOSレベルで安全（Win32 APIの前提）。
unsafe impl Send for RestrictedChild {}

impl RestrictedChild {
    /// `TerminateProcess`で強制終了する（timeout到達時、`shell.rs`から呼ぶ）。
    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.process, 1);
        }
    }

    /// 軽量なkill専用ハンドル。`write_stdin_read_output_and_wait`は`self`を消費して
    /// `spawn_blocking`へ渡す必要があるため、その前に取り出して非同期側に残しておき、
    /// timeout到達時に`kill()`する（`harness-tools::shell`側の責務）。
    pub fn kill_token(&self) -> KillToken {
        KillToken(self.process)
    }

    /// stdinへ書き込みEOFを送り、stdout/stderrを最後まで読み、終了コードを待つ
    /// （ブロッキング。呼び出し側が`spawn_blocking`で包む）。
    pub fn write_stdin_read_output_and_wait(
        mut self,
        stdin_payload: Option<&[u8]>,
    ) -> Result<(String, String, i32), RestrictedError> {
        if let Some(payload) = stdin_payload {
            if let Some(stdin) = self.stdin_write.take() {
                write_all(stdin, payload);
                unsafe {
                    let _ = CloseHandle(stdin);
                }
            }
        } else if let Some(stdin) = self.stdin_write.take() {
            unsafe {
                let _ = CloseHandle(stdin);
            }
        }

        let (out, err) = read_two_pipes_to_strings(self.stdout_read, self.stderr_read);

        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            let mut code: u32 = 0;
            let _ = GetExitCodeProcess(self.process, &mut code);
            Ok((out, err, code as i32))
        }
    }
}

/// `RestrictedChild`が`spawn_blocking`へ移動した後もtimeoutからkillできる軽量ハンドル。
#[derive(Clone, Copy)]
pub struct KillToken(HANDLE);

unsafe impl Send for KillToken {}

impl KillToken {
    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.0, 1);
        }
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        unsafe {
            if let Some(h) = self.stdin_write.take() {
                let _ = CloseHandle(h);
            }
            let _ = CloseHandle(self.stdout_read);
            let _ = CloseHandle(self.stderr_read);
            let _ = CloseHandle(self.job);
            let _ = CloseHandle(self.process);
        }
    }
}

/// パイプを作る。既定のDACLで作った匿名パイプは明示ラベルを持たずMedium IL扱いになり、
/// 低ILの子は**読めるが書けない**（No-Write-Up）。子がstdout/stderrへ書けなくなり
/// 出力が消える実害があるため、パイプの二次記述子へ明示的にLow ILのSACLラベルを付与する。
fn inheritable_pipe() -> Result<(HANDLE, HANDLE), RestrictedError> {
    Ok(create_pipe_with_sddl("S:(ML;;NW;;;LW)")?)
}

fn build_restricted_token() -> Result<HANDLE, RestrictedError> {
    unsafe {
        let mut process_token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(
                TOKEN_DUPLICATE.0
                    | TOKEN_QUERY.0
                    | TOKEN_ASSIGN_PRIMARY.0
                    | TOKEN_ADJUST_DEFAULT.0
                    | TOKEN_ADJUST_SESSIONID.0
                    | TOKEN_ADJUST_GROUPS.0
                    | TOKEN_ADJUST_PRIVILEGES.0,
            ),
            &mut process_token,
        )?;

        // 全特権を無効化した制限トークンを、自プロセスのプライマリトークンから直接作る
        // （SID制限リストは指定しない。主な封じ込めは後続の低IL付与に依る、§6.3の
        // スコープに合わせた簡略化）。`CreateProcessAsUserW`が`SeAssignPrimaryTokenPrivilege`を
        // 要求しない「自トークン由来の制限トークン」特例は、`OpenProcessToken`で得たプライマリ
        // トークンへ直接`CreateRestrictedToken`を適用した場合にのみ成立する。間に
        // `DuplicateTokenEx`を挟むとこの由来が切れ、通常の特権チェックが働いて
        // `ERROR_PRIVILEGE_NOT_HELD`になる（実機で確認済み、BUG-003参照）。
        let mut restricted_token = HANDLE::default();
        CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut restricted_token,
        )?;
        let _ = CloseHandle(process_token);

        // 低ILラベルを設定する。
        let low_sid_str = wide(LOW_IL_SDDL);
        let mut low_sid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(low_sid_str.as_ptr()), &mut low_sid)?;

        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low_sid,
                Attributes: 0x2000_0000, // SE_GROUP_INTEGRITY
            },
        };
        let label_size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>();
        let result = SetTokenInformation(
            restricted_token,
            TokenIntegrityLevel,
            &label as *const _ as *const _,
            label_size as u32,
        );
        let _ = LocalFree(HLOCAL(low_sid.0));
        result?;

        Ok(restricted_token)
    }
}

/// Tier0（Windows）向け: 通常spawn済みの子（`tokio::process::Child`、制限トークン無し）を
/// kill-on-close付きJob Objectへ後付けする。`raw_handle`は
/// `std::os::windows::io::AsRawHandle::as_raw_handle`の戻り値（`isize`として渡す）。
/// 生成したJob Objectのハンドルは意図的にリークする（プロセス終了までOSが保持し、
/// kill-on-closeはこのハンドルが閉じられる=harness自身が終了する時点で効けばよいため、
/// 子の生存期間中ずっと有効なJob Objectを維持する目的に合致する）。
pub fn attach_job_object(raw_handle: isize) -> Result<(), RestrictedError> {
    unsafe {
        let job = create_job_object()?;
        let process = HANDLE(raw_handle as *mut core::ffi::c_void);
        AssignProcessToJobObject(job, process)?;
    }
    Ok(())
}

/// 制限トークン+低IL+Job Objectで子プロセスを起動する。`exe`は絶対パスかPATH解決可能な名前
/// （`CreateProcessAsUserW`の`lpApplicationName`は`None`、`lpCommandLine`にexe+argsを連結して渡す）。
/// stdinは`want_stdin`が`true`の場合のみパイプを用意する。
pub fn spawn(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
) -> Result<RestrictedChild, RestrictedError> {
    let token = build_restricted_token()?;
    let job = create_job_object()?;

    // 親が保持し続ける側（子へは渡さない側）は継承不可に戻す（`clear_inherit`のdocコメント参照）。
    let (stdout_read, stdout_write) = inheritable_pipe()?;
    clear_inherit(stdout_read);
    let (stderr_read, stderr_write) = inheritable_pipe()?;
    clear_inherit(stderr_read);
    let (stdin_read, stdin_write) = if want_stdin {
        let (r, w) = inheritable_pipe()?;
        clear_inherit(w);
        (Some(r), Some(w))
    } else {
        (None, None)
    };

    let mut cmdline = format!("\"{exe}\"");
    for a in args {
        cmdline.push(' ');
        cmdline.push('"');
        cmdline.push_str(&a.replace('"', "\\\""));
        cmdline.push('"');
    }
    let mut cmdline_w = wide(&cmdline);
    let cwd_w = wide(&cwd.to_string_lossy());
    let mut env_block = build_env_block(env);

    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: stdout_write,
        hStdError: stderr_write,
        hStdInput: stdin_read.unwrap_or(INVALID_HANDLE_VALUE),
        ..Default::default()
    };

    let mut process_info = PROCESS_INFORMATION::default();

    let spawn_result = unsafe {
        CreateProcessAsUserW(
            token,
            PCWSTR::null(),
            PWSTR(cmdline_w.as_mut_ptr()),
            None,
            None,
            true,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(env_block.as_mut_ptr() as *mut _),
            PCWSTR(cwd_w.as_ptr()),
            &startup_info,
            &mut process_info,
        )
    };

    // 呼び出し側プロセスのパイプ端（子へ継承させた側）は、spawn後は不要なので閉じる。
    unsafe {
        let _ = CloseHandle(stdout_write);
        let _ = CloseHandle(stderr_write);
        if let Some(r) = stdin_read {
            let _ = CloseHandle(r);
        }
        let _ = CloseHandle(token);
    }

    if let Err(e) = spawn_result {
        unsafe {
            let _ = CloseHandle(job);
            let _ = CloseHandle(stdout_read);
            let _ = CloseHandle(stderr_read);
            if let Some(w) = stdin_write {
                let _ = CloseHandle(w);
            }
        }
        return Err(RestrictedError::from(e));
    }

    unsafe {
        AssignProcessToJobObject(job, process_info.hProcess)?;
        let _ = CloseHandle(process_info.hThread);
    }

    Ok(RestrictedChild {
        process: process_info.hProcess,
        job,
        stdin_write,
        stdout_read,
        stderr_read,
    })
}
