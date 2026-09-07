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
//! read可（No-Read-Upは既定でない）＝機密性は守らない（T-04残存、§9-1）。
//! **networkは制御しない**（capabilityゲートが無い＝T-10残存）。
//!
//! 書込の届く範囲は、spawn直前に呼び出し側が`cwd`ディレクトリ**1つだけ**へ低ILラベルを
//! 付与することで決まる。実測した内訳は次のとおり
//! （回帰テスト`tier1_child_write_reach_under_a_labeled_cwd_is_measured`が固定している）。
//!
//! | 対象 | 可否 | 理由 |
//! |---|---|---|
//! | ラベルを付けた`cwd`直下 | **書ける** | 明示したLowラベル |
//! | 子プロセスが**新規作成した**サブディレクトリの中 | **書ける** | ACL継承ではなく、**MICが新規オブジェクトへ作成者のIL（Low）を書く**ため。`icacls`でも`(I)`の付かないLowラベルとして観測できる |
//! | 既にMedium ILで存在する既存のサブディレクトリ・ファイル（`src/`・`.git/`・過去の非隔離buildの`target/`等） | **書けない** | No-Write-Up。既存ファイルへ遡ってラベルを再帰付与するのは、ユーザの実リポジトリのACLを広範囲に変更する破壊的操作になるため意図的に行わない |
//! | `cwd`の外 | **書けない** | 既定Mediumラベル（範囲外書込拒否＝Tier1本来の保証、T-05） |
//!
//! ラベルを継承させない（フラグ欄を空にする）のはBUG-018でTier2aの一時ディレクトリを
//! 巻き込んだためだが、**継承させないことと「子ディレクトリの中に書けない」ことは別**である
//! ——上表2行目のとおり、実際には書ける。この2つを混同した記述が長く残っていたので表にした。
//!
//! **したがってTier1では`cargo build`/`cargo test`/`git commit`が通らない。**
//! 理由は`target/`がサブディレクトリだからではなく（新規作成なら書ける）、
//! (1) cargoが`cwd`の**外**（`$CARGO_HOME/.package-cache`・`~/.rustup/tmp`）へ書くこと、
//! (2) 既にMediumで存在する`.git/`や過去のbuild成果物へ書けないこと、の2点による。
//! **Tier1にはパス単位で許可を開ける機構が無い**——レバーは「cwd 1個にラベルを付けるか否か」
//! だけで、Tier2aのcapability SID + ACE付与に相当するものを持たない。この非対称が構造的な
//! 制約であって、実装の未熟さではない。詳細は`plans/PLAN-POLICY-EDITOR-EXEC-DENIAL.md`
//! 「第11セッション」節。
//!
//! なお`edit_file`/`write_file`はharness本体（Medium IL）が実行するのでこの制約を受けない。
//! Tier1が拘束するのは`run_shell`の子プロセスだけである。
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
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::win_common::{
    build_env_block, clear_inherit, create_job_object, create_pipe_with_sddl,
    read_two_pipes_to_strings, stream_child_output, terminate_job, terminate_job_and_close, wide,
    write_all,
};

/// ストリーミング出力の1件（[`RestrictedChild::spawn_streaming`]用）。実体はTier2aと共有する
/// [`crate::win_common::OutputEvent`]で、ここは既存の呼び出し元のための再エクスポートである。
pub use crate::win_common::OutputEvent;

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

/// `dir`1つだけに低ILの必須ラベルACEを設定する（非再帰・冪等）。
/// 既存の子孫には遡って効かない（モジュールdocコメントの既知の限界を参照）。
pub fn set_low_integrity_label(dir: &Path) -> Result<(), RestrictedError> {
    // SDDL: "S:(ML;;NW;;;LW)" = SACL(mandatory label)、継承フラグ無し（子孫へ伝播させない）、
    // no-write-up、対象SIDはLow mandatory level。
    //
    // 継承フラグを立てない理由（BUG-018）: `CIOI`（container+object inherit）だと
    // `.harness/sandbox/Tier2a-tmp`にもラベルが継承され、Low IL相当のAppContainerプロセスからの
    // 書込みが PRIVILEGE NOT HELD で拒否される。
    //
    // **`NI`と書いてはいけない**: BUG-018の案Aは`"S:(ML;NI;NW;;;LW)"`を採用したが、`NI`は
    // SDDLの正規のACEフラグトークンではない（正規はCI/OI/NP/IO/ID/SA/FAのみ）。このため
    // `ConvertStringSecurityDescriptorToSecurityDescriptorW`が`ERROR_INVALID_FLAGS`で失敗し、
    // **ラベルが一度も付かない状態**が続いていた。呼び出し側が`let _ =`で結果を捨てていたので
    // 無言のまま検知されず、報告症状（継承ラベルの汚染）は「付けない」ことで消えるため
    // 当時のE2Eも通ってしまった。「継承させない」はフラグ欄を**空にする**ことで表す。
    const SDDL_LOW_LABEL: &str = "S:(ML;;NW;;;LW)";
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
// TerminateJobObject/ReadFile呼び出し自体はOSレベルで安全（Win32 APIの前提）。
unsafe impl Send for RestrictedChild {}

impl RestrictedChild {
    /// Job全体を強制終了する（timeout到達時、`shell.rs`から呼ぶ）。
    pub fn kill(&self) {
        terminate_job(self.job);
    }

    /// 軽量なkill専用ハンドル。`write_stdin_read_output_and_wait`は`self`を消費して
    /// `spawn_blocking`へ渡す必要があるため、その前に取り出して非同期側に残しておき、
    /// timeout到達時に`kill()`する（`harness-tools::shell`側の責務）。
    pub fn kill_token(&self) -> Result<KillToken, RestrictedError> {
        Ok(KillToken::duplicate(self.job)?)
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

    /// ストリーミング版: stdin送出後、stdout/stderrを行単位で`OutputEvent`として流しつつ、
    /// プロセス終了を別イベントとして通知する（ポリシーエディタの記録モードのライブ表示用、
    /// `plans/POLICY-EDITOR-TOMOYO-DIG.md`参照）。`write_stdin_read_output_and_wait`と違い
    /// 呼び出し側で`spawn_blocking`する必要はない——OSスレッド3本（stdout読取・stderr読取・
    /// プロセス待機）を内部で起こし、`tokio::sync::mpsc`のreceiverだけを返す。
    ///
    /// **`Exited`と`OutputClosed`は独立したイベント**（モジュールdocの新設1番）。
    /// 孫プロセスがstdout/stderrを継承したまま握り続けると、親（直接の子）プロセスが終了
    /// しても`OutputClosed`はすぐには来ない。呼び出し側は`Exited`を見た時点でタイムアウト
    /// 判断などへ進んでよく、`OutputClosed`だけを待ってハングする設計にしないこと。
    pub fn spawn_streaming(
        mut self,
        stdin_payload: Option<&[u8]>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<OutputEvent> {
        // ハンドルの値だけを取り出し、`self`のDropが即座に閉じてしまわないよう
        // `mem::forget`で無効化する。以降の後始末は`stream_child_output`が起こす
        // 各スレッドが自分の担当分だけ行う。
        let stdin_write = self.stdin_write.take();
        let (process, job, stdout_read, stderr_read) =
            (self.process, self.job, self.stdout_read, self.stderr_read);
        std::mem::forget(self);

        stream_child_output(
            process,
            job,
            stdin_write,
            stdout_read,
            stderr_read,
            stdin_payload,
        )
    }
}

/// `RestrictedChild`が`spawn_blocking`へ移動した後もtimeoutからkillできる軽量ハンドル。
/// 実体はTier0と共有する[`crate::win_common::KillToken`]で、ここは既存の呼び出し元のための
/// 再エクスポートである（`OutputEvent`と同じ扱い）。
pub use crate::win_common::KillToken;

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        unsafe {
            if let Some(h) = self.stdin_write.take() {
                let _ = CloseHandle(h);
            }
            let _ = CloseHandle(self.stdout_read);
            let _ = CloseHandle(self.stderr_read);
            terminate_job_and_close(self.job);
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
            // CreateProcessAsUserWが失敗し、子は生成されていない。ここはJob終了ではなく
            // kill-on-closeだけで作成途中のJobを破棄する後始末が正しい。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// **BUG-018の「修正」が実は無言で壊れていたことの回帰テスト。**
    ///
    /// 呼び出し側（`shell.rs`の`run_windows_tier1`）は`let _ =`で結果を捨てるため、この関数が
    /// 失敗しても誰も気付けない（B-09/B-10）。実際、BUG-018の案Aで入れた`"S:(ML;NI;NW;;;LW)"`の
    /// `NI`はSDDLの正規ACEフラグトークンではなく（正規はCI/OI/NP/IO/ID/SA/FA）、
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`が`ERROR_INVALID_FLAGS`で失敗し、
    /// **ラベルは一度も付いていなかった**。報告された症状（継承ラベルの汚染）は
    /// 「ラベルを付けない」ことで消えるため、当時のE2Eは通ってしまった。
    ///
    /// 冪等（2回呼んでも成功する）ことも同時に固定する。
    #[test]
    fn set_low_integrity_label_actually_succeeds_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();

        set_low_integrity_label(dir.path()).expect("first call must succeed");
        set_low_integrity_label(dir.path()).expect("second call must succeed (idempotent)");
    }

    /// ラベルが**実際にオブジェクトへ書かれている**ことを、設定した値を読み直して確認する。
    /// 「呼び出しが`Ok`を返した」と「ラベルが付いた」は別の事実なので、実効で検証する（B-25）。
    #[test]
    fn set_low_integrity_label_leaves_a_low_mandatory_label_on_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        set_low_integrity_label(dir.path()).expect("label must be applied");

        let output = std::process::Command::new("icacls")
            .arg(dir.path())
            .output()
            .expect("icacls should run");
        let text = String::from_utf8_lossy(&output.stdout);

        // **ラベル行だけ**を取り出して調べる。DACLのACE行は親から継承した`(I)(OI)(CI)`を
        // 正当に持つので、出力全体に対して継承フラグの有無を問うと必ず誤検出する。
        let label_line = text
            .lines()
            .find(|line| line.contains("Mandatory Label"))
            .unwrap_or_else(|| {
                panic!("a mandatory label must be present on the directory: {text}")
            });

        assert!(
            label_line.contains("Low Mandatory Level"),
            "the label must be the Low mandatory level: {label_line}"
        );
        assert!(
            label_line.contains("(NW)"),
            "the label must carry the no-write-up policy: {label_line}"
        );
        // BUG-018の本来の目的: 子孫へ継承させない。継承フラグが復活していないことを固定する。
        assert!(
            !label_line.contains("(OI)") && !label_line.contains("(CI)"),
            "the mandatory label must not carry inheritance flags (BUG-018): {label_line}"
        );
    }

    /// **モジュールdocの「既知の限界」が実際にそうなっているかを、実機で測って固定する。**
    ///
    /// 非継承ラベルが意味するのは「ACL継承で伝播しない」ことだけで、Windows MICには別途
    /// 「作成者のILがMedium未満なら、新規オブジェクトに作成者のILを明示ラベルとして書く」
    /// という暗黙規則がある。この2つは別の機構なので、**ラベルを継承させないことが
    /// 「子ディレクトリの中に書けない」を意味するとは限らない**。docの記述はこの区別を
    /// 曖昧にしたまま「再びMedium扱いになる」と断言していたので、ここで実測に置き換える。
    ///
    /// 測るのは3つで、**対照群（cwd直下への書込が成功すること）を必ず含める**（B-35）。
    /// 含めないと、ラベルがまったく付いていない＝どこにも書けない状態でも
    /// 「サブディレクトリへ書けない」は成立してしまい、機構の生死を判定できない
    /// （BUG-088がまさにその形で数か月見逃された）。
    #[test]
    fn tier1_child_write_reach_under_a_labeled_cwd_is_measured() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();

        // 対象コマンドが動き出す**前に**、Medium ILのまま存在する既存サブディレクトリを
        // 用意する（実リポジトリの`src/`・`.git/`に相当する。テストプロセスはMedium）。
        std::fs::create_dir(cwd.join("presub")).unwrap();

        set_low_integrity_label(cwd).expect("label must be applied");

        // 成否は例外の有無ではなく`Test-Path`＝実際にファイルが在るかで判定する（B-25）。
        let script = concat!(
            // **失敗の理由を握り潰さない**（B-10）。`Test-Path`が偽だったときに
            // 「なぜ書けなかったのか」がここに出ていないと、調査がACL探しから始まる。
            "$ErrorActionPreference='Continue';",
            "Write-Output \"PWD=$((Get-Location).Path)\";",
            "Write-Output \"CWD=$([System.IO.Directory]::GetCurrentDirectory())\";",
            "Set-Content -Path 'root.txt' -Value x;",
            "Write-Output \"ROOT_WRITE=$(Test-Path 'root.txt')\";",
            "New-Item -ItemType Directory -Path 'newsub' -Force | Out-Null;",
            "Write-Output \"NEWSUB_CREATED=$(Test-Path 'newsub')\";",
            "Set-Content -Path 'newsub/a.txt' -Value x;",
            "Write-Output \"NEWSUB_WRITE=$(Test-Path 'newsub/a.txt')\";",
            "Set-Content -Path 'presub/b.txt' -Value x;",
            "Write-Output \"PRESUB_WRITE=$(Test-Path 'presub/b.txt')\";",
            "Write-Output 'NEWSUB_LABEL_BEGIN';",
            "if (Test-Path 'newsub') { icacls 'newsub' };",
            "Write-Output 'NEWSUB_LABEL_END'",
        );

        let child = spawn(
            test_shell(),
            &["-NoProfile", "-NonInteractive", "-Command", script],
            cwd,
            &test_env(),
            false,
        )
        .expect("spawn Tier1 child");
        let (out, err, code) = child.write_stdin_read_output_and_wait(None).unwrap();
        assert_eq!(
            code, 0,
            "the probe script itself must run: out={out:?} err={err:?}"
        );

        // 実測値をそのまま残す。将来この結果が変わったときに何が変わったのかを追えるようにする。
        eprintln!("[tier1-write-reach] out={out}");
        eprintln!("[tier1-write-reach] err={err}");

        let says = |key: &str, value: &str| out.contains(&format!("{key}={value}"));

        // **対照群**: cwd直下は書ける。ここが偽ならラベルが効いていないので、
        // 以下の「書けない」は機構の証拠にならない。
        // **落ちたときはまず`PWD`と`CWD`を見ること。** 2つある理由がここにある——
        // PowerShellのcmdletが相対パスを解決するのは`$PWD`（プロバイダのロケーション）で、
        // `CreateProcessAsUserW`が設定するのは`CWD`（プロセスの作業ディレクトリ）である。
        // 両者が食い違うと、ラベルは正しく付いているのに書込みだけが別の場所へ飛ぶ。
        // 実際にそうなった実例が[BUG-101](../../../../docs/bugs/BUG-101.md)である。
        assert!(
            says("ROOT_WRITE", "True"),
            "control group: a Tier1 child must be able to write directly in the labeled cwd \
             (if this fails, either the label is not in effect, or PWD != CWD — check both \
             lines above before suspecting the label): {out}"
        );

        // **既存のMediumサブディレクトリへは書けない**——No-Write-Upの帰結で、
        // ラベルはcwd 1個にしか付いていない。これが「Tier1では`git commit`もビルドも通らない」
        // の直接の根拠であり、プロジェクトの置き場所に依らない。
        assert!(
            says("PRESUB_WRITE", "False"),
            "a Tier1 child must NOT be able to write into a pre-existing Medium-IL subdirectory \
             (this is what makes `src/`・`.git/` unwritable in a real repository): {out}"
        );

        // **新規サブディレクトリの扱いは、上の2つとは別の機構で決まる**（MICの暗黙ラベル）。
        // 実測した結果をそのまま固定する。ここが将来変わったら、モジュールdocと
        // `docs/STATUS.md`のTier1の記述を必ず追随させること。
        assert!(
            says("NEWSUB_CREATED", "True"),
            "creating a new subdirectory directly under the labeled cwd must succeed: {out}"
        );
        assert!(
            says("NEWSUB_WRITE", "True"),
            "a directory created BY the low-IL child inherits the creator's integrity level \
             (implicit MIC rule), so writing inside it succeeds — this is NOT the same thing as \
             the mandatory label being inherited via the ACL: {out}"
        );

        // **機構まで固定する。** 「書けた」だけでは、ラベルが継承されたのか
        // MICが作成者ILを書いたのかが区別できない。`icacls`の出力では継承ACEに`(I)`が付くので、
        // ラベル行に`(I)`が**無い**ことが「ACL継承ではない」の直接の証拠になる
        // （同じ出力中のDACL行はすべて`(I)`付きで、対照になっている）。
        let label_line = out
            .lines()
            .skip_while(|l| !l.contains("NEWSUB_LABEL_BEGIN"))
            .take_while(|l| !l.contains("NEWSUB_LABEL_END"))
            .find(|l| l.contains("Mandatory Label"))
            .unwrap_or_else(|| {
                panic!("the child-created subdirectory must carry a mandatory label: {out}")
            });
        assert!(
            label_line.contains("Low Mandatory Level"),
            "the child-created subdirectory must be labeled Low, because its creator was Low: {label_line}"
        );
        assert!(
            !label_line.contains("(I)"),
            "the label must NOT be an inherited ACE — inheritance is deliberately off (BUG-018). \
             It is present because Windows MIC writes the creator's integrity level onto new \
             objects, which is a different mechanism entirely: {label_line}"
        );
    }

    /// テスト用のPowerShell実行ファイル名。`cmd.exe`は`/C`の再トークン化が独特で
    /// （複数の引用符付き引数を再連結する際の挙動がCommandLineToArgvW前提の
    /// `spawn`の組み立てと噛み合わない、既知のWindowsの落とし穴）、実運用の
    /// Tier1起動（`shell.rs`の`run_windows_tier1`）も同じ理由でPowerShellだけを使っている。
    /// テストもそれに合わせ、cmd.exe固有の罠を踏まないようにする。
    fn test_shell() -> &'static str {
        "powershell"
    }

    /// テスト用の最小限だが現実的な子環境。`&[]`（真に空の環境）を渡すと、PowerShell自身が
    /// `SystemRoot`等の初期化に必要な変数を持てず文字化けした起動時メッセージだけを吐いて
    /// 異常終了する（実機で確認済み——`build_env_block`の二重NUL終端バグとは別の、
    /// 「テストの入力が非現実的だった」という原因）。実運用の`run_windows_tier1`と同じく
    /// `secret_env::build_child_env()`を使う。
    fn test_env() -> Vec<(String, String)> {
        crate::secret_env::build_child_env()
    }

    /// `spawn_streaming`はstdout/stderrを行単位で流し、両方がEOFに達したら`OutputClosed`、
    /// プロセスが終了したら`Exited`を送る。`blocking_recv`を使うのは、このクレートが
    /// tokioの`sync`/`time`機能しか有効化しておらず（`#[tokio::test]`が使える`rt`/`macros`は
    /// 無い）、Tier1のspawn自体も管理者権限を要さないため素の`#[test]`で完結できるから。
    #[test]
    fn spawn_streaming_reports_stdout_stderr_and_exit() {
        let cwd = std::env::temp_dir();
        let child = spawn(
            test_shell(),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output out-line; Write-Error err-line",
            ],
            &cwd,
            &test_env(),
            false,
        )
        .expect("spawn should succeed");

        let mut rx = child.spawn_streaming(None);
        let mut stdout_lines = Vec::new();
        let mut stderr_lines = Vec::new();
        let mut saw_output_closed = false;
        let mut exit_code = None;

        // 3つのイベント全てを観測するまで受信する。`Exited`と`OutputClosed`はどちらが
        // 先に届いても正しい（設計上、順序を仮定しない）。
        while exit_code.is_none() || !saw_output_closed {
            match rx.blocking_recv().expect("channel should not close early") {
                OutputEvent::Stdout(line) => stdout_lines.push(line),
                OutputEvent::Stderr(line) => stderr_lines.push(line),
                OutputEvent::OutputClosed => saw_output_closed = true,
                OutputEvent::Exited(code) => exit_code = Some(code),
            }
        }

        assert!(
            stdout_lines.iter().any(|l| l.contains("out-line")),
            "{stdout_lines:?}"
        );
        assert!(
            stderr_lines.iter().any(|l| l.contains("err-line")),
            "{stderr_lines:?}"
        );
        // `Write-Error`はPowerShell自身の終了コードを1にする（-NonInteractiveでの既定挙動）。
        // ここでの主張は「終了コードが伝播すること」であって0であることではない。
        assert_eq!(exit_code, Some(1));
    }

    /// 非ゼロ終了コードもそのまま`Exited`に載る（`Write-Error`とは別経路——`exit N`による
    /// 明示的な終了コード指定が正しく伝播することを確認する）。
    #[test]
    fn spawn_streaming_reports_non_zero_exit_code() {
        let cwd = std::env::temp_dir();
        let child = spawn(
            test_shell(),
            &["-NoProfile", "-NonInteractive", "-Command", "exit 7"],
            &cwd,
            &test_env(),
            false,
        )
        .expect("spawn should succeed");

        let mut rx = child.spawn_streaming(None);
        let mut exit_code = None;
        while let Some(event) = rx.blocking_recv() {
            if let OutputEvent::Exited(code) = event {
                exit_code = Some(code);
                break;
            }
        }

        assert_eq!(exit_code, Some(7));
    }

    /// stdinへ書いた内容がそのままstdoutへ反映される（`-Command -`でスクリプトをstdinから
    /// 読む。実運用の`run_windows_tier1`と同じ形——BUG-050対策でコマンド本体を
    /// コマンドラインへ文字列として埋め込まないパターンをテストでも踏襲する）。
    #[test]
    fn spawn_streaming_delivers_stdin_payload_before_reading_output() {
        let cwd = std::env::temp_dir();
        let child = spawn(
            test_shell(),
            &["-NoProfile", "-NonInteractive", "-Command", "-"],
            &cwd,
            &test_env(),
            true,
        )
        .expect("spawn should succeed");

        let mut rx = child.spawn_streaming(Some(b"Write-Output hello-from-stdin\r\n"));
        let mut stdout_lines = Vec::new();
        while let Some(event) = rx.blocking_recv() {
            if let OutputEvent::Stdout(line) = event {
                stdout_lines.push(line);
            }
        }

        assert!(
            stdout_lines.iter().any(|l| l.contains("hello-from-stdin")),
            "{stdout_lines:?}"
        );
    }
}
