//! Tier0の子プロセス起動（Windows）。`CreateProcessW` + 継承パイプ + Job Object。
//!
//! [`super`]のモジュールdocのとおり、ここには**封じ込めが1つも無い**。
//! Tier1（`tier1::win_restricted`）との差分は次の2点だけで、それ以外の作法
//! （継承フラグの戻し方・コマンドラインの組み立て・env block・spawn後のハンドル整理・
//! ジョブへの割り当て）は同一である。
//!
//! 1. トークンを作らない（`CreateProcessAsUserW`ではなく`CreateProcessW`）。
//! 2. パイプに明示ラベルを付けない（[`create_inheritable_pipe`]のdocに理由）。
//!
//! 出力ストリーミングとkillは**Tier1/Tier2aと同じ実装を共有する**
//! （[`stream_child_output`]・[`KillToken`]）。`Exited`と`OutputClosed`を独立イベントに
//! しておく作法もそこに集約されているので、ここで書き直さない。

use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::win_common::{
    build_env_block, clear_inherit, create_inheritable_pipe, create_job_object,
    stream_child_output, terminate_job_and_close, wide, KillToken, OutputEvent,
};

#[derive(Debug, thiserror::Error)]
pub enum PlainError {
    #[error("win32 call failed: {0}")]
    Win32(String),
}

impl From<windows::core::Error> for PlainError {
    fn from(e: windows::core::Error) -> Self {
        PlainError::Win32(e.to_string())
    }
}

/// spawn済みのTier0子プロセス。
///
/// Tier1の`RestrictedChild`より小さいのは、パス1が必要とするのが
/// [`Self::kill_token`]と[`Self::spawn_streaming`]の2つだけだからである
/// （一問一答の`write_stdin_read_output_and_wait`はTier0には要らない）。
/// 使わないものを「対称のため」に足すと、テストの無いコードが増えるだけになる。
pub struct PlainChild {
    process: HANDLE,
    job: HANDLE,
    stdin_write: Option<HANDLE>,
    stdout_read: HANDLE,
    stderr_read: HANDLE,
}

// HANDLEはカーネルオブジェクトへのポインタ値であり、複数スレッドからの
// TerminateProcess/ReadFile呼び出し自体はOSレベルで安全（Win32 APIの前提）。
unsafe impl Send for PlainChild {}

impl PlainChild {
    /// 本体が別スレッドへ移動した後もtimeout・キャンセルからkillできる軽量ハンドル。
    pub fn kill_token(&self) -> Result<KillToken, PlainError> {
        Ok(KillToken::duplicate(self.job)?)
    }

    /// stdin送出後、stdout/stderrを行単位で[`OutputEvent`]として流し、プロセス終了を
    /// 別イベントとして通知する。実装はTier1/Tier2aと共有（[`stream_child_output`]）。
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

impl Drop for PlainChild {
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

/// 隔離せずに子プロセスを起動する（Job Objectのkill-on-closeだけは付ける）。
/// `exe`は絶対パスかPATH解決可能な名前（`lpApplicationName`は`None`、
/// `lpCommandLine`にexe+argsを連結して渡す）。
/// stdinは`want_stdin`が`true`の場合のみパイプを用意する。
pub fn spawn(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
) -> Result<PlainChild, PlainError> {
    let job = create_job_object()?;

    // 親が保持し続ける側（子へは渡さない側）は継承不可に戻す（`clear_inherit`のdocコメント参照）。
    let (stdout_read, stdout_write) = create_inheritable_pipe()?;
    clear_inherit(stdout_read);
    let (stderr_read, stderr_write) = create_inheritable_pipe()?;
    clear_inherit(stderr_read);
    let (stdin_read, stdin_write) = if want_stdin {
        let (r, w) = create_inheritable_pipe()?;
        clear_inherit(w);
        (Some(r), Some(w))
    } else {
        (None, None)
    };

    // [2026-09-17] 引用の規則は`win_common`が持つ（3Tier共通）。**かつてここに写しがあり、
    // バックスラッシュと引用符が隣り合う引数で引数の境界がずれていた**（同関数のdoc）。
    let cmdline = crate::win_common::command_line_for(exe, args);
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
        CreateProcessW(
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
    }

    if let Err(e) = spawn_result {
        unsafe {
            // CreateProcessWが失敗し、子は生成されていない。ここはJob終了ではなく
            // kill-on-closeだけで作成途中のJobを破棄する後始末が正しい。
            let _ = CloseHandle(job);
            let _ = CloseHandle(stdout_read);
            let _ = CloseHandle(stderr_read);
            if let Some(w) = stdin_write {
                let _ = CloseHandle(w);
            }
        }
        return Err(PlainError::from(e));
    }

    unsafe {
        if let Err(e) = AssignProcessToJobObject(job, process_info.hProcess) {
            // **ここを素通りさせると、誰も殺せない子が走り続ける。** 子は
            // `CREATE_SUSPENDED`無しで起動済みなので、Jobへ入れ損ねたまま`?`で返すと
            // (1) どのJobにも属さない子が生き残り、(2) `hProcess`も閉じてしまうので
            // 後から終了させる手段が無くなる。Tier2aの`spawn_impl`は同じ分岐で
            // この後始末を書いている（`docs/CODE-STRUCTURE-RULES.md`規則5.1の対）。
            //
            // **限界**: 起動済みである以上、Assignが失敗した時点で子が既に孫を作っている
            // 可能性がある。`TerminateProcess`は直接の子しか殺さないので、**この経路だけは
            // 子孫を保証できない**。塞ぐにはTier0/Tier1も`CREATE_SUSPENDED`→Job割り当て
            // →`ResumeThread`の順へ寄せる必要がある（`docs/bugs/BUG-156.md`）。
            let _ = TerminateProcess(process_info.hProcess, 1);
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            // 子は明示終了済みなのでJob終了ではなくkill-on-closeで破棄する（上の分岐と同じ理由）。
            let _ = CloseHandle(job);
            let _ = CloseHandle(stdout_read);
            let _ = CloseHandle(stderr_read);
            if let Some(w) = stdin_write {
                let _ = CloseHandle(w);
            }
            return Err(PlainError::from(e));
        }
        let _ = CloseHandle(process_info.hThread);
    }

    Ok(PlainChild {
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

    /// **Tier0の子は、Tier1が書けない場所へ書ける。**
    ///
    /// パス1をTier1からTier0へ移した理由そのものを固定する回帰テストで、
    /// 対になるのは`tier1::win_restricted`の
    /// `tier1_child_write_reach_under_a_labeled_cwd_is_measured`である
    /// （あちらは「既存のMediumサブディレクトリへは書けない」を測っている）。
    /// 片方だけだと「Tier0にした意味があったのか」を誰も確かめられない（B-35）。
    #[test]
    fn tier0_child_can_write_into_a_pre_existing_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        // Tier1で書けなかったのと**同じ形**の対象を用意する（Medium ILの既存サブディレクトリ）。
        std::fs::create_dir(cwd.join("presub")).unwrap();

        let script = concat!(
            "$ErrorActionPreference='SilentlyContinue';",
            "Set-Content -Path 'presub/b.txt' -Value x;",
            "Write-Output \"PRESUB_WRITE=$(Test-Path 'presub/b.txt')\"",
        );

        let child = spawn(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
            cwd,
            &crate::secret_env::build_child_env(),
            false,
        )
        .expect("spawn Tier0 child");

        let mut rx = child.spawn_streaming(None);
        let mut out = String::new();
        let mut exit = None;
        // **`OutputClosed`で打ち切らない。** `Exited`と`OutputClosed`は別スレッドから送られる
        // 独立したイベントで、順序は保証されない（`OutputEvent`のdoc・`child_run.rs`の1番）。
        // 送信側が全て落ちるとチャネルが閉じるので、`None`まで素直に汲み切る。
        while let Some(event) = rx.blocking_recv() {
            match event {
                OutputEvent::Stdout(line) | OutputEvent::Stderr(line) => out.push_str(&line),
                OutputEvent::Exited(code) => exit = Some(code),
                OutputEvent::OutputClosed => {}
            }
        }

        assert_eq!(exit, Some(0), "the probe script must run: {out}");
        assert!(
            out.contains("PRESUB_WRITE=True"),
            "a Tier0 child must be able to write into a pre-existing Medium-IL subdirectory — \
             this is exactly what Tier1 cannot do, and the reason pass 1 was moved here: {out}"
        );
    }
}
