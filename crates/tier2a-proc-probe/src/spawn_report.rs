//! **「子を1本起こして、その結果を同じ欄で報告する」ところ**だけ。
//!
//! # なぜ2つの腕で共有するのか（2026-09-17、段階6f-2）
//!
//! 同じことを**2通りのやり方**で起こして比べたいからである。
//!
//! | 腕 | 誰が電文を組むか | 何を確かめるための腕か |
//! |---|---|---|
//! | [`crate::spawn_via_daemon`] | **プローブ自身**（フックの役を演じる） | Daemon側が呼び出し元の持ち物で起こせること（段階6f-1） |
//! | [`crate::spawn_transparently`] | **Redirector DLLのフック** | そのフックが同じ電文を組めること（段階6f-2） |
//!
//! **報告の欄が違うと比べられない。** 受け皿（継承可で開く標準出力）・待ち方
//! （`WaitForSingleObject`→`GetExitCodeProcess`）・欄の綴りをここに置いて、
//! 両方の腕がここを通る（`docs/CODE-STRUCTURE-RULES.md` §5.0: 写しを作らない）。

use serde_json::{json, Value};

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;

/// 子の標準出力にするファイル。**開けなかったことを黙らせない**（`B-10`）
/// ——黙ると「子が何も書かなかった」に見える。
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Default)]
pub struct Stdout {
    #[cfg(windows)]
    pub handle: Option<HANDLE>,
    pub open_error: Option<String>,
}

/// 継承可で開く。`None`を渡したら何も開かない（標準出力は`NUL`へ落ちる）。
#[cfg(windows)]
pub fn open_inheritable(path: Option<&str>) -> Stdout {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let Some(path) = path else {
        return Stdout::default();
    };
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // **継承可で開く。** Daemon経由の腕では引き抜かれるので継承可でなくてもよいが、
    // フック経由の腕（生成禁止を積んでいない構成）では**継承で渡る**ので要る。
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa as *const _),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(handle) => Stdout {
            handle: Some(handle),
            open_error: None,
        },
        Err(e) => Stdout {
            handle: None,
            open_error: Some(format!("CreateFileW({path}): {e}")),
        },
    }
}

#[cfg(windows)]
impl Stdout {
    /// 子側の端を閉じる。**閉じないと、子が終わってもファイルが掴まれたままになる。**
    pub fn close(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }

    pub fn value(&self) -> Option<u64> {
        self.handle.map(|h| h.0 as usize as u64)
    }
}

/// 返ってきたプロセスハンドルで待ち、終了コードを読んで報告へ畳む。
///
/// **`GetExitCodeProcess`だけで「終わったか」を判定しない**——`STILL_ACTIVE`(259)と
/// 「259で終了した」が区別できない（`harness-sandbox`の`process_is_alive`と同じ理屈）。
/// 先に`WaitForSingleObject`でシグナルを待つ。
///
/// **待てなかった・読めなかったときは、その旨を欄に残す**（`B-10`）。
/// 「子が走らなかった」と「待てなかった」は別の事実で、混ぜると相手側の不具合が
/// プローブ側の不具合に見える。
#[cfg(windows)]
pub fn wait_and_record(report: &mut Value, process: Option<u64>, thread: Option<u64>) {
    report["got_process_handle"] = json!(process.is_some_and(|h| h != 0));
    report["got_thread_handle"] = json!(thread.is_some_and(|h| h != 0));
    let Some(process) = process.filter(|h| *h != 0) else {
        return;
    };
    let (waited, exit_code, error) = wait_for(process);
    report["waited_ok"] = json!(waited);
    report["child_exit_code"] = exit_code.map(Value::from).unwrap_or(Value::Null);
    report["wait_error"] = error.map(Value::from).unwrap_or(Value::Null);
}

#[cfg(windows)]
fn wait_for(process: u64) -> (bool, Option<u32>, Option<String>) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

    let handle = HANDLE(process as usize as *mut _);
    let waited = unsafe { WaitForSingleObject(handle, 30_000) };
    if waited != WAIT_OBJECT_0 {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return (
            false,
            None,
            Some(format!("WaitForSingleObject returned {}", waited.0)),
        );
    }
    let mut code = 0u32;
    let read = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    match read {
        Ok(()) => (true, Some(code), None),
        Err(e) => (true, None, Some(format!("GetExitCodeProcess: {e}"))),
    }
}
