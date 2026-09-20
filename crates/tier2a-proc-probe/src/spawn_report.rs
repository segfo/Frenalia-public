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

/// [#49] **返ってきたハンドルで何ができるかを測る。**
///
/// # 何のためにあるのか
///
/// Spawn Daemonは起こした子のプロセス／スレッドハンドルを呼び出し元へ複製して返す。
/// **ドメインを跨ぐ遷移では、そこに注入できる権限を載せてはいけない**
/// （`harness-sandbox`の`spawnd::server::caller_handle_rights`）。載っているかどうかは
/// **実際に撃ってみる以外に確かめようが無い**ので、ここで撃って報告する。
///
/// # 測る順序に意味がある
///
/// 1. **注入できるか**（`VirtualAllocEx`→`WriteProcessMemory`）。確保できたら必ず解放する
/// 2. **終了コードを読めるか**（契約の側。絞りすぎていないこと）
/// 3. **`ResumeThread`できるか**。**これは子を動かす**ので最後に撃つ
///
/// # 子が生きている間に撃つこと（呼び出し側の責任）
///
/// 終了済みのプロセスへの`VirtualAllocEx`も失敗する。**一時停止で頼んで、ここを通してから
/// 再開する**形でなければ、「絞れたから失敗した」と「死んでいたから失敗した」が区別できない。
///
/// 報告の形は[`crate::object_reach::attempt`]と同じ（`{kind,target,access,ok,last_error}`）。
#[cfg(windows)]
pub fn record_handle_rights(report: &mut Value, process: Option<u64>, thread: Option<u64>) {
    use windows::Win32::Foundation::{GetLastError, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{GetExitCodeProcess, ResumeThread};

    let mut attempts: Vec<Value> = Vec::new();
    let last_error = || unsafe { GetLastError() }.0;

    if let Some(process) = process.filter(|h| *h != 0) {
        let handle = HANDLE(process as usize as *mut _);
        // 1. 注入の前提。**確保できた時点で注入できる**（書き込みはその確認）。
        let block =
            unsafe { VirtualAllocEx(handle, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        attempts.push(crate::object_reach::attempt(
            "handed-process",
            "returned-by-daemon",
            "PROCESS_VM_OPERATION (VirtualAllocEx)",
            !block.is_null(),
            if block.is_null() { last_error() } else { 0 },
        ));
        if !block.is_null() {
            let payload: [u8; 8] = *b"INJECTED";
            let wrote = unsafe {
                WriteProcessMemory(
                    handle,
                    block,
                    payload.as_ptr() as *const _,
                    payload.len(),
                    None,
                )
            };
            attempts.push(crate::object_reach::attempt(
                "handed-process",
                "returned-by-daemon",
                "PROCESS_VM_WRITE (WriteProcessMemory)",
                wrote.is_ok(),
                if wrote.is_ok() { 0 } else { last_error() },
            ));
            // **借りた物は返す。** 失敗しても報告には出さない（測っているのは注入可否である）。
            unsafe {
                let _ = VirtualFreeEx(handle, block, 0, MEM_RELEASE);
            }
        }
        // 2. 契約の側。ここが落ちていたら絞りすぎである。
        let mut code = 0u32;
        let read = unsafe { GetExitCodeProcess(handle, &mut code) };
        attempts.push(crate::object_reach::attempt(
            "handed-process",
            "returned-by-daemon",
            "PROCESS_QUERY_LIMITED_INFORMATION (GetExitCodeProcess)",
            read.is_ok(),
            if read.is_ok() { 0 } else { last_error() },
        ));
    }

    if let Some(thread) = thread.filter(|h| *h != 0) {
        // 3. **子が動き出す。** 一時停止で頼んでいなければ`-1`（もともと止まっていない）。
        let previous = unsafe { ResumeThread(HANDLE(thread as usize as *mut _)) };
        attempts.push(crate::object_reach::attempt(
            "handed-thread",
            "returned-by-daemon",
            "THREAD_SUSPEND_RESUME (ResumeThread)",
            previous != u32::MAX,
            if previous == u32::MAX {
                last_error()
            } else {
                0
            },
        ));
    }

    report["handle_rights"] = Value::Array(attempts);
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
