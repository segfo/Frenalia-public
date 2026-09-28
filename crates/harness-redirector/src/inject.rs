//! 子プロセスへのDLL注入。
//!
//! `--sandbox tier2a-cow`の封じ込めは子孫プロセスにも及ぶ必要があるため、`CreateProcess*`フックが
//! `CREATE_SUSPENDED`で起動した子へ本DLLを`CreateRemoteThread`で注入してから再開させる。
//! x86子プロセスにはx86版DLLを注入する（`wow64`参照）。

use super::*;

/// このDLL自身の完全パス（`GetModuleFileNameW`、`SELF_MODULE`＝`DllMain`の`hinst`から）。
/// 孫プロセスへ同じDLLを`LoadLibraryW`させるため、また孫プロセス内でのモジュール識別
/// （`find_remote_module_base`）のために使う。
pub(crate) fn self_dll_path() -> Option<PathBuf> {
    let base = *SELF_MODULE.get()?;
    let mut buf = [0u16; 512];
    let len = unsafe { GetModuleFileNameW(HMODULE(base as *mut c_void), &mut buf) };
    if len == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// 孫へ立てたリモートスレッド（`LoadLibraryW`・`harness_cow_init`）を待つ上限。
const REMOTE_THREAD_WAIT_MS: u32 = 5000;

/// 孫のプロセスへ立てたリモートスレッドを待った結末（[BUG-175](../../../docs/bugs/BUG-175.md)）。
///
/// **「成功したか」と「渡したメモリを解放してよいか」は別の問いである。** 以前は4箇所の注入が
/// どちらも待ちの結果を見ず、時間切れの後に読んだ`STILL_ACTIVE`（259）を「0でない＝成功」と読み、
/// **まだ走っているスレッドが読んでいるDLLのパス・設定ブロブを解放していた**。その孫は
/// 警告台帳に1行も残らないまま、フックの設置が終わる前に再開されていた。
///
/// 判定の形は`harness-sandbox`の`inject_redirector`（直接の子への注入）が既に持っていたもの
/// （時間切れ／`WAIT_OBJECT_0`以外／終了コードが読めない／0）をそのまま写している。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteThreadEnd {
    /// スレッドは終わった。値はその終了コード。
    Finished(u32),
    /// 待ちが時間切れになった。スレッドはまだ走っている。
    StillRunning,
    /// スレッドは終わったが、終了コードを読めなかった。
    ExitCodeUnknown,
    /// 待ちそのものが失敗した。スレッドが走っているかどうか分からない。
    WaitFailed,
}

impl RemoteThreadEnd {
    /// 待ちの結果と、読めたなら終了コードから結末を決める。**終了コードは、待ちが
    /// `WAIT_OBJECT_0`（スレッドが終わった）のときにしか意味を持たない**——それ以外のときの値は
    /// `STILL_ACTIVE`（259）で、0でないので成功に見える。
    pub(crate) fn classify(wait: WAIT_EVENT, exit_code: Option<u32>) -> Self {
        if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
            return Self::StillRunning;
        }
        if wait != windows::Win32::Foundation::WAIT_OBJECT_0 {
            return Self::WaitFailed;
        }
        match exit_code {
            Some(code) => Self::Finished(code),
            None => Self::ExitCodeUnknown,
        }
    }

    /// 注入のこの段が成功したか。終わっていて、終了コードが0でないときだけ。
    pub(crate) fn succeeded(self) -> bool {
        matches!(self, Self::Finished(code) if code != 0)
    }

    /// スレッドへ渡したメモリを解放してよいか。**終わったと分かっているときだけ。**
    /// 終わっていない（または分からない）なら解放せずに残す——数百バイトが孫に残るだけで、
    /// 読まれている最中に解放するよりずっと安い。
    pub(crate) fn may_free_remote_memory(self) -> bool {
        matches!(self, Self::Finished(_) | Self::ExitCodeUnknown)
    }
}

/// `thread`を待ち、結末を返して取っ手を閉じる。注入の4箇所（x64・WOW64 × `LoadLibraryW`・
/// `harness_cow_init`）はすべてここを通る。解放してよいかは[`RemoteThreadEnd::may_free_remote_memory`]
/// で決めること。
///
/// # Safety
/// `thread`は`CreateRemoteThread`が返した有効なスレッドの取っ手であること。
pub(crate) unsafe fn wait_remote_thread(thread: HANDLE) -> RemoteThreadEnd {
    let wait = unsafe { WaitForSingleObject(thread, REMOTE_THREAD_WAIT_MS) };
    let mut exit_code: u32 = 0;
    let exit_code_read = unsafe { GetExitCodeThread(thread, &mut exit_code) }.is_ok();
    unsafe {
        let _ = CloseHandle(thread);
    }
    RemoteThreadEnd::classify(wait, exit_code_read.then_some(exit_code))
}

/// `process`（孫プロセス、`LoadLibraryW`完了後）内で、`dll_path`と同じ完全パスを持つ
/// モジュールのベースアドレスを`EnumProcessModulesEx`/`GetModuleFileNameExW`で特定する。
/// `GetExitCodeThread`によるHMODULE取得（32bit切り詰めの既知の制約、`inject_redirector`の
/// コメント参照）は使わない。
pub(crate) unsafe fn find_remote_module_base(process: HANDLE, dll_path: &Path) -> Option<usize> {
    let target_lc = dll_path.to_string_lossy().to_ascii_lowercase();
    let mut modules = vec![HMODULE::default(); 256];
    let mut needed: u32 = 0;
    let ok = unsafe {
        EnumProcessModulesEx(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };
    if ok.is_err() {
        return None;
    }
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
    for m in &modules[..count] {
        let mut buf = [0u16; 512];
        let len = unsafe { GetModuleFileNameExW(process, *m, &mut buf) };
        if len == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
        if name == target_lc {
            return Some(m.0 as usize);
        }
    }
    None
}

/// BUG-045のF2: 設定ブロブ（[`serialize_config_blob`]）を孫プロセスのアドレス空間へ書き込み、
/// `harness_cow_init`のスレッドパラメータとして渡せるポインタを返す。呼び出し元は
/// `CreateRemoteThread`の終了待ちのあとで`VirtualFreeEx`する責務を持つ。
/// WOW64（32bitターゲット）でも`VirtualAllocEx`は4GB未満のアドレスを返すため同じ経路で使える。
pub(crate) unsafe fn write_remote_config_blob(
    process: HANDLE,
    cfg: &Config,
) -> Option<*mut c_void> {
    let bytes = serialize_config_blob(cfg);
    let remote = unsafe {
        VirtualAllocEx(
            process,
            None,
            bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        debug_log("write_remote_config_blob: VirtualAllocEx failed");
        return None;
    }
    let written = unsafe {
        WriteProcessMemory(
            process,
            remote,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            None,
        )
    };
    if written.is_err() {
        debug_log("write_remote_config_blob: WriteProcessMemory failed");
        unsafe {
            let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        return None;
    }
    Some(remote)
}

/// Phase 4a本体: `process`（`CreateProcessW`が返したばかりの、まだSUSPENDEDの孫）へ
/// このDLL自身を2段階で再注入する（モジュールdoc参照）。成功＝フック設置完了確認まで
/// 済んだら`true`を返す。`cfg`は孫へ引き渡す設定（BUG-045のF2）。
pub(crate) unsafe fn inject_grandchild(process: HANDLE, cfg: &Config) -> bool {
    debug_log(&format!(
        "inject_grandchild: enter process_handle={:#x}",
        process.0 as usize
    ));
    let Some(dll_path) = self_dll_path() else {
        debug_log("inject_grandchild: self_dll_path() failed");
        return false;
    };
    let path_w: Vec<u16> = dll_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let size = path_w.len() * std::mem::size_of::<u16>();

    let remote_buf = unsafe {
        VirtualAllocEx(
            process,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buf.is_null() {
        debug_log(&format!(
            "inject_grandchild: VirtualAllocEx failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        return false;
    }
    let write_ok = unsafe {
        WriteProcessMemory(
            process,
            remote_buf,
            path_w.as_ptr() as *const c_void,
            size,
            None,
        )
    };
    if write_ok.is_err() {
        debug_log(&format!(
            "inject_grandchild: WriteProcessMemory failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    }

    let kernel32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let Ok(kernel32) = (unsafe { GetModuleHandleW(PCWSTR(kernel32_name.as_ptr())) }) else {
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    };
    let Some(load_library_addr) = (unsafe {
        GetProcAddress(
            kernel32,
            windows::core::PCSTR(c"LoadLibraryW".as_ptr() as *const u8),
        )
    }) else {
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    };
    let load_start: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<*const c_void, unsafe extern "system" fn(*mut c_void) -> u32>(
            load_library_addr as *const c_void,
        )
    });
    let mut tid: u32 = 0;
    let load_thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            load_start,
            Some(remote_buf),
            0,
            Some(&mut tid),
        )
    };
    let Ok(load_thread) = load_thread else {
        debug_log(&format!(
            "inject_grandchild: CreateRemoteThread(LoadLibraryW) failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    };
    let load_end = unsafe { wait_remote_thread(load_thread) };
    if load_end.may_free_remote_memory() {
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
    }
    debug_log(&format!(
        "inject_grandchild: step1 LoadLibraryW end={load_end:?}"
    ));
    if !load_end.succeeded() {
        // `LoadLibraryW`が孫プロセス内で失敗した（32bitターゲット等、Phase 4bの対象）か、
        // 終わったかどうかが分からない。
        return false;
    }

    // ステップ②: 孫プロセス内の自DLLベースを特定し、`harness_cow_init`のRVAを加算した
    // アドレスへ明示的に`CreateRemoteThread`する。このスレッドの終了待ちが「フック設置完了」の
    // 唯一の同期点になる（モジュールdoc参照）。
    let Some(remote_base) = (unsafe { find_remote_module_base(process, &dll_path) }) else {
        debug_log("inject_grandchild: find_remote_module_base failed (module not found in remote process)");
        return false;
    };
    let Some(local_base) = SELF_MODULE.get().copied() else {
        debug_log("inject_grandchild: SELF_MODULE not set");
        return false;
    };
    let local_init_addr = unsafe {
        GetProcAddress(
            HMODULE(local_base as *mut c_void),
            windows::core::PCSTR(c"harness_cow_init".as_ptr() as *const u8),
        )
    };
    let Some(local_init_addr) = local_init_addr else {
        debug_log("inject_grandchild: GetProcAddress(harness_cow_init) failed");
        return false;
    };
    let rva = (local_init_addr as usize).wrapping_sub(local_base);
    let remote_init_addr = remote_base.wrapping_add(rva);
    debug_log(&format!(
        "inject_grandchild: step2 remote_base={remote_base:#x} local_base={local_base:#x} \
         rva={rva:#x} remote_init_addr={remote_init_addr:#x}"
    ));
    let init_start: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(
            remote_init_addr,
        )
    });
    // BUG-045のF2: 設定を孫プロセスのenv blockに頼らず、スレッドパラメータとして直接渡す。
    // 失敗しても致命ではない（孫側は環境変数へフォールバックする）ため`None`で続行する。
    let config_blob = unsafe { write_remote_config_blob(process, cfg) };
    let mut tid2: u32 = 0;
    let init_thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            init_start,
            config_blob.map(|p| p as *const c_void),
            0,
            Some(&mut tid2),
        )
    };
    let Ok(init_thread) = init_thread else {
        debug_log(&format!(
            "inject_grandchild: CreateRemoteThread(harness_cow_init) failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        if let Some(buf) = config_blob {
            unsafe {
                let _ = VirtualFreeEx(process, buf, 0, MEM_RELEASE);
            }
        }
        return false;
    };
    let init_end = unsafe { wait_remote_thread(init_thread) };
    if let (Some(buf), true) = (config_blob, init_end.may_free_remote_memory()) {
        unsafe {
            let _ = VirtualFreeEx(process, buf, 0, MEM_RELEASE);
        }
    }
    debug_log(&format!(
        "inject_grandchild: step2 harness_cow_init end={init_end:?}"
    ));
    init_end.succeeded()
}

/// フック設置成功後、`lpProcessInformation`（非NULL、Win32 API仕様上保証）から`hProcess`/
/// `hThread`を読み、孫プロセスへ`inject_grandchild`し、呼び出し元が元々`CREATE_SUSPENDED`を
/// 要求していなければ`ResumeThread`する（Q6: 生成自体は拒否しない）。`CreateProcessW`/
/// `CreateProcessAsUserW`の両フックから共有する（BUG-041修正、モジュールdoc参照）。
/// [D-88] 注入しないプロセス名の一覧を運ぶ環境変数。**起動側が積んだものをそのまま読む**
/// （`win_appcontainer::lazy_grant::NO_INJECT_ENV`と同じ綴り。両端で別々に決めない）。
pub(crate) const NO_INJECT_ENV: &str = "HARNESS_REDIRECTOR_NO_INJECT";

/// `process`の実行像が[`NO_INJECT_ENV`]の一覧に入っているか。
///
/// **判定できなければ「入っていない」＝注入する側へ倒す。** 外し損ねても失われるのは
/// 透過性だけだが、外しすぎるとレーンが黙って効かなくなる（`B-10`）。
///
/// # Safety
/// `process`は`PROCESS_QUERY_LIMITED_INFORMATION`相当を持つ有効なハンドルであること。
unsafe fn grandchild_injection_is_excluded(process: HANDLE) -> bool {
    let Ok(list) = std::env::var(NO_INJECT_ENV) else {
        return false;
    };
    if list.trim().is_empty() {
        return false;
    }
    let mut buf = [0u16; 260];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        windows::Win32::System::Threading::QueryFullProcessImageNameW(
            process,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    if ok.is_err() || len == 0 {
        return false;
    }
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    let Some(name) = std::path::Path::new(&full)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
    else {
        return false;
    };
    list.split(';')
        .map(|entry| entry.trim().to_lowercase())
        .any(|entry| !entry.is_empty() && entry == name)
}

/// [D-88] **フックを入れられなかった子を、準備が終わるまで待たせてから動かす。**
///
/// # なぜここで待てるのか（そして走り出したら待てないのか）
///
/// この時点の子は`CREATE_SUSPENDED`で作られたまま**1行も実行していない**。だから
/// 「準備が終わってから始める」に切り替えても、二重に起きる副作用が無い。
/// 走り出した後の失敗（開こうとして拒否された）は巻き戻せないので、そちらは
/// 別の手当て（受付側のラッチ）になる。
///
/// **待てなくても必ず動かす。** 受付へ届かない・準備が配り切れなかった等で待ちが
/// 成立しなくても、一時停止のまま置き去りにはしない（`B-01`: 止めたものを動かす対を書く）。
/// その場合その子はフック無しで走り、未準備のファイルは拒否される——**安全側**である。
///
/// # Safety
/// `pi`は有効な`PROCESS_INFORMATION`を指していること。
unsafe fn wait_then_resume(pi: &PROCESS_INFORMATION, caller_wanted_suspended: bool, caller: &str) {
    if let Some(cfg) = CONFIG.get() {
        let prepared = wait_until_workspace_prepared(cfg);
        debug_log(&format!(
            "{caller}: waited for the workspace preparation before resuming, prepared={prepared}"
        ));
    }
    // **呼び出し元が一時停止を望んでいたなら動かさない**——それはこのフックの都合ではなく
    // アプリの意図なので、勝手に動かすと`CREATE_SUSPENDED`の意味が壊れる。
    if !caller_wanted_suspended {
        unsafe {
            let _ = windows::Win32::System::Threading::ResumeThread(pi.hThread);
        }
    }
}

pub(crate) unsafe fn inject_grandchild_and_maybe_resume(
    process_information: *mut c_void,
    caller_wanted_suspended: bool,
    caller: &str,
) {
    if process_information.is_null() {
        debug_log(&format!(
            "{caller}: lpProcessInformation is null, skip injection"
        ));
        return;
    }
    let pi = unsafe { &*(process_information as *const PROCESS_INFORMATION) };
    // [D-88] **注入の対象外に指定された像なら、ここで降りる。**
    //
    // 判定を4つのプロセス生成フックそれぞれではなくここへ置くのは、**全部がここを通る**
    // からである（`B-06`: 決定は経路の共通点へ置く）。外した子孫はフックを持たないので、
    // 未準備のファイルへのアクセスは**待たされるのではなく拒否される**——
    // 起動側の「待つ／待たない」の判断は、子孫が起きる頃にはもう終わっている。
    if unsafe { grandchild_injection_is_excluded(pi.hProcess) } {
        debug_log(&format!(
            "{caller}: skipping injection because the image is on {NO_INJECT_ENV}"
        ));
        unsafe { wait_then_resume(pi, caller_wanted_suspended, caller) };
        return;
    }
    debug_log(&format!(
        "{caller}: process_handle={:#x} thread_handle={:#x} caller_wanted_suspended={caller_wanted_suspended}, calling inject_grandchild",
        pi.hProcess.0 as usize, pi.hThread.0 as usize
    ));
    if let Some(cfg) = CONFIG.get() {
        let is_wow64 = unsafe { wow64::is_wow64_target(pi.hProcess) };
        let injected = if is_wow64 {
            match self_dll_path() {
                Some(x64_dll_path) => unsafe {
                    wow64::inject_grandchild_wow64(pi.hProcess, pi.hThread, &x64_dll_path, cfg)
                },
                None => {
                    debug_log(&format!(
                        "{caller}: self_dll_path() failed for wow64 injection"
                    ));
                    false
                }
            }
        } else {
            unsafe { inject_grandchild(pi.hProcess, cfg) }
        };
        debug_log(&format!(
            "{caller}: injection (wow64={is_wow64}) returned {injected}"
        ));
        if !injected {
            let message = if is_wow64 {
                "grandchild redirector re-injection failed or timed out (32bit/WOW64 target, \
                 Phase 4b); writes from this process will not be redirected to the CoW diff_layer \
                 directory (workspace stays read-only ACL, so writes fail closed rather than \
                 silently missing the ledger)"
            } else {
                "grandchild redirector re-injection failed or timed out; writes from this \
                 process will not be redirected to the CoW diff_layer directory (workspace stays \
                 read-only ACL, so writes fail closed rather than silently missing the ledger)"
            };
            append_warning_entry(cfg, message);
            // [D-88] **注入できなかった子は、準備が終わるまで動かさない。**
            // フック無しで走ると、未準備のファイルへのアクセスが拒否されて
            // コマンドが失敗する。まだ1行も動いていない今なら待てる（`wait_then_resume`）。
            unsafe { wait_then_resume(pi, caller_wanted_suspended, caller) };
            return;
        }
    } else {
        // このプロセス自体がまだ設定未完了（フック設置競合等の異常系）。孫は素通し。
        debug_log(&format!("{caller}: CONFIG not set, passthrough"));
    }
    if !caller_wanted_suspended {
        unsafe {
            let _ = ResumeThread(pi.hThread);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};

    /// `GetExitCodeThread`が「まだ走っている」ときに返す値。
    const STILL_ACTIVE: u32 = 259;

    /// BUG-175: 待ちが時間切れのとき（または待ちそのものが失敗したとき）、あとから読んだ終了コードは
    /// `STILL_ACTIVE`（259）＝「まだ走っている」で、0でないからといって成功ではない。
    /// そのスレッドは渡したメモリ（DLLのパス・設定ブロブ）をまだ読んでいるかもしれないので、解放もしない。
    #[test]
    fn a_remote_thread_that_did_not_finish_is_neither_a_success_nor_safe_to_free() {
        for (what, wait) in [("timed out", WAIT_TIMEOUT), ("wait failed", WAIT_FAILED)] {
            let end = RemoteThreadEnd::classify(wait, Some(STILL_ACTIVE));
            assert!(
                !end.succeeded(),
                "BUG-175: a remote thread whose wait {what} must not count as injected ({end:?})"
            );
            assert!(
                !end.may_free_remote_memory(),
                "BUG-175: memory a still-running thread may read must not be freed ({what}, {end:?})"
            );
        }
    }

    /// 許可側: 終わったスレッドは終了コードで成否が決まり、成否にかかわらずメモリは解放してよい
    /// （もう誰も読まない）。終了コードが読めなかったときは成功と言わない。
    #[test]
    fn a_finished_remote_thread_is_judged_by_its_exit_code_and_its_memory_may_be_freed() {
        let loaded = RemoteThreadEnd::classify(WAIT_OBJECT_0, Some(1));
        assert!(loaded.succeeded());
        assert!(loaded.may_free_remote_memory());

        let failed = RemoteThreadEnd::classify(WAIT_OBJECT_0, Some(0));
        assert!(!failed.succeeded());
        assert!(failed.may_free_remote_memory());

        let unknown = RemoteThreadEnd::classify(WAIT_OBJECT_0, None);
        assert!(!unknown.succeeded());
        assert!(unknown.may_free_remote_memory());
    }
}
