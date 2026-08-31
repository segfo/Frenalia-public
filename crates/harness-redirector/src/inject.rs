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
    let wait_result = unsafe { WaitForSingleObject(load_thread, 5000) };
    let mut exit_code: u32 = 0;
    unsafe {
        let _ = GetExitCodeThread(load_thread, &mut exit_code);
        let _ = CloseHandle(load_thread);
        let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
    }
    debug_log(&format!(
        "inject_grandchild: step1 LoadLibraryW wait_result={:#x} exit_code={:#x}",
        wait_result.0, exit_code
    ));
    if exit_code == 0 {
        // `LoadLibraryW`が孫プロセス内で失敗した（32bitターゲット等、Phase 4bの対象）。
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
    let init_wait_result = unsafe { WaitForSingleObject(init_thread, 5000) };
    let mut init_exit: u32 = 0;
    unsafe {
        let _ = GetExitCodeThread(init_thread, &mut init_exit);
        let _ = CloseHandle(init_thread);
        if let Some(buf) = config_blob {
            let _ = VirtualFreeEx(process, buf, 0, MEM_RELEASE);
        }
    }
    debug_log(&format!(
        "inject_grandchild: step2 harness_cow_init wait_result={:#x} exit_code={:#x}",
        init_wait_result.0, init_exit
    ));
    init_exit != 0
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
unsafe fn wait_then_resume(
    pi: &PROCESS_INFORMATION,
    caller_wanted_suspended: bool,
    caller: &str,
) {
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
