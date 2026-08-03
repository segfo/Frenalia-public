//! プロセス生成フック（`CreateProcessW`/`CreateProcessAsUserW`/`CreateProcessA`/`WinExec`）。
//!
//! 子を`CREATE_SUSPENDED`付きで起動し、`inject`でDLLを注入してから`ResumeThread`する。
//! `CreateProcessA`は`CreateProcessW`を経由せず直接`CreateProcessInternalW`を呼ぶため
//! 個別のフックが要る。`WinExec`は生成フラグを呼び出し元へ公開しないため、内部で
//! `hooked_create_process_a`へ委譲する。

use super::*;

/// Phase 4a（BUG-041修正）: `CreateProcessW`のフック本体。`dwCreationFlags`にSUSPENDEDを
/// 強制してからオリジナル関数を呼び、Win32レベルのプロセス生成が完全に終わった後（モジュールdoc
/// 参照）に孫プロセスへ再注入する。
pub(crate) unsafe extern "system" fn hooked_create_process_w(
    application_name: PCWSTR,
    command_line: PWSTR,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: BOOL,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: PCWSTR,
    startup_info: *const c_void,
    process_information: *mut c_void,
) -> BOOL {
    let hook = CREATE_PROCESS_W_HOOK.get().expect("hook installed");
    let caller_wanted_suspended = creation_flags & CREATE_SUSPENDED_FLAG != 0;
    let forced_flags = creation_flags | CREATE_SUSPENDED_FLAG;
    let ok = unsafe {
        hook.call(
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            forced_flags,
            environment,
            current_directory,
            startup_info,
            process_information,
        )
    };
    if !ok.as_bool() {
        return ok;
    }
    unsafe {
        inject_grandchild_and_maybe_resume(
            process_information,
            caller_wanted_suspended,
            "hooked_create_process_w",
        );
    }
    ok
}

/// Phase 4a（BUG-041修正）: `CreateProcessAsUserW`のフック本体。`hooked_create_process_w`と
/// 同じロジックで、第1引数の`hToken`はそのまま透過する。
pub(crate) unsafe extern "system" fn hooked_create_process_as_user_w(
    token: HANDLE,
    application_name: PCWSTR,
    command_line: PWSTR,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: BOOL,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: PCWSTR,
    startup_info: *const c_void,
    process_information: *mut c_void,
) -> BOOL {
    let hook = CREATE_PROCESS_AS_USER_W_HOOK.get().expect("hook installed");
    let caller_wanted_suspended = creation_flags & CREATE_SUSPENDED_FLAG != 0;
    let forced_flags = creation_flags | CREATE_SUSPENDED_FLAG;
    let ok = unsafe {
        hook.call(
            token,
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            forced_flags,
            environment,
            current_directory,
            startup_info,
            process_information,
        )
    };
    if !ok.as_bool() {
        return ok;
    }
    unsafe {
        inject_grandchild_and_maybe_resume(
            process_information,
            caller_wanted_suspended,
            "hooked_create_process_as_user_w",
        );
    }
    ok
}

/// 残課題#5: `CreateProcessA`のフック本体。`hooked_create_process_w`と全く同じ構造
/// （`CREATE_SUSPENDED`強制→オリジナル呼び出し→`inject_grandchild_and_maybe_resume`）。
/// `hooked_win_exec`からも（`GenericDetour::call`を経由するのではなく）このRust関数を
/// 直接呼び出す形で再利用する。
pub(crate) unsafe extern "system" fn hooked_create_process_a(
    application_name: PCSTR,
    command_line: PSTR,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: BOOL,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: PCSTR,
    startup_info: *const c_void,
    process_information: *mut c_void,
) -> BOOL {
    let hook = CREATE_PROCESS_A_HOOK.get().expect("hook installed");
    let caller_wanted_suspended = creation_flags & CREATE_SUSPENDED_FLAG != 0;
    let forced_flags = creation_flags | CREATE_SUSPENDED_FLAG;
    let ok = unsafe {
        hook.call(
            application_name,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            forced_flags,
            environment,
            current_directory,
            startup_info,
            process_information,
        )
    };
    if !ok.as_bool() {
        return ok;
    }
    unsafe {
        inject_grandchild_and_maybe_resume(
            process_information,
            caller_wanted_suspended,
            "hooked_create_process_a",
        );
    }
    ok
}

/// 残課題#5: `WinExec`のフック本体。モジュールdoc（`WinExecFn`定義の直前）参照——本物の
/// `WinExec`は呼ばず、`hooked_create_process_a`を直接呼んでsuspended起動→注入→resumeの
/// 経路へ載せ、`PROCESS_INFORMATION`が得られたら`WinExec`の戻り値規約（成功時33、失敗時
/// `ERROR_BAD_FORMAT`=11等の32以下の値）へ変換する。`ReentryGuard`は不要
/// （`hooked_create_process_a`自身のプロセス生成はファイルI/Oフックの再入対象外）。
pub(crate) unsafe extern "system" fn hooked_win_exec(cmd_line: PCSTR, cmd_show: u32) -> u32 {
    const ERROR_BAD_FORMAT: u32 = 11;
    if cmd_line.is_null() {
        return ERROR_BAD_FORMAT;
    }
    // `hooked_create_process_a`は`CREATE_PROCESS_A_HOOK`が設置済みである前提で書かれている
    // （`.expect("hook installed")`）。`install_create_process_hooks`はベストエフォートで
    // 各フックを独立に試みるため、理論上`WinExec`だけ設置に成功し`CreateProcessA`は
    // 失敗する組合せがあり得る——その場合はpanicさせず素直に失敗を返す。
    if CREATE_PROCESS_A_HOOK.get().is_none() {
        return ERROR_BAD_FORMAT;
    }
    // `lpCommandLine`はCreateProcessA側で書換可能である必要があるため、呼び出し元所有の
    // 読み取り専用バッファをそのまま渡さずローカルのミュータブルバッファへコピーする。
    let mut buf: Vec<u8> = unsafe { cmd_line.as_bytes() }.to_vec();
    buf.push(0);

    let mut startup_info = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        dwFlags: windows::Win32::System::Threading::STARTF_USESHOWWINDOW,
        wShowWindow: cmd_show as u16,
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();

    let ok = unsafe {
        hooked_create_process_a(
            PCSTR::null(),
            PSTR(buf.as_mut_ptr()),
            std::ptr::null(),
            std::ptr::null(),
            BOOL(0),
            0,
            std::ptr::null(),
            PCSTR::null(),
            &mut startup_info as *mut _ as *const c_void,
            &mut process_info as *mut _ as *mut c_void,
        )
    };
    if !ok.as_bool() {
        return ERROR_BAD_FORMAT;
    }
    unsafe {
        let _ = CloseHandle(process_info.hThread);
        let _ = CloseHandle(process_info.hProcess);
    }
    33 // WinExecの戻り値規約: 32より大きい値=成功（具体的な値に意味は無い）。
}
