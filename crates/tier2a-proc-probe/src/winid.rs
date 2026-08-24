//! 自プロセスの識別情報（bitness・token integrity level・AppContainer package SID・
//! Redirector DLLのロード有無）をダンプする。`crates/harness-sandbox/src/privhelper.rs`の
//! `current_user_sid_string`と同じ「1回目はサイズ問い合わせのみ・2回目で本体取得」という
//! `GetTokenInformation`の定型パターンを再利用する。

use serde_json::{json, Value};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenAppContainerSid, TokenIntegrityLevel, PSID,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE;
use windows::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2, OpenProcessToken};

fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_invalid() {
        return None;
    }
    unsafe {
        let mut ptr = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut ptr).is_err() {
            return None;
        }
        let s = pwstr_to_string(ptr);
        let _ = LocalFree(HLOCAL(ptr.0 as *mut _));
        Some(s)
    }
}

unsafe fn pwstr_to_string(ptr: PWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    ptr.to_string().unwrap_or_default()
}

fn is_wow64() -> Option<bool> {
    unsafe {
        let mut process_machine = IMAGE_FILE_MACHINE(0);
        let ok = IsWow64Process2(GetCurrentProcess(), &mut process_machine, None);
        if ok.is_err() {
            return None;
        }
        // 0（IMAGE_FILE_MACHINE_UNKNOWN）はネイティブ実行を意味する（WOW64ではない）。
        Some(process_machine.0 != 0)
    }
}

fn with_process_token<T>(f: impl FnOnce(HANDLE) -> T) -> Option<T> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let result = f(token);
        let _ = CloseHandle(token);
        Some(result)
    }
}

fn integrity_level_sid() -> Option<String> {
    with_process_token(|token| unsafe {
        let mut ret_len = 0u32;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut ret_len);
        if ret_len == 0 {
            return None;
        }
        let mut buf = vec![0u8; ret_len as usize];
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        )
        .ok()?;
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        sid_to_string(label.Label.Sid)
    })
    .flatten()
}

fn appcontainer_sid() -> Option<String> {
    with_process_token(|token| unsafe {
        let mut ret_len = 0u32;
        let _ = GetTokenInformation(token, TokenAppContainerSid, None, 0, &mut ret_len);
        if ret_len == 0 {
            return None;
        }
        let mut buf = vec![0u8; ret_len as usize];
        GetTokenInformation(
            token,
            TokenAppContainerSid,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        )
        .ok()?;
        let info = &*(buf.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION);
        sid_to_string(info.TokenAppContainer)
    })
    .flatten()
}

fn module_loaded(name: &str) -> bool {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { GetModuleHandleW(windows::core::PCWSTR(wide.as_ptr())).is_ok() }
}

pub fn collect_identity() -> Value {
    json!({
        "pid": std::process::id(),
        "compiled_arch": if cfg!(target_arch = "x86_64") { "x86_64" } else if cfg!(target_arch = "x86") { "x86" } else { "unknown" },
        "is_wow64": is_wow64(),
        "integrity_level_sid": integrity_level_sid(),
        "appcontainer_sid": appcontainer_sid(),
        "redirector_x64_loaded": module_loaded("harness_redirector.dll"),
        "redirector_x86_loaded": module_loaded("harness_redirector_x86.dll"),
        "env_cow_workspace": std::env::var("HARNESS_COW_WORKSPACE").ok(),
        "env_cow_diff_layer": std::env::var("HARNESS_COW_DIFF_LAYER").ok(),
    })
}
