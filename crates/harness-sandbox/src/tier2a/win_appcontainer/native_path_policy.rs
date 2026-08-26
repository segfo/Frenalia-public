//! Windows の実験的な OS ネイティブ・パス制御 contract の読み取り専用 runtime probe。
//!
//! DLL や export の存在だけでは対応と判定しない。`Experimental_QuerySandboxSupport` がある
//! build では capability bit を問い合わせ、無い過渡期 build では create API を「必ず失敗する
//! 引数」で呼び、`ERROR_CALL_NOT_IMPLEMENTED` / `E_NOTIMPL` とそれ以外を区別する。
//! 子プロセスは起動せず、ホスト DACL も変更しない。

use std::ffi::c_void;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_CALL_NOT_IMPLEMENTED, E_NOTIMPL, HMODULE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};

const SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX: u64 = 0x1;

type QuerySandboxSupport = unsafe extern "system" fn(*mut u64) -> i32;
type CreateProcessInSandbox = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const u16,
    *const STARTUPINFOW,
    *const u16,
    *const u8,
    u32,
    *mut PROCESS_INFORMATION,
) -> i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePathPolicyVerdict {
    /// runtime が SBOX create contract の有効化を明示した、または query の無い過渡期APIが
    /// `CALL_NOT_IMPLEMENTED`以外を返した。実験APIなので、これだけで本番選択はしない。
    RuntimeContractAvailable,
    /// export はあるが runtime capability が無効。
    RuntimeContractDisabled,
    /// processmodel.dll または create export が無い。
    ApiUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePathPolicyProbe {
    pub windows_build: Option<u32>,
    pub verdict: NativePathPolicyVerdict,
    pub create_export_present: bool,
    pub query_export_present: bool,
    pub query_succeeded: bool,
    pub sandbox_capabilities: Option<u64>,
    /// PSEC は3 exportの存在だけを報告する。最小specを実際に create/close できることまで
    /// 検証しない限り、これを `verdict` の根拠にしない。
    pub psec_exports_complete: bool,
    pub detail: String,
}

/// OS ネイティブ・パス制御の候補 contract を副作用無しで調べる。
pub fn probe_native_path_policy() -> NativePathPolicyProbe {
    let windows_build = exact_windows_build();
    let Some(module) = load_system32_dll("processmodel.dll") else {
        return NativePathPolicyProbe {
            windows_build,
            verdict: NativePathPolicyVerdict::ApiUnavailable,
            create_export_present: false,
            query_export_present: false,
            query_succeeded: false,
            sandbox_capabilities: None,
            psec_exports_complete: false,
            detail: "processmodel.dll could not be loaded from System32".to_string(),
        };
    };

    let create = get_proc(module, b"Experimental_CreateProcessInSandbox\0");
    let query = get_proc(module, b"Experimental_QuerySandboxSupport\0");
    let psec_exports_complete = [
        b"CreateProcessSecurityEnvironment\0".as_slice(),
        b"QueryProcessSecurityEnvironmentSupport\0".as_slice(),
        b"CloseProcessSecurityEnvironment\0".as_slice(),
    ]
    .iter()
    .all(|name| get_proc(module, name).is_some());

    let (verdict, query_succeeded, capabilities, detail) = match (create, query) {
        (None, _) => (
            NativePathPolicyVerdict::ApiUnavailable,
            false,
            None,
            "Experimental_CreateProcessInSandbox is not exported".to_string(),
        ),
        (Some(_), Some(query)) => {
            // SAFETY: export名とMicrosoft公開contractのsignatureを一致させ、out-paramは有効。
            let query: QuerySandboxSupport = unsafe { std::mem::transmute(query) };
            let mut capabilities = 0u64;
            let ok = unsafe { query(&mut capabilities) };
            if ok != 0 {
                let available = capabilities & SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX != 0;
                (
                    if available {
                        NativePathPolicyVerdict::RuntimeContractAvailable
                    } else {
                        NativePathPolicyVerdict::RuntimeContractDisabled
                    },
                    true,
                    Some(capabilities),
                    format!(
                        "Experimental_QuerySandboxSupport returned capabilities=0x{capabilities:016x}"
                    ),
                )
            } else {
                probe_legacy_create(create.unwrap(), "support query failed; ")
            }
        }
        (Some(create), None) => probe_legacy_create(create, "support query is not exported; "),
    };

    // processmodel.dll は小さなruntime probeの間だけでなく、将来このcontractでspawnする間も
    // 関数ポインタの生存元になる。MXCと同じくプロセス寿命までloadしたままにする。
    NativePathPolicyProbe {
        windows_build,
        verdict,
        create_export_present: create.is_some(),
        query_export_present: query.is_some(),
        query_succeeded,
        sandbox_capabilities: capabilities,
        psec_exports_complete,
        detail,
    }
}

fn probe_legacy_create(
    create: unsafe extern "system" fn() -> isize,
    detail_prefix: &str,
) -> (NativePathPolicyVerdict, bool, Option<u64>, String) {
    // SAFETY: export名と公開contractのsignatureを一致させる。全入力を無効にしているため
    // プロセスは起動せず、runtime enablementだけがエラーコードに現れる。
    let create: CreateProcessInSandbox = unsafe { std::mem::transmute(create) };
    let mut process_information = PROCESS_INFORMATION::default();
    let result = unsafe {
        create(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut process_information,
        )
    };
    let error = unsafe { GetLastError() }.0;
    let disabled = result == 0
        && (error == ERROR_CALL_NOT_IMPLEMENTED.0 || error == E_NOTIMPL.0 as u32);
    (
        if disabled {
            NativePathPolicyVerdict::RuntimeContractDisabled
        } else {
            NativePathPolicyVerdict::RuntimeContractAvailable
        },
        false,
        None,
        format!("{detail_prefix}side-effect-free create probe returned BOOL={result}, error={error}"),
    )
}

fn load_system32_dll(name: &str) -> Option<HMODULE> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        LoadLibraryExW(
            PCWSTR(wide.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        .ok()
    }
}

type RawProc = unsafe extern "system" fn() -> isize;

fn get_proc(module: HMODULE, name: &[u8]) -> Option<RawProc> {
    unsafe { GetProcAddress(module, PCSTR(name.as_ptr())) }
}

#[repr(C)]
struct RtlOsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform_id: u32,
    service_pack: [u16; 128],
}

fn exact_windows_build() -> Option<u32> {
    let module = load_system32_dll("ntdll.dll")?;
    let proc = get_proc(module, b"RtlGetVersion\0")?;
    type RtlGetVersion = unsafe extern "system" fn(*mut RtlOsVersionInfo) -> i32;
    let get_version: RtlGetVersion = unsafe { std::mem::transmute(proc) };
    let mut info = RtlOsVersionInfo {
        size: std::mem::size_of::<RtlOsVersionInfo>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform_id: 0,
        service_pack: [0; 128],
    };
    let status = unsafe { get_version(&mut info) };
    // ntdll.dll はプロセスの基礎DLLで既にload済み。取得したhandleはプロセス寿命に従う。
    (status >= 0).then_some(info.build)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_capability_bit_is_the_only_positive_query_result() {
        let available = |ok: i32, capabilities: u64| {
            ok != 0 && capabilities & SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX != 0
        };
        assert!(!available(0, SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX));
        assert!(!available(1, 0));
        assert!(available(1, SANDBOX_CAP_CREATE_PROCESS_IN_SANDBOX));
    }
}
