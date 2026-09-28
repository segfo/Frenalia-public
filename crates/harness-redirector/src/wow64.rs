//! Phase 4b: 32bit（WOW64）ターゲットへの再注入（`plans/AppContainerベース Copy-on-Write
//! ワークスペース設計書.md` §32 Phase 4b、`/dig`2026-08-02決定「エントリポイントtrap方式」）。
//!
//! Phase 4a（[`super::inject_grandchild`]）はx64→x64のみを対象とする——`CREATE_SUSPENDED`
//! 起動直後の孫プロセスに32bit kernel32が存在しないため、「自DLLを`LoadLibraryW`する
//! `CreateRemoteThread`」がそのまま使えない（32bit `LoadLibraryW`のアドレスを解決する手段が無い）。
//!
//! この問題を「WOW64ローダは走らせるがアプリコードは1命令も実行させない」トラップで解決する。
//! 孫の32bitエントリポイントを`EB FE`（`jmp $`、自己ループ）へ書き換えてから`ResumeThread`し、
//! WOW64サブシステム（64bit ntdll→wow64.dll→32bit ntdll/kernel32）の初期化だけを完走させる。
//! ローダが自転に到達した時点で32bit kernel32が確実にマップされているため、そのエクスポート
//! テーブルを手動でリモート解析して32bit `LoadLibraryW`のアドレスを求め、通常の
//! `CreateRemoteThread(LoadLibraryW)`→`CreateRemoteThread(harness_cow_init)`という
//! Phase 4aと同型の2段階注入を行う。最後にエントリポイントを復元してから
//! （呼び出し元が要求していなければ）`ResumeThread`する。
//!
//! 途中のどの段階で失敗しても孫プロセスの生成自体は拒否しない（Q6の既定動作を維持）。
//! エントリポイントを書き換えたままにしないよう、失敗時も可能な限り復元を試みる。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessWow64Information};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, ReadProcessMemory, Wow64GetThreadContext, WriteProcessMemory,
    WOW64_CONTEXT, WOW64_CONTEXT_CONTROL,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_32BIT,
};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
use windows::Win32::System::Threading::{
    CreateRemoteThread, IsWow64Process2, ResumeThread, SuspendThread,
};

use super::debug_log;

/// 孫プロセスが実際にWOW64（x64ホスト上のx86ターゲット）かどうかを判定する。判定できない場合は
/// 安全側（`false`＝Phase 4b経路には入らない、通常のPhase 4a経路が失敗して警告台帳に落ちる）。
pub(crate) unsafe fn is_wow64_target(process: HANDLE) -> bool {
    let mut process_machine = windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE(0);
    let ok = unsafe { IsWow64Process2(process, &mut process_machine, None) };
    ok.is_ok() && process_machine == IMAGE_FILE_MACHINE_I386
}

/// 自DLL（x64、`x64_dll_path`）と同じディレクトリにある`harness_redirector_x86.dll`のパス。
/// 新しい環境変数は増やさず固定名で解決する（設計書§32 Phase 4b）。
fn x86_sibling_dll_path(x64_dll_path: &Path) -> Option<PathBuf> {
    Some(x64_dll_path.parent()?.join("harness_redirector_x86.dll"))
}

unsafe fn read_remote_bytes(process: HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut read),
        )
    };
    if ok.is_err() || read != len {
        return None;
    }
    Some(buf)
}

fn u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn u16_at(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

/// エクスポート探索の結果。フォワーダ（他DLLへの転送エクスポート）は文字列のまま返し、
/// 呼び出し元が対象DLLを解決してから再帰する。
enum ExportLookup {
    Rva(u32),
    Forward(String),
}

/// PE32エクスポートディレクトリから`export_name`（大文字小文字区別・完全一致）を探す。
/// `reader`は「RVA相対のオフセットからバイト列を読む」抽象で、呼び出し元がリモートプロセス
/// メモリ（`image_base + rva`が実アドレスと一致する、実行のためロードされたイメージ）または
/// ファイル上のバイト列（RVA→ファイルオフセット変換が別途必要、[`parse_pe32_file_export_rva`]
/// 参照）のいずれかを渡す。
fn find_export(
    reader: &dyn Fn(u32, usize) -> Option<Vec<u8>>,
    export_name: &str,
) -> Option<ExportLookup> {
    let dos = reader(0, 0x40)?;
    let e_lfanew = u32_at(&dos, 0x3C)?;
    let nt = reader(e_lfanew, 128)?;
    if u32_at(&nt, 0)? != 0x0000_4550 {
        // "PE\0\0"
        return None;
    }
    let export_dir_rva = u32_at(&nt, 120)?;
    let export_dir_size = u32_at(&nt, 124)?;
    if export_dir_rva == 0 {
        return None;
    }
    let dir = reader(export_dir_rva, 40)?;
    let number_of_names = u32_at(&dir, 24)?;
    let addr_of_functions = u32_at(&dir, 28)?;
    let addr_of_names = u32_at(&dir, 32)?;
    let addr_of_name_ordinals = u32_at(&dir, 36)?;

    for i in 0..number_of_names {
        let name_rva = u32_at(&reader(addr_of_names + i * 4, 4)?, 0)?;
        let raw = reader(name_rva, 256)?;
        let end = raw.iter().position(|&b| b == 0)?;
        if raw[..end] != *export_name.as_bytes() {
            continue;
        }
        let ordinal = u16_at(&reader(addr_of_name_ordinals + i * 2, 2)?, 0)? as u32;
        let func_rva = u32_at(&reader(addr_of_functions + ordinal * 4, 4)?, 0)?;
        if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
            let fwd_raw = reader(func_rva, 256)?;
            let fwd_end = fwd_raw.iter().position(|&b| b == 0)?;
            return Some(ExportLookup::Forward(
                String::from_utf8_lossy(&fwd_raw[..fwd_end]).into_owned(),
            ));
        }
        return Some(ExportLookup::Rva(func_rva));
    }
    None
}

/// [`find_export`]をリモートプロセスメモリ向けに使う（`image_base + rva`が実行中イメージの
/// 実アドレスと一致するため、ファイルオフセット変換は不要）。
unsafe fn find_export_remote(
    process: HANDLE,
    image_base: usize,
    export_name: &str,
) -> Option<ExportLookup> {
    let reader = |rva: u32, len: usize| -> Option<Vec<u8>> {
        unsafe { read_remote_bytes(process, image_base + rva as usize, len) }
    };
    find_export(&reader, export_name)
}

/// フォワーダ（`"KERNELBASE.LoadLibraryW"`形式）を`modules`（`(base, ファイル名小文字)`の
/// リスト）で解決しながら、`module_base`から`export_name`の絶対アドレスを求める。
/// 循環を避けるため深さを制限する。
unsafe fn resolve_remote_export(
    process: HANDLE,
    module_base: usize,
    export_name: &str,
    modules: &[(usize, String)],
    depth: u32,
) -> Option<usize> {
    if depth > 4 {
        return None;
    }
    match unsafe { find_export_remote(process, module_base, export_name) }? {
        ExportLookup::Rva(rva) => Some(module_base + rva as usize),
        ExportLookup::Forward(fwd) => {
            let (dll_part, func_part) = fwd.split_once('.')?;
            let mut dll_lower = dll_part.to_ascii_lowercase();
            if !dll_lower.ends_with(".dll") {
                dll_lower.push_str(".dll");
            }
            let target_base = modules
                .iter()
                .find(|(_, name)| name.ends_with(&dll_lower))
                .map(|(base, _)| *base)?;
            unsafe { resolve_remote_export(process, target_base, func_part, modules, depth + 1) }
        }
    }
}

/// `<process>`内の32bitモジュール一覧を`(ベースアドレス, フルパス小文字)`として返す
/// （`super::find_remote_module_base`のx64専用版と同型だが、`LIST_MODULES_32BIT`固定＆
/// 全件返却）。
unsafe fn enum_remote_modules_32(process: HANDLE) -> Vec<(usize, String)> {
    let mut modules = vec![HMODULE::default(); 256];
    let mut needed: u32 = 0;
    let ok = unsafe {
        EnumProcessModulesEx(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_32BIT,
        )
    };
    if ok.is_err() {
        return Vec::new();
    }
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
    let mut out = Vec::with_capacity(count);
    for m in &modules[..count] {
        let mut buf = [0u16; 512];
        let len = unsafe { GetModuleFileNameExW(process, *m, &mut buf) };
        if len == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase();
        out.push((m.0 as usize, name));
    }
    out
}

/// `process`の32bit PEB（`ProcessWow64Information`）からImageBase・PEヘッダを読み、
/// `AddressOfEntryPoint`の実アドレス（RVAではなく`image_base + rva`）を返す。
unsafe fn remote_wow64_image_base_and_entry(process: HANDLE) -> Option<(usize, usize)> {
    let mut peb32_addr: usize = 0;
    let mut return_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            ProcessWow64Information,
            &mut peb32_addr as *mut usize as *mut c_void,
            std::mem::size_of::<usize>() as u32,
            &mut return_len,
        )
    };
    if status.is_err() || peb32_addr == 0 {
        debug_log(&format!(
            "wow64: NtQueryInformationProcess(ProcessWow64Information) failed or peb32=0, \
             status={status:?}"
        ));
        return None;
    }
    // PEB32.ImageBaseAddressはオフセット0x08（32bit PEBの固定レイアウト、広く文書化されている）。
    let image_base_bytes = unsafe { read_remote_bytes(process, peb32_addr + 0x08, 4)? };
    let image_base = u32_at(&image_base_bytes, 0)? as usize;
    if image_base == 0 {
        return None;
    }
    let dos = unsafe { read_remote_bytes(process, image_base, 0x40)? };
    let e_lfanew = u32_at(&dos, 0x3C)? as usize;
    let nt = unsafe { read_remote_bytes(process, image_base + e_lfanew, 128)? };
    if u32_at(&nt, 0)? != 0x0000_4550 {
        return None;
    }
    let entry_rva = u32_at(&nt, 40)? as usize;
    Some((image_base, image_base + entry_rva))
}

/// ファイル上（実行前）のx86 DLLバイト列から、RVA→ファイルオフセット変換込みで
/// `export_name`のRVAを求める。孫プロセスへ実際に注入する前に、ローカルで安全にオフラインで
/// 求められる（プロセスを起動・実行することなく`harness_cow_init`のRVAを得るため）。
fn parse_pe32_file_export_rva(bytes: &[u8], export_name: &str) -> Option<u32> {
    let e_lfanew = u32_at(bytes, 0x3C)? as usize;
    let nt = bytes.get(e_lfanew..)?;
    if u32_at(nt, 0)? != 0x0000_4550 {
        return None;
    }
    let size_of_headers = u32_at(nt, 60)?;
    let number_of_sections = u16_at(nt, 6)? as usize;
    let size_of_optional_header = u16_at(nt, 20)? as usize;
    let section_table_off = e_lfanew + 24 + size_of_optional_header;

    let mut sections: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(number_of_sections);
    for i in 0..number_of_sections {
        let off = section_table_off + i * 40;
        let sec = bytes.get(off..off + 40)?;
        let virtual_size = u32_at(sec, 8)?;
        let virtual_address = u32_at(sec, 12)?;
        let size_of_raw_data = u32_at(sec, 16)?;
        let pointer_to_raw_data = u32_at(sec, 20)?;
        sections.push((
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
        ));
    }

    let rva_to_offset = |rva: u32| -> Option<usize> {
        if rva < size_of_headers {
            return Some(rva as usize);
        }
        for &(va, vsize, raw_ptr, raw_size) in &sections {
            let span = vsize.max(raw_size);
            if rva >= va && rva < va + span {
                return Some((raw_ptr + (rva - va)) as usize);
            }
        }
        None
    };

    let reader = |rva: u32, len: usize| -> Option<Vec<u8>> {
        let off = rva_to_offset(rva)?;
        bytes.get(off..off + len).map(|b| b.to_vec())
    };

    match find_export(&reader, export_name)? {
        ExportLookup::Rva(rva) => Some(rva),
        ExportLookup::Forward(_) => None, // 自DLLのエクスポートがフォワーダのはずがない
    }
}

/// エントリポイントの2バイトを退避して`EB FE`（`jmp $`）へ書き換える。戻り値は退避した
/// 元バイト列（復元用）。
unsafe fn patch_entry_trap(process: HANDLE, entry_va: usize) -> Option<[u8; 2]> {
    let original = unsafe { read_remote_bytes(process, entry_va, 2)? };
    let original: [u8; 2] = original.try_into().ok()?;

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let protect_ok = unsafe {
        VirtualProtectEx(
            process,
            entry_va as *const c_void,
            2,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if protect_ok.is_err() {
        debug_log("wow64: VirtualProtectEx(entry point, RWX) failed");
        return None;
    }

    let trap: [u8; 2] = [0xEB, 0xFE];
    let write_ok = unsafe {
        WriteProcessMemory(
            process,
            entry_va as *mut c_void,
            trap.as_ptr() as *const c_void,
            2,
            None,
        )
    };
    // 保護は元に戻す（成否に関わらずベストエフォート、失敗しても実害は小さい——後続の
    // エントリポイント復元でも同じ保護変更を行うため）。
    unsafe {
        let _ = VirtualProtectEx(
            process,
            entry_va as *const c_void,
            2,
            old_protect,
            &mut old_protect,
        );
    }
    if write_ok.is_err() {
        debug_log("wow64: WriteProcessMemory(entry trap) failed");
        return None;
    }
    let _ = unsafe { FlushInstructionCache(process, Some(entry_va as *const c_void), 2) };
    Some(original)
}

/// [`patch_entry_trap`]で退避した元バイト列をエントリポイントへ書き戻す。
unsafe fn restore_entry_trap(process: HANDLE, entry_va: usize, original: [u8; 2]) {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let protect_ok = unsafe {
        VirtualProtectEx(
            process,
            entry_va as *const c_void,
            2,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if protect_ok.is_err() {
        debug_log("wow64: VirtualProtectEx(entry point restore, RWX) failed");
        return;
    }
    let _ = unsafe {
        WriteProcessMemory(
            process,
            entry_va as *mut c_void,
            original.as_ptr() as *const c_void,
            2,
            None,
        )
    };
    unsafe {
        let _ = VirtualProtectEx(
            process,
            entry_va as *const c_void,
            2,
            old_protect,
            &mut old_protect,
        );
    }
    let _ = unsafe { FlushInstructionCache(process, Some(entry_va as *const c_void), 2) };
}

/// `Wow64GetThreadContext`でEIPを読む（自転に到達した＝WOW64ローダの初期化が完走した
/// 確定的な証拠として使う、[`wait_for_wow64_loader_ready`]参照）。
unsafe fn wow64_thread_eip(thread: HANDLE) -> Option<u32> {
    let mut ctx = WOW64_CONTEXT {
        ContextFlags: WOW64_CONTEXT_CONTROL,
        ..unsafe { std::mem::zeroed() }
    };
    let ok = unsafe { Wow64GetThreadContext(thread, &mut ctx) };
    if ok.is_err() {
        return None;
    }
    Some(ctx.Eip)
}

/// エントリトラップ設置後、WOW64ローダが自転（トラップへ到達）するまでポーリングする。
/// 32bit kernel32のマップと、`Wow64GetThreadContext`によるEIP一致の両方を確認して確定させる
/// （`/dig`2026-08-02決定）。既存のリモートスレッド待ちと同じ5秒を基準にする。
unsafe fn wait_for_wow64_loader_ready(process: HANDLE, thread: HANDLE, entry_va: usize) -> bool {
    for _ in 0..50 {
        if let Some(eip) = unsafe { wow64_thread_eip(thread) } {
            if eip as usize == entry_va {
                let modules = unsafe { enum_remote_modules_32(process) };
                if modules
                    .iter()
                    .any(|(_, name)| name.ends_with("kernel32.dll"))
                {
                    return true;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// 自DLL（x86版）のパス文字列を孫プロセスへ書き込み、`load_library_addr`を開始アドレスとする
/// `CreateRemoteThread`でロードさせる（Phase 4aの`inject_grandchild`ステップ①と同型）。
unsafe fn remote_load_library(process: HANDLE, load_library_addr: usize, dll_path: &Path) -> bool {
    let path_w: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
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
        debug_log("wow64: VirtualAllocEx(dll path) failed");
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
        debug_log("wow64: WriteProcessMemory(dll path) failed");
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    }
    let start: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(
            load_library_addr,
        )
    });
    let mut tid: u32 = 0;
    let thread =
        unsafe { CreateRemoteThread(process, None, 0, start, Some(remote_buf), 0, Some(&mut tid)) };
    let Ok(thread) = thread else {
        debug_log(&format!(
            "wow64: CreateRemoteThread(LoadLibraryW) failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return false;
    };
    let end = unsafe { super::wait_remote_thread(thread) };
    if end.may_free_remote_memory() {
        unsafe {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
    }
    debug_log(&format!("wow64: LoadLibraryW end={end:?}"));
    end.succeeded()
}

/// `cfg`はBUG-045のF2で追加した設定引き渡し。32bit孫のenv blockに依存せず設定を届けるため、
/// [`super::write_remote_config_blob`]で書き込んだブロブのアドレスをスレッドパラメータに渡す
/// （`VirtualAllocEx`はWOW64プロセスに対して4GB未満のアドレスを返すため32bit側で正しく読める）。
unsafe fn remote_call_init(process: HANDLE, init_addr: usize, cfg: &super::Config) -> bool {
    let start: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(init_addr)
    });
    let config_blob = unsafe { super::write_remote_config_blob(process, cfg) };
    let mut tid: u32 = 0;
    let thread = unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            start,
            config_blob.map(|p| p as *const c_void),
            0,
            Some(&mut tid),
        )
    };
    let Ok(thread) = thread else {
        debug_log(&format!(
            "wow64: CreateRemoteThread(harness_cow_init) failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        if let Some(buf) = config_blob {
            unsafe {
                let _ = VirtualFreeEx(process, buf, 0, MEM_RELEASE);
            }
        }
        return false;
    };
    let end = unsafe { super::wait_remote_thread(thread) };
    if let (Some(buf), true) = (config_blob, end.may_free_remote_memory()) {
        unsafe {
            let _ = VirtualFreeEx(process, buf, 0, MEM_RELEASE);
        }
    }
    debug_log(&format!("wow64: harness_cow_init end={end:?}"));
    end.succeeded()
}

/// Phase 4b本体。`process`/`thread`はまだSUSPENDEDのWOW64孫。`x64_dll_path`は自DLL（x64）の
/// パスで、ここから兄弟の`harness_redirector_x86.dll`を導出する。成功したら`true`。
pub(crate) unsafe fn inject_grandchild_wow64(
    process: HANDLE,
    thread: HANDLE,
    x64_dll_path: &Path,
    cfg: &super::Config,
) -> bool {
    debug_log("wow64: inject_grandchild_wow64 enter");
    let Some((image_base, entry_va)) = (unsafe { remote_wow64_image_base_and_entry(process) })
    else {
        debug_log("wow64: remote_wow64_image_base_and_entry failed");
        return false;
    };
    debug_log(&format!(
        "wow64: image_base={image_base:#x} entry_va={entry_va:#x}"
    ));

    let Some(original_bytes) = (unsafe { patch_entry_trap(process, entry_va) }) else {
        debug_log("wow64: patch_entry_trap failed");
        return false;
    };

    unsafe {
        let _ = ResumeThread(thread);
    }

    let loader_ready = unsafe { wait_for_wow64_loader_ready(process, thread, entry_va) };
    // 呼び出し元（`inject_grandchild_and_maybe_resume`）の`caller_wanted_suspended`分岐が
    // 唯一の`ResumeThread`地点であるという不変条件（Phase 4aのx64経路と同じ）を保つため、
    // ローダ待ちの成否に関わらずここで必ず`SuspendThread`し、呼び出し元へ戻る時点の
    // suspendカウントをこの関数呼び出し前と一致させる（呼び出し元は最初から
    // `CREATE_SUSPENDED`で作っているため、ここで1、戻った後の条件付き`ResumeThread`で0）。
    unsafe {
        let _ = SuspendThread(thread);
    }
    if !loader_ready {
        debug_log("wow64: wait_for_wow64_loader_ready timed out");
        unsafe {
            restore_entry_trap(process, entry_va, original_bytes);
        }
        return false;
    }
    debug_log("wow64: loader ready (spinning at entry trap)");

    // ここから先で失敗しても、必ずエントリポイントを復元してから抜ける（success変数で追跡）。
    let success = (|| -> bool {
        let modules = unsafe { enum_remote_modules_32(process) };
        let Some(&(kernel32_base, _)) = modules
            .iter()
            .find(|(_, name)| name.ends_with("kernel32.dll"))
        else {
            debug_log("wow64: kernel32.dll not found in remote 32bit module list");
            return false;
        };
        let Some(load_library_addr) =
            (unsafe { resolve_remote_export(process, kernel32_base, "LoadLibraryW", &modules, 0) })
        else {
            debug_log("wow64: resolve_remote_export(LoadLibraryW) failed");
            return false;
        };

        let Some(x86_dll_path) = x86_sibling_dll_path(x64_dll_path) else {
            debug_log("wow64: x86_sibling_dll_path failed");
            return false;
        };
        if !x86_dll_path.exists() {
            debug_log(&format!(
                "wow64: x86 redirector dll not found at {} (Phase 4b requires building it \
                 separately, cargo build -p harness-redirector --target i686-pc-windows-msvc)",
                x86_dll_path.display()
            ));
            return false;
        }
        let Ok(x86_dll_bytes) = std::fs::read(&x86_dll_path) else {
            debug_log("wow64: failed to read x86 redirector dll from disk");
            return false;
        };
        let Some(init_rva) = parse_pe32_file_export_rva(&x86_dll_bytes, "harness_cow_init") else {
            debug_log("wow64: parse_pe32_file_export_rva(harness_cow_init) failed");
            return false;
        };

        if !unsafe { remote_load_library(process, load_library_addr, &x86_dll_path) } {
            debug_log("wow64: remote_load_library failed");
            return false;
        }

        let modules_after = unsafe { enum_remote_modules_32(process) };
        let dll_path_lc = x86_dll_path.to_string_lossy().to_ascii_lowercase();
        let Some(&(remote_dll_base, _)) =
            modules_after.iter().find(|(_, name)| *name == dll_path_lc)
        else {
            debug_log("wow64: x86 redirector dll not found in remote module list after load");
            return false;
        };
        let init_addr = remote_dll_base + init_rva as usize;
        unsafe { remote_call_init(process, init_addr, cfg) }
    })();

    unsafe {
        restore_entry_trap(process, entry_va, original_bytes);
    }
    debug_log(&format!("wow64: inject_grandchild_wow64 result={success}"));
    success
}
