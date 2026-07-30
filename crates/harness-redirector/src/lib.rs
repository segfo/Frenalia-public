//! Tier2a `--cow`（D-30）のRedirector DLL。x64専用・最小スコープ（`NtCreateFile`/`NtOpenFile`のみ）。
//!
//! `plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §13-§19の最小サブセット。
//! `ntdll.dll`の`NtCreateFile`/`NtOpenFile`をinline hook（`retour`クレート、フックの実装品質は
//! セキュリティ保証に影響しない——§13.1の実装方針参照）し、workspace配下への書込操作を
//! CoW upperディレクトリへ誘導する。
//!
//! **境界ではなく誘導**（`plans/DESIGN-SANDBOX.md` D-01/D-30）: このDLLが無効化・回避・
//! アンロードされても、workspace本体はAppContainerのACLでread-only付与済みのため、書込は
//! `STATUS_ACCESS_DENIED`でfail-closeする。このDLLの役割は、フックが機能する場合に
//! `ACCESS_DENIED`を回避してCoW upperへ書けるようにする「利便性」のみ。
//!
//! 設定は環境変数で受け取る（Launcher=`win_appcontainer::spawn_impl`が子のenv blockへ設定、
//! `CreateProcessW`はsuspended起動のためプロセス作成時点でPEBのEnvironmentは既に確定しており、
//! メインスレッド再開前でも`GetEnvironmentVariableW`で読める）。
//!
//! * `HARNESS_COW_WORKSPACE`: workspaceルート（NTパス正規化前、DOS形式）。
//! * `HARNESS_COW_UPPER`: CoW upperディレクトリ（DOS形式）。
//! * `HARNESS_COW_READY_HANDLE`: 初期化完了を知らせるパイプ書込端の継承ハンドル値（10進文字列）。
//!   Launcherが`CREATE_SUSPENDED`起動直後に`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`で子へ継承させ、
//!   `ReadFile`でこのDLLが1バイト書き込むのを待ってから`ResumeThread`する（設計書§10.2、
//!   `win_appcontainer.rs`の`wait_cow_ready`/`appcontainer_pipe`参照。AppContainer子から
//!   名前付きカーネルオブジェクトを触るには別途ACL構成が要るため、package SIDへの
//!   ACL付与が既に済んでいる既存のパイプ生成経路を再利用している）。

#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use retour::GenericDetour;
use windows::core::PCWSTR;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};

/// `retour`が要求する生のNt関数シグネチャ。`windows`クレートの`Wdk`ラッパは実体が
/// `windows_targets::link!`経由のIAT呼び出しであり、ここでフックする対象（`ntdll.dll`の
/// エクスポート本体、`GetProcAddress`で取得したアドレス）とは別物。ABIが一致する生の
/// 関数ポインタ型として定義し直し、`GetProcAddress`のアドレスをこの型へtransmuteして使う。
type NtCreateFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    FILE_ACCESS_RIGHTS,
    *const OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    *const i64,
    FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE,
    NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS,
    *const c_void,
    u32,
) -> NTSTATUS;

type NtOpenFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    u32,
    u32,
) -> NTSTATUS;

struct Config {
    workspace_root: PathBuf,
    upper_dir: PathBuf,
}

static CONFIG: OnceLock<Config> = OnceLock::new();
static CREATE_FILE_HOOK: OnceLock<GenericDetour<NtCreateFileFn>> = OnceLock::new();
static OPEN_FILE_HOOK: OnceLock<GenericDetour<NtOpenFileFn>> = OnceLock::new();

fn get_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// `OBJECT_ATTRIBUTES.ObjectName`（`UNICODE_STRING`、UTF-16・非NUL終端）をRustの`String`へ。
/// `RootDirectory`が`Some`（相対open）の場合は、このDLLの最小スコープでは解決せず
/// `None`を返す（相対openはworkspace外判定ができないため素通しする、§16「非対応パス形は
/// 安全側で素通し」の割り切り）。
unsafe fn object_attributes_path(oa: *const OBJECT_ATTRIBUTES) -> Option<PathBuf> {
    if oa.is_null() {
        return None;
    }
    let oa = unsafe { &*oa };
    if !oa.RootDirectory.is_invalid() && oa.RootDirectory.0 as isize != 0 {
        return None;
    }
    let name_ptr = oa.ObjectName;
    if name_ptr.is_null() {
        return None;
    }
    let us = unsafe { &*name_ptr };
    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }
    let len_u16 = (us.Length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) };
    let raw = String::from_utf16_lossy(slice);
    // NTパスプレフィックス（`\??\`＝DOSデバイスパス, `\\?\`は通常Win32層でしか現れないが
    // 念のため対応）を剥がしてDOS形式へ正規化する（§16の最小サブセット）。
    let stripped = raw
        .strip_prefix(r"\??\")
        .or_else(|| raw.strip_prefix(r"\\?\"))
        .unwrap_or(&raw);
    Some(PathBuf::from(stripped))
}

/// `desired_access`/`create_disposition`から「変更操作か」を判定する（設計書§15の最小
/// サブセット）。`GENERIC_WRITE`の有無だけで判定しない——DELETE単体・APPEND単体も
/// 変更操作として扱う。`create_disposition`は`NtCreateFile`のみが持つ（`NtOpenFile`は
/// 常に`FILE_OPEN`相当のため`None`を渡す）。
fn is_write_intent(desired_access: u32, create_disposition: Option<u32>) -> bool {
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;

    let write_mask = FILE_GENERIC_WRITE.0
        | FILE_WRITE_DATA.0
        | FILE_APPEND_DATA.0
        | FILE_WRITE_ATTRIBUTES.0
        | FILE_WRITE_EA.0
        | windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS(0x0001_0000).0 // DELETE
        ;
    if desired_access & write_mask != 0 {
        return true;
    }
    matches!(
        create_disposition,
        Some(FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF)
    )
}

/// `path`（DOS形式、絶対パス）がworkspace配下かどうかをコンポーネント単位で判定する
/// （§16「単純な前方一致は禁止」）。upper_dir配下は絶対に対象外とする（誤って
/// upperをworkspaceとして再変換すると無限リダイレクトになる、設計書§9）。
fn classify(cfg: &Config, path: &Path) -> Option<PathBuf> {
    let path_lc = path.to_string_lossy().to_ascii_lowercase();
    let upper_lc = cfg.upper_dir.to_string_lossy().to_ascii_lowercase();
    if path_lc.starts_with(&upper_lc) {
        return None;
    }
    let ws_lc = cfg.workspace_root.to_string_lossy().to_ascii_lowercase();
    let is_under_workspace = path_lc == ws_lc
        || (path_lc.starts_with(&ws_lc)
            && path_lc.as_bytes().get(ws_lc.len()) == Some(&b'\\'));
    if !is_under_workspace {
        return None;
    }
    let rel = path
        .strip_prefix(&cfg.workspace_root)
        .ok()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    Some(cfg.upper_dir.join(&rel))
}

/// copy-up（設計書§18の最小サブセット、一時ファイル+原子renameは省略——初期実装として
/// 単純上書きコピーを採用する。並行copy-upの競合は許容し、後勝ちで構わない
/// スコープに留める）。
fn copy_up(workspace_path: &Path, upper_path: &Path) {
    if upper_path.exists() {
        return;
    }
    if let Some(parent) = upper_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if workspace_path.is_file() {
        let _ = std::fs::copy(workspace_path, upper_path);
    }
}

// `copy_up`（`std::fs::copy`/`create_dir_all`）はWin32のCreateFileW等を経由するため、
// パッチ済みの`ntdll!NtCreateFile`/`NtOpenFile`を通って自分自身のフック関数へ再入する
// （このDLLだけでなくプロセス内の全呼び出し元がパッチ済みの実体を叩くため、フック関数の内部から
// 発行したファイルI/Oも同じフック関数へ戻ってくる）。`classify`はupper_dir配下を除外するため
// 単純な無限ループにはならない設計だったが、実機検証でスタックオーバーフローを確認した
// （再帰の呼び出し系列は未特定）。分類・copy-upロジックはスレッドごとに一度だけ働けばよく、
// 再入時は素通し（元のcopy-up呼び出しが要求した実パスをそのまま使わせる）が正しい振る舞いのため、
// スレッドローカルな再入ガードで内側の分類・copy-upロジックを止める。
thread_local! {
    static IN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct ReentryGuard;

impl ReentryGuard {
    fn try_acquire() -> Option<Self> {
        IN_HOOK.with(|f| {
            if f.get() {
                None
            } else {
                f.set(true);
                Some(ReentryGuard)
            }
        })
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        IN_HOOK.with(|f| f.set(false));
    }
}

/// `upper_path`（DOS形式の絶対パス）を、NT名前空間で有効な`\??\`プレフィックス付きUTF-16
/// （NUL終端込み）へ変換する。`object_attributes_path`は読み取り時に`\??\`/`\\?\`を剥がして
/// DOS形式へ正規化するが、書き戻すNT-levelの`ObjectName`は逆にNTデバイス名前空間の完全パス
/// （`\??\`プレフィックス）が必須——プレフィックス無しのDOSパスをそのまま渡すと
/// `NtCreateFile`から見て不正な名前になり`STATUS_OBJECT_NAME_INVALID`（「指定されたパスは
/// 無効です」）で失敗する（実機検証で確認）。
fn nt_path_wide(upper_path: &Path) -> Vec<u16> {
    let nt_path = format!(r"\??\{}", upper_path.to_string_lossy());
    nt_path.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe extern "system" fn hooked_nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: FILE_ACCESS_RIGHTS,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *const i64,
    file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    share_access: FILE_SHARE_MODE,
    create_disposition: NTCREATEFILE_CREATE_DISPOSITION,
    create_options: NTCREATEFILE_CREATE_OPTIONS,
    ea_buffer: *const c_void,
    ea_length: u32,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let (Some(cfg), Some(path)) = (
            CONFIG.get(),
            unsafe { object_attributes_path(object_attributes) },
        ) {
            if is_write_intent(desired_access.0, Some(create_disposition.0)) {
                if let Some(upper_path) = classify(cfg, &path) {
                    copy_up(&path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let mut redirected_oa = unsafe { *object_attributes };
                    let mut redirected_name = windows::Win32::Foundation::UNICODE_STRING {
                        Length: ((upper_wide.len() - 1) * 2) as u16,
                        MaximumLength: (upper_wide.len() * 2) as u16,
                        Buffer: windows::core::PWSTR(upper_wide.as_ptr() as *mut u16),
                    };
                    redirected_oa.ObjectName = &mut redirected_name;
                    redirected_oa.RootDirectory = HANDLE::default();
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    return unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                    };
                }
            }
        }
    }

    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        )
    }
}

unsafe extern "system" fn hooked_nt_open_file(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    // `NtOpenFile`はcreate dispositionを取らない（常に`FILE_OPEN`相当）ため、write intentは
    // desired_accessのみで判定する。既存ファイルの書込open（copy-up要）が主な対象。
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let (Some(cfg), Some(path)) = (
            CONFIG.get(),
            unsafe { object_attributes_path(object_attributes) },
        ) {
            if is_write_intent(desired_access, None) {
                if let Some(upper_path) = classify(cfg, &path) {
                    copy_up(&path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let mut redirected_oa = unsafe { *object_attributes };
                    let mut redirected_name = windows::Win32::Foundation::UNICODE_STRING {
                        Length: ((upper_wide.len() - 1) * 2) as u16,
                        MaximumLength: (upper_wide.len() * 2) as u16,
                        Buffer: windows::core::PWSTR(upper_wide.as_ptr() as *mut u16),
                    };
                    redirected_oa.ObjectName = &mut redirected_name;
                    redirected_oa.RootDirectory = HANDLE::default();
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    return unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                }
            }
        }
    }

    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options,
        )
    }
}

unsafe fn resolve_ntdll_export(name: &str) -> Option<*const c_void> {
    let module_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(PCWSTR(module_name.as_ptr())) }.ok()?;
    let name_c = format!("{name}\0");
    let addr = unsafe {
        GetProcAddress(
            module,
            windows::core::PCSTR(name_c.as_ptr()),
        )
    }?;
    Some(addr as *const c_void)
}

/// フック設置本体（`DllMain`からは呼ばない、Loader Lock回避のため専用スレッドから呼ぶ、
/// 設計書§13.4）。設定を読み・フックを設置し、成功したら`HARNESS_COW_READY_EVENT`へ
/// シグナルする。失敗時はシグナルしない——Launcher側は待機タイムアウトでプロセスを
/// 終了する（設計書§10.2 既定・§25.1）。
fn init() {
    let workspace_root = match get_env("HARNESS_COW_WORKSPACE") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    let upper_dir = match get_env("HARNESS_COW_UPPER") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    let _ = CONFIG.set(Config {
        workspace_root,
        upper_dir,
    });

    let create_file_addr = match unsafe { resolve_ntdll_export("NtCreateFile") } {
        Some(a) => a,
        None => return,
    };
    let open_file_addr = match unsafe { resolve_ntdll_export("NtOpenFile") } {
        Some(a) => a,
        None => return,
    };

    let create_file_fn: NtCreateFileFn = unsafe { std::mem::transmute(create_file_addr) };
    let open_file_fn: NtOpenFileFn = unsafe { std::mem::transmute(open_file_addr) };

    let create_detour = match unsafe { GenericDetour::new(create_file_fn, hooked_nt_create_file) }
    {
        Ok(d) => d,
        Err(_) => return,
    };
    let open_detour = match unsafe { GenericDetour::new(open_file_fn, hooked_nt_open_file) } {
        Ok(d) => d,
        Err(_) => return,
    };
    if unsafe { create_detour.enable() }.is_err() {
        return;
    }
    if unsafe { open_detour.enable() }.is_err() {
        unsafe {
            let _ = create_detour.disable();
        }
        return;
    }
    let _ = CREATE_FILE_HOOK.set(create_detour);
    let _ = OPEN_FILE_HOOK.set(open_detour);

    signal_ready();
}

/// Launcherが`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`で継承させたパイプ書込端（`HARNESS_COW_READY_HANDLE`
/// に生ハンドル値として渡される、`win_appcontainer.rs`の`appcontainer_pipe`+`wait_cow_ready`と対）へ
/// 1バイト書き込む。ハンドルのcloseはLauncher側が読み取り後に行う（`win_appcontainer.rs:1222`）ため、
/// ここでは書込のみ行い、close責務は持たない。
fn signal_ready() {
    let Some(handle_value) = get_env("HARNESS_COW_READY_HANDLE").and_then(|v| v.parse::<isize>().ok())
    else {
        return;
    };
    let handle = HANDLE(handle_value as *mut c_void);
    let buf = [1u8];
    unsafe {
        let _ = WriteFile(handle, Some(&buf), None, None);
    }
}

unsafe extern "system" fn init_thread_proc(_param: *mut c_void) -> u32 {
    init();
    0
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // Loader Lock回避（設計書§13.4）: `DllMain`内でフック設置を完結させず、専用スレッドへ
        // 委譲する。スレッド生成自体はLoader Lock下でも安全（`CreateThread`はローダを介さない）。
        unsafe {
            let _ = CreateThread(
                None,
                0,
                Some(init_thread_proc),
                None,
                THREAD_CREATION_FLAGS(0),
                None,
            );
        }
    }
    1
}
