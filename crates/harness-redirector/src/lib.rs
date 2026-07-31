//! Tier2a `--cow`（D-30）のRedirector DLL。x64専用・最小スコープ。
//!
//! `plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §13-§19。
//! `ntdll.dll`の`NtCreateFile`/`NtOpenFile`/`NtSetInformationFile`/`NtClose`をinline hook
//! （`retour`クレート、フックの実装品質はセキュリティ保証に影響しない——§13.1の実装方針参照）し、
//! workspace配下への書込操作をCoW upperディレクトリへ誘導しつつ、作成・変更・削除・リネームを
//! 操作台帳（`.harness-cow-ops.jsonl`、`crates/harness-change-ledger`）へ記録する。
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

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use harness_change_ledger::{
    hash_bytes, now_millis, parse_ledger, ChangeOp, CowOpEntry, COW_BASELINE_DIRNAME,
    COW_OPS_LEDGER_FILENAME,
};
use retour::GenericDetour;
use windows::core::PCWSTR;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileDispositionInformationEx, FileRenameInformation,
    FileRenameInformationEx, FILE_DELETE_ON_CLOSE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX, FILE_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_OBJECT_NAME_NOT_FOUND};
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

type NtSetInformationFileFn = unsafe extern "system" fn(
    HANDLE,
    *mut IO_STATUS_BLOCK,
    *const c_void,
    u32,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;

type NtCloseFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

/// `GetFileAttributesExW`（ひいては.NETの`File.Exists`/`Directory.Exists`、PowerShellの
/// `Test-Path`）が使う、ハンドルを開かない属性照会。`NtCreateFile`/`NtOpenFile`とは別経路の
/// ため、これをフックしないと論理削除済みパスの`Test-Path`が実workspace側の実体を見て
/// `True`を返してしまう（実機E2Eで発見、設計書§19.7の読み取り時判定を完全にするための追加）。
type NtQueryFullAttributesFileFn = unsafe extern "system" fn(
    *const OBJECT_ATTRIBUTES,
    *mut windows::Wdk::Storage::FileSystem::FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS;

/// `GetFileAttributesW`（`NtQueryFullAttributesFile`より軽量な照会）が使う経路。`windows`クレートは
/// 安全ラッパを提供していないため、他のNt関数と同様`GetProcAddress`のアドレスを手動定義した
/// 関数ポインタ型へtransmuteして使う。
type NtQueryAttributesFileFn = unsafe extern "system" fn(
    *const OBJECT_ATTRIBUTES,
    *mut windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION,
) -> NTSTATUS;

struct Config {
    workspace_root: PathBuf,
    upper_dir: PathBuf,
}

static CONFIG: OnceLock<Config> = OnceLock::new();
static CREATE_FILE_HOOK: OnceLock<GenericDetour<NtCreateFileFn>> = OnceLock::new();
static OPEN_FILE_HOOK: OnceLock<GenericDetour<NtOpenFileFn>> = OnceLock::new();
static SET_INFO_HOOK: OnceLock<GenericDetour<NtSetInformationFileFn>> = OnceLock::new();
static CLOSE_HOOK: OnceLock<GenericDetour<NtCloseFn>> = OnceLock::new();
static QUERY_FULL_ATTR_HOOK: OnceLock<GenericDetour<NtQueryFullAttributesFileFn>> = OnceLock::new();
static QUERY_ATTR_HOOK: OnceLock<GenericDetour<NtQueryAttributesFileFn>> = OnceLock::new();

/// ハンドル値→workspace相対パス（`/`区切り）。`NtClose`で確実に取り除く（際限なく膨らまない
/// ようにする、設計書§19.6）。
fn handle_paths() -> &'static Mutex<HashMap<isize, String>> {
    static M: OnceLock<Mutex<HashMap<isize, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 削除予定（`FileDispositionInformation`のDeleteFile=TRUE、または`FILE_DELETE_ON_CLOSE`）の
/// ハンドル集合。フラグが後から取り消されれば除去する（設計書§19.6）。
fn delete_pending() -> &'static Mutex<HashSet<isize>> {
    static S: OnceLock<Mutex<HashSet<isize>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

/// パスごとの「このセッションで最初に触った瞬間の実workspace側ハッシュ」キャッシュ
/// （`None`＝新規作成）。baselineは「セッションが触る前の姿」を意味するため、2回目以降の
/// 操作では初回に記録した値をそのまま複製する（設計書§19.5）。
fn baseline_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 現在「論理的に削除済み」のworkspace相対パス集合（設計書§19.7）。DLL初期化時に既存の
/// 台帳を再生して組み立て、以降はこのDLLがフックした操作でその都度更新する。
fn deleted_paths_state() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashSet::new()))
}

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
    strip_nt_prefix(&raw)
}

fn strip_nt_prefix(raw: &str) -> Option<PathBuf> {
    // NTパスプレフィックス（`\??\`＝DOSデバイスパス, `\\?\`は通常Win32層でしか現れないが
    // 念のため対応）を剥がしてDOS形式へ正規化する（§16の最小サブセット）。
    let stripped = raw
        .strip_prefix(r"\??\")
        .or_else(|| raw.strip_prefix(r"\\?\"))
        .unwrap_or(raw);
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

/// `create_disposition`が「対象が存在しなくても作成する」種別かどうか（`FILE_SUPERSEDE`=0・
/// `FILE_CREATE`=2・`FILE_OPEN_IF`=3・`FILE_OVERWRITE_IF`=5）。論理削除済みパスへの再作成
/// （削除の取り消し）を判定するために使う（設計書§19.7）。
fn is_create_capable_disposition(create_disposition: u32) -> bool {
    matches!(create_disposition, 0 | 2 | 3 | 5)
}

/// `path`が`upper_dir`配下でなくworkspace配下であれば、workspaceルートからの相対パスを返す。
/// upper_dir配下は絶対に対象外とする（誤ってupperをworkspaceとして再変換すると無限
/// リダイレクトになる、設計書§9）。
fn workspace_relative(cfg: &Config, path: &Path) -> Option<PathBuf> {
    let path_lc = path.to_string_lossy().to_ascii_lowercase();
    let upper_lc = cfg.upper_dir.to_string_lossy().to_ascii_lowercase();
    if path_lc.starts_with(&upper_lc) {
        return None;
    }
    let ws_lc = cfg.workspace_root.to_string_lossy().to_ascii_lowercase();
    let is_under_workspace = path_lc == ws_lc
        || (path_lc.starts_with(&ws_lc) && path_lc.as_bytes().get(ws_lc.len()) == Some(&b'\\'));
    if !is_under_workspace {
        return None;
    }
    path.strip_prefix(&cfg.workspace_root).ok().map(|p| p.to_path_buf())
}

fn rel_to_string(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// `rel`（workspace相対、`/`区切り）を、そのセッションで最初に触った瞬間の実workspace側
/// ハッシュへ解決する（キャッシュ済みならそれを返す、設計書§19.5）。
fn baseline_hash_for(cfg: &Config, rel: &str) -> Option<String> {
    let cache = baseline_cache();
    let mut guard = cache.lock().unwrap();
    if let Some(v) = guard.get(rel) {
        return v.clone();
    }
    let workspace_abs = cfg.workspace_root.join(rel.replace('/', "\\"));
    let bytes = std::fs::read(&workspace_abs).ok();
    if let Some(b) = &bytes {
        let mirror_path = cfg
            .upper_dir
            .join(COW_BASELINE_DIRNAME)
            .join(rel.replace('/', "\\"));
        if let Some(parent) = mirror_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&mirror_path, b);
    }
    let hash = bytes.as_ref().map(|b| hash_bytes(b));
    guard.insert(rel.to_string(), hash.clone());
    hash
}

/// 台帳（`<upper_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記し、メモリ上の削除済み集合も
/// 更新する。追記は`OpenOptions::append`（Windowsでは`FILE_APPEND_DATA`扱い）で行い、1レコード
/// ＝1行を1回の書込みで出す（設計書§19.2「追記の並行性」）。
fn append_ledger_entry(cfg: &Config, op: ChangeOp, rel: &str, baseline_hash: Option<String>) {
    let entry = CowOpEntry {
        op,
        path: rel.to_string(),
        baseline_hash,
        ts_unix_millis: now_millis(),
    };
    if let Ok(mut line) = serde_json::to_string(&entry) {
        line.push('\n');
        let ledger_path = cfg.upper_dir.join(COW_OPS_LEDGER_FILENAME);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&ledger_path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
    let deleted = deleted_paths_state();
    let mut g = deleted.lock().unwrap();
    match op {
        ChangeOp::Delete => {
            g.insert(rel.to_string());
        }
        ChangeOp::Create | ChangeOp::Modify => {
            g.remove(rel);
        }
    }
}

/// copy-up（設計書§18の最小サブセット、一時ファイル+原子renameは省略——初期実装として
/// 単純上書きコピーを採用する。並行copy-upの競合は許容し、後勝ちで構わない
/// スコープに留める）。実際にupperへコピー/新規作成した瞬間（冪等チェックを通過して実際に
/// 作業した瞬間）にCreate/Modifyを1件台帳へ追記する（設計書§19.6）。
fn copy_up(cfg: &Config, rel: &str, workspace_path: &Path, upper_path: &Path) {
    if upper_path.exists() {
        return;
    }
    let baseline_hash = baseline_hash_for(cfg, rel);
    if let Some(parent) = upper_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if workspace_path.is_file() {
        let _ = std::fs::copy(workspace_path, upper_path);
    }
    let op = if baseline_hash.is_some() { ChangeOp::Modify } else { ChangeOp::Create };
    append_ledger_entry(cfg, op, rel, baseline_hash);
}

// `copy_up`（`std::fs::copy`/`create_dir_all`）はWin32のCreateFileW等を経由するため、
// パッチ済みの`ntdll!NtCreateFile`/`NtOpenFile`を通って自分自身のフック関数へ再入する
// （このDLLだけでなくプロセス内の全呼び出し元がパッチ済みの実体を叩くため、フック関数の内部から
// 発行したファイルI/Oも同じフック関数へ戻ってくる）。`classify`はupper_dir配下を除外するため
// 単純な無限ループにはならない設計だったが、実機検証でスタックオーバーフローを確認した
// （再帰の呼び出し系列は未特定）。分類・copy-upロジックはスレッドごとに一度だけ働けばよく、
// 再入時は素通し（元のcopy-up呼び出しが要求した実パスをそのまま使わせる）が正しい振る舞いのため、
// スレッドローカルな再入ガードで内側の分類・copy-upロジックを止める。新設した
// `NtSetInformationFile`/`NtClose`フックの台帳I/Oもこのガードで挟む（設計書§19.6）。
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

/// `object_attributes`をupper側の完全パス（`upper_wide`、`nt_path_wide`済み）へ向け直した
/// `OBJECT_ATTRIBUTES`/`UNICODE_STRING`のペアを組み立てる。呼び出し元は両方を同じスコープで
/// 保持し（`UNICODE_STRING.Buffer`が`upper_wide`を指すため`upper_wide`自体も生存させること）、
/// `oa.ObjectName = &mut name;`してから使うこと（Rustの借用は関数境界を越えて返せないため）。
/// 書込リダイレクト・読み取りリダイレクト（read-through）・属性照会リダイレクトの4箇所で
/// 同じ組み立てが必要なため一本化した（設計書§19.6/§19.7）。
unsafe fn build_redirected_oa(
    object_attributes: *const OBJECT_ATTRIBUTES,
    upper_wide: &[u16],
) -> (OBJECT_ATTRIBUTES, windows::Win32::Foundation::UNICODE_STRING) {
    let mut redirected_oa = unsafe { *object_attributes };
    let redirected_name = windows::Win32::Foundation::UNICODE_STRING {
        Length: ((upper_wide.len() - 1) * 2) as u16,
        MaximumLength: (upper_wide.len() * 2) as u16,
        Buffer: windows::core::PWSTR(upper_wide.as_ptr() as *mut u16),
    };
    redirected_oa.RootDirectory = HANDLE::default();
    (redirected_oa, redirected_name)
}

/// `rel`（workspace相対）のupper側実体パスを返す（存在すれば）。読み取りread-through判定
/// （設計書§19.3/§19.7「削除済み＞upper＞workspace」の中間段）に使う。
fn upper_version_path(cfg: &Config, rel: &Path) -> Option<PathBuf> {
    let upper_path = cfg.upper_dir.join(rel);
    if upper_path.is_file() {
        Some(upper_path)
    } else {
        None
    }
}

/// 論理削除済み集合を確認し、必要なら書換後の`NTSTATUS`を返す（`Some`なら即returnすべき）。
/// 作成可能なdispositionでの再作成は集合から除去して`None`（通常処理へ継続）を返す。
fn check_deleted(rel: &str, allow_recreate: bool) -> Option<NTSTATUS> {
    let deleted = deleted_paths_state();
    let mut g = deleted.lock().unwrap();
    if !g.contains(rel) {
        return None;
    }
    if allow_recreate {
        g.remove(rel);
        None
    } else {
        Some(STATUS_OBJECT_NAME_NOT_FOUND)
    }
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
            if let Some(rel) = workspace_relative(cfg, &path) {
                let rel_str = rel_to_string(&rel);
                if let Some(status) =
                    check_deleted(&rel_str, is_create_capable_disposition(create_disposition.0))
                {
                    return status;
                }
                if is_write_intent(desired_access.0, Some(create_disposition.0)) {
                    let upper_path = cfg.upper_dir.join(&rel);
                    copy_up(cfg, &rel_str, &path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
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
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // 読み取りread-through（設計書§19.3/§19.7「削除済み＞upper＞workspace」の中間段）:
                // 書込意図が無い開き方（`Get-Content`等）でも、upperに版があればそちらを読ませる。
                // これが無いと「書いた直後に読み返す」操作が実workspace側（実体が無いか古い）を見て
                // 失敗する（実機E2Eで発見、既存の`cow_diagnostics`はAppContainer外から
                // `std::fs::read_to_string`で確認するだけだったため見逃されていた）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
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
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // upperにも版が無い（このセッションで一度も触っていない）場合は、これまで通り
                // ハンドル→パス対応表にだけ載せて実workspace側を読ませる（`FILE_DELETE_ON_CLOSE`
                // 無し・この時点では削除予定ではないが、NtClose側での取り除き漏れを防ぐため
                // 対応表自体には登録しておく）。
                let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
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
                };
                track_new_handle(file_handle, status, &rel_str, create_options.0);
                return status;
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

/// 呼び出しが成功していれば、生成されたハンドルをハンドル→パス対応表へ登録し、
/// `FILE_DELETE_ON_CLOSE`が立っていれば削除予定集合にも加える（設計書§19.6）。
fn track_new_handle(file_handle: *mut HANDLE, status: NTSTATUS, rel_str: &str, create_options: u32) {
    if status.is_err() {
        return;
    }
    let handle = unsafe { *file_handle };
    let key = handle.0 as isize;
    handle_paths().lock().unwrap().insert(key, rel_str.to_string());
    if create_options & FILE_DELETE_ON_CLOSE.0 != 0 {
        delete_pending().lock().unwrap().insert(key);
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
            if let Some(rel) = workspace_relative(cfg, &path) {
                let rel_str = rel_to_string(&rel);
                // `NtOpenFile`は既存ファイルを開く操作のみ（`FILE_OPEN`相当）のため、
                // 論理削除済みなら常に失敗させる（再作成の余地は無い）。
                if let Some(status) = check_deleted(&rel_str, false) {
                    return status;
                }
                if is_write_intent(desired_access, None) {
                    let upper_path = cfg.upper_dir.join(&rel);
                    copy_up(cfg, &rel_str, &path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // 読み取りread-through（`hooked_nt_create_file`と同じ理由、設計書§19.3/§19.7）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
                    hook.call(
                        file_handle,
                        desired_access,
                        object_attributes,
                        io_status_block,
                        share_access,
                        open_options,
                    )
                };
                track_new_handle(file_handle, status, &rel_str, open_options);
                return status;
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

/// `FILE_DISPOSITION_INFORMATION`/`_EX`から削除フラグを読み取る。
unsafe fn disposition_delete_flag(is_ex: bool, info_ptr: *const c_void) -> bool {
    if is_ex {
        let info = unsafe { &*(info_ptr as *const FILE_DISPOSITION_INFORMATION_EX) };
        info.Flags.0 & FILE_DISPOSITION_DELETE.0 != 0
    } else {
        let info = unsafe { &*(info_ptr as *const FILE_DISPOSITION_INFORMATION) };
        info.DeleteFile.0 != 0
    }
}

/// `FILE_RENAME_INFORMATION`/`_EX`から移動先パスを読み取る。`RootDirectory`が非NULL
/// （ディレクトリハンドル相対）の場合は安全側の素通しとして`None`を返す（設計書§19.6）。
unsafe fn rename_target_path(info_ptr: *const c_void) -> Option<PathBuf> {
    let info = unsafe { &*(info_ptr as *const FILE_RENAME_INFORMATION) };
    if !info.RootDirectory.0.is_null() {
        return None;
    }
    let len_u16 = (info.FileNameLength as usize) / 2;
    if len_u16 == 0 {
        return None;
    }
    let name_ptr = info.FileName.as_ptr();
    let slice = unsafe { std::slice::from_raw_parts(name_ptr, len_u16) };
    let raw = String::from_utf16_lossy(slice);
    strip_nt_prefix(&raw)
}

/// 移動先をupper配下へ書き換えた`FILE_RENAME_INFORMATION`互換バッファを構築する。
/// `anonymous`（`ReplaceIfExists`/`Flags`共用体）は呼び出し元が指定した値をそのまま複製する
/// （リネームの意味自体は変えず、移動先パスだけを差し替える）。
fn build_rename_info_buffer(
    anonymous: windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION_0,
    new_upper_path: &Path,
) -> (Vec<u8>, usize) {
    let header_offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_wide: Vec<u16> = {
        let nt_path = format!(r"\??\{}", new_upper_path.to_string_lossy());
        nt_path.encode_utf16().collect()
    };
    let name_bytes_len = name_wide.len() * 2;
    let buf_len = std::cmp::max(
        std::mem::size_of::<FILE_RENAME_INFORMATION>(),
        header_offset + name_bytes_len,
    );
    let mut buf = vec![0u8; buf_len];
    unsafe {
        let header_ptr = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*header_ptr).Anonymous = anonymous;
        (*header_ptr).RootDirectory = HANDLE::default();
        (*header_ptr).FileNameLength = name_bytes_len as u32;
    }
    let name_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(name_wide.as_ptr() as *const u8, name_bytes_len) };
    buf[header_offset..header_offset + name_bytes_len].copy_from_slice(name_bytes);
    (buf, header_offset + name_bytes_len)
}

/// リネーム/移動を検知し、(1) 移動先パスをupper配下へ書き換え、(2) 台帳へ旧パスの`Delete`と
/// 新パスの`Create`/`Modify`を1件ずつ追記する（設計書§19.4/§19.6）。書き換え後のバッファと
/// 論理長を返す（`None`なら素通し）。
unsafe fn rewrite_rename_target(
    cfg: &Config,
    handle_key: isize,
    info_ptr: *const c_void,
) -> Option<(Vec<u8>, usize)> {
    let old_rel = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    let new_path = unsafe { rename_target_path(info_ptr) }?;
    let new_rel = workspace_relative(cfg, &new_path)?;
    let new_rel_str = rel_to_string(&new_rel);
    let upper_new = cfg.upper_dir.join(&new_rel);
    if let Some(parent) = upper_new.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let anonymous = unsafe { (*(info_ptr as *const FILE_RENAME_INFORMATION)).Anonymous };
    let buf = build_rename_info_buffer(anonymous, &upper_new);

    let old_baseline = baseline_hash_for(cfg, &old_rel);
    append_ledger_entry(cfg, ChangeOp::Delete, &old_rel, old_baseline);
    let new_baseline = baseline_hash_for(cfg, &new_rel_str);
    let new_op = if new_baseline.is_some() { ChangeOp::Modify } else { ChangeOp::Create };
    append_ledger_entry(cfg, new_op, &new_rel_str, new_baseline);

    // 以降このハンドルに対する操作（例: リネーム直後の削除予約）は新パスを指すべきなので、
    // 対応表を更新しておく。
    handle_paths().lock().unwrap().insert(handle_key, new_rel_str);

    Some(buf)
}

unsafe extern "system" fn hooked_nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *const c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let Some(cfg) = CONFIG.get() {
            let handle_key = file_handle.0 as isize;
            if !file_information.is_null()
                && (file_information_class == FileDispositionInformation
                    || file_information_class == FileDispositionInformationEx)
            {
                let is_ex = file_information_class == FileDispositionInformationEx;
                let delete_flag = unsafe { disposition_delete_flag(is_ex, file_information) };
                let pending = delete_pending();
                let mut g = pending.lock().unwrap();
                if delete_flag {
                    g.insert(handle_key);
                } else {
                    g.remove(&handle_key);
                }
            } else if !file_information.is_null()
                && (file_information_class == FileRenameInformation
                    || file_information_class == FileRenameInformationEx)
            {
                if let Some((buf, len)) =
                    unsafe { rewrite_rename_target(cfg, handle_key, file_information) }
                {
                    let hook = SET_INFO_HOOK.get().expect("hook installed");
                    return unsafe {
                        hook.call(
                            file_handle,
                            io_status_block,
                            buf.as_ptr() as *const c_void,
                            len as u32,
                            file_information_class,
                        )
                    };
                }
            }
        }
    }
    let hook = SET_INFO_HOOK.get().expect("hook installed");
    unsafe { hook.call(file_handle, io_status_block, file_information, length, file_information_class) }
}

unsafe extern "system" fn hooked_nt_close(handle: HANDLE) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let Some(cfg) = CONFIG.get() {
            let key = handle.0 as isize;
            let rel_opt = handle_paths().lock().unwrap().remove(&key);
            let was_pending = delete_pending().lock().unwrap().remove(&key);
            if was_pending {
                if let Some(rel) = rel_opt {
                    let baseline = baseline_hash_for(cfg, &rel);
                    append_ledger_entry(cfg, ChangeOp::Delete, &rel, baseline);
                }
            }
        }
    }
    let hook = CLOSE_HOOK.get().expect("hook installed");
    unsafe { hook.call(handle) }
}

unsafe extern "system" fn hooked_nt_query_full_attributes_file(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut windows::Wdk::Storage::FileSystem::FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let (Some(cfg), Some(path)) = (
            CONFIG.get(),
            unsafe { object_attributes_path(object_attributes) },
        ) {
            if let Some(rel) = workspace_relative(cfg, &path) {
                let rel_str = rel_to_string(&rel);
                if let Some(status) = check_deleted(&rel_str, false) {
                    return status;
                }
                // read-through: `Test-Path`/`.NET File.Exists`が使うこの経路も、upperに版が
                // あればそちらの属性を返す（設計書§19.3/§19.7、`hooked_nt_create_file`と同じ理由）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(&redirected_oa, file_information) };
                }
            }
        }
    }
    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
}

unsafe extern "system" fn hooked_nt_query_attributes_file(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let (Some(cfg), Some(path)) = (
            CONFIG.get(),
            unsafe { object_attributes_path(object_attributes) },
        ) {
            if let Some(rel) = workspace_relative(cfg, &path) {
                let rel_str = rel_to_string(&rel);
                if let Some(status) = check_deleted(&rel_str, false) {
                    return status;
                }
                // read-through（`hooked_nt_query_full_attributes_file`と同じ理由）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(&redirected_oa, file_information) };
                }
            }
        }
    }
    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
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

/// 既存の台帳（あれば）を読み、`deleted_paths_state`を組み立てる（設計書§19.7）。DLLは
/// `run_shell`呼び出しのたびに別プロセスへ再ロードされ得るため、台帳ファイルを唯一の正本に
/// して起動のたびに再生する。
fn load_deleted_set(cfg: &Config) {
    let ledger_path = cfg.upper_dir.join(COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return;
    };
    let entries = parse_ledger(&contents);
    let deleted = harness_change_ledger::deleted_paths(&entries);
    *deleted_paths_state().lock().unwrap() = deleted;
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
    let cfg = Config {
        workspace_root,
        upper_dir,
    };
    load_deleted_set(&cfg);
    let _ = CONFIG.set(cfg);

    let create_file_addr = match unsafe { resolve_ntdll_export("NtCreateFile") } {
        Some(a) => a,
        None => return,
    };
    let open_file_addr = match unsafe { resolve_ntdll_export("NtOpenFile") } {
        Some(a) => a,
        None => return,
    };
    let set_info_addr = match unsafe { resolve_ntdll_export("NtSetInformationFile") } {
        Some(a) => a,
        None => return,
    };
    let close_addr = match unsafe { resolve_ntdll_export("NtClose") } {
        Some(a) => a,
        None => return,
    };
    let query_full_attr_addr =
        match unsafe { resolve_ntdll_export("NtQueryFullAttributesFile") } {
            Some(a) => a,
            None => return,
        };
    let query_attr_addr = match unsafe { resolve_ntdll_export("NtQueryAttributesFile") } {
        Some(a) => a,
        None => return,
    };

    let create_file_fn: NtCreateFileFn = unsafe { std::mem::transmute(create_file_addr) };
    let open_file_fn: NtOpenFileFn = unsafe { std::mem::transmute(open_file_addr) };
    let set_info_fn: NtSetInformationFileFn = unsafe { std::mem::transmute(set_info_addr) };
    let close_fn: NtCloseFn = unsafe { std::mem::transmute(close_addr) };
    let query_full_attr_fn: NtQueryFullAttributesFileFn =
        unsafe { std::mem::transmute(query_full_attr_addr) };
    let query_attr_fn: NtQueryAttributesFileFn = unsafe { std::mem::transmute(query_attr_addr) };

    let create_detour = match unsafe { GenericDetour::new(create_file_fn, hooked_nt_create_file) }
    {
        Ok(d) => d,
        Err(_) => return,
    };
    let open_detour = match unsafe { GenericDetour::new(open_file_fn, hooked_nt_open_file) } {
        Ok(d) => d,
        Err(_) => return,
    };
    let set_info_detour =
        match unsafe { GenericDetour::new(set_info_fn, hooked_nt_set_information_file) } {
            Ok(d) => d,
            Err(_) => return,
        };
    let close_detour = match unsafe { GenericDetour::new(close_fn, hooked_nt_close) } {
        Ok(d) => d,
        Err(_) => return,
    };
    let query_full_attr_detour = match unsafe {
        GenericDetour::new(query_full_attr_fn, hooked_nt_query_full_attributes_file)
    } {
        Ok(d) => d,
        Err(_) => return,
    };
    let query_attr_detour =
        match unsafe { GenericDetour::new(query_attr_fn, hooked_nt_query_attributes_file) } {
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
    if unsafe { set_info_detour.enable() }.is_err() {
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
        }
        return;
    }
    if unsafe { close_detour.enable() }.is_err() {
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
        }
        return;
    }
    if unsafe { query_full_attr_detour.enable() }.is_err() {
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
        }
        return;
    }
    if unsafe { query_attr_detour.enable() }.is_err() {
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
            let _ = query_full_attr_detour.disable();
        }
        return;
    }
    let _ = CREATE_FILE_HOOK.set(create_detour);
    let _ = OPEN_FILE_HOOK.set(open_detour);
    let _ = SET_INFO_HOOK.set(set_info_detour);
    let _ = CLOSE_HOOK.set(close_detour);
    let _ = QUERY_FULL_ATTR_HOOK.set(query_full_attr_detour);
    let _ = QUERY_ATTR_HOOK.set(query_attr_detour);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// `baseline_hash_for`は初回アクセス時（キャッシュmiss）にbaseline内容を
    /// `.harness-cow-baseline/<rel>`へミラーする（設計書「baseline内容の保存」）。
    /// `rel`にテスト固有のユニークなキーを使い、プロセスグローバルな`baseline_cache`を
    /// 他のテストと共有しても衝突しないようにする。
    #[test]
    fn baseline_hash_for_writes_mirror_on_first_access() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("baseline_mirror_probe.txt"), "original").unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
        };

        let hash = baseline_hash_for(&cfg, "baseline_mirror_probe.txt");

        assert!(hash.is_some());
        let mirror = upper
            .path()
            .join(COW_BASELINE_DIRNAME)
            .join("baseline_mirror_probe.txt");
        assert_eq!(std::fs::read_to_string(mirror).unwrap(), "original");
    }

    /// 新規作成（baselineが存在しない）パスはミラーを書かない。
    #[test]
    fn baseline_hash_for_writes_no_mirror_when_path_does_not_exist() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
        };

        let hash = baseline_hash_for(&cfg, "does_not_exist_probe.txt");

        assert!(hash.is_none());
        assert!(!upper
            .path()
            .join(COW_BASELINE_DIRNAME)
            .join("does_not_exist_probe.txt")
            .exists());
    }
}
