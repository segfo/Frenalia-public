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
//!
//! ## Phase 4a: 孫プロセスへの再注入（x64→x64のみ、`/dig`2026-08-01決定）
//!
//! 直接の子（Launcherが起動したプロセス）は上記の経路でLauncherから注入されるが、その子が
//! さらに起動する孫プロセスにはLauncherの手が届かない。このDLLは自分自身の`kernel32!CreateProcessW`
//! /`kernel32!CreateProcessAsUserW`をフックし、**自力で**孫へ再注入する（`/dig`Q5、境界ではなく
//! 透過性の問題なのでD-01には抵触しない——注入に失敗しても孫の書込はworkspace ROのACLで
//! `ACCESS_DENIED`のままfail-closeする。§32 Phase 4a参照）。
//!
//! **BUG-041で判明した経緯**: 当初は`ntdll!NtCreateUserProcess`（`CreateProcessInternalW`が
//! 内部的に呼ぶ、より低レベルなAPI）をフックしていたが、実機E2Eで孫プロセス（`cmd.exe`）が
//! `STATUS_INVALID_HANDLE`の未処理例外でクラッシュした。原因は、`NtCreateUserProcess`が
//! 返った直後の時点では**Win32レベルのプロセス生成がまだ完了していない**こと——
//! `CreateProcessInternalW`はこの後CSRSSへプロセスを登録する処理を続けており、その前に
//! `CreateRemoteThread`でリモートスレッドを走らせると（そのスレッドが`LdrInitializeThunk`経由で
//! Win32サブシステムに依存する初期化を行うため）ハングまたはクラッシュする（診断計装による実測、
//! `docs/bugs/BUG-041.md`参照）。フック地点を「OSがそのプロセスの生成を完全に終えた地点」へ
//! 移すため、`NtCreateUserProcess`より1段上の`CreateProcessW`/`CreateProcessAsUserW`（Win32
//! レベル、`kernel32.dll`のエクスポート。多くの場合`kernelbase.dll`への転送エクスポートなので
//! `GetProcAddress`は自動的に転送先を解決する）へ移した。Launcher側の直接の子への注入
//! （`win_appcontainer.rs`の`spawn_impl`→`inject_redirector`→`wait_cow_ready`→`ResumeThread`、
//! `CreateProcessW(CREATE_SUSPENDED)`が完全に返った後に注入する設計）が実機で安定していたのも
//! 同じ理由——Win32層まで生成が完了した地点でだけ注入するのが安全、という教訓による。
//!
//! `dwCreationFlags`引数の`CREATE_SUSPENDED`ビットだけを操作し、`lpStartupInfo`
//! （`STARTUPINFOW`または`STARTUPINFOEXW`）・`lpProcessInformation`以外の引数の中身には
//! 一切触れず生ポインタのままオリジナル関数へそのまま渡す。
//!
//! 注入は2段階（`/dig`Q8）: ①`CreateRemoteThread(LoadLibraryW)`でこのDLL自身を孫へロードさせ、
//! スレッド終了を待つ（この時点でDLLはロード済みだが、`DllMain`が内部で起動する初期化スレッドは
//! 別スレッドのため完了保証が無い）。②孫プロセス内の自DLLのベースアドレスを`EnumProcessModulesEx`
//! で特定し、自プロセスで計算した`harness_cow_init`（エクスポート済み）のRVAを加算した
//! アドレスへ`CreateRemoteThread`し、その終了を待つ——これが「フック設置完了」を保証する唯一の
//! 同期点になる。`DllMain`側の自動初期化スレッドとの競合は`INIT_ONCE`（`std::sync::Once`）で
//! 吸収する（どちらが先に走っても安全、後者は即noop）。
//!
//! 注入・初期化のいずれかに失敗しても、孫プロセスの生成自体は拒否しない（Q6）。かわりに
//! `<upper_dir>/.harness-cow-warnings.jsonl`へ理由を追記する（`append_warning_entry`）。
//! 32bitターゲット（WOW64）はPhase 4bの対象で、x64専用のこのDLLをロードしようとすると
//! `LoadLibraryW`が自然に失敗する（`ERROR_BAD_EXE_FORMAT`相当）ため、そのまま「注入失敗」の
//! 経路で警告化される（明示的なビット幅事前判定は行わない）。

#![cfg(windows)]

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use harness_change_ledger::{
    hash_bytes, now_millis, parse_ledger, ChangeOp, CowOpEntry, COW_BASELINE_DIRNAME,
    COW_OPS_LEDGER_FILENAME,
};
use retour::GenericDetour;
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::{OBJECT_ATTRIBUTES, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION};
use windows::Wdk::Foundation::NtQueryObject;
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileDispositionInformationEx, FileRenameInformation,
    FileRenameInformationEx, FILE_DELETE_ON_CLOSE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX, FILE_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    BOOL, CloseHandle, HANDLE, HMODULE, NTSTATUS, STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{
    CreateRemoteThread, CreateThread, GetExitCodeThread, ResumeThread, WaitForSingleObject,
    PROCESS_INFORMATION, THREAD_CREATION_FLAGS,
};

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

/// Phase 4a（BUG-041修正後）: `kernel32!CreateProcessW`。`lpStartupInfo`
/// （`STARTUPINFOW`または`STARTUPINFOEXW`、レイアウトが呼び出し元次第で変わる）・
/// `lpProcessAttributes`/`lpThreadAttributes`/`lpEnvironment`は中身を一切解釈せず不透明
/// ポインタとしてそのままオリジナル関数へ渡す。唯一操作するのは独立したu32引数の
/// `dwCreationFlags`（`CREATE_SUSPENDED_FLAG`ビット）のみ（モジュールdoc参照）。
/// `lpProcessInformation`だけは戻り値読み取りのため`PROCESS_INFORMATION`として解釈する
/// （呼び出し元が非NULLを渡す前提はWin32 API仕様上保証されている）。
type CreateProcessWFn = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCWSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// Phase 4a（BUG-041修正後）: `kernel32!CreateProcessAsUserW`。`CreateProcessWFn`と同型で、
/// 第1引数に`hToken`が追加されるだけ。
type CreateProcessAsUserWFn = unsafe extern "system" fn(
    HANDLE,
    PCWSTR,
    PWSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCWSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// Win32 `PROCESS_CREATION_FLAGS`の`CREATE_SUSPENDED`ビット（`windows`クレートの
/// `windows::Win32::System::Threading::CREATE_SUSPENDED`と同値だが、フック関数の引数型が
/// 生の`u32`のためリテラルとして持つ）。
const CREATE_SUSPENDED_FLAG: u32 = 0x0000_0004;

struct Config {
    workspace_root: PathBuf,
    upper_dir: PathBuf,
}

/// 孫プロセスへの再注入が失敗した/初期化未完了だった場合の警告台帳ファイル名
/// （`<upper_dir>/.harness-cow-warnings.jsonl`、Q6）。操作台帳（`COW_OPS_LEDGER_FILENAME`）とは
/// 別ファイルにする——こちらは「透過性が欠けている」という注意喚起であり、`ChangeOp`の
/// 型を汚さないため。
const COW_WARNINGS_LEDGER_FILENAME: &str = ".harness-cow-warnings.jsonl";

#[derive(serde::Serialize)]
struct CowWarningEntry<'a> {
    kind: &'a str,
    message: &'a str,
    ts_unix_millis: u128,
}

static CONFIG: OnceLock<Config> = OnceLock::new();
static CREATE_FILE_HOOK: OnceLock<GenericDetour<NtCreateFileFn>> = OnceLock::new();
static OPEN_FILE_HOOK: OnceLock<GenericDetour<NtOpenFileFn>> = OnceLock::new();
static SET_INFO_HOOK: OnceLock<GenericDetour<NtSetInformationFileFn>> = OnceLock::new();
static CLOSE_HOOK: OnceLock<GenericDetour<NtCloseFn>> = OnceLock::new();
static QUERY_FULL_ATTR_HOOK: OnceLock<GenericDetour<NtQueryFullAttributesFileFn>> = OnceLock::new();
static QUERY_ATTR_HOOK: OnceLock<GenericDetour<NtQueryAttributesFileFn>> = OnceLock::new();
static CREATE_PROCESS_W_HOOK: OnceLock<GenericDetour<CreateProcessWFn>> = OnceLock::new();
static CREATE_PROCESS_AS_USER_W_HOOK: OnceLock<GenericDetour<CreateProcessAsUserWFn>> =
    OnceLock::new();

/// このDLL自身がロードされているモジュールベースアドレス（`DllMain`の`hinst`引数、数値上は
/// そのプロセスにおけるロードベースアドレスと一致する——Windowsの仕様）。孫プロセス内での
/// 自DLLの相対オフセット（RVA）を、自プロセスの`GetProcAddress`結果から逆算するために使う
/// （Phase 4a、`inject_grandchild`参照）。
static SELF_MODULE: OnceLock<usize> = OnceLock::new();

/// `init()`の重複実行を防ぐ。孫プロセスでは`DllMain`の`DLL_PROCESS_ATTACH`が自動的に起動する
/// 内部初期化スレッドと、Launcher役の親プロセス側から`CreateRemoteThread`で明示的に呼ばれる
/// `harness_cow_init`エクスポートの2経路が同一プロセス内で競合し得るため、`std::sync::Once`で
/// 一本化する（Phase 4a、モジュールdoc参照）。
static INIT_ONCE: std::sync::Once = std::sync::Once::new();

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
///
/// Phase 4a（孫プロセスへの再注入）により、同じ台帳へ複数プロセス（兄弟）が並行して追記し得る
/// ようになったため、自プロセスが起こしていない削除（兄弟プロセスが起こした削除）もここへ
/// 反映する必要がある。`refresh_deleted_set`が増分tail再読込でこれを行う（設計書§19.2）。
fn deleted_paths_state() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashSet::new()))
}

/// `deleted_paths_state`を最後に同期した時点での台帳ファイルの読み込み済みバイトオフセット。
fn ledger_read_offset() -> &'static Mutex<u64> {
    static O: OnceLock<Mutex<u64>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(0))
}

fn get_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// BUG-033調査用の診断計装（`docs/bugs/BUG-033.md`参照、再発時の再調査用に残置）。
/// releaseビルドでは`cfg!(debug_assertions)`により本体が定数畳み込みで消えるため、配布
/// バイナリには影響しない。
///
/// BUG-041調査で判明: AppContainer子/孫プロセスに付与しているACLはworkspace（RO）とupper_dir（RW）
/// のみで、`%TEMP%`直下への書込権は無い。そのため`%TEMP%`へ書く実装は**サンドボックス内から
/// 常に無音**だった（BUG-033で「ログが生成されなかった＝該当パスを通っていない」と解釈した
/// 箇所は、この理由で不成立だった可能性が高い——同ファイルに追記済み）。`CONFIG`が既に設定済み
/// なら`upper_dir`（子・孫とも書込可能、`append_ledger_entry`/`append_warning_entry`と同じ場所）
/// へ書き、未設定（`init()`より前、または`CONFIG`取得に失敗する異常系）なら従来通り`%TEMP%`へ
/// フォールバックする。`--cow`のフック呼び出し頻度は対話セッションのシェルコマンド数程度で
/// 済むため、ログ肥大やI/O再入（`copy_up`同様に自分自身のフックへ戻ってくる可能性はあるが、
/// いずれの出力先も`workspace_relative`が`None`を返す経路なので無限ループにはならない）の
/// 実害は無い想定。
fn debug_log(msg: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let path = match CONFIG.get() {
        Some(cfg) => cfg.upper_dir.join(".harness-cow-debug.log"),
        None => std::env::temp_dir().join("harness-cow-debug.log"),
    };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {msg}", now_millis());
    }
}

/// `OBJECT_ATTRIBUTES.ObjectName`（`UNICODE_STRING`、UTF-16・非NUL終端）をRustの`String`へ。
///
/// `RootDirectory`が有効（相対open、いわゆるopenat方式）の場合は、`GetFinalPathNameByHandleW`
/// で`RootDirectory`ハンドルの完全パスを解決し、`ObjectName`（ハンドル起点からの相対パス）を
/// 連結して絶対パスへ組み立てる（BUG-033/BUG-041調査で判明: `cmd.exe`の`>`リダイレクトが
/// この方式でファイルを開くため、これを解決しないと孫プロセスの書込みがworkspace RO ACLへ
/// 素通しされ、fail-closeで消える——実機ログで実証済み）。`GetFinalPathNameByHandleW`は
/// 既存の（他プロセスではなく自プロセス内で有効な）ハンドルに対するクエリのみで新規に
/// ファイルを開かないため、`ReentryGuard`配下から呼んでも`NtCreateFile`/`NtOpenFile`への
/// 再帰は起きない。
unsafe fn object_attributes_path(oa: *const OBJECT_ATTRIBUTES) -> Option<PathBuf> {
    if oa.is_null() {
        return None;
    }
    let oa = unsafe { &*oa };
    let root_dir_value = oa.RootDirectory.0 as isize;
    let is_relative = !oa.RootDirectory.is_invalid() && root_dir_value != 0;
    let raw_name = if !oa.ObjectName.is_null() {
        let us = unsafe { &*oa.ObjectName };
        if us.Buffer.is_null() || us.Length == 0 {
            String::new()
        } else {
            let len_u16 = (us.Length as usize) / 2;
            let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) };
            String::from_utf16_lossy(slice)
        }
    } else {
        String::new()
    };
    if raw_name.to_ascii_lowercase().contains("test.txt")
        || raw_name.to_ascii_lowercase().contains("grandchild")
    {
        debug_log(&format!(
            "object_attributes_path: root_dir={root_dir_value:#x} is_relative={is_relative} \
             raw_name={raw_name:?}"
        ));
    }
    if is_relative {
        return unsafe { resolve_relative_object_attributes_path(oa.RootDirectory, &raw_name) };
    }
    if raw_name.is_empty() {
        return None;
    }
    strip_nt_prefix(&raw_name)
}

/// `object_attributes_path`のopenat方式（`RootDirectory`相対）分岐本体（BUG-033修正）。
///
/// **`GetFinalPathNameByHandleW`/`QueryDosDeviceW`は使わない**: 当初`GetFinalPathNameByHandleW`
/// で`root`をDOS絶対パスへ解決しようとしたが、実機でAppContainer内から呼ぶと常に
/// `ERROR_ACCESS_DENIED`になった（内部で生のボリュームデバイス`\\.\C:`相当を開くため、
/// workspace/upperのACLだけを許可されたパッケージSIDには許可されない）。次に
/// `ntdll!NtQueryObject`でNTデバイスパス（例: `\Device\HarddiskVolume3\Users\...`、ドライブ
/// 文字なし）を得た上で、ドライブ文字→NTデバイス名の対応を`QueryDosDeviceW`のシステム全体
/// 列挙で作ろうとしたが、これもAppContainerからは1件も返らない（実機で確認、`\??\`
/// シンボリックリンク名前空間そのものがパッケージSIDから見えない）。
///
/// かわりに、**このDLLが最初から知っている2つのDOS絶対パス（`cfg.workspace_root`・
/// `cfg.upper_dir`）自身を自分で開いてNTデバイスプレフィックスを逆算**する
/// （`known_root_nt_prefixes`）。システム全体のドライブ列挙が不要になり、workspace/upper
/// 配下だけを解決できれば十分というこのDLLのスコープ（workspace外は既存の設計通り
/// 安全側で素通し）とも一致する。
unsafe fn resolve_relative_object_attributes_path(root: HANDLE, raw_name: &str) -> Option<PathBuf> {
    // 実機回帰テストで発見した誤検知: Windows Defender/AMSIプロバイダ（`MpOav.dll`等）が
    // レジストリのREG_EXPAND_SZ値を展開せずそのまま`NtCreateFile`の`ObjectName`へ渡すことがあり、
    // その結果`raw_name`が`%SystemDrive%\ProgramData\...\MpOav.dll`という**未展開の環境変数文字列を
    // 含む見せかけの相対パス**になる。`root`（この呼び出しでは偶然workspaceのCWDハンドル）と
    // 連結すると構文上は「workspace配下」に見えてしまい、無関係なシステムDLLの読み込みが
    // 誤って変更として記録・リダイレクトされる（実機`cow_ledger_records_single_session_changes_and_applies_cleanly`
    // で`%SystemDrive%/...`という台帳エントリとして再現）。`%`はcmd.exeの`>`リダイレクト等
    // 正規の相対ファイル名には現れないため、含む場合は解決不能として安全側で素通しする。
    if raw_name.contains('%') {
        return None;
    }
    let cfg = CONFIG.get()?;
    let Some(nt_device_path) = (unsafe { query_object_name(root) }) else {
        debug_log("resolve_relative_object_attributes_path: NtQueryObject failed");
        return None;
    };
    let Some(root_path) = nt_device_path_to_known_root(cfg, &nt_device_path) else {
        debug_log(&format!(
            "resolve_relative_object_attributes_path: nt_device_path_to_known_root failed for \
             nt_device_path={nt_device_path:?}"
        ));
        return None;
    };
    let rel = raw_name.trim_start_matches('\\');
    if rel.is_empty() {
        Some(root_path)
    } else {
        Some(root_path.join(rel.replace('/', "\\")))
    }
}

/// `ntdll!NtQueryObject(handle, ObjectNameInformation, ...)`。カーネルのオブジェクトマネージャに
/// 記録されているハンドルの名前（ファイルハンドルの場合はNTデバイスパス）を問い合わせる。
/// `windows`クレートは`ObjectNameInformation`定数自体はエクスポートしていないため
/// （`ObjectBasicInformation`=0・`ObjectTypeInformation`=2のみ生成済み）、phnt由来の値1を
/// 直接リテラルで持つ。
unsafe fn query_object_name(handle: HANDLE) -> Option<String> {
    const OBJECT_NAME_INFORMATION_CLASS: OBJECT_INFORMATION_CLASS = OBJECT_INFORMATION_CLASS(1);
    let mut buf = vec![0u8; 1024];
    let mut return_length: u32 = 0;
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION_CLASS,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            Some(&mut return_length),
        )
    };
    if status.is_err() {
        return None;
    }
    let info = unsafe { &*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION) };
    let name = &info.Name;
    if name.Buffer.is_null() || name.Length == 0 {
        return None;
    }
    let len_u16 = (name.Length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(name.Buffer.0, len_u16) };
    Some(String::from_utf16_lossy(slice))
}

/// `cfg.workspace_root`・`cfg.upper_dir`それぞれについて、自分でその絶対パスを開き
/// `query_object_name`でNTデバイスパス（例: `\Device\HarddiskVolume3\Users\...\workspace`、
/// ルート自身の完全パス）を取得してキャッシュする。プロセス生存中にドライブ構成が変わる
/// ことは無い想定で1度だけ計算する（BUG-033修正）。
fn known_root_nt_paths(cfg: &'static Config) -> &'static [(String, PathBuf)] {
    static CACHE: OnceLock<Vec<(String, PathBuf)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = Vec::new();
        for root in [cfg.workspace_root.clone(), cfg.upper_dir.clone()] {
            if let Some(nt_name) = query_own_nt_device_path(&root) {
                out.push((nt_name, root));
            }
        }
        out
    })
}

/// `root`（このDLLが既に知っているDOS絶対パス）を`FILE_FLAG_BACKUP_SEMANTICS`付きで開き
/// （ディレクトリを`CreateFileW`系で開くにはこのフラグが要る）、`query_object_name`で
/// そのハンドル自身の完全なNTデバイスパスを取得する（`known_root_nt_paths`参照）。
fn query_own_nt_device_path(root: &Path) -> Option<String> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .ok()?;
    let handle = HANDLE(file.as_raw_handle());
    unsafe { query_object_name(handle) }
}

/// NTデバイスパス（例: `\Device\HarddiskVolume3\Users\...`）を、`known_root_nt_paths`の
/// 対応表と比較し、既知ルート（`workspace_root`または`upper_dir`）自身か、その配下かを
/// 判定してDOS絶対パスへ変換する（BUG-033修正）。
fn nt_device_path_to_known_root(cfg: &'static Config, nt_path: &str) -> Option<PathBuf> {
    let nt_lc = nt_path.to_ascii_lowercase();
    for (root_nt_path, dos_root) in known_root_nt_paths(cfg) {
        let root_nt_lc = root_nt_path.to_ascii_lowercase();
        if nt_lc == root_nt_lc {
            return Some(dos_root.clone());
        }
        if nt_lc.starts_with(&format!("{root_nt_lc}\\")) {
            let rest = &nt_path[root_nt_path.len() + 1..];
            return Some(dos_root.join(rest.replace('/', "\\")));
        }
    }
    None
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

/// 台帳ファイルの、前回同期以降に追記された**完全な行だけ**を取り込み、`deleted_paths_state`
/// を増分更新する（設計書§19.2）。`FILE_APPEND_DATA`による1行1書込みという既存の追記規律
/// （書く側、本ファイル`append_ledger_entry`）により、途中まで書かれた行（末尾に`\n`が無い）は
/// 次回の呼び出しまで無視して安全に据え置ける——サイズが前回と変わっていなければファイルI/O
/// すらしないため、フックのホットパスでのコストは兄弟プロセスが実際に書いた場合のみ発生する。
fn refresh_deleted_set(cfg: &Config) {
    let ledger_path = cfg.upper_dir.join(COW_OPS_LEDGER_FILENAME);
    let mut offset_guard = ledger_read_offset().lock().unwrap();
    let Ok(contents) = std::fs::read(&ledger_path) else {
        return;
    };
    let len = contents.len() as u64;
    if len <= *offset_guard {
        // 変化なし、または（想定外だが）縮小。縮小はスコープ外として無視する。
        return;
    }
    let new_bytes = &contents[*offset_guard as usize..];
    let Some(last_nl) = new_bytes.iter().rposition(|&b| b == b'\n') else {
        // 完全な行がまだ1つも届いていない（書込み途中）。オフセットは進めない。
        return;
    };
    let complete = &new_bytes[..=last_nl];
    let text = String::from_utf8_lossy(complete);
    let entries = parse_ledger(&text);
    let mut deleted = deleted_paths_state().lock().unwrap();
    for entry in &entries {
        match entry.op {
            ChangeOp::Delete => {
                deleted.insert(entry.path.clone());
            }
            ChangeOp::Create | ChangeOp::Modify => {
                deleted.remove(&entry.path);
            }
        }
    }
    *offset_guard += complete.len() as u64;
}

/// 論理削除済み集合を確認し、必要なら書換後の`NTSTATUS`を返す（`Some`なら即returnすべき）。
/// 作成可能なdispositionでの再作成は集合から除去して`None`（通常処理へ継続）を返す。
fn check_deleted(cfg: &Config, rel: &str, allow_recreate: bool) -> Option<NTSTATUS> {
    refresh_deleted_set(cfg);
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
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_create_file: rel={rel_str:?} desired_access={:#x} \
                         disposition={:#x} write_intent={} upper_exists={}",
                        desired_access.0,
                        create_disposition.0,
                        is_write_intent(desired_access.0, Some(create_disposition.0)),
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                if let Some(status) =
                    check_deleted(cfg, &rel_str, is_create_capable_disposition(create_disposition.0))
                {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} check_deleted short-circuit status={status:?}"
                        ));
                    }
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
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} branch=write-redirect \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
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
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} branch=read-through \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
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
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_create_file: rel={rel_str:?} branch=passthrough-no-upper \
                         status={status:?}"
                    ));
                }
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
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_open_file: rel={rel_str:?} desired_access={desired_access:#x} \
                         write_intent={} upper_exists={}",
                        is_write_intent(desired_access, None),
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                // `NtOpenFile`は既存ファイルを開く操作のみ（`FILE_OPEN`相当）のため、
                // 論理削除済みなら常に失敗させる（再作成の余地は無い）。
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} check_deleted short-circuit status={status:?}"
                        ));
                    }
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
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} branch=write-redirect \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
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
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} branch=read-through \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
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
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_open_file: rel={rel_str:?} branch=passthrough-no-upper \
                         status={status:?}"
                    ));
                }
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
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} upper_exists={}",
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                             check_deleted short-circuit status={status:?}"
                        ));
                    }
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
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                             branch=read-through upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-upper"
                    ));
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
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} upper_exists={}",
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_attributes_file: rel={rel_str:?} \
                             check_deleted short-circuit status={status:?}"
                        ));
                    }
                    return status;
                }
                // read-through（`hooked_nt_query_full_attributes_file`と同じ理由）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_attributes_file: rel={rel_str:?} \
                             branch=read-through upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-upper"
                    ));
                }
            }
        }
    }
    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
}

/// 孫プロセスへ再注入が失敗した/未完了だった場合の警告を`.harness-cow-warnings.jsonl`へ
/// 追記する（Q6）。孫の書込みが透過されないことを示すだけで、生成自体は拒否しない。
fn append_warning_entry(cfg: &Config, message: &str) {
    let entry = CowWarningEntry {
        kind: "grandchild_injection_incomplete",
        message,
        ts_unix_millis: now_millis(),
    };
    if let Ok(mut line) = serde_json::to_string(&entry) {
        line.push('\n');
        let path = cfg.upper_dir.join(COW_WARNINGS_LEDGER_FILENAME);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// このDLL自身の完全パス（`GetModuleFileNameW`、`SELF_MODULE`＝`DllMain`の`hinst`から）。
/// 孫プロセスへ同じDLLを`LoadLibraryW`させるため、また孫プロセス内でのモジュール識別
/// （`find_remote_module_base`）のために使う。
fn self_dll_path() -> Option<PathBuf> {
    let base = *SELF_MODULE.get()?;
    let mut buf = [0u16; 512];
    let len = unsafe { GetModuleFileNameW(HMODULE(base as *mut c_void), &mut buf) };
    if len == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

/// `process`（孫プロセス、`LoadLibraryW`完了後）内で、`dll_path`と同じ完全パスを持つ
/// モジュールのベースアドレスを`EnumProcessModulesEx`/`GetModuleFileNameExW`で特定する。
/// `GetExitCodeThread`によるHMODULE取得（32bit切り詰めの既知の制約、`inject_redirector`の
/// コメント参照）は使わない。
unsafe fn find_remote_module_base(process: HANDLE, dll_path: &Path) -> Option<usize> {
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

/// Phase 4a本体: `process`（`NtCreateUserProcess`が返したばかりの、まだSUSPENDEDの孫）へ
/// このDLL自身を2段階で再注入する（モジュールdoc参照）。成功＝フック設置完了確認まで
/// 済んだら`true`を返す。
unsafe fn inject_grandchild(process: HANDLE) -> bool {
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
        VirtualAllocEx(process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote_buf.is_null() {
        debug_log(&format!(
            "inject_grandchild: VirtualAllocEx failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        return false;
    }
    let write_ok = unsafe {
        WriteProcessMemory(process, remote_buf, path_w.as_ptr() as *const c_void, size, None)
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
        GetProcAddress(kernel32, windows::core::PCSTR(c"LoadLibraryW".as_ptr() as *const u8))
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
        CreateRemoteThread(process, None, 0, load_start, Some(remote_buf), 0, Some(&mut tid))
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
    let mut tid2: u32 = 0;
    let init_thread =
        unsafe { CreateRemoteThread(process, None, 0, init_start, None, 0, Some(&mut tid2)) };
    let Ok(init_thread) = init_thread else {
        debug_log(&format!(
            "inject_grandchild: CreateRemoteThread(harness_cow_init) failed, GetLastError={:#x}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        ));
        return false;
    };
    let init_wait_result = unsafe { WaitForSingleObject(init_thread, 5000) };
    let mut init_exit: u32 = 0;
    unsafe {
        let _ = GetExitCodeThread(init_thread, &mut init_exit);
        let _ = CloseHandle(init_thread);
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
unsafe fn inject_grandchild_and_maybe_resume(
    process_information: *mut c_void,
    caller_wanted_suspended: bool,
    caller: &str,
) {
    if process_information.is_null() {
        debug_log(&format!("{caller}: lpProcessInformation is null, skip injection"));
        return;
    }
    let pi = unsafe { &*(process_information as *const PROCESS_INFORMATION) };
    debug_log(&format!(
        "{caller}: process_handle={:#x} thread_handle={:#x} caller_wanted_suspended={caller_wanted_suspended}, calling inject_grandchild",
        pi.hProcess.0 as usize, pi.hThread.0 as usize
    ));
    if let Some(cfg) = CONFIG.get() {
        let injected = unsafe { inject_grandchild(pi.hProcess) };
        debug_log(&format!("{caller}: inject_grandchild returned {injected}"));
        if !injected {
            append_warning_entry(
                cfg,
                "grandchild redirector re-injection failed or timed out; writes from this \
                 process will not be redirected to the CoW upper directory (workspace stays \
                 read-only ACL, so writes fail closed rather than silently missing the ledger)",
            );
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

/// Phase 4a（BUG-041修正）: `CreateProcessW`のフック本体。`dwCreationFlags`にSUSPENDEDを
/// 強制してからオリジナル関数を呼び、Win32レベルのプロセス生成が完全に終わった後（モジュールdoc
/// 参照）に孫プロセスへ再注入する。
unsafe extern "system" fn hooked_create_process_w(
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
unsafe extern "system" fn hooked_create_process_as_user_w(
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

unsafe fn resolve_ntdll_export(name: &str) -> Option<*const c_void> {
    unsafe { resolve_module_export("ntdll.dll", name) }
}

/// `resolve_ntdll_export`の一般化版（Phase 4a、BUG-041修正で追加）。`kernel32.dll`/
/// `kernelbase.dll`からのエクスポート解決にも使う。`GetProcAddress`は転送エクスポート
/// （export forwarder、例えば`kernel32!CreateProcessW`が`KERNELBASE.CreateProcessW`へ転送する
/// 形式）を自動的に解決するため、`kernelbase.dll`から先に解決を試みれば実体のアドレスが
/// 直接得られる。
unsafe fn resolve_module_export(module: &str, name: &str) -> Option<*const c_void> {
    let module_name: Vec<u16> = format!("{module}\0").encode_utf16().collect();
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
    let Ok(contents) = std::fs::read(&ledger_path) else {
        return;
    };
    let text = String::from_utf8_lossy(&contents);
    let entries = parse_ledger(&text);
    let deleted = harness_change_ledger::deleted_paths(&entries);
    *deleted_paths_state().lock().unwrap() = deleted;
    // 起動時に読んだ全内容をオフセットとして記録し、以降`refresh_deleted_set`が同じ範囲を
    // 二重に取り込まないようにする。
    *ledger_read_offset().lock().unwrap() = contents.len() as u64;
}

/// フック設置本体（`DllMain`からは呼ばない、Loader Lock回避のため専用スレッドから呼ぶ、
/// 設計書§13.4）。設定を読み・フックを設置し、成功したら`HARNESS_COW_READY_EVENT`へ
/// シグナルする。失敗時はシグナルしない——Launcher側は待機タイムアウトでプロセスを
/// 終了する（設計書§10.2 既定・§25.1）。
fn init() {
    debug_log(&format!(
        "init: enter, HARNESS_COW_WORKSPACE={:?} HARNESS_COW_UPPER={:?}",
        get_env("HARNESS_COW_WORKSPACE"),
        get_env("HARNESS_COW_UPPER")
    ));
    let workspace_root = match get_env("HARNESS_COW_WORKSPACE") {
        Some(v) => PathBuf::from(v),
        None => {
            debug_log("init: HARNESS_COW_WORKSPACE not set, bail");
            return;
        }
    };
    let upper_dir = match get_env("HARNESS_COW_UPPER") {
        Some(v) => PathBuf::from(v),
        None => {
            debug_log("init: HARNESS_COW_UPPER not set, bail");
            return;
        }
    };
    let cfg = Config {
        workspace_root,
        upper_dir,
    };
    load_deleted_set(&cfg);
    let _ = CONFIG.set(cfg);

    let create_file_addr = match unsafe { resolve_ntdll_export("NtCreateFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtCreateFile) failed, bail");
            return;
        }
    };
    let open_file_addr = match unsafe { resolve_ntdll_export("NtOpenFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtOpenFile) failed, bail");
            return;
        }
    };
    let set_info_addr = match unsafe { resolve_ntdll_export("NtSetInformationFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtSetInformationFile) failed, bail");
            return;
        }
    };
    let close_addr = match unsafe { resolve_ntdll_export("NtClose") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtClose) failed, bail");
            return;
        }
    };
    let query_full_attr_addr =
        match unsafe { resolve_ntdll_export("NtQueryFullAttributesFile") } {
            Some(a) => a,
            None => {
                debug_log("init: resolve_ntdll_export(NtQueryFullAttributesFile) failed, bail");
                return;
            }
        };
    let query_attr_addr = match unsafe { resolve_ntdll_export("NtQueryAttributesFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryAttributesFile) failed, bail");
            return;
        }
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
        debug_log("init: create_detour.enable() failed, bail");
        return;
    }
    if unsafe { open_detour.enable() }.is_err() {
        debug_log("init: open_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
        }
        return;
    }
    if unsafe { set_info_detour.enable() }.is_err() {
        debug_log("init: set_info_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
        }
        return;
    }
    if unsafe { close_detour.enable() }.is_err() {
        debug_log("init: close_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
        }
        return;
    }
    if unsafe { query_full_attr_detour.enable() }.is_err() {
        debug_log("init: query_full_attr_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
        }
        return;
    }
    if unsafe { query_attr_detour.enable() }.is_err() {
        debug_log("init: query_attr_detour.enable() failed, bail");
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
    debug_log("init: all 6 file hooks installed successfully");

    // Phase 4a（BUG-041修正）: `CreateProcessW`/`CreateProcessAsUserW`フックはベストエフォート。
    // Phase 1-3（直接の子の書込リダイレクト）は実機で確立済みの機能であり、これらのフックが
    // 何らかの理由で設置に失敗しても、上記6フックを巻き戻さずそのまま活かす（孫プロセスへの
    // 再注入だけが働かなくなる＝Phase 4a以前と同じ状態に留まる）。
    install_create_process_hooks();
    debug_log(&format!(
        "init: install_create_process_hooks done, create_process_w_hook={} create_process_as_user_w_hook={}",
        CREATE_PROCESS_W_HOOK.get().is_some(),
        CREATE_PROCESS_AS_USER_W_HOOK.get().is_some()
    ));

    signal_ready();
}

/// `CreateProcessW`/`CreateProcessAsUserW`のベストエフォートフック設置（Phase 4a、BUG-041修正、
/// `init`から呼ばれる）。失敗しても他の6フックには一切影響しない（呼び出し元コメント参照）。
/// `kernelbase.dll`から先に解決を試みる（`resolve_module_export`のdoc参照、転送エクスポートの
/// 実体を直接掴むため）。`kernel32.dll`の解決に失敗する環境は無い想定だが、フォールバックとして
/// `kernelbase.dll`側の解決が失敗した場合のみ`kernel32.dll`を試す。
fn install_create_process_hooks() {
    for module in ["kernelbase.dll", "kernel32.dll"] {
        if CREATE_PROCESS_W_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessW") } {
                let target: CreateProcessWFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_create_process_w) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_W_HOOK.set(detour);
                    }
                }
            }
        }
        if CREATE_PROCESS_AS_USER_W_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessAsUserW") } {
                let target: CreateProcessAsUserWFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) =
                    unsafe { GenericDetour::new(target, hooked_create_process_as_user_w) }
                {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_AS_USER_W_HOOK.set(detour);
                    }
                }
            }
        }
    }
}

/// Launcherが`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`で継承させたパイプ書込端（`HARNESS_COW_READY_HANDLE`
/// に生ハンドル値として渡される、`win_appcontainer.rs`の`appcontainer_pipe`+`wait_cow_ready`と対）へ
/// 1バイト書き込む。ハンドルのcloseはLauncher側が読み取り後に行う（`win_appcontainer.rs:1222`）ため、
/// ここでは書込のみ行い、close責務は持たない。
///
/// BUG-041調査で判明した副次バグ: `HARNESS_COW_READY_HANDLE`はLauncherが直接の子にのみ継承させた
/// パイプハンドル値であり、その子だけに意味を持つ。しかしenv変数はPhase 4aの孫プロセスにも
/// そのまま継承されるため、孫の`init()`が**孫プロセス内では無関係な（あるいは無効な）ハンドル値**
/// へ書き込みを試みてしまう。書き終えた直後に自プロセスのenvから消し、子孫プロセスへ伝播しない
/// ようにする（`HARNESS_COW_WORKSPACE`/`HARNESS_COW_UPPER`は孫にも必要なので残す）。
fn signal_ready() {
    let Some(handle_value) = get_env("HARNESS_COW_READY_HANDLE").and_then(|v| v.parse::<isize>().ok())
    else {
        return;
    };
    let handle = HANDLE(handle_value as *mut c_void);
    let buf = [1u8];
    unsafe {
        let _ = WriteFile(handle, Some(&buf), None, None);
        std::env::remove_var("HARNESS_COW_READY_HANDLE");
    }
}

unsafe extern "system" fn init_thread_proc(_param: *mut c_void) -> u32 {
    INIT_ONCE.call_once(init);
    0
}

/// Phase 4a: 親プロセス側の`hooked_nt_create_user_process`が孫プロセスへ`CreateRemoteThread`で
/// 明示的に呼ぶエクスポート（`#[no_mangle]`必須、`GetProcAddress`で名前解決される）。
/// `DllMain`の内部初期化スレッドとの競合は`INIT_ONCE`が吸収するため、呼び出し順は問わない——
/// この関数のリモートスレッドが終了した時点でフック設置が完了していることだけが保証される
/// （`inject_grandchild`の同期点、モジュールdoc参照）。
///
/// # Safety
/// `CreateRemoteThread`のスレッド開始関数として呼ばれる前提（`LPTHREAD_START_ROUTINE`互換
/// シグネチャ）。`_param`は使用しない。呼び出し元スレッドの状態に依存する処理は行わない。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn harness_cow_init(_param: *mut c_void) -> u32 {
    INIT_ONCE.call_once(init);
    1
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        let _ = SELF_MODULE.set(_hinst.0 as usize);
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

    /// Q9（増分tail再読込）の回帰テスト。`deleted_paths_state`/`ledger_read_offset`は
    /// プロセスグローバルな唯一のsingletonであり、他のテストと並行実行されると相互汚染し得るため、
    /// この1関数内で「初期ロード→兄弟プロセスによる追記を模擬→check_deleted経由での増分反映→
    /// 未完了行（末尾に\nが無い）は次回まで据え置き」まで一通り検証する。
    #[test]
    fn check_deleted_picks_up_incremental_ledger_appends_from_sibling_process() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
        };
        let ledger_path = upper.path().join(COW_OPS_LEDGER_FILENAME);

        // 初期状態: まだ何も削除されていない。
        load_deleted_set(&cfg);
        assert!(check_deleted(&cfg, "sibling_probe.txt", false).is_none());

        // 兄弟プロセス（別スレッドが模擬）が完全な1行を追記した場合、次回の`check_deleted`が
        // それを拾って「削除済み」を返すこと。
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ledger_path)
                .unwrap();
            writeln!(
                f,
                r#"{{"op":"delete","path":"sibling_probe.txt","baseline_hash":"h1","ts_unix_millis":1}}"#
            )
            .unwrap();
        }
        assert!(check_deleted(&cfg, "sibling_probe.txt", false).is_some());

        // 書込み途中（末尾に改行が無い）の不完全な行は、次回まで無視して安全に据え置く。
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&ledger_path)
                .unwrap();
            // 削除の取り消し（再作成）を意味する行を、改行を付けずに書く＝書込み途中を模擬。
            write!(
                f,
                r#"{{"op":"create","path":"sibling_probe.txt","baseline_hash":"h1","ts_unix_millis":2}}"#
            )
            .unwrap();
        }
        assert!(
            check_deleted(&cfg, "sibling_probe.txt", false).is_some(),
            "incomplete (no trailing newline) line must not be consumed yet"
        );

        // 改行を追記して行を完成させると、次回の`check_deleted`が正しく再作成を反映する。
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&ledger_path)
                .unwrap();
            writeln!(f).unwrap();
        }
        assert!(check_deleted(&cfg, "sibling_probe.txt", true).is_none());
    }

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
