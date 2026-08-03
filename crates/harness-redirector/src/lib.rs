//! Tier2a `--cow`（D-30）のRedirector DLL。x64専用・最小スコープ。
//!
//! `plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §13-§19。
//! `ntdll.dll`の`NtCreateFile`/`NtOpenFile`/`NtSetInformationFile`/`NtClose`/
//! `NtQueryFullAttributesFile`/`NtQueryAttributesFile`/`NtQueryDirectoryFile`をinline hook
//! （`retour`クレート、フックの実装品質はセキュリティ保証に影響しない——§13.1の実装方針参照）し、
//! workspace配下への書込操作をCoW upperディレクトリへ誘導しつつ、作成・変更・削除・リネームを
//! 操作台帳（`.harness-cow-ops.jsonl`、`crates/harness-change-ledger`）へ記録する。
//! `NtQueryDirectoryFile`（ディレクトリ列挙）は、セッション中に新規作成したファイルが
//! `Remove-Item`等から「存在しない」と誤認されるバグ（BUG-047）の修正として追加された——
//! 他のフックがworkspaceとupperを個別パス指定で正しく振り分けていても、ディレクトリを
//! **列挙**する経路だけは別物であり、upper側だけに存在するファイルはこれをフックしない限り
//! 一覧に現れない（§7.8「ディレクトリ列挙」参照）。
//!
//! **境界ではなく誘導**（`plans/DESIGN-SANDBOX.md` D-01/D-30）: このDLLが無効化・回避・
//! アンロードされても、workspace本体はAppContainerのACLでread-only付与済みのため、書込は
//! `STATUS_ACCESS_DENIED`でfail-closeする。このDLLの役割は、フックが機能する場合に
//! `ACCESS_DENIED`を回避してCoW upperへ書けるようにする「利便性」のみ。
//!
//! ## 設定の伝播（2経路、BUG-045のF2以降）
//!
//! * **直接の子**: 環境変数（下記`HARNESS_COW_*`）。Launcherが子のenv blockへ設定する。
//! * **孫以降**: 親世代のDLLが`harness_cow_init`のスレッドパラメータへ渡す設定ブロブ
//!   （[`serialize_config_blob`]、`VirtualAllocEx`+`WriteProcessMemory`で相手のアドレス空間へ
//!   書く）。**envに依存しない**ため、途中の世代が自前のenv blockを組み立てて子を起動しても
//!   （`hooked_create_process_w`は設計どおり`lpEnvironment`を素通しする）設定が途切れない。
//!   パラメータがNULL/不正なら従来どおり環境変数へフォールバックする（[`resolve_config`]）。
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
//!
//! ## Phase 4b: 32bit（WOW64）ターゲットへの再注入
//!
//! 32bitターゲット（WOW64、x64ホスト上のx86プロセス）は`IsWow64Process2`で判定し、
//! [`wow64::inject_grandchild_wow64`]（別モジュール、詳細はそちらのモジュールdoc参照）へ
//! 委譲する。x64専用のこのDLLをそのまま`LoadLibraryW`することはできない
//! （`ERROR_BAD_EXE_FORMAT`相当で失敗する）ため、`harness.exe`と同じディレクトリに配置された
//! 兄弟の`harness_redirector_x86.dll`（i686ビルド）を注入する。x86→x64（32bitプロセスから
//! 64bit孫プロセスを起動するケース）はHeaven's Gate相当の実装コストに見合わないため対象外とし、
//! 素通し（警告台帳へ記録するのみ）とする。

#![cfg(windows)]

mod wow64;

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use harness_change_ledger::{now_millis, parse_ledger, store, ChangeOp, COW_OPS_LEDGER_FILENAME};
use retour::GenericDetour;
use windows::core::{PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Wdk::Foundation::{OBJECT_ATTRIBUTES, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION};
use windows::Wdk::Foundation::NtQueryObject;
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileDispositionInformationEx, FileRenameInformation,
    FileRenameInformationEx, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX, FILE_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    BOOL, CloseHandle, HANDLE, HMODULE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_NO_MORE_FILES, STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_FLAGS_AND_ATTRIBUTES,
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
    CreateRemoteThread, CreateThread, GetCurrentProcessId, GetExitCodeThread, ResumeThread,
    WaitForSingleObject, PROCESS_INFORMATION, STARTUPINFOA, THREAD_CREATION_FLAGS,
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

/// ディレクトリ列挙（`FindFirstFile`/`FindNextFile`、.NETの`Directory.EnumerateFileSystemEntries`、
/// PowerShellの`Remove-Item`/`Test-Path`のパス解決層が最終的にたどり着く経路）。BUG-047:
/// このAPIだけ未フックだったため、セッション中にupper側だけへ新規作成されたファイルが
/// ディレクトリ列挙結果に現れず、`Remove-Item`等が「存在しない」と誤判定していた
/// （個別パス指定の`NtCreateFile`/`NtQueryAttributesFile`等は元々正しくupper優先だった）。
type NtQueryDirectoryFileFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    windows::Win32::System::IO::PIO_APC_ROUTINE,
    *const c_void,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    FILE_INFORMATION_CLASS,
    windows::Win32::Foundation::BOOLEAN,
    *const windows::Win32::Foundation::UNICODE_STRING,
    windows::Win32::Foundation::BOOLEAN,
) -> NTSTATUS;

/// BUG-048（F3）: Windows 10 1709以降、`FindFirstFileEx`系の実際の経路は`NtQueryDirectoryFile`
/// ではなく`NtQueryDirectoryFileEx`（`RestartScan`/`ReturnSingleEntry`の2つのBOOLEAN引数の
/// 代わりに`QueryFlags: u32`を取る、`SL_RESTART_SCAN`/`SL_RETURN_SINGLE_ENTRY`ビット）。
type NtQueryDirectoryFileExFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    windows::Win32::System::IO::PIO_APC_ROUTINE,
    *const c_void,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    FILE_INFORMATION_CLASS,
    u32,
    *const windows::Win32::Foundation::UNICODE_STRING,
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

/// 残課題#5（Phase 4a以降）: `kernel32!CreateProcessA`。`CreateProcessWFn`と同じ引数個数・
/// 意味だが、文字列引数がANSI（`PCSTR`/`PSTR`）になる。`CreateProcessA`は内部で
/// `CreateProcessW`を経由せず直接`CreateProcessInternalW`（より下位の共通API）を呼ぶため
/// （一般的なWindows内部実装のknown-how、実装側のコードコメントとも符合）、既存の
/// `CreateProcessW`/`CreateProcessAsUserW`フックは`CreateProcessA`呼び出しを完全に素通しして
/// いた。同じ「オリジナルが完全に返った後に注入する」安全なタイミング（BUG-041の教訓）を
/// そのまま適用する。
type CreateProcessAFn = unsafe extern "system" fn(
    PCSTR,
    PSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// 残課題#5: `kernel32!WinExec`。`UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)`。
/// `CreateProcessA`/`W`と違い`dwCreationFlags`も`lpProcessInformation`も呼び出し元へ一切
/// 公開しないため、この関数自身のシグネチャ経由では「suspendedで起動して孫へ注入してから
/// resumeする」ことができない。そのため`hooked_win_exec`は本物の`WinExec`を呼ばず、
/// 代わりに（フック済みの）`CreateProcessA`相当のロジック（`hooked_create_process_a`関数を
/// 直接呼ぶ、`GenericDetour::call`＝オリジナル関数呼び出しではない点に注意）を自前で実行し、
/// 得られた`PROCESS_INFORMATION`を注入に使ってから、WinExecの戻り値規約（成功時は32より
/// 大きい値、失敗時はエラーコード相当の32以下の値）に変換する。
type WinExecFn = unsafe extern "system" fn(PCSTR, u32) -> u32;

/// Win32 `PROCESS_CREATION_FLAGS`の`CREATE_SUSPENDED`ビット（`windows`クレートの
/// `windows::Win32::System::Threading::CREATE_SUSPENDED`と同値だが、フック関数の引数型が
/// 生の`u32`のためリテラルとして持つ）。
const CREATE_SUSPENDED_FLAG: u32 = 0x0000_0004;

struct Config {
    workspace_root: PathBuf,
    upper_dir: PathBuf,
    /// Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴の
    /// ルート一覧（DOS形式、正規化前）。ここに含まれるパスへの書込は、workspace内と同じ
    /// `_ext/<key>`経由の操作台帳captureの対象になる（境界＝ACLはfs-allowが既に張っている、
    /// ここはあくまで透過性・変更の可視化のためのcaptureであってACL自体を変えない）。
    ext_capture_roots: Vec<PathBuf>,
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
static QUERY_DIR_HOOK: OnceLock<GenericDetour<NtQueryDirectoryFileFn>> = OnceLock::new();
static QUERY_DIR_EX_HOOK: OnceLock<GenericDetour<NtQueryDirectoryFileExFn>> = OnceLock::new();
static CREATE_PROCESS_W_HOOK: OnceLock<GenericDetour<CreateProcessWFn>> = OnceLock::new();
static CREATE_PROCESS_AS_USER_W_HOOK: OnceLock<GenericDetour<CreateProcessAsUserWFn>> =
    OnceLock::new();
static CREATE_PROCESS_A_HOOK: OnceLock<GenericDetour<CreateProcessAFn>> = OnceLock::new();
static WIN_EXEC_HOOK: OnceLock<GenericDetour<WinExecFn>> = OnceLock::new();

/// このDLL自身がロードされているモジュールベースアドレス（`DllMain`の`hinst`引数、数値上は
/// そのプロセスにおけるロードベースアドレスと一致する——Windowsの仕様）。孫プロセス内での
/// 自DLLの相対オフセット（RVA）を、自プロセスの`GetProcAddress`結果から逆算するために使う
/// （Phase 4a、`inject_grandchild`参照）。
static SELF_MODULE: OnceLock<usize> = OnceLock::new();

/// `init()`の同時実行を防ぐ。孫プロセスでは`DllMain`の`DLL_PROCESS_ATTACH`が自動的に起動する
/// 内部初期化スレッドと、Launcher役の親プロセス側から`CreateRemoteThread`で明示的に呼ばれる
/// `harness_cow_init`エクスポートの2経路が同一プロセス内で競合し得るため直列化する
/// （Phase 4a、モジュールdoc参照）。
///
/// BUG-045: 以前は`std::sync::Once`だったが、**失敗した初期化まで確定させてしまう**ため
/// `Mutex`+[`INIT_SUCCEEDED`]へ置き換えた。`DllMain`側のスレッド（設定を環境変数からしか
/// 取れない）が先に走って失敗しても、後から来る`harness_cow_init`（注入パラメータで設定を
/// 直接受け取れる、F2）が再試行できる必要がある。成功は冪等に一度だけ確定する。
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// `init()`が最後まで成功（6つのファイルフック設置完了）したか。`harness_cow_init`の戻り値
/// そのものであり、注入側（`inject_grandchild`／`wow64::remote_call_init`）が
/// `GetExitCodeThread`で読む唯一の成否シグナルになる（BUG-045のF1）。
static INIT_SUCCEEDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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

/// ディレクトリハンドル値→マージ済み列挙の再開カーソル（BUG-047）。`NtQueryDirectoryFile`は
/// 同一ハンドルに対し`RestartScan=FALSE`で繰り返し呼ばれてページングするため、次に返す
/// マージ済みエントリの先頭インデックスをハンドルごとに覚えておく必要がある
/// （`handle_paths`と同じくハンドル値をキーにする一時マップ、`NtClose`で確実に取り除く）。
/// マージ結果自体は毎回`std::fs::read_dir`から再計算するため、呼び出しの合間にディレクトリの
/// 中身が変化すると位置がずれ得るが、これは許容する既知の簡略化とする（同期的な単一セッション
/// 内での列挙という想定スコープでは実害が薄い）。
fn dir_query_cursor() -> &'static Mutex<HashMap<isize, usize>> {
    static C: OnceLock<Mutex<HashMap<isize, usize>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
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

/// Phase 4: 既にこのプロセスで`.harness-cow-denied.jsonl`へ記録済みのパス集合（同一パスへの
/// 繰り返し拒否試行で台帳が肥大しないようにする、プロセス内のみのdedup——別プロセス/セッションで
/// 再度記録され得るが実害は無い）。
fn denied_paths_state() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashSet::new()))
}

/// ACLで実際に拒否された（`STATUS_ACCESS_DENIED`）workspace外書込試行を
/// `<upper_dir>/.harness-cow-denied.jsonl`へ1行追記する（Phase 4、設計書§19.8）。
/// 同一パスは初回のみ記録する。追記の実体は`store::append_denied_entry`
/// （`harness cow audit`の読み側と型を共有、host側で拒否を検知する経路が将来できても
/// 同じ形式で書けるようにするため）。
fn record_denied_attempt(cfg: &Config, path: &Path, access_mask: u32) {
    let path_str = path.to_string_lossy().replace('\\', "/");
    {
        let mut g = denied_paths_state().lock().unwrap();
        if !g.insert(path_str.clone()) {
            return;
        }
    }
    let pid = unsafe { GetCurrentProcessId() };
    store::append_denied_entry(&cfg.upper_dir, &path_str, access_mask, pid);
}

/// `deleted_paths_state`を最後に同期した時点での台帳ファイルの読み込み済みバイトオフセット。
fn ledger_read_offset() -> &'static Mutex<u64> {
    static O: OnceLock<Mutex<u64>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(0))
}

fn get_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// 注入パラメータ（`harness_cow_init`の引数）で運ぶ設定のバイト列上限。実際の中身は
/// 3行のパス文字列なので通常は数百バイトで、この上限は「NUL終端が壊れていた場合に
/// 無限に読み進めない」ための安全弁。
const CONFIG_BLOB_MAX_LEN: usize = 64 * 1024;

/// 注入パラメータで運ぶ設定のシリアライズ（BUG-045のF2）。`\n`区切り3行・NUL終端のUTF-8:
///
/// ```text
/// <workspace_root>\n<upper_dir>\n<ext_capture_roots を ';' で連結>\0
/// ```
///
/// 環境変数（`HARNESS_COW_*`）と等価な情報を、**子孫プロセスのenv blockに依存せずに**
/// 渡すための唯一の形式。途中の世代が自前のenv blockを組み立てて子を起動しても設定が
/// 途切れないようにする（モジュールdoc「設定の伝播」参照）。
fn serialize_config_blob(cfg: &Config) -> Vec<u8> {
    let ext = cfg
        .ext_capture_roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(";");
    let mut bytes = format!(
        "{}\n{}\n{}",
        cfg.workspace_root.to_string_lossy(),
        cfg.upper_dir.to_string_lossy(),
        ext
    )
    .into_bytes();
    bytes.push(0);
    bytes
}

/// [`serialize_config_blob`]の逆。自プロセス内のNUL終端バイト列を指すポインタから設定を復元する。
///
/// # Safety
/// `param`はNULLか、自プロセスで読み取り可能なNUL終端バイト列の先頭でなければならない
/// （注入側が`VirtualAllocEx`+`WriteProcessMemory`で書き込んだ領域）。
unsafe fn deserialize_config_blob(param: *const u8) -> Option<Config> {
    if param.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < CONFIG_BLOB_MAX_LEN {
        if unsafe { *param.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 || len >= CONFIG_BLOB_MAX_LEN {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(param, len) };
    parse_config_blob(&String::from_utf8_lossy(bytes))
}

/// 復元のうち文字列解析だけを切り出した部分（単体テスト可能にするため）。
fn parse_config_blob(text: &str) -> Option<Config> {
    let mut lines = text.split('\n');
    let workspace_root = lines.next().filter(|s| !s.is_empty())?;
    let upper_dir = lines.next().filter(|s| !s.is_empty())?;
    let ext_capture_roots = lines
        .next()
        .unwrap_or("")
        .split(';')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    Some(Config {
        workspace_root: PathBuf::from(workspace_root),
        upper_dir: PathBuf::from(upper_dir),
        ext_capture_roots,
    })
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
/// BUG-048: `FILE_GENERIC_WRITE`は使わない——`GENERIC_WRITE`をファイルへマップした結果の
/// 複合マスクで、`SYNCHRONIZE`(0x10_0000)・`READ_CONTROL`(0x2_0000)を含む。Win32の
/// `CreateFileW`は**読み取り専用**openでも常に`SYNCHRONIZE`を要求する（同期I/O前提のため）ため、
/// これを含むマスクで判定すると`Get-ChildItem`のディレクトリopenや`Get-Content`の読み取りopen
/// まで「書込意図あり」と誤判定してしまう（実機で確認: `desired_access=0x100001`
/// `=FILE_LIST_DIRECTORY|SYNCHRONIZE`が`write_intent=true`になっていた）。書込を意味する
/// ビットだけを明示的に列挙すること。
fn is_write_intent(desired_access: u32, create_disposition: Option<u32>) -> bool {
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    let write_mask = FILE_WRITE_DATA.0
        | FILE_APPEND_DATA.0
        | FILE_WRITE_ATTRIBUTES.0
        | FILE_WRITE_EA.0
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;
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

/// BUG-048（F2）: `write_intent`が立っていても、`create_options`に`FILE_DIRECTORY_FILE`が
/// 付いた**ディレクトリのopen**は、新規作成dispositionでない限りcopy-up/リダイレクト対象から
/// 除外する。`Remove-Item`のパス解決やcwdの保持等、既存ディレクトリを`DELETE`/
/// `WRITE_ATTRIBUTES`アクセス込みで開くケースがあり、これをリダイレクトすると
/// `upper_dir`側に実体の無いディレクトリを開こうとして失敗したり、`copy_up`が
/// （ファイルではないため中身を伴わない）偽の`create`/`modify`エントリを台帳へ積んだりする
/// （実機で`ls .harness`後に`.harness-cow-ops.jsonl`へ`create .harness`が誤記録されるのを確認）。
/// `NtOpenFile`は`create_disposition`を持たない（常に`FILE_OPEN`相当）ため`None`を渡すと
/// 常に除外側になる——既存ディレクトリを開くだけの操作しか無いことと整合する。
fn should_redirect_write(
    write_intent: bool,
    create_options: u32,
    create_disposition: Option<u32>,
) -> bool {
    if !write_intent {
        return false;
    }
    let is_dir_open = create_options & FILE_DIRECTORY_FILE.0 != 0;
    if !is_dir_open {
        return true;
    }
    matches!(create_disposition, Some(d) if is_create_capable_disposition(d))
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

/// `path`が`ext_capture_roots`のいずれか配下であれば、`(ext_key, 正規化済み絶対パス文字列)`を
/// 返す（Phase 3、設計書§19.8）。`workspace_relative`と同じ大小無視・パス区切り境界判定。
fn ext_relative(cfg: &Config, path: &Path) -> Option<(String, String)> {
    let path_lc = path.to_string_lossy().to_ascii_lowercase();
    for root in &cfg.ext_capture_roots {
        let root_lc = root.to_string_lossy().to_ascii_lowercase();
        let is_under = path_lc == root_lc
            || (path_lc.starts_with(&root_lc) && path_lc.as_bytes().get(root_lc.len()) == Some(&b'\\'));
        if is_under {
            let original = store::normalize_abs_path(&path.to_string_lossy());
            let key = store::ext_key(&original).ok()?;
            return Some((key, original));
        }
    }
    None
}

/// `workspace_relative`/`ext_relative`の判定結果を統一する。`rel`は`cfg.upper_dir.join(&rel)`で
/// 常に正しいupper側実体パスになる（workspace内なら`<rel>`そのまま、`_ext`ならcapture root配下
/// への写像`_ext/<key>`）。`ledger_key`は操作台帳・`check_deleted`・ハンドル対応表で使う識別子
/// （workspace内ならworkspace相対パス、`_ext`なら正規化済み絶対パス文字列——host側`apply()`が
/// `workspace_root.join(&path)`でそのまま実ターゲットを求められる形、設計書§19.8）。
struct Classified {
    rel: PathBuf,
    ledger_key: String,
}

fn classify_target(cfg: &Config, path: &Path) -> Option<Classified> {
    if let Some(rel) = workspace_relative(cfg, path) {
        let ledger_key = rel_to_string(&rel);
        return Some(Classified { rel, ledger_key });
    }
    let (key, original) = ext_relative(cfg, path)?;
    Some(Classified {
        rel: Path::new("_ext").join(&key),
        ledger_key: original,
    })
}

/// `ledger_key`（`Classified::ledger_key`、workspace相対パスまたは`_ext`の正規化済み絶対パス）を、
/// そのセッションで最初に触った瞬間の実内容ハッシュへ解決する（キャッシュ済みならそれを返す、
/// 設計書§19.5）。権威となる計算・baselineミラー書込は`harness_change_ledger::store`（`_ext`は
/// `baseline_hash_and_mirror_ext`、workspace内は`baseline_hash_and_mirror`）が唯一の実装
/// （host内蔵ツール`write_file`/`edit_file`側も同じ関数を呼ぶ、BUG-042の再発防止）——ここでの
/// `baseline_cache`はDLLのホットパス向けのメモ化に過ぎない。`ledger_key`が絶対パスかどうかで
/// `_ext`かworkspace内かを判定する（workspace相対パスは`check_relative_path`相当の生成元
/// （`workspace_relative`）が絶対パスを作らないため、この判定で一意に決まる）。
fn baseline_hash_for(cfg: &Config, ledger_key: &str) -> Option<String> {
    let cache = baseline_cache();
    let mut guard = cache.lock().unwrap();
    if let Some(v) = guard.get(ledger_key) {
        return v.clone();
    }
    let hash = if Path::new(ledger_key).is_absolute() {
        store::ext_key(ledger_key)
            .ok()
            .and_then(|key| store::baseline_hash_and_mirror_ext(&cfg.upper_dir, ledger_key, &key))
    } else {
        store::baseline_hash_and_mirror(&cfg.upper_dir, &cfg.workspace_root, ledger_key)
    };
    guard.insert(ledger_key.to_string(), hash.clone());
    hash
}

/// 台帳（`<upper_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記し、メモリ上の削除済み集合も
/// 更新する。追記の実体は`store::append_entry`（host側と共有、設計書§19.2「追記の並行性」）。
fn append_ledger_entry(cfg: &Config, op: ChangeOp, rel: &str, baseline_hash: Option<String>) {
    store::append_entry(&cfg.upper_dir, op, rel, baseline_hash);
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
///
/// **`/`→`\`正規化が必須**（Phase 3実機E2Eで発見）: `classify_target`のPhase 3 `_ext`分岐は
/// `store::ext_key()`が返す`/`区切りのキー文字列（例`"c/harness-.../probe.txt"`）を
/// `PathBuf::join`で連結するが、`PathBuf::join`は引数中の`/`を`\`へ**変換しない**
/// （`Path`のcomponent解析は`/`も区切りとして認識するが、`to_string_lossy()`が返す生の
/// 内部表現は連結時の元の区切り文字をそのまま保持する）。Win32層（`CreateFileW`等、
/// `std::fs`はこちらを使う）は`/`を`\`と同様に解釈するため気付きにくいが、NT名前空間
/// （`NtCreateFile`が見るのはこちら）は`/`を区切りとして認識せず不正な名前として拒否する
/// （実機E2Eで`STATUS_OBJECT_NAME_INVALID`を確認）。ここで一括正規化することで、
/// 呼び出し元がどう`PathBuf`を組み立てても安全にする。
fn nt_path_wide(upper_path: &Path) -> Vec<u16> {
    let normalized = upper_path.to_string_lossy().replace('/', "\\");
    let nt_path = format!(r"\??\{normalized}");
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
            if let Some(Classified { rel, ledger_key: rel_str }) = classify_target(cfg, &path) {
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
                if should_redirect_write(
                    is_write_intent(desired_access.0, Some(create_disposition.0)),
                    create_options.0,
                    Some(create_disposition.0),
                ) {
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
            } else if is_write_intent(desired_access.0, Some(create_disposition.0)) {
                // Phase 4（設計書§19.8）: workspace内でもext capture root配下でもない絶対パスへの
                // 書込意図。素通しさせ、実際にACLで拒否された（`STATUS_ACCESS_DENIED`）場合のみ
                // 監査台帳へ記録する（境界自体はACLが既に保証しているので、ここでは何も遮断/
                // 誘導しない——フックは境界にしない、D-01）。
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
                if status == STATUS_ACCESS_DENIED {
                    record_denied_attempt(cfg, &path, desired_access.0);
                }
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
            if let Some(Classified { rel, ledger_key: rel_str }) = classify_target(cfg, &path) {
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
                if should_redirect_write(is_write_intent(desired_access, None), open_options, None) {
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
            } else if is_write_intent(desired_access, None) {
                // Phase 4（設計書§19.8）: `hooked_nt_create_file`と同じ理由。
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
                if status == STATUS_ACCESS_DENIED {
                    record_denied_attempt(cfg, &path, desired_access);
                }
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
        // `nt_path_wide`と同じ理由で`/`→`\`正規化が必須（Phase 3実機E2Eで発見）。
        let normalized = new_upper_path.to_string_lossy().replace('/', "\\");
        let nt_path = format!(r"\??\{normalized}");
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
    let Classified { rel: new_rel, ledger_key: new_rel_str } = classify_target(cfg, &new_path)?;
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
            dir_query_cursor().lock().unwrap().remove(&key);
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
            if let Some(Classified { rel, ledger_key: rel_str }) = classify_target(cfg, &path) {
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
            if let Some(Classified { rel, ledger_key: rel_str }) = classify_target(cfg, &path) {
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

/// BUG-047: ディレクトリ列挙のマージ・マーシャルロジック（フックにもDLL注入にも依存しない
/// 純粋関数のみを持つ、`tempfile::tempdir()`だけで単体テスト可能——設計書§7.8「Workspaceと
/// Sandboxのディレクトリ列挙をマージして返す」の実装）。
mod dir_merge {
    use super::{FILE_INFORMATION_CLASS, HashMap, HashSet, Path};
    use windows::Wdk::Storage::FileSystem::{
        FileBothDirectoryInformation, FileDirectoryInformation, FileFullDirectoryInformation,
        FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, FileNamesInformation,
        FILE_BOTH_DIR_INFORMATION, FILE_DIRECTORY_INFORMATION, FILE_FULL_DIR_INFORMATION,
        FILE_ID_BOTH_DIR_INFORMATION, FILE_ID_FULL_DIR_INFORMATION, FILE_NAMES_INFORMATION,
    };

    /// このフックがマージ対象として自前で構築する`FileInformationClass`か（Stage 0の決定）。
    /// それ以外（`FileIdExtdDirectoryInformation`等の稀なクラス）は素通しする——このフックは
    /// ACL境界ではなく可視性の利便機能であり（`docs/SECURITY-PRINCIPLES.md` P-02）、
    /// 対応漏れは修正前の（見えない）挙動に戻るだけで安全側。
    pub(super) fn is_supported_class(class: FILE_INFORMATION_CLASS) -> bool {
        matches!(
            class,
            c if c == FileDirectoryInformation
                || c == FileFullDirectoryInformation
                || c == FileBothDirectoryInformation
                || c == FileNamesInformation
                || c == FileIdBothDirectoryInformation
                || c == FileIdFullDirectoryInformation
        )
    }

    /// base（実workspace/`_ext`実体）側とupper（CoW）側のディレクトリ実体1件分のメタデータ。
    #[derive(Clone)]
    pub(super) struct MergedEntry {
        pub name: Vec<u16>,
        pub file_attributes: u32,
        pub creation_time: i64,
        pub last_access_time: i64,
        pub last_write_time: i64,
        pub change_time: i64,
        pub end_of_file: i64,
        pub allocation_size: i64,
    }

    fn read_entries(dir: &Path) -> HashMap<String, std::fs::Metadata> {
        let mut out = HashMap::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
                out.insert(name, meta);
            }
        }
        out
    }

    fn to_merged_entry(name: &str, meta: &std::fs::Metadata) -> MergedEntry {
        use std::os::windows::fs::MetadataExt as _;
        let end_of_file = meta.len() as i64;
        // NTFSクラスタサイズ相当（4096バイト）へ切り上げる近似値。実クラスタサイズは
        // ボリューム依存だが、このフィールドを厳密参照する呼び出し元は稀なため簡略化する。
        let allocation_size = (end_of_file + 4095) / 4096 * 4096;
        MergedEntry {
            name: name.encode_utf16().collect(),
            file_attributes: meta.file_attributes(),
            creation_time: meta.creation_time() as i64,
            last_access_time: meta.last_access_time() as i64,
            last_write_time: meta.last_write_time() as i64,
            change_time: meta.last_write_time() as i64,
            end_of_file,
            allocation_size,
        }
    }

    /// `rel_prefix`（`/`区切りのworkspace相対、ルート自身なら空文字列）配下の1階層について、
    /// upper側とbase側をマージした一覧を、設計書§7.8の優先順位
    /// （1. whiteout済みは除外 2. upper優先 3. 同名upperが無いbaseのみ採用）で返す。
    /// 名前の大小無視での重複排除・昇順ソート済み（呼び出し元の複数回呼び出しをまたぐカーソルが
    /// 安定した順序を前提にできるようにするため）。
    pub(super) fn merge_dir_entries(
        base_dir: &Path,
        upper_dir: &Path,
        deleted: &HashSet<String>,
        rel_prefix: &str,
    ) -> Vec<MergedEntry> {
        let upper_entries = read_entries(upper_dir);
        let base_entries = read_entries(base_dir);
        let mut seen_lc: HashSet<String> = HashSet::new();
        let mut merged: Vec<(String, std::fs::Metadata)> = Vec::new();

        let child_rel = |name: &str| -> String {
            if rel_prefix.is_empty() {
                name.to_string()
            } else {
                format!("{rel_prefix}/{name}")
            }
        };

        for (name, meta) in upper_entries {
            if deleted.contains(&child_rel(&name)) {
                continue;
            }
            seen_lc.insert(name.to_ascii_lowercase());
            merged.push((name, meta));
        }
        for (name, meta) in base_entries {
            let lc = name.to_ascii_lowercase();
            if seen_lc.contains(&lc) || deleted.contains(&child_rel(&name)) {
                continue;
            }
            seen_lc.insert(lc);
            merged.push((name, meta));
        }
        merged.sort_by_key(|a| a.0.to_ascii_lowercase());
        merged.iter().map(|(name, meta)| to_merged_entry(name, meta)).collect()
    }

    /// DOSワイルドカード（`*`＝任意長・`?`＝任意1文字）の簡易大小無視マッチ。`NtQueryDirectoryFile`
    /// の`FileName`引数（例: `Get-ChildItem -Filter *.txt`）に対応するための簡略実装——短縮名
    /// （8.3形式）の特殊扱い等、DOSワイルドカードの厳密な歴史的仕様までは再現しない
    /// （既知の簡略化、Stage 0で観測された実クエリが`*`単体のみだった場合はこの関数自体使われない）。
    pub(super) fn wildcard_match(pattern: &str, name: &str) -> bool {
        if pattern.is_empty() || pattern == "*" {
            return true;
        }
        fn helper(p: &[u8], n: &[u8]) -> bool {
            match (p.first(), n.first()) {
                (None, None) => true,
                (Some(b'*'), _) => helper(&p[1..], n) || (!n.is_empty() && helper(p, &n[1..])),
                (Some(b'?'), Some(_)) => helper(&p[1..], &n[1..]),
                (Some(pc), Some(nc)) if pc.eq_ignore_ascii_case(nc) => {
                    helper(&p[1..], &n[1..])
                }
                _ => false,
            }
        }
        helper(pattern.as_bytes(), name.as_bytes())
    }

    fn align8(n: usize) -> usize {
        (n + 7) & !7
    }

    /// 1エントリぶんの可変長レコードをバッファへ書き込む。`header_offset`は
    /// `std::mem::offset_of!(T, FileName)`、`write_header`はNextEntryOffset/FileNameLength以外の
    /// 固定長フィールドを埋めるクロージャ。戻り値は書き込んだバイト数（8バイト境界に切り上げ済み、
    /// 実際に確保する領域はこのバイト数——NTの規約でレコード間に`NextEntryOffset`分のパディングが
    /// 入り得るため、次のレコードもこのアライメントを前提にしてよい）。
    fn write_record(
        buf: &mut [u8],
        cursor: usize,
        header_offset: usize,
        entry: &MergedEntry,
        write_header: impl FnOnce(*mut u8),
    ) -> Option<usize> {
        let name_bytes_len = entry.name.len() * 2;
        let record_len = align8(header_offset + name_bytes_len);
        if cursor + record_len > buf.len() {
            return None;
        }
        let ptr = buf[cursor..].as_mut_ptr();
        // ゼロ初期化してから固定長ヘッダ・可変長ファイル名を書く（未使用のパディング部分に
        // 前回の呼び出しの残骸が残らないようにする）。
        unsafe { std::ptr::write_bytes(ptr, 0, record_len) };
        write_header(ptr);
        let name_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(entry.name.as_ptr() as *const u8, name_bytes_len) };
        buf[cursor + header_offset..cursor + header_offset + name_bytes_len]
            .copy_from_slice(name_bytes);
        Some(record_len)
    }

    /// `merged[start..]`から、`class`の型でバッファへ入るだけレコードを書き込む。
    /// `return_single_entry`なら最大1件。戻り値は`(書き込んだバイト数, 消費したエントリ数)`。
    /// 全件書ける場合と一部しか書けない場合の両方に対応し、後者でも部分的な書き込み結果を
    /// 呼び出し元がそのまま`STATUS_SUCCESS`として返せるようにする（NT既定の挙動——
    /// `STATUS_BUFFER_OVERFLOW`は「1件も書けなかった」場合専用）。
    pub(super) fn marshal_entries(
        buf: &mut [u8],
        class: FILE_INFORMATION_CLASS,
        merged: &[MergedEntry],
        start: usize,
        return_single_entry: bool,
    ) -> (usize, usize) {
        let mut cursor = 0usize;
        let mut consumed = 0usize;
        let mut last_record_start: Option<usize> = None;
        for entry in &merged[start..] {
            let header_offset = if class == FileDirectoryInformation {
                std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileName)
            } else if class == FileFullDirectoryInformation {
                std::mem::offset_of!(FILE_FULL_DIR_INFORMATION, FileName)
            } else if class == FileBothDirectoryInformation {
                std::mem::offset_of!(FILE_BOTH_DIR_INFORMATION, FileName)
            } else if class == FileNamesInformation {
                std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName)
            } else if class == FileIdBothDirectoryInformation {
                std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName)
            } else {
                // FileIdFullDirectoryInformation（is_supported_classで既に絞り込み済み）。
                std::mem::offset_of!(FILE_ID_FULL_DIR_INFORMATION, FileName)
            };
            let write_header = |ptr: *mut u8| unsafe {
                if class == FileDirectoryInformation {
                    let h = ptr as *mut FILE_DIRECTORY_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).CreationTime = entry.creation_time;
                    (*h).LastAccessTime = entry.last_access_time;
                    (*h).LastWriteTime = entry.last_write_time;
                    (*h).ChangeTime = entry.change_time;
                    (*h).EndOfFile = entry.end_of_file;
                    (*h).AllocationSize = entry.allocation_size;
                    (*h).FileAttributes = entry.file_attributes;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                } else if class == FileFullDirectoryInformation {
                    let h = ptr as *mut FILE_FULL_DIR_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).CreationTime = entry.creation_time;
                    (*h).LastAccessTime = entry.last_access_time;
                    (*h).LastWriteTime = entry.last_write_time;
                    (*h).ChangeTime = entry.change_time;
                    (*h).EndOfFile = entry.end_of_file;
                    (*h).AllocationSize = entry.allocation_size;
                    (*h).FileAttributes = entry.file_attributes;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                    (*h).EaSize = 0;
                } else if class == FileBothDirectoryInformation {
                    let h = ptr as *mut FILE_BOTH_DIR_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).CreationTime = entry.creation_time;
                    (*h).LastAccessTime = entry.last_access_time;
                    (*h).LastWriteTime = entry.last_write_time;
                    (*h).ChangeTime = entry.change_time;
                    (*h).EndOfFile = entry.end_of_file;
                    (*h).AllocationSize = entry.allocation_size;
                    (*h).FileAttributes = entry.file_attributes;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                    (*h).EaSize = 0;
                    (*h).ShortNameLength = 0;
                } else if class == FileNamesInformation {
                    let h = ptr as *mut FILE_NAMES_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                } else if class == FileIdBothDirectoryInformation {
                    let h = ptr as *mut FILE_ID_BOTH_DIR_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).CreationTime = entry.creation_time;
                    (*h).LastAccessTime = entry.last_access_time;
                    (*h).LastWriteTime = entry.last_write_time;
                    (*h).ChangeTime = entry.change_time;
                    (*h).EndOfFile = entry.end_of_file;
                    (*h).AllocationSize = entry.allocation_size;
                    (*h).FileAttributes = entry.file_attributes;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                    (*h).EaSize = 0;
                    (*h).ShortNameLength = 0;
                    (*h).FileId = 0;
                } else {
                    let h = ptr as *mut FILE_ID_FULL_DIR_INFORMATION;
                    (*h).FileIndex = consumed as u32;
                    (*h).CreationTime = entry.creation_time;
                    (*h).LastAccessTime = entry.last_access_time;
                    (*h).LastWriteTime = entry.last_write_time;
                    (*h).ChangeTime = entry.change_time;
                    (*h).EndOfFile = entry.end_of_file;
                    (*h).AllocationSize = entry.allocation_size;
                    (*h).FileAttributes = entry.file_attributes;
                    (*h).FileNameLength = (entry.name.len() * 2) as u32;
                    (*h).EaSize = 0;
                    (*h).FileId = 0;
                }
            };
            let Some(record_len) = write_record(buf, cursor, header_offset, entry, write_header)
            else {
                break;
            };
            // 直前のレコードのNextEntryOffsetを、いま書いたレコードの開始位置へ設定する
            // （末尾レコードは0のまま——ゼロ初期化済みバッファ、または後段でリセットする）。
            if let Some(prev_start) = last_record_start {
                let prev_header_offset = header_offset; // 同一class内では固定
                let _ = prev_header_offset;
                let prev_ptr = buf[prev_start..].as_mut_ptr() as *mut u32;
                unsafe { *prev_ptr = (cursor - prev_start) as u32 };
            }
            last_record_start = Some(cursor);
            cursor += record_len;
            consumed += 1;
            if return_single_entry {
                break;
            }
        }
        (cursor, consumed)
    }
}

/// `NtQueryDirectoryFile`/`NtQueryDirectoryFileEx`（BUG-047/BUG-048）共通のマージ・
/// マーシャル本体。`handle_paths()`でトラック済みのディレクトリハンドルに対してのみ、
/// upper/base両方をマージした列挙結果を自前で構築して返す（`Some(status)`）。それ以外
/// （未トラックのハンドル・非対応`FileInformationClass`）は`None`を返し、呼び出し元が
/// 元の関数へ完全に素通しする。
///
/// BUG-048（F3）: `FindFirstFileEx`系（.NETの`Directory.EnumerateFileSystemEntries`が
/// 実際に使う経路を含む）はWindows 10 1709以降`ntdll!NtQueryDirectoryFile`ではなく
/// **`NtQueryDirectoryFileEx`**を叩く（本機のntdllで両exportの存在を確認済み）。
/// BUG-047はマージ実装自体は正しかったが`NtQueryDirectoryFile`しかフックしていなかったため、
/// 実運用の列挙経路の多くを素通りしていた（マージが効いていないように見えるバグとして
/// 再発した）。
#[allow(clippy::too_many_arguments)] // NtQueryDirectoryFile(Ex)両方の引数を素通しする性質上、削れない。
unsafe fn try_merged_dir_query(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
    restart_scan: bool,
) -> Option<NTSTATUS> {
    let _guard = ReentryGuard::try_acquire()?;
    let cfg = CONFIG.get()?;
    let handle_key = file_handle.0 as isize;
    let rel_str = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    if !dir_merge::is_supported_class(file_information_class) {
        return None;
    }
    let (base_dir, upper_dir, rel_prefix) = dir_query_roots(cfg, &rel_str)?;
    refresh_deleted_set(cfg);
    let deleted = deleted_paths_state().lock().unwrap().clone();
    let merged = dir_merge::merge_dir_entries(&base_dir, &upper_dir, &deleted, &rel_prefix);
    let pattern = unsafe { filename_filter_string(file_name) };
    let merged: Vec<dir_merge::MergedEntry> = if pattern.is_empty() {
        merged
    } else {
        merged
            .into_iter()
            .filter(|e| dir_merge::wildcard_match(&pattern, &String::from_utf16_lossy(&e.name)))
            .collect()
    };
    let mut cursors = dir_query_cursor().lock().unwrap();
    let start = if restart_scan { 0 } else { *cursors.get(&handle_key).unwrap_or(&0) };
    if start >= merged.len() {
        unsafe {
            (*io_status_block).Anonymous.Status = STATUS_NO_MORE_FILES;
            (*io_status_block).Information = 0;
        }
        return Some(STATUS_NO_MORE_FILES);
    }
    let buf_len = length as usize;
    let out_buf =
        unsafe { std::slice::from_raw_parts_mut(file_information as *mut u8, buf_len) };
    let (bytes_written, consumed) = dir_merge::marshal_entries(
        out_buf,
        file_information_class,
        &merged,
        start,
        return_single_entry,
    );
    if consumed == 0 {
        // 先頭1件すら入らないバッファ長（NT既定の「バッファ不足」応答）。
        return Some(STATUS_BUFFER_OVERFLOW);
    }
    cursors.insert(handle_key, start + consumed);
    drop(cursors);
    unsafe {
        (*io_status_block).Anonymous.Status = NTSTATUS(0);
        (*io_status_block).Information = bytes_written;
    }
    Some(NTSTATUS(0))
}

unsafe extern "system" fn hooked_nt_query_directory_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: windows::Win32::System::IO::PIO_APC_ROUTINE,
    apc_context: *const c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    return_single_entry: windows::Win32::Foundation::BOOLEAN,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
    restart_scan: windows::Win32::Foundation::BOOLEAN,
) -> NTSTATUS {
    if let Some(status) = unsafe {
        try_merged_dir_query(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry.as_bool(),
            file_name,
            restart_scan.as_bool(),
        )
    } {
        return status;
    }
    let hook = QUERY_DIR_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry,
            file_name,
            restart_scan,
        )
    }
}

/// `NtQueryDirectoryFileEx`用の`QueryFlags`ビット（phnt由来、`windows`クレートは未エクスポート）。
const SL_RESTART_SCAN: u32 = 0x0000_0001;
const SL_RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;

unsafe extern "system" fn hooked_nt_query_directory_file_ex(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: windows::Win32::System::IO::PIO_APC_ROUTINE,
    apc_context: *const c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    query_flags: u32,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
) -> NTSTATUS {
    if let Some(status) = unsafe {
        try_merged_dir_query(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
            query_flags & SL_RETURN_SINGLE_ENTRY != 0,
            file_name,
            query_flags & SL_RESTART_SCAN != 0,
        )
    } {
        return status;
    }
    let hook = QUERY_DIR_EX_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            query_flags,
            file_name,
        )
    }
}

/// `handle_key`（`handle_paths()`のディレクトリハンドル用エントリ、`Classified.ledger_key`）から
/// `(base_dir実体パス, upper_dir実体パス, whiteout集合キーのprefix)`を求める。`baseline_hash_for`
/// と同じく、絶対パスなら`_ext`capture root、そうでなければworkspace相対として扱う
/// （設計書§19.8、Stage 2）。ディレクトリ自体が両側どちらにも存在しない場合は`None`
/// （通常起き得ないが、フックの再入・競合等の異常系での安全側フォールバック用）。
fn dir_query_roots(cfg: &Config, rel_str: &str) -> Option<(PathBuf, PathBuf, String)> {
    if Path::new(rel_str).is_absolute() {
        let key = store::ext_key(rel_str).ok()?;
        let upper_dir = cfg.upper_dir.join("_ext").join(&key);
        Some((PathBuf::from(rel_str), upper_dir, rel_str.replace('\\', "/")))
    } else {
        let base_dir = cfg.workspace_root.join(rel_str);
        let upper_dir = cfg.upper_dir.join(rel_str);
        Some((base_dir, upper_dir, rel_str.to_string()))
    }
}

/// `NtQueryDirectoryFile`の`FileName`（ワイルドカードフィルタ、任意）引数をRustの`String`へ。
/// NULLまたは空なら「フィルタ無し」を表す空文字列を返す（`dir_merge::wildcard_match`は
/// 空パターンを常に一致として扱う）。
unsafe fn filename_filter_string(us: *const windows::Win32::Foundation::UNICODE_STRING) -> String {
    if us.is_null() {
        return String::new();
    }
    let us = unsafe { &*us };
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    let len_u16 = (us.Length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) };
    String::from_utf16_lossy(slice)
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

/// BUG-045のF2: 設定ブロブ（[`serialize_config_blob`]）を孫プロセスのアドレス空間へ書き込み、
/// `harness_cow_init`のスレッドパラメータとして渡せるポインタを返す。呼び出し元は
/// `CreateRemoteThread`の終了待ちのあとで`VirtualFreeEx`する責務を持つ。
/// WOW64（32bitターゲット）でも`VirtualAllocEx`は4GB未満のアドレスを返すため同じ経路で使える。
unsafe fn write_remote_config_blob(process: HANDLE, cfg: &Config) -> Option<*mut c_void> {
    let bytes = serialize_config_blob(cfg);
    let remote = unsafe {
        VirtualAllocEx(process, None, bytes.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
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
unsafe fn inject_grandchild(process: HANDLE, cfg: &Config) -> bool {
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
        let is_wow64 = unsafe { wow64::is_wow64_target(pi.hProcess) };
        let injected = if is_wow64 {
            match self_dll_path() {
                Some(x64_dll_path) => unsafe {
                    wow64::inject_grandchild_wow64(pi.hProcess, pi.hThread, &x64_dll_path, cfg)
                },
                None => {
                    debug_log(&format!("{caller}: self_dll_path() failed for wow64 injection"));
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
                 Phase 4b); writes from this process will not be redirected to the CoW upper \
                 directory (workspace stays read-only ACL, so writes fail closed rather than \
                 silently missing the ledger)"
            } else {
                "grandchild redirector re-injection failed or timed out; writes from this \
                 process will not be redirected to the CoW upper directory (workspace stays \
                 read-only ACL, so writes fail closed rather than silently missing the ledger)"
            };
            append_warning_entry(cfg, message);
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

/// 残課題#5: `CreateProcessA`のフック本体。`hooked_create_process_w`と全く同じ構造
/// （`CREATE_SUSPENDED`強制→オリジナル呼び出し→`inject_grandchild_and_maybe_resume`）。
/// `hooked_win_exec`からも（`GenericDetour::call`を経由するのではなく）このRust関数を
/// 直接呼び出す形で再利用する。
unsafe extern "system" fn hooked_create_process_a(
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
unsafe extern "system" fn hooked_win_exec(cmd_line: PCSTR, cmd_show: u32) -> u32 {
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

/// 設定の取得（BUG-045のF2）。注入パラメータ（`harness_cow_init`の引数、非NULLなら正）を
/// 優先し、無ければ環境変数`HARNESS_COW_*`へフォールバックする。Launcherが直接起動する子
/// （`win_appcontainer.rs`の`inject_redirector`）はenv経路、DLL自身が再注入する孫以降は
/// パラメータ経路を通る。
///
/// # Safety
/// `param`は[`deserialize_config_blob`]の要件を満たすこと。
unsafe fn resolve_config(param: *const u8) -> Option<Config> {
    if let Some(cfg) = unsafe { deserialize_config_blob(param) } {
        debug_log(&format!(
            "init: config from injection parameter workspace={:?} upper={:?} ext_roots={:?}",
            cfg.workspace_root, cfg.upper_dir, cfg.ext_capture_roots
        ));
        return Some(cfg);
    }
    debug_log(&format!(
        "init: config from env, HARNESS_COW_WORKSPACE={:?} HARNESS_COW_UPPER={:?}",
        get_env("HARNESS_COW_WORKSPACE"),
        get_env("HARNESS_COW_UPPER")
    ));
    let workspace_root = match get_env("HARNESS_COW_WORKSPACE") {
        Some(v) => PathBuf::from(v),
        None => {
            debug_log("init: HARNESS_COW_WORKSPACE not set, bail");
            return None;
        }
    };
    let upper_dir = match get_env("HARNESS_COW_UPPER") {
        Some(v) => PathBuf::from(v),
        None => {
            debug_log("init: HARNESS_COW_UPPER not set, bail");
            return None;
        }
    };
    // Phase 3（設計書§19.8）: `;`区切りのDOS形式絶対パス一覧。空文字列要素は無視する
    // （`get_env`が空文字列全体は既に`None`扱いにするが、"C:\a;;C:\b"のような中間の
    // 空要素を防御的に無視する）。
    let ext_capture_roots: Vec<PathBuf> = get_env("HARNESS_COW_EXT_ROOTS")
        .map(|v| v.split(';').filter(|s| !s.is_empty()).map(PathBuf::from).collect())
        .unwrap_or_default();
    debug_log(&format!("init: HARNESS_COW_EXT_ROOTS={ext_capture_roots:?}"));
    Some(Config {
        workspace_root,
        upper_dir,
        ext_capture_roots,
    })
}

/// [`init`]を直列化し、**成功だけを確定させる**入口（BUG-045）。既に成功済みなら即`true`
/// （冪等）。失敗は確定させないため、先行した`DllMain`スレッドがenv欠落で失敗しても、
/// 後続の`harness_cow_init(param)`が注入パラメータで再試行できる。
///
/// # Safety
/// `param`は[`resolve_config`]の要件を満たすこと。
unsafe fn ensure_init(param: *const u8) -> bool {
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if INIT_SUCCEEDED.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    let ok = unsafe { init(param) };
    if ok {
        INIT_SUCCEEDED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    ok
}

/// フック設置本体（`DllMain`からは呼ばない、Loader Lock回避のため専用スレッドから呼ぶ、
/// 設計書§13.4）。設定を読み・フックを設置し、成功したらready通知を送る。
/// 失敗時は通知しない——Launcher側は待機タイムアウトでプロセスを終了する
/// （設計書§10.2 既定・§25.1）。
///
/// 戻り値は「6つのファイルフックの設置まで完了したか」。BUG-045のF1修正前はこの成否が
/// 呼び出し元へ一切伝わらず、フック未設置でも注入側が成功と誤判定していた。直接呼ばず
/// [`ensure_init`]経由で使うこと。
///
/// # Safety
/// `param`は[`resolve_config`]の要件を満たすこと。
unsafe fn init(param: *const u8) -> bool {
    let Some(cfg) = (unsafe { resolve_config(param) }) else {
        return false;
    };
    load_deleted_set(&cfg);
    let _ = CONFIG.set(cfg);

    let create_file_addr = match unsafe { resolve_ntdll_export("NtCreateFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtCreateFile) failed, bail");
            return false;
        }
    };
    let open_file_addr = match unsafe { resolve_ntdll_export("NtOpenFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtOpenFile) failed, bail");
            return false;
        }
    };
    let set_info_addr = match unsafe { resolve_ntdll_export("NtSetInformationFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtSetInformationFile) failed, bail");
            return false;
        }
    };
    let close_addr = match unsafe { resolve_ntdll_export("NtClose") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtClose) failed, bail");
            return false;
        }
    };
    let query_full_attr_addr =
        match unsafe { resolve_ntdll_export("NtQueryFullAttributesFile") } {
            Some(a) => a,
            None => {
                debug_log("init: resolve_ntdll_export(NtQueryFullAttributesFile) failed, bail");
                return false;
            }
        };
    let query_attr_addr = match unsafe { resolve_ntdll_export("NtQueryAttributesFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryAttributesFile) failed, bail");
            return false;
        }
    };
    let query_dir_addr = match unsafe { resolve_ntdll_export("NtQueryDirectoryFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryDirectoryFile) failed, bail");
            return false;
        }
    };

    let create_file_fn: NtCreateFileFn = unsafe { std::mem::transmute(create_file_addr) };
    let open_file_fn: NtOpenFileFn = unsafe { std::mem::transmute(open_file_addr) };
    let set_info_fn: NtSetInformationFileFn = unsafe { std::mem::transmute(set_info_addr) };
    let close_fn: NtCloseFn = unsafe { std::mem::transmute(close_addr) };
    let query_full_attr_fn: NtQueryFullAttributesFileFn =
        unsafe { std::mem::transmute(query_full_attr_addr) };
    let query_attr_fn: NtQueryAttributesFileFn = unsafe { std::mem::transmute(query_attr_addr) };
    let query_dir_fn: NtQueryDirectoryFileFn = unsafe { std::mem::transmute(query_dir_addr) };

    let create_detour = match unsafe { GenericDetour::new(create_file_fn, hooked_nt_create_file) }
    {
        Ok(d) => d,
        Err(_) => return false,
    };
    let open_detour = match unsafe { GenericDetour::new(open_file_fn, hooked_nt_open_file) } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let set_info_detour =
        match unsafe { GenericDetour::new(set_info_fn, hooked_nt_set_information_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    let close_detour = match unsafe { GenericDetour::new(close_fn, hooked_nt_close) } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let query_full_attr_detour = match unsafe {
        GenericDetour::new(query_full_attr_fn, hooked_nt_query_full_attributes_file)
    } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let query_attr_detour =
        match unsafe { GenericDetour::new(query_attr_fn, hooked_nt_query_attributes_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    let query_dir_detour =
        match unsafe { GenericDetour::new(query_dir_fn, hooked_nt_query_directory_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    if unsafe { create_detour.enable() }.is_err() {
        debug_log("init: create_detour.enable() failed, bail");
        return false;
    }
    if unsafe { open_detour.enable() }.is_err() {
        debug_log("init: open_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
        }
        return false;
    }
    if unsafe { set_info_detour.enable() }.is_err() {
        debug_log("init: set_info_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
        }
        return false;
    }
    if unsafe { close_detour.enable() }.is_err() {
        debug_log("init: close_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
        }
        return false;
    }
    if unsafe { query_full_attr_detour.enable() }.is_err() {
        debug_log("init: query_full_attr_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
        }
        return false;
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
        return false;
    }
    if unsafe { query_dir_detour.enable() }.is_err() {
        debug_log("init: query_dir_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
            let _ = query_full_attr_detour.disable();
            let _ = query_attr_detour.disable();
        }
        return false;
    }
    let _ = CREATE_FILE_HOOK.set(create_detour);
    let _ = OPEN_FILE_HOOK.set(open_detour);
    let _ = SET_INFO_HOOK.set(set_info_detour);
    let _ = CLOSE_HOOK.set(close_detour);
    let _ = QUERY_FULL_ATTR_HOOK.set(query_full_attr_detour);
    let _ = QUERY_ATTR_HOOK.set(query_attr_detour);
    let _ = QUERY_DIR_HOOK.set(query_dir_detour);
    debug_log("init: all 7 file hooks installed successfully");

    // BUG-048（F3）: `NtQueryDirectoryFileEx`はWindows 10 1709以降にのみ存在するため、
    // `CreateProcessW`等と同じくベストエフォート（無くても上記7フックの動作には影響しない、
    // 単に`FindFirstFileEx`系の一部経路でマージが効かないだけ＝BUG-047修正前の挙動に戻るだけ）。
    let query_dir_ex_installed = install_query_dir_ex_hook();
    debug_log(&format!(
        "init: install_query_dir_ex_hook done, installed={query_dir_ex_installed}"
    ));

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
    true
}

/// `NtQueryDirectoryFileEx`のベストエフォートフック設置（BUG-048 F3、`init`から呼ばれる）。
/// exportが無い（Windows 10 1709未満）・detour設置/enable失敗のいずれでも`false`を返すだけで、
/// 他の必須7フックには一切影響しない（`NtQueryDirectoryFile`フック単体でも大半の列挙経路は
/// カバーする——`try_merged_dir_query`本体の効果が一部の経路で得られなくなるだけ）。
fn install_query_dir_ex_hook() -> bool {
    let Some(addr) = (unsafe { resolve_ntdll_export("NtQueryDirectoryFileEx") }) else {
        return false;
    };
    let target: NtQueryDirectoryFileExFn = unsafe { std::mem::transmute(addr) };
    let Ok(detour) = (unsafe { GenericDetour::new(target, hooked_nt_query_directory_file_ex) })
    else {
        return false;
    };
    if unsafe { detour.enable() }.is_err() {
        return false;
    }
    QUERY_DIR_EX_HOOK.set(detour).is_ok()
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
        // 残課題#5: `CreateProcessA`/`WinExec`も同じベストエフォート方針で追加する
        // （失敗しても他フックには影響しない、モジュールdoc「CreateProcessAFn」参照）。
        if CREATE_PROCESS_A_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessA") } {
                let target: CreateProcessAFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_create_process_a) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_A_HOOK.set(detour);
                    }
                }
            }
        }
        if WIN_EXEC_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "WinExec") } {
                let target: WinExecFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_win_exec) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = WIN_EXEC_HOOK.set(detour);
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

/// `DllMain`が起動する内部初期化スレッド。設定は環境変数からしか取れない（`DllMain`は
/// 注入パラメータを受け取れない）ため`param=NULL`で試みる。ここで失敗しても確定はせず、
/// 後続の`harness_cow_init`（注入パラメータ付き）が再試行できる（BUG-045）。
unsafe extern "system" fn init_thread_proc(_param: *mut c_void) -> u32 {
    let _ = unsafe { ensure_init(std::ptr::null()) };
    0
}

/// Phase 4a: 親プロセス側の`hooked_create_process_w`が孫プロセスへ`CreateRemoteThread`で
/// 明示的に呼ぶエクスポート（`#[no_mangle]`必須、`GetProcAddress`で名前解決される）。
/// `DllMain`の内部初期化スレッドとの競合は[`ensure_init`]が吸収するため、呼び出し順は問わない——
/// この関数のリモートスレッドが終了した時点でフック設置の成否が確定していることだけが保証される
/// （`inject_grandchild`の同期点、モジュールdoc参照）。
///
/// `param`は注入側が`VirtualAllocEx`+`WriteProcessMemory`で書き込んだ設定ブロブ
/// （[`serialize_config_blob`]の形式、NULL可）。**戻り値は初期化の実際の成否**（成功=1・失敗=0）で、
/// 注入側は`GetExitCodeThread`でこれを読む。BUG-045のF1修正前は常に1を返しており、フック未設置でも
/// 注入成功と誤判定して警告台帳に何も残らなかった。
///
/// # Safety
/// `CreateRemoteThread`のスレッド開始関数として呼ばれる前提（`LPTHREAD_START_ROUTINE`互換
/// シグネチャ）。`param`は[`deserialize_config_blob`]の要件を満たすこと。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn harness_cow_init(param: *mut c_void) -> u32 {
    if unsafe { ensure_init(param as *const u8) } {
        1
    } else {
        0
    }
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

    /// BUG-045のF2: 注入パラメータで運ぶ設定ブロブが往復すること（env非依存の設定伝播）。
    /// ext_capture_rootsが空の場合・複数ある場合の両方を1関数で見る。
    #[test]
    fn config_blob_round_trips_through_serialize_and_parse() {
        let cfg = Config {
            workspace_root: PathBuf::from(r"C:\ws\project"),
            upper_dir: PathBuf::from(r"C:\upper\abc"),
            ext_capture_roots: vec![PathBuf::from(r"C:\ext one"), PathBuf::from(r"D:\ext2")],
        };
        let blob = serialize_config_blob(&cfg);
        assert_eq!(blob.last(), Some(&0u8), "blob must be NUL-terminated");
        let parsed = unsafe { deserialize_config_blob(blob.as_ptr()) }.expect("parse");
        assert_eq!(parsed.workspace_root, cfg.workspace_root);
        assert_eq!(parsed.upper_dir, cfg.upper_dir);
        assert_eq!(parsed.ext_capture_roots, cfg.ext_capture_roots);

        let empty_ext = Config {
            workspace_root: PathBuf::from(r"C:\ws"),
            upper_dir: PathBuf::from(r"C:\upper"),
            ext_capture_roots: Vec::new(),
        };
        let parsed = unsafe { deserialize_config_blob(serialize_config_blob(&empty_ext).as_ptr()) }
            .expect("parse (no ext roots)");
        assert!(parsed.ext_capture_roots.is_empty());
    }

    /// 壊れた/不足したブロブは`None`になり、環境変数フォールバックへ落ちること
    /// （`resolve_config`の分岐条件）。
    #[test]
    fn config_blob_parse_rejects_incomplete_input() {
        assert!(unsafe { deserialize_config_blob(std::ptr::null()) }.is_none());
        assert!(parse_config_blob("").is_none());
        assert!(parse_config_blob("C:\\ws").is_none(), "upper_dir missing");
        assert!(parse_config_blob("\nC:\\upper\n").is_none(), "workspace empty");
        assert!(parse_config_blob("C:\\ws\n\n").is_none(), "upper empty");
    }

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
            ext_capture_roots: Vec::new(),
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
            ext_capture_roots: Vec::new(),
        };

        let hash = baseline_hash_for(&cfg, "baseline_mirror_probe.txt");

        assert!(hash.is_some());
        let mirror = upper
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
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
            ext_capture_roots: Vec::new(),
        };

        let hash = baseline_hash_for(&cfg, "does_not_exist_probe.txt");

        assert!(hash.is_none());
        assert!(!upper
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
            .join("does_not_exist_probe.txt")
            .exists());
    }

    /// Phase 3（設計書§19.8）: `ext_capture_roots`配下の絶対パスは`ext_relative`が
    /// `(ext_key, 正規化済み絶対パス)`を返し、`classify_target`は`_ext/<key>`へのupper
    /// マッピングを返す。
    #[test]
    fn classify_target_maps_ext_capture_root_path_to_ext_prefixed_rel() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let capture_root = tempfile::tempdir().unwrap();
        let target = capture_root.path().join("cache").join("probe.txt");
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
            ext_capture_roots: vec![capture_root.path().to_path_buf()],
        };

        let classified = classify_target(&cfg, &target).expect("must classify under capture root");

        let expected_key = store::ext_key(&store::normalize_abs_path(&target.to_string_lossy())).unwrap();
        assert_eq!(classified.rel, Path::new("_ext").join(&expected_key));
        assert_eq!(
            classified.ledger_key,
            store::normalize_abs_path(&target.to_string_lossy())
        );
        assert_eq!(
            cfg.upper_dir.join(&classified.rel),
            upper.path().join("_ext").join(&expected_key)
        );
    }

    /// capture root配下でもworkspace配下でもないパスは`None`（素通し対象）。
    #[test]
    fn classify_target_returns_none_outside_workspace_and_capture_roots() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };

        assert!(classify_target(&cfg, &elsewhere.path().join("x.txt")).is_none());
    }

    /// `baseline_hash_for`はledger_keyが絶対パス（`_ext`）なら`baseline_hash_and_mirror_ext`
    /// 経由でbaselineミラーを`.harness-cow-baseline/_ext/<key>`へ書く（BUG-042型の値ずれ防止:
    /// workspace内と誤って`workspace_root.join(絶対パス)`を計算しないことを確認する）。
    #[test]
    fn baseline_hash_for_routes_absolute_ledger_key_through_ext_mirror() {
        let workspace = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::fs::write(&target, b"ext-original").unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            upper_dir: upper.path().to_path_buf(),
            ext_capture_roots: vec![outside.path().to_path_buf()],
        };
        let original = store::normalize_abs_path(&target.to_string_lossy());
        let key = store::ext_key(&original).unwrap();

        let hash = baseline_hash_for(&cfg, &original);

        assert_eq!(hash, Some(harness_change_ledger::hash_bytes(b"ext-original")));
        let mirror = upper
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
            .join("_ext")
            .join(&key);
        assert_eq!(std::fs::read_to_string(mirror).unwrap(), "ext-original");
        // workspace配下には何も新規作成されていないこと（誤ってworkspace_root.join(絶対パス)を
        // 計算していれば、`PathBuf::join`が絶対パスで丸ごと置き換わり実質`target`と同じパスを
        // 指してしまう——今回は書込先自体が無いためディレクトリの中身が空のままであることで
        // 間接的に確認する）。
        assert!(std::fs::read_dir(workspace.path()).unwrap().next().is_none());
    }
}
