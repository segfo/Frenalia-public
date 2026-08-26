//! Tier2a `--sandbox tier2a-cow`（D-30）のRedirector DLL。x64専用・最小スコープ。
//!
//! `plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §13-§19。
//! `ntdll.dll`の`NtCreateFile`/`NtOpenFile`/`NtSetInformationFile`/`NtClose`/
//! `NtQueryFullAttributesFile`/`NtQueryAttributesFile`/`NtQueryDirectoryFile`をinline hook
//! （`retour`クレート、フックの実装品質はセキュリティ保証に影響しない——§13.1の実装方針参照）し、
//! workspace配下への書込操作をCoW 差分層ディレクトリへ誘導しつつ、作成・変更・削除・リネームを
//! 操作台帳（`.harness-cow-ops.jsonl`、`crates/harness-change-ledger`）へ記録する。
//! `NtQueryDirectoryFile`（ディレクトリ列挙）は、セッション中に新規作成したファイルが
//! `Remove-Item`等から「存在しない」と誤認されるバグ（BUG-047）の修正として追加された——
//! 他のフックがworkspaceと差分層を個別パス指定で正しく振り分けていても、ディレクトリを
//! **列挙**する経路だけは別物であり、差分層側だけに存在するファイルはこれをフックしない限り
//! 一覧に現れない（§7.8「ディレクトリ列挙」参照）。
//!
//! **境界ではなく誘導**（`plans/DESIGN-SANDBOX.md` D-01/D-30）: このDLLが無効化・回避・
//! アンロードされても、workspace本体はAppContainerのACLでread-only付与済みのため、書込は
//! `STATUS_ACCESS_DENIED`でfail-closeする。このDLLの役割は、フックが機能する場合に
//! `ACCESS_DENIED`を回避してCoW 差分層へ書けるようにする「利便性」のみ。
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
//! * `HARNESS_COW_DIFF_LAYER`: CoW 差分層ディレクトリ（DOS形式）。
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
//! `<diff_layer_dir>/.harness-cow-warnings.jsonl`へ理由を追記する（`append_warning_entry`）。
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
use windows::Wdk::Foundation::NtQueryObject;
use windows::Wdk::Foundation::{
    OBJECT_ATTRIBUTES, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION,
};
use windows::Wdk::Storage::FileSystem::{
    FileDispositionInformation, FileDispositionInformationEx, FileRenameInformation,
    FileRenameInformationEx, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX, FILE_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, HANDLE, HMODULE, NTSTATUS, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_NO_MORE_FILES, STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_APPEND_DATA, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
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
use windows::Win32::System::IO::IO_STATUS_BLOCK;

// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則3） ---
//
// 分割線は「どのOS機構を触るか」と「フックか否か」で引いている。フック本体
// （`file_hooks`・`dir_merge`・`process_hooks`）は**境界ではない**（D-01）——境界はACLであり、
// これらは`--sandbox tier2a-cow`の透過性のためだけに存在する。素通りしてもACLがfail-closeするので、
// 失われるのは透過性だけである。
//
// | モジュール | 役割 |
// |---|---|
// | `state`         | フックのシグネチャ型・`Config`・プロセス内グローバル状態 |
// | `config`        | 設定blobのシリアライズとデバッグログ |
// | `ntpath`        | NTパス ⇔ Win32パスの相互変換 |
// | `policy`        | リダイレクト要否の判定（純粋） |
// | `ledger`        | 操作台帳・copy-up・リダイレクト先OAの組み立て |
// | `file_hooks`    | ファイル系NTフック |
// | `dir_merge`     | ディレクトリ列挙のマージ |
// | `inject`        | 子プロセスへのDLL注入 |
// | `process_hooks` | プロセス生成フック |
// | `init`          | 初期化・フック設置・エントリポイント |

mod config;
mod dir_merge;
mod file_hooks;
mod init;
mod inject;
mod ledger;
mod ntpath;
mod policy;
mod process_hooks;
mod state;

use config::*;
use dir_merge::*;
use file_hooks::*;
use inject::*;
use ledger::*;
use ntpath::*;
use policy::*;
use process_hooks::*;
use state::*;

// `init`はエントリポイント（`harness_cow_init`・`DllMain`）とフック設置を持つ。
// 他モジュールから名前で参照されることは無いが、モジュールとしてリンクされる必要がある。
#[allow(unused_imports)]
use init::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-045のF2: 注入パラメータで運ぶ設定ブロブが往復すること（env非依存の設定伝播）。
    /// ext_capture_rootsが空の場合・複数ある場合の両方を1関数で見る。
    #[test]
    fn config_blob_round_trips_through_serialize_and_parse() {
        let cfg = Config {
            workspace_root: PathBuf::from(r"C:\ws\project"),
            diff_layer_dir: PathBuf::from(r"C:\diff_layer\abc"),
            ext_capture_roots: vec![PathBuf::from(r"C:\ext one"), PathBuf::from(r"D:\ext2")],
        };
        let blob = serialize_config_blob(&cfg);
        assert_eq!(blob.last(), Some(&0u8), "blob must be NUL-terminated");
        let parsed = unsafe { deserialize_config_blob(blob.as_ptr()) }.expect("parse");
        assert_eq!(parsed.workspace_root, cfg.workspace_root);
        assert_eq!(parsed.diff_layer_dir, cfg.diff_layer_dir);
        assert_eq!(parsed.ext_capture_roots, cfg.ext_capture_roots);

        let empty_ext = Config {
            workspace_root: PathBuf::from(r"C:\ws"),
            diff_layer_dir: PathBuf::from(r"C:\diff_layer"),
            ext_capture_roots: Vec::new(),
        };
        let parsed = unsafe { deserialize_config_blob(serialize_config_blob(&empty_ext).as_ptr()) }
            .expect("parse (no ext roots)");
        assert!(parsed.ext_capture_roots.is_empty());
    }

    /// **BUG-066の追加検証（2026-08-06）**: DLLが受け取った設定のルートは、綴りが揺れていても
    /// 同じ形へ揃うこと。`spawn`側（`normalize_cow_root`）が既に正規化しているが、DLL側でも
    /// 独立に揃えるのは、注入blob経由の孫世代や、将来別経路から設定が来た場合の保険である。
    #[test]
    fn finalize_config_folds_every_root_spelling() {
        let diff_layer = tempfile::tempdir().unwrap();
        for root in [
            PathBuf::from(r"C:\ws\"),
            PathBuf::from(r"\\?\C:\ws"),
            PathBuf::from(r"\??\C:\ws"),
        ] {
            let cfg = finalize_config(Config {
                workspace_root: root.clone(),
                diff_layer_dir: PathBuf::from(format!(r"\\?\{}\", diff_layer.path().to_string_lossy())),
                ext_capture_roots: vec![PathBuf::from(r"\\?\D:\ext\")],
            });
            assert_eq!(cfg.workspace_root, PathBuf::from(r"C:\ws"), "root={root:?}");
            assert_eq!(cfg.diff_layer_dir, diff_layer.path());
            assert_eq!(cfg.ext_capture_roots, vec![PathBuf::from(r"D:\ext")]);
        }
    }

    /// **BUG-066の追加検証**: workspace_rootが絶対パスでない（`--cwd .`相当）ときだけ、
    /// 警告台帳へ`config_workspace_not_absolute`が残ること。この形は判定規則では救えない
    /// （絶対パスと照合しようがない）ので、**黙って透過性が全滅する代わりに名乗る**のが
    /// 唯一の防御になる。2026-08-05のセッションにはこの痕跡がどこにも無かった。
    #[test]
    fn finalize_config_warns_when_the_workspace_root_is_not_absolute() {
        let diff_layer = tempfile::tempdir().unwrap();
        let warnings = diff_layer.path().join(COW_WARNINGS_LEDGER_FILENAME);

        let cfg = finalize_config(Config {
            workspace_root: PathBuf::from("."),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        });
        assert_eq!(cfg.workspace_root, PathBuf::from("."));
        let text = std::fs::read_to_string(&warnings).expect("warnings ledger must be written");
        assert!(text.contains("config_workspace_not_absolute"), "{text}");
        assert!(
            text.contains("BUG-066"),
            "the warning must point at the writeup: {text}"
        );

        // 絶対パスなら1行も増やさない（正常系を騒がせない）。
        let before = std::fs::read_to_string(&warnings).unwrap_or_default();
        finalize_config(Config {
            workspace_root: PathBuf::from(r"C:\ws"),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        });
        assert_eq!(
            std::fs::read_to_string(&warnings).unwrap_or_default(),
            before
        );
    }

    /// 壊れた/不足したブロブは`None`になり、環境変数フォールバックへ落ちること
    /// （`resolve_config`の分岐条件）。
    #[test]
    fn config_blob_parse_rejects_incomplete_input() {
        assert!(unsafe { deserialize_config_blob(std::ptr::null()) }.is_none());
        assert!(parse_config_blob("").is_none());
        assert!(parse_config_blob("C:\\ws").is_none(), "diff_layer_dir missing");
        assert!(
            parse_config_blob("\nC:\\diff_layer\n").is_none(),
            "workspace empty"
        );
        assert!(parse_config_blob("C:\\ws\n\n").is_none(), "diff layer empty");
    }

    /// BUG-048 F1回帰: `FILE_GENERIC_WRITE`ベースの旧実装は`SYNCHRONIZE`/`READ_CONTROL`を
    /// 誤って書込ビットとして扱っていた。実機ログで観測した`0x100001`
    /// （`FILE_LIST_DIRECTORY|SYNCHRONIZE`、`Get-ChildItem`のディレクトリopen）が
    /// `write_intent=false`になることを確認する。
    #[test]
    fn is_write_intent_does_not_flag_synchronize_or_list_directory() {
        const FILE_LIST_DIRECTORY: u32 = 0x1;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const FILE_OPEN: u32 = 1;
        assert!(!is_write_intent(
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            Some(FILE_OPEN)
        ));
        assert!(!is_write_intent(SYNCHRONIZE | READ_CONTROL, None));
        // `FILE_GENERIC_READ`相当（READ_DATA|READ_ATTRIBUTES|READ_EA|READ_CONTROL|SYNCHRONIZE）。
        const FILE_GENERIC_READ: u32 = 0x0012_0089;
        assert!(!is_write_intent(FILE_GENERIC_READ, Some(FILE_OPEN)));
    }

    /// 書込を意味するビットは引き続き検出されること（DELETE単体・APPEND単体を含む）。
    #[test]
    fn is_write_intent_flags_actual_write_bits() {
        const DELETE: u32 = 0x0001_0000;
        const FILE_APPEND_DATA: u32 = 0x4;
        const FILE_WRITE_DATA: u32 = 0x2;
        const FILE_OPEN_IF: u32 = 3;
        const FILE_OVERWRITE_IF: u32 = 5;
        assert!(is_write_intent(DELETE, Some(FILE_OPEN_IF)));
        assert!(is_write_intent(FILE_APPEND_DATA, None));
        assert!(is_write_intent(FILE_WRITE_DATA, None));
        assert!(
            is_write_intent(0, Some(FILE_OVERWRITE_IF)),
            "OVERWRITE_IF disposition alone"
        );
    }

    /// BUG-048 F2回帰: ディレクトリopen（`FILE_DIRECTORY_FILE`）は、書込ビットが立っていても
    /// 新規作成dispositionでなければリダイレクト対象から除外する。既存ディレクトリを
    /// `DELETE`/`WRITE_ATTRIBUTES`込みで開くケース（`Remove-Item`のパス解決等）を想定。
    #[test]
    fn should_redirect_write_excludes_existing_directory_open_but_allows_mkdir() {
        const FILE_OPEN: u32 = 1;
        const FILE_CREATE: u32 = 2;
        let dir_flag = FILE_DIRECTORY_FILE.0;
        // 既存ディレクトリを書込アクセス込みで開く（削除・属性変更等）→リダイレクトしない。
        assert!(!should_redirect_write(true, dir_flag, Some(FILE_OPEN)));
        // `NtOpenFile`相当（disposition無し）でのディレクトリopen→リダイレクトしない。
        assert!(!should_redirect_write(true, dir_flag, None));
        // 新規ディレクトリ作成（mkdir相当）→引き続きリダイレクトする。
        assert!(should_redirect_write(true, dir_flag, Some(FILE_CREATE)));
        // ファイル（ディレクトリフラグ無し）は従来通り。
        assert!(should_redirect_write(true, 0, Some(FILE_OPEN)));
        assert!(
            !should_redirect_write(false, 0, Some(FILE_OPEN)),
            "write_intent=falseなら常にfalse"
        );
    }

    /// Q9（増分tail再読込）の回帰テスト。`deleted_paths_state`/`ledger_read_offset`は
    /// プロセスグローバルな唯一のsingletonであり、他のテストと並行実行されると相互汚染し得るため、
    /// この1関数内で「初期ロード→兄弟プロセスによる追記を模擬→check_deleted経由での増分反映→
    /// 未完了行（末尾に\nが無い）は次回まで据え置き」まで一通り検証する。
    #[test]
    fn check_deleted_picks_up_incremental_ledger_appends_from_sibling_process() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };
        let ledger_path = diff_layer.path().join(COW_OPS_LEDGER_FILENAME);

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
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace.path().join("baseline_mirror_probe.txt"),
            "original",
        )
        .unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };

        let hash = baseline_hash_for(&cfg, "baseline_mirror_probe.txt");

        assert!(hash.is_some());
        let mirror = diff_layer
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
            .join("baseline_mirror_probe.txt");
        assert_eq!(std::fs::read_to_string(mirror).unwrap(), "original");
    }

    /// 新規作成（baselineが存在しない）パスはミラーを書かない。
    #[test]
    fn baseline_hash_for_writes_no_mirror_when_path_does_not_exist() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };

        let hash = baseline_hash_for(&cfg, "does_not_exist_probe.txt");

        assert!(hash.is_none());
        assert!(!diff_layer
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
            .join("does_not_exist_probe.txt")
            .exists());
    }

    /// Phase 3（設計書§19.8）: `ext_capture_roots`配下の絶対パスは`ext_relative`が
    /// `(ext_key, 正規化済み絶対パス)`を返し、`classify_target`は`_ext/<key>`への差分層
    /// マッピングを返す。
    #[test]
    fn classify_target_maps_ext_capture_root_path_to_ext_prefixed_rel() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let capture_root = tempfile::tempdir().unwrap();
        let target = capture_root.path().join("cache").join("probe.txt");
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: vec![capture_root.path().to_path_buf()],
        };

        let classified = classify_target(&cfg, &target).expect("must classify under capture root");

        let expected_key =
            store::ext_key(&store::normalize_abs_path(&target.to_string_lossy())).unwrap();
        assert_eq!(classified.rel, Path::new("_ext").join(&expected_key));
        assert_eq!(
            classified.ledger_key,
            store::normalize_abs_path(&target.to_string_lossy())
        );
        assert_eq!(
            cfg.diff_layer_dir.join(&classified.rel),
            diff_layer.path().join("_ext").join(&expected_key)
        );
    }

    /// **BUG-066の回帰テスト（B-1）**: workspace_rootの綴りが実際に渡されるパスと大小・
    /// 末尾区切りで食い違っていても、workspace内と判定し**相対パスまで返し切る**こと。
    /// 旧実装はここで`None`を返し、呼び出し側が「workspace外」と誤認して素通し→ACL拒否に
    /// なっていた（`--sandbox tier2a-cow`セッションで書込が1件もリダイレクトされない状態）。
    #[test]
    fn classify_target_matches_workspace_paths_whose_spelling_differs_in_case_or_trailing_sep() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let target = workspace.path().join("sub").join("merge-demo.txt");
        for root in [
            PathBuf::from(workspace.path().to_string_lossy().to_uppercase()),
            PathBuf::from(format!("{}\\", workspace.path().to_string_lossy())),
            PathBuf::from(format!("\\\\?\\{}", workspace.path().to_string_lossy())),
        ] {
            let cfg = Config {
                workspace_root: root.clone(),
                diff_layer_dir: diff_layer.path().to_path_buf(),
                ext_capture_roots: Vec::new(),
            };
            let classified = classify_target(&cfg, &target)
                .unwrap_or_else(|| panic!("must classify with root={root:?}"));
            assert_eq!(classified.kind, TargetKind::Workspace);
            assert_eq!(classified.ledger_key, "sub/merge-demo.txt");
            assert_eq!(
                cfg.diff_layer_dir.join(&classified.rel),
                diff_layer.path().join("sub").join("merge-demo.txt")
            );
        }
    }

    /// **BUG-066の回帰テスト（B-2）**: 差分層配下の実体を直接指すパスは、同じファイルの
    /// 別の綴りとして**workspaceと同じ台帳キー**へ写る（リダイレクトはしない）。
    #[test]
    fn classify_target_treats_a_path_inside_the_diff_layer_dir_as_an_alias_with_the_same_ledger_key() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };

        let classified = classify_target(&cfg, &diff_layer.path().join("merge-demo.txt"))
            .expect("a direct write into the diff layer dir must classify");

        assert_eq!(classified.kind, TargetKind::DiffLayerAlias);
        assert_eq!(classified.ledger_key, "merge-demo.txt");
        // 誘導先は自分自身（＝「差分層の差分層」は作らない）。
        assert_eq!(
            cfg.diff_layer_dir.join(&classified.rel),
            diff_layer.path().join("merge-demo.txt")
        );
    }

    /// CoW自身の帳簿（`.harness-cow-*`）と`_ext`配下は別名として扱わない
    /// （前者は変更ではない、後者はhost側の実体走査が拾う）。
    #[test]
    fn classify_target_ignores_cow_bookkeeping_and_ext_entries_inside_the_diff_layer_dir() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: Vec::new(),
        };
        for name in [
            COW_OPS_LEDGER_FILENAME,
            ".harness-cow-denied.jsonl",
            ".harness-cow-session.json",
        ] {
            assert!(
                classify_target(&cfg, &diff_layer.path().join(name)).is_none(),
                "{name} must not be recorded as a change"
            );
        }
        assert!(classify_target(
            &cfg,
            &diff_layer
                .path()
                .join(harness_change_ledger::COW_BASELINE_DIRNAME)
                .join("a.txt")
        )
        .is_none());
        assert!(
            classify_target(&cfg, &diff_layer.path().join("_ext").join("c").join("x.txt")).is_none()
        );
    }

    /// capture root配下でもworkspace配下でもないパスは`None`（素通し対象）。
    #[test]
    fn classify_target_returns_none_outside_workspace_and_capture_roots() {
        let workspace = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
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
        let diff_layer = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::fs::write(&target, b"ext-original").unwrap();
        let cfg = Config {
            workspace_root: workspace.path().to_path_buf(),
            diff_layer_dir: diff_layer.path().to_path_buf(),
            ext_capture_roots: vec![outside.path().to_path_buf()],
        };
        let original = store::normalize_abs_path(&target.to_string_lossy());
        let key = store::ext_key(&original).unwrap();

        let hash = baseline_hash_for(&cfg, &original);

        assert_eq!(
            hash,
            Some(harness_change_ledger::hash_bytes(b"ext-original"))
        );
        let mirror = diff_layer
            .path()
            .join(harness_change_ledger::COW_BASELINE_DIRNAME)
            .join("_ext")
            .join(&key);
        assert_eq!(std::fs::read_to_string(mirror).unwrap(), "ext-original");
        // workspace配下には何も新規作成されていないこと（誤ってworkspace_root.join(絶対パス)を
        // 計算していれば、`PathBuf::join`が絶対パスで丸ごと置き換わり実質`target`と同じパスを
        // 指してしまう——今回は書込先自体が無いためディレクトリの中身が空のままであることで
        // 間接的に確認する）。
        assert!(std::fs::read_dir(workspace.path())
            .unwrap()
            .next()
            .is_none());
    }

    fn names(entries: &[crate::MergedEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| String::from_utf16_lossy(&e.name))
            .collect()
    }

    /// BUG-047 §7.8優先順位: whiteout済みは除外・差分層優先・同名差分層が無いbaseのみ採用。
    #[test]
    fn merge_dir_entries_applies_whiteout_and_diff_layer_priority() {
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("only_base.txt"), "b").unwrap();
        std::fs::write(base.path().join("both.txt"), "base-version").unwrap();
        std::fs::write(base.path().join("deleted.txt"), "b").unwrap();
        std::fs::write(diff_layer.path().join("only_diff_layer.txt"), "u").unwrap();
        std::fs::write(diff_layer.path().join("both.txt"), "diff-layer-version").unwrap();

        let mut deleted = HashSet::new();
        deleted.insert("deleted.txt".to_string());

        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &deleted, "");
        let mut got = names(&merged);
        got.sort();
        assert_eq!(got, vec!["both.txt", "only_base.txt", "only_diff_layer.txt"]);
        let both = merged
            .iter()
            .find(|e| String::from_utf16_lossy(&e.name) == "both.txt")
            .unwrap();
        assert_eq!(
            both.end_of_file,
            "diff-layer-version".len() as i64,
            "diff layer must win over same-name base"
        );
    }

    /// セッション中に新規作成（baseには無く差分層にのみ存在）したファイルがマージ結果に
    /// 現れること（BUG-047のユーザー報告シナリオそのもの）。
    #[test]
    fn merge_dir_entries_surfaces_session_created_file_missing_from_base() {
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(diff_layer.path().join("test.txt"), "new").unwrap();

        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");

        assert_eq!(names(&merged), vec!["test.txt"]);
    }

    #[test]
    fn merge_dir_entries_empty_directories_yield_empty_result() {
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");
        assert!(merged.is_empty());
    }

    #[test]
    fn wildcard_match_supports_star_and_question_mark() {
        assert!(crate::wildcard_match("*", "anything.txt"));
        assert!(crate::wildcard_match("", "anything.txt"));
        assert!(crate::wildcard_match("*.txt", "test.txt"));
        assert!(!crate::wildcard_match("*.txt", "test.ps1"));
        assert!(crate::wildcard_match("te?t.txt", "test.txt"));
        assert!(!crate::wildcard_match("te?t.txt", "teXXt.txt"));
        assert!(
            crate::wildcard_match("TEST.TXT", "test.txt"),
            "case-insensitive"
        );
    }

    /// マーシャルしたバイト列を`FILE_NAMES_INFORMATION`として読み戻し、`NextEntryOffset`の
    /// チェーンとファイル名が正しく往復することを確認する（Stage 1の最難関部分の検証）。
    #[test]
    fn marshal_entries_round_trips_file_names_information() {
        use windows::Wdk::Storage::FileSystem::{FileNamesInformation, FILE_NAMES_INFORMATION};
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        for n in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(diff_layer.path().join(n), "x").unwrap();
        }
        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");
        assert_eq!(merged.len(), 3);

        let mut buf = vec![0u8; 4096];
        let (bytes_written, consumed) =
            crate::marshal_entries(&mut buf, FileNamesInformation, &merged, 0, false);
        assert_eq!(consumed, 3);
        assert!(bytes_written > 0 && bytes_written <= buf.len());

        // NextEntryOffsetチェーンを歩いて、書き込んだ3件のファイル名を読み戻す。
        let mut offset = 0usize;
        let mut read_names = Vec::new();
        loop {
            let ptr = buf[offset..].as_ptr() as *const FILE_NAMES_INFORMATION;
            let header = unsafe { &*ptr };
            let name_offset = offset + std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName);
            let len_u16 = (header.FileNameLength as usize) / 2;
            let name_bytes = &buf[name_offset..name_offset + header.FileNameLength as usize];
            let name_u16: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            assert_eq!(name_u16.len(), len_u16);
            read_names.push(String::from_utf16_lossy(&name_u16));
            if header.NextEntryOffset == 0 {
                break;
            }
            offset += header.NextEntryOffset as usize;
        }
        assert_eq!(read_names, vec!["a.txt", "b.txt", "c.txt"]);
    }

    /// バッファが1件も入らない小ささなら`consumed == 0`（呼び出し元がSTATUS_BUFFER_OVERFLOWへ
    /// 変換する契約、Stage 1.2の「全件入らない場合」の一番厳しいケース）。
    #[test]
    fn marshal_entries_reports_zero_consumed_when_buffer_too_small() {
        use windows::Wdk::Storage::FileSystem::FileNamesInformation;
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(diff_layer.path().join("longer-file-name.txt"), "x").unwrap();
        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");

        let mut tiny_buf = vec![0u8; 4];
        let (bytes_written, consumed) =
            crate::marshal_entries(&mut tiny_buf, FileNamesInformation, &merged, 0, false);
        assert_eq!(consumed, 0);
        assert_eq!(bytes_written, 0);
    }

    /// `return_single_entry`は最大1件だけ書くこと。複数回呼び出し（`start`をずらす）で
    /// 残りのエントリへページングできること（Stage 1.3のカーソル継続の基礎）。
    #[test]
    fn marshal_entries_return_single_entry_and_pagination() {
        use windows::Wdk::Storage::FileSystem::FileNamesInformation;
        let base = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        for n in ["a.txt", "b.txt"] {
            std::fs::write(diff_layer.path().join(n), "x").unwrap();
        }
        let merged = crate::merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");

        let mut buf = vec![0u8; 4096];
        let (_, consumed_first) =
            crate::marshal_entries(&mut buf, FileNamesInformation, &merged, 0, true);
        assert_eq!(
            consumed_first, 1,
            "return_single_entry must yield exactly one record"
        );

        let mut buf2 = vec![0u8; 4096];
        let (_, consumed_rest) =
            crate::marshal_entries(&mut buf2, FileNamesInformation, &merged, 1, false);
        assert_eq!(
            consumed_rest, 1,
            "continuation from start=1 must yield the remaining entry"
        );
    }
}
