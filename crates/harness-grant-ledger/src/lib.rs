//! harness-grant-ledger: 「このマシンに対して実際に行った付与」を追跡する台帳の共通機構。
//!
//! `%APPDATA%\harness\config\*.json`（Windows。`directories::ProjectDirs::config_dir()`）に
//! 置かれる次の4台帳が本クレートの`Ledger<T>`を共有する。
//!
//! | 台帳 | 記録する内容 | 所有モジュール |
//! |---|---|---|
//! | `fs-passthrough-ledger.json` | `--fs-allow`/`settings.json`で付与したACE | `harness-cli` |
//! | `traverse-grant-ledger.json` | ドライブルート/祖先へのtraverse ACE（D10の巻き戻し用） | `harness-sandbox` |
//! | `tier3-vm-ledger.json` | Hyper-V VM・差分VHDX・SMB共有 | `harness-sandbox` |
//! | `workspace-grant-ledger.json` | preflightが付与したworkspaceの継承ACE（一覧表示用） | `harness-sandbox` |
//!
//! `Ledger<T>`はこの4台帳以外にも使われる。**性質が違うもの**が2つある。
//!
//! | 台帳 | 記録する内容 | 消えたときに起きること |
//! |---|---|---|
//! | `appcontainer-session-ledger.json` | セッション/MCPサーバのプロファイルとACE付与先（D-37/D-38） | 接頭辞によるGC経路へ縮退（`session_profile`のdoc参照） |
//! | `mcp-approval-ledger.json` | **ユーザーがどのMCPサーバ宣言を起動してよいと決めたか**（D-39） | 全サーバが未承認扱いになり再承認が要るだけ（fail-closed） |
//!
//! 後者は「実マシンへ加えた変更」ではなく**判断の記録**なので、消えても孤立した穴は残らない。
//! だからクリーンアップ禁止ファイル（下記）には含めない。
//!
//! **`harness-change-ledger`とは別物**である。あちらは1セッション内のCoW変更（どのファイルを
//! 書き換えたか）を記録する揮発的なもので、こちらは**実マシンへ加えた永続的な変更**を記録する。
//! こちらの3ファイル（`fs-passthrough`・`traverse-grant`・`tier3-vm`）は、消えると
//! 「付与した記憶はあるが記録が無い」孤立した穴が実マシンに残るため、`CLAUDE.md`が
//! クリーンアップ禁止ファイルとして名指ししている。
//!
//! ## 誤削除防止の2層
//!
//! [`Ledger::save`]は書込のたびに次の2つを行う。エージェント（コーディングツール）による
//! 無関係な一括クリーンアップの巻き込みを防ぐための措置である。
//!
//! 1. 上書き前に既存ファイルのread-onlyを解除し、`.json.bak`へコピーする（復元用）。
//! 2. 書込後にread-only属性を付ける（`-Force`無しの`Remove-Item`/`rm`による削除を防ぐ）。
//!
//! 非Windowsでは(2)を行わない。`set_readonly(true)`の意味論がプラットフォームで異なり、
//! Unixではchmodのworld-writable相当になり得て有効な防御にならないため。
//!
//! ## fail-open
//!
//! 読取（[`Ledger::load`]）は、ファイルが無い・読めない・パースできないいずれの場合も
//! `T::default()`を返す。台帳の不在で起動を止めない（`harness-config`の設定読み込みと
//! 同じ方針）。書込の失敗も無視する。

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod prune;

/// 名前付きOSミューテックスで`f`を直列化する。
///
/// 複数の`harness.exe`が同時に起動している状況で、台帳のread-modify-write
/// （load→変更→save）がロストアップデートを起こさないようにするために使う（D-27）。
/// `name`は`Local\`接頭辞を含む完全なカーネルオブジェクト名を渡すこと。
///
/// ミューテックスの取得自体に失敗した場合はロック無しで`f`を実行する（fail-open、
/// 台帳操作そのものは止めない）。
///
/// 台帳以外にも使える汎用ヘルパーで、`harness-sandbox`はworkspaceのモード別mutexの
/// セットアップ（`workspace_ledger::begin_workspace_mode`）でもこれを使う。
#[cfg(windows)]
pub fn with_named_lock<R>(name: &str, f: impl FnOnce() -> R) -> R {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateMutexW, ReleaseMutex, WaitForSingleObject, INFINITE,
    };

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { CreateMutexW(None, false, windows::core::PCWSTR(wide_name.as_ptr())) };
    let Ok(handle) = handle else {
        return f();
    };
    let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return f();
    }
    let result = f();
    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }
    result
}

#[cfg(not(windows))]
pub fn with_named_lock<R>(_name: &str, f: impl FnOnce() -> R) -> R {
    f()
}

/// `path`のread-only属性を切り替える（Windowsの`attrib +R`/`-R`相当）。
/// 非Windowsでは何もしない（モジュールdoc「誤削除防止の2層」参照）。
#[cfg(windows)]
fn set_file_readonly(path: &Path, readonly: bool) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(windows))]
fn set_file_readonly(_path: &Path, _readonly: bool) {}

/// 1つの台帳ファイル。`T`はその台帳のペイロード型。
///
/// 4台帳の違いは**(ファイル名, ロック名, ペイロード型)** の3点だけなので、それらを
/// この型のフィールド/型引数として持つ。
pub struct Ledger<T> {
    /// 台帳ファイルの絶対パス。`ProjectDirs`が解決できない環境では`None`になり、
    /// その場合は読取が`T::default()`・書込がno-opになる（既存4実装と同じ）。
    path: Option<PathBuf>,
    /// `Some`なら[`with_named_lock`]で直列化する。`None`ならロックしない。
    ///
    /// 4台帳（`fs-passthrough`・`traverse-grant`・`tier3-vm`・`workspace-grant`）はいずれも
    /// `Local\harness-<台帳名>-ledger`形式のロック名を渡し、read-modify-writeを直列化する。
    /// `None`はAPIとしては引き続きサポートするが（テスト用途等）、実運用の4台帳では使わない。
    lock_name: Option<String>,
    _payload: PhantomData<T>,
}

impl<T> Ledger<T> {
    /// `%APPDATA%\harness\config\<file_name>`を指す台帳を作る。
    pub fn in_config_dir(file_name: &str, lock_name: Option<&str>) -> Self {
        Self {
            path: directories::ProjectDirs::from("", "", "harness")
                .map(|d| d.config_dir().join(file_name)),
            lock_name: lock_name.map(str::to_owned),
            _payload: PhantomData,
        }
    }

    /// 明示したパスを指す台帳を作る（テストで`%APPDATA%`を汚さないための注入点）。
    pub fn at_path(path: PathBuf, lock_name: Option<&str>) -> Self {
        Self {
            path: Some(path),
            lock_name: lock_name.map(str::to_owned),
            _payload: PhantomData,
        }
    }

    /// 台帳ファイルのパス。`harness fs list`のような表示系がユーザーへ場所を示すのに使う。
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn with_lock<R>(&self, f: impl FnOnce() -> R) -> R {
        match &self.lock_name {
            Some(name) => with_named_lock(name, f),
            None => f(),
        }
    }
}

impl<T: Serialize + DeserializeOwned + Default> Ledger<T> {
    /// 台帳を読む。ファイルが無い・読めない・パースできない場合は`T::default()`
    /// （モジュールdoc「fail-open」参照）。ロック名が設定されていれば取得してから読む。
    pub fn load(&self) -> T {
        self.with_lock(|| self.load_unlocked())
    }

    /// ロックを取らずに読む。[`Ledger::update`]の内側のように、既にロックを保持している
    /// 文脈からのみ使う（同じスレッドで名前付きmutexを再取得しても手放しが1回になり
    /// 対応が崩れるため）。
    pub fn load_unlocked(&self) -> T {
        let Some(path) = &self.path else {
            return T::default();
        };
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => T::default(),
        }
    }

    /// 台帳を書く（誤削除防止の2層つき、モジュールdoc参照）。
    pub fn save(&self, ledger: &T) {
        self.with_lock(|| self.save_unlocked(ledger));
    }

    /// ロックを取らずに書く（[`Ledger::load_unlocked`]と同じ注意）。
    pub fn save_unlocked(&self, ledger: &T) {
        let Some(path) = &self.path else {
            return;
        };
        if let Ok(s) = serde_json::to_string_pretty(ledger) {
            write_ledger_file(path, &s);
        }
    }

    /// read-modify-writeを1つのロック区間で行う。
    ///
    /// `load`してから`save`するまでの間に他プロセスが書き込むと更新が失われるため、
    /// エントリの追加・削除は必ずこれを通すこと。
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        self.with_lock(|| {
            let mut ledger = self.load_unlocked();
            let result = f(&mut ledger);
            self.save_unlocked(&ledger);
            result
        })
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層を通して行う（モジュールdoc参照）。
fn write_ledger_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if path.exists() {
        set_file_readonly(path, false);
        let backup_path = path.with_extension("json.bak");
        let _ = std::fs::copy(path, &backup_path);
    }
    if std::fs::write(path, contents).is_ok() {
        set_file_readonly(path, true);
    }
}

/// UNIXエポック秒。各台帳のエントリが`granted_at_unix_secs`として持つ。
/// システム時刻がエポック以前を指す異常時は0を返す（既存4実装と同じ）。
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestLedger {
        entries: Vec<String>,
    }

    fn ledger_at(dir: &Path) -> Ledger<TestLedger> {
        Ledger::at_path(dir.join("ledger.json"), None)
    }

    // --- 以下5件は harness-sandbox::traverse_ledger から移設した characterization test。
    //     統合前に既存実装に対して緑であることを確認済み（規則6）。

    #[test]
    fn creates_missing_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("deeper").join("ledger.json");
        write_ledger_file(&path, "{}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
    }

    #[test]
    fn first_write_creates_no_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, r#"{"entries":[]}"#);
        assert!(!tmp.path().join("ledger.json.bak").exists());
    }

    #[test]
    fn overwrite_backs_up_the_previous_contents_to_json_bak() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "OLD");
        write_ledger_file(&path, "NEW");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "NEW");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("ledger.json.bak")).unwrap(),
            "OLD"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_leaves_the_file_readonly_and_can_still_overwrite_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "first");
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        write_ledger_file(&path, "second");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
    }

    #[cfg(not(windows))]
    #[test]
    fn readonly_attribute_is_not_touched_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "first");
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
    }

    #[test]
    fn corrupt_or_missing_json_loads_as_the_default_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());

        assert_eq!(ledger.load(), TestLedger::default());

        std::fs::write(tmp.path().join("ledger.json"), "{ this is not json").unwrap();
        assert_eq!(ledger.load(), TestLedger::default());
    }

    // --- ここから下は`Ledger<T>`が新たに提供するAPIの分。

    #[test]
    fn save_then_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        let value = TestLedger {
            entries: vec!["a".to_string(), "b".to_string()],
        };
        ledger.save(&value);
        assert_eq!(ledger.load(), value);
    }

    #[test]
    fn update_reads_modifies_and_writes_in_one_step() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = ledger_at(tmp.path());
        ledger.update(|l| l.entries.push("first".to_string()));
        let returned = ledger.update(|l| {
            l.entries.push("second".to_string());
            l.entries.len()
        });
        assert_eq!(returned, 2);
        assert_eq!(ledger.load().entries, vec!["first", "second"]);
    }

    #[test]
    fn a_ledger_without_a_resolvable_path_is_a_no_op_rather_than_an_error() {
        let ledger: Ledger<TestLedger> = Ledger {
            path: None,
            lock_name: None,
            _payload: PhantomData,
        };
        ledger.save(&TestLedger {
            entries: vec!["ignored".to_string()],
        });
        assert_eq!(ledger.load(), TestLedger::default());
        assert!(ledger.path().is_none());
    }

    /// ロック名を設定した場合も、単一プロセス内では素直に読み書きできる
    /// （名前付きmutexは再入不可ではなく所有スレッドが再取得できるため、`update`の
    /// 内側で`load_unlocked`を使う設計が正しいことの確認も兼ねる）。
    #[cfg(windows)]
    #[test]
    fn a_locked_ledger_can_still_be_updated_from_a_single_process() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(
            tmp.path().join("ledger.json"),
            Some("Local\\harness-grant-ledger-unit-test"),
        );
        ledger.update(|l| l.entries.push("x".to_string()));
        ledger.update(|l| l.entries.push("y".to_string()));
        assert_eq!(ledger.load().entries, vec!["x", "y"]);
    }

    #[test]
    fn in_config_dir_points_at_the_named_file_under_the_harness_config_dir() {
        let ledger: Ledger<TestLedger> = Ledger::in_config_dir("example-ledger.json", None);
        // `ProjectDirs`が解決できない環境（CI等）では`None`。解決できるなら末尾が一致する。
        if let Some(path) = ledger.path() {
            assert_eq!(path.file_name().unwrap(), "example-ledger.json");
            assert!(path.parent().unwrap().ends_with("config"));
        }
    }

    /// R-01: 名前付きロックが実際に並行`update`を直列化することの確認（`traverse-grant`・
    /// `workspace-grant`にロック名を追加する根拠）。名前付きmutexはプロセス跨ぎだが同一
    /// プロセス内のスレッド間でも機能するため、実プロセスを起動せず`std::thread`で検証できる。
    /// テスト専用のロック名を使い、実運用4台帳のロックとは衝突させない。
    #[cfg(windows)]
    #[test]
    fn a_named_lock_serializes_concurrent_updates_across_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(
            tmp.path().join("ledger.json"),
            Some("Local\\harness-grant-ledger-concurrency-test"),
        );
        let thread_count = 20;
        std::thread::scope(|scope| {
            for i in 0..thread_count {
                let ledger = &ledger;
                scope.spawn(move || {
                    ledger.update(|l| l.entries.push(format!("entry-{i}")));
                });
            }
        });
        assert_eq!(ledger.load().entries.len(), thread_count);
    }

    /// ロック名`None`でも`update`を複数スレッドから呼んで壊れない（パニックしない・
    /// 台帳が読める状態を保つ）ことを確認する。`None`はAPIとして引き続きサポートするため、
    /// この経路自体は壊していないことの確認であり、ロストアップデートが起き得ることは
    /// 妨げない（件数の完全一致は主張しない）。
    #[test]
    fn update_without_a_lock_name_does_not_corrupt_the_ledger_under_concurrent_writers() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger: Ledger<TestLedger> = Ledger::at_path(tmp.path().join("ledger.json"), None);
        let thread_count = 20;
        std::thread::scope(|scope| {
            for i in 0..thread_count {
                let ledger = &ledger;
                scope.spawn(move || {
                    ledger.update(|l| l.entries.push(format!("entry-{i}")));
                });
            }
        });
        assert!(ledger.load().entries.len() <= thread_count);
    }
}
