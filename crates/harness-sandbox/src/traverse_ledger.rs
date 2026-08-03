//! traverse台帳（D10の巻き戻し用、`fs-passthrough-ledger.json`とは別ファイル）。
//!
//! 元々`crates/harness-cli/src/main.rs`にあったが、`win_appcontainer::preflight`が
//! traverse ACE不足を自動検知してprivhelper経由で付与するようになったため（`preflight`は
//! このcrate内にある）、harness-cli→harness-sandboxの依存方向を逆流させないためここへ移動した。
//! `harness fs grant-traverse`/`revoke-traverse`（harness-cli側）はこのモジュールの関数を呼ぶ。

use std::path::{Path, PathBuf};

/// traverse台帳の1エントリ。`grant-traverse`は`writable`という概念を持たない（付与する
/// アクセス権は常に`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`固定）ため、fs-passthrough-ledgerの
/// エントリ型とは別の小さな型にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraverseLedgerEntry {
    pub path: String,
    pub granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TraverseLedger {
    pub entries: Vec<TraverseLedgerEntry>,
}

/// 台帳ファイルのパス（`%APPDATA%\harness\config\traverse-grant-ledger.json`）。
/// `fs-passthrough-ledger.json`と意味が異なる記録（ドライブルート/祖先ディレクトリへの
/// traverse付与）を混在させないため、別ファイルにする。
pub fn traverse_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("traverse-grant-ledger.json"))
}

pub fn load_traverse_ledger() -> TraverseLedger {
    let Some(path) = traverse_ledger_path() else {
        return TraverseLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => TraverseLedger::default(),
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層（read-only属性＋`.bak`バックアップ）を通して行う
/// （`crates/harness-cli/src/main.rs`の`write_ledger_file`と同じロジックの複製。fs-passthrough-ledger
/// 側の既存経路には手を触れず、traverse台帳専用にこの小さなヘルパーを複製することで影響範囲を
/// 最小化する）。
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

pub fn save_traverse_ledger(ledger: &TraverseLedger) {
    let Some(path) = traverse_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

/// `grant-traverse`が実際にACE付与を試みたパスをtraverse台帳へ記録する（D10の巻き戻し用）。
/// 同一パスは上書き（冪等）。
pub fn record_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.granted_at_unix_secs = granted_at;
    } else {
        ledger.entries.push(TraverseLedgerEntry {
            path: path_str,
            granted_at_unix_secs: granted_at,
        });
    }
    save_traverse_ledger(&ledger);
}

pub fn remove_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_traverse_ledger(&ledger);
}

/// `write_ledger_file`の現行の振る舞いを固定するcharacterization test。
///
/// この関数は`fs-passthrough-ledger`・`tier3-vm-ledger`・`workspace-grant-ledger`にも
/// ほぼ同一のコピーが存在し（`docs/CODE-STRUCTURE-RULES.md`規則5）、`harness-grant-ledger`
/// クレートへ1本化する予定である。統合の前後で振る舞いが変わっていないことを示す基準として
/// ここに置く（規則6）。統合後はテストごと新クレートへ移す。
///
/// パス解決（`traverse_ledger_path`）は`%APPDATA%`固定でテストから差し替えられないため、
/// ここでは明示パスを受け取る`write_ledger_file`だけを対象にする。
#[cfg(test)]
mod write_ledger_file_characterization {
    use super::*;

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

    /// 誤削除防止の2層のうち`.bak`側。上書き時、**旧内容**が`.json.bak`へ退避される。
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

    /// 誤削除防止の2層のうちread-only属性側（`-Force`無しの`Remove-Item`を弾く）。
    /// 上書き時は一旦解除してから書き、書込後に再付与する。
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

    /// 非Windowsでは`set_readonly`がchmodのworld-writable相当になり有効な防御にならないため
    /// 何もしない。`workspace_ledger`のコピーだけこの`#[cfg]`ガードを欠いている。
    #[cfg(not(windows))]
    #[test]
    fn readonly_attribute_is_not_touched_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ledger.json");
        write_ledger_file(&path, "first");
        assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
    }

    /// 読取側のfail-open: 壊れたJSON・存在しないファイルはいずれも空台帳として扱い、
    /// 起動を止めない（`harness-config`の設定読み込みと同じ方針）。
    #[test]
    fn corrupt_or_missing_json_deserializes_to_the_default_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let corrupt = tmp.path().join("corrupt.json");
        std::fs::write(&corrupt, "{ this is not json").unwrap();

        let from_corrupt: TraverseLedger = std::fs::read_to_string(&corrupt)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        assert!(from_corrupt.entries.is_empty());

        let from_missing: TraverseLedger = std::fs::read_to_string(tmp.path().join("nope.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        assert!(from_missing.entries.is_empty());
    }
}
