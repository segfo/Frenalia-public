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
