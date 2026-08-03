//! traverse台帳（D10の巻き戻し用、`fs-passthrough-ledger.json`とは別ファイル）。
//!
//! 元々`crates/harness-cli/src/main.rs`にあったが、`win_appcontainer::preflight`が
//! traverse ACE不足を自動検知してprivhelper経由で付与するようになったため（`preflight`は
//! このcrate内にある）、harness-cli→harness-sandboxの依存方向を逆流させないためここへ移動した。
//! `harness fs grant-traverse`/`revoke-traverse`（harness-cli側）はこのモジュールの関数を呼ぶ。
//!
//! ファイル入出力（誤削除防止の2層・fail-open）は`harness-grant-ledger`の`Ledger<T>`が持つ。
//! 本モジュールはこの台帳固有の「何を記録するか」だけを持つ。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use harness_grant_ledger::Ledger;

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

/// `fs-passthrough-ledger.json`と意味が異なる記録（ドライブルート/祖先ディレクトリへの
/// traverse付与）を混在させないため、別ファイルにする。
///
/// ロック名を渡していない（＝read-modify-writeを直列化しない）のは移設前からの挙動を
/// そのまま保存しているため。複数`harness.exe`同時起動下でのロストアップデートは
/// `docs/STATUS.md`の残課題として扱う。
fn ledger() -> &'static Ledger<TraverseLedger> {
    static LEDGER: OnceLock<Ledger<TraverseLedger>> = OnceLock::new();
    LEDGER.get_or_init(|| Ledger::in_config_dir("traverse-grant-ledger.json", None))
}

/// 台帳ファイルのパス（`%APPDATA%\harness\config\traverse-grant-ledger.json`）。
pub fn traverse_ledger_path() -> Option<PathBuf> {
    ledger().path().map(Path::to_path_buf)
}

pub fn load_traverse_ledger() -> TraverseLedger {
    ledger().load()
}

pub fn save_traverse_ledger(ledger_value: &TraverseLedger) {
    ledger().save(ledger_value);
}

/// `grant-traverse`が実際にACE付与を試みたパスをtraverse台帳へ記録する（D10の巻き戻し用）。
/// 同一パスは上書き（冪等）。
pub fn record_traverse_grant(path: &Path) {
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = harness_grant_ledger::now_unix_secs();
    ledger().update(|l| {
        if let Some(entry) = l.entries.iter_mut().find(|e| e.path == path_str) {
            entry.granted_at_unix_secs = granted_at;
        } else {
            l.entries.push(TraverseLedgerEntry {
                path: path_str,
                granted_at_unix_secs: granted_at,
            });
        }
    });
}

pub fn remove_traverse_grant(path: &Path) {
    let path_str = path.to_string_lossy().into_owned();
    ledger().update(|l| l.entries.retain(|e| e.path != path_str));
}
