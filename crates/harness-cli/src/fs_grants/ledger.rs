//! fs passthrough台帳（D5）。`--fs-allow`と`.harness/settings.json`で実際にACEを付与した
//! パスを、どのプロジェクトからでも一括撤収できるよう1台帳へ集約する。
//!
//! ファイル入出力（誤削除防止の2層・fail-open・名前付きmutexによるRMW直列化）は
//! `harness-grant-ledger`の`Ledger<T>`が持つ。

use super::*;


/// fs passthrough台帳（D5、ユーザグローバル、`directories`設定ディレクトリ配下）の1エントリ。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct FsLedgerEntry {
    pub(crate) path: String,
    pub(crate) writable: bool,
    pub(crate) granted_at_unix_secs: u64,
    /// `--force-system-acl`（D-19）で`SeRestorePrivilege`を使って強制付与したか。
    /// 撤収時も同じ特権が要るため記録する。旧台帳（このフィールド欠落）は`false`扱い（後方互換）。
    #[serde(default)]
    pub(crate) forced: bool,
    /// このパスを現在`.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`で
    /// 宣言しているワークスペースroot文字列の集合（D-27、`vm_ledger::WorkspaceResourceEntry.refcount`
    /// と同型の参照カウント）。空なら「settings.json経由の宣言者が現在いない」。
    #[serde(default)]
    pub(crate) settings_workspaces: Vec<String>,
    /// 一度でも`.harness/settings.json`経由（`--fs-allow`ではなく）で付与されたことがあるか（D-27）。
    /// `false`のままなら`--fs-allow`専用エントリであり、`reconcile_fs_ledger_for_workspace`の
    /// 自動撤収対象にしない（D2/D3のsticky挙動を維持する）。
    #[serde(default)]
    pub(crate) settings_managed: bool,
}

/// 到達不能/付与失敗だったfs passthrough候補。`harness fs list`/`harness fs denied`で表示し、
/// `.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`へ後から足すための材料にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct FsDeniedLedgerEntry {
    pub(crate) path: String,
    pub(crate) access: String,
    pub(crate) reason: String,
    pub(crate) last_denied_at_unix_secs: u64,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct FsLedger {
    #[serde(default)]
    pub(crate) entries: Vec<FsLedgerEntry>,
    #[serde(default)]
    pub(crate) denied_entries: Vec<FsDeniedLedgerEntry>,
}

/// 台帳ファイル（`%APPDATA%\harness\config\fs-passthrough-ledger.json`）。横断的な穴を
/// 1台帳に集約し、どのプロジェクトからでも全撤収できるようにする（D5）。
///
/// ファイル入出力（誤削除防止の2層・fail-open）と、複数`harness.exe`同時起動下での
/// read-modify-write直列化（D-27）は`harness-grant-ledger`の`Ledger<T>`が持つ。
pub(crate) fn fs_ledger() -> &'static harness_grant_ledger::Ledger<FsLedger> {
    static LEDGER: std::sync::OnceLock<harness_grant_ledger::Ledger<FsLedger>> =
        std::sync::OnceLock::new();
    LEDGER.get_or_init(|| {
        harness_grant_ledger::Ledger::in_config_dir(
            "fs-passthrough-ledger.json",
            Some("Local\\harness-fs-passthrough-ledger"),
        )
    })
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（fail-open、起動を止めない）。
/// 単発の読取専用アクセス用。複合的なread-modify-writeには`fs_ledger().update(..)`を使うこと。
pub(crate) fn load_fs_ledger() -> FsLedger {
    fs_ledger().load()
}

/// `--fs-allow`/`.harness/settings.json`でTier2a preflightが実際にACE付与を試みたルートを
/// 台帳へ記録する（D2/D3）。同一パスは上書き（冪等）。ACE自体は「付けっぱなし」（D2）だが、
/// 台帳があるので後から`harness fs revoke`/`revoke-all`で一括撤収できる。
/// `settings_workspace`が`Some`なら、このパスが`.harness/settings.json`経由（`--fs-allow`ではなく）で
/// 宣言されたことを示し、`settings_workspaces`（D-27の参照カウント）へワークスペースrootを
/// dedup追加し`settings_managed`を立てる（一度立ったら以後trueのまま維持し、`--fs-allow`のみの
/// 再起動を挟んでも自動整合対象であり続ける）。
pub fn record_fs_passthrough_grant(
    path: &Path,
    writable: bool,
    forced: bool,
    settings_workspace: Option<&str>,
) {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        let granted_at = harness_grant_ledger::now_unix_secs();
        if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
            entry.writable = writable;
            entry.granted_at_unix_secs = granted_at;
            entry.forced = forced;
            if let Some(ws) = settings_workspace {
                if !entry.settings_workspaces.iter().any(|w| w == ws) {
                    entry.settings_workspaces.push(ws.to_string());
                }
                entry.settings_managed = true;
            }
        } else {
            ledger.entries.push(FsLedgerEntry {
                path: path_str.clone(),
                writable,
                granted_at_unix_secs: granted_at,
                forced,
                settings_workspaces: settings_workspace
                    .map(|ws| vec![ws.to_string()])
                    .unwrap_or_default(),
                settings_managed: settings_workspace.is_some(),
            });
        }
        ledger.denied_entries.retain(|e| e.path != path_str);
    });
}

pub fn record_fs_passthrough_denied(path: &Path, access: &str, reason: &str) {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        let denied_at = harness_grant_ledger::now_unix_secs();
        if let Some(entry) = ledger
            .denied_entries
            .iter_mut()
            .find(|e| e.path == path_str && e.access == access)
        {
            entry.reason = reason.to_string();
            entry.last_denied_at_unix_secs = denied_at;
            entry.count = entry.count.saturating_add(1);
        } else {
            ledger.denied_entries.push(FsDeniedLedgerEntry {
                path: path_str,
                access: access.to_string(),
                reason: reason.to_string(),
                last_denied_at_unix_secs: denied_at,
                count: 1,
            });
        }
    });
}

pub(crate) fn remove_fs_passthrough_grant(path: &Path) {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        ledger.entries.retain(|e| e.path != path_str);
        ledger.denied_entries.retain(|e| e.path != path_str);
    });
}

/// `reconcile_fs_ledger_for_workspace`専用の除去。orphan候補を確定してからACE撤収を試みるまでの
/// 間（ロックを一旦手放す）に、別プロセスが同じパスを新たに宣言し直す競合（TOCTOU）を考慮し、
/// 撤収成功後もなお「settings管理下で参照者ゼロ」のままである場合だけ台帳から除去する（D-27）。
/// 競合で参照者が復活していた場合は台帳エントリを残す（ACEは撤収済みのため、次回起動の
/// `reconcile_fs_ledger_for_workspace`が再度grantを試みて整合を取り戻す）。
#[cfg(windows)]
pub(crate) fn remove_fs_passthrough_grant_if_still_orphaned(path: &Path) {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        ledger.entries.retain(|e| {
            e.path != path_str || (e.settings_managed && !e.settings_workspaces.is_empty())
        });
        ledger.denied_entries.retain(|e| e.path != path_str);
    });
}

#[cfg(test)]
mod fs_ledger_tests {
    use super::{FsDeniedLedgerEntry, FsLedger, FsLedgerEntry};

    /// D-19以前に書かれた台帳（`forced`フィールドが無いJSON）が、`#[serde(default)]`で
    /// `forced=false`として読めることを確認する（後方互換）。台帳が読めないと既存のACEを
    /// 追跡できなくなり「付与した記憶はあるが記録が無い」孤立ACEに直結するため重要。
    #[test]
    fn legacy_ledger_without_forced_field_deserializes_as_not_forced() {
        let legacy = r#"{"entries":[
            {"path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu","writable":false,"granted_at_unix_secs":1700000000}
        ]}"#;
        let ledger: FsLedger = serde_json::from_str(legacy).expect("legacy ledger must parse");
        assert_eq!(ledger.entries.len(), 1);
        assert!(ledger.denied_entries.is_empty());
        assert!(
            !ledger.entries[0].forced,
            "missing forced field must default to false"
        );
    }

    /// `forced=true`の台帳が正しくラウンドトリップすることを確認する。
    #[test]
    fn forced_entry_roundtrips() {
        let ledger = FsLedger {
            entries: vec![FsLedgerEntry {
                path: r"C:\ProgramData\Microsoft\Windows\Start Menu".to_string(),
                writable: false,
                granted_at_unix_secs: 1_700_000_000,
                forced: true,
                settings_workspaces: Vec::new(),
                settings_managed: false,
            }],
            denied_entries: Vec::new(),
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert!(back.entries[0].forced);
    }

    #[test]
    fn denied_entries_roundtrip() {
        let ledger = FsLedger {
            entries: Vec::new(),
            denied_entries: vec![FsDeniedLedgerEntry {
                path: r"C:\Users\segfo\.local\bin".to_string(),
                access: "read_exec".to_string(),
                reason: "ACE grant failed".to_string(),
                last_denied_at_unix_secs: 1_700_000_001,
                count: 2,
            }],
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.denied_entries[0].access, "read_exec");
        assert_eq!(back.denied_entries[0].count, 2);
    }
}
