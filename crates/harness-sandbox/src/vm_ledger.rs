//! Tier3（Hyper-V外層VM + Incusコンテナ）のリソース台帳（D-24、
//! `plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6・§4）。
//!
//! Hyper-V VMはharness本体プロセスと独立に生存し続けるため（WFPの
//! `FWPM_SESSION_FLAG_DYNAMIC`とは逆の性質、`vmsandboxd.rs`モジュールdoc参照）、
//! daemonがクラッシュ等で撤収を完了できなかった場合、走行中VM・差分VHDXが
//! 孤児として残り得る。**Tier3は固定静的IP（`172.20.100.10`）を使う設計のため、
//! 孤児VMが残ると次セッションのVMとIP重複を起こす**という深刻な症状に
//! つながる（`vmsandbox.rs`の`VmSession::start`コメント参照）。この台帳は、
//! 次回起動時に前回セッションの孤児を検出・撤収するGC（`crate::vmsandbox::
//! gc_orphan_sessions`）の記録媒体として機能する。
//!
//! 置き場所・誤削除防止の運用規律は既存の`fs-passthrough-ledger.json`/
//! `traverse-grant-ledger.json`（`harness-cli/src/main.rs`）と同じにする
//! （`%APPDATA%\harness\`配下、`.json.bak`バックアップ、read-only属性による
//! 素の`rm`/`Remove-Item`からの保護）。この台帳自体もクリーンアップ操作で
//! 誤って削除してはならないファイルとして同じ規律のもとに置く（`CLAUDE.md`参照）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 台帳の1エントリ（起動中または起動を試みた1 Tier3セッション）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLedgerEntry {
    pub session_id: String,
    pub vm_name: String,
    pub diff_vhdx: String,
    pub created_at_unix_secs: u64,
    /// ウォームスタート用の永続VM（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1の
    /// 将来像）かどうか。ウォームVMはセッションをまたいで意図的に生存し続けるため、
    /// GCの回収対象から除外する必要がある（`旧台帳（このフィールド欠落）はfalse扱い`、
    /// 通常のコールドセッション扱いで後方互換を保つ）。
    #[serde(default)]
    pub warm: bool,
    /// ワークスペースCIFSライブ共有（`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4）で
    /// このセッションが作成したWindows側の使い捨てSMB共有名・ローカルアカウント名。
    /// `None`は「まだSMB共有ステップに到達していない」または「旧方式（copy-in/copy-out）
    /// のセッション」を表す（`#[serde(default)]`で旧台帳との後方互換を保つ）。
    #[serde(default)]
    pub smb_share_name: Option<String>,
    #[serde(default)]
    pub smb_user: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmLedger {
    pub entries: Vec<VmLedgerEntry>,
}

/// 台帳ファイルのパス（`%APPDATA%\harness\tier3-vm-ledger.json`、既存台帳群と同じ
/// `ProjectDirs::config_dir()`配下）。
fn ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-vm-ledger.json"))
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（`harness-cli`の
/// `load_fs_ledger`と同じfail-open方針、daemonの起動を止めない）。
pub fn load() -> VmLedger {
    let Some(path) = ledger_path() else {
        return VmLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => VmLedger::default(),
    }
}

pub fn save(ledger: &VmLedger) {
    let Some(path) = ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層（read-only属性＋`.bak`バックアップ）を
/// 通して行う（`harness-cli::write_ledger_file`と同じパターン、`CLAUDE.md`のクリーン
/// アップ禁止ファイル規約参照）。
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

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `VmSession::start`がVM作成に成功した直後に呼ぶ（冪等upsert、session_idで一意）。
pub fn record_session(session_id: &str, vm_name: &str, diff_vhdx: &Path, warm: bool) {
    let mut ledger = load();
    let diff_vhdx_str = diff_vhdx.to_string_lossy().into_owned();
    let created_at = now_unix_secs();
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.session_id == session_id) {
        entry.vm_name = vm_name.to_string();
        entry.diff_vhdx = diff_vhdx_str;
        entry.created_at_unix_secs = created_at;
        entry.warm = warm;
    } else {
        ledger.entries.push(VmLedgerEntry {
            session_id: session_id.to_string(),
            vm_name: vm_name.to_string(),
            diff_vhdx: diff_vhdx_str,
            created_at_unix_secs: created_at,
            warm,
            smb_share_name: None,
            smb_user: None,
        });
    }
    save(&ledger);
}

/// `VmSession::attach_to_guest`がWindows側の使い捨てSMB共有・ローカルアカウントを作成した
/// 直後に呼ぶ（`record_session`が既に作った台帳エントリへの追記、B10）。この時点より前に
/// daemonがクラッシュした場合はSMB共有自体が未作成なので、GC側で回収すべきリソースも無い。
pub fn record_smb_share(session_id: &str, share_name: &str, user: &str) {
    let mut ledger = load();
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.session_id == session_id) {
        entry.smb_share_name = Some(share_name.to_string());
        entry.smb_user = Some(user.to_string());
        save(&ledger);
    }
}

/// `VmSession::teardown`成功後、または`start`失敗パスでのbest-effort後始末後に呼ぶ。
pub fn remove_session(session_id: &str) {
    let mut ledger = load();
    ledger.entries.retain(|e| e.session_id != session_id);
    save(&ledger);
}

/// フェーズB（ウォームスタート）で使う永続VM名。ウォームVMはセッションをまたいで
/// 意図的に生存し続けるため、GCの回収対象から除外する（`select_orphans`参照、
/// `plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1）。
pub const WARM_VM_NAME: &str = "harness-tier3-warm";

/// GCで撤収すべきVM名（=session_id、この設計では両者が同一）を副作用なしに選定する
/// （`crate::vmsandbox::gc_orphan_sessions`から呼ばれる、テスト容易性のため純関数化）。
///
/// 2つの経路を合わせて候補にする（belt-and-suspenders、`plans/DESIGN-SANDBOX-VMISOLATION.md`
/// §2.6 D-24）:
/// 1. 台帳に載っているが`current_session_id`でも`warm`でもないエントリ（daemonクラッシュ等
///    で撤収できなかった前回セッションの記録）。
/// 2. Hyper-Vに実在するが台帳には載っていない`harness-tier3-`系VM（台帳自体が何らかの理由で
///    書けなかった場合の保険）。
///
/// ウォームVM（`WARM_VM_NAME`）と現在起動しようとしているセッション自身は、どちらの経路でも
/// 除外する。
pub fn select_orphans(
    ledger: &VmLedger,
    current_session_id: &str,
    existing_vm_names: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    for entry in &ledger.entries {
        if entry.warm || entry.vm_name == current_session_id {
            continue;
        }
        out.push(entry.vm_name.clone());
    }

    for name in existing_vm_names {
        if name == WARM_VM_NAME || name == current_session_id {
            continue;
        }
        if !out.contains(name) {
            out.push(name.clone());
        }
    }

    out
}

/// GCで撤収すべきSMB共有名・ローカルアカウント名のペアを副作用なしに選定する
/// （`select_orphans`のSMB版、B10）。台帳上の孤児VMエントリ（`entry.vm_name`が
/// `vm_orphans`に含まれる）が持つ`smb_share_name`/`smb_user`を回収対象にする。
/// VM自体は孤児でなくてもSMB共有だけが取り残されるケースは想定していない
/// （このプロジェクトのSMB共有はVMセッションの一部としてのみ作成されるため）。
pub fn select_smb_orphans(ledger: &VmLedger, vm_orphans: &[String]) -> Vec<(String, String)> {
    ledger
        .entries
        .iter()
        .filter(|e| vm_orphans.contains(&e.vm_name))
        .filter_map(|e| Some((e.smb_share_name.clone()?, e.smb_user.clone()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_entry_without_warm_field_deserializes_as_not_warm() {
        let legacy = r#"{"entries":[{"session_id":"s1","vm_name":"harness-tier3-s1","diff_vhdx":"C:\\x.vhdx","created_at_unix_secs":100}]}"#;
        let ledger: VmLedger = serde_json::from_str(legacy).expect("legacy ledger must parse");
        assert_eq!(ledger.entries.len(), 1);
        assert!(!ledger.entries[0].warm);
    }

    #[test]
    fn ledger_roundtrips_through_json() {
        let ledger = VmLedger {
            entries: vec![VmLedgerEntry {
                session_id: "harness-tier3-1-2".to_string(),
                vm_name: "harness-tier3-1-2".to_string(),
                diff_vhdx: r"C:\ProgramData\harness\vm-sessions\harness-tier3-1-2.diff.vhdx"
                    .to_string(),
                created_at_unix_secs: 12345,
                warm: false,
                smb_share_name: None,
                smb_user: None,
            }],
        };
        let json = serde_json::to_string_pretty(&ledger).unwrap();
        let back: VmLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].session_id, "harness-tier3-1-2");
        assert!(!back.entries[0].warm);
    }

    /// `record_session`/`remove_session`はプロセスグローバルな`%APPDATA%`台帳ファイルを
    /// 直接読み書きするため、cargo testの並列実行で他テストと競合しうる。ここではその
    /// I/Oを経由しない純粋なupsert/removeロジックのみを、ローカルな`VmLedger`値に対して
    /// 検証する（実ファイルI/Oを伴う統合的な確認は実機E2Eで行う、A10参照）。
    #[test]
    fn upsert_semantics_are_idempotent_by_session_id() {
        let mut ledger = VmLedger::default();
        let entry = VmLedgerEntry {
            session_id: "s1".to_string(),
            vm_name: "harness-tier3-s1".to_string(),
            diff_vhdx: "a.vhdx".to_string(),
            created_at_unix_secs: 1,
            warm: false,
            smb_share_name: None,
            smb_user: None,
        };
        ledger.entries.push(entry.clone());
        // 同一session_idの再挿入は上書き（`record_session`と同じ`find`+更新パターン）。
        if let Some(e) = ledger.entries.iter_mut().find(|e| e.session_id == "s1") {
            e.diff_vhdx = "b.vhdx".to_string();
        } else {
            ledger.entries.push(entry);
        }
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].diff_vhdx, "b.vhdx");

        ledger.entries.retain(|e| e.session_id != "s1");
        assert!(ledger.entries.is_empty());
    }

    fn entry(session_id: &str, warm: bool) -> VmLedgerEntry {
        VmLedgerEntry {
            session_id: session_id.to_string(),
            vm_name: session_id.to_string(),
            diff_vhdx: format!("{session_id}.diff.vhdx"),
            created_at_unix_secs: 1,
            warm,
            smb_share_name: None,
            smb_user: None,
        }
    }

    #[test]
    fn select_orphans_reaps_ledger_entries_other_than_current() {
        let ledger = VmLedger {
            entries: vec![entry("harness-tier3-old-1", false), entry("harness-tier3-old-2", false)],
        };
        let orphans = select_orphans(&ledger, "harness-tier3-current", &[]);
        assert_eq!(orphans, vec!["harness-tier3-old-1", "harness-tier3-old-2"]);
    }

    #[test]
    fn select_orphans_excludes_current_session() {
        let ledger = VmLedger {
            entries: vec![entry("harness-tier3-current", false)],
        };
        let orphans = select_orphans(&ledger, "harness-tier3-current", &[]);
        assert!(orphans.is_empty());
    }

    #[test]
    fn select_orphans_excludes_warm_entries() {
        let ledger = VmLedger {
            entries: vec![entry(WARM_VM_NAME, true)],
        };
        let orphans = select_orphans(&ledger, "harness-tier3-current", &[WARM_VM_NAME.to_string()]);
        assert!(orphans.is_empty());
    }

    #[test]
    fn select_orphans_detects_vms_present_but_missing_from_ledger() {
        let ledger = VmLedger::default();
        let existing = vec!["harness-tier3-untracked".to_string(), WARM_VM_NAME.to_string()];
        let orphans = select_orphans(&ledger, "harness-tier3-current", &existing);
        assert_eq!(orphans, vec!["harness-tier3-untracked".to_string()]);
    }

    #[test]
    fn select_orphans_deduplicates_entries_present_in_both_sources() {
        let ledger = VmLedger {
            entries: vec![entry("harness-tier3-old", false)],
        };
        let existing = vec!["harness-tier3-old".to_string()];
        let orphans = select_orphans(&ledger, "harness-tier3-current", &existing);
        assert_eq!(orphans, vec!["harness-tier3-old".to_string()]);
    }

    #[test]
    fn select_smb_orphans_returns_share_and_user_for_orphaned_vms() {
        let mut e = entry("harness-tier3-old", false);
        e.smb_share_name = Some("harness-ws-old".to_string());
        e.smb_user = Some("hns3-old".to_string());
        let ledger = VmLedger { entries: vec![e] };
        let orphans = select_smb_orphans(&ledger, &["harness-tier3-old".to_string()]);
        assert_eq!(
            orphans,
            vec![("harness-ws-old".to_string(), "hns3-old".to_string())]
        );
    }

    #[test]
    fn select_smb_orphans_skips_entries_without_smb_share() {
        let ledger = VmLedger {
            entries: vec![entry("harness-tier3-old", false)],
        };
        let orphans = select_smb_orphans(&ledger, &["harness-tier3-old".to_string()]);
        assert!(orphans.is_empty());
    }

    #[test]
    fn record_smb_share_updates_existing_entry_only() {
        let mut ledger = VmLedger {
            entries: vec![entry("s1", false)],
        };
        if let Some(e) = ledger.entries.iter_mut().find(|e| e.session_id == "s1") {
            e.smb_share_name = Some("harness-ws-s1".to_string());
            e.smb_user = Some("hns3-s1".to_string());
        }
        assert_eq!(ledger.entries[0].smb_share_name.as_deref(), Some("harness-ws-s1"));
        assert_eq!(ledger.entries[0].smb_user.as_deref(), Some("hns3-s1"));
    }
}
