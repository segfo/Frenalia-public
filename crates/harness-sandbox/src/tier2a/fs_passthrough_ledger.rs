//! fs passthrough台帳（D5）。`--fs-allow`と`.harness/settings.json`で実際にACEを付与した
//! パスを、どのプロジェクトからでも一括撤収できるよう1台帳へ集約する。
//!
//! 元々`crates/harness-cli/src/fs_grants/ledger.rs`にあったが、ACEを実際に付与する
//! `win_appcontainer::preflight`はこのクレート内にあり、**付与した側が記録する**という
//! 形にしないと台帳に載らない付与（＝撤収経路の無い孤立ACE、BUG-017）が生まれる。
//! `harness.exe`以外の付与側——ポリシーエディタのパス2
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）——からも記録できるよう、harness-cli→harness-sandboxの
//! 依存方向を逆流させないためここへ移動した（`traverse_ledger`とまったく同じ理由・同じ形）。
//! `harness fs list/revoke/prune`（harness-cli側）はこのモジュールの関数を呼ぶ。
//!
//! ファイル入出力（誤削除防止の2層・fail-open・名前付きmutexによるRMW直列化）は
//! `harness-grant-ledger`の`Ledger<T>`が持つ。本モジュールはこの台帳固有の
//! 「何を記録するか」だけを持つ。

use std::path::Path;


/// fs passthrough台帳（D5、ユーザグローバル、`directories`設定ディレクトリ配下）の1エントリ。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsLedgerEntry {
    pub path: String,
    pub writable: bool,
    pub granted_at_unix_secs: u64,
    /// `--force-system-acl`（D-19）で`SeRestorePrivilege`を使って強制付与したか。
    /// 撤収時も同じ特権が要るため記録する。旧台帳（このフィールド欠落）は`false`扱い（後方互換）。
    #[serde(default)]
    pub forced: bool,
    /// このパスを現在`.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`で
    /// 宣言しているワークスペースroot文字列の集合（D-27、`vm_ledger::WorkspaceResourceEntry.refcount`
    /// と同型の参照カウント）。空なら「settings.json経由の宣言者が現在いない」。
    #[serde(default)]
    pub settings_workspaces: Vec<String>,
    /// 一度でも`.harness/settings.json`経由（`--fs-allow`ではなく）で付与されたことがあるか（D-27）。
    /// `false`のままなら`--fs-allow`専用エントリであり、`reconcile_fs_ledger_for_workspace`の
    /// 自動撤収対象にしない（D2/D3のsticky挙動を維持する）。
    #[serde(default)]
    pub settings_managed: bool,
}

/// 到達不能/付与失敗だったfs passthrough候補。`harness fs list`/`harness fs denied`で表示し、
/// `.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`へ後から足すための材料にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FsDeniedLedgerEntry {
    pub path: String,
    pub access: String,
    pub reason: String,
    pub last_denied_at_unix_secs: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FsLedger {
    #[serde(default)]
    pub entries: Vec<FsLedgerEntry>,
    #[serde(default)]
    pub denied_entries: Vec<FsDeniedLedgerEntry>,
}

/// 台帳の中身をどう書き換えるかは、**ファイルにもロックにも触れない純粋な操作**として
/// ここに置く。`record_*`はロックを取って永続化するだけの薄い外皮になる。
///
/// 分けている理由は単体テストである。台帳ファイルはユーザグローバルな実ファイル1つきり
/// （`%APPDATA%\harness\config\fs-passthrough-ledger.json`、`docs/DEV-ENVIRONMENT.md`が
/// 「絶対に消してはいけないファイル」に挙げているもの）で、実マシンに残したACEを追跡する
/// 唯一の記録である。**テストのために本物を触ることはできない**ので、上書き規則の側だけを
/// 切り出して固定する。
impl FsLedger {
    /// `record_fs_passthrough_grant`の中身（同一パスは上書き＝冪等、`settings_workspaces`は
    /// dedup追加、`settings_managed`は一度立ったら降ろさない、拒否記録は消す）。
    pub fn upsert_grant(
        &mut self,
        path_str: String,
        writable: bool,
        forced: bool,
        settings_workspace: Option<&str>,
        granted_at: u64,
    ) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.path == path_str) {
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
            self.entries.push(FsLedgerEntry {
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
        // 付与できたパスは「到達不能候補」ではなくなる。両方に載ったままだと
        // `harness fs denied`が既に開いている穴を勧め続ける。
        self.denied_entries.retain(|e| e.path != path_str);
    }

    /// `record_fs_passthrough_denied`の中身（同一`(path, access)`は回数を積む）。
    pub fn record_denied(
        &mut self,
        path_str: String,
        access: &str,
        reason: &str,
        denied_at: u64,
    ) {
        if let Some(entry) = self
            .denied_entries
            .iter_mut()
            .find(|e| e.path == path_str && e.access == access)
        {
            entry.reason = reason.to_string();
            entry.last_denied_at_unix_secs = denied_at;
            entry.count = entry.count.saturating_add(1);
        } else {
            self.denied_entries.push(FsDeniedLedgerEntry {
                path: path_str,
                access: access.to_string(),
                reason: reason.to_string(),
                last_denied_at_unix_secs: denied_at,
                count: 1,
            });
        }
    }
}

/// 台帳ファイル（`%APPDATA%\harness\config\fs-passthrough-ledger.json`）。横断的な穴を
/// 1台帳に集約し、どのプロジェクトからでも全撤収できるようにする（D5）。
///
/// ファイル入出力（誤削除防止の2層・fail-open）と、複数`harness.exe`同時起動下での
/// read-modify-write直列化（D-27）は`harness-grant-ledger`の`Ledger<T>`が持つ。
pub fn fs_ledger() -> &'static harness_grant_ledger::Ledger<FsLedger> {
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
pub fn load_fs_ledger() -> FsLedger {
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
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| {
        ledger.upsert_grant(path_str, writable, forced, settings_workspace, granted_at)
    });
}

pub fn record_fs_passthrough_denied(path: &Path, access: &str, reason: &str) {
    let path_str = path.to_string_lossy().into_owned();
    let denied_at = harness_grant_ledger::now_unix_secs();
    fs_ledger().update(|ledger| ledger.record_denied(path_str, access, reason, denied_at));
}

pub fn remove_fs_passthrough_grant(path: &Path) {
    fs_ledger().update(|ledger| {
        let path_str = path.to_string_lossy().into_owned();
        ledger.entries.retain(|e| e.path != path_str);
        ledger.denied_entries.retain(|e| e.path != path_str);
    });
}

/// `should_remove`がtrueを返したパスのエントリを台帳から落とす（`harness fs prune`、D-53）。
/// `entries`と`denied_entries`の両方が対象。返り値は実際に落としたパスの一覧。
///
/// **判定（何を落とすか）は呼び出し側が持ち、本関数はロックと永続化だけを持つ。** 台帳ファイルを
/// 所有するのはこのモジュールなので、CLI側で`load`→`save`する形にはしない（複数`harness.exe`
/// 同時起動下のlost updateを避ける、R-01）。
pub fn prune_fs_ledger_entries(should_remove: impl Fn(&Path) -> bool) -> Vec<String> {
    fs_ledger().update(|ledger| {
        let mut removed = Vec::new();
        ledger.entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        ledger.denied_entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        removed
    })
}

/// `reconcile_fs_ledger_for_workspace`専用の除去。orphan候補を確定してからACE撤収を試みるまでの
/// 間（ロックを一旦手放す）に、別プロセスが同じパスを新たに宣言し直す競合（TOCTOU）を考慮し、
/// 撤収成功後もなお「settings管理下で参照者ゼロ」のままである場合だけ台帳から除去する（D-27）。
/// 競合で参照者が復活していた場合は台帳エントリを残す（ACEは撤収済みのため、次回起動の
/// `reconcile_fs_ledger_for_workspace`が再度grantを試みて整合を取り戻す）。
#[cfg(windows)]
pub fn remove_fs_passthrough_grant_if_still_orphaned(path: &Path) {
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

    const PATH: &str = r"C:\Users\segfo\.cargo";

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

    /// 同じパスを2回付与しても**エントリは1件のまま**（冪等な上書き）。
    /// 増えると`harness fs revoke-all`が同じパスを何度も撤収しようとする。
    #[test]
    fn granting_the_same_path_twice_upserts_instead_of_appending() {
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(PATH.to_string(), false, false, None, 100);
        ledger.upsert_grant(PATH.to_string(), true, true, None, 200);

        assert_eq!(ledger.entries.len(), 1, "the same path must not accumulate");
        assert!(ledger.entries[0].writable, "the newest access wins");
        assert!(ledger.entries[0].forced);
        assert_eq!(ledger.entries[0].granted_at_unix_secs, 200);
    }

    /// `settings.json`由来の宣言者（D-27の参照カウント）は**重複追加しない**。
    /// 同じworkspaceの再起動ごとに積むと、参照者ゼロの判定が永遠に成立しなくなる。
    #[test]
    fn the_declaring_workspaces_are_deduped_and_settings_managed_never_goes_back_down() {
        let mut ledger = FsLedger::default();
        ledger.upsert_grant(PATH.to_string(), false, false, Some(r"C:\ws"), 100);
        ledger.upsert_grant(PATH.to_string(), false, false, Some(r"C:\ws"), 200);
        ledger.upsert_grant(PATH.to_string(), false, false, Some(r"C:\other"), 300);

        assert_eq!(
            ledger.entries[0].settings_workspaces,
            vec![r"C:\ws".to_string(), r"C:\other".to_string()]
        );
        assert!(ledger.entries[0].settings_managed);

        // `--fs-allow`だけの再起動（settings_workspace = None）を挟んでも降ろさない。
        ledger.upsert_grant(PATH.to_string(), false, false, None, 400);
        assert!(
            ledger.entries[0].settings_managed,
            "settings_managed must stay true once set (D-27: otherwise the entry silently drops \
             out of automatic reconciliation)"
        );
        assert_eq!(ledger.entries[0].settings_workspaces.len(), 2);
    }

    /// 付与に成功したパスは「到達不能候補」から**消える**。両方に残ると
    /// `harness fs denied`が既に開いている穴を勧め続ける。
    #[test]
    fn a_successful_grant_clears_the_denied_record_for_the_same_path() {
        let mut ledger = FsLedger::default();
        ledger.record_denied(PATH.to_string(), "read_exec", "ACCESS_DENIED", 100);
        assert_eq!(ledger.denied_entries.len(), 1);

        ledger.upsert_grant(PATH.to_string(), false, false, None, 200);

        assert!(
            ledger.denied_entries.is_empty(),
            "granting must retire the denied candidate"
        );
    }

    /// 同じ`(path, access)`の拒否は**回数を積む**（別accessは別エントリ）。
    #[test]
    fn repeated_denials_increment_the_count_and_different_access_kinds_stay_separate() {
        let mut ledger = FsLedger::default();
        ledger.record_denied(PATH.to_string(), "read_exec", "first", 100);
        ledger.record_denied(PATH.to_string(), "read_exec", "second", 200);
        ledger.record_denied(PATH.to_string(), "read_write", "third", 300);

        assert_eq!(ledger.denied_entries.len(), 2);
        let read_exec = ledger
            .denied_entries
            .iter()
            .find(|e| e.access == "read_exec")
            .unwrap();
        assert_eq!(read_exec.count, 2);
        assert_eq!(read_exec.reason, "second", "the newest reason wins");
        assert_eq!(read_exec.last_denied_at_unix_secs, 200);
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
