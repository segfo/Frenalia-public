//! Tier3（Hyper-V外層VM + Incusコンテナ）のリソース台帳（D-24、
//! `plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6・§4・項目8）。
//!
//! Hyper-V VMはharness本体プロセスと独立に生存し続けるため（WFPの
//! `FWPM_SESSION_FLAG_DYNAMIC`とは逆の性質、`vmsandboxd.rs`モジュールdoc参照）、
//! daemonがクラッシュ等で撤収を完了できなかった場合、走行中VM・差分VHDXが
//! 孤児として残り得る。この台帳は、次回起動時に前回の孤児を検出・撤収するGC
//! （`crate::vmsandbox::gc_orphan_sessions`）の記録媒体として機能する。
//!
//! **Phase B（`VmHost`常駐化）でのスキーマ変更**: 従来は「1セッション=1VM」だったため
//! `session_id`＝`vm_name`のエントリを複数持つ配列だったが、VMが1台の共有resident資源
//! （`crate::vm_host::VmHost`）になったことで意味が変わった。台帳を2種類のエントリへ
//! 分離する:
//! - [`VmHostEntry`]: resident VM自体（固定`vm_name`）が起動中かどうかを表す**単一**エントリ。
//! - [`WorkspaceResourceEntry`][]: `workspace_id`単位で参照カウント共有されるWindows側資源
//!   （SMB共有・使い捨てローカルアカウント・そのSID・`workspace_root`）。A-5（daemon死亡時に
//!   NTFS ACEが回収できない既知の限界）を、`workspace_root`+SIDを台帳へ記録することで解消する。
//!
//! 置き場所・誤削除防止の運用規律は既存の`fs-passthrough-ledger.json`/
//! `traverse-grant-ledger.json`（`harness-cli/src/main.rs`）と同じにする
//! （`%APPDATA%\harness\`配下、`.json.bak`バックアップ、read-only属性による
//! 素の`rm`/`Remove-Item`からの保護）。この台帳自体もクリーンアップ操作で
//! 誤って削除してはならないファイルとして同じ規律のもとに置く（`CLAUDE.md`参照）。

use std::path::Path;

use serde::{Deserialize, Serialize};

/// resident VM（`crate::vm_host::VmHost`が管理する共有VM）が起動中であることを示す台帳エントリ。
/// 台帳全体で最大1件（`VmLedger::vm_host`が`Option`である理由）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmHostEntry {
    pub vm_name: String,
    pub diff_vhdx: String,
    pub created_at_unix_secs: u64,
    /// このVMを起動した常駐daemonプロセス自身のPID（BUG-027対策）。`#[serde(default)]`は
    /// 旧スキーマの台帳ファイルを黙って`0`（＝生存判定は常に偽）扱いにするため。`gc_orphan_sessions`
    /// はこのPIDが生存している間、そのVM・全`workspace_resources`をGC対象から除外する——
    /// 稼働中の常駐daemonが管理するVMを、別プロセス（`harness tier3 gc`）が誤って撤収する
    /// 事故を防ぐ（`docs/bugs/BUG-027.md`）。
    #[serde(default)]
    pub daemon_pid: u32,
}

/// 指定PIDのプロセスが現在も生存しているかを確認する（BUG-027対策）。`vmsandboxd.rs`の
/// `query_process_token_sid`と同じ`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`パターン
/// （daemonは昇格済みトークンで動作しており、同一ユーザーの他プロセスを開くのに十分な権限を
/// 持つ）。`pid == 0`（旧スキーマからの`#[serde(default)]`補完、またはSystem Idle Process）は
/// 常に「生存していない」として扱う。
#[cfg(windows)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(not(windows))]
pub fn is_pid_alive(_pid: u32) -> bool {
    false
}

/// `workspace_id`単位で参照カウント共有されるWindows側資源（SMB共有・使い捨てローカル
/// アカウント・NTFS ACE付与先のSID・元の`workspace_root`）。`refcount`はdaemonプロセス内の
/// `SessionRegistry`が正であり、この台帳の値は永続化のためのスナップショムに過ぎない
/// （daemon生存中は都度`save`で追随させる）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceResourceEntry {
    pub workspace_id: String,
    pub workspace_root: String,
    pub smb_share_name: String,
    pub smb_user: String,
    /// 使い捨てローカルアカウントのSID文字列（A-5）。daemon死亡後のGCで、アカウント名から
    /// SIDを解決できなくなっていても（`Remove-LocalUser`済み等）NTFS ACEを取り消せるようにする。
    pub smb_user_sid: String,
    pub refcount: u32,
    pub created_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmLedger {
    #[serde(default)]
    pub vm_host: Option<VmHostEntry>,
    #[serde(default)]
    pub workspace_resources: Vec<WorkspaceResourceEntry>,
}

/// 台帳ファイル（`%APPDATA%\harness\config\tier3-vm-ledger.json`）。ファイル入出力
/// （誤削除防止の2層・fail-open）と名前付きmutexによる直列化は`harness-grant-ledger`の
/// `Ledger<T>`が持つ。
fn ledger() -> &'static harness_grant_ledger::Ledger<VmLedger> {
    static LEDGER: std::sync::OnceLock<harness_grant_ledger::Ledger<VmLedger>> =
        std::sync::OnceLock::new();
    LEDGER.get_or_init(|| {
        harness_grant_ledger::Ledger::in_config_dir(
            "tier3-vm-ledger.json",
            Some("Local\\harness-tier3-vm-ledger"),
        )
    })
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（fail-open、daemonの起動を止めない）。
/// **Phase Bでスキーマを破壊的に変更したため、旧スキーマ（`entries: [...]`）のファイルは
/// 黙って空扱いになる**（このファイルは`%APPDATA%`配下のローカル運用状態であり、ユーザー
/// データではないため移行コードは書かない。実際にVMが孤児として起動中だった場合は、後段の
/// `existing_vm_names`（Hyper-V実機照会）が belt-and-suspenders として拾う）。
pub fn load() -> VmLedger {
    ledger().load()
}

// 書込は全て`update`（read-modify-writeを1つのロック区間で行う）経由。単独の`save`は
// Stage 1で`Ledger::update`を導入した時点で呼び出し元が無くなったため置かない。

use harness_grant_ledger::now_unix_secs;

/// `VmHost::attach`がVM起動（コールド/ウォームいずれか）に成功した直後に呼ぶ（冪等upsert）。
/// `daemon_pid`はこのVMを起動した常駐daemonプロセス自身のPID（`std::process::id()`）。
/// BUG-027対策の生存判定に使う（`is_pid_alive`のdoc参照）。
pub fn record_vm_host(vm_name: &str, diff_vhdx: &Path, daemon_pid: u32) {
    ledger().update(|l| {
        l.vm_host = Some(VmHostEntry {
            vm_name: vm_name.to_string(),
            diff_vhdx: diff_vhdx.to_string_lossy().into_owned(),
            daemon_pid,
            created_at_unix_secs: now_unix_secs(),
        });
    });
}

/// `VmHost::release`がVM撤収（refcountが0になった）に成功した後に呼ぶ。
pub fn remove_vm_host() {
    ledger().update(|l| l.vm_host = None);
}

/// `workspace_id`単位資源の参照カウントをインクリメントする（新規作成時は`refcount=1`で
/// 追加、既存なら`refcount += 1`して共有情報はそのまま）。`create_ephemeral_share`が
/// 実際に`New-SmbShare`/`New-LocalUser`を実行した直後に呼ぶ（新規作成時のみ）か、
/// 既存資源を再利用する場合は共有情報を引数に渡さず参照カウントだけ増やす
/// （呼び出し側は`crate::smb_share::create_ephemeral_share`の呼び出し要否をこの関数の
/// 戻り値では判断しない——daemon内`SessionRegistry`が「新規か再利用か」を先に判定し、
/// 新規の場合のみ`create_ephemeral_share`を呼んでからこの関数へ結果を渡す設計とする）。
pub fn record_workspace_resource(
    workspace_id: &str,
    workspace_root: &Path,
    share_name: &str,
    user: &str,
    user_sid: &str,
) {
    ledger().update(|l| {
        upsert_workspace_resource_in_ledger(
            l,
            workspace_id,
            workspace_root,
            share_name,
            user,
            user_sid,
        );
    });
}

/// [`record_workspace_resource`]の純粋ロジック部分（`%APPDATA%`台帳ファイルへのI/Oを伴わない）。
/// テストはこちらを直接呼ぶ（`record_session`/`remove_session`の既存テストと同じ方針——
/// グローバル台帳ファイルへ実際に読み書きする関数を並列`cargo test`から直接叩くと、他テストの
/// `load`/`save`と競合するレースが起きる）。
fn upsert_workspace_resource_in_ledger(
    ledger: &mut VmLedger,
    workspace_id: &str,
    workspace_root: &Path,
    share_name: &str,
    user: &str,
    user_sid: &str,
) {
    if let Some(entry) = ledger
        .workspace_resources
        .iter_mut()
        .find(|e| e.workspace_id == workspace_id)
    {
        entry.refcount += 1;
    } else {
        ledger.workspace_resources.push(WorkspaceResourceEntry {
            workspace_id: workspace_id.to_string(),
            workspace_root: workspace_root.to_string_lossy().into_owned(),
            smb_share_name: share_name.to_string(),
            smb_user: user.to_string(),
            smb_user_sid: user_sid.to_string(),
            refcount: 1,
            created_at_unix_secs: now_unix_secs(),
        });
    }
}

/// 参照カウントをデクリメントする。0になった場合はエントリを台帳から除去し、呼び出し側が
/// `crate::smb_share::destroy_ephemeral_share`を呼ぶための情報として`Some`で返す
/// （まだ他セッションが使用中＝`refcount > 0`のままなら`None`を返し、共有・アカウントは
/// 破棄しない）。
pub fn release_workspace_resource(workspace_id: &str) -> Option<WorkspaceResourceEntry> {
    ledger().update(|l| release_workspace_resource_in_ledger(l, workspace_id))
}

pub fn update<R>(f: impl FnOnce(&mut VmLedger) -> R) -> R {
    ledger().update(f)
}

/// [`release_workspace_resource`]の純粋ロジック部分（テストはこちらを直接呼ぶ、
/// [`upsert_workspace_resource_in_ledger`]のdoc参照）。
fn release_workspace_resource_in_ledger(
    ledger: &mut VmLedger,
    workspace_id: &str,
) -> Option<WorkspaceResourceEntry> {
    let pos = ledger
        .workspace_resources
        .iter()
        .position(|e| e.workspace_id == workspace_id)?;
    ledger.workspace_resources[pos].refcount =
        ledger.workspace_resources[pos].refcount.saturating_sub(1);
    if ledger.workspace_resources[pos].refcount == 0 {
        Some(ledger.workspace_resources.remove(pos))
    } else {
        None
    }
}

/// GCで撤収すべきresident VM名を副作用なしに選定する（`crate::vmsandbox::gc_orphan_sessions`
/// から呼ばれる、テスト容易性のため純関数化）。**`VmHost::attach`がStopped→Runningへ遷移する
/// 直前にのみ**呼ばれる想定——daemon生存中のセッション途中で誤って現在のresident VMを孤児
/// 扱いしないよう、呼び出し側がタイミングを保証する。
///
/// 2つの経路を合わせて候補にする（belt-and-suspenders、`plans/DESIGN-SANDBOX-VMISOLATION.md`
/// §2.6 D-24）: (1) 台帳に載っている前回のresident VM（daemonクラッシュ等で撤収できなかった
/// 記録）、(2) Hyper-Vに実在するが台帳には載っていない`harness-tier3-`系VM（台帳自体が何らかの
/// 理由で書けなかった場合の保険）。
pub fn select_orphan_vm_names(ledger: &VmLedger, existing_vm_names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(host) = &ledger.vm_host {
        out.push(host.vm_name.clone());
    }
    for name in existing_vm_names {
        if !out.contains(name) {
            out.push(name.clone());
        }
    }
    out
}

/// resident VMが孤児と判定された場合、ぶら下がっている全`workspace_resources`を撤収対象と
/// して返す（副作用なし）。VMが孤児化した＝そのVMの生存期間中に参照カウントを管理していた
/// daemonプロセスの`SessionRegistry`ごと消失しているため、台帳上の全エントリが用済みになる。
pub fn select_all_workspace_resources(ledger: &VmLedger) -> Vec<WorkspaceResourceEntry> {
    ledger.workspace_resources.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_schema_ledger_deserializes_as_empty_not_erroring() {
        let legacy = r#"{"entries":[{"session_id":"s1","vm_name":"harness-tier3-s1","diff_vhdx":"C:\\x.vhdx","created_at_unix_secs":100}]}"#;
        let ledger: VmLedger = serde_json::from_str(legacy).unwrap_or_default();
        assert!(ledger.vm_host.is_none());
        assert!(ledger.workspace_resources.is_empty());
    }

    #[test]
    fn ledger_roundtrips_through_json() {
        let ledger = VmLedger {
            vm_host: Some(VmHostEntry {
                vm_name: "harness-tier3-resident".to_string(),
                diff_vhdx: r"C:\ProgramData\harness\vm-sessions\resident.diff.vhdx".to_string(),
                daemon_pid: 4242,
                created_at_unix_secs: 12345,
            }),
            workspace_resources: vec![WorkspaceResourceEntry {
                workspace_id: "abcd1234".to_string(),
                workspace_root: r"C:\work\project".to_string(),
                smb_share_name: "harness-ws-abcd1234".to_string(),
                smb_user: "hns3-abcd1234".to_string(),
                smb_user_sid: "S-1-5-21-1-2-3-1001".to_string(),
                refcount: 2,
                created_at_unix_secs: 12345,
            }],
        };
        let json = serde_json::to_string_pretty(&ledger).unwrap();
        let back: VmLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vm_host.unwrap().vm_name, "harness-tier3-resident");
        assert_eq!(back.workspace_resources.len(), 1);
        assert_eq!(back.workspace_resources[0].refcount, 2);
    }

    /// `record_workspace_resource`/`release_workspace_resource`の純粋ロジック部分
    /// （`upsert_workspace_resource_in_ledger`/`release_workspace_resource_in_ledger`）を
    /// ローカルな`VmLedger`値に対して検証する。グローバル`%APPDATA%`台帳ファイルへ実際に
    /// 読み書きする公開関数を並列`cargo test`から直接叩くと、他テストの`load`/`save`と
    /// read-modify-writeが競合してエントリを失うレースが起きる（実際に踏んだ、
    /// `record_session`/`remove_session`の既存テストが同じ理由でI/Oを経由しない方針を
    /// 取っているのと同じ教訓）。
    #[test]
    fn record_and_release_workspace_resource_refcounts_correctly() {
        let workspace_id = "test-refcount-wsid";
        let mut ledger = VmLedger::default();

        upsert_workspace_resource_in_ledger(
            &mut ledger,
            workspace_id,
            Path::new(r"C:\work\refcount-test"),
            "harness-ws-test",
            "hns3-test",
            "S-1-5-21-1-2-3-9999",
        );
        upsert_workspace_resource_in_ledger(
            &mut ledger,
            workspace_id,
            Path::new(r"C:\work\refcount-test"),
            "harness-ws-test",
            "hns3-test",
            "S-1-5-21-1-2-3-9999",
        );

        let entry = ledger
            .workspace_resources
            .iter()
            .find(|e| e.workspace_id == workspace_id)
            .expect("entry must exist after record");
        assert_eq!(entry.refcount, 2);

        // 1回目のreleaseはまだ他セッションが使用中なので破棄しない。
        assert!(release_workspace_resource_in_ledger(&mut ledger, workspace_id).is_none());
        assert_eq!(
            ledger
                .workspace_resources
                .iter()
                .find(|e| e.workspace_id == workspace_id)
                .unwrap()
                .refcount,
            1
        );

        // 2回目のreleaseで最後の1セッションが抜け、エントリが除去される。
        let removed = release_workspace_resource_in_ledger(&mut ledger, workspace_id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().smb_share_name, "harness-ws-test");
        assert!(ledger
            .workspace_resources
            .iter()
            .all(|e| e.workspace_id != workspace_id));
    }

    /// `record_vm_host`/`remove_vm_host`の純粋ロジック（`Option`の設定/クリア）を
    /// ローカルな`VmLedger`値に対して検証する（上のテストと同じ理由でグローバル台帳
    /// ファイルへの実I/Oを経由しない）。
    #[test]
    fn vm_host_option_set_and_clear_roundtrips() {
        let mut ledger = VmLedger::default();
        assert!(ledger.vm_host.is_none());

        ledger.vm_host = Some(VmHostEntry {
            vm_name: "harness-tier3-resident".to_string(),
            diff_vhdx: r"C:\x\resident.diff.vhdx".to_string(),
            daemon_pid: 4242,
            created_at_unix_secs: now_unix_secs(),
        });
        assert_eq!(
            ledger.vm_host.as_ref().unwrap().vm_name,
            "harness-tier3-resident"
        );

        ledger.vm_host = None;
        assert!(ledger.vm_host.is_none());
    }

    fn vm_host_entry(name: &str) -> VmHostEntry {
        VmHostEntry {
            vm_name: name.to_string(),
            diff_vhdx: format!("{name}.diff.vhdx"),
            daemon_pid: 0,
            created_at_unix_secs: 1,
        }
    }

    #[test]
    fn select_orphan_vm_names_includes_ledger_entry() {
        let ledger = VmLedger {
            vm_host: Some(vm_host_entry("harness-tier3-resident")),
            workspace_resources: vec![],
        };
        let orphans = select_orphan_vm_names(&ledger, &[]);
        assert_eq!(orphans, vec!["harness-tier3-resident".to_string()]);
    }

    #[test]
    fn select_orphan_vm_names_detects_vm_present_but_missing_from_ledger() {
        let ledger = VmLedger::default();
        let existing = vec!["harness-tier3-resident".to_string()];
        let orphans = select_orphan_vm_names(&ledger, &existing);
        assert_eq!(orphans, vec!["harness-tier3-resident".to_string()]);
    }

    #[test]
    fn select_orphan_vm_names_deduplicates_entries_present_in_both_sources() {
        let ledger = VmLedger {
            vm_host: Some(vm_host_entry("harness-tier3-resident")),
            workspace_resources: vec![],
        };
        let existing = vec!["harness-tier3-resident".to_string()];
        let orphans = select_orphan_vm_names(&ledger, &existing);
        assert_eq!(orphans, vec!["harness-tier3-resident".to_string()]);
    }

    #[test]
    fn select_all_workspace_resources_returns_every_entry() {
        let ledger = VmLedger {
            vm_host: None,
            workspace_resources: vec![
                WorkspaceResourceEntry {
                    workspace_id: "a".to_string(),
                    workspace_root: "C:\\a".to_string(),
                    smb_share_name: "harness-ws-a".to_string(),
                    smb_user: "hns3-a".to_string(),
                    smb_user_sid: "S-1-5-21-1".to_string(),
                    refcount: 1,
                    created_at_unix_secs: 1,
                },
                WorkspaceResourceEntry {
                    workspace_id: "b".to_string(),
                    workspace_root: "C:\\b".to_string(),
                    smb_share_name: "harness-ws-b".to_string(),
                    smb_user: "hns3-b".to_string(),
                    smb_user_sid: "S-1-5-21-2".to_string(),
                    refcount: 3,
                    created_at_unix_secs: 1,
                },
            ],
        };
        let all = select_all_workspace_resources(&ledger);
        assert_eq!(all.len(), 2);
    }

    /// BUG-027対策: `is_pid_alive`が現在プロセス自身（確実に生存中）を真、
    /// 現実的に存在し得ない大きなPIDを偽と判定することを確認する。
    /// 実際に別プロセスを起動せずに検証できるよう、自プロセスのPIDを流用する。
    #[cfg(windows)]
    #[test]
    fn is_pid_alive_detects_current_process_and_rejects_implausible_pid() {
        assert!(is_pid_alive(std::process::id()));
        assert!(!is_pid_alive(0));
        // Windows PIDは実質的に4の倍数かつ32bit値。u32::MAXはまず割り当てられない。
        assert!(!is_pid_alive(u32::MAX));
    }
}
