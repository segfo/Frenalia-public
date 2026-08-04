//! MCPサーバ宣言の承認台帳（D-39、`plans/DESIGN-MCP.md` §4.2）。
//!
//! ## なぜ承認が要るのか（他の設定と違う点）
//!
//! `.harness/settings.json`への**書込**は多層で塞がれている——`write_file`/`edit_file`はD-05の
//! hard-deny、`run_shell`の子孫はTier2aが`.harness`配下からpackage SIDのACEを除去、overlayの
//! `apply`はD-09で再チェックする。**しかしこれらはいずれも「書込」への防御である。**
//! リポジトリに最初から`.harness/settings.json`が同梱されていれば書込は一度も発生せず、
//! `Settings::load`はサンドボックスが立つより前に走るので、防ぐ機会がそこには無い。
//! この台帳はその経路のためだけに存在する。
//!
//! ## 置き場所が本質
//!
//! 台帳は**ワークスペースの外**（設定ディレクトリ、他の4台帳と同じ場所）に置く。リポジトリ側から
//! 内容を左右できてはいけないので、これは実装詳細ではなく要件である。read-modify-writeの
//! 直列化・`.bak`バックアップ・read-only属性による誤削除防止は`harness_grant_ledger::Ledger`が
//! 既に持っているものをそのまま使う。
//!
//! **Tier0ではこの台帳を守れない**（`run_shell`の子がharnessと同一権限で動くため設定ディレクトリ
//! へ書ける）。Tier0は隔離を放棄したリスク受容モードであり、この台帳もその前提を共有する。

use std::path::PathBuf;

use harness_grant_ledger::{now_unix_secs, Ledger};
use serde::{Deserialize, Serialize};

use crate::decl::McpServerDecl;

const LEDGER_FILE: &str = "mcp-approval-ledger.json";
const LEDGER_LOCK: &str = r"Local\harness-mcp-approval-ledger";

/// 台帳のペイロード。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpApprovalLedger {
    #[serde(default)]
    pub approvals: Vec<McpApproval>,
}

/// 承認1件。「この**宣言内容**を起動してよい」の記録であって、「このサーバは安全である」の
/// 記録ではない（承認済みのサーバもD-38の隔離の中で動く）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpApproval {
    pub id: String,
    /// [`McpServerDecl::approval_hash`]の値。
    pub decl_hash: String,
    pub approved_at_unix_secs: u64,
    /// 承認時点の宣言の要約（ユーザーが後から`harness mcp list`で見て思い出すため）。
    /// **照合には使わない**——照合は`decl_hash`だけで行う。
    #[serde(default)]
    pub summary: Option<String>,
}

impl McpApprovalLedger {
    /// この宣言が承認済みか。idとハッシュの**両方**が一致した場合のみ真。
    ///
    /// idだけの一致で通すと、承認済みidの中身をリポジトリ側で差し替える経路がそのまま開く。
    pub fn is_approved(&self, decl: &McpServerDecl) -> bool {
        let hash = decl.approval_hash();
        self.approvals
            .iter()
            .any(|a| a.id == decl.id && a.decl_hash == hash)
    }

    /// idに対する既存の承認（内容が変わって失効している場合の説明に使う）。
    pub fn approval_for_id(&self, id: &str) -> Option<&McpApproval> {
        self.approvals.iter().find(|a| a.id == id)
    }
}

/// 承認台帳のファイル。テストが`%APPDATA%`を汚さないよう[`ApprovalStore::at_path`]を持つ
/// （`harness_grant_ledger::Ledger`と同じ注入点の付け方）。
pub struct ApprovalStore {
    ledger: Ledger<McpApprovalLedger>,
}

impl Default for ApprovalStore {
    fn default() -> Self {
        Self::in_config_dir()
    }
}

impl ApprovalStore {
    pub fn in_config_dir() -> Self {
        Self {
            ledger: Ledger::in_config_dir(LEDGER_FILE, Some(LEDGER_LOCK)),
        }
    }

    pub fn at_path(path: PathBuf) -> Self {
        Self {
            ledger: Ledger::at_path(path, None),
        }
    }

    pub fn path(&self) -> Option<&std::path::Path> {
        self.ledger.path()
    }

    pub fn load(&self) -> McpApprovalLedger {
        self.ledger.load()
    }

    /// 宣言を承認する。同じidの古い承認は置き換える（1 idにつき承認は1件）。
    pub fn approve(&self, decl: &McpServerDecl) {
        let approval = McpApproval {
            id: decl.id.clone(),
            decl_hash: decl.approval_hash(),
            approved_at_unix_secs: now_unix_secs(),
            summary: Some(decl.describe()),
        };
        self.ledger.update(|l| {
            l.approvals.retain(|a| a.id != approval.id);
            l.approvals.push(approval);
        });
    }

    /// idの承認を取り消す。取り消した件数を返す。
    pub fn revoke(&self, id: &str) -> usize {
        self.ledger.update(|l| {
            let before = l.approvals.len();
            l.approvals.retain(|a| a.id != id);
            before - l.approvals.len()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::{McpNetworkDecl, McpServerDecl, McpTransportKind, McpWorkspaceAccess};

    fn decl(id: &str) -> McpServerDecl {
        McpServerDecl {
            id: id.to_string(),
            transport: McpTransportKind::Stdio,
            command: "node.exe".to_string(),
            args: vec!["server.js".to_string()],
            env: Default::default(),
            tools: Default::default(),
            network: McpNetworkDecl::default(),
            workspace: McpWorkspaceAccess::None,
        }
    }

    fn store() -> (tempfile::TempDir, ApprovalStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ApprovalStore::at_path(dir.path().join("mcp-approval-ledger.json"));
        (dir, store)
    }

    #[test]
    fn an_unapproved_declaration_is_not_approved() {
        let (_dir, store) = store();
        assert!(!store.load().is_approved(&decl("docs")));
    }

    #[test]
    fn approving_then_loading_recognises_the_same_declaration() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        assert!(store.load().is_approved(&d));
    }

    /// **D-39の中核**: 承認後に宣言の中身が変われば失効する。
    #[test]
    fn changing_the_declaration_after_approval_invalidates_it() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);

        let mut tampered = d.clone();
        tampered.args = vec!["evil.js".to_string()];
        assert!(
            !store.load().is_approved(&tampered),
            "a tampered declaration must not inherit the approval of the original"
        );
        // idそのものは残っているので、CLIは「承認はあるが内容が変わった」と説明できる。
        assert!(store.load().approval_for_id("docs").is_some());
    }

    /// idだけ合わせても通らない（別サーバの承認を借りられない）。
    #[test]
    fn approval_does_not_transfer_between_different_commands_with_the_same_id() {
        let (_dir, store) = store();
        store.approve(&decl("docs"));

        let mut impostor = decl("docs");
        impostor.command = "C:\\evil\\node.exe".to_string();
        assert!(!store.load().is_approved(&impostor));
    }

    #[test]
    fn re_approving_replaces_rather_than_appends() {
        let (_dir, store) = store();
        let mut d = decl("docs");
        store.approve(&d);
        d.args = vec!["v2.js".to_string()];
        store.approve(&d);

        let ledger = store.load();
        assert_eq!(ledger.approvals.len(), 1);
        assert!(ledger.is_approved(&d));
    }

    #[test]
    fn revoke_removes_the_approval() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        assert_eq!(store.revoke("docs"), 1);
        assert!(!store.load().is_approved(&d));
        assert_eq!(store.revoke("docs"), 0);
    }

    /// 台帳が壊れている/存在しない場合はデフォルト（＝何も承認されていない）として読む。
    /// **これはfail-closed**である——読めない台帳は「全部承認済み」ではなく「全部未承認」。
    #[test]
    fn a_corrupt_ledger_reads_as_no_approvals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-approval-ledger.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        let store = ApprovalStore::at_path(path);
        assert!(store.load().approvals.is_empty());
        assert!(!store.load().is_approved(&decl("docs")));
    }
}
