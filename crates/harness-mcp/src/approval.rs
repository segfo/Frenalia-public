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
    /// 記録した時点の**宣言の形の版**（[`crate::decl::DECL_FORMAT_VERSION`]）。
    ///
    /// `None`は版という欄が無かった頃に書かれたエントリで、版1として扱う。
    /// **古い台帳がそのまま読める**ことがこの欄を`Option`にしている理由である。
    #[serde(default)]
    pub decl_format_version: Option<u32>,
}

impl McpApproval {
    /// いまの harness が使っている宣言の形で記録されたエントリか。
    ///
    /// 偽なら、この承認は**harnessが宣言に欄を増やしたことで失効した**もので、
    /// ユーザーが宣言を書き換えたわけではない。
    fn is_current_format(&self) -> bool {
        self.decl_format_version.unwrap_or(1) == crate::decl::DECL_FORMAT_VERSION
    }
}

impl McpApprovalLedger {
    /// この宣言が承認済みか。id・ハッシュ・**宣言の形の版**がすべて一致した場合のみ真。
    ///
    /// idだけの一致で通すと、承認済みidの中身をリポジトリ側で差し替える経路がそのまま開く。
    ///
    /// **版も見るのは、ハッシュ差に頼らないためである。** 欄を1つ増やせば正規化JSONが変わるので
    /// 普通はハッシュ側だけで落ちるが、版を上げる理由は欄の追加とは限らない（正規化の仕方を
    /// 変える等）。**そのときハッシュが偶然一致すると、古い形で承認したものが通ってしまう。**
    /// 版を条件に入れておけば、理由が何であれ「形が変わったら通さない」が成立する
    /// （[`crate::decl::DECL_FORMAT_VERSION`]。倒れる向きは常に fail-closed）。
    pub fn is_approved(&self, decl: &McpServerDecl) -> bool {
        let hash = decl.approval_hash();
        self.approvals
            .iter()
            .any(|a| a.id == decl.id && a.decl_hash == hash && a.is_current_format())
    }

    /// idに対する既存の承認（内容が変わって失効している場合の説明に使う）。
    ///
    /// **版が古いエントリは返さない。** 返すと、harnessが宣言に欄を増やしたことによる失効が
    /// 「ユーザーが宣言を書き換えた」という断り文で案内されてしまう
    /// （[`crate::decl::DECL_FORMAT_VERSION`]）。無かったものとして扱えば、
    /// 断り文は既存の「宣言はあるが未承認」1本で足り、**その文はどの場合でも正しい**。
    pub fn approval_for_id(&self, id: &str) -> Option<&McpApproval> {
        self.approvals
            .iter()
            .find(|a| a.id == id && a.is_current_format())
    }

    /// **harnessが宣言の形を変えたせいで無視している承認**があるか。
    ///
    /// 起動時に理由を1行出すためだけに使う（[`Self::is_approved`]も
    /// [`Self::approval_for_id`]もこれを見ない）。**理由を出さないと、
    /// 「昨日まで動いていたサーバが黙って起動しなくなった」になる。**
    pub fn is_voided_by_format_upgrade(&self, id: &str) -> bool {
        self.approvals
            .iter()
            .any(|a| a.id == id && !a.is_current_format())
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
            decl_format_version: Some(crate::decl::DECL_FORMAT_VERSION),
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
    use crate::decl::{
        McpNetworkDecl, McpProcessAccess, McpServerDecl, McpTransportKind, McpWorkspaceAccess,
    };

    fn decl(id: &str) -> McpServerDecl {
        McpServerDecl {
            id: id.to_string(),
            transport: McpTransportKind::Stdio,
            command: "node.exe".to_string(),
            args: vec!["server.js".to_string()],
            env: Default::default(),
            url: String::new(),
            headers: Default::default(),
            tls_pin: None,
            tools: Default::default(),
            network: McpNetworkDecl::default(),
            workspace: McpWorkspaceAccess::None,
            process: McpProcessAccess::Deny,
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

    /// 版を1つ古くしたエントリを1件だけ持つ台帳。
    fn ledger_with_version(d: &McpServerDecl, version: Option<u32>) -> McpApprovalLedger {
        McpApprovalLedger {
            approvals: vec![McpApproval {
                id: d.id.clone(),
                decl_hash: d.approval_hash(),
                approved_at_unix_secs: 0,
                summary: None,
                decl_format_version: version,
            }],
        }
    }

    /// **版が古い承認は「無かったもの」として扱う**（[`crate::decl::DECL_FORMAT_VERSION`]）。
    ///
    /// ハッシュがたまたま一致していても（このテストは一致させている）、
    /// `approval_for_id`は返さない——返すと、harnessが宣言に欄を増やしたことによる失効が
    /// 「あなたが宣言を書き換えた」という断り文で案内されてしまう。
    #[test]
    fn an_approval_recorded_under_an_older_declaration_format_is_ignored() {
        let d = decl("docs");
        for stale in [None, Some(crate::decl::DECL_FORMAT_VERSION - 1)] {
            let ledger = ledger_with_version(&d, stale);
            assert!(
                ledger.approval_for_id("docs").is_none(),
                "版 {stale:?} のエントリが現行として見えている"
            );
            assert!(ledger.is_voided_by_format_upgrade("docs"));
            // **ハッシュが一致していても通さない**（`is_approved`のdoc）。この台帳は
            // わざとハッシュを合わせてあるので、落ちる理由は版だけである。
            assert!(
                !ledger.is_approved(&d),
                "版 {stale:?} の承認がハッシュ一致で通っている"
            );
        }
    }

    /// **対の側**（`B-35`）: 現行版のエントリは今までどおり見える。
    ///
    /// 片方だけだと「常に`None`を返す実装」でも上のテストは通る。
    #[test]
    fn an_approval_recorded_under_the_current_format_is_still_visible() {
        let d = decl("docs");
        let ledger = ledger_with_version(&d, Some(crate::decl::DECL_FORMAT_VERSION));
        assert!(ledger.approval_for_id("docs").is_some());
        assert!(
            !ledger.is_voided_by_format_upgrade("docs"),
            "現行版なのに「harnessが変えたせい」と報告されている"
        );
        assert!(ledger.is_approved(&d), "現行版の承認が照合で落ちている");
    }

    /// 再承認すると現行の版が記録され、以後は「harnessが変えたせい」に数えられない。
    #[test]
    fn re_approving_stamps_the_current_declaration_format() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let ledger = store.load();
        assert_eq!(
            ledger.approvals[0].decl_format_version,
            Some(crate::decl::DECL_FORMAT_VERSION)
        );
        assert!(!ledger.is_voided_by_format_upgrade("docs"));
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
