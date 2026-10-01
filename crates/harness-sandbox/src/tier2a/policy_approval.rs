//! [#30] `policy.json`のファイル宣言の**このマシンでの承認**の台帳（D-112）。
//!
//! # なぜ承認が要るのか
//!
//! `harness.exe`は起動時に`policy.json`のファイル宣言へ許可（ACE）を付ける。`policy.json`は
//! リポジトリの`.harness/`に置かれるので、**クローンしたリポジトリに最初から同梱されていることがある**。
//! `.harness/**`への書込は多層で塞がれている（P-08）が、それらはいずれも「書込」への防御で、
//! 同梱されたファイルには一度も発火しない——MCPサーバ宣言の承認台帳（D-39、
//! `harness_mcp::approval`）と同じ理由である。この台帳はその経路のためだけに存在する。
//!
//! # 置き場所が本質
//!
//! 台帳は**ワークスペースの外**（`%APPDATA%\harness\config`。他の台帳と同じ場所。一覧は
//! `harness_grant_ledger::CONFIG_DIR_LEDGERS`）に置く。リポジトリ側から内容を左右できては
//! いけないので、これは実装詳細ではなく要件である。サンドボックスの子はそこへ書けない
//! （許可の一覧を作る側が制御ディレクトリを拒む。`policy_grants::SkipReason::ControlDirectory`）。
//!
//! # 1件の鍵
//!
//! `(ワークスペース, ドメイン, 種類, 値)`の**完全一致**で照合する。
//!
//! - **ドメインを鍵に入れる**のは、同じパスを別のドメインへ移されたときに承認を引き継がせないため
//!   （ドメインが違えば、その許可を持つ子が違う）。
//! - **値は`policy.json`に書いてあるとおりの文字列**で比べる。綴りを変えた（手で書き換えた）値は
//!   別物として未承認になる——倒れる向きは常に「付けない」側である。
//! - **ワークスペースは`canonicalize`してから`workspace_capability::workspace_key`で畳む**。
//!   `workspace_key`は大小・区切り・`\\?\`前置を畳むが`..`や8.3短縮名は解かないので、
//!   書く側（エディタ）と読む側（`harness.exe`）が別の形で渡すと全宣言が未承認になる。
//!
//! # この台帳が守らないもの
//!
//! - **隔離せずに走ったコードは書き換えられる**（Tier0。ポリシーエディタのパス1を含む）。
//!   ユーザーと同じ権限で動くので、原理的に防げない（D-39の台帳と同じ限界）。
//! - **ファイル宣言しか見ない。** `policy.json`の遷移の宣言（`process`）と、同梱された
//!   `settings.json`の`fs.*`は、この台帳の対象外である。
//! - **ワークスペースを移動・改名すると承認は引き継がれない**（鍵がワークスペースのパスのため）。

use std::path::Path;

use harness_grant_ledger::{now_unix_secs, Ledger};
use serde::{Deserialize, Serialize};

const LEDGER_FILE: &str = "policy-approval-ledger.json";
const LEDGER_LOCK: &str = r"Local\harness-policy-approval-ledger";

/// 承認の形の版。**照合の意味を変えたら上げる**（値の正規化の仕方を変える・鍵の欄を足す等）。
///
/// 古い版の承認は「無かったもの」として扱う（`harness_mcp::approval`と同じ理由。ハッシュや
/// 文字列が偶然一致しても、意味が変わった後の照合で古い承認を通さない）。
pub const APPROVAL_FORMAT_VERSION: u32 = 1;

/// 台帳のペイロード。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyApprovalLedger {
    #[serde(default)]
    pub approvals: Vec<FsDeclarationApproval>,
}

/// 承認1件。「このワークスペースのこのドメインで、この値にこの種類の許可を付けてよい」の記録。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDeclarationApproval {
    /// `canonicalize`して`workspace_key`で畳んだワークスペース。
    pub workspace: String,
    pub domain: String,
    pub access: harness_config::FsAccess,
    /// `policy.json`に書いてあるとおりの値。
    pub value: String,
    pub approved_at_unix_secs: u64,
    /// 記録した時点の[`APPROVAL_FORMAT_VERSION`]。`None`は読めるが照合では通さない。
    #[serde(default)]
    pub format_version: Option<u32>,
}

/// 照合する宣言1件（台帳の鍵の4つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclarationRef<'a> {
    pub domain: &'a str,
    pub value: &'a str,
    pub access: harness_config::FsAccess,
}

/// 台帳を引くときのワークスペースの鍵（モジュールdocの「1件の鍵」）。
pub fn approval_workspace_key(workspace: &Path) -> String {
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    crate::tier2a::workspace_capability::workspace_key(&canonical)
}

impl FsDeclarationApproval {
    fn matches(&self, workspace_key: &str, declaration: DeclarationRef<'_>) -> bool {
        self.workspace == workspace_key
            && self.domain == declaration.domain
            && self.access == declaration.access
            && self.value == declaration.value
            && self.format_version == Some(APPROVAL_FORMAT_VERSION)
    }
}

impl PolicyApprovalLedger {
    /// このワークスペースのこの宣言が承認済みか。**4つの鍵と版がすべて一致したときだけ真**。
    pub fn is_approved(&self, workspace: &Path, declaration: DeclarationRef<'_>) -> bool {
        self.is_approved_for_key(&approval_workspace_key(workspace), declaration)
    }

    /// [`Self::is_approved`]の、ワークスペースの鍵を作り済みで渡す版（同じワークスペースの宣言を
    /// 何百件も照合するとき、`canonicalize`を件数ぶん回さないため）。
    pub fn is_approved_for_key(&self, workspace_key: &str, declaration: DeclarationRef<'_>) -> bool {
        self.approvals
            .iter()
            .any(|a| a.matches(workspace_key, declaration))
    }
}

/// 承認台帳のファイル。テストが`%APPDATA%`を汚さないよう[`Self::at_path`]を持つ
/// （`harness_grant_ledger::Ledger`と同じ注入点の付け方）。
pub struct PolicyApprovalStore {
    ledger: Ledger<PolicyApprovalLedger>,
}

impl PolicyApprovalStore {
    pub fn in_config_dir() -> Self {
        Self {
            ledger: Ledger::in_config_dir(LEDGER_FILE, Some(LEDGER_LOCK)),
        }
    }

    pub fn at_path(path: std::path::PathBuf) -> Self {
        Self {
            ledger: Ledger::at_path(path, None),
        }
    }

    /// 読む。**壊れている・無いときは「何も承認されていない」**（fail-closed——読めない台帳を
    /// 「全部承認済み」には倒さない）。
    pub fn load(&self) -> PolicyApprovalLedger {
        self.ledger.load()
    }

    /// 宣言を承認する。同じ鍵の古い承認は置き換える（1つの鍵につき1件）。
    ///
    /// **記録できなかった宣言を返す**（書いた後に読み直して確かめる）。`Ledger`は書込の失敗を
    /// 返さないので、見た目の成功を信用しない——記録できなかった宣言は未承認のまま、つまり
    /// 許可は付かない側に倒れるが、ユーザーには「承認したのに効かない」に見えるので名指しで出す。
    pub fn approve<'a>(
        &self,
        workspace: &Path,
        declarations: &[DeclarationRef<'a>],
    ) -> Vec<DeclarationRef<'a>> {
        let key = approval_workspace_key(workspace);
        let now = now_unix_secs();
        self.ledger.update(|ledger| {
            for declaration in declarations {
                ledger.approvals.retain(|a| {
                    !(a.workspace == key
                        && a.domain == declaration.domain
                        && a.access == declaration.access
                        && a.value == declaration.value)
                });
                ledger.approvals.push(FsDeclarationApproval {
                    workspace: key.clone(),
                    domain: declaration.domain.to_string(),
                    access: declaration.access,
                    value: declaration.value.to_string(),
                    approved_at_unix_secs: now,
                    format_version: Some(APPROVAL_FORMAT_VERSION),
                });
            }
        });
        let reloaded = self.load();
        declarations
            .iter()
            .copied()
            .filter(|d| !reloaded.is_approved_for_key(&key, *d))
            .collect()
    }

    /// 承認を取り消す。**消せなかった宣言を返す**（[`Self::approve`]と同じ理由で読み直して確かめる）。
    ///
    /// 消し残すと、同じ値が後で同梱されたとき承認済みとして通るので、黙って飛ばさない。
    ///
    /// **値は大文字小文字を無視して消す。** 照合（[`PolicyApprovalLedger::is_approved`]）は
    /// 完全一致だが、`policy.json`から宣言を消す側（ポリシーエディタの`unapprove`）が大文字小文字を
    /// 無視して消すので、こちらも同じ範囲を消す。消しすぎる向きは「付けない」側である。
    pub fn revoke<'a>(
        &self,
        workspace: &Path,
        declarations: &[DeclarationRef<'a>],
    ) -> Vec<DeclarationRef<'a>> {
        let key = approval_workspace_key(workspace);
        let covers = |a: &FsDeclarationApproval, d: &DeclarationRef<'_>| {
            a.workspace == key
                && a.domain == d.domain
                && a.access == d.access
                && a.value.eq_ignore_ascii_case(d.value)
        };
        self.ledger.update(|ledger| {
            ledger
                .approvals
                .retain(|a| !declarations.iter().any(|d| covers(a, d)));
        });
        let reloaded = self.load();
        declarations
            .iter()
            .copied()
            .filter(|d| reloaded.approvals.iter().any(|a| covers(a, d)))
            .collect()
    }
}

#[cfg(test)]
#[path = "policy_approval_tests.rs"]
mod policy_approval_tests;
