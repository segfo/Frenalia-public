//! 承認済み宣言の取り消し——[`crate::approve`]の対。`policy.json`から宣言を**消す**。
//!
//! # なぜACEを触らないのか（付与の対称）
//!
//! 承認がACEを付けないのと同じ理由で、取り消しもACEを剥がさない。実測した付与/撤収の
//! ライフサイクルはこうなっている:
//!
//! | 何が | いつ |
//! |---|---|
//! | ACE付与 | **パス2の開始時**（`record_net`が`preflight`を通す）と、[#30] **`harness.exe`の起動時**（このマシンで承認した宣言だけ） |
//! | 撤収 | **次のパス2の開始時**（もう宣言されていない分。BUG-184以降は実行中のワークスペースでは見送る）と、[#30] **`harness.exe`の起動時の自動撤収**（D-27）。宣言ごとの宛先SIDのACEは永続で、プロセス終了時には剥がさない（[`crate::record_net::SessionGrants`]のDropが剥がすのはセッションのプロファイルと差分層の分） |
//!
//! 付与が「承認した瞬間」ではなく「次にパス2を走らせた時」なのだから、撤収も
//! 「取り消した瞬間」ではなく**同じライフサイクル点**（パス2の開始時のreconcile）に置くのが対に
//! なる。ここで即座にACEを剥がすと、付与と撤収が別の時点で起きる非対称を作ることになる
//! ——しかもUACを要求しうる操作が、宣言を1行消すだけのつもりの操作に紛れ込む。
//!
//! # ドメインは空になっても消さない
//!
//! 宣言を全部取り消しても`PolicyDomain`自体は残す（`commands`・`cwd`・`provenance`はそのまま）。
//! **消すと`record-net --domain <name>`が動かなくなる**——「宣言を全部外した状態でパス2を走らせ、
//! 本当に拒否されることを確かめる」という再現性の確認が、まさにその状態を必要とする。
//! 由来の記録（どのコマンドを記録したか）を失う理由も無い。
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果を返し、[`commit`]がそれを書く（[`crate::approve`]と同じ2段）。
//! CLIは間で差分を見せて確認を取り、TUIは同じ2段をモーダルで使う。

use std::path::Path;

use harness_policy::generalize::SettingsKey;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use crate::policy_file::{self, PolicyDomain, PolicyFile, PolicyFileError};

/// 取り消しがACEに何をするのかの説明。**この文言の持ち主はここだけ**（CLIもTUIもこれを出す）。
///
/// 「取り消した瞬間にACLが変わる」と誤解させないために必ず出す。付与がパス2開始時なので、
/// 撤収も同じライフサイクル点にある（モジュールdoc）。
pub const ACE_NOTICE: &str = concat!(
    "注: 宣言を消すだけで、ACLはまだ変わりません。付与済みのACEは、次にパス2（record-net）を\n",
    "    開始したとき、または harness.exe を起動したときに「もう宣言されていない分」として\n",
    "    撤収されます（そのワークスペースが使用中のときは見送ります）。このマシンでの承認は\n",
    "    いま消えるので、消した宣言にはこの先許可が付きません。"
);

/// 取り消す宣言1件の指定。
///
/// **提案id（`fs-53`等）ではなく`(ドメイン, キー, 値)`で指す。** idは候補の畳み込みと
/// 候補の顔ぶれで振り直されるので、「どの宣言を消したいか」を表す識別子にはならない。
/// 消す対象は`policy.json`に書かれている行そのものであり、それはこの3つ組で一意である。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnapproveTarget {
    pub domain: String,
    pub key: SettingsKey,
    pub value: String,
}

impl UnapproveTarget {
    /// 承認台帳（D-112）を引く鍵の形。**通信の宣言も鍵を持つ**（決定69(2)。以前は`None`だった）。
    ///
    /// 取り消し・宣言の承認・付け替えの3つが台帳を引くので、変換を1箇所に置く（規則5.0）。
    pub fn declaration(&self) -> DeclarationRef<'_> {
        DeclarationRef {
            domain: &self.domain,
            value: &self.value,
            key: self.key,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UnapproveError {
    #[error(transparent)]
    PolicyFile(#[from] PolicyFileError),
    /// `policy.json`からは消したが、このマシンでの承認（D-112）を台帳から消せなかった。
    ///
    /// **黙らない。** 承認が残ると、同じ値が後でリポジトリに同梱されて戻ってきたとき、
    /// 承認済みとして許可が付く。
    #[error(
        "policy.json からは消しましたが、このマシンでの承認を台帳から消せませんでした: {0}\n\
         同じ値が後で policy.json に戻ると承認済みとして扱われます（台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    ApprovalNotRevoked(String),
}

/// 1回の取り消しで何が消えるか。**「消した」と「元から無かった」を必ず区別する**（B-09）
/// ——区別しないと、綴りを間違えた指定が「取り消しました」として通る。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnapprovePlan {
    /// 書き込む予定の`policy.json`（[`commit`]がこれを保存する）。
    pub file: PolicyFile,
    /// 実際に消える宣言。
    pub removed: Vec<UnapproveTarget>,
    /// 指定されたが`policy.json`に無かったもの。
    pub not_found: Vec<UnapproveTarget>,
    /// この取り消しで宣言が1件も無くなるドメイン（**ドメイン自体は残す**。モジュールdoc）。
    pub emptied_domains: Vec<String>,
    /// この取り消しで広がる遷移（遷移元の宣言を減らすと、その遷移元から出る辺が呼び出し元へ渡す権限が増える。
    /// 決定66）。確認の画面と CLI が[`crate::exposure_view::lines`]で並べる。
    pub widening: crate::exposure_view::Widening,
}

impl UnapprovePlan {
    /// 消えるものが1件も無い（＝書く必要が無い）。
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty()
    }
}

/// 取り消しの内容を決める（**何も書かない**）。
pub fn plan(
    workspace_root: &Path,
    targets: &[UnapproveTarget],
) -> Result<UnapprovePlan, UnapproveError> {
    let mut file = policy_file::load(workspace_root)?;
    let before = file.clone();
    let mut removed = Vec::new();
    let mut not_found = Vec::new();

    for target in targets {
        // ドメイン名は**ユーザーが打つ識別子**なので完全一致で引く（`policy_file::domain`と同じ）。
        let Some(domain) = file.domains.iter_mut().find(|d| d.name == target.domain) else {
            not_found.push(target.clone());
            continue;
        };
        if remove_value(domain, target.key, &target.value) {
            removed.push(target.clone());
        } else {
            not_found.push(target.clone());
        }
    }

    // 空になったドメインは**報告するが消さない**（モジュールdoc）。
    let emptied_domains = file
        .domains
        .iter()
        .filter(|d| d.fs.is_empty() && d.net.allow_domains.is_empty())
        .filter(|d| removed.iter().any(|t| t.domain == d.name))
        .map(|d| d.name.clone())
        .collect();

    let widening = crate::exposure_view::widening(&before, &file, workspace_root);
    Ok(UnapprovePlan {
        file,
        removed,
        not_found,
        emptied_domains,
        widening,
    })
}

/// [`plan`]の結果を書く。**消えるものが無いときは書かない**——書くと`updated`時刻だけが動いて
/// 「何かした」ように見える（B-09）。書いたかどうかを返す。
///
/// [D-112] 消した**ファイル宣言**の、このマシンでの承認も台帳から消す（`policy.json`を書いた後）。
pub fn commit(workspace_root: &Path, plan: &UnapprovePlan) -> Result<bool, UnapproveError> {
    if plan.is_empty() {
        return Ok(false);
    }
    policy_file::save(workspace_root, &plan.file)?;
    // [決定69(2)] 通信の宣言の承認も消す（鍵を持つようになったので、ファイルの分と同じ経路で消える）。
    let declarations: Vec<DeclarationRef<'_>> = plan
        .removed
        .iter()
        .map(UnapproveTarget::declaration)
        .collect();
    if !declarations.is_empty() {
        let left = crate::approval_store::approval_store().revoke(workspace_root, &declarations);
        if !left.is_empty() {
            return Err(UnapproveError::ApprovalNotRevoked(
                left.iter()
                    .map(|d| format!("{} ({}) in {}", d.value, d.key_label(), d.domain))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
    }
    Ok(true)
}

/// ドメインの該当バケットから値を1件消す。消えたら`true`。
///
/// 値の比較は**大文字小文字を無視する**——Windowsのパスは大文字小文字を区別せず、
/// ドメイン名（`net.allow_domains`）もDNS上区別しない。区別すると、画面に出ている行を
/// 指定したのに「無い」と言われる。
///
/// **付け替え（[`crate::reassign`]）の「元の値を消す」半分もこれを通す**——消す規則を2つ持つと、
/// 取り消しなら消える綴りが付け替えでは残る（`CODE-STRUCTURE-RULES`§5.0）。
pub(crate) fn remove_value(domain: &mut PolicyDomain, key: SettingsKey, value: &str) -> bool {
    let bucket = match key {
        SettingsKey::NetAllowDomains => &mut domain.net.allow_domains,
        SettingsKey::FsRead => &mut domain.fs.read,
        SettingsKey::FsReadWrite => &mut domain.fs.read_write,
        SettingsKey::FsReadExec => &mut domain.fs.read_exec,
    };
    let before = bucket.len();
    bucket.retain(|v| !v.eq_ignore_ascii_case(value));
    bucket.len() != before
}

/// `policy.json`の**全ドメインの全宣言**を取り消し対象として列挙する。
///
/// 専用画面の一括取り消しとCLIの`--all`が使う。**一括承認のショートハンドは無い**（D-42）のに
/// 一括取り消しを用意するのは非対称に見えるが、向きが逆である——D-42が禁じているのは
/// 「読まずに権限を**与える**」ことで、こちらは権限を**減らす**操作である。減らす側を
/// 面倒にすると、「とりあえず全部消してやり直す」という安全な回復手段が失われる。
pub fn all_targets(file: &PolicyFile) -> Vec<UnapproveTarget> {
    file.domains.iter().flat_map(domain_targets).collect()
}

/// [BUG-103] **いまの規則なら候補にしなかった宣言**を列挙する（`unapprove --excluded`）。
///
/// 候補側を直しても、**既に`policy.json`に入っている宣言は消えない**（BUG-099(b)と同じ形）。
/// 実マシンでは2,425件のうち1,637件が「二度と存在しないパス」で、パス2のたびに
/// `path does not exist, skipped`を1,320件出していた。
///
/// **判定は候補側と同じ[`crate::exclusion::ExclusionRules`]を通す。** ここに別の規則を書くと、
/// 「候補には出さないのに掃除もされない宣言」や、その逆が生まれる（B-05）。
/// 値はワイルドカードを含み得るが、`is_under`が最初の`*`より前で判定するので同じ関数で足りる。
///
/// ネットワーク宣言（`net.allow_domains`）は**対象外**——パスではないので、パスの規則を
/// 当てはめる意味が無い。
pub fn excluded_targets(
    file: &PolicyFile,
    rules: &crate::exclusion::ExclusionRules,
) -> Vec<(UnapproveTarget, crate::exclusion::Excluded)> {
    let mut out = Vec::new();
    for domain in &file.domains {
        for (value, access) in domain.fs.entries() {
            let Some(reason) = rules.excluded(value) else {
                continue;
            };
            out.push((
                UnapproveTarget {
                    domain: domain.name.clone(),
                    key: SettingsKey::from_access(access),
                    value: value.to_string(),
                },
                reason,
            ));
        }
    }
    out
}

/// 1ドメインの全宣言を取り消し対象として列挙する。
pub fn domain_targets(domain: &PolicyDomain) -> Vec<UnapproveTarget> {
    let fs = domain
        .fs
        .entries()
        .into_iter()
        .map(|(value, access)| UnapproveTarget {
            domain: domain.name.clone(),
            key: SettingsKey::from_access(access),
            value: value.to_string(),
        });
    let net = domain
        .net
        .allow_domains
        .iter()
        .map(|value| UnapproveTarget {
            domain: domain.name.clone(),
            key: SettingsKey::NetAllowDomains,
            value: value.clone(),
        });
    fs.chain(net).collect()
}

#[cfg(test)]
#[path = "unapprove_tests.rs"]
mod unapprove_tests;
