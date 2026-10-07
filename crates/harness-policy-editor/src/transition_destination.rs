//! [段階⑦] 遷移先ドメインを`harness.exe`が**用意する見込み**
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`「別ドメインへの遷移を書けるようにした（2026-10-01）」）。
//!
//! 遷移先の名前の検査は`harness_sandbox::tier2a::domain_profile_name_problem`が持つ（2026-10-05に
//! ここから移した。入れ物の名前の接頭辞の写しをエディタに置かないため、`bug-pattern-rules` B-05）。
//!
//! # 何のためにあるのか
//!
//! 別のドメインへ移す遷移は、**遷移先ドメインの実体（package SIDとcapabilityの組）を`harness.exe`が
//! 起動時に用意できたときだけ**通る——Spawn Daemonは用意された表に無い遷移先を
//! `TargetDomainNotProvisioned`で断る（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）。
//! 用意できるかは`policy.json`と承認台帳から決まる（D-112、#30）ので、エディタも書く前に
//! 「宣言の上では用意されない」ことを言える。ここがその見込みを作る。
//!
//! # 判定は`harness.exe`と同じ関数を通す
//!
//! - **宣言ごとに許可が付くか**: `policy_grants::GrantContext::domain_grants`——`harness.exe`の
//!   付与の一覧（`harness_sandbox::tier2a::policy_fs::plan`）が呼ぶのと**同じ関数・同じ承認台帳**。
//! - **用意できるか**（通信を宣言している→付かない宣言が1件でもある→用意できる）は
//!   `harness_sandbox::tier2a::policy_fs::domain_readiness`の1つ（2026-10-07、決定68の前例の(9)。それまではここに
//!   判定順の写しがあった）。実際に起こせるかは`harness.exe`が決め、モデルへ見せる一覧も`harness.exe`が実際に
//!   用意した表から作る（`transition_tool::facts_from_policy`）。
//!
//! # 見込みが言わないもの（限界）
//!
//! - **実行時の失敗**——パスが無い・昇格を断られた・入れ物を作れない。`harness.exe`の起動時の警告が持つ
//! - **遷移の強制が無効な起動**——そもそも遷移が起きない。ファイル宣言を持つ遷移先は、強制を有効にした
//!   起動でしか許可が付かない（付与の費用を使われない起動に払わないため。D-112）が、その起動では
//!   遷移も起きないので、見込みは「強制を有効にした起動なら」の1通りだけを答える
//! - **いま用意されているか**——エディタは`harness.exe`とは別プロセスで、どのセッションが何を用意したかを
//!   知らない。答えるのは「次に起動したら用意されるはずか」である

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use harness_policy::policy_file::{PolicyDomain, PolicyFile};
use harness_sandbox::tier2a::policy_fs::DomainReadiness;
use harness_sandbox::tier2a::policy_grants::{DomainGrants, SkipReason, SkippedDeclaration};

/// 遷移先ドメインを`harness.exe`が用意する見込み。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outlook {
    /// 遷移先が呼び出し元と同じドメイン（自己ループ辺）。**凍結中で、エディタからは書けない**
    /// （決定65(3)）。この変種が出るのは、遷移先の欄に呼び出し元の名前が入ったときと、手で書いた
    /// 自己ループ辺の見込みを引いたときである。Daemonは表を引かず、呼び出し元の実体のまま起こす
    /// （`spawnd::server::serve_spawn_request`）。
    SameDomain,
    /// 宣言の上では用意される。
    Provisioned {
        /// 遷移先のファイル宣言の件数。0なら共通の土台（ワークスペース等）だけで用意される。
        /// 1以上なら、`harness.exe`が起動時にそれらへ許可を付けてから用意する。
        declarations: usize,
    },
    /// 宣言の上で、用意されないことが分かっている。**この遷移は断られ続ける。**
    NotProvisioned(Blocker),
}

/// 用意されない理由。**`harness.exe`の起動時の警告と同じ分け方**（`domain_provision`の`skipped`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// 通信を宣言している。**【暫定】**ドメインごとの通信の出口制御（専用プロキシ＋WFPの欄）が
    /// まだ無いので、`harness.exe`は通信を宣言するドメインを用意しない（`domain_provision`のdoc）。
    ///
    /// # いつ消えるか
    ///
    /// ドメインごとの出口制御が入り、`harness.exe`が通信を宣言するドメインを用意するようになった日
    /// （`plans/HANDOFF-POLICY-EDITOR.md`の「前提を待つもの」D、`docs/INDEX.md`の未実装機能
    /// サンドボックス周辺 #55）。**この変種を消すと、文言を組む`match`がコンパイルできなくなる**。
    DeclaresNetwork { count: usize },
    /// 許可が付かないファイル宣言がある。**1件でもあればドメインごと用意されない**（fail-closed。
    /// 付いた分だけで用意すると、エディタで確かめたより狭い権限で黙って動く。D-112）。
    DeclarationsNotGranted { skipped: Vec<SkippedDeclaration> },
}

impl Outlook {
    /// この遷移先への辺は、宣言の上では起こせるか。
    pub fn is_provisioned(&self) -> bool {
        !matches!(self, Outlook::NotProvisioned(_))
    }

    /// 遷移先の欄と一覧の行末に出す一言。
    pub fn short_label(&self) -> String {
        match self {
            Outlook::SameDomain => {
                "呼び出し元と同じドメイン（自己ループ辺は凍結中で書けない）".to_string()
            }
            Outlook::Provisioned { declarations: 0 } => {
                "用意される見込み（ファイル宣言なし・共通の土台だけ）".to_string()
            }
            Outlook::Provisioned { declarations } => {
                format!("用意される見込み（承認済みのファイル宣言 {declarations}件に許可が付く）")
            }
            Outlook::NotProvisioned(Blocker::DeclaresNetwork { count }) => {
                format!("用意されない: 通信を宣言している（{count}件）")
            }
            Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped }) => {
                let unapproved = unapproved_count(skipped);
                if unapproved == skipped.len() {
                    format!("用意されない: このマシンで未承認のファイル宣言 {unapproved}件")
                } else {
                    format!(
                        "用意されない: 許可が付かないファイル宣言 {}件（うち未承認 {unapproved}件）",
                        skipped.len()
                    )
                }
            }
        }
    }

    /// 確定の直前に出す説明。**取り消しの効かない操作の直前なので、何が起きるかを全部言う。**
    pub fn notice_lines(&self, to_domain: &str) -> Vec<String> {
        match self {
            Outlook::SameDomain => vec![
                format!("遷移先が呼び出し元と同じドメイン（{to_domain}）です。"),
                "  自己ループ辺は凍結中のため書けません（決定65）。".to_string(),
                "  Tab で遷移先の欄へ移って、別のドメイン名を入れてから確定してください。".to_string(),
            ],
            Outlook::Provisioned { declarations: 0 } => vec![
                format!("遷移先 {to_domain} はファイル宣言を持たないので、harness.exe は"),
                "  共通の土台（ワークスペース・祖先の通り抜け・生成の依頼口）だけでこのドメインを用意します。"
                    .to_string(),
            ],
            Outlook::Provisioned { declarations } => vec![
                format!(
                    "遷移先 {to_domain} の承認済みのファイル宣言 {declarations}件に、harness.exe が起動時に"
                ),
                "  許可を付けてからこのドメインを用意します（遷移の強制を有効にした起動だけ）。"
                    .to_string(),
                "  付与に失敗するとそのドメインは用意されず、遷移は断られます（起動時に警告が出ます）。"
                    .to_string(),
            ],
            Outlook::NotProvisioned(Blocker::DeclaresNetwork { count }) => vec![
                format!("⚠ 遷移先 {to_domain} は通信を {count}件宣言しています。"),
                "  ドメインごとの通信の出口制御がまだ無いので、harness.exe はこのドメインを用意せず、"
                    .to_string(),
                "  この遷移は断られ続けます（書くことはできます。通信の宣言を外せば用意されます）。"
                    .to_string(),
            ],
            Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped }) => {
                let mut lines = vec![
                    format!(
                        "⚠ 遷移先 {to_domain} のファイル宣言のうち {}件に許可が付きません。",
                        skipped.len()
                    ),
                    "  1件でも付かないドメインは用意されず、この遷移は断られ続けます（書くことはできます）。"
                        .to_string(),
                ];
                if unapproved_count(skipped) > 0 {
                    lines.push(
                        "  未承認の宣言は、宣言画面（F3）の y で「このマシンで承認」すると付きます。"
                            .to_string(),
                    );
                }
                for skip in skipped.iter().take(SKIPPED_SHOWN) {
                    lines.push(format!(
                        "    - {} ({}): {}",
                        skip.value,
                        skip.access.settings_key(),
                        skip.reason.describe()
                    ));
                }
                if skipped.len() > SKIPPED_SHOWN {
                    lines.push(format!(
                        "    …ほか {}件（宣言画面 F3 で全部見られます）",
                        skipped.len() - SKIPPED_SHOWN
                    ));
                }
                lines
            }
        }
    }
}

/// 確認ダイアログに名指しする付かない宣言の上限（残りは件数で言う）。
const SKIPPED_SHOWN: usize = 5;

fn unapproved_count(skipped: &[SkippedDeclaration]) -> usize {
    skipped
        .iter()
        .filter(|s| s.reason == SkipReason::NotApprovedOnThisMachine)
        .count()
}

/// 遷移先`to_domain`を`harness.exe`が用意する見込み。
///
/// `grants`はドメインの宣言から付ける一覧を作る関数で、製品では[`grants_on_this_machine`]を渡す
/// （試験では承認台帳を介さずに渡せるよう、引数で受ける）。
///
/// **`policy.json`に無い名前は「宣言が空のドメイン」として答える**——確定すると
/// [`crate::transition_approve::plan`]が宣言の無いドメインとして作るからである。
pub fn outlook(
    file: &PolicyFile,
    from_domain: &str,
    to_domain: &str,
    grants: &dyn Fn(&PolicyDomain) -> DomainGrants,
) -> Outlook {
    if to_domain == from_domain {
        return Outlook::SameDomain;
    }
    let Some(domain) = file.domain(to_domain) else {
        return Outlook::Provisioned { declarations: 0 };
    };
    // 判定は`harness.exe`の付与の一覧と同じ関数（`policy_fs::domain_readiness`。決定68の前例の(9)）。ここは写すだけ。
    match harness_sandbox::tier2a::policy_fs::domain_readiness(domain, grants) {
        DomainReadiness::DeclaresNetwork { count } => {
            Outlook::NotProvisioned(Blocker::DeclaresNetwork { count })
        }
        DomainReadiness::NotGranted { skipped } => {
            Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped })
        }
        DomainReadiness::Ready { .. } => Outlook::Provisioned {
            declarations: domain.fs.entries().len(),
        },
    }
}

/// `policy.json`の全ドメインについての見込み（遷移先の欄と一覧の行が引く表）。
pub fn outlooks(
    file: &PolicyFile,
    from_domain: &str,
    grants: &dyn Fn(&PolicyDomain) -> DomainGrants,
) -> BTreeMap<String, Outlook> {
    file.domains
        .iter()
        .map(|d| (d.name.clone(), outlook(file, from_domain, &d.name, grants)))
        .collect()
}

/// 用意される見込みのドメイン名（[`harness_policy::transition_listing::rows`]へ渡す表）。
///
/// `harness.exe`は実際に用意できた表を渡すが、エディタはそれを知らないので見込みを渡す（モジュールdoc）。
/// 自己ループは表を引かないので、ここに入れなくても「起こせる」と出る。
pub fn provisioned_names(outlooks: &BTreeMap<String, Outlook>) -> BTreeSet<String> {
    outlooks
        .iter()
        .filter(|(_, o)| matches!(o, Outlook::Provisioned { .. }))
        .map(|(name, _)| name.clone())
        .collect()
}

/// このマシンの承認台帳（D-112）で、ドメインの宣言から付ける一覧を作る。
///
/// **`harness.exe`と同じ関数・同じ台帳**（`policy_grants`・`approval_store`）を通す。
/// 台帳は呼ぶたびに1回読む（呼び出し側は表を作り直すときに1回呼ぶこと）。
pub fn grants_on_this_machine(workspace_root: &Path) -> impl Fn(&PolicyDomain) -> DomainGrants {
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key =
        harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
    let context = harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(workspace_root);
    move |domain: &PolicyDomain| {
        context.domain_grants(domain, &|d| approvals.is_approved_for_key(&workspace_key, d))
    }
}

#[cfg(test)]
#[path = "transition_destination_tests.rs"]
mod transition_destination_tests;
