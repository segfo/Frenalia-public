//! [D-112] **既に`policy.json`にある宣言を、このマシンで承認する**（`approve-declared`・宣言画面の`y`）。
//!
//! # 何のためにあるのか
//!
//! 候補を承認したときは、その値が承認台帳へ記録される（`approve::commit`）。だが
//! `policy.json`には**このマシンで承認していない宣言**も入り得る——リポジトリに同梱されていた
//! もの、手で書いたもの、承認台帳ができる前に承認したもの。それらは許可が付かないので、
//! ユーザーが1件ずつ読んで承認する道が要る。
//!
//! # 候補の承認と同じ検査を通す
//!
//! ここは**検査を経ずに`policy.json`へ入った値**を承認する入口である。候補の承認が通す検査
//! （`gate`＝`--require-sandbox`との矛盾、`breadth`＝広すぎる値）と、候補にしない規則
//! （[`crate::exclusion::ExclusionRules`]）と、許可の一覧を作る関数が付けない値
//! （`policy_grants::SkipReason`）を**全部**通す。どれかを省くと、同梱された宣言が
//! 候補なら止まった値を素通しで承認させられる。
//!
//! # 一括承認は作らない
//!
//! 承認する宣言は1件ずつ名指しする（CLIは`--fs`を並べる、画面は配下を選ぶ）。
//! 「ファイル全体を承認する」操作は作らない（決定51・D-42）。
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果を返し、[`commit`]が台帳へ書く（`approve`・`unapprove`と同じ2段）。

use std::path::Path;

use harness_core::RequireSandbox;
use harness_policy::{breadth, gate, generalize::SettingsKey, GateVerdict, RuleProposal};
use harness_sandbox::tier2a::policy_approval::{approval_workspace_key, DeclarationRef};

use crate::policy_file::{self, PolicyFileError};
use crate::unapprove::UnapproveTarget;

/// 1回の承認で何が起きるか。**「承認する」「承認済みだった」「断った」「無かった」を必ず分ける**（B-09）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclaredApprovalPlan {
    /// 台帳へ記録する宣言（値は`policy.json`に書いてあるとおりの綴り）。
    pub approve: Vec<UnapproveTarget>,
    /// 既にこのマシンで承認済みだった宣言。
    pub already: Vec<UnapproveTarget>,
    /// 承認しない宣言と、その理由。
    pub refused: Vec<(UnapproveTarget, String)>,
    /// 指定されたが`policy.json`に無かったもの。
    pub not_found: Vec<UnapproveTarget>,
}

impl DeclaredApprovalPlan {
    /// 書くものが無い。
    pub fn is_empty(&self) -> bool {
        self.approve.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveDeclaredError {
    #[error(transparent)]
    PolicyFile(#[from] PolicyFileError),
    /// 台帳へ記録できなかった（書いた後に読み直して確かめる。`PolicyApprovalStore::approve`）。
    #[error(
        "このマシンでの承認を台帳へ記録できませんでした: {0}\n\
         これらの宣言には許可が付きません（台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    NotRecorded(String),
}

/// このマシンで承認してよい値かを見る検査一式（モジュールdocの「候補の承認と同じ検査を通す」）。
///
/// **宣言の承認（[`plan`]）と宣言の付け替え（[`crate::reassign`]）が同じこれを通す。** 付け替えは
/// 承認済みの宣言を別の値へ書き換える入口なので、検査を別に持つと「`y`なら断る値を付け替えで作れる」
/// 形になる（B-05・B-20: 判定は1箇所）。
pub(crate) struct ApprovalChecks {
    require_sandbox: RequireSandbox,
    exclusion: crate::exclusion::ExclusionRules,
    grants: harness_sandbox::tier2a::policy_grants::GrantContext,
}

impl ApprovalChecks {
    pub(crate) fn for_workspace(workspace_root: &Path, require_sandbox: RequireSandbox) -> Self {
        Self {
            require_sandbox,
            exclusion: crate::exclusion::ExclusionRules::for_session(workspace_root),
            grants: harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(
                workspace_root,
            ),
        }
    }

    /// 承認しない理由（承認してよいなら`None`）。中身は[`refusal`]。
    pub(crate) fn refusal(&self, target: &UnapproveTarget) -> Option<String> {
        refusal(target, self.require_sandbox, &self.exclusion, &self.grants)
    }
}

/// 承認の内容を決める（**何も書かない**）。
pub fn plan(
    workspace_root: &Path,
    targets: &[UnapproveTarget],
    require_sandbox: RequireSandbox,
) -> Result<DeclaredApprovalPlan, ApproveDeclaredError> {
    let file = policy_file::load(workspace_root)?;
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key = approval_workspace_key(workspace_root);
    let checks = ApprovalChecks::for_workspace(workspace_root, require_sandbox);

    let mut out = DeclaredApprovalPlan::default();
    for target in targets {
        let Some(access) = target.key.fs_access() else {
            out.refused.push((
                target.clone(),
                "ネットワークの宣言は、このマシンでの承認の対象外です（承認台帳はファイル宣言だけを持つ）"
                    .to_string(),
            ));
            continue;
        };
        let Some(target) = stored_spelling(&file, target) else {
            out.not_found.push(target.clone());
            continue;
        };
        if let Some(reason) = checks.refusal(&target) {
            out.refused.push((target, reason));
            continue;
        }
        let declaration = DeclarationRef {
            domain: &target.domain,
            value: &target.value,
            access,
        };
        if approvals.is_approved_for_key(&workspace_key, declaration) {
            out.already.push(target);
        } else if !out.approve.contains(&target) {
            out.approve.push(target);
        }
    }
    Ok(out)
}

/// 承認しない理由（承認してよいなら`None`）。順序は「候補にしない規則 → 許可を付けない値 →
/// `--require-sandbox`との矛盾 → 広すぎる値」。
fn refusal(
    target: &UnapproveTarget,
    require_sandbox: RequireSandbox,
    exclusion: &crate::exclusion::ExclusionRules,
    grants: &harness_sandbox::tier2a::policy_grants::GrantContext,
) -> Option<String> {
    if let Some(reason) = exclusion.excluded(&target.value) {
        return Some(format!(
            "いまの規則なら候補にしない値です（{reason:?}）。`unapprove --excluded`で宣言ごと消せます"
        ));
    }
    match grants.grant_root(&target.value) {
        Err(reason) => return Some(reason.describe().to_string()),
        Ok(None) => {
            return Some(
                "ワークスペースの中なので、承認しなくても許可は要りません（Tier2aがワークスペース全体へ付けている）"
                    .to_string(),
            )
        }
        Ok(Some(_)) => {}
    }
    let proposal = RuleProposal {
        id: String::new(),
        key: target.key,
        value: target.value.clone(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    };
    if let GateVerdict::Rejected(message) = gate::check_proposal(&proposal, require_sandbox) {
        return Some(message);
    }
    breadth::check(&proposal).message().map(str::to_string)
}

/// 指定した宣言を、**`policy.json`に書いてあるとおりの綴り**で引き直す（無ければ`None`）。
///
/// 照合（`is_approved`）は完全一致なので、指定の大文字小文字が違う綴りで記録すると「承認したのに
/// 付かない」になる。探すのは`unapprove`と同じく大文字小文字を無視して。
/// **付け替え（[`crate::reassign`]）も同じこれを通す**——承認を引き継ぐかどうかを、ここで引いた
/// 綴りで台帳に問い合わせるため。
pub(crate) fn stored_spelling(
    file: &crate::PolicyFile,
    target: &UnapproveTarget,
) -> Option<UnapproveTarget> {
    let domain = file.domain(&target.domain)?;
    let value = bucket(domain, target.key)
        .iter()
        .find(|v| v.eq_ignore_ascii_case(&target.value))?
        .clone();
    Some(UnapproveTarget {
        domain: target.domain.clone(),
        key: target.key,
        value,
    })
}

fn bucket(domain: &crate::PolicyDomain, key: SettingsKey) -> &[String] {
    match key {
        SettingsKey::FsRead => &domain.fs.read,
        SettingsKey::FsReadWrite => &domain.fs.read_write,
        SettingsKey::FsReadExec => &domain.fs.read_exec,
        SettingsKey::NetAllowDomains => &domain.net.allow_domains,
    }
}

/// [`plan`]の結果を台帳へ書く。記録した件数を返す。
pub fn commit(
    workspace_root: &Path,
    plan: &DeclaredApprovalPlan,
) -> Result<usize, ApproveDeclaredError> {
    let declarations: Vec<DeclarationRef<'_>> = plan
        .approve
        .iter()
        .filter_map(UnapproveTarget::declaration)
        .collect();
    if declarations.is_empty() {
        return Ok(0);
    }
    let not_recorded =
        crate::approval_store::approval_store().approve(workspace_root, &declarations);
    if !not_recorded.is_empty() {
        return Err(ApproveDeclaredError::NotRecorded(
            not_recorded
                .iter()
                .map(|d| format!("{} ({}) in {}", d.value, d.access.settings_key(), d.domain))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    Ok(declarations.len())
}

#[cfg(test)]
#[path = "approve_declared_tests.rs"]
mod approve_declared_tests;
