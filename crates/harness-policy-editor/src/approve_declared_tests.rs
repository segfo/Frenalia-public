//! [`crate::approve_declared`]のテスト。
//!
//! 守っているのは2つ——**承認できるのは名指しした宣言だけ**であることと、**候補の承認なら
//! 止まった値はここでも止まる**こと。後者を省くと、同梱された宣言が検査を素通りで承認される。

use std::path::Path;

use harness_core::RequireSandbox;
use harness_policy::generalize::SettingsKey;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use super::*;
use crate::policy_file::{PolicyDomain, PolicyFile};

/// リポジトリに同梱されていた（＝このマシンで承認していない）宣言の入ったworkspace。
fn workspace_with(domain: PolicyDomain) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    crate::policy_file::save(
        dir.path(),
        &PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![domain],
        },
    )
    .expect("save");
    dir
}

fn shipped() -> PolicyDomain {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/x/.cargo/registry/**".to_string());
    domain.fs.read.push("C:/Users/x/.ssh/**".to_string());
    domain.fs.read_write.push("C:/Users/x/.cargo/git/db".to_string());
    domain.fs.read_write.push("C:/Users/x/.cargo/bin/**".to_string());
    domain.fs.read.push("C:/other/.harness/**".to_string());
    domain.net.allow_domains.push("crates.io".to_string());
    domain
}

fn target(key: SettingsKey, value: &str) -> UnapproveTarget {
    UnapproveTarget {
        domain: "cargo".to_string(),
        key,
        value: value.to_string(),
    }
}

fn approved(ws: &Path, value: &str, access: harness_config::FsAccess) -> bool {
    crate::approval_store::approval_store().load().is_approved(
        ws,
        DeclarationRef {
            domain: "cargo",
            value,
            access,
        },
    )
}

/// 名指しした宣言**だけ**が承認され、同じドメインの他の宣言は未承認のまま（対で固定する、B-35）。
#[test]
fn only_the_named_declaration_is_approved() {
    let ws = workspace_with(shipped());
    let plan = plan(
        ws.path(),
        &[target(SettingsKey::FsRead, "C:/Users/x/.cargo/registry/**")],
        RequireSandbox::None,
    )
    .expect("plan");
    assert_eq!(plan.approve.len(), 1, "{plan:?}");
    assert_eq!(commit(ws.path(), &plan).expect("commit"), 1);

    assert!(approved(ws.path(), "C:/Users/x/.cargo/registry/**", harness_config::FsAccess::Read));
    assert!(
        !approved(ws.path(), "C:/Users/x/.ssh/**", harness_config::FsAccess::Read),
        "a declaration that was not named must stay unapproved"
    );
}

/// 指定の大文字小文字が違っても、**`policy.json`に書いてある綴りで**承認する
/// （照合は完全一致なので、指定の綴りで記録すると承認したのに付かない）。
#[test]
fn the_approval_is_recorded_under_the_spelling_in_policy_json() {
    let ws = workspace_with(shipped());
    let plan = plan(
        ws.path(),
        &[target(SettingsKey::FsRead, "c:/users/X/.CARGO/registry/**")],
        RequireSandbox::None,
    )
    .expect("plan");
    commit(ws.path(), &plan).expect("commit");
    assert!(approved(ws.path(), "C:/Users/x/.cargo/registry/**", harness_config::FsAccess::Read));
}

/// 承認済みは「承認する」に数えない（何度押しても書き直さない）。
#[test]
fn an_already_approved_declaration_is_reported_as_such() {
    let ws = workspace_with(shipped());
    let t = target(SettingsKey::FsRead, "C:/Users/x/.cargo/registry/**");
    let first = plan(ws.path(), std::slice::from_ref(&t), RequireSandbox::None).expect("plan");
    commit(ws.path(), &first).expect("commit");

    let again = plan(ws.path(), &[t], RequireSandbox::None).expect("plan");
    assert!(again.approve.is_empty());
    assert_eq!(again.already.len(), 1);
}

/// `policy.json`に無い指定は、承認せずに「無かった」と返す（綴りの間違いはここでしか気付けない）。
#[test]
fn a_declaration_that_is_not_in_policy_json_is_not_found() {
    let ws = workspace_with(shipped());
    let plan = plan(
        ws.path(),
        &[target(SettingsKey::FsReadWrite, "C:/Users/x/.cargo/registry/**")],
        RequireSandbox::None,
    )
    .expect("plan");
    assert!(plan.approve.is_empty());
    assert_eq!(plan.not_found.len(), 1, "the same value under another access is another declaration");
}

/// **制御ディレクトリは承認させない**（承認しても許可は付かないが、承認台帳に残すこと自体を断る）。
#[test]
fn a_control_directory_declaration_is_refused() {
    let ws = workspace_with(shipped());
    let plan = plan(
        ws.path(),
        &[target(SettingsKey::FsRead, "C:/other/.harness/**")],
        RequireSandbox::None,
    )
    .expect("plan");
    assert!(plan.approve.is_empty());
    assert_eq!(plan.refused.len(), 1, "{plan:?}");
}

/// **候補の承認と同じ`--require-sandbox`の検査を通す。** 書込の宣言は`write-containment`と矛盾する。
#[test]
fn the_require_sandbox_gate_applies_to_shipped_declarations_too() {
    let ws = workspace_with(shipped());
    let plan = plan(
        ws.path(),
        &[target(SettingsKey::FsReadWrite, "C:/Users/x/.cargo/git/db")],
        RequireSandbox::WriteContainment,
    )
    .expect("plan");
    assert!(plan.approve.is_empty());
    assert_eq!(plan.refused.len(), 1, "{plan:?}");

    // 対の側: 同じ宣言でも矛盾しない宣言なら承認できる。
    let plan = plan_none(ws.path(), target(SettingsKey::FsReadWrite, "C:/Users/x/.cargo/git/db"));
    assert_eq!(plan.approve.len(), 1, "{plan:?}");
}

fn plan_none(ws: &Path, t: UnapproveTarget) -> DeclaredApprovalPlan {
    plan(ws, &[t], RequireSandbox::None).expect("plan")
}

/// 候補にしない規則（ここでは`%TEMP%`配下）に当たる値は承認しない。
#[test]
fn a_value_the_candidate_rules_would_not_propose_is_refused() {
    let temp_value = format!(
        "{}/build-1234/**",
        std::env::temp_dir().to_string_lossy().replace('\\', "/").trim_end_matches('/')
    );
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(temp_value.clone());
    let ws = workspace_with(domain);
    let plan = plan_none(ws.path(), target(SettingsKey::FsRead, &temp_value));
    assert!(plan.approve.is_empty());
    assert_eq!(plan.refused.len(), 1, "{plan:?}");
}

/// ネットワークの宣言は承認台帳の対象外（断って理由を返す）。
#[test]
fn a_network_declaration_is_refused_with_a_reason() {
    let ws = workspace_with(shipped());
    let plan = plan_none(ws.path(), target(SettingsKey::NetAllowDomains, "crates.io"));
    assert!(plan.approve.is_empty());
    assert_eq!(plan.refused.len(), 1);
}

/// **候補の承認と同じ幅の検査（`breadth`）を通す。** 配下すべてへの書込は、同梱された宣言でも断る。
#[test]
fn a_recursive_write_declaration_is_refused_by_the_breadth_check() {
    let ws = workspace_with(shipped());
    let plan = plan_none(ws.path(), target(SettingsKey::FsReadWrite, "C:/Users/x/.cargo/bin/**"));
    assert!(plan.approve.is_empty());
    assert_eq!(plan.refused.len(), 1, "{plan:?}");
}
