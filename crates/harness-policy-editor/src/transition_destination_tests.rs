//! 遷移先ドメインの見込みの単体試験。**端末もWin32も要らない。**
//! （名前の検査の試験は`harness-sandbox`の`tier2a::domain_profile`へ移した）
//!
//! 見込みは`harness.exe`の判断（`policy_fs::plan`・`domain_provision`）の写しなので、
//! **分岐ごとに禁止側と許可側を対で**固定する——写しがずれたときに、どの分岐がずれたかが分かるように。

use super::*;

use harness_config::FsAccess;
use harness_policy::policy_file::ENTRY_DOMAIN;

fn file_with(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        domains,
        ..PolicyFile::default()
    }
}

fn domain_reading(name: &str, values: &[&str]) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.fs.read = values.iter().map(|v| v.to_string()).collect();
    domain
}

/// 宣言を全部付ける（＝全部このマシンで承認済み）として一覧を作る。見込みが見るのは
/// 「付かなかった宣言」だけなので、付ける一覧（`passthrough`）の中身は空のままでよい。
fn all_granted(_domain: &PolicyDomain) -> DomainGrants {
    DomainGrants::default()
}

/// 宣言を全部「このマシンで未承認」として扱う。
fn none_approved(domain: &PolicyDomain) -> DomainGrants {
    DomainGrants {
        passthrough: Vec::new(),
        skipped: domain
            .fs
            .entries()
            .into_iter()
            .map(|(value, access)| SkippedDeclaration {
                value: value.to_string(),
                access,
                reason: SkipReason::NotApprovedOnThisMachine,
            })
            .collect(),
    }
}

// --- 見込み ---------------------------------------------------------------

/// 自己ループは用意が要らない（Daemonは表を引かない）。宣言の中身に関係なく「同じドメイン」。
#[test]
fn the_callers_own_domain_needs_no_provisioning() {
    let file = file_with(vec![domain_reading(ENTRY_DOMAIN, &["C:/x/**"])]);
    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, ENTRY_DOMAIN, &none_approved),
        Outlook::SameDomain
    );
}

/// **禁止側**: 通信を宣言している遷移先は用意されない（ドメインごとの出口制御が無い。`harness.exe`と同じ順で、
/// ファイル宣言の承認より先に断る）。
#[test]
fn a_destination_that_declares_network_is_not_provisioned() {
    let mut iso = PolicyDomain::new("iso");
    iso.net.allow_domains.push("example.com".to_string());
    let file = file_with(vec![PolicyDomain::new(ENTRY_DOMAIN), iso]);

    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, "iso", &all_granted),
        Outlook::NotProvisioned(Blocker::DeclaresNetwork { count: 1 })
    );
}

/// **禁止側**: 許可が付かないファイル宣言が1件でもあれば用意されない（fail-closed）。理由は宣言ごとに運ぶ。
#[test]
fn a_destination_with_unapproved_declarations_is_not_provisioned() {
    let file = file_with(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        domain_reading("iso", &["C:/a/**", "C:/b/**"]),
    ]);

    match outlook(&file, ENTRY_DOMAIN, "iso", &none_approved) {
        Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped }) => {
            assert_eq!(skipped.len(), 2);
            assert!(skipped
                .iter()
                .all(|s| s.reason == SkipReason::NotApprovedOnThisMachine
                    && s.access == FsAccess::Read));
        }
        other => panic!("未承認の宣言を持つ遷移先が用意される見込みになった: {other:?}"),
    }
}

/// **許可側（上2つの対）**: 通信を宣言せず、宣言に全部許可が付くなら用意される（宣言の件数を運ぶ）。
#[test]
fn a_destination_whose_declarations_are_all_granted_is_provisioned() {
    let file = file_with(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        domain_reading("iso", &["C:/a/**", "C:/b/**"]),
    ]);
    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, "iso", &all_granted),
        Outlook::Provisioned { declarations: 2 }
    );
}

/// 宣言の無い遷移先・`policy.json`に無い名前は、共通の土台だけで用意される
/// （後者は、確定すると宣言の無いドメインとして作るため）。
#[test]
fn an_empty_or_new_destination_is_provisioned_with_the_common_base_only() {
    let file = file_with(vec![PolicyDomain::new(ENTRY_DOMAIN), PolicyDomain::new("iso")]);
    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, "iso", &none_approved),
        Outlook::Provisioned { declarations: 0 }
    );
    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, "brand-new", &none_approved),
        Outlook::Provisioned { declarations: 0 }
    );
}

/// 一覧へ渡す表には、**用意される見込みのものだけ**が入る（自己ループ・用意されないものは入らない）。
#[test]
fn only_destinations_expected_to_be_provisioned_go_into_the_listing_table() {
    let mut net = PolicyDomain::new("net");
    net.net.allow_domains.push("example.com".to_string());
    let file = file_with(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        PolicyDomain::new("iso"),
        net,
    ]);
    let table = outlooks(&file, ENTRY_DOMAIN, &all_granted);

    assert_eq!(
        provisioned_names(&table),
        ["iso".to_string()].into_iter().collect::<BTreeSet<_>>()
    );
}

/// 文言は**理由を言う**（用意されないことだけを言うと、何を直せばよいか分からない）。
#[test]
fn the_notice_names_what_to_do_about_an_unapproved_destination() {
    let file = file_with(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        domain_reading("iso", &["C:/a/**"]),
    ]);
    let lines = outlook(&file, ENTRY_DOMAIN, "iso", &none_approved).notice_lines("iso");
    let text = lines.join("\n");
    assert!(text.contains('⚠'), "{text}");
    assert!(text.contains("F3"), "承認の仕方を言っていない: {text}");
    assert!(text.contains("C:/a/**"), "どの宣言かを言っていない: {text}");
}

/// **このマシンの承認台帳を通る経路**（製品が渡す関数）。承認すると「用意される」へ変わる。
///
/// 台帳は試験ごとの一時ファイル（`approval_store`のdoc）なので、実マシンの台帳は触らない。
#[test]
fn approving_on_this_machine_turns_the_outlook_into_provisioned() {
    let ws = tempfile::tempdir().unwrap();
    let file = file_with(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        domain_reading("iso", &["C:/approved-for-test/**"]),
    ]);

    let before = grants_on_this_machine(ws.path());
    assert!(
        !outlook(&file, ENTRY_DOMAIN, "iso", &before).is_provisioned(),
        "未承認のまま用意される見込みになった"
    );

    let declaration = harness_sandbox::tier2a::policy_approval::DeclarationRef {
        domain: "iso",
        value: "C:/approved-for-test/**",
        key: harness_policy::generalize::SettingsKey::FsRead,
    };
    assert!(
        crate::approval_store::approval_store()
            .approve(ws.path(), &[declaration])
            .is_empty(),
        "setup: 承認を記録できない"
    );
    let after = grants_on_this_machine(ws.path());
    assert_eq!(
        outlook(&file, ENTRY_DOMAIN, "iso", &after),
        Outlook::Provisioned { declarations: 1 }
    );
}
