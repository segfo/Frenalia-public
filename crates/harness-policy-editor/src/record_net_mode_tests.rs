//! [決定64] パス2の通信の扱い（記録／強制）から、中継プロキシと名前解決へ渡す値を作る部分の試験。
//!
//! 実際に Tier2a で走らせる側（`record_net`）は実マシンの E2E でしか通らないので、
//! **何を許して何を断るか**はここで純関数として固定する。禁止側と許可側を対にする（B-35）。

use super::*;

fn domain_allowing(name: &str, hosts: &[&str]) -> crate::policy_file::PolicyDomain {
    let mut domain = crate::policy_file::PolicyDomain::new(name);
    domain.net.allow_domains = hosts.iter().map(|h| h.to_string()).collect();
    domain
}

/// [決定68(2)] **通信の宣言は入口のドメインのものだけを使う**（パス2は常に入口から始める。ドメインごとの出口は P7）。
/// 別のドメインが宣言した宛先は、強制で走らせても通さない（禁止側）。入口が宣言した宛先は通す（許可側）。
#[test]
fn the_network_declarations_come_from_the_entry_domain() {
    let policy = crate::policy_file::PolicyFile {
        domains: vec![
            domain_allowing("cargo", &["github.com"]),
            domain_allowing(crate::policy_file::ENTRY_DOMAIN, &["crates.io"]),
        ],
        ..crate::policy_file::PolicyFile::default()
    };

    let declared = entry_net_declarations(&policy);
    assert_eq!(declared, ["crates.io".to_string()]);

    let plan = net_policy_plan(NetMode::Declared, declared).expect("plan");
    assert!(plan.policy.evaluate_host("crates.io").allowed, "入口の宣言は通す");
    assert!(
        !plan.policy.evaluate_host("github.com").allowed,
        "入口でないドメインの宣言を通した"
    );
}

/// 入口のドメインが無い`policy.json`では宣言は空——強制で走らせると全部断る（「全部許す」へ倒れない）。
/// 入口でないドメインの宣言を代わりに使わない。
#[test]
fn a_policy_without_an_entry_domain_runs_with_no_declarations() {
    let policy = crate::policy_file::PolicyFile {
        domains: vec![domain_allowing("cargo", &["crates.io"])],
        ..crate::policy_file::PolicyFile::default()
    };

    let declared = entry_net_declarations(&policy);
    assert!(declared.is_empty(), "{declared:?}");
    let plan = net_policy_plan(NetMode::Declared, declared).expect("plan");
    assert!(!plan.policy.evaluate_host("crates.io").allowed);
    assert!(
        entry_net_declarations(&crate::policy_file::PolicyFile::default()).is_empty(),
        "policy.json が空でも落ちない"
    );
}

/// 遷移先のドメインを用意した結果の1行（CLI と画面が共有する）。用意したドメインの名前と、用意できなかった数を出す
/// ——用意できなかったものを黙らない（`B-10`。理由は警告の側が1件ずつ持つ）。0件なら0件と言う。
#[test]
fn the_provisioned_line_names_the_domains_and_counts_the_ones_left_out() {
    let line = domains_provisioned_line(&["cargo".to_string(), "npm".to_string()], 1);
    assert!(line.contains("cargo") && line.contains("npm"), "{line}");
    assert!(line.contains('1'), "用意できなかった数を出す: {line}");

    let none = domains_provisioned_line(&[], 0);
    assert!(none.contains("ありません"), "{none}");
    assert!(!none.contains("用意できなかった"), "{none}");
}

/// 記録は今までどおり全許可（IPリテラルだけを断る）。設定型の許可リストは空のまま。
#[test]
fn record_all_lets_every_named_host_through() {
    let plan = net_policy_plan(NetMode::RecordAll, &["crates.io".to_string()]).expect("plan");

    assert!(plan.policy.is_record_all());
    assert!(
        plan.allow_domains.is_empty(),
        "記録では宣言を許可リストへ写さない（判定は record_all が持つ）: {:?}",
        plan.allow_domains
    );
    assert!(plan.policy.evaluate_host("example.com").allowed);
    assert!(!plan.policy.evaluate_host("192.0.2.1").allowed);
}

/// 強制は宣言に一致する宛先だけを通し、ほかは断る（許可側と禁止側の対）。
#[test]
fn declared_allows_only_what_policy_json_declares() {
    let declared = vec!["crates.io".to_string(), "*.github.com".to_string()];
    let plan = net_policy_plan(NetMode::Declared, &declared).expect("plan");

    assert!(!plan.policy.is_record_all());
    // 許可側
    assert!(plan.policy.evaluate_host("crates.io").allowed);
    assert!(plan.policy.evaluate_host("api.github.com").allowed);
    // 禁止側
    let denied = plan.policy.evaluate_host("example.com");
    assert!(!denied.allowed);
    assert_eq!(denied.reason, "domain_denied");
    assert!(
        !plan.policy.evaluate_host("static.crates.io").allowed,
        "素の名前はサブドメインを含まない"
    );
}

/// 中継プロキシと名前解決の設定型へ入れる値は、`harness.exe`本体と同じ正規化を通した形で、
/// 重複を除いて1回ずつ並ぶ。
#[test]
fn declared_values_are_normalized_like_harness_exe_does() {
    let declared = vec![
        "Crates.IO.".to_string(),
        "crates.io".to_string(),
        " *.GitHub.com ".to_string(),
    ];
    let plan = net_policy_plan(NetMode::Declared, &declared).expect("plan");

    assert_eq!(
        plan.allow_domains,
        vec!["crates.io".to_string(), "*.github.com".to_string()]
    );
    assert_eq!(plan.policy.allow_domains(), plan.allow_domains.as_slice());
}

/// 宣言が0件の強制は「全部断る」になる（「全部許す」へ倒れない）。
#[test]
fn declared_with_nothing_declared_denies_everything() {
    let plan = net_policy_plan(NetMode::Declared, &[]).expect("plan");

    assert!(plan.allow_domains.is_empty());
    assert!(!plan.policy.is_record_all());
    assert!(!plan.policy.evaluate_host("crates.io").allowed);
}

/// **解釈できない値が1つでもあれば走らせない。** `DomainPolicy::new`はそういう値を黙って
/// 捨てるので、そのまま渡すと宣言の一部が消えたまま「宣言どおりに走った」と出る（B-10）。
/// 理由には値そのものを名指しする。
#[test]
fn an_unparsable_declaration_refuses_to_run_and_names_the_value() {
    for bad in ["192.0.2.1", "", "*."] {
        let declared = vec!["crates.io".to_string(), bad.to_string()];
        let err = net_policy_plan(NetMode::Declared, &declared)
            .expect_err(&format!("{bad:?} を受け付けてはいけない"));
        assert!(err.contains(&format!("`{bad}`")), "{bad:?}: {err}");
    }
    // 記録では宣言を使わないので、同じ値があっても走れる（記録で集め直す道を塞がない）。
    let declared = vec!["192.0.2.1".to_string()];
    assert!(net_policy_plan(NetMode::RecordAll, &declared).is_ok());
}

/// 断った理由はマニフェストへ機械可読のタグで残る（`RecordNetError::kind`）。
#[test]
fn the_refusal_has_its_own_failure_tag() {
    let err = RecordNetError::InvalidNetDeclaration("`192.0.2.1`: invalid".to_string());

    assert_eq!(err.kind(), "invalid_net_declaration");
    assert!(err.to_string().contains("記録モードで走らせて"), "{err}");
}

/// 中継プロキシを起こしたときの1行は、モードごとに違う（強制を「全許可」と書かない）。
#[test]
fn the_proxy_line_names_the_mode() {
    let addr: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("addr");

    let record_all = proxy_started_line(addr, NetMode::RecordAll, 0);
    let declared = proxy_started_line(addr, NetMode::Declared, 3);

    assert!(record_all.contains("全部許して記録"), "{record_all}");
    assert!(declared.contains("3件だけを許し"), "{declared}");
    assert!(!declared.contains("全部許して"), "{declared}");
}
