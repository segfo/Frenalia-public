//! [#55] 遷移先ドメインを用意する判断の単体テスト。
//!
//! **実資源を作る腕だけが`#[ignore]`である**——用意できない側の判断（宣言が許可済みでない・
//! 通信を宣言している・定義が無い）は入れ物を1つも作らないので、通常の`cargo test`で回る。

use super::*;
use harness_policy::policy_file::{PolicyDomain, PolicyFile};
use harness_policy::transition::{AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};

/// 入口ドメインから`to`への辺を1本持つ宣言を組む。
fn policy_with_edge(to: &str, target: Option<PolicyDomain>) -> PolicyFile {
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions = vec![TransitionEdge {
        exe: ExeMatcher::Literal("C:/git.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: to.to_string(),
        env: None,
    }];
    let mut file = PolicyFile {
        domains: vec![entry],
        ..PolicyFile::default()
    };
    if let Some(target) = target {
        file.domains.push(target);
    }
    file
}

/// 自己ループしか無い宣言からは、用意すべき遷移先が1つも出ない。
///
/// **表を引くのは別ドメインへの遷移だけ**である（自己ループは呼び出し元の実体をそのまま使う）。
#[test]
fn a_policy_with_only_self_loops_has_no_target_domains() {
    let policy = policy_with_edge(ENTRY_DOMAIN, None);
    assert!(target_domain_names(&policy).is_empty());
}

/// 別ドメインへの辺があれば、その名前が1回だけ出る（同じ先への辺が複数あっても重複しない）。
#[test]
fn each_target_domain_is_listed_once() {
    let mut policy = policy_with_edge("cargo", Some(PolicyDomain::new("cargo")));
    // 同じ先への2本目。
    let entry = policy
        .domains
        .iter_mut()
        .find(|d| d.name == ENTRY_DOMAIN)
        .expect("entry domain");
    entry.process.transitions.push(TransitionEdge {
        exe: ExeMatcher::Literal("C:/cargo.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: "cargo".to_string(),
        env: None,
    });

    assert_eq!(target_domain_names(&policy), vec!["cargo".to_string()]);
}

/// **通信を宣言するドメインは用意しない**（理由付きで断る）。
///
/// # 壊れた状態を一文で
///
/// **通信が素通しになる。** 出口は`internetClient`（capability）とWFPの既定拒否の
/// 両方で閉じており、**capabilityだけ与えて既定拒否を張らないと開いてしまう**
/// ——`tier2a::wfp`のdocが「`internetClient`を持ったままdefault-denyだけ失う（fail-open）」
/// という欠陥として書いている形そのものである。
#[test]
fn a_domain_that_declares_network_is_not_provisioned() {
    let mut target = PolicyDomain::new("fetcher");
    target.net.allow_domains = vec!["crates.io".to_string()];
    let policy = policy_with_edge("fetcher", Some(target));
    let workspace = tempfile::tempdir().expect("temp workspace");

    let outcome = provision_target_domains(&policy, workspace.path(), "rwx");
    assert!(
        outcome.domains.is_empty(),
        "通信を宣言したドメインを用意している"
    );
    assert_eq!(outcome.skipped.len(), 1);
    assert!(
        outcome.skipped[0].1.contains("通信"),
        "断った理由が通信だと分からない: {}",
        outcome.skipped[0].1
    );
}

/// 遷移先として名指しされているのに**定義が無い**ドメインは用意しない。
///
/// 宣言としては編集時検査を通り得る（辺の`to`は文字列）ので、ここで落とす。
#[test]
fn a_target_domain_without_a_definition_is_not_provisioned() {
    let policy = policy_with_edge("ghost", None);
    let workspace = tempfile::tempdir().expect("temp workspace");

    let outcome = provision_target_domains(&policy, workspace.path(), "rwx");
    assert!(outcome.domains.is_empty());
    assert_eq!(outcome.skipped.len(), 1);
    assert!(
        outcome.skipped[0].1.contains("定義が無い"),
        "断った理由が読めない: {}",
        outcome.skipped[0].1
    );
}

/// **宣言が許可済みでなければ用意しない**（骨格の定義）。
///
/// # 壊れた状態を一文で
///
/// **新しい許可をACLへ書いてしまう。** この回のスコープは「1本も書かない」であり、
/// 書く経路が増えるほど「片方だけが台帳へ記録する／片方だけが撤収できる」形の
/// 事故が起きる（BUG-017の孤立ACEと同型）。
#[test]
fn a_domain_whose_declarations_are_not_granted_is_not_provisioned() {
    let mut target = PolicyDomain::new("cargo");
    // このワークスペースでは誰も許可していないパス。
    target.fs.read = vec!["C:/nowhere/never-granted".to_string()];
    let policy = policy_with_edge("cargo", Some(target));
    let workspace = tempfile::tempdir().expect("temp workspace");

    let outcome = provision_target_domains(&policy, workspace.path(), "rwx");
    assert!(
        outcome.domains.is_empty(),
        "許可されていない宣言を持つドメインを用意している"
    );
    assert_eq!(outcome.skipped.len(), 1);
    assert!(
        outcome.skipped[0].1.contains("許可されていない"),
        "断った理由が読めない: {}",
        outcome.skipped[0].1
    );
}

/// **対の側**（`B-35`）: 宣言が1件も無いドメインは用意できる。
///
/// これが無いと「常に断る」実装でも上の3本は緑になり、**別ドメインへの遷移が
/// 一度も成立しない**まま「実装した」ことになる。
///
/// 実資源（AppContainerプロファイル）を作るので`#[ignore]`。
/// 用意した入れ物は`end_session`で回収する。
#[test]
#[ignore = "creates a real AppContainer profile; run serially"]
fn a_domain_with_no_declarations_is_provisioned() {
    let policy = policy_with_edge("s55bare", Some(PolicyDomain::new("s55bare")));
    let workspace = tempfile::tempdir().expect("temp workspace");

    let outcome = provision_target_domains(&policy, workspace.path(), "rwx");
    let _cleanup = super::super::test_support::scopeguard(|| {
        let _ = crate::tier2a::session_profile::end_session(&super::super::revoke_session_grant);
    });

    assert_eq!(
        outcome.domains.len(),
        1,
        "宣言が1件も無いドメインすら用意できていない: {:?}",
        outcome.skipped
    );
    let spec = &outcome.domains[0];
    assert_eq!(spec.policy_domain, "s55bare");
    assert!(
        spec.container_sid.starts_with("S-1-15-2-"),
        "package SIDになっていない: {}",
        spec.container_sid
    );
    // **全Tier2aの子が共通で携える土台が積まれている。** 積まれていないと、
    // この表から起きた子は何も読めず、孫を頼むこともできず、注入にも失敗する。
    // 内訳は`capability_sids_for`の表（traverse・spawn要求・workspace・Redirector DLL）。
    // **本数で固定しない**——DLLはビルド構成で1本か2本かが変わる（`redirector_dll_paths`は
    // `exists()`で絞る）ので、本数を書くと構成によって赤くなる。
    assert!(
        spec.capability_sids.len() >= 3,
        "共通の土台（traverse・spawn要求・workspace）が積まれていない: {:?}",
        spec.capability_sids
    );
    assert!(
        spec.capability_sids
            .iter()
            .all(|s| s.starts_with("S-1-15-3-")),
        "capability SIDでないものが混ざっている: {:?}",
        spec.capability_sids
    );
    // 入れ物が**マシンに実在する**こと（台帳ではなくOSに聞く）。
    assert!(
        crate::tier2a::session_profile::existing_profiles_for_test().contains(&spec.name),
        "入れ物が作られていない: {}",
        spec.name
    );
}
