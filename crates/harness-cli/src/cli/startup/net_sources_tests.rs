//! [決定69(1)(4)] Tier2a の入口の通信の宛先をどこから取るかの単体試験。
//!
//! 守っているのは3つ——**承認済みの宣言と`--net-allow-domain`の和を取る**こと、**未承認・解釈できない
//! 宣言は使わず名指しする**こと（`B-10`）、**`--net-allow-domain`の綴りが読めなければ起動を止める**こと。

use super::*;

use harness_sandbox::tier2a::policy_fs::{NetSkipReason, SkippedNetDeclaration};

fn net(allow: &[&str], skipped: &[(&str, NetSkipReason)]) -> DomainNet {
    DomainNet {
        allow_domains: allow.iter().map(|v| v.to_string()).collect(),
        skipped: skipped
            .iter()
            .map(|(value, reason)| SkippedNetDeclaration {
                value: value.to_string(),
                reason: reason.clone(),
            })
            .collect(),
    }
}

/// **許可側**: 承認済みの宣言と`--net-allow-domain`の和（正規化済み・重複なし）。
#[test]
fn the_entry_destinations_are_the_approved_declarations_plus_the_cli_flag() {
    let destinations = entry_destinations(
        &net(&["Example.COM", "api.example.com"], &[]),
        &["crates.io".to_string(), "example.com".to_string()],
    )
    .expect("綴りは全部読める");

    assert_eq!(
        destinations.allow_domains,
        vec!["example.com", "api.example.com", "crates.io"],
        "正規化（小文字へ畳む）か重複の除去が効いていない"
    );
    assert!(destinations.warnings.is_empty(), "{:?}", destinations.warnings);
}

/// **禁止側の対**: 未承認の宣言は宛先に入らず、理由を名指しする（黙って落とすと「承認したのに
/// 通信できない」の原因が画面のどこにも出ない）。
#[test]
fn an_unapproved_entry_declaration_is_not_used_and_is_named() {
    let destinations = entry_destinations(
        &net(
            &[],
            &[("example.com", NetSkipReason::NotApprovedOnThisMachine)],
        ),
        &[],
    )
    .expect("承認の有無は綴りの検査と関係ない");

    assert!(destinations.allow_domains.is_empty());
    assert_eq!(destinations.warnings.len(), 1);
    assert!(
        destinations.warnings[0].contains("example.com")
            && destinations.warnings[0].contains("not approved"),
        "{:?}",
        destinations.warnings
    );
}

/// 解釈できない宣言も同じく名指しする（理由が未承認と混ざらない）。
#[test]
fn an_unparsable_entry_declaration_is_named_with_its_own_reason() {
    let destinations = entry_destinations(
        &net(
            &[],
            &[(
                "127.0.0.1",
                NetSkipReason::Unparsable("ip literal".to_string()),
            )],
        ),
        &[],
    )
    .expect("解釈できない宣言は`domain_net`が既に落としている");

    assert_eq!(destinations.warnings.len(), 1);
    assert!(
        destinations.warnings[0].contains("ip literal"),
        "{:?}",
        destinations.warnings
    );
}

/// **`--net-allow-domain`の綴りが読めなければ起動を止める**（黙って捨てると、打ったのに効かない）。
#[test]
fn an_unparsable_cli_value_stops_the_startup() {
    let error = entry_destinations(&net(&[], &[]), &["127.0.0.1".to_string()])
        .expect_err("IPリテラルは宛先の綴りとして読めない");
    assert!(error.contains("127.0.0.1"), "{error}");
}

// --- [決定69(1)] confidential との矛盾 ---

/// **禁止側**: `policy.json`が宛先を宣言していれば confidential は起動を断る（入口でも遷移先でも）。
#[test]
fn confidential_refuses_to_start_when_policy_json_declares_network() {
    let entry = net(&["example.com"], &[]);
    let reason = confidential_conflict(
        harness_core::RequireSandbox::Confidential,
        &entry,
        &[],
    )
    .expect("入口の宣言で断らなければならない");
    assert!(reason.contains("example.com"), "{reason}");

    // 遷移先のドメインの宣言も数える（出口を与えるのはこの起動自身である）。
    let reason = confidential_conflict(
        harness_core::RequireSandbox::Confidential,
        &DomainNet::default(),
        &[("ssh".to_string(), net(&["github.com"], &[]))],
    )
    .expect("遷移先の宣言で断らなければならない");
    assert!(reason.contains("github.com"), "{reason}");
}

/// **許可側の対**: 宣言が無ければ confidential でも起動する（未承認の宣言は宛先に入らないので数えない）。
#[test]
fn confidential_starts_when_nothing_is_declared_or_approved() {
    assert!(confidential_conflict(
        harness_core::RequireSandbox::Confidential,
        &DomainNet::default(),
        &[],
    )
    .is_none());
    // 未承認の宣言だけなら宛先は0件（`domain_net`が落としている）ので矛盾しない。
    assert!(confidential_conflict(
        harness_core::RequireSandbox::Confidential,
        &net(&[], &[("example.com", NetSkipReason::NotApprovedOnThisMachine)]),
        &[],
    )
    .is_none());
    // confidential でなければ宣言があっても断らない。
    assert!(confidential_conflict(
        harness_core::RequireSandbox::None,
        &net(&["example.com"], &[]),
        &[],
    )
    .is_none());
}

/// [決定69 の前例の(13)] **起動と`harness prompt`の下見が同じ関数を通る**ことを数える（`B-06`）。
///
/// 下見が別の組み立てを持つと、モデルへ見える制約を確かめる道具としての意味が無い。関数名を変えたら
/// ここが赤くなる（`launch.rs`の姿勢の数え上げと同じ形の見張り）。
#[test]
fn both_hosts_build_the_entry_destinations_with_this_module() {
    let startup = include_str!("sandbox.rs");
    let prompt = include_str!("../workspace_cmd.rs");
    assert!(
        startup.contains("net_sources::entry_destinations("),
        "起動（stage_prepare_sandbox）がこのモジュールを通っていない"
    );
    assert!(
        prompt.contains("entry_destinations_from_workspace("),
        "harness prompt の下見がこのモジュールを通っていない"
    );
}
