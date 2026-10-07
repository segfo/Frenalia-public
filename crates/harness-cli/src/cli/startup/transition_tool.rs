//! [段階6e] 遷移MACについて**モデルへ何を見せるか**の判定と、その事実の組み立て
//! （`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.8）。
//!
//! # なぜ判定を関数に切り出してあるのか
//!
//! **今日の製品経路はこの条件を満たさないからである。** `run_agent`がSpawn Daemonへ渡すのは
//! `ChildProcessPolicy::Unrestricted`（生成禁止を積まない）で、条件は静的に偽になる。
//! 分岐の中へ条件を直接書くと、**配線したこと自体をテストできない**——
//! 「今日の組み合わせでは出さない／生成禁止を積めば出す」を対で固定するために関数にする。
//!
//! # 3つ揃わないと出さない
//!
//! | 条件 | 揃わないと何が嘘になるか |
//! |---|---|
//! | Tier2aである | それ以外のTierにはAppContainerの境界が無く、遷移という概念が無い |
//! | Spawn Daemonが居る | 判定する者が居ない |
//! | **生成禁止を積んでいる** | **子は頼まずに自分で起こせる**ので、「宣言された組み合わせだけ」が嘘になる |
//!
//! 3つ目が要である。1と2だけで出すと、**Daemonは居るのに誰もDaemonに頼んでいない**状態で
//! 「宣言外の生成は拒否されます」と宣言することになる。

use harness_core::{RunnableProgramFact, ShellTier, TransitionFacts};

/// この構成で`can_run_program`と宣言の1行を出してよいか。
///
/// **`daemon_present`と`child_process_restricted`を別々に受けるのは、片方だけの状態が
/// 実在するからである**——Daemonは常に起こすが、生成禁止は⑤を既定へ入れるまで積まない。
pub(super) fn should_expose(
    tier: ShellTier,
    daemon_present: bool,
    child_process_restricted: bool,
) -> bool {
    tier == ShellTier::Tier2a && daemon_present && child_process_restricted
}

/// 宣言から、モデルへ見せる一覧を組み立てる。
///
/// **Daemonへ渡したのと同じ宣言（起動時に1回読んだもの）を使うこと。** ここで
/// `policy.json`を読み直すと、**Daemonが判定に使うグラフとずれる**——モデルには
/// 「起こせる」と答えたのにDaemonが拒否する、という食い違いが起きる（正本を2つ持たない、`B-13`）。
///
/// 一覧と権限の要約の計算は[`harness_policy::transition_listing`]が持つ。
/// **ここへ写さない**——段階⑦のポリシーエディタの画面も同じものを使う。
///
/// [#30] **権限欄（`rights_fs`）には、このマシンで承認済みの宣言だけを載せる**（`approved_fs_values`、
/// `harness_sandbox::tier2a::policy_fs::approved_fs_values`が作る）。未承認の宣言には許可が付かないので、載せると
/// 付いていない許可をモデルへ伝えることになる。辺と判定の入力は変えない（Daemonと同じグラフのまま）。
///
/// **`provisioned_domains`はDaemonへ渡すのと同じ表から作ること**（`domain_provision`が実際に用意できた
/// 遷移先の`policy_domain`）。「いま起こせるか」はその表に在るかで決まる——別に数えると、
/// モデルには「起こせる」と答えたのにDaemonが`TargetDomainNotProvisioned`で断る形になる（`B-13`）。
/// かつては表を受け取らず「別ドメイン行きは全部起こせない」と答えていた（§10.1.2の撤去一覧5点目）。
pub(super) fn facts_from_policy(
    policy: &harness_policy::policy_file::PolicyFile,
    workspace_root: &str,
    writable_outside_policy: &[String],
    approved_fs_values: &std::collections::BTreeSet<(String, &'static str)>,
    provisioned_domains: &std::collections::BTreeSet<String>,
) -> TransitionFacts {
    let input = policy.transition_graph_input(Some(workspace_root), writable_outside_policy);
    let from_domain = harness_policy::policy_file::ENTRY_DOMAIN;
    // 宣言が壊れているならDaemonも起動していない（`TransitionGraph::build`が落ちる）ので、
    // ここで失敗したときは**空の一覧**にする。**空は「起こせるものが無い」**であり、
    // 「機構が効いていない」ではない——後者は`Option`が`None`であることで表す。
    let programs = harness_policy::transition_listing::rows(&input, from_domain, provisioned_domains)
        .unwrap_or_default()
        .into_iter()
        .map(|row| RunnableProgramFact {
            exe: row.exe,
            exe_is_pattern: row.exe_is_pattern,
            argv: row.argv,
            argv_is_pattern: row.argv_is_pattern,
            to_domain: row.to_domain,
            rights_fs: row
                .rights
                .fs
                .into_iter()
                .filter(|(path, access)| approved_fs_values.contains(&(path.clone(), *access)))
                .map(|(path, access)| (path, access.to_string()))
                .collect(),
            rights_net: row.rights.net,
            runnable_now: row.runnable_now,
        })
        .collect();
    TransitionFacts {
        from_domain: from_domain.to_string(),
        programs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **禁止側**: 今日の製品の組み合わせ（生成禁止を積まない）では出さない。
    ///
    /// ここが真になった瞬間、モデルは「宣言外の生成は拒否される」と読むが、
    /// 実際には子は自分で起こせる——**嘘を宣言することになる**。
    #[test]
    fn todays_production_combination_does_not_expose_the_tool() {
        assert!(!should_expose(ShellTier::Tier2a, true, false));
    }

    /// **許可側（対）**: 生成禁止を積んだ構成では出す。
    ///
    /// 対にしないと「常に偽」の実装でも禁止側が緑になり、⑤を既定へ入れた日に
    /// **誰も気づかないまま出ないまま**になる（`B-35`）。
    #[test]
    fn a_session_that_actually_blocks_spawning_exposes_the_tool() {
        assert!(should_expose(ShellTier::Tier2a, true, true));
    }

    /// 残り2つの条件も、それぞれ単独で欠けたら出さない。
    #[test]
    fn every_condition_is_necessary() {
        assert!(
            !should_expose(ShellTier::Tier2a, false, true),
            "判定する者が居ないのに「宣言のみ許可」と言っている"
        );
        for tier in [
            ShellTier::Tier0,
            ShellTier::Tier1,
            ShellTier::Tier2b,
            ShellTier::Tier3,
        ] {
            assert!(
                !should_expose(tier, true, true),
                "{tier:?}には遷移MACの境界が無い"
            );
        }
    }

    /// 宣言から一覧を組み立てる側。**入口ドメインの辺だけ**を拾い、他ドメインの宣言は載せない。
    #[test]
    fn facts_carry_only_the_entry_domains_edges() {
        let json = serde_json::json!({
            "schema_version": 2,
            "domains": [
                {
                    "name": harness_policy::policy_file::ENTRY_DOMAIN,
                    "process": { "transitions": [
                        { "exe": { "literal": "C:/bin/git.exe" }, "argv": { "any": true },
                          "to": harness_policy::policy_file::ENTRY_DOMAIN }
                    ]}
                },
                {
                    "name": "other",
                    "process": { "transitions": [
                        { "exe": { "literal": "C:/bin/secret.exe" }, "argv": { "any": true },
                          "to": "other" }
                    ]}
                }
            ]
        });
        let policy: harness_policy::policy_file::PolicyFile =
            serde_json::from_value(json).expect("parse");

        let facts = facts_from_policy(&policy, "C:/ws", &[], &Default::default(), &Default::default());

        assert_eq!(facts.from_domain, harness_policy::policy_file::ENTRY_DOMAIN);
        assert_eq!(facts.programs.len(), 1);
        assert_eq!(facts.programs[0].exe, "C:/bin/git.exe");
        assert!(facts.programs[0].runnable_now);
    }

    /// 遷移を1本も宣言していないポリシーでは**空の一覧**になる（`None`とは別物）。
    ///
    /// 空は「起こせるものが無い」、`None`は「機構が効いていない」——**混ぜると、
    /// モデルは存在しない制約に合わせて動く**。
    #[test]
    fn a_policy_without_transitions_yields_an_empty_list_not_a_missing_one() {
        let policy = harness_policy::policy_file::PolicyFile::default();
        let facts = facts_from_policy(&policy, "C:/ws", &[], &Default::default(), &Default::default());
        assert!(facts.programs.is_empty());
    }

    fn entry_with_an_edge_to(target: &str) -> harness_policy::policy_file::PolicyFile {
        serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "domains": [
                {
                    "name": harness_policy::policy_file::ENTRY_DOMAIN,
                    "process": { "transitions": [
                        { "exe": { "literal": "C:/bin/curl.exe" }, "argv": { "any": true },
                          "to": target }
                    ]}
                },
                { "name": target }
            ]
        }))
        .expect("parse")
    }

    /// **許可側**: Daemonへ渡す表に在る遷移先への辺は、モデルへ「起こせる」と見せる
    /// （§10.1.2の撤去一覧5点目を外した。2026-10-01）。
    #[test]
    fn an_edge_to_a_provisioned_domain_is_shown_as_runnable() {
        let provisioned: std::collections::BTreeSet<String> = ["iso".to_string()].into();
        let facts = facts_from_policy(
            &entry_with_an_edge_to("iso"),
            "C:/ws",
            &[],
            &Default::default(),
            &provisioned,
        );
        assert!(
            facts.programs[0].runnable_now,
            "Daemonが起こせる遷移を、モデルには「起こせない」と言っている"
        );
    }

    /// **禁止側（対）**: 表に無い遷移先（このセッションで用意できなかった）への辺は「いまは起こせない」。
    /// 「起こせる」と言うと、撃った瞬間に`TargetDomainNotProvisioned`で断られる。
    #[test]
    fn an_edge_to_a_domain_missing_from_the_daemons_table_is_not_runnable() {
        let facts = facts_from_policy(
            &entry_with_an_edge_to("iso"),
            "C:/ws",
            &[],
            &Default::default(),
            &Default::default(),
        );
        assert!(!facts.programs[0].runnable_now);
    }

    /// [#30] **権限欄には、このマシンで承認済みの宣言だけを載せる**（未承認には許可が付かない）。
    /// 対の側として、承認済みの宣言は載る（`B-35`）。辺そのものは承認に関係なく載る。
    #[test]
    fn the_rights_column_shows_only_approved_file_declarations() {
        let json = serde_json::json!({
            "schema_version": 2,
            "domains": [{
                "name": harness_policy::policy_file::ENTRY_DOMAIN,
                "fs": { "read": ["C:/approved/**", "C:/shipped/**"] },
                "process": { "transitions": [
                    { "exe": { "literal": "C:/bin/git.exe" }, "argv": { "any": true },
                      "to": harness_policy::policy_file::ENTRY_DOMAIN }
                ]}
            }]
        });
        let policy: harness_policy::policy_file::PolicyFile =
            serde_json::from_value(json).expect("parse");
        let approved: std::collections::BTreeSet<(String, &'static str)> =
            [("C:/approved/**".to_string(), "read")].into_iter().collect();

        let facts = facts_from_policy(&policy, "C:/ws", &[], &approved, &Default::default());

        assert_eq!(facts.programs.len(), 1, "the edge itself does not depend on approval");
        let rights: Vec<&str> = facts.programs[0]
            .rights_fs
            .iter()
            .map(|(path, _)| path.as_str())
            .collect();
        assert_eq!(rights, vec!["C:/approved/**"]);
    }

}
