//! 提案を受け入れる前の矛盾チェック（D-42 最終文「特に`read_write`への昇格は
//! write-containmentを弱めるため`--require-sandbox`との矛盾チェックを通す」）。
//!
//! `--require-sandbox`はユーザーが「この水準を満たせないなら起動しない」と宣言したものである。
//! その宣言と正面から矛盾する穴を、拒否の観測を根拠に開けてはいけない——**監査由来の情報が
//! ユーザーの明示的な意思を上書きする経路を作らない**（P-07の裏返し）。
//!
//! 判定規則は`--fs-allow`のD7と同じにする（`crates/harness-cli/src/cli/mod.rs`の`--fs-allow`ヘルプ参照）:
//!
//! | `--require-sandbox` | `fs.read` / `fs.read_exec` | `fs.read_write` | `net.allow_domains` |
//! |---|---|---|---|
//! | 指定なし | 許可 | 許可 | 許可 |
//! | `write-containment` | 許可 | **拒否** | 許可 |
//! | `confidential` | **拒否** | **拒否** | 警告（Layer1/2の宛先allowlistであって capability の開放ではないため拒否まではしない） |

use harness_core::RequireSandbox;

use crate::generalize::{RuleProposal, SettingsKey};

/// [`check_proposal`]の判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    /// そのまま適用してよい。
    Allowed,
    /// 適用してよいが、読んでほしい注意がある。
    AllowedWithWarning(String),
    /// `--require-sandbox`の宣言と矛盾するため適用しない。
    Rejected(String),
}

impl GateVerdict {
    pub fn is_rejected(&self) -> bool {
        matches!(self, GateVerdict::Rejected(_))
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            GateVerdict::Allowed => None,
            GateVerdict::AllowedWithWarning(m) | GateVerdict::Rejected(m) => Some(m),
        }
    }
}

/// 1件の提案を`--require-sandbox`の宣言と突き合わせる。
pub fn check_proposal(proposal: &RuleProposal, require_sandbox: RequireSandbox) -> GateVerdict {
    match (proposal.key, require_sandbox) {
        (_, RequireSandbox::None) => GateVerdict::Allowed,

        (SettingsKey::FsReadWrite, RequireSandbox::WriteContainment) => {
            GateVerdict::Rejected(format!(
                "{} would grant write access outside the workspace, which contradicts \
                 --require-sandbox (write containment). Accept it only after dropping that \
                 requirement, or propose fs.read instead.",
                proposal.value
            ))
        }
        (SettingsKey::FsReadWrite, RequireSandbox::Confidential) => GateVerdict::Rejected(format!(
            "{} would grant write access outside the workspace, which contradicts \
             --require-sandbox=confidential.",
            proposal.value
        )),
        (SettingsKey::FsRead | SettingsKey::FsReadExec, RequireSandbox::Confidential) => {
            GateVerdict::Rejected(format!(
                "{} would open a read hole outside the workspace, which contradicts \
                 --require-sandbox=confidential (that level requires the sandbox to keep \
                 out-of-workspace contents unreadable).",
                proposal.value
            ))
        }

        (SettingsKey::NetAllowDomains, RequireSandbox::Confidential) => {
            GateVerdict::AllowedWithWarning(format!(
                "{} allows an outbound destination while --require-sandbox=confidential is set. \
                 This is a destination allowlist enforced by the proxy/WFP layers, not an \
                 internetClient capability grant, so it is not refused outright -- but it does \
                 widen the exfiltration surface you asked to keep closed.",
                proposal.value
            ))
        }

        (SettingsKey::FsRead | SettingsKey::FsReadExec, RequireSandbox::WriteContainment) => {
            GateVerdict::Allowed
        }
        (SettingsKey::NetAllowDomains, RequireSandbox::WriteContainment) => GateVerdict::Allowed,
    }
}

/// 複数の提案をまとめて判定し、`(提案id, 判定)`を返す。
pub fn check_all<'a>(
    proposals: impl IntoIterator<Item = &'a RuleProposal>,
    require_sandbox: RequireSandbox,
) -> Vec<(String, GateVerdict)> {
    proposals
        .into_iter()
        .map(|p| (p.id.clone(), check_proposal(p, require_sandbox)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::generalize::generalize;
    use crate::normalize::{DeniedCandidate, Source};
    use harness_config::FsAccess;

    fn proposal(access: FsAccess) -> RuleProposal {
        generalize(
            &[DeniedCandidate::fs(
                Source::Etw,
                "C:/outside",
                access,
                "denied",
                1,
                0,
            )],
        )
        .remove(0)
    }

    fn net_proposal() -> RuleProposal {
        generalize(
            &[DeniedCandidate::net(
                Source::Network,
                "api.example.com",
                "denied",
                1,
                0,
            )],
        )
        .remove(0)
    }

    /// 宣言が無ければ何も阻まない。
    #[test]
    fn without_require_sandbox_everything_is_allowed() {
        for access in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
            assert_eq!(
                check_proposal(&proposal(access), RequireSandbox::None),
                GateVerdict::Allowed
            );
        }
        assert_eq!(
            check_proposal(&net_proposal(), RequireSandbox::None),
            GateVerdict::Allowed
        );
    }

    /// `write-containment`は`read_write`だけを拒否し、読取系は通す（D7と同じ規則）。
    #[test]
    fn write_containment_rejects_only_read_write() {
        assert!(check_proposal(
            &proposal(FsAccess::ReadWrite),
            RequireSandbox::WriteContainment
        )
        .is_rejected());
        assert_eq!(
            check_proposal(&proposal(FsAccess::Read), RequireSandbox::WriteContainment),
            GateVerdict::Allowed
        );
        assert_eq!(
            check_proposal(
                &proposal(FsAccess::ReadExec),
                RequireSandbox::WriteContainment
            ),
            GateVerdict::Allowed
        );
    }

    /// `confidential`はFS passthroughを読取・書込のいずれも拒否する。
    #[test]
    fn confidential_rejects_every_fs_passthrough() {
        for access in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
            let verdict = check_proposal(&proposal(access), RequireSandbox::Confidential);
            assert!(verdict.is_rejected(), "{access:?} must be rejected");
            assert!(verdict.message().unwrap().contains("confidential"));
        }
    }

    /// `confidential`下のドメイン許可は拒否せず警告に留める（capabilityの開放ではないため）。
    /// ただし「閉じておくと宣言した出口を広げる」ことは明示する。
    #[test]
    fn confidential_warns_about_domain_allowlisting_without_rejecting() {
        let verdict = check_proposal(&net_proposal(), RequireSandbox::Confidential);

        assert!(!verdict.is_rejected());
        let message = verdict.message().expect("carries a warning");
        assert!(message.contains("exfiltration"));
    }

    /// 拒否メッセージには対象の値が入る（どれが弾かれたか一覧から分かるように）。
    #[test]
    fn rejection_messages_name_the_offending_value() {
        let verdict = check_proposal(
            &proposal(FsAccess::ReadWrite),
            RequireSandbox::WriteContainment,
        );

        assert!(verdict.message().unwrap().contains("C:/outside"));
    }

    #[test]
    fn check_all_pairs_verdicts_with_proposal_ids() {
        let proposals = vec![proposal(FsAccess::ReadWrite), net_proposal()];

        let verdicts = check_all(&proposals, RequireSandbox::WriteContainment);

        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].0, "fs-1");
        assert!(verdicts[0].1.is_rejected());
        assert_eq!(verdicts[1].0, "net-1");
        assert!(!verdicts[1].1.is_rejected());
    }
}
