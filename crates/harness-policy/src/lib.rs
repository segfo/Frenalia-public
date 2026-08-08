//! harness-policy: ポリシー学習ヘルパーの提案エンジン（M15.7）。
//!
//! 設計正本は`plans/DESIGN-SANDBOX-APPPOLICY.md` §11（拘束的決定 D-42/D-43）。
//!
//! サンドボックスが何かを拒否したとき、ユーザーが次に知りたいのは「何が拒否されたか」ではなく
//! 「**では何を許せばよいか**」である。本クレートはその橋渡しを担う——4つの収集源に散らばった
//! 拒否記録を1つの候補列へ正規化し（[`normalize`]）、許可ルールの候補へ一般化し（[`generalize`]）、
//! `.harness/settings.json`への差分として提示する（[`diff`]）。
//!
//! ```text
//!   fs-passthrough-ledger.json (preflight) ─┐
//!   net-audit.jsonl            (network)   ├→ normalize → DeniedCandidate
//!   .harness-cow-denied.jsonl  (CoW)       │       ↓ generalize
//!   fs-audit.jsonl             (OS監査)  ─┘   RuleProposal → diff → settings.json差分
//! ```
//!
//! # このクレートが**しない**こと
//!
//! - **設定ファイルへ書かない**（D-42）。差分を値として返すだけで、反映はユーザーの明示操作を
//!   経て`harness-cli`が行う。監査由来の情報が権限付与を自動で駆動すると、監査機構の正しさが
//!   そのまま境界の正しさになってしまう（P-07）。加えて、敵対的な子プロセスは意図的に大量の
//!   パスへ触れて候補リストを汚染できるため、自動適用は「触れば通る」という権限拡大経路になる。
//! - **ファイルを読まない**。入力は常に読み込み済みの文字列で受け取る（純粋性の維持）。
//! - **拒否を防がない**。ここは境界ではない（P-07）。収集源が1つも読めなくても、その事実を
//!   [`SourceReport::available`]で可視化したうえで残りの経路だけで動く（D-43 fail-open）。

pub mod breadth;
pub mod diff;
pub mod event;
pub mod gate;
pub mod generalize;
pub mod insufficient;
pub mod normalize;

pub use breadth::BreadthVerdict;
pub use diff::{SettingsDiff, SettingsDiffEntry};
pub use event::{FsAuditEvent, FsAuditKind};
pub use gate::{check_proposal, GateVerdict};
pub use generalize::{Generalization, RuleProposal, SettingsKey};
pub use insufficient::{diagnose, GrantedPaths, Insufficient};
pub use normalize::{DeniedCandidate, FsFolder, NetIntake, Requested, Source, SourceReport};

/// 4経路ぶんの[`SourceReport`]をまとめた、提案生成の入力一式。
///
/// 「読めなかった経路」も[`SourceReport::available`]`= false`のエントリとして**残す**。
/// 黙って空にすると、収集器が動いていないのか本当に拒否が無かったのかを区別できなくなる
/// ——D-43がfail-openを許すのは「起動を止めない」ことであって、「失敗を隠す」ことではない。
#[derive(Debug, Clone, Default)]
pub struct PolicyInput {
    pub reports: Vec<SourceReport>,
}

impl PolicyInput {
    pub fn new(reports: Vec<SourceReport>) -> Self {
        Self { reports }
    }

    /// 全経路の候補を1本に連結する（順序は`reports`の順、経路内の順序は保持）。
    pub fn candidates(&self) -> Vec<DeniedCandidate> {
        self.reports
            .iter()
            .flat_map(|r| r.candidates.iter().cloned())
            .collect()
    }

    /// 読めなかった経路の一覧（`(source, note)`）。CLIはこれを「収集不能」の明示に使う。
    pub fn unavailable(&self) -> Vec<(Source, String)> {
        self.reports
            .iter()
            .filter(|r| !r.available)
            .map(|r| {
                (
                    r.source,
                    r.notes
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "not available".to_string()),
                )
            })
            .collect()
    }

    /// 収集源をまたいだ提案生成。
    pub fn proposals(&self, generalization: Generalization) -> Vec<RuleProposal> {
        generalize::generalize(&self.candidates(), generalization)
    }

    /// 「既に設定で許可済みのパス」を踏まえた提案生成。
    ///
    /// **既に許可済みなのに拒否された＝その許可では足りない**が確定するので、その旨が提案へ載る
    /// （`plans/etw-spike/RESULTS.md` §15）。`fs.read`を足したのにまだ失敗する、という
    /// いちばん困る状況で「readでは直らない」と言えるようになる。
    pub fn proposals_with_granted(
        &self,
        generalization: Generalization,
        granted: &GrantedPaths,
    ) -> Vec<RuleProposal> {
        generalize::generalize_with_granted(&self.candidates(), generalization, granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 読めなかった経路は「候補ゼロ」に潰れず、`unavailable()`から取り出せる（D-43の可視化）。
    #[test]
    fn unavailable_sources_stay_visible_instead_of_collapsing_to_empty() {
        let input = PolicyInput::new(vec![
            SourceReport::unavailable(Source::Etw, "fs-audit.jsonl not found"),
            SourceReport {
                source: Source::Preflight,
                available: true,
                candidates: vec![DeniedCandidate::fs(
                    Source::Preflight,
                    "C:/Users/me/.cargo",
                    harness_config::FsAccess::Read,
                    "path not reachable",
                    1,
                    0,
                )],
                notes: Vec::new(),
            },
        ]);

        assert_eq!(input.candidates().len(), 1);
        let unavailable = input.unavailable();
        assert_eq!(unavailable.len(), 1);
        assert_eq!(unavailable[0].0, Source::Etw);
        assert!(unavailable[0].1.contains("fs-audit.jsonl"));
    }
}
