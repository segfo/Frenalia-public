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
//!   **例外は[`policy_file`]ただ1つで、名前を挙げて許してある**（2026-09-12、段階6b）。
//!   あれは`policy.json`を読み書きする**唯一の口**で、読む側が
//!   `harness-policy-editor`・`harness-cli`・`harness-sandbox`（Spawn Daemon）の3クレートに
//!   跨るようになったため、両方から見えるここへ置くほかない。**読み書きは`load`/`save`の
//!   2関数に閉じており**、提案エンジン（[`normalize`]・[`generalize`]・[`diff`]・[`gate`]）は
//!   いまも1バイトも読まない——上の(2)「実機・管理者権限なしに全数テストできる」は保たれている。
//! - **拒否を防がない**。ここは境界ではない（P-07）。収集源が1つも読めなくても、その事実を
//!   [`SourceReport::available`]で可視化したうえで残りの経路だけで動く（D-43 fail-open）。

pub mod breadth;
pub mod diff;
pub mod event;
pub mod gate;
pub mod generalize;
pub mod insufficient;
pub mod normalize;
pub mod policy_file;
/// 記録したプロセスの木（`process-audit.jsonl`）の位置ごとに遷移先のドメインを割り当て、ファイル操作を
/// ドメインへ振り分ける（決定65(1)）。**書かない**——辺を`policy.json`へ書くのはポリシーエディタで、
/// 既にある辺は Spawn Daemon と同じ判定器（[`transition::TransitionGraph::resolve`]）で引く。
pub mod position_domains;
/// 記録したプロセスの木（`process-audit.jsonl`）の1行分レコード（決定23）。**書く側は昇格した
/// 収集プロセス、読む側はポリシーエディタ**——[`event`]と同じ理由で定義はここだけに置く。
pub mod process_event;
/// 親子の鍵で組んだ森を、閉路があっても止まって1件も落とさずに親→子の順へ並べる。
/// **pid の木（エディタの古い記録の表示）と通し番号の木（位置ごとのドメインの割り当て）が
/// 同じ辿り方を通る**——2つ書くと片方だけ直る。
pub mod process_tree;
pub mod transition;
/// [段階6e] 「このドメインから、いま何を起こせるか」の一覧（§19.3.8）。**モデルへ答える
/// ツールと、段階⑦のエディタ表示が同じものを使う**——2つ作ると見えるものがずれる。
pub mod transition_listing;

pub use breadth::BreadthVerdict;
pub use diff::{SettingsDiff, SettingsDiffEntry};
pub use event::{FsAuditEvent, FsAuditKind};
pub use gate::{check_proposal, GateVerdict};
pub use generalize::{RuleProposal, SettingsKey};
pub use insufficient::{diagnose, GrantedPaths, Insufficient};
pub use normalize::{
    is_net_control_record, DeniedCandidate, FsFolder, GrantScope, NetIntake, Requested, Source,
    SourceReport,
};
pub use transition::{
    ArgvMatcher, DomainView, EnvOverride, ExeMatcher, GraphInput, TransitionEdge, TransitionGraph,
    TransitionRules,
};

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
    pub fn proposals(&self) -> Vec<RuleProposal> {
        generalize::generalize(&self.candidates())
    }

    /// 「既に設定で許可済みのパス」を踏まえた提案生成。
    ///
    /// **既に許可済みなのに拒否された＝その許可では足りない**が確定するので、その旨が提案へ載る
    /// （`plans/etw-spike/RESULTS.md` §15）。`fs.read`を足したのにまだ失敗する、という
    /// いちばん困る状況で「readでは直らない」と言えるようになる。
    pub fn proposals_with_granted(&self, granted: &GrantedPaths) -> Vec<RuleProposal> {
        generalize::generalize_with_granted(&self.candidates(), granted)
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
