//! Recall: ゴールを横断する永続記憶。`plans/PLAN-RECALL-MEMORY.md`が設計正本。
//!
//! `census`と同じく、`harness-tools`ではなく`harness-cognition`に置く（`tool.rs`が内部で
//! `PhaseRunner`／`Phase::Recall`の1コールを回す必要があるため）。
//!
//! # 配置
//!
//! `directories::ProjectDirs::data_dir()`配下`memory/<workspace-key>/`（ワークスペース外）。
//! Tier2a以上ではサンドボックス内から書けないが、**Tier0/Tier1では同一ユーザー権限で書ける**
//! ため、[`git`]モジュールが起動するgitは必ず`harness_core::git::hardening_env`を経由する。

pub mod checkpoint;
mod git;
pub mod judge;
pub mod search;
pub mod store;
pub mod tool;
pub mod write;

pub use checkpoint::{Checkpoint, CheckpointMeta, CheckpointSource};
pub use store::{AppendOutcome, RecallStore, ReviewedWatermark, WorkspaceSummary};

/// checkpoint 1件の表示用1行。CLI（`harness memory list/review`）とTUI（`/memory`）が
/// 共有する（`bug-pattern-rules` B-05: 表示文字列の生成を2実装にすると綴りがずれる）。
pub fn format_checkpoint_line(meta: &CheckpointMeta, reviewed: bool) -> String {
    if reviewed {
        format!("{}: {}", meta.id, meta.summary)
    } else {
        format!("{}: {} (unreviewed)", meta.id, meta.summary)
    }
}
