//! harness-cognition: 認知レイヤー。`plans/DESIGN-COGNITION.md` が設計正本。
//!
//! `harness-engine`（1ステップ＝`RawTurn`）とフロントエンド（`harness-cli`/`harness-tui`）の
//! 間に立ち、**認知の唯一の強制点**として「次に何をするか」を決める層。
//!
//! # 現在の実装範囲（M15）
//!
//! [`CognitiveOrchestrator`]が実行できるのは`CognitionLevel::Off`（素朴ループ）と
//! `Always`（HIVループの**ライト構成**: Hypothesize→Investigate→Distill→Verify→Decide）。
//! `Auto`は難易度ルータ（M17）が無いため[`CognitiveOrchestrator::new`]が拒否する——黙って
//! `Off`へ落とすと「賢く動いているつもりで素朴ループだった」という気付けない劣化になるため、
//! 起動時に明示エラーにする。各段階の実装マイルストーンは`docs/INDEX.md`（M16–M20）。
//!
//! 部品は[`memory`]（構造化台帳と妥当性評価）・[`scratch`]（生出力の退避）・[`context`]
//! （フェーズ別最小コンテキスト組立、M14）・[`source`]（情報源カタログ、M16）と、
//! それらを回す[`hiv`]（状態機械、M15）に分かれている。
//! Orient/Critic/Planner（フル構成）はM19。
//!
//! この層は`LlmProvider`を直接持たず、必ず`harness_engine`の`Executor`／素朴ループを経由する。
//! そのためパーミッション・fsジェイル・サンドボックスの強制点は`harness-engine`側の1箇所に
//! 保たれ、認知層はそれを**バイパスできない**（`plans/DESIGN-COGNITION.md` §1）。

// M15以降で`CognitionLevel`へ段階を足したとき、あるいは既存段階の実装を埋めたときに、
// 分岐の書き漏らしをコンパイルエラーとして検出する（`harness_core::prompt`と同じ手法）。
#![deny(clippy::wildcard_enum_match_arm)]

pub(crate) mod call;
pub mod census;
pub mod context;
pub mod hiv;
pub(crate) mod ledger;
pub mod memory;
pub mod orchestrator;
pub mod phase;
pub mod prompts;
pub mod schema;
pub mod scratch;
pub mod source;

pub use census::tool::CensusTool;
pub use census::{CensusContext, CensusEngine, CensusLimits, CensusOutcome, CensusStop};
pub use context::{AssembledCall, CallKind, ContextAssembler, PhaseInput};
pub use hiv::{HivContext, HivEngine, HivLimits, HivOutcome, HivStop};
pub use memory::validity::{EvidenceStrength, Freshness, Grade, TrustLevel, Validity};
pub use memory::{MemoryView, WorkingMemory};
pub use orchestrator::{CognitiveOrchestrator, UnsupportedLevel};
pub use phase::{PhaseBudgets, PhaseSpec, ToolSelection};
pub use scratch::ScratchStore;
pub use source::{SourceCatalog, SourceEntry};
