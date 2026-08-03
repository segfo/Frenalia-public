//! harness-cognition: 認知レイヤー。`plans/DESIGN-COGNITION.md` が設計正本。
//!
//! `harness-engine`（1ステップ＝`RawTurn`）とフロントエンド（`harness-cli`/`harness-tui`）の
//! 間に立ち、**認知の唯一の強制点**として「次に何をするか」を決める層。
//!
//! # 現在の実装範囲（M13）
//!
//! [`CognitiveOrchestrator`]は`CognitionLevel::Off`（素朴ループ）だけを実行できる。
//! `Auto`/`Always`は[`CognitiveOrchestrator::new`]が拒否する——黙って`Off`へ落とすと
//! 「賢く動いているつもりで素朴ループだった」という気付けない劣化になるため、
//! 起動時に明示エラーにする。各段階の実装マイルストーンは`docs/INDEX.md`（M14–M20）。
//!
//! この層は`LlmProvider`を直接持たず、必ず`harness_engine`の`Executor`／素朴ループを経由する。
//! そのためパーミッション・fsジェイル・サンドボックスの強制点は`harness-engine`側の1箇所に
//! 保たれ、認知層はそれを**バイパスできない**（`plans/DESIGN-COGNITION.md` §1）。

// M14以降で`CognitionLevel`へ段階を足したとき、あるいは既存段階の実装を埋めたときに、
// 分岐の書き漏らしをコンパイルエラーとして検出する（`harness_core::prompt`と同じ手法）。
#![deny(clippy::wildcard_enum_match_arm)]

pub mod orchestrator;

pub use orchestrator::{CognitiveOrchestrator, UnsupportedLevel};
