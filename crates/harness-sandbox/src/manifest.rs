//! 操作種別の再エクスポート。CoW一本化（Phase 2）以降、変更マニフェストの実体は
//! `overlay.rs`が`harness_change_ledger::store`を通じて扱う操作台帳（`.harness-cow-ops.jsonl`）
//! そのものであり、このクレート独自の`ManifestEntry`/`ManifestTarget`型はもう存在しない。
//!
//! `ManifestOp`という名前は既存呼び出し側（`win_appcontainer.rs`のテスト等）との差分を
//! 最小化するために残してあるが、実体は`harness_change_ledger::ChangeOp`そのものである。

pub use harness_change_ledger::ChangeOp as ManifestOp;
