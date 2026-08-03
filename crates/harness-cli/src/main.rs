//! harness-cli: binターゲットのエントリポイント。
//!
//! 実体は`harness_cli::cli`（clap定義・起動パイプライン・各サブコマンド）にある。
//! ここは`#[tokio::main]`を張って`run()`を呼ぶだけに保つ——binの中のコードは
//! `tests/`から到達できないため、テストしたいものはlib側に置く
//! （`docs/CODE-STRUCTURE-RULES.md`規則4、`harness-cli`はワークスペースの終端クレートで
//! 誰にも依存されていないので公開面を広げるコストが無い）。

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    harness_cli::cli::run().await
}
