//! codewandler（`codewandler-markdown-stream`の解析器と、`codewandler-markdown-ratatui`の描画部品）で
//! Markdownを整形して描く実装の置き場（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4）。
//!
//! # 何のためにあるのか
//!
//! assistantの返答を整形して描く実装（Adapter）を、ここ1か所に閉じ込める。codewandlerは**急場しのぎの依存**で
//! （計画書§1.2・§1.6）、別の実装へ差し替えるときはこのディレクトリを消し、`markdown/mod.rs`の実装の選択と
//! `Cargo.toml`の依存を直すだけで済むようにする。codewandlerの名前がこの外に出ないことは`super::leak_tests`が数える。
//!
//! | 部品 | 役割 |
//! |---|---|
//! | `render` | 写した描画部品（`codewandler-markdown-ratatui` 0.2.1。出典とライセンス表記と、写した後に変えたものの一覧はファイルの冒頭）。行を幅に合わせて分けるところは計画書のT7aで直した（`render/wrap.rs`）。構造の不具合とリンクはT7b |
//!
//! # 限界
//!
//! - いまはまだAdapterが無い（計画書のT8）。Facadeからの切り替えはT9で、それまで製品はこの実装を使わない。
//! - 写した描画部品は、**元の出力が幅に左右されない入力では、今も元と1文字も違わない**（`equivalence_tests`）。
//!   幅に合わせて行を分けるところだけを直してあり（`wrap_tests`）、構造の既知の不具合は元のまま持っている
//!   （`characterization_tests`のモジュールdoc）。

/// 写した描画部品（モジュールdoc）。
///
/// **製品からの呼び出しはまだ無い**——呼ぶのはAdapter（計画書のT8）で、Facadeがこの実装へ切り替わるのはT9。
/// それまでは試験（`characterization_tests`・`equivalence_tests`・`wrap_tests`）だけが使うので、試験でないビルドの
/// 「使われていない」の警告を止める（`super::MarkdownView::reset`と同じ扱い）。T8でAdapterから呼んだら、この`allow`を外す。
#[cfg_attr(not(test), allow(dead_code))]
mod render;

#[cfg(test)]
#[path = "characterization_tests.rs"]
mod characterization_tests;
#[cfg(test)]
#[path = "equivalence_tests.rs"]
mod equivalence_tests;
#[cfg(test)]
#[path = "wrap_tests.rs"]
mod wrap_tests;
