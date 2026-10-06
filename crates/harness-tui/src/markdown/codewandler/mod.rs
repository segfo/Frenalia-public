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
//! | `render` | 写した描画部品（`codewandler-markdown-ratatui` 0.2.1。出典とライセンス表記はファイルの冒頭）。直すのは計画書のT7 |
//!
//! # 限界
//!
//! - いまはまだAdapterが無い（計画書のT8）。Facadeからの切り替えはT9で、それまで製品はこの実装を使わない。
//! - 写した描画部品は、**写した時点では元と1文字も違わない**ことだけを確かめてある（`equivalence_tests`）。
//!   既知の不具合も元のまま持っている（`characterization_tests`のモジュールdoc）。

/// 写した描画部品（モジュールdoc）。
///
/// **製品からの呼び出しはまだ無い**——呼ぶのはAdapter（計画書のT8）で、Facadeがこの実装へ切り替わるのはT9。
/// それまでは試験（`equivalence_tests`）だけが使うので、試験でないビルドの「使われていない」の警告を止める
/// （`super::MarkdownView::reset`と同じ扱い）。T8でAdapterから呼んだら、この`allow`を外す。
#[cfg_attr(not(test), allow(dead_code))]
mod render;

#[cfg(test)]
#[path = "characterization_tests.rs"]
mod characterization_tests;
#[cfg(test)]
#[path = "equivalence_tests.rs"]
mod equivalence_tests;
