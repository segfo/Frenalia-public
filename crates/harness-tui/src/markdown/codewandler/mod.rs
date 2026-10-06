//! codewandler（`codewandler-markdown-stream`の解析器と、`codewandler-markdown-ratatui`の描画部品）で
//! Markdownを整形して描く実装の置き場（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4）。
//!
//! # 何のためにあるのか
//!
//! assistantの返答を整形して描く実装（Adapter）を、ここ1か所に閉じ込める。codewandlerは**急場しのぎの依存**で
//! （計画書§1.2・§1.6）、別の実装へ差し替えるときはこのディレクトリを消し、`markdown/mod.rs`の実装の選択と
//! `Cargo.toml`の依存を直すだけで済むようにする。codewandlerの名前がこの外に出ないことは`super::leak_tests`が数える。
//!
//! # 限界
//!
//! - いまはまだAdapterが無い。置いてあるのは、素の描画部品が今どう描くかを固定した試験だけ
//!   （`characterization_tests`。計画書§0のT6）。Adapterは計画書のT8、Facadeからの切り替えはT9。

#[cfg(test)]
#[path = "characterization_tests.rs"]
mod characterization_tests;
