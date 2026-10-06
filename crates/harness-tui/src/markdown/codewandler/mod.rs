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
//! | `render` | 写した描画部品（`codewandler-markdown-ratatui` 0.2.1。出典とライセンス表記と、写した後に変えたものの一覧はファイルの冒頭）。行を幅に合わせて分けるところは計画書のT7aで直した（`render/wrap.rs`）。構造の不具合（入れ子のリスト・リストの中のブロック・タスクリスト・HTMLブロック・コードの字下げ）とリンクの区間はT7bで直した |
//!
//! # 限界
//!
//! - いまはまだAdapterが無い（計画書のT8）。Facadeからの切り替えはT9で、それまで製品はこの実装を使わない。
//! - 写した描画部品は、**元の出力が幅に左右されず、T7bで直した構造を含まない入力では、今も元と1文字も違わない**
//!   （`equivalence_tests`）。行の分け方（`wrap_tests`）・構造（`characterization_tests`・`structure_tests`）・
//!   リンクの区間（`link_tests`）はそれぞれの試験が固定する。
//! - 画像は、代わりの文字（alt）をリンクと同じ書式で描くが、リンクの区間は返さない（`link_tests`のモジュールdoc）。

/// 写した描画部品（モジュールdoc）。
///
/// **製品からの呼び出しはまだ無い**——呼ぶのはAdapter（計画書のT8）で、Facadeがこの実装へ切り替わるのはT9。
/// それまでは試験（`characterization_tests`・`equivalence_tests`・`link_tests`・`structure_tests`・`wrap_tests`）
/// だけが使うので、試験でないビルドの「使われていない」の警告を止める（`super::MarkdownView::reset`と同じ扱い）。
/// T8でAdapterから呼んだら、この`allow`を外す。
#[cfg_attr(not(test), allow(dead_code))]
mod render;

#[cfg(test)]
#[path = "characterization_tests.rs"]
mod characterization_tests;
#[cfg(test)]
#[path = "equivalence_tests.rs"]
mod equivalence_tests;
#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
#[cfg(test)]
#[path = "structure_tests.rs"]
mod structure_tests;
#[cfg(test)]
#[path = "wrap_tests.rs"]
mod wrap_tests;
