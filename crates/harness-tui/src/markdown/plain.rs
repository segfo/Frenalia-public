//! [`PlainText`]: 原文を1行ずつ、そのまま描く実装（Markdownとして整形しない）。
//!
//! # 何のためにあるのか
//!
//! - **付け替える前のtranscriptと同じ見た目**を、Port（[`StreamingMarkdown`]）越しに出す。整形する実装へ差し替える
//!   前に、使用側の配線だけを画面を変えずに確かめられる
//! - 整形する実装を外したビルドの受け皿になる
//! - Portが特定の解析器の形に寄っていないことを、2つ目の実装として確かめる
//!
//! # 限界
//!
//! - 折り返さない。長い行も1つの`Line`で返し、折り返しは`harness_term::wrap`が受け持つ（だから印は全部`Break`）。
//! - 行の割り方は`str::lines`のまま（`\r\n`も区切り、末尾の改行は空の行を足さない）。空の文章は空の1行にする
//!   （0行にすると、流れ込み始めた返答の場所が画面に無くなる）。

use harness_term::select::LineJoin;
use ratatui::text::Line;

use super::{Rendered, StreamingMarkdown};

#[cfg(test)]
#[path = "plain_tests.rs"]
mod tests;

/// 原文をそのまま描く実装（モジュールdoc）。
#[derive(Debug, Default)]
pub(crate) struct PlainText {
    source: String,
}

impl StreamingMarkdown for PlainText {
    fn push(&mut self, chunk: &str) {
        self.source.push_str(chunk);
    }

    /// 確定させる未確定の部分が無い（足された文章をそのまま描くだけ）。
    fn finish(&mut self) {}

    fn reset(&mut self) {
        self.source.clear();
    }

    /// 幅は使わない（折り返さない。モジュールdocの限界）。
    fn render(&mut self, _width: u16) -> Rendered {
        let mut lines: Vec<Line<'static>> = self
            .source
            .lines()
            .map(|line| Line::from(line.to_string()))
            .collect();
        if self.source.is_empty() {
            lines.push(Line::from(""));
        }
        let joins = vec![LineJoin::Break; lines.len()];
        Rendered { lines, joins }
    }
}
