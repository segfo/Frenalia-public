// =================================================================================================
// 出典: crates.io の `codewandler-markdown-ratatui` 0.2.1 の `src/theme.rs`
//   リポジトリ: https://github.com/codewandler/markdown （`crates/markdown-ratatui/src/theme.rs`）
//   コミット: acbe68d0ffcb853ed4f01cf5a3bc8967489378c7（crates.io の版と1バイトも違わないことを、写したときに確かめた）
// ライセンス: 上流は `MIT OR Apache-2.0`。ここでは MIT を選び、上流の `LICENSE-MIT`（同じコミット）の表記を
//   そのまま下に置く。crates.io のパッケージにはライセンスの文書が入っていないので、リポジトリから取った。
//
// Copyright (c) 2026 The markdown authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// =================================================================================================
// 【harness側の注記】
// - これは上流のソースの**写し**（vendored copy）である。依存として使わずに写したのは、直したい箇所が
//   あっても上流に差し込み口が無く、作者は更新を止めて後継へ移ったため（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.3）。
// - 写したときに変えたのは次の2つだけ。写した直後の出力が元と同じことは`markdown/codewandler/equivalence_tests.rs`が確かめる。
//   (1) この冒頭の表記を足した
//   (2) `pub`を`pub(crate)`にした（harness-tuiの外へ出さないため。`docs/CODE-STRUCTURE-RULES.md`規則4）
// - 計画書のT7で、ここに手を入れる（全角文字の間での折り返し・入れ子のリスト等。計画書§1.5）。
// - **暫定の部品である**（計画書§1.6）。別の実装がPortの契約試験を通ったら、`markdown/codewandler/`ごと消す。
// =================================================================================================

//! Terminal themes for the ratatui renderer: named roles mapped to `ratatui::style::Style`. Mirrors
//! the ANSI defaults of `markdown-terminal::Theme` so the two renderers look the same.

use ratatui::style::{Color, Modifier, Style};

/// A theme — the `Style` for each rendered role. `Style::default()` (an empty style) disables a role.
#[derive(Debug, Clone)]
pub(crate) struct Theme {
    pub(crate) heading: Style,
    pub(crate) code: Style,
    pub(crate) link: Style,
    pub(crate) muted: Style,
    pub(crate) bold: Style,
    pub(crate) italic: Style,
    pub(crate) strike: Style,
    // syntax-highlighting roles for fenced code (reserved; v1 renders code uniformly)
    pub(crate) kw: Style,
    pub(crate) str: Style,
    pub(crate) comment: Style,
    pub(crate) num: Style,
}

impl Default for Theme {
    /// A dark-terminal default matching `markdown-terminal::Theme::default()`.
    fn default() -> Self {
        Theme {
            heading: Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD), // 1;36
            code: Style::new().fg(Color::Indexed(180)),                         // 38;5;180
            link: Style::new()
                .fg(Color::Blue)
                .add_modifier(Modifier::UNDERLINED), // 4;34
            muted: Style::new().add_modifier(Modifier::DIM),                    // 2
            bold: Style::new().add_modifier(Modifier::BOLD),                    // 1
            italic: Style::new().add_modifier(Modifier::ITALIC),                // 3
            strike: Style::new().add_modifier(Modifier::CROSSED_OUT),           // 9
            kw: Style::new().fg(Color::Magenta),                                // 35
            str: Style::new().fg(Color::Green),                                 // 32
            comment: Style::new().fg(Color::DarkGray),                          // 90 (bright black)
            num: Style::new().fg(Color::Yellow),                                // 33
        }
    }
}

impl Theme {
    /// A theme that applies no styling (every role is the empty `Style`).
    pub(crate) fn no_color() -> Self {
        let s = Style::new();
        Theme {
            heading: s,
            code: s,
            link: s,
            muted: s,
            bold: s,
            italic: s,
            strike: s,
            kw: s,
            str: s,
            comment: s,
            num: s,
        }
    }
}
