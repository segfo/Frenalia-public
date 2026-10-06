// =================================================================================================
// 出典: crates.io の `codewandler-markdown-ratatui` 0.2.1 の `src/lib.rs`
//   リポジトリ: https://github.com/codewandler/markdown （`crates/markdown-ratatui/src/lib.rs`）
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
// - 写したとき（計画書のT6）に変えたのは次の2つだけ。
//   (1) この冒頭の表記を足した
//   (2) `pub`を`pub(crate)`にした（harness-tuiの外へ出さないため。`docs/CODE-STRUCTURE-RULES.md`規則4）
//   ファイルの名前は`lib.rs`→`render.rs`（モジュールとして置くため）。中の`mod theme;`は`render/theme.rs`を指す。
// - 計画書のT7aで、**行を幅に合わせて分けるところ**を直した（計画書§1.5の1と7）。直した箇所には`【harness】`と書いた。
//   (3) 行と並べて、行ごとの前の行とのつながり（`harness_term::select::LineJoin`）を返す口`render_lines`を足した
//       （`render_with`はその行だけを返す）。行と印は`render/wrap.rs`の`Sink`へ必ず対で積む
//   (4) 段落と見出しの分け方を`render/wrap.rs`の`fill`へ置き換えた（全角文字の間・幅を超える語の文字の間でも分ける／
//       英語の語の間で分けた所の空白を前の行の末尾に残す／分けた続きの行に`Continues { indent }`を付ける）。
//       `render/wrap.rs`は上流に無い、harnessで書いたファイル
//   (5) 幅の下限20（`width.max(20)`と、字下げの後ろの幅の`max(20)`）をやめた
//   (6) コードの行と表の行を、幅を超えたら文字の間で切って続きの行へ送る（`render/wrap.rs`の`push_cut`）
//   (7) 区切り線の長さを、字下げの後ろに残る幅（最大60桁）にした（上流は字下げを引かず、引用の中で幅を超えた）
//   元の出力が幅に左右されない入力では、今も元と1つも違わない（`super::equivalence_tests`が確かめる）。
// - 計画書のT7bで、構造の不具合（入れ子のリスト・タスクリスト・HTMLブロック・コードの2桁の字下げ）とリンクを直す。
// - **暫定の部品である**（計画書§1.6）。別の実装がPortの契約試験を通ったら、`markdown/codewandler/`ごと消す。
// =================================================================================================

//! `markdown-ratatui` — render a [`markdown_stream`] event stream to `ratatui::text::Text`.
//!
//! A sibling of `markdown-terminal`: it walks the same parser events and does the same width-aware
//! wrapping, list/blockquote indentation, and inline styling — but emits `ratatui` `Line`/`Span`
//! directly (styled with `ratatui::style::Style`) instead of ANSI. That lets a TUI render Markdown
//! natively, with no ANSI round-trip. Output is pre-wrapped to the given width with list hanging
//! indents baked in, so render it WITHOUT a wrapping `Paragraph` (or keep wrap only as a safety net;
//! never `trim`, it would eat the hanging indents).

#![forbid(unsafe_code)]

use harness_term::select::LineJoin;
use markdown_stream::{Alignment, BlockKind, Event, InlineStyle};
use ratatui::style::Style;
use ratatui::text::{Span, Text};
use unicode_width::UnicodeWidthStr;

use crate::markdown::Rendered;

mod theme;
mod wrap;
pub(crate) use theme::Theme;
use wrap::{Sink, Token};

/// Render a complete event stream with the default theme and width 80.
pub(crate) fn render(events: &[Event]) -> Text<'static> {
    render_with(events, &Theme::default(), 80)
}

/// Render a complete event stream with an explicit theme and wrap width.
///
/// 【harness】行だけを返す（[`render_lines`]の`lines`）。続きの行の印が要る使い道（Adapter。計画書のT8）は
/// [`render_lines`]を使う。
pub(crate) fn render_with(events: &[Event], theme: &Theme, width: usize) -> Text<'static> {
    Text::from(render_lines(events, theme, width).lines)
}

/// 【harness】`width`桁で描いた行と、行ごとの前の行とのつながり（`LineJoin`）。描画部品が幅に合わせて自分で分けた
/// 続きの行は`Continues { indent }`、それ以外は`Break`（`render/wrap.rs`のモジュールdoc）。
///
/// どの行も`width`桁を超えない。例外は、字下げの後に1文字も入らないほど狭い幅だけ（同じく`render/wrap.rs`）。
pub(crate) fn render_lines(events: &[Event], theme: &Theme, width: usize) -> Rendered {
    let mut r = Renderer::new(theme.clone(), width);
    r.feed(events);
    r.finish()
}

struct Renderer {
    theme: Theme,
    width: usize,
    /// nesting prefixes (one per open blockquote / list level)
    prefixes: Vec<Prefix>,
    list_stack: Vec<ListCtx>,
    /// accumulated styled segments for the current paragraph/heading/table cell
    segments: Vec<(String, InlineStyle)>,
    in_code: bool,
    table: Option<TableBuf>,
    /// blank line owed before the next block
    pending_gap: bool,
    wrote_any: bool,
    /// spans of the physical line currently being built
    cur: Vec<Span<'static>>,
    /// 【harness】出した行と、行ごとの前の行とのつながり（上流の`lines`を置き換えた。必ず対で積む）
    out: Sink,
}

struct ListCtx {
    ordered: bool,
    next: u64,
}

/// A nesting prefix: `first` (text + style) is printed on the first line a level appears on (a list
/// marker like `1. `), `cont` on continuation/wrapped lines (blanks of equal width for list markers;
/// the `│ ` bar repeats for blockquotes). `emitted` flips after `first` is used once.
struct Prefix {
    first: (String, Style),
    cont: (String, Style),
    emitted: bool,
}

impl Prefix {
    fn repeating(text: String, style: Style) -> Self {
        Prefix {
            first: (text.clone(), style),
            cont: (text, style),
            emitted: false,
        }
    }

    fn marker(marker: String) -> Self {
        let pad = " ".repeat(UnicodeWidthStr::width(marker.as_str()));
        Prefix {
            first: (marker, Style::default()),
            cont: (pad, Style::default()),
            emitted: false,
        }
    }
}

/// A buffered table cell: its rendered spans plus their visible width (for column sizing).
type Cell = (Vec<Span<'static>>, usize);

struct TableBuf {
    aligns: Vec<Alignment>,
    rows: Vec<Vec<Cell>>,
    cur_row: Vec<Cell>,
}

impl Renderer {
    fn new(theme: Theme, width: usize) -> Self {
        Renderer {
            theme,
            // 【harness】上流は`width.max(20)`で20桁未満にしなかった。渡された幅を守る（T7a）。
            width,
            prefixes: Vec::new(),
            list_stack: Vec::new(),
            segments: Vec::new(),
            in_code: false,
            table: None,
            pending_gap: false,
            wrote_any: false,
            cur: Vec::new(),
            out: Sink::default(),
        }
    }

    fn feed(&mut self, events: &[Event]) {
        for ev in events {
            self.event(ev);
        }
    }

    fn finish(mut self) -> Rendered {
        if !self.cur.is_empty() {
            self.newline();
        }
        self.out.finish()
    }

    /// Push the in-progress spans as a finished line.
    fn newline(&mut self) {
        let spans = std::mem::take(&mut self.cur);
        self.out.push(spans, LineJoin::Break);
        self.wrote_any = true;
    }

    /// 【harness】`prefix`の後ろに`body`を置いた1行を出す。幅を超えたら文字の間で切って続きの行へ送る（コードの行と
    /// 表の行。`wrap::push_cut`）。
    fn emit_cut(&mut self, prefix: Vec<Span<'static>>, body: Vec<Span<'static>>) {
        wrap::push_cut(&mut self.out, prefix, body, self.width);
        self.wrote_any = true;
    }

    /// Emit an owed blank line before a block.
    fn gap(&mut self) {
        if self.pending_gap && self.wrote_any {
            self.out.push(Vec::new(), LineJoin::Break);
        }
        self.pending_gap = false;
    }

    /// Prefix spans for the first line of a block (consumes each level's marker once), plus width.
    fn indent_first_spans(&mut self) -> (Vec<Span<'static>>, usize) {
        let mut spans = Vec::new();
        let mut w = 0;
        for p in &mut self.prefixes {
            let seg = if p.emitted {
                &p.cont
            } else {
                p.emitted = true;
                &p.first
            };
            w += UnicodeWidthStr::width(seg.0.as_str());
            spans.push(Span::styled(seg.0.clone(), seg.1));
        }
        (spans, w)
    }

    /// Prefix spans for continuation/wrapped lines (markers become blanks), plus width.
    fn indent_cont_spans(&self) -> (Vec<Span<'static>>, usize) {
        let mut spans = Vec::new();
        let mut w = 0;
        for p in &self.prefixes {
            w += UnicodeWidthStr::width(p.cont.0.as_str());
            spans.push(Span::styled(p.cont.0.clone(), p.cont.1));
        }
        (spans, w)
    }

    /// Compose a `Style` from an inline style and an optional block base (e.g. heading).
    fn style_for(&self, inline: &InlineStyle, base: Option<Style>) -> Style {
        let mut s = base.unwrap_or_default();
        if inline.strong {
            s = s.patch(self.theme.bold);
        }
        if inline.emphasis {
            s = s.patch(self.theme.italic);
        }
        if inline.strikethrough {
            s = s.patch(self.theme.strike);
        }
        if inline.code {
            s = s.patch(self.theme.code);
        }
        if inline.link.is_some() {
            s = s.patch(self.theme.link);
        }
        s
    }

    fn event(&mut self, ev: &Event) {
        match ev {
            Event::EnterBlock { block, data, .. } => match block {
                BlockKind::BlockQuote => {
                    self.gap();
                    let muted = self.theme.muted;
                    self.prefixes
                        .push(Prefix::repeating("│ ".to_string(), muted));
                }
                BlockKind::List => {
                    self.gap();
                    self.list_stack.push(ListCtx {
                        ordered: data.list.as_ref().is_some_and(|l| l.ordered),
                        next: data.list.as_ref().map(|l| l.start).unwrap_or(1),
                    });
                }
                BlockKind::ListItem => {
                    let marker = match self.list_stack.last_mut() {
                        Some(l) if l.ordered => {
                            let n = l.next;
                            l.next += 1;
                            format!("{n}. ")
                        }
                        _ => "• ".to_string(),
                    };
                    self.prefixes.push(Prefix::marker(marker));
                }
                BlockKind::FencedCode | BlockKind::IndentedCode => {
                    self.gap();
                    self.in_code = true;
                }
                BlockKind::Table => {
                    self.gap();
                    self.table = Some(TableBuf {
                        aligns: data.alignment.clone(),
                        rows: Vec::new(),
                        cur_row: Vec::new(),
                    });
                }
                BlockKind::TableRow => {
                    if let Some(t) = &mut self.table {
                        t.cur_row.clear();
                    }
                }
                BlockKind::TableCell => self.segments.clear(),
                _ => {}
            },
            Event::ExitBlock { block, .. } => match block {
                BlockKind::Paragraph => {
                    self.flush_segments(None);
                    self.pending_gap = true;
                }
                BlockKind::Heading => {
                    let base = self.theme.heading;
                    self.flush_segments(Some(base));
                    self.pending_gap = true;
                }
                BlockKind::BlockQuote => {
                    self.prefixes.pop();
                    self.pending_gap = true;
                }
                BlockKind::List => {
                    self.list_stack.pop();
                    self.pending_gap = true;
                }
                BlockKind::ListItem => {
                    if !self.segments.is_empty() {
                        self.flush_segments(None);
                    }
                    self.prefixes.pop();
                }
                BlockKind::ThematicBreak => {
                    self.gap();
                    self.thematic_break();
                    self.pending_gap = true;
                }
                BlockKind::FencedCode | BlockKind::IndentedCode => {
                    self.in_code = false;
                    self.pending_gap = true;
                }
                BlockKind::TableCell => {
                    let cell = self.take_cell();
                    if let Some(t) = &mut self.table {
                        t.cur_row.push(cell);
                    }
                }
                BlockKind::TableRow => {
                    if let Some(t) = &mut self.table {
                        let row = std::mem::take(&mut t.cur_row);
                        t.rows.push(row);
                    }
                }
                BlockKind::Table => self.render_table(),
                _ => {}
            },
            Event::Text { text, style, .. } => {
                if self.in_code {
                    self.write_code_line(text);
                } else {
                    self.segments.push((text.clone(), style.clone()));
                }
            }
            // Inline nesting is already baked into each Text event's `InlineStyle`.
            Event::EnterInline { .. } | Event::ExitInline { .. } => {}
            Event::SoftBreak => {
                if !self.in_code {
                    self.segments
                        .push((" ".to_string(), InlineStyle::default()));
                }
            }
            Event::LineBreak => {
                if !self.in_code {
                    self.segments
                        .push(("\n".to_string(), InlineStyle::default()));
                }
            }
        }
    }

    /// Render the accumulated inline segments as wrapped, styled, indented lines.
    ///
    /// 【harness】行の分け方は`wrap::fill`へ置き換えた（T7a）。上流はASCIIの空白でしか分けず（日本語の段落は幅を
    /// 超えたまま1行で出た）、字下げの後ろの幅を`max(20)`で20桁未満にしなかった。語の区切り（`atoms`）と、語ごとの
    /// 書式（`style_for`）は上流のまま。
    fn flush_segments(&mut self, base: Option<Style>) {
        if self.segments.is_empty() {
            return;
        }
        self.gap();
        let segments = std::mem::take(&mut self.segments);
        let (cont_spans, _) = self.indent_cont_spans();
        let (first_spans, _) = self.indent_first_spans();
        let mut first = std::mem::take(&mut self.cur);
        first.extend(first_spans);

        let mut tokens = Vec::new();
        for (raw, style) in &segments {
            let st = self.style_for(style, base);
            tokens.extend(atoms(raw).into_iter().map(|atom| match atom {
                Atom::Word(word) => Token::Word(word, st),
                Atom::Space => Token::Space,
                Atom::Hard => Token::Hard,
            }));
        }
        wrap::fill(&mut self.out, first, &cont_spans, self.width, &tokens);
        self.wrote_any = true;
    }

    /// Render one fenced/indented code line (uniform code color; no syntax highlighting in v1).
    ///
    /// 【harness】幅を超える行は文字の間で切り、続きの行にも同じ字下げ（入れ子の字下げ＋コードの2桁）を付ける（T7a。
    /// `wrap::push_cut`）。上流は切らずに幅を超えたまま出した。上流は改行で終わらない断片を次の文字とつなげる形
    /// だったが、解析器はコードの文字を必ず改行で終えて渡す（`markdown_stream`の`block.rs`）ので、断片を1行として扱う。
    fn write_code_line(&mut self, text: &str) {
        self.gap();
        for piece in text.split_inclusive('\n') {
            let body = piece.strip_suffix('\n').unwrap_or(piece);
            let (mut prefix, _) = self.indent_cont_spans();
            prefix.push(Span::raw("  "));
            let body = vec![Span::styled(body.to_string(), self.theme.code)];
            self.emit_cut(prefix, body);
        }
    }

    fn thematic_break(&mut self) {
        let (ind, ind_w) = self.indent_cont_spans();
        self.cur.extend(ind);
        // 【harness】上流は字下げを引かない`width.min(60)`で、引用の中では幅を超えた。字下げの後ろに残る幅で引く（T7a。
        // 狭すぎて0桁なら1桁——何も描けない形にはしない）。
        let rule = "─".repeat(self.width.saturating_sub(ind_w).clamp(1, 60));
        self.cur.push(Span::styled(rule, self.theme.muted));
        self.newline();
    }

    /// Build a table cell's spans + visible width from the accumulated segments.
    fn take_cell(&mut self) -> Cell {
        let segs = std::mem::take(&mut self.segments);
        let mut spans = Vec::new();
        let mut w = 0;
        for (text, style) in &segs {
            let t = text.replace('\n', " ");
            w += UnicodeWidthStr::width(t.as_str());
            let st = self.style_for(style, None);
            spans.push(Span::styled(t, st));
        }
        (spans, w)
    }

    /// Render a buffered table: column widths, box-drawing borders, aligned cells.
    fn render_table(&mut self) {
        let Some(t) = self.table.take() else {
            return;
        };
        self.gap();
        let ncol = t
            .aligns
            .len()
            .max(t.rows.iter().map(Vec::len).max().unwrap_or(0));
        let mut widths = vec![0usize; ncol];
        for row in &t.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.1);
            }
        }
        let muted = self.theme.muted;
        let empty: Cell = (Vec::new(), 0);
        // 【harness】行は`emit_cut`で出す——幅を超えたら文字の間で切り、続きの行には入れ子の字下げだけを付ける（T7a）。
        // 上流は切らずに幅を超えたまま出した。組み立てる中身は上流のまま。
        for (ri, row) in t.rows.iter().enumerate() {
            let (ind, _) = self.indent_cont_spans();
            let mut body = vec![Span::styled("│ ".to_string(), muted)];
            for (i, width) in widths.iter().enumerate() {
                let cell = row.get(i).unwrap_or(&empty);
                let pad = width.saturating_sub(cell.1);
                match t.aligns.get(i).copied().unwrap_or(Alignment::None) {
                    Alignment::Right => {
                        body.push(Span::raw(" ".repeat(pad)));
                        body.extend(cell.0.clone());
                    }
                    Alignment::Center => {
                        let l = pad / 2;
                        body.push(Span::raw(" ".repeat(l)));
                        body.extend(cell.0.clone());
                        body.push(Span::raw(" ".repeat(pad - l)));
                    }
                    _ => {
                        body.extend(cell.0.clone());
                        body.push(Span::raw(" ".repeat(pad)));
                    }
                }
                body.push(Span::styled(" │ ".to_string(), muted));
            }
            self.emit_cut(ind, body);
            if ri == 0 {
                let (ind2, _) = self.indent_cont_spans();
                let mut body = vec![Span::styled("├".to_string(), muted)];
                for (i, width) in widths.iter().enumerate() {
                    body.push(Span::styled("─".repeat(width + 2), muted));
                    let joint = if i + 1 < ncol { "┼" } else { "┤" };
                    body.push(Span::styled(joint.to_string(), muted));
                }
                self.emit_cut(ind2, body);
            }
        }
        self.pending_gap = true;
    }
}

/// A wrapping atom: a word, a space between words, or a hard line break.
enum Atom<'a> {
    Word(&'a str),
    Space,
    Hard,
}

/// Split a string into wrap atoms — words, spaces, and hard breaks — preserving exactly where
/// spaces did and didn't exist (adjacent styled runs must not gain a space).
fn atoms(s: &str) -> Vec<Atom<'_>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let (mut start, mut i) = (0usize, 0usize);
    while i < b.len() {
        match b[i] {
            b'\n' => {
                if start < i {
                    out.push(Atom::Word(&s[start..i]));
                }
                out.push(Atom::Hard);
                i += 1;
                start = i;
            }
            b' ' | b'\t' => {
                if start < i {
                    out.push(Atom::Word(&s[start..i]));
                }
                out.push(Atom::Space);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < s.len() {
        out.push(Atom::Word(&s[start..]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{render_with, Theme};
    use markdown_stream::parse;

    /// Render to plain per-line strings (joined span text), ignoring style.
    fn lines(src: &str, width: usize) -> Vec<String> {
        let text = render_with(&parse(src), &Theme::no_color(), width);
        text.lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn wrapped_list_item_shows_marker_once_then_aligns() {
        let ls = lines("- alpha beta gamma delta epsilon zeta eta theta iota\n", 24);
        let body: Vec<&String> = ls.iter().filter(|l| !l.trim().is_empty()).collect();
        assert!(body.len() > 1, "input should wrap: {ls:?}");
        assert!(
            body[0].starts_with("• "),
            "marker on first line: {:?}",
            body[0]
        );
        for l in &body[1..] {
            assert!(!l.starts_with("• "), "marker repeated on wrap: {l:?}");
            assert!(
                l.starts_with("  ") && !l.trim_start().is_empty(),
                "continuation should be space-aligned: {l:?}"
            );
        }
    }

    #[test]
    fn loose_list_item_has_no_bare_marker_line() {
        let src = "1. first item that is quite long and certainly wraps\n\n\
                   2. second item that is also long enough to wrap as well\n";
        let ls = lines(src, 24);
        for l in &ls {
            let t = l.trim_end();
            assert!(t != "1." && t != "2.", "bare marker line in {ls:?}");
        }
        assert_eq!(
            ls.iter().filter(|l| l.starts_with("1. ")).count(),
            1,
            "{ls:?}"
        );
        assert_eq!(
            ls.iter().filter(|l| l.starts_with("2. ")).count(),
            1,
            "{ls:?}"
        );
    }

    #[test]
    fn heading_span_carries_style() {
        let text = render_with(&parse("# Title\n"), &Theme::default(), 40);
        let span = &text.lines[0].spans[0];
        assert!(span.content.contains("Title"));
        assert!(span
            .style
            .add_modifier
            .contains(ratatui::style::Modifier::BOLD));
    }
}
