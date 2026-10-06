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
//   T7aの時点では、元の出力が幅に左右されない入力で元と1つも違わなかった（`super::equivalence_tests`が確かめた）。
// - 計画書のT7bで、**構造の不具合とリンク**を直した（計画書§1.5の2〜6）。直した箇所には`【harness】`と書いた。
//   (8) 開いている入れ物（リスト・項目・引用）の並びを持ち、詰めたリストの項目の本文を、中のブロック（入れ子の
//       リスト・コード等）より先に出す。項目の記号は、その項目の最初の行に1回だけ出す（最初の行がコード・表・
//       区切り線・HTMLでも）。中身の無い項目は記号だけの行にする。詰めたリストの項目の中のブロックの間に空行を入れない
//   (9) 解析器がリストの中（最後の項目の後）へ出したブロック（リスト直後の引用）を、リストの後ろのブロックとして描く
//   (10) GFMのタスクリストの印（解析器が出すHTMLの文字）を、項目の記号の後ろの`[ ] `／`[x] `にする
//   (11) HTMLブロックを落とさず、中の文字を1行ずつ薄い書式（`muted`）で出し、前後を空行で分ける。解析器が閉じずに
//        次のブロックを始めたHTMLブロックも、そこで閉じたものとして扱う
//   (12) コードブロックの2桁の字下げを外した。コードとHTMLの行のタブを空白にする（`render/wrap.rs`の`expand_tabs`）
//   (13) リンクの文字の場所とURLを`Rendered::links`で返す（`render/wrap.rs`の`Sink`）。リンクの書式は上流のまま
//        青の下線で、文中にURLは出さない。画像は区間を返さない（代わりの文字の描き方は上流のまま）
//   段落の末尾のハードな改行を捨てるのは`render/wrap.rs`の`fill`。
//   T7bで直した構造を含まない入力では、今も元と1つも違わない（`super::equivalence_tests`が確かめる）。
// - 計画書のT8で、既に何か描いた文書の続きとして描く口`render_lines_following`と、描いた結果をつなぐ口`append`を
//   足した（上流に無い）。Adapter（`super::CodewandlerMarkdown`）が、確定した塊と書きかけの末尾を別々に解析して描くため。
//   あわせて、製品が使わない口（`render`・`render_with`・`render_lines`・`Theme::no_color`・構文の色付け用に予約された
//   書式の役割）に、試験でないビルドの「使われていない」の警告を止める印を付けた（それまではモジュール全体に付けていた）。
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
use markdown_stream::{Alignment, BlockData, BlockKind, Event, Inline, InlineStyle};
use ratatui::style::Style;
use ratatui::text::{Span, Text};
use unicode_width::UnicodeWidthStr;

use crate::markdown::{LinkSpan, Rendered};

mod theme;
mod wrap;
pub(crate) use theme::Theme;
use wrap::{Piece, Sink, Token};

/// Render a complete event stream with the default theme and width 80.
///
/// 【harness】**製品は使わない**——試験だけが使う（T8の時点。Adapterは[`render_lines_following`]を使う）。
/// 試験でないビルドの「使われていない」の警告を止める（`crate::markdown::MarkdownView::reset`と同じ扱い）。
/// 製品が使い始めたら外す。
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn render(events: &[Event]) -> Text<'static> {
    render_with(events, &Theme::default(), 80)
}

/// Render a complete event stream with an explicit theme and wrap width.
///
/// 【harness】行だけを返す（[`render_lines`]の`lines`）。続きの行の印とリンクの区間が要る使い道（Adapter。
/// 計画書のT8）は[`render_lines_following`]を使う。
///
/// 【harness】**製品は使わない**——試験だけが使う（T8の時点。Adapterは[`render_lines_following`]を使う）。
/// 試験でないビルドの「使われていない」の警告を止める（`crate::markdown::MarkdownView::reset`と同じ扱い）。
/// 製品が使い始めたら外す。
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn render_with(events: &[Event], theme: &Theme, width: usize) -> Text<'static> {
    Text::from(render_lines(events, theme, width).lines)
}

/// 【harness】`width`桁で描いた行と、行ごとの前の行とのつながり（`LineJoin`）と、リンクの区間。描画部品が幅に
/// 合わせて自分で分けた続きの行は`Continues { indent }`、それ以外は`Break`（`render/wrap.rs`のモジュールdoc）。
///
/// どの行も`width`桁を超えない。例外は、字下げの後に1文字も入らないほど狭い幅だけ（同じく`render/wrap.rs`）。
///
/// 【harness】**製品は使わない**——試験だけが使う（T8の時点。Adapterは[`render_lines_following`]を使う）。
/// 試験でないビルドの「使われていない」の警告を止める（`crate::markdown::MarkdownView::reset`と同じ扱い）。
/// 製品が使い始めたら外す。
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn render_lines(events: &[Event], theme: &Theme, width: usize) -> Rendered {
    render_lines_following(events, theme, width, false)
}

/// 【harness】[`render_lines`]と同じに描く。`follows`なら、**既に何か描いた文書の続きとして**描く（T8。Adapterが
/// 確定した塊と書きかけの末尾を別々に解析して描き、[`append`]でつなぐため）。
///
/// 描画部品は最上位のブロックの間に空行を1つ置く（`Renderer::gap`）。置くのは**次のブロックが始まるとき**で、前に
/// 何か描いていれば、そのブロックが何も描かなくても置く（中身の無いコードブロックでも空行だけが出る）。だから
/// 「つなぐ2つが両方1行以上あれば間に空行」では決まらず、続きとして描く側が自分で置く——`follows`は、前の文書の
/// 最後のブロックの後ろに空行を置く約束（`pending_gap`）と、前に描いたこと（`wrote_any`）を引き継ぐ。最上位の
/// ブロックは閉じるときに必ず空行を約束するので、前の文書が何か描いていれば、約束は必ず残っている。
///
/// **前提**: 前の文書との境目が最上位のブロックの境目で、2つを続けて解析しても出来事が変わらないこと（Adapterは
/// 境界を採るときに解析器でそれを確かめる）。前提が成り立つ入力で、続けて描いたものと同じになることは、Adapterの
/// 試験（`super::stream_tests`）が、全文を1回で解析して描いたものとの比較で確かめる。
pub(crate) fn render_lines_following(
    events: &[Event],
    theme: &Theme,
    width: usize,
    follows: bool,
) -> Rendered {
    let mut r = Renderer::new(theme.clone(), width);
    r.pending_gap = follows;
    r.wrote_any = follows;
    r.feed(events);
    r.finish()
}

/// 【harness】`next`を`into`の後ろへつなぐ（T8）。`next`のリンクの区間の行は、つないだ位置のぶんずらす。間に何も
/// 足さない——ブロックの間の空行は、`next`を[`render_lines_following`]で続きとして描いた側が持つ。
pub(crate) fn append(into: &mut Rendered, next: &Rendered) {
    let offset = into.lines.len();
    into.lines.extend(next.lines.iter().cloned());
    into.joins.extend(next.joins.iter().copied());
    into.links.extend(next.links.iter().map(|link| LinkSpan {
        line: link.line + offset,
        ..link.clone()
    }));
}

/// 【harness】段落の文字の1区間——文字と書式と、リンクの中ならそのリンクの番号（`wrap::Sink::add_link`。T7b）。
type Segment = (String, InlineStyle, Option<usize>);

/// 【harness】解析器がGFMのタスクリストの印として出す文字（`markdown_stream`の`block.rs`。T7b）。文中のHTMLとして
/// モデルが書いたものと見分けるため、末尾の空白まで含めて完全に一致したものだけを印として扱う。
const TASK_UNCHECKED: &str = "<input disabled=\"\" type=\"checkbox\"> ";
const TASK_CHECKED: &str = "<input checked=\"\" disabled=\"\" type=\"checkbox\"> ";

struct Renderer {
    theme: Theme,
    width: usize,
    /// nesting prefixes (one per open blockquote / list level)
    prefixes: Vec<Prefix>,
    list_stack: Vec<ListCtx>,
    /// 【harness】開いている入れ物（`List`・`ListItem`・`BlockQuote`）の並び。項目の中か・リストの中に直接出た
    /// ブロックか・詰めたリストの項目の中かを見分ける（T7b）
    containers: Vec<BlockKind>,
    /// accumulated styled segments for the current paragraph/heading/table cell
    segments: Vec<Segment>,
    in_code: bool,
    /// 【harness】HTMLブロックの中か（T7b。上流はHTMLブロックを扱わず、中の文字を次の段落の文字として溜めた）
    in_html: bool,
    /// 【harness】いま読んでいるリンクの番号（T7b）
    link: Option<usize>,
    table: Option<TableBuf>,
    /// blank line owed before the next block
    pending_gap: bool,
    wrote_any: bool,
    /// spans of the physical line currently being built
    cur: Vec<Span<'static>>,
    /// 【harness】出した行と、行ごとの前の行とのつながりと、リンクの区間（上流の`lines`を置き換えた。必ず対で積む）
    out: Sink,
}

struct ListCtx {
    ordered: bool,
    next: u64,
    /// 【harness】詰めたリストか（項目の中のブロックの間に空行を入れない。T7b）
    tight: bool,
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

    /// 【harness】項目の記号の後ろにタスクリストの印を足す（T7b）。続きの行は印の後ろの文字に揃う。
    fn add_checkbox(&mut self, checked: bool) {
        let checkbox = if checked { "[x]" } else { "[ ]" };
        *self = Prefix::marker(format!("{}{checkbox} ", self.first.0));
    }
}

/// A buffered table cell: its rendered spans plus their visible width (for column sizing).
///
/// 【harness】`Span`にリンクの番号を添えて持つ（`wrap::Piece`。T7b）。
type Cell = (Vec<Piece>, usize);

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
            containers: Vec::new(),
            segments: Vec::new(),
            in_code: false,
            in_html: false,
            link: None,
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
        self.out.push(wrap::plain(spans), LineJoin::Break);
        self.wrote_any = true;
    }

    /// 【harness】字下げの後ろに`body`を置いた1行を出す。最初の行の字下げは、まだ出していない項目の記号を含む
    /// （T7b。上流は続きの行の字下げだけを付けたので、コード・表・区切り線から始まる項目は記号を失った）。幅を超えたら
    /// 文字の間で切って続きの行へ送る（コード・表・HTMLの行。`wrap::push_cut`）。
    fn emit_cut(&mut self, body: Vec<Piece>) {
        let (cont, _) = self.indent_cont_spans();
        let (first, _) = self.indent_first_spans();
        wrap::push_cut(&mut self.out, first, &cont, body, self.width);
        self.wrote_any = true;
    }

    /// Emit an owed blank line before a block.
    fn gap(&mut self) {
        if self.pending_gap && self.wrote_any {
            self.out.push(Vec::new(), LineJoin::Break);
        }
        self.pending_gap = false;
    }

    /// 【harness】ブロックの後ろに空行を1つ置く約束をする（上流は`pending_gap = true`を直に書いた）。詰めたリストの
    /// 項目のすぐ中のブロックは空行を置かない——項目の本文・入れ子のリスト・コード・引用の間を詰める（T7b）。
    /// そのとき、閉じたブロックの中で置こうとしていた空行（引用の中の段落・内側のゆるいリストの段落の後ろ）も
    /// 打ち消す——項目どうしの間を詰めるかは、外側のリストが詰めたものかで決まるため。
    fn owe_gap(&mut self) {
        let in_tight_item = self.containers.last() == Some(&BlockKind::ListItem)
            && self.list_stack.last().is_some_and(|list| list.tight);
        self.pending_gap = !in_tight_item;
    }

    /// 【harness】閉じた入れ物を並びから外す（T7b）。解析器の出入りが釣り合わなくても、関係の無い入れ物は外さない。
    fn close_container(&mut self, block: BlockKind) {
        if self.containers.last() == Some(&block) {
            self.containers.pop();
        }
    }

    /// 【harness】溜めた文字のうち、詰めたリストの項目の本文（段落に包まれない）を、次のブロックより先に出す（T7b）。
    /// 上流は項目が閉じるまで溜めたので、本文が中のブロック（入れ子のリスト・コード）より後ろに出て、入れ子の記号も
    /// 1行目に重なった。空白と改行だけ（解析器がブロックの前に出す区切り）なら捨てる。
    fn flush_item_text(&mut self) {
        if self
            .segments
            .iter()
            .any(|(text, _, _)| !text.trim().is_empty())
        {
            self.flush_segments(None);
        } else {
            self.segments.clear();
        }
    }

    /// 【harness】HTMLブロックを閉じる（T7b）。解析器はHTMLのコメント等のブロックを閉じずに次のブロックを始めることが
    /// あるので、ほかのブロックの出入りでも閉じる。
    fn end_html(&mut self) {
        if self.in_html {
            self.in_html = false;
            self.owe_gap();
        }
    }

    /// 【harness】項目が閉じるときに記号がまだ出ていなければ、中身の無い項目なので記号だけの1行を出す（T7b。上流は
    /// 項目ごと落とした）。行末の空白は付けない。
    fn emit_marker_of_empty_item(&mut self) {
        if self.prefixes.last().is_none_or(|prefix| prefix.emitted) {
            return;
        }
        self.gap();
        let (mut spans, _) = self.indent_first_spans();
        if let Some(last) = spans.last_mut() {
            let trimmed = last.content.trim_end().to_string();
            last.content = trimmed.into();
        }
        self.out.push(wrap::plain(spans), LineJoin::Break);
        self.wrote_any = true;
    }

    /// 【harness】タスクリストの印を、いま開いている項目の記号へ付けられるか（T7b）——項目のすぐ中で、記号をまだ
    /// 出しておらず、本文もまだ無い（解析器は印を項目の最初の中身として出す）。
    fn can_take_checkbox(&self) -> bool {
        self.containers.last() == Some(&BlockKind::ListItem)
            && self.prefixes.last().is_some_and(|prefix| !prefix.emitted)
            && self
                .segments
                .iter()
                .all(|(text, _, _)| text.trim().is_empty())
    }

    /// 【harness】文字の書式`style`がリンクの中なら、そのリンクの番号（T7b）。同じリンクの中で書式が変わっても同じ
    /// 番号。画像の代わりの文字はリンクとして扱わない（区間を返さない）。
    fn link_id(&mut self, style: &InlineStyle) -> Option<usize> {
        match &style.link {
            Some(link) if !link.image => {
                let id = match self.link {
                    Some(id) if self.out.url(id) == link.href => id,
                    _ => self.out.add_link(&link.href),
                };
                self.link = Some(id);
                Some(id)
            }
            _ => {
                self.link = None;
                None
            }
        }
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
            // 【harness】ブロックの出入りは`enter_block`・`exit_block`へ分けた（T7b）。どちらの前にも、閉じられていない
            // HTMLブロックを閉じる（`ExitBlock(HtmlBlock)`はここで閉じる）。
            Event::EnterBlock { block, data, .. } => {
                self.end_html();
                self.enter_block(*block, data);
            }
            Event::ExitBlock { block, .. } => {
                self.end_html();
                self.exit_block(*block);
            }
            Event::Text { text, style, .. } => self.text(text, style),
            // 【harness】リンクの出入りでリンクの番号を区切る（隣り合う別のリンクを1つの区間にしないため。T7b）。
            Event::EnterInline {
                inline: Inline::Link(_),
                ..
            }
            | Event::ExitInline {
                inline: Inline::Link(_),
            } => self.link = None,
            // Inline nesting is already baked into each Text event's `InlineStyle`.
            Event::EnterInline { .. } | Event::ExitInline { .. } => {}
            Event::SoftBreak => {
                if !self.in_code {
                    self.segments
                        .push((" ".to_string(), InlineStyle::default(), None));
                }
            }
            Event::LineBreak => {
                if !self.in_code {
                    self.segments
                        .push(("\n".to_string(), InlineStyle::default(), None));
                }
            }
        }
    }

    fn enter_block(&mut self, block: BlockKind, data: &BlockData) {
        // 【harness】ブロックが始まる前に、詰めたリストの項目の本文を出す。解析器がリストの中（最後の項目の後）へ
        // 出したブロックは、リストの後ろのブロックとして空行を挟んで描く（T7b）。
        if !matches!(
            block,
            BlockKind::Document | BlockKind::TableRow | BlockKind::TableCell
        ) {
            self.flush_item_text();
            if block != BlockKind::ListItem && self.containers.last() == Some(&BlockKind::List) {
                self.pending_gap = true;
            }
        }
        match block {
            BlockKind::BlockQuote => {
                self.gap();
                let muted = self.theme.muted;
                self.prefixes
                    .push(Prefix::repeating("│ ".to_string(), muted));
                self.containers.push(block);
            }
            BlockKind::List => {
                self.gap();
                self.list_stack.push(ListCtx {
                    ordered: data.list.as_ref().is_some_and(|l| l.ordered),
                    next: data.list.as_ref().map(|l| l.start).unwrap_or(1),
                    tight: data.list.as_ref().is_some_and(|l| l.tight),
                });
                self.containers.push(block);
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
                self.containers.push(block);
            }
            BlockKind::FencedCode | BlockKind::IndentedCode => {
                self.gap();
                self.in_code = true;
            }
            // 【harness】T7b。上流はHTMLブロックを扱わなかった。
            BlockKind::HtmlBlock => {
                self.gap();
                self.in_html = true;
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
        }
    }

    /// 【harness】ブロックの後ろの空行は`owe_gap`で約束する（詰めたリストの項目の中では置かない。T7b）。
    fn exit_block(&mut self, block: BlockKind) {
        match block {
            BlockKind::Paragraph => {
                self.flush_segments(None);
                self.owe_gap();
            }
            BlockKind::Heading => {
                let base = self.theme.heading;
                self.flush_segments(Some(base));
                self.owe_gap();
            }
            BlockKind::BlockQuote => {
                self.prefixes.pop();
                self.close_container(block);
                self.owe_gap();
            }
            BlockKind::List => {
                self.list_stack.pop();
                self.close_container(block);
                self.owe_gap();
            }
            BlockKind::ListItem => {
                self.flush_item_text();
                self.emit_marker_of_empty_item();
                self.prefixes.pop();
                self.close_container(block);
            }
            BlockKind::ThematicBreak => {
                self.gap();
                self.thematic_break();
                self.owe_gap();
            }
            BlockKind::FencedCode | BlockKind::IndentedCode => {
                self.in_code = false;
                self.owe_gap();
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
        }
    }

    /// 【harness】文字の出来事（T7bで`event`から分けた）。コードとHTMLブロックの中なら1行ずつそのまま出す。タスク
    /// リストの印なら項目の記号へ付ける。それ以外は段落の文字として溜める（リンクの中ならその番号を添える）。
    fn text(&mut self, text: &str, style: &InlineStyle) {
        if self.in_code {
            self.write_literal_lines(text, self.theme.code);
            return;
        }
        if self.in_html {
            self.write_literal_lines(text, self.theme.muted);
            return;
        }
        let checkbox = match text {
            TASK_UNCHECKED if style.raw_html => Some(false),
            TASK_CHECKED if style.raw_html => Some(true),
            _ => None,
        };
        if let Some(checked) = checkbox.filter(|_| self.can_take_checkbox()) {
            if let Some(prefix) = self.prefixes.last_mut() {
                prefix.add_checkbox(checked);
            }
            return;
        }
        let link = self.link_id(style);
        self.segments.push((text.to_string(), style.clone(), link));
    }

    /// Render the accumulated inline segments as wrapped, styled, indented lines.
    ///
    /// 【harness】行の分け方は`wrap::fill`へ置き換えた（T7a）。上流はASCIIの空白でしか分けず（日本語の段落は幅を
    /// 超えたまま1行で出た）、字下げの後ろの幅を`max(20)`で20桁未満にしなかった。語の区切り（`atoms`）と、語ごとの
    /// 書式（`style_for`）は上流のまま。語にはリンクの番号を添える（T7b）。
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
        for (raw, style, link) in &segments {
            let st = self.style_for(style, base);
            tokens.extend(atoms(raw).into_iter().map(|atom| match atom {
                Atom::Word(word) => Token::Word(word, st, *link),
                Atom::Space => Token::Space,
                Atom::Hard => Token::Hard,
            }));
        }
        wrap::fill(&mut self.out, first, &cont_spans, self.width, &tokens);
        self.wrote_any = true;
    }

    /// Render one fenced/indented code line (uniform code color; no syntax highlighting in v1).
    ///
    /// 【harness】コードとHTMLブロックの文字を、1行ずつ`style`で出す（上流の`write_code_line`をHTMLブロックにも
    /// 使えるようにした。T7b）。字下げは入れ子の字下げだけで、上流が付けたコードの2桁の字下げは外した（コピーした
    /// コードに余分な空白が入らないように。T7b）。タブは空白にする（`wrap::expand_tabs`。T7b）。幅を超える行は文字の
    /// 間で切り、続きの行にも同じ字下げを付ける（T7a。`emit_cut`）。上流は改行で終わらない断片を次の文字とつなげる
    /// 形だったが、解析器はコードの文字を必ず改行で終えて渡す（`markdown_stream`の`block.rs`）ので、断片を1行として扱う。
    fn write_literal_lines(&mut self, text: &str, style: Style) {
        self.gap();
        for piece in text.split_inclusive('\n') {
            let body = piece.strip_suffix('\n').unwrap_or(piece);
            self.emit_cut(vec![(Span::styled(wrap::expand_tabs(body), style), None)]);
        }
    }

    fn thematic_break(&mut self) {
        // 【harness】字下げは最初の行の字下げ（まだ出していない項目の記号を含む。T7b。上流は続きの行の字下げ）。
        let (ind, ind_w) = self.indent_first_spans();
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
        for (text, style, link) in &segs {
            let t = text.replace('\n', " ");
            w += UnicodeWidthStr::width(t.as_str());
            let st = self.style_for(style, None);
            spans.push((Span::styled(t, st), *link));
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
        let raw = |text: String| -> Piece { (Span::raw(text), None) };
        let border = |text: String| -> Piece { (Span::styled(text, muted), None) };
        // 【harness】行は`emit_cut`で出す——幅を超えたら文字の間で切り、続きの行には入れ子の字下げだけを付ける（T7a）。
        // 上流は切らずに幅を超えたまま出した。組み立てる中身は上流のまま（`Span`にリンクの番号を添える。T7b）。
        for (ri, row) in t.rows.iter().enumerate() {
            let mut body = vec![border("│ ".to_string())];
            for (i, width) in widths.iter().enumerate() {
                let cell = row.get(i).unwrap_or(&empty);
                let pad = width.saturating_sub(cell.1);
                match t.aligns.get(i).copied().unwrap_or(Alignment::None) {
                    Alignment::Right => {
                        body.push(raw(" ".repeat(pad)));
                        body.extend(cell.0.clone());
                    }
                    Alignment::Center => {
                        let l = pad / 2;
                        body.push(raw(" ".repeat(l)));
                        body.extend(cell.0.clone());
                        body.push(raw(" ".repeat(pad - l)));
                    }
                    _ => {
                        body.extend(cell.0.clone());
                        body.push(raw(" ".repeat(pad)));
                    }
                }
                body.push(border(" │ ".to_string()));
            }
            self.emit_cut(body);
            if ri == 0 {
                let mut body = vec![border("├".to_string())];
                for (i, width) in widths.iter().enumerate() {
                    body.push(border("─".repeat(width + 2)));
                    let joint = if i + 1 < ncol { "┼" } else { "┤" };
                    body.push(border(joint.to_string()));
                }
                self.emit_cut(body);
            }
        }
        self.owe_gap();
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
