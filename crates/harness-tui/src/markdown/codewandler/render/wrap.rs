// 【harness側で書いたファイル】上流（`codewandler-markdown-ratatui`）には無い。写した描画部品（`super`）の
// 折り返しを、このファイルの部品で置き換えた（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT7a）。

//! 写した描画部品が、長い1行を渡された幅に合わせて**自分で**複数の行へ分ける部品（計画書§1.5の1と7・§2）。
//!
//! # 何のためにあるのか
//!
//! 描画部品が自分で行を分けるのは、リストの2行目以降の字下げ（継続インデント）と引用の縦線を保つためである
//! （計画書§1.2）。共有の折り返し部品（`harness_term::wrap`。ratatuiの単語折り返し）は字下げを知らないので、
//! それに任せると続きの行が左端から始まってしまう。そこで、描画部品が出す行は次の2つを守る。
//!
//! 1. **画面で1行に収まる。** 出す行はどれも、渡された幅（`harness_term::wrap::text_width`で狭めたもの）を超えない。
//!    共有の折り返し部品はtranscriptを描くときにもう一度通るが、収まっている行は折り返し直さない
//!    （数えるのも描くのも共有の部品のまま。計画書§1.4の「BUG-192の例外」）
//! 2. **コピーで元の1行に戻る。** 自分で分けた続きの行には`LineJoin::Continues { indent }`を付ける。`indent`は
//!    続きの行の頭に付けた字下げの文字（書記素）の数で、範囲選択の`Pos.offset`と同じ数え方（`harness_term::select`）。
//!    英語の語の間で分けたときは、空白を**前の行の末尾に残す**（つなぐときに空白を足さない約束。計画書§2.4）
//!
//! 行と印は[`Sink`]へ必ず対で積む（片方だけ積む書き方ができない）。
//!
//! # 分けてよい所
//!
//! - ASCIIの空白（語の区切りは上流の関数`atoms`のまま）
//! - 全角文字（`cell_width`が2以上）と、その隣の文字の間。半角の語の中では分けない
//! - 幅を超える語（URL・パス・長い識別子）の文字（書記素）の間
//!
//! 空白の後ろで分ける語は、**その空白の1桁まで含めて**行に収める（行をちょうど埋めた語の後ろで分けると、残す空白が
//! 幅を超えるため）。行の頭から置いても空白の1桁ぶん入らない語は、文字の間で切る。
//!
//! # 限界
//!
//! - **禁則を見ない**（句読点が行頭に来ることがある）。共有の折り返し部品（`harness_term::wrap`の「限界」）と同じ
//! - **狭すぎる幅だけの例外**: 字下げの後に1文字（と、その語の後ろに残す空白）も入らないときは、1行に1文字を置いて
//!   幅を超える（何も描けない形にはしない。`harness_term::wrap::rows`が幅0を1桁として数えるのと同じ考え方）。
//!   超えた行は共有の折り返し部品が折り返し直すので、その幅では継続インデントが崩れる
//! - 桁の数え方は共有の折り返し部品に合わせる（書記素ごとの`cell_width`。描かれない制御文字は0桁）。端末が
//!   「曖昧な幅」の文字（`•`・`│`等）を2桁で描く設定だと揃わない（計画書§1.7）

use std::mem;

use harness_term::select::LineJoin;
use ratatui::buffer::CellWidth;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use crate::markdown::Rendered;

/// 描いた行と、行ごとの前の行とのつながり（[`LineJoin`]）を、**必ず対で**積む置き場（モジュールdoc）。
#[derive(Debug, Default)]
pub(super) struct Sink {
    lines: Vec<Line<'static>>,
    joins: Vec<LineJoin>,
}

impl Sink {
    /// 1行を積む。`join`は前の行とのつながり。
    pub(super) fn push(&mut self, spans: Vec<Span<'static>>, join: LineJoin) {
        self.lines.push(Line::from(spans));
        self.joins.push(join);
    }

    /// 積んだ行と印（[`Rendered`]。同じ長さ）。
    pub(super) fn finish(self) -> Rendered {
        Rendered {
            lines: self.lines,
            joins: self.joins,
        }
    }
}

/// 段落の文字を、語・空白・ハードな改行に分けたもの（上流の`atoms`の結果に、描く書式を付けたもの）。
pub(super) enum Token<'a> {
    Word(&'a str, Style),
    Space,
    Hard,
}

/// 書記素の桁数。共有の折り返し部品と同じ数え方——`Span::styled_graphemes`が落とす制御文字（タブ等）は描かれない
/// ので0桁、それ以外は`cell_width`。
fn grapheme_width(grapheme: &str) -> usize {
    if grapheme.contains(char::is_control) {
        0
    } else {
        usize::from(grapheme.cell_width())
    }
}

/// `spans`の桁数。
fn spans_width(spans: &[Span<'_>]) -> usize {
    spans
        .iter()
        .flat_map(|span| span.content.graphemes(true))
        .map(grapheme_width)
        .sum()
}

/// `spans`の文字（書記素）の数。範囲選択の`Pos.offset`と同じく、描かれる書記素で数える（`LineJoin`の`indent`）。
fn spans_graphemes(spans: &[Span<'_>]) -> usize {
    spans
        .iter()
        .map(|span| span.styled_graphemes(Style::default()).count())
        .sum()
}

/// 語の中の1文字（書記素）。`piece`は元の[`Token::Word`]の番号で、同じ番号の文字は1つの`Span`にまとめて描く。
struct Grapheme<'a> {
    text: &'a str,
    piece: usize,
    style: Style,
    width: usize,
}

/// 空白で区切られた1語。書式の違う`Token::Word`が空白なしで続くときは、まとめて1語にする（`**太字**、`の`、`を
/// 太字の語から引き離して行頭へ送らないため）。
struct Word<'a> {
    graphemes: Vec<Grapheme<'a>>,
    /// 前に空白があった（行の途中なら空白1つを挟む）。
    space_before: bool,
    /// 後ろに空白があり、その後に語が続く（この語の後ろで分けると、空白を行末に残す）。
    space_after: bool,
}

impl Word<'_> {
    /// 分けてよい所で区切った塊（`graphemes`の添字の範囲）。全角文字とその隣の文字の間で区切る。
    fn chunks(&self) -> Vec<std::ops::Range<usize>> {
        let mut chunks = Vec::new();
        let mut start = 0;
        for index in 1..self.graphemes.len() {
            if self.graphemes[index - 1].width >= 2 || self.graphemes[index].width >= 2 {
                chunks.push(start..index);
                start = index;
            }
        }
        if start < self.graphemes.len() {
            chunks.push(start..self.graphemes.len());
        }
        chunks
    }
}

enum Item<'a> {
    Word(Word<'a>),
    Hard,
}

/// 字句を、語とハードな改行の並びにする。空白は語の`space_before`・`space_after`になる。
fn items<'a>(tokens: &[Token<'a>]) -> Vec<Item<'a>> {
    let mut items = Vec::new();
    let mut current: Option<Word<'a>> = None;
    let mut pending_space = false;
    for (piece, token) in tokens.iter().enumerate() {
        match token {
            Token::Word(text, style) => {
                if pending_space || current.is_none() {
                    items.extend(current.take().map(Item::Word));
                    current = Some(Word {
                        graphemes: Vec::new(),
                        space_before: pending_space,
                        space_after: false,
                    });
                }
                let word = current.as_mut().expect("直前で作った");
                for grapheme in text.graphemes(true) {
                    word.graphemes.push(Grapheme {
                        text: grapheme,
                        piece,
                        style: *style,
                        width: grapheme_width(grapheme),
                    });
                }
                pending_space = false;
            }
            Token::Space => pending_space = true,
            Token::Hard => {
                items.extend(current.take().map(Item::Word));
                items.push(Item::Hard);
                pending_space = false;
            }
        }
    }
    items.extend(current.take().map(Item::Word));
    for index in 0..items.len() {
        let next_has_space_before =
            matches!(items.get(index + 1), Some(Item::Word(next)) if next.space_before);
        if let Item::Word(word) = &mut items[index] {
            word.space_after = next_has_space_before;
        }
    }
    items
}

/// 1段落ぶんの行を組み立てる途中の状態。
struct Filler<'s> {
    sink: &'s mut Sink,
    /// 続きの行の頭に付ける字下げ（リストの記号の幅の空白・引用の縦線）。
    cont: &'s [Span<'static>],
    /// `cont`の文字の数（続きの行の`LineJoin::Continues`の`indent`）。
    indent: usize,
    /// 字下げの後ろに使える桁数。
    avail: usize,
    /// 組み立て中の行（頭の字下げを含む）。
    spans: Vec<Span<'static>>,
    /// 組み立て中の、同じ`piece`の文字の並び（`piece`・文字・書式）。
    run: Option<(usize, String, Style)>,
    /// 組み立て中の行の、字下げの後ろの桁数。
    vis: usize,
    /// 組み立て中の行の、前の行とのつながり。
    join: LineJoin,
}

impl Filler<'_> {
    fn flush_run(&mut self) {
        if let Some((_, text, style)) = self.run.take() {
            self.spans.push(Span::styled(text, style));
        }
    }

    fn push_space(&mut self) {
        self.flush_run();
        self.spans.push(Span::raw(" "));
        self.vis += 1;
    }

    fn push_grapheme(&mut self, grapheme: &Grapheme<'_>) {
        match &mut self.run {
            Some((piece, text, _)) if *piece == grapheme.piece => text.push_str(grapheme.text),
            _ => {
                self.flush_run();
                self.run = Some((grapheme.piece, grapheme.text.to_string(), grapheme.style));
            }
        }
        self.vis += grapheme.width;
    }

    /// 組み立て中の行を積む。
    fn end_line(&mut self) {
        self.flush_run();
        let spans = mem::take(&mut self.spans);
        self.sink.push(spans, self.join);
    }

    /// 組み立て中の行を積み、`join`でつながる次の行を字下げから始める。
    fn start_next_line(&mut self, join: LineJoin) {
        self.end_line();
        self.spans = self.cont.to_vec();
        self.vis = 0;
        self.join = join;
    }

    /// 幅に合わせて分ける（次の行は続きの行）。`trailing_space`なら、分けた所の空白を行末に残す。
    fn wrap(&mut self, trailing_space: bool) {
        if trailing_space {
            self.push_space();
        }
        let indent = self.indent;
        self.start_next_line(LineJoin::Continues { indent });
    }

    fn place_word(&mut self, word: &Word<'_>) {
        let chunks = word.chunks();
        for (index, range) in chunks.iter().enumerate() {
            let graphemes = &word.graphemes[range.clone()];
            let width: usize = graphemes.iter().map(|grapheme| grapheme.width).sum();
            // 語の後ろで分けるときに残す空白の1桁（モジュールdoc）。
            let reserve = usize::from(index + 1 == chunks.len() && word.space_after);
            let sep = usize::from(index == 0 && word.space_before && self.vis > 0);
            if self.vis + sep + width + reserve <= self.avail {
                if sep == 1 {
                    self.push_space();
                }
                graphemes
                    .iter()
                    .for_each(|grapheme| self.push_grapheme(grapheme));
                continue;
            }
            if self.vis > 0 {
                self.wrap(sep == 1);
            }
            if width + reserve <= self.avail {
                graphemes
                    .iter()
                    .for_each(|grapheme| self.push_grapheme(grapheme));
            } else {
                self.cut(graphemes, reserve);
            }
        }
    }

    /// 行の頭から置いても入らない塊を、文字の間で切る。どの行にも少なくとも1文字は置く（狭すぎる幅の例外）。
    fn cut(&mut self, graphemes: &[Grapheme<'_>], reserve: usize) {
        for (index, grapheme) in graphemes.iter().enumerate() {
            let reserve = if index + 1 == graphemes.len() {
                reserve
            } else {
                0
            };
            if self.vis > 0 && self.vis + grapheme.width + reserve > self.avail {
                self.wrap(false);
            }
            self.push_grapheme(grapheme);
        }
    }
}

/// 段落（見出しを含む）の字句を、`width`桁に収まる行へ分けて`sink`へ積む。
///
/// 最初の行は`first`（リストの記号等）から、続きの行は`cont`から始める。`first`と`cont`の桁数は同じ
/// （リストの記号は同じ幅の空白に、引用の縦線はそのまま続く）。ハードな改行の後ろの行は元の文章にある改行なので
/// `Break`、幅に合わせて分けた行は`Continues`。ハードな改行が語より前にあれば捨てる（上流と同じ。ゆるいリストの
/// 項目は段落の前に余分な改行を出すので、記号だけの行になるのを防ぐ）。
pub(super) fn fill(
    sink: &mut Sink,
    first: Vec<Span<'static>>,
    cont: &[Span<'static>],
    width: usize,
    tokens: &[Token<'_>],
) {
    let mut filler = Filler {
        sink,
        cont,
        indent: spans_graphemes(cont),
        avail: width.saturating_sub(spans_width(cont)),
        spans: first,
        run: None,
        vis: 0,
        join: LineJoin::Break,
    };
    let mut started = false;
    for item in items(tokens) {
        match item {
            Item::Hard if started => filler.start_next_line(LineJoin::Break),
            Item::Hard => {}
            Item::Word(word) => {
                filler.place_word(&word);
                started = true;
            }
        }
    }
    filler.end_line();
}

/// `prefix`（入れ子の字下げ等）の後ろに`body`を置いた1行を`sink`へ積む。`width`桁を超えるなら`body`を文字の間で
/// 切り、続きの行（頭に同じ`prefix`、印は`Continues { indent: prefixの文字数 }`）へ送る——コピーすると元の1行に戻る。
/// コードの行と表の行に使う。どの行にも少なくとも1文字は置く（狭すぎる幅の例外。モジュールdoc）。
///
/// 収まるときは、`prefix`と`body`の`Span`をそのまま並べる（切らない行は上流と1つも違わない）。
pub(super) fn push_cut(
    sink: &mut Sink,
    prefix: Vec<Span<'static>>,
    body: Vec<Span<'static>>,
    width: usize,
) {
    let avail = width.saturating_sub(spans_width(&prefix));
    if spans_width(&body) <= avail {
        let mut spans = prefix;
        spans.extend(body);
        sink.push(spans, LineJoin::Break);
        return;
    }
    let indent = spans_graphemes(&prefix);
    let mut line = prefix.clone();
    let mut vis = 0;
    let mut join = LineJoin::Break;
    for span in body {
        let mut run = String::new();
        for grapheme in span.content.graphemes(true) {
            let width = grapheme_width(grapheme);
            if vis > 0 && vis + width > avail {
                if !run.is_empty() {
                    line.push(Span::styled(mem::take(&mut run), span.style));
                }
                sink.push(mem::replace(&mut line, prefix.clone()), join);
                vis = 0;
                join = LineJoin::Continues { indent };
            }
            run.push_str(grapheme);
            vis += width;
        }
        if !run.is_empty() {
            line.push(Span::styled(run, span.style));
        }
    }
    sink.push(line, join);
}
