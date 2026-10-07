// 【harness側で書いたファイル】上流（`codewandler-markdown-ratatui`）には無い。写した描画部品（`super`）の
// 折り返しを、このファイルの部品で置き換えた（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT7a）。
// T7bで、行と一緒にリンクの文字の場所を積む口（`Piece`・`Sink`のリンクの区間）と、タブを空白にする`expand_tabs`を足した。
// T11aで、折り返しをまたいだリンクの2行目以降の区間に続きの印（`LinkSpan::continues`）を付けるようにした。

//! 写した描画部品が、長い1行を渡された幅に合わせて**自分で**複数の行へ分ける部品（計画書§1.5の1と7・§2）と、
//! 出した行を積む置き場（[`Sink`]。行・つながりの印・リンクの区間。計画書§1.5の6・§3）。
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
//! # リンクの区間も、行を積むところで1か所で数える
//!
//! 行は[`Piece`]（`Span`と、それがどのリンクの文字か）の並びで積む。[`Sink::push`]が行の文字を数えながら、
//! リンクの文字が描かれた場所（`crate::markdown::LinkSpan`）を記録する——段落・見出し・表のセル・コードのどれから
//! 来た行も同じ口を通るので、出し方ごとに数え直す場所を作らない。数え方は`Line::styled_graphemes`と同じ
//! （描かれない制御文字は数えない）。リンクは描画部品が見つけた順に番号（[`Sink::add_link`]）を持ち、
//!
//! - 同じ番号の文字が同じ行に続けば1つの区間（間の空白——英語の語の間——も区間に入る）
//! - 次の行の最初のリンクの文字が同じ番号なら、リンクが折り返しをまたいだので、前の行の区間を行末まで延ばす
//!   （分けた所に残した空白を含める。各行の区間の文字をつなぐと、リンクの文字に戻る）。次の行の区間には続きの印
//!   （`LinkSpan::continues`）を付ける——使う側が分かれた区間を1つのリンクにまとめるため（吹き出しの置き場所）
//!
//! 番号で見分けるので、URLが同じでも隣り合う別のリンクは別の区間になる。
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
//! - [`expand_tabs`]で空白にしたタブは、コピーしても空白のまま（元のタブには戻らない）

use std::mem;

use harness_term::select::LineJoin;
use ratatui::buffer::CellWidth;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use crate::markdown::{LinkSpan, Rendered};

/// 行の1区間と、それがどのリンクの文字か（[`Sink::add_link`]の番号。リンクでなければ`None`）。
pub(super) type Piece = (Span<'static>, Option<usize>);

/// リンクを含まない`spans`を、行に積む形にする。
pub(super) fn plain(spans: Vec<Span<'static>>) -> Vec<Piece> {
    spans.into_iter().map(|span| (span, None)).collect()
}

/// 描いた行と、行ごとの前の行とのつながり（[`LineJoin`]）を**必ず対で**積み、リンクの文字の場所を記録する置き場
/// （モジュールdoc）。
#[derive(Debug, Default)]
pub(super) struct Sink {
    lines: Vec<Line<'static>>,
    joins: Vec<LineJoin>,
    /// リンクの番号ごとのURL。
    urls: Vec<String>,
    links: Vec<LinkSpan>,
    /// 最後に記録した区間（`links`の添字）と、そのリンクの番号。
    last_link: Option<(usize, usize)>,
}

impl Sink {
    /// 新しいリンクの番号を取る（`url`はリンク先）。
    pub(super) fn add_link(&mut self, url: &str) -> usize {
        self.urls.push(url.to_string());
        self.urls.len() - 1
    }

    /// 番号`id`のリンクのURL。
    pub(super) fn url(&self, id: usize) -> &str {
        &self.urls[id]
    }

    /// 1行を積む。`join`は前の行とのつながり。リンクの文字の場所を記録する（モジュールdoc）。
    pub(super) fn push(&mut self, pieces: Vec<Piece>, join: LineJoin) {
        let line = self.lines.len();
        let mut offset = 0;
        let mut spans = Vec::with_capacity(pieces.len());
        for (span, link) in pieces {
            let count = graphemes(&span);
            if let (Some(id), true) = (link, count > 0) {
                self.mark_link(id, line, offset, offset + count);
            }
            offset += count;
            spans.push(span);
        }
        self.lines.push(Line::from(spans));
        self.joins.push(join);
    }

    /// 番号`id`のリンクの文字が、`line`行目の`start..end`に描かれた（モジュールdoc）。
    fn mark_link(&mut self, id: usize, line: usize, start: usize, end: usize) {
        let mut continues = false;
        if let Some((index, last_id)) = self.last_link {
            if last_id == id {
                let previous = self.links[index].line;
                if previous == line {
                    self.links[index].end = end;
                    return;
                }
                if previous + 1 == line {
                    let line_end = self.lines[previous].spans.iter().map(graphemes).sum();
                    self.links[index].end = line_end;
                    continues = true;
                }
            }
        }
        self.links.push(LinkSpan {
            line,
            start,
            end,
            url: self.urls[id].clone(),
            continues,
        });
        self.last_link = Some((self.links.len() - 1, id));
    }

    /// 積んだ行と印（同じ長さ）とリンクの区間（[`Rendered`]）。
    pub(super) fn finish(self) -> Rendered {
        Rendered {
            lines: self.lines,
            joins: self.joins,
            links: self.links,
        }
    }
}

/// 段落の文字を、語・空白・ハードな改行に分けたもの（上流の`atoms`の結果に、描く書式とリンクの番号を付けたもの）。
pub(super) enum Token<'a> {
    Word(&'a str, Style, Option<usize>),
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

/// `span`の文字（書記素）の数。範囲選択の`Pos.offset`と同じく、描かれる書記素で数える（`Span::styled_graphemes`）。
fn graphemes(span: &Span<'_>) -> usize {
    span.styled_graphemes(Style::default()).count()
}

/// `spans`の桁数。
fn spans_width(spans: &[Span<'_>]) -> usize {
    spans
        .iter()
        .flat_map(|span| span.content.graphemes(true))
        .map(grapheme_width)
        .sum()
}

/// `spans`の文字（書記素）の数（`LineJoin`の`indent`）。
fn spans_graphemes(spans: &[Span<'_>]) -> usize {
    spans.iter().map(graphemes).sum()
}

/// タブの間隔（桁）。
const TAB_STOP: usize = 4;

/// コードとHTMLブロックの1行のタブを、行の頭から数えて次の[`TAB_STOP`]の倍数の桁まで空白に置き換える（全角文字は
/// 2桁と数える）。ratatuiは制御文字を描かないので、置き換えないとタブが画面にもコピーにも出ない（計画書§0のT7b）。
/// **コピーしても空白のまま**（モジュールdocの限界）。
pub(super) fn expand_tabs(line: &str) -> String {
    if !line.contains('\t') {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len() + TAB_STOP);
    let mut column = 0;
    for grapheme in line.graphemes(true) {
        if grapheme == "\t" {
            let spaces = TAB_STOP - column % TAB_STOP;
            out.extend(std::iter::repeat_n(' ', spaces));
            column += spaces;
        } else {
            out.push_str(grapheme);
            column += grapheme_width(grapheme);
        }
    }
    out
}

/// 語の中の1文字（書記素）。`piece`は元の[`Token::Word`]の番号で、同じ番号の文字は1つの`Span`にまとめて描く。
struct Grapheme<'a> {
    text: &'a str,
    piece: usize,
    style: Style,
    link: Option<usize>,
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
            Token::Word(text, style, link) => {
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
                        link: *link,
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

/// 組み立て中の、同じ`piece`の文字の並び。
struct Run {
    piece: usize,
    text: String,
    style: Style,
    link: Option<usize>,
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
    pieces: Vec<Piece>,
    /// 組み立て中の、同じ`piece`の文字の並び。
    run: Option<Run>,
    /// 組み立て中の行の、字下げの後ろの桁数。
    vis: usize,
    /// 組み立て中の行の、前の行とのつながり。
    join: LineJoin,
}

impl Filler<'_> {
    fn flush_run(&mut self) {
        if let Some(run) = self.run.take() {
            self.pieces
                .push((Span::styled(run.text, run.style), run.link));
        }
    }

    fn push_space(&mut self) {
        self.flush_run();
        self.pieces.push((Span::raw(" "), None));
        self.vis += 1;
    }

    fn push_grapheme(&mut self, grapheme: &Grapheme<'_>) {
        match &mut self.run {
            Some(run) if run.piece == grapheme.piece => run.text.push_str(grapheme.text),
            _ => {
                self.flush_run();
                self.run = Some(Run {
                    piece: grapheme.piece,
                    text: grapheme.text.to_string(),
                    style: grapheme.style,
                    link: grapheme.link,
                });
            }
        }
        self.vis += grapheme.width;
    }

    /// 組み立て中の行を積む。
    fn end_line(&mut self) {
        self.flush_run();
        let pieces = mem::take(&mut self.pieces);
        self.sink.push(pieces, self.join);
    }

    /// 組み立て中の行を積み、`join`でつながる次の行を字下げから始める。
    fn start_next_line(&mut self, join: LineJoin) {
        self.end_line();
        self.pieces = plain(self.cont.to_vec());
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
///
/// 【T7b】最後の語より後ろのハードな改行も捨てる。詰めたリストの項目は、本文の後ろに入れ子のリストやコードが続くとき
/// 本文の末尾に改行を付けて出すので、捨てないと字下げだけの空白の行が残る（CommonMarkでも、ブロックの末尾の
/// ハードな改行は無視する）。
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
        pieces: plain(first),
        run: None,
        vis: 0,
        join: LineJoin::Break,
    };
    let mut started = false;
    let mut pending_breaks = 0;
    for item in items(tokens) {
        match item {
            Item::Hard if started => pending_breaks += 1,
            Item::Hard => {}
            Item::Word(word) => {
                for _ in 0..mem::take(&mut pending_breaks) {
                    filler.start_next_line(LineJoin::Break);
                }
                filler.place_word(&word);
                started = true;
            }
        }
    }
    filler.end_line();
}

/// 字下げの後ろに`body`を置いた1行を`sink`へ積む。最初の行の字下げは`first`（リストの記号を含み得る）、続きの行は
/// `cont`（`first`と同じ桁数）。`width`桁を超えるなら`body`を文字の間で切り、続きの行（頭に`cont`、印は
/// `Continues { indent: contの文字数 }`）へ送る——コピーすると元の1行に戻る。コードの行・表の行・HTMLブロックの行に
/// 使う。どの行にも少なくとも1文字は置く（狭すぎる幅の例外。モジュールdoc）。
///
/// 収まるときは、`first`と`body`の`Span`をそのまま並べる（切らない行は上流と1つも違わない）。
pub(super) fn push_cut(
    sink: &mut Sink,
    first: Vec<Span<'static>>,
    cont: &[Span<'static>],
    body: Vec<Piece>,
    width: usize,
) {
    let avail = width.saturating_sub(spans_width(cont));
    let body_width: usize = body
        .iter()
        .map(|(span, _)| spans_width(std::slice::from_ref(span)))
        .sum();
    let mut line = plain(first);
    if body_width <= avail {
        line.extend(body);
        sink.push(line, LineJoin::Break);
        return;
    }
    let indent = spans_graphemes(cont);
    let mut vis = 0;
    let mut join = LineJoin::Break;
    for (span, link) in body {
        let mut run = String::new();
        for grapheme in span.content.graphemes(true) {
            let width = grapheme_width(grapheme);
            if vis > 0 && vis + width > avail {
                if !run.is_empty() {
                    line.push((Span::styled(mem::take(&mut run), span.style), link));
                }
                sink.push(mem::replace(&mut line, plain(cont.to_vec())), join);
                vis = 0;
                join = LineJoin::Continues { indent };
            }
            run.push_str(grapheme);
            vis += width;
        }
        if !run.is_empty() {
            line.push((Span::styled(run, span.style), link));
        }
    }
    sink.push(line, join);
}
