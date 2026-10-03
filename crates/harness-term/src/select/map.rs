//! 送れる枠に描いた文章の、**どの文字が画面のどこに描かれたか**（[`TextMap`]）と、選んだ範囲の色付け・取り出し。
//!
//! # 文字の場所は、ratatui自身に描かせて読み取る
//!
//! 折り返しはratatuiの単語折り返し（`WordWrapper`）が決めていて、その中身は公開されていない
//! （`ratatui-widgets`の`reflow`は非公開）。自前で幅を足し算して写すと、空白で切る規則の分だけ描画とずれる
//! ——[`crate::wrap`]がBUG-192で採らなかった形である。そこで、見えている行だけを**もう一度ratatuiに描かせる**。
//! そのとき各文字の色（前景色）に「その行の何番目の文字か」を埋めておき、描き上がったセルの色を読めば、
//! 文字が描かれた場所がそのまま分かる。**折り返しは文字の色を見ない**（`WordWrapper`は記号と幅だけで決める）ので、
//! 色を変えても折り返し方は本物の描画と同じになる（試験`the_map_matches_the_drawn_screen`が本物の画面と突き合わせる）。
//!
//! # 位置は「描いた行の何番目の文字か」で持つ
//!
//! 文字の単位はratatuiが描く単位（`Span::styled_graphemes`が返す書記素。**制御文字を含む書記素は描かれないので数えない**）。
//! 行は呼び出し側が渡した`Text`の行で、折り返した後の表示行ではない——だから折り返して描いた1行を選ぶと、
//! 取り出す文章は改行の入らない元の1行に戻る（折り返しの位置で落ちた空白も戻る）。
//!
//! # 限界
//!
//! - 見えている行だけを数え直す（描くたびに、見えている行の数だけ小さく描き直す）。費用は測っていない。
//! - 1行に約1,677万文字（色に埋められる24ビット）を超える文字があると、それより後ろの文字の場所が分からない。
//! - 描かれない文字（幅0の書記素）は取り出さない（見えないものは写さない）。

use ratatui::buffer::{Buffer, CellWidth};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Widget, Wrap};

use super::SELECTED;

/// 文章の中の位置——描いた`Text`の何行目の、何番目の文字（書記素）の**前**か。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct Pos {
    /// `Text`の行（折り返す前の行）。
    pub line: usize,
    /// その行の何番目の文字の前か（描かれる書記素で数える。モジュールdoc）。
    pub offset: usize,
}

/// ポインタが指したところ。文字の上ならその文字の前と後ろ、文字の無いところ（行の右の空き・枠の外）なら同じ1点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hit {
    pub before: Pos,
    pub after: Pos,
}

impl Hit {
    /// 文字と文字の間の1点。
    fn caret(line: usize, offset: usize) -> Self {
        let at = Pos { line, offset };
        Self {
            before: at,
            after: at,
        }
    }

    /// 行`line`の`index`番目の文字の上。
    fn glyph(line: usize, index: usize) -> Self {
        Self {
            before: Pos {
                line,
                offset: index,
            },
            after: Pos {
                line,
                offset: index + 1,
            },
        }
    }
}

/// 押した所（`anchor`）から今の所（`head`）までで選ばれる範囲（半開区間）。**押した文字も今の文字も含む**
/// （端末の文字選択と同じ）。空なら`None`。
pub(crate) fn span(anchor: Hit, head: Hit) -> Option<(Pos, Pos)> {
    let (start, end) = if head.before >= anchor.before {
        (anchor.before, anchor.after.max(head.after))
    } else {
        (head.before, anchor.after)
    };
    (start < end).then_some((start, end))
}

/// 描くときに、選んでいる範囲をどう決めるか（[`super::Selection::mark`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mark {
    /// 押した所。
    pub anchor: Hit,
    pub head: Head,
}

/// 選んでいる範囲の、押した所ではない側の端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Head {
    /// 決まっている（ボタンを離した後）。
    Fixed(Hit),
    /// ドラッグ中——この描画で描いた場所に対して、このセルが指すところ（枠の外なら枠の端へ寄せる）。
    /// 描くたびに引き直すので、送られても応答が流れ込んでも、ポインタの下の文字を指す。
    Pointer(u16, u16),
}

/// 1つの枠について、見えている文字が画面のどこに描かれたか（モジュールdoc）。描くたびに作り直す。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct TextMap {
    /// 文章を描いた矩形（枠線の内側）。
    area: Rect,
    /// 見えている表示行（上から順）。
    rows: Vec<Row>,
    /// 選んだ範囲があれば、この描画で決まった端と、取り出した文章。
    marked: Option<Marked>,
}

/// 見えている表示行1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    y: u16,
    /// `Text`の何行目を描いた行か。
    line: usize,
    /// 描かれた文字（左から順）。
    glyphs: Vec<Glyph>,
    /// この表示行の頭と末尾の位置（行の何番目の文字の前か）。末尾は次の表示行の頭——折り返しで落ちた空白を含む。
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Glyph {
    x: u16,
    width: u16,
    /// 行の何番目の文字か。
    index: usize,
}

/// この描画で決まった、選んでいる範囲の端と文章。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marked {
    pub head: Hit,
    /// 選んだ範囲の文章（改行は`\n`）。範囲が空なら空。
    pub text: String,
}

impl TextMap {
    /// 文章を描いた矩形（枠線の内側）。
    pub(crate) fn area(&self) -> Rect {
        self.area
    }

    pub(crate) fn marked(&self) -> Option<&Marked> {
        self.marked.as_ref()
    }

    /// 文字の無い地図（`area`だけを持つ。押した場所の当たり判定の試験用）。
    #[cfg(test)]
    pub(crate) fn empty(area: Rect) -> Self {
        Self {
            area,
            ..Self::default()
        }
    }

    /// `(column, row)`が指す文章の位置。**枠の外も枠の端へ寄せて答える**——上なら見えている最初の表示行の頭、
    /// 下（と文章の終わりより下）なら見えている最後の表示行の末尾、左右ならその表示行の頭と末尾。
    /// 見えている文字が1つも無い（文章が空・枠が潰れている）なら`None`。
    pub(crate) fn hit(&self, column: u16, row: u16) -> Option<Hit> {
        let first = self.rows.first()?;
        let last = self.rows.last()?;
        if row < first.y {
            return Some(Hit::caret(first.line, first.start));
        }
        match self.rows.iter().find(|r| r.y == row) {
            Some(r) => Some(r.hit(column)),
            None => Some(Hit::caret(last.line, last.end)),
        }
    }
}

impl Row {
    fn hit(&self, column: u16) -> Hit {
        let (Some(first), Some(last)) = (self.glyphs.first(), self.glyphs.last()) else {
            return Hit::caret(self.line, self.start);
        };
        if column < first.x {
            return Hit::caret(self.line, self.start);
        }
        if column >= last.x.saturating_add(last.width) {
            return Hit::caret(self.line, self.end);
        }
        self.glyphs
            .iter()
            .find(|g| g.x <= column && column < g.x.saturating_add(g.width))
            .map_or(Hit::caret(self.line, self.start), |g| {
                Hit::glyph(self.line, g.index)
            })
    }
}

/// 描く本文の形（送れる枠が描く直前に分かっていること）。
pub(crate) struct Shape<'h> {
    /// 文章を描く矩形（枠線の内側）。
    pub inner: Rect,
    /// 行ごとの表示行の数（折り返さない枠は全部1）。
    pub heights: &'h [usize],
    /// 枠の一番上に見せる表示行。
    pub top: usize,
    /// 折り返すか（[`crate::wrap::Wrapped`]で描くか、折り返さない`Paragraph`で描くか）。
    pub wrapped: bool,
}

/// 描く直前に呼ぶ。見えている行の文字の場所を[`TextMap`]にし、`mark`があれば選んだ範囲を決めて、
/// **見えている行のうち範囲に入る文字に選択の色を付けた`text`**と、範囲の文章を返す。
///
/// 色を付けても折り返しは変わらない（モジュールdoc）ので、返した`text`をそのまま同じ形で描けばよい。
pub(crate) fn prepare<'a>(
    mut text: Text<'a>,
    shape: Shape<'_>,
    mark: Option<Mark>,
) -> (Text<'a>, TextMap) {
    let width = if shape.wrapped {
        crate::wrap::text_width(shape.inner.width)
    } else {
        shape.inner.width
    };
    let visible = usize::from(shape.inner.height);
    let (shown_from, shown_to) = (shape.top, shape.top + visible);
    let mut rows = Vec::new();
    let mut shown_lines = Vec::new();
    let mut start = 0usize;
    for (index, &height) in shape.heights.iter().enumerate() {
        let (from, to) = (start, start + height);
        start = to;
        if to <= shown_from {
            continue;
        }
        if from >= shown_to {
            break;
        }
        let Some(line) = text.lines.get(index) else {
            break;
        };
        shown_lines.push(index);
        for (r, row) in line_rows(line, text.alignment, width, height, shape.wrapped)
            .into_iter()
            .enumerate()
        {
            let at = from + r;
            if at < shown_from || at >= shown_to {
                continue;
            }
            let y = shape
                .inner
                .y
                .saturating_add(u16::try_from(at - shown_from).unwrap_or(u16::MAX));
            rows.push(Row {
                y,
                line: index,
                glyphs: row
                    .glyphs
                    .into_iter()
                    .map(|g| Glyph {
                        x: shape.inner.x.saturating_add(g.x),
                        ..g
                    })
                    .collect(),
                start: row.start,
                end: row.end,
            });
        }
    }
    let mut map = TextMap {
        area: shape.inner,
        rows,
        marked: None,
    };
    let Some(mark) = mark else {
        return (text, map);
    };
    let head = match mark.head {
        Head::Fixed(hit) => Some(hit),
        Head::Pointer(column, row) => map.hit(column, row),
    };
    let Some(head) = head else {
        return (text, map);
    };
    let range = span(mark.anchor, head);
    let selected = range.map(|range| extract(&text, range)).unwrap_or_default();
    if let Some((from, to)) = range {
        for index in shown_lines {
            if index < from.line || index > to.line {
                continue;
            }
            let first = if index == from.line { from.offset } else { 0 };
            let last = if index == to.line {
                to.offset
            } else {
                usize::MAX
            };
            text.lines[index] = highlighted(&text.lines[index], first, last);
        }
    }
    map.marked = Some(Marked {
        head,
        text: selected,
    });
    (text, map)
}

/// 1行を描いたときの表示行ごとの文字（位置は描く矩形の左端から）。
struct LineRow {
    glyphs: Vec<Glyph>,
    start: usize,
    end: usize,
}

/// `line`を`width`桁の場所へ描いたときの、表示行ごとの文字の場所（モジュールdoc「ratatui自身に描かせて読み取る」）。
fn line_rows(
    line: &Line,
    text_alignment: Option<Alignment>,
    width: u16,
    height: usize,
    wrapped: bool,
) -> Vec<LineRow> {
    let graphemes: Vec<&str> = line
        .styled_graphemes(Style::default())
        .map(|g| g.symbol)
        .collect();
    let len = graphemes.len();
    let spans: Vec<Span> = graphemes
        .iter()
        .enumerate()
        .map(|(index, symbol)| Span::styled(*symbol, Style::new().fg(encode(index))))
        .collect();
    let mut marked = Line::from(spans);
    marked.alignment = line.alignment.or(text_alignment);
    let height = u16::try_from(height.max(1)).unwrap_or(u16::MAX);
    // 右に2桁の余白を持たせる。折り返しは行末の全角文字を描く場所の右へ1桁はみ出させることがあり
    // （`crate::wrap`のBUG-200）、本物の画面ではそれが空けてある1桁に描かれる。
    let mut buffer = Buffer::empty(Rect::new(0, 0, width.saturating_add(2), height));
    let paragraph = Paragraph::new(marked);
    let paragraph = if wrapped {
        paragraph.wrap(Wrap { trim: false })
    } else {
        paragraph
    };
    paragraph.render(Rect::new(0, 0, width, height), &mut buffer);

    let mut rows: Vec<Vec<Glyph>> = (0..height)
        .map(|y| {
            (0..buffer.area.width)
                .filter_map(|x| {
                    let cell = &buffer[(x, y)];
                    decode(cell.fg).map(|index| Glyph {
                        x,
                        width: cell.symbol().cell_width().max(1),
                        index,
                    })
                })
                .collect()
        })
        .collect();
    // 描かれた表示行の数より後ろの空行は落とす（数えた行数と描いた行数は同じはずだが、念のため描いた分だけを持つ）。
    while rows.len() > 1 && rows.last().is_some_and(Vec::is_empty) {
        rows.pop();
    }
    let firsts: Vec<Option<usize>> = rows
        .iter()
        .map(|glyphs| glyphs.iter().map(|g| g.index).min())
        .collect();
    let mut previous_end = 0;
    rows.into_iter()
        .enumerate()
        .map(|(r, glyphs)| {
            let end = if wrapped {
                firsts[r + 1..]
                    .iter()
                    .flatten()
                    .next()
                    .copied()
                    .unwrap_or(len)
            } else {
                len
            };
            let start = firsts[r].unwrap_or(previous_end);
            previous_end = end;
            LineRow { glyphs, start, end }
        })
        .collect()
}

/// 色に埋められる文字の番号の上限（24ビット）。
const MAX_INDEX: usize = 0xFF_FFFF;

fn encode(index: usize) -> Color {
    let index = index.min(MAX_INDEX) as u32;
    Color::Rgb((index >> 16) as u8, (index >> 8) as u8, index as u8)
}

fn decode(color: Color) -> Option<usize> {
    match color {
        Color::Rgb(r, g, b) => {
            Some((usize::from(r) << 16) | (usize::from(g) << 8) | usize::from(b))
        }
        _ => None,
    }
}

/// `range`の文章を取り出す（行の間は`\n`）。描かれない文字（幅0）は入れない（モジュールdoc）。
pub(crate) fn extract(text: &Text, (from, to): (Pos, Pos)) -> String {
    let mut out = String::new();
    let Some(last_line) = text.lines.len().checked_sub(1) else {
        return out;
    };
    for index in from.line..=to.line.min(last_line) {
        if index > from.line {
            out.push('\n');
        }
        let first = if index == from.line { from.offset } else { 0 };
        let last = if index == to.line {
            to.offset
        } else {
            usize::MAX
        };
        for (k, grapheme) in text.lines[index]
            .styled_graphemes(Style::default())
            .enumerate()
        {
            if k >= first && k < last && grapheme.symbol.cell_width() > 0 {
                out.push_str(grapheme.symbol);
            }
        }
    }
    out
}

/// `line`の`from..to`番目の文字に選択の色（[`SELECTED`]）を重ねた行。行の色は文字ごとの色へ移す（描いた見た目は同じ）。
fn highlighted(line: &Line, from: usize, to: usize) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    for (k, grapheme) in line.styled_graphemes(Style::default()).enumerate() {
        let style = if k >= from && k < to {
            grapheme
                .style
                .patch(SELECTED)
                .remove_modifier(Modifier::REVERSED)
        } else {
            grapheme.style
        };
        match spans.last_mut() {
            Some(last) if last.style == style => last.content.to_mut().push_str(grapheme.symbol),
            _ => spans.push(Span::styled(grapheme.symbol.to_string(), style)),
        }
    }
    let mut out = Line::from(spans);
    out.alignment = line.alignment;
    out
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::widgets::{Block, Borders};
    use ratatui::Terminal;

    use super::*;
    use crate::wrap::{line_rows as heights_of, Wrapped};

    /// `lines`を`width`×`height`の枠（枠線付き）へ`top`から折り返して描いた画面と、同じ形で作った地図。
    fn drawn(
        lines: &[Line<'static>],
        width: u16,
        height: u16,
        top: u16,
        wrapped: bool,
    ) -> (Buffer, TextMap) {
        let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        let mut map = None;
        term.draw(|frame| {
            let block = Block::default().borders(Borders::ALL);
            let inner = block.inner(frame.area());
            let text = Text::from(lines.to_vec());
            let heights = if wrapped {
                heights_of(text.clone(), inner.width)
            } else {
                vec![1; lines.len()]
            };
            // 送れる上限で切り詰める（`crate::scrollable::Window`と同じ。上限より先は描く位置にならない）。
            let total: usize = heights.iter().sum();
            let top = top
                .min(u16::try_from(total.saturating_sub(usize::from(inner.height))).unwrap_or(0));
            let (text, built) = prepare(
                text,
                Shape {
                    inner,
                    heights: &heights,
                    top: usize::from(top),
                    wrapped,
                },
                None,
            );
            if wrapped {
                Wrapped::new(text)
                    .block(block)
                    .scroll(top)
                    .render(frame, frame.area());
            } else {
                frame.render_widget(
                    Paragraph::new(text).block(block).scroll((top, 0)),
                    frame.area(),
                );
            }
            map = Some(built);
        })
        .expect("draw");
        (term.backend().buffer().clone(), map.expect("地図"))
    }

    fn sample() -> Vec<Line<'static>> {
        vec![
            Line::raw("short"),
            Line::raw("the quick brown fox jumps over the lazy dog again and again"),
            Line::raw(""),
            Line::raw(format!("{} 全角の語が続く行です", "あ".repeat(12))),
            Line::from(vec![
                Span::raw("tab\there "),
                Span::styled("styled", Style::new().fg(Color::Red)),
                Span::raw(" end"),
            ]),
            Line::raw(crate::spilling_line(20)),
        ]
    }

    /// **地図が指す場所には、本当にその文字が描かれている**——本物の描画（`Wrapped`/`Paragraph`）の画面と、
    /// 色を埋めて描き直した地図を突き合わせる。幅・送り位置・折り返すかを変える。
    #[test]
    fn the_map_matches_the_drawn_screen() {
        let lines = sample();
        for wrapped in [true, false] {
            for width in [12u16, 17, 22, 23, 40] {
                for top in [0u16, 1, 3, 7] {
                    let (buffer, map) = drawn(&lines, width, 8, top, wrapped);
                    assert!(!map.rows.is_empty(), "幅{width} 位置{top}: 地図が空");
                    for row in &map.rows {
                        let graphemes: Vec<&str> = lines[row.line]
                            .styled_graphemes(Style::default())
                            .map(|g| g.symbol)
                            .collect();
                        for glyph in &row.glyphs {
                            assert_eq!(
                                buffer[(glyph.x, row.y)].symbol(),
                                graphemes[glyph.index],
                                "折り返し{wrapped} 幅{width} 位置{top}: ({}, {})",
                                glyph.x,
                                row.y
                            );
                        }
                    }
                    // 地図に無い文字のセルは、枠線か空白だけ（描かれた文字を地図が取りこぼしていない）。
                    for y in 1..7u16 {
                        for x in 1..width - 1 {
                            let mapped = map
                                .rows
                                .iter()
                                .filter(|r| r.y == y)
                                .flat_map(|r| &r.glyphs)
                                .any(|g| g.x <= x && x < g.x + g.width);
                            let symbol = buffer[(x, y)].symbol();
                            if !mapped {
                                assert!(
                                    symbol == " " || symbol.is_empty(),
                                    "折り返し{wrapped} 幅{width} 位置{top}: ({x}, {y})の「{symbol}」が地図に無い"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// 地図の表示行の頭と末尾が行の文字を漏れなく分ける（ある表示行の末尾が次の表示行の頭）。
    #[test]
    fn the_rows_of_a_line_partition_its_characters() {
        let lines = sample();
        let (_, map) = drawn(&lines, 14, 40, 0, true);
        for (line, text) in lines.iter().enumerate() {
            let rows: Vec<&Row> = map.rows.iter().filter(|r| r.line == line).collect();
            let len = text.styled_graphemes(Style::default()).count();
            assert_eq!(rows.first().map(|r| r.start), Some(0), "{line}行目の頭");
            assert_eq!(rows.last().map(|r| r.end), Some(len), "{line}行目の末尾");
            for pair in rows.windows(2) {
                assert_eq!(pair[0].end, pair[1].start, "{line}行目の表示行の継ぎ目");
            }
        }
    }

    /// 制御文字は描かれないので数えない（タブの後ろの文字の番号がずれない）。取り出しにも入らない。
    #[test]
    fn control_characters_are_neither_counted_nor_extracted() {
        let line = Line::raw("a\tb");
        assert_eq!(line.styled_graphemes(Style::default()).count(), 2);
        let text = Text::from(vec![line]);
        let all = extract(&text, (Pos::default(), Pos { line: 0, offset: 2 }));
        assert_eq!(all, "ab");
    }

    /// 押した文字から今の文字まで（両端を含む）。逆向きにずらしても同じ範囲。文字の無い1点同士は空。
    #[test]
    fn the_span_includes_both_ends_in_either_direction() {
        let at = |line, offset| Pos { line, offset };
        let forward = span(Hit::glyph(0, 2), Hit::glyph(1, 3));
        assert_eq!(forward, Some((at(0, 2), at(1, 4))));
        let backward = span(Hit::glyph(1, 3), Hit::glyph(0, 2));
        assert_eq!(backward, Some((at(0, 2), at(1, 4))));
        assert_eq!(
            span(Hit::glyph(0, 5), Hit::glyph(0, 5)),
            Some((at(0, 5), at(0, 6)))
        );
        assert_eq!(span(Hit::caret(0, 5), Hit::caret(0, 5)), None);
    }

    /// 選んだ範囲は、色を重ねても折り返しが変わらず（地図が同じ）、範囲の文字だけが選択の色になる。
    #[test]
    fn highlighting_changes_colours_but_not_where_characters_are() {
        let lines = sample();
        let mut term = Terminal::new(TestBackend::new(20, 10)).expect("test terminal");
        let block = Block::default().borders(Borders::ALL);
        let inner = block.inner(Rect::new(0, 0, 20, 10));
        let text = Text::from(lines.clone());
        let heights = heights_of(text.clone(), inner.width);
        let shape = |heights| Shape {
            inner,
            heights,
            top: 0,
            wrapped: true,
        };
        let (_, plain) = prepare(text.clone(), shape(&heights), None);
        let mark = Mark {
            anchor: Hit::glyph(1, 4),
            head: Head::Fixed(Hit::glyph(1, 18)),
        };
        let (marked_text, marked) = prepare(text, shape(&heights), Some(mark));
        assert_eq!(plain.rows, marked.rows, "色を重ねたら文字の場所が変わった");
        assert_eq!(
            marked.marked.as_ref().map(|m| m.text.as_str()),
            Some("quick brown fox")
        );
        term.draw(|frame| {
            Wrapped::new(marked_text)
                .block(block.clone())
                .render(frame, frame.area());
        })
        .expect("draw");
        let buffer = term.backend().buffer();
        for row in marked.rows.iter().filter(|r| r.line == 1) {
            for glyph in &row.glyphs {
                let selected = (4..19).contains(&glyph.index);
                assert_eq!(
                    buffer[(glyph.x, row.y)].bg == Color::Blue,
                    selected,
                    "{}番目の文字",
                    glyph.index
                );
            }
        }
    }

    /// 色の入れ替えの行（承認ダイアログの候補のカーソル）にある文字を選んでも、選んだ文字は入れ替えの見た目にならない
    /// （押されているボタン・一覧のいまの行と見分けが付く）。選んでいない文字の入れ替えはそのまま。
    #[test]
    fn a_selected_character_on_a_reversed_line_loses_the_reversal() {
        let line = Line::styled("cursor row", Style::new().add_modifier(Modifier::REVERSED));
        let marked = highlighted(&line, 0, 6);
        let styles: Vec<Style> = marked
            .styled_graphemes(Style::default())
            .map(|g| g.style)
            .collect();
        assert_eq!(styles[0].bg, Some(Color::Blue));
        assert!(!Style::default()
            .patch(styles[0])
            .add_modifier
            .contains(Modifier::REVERSED));
        assert!(Style::default()
            .patch(styles[7])
            .add_modifier
            .contains(Modifier::REVERSED));
    }

    /// 枠の外は枠の端へ寄せる: 上は見えている最初の表示行の頭、下は最後の表示行の末尾、左右は表示行の頭と末尾。
    #[test]
    fn a_pointer_outside_the_box_is_pulled_to_its_edge() {
        let lines = sample();
        let (_, map) = drawn(&lines, 14, 6, 2, true);
        let first = &map.rows[0];
        let last = map.rows.last().expect("表示行");
        assert_eq!(map.hit(5, 0), Some(Hit::caret(first.line, first.start)));
        assert_eq!(map.hit(5, 30), Some(Hit::caret(last.line, last.end)));
        assert_eq!(
            map.hit(0, first.y),
            Some(Hit::caret(first.line, first.start))
        );
        assert_eq!(
            map.hit(60, first.y),
            Some(Hit::caret(first.line, first.end))
        );
        assert_eq!(TextMap::default().hit(1, 1), None, "文字が無い地図");
    }
}
