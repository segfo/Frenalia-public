//! レビューパネルの描画（一覧＋ハンク分割されたdiff）。
//!
//! **面ごとの語彙をここに書かない**——見出し・キー説明・全破棄の有無は
//! [`ReviewPanelState`]が値として持っており、この描画は行と`diff_view()`をそのまま
//! 色付けするだけである（`crate::app::review`のモジュールdoc参照）。
//!
//! diffペインは**折り返さない**（長い行は右で切る）。`Paragraph`のスクロール量は
//! 折り返し後の行数で数えられるため、折り返すと`diff_view()`の論理行番号と食い違い、
//! ハンクカーソルへの追従（`diff_scroll`）がずれるからである。
//!
//! # 送れる枠と押せる場所（ポリシーエディタと共有の部品）
//!
//! - 一覧は`harness_term::list`で描く（選んだ行が必ず見え、各行が描かれた場所が返る）。全行を1つの
//!   `Paragraph`に入れていた頃は、枠より下の行が**黙って切れ**、そこを選んでも見えなかった。
//! - 差分ペインは`harness_term::scrollable::draw_unwrapped`で描く。送る上限は「最後の行が枠の一番下」
//!   （[BUG-204](../../../../docs/bugs/BUG-204.md)。ポリシーエディタのBUG-196と同じ形）。
//! - どちらも入り切らないときだけ、右の枠線の上にスクロールバーを出す。
//! - キーの案内はパネルの一番下の枠に並べる（入り切らない項目は次の行へ）。一覧の枠の見出しに入れていた頃は、
//!   一覧の枠の幅（パネルの4割）で右が切れ、`c=commit`・`Esc=close`が画面に出ていなかった。案内の枠は2つの
//!   ペインの下に付け、外側の角を`├`/`┤`にして1つの面に見せる（承認ダイアログの本文と選択肢の仕切りと同じ）。
//!
//! 押せる場所は、一覧の行（選ぶ）と取り込みの印・差分のハンクの見出し（選ぶ）とその印・ペイン（フォーカス）・
//! 案内の項目（そのキー）。ホイールはポインタの下のペインを送る（`crate::app::pointer`）。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, ListItem, ListState, Paragraph};
use ratatui::Frame;

use harness_sandbox::textdiff::DiffKind;
use harness_term::scrollable::{Look, Window};
use harness_term::select::{Selectable, Selection};

use crate::app::{
    Click, ReviewDiffLine, ReviewDrawn, ReviewFocus, ReviewPanelState, Targets, Wheel,
};

/// レビューパネルを描き、描いて分かったこと（差分ペインの上限・一覧の表示位置）を返す。押せる場所と送れる枠を
/// `targets`へ登録する（呼び出し側は、後ろの画面を先に覆っておく。`crate::ui::render`）。
pub(super) fn render_review_panel(
    f: &mut Frame,
    area: Rect,
    panel: &ReviewPanelState,
    targets: &mut Targets,
    selection: &Selection<Wheel>,
) -> ReviewDrawn {
    let rect = super::centered_rect(90, 80, area);
    // 後ろの画面の全角文字に左の枠線が欠けないよう、共有の部品で消す（`harness_term::overlay`）。
    harness_term::overlay::clear(f, rect);
    targets.cover(rect);

    // キーの案内はパネルの一番下の枠（案内の行＋下の枠線）。2つのペインには少なくとも枠線2行＋1行を残す。
    // 案内は文字のまま描く（承認ダイアログの選択肢のようなボタンにはしていない。`super::HintLook`）。
    let look = super::HintLook::Text(Style::default().fg(Color::DarkGray));
    let hint_rows = super::hint_rows(&panel.key_hints, look, rect.width.saturating_sub(2))
        .min(rect.height.saturating_sub(4));
    let hint_height = if hint_rows == 0 { 0 } else { hint_rows + 1 };
    let [panes, hints] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(hint_height)]).areas(rect);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(panes);

    let joined = hint_height > 0;
    let list_offset = render_list(f, cols[0], panel, joined, targets);
    let diff_max = render_diff(f, cols[1], panel, joined, targets, selection);
    if joined {
        let block = Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM);
        let inner = block.inner(hints);
        f.render_widget(block, hints);
        super::draw_hints(f, inner, &panel.key_hints, look, targets);
    }
    ReviewDrawn {
        diff_max,
        list_offset,
    }
}

/// ペインの枠。`joined`なら、下に付く案内の枠とつながるよう外側の下の角を`├`（一覧）か`┤`（差分）にする。
fn pane_block<'a>(
    title: impl Into<Line<'a>>,
    focused: bool,
    joined: bool,
    left: bool,
) -> Block<'a> {
    let mut set = symbols::border::PLAIN;
    if joined {
        if left {
            set.bottom_left = symbols::line::VERTICAL_RIGHT;
        } else {
            set.bottom_right = symbols::line::VERTICAL_LEFT;
        }
    }
    Block::default()
        .borders(Borders::ALL)
        .border_set(set)
        .border_style(focus_border(focused))
        .title(title)
}

fn focus_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// 一覧を描き、表示を始める位置（描いた後の`ListState::offset`）を返す。
fn render_list(
    f: &mut Frame,
    area: Rect,
    panel: &ReviewPanelState,
    joined: bool,
    targets: &mut Targets,
) -> usize {
    let focused = panel.focus == ReviewFocus::List;
    let border = focus_border(focused);
    let block = pane_block(panel.title.clone(), focused, joined, true);
    // ペインのどこを押してもフォーカスがここへ移る（行と印はこの上に重ねて登録する）。
    targets.click(area, Click::ReviewPane(ReviewFocus::List));
    targets.wheel(area, Wheel::ReviewList);
    if panel.rows.is_empty() {
        f.render_widget(Paragraph::new("(nothing to review)").block(block), area);
        return 0;
    }

    // 行の中の取り込みの印の桁（行の左端から何桁目に何桁）。行は`List`が描くので、ratatuiが行を描く規則で求める
    // （`harness_term::row::spans_in`。ポリシーエディタの一覧の`[x]`と同じ）。
    let mut marks = Vec::with_capacity(panel.rows.len());
    let items: Vec<ListItem> = panel
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let row_rejected = panel.rejected.contains(&i);
            let partial = !row_rejected
                && panel
                    .rejected_hunks
                    .get(&i)
                    .is_some_and(|set| !set.is_empty());
            let mark = if row_rejected {
                "[ ]"
            } else if partial {
                // 一部のハンクだけを採る行は、全採用と見分けが付く印にする。
                "[~]"
            } else {
                "[x]"
            };
            let cursor = if i == panel.selected { ">" } else { " " };
            let style = Style::default().fg(if row_rejected {
                Color::DarkGray
            } else {
                Color::White
            });
            let spans = vec![
                Span::styled(cursor, style),
                Span::styled(mark, style),
                Span::styled(format!(" {} {}", row.badge, row.label), style),
            ];
            marks.push(harness_term::row::spans_in(Rect::new(0, 0, u16::MAX, 1), &spans)[1]);
            ListItem::new(Line::from(spans))
        })
        .collect();

    let visible = usize::from(block.inner(area).height);
    let mut state = ListState::default()
        .with_offset(panel.list_offset)
        .with_selected(Some(panel.selected));
    // 選んだ行の強調は行頭の`>`が受け持つ（以前と同じ見た目。`List`の強調の色は付けない）。
    let rows = harness_term::list::draw(f, area, items, Some(block), Style::default(), &mut state);
    harness_term::scrollable::draw_scrollbar(
        f,
        area,
        Window::new(
            panel.rows.len(),
            visible,
            u16::try_from(state.offset()).unwrap_or(u16::MAX),
        ),
        border,
    );
    for row in &rows {
        targets.click(row.area, Click::ReviewRow(row.index));
        if let Some(mark) = marks.get(row.index) {
            let cell = Rect::new(row.area.x.saturating_add(mark.x), row.area.y, mark.width, 1)
                .intersection(row.area);
            targets.click(cell, Click::ReviewMark(row.index));
        }
    }
    state.offset()
}

/// 差分ペインを描き、送れる上限を返す。差分の文章はマウスで選んで写せる（ハンクの見出しは押せる場所なので、
/// そこからは選び始めない。`crate::app::select`）。
fn render_diff(
    f: &mut Frame,
    area: Rect,
    panel: &ReviewPanelState,
    joined: bool,
    targets: &mut Targets,
    selection: &Selection<Wheel>,
) -> u16 {
    // ハンクがrejectされている間は本文もくすませる（見出しの`[ ]`だけだと、
    // 長いハンクをスクロールしている最中にどちら側を見ているのか分からなくなる）。
    let mut accepted = true;
    // ハンクの見出し: 何行目か・何番目のハンクか・印の桁（行の左端から）。
    let mut headers = Vec::new();
    let lines: Vec<Line> = panel
        .diff_view()
        .into_iter()
        .enumerate()
        .map(|(i, line)| match line {
            ReviewDiffLine::Header {
                hunk,
                accepted: is_accepted,
                selected,
                mark,
                text,
            } => {
                accepted = is_accepted;
                let mut style = Style::default().fg(Color::Cyan);
                if selected {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                let spans = vec![
                    Span::styled(mark, style),
                    Span::styled(" ", style),
                    Span::styled(text, style),
                ];
                headers.push((
                    i,
                    hunk,
                    harness_term::row::spans_in(Rect::new(0, 0, u16::MAX, 1), &spans)[0],
                ));
                Line::from(spans)
            }
            ReviewDiffLine::Skipped(text) => {
                Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
            }
            ReviewDiffLine::Note(text) => {
                Line::from(Span::styled(text, Style::default().fg(Color::Yellow)))
            }
            ReviewDiffLine::Line(kind, text) => {
                let (prefix, color) = match kind {
                    DiffKind::Context => (" ", Color::Gray),
                    DiffKind::Removed => ("-", Color::Red),
                    DiffKind::Added => ("+", Color::Green),
                };
                let mut style = Style::default().fg(color);
                if !accepted {
                    style = style.add_modifier(Modifier::DIM);
                }
                Line::from(Span::styled(format!("{prefix} {text}"), style))
            }
        })
        .collect();

    let selectable = panel
        .selected_row()
        .is_some_and(|row| row.review.hunks_selectable());
    let hunk_hint = match panel.selected_row() {
        Some(row) if selectable => format!(
            "diff — {} hunk(s) (Tab=focus, ↑↓=hunk, Enter/Space=toggle hunk)",
            row.review.hunks.len()
        ),
        _ => "diff".to_string(),
    };
    let focused = panel.focus == ReviewFocus::Diff;
    let border = focus_border(focused);
    let block = pane_block(hunk_hint, focused, joined, false);
    targets.click(area, Click::ReviewPane(ReviewFocus::Diff));
    targets.wheel(area, Wheel::ReviewDiff);
    let drawn = harness_term::scrollable::draw_unwrapped(
        f,
        area,
        lines,
        block,
        panel.diff_scroll,
        Look {
            // `↑↓`はハンクか一覧の行を動かすので、差分を送る手段として書かない（B-32）。
            how: "PgUp/PgDn・ホイールで送る",
            notice: Style::default().fg(Color::DarkGray),
            bar: border,
        },
        Selectable::new(targets, Wheel::ReviewDiff, selection),
    );
    // ハンク単位の操作が使えない行では、見出しも印も押せない（`Enter`も何もしない）。
    if selectable {
        for (index, hunk, mark) in headers {
            let Some(&line) = drawn.lines.get(index) else {
                continue;
            };
            targets.click(line, Click::Hunk(hunk));
            let cell = Rect::new(
                line.x.saturating_add(mark.x),
                line.y,
                mark.width,
                line.height.min(1),
            )
            .intersection(line);
            targets.click(cell, Click::HunkMark(hunk));
        }
    }
    drawn.max_top
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::{ReviewPanelState, ReviewRow, ReviewTarget};

    fn row(label: &str, old: &str, new: &str) -> ReviewRow {
        ReviewRow {
            label: label.to_string(),
            badge: 'M',
            review: harness_sandbox::FileReview {
                hunks: harness_sandbox::textdiff::diff_hunks(old, new),
                hunk_block: None,
                workspace_hash: Some("ws".into()),
                overlay_hash: Some("ov".into()),
            },
            target: ReviewTarget::Change {
                path: label.to_string(),
            },
        }
    }

    /// パネルを1枚描き、画面（行ごと）と描いて分かったことを返す。
    fn drawn(panel: &ReviewPanelState) -> (Vec<String>, super::ReviewDrawn) {
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        let mut result = None;
        term.draw(|f| {
            result = Some(super::render_review_panel(
                f,
                f.area(),
                panel,
                &mut Default::default(),
                &Default::default(),
            ))
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let screen = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        (screen, result.expect("描いた"))
    }

    fn rendered(panel: &ReviewPanelState) -> String {
        drawn(panel).0.join("\n")
    }

    fn two_hunk_panel() -> ReviewPanelState {
        let old: String = (0..30).map(|i| format!("line{i}\n")).collect();
        let new = old
            .replace("line2\n", "CHANGED2\n")
            .replace("line25\n", "CHANGED25\n");
        ReviewPanelState::changes(vec![row("a.txt", &old, &new)], None)
    }

    /// ハンク見出し・差分行・省略行が実際に画面へ出る（スクロール0の位置）。
    #[test]
    fn the_panel_draws_hunk_headers_and_the_diff_body() {
        let screen = rendered(&two_hunk_panel());
        assert!(screen.contains("[x] hunk 1/2"), "{screen}");
        assert!(screen.contains("- line2"), "{screen}");
        assert!(screen.contains("+ CHANGED2"), "{screen}");
        assert!(screen.contains("[x] M a.txt"), "{screen}");
    }

    /// rejectしたハンクは見出しの印が変わり、行の印も`[~]`（一部採用）になる。
    #[test]
    fn a_rejected_hunk_is_visible_as_such() {
        let mut panel = two_hunk_panel();
        panel.rejected_hunks.entry(0).or_default().insert(0);
        let screen = rendered(&panel);
        assert!(screen.contains("[ ] hunk 1/2"), "{screen}");
        assert!(screen.contains("[~] M a.txt"), "{screen}");
    }

    /// 1行おきに50行を書き換えた、枠に入り切らない1つのハンクを持つパネル。
    fn long_panel() -> ReviewPanelState {
        let old: String = (0..80).map(|i| format!("line{i}\n")).collect();
        let new: String = (0..80)
            .map(|i| match (10..60).contains(&i) && i % 2 == 0 {
                true => format!("CHANGED{i}\n"),
                false => format!("line{i}\n"),
            })
            .collect();
        ReviewPanelState::changes(vec![row("a.txt", &old, &new)], None)
    }

    /// [BUG-204] **差分ペインは、最後の行が枠の一番下に来るところまでしか送れない。**
    /// 状態が上限を超えて持っていても（`diff_view()`の最後の行を一番上に置く値＝直す前の上限）、描くのは上限の
    /// 位置で、差分ペインの中の一番下の行が差分の最後の行になる。
    #[test]
    fn the_diff_pane_stops_with_the_last_line_at_the_bottom() {
        let mut panel = long_panel();
        let view = panel.diff_view();
        let Some(crate::app::ReviewDiffLine::Line(_, last)) = view.last() else {
            panic!("最後の行が差分の行でない: {view:?}");
        };
        let last = format!("  {last}");
        panel.diff_scroll = view.len() as u16 - 1;
        let (screen, result) = drawn(&panel);
        // 差分ペインの下辺（位置の案内「N〜M/T行」を持つ行）の1つ上が、ペインの中の一番下の行。
        let bottom = screen
            .iter()
            .rposition(|line| line.contains('〜'))
            .unwrap_or_else(|| {
                panic!("位置の案内が無い（入り切っている）:\n{}", screen.join("\n"))
            });
        assert!(
            screen[bottom - 1].contains(&last),
            "ペインの一番下の行が最後の行「{last}」でない:\n{}",
            screen.join("\n")
        );
        // 最後の行は1回だけ、一番下にだけ出る（枠の上の方に残って空白が続く形ではない）。
        assert_eq!(
            screen.iter().filter(|line| line.contains(&last)).count(),
            1,
            "{}",
            screen.join("\n")
        );
        assert!(
            usize::from(result.diff_max) < view.len() - 1,
            "上限が「最後の行が一番上」のまま: {result:?}"
        );
    }

    /// 空のパネル（レビュー対象なし）でも落ちない。
    #[test]
    fn an_empty_panel_renders_a_placeholder() {
        let screen = rendered(&ReviewPanelState::changes(Vec::new(), None));
        assert!(screen.contains("nothing to review"), "{screen}");
    }

    /// **キーの案内がパネルの中に全部見える**（一覧の枠の見出しに入れていた頃は、一覧の枠の幅で切れていた）。
    #[test]
    fn every_key_hint_is_on_the_screen() {
        let panel = two_hunk_panel();
        let screen = rendered(&panel);
        for hint in &panel.key_hints {
            assert!(
                screen.contains(&hint.label),
                "{}が見えない:\n{screen}",
                hint.label
            );
        }
    }
}
