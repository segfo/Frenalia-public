//! 承認待ち（`F2`）の「遷移・観測から」の**位置の行**の描画（P4.3）。状態とキーは[`crate::tui::transition_positions`]。
//!
//! 割り付けは平らな一覧（[`crate::tui::transition_screen`]）と同じ3段——上に遷移先の欄、真ん中に一覧、下に説明欄
//! ——で、押せる場所・送れる枠も同じ種類で登録する（同じタブの中で操作系を変えない、決定62）。違うのは、欄が
//! **選んでいる位置の遷移先**を直すこと（平らな一覧の欄は1回の確定の全部の辺に効く）と、行が木の字下げを持つこと。
//! チェックの記号は[`crate::tui::checkbox_tree`]から借りる（`[x]`＝確定したらこの位置で起こせる）。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, ListItem, ListState, Paragraph};
use ratatui::Frame;

use harness_policy::position_domains::PositionSource;

use crate::position_view::{EdgeVerdict, PositionRow};
use crate::tui::checkbox_tree::Mark;
use crate::tui::pointer::{register_rows, Click, Field, Hot, ListId, Targets};
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::App;
use crate::tui::transition_positions::PositionsState;
use crate::tui::transition_screen::{file_name, truncate};
use crate::tui::wrap;

/// 下の枠（「この画面」）の高さの下限（平らな一覧と同じ。枠線2＋中身6）。
const NOTES_FLOOR: u16 = 8;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let mut feedback = crate::tui::DrawFeedback::default();
    let Some(positions) = app.pending.positions.as_ref() else {
        return feedback;
    };
    let notes = notes_text(app, positions);
    let height = wrap::box_height(notes.as_str(), area.width, NOTES_FLOOR, area.height / 2);
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(height),
    ])
    .split(area);
    draw_destination(frame, chunks[0], positions);
    feedback
        .targets
        .click(chunks[0], Click::Field(Field::Destination));
    feedback.candidate_list_offset = Some(draw_list(
        frame,
        chunks[1],
        app,
        positions,
        &mut feedback.targets,
    ));
    feedback
        .targets
        .wheel(chunks[2], Wheel::Panel(Panel::TransitionNotes));
    feedback.panels.set(
        Panel::TransitionNotes,
        harness_term::scrollable::draw(
            frame,
            chunks[2],
            notes,
            Block::default().borders(Borders::ALL).title(" この画面 "),
            app.panels.top(Panel::TransitionNotes),
            wrap::panel_look(Style::default()),
            harness_term::select::Selectable::new(
                &mut feedback.targets,
                Wheel::Panel(Panel::TransitionNotes),
                &app.selection,
            ),
        ),
    );
    feedback
}

/// 選んでいる位置の遷移先の欄。欄に居る間は打っている名前、居ないときはいまの遷移先を出す。
fn draw_destination(frame: &mut Frame, area: Rect, positions: &PositionsState) {
    let focused = positions.editing.is_some();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(" 選んだ位置の遷移先（Tab で編集。Enter で決める。子の行の遷移元も一緒に変わる） ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let line = match (&positions.editing, positions.selected_index()) {
        (Some(input), _) => Line::from(Span::styled(
            input.text().to_string(),
            Style::default().fg(Color::White),
        )),
        (None, Some(index)) => {
            let position = &positions.view.assignment.positions[index];
            Line::from(vec![
                Span::styled(
                    positions.destination_name(position).to_string(),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(
                        "   {} から {}",
                        positions.source_name(position),
                        file_name(&position.exe)
                    ),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        }
        (None, None) => Line::from(""),
    };
    frame.render_widget(Paragraph::new(line), inner);
    if let Some(input) = &positions.editing {
        frame.set_cursor_position(ratatui::layout::Position::new(
            inner.x + input.cursor_col(),
            inner.y,
        ));
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
fn draw_list(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    positions: &PositionsState,
    targets: &mut Targets,
) -> usize {
    let (writes, total) = positions.counts();
    // **件数を必ず見出しに出す**（「無い」と「隠している」を区別する、`B-09`）。
    let title = format!(
        " 位置ごとの遷移（記録: {}） 書くもの {writes}件 / 全 {total}件（表示: {}） ",
        positions.view.session_id,
        positions.filter.label()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);

    let visible = positions.visible();
    if visible.is_empty() {
        let text = if total == 0 {
            "この記録には割り当てた位置がありません（下の枠の件数を見てください）。".to_string()
        } else {
            format!("書く位置はありません（全{total}件は既にある辺です）。f を押すと全部が出ます。")
        };
        harness_term::wrap::Wrapped::new(text)
            .block(block)
            .render(frame, area);
        return app.candidate_list_offset;
    }

    let lines: Vec<Line> = visible.iter().map(|row| row_line(positions, row)).collect();
    // 先頭のspanは字下げ、チェックの記号は2つ目（[`row_line`]）。
    let hot: Vec<Hot> = lines
        .iter()
        .map(|line| Hot::of(&line.spans, Some(1), None))
        .collect();
    let items: Vec<ListItem> = lines.into_iter().map(ListItem::new).collect();
    let mut state = ListState::default().with_offset(app.candidate_list_offset);
    state.select(Some(positions.row));
    let rows = harness_term::list::draw(
        frame,
        area,
        items,
        Some(block),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut state,
    );
    register_rows(targets, ListId::Positions, &rows, &hot);
    state.offset()
}

/// 1行: 字下げ・チェック・実行ファイル・引数・回数・遷移先・出どころ・書けない理由・予約。
///
/// **引数の欄は書く辺の引数**（絞っていなければ任意の引数）——平らな一覧の`argv_label`と同じく、観測した綴りを
/// 出すと「その引数だけ許す」と読まれる。記録したコマンドラインは下の枠に出す。
fn row_line<'a>(positions: &'a PositionsState, row: &PositionRow) -> Line<'a> {
    let position = &positions.view.assignment.positions[row.position];
    let verdict = positions
        .verdicts
        .get(row.position)
        .cloned()
        .unwrap_or(EdgeVerdict::Writable);
    let reserved = positions.is_reserved(position);
    let blocked = !verdict.is_writable() || row.startable.note().is_some();
    let mark = if position.source == PositionSource::ExistingEdge || reserved {
        Mark::All
    } else if blocked {
        Mark::NotApplicable
    } else {
        Mark::None
    };
    let argv = if positions.is_narrowed(position) {
        truncate(&position.command_lines[0], 40)
    } else {
        harness_policy::transition_listing::ANY_ARGV.to_string()
    };
    let source = match position.source {
        PositionSource::ExistingEdge => "宣言済み",
        PositionSource::Proposed => "新規",
        PositionSource::ReplacesSelfLoop => "自己ループ辺を置き換え",
    };
    let mut spans = vec![
        Span::raw("  ".repeat(row.depth)),
        mark.span(),
        Span::raw(format!(" {:<20}", file_name(&position.exe))),
        Span::styled(format!(" {argv:<24}"), Style::default().fg(Color::Gray)),
        Span::styled(
            format!(" {:>4}回", position.instances.len()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("  → {}", positions.destination_name(position)),
            Style::default().fg(Color::White),
        ),
        Span::styled(format!("  {source}"), Style::default().fg(Color::DarkGray)),
    ];
    if row.startable.note().is_some() {
        spans.push(Span::styled(
            "  ［この綴りは起こせない］".to_string(),
            Style::default().fg(Color::Red),
        ));
    }
    if let Some(note) = verdict.note() {
        spans.push(Span::styled(
            format!("  ［{note}］"),
            Style::default().fg(Color::Yellow),
        ));
    }
    if reserved {
        spans.push(Span::styled(
            "  ← 許します".to_string(),
            Style::default().fg(Color::Green),
        ));
    }
    Line::from(spans)
}

/// 説明欄の中身。並びは平らな一覧と同じく「最初に見えていなければならない順」——(1)ACEの注記→(2)予約と操作→
/// (3)読めなかった・割り当てなかった事実→(4)選んでいる位置の詳しいこと（`tui::transition_screen::notes_text`のdoc）。
fn notes_text(app: &App, positions: &PositionsState) -> String {
    // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
    let mut text = format!("{}\n", crate::transition_approve::ACE_NOTICE);
    if positions.editing.is_some() {
        text.push_str("遷移先の名前を入力中です（Enter で決める・空のまま Enter でやめる）。\n");
    } else if positions.approve.is_empty() {
        text.push_str("Spaceで選ぶ／Tabで遷移先／uで引数の広さ／fで表示の切替／rで読み直し。\n");
    } else {
        text.push_str(&format!(
            "位置 {}件を予約中（位置ごとの承認は P4.5 で1回の確定にまとめます。いまは a で書けません）。\n",
            positions.approve.len()
        ));
    }
    for note in positions.view.notes.iter().chain(app.pending.notes.iter()) {
        text.push_str(note);
        text.push('\n');
    }
    if let Some(index) = positions.selected_index() {
        let position = &positions.view.assignment.positions[index];
        if let Some(row) = positions.view.rows.iter().find(|row| row.position == index) {
            if let Some(note) = row.startable.note() {
                text.push_str(note);
                text.push('\n');
            }
        }
        if let Some(EdgeVerdict::Widens { detail } | EdgeVerdict::Rejected { detail }) =
            positions.verdicts.get(index)
        {
            text.push_str(&format!("書けない理由（検査）: {detail}\n"));
        }
        text.push_str(&format!(
            "選択中: {} から {}（→ {}）\n",
            positions.source_name(position),
            position.exe,
            positions.destination_name(position)
        ));
        let lines = &position.command_lines;
        text.push_str(&format!("  記録したコマンドライン {}通り", lines.len()));
        for line in lines.iter().take(3) {
            text.push_str(&format!("\n    {line}"));
        }
        if lines.len() > 3 {
            text.push_str(&format!("\n    ほか {}通り", lines.len() - 3));
        }
        if position.argv_missing > 0 || position.argv_truncated > 0 {
            text.push_str(&format!(
                "\n  引数が結び付かなかった起動 {}回・切り詰めの疑い {}回",
                position.argv_missing, position.argv_truncated
            ));
        }
    }
    text
}
