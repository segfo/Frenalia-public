//! `AppState`から毎フレーム全ウィジェットを再描画する（即時モード、§リッチTUI）。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{AppState, ToolCardStatus, TranscriptItem};

pub fn render(f: &mut Frame, app: &AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(f.area());

    render_transcript(f, root[0], app);
    render_status(f, root[1], app);
    render_input(f, root[2], app);

    if let Some(pending) = &app.pending_permission {
        render_permission_modal(f, f.area(), pending);
    } else {
        // 端末の実カーソルを入力欄の入力末尾へ明示的に置く。ratatuiは`set_cursor_position`を
        // 呼ばない限りカーソルを隠したままにするため、これを怠るとOS/端末のIME（日本語等の
        // 変換候補ウィンドウ）が「前回カーソルがあった場所」（起動直後は画面右下等）に出てしまい、
        // 入力ボックスと無関係な位置に文字が表示されるように見える不具合が起きる。
        set_input_cursor(f, root[2], app);
    }
}

fn set_input_cursor(f: &mut Frame, area: Rect, app: &AppState) {
    // 枠線ぶん+1、入力済みテキストの表示幅ぶん右へ（全角文字は2セル分としてIME側の位置計算と
    // 一致させる。§リッチTUI「入力ボックス」）。
    let text_width = UnicodeWidthStr::width(app.input.as_str()) as u16;
    let x = area.x + 1 + text_width;
    let y = area.y + 1;
    f.set_cursor_position((x.min(area.x + area.width.saturating_sub(2)), y));
}

fn transcript_lines(app: &AppState) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for item in &app.transcript {
        match item {
            TranscriptItem::User(text) => {
                lines.push(Line::from(Span::styled(
                    format!("> {text}"),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
            }
            TranscriptItem::Assistant(text) => {
                for l in text.lines() {
                    lines.push(Line::from(l.to_string()));
                }
                if text.is_empty() {
                    lines.push(Line::from(""));
                }
            }
            TranscriptItem::Thinking(text) => {
                for l in text.lines() {
                    lines.push(Line::from(Span::styled(
                        format!("  {l}"),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    )));
                }
            }
            TranscriptItem::ToolCard {
                name,
                input,
                status,
                ..
            } => {
                lines.push(Line::from(Span::styled(
                    format!("┌─ tool: {name} ─────"),
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(format!("│ input: {input}")));
                match status {
                    ToolCardStatus::Running => {
                        lines.push(Line::from(Span::styled(
                            "│ ... running",
                            Style::default().fg(Color::Yellow),
                        )));
                    }
                    ToolCardStatus::Done { is_error, output } => {
                        let color = if *is_error { Color::Red } else { Color::Green };
                        for l in output.lines() {
                            lines.push(Line::from(Span::styled(
                                format!("│ {l}"),
                                Style::default().fg(color),
                            )));
                        }
                    }
                }
                lines.push(Line::from(Span::styled(
                    "└─────────────────────",
                    Style::default().fg(Color::Yellow),
                )));
            }
            TranscriptItem::Error(message) => {
                lines.push(Line::from(Span::styled(
                    format!("error: {message}"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            }
        }
    }
    lines
}

fn render_transcript(f: &mut Frame, area: Rect, app: &AppState) {
    let lines = transcript_lines(app);
    let total = lines.len() as u16;
    let viewport = area.height.saturating_sub(2);
    let scroll = total.saturating_sub(viewport);

    let block = Block::default().borders(Borders::ALL).title("transcript");
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(paragraph, area);
}

fn render_status(f: &mut Frame, area: Rect, app: &AppState) {
    let stop = app
        .last_stop_reason
        .as_ref()
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "-".to_string());
    let text = format!(
        " {} | model={} | stop={} | tokens in={} out={}",
        app.provider_label,
        app.model,
        stop,
        app.last_usage.input,
        app.last_usage.output,
    );
    let paragraph = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::Black).bg(Color::Gray),
    )));
    f.render_widget(paragraph, area);
}

fn render_input(f: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default().borders(Borders::ALL).title("input (Enter=送信, Ctrl-C=終了)");
    let paragraph = Paragraph::new(app.input.as_str()).block(block);
    f.render_widget(paragraph, area);
}

fn render_permission_modal(f: &mut Frame, area: Rect, pending: &crate::app::PermissionView) {
    let rect = centered_rect(70, 40, area);
    f.render_widget(Clear, rect);
    let lines = vec![
        Line::from(Span::styled(
            format!("tool: {}  risk: {:?}", pending.tool, pending.risk),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(pending.input.clone()),
        Line::from(""),
        Line::from("[y] allow once   [a] allow always"),
        Line::from("[n] deny once    [d] deny always"),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title("permission required")
        .style(Style::default().fg(Color::White).bg(Color::Black));
    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(paragraph, rect);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
