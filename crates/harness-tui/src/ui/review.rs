//! レビューパネルの描画（一覧＋ハンク分割されたdiff）。
//!
//! **面ごとの語彙をここに書かない**——見出し・キー説明・全破棄の有無は
//! [`ReviewPanelState`]が値として持っており、この描画は行と`diff_view()`をそのまま
//! 色付けするだけである（`crate::app::review`のモジュールdoc参照）。
//!
//! diffペインは**折り返さない**（長い行は右で切る）。`Paragraph`のスクロール量は
//! 折り返し後の行数で数えられるため、折り返すと`diff_view()`の論理行番号と食い違い、
//! ハンクカーソルへの追従（`diff_scroll`）がずれるからである。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use harness_sandbox::textdiff::DiffKind;

use crate::app::{ReviewDiffLine, ReviewFocus, ReviewPanelState};

pub(super) fn render_review_panel(f: &mut Frame, area: Rect, panel: &ReviewPanelState) {
    let rect = super::centered_rect(90, 80, area);
    f.render_widget(Clear, rect);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(rect);

    render_list(f, cols[0], panel);
    render_diff(f, cols[1], panel);
}

fn focus_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn render_list(f: &mut Frame, area: Rect, panel: &ReviewPanelState) {
    let lines: Vec<Line> = if panel.rows.is_empty() {
        vec![Line::from("(nothing to review)")]
    } else {
        panel
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
                let color = if row_rejected {
                    Color::DarkGray
                } else {
                    Color::White
                };
                Line::from(Span::styled(
                    format!("{cursor}{mark} {} {}", row.badge, row.label),
                    Style::default().fg(color),
                ))
            })
            .collect()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border(panel.focus == ReviewFocus::List))
        .title(format!("{} ({})", panel.title, panel.key_hint));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_diff(f: &mut Frame, area: Rect, panel: &ReviewPanelState) {
    // ハンクがrejectされている間は本文もくすませる（見出しの`[ ]`だけだと、
    // 長いハンクをスクロールしている最中にどちら側を見ているのか分からなくなる）。
    let mut accepted = true;
    let lines: Vec<Line> = panel
        .diff_view()
        .into_iter()
        .map(|line| match line {
            ReviewDiffLine::Header {
                accepted: is_accepted,
                selected,
                text,
                ..
            } => {
                accepted = is_accepted;
                let mut style = Style::default().fg(Color::Cyan);
                if selected {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                Line::from(Span::styled(text, style))
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

    let hunk_hint = match panel.selected_row() {
        Some(row) if row.review.hunks_selectable() => format!(
            "diff — {} hunk(s) (Tab=focus, ↑↓=hunk, Enter/Space=toggle hunk)",
            row.review.hunks.len()
        ),
        _ => "diff".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border(panel.focus == ReviewFocus::Diff))
        .title(hunk_hint);
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((panel.diff_scroll, 0)),
        area,
    );
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

    fn rendered(panel: &ReviewPanelState) -> String {
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| super::render_review_panel(f, f.area(), panel))
            .unwrap();
        let buffer = term.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
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

    /// スクロール位置が内容の末尾付近でも描画がパニックしない（`Paragraph::scroll`は
    /// 内容行数を超える値を渡しても空を描くだけだが、ここを実際に通しておく）。
    #[test]
    fn scrolling_to_the_end_does_not_panic() {
        let mut panel = two_hunk_panel();
        panel.diff_scroll = panel.diff_view().len() as u16 - 1;
        let screen = rendered(&panel);
        assert!(screen.contains("a.txt"), "{screen}");
    }

    /// 空のパネル（レビュー対象なし）でも落ちない。
    #[test]
    fn an_empty_panel_renders_a_placeholder() {
        let screen = rendered(&ReviewPanelState::changes(Vec::new(), None));
        assert!(screen.contains("nothing to review"), "{screen}");
    }
}
