//! セッション選択ピッカー（Fork/一覧・resume UX、M9拡張）。
//!
//! 引数なし`--resume`での起動時ピッカーと、対話中の`/sessions`スラッシュコマンドの
//! 両方から使う共用ロジック。既にオルタネートスクリーン+raw modeへ入っている
//! `Terminal`/`EventStream`をそのまま借りて描画し、選択完了で呼び出し元へ返す。

use std::io::{self, Stdout};
use std::path::Path;

use crossterm::event::{Event as CEvent, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

use harness_core::Message;
use harness_engine::{SessionStore, SessionSummary};

/// ピッカーの選択結果。
pub enum PickerOutcome {
    /// 既存セッションをそのまま復元する。
    Selected(SessionStore, Vec<Message>),
    /// 既存セッションをForkして復元する（元は不変）。
    Forked {
        source_id: String,
        session: SessionStore,
        messages: Vec<Message>,
    },
    /// Escでキャンセル（呼び出し元が用意した既定のセッションをそのまま使う）。
    Cancelled,
}

/// `term`/`term_events`は呼び出し側が既に`TerminalGuard::enter`済みであることを前提とする。
pub async fn run_picker(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    term_events: &mut EventStream,
    sessions_dir: &Path,
) -> io::Result<PickerOutcome> {
    let summaries = SessionStore::list(sessions_dir)?;
    let mut selected: usize = 0;

    loop {
        term.draw(|f| render_picker(f, &summaries, selected))?;

        let Some(Ok(ev)) = term_events.next().await else {
            return Ok(PickerOutcome::Cancelled);
        };
        let CEvent::Key(key) = ev else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => {
                if !summaries.is_empty() {
                    selected = (selected + 1).min(summaries.len() - 1);
                }
            }
            KeyCode::Esc => return Ok(PickerOutcome::Cancelled),
            KeyCode::Enter => {
                if let Some(s) = summaries.get(selected) {
                    let store = SessionStore::open(s.path.clone());
                    let messages = store.load_messages()?;
                    return Ok(PickerOutcome::Selected(store, messages));
                }
            }
            KeyCode::Char('f') => {
                if let Some(s) = summaries.get(selected) {
                    let forked = SessionStore::fork_from(sessions_dir, &s.path)?;
                    let messages = forked.load_messages()?;
                    return Ok(PickerOutcome::Forked {
                        source_id: s.id.clone(),
                        session: forked,
                        messages,
                    });
                }
            }
            _ => {}
        }
    }
}

fn render_picker(f: &mut ratatui::Frame, summaries: &[SessionSummary], selected: usize) {
    let area = f.area();
    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).split(area);

    let items: Vec<ListItem> = if summaries.is_empty() {
        vec![ListItem::new("(no saved sessions)")]
    } else {
        summaries
            .iter()
            .map(|s| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<16}", s.id), Style::default().fg(Color::Yellow)),
                    Span::raw(format!(" ({} msgs) ", s.message_count)),
                    Span::raw(s.first_prompt.clone()),
                ]))
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Resume session (Enter=open, f=fork, Esc=new)"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut state = ListState::default();
    if !summaries.is_empty() {
        state.select(Some(selected));
    }
    f.render_stateful_widget(list, chunks[0], &mut state);

    let help = Paragraph::new("↑/↓ move  Enter select  f fork  Esc start new session");
    f.render_widget(help, chunks[1]);
}
