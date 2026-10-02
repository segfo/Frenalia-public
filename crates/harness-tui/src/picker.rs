//! セッション選択ピッカー（Fork/一覧・resume UX、M9拡張）。
//!
//! 引数なし`--resume`での起動時ピッカーと、対話中の`/sessions`スラッシュコマンドの
//! 両方から使う共用ロジック。既にオルタネートスクリーン+raw modeへ入っている
//! `Terminal`/`EventStream`をそのまま借りて描画し、選択完了で呼び出し元へ返す。
//!
//! # マウス（会話画面と同じ部品。`crate::app::pointer`）
//!
//! 一覧の行を押すとその行を選ぶ（`↑↓`と同じ）。**選んでいる行をもう一度押すと開く**（`Enter`と同じ）。
//! 1回で開かないのは、ポリシーエディタの一覧と同じく「行を押す＝選ぶ」に揃えるため（選ぶつもりで押した行が
//! いきなり開くと、選び直す前にセッションが切り替わる）。下の案内の`Enter select`・`f fork`・`Esc …`も、
//! 押せばそのキーを押したのと同じ。一覧は`harness_term::list`で描く（選んだ行が必ず見え、各行の場所が返る）。

use std::io::{self, Stdout};
use std::path::Path;

use crossterm::event::{Event as CEvent, EventStream, KeyCode, KeyEventKind, MouseEvent};
use futures::StreamExt;
use harness_term::pointer::Pointer;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, ListItem, ListState};
use ratatui::Terminal;

use harness_core::Message;
use harness_engine::{SessionStore, SessionSummary};

use crate::app::KeyHint;

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

/// ピッカーで決まったこと（ファイルを読む前の、キーとクリックの意味だけ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Open,
    Fork,
    Cancel,
}

/// ピッカーで押せるもの。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PickerClick {
    /// 一覧の行。
    Row(usize),
    /// 案内の項目（そのキーを押す）。
    Key(KeyCode),
}

type PickerTargets = harness_term::pointer::Targets<PickerClick, ()>;

/// ピッカーの状態（選んでいる行・一覧の表示位置・直前に描いた画面の押せる場所）。
struct Picker {
    /// 一覧の件数。
    len: usize,
    selected: usize,
    list: ListState,
    targets: PickerTargets,
}

/// 何も変えないイベントか、何かを決めたか（[`Picker::handle_event`]）。
enum PickerStep {
    /// 描き直さなくてよい（キーを離した・ポインタが動いただけ）。
    Unchanged,
    Handled(Option<Choice>),
}

impl Picker {
    fn new(len: usize) -> Self {
        Self {
            len,
            selected: 0,
            list: ListState::default(),
            targets: PickerTargets::default(),
        }
    }

    /// 端末のイベント1つ（ピッカーのループと試験が同じこれを通る）。
    fn handle_event(&mut self, event: CEvent) -> PickerStep {
        match event {
            CEvent::Key(key) if key.kind == KeyEventKind::Press => {
                PickerStep::Handled(self.on_key(key.code))
            }
            CEvent::Key(_) => PickerStep::Unchanged,
            CEvent::Mouse(mouse) if !harness_term::pointer::acts(mouse.kind) => {
                PickerStep::Unchanged
            }
            CEvent::Mouse(mouse) => PickerStep::Handled(self.on_mouse(mouse)),
            _ => PickerStep::Handled(None),
        }
    }

    fn on_key(&mut self, code: KeyCode) -> Option<Choice> {
        match code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                if self.len > 0 {
                    self.selected = (self.selected + 1).min(self.len - 1);
                }
            }
            KeyCode::Esc => return Some(Choice::Cancel),
            KeyCode::Enter if self.len > 0 => return Some(Choice::Open),
            KeyCode::Char('f') if self.len > 0 => return Some(Choice::Fork),
            _ => {}
        }
        None
    }

    /// クリック（直前に描いた画面の登録で引く）。行は選ぶ、選んでいる行は開く（モジュールdoc）。
    fn on_mouse(&mut self, event: MouseEvent) -> Option<Choice> {
        match self.targets.resolve(&event)? {
            Pointer::Click(PickerClick::Row(row)) if row == self.selected => {
                self.on_key(KeyCode::Enter)
            }
            Pointer::Click(PickerClick::Row(row)) => {
                // `↑↓`と同じく、一覧の中で選ぶ（行を押せるのは描いた行だけなので、範囲の中）。
                self.selected = row.min(self.len.saturating_sub(1));
                None
            }
            Pointer::Click(PickerClick::Key(code)) => self.on_key(code),
            Pointer::Wheel { .. } => None,
        }
    }
}

/// `term`/`term_events`は呼び出し側が既に`harness_term::TerminalGuard::enter`済みであることを
/// 前提とする。
pub async fn run_picker(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    term_events: &mut EventStream,
    sessions_dir: &Path,
) -> io::Result<PickerOutcome> {
    let summaries = SessionStore::list(sessions_dir)?;
    let mut picker = Picker::new(summaries.len());

    loop {
        // 1イベントごとに描き直す（クリックは直前に描いた画面の登録で引く）。何も変えないイベントでは描かない。
        let mut targets = PickerTargets::default();
        term.draw(|f| targets = render_picker(f, &summaries, &mut picker))?;
        picker.targets = targets;

        let choice = loop {
            let Some(Ok(ev)) = term_events.next().await else {
                return Ok(PickerOutcome::Cancelled);
            };
            match picker.handle_event(ev) {
                PickerStep::Unchanged => continue,
                PickerStep::Handled(choice) => break choice,
            }
        };
        match choice {
            None => {}
            Some(Choice::Cancel) => return Ok(PickerOutcome::Cancelled),
            Some(Choice::Open) => {
                if let Some(s) = summaries.get(picker.selected) {
                    let store = SessionStore::open(s.path.clone());
                    let messages = store.load_messages()?;
                    return Ok(PickerOutcome::Selected(store, messages));
                }
            }
            Some(Choice::Fork) => {
                if let Some(s) = summaries.get(picker.selected) {
                    let forked = SessionStore::fork_from(sessions_dir, &s.path)?;
                    let messages = forked.load_messages()?;
                    return Ok(PickerOutcome::Forked {
                        source_id: s.id.clone(),
                        session: forked,
                        messages,
                    });
                }
            }
        }
    }
}

/// ピッカーの下の案内（押せばそのキー）。
fn picker_hints() -> Vec<KeyHint> {
    vec![
        KeyHint::shown("↑/↓ move"),
        KeyHint::press("Enter select", KeyCode::Enter),
        KeyHint::press("f fork", KeyCode::Char('f')),
        KeyHint::press("Esc start new session", KeyCode::Esc),
    ]
}

/// ピッカーを描き、押せる場所を返す。一覧の表示位置は`picker.list`へ書き戻る。
fn render_picker(
    f: &mut ratatui::Frame,
    summaries: &[SessionSummary],
    picker: &mut Picker,
) -> PickerTargets {
    let area = f.area();
    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).split(area);
    let mut targets = PickerTargets::default();

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
    picker
        .list
        .select((!summaries.is_empty()).then_some(picker.selected));
    let rows = harness_term::list::draw(
        f,
        chunks[0],
        items,
        Some(
            Block::default()
                .borders(Borders::ALL)
                .title("Resume session (Enter=open, f=fork, Esc=new)"),
        ),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut picker.list,
    );
    if !summaries.is_empty() {
        for row in rows {
            targets.click(row.area, PickerClick::Row(row.index));
        }
    }

    // 案内は以前と同じ「項目を2桁空けて並べた1行」。押せる項目はそのキーを押す場所にする。
    let hints = picker_hints();
    let mut spans = Vec::with_capacity(hints.len() * 2);
    let mut at = Vec::with_capacity(hints.len());
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        at.push(spans.len());
        spans.push(Span::raw(hint.label.clone()));
    }
    let drawn = harness_term::row::draw(f, chunks[1], &spans);
    for (hint, index) in hints.iter().zip(at) {
        if let Some(key) = hint.key {
            targets.click(drawn[index], PickerClick::Key(key.code));
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
    use ratatui::backend::TestBackend;

    use super::*;

    fn summaries(n: usize) -> Vec<SessionSummary> {
        (0..n)
            .map(|i| SessionSummary {
                id: format!("session-{i}"),
                path: std::path::PathBuf::from(format!("session-{i}.jsonl")),
                message_count: i,
                first_prompt: format!("prompt number {i}"),
                modified: std::time::SystemTime::UNIX_EPOCH,
            })
            .collect()
    }

    /// ピッカーを1枚描いて登録を書き戻し、画面（行ごと）を返す（ループと同じ順）。
    fn draw(picker: &mut Picker, list: &[SessionSummary]) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(80, 12)).expect("test terminal");
        let mut targets = PickerTargets::default();
        term.draw(|f| targets = render_picker(f, list, picker))
            .expect("draw");
        picker.targets = targets;
        let buffer = term.backend().buffer();
        (0..12)
            .map(|y| (0..80).map(|x| buffer[(x, y)].symbol()).collect())
            .collect()
    }

    /// 画面で`text`が描かれている最初のセル（列, 行）。
    fn cell_of(screen: &[String], text: &str) -> (u16, u16) {
        for (y, line) in screen.iter().enumerate() {
            if let Some(byte) = line.find(text) {
                let column = line[..byte].chars().count();
                return (column as u16, y as u16);
            }
        }
        panic!("「{text}」が画面に無い:\n{}", screen.join("\n"));
    }

    fn click(picker: &mut Picker, (column, row): (u16, u16)) -> PickerStep {
        picker.handle_event(CEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }))
    }

    /// **行を押すと選び（`↓`を押したのと同じ）、選んでいる行をもう一度押すと開く（`Enter`と同じ）。**
    #[test]
    fn clicking_a_row_selects_it_and_clicking_it_again_opens_it() {
        let list = summaries(5);
        let mut picker = Picker::new(list.len());
        let screen = draw(&mut picker, &list);
        let third = cell_of(&screen, "session-2");
        assert!(matches!(
            click(&mut picker, third),
            PickerStep::Handled(None)
        ));

        let mut by_keys = Picker::new(list.len());
        by_keys.on_key(KeyCode::Down);
        by_keys.on_key(KeyCode::Down);
        assert_eq!(picker.selected, by_keys.selected);

        draw(&mut picker, &list);
        assert!(matches!(
            click(&mut picker, third),
            PickerStep::Handled(Some(Choice::Open))
        ));
        assert_eq!(picker.selected, 2, "開いたのは選んだ行");
    }

    /// 下の案内の`f fork`・`Esc …`は、そのキーを押したのと同じ。`↑/↓ move`と行の外は何も変えない。
    #[test]
    fn the_hints_press_their_keys_and_other_places_do_nothing() {
        let list = summaries(3);
        let mut picker = Picker::new(list.len());
        let screen = draw(&mut picker, &list);
        assert!(matches!(
            click(&mut picker, cell_of(&screen, "f fork")),
            PickerStep::Handled(Some(Choice::Fork))
        ));
        assert!(matches!(
            click(&mut picker, cell_of(&screen, "Esc start")),
            PickerStep::Handled(Some(Choice::Cancel))
        ));
        assert!(matches!(
            click(&mut picker, cell_of(&screen, "Enter select")),
            PickerStep::Handled(Some(Choice::Open))
        ));
        let before = picker.selected;
        for place in [cell_of(&screen, "move"), (40, 9)] {
            assert!(matches!(
                click(&mut picker, place),
                PickerStep::Handled(None)
            ));
            assert_eq!(picker.selected, before);
        }
        // ポインタが動いただけ・キーを離しただけのイベントは描き直さない。
        assert!(matches!(
            picker.handle_event(CEvent::Mouse(MouseEvent {
                kind: MouseEventKind::Moved,
                column: 1,
                row: 1,
                modifiers: KeyModifiers::NONE,
            })),
            PickerStep::Unchanged
        ));
        let mut release = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert!(matches!(
            picker.handle_event(CEvent::Key(release)),
            PickerStep::Unchanged
        ));
    }
}
