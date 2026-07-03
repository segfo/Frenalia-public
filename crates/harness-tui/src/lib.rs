//! harness-tui: ratatuiフロントエンド。`AgentEvent`を消費し、ストリーミング描画/ツールカード/
//! 承認モーダルを`tokio::select!`ループで描画する（`plans/DESIGN.md` §リッチTUI）。

mod app;
mod engine;
mod gate;
mod terminal;
mod ui;

use std::io;
use std::time::Duration;

use crossterm::event::{Event as CEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use harness_core::{LlmProvider, ToolCtx};
use harness_engine::PermissionArbiter;
use harness_tools::ToolRegistry;

pub use app::{Action, AppState};
pub use engine::{spawn_engine, EngineHandle};
pub use gate::InteractiveGate;

const TICK: Duration = Duration::from_millis(33);

/// tracingの出力先をログファイルへ切り替える（stdoutを汚さない、§リッチTUI「端末復帰」）。
/// 返り値の`WorkerGuard`はプロセス終了まで保持しないとバッファが破棄されるため、
/// 呼び出し側（`harness-cli`）がライフタイムを保持する。
pub fn init_file_logging(log_dir: &std::path::Path) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = tracing_appender::rolling::never(log_dir, "harness-tui.log");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt().with_writer(writer).with_ansi(false).init();
    guard
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    provider: Box<dyn LlmProvider>,
    tools: ToolRegistry,
    ctx: ToolCtx,
    arbiter: PermissionArbiter,
    model: String,
    max_tokens: u32,
    max_turns: usize,
    provider_label: String,
) -> io::Result<()> {
    let mut engine = spawn_engine(provider, tools, ctx, arbiter, model.clone(), max_tokens, max_turns);
    let mut app = AppState::new(provider_label, model);

    let _guard = terminal::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut term = Terminal::new(backend)?;

    let mut term_events = EventStream::new();
    let mut tick = tokio::time::interval(TICK);

    loop {
        tokio::select! {
            ev = engine.events_rx.recv() => {
                match ev {
                    Some(ev) => app.apply(ev),
                    None => break,
                }
            }
            ev = term_events.next() => {
                // Windowsのコンソールバックエンドはキー押下・離上の両方を`KeyEvent`として送るため、
                // ここで`Press`のみに絞らないと1文字が2回入力されてしまう
                // （離上も拾うと`Release`分だけ重複する）。
                if let Some(Ok(CEvent::Key(key))) = ev {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if let Some(action) = app.on_key(key) {
                        match action {
                            Action::Submit(text) => engine.submit(text),
                            Action::Respond(id, decision) => engine.gate.respond(&id, decision),
                            Action::Quit => {}
                        }
                    }
                }
            }
            _ = tick.tick() => {}
        }

        term.draw(|f| ui::render(f, &app))?;

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
