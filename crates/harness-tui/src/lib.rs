//! harness-tui: ratatuiフロントエンド。`AgentEvent`を消費し、ストリーミング描画/ツールカード/
//! 承認モーダルを`tokio::select!`ループで描画する（`plans/DESIGN.md` §リッチTUI）。

mod app;
mod diff;
mod engine;
mod gate;
mod picker;
mod terminal;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event as CEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use harness_core::{LlmProvider, ToolCtx};
use harness_engine::{ConversationState, PermissionArbiter, SessionStore};
use harness_tools::ToolRegistry;

pub use app::{Action, AppState, SlashCommand};
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
    mut state: ConversationState,
    mut session: SessionStore,
    sessions_dir: PathBuf,
    enter_submits: bool,
    start_with_picker: bool,
) -> io::Result<()> {
    let _guard = terminal::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut term = Terminal::new(backend)?;
    let mut term_events = EventStream::new();

    // 引数なし`--resume`で起動された場合、通常のresume/continue解決（`harness-cli::resolve_session`）
    // ではなく対話的にセッションを選ばせる（§非対話モードの原則により、ヘッドレスでは
    // このピッカーを一切出さない。TUI起動時のみここに到達する）。
    let mut forked_from: Option<String> = None;
    if start_with_picker {
        match picker::run_picker(&mut term, &mut term_events, &sessions_dir).await? {
            picker::PickerOutcome::Selected(s, msgs) => {
                session = s;
                state.messages = msgs;
            }
            picker::PickerOutcome::Forked { source_id, session: s, messages } => {
                session = s;
                state.messages = messages;
                forked_from = Some(source_id);
            }
            picker::PickerOutcome::Cancelled => {
                // 呼び出し側が既定として渡した新規セッションをそのまま使う。
            }
        }
    }

    let resumed_messages = state.messages.len();
    let new_session_id = session.id();
    let mut engine = spawn_engine(
        provider,
        tools,
        ctx,
        arbiter,
        model.clone(),
        max_tokens,
        max_turns,
        state,
        session,
        sessions_dir.clone(),
    );
    let mut app = AppState::new(provider_label, model);
    app.enter_submits = enter_submits;
    // Enter系キー化けの検証用: `HARNESS_KEY_DEBUG`（`0`/空以外）で受信キーイベントを画面へecho。
    if std::env::var("HARNESS_KEY_DEBUG").map(|v| !v.is_empty() && v != "0").unwrap_or(false) {
        app.enable_key_debug();
    }
    if let Some(source_id) = forked_from {
        app.apply(harness_core::AgentEvent::SessionSwitched {
            source_id: Some(source_id),
            new_id: new_session_id,
            message_count: resumed_messages,
        });
    } else if resumed_messages > 0 {
        app.note_resumed_session(resumed_messages);
    }

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
                match ev {
                    Some(Ok(CEvent::Key(key))) => {
                        // Shift+Enter等の修飾キーが端末/ConPTY越しに実際どう届いているか
                        // 切り分けるための生イベントログ（`init_file_logging`のログファイル参照）。
                        tracing::debug!(code = ?key.code, modifiers = ?key.modifiers, kind = ?key.kind, "raw key event");
                        // `HARNESS_KEY_DEBUG=1`時は画面にもecho（Press/Release両方を観測するため
                        // Pressフィルタより前に呼ぶ）。無効時は`note_key_event`が即returnする。
                        app.note_key_event(key);
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        if let Some(action) = app.on_key(key) {
                            match action {
                                Action::Submit(text) => engine.submit(text),
                                Action::Respond(id, decision) => engine.gate.respond(&id, decision),
                                Action::Cancel => engine.cancel_current(),
                                Action::Slash(cmd) => match cmd {
                                    SlashCommand::Model(m) => engine.set_model(m),
                                    SlashCommand::Mode(mode) => engine.gate.set_mode(mode),
                                    SlashCommand::Allow(rule) => engine.gate.add_allow(rule),
                                    SlashCommand::Compact => engine.compact(),
                                    SlashCommand::Clear => engine.clear(),
                                    SlashCommand::Fork => engine.fork(),
                                    SlashCommand::Sessions => {
                                        // ピッカーの間は描画/入力ループを一時的に明け渡す
                                        // （`/clear`等と同じくengineタスクへコマンドを送るだけの
                                        // 他分岐と異なり、選択自体をここでブロッキング的に待つ）。
                                        match picker::run_picker(&mut term, &mut term_events, &sessions_dir).await {
                                            Ok(picker::PickerOutcome::Selected(s, msgs)) => {
                                                engine.switch_session(s, msgs);
                                            }
                                            Ok(picker::PickerOutcome::Forked { session: s, messages, .. }) => {
                                                engine.switch_session(s, messages);
                                            }
                                            Ok(picker::PickerOutcome::Cancelled) => {}
                                            Err(e) => {
                                                app.apply(harness_core::AgentEvent::Error {
                                                    message: format!("session picker failed: {e}"),
                                                });
                                            }
                                        }
                                    }
                                },
                                Action::Quit => {}
                            }
                        }
                    }
                    // マウスホイールでのtranscriptスクロール（`AppState::on_mouse`）。
                    Some(Ok(CEvent::Mouse(mouse))) => app.on_mouse(mouse.kind),
                    _ => {}
                }
            }
            _ = tick.tick() => { app.tick(); }
        }

        term.draw(|f| ui::render(f, &app))?;

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
