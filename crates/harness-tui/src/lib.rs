//! harness-tui: ratatuiフロントエンド。`AgentEvent`を消費し、ストリーミング描画/ツールカード/
//! 承認モーダルを`tokio::select!`ループで描画する（`plans/DESIGN.md` §リッチTUI）。

mod app;
mod diff;
mod engine;
mod gate;
mod picker;
#[cfg(windows)]
mod sandbox_prep;
mod terminal;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event as CEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use harness_core::{LlmProvider, StagingConfig, ToolCtx};
use harness_engine::{ConversationState, PermissionArbiter, SessionStore};
use harness_sandbox::{ApplyOptions, ManifestOp, ManifestTarget, SandboxFs};
use harness_tools::ToolRegistry;

pub use app::{Action, AppState, ChangeRow, ChangesPanelState, SlashCommand};
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

/// 変更パネル（M10）を開く際、`SandboxFs::change_set()`の各エントリに差分プレビューを
/// 添えて`ChangeRow`へ変換する。baseline（変更前）の内容は実FSから直接読む
/// （`Tree`はworkspace内の相対パス、`Ext`は絶対パスそのもの）。表示専用のbest-effort読取
/// のため、読めない場合は空文字列扱いにする（§リッチTUI「変更パネル」）。
fn build_change_rows(workspace_root: &std::path::Path, fs: &SandboxFs, entries: Vec<harness_sandbox::ChangeEntry>) -> Vec<ChangeRow> {
    entries
        .into_iter()
        .map(|entry| {
            let baseline = match entry.target {
                ManifestTarget::Tree => std::fs::read_to_string(workspace_root.join(&entry.path)),
                ManifestTarget::Ext => std::fs::read_to_string(&entry.path),
                ManifestTarget::Live => Ok(String::new()),
            }
            .unwrap_or_default();
            let current = if entry.op == ManifestOp::Delete {
                String::new()
            } else {
                fs.read_to_string(&entry.overlay_path).unwrap_or_default()
            };
            let diff = diff::line_diff(&baseline, &current);
            ChangeRow { entry, diff }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    provider: Box<dyn LlmProvider>,
    tools: ToolRegistry,
    mut ctx: ToolCtx,
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
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> io::Result<()> {
    let guard = terminal::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut term = Terminal::new(backend)?;
    let mut term_events = EventStream::new();

    // Tier3が選択されている場合、VM+コンテナ起動デーモンの準備が終わるまで（コールドブート
    // 約212秒/ウォーム再利用約20秒、`docs/STATUS.md`Tier3残課題#3）このオルタネートスクリーン内で
    // 進捗画面を表示する（`TerminalGuard::enter()`は再入不可のため、`main.rs`側で別途端末を
    // 握るのではなくここで行う）。表示する進捗は経過時間ベースの合成データであり、daemonの
    // 実測値ではない（`harness_sandbox::vmsandboxd_progress`のモジュールdoc、
    // `plans/DESIGN-SANDBOX-VMISOLATION.md`参照）。
    #[cfg(windows)]
    let vm_sandbox_handle: Option<std::sync::Arc<harness_sandbox::vmsandboxd::VmSandboxHandle>> =
        if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
            sandbox_prep::run_prep_screen(
                &mut term,
                &mut term_events,
                &ctx.workspace_root,
                &ctx.net_proxy.allow_domains,
                tier3_warm,
                tier3_max_sessions,
            )
            .await?
        } else {
            None
        };
    #[cfg(not(windows))]
    let vm_sandbox_handle: Option<std::sync::Arc<()>> = None;

    #[cfg(windows)]
    {
        ctx.vm_sandbox = vm_sandbox_handle
            .clone()
            .map(|h| h as std::sync::Arc<dyn harness_core::VmShellExecutor>);
    }

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
    // `ctx`は`spawn_engine`へ移動するため、変更パネル（M10）用に先に複製しておく
    // （パネルの開閉・apply/discardはengineタスクを介さず、`ConversationState`と無関係に
    // `SandboxFs`を直接この描画ループから同期的に叩く。ピッカーが`session`を直接触るのと
    // 同じアーキテクチャ上の位置付け）。
    let workspace_root_for_panel = ctx.workspace_root.clone();
    let staging_for_panel: StagingConfig = ctx.staging.clone();
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
                                Action::ToggleChangesPanel => {
                                    if app.changes_panel.is_some() {
                                        app.close_changes_panel();
                                    } else {
                                        match SandboxFs::open(&workspace_root_for_panel, &staging_for_panel) {
                                            Ok(fs) => match fs.change_set() {
                                                Ok(entries) => {
                                                    let rows = build_change_rows(&workspace_root_for_panel, &fs, entries);
                                                    app.open_changes_panel(rows);
                                                }
                                                Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                    message: format!("failed to read staged changes: {e}"),
                                                }),
                                            },
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("failed to open sandbox: {e}"),
                                            }),
                                        }
                                    }
                                }
                                Action::CommitChanges(only_paths) => {
                                    match SandboxFs::open(&workspace_root_for_panel, &staging_for_panel) {
                                        Ok(fs) => match fs.apply(&ApplyOptions {
                                            only_glob: None,
                                            only_paths: Some(&only_paths),
                                            allow_ext: false,
                                        }) {
                                            Ok(report) => {
                                                app.transcript.push(app::TranscriptItem::Info(format!(
                                                    "applied {} change(s){}{}{}",
                                                    report.applied.len(),
                                                    if report.conflicts.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!(", {} conflict(s) skipped", report.conflicts.len())
                                                    },
                                                    if report.ext_blocked.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!(
                                                            ", {} out-of-workspace change(s) need --dangerously-allow via `harness apply`",
                                                            report.ext_blocked.len()
                                                        )
                                                    },
                                                    if report.hard_denied.is_empty() {
                                                        String::new()
                                                    } else {
                                                        format!(
                                                            ", {} config-injection change(s) blocked (D-05, cannot be applied)",
                                                            report.hard_denied.len()
                                                        )
                                                    }
                                                )));
                                            }
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("apply failed: {e}"),
                                            }),
                                        },
                                        Err(e) => app.apply(harness_core::AgentEvent::Error {
                                            message: format!("failed to open sandbox: {e}"),
                                        }),
                                    }
                                }
                                Action::DiscardChanges => {
                                    match SandboxFs::open(&workspace_root_for_panel, &staging_for_panel) {
                                        Ok(fs) => match fs.discard() {
                                            Ok(()) => app.transcript.push(app::TranscriptItem::Info(
                                                "discarded staged changes".to_string(),
                                            )),
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("discard failed: {e}"),
                                            }),
                                        },
                                        Err(e) => app.apply(harness_core::AgentEvent::Error {
                                            message: format!("failed to open sandbox: {e}"),
                                        }),
                                    }
                                }
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

    // 端末復帰を先に済ませてから、Tier3 VMサンドボックスのteardown（ワークスペース
    // copy-out・コンテナ削除・VM/差分VHDX撤収）を行う。失敗時の警告`eprintln!`が
    // raw mode/alt screen中に出て見えなくなる/表示崩れするのを避けるため
    // （元は`main.rs`末尾にあった処理をTUI側で完結させる、`sandbox_prep`で開始した
    // ため対称的にここで終える）。
    drop(guard);
    #[cfg(windows)]
    if let Some(handle) = vm_sandbox_handle {
        if let Err(e) = handle.stop() {
            eprintln!("warning: failed to cleanly tear down Tier3 VM sandbox session: {e}");
        }
    }

    Ok(())
}
