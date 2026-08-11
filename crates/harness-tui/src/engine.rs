//! バックグラウンドの「engineアクター」。`ConversationState`を1タスクに閉じ込め、
//! ユーザ入力（プロンプト）をmpscで受け取ってターンを1つずつ`run_agent_loop`へ渡し、
//! `AgentEvent`を別のmpscでTUI側へ流す（§リッチTUI「非同期ループ」）。
//! `PermissionArbiter`は`InteractiveGate`越しに参照されるため、承認待ちの間もTUIの描画
//! ループ（別タスク）は動き続けられる。
//!
//! M9で以下を追加した:
//! - `cancel_current()`: 進行中ターンを`CancellationToken`でキャンセルする（Escキー、
//!   §エージェントループ キャンセル整合）。ターンごとに使い捨てトークンを生成し
//!   `cancel_slot`へ差し替えるため、キャンセル済みトークンが次のターンへ持ち越されない。
//! - `EngineCommand`（`SetModel`/`Compact`/`Clear`）: `state`はこのタスク内に閉じているため、
//!   スラッシュコマンドのうち`state`に触れるものは`prompt_tx`と同様mpsc経由で処理する
//!   （`/mode`/`/allow`は`InteractiveGate`が直接持つため`gate`経由、engineタスクを介さない）。
//! - JSONL セッション永続化: プロンプト送信直後・ターン完了直後の両方で増分メッセージを
//!   `SessionStore`へ追記する。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use harness_cognition::CognitiveOrchestrator;
use harness_core::{AgentEvent, LlmProvider, ToolCtx};
use harness_engine::{
    compaction, AgentLoopConfig, ConversationState, PermissionArbiter, SessionStore,
};
use harness_sandbox::session_scope::SessionScope;
use harness_tools::ToolRegistry;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::gate::InteractiveGate;

enum EngineCommand {
    SetModel(String),
    Compact,
    Clear,
    /// 現在のセッションをForkし、以降の追記を新しいファイルへ切り替える（`/fork`）。
    /// 元IDと新IDを`AgentEvent::Info`で通知する。
    Fork,
    /// 既存セッションへ切り替える（`/sessions`のピッカーで選択された結果）。
    ///
    /// `scope`は**そのセッションのオーバーレイの置き場**（`harness_sandbox::session_scope`）。
    /// 会話とオーバーレイは1単位で切り替える——片方だけ動かすと「会話はセッションB、
    /// エージェントの書込先はセッションA」という食い違いが常態化する（BUG-069/BUG-072と
    /// 同型）。呼び出し側は`prepare_scope`で置き場を用意し終えてからこれを送ること。
    SwitchSession {
        session: SessionStore,
        messages: Vec<harness_core::Message>,
        scope: SessionScope,
    },
    /// 会話はそのままに、オーバーレイの置き場だけを差し替える（`/fork`の第2段）。
    ///
    /// `/fork`のセッションID採番はこのタスクの中（`SessionStore::fork_from`）で起きるため、
    /// 新IDを知ってからスコープを計算・準備できるのは`SessionSwitched`を受け取った
    /// **呼び出し側**である。だから2段に分かれる（`crate::run`の該当アーム参照）。
    SetScope(SessionScope),
}

pub struct EngineHandle {
    prompt_tx: mpsc::UnboundedSender<String>,
    command_tx: mpsc::UnboundedSender<EngineCommand>,
    pub events_rx: mpsc::UnboundedReceiver<AgentEvent>,
    pub gate: Arc<InteractiveGate>,
    cancel_slot: Arc<Mutex<CancellationToken>>,
}

impl EngineHandle {
    pub fn submit(&self, prompt: String) {
        let _ = self.prompt_tx.send(prompt);
    }

    pub fn set_model(&self, model: String) {
        let _ = self.command_tx.send(EngineCommand::SetModel(model));
    }

    pub fn compact(&self) {
        let _ = self.command_tx.send(EngineCommand::Compact);
    }

    pub fn clear(&self) {
        let _ = self.command_tx.send(EngineCommand::Clear);
    }

    pub fn fork(&self) {
        let _ = self.command_tx.send(EngineCommand::Fork);
    }

    pub fn switch_session(
        &self,
        session: SessionStore,
        messages: Vec<harness_core::Message>,
        scope: SessionScope,
    ) {
        let _ = self.command_tx.send(EngineCommand::SwitchSession {
            session,
            messages,
            scope,
        });
    }

    /// オーバーレイの置き場だけを差し替える（`/fork`の第2段、[`EngineCommand::SetScope`]）。
    pub fn set_scope(&self, scope: SessionScope) {
        let _ = self.command_tx.send(EngineCommand::SetScope(scope));
    }

    /// 現在進行中のターンをキャンセルする（Escキー、M9）。進行中のターンが無ければ無害。
    pub fn cancel_current(&self) {
        self.cancel_slot.lock().unwrap().cancel();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_engine(
    provider: Arc<dyn LlmProvider>,
    tools: ToolRegistry,
    // セッション切替（`/sessions`・`/fork`）でオーバーレイの置き場（`staging`・`cow_upper_dir`）
    // だけが差し替わる（[`apply_scope`]）。他のフィールドはプロセス寿命で不変。
    mut ctx: ToolCtx,
    arbiter: PermissionArbiter,
    cognition: CognitiveOrchestrator,
    model: String,
    max_tokens: u32,
    max_turns: usize,
    // `harness-cli`が`settings.json`/CLIフラグとプロバイダcapabilityから解決済みのもの。
    compaction: compaction::CompactionPolicy,
    // 縮退ガードの移動統計（`plans/DESIGN-COGNITION.md` §11）。**セッション全体で1つ**を
    // 借り、発話ごとに`clone`して`AgentLoopConfig`へ載せる（中身は`Arc`なので統計は共有される）。
    degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    mut state: ConversationState,
    mut session: SessionStore,
    sessions_dir: PathBuf,
) -> EngineHandle {
    refresh_system_for_ctx(&mut state, &ctx);

    let (prompt_tx, mut prompt_rx) = mpsc::unbounded_channel::<String>();
    let (command_tx, mut command_rx) = mpsc::unbounded_channel::<EngineCommand>();
    let (events_tx, events_rx) = mpsc::unbounded_channel::<AgentEvent>();
    let gate = Arc::new(InteractiveGate::new(arbiter, events_tx.clone()));
    let gate_for_task = gate.clone();
    let cancel_slot: Arc<Mutex<CancellationToken>> = Arc::new(Mutex::new(CancellationToken::new()));
    let cancel_for_task = cancel_slot.clone();
    let mut model = model;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                prompt = prompt_rx.recv() => {
                    let Some(prompt) = prompt else { break };
                    state.push_user_text(prompt);
                    let _ = session.append_messages(&state.messages[state.messages.len() - 1..]);
                    // BUG-075: 生の`len()`を控えるとターン中の圧縮でスライスがパニックする。
                    let before_turn = state.mark();

                    let turn_cancel = CancellationToken::new();
                    *cancel_for_task.lock().unwrap() = turn_cancel.clone();

                    let result = cognition.run(
                        provider.as_ref(),
                        &mut state,
                        &tools,
                        &ctx,
                        gate_for_task.as_ref(),
                        AgentLoopConfig {
                            model: model.clone(),
                            max_tokens,
                            max_turns,
                            compaction,
                            degeneracy: degeneracy.clone(),
                        },
                        Some(&events_tx),
                        Some(&turn_cancel),
                        // TextDelta は`events`側で既に発行されるため、ここでの二重出力は不要
                        // （§リッチTUI: TUIは`AgentEvent`のみを消費する）。
                        |_delta: &str| {},
                    )
                    .await;
                    // 圧縮で履歴の先頭が畳まれたターンは、増分追記では足りない——ファイルには
                    // 畳む前の履歴が残り続け、`--resume`が圧縮前の長い会話へ戻ってしまう。
                    let _ = if state.folded_since(before_turn) {
                        session.append_checkpoint(&state.messages)
                    } else {
                        session.append_messages(state.since(before_turn))
                    };
                    if let Err(e) = result {
                        let _ = events_tx.send(AgentEvent::Error {
                            message: e.to_string(),
                        });
                    }
                }
                cmd = command_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        EngineCommand::SetModel(m) => {
                            model = m;
                        }
                        EngineCommand::Compact => {
                            // BUG-074: Escは`cancel_slot`に入っているトークンを発火させる。
                            // ターン用のものが入ったままだと`/compact`中のEscは**どこにも
                            // 届かない**ので、要約用のトークンを作って差し替える
                            // （＝Escは常に「いま走っているもの」を止める、という一貫した規則）。
                            let compact_cancel = CancellationToken::new();
                            *cancel_for_task.lock().unwrap() = compact_cancel.clone();
                            // BUG-071: このコマンドは**キューで待たされ得る**（ターン実行中は
                            // このループ本体が返らないので`command_rx`を1度もpollしない）。
                            // 送信時ではなくここが実際の開始点なので、その時点を通知する。
                            let _ = events_tx.send(AgentEvent::ContextCompactionStarted);
                            // ②ローリング要約 →①残った側の`tool_result`切詰め。順序と範囲の根拠は
                            // `harness_engine::compaction::manual`のモジュールdocが正本。
                            match compaction::compact_now(
                                provider.as_ref(),
                                &mut state,
                                &model,
                                compaction::summarize::chunk_tokens_for(
                                    compaction.context_window,
                                ),
                                Some(&compact_cancel),
                            )
                            .await
                            {
                                Ok(outcome) => match outcome.compacted.removed() {
                                    Some(removed_messages) => {
                                        let _ = events_tx.send(AgentEvent::ContextCompacted {
                                            removed_messages,
                                        });
                                        // ①が縮めたのはモデルが既に見た出力なので、静かに
                                        // やらず別イベントで可視化する。
                                        if !outcome.shrunk.is_noop() {
                                            let _ = events_tx.send(AgentEvent::ContextShrunk {
                                                truncated_blocks: outcome.shrunk.blocks,
                                                saved_tokens: outcome.shrunk.saved_tokens,
                                            });
                                        }
                                        // 何かが変わったときだけチェックポイントを残す
                                        // （空振りのたびに履歴全体を書き足さない）。
                                        if removed_messages > 0 || !outcome.shrunk.is_noop() {
                                            let _ = session.append_checkpoint(&state.messages);
                                        }
                                    }
                                    // 履歴は無傷のまま。ターンのキャンセルと同じ通知にする
                                    // （ユーザーから見れば「止めた」という同じ操作の結果）。
                                    None => {
                                        let _ = events_tx.send(AgentEvent::Cancelled);
                                    }
                                },
                                Err(e) => {
                                    let _ = events_tx.send(AgentEvent::Error {
                                        message: e.to_string(),
                                    });
                                }
                            }
                        }
                        EngineCommand::Clear => {
                            state = ConversationState::new(harness_engine::system_blocks_for(&ctx));
                            if let Ok(fresh) = SessionStore::create_new(&sessions_dir) {
                                session = fresh;
                            }
                        }
                        EngineCommand::Fork => {
                            let source_id = session.id();
                            match SessionStore::fork_from(&sessions_dir, session.path()) {
                                Ok(forked) => {
                                    let new_id = forked.id();
                                    let message_count = state.messages.len();
                                    session = forked;
                                    let _ = events_tx.send(AgentEvent::SessionSwitched {
                                        source_id: Some(source_id),
                                        new_id,
                                        message_count,
                                    });
                                }
                                Err(e) => {
                                    let _ = events_tx.send(AgentEvent::Error {
                                        message: format!("failed to fork session: {e}"),
                                    });
                                }
                            }
                        }
                        EngineCommand::SwitchSession { session: new_session, messages, scope } => {
                            let new_id = new_session.id();
                            let message_count = messages.len();
                            // オーバーレイの置き場を**会話より先に**差し替える。直後の
                            // `system_blocks_for(&ctx)`が新しい`staging`/`cow_upper_dir`を読むので、
                            // モデルへ送る環境事実（`EnvironmentFacts`、`CLAUDE.md`の規約）が
                            // 追加コード無しで張り直る。順序を逆にすると、この会話の最初の
                            // ターンだけが古いオーバーレイの説明を持つ。
                            apply_scope(&mut ctx, scope);
                            state = ConversationState::new(harness_engine::system_blocks_for(&ctx));
                            state.messages = messages;
                            session = new_session;
                            let _ = events_tx.send(AgentEvent::SessionSwitched {
                                source_id: None,
                                new_id,
                                message_count,
                            });
                        }
                        EngineCommand::SetScope(scope) => {
                            apply_scope(&mut ctx, scope);
                            // 会話は続いているので`state`は捨てず、環境事実の板だけ差し替える。
                            refresh_system_for_ctx(&mut state, &ctx);
                        }
                    }
                }
            }
        }
    });

    EngineHandle {
        prompt_tx,
        command_tx,
        events_rx,
        gate,
        cancel_slot,
    }
}

fn refresh_system_for_ctx(state: &mut ConversationState, ctx: &ToolCtx) {
    state.system = harness_engine::system_blocks_for(ctx);
}

/// オーバーレイの置き場を`ToolCtx`へ書き戻す。**`ToolCtx`のうちセッション切替で動くのは
/// この2フィールドだけ**であり、それを1箇所に閉じ込めるための関数である。
///
/// これで全経路が追随する理由: fsツールは呼び出しのたびに`ctx`から`SandboxFs`を開き直し
/// （`harness_tools::fs_tools`）、`run_shell`はCoW upperを呼び出しのたびに`ctx.cow_upper_dir`から
/// 子プロセスのenvへ注入する（`harness_tools::shell`）。どちらも起動時の値を握らないので、
/// ここを書き換えるだけで次の呼び出しから新しいオーバーレイを見る。
///
/// **Tier・capability・preflightは動かさない。** workspaceツリーのアクセス形状（RWXかROか）は
/// 起動時の`preflight`が確定し、capability・ACE・モードmutexがそれに紐付いている（D-54）。
/// 動くのは「どのセッションのオーバーレイへ書くか」だけである。
fn apply_scope(ctx: &mut ToolCtx, scope: SessionScope) {
    ctx.staging = scope.staging;
    ctx.cow_upper_dir = scope.cow_upper_dir;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use harness_core::{
        NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, ShellTier, ShellTierSelection,
        StagingConfig, StagingMode, ToolCtx,
    };

    use super::*;

    #[test]
    fn refresh_system_for_tier3_uses_container_workspace_not_windows_host_path() {
        let stale_ctx = ToolCtx {
            workspace_root: PathBuf::from(r"C:\Users\segfo\Documents\AI\harness"),
            staging: StagingConfig {
                mode: StagingMode::WorkspaceCommit,
                sandbox_dir: None,
            },
            read_scope: ReadScopeConfig {
                mode: ReadMode::Whitelist,
                allow: Vec::new(),
                allow_descend: Vec::new(),
                deny: Vec::new(),
                deny_descend: Vec::new(),
            },
            shell_sees_staged_writes: true,
            shell_tier: ShellTierSelection {
                tier: ShellTier::Tier0,
                reason: None,
                downgraded_from: None,
                granted_passthrough: Vec::new(),
                denied_passthrough: Vec::new(),
                passthrough_warnings: Vec::new(),
                netfilterd_chain_attempted: false,
            },
            net_proxy: NetProxyConfig::default(),
            net_app: NetAppPolicy::default(),
            run_shell_path_extra: Vec::new(),
            vm_sandbox: None,
            cow_upper_dir: None,
            mcp_servers: Vec::new(),
        };
        let mut state = ConversationState::new(harness_engine::system_blocks_for(&stale_ctx));

        let tier3_ctx = ToolCtx {
            shell_tier: ShellTierSelection {
                tier: ShellTier::Tier3,
                ..stale_ctx.shell_tier.clone()
            },
            ..stale_ctx
        };

        refresh_system_for_ctx(&mut state, &tier3_ctx);
        let rendered = state
            .system
            .iter()
            .map(|block| block.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("/workspace"));
        assert!(rendered.contains("Linuxコンテナ実行環境"));
        assert!(!rendered.contains(r"C:\Users"));
        assert!(!rendered.contains("PowerShell"));
    }

    fn ctx_for_scope_tests() -> ToolCtx {
        ToolCtx {
            workspace_root: PathBuf::from(r"C:\ws"),
            staging: StagingConfig {
                mode: StagingMode::Live,
                sandbox_dir: None,
            },
            read_scope: ReadScopeConfig::default(),
            shell_sees_staged_writes: false,
            shell_tier: ShellTierSelection::default(),
            net_proxy: NetProxyConfig::default(),
            net_app: NetAppPolicy::default(),
            run_shell_path_extra: Vec::new(),
            vm_sandbox: None,
            cow_upper_dir: Some(PathBuf::from(r"C:\cow\session-old")),
            mcp_servers: Vec::new(),
        }
    }

    /// セッション切替で動くのは**この2フィールドだけ**。ここが増えると、切替のコストが
    /// 「置き場を差し替えるだけ」ではなくなる（Tier・capability・preflightの張り直しが要る）。
    #[test]
    fn applying_a_scope_moves_only_the_overlay_location() {
        let mut ctx = ctx_for_scope_tests();
        let before = (ctx.workspace_root.clone(), ctx.shell_tier.tier);
        apply_scope(
            &mut ctx,
            harness_sandbox::session_scope::ScopeTemplate::new(StagingMode::Staged, false)
                .scope_for("session-new"),
        );
        assert_eq!(
            ctx.staging.sandbox_dir,
            Some(harness_sandbox::session_scope::sandbox_dir_for_session(
                "session-new"
            ))
        );
        assert_eq!(ctx.cow_upper_dir, None);
        assert_eq!((ctx.workspace_root.clone(), ctx.shell_tier.tier), before);
    }

    /// `CLAUDE.md`の`EnvironmentFacts`規約: モデルへ送る環境事実は`ToolCtx`から毎回組み直す。
    /// `--cow`のupperパスはプロンプトに載る（`prompt::render_cow`）ので、切替後の会話が
    /// **古いオーバーレイの説明を持ったまま**にならないことをここで固定する。
    #[test]
    fn switching_the_cow_overlay_is_reflected_in_the_system_prompt() {
        let mut ctx = ctx_for_scope_tests();
        let mut state = ConversationState::new(harness_engine::system_blocks_for(&ctx));
        let rendered = |state: &ConversationState| {
            state
                .system
                .iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(rendered(&state).contains("session-old"));

        let staging = ctx.staging.clone();
        apply_scope(
            &mut ctx,
            SessionScope {
                session_id: "session-new".to_string(),
                staging,
                cow_upper_dir: Some(PathBuf::from(r"C:\cow\session-new")),
            },
        );
        refresh_system_for_ctx(&mut state, &ctx);
        assert!(rendered(&state).contains("session-new"));
        assert!(!rendered(&state).contains("session-old"));
    }
}
