//! harness-tui: ratatuiフロントエンド。`AgentEvent`を消費し、ストリーミング描画/ツールカード/
//! 承認モーダルを`tokio::select!`ループで描画する（`plans/DESIGN.md` §リッチTUI）。

mod app;
mod engine;
mod gate;
mod picker;
#[cfg(windows)]
mod sandbox_prep;
mod ui;

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event as CEvent, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use harness_cognition::{CognitiveOrchestrator, RecallStore, ReviewedWatermark};
use harness_core::{LlmProvider, ReadScopeConfig, ToolCtx};
use harness_engine::{ConversationState, PermissionArbiter, SessionStore};
use harness_sandbox::{ApplyOptions, ManifestOp, SandboxFs};
use harness_tools::ToolRegistry;

pub use app::{
    Action, AppState, BusyEnd, BusyProgress, CommitSelection, MemoryCommand, PartialFile,
    ReviewPanelState, ReviewRow, ReviewTarget, SlashCommand,
};
pub use engine::{spawn_engine, EngineHandle};
pub use gate::InteractiveGate;

/// [`run`]が終わった理由。
///
/// `/workspace`をプロセス内の切替ではなく**再起動**にしているのは、`workspace_root`が
/// D-54のcapability台帳・`begin_workspace_mode`のモードmutex・`preflight`・背景`grant_job`・
/// traverse台帳・ログ出力先・MCP・Recall記憶鍵すべての基点だからである。プロセス途中で
/// 動かすことは起動パイプライン（Stage1〜5）をもう一度実行するのと同義で、しかもmutex・
/// loopback exemption・WFPフィルタ・昇格ヘルパーのパイプは**プロセス寿命に紐付いている**
/// （それが設計）。プロセス内で解いて張り直すのは、既存の順序制約の二重実装になる。
///
/// 再起動そのものは`harness-cli`が行う——MCP停止・WFP撤収・policy-learn撤収・
/// `session_profile::end_session`という**既存のteardown順序を全部通した後**に置けるのは
/// あちら側だけであり、TUIが自分でプロセスを起こすとその順序を迂回することになる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Quit,
    /// `/workspace <path>`。`workspace`は正規化済み（`harness-cli`の
    /// `normalize_workspace_root`と同じ規則）で、実在するディレクトリであることを確認済み。
    Relaunch {
        workspace: PathBuf,
    },
}

const TICK: Duration = Duration::from_millis(33);

/// ステータスバーへ出す「いま何を待たされているか」。走っていなければ`None`
/// （ステータスバーから表示が消える）。
///
/// **ツールカード側（`harness-engine`のツール実行ループ）と同じレジストリを見る。**
/// 以前はここが`grant_job::progress()`を直結で読んでおり、(1) `win_appcontainer`という
/// 具象がTUIへ漏れ上がる、(2) `JobPhase`の鏡写しenumをTUI側に持つ、(3) 「終わっていたら
/// 出さない」判定が`WorkspaceAclWaitReason`とここの2箇所にある、という3点が同時に起きていた
/// （`refactor-perspectives` R-01）。新しい背景ジョブが増えても、`harness_tools::wait_reasons`
/// へ`WaitReason`実装を1つ足すだけでこの表示にも載る——ここの変更は要らない。
///
/// cfg分岐は`known_wait_reasons`が持つので、ここには要らない（非Windowsでは空のレジストリが
/// 返り、常に`None`になる）。
fn poll_wait_state() -> Option<harness_core::tool::WaitState> {
    harness_tools::wait_reasons::known_wait_reasons().active_state()
}

#[cfg(test)]
#[path = "review_flow_tests.rs"]
mod review_flow_tests;

/// tracingの出力先をログファイルへ切り替える（stdoutを汚さない、§リッチTUI「端末復帰」）。
/// 返り値の`WorkerGuard`はプロセス終了まで保持しないとバッファが破棄されるため、
/// 呼び出し側（`harness-cli`）がライフタイムを保持する。
pub fn init_file_logging(log_dir: &std::path::Path) -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = tracing_appender::rolling::never(log_dir, "harness-tui.log");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .init();
    guard
}

/// 変更パネル（M10）を開く際、`SandboxFs::change_set()`の各エントリをレビュー行
/// （[`ReviewRow`]）へ変換する。CoW一本化（Phase 2）により`--staged`/`--sandbox tier2a-cow`は同じ
/// `SandboxFs`バックエンドを使うため、この1関数だけで両方をカバーする（以前あった
/// `build_cow_change_rows`との重複は解消済み）。
///
/// 差分（ハンク）と両側のハッシュの計算は`SandboxFs::review_file`が持つ——**部分適用が
/// 同じ計算を再実行する**ため、表示側で別に計算してはならない
/// （`plans/PLAN-VSCODE-REVIEW.md`「ハンク計算は表示側と適用側で同一実装を使う」）。
fn build_change_rows(fs: &SandboxFs, entries: Vec<harness_sandbox::ChangeEntry>) -> Vec<ReviewRow> {
    entries
        .into_iter()
        .map(|entry| {
            let badge = match entry.op {
                ManifestOp::Create => 'A',
                ManifestOp::Modify => 'M',
                ManifestOp::Delete => 'D',
            };
            ReviewRow {
                label: entry.path.clone(),
                badge,
                review: fs.review_file(&entry),
                target: ReviewTarget::Change { path: entry.path },
            }
        })
        .collect()
}

/// 変更パネルの`c`／`/fsstage commit*`が返した選択を実際に適用する。ファイル単位
/// （`SandboxFs::apply`）とハンク単位（`SandboxFs::apply_hunks`、ファイルごとに1回）へ
/// 分かれるため、結果は1つの`ApplyReport`へまとめてから1行で報告する。
fn apply_commit_selection(
    fs: &SandboxFs,
    selection: &CommitSelection,
) -> Result<harness_sandbox::ApplyReport, harness_sandbox::SandboxError> {
    let mut report = harness_sandbox::ApplyReport::default();
    if !selection.whole_files.is_empty() {
        report.merge(fs.apply(&ApplyOptions {
            only_glob: None,
            only_paths: Some(&selection.whole_files),
            allow_ext: false,
            // BUG-066: baselineが不明なエントリはTUIからも黙って取り込まない
            // （`push_apply_report`が`unledgered:`として見せる）。
            adopt_unledgered: false,
        })?);
    }
    for partial in &selection.partial {
        report.merge(fs.apply_hunks(&harness_sandbox::HunkSelection {
            path: &partial.path,
            workspace_hash: partial.workspace_hash.clone(),
            overlay_hash: partial.overlay_hash.clone(),
            accepted: &partial.accepted_hunks,
        })?);
    }
    Ok(report)
}

/// 変更パネル（`/fsstage`系Action）が使う`SandboxFs`を開く。CoW一本化（Phase 2）により、
/// `--staged`/`--sandbox tier2a-cow`いずれもこの1関数・1つの`SandboxFs`インスタンスで扱える
/// （以前あったAction毎のstaged/CoW分岐は解消済み）。
fn open_panel_fs(
    workspace_root: &std::path::Path,
    scope: &harness_sandbox::session_scope::SessionScope,
) -> Result<SandboxFs, harness_sandbox::SandboxError> {
    SandboxFs::open_with_cow(
        workspace_root,
        &scope.staging,
        &ReadScopeConfig::default(),
        scope.cow_upper_dir.as_deref(),
    )
}

/// `/memory`（`Recall`、`plans/PLAN-RECALL-MEMORY.md`）。表示行の生成はCLIの`harness memory`
/// と共有する`harness_cognition::format_checkpoint_line`を使う（`bug-pattern-rules` B-05）。
fn run_memory_slash_command(workspace_root: &std::path::Path, cmd: MemoryCommand) -> Vec<String> {
    let store = match RecallStore::for_workspace(workspace_root) {
        Ok(s) => s,
        Err(reason) => return vec![format!("recall store unavailable: {reason}")],
    };
    if let Err(e) = store.open() {
        return vec![format!("failed to open the recall store: {e}")];
    }

    match cmd {
        MemoryCommand::List => match store.unreviewed() {
            Ok(list) if list.is_empty() => vec!["no unreviewed checkpoints.".to_string()],
            Ok(list) => list
                .iter()
                .map(|m| harness_cognition::format_checkpoint_line(m, false))
                .collect(),
            Err(e) => vec![format!("failed to list checkpoints: {e}")],
        },
        MemoryCommand::MarkReviewed => {
            let unreviewed = match store.unreviewed() {
                Ok(u) => u,
                Err(e) => return vec![format!("failed to list checkpoints: {e}")],
            };
            if unreviewed.is_empty() {
                return vec!["no unreviewed checkpoints.".to_string()];
            }
            let mut lines: Vec<String> = unreviewed
                .iter()
                .map(|m| harness_cognition::format_checkpoint_line(m, false))
                .collect();
            if let Some(latest) = unreviewed
                .iter()
                .max_by(|a, b| (a.created_at_ms, &a.id).cmp(&(b.created_at_ms, &b.id)))
            {
                store.mark_reviewed(ReviewedWatermark {
                    created_at_ms: latest.created_at_ms,
                    id: latest.id.clone(),
                });
                lines.push(format!(
                    "marked {} checkpoint(s) as reviewed.",
                    unreviewed.len()
                ));
            }
            lines
        }
        MemoryCommand::Discard(id) => match store.discard(&id) {
            Ok(()) => vec![format!("discarded {id}.")],
            Err(e) => vec![format!("failed to discard {id}: {e}")],
        },
    }
}

/// `SandboxFs::apply()`の結果をtranscriptへ1行のInfo通知として積む。変更パネルの`c`、
/// `/fsstage commit <file>`、`/fsstage commit_all`の3経路で共通のため関数化した。
fn push_apply_report(app: &mut AppState, report: &harness_sandbox::ApplyReport) {
    app.transcript.push(app::TranscriptItem::Info(format!(
        "applied {} change(s){}{}{}{}",
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
        },
        // BUG-062: 台帳のパスの形が不正だったもの。`hard_denied`とは原因が違う
        // （あちらは「書いてはいけない場所」、こちらは「台帳が改竄されたか壊れている」）
        // ので、件数も別に見せる。
        if report.rejected.is_empty() {
            String::new()
        } else {
            format!(
                ", {} change(s) rejected as malformed ledger paths (the operations ledger may \
                 have been tampered with, see docs/bugs/BUG-062.md)",
                report.rejected.len()
            )
        }
    )));
    // BUG-066: 台帳に無いオーバーレイ実体は**件数だけでは足りない**——「適用されなかった変更が
    // upperに残っている」という復旧手段そのものなので、パスを1件ずつ見せる。
    for path in &report.unledgered {
        app.transcript.push(app::TranscriptItem::Info(format!(
            "unledgered (in the overlay but not recorded; baseline unknown, not applied): {path} \
             -- `harness apply --adopt-unledgered` to take it",
        )));
    }
}

/// `/workspace <path>`の引数を、起動時と**同じ規則**で正規化して実在確認する。
///
/// 綴りの正規化（`\\?\`前置の除去・`.`/`..`の字句的な畳み込み・絶対化）は
/// `harness_change_ledger::path_rules::normalize_root_spelling` + `std::path::absolute` で行う
/// ——`harness-cli`の`normalize_workspace_root`と**同じ2関数**である。ここに別の規則を書くと、
/// 「`/workspace .`で入ったときだけ台帳のキーがずれる」というBUG-066/BUG-068と同型の穴になる
/// （`bug-pattern-rules` B-05/B-19）。`canonicalize`は使わない——シンボリックリンクを辿って
/// 対象をすり替えてしまい、境界の意味が変わる。
fn resolve_workspace_arg(raw: &str, current: &std::path::Path) -> Result<PathBuf, String> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() {
        return Err("usage: /workspace <path>".to_string());
    }
    // 相対パスは「いまのワークスペースから見て」解決する（cwdはTUIの起動時から変わらないが、
    // ユーザーが画面で見ているのはワークスペースなので、そちらを基準にする方が驚きが少ない）。
    let abs = harness_sandbox::session_scope::normalize_workspace_root(&current.join(raw));
    if !abs.is_dir() {
        return Err(format!("{} はディレクトリではありません", abs.display()));
    }
    Ok(abs)
}

/// ステータスバーへ出すオーバーレイ名。`--live`はオーバーレイを持たないので空
/// （`AppState::note_scope`が`None`＝非表示として扱う）。
fn overlay_label(scope: &harness_sandbox::session_scope::SessionScope) -> &str {
    if scope.is_live() {
        ""
    } else {
        &scope.session_id
    }
}

/// 切替先のオーバーレイを用意し、成功したときだけ`Some`を返す（`/sessions`）。
///
/// **`None`のときは会話も切り替えない**（fail-closed）。書けないオーバーレイへ会話だけ移すと、
/// 以後の書込が全部失敗し続けることになる。理由は必ず1行残す（B-10: 握り潰さない）。
fn prepared_scope(
    app: &mut AppState,
    workspace_root: &std::path::Path,
    template: &harness_sandbox::session_scope::ScopeTemplate,
    session_id: &str,
) -> Option<harness_sandbox::session_scope::SessionScope> {
    let next = template.scope_for(session_id);
    match harness_sandbox::session_scope::prepare_scope(workspace_root, &next) {
        Ok(_) => Some(next),
        Err(e) => {
            app.transcript.push(app::TranscriptItem::Error(format!(
                "{session_id} のオーバーレイを用意できませんでした: {e} （会話も切り替えていません）"
            )));
            None
        }
    }
}

/// 用意済みのスコープを「いま見ているオーバーレイ」として採用し、未適用件数を返す。
///
/// **開いているレビューパネルは閉じる**（`bug-pattern-rules` B-22）。パネルの行は開いた時点の
/// オーバーレイから作られている一方、`c`（commit）は適用の瞬間に`open_panel_fs`で開き直す。
/// 対象が変わったのに行が残っていると、**旧オーバーレイの一覧を見ながら新オーバーレイへ
/// 適用する**ことになる。現状はパネル表示中に全キー入力をパネルが奪うのでここへ到達しないが、
/// 条件は「その意図で書かれた経路」ではなく「その状態を作り得る全経路」で閉じる（BUG-085）。
fn adopt_scope(
    app: &mut AppState,
    workspace_root: &std::path::Path,
    review_scope: &mut harness_sandbox::session_scope::SessionScope,
    next: harness_sandbox::session_scope::SessionScope,
) -> usize {
    *review_scope = next;
    app.review_panel = None;
    open_panel_fs(workspace_root, review_scope)
        .and_then(|fs| fs.change_set())
        .map(|entries| entries.len())
        .unwrap_or(0)
}

/// `/fork`の第2段。新セッション用のオーバーレイを用意し、いまのオーバーレイの中身をそこへ
/// コピーしてから、engineへ差し替えを伝える。
///
/// **失敗したらスコープを動かさない。** 会話のforkは既に済んでいるので巻き戻せないが、
/// レビュー対象を元のオーバーレイに留めておけば変更は1つも失われない（非破壊）。
/// 何が起きたかは必ず1行出す——黙って元のままにすると、`/fork`したのに分岐していないことに
/// 気付けない（B-10）。
fn fork_overlay_into(
    app: &mut AppState,
    engine: &EngineHandle,
    workspace_root: &std::path::Path,
    template: &harness_sandbox::session_scope::ScopeTemplate,
    review_scope: &mut harness_sandbox::session_scope::SessionScope,
    new_session_id: &str,
) {
    let next = template.scope_for(new_session_id);
    if next.is_live() {
        // `--live`はオーバーレイを持たないので、分岐すべき変更が存在しない。
        return;
    }
    match harness_sandbox::session_scope::fork_overlay(workspace_root, review_scope, &next) {
        Ok(copied) => {
            let previous = review_scope.session_id.clone();
            adopt_scope(app, workspace_root, review_scope, next);
            engine.set_scope(review_scope.clone());
            app.transcript.push(app::TranscriptItem::Info(format!(
                "オーバーレイを {previous} から {} へコピーしました（{copied} ファイル）。以降の変更は分岐先だけに入ります",
                review_scope.session_id
            )));
        }
        Err(e) => app.transcript.push(app::TranscriptItem::Error(format!(
            "会話はforkしましたが、オーバーレイのコピーに失敗しました: {e} \
             （レビュー対象と書込先は {} のまま。変更は失われていません）",
            review_scope.session_id
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    provider: Arc<dyn LlmProvider>,
    tools: ToolRegistry,
    mut ctx: ToolCtx,
    arbiter: PermissionArbiter,
    cognition: CognitiveOrchestrator,
    model: String,
    max_tokens: u32,
    max_turns: usize,
    compaction: harness_engine::compaction::CompactionPolicy,
    degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    provider_label: String,
    mut state: ConversationState,
    mut session: SessionStore,
    sessions_dir: PathBuf,
    enter_submits: bool,
    start_with_picker: bool,
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> io::Result<RunOutcome> {
    let guard = harness_term::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut term = Terminal::new(backend)?;
    let mut term_events = EventStream::new();

    // Tier3が選択されている場合、VM+コンテナ起動デーモンの準備が終わるまで（コールドブート
    // 約212秒/ウォーム再利用約20秒、`docs/STATUS.md`Tier3残課題#3）このオルタネートスクリーン内で
    // 進捗画面を表示する（`TerminalGuard::enter()`は再入不可のため、`main.rs`側で別途端末を
    // 握るのではなくここで行う）。表示する進捗は経過時間ベースの合成データであり、daemonの
    // 実測値ではない（`harness_sandbox_vm::vmsandboxd_progress`のモジュールdoc、
    // `plans/DESIGN-SANDBOX-VMISOLATION.md`参照）。
    #[cfg(windows)]
    let vm_sandbox_handle: Option<
        std::sync::Arc<harness_sandbox_vm::vmsandboxd::VmSandboxHandle>,
    > = if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
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
            picker::PickerOutcome::Forked {
                source_id,
                session: s,
                messages,
            } => {
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
    // BUG-069: 復元した会話を画面へも積むため、engineへ`state`を渡す前に複製しておく。
    let restored_messages: Vec<harness_core::Message> = state.messages.clone();
    let new_session_id = session.id();
    // `ctx`は`spawn_engine`へ移動するため、変更パネル（M10）用に先に複製しておく
    // （パネルの開閉・apply/discardはengineタスクを介さず、`ConversationState`と無関係に
    // `SandboxFs`を直接この描画ループから同期的に叩く。ピッカーが`session`を直接触るのと
    // 同じアーキテクチャ上の位置付け）。
    let workspace_root_for_panel = ctx.workspace_root.clone();
    // このプロセスのオーバーレイ機構（`--live`/`--staged`/`--sandbox tier2a-cow`）。
    // **セッションを切り替えても変わらない**——workspaceツリーのアクセス形状は起動時の
    // `preflight`が確定し、capability・ACE・モードmutexがそれに紐付いているため（D-54）。
    // 切替で動くのは「どのセッションのオーバーレイか」だけで、それを`scope_for`が引く。
    //
    // **CLIのフラグではなく、いま走っている`ToolCtx`の実際の値から作る**（TUIは
    // `harness-cli`へ依存できないうえ、ここで欲しいのは「要求」ではなく「成立した形」である）。
    // D-81で差分層の根はワークスペースのボリュームで決まるようになったが、ここでも
    // **ワークスペースから導出し直さない**——いま実際に使っている差分層の親をそのまま採る。
    // 導出規則を2箇所に持つと、片方だけ変わったときに切替先だけ別の根を指す（B-05）。
    let scope_template = match &ctx.cow_upper_dir {
        Some(dir) => harness_sandbox::session_scope::ScopeTemplate::Cow {
            upper_root: dir
                .parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| dir.clone()),
        },
        None => harness_sandbox::session_scope::ScopeTemplate::Staging(ctx.staging.mode),
    };
    // **いま見ている／書いているオーバーレイ**。`/sessions`・`/fork`で差し替わり、engine側の
    // `ToolCtx`とこの値は常に同じものを指す（engineの確認イベントを受けてから更新するため、
    // ずれる窓が無い）。パネルの開閉・apply/discardはengineタスクを介さず、
    // `ConversationState`と無関係に`SandboxFs`を直接この描画ループから同期的に叩く
    // （ピッカーが`session`を直接触るのと同じアーキテクチャ上の位置付け）。
    let mut review_scope = scope_template.scope_for(&new_session_id);
    // `AppState`はこの下でしか作れないので、ここで出したい警告を1つ預けておく。
    let mut app_startup_scope_warning: Option<String> = None;
    // 起動時ピッカー（`--resume`を引数なしで指定）が別のセッションを選んだ場合、`harness-cli`が
    // 組んだ`ctx`は**ピッカーより前の使い捨てセッション**のオーバーレイを指したままである
    // （`sandbox_dir`はセッションID確定時に決まるが、確定はピッカーの後になる）。ここで
    // 選ばれたセッションのものへ揃える。`ctx`をまだ手放していないこの一点でしか直せない。
    if ctx.staging != review_scope.staging || ctx.cow_upper_dir != review_scope.cow_upper_dir {
        // ピッカーで`f`（fork）を選んだ場合は、元セッションの未適用変更も分岐先へ持っていく
        // （`--fork-session`・`/fork`と同じ意味論。`bug-pattern-rules` B-06）。
        let prepared = match &forked_from {
            Some(source_id) => harness_sandbox::session_scope::fork_overlay(
                &workspace_root_for_panel,
                &scope_template.scope_for(source_id),
                &review_scope,
            )
            .map(|_| ()),
            None => harness_sandbox::session_scope::prepare_scope(
                &workspace_root_for_panel,
                &review_scope,
            )
            .map(|_| ()),
        };
        if let Err(e) = prepared {
            // 用意できないなら**起動時のオーバーレイのまま続ける**（会話だけ選んだものになる）。
            // 黙って続けると食い違いに気付けないので、必ず1行残す。
            app_startup_scope_warning = Some(format!(
                "could not switch the overlay to {}: {e} (reviewing session-{}'s overlay instead)",
                review_scope.session_id,
                ctx.staging
                    .sandbox_dir
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "?".to_string())
            ));
            review_scope = scope_template.scope_for(&new_session_id);
            review_scope.staging = ctx.staging.clone();
            review_scope.cow_upper_dir = ctx.cow_upper_dir.clone();
        } else {
            ctx.staging = review_scope.staging.clone();
            ctx.cow_upper_dir = review_scope.cow_upper_dir.clone();
        }
    }
    let mut engine = spawn_engine(
        provider,
        tools,
        ctx,
        arbiter,
        cognition,
        model.clone(),
        max_tokens,
        max_turns,
        compaction,
        degeneracy,
        state,
        session,
        sessions_dir.clone(),
    );
    let mut app = AppState::new(provider_label, model);
    app.enter_submits = enter_submits;
    app.host_is_vscode = harness_term::host_is_vscode();
    app.workspace_label = workspace_root_for_panel
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| workspace_root_for_panel.to_string_lossy().into_owned());
    app.note_scope(overlay_label(&review_scope), &new_session_id);
    if let Some(warning) = app_startup_scope_warning.take() {
        app.transcript.push(app::TranscriptItem::Error(warning));
    }
    // Enter系キー化けの検証用: `HARNESS_KEY_DEBUG`（`0`/空以外）で受信キーイベントを画面へecho。
    if std::env::var("HARNESS_KEY_DEBUG")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
    {
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
    // BUG-069: 件数の通知だけでは「何を再開したのか」が分からない。通知行の**後ろ**へ
    // 実際のやりとりを積む（通知行が復元分の見出しになる）。
    app.restore_transcript(&restored_messages);

    // `Recall`: セッション開始時に未レビュー件数を1行通知する（TUIのみ、headlessは
    // 無人実行に通知の受け手がいないため通知しない、`plans/PLAN-RECALL-MEMORY.md`）。
    // 解決・読出しに失敗しても通知しないだけで起動は止めない（fail-open）。
    if let Ok(store) = RecallStore::for_workspace(&workspace_root_for_panel) {
        if store.open().is_ok() {
            if let Ok(unreviewed) = store.unreviewed() {
                if !unreviewed.is_empty() {
                    app.transcript.push(app::TranscriptItem::Info(format!(
                        "{} unreviewed memory checkpoint(s). See `/memory`.",
                        unreviewed.len()
                    )));
                }
            }
        }
    }

    let mut tick = tokio::time::interval(TICK);
    // BUG-069: `/sessions`で別セッションへ切り替えたとき、engineが返す`SessionSwitched`
    // （見出し行）の**後ろ**へ復元分を積むための予約置き場。
    let mut pending_restore: Option<Vec<harness_core::Message>> = None;
    // 切り替え先のオーバーレイ。`pending_restore`と同じ理由で予約する——engineが実際に
    // `ToolCtx`を差し替えたのは`SessionSwitched`が返ってきた時点なので、ピッカーから戻った
    // 直後にここを更新すると、ターン実行中はパネルだけが先に新しい方を見ることになる。
    let mut pending_scope: Option<harness_sandbox::session_scope::SessionScope> = None;
    // `/workspace`で選ばれた移動先（ループを抜けて`harness-cli`が再起動する、§`RunOutcome`）。
    let mut relaunch_into: Option<PathBuf> = None;

    loop {
        tokio::select! {
            ev = engine.events_rx.recv() => {
                match ev {
                    Some(ev) => {
                        let switched = matches!(ev, harness_core::AgentEvent::SessionSwitched { .. });
                        // `/fork`はengineの中で新IDが決まるので、それを受け取ってから
                        // オーバーレイをコピーする（`EngineCommand::SetScope`＝第2段）。
                        let forked_to = match &ev {
                            harness_core::AgentEvent::SessionSwitched { source_id: Some(_), new_id, .. }
                                if pending_restore.is_none() => Some(new_id.clone()),
                            _ => None,
                        };
                        // BUG-078: 進捗表示（`busy_progress`）の**イベント側のライフサイクル**は
                        // `AppState::apply`が握る。ここに置いていた頃は`app_state_tests`から
                        // 一切テストできず、「engineが始めた縮約では表示が出ない」という穴が
                        // 実端末で踏むまで見つからなかった。コマンド送信時の`begin_busy`
                        // （キューへ入れた＝まだ走っていない）だけが送信側の責務として残る。
                        // BUG-072: `/sessions`で**別の会話**へ移るときは、前の会話を画面から
                        // 消してから見出し行を積む。残すと2つの会話が地続きに見え、モデルが
                        // 見ていない前半まで「この会話の一部」として読めてしまう。
                        // `/fork`（`pending_restore`が`None`）は同じ会話の続きなので消さない。
                        if switched && pending_restore.is_some() {
                            app.clear_transcript();
                        }
                        let session_id_after = match &ev {
                            harness_core::AgentEvent::SessionSwitched { new_id, .. } => Some(new_id.clone()),
                            _ => None,
                        };
                        app.apply(ev);
                        if switched {
                            if let Some(messages) = pending_restore.take() {
                                app.restore_transcript(&messages);
                            }
                            // engineが`ToolCtx`を差し替え終えた**この時点で**、パネル側も
                            // 同じオーバーレイを指す（両者がずれる窓を作らない）。
                            if let Some(next) = pending_scope.take() {
                                let unapplied = adopt_scope(&mut app, &workspace_root_for_panel, &mut review_scope, next);
                                app.transcript.push(app::TranscriptItem::Info(format!(
                                    "レビュー対象を {} のオーバーレイへ切り替えました（未適用 {unapplied} 件。`/fsstage commit` で開けます）",
                                    review_scope.session_id
                                )));
                            }
                            if let Some(session_id) = &session_id_after {
                                app.note_scope(overlay_label(&review_scope), session_id);
                            }
                        }
                        // `/fork`の第2段: 新セッション用のオーバーレイを用意し、いまの
                        // オーバーレイの中身をコピーしてから、engineへ差し替えを伝える。
                        if let Some(new_id) = forked_to {
                            fork_overlay_into(
                                &mut app,
                                &engine,
                                &workspace_root_for_panel,
                                &scope_template,
                                &mut review_scope,
                                &new_id,
                            );
                        }
                    }
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
                                    // BUG-070: 要約はLLM呼び出しなので数秒〜数十秒かかる。
                                    // 進捗を出さないとユーザーは「効いていない」と思って
                                    // 連打し、**その回数だけ要約が直列に走る**。
                                    SlashCommand::Compact => {
                                        if app.begin_busy("Compacting context") {
                                            engine.compact();
                                        } else {
                                            app.transcript.push(app::TranscriptItem::Info(
                                                "compaction is already running; ignoring this /compact".to_string(),
                                            ));
                                        }
                                    }
                                    // BUG-072: engine側は会話状態を捨てて新しいセッションへ
                                    // 差し替えるので、画面も同時に空にする。片方だけ消すと
                                    // 「画面には残っているのにモデルは覚えていない」という
                                    // `/sessions`と同型のズレになる（engineは`/clear`で
                                    // イベントを返さないので、ここで1行だけ通知も出す）。
                                    SlashCommand::Clear => {
                                        engine.clear();
                                        app.clear_transcript();
                                        app.transcript.push(app::TranscriptItem::Info(
                                            "cleared conversation (started a new session)".to_string(),
                                        ));
                                    }
                                    SlashCommand::Fork => engine.fork(),
                                    SlashCommand::Sessions => {
                                        // ピッカーの間は描画/入力ループを一時的に明け渡す
                                        // （`/clear`等と同じくengineタスクへコマンドを送るだけの
                                        // 他分岐と異なり、選択自体をここでブロッキング的に待つ）。
                                        match picker::run_picker(&mut term, &mut term_events, &sessions_dir).await {
                                            // BUG-069: 切替後の会話も画面へ積む。ただし
                                            // engineは`SessionSwitched`通知を**非同期で**返すので、
                                            // ここで積むと見出し行が復元分の後ろに来てしまう。
                                            // 通知を受け取った時点で積むよう予約しておく。
                                            Ok(picker::PickerOutcome::Selected(s, msgs)) => {
                                                // 会話とオーバーレイは1単位。置き場を用意
                                                // できなければ**どちらも切り替えない**。
                                                if let Some(next) = prepared_scope(&mut app, &workspace_root_for_panel, &scope_template, &s.id()) {
                                                    pending_restore = Some(msgs.clone());
                                                    pending_scope = Some(next.clone());
                                                    engine.switch_session(s, msgs, next);
                                                }
                                            }
                                            // ピッカーの`f`（fork）。**元セッションの未適用変更も
                                            // 分岐先へ持っていく**（`/fork`・`--fork-session`と
                                            // 同じ意味論、B-06）。
                                            Ok(picker::PickerOutcome::Forked { source_id, session: s, messages }) => {
                                                let next = scope_template.scope_for(&s.id());
                                                let from = scope_template.scope_for(&source_id);
                                                match harness_sandbox::session_scope::fork_overlay(&workspace_root_for_panel, &from, &next) {
                                                    Ok(_) => {
                                                        pending_restore = Some(messages.clone());
                                                        pending_scope = Some(next.clone());
                                                        engine.switch_session(s, messages, next);
                                                    }
                                                    Err(e) => app.transcript.push(app::TranscriptItem::Error(format!(
                                                        "{source_id} のオーバーレイを分岐先へ引き継げませんでした: {e} （会話も切り替えていません）"
                                                    ))),
                                                }
                                            }
                                            Ok(picker::PickerOutcome::Cancelled) => {}
                                            Err(e) => {
                                                app.apply(harness_core::AgentEvent::Error {
                                                    message: format!("session picker failed: {e}"),
                                                });
                                            }
                                        }
                                    }
                                    // `AppState::submit_input`が`/fsstage`を`Action::Slash`ではなく
                                    // 専用の`Action`（`OpenChangesPanel`/`ListChanges`/`CommitChanges`/
                                    // `CommitAllChanges`/`DiscardChanges`）へ直接変換するため、ここには
                                    // 到達しない（engineアクターはSandboxFsへアクセスしないため）。
                                    SlashCommand::FsStage(_) => unreachable!(
                                        "AppState::submit_input converts /fsstage into a dedicated Action before it reaches Action::Slash"
                                    ),
                                    // `Recall`（`plans/PLAN-RECALL-MEMORY.md`）。`OpenChangesPanel`と
                                    // 同じく、この非対話ループ内で直接ファイルI/Oを行う
                                    // （記憶ディレクトリは小さいJSON/Markdownのみで、
                                    // `open_panel_fs`と同程度の軽さ）。
                                    // `/workspace`はプロセス内では移らない。ループを抜けて
                                    // `harness-cli`が既存のteardownを全部通した後に起動し直す
                                    // （`RunOutcome::Relaunch`のdoc）。
                                    SlashCommand::Workspace(raw) => {
                                        match resolve_workspace_arg(&raw, &workspace_root_for_panel) {
                                            Ok(next) if next == workspace_root_for_panel => {
                                                app.transcript.push(app::TranscriptItem::Info(
                                                    "既にそのワークスペースを開いています".to_string(),
                                                ));
                                            }
                                            Ok(next) => {
                                                app.transcript.push(app::TranscriptItem::Info(format!(
                                                    "{} を開き直します（このセッションは終了し、移動先のセッション一覧が出ます）",
                                                    next.display()
                                                )));
                                                relaunch_into = Some(next);
                                                app.should_quit = true;
                                            }
                                            Err(e) => app.transcript.push(app::TranscriptItem::Error(e)),
                                        }
                                    }
                                    SlashCommand::Memory(cmd) => {
                                        for line in run_memory_slash_command(&workspace_root_for_panel, cmd) {
                                            app.transcript.push(app::TranscriptItem::Info(line));
                                        }
                                    }
                                },
                                Action::Quit => {}
                                Action::OpenChangesPanel => {
                                    match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => match fs.change_set() {
                                            Ok(entries) => {
                                                let rows = build_change_rows(&fs, entries);
                                                app.open_changes_panel(rows);
                                            }
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("failed to read changes: {e}"),
                                            }),
                                        },
                                        Err(e) => app.apply(harness_core::AgentEvent::Error {
                                            message: format!("failed to open sandbox: {e}"),
                                        }),
                                    }
                                }
                                Action::ListChanges => {
                                    match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => match fs.change_set() {
                                            Ok(entries) if entries.is_empty() => {
                                                app.transcript.push(app::TranscriptItem::Info(
                                                    "(no changes)".to_string(),
                                                ));
                                            }
                                            Ok(entries) => {
                                                for e in &entries {
                                                    app.transcript.push(app::TranscriptItem::Info(format!(
                                                        "{:<7} {}",
                                                        format!("{:?}", e.op).to_lowercase(),
                                                        e.path
                                                    )));
                                                }
                                            }
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("failed to read changes: {e}"),
                                            }),
                                        },
                                        Err(e) => app.apply(harness_core::AgentEvent::Error {
                                            message: format!("failed to open sandbox: {e}"),
                                        }),
                                    }
                                }
                                Action::CommitChanges(selection) => {
                                    match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => match apply_commit_selection(&fs, &selection) {
                                            Ok(report) => {
                                                push_apply_report(&mut app, &report);
                                                // 部分適用したファイルは**オーバーレイに残る**
                                                // （rejectしたハンクは非破壊）。件数だけの報告では
                                                // 「まだ残っている」ことが伝わらないのでパスを出す。
                                                for partial in &selection.partial {
                                                    if report.applied.contains(&partial.path) {
                                                        app.transcript.push(app::TranscriptItem::Info(format!(
                                                            "partially applied ({} hunk(s)); the rejected hunks stay in the overlay: {}",
                                                            partial.accepted_hunks.len(),
                                                            partial.path
                                                        )));
                                                    }
                                                }
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
                                Action::CommitAllChanges => {
                                    match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => match fs.apply(&ApplyOptions {
                                            only_glob: None,
                                            only_paths: None,
                                            allow_ext: false,
                                            adopt_unledgered: false,
                                        }) {
                                            Ok(report) => push_apply_report(&mut app, &report),
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
                                    match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => match fs.discard() {
                                            Ok(()) => app.transcript.push(app::TranscriptItem::Info(
                                                "discarded changes".to_string(),
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
                                Action::ResolveChanges(only_path) => {
                                    let fs_opt = match open_panel_fs(&workspace_root_for_panel, &review_scope) {
                                        Ok(fs) => Some(fs),
                                        Err(e) => {
                                            app.apply(harness_core::AgentEvent::Error {
                                                message: format!("failed to open sandbox: {e}"),
                                            });
                                            None
                                        }
                                    };
                                    if let Some(fs) = fs_opt {
                                        match harness_sandbox::resolve::prepare_resolve(&fs) {
                                            Ok((report, prepared)) => {
                                                for p in &report.applied {
                                                    app.transcript.push(app::TranscriptItem::Info(format!(
                                                        "applied (no conflict): {p}"
                                                    )));
                                                }
                                                if report.conflicts.is_empty() {
                                                    app.transcript.push(app::TranscriptItem::Info(
                                                        "no conflicts to resolve".to_string(),
                                                    ));
                                                } else {
                                                    let mut resolved = 0usize;
                                                    let mut failed = 0usize;
                                                    for attempt in &prepared.attempts {
                                                        if let Some(want) = &only_path {
                                                            if &attempt.path != want {
                                                                continue;
                                                            }
                                                        }
                                                        if attempt.needs_edit {
                                                            match harness_sandbox::resolve::editor_command() {
                                                                Ok(mut cmd) => {
                                                                    // エディタは対話子プロセスなので、
                                                                    // 代替スクリーン・raw mode・マウスキャプチャを
                                                                    // 一時的に明け渡してから起動・待機する
                                                                    // （`TerminalGuard::suspend`/`resume`）。
                                                                    if let Err(e) = guard.suspend() {
                                                                        app.transcript.push(app::TranscriptItem::Error(format!(
                                                                            "failed to suspend terminal: {e}"
                                                                        )));
                                                                        failed += 1;
                                                                        continue;
                                                                    }
                                                                    let status = cmd.arg(&attempt.merged_path).status();
                                                                    let _ = guard.resume();
                                                                    // エディタが残した画面内容を消し、
                                                                    // TUIを再描画する。
                                                                    term.clear()?;
                                                                    match status {
                                                                        Ok(s) if s.success() => {}
                                                                        Ok(s) => {
                                                                            app.transcript.push(app::TranscriptItem::Error(format!(
                                                                                "{}: editor exited with {s}; skipping",
                                                                                attempt.path
                                                                            )));
                                                                            failed += 1;
                                                                            continue;
                                                                        }
                                                                        Err(e) => {
                                                                            app.transcript.push(app::TranscriptItem::Error(format!(
                                                                                "{}: failed to launch editor: {e}",
                                                                                attempt.path
                                                                            )));
                                                                            failed += 1;
                                                                            continue;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    app.transcript.push(app::TranscriptItem::Error(format!(
                                                                        "{}: {e}",
                                                                        attempt.path
                                                                    )));
                                                                    failed += 1;
                                                                    continue;
                                                                }
                                                            }
                                                        }
                                                        match attempt.finalize(&fs) {
                                                            // BUG-065: markerが残ったまま書いた場合は
                                                            // 未解決として数える（内容は書く）。
                                                            Ok(true) => {
                                                                app.transcript.push(app::TranscriptItem::Error(format!(
                                                                    "unresolved: {} (conflict markers remain)",
                                                                    attempt.path
                                                                )));
                                                                failed += 1;
                                                            }
                                                            Ok(false) => {
                                                                app.transcript.push(app::TranscriptItem::Info(format!(
                                                                    "resolved: {}",
                                                                    attempt.path
                                                                )));
                                                                resolved += 1;
                                                            }
                                                            Err(e) => {
                                                                app.transcript.push(app::TranscriptItem::Error(format!(
                                                                    "{}: failed to finalize: {e}",
                                                                    attempt.path
                                                                )));
                                                                failed += 1;
                                                            }
                                                        }
                                                    }
                                                    for s in &prepared.skipped {
                                                        if let Some(want) = &only_path {
                                                            if &s.path != want {
                                                                continue;
                                                            }
                                                        }
                                                        app.transcript.push(app::TranscriptItem::Info(format!(
                                                            "skipped: {} ({})",
                                                            s.path, s.reason
                                                        )));
                                                    }
                                                    app.transcript.push(app::TranscriptItem::Info(format!(
                                                        "{resolved} resolved, {failed} skipped/failed"
                                                    )));
                                                }
                                            }
                                            Err(e) => app.apply(harness_core::AgentEvent::Error {
                                                message: format!("resolve failed: {e}"),
                                            }),
                                        }
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
            _ = tick.tick() => {
                app.tick();
                app.wait_state = poll_wait_state();
            }
        }

        // BUG-076: 遡れる上限は折り畳み状態と端末幅に依存し、描画時にしか決まらない。
        // 描いた直後に状態そのものを切り詰める——表示側だけで止めると、先頭に着いた後も
        // ホイールを回した分だけ`scroll_offset`が伸び、同じ回数下へ回すまで画面が動かない。
        let mut max_scroll = 0u16;
        term.draw(|f| max_scroll = ui::render(f, &app))?;
        app.clamp_scroll(max_scroll);

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

    Ok(match relaunch_into {
        Some(workspace) => RunOutcome::Relaunch { workspace },
        None => RunOutcome::Quit,
    })
}
