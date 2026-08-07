//! 起動パイプライン Stage3: セッションの解決と履歴読込。
//!
//! `sessions_dir`作成・`SessionStore`解決・`--fork-session`・履歴読込。

use super::*;
use super::configure::Configured;

/// [`stage_open_session`]の出力。Stage4（`stage_prepare_sandbox`）以降が必要とする値を運ぶ。
pub(super) struct SessionOpened {
    pub(super) cli: Cli,
    pub(super) workspace_root: PathBuf,
    pub(super) resume_wants_picker: bool,
    pub(super) settings: harness_config::Settings,
    pub(super) provider: Box<dyn LlmProvider>,
    pub(super) model: String,
    pub(super) max_turns: usize,
    pub(super) compaction: harness_engine::compaction::CompactionPolicy,
    pub(super) degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    pub(super) enter_submits: bool,
    pub(super) tools: ToolRegistry,
    pub(super) arbiter: PermissionArbiter,
    pub(super) cognition: CognitiveOrchestrator,
    pub(super) sessions_dir: PathBuf,
    pub(super) session: harness_engine::SessionStore,
    pub(super) session_messages: Vec<harness_core::Message>,
    /// `--fork-session`でforkした場合の**元**セッションID。
    ///
    /// Stage4がここから元セッションのオーバーレイを引き継がせる
    /// （`session_scope::fork_overlay`）。**forkは会話だけでなく変更も分岐する**——
    /// コピーしないと、`--resume <id> --fork-session`で開いた瞬間にそれまでの未適用変更が
    /// レビュー対象から消える（実体は元セッション側に残るので失われはしないが、画面からは
    /// 消える）。TUIの`/fork`と意味論を揃えるための値である（`bug-pattern-rules` B-06:
    /// 同じ状態を作り得る経路を全部数える）。
    pub(super) forked_from_session_id: Option<String>,
}

/// `sessions_dir`作成・`SessionStore`解決・`--fork-session`・履歴読込。
pub(super) fn stage_open_session(configured: Configured) -> Result<SessionOpened, ExitCode> {
    let Configured {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
        settings,
        provider,
        model,
        max_turns,
        compaction,
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        cognition,
    } = configured;

    // JSONL追記型セッション永続化（M9、§非対話モード「JSONL 追記型セッション永続化
    // （`--resume`/`--continue`）」）。`.harness/sessions/`直下に1ファイル1セッション。
    let sessions_dir = workspace_root.join(".harness").join("sessions");
    if let Err(e) = std::fs::create_dir_all(&sessions_dir) {
        eprintln!(
            "failed to create sessions directory {}: {e}",
            sessions_dir.display()
        );
        return Err(ExitCode::FAILURE);
    }
    let mut session =
        match resolve_session(&sessions_dir, resume_id.as_deref(), cli.continue_session) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e}");
                return Err(ExitCode::FAILURE);
            }
        };

    // `--fork-session`: 解決済みの元セッションを不変のまま、全履歴を新規セッションへコピーして
    // 以降の追記先を切り替える（Claude Codeの`--fork-session`/`/branch`相当）。
    let mut forked_from_session_id = None;
    if cli.fork_session {
        let source_id = session.id();
        match harness_engine::SessionStore::fork_from(&sessions_dir, session.path()) {
            Ok(forked) => {
                eprintln!("forked session {source_id} -> {}", forked.id());
                session = forked;
                forked_from_session_id = Some(source_id);
            }
            Err(e) => {
                eprintln!("failed to fork session {source_id}: {e}");
                return Err(ExitCode::FAILURE);
            }
        }
    }

    // `ConversationState`自体は`tool_ctx`確定後（下記）に組み立てる。systemは`tool_ctx`が運ぶ
    // 環境事実（`harness_engine::system_blocks_for`）から作るため、先に`tool_ctx`が要る
    // （`run_shell`不安定性調査で見つかった「systemが一切送られていない」欠陥への対処、
    // `plans/DESIGN.md` §システムプロンプト参照）。
    let session_messages = match session.load_messages() {
        Ok(msgs) => msgs,
        Err(e) => {
            eprintln!("failed to load session {}: {e}", session.path().display());
            return Err(ExitCode::FAILURE);
        }
    };

    Ok(SessionOpened {
        cli,
        workspace_root,
        resume_wants_picker,
        settings,
        provider,
        model,
        max_turns,
        compaction,
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        // 認知レイヤーの生出力scratch（`.harness/cognition/<session-id>/raw/`）を、会話履歴と
        // **同じセッションID**へ向ける（`plans/DESIGN-COGNITION.md` §5）。M20の`--resume`が
        // 台帳と履歴を同じ鍵で復元できるようにするため、ここで確定したIDを渡す。
        cognition: cognition.with_session_id(session.id()),
        sessions_dir,
        session,
        session_messages,
        forked_from_session_id,
    })
}

