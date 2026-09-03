//! `plans/DESIGN.md` L349「JSONL 追記型セッション永続化（`--resume`/`--continue`）」の
//! 統合テスト。`main.rs`のCLI引数解析は経由せず、`main.rs`が実際に呼ぶのと同じ
//! `harness_engine::SessionStore` + `harness_cli::run_headless`の組み合わせを直接駆動する
//! （§ワークスペース構成の慣例、`headless_output.rs`と同じ方針）。

use harness_cognition::{CognitiveOrchestrator, PhaseBudgets};
use harness_core::{BlockKind, CognitionLevel, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{
    AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode, SessionStore,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

use harness_cli::{run_headless, OutputFormat};

fn end_turn(text: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: text.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

async fn run_one_turn(
    session: &SessionStore,
    state: &mut ConversationState,
    prompt: &str,
    reply: &str,
) {
    drive_turn(
        session,
        state,
        prompt,
        vec![end_turn(reply)],
        Default::default(),
    )
    .await;
}

/// 1ターンを回して`main.rs`（`cli/startup/run_agent.rs`）と**同じ規則**でセッションへ書く。
/// 圧縮が履歴の先頭を畳んだターンだけチェックポイントを書く、という分岐まで含めて模す。
async fn drive_turn(
    session: &SessionStore,
    state: &mut ConversationState,
    prompt: &str,
    provider_turns: Vec<Vec<StreamEvent>>,
    compaction: harness_engine::compaction::CompactionPolicy,
) {
    state.push_user_text(prompt);
    session
        .append_messages(&state.messages[state.messages.len() - 1..])
        .unwrap();
    let before = state.mark();

    let provider = MockProvider::new(provider_turns);
    let tools = ToolRegistry::with_builtin_tools();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace");

    let mut out = Vec::new();
    run_headless(
        &provider,
        state,
        &tools,
        &ctx,
        &arbiter,
        &CognitiveOrchestrator::new(CognitionLevel::Off, PhaseBudgets::default()).unwrap(),
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction,
            degeneracy: None,
        },
        OutputFormat::Text,
        &mut out,
    )
    .await;
    if state.folded_since(before) {
        session.append_checkpoint(&state.messages).unwrap();
    } else {
        session.append_messages(state.since(before)).unwrap();
    }
}

/// `--resume <id>`相当: セッションファイルに保存済みのメッセージが新しい`ConversationState`へ
/// そのまま読み込まれ、続きのターンを送っても両方の会話が1つのJSONLへ追記されること。
#[tokio::test]
async fn resume_restores_prior_messages_and_appends_continuation() {
    let sessions_dir = tempfile::tempdir().unwrap();
    let session = SessionStore::create_new(sessions_dir.path()).unwrap();
    let mut state = ConversationState::new(Vec::new());

    run_one_turn(&session, &mut state, "first question", "first answer").await;

    // 新規プロセス相当: 同じセッションファイルを開き直し、messagesを先読みする
    // （main.rsの`--resume`経路と同じ`SessionStore::open`+`load_messages`）。
    let resumed_session = SessionStore::open(session.path().to_path_buf());
    let mut resumed_state = ConversationState::new(Vec::new());
    resumed_state.messages = resumed_session.load_messages().unwrap();

    assert_eq!(resumed_state.messages.len(), state.messages.len());
    assert_eq!(resumed_state.messages, state.messages);

    run_one_turn(
        &resumed_session,
        &mut resumed_state,
        "second question",
        "second answer",
    )
    .await;

    let all_messages = SessionStore::open(session.path().to_path_buf())
        .load_messages()
        .unwrap();
    // 1ターン目のuser+assistant、2ターン目のuser+assistantの計4件が1ファイルに追記されている。
    assert_eq!(all_messages.len(), 4);
}

/// ターン中に圧縮が走ったら**チェックポイント**が書かれ、`--resume`が圧縮前の長い履歴へ
/// 戻らないこと。JSONLは追記専用なので、これが無いと再開した瞬間に畳んだはずの履歴が
/// 丸ごと復活する（圧縮の意味が消える）。
#[tokio::test]
async fn resume_after_a_compaction_starts_from_the_compacted_history() {
    let sessions_dir = tempfile::tempdir().unwrap();
    let session = SessionStore::create_new(sessions_dir.path()).unwrap();
    let mut state = ConversationState::new(Vec::new());

    for i in 0..3 {
        run_one_turn(
            &session,
            &mut state,
            &format!("question {i}"),
            &"x".repeat(2_000),
        )
        .await;
    }
    let before_compaction = SessionStore::open(session.path().to_path_buf())
        .load_messages()
        .unwrap();
    assert_eq!(before_compaction.len(), 6);

    // 実`n_ctx`が小さいローカルモデル相当のポリシー。この履歴では次のターンの前に
    // 予防的縮約の②（ローリング要約）が走る。
    drive_turn(
        &session,
        &mut state,
        "one more",
        vec![end_turn("summary of earlier turns"), end_turn("done")],
        harness_engine::compaction::CompactionPolicy {
            trigger_ratio: 0.5,
            target_ratio: 0.3,
            context_window: 1_000,
        },
    )
    .await;
    assert!(
        state.messages.len() < 8,
        "履歴が畳まれていない: {}",
        state.messages.len()
    );

    let resumed = SessionStore::open(session.path().to_path_buf())
        .load_messages()
        .unwrap();
    assert_eq!(resumed, state.messages, "resumeは圧縮後の履歴から始まる");
}

/// `--continue`相当: `.harness/sessions/`内の最新セッションを自動選択できること。
#[tokio::test]
async fn continue_picks_the_most_recently_modified_session() {
    let sessions_dir = tempfile::tempdir().unwrap();
    let older = SessionStore::create_new(sessions_dir.path()).unwrap();
    let mut older_state = ConversationState::new(Vec::new());
    run_one_turn(
        &older,
        &mut older_state,
        "older session prompt",
        "older reply",
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let newer = SessionStore::create_new(sessions_dir.path()).unwrap();
    let mut newer_state = ConversationState::new(Vec::new());
    run_one_turn(
        &newer,
        &mut newer_state,
        "newer session prompt",
        "newer reply",
    )
    .await;

    let latest = SessionStore::resume_latest(sessions_dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(latest.path(), newer.path());
    let restored = latest.load_messages().unwrap();
    assert_eq!(restored, newer_state.messages);
}

/// `--resume <id> --fork-session`相当: Fork後に元セッションへは何も追記されず、
/// Fork先だけに以降のターンが積まれること。
#[tokio::test]
async fn fork_session_leaves_source_untouched_and_continues_on_fork() {
    let sessions_dir = tempfile::tempdir().unwrap();
    let source = SessionStore::create_new(sessions_dir.path()).unwrap();
    let mut source_state = ConversationState::new(Vec::new());
    run_one_turn(
        &source,
        &mut source_state,
        "original prompt",
        "original reply",
    )
    .await;

    // main.rsの`--fork-session`経路と同じ`SessionStore::fork_from`。
    let forked = SessionStore::fork_from(sessions_dir.path(), source.path()).unwrap();
    assert_ne!(forked.path(), source.path());
    let mut forked_state = ConversationState::new(Vec::new());
    forked_state.messages = forked.load_messages().unwrap();
    assert_eq!(forked_state.messages, source_state.messages);

    run_one_turn(&forked, &mut forked_state, "forked prompt", "forked reply").await;

    // 元セッションは2件（user+assistant）のまま、Fork先だけ4件に増える。
    let source_messages = SessionStore::open(source.path().to_path_buf())
        .load_messages()
        .unwrap();
    assert_eq!(source_messages.len(), 2);
    let forked_messages = SessionStore::open(forked.path().to_path_buf())
        .load_messages()
        .unwrap();
    assert_eq!(forked_messages.len(), 4);
}

/// `--resume <bare-millis>`と`--resume session-<millis>`の両方が同じファイルに解決できること
/// （`SessionStore::resolve_path`、main.rsの`resolve_session`が使う正規化）。
#[test]
fn resolve_path_normalizes_both_id_forms() {
    let sessions_dir = tempfile::tempdir().unwrap();
    let store = SessionStore::create_new(sessions_dir.path()).unwrap();
    let prefixed = store.id();
    let bare = prefixed.strip_prefix("session-").unwrap();

    assert_eq!(
        SessionStore::resolve_path(sessions_dir.path(), &prefixed),
        *store.path()
    );
    assert_eq!(
        SessionStore::resolve_path(sessions_dir.path(), bare),
        *store.path()
    );
}
