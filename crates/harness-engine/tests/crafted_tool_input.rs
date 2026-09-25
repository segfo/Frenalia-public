//! [BUG-164](../../../docs/bugs/BUG-164.md) の回帰テスト——ツールの入力に**使いもしない項目**を足して
//! 判定を騙す細工が、書込まで届かないこと。
//!
//! 細工の形: `write_file` の入力に `command: "x"` を足す。判定に渡す文字列を入力のキーで選んでいた頃は、
//! 設定注入パス（`.git/config`）の拒否が `"x"` で判定されて当たらず、余分な項目は読み込みで黙って
//! 捨てられて書込が続いた。**判定の側と読み込みの側のどちらで止まっても、ファイルは変わってはいけない。**
//!
//! 素直な入力と細工した入力を**同じモードで対にして**測る（`test-logic-rules`・B-35）。
//! 対照として、細工の無い素直な書込が普通のファイルには届くことも確かめる——
//! 「何も書けない」状態で緑になるテストにしないため。
//!
//! `ToolCtx::new` はオーバーレイ無し（直接書くモード）で、BUG-164 の再現で実ファイルまで届いた構成と同じ。

use harness_core::{BlockKind, ContentBlock, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

const ORIGINAL_GIT_CONFIG: &str = "[core]\n\trepositoryformatversion = 0\n";
const EVIL_GIT_CONFIG: &str = "[core]\n\thooksPath = /tmp/evil\n";

fn tool_use_turn(input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: "write_file".to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

fn end_turn() -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: "done".to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

/// `.git/config` を持つワークスペースで `write_file` を1回だけ撃ち、ツール結果（本文・エラーか）を返す。
async fn run_write(
    workspace: &std::path::Path,
    mode: PermissionMode,
    input: serde_json::Value,
) -> (String, bool) {
    let provider = MockProvider::new(vec![tool_use_turn(input), end_turn()]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("write it");

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(workspace.to_path_buf());
    // 判定器のワークスペースルートは本物と同じ値にする（設定注入パスの判定はルートからの相対で見る）。
    let arbiter = PermissionArbiter::new(mode, vec![], workspace);

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
        },
        None,
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");

    state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                content, is_error, ..
            } => Some((content.clone(), *is_error)),
            _ => None,
        })
        .expect("the write_file call must produce a tool_result")
}

fn workspace_with_git_config() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join(".git/config"), ORIGINAL_GIT_CONFIG).unwrap();
    dir
}

fn git_config(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join(".git/config")).unwrap()
}

/// 書込を自動許可するモード2つで、素直な入力と細工した入力のどちらも `.git/config` を変えない。
#[tokio::test]
async fn crafted_extra_field_cannot_write_git_config_in_auto_write_modes() {
    for mode in [PermissionMode::AcceptEdits, PermissionMode::AcceptAll] {
        // 素直な入力: 設定注入パスの拒否で止まる。
        let dir = workspace_with_git_config();
        let (out, is_error) = run_write(
            dir.path(),
            mode,
            serde_json::json!({ "path": ".git/config", "content": EVIL_GIT_CONFIG }),
        )
        .await;
        assert!(is_error, "{mode:?}: honest write to .git/config must fail: {out}");
        assert_eq!(git_config(&dir), ORIGINAL_GIT_CONFIG, "{mode:?}: honest input");

        // 細工した入力: 使いもしない `command` を足す。どこで止まってもよいが、書込は届かない。
        let dir = workspace_with_git_config();
        let (out, is_error) = run_write(
            dir.path(),
            mode,
            serde_json::json!({
                "path": ".git/config",
                "content": EVIL_GIT_CONFIG,
                "command": "x",
            }),
        )
        .await;
        assert!(is_error, "{mode:?}: crafted write to .git/config must fail: {out}");
        assert_eq!(git_config(&dir), ORIGINAL_GIT_CONFIG, "{mode:?}: crafted input");
    }
}

/// 対照: 余分な項目の無い素直な書込は、普通のファイルには届く。
/// 余分な項目を1つ足すと、普通のファイルでも書かれない（知らない項目を拒否している）。
#[tokio::test]
async fn honest_write_reaches_a_normal_file_but_an_extra_field_is_refused() {
    let dir = workspace_with_git_config();
    let (out, is_error) = run_write(
        dir.path(),
        PermissionMode::AcceptEdits,
        serde_json::json!({ "path": "notes.txt", "content": "hello" }),
    )
    .await;
    assert!(!is_error, "honest write must succeed: {out}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("notes.txt")).unwrap(),
        "hello"
    );

    let (out, is_error) = run_write(
        dir.path(),
        PermissionMode::AcceptEdits,
        serde_json::json!({ "path": "other.txt", "content": "hello", "command": "x" }),
    )
    .await;
    assert!(is_error, "an unknown field must be refused: {out}");
    assert!(
        !dir.path().join("other.txt").exists(),
        "a refused input must not write anything"
    );
}
