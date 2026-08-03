//! `CognitionLevel::Always`（HIVループ・ライト構成）の**決定的トランスクリプト**。
//! `docs/INDEX.md` M15の完了条件「仮説→調査→検証のgolden test」。
//!
//! `crates/harness-cognition/src/hiv/mod.rs`のユニットテストが状態機械の遷移を
//! （`Executor`をスクリプト化して）固定するのに対し、こちらは**実際の経路を端から端まで**
//! 通す: `CognitiveOrchestrator` → `TurnExecutor` → `PermissionArbiter` → 実ツール
//! （`read_file`が本当にファイルを読む）→ `WorkingMemory` → 最終回答。
//!
//! ここで固定したいのは3点。
//!
//! 1. モデルへ送るリクエスト列（何を何回、どのフェーズで送ったか）
//! 2. ユーザに見える出力が**最終回答だけ**であること（フェーズ出力のJSONが漏れない）
//! 3. 生出力がscratchに落ち、台帳にも組み立て済みリクエストにも現れないこと

use harness_cognition::{CognitiveOrchestrator, PhaseBudgets};
use harness_core::{
    AgentEvent, BlockKind, CognitionLevel, ContentBlock, Phase, Role, StopReason, StreamEvent,
    ToolCtx, Usage,
};
use harness_engine::{AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

const SESSION_ID: &str = "session-15";

fn text_turn(text: &str) -> Vec<StreamEvent> {
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
            usage: Usage {
                input: 100,
                output: 20,
                cache_read: 0,
                cache_creation: 0,
            },
        },
    ]
}

/// スキーマとツールを融合できるプロバイダのInvestigateターン: 計画（JSON）とツール呼び出しを
/// 同じアシスタントメッセージで返す（`CallKind::Fused`）。
fn plan_and_tool_turn(plan: &str, tool: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: plan.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: tool.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 1,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 1 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage {
                input: 100,
                output: 20,
                cache_read: 0,
                cache_creation: 0,
            },
        },
    ]
}

fn scripted_turns() -> Vec<Vec<StreamEvent>> {
    vec![
        // 1. Hypothesize
        text_turn(
            &serde_json::json!({
                "hypotheses": [{
                    "statement": "run_shellはPowerShellを起動している",
                    "predicts": ["shell.rsにpowershellの記述が無ければ偽"],
                    "confidence": 0.7
                }]
            })
            .to_string(),
        ),
        // 2. Investigate（計画 + read_fileの実行）
        plan_and_tool_turn(
            &serde_json::json!({
                "plan": [{ "source": "read_file", "query": "shell.rs", "expects": "起動するシェル名" }]
            })
            .to_string(),
            "read_file",
            serde_json::json!({ "path": "shell.rs" }),
        ),
        // 3. Distill
        text_turn(
            &serde_json::json!({
                "evidence": [{
                    "claim": "shell.rsがpowershell.exeを起動している",
                    "relation": "supports",
                    "source": "shell.rs"
                }]
            })
            .to_string(),
        ),
        // 4. Verify
        text_turn(
            &serde_json::json!({
                "verdict": "confirms",
                "missing": [],
                "note": "起動コマンドを直接読んだ"
            })
            .to_string(),
        ),
        // 5. Decide
        text_turn(
            &serde_json::json!({
                "action": "PowerShellを前提に手順を書く",
                "then_verify": "run_shellでecho $PSVersionTableを実行する"
            })
            .to_string(),
        ),
    ]
}

struct Run {
    outcome: harness_engine::AgentLoopOutcome,
    requests: Vec<harness_core::CompletionRequest>,
    events: Vec<AgentEvent>,
    deltas: String,
    messages: Vec<harness_core::Message>,
    workspace: tempfile::TempDir,
}

async fn run_always(turns: Vec<Vec<StreamEvent>>) -> Run {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(
        workspace.path().join("shell.rs"),
        "let mut cmd = Command::new(\"powershell.exe\");",
    )
    .unwrap();
    let record = workspace.path().join("requests.jsonl");

    let provider = MockProvider::new(turns).with_request_record_path(record.clone());
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(workspace.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("run_shellがどのシェルを使うか、根拠を挙げて答えて");

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut deltas = String::new();

    let orchestrator = CognitiveOrchestrator::new(CognitionLevel::Always, PhaseBudgets::default())
        .unwrap()
        .with_session_id(SESSION_ID);
    let outcome = orchestrator
        .run(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 1_000,
                max_turns: 30,
            },
            Some(&events_tx),
            None,
            |d: &str| deltas.push_str(d),
        )
        .await
        .unwrap();

    let mut events = Vec::new();
    while let Ok(ev) = events_rx.try_recv() {
        events.push(ev);
    }
    let requests = std::fs::read_to_string(&record)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    Run {
        outcome,
        requests,
        events,
        deltas,
        messages: state.messages.clone(),
        workspace,
    }
}

fn phases(events: &[AgentEvent]) -> Vec<Phase> {
    events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::PhaseChanged { phase } => Some(*phase),
            _ => None,
        })
        .collect()
}

/// **M15の受入条件**: 仮説→調査→蒸留→検証→決定が決定的に走り、台帳に基づく回答が出る。
#[tokio::test]
async fn hiv_light_runs_hypothesize_to_decide_deterministically() {
    let run = run_always(scripted_turns()).await;

    assert_eq!(
        phases(&run.events),
        vec![
            Phase::Hypothesize,
            Phase::Investigate,
            Phase::Distill,
            Phase::Verify,
            Phase::Decide
        ]
    );
    assert_eq!(run.requests.len(), 5, "1フェーズ1コール");
    assert_eq!(run.outcome.stop_reason, StopReason::EndTurn);
    // usageは全フェーズの合計（5コール × input:100）。
    assert_eq!(run.outcome.usage.input, 500);

    // 台帳イベントが順に出る（TUIの表示・ヘッドレスjsonlの中身はこれ）。
    let hypotheses: Vec<&AgentEvent> = run
        .events
        .iter()
        .filter(|e| matches!(e, AgentEvent::HypothesisFormed { .. }))
        .collect();
    assert_eq!(hypotheses.len(), 1);
    let AgentEvent::HypothesisFormed { id, predicts, .. } = hypotheses[0] else {
        panic!()
    };
    assert_eq!(id, "H2");
    assert!(!predicts.is_empty(), "反証条件を伴わない仮説は通らない");

    let verification = run
        .events
        .iter()
        .find_map(|e| match e {
            AgentEvent::VerificationResult {
                verdict, promoted, ..
            } => Some((verdict.clone(), *promoted)),
            _ => None,
        })
        .expect("verification event");
    assert_eq!(verification, ("confirms".to_string(), true));

    // 最終回答は台帳から組まれ、出典を伴う。
    assert!(
        run.outcome.text.contains("PowerShellを前提に手順を書く"),
        "{}",
        run.outcome.text
    );
    assert!(
        run.outcome.text.contains("shell.rs"),
        "出典が無い回答は監査できない: {}",
        run.outcome.text
    );
}

/// ユーザに見える出力は**最終回答だけ**（フェーズ出力のJSONが混ざらない）。
#[tokio::test]
async fn phase_json_never_reaches_the_user_facing_output() {
    let run = run_always(scripted_turns()).await;

    // ヘッドレスのtext出力（`on_text_delta`）とTUIのトランスクリプト（`TextDelta`）の両方。
    let text_deltas: String = run
        .events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    for visible in [&run.deltas, &text_deltas] {
        assert!(!visible.contains("\"predicts\""), "{visible}");
        assert!(!visible.contains("\"verdict\""), "{visible}");
        assert!(!visible.contains("\"then_verify\""), "{visible}");
        assert!(visible.contains("## 結論"), "{visible}");
    }
    assert_eq!(run.deltas, text_deltas);

    // 会話履歴へ積まれるのも最終回答だけ（セッション永続化・`--resume`はこれを見る）。
    assert_eq!(run.messages.len(), 2);
    assert_eq!(run.messages[1].role, Role::Assistant);
    let ContentBlock::Text(assistant) = &run.messages[1].content[0] else {
        panic!()
    };
    assert_eq!(assistant, &run.outcome.text);
}

/// 生出力はscratchに落ち、モデルへ送るリクエストにはどこにも現れない（§5・§6.3）。
#[tokio::test]
async fn raw_tool_output_lives_in_scratch_and_not_in_any_request() {
    let run = run_always(scripted_turns()).await;

    let raw_dir = run
        .workspace
        .path()
        .join(".harness")
        .join("cognition")
        .join(SESSION_ID)
        .join("raw");
    let files: Vec<_> = std::fs::read_dir(&raw_dir).unwrap().flatten().collect();
    assert_eq!(files.len(), 1, "観測1件がscratchへ退避される");
    let stashed = std::fs::read_to_string(files[0].path()).unwrap();
    assert!(stashed.contains("Command::new"), "{stashed}");

    // 生出力そのものを含むリクエストはDistillの1本だけ（台帳スライスには入らない）。
    // 目印には**生出力にしか無い断片**を使う——蒸留済みclaimにも出る語（powershell等）で
    // 数えると、台帳スライス経由の出現を生出力と取り違える。
    let with_raw = run
        .requests
        .iter()
        .filter(|req| serde_json::to_string(req).unwrap().contains("Command::new"))
        .count();
    assert_eq!(
        with_raw, 1,
        "生出力は蒸留コールにだけ載る（台帳には`RawRef`しか持たない）"
    );

    // 台帳から組んだ最終回答にも生出力は載らない（載るのは蒸留済みのclaim）。
    assert!(
        !run.outcome.text.contains("Command::new"),
        "{}",
        run.outcome.text
    );
    assert!(run
        .outcome
        .text
        .contains("shell.rsがpowershell.exeを起動している"));
}

/// 各フェーズのリクエストが§3.3の入力予算に収まる（実経路での担保）。
#[tokio::test]
async fn every_phase_request_stays_within_its_input_budget() {
    let run = run_always(scripted_turns()).await;
    let budgets = PhaseBudgets::default();

    for req in &run.requests {
        let phase = Phase::ALL
            .into_iter()
            .find(|p| {
                req.system
                    .first()
                    .is_some_and(|s| s.text == harness_cognition::prompts::system_prompt(*p))
            })
            .expect("each request carries a phase system prompt");
        let estimated = harness_engine::estimate_tokens(req);
        assert!(
            estimated <= u64::from(budgets.get(phase).max_in),
            "{phase}: {estimated} > {}",
            budgets.get(phase).max_in
        );
    }
}

/// 会話履歴を丸ごと送らない（§5「履歴丸投げの廃止」）。どのフェーズのリクエストも
/// ユーザ発話1件分より多くのメッセージを持たない。
#[tokio::test]
async fn no_request_carries_the_conversation_transcript() {
    let run = run_always(scripted_turns()).await;
    for req in &run.requests {
        assert_eq!(req.messages.len(), 1, "台帳スライス1通だけを送る");
        assert_eq!(req.messages[0].role, Role::User);
    }
}
