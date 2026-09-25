//! M16の受入条件（`docs/INDEX.md`）を端から端まで通す:
//! **read系MCP mockを使い「webの主張をMCPで裏取り」するトランスクリプト**と、
//! **書込系MCPがパーミッションゲートに掛かること**。
//!
//! `hiv_light_transcript.rs`がM15の遷移そのものを固定するのに対し、こちらは
//! `plans/DESIGN-COGNITION.md` §4（Validity & SourceBroker）が回っていることを見る。
//!
//! 1. 別種ソースでの裏取りが成立すると`Corroborated`へ上がり、確証まで進む（§4.2/§4.3）
//! 2. MCPが無ければ`SingleSource`のまま**結論は出し**、「MCP裏取り不可」を明記する（§4.2）
//! 3. 矛盾した観測は決着するまで確証を止める（§3.4の遷移条件・§4.3の矛盾検出）
//! 4. 書込系MCPはInvestigateの候補集合に入らない（§7.3 ToolGate、最終強制はパーミッション）
//!
//! # MCPクライアント（M15.5）を必要としない
//!
//! 認知レイヤーがMCPについて知っているのは**ツール名の名前空間だけ**なので、
//! `mcp__<server>__<tool>`という名前のスタブツールを`ToolRegistry`へ登録すれば全経路を通せる。
//! 名前空間が本物（`harness_mcp::decl::namespaced_tool_name`）と一致していることは、
//! 両方へ依存する`harness-cli`の`tests/mcp_namespace_drift.rs`が固定している。

use std::sync::Arc;

use async_trait::async_trait;
use harness_cognition::{CognitiveOrchestrator, PhaseBudgets, SourceCatalog, SourceEntry};
use harness_core::{
    AgentEvent, BlockKind, CognitionLevel, ContentBlock, RiskClass, StopReason, StreamEvent, Tool,
    ToolCtx, ToolError, ToolOutput, Usage,
};
use harness_engine::{AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

const READ_MCP: &str = "mcp__company-docs__search_docs";
const WRITE_MCP: &str = "mcp__jira__create_issue";

// --- スタブMCPツール ---------------------------------------------------------

/// MCPサーバのツールの器。認知層から見えるのは**名前と`RiskClass`**だけなので、これで足りる。
///
/// `RiskClass`をコンストラクタで受けるのはD-40の写し——実装では**ユーザ宣言**が
/// `Tool::risk()`の答えを決め、無宣言のツールは非readになる。認知層はその結果に従うだけで、
/// 判断を足さない。
struct StubMcpTool {
    name: &'static str,
    risk: RiskClass,
    output: &'static str,
}

#[async_trait]
impl Tool for StubMcpTool {
    fn name(&self) -> &str {
        self.name
    }
    fn description(&self) -> &str {
        "stub mcp tool"
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "query": { "type": "string" } },
            "required": ["query"],
            "additionalProperties": false
        })
    }
    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        self.risk
    }
    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<harness_core::PermissionSubject, ToolError> {
        Ok(harness_core::PermissionSubject::Text(input.to_string()))
    }
    async fn call(
        &self,
        _input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput {
            content: self.output.to_string(),
            is_error: false,
        })
    }
}

// --- スクリプト用のヘルパー ---------------------------------------------------

fn usage() -> Usage {
    Usage {
        input: 100,
        output: 20,
        cache_read: 0,
        cache_creation: 0,
    }
}

fn text_turn(value: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: value.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: usage(),
        },
    ]
}

/// Investigateターン（計画のJSON + ツール呼び出しを同じメッセージで返す＝`CallKind::Fused`）。
fn plan_and_tool_turn(id: &str, tool: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: serde_json::json!({
                "plan": [{ "source": tool, "query": "run_shell", "expects": "起動するシェル名" }]
            })
            .to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
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
            usage: usage(),
        },
    ]
}

fn distill(claim: &str, contradicts: &[&str]) -> Vec<StreamEvent> {
    text_turn(serde_json::json!({
        "evidence": [{
            "claim": claim,
            "relation": "supports",
            "source": "（自己申告の出典は台帳に入らない）",
            "contradicts": contradicts
        }]
    }))
}

fn hypothesize() -> Vec<StreamEvent> {
    text_turn(serde_json::json!({
        "hypotheses": [{
            "statement": "run_shellはPowerShellを起動している",
            "predicts": ["shell.rsにpowershellの記述が無ければ偽"],
            "confidence": 0.7
        }]
    }))
}

fn verify(verdict: &str) -> Vec<StreamEvent> {
    text_turn(serde_json::json!({
        "verdict": verdict, "missing": [], "note": "集めた証拠を突き合わせた"
    }))
}

fn decide() -> Vec<StreamEvent> {
    text_turn(serde_json::json!({
        "action": "PowerShellを前提に手順を書く",
        "then_verify": "run_shellでecho $PSVersionTableを実行する"
    }))
}

// --- 実行 --------------------------------------------------------------------

struct Run {
    text: String,
    stop_reason: StopReason,
    requests: Vec<harness_core::CompletionRequest>,
    events: Vec<AgentEvent>,
}

/// `mcp_tools`が空ならMCP未接続の構成（§4.2のフォールバック経路）になる。
async fn run_always(turns: Vec<Vec<StreamEvent>>, mcp_tools: &[(&'static str, RiskClass)]) -> Run {
    run_always_bounded(turns, mcp_tools, 30).await
}

/// `max_turns`は認知層では**フェーズコールの総数**の上限になる（§3.5）。決着しない台本を
/// 有限で畳むために、テストから明示できるようにしている。
async fn run_always_bounded(
    turns: Vec<Vec<StreamEvent>>,
    mcp_tools: &[(&'static str, RiskClass)],
    max_turns: usize,
) -> Run {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(
        workspace.path().join("shell.rs"),
        "let mut cmd = Command::new(\"powershell.exe\");",
    )
    .unwrap();
    let record = workspace.path().join("requests.jsonl");

    let provider = MockProvider::new(turns).with_request_record_path(record.clone());
    let mut tools = ToolRegistry::with_builtin_tools();
    for (name, risk) in mcp_tools {
        tools.register(Arc::new(StubMcpTool {
            name,
            risk: *risk,
            output: "社内仕様: run_shellはPowerShellを既定シェルとする",
        }));
    }

    // カタログはサーバ単位で宣言する（ユーザが書く単位）。ツールが登録されていなければ
    // このエントリは`available`に出てこない＝MCP未接続として扱われる。
    let catalog = SourceCatalog::with_builtin_defaults().merged_with([
        SourceEntry::from_declaration(
            "mcp/company-docs",
            Some("mcp"),
            vec!["社内仕様".to_string()],
            Some("high"),
            Some("authoritative"),
        ),
        SourceEntry::from_declaration(
            "mcp/jira",
            Some("mcp"),
            vec!["課題".to_string()],
            Some("high"),
            None,
        ),
    ]);

    let ctx = ToolCtx::new(workspace.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace");
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text("run_shellがどのシェルを使うか、根拠を挙げて答えて");

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

    // Recallは明示的に切る（理由は`hiv_light_transcript.rs`の同じ箇所と同一——実`%APPDATA%`を
    // 汚さない。Recall本体のE2Eは`harness-cli`の`tests/recall_e2e.rs`）。
    let orchestrator = CognitiveOrchestrator::new(CognitionLevel::Always, PhaseBudgets::default())
        .unwrap()
        .with_recall_settings(false, false, 5, false)
        .with_catalog(catalog)
        .with_session_id("session-16");
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
                max_turns,
                compaction: Default::default(),
                degeneracy: None,
            },
            Some(&events_tx),
            None,
            |_: &str| {},
        )
        .await
        .unwrap();

    let mut events = Vec::new();
    while let Ok(ev) = events_rx.try_recv() {
        events.push(ev);
    }
    let requests: Vec<harness_core::CompletionRequest> = std::fs::read_to_string(&record)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    Run {
        text: outcome.text,
        stop_reason: outcome.stop_reason,
        requests,
        events,
    }
}

/// 「ローカルで見つけた主張を、次のラウンドでMCPが裏取りする」2ラウンドの台本。
fn corroboration_script() -> Vec<Vec<StreamEvent>> {
    vec![
        hypothesize(),
        // ラウンド1: ワークスペースの実ファイル（§4.2の接地優先順位1）。
        plan_and_tool_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "shell.rs" }),
        ),
        distill("shell.rsがpowershell.exeを起動している", &[]),
        // まだ裏取りできていないので決着させない。
        verify("inconclusive"),
        // ラウンド2: MCPで裏取り（§4.2の接地優先順位2）。
        plan_and_tool_turn(
            "call_2",
            READ_MCP,
            serde_json::json!({ "query": "run_shell" }),
        ),
        distill("社内仕様もPowerShellを既定としている", &[]),
        verify("confirms"),
        decide(),
    ]
}

/// 記録されたリクエストのうち、指定フェーズのものが載せたツール名の一覧。
///
/// フェーズの判別は**システムプロンプトの一致**で行う（`hiv::testing::phase_of`と同じ手法）。
/// ツールの中身で見分けようとすると、`ToolSelection`の変更でテストが循環参照になる。
fn tool_names_of(run: &Run, phase: harness_core::Phase) -> Vec<Vec<String>> {
    let role = harness_cognition::prompts::system_prompt(phase);
    run.requests
        .iter()
        .filter(|r| r.system.iter().any(|s| s.text == role))
        .map(|r| {
            let mut names: Vec<String> = r.tools.iter().map(|t| t.name.clone()).collect();
            names.sort();
            names
        })
        .collect()
}

fn evidence_events(events: &[AgentEvent]) -> Vec<(String, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::EvidenceAdded { id, validity, .. } => Some((id.clone(), validity.clone())),
            _ => None,
        })
        .collect()
}

// --- テスト ------------------------------------------------------------------

/// **M16の受入条件その1**: 別種の情報源で裏取りできると`Corroborated`へ上がり、確証まで進む。
#[tokio::test]
async fn a_claim_corroborated_by_mcp_reaches_confirmation() {
    let run = run_always(corroboration_script(), &[(READ_MCP, RiskClass::ReadOnly)]).await;

    assert_eq!(run.stop_reason, StopReason::EndTurn);

    // 2件の証拠が積まれ、**両方**が裏取り成立（`Corroborated`）になる。
    let evidence = evidence_events(&run.events);
    assert_eq!(evidence.len(), 2, "{evidence:?}");
    // 1件目はMCPが来る前なので、積まれた時点では単一ソース。
    assert!(evidence[0].1.starts_with("single_source"), "{evidence:?}");
    // 2件目（MCP）が積まれた時点で裏取りが成立する。
    assert!(evidence[1].1.starts_with("corroborated"), "{evidence:?}");

    // 最終回答は台帳から組まれ、裏取り済みであることが読める。
    assert!(run.text.contains("corroborated"), "{}", run.text);
    assert!(
        run.text.contains("mcp/company-docs/search_docs"),
        "{}",
        run.text
    );
    assert!(run.text.contains("shell.rs"), "{}", run.text);
    assert!(
        run.text.contains("根拠の強さ: strong"),
        "裏取りが成立したら強さも上がる: {}",
        run.text
    );
    // 裏取りできているので、この注記は出ない。
    assert!(!run.text.contains("MCP裏取り不可"), "{}", run.text);

    let promoted = run
        .events
        .iter()
        .any(|e| matches!(e, AgentEvent::VerificationResult { promoted: true, .. }));
    assert!(promoted, "接地と裏取りが揃えば確証へ上がる");
}

/// **M16の受入条件その2（§4.2のフォールバック）**: MCPが無くても**結論は出す**。
/// ただし「裏取りできていない」ことを隠さない。
#[tokio::test]
async fn without_mcp_the_conclusion_still_lands_but_says_it_is_single_source() {
    // MCPツールを1つも登録しない＝カタログのMCPエントリは`available`に出てこない。
    let run = run_always(
        vec![
            hypothesize(),
            plan_and_tool_turn(
                "call_1",
                "read_file",
                serde_json::json!({ "path": "shell.rs" }),
            ),
            distill("shell.rsがpowershell.exeを起動している", &[]),
            verify("confirms"),
            decide(),
        ],
        &[],
    )
    .await;

    // **止まらない**（降格しても結論は出せる、§4.2）。
    assert_eq!(run.stop_reason, StopReason::EndTurn);
    assert!(
        run.text.contains("PowerShellを前提に手順を書く"),
        "{}",
        run.text
    );
    // **隠さない**（§4.2）。
    assert!(run.text.contains("single_source"), "{}", run.text);
    assert!(run.text.contains("MCP裏取り不可"), "{}", run.text);
}

/// **§4.3の矛盾検出と決着**: 相反する観測は決着するまで確証を止める。
/// 信頼度・鮮度で優劣が付かなければ`OpenQuestion`としてユーザへ返す。
#[tokio::test]
async fn contradicting_observations_block_confirmation_until_they_are_decided() {
    // 7コールぴったりで畳む（決着しない台本なので、上限で止まること自体も含めて見る）。
    let run = run_always_bounded(
        vec![
            hypothesize(),
            plan_and_tool_turn(
                "call_1",
                "read_file",
                serde_json::json!({ "path": "shell.rs" }),
            ),
            distill("shell.rsはpowershell.exeを起動している", &[]),
            verify("inconclusive"),
            // 同じファイルから相反する読み取り。出典も信頼度も鮮度も同格なので決着しない。
            plan_and_tool_turn(
                "call_2",
                "read_file",
                serde_json::json!({ "path": "shell.rs" }),
            ),
            distill("shell.rsはcmd.exeを起動している", &["E3"]),
            // モデルは確証したがるが、ハーネスが止める。
            verify("confirms"),
        ],
        &[],
        7,
    )
    .await;

    // 矛盾を抱えたまま`Confirmed`へ上がっていないこと。
    let promoted = run
        .events
        .iter()
        .any(|e| matches!(e, AgentEvent::VerificationResult { promoted: true, .. }));
    assert!(!promoted, "未決着の矛盾があるうちは確証へ上げない");

    let missing: Vec<String> = run
        .events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::VerificationResult { missing, .. } => Some(missing.join(" / ")),
            _ => None,
        })
        .collect();
    assert!(
        missing.iter().any(|m| m.contains("未決着の矛盾")),
        "{missing:?}"
    );
    // 決着不能な矛盾はユーザへの問いとして残る（§4.3）。
    assert!(run.text.contains("矛盾"), "{}", run.text);
    assert!(run.text.contains("確証できた仮説はない"), "{}", run.text);
}

/// **M16の受入条件その3**: 書込系MCPはInvestigateの候補集合に入らない（§7.3 ToolGate）。
/// Decideには入り、そこで初めてパーミッションゲートに掛かる。
#[tokio::test]
async fn a_write_mcp_tool_is_never_offered_to_the_investigation_phase() {
    let run = run_always(
        corroboration_script(),
        &[
            (READ_MCP, RiskClass::ReadOnly),
            // D-40: 無宣言のMCPツールは非read扱いになる。その`RiskClass`をそのまま使う。
            (WRITE_MCP, RiskClass::Write),
        ],
    )
    .await;

    let investigate: Vec<Vec<String>> = tool_names_of(&run, harness_core::Phase::Investigate);
    assert!(
        !investigate.is_empty(),
        "Investigateのコールが記録されていない"
    );
    for names in &investigate {
        assert!(
            names.iter().any(|n| n == READ_MCP),
            "read宣言済みのMCPはInvestigateで自動許可される（§4.2）: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == WRITE_MCP),
            "書込系MCPがInvestigateの候補に混ざった: {names:?}"
        );
        // 内蔵の書込・実行ツールも同様に外れている（同じ`ToolSelection::ReadOnly`の効果）。
        assert!(!names.iter().any(|n| n == "write_file"), "{names:?}");
        assert!(!names.iter().any(|n| n == "run_shell"), "{names:?}");
    }

    // Decideは書込系を候補に持つ（実行の可否は`PermissionArbiter`が決める）。
    let decide = tool_names_of(&run, harness_core::Phase::Decide);
    assert!(!decide.is_empty(), "Decideのコールが記録されていない");
    assert!(
        decide
            .iter()
            .all(|names| names.iter().any(|n| n == WRITE_MCP)),
        "Decideで書込系MCPが候補に入っていない: {decide:?}"
    );
}

/// 情報源カタログがInvestigateのコールへ載る（§4.2「使える情報源の一覧だけを渡す」）。
/// **登録されていないMCPは出てこない**——呼べない情報源を勧めない。
#[tokio::test]
async fn the_investigate_call_lists_only_the_sources_that_can_actually_be_called() {
    let run = run_always(corroboration_script(), &[(READ_MCP, RiskClass::ReadOnly)]).await;

    let bodies: Vec<String> = run
        .requests
        .iter()
        .filter_map(|r| match r.messages.first()?.content.first()? {
            ContentBlock::Text(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    let catalogs: Vec<&String> = bodies
        .iter()
        .filter(|b| b.contains("使える情報源"))
        .collect();
    assert!(!catalogs.is_empty(), "カタログがどのコールにも載っていない");

    for body in &catalogs {
        assert!(body.contains("mcp/company-docs"), "{body}");
        assert!(body.contains("read_file"), "{body}");
        // `mcp/jira`は宣言されているがツールが登録されていないので出ない。
        assert!(
            !body.contains("mcp/jira"),
            "呼べない情報源をカタログに出してはならない: {body}"
        );
    }
}
