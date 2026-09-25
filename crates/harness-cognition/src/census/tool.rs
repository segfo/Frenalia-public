//! 対話ループから呼べる`census`ツール。`plans/PLAN-CENSUS-ENGINE.md`段階3。
//!
//! # 置き場所
//!
//! `harness-tools`ではなく`harness-cognition`に置く。`census`の`call()`内部は
//! `TurnExecutor`（`harness-engine`）を組み立てて回す必要があるが、`harness-tools`が
//! `harness-engine`へ依存すると`harness-engine → harness-tools → harness-engine`の循環に
//! なる（`TurnExecutor`は`tools: &ToolRegistry`を要求するのでこの依存方向は固定）。
//! `harness-cognition`は既に`harness-engine`・`harness-tools`の両方に依存しているので
//! 唯一合法な置き場所。
//!
//! # 再帰的自己呼び出しの防止
//!
//! [`CensusTool`]の`risk()`は`ReadOnly`であり、`Phase::Collect`の候補ツール選択
//! （`ToolSelection::ReadOnly`）はこのリスククラスを通す。もし内側の`TurnExecutor`に
//! 渡すレジストリが`census`自身を含んでいたら、Collectフェーズ中にモデルが`census`を
//! 再帰的に呼び出せてしまう（無制限再帰の構造的な穴）。**`inner_tools`は生産コードの
//! 登録地点で、`census`を登録する直前に取ったレジストリのクローンでなければならない**
//! （`ToolRegistry::register`で`census`を足すのはそのクローンを取った後）。
//!
//! # PermissionGateの迂回不能性
//!
//! `call()`内で新しく組む`TurnExecutor`は、外側から渡された`gate`（本物の`PermissionGate`
//! 実装）と、呼び出し時点の`ctx`（サンドボックス設定そのもの）をそのまま使う。ツール呼び出しの
//! 唯一の実行点は`TurnExecutor::dispatch_one`であり、ここは一切変更していない——
//! `crates/harness-engine/tests/golden_transcript.rs`の
//! `executor_trait_cannot_bypass_the_permission_gate`は無改造のまま緑であり続ける。
//!
//! # 既知の制約（本スコープでは解決しない）
//!
//! - `Tool::call`は`events`/`cancel`/縮退ガードを受け取らないため、`census`内部の
//!   フェーズコールは外側ターンのキャンセル・イベント表示・M21縮退ガードと接続されない。
//!   `Tool` trait自体の変更を要するため本タスクの範囲外。
//! - 内側の`TurnExecutor`は常に`Arc<PermissionArbiter>`（headless相当のポリシー判定）を
//!   使う。TUIの`InteractiveGate`（モーダル確認）は経由しない。**そのうえで ReadOnly 以外を
//!   拒否する包み（[`ReadOnlyOnly`]）を必ず掛ける**。`Phase::Collect`が候補として見せるツールは
//!   `ToolSelection::ReadOnly`に絞ってあるが、それはモデルへの**申告**で、実行はレジストリ全体から
//!   引く（`dispatch_one`）——宣伝されていない`run_program`を名指しすれば届く。判定器の複製に
//!   承認の記録の規則が載ると、画面に何も出ずに走りうる（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.2）。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use harness_core::{
    parse_tool_input, LlmProvider, PermissionSubject, RiskClass, Tool, ToolCtx, ToolError,
    ToolOutput,
};
use harness_engine::{Decision, PermissionGate, TurnExecutor};
use harness_tools::ToolRegistry;
use serde::Deserialize;

use crate::census::{CensusContext, CensusEngine, CensusLimits, CensusStop};
use crate::context::ContextAssembler;
use crate::phase::PhaseBudgets;
use crate::scratch::ScratchStore;

/// census の内側のゲート。**ReadOnly 以外は、内側のゲートに聞く前に拒否する**（モジュールdoc
/// 「既知の制約」）。見せていないものは通さない。
struct ReadOnlyOnly<'g>(&'g dyn PermissionGate);

#[async_trait]
impl PermissionGate for ReadOnlyOnly<'_> {
    async fn resolve(
        &self,
        tool: &str,
        risk: RiskClass,
        subject: &PermissionSubject,
        input: &serde_json::Value,
    ) -> Decision {
        if risk != RiskClass::ReadOnly {
            return Decision::Deny;
        }
        self.0.resolve(tool, risk, subject, input).await
    }
}

/// `census`の入力。**知らない項目は拒否する**（BUG-164・D-101）。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CensusInput {
    goal: String,
}

pub struct CensusTool {
    provider: Arc<dyn LlmProvider>,
    gate: Arc<dyn PermissionGate>,
    /// `census`自身を含まないスナップショット（モジュールdoc「再帰的自己呼び出しの防止」）。
    inner_tools: Arc<ToolRegistry>,
    budgets: PhaseBudgets,
    model: String,
    context_window: u32,
}

impl CensusTool {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        gate: Arc<dyn PermissionGate>,
        inner_tools: Arc<ToolRegistry>,
        budgets: PhaseBudgets,
        model: String,
        context_window: u32,
    ) -> Self {
        Self {
            provider,
            gate,
            inner_tools,
            budgets,
            model,
            context_window,
        }
    }
}

#[async_trait]
impl Tool for CensusTool {
    fn name(&self) -> &str {
        "census"
    }

    fn description(&self) -> &str {
        "多数の対象（ファイル・記録等）を1件ずつ読んで傾向・共通点をまとめる網羅調査を行う。\
         「バグカタログを全部見て傾向を分析して」のような、対象を全件処理して終わる依頼に使う。\
         通常の会話の中では文脈が伸び続けてしまう規模の調査を、ここへ切り出して1件ずつ処理する。"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "goal": {
                    "type": "string",
                    "description": "調査してほしい依頼（対象の範囲と、何を見たいか）"
                }
            },
            "required": ["goal"],
            "additionalProperties": false,
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::ReadOnly
    }

    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        let input: CensusInput = parse_tool_input(input)?;
        Ok(PermissionSubject::Text(input.goal))
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: CensusInput = parse_tool_input(&input)?;
        let goal = input.goal.as_str();

        let session_id = format!(
            "census-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let dir = ScratchStore::dir_for_session(&ctx.workspace_root, &session_id);
        let scratch = ScratchStore::open(&dir).map_err(|e| {
            ToolError::ExecutionFailed(format!("failed to open scratch store: {e}"))
        })?;

        let assembler = ContextAssembler::new(self.model.clone(), self.budgets.clone());
        let mut engine = CensusEngine::new(assembler, scratch, CensusLimits::default());

        // **PermissionGateを通す唯一の場所**（`TurnExecutor::dispatch_one`）を経由する
        // 実行器を、ここで新しく組む。`gate`/`ctx`は外側から渡された本物の値をそのまま使う。
        let inner_gate = ReadOnlyOnly(self.gate.as_ref());
        let executor = TurnExecutor::new(
            self.provider.as_ref(),
            &self.inner_tools,
            ctx,
            &inner_gate,
            None,
            None,
            None,
        );
        let cx = CensusContext {
            exec: &executor,
            ctx,
            tools: &self.inner_tools,
            caps: self.provider.capabilities(),
            events: None,
            cancel: None,
            context_window: self.context_window,
        };
        let outcome = engine.run_goal(goal, &cx).await;

        Ok(ToolOutput {
            is_error: matches!(outcome.stop, CensusStop::Blocked { .. }),
            content: outcome.answer,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use harness_core::{BlockKind, CompletionRequest, StopReason, StreamEvent, Usage};
    use harness_engine::{Decision, PermissionArbiter, PermissionMode};
    use harness_providers::MockProvider;

    use super::*;

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

    fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
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

    fn plan_json(items: &[(&str, &str)]) -> String {
        let items: Vec<serde_json::Value> = items
            .iter()
            .map(|(id, query)| serde_json::json!({ "id": id, "query": query }))
            .collect();
        serde_json::json!({ "items": items }).to_string()
    }

    fn distill_json(claim: &str) -> String {
        serde_json::json!({
            "evidence": [{ "claim": claim, "relation": "neutral", "source": "s", "contradicts": [] }]
        })
        .to_string()
    }

    fn join_json(summary: &str) -> String {
        serde_json::json!({ "summary": summary, "key_findings": [] }).to_string()
    }

    /// `resolve()`が呼ばれたことを記録し、常に拒否する`PermissionGate`。
    /// `census`内側のツール呼び出しが本当にゲートを経由しているかを直接確認するために使う
    /// （`PermissionArbiter`のReadOnly自動許可を挟まず、ゲートが引かれたこと自体を見る）。
    struct RecordingGate {
        resolved: Mutex<Vec<(String, RiskClass)>>,
    }

    impl RecordingGate {
        fn new() -> Self {
            Self {
                resolved: Mutex::new(Vec::new()),
            }
        }

        fn resolved_calls(&self) -> Vec<(String, RiskClass)> {
            self.resolved.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PermissionGate for RecordingGate {
        async fn resolve(
            &self,
            tool: &str,
            risk: RiskClass,
            _subject: &PermissionSubject,
            _input: &serde_json::Value,
        ) -> Decision {
            self.resolved.lock().unwrap().push((tool.to_string(), risk));
            Decision::Deny
        }
    }

    /// 何でも許可するゲート。内側の包みが、内側のゲートの判断に関わらず ReadOnly 以外を止めることを
    /// 確かめるために使う（包みが無ければ、このゲートは run_program を通してしまう）。
    struct AllowAllGate {
        resolved: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl PermissionGate for AllowAllGate {
        async fn resolve(
            &self,
            tool: &str,
            _risk: RiskClass,
            _subject: &PermissionSubject,
            _input: &serde_json::Value,
        ) -> Decision {
            self.resolved.lock().unwrap().push(tool.to_string());
            Decision::Allow
        }
    }

    /// 6. `census`内側のツール呼び出しも必ず`PermissionGate`を通ること。
    ///
    /// `TurnExecutor::dispatch_one`（`crates/harness-engine/tests/golden_transcript.rs`の
    /// `executor_trait_cannot_bypass_the_permission_gate`が固定する構造）は無改造のまま
    /// `CensusTool`から新しく組んでいるので、ここでは「実際に`resolve()`が呼ばれ、
    /// 拒否されたツールは実行されない」ことを固定する。
    #[tokio::test]
    async fn the_inner_tool_calls_still_go_through_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        // 拒否される前提なので、このファイルが実在しなくてもテストは成立する
        // （`tool.call()`まで到達しないことそのものが主張）。
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let tools = Arc::new(ToolRegistry::with_builtin_tools());

        let provider = Arc::new(MockProvider::new(vec![
            end_turn(&plan_json(&[("a", "read a")])),
            tool_use_turn(
                "call_1",
                "read_file",
                serde_json::json!({ "path": "a.txt" }),
            ),
            end_turn(&join_json("summary")),
        ]));
        let gate = Arc::new(RecordingGate::new());
        let census = CensusTool::new(
            provider,
            gate.clone(),
            tools,
            PhaseBudgets::default(),
            "mock".to_string(),
            200_000,
        );

        let output = census
            .call(serde_json::json!({ "goal": "aを調べて" }), &ctx)
            .await
            .unwrap();

        let calls = gate.resolved_calls();
        assert!(
            calls
                .iter()
                .any(|(tool, risk)| tool == "read_file" && *risk == RiskClass::ReadOnly),
            "read_fileの許可判定がgateを経由していない: {calls:?}"
        );
        // 拒否されたので観測ゼロ→そのitemは失敗として記録され、ツール出力は最終回答に現れない。
        assert!(!output.content.contains("a.txt"), "{}", output.content);
    }

    /// 内側の包みは ReadOnly 以外を、**内側のゲートに聞く前に**止める。内側のゲートが
    /// 何でも許可するものでも、宣伝されていない`run_program`は走らない（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.2）。
    /// 対照として、同じ実行の中の`read_file`（ReadOnly）は内側のゲートまで届く。
    #[tokio::test]
    async fn the_inner_gate_refuses_anything_but_read_only_before_asking() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let provider = Arc::new(MockProvider::new(vec![
            end_turn(&plan_json(&[("a", "read a")])),
            tool_use_turn(
                "call_1",
                "run_program",
                serde_json::json!({ "program": "git", "args": ["status"] }),
            ),
            tool_use_turn(
                "call_2",
                "read_file",
                serde_json::json!({ "path": "a.txt" }),
            ),
            end_turn(&join_json("summary")),
        ]));
        let gate = Arc::new(AllowAllGate {
            resolved: Mutex::new(Vec::new()),
        });
        let census = CensusTool::new(
            provider,
            gate.clone(),
            Arc::new(ToolRegistry::with_builtin_tools()),
            PhaseBudgets::default(),
            "mock".to_string(),
            200_000,
        );

        let _ = census
            .call(serde_json::json!({ "goal": "aを調べて" }), &ctx)
            .await
            .unwrap();

        let resolved = gate.resolved.lock().unwrap().clone();
        assert!(
            !resolved.iter().any(|t| t == "run_program"),
            "run_program must be refused before the inner gate is asked: {resolved:?}"
        );
        assert!(
            resolved.iter().any(|t| t == "read_file"),
            "read_file (ReadOnly) must still reach the inner gate: {resolved:?}"
        );
    }

    /// 知らない項目は拒否する（BUG-164・D-101）。LLM を1回も呼ばずに止まる
    /// （応答を1つも積んでいない MockProvider が呼ばれれば、結果は `InvalidInput` にならない）。
    /// 素直な入力（`goal` だけ）が通ることは上のテストが測っている。
    #[tokio::test]
    async fn an_unknown_field_is_refused_before_any_llm_call() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let census = CensusTool::new(
            Arc::new(MockProvider::new(vec![])),
            Arc::new(RecordingGate::new()),
            Arc::new(ToolRegistry::with_builtin_tools()),
            PhaseBudgets::default(),
            "mock".to_string(),
            200_000,
        );

        let err = census
            .call(
                serde_json::json!({ "goal": "aを調べて", "command": "x" }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ToolError::InvalidInput(m) if m.contains("unknown field")),
            "{err:?}"
        );
    }

    /// 7. `census`ツールの`tool_result`は`notes/`の要約を結合したものだけで、
    /// `Join`フェーズへ渡るリクエストに生出力が混ざらないこと（`census::mod`の
    /// `join_reads_only_notes_never_raw`のCensusTool越し版）。
    #[tokio::test]
    async fn the_tool_result_carries_only_the_joined_notes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "RAW_SECRET_CONTENT_XYZ").unwrap();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let tools = Arc::new(ToolRegistry::with_builtin_tools());

        let record_path = dir.path().join("requests.jsonl");
        let provider = Arc::new(
            MockProvider::new(vec![
                end_turn(&plan_json(&[("a", "read a")])),
                tool_use_turn(
                    "call_1",
                    "read_file",
                    serde_json::json!({ "path": "a.txt" }),
                ),
                end_turn(&distill_json("蒸留済みの短い要約")),
                end_turn(&join_json("summary")),
            ])
            .with_request_record_path(record_path.clone()),
        );
        // read_fileはReadOnlyなのでDefaultモード（allowlist未登録）でも自動許可される
        // （`golden_transcript.rs`と同じ前提）。
        let gate: Arc<dyn PermissionGate> = Arc::new(PermissionArbiter::new(
            PermissionMode::Default,
            vec![],
            "/workspace",
        ));
        let census = CensusTool::new(
            provider,
            gate,
            tools,
            PhaseBudgets::default(),
            "mock".to_string(),
            200_000,
        );

        let output = census
            .call(serde_json::json!({ "goal": "aを調べて" }), &ctx)
            .await
            .unwrap();
        assert!(!output.is_error, "{}", output.content);

        let recorded = std::fs::read_to_string(&record_path).unwrap();
        let join_request = recorded
            .lines()
            .filter_map(|line| serde_json::from_str::<CompletionRequest>(line).ok())
            .find(|req| crate::hiv::testing::phase_of(req) == Some(harness_core::Phase::Join))
            .expect("a Join request was recorded");

        let harness_core::ContentBlock::Text(body) = &join_request.messages[0].content[0] else {
            panic!("Join request body must be a text block")
        };
        assert!(body.contains("蒸留済みの短い要約"), "{body}");
        assert!(
            !body.contains("RAW_SECRET_CONTENT_XYZ"),
            "raw output leaked into the Join request: {body}"
        );
    }
}
