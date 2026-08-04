//! 1フェーズ分の実行。組立 → `Executor::raw_turn` → 抽出 → 意味検証 → 修復再実行。
//! `plans/DESIGN-COGNITION.md` §3.3（各フェーズのLLM呼び出し仕様）・§3.4（typed schemaによる強制）。
//!
//! # 再実行が「同じフェーズをもう一度」で済む理由
//!
//! 各フェーズは会話履歴を持たない独立した1コール（§3.3）なので、やり直しは
//! 台帳スライスから組み直すだけでよい。失敗理由を`PhaseInput.repair`として本文末尾へ
//! 足し、同じ誤りを繰り返させない。
//!
//! # 再実行では**ツールを渡さない**
//!
//! 1回目でツールは既に実行済みで、同じリクエストをもう一度投げると副作用が二重に走る
//! （Decideの`edit_file`が2回適用される）。やり直しは常に
//! [`ContextAssembler::build_conclusion`]（ツール無し・スキーマのみ）で行い、1回目の観測は
//! `raw_output`として文章で運ぶ。これは【T7】のコール分割（`ToolsOnly`の結論コール）と
//! 同じ経路なので、実装も1本で済む。

use harness_core::{AgentEvent, Phase, ProviderCapabilities, ToolCtx, Usage};
use harness_engine::{
    emit_event, CompletedToolCall, EventSink, Executor, RawTurn, RawTurnRequest, RawTurnResult,
};
use harness_tools::ToolRegistry;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;

use crate::context::{AssembledCall, CallKind, ContextAssembler, PhaseInput};
use crate::hiv::parse::parse_phase_output;
use crate::memory::WorkingMemory;

/// フェーズの構造化出力をどこまで必須にするか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Conclusion {
    /// 取れなければ結論コールでやり直す（Verify/Decide/解釈フェーズ）。
    Required,
    /// 取れなくても先へ進む（Investigate。本来の産物はツール呼び出しの方で、
    /// `plan`は`VerifyMethod`を決めるための補助でしかない）。
    Optional,
}

/// 1フェーズの実行結果。
#[derive(Debug)]
pub(crate) struct PhaseValue<T> {
    pub value: Option<T>,
    pub tool_calls: Vec<CompletedToolCall>,
    pub usage: Usage,
    /// このフェーズで実際に投げたプロバイダ呼び出しの数（結論コール・修復再実行も数える）。
    /// 呼び出し側の総コール上限が、再実行の分だけ甘くならないようにするため。
    pub calls: usize,
}

/// フェーズが進めなくなった理由。
#[derive(Debug)]
pub(crate) enum PhaseError {
    /// スキーマ検証に規定回数失敗した。**fail-closed**でゴールを打ち切る
    /// （上位tierへのエスカレーションはM17のモデル階層化が入ってから）。
    SchemaRejected {
        phase: Phase,
        attempts: u32,
        reason: String,
    },
    /// キャンセルされた。台帳へは何も足さずに畳む。
    Cancelled,
    /// 回復の梯子を使い切ってなお縮退した（`plans/DESIGN-COGNITION.md` §11.4）。
    /// **fail-closed**でゴールを打ち切る（上位tierへのエスカレーションはM17待ち）。
    ///
    /// スキーマ検証の失敗（[`PhaseError::SchemaRejected`]）と分けているのは、原因が
    /// 「モデルが要求を理解できなかった」ではなく「モデルの出力そのものが壊れた」だからで、
    /// 修復指示を添えて再実行しても意味が無い（既に`TurnExecutor`が§11.3の梯子を登り切っている）。
    Degenerate {
        phase: Phase,
        kind: harness_core::DegenerateKind,
    },
    Provider(harness_core::ProviderError),
}

/// フェーズ実行に要る周辺（`HivEngine`が毎回渡すもの）。
pub(crate) struct PhaseRunner<'a> {
    pub exec: &'a dyn Executor,
    pub ctx: &'a ToolCtx,
    pub tools: &'a ToolRegistry,
    pub caps: ProviderCapabilities,
    pub events: Option<&'a EventSink>,
    pub cancel: Option<&'a CancellationToken>,
    pub assembler: &'a ContextAssembler,
    pub max_schema_retries: u32,
}

impl PhaseRunner<'_> {
    /// 1フェーズを最後まで進める。フェーズ内で発行するのは`PhaseChanged`1回と、
    /// コールごとの`TurnStarted`（ツールイベントは`raw_turn`側が出す）。
    pub(crate) async fn run<T: DeserializeOwned>(
        &self,
        phase: Phase,
        input: PhaseInput<'_>,
        mem: &WorkingMemory,
        conclusion: Conclusion,
        validate: fn(&T) -> Result<(), String>,
    ) -> Result<PhaseValue<T>, PhaseError> {
        emit_event(self.events, AgentEvent::PhaseChanged { phase });

        let mut usage = Usage::default();
        let mut calls = 0;

        // --- 1回目: フェーズ仕様通り（ツールが載ることがある） ---
        let call = self
            .assembler
            .build(phase, input, mem, self.ctx, self.tools, &self.caps);
        let schema_requested = call.kind != CallKind::ToolsOnly;
        let raw = self.turn(phase, call, &mut usage, &mut calls).await?;
        let tool_calls = raw.tool_calls.clone();

        let mut reason = if schema_requested {
            match parse_and_validate(&raw.text, validate) {
                Ok(value) => {
                    return Ok(PhaseValue {
                        value: Some(value),
                        tool_calls,
                        usage,
                        calls,
                    })
                }
                Err(reason) => Some(reason),
            }
        } else {
            // 【T7】: このコールにはスキーマを載せていない。失敗ではないので
            // 再実行回数には数えず、結論コールで構造化出力を取りに行く。
            None
        };

        if conclusion == Conclusion::Optional {
            return Ok(PhaseValue {
                value: None,
                tool_calls,
                usage,
                calls,
            });
        }

        // --- 結論コール / 修復再実行（いずれもツール無し） ---
        let observed = observed_text(&tool_calls);
        let mut failures = u32::from(reason.is_some());
        let mut attempts = 1;
        while failures <= self.max_schema_retries {
            let call = self.assembler.build_conclusion(
                phase,
                PhaseInput {
                    target: input.target,
                    goal: input.goal,
                    raw_output: observed.as_deref().or(input.raw_output),
                    repair: reason.as_deref(),
                },
                mem,
                self.ctx,
                &self.caps,
            );
            let raw = self.turn(phase, call, &mut usage, &mut calls).await?;
            attempts += 1;
            match parse_and_validate(&raw.text, validate) {
                Ok(value) => {
                    return Ok(PhaseValue {
                        value: Some(value),
                        tool_calls,
                        usage,
                        calls,
                    })
                }
                Err(next) => {
                    failures += 1;
                    reason = Some(next);
                }
            }
        }

        Err(PhaseError::SchemaRejected {
            phase,
            attempts,
            reason: reason.unwrap_or_else(|| "構造化出力を取得できなかった".to_string()),
        })
    }

    /// 1コール分。`TurnVisibility::Internal`で投げるので、フェーズ出力のJSONは
    /// TUIのトランスクリプトにもヘッドレスのtext出力にも流れない。
    async fn turn(
        &self,
        phase: Phase,
        call: AssembledCall,
        usage: &mut Usage,
        calls: &mut usize,
    ) -> Result<RawTurn, PhaseError> {
        if self.cancel.is_some_and(|c| c.is_cancelled()) {
            return Err(PhaseError::Cancelled);
        }
        emit_event(
            self.events,
            AgentEvent::TurnStarted {
                estimated_input_tokens: call.estimated_input_tokens,
            },
        );
        let result = self
            .exec
            .raw_turn(RawTurnRequest::internal(call.req))
            .await
            .map_err(|e| PhaseError::Provider(e.into_provider_error()))?;
        match result {
            // ストリーム途中のキャンセル: 部分assistantは破棄済みで、台帳へも何も足さない。
            RawTurnResult::CancelledMidStream => Err(PhaseError::Cancelled),
            // 縮退で捨てたコールは**数えない**（§11.3「進捗予算と回復予算を混ぜない」）。
            // 数えると「モデルが壊れていた」だけの理由で`max_phase_calls`が減り、
            // ログ上は「予算切れ」としか見えず原因と結果が分離できなくなる。
            RawTurnResult::Discarded { kind } => Err(PhaseError::Degenerate { phase, kind }),
            RawTurnResult::Completed(raw) => {
                // 実際に成立したコールだけを数える（上の2経路は`*calls`を増やさない）。
                *calls += 1;
                add_usage(usage, &raw.usage);
                if raw.cancelled_mid_tool {
                    // ツールの一部だけが走った状態。未蒸留の生出力は証拠にしない（§3.2【T6】）。
                    return Err(PhaseError::Cancelled);
                }
                Ok(raw)
            }
        }
    }
}

fn parse_and_validate<T: DeserializeOwned>(
    text: &str,
    validate: fn(&T) -> Result<(), String>,
) -> Result<T, String> {
    let value = parse_phase_output::<T>(text)?;
    validate(&value)?;
    Ok(value)
}

/// 結論コールへ渡す「このフェーズで実際に何をしたか」。組立側が予算まで切詰めるので、
/// ここでは呼び出しごとの見出しを付けて並べるだけにする。
fn observed_text(calls: &[CompletedToolCall]) -> Option<String> {
    if calls.is_empty() {
        return None;
    }
    let mut out = String::new();
    for call in calls {
        out.push_str(&format!(
            "$ {} {}\n{}\n\n",
            call.name, call.input, call.output.content
        ));
    }
    Some(out)
}

fn add_usage(total: &mut Usage, delta: &Usage) {
    total.input = total.input.saturating_add(delta.input);
    total.output = total.output.saturating_add(delta.output);
    total.cache_read = total.cache_read.saturating_add(delta.cache_read);
    total.cache_creation = total.cache_creation.saturating_add(delta.cache_creation);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiv::parse::{validate_decide, validate_hypothesize, validate_investigate};
    use crate::hiv::testing::{PhaseExecutor, Reply};
    use crate::phase::PhaseBudgets;
    use crate::schema::{DecideOutput, HypothesizeOutput, InvestigateOutput};

    fn caps(schema_with_tools: bool) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: true,
            forced_tool_choice: true,
            schema_with_thinking: true,
            schema_with_tools,
            prompt_caching: false,
            context_window: 128_000,
            local: false,
        }
    }

    struct Harness {
        ctx: ToolCtx,
        tools: ToolRegistry,
        assembler: ContextAssembler,
        mem: WorkingMemory,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                ctx: ToolCtx::new(std::path::PathBuf::from("C:/ws")),
                tools: ToolRegistry::with_builtin_tools(),
                assembler: ContextAssembler::new("test-model", PhaseBudgets::default()),
                mem: WorkingMemory::new(),
            }
        }

        fn runner<'a>(&'a self, exec: &'a PhaseExecutor, with_tools: bool) -> PhaseRunner<'a> {
            PhaseRunner {
                exec,
                ctx: &self.ctx,
                tools: &self.tools,
                caps: caps(with_tools),
                events: None,
                cancel: None,
                assembler: &self.assembler,
                max_schema_retries: 2,
            }
        }
    }

    fn good_hypothesis() -> Reply {
        Reply::Text(
            serde_json::json!({
                "hypotheses": [{ "statement": "原因はX", "predicts": ["Yが見えれば偽"], "confidence": 0.6 }]
            })
            .to_string(),
        )
    }

    /// 反証条件の無い仮説（スキーマ上は適合するが、意味の制約に反する）。
    fn hypothesis_without_predicts() -> Reply {
        Reply::Text(
            serde_json::json!({
                "hypotheses": [{ "statement": "原因はX", "predicts": [], "confidence": 0.9 }]
            })
            .to_string(),
        )
    }

    /// 1回目が不正でも、理由を添えた再実行で通れば通常どおり値を返す
    /// （再実行が「停止するためだけの機構」でないことの固定）。
    #[tokio::test]
    async fn an_invalid_output_is_retried_with_a_repair_instruction_and_can_succeed() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Hypothesize,
            vec![hypothesis_without_predicts(), good_hypothesis()],
        )]);

        let out: PhaseValue<HypothesizeOutput> = h
            .runner(&exec, true)
            .run(
                Phase::Hypothesize,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_hypothesize,
            )
            .await
            .unwrap();

        assert_eq!(
            out.value.unwrap().hypotheses[0].predicts,
            vec!["Yが見えれば偽"]
        );
        assert_eq!(out.calls, 2);
        // 2回目には「何が不正だったか」が載る。
        let second = &exec.seen()[1].req;
        let harness_core::ContentBlock::Text(body) = &second.messages[0].content[0] else {
            panic!()
        };
        assert!(body.contains("predicts"), "{body}");
        assert!(body.contains("前回の出力の不備"), "{body}");
    }

    /// **M15の受入条件**: 規定回数（1回目 + 再実行2回）ともスキーマ検証に落ちたら
    /// fail-closedで止まる。素朴ループへ黙って降格しない。
    #[tokio::test]
    async fn schema_rejection_is_fail_closed_after_the_retry_budget() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Hypothesize,
            vec![hypothesis_without_predicts()], // 最後の応答は繰り返される
        )]);

        let err = h
            .runner(&exec, true)
            .run::<HypothesizeOutput>(
                Phase::Hypothesize,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_hypothesize,
            )
            .await
            .unwrap_err();

        let PhaseError::SchemaRejected {
            phase,
            attempts,
            reason,
        } = err
        else {
            panic!("expected a schema rejection, got {err:?}");
        };
        assert_eq!(phase, Phase::Hypothesize);
        assert_eq!(attempts, 3, "1回目 + 再実行2回で打ち切る");
        assert!(reason.contains("predicts"), "{reason}");
        assert_eq!(exec.calls_to(Phase::Hypothesize), 3);
    }

    /// **再実行でツールを再送しない**（Decideの`edit_file`が二重に適用されるのを防ぐ）。
    #[tokio::test]
    async fn retries_never_resend_the_tools() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Decide,
            vec![
                Reply::tool(
                    "write_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "written",
                ),
                Reply::Text(
                    serde_json::json!({ "action": "書いた", "then_verify": "cargo test" })
                        .to_string(),
                ),
            ],
        )]);

        let out: PhaseValue<DecideOutput> = h
            .runner(&exec, true)
            .run(
                Phase::Decide,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_decide,
            )
            .await
            .unwrap();

        assert_eq!(out.tool_calls.len(), 1, "ツール実行は1回目のコールだけ");
        let seen = exec.seen();
        assert!(!seen[0].req.tools.is_empty(), "1回目はツールを渡す");
        assert!(
            seen[1].req.tools.is_empty(),
            "やり直しのコールにツールを載せてはならない"
        );
        // 1回目の観測は文章で結論コールへ運ばれる。
        let harness_core::ContentBlock::Text(body) = &seen[1].req.messages[0].content[0] else {
            panic!()
        };
        assert!(body.contains("written"), "{body}");
    }

    /// 【T7】: スキーマとツールを融合できないプロバイダでは、ツール実行コールの後に
    /// 結論コール（スキーマのみ）を追加で投げる。
    #[tokio::test]
    async fn a_provider_that_cannot_fuse_takes_a_separate_conclusion_call() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Decide,
            vec![
                Reply::tool(
                    "write_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "written",
                ),
                Reply::Text(
                    serde_json::json!({ "action": "書いた", "then_verify": "cargo test" })
                        .to_string(),
                ),
            ],
        )]);

        let out: PhaseValue<DecideOutput> = h
            .runner(&exec, false)
            .run(
                Phase::Decide,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_decide,
            )
            .await
            .unwrap();

        assert_eq!(out.value.unwrap().action, "書いた");
        assert_eq!(out.calls, 2);
        let seen = exec.seen();
        assert!(seen[0].req.output.is_none(), "1回目はツール実行専用");
        assert!(
            seen[1].req.output.is_some(),
            "結論コールでスキーマを要求する"
        );
    }

    /// **M21の受入条件（認知層側）**: 縮退ガードが梯子を使い切ったら`Degenerate`で
    /// fail-closedになり、**捨てたコールは`PhaseValue.calls`に数えない**
    /// （§11.3「進捗予算と回復予算を混ぜない」）。数えてしまうと、モデルが壊れていただけの
    /// 理由で`max_phase_calls`が減り、ログ上は「予算切れ」としか見えなくなる。
    #[tokio::test]
    async fn a_discarded_call_fails_closed_and_is_not_charged_to_the_phase_budget() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(Phase::Hypothesize, vec![Reply::Discarded])]);

        let err = h
            .runner(&exec, true)
            .run::<HypothesizeOutput>(
                Phase::Hypothesize,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_hypothesize,
            )
            .await
            .unwrap_err();

        let PhaseError::Degenerate { phase, kind } = err else {
            panic!("expected a degeneracy stop, got {err:?}");
        };
        assert_eq!(phase, Phase::Hypothesize);
        assert_eq!(kind, harness_core::DegenerateKind::ShortPeriodRepeat);
        // スキーマ再実行の輪に入らず、1回で止まる（梯子は`TurnExecutor`が既に登り切っている）。
        assert_eq!(exec.calls_to(Phase::Hypothesize), 1);
    }

    /// 縮退の**手前まで**は通常どおり数える。上のテストと対にして「数えないのは
    /// 捨てたコールだけ」であることを固定する。
    #[tokio::test]
    async fn only_the_discarded_call_is_excluded_from_the_count() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Hypothesize,
            vec![hypothesis_without_predicts(), good_hypothesis()],
        )]);

        let out: PhaseValue<HypothesizeOutput> = h
            .runner(&exec, true)
            .run(
                Phase::Hypothesize,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Required,
                validate_hypothesize,
            )
            .await
            .unwrap();
        assert_eq!(out.calls, 2, "成立したコールは1回目も再実行も数える");
    }

    /// Investigateの計画は補助なので、取れなくても追加コールを投げずに先へ進む。
    #[tokio::test]
    async fn an_optional_conclusion_does_not_spend_an_extra_call() {
        let h = Harness::new();
        let exec = PhaseExecutor::new([(
            Phase::Investigate,
            vec![Reply::tool(
                "read_file",
                serde_json::json!({ "path": "a.rs" }),
                "content",
            )],
        )]);

        let out: PhaseValue<InvestigateOutput> = h
            .runner(&exec, true)
            .run(
                Phase::Investigate,
                PhaseInput::default(),
                &h.mem,
                Conclusion::Optional,
                validate_investigate,
            )
            .await
            .unwrap();

        assert!(out.value.is_none());
        assert_eq!(out.calls, 1);
        assert_eq!(out.tool_calls.len(), 1);
    }
}
