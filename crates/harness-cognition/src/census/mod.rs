//! `CensusEngine`の状態機械（網羅で終わる）。`plans/PLAN-CENSUS-ENGINE.md`段階2。
//!
//! ```text
//! Plan ──▶ Collect(item) ──▶ Distill(観測) ──▶ (worklistが空?) ──no──▶ 次のitem
//!                                                  │yes
//!                                                  ▼
//!                                                Join ──▶ 結論
//! ```
//!
//! **終了条件は「worklistが空」＝網羅。仮説の判定は使わない**（`hiv::HivEngine`との違い）。
//! `WorkingMemory`を一切持たない——網羅で終わる仕事に妥当性評価・矛盾検出は要らない。
//!
//! 再開性は`ScratchStore`の`notes/`だけで完結する（`WorkingMemory`の永続化＝M20を待たない）。
//! `notes/<item-id>.md`が既にあればその項目は`Collect`/`Distill`を一切打たずに飛ばす。

pub(crate) mod ledger;
pub(crate) mod plan;
pub mod tool;

use harness_core::{Phase, ProviderCapabilities, ToolCtx, Usage};
use harness_engine::{EventSink, Executor};
use harness_tools::ToolRegistry;
use tokio_util::sync::CancellationToken;

use crate::call::{Conclusion, PhaseError, PhaseRunner, PhaseValue};
use crate::census::ledger::CensusLedger;
use crate::census::plan::WorklistItem;
use crate::context::{ContextAssembler, PhaseInput};
use crate::hiv::evidence::{observations, Observation};
use crate::schema::{CollectOutput, DistillOutput, JoinOutput, PlanOutput};
use crate::scratch::ScratchStore;

/// ループの上限。HIVの`HivLimits`と同じ役割だが、Censusは仮説やラウンドの概念を
/// 持たないので`max_hypotheses`/`max_investigate_rounds`に相当するものが無い。
#[derive(Debug, Clone, Copy)]
pub struct CensusLimits {
    /// フェーズコールの総数。`--max-turns`を認知層へ拡張したもの（HIVの`max_phase_calls`と同じ）。
    pub max_phase_calls: usize,
    /// スキーマ検証に落ちたときの再実行回数。
    pub max_schema_retries: u32,
}

impl Default for CensusLimits {
    fn default() -> Self {
        Self {
            max_phase_calls: 100,
            max_schema_retries: 2,
        }
    }
}

/// ループが止まった理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CensusStop {
    /// worklistを網羅し、Joinまで到達した。
    Joined,
    /// 構造化出力が規定回数取れない等でこれ以上進めない（fail-closed）。
    Blocked {
        reason: String,
    },
    /// コール数の上限に当たった。
    BudgetExhausted,
    Cancelled,
}

/// 1ゴール分の実行結果。
#[derive(Debug)]
pub struct CensusOutcome {
    pub answer: String,
    pub usage: Usage,
    pub stop: CensusStop,
    pub provider_error: Option<harness_core::ProviderError>,
}

/// 1回の`run_goal`が要る周辺。`HivContext`と同型（`Executor`しか受け取らない、§1の不変条件）。
pub struct CensusContext<'a> {
    pub exec: &'a dyn Executor,
    pub ctx: &'a ToolCtx,
    pub tools: &'a ToolRegistry,
    pub caps: ProviderCapabilities,
    pub events: Option<&'a EventSink>,
    pub cancel: Option<&'a CancellationToken>,
    pub context_window: u32,
}

/// 内部の遷移状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Plan,
    Collect(usize),
    Distill(usize),
    Join,
}

/// `CensusEngine`の実体。台帳（`CensusLedger`）を所有し、フェーズ遷移の唯一の権限を持つ。
pub struct CensusEngine {
    ledger: CensusLedger,
    assembler: ContextAssembler,
    /// **必須**（`Option`ではない）。`HivEngine`は開けなくても素の調査を続けるが、
    /// Censusの再開性は`notes/`だけで成り立っているので、開けなければ機構そのものが
    /// 成立しない——開けなければ起動時点で`CensusStop::Blocked`にする非対称な設計。
    scratch: ScratchStore,
    limits: CensusLimits,
    calls_made: usize,
    usage: Usage,
    /// 直前の`step_collect`が得た観測。`State::Distill`は必ず`State::Collect`の直後にだけ
    /// 遷移するので、次の`step_distill`が消費するまでの1ステップ分だけ生存する。
    current_observation: Option<Observation>,
    /// `step_join`が組んだ最終回答。`run_goal`の末尾でこれを取り出す。
    final_answer: Option<String>,
}

impl CensusEngine {
    pub fn new(assembler: ContextAssembler, scratch: ScratchStore, limits: CensusLimits) -> Self {
        Self {
            ledger: CensusLedger::new(),
            assembler,
            scratch,
            limits,
            calls_made: 0,
            usage: Usage::default(),
            current_observation: None,
            final_answer: None,
        }
    }

    /// 1ゴールを最後まで進める。`HivEngine::run_goal`と同じく**失敗してもErrを返さない**
    /// ——ここまでに集まったnotesの件数を添えて、何が分かって何が分からなかったかを
    /// [`CensusOutcome::stop`]で区別する。
    pub async fn run_goal(&mut self, goal_text: &str, cx: &CensusContext<'_>) -> CensusOutcome {
        self.ledger.set_goal_text(goal_text.to_string());
        let mut state = State::Plan;
        let mut provider_error = None;

        let stop = loop {
            if cx.cancel.is_some_and(|c| c.is_cancelled()) {
                break CensusStop::Cancelled;
            }
            if self.calls_made >= self.limits.max_phase_calls {
                break CensusStop::BudgetExhausted;
            }

            let step = match state {
                State::Plan => self.step_plan(cx).await,
                State::Collect(index) => self.step_collect(index, cx).await,
                State::Distill(index) => self.step_distill(index, cx).await,
                State::Join => self.step_join(cx).await,
            };

            match step {
                Ok(Some(next)) => state = next,
                Ok(None) => break CensusStop::Joined,
                Err(PhaseError::Cancelled) => break CensusStop::Cancelled,
                Err(PhaseError::SchemaRejected {
                    phase,
                    attempts,
                    reason,
                }) => {
                    let text = format!(
                        "{phase}フェーズの出力が{attempts}回ともスキーマ検証に通らなかった: {reason}"
                    );
                    break CensusStop::Blocked { reason: text };
                }
                Err(PhaseError::Degenerate { phase, kind }) => {
                    let text = format!(
                        "{phase}フェーズの出力が縮退した（{}）。再推論の梯子を使い切っても回復しなかった",
                        kind.as_str()
                    );
                    break CensusStop::Blocked { reason: text };
                }
                Err(PhaseError::ContextOverflow {
                    phase,
                    estimated_input_tokens,
                    max_out,
                    context_window,
                }) => {
                    let text = format!(
                        "{phase}フェーズの1コールがコンテキスト窓に収まらない（入力概算\
                         {estimated_input_tokens} + 出力枠{max_out} > 窓{context_window}）。\
                         settings.jsonの`cognition.budgets.{}`を小さくするか、\
                         `compaction.context_window`（または--context-window）で実n_ctxを\
                         正しく指定すること",
                        phase.as_str()
                    );
                    break CensusStop::Blocked { reason: text };
                }
                Err(PhaseError::Provider(e)) => {
                    let reason = format!("プロバイダ呼び出しに失敗した: {e}");
                    provider_error = Some(e);
                    break CensusStop::Blocked { reason };
                }
            }
        };

        let answer = match &stop {
            CensusStop::Cancelled => String::new(),
            CensusStop::Joined => self.final_answer.take().unwrap_or_default(),
            CensusStop::Blocked { reason } => {
                let done = self.scratch.list_notes().map(|n| n.len()).unwrap_or(0);
                format!("調査を完了できなかった（{reason}）。{done}件のnotesまでは集まっている。")
            }
            CensusStop::BudgetExhausted => {
                let done = self.scratch.list_notes().map(|n| n.len()).unwrap_or(0);
                format!("コール数の上限に達したため調査を打ち切った。{done}件のnotesまでは集まっている。")
            }
        };

        CensusOutcome {
            answer,
            usage: self.usage,
            stop,
            provider_error,
        }
    }

    fn runner<'a>(&'a self, cx: &'a CensusContext<'a>) -> PhaseRunner<'a> {
        PhaseRunner {
            exec: cx.exec,
            ctx: cx.ctx,
            tools: cx.tools,
            caps: cx.caps,
            events: cx.events,
            cancel: cx.cancel,
            assembler: &self.assembler,
            max_schema_retries: self.limits.max_schema_retries,
            context_window: cx.context_window,
        }
    }

    /// worklistの列挙結果からworklistを組む。列挙自体はツール（`glob`等）で行う——
    /// モデルに数えさせない（`plans/PLAN-CENSUS-ENGINE.md`「列挙自体はツール」）。
    async fn step_plan(&mut self, cx: &CensusContext<'_>) -> Result<Option<State>, PhaseError> {
        let result: PhaseValue<PlanOutput> = self
            .runner(cx)
            .run(
                Phase::Plan,
                PhaseInput::default(),
                &self.ledger,
                Conclusion::Required,
                plan::validate_plan,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");
        self.ledger.set_worklist(plan::build_worklist(out));
        Ok(Some(self.next_state(0)))
    }

    /// worklistの1項目についてツールを叩き、生出力を得る。**判断や要約はしない**
    /// （本来の産物はツール呼び出しの方、`Investigate`と同じ`Conclusion::Optional`）。
    ///
    /// `notes/<item.id>.md`が既にあればモデルを一切呼ばずに次へ進む——実測で見えた
    /// 「同じファイルを5回読む」浪費を構造的に修正する部分そのもの。
    async fn step_collect(
        &mut self,
        index: usize,
        cx: &CensusContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        let item = self
            .ledger
            .item(index)
            .expect("index within worklist bounds")
            .clone();

        if self.scratch.note_exists(&item.id).unwrap_or(false) {
            return Ok(Some(self.next_state(index + 1)));
        }

        let result: PhaseValue<CollectOutput> = self
            .runner(cx)
            .run(
                Phase::Collect,
                PhaseInput {
                    target: Some(&item.id),
                    ..Default::default()
                },
                &self.ledger,
                Conclusion::Optional,
                validate_collect,
            )
            .await?;

        // 蒸留コールの入力予算いっぱいまで抜き出す（`hiv::step_investigate`と同じ式）。
        let excerpt_chars = self.assembler.budget(Phase::Distill).max_in as usize * 4;
        let mut found = observations(
            &result.tool_calls,
            |call| cx.tools.get(&call.name).map(|t| t.risk(&call.input)),
            Some(&self.scratch),
            excerpt_chars,
        );
        self.account(result);

        match found.pop() {
            Some(observation) => {
                self.current_observation = Some(observation);
                Ok(Some(State::Distill(index)))
            }
            // ツール呼び出しが0件（拒否・未知ツール・キャンセル含む）。1項目の失敗で
            // 全体は止めず、理由を記録して次へ進む。
            None => {
                let _ = self
                    .scratch
                    .put_note(&item.id, "（この項目からは観測が得られなかった）");
                Ok(Some(self.next_state(index + 1)))
            }
        }
    }

    /// 直前の観測1件を蒸留し、`notes/<item.id>.md`へ書く。**1観測1コール・履歴なし**
    /// （既存`Phase::Distill`のプロンプト・予算・検証をそのまま流用）。
    async fn step_distill(
        &mut self,
        index: usize,
        cx: &CensusContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        let item = self
            .ledger
            .item(index)
            .expect("index within worklist bounds")
            .clone();
        let observation = self
            .current_observation
            .take()
            .expect("State::Distill always follows a State::Collect that found an observation");

        let result: PhaseValue<DistillOutput> = self
            .runner(cx)
            .run(
                Phase::Distill,
                PhaseInput {
                    raw_output: Some(&observation.excerpt),
                    ..Default::default()
                },
                &self.ledger,
                Conclusion::Required,
                crate::hiv::parse::validate_distill,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");

        let _ = self.scratch.put_note(&item.id, &render_note(&item, &out));
        Ok(Some(self.next_state(index + 1)))
    }

    /// `notes/*.md`の要約だけを連結して最終回答を組む。`raw/`には一切触れない。
    async fn step_join(&mut self, cx: &CensusContext<'_>) -> Result<Option<State>, PhaseError> {
        let notes = self.scratch.list_notes().unwrap_or_default();
        let joined: String = notes
            .iter()
            .map(|(_, content)| content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let result: PhaseValue<JoinOutput> = self
            .runner(cx)
            .run(
                Phase::Join,
                PhaseInput {
                    raw_output: Some(&joined),
                    ..Default::default()
                },
                &self.ledger,
                Conclusion::Required,
                validate_join,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");
        self.final_answer = Some(render_answer(&out));
        Ok(None)
    }

    /// 次のitemがあれば`Collect`、無ければ`Join`（＝worklistを網羅した）。
    fn next_state(&self, index: usize) -> State {
        if index < self.ledger.len() {
            State::Collect(index)
        } else {
            State::Join
        }
    }

    fn account<T>(&mut self, result: PhaseValue<T>) -> Option<T> {
        self.calls_made += result.calls;
        self.usage.input = self.usage.input.saturating_add(result.usage.input);
        self.usage.output = self.usage.output.saturating_add(result.usage.output);
        self.usage.cache_read = self
            .usage
            .cache_read
            .saturating_add(result.usage.cache_read);
        self.usage.cache_creation = self
            .usage
            .cache_creation
            .saturating_add(result.usage.cache_creation);
        result.value
    }
}

/// `CollectOutput.summary`は使わない（本来の産物はツール呼び出しの方）ので、
/// 追加の意味検証は無い。
fn validate_collect(_out: &CollectOutput) -> Result<(), String> {
    Ok(())
}

fn validate_join(out: &JoinOutput) -> Result<(), String> {
    if out.summary.trim().is_empty() {
        return Err("summaryが空だった。notesを読んで全体の結論を書くこと。".to_string());
    }
    Ok(())
}

fn render_note(item: &WorklistItem, out: &DistillOutput) -> String {
    let mut body = format!("## {}\n\n", item.id);
    if out.evidence.is_empty() {
        body.push_str("（関係する事実は見つからなかった）\n");
    } else {
        for e in &out.evidence {
            body.push_str(&format!("- {}\n", e.claim));
        }
    }
    body
}

fn render_answer(out: &JoinOutput) -> String {
    let mut body = out.summary.clone();
    if !out.key_findings.is_empty() {
        body.push_str("\n\n## 主な所見\n\n");
        for f in &out.key_findings {
            body.push_str(&format!("- {f}\n"));
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiv::testing::{PhaseExecutor, Reply};
    use crate::phase::PhaseBudgets;

    fn caps() -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: true,
            forced_tool_choice: true,
            schema_with_thinking: true,
            schema_with_tools: true,
            prompt_caching: false,
            context_window: 128_000,
            local: false,
        }
    }

    struct Harness {
        ctx: ToolCtx,
        tools: ToolRegistry,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                ctx: ToolCtx::new(std::path::PathBuf::from("C:/ws")),
                tools: ToolRegistry::with_builtin_tools(),
            }
        }

        fn cx<'a>(&'a self, exec: &'a PhaseExecutor) -> CensusContext<'a> {
            CensusContext {
                exec,
                ctx: &self.ctx,
                tools: &self.tools,
                caps: caps(),
                events: None,
                cancel: None,
                context_window: 128_000,
            }
        }
    }

    fn engine(scratch: ScratchStore) -> CensusEngine {
        CensusEngine::new(
            ContextAssembler::new("test-model", PhaseBudgets::default()),
            scratch,
            CensusLimits::default(),
        )
    }

    fn open_scratch(dir: &std::path::Path) -> ScratchStore {
        ScratchStore::open(dir).unwrap()
    }

    fn plan_reply(items: &[(&str, &str)]) -> Reply {
        let items: Vec<serde_json::Value> = items
            .iter()
            .map(|(id, query)| serde_json::json!({ "id": id, "query": query }))
            .collect();
        Reply::Text(serde_json::json!({ "items": items }).to_string())
    }

    fn distill_reply(claim: &str) -> Reply {
        Reply::Text(
            serde_json::json!({
                "evidence": [{ "claim": claim, "relation": "neutral", "source": "s", "contradicts": [] }]
            })
            .to_string(),
        )
    }

    fn join_reply(summary: &str) -> Reply {
        Reply::Text(serde_json::json!({ "summary": summary, "key_findings": [] }).to_string())
    }

    /// 1. `notes/<id>.md`が既にあれば、その項目の`Collect`/`Distill`を一切打たない
    ///    （実測で見えた「同じファイルを5回読み直す」の回帰テスト）。
    #[tokio::test]
    async fn a_finished_item_is_skipped_on_the_second_run() {
        let dir = tempfile::tempdir().unwrap();
        let h = Harness::new();

        // 1回目: フルに回してnotes/a.mdを作る。
        let exec1 = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "read a")])]),
            (
                Phase::Collect,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "raw content of a",
                )],
            ),
            (Phase::Distill, vec![distill_reply("fact about a")]),
            (Phase::Join, vec![join_reply("done")]),
        ]);
        let mut engine1 = engine(open_scratch(dir.path()));
        let outcome1 = engine1.run_goal("調べて", &h.cx(&exec1)).await;
        assert_eq!(outcome1.stop, CensusStop::Joined);
        assert_eq!(exec1.calls_to(Phase::Collect), 1);
        assert_eq!(exec1.calls_to(Phase::Distill), 1);

        // 2回目: 同じscratchディレクトリで新しいエンジンを起動。Planが同じ項目を
        // 出しても、notes/a.mdが既にあるのでCollect/Distillを一切呼ばない。
        let exec2 = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "read a")])]),
            (Phase::Join, vec![join_reply("done again")]),
        ]);
        let mut engine2 = engine(open_scratch(dir.path()));
        let outcome2 = engine2.run_goal("調べて", &h.cx(&exec2)).await;
        assert_eq!(outcome2.stop, CensusStop::Joined);
        assert_eq!(
            exec2.calls_to(Phase::Collect),
            0,
            "2回目はCollectを呼ばない"
        );
        assert_eq!(
            exec2.calls_to(Phase::Distill),
            0,
            "2回目はDistillを呼ばない"
        );
    }

    /// 2. 終了条件が「worklistが空（＝全項目にnotesがある）」であること。
    #[tokio::test]
    async fn the_worklist_terminates_when_every_item_has_notes() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = open_scratch(dir.path());
        scratch.put_note("a", "既存の要約A").unwrap();
        scratch.put_note("b", "既存の要約B").unwrap();

        let h = Harness::new();
        let exec = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "qa"), ("b", "qb")])]),
            (Phase::Join, vec![join_reply("全部既知")]),
        ]);
        let mut eng = engine(scratch);
        let outcome = eng.run_goal("依頼", &h.cx(&exec)).await;

        assert_eq!(outcome.stop, CensusStop::Joined);
        assert_eq!(exec.calls_to(Phase::Collect), 0);
        assert_eq!(exec.calls_to(Phase::Distill), 0);
        assert_eq!(exec.calls_to(Phase::Join), 1);
    }

    /// 3. `Join`の入力に生出力が混ざらない（notesの要約だけを見る）。
    #[tokio::test]
    async fn join_reads_only_notes_never_raw() {
        let dir = tempfile::tempdir().unwrap();
        let h = Harness::new();
        let exec = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "read a")])]),
            (
                Phase::Collect,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "SECRET_RAW_MARKER_12345",
                )],
            ),
            (Phase::Distill, vec![distill_reply("蒸留済みの短い要約")]),
            (Phase::Join, vec![join_reply("まとめ")]),
        ]);
        let mut eng = engine(open_scratch(dir.path()));
        let outcome = eng.run_goal("依頼", &h.cx(&exec)).await;
        assert_eq!(outcome.stop, CensusStop::Joined);

        let join_call = exec
            .seen()
            .into_iter()
            .find(|s| s.phase == Some(Phase::Join))
            .expect("Join was called");
        let harness_core::ContentBlock::Text(body) = &join_call.req.messages[0].content[0] else {
            panic!()
        };
        assert!(body.contains("蒸留済みの短い要約"), "{body}");
        assert!(
            !body.contains("SECRET_RAW_MARKER_12345"),
            "raw output leaked into Join: {body}"
        );
    }

    /// 4. 1項目の失敗（観測ゼロ）で全体を止めず、記録して次の項目へ進む。
    #[tokio::test]
    async fn a_failed_item_does_not_abort_the_census() {
        let dir = tempfile::tempdir().unwrap();
        let h = Harness::new();
        let exec = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "qa"), ("b", "qb")])]),
            (
                Phase::Collect,
                vec![
                    // item a: ツールを1つも呼ばない（観測ゼロ）。
                    Reply::Text(serde_json::json!({ "summary": "" }).to_string()),
                    // item b: 通常どおり観測が取れる。
                    Reply::tool(
                        "read_file",
                        serde_json::json!({ "path": "b.rs" }),
                        "raw content of b",
                    ),
                ],
            ),
            (Phase::Distill, vec![distill_reply("fact about b")]),
            (Phase::Join, vec![join_reply("summary")]),
        ]);
        let mut eng = engine(open_scratch(dir.path()));
        let outcome = eng.run_goal("依頼", &h.cx(&exec)).await;

        assert_eq!(
            outcome.stop,
            CensusStop::Joined,
            "1項目の失敗で全体を止めない"
        );
        assert_eq!(
            exec.calls_to(Phase::Collect),
            2,
            "両方のitemでCollectを試みる"
        );
        assert_eq!(
            exec.calls_to(Phase::Distill),
            1,
            "観測が取れたitem bだけdistillする"
        );
    }

    /// 5. 各`Distill`コールは1観測だけを見る（履歴なし・他項目の観測を混ぜない）。
    #[tokio::test]
    async fn every_distill_call_sees_exactly_one_observation() {
        let dir = tempfile::tempdir().unwrap();
        let h = Harness::new();
        let exec = PhaseExecutor::new([
            (Phase::Plan, vec![plan_reply(&[("a", "qa"), ("b", "qb")])]),
            (
                Phase::Collect,
                vec![
                    Reply::tool(
                        "read_file",
                        serde_json::json!({ "path": "a.rs" }),
                        "content of a",
                    ),
                    Reply::tool(
                        "read_file",
                        serde_json::json!({ "path": "b.rs" }),
                        "content of b",
                    ),
                ],
            ),
            (Phase::Distill, vec![distill_reply("noop")]),
            (Phase::Join, vec![join_reply("s")]),
        ]);
        let mut eng = engine(open_scratch(dir.path()));
        let outcome = eng.run_goal("依頼", &h.cx(&exec)).await;
        assert_eq!(outcome.stop, CensusStop::Joined);

        let distill_calls: Vec<_> = exec
            .seen()
            .into_iter()
            .filter(|s| s.phase == Some(Phase::Distill))
            .collect();
        assert_eq!(distill_calls.len(), 2, "1項目1コール");
        for call in &distill_calls {
            assert_eq!(call.req.messages.len(), 1, "履歴なし（1メッセージだけ）");
        }
        let harness_core::ContentBlock::Text(first) = &distill_calls[0].req.messages[0].content[0]
        else {
            panic!()
        };
        assert!(first.contains("content of a"), "{first}");
        assert!(
            !first.contains("content of b"),
            "1件目はaの観測だけ: {first}"
        );
        let harness_core::ContentBlock::Text(second) = &distill_calls[1].req.messages[0].content[0]
        else {
            panic!()
        };
        assert!(second.contains("content of b"), "{second}");
        assert!(
            !second.contains("content of a"),
            "2件目はbの観測だけ: {second}"
        );
    }
}
