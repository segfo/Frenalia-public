//! HIVループの状態機械（ライト構成）。`plans/DESIGN-COGNITION.md` §3。
//!
//! ```text
//! Hypothesize ─▶ Investigate ─▶ Distill(観測1件ごと) ─▶ Verify ─┬─ confirms+接地OK ─▶ Decide
//!      ▲              ▲                                          │
//!      │              └─ inconclusive（ラウンド残あり）───────────┤
//!      └─ 全仮説が決着済み（仮説の上限まで）─────────────────────┘
//! ```
//!
//! **遷移権限を持つのはここだけ**（§3.4「状態はハーネスが持つ。プロンプトに『次はこうして』と
//! 祈らない」）。モデルは各フェーズで小さな解釈タスクを1つこなすだけで、次に何をするかは
//! フェーズ出力が揃ったかどうかで機械的に決まる。
//!
//! # ライト構成であること
//!
//! §3.3の但し書き「ライトは Orient/Critic を省き Hypothesize→Investigate→Distill→Verify→Decide
//! の最短」に従う。Orient（状況把握）・Critic（自己批判）・Planner（タスク分解）はM19。
//! したがって`--cognition always`はM19までこのライト構成で走る（`docs/STATUS.md`）。
//!
//! # 1フェーズ = 1コール（フェーズ内サブループを作らない）
//!
//! `parallel_tool_calls:false`（`plans/DESIGN.md` Phase5-D）なので1ラウンドの観測は最大1件。
//! 反復はフェーズ内のサブループではなく「Verifyが決着しなければInvestigateへ再入」という
//! ラウンドで表現する。フェーズ内に会話履歴を持つサブループを作ると、そのフェーズだけ
//! 素朴ループと同じ文脈肥大が起きる（§0の弱点1）ため。

pub(crate) mod answer;
pub(crate) mod call;
pub(crate) mod evidence;
pub(crate) mod parse;
#[cfg(test)]
pub(crate) mod testing;

use std::collections::BTreeMap;

use harness_core::{AgentEvent, Phase, ProviderCapabilities, ToolCtx, Usage};
use harness_engine::{emit_event, EventSink, Executor};
use harness_tools::ToolRegistry;
use tokio_util::sync::CancellationToken;

use crate::context::{ContextAssembler, PhaseInput};
use crate::hiv::call::{Conclusion, PhaseError, PhaseRunner, PhaseValue};
use crate::memory::types::{
    Decision, GoalId, GoalStatus, HypId, HypStatus, Verdict, Verification, VerifyMethod,
};
use crate::memory::WorkingMemory;
use crate::schema::{
    DecideOutput, DistillOutput, HypothesizeOutput, InvestigateOutput, VerifyOutput, VerifyVerdict,
};
use crate::scratch::ScratchStore;
use crate::source::SourceCatalog;

/// ループの上限（`plans/DESIGN-COGNITION.md` §3.5のうちM15で実装する部分）。
///
/// 「進展なし検知 → `NeedsInput`でユーザへエスカレーション」はM20。M15は
/// **必ず有限で止まること**だけを担保する。
#[derive(Debug, Clone, Copy)]
pub struct HivLimits {
    /// 1ゴールで立てる仮説の総数（§3.5 既定3）。
    pub max_hypotheses: usize,
    /// 1仮説あたりの調査ラウンド数（§3.5 既定4）。
    pub max_investigate_rounds: u32,
    /// フェーズコールの総数。`--max-turns`を認知層へ拡張したもの（§3.5）。
    pub max_phase_calls: usize,
    /// スキーマ検証に落ちたときの再実行回数（§3.4 最大2）。
    pub max_schema_retries: u32,
}

impl Default for HivLimits {
    fn default() -> Self {
        Self {
            max_hypotheses: 3,
            max_investigate_rounds: 4,
            max_phase_calls: 30,
            max_schema_retries: 2,
        }
    }
}

/// ループが止まった理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HivStop {
    /// Decideまで到達した。
    Decided,
    /// 構造化出力が規定回数取れない等でこれ以上進めない（fail-closed）。
    Blocked {
        reason: String,
    },
    /// 上限（ラウンド・コール数）に当たった。
    BudgetExhausted,
    Cancelled,
}

/// 1ゴール分の実行結果。
#[derive(Debug)]
pub struct HivOutcome {
    /// 台帳から決定的に組んだ最終回答（`Cancelled`のときは空）。
    pub answer: String,
    pub usage: Usage,
    pub stop: HivStop,
    /// プロバイダ呼び出し自体が失敗した場合のみ`Some`。
    pub provider_error: Option<harness_core::ProviderError>,
}

/// 1回の`run_goal`が要る周辺。`Executor`しか受け取らないので、この層は
/// `LlmProvider`にもツールの実行にも直接触れられない（§1の不変条件）。
pub struct HivContext<'a> {
    pub exec: &'a dyn Executor,
    pub ctx: &'a ToolCtx,
    pub tools: &'a ToolRegistry,
    pub caps: ProviderCapabilities,
    pub events: Option<&'a EventSink>,
    pub cancel: Option<&'a CancellationToken>,
    /// 1コールを収めるべき実コンテキスト窓（§6.6）。`caps.context_window`ではなく
    /// **解決済みの値**（CLIの`--context-window`／`settings.json`の`compaction.context_window`／
    /// capabilityの順）を受ける——ローカル推論サーバのcapabilityは128,000決め打ちで、
    /// 実`n_ctx`（ロード設定）とは別物だから（`plans/PLAN-COMPACTION.md`）。
    pub context_window: u32,
}

/// 内部の遷移状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Hypothesize,
    Investigate(HypId),
    Verify(HypId),
    Decide,
}

/// HIVループの実体。台帳を所有し、フェーズ遷移の唯一の権限を持つ。
pub struct HivEngine {
    mem: WorkingMemory,
    assembler: ContextAssembler,
    scratch: Option<ScratchStore>,
    /// 情報源カタログ（M16、§4.2）。証拠の`trust`/`freshness`の決定と、CrossSourceの
    /// 示唆に使う。`ContextAssembler`も同じカタログを持つ（あちらはInvestigateへ見せる用）。
    catalog: SourceCatalog,
    limits: HivLimits,
    /// 実際に投げたプロバイダ呼び出しの数（スキーマ再実行も1回として数える）。
    calls_made: usize,
    usage: Usage,
    /// Investigateの計画から決めた検証手段を、同じ仮説のVerifyへ引き継ぐ。
    methods: BTreeMap<HypId, VerifyMethod>,
    /// 仮説ごとの調査ラウンド数。
    rounds: BTreeMap<HypId, u32>,
}

impl HivEngine {
    pub fn new(
        assembler: ContextAssembler,
        scratch: Option<ScratchStore>,
        catalog: SourceCatalog,
        limits: HivLimits,
    ) -> Self {
        Self {
            mem: WorkingMemory::new(),
            assembler,
            scratch,
            catalog,
            limits,
            calls_made: 0,
            usage: Usage::default(),
            methods: BTreeMap::new(),
            rounds: BTreeMap::new(),
        }
    }

    pub fn memory(&self) -> &WorkingMemory {
        &self.mem
    }

    /// 1ゴールを最後まで進める。
    ///
    /// **失敗しても`Err`を返さない**——プロバイダ失敗もスキーマ枯渇も、台帳に残った
    /// ところまでを回答として返す方が呼び出し側（フロントエンド）にとって扱いやすく、
    /// 「何が分かって何が分からなかったか」も伝わるため。区別は[`HivOutcome::stop`]で付く。
    pub async fn run_goal(&mut self, goal_text: &str, cx: &HivContext<'_>) -> HivOutcome {
        let goal = self.mem.add_goal(goal_text, Vec::new());
        let mut state = State::Hypothesize;
        let mut provider_error = None;

        let stop = loop {
            if cx.cancel.is_some_and(|c| c.is_cancelled()) {
                break HivStop::Cancelled;
            }
            if self.calls_made >= self.limits.max_phase_calls {
                break HivStop::BudgetExhausted;
            }

            let step = match state {
                State::Hypothesize => self.step_hypothesize(goal, cx).await,
                State::Investigate(hyp) => {
                    *self.rounds.entry(hyp).or_default() += 1;
                    self.step_investigate(hyp, cx).await
                }
                State::Verify(hyp) => self.step_verify(hyp, cx).await,
                State::Decide => self.step_decide(goal, cx).await,
            };

            match step {
                Ok(Some(next)) => state = next,
                Ok(None) => break HivStop::Decided,
                Err(PhaseError::Cancelled) => break HivStop::Cancelled,
                Err(PhaseError::SchemaRejected {
                    phase,
                    attempts,
                    reason,
                }) => {
                    // fail-closed。§3.4の「上位tierへエスカレーション」はモデル階層化（M17）が
                    // 入ってから——降格先が無い状態で素朴ループへ落とすと、認知レイヤーが
                    // 働いていないことに気付けないまま結論だけが出る。
                    let text = format!(
                        "{phase}フェーズの出力が{attempts}回ともスキーマ検証に通らなかった: {reason}"
                    );
                    self.mem.add_open_question(text.clone(), true);
                    break HivStop::Blocked { reason: text };
                }
                // 縮退（§11.4）。`TurnExecutor`が回復の梯子を登り切ってなお壊れた出力しか
                // 返らなかったので、修復指示を添えた再実行にも意味が無い。fail-closedで畳む。
                Err(PhaseError::Degenerate { phase, kind }) => {
                    let text = format!(
                        "{phase}フェーズの出力が縮退した（{}）。再推論の梯子を使い切っても回復しなかった",
                        kind.as_str()
                    );
                    self.mem.add_open_question(text.clone(), true);
                    break HivStop::Blocked { reason: text };
                }
                // コンテキスト超過（§6.6 規則4）。縮小の梯子を使い切ってなお1コールが
                // 窓に収まらない＝**設定の組合せが成立していない**ので、直し方を書いて畳む。
                // 送れば通るかもしれない、で送らないのは、ローカル推論サーバが超過を
                // エラーにせず黙って古いトークンを捨てる（＝静かに間違える）ためである。
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
                    self.mem.add_open_question(text.clone(), true);
                    break HivStop::Blocked { reason: text };
                }
                Err(PhaseError::Provider(e)) => {
                    let reason = format!("プロバイダ呼び出しに失敗した: {e}");
                    provider_error = Some(e);
                    break HivStop::Blocked { reason };
                }
            }
        };

        match &stop {
            HivStop::Decided => self.mem.set_goal_status(goal, GoalStatus::Achieved),
            HivStop::Blocked { .. } => self.mem.set_goal_status(goal, GoalStatus::Blocked),
            HivStop::BudgetExhausted | HivStop::Cancelled => {}
        }
        let answer = match stop {
            // キャンセル時はフロントエンドが「cancelled」を出す（素朴ループの
            // `AgentLoopOutcome.text`が空になるのと同じ扱い）。
            HivStop::Cancelled => String::new(),
            HivStop::Decided | HivStop::Blocked { .. } | HivStop::BudgetExhausted => {
                answer::render(&self.mem, &stop, self.catalog.has_mcp(cx.tools))
            }
        };
        HivOutcome {
            answer,
            usage: self.usage,
            stop,
            provider_error,
        }
    }

    fn runner<'a>(&'a self, cx: &'a HivContext<'a>) -> PhaseRunner<'a> {
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

    async fn step_hypothesize(
        &mut self,
        goal: GoalId,
        cx: &HivContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        let result: PhaseValue<HypothesizeOutput> = self
            .runner(cx)
            .run(
                Phase::Hypothesize,
                PhaseInput::default(),
                &self.mem,
                Conclusion::Required,
                parse::validate_hypothesize,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");

        // ライトは1本ずつ潰す（複数仮説の並行調査は§9の限定並列＝M17以降）。検証を通った
        // 出力なので`hypotheses`は非空・`predicts`も非空であることが保証されている。
        let mut proposed = None;
        if self.mem.hypotheses().len() < self.limits.max_hypotheses {
            proposed = out.hypotheses.into_iter().next();
        }
        let added = proposed.map(|p| {
            let id = self.mem.add_hypothesis(
                goal,
                p.statement.clone(),
                p.predicts.clone(),
                p.confidence,
            );
            emit_event(
                cx.events,
                AgentEvent::HypothesisFormed {
                    id: id.label(),
                    statement: p.statement,
                    predicts: p.predicts,
                },
            );
            id
        });

        Ok(Some(
            match added.or_else(|| self.next_open_hypothesis(None)) {
                Some(hyp) => State::Investigate(hyp),
                // 仮説の上限に達していて、未決着のものも無い。持っている材料で結論へ。
                None => State::Decide,
            },
        ))
    }

    async fn step_investigate(
        &mut self,
        hyp: HypId,
        cx: &HivContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        self.mem
            .set_hypothesis_status(hyp, HypStatus::Investigating);
        let result: PhaseValue<InvestigateOutput> = self
            .runner(cx)
            .run(
                Phase::Investigate,
                PhaseInput {
                    target: Some(hyp),
                    ..Default::default()
                },
                &self.mem,
                // 計画は補助（本来の産物はツール呼び出し）。取れなくても止めない。
                Conclusion::Optional,
                parse::validate_investigate,
            )
            .await?;

        // 蒸留コールの入力予算いっぱいまで抜き出す（トークン概算は文字数/4なので×4。
        // 台帳スライスの分だけ超えるが、組立側が改めて予算内へ縮約する）。
        let excerpt_chars = self.assembler.budget(Phase::Distill).max_in as usize * 4;
        let observations = evidence::observations(
            &result.tool_calls,
            |call| cx.tools.get(&call.name).map(|t| t.risk(&call.input)),
            self.scratch.as_ref(),
            excerpt_chars,
        );
        let plan = self.account(result);
        self.methods.insert(hyp, verify_method_for(plan.as_ref()));

        for observation in observations {
            let distilled: PhaseValue<DistillOutput> = self
                .runner(cx)
                .run(
                    Phase::Distill,
                    PhaseInput {
                        target: Some(hyp),
                        raw_output: Some(&observation.excerpt),
                        ..Default::default()
                    },
                    &self.mem,
                    Conclusion::Required,
                    parse::validate_distill,
                )
                .await?;
            let out = self.account(distilled).expect("Required yields a value");
            evidence::record_distilled(
                &mut self.mem,
                hyp,
                &observation,
                out,
                &self.catalog,
                cx.events,
            );
        }

        Ok(Some(State::Verify(hyp)))
    }

    async fn step_verify(
        &mut self,
        hyp: HypId,
        cx: &HivContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        // **§4.3「Verifyで決着」**: 検証コールの前に矛盾を機械的に決着させる。先に済ませるのは、
        // 決着の結果が`Validity.grade`を通じて検証コールの入力（台帳スライス）へ反映されるため。
        for (a, b) in self.mem.resolve_conflicts() {
            self.mem.add_open_question(
                format!(
                    "{a}と{b}が矛盾しており、信頼度・鮮度のどちらでも優劣が付かない。\
                     どちらを採るか判断が要る。"
                ),
                false,
            );
        }

        let result: PhaseValue<VerifyOutput> = self
            .runner(cx)
            .run(
                Phase::Verify,
                PhaseInput {
                    target: Some(hyp),
                    ..Default::default()
                },
                &self.mem,
                Conclusion::Required,
                parse::validate_verify,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");

        let mut verdict = match out.verdict {
            VerifyVerdict::Confirms => Verdict::Confirms,
            VerifyVerdict::Refutes => Verdict::Refutes,
            VerifyVerdict::Inconclusive => Verdict::Inconclusive,
        };
        let mut missing = out.missing;

        // **§3.4の遷移条件**: 自己申告の`confirms`だけでは確証にしない。
        if verdict == Verdict::Confirms {
            if let Err(reason) = self.can_confirm(hyp) {
                verdict = Verdict::Inconclusive;
                missing.push(reason);
            }
        }
        // 確証したが単一ソースどまりで、まだ使っていない別種の接地が残っている場合は
        // 裏取りを促す（§4.3「裏取り強化ルール」）。**確証は止めない**——§4.2が
        // 「MCPが使えないときはCrossSource要求を免除」「降格しても結論は出せる」と定めており、
        // 使える情報源が残っているかどうかで結論の可否が変わるのは筋が通らないため。
        if verdict == Verdict::Confirms {
            if let Some(hint) = self.cross_source_hint(hyp, cx.tools) {
                missing.push(hint);
            }
        }

        self.mem.record_verification(Verification {
            hyp,
            method: self.methods.remove(&hyp).unwrap_or(VerifyMethod::ReRead),
            verdict,
            missing: missing.clone(),
            note: out.note,
        });

        let promoted = verdict == Verdict::Confirms;
        if promoted {
            self.mem.set_hypothesis_status(hyp, HypStatus::Confirmed);
        }
        emit_event(
            cx.events,
            AgentEvent::VerificationResult {
                hyp: hyp.label(),
                verdict: format!("{verdict:?}").to_lowercase(),
                missing,
                promoted,
                strength: self.mem.evidence_strength(hyp).as_str().to_string(),
            },
        );

        if promoted {
            return Ok(Some(State::Decide));
        }
        // 決着していない: ラウンドが残っていれば同じ仮説をもう一度調べる。
        if verdict == Verdict::Inconclusive && self.rounds_left(hyp) {
            return Ok(Some(State::Investigate(hyp)));
        }
        // 尽きた/反証された: 別の未決着仮説 → 新しい仮説 → 諦めてDecide、の順。
        if let Some(next) = self.next_open_hypothesis(Some(hyp)) {
            return Ok(Some(State::Investigate(next)));
        }
        if self.mem.hypotheses().len() < self.limits.max_hypotheses {
            return Ok(Some(State::Hypothesize));
        }
        Ok(Some(State::Decide))
    }

    async fn step_decide(
        &mut self,
        goal: GoalId,
        cx: &HivContext<'_>,
    ) -> Result<Option<State>, PhaseError> {
        let result: PhaseValue<DecideOutput> = self
            .runner(cx)
            .run(
                Phase::Decide,
                PhaseInput {
                    goal: Some(goal),
                    ..Default::default()
                },
                &self.mem,
                Conclusion::Required,
                parse::validate_decide,
            )
            .await?;
        let out = self.account(result).expect("Required yields a value");

        let based_on = self
            .mem
            .hypotheses()
            .iter()
            .filter(|h| h.goal == goal && h.status == HypStatus::Confirmed)
            .map(|h| h.id)
            .collect();
        self.mem.add_decision(Decision {
            goal,
            action: out.action,
            based_on,
            verify_hint: Some(out.then_verify),
        });
        Ok(None)
    }

    /// §3.4の`Confirmed`遷移条件。**条件を足すのはこの関数だけ**にする（判定を1箇所に保つ）。
    ///
    /// 現在の条件は2つ:
    ///
    /// 1. **接地種別の下限【E1】** — `File`/`Shell`/`Mcp`のいずれかが1件以上。`ModelPrior`単独は
    ///    もちろん、`Web`単独でも確証にしない。矛盾の決着で退けられた観測も数えない。
    /// 2. **未決着Conflictingなし**（M16） — 支持証拠が矛盾を抱えたままなら確証へ上げない。
    ///
    /// M19のCritic通過はここへ足す。`Err`の中身はそのまま`Verification.missing`へ入り、
    /// ユーザにも次ラウンドのモデルにも「何が足りないか」として見える。
    fn can_confirm(&self, hyp: HypId) -> Result<(), String> {
        if !self.mem.has_grounded_support(hyp) {
            return Err("ワークスペースのファイル・shell実行・MCPのいずれかで直接観測した証拠が無い\
                 （web・モデルの内部知識だけでは確証にしない）"
                .to_string());
        }
        let conflicts = self.mem.unresolved_conflicts(hyp);
        if !conflicts.is_empty() {
            let labels: Vec<String> = conflicts.iter().map(|id| id.label()).collect();
            return Err(format!(
                "支持する証拠に未決着の矛盾がある（{}）。どちらが正しいかを判定できる観測が要る",
                labels.join("・")
            ));
        }
        Ok(())
    }

    /// 裏取りの示唆（§4.3「裏取り強化ルール」）。単一ソースどまりで、かつ**実際に呼べる**
    /// 別種の接地が残っているときだけ返す。カタログに無いものは示唆しない——出せない要求を
    /// `missing`へ書くと、次ラウンドのモデルが達成不能な指示を追い続ける。
    fn cross_source_hint(&self, hyp: HypId, tools: &ToolRegistry) -> Option<String> {
        let used = self.mem.grounded_kinds(hyp);
        let left = self.catalog.grounding_kinds_not_yet_used(tools, &used);
        if left.is_empty() {
            return None;
        }
        let names: Vec<&str> = left
            .iter()
            .map(|k| match k {
                crate::memory::types::SourceKind::File => "ワークスペースのファイル",
                crate::memory::types::SourceKind::Shell => "コマンド実行",
                crate::memory::types::SourceKind::Mcp => "MCP",
                crate::memory::types::SourceKind::Web
                | crate::memory::types::SourceKind::Memory
                | crate::memory::types::SourceKind::ModelPrior => "その他",
            })
            .collect();
        Some(format!(
            "単一の情報源しか根拠になっていない。{}でも裏取りできればより確かになる（必須ではない）",
            names.join("・")
        ))
    }

    fn rounds_left(&self, hyp: HypId) -> bool {
        self.rounds.get(&hyp).copied().unwrap_or(0) < self.limits.max_investigate_rounds
    }

    /// 次に調べる未決着の仮説（`confidence`降順＝§3.4のconfidenceの唯一の用途）。
    /// **調査ラウンドを使い切った仮説は返さない**——返すと、決着しない仮説同士を
    /// 行き来し続ける経路ができてしまう。
    fn next_open_hypothesis(&self, exclude: Option<HypId>) -> Option<HypId> {
        self.mem
            .investigation_order()
            .into_iter()
            .find(|id| Some(*id) != exclude && self.rounds_left(*id))
    }

    /// コール数・usageを計上して値を取り出す。**全フェーズがこれを通る**ので、
    /// 上限の会計から漏れるコールが構造的に無くなる。
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

/// Investigateの計画（`plan[].source`）から検証手段を決める（§3.1 `VerifyMethod`）。
/// 計画が取れなかったときは、既に集めた証拠を読み直す`ReRead`に倒す。
fn verify_method_for(plan: Option<&InvestigateOutput>) -> VerifyMethod {
    let Some(plan) = plan else {
        return VerifyMethod::ReRead;
    };
    let sources: Vec<&str> = plan.plan.iter().map(|s| s.source.as_str()).collect();
    if sources
        .iter()
        .any(|s| s.contains("shell") || s.contains("test"))
    {
        VerifyMethod::RunTest
    } else if sources.len() > 1 {
        VerifyMethod::CrossSource
    } else {
        VerifyMethod::ReRead
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{phase_of, PhaseExecutor, Reply};
    use super::*;
    use crate::memory::types::{Evidence, SourceRef};
    use crate::memory::validity::{Freshness, TrustLevel, Validity};
    use crate::phase::PhaseBudgets;
    use harness_engine::TurnVisibility;

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

    fn engine(limits: HivLimits) -> HivEngine {
        engine_with(SourceCatalog::with_builtin_defaults(), limits)
    }

    fn engine_with(catalog: SourceCatalog, limits: HivLimits) -> HivEngine {
        HivEngine::new(
            ContextAssembler::new("test-model", PhaseBudgets::default())
                .with_catalog(catalog.clone()),
            None,
            catalog,
            limits,
        )
    }

    fn hypothesize(statement: &str) -> Reply {
        Reply::Text(
            serde_json::json!({
                "hypotheses": [{
                    "statement": statement,
                    "predicts": ["該当の記述が見つからなければ偽"],
                    "confidence": 0.7
                }]
            })
            .to_string(),
        )
    }

    fn distill(claim: &str, relation: &str) -> Reply {
        distill_contradicting(claim, relation, &[])
    }

    fn distill_contradicting(claim: &str, relation: &str, contradicts: &[&str]) -> Reply {
        Reply::Text(
            serde_json::json!({
                "evidence": [{ "claim": claim, "relation": relation, "source": "read_file",
                               "contradicts": contradicts }]
            })
            .to_string(),
        )
    }

    fn verify(verdict: &str) -> Reply {
        Reply::Text(
            serde_json::json!({ "verdict": verdict, "missing": [], "note": "証拠を読んだ" })
                .to_string(),
        )
    }

    fn decide() -> Reply {
        Reply::Text(
            serde_json::json!({ "action": "run_shellの実装を直す", "then_verify": "cargo test" })
                .to_string(),
        )
    }

    async fn run(exec: &PhaseExecutor, limits: HivLimits) -> (HivEngine, HivOutcome) {
        // `caps()`と同じ広い窓。既定では§6.6の梯子を踏ませない。
        run_with_window(exec, limits, caps().context_window).await
    }

    async fn run_with_window(
        exec: &PhaseExecutor,
        limits: HivLimits,
        context_window: u32,
    ) -> (HivEngine, HivOutcome) {
        let ctx = ToolCtx::new(std::path::PathBuf::from("C:/ws"));
        let tools = ToolRegistry::with_builtin_tools();
        let mut engine = engine(limits);
        let cx = HivContext {
            exec,
            ctx: &ctx,
            tools: &tools,
            caps: caps(),
            events: None,
            cancel: None,
            context_window,
        };
        let outcome = engine.run_goal("run_shellが使うシェルを調べて", &cx).await;
        (engine, outcome)
    }

    /// **受入条件**: 仮説→調査→蒸留→検証→決定を強制遷移し、台帳が埋まること。
    #[tokio::test]
    async fn hiv_light_walks_hypothesize_to_decide_and_fills_the_ledger() {
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("PowerShellを使う")]),
            (
                Phase::Investigate,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "crates/harness-tools/src/shell.rs" }),
                    "powershell.exe を起動している",
                )],
            ),
            (
                Phase::Distill,
                vec![distill("shell.rsがpowershellを起動している", "supports")],
            ),
            (Phase::Verify, vec![verify("confirms")]),
            (Phase::Decide, vec![decide()]),
        ]);
        let (engine, outcome) = run(&exec, HivLimits::default()).await;

        assert_eq!(
            exec.phases(),
            vec![
                Phase::Hypothesize,
                Phase::Investigate,
                Phase::Distill,
                Phase::Verify,
                Phase::Decide
            ],
            "HIVライトのフェーズ列は決定的でなければならない"
        );
        assert_eq!(outcome.stop, HivStop::Decided);

        let mem = engine.memory();
        assert_eq!(mem.hypotheses().len(), 1);
        assert_eq!(mem.hypotheses()[0].status, HypStatus::Confirmed);
        assert_eq!(mem.evidence().len(), 1);
        assert_eq!(
            mem.evidence()[0].source,
            SourceRef::File {
                path: "crates/harness-tools/src/shell.rs".to_string(),
                lines: (0, 0)
            },
            "出典はハーネスが観測したツール呼び出しから決まる"
        );
        assert_eq!(mem.verifications().len(), 1);
        assert_eq!(mem.decisions().len(), 1);
        assert_eq!(mem.goals()[0].status, GoalStatus::Achieved);

        // 最終回答は台帳から組まれ、根拠と出典を伴う。
        assert!(
            outcome.answer.contains("run_shellの実装を直す"),
            "{}",
            outcome.answer
        );
        assert!(
            outcome
                .answer
                .contains("shell.rsがpowershellを起動している"),
            "{}",
            outcome.answer
        );
        // usageは全フェーズの合計（5コール × input:10）。
        assert_eq!(outcome.usage.input, 50);
    }

    /// フェーズコールは全て`Internal`で投げる（フェーズ出力のJSONがユーザに見えない）。
    #[tokio::test]
    async fn every_phase_call_is_marked_internal() {
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("X")]),
            (
                Phase::Investigate,
                vec![Reply::Text("{\"plan\":[]}".into())],
            ),
            (Phase::Verify, vec![verify("inconclusive")]),
            (Phase::Decide, vec![decide()]),
        ]);
        run(
            &exec,
            HivLimits {
                max_investigate_rounds: 0,
                ..HivLimits::default()
            },
        )
        .await;

        assert!(!exec.seen().is_empty());
        for seen in exec.seen() {
            assert_eq!(
                seen.visibility,
                TurnVisibility::Internal,
                "{:?}",
                seen.phase
            );
        }
    }

    /// 各フェーズのリクエストが§3.3の入力予算に収まっていること（実ループでの担保）。
    #[tokio::test]
    async fn every_phase_request_stays_within_its_input_budget() {
        let huge: &'static str = Box::leak("x".repeat(200_000).into_boxed_str());
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("PowerShellを使う")]),
            (
                Phase::Investigate,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "src/shell.rs" }),
                    huge,
                )],
            ),
            (Phase::Distill, vec![distill("観測", "supports")]),
            (Phase::Verify, vec![verify("confirms")]),
            (Phase::Decide, vec![decide()]),
        ]);
        run(&exec, HivLimits::default()).await;

        let budgets = PhaseBudgets::default();
        for seen in exec.seen() {
            let phase = seen.phase.unwrap();
            let estimated = harness_engine::estimate_tokens(&seen.req);
            assert!(
                estimated <= u64::from(budgets.get(phase).max_in),
                "{phase}: {estimated} > {}",
                budgets.get(phase).max_in
            );
        }
    }

    /// **§3.4の接地チェック**（【E1】）。`ModelPrior`単独はもちろん`Web`単独でも確証にしない。
    #[test]
    fn only_file_shell_or_mcp_evidence_counts_as_grounding() {
        for (source, grounded) in [
            (
                SourceRef::File {
                    path: "a.rs".into(),
                    lines: (0, 0),
                },
                true,
            ),
            (
                SourceRef::Shell {
                    cmd: "cargo test".into(),
                    exit: 0,
                },
                true,
            ),
            (
                SourceRef::Mcp {
                    server: "docs".into(),
                    tool: "search".into(),
                    args_digest: "d".into(),
                },
                true,
            ),
            (
                SourceRef::Web {
                    url: "https://example.com".into(),
                    fetched_at: "0".into(),
                },
                false,
            ),
            (SourceRef::ModelPrior, false),
            (
                SourceRef::Memory {
                    note_id: "n1".into(),
                },
                false,
            ),
        ] {
            let mut e = engine(HivLimits::default());
            let g = e.mem.add_goal("直す", vec![]);
            let h = e
                .mem
                .add_hypothesis(g, "原因はX", vec!["Yが見える".into()], 0.7);
            let recorded = source.clone();
            e.mem.add_evidence(
                move |id| Evidence {
                    id,
                    claim: "観測".to_string(),
                    source: recorded,
                    validity: Validity::seed(TrustLevel::High, Freshness::Fresh),
                    raw_ref: None,
                },
                Some((h, true)),
            );
            assert_eq!(e.can_confirm(h).is_ok(), grounded, "{source:?}");
        }
    }

    /// **§3.4のもう1つの遷移条件（M16）**: 支持証拠が未決着の矛盾を抱えていたら確証へ上げない。
    #[test]
    fn an_unresolved_conflict_blocks_confirmation() {
        let mut e = engine(HivLimits::default());
        let g = e.mem.add_goal("直す", vec![]);
        let h = e
            .mem
            .add_hypothesis(g, "原因はX", vec!["Yが見える".into()], 0.7);
        let mut add = |claim: &'static str, trust| {
            e.mem.add_evidence(
                move |id| Evidence {
                    id,
                    claim: claim.to_string(),
                    source: SourceRef::File {
                        path: "a.rs".into(),
                        lines: (0, 0),
                    },
                    validity: Validity::seed(trust, Freshness::Fresh),
                    raw_ref: None,
                },
                Some((h, true)),
            )
        };
        let a = add("Aと書いてある", TrustLevel::High);
        let b = add("Bと書いてある", TrustLevel::High);
        assert!(e.can_confirm(h).is_ok(), "矛盾が無いうちは接地だけで通る");

        e.mem.record_conflict(a, b);
        let err = e.can_confirm(h).unwrap_err();
        assert!(err.contains("未決着の矛盾"), "{err}");
        assert!(err.contains(&a.label()) && err.contains(&b.label()), "{err}");
    }

    /// 自己申告の`confirms`がweb証拠だけで来ても`Confirmed`へ上げず、不足を記録する。
    #[tokio::test]
    async fn a_web_only_confirmation_is_downgraded_to_inconclusive() {
        let exec = PhaseExecutor::new([
            (
                Phase::Hypothesize,
                vec![hypothesize("公式ドキュメントの通りである")],
            ),
            (
                Phase::Investigate,
                vec![Reply::tool(
                    "web_fetch",
                    serde_json::json!({ "url": "https://example.com/doc" }),
                    "the shell is powershell",
                )],
            ),
            (
                Phase::Distill,
                vec![distill("ドキュメントにそう書いてある", "supports")],
            ),
            (Phase::Verify, vec![verify("confirms")]),
            (Phase::Decide, vec![decide()]),
        ]);
        // 1ラウンドで打ち切り、確証されないままDecideへ落ちることを見る。
        let (engine, outcome) = run(
            &exec,
            HivLimits {
                max_investigate_rounds: 1,
                ..HivLimits::default()
            },
        )
        .await;

        let mem = engine.memory();
        assert!(matches!(mem.evidence()[0].source, SourceRef::Web { .. }));
        let verification = &mem.verifications()[0];
        assert_eq!(verification.verdict, Verdict::Inconclusive);
        assert!(
            verification.missing.iter().any(|m| m.contains("直接観測")),
            "{:?}",
            verification.missing
        );
        assert_ne!(mem.hypotheses()[0].status, HypStatus::Confirmed);
        assert_eq!(outcome.stop, HivStop::Decided);
        assert!(
            outcome.answer.contains("確証できた仮説はない"),
            "{}",
            outcome.answer
        );
    }

    /// 決着しないモデルでも必ず有限で止まる（ラウンド・仮説・総コールの3つの上限）。
    #[tokio::test]
    async fn the_loop_terminates_even_if_nothing_is_ever_decided() {
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("よく分からない")]),
            (
                Phase::Investigate,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "content",
                )],
            ),
            (Phase::Distill, vec![distill("何か見えた", "supports")]),
            // 常にinconclusive → ラウンド上限 → 別/新しい仮説 → 仮説上限 → Decide。
            (Phase::Verify, vec![verify("inconclusive")]),
            (Phase::Decide, vec![decide()]),
        ]);
        let limits = HivLimits {
            max_phase_calls: 60,
            ..HivLimits::default()
        };
        let (engine, outcome) = run(&exec, limits).await;

        assert!(
            matches!(outcome.stop, HivStop::Decided | HivStop::BudgetExhausted),
            "{:?}",
            outcome.stop
        );
        assert!(exec.seen().len() <= 60, "{} calls", exec.seen().len());
        assert!(engine.memory().hypotheses().len() <= 3);
    }

    /// 反証された仮説は捨てられ、次の仮説が立つ（§3.2「反証/不足 → 次の仮説へ」）。
    #[tokio::test]
    async fn a_refuted_hypothesis_leads_to_a_new_one() {
        let exec = PhaseExecutor::new([
            (
                Phase::Hypothesize,
                vec![hypothesize("最初の仮説"), hypothesize("次の仮説")],
            ),
            (
                Phase::Investigate,
                vec![Reply::tool(
                    "read_file",
                    serde_json::json!({ "path": "a.rs" }),
                    "content",
                )],
            ),
            (Phase::Distill, vec![distill("観測", "supports")]),
            (Phase::Verify, vec![verify("refutes"), verify("confirms")]),
            (Phase::Decide, vec![decide()]),
        ]);
        let (engine, outcome) = run(&exec, HivLimits::default()).await;

        let mem = engine.memory();
        assert_eq!(mem.hypotheses().len(), 2);
        assert_eq!(mem.hypotheses()[0].status, HypStatus::Refuted);
        assert_eq!(mem.hypotheses()[1].status, HypStatus::Confirmed);
        assert_eq!(outcome.stop, HivStop::Decided);
        assert_eq!(exec.calls_to(Phase::Hypothesize), 2);
    }

    /// **M15の受入条件**: 反証条件（`predicts`）の無い仮説では**次のフェーズへ進まない**。
    /// 再実行しても直らなければfail-closedで止まり、理由がblockingな未解決の問いとして残る。
    #[tokio::test]
    async fn a_hypothesis_without_predicts_never_reaches_the_investigation() {
        let exec = PhaseExecutor::new([(
            Phase::Hypothesize,
            vec![Reply::Text(
                serde_json::json!({
                    "hypotheses": [{ "statement": "たぶん原因はX", "predicts": [], "confidence": 0.9 }]
                })
                .to_string(),
            )],
        )]);
        let (engine, outcome) = run(&exec, HivLimits::default()).await;

        assert_eq!(
            exec.calls_to(Phase::Investigate),
            0,
            "調査へ進んではならない"
        );
        assert_eq!(exec.calls_to(Phase::Hypothesize), 3, "1回目 + 再実行2回");
        let HivStop::Blocked { reason } = &outcome.stop else {
            panic!("expected fail-closed, got {:?}", outcome.stop);
        };
        assert!(reason.contains("predicts"), "{reason}");

        let mem = engine.memory();
        assert!(
            mem.hypotheses().is_empty(),
            "検証を通らない仮説は台帳へ入れない"
        );
        assert_eq!(mem.goals()[0].status, GoalStatus::Blocked);
        assert!(mem.open_questions()[0].blocking);
        // 回答は「確証していない」ことを明示する（でっち上げない）。
        assert!(
            outcome.answer.contains("推測を結論として返すことはしない"),
            "{}",
            outcome.answer
        );
    }

    /// キャンセルされたら台帳へ何も足さずに畳む（§3.2【T6】）。
    #[tokio::test]
    async fn cancelling_mid_phase_leaves_no_partial_evidence() {
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("X")]),
            (Phase::Investigate, vec![Reply::CancelledMidStream]),
        ]);
        let (engine, outcome) = run(&exec, HivLimits::default()).await;

        assert_eq!(outcome.stop, HivStop::Cancelled);
        assert!(outcome.answer.is_empty(), "cancel時は回答を出さない");
        assert!(engine.memory().evidence().is_empty());
        assert_eq!(engine.memory().hypotheses().len(), 1);
    }

    /// **M21**: 縮退ガードが梯子を使い切ったら fail-closed でゴールを畳む
    /// （`plans/DESIGN-COGNITION.md` §11.4）。素朴ループへ黙って降格しない。
    #[tokio::test]
    async fn a_degenerate_phase_blocks_the_goal_and_says_so() {
        let exec = PhaseExecutor::new([
            (Phase::Hypothesize, vec![hypothesize("X")]),
            (Phase::Investigate, vec![Reply::Discarded]),
        ]);
        let (engine, outcome) = run(&exec, HivLimits::default()).await;

        let HivStop::Blocked { reason } = &outcome.stop else {
            panic!("expected fail-closed, got {:?}", outcome.stop);
        };
        assert!(reason.contains("縮退"), "{reason}");
        assert!(reason.contains("short_period_repeat"), "{reason}");
        assert!(outcome.provider_error.is_none(), "プロバイダ障害ではない");

        let mem = engine.memory();
        assert_eq!(mem.goals()[0].status, GoalStatus::Blocked);
        // 何が起きたかをユーザへ返す（黙って「分かりませんでした」にしない）。
        assert!(mem.open_questions()[0].blocking);
        assert!(!outcome.answer.is_empty());
        // 未蒸留の生出力は証拠にしない（捨てたコールから何も学ばない）。
        assert!(mem.evidence().is_empty());
    }

    /// **§6.6 規則4**: 1コールが実コンテキスト窓に収まらないまま梯子を使い切ったら、
    /// fail-closedでゴールを畳み、**直し方**を返す（設定の組合せが成立していないので、
    /// ユーザが`cognition.budgets`／`compaction.context_window`で直せる）。
    #[tokio::test]
    async fn a_call_that_never_fits_the_window_blocks_the_goal_with_a_way_out() {
        // どの応答も使われない——1コールも送らずに止まるのが正しい挙動。
        let exec = PhaseExecutor::new([(Phase::Hypothesize, vec![hypothesize("X")])]);
        let (engine, outcome) = run_with_window(&exec, HivLimits::default(), 900).await;

        let HivStop::Blocked { reason } = &outcome.stop else {
            panic!("expected fail-closed, got {:?}", outcome.stop);
        };
        assert!(reason.contains("コンテキスト窓"), "{reason}");
        assert!(reason.contains("cognition.budgets"), "{reason}");
        assert!(reason.contains("context_window"), "{reason}");
        assert!(
            outcome.provider_error.is_none(),
            "プロバイダ障害ではなく構成の問題"
        );
        assert!(
            exec.seen().is_empty(),
            "収まらないと分かっているリクエストは送らない"
        );

        let mem = engine.memory();
        assert_eq!(mem.goals()[0].status, GoalStatus::Blocked);
        assert!(mem.open_questions()[0].blocking);
        assert!(!outcome.answer.is_empty(), "何が起きたかは返す");
    }

    /// プロバイダ失敗はそのまま呼び出し側へ返す（素朴ループと同じ扱い）。
    #[tokio::test]
    async fn a_provider_failure_stops_the_goal_and_is_reported() {
        let exec = PhaseExecutor::new([(Phase::Hypothesize, vec![Reply::Error])]);
        let (_, outcome) = run(&exec, HivLimits::default()).await;
        assert!(outcome.provider_error.is_some());
        assert!(matches!(outcome.stop, HivStop::Blocked { .. }));
    }

    /// テスト基盤の前提（フェーズ判別）が全フェーズで効くこと。
    #[test]
    fn each_phase_is_identifiable_from_its_system_prompt() {
        let assembler = ContextAssembler::new("m", PhaseBudgets::default());
        let ctx = ToolCtx::new(std::path::PathBuf::from("C:/ws"));
        let tools = ToolRegistry::with_builtin_tools();
        let mem = WorkingMemory::new();
        for phase in Phase::ALL {
            let call = assembler.build(phase, PhaseInput::default(), &mem, &ctx, &tools, &caps());
            assert_eq!(phase_of(&call.req), Some(phase));
        }
    }
}
