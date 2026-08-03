//! フェーズ別の最小コンテキスト組立。`plans/DESIGN-COGNITION.md` §6.1「Context Assembler」。
//!
//! 素朴ループの`build_request`（`harness_engine`）が`ConversationState`全体を1リクエストへ
//! 写すのに対し、ここは**そのフェーズに必要な台帳スライスとツールspecだけ**を組む。
//! これが「ターンが伸びても送信量が伸びない」ことの実体である。
//!
//! # スキーマ強制とツール呼び出しの分離
//!
//! 【T7】（`plans/DESIGN.md` §構造化出力）の通り、両者の同時可否はプロバイダ依存である。
//! 融合できないプロバイダでは、設計書の指示通り**ツール実行コール（schema無し）→
//! 結論コール（schema有り・ツール無し）**へ分割する必要があるので、組み立て結果に
//! [`CallKind`]を添えてM15の状態機械が後続コールの要否を判断できるようにする。
//!
//! なお、仮にこの分割を行わずスキーマとツールを同時に載せたリクエストを送っても、
//! `harness_core::apply_schema_strategy`がプロバイダ手前で`PromptEmbedded`へ降格させる
//! （ツールは落とさない）。設計上の分割は`CallKind`、最後の砦はアダプタ手前、の二段になる。

use harness_core::{
    CompletionRequest, ContentBlock, Message, Phase, ProviderCapabilities, Role, Sampling,
    SystemBlock, TokenBudget, ToolChoice, ToolCtx, ToolSpec,
};
use harness_tools::ToolRegistry;

use crate::memory::render::Reduction;
use crate::memory::types::{GoalId, HypId};
use crate::memory::WorkingMemory;
use crate::phase::{spec, PhaseBudgets, ToolSelection};
use crate::{prompts, schema};

/// 台帳スライス・生出力をこれ以上は削らない下限（文字数）。ここまで削っても予算に
/// 収まらない構成は、固定費（システムプロンプト+ツールspec）自体が予算を超えている。
const MIN_BODY_CHARS: usize = 200;

/// 縮約ループの上限。幾何級数で減るので実際はこれよりずっと早く止まるが、
/// 予算が異常値（0等）でも必ず停止することを型の外側で保証する。
const MAX_SHRINK_STEPS: usize = 32;

/// このコールがスキーマ強制なのかツール実行なのか（【T7】のコール分割）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// スキーマ強制のみ（ツールを渡さない解釈コール）。
    SchemaOnly,
    /// ツールを渡し、スキーマは要求しない。結論はこの後の別コールで取る。
    ToolsOnly,
    /// スキーマとツールを同時に載せた1コール（`schema_with_tools`なプロバイダのみ）。
    Fused,
}

/// 組み立て結果。
#[derive(Debug, Clone)]
pub struct AssembledCall {
    pub req: CompletionRequest,
    pub kind: CallKind,
    /// `harness_engine::estimate_tokens`による入力トークン概算（TUI表示と同じ推定器）。
    /// 予算超過の判定は呼び出し側が`budget.max_in`と比べて行う。
    pub estimated_input_tokens: u64,
}

/// 何を組むか。
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseInput<'a> {
    /// 対象仮説（Investigate/Verify/Critic）。
    pub target: Option<HypId>,
    /// 対象ゴール（Decide）。
    pub goal: Option<GoalId>,
    /// Distillへ注入する生出力（`ScratchStore::zoom`で読み出したもの）。
    /// 台帳には入っていないので、必要なフェーズだけがここで明示的に運ぶ。
    pub raw_output: Option<&'a str>,
}

/// フェーズ別最小コンテキストの組立器。
#[derive(Debug, Clone)]
pub struct ContextAssembler {
    model: String,
    budgets: PhaseBudgets,
}

impl ContextAssembler {
    /// `model`はこの組立器が出す全リクエストのモデルid。フェーズ×難易度でのモデル
    /// 差し替え（§6.4 `ModelRouter`）はM17で、そこがフェーズごとに別の組立器を使う。
    pub fn new(model: impl Into<String>, budgets: PhaseBudgets) -> Self {
        Self {
            model: model.into(),
            budgets,
        }
    }

    pub fn budget(&self, phase: Phase) -> TokenBudget {
        self.budgets.get(phase)
    }

    /// 1フェーズ分のリクエストを組む。**失敗しない**——予算に収まらない場合も、
    /// 縮約できるところまで縮約したリクエストを返す（`estimated_input_tokens`で
    /// 超過が分かる）。組み立てが例外を返すと、状態機械がそこで止まってしまうため。
    pub fn build(
        &self,
        phase: Phase,
        input: PhaseInput<'_>,
        mem: &WorkingMemory,
        ctx: &ToolCtx,
        tools: &ToolRegistry,
        caps: &ProviderCapabilities,
    ) -> AssembledCall {
        let budget = self.budgets.get(phase);
        let spec = spec(phase, input.target, input.goal);
        let tool_specs = select_tools(tools, ctx, spec.tools);
        let kind = call_kind(spec.wants_schema, !tool_specs.is_empty(), caps);

        let system = self.system_blocks(phase, ctx, !tool_specs.is_empty());
        let raw = input.raw_output.unwrap_or("");

        // 1段目: 台帳スライスの構造的な縮約（決定的な順序、§6.1）。
        let mut slice = String::new();
        for reduction in Reduction::LEVELS {
            slice = mem.render(spec.view, reduction);
            let req = self.request(&system, &tool_specs, &slice, raw, kind, phase, budget);
            if harness_engine::estimate_tokens(&req) <= u64::from(budget.max_in) {
                return finish(req, kind);
            }
        }

        // 2段目: 生出力の機械的な切詰め（§6.2「まず機械的に切詰め → 蒸留で意味的に抽出」）。
        // スライスより先に削るのは、構造的縮約を通り抜けた後で残っている嵩の主因が
        // 生出力だから（Distillフェーズでは台帳スライス自体が空である）。
        let mut raw_owned = raw.to_string();
        let mut steps = 0;
        while raw_owned.chars().count() > MIN_BODY_CHARS && steps < MAX_SHRINK_STEPS {
            raw_owned = shrink(&raw_owned);
            steps += 1;
            let req = self.request(
                &system,
                &tool_specs,
                &slice,
                &raw_owned,
                kind,
                phase,
                budget,
            );
            if harness_engine::estimate_tokens(&req) <= u64::from(budget.max_in) {
                return finish(req, kind);
            }
        }

        // 3段目: 台帳スライス自体の切詰め（構造を保てなくなるので最後）。
        let mut steps = 0;
        while slice.chars().count() > MIN_BODY_CHARS && steps < MAX_SHRINK_STEPS {
            slice = shrink(&slice);
            steps += 1;
            let req = self.request(
                &system,
                &tool_specs,
                &slice,
                &raw_owned,
                kind,
                phase,
                budget,
            );
            if harness_engine::estimate_tokens(&req) <= u64::from(budget.max_in) {
                return finish(req, kind);
            }
        }

        // ここまで来たら固定費（システムプロンプト + ツールspec）が予算を超えている。
        // 削れるものが無いので、そのまま返して超過を`estimated_input_tokens`で見せる。
        let req = self.request(
            &system,
            &tool_specs,
            &slice,
            &raw_owned,
            kind,
            phase,
            budget,
        );
        finish(req, kind)
    }

    /// systemは「フェーズ役割」+「環境事実（ツールを渡すときだけ）」の最大2枚。
    ///
    /// **ツールを渡すフェーズには`EnvironmentFacts`のレンダリングを必ず載せる。**
    /// モデルに見える制約（シェル隔離Tier・staging mode・read scope・network policy）の
    /// 宣言点は`harness_core::prompt`ただ1つ、というのがこのリポジトリの規約
    /// （`CLAUDE.md`、発端は`docs/bugs/BUG-030.md`のシステムプロンプト未送信）。認知
    /// レイヤーがそこを迂回した小さいプロンプトを組むと、同じ欠陥を別経路で再発させる。
    /// 逆にツールを渡さない解釈コールでは、モデルに実行手段が無いので環境事実は載せない
    /// （§6.1「そのフェーズで使うものだけ」）。
    fn system_blocks(&self, phase: Phase, ctx: &ToolCtx, has_tools: bool) -> Vec<SystemBlock> {
        let mut blocks = vec![SystemBlock {
            text: prompts::system_prompt(phase).to_string(),
            cache: true,
        }];
        if has_tools {
            blocks.extend(harness_engine::system_blocks_for(ctx));
        }
        blocks
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        system: &[SystemBlock],
        tools: &[ToolSpec],
        slice: &str,
        raw: &str,
        kind: CallKind,
        phase: Phase,
        budget: TokenBudget,
    ) -> CompletionRequest {
        CompletionRequest {
            system: system.to_vec(),
            // §6.5: 毎コール変動する台帳スライスは、安定プレフィックス（system + tools）の
            // **後ろ**に置く。プレフィックスを汚さないことでprompt cachingが効く余地を残す。
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text(body(slice, raw))],
            }],
            tools: tools.to_vec(),
            tool_choice: if tools.is_empty() {
                ToolChoice::None
            } else {
                ToolChoice::Auto
            },
            output: match kind {
                CallKind::SchemaOnly | CallKind::Fused => Some(schema::output_contract(phase)),
                // 【T7】の分割: このコールはツール実行専用で、結論は次のコールで取る。
                CallKind::ToolsOnly => None,
            },
            // 素朴ループと同じ理由（`harness_engine::build_request`のPhase5-D注記）で
            // 並列tool_callを抑止する。
            parallel_tool_calls: Some(false),
            max_tokens: budget.max_out,
            sampling: Sampling::default(),
            model: self.model.clone(),
        }
    }
}

fn finish(req: CompletionRequest, kind: CallKind) -> AssembledCall {
    let estimated_input_tokens = harness_engine::estimate_tokens(&req);
    AssembledCall {
        req,
        kind,
        estimated_input_tokens,
    }
}

fn call_kind(wants_schema: bool, has_tools: bool, caps: &ProviderCapabilities) -> CallKind {
    match (wants_schema, has_tools) {
        (true, false) => CallKind::SchemaOnly,
        (false, _) => CallKind::ToolsOnly,
        (true, true) => {
            if caps.schema_with_tools {
                CallKind::Fused
            } else {
                CallKind::ToolsOnly
            }
        }
    }
}

/// そのフェーズの候補集合に入るツールのspecだけを返す（§6.1「そのフェーズで使うツールの
/// spec だけ」）。
///
/// 分類には`Tool::risk`へ空の入力を渡した値を使う。組み込みツールはいずれも入力に
/// 依存せず静的な`RiskClass`を返すため、これが実質的な静的分類になる。**ここは候補集合を
/// 絞るだけ**で、実行時の許可判定は具体的な入力を見る`PermissionArbiter`が引き続き行う。
fn select_tools(tools: &ToolRegistry, ctx: &ToolCtx, selection: ToolSelection) -> Vec<ToolSpec> {
    if selection == ToolSelection::None {
        return Vec::new();
    }
    let empty = serde_json::Value::Object(Default::default());
    let mut specs: Vec<ToolSpec> = tools
        .iter()
        .filter(|tool| selection.admits(tool.risk(&empty)))
        .map(|tool| tool.spec_for_ctx(ctx))
        .collect();
    // `ToolRegistry`はHashMap実装なので反復順が不定。リクエストを決定的にするために
    // 名前で並べる（golden test・prompt cachingの安定プレフィックスの両方に効く）。
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    specs
}

fn body(slice: &str, raw: &str) -> String {
    let mut out = String::new();
    if !slice.trim().is_empty() {
        out.push_str(slice);
    }
    if !raw.trim().is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("## ツール出力（生）\n\n```\n");
        out.push_str(raw);
        out.push_str("\n```\n");
    }
    if out.trim().is_empty() {
        // 空のuserメッセージはプロバイダによっては400になる。
        out.push_str("（作業記憶は空である。）");
    }
    out
}

/// 3/4ずつ削る（頭尾を残して中間を省略）。幾何級数なので必ず`MIN_BODY_CHARS`へ収束する。
fn shrink(text: &str) -> String {
    let target = text.chars().count() * 3 / 4;
    truncate_head_tail(text, target.max(MIN_BODY_CHARS))
}

fn truncate_head_tail(content: &str, max_chars: usize) -> String {
    let total = content.chars().count();
    if total <= max_chars {
        return content.to_string();
    }
    let half = max_chars / 2;
    let head: String = content.chars().take(half).collect();
    let tail: String = content.chars().skip(total - half).collect();
    let omitted = total - 2 * half;
    format!("{head}\n... [{omitted} chars truncated] ...\n{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{Evidence, EvidenceId, RawRef, SourceRef};

    fn caps(schema_with_tools: bool) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: true,
            forced_tool_choice: true,
            schema_with_thinking: true,
            schema_with_tools,
            prompt_caching: true,
            context_window: 128_000,
        }
    }

    fn assembler() -> ContextAssembler {
        ContextAssembler::new("test-model", PhaseBudgets::default())
    }

    fn memory() -> (WorkingMemory, HypId, GoalId) {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("テストの失敗を直す", vec!["cargo testが緑".into()]);
        let h = mem.add_hypothesis(
            g,
            "原因はロック順序",
            vec!["単一スレッドでは緑".into()],
            0.7,
        );
        mem.add_evidence(
            move |id| Evidence {
                id,
                claim: "2箇所で逆順にlockを取得している".to_string(),
                source: SourceRef::File {
                    path: "src/lib.rs".to_string(),
                    lines: (40, 52),
                },
                raw_ref: Some(RawRef {
                    tool_call_id: "call_1".to_string(),
                    chars: 9_000,
                }),
            },
            Some((h, true)),
        );
        (mem, h, g)
    }

    fn ctx() -> ToolCtx {
        ToolCtx::new(std::path::PathBuf::from("C:/ws"))
    }

    fn build(phase: Phase, input: PhaseInput<'_>) -> AssembledCall {
        let (mem, _, _) = memory();
        assembler().build(
            phase,
            input,
            &mem,
            &ctx(),
            &ToolRegistry::with_builtin_tools(),
            &caps(true),
        )
    }

    /// 会話履歴を一切載せないこと（これがM14の存在理由そのもの）。
    #[test]
    fn assembled_request_carries_a_ledger_slice_not_a_transcript() {
        let (mem, hyp, _) = memory();
        let call = assembler().build(
            Phase::Verify,
            PhaseInput {
                target: Some(hyp),
                ..Default::default()
            },
            &mem,
            &ctx(),
            &ToolRegistry::with_builtin_tools(),
            &caps(true),
        );
        assert_eq!(
            call.req.messages.len(),
            1,
            "exactly one ledger-slice message"
        );
        assert_eq!(call.req.messages[0].role, Role::User);
        let ContentBlock::Text(text) = &call.req.messages[0].content[0] else {
            panic!("ledger slice must be a text block");
        };
        assert!(text.contains("原因はロック順序"), "{text}");
        assert!(text.contains("2箇所で逆順にlockを取得している"), "{text}");
    }

    /// §7.3: Investigateにはread-onlyツールのspecだけが載る。
    #[test]
    fn investigate_receives_read_only_tool_specs_only() {
        let (_, hyp, _) = memory();
        let call = build(
            Phase::Investigate,
            PhaseInput {
                target: Some(hyp),
                ..Default::default()
            },
        );
        let names: Vec<&str> = call.req.tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"read_file"), "{names:?}");
        assert!(names.contains(&"grep"), "{names:?}");
        assert!(!names.contains(&"write_file"), "{names:?}");
        assert!(!names.contains(&"run_shell"), "{names:?}");
    }

    /// 解釈フェーズはツール定義を1つも送らない（§6.1「全ツール定義は渡さない」）。
    #[test]
    fn interpretation_phases_send_no_tool_specs() {
        for phase in [
            Phase::Orient,
            Phase::Hypothesize,
            Phase::Distill,
            Phase::Critic,
        ] {
            let call = build(phase, PhaseInput::default());
            assert!(call.req.tools.is_empty(), "{phase} sent tool specs");
            assert_eq!(call.req.tool_choice, ToolChoice::None);
            assert_eq!(call.kind, CallKind::SchemaOnly);
        }
    }

    /// ツールspecの順序は決定的（`ToolRegistry`のHashMap反復順に依存しない）。
    #[test]
    fn tool_specs_are_ordered_deterministically() {
        let (_, hyp, _) = memory();
        let first = build(
            Phase::Investigate,
            PhaseInput {
                target: Some(hyp),
                ..Default::default()
            },
        );
        let second = build(
            Phase::Investigate,
            PhaseInput {
                target: Some(hyp),
                ..Default::default()
            },
        );
        assert_eq!(first.req.tools, second.req.tools);
        let names: Vec<&str> = first.req.tools.iter().map(|t| t.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    /// **BUG-030型の再発防止**: ツールを渡すフェーズには環境事実が必ず載る。
    #[test]
    fn tool_bearing_phases_include_the_environment_facts_declaration() {
        let (_, hyp, goal) = memory();
        for (phase, input) in [
            (
                Phase::Investigate,
                PhaseInput {
                    target: Some(hyp),
                    ..Default::default()
                },
            ),
            (
                Phase::Decide,
                PhaseInput {
                    goal: Some(goal),
                    ..Default::default()
                },
            ),
        ] {
            let call = build(phase, input);
            assert!(!call.req.tools.is_empty(), "{phase}");
            let system: String = call.req.system.iter().map(|s| s.text.clone()).collect();
            assert!(
                system.contains("ワークスペースルート"),
                "{phase}: environment facts missing from system prompt"
            );
        }
    }

    /// ツールを渡さないフェーズには環境事実を載せない（実行手段が無いので不要）。
    #[test]
    fn interpretation_phases_omit_the_environment_facts() {
        let call = build(Phase::Hypothesize, PhaseInput::default());
        assert_eq!(call.req.system.len(), 1);
        assert!(!call.req.system[0].text.contains("ワークスペースルート"));
    }

    /// 【T7】: 融合できるプロバイダでは1コール、できないプロバイダではツール実行コールへ
    /// 分割する（結論は次のコールで取る＝M15が`CallKind`を見て判断する）。
    #[test]
    fn schema_and_tools_are_split_when_the_provider_cannot_combine_them() {
        let (mem, hyp, _) = memory();
        let input = PhaseInput {
            target: Some(hyp),
            ..Default::default()
        };
        let tools = ToolRegistry::with_builtin_tools();

        let fused = assembler().build(Phase::Investigate, input, &mem, &ctx(), &tools, &caps(true));
        assert_eq!(fused.kind, CallKind::Fused);
        assert!(fused.req.output.is_some());
        assert!(!fused.req.tools.is_empty());

        let split = assembler().build(
            Phase::Investigate,
            input,
            &mem,
            &ctx(),
            &tools,
            &caps(false),
        );
        assert_eq!(split.kind, CallKind::ToolsOnly);
        // ツールは残し、スキーマ側を次のコールへ回す（ツールを落とすと調査できなくなる）。
        assert!(split.req.output.is_none());
        assert!(!split.req.tools.is_empty());
    }

    /// 出力スキーマとフェーズが対応していること。
    #[test]
    fn each_phase_requests_its_own_output_schema() {
        for phase in [
            Phase::Orient,
            Phase::Hypothesize,
            Phase::Distill,
            Phase::Critic,
        ] {
            let call = build(phase, PhaseInput::default());
            let Some(harness_core::OutputContract::JsonSchema { name, .. }) = &call.req.output
            else {
                panic!("{phase} must request a schema");
            };
            assert_eq!(*name, format!("{}_output", phase.as_str()));
        }
    }

    /// `max_tokens`はフェーズ予算の`max_out`（§3.3の表）。
    #[test]
    fn max_tokens_comes_from_the_phase_budget() {
        assert_eq!(
            build(Phase::Hypothesize, PhaseInput::default())
                .req
                .max_tokens,
            1_000
        );
        assert_eq!(
            build(Phase::Distill, PhaseInput::default()).req.max_tokens,
            500
        );
    }

    /// Distillは台帳ではなく生出力を見る（§3.3）。生出力は台帳に無いので、
    /// 呼び出し側がscratchから読んで明示的に渡す経路になっている。
    #[test]
    fn distill_receives_the_raw_output_and_no_ledger_slice() {
        let call = build(
            Phase::Distill,
            PhaseInput {
                raw_output: Some("line A\nline B"),
                ..Default::default()
            },
        );
        let ContentBlock::Text(text) = &call.req.messages[0].content[0] else {
            panic!()
        };
        assert!(text.contains("line A"), "{text}");
        // 台帳スライスは載らない。
        assert!(!text.contains("原因はロック順序"), "{text}");
    }

    /// **予算の担保**: 巨大な生出力を渡しても、組み立て結果は予算内に収まる。
    #[test]
    fn oversized_raw_output_is_shrunk_until_it_fits_the_budget() {
        let huge = "x".repeat(400_000);
        let call = build(
            Phase::Distill,
            PhaseInput {
                raw_output: Some(&huge),
                ..Default::default()
            },
        );
        let budget = assembler().budget(Phase::Distill);
        assert!(
            call.estimated_input_tokens <= u64::from(budget.max_in),
            "{} > {}",
            call.estimated_input_tokens,
            budget.max_in
        );
    }

    /// **予算の担保**: 巨大な台帳（仮説50本・証拠200件）でも予算内に収まる。
    #[test]
    fn oversized_ledger_is_reduced_until_it_fits_the_budget() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("大きなゴール", vec!["条件".repeat(50)]);
        let mut first = None;
        for i in 0..50 {
            let h = mem.add_hypothesis(
                g,
                format!("仮説{i}: {}", "詳細な説明".repeat(30)),
                vec!["反証条件".repeat(20)],
                0.5,
            );
            first.get_or_insert(h);
            for j in 0..4 {
                mem.add_evidence(
                    move |id| Evidence {
                        id,
                        claim: format!("証拠{i}-{j}: {}", "長い主張".repeat(40)),
                        source: SourceRef::File {
                            path: format!("src/file{i}.rs"),
                            lines: (1, 100),
                        },
                        raw_ref: None,
                    },
                    Some((h, j % 2 == 0)),
                );
            }
        }

        let a = assembler();
        for phase in Phase::ALL {
            let call = a.build(
                phase,
                PhaseInput {
                    target: first,
                    goal: Some(g),
                    ..Default::default()
                },
                &mem,
                &ctx(),
                &ToolRegistry::with_builtin_tools(),
                &caps(true),
            );
            let budget = a.budget(phase);
            assert!(
                call.estimated_input_tokens <= u64::from(budget.max_in),
                "{phase}: {} > {}",
                call.estimated_input_tokens,
                budget.max_in
            );
        }
    }

    /// 縮約は決定的（同じ台帳からは毎回同じリクエストが出る）。
    #[test]
    fn shrinking_is_deterministic() {
        let huge = "y".repeat(200_000);
        let a = build(
            Phase::Distill,
            PhaseInput {
                raw_output: Some(&huge),
                ..Default::default()
            },
        );
        let b = build(
            Phase::Distill,
            PhaseInput {
                raw_output: Some(&huge),
                ..Default::default()
            },
        );
        assert_eq!(a.req, b.req);
    }

    /// 空の台帳でも空メッセージを送らない（プロバイダによっては400になる）。
    #[test]
    fn empty_memory_still_produces_a_non_empty_message() {
        let mem = WorkingMemory::new();
        let call = assembler().build(
            Phase::Orient,
            PhaseInput::default(),
            &mem,
            &ctx(),
            &ToolRegistry::with_builtin_tools(),
            &caps(true),
        );
        let ContentBlock::Text(text) = &call.req.messages[0].content[0] else {
            panic!()
        };
        assert!(!text.trim().is_empty());
    }

    /// 対象仮説が指定されていなくても組み立ては失敗しない（状態機械を止めない）。
    #[test]
    fn missing_target_does_not_fail_the_assembly() {
        let call = build(Phase::Verify, PhaseInput::default());
        assert_eq!(call.kind, CallKind::Fused);
        assert!(!call.req.messages.is_empty());
    }

    /// `EvidenceId`が未使用にならないための型チェック用（レンダリング側の契約は
    /// `memory::render`のテストが持つ）。
    #[test]
    fn evidence_ids_are_addressable() {
        let (mem, hyp, _) = memory();
        let id: EvidenceId = mem.hypothesis(hyp).unwrap().supporting[0];
        assert!(mem.evidence_by_id(id).is_some());
    }
}
