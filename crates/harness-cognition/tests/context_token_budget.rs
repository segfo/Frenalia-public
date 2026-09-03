//! M14の受入条件そのもの: **同一タスクで送信トークン量が素朴ループ比で大幅減**
//! （`docs/INDEX.md` M14行・`plans/DESIGN-COGNITION.md` §10）。
//!
//! # 何を測っているか
//!
//! 同一のタスク（大きめのファイルを4回読む調査）を2経路で流し、**プロバイダへ送られる
//! リクエスト**の入力トークン概算を突き合わせる。
//!
//! - **素朴ループ側**: `run_agent_loop`を実`MockProvider`で回し、`MockProvider`が受け取った
//!   `CompletionRequest`をJSONLで記録する。実際に送信されたものそのもの。
//! - **認知側**: 同じツール出力を`ScratchStore`へ退避し、`WorkingMemory`へ台帳として積み、
//!   `ContextAssembler`でライト5フェーズ分のリクエストを組む。
//!
//! # 測定を有利にしていないことの担保
//!
//! 認知側のEvidenceの`claim`は、**生出力をDistill予算まで頭尾切詰めしたもの**を使う。
//! 実際の蒸留コール（安価モデル）はこれより短い出力を出すので、この代用は節約量を
//! **過小評価する側**へ倒れる。つまり実測値は「少なくともこれだけは減る」の下限である。
//!
//! トークン推定器は両辺とも`harness_engine::estimate_tokens`（chars/4）で、TUI表示・
//! 予算会計と同一。日本語では過小評価になる粗い推定だが、**両辺に同じ偏りが乗る**ため
//! 相対比の主張は成立する。
//!
//! # なぜ2つのセッション長で測るか
//!
//! 1つの長さだけで「N%減った」と言うと、シナリオの規模を選べば任意の比率を作れてしまう。
//! M14が実際に解決したのは「**ツールを叩くほど送信量が増える**」という性質そのもの
//! （§0の弱点1）なので、調査ラウンド数を変えて2回測り、
//! **素朴ループは増える／認知レイヤーは増えない**ことを固定する。比率はその帰結として出す。

use harness_cognition::context::{ContextAssembler, PhaseInput};
use harness_cognition::memory::types::{Evidence, EvidenceId, SourceRef};
use harness_cognition::memory::validity::{Freshness, TrustLevel, Validity};
use harness_cognition::memory::WorkingMemory;
use harness_cognition::phase::PhaseBudgets;
use harness_cognition::ScratchStore;
use harness_core::{
    BlockKind, CompletionRequest, Phase, ProviderCapabilities, StopReason, StreamEvent, ToolCtx,
    Usage,
};
use harness_engine::{
    estimate_tokens, run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter,
    PermissionMode,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

/// 調査対象ファイル1件あたりの文字数（約6,000文字≒1,500トークン）。素朴ループでは
/// これがラウンドごとに会話履歴へ積み上がる。
const FILE_CHARS: usize = 6_000;

/// 調査ラウンド数。`SHORT`と`LONG`の2点で測り、送信量が
/// ラウンド数に**比例して増えるか（素朴ループ）／頭打ちになるか（認知レイヤー）**を見る。
///
/// `LONG`は、認知側が予算上限に達するのに十分な長さにしてある。素朴ループはここでも
/// 上限を持たずに伸び続けるので、両者の性質の違いが1回の測定で出る。
const SHORT_ROUNDS: usize = 4;
const LONG_ROUNDS: usize = 32;

fn file_names(rounds: usize) -> Vec<String> {
    (0..rounds).map(|i| format!("module_{i}.rs")).collect()
}

fn file_body(name: &str, size: usize) -> String {
    // 行番号付きで読まれるので、それらしい行構造を持たせる。
    let mut out = String::new();
    let mut line = 0;
    while out.chars().count() < size {
        line += 1;
        out.push_str(&format!(
            "// {name} line {line}: some plausible source code here\n"
        ));
    }
    out
}

fn tool_use_turn(id: &str, path: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: "read_file".to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: serde_json::json!({ "path": path }).to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

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

/// 素朴ループを実際に走らせ、プロバイダが受け取った各リクエストのトークン概算を返す。
async fn naive_loop_request_sizes(workspace: &std::path::Path, rounds: usize) -> Vec<u64> {
    let names = file_names(rounds);
    for name in &names {
        std::fs::write(workspace.join(name), file_body(name, FILE_CHARS)).unwrap();
    }

    let record_path = workspace.join(format!("requests-{rounds}.jsonl"));
    let mut turns: Vec<Vec<StreamEvent>> = names
        .iter()
        .enumerate()
        .map(|(i, name)| tool_use_turn(&format!("call_{i}"), name))
        .collect();
    turns.push(end_turn("原因はロック順序である。"));

    let provider = MockProvider::new(turns).with_request_record_path(record_path.clone());
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(workspace.to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace");
    let mut state = ConversationState::new(harness_engine::system_blocks_for(&ctx));
    state.push_user_text("テストが並列時だけ落ちる原因を調べて");

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 1_000,
            max_turns: rounds + 2,
            compaction: Default::default(),
            degeneracy: None,
        },
        None,
        None,
        |_| {},
    )
    .await
    .unwrap();

    std::fs::read_to_string(&record_path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| estimate_tokens(&serde_json::from_str::<CompletionRequest>(l).unwrap()))
        .collect()
}

fn caps() -> ProviderCapabilities {
    ProviderCapabilities {
        native_json_schema: true,
        forced_tool_choice: true,
        schema_with_thinking: true,
        schema_with_tools: true,
        prompt_caching: true,
        context_window: 128_000,
        local: false,
    }
}

/// 認知側: 同じツール出力から台帳を組み、ライト5フェーズ分のリクエストを組み立てる。
/// 戻り値は`(フェーズ, 入力トークン概算)`。
fn cognitive_request_sizes(workspace: &std::path::Path, rounds: usize) -> Vec<(Phase, u64)> {
    let scratch = ScratchStore::open(&ScratchStore::dir_for_session(
        workspace,
        &format!("session-{rounds}"),
    ))
    .unwrap();
    let assembler = ContextAssembler::new("mock", PhaseBudgets::default());
    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(workspace.to_path_buf());

    let mut mem = WorkingMemory::new();
    let goal = mem.add_goal(
        "テストが並列時だけ落ちる原因を特定する",
        vec!["原因が1つに絞れている".into()],
    );
    mem.set_unknowns(vec!["並列時のみ失敗する理由".into()]);
    let hyp = mem.add_hypothesis(
        goal,
        "原因はロック順序の不一致",
        vec!["単一スレッドでは緑になる".into()],
        0.7,
    );

    // 各ツール出力を scratch へ退避し、台帳には蒸留済みclaimとポインタだけを積む。
    let distill_budget = assembler.budget(Phase::Distill);
    let mut last_raw = String::new();
    for (i, name) in file_names(rounds).iter().enumerate() {
        let raw = file_body(name, FILE_CHARS);
        let raw_ref = scratch.put_raw(&format!("call_{i}"), &raw).unwrap();

        // 蒸留の代用: 生出力の頭を「Distillの出力予算ぶん」だけ切り出す。
        // 本物の蒸留はこれより短い（＝節約量の過小評価）。
        let claim: String = raw
            .chars()
            .take(distill_budget.max_out as usize * 4)
            .collect();
        let path = name.to_string();
        mem.add_evidence(
            move |id: EvidenceId| Evidence {
                id,
                claim,
                source: SourceRef::File {
                    path,
                    lines: (1, 100),
                },
                validity: Validity::seed(TrustLevel::High, Freshness::Fresh),
                raw_ref: Some(raw_ref),
            },
            Some((hyp, i % 2 == 0)),
        );
        last_raw = raw;
    }

    // ライト構成（Involved）: Hypothesize→Investigate→Distill→Verify→Decide（§3.3）。
    let hyp_label = hyp.label();
    let goal_label = goal.label();
    let light = [
        (Phase::Hypothesize, PhaseInput::default()),
        (
            Phase::Investigate,
            PhaseInput {
                target: Some(&hyp_label),
                ..Default::default()
            },
        ),
        (
            Phase::Distill,
            PhaseInput {
                raw_output: Some(&last_raw),
                ..Default::default()
            },
        ),
        (
            Phase::Verify,
            PhaseInput {
                target: Some(&hyp_label),
                ..Default::default()
            },
        ),
        (
            Phase::Decide,
            PhaseInput {
                goal: Some(&goal_label),
                ..Default::default()
            },
        ),
    ];

    light
        .into_iter()
        .map(|(phase, input)| {
            let call = assembler.build(phase, input, &mem, &ctx, &tools, &caps());
            (phase, call.estimated_input_tokens)
        })
        .collect()
}

struct Measurement {
    rounds: usize,
    naive: Vec<u64>,
    cognitive: Vec<(Phase, u64)>,
}

impl Measurement {
    fn naive_peak(&self) -> u64 {
        *self.naive.iter().max().expect("naive loop sent requests")
    }
    fn cognitive_peak(&self) -> u64 {
        self.cognitive.iter().map(|(_, t)| *t).max().unwrap()
    }
    fn report(&self) {
        let budgets = PhaseBudgets::default();
        println!("\n===== 調査ラウンド数 {} =====", self.rounds);
        println!("-- 素朴ループ（run_agent_loop が実際に送信したリクエスト） --");
        for (i, tokens) in self.naive.iter().enumerate() {
            println!("   turn {}: {tokens} tokens", i + 1);
        }
        println!("-- 認知レイヤー（ContextAssembler が組んだフェーズ別リクエスト） --");
        for (phase, tokens) in &self.cognitive {
            println!(
                "   {phase}: {tokens} tokens (budget max_in={})",
                budgets.get(*phase).max_in
            );
        }
        println!(
            "-- ピーク: 素朴 {} / 認知 {} （{:.1}%）",
            self.naive_peak(),
            self.cognitive_peak(),
            self.cognitive_peak() as f64 / self.naive_peak() as f64 * 100.0
        );
    }
}

async fn measure(rounds: usize) -> Measurement {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path();
    let naive = naive_loop_request_sizes(workspace, rounds).await;
    let cognitive = cognitive_request_sizes(workspace, rounds);
    Measurement {
        rounds,
        naive,
        cognitive,
    }
}

/// M14の受入条件。相対比と絶対予算の**両方**を固定する。
#[tokio::test]
async fn phase_requests_do_not_grow_with_the_session_while_the_naive_loop_does() {
    let short = measure(SHORT_ROUNDS).await;
    let long = measure(LONG_ROUNDS).await;
    short.report();
    long.report();

    let budgets = PhaseBudgets::default();

    // シナリオが期待通り動いていること（両辺が同じように壊れていても気付けるように）。
    assert_eq!(
        short.naive.len(),
        SHORT_ROUNDS + 1,
        "naive loop calls the provider once per tool round plus the final turn"
    );
    assert_eq!(long.naive.len(), LONG_ROUNDS + 1);

    // (c) 素朴ループは1セッション内で**単調増加**する。これが§0の弱点1
    //     「文脈の肥大」そのもので、M14が解決しようとしている当の性質。
    for m in [&short, &long] {
        for pair in m.naive.windows(2) {
            assert!(
                pair[1] > pair[0],
                "naive request sizes must grow monotonically: {:?}",
                m.naive
            );
        }
    }

    // (c') **素朴ループはラウンド数に比例して伸びるが、認知レイヤーは予算上限で頭打ちになる。**
    //      単一のシナリオ規模での比率と違い、これはシナリオの選び方で作れる数字ではない
    //      （認知側の上限は`PhaseBudgets`が決めており、セッション長に依存しない）。
    let naive_growth = long.naive_peak() as f64 / short.naive_peak() as f64;
    let cognitive_growth = long.cognitive_peak() as f64 / short.cognitive_peak() as f64;
    println!(
        "\n===== ラウンド数 {SHORT_ROUNDS}→{LONG_ROUNDS}（x{:.0}）での増加率: 素朴 x{naive_growth:.2} / 認知 x{cognitive_growth:.2} =====\n",
        LONG_ROUNDS as f64 / SHORT_ROUNDS as f64
    );
    // 素朴ループはラウンド数の増加（x8）に概ね比例して伸びる。
    assert!(
        naive_growth > 5.0,
        "the naive loop must grow with the session length, got x{naive_growth:.2}"
    );
    // 認知側の伸びは**劣線形**。上限（フェーズ予算）を持つので、セッションを
    // いくら伸ばしてもここは天井で止まる。
    assert!(
        cognitive_growth < naive_growth / 3.0,
        "phase requests must grow sublinearly: naive x{naive_growth:.2} vs cognitive x{cognitive_growth:.2}"
    );

    // (a) 相対比: 長いセッションでは、各フェーズが素朴ループのピークの30%以下。
    for (phase, tokens) in &long.cognitive {
        let ratio = *tokens as f64 / long.naive_peak() as f64;
        assert!(
            ratio <= 0.30,
            "{phase}: {tokens} tokens is {:.1}% of the naive peak ({}); expected <= 30%",
            ratio * 100.0,
            long.naive_peak()
        );
    }

    // (b) 絶対予算: どちらの長さでも、各フェーズが§3.3の`max_in`を超えない。
    for m in [&short, &long] {
        for (phase, tokens) in &m.cognitive {
            let max_in = u64::from(budgets.get(*phase).max_in);
            assert!(
                *tokens <= max_in,
                "rounds={}: {phase}: {tokens} tokens exceeds the phase budget max_in={max_in}",
                m.rounds
            );
        }
    }

    // 認知側が空リクエストを組んで「減った」ことにしていない。
    let cognitive_min = long.cognitive.iter().map(|(_, t)| *t).min().unwrap();
    assert!(
        cognitive_min > 100,
        "phase requests must not be empty: {cognitive_min}"
    );
}

/// 生出力は台帳ではなく scratch にあり、**リクエストの中身にも現れない**
/// （§5「生出力の退避」・§6.3「参照渡し」）。素朴ループでは全文が乗ることと対照になる。
#[tokio::test]
async fn raw_tool_output_lives_in_scratch_and_not_in_the_assembled_request() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path();

    let scratch =
        ScratchStore::open(&ScratchStore::dir_for_session(workspace, "session-probe")).unwrap();
    let raw = file_body("module_0.rs", FILE_CHARS);
    let raw_ref = scratch.put_raw("call_0", &raw).unwrap();

    // 生出力の実体はディスク上にある。
    assert_eq!(raw_ref.chars, raw.chars().count());
    assert_eq!(scratch.read_raw(&raw_ref).unwrap(), raw);

    let mut mem = WorkingMemory::new();
    let goal = mem.add_goal("原因を特定する", vec![]);
    let hyp = mem.add_hypothesis(
        goal,
        "原因はロック順序",
        vec!["単一スレッドでは緑".into()],
        0.7,
    );
    mem.add_evidence(
        move |id| Evidence {
            id,
            claim: "lockを2箇所で逆順に取得している".to_string(),
            source: SourceRef::File {
                path: "module_0.rs".to_string(),
                lines: (1, 100),
            },
            validity: Validity::seed(TrustLevel::High, Freshness::Fresh),
            raw_ref: Some(raw_ref),
        },
        Some((hyp, true)),
    );

    let assembler = ContextAssembler::new("mock", PhaseBudgets::default());
    let hyp_label = hyp.label();
    let call = assembler.build(
        Phase::Verify,
        PhaseInput {
            target: Some(&hyp_label),
            ..Default::default()
        },
        &mem,
        &ToolCtx::new(workspace.to_path_buf()),
        &ToolRegistry::with_builtin_tools(),
        &caps(),
    );

    let serialized = serde_json::to_string(&call.req).unwrap();
    assert!(
        !serialized.contains("line 120"),
        "raw tool output leaked into the assembled request"
    );
    assert!(serialized.contains("lockを2箇所で逆順に取得している"));

    // 対照: 素朴ループのリクエストには同じ生出力が丸ごと乗っている。
    let naive_sizes = naive_loop_request_sizes(workspace, SHORT_ROUNDS).await;
    assert!(
        naive_sizes.last().unwrap() > &call.estimated_input_tokens,
        "the naive loop must be the larger side of this comparison"
    );
}
