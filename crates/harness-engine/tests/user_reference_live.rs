//! ユーザーが書いた長い値を、**実物のモデルを相手に1往復**させる（D-113・D-114）。`#[ignore]`。
//!
//! # なぜ偽のプロバイダでは足りないのか
//!
//! 偽のプロバイダを使う試験（`tests/user_reference.rs`）は、**モデルが何を書いたことにするか**を
//! こちらが決めている。だから「参照の書き方を使う」も「1文字落として書き写す」も思いどおりに作れるが、
//! **実物のモデルが実際にどちらをやるか**は測れない。ここで測りたいのはその一点である。
//!
//! モデルが決まりを守るかどうかは**この機械のこのモデルでの観測**であって、保証ではない。
//! だから試験が固定するのは「どちらの道を通ったか」ではなく、**走る値がユーザーの値と一字一句同じか**だけにする。
//!
//! ```text
//!                      ┌─ モデルが {{user:1}} と書いた  ─┐
//!  ユーザーの308文字 ──┤                                 ├─→ 走る値はユーザーの値と同一
//!                      └─ モデルが書き写した（損じた）  ─┘   （前者は差し込み、後者はハーネスが直す）
//! ```
//!
//! # 走らせ方
//!
//! ローカルの LMStudio（`docs/DEV-ENVIRONMENT.md`「手動E2E用ローカルLMStudioサーバ」）を
//! 起動してから撃つ。
//!
//! ```powershell
//! $env:HARNESS_TEST_SUMMARY_LIVE_MODEL = "<ロード済みモデルのid>"   # 省略可
//! cargo test -p harness-engine --test user_reference_live -- --ignored --nocapture
//! ```
//!
//! サーバが居なければ**失敗する**——`#[ignore]`なので明示的に撃ったときしか走らず、
//! 「居ないから飛ばした」を緑にすると走っていないことが見えなくなる。
//!
//! # ここで測らないもの
//!
//! モデルが参照の書き方を**使うかどうか**は固定しない（モデルが変われば変わるし、実測では使わなかった）。
//! 符号化された中身が何であるかも見ない——測るのは**ツールへ渡る文字列**だけで、その先の解読・危険度の判定は
//! 別の試験が持つ。

use harness_core::{AgentEvent, LlmProvider, ToolCtx};
use harness_engine::{
    run_agent_loop, system_blocks_for, AgentLoopConfig, ConversationState, PermissionArbiter,
    PermissionMode,
};
use harness_tools::ToolRegistry;

/// ユーザーが実際に貼った値（2026-10-04、`<workspace>\.harness\sessions\session-*.jsonl` から写した）。
/// UTF-16LE の base64 で、解くと `pwsh --enc <さらに base64>` になる二重の形。
const USER_VALUE: &str = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAQQBCADMAQQBIAE0AQQBhAEEAQQBnAEEAQwAwAEEATABRAEIAbABBAEcANABBAFkAdwBBAGcAQQBHAE0AQQBkAHcAQgBDAEEARABVAEEAUQBRAEIASQBBAEUAMABBAFEAUQBCAGsAQQBFAEUAQQBRAGcAQgBzAEEARQBFAEEAUgB3AEEAdwBBAEUARQBBAFkAUQBCAFIAQQBFAEkAQQBkAFEAQgBCAEEARQBjAEEAVwBRAEIAQgBBAEcASQBBAGQAdwBCAEIAQQBEADAAQQA=";

async fn model() -> String {
    if let Ok(m) = std::env::var("HARNESS_TEST_SUMMARY_LIVE_MODEL") {
        return m;
    }
    // **既に読み込まれているものを選ぶ**（一覧の先頭だと、この機械では大きいモデルが先に並んでいて
    // 「読み込みに失敗した」で落ちる。測りたいのはそこではない）。
    let parsed: serde_json::Value = reqwest::get("http://localhost:1234/api/v0/models")
        .await
        .expect("LMStudio is not answering on localhost:1234 (start it first)")
        .json()
        .await
        .expect("the model list is not JSON");
    let models = parsed["data"].as_array().expect("no model list");
    models
        .iter()
        .find(|m| m["state"].as_str() == Some("loaded"))
        .or_else(|| models.first())
        .and_then(|m| m["id"].as_str())
        .expect(
            "LMStudio lists no models. Load one in LMStudio, or pass \
             HARNESS_TEST_SUMMARY_LIVE_MODEL=<id>.",
        )
        .to_string()
}

/// **実物のモデルに1往復させて、`run_shell`へ渡った行がユーザーの値を一字一句そのまま含むかを見る。**
///
/// モデルが参照の書き方（`{{user:1}}`）を使えばハーネスが差し込み、書き写せばハーネスが直す。
/// どちらを通ったかは`--nocapture`で出す（どちらでも合格だが、**どちらだったかは記録に残す**）。
#[tokio::test]
#[ignore = "requires a running LMStudio on localhost:1234"]
async fn the_command_that_reaches_the_tool_carries_the_users_value_verbatim() {
    let model = model().await;
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let tools = ToolRegistry::with_builtin_tools();
    // **何も走らせない。** 測るのはツールへ渡る文字列で、実行結果ではない。
    let arbiter = PermissionArbiter::new(PermissionMode::Deny, vec![], dir.path());
    let provider: Box<dyn LlmProvider> = Box::new(harness_providers::OpenAiProvider::lmstudio());

    let mut state = ConversationState::new(system_blocks_for(&ctx));
    state.push_user_text(format!("これを実行して pwsh --enc {USER_VALUE}"));

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let started = std::time::Instant::now();
    let outcome = run_agent_loop(
        provider.as_ref(),
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: model.clone(),
            // 書き写すと出力の上限をそれだけで使い切る（実測で`no_output_at_max_tokens`になった）。
            max_tokens: 4096,
            max_turns: 3,
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&tx),
        None,
        |_| {},
    )
    .await;
    drop(tx);
    // **ツールを全部拒否するので、モデルは諦めるまで撃ち直し、たいてい回数の上限で終わる。**
    // それは測りたいことではないので、ここでは結果を見ずに、出たイベントだけを見る
    // （何も提案されなかったときは下の assert が赤になる）。
    println!("loop: {outcome:?}");

    let mut proposed: Vec<String> = Vec::new();
    let mut transcriptions: Vec<(usize, bool)> = Vec::new();
    while let Ok(event) = rx.try_recv() {
        match event {
            AgentEvent::ToolCallProposed { name, input, .. } if name == "run_shell" => {
                if let Some(command) = input.get("command").and_then(|v| v.as_str()) {
                    proposed.push(command.to_string());
                }
            }
            AgentEvent::UserValueTranscribed {
                differences,
                refused,
                ..
            } => transcriptions.push((differences, refused)),
            _ => {}
        }
    }

    // **モデル自身が何を書いたか**は会話の記録の側にある（ハーネスの差し込みはツールへ渡る手前なので、
    // `ToolCallProposed`からは見分けられない）。**`run_shell`に限らず全部のツール呼び出しを見る**
    // ——実測ではモデルが同じ値を`run_program`へも渡しており、片方だけ数えると読めない記録になった。
    let wrote_by_model: Vec<(String, String)> = state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            harness_core::ContentBlock::ToolUse { name, input, .. } => {
                Some((name.clone(), input.to_string()))
            }
            _ => None,
        })
        .collect();
    let refused = transcriptions.iter().filter(|(_, r)| *r).count();
    println!(
        "model={model} / {:.1}s / ツール呼び出し {} 件 / run_shell が実行まで進んだ {} 件 /          書き写し {} 件（うち断った {refused} 件）",
        started.elapsed().as_secs_f32(),
        wrote_by_model.len(),
        proposed.len(),
        transcriptions.len(),
    );
    // **呼び出し1件ごとに道を出す。** 1往復の中で道が分かれることがある（実測: 1件目は損じ無し、
    // 2件目は64文字落ち）ので、先頭だけを見ると片方を取りこぼす。
    for (i, (tool, written)) in wrote_by_model.iter().enumerate() {
        let path = if written.contains(harness_core::user_reference::SYNTAX_EXAMPLE) {
            "モデルが参照の書き方を使った（ハーネスが差し込んだ）"
        } else if written.contains(USER_VALUE) {
            "モデルが書き写し、一字一句同じだった"
        } else if transcriptions.iter().any(|(d, _)| *d > 0) {
            "モデルが書き写して損じ、ハーネスが実行を断った"
        } else {
            "モデルが別のものを書いた"
        };
        println!("  {}件目（{tool}）: {path}", i + 1);
    }

    // **測りたい不変条件**: ツールまで進んだ行に、ユーザーの値の壊れた写しが1つも入っていない。
    //
    // 値を1つも含まない行（実測では、断られた後にモデルが試した `where pwsh`）は対象外である
    // ——モデルが別のことをするのは自由で、止めたいのは**壊れた写しが走ること**だけ。
    // ここで見ているのは判定そのものではなく**配線**（審査が実行より前に掛かっているか）で、
    // 判定の中身は `harness-core` の単体試験が持つ。
    let value = USER_VALUE.to_string();
    for command in &proposed {
        let damaged: Vec<_> = harness_core::user_reference::review(
            &serde_json::json!({ "command": command }),
            std::slice::from_ref(&value),
        )
        .into_iter()
        .filter(|t| !t.is_exact())
        .collect();
        assert!(
            damaged.is_empty(),
            "壊れた写しがツールまで進んだ（審査が実行より前に掛かっていない）: {damaged:?}
  {command}"
        );
    }
    // 提案も書き写しも1件も無ければ、この往復では何も測れていない（緑にしない）。
    assert!(
        !proposed.is_empty() || !transcriptions.is_empty(),
        "モデルが run_shell を1度も呼ばず、値を書き写しもしなかった。\
         指示の出し方かモデルの問題で、走る値を測れていない"
    );
}
