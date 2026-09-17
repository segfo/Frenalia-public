//! [段階6e] `can_run_program`のテスト。
//!
//! **Win32もETWも触らないので昇格は要らない。** ここで固定するのは、モデルが受け取る文面の
//! うち**判断を変えるもの**だけである——強制が効いていないときの答え・起こせない辺の印・
//! 残りがあることの告知・パターンをそのまま打てる名前と誤読させないこと。

use super::*;

use harness_core::TransitionFacts;
use std::sync::Arc;

fn program(exe: &str, runnable_now: bool) -> RunnableProgramFact {
    RunnableProgramFact {
        exe: exe.to_string(),
        exe_is_pattern: false,
        argv: harness_policy::transition_listing::ANY_ARGV.to_string(),
        argv_is_pattern: false,
        to_domain: "workspace-shell".to_string(),
        rights_fs: Vec::new(),
        rights_net: Vec::new(),
        runnable_now,
    }
}

fn ctx_with(programs: Vec<RunnableProgramFact>) -> ToolCtx {
    let mut ctx = ToolCtx::new(std::path::PathBuf::from("C:/ws"));
    ctx.transition_facts = Some(Arc::new(TransitionFacts {
        from_domain: "workspace-shell".to_string(),
        programs,
    }));
    ctx
}

async fn call(ctx: &ToolCtx, input: serde_json::Value) -> String {
    CanRunProgramTool
        .call(input, ctx)
        .await
        .expect("読み取りのみのツールは失敗しない")
        .content
}

/// **強制が効いていない構成では、空一覧ではなくその事実を答える**（`B-10`）。
///
/// 空を返すと、モデルは「何も起こせない」と読んで**存在しない制約に合わせて動く**。
#[tokio::test]
async fn it_says_the_mechanism_is_off_instead_of_returning_an_empty_list() {
    let ctx = ToolCtx::new(std::path::PathBuf::from("C:/ws"));
    assert!(ctx.transition_facts.is_none());

    let out = call(&ctx, serde_json::json!({})).await;

    assert!(out.contains("有効になっていません"), "{out}");
    assert!(
        !out.contains("ありません。"),
        "「起こせるものが無い」と読める文面になっている: {out}"
    );
}

/// **対の側**（`B-35`）: 強制が効いていて宣言が0本なら、「無い」と答える。
///
/// 上のテストだけだと「常に『無効です』と答える」実装でも緑になる。
#[tokio::test]
async fn an_enforced_session_with_no_declarations_says_there_are_none() {
    let out = call(&ctx_with(Vec::new()), serde_json::json!({})).await;
    assert!(out.contains("ありません"), "{out}");
    assert!(!out.contains("有効になっていません"), "{out}");
}

/// 名前で引くと、その行が出る。引数なしなら一覧になる。
#[tokio::test]
async fn a_name_query_finds_the_declared_program() {
    let ctx = ctx_with(vec![
        program(r"C:\bin\git.exe", true),
        program(r"C:\bin\cargo.exe", true),
    ]);

    let hit = call(&ctx, serde_json::json!({"program": "git"})).await;
    assert!(hit.contains(r"C:\bin\git.exe"), "{hit}");
    assert!(!hit.contains("cargo.exe"), "絞り込みが効いていない: {hit}");

    let all = call(&ctx, serde_json::json!({})).await;
    assert!(all.contains("git.exe") && all.contains("cargo.exe"), "{all}");
}

/// 一致しないときは「無い」と答え、**一覧の引き方を教える**。
#[tokio::test]
async fn a_query_with_no_match_points_back_to_the_listing() {
    let ctx = ctx_with(vec![program(r"C:\bin\git.exe", true)]);
    let out = call(&ctx, serde_json::json!({"program": "svn"})).await;

    assert!(out.contains("一致するものはありません"), "{out}");
    assert!(out.contains("引数なし"), "次の一手を書いていない: {out}");
}

/// **【暫定】起こせない辺には、その旨がはっきり出る**
/// （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の撤去一覧5点目）。
///
/// 出さないと、一覧に出ているのに撃つと拒否される——**モデルから見て最も分かりにくい形**になる。
/// §22.9が着地したらこのテストごと消す（暫定が残っていることを固定するためだけに在る）。
#[tokio::test]
async fn a_program_that_cannot_be_started_yet_says_so() {
    let ctx = ctx_with(vec![program(r"C:\bin\node.exe", false)]);
    let out = call(&ctx, serde_json::json!({})).await;

    assert!(
        out.contains("いまは起こせません"),
        "起こせない辺が起こせるものとして並んでいる: {out}"
    );
}

/// 権限の要約は**中身を出す**（件数ではない）。
#[tokio::test]
async fn the_rights_summary_names_what_becomes_usable() {
    let mut p = program(r"C:\bin\git.exe", true);
    p.rights_fs = vec![(r"C:\ws".to_string(), "read_write".to_string())];
    p.rights_net = vec!["github.com".to_string()];
    let out = call(&ctx_with(vec![p]), serde_json::json!({})).await;

    assert!(out.contains(r"C:\ws(read_write)"), "{out}");
    assert!(out.contains("github.com"), "{out}");
}

/// **パターンの辺を「そのまま打てる名前」と誤読させない。**
#[tokio::test]
async fn a_pattern_edge_is_labelled_as_a_pattern() {
    let mut p = program(r"C:\\tools\\.*\.exe", true);
    p.exe_is_pattern = true;
    let out = call(&ctx_with(vec![p]), serde_json::json!({})).await;

    assert!(out.contains("パターン"), "{out}");
}

/// ページングと、**残りがあることの告知**（既存の`[output truncated]`の作法）。
#[tokio::test]
async fn paging_tells_how_to_get_the_rest() {
    let programs: Vec<RunnableProgramFact> = (0..25)
        .map(|i| program(&format!(r"C:\bin\p{i}.exe"), true))
        .collect();
    let ctx = ctx_with(programs);

    let first = call(&ctx, serde_json::json!({"limit": 10})).await;
    assert!(first.contains("[output truncated]"), "{first}");
    assert!(first.contains("offset=10"), "続きの引き方が無い: {first}");
    assert_eq!(
        first.matches(".exe").count(),
        10,
        "limitが効いていない: {first}"
    );

    let second = call(&ctx, serde_json::json!({"offset": 10, "limit": 10})).await;
    assert!(second.contains("p10.exe"), "{second}");
    assert!(!second.contains("p9.exe "), "{second}");

    // 最後のページでは打ち切りの告知を出さない（残りが無いのに「続きがある」と言わない）。
    let last = call(&ctx, serde_json::json!({"offset": 20, "limit": 10})).await;
    assert!(!last.contains("[output truncated]"), "{last}");
}

/// 一度に返す件数には上限がある（宣言が増えたときに1回の応答が破裂しないため）。
#[tokio::test]
async fn the_page_size_is_capped() {
    let programs: Vec<RunnableProgramFact> = (0..200)
        .map(|i| program(&format!(r"C:\bin\p{i}.exe"), true))
        .collect();
    let out = call(&ctx_with(programs), serde_json::json!({"limit": 1000})).await;

    assert_eq!(out.matches(".exe").count(), 100, "上限が効いていない");
    assert!(out.contains("[output truncated]"), "{out}");
}

/// **書き込み口を持たない**（D-42: ポリシーの変更は常にユーザーの明示操作）。
#[test]
fn the_tool_declares_itself_read_only() {
    assert_eq!(
        CanRunProgramTool.risk(&serde_json::json!({})),
        RiskClass::ReadOnly
    );
    let schema = CanRunProgramTool.input_schema();
    let properties = schema["properties"].as_object().expect("object");
    // **順序ではなく集合で見る**（JSONのキーは整列されるので、順序で固定すると
    // 何も足していないのに赤くなる）。見たいのは「書き込みの口が増えていないこと」である。
    let mut keys: Vec<&str> = properties.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["limit", "offset", "program"],
        "入力に書き込みの口が増えている"
    );
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
}
