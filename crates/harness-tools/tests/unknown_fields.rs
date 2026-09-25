//! 組み込みツールの入力は**知らない項目を拒否する**（BUG-164・`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-101）。
//!
//! 余分な項目を黙って捨てる実装は、判定だけを騙す細工（使いもしない `command` を足す）を
//! 最後まで通す部品になった。ここでは各ツールについて、**素直な入力が読み込みを通ること**と
//! **余分な項目を1つ足した同じ入力が `InvalidInput` で止まること**を対で固定する
//! （拒否だけを測ると「何でも拒否する」実装でも緑になるため、`test-logic-rules`）。
//!
//! 素直な入力の側は、ツールが実際に成功するかではなく**読み込みを通ったか**
//! （serde の読み込みの誤りで終わらないか）で判定する。`run_shell` や `web_fetch` の成否は
//! 環境（シェルの有無・ネットワーク）に依るので、この性質の証拠にならない。

use harness_core::{Tool, ToolCtx, ToolError};
use harness_tools::{CanRunProgramTool, ToolRegistry};

/// 各ツールの、読み込みを通る最小の入力。
fn honest_inputs() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("read_file", serde_json::json!({ "path": "a.txt" })),
        (
            "write_file",
            serde_json::json!({ "path": "b.txt", "content": "x" }),
        ),
        (
            "edit_file",
            serde_json::json!({ "path": "a.txt", "old_string": "hello", "new_string": "bye" }),
        ),
        ("grep", serde_json::json!({ "pattern": "hello" })),
        ("glob", serde_json::json!({ "pattern": "*.txt" })),
        // 到達できない宛先。読み込みを通ったかだけを見る（成否は問わない）。
        (
            "web_fetch",
            serde_json::json!({ "url": "http://127.0.0.1:9/" }),
        ),
        (
            "run_shell",
            serde_json::json!({ "command": "echo hi", "timeout_ms": 10000 }),
        ),
        (
            "run_program",
            serde_json::json!({ "program": "harness-no-such-program", "args": [] }),
        ),
    ]
}

/// 入力の読み込み（serde）で止まったか。`InvalidInput` は宛先の検査等でも返るので、
/// 読み込みの誤りだけを serde の文言で見分ける。
fn is_deserialization_error<T>(r: &Result<T, ToolError>) -> bool {
    matches!(r, Err(ToolError::InvalidInput(m))
        if m.contains("unknown field") || m.contains("missing field") || m.contains("invalid type"))
}

/// 知らない項目を拒否したことによる `InvalidInput` か。
fn is_unknown_field_error<T>(r: &Result<T, ToolError>) -> bool {
    matches!(r, Err(ToolError::InvalidInput(m)) if m.contains("unknown field"))
}

#[tokio::test]
async fn every_builtin_tool_refuses_an_unknown_field_and_accepts_the_honest_input() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let reg = ToolRegistry::with_builtin_tools();

    let inputs = honest_inputs();
    // 組み込みツールを1つ足したら、ここに入力を足すまで落ちる（数え漏れを止める）。
    let mut listed: Vec<&str> = inputs.iter().map(|(n, _)| *n).collect();
    listed.sort_unstable();
    let mut registered: Vec<String> = reg.iter().map(|t| t.name().to_string()).collect();
    registered.sort_unstable();
    assert_eq!(
        listed, registered,
        "every builtin tool must have an honest input in this test"
    );

    for (name, honest) in inputs {
        let tool = reg.get(name).expect("listed tool must be registered");

        let r = tool.call(honest.clone(), &ctx).await;
        assert!(
            !is_deserialization_error(&r),
            "{name}: the honest input must pass deserialization, got {:?}",
            r.err()
        );

        let mut crafted = honest.clone();
        crafted
            .as_object_mut()
            .unwrap()
            .insert("command".to_string(), serde_json::json!("x"));
        // run_shell は `command` を本当に持つので、別の知らない項目で試す。
        if name == "run_shell" {
            crafted
                .as_object_mut()
                .unwrap()
                .insert("path".to_string(), serde_json::json!(".git/config"));
        }
        let r = tool.call(crafted, &ctx).await;
        assert!(
            is_unknown_field_error(&r),
            "{name}: an unknown field must be refused before anything runs, got {:?}",
            r.map(|o| o.content)
        );
    }
}

#[tokio::test]
async fn can_run_program_refuses_an_unknown_field() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let tool = CanRunProgramTool;

    let r = tool
        .call(serde_json::json!({ "program": "git" }), &ctx)
        .await;
    assert!(!is_deserialization_error(&r), "honest input: {:?}", r.err());

    let r = tool
        .call(serde_json::json!({ "program": "git", "path": "x" }), &ctx)
        .await;
    assert!(
        is_unknown_field_error(&r),
        "crafted input: {:?}",
        r.map(|o| o.content)
    );
}
