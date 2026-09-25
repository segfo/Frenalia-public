//! 組み込みツールが返す判定の材料（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.1・D-101）。
//!
//! 判定器は材料の**変種**で判定を掛ける（設定注入パスの拒否は `WritePath`、T-09 は `Command`、
//! インタプリタは `Program`）。**書くツールが `WritePath` 以外を返すと、設定注入パスの拒否が
//! 掛からなくなる**——これは型では守れないので、組み込みツール全件の変種を表で固定する。
//! 組み込みツールを足すと、この表に載せるまで落ちる。

use harness_core::{CommandSubject, PermissionSubject, ProgramSubject, ToolCtx, ToolError};
use harness_tools::ToolRegistry;

fn ctx() -> (tempfile::TempDir, ToolCtx) {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    (dir, ctx)
}

async fn subject_of(name: &str, input: serde_json::Value) -> Result<PermissionSubject, ToolError> {
    let (_dir, ctx) = ctx();
    let reg = ToolRegistry::with_builtin_tools();
    let tool = reg.get(name).expect("builtin tool");
    tool.permission_subject(&input, &ctx).await
}

#[tokio::test]
async fn every_builtin_tool_returns_the_expected_kind_of_subject() {
    let table: Vec<(&str, serde_json::Value, PermissionSubject)> = vec![
        (
            "read_file",
            serde_json::json!({ "path": "a.txt" }),
            PermissionSubject::Text("a.txt".into()),
        ),
        (
            "write_file",
            serde_json::json!({ "path": "b.txt", "content": "x" }),
            PermissionSubject::WritePath("b.txt".into()),
        ),
        (
            "edit_file",
            serde_json::json!({ "path": "c.txt", "old_string": "a", "new_string": "b" }),
            PermissionSubject::WritePath("c.txt".into()),
        ),
        (
            "grep",
            serde_json::json!({ "pattern": "x", "path": "src" }),
            PermissionSubject::Text("src".into()),
        ),
        (
            "glob",
            serde_json::json!({ "pattern": "*.rs" }),
            PermissionSubject::Text(".".into()),
        ),
        (
            "web_fetch",
            serde_json::json!({ "url": "https://docs.rs/serde" }),
            PermissionSubject::Text("https://docs.rs/serde".into()),
        ),
        (
            "run_shell",
            serde_json::json!({ "command": "git status" }),
            PermissionSubject::Command(CommandSubject {
                line: "git status".into(),
            }),
        ),
        (
            "run_program",
            serde_json::json!({ "program": "git", "args": ["log", "-n", "5"], "cwd": "sub" }),
            PermissionSubject::Program(ProgramSubject {
                program: "git".into(),
                args: vec!["log".into(), "-n".into(), "5".into()],
            }),
        ),
    ];

    let reg = ToolRegistry::with_builtin_tools();
    let mut listed: Vec<&str> = table.iter().map(|(n, _, _)| *n).collect();
    listed.sort_unstable();
    let mut registered: Vec<String> = reg.iter().map(|t| t.name().to_string()).collect();
    registered.sort_unstable();
    assert_eq!(listed, registered, "every builtin tool must be listed here");

    for (name, input, expected) in table {
        assert_eq!(subject_of(name, input).await.unwrap(), expected, "{name}");
    }
}

/// 書込先は書込口と同じ関数で正規化する（区切りは `/`、`./` は剥がす）。書込口が拒否する綴りは
/// 材料の段階で `InvalidInput` になり、判定にも実行にも進まない。絶対パスはそのまま渡す。
#[tokio::test]
async fn write_paths_are_normalized_like_the_write_itself() {
    for (path, expected) in [
        ("./src/main.rs", "src/main.rs"),
        (r"src\main.rs", "src/main.rs"),
        ("src/./main.rs", "src/main.rs"),
    ] {
        let s = subject_of(
            "write_file",
            serde_json::json!({ "path": path, "content": "x" }),
        )
        .await
        .unwrap();
        assert_eq!(s, PermissionSubject::WritePath(expected.into()), "{path}");
    }

    for bad in ["../outside.txt", "a/../../outside.txt"] {
        let r = subject_of(
            "edit_file",
            serde_json::json!({ "path": bad, "old_string": "a", "new_string": "b" }),
        )
        .await;
        assert!(matches!(r, Err(ToolError::InvalidInput(_))), "{bad}: {r:?}");
    }

    let abs = if cfg!(windows) {
        r"C:\elsewhere\notes.txt"
    } else {
        "/elsewhere/notes.txt"
    };
    let s = subject_of(
        "write_file",
        serde_json::json!({ "path": abs, "content": "x" }),
    )
    .await
    .unwrap();
    assert_eq!(s, PermissionSubject::WritePath(abs.into()));
}

/// 何を起動するか読めない `run_program` の入力は、材料の段階で止まる（判定器まで届かない）。
/// 以前は判定器が入力から `program` を探し、読めなければ聞く側へ倒していた。
#[tokio::test]
async fn a_run_program_input_without_a_readable_program_never_reaches_the_judge() {
    for input in [
        serde_json::json!({ "args": ["x"] }),
        serde_json::json!({ "program": 42 }),
        serde_json::json!({ "program": "git", "args": "status" }),
    ] {
        let r = subject_of("run_program", input.clone()).await;
        assert!(
            matches!(r, Err(ToolError::InvalidInput(_))),
            "{input}: {r:?}"
        );
    }
}
