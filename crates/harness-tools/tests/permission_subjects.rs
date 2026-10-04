//! 組み込みツールが返す判定の材料（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.1・D-101）。
//!
//! 判定器は材料の**変種**で判定を掛ける（設定注入パスの拒否は `WritePath`、T-09 は `Command`、
//! インタプリタは `Program`）。**書くツールが `WritePath` 以外を返すと、設定注入パスの拒否が
//! 掛からなくなる**——これは型では守れないので、組み込みツール全件の変種を表で固定する。
//! 組み込みツールを足すと、この表に載せるまで落ちる。

use harness_core::{CommandSubject, PermissionSubject, ToolCtx, ToolError};
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
            PermissionSubject::Command(CommandSubject::line_only("git status")),
        ),
    ];

    // run_program の材料は解決先（この機械の PATH に依存する）を含むので、欄ごとに確かめる。
    let program = subject_of(
        "run_program",
        serde_json::json!({ "program": "harness-no-such-program", "args": ["log", "-n", "5"] }),
    )
    .await
    .unwrap();
    match program {
        PermissionSubject::Program(p) => {
            assert_eq!(p.program, "harness-no-such-program");
            assert_eq!(p.args, ["log", "-n", "5"]);
            assert_eq!(p.resolved, None, "an unknown program does not resolve");
            assert!(!p.runs_code);
            assert!(p.files.is_empty());
        }
        other => panic!("run_program must return a Program subject, got {other:?}"),
    }

    let reg = ToolRegistry::with_builtin_tools();
    let mut listed: Vec<&str> = table.iter().map(|(n, _, _)| *n).collect();
    listed.push("run_program");
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

/// インタプリタでないツール（`uv`等）でも、引数に名指しされた実在ファイルを中身で縛る（D-123）。
/// `uv run eb.py` の `eb.py` は、`uv` が「コードを走らせるツール」の一覧に無くても承認材料に入る。
/// サブコマンド `run` はファイルでないので咎めず、恒久承認できる（`one_shot_only` は立たない）。
#[tokio::test]
async fn a_non_interpreter_call_binds_its_named_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("eb.py"), "import socket  # exploit").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "rm -rf /").unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let reg = ToolRegistry::with_builtin_tools();
    let tool = reg.get("run_program").unwrap();

    let s = tool
        .permission_subject(
            &serde_json::json!({ "program": "uv", "args": ["run", "eb.py"] }),
            &ctx,
        )
        .await
        .unwrap();
    let PermissionSubject::Program(p) = s else {
        panic!("expected a Program subject")
    };
    assert!(!p.runs_code, "uv is not an interpreter");
    assert!(
        !p.one_shot_only,
        "the subcommand `run` is not a file, so it is not held against permanent approval"
    );
    assert_eq!(p.files.len(), 1, "{:?}", p.files);
    assert_eq!(p.files[0].rel_path, "eb.py");
    assert_eq!(p.previews[0].text, "import socket  # exploit");

    // 拡張子がスクリプトでないファイルも、承認材料としては縛る（判定モデルは全ファイルを見る）。
    // 機械の被害判定を拡張子で絞るのは、縛りではなく危険度の計算の側（`approval_risk`）。
    let s = tool
        .permission_subject(
            &serde_json::json!({ "program": "uv", "args": ["run", "notes.txt"] }),
            &ctx,
        )
        .await
        .unwrap();
    let PermissionSubject::Program(p) = s else {
        panic!("expected a Program subject")
    };
    assert_eq!(p.files.len(), 1, "{:?}", p.files);
    assert_eq!(p.files[0].rel_path, "notes.txt");
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

/// インタプリタの`run_program`は、ファイル引数を中身と隣の名前一覧で縛る（D-104）。
/// その場のコードを渡す呼び出しは恒久承認できない印が立ち、`-EncodedCommand`は解読して添える。
#[tokio::test]
async fn an_interpreter_call_binds_its_script_and_flags_inline_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("build.py"), "print(1)").unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let reg = ToolRegistry::with_builtin_tools();
    let tool = reg.get("run_program").unwrap();

    let s = tool
        .permission_subject(
            &serde_json::json!({ "program": "python", "args": ["build.py"] }),
            &ctx,
        )
        .await
        .unwrap();
    let PermissionSubject::Program(p) = s else {
        panic!("expected a Program subject")
    };
    assert!(p.runs_code);
    assert!(!p.one_shot_only);
    assert_eq!(p.files.len(), 1);
    assert_eq!(p.files[0].rel_path, "build.py");
    assert!(p.files[0].dir_listing_sha256.is_some());
    assert_eq!(p.previews[0].text, "print(1)");

    let s = tool
        .permission_subject(
            &serde_json::json!({ "program": "pwsh", "args": ["-EncodedCommand", "RwBlAHQALQBEAGEAdABlAA=="] }),
            &ctx,
        )
        .await
        .unwrap();
    let PermissionSubject::Program(p) = s else {
        panic!("expected a Program subject")
    };
    assert!(p.runs_code);
    assert!(
        p.one_shot_only,
        "inline code cannot be approved permanently"
    );
    // 符号化された中身は、ハーネスが機械的に解読して添える（§4.4。[BUG-224]）。
    assert_eq!(p.decoded.len(), 1, "{:?}", p.decoded);
    assert_eq!(p.decoded[0].depth, 1);
    assert_eq!(
        p.decoded[0].source,
        harness_core::EncodedSource::EncodedCommand
    );
    assert_eq!(
        p.decoded[0].outcome,
        harness_core::DecodeOutcome::Text {
            encoding: harness_core::TextEncoding::Utf16Le,
            text: "Get-Date".to_string(),
        }
    );
}

/// [BUG-224] `run_shell`の行も、符号化された中身をハーネスが解読して材料に添える（§4.4）。以前は
/// `run_program`の経路にしか配線されておらず、ユーザーが実機で見た行（中身は`systeminfo`）は
/// 塊のまま承認ダイアログに出た。符号化の無い行は空のまま（上の表の`git status`が対照）。
#[tokio::test]
async fn a_shell_line_carries_its_encoded_payload_decoded() {
    let s = subject_of(
        "run_shell",
        serde_json::json!({ "command": "pwsh --enc cwB5AHMAdABlAG0AaQBuAGYAbwA=" }),
    )
    .await
    .unwrap();
    let PermissionSubject::Command(c) = s else {
        panic!("expected a Command subject")
    };
    assert_eq!(c.line, "pwsh --enc cwB5AHMAdABlAG0AaQBuAGYAbwA=");
    assert_eq!(c.decoded.len(), 1, "{:?}", c.decoded);
    assert_eq!(
        c.decoded[0].outcome,
        harness_core::DecodeOutcome::Text {
            encoding: harness_core::TextEncoding::Utf16Le,
            text: "systeminfo".to_string(),
        }
    );
}

/// 解決先がワークスペース内の実行ファイルは、コードを走らせる呼び出しとして扱い、実体を縛る（D-103）。
#[tokio::test]
async fn an_executable_inside_the_workspace_runs_code_and_is_bound() {
    let dir = tempfile::tempdir().unwrap();
    let exe = if cfg!(windows) { "tool.exe" } else { "tool" };
    std::fs::write(dir.path().join(exe), "not really a program").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path().join(exe), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let reg = ToolRegistry::with_builtin_tools();
    let tool = reg.get("run_program").unwrap();
    let s = tool
        .permission_subject(
            &serde_json::json!({ "program": format!("./{exe}"), "args": [] }),
            &ctx,
        )
        .await
        .unwrap();
    let PermissionSubject::Program(p) = s else {
        panic!("expected a Program subject")
    };
    assert!(p.resolved.is_some(), "{p:?}");
    assert!(
        p.runs_code,
        "an executable the model can write runs code: {p:?}"
    );
    assert!(!p.one_shot_only, "{p:?}");
    assert_eq!(
        p.files
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect::<Vec<_>>(),
        [exe]
    );
}

/// **`run_shell`・`run_program` の材料に、縛ったファイルの中身を解読した段が入っている**（D-122）。
///
/// 解読する関数が在ることと、**それが材料の組み立てへ配線されていること**は別の事実である
/// （`bug-pattern-rules` B-06）。配線を外しても、解読そのものの試験は緑のままだった。
///
/// 使う形は実測（2026-10-04、ユーザーの画面）と同じ——`test.py` の中に
/// `os.remove("pwsh --enc <塊>")` と書かれており、その塊を2段解くと
/// `rm C:\Windows\System32\calc.exe` になる。
#[tokio::test]
async fn the_subject_carries_layers_decoded_from_inside_a_bound_file() {
    let dir = tempfile::tempdir().unwrap();
    let body = "import os\nprint(\"hello\")\nos.remove(\"pwsh --enc cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAZwBCAHQAQQBDAEEAQQBRAHcAQQA2AEEARgB3AEEAVgB3AEIAcABBAEcANABBAFoAQQBCAHYAQQBIAGMAQQBjAHcAQgBjAEEARgBNAEEAZQBRAEIAegBBAEgAUQBBAFoAUQBCAHQAQQBEAE0AQQBNAGcAQgBjAEEARwBNAEEAWQBRAEIAcwBBAEcATQBBAEwAZwBCAGwAQQBIAGcAQQBaAFEAQQA9AA==\")";
    std::fs::write(dir.path().join("test.py"), body).unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let reg = ToolRegistry::with_builtin_tools();

    for (name, input) in [
        (
            "run_shell",
            serde_json::json!({ "command": "uv run test.py" }),
        ),
        (
            "run_program",
            serde_json::json!({ "program": "python", "args": ["test.py"] }),
        ),
    ] {
        let subject = reg
            .get(name)
            .unwrap()
            .permission_subject(&input, &ctx)
            .await
            .unwrap();
        let decoded = match &subject {
            PermissionSubject::Command(c) => &c.decoded,
            PermissionSubject::Program(p) => &p.decoded,
            other => panic!("{name}: {other:?}"),
        };
        let texts: Vec<&str> = decoded
            .iter()
            .filter_map(|l| match &l.outcome {
                harness_core::DecodeOutcome::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&r"rm C:\Windows\System32\calc.exe"),
            "{name}: ファイルの中の塊が解読されていない: {texts:?}"
        );
        assert!(
            decoded
                .iter()
                .any(|l| l.in_file.as_deref() == Some("test.py")),
            "{name}: どのファイルの中で見つけたかが残っていない"
        );
    }
}
