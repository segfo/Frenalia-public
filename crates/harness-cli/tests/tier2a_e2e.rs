//! Tier2a（AppContainer）のout-of-process E2E回帰テスト。CoWコミット粒度とネットワーク
//! ドメインポリシーの強制機構を、実`harness.exe`（`env!(CARGO_BIN_EXE_harness)`）を起動して
//! 検証する。LLM推論は一切使わない（`--provider mock`、`harness_providers::MockProvider`が
//! 台本化された`run_shell`呼び出しを返す）。
//!
//! 実行方法・前提条件は`docs/DEV-ENVIRONMENT.md`「Tier2a E2Eテストの実行方法」参照。
//! 実AppContainer・実CoW upperディレクトリ・（ネット側は）実インターネット到達性を使う
//! 重い/副作用ありのテストのため、既定の`cargo test`では走らない（`#[ignore]`、
//! `crates/harness-sandbox/src/win_appcontainer.rs`の既存規約と同じ）。
//!
//! ワークスペースは`C:\harness-e2e\<case>\`固定（`%TEMP%`を使うと`preflight`がプロファイル
//! 全階層のtraverse ACEを恒久付与し、保護対象の`traverse-grant-ledger.json`を汚すため、
//! `docs/STATUS.md`「Tier2a起動時のtraverse ACE自動付与（D-31）」参照）。成功したケースは
//! ワークスペース・CoW upperセッション・スクラッチファイルを削除する。失敗したケースは
//! 調査のため残す。

#![cfg(all(windows, feature = "e2e-mock"))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use harness_core::{BlockKind, CompletionRequest, StopReason, StreamEvent, Usage};

const CASE_ROOT: &str = r"C:\harness-e2e";

type CaseFn = fn() -> Result<(), String>;

fn harness_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
}

/// `tools/tier1a_net_e2e/README.md`のcase-matrixバイナリ。`cargo build -p tier2a-net-e2e`が
/// 事前に必要（`docs/DEV-ENVIRONMENT.md`参照）。`harness`と同じ`target/<profile>/`直下にある
/// 前提（ワークスペース共通のビルド出力先）。
fn net_probe_exe() -> PathBuf {
    harness_exe()
        .parent()
        .expect("harness exe has a parent dir")
        .join("tier2a-net-e2e.exe")
}

fn scratch_dir() -> PathBuf {
    let dir = Path::new(CASE_ROOT).join("_scratch");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// ケース専用ワークスペース。既存があれば作り直す（前回失敗の残骸を引き継がない）。
fn case_dir(name: &str) -> PathBuf {
    let dir = Path::new(CASE_ROOT).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create case workspace");
    dir
}

fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: input.to_string(),
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

/// host内蔵`write_file`ツールを1回だけ呼ぶ台本（CoW一本化: run_shellではなくwrite_file自身が
/// CoW upperへ捕まることを確認するための対照ケース）。
fn write_file_tool_turns(path: &str, content: &str) -> Vec<Vec<StreamEvent>> {
    vec![
        tool_use_turn(
            "call_1",
            "write_file",
            serde_json::json!({ "path": path, "content": content }),
        ),
        end_turn("done"),
    ]
}

/// 1回の`run_shell`呼び出し（PowerShellスクリプト1本）だけを行う台本。
fn run_shell_script_turns(script: &str) -> Vec<Vec<StreamEvent>> {
    vec![
        tool_use_turn(
            "call_1",
            "run_shell",
            serde_json::json!({ "command": script }),
        ),
        end_turn("done"),
    ]
}

struct HarnessRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    record_path: PathBuf,
}

/// 実`harness.exe`を`--provider mock`で起動する（Q1〜Q2: out-of-process統一、
/// featureゲート下のモック経路）。`--permission-mode accept-all --dangerously-allow`は
/// 台本化されたrun_shellをheadlessで実行するために必須（Defaultモードだと
/// Exec種別のrun_shellは拒否される、既存`headless_output.rs`参照）。
fn run_harness(ws: &Path, turns: &[Vec<StreamEvent>], extra_args: &[&str], case_name: &str) -> HarnessRun {
    let scratch = scratch_dir();
    let turns_path = scratch.join(format!("{case_name}-turns.json"));
    let record_path = scratch.join(format!("{case_name}-requests.jsonl"));
    let _ = std::fs::remove_file(&record_path);
    std::fs::write(&turns_path, serde_json::to_string(turns).unwrap()).expect("write turns file");

    let mut cmd = Command::new(harness_exe());
    cmd.args([
        "--provider",
        "mock",
        "--mock-turns",
        turns_path.to_str().unwrap(),
        "--mock-record-requests",
        record_path.to_str().unwrap(),
        "--cwd",
        ws.to_str().unwrap(),
        "--permission-mode",
        "accept-all",
        "--dangerously-allow",
        "--output-format",
        "json",
        "-p",
        "(scripted; prompt text is ignored by the mock provider)",
    ]);
    cmd.args(extra_args);
    let output = cmd.output().expect("failed to spawn harness.exe");
    HarnessRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        record_path,
    }
}

/// モックへ実際に送信された`CompletionRequest`を読み、BUG-030型
/// （システムプロンプト・ツールスキーマの送信漏れ）を直接検出する（Q9）。
fn assert_prompt_sane(run: &HarnessRun, must_contain: &[&str]) -> Result<(), String> {
    let data = std::fs::read_to_string(&run.record_path)
        .map_err(|e| format!("failed to read recorded requests {}: {e}", run.record_path.display()))?;
    let first_line = data
        .lines()
        .next()
        .ok_or_else(|| "no CompletionRequest was recorded (mock provider never called?)".to_string())?;
    let req: CompletionRequest = serde_json::from_str(first_line)
        .map_err(|e| format!("recorded request is not valid CompletionRequest JSON: {e}"))?;
    if req.system.is_empty() || req.system.iter().all(|b| b.text.trim().is_empty()) {
        return Err("BUG-030型の欠陥: system prompt が空/未送信".to_string());
    }
    if !req.tools.iter().any(|t| t.name == "run_shell") {
        return Err("run_shell がツール定義として送信されていない".to_string());
    }
    let system_text: String = req.system.iter().map(|b| b.text.as_str()).collect::<Vec<_>>().join("\n");
    for needle in must_contain {
        if !system_text.contains(needle) {
            return Err(format!(
                "system prompt に期待した文字列 {needle:?} が含まれていない（EnvironmentFactsの更新漏れの疑い）"
            ));
        }
    }
    Ok(())
}

fn parse_json_stdout(run: &HarnessRun) -> Result<serde_json::Value, String> {
    serde_json::from_str(run.stdout.trim())
        .map_err(|e| format!("stdout is not valid JSON: {e}\nstdout={}\nstderr={}", run.stdout, run.stderr))
}

fn list_cow_sessions() -> HashSet<String> {
    harness_sandbox::workspace_ledger::list_cow_sessions()
        .into_iter()
        .collect()
}

/// `before`との差分から、このケースで新規に作られたCoWセッションIDを1つ特定する。
fn new_cow_session(before: &HashSet<String>) -> Result<String, String> {
    let after = list_cow_sessions();
    let mut new_ones: Vec<&String> = after.difference(before).collect();
    match new_ones.len() {
        1 => Ok(new_ones.remove(0).clone()),
        0 => Err("CoWセッションが新規作成されなかった".to_string()),
        n => Err(format!("CoWセッションが{n}件同時に新規作成された（並行実行を疑う）")),
    }
}

fn cow_upper_dir(session_id: &str) -> PathBuf {
    harness_sandbox::workspace_ledger::cow_upper_root()
        .expect("resolve %LOCALAPPDATA%\\harness\\cow")
        .join(session_id)
}

/// `--cwd`はclapのトップレベル引数であり、サブコマンド名(`apply`)より前に置かないと
/// 「unexpected argument」で拒否される(手動確認済み)。CoW一本化（Phase 2）により`--source`は
/// 廃止済み——`--session`が指すCoWセッションを`apply`が自動的に見つける。
fn apply_cow(ws: &Path, session_id: &str, only: Option<&str>) -> Result<serde_json::Value, String> {
    let mut args = vec![
        "--cwd".to_string(),
        ws.to_str().unwrap().to_string(),
        "apply".to_string(),
        "--session".to_string(),
        session_id.to_string(),
        "--output-format".to_string(),
        "json".to_string(),
    ];
    if let Some(glob) = only {
        args.push("--only".to_string());
        args.push(glob.to_string());
    }
    let output = Command::new(harness_exe())
        .args(&args)
        .output()
        .map_err(|e| format!("failed to spawn harness apply: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("apply stdout is not valid JSON: {e} (stdout={stdout}, stderr={stderr})"))
}

fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
}

fn expect_eq(what: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual != expected {
        Err(format!("{what}: expected {expected:?}, got {actual:?}"))
    } else {
        Ok(())
    }
}

/// 成功時のみワークスペース・CoW upperセッション・スクラッチを削除する（Q10）。
fn cleanup_on_success(ws: &Path, sessions: &[&str], case_name: &str) {
    for session_id in sessions {
        let _ = std::fs::remove_dir_all(cow_upper_dir(session_id));
    }
    let _ = std::fs::remove_dir_all(ws);
    let scratch = scratch_dir();
    let _ = std::fs::remove_file(scratch.join(format!("{case_name}-turns.json")));
    let _ = std::fs::remove_file(scratch.join(format!("{case_name}-requests.jsonl")));
}

fn run_named_case<F: FnOnce() -> Result<(), String>>(name: &str, f: F) -> bool {
    let result = f();
    let passed = result.is_ok();
    let record = serde_json::json!({
        "case": name,
        "passed": passed,
        "error": result.err(),
    });
    println!("{record}");
    passed
}

// ============================================================================
// CoWコミット粒度マトリクス
// ============================================================================

const ROUND1_SCRIPT: &str = "Set-Content test.txt 'helloworld' -NoNewline; \
Set-Content test1.txt 'helloworld123' -NoNewline; \
Set-Content test3.txt 'baseline3' -NoNewline; \
Set-Content test4.txt 'baseline4' -NoNewline";

const ROUND2_SCRIPT: &str = "Set-Content test.txt 'helloworld!!!' -NoNewline; \
Set-Content test1.txt 'evil' -NoNewline; \
Set-Content test2.txt 'helloworld123' -NoNewline; \
Remove-Item test3.txt; \
Rename-Item test4.txt test5.txt";

/// ラウンド1（ベースライン4ファイル作成）を実行し全コミットする。以後の各ケースは
/// このベースラインの上にラウンド2を重ねる。
fn setup_baseline(ws: &Path, case_name: &str) -> Result<String, String> {
    let before = list_cow_sessions();
    let run = run_harness(
        ws,
        &run_shell_script_turns(ROUND1_SCRIPT),
        &["--cow"],
        &format!("{case_name}-r1"),
    );
    if !run.status.success() {
        return Err(format!("round1 harness invocation failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["run_shell"])?;
    let session1 = new_cow_session(&before)?;
    let report = apply_cow(ws, &session1, None)?;
    let applied = report["applied"].as_array().ok_or("apply report missing applied[]")?;
    if applied.len() != 4 {
        return Err(format!("round1 commit_all applied {} files, expected 4: {report}", applied.len()));
    }
    expect_eq("test.txt (baseline)", &read_file(&ws.join("test.txt"))?, "helloworld")?;
    expect_eq("test1.txt (baseline)", &read_file(&ws.join("test1.txt"))?, "helloworld123")?;
    Ok(session1)
}

fn run_round2(ws: &Path, script: &str, case_name: &str) -> Result<(String, HashSet<String>), String> {
    let before = list_cow_sessions();
    let run = run_harness(ws, &run_shell_script_turns(script), &["--cow"], case_name);
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = new_cow_session(&before)?;
    Ok((session2, before))
}

/// A: 新規作成のみコミット。他の4件は未コミットのまま残ること。
fn case_a_commit_only_new_file() -> Result<(), String> {
    let ws = case_dir("cow-a-new-only");
    let session1 = setup_baseline(&ws, "cow-a")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-a-r2")?;

    let report = apply_cow(&ws, &session2, Some("test2.txt"))?;
    let applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if applied != vec!["test2.txt".to_string()] {
        return Err(format!("expected only test2.txt applied, got {applied:?}"));
    }
    expect_eq("test2.txt", &read_file(&ws.join("test2.txt"))?, "helloworld123")?;
    // 他は未コミットのまま(ラウンド1の値のまま)であること。
    expect_eq("test.txt unchanged", &read_file(&ws.join("test.txt"))?, "helloworld")?;
    expect_eq("test1.txt unchanged", &read_file(&ws.join("test1.txt"))?, "helloworld123")?;
    if !ws.join("test3.txt").exists() {
        return Err("test3.txt should still exist (delete not committed)".to_string());
    }
    if !ws.join("test4.txt").exists() || ws.join("test5.txt").exists() {
        return Err("test4.txt/test5.txt rename should not be committed yet".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-a");
    Ok(())
}

/// B: 修正のみコミット。
fn case_b_commit_only_modifications() -> Result<(), String> {
    let ws = case_dir("cow-b-modify-only");
    let session1 = setup_baseline(&ws, "cow-b")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-b-r2")?;

    apply_cow(&ws, &session2, Some("test.txt"))?;
    let report = apply_cow(&ws, &session2, Some("test1.txt"))?;
    let _ = report;
    expect_eq("test.txt modified", &read_file(&ws.join("test.txt"))?, "helloworld!!!")?;
    expect_eq("test1.txt modified", &read_file(&ws.join("test1.txt"))?, "evil")?;
    if ws.join("test2.txt").exists() {
        return Err("test2.txt (create) should not be committed yet".to_string());
    }
    if !ws.join("test3.txt").exists() {
        return Err("test3.txt (delete) should not be committed yet".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-b");
    Ok(())
}

/// C: 削除のみコミット。
fn case_c_commit_only_deletion() -> Result<(), String> {
    let ws = case_dir("cow-c-delete-only");
    let session1 = setup_baseline(&ws, "cow-c")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-c-r2")?;

    apply_cow(&ws, &session2, Some("test3.txt"))?;
    if ws.join("test3.txt").exists() {
        return Err("test3.txt should have been deleted".to_string());
    }
    expect_eq("test.txt unchanged", &read_file(&ws.join("test.txt"))?, "helloworld")?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-c");
    Ok(())
}

/// D: 移動のみコミット（Delete test4.txt + Create test5.txtの2エントリ）。
fn case_d_commit_only_rename() -> Result<(), String> {
    let ws = case_dir("cow-d-rename-only");
    let session1 = setup_baseline(&ws, "cow-d")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-d-r2")?;

    apply_cow(&ws, &session2, Some("test4.txt"))?;
    apply_cow(&ws, &session2, Some("test5.txt"))?;
    if ws.join("test4.txt").exists() {
        return Err("test4.txt should be gone after rename commit".to_string());
    }
    expect_eq("test5.txt", &read_file(&ws.join("test5.txt"))?, "baseline4")?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-d");
    Ok(())
}

/// E: 全部コミット。
fn case_e_commit_all_at_once() -> Result<(), String> {
    let ws = case_dir("cow-e-commit-all");
    let session1 = setup_baseline(&ws, "cow-e")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-e-r2")?;

    let report = apply_cow(&ws, &session2, None)?;
    let applied = report["applied"].as_array().ok_or("missing applied[]")?;
    // modify x2 (test.txt/test1.txt) + create x1 (test2.txt) + delete x1 (test3.txt)
    // + rename=delete+create x2 (test4.txt/test5.txt) = 6。
    if applied.len() != 6 {
        return Err(format!("expected 6 applied entries (modify x2, create x1, delete x1, rename=delete+create x2), got {}: {report}", applied.len()));
    }
    expect_eq("test.txt", &read_file(&ws.join("test.txt"))?, "helloworld!!!")?;
    expect_eq("test1.txt", &read_file(&ws.join("test1.txt"))?, "evil")?;
    expect_eq("test2.txt", &read_file(&ws.join("test2.txt"))?, "helloworld123")?;
    expect_eq("test5.txt", &read_file(&ws.join("test5.txt"))?, "baseline4")?;
    if ws.join("test3.txt").exists() || ws.join("test4.txt").exists() {
        return Err("test3.txt/test4.txt should be gone".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-e");
    Ok(())
}

/// F: 部分コミット→残りを追いコミットした最終状態が、Eの全コミット結果とバイト一致すること
/// （データが飛ばない不変条件、当初の要求の核心）。
fn case_f_partial_then_rest_matches_commit_all() -> Result<(), String> {
    let ws = case_dir("cow-f-partial-then-rest");
    let session1 = setup_baseline(&ws, "cow-f")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-f-r2")?;

    apply_cow(&ws, &session2, Some("test2.txt"))?;
    apply_cow(&ws, &session2, Some("test.txt"))?;
    let final_report = apply_cow(&ws, &session2, None)?;
    let _ = final_report;

    expect_eq("test.txt", &read_file(&ws.join("test.txt"))?, "helloworld!!!")?;
    expect_eq("test1.txt", &read_file(&ws.join("test1.txt"))?, "evil")?;
    expect_eq("test2.txt", &read_file(&ws.join("test2.txt"))?, "helloworld123")?;
    expect_eq("test5.txt", &read_file(&ws.join("test5.txt"))?, "baseline4")?;
    if ws.join("test3.txt").exists() || ws.join("test4.txt").exists() {
        return Err("test3.txt/test4.txt should be gone after committing the rest".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-f");
    Ok(())
}

/// G: D-05ハードデニー。`.git/config`をupperへ書いてもapplyで実workspaceへ書き戻せないこと。
fn case_g_hard_deny_config_injection() -> Result<(), String> {
    let ws = case_dir("cow-g-hard-deny");
    let session1 = setup_baseline(&ws, "cow-g")?;
    let before = list_cow_sessions();
    let script = "New-Item -ItemType Directory -Force .git | Out-Null; \
Set-Content .git/config 'evil-injected' -NoNewline";
    let run = run_harness(&ws, &run_shell_script_turns(script), &["--cow"], "cow-g-r2");
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = new_cow_session(&before)?;

    let report = apply_cow(&ws, &session2, None)?;
    let hard_denied: Vec<String> = report["hard_denied"]
        .as_array()
        .ok_or("missing hard_denied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if !hard_denied.iter().any(|p| p.replace('\\', "/") == ".git/config") {
        return Err(format!(".git/config should be hard_denied (D-05), got {report}"));
    }
    if ws.join(".git").join("config").exists() {
        return Err("D-05 violated: .git/config was written to the real workspace".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-g");
    Ok(())
}

/// H: TOCTOU。セッション中に実workspace側を外から書き換えると、conflictとして扱われ
/// CoW側の内容で黙って上書きされないこと。
fn case_h_toctou_conflict() -> Result<(), String> {
    let ws = case_dir("cow-h-toctou");
    let session1 = setup_baseline(&ws, "cow-h")?;
    let before = list_cow_sessions();
    let script = "Set-Content test.txt 'modified-by-session' -NoNewline";
    let run = run_harness(&ws, &run_shell_script_turns(script), &["--cow"], "cow-h-r2");
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = new_cow_session(&before)?;

    // セッション外からの書き換え(TOCTOU)をシミュレートする。
    std::fs::write(ws.join("test.txt"), "tampered-externally")
        .map_err(|e| format!("failed to simulate external write: {e}"))?;

    let report = apply_cow(&ws, &session2, Some("test.txt"))?;
    let conflicts: Vec<String> = report["conflicts"]
        .as_array()
        .ok_or("missing conflicts[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if conflicts != vec!["test.txt".to_string()] {
        return Err(format!("expected test.txt to be a conflict, got {report}"));
    }
    expect_eq(
        "test.txt must keep the externally-written content (no silent overwrite)",
        &read_file(&ws.join("test.txt"))?,
        "tampered-externally",
    )?;

    // このケースは意図的にconflictを残すため、CoWセッションのdiscardで後始末する。
    // `--cwd`はサブコマンド名より前に置く必要がある(clapのトップレベル引数)。
    let _ = Command::new(harness_exe())
        .args([
            "--cwd",
            ws.to_str().unwrap(),
            "discard",
            "--session",
            &session2,
        ])
        .status();
    cleanup_on_success(&ws, &[&session1], "cow-h");
    Ok(())
}

/// I: host内蔵`write_file`ツール自身が`--cow`時にCoW保護を経由すること（2026-08-01実機ドライ
/// ランで発見したバグの回帰確認、Phase 1修正）。`run_shell`経由（PowerShellの`Set-Content`）
/// ではなく`write_file`ツールを直接呼ぶ台本で、(a) workspace本体がwrite_file実行直後は
/// 無傷、(b) 新規CoWセッションが記録され、(c) `apply`で反映される、ことを検証する。
fn case_i_write_file_tool_is_captured_by_cow() -> Result<(), String> {
    let ws = case_dir("cow-i-write-file-tool");
    let before = list_cow_sessions();
    let run = run_harness(
        &ws,
        &write_file_tool_turns("notes.txt", "written via write_file tool"),
        &["--cow"],
        "cow-i",
    );
    if !run.status.success() {
        return Err(format!("harness invocation failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["Copy-on-Write"])?;

    if ws.join("notes.txt").exists() {
        return Err(
            "write_file must not touch the real workspace directly under --cow (regression)"
                .to_string(),
        );
    }
    let session = new_cow_session(&before)?;

    let report = apply_cow(&ws, &session, None)?;
    let applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if applied != vec!["notes.txt".to_string()] {
        return Err(format!("expected only notes.txt applied, got {applied:?}: {report}"));
    }
    expect_eq(
        "notes.txt",
        &read_file(&ws.join("notes.txt"))?,
        "written via write_file tool",
    )?;

    cleanup_on_success(&ws, &[&session], "cow-i");
    Ok(())
}

/// `tier2a_cow_commit_matrix`と`tier2a_net_policy_matrix`は同じテストバイナリ内の別々の
/// `#[test]`関数であり、既定では別スレッドで並行実行される。両者は共有WFPエンジン・
/// netfilterdの単一インスタンス・`C:\harness-e2e`を奪い合うため、Q5(機構ごとに1テストで
/// 直列実行)は各マトリクス内部だけでなくこの2関数間でも保証する必要がある。プロセス内の
/// 全スレッドが共有する`static Mutex`でロックし、`--test-threads`の指定に関わらず
/// 直列化する(実機検証で、並行実行時にネットワークマトリクスがWFPの
/// net_event_collection_enable_failed等で不安定になることを確認した)。
static CROSS_MATRIX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
#[ignore]
fn tier2a_cow_commit_matrix() {
    let _guard = CROSS_MATRIX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cases: Vec<(&str, CaseFn)> = vec![
        ("A-new-only", case_a_commit_only_new_file),
        ("B-modify-only", case_b_commit_only_modifications),
        ("C-delete-only", case_c_commit_only_deletion),
        ("D-rename-only", case_d_commit_only_rename),
        ("E-commit-all", case_e_commit_all_at_once),
        ("F-partial-then-rest", case_f_partial_then_rest_matches_commit_all),
        ("G-hard-deny-config-injection", case_g_hard_deny_config_injection),
        ("H-toctou-conflict", case_h_toctou_conflict),
        ("I-write-file-tool-captured", case_i_write_file_tool_is_captured_by_cow),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(passed, total, "{passed}/{total} CoW commit matrix cases passed (see per-case JSON above for details)");
}

// ============================================================================
// ネットワークドメインポリシー・マトリクス
// ============================================================================

/// サンドボックス外(このテストプロセス自身)から`fetch-example`を実行し、判定不能
/// (実マシンがオフライン等)を検出する(Q4: positive control)。落ちたら以降の全ケースを
/// 実行する意味がないため、この関数の呼び出し元は即座に失敗させる。
fn liveness_gate() -> Result<(), String> {
    let exe = net_probe_exe();
    if !exe.exists() {
        return Err(format!(
            "{} not found; run `cargo build -p tier2a-net-e2e` first (docs/DEV-ENVIRONMENT.md)",
            exe.display()
        ));
    }
    let output = Command::new(&exe)
        .arg("fetch-example")
        .output()
        .map_err(|e| format!("failed to spawn {}: {e}", exe.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line: serde_json::Value = stdout
        .lines()
        .next()
        .and_then(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| format!("liveness probe produced no parseable output: {stdout}"))?;
    if line["ok"].as_bool() != Some(true) {
        return Err(format!(
            "判定不能: サンドボックス外からのexample.com到達性が無い(オフライン?)。以降の全ケースを保留する: {line}"
        ));
    }
    Ok(())
}

fn net_case_ws(name: &str) -> PathBuf {
    let ws = case_dir(name);
    std::fs::copy(net_probe_exe(), ws.join("tier2a-net-e2e.exe"))
        .expect("copy net probe exe into case workspace");
    ws
}

/// case-matrixバイナリを`run_shell`経由でサンドボックス内から実行し、全プローブが期待通り
/// (allow/deny)だったときだけ`Ok`にする。監査ログ(`net-audit.jsonl`)にも当該ホストの
/// `allowed:false`エントリがあることを二重証拠として要求する(Q4)。`--staged`を付けて
/// `sandbox_dir`を確保するのは、それが無いと`net-audit.jsonl`自体が書かれないため
/// (`crates/harness-tools/src/shell.rs`の`audit_log_path`はstaging有効時のみ設定される)。
fn run_net_case(name: &str, allow_domains: &[&str], case_matrix_case: &str, deny_hosts_expected: &[&str]) -> Result<(), String> {
    let ws = net_case_ws(name);
    let mut extra_args = vec!["--staged"];
    for d in allow_domains {
        extra_args.push("--net-allow-domain");
        extra_args.push(d);
    }
    let script = format!(".\\tier2a-net-e2e.exe case-matrix --case {case_matrix_case}");
    let run = run_harness(&ws, &run_shell_script_turns(&script), &extra_args, name);
    if !run.status.success() {
        return Err(format!("harness invocation itself failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["run_shell"])?;
    let outcome = parse_json_stdout(&run)?;
    // `outcome["result"]`はモデルの最終応答文（このテストではend_turnの固定文字列"done"）で、
    // run_shellの実際のstdoutは`tool_calls[0].result`にある(`JsonToolCall`、`harness-cli/src/lib.rs`)。
    let result_text = outcome["tool_calls"]
        .get(0)
        .and_then(|c| c["result"].as_str())
        .ok_or_else(|| format!("no tool_calls[0].result in outcome: {outcome}"))?;

    // case-matrixバイナリ自身が最終行で{"passed":true/false,...}を出す(expect_ok一致判定)。
    let case_matrix_passed = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("passed").is_some())
        .and_then(|v| v["passed"].as_bool())
        .ok_or_else(|| format!("could not find case-matrix summary line in output: {result_text}"))?;
    if !case_matrix_passed {
        return Err(format!("case-matrix reported a mismatch (allow/deny did not match expectation): {result_text}"));
    }

    // 二重証拠: 監査ログにも対象ホストのallowed:falseが実際に記録されていること。
    let audit_path = ws.join(".harness").join("sandbox");
    let audit_entries = collect_audit_entries(&audit_path)?;
    for host in deny_hosts_expected {
        let found = audit_entries.iter().any(|e| {
            e.get("allowed") == Some(&serde_json::Value::Bool(false))
                && e.get("host").and_then(|h| h.as_str()).map(|h| h.contains(host)).unwrap_or(false)
        });
        if !found {
            return Err(format!(
                "no audit log entry recorded a deny for host containing {host:?} (audit entries: {audit_entries:?})"
            ));
        }
    }

    cleanup_on_success(&ws, &[], name);
    Ok(())
}

/// `.harness/sandbox/**/net-audit.jsonl`を全て読み、JSON行を集める(kind:proxy/wfp/fake_dns
/// いずれも同じファイルに載る、`net_proxy.rs`のdocコメント参照。型を固定せず`Value`で読むのは、
/// 複数機構がこのファイルへ相乗りする設計のため)。
fn collect_audit_entries(sandbox_root: &Path) -> Result<Vec<serde_json::Value>, String> {
    let mut out = Vec::new();
    let Ok(sessions) = std::fs::read_dir(sandbox_root) else {
        return Ok(out);
    };
    for session in sessions.flatten() {
        let audit = session.path().join("net-audit.jsonl");
        if let Ok(data) = std::fs::read_to_string(&audit) {
            for line in data.lines() {
                if let Ok(v) = serde_json::from_str(line) {
                    out.push(v);
                }
            }
        }
    }
    Ok(out)
}

fn net_case_01_none() -> Result<(), String> {
    run_net_case("net-01-none", &[], "all-denied", &["example.com", "google.com"])
}

fn net_case_02_invalid_domain() -> Result<(), String> {
    run_net_case("net-02-invalid", &["invalidexample.com"], "all-denied", &["example.com", "google.com"])
}

/// 03: example.com許可。case-matrix `domains`はexample.com=allow/google.com=denyを同時に
/// アサートするため、これ自体がpositive control(通信路が生きていることの証明)を兼ねる(Q5)。
fn net_case_03_example_allowed() -> Result<(), String> {
    run_net_case("net-03-example", &["example.com"], "domains", &["google.com"])
}

/// 05: Layer2検証。example.comは許可済みだが、`raw-connect`はプロキシ環境変数を無視して
/// 直接TCP接続する(`tier2a-net-e2e.exe`のdocコメント参照)。WFPが機能していなければ
/// ここが素通りする=D-01「フックは境界にしない」の直接検証。
fn net_case_05_raw_tcp_bypasses_proxy() -> Result<(), String> {
    run_net_case("net-05-rawtcp", &["example.com"], "example-ip", &[])
}

/// 06: Layer1検証。10進/16進/8進のIPリテラルでドメインマッチングをすり抜けようとする経路。
fn net_case_06_numeric_ip_obfuscation() -> Result<(), String> {
    run_net_case("net-06-numeric", &["example.com"], "numeric-ip", &[])
}

#[test]
#[ignore]
fn tier2a_net_policy_matrix() {
    let _guard = CROSS_MATRIX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = liveness_gate() {
        panic!("liveness gate failed, all subsequent cases are indeterminate: {e}");
    }

    let cases: Vec<(&str, CaseFn)> = vec![
        ("01-none", net_case_01_none),
        ("02-invalid-domain", net_case_02_invalid_domain),
        ("03-example-allowed", net_case_03_example_allowed),
        ("05-raw-tcp-layer2", net_case_05_raw_tcp_bypasses_proxy),
        ("06-numeric-ip-layer1", net_case_06_numeric_ip_obfuscation),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(passed, total, "{passed}/{total} network policy matrix cases passed (see per-case JSON above for details)");
}
