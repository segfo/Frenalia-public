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
    run_harness_with_exe(&harness_exe(), ws, turns, extra_args, case_name)
}

/// `run_harness`の`harness.exe`パスを差し替え可能な版。WFP fail-closedケース
/// （`net_case_07_wfp_start_failure_is_fail_closed`）が、`harness-netfilterd.exe`の解決先
/// （`current_exe().parent()`）を差し替えるために専用の一時ディレクトリへコピーした
/// `harness.exe`を起動するのに使う。
fn run_harness_with_exe(
    exe: &Path,
    ws: &Path,
    turns: &[Vec<StreamEvent>],
    extra_args: &[&str],
    case_name: &str,
) -> HarnessRun {
    let scratch = scratch_dir();
    let turns_path = scratch.join(format!("{case_name}-turns.json"));
    let record_path = scratch.join(format!("{case_name}-requests.jsonl"));
    let _ = std::fs::remove_file(&record_path);
    std::fs::write(&turns_path, serde_json::to_string(turns).unwrap()).expect("write turns file");

    let mut cmd = Command::new(exe);
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

/// J: `discard`（upper丸ごと破棄）。`--output-format`が無くテキスト出力のみ（`Discard`は
/// JSON化されていない）ため、既存`case_h_toctou_conflict`が後始末目的で同コマンドを呼ぶ
/// 前例に倣い、終了コードと文字列マッチで検証する。
fn case_j_discard_removes_all_changes() -> Result<(), String> {
    let ws = case_dir("cow-j-discard");
    let session1 = setup_baseline(&ws, "cow-j")?;
    let (session2, _) = run_round2(&ws, ROUND2_SCRIPT, "cow-j-r2")?;

    let output = Command::new(harness_exe())
        .args(["--cwd", ws.to_str().unwrap(), "discard", "--session", &session2])
        .output()
        .map_err(|e| format!("failed to spawn harness discard: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "discard should succeed for a non-live session: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("discarded changes") {
        return Err(format!("expected discard stdout to contain 'discarded changes', got: {stdout}"));
    }
    // round2の変更（`helloworld!!!`）はworkspaceへ一切反映されず、round1のbaselineのまま。
    expect_eq(
        "test.txt must remain at the round1 baseline after discard",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;
    let after = list_cow_sessions();
    if after.contains(&session2) {
        return Err(format!("session {session2} must be gone from list_cow_sessions() after discard"));
    }

    cleanup_on_success(&ws, &[&session1], "cow-j");
    Ok(())
}

/// K: `resolve`（3-way merge）。baseline（3行）に対し、CoWセッション側が1行目を、実workspace
/// 側（TOCTOU、`case_h_toctou_conflict`と同型の外部書き換え）が3行目を、それぞれ非重複に
/// 変更する。`git merge-file`は重ならない変更を自動マージできるため、`--always-edit`無し
/// （既定）でもエディタを起動せず即座に解消される——エディタが起動する分岐（コンフリクトが
/// 真に重なる場合）はここでは検証しない（Windowsで`notepad.exe`が起動しテストがハングする
/// リスクを避けるため、既存E2Eの注意事項どおり自動マージ可能なケースに限定する）。
fn case_k_resolve_auto_merges_non_overlapping_conflict() -> Result<(), String> {
    let ws = case_dir("cow-k-resolve");
    let before = list_cow_sessions();
    let baseline_script = "Set-Content test.txt \"line1`nline2`nline3\" -NoNewline";
    let run1 = run_harness(&ws, &run_shell_script_turns(baseline_script), &["--cow"], "cow-k-r1");
    if !run1.status.success() {
        return Err(format!("baseline harness invocation failed: {}", run1.stderr));
    }
    let session1 = new_cow_session(&before)?;
    let report1 = apply_cow(&ws, &session1, None)?;
    if report1["applied"].as_array().map(|a| a.len()).unwrap_or(0) != 1 {
        return Err(format!("expected baseline commit to apply exactly test.txt: {report1}"));
    }
    expect_eq(
        "test.txt (baseline)",
        &read_file(&ws.join("test.txt"))?,
        "line1\nline2\nline3",
    )?;

    let (session2, _) = run_round2(
        &ws,
        "Set-Content test.txt \"line1-cow`nline2`nline3\" -NoNewline",
        "cow-k-r2",
    )?;

    // セッション外からの書き換え(TOCTOU、`case_h`と同型)。CoW側とは別の行(3行目)を変更する
    // ため、非重複な変更として自動マージできる。
    std::fs::write(ws.join("test.txt"), "line1\nline2\nline3-external")
        .map_err(|e| format!("failed to simulate external write: {e}"))?;

    let output = Command::new(harness_exe())
        .args(["--cwd", ws.to_str().unwrap(), "resolve", "--session", &session2])
        .output()
        .map_err(|e| format!("failed to spawn harness resolve: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "resolve should succeed for a non-overlapping conflict: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("resolved: test.txt") || !stdout.contains("1 resolved, 0 skipped/failed") {
        return Err(format!(
            "expected resolve to auto-merge test.txt without needing an editor, got: {stdout}"
        ));
    }
    expect_eq(
        "test.txt must contain both non-overlapping edits after auto-merge",
        &read_file(&ws.join("test.txt"))?,
        "line1-cow\nline2\nline3-external",
    )?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-k");
    Ok(())
}

/// L: `--resume <id> --cow`によるセッション再開（設計書§19.11、仕様確定: 同一upper_dirを
/// 再利用し同一セッションIDで継続キャプチャする）。1つの`--cow`セッションで変更を行い
/// （discardせず）プロセスを終了し、同じセッションIDで`--resume --cow`により再開して
/// 追加の変更を行い、`apply`で両方の変更が反映されることを確認する。
fn case_l_resume_continues_same_cow_session() -> Result<(), String> {
    let ws = case_dir("cow-l-resume");
    let before = list_cow_sessions();
    let run1 = run_harness(
        &ws,
        &write_file_tool_turns("first.txt", "written in round 1"),
        &["--cow"],
        "cow-l-r1",
    );
    if !run1.status.success() {
        return Err(format!("round1 harness invocation failed: {}", run1.stderr));
    }
    let session_id = new_cow_session(&before)?;
    // round1のプロセスは正常終了しdiscardしていない前提（liveness mutexは名前付きmutexで、
    // 所有プロセスの終了とともにOSが解放するため、再開時に「まだliveと誤認識される」ことは
    // 無い、設計書§19.11参照）。
    if cow_session_is_live(&session_id) {
        return Err(format!("session {session_id} should not be live after its process exited"));
    }

    // 同一session_idで--resume --cowにより再開し、2つ目のファイルを追加する。
    let run2 = run_harness_with_exe(
        &harness_exe(),
        &ws,
        &write_file_tool_turns("second.txt", "written in round 2 after resume"),
        &["--cow", "--resume", &session_id],
        "cow-l-r2",
    );
    if !run2.status.success() {
        return Err(format!("resumed harness invocation failed: {}", run2.stderr));
    }
    // resumeは新しいCoWセッションを作らず、同じsession_idのupper_dirを再利用しているはず。
    let after_resume = list_cow_sessions();
    if !after_resume.contains(&session_id) {
        return Err(format!("session {session_id} should still exist after resume"));
    }
    let new_sessions: Vec<&String> = after_resume.difference(&before).collect();
    if new_sessions != vec![&session_id] {
        return Err(format!(
            "resume must not create a new CoW session, expected only {session_id:?}, got {new_sessions:?}"
        ));
    }

    let report = apply_cow(&ws, &session_id, None)?;
    let mut applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    applied.sort();
    if applied != vec!["first.txt".to_string(), "second.txt".to_string()] {
        return Err(format!(
            "expected both round1 and round2 files to be captured under the same session, got {applied:?}: {report}"
        ));
    }
    expect_eq("first.txt", &read_file(&ws.join("first.txt"))?, "written in round 1")?;
    expect_eq(
        "second.txt",
        &read_file(&ws.join("second.txt"))?,
        "written in round 2 after resume",
    )?;

    cleanup_on_success(&ws, &[&session_id], "cow-l");
    Ok(())
}

fn cow_session_is_live(session_id: &str) -> bool {
    harness_sandbox::workspace_ledger::cow_session_is_live(session_id)
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
        ("J-discard", case_j_discard_removes_all_changes),
        ("K-resolve-auto-merge", case_k_resolve_auto_merges_non_overlapping_conflict),
        ("L-resume-continues-session", case_l_resume_continues_same_cow_session),
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
    run_net_case_with_exe(&harness_exe(), name, allow_domains, case_matrix_case, deny_hosts_expected)
}

/// `run_net_case`の`harness.exe`パスを差し替え可能な版（WFP fail-closedケース専用）。
fn run_net_case_with_exe(
    exe: &Path,
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
) -> Result<(), String> {
    run_net_case_with_exe_and_stderr_check(exe, name, allow_domains, case_matrix_case, deny_hosts_expected, None)
}

/// `run_net_case_with_exe`に、harness自身のstderrへ特定文字列が出ていることの追加検証を
/// 挟めるようにした版。WFP fail-closedケースが、単に通信が拒否されただけでなく
/// 「WFP起動失敗によるfail-closed」という想定した理由で拒否されたことを確認するのに使う。
fn run_net_case_with_exe_and_stderr_check(
    exe: &Path,
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
    stderr_must_contain: Option<&str>,
) -> Result<(), String> {
    let ws = net_case_ws(name);
    let mut extra_args = vec!["--staged"];
    for d in allow_domains {
        extra_args.push("--net-allow-domain");
        extra_args.push(d);
    }
    let script = format!(".\\tier2a-net-e2e.exe case-matrix --case {case_matrix_case}");
    let run = run_harness_with_exe(exe, &ws, &run_shell_script_turns(&script), &extra_args, name);
    if !run.status.success() {
        return Err(format!("harness invocation itself failed: {}", run.stderr));
    }
    if let Some(needle) = stderr_must_contain {
        if !run.stderr.contains(needle) {
            return Err(format!(
                "expected stderr to contain {needle:?} (confirms the specific fail-closed reason), got: {}",
                run.stderr
            ));
        }
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

/// `crates/tier2a-mock-netfilterd`（`docs/DEV-ENVIRONMENT.md`参照）。本物の
/// `harness-netfilterd.exe`とは無関係な別クレートで、named pipeへ一瞬だけ接続してすぐ
/// 切断するだけの、WFP fail-closed E2E専用のフォールト注入バイナリ。
fn mock_netfilterd_exe() -> PathBuf {
    harness_exe()
        .parent()
        .expect("harness exe has a parent dir")
        .join("tier2a-mock-netfilterd.exe")
}

/// `harness-netfilterd.exe`の解決先(`current_exe().parent()`、`netfilterd.rs::daemon_exe_path`)
/// を差し替えるための専用launcherディレクトリを用意する。`harness.exe`をコピーし、隣に
/// `tier2a-mock-netfilterd.exe`を`harness-netfilterd.exe`という名前でコピーする。本物の
/// `target/debug/harness-netfilterd.exe`・共有WFPエンジンには一切触れない。
fn wfp_fail_closed_launcher_exe() -> PathBuf {
    let dir = Path::new(CASE_ROOT).join("_launcher-wfp-failclosed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create launcher dir");
    let harness_copy = dir.join("harness.exe");
    std::fs::copy(harness_exe(), &harness_copy).expect("copy harness.exe into launcher dir");
    std::fs::copy(mock_netfilterd_exe(), dir.join("harness-netfilterd.exe"))
        .expect("copy mock netfilterd exe into launcher dir as harness-netfilterd.exe");
    harness_copy
}

/// 07: WFP fail-closed。`--net-allow-domain example.com`でドメインポリシーを要求しつつ、
/// `harness-netfilterd.exe`の解決先を即座に切断するモックへ差し替えることで、
/// `NetfilterHandle::start`のハンドシェイクを確実に失敗させる（実WFPエンジン・実netfilterdは
/// 一切起動しない、決定論的なフォールト注入）。`should_grant_tier2a_network_capability`
/// （`crates/harness-tools/src/shell.rs`）により、この状態ではAppContainer capability自体が
/// `Deny`になる——example.comを明示許可していても、Layer1協調プロキシへの縮退運用にすら
/// ならず、ソケット生成そのものが一切できない、より強いfail-closed（`main.rs`のWFP起動失敗
/// 警告文言もこの挙動に合わせて修正済み）。既存のcase 01（ドメイン未指定）と同じ
/// "all-denied"のcase-matrixで両ホストとも拒否されることを検証しつつ、stderrに
/// fail-closedの理由が明記されていることも二重に確認する。BFEサービス停止・
/// `FwpmEngineOpen0`自体の失敗は別経路のため、このケースの対象外（`docs/STATUS.md`参照）。
///
/// **`deny_hosts_expected`を空にする理由**: `run_net_case`の「二重証拠」（case-matrix結果＋
/// `net-audit.jsonl`のdeny記録）は、Local Proxy Agentへ到達できてこそ書かれる監査ログを
/// 前提にしている。しかしcapability自体が`Deny`のこのケースでは、サンドボックス化された
/// プロセスはLocal Proxy Agentへloopback到達すること自体ができず、監査ログには何も書かれ
/// ない（`audit entries: []`が正しい結果）。これは「アプリ層のプロキシまで到達して拒否
/// された」場合より強い証拠（AppContainer境界そのもので止まっている）なので、caseの成否は
/// case-matrix自身のJSON出力（プローブが実際に接続を試みて失敗したか）だけで判定する。
///
/// **既知の脆さ（発見済み、テスト側で回避）**: Tier2aのAppContainerプロファイル
/// （`harness.shell.sandbox`）は全ケースで共有される。`harness-netfilterd`はWFP適用時に
/// このSIDをWindowsのAppContainer loopback exemptionへ一時追加し、「このセッションで
/// 新規追加した場合のみ」teardown時に削除する（設計書`AppContainerを用いたドメインベース
/// 通信制御アーキテクチャ設計書.md:133`）。本セッションでの動作確認中、`sudo`呼び出しの
/// 中断・`taskkill`によるプロセス強制終了を繰り返した結果、このexemptionが残留した状態で
/// 本ケースを実行し、モックがWFP起動を阻止していてもLayer1プロキシへのloopback到達だけは
/// 生き残ってしまう（`CheckNetIsolation LoopbackExempt -s`で残留を確認、`sudo
/// CheckNetIsolation LoopbackExempt -d -n=harness.shell.sandbox`で解消）という現象を実機で
/// 観測した。正常終了時のteardownがこのexemptionを確実に削除しているかは未検証のまま
/// 残っている（BUG-046と同型の「共有プロファイルへの残留状態」クラスの脆弱性の可能性が
/// あるが、今回の観測はテスト実行中の異常終了が原因である可能性が高く切り分けられて
/// いない）。次にTier2a関連のE2Eが不可解に失敗したら、まずこれを疑うこと。
fn net_case_07_wfp_start_failure_is_fail_closed() -> Result<(), String> {
    let exe = wfp_fail_closed_launcher_exe();
    run_net_case_with_exe_and_stderr_check(
        &exe,
        "net-07-wfp-failclosed",
        &["example.com"],
        "all-denied",
        &[],
        Some("Tier2a run_shell network capability will remain denied"),
    )
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
        ("07-wfp-start-failure-fail-closed", net_case_07_wfp_start_failure_is_fail_closed),
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
