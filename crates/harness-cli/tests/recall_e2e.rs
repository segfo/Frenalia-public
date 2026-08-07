//! Recall（ゴールを横断する永続記憶、`plans/PLAN-RECALL-MEMORY.md`）のout-of-process E2E。
//! 実`harness.exe`（`env!(CARGO_BIN_EXE_harness)`）を`--provider mock`で起動し、
//! **プロセス境界を越える配線**を端から端まで通す。LLM推論は使わない。
//!
//! 単体テスト（`crates/harness-cognition/src/recall/`の31件）が届かないのは次の3つで、
//! ここはその3つだけを狙う。
//!
//! 1. **実`RecallStore::for_workspace`の解決経路** — 単体テストは全て`at_root`（一時ディレクトリ）
//!    へ逃がしてあり、本番の解決経路を通っていない。
//! 2. **注入した記憶がモデルへ実際に届いているか** — `--mock-record-requests`で
//!    「Hypothesizeフェーズのリクエスト本文に過去の記憶が載っている」ことを直接見る。
//!    ここが空振りしても既存テストは全部緑のままになる。
//! 3. **CLI（`harness memory *`）のレビュー運用** — 自動テストが1件も無かった。
//!
//! **記憶の置き場は`HARNESS_RECALL_DATA_ROOT`でケースごとの一時ディレクトリへ逃がす**
//! （`e2e-mock` featureが連れてくる`harness-cognition/e2e-test-hooks`。既定ビルドには
//! コンパイルされない）。実`%APPDATA%\harness\data\memory\`は一切触らない。
//!
//! ワークスペースは`C:\harness-e2e\recall\<case>\`固定（`%TEMP%`を使うと`preflight`が
//! プロファイル全階層のtraverse ACEを恒久付与する。`tier2a_e2e.rs`と同じ規約）。
//! 実`harness.exe`の起動が重いため`#[ignore]`。実行方法は`docs/DEV-ENVIRONMENT.md`。

#![cfg(all(windows, feature = "e2e-mock"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use harness_core::{BlockKind, StopReason, StreamEvent, Usage};

const CASE_ROOT: &str = r"C:\harness-e2e\recall";

type CaseFn = fn() -> Result<(), String>;

fn harness_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
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

/// ケース専用の記憶データルート。**ここがあるので実`%APPDATA%`を汚さない**。
fn case_data_root(name: &str) -> PathBuf {
    let dir = Path::new(CASE_ROOT).join("_memory").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create memory data root");
    dir
}

// ---------------------------------------------------------------- 台本の部品

fn done(stop_reason: StopReason) -> StreamEvent {
    StreamEvent::Done {
        stop_reason,
        usage: Usage {
            input: 100,
            output: 20,
            cache_read: 0,
            cache_creation: 0,
        },
    }
}

fn text_turn(text: &str) -> Vec<StreamEvent> {
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
        done(StopReason::EndTurn),
    ]
}

/// ツール呼び出しだけを返すターン（素朴ループ＝`--cognition off`用）。
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
        done(StopReason::ToolUse),
    ]
}

/// Investigateターン: 計画（JSON）とツール呼び出しを同じメッセージで返す（`CallKind::Fused`）。
fn plan_and_tool_turn(plan: &str, tool: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: plan.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: tool.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 1,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 1 },
        done(StopReason::ToolUse),
    ]
}

/// HIVループ1周分（Hypothesize→Investigate→Distill→Verify→Decide）。1フェーズ1コールで、
/// `crates/harness-cognition/tests/hiv_light_transcript.rs`の台本と同じ形にしてある。
fn hiv_turns() -> Vec<Vec<StreamEvent>> {
    vec![
        text_turn(
            &serde_json::json!({
                "hypotheses": [{
                    "statement": "run_shellはPowerShellを起動している",
                    "predicts": ["shell.rsにpowershellの記述が無ければ偽"],
                    "confidence": 0.7
                }]
            })
            .to_string(),
        ),
        plan_and_tool_turn(
            &serde_json::json!({
                "plan": [{ "source": "read_file", "query": "shell.rs", "expects": "起動するシェル名" }]
            })
            .to_string(),
            "read_file",
            serde_json::json!({ "path": "shell.rs" }),
        ),
        text_turn(
            &serde_json::json!({
                "evidence": [{
                    "claim": "shell.rsがpowershell.exeを起動している",
                    "relation": "supports",
                    "source": "shell.rs"
                }]
            })
            .to_string(),
        ),
        text_turn(
            &serde_json::json!({ "verdict": "confirms", "missing": [], "note": "起動コマンドを直接読んだ" })
                .to_string(),
        ),
        text_turn(
            &serde_json::json!({
                "action": "PowerShellを前提に手順を書く",
                "then_verify": "run_shellでecho $PSVersionTableを実行する"
            })
            .to_string(),
        ),
    ]
}

/// 読出しが走る2周目以降の台本。**先頭に`Phase::Recall`の判定コールが1つ増える**
/// （bigram検索で候補が1件以上あるときだけ打たれる）。
fn hiv_turns_with_recall(picks: serde_json::Value) -> Vec<Vec<StreamEvent>> {
    let mut turns = vec![text_turn(&serde_json::json!({ "picks": picks }).to_string())];
    turns.extend(hiv_turns());
    turns
}

// ------------------------------------------------------------ harnessの起動

struct HarnessRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    record_path: PathBuf,
}

struct RunSpec<'a> {
    ws: &'a Path,
    data_root: &'a Path,
    turns: &'a [Vec<StreamEvent>],
    extra_args: &'a [&'a str],
    case_name: &'a str,
    /// `PATH`を差し替える（gitを見つけられない環境の再現用）。`None`なら継承。
    path_override: Option<&'a str>,
    /// `--cwd`へ渡す綴り。`None`なら`ws`をそのまま渡す（綴りの畳み込み確認で使う）。
    cwd_spelling: Option<&'a str>,
}

/// 実`harness.exe`を`--provider mock`＋`--output-format jsonl`で1回起動する。
///
/// `jsonl`にするのは`AgentEvent`を1行ずつstdoutへ出させるため——**`text`モードでは
/// `MemoryRecalled`/`MemoryCheckpointed`が1行も出ない**（`harness_cli::run_headless`）。
fn run_harness(spec: RunSpec<'_>) -> HarnessRun {
    let scratch = scratch_dir();
    let turns_path = scratch.join(format!("{}-turns.json", spec.case_name));
    let record_path = scratch.join(format!("{}-requests.jsonl", spec.case_name));
    let _ = std::fs::remove_file(&record_path);
    std::fs::write(
        &turns_path,
        serde_json::to_string(spec.turns).expect("serialize turns"),
    )
    .expect("write turns file");

    let cwd_arg = spec
        .cwd_spelling
        .map(str::to_string)
        .unwrap_or_else(|| spec.ws.to_string_lossy().to_string());

    let mut cmd = Command::new(harness_exe());
    cmd.args([
        "--provider",
        "mock",
        "--mock-turns",
        turns_path.to_str().unwrap(),
        "--mock-record-requests",
        record_path.to_str().unwrap(),
        "--cwd",
        &cwd_arg,
        // **Recallはシェル隔離Tierと無関係**なので、明示的にTier1へ落とす。既定のTier2a
        // プローブは新しいワークスペース木に対して祖先traverse ACEの付与（＝privhelperの
        // 昇格＝UAC）を要求し、無人実行できないうえ、記憶とは関係のないACEを実マシンへ
        // 残す（D-31/D-44）。ここで測りたいのは記憶の配線であって隔離ではない。
        "--tier1",
        "--output-format",
        "jsonl",
        "-p",
        "run_shellがどのシェルを使うか、根拠を挙げて答えて",
    ]);
    cmd.args(spec.extra_args);
    cmd.env("HARNESS_RECALL_DATA_ROOT", spec.data_root);
    if let Some(path) = spec.path_override {
        cmd.env("PATH", path);
    }
    let output = cmd.output().expect("failed to spawn harness.exe");
    HarnessRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        record_path,
    }
}

/// `--cognition always`（HIVループ）で1回起動する既定形。
fn run_hiv(
    ws: &Path,
    data_root: &Path,
    turns: &[Vec<StreamEvent>],
    case_name: &str,
) -> HarnessRun {
    run_harness(RunSpec {
        ws,
        data_root,
        turns,
        extra_args: &["--cognition", "always"],
        case_name,
        path_override: None,
        cwd_spelling: None,
    })
}

/// `harness <global-args> memory <args>`を実行する（`--cwd`はグローバル引数なので
/// サブコマンドより前に置く）。
fn memory_cli(ws: &Path, data_root: &Path, args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(harness_exe());
    cmd.arg("--cwd").arg(ws).arg("memory").args(args);
    cmd.env("HARNESS_RECALL_DATA_ROOT", data_root);
    let out = cmd.output().expect("failed to spawn harness.exe memory");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// -------------------------------------------------------------- 観測ヘルパー

/// stdoutのJSONL（1行1`AgentEvent`）をパースする。
fn events(run: &HarnessRun) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .collect()
}

/// 外部タグ付きenumの`AgentEvent`から、指定バリアントの中身だけを取り出す。
fn events_named<'a>(evs: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    evs.iter().filter_map(|e| e.get(name)).collect()
}

fn require_success(run: &HarnessRun, what: &str) -> Result<(), String> {
    if run.status.success() {
        return Ok(());
    }
    Err(format!(
        "{what}: harness.exe exited with {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        run.status.code(),
        run.stdout,
        run.stderr
    ))
}

/// データルート直下の記憶ディレクトリ（`<workspace-key>/`）。**1つだけであること**も同時に
/// 確かめる（綴り違いで2つできていないか）。
fn memory_dir(data_root: &Path) -> Result<PathBuf, String> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(data_root)
        .map_err(|e| format!("read {}: {e}", data_root.display()))?
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    dirs.sort();
    match dirs.len() {
        1 => Ok(dirs.remove(0)),
        n => Err(format!(
            "expected exactly 1 workspace-key dir under {}, found {n}: {dirs:?}",
            data_root.display()
        )),
    }
}

fn checkpoint_files(mem_dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(mem_dir.join("checkpoints"))
        .map(|it| {
            it.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// `harness memory list --all --output-format json`の結果。
fn list_all(ws: &Path, data_root: &Path) -> Result<Vec<serde_json::Value>, String> {
    let (ok, stdout, stderr) = memory_cli(ws, data_root, &["list", "--all", "--output-format", "json"]);
    if !ok {
        return Err(format!("memory list failed: {stderr}"));
    }
    serde_json::from_str(stdout.trim())
        .map_err(|e| format!("memory list did not print a JSON array: {e}\n{stdout}"))
}

/// モックへ実際に送信された`CompletionRequest`のJSONL（1行1リクエスト）。
fn recorded_requests(run: &HarnessRun) -> Result<Vec<String>, String> {
    let data = std::fs::read_to_string(&run.record_path).map_err(|e| {
        format!(
            "failed to read recorded requests {}: {e}",
            run.record_path.display()
        )
    })?;
    Ok(data.lines().map(str::to_string).collect())
}

fn git_head(mem_dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .current_dir(mem_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_log(mem_dir: &Path) -> String {
    Command::new("git")
        .current_dir(mem_dir)
        .args(["log", "--oneline"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// ディレクトリ全体のスナップショット（相対パス＋内容ハッシュ）。`--cognition off`が
/// 記憶を1バイトも触らないことを確かめるために使う。
fn snapshot(dir: &Path) -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let bytes = std::fs::read(&path).unwrap_or_default();
                out.push((rel, harness_change_ledger::hash_bytes(&bytes)));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// ワークスペースの中身（HIV台本が`read_file`で読むファイル）を用意する。
fn seed_workspace(ws: &Path) {
    std::fs::write(
        ws.join("shell.rs"),
        "let mut cmd = Command::new(\"powershell.exe\");",
    )
    .expect("seed shell.rs");
}

fn run_named_case<F: FnOnce() -> Result<(), String>>(name: &str, f: F) -> bool {
    let result = f();
    let passed = result.is_ok();
    println!(
        "{}",
        serde_json::json!({ "case": name, "passed": passed, "error": result.err() })
    );
    passed
}

// ============================================================================
// ケース
// ============================================================================

/// R1: Decide到達で1件書かれ、git履歴に1コミット残り、File出典のダイジェストが記録される。
fn case_write_on_decide() -> Result<(), String> {
    let ws = case_dir("write-on-decide");
    let data = case_data_root("write-on-decide");
    seed_workspace(&ws);

    let run = run_hiv(&ws, &data, &hiv_turns(), "write-on-decide");
    require_success(&run, "R1")?;

    let evs = events(&run);
    let checkpointed = events_named(&evs, "MemoryCheckpointed");
    if checkpointed.len() != 1 {
        return Err(format!(
            "expected exactly 1 MemoryCheckpointed event, got {}: {}",
            checkpointed.len(),
            run.stdout
        ));
    }
    if checkpointed[0].get("skipped") != Some(&serde_json::Value::Null) {
        return Err(format!("checkpoint was skipped: {}", checkpointed[0]));
    }
    let id = checkpointed[0]
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("MemoryCheckpointed carried no id")?;

    // indexとCLIから同じ1件が見える（＝実`for_workspace`の解決経路が通っている）。
    let list = list_all(&ws, &data)?;
    if list.len() != 1 || list[0]["id"] != id {
        return Err(format!("memory list disagrees with the event: {list:?}"));
    }
    if list[0]["summary"] != "run_shellはPowerShellを起動している" {
        return Err(format!("unexpected summary: {}", list[0]["summary"]));
    }

    let mem_dir = memory_dir(&data)?;
    let files = checkpoint_files(&mem_dir);
    if files.len() != 1 {
        return Err(format!("expected 1 checkpoint file, got {files:?}"));
    }
    let body = std::fs::read_to_string(&files[0]).map_err(|e| e.to_string())?;
    for needle in ["## 決定", "PowerShellを前提に手順を書く", "\"sources\""] {
        if !body.contains(needle) {
            return Err(format!("checkpoint body lacks {needle:?}:\n{body}"));
        }
    }
    // File出典のSHA-256が記録される（Freshness照合の材料、未決④）。
    if !body.contains("\"path\": \"shell.rs\"") {
        return Err(format!("shell.rs was not digested as a source:\n{body}"));
    }

    // git履歴化: 1書込み＝1コミット。
    let log = git_log(&mem_dir);
    if !log.contains("checkpoint: run_shellはPowerShellを起動している") {
        return Err(format!("git log lacks the checkpoint commit:\n{log}"));
    }
    Ok(())
}

/// R2/R16: 2周目で記憶が検索・判定・注入され、**その内容がHypothesizeのプロンプトに載る**。
/// 併せて、注入した記憶が次のcheckpointへ書き戻されない（自己参照ループの遮断）ことも見る。
fn case_recall_injection_reaches_the_prompt() -> Result<(), String> {
    let ws = case_dir("recall-injection");
    let data = case_data_root("recall-injection");
    seed_workspace(&ws);

    // 1周目: 記憶を作る。
    let first = run_hiv(&ws, &data, &hiv_turns(), "recall-injection-1");
    require_success(&first, "R2の1周目")?;
    let list = list_all(&ws, &data)?;
    let id = list
        .first()
        .and_then(|m| m["id"].as_str())
        .ok_or("1周目でcheckpointが書かれていない")?
        .to_string();

    // 1周目は候補ゼロ（indexが空）なので判定コールを打たない。
    let first_recalled = events_named(&events(&first), "MemoryRecalled")
        .first()
        .cloned()
        .cloned()
        .ok_or("1周目にMemoryRecalledが出ていない")?;
    if first_recalled["candidates"] != 0 || first_recalled["injected"] != 0 {
        return Err(format!(
            "1周目は候補ゼロのはず（indexが空）: {first_recalled}"
        ));
    }

    // 2周目: 判定コールが1つ増える。**IDは実行時採番なので、ここで台本へ埋め込む。**
    let picks = serde_json::json!([{ "id": id, "relevant": true, "trust": "needs_verification" }]);
    let second = run_hiv(
        &ws,
        &data,
        &hiv_turns_with_recall(picks),
        "recall-injection-2",
    );
    require_success(&second, "R2の2周目")?;

    let evs = events(&second);
    let recalled = events_named(&evs, "MemoryRecalled");
    let recalled = recalled.first().ok_or("2周目にMemoryRecalledが出ていない")?;
    if recalled["candidates"] != 1 || recalled["injected"] != 1 {
        return Err(format!("記憶が注入されていない: {recalled}"));
    }
    if recalled["skipped"] != serde_json::Value::Null {
        return Err(format!("読出しがスキップされた: {recalled}"));
    }

    // **この機構の核心**: 注入した記憶がHypothesizeのリクエスト本文に載っているか。
    // 載っていなければ、イベント上は「注入した」のにモデルは何も見ていない（空振り）。
    let requests = recorded_requests(&second)?;
    if requests.len() < 2 {
        return Err(format!("記録されたリクエストが少なすぎる: {}", requests.len()));
    }
    let hypothesize = &requests[1];
    for needle in [
        "過去の記憶（要再検証）",
        id.as_str(),
        "run_shellはPowerShellを起動している",
        "未レビュー",
    ] {
        if !hypothesize.contains(needle) {
            return Err(format!(
                "Hypothesizeのプロンプトに{needle:?}が無い（注入が空振りしている）:\n{hypothesize}"
            ));
        }
    }
    // `trust: needs_verification`の機械的帰結（未決②）: 再検証項目がunknownsへ積まれる。
    if !hypothesize.contains("の内容を再検証する") {
        return Err(format!(
            "needs_verificationが再検証項目として積まれていない:\n{hypothesize}"
        ));
    }

    // 自己参照の遮断（設計変更B / BUG-077と同型）: 2件目のcheckpointに、注入した記憶の
    // 主張が本文として書き戻されていないこと。
    let mem_dir = memory_dir(&data)?;
    let files = checkpoint_files(&mem_dir);
    if files.len() != 2 {
        return Err(format!("2周目でcheckpointが2件になっていない: {files:?}"));
    }
    let newest = files
        .iter()
        .max_by_key(|p| p.file_name().unwrap().to_os_string())
        .unwrap();
    let body = std::fs::read_to_string(newest).map_err(|e| e.to_string())?;
    if body.contains(&format!("memory/{id}")) {
        return Err(format!(
            "注入した記憶が次のcheckpointへ書き戻されている（自己参照ループ）:\n{body}"
        ));
    }
    Ok(())
}

/// R3: `--cognition off`は記憶ディレクトリを1バイトも触らない（M13のバイト等価性の系）。
fn case_off_does_not_touch_memory() -> Result<(), String> {
    let ws = case_dir("off-untouched");
    let data = case_data_root("off-untouched");
    seed_workspace(&ws);

    // まず記憶を1件作る（触らないことを見るには、触れる対象が要る）。
    require_success(
        &run_hiv(&ws, &data, &hiv_turns(), "off-untouched-seed"),
        "R3の準備",
    )?;
    let mem_dir = memory_dir(&data)?;
    let before = snapshot(&mem_dir);
    let head_before = git_head(&mem_dir);

    let run = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &[text_turn("素朴ループの回答")],
        extra_args: &["--cognition", "off"],
        case_name: "off-untouched",
        path_override: None,
        cwd_spelling: None,
    });
    require_success(&run, "R3")?;

    let evs = events(&run);
    if !events_named(&evs, "MemoryRecalled").is_empty()
        || !events_named(&evs, "MemoryCheckpointed").is_empty()
    {
        return Err(format!("Offなのに記憶イベントが出た: {}", run.stdout));
    }
    let after = snapshot(&mem_dir);
    if before != after {
        return Err(format!(
            "Offなのに記憶ディレクトリが変わった:\nbefore={before:?}\nafter={after:?}"
        ));
    }
    if head_before != git_head(&mem_dir) {
        return Err("Offなのにgit HEADが動いた".to_string());
    }
    Ok(())
}

/// R4: `Blocked`（スキーマ枯渇）では書かない（確定①）。
fn case_blocked_writes_nothing() -> Result<(), String> {
    let ws = case_dir("blocked-writes-nothing");
    let data = case_data_root("blocked-writes-nothing");
    seed_workspace(&ws);

    // Hypothesizeがスキーマに通らない出力を返し続ける（`max_schema_retries = 2`なので
    // 3回で枯渇して`Blocked`。台本は多めに積んでおく）。
    let turns: Vec<Vec<StreamEvent>> = (0..4).map(|_| text_turn("これはJSONではない")).collect();
    let run = run_hiv(&ws, &data, &turns, "blocked-writes-nothing");
    // `Blocked`は`StopReason::Other("cognition_blocked")`＝終了コード4（`exit_code_for`）。
    // プロセスは落ちず、台帳に残った範囲を回答として返す。
    if run.status.code() != Some(4) {
        return Err(format!(
            "Blockedの終了コードが4でない: {:?}\n{}\n{}",
            run.status.code(),
            run.stdout,
            run.stderr
        ));
    }

    let evs = events(&run);
    // 読出しは走る（＝Recallは有効）が、書込みは1件も起きない。
    if events_named(&evs, "MemoryRecalled").is_empty() {
        return Err("Recallが無効な状態で測っている（MemoryRecalledが無い）".to_string());
    }
    let checkpointed = events_named(&evs, "MemoryCheckpointed");
    if !checkpointed.is_empty() {
        return Err(format!(
            "Blockedなのに書込みが走った: {checkpointed:?}"
        ));
    }
    // 読出しだけでは記憶ディレクトリを作らない（`open`＝作成は書込み経路にしか無い）ので、
    // 「ディレクトリが無い」か「あってもcheckpointが0件」のどちらかであればよい。
    if let Ok(mem_dir) = memory_dir(&data) {
        let files = checkpoint_files(&mem_dir);
        if !files.is_empty() {
            return Err(format!("Blockedなのにcheckpointが増えた: {files:?}"));
        }
    }
    Ok(())
}

/// R6: `remember`（`RiskClass::Write`）はheadless既定で拒否される。
fn case_remember_is_denied_by_default() -> Result<(), String> {
    let ws = case_dir("remember-denied");
    let data = case_data_root("remember-denied");

    let run = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &[
            tool_use_turn(
                "call_1",
                "recall",
                serde_json::json!({ "action": "remember", "text": "覚えてはいけない" }),
            ),
            text_turn("拒否された"),
        ],
        extra_args: &["--cognition", "off"],
        case_name: "remember-denied",
        path_override: None,
        cwd_spelling: None,
    });
    require_success(&run, "R6")?;

    let evs = events(&run);
    let finished = events_named(&evs, "ToolFinished");
    let denied = finished.iter().any(|f| {
        f["output"]["content"]
            .as_str()
            .is_some_and(|c| c.starts_with("permission denied by policy"))
    });
    if !denied {
        return Err(format!("rememberが拒否されていない: {}", run.stdout));
    }
    // 拒否されたのだから記憶ディレクトリ自体が作られていない。
    if memory_dir(&data).is_ok() {
        return Err("拒否されたのに記憶が書かれた".to_string());
    }
    Ok(())
}

/// R7/R17: allowlistで許可すれば`remember`が書ける。**パス風の入力を渡しても書込先は
/// ハーネス採番のIDに固定される**（入力からパスを一切受け取らない設計の実経路確認）。
fn case_remember_with_allowlist_writes_only_inside_checkpoints() -> Result<(), String> {
    let ws = case_dir("remember-allowed");
    let data = case_data_root("remember-allowed");

    // `arg_repr`は入力JSON全体（`serde_json`のオブジェクトはキー昇順）なので、
    // `{"action":"remember"`が前方一致の接頭辞になる。
    let run = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &[
            tool_use_turn(
                "call_1",
                "recall",
                serde_json::json!({
                    "action": "remember",
                    "text": "../../evil\r\n\\\\?\\C:\\Windows\\System32 を含む本文",
                    "tags": ["../../evil", "sandbox"]
                }),
            ),
            text_turn("記憶した"),
        ],
        extra_args: &[
            "--cognition",
            "off",
            "--allow",
            r#"recall:{"action":"remember"*"#,
        ],
        case_name: "remember-allowed",
        path_override: None,
        cwd_spelling: None,
    });
    require_success(&run, "R7")?;

    let evs = events(&run);
    let stored = events_named(&evs, "ToolFinished")
        .iter()
        .any(|f| f["output"]["content"].as_str().is_some_and(|c| c.contains("記憶した（cp-")));
    if !stored {
        return Err(format!("rememberが許可されなかった: {}", run.stdout));
    }

    let mem_dir = memory_dir(&data)?;
    let files = checkpoint_files(&mem_dir);
    if files.len() != 1 {
        return Err(format!("checkpointが1件でない: {files:?}"));
    }
    let name = files[0].file_name().unwrap().to_string_lossy().to_string();
    if !name.starts_with("cp-") {
        return Err(format!("IDがハーネス採番でない: {name}"));
    }
    // データルート直下（＝`checkpoints/`の外）に余計なファイルが生まれていないこと。
    let stray: Vec<_> = std::fs::read_dir(&data)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.path())
        .collect();
    if !stray.is_empty() {
        return Err(format!("記憶ディレクトリの外にファイルが出た: {stray:?}"));
    }
    // タグは検索用としてそのまま載る（本文・タグは値であってパスではない）。
    let list = list_all(&ws, &data)?;
    if list[0]["tags"][0] != "../../evil" {
        return Err(format!("タグが保存されていない: {list:?}"));
    }
    Ok(())
}

/// R8: `search`は「indexが0件」と「N件あるが閾値未満」を区別して報告する（B-12）。
fn case_search_distinguishes_empty_from_miss() -> Result<(), String> {
    let ws = case_dir("search-messages");
    let data = case_data_root("search-messages");
    seed_workspace(&ws);

    let empty = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &[
            tool_use_turn(
                "call_1",
                "recall",
                serde_json::json!({ "action": "search", "query": "何か過去の知見" }),
            ),
            text_turn("記憶なし"),
        ],
        extra_args: &["--cognition", "off"],
        case_name: "search-empty",
        path_override: None,
        cwd_spelling: None,
    });
    require_success(&empty, "R8（空index）")?;
    let empty_msg = tool_output(&empty, "recall")?;
    if !empty_msg.contains("まだ記憶が無い") {
        return Err(format!("空indexの文言が違う: {empty_msg}"));
    }

    // 1件書いてから、まったく無関係な語で検索する。
    require_success(
        &run_hiv(&ws, &data, &hiv_turns(), "search-seed"),
        "R8の準備",
    )?;
    let miss = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &[
            tool_use_turn(
                "call_1",
                "recall",
                serde_json::json!({ "action": "search", "query": "ZZZZQQQQ_XYZW" }),
            ),
            text_turn("該当なし"),
        ],
        extra_args: &["--cognition", "off"],
        case_name: "search-miss",
        path_override: None,
        cwd_spelling: None,
    });
    require_success(&miss, "R8（閾値未満）")?;
    let miss_msg = tool_output(&miss, "recall")?;
    if !miss_msg.contains("1件の記憶を検索したが") {
        return Err(format!("閾値未満の文言が違う（件数を報告していない）: {miss_msg}"));
    }
    Ok(())
}

/// 指定ツールの`ToolFinished`出力本文。
fn tool_output(run: &HarnessRun, tool: &str) -> Result<String, String> {
    let evs = events(run);
    let proposed: Vec<String> = events_named(&evs, "ToolCallProposed")
        .iter()
        .filter(|p| p["name"] == tool)
        .filter_map(|p| p["id"].as_str().map(str::to_string))
        .collect();
    events_named(&evs, "ToolFinished")
        .iter()
        .find(|f| f["id"].as_str().is_some_and(|id| proposed.iter().any(|p| p == id)))
        .and_then(|f| f["output"]["content"].as_str().map(str::to_string))
        .ok_or_else(|| format!("{tool}のToolFinishedが無い: {}", run.stdout))
}

/// R9/R10: index自己修復と、index由来IDのトラバーサル拒否（設計変更D、P-01）。
fn case_index_self_repair_and_traversal_rejection() -> Result<(), String> {
    let ws = case_dir("index-repair");
    let data = case_data_root("index-repair");
    seed_workspace(&ws);

    require_success(&run_hiv(&ws, &data, &hiv_turns(), "index-repair-1"), "R9の準備1")?;
    require_success(
        &run_hiv(
            &ws,
            &data,
            &hiv_turns_with_recall(serde_json::json!([])),
            "index-repair-2",
        ),
        "R9の準備2",
    )?;

    let mem_dir = memory_dir(&data)?;
    let files = checkpoint_files(&mem_dir);
    if files.len() != 2 {
        return Err(format!("準備で2件にならなかった: {files:?}"));
    }

    // (a) 本体だけを1件消す → 次の`list`が自己修復して1件になる。
    std::fs::remove_file(&files[0]).map_err(|e| e.to_string())?;
    let list = list_all(&ws, &data)?;
    if list.len() != 1 {
        return Err(format!("indexが自己修復していない: {list:?}"));
    }

    // (b) index由来のIDに`../`が混ざっていても、`checkpoints/`の外を読まない。
    let index_path = mem_dir.join("index.jsonl");
    let mut index = std::fs::read_to_string(&index_path).map_err(|e| e.to_string())?;
    index.push_str(
        &serde_json::json!({
            "id": "../../evil",
            "created_at_ms": 1u64,
            "tags": [],
            "summary": "traversal",
            "goal_excerpt": "",
            "sources": []
        })
        .to_string(),
    );
    index.push('\n');
    std::fs::write(&index_path, index).map_err(|e| e.to_string())?;

    let (ok, _stdout, stderr) = memory_cli(&ws, &data, &["show", "../../evil"]);
    if ok {
        return Err("トラバーサルIDの`memory show`が成功してしまった".to_string());
    }
    if !stderr.contains("unsafe id") {
        return Err(format!("拒否理由が報告されていない: {stderr}"));
    }
    // 一覧側も落ちない（不整合はrebuildで直る）。
    list_all(&ws, &data)?;
    Ok(())
}

/// R11: ウォーターマーク（既定listは未レビューのみ／`review --mark-reviewed`で進む）。
fn case_review_watermark() -> Result<(), String> {
    let ws = case_dir("review-watermark");
    let data = case_data_root("review-watermark");
    seed_workspace(&ws);

    require_success(&run_hiv(&ws, &data, &hiv_turns(), "watermark-1"), "R11の準備1")?;
    require_success(
        &run_hiv(
            &ws,
            &data,
            &hiv_turns_with_recall(serde_json::json!([])),
            "watermark-2",
        ),
        "R11の準備2",
    )?;

    let (ok, before, _) = memory_cli(&ws, &data, &["list"]);
    if !ok || before.lines().filter(|l| l.contains("cp-")).count() != 2 {
        return Err(format!("未レビュー2件が並ばない: {before}"));
    }
    if !before.contains("(unreviewed)") {
        return Err(format!("未レビュー表記が無い: {before}"));
    }

    let (ok, marked, stderr) = memory_cli(&ws, &data, &["review", "--mark-reviewed"]);
    if !ok || !marked.contains("marked 2 checkpoint(s) as reviewed.") {
        return Err(format!("review --mark-reviewedが効かない: {marked}{stderr}"));
    }

    let (ok, after, _) = memory_cli(&ws, &data, &["list"]);
    if !ok || !after.contains("no unreviewed checkpoints.") {
        return Err(format!("ウォーターマークが進んでいない: {after}"));
    }
    let (ok, all, _) = memory_cli(&ws, &data, &["list", "--all"]);
    if !ok || all.lines().filter(|l| l.contains("cp-")).count() != 2 {
        return Err(format!("--allで2件見えない: {all}"));
    }
    if all.contains("(unreviewed)") {
        return Err(format!("レビュー済みなのに未レビュー表記が残る: {all}"));
    }
    Ok(())
}

/// R12: gitが無い環境では**書かずに理由を報告し、ゴールは止めない**（fail-open、B-10）。
/// 併せて、プロジェクト層から`allow_unversioned`を有効化できないこと（D-49同型クランプ）。
fn case_git_absent_is_reported_and_project_cannot_opt_in() -> Result<(), String> {
    let ws = case_dir("git-absent");
    let data = case_data_root("git-absent");
    seed_workspace(&ws);
    std::fs::create_dir_all(ws.join(".harness")).map_err(|e| e.to_string())?;
    std::fs::write(
        ws.join(".harness").join("settings.json"),
        serde_json::json!({ "cognition": { "recall": { "allow_unversioned": true } } }).to_string(),
    )
    .map_err(|e| e.to_string())?;

    // `git`を解決できないPATHで起動する（`which::which("git")`が失敗する状態）。
    let run = run_harness(RunSpec {
        ws: &ws,
        data_root: &data,
        turns: &hiv_turns(),
        extra_args: &["--cognition", "always"],
        case_name: "git-absent",
        path_override: Some(r"C:\Windows\System32;C:\Windows"),
        cwd_spelling: None,
    });
    require_success(&run, "R12（gitが無くてもゴールは完了する）")?;

    let evs = events(&run);
    let checkpointed = events_named(&evs, "MemoryCheckpointed");
    let ev = checkpointed.first().ok_or("MemoryCheckpointedが出ていない（無音）")?;
    if ev["id"] != serde_json::Value::Null {
        return Err(format!("gitが無いのに書かれた: {ev}"));
    }
    let skipped = ev["skipped"].as_str().unwrap_or_default();
    if !skipped.contains("git not found") {
        return Err(format!("スキップ理由が報告されていない: {ev}"));
    }
    // プロジェクト層の`allow_unversioned`は警告付きで無視される。
    if !run.stderr.contains("allow_unversioned") || !run.stderr.contains("ignoring") {
        return Err(format!(
            "プロジェクト層のallow_unversionedを無視した警告が出ていない:\n{}",
            run.stderr
        ));
    }
    if memory_dir(&data).is_ok_and(|d| !checkpoint_files(&d).is_empty()) {
        return Err("gitが無く未承認なのにcheckpointが書かれた".to_string());
    }
    Ok(())
}

/// R13: 撤収経路。`forget`は`--yes`必須、`gc`は一覧のみで削除しない（設計変更G、B-14）。
fn case_forget_and_gc() -> Result<(), String> {
    let ws = case_dir("forget-and-gc");
    let data = case_data_root("forget-and-gc");
    seed_workspace(&ws);
    require_success(&run_hiv(&ws, &data, &hiv_turns(), "forget-and-gc"), "R13の準備")?;
    let mem_dir = memory_dir(&data)?;

    // `gc`は一覧するだけで消さない。
    let (ok, listing, _) = memory_cli(&ws, &data, &["gc"]);
    if !ok || !listing.contains("1 checkpoint(s)") {
        return Err(format!("gcの一覧が出ない: {listing}"));
    }
    let (ok_yes, _, warn) = memory_cli(&ws, &data, &["gc", "--yes"]);
    if !ok_yes || !warn.contains("not implemented") {
        return Err(format!("gc --yesが未実装である旨を言わない: {warn}"));
    }
    if !mem_dir.exists() {
        return Err("gcが記憶を削除した（既定で削除しない約束に反する）".to_string());
    }

    // `forget`は`--yes`が無ければ何もしない。
    let (ok, _, stderr) = memory_cli(&ws, &data, &["forget"]);
    if ok {
        return Err("forgetが--yes無しで成功した".to_string());
    }
    if !stderr.contains("--yes") || !mem_dir.exists() {
        return Err(format!("forgetが--yes無しで消した/理由を言わない: {stderr}"));
    }

    let (ok, out, stderr) = memory_cli(&ws, &data, &["forget", "--yes"]);
    if !ok || !out.contains("forgot all checkpoints") {
        return Err(format!("forget --yesが失敗した: {out}{stderr}"));
    }
    if mem_dir.exists() {
        return Err("forget --yesの後も記憶ディレクトリが残っている".to_string());
    }
    Ok(())
}

/// R14: 綴り違い（大小・区切り・末尾）の`--cwd`が同じ記憶を指す（設計変更E、B-19）。
fn case_spelling_variants_share_one_store() -> Result<(), String> {
    let ws = case_dir("spelling");
    let data = case_data_root("spelling");
    seed_workspace(&ws);
    require_success(&run_hiv(&ws, &data, &hiv_turns(), "spelling"), "R14の準備")?;

    // `C:\harness-e2e\recall\spelling` → `c:/harness-e2e/recall/spelling/`
    let variant = format!(
        "{}/",
        ws.to_string_lossy().replace('\\', "/").to_lowercase()
    );
    let mut cmd = Command::new(harness_exe());
    cmd.arg("--cwd")
        .arg(&variant)
        .args(["memory", "list", "--all", "--output-format", "json"]);
    cmd.env("HARNESS_RECALL_DATA_ROOT", &data);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "綴り違いの--cwdでmemory listが失敗した: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let list: Vec<serde_json::Value> =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
            .map_err(|e| format!("JSONではない: {e}"))?;
    if list.len() != 1 {
        return Err(format!("綴り違いで同じ記憶が見えない: {list:?}"));
    }
    // 2つ目のworkspace-keyディレクトリが増えていないこと（`memory_dir`が1つだけを要求する）。
    memory_dir(&data)?;
    Ok(())
}

/// R15: 記憶ディレクトリに仕込んだgitフックは発火しない（設計変更A、`hardening_env`）。
/// 単体テスト（`recall/git.rs::hooks_do_not_fire`）はtempdirでの確認なので、
/// **本番の置き場・本番の書込経路での実証はここが初めて**。
fn case_git_hooks_do_not_fire() -> Result<(), String> {
    let ws = case_dir("git-hooks");
    let data = case_data_root("git-hooks");
    seed_workspace(&ws);
    require_success(&run_hiv(&ws, &data, &hiv_turns(), "git-hooks-1"), "R15の準備")?;

    let mem_dir = memory_dir(&data)?;
    let hooks_dir = mem_dir.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).map_err(|e| e.to_string())?;
    let marker = mem_dir.join("HOOK_FIRED");
    std::fs::write(
        hooks_dir.join("post-commit"),
        format!(
            "#!/bin/sh\necho fired > \"{}\"\n",
            marker.to_string_lossy().replace('\\', "/")
        ),
    )
    .map_err(|e| e.to_string())?;

    // 2周目の書込み＝2回目のcommitでフックが呼ばれ得る。
    require_success(
        &run_hiv(
            &ws,
            &data,
            &hiv_turns_with_recall(serde_json::json!([])),
            "git-hooks-2",
        ),
        "R15の2周目",
    )?;
    if checkpoint_files(&mem_dir).len() != 2 {
        return Err("2周目の書込みが起きていない（フック検査が空振り）".to_string());
    }
    if marker.exists() {
        return Err("post-commitフックが発火した（gitハードニングが効いていない）".to_string());
    }
    Ok(())
}

// ============================================================================
// 実行ドライバ
// ============================================================================

#[test]
#[ignore]
fn recall_e2e_matrix() {
    let cases: Vec<(&str, CaseFn)> = vec![
        ("R1-write-on-decide", case_write_on_decide),
        ("R2-recall-injection", case_recall_injection_reaches_the_prompt),
        ("R3-off-untouched", case_off_does_not_touch_memory),
        ("R4-blocked-writes-nothing", case_blocked_writes_nothing),
        ("R6-remember-denied", case_remember_is_denied_by_default),
        (
            "R7-remember-allowlisted",
            case_remember_with_allowlist_writes_only_inside_checkpoints,
        ),
        ("R8-search-messages", case_search_distinguishes_empty_from_miss),
        (
            "R9R10-index-repair-and-traversal",
            case_index_self_repair_and_traversal_rejection,
        ),
        ("R11-review-watermark", case_review_watermark),
        (
            "R12-git-absent",
            case_git_absent_is_reported_and_project_cannot_opt_in,
        ),
        ("R13-forget-and-gc", case_forget_and_gc),
        ("R14-spelling-variants", case_spelling_variants_share_one_store),
        ("R15-git-hooks", case_git_hooks_do_not_fire),
    ];

    let total = cases.len();
    // BUG-056: フィルタが0件マッチでも`cargo test`はexit 0を返す。**実行件数を必ず印字する**。
    println!("running {total} recall e2e case(s)");
    let mut passed = 0;
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    // 全件緑のときだけ後始末する（失敗したケースは調査のため残す。`tier2a_e2e.rs`と同じ方針）。
    if passed == total {
        let _ = std::fs::remove_dir_all(CASE_ROOT);
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} recall e2e cases passed (see per-case JSON above)"
    );
}
