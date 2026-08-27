//! **標準出力は出力先ではなく契約である**（`bug-pattern-rules` `B-24`）を、機構で固定する。
//!
//! # 何を守るテストか
//!
//! `--output-format json` / `jsonl` を持つサブコマンドの標準出力は、人が読む画面ではなく
//! **パーサが読む契約**である。そこへ人間向けの行が1行混ざるだけでパースが落ちる。
//! これは2度起きた——[BUG-064](../../../docs/bugs/BUG-064.md)（自動撤収の報告がJSONの**前**へ）と
//! [BUG-131](../../../docs/bugs/BUG-131.md)（差分層の後片付けの報告がJSONの**後ろ**へ）。
//! どちらも既定の `text` 出力では自然に見えるので、**目視では止まらない**。
//!
//! # なぜプロセスを起動するのか（既存テストが構造的に検出できない理由）
//!
//! [`headless_output.rs`](headless_output.rs) は `run_headless` を**このプロセスの中**で呼び、
//! writer に `Vec<u8>` を渡して受け取る。だから**同じプロセスの他の場所が出した `println!` は
//! 実プロセスの標準出力へ出て、そのバッファには入らない**。BUG-064・BUG-131 がどちらも
//! 管理者権限の要る実機E2Eでしか捕まらなかったのは、これが機械的な理由である。
//!
//! ここでは**ビルド済みの `harness` バイナリを別プロセスとして起動し、標準出力を丸ごと
//! 受け取って**パースする（型は `harness-policy-editor/tests/show_cli.rs` から流用した）。
//! 管理者権限は要らず、`#[ignore]` も1件も付いていない——通常の `cargo test` で走ることが
//! このテストの成果物である。
//!
//! # 作法
//!
//! 1. **標準出力と標準エラー出力を分けて取り、標準出力だけをパースする。** 昇格して走ると
//!    `startup/parse_args.rs` が警告を1行 stderr へ出す（`dev-elevated-runner` 配下では必ず出る）。
//! 2. **対で固定する**（`B-35`）。`json`/`jsonl` が壊れないことだけでなく、**`text` では
//!    従来どおり人間向けの行が出る**ことも見る。片側だけだと「常に何も出さない」実装でも緑になる。
//! 3. **入力はすべて一時ディレクトリに収める。** 実マシン共有の台帳・`%LOCALAPPDATA%`・
//!    `%APPDATA%` を書き換えない（`mcp list` の承認台帳と `policy` の preflight 台帳は
//!    読むだけなので、`--source` で経路を限定して実マシンの中身に依存しないようにしてある）。
//!
//! # ここで守れない4つ（黙って落とすと網羅に見えるので、理由を書き残す）
//!
//! | 対象 | 起動できない理由 |
//! |---|---|
//! | `harness policy learn` | ETW収集器を昇格で起こすため **UACが1回出る**。加えて既定60秒スリープする |
//! | `harness cow audit` | 実 `%LOCALAPPDATA%\harness\data\cow\` を走査し、`--session` 省略時は「最新」を拾うので**他の実セッションと干渉する** |
//! | `harness memory list` | `store.open()` が実 `%APPDATA%` を作る。隔離には `e2e-test-hooks` feature と `HARNESS_TEST_RECALL_DATA_ROOT` が要る |
//! | ヘッドレス `-p` 経路 | `--provider mock` に `e2e-mock` feature が要る。加えて BUG-064 が住む `reconcile_fs_ledger_for_workspace` は、1行でも出力させるには**実マシン共有の `%APPDATA%\harness\config\fs-passthrough-ledger.json` に孤児エントリが必要**で、この台帳には注入口が一つも無い（`Ledger::in_config_dir` が `directories::ProjectDirs` 直結） |
//!
//! `policy learn` は D-43 の注記を出す3箇所目でもあるので、[BUG-134](../../../docs/bugs/BUG-134.md)
//! の3箇所のうち**ここで測れるのは2箇所**（`audit` と `suggest`）である。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use harness_change_ledger::{ChangeOp, CowOpEntry, COW_OPS_LEDGER_FILENAME};
use harness_core::{ContentBlock, Message, Role};

// ---------------------------------------------------------------------------
// 起動と観測
// ---------------------------------------------------------------------------

fn harness_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness")
}

/// 一時ワークスペース。
///
/// **中身が空のままであることを assert してはいけない**——`stage_parse_args` が
/// `ensure_project_settings_file` を無条件で呼ぶので `.harness/settings.json` が生える。
fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn run(ws: &Path, args: &[&str]) -> Output {
    Command::new(harness_exe())
        .arg("--cwd")
        .arg(ws)
        .args(args)
        .output()
        .expect("the harness binary should run")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// 失敗したときに**両方のストリームを見せる**。どちらが汚れているかが分からないと、
/// 「JSONではない」という報告だけでは原因に一歩も近づけない。
fn context(what: &str, out: &Output) -> String {
    format!(
        "{what}\n--- exit ---\n{:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status.code(),
        stdout_of(out),
        stderr_of(out)
    )
}

/// 標準出力**全体**が1つのJSONとして読めること。
fn parse_json_stdout(what: &str, out: &Output) -> serde_json::Value {
    let stdout = stdout_of(out);
    match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(e) => panic!(
            "{}",
            context(&format!("{what}: stdout is not valid JSON: {e}"), out)
        ),
    }
}

/// 標準出力の**空行を除く各行**が、それぞれ独立したJSONとして読めること。
fn parse_jsonl_stdout(what: &str, out: &Output) -> Vec<serde_json::Value> {
    let stdout = stdout_of(out);
    let mut parsed = Vec::new();
    for (idx, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(v) => parsed.push(v),
            Err(e) => panic!(
                "{}",
                context(
                    &format!("{what}: stdout line {} is not valid JSON: {e}", idx + 1),
                    out
                )
            ),
        }
    }
    parsed
}

// ---------------------------------------------------------------------------
// 入力を組み立てる（すべて一時ディレクトリの中）
// ---------------------------------------------------------------------------

const SESSION: &str = "stdoutcontract";

/// `--staged` のオーバーレイ置き場（`.harness/sandbox/session-<id>`）を作る。
/// `resolve_sandbox_dir` は純粋なFS走査なので、ここに置くだけで `changes`/`apply` が成立する。
fn staged_overlay(ws: &Path) -> PathBuf {
    let dir = ws
        .join(".harness")
        .join("sandbox")
        .join(format!("session-{SESSION}"));
    std::fs::create_dir_all(&dir).expect("staged overlay dir");
    dir
}

/// 操作台帳（`.harness-cow-ops.jsonl`）へ1行足す。
fn stage_ledger_entry(overlay: &Path, op: ChangeOp, rel: &str, baseline_hash: Option<&str>) {
    let entry = CowOpEntry {
        op,
        path: rel.to_string(),
        baseline_hash: baseline_hash.map(str::to_string),
        ts_unix_millis: 1_700_000_000_000,
    };
    let mut line = serde_json::to_string(&entry).expect("ledger entry");
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(overlay.join(COW_OPS_LEDGER_FILENAME))
        .expect("open ops ledger");
    file.write_all(line.as_bytes()).expect("append ops ledger");
}

/// 差分層側の実体と台帳エントリをまとめて置く。
fn stage_created_file(overlay: &Path, rel: &str, content: &str) {
    let path = overlay.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("overlay parent");
    }
    std::fs::write(&path, content).expect("overlay content");
    stage_ledger_entry(overlay, ChangeOp::Create, rel, None);
}

fn write_file(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("parent");
    }
    std::fs::write(path, content).expect("write");
}

/// ネットワーク監査ログ1本（拒否イベント2件）。`net audit --path` と
/// `policy audit/suggest --source net` の**両方の入力**になる。
fn write_net_audit_log(path: &Path) {
    let denied = concat!(
        r#"{"kind":"proxy","protocol":"socks5","host":"blocked.example","port":443,"#,
        r#""allowed":false,"reason":"domain_denied","timestamp_unix_ms":1700000000000}"#,
        "\n",
        r#"{"kind":"fake_dns","protocol":"dns_udp","host":"other.example","#,
        r#""allowed":false,"reason":"domain_denied","timestamp_unix_ms":1700000001000}"#,
        "\n",
    );
    write_file(path, denied);
}

/// `.harness/settings.json` を**先に**置く（`ensure_project_settings_file` は
/// ファイルが在れば何もしないので、雛形で上書きされない）。
fn write_project_settings(ws: &Path, value: serde_json::Value) {
    write_file(
        &ws.join(".harness").join("settings.json"),
        &serde_json::to_string_pretty(&value).expect("settings json"),
    );
}

// ---------------------------------------------------------------------------
// changes / apply
// ---------------------------------------------------------------------------

/// `harness changes` の3形式。`json` は配列1つ、`jsonl` は1件1行、`text` は人が読む行。
#[test]
fn changes_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = workspace();
    let overlay = staged_overlay(ws.path());
    stage_created_file(&overlay, "created.txt", "hello\n");

    let session = format!("session-{SESSION}");
    let json = run(
        ws.path(),
        &["changes", "--session", &session, "--output-format", "json"],
    );
    let value = parse_json_stdout("changes --output-format json", &json);
    let array = value.as_array().expect("changes json must be an array");
    assert_eq!(array.len(), 1, "{}", context("changes json", &json));
    assert_eq!(array[0]["path"], "created.txt");

    let jsonl = run(
        ws.path(),
        &["changes", "--session", &session, "--output-format", "jsonl"],
    );
    let lines = parse_jsonl_stdout("changes --output-format jsonl", &jsonl);
    assert_eq!(lines.len(), 1, "{}", context("changes jsonl", &jsonl));
    assert_eq!(lines[0]["path"], "created.txt");

    // 対の側。**人間向けの行が消えていないこと**を見る（B-35）。
    let text = run(
        ws.path(),
        &["changes", "--session", &session, "--output-format", "text"],
    );
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("create") && rendered.contains("created.txt"),
        "{}",
        context("changes text", &text)
    );
}

/// `harness apply` の3形式。**[BUG-132](../../../docs/bugs/BUG-132.md) の回帰テスト**——
/// `jsonl` が `text` と同じアームに畳まれていた頃は、ここで `applied: created.txt` という
/// 人間向けの行が1行目に出てパースが落ちる。
///
/// 6区分のうち3つ（`applied` / `hard_denied` / `conflicts`）を同時に出させているのは、
/// **`kind` の綴りが `json` 側のフィールド名と揃っていること**まで固定するためである。
#[test]
fn apply_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let session = format!("session-{SESSION}");

    // `apply` は実FSを書き換えて台帳を刈るので、形式ごとにワークスペースを作り直す。
    let build = |ws: &Path| {
        let overlay = staged_overlay(ws);
        stage_created_file(&overlay, "created.txt", "hello\n");
        // 層3 hard-deny（D-05）。実体は要らない——判定は内容を読む前に効く。
        stage_ledger_entry(&overlay, ChangeOp::Create, ".git/config", None);
        // baseline照合の相違（実workspace側が別物）。
        write_file(&ws.join("conflicted.txt"), "workspace side\n");
        stage_ledger_entry(
            &overlay,
            ChangeOp::Modify,
            "conflicted.txt",
            Some("0000000000000000"),
        );
    };

    let ws_json = workspace();
    build(ws_json.path());
    let json = run(
        ws_json.path(),
        &["apply", "--session", &session, "--output-format", "json"],
    );
    let report = parse_json_stdout("apply --output-format json", &json);
    assert_eq!(report["applied"], serde_json::json!(["created.txt"]));
    assert_eq!(report["hard_denied"], serde_json::json!([".git/config"]));
    assert_eq!(report["conflicts"], serde_json::json!(["conflicted.txt"]));

    let ws_jsonl = workspace();
    build(ws_jsonl.path());
    let jsonl = run(
        ws_jsonl.path(),
        &["apply", "--session", &session, "--output-format", "jsonl"],
    );
    let lines = parse_jsonl_stdout("apply --output-format jsonl", &jsonl);
    let mut seen: Vec<(String, String)> = lines
        .iter()
        .map(|l| {
            (
                l["kind"].as_str().unwrap_or_default().to_string(),
                l["path"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("applied".to_string(), "created.txt".to_string()),
            ("conflicts".to_string(), "conflicted.txt".to_string()),
            ("hard_denied".to_string(), ".git/config".to_string()),
        ],
        "{}",
        context("apply jsonl", &jsonl)
    );

    // 対の側。`text` では従来どおり人間向けの行が出る。
    let ws_text = workspace();
    build(ws_text.path());
    let text = run(
        ws_text.path(),
        &["apply", "--session", &session, "--output-format", "text"],
    );
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("applied: created.txt"),
        "{}",
        context("apply text", &text)
    );
    assert!(
        rendered.contains("hard-denied"),
        "{}",
        context("apply text", &text)
    );
    assert!(
        rendered.contains("conflict"),
        "{}",
        context("apply text", &text)
    );
}

// ---------------------------------------------------------------------------
// net audit
// ---------------------------------------------------------------------------

/// `harness net audit --path <file>`。`--path` がセッション解決を完全に迂回するので、
/// 一時ディレクトリのJSONL1本だけで成立する（最も安く撃てる対象）。
#[test]
fn net_audit_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = workspace();
    let log = ws.path().join("net-audit.jsonl");
    write_net_audit_log(&log);
    let log = log.to_string_lossy().into_owned();

    let json = run(
        ws.path(),
        &["net", "audit", "--path", &log, "--output-format", "json"],
    );
    let value = parse_json_stdout("net audit --output-format json", &json);
    assert_eq!(
        value.as_array().map(Vec::len),
        Some(2),
        "{}",
        context("net audit json", &json)
    );

    let jsonl = run(
        ws.path(),
        &["net", "audit", "--path", &log, "--output-format", "jsonl"],
    );
    let lines = parse_jsonl_stdout("net audit --output-format jsonl", &jsonl);
    assert_eq!(lines.len(), 2, "{}", context("net audit jsonl", &jsonl));
    assert_eq!(lines[0]["host"], "blocked.example");

    let text = run(
        ws.path(),
        &["net", "audit", "--path", &log, "--output-format", "text"],
    );
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("DENY") && rendered.contains("blocked.example"),
        "{}",
        context("net audit text", &text)
    );
}

// ---------------------------------------------------------------------------
// policy audit / suggest
// ---------------------------------------------------------------------------

/// `policy` 系は `--source net` に限定して撃つ。既定の `all` は preflight 経路で
/// **この開発機の実台帳**（`%APPDATA%\harness\config\fs-passthrough-ledger.json`）を読むため、
/// 出力がマシンの状態に依存してしまう。
fn policy_workspace() -> tempfile::TempDir {
    let ws = workspace();
    let overlay = staged_overlay(ws.path());
    write_net_audit_log(&overlay.join("net-audit.jsonl"));
    ws
}

#[test]
fn policy_audit_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = policy_workspace();
    let session = format!("session-{SESSION}");
    let args = |format: &'static str| {
        vec![
            "policy".to_string(),
            "audit".to_string(),
            "--session".to_string(),
            session.clone(),
            "--source".to_string(),
            "net".to_string(),
            "--output-format".to_string(),
            format.to_string(),
        ]
    };
    let run_policy = |format: &'static str| {
        let owned = args(format);
        let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
        run(ws.path(), &borrowed)
    };

    let json = run_policy("json");
    let value = parse_json_stdout("policy audit --output-format json", &json);
    assert_eq!(
        value.as_array().map(Vec::len),
        Some(2),
        "{}",
        context("policy audit json", &json)
    );

    let jsonl = run_policy("jsonl");
    let lines = parse_jsonl_stdout("policy audit --output-format jsonl", &jsonl);
    assert_eq!(lines.len(), 2, "{}", context("policy audit jsonl", &jsonl));

    let text = run_policy("text");
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("blocked.example"),
        "{}",
        context("policy audit text", &text)
    );
}

#[test]
fn policy_suggest_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = policy_workspace();
    let session = format!("session-{SESSION}");
    let run_policy = |format: &str| {
        run(
            ws.path(),
            &[
                "policy",
                "suggest",
                "--session",
                &session,
                "--source",
                "net",
                "--output-format",
                format,
            ],
        )
    };

    let json = run_policy("json");
    let value = parse_json_stdout("policy suggest --output-format json", &json);
    let proposals = value
        .as_array()
        .expect("policy suggest json must be an array");
    assert!(
        !proposals.is_empty(),
        "{}",
        context("policy suggest json", &json)
    );

    let jsonl = run_policy("jsonl");
    let lines = parse_jsonl_stdout("policy suggest --output-format jsonl", &jsonl);
    assert_eq!(
        lines.len(),
        proposals.len(),
        "{}",
        context("policy suggest jsonl", &jsonl)
    );

    let text = run_policy("text");
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("net.allow_domains"),
        "{}",
        context("policy suggest text", &text)
    );
}

/// **[BUG-134](../../../docs/bugs/BUG-134.md) の回帰テスト**（`audit` 側）。
///
/// 読めなかった経路の注記（D-43「読めなかった経路を隠さない」）は、`--output-format` が
/// 何であっても標準エラー出力へ出る。修正前は `text` のときだけ出しており、
/// `json`/`jsonl` では**標準エラー出力にすら出さず丸ごと捨てて**いた。
///
/// 対で見ることが要点で（`B-35`）、`text` 側だけを見ていると
/// 「常に黙る」実装でも `json` 側の assert が無いぶん緑になる。
#[test]
fn policy_audit_reports_unreadable_sources_on_stderr_in_every_output_format() {
    let ws = policy_workspace();
    let session = format!("session-{SESSION}");
    // `etw` 経路（`fs-audit.jsonl`）はセッションディレクトリに置いていないので読めない。
    let run_policy = |format: &str| {
        run(
            ws.path(),
            &[
                "policy",
                "audit",
                "--session",
                &session,
                "--source",
                "etw",
                "--output-format",
                format,
            ],
        )
    };

    for format in ["json", "jsonl", "text"] {
        let out = run_policy(format);
        assert!(
            stderr_of(&out).contains("no data from the 'etw' source"),
            "{}",
            context(
                &format!("policy audit --output-format {format}: the D-43 note must reach stderr"),
                &out
            )
        );
        // そして**標準出力は汚れていない**（注記がstdoutへ逃げていない）。
        if format != "text" {
            assert!(
                !stdout_of(&out).contains("no data from"),
                "{}",
                context("the note must not land on stdout", &out)
            );
        }
    }
}

/// 同じことを `suggest` 側でも見る。[BUG-134](../../../docs/bugs/BUG-134.md) は
/// **3箇所**にあり、`audit` を直しても `suggest` が残る形だった（`B-06`）。
#[test]
fn policy_suggest_reports_unreadable_sources_on_stderr_in_every_output_format() {
    let ws = policy_workspace();
    let session = format!("session-{SESSION}");
    for format in ["json", "jsonl", "text"] {
        let out = run(
            ws.path(),
            &[
                "policy",
                "suggest",
                "--session",
                &session,
                "--source",
                "etw",
                "--output-format",
                format,
            ],
        );
        assert!(
            stderr_of(&out).contains("no data from the 'etw' source"),
            "{}",
            context(
                &format!(
                    "policy suggest --output-format {format}: the D-43 note must reach stderr"
                ),
                &out
            )
        );
    }
}

// ---------------------------------------------------------------------------
// mcp list
// ---------------------------------------------------------------------------

/// `harness mcp list`。**[BUG-133](../../../docs/bugs/BUG-133.md) の回帰テスト**——
/// `jsonl` が `json` と同じアームで `to_string_pretty`（＝複数行）を出していた頃は、
/// 1行目の `{` だけでパースが落ちる。
#[test]
fn mcp_list_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = workspace();
    write_project_settings(
        ws.path(),
        serde_json::json!({
            "mcp": {
                "servers": [
                    { "id": "stdout-contract-a", "command": "node.exe", "args": ["a.js"] },
                    { "id": "stdout-contract-b", "command": "node.exe", "args": ["b.js"] }
                ]
            }
        }),
    );

    let json = run(ws.path(), &["mcp", "list", "--output-format", "json"]);
    let value = parse_json_stdout("mcp list --output-format json", &json);
    assert_eq!(
        value["servers"].as_array().map(Vec::len),
        Some(2),
        "{}",
        context("mcp list json", &json)
    );

    let jsonl = run(ws.path(), &["mcp", "list", "--output-format", "jsonl"]);
    let lines = parse_jsonl_stdout("mcp list --output-format jsonl", &jsonl);
    assert_eq!(lines.len(), 2, "{}", context("mcp list jsonl", &jsonl));
    assert_eq!(lines[0]["id"], "stdout-contract-a");
    assert_eq!(lines[1]["id"], "stdout-contract-b");

    let text = run(ws.path(), &["mcp", "list", "--output-format", "text"]);
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("stdout-contract-a") && rendered.contains("approval ledger:"),
        "{}",
        context("mcp list text", &text)
    );
}

// ---------------------------------------------------------------------------
// --list-sessions
// ---------------------------------------------------------------------------

/// `harness --list-sessions`。純粋なFS走査で、provider もサンドボックスも要らない。
#[test]
fn list_sessions_stdout_parses_in_json_and_jsonl_and_still_speaks_to_humans_in_text() {
    let ws = workspace();
    let user = Message {
        role: Role::User,
        content: vec![ContentBlock::Text(
            "ping from the stdout contract".to_string(),
        )],
    };
    let assistant = Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text("pong".to_string())],
    };
    let mut jsonl_body = String::new();
    for message in [&user, &assistant] {
        jsonl_body.push_str(&serde_json::to_string(message).expect("session line"));
        jsonl_body.push('\n');
    }
    write_file(
        &ws.path()
            .join(".harness")
            .join("sessions")
            .join("session-1700000000000.jsonl"),
        &jsonl_body,
    );

    let json = run(ws.path(), &["--list-sessions", "--output-format", "json"]);
    let value = parse_json_stdout("--list-sessions --output-format json", &json);
    let array = value.as_array().expect("session list must be an array");
    assert_eq!(array.len(), 1, "{}", context("list-sessions json", &json));
    assert_eq!(array[0]["message_count"], 2);

    let jsonl = run(ws.path(), &["--list-sessions", "--output-format", "jsonl"]);
    let lines = parse_jsonl_stdout("--list-sessions --output-format jsonl", &jsonl);
    assert_eq!(lines.len(), 1, "{}", context("list-sessions jsonl", &jsonl));
    assert_eq!(lines[0]["id"], "session-1700000000000");

    let text = run(ws.path(), &["--list-sessions", "--output-format", "text"]);
    let rendered = stdout_of(&text);
    assert!(
        rendered.contains("ping from the stdout contract"),
        "{}",
        context("list-sessions text", &text)
    );
}
