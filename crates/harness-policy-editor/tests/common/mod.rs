//! 位置ごとのドメインの E2E（`position_domains_e2e.rs`）・広げる遷移の E2E（`widening_transitions_e2e.rs`）・
//! 引数を固定した位置と Strict の辺の E2E（`split_strict_e2e.rs`）・パス2の E2E（`record_net_e2e.rs`・
//! `pass2_domains_e2e.rs`）が共有する部品。どのテストバイナリからも`mod common;`で取り込む
//! （`plans/position-domains/P5.md`の P5.7・P5.10.3、`P6.md`の P6.8）。
//!
//! # 置き場の注意
//!
//! Cargoは`tests/`直下のファイルだけをテストバイナリにするので、`tests/common/mod.rs`は
//! バイナリにならない（`tests/common.rs`にすると、それ自体が1本のテストバイナリになる）。
//! テストバイナリごとに使う項目が違うので、未使用の警告は抑える
//! （前例: `crates/harness-cli/tests/support/mod.rs`）。置き場の根の下の名前（ケース）は
//! 引数で受ける（同じ前例。ケースごとにワークスペースを分ける）。
//!
//! # 写した部品（`B-05`: 写しが片方だけ変わったら気付けるよう、写し元を書く）
//!
//! この試験は別クレートの`tests/`なので、`harness-cli`の試験の補助を呼べない。次を最小限で写した。
//!
//! - 模擬応答の1ターン（[`tool_use_turn`]・[`end_turn`]）: `crates/harness-cli/tests/tier2a_e2e.rs`の
//!   `tool_use_turn`（79行）・`end_turn`（100行）・`run_shell_script_turns`（132行）
//! - `harness.exe`の起こし方（[`run_arm`]）: 同`run_harness_driven`（301行）の`Driver::Mock`の引数の並びと
//!   `HARNESS_TEST_RECALL_DATA_ROOT`、`scripted_shell_rule_args`（149行。撃つ行を`--allow run_shell:<行>`に）
//! - 出力の読み方: 同`Outcome::first_tool_result`（513行。`tool_calls[0].result`だけを見る＝BUG-137）・
//!   `assert_prompt_sane`（461行。強制が効いている回にだけモデルへ見える`can_run_program`）
//! - 待ち行列の読み方: 同`run_arm_collecting_denials_in`（9235行。撃つ前に消す・あふれと読めない行で無効）
//! - 記録の起こし方: `tests/record_e2e.rs`（`record --workspace <ws> --cwd <ws> --limit 0 -- <行>`と
//!   `HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS=1`）
//! - 中の段のシェルを探す場所（[`middle_shell`]の`which::which("pwsh")`と`SystemRoot`）:
//!   `harness-sandbox`の`win_appcontainer/spawn.rs`の`shell_candidates`。**どれを外し、どれを最後に積むかの
//!   判断は写さず**、公開した`shell_candidates_from`を呼ぶ
//! - 宣言の取り消し（[`unapprove_all`]）: `tests/record_net_e2e.rs`の後片付け。広げる遷移の E2E が写したものを、
//!   引数を固定した位置の E2E（`split_strict_e2e.rs`）も使うのでここへ移した（P5.10.3）
//!
//! # 移してきた部品（写しではなく、ここが正本）
//!
//! - DACL の読み方（[`acl_sddl`]・[`count_sid_prefix`]）・パス2の CLI の撃ち方（[`record_net_cli`]）・
//!   `harness-netfilterd.exe`の置き方（[`place_netfilterd_next_to_the_test_binary`]）: `tests/record_net_e2e.rs`に
//!   あったものを、位置ごとのパス2の E2E（`pass2_domains_e2e.rs`）も使うのでそのまま移した（P6.8。3つ目の写しを作らない）

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_core::{BlockKind, CompletionRequest, StopReason, StreamEvent, Usage};
use harness_policy::policy_file;
use harness_policy::process_event::{
    parse_process_audit, ProcessAuditLog, ProcessInstance, PROCESS_AUDIT_FILE,
};
use harness_policy_editor::tui::state::App;
use harness_sandbox::tier2a::spawnd::client::DAEMON_STDERR_ENV;
use harness_sandbox::tier2a::spawnd::transitions::{pending_path, read_from, PendingRecord};
use harness_sandbox::tier2a::spawnd::{ChildProcessPolicy, DenyReason};
use harness_sandbox::tier2a::win_appcontainer::shell_candidates_from;

/// この試験の置き場の根（`tier2a_e2e.rs`の`CASE_ROOT`と同じ）。
pub const CASE_ROOT: &str = r"C:\harness-e2e";

/// e2e-mock でない`harness.exe`を見つけたときの文言（[`harness_exe`]）。
pub const BUILD_E2E_MOCK: &str =
    "先に `cargo build -p harness-cli --features e2e-mock` を実行してください";

pub fn editor_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness-policy-editor")
}

/// 模擬プロバイダつきの`harness.exe`（このテストの実行ファイルの2つ上＝`target/debug/`）。
///
/// **違うビルドを黙って撃たない**（`B-09`）。e2e-mock でないビルドは`--provider mock`を知らず、
/// 起動の引数エラーで落ちる——それを「遷移が断られた」と読まないよう、撃つ前に`--help`で確かめる。
pub fn harness_exe() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let dir = test_exe
        .parent()
        .and_then(Path::parent)
        .expect("target/debug/deps の2つ上");
    let exe = dir.join("harness.exe");
    assert!(exe.is_file(), "{} が無い。{BUILD_E2E_MOCK}", exe.display());
    let help = Command::new(&exe)
        .arg("--help")
        .output()
        .unwrap_or_else(|e| panic!("{} --help を起こせない: {e}", exe.display()));
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("--mock-turns"),
        "{} は e2e-mock でないビルド（`--help`に`--mock-turns`が無い）。{BUILD_E2E_MOCK}",
        exe.display()
    );
    exe
}

pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

pub fn system32(name: &str) -> String {
    format!(r"{}\System32\{name}", system_root())
}

/// 連鎖の中の段のシェル（[`middle_shell`]が選ぶ）。
pub struct MiddleShell {
    /// 実行ファイルのフルパス（行にそのまま書く）。
    pub path: String,
    /// 実行ファイル名（`pwsh.exe`／`powershell.exe`。木と辺の照合に使う）。
    pub exe: String,
    /// 割り当てで付くドメインの名前（葉名。`pwsh`／`powershell`）。
    pub domain: String,
}

/// 中の段のシェルを`harness.exe`と**同じ判断**で選ぶ（`B-05`）。強制の下では生成禁止を積むので
/// `ChildProcessPolicy::Restricted`で聞く——ストアアプリの`pwsh`は`dropped`へ回り（§S62）、
/// 先頭はストアアプリでない`pwsh`か、無ければ 5.1 になる。**選んだものと外したものを必ず出す**
/// （黙って 5.1 へ落ちると、`pwsh`の枝を撃ったのかどうかが記録から分からない。`B-10`）。
/// `harness.exe`の preflight と違って候補を起こして確かめはしない——起こせない先頭なら検算の腕が赤くなる。
pub fn middle_shell() -> MiddleShell {
    let choices = shell_candidates_from(
        which::which("pwsh").ok(),
        &system_root(),
        ChildProcessPolicy::Restricted,
    );
    if choices.dropped.is_empty() {
        println!("[position-domains] 中の段の候補から外した綴り: なし");
    }
    for dropped in &choices.dropped {
        println!(
            "[position-domains] 中の段の候補から外した綴り: {dropped}\
             （ストアアプリの綴りは遷移の強制の下で起こせない。§S62）"
        );
    }
    let (path, label) = choices
        .candidates
        .into_iter()
        .next()
        .expect("shell_candidates_from always yields at least PowerShell 5.1");
    let exe = file_name(&path);
    let domain = exe.strip_suffix(".exe").unwrap_or(&exe).to_string();
    println!("[position-domains] 中の段のシェル: {path}（{label}、ドメイン {domain}）");
    MiddleShell { path, exe, domain }
}

/// パスの最後の要素を小文字で（`C:/Windows/System32/cmd.exe` → `cmd.exe`）。
pub fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// 1本の`run_shell`の行（記録でも強制でも同じものを撃つ）。`name`は台本と要求の記録のファイル名に使う。
pub struct Script {
    pub name: &'static str,
    pub line: String,
}

/// 中の段のシェルに1行を撃たせる綴り。**実行ファイルも1行も PowerShell の単引用符の文字列にし、`&`で呼ぶ**
/// ——MSI の`pwsh`（`C:\Program Files\PowerShell\7\pwsh.exe`）はパスに空白を含むので、囲まないと割れる。
/// 単引用符の中で特別な文字は`'`だけ（`''`に重ねる）で、外の段が1重剥がしたものが次の段の`-Command`に届く。
/// 二重引用符は使わない——子へ渡すときの`"`の扱いが 5.1 と 7 で違う（`$PSNativeCommandArgumentPassing`）。
/// `-NoProfile -NonInteractive -Command`は`pwsh`と 5.1 で同じ綴りで通る。
pub fn ps_run(shell: &MiddleShell, rest: &str) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    format!(
        "& {} -NoProfile -NonInteractive -Command {}",
        quote(&shell.path),
        quote(rest)
    )
}

/// ケース専用ワークスペース。既存があれば作り直す（前回失敗の残骸を引き継がない）。
pub fn case_dir(case: &str) -> PathBuf {
    let dir = Path::new(CASE_ROOT).join(case);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create case workspace");
    dir
}

/// 台本・要求の記録・Recall の置き場（ワークスペースの外。緑なら消す）。
pub fn scratch_dir(case: &str) -> PathBuf {
    let dir = Path::new(CASE_ROOT).join("_scratch").join(case);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

// --- 記録（パス1） ---------------------------------------------------------------

/// パス1で`script`を1回記録し、記録のディレクトリを返す。木に「根 → 中の段 → `leaf`」の鎖が
/// あることを確かめる（**無ければ収集の失敗**。後の承認と強制の判定の前提が崩れる）。
pub fn record(
    ws: &Path,
    shell: &MiddleShell,
    script: &Script,
    leaf_output: &str,
    leaf: &str,
) -> PathBuf {
    let (dir, tree) = record_tree(ws, script, leaf_output);
    let root = scope_root(&tree);
    let middle = child_named(&tree.instances, root, &shell.exe);
    child_named(&tree.instances, middle, leaf);
    dir
}

/// 記録の根（`harness-policy-editor record`が起こした最初のシェル）。
pub fn scope_root(tree: &ProcessAuditLog) -> &ProcessInstance {
    tree.instances
        .iter()
        .find(|i| i.is_scope_root)
        .expect("記録の根が木にある")
}

/// パス1で`script`を1回記録し、記録のディレクトリと木を返す。記録の標準出力（小文字にしたもの）が
/// `expected_output`を含むことを確かめる（**無ければ記録の中で走るはずのものが走っていない**）。
/// 木の形は呼び出し側が確かめる（[`record`]は「根 → 中の段 → 葉」の1本）。
pub fn record_tree(
    ws: &Path,
    script: &Script,
    expected_output: &str,
) -> (PathBuf, ProcessAuditLog) {
    let before = record_dirs(ws);
    let output = Command::new(editor_exe())
        .args([
            "record",
            "--workspace",
            &ws.to_string_lossy(),
            "--cwd",
            &ws.to_string_lossy(),
            "--limit",
            "0",
            "--",
            &script.line,
        ])
        // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る（`record_e2e.rs`と同じ）。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .output()
        .expect("the policy editor binary should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!(
        "[position-domains] record {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        script.name
    );
    assert!(output.status.success(), "record が失敗した: {stderr}");
    assert!(
        stdout.to_ascii_lowercase().contains(expected_output),
        "記録の中で走るはずのものが走っていない（出力に {expected_output} が無い）"
    );

    let dir = record_dirs(ws)
        .difference(&before)
        .next()
        .cloned()
        .expect("新しい記録のディレクトリ");
    let text = std::fs::read_to_string(dir.join(PROCESS_AUDIT_FILE))
        .unwrap_or_else(|e| panic!("{PROCESS_AUDIT_FILE} が無い: {e}"));
    let tree = parse_process_audit(&text).expect("process-audit.jsonl starts with its header");
    for i in &tree.instances {
        eprintln!(
            "[position-domains] 木: seq={} parent={:?} ({:?}) root={} exe={:?} argv={:?}",
            i.seq, i.parent_seq, i.parent_seq_source, i.is_scope_root, i.image_path, i.argv
        );
    }
    (dir, tree)
}

/// `parent`の子で実行ファイル名が`name`のインスタンス（無ければ落とす）。
pub fn child_named<'a>(
    instances: &'a [ProcessInstance],
    parent: &ProcessInstance,
    name: &str,
) -> &'a ProcessInstance {
    instances
        .iter()
        .find(|i| {
            i.parent_seq == Some(parent.seq)
                && i.image_path.as_deref().map(file_name).as_deref() == Some(name)
        })
        .unwrap_or_else(|| {
            panic!(
                "木に {name} が {:?}（seq={}）の子として無い——収集の失敗（後の判定の前提が無い）",
                parent.image_path, parent.seq
            )
        })
}

/// 記録のディレクトリ（`record-session.json`を持つもの）の集合。
pub fn record_dirs(ws: &Path) -> BTreeSet<PathBuf> {
    let sandbox = ws.join(".harness").join("sandbox");
    std::fs::read_dir(&sandbox)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|dir| dir.join("record-session.json").is_file())
                .collect()
        })
        .unwrap_or_default()
}

pub fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

/// `policy.json`の辺を（遷移元, 実行ファイル名, 遷移先）で。
pub fn written_edges(ws: &Path) -> BTreeSet<(String, String, String)> {
    let file = policy_file::load(ws).expect("policy.json を読める");
    let mut edges = BTreeSet::new();
    for domain in &file.domains {
        for edge in &domain.process.transitions {
            let exe = match &edge.exe {
                harness_policy::transition::ExeMatcher::Literal(path) => file_name(path),
                other => panic!("エディタがリテラルでない辺を書いた: {other:?}"),
            };
            edges.insert((domain.name.clone(), exe, edge.to.clone()));
        }
    }
    edges
}

// --- 強制（harness.exe） ----------------------------------------------------------

/// 1本の腕の結果。
#[derive(Debug)]
pub struct Arm {
    /// `run_shell`の結果本文（`tool_calls[0].result`）。
    pub result: String,
    /// 待ち行列の Daemon の拒否（遷移元, 実行ファイル名, 理由）。同じ種類の更新行は畳む。
    pub denials: Vec<(Option<String>, String, DenyReason)>,
    /// Spawn Daemon の標準エラー（`DAEMON_STDERR_ENV`で張った受け皿）。Daemon はコンソールを持たないので、
    /// 張らないと起こし損ねた理由がどこにも届かない（`tier2a_e2e.rs`の`run_arm_collecting_denials_in`と同じ）。
    pub daemon_stderr: String,
    /// `harness.exe`の標準エラー（遷移先ドメインを用意できなかった警告などが出る）。
    pub harness_stderr: String,
}

impl Arm {
    /// 報告の材料（各腕の本文・拒否・Daemon と harness の標準エラー）を読める形で出す。
    pub fn print(&self, name: &str) {
        eprintln!(
            "[position-domains] --- 腕 {name} ---
拒否: {:?}
--- run_shell の本文 ---
{}
\r
             --- Daemon の標準エラー ---
{}
--- harness の標準エラー ---
{}
[position-domains] --- 腕 {name} ここまで ---",
            self.denials, self.result, self.daemon_stderr, self.harness_stderr
        );
    }
}

/// `script`を`run_shell`で1回撃つ。**撃つ前に`pending.jsonl`を消す**（前の腕の拒否を数えない）。
pub fn run_arm(harness: &Path, ws: &Path, case: &str, script: &Script) -> Arm {
    run_arm_with(harness, ws, case, script, &[])
}

/// [`run_arm`]に`harness.exe`の引数を足して撃つ（入口のドメインに通信を許す`--net-allow-domain`など）。
/// 足した引数は決まった引数の後ろに並ぶ。
pub fn run_arm_with(
    harness: &Path,
    ws: &Path,
    case: &str,
    script: &Script,
    extra_args: &[&str],
) -> Arm {
    let queue = pending_path(ws);
    let _ = std::fs::remove_file(&queue);
    let line = &script.line;
    let scratch = scratch_dir(case);
    let turns_path = scratch.join(format!("{}-turns.json", script.name));
    let record_path = scratch.join(format!("{}-requests.jsonl", script.name));
    let _ = std::fs::remove_file(&record_path);
    // **腕ごとに1本、撃つ前に消す**（前の腕の失敗を今の腕の説明として読まない）。
    let daemon_log = scratch.join(format!("{}-spawnd.log", script.name));
    let _ = std::fs::remove_file(&daemon_log);
    let turns = vec![
        tool_use_turn(
            "call_1",
            "run_shell",
            serde_json::json!({ "command": line }),
        ),
        end_turn("done"),
    ];
    std::fs::write(&turns_path, serde_json::to_string(&turns).unwrap()).expect("write turns");

    let output = Command::new(harness)
        .args([
            "--provider",
            "mock",
            "--mock-turns",
            turns_path.to_str().unwrap(),
            "--mock-record-requests",
            record_path.to_str().unwrap(),
            "--cwd",
            &ws.to_string_lossy(),
            "--permission-mode",
            "accept-all",
            "--dangerously-allow",
            "--output-format",
            "json",
            "-p",
            "(scripted; prompt text is ignored by the mock provider)",
            "--allow",
            &format!("run_shell:{line}"),
            "--sandbox",
            "tier2a",
            "--enforce-transitions",
        ])
        .args(extra_args)
        .env(
            "HARNESS_TEST_RECALL_DATA_ROOT",
            scratch.join("recall-memory"),
        )
        .env(DAEMON_STDERR_ENV, &daemon_log)
        .output()
        .expect("failed to spawn harness.exe");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "{}: harness.exe 自体が失敗した（{}）。**拒否ではなく起動の失敗である**: {stderr}",
        script.name,
        output.status
    );
    assert_enforcement_visible(&record_path, script.name);
    let outcome: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout が JSON でない: {e}\nstdout={stdout}\nstderr={stderr}"));
    let call = &outcome["tool_calls"][0];
    assert_eq!(
        call["decision"].as_str(),
        Some("allowed"),
        "{}: run_shell が許可の層で止まった（サンドボックスへ届いていない）: {call}\nstderr={stderr}",
        script.name
    );
    let result = call["result"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool_calls[0].result in outcome: {outcome}"))
        .to_string();

    Arm {
        result,
        denials: daemon_denials(ws, script.name),
        daemon_stderr: std::fs::read_to_string(&daemon_log).unwrap_or_default(),
        harness_stderr: stderr,
    }
}

/// 待ち行列（`pending.jsonl`）の Daemon の拒否を（遷移元, 実行ファイル名, 理由）で。同じ種類の更新行は畳む。
/// **読めない行・あふれ・カーネルの拒否は落とす**——断った一覧が欠けたまま「拒否は無い」と読まない（`B-09`）。
/// `name`は落としたときの文面に出す腕の名前。[`run_arm`]とパス2の E2E（`record_net_e2e.rs`・`pass2_domains_e2e.rs`）が使う。
pub fn daemon_denials(ws: &Path, name: &str) -> Vec<(Option<String>, String, DenyReason)> {
    let tail = read_from(&pending_path(ws), 0);
    assert_eq!(
        tail.skipped, 0,
        "{name}: 待ち行列の行が読めなかった（断った一覧が欠けている）"
    );
    let mut denials: Vec<(Option<String>, String, DenyReason)> = Vec::new();
    for record in &tail.records {
        let key = match record {
            PendingRecord::DeniedByDaemon(d) => {
                (d.from_domain.clone(), file_name(&d.exe), d.reason.clone())
            }
            PendingRecord::DeniedByKernel(d) => {
                panic!("{name}: カーネルの拒否が積まれた（今日これを書く者は居ないはず）: {d:?}")
            }
            PendingRecord::Overflowed { dropped, .. } => {
                panic!("{name}: 待ち行列が{dropped}件あふれた（断った一覧が欠けている）")
            }
        };
        if !denials.contains(&key) {
            denials.push(key);
        }
    }
    denials
}

/// 強制が効いている回にだけモデルへ見える`can_run_program`が、送ったシステムプロンプトにあるか
/// （`tier2a_e2e.rs`の`assert_prompt_sane`。旗が届いていないまま「通った」と読まない）。
pub fn assert_enforcement_visible(record_path: &Path, arm: &str) {
    let data = std::fs::read_to_string(record_path).unwrap_or_else(|e| {
        panic!(
            "{arm}: 要求の記録 {} を読めない: {e}",
            record_path.display()
        )
    });
    let first = data
        .lines()
        .next()
        .unwrap_or_else(|| panic!("{arm}: 模擬プロバイダが1度も呼ばれていない"));
    let request: CompletionRequest =
        serde_json::from_str(first).expect("recorded request is CompletionRequest JSON");
    let system: String = request
        .system
        .iter()
        .map(|b| b.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        system.contains("can_run_program"),
        "{arm}: システムプロンプトに can_run_program が無い——遷移の強制が効いていない回を撃っている"
    );
}

/// ツール呼び出しだけを返すターン（`tier2a_e2e.rs`の`tool_use_turn`の写し）。
pub fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
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

/// 文章だけを返して終わるターン（`tier2a_e2e.rs`の`end_turn`の写し）。
pub fn end_turn(text: &str) -> Vec<StreamEvent> {
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

/// この回だけの印（前の回の出力や台帳の残りを今回の証拠として読まない）。
pub fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{}_{nanos}", std::process::id())
}

/// パスを比べる形へ畳む（区切りを`/`、小文字）。
pub fn fold(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

/// 宣言した辺だけを撃つ腕で、待ち行列に拒否が積まれていないか（積まれていたら`failures`へ足す）。
pub fn expect_no_denials(failures: &mut Vec<String>, name: &str, arm: &Arm) {
    if !arm.denials.is_empty() {
        failures.push(format!(
            "{name}: 宣言した辺だけを撃つ腕で拒否が積まれた: {:?}",
            arm.denials
        ));
    }
}

// --- 後始末の確かめ ---------------------------------------------------------------

/// エディタの CLI でドメインの宣言を全部取り消す（`record_net_e2e.rs`の後片付けと同じ。取り消しは
/// 狭める向きなので`--auto-approve`で書ける）。ACE はここでは剥がさない——次の`harness.exe`の起動が剥がす。
pub fn unapprove_all(ws: &Path, domain: &str) {
    let output = Command::new(editor_exe())
        .args([
            "unapprove",
            "--workspace",
            &ws.to_string_lossy(),
            "--domain",
            domain,
            "--all",
            "--auto-approve",
        ])
        .output()
        .expect("unapprove should run");
    eprintln!(
        "[position-domains] unapprove {domain}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "unapprove {domain} が失敗した");
}

/// 対象パスのDACLをSDDL（セキュリティ記述子の文字列表現）で読む（`record_net_e2e.rs`からそのまま移した。P6.8）。
///
/// # なぜharnessの関数で数えないのか
///
/// ACEを**付ける**のも**数える**のも同じ関数だと、その関数が同じ向きに間違えていても
/// 緑になる。ここは「実マシンに何が残ったか」を測るところなので、**別の道具**（`Get-Acl`）で
/// 読み直す。同じ形の裏取りをD-84の実装でも行っている。
///
/// **限界**: SDDLは継承ACEと明示ACEを1つの文字列に並べる。ここで測る対象は
/// **新しく作ったファイル**で、capability SID（`S-1-15-3-`）や
/// AppContainerのpackage SID（`S-1-15-2-`）が最初から載っていることは無いため、
/// **測定前後の差**を見れば継承分と混ざらない。だから基準線を必ず先に取る。
pub fn acl_sddl(path: &Path) -> String {
    let script = format!(
        "(Get-Acl -LiteralPath '{}').Sddl",
        path.display().to_string().replace('\'', "''")
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("powershell.exe should run");
    assert!(
        output.status.success(),
        "Get-Acl failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// SDDLの中に現れる、指定した接頭辞を持つSIDの件数。
///
/// `S-1-15-3-`＝capability SID（宣言ごとの宛先SID、残課題#20の移行先）、
/// `S-1-15-2-`＝AppContainerのpackage SID（移行元。**移行後は0本でなければならない**）。
pub fn count_sid_prefix(sddl: &str, prefix: &str) -> usize {
    sddl.match_indices(prefix).count()
}

// --- パス2（`record-net`） -------------------------------------------------------------

/// パス2を CLI（`record-net`）で1回撃つ（`record_net_e2e.rs`の`run_record_net_with`をそのまま移した。P6.8）。
/// [決定68(2)] `--domain`は無い（パス2は常に入口から始める）。`flags`は`--enforce-net`等、`envs`は足す環境変数
/// （Spawn Daemon の標準エラーの受け皿`DAEMON_STDERR_ENV`など）。
///
/// 戻り値の2つ目は**撃ったエディタのプロセスID**——その回のセッションと遷移先ドメインの AppContainer
/// プロファイルの名前のトークンに入る（[`profiles_added_since`]が「自分が作った分」を見分けるのに使う）。
pub fn record_net_cli(
    workspace_root: &Path,
    command: &str,
    flags: &[&str],
    envs: &[(&str, &Path)],
) -> (std::process::Output, u32) {
    let child = Command::new(editor_exe())
        .arg("record-net")
        .args(flags)
        .args([
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--cwd",
            &workspace_root.to_string_lossy(),
            "--limit",
            "0",
            "--timeout",
            "120",
            "--",
            command,
        ])
        // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .envs(envs.iter().map(|(name, value)| (*name, *value)))
        // `output()`と同じ持ち方（標準入力は渡さない・出力は全部受ける）。プロセスIDを取るために`spawn`で起こす。
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the policy editor binary should run");
    let pid = child.id();
    (
        child
            .wait_with_output()
            .expect("the policy editor binary should finish"),
        pid,
    )
}

/// `NetfilterHandle::start`は`current_exe().parent()`の隣から`harness-netfilterd.exe`を探すが、
/// **統合テストのバイナリが置かれる`target/debug/deps/`にそれは無い**（cargoが実行ファイルを
/// 置くのは`target/debug/`）。ビルド済みCLIをサブプロセスとして起こす試験は影響を
/// 受けないが、ライブラリ（`record_net`）を直接呼ぶ試験は自分で置く必要がある
/// （`record_net_e2e.rs`からそのまま移した。P6.8）。
///
/// 実装は`harness-sandbox`側の`ensure_daemon_next_to_test_binary`と同型だが、あちらは
/// `#[cfg(test)]`のクレート内部関数なので参照できない（テスト専用の関数を製品APIとして
/// 公開する方が悪い）。**同じ理由で同じことをしている**ことをここに書いておく。
pub fn place_netfilterd_next_to_the_test_binary() {
    const NAME: &str = "harness-netfilterd.exe";
    let current = std::env::current_exe().expect("current_exe");
    let deps = current.parent().expect("deps dir");
    let target = deps.join(NAME);
    let source = deps.parent().expect("target/debug").join(NAME);
    assert!(
        source.exists(),
        "{} is missing; run `cargo build --workspace` first",
        source.display()
    );
    let same = (|| -> Option<bool> {
        let (a, b) = (
            std::fs::metadata(&source).ok()?,
            std::fs::metadata(&target).ok()?,
        );
        Some(a.len() == b.len() && a.modified().ok()? == b.modified().ok()?)
    })()
    .unwrap_or(false);
    if !same {
        std::fs::copy(&source, &target).unwrap_or_else(|e| {
            panic!(
                "failed to place a fresh {NAME} next to the test binary ({e}). If a previous \
                 harness-netfilterd.exe is still running, stop it and re-run."
            )
        });
    }
}

/// **このプロセスが起こした`harness-spawnd.exe`のプロセスID**（`Get-CimInstance Win32_Process`で読む）。
///
/// パス2は Spawn Daemon をパス2のたびに起こし直す（決定68 の前例の(3)）。エディタの持ち主（`SharedSpawnDaemon`）の中身は
/// 非公開なので、**製品の公開面を試験のために広げず、別の道具で数える**（[`acl_sddl`]と同じ考え方）。Daemon は
/// ホストが`CreateProcessW`で直接起こすので、親のプロセスIDはこの試験のプロセスになる（`spawnd/client.rs`の`launch_daemon`）。
/// **一覧を取れなかったことを「1つも無い」と読まない**（`B-09`）——`powershell.exe`が失敗したら落とす。
pub fn spawn_daemons_started_by_this_process() -> BTreeSet<u32> {
    let script = format!(
        "Get-CimInstance Win32_Process -Filter \"Name='harness-spawnd.exe' AND ParentProcessId={}\" | \
         ForEach-Object {{ $_.ProcessId }}",
        std::process::id()
    );
    let output = Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("powershell.exe should run");
    assert!(
        output.status.success(),
        "harness-spawnd.exe の一覧を取れない: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// `before`の後に増えた harness の族の AppContainer プロファイルを、**名前のトークンのプロセスIDが`pid`のもの**
/// （その回のパス2が作った分。トークンは`<pid>-<起動秒>`＝`session_profile::session_token`）と、**それ以外**に分ける。
///
/// それ以外は、同じ機で動いている別の作業ツリーの`harness.exe`などが作ったもので、この試験の後始末の判定に入れない
/// ——入れると、隣の実行が作った入れ物でこの試験が赤くなる（`plans/position-domains/P6.md`の P6.8 の注意）。
/// 呼び出し側は2つ目も記録に残すために出す。
pub fn profiles_added_since(before: &BTreeSet<String>, pid: u32) -> (Vec<String>, Vec<String>) {
    let ours = format!("{pid}-");
    harness_profiles()
        .difference(before)
        .cloned()
        .partition(|name| {
            harness_sandbox::tier2a::session_profile::token_of_profile(name)
                .is_some_and(|token| token.starts_with(&ours))
        })
}

/// このユーザーの AppContainer プロファイルのうち、harness の族（セッション・MCP・遷移先ドメイン）の名前。
///
/// 族の見分けは`harness_sandbox`の`token_of_profile`に聞く（接頭辞を写さない、`B-05`）。
/// **一覧を取れなかったことを「1つも無い」と読まない**（`B-09`）——`reg`が失敗したら落とす。
pub fn harness_profiles() -> BTreeSet<String> {
    let output = Command::new(system32("reg.exe"))
        .args([
            "query",
            r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings",
            "/s",
            "/v",
            "Moniker",
        ])
        .output()
        .expect("reg.exe を起こせない");
    assert!(
        output.status.success(),
        "AppContainer プロファイルの一覧を取れない: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("Moniker"), Some("REG_SZ"), Some(name)) => Some(name.to_string()),
                _ => None,
            }
        })
        .filter(|name| harness_sandbox::tier2a::session_profile::token_of_profile(name).is_some())
        .collect()
}

/// 通信の宣言（`net.allow_domains`）をこのマシンの承認台帳へ記録する／消す（決定69(2)）。
///
/// **`harness.exe`とパス2はどちらも承認済みの宣言しか通さない**ので、強制を測る試験は先に
/// ここを通す。製品の経路（エディタの`approve`・`approve-declared`・宣言画面の`y`）と同じ
/// 台帳へ直接書く——測りたいのは強制の振る舞いで、承認の操作そのものは単体試験が見ている。
///
/// **付与と撤収を1つの関数にまとめてよいのは、どちらを行うかが引数で決まるからである**
/// （環境変数で切り替えると「撤収したつもりで付与していた」が無言で起きる＝`CLAUDE.md`）。
/// 残った分（台帳へ書けなかった宣言）を返すので、**呼ぶ側が空を確かめること**。
pub fn net_approval_in_ledger(
    workspace_root: &Path,
    declarations: &[(&str, &str)],
    approve: bool,
) -> Vec<String> {
    use harness_sandbox::tier2a::policy_approval::{DeclarationRef, PolicyApprovalStore};
    if declarations.is_empty() {
        return Vec::new();
    }
    let refs: Vec<DeclarationRef<'_>> = declarations
        .iter()
        .map(|(domain, value)| DeclarationRef {
            domain,
            value,
            key: harness_policy::generalize::SettingsKey::NetAllowDomains,
        })
        .collect();
    let store = PolicyApprovalStore::in_config_dir();
    let left = if approve {
        store.approve(workspace_root, &refs)
    } else {
        store.revoke(workspace_root, &refs)
    };
    left.iter().map(|d| format!("{d:?}")).collect()
}

/// 通信の宣言を承認する。**書けなければ落ちる**（承認が無いと強制の試験は何も測れない）。
pub fn approve_net_in_ledger(workspace_root: &Path, declarations: &[(&str, &str)]) {
    let left = net_approval_in_ledger(workspace_root, declarations, true);
    assert!(left.is_empty(), "通信の宣言を台帳へ記録できない: {left:?}");
}

/// 承認を台帳から消す（**付与と撤収の対**。`B-01`）。一時ワークスペースの承認を残すと、
/// 実在しない置き場の行が台帳に積もる。
pub fn revoke_net_in_ledger(workspace_root: &Path, declarations: &[(&str, &str)]) {
    let left = net_approval_in_ledger(workspace_root, declarations, false);
    assert!(left.is_empty(), "通信の宣言の承認を台帳から消せない: {left:?}");
}
