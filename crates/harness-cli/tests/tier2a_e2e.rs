//! Tier2a（AppContainer）のout-of-process E2E回帰テスト。CoWコミット粒度とネットワーク
//! ドメインポリシーの強制機構を、実`harness.exe`（`env!(CARGO_BIN_EXE_harness)`）を起動して
//! 検証する。LLM推論は使わない（`--provider mock`、`harness_providers::MockProvider`が
//! 台本化された道具呼び出しを返す）。**例外は1本だけ**——段5の測定の実プロバイダの腕
//! （`tier2a_cow_change_census_lmstudio`）がローカルのLMStudioを呼ぶ。これは`e2e-live`
//! featureの下でしかコンパイルされず、`e2e-all`（`e2e-mock`だけを立てる）には入らない。
//!
//! 実行方法・前提条件は`docs/DEV-ENVIRONMENT.md`「Tier2a E2Eテストの実行方法」参照。
//! 実AppContainer・実CoW 差分層ディレクトリ・（ネット側は）実インターネット到達性を使う
//! 重い/副作用ありのテストのため、既定の`cargo test`では走らない（`#[ignore]`、
//! `crates/harness-sandbox/src/win_appcontainer.rs`の既存規約と同じ）。
//!
//! ワークスペースは`C:\harness-e2e\<case>\`固定（`%TEMP%`を使うと`preflight`がプロファイル
//! 全階層のtraverse ACEを恒久付与し、保護対象の`traverse-grant-ledger.json`を汚すため、
//! `docs/STATUS.md`「Tier2a起動時のtraverse ACE自動付与（D-31）」参照）。成功したケースは
//! ワークスペース・CoW 差分層セッション・スクラッチファイルを削除する。失敗したケースは
//! 調査のため残す。

#![cfg(all(windows, feature = "e2e-mock"))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use harness_core::{BlockKind, CompletionRequest, StopReason, StreamEvent, Usage};

const CASE_ROOT: &str = r"C:\harness-e2e";

type CaseFn = fn() -> Result<(), String>;

/// CoWセッションを作る／読むケース専用。**排他の証（[`CowExclusive`]）を引数で要求する**
/// ので、排他ガードを取らずに書くことができない（BUG-135）。
///
/// [`CaseFn`]を替えずに別の型を立てているのは、あちらを6つの行列が共有していて、
/// 替えるとCoWと無関係なケースまで巻き込むため。
type CowCaseFn = fn(&CowExclusive) -> Result<(), String>;
/// fs passthrough台帳を触るケース。**排他ガードを引数で受け取る**——受け取れない形にすると、
/// 呼ぶ側が排他ガードを取り忘れても書けてしまう（[`CowCaseFn`]と同じ理由、BUG-135）。
type FsLedgerCaseFn = fn(&FsLedgerExclusive) -> Result<(), String>;

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

/// ケース専用のRecall記憶データルート（`HARNESS_TEST_RECALL_DATA_ROOT`）。書込み先を決める側と
/// 後始末する側が同じ式を使うための1関数（`bug-pattern-rules` B-01: 副作用を作ったら
/// 撤収も同じ変更で書く／B-05: 同じパスを2箇所に別々に書かない）。
fn recall_data_root(scratch: &Path, case_name: &str) -> PathBuf {
    scratch.join("recall-memory").join(case_name)
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
/// CoW 差分層へ捕まることを確認するための対照ケース）。
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

/// 台本に出てくる`run_shell`の行を、完全一致の規則（`--allow run_shell:<行>`）の引数にする。
///
/// accept-all でも`run_shell`は、承認した文字列と完全に一致し、字面に出るファイルの中身が同じときだけ
/// 自動で通る（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-102）。人のいない E2E は、撃つ行を規則として
/// 宣言する。**照合は緩めていない**——台本に無い行・T-09 の綴りを含む行は、従来どおり拒否される。
/// 規則は harness が起動した時点の中身で縛られる（D-104）ので、各ケースが起動直後に撃つ行と一致する。
fn scripted_shell_rule_args(turns: &[Vec<StreamEvent>]) -> Vec<String> {
    let mut out = Vec::new();
    for turn in turns {
        let mut shell_blocks: std::collections::BTreeMap<usize, String> = Default::default();
        for ev in turn {
            match ev {
                StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::ToolUse { name, .. },
                } if name == "run_shell" => {
                    shell_blocks.insert(*index, String::new());
                }
                StreamEvent::ToolInputDelta {
                    index,
                    json_fragment,
                } => {
                    if let Some(buf) = shell_blocks.get_mut(index) {
                        buf.push_str(json_fragment);
                    }
                }
                _ => {}
            }
        }
        for json in shell_blocks.values() {
            let input: serde_json::Value =
                serde_json::from_str(json).expect("scripted run_shell input is JSON");
            let command = input["command"]
                .as_str()
                .expect("scripted run_shell input has a command");
            out.push("--allow".to_string());
            out.push(format!("run_shell:{command}"));
        }
    }
    out
}

struct HarnessRun {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
    record_path: PathBuf,
    /// 起動の期限（[`Driver::Lmstudio`]の`deadline`）を過ぎて、こちらから止めたか。
    /// **止めた回の`status`は失敗だが、製品が失敗したのではない**——読む側が取り違えないよう
    /// 別の欄にしてある。mock の起動は期限を持たないので常に`false`。
    timed_out: bool,
}

/// 実`harness.exe`を`--provider mock`で起動する（Q1〜Q2: out-of-process統一、
/// featureゲート下のモック経路）。`--permission-mode accept-all --dangerously-allow`は
/// 台本化されたrun_shellをheadlessで実行するために必須（Defaultモードだと
/// Exec種別のrun_shellは拒否される、既存`headless_output.rs`参照）。
fn run_harness(
    ws: &Path,
    turns: &[Vec<StreamEvent>],
    extra_args: &[&str],
    case_name: &str,
) -> HarnessRun {
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
    run_harness_full(
        exe,
        &ws.to_string_lossy(),
        None,
        turns,
        extra_args,
        case_name,
        &[],
    )
}

/// `run_harness`の、**起こす`harness.exe`へ環境変数を足せる版**。
///
/// # なぜ環境変数の口が要るのか（2026-09-19）
///
/// 診断の受け皿には**プロセス環境でしか開かないもの**がある。実例が
/// `HARNESS_SPAWND_STDERR`（[`harness_sandbox::tier2a::spawnd::DAEMON_STDERR_ENV`]）で、
/// Spawn Daemonはコンソールを持たないため、**既定では書いた診断がどこにも届かない**。
///
/// **テストプロセス側で`std::env::set_var`しない。** あれはプロセス全体を変えるので、
/// 並行して走る他のケースが起こす`harness.exe`にも掛かる——ログが混ざった回と
/// 混ざらなかった回が区別できなくなる。**起こす1本だけに渡す。**
fn run_harness_with_env(
    ws: &Path,
    turns: &[Vec<StreamEvent>],
    extra_args: &[&str],
    case_name: &str,
    env: &[(&str, String)],
) -> HarnessRun {
    run_harness_full(
        &harness_exe(),
        &ws.to_string_lossy(),
        None,
        turns,
        extra_args,
        case_name,
        env,
    )
}

/// `--cwd`へ渡す**文字列**と、harnessプロセス自身のカレントディレクトリを別々に指定できる版
/// （[BUG-066](../../../docs/bugs/BUG-066.md)の追加検証）。
///
/// `--cwd`の綴りが揺れても製品全体が壊れないことを確かめるために要る。特に`--cwd .`は
/// 「ワークスペースへ`cd`してから起動する」という**利用者が実際に打つ形**であり、それを
/// 再現するにはプロセスのcwdを立てる必要がある（`cwd_for_process`）。
fn run_harness_full(
    exe: &Path,
    cwd_arg: &str,
    cwd_for_process: Option<&Path>,
    turns: &[Vec<StreamEvent>],
    extra_args: &[&str],
    case_name: &str,
    // 起こす`harness.exe`だけに足す環境変数（[`run_harness_with_env`]）。
    // **既定は`&[]`で、渡さない呼び出しの挙動は1ビットも変わらない。**
    env: &[(&str, String)],
) -> HarnessRun {
    run_harness_driven(
        exe,
        cwd_arg,
        cwd_for_process,
        Driver::Mock(turns),
        extra_args,
        case_name,
        env,
    )
}

/// 起こす`harness.exe`の**モデル側**。台本（mock）か、実プロバイダ（LMStudio）か。
///
/// 実プロバイダの腕は段5の測定（[`tier2a_cow_change_census_lmstudio`]）の1本だけが使う。
/// このファイルの他のテストは全部`Mock`で、LLM推論を使わない。
enum Driver<'a> {
    Mock(&'a [Vec<StreamEvent>]),
    /// **呼び出し側の環境変数は昇格デーモン配下の試験へ届かない**ので、接続先とモデル名は
    /// 引数で渡す（`OPENAI_BASE_URL`等に頼らない）。
    Lmstudio {
        base_url: &'a str,
        model: &'a str,
        prompt: &'a str,
        /// 期限を過ぎたら子を止めて[`HarnessRun::timed_out`]を立てる。`dev-elevated-run`の
        /// クライアントは応答を20分しか待たず、しかも cargo が終わるまで何も返さないので、
        /// 期限が無いと**途中までの結果ごと失う**。
        deadline: std::time::Duration,
    },
}

/// **CoWセッションを作る唯一の入口**（BUG-135）。[`run_harness_full`]も[`Driver`]を
/// 足しただけの包みで、ゲートはここにしか無い。
fn run_harness_driven(
    exe: &Path,
    cwd_arg: &str,
    cwd_for_process: Option<&Path>,
    driver: Driver<'_>,
    extra_args: &[&str],
    case_name: &str,
    env: &[(&str, String)],
) -> HarnessRun {
    // この関数が唯一であることは数えてある——このファイルで`"--sandbox"`を含む行は22行で、
    // 22行すべてが`run_harness`系（→[`run_harness_full`]）か段5の測定（[`run_census`]）を
    // 経由してここへ来る（数え方: `grep -n '"--sandbox"' tier2a_e2e.rs`からこのコメントの2行を
    // 除く。22行のうち2行はゲートの歯のテスト自身——mockの入口と[`Driver::Lmstudio`]の入口）。
    // 2026-09-27に数え直した（分割前のこのコメントは「16箇所」で、既に古くなっていた）。
    // `harness.exe`を直に起動している他の箇所は
    // 既存セッションを操作するサブコマンド（`apply`・`changes`・`discard`等）で、
    // `--sandbox`を渡さない＝差分層を新規に作らない。
    if extra_args.iter().any(|a| a.contains("tier2a-cow")) {
        assert_cow_exclusive_held("CoWセッションを作る（--sandbox tier2a-cow）");
    }

    let scratch = scratch_dir();
    let record_path = scratch.join(format!("{case_name}-requests.jsonl"));
    let _ = std::fs::remove_file(&record_path);

    let mut cmd = Command::new(exe);
    let turns_path = scratch.join(format!("{case_name}-turns.json"));
    // 引数の並びは`Mock`について分割前と1つも変えていない（プロバイダ → 共通 → `-p` → 規則 → 呼び出し側）。
    match &driver {
        Driver::Mock(_) => {
            cmd.args([
                "--provider",
                "mock",
                "--mock-turns",
                turns_path.to_str().unwrap(),
                "--mock-record-requests",
                record_path.to_str().unwrap(),
            ]);
        }
        Driver::Lmstudio {
            base_url, model, ..
        } => {
            cmd.args([
                "--provider",
                "lmstudio",
                "--base-url",
                *base_url,
                "--model",
                *model,
            ]);
        }
    }
    cmd.args([
        "--cwd",
        cwd_arg,
        "--permission-mode",
        "accept-all",
        "--dangerously-allow",
        "--output-format",
        "json",
    ]);
    let deadline = match &driver {
        Driver::Mock(turns) => {
            std::fs::write(&turns_path, serde_json::to_string(turns).unwrap())
                .expect("write turns file");
            cmd.args([
                "-p",
                "(scripted; prompt text is ignored by the mock provider)",
            ]);
            cmd.args(scripted_shell_rule_args(turns));
            None
        }
        Driver::Lmstudio {
            prompt, deadline, ..
        } => {
            cmd.args(["-p", *prompt]);
            Some(*deadline)
        }
    };
    cmd.args(extra_args);
    // Recall（`plans/PLAN-RECALL-MEMORY.md`）の記憶ディレクトリをケース専用のscratchへ逃がす。
    // `--cognition always`で回すケース（`run_cognition_harness`）はゴール完了時に
    // checkpointを書くため、これが無いと実`%APPDATA%\harness\data\memory\`へE2Eの
    // 残骸が溜まり続ける（`e2e-mock` featureが連れてくる`e2e-test-hooks`の逃がし口）。
    // ケース単位にするのは`cleanup_on_success`が他ケースの分を巻き込まず消せるようにするため。
    cmd.env(
        "HARNESS_TEST_RECALL_DATA_ROOT",
        recall_data_root(&scratch, case_name),
    );
    // **呼び出し側が明示したものは最後に載せる**（[`run_harness_with_env`]）。
    for (name, value) in env {
        cmd.env(name, value);
    }
    if let Some(dir) = cwd_for_process {
        cmd.current_dir(dir);
    }
    let Some(deadline) = deadline else {
        let output = cmd.output().expect("failed to spawn harness.exe");
        return HarnessRun {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            record_path,
            timed_out: false,
        };
    };
    let (status, stdout, stderr, timed_out) = wait_with_deadline(cmd, deadline);
    HarnessRun {
        status,
        stdout,
        stderr,
        record_path,
        timed_out,
    }
}

/// 子を起こし、期限までに終わらなければ止める。**stdout と stderr は別スレッドで読み切る**
/// ——片方の管が詰まると子が書込で止まり、期限まで「終わらない」ように見えるため。
fn wait_with_deadline(
    mut cmd: Command,
    deadline: std::time::Duration,
) -> (std::process::ExitStatus, String, String, bool) {
    use std::io::Read;
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn harness.exe");
    let mut out_pipe = child.stdout.take().expect("piped stdout");
    let mut err_pipe = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });
    let started = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll harness.exe") {
            break status;
        }
        if started.elapsed() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().expect("reap harness.exe after kill");
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    let stdout = String::from_utf8_lossy(&out_reader.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).to_string();
    (status, stdout, stderr, timed_out)
}

/// モックへ実際に送信された`CompletionRequest`を読み、BUG-030型
/// （システムプロンプト・ツールスキーマの送信漏れ）を直接検出する（Q9）。
fn assert_prompt_sane(run: &HarnessRun, must_contain: &[&str]) -> Result<(), String> {
    let data = std::fs::read_to_string(&run.record_path).map_err(|e| {
        format!(
            "failed to read recorded requests {}: {e}",
            run.record_path.display()
        )
    })?;
    let first_line = data.lines().next().ok_or_else(|| {
        "no CompletionRequest was recorded (mock provider never called?)".to_string()
    })?;
    let req: CompletionRequest = serde_json::from_str(first_line)
        .map_err(|e| format!("recorded request is not valid CompletionRequest JSON: {e}"))?;
    if req.system.is_empty() || req.system.iter().all(|b| b.text.trim().is_empty()) {
        return Err("BUG-030型の欠陥: system prompt が空/未送信".to_string());
    }
    if !req.tools.iter().any(|t| t.name == "run_shell") {
        return Err("run_shell がツール定義として送信されていない".to_string());
    }
    let system_text: String = req
        .system
        .iter()
        .map(|b| b.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for needle in must_contain {
        if !system_text.contains(needle) {
            return Err(format!(
                "system prompt に期待した文字列 {needle:?} が含まれていない（EnvironmentFactsの更新漏れの疑い）"
            ));
        }
    }
    Ok(())
}

/// `harness.exe --output-format json`の標準出力（`JsonOutcome`、`harness-cli/src/lib.rs`）。
///
/// **`Display`・`to_string`を意図的に実装していない**（[BUG-137](../../../docs/bugs/BUG-137.md)）。
/// このJSONには、子プロセスが**返した**結果（`tool_calls[].result`）と、子プロセスへ
/// **渡した**入力（`tool_calls[].input.command`＝実行したスクリプト本文）が**同居している**。
/// JSON全体を文字列にして`contains`に掛けると、探している語がスクリプト本文の側に当たり、
/// **子が何をしようと必ず真**になる。実際`WRITE=DENIED`・`DELETE=OK`・`MOVE=OK`の3判定が
/// 長期間そうなっており、`--fs-allow`の回帰（BUG-136）が2週間気付かれなかった一因になった。
///
/// 対策は「`contains`の前に一度考える」という規律ではなく、**探す先を選べなくすること**
/// （BUG-135の[`CowExclusive`]と同じ形）。見てよい場所は下の2つだけである。
struct Outcome(serde_json::Value);

impl Outcome {
    /// 子プロセスが返したstdout（`tool_calls[0].result`）。**振る舞いのassertはここに当てる。**
    ///
    /// 呼び出し側が`?`でも`panic!`でも受けられるよう`Result`を返す。エラー文言をここが
    /// 1つだけ持つので、生JSONを各呼び出し側でフォーマットする必要は無い。
    fn first_tool_result(&self) -> Result<&str, String> {
        self.0["tool_calls"]
            .get(0)
            .and_then(|c| c["result"].as_str())
            .ok_or_else(|| format!("no tool_calls[0].result in outcome: {}", self.0))
    }

    /// モデルの最終応答文（トップレベルの`result`）。認知レイヤーが組み立てた回答文を
    /// 見たいときはこちら——子プロセスのstdoutとは別物である。
    fn answer(&self) -> &str {
        self.0["result"].as_str().unwrap_or_default()
    }

    /// 道具呼び出しを**1件ずつ、欄を分けたまま**返す（段5の測定が、手順の各段が踏まれたかを
    /// 照合するのに使う）。入力（`input`）と子の出力（`result`）を**別の欄のまま**渡すので、
    /// 片方を探したつもりでもう片方に当たる形（BUG-137）にならない。
    fn tool_call_views(&self) -> Vec<ToolCallView> {
        self.0["tool_calls"]
            .as_array()
            .map(|calls| {
                calls
                    .iter()
                    .map(|c| ToolCallView {
                        name: c["name"].as_str().unwrap_or_default().to_string(),
                        input: c["input"].clone(),
                        decision: c["decision"].as_str().unwrap_or_default().to_string(),
                        result: c["result"].as_str().unwrap_or_default().to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 縮退ガードが捨てたLLMコールの数（`JsonOutcome::discarded_turns`）。
    fn discarded_turns(&self) -> u64 {
        self.0["discarded_turns"].as_u64().unwrap_or(0)
    }

    // 生JSONを返すメソッドは**置かない**。いま誰も要らないうえ、置けば
    // `raw().to_string().contains(..)`でBUG-137がそのまま復活する口になる。
    // 必要になった時点で、用途を限定した名前のメソッドとして足すこと。
}

/// [`Outcome::tool_call_views`]の1件。
struct ToolCallView {
    name: String,
    input: serde_json::Value,
    /// `"allowed"`・`"denied"`・`"invalid"`（`JsonToolCall::decision`）。
    decision: String,
    result: String,
}

impl ToolCallView {
    /// 道具が成功したか。`run_program`は結果末尾の`[exit code: N]`（**最後に出たもの**——
    /// 子が同じ綴りを印字しても、ハーネスのフッタは必ずその後ろに付く）、`write_file`は
    /// `wrote `で始まること。判定に進まなかった・拒否された呼び出しは成功ではない。
    fn succeeded(&self) -> bool {
        if self.decision != "allowed" {
            return false;
        }
        match self.name.as_str() {
            "run_program" => self
                .result
                .rfind("[exit code: ")
                .map(|i| self.result[i..].starts_with("[exit code: 0]"))
                .unwrap_or(false),
            "write_file" => self.result.starts_with("wrote "),
            _ => false,
        }
    }
}

fn parse_json_stdout(run: &HarnessRun) -> Result<Outcome, String> {
    serde_json::from_str(run.stdout.trim())
        .map(Outcome)
        .map_err(|e| {
            format!(
                "stdout is not valid JSON: {e}\nstdout={}\nstderr={}",
                run.stdout, run.stderr
            )
        })
}

// --- 共有資源の排他（[BUG-135](../../../docs/bugs/BUG-135.md)） ---------------------------
//
// 同じテストバイナリの`#[test]`は既定で別スレッドに並行実行される。このE2Eには
// **プロセスをまたいで共有されるもの**が4種類あり、同時に触ると互いを壊す。
//
//   1. 共有WFPエンジンとnetfilterdの単一インスタンス（ネットワーク行列）
//   2. ワークスペースの置き場 `C:\harness-e2e`
//   3. **このマシン上のCoWセッション（差分層）の一覧**
//   4. **`%APPDATA%\harness\config\fs-passthrough-ledger.json`**（[`FsLedgerExclusive`]が守る）
//
// 3番目が、長らく説明書きに**書かれていなかった**もの。各ケースは「起動の前後で一覧を
// 見比べて、増えた1件が自分のもの」という方法で自分のセッションを特定する
// （[`CowExclusive::new_cow_session`]）ので、隣が同時にセッションを作ると増えた件数が2に
// なって特定できない。理由が書かれていなかったため、
// `tier2a_cow_git_commit_writes_objects_under_the_redirector`はこのロックを取らないまま
// 追加され、全件を並行実行する`e2e-all`でだけ2本とも落ちた。
// **書いていない理由は次の人に伝わらない。**
//
// 対策は「触るテストを全部数えてロックを配る」ではなく、**数えなくてよくすること**。
//   (a) 一覧を読む側は[`CowExclusive`]のメソッドにした——排他ガードが無いと**そもそも書けない**
//   (b) 一覧を読まずにセッションを`作るだけ`の側は型で縛れないので、作る唯一の入口
//       （[`run_harness_full`]）に[`assert_cow_exclusive_held`]を置いた
//
// 4番目（台帳）は、**規約は書かれていたが機構が無かった**もの。`KNOWN_TARGETS`の
// `e2e-fs-ledger`には「保護対象の`fs-passthrough-ledger.json`を触るため、他のE2Eと同時に
// 走らせない」と書いてあるが、`e2e-all`は全件を既定の並列度で回すので**その規約は
// 誰にも守られていなかった**。`tier2a_fs_allow_matrix`と`tier2a_fs_ledger_lifecycle`が
// 同じ1ファイルへ無ロックのread-modify-writeを撃ち合い、(i) read-only属性の解除と再付与が
// 交差して書込が失敗する、(ii) 片方が読んだ古い内容を書き戻して相手のタグを復活させる、
// の2つが起きる。**規約を機構へ変える**のが[`FsLedgerExclusive`]で、台帳を読む/書く手段を
// その排他ガードのメソッドだけにしてある（(a)と同じ形）。
//
// **[`CowExclusive`]とは別のロックにしてある。** 守っている資源が違い、いま台帳を触る
// 2本はどちらもCoWセッションを作らないので、両方を同時に取るテストは存在しない
// （＝ロック順序による相互待ちが起きない）。両方が要るテストを書くときは、
// **必ず`cow_exclusive()`→`fs_ledger_exclusive()`の順**で取ること。

/// 上記1〜3の共有資源を直列化するロック。実機検証で、並行実行時にネットワーク行列が
/// `net_event_collection_enable_failed`等で不安定になることを確認している。
static CROSS_MATRIX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 上記4（fs passthrough台帳）を直列化するロック。
static FS_LEDGER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// いま[`CowExclusive`]を持っているスレッド。
///
/// **`AtomicBool`にしないこと。** 「誰かが持っている」と「自分が持っている」は別の事実で、
/// 前者で代用すると、排他ガードを持たないテストが**隣のテストの保持を自分の保持と読み違えて**
/// ゲートを素通りする。
static COW_EXCLUSIVE_OWNER: std::sync::Mutex<Option<std::thread::ThreadId>> =
    std::sync::Mutex::new(None);

/// 共有資源を触ってよいことの証。**取得手段はこの関数だけ**である。
fn cow_exclusive() -> CowExclusive {
    let guard = CROSS_MATRIX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *COW_EXCLUSIVE_OWNER
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(std::thread::current().id());
    CowExclusive { _guard: guard }
}

struct CowExclusive {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for CowExclusive {
    fn drop(&mut self) {
        // 登録と抹消は対で置く（`bug-pattern-rules` B-01）。フィールドより先にこの本体が
        // 走るので、「ロックは手放したのに所有者は自分のまま」という窓は開かない。
        *COW_EXCLUSIVE_OWNER
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// 排他ガードを持たずに共有資源へ触ろうとしたら、その場で止める。
///
/// **型で縛れない側のゲート**——一覧を読まずにCoWセッションを**作るだけ**のテストは
/// [`CowExclusive`]を要求されないが、それでも隣の見比べを狂わせる。
fn assert_cow_exclusive_held(what: &str) {
    let owner = *COW_EXCLUSIVE_OWNER
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        owner,
        Some(std::thread::current().id()),
        "BUG-135: 「{what}」は排他ロックを取ってから行うこと。テスト関数の先頭で \
         `let ex = cow_exclusive();` を取る（取らないと、同時に走る別のテストと \
         CoWセッションを取り違えて両方が落ちる）"
    );
}

impl CowExclusive {
    fn list_cow_sessions(&self) -> HashSet<String> {
        // D-81で根が複数になり、返り値は`(一覧, 到達できなかったボリューム数)`になった。
        // このテストは同じマシン上の差分ID差分を見るだけなので、到達不能数は使わない。
        let (dirs, _unreachable) = harness_sandbox::tier2a::workspace_ledger::list_cow_sessions();
        dirs.into_iter().map(|d| d.session_id).collect()
    }

    /// `before`との差分から、このケースで新規に作られたCoWセッションIDを1つ特定する。
    fn new_cow_session(&self, before: &HashSet<String>) -> Result<String, String> {
        let after = self.list_cow_sessions();
        let mut new_ones: Vec<&String> = after.difference(before).collect();
        match new_ones.len() {
            1 => Ok(new_ones.remove(0).clone()),
            0 => Err("CoWセッションが新規作成されなかった".to_string()),
            n => Err(format!(
                "CoWセッションが{n}件同時に新規作成された（並行実行を疑う）"
            )),
        }
    }
}

/// **BUG-135の歯**（B-27）: 排他ガードを持たずに触ったら、不定期な赤ではなく**その場で**落ちること。
///
/// このファイルの他のテストはすべて`#[ignore]`（実機・管理者権限が要る）なので、
/// ゲートの生死を確かめるにはこれが唯一の軽い経路である
/// （`cargo test -p harness-cli --features e2e-mock` で走る。管理者権限は不要）。
#[test]
#[should_panic(expected = "BUG-135")]
fn touching_a_cow_session_without_the_exclusive_guard_fails_loudly() {
    assert_cow_exclusive_held("この検査自体の歯の確認");
}

/// **ゲートが実際に配線されていることの歯**（B-27・B-06）。
///
/// 上のテストは検査関数が動くことしか見ていない。**検査が存在することと、
/// CoWセッションを作る入口から呼ばれていることは別の事実**で、後者が抜けていたのが
/// BUG-135 そのものだった。だから入口（[`run_harness_full`]）を排他ガード無しで叩いて確かめる。
///
/// **`harness.exe`は起動しない**——検査は関数の先頭、スクラッチ用ファイルを作るより前に
/// あるので、パニックが先に出る。実機も管理者権限も要らない。
#[test]
#[should_panic(expected = "BUG-135")]
fn starting_a_cow_session_without_the_exclusive_guard_fails_before_spawning() {
    let _ = run_harness_full(
        &harness_exe(),
        CASE_ROOT,
        None,
        &[],
        &["--sandbox", "tier2a-cow"],
        "guard-probe-must-never-spawn",
        &[],
    );
}

/// 上と同じ歯を、**実プロバイダの腕**（[`Driver::Lmstudio`]）でも立てる。入口を割ったので、
/// 「mock の包みを通ったときだけゲートが効く」形に戻っていないことを固定する（B-06）。
/// 検査は起動より前にあるので、LMStudio も`harness.exe`も要らない。
#[test]
#[should_panic(expected = "BUG-135")]
fn starting_a_live_cow_session_without_the_exclusive_guard_fails_before_spawning() {
    let _ = run_harness_driven(
        &harness_exe(),
        CASE_ROOT,
        None,
        Driver::Lmstudio {
            base_url: LMSTUDIO_BASE_URL,
            model: "guard-probe-model",
            prompt: "guard probe",
            deadline: std::time::Duration::from_secs(1),
        },
        &["--sandbox", "tier2a-cow"],
        "guard-probe-live-must-never-spawn",
        &[],
    );
}

/// D-81で差分層の根が複数になったので、**全部の根を探す**。
/// ここでプロファイル側の根だけを見ると、別ボリュームのワークスペースで走らせたときだけ
/// 「セッションが見つからない」という無関係な失敗になる。
fn cow_diff_layer_dir(session_id: &str) -> PathBuf {
    let (roots, _unreachable) = harness_sandbox::session_scope::cow_diff_layer_roots();
    roots
        .iter()
        .map(|root| harness_sandbox::session_scope::cow_diff_layer_dir_in(root, session_id))
        .find(|dir| dir.is_dir())
        .unwrap_or_else(|| {
            // まだ作られていない場合は、プロファイル側の根の下を指す（従来の挙動）。
            harness_sandbox::session_scope::cow_diff_layer_dir_in(
                roots
                    .first()
                    .expect("at least the profile root must resolve"),
                session_id,
            )
        })
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
    serde_json::from_str(stdout.trim()).map_err(|e| {
        format!("apply stdout is not valid JSON: {e} (stdout={stdout}, stderr={stderr})")
    })
}

/// `harness changes --session <id> --output-format json`を呼び、変更一覧(apply前の見え方)を
/// JSON配列で返す。各要素は`{op, path, unledgered, rejected, ...}`
/// (`workspace_cmd.rs`の`fs.change_set()`直列化)。CoW既定化の検証(`PLAN-COW-AS-DEFAULT.md`
/// 検証タスク手順3「`harness changes`に何がどう出るか」)で、`.git/objects/**`が何件出るかを
/// 数えるために使う。
fn list_changes_json(ws: &Path, session_id: &str) -> Result<serde_json::Value, String> {
    let output = Command::new(harness_exe())
        .args([
            "--cwd",
            ws.to_str().unwrap(),
            "changes",
            "--session",
            session_id,
            "--output-format",
            "json",
        ])
        .output()
        .map_err(|e| format!("failed to spawn harness changes: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    serde_json::from_str(stdout.trim()).map_err(|e| {
        format!("changes stdout is not valid JSON: {e} (stdout={stdout}, stderr={stderr})")
    })
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

/// 成功時のみワークスペース・CoW 差分層セッション・スクラッチを削除する（Q10）。
fn cleanup_on_success(ws: &Path, sessions: &[&str], case_name: &str) {
    for session_id in sessions {
        let _ = std::fs::remove_dir_all(cow_diff_layer_dir(session_id));
    }
    let _ = std::fs::remove_dir_all(ws);
    let scratch = scratch_dir();
    let _ = std::fs::remove_file(scratch.join(format!("{case_name}-turns.json")));
    let _ = std::fs::remove_file(scratch.join(format!("{case_name}-requests.jsonl")));
    let _ = std::fs::remove_dir_all(recall_data_root(&scratch, case_name));
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
fn setup_baseline(ex: &CowExclusive, ws: &Path, case_name: &str) -> Result<String, String> {
    let before = ex.list_cow_sessions();
    let run = run_harness(
        ws,
        &run_shell_script_turns(ROUND1_SCRIPT),
        &["--sandbox", "tier2a-cow"],
        &format!("{case_name}-r1"),
    );
    if !run.status.success() {
        return Err(format!("round1 harness invocation failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["run_shell"])?;
    let session1 = ex.new_cow_session(&before)?;
    let report = apply_cow(ws, &session1, None)?;
    let applied = report["applied"]
        .as_array()
        .ok_or("apply report missing applied[]")?;
    if applied.len() != 4 {
        return Err(format!(
            "round1 commit_all applied {} files, expected 4: {report}",
            applied.len()
        ));
    }
    expect_eq(
        "test.txt (baseline)",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;
    expect_eq(
        "test1.txt (baseline)",
        &read_file(&ws.join("test1.txt"))?,
        "helloworld123",
    )?;
    Ok(session1)
}

fn run_round2(
    ex: &CowExclusive,
    ws: &Path,
    script: &str,
    case_name: &str,
) -> Result<(String, HashSet<String>), String> {
    let before = ex.list_cow_sessions();
    let run = run_harness(
        ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        case_name,
    );
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = ex.new_cow_session(&before)?;
    Ok((session2, before))
}

/// A: 新規作成のみコミット。他の4件は未コミットのまま残ること。
fn case_a_commit_only_new_file(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-a-new-only");
    let session1 = setup_baseline(ex, &ws, "cow-a")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-a-r2")?;

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
    expect_eq(
        "test2.txt",
        &read_file(&ws.join("test2.txt"))?,
        "helloworld123",
    )?;
    // 他は未コミットのまま(ラウンド1の値のまま)であること。
    expect_eq(
        "test.txt unchanged",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;
    expect_eq(
        "test1.txt unchanged",
        &read_file(&ws.join("test1.txt"))?,
        "helloworld123",
    )?;
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
fn case_b_commit_only_modifications(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-b-modify-only");
    let session1 = setup_baseline(ex, &ws, "cow-b")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-b-r2")?;

    apply_cow(&ws, &session2, Some("test.txt"))?;
    let report = apply_cow(&ws, &session2, Some("test1.txt"))?;
    let _ = report;
    expect_eq(
        "test.txt modified",
        &read_file(&ws.join("test.txt"))?,
        "helloworld!!!",
    )?;
    expect_eq(
        "test1.txt modified",
        &read_file(&ws.join("test1.txt"))?,
        "evil",
    )?;
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
fn case_c_commit_only_deletion(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-c-delete-only");
    let session1 = setup_baseline(ex, &ws, "cow-c")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-c-r2")?;

    apply_cow(&ws, &session2, Some("test3.txt"))?;
    if ws.join("test3.txt").exists() {
        return Err("test3.txt should have been deleted".to_string());
    }
    expect_eq(
        "test.txt unchanged",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-c");
    Ok(())
}

/// D: 移動のみコミット（Delete test4.txt + Create test5.txtの2エントリ）。
fn case_d_commit_only_rename(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-d-rename-only");
    let session1 = setup_baseline(ex, &ws, "cow-d")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-d-r2")?;

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
fn case_e_commit_all_at_once(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-e-commit-all");
    let session1 = setup_baseline(ex, &ws, "cow-e")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-e-r2")?;

    let report = apply_cow(&ws, &session2, None)?;
    let applied = report["applied"].as_array().ok_or("missing applied[]")?;
    // modify x2 (test.txt/test1.txt) + create x1 (test2.txt) + delete x1 (test3.txt)
    // + rename=delete+create x2 (test4.txt/test5.txt) = 6。
    if applied.len() != 6 {
        return Err(format!("expected 6 applied entries (modify x2, create x1, delete x1, rename=delete+create x2), got {}: {report}", applied.len()));
    }
    expect_eq(
        "test.txt",
        &read_file(&ws.join("test.txt"))?,
        "helloworld!!!",
    )?;
    expect_eq("test1.txt", &read_file(&ws.join("test1.txt"))?, "evil")?;
    expect_eq(
        "test2.txt",
        &read_file(&ws.join("test2.txt"))?,
        "helloworld123",
    )?;
    expect_eq("test5.txt", &read_file(&ws.join("test5.txt"))?, "baseline4")?;
    if ws.join("test3.txt").exists() || ws.join("test4.txt").exists() {
        return Err("test3.txt/test4.txt should be gone".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-e");
    Ok(())
}

/// F: 部分コミット→残りを追いコミットした最終状態が、Eの全コミット結果とバイト一致すること
/// （データが飛ばない不変条件、当初の要求の核心）。
fn case_f_partial_then_rest_matches_commit_all(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-f-partial-then-rest");
    let session1 = setup_baseline(ex, &ws, "cow-f")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-f-r2")?;

    apply_cow(&ws, &session2, Some("test2.txt"))?;
    apply_cow(&ws, &session2, Some("test.txt"))?;
    let final_report = apply_cow(&ws, &session2, None)?;
    let _ = final_report;

    expect_eq(
        "test.txt",
        &read_file(&ws.join("test.txt"))?,
        "helloworld!!!",
    )?;
    expect_eq("test1.txt", &read_file(&ws.join("test1.txt"))?, "evil")?;
    expect_eq(
        "test2.txt",
        &read_file(&ws.join("test2.txt"))?,
        "helloworld123",
    )?;
    expect_eq("test5.txt", &read_file(&ws.join("test5.txt"))?, "baseline4")?;
    if ws.join("test3.txt").exists() || ws.join("test4.txt").exists() {
        return Err("test3.txt/test4.txt should be gone after committing the rest".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-f");
    Ok(())
}

/// G: D-05ハードデニー。`.git/config`を差分層へ書いてもapplyで実workspaceへ書き戻せないこと。
fn case_g_hard_deny_config_injection(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-g-hard-deny");
    let session1 = setup_baseline(ex, &ws, "cow-g")?;
    let before = ex.list_cow_sessions();
    let script = "New-Item -ItemType Directory -Force .git | Out-Null; \
Set-Content .git/config 'evil-injected' -NoNewline";
    let run = run_harness(
        &ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        "cow-g-r2",
    );
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = ex.new_cow_session(&before)?;

    let report = apply_cow(&ws, &session2, None)?;
    let hard_denied: Vec<String> = report["hard_denied"]
        .as_array()
        .ok_or("missing hard_denied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if !hard_denied
        .iter()
        .any(|p| p.replace('\\', "/") == ".git/config")
    {
        return Err(format!(
            ".git/config should be hard_denied (D-05), got {report}"
        ));
    }
    if ws.join(".git").join("config").exists() {
        return Err("D-05 violated: .git/config was written to the real workspace".to_string());
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-g");
    Ok(())
}

/// H: TOCTOU。セッション中に実workspace側を外から書き換えると、conflictとして扱われ
/// CoW側の内容で黙って上書きされないこと。
fn case_h_toctou_conflict(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-h-toctou");
    let session1 = setup_baseline(ex, &ws, "cow-h")?;
    let before = ex.list_cow_sessions();
    let script = "Set-Content test.txt 'modified-by-session' -NoNewline";
    let run = run_harness(
        &ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        "cow-h-r2",
    );
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session2 = ex.new_cow_session(&before)?;

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

/// I: host内蔵`write_file`ツール自身が`--sandbox tier2a-cow`時にCoW保護を経由すること（2026-08-01実機ドライ
/// ランで発見したバグの回帰確認、Phase 1修正）。`run_shell`経由（PowerShellの`Set-Content`）
/// ではなく`write_file`ツールを直接呼ぶ台本で、(a) workspace本体がwrite_file実行直後は
/// 無傷、(b) 新規CoWセッションが記録され、(c) `apply`で反映される、ことを検証する。
fn case_i_write_file_tool_is_captured_by_cow(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-i-write-file-tool");
    let before = ex.list_cow_sessions();
    let run = run_harness(
        &ws,
        &write_file_tool_turns("notes.txt", "written via write_file tool"),
        &["--sandbox", "tier2a-cow"],
        "cow-i",
    );
    if !run.status.success() {
        return Err(format!("harness invocation failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["Copy-on-Write"])?;

    if ws.join("notes.txt").exists() {
        return Err(
            "write_file must not touch the real workspace directly under --sandbox tier2a-cow (regression)"
                .to_string(),
        );
    }
    let session = ex.new_cow_session(&before)?;

    let report = apply_cow(&ws, &session, None)?;
    let applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if applied != vec!["notes.txt".to_string()] {
        return Err(format!(
            "expected only notes.txt applied, got {applied:?}: {report}"
        ));
    }
    expect_eq(
        "notes.txt",
        &read_file(&ws.join("notes.txt"))?,
        "written via write_file tool",
    )?;

    cleanup_on_success(&ws, &[&session], "cow-i");
    Ok(())
}

/// J: `discard`（差分層丸ごと破棄）。`--output-format`が無くテキスト出力のみ（`Discard`は
/// JSON化されていない）ため、既存`case_h_toctou_conflict`が後始末目的で同コマンドを呼ぶ
/// 前例に倣い、終了コードと文字列マッチで検証する。
fn case_j_discard_removes_all_changes(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-j-discard");
    let session1 = setup_baseline(ex, &ws, "cow-j")?;
    let (session2, _) = run_round2(ex, &ws, ROUND2_SCRIPT, "cow-j-r2")?;

    let output = Command::new(harness_exe())
        .args([
            "--cwd",
            ws.to_str().unwrap(),
            "discard",
            "--session",
            &session2,
        ])
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
        return Err(format!(
            "expected discard stdout to contain 'discarded changes', got: {stdout}"
        ));
    }
    // round2の変更（`helloworld!!!`）はworkspaceへ一切反映されず、round1のbaselineのまま。
    expect_eq(
        "test.txt must remain at the round1 baseline after discard",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;
    let after = ex.list_cow_sessions();
    if after.contains(&session2) {
        return Err(format!(
            "session {session2} must be gone from list_cow_sessions() after discard"
        ));
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
fn case_k_resolve_auto_merges_non_overlapping_conflict(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-k-resolve");
    let before = ex.list_cow_sessions();
    let baseline_script = "Set-Content test.txt \"line1`nline2`nline3\" -NoNewline";
    let run1 = run_harness(
        &ws,
        &run_shell_script_turns(baseline_script),
        &["--sandbox", "tier2a-cow"],
        "cow-k-r1",
    );
    if !run1.status.success() {
        return Err(format!(
            "baseline harness invocation failed: {}",
            run1.stderr
        ));
    }
    let session1 = ex.new_cow_session(&before)?;
    let report1 = apply_cow(&ws, &session1, None)?;
    if report1["applied"].as_array().map(|a| a.len()).unwrap_or(0) != 1 {
        return Err(format!(
            "expected baseline commit to apply exactly test.txt: {report1}"
        ));
    }
    expect_eq(
        "test.txt (baseline)",
        &read_file(&ws.join("test.txt"))?,
        "line1\nline2\nline3",
    )?;

    let (session2, _) = run_round2(
        ex,
        &ws,
        "Set-Content test.txt \"line1-cow`nline2`nline3\" -NoNewline",
        "cow-k-r2",
    )?;

    // セッション外からの書き換え(TOCTOU、`case_h`と同型)。CoW側とは別の行(3行目)を変更する
    // ため、非重複な変更として自動マージできる。
    std::fs::write(ws.join("test.txt"), "line1\nline2\nline3-external")
        .map_err(|e| format!("failed to simulate external write: {e}"))?;

    let output = Command::new(harness_exe())
        .args([
            "--cwd",
            ws.to_str().unwrap(),
            "resolve",
            "--session",
            &session2,
        ])
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

/// L: `--resume <id> --sandbox tier2a-cow`によるセッション再開（設計書§19.11、仕様確定: 同一diff_layer_dirを
/// 再利用し同一セッションIDで継続キャプチャする）。1つの`--sandbox tier2a-cow`セッションで変更を行い
/// （discardせず）プロセスを終了し、同じセッションIDで`--resume --sandbox tier2a-cow`により再開して
/// 追加の変更を行い、`apply`で両方の変更が反映されることを確認する。
fn case_l_resume_continues_same_cow_session(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-l-resume");
    let before = ex.list_cow_sessions();
    let run1 = run_harness(
        &ws,
        &write_file_tool_turns("first.txt", "written in round 1"),
        &["--sandbox", "tier2a-cow"],
        "cow-l-r1",
    );
    if !run1.status.success() {
        return Err(format!("round1 harness invocation failed: {}", run1.stderr));
    }
    let session_id = ex.new_cow_session(&before)?;
    // round1のプロセスは正常終了しdiscardしていない前提（liveness mutexは名前付きmutexで、
    // 所有プロセスの終了とともにOSが解放するため、再開時に「まだliveと誤認識される」ことは
    // 無い、設計書§19.11参照）。
    if cow_session_is_live(&session_id) {
        return Err(format!(
            "session {session_id} should not be live after its process exited"
        ));
    }

    // 同一session_idで--resume --sandbox tier2a-cowにより再開し、2つ目のファイルを追加する。
    let run2 = run_harness_with_exe(
        &harness_exe(),
        &ws,
        &write_file_tool_turns("second.txt", "written in round 2 after resume"),
        &["--sandbox", "tier2a-cow", "--resume", &session_id],
        "cow-l-r2",
    );
    if !run2.status.success() {
        return Err(format!(
            "resumed harness invocation failed: {}",
            run2.stderr
        ));
    }
    // resumeは新しいCoWセッションを作らず、同じsession_idのdiff_layer_dirを再利用しているはず。
    let after_resume = ex.list_cow_sessions();
    if !after_resume.contains(&session_id) {
        return Err(format!(
            "session {session_id} should still exist after resume"
        ));
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
    expect_eq(
        "first.txt",
        &read_file(&ws.join("first.txt"))?,
        "written in round 1",
    )?;
    expect_eq(
        "second.txt",
        &read_file(&ws.join("second.txt"))?,
        "written in round 2 after resume",
    )?;

    cleanup_on_success(&ws, &[&session_id], "cow-l");
    Ok(())
}

fn cow_session_is_live(session_id: &str) -> bool {
    harness_sandbox::tier2a::workspace_ledger::cow_session_is_live(session_id)
}

/// M（BUG-047回帰）: `ROUND1_SCRIPT`/`ROUND2_SCRIPT`ベースのA〜L系ケースは、いずれもラウンド間で
/// `apply_cow`（コミット）を挟むため、「セッション中に新規作成したファイルをそのセッション内で
/// 削除する」経路を一度も通らない。BUG-047はまさにその経路（`NtQueryDirectoryFile`未フックにより
/// ディレクトリ列挙が差分層側だけの新規ファイルを見落とし、`Remove-Item`が「存在しない」と誤判定
/// する）で発生したため、既存マトリクスでは検出できなかった（ユーザー報告: ハーネス起動後に
/// 新規作成したファイルを削除しようとすると失敗する。ハーネス起動前から存在するファイルの削除は
/// 問題なかった——後者は個別パス指定のオープンだけで完結し列挙を経由しないため）。
/// この1回の`run_shell`セッション内でNew-Item→Test-Path→Remove-Item→Test-Pathまで完結させ、
/// commit/discardを一切挟まない。
fn case_m_new_file_created_and_deleted_within_same_cow_session(
    ex: &CowExclusive,
) -> Result<(), String> {
    let ws = case_dir("cow-m-create-delete-same-session");
    let before = ex.list_cow_sessions();
    let script = "$created = Test-Path newfile.txt; \
New-Item newfile.txt -ItemType File | Out-Null; \
$existsAfterCreate = Test-Path newfile.txt; \
try { Remove-Item newfile.txt -ErrorAction Stop; $deleted = $true; $err = $null } \
catch { $deleted = $false; $err = $_.Exception.Message }; \
$existsAfterDelete = Test-Path newfile.txt; \
[pscustomobject]@{ createdBefore = $created; existsAfterCreate = $existsAfterCreate; \
deleted = $deleted; err = $err; existsAfterDelete = $existsAfterDelete } | ConvertTo-Json -Compress";
    let run = run_harness(
        &ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        "cow-m",
    );
    if !run.status.success() {
        return Err(format!("harness invocation failed: {}", run.stderr));
    }
    let session = ex.new_cow_session(&before)?;
    assert_prompt_sane(&run, &["run_shell"])?;

    let outcome = parse_json_stdout(&run)?;
    let result_text = outcome.first_tool_result()?;
    // ネットワーク診断ログ等、無関係な行がstdoutへ混入し得る（実機確認: fake DNSの
    // 診断行）ため、他ケース（`net_case_matrix`系）と同じく「JSONとして解釈できて
    // 目的のキーを持つ最後の行」を探す（単純な「最後の非空行」だと診断行を誤って
    // 拾ってしまう）。
    let report: serde_json::Value = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("existsAfterDelete").is_some())
        .ok_or_else(|| {
            format!("could not find the expected JSON summary line in output: {result_text}")
        })?;

    if report["createdBefore"].as_bool() != Some(false) {
        return Err(format!(
            "newfile.txt should not exist before New-Item: {report}"
        ));
    }
    if report["existsAfterCreate"].as_bool() != Some(true) {
        return Err(format!(
            "newfile.txt should exist right after New-Item: {report}"
        ));
    }
    if report["deleted"].as_bool() != Some(true) {
        return Err(format!(
            "Remove-Item on the session-created file must succeed \
             (BUG-047: it previously failed as ItemNotFoundException because directory \
             enumeration never saw the diff-layer-only file): {report}"
        ));
    }
    if !report["err"].is_null() {
        return Err(format!("Remove-Item must not raise an error: {report}"));
    }
    if report["existsAfterDelete"].as_bool() != Some(false) {
        return Err(format!(
            "newfile.txt must be gone after Remove-Item: {report}"
        ));
    }

    cleanup_on_success(&ws, &[&session], "cow-m");
    Ok(())
}

/// N（BUG-048回帰）: `is_write_intent`が`FILE_GENERIC_WRITE`（`SYNCHRONIZE`/`READ_CONTROL`込み）
/// で判定していたため、`Get-ChildItem`のディレクトリopenや`Get-Content`の読み取りopenまで
/// 「書込意図あり」と誤判定し、以下のユーザー報告そのものの症状を起こしていた
/// （`docs/CowIssueSummary.md`）:
/// - `Get-ChildItem`がworkspace本体ではなくCoW 差分層の中身だけを返す
/// - 既存ファイルの読み取り（`Get-Content`）だけで`.harness-cow-ops.jsonl`へ偽の`modify`が
///   積まれる
///
/// このケースは1セッション内で、事前に存在するファイル/サブディレクトリとセッション中に
/// 新規作成したファイルが同じ`Get-ChildItem`結果に揃って現れること・サブディレクトリの列挙も
/// 動くこと・純粋な読み取りが台帳を汚さないことを検証する。
fn case_n_ls_merges_preexisting_and_new_files_read_does_not_dirty_ledger(
    ex: &CowExclusive,
) -> Result<(), String> {
    let ws = case_dir("cow-n-ls-merge-and-clean-read");
    std::fs::write(ws.join("seed.txt"), "seed-content").map_err(|e| e.to_string())?;
    std::fs::create_dir(ws.join("sub")).map_err(|e| e.to_string())?;
    std::fs::write(ws.join("sub").join("inner.txt"), "inner-content").map_err(|e| e.to_string())?;

    let before = ex.list_cow_sessions();
    // `Get-Content`の戻り値はPSPath/PSParentPath等のETS(拡張型システム)ノートプロパティ付きの
    // Stringで、そのままpscustomobjectのプロパティへ入れると`ConvertTo-Json`がノートプロパティ
    // ごとシリアライズしてしまう（実行して発見したPowerShellの既知の挙動）。`[string]`へ
    // 明示キャストして生の文字列だけを残す。
    let script = "New-Item newfile.txt -ItemType File | Out-Null; \
$names = (Get-ChildItem -Force -Name) -join ','; \
$subNames = (Get-ChildItem -Force -Name sub) -join ','; \
$seedContent = [string](Get-Content seed.txt -Raw); \
[pscustomobject]@{ names = $names; subNames = $subNames; seedContent = $seedContent } \
| ConvertTo-Json -Compress";
    let run = run_harness(
        &ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        "cow-n",
    );
    if !run.status.success() {
        return Err(format!("harness invocation failed: {}", run.stderr));
    }
    let session = ex.new_cow_session(&before)?;
    assert_prompt_sane(&run, &["run_shell"])?;

    let outcome = parse_json_stdout(&run)?;
    let result_text = outcome.first_tool_result()?;
    let report: serde_json::Value = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("names").is_some())
        .ok_or_else(|| {
            format!("could not find the expected JSON summary line in output: {result_text}")
        })?;

    let names = report["names"].as_str().unwrap_or_default();
    let name_list: Vec<&str> = names.split(',').collect();
    for expected in ["seed.txt", "sub", "newfile.txt"] {
        if !name_list.contains(&expected) {
            return Err(format!(
                "BUG-048: Get-ChildItem must show pre-existing and session-created entries \
                 together, but {expected:?} is missing from {name_list:?} (report={report})"
            ));
        }
    }

    let sub_names = report["subNames"].as_str().unwrap_or_default();
    if !sub_names.split(',').any(|n| n == "inner.txt") {
        return Err(format!(
            "subdirectory enumeration must show pre-existing file: subNames={sub_names:?} (report={report})"
        ));
    }

    let seed_content = report["seedContent"].as_str().unwrap_or_default();
    if seed_content.trim() != "seed-content" {
        return Err(format!(
            "Get-Content seed.txt returned unexpected content: {report}"
        ));
    }

    let ops_path = cow_diff_layer_dir(&session).join(".harness-cow-ops.jsonl");
    if ops_path.exists() {
        let ops_text = std::fs::read_to_string(&ops_path).unwrap_or_default();
        if ops_text.contains("seed.txt") {
            return Err(format!(
                "BUG-048: reading seed.txt must not append a fake ledger entry (copy-up on \
                 read-only open), but ops ledger contains it: {ops_text}"
            ));
        }
    }

    cleanup_on_success(&ws, &[&session], "cow-n");
    Ok(())
}

/// O（[BUG-066](../../../docs/bugs/BUG-066.md)の回帰）: `run_shell`から**CoW 差分層の絶対パスを
/// 直接指定して**書いたファイルが、操作台帳に載り`changes`に現れ`apply`で実workspaceへ反映される。
///
/// 実際にモデルがやったのはこれである——workspace内への`Set-Content`が拒否され続けたので、
/// システムプロンプトに書かれていた差分層のパスへ直接書いた。差分層はサンドボックス子へRW付与
/// されているので書込自体は成功し、しかし`copy_up`を経由しないので台帳には何も残らず、
/// `harness changes`は「変更なし」と答え、`discard`すれば作業ごと消える状態になっていた。
///
/// 差分層のパスは子プロセスから`$env:HARNESS_COW_DIFF_LAYER`で引ける（Redirector DLLへ設定を渡す
/// ための環境変数。モデルにはシステムプロンプトでも見えている）。
///
/// なお**DLLが注入されなかった/回避された場合**（台帳へ何も書かれない場合）の受け皿は
/// host側の実体走査であり、そちらは`overlay.rs`のユニットテスト
/// （`unledgered_*`）が固定している。ここで見るのはDLLが生きている経路の方。
fn case_o_direct_write_into_the_diff_layer_dir_is_recorded(
    ex: &CowExclusive,
) -> Result<(), String> {
    let ws = case_dir("cow-o-direct-diff-layer-write");
    let before = ex.list_cow_sessions();
    const SCRIPT: &str = "Set-Content (Join-Path $env:HARNESS_COW_DIFF_LAYER 'direct.txt') \
                          'written straight into the diff layer dir' -NoNewline";
    let run = run_harness(
        &ws,
        &run_shell_script_turns(SCRIPT),
        &["--sandbox", "tier2a-cow"],
        "cow-o",
    );
    if !run.status.success() {
        return Err(format!("harness invocation failed: {}", run.stderr));
    }
    let session = ex.new_cow_session(&before)?;

    let diff_layer_file = cow_diff_layer_dir(&session).join("direct.txt");
    if !diff_layer_file.exists() {
        return Err(format!(
            "the script must have created {} (if this fails the test setup is wrong, not the fix)",
            diff_layer_file.display()
        ));
    }
    let ops_text =
        std::fs::read_to_string(cow_diff_layer_dir(&session).join(".harness-cow-ops.jsonl"))
            .unwrap_or_default();
    if !ops_text.contains("direct.txt") {
        return Err(format!(
            "BUG-066: a direct write into the diff_layer dir must be recorded in the operations \
             ledger, but the ledger is {ops_text:?}"
        ));
    }

    let report = apply_cow(&ws, &session, None)?;
    let applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if applied != vec!["direct.txt".to_string()] {
        return Err(format!(
            "expected direct.txt to be applied, got {applied:?}: {report}"
        ));
    }
    expect_eq(
        "direct.txt",
        &read_file(&ws.join("direct.txt"))?,
        "written straight into the diff layer dir",
    )?;

    cleanup_on_success(&ws, &[&session], "cow-o");
    Ok(())
}

/// **BUG-066の追加検証（2026-08-06）**: `--cwd`の綴りが揺れても、製品を通しで動かして
/// リダイレクトが成立することを確かめる（ケースP〜S共通の本体）。
///
/// 2026-08-05の障害では、DLLがworkspace内の絶対パスをworkspace外と判定して全書込が拒否されて
/// いた。候補の綴りは4つあり、どれだったかは残存証跡から特定できない。ここでは4つとも
/// **実`harness.exe`へ`--cwd`として渡して**測る。`cwd_for_process`を立てるのは`--cwd .`
/// （ワークスペースへ`cd`してから起動する形）のためで、これが最も疑わしい候補である。
///
/// 子には**絶対パス指定の書込**をさせる（当時失敗したのがこの形。cwd相対のopenは別経路を通り、
/// 綴りが揺れていても成立し得るため、綴りの影響を見るには絶対パスでなければならない）。
fn run_cwd_spelling_case(
    ex: &CowExclusive,
    case_name: &str,
    make_cwd_arg: fn(&Path) -> String,
    use_process_cwd: bool,
) -> Result<(), String> {
    let ws = case_dir(case_name);
    // `case_dir`は相対パスを返さない（`CASE_ROOT`固定）。実パスを控えてから綴りを作る。
    let real = ws
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", ws.display()))?;
    let real = real
        .to_string_lossy()
        .strip_prefix(r"\\?\")
        .map(PathBuf::from)
        .unwrap_or(real.clone());
    let cwd_arg = make_cwd_arg(&real);
    assert_cow_redirect_through_cwd(ex, case_name, &real, &cwd_arg, use_process_cwd, &ws)
}

/// ケースP〜Tの本体。`ws_root`（実在する実パス）をworkspaceとして`--cwd <cwd_arg>`で
/// harnessを起動し、境界・透過性・可視性・自己診断の4点を確認する。
fn assert_cow_redirect_through_cwd(
    ex: &CowExclusive,
    case_name: &str,
    real: &Path,
    cwd_arg: &str,
    use_process_cwd: bool,
    cleanup_root: &Path,
) -> Result<(), String> {
    let real = real.to_path_buf();
    std::fs::write(real.join("notes.txt"), "original")
        .map_err(|e| format!("seed notes.txt: {e}"))?;

    let script = format!(
        "Set-Content -LiteralPath '{}' -Value 'modified-by-agent' -NoNewline",
        real.join("notes.txt").display()
    );
    let before = ex.list_cow_sessions();
    let run = run_harness_full(
        &harness_exe(),
        cwd_arg,
        use_process_cwd.then_some(real.as_path()),
        &run_shell_script_turns(&script),
        &["--sandbox", "tier2a-cow"],
        case_name,
        &[],
    );
    if !run.status.success() {
        return Err(format!(
            "harness invocation failed with --cwd {cwd_arg:?}: stdout={} stderr={}",
            run.stdout, run.stderr
        ));
    }
    let session = ex.new_cow_session(&before)?;
    let diff_layer = cow_diff_layer_dir(&session);

    // 1. 境界: workspace本体は不変。
    expect_eq(
        "workspace body must stay untouched under --sandbox tier2a-cow",
        &read_file(&real.join("notes.txt"))?,
        "original",
    )?;
    // 2. 透過性: 差分層へリダイレクトされている。
    let diff_layer_content = read_file(&diff_layer.join("notes.txt")).map_err(|e| {
        format!(
            "--cwd {cwd_arg:?}: the write was not redirected to the diff_layer dir ({e}); \
                 this is exactly the BUG-066 symptom"
        )
    })?;
    expect_eq(
        "diff layer content",
        &diff_layer_content,
        "modified-by-agent",
    )?;
    // 3. 可視性: 操作台帳に載り、`apply`で実workspaceへ反映される。
    let report = apply_cow(&real, &session, None)?;
    let applied: Vec<String> = report["applied"]
        .as_array()
        .ok_or("missing applied[]")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    if applied != vec!["notes.txt".to_string()] {
        return Err(format!(
            "expected notes.txt applied, got {applied:?}: {report}"
        ));
    }
    expect_eq(
        "applied content",
        &read_file(&real.join("notes.txt"))?,
        "modified-by-agent",
    )?;
    // 4. 自己診断: workspace**内**への拒否が1件も無いこと（あればリダイレクトが働いていない）。
    let denied = harness_change_ledger::store::read_denied_log(&diff_layer);
    let inside: Vec<&str> = denied
        .iter()
        .filter(|e| {
            harness_change_ledger::path_rules::relative_under_root(&e.path, &real.to_string_lossy())
                .is_some()
        })
        .map(|e| e.path.as_str())
        .collect();
    if !inside.is_empty() {
        return Err(format!(
            "--cwd {cwd_arg:?}: writes inside the workspace were denied instead of redirected: {inside:?}"
        ));
    }

    cleanup_on_success(cleanup_root, &[&session], case_name);
    Ok(())
}

fn case_p_cwd_relative(ex: &CowExclusive) -> Result<(), String> {
    run_cwd_spelling_case(ex, "cow-p-cwd-relative", |_| ".".to_string(), true)
}

fn case_q_cwd_uppercased(ex: &CowExclusive) -> Result<(), String> {
    run_cwd_spelling_case(
        ex,
        "cow-q-cwd-uppercased",
        |p| p.to_string_lossy().to_uppercase(),
        false,
    )
}

fn case_r_cwd_trailing_separator(ex: &CowExclusive) -> Result<(), String> {
    run_cwd_spelling_case(
        ex,
        "cow-r-cwd-trailing-sep",
        |p| format!("{}\\", p.to_string_lossy()),
        false,
    )
}

fn case_s_cwd_verbatim_prefix(ex: &CowExclusive) -> Result<(), String> {
    run_cwd_spelling_case(
        ex,
        "cow-s-cwd-verbatim",
        |p| format!(r"\\?\{}", p.to_string_lossy()),
        false,
    )
}

/// T: workspaceのパスが**`MAX_PATH`（260文字）を超える**場合は、理由を名指しして起動を断る。
///
/// `\\?\`前置は「Win32のパス正規化をスキップする」印で、その副作用として260文字制限が外れます。
/// [BUG-068](../../../docs/bugs/BUG-068.md)で`--cwd`から前置を剥がしたので、**長いパスの扱いが
/// 落ちていないか**を実際に測りました。結果は「元々使えなかった」で、原因はharnessではなく
/// **Windowsのプロセス・カレントディレクトリの制限**です（実測: 258文字までOK、259文字から
/// `ERROR_DIRECTORY`(267)。`\\?\`を付けた285文字も同じく失敗）。ACL API側は
/// `win_common::long_path_wide`が直前で`\\?\`を付け直すので無傷ですが、**子プロセスのcwdに
/// できない**ので`run_shell`が成立しません。
///
/// したがってこのケースが固定するのは「動くこと」ではなく**断り方**です。素の
/// `CreateProcessW: ディレクトリ名が無効です (0x8007010B)`は、存在する正しいディレクトリを
/// 指して「無効」と言うため原因に辿り着けません。`preflight`がACEを1本も付ける前に、
/// 文字数・平台の制限・回避策（`subst`）を名指しして止めることを確認します。
fn case_t_workspace_path_longer_than_max_path(ex: &CowExclusive) -> Result<(), String> {
    const CASE: &str = "cow-t-longpath";
    let case_root = case_dir(CASE);
    // `C:\harness-e2e\cow-t-longpath` + 41文字×6階層 ＝ 281文字。
    let mut deep = case_root.clone();
    for i in 0..6 {
        deep = deep.join(format!("seg{i:02}-{}", "x".repeat(35)));
    }
    std::fs::create_dir_all(&deep)
        .map_err(|e| format!("create deep workspace {}: {e}", deep.display()))?;
    let len = deep.to_string_lossy().chars().count();
    if len <= 260 {
        return Err(format!(
            "test setup is wrong: workspace path is only {len} chars"
        ));
    }
    println!("MEASUREMENT: long workspace path is {len} chars");

    let before = ex.list_cow_sessions();
    let run = run_harness_full(
        &harness_exe(),
        &deep.to_string_lossy(),
        None,
        &run_shell_script_turns("Write-Output 'unreachable'"),
        &["--sandbox", "tier2a-cow"],
        CASE,
        &[],
    );
    if run.status.success() {
        return Err(format!(
            "harness must refuse a workspace that cannot be a child process cwd, but it started: \
             stdout={}",
            run.stdout
        ));
    }
    // 断り方の中身（**これがこのケースの本体**）。
    for needle in [
        "characters long",
        "process working directory",
        "LongPathsEnabled",
        "subst",
    ] {
        if !run.stderr.contains(needle) {
            return Err(format!(
                "the refusal must explain itself and contain {needle:?}, got: {}",
                run.stderr
            ));
        }
    }
    // ACEを付ける前に断っているので、CoWセッションも作られていないこと。
    let after = ex.list_cow_sessions();
    let leaked: Vec<&String> = after.difference(&before).collect();
    if !leaked.is_empty() {
        return Err(format!(
            "no CoW session may be created before refusing: {leaked:?}"
        ));
    }

    let _ = std::fs::remove_dir_all(&case_root);
    let scratch = scratch_dir();
    let _ = std::fs::remove_file(scratch.join(format!("{CASE}-turns.json")));
    let _ = std::fs::remove_file(scratch.join(format!("{CASE}-requests.jsonl")));
    Ok(())
}

// --- U〜W（BUG-171）: 失敗した操作を、台帳が「起きた」と記録しないこと ----------------------
//
// Redirector（子の書込を差分層へ向け直すDLL）は、台帳への記録を**本当の操作を呼ぶ前に、
// 結果を見ずに**行っていた。操作が失敗しても記録は残り、台帳だけが「起きた」と言う。
// 台帳は一覧（`harness changes`）・承認（`harness apply`）・セッションの中の見え方
// （削除済みの集合）の唯一の材料なので、3つが揃って実体と食い違う。
// U・V・Wは、同じ形が現れる3つの場所（開く・名前の変更・削除の予約）を1つずつ失敗させる。

/// ラウンド2を1本の`run_shell`で回し、その行が最後に印字したJSONの要約（`key`を持つ最後の行）を返す。
/// 要約は子のstdout（道具の結果欄）からだけ読む（BUG-137）。
fn run_round2_with_report(
    ex: &CowExclusive,
    ws: &Path,
    script: &str,
    case_name: &str,
    key: &str,
) -> Result<(String, serde_json::Value), String> {
    let before = ex.list_cow_sessions();
    let run = run_harness(
        ws,
        &run_shell_script_turns(script),
        &["--sandbox", "tier2a-cow"],
        case_name,
    );
    if !run.status.success() {
        return Err(format!("round2 harness invocation failed: {}", run.stderr));
    }
    let session = ex.new_cow_session(&before)?;
    let outcome = parse_json_stdout(&run)?;
    let result_text = outcome.first_tool_result()?;
    let report = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get(key).is_some())
        .ok_or_else(|| {
            format!("could not find the JSON summary line with {key:?} in the tool output: {result_text}")
        })?;
    Ok((session, report))
}

/// 変更一覧（`harness changes`のJSON）のうち、`path`のエントリの`op`を並べる。
fn change_ops_for(changes: &serde_json::Value, path: &str) -> Result<Vec<String>, String> {
    Ok(changes
        .as_array()
        .ok_or("changes json is not an array")?
        .iter()
        .filter(|c| c["path"].as_str().map(|p| p.replace('\\', "/")).as_deref() == Some(path))
        .map(|c| c["op"].as_str().unwrap_or_default().to_string())
        .collect())
}

/// `apply`の結果に、人の手が要る欄（衝突・拒否・台帳に無い実体・hard-deny・外への書込）が1件も無いこと。
fn expect_apply_clean(what: &str, report: &serde_json::Value) -> Result<(), String> {
    for key in [
        "conflicts",
        "rejected",
        "unledgered",
        "hard_denied",
        "ext_blocked",
    ] {
        let n = report[key]
            .as_array()
            .map(|a| a.len())
            .ok_or_else(|| format!("apply report has no {key}[]: {report}"))?;
        if n != 0 {
            return Err(format!("{what}: apply left {n} entr(ies) in {key}: {report}"));
        }
    }
    Ok(())
}

/// U: 存在しないファイルを消そうとしただけで、変更一覧に「作った」が残らないこと。
///
/// Windowsの削除は「削除の権限を付けてファイルを開く」から始まる。Redirectorはそのopenを
/// 本当に開く前に台帳へ`create`として記録していた（`copy_up`）。開くのは「ファイルが無い」で
/// 失敗するので、対になる`delete`は来ない——一覧に中身の無い`create`が残り、`apply`は中身を
/// 読めずに拒否欄へ積み（終了コード4）、差分層も回収されなかった。存在しないファイルを黙って
/// 消すのはビルドの後始末やgit自身が普通にやることで（段5の測定で`.git`の中に7件出た）、
/// CoWを既定にすると承認が毎回これで止まる。
///
/// 対照として、同じ行で既存の`test3.txt`を消す（こちらは`delete`が載り、適用で本物が消える）。
fn case_u_deleting_a_missing_file_leaves_no_entry(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-u-delete-missing");
    let session1 = setup_baseline(ex, &ws, "cow-u")?;
    let script = "[System.IO.File]::Delete('stale.txt'); \
[System.IO.File]::Delete('test3.txt'); \
[pscustomobject]@{ staleExists = (Test-Path stale.txt); test3Exists = (Test-Path test3.txt) } \
| ConvertTo-Json -Compress";
    let (session2, report) = run_round2_with_report(ex, &ws, script, "cow-u-r2", "test3Exists")?;
    if report["test3Exists"].as_bool() != Some(false)
        || report["staleExists"].as_bool() != Some(false)
    {
        return Err(format!(
            "control: inside the session test3.txt must be gone and stale.txt must not exist: {report}"
        ));
    }

    let changes = list_changes_json(&ws, &session2)?;
    let stale = change_ops_for(&changes, "stale.txt")?;
    if !stale.is_empty() {
        return Err(format!(
            "BUG-171: deleting a file that does not exist left {stale:?} for stale.txt in the change \
             list (the ledger was written before the open, whose result was 'not found'): {changes}"
        ));
    }
    let test3 = change_ops_for(&changes, "test3.txt")?;
    if test3 != ["delete"] {
        return Err(format!(
            "control: deleting the existing test3.txt must be listed as one delete, got {test3:?}: {changes}"
        ));
    }

    let applied = apply_cow(&ws, &session2, None)?;
    expect_apply_clean("U", &applied)?;
    if ws.join("test3.txt").exists() {
        return Err(format!("test3.txt must be deleted by apply: {applied}"));
    }
    if ws.join("stale.txt").exists() {
        return Err(format!("apply must not create stale.txt: {applied}"));
    }
    // 全部を適用し切ったのに差分層が残ったら、製品と同じ判定（D-82）で理由を取り出す。
    // BUG-171の残り（中身の無い記録）が回収を止めているなら、理由は「未適用の変更がある」になる
    // ——そのときだけ赤にする。それ以外の理由（harnessが終わった直後でまだ動いていると見える等）は
    // BUG-171と別の事柄なので、理由を印字して記録へ回す（2026-09-27の実行で、適用の直後には
    // 残り、次のケースの起動時回収で消えるのを観測した）。
    if cow_diff_layer_dir(&session2).exists() {
        let (verdict, facts) = cow_gc_verdict_for(&session2);
        if verdict == Some(harness_sandbox::tier2a::workspace_ledger::CowGcVerdict::KeepHasChanges) {
            return Err(format!(
                "BUG-171: a clean apply left the diff layer holding changes: {facts}"
            ));
        }
        println!(
            "{}",
            serde_json::json!({
                // 各ケースの合否の行（`{"case":…,"passed":…}`）と見分けられる名前にする。
                "observed_in": "U",
                "note": "the diff layer was kept right after a clean apply (not BUG-171)",
                "verdict": format!("{verdict:?}"),
                "facts": facts,
            })
        );
    }

    cleanup_on_success(&ws, &[&session1, &session2], "cow-u");
    Ok(())
}

/// `session_id`の差分層について、`apply`の後片付けと同じ判定（`plan_cow_gc`、既定の方針）を撃ち、
/// 判定と、その材料になった事実（印字用）を返す。差分層が一覧に無ければ判定は`None`。
fn cow_gc_verdict_for(
    session_id: &str,
) -> (
    Option<harness_sandbox::tier2a::workspace_ledger::CowGcVerdict>,
    String,
) {
    use harness_sandbox::tier2a::workspace_ledger as wl;
    let (facts, _unreachable) = wl::collect_cow_session_facts();
    let Some(fact) = facts.into_iter().find(|f| f.session_id == session_id) else {
        return (None, "the session is not listed".to_string());
    };
    let verdict = wl::plan_cow_gc(std::slice::from_ref(&fact), wl::CowGcPolicy::default())
        .first()
        .map(|(_, v)| *v);
    (verdict, format!("{fact:?}"))
}

/// V: 失敗した名前の変更が、元のファイルを消したことにしないこと。
///
/// Redirectorは名前の変更を受け取ると、本当の変更を呼ぶ前に台帳へ「旧パスを削除・新パスを作成」を
/// 書いていた。移動先が既にある等で変更が失敗しても記録は残り、元のファイルは台帳の上で
/// 削除済みになる——セッションの中から見えなくなり、`apply`は本物を消しに行く。
/// ここでは移動先`fresh.txt`を先に作っておき、上書き無しの移動を必ず失敗させる。
fn case_v_a_failed_rename_keeps_the_source(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-v-failed-rename");
    let session1 = setup_baseline(ex, &ws, "cow-v")?;
    let script = "Set-Content fresh.txt 'fresh' -NoNewline; \
try { [System.IO.File]::Move('test.txt', 'fresh.txt'); $moved = $true } catch { $moved = $false }; \
$source = if (Test-Path test.txt) { Get-Content test.txt -Raw } else { $null }; \
[pscustomobject]@{ moved = $moved; source = $source } | ConvertTo-Json -Compress";
    let (session2, report) = run_round2_with_report(ex, &ws, script, "cow-v-r2", "moved")?;
    if report["moved"].as_bool() != Some(false) {
        return Err(format!(
            "precondition: the move onto the existing fresh.txt must fail, otherwise this case \
             tests nothing: {report}"
        ));
    }
    if report["source"].as_str() != Some("helloworld") {
        return Err(format!(
            "BUG-171: after a failed rename, test.txt must still be readable inside the session \
             (the ledger recorded the rename before it failed): {report}"
        ));
    }

    let changes = list_changes_json(&ws, &session2)?;
    if change_ops_for(&changes, "test.txt")?
        .iter()
        .any(|op| op == "delete")
    {
        return Err(format!(
            "BUG-171: a failed rename left a delete of test.txt in the change list: {changes}"
        ));
    }

    let applied = apply_cow(&ws, &session2, None)?;
    expect_apply_clean("V", &applied)?;
    expect_eq(
        "test.txt after apply",
        &read_file(&ws.join("test.txt"))?,
        "helloworld",
    )?;
    expect_eq(
        "fresh.txt after apply",
        &read_file(&ws.join("fresh.txt"))?,
        "fresh",
    )?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-v");
    Ok(())
}

/// W: 読み取り専用で消せなかったファイルを、消したことにしないこと。
///
/// Redirectorは「閉じたら消す」予約（`FileDispositionInformation`）を、本当の予約が成功したかを
/// 見ずに覚えておき、閉じるときに台帳へ`delete`を書いていた。読み取り専用のファイルは予約そのものが
/// 断られる（`STATUS_CANNOT_DELETE`）ので、実際には消えていないのに台帳の上では削除済みになる。
fn case_w_a_refused_delete_keeps_the_file(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-w-refused-delete");
    let session1 = setup_baseline(ex, &ws, "cow-w")?;
    // サンドボックスの外（この試験プロセス）で本物を読み取り専用にする。
    // **どの経路で抜けても戻す**——残すと次の回の`case_dir`がこのワークスペースを消せない。
    let target = ws.join("test3.txt");
    set_readonly_checked(&target, true)?;
    let body = case_w_body(ex, &ws, &target);
    let restored = if target.exists() {
        set_readonly_checked(&target, false)
    } else {
        Ok(())
    };
    let session2 = body?;
    restored?;
    cleanup_on_success(&ws, &[&session1, &session2], "cow-w");
    Ok(())
}

fn case_w_body(ex: &CowExclusive, ws: &Path, target: &Path) -> Result<String, String> {
    let script = "try { [System.IO.File]::Delete('test3.txt'); $deleted = $true } \
catch { $deleted = $false }; \
$content = if (Test-Path test3.txt) { Get-Content test3.txt -Raw } else { $null }; \
[pscustomobject]@{ deleted = $deleted; content = $content } | ConvertTo-Json -Compress";
    let (session2, report) = run_round2_with_report(ex, ws, script, "cow-w-r2", "deleted")?;
    if report["deleted"].as_bool() != Some(false) {
        return Err(format!(
            "precondition: deleting the read-only test3.txt must fail inside the session, \
             otherwise this case tests nothing: {report}"
        ));
    }
    if report["content"].as_str() != Some("baseline3") {
        return Err(format!(
            "BUG-171: after a refused delete, test3.txt must still be readable inside the session \
             (the delete was recorded although the disposition was refused): {report}"
        ));
    }

    let changes = list_changes_json(ws, &session2)?;
    if change_ops_for(&changes, "test3.txt")?
        .iter()
        .any(|op| op == "delete")
    {
        return Err(format!(
            "BUG-171: a refused delete left a delete of test3.txt in the change list: {changes}"
        ));
    }

    // BUG-171が守るのは「本物を消さない」こと。`apply`の結果が綺麗かは見ない——削除のための
    // openは成功しているので、中身の変わらないコピーが`modify`として載り（合格基準P2の問題、段6）、
    // `apply`は読み取り専用の本物へ同じ中身を書こうとして断られる（2026-09-27の実行で観測。
    // 拒否欄へ入るので終了コード4になるが、本物は変わらない）。その結果は印字して記録へ回す。
    let applied = apply_cow(ws, &session2, None)?;
    println!(
        "{}",
        serde_json::json!({ "observed_in": "W", "apply_report": applied })
    );
    expect_eq(
        "test3.txt after apply (it must not be deleted)",
        &read_file(target)?,
        "baseline3",
    )?;
    Ok(session2)
}

/// X: セッションの中で消したファイルを同じ名前で作り直すと、**新しい中身だけ**になること。
///
/// BUG-171の横展開で見つけた形。論理削除（台帳の`Delete`とメモリ上の削除済み集合）の後に
/// 作成できる開き方で開くと、Redirectorは削除済みの印を**本当のopenの前に**外し、`copy_up`が
/// workspaceの**元の中身**を差分層へ写してから開いていた。追記で作り直すと「元の中身＋追記」になり、
/// 「新規のみ」で作り直すと写したばかりのコピーとぶつかって失敗する——どちらも、消したはずの
/// ファイルが生き返る。2通りの作り直し方を1本の行で並べる。
fn case_x_recreating_a_deleted_file_starts_empty(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-x-recreate-deleted");
    let session1 = setup_baseline(ex, &ws, "cow-x")?;
    let script = "Remove-Item test.txt; Add-Content test.txt 'x' -NoNewline; \
$appended = Get-Content test.txt -Raw; \
Remove-Item test1.txt; \
try { [System.IO.File]::Open('test1.txt', 'CreateNew').Dispose(); $createdNew = $true } \
catch { $createdNew = $false }; \
$fresh = if (Test-Path test1.txt) { [System.IO.File]::ReadAllText('test1.txt') } else { $null }; \
[pscustomobject]@{ appended = $appended; createdNew = $createdNew; fresh = $fresh } \
| ConvertTo-Json -Compress";
    let (session2, report) = run_round2_with_report(ex, &ws, script, "cow-x-r2", "createdNew")?;
    if report["appended"].as_str() != Some("x") {
        return Err(format!(
            "appending to a deleted-then-recreated test.txt must give only the new content 'x' \
             (the original was copied back before the open): {report}"
        ));
    }
    if report["createdNew"].as_bool() != Some(true) || report["fresh"].as_str() != Some("") {
        return Err(format!(
            "CreateNew on a deleted test1.txt must succeed and give an empty file (it collided \
             with the original copied back before the open): {report}"
        ));
    }

    let applied = apply_cow(&ws, &session2, None)?;
    expect_apply_clean("X", &applied)?;
    expect_eq("test.txt after apply", &read_file(&ws.join("test.txt"))?, "x")?;
    expect_eq("test1.txt after apply", &read_file(&ws.join("test1.txt"))?, "")?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-x");
    Ok(())
}

/// Y: セッションの中で消したファイルを「無ければ作る」開き方で開くと、**元の中身が見えない**こと。
///
/// 論理削除の判定（`check_deleted`）は、作り直せる開き方を通していた——作り直しの書込に
/// 進ませるためである。ところがその後の分岐は**書込目的があるかどうか**で誘導を決めるので、
/// 「無ければ作るが、読むだけ」という開き方はどちらの枝にも入らず素通しし、
/// **読取専用のworkspaceに在る元のファイルを開いてしまう**。同じとき`Test-Path`は偽を返すので、
/// セッションの中の見え方が入口ごとに食い違う（BUG-172の教訓「状態を読む入口がすべて同じ答えを
/// 返すか」の残り）。`.NET`の`FileMode.OpenOrCreate`がこの開き方である。
fn case_y_opening_a_deleted_file_with_open_or_create_does_not_see_the_original(
    ex: &CowExclusive,
) -> Result<(), String> {
    let ws = case_dir("cow-y-deleted-open-or-create");
    let session1 = setup_baseline(ex, &ws, "cow-y")?;
    let script = "Remove-Item test.txt; \
$exists = Test-Path test.txt; \
$s = [System.IO.File]::Open('test.txt', 'OpenOrCreate', 'Read'); \
$len = $s.Length; $s.Dispose(); \
[pscustomobject]@{ exists = $exists; len = $len } | ConvertTo-Json -Compress";
    let (session2, report) = run_round2_with_report(ex, &ws, script, "cow-y-r2", "len")?;
    if report["exists"].as_bool() != Some(false) {
        return Err(format!(
            "control: after Remove-Item, Test-Path must say the file is gone: {report}"
        ));
    }
    if report["len"].as_i64() != Some(0) {
        return Err(format!(
            "BUG: opening the deleted test.txt with OpenOrCreate must not show the original \
             content (got {} bytes; the workspace original is 10): {report}",
            report["len"].as_i64().unwrap_or(-1)
        ));
    }

    // 台帳の側も、削除のあとに作り直しが載っていること（見え方と一覧が食い違わない）。
    let changes = list_changes_json(&ws, &session2)?;
    let ops = change_ops_for(&changes, "test.txt")?;
    if ops.last().map(String::as_str) == Some("delete") {
        return Err(format!(
            "the change list still ends with a delete of test.txt, although the session recreated \
             it: {changes}"
        ));
    }

    let applied = apply_cow(&ws, &session2, None)?;
    expect_apply_clean("Y", &applied)?;
    expect_eq("test.txt after apply", &read_file(&ws.join("test.txt"))?, "")?;

    cleanup_on_success(&ws, &[&session1, &session2], "cow-y");
    Ok(())
}

#[test]
#[ignore]
fn tier2a_cow_commit_matrix() {
    let ex = cow_exclusive();
    let cases: Vec<(&str, CowCaseFn)> = vec![
        ("A-new-only", case_a_commit_only_new_file),
        ("B-modify-only", case_b_commit_only_modifications),
        ("C-delete-only", case_c_commit_only_deletion),
        ("D-rename-only", case_d_commit_only_rename),
        ("E-commit-all", case_e_commit_all_at_once),
        (
            "F-partial-then-rest",
            case_f_partial_then_rest_matches_commit_all,
        ),
        (
            "G-hard-deny-config-injection",
            case_g_hard_deny_config_injection,
        ),
        ("H-toctou-conflict", case_h_toctou_conflict),
        (
            "I-write-file-tool-captured",
            case_i_write_file_tool_is_captured_by_cow,
        ),
        ("J-discard", case_j_discard_removes_all_changes),
        (
            "K-resolve-auto-merge",
            case_k_resolve_auto_merges_non_overlapping_conflict,
        ),
        (
            "L-resume-continues-session",
            case_l_resume_continues_same_cow_session,
        ),
        (
            "M-create-delete-same-session",
            case_m_new_file_created_and_deleted_within_same_cow_session,
        ),
        (
            "N-ls-merge-and-clean-read",
            case_n_ls_merges_preexisting_and_new_files_read_does_not_dirty_ledger,
        ),
        (
            "O-direct-diff-layer-write-is-recorded",
            case_o_direct_write_into_the_diff_layer_dir_is_recorded,
        ),
        // P〜S: BUG-066追加検証。`--cwd`の綴り4形（相対・大小差・末尾区切り・`\\?\`）を
        // 製品通しで測る（`run_cwd_spelling_case`のdoc参照）。
        ("P-cwd-relative", case_p_cwd_relative),
        ("Q-cwd-uppercased", case_q_cwd_uppercased),
        ("R-cwd-trailing-separator", case_r_cwd_trailing_separator),
        ("S-cwd-verbatim-prefix", case_s_cwd_verbatim_prefix),
        (
            "T-workspace-longer-than-max-path",
            case_t_workspace_path_longer_than_max_path,
        ),
        // U〜W: BUG-171。失敗した操作を台帳が「起きた」と記録しないこと。
        (
            "U-deleting-a-missing-file-leaves-no-entry",
            case_u_deleting_a_missing_file_leaves_no_entry,
        ),
        (
            "V-a-failed-rename-keeps-the-source",
            case_v_a_failed_rename_keeps_the_source,
        ),
        (
            "W-a-refused-delete-keeps-the-file",
            case_w_a_refused_delete_keeps_the_file,
        ),
        // X: BUG-171の横展開。消したファイルを作り直すと新しい中身だけになること。
        (
            "X-recreating-a-deleted-file-starts-empty",
            case_x_recreating_a_deleted_file_starts_empty,
        ),
        // Y: 論理削除の後の「無ければ作るが読むだけ」の開き方（`.NET`の`OpenOrCreate`）。
        (
            "Y-deleted-file-opened-with-open-or-create-is-empty",
            case_y_opening_a_deleted_file_with_open_or_create_does_not_see_the_original,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, || f(&ex)) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} CoW commit matrix cases passed (see per-case JSON above for details)"
    );
}

// ============================================================================
// 検証: git だけで層3 hard-deny（設定注入パスの拒否）を迂回できるか
// （`plans/PLAN-COW-AS-DEFAULT.md`「検証タスク」。CoW既定化の決める4つの2の前提）
// ============================================================================

/// サンドボックス外（このテストプロセス自身、昇格済み）で回す素の`git`。種付けと最後の
/// `checkout`に使う。ハードニングenv（`harness-core::git::hardening_env`）は**わざと通さない**
/// ——ここはサンドボックス内でモデルが起動する git ではなく、テスト足場の git だから。
/// `-c safe.directory=*`と作者identityだけ固定する（AppContainerが書いた 差分層 由来の
/// オブジェクトを apply で受けた実リポジトリを、別条件で触っても「dubious ownership」等で
/// 落ちないように）。
fn plain_git(ws: &Path, args: &[&str]) -> Result<String, String> {
    let mut full = vec![
        "-c".to_string(),
        "safe.directory=*".to_string(),
        "-c".to_string(),
        "user.name=e2e".to_string(),
        "-c".to_string(),
        "user.email=e2e@example.com".to_string(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let output = Command::new("git")
        .current_dir(ws)
        .args(&full)
        .output()
        .map_err(|e| format!("failed to spawn git {args:?}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 実workspaceに正当な git リポジトリを1つ種付けする（`master`＝README1件のコミット）。
/// **サンドボックスの外**で作るので、以後の CoW セッション内 git はこの`.git`を読む
/// （RO読取は read scope 内、書込は 差分層 へリダイレクト）。
fn git_seed_repo(ws: &Path) -> Result<(), String> {
    std::fs::write(ws.join("README.md"), "seed\n").map_err(|e| format!("seed README: {e}"))?;
    plain_git(ws, &["init", "-q"])?;
    plain_git(ws, &["add", "README.md"])?;
    plain_git(ws, &["commit", "-q", "-m", "seed"])?;
    Ok(())
}

/// `ws/.git/objects/xx/....`のルース・オブジェクト数（`pack`/`info`は除く）。迂回で
/// 実リポジトリのオブジェクトが増えたことの傍証に使う。
fn count_loose_git_objects(ws: &Path) -> usize {
    let objects = ws.join(".git").join("objects");
    let mut n = 0;
    let Ok(top) = std::fs::read_dir(&objects) else {
        return 0;
    };
    for e in top.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        // ルースは2桁hexのファンアウトディレクトリ配下にある。
        if name.len() == 2 && name.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(inner) = std::fs::read_dir(e.path()) {
                n += inner.flatten().count();
            }
        }
    }
    n
}

/// CoWセッション内で **git だけ** を使い、hard-deny 対象パス(`.github/workflows/x.yml`)を
/// 「ワークツリー実体」ではなく「コミット・オブジェクト＋ブランチ移動」として運ぶ台本。
///
/// 全 git 出力を`_git-log.txt`（ワークツリー、＝差分層へ捕捉される）へ落とし、セッション後に
/// テスト側が読んで診断できるようにする（run_shellの出力はモックへ返るだけで harness の
/// stdout には出ないため）。`$env:GIT_*`で作者identityを固定し、ハードニングenvの
/// `GIT_CONFIG_COUNT`とは衝突しない別チャネルで author を与える。
const GIT_INJECTION_SCRIPT: &str = r#"$ErrorActionPreference = 'Continue'
$env:GIT_AUTHOR_NAME = 'e2e'
$env:GIT_AUTHOR_EMAIL = 'e2e@example.com'
$env:GIT_COMMITTER_NAME = 'e2e'
$env:GIT_COMMITTER_EMAIL = 'e2e@example.com'
'=== git --version ===' | Out-File -FilePath _git-log.txt -Encoding utf8
git -c safe.directory=* --version *>> _git-log.txt
New-Item -ItemType Directory -Force .github/workflows | Out-Null
Set-Content -LiteralPath .github/workflows/x.yml -Value 'name: evil-injected-via-git' -NoNewline
'=== git add (config-injection path, tracked) ===' | Out-File -FilePath _git-log.txt -Append -Encoding utf8
git -c safe.directory=* add .github/workflows/x.yml *>> _git-log.txt
"add exit=$LASTEXITCODE" | Out-File -FilePath _git-log.txt -Append -Encoding utf8
'=== git commit ===' | Out-File -FilePath _git-log.txt -Append -Encoding utf8
git -c safe.directory=* commit -m 'inject ci workflow via tracked object' *>> _git-log.txt
"commit exit=$LASTEXITCODE" | Out-File -FilePath _git-log.txt -Append -Encoding utf8
'=== git update-ref (move master to the injected commit) ===' | Out-File -FilePath _git-log.txt -Append -Encoding utf8
git -c safe.directory=* update-ref refs/heads/master HEAD *>> _git-log.txt
"update-ref exit=$LASTEXITCODE" | Out-File -FilePath _git-log.txt -Append -Encoding utf8
'=== git rev-parse HEAD ===' | Out-File -FilePath _git-log.txt -Append -Encoding utf8
git -c safe.directory=* rev-parse HEAD *>> _git-log.txt
"rev-parse exit=$LASTEXITCODE" | Out-File -FilePath _git-log.txt -Append -Encoding utf8"#;

/// **BUG-128 の回帰テスト（`docs/bugs/BUG-128.md`）**。
///
/// CoW（`--sandbox tier2a-cow`）セッション内で、**git がオブジェクトを書けて `git commit` が
/// 完走する**ことを実機で確かめる。修正前は、透過役（Redirector DLL）が git のハンドル相対 open
/// （openat 方式）を解決できず、`.git/objects/pack: Function not implemented` で commit が落ちて
/// いた。修正は「OS にハンドルの名前を後から聞く」代わりに「開いた瞬間に記録した対応表を引く」
/// もので、`crates/harness-redirector/src/ntpath.rs` の `resolve_relative_via_handle_map` が本体。
///
/// **緑 = 修正が効いている**（git がオブジェクトを書き、`commit` が exit 0）。
/// **赤 = まだ完走しない**（対応表に無いハンドルが残る等）。赤なら 差分層 の `_git-log.txt` と、
/// `resolve_relative_via_handle_map` が仕込んだ hit/miss ログ（差分層 の `.harness-cow-debug.log`）で
/// どのハンドルが未解決かを辿る。
///
/// **このテストは 穴2（CoW 下で git が動かない）だけを見る。** 穴1（apply の層3 hard-deny が
/// git オブジェクト経由の設定注入を通すこと）は別レイヤで、`harness-sandbox` の
/// `overlay.rs::apply_hard_deny_is_bypassed_by_git_objects_carrying_a_config_injection_file` が
/// 確定済み。穴2が直った今、穴1は live でも到達可能になった——その塞ぎ方は運用判断待ち
/// （`plans/PLAN-COW-AS-DEFAULT.md` 決める4つの2）。
#[test]
#[ignore]
fn tier2a_cow_git_commit_writes_objects_under_the_redirector() {
    // **BUG-135の修正はこの1行。** CoWセッションを作るテストなのに排他ロックを取っておらず、
    // `e2e-all`（全件を並行実行）では`tier2a_cow_commit_matrix`と互いのセッションを拾って
    // 両方落ちていた。単独実行では2本とも緑なので、個別ターゲットだけ回していると見えない。
    let ex = cow_exclusive();
    if let Err(e) = git_commit_under_cow_probe(&ex) {
        panic!("{e}");
    }
}

fn git_commit_under_cow_probe(ex: &CowExclusive) -> Result<(), String> {
    let ws = case_dir("cow-git-injection");

    // サンドボックス外で正当なリポジトリを種付け（git がコミット先の `.git` を持つように）。
    git_seed_repo(&ws)?;

    // CoW セッションで git だけを使い、コミット＋ref移動を試みる。
    let before = ex.list_cow_sessions();
    let run = run_harness(
        &ws,
        &run_shell_script_turns(GIT_INJECTION_SCRIPT),
        &["--sandbox", "tier2a-cow"],
        "cow-git-injection-r2",
    );
    if !run.status.success() {
        return Err(format!(
            "harness invocation failed (stdout={} stderr={})",
            run.stdout, run.stderr
        ));
    }
    let session = ex.new_cow_session(&before)?;
    let diff_layer = cow_diff_layer_dir(&session);
    let git_log = std::fs::read_to_string(diff_layer.join("_git-log.txt"))
        .unwrap_or_else(|e| format!("(could not read diff_layer/_git-log.txt: {e})"));

    // 台帳（apply 前の changes 一覧）に git オブジェクトが載ったか。
    let changes = list_changes_json(&ws, &session)?;
    let change_paths: Vec<String> = changes
        .as_array()
        .ok_or("changes json is not an array")?
        .iter()
        .filter_map(|c| c["path"].as_str().map(|p| p.replace('\\', "/")))
        .collect();
    let object_entries: Vec<&String> = change_paths
        .iter()
        .filter(|p| p.starts_with(".git/objects/"))
        .collect();
    let diff_layer_loose_objects = count_loose_git_objects(&diff_layer);
    let commit_ok = git_log.contains("commit exit=0");
    // 対照: 通常のファイル書込（ワークツリー実体）の copy-up が成立していること
    //（＝Redirector はロードされ、セッションは実際に走った。空振り緑を避ける、B-35）。
    let working_tree_copy_up = change_paths.iter().any(|p| p == ".github/workflows/x.yml");

    let evidence = serde_json::json!({
        "bug": "BUG-128",
        "git_objects_in_ledger": object_entries.len(),
        "diff_layer_loose_objects": diff_layer_loose_objects,
        "commit_reported_exit_0": commit_ok,
        "working_tree_copy_up_succeeded": working_tree_copy_up,
        "changes_paths_sample": change_paths.iter().take(30).collect::<Vec<_>>(),
    });

    if !working_tree_copy_up {
        return Err(format!(
            "control failed: the CoW session did not even copy-up the working-tree file, so a green \
             result would be vacuous (the session may not have run under the redirector).\n\
             {evidence:#}\n--- diff_layer/_git-log.txt ---\n{git_log}"
        ));
    }

    if object_entries.is_empty() && diff_layer_loose_objects == 0 {
        return Err(format!(
            "BUG-128 still reproduces: git wrote NO objects under CoW. The handle-map fallback \
             (resolve_relative_via_handle_map) did not resolve git's openat chain — check diff_layer/\
             .harness-cow-debug.log for which root handle was 'not in handle_paths'.\n{evidence:#}\n\
             --- diff_layer/_git-log.txt ---\n{git_log}"
        ));
    }

    if !commit_ok {
        return Err(format!(
            "git wrote objects but `git commit` did not report exit=0 — the fix is partial.\n\
             {evidence:#}\n--- diff_layer/_git-log.txt ---\n{git_log}"
        ));
    }

    // 緑: 修正が効いている（git がオブジェクトを書き、commit が完走した）。
    println!("{evidence:#}\n--- diff_layer/_git-log.txt ---\n{git_log}");
    cleanup_on_success(&ws, &[&session], "cow-git-injection");
    Ok(())
}

// ============================================================================
// 段5: CoWセッション1本の変更一覧を、分類ごとに数える
// （`plans/PLAN-COW-AS-DEFAULT.md` 段5・合格基準P1〜P6、`plans/handoff/cow-followup/INDEX.md` T-D）
// ============================================================================
//
// **何のための測定か。** CoWを既定にする前に、段6で「一覧のまとめ方」と「ignoreの扱い」を
// 決める。その入力は「いまCoWセッションを1本回すと、変更一覧（`harness changes`）に何が何件出るか」
// で、これは一度も測られていなかった。段7は**この試験を撃ち直して**合格基準P1〜P6を判定する。
//
// **数える軸は合格基準P1〜P6が見る軸**——`.git`成分を含むパス（P1）／中身の変わらないコピー（P2）／
// ignoreされた生成物（P6）／それ以外。**製品の分類（`ChangeEntry::category`）は使わない**:
// 製品は`.git/config`・`.git/hooks/**`を`config_injection`へ入れるので、`git_internal`だけを
// 数えると`.git`成分を数え漏らす。計器は製品から独立に作る（同じ源から出た2つを突き合わせても
// 検算にならない）。
//
// **手順は[`CENSUS_STEPS`]の1つの表にだけ書く。** mockの台本・実モデルへの指示文・
// 「その段を踏んだか」の照合は、全部この表から作る——2本の腕が同じ手順であることを、
// 書き写しではなく作りで保証するため。手順が`run_shell`を使わないのは、人のいない`accept-all`
// では完全一致の規則が無い`run_shell`が全部拒否され（D-102）、実モデルが自分で書く行は
// 1本も通らないから。`run_program`（gitを直接起動）と`write_file`は規則無しで通る。
//
// **限界（同じ場所で言う）**: 小さなリポジトリで1コミットだけの手順なので、件数の絶対値は
// 実際のセッション（ビルドで何千件の生成物が出る等）を代表しない。読むのは「どの分類が出るか」と
// 分類どうしの関係である。人が見る一覧のうち測るのはCLI（JSONとテキスト）だけで、TUIの変更パネルは
// 測らない。ワークスペース外への書込（`_ext`）と`run_shell`経由の書込は手順に入れていない。

/// LMStudio（`docs/DEV-ENVIRONMENT.md`「手動E2E用ローカルLMStudioサーバ」）。
#[cfg(feature = "e2e-live")]
const LMSTUDIO_ORIGIN: &str = "http://localhost:1234";
const LMSTUDIO_BASE_URL: &str = "http://localhost:1234/v1";

/// 実モデルの腕の既定モデル。`docs/DEV-ENVIRONMENT.md`が手動E2E用に名指しするモデル
/// （`qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp`）の、LMStudio上の現在のid。
#[cfg(feature = "e2e-live")]
const CENSUS_LIVE_DEFAULT_MODEL: &str = "luffythefox/qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp-gguf/qwen3.6-35b-a3b-uncensored-genesis-mtp-apex.gguf";

/// 実モデルの腕のモデルを差し替えるファイル（1行にモデルid）。**環境変数は昇格デーモン配下の
/// 試験へ届かない**ので、ファイルで渡す（`n8-smb445-layer2`の`n8-smb-host.txt`と同じ形）。
#[cfg(feature = "e2e-live")]
const CENSUS_LIVE_MODEL_FILE: &str = r"C:\harness-e2e\cow-census-live-model.txt";

/// 実モデルの腕の期限。`dev-elevated-run`のクライアントは20分しか待たない。
const CENSUS_LIVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(14 * 60);

/// 段9で**同じ中身のまま**書き直すファイルの中身。種付けと段9の両方がこの1つの定数を使う
/// ——片方だけ書き換えると「中身の変わらないコピー」の対照が黙って崩れるため。
const CENSUS_GUIDE_TXT: &str = "guide: the agent rewrites this file with identical bytes\n";

/// 種付けするファイル（改行はLFだけ。`core.autocrlf`で中身が変わらないように）。
const CENSUS_SEED: &[(&str, &str)] = &[
    ("README.md", "census seed\n"),
    ("notes.txt", "this file is deleted by the agent\n"),
    ("src/lib.txt", "fn original() {}\n"),
    ("docs/guide.txt", CENSUS_GUIDE_TXT),
    (".gitignore", "target/\n"),
];

/// 手順の1段。
enum CensusStep {
    /// `git -c safe.directory=* <args…>`を`run_program`で起こす。`safe.directory`は計器側の都合
    /// ——昇格した試験が作ったワークスペースは所有者がAdministratorsになり、サンドボックスの子の
    /// gitが「dubious ownership」で止まる（`plans/net-spike/RESULTS.md` N8-M1-iと同じ）。
    Git(&'static [&'static str]),
    /// `write_file`で書く。
    Write {
        path: &'static str,
        content: &'static str,
    },
}

/// 手順。**mockの台本・実モデルへの指示文・踏んだかの照合の3つを、ここからだけ作る。**
/// 右の注記は、その段が変更一覧のどの分類を作るつもりか。
const CENSUS_STEPS: &[CensusStep] = &[
    // 1: .git（HEAD・refs・reflog）
    CensusStep::Git(&["switch", "-c", "feature"]),
    // 2・3: それ以外（この後コミットする作業ツリーの変更）
    CensusStep::Write {
        path: "src/lib.txt",
        content: "fn original() {}\nfn added_by_agent() {}\n",
    },
    CensusStep::Write {
        path: "src/new.txt",
        content: "new file committed by the agent\n",
    },
    // 4: .git（index）。`add -A`は使わない——ハーネスは起動のたびに本物のワークスペースへ
    // `.harness/`を作り、サンドボックスからの読み書きを剥がすので、全体を拾うと当たる。
    CensusStep::Git(&["add", "--", "src/lib.txt", "src/new.txt"]),
    // 5: .git（ゆるいオブジェクト・ref）。種付けで全部packへ畳んであるので、gitがpackの
    // 時刻だけを更新しに来れば「中身の変わらないコピー」が.gitの中に出る（出るかは観測）。
    CensusStep::Git(&[
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.com",
        "commit",
        "-q",
        "-m",
        "census: agent commit",
    ]),
    // 6・7・8: それ以外（コミットしない変更: 変更・未追跡の新規・削除）
    CensusStep::Write {
        path: "README.md",
        content: "census seed\nedited but not committed\n",
    },
    CensusStep::Write {
        path: "scratch.txt",
        content: "untracked scratch file\n",
    },
    CensusStep::Git(&["rm", "-q", "notes.txt"]),
    // 9: 中身の変わらないコピー（何も変えなかった整形器の模擬）
    CensusStep::Write {
        path: "docs/guide.txt",
        content: CENSUS_GUIDE_TXT,
    },
    // 10・11: ignoreされた生成物（ホスト側の書込と、子プロセスの書込の両方）
    CensusStep::Write {
        path: "target/debug/build.log",
        content: "build output (ignored)\n",
    },
    CensusStep::Git(&["archive", "--format=tar", "-o", "target/debug/app.tar", "HEAD"]),
];

/// 段の道具呼び出し（道具名と入力）。台本・指示文・照合の3つが共有する。
fn census_step_call(step: &CensusStep) -> (&'static str, serde_json::Value) {
    match step {
        CensusStep::Git(args) => {
            let mut argv = vec!["-c".to_string(), "safe.directory=*".to_string()];
            argv.extend(args.iter().map(|a| a.to_string()));
            (
                "run_program",
                serde_json::json!({ "program": "git", "args": argv }),
            )
        }
        CensusStep::Write { path, content } => (
            "write_file",
            serde_json::json!({ "path": path, "content": content }),
        ),
    }
}

/// gitの引数列から副コマンドを取り出す（`-c <値>`を読み飛ばした最初の、`-`で始まらない語）。
fn git_subcommand(args: &[String]) -> Option<&str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-c" || a == "-C" {
            it.next();
            continue;
        }
        if !a.starts_with('-') {
            return Some(a.as_str());
        }
    }
    None
}

fn census_mock_turns() -> Vec<Vec<StreamEvent>> {
    let mut turns: Vec<Vec<StreamEvent>> = CENSUS_STEPS
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let (tool, input) = census_step_call(step);
            tool_use_turn(&format!("call_{}", i + 1), tool, input)
        })
        .collect();
    turns.push(end_turn("done"));
    turns
}

/// 実モデルへ渡す指示文。**各段の道具と入力を、台本と同じJSONのまま**並べる。
fn census_live_prompt() -> String {
    let mut prompt = format!(
        "This is a scripted measurement of the sandbox, not a coding task. Perform exactly the \
         following {} steps, in order, one tool call per step, using exactly the tool and the \
         arguments given as JSON. Do not call any other tool, do not use run_shell, do not read or \
         verify anything between steps, and do not retry a step that fails. After the last step, \
         reply with the single word DONE.\n\n",
        CENSUS_STEPS.len()
    );
    for (i, step) in CENSUS_STEPS.iter().enumerate() {
        let (tool, input) = census_step_call(step);
        prompt.push_str(&format!("Step {}: call `{tool}` with {input}\n", i + 1));
    }
    prompt
}

/// 道具呼び出しが手順の段に当たるか。**厳密**（mock）は道具名と入力の完全一致、
/// **緩い**（実モデル）は道具名と、gitなら副コマンド・書込ならパスの一致。
fn census_call_matches(step: &CensusStep, call: &ToolCallView, strict: bool) -> bool {
    let (tool, input) = census_step_call(step);
    if call.name != tool {
        return false;
    }
    if strict {
        return call.input == input;
    }
    match step {
        CensusStep::Git(_) => {
            let program = call.input["program"].as_str().unwrap_or_default();
            let program_is_git = Path::new(program)
                .file_stem()
                .is_some_and(|s| s.eq_ignore_ascii_case("git"));
            let args: Vec<String> = call.input["args"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let expected: Vec<String> = input["args"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            program_is_git && git_subcommand(&args) == git_subcommand(&expected)
        }
        CensusStep::Write { path, .. } => {
            call.input["path"].as_str().map(|p| p.replace('\\', "/")).as_deref() == Some(*path)
        }
    }
}

/// 手順の各段に、それを踏んだ呼び出しの添字を割り当てる（順序を保って前から探す）。
/// 返り値の2つ目は、どの段にも当たらなかった呼び出しの添字。
fn match_census_steps(
    calls: &[ToolCallView],
    strict: bool,
) -> (Vec<Option<usize>>, Vec<usize>) {
    let mut assigned = Vec::with_capacity(CENSUS_STEPS.len());
    let mut used = vec![false; calls.len()];
    let mut cursor = 0;
    for step in CENSUS_STEPS {
        let found = (cursor..calls.len()).find(|&i| census_call_matches(step, &calls[i], strict));
        if let Some(i) = found {
            used[i] = true;
            cursor = i + 1;
        }
        assigned.push(found);
    }
    let extras = (0..calls.len()).filter(|&i| !used[i]).collect();
    (assigned, extras)
}

/// 種付け: 全部をpackへ畳み、本体層のゆるいオブジェクトを0にする。そうしておくと、差分層に
/// 出たゆるいオブジェクトはエージェントのものだと読め、packの時刻更新も観測できる（N8-M1-i）。
fn census_seed_repo(ws: &Path) -> Result<(), String> {
    for (rel, content) in CENSUS_SEED {
        let path = ws.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("seed mkdir {rel}: {e}"))?;
        }
        std::fs::write(&path, content).map_err(|e| format!("seed write {rel}: {e}"))?;
    }
    plain_git(ws, &["init", "-q", "-b", "main"])?;
    plain_git(ws, &["-c", "core.autocrlf=false", "add", "-A"])?;
    plain_git(ws, &["-c", "core.autocrlf=false", "commit", "-q", "-m", "seed"])?;
    plain_git(ws, &["repack", "-adq"])?;
    plain_git(ws, &["prune"])?;
    let loose = count_loose_git_objects(ws);
    if loose != 0 {
        return Err(format!(
            "seed left {loose} loose object(s) in the real repository, so loose objects in the diff \
             layer can no longer be read as the agent's own"
        ));
    }
    Ok(())
}

/// 本物のワークスペースで、どのパスがignoreされるかを素の`git check-ignore`で判定する。
///
/// - **利用者全体のignore（`core.excludesFile`）は切る**——この機には`~/.config/git/ignore`が
///   あり、混ざると「リポジトリの`.gitignore`が何を捨てるか」ではなくなる。
///   出所が`.gitignore`以外なら誤りとして返す。
/// - 渡すのは`.git`でない**相対**パスだけにすること（絶対パスが混ざるとgitは全体を128で落とす）。
///   差分層でディレクトリのものは末尾`/`を付けて渡す（`target/`は「ディレクトリだけ」の規則で、
///   本物のワークスペースにはそのディレクトリが無いため）。
/// - 終了コードは0（1つ以上ignore）と1（1つも無い）が正常。
fn git_check_ignore(ws: &Path, paths: &[String]) -> Result<HashSet<String>, String> {
    use std::io::Write;
    if paths.is_empty() {
        return Ok(HashSet::new());
    }
    let mut child = Command::new("git")
        .current_dir(ws)
        .args([
            "-c",
            "safe.directory=*",
            "-c",
            r"core.excludesFile=C:/harness-e2e/_no-such-global-excludes-file",
            "check-ignore",
            "-v",
            "-n",
            "-z",
            "--stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn git check-ignore: {e}"))?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut input = Vec::new();
        for p in paths {
            input.extend_from_slice(p.as_bytes());
            input.push(0);
        }
        stdin
            .write_all(&input)
            .map_err(|e| format!("failed to feed git check-ignore: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("git check-ignore did not finish: {e}"))?;
    match output.status.code() {
        Some(0) | Some(1) => {}
        other => {
            return Err(format!(
                "git check-ignore failed ({other:?}): {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
    // `-v -n -z`: 入力1件ごとに、**入力の順で** `<出所>\0<行番号>\0<パターン>\0<パス>\0`。
    // 一致しないものは出所が空。答えは**順番で**入力へ対応付ける——gitが返すパスの綴り
    // （末尾`/`の有無など）に頼ると、綴りが1文字違っただけで無言で取りこぼす。
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let fields: Vec<&str> = stdout.split('\0').collect();
    let records: Vec<&[&str]> = fields.chunks(4).filter(|r| r.len() == 4).collect();
    if records.len() != paths.len() {
        return Err(format!(
            "git check-ignore answered {} record(s) for {} path(s) — cannot tell which path an \
             answer belongs to. stdout={stdout:?}",
            records.len(),
            paths.len()
        ));
    }
    let mut ignored = HashSet::new();
    for (asked, rec) in paths.iter().zip(records) {
        let source = rec[0];
        if source.is_empty() {
            continue;
        }
        if source != ".gitignore" {
            return Err(format!(
                "{asked:?} was ignored by {source:?}, not by the repository's .gitignore — the \
                 census would be counting a rule that is not part of the repository"
            ));
        }
        ignored.insert(asked.clone());
    }
    Ok(ignored)
}

/// 変更一覧1件を分けた先。**排他の順序は INDEX の軸の順**（`.git` → 同一コピー → ignore → それ以外）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CensusClass {
    GitComponent,
    ByteIdentical,
    Ignored,
    Other,
}

impl CensusClass {
    const ALL: [CensusClass; 4] = [
        CensusClass::GitComponent,
        CensusClass::ByteIdentical,
        CensusClass::Ignored,
        CensusClass::Other,
    ];

    fn key(self) -> &'static str {
        match self {
            CensusClass::GitComponent => "git_component",
            CensusClass::ByteIdentical => "byte_identical",
            CensusClass::Ignored => "ignored",
            CensusClass::Other => "other",
        }
    }
}

/// 変更一覧1件に、製品の分類とは独立に付けた印。
#[derive(Debug)]
struct CensusEntry {
    op: String,
    path: String,
    product_category: String,
    unledgered: bool,
    rejected: bool,
    ext: bool,
    is_dir: bool,
    /// `create`として一覧に載っているのに、差分層にも本物にも実体が無い（**実体の無い`create`**）。
    ///
    /// 2026-09-27の初回の測定で見つかった（`plans/cow-default-spike/RESULTS.md`）。gitは
    /// `switch`・`commit`のたびに`MERGE_HEAD`等の後始末で**存在しないファイルを消しに行き**、
    /// Redirectorはその削除のためのopenを`create`として台帳へ載せ、対になる削除を載せない。
    /// **計器の故障ではなく、いまの一覧が実際に持っているもの**なので、数えて出す。
    phantom_create: bool,
    /// `modify`なのに差分層に実体が無い（copy-upの失敗は製品側で捨てられる）。**その書込は
    /// 失われている**ので、これは計器の検算に使う（実体の無い `create` とは別の事実）。
    lost_in_diff_layer: bool,
    git_component: bool,
    byte_identical: bool,
    /// `modify`のファイルについて、バイト比較の結果と「`baseline_hash`＝差分層の中身のハッシュ」が
    /// 同じ答えを出したか。**2つの独立した計器の突き合わせ**で、`false`なら計器のどちらかが壊れている。
    baseline_agrees: Option<bool>,
    ignored: bool,
    class: CensusClass,
}

/// `harness changes --output-format json`の配列を分類する。
fn classify_census(
    ws: &Path,
    diff_layer: &Path,
    changes: &serde_json::Value,
) -> Result<Vec<CensusEntry>, String> {
    let items = changes
        .as_array()
        .ok_or("changes json is not an array")?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let op = item["op"].as_str().unwrap_or_default().to_string();
        let path = item["path"]
            .as_str()
            .ok_or_else(|| format!("change entry without a path: {item}"))?
            .to_string();
        let ext = Path::new(&path).is_absolute();
        let git_component = harness_core::is_git_internal_path(&path, ws);
        let (is_dir, exists, diff_file) = if ext {
            (false, false, None)
        } else {
            let f = diff_layer.join(path.replace('/', "\\"));
            (f.is_dir(), f.exists(), Some(f))
        };
        let phantom_create = !ext
            && op == "create"
            && !exists
            && !ws.join(path.replace('/', "\\")).exists();
        let lost_in_diff_layer = !ext && op == "modify" && !exists;
        let (byte_identical, baseline_agrees) = match &diff_file {
            Some(f) if op == "modify" && exists && !is_dir => {
                let diff_bytes =
                    std::fs::read(f).map_err(|e| format!("read {}: {e}", f.display()))?;
                let real = ws.join(path.replace('/', "\\"));
                let identical = real.is_file()
                    && std::fs::read(&real).map_err(|e| format!("read {}: {e}", real.display()))?
                        == diff_bytes;
                let by_hash = item["baseline_hash"].as_str()
                    == Some(harness_change_ledger::hash_bytes(&diff_bytes).as_str());
                (identical, Some(by_hash == identical))
            }
            _ => (false, None),
        };
        entries.push(CensusEntry {
            op,
            path,
            product_category: item["category"].as_str().unwrap_or_default().to_string(),
            unledgered: item["unledgered"].as_bool().unwrap_or(false),
            rejected: item.get("rejected").is_some_and(|r| !r.is_null()),
            ext,
            is_dir,
            phantom_create,
            lost_in_diff_layer,
            git_component,
            byte_identical,
            baseline_agrees,
            ignored: false,
            class: CensusClass::Other,
        });
    }
    // ignoreの判定は、`.git`でも`_ext`でもないものをまとめて1回で問う。
    let asked: Vec<(usize, String)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.ext && !e.git_component)
        .map(|(i, e)| {
            let p = if e.is_dir {
                format!("{}/", e.path.trim_end_matches('/'))
            } else {
                e.path.clone()
            };
            (i, p)
        })
        .collect();
    let ignored = git_check_ignore(ws, &asked.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>())?;
    for (i, p) in &asked {
        entries[*i].ignored = ignored.contains(p);
    }
    for e in &mut entries {
        e.class = if e.git_component {
            CensusClass::GitComponent
        } else if e.byte_identical {
            CensusClass::ByteIdentical
        } else if e.ignored {
            CensusClass::Ignored
        } else {
            CensusClass::Other
        };
    }
    Ok(entries)
}

/// `harness changes`（テキスト）のうち、人に見えている行。
#[derive(Debug, PartialEq)]
struct ChangesText {
    /// `(op, path)`。`^(create|modify|delete) +`の行だけ。
    visible: Vec<(String, String)>,
    /// `(N file(s) under `.git` ...)`の N。畳み込み行が無ければ0。
    folded_git: usize,
}

/// テキスト出力（`workspace_cmd.rs`の`Commands::Changes`の`Text`分岐）を読む。
/// **変更の行として数えるのは`^(create|modify|delete) +`だけ**——畳み込み行・`(no changes)`・
/// 拒否の要約（`WARNING: ...`）は行として数えない。
fn parse_changes_text(text: &str) -> ChangesText {
    let mut visible = Vec::new();
    let mut folded_git = 0;
    for line in text.lines() {
        let op = ["create", "modify", "delete"]
            .into_iter()
            .find(|op| line.starts_with(op) && line[op.len()..].starts_with(' '));
        if let Some(op) = op {
            let mut path = line[op.len()..].trim_start();
            for mark in [" [unledgered: ", " [rejected: "] {
                if let Some(i) = path.find(mark) {
                    path = &path[..i];
                }
            }
            visible.push((op.to_string(), path.to_string()));
            continue;
        }
        if let Some(rest) = line.strip_prefix('(') {
            if rest.contains("file(s) under `.git`") {
                if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
                    folded_git = n;
                }
            }
        }
    }
    ChangesText {
        visible,
        folded_git,
    }
}

/// `harness changes --session <id>`（テキスト）の標準出力。
fn list_changes_text(ws: &Path, session_id: &str) -> Result<String, String> {
    let output = Command::new(harness_exe())
        .args([
            "--cwd",
            ws.to_str().unwrap(),
            "changes",
            "--session",
            session_id,
        ])
        .output()
        .map_err(|e| format!("failed to spawn harness changes (text): {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "harness changes (text) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// 差分層の中身とメタデータの量（P7、記録のみ）。copy-upは基準の写し（`.harness-cow-baseline`）も
/// 作るので、**中身と写しを分けて**数える（pack 1つのコピーは容量を2倍食う）。
fn diff_layer_inventory(diff_layer: &Path) -> serde_json::Value {
    fn walk(dir: &Path, files: &mut u64, bytes: &mut u64) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, files, bytes);
            } else if let Ok(m) = e.metadata() {
                *files += 1;
                *bytes += m.len();
            }
        }
    }
    let (mut content_files, mut content_bytes) = (0u64, 0u64);
    let (mut meta_files, mut meta_bytes) = (0u64, 0u64);
    let (mut ext_files, mut ext_bytes) = (0u64, 0u64);
    if let Ok(rd) = std::fs::read_dir(diff_layer) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let (files, bytes) = if name.starts_with(".harness-cow-") {
                (&mut meta_files, &mut meta_bytes)
            } else if name == "_ext" {
                (&mut ext_files, &mut ext_bytes)
            } else {
                (&mut content_files, &mut content_bytes)
            };
            let p = e.path();
            if p.is_dir() {
                walk(&p, files, bytes);
            } else if let Ok(m) = e.metadata() {
                *files += 1;
                *bytes += m.len();
            }
        }
    }
    serde_json::json!({
        "content_files": content_files,
        "content_bytes": content_bytes,
        "metadata_files": meta_files,
        "metadata_bytes": meta_bytes,
        "ext_files": ext_files,
        "ext_bytes": ext_bytes,
    })
}

/// 数えた結果を分類ごと・重なりごとに畳む。
fn census_counts(entries: &[CensusEntry]) -> serde_json::Value {
    let mut by_class = serde_json::Map::new();
    for class in CensusClass::ALL {
        let of: Vec<&CensusEntry> = entries.iter().filter(|e| e.class == class).collect();
        let mut ops: std::collections::BTreeMap<&str, usize> = Default::default();
        let mut cats: std::collections::BTreeMap<&str, usize> = Default::default();
        for e in &of {
            *ops.entry(e.op.as_str()).or_default() += 1;
            *cats.entry(e.product_category.as_str()).or_default() += 1;
        }
        by_class.insert(
            class.key().to_string(),
            serde_json::json!({
                "count": of.len(),
                "directories": of.iter().filter(|e| e.is_dir).count(),
                "unledgered": of.iter().filter(|e| e.unledgered).count(),
                "phantom_create": of.iter().filter(|e| e.phantom_create).count(),
                "ops": ops,
                "product_category": cats,
            }),
        );
    }
    serde_json::json!({
        "total": entries.len(),
        "by_class": by_class,
        "overlaps": {
            // .git の中の、中身が変わらないコピー（packの時刻更新など）。
            "git_and_byte_identical": entries.iter().filter(|e| e.git_component && e.byte_identical).count(),
            // 差分層にも本物にも実体の無い create（[`CensusEntry::phantom_create`]）。
            "phantom_create": entries.iter().filter(|e| e.phantom_create).count(),
            "ext": entries.iter().filter(|e| e.ext).count(),
        },
    })
}

/// 分類ごとのパス（`.git`は多いので先頭だけ）。
fn census_paths(entries: &[CensusEntry]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for class in CensusClass::ALL {
        let paths: Vec<String> = entries
            .iter()
            .filter(|e| e.class == class)
            .map(|e| {
                let mut s = format!("{} {}", e.op, e.path);
                if e.is_dir {
                    s.push_str(" (dir)");
                }
                if e.git_component && e.byte_identical {
                    s.push_str(" (identical)");
                }
                if e.phantom_create {
                    s.push_str(" (phantom)");
                }
                s
            })
            .collect();
        let shown: Vec<String> = if class == CensusClass::GitComponent {
            paths.into_iter().take(60).collect()
        } else {
            paths
        };
        out.insert(class.key().to_string(), serde_json::json!(shown));
    }
    serde_json::Value::Object(out)
}

/// 段5の腕。
enum CensusArm {
    Mock,
    /// 実プロバイダ（LMStudio）。`e2e-live`でだけ作られる。
    #[cfg_attr(not(feature = "e2e-live"), allow(dead_code))]
    Lmstudio { model: String },
}

impl CensusArm {
    fn key(&self) -> &'static str {
        match self {
            CensusArm::Mock => "mock",
            CensusArm::Lmstudio { .. } => "lmstudio",
        }
    }
}

/// 段5の測定を1本撃つ。結果のJSONを印字し、`C:\harness-e2e\_scratch\cow-census-<腕>.json`へ
/// 書く（**assertより先に書く**——落ちた回・時間切れの回の数字も残す）。
///
/// assertするのは2種類だけ。(1) **計器の検算**——崩れたら数字そのものが無意味になるもの。
/// (2) **手順が踏まれたか**——踏まれていない回の数字は、測りたいものの数字ではない。
/// **分類ごとの件数そのもの（合格基準P1〜P6の判定）はここではassertしない**——段5は現状を測る段で、
/// 判定は段7がこの試験に足す。
fn run_census(ex: &CowExclusive, arm: CensusArm) -> Result<serde_json::Value, String> {
    let case_name = format!("cow-census-{}", arm.key());
    let ws = case_dir(&case_name);
    census_seed_repo(&ws)?;

    let extra: &[&str] = &[
        "--sandbox",
        "tier2a-cow",
        "--max-turns",
        "40",
        "--cognition",
        "off",
    ];
    let mock_turns = census_mock_turns();
    let live_prompt = census_live_prompt();
    let before = ex.list_cow_sessions();
    let started = std::time::Instant::now();
    let driver = match &arm {
        CensusArm::Mock => Driver::Mock(&mock_turns),
        CensusArm::Lmstudio { model } => Driver::Lmstudio {
            base_url: LMSTUDIO_BASE_URL,
            model,
            prompt: &live_prompt,
            deadline: CENSUS_LIVE_DEADLINE,
        },
    };
    let run = run_harness_driven(
        &harness_exe(),
        &ws.to_string_lossy(),
        None,
        driver,
        extra,
        &case_name,
        &[],
    );
    let harness_secs = started.elapsed().as_secs_f64();
    if run.timed_out {
        return Err(format!(
            "判定不能（時間切れ）: harness did not finish within the deadline and was stopped. \
             stdout={} stderr={}",
            run.stdout, run.stderr
        ));
    }
    let outcome = parse_json_stdout(&run)?;
    let session = ex.new_cow_session(&before)?;
    let diff_layer = cow_diff_layer_dir(&session);

    // --- 手順が踏まれたか ---
    let calls = outcome.tool_call_views();
    let strict = matches!(arm, CensusArm::Mock);
    let (assigned, extras) = match_census_steps(&calls, strict);
    let steps_json: Vec<serde_json::Value> = CENSUS_STEPS
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let (tool, expected) = census_step_call(step);
            let call = assigned[i].map(|c| &calls[c]);
            serde_json::json!({
                "step": i + 1,
                "tool": tool,
                "expected_input": expected,
                "matched_call": assigned[i],
                "actual_input": call.map(|c| c.input.clone()),
                "decision": call.map(|c| c.decision.clone()),
                "succeeded": call.is_some_and(|c| c.succeeded()),
            })
        })
        .collect();
    let extras_json: Vec<serde_json::Value> = extras
        .iter()
        .map(|&i| {
            serde_json::json!({
                "call": i,
                "tool": calls[i].name,
                "input": calls[i].input,
                "decision": calls[i].decision,
                "succeeded": calls[i].succeeded(),
            })
        })
        .collect();
    let steps_not_done: Vec<usize> = (0..CENSUS_STEPS.len())
        .filter(|&i| !assigned[i].is_some_and(|c| calls[c].succeeded()))
        .map(|i| i + 1)
        .collect();

    // --- 数える ---
    let t = std::time::Instant::now();
    let changes = list_changes_json(&ws, &session)?;
    let changes_json_ms = t.elapsed().as_millis();
    let t = std::time::Instant::now();
    let text = list_changes_text(&ws, &session)?;
    let changes_text_ms = t.elapsed().as_millis();
    let entries = classify_census(&ws, &diff_layer, &changes)?;
    let shown = parse_changes_text(&text);
    let by_path: std::collections::HashMap<&str, &CensusEntry> =
        entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut visible_by_class = serde_json::Map::new();
    for class in CensusClass::ALL {
        let n = shown
            .visible
            .iter()
            .filter(|(_, p)| by_path.get(p.as_str()).is_some_and(|e| e.class == class))
            .count();
        visible_by_class.insert(class.key().to_string(), n.into());
    }
    let visible_unmatched: Vec<&String> = shown
        .visible
        .iter()
        .map(|(_, p)| p)
        .filter(|p| !by_path.contains_key(p.as_str()))
        .collect();

    // --- 計器の検算 ---
    let ws_str = ws.to_string_lossy().to_string();
    let denied = harness_change_ledger::store::read_denied_log(&diff_layer);
    let denied_inside: Vec<&str> = denied
        .iter()
        .filter(|e| {
            harness_change_ledger::path_rules::relative_under_root(&e.path, &ws_str).is_some()
        })
        .map(|e| e.path.as_str())
        .collect();
    let rejected: Vec<&str> = entries
        .iter()
        .filter(|e| e.rejected)
        .map(|e| e.path.as_str())
        .collect();
    let lost: Vec<&str> = entries
        .iter()
        .filter(|e| e.lost_in_diff_layer)
        .map(|e| e.path.as_str())
        .collect();
    let disagreements: Vec<&str> = entries
        .iter()
        .filter(|e| e.baseline_agrees == Some(false))
        .map(|e| e.path.as_str())
        .collect();
    let visible_plus_folded = shown.visible.len() + shown.folded_git;
    let class_of = |p: &str| by_path.get(p).map(|e| e.class);
    // 陽性対照「同じ中身で書き直したものは同一コピーに入る」が使えるのは、段9で実際に同じ中身を
    // 書いたときだけ（実モデルが1文字でも変えたら、その回ではこの対照は適用できない）。
    let guide_step = CENSUS_STEPS
        .iter()
        .position(|s| matches!(s, CensusStep::Write { path, .. } if *path == "docs/guide.txt"))
        .expect("the procedure rewrites docs/guide.txt");
    let guide_written_identically = assigned[guide_step]
        .is_some_and(|c| calls[c].input["content"].as_str() == Some(CENSUS_GUIDE_TXT));

    let evidence = serde_json::json!({
        "arm": arm.key(),
        "model": match &arm { CensusArm::Mock => None, CensusArm::Lmstudio { model } => Some(model.clone()) },
        "session": session,
        "harness": {
            "exit_code": run.status.code(),
            "seconds": harness_secs,
            "discarded_turns": outcome.discarded_turns(),
            "answer": outcome.answer(),
        },
        "steps": steps_json,
        "steps_not_done": steps_not_done,
        "extra_calls": extras_json,
        "counts": census_counts(&entries),
        "visible_list": {
            "lines": shown.visible.len(),
            "by_class": visible_by_class,
            "folded_git": shown.folded_git,
            "unmatched_paths": visible_unmatched,
        },
        "paths": census_paths(&entries),
        "git": {
            "diff_layer_loose_objects": count_loose_git_objects(&diff_layer),
            "feature_ref": std::fs::read_to_string(diff_layer.join(r".git\refs\heads\feature")).ok().map(|s| s.trim().to_string()),
        },
        "p7": {
            "changes_json_ms": changes_json_ms,
            "changes_text_ms": changes_text_ms,
            "diff_layer": diff_layer_inventory(&diff_layer),
        },
        "instrument_checks": {
            "rejected_entries": rejected,
            "visible_plus_folded": visible_plus_folded,
            "json_total": entries.len(),
            "baseline_hash_disagreements": disagreements,
            "lost_in_diff_layer": lost,
            "denied_inside_workspace": denied_inside,
            "denied_outside_workspace": denied.len() - denied_inside.len(),
            "control_guide_is_byte_identical": class_of("docs/guide.txt").map(|c| c.key()),
            "control_guide_applicable": guide_written_identically,
            "control_build_log_is_ignored": class_of("target/debug/build.log").map(|c| c.key()),
            "control_lib_is_other": class_of("src/lib.txt").map(|c| c.key()),
        },
    });
    let rendered = serde_json::to_string_pretty(&evidence).unwrap_or_default();
    println!("[cow-census] {rendered}");
    let record = scratch_dir().join(format!("{case_name}.json"));
    std::fs::write(&record, &rendered)
        .map_err(|e| format!("failed to write {}: {e}", record.display()))?;

    // --- (2) 手順が踏まれたか。踏まれていない回の数字は使えない ---
    if !steps_not_done.is_empty() {
        let per_step: Vec<String> = calls
            .iter()
            .enumerate()
            .map(|(i, c)| format!("  call {i}: {} {} -> {} / {}", c.name, c.input, c.decision, c.result))
            .collect();
        return Err(format!(
            "判定不能: 手順の段 {steps_not_done:?} が踏まれなかった（または失敗した）ので、この回の数字は \
             測りたいもの（手順どおりのセッションの一覧）の数字ではない。record={}\n{}",
            record.display(),
            per_step.join("\n")
        ));
    }
    if strict && !extras.is_empty() {
        return Err(format!(
            "mock が台本に無い呼び出しをした（{extras:?}）——台本と照合器の食い違い。record={}",
            record.display()
        ));
    }

    // --- (1) 計器の検算 ---
    let mut broken = Vec::new();
    if !rejected.is_empty() {
        broken.push(format!("形の崩れたパスが一覧にある（.git 側へ数えられ得る）: {rejected:?}"));
    }
    if visible_plus_folded != entries.len() {
        broken.push(format!(
            "テキストの見える行 {} + 畳み込み {} ≠ JSON の {} 件（どちらかの読み方が壊れている）",
            shown.visible.len(),
            shown.folded_git,
            entries.len()
        ));
    }
    if !visible_unmatched.is_empty() {
        broken.push(format!("テキストの行が JSON のどのパスとも一致しない: {visible_unmatched:?}"));
    }
    if !disagreements.is_empty() {
        broken.push(format!(
            "バイト比較と baseline_hash が逆の答えを出した（計器のどちらかが壊れている）: {disagreements:?}"
        ));
    }
    if !lost.is_empty() {
        broken.push(format!(
            "modify なのに差分層に実体が無い（copy-up の失敗＝その書込は失われている）: {lost:?}"
        ));
    }
    if !denied_inside.is_empty() {
        broken.push(format!(
            "ワークスペース内への書込が ACL に拒否された＝その書込は一覧から漏れている: {denied_inside:?}"
        ));
    }
    if guide_written_identically && class_of("docs/guide.txt") != Some(CensusClass::ByteIdentical) {
        broken.push(format!(
            "陽性対照: 同じ中身で書き直した docs/guide.txt が「中身の変わらないコピー」に入らない（{:?}）",
            class_of("docs/guide.txt")
        ));
    }
    if class_of("target/debug/build.log") != Some(CensusClass::Ignored) {
        broken.push(format!(
            "陽性対照: target/debug/build.log が ignore に入らない（{:?}）",
            class_of("target/debug/build.log")
        ));
    }
    if class_of("src/lib.txt") != Some(CensusClass::Other) {
        broken.push(format!(
            "陰性対照: 中身を変えた追跡ファイル src/lib.txt が「それ以外」に入らない（{:?}）",
            class_of("src/lib.txt")
        ));
    }
    // mock は手順が決まっているので、「それ以外」と「.git 以外の同一コピー」は集合ごと一致するはず。
    if strict {
        let other: std::collections::BTreeSet<(String, String)> = entries
            .iter()
            .filter(|e| e.class == CensusClass::Other)
            .map(|e| (e.op.clone(), e.path.clone()))
            .collect();
        let expected_other: std::collections::BTreeSet<(String, String)> = [
            ("modify", "src/lib.txt"),
            ("create", "src/new.txt"),
            ("modify", "README.md"),
            ("create", "scratch.txt"),
            ("delete", "notes.txt"),
        ]
        .iter()
        .map(|(o, p)| (o.to_string(), p.to_string()))
        .collect();
        if other != expected_other {
            broken.push(format!(
                "「それ以外」が手順で作った変更（段2・3・6・7・8）と一致しない: got={other:?} expected={expected_other:?}"
            ));
        }
        let identical: Vec<&str> = entries
            .iter()
            .filter(|e| e.class == CensusClass::ByteIdentical)
            .map(|e| e.path.as_str())
            .collect();
        if identical != ["docs/guide.txt"] {
            broken.push(format!(
                "「.git 以外の中身の変わらないコピー」が段9の docs/guide.txt だけでない: {identical:?}"
            ));
        }
        let ignored: HashSet<&str> = entries
            .iter()
            .filter(|e| e.class == CensusClass::Ignored)
            .map(|e| e.path.as_str())
            .collect();
        for p in ["target/debug/build.log", "target/debug/app.tar"] {
            if !ignored.contains(p) {
                broken.push(format!("段10・11の生成物 {p} が ignore に入らない"));
            }
        }
        if !entries.iter().any(|e| e.class == CensusClass::GitComponent) {
            broken.push("段1・4・5の git 操作が .git 成分のエントリを1件も作らなかった".to_string());
        }
    }
    if !broken.is_empty() {
        return Err(format!(
            "計器の検算が崩れた（この回の数字は読めない）。record={}\n- {}",
            record.display(),
            broken.join("\n- ")
        ));
    }

    // 成功した回だけ後始末する。**消えたことを読み返す**——`cleanup_on_success`は削除の失敗を
    // 捨てるので、残ったまま次の回の前後差へ混ざることがある（B-10）。
    cleanup_on_success(&ws, &[&session], &case_name);
    let _ = std::fs::remove_file(scratch_dir().join(format!("{case_name}-turns.json")));
    let leftovers: Vec<String> = [&ws, &diff_layer]
        .iter()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !leftovers.is_empty() {
        return Err(format!(
            "測定は通ったが後始末が残った（次の回の交絡になる）: {leftovers:?}。record={}",
            record.display()
        ));
    }
    Ok(evidence)
}

/// **段5の固定の試験（mock の腕）**。`dev-elevated-run e2e-cow-change-census`。
#[test]
#[ignore]
fn tier2a_cow_change_census_mock() {
    let ex = cow_exclusive();
    if let Err(e) = run_census(&ex, CensusArm::Mock) {
        panic!("{e}");
    }
}

/// LMStudioが答えるモデルの一覧（`id`と`state`）。`curl.exe`を使う（Windows標準）。
#[cfg(feature = "e2e-live")]
fn lmstudio_models() -> Result<Vec<(String, String)>, String> {
    let url = format!("{LMSTUDIO_ORIGIN}/api/v0/models");
    let output = Command::new("curl.exe")
        .args(["-s", "-m", "10", &url])
        .output()
        .map_err(|e| format!("failed to run curl.exe: {e}"))?;
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "判定不能: LMStudio が {url} で答えない（起動していない？）: {e} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok(parsed["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|m| {
                    (
                        m["id"].as_str().unwrap_or_default().to_string(),
                        m["state"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default())
}

/// **段5の固定の試験（実プロバイダの腕）**。`dev-elevated-run e2e-cow-change-census-live`。
///
/// LMStudio が起動していることが前提。**居なければ赤にする**（飛ばして緑にすると、
/// 走っていないことが見えなくなる）。モデルは[`CENSUS_LIVE_DEFAULT_MODEL`]、
/// [`CENSUS_LIVE_MODEL_FILE`]があればその1行。読み込まれていなければ LMStudio が読み込む
/// （その時間も期限に含まれる）。
#[cfg(feature = "e2e-live")]
#[test]
#[ignore]
fn tier2a_cow_change_census_lmstudio() {
    let model = std::fs::read_to_string(CENSUS_LIVE_MODEL_FILE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| CENSUS_LIVE_DEFAULT_MODEL.to_string());
    let models = lmstudio_models().unwrap_or_else(|e| panic!("{e}"));
    if !models.iter().any(|(id, _)| *id == model) {
        panic!(
            "判定不能: モデル {model:?} が LMStudio に無い。{CENSUS_LIVE_MODEL_FILE} に id を1行書いて \
             差し替えられる。LMStudio が答えたモデル: {models:?}"
        );
    }
    let ex = cow_exclusive();
    if let Err(e) = run_census(&ex, CensusArm::Lmstudio { model }) {
        panic!("{e}");
    }
}

// --- 段5の計器の単体テスト（管理者権限・実機・LMStudioのどれも要らない） ---------------
//
// `cargo test -p harness-cli --features e2e-mock` で走る。計器（分類器・ignore判定・テキスト解析）が
// **正しいものを正しく分け、分けてはいけないものを分けない**ことを、実機で撃つ前に固定する。

/// 一時フォルダに、種付けと同じ形のリポジトリ（`.gitignore`は`target/`）と、差分層に見立てた
/// フォルダを作る。
fn census_unit_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let ws = root.path().join("ws");
    let diff = root.path().join("diff");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(&diff).unwrap();
    for (rel, content) in CENSUS_SEED {
        let p = ws.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
    }
    plain_git(&ws, &["init", "-q", "-b", "main"]).unwrap();
    plain_git(&ws, &["-c", "core.autocrlf=false", "add", "-A"]).unwrap();
    plain_git(&ws, &["-c", "core.autocrlf=false", "commit", "-q", "-m", "seed"]).unwrap();
    (root, ws, diff)
}

fn put(dir: &Path, rel: &str, content: &[u8]) {
    let p = dir.join(rel.replace('/', "\\"));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn entry(op: &str, path: &str, baseline: Option<&[u8]>, category: &str) -> serde_json::Value {
    serde_json::json!({
        "op": op,
        "path": path,
        "baseline_hash": baseline.map(harness_change_ledger::hash_bytes),
        "unledgered": false,
        "category": category,
    })
}

/// 分類器の両側。**分けるべきものを分け、分けてはいけないものを分けない**（test-logic-rules 問4）。
#[test]
fn census_classifier_separates_each_axis_and_leaves_lookalikes_alone() {
    let (_root, ws, diff) = census_unit_fixture();
    let guide = CENSUS_GUIDE_TXT.as_bytes();
    let lib = b"fn original() {}\n";
    // 差分層に見立てたフォルダへ、各分類の代表を置く。
    put(&diff, "docs/guide.txt", guide); // 同じ中身の書き直し
    put(&diff, "src/lib.txt", b"changed\n"); // 中身を変えた追跡ファイル
    put(&diff, ".git/objects/pack/p.pack", b"pack"); // .git（中身は本物側に無い）
    put(&diff, ".git/HEAD", b"ref: refs/heads/feature\n");
    put(&diff, "sub/.git/HEAD", b"x"); // 入れ子の .git も成分で当たる
    put(&diff, ".gitignore", b"target/\nextra/\n"); // .git に見えて違う
    put(&diff, ".github/workflows/x.yml", b"on: push\n"); // .git に見えて違う
    put(&diff, "target/debug/build.log", b"out"); // ignore
    std::fs::create_dir_all(diff.join(r"target\debug")).unwrap();
    put(&diff, "targets.txt", b"not ignored"); // 名前が似ているだけ
    put(&diff, "scratch.txt", b"new"); // 新規（同一にならない）
    let changes = serde_json::json!([
        entry("modify", "docs/guide.txt", Some(guide), "side_effect"),
        entry("modify", "src/lib.txt", Some(lib), "side_effect"),
        entry("create", ".git/objects/pack/p.pack", None, "git_internal"),
        entry("modify", ".git/HEAD", Some(b"ref: refs/heads/main\n"), "git_internal"),
        entry("create", "sub/.git/HEAD", None, "git_internal"),
        entry("modify", ".gitignore", Some(b"target/\n"), "config_injection"),
        entry("create", ".github/workflows/x.yml", None, "config_injection"),
        entry("create", "target/debug/build.log", None, "side_effect"),
        entry("create", "target/debug", None, "side_effect"),
        entry("create", "target", None, "side_effect"),
        entry("create", "targets.txt", None, "side_effect"),
        entry("create", "scratch.txt", None, "side_effect"),
        entry("delete", "notes.txt", Some(b"this file is deleted by the agent\n"), "side_effect"),
    ]);

    let entries = classify_census(&ws, &diff, &changes).expect("classify");
    let class = |p: &str| entries.iter().find(|e| e.path == p).map(|e| e.class);

    assert_eq!(class("docs/guide.txt"), Some(CensusClass::ByteIdentical));
    assert_eq!(class("src/lib.txt"), Some(CensusClass::Other));
    assert_eq!(class(".git/objects/pack/p.pack"), Some(CensusClass::GitComponent));
    assert_eq!(class(".git/HEAD"), Some(CensusClass::GitComponent));
    assert_eq!(class("sub/.git/HEAD"), Some(CensusClass::GitComponent));
    assert_eq!(class(".gitignore"), Some(CensusClass::Other), ".gitignore is not a .git component");
    assert_eq!(class(".github/workflows/x.yml"), Some(CensusClass::Other));
    assert_eq!(class("target/debug/build.log"), Some(CensusClass::Ignored));
    assert_eq!(class("target/debug"), Some(CensusClass::Ignored));
    // **末尾`/`が効くのはここだけ**——`target/debug`は親の`target`がディレクトリとして読まれるので
    // 末尾`/`が無くても一致するが、`target`そのものは本物のワークスペースに無いので、
    // ディレクトリだと教えないと規則`target/`（ディレクトリだけ）に一致しない（2026-09-27 実測）。
    assert_eq!(
        class("target"),
        Some(CensusClass::Ignored),
        "a directory entry that exists only in the diff layer must be asked with a trailing /"
    );
    assert_eq!(class("targets.txt"), Some(CensusClass::Other));
    assert_eq!(class("scratch.txt"), Some(CensusClass::Other), "create is never byte-identical");
    assert_eq!(class("notes.txt"), Some(CensusClass::Other), "delete is never byte-identical");

    // 2つの計器（バイト比較と baseline_hash）が、modify の全件で同じ答えを出している。
    for e in entries.iter().filter(|e| e.op == "modify") {
        assert_eq!(e.baseline_agrees, Some(true), "{}", e.path);
    }
    // 追跡されている src/lib.txt は ignore に入らない（check-ignore の既定）。
    assert!(!entries.iter().find(|e| e.path == "src/lib.txt").unwrap().ignored);
    // 差分層にも本物にも実体の無い create と、差分層に実体の無い modify（失われた書込）を
    // **取り違えない**（前者は一覧の性質として数え、後者は計器の検算に使う）。
    let without_entity = serde_json::json!([
        entry("create", "ghost.txt", None, "side_effect"),
        entry("modify", "README.md", Some(b"census seed\n"), "side_effect"),
    ]);
    let ghosts = classify_census(&ws, &diff, &without_entity).expect("classify");
    assert!(ghosts[0].phantom_create && !ghosts[0].lost_in_diff_layer);
    assert!(ghosts[1].lost_in_diff_layer && !ghosts[1].phantom_create);
    // 実体のある create は実体の無い `create` ではない。
    assert!(!entries.iter().find(|e| e.path == "scratch.txt").unwrap().phantom_create);
}

/// `.git`の中でも、中身の変わらないコピーは「重なり」として数えられ、分類は`.git`が勝つ。
#[test]
fn census_git_component_wins_over_byte_identical_and_the_overlap_is_counted() {
    let (_root, ws, diff) = census_unit_fixture();
    let real_pack_dir = ws.join(r".git\objects\pack");
    std::fs::create_dir_all(&real_pack_dir).unwrap();
    std::fs::write(real_pack_dir.join("same.pack"), b"PACKDATA").unwrap();
    put(&diff, ".git/objects/pack/same.pack", b"PACKDATA");
    let changes = serde_json::json!([entry(
        "modify",
        ".git/objects/pack/same.pack",
        Some(b"PACKDATA"),
        "git_internal"
    )]);
    let entries = classify_census(&ws, &diff, &changes).expect("classify");
    assert_eq!(entries[0].class, CensusClass::GitComponent);
    assert!(entries[0].byte_identical);
    assert_eq!(census_counts(&entries)["overlaps"]["git_and_byte_identical"], 1);
}

/// 利用者全体の ignore（`core.excludesFile`）は判定に混ざらない。混ざると「リポジトリの
/// `.gitignore`が何を捨てるか」を数えたことにならない。
#[test]
fn census_ignore_check_does_not_use_the_global_excludes_file() {
    let (_root, ws, _diff) = census_unit_fixture();
    // ワークスペース内の設定で excludesFile を立てても、判定側の `-c` が上書きする。
    let global = ws.join("global-excludes");
    std::fs::write(&global, "*.log\n").unwrap();
    plain_git(&ws, &["config", "core.excludesFile", &global.to_string_lossy().replace('\\', "/")])
        .unwrap();
    let ignored =
        git_check_ignore(&ws, &["x.log".to_string(), "target/y.o".to_string()]).expect("check");
    assert!(!ignored.contains("x.log"), "the excludes file leaked into the census");
    assert!(ignored.contains("target/y.o"));
}

/// テキストの読み方。変更の行だけを数え、畳み込み行の件数を拾い、要約の行を数えない。
#[test]
fn census_text_parser_counts_only_change_lines_and_reads_the_fold_count() {
    let text = "create  src/new.txt\n\
                modify  README.md [unledgered: present in the overlay but not recorded]\n\
                delete  notes.txt [rejected: bad]\n\
                (12 file(s) under `.git` are git internals -- they are reviewed through git, not applied as files. Use `--output-format json` to list them.)\n\
                (3 workspace-external write attempt(s) were denied by ACL; see `harness cow audit`)\n\
                WARNING: 1 write attempt(s) INSIDE the workspace were denied by ACL.\n";
    let parsed = parse_changes_text(text);
    assert_eq!(
        parsed.visible,
        vec![
            ("create".to_string(), "src/new.txt".to_string()),
            ("modify".to_string(), "README.md".to_string()),
            ("delete".to_string(), "notes.txt".to_string()),
        ]
    );
    assert_eq!(parsed.folded_git, 12);
    assert_eq!(
        parse_changes_text("(no changes)\n"),
        ChangesText {
            visible: vec![],
            folded_git: 0
        }
    );
}

/// **2本の腕が同じ手順であること**を作りで固定する。mock の台本の各段と、実モデルへの指示文の
/// 各段が、同じ表（[`CENSUS_STEPS`]）の同じ道具・同じ入力を指している。
#[test]
fn census_mock_script_and_live_prompt_describe_the_same_steps() {
    let turns = census_mock_turns();
    assert_eq!(turns.len(), CENSUS_STEPS.len() + 1, "one turn per step, then end_turn");
    let prompt = census_live_prompt();
    for (i, step) in CENSUS_STEPS.iter().enumerate() {
        let (tool, input) = census_step_call(step);
        let line = format!("Step {}: call `{tool}` with {input}", i + 1);
        assert!(prompt.contains(&line), "prompt is missing {line:?}");
    }
    // 台本の呼び出しを照合器へ通すと、全段が厳密一致で踏まれ、余りが出ない。
    let calls: Vec<ToolCallView> = CENSUS_STEPS
        .iter()
        .map(|s| {
            let (tool, input) = census_step_call(s);
            let result = if tool == "run_program" {
                "ok\n[exit code: 0]\n[program: git]".to_string()
            } else {
                "wrote 1 bytes to x".to_string()
            };
            ToolCallView {
                name: tool.to_string(),
                input,
                decision: "allowed".to_string(),
                result,
            }
        })
        .collect();
    let (assigned, extras) = match_census_steps(&calls, true);
    assert!(assigned.iter().all(Option::is_some) && extras.is_empty());
    assert!(calls.iter().all(ToolCallView::succeeded));
}

/// 段の照合の両側: 緩い照合は副コマンドとパスで当て、失敗した段・拒否された段は「踏んだ」に
/// 数えない（test-logic-rules 問2: 許可側と対にする）。
#[test]
fn census_step_matching_accepts_loose_variants_and_rejects_failures() {
    let view = |name: &str, input: serde_json::Value, decision: &str, result: &str| ToolCallView {
        name: name.to_string(),
        input,
        decision: decision.to_string(),
        result: result.to_string(),
    };
    // 実モデルが git を絶対パスで呼び、引数の並びを変えても、副コマンドが同じなら段1に当たる。
    let loose = view(
        "run_program",
        serde_json::json!({"program": r"C:\Program Files\Git\cmd\git.exe", "args": ["-c", "safe.directory=*", "switch", "-c", "feature"]}),
        "allowed",
        "Switched\n[exit code: 0]",
    );
    assert!(census_call_matches(&CENSUS_STEPS[0], &loose, false));
    assert!(!census_call_matches(&CENSUS_STEPS[0], &loose, true), "strict needs the exact input");
    // 副コマンドが違えば当たらない。
    let other = view(
        "run_program",
        serde_json::json!({"program": "git", "args": ["status"]}),
        "allowed",
        "[exit code: 0]",
    );
    assert!(!census_call_matches(&CENSUS_STEPS[0], &other, false));
    // 失敗・拒否は成功ではない。子が同じ綴りを印字しても、最後のフッタで判定する。
    assert!(!view("run_program", serde_json::json!({}), "allowed", "[exit code: 1]").succeeded());
    assert!(!view(
        "run_program",
        serde_json::json!({}),
        "allowed",
        "[exit code: 0] printed by child\n[exit code: 128]"
    )
    .succeeded());
    assert!(!view("write_file", serde_json::json!({}), "denied", "wrote 1 bytes").succeeded());
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
/// `allowed:false`エントリがあることを二重証拠として要求する(Q4)。監査ログの置き場は
/// 書込の捕まえ方に関係なく全セッションで作られる（`.harness/sandbox/audit-<id>/`、D-90 反転の
/// 前提(3)）ので、**`--staged`を付けない既定のモードで**測る。かつては`--staged`でしか
/// `net-audit.jsonl`が書かれず、ここでも`--staged`を付けていた。
/// `expect_proxy_denials`は「層1（プロキシ）が、この理由でこの件数だけ断つこと」
/// （[`assert_proxy_denials`]）。**WFPの拒否0件を「正しい0」と読むケースはここを埋める**
/// ——そうしないと、層1が断たなくなった日に0が取りこぼしと見分けられなくなる（[BUG-094]）。
fn run_net_case(
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
    expect_proxy_denials: &[(&str, usize)],
) -> Result<(), String> {
    run_net_case_with_exe(
        &harness_exe(),
        name,
        allow_domains,
        case_matrix_case,
        deny_hosts_expected,
        expect_proxy_denials,
    )
}

/// `run_net_case`の`harness.exe`パスを差し替え可能な版（WFP fail-closedケース専用）。
fn run_net_case_with_exe(
    exe: &Path,
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
    expect_proxy_denials: &[(&str, usize)],
) -> Result<(), String> {
    run_net_case_with_exe_and_stderr_check(
        exe,
        name,
        allow_domains,
        case_matrix_case,
        deny_hosts_expected,
        None,
        expect_proxy_denials,
    )
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
    expect_proxy_denials: &[(&str, usize)],
) -> Result<(), String> {
    let ws = net_case_ws(name);
    let mut extra_args: Vec<&str> = Vec::new();
    for d in allow_domains {
        extra_args.push("--net-allow-domain");
        extra_args.push(d);
    }
    let script = format!(".\\tier2a-net-e2e.exe case-matrix --case {case_matrix_case}");
    let run = run_harness_with_exe(
        exe,
        &ws,
        &run_shell_script_turns(&script),
        &extra_args,
        name,
    );
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
    let result_text = outcome.first_tool_result()?;

    // case-matrixバイナリ自身が最終行で{"passed":true/false,...}を出す(expect_ok一致判定)。
    let case_matrix_passed = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("passed").is_some())
        .and_then(|v| v["passed"].as_bool())
        .ok_or_else(|| {
            format!("could not find case-matrix summary line in output: {result_text}")
        })?;
    if !case_matrix_passed {
        return Err(format!(
            "case-matrix reported a mismatch (allow/deny did not match expectation): {result_text}"
        ));
    }

    // 二重証拠: 監査ログにも対象ホストのallowed:falseが実際に記録されていること。
    let audit_path = ws.join(".harness").join("sandbox");
    let audit_entries = collect_audit_entries(&audit_path)?;
    for host in deny_hosts_expected {
        let found = audit_entries.iter().any(|e| {
            e.get("allowed") == Some(&serde_json::Value::Bool(false))
                && e.get("host")
                    .and_then(|h| h.as_str())
                    .map(|h| h.contains(host))
                    .unwrap_or(false)
        });
        if !found {
            return Err(format!(
                "no audit log entry recorded a deny for host containing {host:?} (audit entries: {audit_entries:?})"
            ));
        }
    }

    report_net_event_audit(name, &audit_entries);
    assert_filter_attribution_is_wired(name, &audit_entries)?;
    assert_proxy_denials(name, &audit_entries, expect_proxy_denials)?;

    cleanup_on_success(&ws, &[], name);
    Ok(())
}

/// [BUG-094] **拒否の出所を注記する配線が生きていることを、競争に依存せず固定する。**
///
/// # なぜ「`net-05`に`harness`が1件」を`assert`しないのか
///
/// **それは取れない回がある**（実測でも、待たずに畳めば0件になる回がある）。
/// 配送が間に合うかは競争の結果なので、件数を`assert`すると**壊れていなくても赤くなる**。
///
/// # 代わりに何を固定するか——**壊れたときだけ必ず出る2つ**
///
/// | 固定する事実 | これが破れたら何が起きているか |
/// |---|---|
/// | 要約の`owned_filter_ids`が0でない | フィルタIDを監査シンクへ渡す配線が落ちた。**全部の拒否が無言で`other`に化ける** |
/// | 記録された`classify_drop`に必ず`filter_owner`が載る | 注記を書かない経路が生まれた（古い`netfilterd`が動いている等） |
///
/// どちらも**拒否が1件も取れなかった回でも判定できる**（前者は要約だけで足り、
/// 後者は0件なら空虚に真）。**WFPを張らない経路（fail-closed系）では要約が無い**ので、
/// そこは対象外にする——無いことを失敗にすると、別の機構の正常動作でこのテストが落ちる。
fn assert_filter_attribution_is_wired(
    name: &str,
    audit_entries: &[serde_json::Value],
) -> Result<(), String> {
    let summary = audit_entries.iter().find_map(|e| {
        e.get("reason")
            .and_then(|r| r.as_str())
            .filter(|r| r.starts_with("net_event_summary"))
    });
    let Some(summary) = summary else {
        // WFPを張らない経路。ここで失敗させない理由は本関数のdoc参照。
        return Ok(());
    };
    let owned: u64 = summary
        .split("owned_filter_ids=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| {
            format!("[{name}] 要約に`owned_filter_ids=`が無い（注記の配線より前のnetfilterdが動いている）: {summary}")
        })?;
    if owned == 0 {
        return Err(format!(
            "[{name}] 控えたフィルタIDが0件。フィルタは張られているのにIDが監査シンクへ渡っていない\
             ——この状態では全ての拒否が無言で`filter_owner=other`になる: {summary}"
        ));
    }

    for e in audit_entries
        .iter()
        .filter(|e| e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop"))
    {
        if e.get("filter_owner").and_then(|o| o.as_str()).is_none() {
            return Err(format!(
                "[{name}] `classify_drop`に`filter_owner`が載っていない行がある（注記を書かない経路が在る）: {e}"
            ));
        }
    }
    Ok(())
}

/// [BUG-094] **層1（プロキシ）が、期待した理由で、期待した件数だけ断ったこと。**
///
/// # なぜこれを固定するのか
///
/// `net-06-numeric`のWFP拒否が0件なのは**正しい**——層1で断たれるので外向きのソケットが
/// 一度も開かれず、WFPに落とすものが無い。**だが「0件が正しい」の根拠は層1の側にある**ので、
/// 層1が断たなくなった日に、この0は**取りこぼしと見分けが付かなくなる**。
/// ここを固定しておけば、根拠が消えた瞬間にそちらが赤くなる。
///
/// # 理由コードまで見る
///
/// このケースが出すのは`ip_literal_denied`（IPリテラル判定が名前照合より**前**にある）。
/// **件数だけを見ると、別の理由で断られていても通る**——たとえば名前照合の側で
/// 断られるようになったら、それは層1の意味が変わったということで、気付く必要がある。
fn assert_proxy_denials(
    name: &str,
    audit_entries: &[serde_json::Value],
    expected: &[(&str, usize)],
) -> Result<(), String> {
    for (reason, count) in expected {
        let actual = audit_entries
            .iter()
            .filter(|e| e.get("protocol").and_then(|p| p.as_str()) != Some("control"))
            .filter(|e| e.get("kind").and_then(|k| k.as_str()) != Some("wfp"))
            .filter(|e| e.get("allowed").and_then(|a| a.as_bool()) == Some(false))
            .filter(|e| e.get("reason").and_then(|r| r.as_str()) == Some(reason))
            .count();
        if actual != *count {
            return Err(format!(
                "[{name}] 層1の拒否が期待と違う: {reason} を{count}件期待したが{actual}件。\
                 WFPの拒否0件を「層1で断たれたから正しい」と読む根拠がこれである"
            ));
        }
    }
    Ok(())
}

/// [BUG-094] **この機械の監査ポリシーを読んで残す。1ビットも変えない。**
///
/// # なぜ読むのか
///
/// 2026-09-20の対照で、**公開アドレスへのclassify drop（`net-05-rawtcp`）でも
/// コールバックが1度も呼ばれない**ことが分かった。購読は成功し、エンジン全体の収集も
/// 有効（`collect=0x1`）で、購読テンプレートは`default()`＝全イベントである。
/// **配送を止めているものが他にある。**
///
/// WFPのnet eventは、Windowsの詳細監査ポリシーの2つのサブカテゴリ
/// （`Filtering Platform Packet Drop`・`Filtering Platform Connection`）と同じ事象を指す。
/// **そちらが無効なら、そもそも事象が生成されない**というのが次の候補である。
/// この候補はこの記録で一度も検討されていない。
///
/// # 読むだけにする理由
///
/// 監査ポリシーは**マシン全体の設定**である。立てれば残り、倒す責任者を決める必要がある
/// （案Aが同じ壁で消えたのと同じ構図）。**まず現在値を知る**のが先で、
/// 変えるかどうかはその後の決定である。`plans/etw-spike/RESULTS.md`も
/// 「`auditpol /get`の読み取りのみ」という同じ線を引いている。
///
/// # このテストの中で撃つ理由
///
/// `auditpol`は管理者でないと読めない。**このテストは既に昇格して走っている**ので、
/// 新しい`KNOWN_TARGETS`を足さずに済む（足すとデーモンの停止が要り、
/// それは`dev-elevated-runner`を通らない昇格になる）。
fn report_wfp_audit_policy() {
    // **名前ではなくGUIDで引く。** サブカテゴリ名はOSの表示言語で翻訳されるので、
    // 英語名を渡すとこの開発機（日本語版）では`0x57`（パラメーターが間違っています）で落ちる
    // ——**「無効」と「名前が解決できなかった」が同じ見た目になる**ので、名前では引かない。
    for (guid, what) in [
        (
            "{0CCE9225-69AE-11D9-BED3-505054503030}",
            "Filtering Platform Packet Drop",
        ),
        (
            "{0CCE9226-69AE-11D9-BED3-505054503030}",
            "Filtering Platform Connection",
        ),
    ] {
        let out = Command::new("auditpol")
            .args(["/get", &format!("/subcategory:{guid}")])
            .output();
        match out {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                eprintln!("[BUG-094][audit-policy] {what} exit={:?}", o.status.code());
                // **バイト列も出す。** `auditpol`の出力はこの機械のANSIコードページ（日本語）で、
                // UTF-8として読むと化ける。**化けた表示から設定値を推測して記録へ書かない**ため、
                // 16進も並べて後から確実に復号できるようにする。
                for line in text.lines().chain(err.lines()) {
                    if !line.trim().is_empty() {
                        eprintln!("[BUG-094][audit-policy] {what}: {}", line.trim_end());
                    }
                }
                let hex: String = o
                    .stdout
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                eprintln!("[BUG-094][audit-policy] {what} stdout-hex: {hex}");
            }
            Err(e) => eprintln!("[BUG-094][audit-policy] auditpol を起動できなかった: {e}"),
        }
    }
}

/// [BUG-094] **WFPのnet-event購読が何を受け取ったかを、caseごとに1回だけ残す。**
///
/// # なぜ全caseで出すのか
///
/// 分かっていないのは「購読は成立しているのにコールバックが1度も呼ばれない」理由である。
/// 2026-09-20の測定は`net-11-smb445`（宛先は`100.64.0.0/10`）1件だけで取ったので、
/// **「購読が何も受け取らない」のか「その拒否が配送対象でない」のか**が分かれていない。
///
/// **`net-05-rawtcp`がその対照になる。** 宛先は公開アドレス（`172.66.147.243`）なので
/// Tier2aが積む`internetClient`の射程内であり、**capability dropではなく
/// harness自身のBLOCKフィルタによるclassify drop**である。ここで呼び出し回数が0より大きければ
/// 「購読は受け取っている」が言え、0なら「購読そのものが何も受け取らない」が言える。
///
/// # 判定しない
///
/// **ここでは`assert`しない。** いま閾値を書くと、**測る前に答えを書く**ことになる。
/// 数えた値を残すところまでが本関数の仕事で、結論が出たらその時点で対の`assert`を置く。
/// 成功した回はワークスペースごと片付くので、**ログに残すのがこの事実を残す唯一の口**である。
fn report_net_event_audit(name: &str, audit_entries: &[serde_json::Value]) {
    // [BUG-094] **WFPの話をする前に、層1（プロキシ）の拒否を出す。**
    // 早期returnより前に置くのは、WFPの制御レコードが1件も無いケースでも
    // 層1の結果だけは残す必要があるためである。
    report_proxy_denials(name, audit_entries);
    let controls: Vec<&str> = audit_entries
        .iter()
        .filter(|e| e.get("protocol").and_then(|p| p.as_str()) == Some("control"))
        .filter_map(|e| e.get("reason").and_then(|r| r.as_str()))
        .collect();
    let net_event_controls: Vec<&&str> = controls
        .iter()
        .filter(|r| r.starts_with("net_event_"))
        .collect();
    let classify_drops = audit_entries
        .iter()
        .filter(|e| e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop"))
        .count();
    if net_event_controls.is_empty() {
        eprintln!(
            "[BUG-094][{name}] net-eventの制御レコードが1件も無い（WFPを張らない経路か、\
             監査シンクが作られていない）。classify_drop={classify_drops}"
        );
        return;
    }
    for r in &net_event_controls {
        eprintln!("[BUG-094][{name}] control: {r}");
    }
    eprintln!("[BUG-094][{name}] classify_drop記録={classify_drops}");
    report_delivery_lag(name, audit_entries, &net_event_controls);
}

/// [BUG-094] **層1（プロキシ）が断った件数を、理由ごとにcaseへ1行ずつ残す。**
///
/// # 何を分けたいのか
///
/// `classify_drop`が0件のとき、次の2つが区別できない（`B-10`）。
///
/// | 実際 | 意味 |
/// |---|---|
/// | 層1で断たれた | **外向きのソケットが一度も開かれない**ので、WFPに落とすものが無い。0は正しい |
/// | 層1を通った | WFPまで届いたはずなのに記録が無い＝**取りこぼしている** |
///
/// # 理由コードを潰さずに出す
///
/// `net-06-numeric`が投げるのは10進/16進/8進のIPリテラルで、
/// このとき層1が出す理由は**`ip_literal_denied`**である（`harness-core`の`evaluate_host`は
/// IPリテラル判定を名前照合より**前**に置いている）。**`domain_denied`だけを見ると、
/// 正しく断たれていても「拒否が無い」と読めてしまう**ので、理由で畳まず全部出す。
///
/// # 判定しない
///
/// 呼び出し元と同じ理由で`assert`を置かない（いま閾値を書くと測る前に答えを書くことになる）。
/// **結論が出たらその時点で対の`assert`へ置き換える。**
fn report_proxy_denials(name: &str, audit_entries: &[serde_json::Value]) {
    let mut by_reason: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for e in audit_entries {
        // 制御レコードは通信の記録ではない（`harness_policy::is_net_control_record`と同じ判定）。
        if e.get("protocol").and_then(|p| p.as_str()) == Some("control") {
            continue;
        }
        if e.get("allowed").and_then(|a| a.as_bool()) != Some(false) {
            continue;
        }
        // WFP側（層2）はこの関数の対象外——そちらは`report_net_event_audit`が数える。
        if e.get("kind").and_then(|k| k.as_str()) == Some("wfp") {
            continue;
        }
        // **`kind`も鍵に含める。** 層1の拒否は`fake_dns`（名前解決の段）と`proxy`（接続の段）の
        // 2種あり、**どちらで断たれたかで「外へソケットが開かれたか」が変わる**
        // ——名前解決で断たれていれば接続そのものが起きない。理由コードだけで畳むと潰れる。
        let kind = e
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("(kindなし)");
        let reason = e
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("(理由なし)");
        let host = e
            .get("host")
            .and_then(|h| h.as_str())
            .unwrap_or("(ホスト名なし)")
            .to_string();
        by_reason
            .entry(format!("{kind}/{reason}"))
            .or_default()
            .push(host);
    }

    if by_reason.is_empty() {
        // **黙って飛ばさない。** 「層1の拒否が1件も無い」こと自体が、
        // `classify_drop=0`を取りこぼしと読むべき根拠になる。
        eprintln!("[BUG-094][{name}] 層1(プロキシ)の拒否: 0件");
        return;
    }
    for (kind_and_reason, hosts) in by_reason {
        eprintln!(
            "[BUG-094][{name}] 層1(プロキシ)の拒否: {kind_and_reason}={} 宛先={hosts:?}",
            hosts.len()
        );
    }
}

/// [BUG-094] **届いたイベントが「自分の窓の中で起きたもの」かを出す。**
///
/// # 何を分けたいのか
///
/// 購読はharnessの実行ごとに張って畳むので、窓は短い。WFPの配送が非同期なら、
/// **畳んだ後に届いた分は捨てられ**、間に合った分だけが**そのとき生きている購読**へ着地する。
/// それが起きているなら、届いたイベントの**発生時刻が自分の窓より前**になる。
///
/// 窓の両端は要約レコード1行で足りる——始まりは`subscribed_at_unix_ms=`、
/// 終わりはその要約自身の`timestamp_unix_ms`（撤収時に書くため）。
///
/// # 判定しない
///
/// 呼び出し元と同じ理由で`assert`を置かない。**数えた値を残すところまで**が仕事である。
fn report_delivery_lag(name: &str, audit_entries: &[serde_json::Value], controls: &[&&str]) {
    let summary = controls.iter().find(|r| r.starts_with("net_event_summary"));
    let window_opened: Option<u64> = summary.and_then(|r| {
        r.split("subscribed_at_unix_ms=")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    });
    let window_closed: Option<u64> = audit_entries
        .iter()
        .find(|e| {
            e.get("reason")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.starts_with("net_event_summary"))
        })
        .and_then(|e| e.get("timestamp_unix_ms").and_then(|t| t.as_u64()));
    let (Some(opened), Some(closed)) = (window_opened, window_closed) else {
        // **黙って飛ばさない。** 窓が引けないこと自体が、次に直す場所を指している。
        eprintln!(
            "[BUG-094][{name}] 購読の窓を引けなかった（要約に`subscribed_at_unix_ms=`が無いか、\
             要約レコード自体が無い）。古いnetfilterdが動いていないか確かめること"
        );
        return;
    };
    eprintln!(
        "[BUG-094][{name}] 購読の窓: {opened} 〜 {closed}（unix ms、幅{}ms）",
        closed.saturating_sub(opened)
    );
    for e in audit_entries
        .iter()
        .filter(|e| e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop"))
    {
        let received = e.get("timestamp_unix_ms").and_then(|t| t.as_u64());
        let occurred = e.get("event_unix_ms").and_then(|t| t.as_u64());
        let verdict = match (occurred, received) {
            (None, _) => "発生時刻が載っていない（古いnetfilterdが書いた行）".to_string(),
            (Some(o), _) if o < opened => {
                format!(
                    "**窓が開く{}ms前**に起きたもの＝前の購読の落とし分",
                    opened - o
                )
            }
            (Some(o), _) if o > closed => format!("窓が閉じた{}ms後に起きたもの", o - closed),
            (Some(o), Some(r)) => format!("窓の中。配送の遅れ={}ms", r.saturating_sub(o)),
            (Some(_), None) => "窓の中（受信時刻が読めない）".to_string(),
        };
        // **宛先まで出す。** 購読テンプレートは`default()`＝絞り込み無しなので、
        // このコールバックはharnessが張ったフィルタの落とし分だけを受け取るとは限らない。
        // 「自分が塞いだ通信か、マシン上の無関係な通信か」は宛先を見ないと言えない。
        let peer = e.get("remote_addr").and_then(|a| a.as_str()).unwrap_or("?");
        let port = e.get("remote_port").and_then(|p| p.as_u64()).unwrap_or(0);
        let filter = e.get("filter_id").and_then(|f| f.as_u64());
        // [BUG-094] **誰のフィルタが落としたか。** 購読も列挙もマシン全体が対象なので、
        // これが無いと1行を見ても「自分が塞いだ通信」か「隣の無関係なプロセス」かを言えない。
        // 項目自体が無いのは**この注記より前のnetfilterdが書いた行**である
        // （「harnessのものではない」と混同しない、`B-10`）。
        let owner = e
            .get("filter_owner")
            .and_then(|o| o.as_str())
            .unwrap_or("(注記なし＝古いnetfilterd)");
        eprintln!(
            "[BUG-094][{name}] classify_drop 宛先={peer}:{port} filter={filter:?} \
             出所={owner} 発生={occurred:?} 受信={received:?} → {verdict}"
        );
    }
    report_filter_owner_tally(name, audit_entries);
}

/// [BUG-094] **出所の内訳をcaseごとに1行で残す。**
///
/// 個別行だけだと、件数が増えたときに「何件が自分の分か」を数え直すことになる。
/// **`harness`が0件のときは、要約レコードの`owned_filter_ids=`と対で読む**
/// ——そちらが0なら判定ではなく配線（IDを渡す経路）が落ちている。
fn report_filter_owner_tally(name: &str, audit_entries: &[serde_json::Value]) {
    let mut tally: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for e in audit_entries
        .iter()
        .filter(|e| e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop"))
    {
        let owner = e
            .get("filter_owner")
            .and_then(|o| o.as_str())
            .unwrap_or("(注記なし)");
        *tally.entry(owner).or_default() += 1;
    }
    if tally.is_empty() {
        return;
    }
    eprintln!("[BUG-094][{name}] classify_dropの出所内訳: {tally:?}");
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
    run_net_case(
        "net-01-none",
        &[],
        "all-denied",
        &["example.com", "google.com"],
        // 2本とも層1で断たれる（許可リストが空）。WFPの拒否0件はそれで説明が付く。
        &[("domain_denied", 2)],
    )
}

fn net_case_02_invalid_domain() -> Result<(), String> {
    run_net_case(
        "net-02-invalid",
        &["invalidexample.com"],
        "all-denied",
        &["example.com", "google.com"],
        &[("domain_denied", 2)],
    )
}

/// 03: example.com許可。case-matrix `domains`はexample.com=allow/google.com=denyを同時に
/// アサートするため、これ自体がpositive control(通信路が生きていることの証明)を兼ねる(Q5)。
fn net_case_03_example_allowed() -> Result<(), String> {
    run_net_case(
        "net-03-example",
        &["example.com"],
        "domains",
        &["google.com"],
        &[("domain_denied", 1)],
    )
}

/// 05: Layer2検証。example.comは許可済みだが、`raw-connect`はプロキシ環境変数を無視して
/// 直接TCP接続する(`tier2a-net-e2e.exe`のdocコメント参照)。WFPが機能していなければ
/// ここが素通りする=D-01「フックは境界にしない」の直接検証。
fn net_case_05_raw_tcp_bypasses_proxy() -> Result<(), String> {
    // 層1を通る唯一のケース（プロキシ環境変数を無視して直接TCPを張る）なので、層1の拒否は0件。
    run_net_case("net-05-rawtcp", &["example.com"], "example-ip", &[], &[])
}

/// 06: Layer1検証。10進/16進/8進のIPリテラルでドメインマッチングをすり抜けようとする経路。
fn net_case_06_numeric_ip_obfuscation() -> Result<(), String> {
    // [BUG-094] **WFPの拒否が0件なのは正しい。** 3本のプローブはすべて層1で
    // `ip_literal_denied`（宛先が名前ではなく数字のアドレス）として断たれ、
    // 外向きのソケットが一度も開かれないのでWFPに落とすものが無い。
    // **ここを固定しておかないと、層1が断たなくなった日に0が取りこぼしと見分けられなくなる。**
    run_net_case(
        "net-06-numeric",
        &["example.com"],
        "numeric-ip",
        &[],
        &[("ip_literal_denied", 3)],
    )
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
///
/// # **隣に置くものは1つではない**（2026-09-20に07・10が落ちて判明）
///
/// harnessは**自分の実行ファイルの隣**から相棒を解決する。したがってこのディレクトリは
/// 「モックを差し込む場所」であると同時に、**harnessが隣に期待する物すべてを揃える場所**でもある。
/// 後から`harness-spawnd.exe`（Tier2aの起動に必須）が増えたとき、増やした側は
/// 本物の`target/debug`しか見ていなかったので、ここだけが取り残された。
///
/// 症状は「そのケースだけ**harnessの起動自体が失敗する**」で、**テストは赤くなるが理由が
/// 測っている対象と無関係**になる（07・10はどちらもWFP不成立時のfail-closedを測る腕なので、
/// 起動できない限り**その不変条件は1度も確かめられない**）。しかも両ケースは
/// `--ignored`で通常のテスト実行から外れているため、**誰も気づかないまま空振りし続ける**。
///
/// **隣に置く物を増やしたら、ここへも足すこと。**
fn wfp_fail_closed_launcher_exe() -> PathBuf {
    wfp_fail_closed_launcher_exe_with_mode("_launcher-wfp-failclosed", None)
}

/// `wfp_fail_closed_launcher_exe`のモード指定版。モックの故障モードは**環境変数ではなく
/// `mock-mode`ファイル**で渡す——モックは`ShellExecuteExW(runas)`経由で起動されうるが、
/// その場合プロセスを生成するのはAppInfoサービスなのでテストプロセスの環境変数が継承されない
/// （`crates/tier2a-mock-netfilterd/src/main.rs`のモジュールdoc参照）。
fn wfp_fail_closed_launcher_exe_with_mode(dir_name: &str, mode: Option<&str>) -> PathBuf {
    let dir = Path::new(CASE_ROOT).join(dir_name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create launcher dir");
    let harness_copy = dir.join("harness.exe");
    std::fs::copy(harness_exe(), &harness_copy).expect("copy harness.exe into launcher dir");
    std::fs::copy(mock_netfilterd_exe(), dir.join("harness-netfilterd.exe"))
        .expect("copy mock netfilterd exe into launcher dir as harness-netfilterd.exe");
    // **本物をそのまま持ってくる**——ここで差し替えたいのはnetfilterdだけである。
    // 一覧にしてあるのは、**次に増えたときに足す場所を1箇所にする**ため。
    // 増えた順に: Spawn Daemon（遷移MACの強制点）、Redirector DLL（透過層の注入元）、
    // 32bit版のRedirector DLL（D-90の段3で版一致のゲートが全Tier2aへ広がり、無ければ
    // Tier2aの起動前確認で止まるようになった。名前は起動前確認と同じ定数から取る）。
    let real_dir = harness_exe()
        .parent()
        .expect("harness exe has a parent dir")
        .to_path_buf();
    for sibling in [
        "harness-spawnd.exe",
        "harness_redirector.dll",
        harness_sandbox::tier2a::redirector_identity::X86_DLL_FILENAME,
    ] {
        let src = real_dir.join(sibling);
        std::fs::copy(&src, dir.join(sibling)).unwrap_or_else(|e| {
            panic!(
                "copy {sibling} into the launcher dir failed ({}): {e}. \
                 harness resolves it next to its own exe, so this relocated copy needs it too \
                 (build the workspace first).",
                src.display()
            )
        });
    }
    if let Some(mode) = mode {
        std::fs::write(dir.join("mock-mode"), mode).expect("write mock mode marker");
    }
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
/// **かつての既知の脆さ（[BUG-053](../../../docs/bugs/BUG-053.md)で解消済み）**: Tier2aの
/// AppContainerプロファイル（`harness.shell.sandbox`）は全ケースで共有される。かつて
/// `harness-netfilterd`はloopback exemptionを「このセッションで新規追加した場合のみ」teardown時に
/// 削除する設計だったため、`sudo`呼び出しの中断・`taskkill`による強制終了の後にexemptionが残留し、
/// モックがWFP起動を阻止していてもLayer1プロキシへのloopback到達だけが生き残る、という現象を実機で
/// 観測していた（`CheckNetIsolation LoopbackExempt -s`で残留を確認していた）。現在は所有権を
/// プロセス跨ぎの参照カウントで管理し（D-36、`crates/harness-sandbox/src/tier2a/loopback_exemption.rs`）、
/// 最後の所有者が抜けた時点で確実に削除される。生存所有者が居ない残留は次セッションが引き取って
/// 掃除するため、異常終了後も1サイクルで自己修復する。
fn net_case_07_wfp_start_failure_is_fail_closed() -> Result<(), String> {
    let exe = wfp_fail_closed_launcher_exe();
    run_net_case_with_exe_and_stderr_check(
        &exe,
        "net-07-wfp-failclosed",
        &["example.com"],
        "all-denied",
        &[],
        Some("Tier2a run_shell network capability will remain denied"),
        // WFPが立たないのでネットワークcapability自体が与えられない。
        // **層1のプロキシも起きない**ので、層1の拒否は0件が正しい。
        &[],
    )
}

/// 10: WFP fail-closed の**もう一方の分岐**（`docs/STATUS.md` Tier2a残課題#2）。
///
/// case 07 が固定しているのは`connect_and_apply`の**I/O失敗**分岐だけである（モックが接続直後に
/// パイプを閉じるので`ERROR_BROKEN_PIPE`になる）。しかし現実には、**daemonは正常に起動して
/// 応答も返すが、WFPエンジン自体が開けない**という失敗の形がある——BFEサービスが停止している、
/// `FwpmEngineOpen0`が失敗する、等。このときdaemonは`NetfilterResponse::Err`を返し
/// （`netfilterd.rs`の`serve_inner`）、親側は`NetfilterError::Rejected`へ写す。
/// **`connect_and_apply`の中で通る分岐がcase 07とは違う。**
///
/// この分岐でもfail-closedでなければならない理由は capability の粒度にある。AppContainerの
/// network capabilityは「全遮断」か「開放」の2値しかないので、`--net-allow-domain`を
/// 指定した時点でharnessは子へcapabilityを与えざるを得ず、**子とインターネット全体の間に
/// 立っているのはWFPフィルタだけ**になる。WFPが張れていないのにcapabilityを与えると、
/// モデルから見える`EnvironmentFacts`にはドメイン制限が宣言されたまま出口が全開になる。
///
/// モックの`reject`モードは`ApplyRules`を読み切ってから`Err`応答を1フレーム返すので、
/// 親から見た経路は実daemonがWFP失敗を報告したときと同じである。
///
/// **stderrの検査文字列に`daemon rejected the request`を選んでいるのが、このケースの肝**。
/// case 07と同じ「capabilityがDenyになった」だけを見ると、モックの`reject`モードが
/// 何かの理由で動かず**パイプを閉じてcase 07と同じ経路に落ちても緑になってしまう**
/// （[BUG-056](../../../docs/bugs/BUG-056.md)と同じ「緑だが測っていない」形）。
/// `NetfilterError::Rejected`のDisplayはこの分岐でしか出ないので、これを要求すれば
/// 「意図した分岐を通った」ことまで固定できる。
fn net_case_10_wfp_rejected_response_is_fail_closed() -> Result<(), String> {
    let exe = wfp_fail_closed_launcher_exe_with_mode("_launcher-wfp-rejected", Some("reject"));
    run_net_case_with_exe_and_stderr_check(
        &exe,
        "net-10-wfp-rejected",
        &["example.com"],
        "all-denied",
        &[],
        Some("daemon rejected the request: failed to apply WFP rules: mock fault injection"),
        // WFPが立たないのでネットワークcapability自体が与えられない。
        // **層1のプロキシも起きない**ので、層1の拒否は0件が正しい。
        &[],
    )
}

/// `run_net_case`はcase-matrixバイナリ専用のため、`keepalive-reuse`/`connect-sni`のような
/// 個別プローブ呼び出しを`run_shell`経由でサンドボックス内から実行し、tool_calls結果の
/// 最後のJSON行を返す（案08/09専用）。ワークスペースは呼び出し側が判定を終えてから
/// `cleanup_on_success`すること（先に消すと失敗時の調査ができなくなる）。
fn run_net_probe_script(
    name: &str,
    allow_domains: &[&str],
    script: &str,
) -> Result<(PathBuf, serde_json::Value), String> {
    let ws = net_case_ws(name);
    // 監査ログの置き場は全セッションで作られるので`--staged`は要らない（`run_net_case`のdoc）。
    let mut extra_args: Vec<&str> = Vec::new();
    for d in allow_domains {
        extra_args.push("--net-allow-domain");
        extra_args.push(d);
    }
    let run = run_harness(&ws, &run_shell_script_turns(script), &extra_args, name);
    if !run.status.success() {
        return Err(format!("harness invocation itself failed: {}", run.stderr));
    }
    assert_prompt_sane(&run, &["run_shell"])?;
    let outcome = parse_json_stdout(&run)?;
    let result_text = outcome.first_tool_result()?;
    let last_json = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .next_back()
        .ok_or_else(|| format!("no parseable JSON line in probe output: {result_text}"))?;
    Ok((ws, last_json))
}

/// 08: HTTP keep-alive。`tier2a-net-e2e.exe keepalive-reuse`が1本のTCP接続上で
/// 許可(example.com)→拒否(google.com)→許可(example.com)の3リクエストを送る。拒否後も
/// 接続が維持されリクエストごとにポリシーが再評価されることを実AppContainer子プロセス
/// 経由で確認する（`crates/harness-tools/src/net_proxy.rs`の
/// `keepalive_connection_reevaluates_policy_per_request`ユニットテストと同じ主張の実機版）。
fn net_case_08_keepalive_reevaluates_per_request() -> Result<(), String> {
    let script = ".\\tier2a-net-e2e.exe keepalive-reuse http://example.com/ http://google.com/";
    let (ws, json) = run_net_probe_script("net-08-keepalive", &["example.com"], script)?;
    let ok = json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let statuses: Vec<u64> = json["statuses"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();
    if !ok || statuses.len() != 3 || statuses[1] != 403 {
        return Err(format!(
            "expected [2xx, 403, 2xx] on one keep-alive connection, got statuses={statuses:?}: {json}"
        ));
    }

    let audit_path = ws.join(".harness").join("sandbox");
    let audit_entries = collect_audit_entries(&audit_path)?;
    let denied = audit_entries.iter().any(|e| {
        e.get("allowed") == Some(&serde_json::Value::Bool(false))
            && e.get("host")
                .and_then(|h| h.as_str())
                .map(|h| h.contains("google.com"))
                .unwrap_or(false)
    });
    if !denied {
        return Err(format!(
            "no audit deny entry for google.com on the keep-alive connection: {audit_entries:?}"
        ));
    }

    cleanup_on_success(&ws, &[], "net-08-keepalive");
    Ok(())
}

/// 09: CONNECTトンネル内のTLS SNI検査。`example.com`へCONNECTした上で、ClientHelloの
/// SNIを許可リスト外の`notallowed.invalid.example`に差し替えて送る。トンネルは即座に
/// 閉じられ（`outcome=tunnel_closed`）、監査ログに`protocol=tls_sni`かつ`reason=sni_denied`の
/// エントリが残ることを実機で確認する（`crates/harness-tools/src/tunnel.rs`の
/// `SniTunnelHandler`が実AppContainer子プロセス配下でも機能していることの確認）。
fn net_case_09_connect_sni_denied_closes_tunnel() -> Result<(), String> {
    let script = ".\\tier2a-net-e2e.exe connect-sni example.com --sni notallowed.invalid.example";
    let (ws, json) = run_net_probe_script("net-09-connect-sni", &["example.com"], script)?;
    let ok = json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let outcome = json.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
    if !ok || outcome != "tunnel_closed" {
        return Err(format!(
            "expected outcome=tunnel_closed for an SNI-denied ClientHello, got: {json}"
        ));
    }

    let audit_path = ws.join(".harness").join("sandbox");
    let audit_entries = collect_audit_entries(&audit_path)?;
    let found = audit_entries.iter().any(|e| {
        e.get("protocol").and_then(|p| p.as_str()) == Some("tls_sni")
            && e.get("allowed") == Some(&serde_json::Value::Bool(false))
            && e.get("reason").and_then(|r| r.as_str()) == Some("sni_denied")
    });
    if !found {
        return Err(format!(
            "no tls_sni/sni_denied audit entry found: {audit_entries:?}"
        ));
    }

    cleanup_on_success(&ws, &[], "net-09-connect-sni");
    Ok(())
}

#[test]
#[ignore]
fn tier2a_net_policy_matrix() {
    let _ex = cow_exclusive();
    if let Err(e) = liveness_gate() {
        panic!("liveness gate failed, all subsequent cases are indeterminate: {e}");
    }
    report_wfp_audit_policy();

    let cases: Vec<(&str, CaseFn)> = vec![
        ("01-none", net_case_01_none),
        ("02-invalid-domain", net_case_02_invalid_domain),
        ("03-example-allowed", net_case_03_example_allowed),
        ("05-raw-tcp-layer2", net_case_05_raw_tcp_bypasses_proxy),
        ("06-numeric-ip-layer1", net_case_06_numeric_ip_obfuscation),
        (
            "07-wfp-start-failure-fail-closed",
            net_case_07_wfp_start_failure_is_fail_closed,
        ),
        (
            "08-keepalive-reevaluates-per-request",
            net_case_08_keepalive_reevaluates_per_request,
        ),
        (
            "09-connect-sni-denied-closes-tunnel",
            net_case_09_connect_sni_denied_closes_tunnel,
        ),
        (
            "10-wfp-rejected-response-fail-closed",
            net_case_10_wfp_rejected_response_is_fail_closed,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} network policy matrix cases passed (see per-case JSON above for details)"
    );
}

// ============================================================================
// W6: `--fs-allow`を実CLIフラグ経由で通すE2E
//
// `plans/PLAN-M15.7-FOLLOWUP.md` F10が指摘していた穴——`--fs-allow`は`preflight`の
// 単体テストでは測られていたが、**実CLIフラグからサンドボックスの子まで通す経路**の
// 回帰テストが1件も無かった。D-45（fs-allowの祖先へtraverseを付与する）を入れた今、
// ここが赤くなれば「明示的に許可したパスが使えない」という退行を機械的に検出できる。
//
// `dev-elevated-run.exe e2e-fs-allow`（フィルタ`tier2a_fs_allow`）。

/// `--fs-allow`のエントリを`C:\`直下に作る。深い場所（`%TEMP%`等）に置くと、この機で
/// 既に付与済みの祖先traverseに相乗りしてしまい、**D-45が効いているのか、以前からの
/// 付与のおかげなのかを区別できない**（RESULTS.md §19の測定と同じ理由）。
fn fs_allow_case_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(format!(
        r"C:\harness-e2e-fsallow-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create fs-allow target dir");
    dir
}

/// **前の実行が残した合成保護パスを掃除する**（自分のPIDのものは触らない）。
///
/// # なぜこれが要るか
///
/// 保護の掛け方（[`harden_as_system_protected`]）は`icacls`を4手撃つ。**途中で落ちると、
/// 所有者がSYSTEMでDACLが空のディレクトリが残る**——この状態は所有者でもなく権利も無いので、
/// **非昇格では読むことも消すこともできない**（`Get-Acl`すら`UnauthorizedAccessException`になる）。
/// 残ると次の測定の前後差に混ざるので、**測る側が自分で掃く**（`measurement-review`の検問11）。
///
/// # なぜ`takeown`なのか
///
/// `icacls /setowner`は`WRITE_OWNER`を要求するが、この状態のディレクトリにはそれが無い。
/// `takeown`は`SeTakeOwnershipPrivilege`を**自分で有効化する**ので、昇格して走っていれば通る。
/// **`/a`でAdministratorsへ渡す**——このプロセスはそのメンバーなので、以後DACLを書ける。
fn sweep_stale_fs_allow_protected_dirs() {
    const PREFIX: &str = "harness-e2e-fsallow-elev-";
    let mine = format!("-{}", std::process::id());
    let Ok(entries) = std::fs::read_dir(r"C:\") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(PREFIX) || name.ends_with(&mine) {
            continue;
        }
        let path = entry.path();
        // まず素で消せるなら消す（保護が掛かる前に落ちた回はこれで片付く）。
        if std::fs::remove_dir_all(&path).is_ok() {
            eprintln!("[fs-allow-elev] swept stale dir: {}", path.display());
            continue;
        }
        let path_str = path.display().to_string();
        let _ = Command::new("takeown")
            .args(["/f", path_str.as_str(), "/a"])
            .output();
        let grant = format!("*{BUILTIN_ADMINISTRATORS_SID}:(OI)(CI)(F)");
        let _ = Command::new("icacls")
            .args([path_str.as_str(), "/grant", grant.as_str()])
            .output();
        match std::fs::remove_dir_all(&path) {
            Ok(()) => eprintln!("[fs-allow-elev] swept stale protected dir: {path_str}"),
            // **黙って諦めない**（`B-10`）。残ったことと、手で消す方法を出す。
            Err(e) => eprintln!(
                "[fs-allow-elev] could not sweep {path_str} ({e}). Recover with (elevated): \
                 takeown /f \"{path_str}\" /a && icacls \"{path_str}\" /grant \"{grant}\" && \
                 rmdir /s /q \"{path_str}\""
            ),
        }
    }
}

/// ROで許可したエントリは**読めて書けない**。境界はACLなので、書込は子プロセスの側で
/// `ACCESS_DENIED`にならなければならない。
///
/// **宣言は`<path>\**`（配下まで）である**——D-63で「素のパスはそのオブジェクト1個だけ」に
/// 変わったため、配下の`secret.txt`を開くには`**`が要る（[BUG-136](../../../docs/bugs/BUG-136.md)）。
/// **この追随だけでは足りない**: `**`付きに揃えると、D-63の本体（素のパス＝オブジェクト単体）を
/// 誰も測らなくなり、スコープ判定が全部再帰へ退化しても緑のままになる。対になる
/// [`fs_allow_case_bare_path_grants_the_object_only`]が素のパスの側を固定している。
fn fs_allow_case_ro_reads_but_cannot_write(ledger: &FsLedgerExclusive) -> Result<(), String> {
    let ws = case_dir("fs-allow-ro");
    let target = fs_allow_case_dir("ro");
    std::fs::write(target.join("secret.txt"), "readable").map_err(|e| e.to_string())?;

    let allow = format!(r"{}\**", target.display());
    // PowerShellはパス区切りに`/`を受け付ける。Rustの文字列・シェル・PowerShellの3段で
    // バックスラッシュを重ねるとエスケープ事故になるので、スクリプト内では`/`で書く。
    let t = target.display().to_string().replace('\\', "/");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         $r = Get-Content -LiteralPath '{t}/secret.txt' -Raw; Write-Output ('READ=' + $r); \
         try {{ Set-Content -LiteralPath '{t}/written.txt' -Value 'x' -ErrorAction Stop; \
           Write-Output 'WRITE=OK' }} catch {{ Write-Output 'WRITE=DENIED' }}"
    );
    let run = run_harness(
        &ws,
        &run_shell_script_turns(&script),
        &["--fs-allow", &allow],
        "fs-allow-ro",
    );
    let json = parse_json_stdout(&run)?;
    // 子が**返した**stdoutだけを見る。JSON全体を見ると、子へ**渡した**スクリプト本文
    // （`WRITE=DENIED`をリテラルで含む）にも当たって判定が素通しになる（BUG-137）。
    let text = json.first_tool_result()?;
    if !text.contains("READ=readable") {
        return Err(format!("read-only fs-allow entry was not readable: {text}"));
    }
    if !text.contains("WRITE=DENIED") {
        return Err(format!(
            "read-only fs-allow entry must not be writable (boundary is the ACL, not the hook): {text}"
        ));
    }
    let leaked = target.join("written.txt");
    if leaked.exists() {
        return Err(format!("the child actually wrote {}", leaked.display()));
    }

    // 台帳から自分のエントリを落としてから消す。`--fs-allow`由来のエントリは
    // `settings_managed`が立たずD-27の自動撤収対象にならないので、放っておくと
    // 実在しないパスを指す残骸が保護対象の台帳へ溜まり続ける（実機で21件溜まっていた）。
    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws, &[], "fs-allow-ro");
    Ok(())
}

/// `:rw`で許可したエントリは**書けて・消せて・移動できる**。
///
/// 削除と移動はD-45（`--fs-allow`の祖先へtraverseを付与する）が入るまで失敗していた
/// （RESULTS.md §19.2）。この2操作は祖先ディレクトリを通過ではなく**オープン**するため、
/// 対象自身へのACEだけでは足りない。**このケースがD-45の製品経路での回帰テストである。**
///
/// 宣言が`<path>\**:rw`である理由と、それだけでは足りない理由は
/// [`fs_allow_case_ro_reads_but_cannot_write`]と同じ（D-63／BUG-136）。
/// パーサは`strip_suffix(":rw")`（`cli/startup/sandbox.rs`）なので、
/// `<path>\**:rw`は`path=<path>\**`＋ReadWriteに割れる。
fn fs_allow_case_rw_can_write_delete_and_move(ledger: &FsLedgerExclusive) -> Result<(), String> {
    let ws = case_dir("fs-allow-rw");
    let target = fs_allow_case_dir("rw");
    std::fs::write(target.join("to-delete.txt"), "bye").map_err(|e| e.to_string())?;
    std::fs::write(target.join("to-move.txt"), "move me").map_err(|e| e.to_string())?;
    std::fs::create_dir_all(target.join("dest")).map_err(|e| e.to_string())?;

    let allow = format!(r"{}\**:rw", target.display());
    let t = target.display().to_string().replace('\\', "/");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ Set-Content -LiteralPath '{t}/new.txt' -Value 'created' -ErrorAction Stop; \
           Write-Output 'WRITE=OK' }} catch {{ Write-Output 'WRITE=FAIL' }}; \
         try {{ Remove-Item -LiteralPath '{t}/to-delete.txt' -ErrorAction Stop; \
           Write-Output 'DELETE=OK' }} catch {{ Write-Output 'DELETE=FAIL' }}; \
         try {{ Move-Item -LiteralPath '{t}/to-move.txt' -Destination '{t}/dest/moved.txt' \
           -ErrorAction Stop; Write-Output 'MOVE=OK' }} catch {{ Write-Output 'MOVE=FAIL' }}"
    );
    let run = run_harness(
        &ws,
        &run_shell_script_turns(&script),
        &["--fs-allow", &allow],
        "fs-allow-rw",
    );
    let json = parse_json_stdout(&run)?;
    // 子が**返した**stdoutだけを見る（BUG-137）。JSON全体だと、子へ**渡した**スクリプト本文が
    // `DELETE=OK`・`MOVE=OK`をリテラルで含むので、この3判定は子が何をしても真になっていた。
    let text = json.first_tool_result()?;
    for expected in ["WRITE=OK", "DELETE=OK", "MOVE=OK"] {
        if !text.contains(expected) {
            return Err(format!(
                "`--fs-allow <path>:rw` must allow write/delete/move (D-45: the fs-allow ancestors \
                 get a traverse ACE); missing {expected} in: {text}"
            ));
        }
    }
    if target.join("to-delete.txt").exists() {
        return Err("delete reported OK but the file is still there".to_string());
    }
    if !target.join("dest").join("moved.txt").exists() {
        return Err("move reported OK but the destination file does not exist".to_string());
    }

    // 台帳から自分のエントリを落としてから消す。`--fs-allow`由来のエントリは
    // `settings_managed`が立たずD-27の自動撤収対象にならないので、放っておくと
    // 実在しないパスを指す残骸が保護対象の台帳へ溜まり続ける（実機で21件溜まっていた）。
    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws, &[], "fs-allow-rw");
    Ok(())
}

/// **素のパス（`**`無し）は、そのオブジェクト1個だけを開く**（D-63、
/// `plans/DESIGN-SANDBOX-APPPOLICY.md`）。上の2ケースを`**`付きへ揃えたことで空いた穴を
/// 埋めるのがこのケースである（[BUG-136](../../../docs/bugs/BUG-136.md)のC2）。
///
/// **これが無いと、スコープ判定が全部`Recursive`へ退化しても行列は緑のまま**になる——
/// 「赤いテストを、確かめている中身を減らすことで緑にする」型（[BUG-088]）そのもの。
///
/// 許可側と禁止側を対で固定する（`B-35`）。**両方とも実測に基づく**——BUG-136が残した証跡で、
/// ディレクトリ1個への非継承ACEでは「新規ファイルは作れるが、既存の子ファイルは開けない」
/// ことが確認されている（`fs_access_mask`の`ReadWrite`は`FILE_DELETE_CHILD`を含まない）。
///
/// | 見るもの | 期待 | これが崩れると何が壊れたと言えるか |
/// |---|---|---|
/// | 子が`new.txt`を作れる | できる | 素のパスの付与自体が効いていない（機構が死んでいる） |
/// | 子が`existing.txt`の中身を得られない | 得られない | スコープが再帰へ退化し、宣言より広く開いている |
fn fs_allow_case_bare_path_grants_the_object_only(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    let ws = case_dir("fs-allow-bare");
    let target = fs_allow_case_dir("bare");
    // 中身は子の出力に現れてはならない印。ラベルではなく**中身そのもの**を探すことで、
    // 「拒否された」と「空を読めた」を区別せずに『子へ渡っていない』だけを固定できる。
    std::fs::write(target.join("existing.txt"), "keepme").map_err(|e| e.to_string())?;

    // `**`を**付けない**のがこのケースの主題。`:rw`だけを付ける。
    let allow = format!("{}:rw", target.display());
    let t = target.display().to_string().replace('\\', "/");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ Set-Content -LiteralPath '{t}/new.txt' -Value 'created' -ErrorAction Stop; \
           Write-Output 'CREATE=OK' }} catch {{ Write-Output 'CREATE=FAIL' }}; \
         try {{ $r = Get-Content -LiteralPath '{t}/existing.txt' -Raw -ErrorAction Stop; \
           Write-Output ('READCHILD=OK:' + $r) }} catch {{ Write-Output 'READCHILD=DENIED' }}"
    );
    let run = run_harness(
        &ws,
        &run_shell_script_turns(&script),
        &["--fs-allow", &allow],
        "fs-allow-bare",
    );
    let json = parse_json_stdout(&run)?;
    let text = json.first_tool_result()?;

    // 許可側: ディレクトリ自身への非継承ACEは効いている。
    if !text.contains("CREATE=OK") {
        return Err(format!(
            "a bare `--fs-allow <dir>:rw` must still grant the directory object itself \
             (new files can be created in it): {text}"
        ));
    }
    // `B-12`型の穴を塞ぐ: 2文目まで到達したことを確かめてから「読めなかった」を主張する。
    // 途中でスクリプトが死んでいれば、以降は何でも「拒否された」に見える。
    if !text.contains("READCHILD=") {
        return Err(format!(
            "the probe script did not reach the read step, so 'the child could not read it' \
             cannot be concluded: {text}"
        ));
    }
    // 禁止側（D-63の本体）: 配下の中身は子へ渡らない。
    if text.contains("keepme") {
        return Err(format!(
            "D-63 violated: a bare `--fs-allow <dir>` must grant the object only, but the child \
             read the contents of a file *under* it -- the declared scope has degraded to \
             recursive: {text}"
        ));
    }
    if !target.join("new.txt").exists() {
        return Err("the child reported CREATE=OK but new.txt is not on disk".to_string());
    }
    // 子が書き換えていないことも見る（読めなかったのであって、壊したのではない）。
    let still = std::fs::read_to_string(target.join("existing.txt")).map_err(|e| e.to_string())?;
    if still != "keepme" {
        return Err(format!("existing.txt was modified by the child: {still:?}"));
    }

    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws, &[], "fs-allow-bare");
    Ok(())
}

/// `path`のDACLに載っている、接頭辞`prefix`のSIDのACE本数（実DACLを`Get-Acl`で読む）。
///
/// **台帳ではなく実体を見る**（`B-14`）。`S-1-15-2-`はAppContainerのpackage SID、
/// `S-1-15-3-`はcapability SIDで、`--fs-allow`の宛先SIDは前者から後者へ移った（§22.3）。
fn count_sid_aces(path: &Path, prefix: &str) -> Result<usize, String> {
    Ok(sid_aces(path, prefix)?.len())
}

/// [`count_sid_aces`]の**綴りまで返す版**（同じ`Get-Acl`の1回で本数も綴りも取れるので、
/// 数える側をこちらへ寄せてある——2つの読み方が別々のPowerShellを持つと、片方だけ
/// フィルタが変わってずれる形を作る）。
///
/// **本数だけでは級を判定できない。** `--fs-allow`の宛先SIDは`(秘密, 畳み込み済みパス,
/// access級)`から導出されるので、**級が違えば別の綴りのSID**になる（§22.2.0）。
/// 「1本だけ載っている」は本数の話でしかなく、載っているのが宣言した級のものかは
/// 綴りを見るまで言えない。
fn sid_aces(path: &Path, prefix: &str) -> Result<Vec<String>, String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "@((Get-Acl '{}').Access | Where-Object {{ $_.IdentityReference -like '{prefix}*' }}) \
                 | ForEach-Object {{ $_.IdentityReference.Value }}",
                path.display()
            ),
        ])
        .output()
        .map_err(|e| format!("failed to run Get-Acl: {e}"))?;
    // **読めなかったことを0本と読ませない**（`B-10`）。旧版は`.Count`を数えており、
    // `Get-Acl`自体が失敗しても`0`が返って「ACEは載っていない」と同じ形になっていた。
    if !output.status.success() {
        return Err(format!(
            "Get-Acl on {} failed with {}: {}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// **[BUG-119] `--force-system-acl`を打っても、普通に付与できたパスは`forced`として
/// 記録されない。**
///
/// # なぜ実機で測るのか
///
/// 単体テスト（`fs_passthrough_ledger::grant_record_tests`）が固定しているのは
/// 「`preflight`の結果から台帳の1件を組む規則」であって、
/// **`preflight`が正しい`used_restore_privilege`を返すこと**ではない。
/// そこは実ACL・実際の付与経路を通らないと測れない。
///
/// # 何が起きていたか
///
/// `--force-system-acl`は**セッション全域のスイッチ**なので、付与に特権が要らなかった
/// パスにも`forced: true`が載っていた。台帳はユーザグローバルに1つきりで`forced`は
/// 上書きなので、**別のワークスペースの1回の起動が無関係なパスの過去の記録まで書き換える。**
/// そして`forced`は後日の`harness fs revoke`が`SeRestorePrivilege`を有効化するかを決める。
///
/// # この腕が測れないこと（先に書く）
///
/// 対象は`C:\harness-e2e`配下の**普通に書けるディレクトリ**なので、
/// `needs_elevation`へは入らない——つまり**「特権を使ったときに`true`になること」は
/// ここでは測っていない**。そちらは`elevated-grant-opens-only-the-declared-subject`が通る
/// 合成システム保護パスの腕に足すのが筋だが、本件では触っていない。
fn fs_allow_case_a_normally_grantable_path_is_not_recorded_as_forced(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    let ws = case_dir("fs-allow-forced-record");
    let target = fs_allow_case_dir("forced-record");
    std::fs::write(target.join("f.txt"), "x").map_err(|e| e.to_string())?;

    // **綴りは`<path>`か`<path>:rw`の2つだけである**（`sandbox.rs`の`strip_suffix(":rw")`と
    // `harness-config`の`FsSettings::to_fs_passthrough`。どちらも`:rw`しか剥がさない）。
    // ここはかつて`{}:ro`と書いており、`:ro`が**パスの一部**として扱われて
    // 「path does not exist, skipped」で丸ごと落ちていた——この腕は
    // [BUG-153](../../../docs/bugs/BUG-153.md)として記録した「一度も走らせていないテスト」で、
    // 追加時（2026-09-04）から赤のままだった。read-onlyは**接尾辞を付けない**のが正しい綴りで、
    // `--force-system-acl`のゲート（`:rw`が1つでもあれば起動拒否）もこの形で通る。
    let allow = target.display().to_string();
    let run = run_harness(
        &ws,
        &run_shell_script_turns("Write-Output 'ran'"),
        &["--fs-allow", &allow, "--force-system-acl"],
        "fs-allow-forced-record",
    );
    parse_json_stdout(&run)?;

    let entries = read_fs_ledger_forced_flags()?;
    let target_key = target
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    let mine: Vec<&(String, bool)> = entries
        .iter()
        .filter(|(p, _)| p.to_ascii_lowercase().replace('\\', "/") == target_key)
        .collect();
    if mine.is_empty() {
        return Err(format!(
            "the ledger has no entry for {} after the session; the grant never got recorded, so              this arm cannot say anything about `forced` (0件と成功を同じ値にしない、B-09)",
            target.display()
        ));
    }
    for (p, forced) in &mine {
        if *forced {
            return Err(format!(
                "[BUG-119] {p} is recorded as forced=true, but this path is writable without                  SeRestorePrivilege -- `--force-system-acl` is a session-wide switch, not a fact                  about this path. A later `harness fs revoke` would enable the privilege for it."
            ));
        }
    }
    eprintln!(
        "[fs-allow-forced-record] {} ledger entr(y/ies) for the target, all forced=false",
        mine.len()
    );

    // 名前の付いた扉で片付ける（案Cのゲートが正常系を素通りすることも、ここで通る）。
    let revoke = Command::new(harness_exe())
        .args(["fs", "revoke"])
        .arg(&target)
        .output()
        .map_err(|e| format!("failed to run `harness fs revoke`: {e}"))?;
    if !revoke.status.success() {
        return Err(format!(
            "`harness fs revoke {}` failed after the forced-record arm: {}{}",
            target.display(),
            String::from_utf8_lossy(&revoke.stdout),
            String::from_utf8_lossy(&revoke.stderr)
        ));
    }

    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws, &[], "fs-allow-forced-record");
    Ok(())
}

/// [§22.2.1] **`--fs-allow`のACEはharnessの終了後も残り、`harness fs revoke`で消える。**
///
/// # このテストは意味を変えてある（旧名 `..._is_revoked_when_the_session_ends`）
///
/// 旧版は「セッション終了でACEが失効する」（D-37の仕様）を測っており、その手段として
/// **`S-1-15-2-*`（package SID）の本数が0になること**だけを見ていた。宛先SIDが宣言ごとの
/// capability SID（`S-1-15-3-*`）へ移った後もこのassertはそのまま通る——**測る相手が
/// 変わっただけで、テストは緑のまま意味だけが嘘になる**（`B-08`）。
///
/// いま固定するのは3つ。
///
/// 1. 終了後、**package SID宛は0本**（§22.3.0の移行の不変条件。1本でも残っていれば、
///    その1本が同一セッションの全ドメインへ許可を出し続ける）
/// 2. 終了後、**宣言capability宛は残っている**（§22.2.1の寿命そのもの。セッション終了時に
///    剥がすと、同じワークスペースの並行セッションが互いの許可を落とす）
/// 3. `harness fs revoke <path>`の後、**どちらも0本**（T1-cの受け入れ条件1）
fn fs_allow_case_the_ace_persists_after_exit_and_the_named_door_removes_it(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    let ws = case_dir("fs-allow-revoke");
    let target = fs_allow_case_dir("revoke");
    std::fs::write(target.join("f.txt"), "x").map_err(|e| e.to_string())?;

    let allow = format!("{}:rw", target.display());
    let run = run_harness(
        &ws,
        &run_shell_script_turns("Write-Output 'ran'"),
        &["--fs-allow", &allow],
        "fs-allow-revoke",
    );
    parse_json_stdout(&run)?;

    // (1) 移行の不変条件。**capability宛を足しただけでは1ミリも成立しない**ので、
    // 「新しい宛先SIDが付いたか」ではなく「**旧い宛先SIDが消えたか**」を測る（§22.3.0）。
    let package = count_sid_aces(&target, "S-1-15-2-")?;
    if package != 0 {
        return Err(format!(
            "§22.3.0: {} still carries {package} package-SID ACE(s) after the harness session \
             ended; that one ACE keeps the path open to every domain in the session",
            target.display()
        ));
    }

    // (2) 新しい寿命。**この行が旧版には無かった**——無いと、付与そのものが壊れて
    // 「1本も付かなかった」場合も(1)は緑になる（0件と成功を同じ値にしない、`B-09`）。
    let subjects =
        harness_sandbox::tier2a::win_appcontainer::fs_allow_capability_sids(&target, None);
    if subjects.is_empty() {
        return Err(format!(
            "§22.2.1: the capability ledger has no declaration subject for {}, so the grant path \
             never minted one (nothing could revoke it later either)",
            target.display()
        ));
    }
    let capability = count_sid_aces(&target, "S-1-15-3-")?;
    if capability == 0 {
        return Err(format!(
            "§22.2.1: {} carries no declaration capability ACE after the session ended; \
             `--fs-allow` grants are persistent by design and the named door is the way to \
             remove them",
            target.display()
        ));
    }

    // (3) 名前の付いた扉で両方が消えること（T1-cの受け入れ条件1）。
    let revoke = Command::new(harness_exe())
        .args(["fs", "revoke"])
        .arg(&target)
        .output()
        .map_err(|e| format!("failed to run `harness fs revoke`: {e}"))?;
    eprintln!(
        "[fs-allow-revoke] fs revoke -> {} {}",
        revoke.status,
        String::from_utf8_lossy(&revoke.stdout).trim()
    );
    if !revoke.status.success() {
        return Err(format!(
            "`harness fs revoke {}` failed: {}{}",
            target.display(),
            String::from_utf8_lossy(&revoke.stdout),
            String::from_utf8_lossy(&revoke.stderr)
        ));
    }
    for prefix in ["S-1-15-2-", "S-1-15-3-"] {
        let left = count_sid_aces(&target, prefix)?;
        if left != 0 {
            return Err(format!(
                "{} still carries {left} {prefix}* ACE(s) after `harness fs revoke`; the named \
                 door must leave zero of both subjects (T1-cの受け入れ条件1)",
                target.display()
            ));
        }
    }

    // (4) [BUG-148] **記録も落ちること。** 上の(2)で同じ問いに「ある」と答えているので、
    // これは**宣言を1つ撤収するだけで結果が反転する対照**になっている——ACEが消えたことと
    // 記録が落ちたことを別々に測って、片方だけが起きていないかを見る。
    //
    // 旧実装はACEだけを剥がして記録を残した。`harness fs prune`は実在しないパスしか
    // 落とさない（D-53）ので、撤収したパスがディスクに在る限り消す手段が無く、
    // **宣言→撤収を繰り返すたびに台帳が単調に増えていた**。
    let left_records =
        harness_sandbox::tier2a::win_appcontainer::fs_allow_capability_sids(&target, None);
    if !left_records.is_empty() {
        return Err(format!(
            "[BUG-148] the capability ledger still records {} declaration subject(s) for {} after \
             `harness fs revoke`, even though the path carries zero capability ACEs. The record \
             is the index used to revoke, so leaving it behind makes it drift from reality (and \
             `harness fs prune` cannot collect it while the path still exists).",
            left_records.len(),
            target.display()
        ));
    }

    // 台帳から自分のエントリを落としてから消す。`--fs-allow`由来のエントリは
    // `settings_managed`が立たずD-27の自動撤収対象にならないので、放っておくと
    // 実在しないパスを指す残骸が保護対象の台帳へ溜まり続ける（実機で21件溜まっていた）。
    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws, &[], "fs-allow-revoke");
    Ok(())
}

// ----------------------------------------------------------------------------
// 昇格が要るシステム保護パスの腕（残課題#20の測定7、分流D）
//
// # 何を測るのか
//
// `preflight`は`--fs-allow`のACEを**このプロセスで書けなかったとき**だけ`needs_elevation`へ
// 積み、そこから先は別の後始末（完走・部分適用・ヘルパー不通の3分岐）を通る。2026-09-01の
// 分流N1は**まさにこの区間**を「昇格の後で宛先SIDを導出し直す」から「導出済みのSIDを
// `PendingElevation`で持ち回す」へ変えた。ところが受け入れ測定（§S40）は`C:\`直下の
// 書けるパスでしか回っておらず、**この区間はどのテストからも1度も実行されていない**。
//
// # どうやって`needs_elevation`へ入れるか
//
// 入るための条件はただ1つ、「素の`SetNamedSecurityInfoW`が`ACCESS_DENIED`になること」である。
// このE2Eは`dev-elevated-runner`配下で走る＝**テストもharnessも管理者**なので、普通のパスは
// 全部書けてしまう。そこで**合成のシステム保護パス**を作る（[`SystemProtectedDir`]）——
// 所有者をLocalSystemにし、DACLから`WRITE_DAC`を持つ項目を落とす。管理者トークンでも
// `WRITE_DAC`が取れなくなり、`SeRestorePrivilege`（`--force-system-acl`＝D-19の経路）でしか
// 書けない状態になる。これは`NT SERVICE\TrustedInstaller`所有ツリーが持つ性質と同じ形で、
// **本物のシステムディレクトリへACEを書かずに**同じ分岐へ入れる。
//
// # この器が測れないこと（先に書く）
//
// - **特権分離ヘルパー（privhelper、D-16）の線は通らない。** harness本体が既に管理者なので
//   `preflight`は「本体が既に管理者」の枝へ入り、ヘルパーへは委譲しない。非昇格のharnessから
//   ヘルパーだけを昇格させる口は`plans/PLAN-NONELEVATED-E2E.md`の段階2〜5が未実装で、
//   いま非昇格で回すとUACが出る。**ヘルパー側が`secret_hex`から独立に導出し直すSIDと、
//   こちら側が運ぶSIDが一致するか**は、したがって本器の射程外である。
// - **運ばれた宛先SIDの文字列そのものは読めない。** `harness-sandbox`はSIDを文字列にする口を
//   クレート外へ出しておらず（`win_common::sid_to_string`は`pub(crate)`）、`granted_passthrough`は
//   プロセスの外へ出ない。外から見えるのは**実DACL上のcapability ACEの本数**と**子の到達性**で、
//   本器はその2つで「宣言した1件だけが開いている」を固定する。
// ----------------------------------------------------------------------------

/// LocalSystem。合成のシステム保護パスの所有者にする相手。
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// `BUILTIN\Administrators`。**所有者にしてはいけない相手**として、理由とともに残してある。
///
/// # 所有者を`Administrators`にすると測定が成立しない（**実測**）
///
/// 一度これを所有者にして走らせたところ、`icacls`は通ったが**その次で落ちた**——
/// このE2Eは`dev-elevated-runner`経由で**昇格して走る**ので、そこから起動される
/// `harness.exe`も昇格トークンを継承する。**昇格したharnessは`Administrators`のメンバー＝
/// 所有者そのもの**なので、所有者が暗黙に得る`WRITE_DAC`でDACLを書けてしまい、
/// 「保護パスなので素では付与できない」という本ケースの前提が消える
/// （2026-09-01実測、`plans/mac-spike/RESULTS.md` §S44）。
///
/// **だから所有者は`S-1-5-18`（LocalSystem）でなければならない。** 昇格したharnessも
/// LocalSystemではないので、所有者としての`WRITE_DAC`を得られない。
#[allow(dead_code)]
const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// `WRITE_DAC`（`FileSystemRights::ChangePermissions`）。DACLを書き換える権利そのもの。
const WRITE_DAC_MASK: u32 = 0x0004_0000;

/// 合成のシステム保護ディレクトリ。**作った側が必ず戻す**（`Drop`で所有者と権限を戻して消す）。
///
/// `Drop`にしてあるのは、途中でassertが落ちても実マシンに「所有者がLocalSystemで、自分では
/// 消せないディレクトリ」を残さないためである。`?`で早期に返るケース関数の途中に後始末を
/// 書くと、**落ちた回だけ残骸が出る**——そして残骸は次の測定の前後差に混ざる。
struct SystemProtectedDir {
    path: PathBuf,
    /// 戻す先の所有者（＝この測定を走らせているユーザー）。
    restore_owner_sid: String,
}

impl SystemProtectedDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SystemProtectedDir {
    fn drop(&mut self) {
        // 所有権を取り戻す → フルコントロールを付け直す → 消す、の順。順番を変えると
        // 「所有者ではないのでDACLを書けない」で止まる。
        //
        // **この順序が成立するのは、保護を掛けるときにユーザーへ`WRITE_OWNER`を残してあるから**
        // である（`harden_as_system_protected`の`(M,WO)`）。残していないと1手目で止まる。
        let owner = format!("*{}", self.restore_owner_sid);
        let grant = format!("*{}:(OI)(CI)(F)", self.restore_owner_sid);
        for (args, what) in [
            (vec!["/setowner", owner.as_str()], "restore owner"),
            (vec!["/grant", grant.as_str()], "restore full control"),
        ] {
            if let Err(e) = icacls_on(&self.path, &args, what) {
                eprintln!("[fs-allow-elev] cleanup: {e}");
            }
        }
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            // **黙って諦めない。** 残ると次の測定の前後差に混ざるので、手で消すための
            // 手順をその場に出す（`B-10`: 無言で失敗しない）。
            eprintln!(
                "[fs-allow-elev] cleanup: could not remove {} ({e}). Recover with (elevated): \
                 icacls \"{}\" /setowner \"*{}\" && icacls \"{}\" /grant \"*{}:(OI)(CI)(F)\" && \
                 rmdir /s /q \"{}\"",
                self.path.display(),
                self.path.display(),
                self.restore_owner_sid,
                self.path.display(),
                self.restore_owner_sid,
                self.path.display()
            );
        }
    }
}

/// `icacls`を1回だけ叩く。**対象が実在することを先に確かめる**（[BUG-012](../../../docs/bugs/BUG-012.md):
/// 実在しないパスを渡すと`icacls`は黙って別の場所を走査しに行く）。`/T`は一切使わない。
fn icacls_on(dir: &Path, args: &[&str], what: &str) -> Result<(), String> {
    if !dir.exists() {
        return Err(format!(
            "refusing to run icacls ({what}): {} does not exist (BUG-012)",
            dir.display()
        ));
    }
    let output = Command::new("icacls")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run icacls ({what}) on {}: {e}", dir.display()))?;
    if !output.status.success() {
        return Err(format!(
            "icacls ({what}) on {} failed with {}: {} {}",
            dir.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// `path`の**所有者SID**と、**LocalSystem以外で`WRITE_DAC`を持つACEの本数**を実測する。
///
/// `icacls`の終了コードは信用しない——設定に失敗しても成功に見えることがあるので、
/// 掛けた保護が本当に掛かったかは**別の口で読み直して**確かめる。
fn owner_and_foreign_write_dac(path: &Path) -> Result<(String, usize), String> {
    let script = format!(
        "$acl = Get-Acl -LiteralPath '{}'; \
         Write-Output ('OWNER=' + $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value); \
         $bad = @($acl.Access | Where-Object {{ \
             ((([int]$_.FileSystemRights) -band {WRITE_DAC_MASK}) -ne 0) -and \
             ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne '{LOCAL_SYSTEM_SID}') }}).Count; \
         Write-Output ('WRITEDAC_OTHERS=' + $bad)",
        path.display()
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| format!("failed to read the ACL of {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let field = |key: &str| -> Result<String, String> {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
            .ok_or_else(|| format!("could not read {key} for {} from: {text}", path.display()))
    };
    let owner = field("OWNER=")?;
    let holders = field("WRITEDAC_OTHERS=")?.parse::<usize>().map_err(|e| {
        format!(
            "could not parse WRITEDAC_OTHERS for {}: {e}",
            path.display()
        )
    })?;
    Ok((owner, holders))
}

/// `dir`を**合成のシステム保護パス**に変える。戻り値の`Drop`が元へ戻す。
///
/// 掛けるのは3手で、どれが欠けても「昇格が要る」状態にならない。
///
/// 1. 継承ACEを落とす（`/inheritance:r`）——親から降りてくるフルコントロールを消す
/// 2. LocalSystemへフルコントロール、**このユーザーへはModify**（`WRITE_DAC`を渡さない）
/// 3. 所有者をLocalSystemにする——**所有者には`WRITE_DAC`が暗黙に付く**ので、
///    自分が所有者のままだと2をやっても書けてしまう
///
/// 3手を掛けたあと、**掛かったことを別の口（`Get-Acl`）で読み直して確かめる**。
///
/// # なぜユーザー側を`(RX)`ではなく`(M)`にするか（**計器で軸を潰さないため**）
///
/// AppContainerの判定は**ユーザー側とcapability側の両方**が許して初めて通る（DACLは
/// 片方だけでは開かない）。ユーザー側を`(RX)`にすると、子は**何をトークンへ積んでいても**
/// このディレクトリへ書けなくなる——つまり`HARD_WRITE=DENIED`は保護の掛け方だけで確定し、
/// 「宣言した級（`read_exec`）で開いたから書けない」の証拠にならない。それは
/// 本ケースが測りたい軸（**級**）を計器の側で潰している状態である。
///
/// `Modify`（`0x301BF`）は`WRITE_DAC`（`0x40000`）を**含まない**ので、DACLの書込は
/// 依然`ACCESS_DENIED`のまま＝`needs_elevation`へ入る性質は変わらず、下の
/// 「非SYSTEMで`WRITE_DAC`を持つACEは0本」の検算も変わらない。**変わるのは、
/// 書込の可否を決めるのがcapability側だけになることである。**
fn harden_as_system_protected(dir: &Path) -> Result<SystemProtectedDir, String> {
    let user_sid = harness_sandbox::win_pipe_ipc::current_user_sid_string()
        .map_err(|e| format!("could not resolve the current user SID: {e}"))?;
    let guard = SystemProtectedDir {
        path: dir.to_path_buf(),
        restore_owner_sid: user_sid.clone(),
    };
    let system_full = format!("*{LOCAL_SYSTEM_SID}:(OI)(CI)(F)");
    // `(M,WO)`＝Modify ＋ `WRITE_OWNER`。**`WRITE_DAC` は含まない**（下のコメントを参照）。
    let user_modify = format!("*{user_sid}:(OI)(CI)(M,WO)");
    // **所有者は`BUILTIN\Administrators`にする**（SYSTEMではない。理由は
    // [`BUILTIN_ADMINISTRATORS_SID`]のdoc——SYSTEMへ渡すには`SeRestorePrivilege`が要り、
    // 昇格して走らせても`icacls`は拒否される。実測済み）。
    let system_owner = format!("*{LOCAL_SYSTEM_SID}");
    // **順序と、ユーザーへ残す権利の両方が要る。3通り試して分かった**
    // （`plans/mac-spike/RESULTS.md` §S44）。
    //
    // - `/setowner` を**最後**に撃つと `ACCESS_DENIED`——`(M)` に `WRITE_OWNER` が含まれないため
    // - `/setowner` を**最初**に撃つと、所有者がSYSTEMになった後の `/grant` が `ACCESS_DENIED`
    //   ——`/inheritance:r` でDACLが空になり、こちらはもう所有者ではないため
    //
    // **どちらの順序でも詰む。** 抜け道は「ユーザーへ `WRITE_OWNER` を残したままDACLを固め、
    // 最後に所有権を渡す」ことである。`(M,WO)` は `WRITE_OWNER` を含み **`WRITE_DAC` は含まない**ので、
    // 「素ではDACLを書けない＝昇格の枝へ入る」という本ケースの前提は保たれる。
    icacls_on(dir, &["/inheritance:r"], "drop inherited ACEs")?;
    icacls_on(dir, &["/grant", system_full.as_str()], "grant SYSTEM full")?;
    icacls_on(
        dir,
        &["/grant", user_modify.as_str()],
        "grant user modify+WRITE_OWNER",
    )?;
    icacls_on(
        dir,
        &["/setowner", system_owner.as_str()],
        "set owner=SYSTEM",
    )?;

    let (owner, foreign_write_dac) = owner_and_foreign_write_dac(dir)?;
    if owner != LOCAL_SYSTEM_SID {
        return Err(format!(
            "the synthetic system-protected directory {} is still owned by {owner} (expected \
             {LOCAL_SYSTEM_SID}); an owner always holds WRITE_DAC implicitly, so the in-process \
             grant would succeed and the measurement would never reach the elevation branch",
            dir.display()
        ));
    }
    if foreign_write_dac != 0 {
        return Err(format!(
            "{} still has {foreign_write_dac} non-SYSTEM ACE(s) carrying WRITE_DAC; the \
             in-process grant would succeed and the measurement would never reach the elevation \
             branch",
            dir.display()
        ));
    }
    Ok(guard)
}

/// このworkspaceが発行した、`declared_path`宛の宣言capabilityの件数（**台帳側の索引**）。
///
/// 実DACLとも、子のトークンとも別の経路で作られる第3の値である（§S38-4・§S40-2）。
fn declaration_capability_count(declared_path: &Path, workspace: &Path) -> usize {
    harness_sandbox::tier2a::workspace_capability::declaration_capability_names(
        declared_path,
        Some(workspace),
    )
    .len()
}

/// `workspace`が`declared_path`を`access`級で宣言したときの**宛先SIDの綴り**。
///
/// # なぜ「書いて読み直す」のか
///
/// SIDを文字列にする口（`win_common::sid_to_string`）は`harness-sandbox`の外へ出ていないので、
/// このプロセスからは綴りを直接作れない。そこで**使い捨てのディレクトリへその宛先SID宛の
/// ACEを1本だけ書き、`Get-Acl`で読み直す**——OSに綴らせるので、SID文字列化を自前で
/// 実装し直す（＝新しい検算を1つ増やす）ことを避けられる。読み終えたらディレクトリごと
/// 消すので、ACEも道連れになる。
///
/// # これで何が測れるようになるか（**級の軸**）
///
/// 実DACLに載っているcapability ACEの綴りを、**テスト側が明示した級**から作った綴りと
/// 突き合わせられる。本数（[`count_sid_aces`]）は級に無関心なので、「宣言した級のもの1件だけ」
/// という白黒条件は本数だけでは判定できない。
///
/// # 限界（同じ場所で言う）
///
/// 突き合わせる2つは`fs_allow_capability_sid`まで遡ると同じ関数である。**級を渡し違える
/// 欠陥は捕まえられるが、その関数自身の導出が取り違えている欠陥は両方を同じだけずらす**
/// （§S38-4と同じ形）。
///
/// # 呼ぶ順序の拘束
///
/// この関数は`fs_allow_capability_sid`経由で**台帳へ発行もする**（冪等だが、未発行なら作る）。
/// したがって「台帳の宣言capabilityが何件か」を見るassertより**後**に呼ぶこと——先に呼ぶと、
/// 測定対象の実行が発行し損ねていても件数が揃ってしまう。
fn capability_sid_text(
    workspace: &Path,
    declared_path: &Path,
    access: harness_sandbox::FsAccess,
    probe_tag: &str,
) -> Result<String, String> {
    let probe = fs_allow_case_dir(&format!("elev-cal-{probe_tag}"));
    let read_back = (|| -> Result<String, String> {
        let sid = harness_sandbox::tier2a::win_appcontainer::fs_allow_capability_sid(
            workspace,
            declared_path,
            access,
        )
        .map_err(|e| {
            format!(
                "could not derive the {} subject for {}: {e}",
                access.label(),
                declared_path.display()
            )
        })?;
        harness_sandbox::tier2a::win_appcontainer::grant_ace_scoped(
            &probe,
            sid.as_psid(),
            access,
            harness_policy::GrantScope::Object,
        )
        .map_err(|e| {
            format!(
                "could not write the calibration ACE for the {} subject of {} onto {}: {e}",
                access.label(),
                declared_path.display(),
                probe.display()
            )
        })?;
        match sid_aces(&probe, "S-1-15-3-")?.as_slice() {
            [only] => Ok(only.clone()),
            other => Err(format!(
                "the calibration directory {} carries {} capability ACE(s) after writing exactly \
                 one; the spelling of the {} subject cannot be read out of it",
                probe.display(),
                other.len(),
                access.label()
            )),
        }
    })();
    let _ = std::fs::remove_dir_all(&probe);
    read_back
}

/// `--force-system-acl`で書いた付与が**実際に載って台帳へ`forced`として記録された**ときに
/// `run_agent.rs`が出す警告の頭。**子の到達性とは独立な印**である。
///
/// これを見ないと、`HARD_READ=DENIED`が「運ぶ宛先SIDと付いた宛先SIDが違う」なのか
/// 「そもそもACEが1本も載らなかった」なのかが出力から分かれない。
const FORCED_GRANT_MARKER: &str = "WARNING: forced system ACL grant (--force-system-acl";

/// 部分適用（rootにはACEが載ったが子孫のどれかで失敗した）のときに`preflight`が積む警告。
/// **これが出ていたら、子が読めないのは宛先SIDの取り違えではなく伝播の失敗である。**
const PARTIAL_APPLY_MARKER: &str = "partially applied";

/// 失敗を1件積む。**その場で打ち切らない**（理由は[測定7]の本体のdoc「最初の失敗で
/// 打ち切らない」）。積むと同時にstderrへも出すのは、まとめて返す1本のエラー文よりも
/// 「何番目の検査が落ちたか」を追いやすくするためである。
fn record_failure(failed: &mut Vec<String>, message: String) {
    eprintln!(
        "[fs-allow-elev] FAILED CHECK #{}: {message}",
        failed.len() + 1
    );
    failed.push(message);
}

/// [測定7] **昇格が要るシステム保護パスでも、開くのは宣言した1件だけである。**
///
/// # 3本の腕を同じケースに混ぜる
///
/// | 腕 | 対象 | 期待 | これが崩れると何が言えなくなるか |
/// |---|---|---|---|
/// | **失敗するはず** | 保護パス、`--force-system-acl`**無し** | 付与が拒否され、capability ACEは0本 | 保護が効いていない＝以降の「昇格が要った」は根拠を失う（計器の較正） |
/// | **成功するはず（昇格側）** | 同じ保護パス、`--force-system-acl`**あり** | 付与が通り、capability ACEが**ちょうど1本** | — |
/// | **成功するはず（非昇格側）** | 普通のパス、同じ1回 | 同上 | 落ちたときに「昇格の枝のせい」か「仕掛け全体のせい」かが切り分けられない |
///
/// 1本目と2本目は**同じオブジェクトに対して`--force-system-acl`の有無だけが違う**。したがって
/// 2本目の成功は`SeRestorePrivilege`を有効にした付与でしか説明できず、その経路は
/// `needs_elevation`の内側にしか無い。**「昇格の枝を通った」の根拠はこの対である。**
///
/// # 歯の対照（広い側）を先に置く
///
/// 各対象へ**先に`read_write`級のcapabilityを発行しておく**。これが無いと「capability ACEが
/// 1本だけ」は絞り込みの証拠ではなく、**そもそも候補が1つしか無かっただけ**になる（§S40-2）。
/// 発行だけでACEは書かないので、1本になるのは`preflight`が級を選んでいるからである。
///
/// # 級の軸は「本数」では測れない（**2つの半分を別々に固定する**）
///
/// 白黒条件は「宣言した**級**のもの1件だけ」であって「1件だけ」ではない。本数
/// （[`count_sid_aces`]）は級に無関心なので、**宣言の級ではなく広い側の宛先SIDで1本書く**
/// 欠陥——移行前の「広い側を積む」形がこの枝にだけ残っている状態——を素通りさせる。
/// そこで級を2つの半分に分けて別々に固定する。
///
/// 1. **宛先SIDの級**: 実DACLに載った綴りを、テスト側が`read_exec`と明示して作った綴りと
///    突き合わせる（[`capability_sid_text`]）。広い側の綴りも同時に作り、**そちらと一致したら
///    名指しで言う**
/// 2. **書いたマスクの級**: 宣言は読取専用なので子は書けないはず。これが計器で潰れないように、
///    合成の保護パスはユーザー側を`(M)`にしてある（[`harden_as_system_protected`]）——
///    `(RX)`だと**capability側が何であっても**書けず、`HARD_WRITE=DENIED`が級の証拠に
///    ならない。同じ理由で非昇格側（soft）にも`SOFT_WRITE`の腕を置く
///
/// # 突き合わせる3つ
///
/// 運ぶ側（子の到達性）・付ける側（実DACL）・**台帳の索引**（宣言capabilityの件数）。前2つは
/// 同じ導出から出るので上流の欠陥では**両方が同じだけずれる**（§S38-4）。台帳は別経路である。
///
/// # 最初の失敗で打ち切らない
///
/// このケースは**運ぶ側（子のトークン）と付ける側（実DACL）を分けて読む**ために在るが、
/// 最初の`Err`で返ると**どの仕込みでも出力は「子が読めない」の1行だけ**になり、分離が
/// 原理的に起きない。だから各assertの結果を積んで最後にまとめて返す（[`record_failure`]）。
/// 読み分けの表は`plans/handoff/issue20-measure/D.md`にある。
fn fs_allow_case_the_elevated_grant_opens_only_the_declared_subject(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    // **昇格していなければ、この測定は成立しない。** 非昇格で走ると保護パスの用意
    // （所有者の変更）から失敗するが、そこで初めて気付くと「何を測ろうとして失敗したか」が
    // 読めない。走らせる前に名指しで落とす（`B-33`: 走らなかったことを緑にしない）。
    if !harness_sandbox::tier2a::privhelper::is_elevated() {
        return Err(
            "this case must run elevated (it builds a synthetic system-protected directory by \
             changing its owner to LocalSystem). Run it through \
             `dev-elevated-run.exe e2e-fs-allow`, not a bare `cargo test`."
                .to_string(),
        );
    }

    // **前の実行が保護を掛け損ねて残したディレクトリを、先に掃く。** 非昇格では消せない形で
    // 残るので、昇格して走るこのケースが自分で片付ける（理由は関数のdoc）。
    sweep_stale_fs_allow_protected_dirs();

    let ws = case_dir("fs-allow-elev");
    let ws_canon = ws.canonicalize().unwrap_or_else(|_| ws.clone());

    // 保護しない側（成功対照）と、宣言しない側（禁止対照）。
    let soft = fs_allow_case_dir("elev-soft");
    let outside = fs_allow_case_dir("elev-out");
    std::fs::write(soft.join("secret.txt"), "soft-readable").map_err(|e| e.to_string())?;
    // **ラベルではなく中身そのもの**を探すことで、「拒否された」と「空を読めた」を区別せずに
    // 『子へ渡っていない』だけを固定できる（`fs_allow_case_bare_path_grants_the_object_only`と同型）。
    std::fs::write(outside.join("secret.txt"), "outside-must-not-leak")
        .map_err(|e| e.to_string())?;

    let hard_dir = fs_allow_case_dir("elev-hard");
    std::fs::write(hard_dir.join("secret.txt"), "hard-readable").map_err(|e| e.to_string())?;
    // ここから先、`hard`が生きている間だけ保護が掛かる（`Drop`で戻す）。
    let hard = harden_as_system_protected(&hard_dir)?;
    let hard_path = hard.path().to_path_buf();

    // **ここから先は最初の失敗で打ち切らない。** 積んだものは後始末を通してから1本に
    // まとめて返す（このケースのdoc「最初の失敗で打ち切らない」）。
    let mut failed: Vec<String> = Vec::new();

    // --- 歯の対照（広い側）を先に発行する。ACEは書かない ---
    for target in [&hard_path, &soft] {
        match harness_sandbox::tier2a::win_appcontainer::fs_allow_capability_sid(
            &ws_canon,
            target,
            harness_sandbox::FsAccess::ReadWrite,
        ) {
            Ok(_) => {
                if declaration_capability_count(target, &ws_canon) != 1 {
                    record_failure(
                        &mut failed,
                        format!(
                            "the wider declaration capability for {} was not minted, so \"only \
                             one capability ACE\" below would not be evidence of narrowing -- it \
                             would just mean there was never a second candidate",
                            target.display()
                        ),
                    );
                }
            }
            Err(e) => record_failure(
                &mut failed,
                format!(
                    "could not mint the wider (read_write) declaration capability for {}: {e}",
                    target.display()
                ),
            ),
        }
    }

    // --- 腕1: 失敗するはず（保護パス、--force-system-acl 無し） ---
    let hard_allow = format!(r"{}\**", hard_path.display());
    let run_no_force = run_harness(
        &ws,
        &run_shell_script_turns("Write-Output 'ran'"),
        &["--fs-allow", &hard_allow],
        "fs-allow-elev-noforce",
    );
    if let Err(e) = parse_json_stdout(&run_no_force) {
        record_failure(
            &mut failed,
            format!(
                "arm 1 (the same object without --force-system-acl) did not produce a readable \
                 run: {e}"
            ),
        );
    }
    if !run_no_force.stderr.contains("ACE grant failed") {
        record_failure(
            &mut failed,
            format!(
                "without --force-system-acl the grant on the synthetic system-protected path \
                 {} was expected to be refused, but harness did not report a failed ACE grant. \
                 The protection is not doing anything, so the arms below cannot be read as \
                 \"the elevation branch made the difference\". stderr: {}",
                hard_path.display(),
                run_no_force.stderr
            ),
        );
    }
    match count_sid_aces(&hard_path, "S-1-15-3-") {
        Ok(0) => {}
        Ok(leaked) => record_failure(
            &mut failed,
            format!(
                "{} carries {leaked} capability ACE(s) after the refused grant; a declaration \
                 that was not granted must not leave a subject behind",
                hard_path.display()
            ),
        ),
        Err(e) => record_failure(
            &mut failed,
            format!(
                "could not read the capability ACEs of {} after the refused grant: {e}",
                hard_path.display()
            ),
        ),
    }
    // **落ちた場所が「DACLの書込」であることを固定する。** 宣言の解釈や正規化の手前で
    // 落ちていたなら宛先SIDは発行されない——発行されているなら、失敗はACEを書く段である
    // （`plans/etw-spike/RESULTS.md` §21.4「ゲートがどこにあるかを先に確かめる」）。
    let minted = declaration_capability_count(&hard_path, &ws_canon);
    if minted < 2 {
        record_failure(
            &mut failed,
            format!(
                "the refused declaration for {} minted {minted} capability names (expected the \
                 pre-minted read_write plus this run's read_exec); the run failed before it ever \
                 tried to write a DACL, so it does not show that the write is what was denied",
                hard_path.display()
            ),
        );
    }

    // --- 腕2+3: 成功するはず（保護パスは昇格の枝／普通のパスは非昇格の枝、同じ1回） ---
    //
    // **書込の腕を両側に置く。** 宣言は`read_exec`なので、どちらのパスでも子は書けない
    // はずである。保護パス側はユーザー側を`(M)`にしてあるので（[`harden_as_system_protected`]）、
    // ここでの拒否は**capability側＝宣言した級**にしか帰属しない。
    let soft_allow = format!(r"{}\**", soft.display());
    let hard_p = hard_path.display().to_string().replace('\\', "/");
    let soft_p = soft.display().to_string().replace('\\', "/");
    let out_p = outside.display().to_string().replace('\\', "/");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ $r = Get-Content -LiteralPath '{hard_p}/secret.txt' -Raw -ErrorAction Stop; \
           Write-Output ('HARD_READ=' + $r) }} catch {{ Write-Output 'HARD_READ=DENIED' }}; \
         try {{ Set-Content -LiteralPath '{hard_p}/written.txt' -Value 'x' -ErrorAction Stop; \
           Write-Output 'HARD_WRITE=OK' }} catch {{ Write-Output 'HARD_WRITE=DENIED' }}; \
         try {{ $r = Get-Content -LiteralPath '{soft_p}/secret.txt' -Raw -ErrorAction Stop; \
           Write-Output ('SOFT_READ=' + $r) }} catch {{ Write-Output 'SOFT_READ=DENIED' }}; \
         try {{ Set-Content -LiteralPath '{soft_p}/written.txt' -Value 'x' -ErrorAction Stop; \
           Write-Output 'SOFT_WRITE=OK' }} catch {{ Write-Output 'SOFT_WRITE=DENIED' }}; \
         try {{ $r = Get-Content -LiteralPath '{out_p}/secret.txt' -Raw -ErrorAction Stop; \
           Write-Output ('OUT_READ=' + $r) }} catch {{ Write-Output 'OUT_READ=DENIED' }}; \
         Write-Output 'PROBE_DONE'"
    );
    let run = run_harness(
        &ws,
        &run_shell_script_turns(&script),
        &[
            "--fs-allow",
            &hard_allow,
            "--fs-allow",
            &soft_allow,
            "--force-system-acl",
        ],
        "fs-allow-elev",
    );
    // 子が**返した**stdoutだけを見る（BUG-137）。JSON全体だと、子へ**渡した**スクリプト本文が
    // `HARD_WRITE=DENIED`等をリテラルで含むので、判定が子の挙動と無関係に真になる。
    let outcome_json = parse_json_stdout(&run);
    let text: Option<String> = match &outcome_json {
        Ok(json) => match json.first_tool_result() {
            Ok(t) => Some(t.to_string()),
            Err(e) => {
                record_failure(
                    &mut failed,
                    format!("the granting run produced no tool result to read: {e}"),
                );
                None
            }
        },
        Err(e) => {
            record_failure(
                &mut failed,
                format!("the granting run did not produce a readable outcome: {e}"),
            );
            None
        }
    };

    // --- 付ける側（実DACL）を先に読む ---
    //
    // **子の到達性より前に置く。** 「運ぶ側だけ壊す」仕込みと「付ける側だけ壊す」仕込みは
    // どちらも子が読めなくなるので、実DACLを独立に読まないと出力から分かれない。
    for (tag, target, arm) in [
        (
            "hard",
            &hard_path,
            "the elevated (SeRestorePrivilege) branch",
        ),
        ("soft", &soft, "the in-process (non-elevated) control"),
    ] {
        let found = match sid_aces(target, "S-1-15-3-") {
            Ok(found) => Some(found),
            Err(e) => {
                record_failure(
                    &mut failed,
                    format!(
                        "could not read the capability ACEs of {} ({arm}): {e}",
                        target.display()
                    ),
                );
                None
            }
        };
        if let Some(found) = found.as_ref() {
            if found.len() != 1 {
                record_failure(
                    &mut failed,
                    format!(
                        "{} carries {} capability ACE(s) ({arm}); exactly one is required. Two \
                         access classes exist for this declaration in the ledger (the pre-minted \
                         read_write and this run's read_exec), so anything other than 1 means the \
                         grant path did not pick a single declared subject (§22.3.4). On the \
                         DACL: {found:?}",
                        target.display(),
                        found.len()
                    ),
                );
            }
        }
        // [§22.3.0] 移行の不変条件を**昇格の枝でも**測る。1本でも残っていれば、その1本が
        // 同一セッションの全ドメインへこのパスを開き続ける（DACLはANDを表現できない）。
        match count_sid_aces(target, "S-1-15-2-") {
            Ok(0) => {}
            Ok(package) => record_failure(
                &mut failed,
                format!(
                    "§22.3.0: {} still carries {package} package-SID ACE(s) after the grant ({arm})",
                    target.display()
                ),
            ),
            Err(e) => record_failure(
                &mut failed,
                format!(
                    "could not read the package-SID ACEs of {} ({arm}): {e}",
                    target.display()
                ),
            ),
        }
        // **葉まで届いたか。** 宣言は`<path>\**`（配下まで）なので、子が読む`secret.txt`にも
        // 宛先SIDのACEが要る。ここが0本なら、子が読めない原因は宛先SIDの取り違えではなく
        // **rootだけ載って伝播しなかった**（部分適用）である。本数ではなく**0か否か**で見るのは、
        // 継承ACEと子孫救済walkの明示ACEが両方載る形があり得るため。
        let leaf = target.join("secret.txt");
        match count_sid_aces(&leaf, "S-1-15-3-") {
            Ok(0) => record_failure(
                &mut failed,
                format!(
                    "{} carries no capability ACE ({arm}); the declaration was `<path>\\**`, so \
                     the ACE has to reach the file the child actually reads. A `READ=DENIED` \
                     below is then a propagation failure, not a mismatched subject",
                    leaf.display()
                ),
            ),
            Ok(_) => {}
            Err(e) => record_failure(
                &mut failed,
                format!(
                    "could not read the capability ACEs of {} ({arm}): {e}",
                    leaf.display()
                ),
            ),
        }
        // 台帳側（第3の値）。広い側が消えずに残っていること＝1本だったのは絞り込みの結果である。
        let names = declaration_capability_count(target, &ws_canon);
        if names != 2 {
            record_failure(
                &mut failed,
                format!(
                    "{} has {names} declaration capabilities in the ledger (expected 2: the \
                     pre-minted read_write and this run's read_exec). Without the second one, \
                     \"exactly one ACE\" is not evidence that a class was chosen",
                    target.display()
                ),
            );
        }
        // --- 級の軸（**本数では言えないほう**） ---
        // **台帳の件数を見た後で呼ぶ**（[`capability_sid_text`]は発行もするので、先に呼ぶと
        // 上の`names != 2`が「この測定が発行したぶん」で埋まってしまう）。
        match (
            capability_sid_text(
                &ws_canon,
                target,
                harness_sandbox::FsAccess::ReadExec,
                &format!("{tag}-ro"),
            ),
            capability_sid_text(
                &ws_canon,
                target,
                harness_sandbox::FsAccess::ReadWrite,
                &format!("{tag}-rw"),
            ),
        ) {
            (Ok(declared), Ok(wider)) => {
                // **1本も載っていない回では級を問わない**——上の本数のassertが既に言っており、
                // 同じ事実で2本赤くすると「級が違う」と「1本も無い」が読み分けられなくなる。
                if let Some(found) = found.as_ref().filter(|found| !found.is_empty()) {
                    if !found.iter().any(|sid| sid.eq_ignore_ascii_case(&declared)) {
                        let widened = found.iter().any(|sid| sid.eq_ignore_ascii_case(&wider));
                        record_failure(
                            &mut failed,
                            format!(
                                "the capability ACE(s) on {} ({arm}) are {found:?}, but this run \
                                 declared read_exec, whose subject is {declared}.{}",
                                target.display(),
                                if widened {
                                    format!(
                                        " What is on the DACL is {wider} -- the wider \
                                         (read_write) subject of the same declaration. That is \
                                         the pre-migration \"put the wider class on the path\" \
                                         shape surviving in this branch (§22.3.4)."
                                    )
                                } else {
                                    String::new()
                                }
                            ),
                        );
                    }
                }
            }
            (declared, wider) => {
                for outcome in [declared, wider] {
                    if let Err(e) = outcome {
                        record_failure(
                            &mut failed,
                            format!(
                                "could not read back the spelling of a declaration subject for \
                                 {} ({arm}), so the class of the ACE that landed cannot be \
                                 judged: {e}",
                                target.display()
                            ),
                        );
                    }
                }
            }
        }
    }

    // --- 昇格の枝が実際に走ってACEを載せたか（**子の到達性とは独立な印**） ---
    //
    // `run_agent.rs`はforcedで載った付与にだけこの警告を出す。保護パスは素の書込が
    // 通らないので、ここに出る＝`needs_elevation`の内側で書けた、と読める。
    let hard_leaf = hard_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mentions_hard =
        |line: &&str, marker: &str| line.contains(marker) && line.contains(hard_leaf.as_str());
    if !run
        .stderr
        .lines()
        .any(|l| mentions_hard(&l, FORCED_GRANT_MARKER))
    {
        record_failure(
            &mut failed,
            format!(
                "harness never reported a forced (SeRestorePrivilege) grant for {}, so nothing \
                 says an ACE was written and recorded through the elevation branch at all. A \
                 reachability failure below must then be read as \"no ACE\", not as \"the wrong \
                 subject\". stderr: {}",
                hard_path.display(),
                run.stderr
            ),
        );
    }
    if run
        .stderr
        .lines()
        .any(|l| mentions_hard(&l, PARTIAL_APPLY_MARKER))
    {
        record_failure(
            &mut failed,
            format!(
                "the grant on {} was only partially applied (the root carries the ACE but some \
                 descendant failed), so this run cannot be read as \"the elevation branch \
                 completed\". stderr: {}",
                hard_path.display(),
                run.stderr
            ),
        );
    }

    // --- 運ぶ側（子のトークン＝到達性と級） ---
    if let Some(text) = text.as_deref() {
        // `B-12`型の穴を塞ぐ: 最後まで到達したことを先に確かめてから「拒否された」を主張する。
        if !text.contains("PROBE_DONE") {
            record_failure(
                &mut failed,
                format!(
                    "the probe script did not reach its last line, so none of its DENIED \
                     outcomes can be read as \"the sandbox refused it\": {text}"
                ),
            );
        } else {
            // 昇格側の腕（本題）。**どこが壊れているかはここでは名乗らない**——同じ症状に
            // なる原因が3つあり（運ぶ側／付ける側／伝播）、分けるのは上の実DACL側の検査である。
            if !text.contains("HARD_READ=hard-readable") {
                record_failure(
                    &mut failed,
                    format!(
                        "the declaration on the system-protected path went through the elevation \
                         branch, but the child could not read it. Read this together with the \
                         DACL checks above: an ACE of the declared class on both the root and \
                         the leaf means the subject carried into the child's token is the one \
                         that does not match (§22.3): {text}"
                    ),
                );
            }
            // 非昇格側の腕（成功対照）。ここが落ちたら原因は昇格の枝ではなく仕掛け全体である。
            if !text.contains("SOFT_READ=soft-readable") {
                record_failure(
                    &mut failed,
                    format!(
                        "the control arm (an ordinary, writable path declared in the same run) \
                         was not reachable either, so the elevated arm's outcome says nothing \
                         about the elevation branch: {text}"
                    ),
                );
            }
            // 禁止側。宣言していないものは開かない。
            if text.contains("outside-must-not-leak") {
                record_failure(
                    &mut failed,
                    format!(
                        "the child read the contents of a path that was never declared in this \
                         run; the subjects carried into the token are wider than the \
                         declarations: {text}"
                    ),
                );
            }
            // 級の側（宣言は`read_exec`＝読めて書けない）。**両方の腕で見る**——保護パスは
            // ユーザー側を`(M)`にしてあるので、どちらの拒否もcapability側にしか帰属しない。
            for (probe, target) in [("HARD_WRITE", &hard_path), ("SOFT_WRITE", &soft)] {
                if !text.contains(&format!("{probe}=DENIED")) {
                    record_failure(
                        &mut failed,
                        format!(
                            "the declaration on {} was read_exec, but the child reported that it \
                             could write into it ({probe}); the mask that was actually written is \
                             wider than the declared class: {text}",
                            target.display()
                        ),
                    );
                }
            }
        }
    }
    // **「禁止された」は必ず実体でも確かめる**——子が「拒否された」と言ったこととファイルが
    // 無いことは別の事実である（`B-09`）。子の出力が読めなかった回でも、これは見られる。
    for target in [&hard_path, &soft] {
        if target.join("written.txt").exists() {
            record_failure(
                &mut failed,
                format!(
                    "the child actually wrote into {} even though the declaration was read_exec",
                    target.display()
                ),
            );
        }
    }

    // --- 名前の付いた扉が、昇格して書いたACEも剥がせること（対の片方を残さない、`B-01`） ---
    // forcedで書いたACEの撤収も`SeRestorePrivilege`が要る（台帳の`forced`欄がその索引）。
    for target in [&hard_path, &soft] {
        match Command::new(harness_exe())
            .args(["fs", "revoke"])
            .arg(target)
            .output()
        {
            Ok(revoke) => {
                eprintln!(
                    "[fs-allow-elev] fs revoke {} -> {} {}",
                    target.display(),
                    revoke.status,
                    String::from_utf8_lossy(&revoke.stdout).trim()
                );
                if !revoke.status.success() {
                    record_failure(
                        &mut failed,
                        format!(
                            "`harness fs revoke {}` failed: {}{}",
                            target.display(),
                            String::from_utf8_lossy(&revoke.stdout),
                            String::from_utf8_lossy(&revoke.stderr)
                        ),
                    );
                }
                match count_sid_aces(target, "S-1-15-3-") {
                    Ok(0) => {}
                    Ok(left) => record_failure(
                        &mut failed,
                        format!(
                            "{} still carries {left} capability ACE(s) after `harness fs revoke`; \
                             a grant written through the elevation branch must be removable \
                             through the named door",
                            target.display()
                        ),
                    ),
                    Err(e) => record_failure(
                        &mut failed,
                        format!(
                            "could not read the capability ACEs of {} after `harness fs revoke`: \
                             {e}",
                            target.display()
                        ),
                    ),
                }
            }
            Err(e) => record_failure(
                &mut failed,
                format!(
                    "failed to run `harness fs revoke {}`: {e}",
                    target.display()
                ),
            ),
        }
    }

    // **後始末は成否に関わらず通す。** 台帳（fs passthroughの`entries`/`denied_entries`・
    // 宣言capability・workspace grant）を測定前の形へ戻さないと、次の測定の前後差に混ざる
    // （§S39-6）。`hard`の保護解除と削除は`Drop`が行う。
    ledger.purge_entries(&[&hard_path, &soft, &outside]);
    let dropped = harness_sandbox::tier2a::workspace_capability::forget_capability(&ws_canon, "");
    eprintln!(
        "[fs-allow-elev] dropped {} capability ledger entries for {}",
        dropped.len(),
        ws_canon.display()
    );
    harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&ws_canon);
    let _ = std::fs::remove_dir_all(&soft);
    let _ = std::fs::remove_dir_all(&outside);
    drop(hard);

    // **落ちた検査を全部まとめて返す。** 1件目で返すと、この測定が分けたい2つ（運ぶ側と
    // 付ける側）がどの仕込みでも同じ1行になる。
    if !failed.is_empty() {
        return Err(format!(
            "{} of the checks in this case failed (each is listed in full; they are independent, \
             so read them together): {}",
            failed.len(),
            failed
                .iter()
                .enumerate()
                .map(|(i, m)| format!("[{}] {m}", i + 1))
                .collect::<Vec<_>>()
                .join(" || ")
        ));
    }
    // **このケースは`harness.exe`を2回起こす**ので、スクラッチも2つ分ある（片方だけ消すと
    // `_scratch`へ台本と記録が残り続ける）。
    cleanup_on_success(&ws, &[], "fs-allow-elev-noforce");
    cleanup_on_success(&ws, &[], "fs-allow-elev");
    Ok(())
}

/// [BUG-014] **Visual Studio検出用DLLを、宣言1つで読めるようにできるか。**
///
/// # 何を測るのか
///
/// AppContainerの中でビルドすると、rustcのVisual Studio自動検出が失敗し、
/// フォールバックの「素の名前でのPATH解決」が**MSYS2の同名コマンド**を掴んでクラッシュする。
/// 検出が失敗する理由は1つで、**検出用DLLが置かれたディレクトリにAppContainer宛のACEが無い**
/// ——`C:\ProgramData\Microsoft\VisualStudio\Setup`には`ALL APPLICATION PACKAGES`が付いていない。
///
/// 当時（2026-07-22）は`--fs-allow`でこれを開こうとして`0x80070005`で失敗した。理由は
/// **`--fs-allow`のACE付与が特権分離ヘルパーを経由していなかった**ことで、システム保護パスへは
/// 常に無言で失敗していた。この欠陥は[BUG-015](../../../docs/bugs/BUG-015.md)で直っている。
///
/// **つまりこのケースは「当時の一般解が、いまなら成立するか」を測る。**
///
/// # 測るのは読めるかどうかだけである（**ビルドまで回さない**）
///
/// 「宣言すればビルドが通る」までを1本のテストで測ろうとすると、サンドボックスの中で
/// Rustツールチェーン一式（`~/.cargo`・`~/.rustup`・MSVC・Windows SDK）を開く必要があり、
/// **落ちたときにどれが原因か分けられない**。ここで測るのは
/// [BUG-014](../../../docs/bugs/BUG-014.md)が名指しした機構——**検出用DLLへ届くか**——だけである。
///
/// 「届けばビルドも通る」は**測っていない**。記録にそう書く。
///
/// # マシンに何を残すか
///
/// 測定中だけ、実在のシステムディレクトリへ宣言capability宛のACEが1本増える。
/// **読取のみ**で、このケースの最後に`harness fs revoke`で撤収し、撤収できたことまで確かめる。
/// 対象のファイルには一切書き込まない（読むだけ）。
fn fs_allow_case_the_visual_studio_detection_dll_can_be_opened(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    const SETUP_DIR: &str = r"C:\ProgramData\Microsoft\VisualStudio\Setup";
    let dll = Path::new(SETUP_DIR)
        .join("x64")
        .join("Microsoft.VisualStudio.Setup.Configuration.Native.dll");
    if !dll.exists() {
        // **この機にVisual Studioが入っていないなら、測る対象が無い。**
        // 「読めなかった」と混同しないよう、ここで明示的に抜ける（`B-10`）。
        eprintln!(
            "[fs-allow-vsdetect] skipped: {} does not exist on this machine",
            dll.display()
        );
        return Ok(());
    }
    let dll_for_script = dll.display().to_string().replace('\\', "/");
    // 読めたかどうかだけを見る。**中身は出さない**（760KBのバイナリで、しかも診断に要らない）。
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         try {{ $s = [System.IO.File]::OpenRead('{dll_for_script}'); \
           $n = $s.Length; $s.Close(); Write-Output ('DLL=OPENED len=' + $n) }} \
         catch {{ Write-Output 'DLL=DENIED' }}"
    );

    // --- 腕1（対照）: 宣言しない。**届かないはず。** ---
    let ws_without = case_dir("fs-allow-vsdetect-without");
    let without = run_harness(
        &ws_without,
        &run_shell_script_turns(&script),
        &[],
        "fs-allow-vsdetect-without",
    );
    let without_json = parse_json_stdout(&without)?;
    let without_text = without_json.first_tool_result()?.to_string();

    // --- 腕2: 同じ台本を、宣言1つだけ足して撃つ ---
    let ws_with = case_dir("fs-allow-vsdetect-with");
    let allow = format!(r"{SETUP_DIR}\**");
    let with = run_harness(
        &ws_with,
        &run_shell_script_turns(&script),
        &["--fs-allow", &allow],
        "fs-allow-vsdetect-with",
    );
    let with_json = parse_json_stdout(&with)?;
    let with_text = with_json.first_tool_result()?.to_string();

    eprintln!("[fs-allow-vsdetect] 宣言なし = {}", without_text.trim());
    eprintln!("[fs-allow-vsdetect] 宣言あり = {}", with_text.trim());

    // --- 撤収を先に済ませる。**判定で早期returnしても、マシンに残さない。** ---
    let revoke = Command::new(harness_exe())
        .args(["fs", "revoke"])
        .arg(SETUP_DIR)
        .output()
        .map_err(|e| format!("failed to run `harness fs revoke`: {e}"))?;
    eprintln!(
        "[fs-allow-vsdetect] fs revoke -> {} {}",
        revoke.status,
        String::from_utf8_lossy(&revoke.stdout).trim()
    );
    let left = count_sid_aces(Path::new(SETUP_DIR), "S-1-15-3-").unwrap_or(usize::MAX);
    ledger.purge_entries(&[Path::new(SETUP_DIR)]);

    // --- 判定 ---
    let mut failed: Vec<String> = Vec::new();
    if !with_text.contains("DLL=OPENED") {
        failed.push(format!(
            "[BUG-014] declaring `{allow}` did not make the Visual Studio detection DLL readable \
             from inside Tier2a. The generalisation that BUG-014 left open depends on this exact \
             grant working (it could not in 2026-07, because `--fs-allow` did not go through the \
             privilege-separation helper -- BUG-015 fixed that). got: {with_text}"
        ));
    }
    if !without_text.contains("DLL=DENIED") {
        failed.push(format!(
            "[BUG-014] the control arm could already read the DLL **without** declaring anything, \
             so the arm above proves nothing about the declaration. Either this machine grants \
             AppContainers access to that tree by default, or a previous grant was left behind. \
             got: {without_text}"
        ));
    }
    if left != 0 {
        failed.push(format!(
            "`harness fs revoke {SETUP_DIR}` left {left} declaration-capability ACE(s) on a real \
             system directory. This case must not widen the machine it runs on."
        ));
    }

    if !failed.is_empty() {
        return Err(failed.join(" || "));
    }
    cleanup_on_success(&ws_without, &[], "fs-allow-vsdetect-without");
    cleanup_on_success(&ws_with, &[], "fs-allow-vsdetect-with");
    Ok(())
}

#[test]
#[ignore]
fn tier2a_fs_allow_matrix() {
    // `--fs-allow`は`fs-passthrough-ledger.json`へエントリを足し、各ケースは後始末で
    // そこから自分の分を落とす。**排他ガードはテスト関数の全体で持つ**——ケース単位に縮めると、
    // ケースとケースの間に隣（`tier2a_fs_ledger_lifecycle`）が割り込める。
    let ledger = fs_ledger_exclusive();
    let cases: Vec<(&str, FsLedgerCaseFn)> = vec![
        (
            "ro-reads-but-cannot-write",
            fs_allow_case_ro_reads_but_cannot_write,
        ),
        (
            "rw-write-delete-move",
            fs_allow_case_rw_can_write_delete_and_move,
        ),
        // 上2本は`<path>\**`（配下まで）を宣言する。この1本だけが**素のパス**を宣言し、
        // D-63の本体（オブジェクト単体）を測る。対で置かないと、上2本を`**`付きに
        // 追随させた時点でD-63を誰も測らなくなる（BUG-136）。
        (
            "bare-path-grants-the-object-only",
            fs_allow_case_bare_path_grants_the_object_only,
        ),
        (
            "ace-persists-after-exit-and-the-named-door-removes-it",
            fs_allow_case_the_ace_persists_after_exit_and_the_named_door_removes_it,
        ),
        // [BUG-119] `--force-system-acl`を打った回に、特権が要らなかったパスが
        // `forced`として記録されないこと。**上の4本は`--force-system-acl`を打たない**ので、
        // この腕が唯一その組み合わせを通る。
        (
            "a-normally-grantable-path-is-not-recorded-as-forced",
            fs_allow_case_a_normally_grantable_path_is_not_recorded_as_forced,
        ),
        // [測定7] 昇格が要るシステム保護パスの腕。**上の4本はどれも`preflight`の
        // `needs_elevation`へ入らない**（`C:\`直下の書けるパスなので、その場で書けてしまう）ので、
        // 宛先SIDを持ち回す形へ変えた区間はここが唯一の実行経路である。
        // **最後に置いてある**——所有者をLocalSystemへ移す腕なので、先に置くと前の4本が
        // 落ちたときにその残骸と混ざる。
        (
            "elevated-grant-opens-only-the-declared-subject",
            fs_allow_case_the_elevated_grant_opens_only_the_declared_subject,
        ),
        // [BUG-014] **実在のシステムディレクトリを開く唯一の腕。** 上の腕は自分で作った
        // 保護パスを使うが、こちらは`C:\ProgramData\Microsoft\VisualStudio\Setup`そのものを
        // 測る（当時`0x80070005`で失敗した相手）。**最後に置く**——マシンに元から在る物を
        // 触るので、前の腕が落ちた回にその残骸と混ざらないようにする。
        (
            "the-visual-studio-detection-dll-can-be-opened",
            fs_allow_case_the_visual_studio_detection_dll_can_be_opened,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, || f(&ledger)) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} fs-allow cases passed (see per-case JSON above)"
    );
}

// ============================================================================
// W7: netfilterdからの連鎖起動（追加UACなし経路）をassertにする
//
// `docs/STATUS.md`のOS監査収集器・残課題`a`は「`--policy-learn`＋ドメインポリシー有効の
// 組み合わせで実際にUACが増えないことは未確認」だった。「UACが増えないことを目視で確認」は
// **人間にしか実行できず、再実行も自動検証もできない**。同じ事実を機械的に取り直す。
//
// 経路(A)（netfilterdの昇格トークンから`harness-policy-learnd.exe`を連鎖起動する＝追加UACなし）
// が採られたことは、次の2つと同値である。
//
// 1. 「パイプを用意できなかった」「連鎖先が応答しないので直接起動へフォールバックする」の
//    どちらの警告もstderrに出ていない（`run_agent.rs`のこの2箇所以外に経路(A)を諦める道は無い）
// 2. 収集器が実際に動いて`fs-audit.jsonl`を書いている
//
// `dev-elevated-run.exe e2e-chain-launch`（フィルタ`tier2a_chain_launch`）。

/// 経路(A)を諦めたときに`run_agent.rs`が出す警告。**どちらもstderrに現れてはいけない。**
const CHAIN_LAUNCH_GIVE_UP_MARKERS: &[&str] = &[
    // `prepare_pipe`が失敗した（run_agent.rs、`policy_learn_prelude`）
    "could not prepare the policy-learning pipe",
    // 連鎖先が応答せず`runas`直接起動へ落ちた（UACが1回増える）
    "falling back to launching it directly",
];

/// 既定の書込モード（Live）で経路(A)を通す。
fn chain_launch_case_no_extra_uac_path_is_taken() -> Result<(), String> {
    let ws = case_dir("chain-launch");
    chain_launch_case_in(&ws, &[], "chain-launch")?;
    cleanup_on_success(&ws, &[], "chain-launch");
    Ok(())
}

/// **CoWでも同じ**（D-90でTier2aは常にCoWになる）。監査ログの置き場は書込の捕まえ方に
/// 関係なく作られるので、CoWでも収集器が収集先を持てること。かつてCoWでは置き場が作られず、
/// `--policy-learn`は黙って無効になっていた（D-90 反転の前提(3)）。
fn chain_launch_case_under_cow() -> Result<(), String> {
    let ex = cow_exclusive();
    let ws = case_dir("chain-launch-cow");
    let before = ex.list_cow_sessions();
    chain_launch_case_in(&ws, &["--sandbox", "tier2a-cow"], "chain-launch-cow")?;
    let session = ex.new_cow_session(&before)?;
    cleanup_on_success(&ws, &[&session], "chain-launch-cow");
    Ok(())
}

fn chain_launch_case_in(ws: &Path, mode_args: &[&str], case_name: &str) -> Result<(), String> {
    // 2つとも必要な条件である。
    // - `--net-allow-domain`: ドメインポリシーが無いと`netfilterd`自体が起動せず、
    //   連鎖の**親**が存在しない（経路(A)が原理的に成立しない）
    // - `--policy-learn true`: 収集器を有効にする
    // **`--staged`は付けない。** かつては既定とCoWで`fs-audit.jsonl`の置き場が決まらず、
    // 収集器がそもそも起動しなかったので付けていた。いまは全セッションに置き場がある。
    let mut args = mode_args.to_vec();
    args.extend(["--policy-learn", "true", "--net-allow-domain", "example.com"]);
    let run = run_harness(
        ws,
        &run_shell_script_turns("Get-Content -LiteralPath 'C:/Windows/System32/config/SAM' -ErrorAction SilentlyContinue; Write-Output 'ran'"),
        &args,
        case_name,
    );
    parse_json_stdout(&run)?;

    for marker in CHAIN_LAUNCH_GIVE_UP_MARKERS {
        if run.stderr.contains(marker) {
            return Err(format!(
                "the chain-launch path (A) was abandoned -- stderr contains {marker:?}, which means \
                 the collector was launched via `runas` instead (one extra UAC prompt). \
                 stderr={}",
                run.stderr
            ));
        }
    }

    // 収集器が実際に動いた証拠。`.harness/sandbox/audit-<session-id>/fs-audit.jsonl`。
    // **置き場の名前まで見る**——`audit-`以外（`--staged`の`session-*`など）に書かれていたら、
    // 監査ログがまだ書込の捕まえ方に結び付いている。
    let sandbox_dir = ws.join(".harness").join("sandbox");
    let audit = std::fs::read_dir(&sandbox_dir)
        .map_err(|e| {
            format!(
                "no sandbox dir at {}: {e}\n--- harness stderr ---\n{}",
                sandbox_dir.display(),
                run.stderr
            )
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("fs-audit.jsonl"))
        .find(|p| p.exists());
    let Some(audit) = audit else {
        return Err(format!(
            "no fs-audit.jsonl under {} -- the collector never wrote anything, so the chain launch \
             did not actually produce a working collector. stderr={}",
            sandbox_dir.display(),
            run.stderr
        ));
    };
    let parent = audit
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if !parent.starts_with("audit-") {
        return Err(format!(
            "fs-audit.jsonl was written into {parent:?}, not the session audit directory \
             (audit-<session-id>)"
        ));
    }
    // 空のファイルは依頼する側が先に作る（BUG-109）ので、在るだけでは収集器が動いた証拠にならない。
    let body = std::fs::read_to_string(&audit).map_err(|e| e.to_string())?;
    if body.trim().is_empty() {
        return Err(format!("{} exists but is empty", audit.display()));
    }
    Ok(())
}

#[test]
#[ignore]
fn tier2a_chain_launch_uses_the_no_extra_uac_path() {
    let cases: Vec<(&str, CaseFn)> = vec![
        ("no-extra-uac", chain_launch_case_no_extra_uac_path_is_taken),
        ("no-extra-uac-under-cow", chain_launch_case_under_cow),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} chain-launch cases passed (see per-case JSON above)"
    );
}

// ============================================================================
// M16: 妥当性（Validity）の経路を**本物のMCPサーバ**で通す
//
// `docs/STATUS.md`認知レイヤー残課題#4は「M16はスタブMCPツールで全経路を単体・統合テスト
// 済みだが、M15.5が実装した本物のMCPサーバ経由での裏取りは通していない」だった。ここが
// 埋めるのは**配線**である——実MCPクライアント（AppContainer隔離下のstdioサーバ）→
// `ToolRegistry`への`mcp__<server>__<tool>`登録 → SourceBrokerのカタログ →
// `Corroborated`昇格 → 最終回答の表示、が実起動経路で繋がっているか。
//
// **モデルのツール選択能力は測らない。** 2026-08-04のLMStudio実機E2Eが表示経路へ到達
// しなかった原因はそちら（`docs/STATUS.md`認知レイヤー残課題#10＝ローカルモデルが
// `read_file`を呼べない）で、M16の配線とは別の変数である。混ぜると「配線が壊れている」と
// 「モデルが道具を選べない」を切り分けられないので、`--provider mock --mock-turns`で
// フェーズ出力を台本化して固定する。
//
// 成功対照（宣言あり＝`corroborated`）と失敗対照（宣言なし＝`single_source`＋「MCP裏取り
// 不可」）を必ず**組**で回す。片方だけでは、見えた表示が本当にMCP由来かを言えない。
//
// `dev-elevated-run.exe e2e-mcp-corroboration`（フィルタ`tier2a_mcp_corroboration`）。

/// 検証用MCPサーバ（`crates/harness-mcp/src/bin/mcp-mock-server.rs`）。
///
/// `cargo test -p harness-cli`はこのbinをビルドしない（`CARGO_BIN_EXE_*`が渡るのは
/// 同じパッケージのbinだけ）ので、`net_probe_exe`と同じく**事前ビルドを前提条件**にする。
/// 無ければ手順を添えて落とす——黙って飛ばすと「0件で緑」になる（BUG-056と同じ形）。
fn mcp_mock_server_exe() -> Result<PathBuf, String> {
    let exe = harness_exe()
        .parent()
        .expect("harness exe has a parent dir")
        .join("mcp-mock-server.exe");
    if !exe.exists() {
        return Err(format!(
            "{} not found. build it first: cargo build -p harness-mcp --bin mcp-mock-server",
            exe.display()
        ));
    }
    Ok(exe)
}

/// M16の台本が使うMCPサーバid（`mcp__docs__search`へ名前空間化される）。
const MCP_SERVER_ID: &str = "docs";
const MCP_SEARCH_TOOL: &str = "mcp__docs__search";

/// ワークスペースを作る。`declare_server`が偽なら**MCPの宣言だけを落とす**——他は
/// 完全に同一にして、2つの実行の差が「サーバが居るかどうか」だけになるようにする。
fn mcp_case_workspace(name: &str, declare_server: bool) -> Result<PathBuf, String> {
    let ws = case_dir(name);
    // ローカル一次証拠（§4.2の接地優先順位1）。台本のラウンド1がこれを読む。
    std::fs::write(
        ws.join("shell.rs"),
        "let mut cmd = Command::new(\"powershell.exe\");",
    )
    .map_err(|e| e.to_string())?;

    let harness_dir = ws.join(".harness");
    std::fs::create_dir_all(&harness_dir).map_err(|e| e.to_string())?;

    // `cognition.sources`はどちらの構成でも書く。宣言だけあってツールが登録されていなければ
    // `SourceCatalog::available`から落ちる＝MCP未接続として扱われる、という設計
    // （`harness-cognition`の`source.rs`）そのものを実起動経路で確認するため。
    let mut settings = serde_json::json!({
        "cognition": {
            "sources": [
                { "id": "mcp/docs", "kind": "mcp", "use_for": ["社内仕様"], "trust": "high" }
            ]
        }
    });
    if declare_server {
        let exe = mcp_mock_server_exe()?;
        settings["mcp"] = serde_json::json!({
            "servers": [{
                "id": MCP_SERVER_ID,
                "transport": "stdio",
                "command": exe.display().to_string(),
                // D-40: 宣言したツールだけがread扱いになる。`search`をread-onlyにするのは
                // Investigate（ToolGateがReadOnlyしか候補に入れない）で呼ばせるため。
                // workspace要求もnetwork要求も**書かない**（既定＝ACE無し・全拒否）。
                // 裏取りに要るのはサーバ自身の応答だけで、workspaceを読ませる理由が無い。
                "tools": { "search": "read_only" }
            }]
        });
    }
    std::fs::write(
        harness_dir.join("settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// `harness mcp approve <id> --yes` / `revoke <id>`（D-39の承認台帳）。
/// 台帳はユーザグローバル（`%APPDATA%\harness\config\mcp-approval-ledger.json`）なので、
/// ケースの最後で必ず`revoke`して元へ戻す。
fn mcp_approval(ws: &Path, action: &str) -> Result<String, String> {
    let mut cmd = Command::new(harness_exe());
    cmd.args(["--cwd", ws.to_str().unwrap(), "mcp", action, MCP_SERVER_ID]);
    if action == "approve" {
        cmd.arg("--yes");
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run `harness mcp {action}`: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(format!(
            "`harness mcp {action} {MCP_SERVER_ID}` failed: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}

fn phase_text_turn(value: serde_json::Value) -> Vec<StreamEvent> {
    end_turn(&value.to_string())
}

/// Investigateのターン。**計画のJSONとツール呼び出しを同じメッセージで返す**
/// （mockの`schema_with_tools:true`により`CallKind::Fused`になる）。
fn plan_and_tool_turn(id: &str, tool: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: serde_json::json!({
                "plan": [{ "source": tool, "query": "run_shell", "expects": "起動するシェル名" }]
            })
            .to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: tool.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 1,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 1 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

/// 「ローカルで見つけた主張を、次のラウンドでMCPが裏取りする」2ラウンドの台本。
/// `crates/harness-cognition/tests/m16_validity_transcript.rs`の`corroboration_script`と
/// 同じ形で、**MCPツールだけが本物**（あちらはスタブツール）。
fn mcp_corroboration_turns() -> Vec<Vec<StreamEvent>> {
    let distill = |claim: &str| {
        phase_text_turn(serde_json::json!({
            "evidence": [{
                "claim": claim,
                "relation": "supports",
                "source": "（自己申告の出典は台帳に入らない）",
                "contradicts": []
            }]
        }))
    };
    vec![
        phase_text_turn(serde_json::json!({
            "hypotheses": [{
                "statement": "run_shellはPowerShellを起動している",
                "predicts": ["shell.rsにpowershellの記述が無ければ偽"],
                "confidence": 0.7
            }]
        })),
        // ラウンド1: ワークスペースの実ファイル（接地優先順位1）。
        plan_and_tool_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "shell.rs" }),
        ),
        distill("shell.rsがpowershell.exeを起動している"),
        // まだ裏取りできていないので決着させない。
        phase_text_turn(serde_json::json!({
            "verdict": "inconclusive", "missing": ["別系統の裏取り"], "note": "ローカル観測のみ"
        })),
        // ラウンド2: 実MCPサーバで裏取り（接地優先順位2）。
        plan_and_tool_turn(
            "call_2",
            MCP_SEARCH_TOOL,
            serde_json::json!({ "query": "run_shell" }),
        ),
        distill("社内仕様もPowerShellを既定としている"),
        phase_text_turn(serde_json::json!({
            "verdict": "confirms", "missing": [], "note": "2系統で一致した"
        })),
        phase_text_turn(serde_json::json!({
            "action": "PowerShellを前提に手順を書く",
            "then_verify": "run_shellでecho $PSVersionTableを実行する"
        })),
    ]
}

fn run_cognition_harness(ws: &Path, case_name: &str) -> HarnessRun {
    run_harness(
        ws,
        &mcp_corroboration_turns(),
        &["--cognition", "always"],
        case_name,
    )
}

/// モックへ実際に送られたリクエストの中に、そのツール名のspecが載っていたか。
/// 「MCPサーバが起動して`tools/list`が返り、`ToolRegistry`へ登録された」ことの直接の証拠。
fn recorded_requests_offer_tool(run: &HarnessRun, tool: &str) -> Result<bool, String> {
    let data = std::fs::read_to_string(&run.record_path)
        .map_err(|e| format!("failed to read {}: {e}", run.record_path.display()))?;
    for line in data.lines() {
        let req: CompletionRequest = serde_json::from_str(line)
            .map_err(|e| format!("recorded request is not valid JSON: {e}"))?;
        if req.tools.iter().any(|t| t.name == tool) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 成功対照: 宣言・承認済みの実MCPサーバがあると、ローカル観測がMCPで裏取りされて
/// `corroborated`まで上がり、「MCP裏取り不可」の注記は出ない。
fn mcp_case_real_server_corroborates_a_local_observation() -> Result<(), String> {
    let ws = mcp_case_workspace("mcp-corroborated", true)?;
    mcp_approval(&ws, "approve")?;
    let run = run_cognition_harness(&ws, "mcp-corroborated");
    // 承認台帳はユーザグローバルなので、判定より先に必ず戻す。
    let revoked = mcp_approval(&ws, "revoke");

    let json = parse_json_stdout(&run)?;
    // 探す語はどちらも**最終応答文**に着地する（`corroborated`は`Grade::Corroborated`のラベル、
    // 「MCP裏取り不可」は`hiv/answer.rs`が本文へ書く注記）。JSON全体を見ると、無関係な
    // ツール入力にも当たり得る（BUG-137）。
    let text = json.answer();
    revoked?;

    if !recorded_requests_offer_tool(&run, MCP_SEARCH_TOOL)? {
        return Err(format!(
            "{MCP_SEARCH_TOOL} was never offered to the model -- the mcp server did not start or \
             its tools were not registered. stderr={}",
            run.stderr
        ));
    }
    if !text.contains("corroborated") {
        return Err(format!(
            "the answer does not report a corroborated grade (real-mcp cross-source did not \
             land): {text}\nstderr={}",
            run.stderr
        ));
    }
    if text.contains("MCP裏取り不可") {
        return Err(format!(
            "the answer claims MCP corroboration was unavailable even though the server ran: {text}"
        ));
    }

    cleanup_on_success(&ws, &[], "mcp-corroborated");
    Ok(())
}

/// 失敗対照: **同じ台本**でMCPの宣言だけを外すと、裏取りは成立せず`single_source`のまま
/// 結論し、「MCP裏取り不可」を明記する（§4.2「隠さない」）。上のケースで見えた
/// `corroborated`が本当にMCP由来だったことは、この対照が付いて初めて言える。
fn mcp_case_without_the_declaration_it_stays_single_source() -> Result<(), String> {
    let ws = mcp_case_workspace("mcp-single-source", false)?;
    let run = run_cognition_harness(&ws, "mcp-single-source");

    let json = parse_json_stdout(&run)?;
    // 上のケースと対称に、最終応答文だけを見る（BUG-137）。
    let text = json.answer();

    if recorded_requests_offer_tool(&run, MCP_SEARCH_TOOL)? {
        return Err(format!(
            "{MCP_SEARCH_TOOL} was offered even though no server is declared -- the two runs are \
             not differing only in the declaration. stderr={}",
            run.stderr
        ));
    }
    if !text.contains("single_source") {
        return Err(format!("the answer does not report single_source: {text}"));
    }
    if !text.contains("MCP裏取り不可") {
        return Err(format!(
            "a single-source conclusion must say that MCP corroboration was unavailable: {text}"
        ));
    }

    cleanup_on_success(&ws, &[], "mcp-single-source");
    Ok(())
}

#[test]
#[ignore]
fn tier2a_mcp_corroboration() {
    let cases: Vec<(&str, CaseFn)> = vec![
        (
            "real-server-corroborates",
            mcp_case_real_server_corroborates_a_local_observation,
        ),
        (
            "no-declaration-stays-single-source",
            mcp_case_without_the_declaration_it_stays_single_source,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} mcp corroboration cases passed (see per-case JSON above)"
    );
}

// ============================================================================
// D-27: fs passthrough台帳のライフサイクル（参照カウントと並行起動時の整合性）
//
// `docs/STATUS.md`は「手動E2E（複数ワークスペース共有時の安全性・並行起動時のledger整合性）は
// 未実施」と記録していた。どちらも**人間が目で確認しても再実行できない**種類の事実なので、
// `plans/VERIFY-TODO.md`項目1をここで機械的なassertとして取り直す。
//
// 測っているのは`reconcile_fs_ledger_for_workspace`（`crates/harness-cli/src/fs_grants/revoke.rs`）
// の2つの契約である。
//
//  1. **参照カウント**: `.harness/settings.json`がパスを宣言しているワークスペースのroot文字列を
//     `settings_workspaces`へ積み、宣言を外したら抜く。**他のワークスペースがまだ宣言している間は
//     台帳エントリを消さない**。誰も宣言しなくなって初めて撤収対象になる。
//  2. **並行起動でlost updateしない**: 台帳のread-modify-writeは`with_named_lock`
//     （`crates/harness-sandbox/src/lib.rs`）で直列化される。複数の`harness.exe`を同時に
//     起動しても、あるプロセスのタグ付けが別のプロセスの書込に踏み潰されてはならない。
//
// **ACEの寿命はここでは測らない。** [§22.2.1] `--fs-allow`の宛先SIDは宣言ごとのcapability SIDへ
// 移り、そのACEは**harnessの終了後も残る**（共有され得る宣言をセッション終了時に剥がすと、
// 同じワークスペースの並行セッションが互いの許可を落とすため）。寿命そのものと、名前の付いた扉
// （`harness fs revoke`）で消えることは
// `fs_allow_case_the_ace_persists_after_exit_and_the_named_door_removes_it`が固定している。
// ここで測るのは帳簿の側——D-27が守っているのは「誰も宣言しなくなったら撤収対象にする」という
// 参照カウントの契約である。
//
// `dev-elevated-run.exe e2e-fs-ledger`（フィルタ`tier2a_fs_ledger_lifecycle`）。

/// `%APPDATA%\harness\config\fs-passthrough-ledger.json`。**保護対象の台帳**（`docs/DEV-ENVIRONMENT.md`
/// 「クリーンアップ時に絶対に消してはいけないファイル」）なので、テストは自分が足したエントリ以外に
/// 触れない。ケース終了時に自分のエントリだけを取り除く。
fn fs_passthrough_ledger_path() -> PathBuf {
    directories::ProjectDirs::from("", "", "harness")
        .expect("resolve harness config dir")
        .config_dir()
        .join("fs-passthrough-ledger.json")
}

/// マシン全体で1つしか無いfs passthrough台帳を触ってよいことの証。
/// **取得手段は[`fs_ledger_exclusive`]だけ**で、台帳を読む／書く手段はこの型のメソッドだけ。
///
/// 排他ガードを持たないと呼べない形にしてあるのは、`e2e-all`が全件を並行実行するため
/// （上の「共有資源の排他」節の4番）。排他ガードは**ケース単位ではなくテスト関数の全体**で持つ——
/// [`FsLedgerExclusive::entry_for`]で観測した状態は次の`harness.exe`起動まで保たれている
/// 必要があり、1呼び出しだけを直列化しても意味が無い。
struct FsLedgerExclusive {
    _guard: std::sync::MutexGuard<'static, ()>,
}

/// 台帳を触ってよいことの証を取る。**取得手段はこの関数だけ**である。
fn fs_ledger_exclusive() -> FsLedgerExclusive {
    FsLedgerExclusive {
        _guard: FS_LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

impl FsLedgerExclusive {
    /// 台帳から`target`のエントリを引く。無ければ`None`。
    fn entry_for(&self, target: &Path) -> Result<Option<(bool, Vec<String>)>, String> {
        let key = target.to_string_lossy().to_string();
        Ok(read_fs_ledger_entries()?
            .into_iter()
            .find(|(p, _, _)| *p == key)
            .map(|(_, managed, ws)| (managed, ws)))
    }

    /// 台帳を汚したまま終わらないための後始末。`harness fs revoke <path>`は撤収できたときだけ
    /// エントリを消すので、ディレクトリを消した後だと残ることがある。テストが足したエントリは
    /// テストが責任を持って落とす。
    ///
    /// **`entries`と`denied_entries`の両方を落とす。** かつては`entries`だけだったが、
    /// 付与に失敗した宣言は`denied_entries`の側へ記録されるので、**わざと失敗させる腕を持つ
    /// ケース**（[`fs_allow_case_the_elevated_grant_opens_only_the_declared_subject`]）は
    /// 片方だけ消しても中立にならない。**対の片方だけ実装しない**（`B-01`）。
    ///
    /// **台帳ファイルはread-only属性付きで書かれている**（`harness-grant-ledger`の
    /// 「誤削除防止の2層」）。素の`std::fs::write`は黙って失敗するので、本体と同じく
    /// 解除→書込→再付与の順で触る。この3手が**分割できない**ことが、排他ガードを要求する直接の理由——
    /// 隣が同時に再付与すると、こちらの`write`が「アクセスが拒否されました」で落ちる。
    fn purge_entries(&self, targets: &[&Path]) {
        let path = fs_passthrough_ledger_path();
        let Ok(data) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&data) else {
            return;
        };
        let keys: HashSet<String> = targets
            .iter()
            .map(|t| t.to_string_lossy().to_string())
            .collect();
        for bucket in ["entries", "denied_entries"] {
            if let Some(entries) = json.get_mut(bucket).and_then(|v| v.as_array_mut()) {
                entries.retain(|e| {
                    !e.get("path")
                        .and_then(|v| v.as_str())
                        .map(|p| keys.contains(p))
                        .unwrap_or(false)
                });
            }
        }
        let Ok(text) = serde_json::to_string_pretty(&json) else {
            return;
        };
        set_ledger_readonly(&path, false);
        let wrote = std::fs::write(&path, text).is_ok();
        set_ledger_readonly(&path, true);
        assert!(
            wrote,
            "failed to purge test entries from {}",
            path.display()
        );
    }
}

/// 台帳の`entries`を`(path, settings_managed, settings_workspaces)`で読み出す。
/// **[`FsLedgerExclusive`]のメソッドからのみ呼ぶこと**（排他ガードの外から呼べる自由関数にしない）。
/// 台帳の`forced`欄を`(path, forced)`で読む（[BUG-119](../../../docs/bugs/BUG-119.md)）。
///
/// [`read_fs_ledger_entries`]は`settings_managed`側を見る別の測定用なので、
/// **同じJSONを読むが返す欄が違う**。片方へ欄を足して両方の呼び出し元を直すより、
/// 測る対象ごとに小さく読むほうが「何を測っているか」が読める。
fn read_fs_ledger_forced_flags() -> Result<Vec<(String, bool)>, String> {
    let path = fs_passthrough_ledger_path();
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let entries = json
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{} has no `entries` array", path.display()))?;
    Ok(entries
        .iter()
        .map(|e| {
            (
                e.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                e.get("forced").and_then(|v| v.as_bool()).unwrap_or(false),
            )
        })
        .collect())
}

fn read_fs_ledger_entries() -> Result<Vec<(String, bool, Vec<String>)>, String> {
    let path = fs_passthrough_ledger_path();
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let entries = json
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("{} has no `entries` array", path.display()))?;
    Ok(entries
        .iter()
        .map(|e| {
            let path = e
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let managed = e
                .get("settings_managed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let workspaces = e
                .get("settings_workspaces")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|w| w.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            (path, managed, workspaces)
        })
        .collect())
}

/// `<ws>/.harness/settings.json`へ`fs.read`宣言を書く（`paths`が空なら`fs`キーごと落とす）。
fn write_fs_settings(ws: &Path, paths: &[&Path]) -> Result<(), String> {
    let dir = ws.join(".harness");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let settings = if paths.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::json!({
            "fs": { "read": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>() }
        })
    };
    std::fs::write(
        dir.join("settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .map_err(|e| e.to_string())
}

fn set_ledger_readonly(path: &Path, readonly: bool) {
    // 台帳の後始末は最善努力（失敗しても次の手当てがある）なので、結果は捨てる。
    let _ = set_readonly_checked(path, readonly);
}

/// 読み取り専用の属性を立てる／下ろす。**失敗を返す**——属性が立たなかったのに先へ進むと、
/// それを前提にした試験（CoW行列のW）が何も確かめないまま緑になる。
fn set_readonly_checked(path: &Path, readonly: bool) -> Result<(), String> {
    let mut perms = std::fs::metadata(path)
        .map_err(|e| format!("metadata {}: {e}", path.display()))?
        .permissions();
    perms.set_readonly(readonly);
    std::fs::set_permissions(path, perms)
        .map_err(|e| format!("set readonly={readonly} on {}: {e}", path.display()))
}

/// 2つのワークスペースが同じパスを宣言している間はエントリが生き、両方が宣言を外して初めて
/// 撤収される（D-27の参照カウント）。
fn fs_ledger_case_shared_declaration_is_refcounted(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    let ws1 = case_dir("fs-ledger-ws1");
    let ws2 = case_dir("fs-ledger-ws2");
    let target = fs_allow_case_dir("ledger-shared");
    std::fs::write(target.join("f.txt"), "x").map_err(|e| e.to_string())?;
    let ws1_key = ws1.to_string_lossy().to_string();
    let ws2_key = ws2.to_string_lossy().to_string();
    let script = "Write-Output 'ran'";

    let finish = |e: String| -> String {
        ledger.purge_entries(&[&target]);
        let _ = std::fs::remove_dir_all(&target);
        e
    };

    // (1) ws1が宣言して起動 → ws1だけがタグされる。
    write_fs_settings(&ws1, &[&target])?;
    let run = run_harness(&ws1, &run_shell_script_turns(script), &[], "fs-ledger-1");
    parse_json_stdout(&run).map_err(&finish)?;
    match ledger.entry_for(&target).map_err(&finish)? {
        Some((true, ws)) if ws == vec![ws1_key.clone()] => {}
        other => {
            return Err(finish(format!(
                "after ws1 declared the path, the ledger entry should be settings_managed with \
                 exactly [ws1]; got {other:?}"
            )))
        }
    }

    // (2) ws2も宣言して起動 → 参照が2つになる。
    write_fs_settings(&ws2, &[&target])?;
    let run = run_harness(&ws2, &run_shell_script_turns(script), &[], "fs-ledger-2");
    parse_json_stdout(&run).map_err(&finish)?;
    match ledger.entry_for(&target).map_err(&finish)? {
        Some((true, ws)) if ws.contains(&ws1_key) && ws.contains(&ws2_key) && ws.len() == 2 => {}
        other => {
            return Err(finish(format!(
                "after ws2 also declared the path, both workspaces must be tagged; got {other:?}"
            )))
        }
    }

    // (3) ws1が宣言を外して再起動 → **ws2がまだ参照しているのでエントリは残る**（本題）。
    write_fs_settings(&ws1, &[])?;
    let run = run_harness(&ws1, &run_shell_script_turns(script), &[], "fs-ledger-3");
    parse_json_stdout(&run).map_err(&finish)?;
    match ledger.entry_for(&target).map_err(&finish)? {
        Some((true, ws)) if ws == vec![ws2_key.clone()] => {}
        None => {
            return Err(finish(
                "D-27 violation: the entry was revoked while ws2 still declares the path in its \
                 .harness/settings.json (a shared passthrough must survive until the last \
                 declaring workspace drops it)"
                    .to_string(),
            ))
        }
        other => {
            return Err(finish(format!(
                "after ws1 dropped the declaration only ws2 should remain tagged; got {other:?}"
            )))
        }
    }

    // (4) ws2も宣言を外して再起動 → 参照ゼロになったので撤収され、台帳から消える。
    write_fs_settings(&ws2, &[])?;
    let run = run_harness(&ws2, &run_shell_script_turns(script), &[], "fs-ledger-4");
    parse_json_stdout(&run).map_err(&finish)?;
    if let Some(entry) = ledger.entry_for(&target).map_err(&finish)? {
        return Err(finish(format!(
            "the entry must be auto-revoked once no workspace declares it; it is still there as \
             {entry:?}"
        )));
    }
    if !run.stderr.contains("no longer declared by any workspace") {
        return Err(finish(format!(
            "the auto-revoke must be announced on stderr (D-43: do not hide what was changed); \
             stderr={}",
            run.stderr
        )));
    }

    // (5) [§22.2.1] **実ACLを見る。** ここまでは台帳の側しか測っていない——
    // 台帳エントリが消えたことは、そのパスのACEが消えたことを意味しない（`B-14`）。
    // `--fs-allow`の宛先SIDが宣言ごとのcapability SID（`S-1-15-3-*`）へ移った後は、
    // **これが「宣言が消えた次の起動で剥がれる」の唯一の証拠**になる（T1-cの受け入れ条件3）。
    // 宛先SIDが移る前は同じ経路がpackage SID（`S-1-15-2-*`）宛を剥がしていたので、両方を数える。
    for prefix in ["S-1-15-2-", "S-1-15-3-"] {
        let left = count_sid_aces(&target, prefix).map_err(&finish)?;
        if left != 0 {
            return Err(finish(format!(
                "§22.2.1: {} still carries {left} {prefix}* ACE(s) after the last declaring \
                 workspace dropped it; the ledger entry is gone but the hole is still open",
                target.display()
            )));
        }
    }

    ledger.purge_entries(&[&target]);
    let _ = std::fs::remove_dir_all(&target);
    cleanup_on_success(&ws1, &[], "fs-ledger-1");
    cleanup_on_success(&ws2, &[], "fs-ledger-3");
    cleanup_on_success(&ws1, &[], "fs-ledger-2");
    cleanup_on_success(&ws2, &[], "fs-ledger-4");
    Ok(())
}

/// 複数の`harness.exe`を**同時に**起動しても、各ワークスペースの宣言が台帳へ揃って残る
/// （read-modify-writeが`with_named_lock`で直列化され、lost updateが起きない）。
fn fs_ledger_case_concurrent_startups_do_not_lose_updates(
    ledger: &FsLedgerExclusive,
) -> Result<(), String> {
    const N: usize = 4;
    let shared = fs_allow_case_dir("ledger-concurrent-shared");
    std::fs::write(shared.join("f.txt"), "x").map_err(|e| e.to_string())?;

    let mut workspaces = Vec::new();
    let mut owned = Vec::new();
    for i in 0..N {
        let ws = case_dir(&format!("fs-ledger-conc-{i}"));
        let mine = fs_allow_case_dir(&format!("ledger-concurrent-{i}"));
        std::fs::write(mine.join("f.txt"), "x").map_err(|e| e.to_string())?;
        write_fs_settings(&ws, &[&shared, &mine])?;
        workspaces.push(ws);
        owned.push(mine);
    }
    let all_targets: Vec<&Path> = std::iter::once(shared.as_path())
        .chain(owned.iter().map(|p| p.as_path()))
        .collect();
    let finish = |e: String| -> String {
        ledger.purge_entries(&all_targets);
        for t in &all_targets {
            let _ = std::fs::remove_dir_all(t);
        }
        e
    };

    // 台本ファイルはケース名ごとに別なので、同時起動しても互いに踏まない。
    let turns = run_shell_script_turns("Write-Output 'ran'");
    let scratch = scratch_dir();
    let mut children = Vec::new();
    for (i, ws) in workspaces.iter().enumerate() {
        let case_name = format!("fs-ledger-conc-{i}");
        let turns_path = scratch.join(format!("{case_name}-turns.json"));
        std::fs::write(&turns_path, serde_json::to_string(&turns).unwrap())
            .map_err(|e| finish(e.to_string()))?;
        let mut cmd = Command::new(harness_exe());
        cmd.args([
            "--provider",
            "mock",
            "--mock-turns",
            turns_path.to_str().unwrap(),
            "--cwd",
            ws.to_str().unwrap(),
            "--permission-mode",
            "accept-all",
            "--dangerously-allow",
            "--output-format",
            "json",
            "-p",
            "(scripted)",
        ]);
        cmd.args(scripted_shell_rule_args(&turns));
        children.push(
            cmd.spawn()
                .map_err(|e| finish(format!("failed to spawn harness.exe: {e}")))?,
        );
    }
    let mut failures = Vec::new();
    for (i, child) in children.into_iter().enumerate() {
        let out = child
            .wait_with_output()
            .map_err(|e| finish(e.to_string()))?;
        if !out.status.success() {
            failures.push(format!(
                "concurrent harness #{i} exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    if !failures.is_empty() {
        return Err(finish(failures.join("\n")));
    }

    // 共有パスは**全ワークスペース**からタグされていなければならない（1件でも欠けたら
    // それが lost update そのもの）。各ワークスペース専用のパスも同様に残っている必要がある。
    let shared_entry = ledger
        .entry_for(&shared)
        .map_err(&finish)?
        .ok_or_else(|| finish("the shared path has no ledger entry at all".to_string()))?;
    let tagged: HashSet<String> = shared_entry.1.into_iter().collect();
    let missing: Vec<String> = workspaces
        .iter()
        .map(|w| w.to_string_lossy().to_string())
        .filter(|w| !tagged.contains(w))
        .collect();
    if !missing.is_empty() {
        return Err(finish(format!(
            "lost update: {} of {N} concurrent workspaces are missing from the shared entry's \
             settings_workspaces ({missing:?}); the ledger read-modify-write is not serialized",
            missing.len()
        )));
    }
    for (i, mine) in owned.iter().enumerate() {
        match ledger.entry_for(mine).map_err(&finish)? {
            Some((true, ws)) if ws.len() == 1 => {}
            other => {
                return Err(finish(format!(
                    "workspace #{i}'s own declaration was lost or mis-tagged: {other:?}"
                )))
            }
        }
    }

    ledger.purge_entries(&all_targets);
    for t in &all_targets {
        let _ = std::fs::remove_dir_all(t);
    }
    for (i, ws) in workspaces.iter().enumerate() {
        cleanup_on_success(ws, &[], &format!("fs-ledger-conc-{i}"));
    }
    Ok(())
}

#[test]
#[ignore]
fn tier2a_fs_ledger_lifecycle() {
    // `KNOWN_TARGETS`の`e2e-fs-ledger`は「保護対象の`fs-passthrough-ledger.json`を触るため、
    // 他のE2Eと同時に走らせない」と書いているが、`e2e-all`は全件を並列で回すので**その規約は
    // 誰にも守られていなかった**。排他ガードを取ることで規約を機構にする。
    let ledger = fs_ledger_exclusive();
    let cases: Vec<(&str, FsLedgerCaseFn)> = vec![
        (
            "shared-declaration-is-refcounted",
            fs_ledger_case_shared_declaration_is_refcounted,
        ),
        (
            "concurrent-startups-do-not-lose-updates",
            fs_ledger_case_concurrent_startups_do_not_lose_updates,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, || f(&ledger)) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} fs ledger lifecycle cases passed (see per-case JSON above)"
    );
}

/// **N8-③-C-WFP**: 生TCPの445が、**本番Tier2aのWFP適用下**でも塞がるか
/// （`plans/net-spike/RESULTS.md` `N8-③-C`）。
///
/// `N8-③-C`は**素のAppContainerトークン**（netfilterd非適用）で測っており、
/// `internetClient`を積むと**445へのTCPが張れた**。本番ではWFPの既定拒否が
/// `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`に張られ、条件は`FWPM_CONDITION_ALE_PACKAGE_ID`だけ
/// （`wfp.rs`の`add_default_deny_filter`は`numFilterConditions: 1`）なので**ポートを見ない**
/// ——したがって445も塞がるはずである。**「はず」を測る。**
///
/// case 05（`example-ip`）が既に生TCPの80番を測っているが、**445は測っていない**。
/// Windowsが445を特別扱いする経路（別のpermit規則等）が無いことを、ポート番号を変えて確かめる。
///
/// **ホストは環境依存なのでファイルで渡す**——`dev-elevated-runner`経由の昇格側プロセスへは
/// **呼び出し元の環境変数が引き継がれる保証が無い**（`CLAUDE.md`。`tier2a-mock-netfilterd`が
/// `mock-mode`ファイルを使っているのと同じ理由）。
///
/// **`tier2a_net_policy_matrix`のcaseにせず独立させているのは意図である**（漏れではない）。
/// このテストは`C:\harness-e2e\n8-smb-host.txt`と、そこに書かれたホストの445が開いていること、
/// という**この開発機の外では保証できない前提**を持つ。行列のcaseにすると、前提が無い環境で
/// 行列**全体**が落ち、他の10ケースの結果まで読めなくなる。**動作を保証できない前提を
/// 共有の行列へ持ち込まない**、という切り分けである（`plan-review-gates`検問7）。
/// 起動は専用の`KNOWN_TARGETS`エントリ`n8-smb445-layer2`だけに紐づけてある。
#[test]
#[ignore = "実Tier2a・実WFP。dev-elevated-runnerの n8-smb445-layer2 経由で走らせること"]
fn tier2a_smb445_layer2() {
    let host_file = Path::new(CASE_ROOT).join("n8-smb-host.txt");
    let host = std::fs::read_to_string(&host_file)
        .unwrap_or_else(|e| {
            panic!(
                "{} が読めない（445が開いている検証用ホストのIPを1行で置くこと）: {e}",
                host_file.display()
            )
        })
        .trim()
        .to_string();
    assert!(!host.is_empty(), "{} が空", host_file.display());

    if let Err(e) = liveness_gate() {
        panic!("liveness gate failed, the result would be indeterminate: {e}");
    }

    // --- 対照: **コンテナ外から445へ繋がること**を、**測定と同じ計器で**確かめる。
    //
    // 別の手段（`TcpStream::connect_timeout`を直に呼ぶ等）で対照を取ると、
    // 「ホストの445が開いている」ことしか言えない。**この計器が`ok=true`を返し得ること**が
    // 未検証のまま残り、計器が常に`false`を返す壊れ方をしても本体のassertは緑になる
    // （`test-logic-rules`問3: 歯があることを確認していないテストは、緑が合格の証拠にならない）。
    let outside = std::process::Command::new(net_probe_exe())
        .args(["raw-connect", &host, "445", "--label", "smb445-outside"])
        .output()
        .expect("run the probe outside the container");
    let outside_text = String::from_utf8_lossy(&outside.stdout).to_string();
    let outside_ok = outside_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("probe").and_then(|p| p.as_str()) == Some("raw_connect"))
        .and_then(|v| v["ok"].as_bool());
    assert_eq!(
        outside_ok,
        Some(true),
        "対照が落ちた＝**同じ計器**でコンテナ外からも {host}:445 へ繋がらない。\
         以降の`ok=false`は「WFPが塞いだ」の証拠にならない。out={outside_text}"
    );

    // --- 本番と同じ経路でTier2aを起動する。`--net-allow-domain`を与えるのは、
    // network capabilityが`Deny`へ落ちる経路（case 07）を避け、**capabilityは在るのに
    // WFPが塞ぐ**という一番強い形で測るため。case 10のdocが書いているとおり、
    // 「`--net-allow-domain`を指定した時点でharnessは子へcapabilityを与えざるを得ず、
    // 子とインターネット全体の間に立っているのはWFPフィルタだけ」になる。
    let name = "net-11-smb445";
    let ws = net_case_ws(name);
    // **同じ実行の中に陽性対照を置く**（B-29・§18.5）。`raw-connect`が失敗しただけでは
    // 「WFPが落とした」と「そもそも通信路が死んでいた」を区別できない。プロキシ経由の
    // example.comが**同じセッションで**通ることを先に見る。
    let script = format!(
        ".\\tier2a-net-e2e.exe fetch-url https://example.com/ --label example; \
         .\\tier2a-net-e2e.exe raw-connect {host} 445 --label smb445"
    );
    let run = run_harness_with_exe(
        &harness_exe(),
        &ws,
        &run_shell_script_turns(&script),
        &["--net-allow-domain", "example.com"],
        name,
    );
    assert!(
        run.status.success(),
        "harness invocation itself failed: {}",
        run.stderr
    );
    let outcome = parse_json_stdout(&run).unwrap_or_else(|e| panic!("{e}"));
    let result_text = outcome
        .first_tool_result()
        .unwrap_or_else(|e| panic!("{e}"));
    let json_lines: Vec<serde_json::Value> = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    let by_label = |label: &str| -> serde_json::Value {
        json_lines
            .iter()
            .rfind(|v| v.get("label").and_then(|p| p.as_str()) == Some(label))
            .unwrap_or_else(|| panic!("label={label} のJSONが出力に無い: {result_text}"))
            .clone()
    };

    // --- 陽性対照: 許可済みドメインはプロキシ経由で通る ---
    let allowed = by_label("example");
    assert_eq!(
        allowed["ok"].as_bool(),
        Some(true),
        "陽性対照が落ちた＝許可済みのexample.comすら通っていない。\
         445の失敗を「WFPが塞いだ」と読んではいけない。probe={allowed}"
    );

    // --- 本題: 445への生TCP ---
    let probe = by_label("smb445");
    let ok = probe["ok"].as_bool().unwrap_or(true);
    eprintln!("[N8-③-C-WFP] host={host} port=445 in-container ok={ok} probe={probe}");
    assert!(
        !ok,
        "**WFP適用下でもコンテナから445へ繋がった。** 既定拒否がポートを見ない前提が崩れている\
         （`wfp.rs`の`add_default_deny_filter`）。probe={probe}"
    );

    // --- `10013`の出どころを分ける。
    //
    // **`classify_drop`の記録があるとは限らない。** harnessはWFPセッションを**動的**で開く
    // （持ち主が死ねばOSが登録を自動で消す＝フェイルセーフの根拠）が、イベント収集の有効化は
    // エンジン全体の設定なので、動的セッションの中からは呼べない
    // （`FwpmEngineSetOption0`が`FWP_E_DYNAMIC_SESSION_IN_PROGRESS` 0x8032000b を返す）。
    // **「dropの記録が無い」を「dropしていない」と読まないため、ここで理由まで確かめておく**
    // （B-10: 記録の不在は事実の不在ではない）。
    //
    // [BUG-094] **ここが案Bの測定点でもある。** 収集を有効化できなくても購読だけは試すように
    // したので（`wfp.rs`の`start_wfp_drop_audit`）、**マシン側で既に収集が有効なら
    // イベントが届く**。届いたかどうかは`classify_drop`の有無がそのまま答えになる。
    let audit_entries = collect_audit_entries(&ws.join(".harness").join("sandbox"))
        .unwrap_or_else(|e| panic!("{e}"));
    let control_reason = |needle: &str| {
        audit_entries.iter().any(|e| {
            e.get("reason")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.starts_with(needle))
        })
    };
    let collection_enabled_by_harness = control_reason("net_event_collection_enabled_by_harness");
    let collection_not_enabled = control_reason("net_event_collection_not_enabled_by_harness");
    let subscribed = control_reason("net_event_subscribed");
    let subscribe_failed = control_reason("net_event_subscribe_failed");
    let has_drop_445 = audit_entries.iter().any(|e| {
        e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop")
            && e.get("remote_port").and_then(|p| p.as_u64()) == Some(445)
    });
    // **有効化の可否と購読の可否は別々に載る**（旧実装は前者で失敗すると後者を試さなかった）。
    // どちらかの制御レコードが必ず在ることを要求する——両方無いなら監査は何も言っていない。
    assert!(
        collection_enabled_by_harness || collection_not_enabled,
        "[BUG-094] イベント収集の有効化について、成功も失敗も記録されていない。\
         **この監査ログは何も言っていない**ので、10013の出どころを主張できない。\
         audit={audit_entries:?}"
    );
    assert!(
        subscribed || subscribe_failed,
        "[BUG-094] 購読を試した形跡が無い。有効化に失敗しても購読は試すはず\
         （マシン側で既に収集が有効なら、それでイベントが届く）。audit={audit_entries:?}"
    );
    eprintln!(
        "[N8-③-C-WFP][BUG-094] harnessが収集を有効化できた={collection_enabled_by_harness} / \
         できなかった={collection_not_enabled} / 購読できた={subscribed} / \
         445のclassify_drop記録={has_drop_445}"
    );
    // **判定の元になった文字列そのものを出す。** 上の真偽値は前方一致で畳んだ結果なので、
    // 「イベントが来ない理由」——マシン全体の収集が無効なのか、有効なのに来ないのか——は
    // ここを読まないと分からない（BUG-094の結論が分岐する唯一の材料）。成功した回は
    // ワークスペースごと片付くので、**ログに残すのがこの事実を残す唯一の口**である。
    for e in &audit_entries {
        if e.get("protocol").and_then(|p| p.as_str()) == Some("control") {
            eprintln!(
                "[N8-③-C-WFP][BUG-094] control: {}",
                e.get("reason").and_then(|r| r.as_str()).unwrap_or("<none>")
            );
        }
    }

    // 代わりに**分岐を固定する**。`10013`は「WFPの既定拒否」でも「network capabilityが無い」でも
    // 出るので、後者の分岐を通っていないことを、その分岐だけが出す文言の**不在**で押さえる
    // （case 07・case 10がこの文言の**存在**を要求しているのと対になる）。
    const CAPABILITY_DENIED_MSG: &str = "Tier2a run_shell network capability will remain denied";
    assert!(
        !run.stderr.contains(CAPABILITY_DENIED_MSG),
        "capabilityがDenyへ落ちる分岐を通っている＝**445の拒否はWFPの手柄ではない**。\
         stderr={}",
        run.stderr
    );
    assert!(
        result_text.contains("net-proxy: enforced-by-wfp"),
        "WFPが効いている宣言がシェルのバナーに無い。この実行でWFPが張られた保証が無い: {result_text}"
    );

    cleanup_on_success(&ws, &[], name);
}

// ============================================================================
// W7: ワークスペース**内**の実行が、そのファイルのACEで制御されるか（D-79の前提測定）
//
// 問い（`test-logic-rules`問1を一文で）: **「ワークスペース内のファイルを起動できるか
// どうかは、そのファイルのDACLが持つ実行権（`FILE_EXECUTE`）で決まるか」**。
//
// なぜ測るか: `acl_grant.rs`の`workspace_rwx_mask()`は
// `FILE_GENERIC_READ|FILE_GENERIC_WRITE|FILE_GENERIC_EXECUTE|DELETE`を、workspace rootへ
// `CONTAINER_INHERIT_ACE|OBJECT_INHERIT_ACE`の**1本のACE**で付ける。つまりツリー内の
// 全ファイルが実行可で、`cargo build`が吐いたexeもそのまま走る。D-79
// （`plans/DESIGN-SANDBOX-APPPOLICY.md`）はこれを宣言制へ変える決定だが**未実装**であり、
// D-79自身が「スクリプトは本決定では止まらない」と限界を書いている。その2つ——
// 「いまは止まらない」と「ACEを変えれば止まる／スクリプトは止まらない」——を実測する。
//
// 2ラウンドで測る（`test-logic-rules`問2: 禁止側だけでは機構の生死を判定できない）。
//   ラウンドA（既定のACEのまま）: 全経路が**走る**こと。ここが緑でなければ、ラウンドBの
//     「走らない」は「ACEが効いた」の証拠にならない（計器が死んでいるだけかもしれない）。
//   ラウンドB（対象ファイルへ明示DENYを1本足す）: PEだけが止まり、スクリプトは止まらないこと。
//
// **これはD-79の実装のテストではない。** D-79は継承ACEを2本に割る形
// （`OBJECT_INHERIT_ACE`側から実行権を落とす）を要求しており、本測定が使う明示DENYとは
// ACEの形が違う。本測定が答えるのはその手前の命題（実行可否はEXECUTE権で決まるのか）だけで、
// D-79の付与コスト・2本割りの成否は`plans/mac-spike/RESULTS.md` §S9（M2）が持つ。
//
// `dev-elevated-run.exe e2e-exec-ace`（フィルタ`tier2a_workspace_exec_ace_matrix`）。

/// 実行経路1つ。`token`が`run_shell`の出力に現れたら「起動できた」。
///
/// ラウンドごとの**期待値**を持つ。`b`（明示DENY）と`c`（ALLOWから権利を落とす）を
/// 分けているのは、**AppContainerではこの2つが同じ結果にならない**ためで、
/// それ自体が本測定で分かったことである（下の`EXEC_PROBES`の`why`を参照）。
struct ExecProbe {
    name: &'static str,
    token: &'static str,
    /// ラウンドB（対象ファイルへ明示DENY ACEを足す）で走るか。
    runs_in_b: bool,
    /// ラウンドC（対象ファイルのcapability SID宛ALLOWから権利を落とす＝D-79の形）で走るか。
    runs_in_c: bool,
    why: &'static str,
}

/// トークンは**互いに接頭辞にならない**ようにしてある。`HP_EXE`と`HP_EXE_COPY`のような
/// 組にすると`contains`が前者で後者に当たり、片方しか走っていなくても両方緑になる。
///
/// **JScript（`cscript.exe`）の経路は落とした。** ラウンドAで
/// `CScript Error: Loading your settings failed. (Access is denied.)`となり、
/// スクリプトのDACLとは無関係な理由（cscriptが自分の設定をHKCUから読めない）で起動しない。
/// **計器として使えないものを行列に残すと、Bの「走らなかった」がACEの手柄に見える。**
const EXEC_PROBES: &[ExecProbe] = &[
    ExecProbe {
        name: "pe-placed-before-launch",
        token: "HP_A_EXE",
        runs_in_b: true,
        runs_in_c: false,
        why: "PEの起動はイメージを実行権で開くので、capability SID宛ALLOWから実行権を\
              落とせば止まる（C）。**明示DENYでは止まらない**（B）——AppContainerの\
              アクセスチェックはcapability SIDを許可の側でしか見ていない",
    },
    ExecProbe {
        name: "pe-copied-inside-the-session",
        token: "HP_B_EXECOPY",
        runs_in_b: true,
        runs_in_c: true,
        why: "手術は元のファイルにしか掛かっていない。読取は残っているので複製が作れ、\
              複製はworkspace rootの継承ALLOW（実行権つき）を受け取る。\
              **D-79が継承ACEを2本に割るのはここを塞ぐため**で、ファイル単位の手当てでは閉じない",
    },
    ExecProbe {
        name: "ps1-invoked-directly",
        token: "HP_C_PS1",
        runs_in_b: true,
        runs_in_c: true,
        why: "pwshはスクリプトを読むだけ。実行権を落としてもREADがあれば走る（D-79の限界節）",
    },
    ExecProbe {
        name: "ps1-via-scriptblock",
        token: "HP_D_IEX",
        runs_in_b: true,
        runs_in_c: true,
        why: "同上。読取と実行の区別がそもそも無い経路",
    },
    ExecProbe {
        name: "cmd-batch-invoked-directly",
        token: "HP_E_CMD",
        runs_in_b: true,
        runs_in_c: false,
        why: "**実測で分かったこと**: pwshが`.\\x.cmd`を直に起動する経路は`CreateProcess`を通り、\
              バッチファイル自身の実行権が見られる。スクリプトでも**この呼び方なら**止まる",
    },
    ExecProbe {
        name: "cmd-batch-handed-to-the-interpreter",
        token: "HP_I_CMDX",
        runs_in_b: true,
        runs_in_c: true,
        why: "同じバッチを`%ComSpec% /c <path>`として渡すと、cmd.exeが**読むだけ**になるので\
              実行権を落としても走る。**呼び方を変えるだけで直上のケースの拒否が外れる**\
              ——これがパスベースの実行制御とインタプリタの関係そのものである",
    },
    ExecProbe {
        name: "python-script",
        token: "HP_G_PY",
        runs_in_b: true,
        runs_in_c: true,
        why: "python.exeがスクリプトを読むだけ（ユーザーが名指しした`evil.py`の形）",
    },
    ExecProbe {
        name: "ps1-with-read-removed",
        token: "HP_H_RDENY",
        runs_in_b: true,
        runs_in_c: false,
        why: "スクリプトに効く唯一のレバーはREADで、しかもALLOWから落とす形でしか効かない。\
              **ただしワークスペース内で読取を落とすことは実運用では選べない**\
              ——作業場そのものが読めなくなる",
    },
];

/// プローブ本体。ラウンドA・Bで**同じ文字列**を使う（計器を変えると差分が読めない）。
/// `@PY@`だけは、この機にPythonが無いときに空へ差し替える。
///
/// **T-09の危険構文マーカーを踏まないように書いてある**（`harness-engine/src/permission.rs`の
/// `looks_like_allowlist_bypass`）。`Invoke-Expression`と`cmd.exe /c`は`accept-all`下でも
/// 強制Promptへ落ち、ヘッドレスでは自動拒否になる——最初の実測はこれで`run_shell`ごと
/// 拒否された。ここで測りたいのは**ACLの層**なので、同じ意味の別の綴り
/// （`[scriptblock]::Create`・`.cmd`の直接起動）へ置き換えてある。
/// **この置き換えが成立すること自体が、T-09が境界ではないこと**（`DESIGN.md`が
/// 「明白物の追加ブロックであり安全の根拠にしない」と書いているとおり）**の実例**である。
const EXEC_PROBE_SCRIPT: &str = "\
$ErrorActionPreference='SilentlyContinue'; \
try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }; \
Remove-Item -LiteralPath '.\\copied.exe' -Force -ErrorAction SilentlyContinue; \
try { & '.\\evil.exe' /c echo HP_A_EXE } catch { }; \
try { Copy-Item -LiteralPath '.\\evil.exe' -Destination '.\\copied.exe' -Force -ErrorAction Stop; \
      & '.\\copied.exe' /c echo HP_B_EXECOPY } catch { }; \
try { & '.\\evil.ps1' } catch { }; \
try { & ([scriptblock]::Create((Get-Content -LiteralPath '.\\evil_iex.ps1' -Raw))) } catch { }; \
try { & '.\\evil.cmd' } catch { }; \
try { & $env:ComSpec '/c' '.\\evil2.cmd' } catch { }; \
try { & '.\\evil_readdeny.ps1' } catch { }; \
@PY@\
Write-Output 'HP_PROBE_DONE'";

const EXEC_PROBE_PY_LINE: &str = "try { & '.\\py\\python.exe' '.\\evil.py' } catch { }; ";

/// PowerShellを1本走らせて標準出力を返す。ACEの読み書きに使う。
fn powershell(script: &str) -> Result<String, String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("failed to spawn powershell: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "powershell failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// このワークスペースへ付いている **`rwx`モードのworkspace capability SID**（D-54）を読む。
///
/// DENYの宛先はこれでなければならない——workspaceツリーのACEはセッションのpackage SIDではなく
/// **workspace＋モード単位のcapability SID**宛に付く（`tier2a/workspace_capability.rs`）。
/// package SID宛にDENYを置いても当たらないので、間違えると「DENYを置いたのに走った」という
/// 誤った結論になる。
///
/// # **[D-84] ここは1本ではなく2本になった**
///
/// 以前は「継承あり かつ 実行権（`FILE_EXECUTE`=0x20）」で絞れば1本だけ当たった。
/// D-84で`preflight`が**両モード（`rwx`/`ro`）のcapability SID宛ACEを毎回まとめて配る**ように
/// なったため、この条件では**2本**当たる——`ro`のマスク（`FILE_GENERIC_READ |
/// FILE_GENERIC_EXECUTE`）にも`FILE_EXECUTE`が入っているからである。
///
/// この測定が止めたいのは**プローブの子が実際に名乗っているcapability SID**で、
/// この経路は通常起動（`WorkspaceWriteMode::DirectRw`）なので`rwx`側である。
/// **書込権（`FILE_WRITE_DATA`=0x2）の有無で選ぶ**——`rwx`のマスクだけがこれを持ち、
/// `ro`のマスクは持たない（`win_appcontainer::workspace_mode_mask`が唯一の対応表）。
///
/// **複合マスクで絞らないこと**（BUG-048）。`FileSystemRights`を`Write`のような
/// 複合値と比べると`READ_CONTROL`/`SYNCHRONIZE`を共有する読取専用ACEまで当たり、
/// **`ro`宛のACEを`rwx`宛と誤認して**「DENYを置いたのに走った」に戻る。原子ビットで見る。
///
/// 2本という本数そのものは[`WS_CAP_SID_SCRIPT`]の絞り込みが正しいかの検算でもあるので、
/// **0本と複数本を別のメッセージで落とす**（どちらも「絞り方が実装とずれた」の症状だが、
/// ずれ方が逆であり、混ぜると次に読む人が原因を取り違える）。
fn workspace_capability_sid(ws: &Path) -> Result<String, String> {
    let script = WS_CAP_SID_SCRIPT.replace("@WS@", &ws.display().to_string());
    let found = powershell(&script)?;
    let sids: Vec<&str> = found
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    match sids.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(format!(
            "{} に継承あり＋書込権を持つworkspace capability ACE（S-1-15-3-*）が1本も無い。\
             preflightが付与に失敗しているか、SIDの選び方が実装とずれている（D-54/D-84）",
            ws.display()
        )),
        many => Err(format!(
            "書込権を持つworkspace capability ACEが{}本あり、どれを止めるべきか決められない: \
             {many:?}（D-84で配るのは`rwx`と`ro`の2本だが、書込権を持つのは`rwx`の1本だけの\
             はずである。2本以上当たるなら絞り込みが実装とずれている）",
            many.len()
        )),
    }
}

/// [D-84] `0x20`（`FILE_EXECUTE`）**と**`0x2`（`FILE_WRITE_DATA`）の両方を持つ継承ACEだけを
/// 拾う。前者だけだと`ro`宛のACEまで当たる（`workspace_capability_sid`のdoc）。
/// どちらも**原子ビット**であって複合マスクではない（BUG-048）。
const WS_CAP_SID_SCRIPT: &str = "\
@((Get-Acl -LiteralPath '@WS@').Access | \
  Where-Object { $_.IdentityReference.Value -like 'S-1-15-3-*' -and \
                 (([int]$_.InheritanceFlags -band 2) -eq 2) -and \
                 (([int]$_.FileSystemRights -band 0x20) -eq 0x20) -and \
                 (([int]$_.FileSystemRights -band 0x2) -eq 0x2) -and \
                 ($_.AccessControlType -eq 'Allow') } | \
  ForEach-Object { $_.IdentityReference.Value }) -join \"`n\"";

/// `file`へ`sid`宛の**明示DENY** ACEを1本足し、**読み返して載ったことを確かめる**
/// （`test-logic-rules`型A: 「設定した」と「効いている」は別の事実）。
/// `rights`は`FileSystemRights`の数値（`0x20`=`ExecuteFile`、`0x1`=`ReadData`）。
fn add_deny_ace(file: &Path, sid: &str, rights: u32) -> Result<(), String> {
    let script = DENY_ACE_SCRIPT
        .replace("@FILE@", &file.display().to_string())
        .replace("@SID@", sid)
        .replace("@RIGHTS@", &format!("{rights}"));
    let echoed = powershell(&script)?;
    if !echoed.contains("DENY_VERIFIED") {
        return Err(format!(
            "{} へのDENY ACE（rights=0x{rights:x}）が読み返しで確認できなかった: {echoed}",
            file.display()
        ));
    }
    Ok(())
}

const DENY_ACE_SCRIPT: &str = "\
$f='@FILE@'; \
$acl = Get-Acl -LiteralPath $f; \
$id = New-Object System.Security.Principal.SecurityIdentifier('@SID@'); \
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(\
  $id, [System.Security.AccessControl.FileSystemRights]@RIGHTS@, 'None', 'None', 'Deny'); \
$acl.AddAccessRule($rule); \
Set-Acl -LiteralPath $f -AclObject $acl; \
$back = (Get-Acl -LiteralPath $f).Access | Where-Object { \
  $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -eq '@SID@' -and \
  (([int]$_.FileSystemRights -band @RIGHTS@) -eq @RIGHTS@) }; \
if ($back) { 'DENY_VERIFIED' } else { 'DENY_MISSING' }";

/// `file`のcapability SID宛**ALLOW**を`rights`へ張り替える（D-79が採る形）。
///
/// 明示DENYを足す[`add_deny_ace`]との違いが本測定の核心である——AppContainerの
/// アクセスチェックはcapability SIDを**許可の側でしか見ない**ので、DENYは素通りする。
/// 止めたければ「許可しない」しかない。
///
/// 手順は2段。(1) そのファイルの継承を切って継承ACEを明示コピーへ移し
/// （切らないとworkspace rootの継承ALLOWが実行権を運び続ける）、(2) capability SID宛の
/// ルールを全消しして`rights`のALLOWを1本だけ置く。`PurgeAccessRules`はDENYも消すので、
/// ラウンドBで置いたDENYはここで無くなる（ラウンドCを単独の条件として測るため）。
fn strip_capability_right(file: &Path, sid: &str, rights: u32) -> Result<(), String> {
    let script = STRIP_ACE_SCRIPT
        .replace("@FILE@", &file.display().to_string())
        .replace("@SID@", sid)
        .replace("@RIGHTS@", &format!("{rights}"));
    let echoed = powershell(&script)?;
    if !echoed.contains("STRIP_VERIFIED") {
        return Err(format!(
            "{} のcapability ALLOWを0x{rights:x}へ張り替えられなかった: {echoed}",
            file.display()
        ));
    }
    Ok(())
}

const STRIP_ACE_SCRIPT: &str = "\
$f='@FILE@'; \
$acl = Get-Acl -LiteralPath $f; \
$acl.SetAccessRuleProtection($true, $true); \
Set-Acl -LiteralPath $f -AclObject $acl; \
$acl = Get-Acl -LiteralPath $f; \
$id = New-Object System.Security.Principal.SecurityIdentifier('@SID@'); \
[void]$acl.PurgeAccessRules($id); \
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(\
  $id, [System.Security.AccessControl.FileSystemRights]@RIGHTS@, 'None', 'None', 'Allow'); \
$acl.AddAccessRule($rule); \
Set-Acl -LiteralPath $f -AclObject $acl; \
$back = @((Get-Acl -LiteralPath $f).Access | \
  Where-Object { $_.IdentityReference.Value -eq '@SID@' }); \
if ($back.Count -eq 1 -and $back[0].AccessControlType -eq 'Allow' -and \
    [int]$back[0].FileSystemRights -eq @RIGHTS@) { 'STRIP_VERIFIED' } \
else { 'STRIP_UNEXPECTED:' + (($back | ForEach-Object { \
  $_.AccessControlType.ToString() + ':' + [int]$_.FileSystemRights }) -join ',') }";

/// `file`のDACLを全件、`種別 0xマスク 継承 宛先SID`の形で返す（記録用）。
fn full_dacl(file: &Path) -> Result<String, String> {
    let script = FULL_DACL_SCRIPT.replace("@FILE@", &file.display().to_string());
    powershell(&script)
}

const FULL_DACL_SCRIPT: &str = "\
(Get-Acl -LiteralPath '@FILE@').Access | ForEach-Object { \
  '{0,-5} 0x{1:x8} inherited={2,-5} {3}' -f $_.AccessControlType, \
  ([int]$_.FileSystemRights), $_.IsInherited, $_.IdentityReference.Value }";

/// `file`に載っているcapability SID宛の**ALLOW**が1本だけであることを確かめ、そのマスクを返す。
/// 2本以上あると「どれを落とせばよいか」が決まらないので、黙って先頭を採らずエラーにする。
fn capability_allow_mask(file: &Path, sid: &str) -> Result<u32, String> {
    let listed = capability_aces_on(file, sid)?;
    let masks: Vec<u32> = listed
        .split(',')
        .filter_map(|e| e.trim().strip_prefix("Allow:"))
        .filter_map(|m| m.trim().parse::<u32>().ok())
        .collect();
    match masks.as_slice() {
        [one] => Ok(*one),
        _ => Err(format!(
            "{} のcapability ALLOWが1本に決まらない: {listed:?}",
            file.display()
        )),
    }
}

/// `file`に載っているcapability SID宛のACEを`種別:マスク`の一覧で返す。
/// ラウンドCの**後**にもう一度読むために要る——preflightが再付与していたら、
/// 「走らなかった」も「走った」も手術の結果として読めない（`test-logic-rules`型A）。
fn capability_aces_on(file: &Path, sid: &str) -> Result<String, String> {
    let script = READ_CAP_ACE_SCRIPT
        .replace("@FILE@", &file.display().to_string())
        .replace("@SID@", sid);
    powershell(&script)
}

const READ_CAP_ACE_SCRIPT: &str = "\
(@((Get-Acl -LiteralPath '@FILE@').Access | \
  Where-Object { $_.IdentityReference.Value -eq '@SID@' } | \
  ForEach-Object { $_.AccessControlType.ToString() + ':' + [int]$_.FileSystemRights }) \
  -join ',')";

/// この機のPython（uv管理）の在処。無ければ`None`——**黙って飛ばさず**、呼び出し側が
/// 「測っていない」と印字する（`test-logic-rules`型B: 0件と未実行を区別する）。
fn uv_python_dir() -> Option<PathBuf> {
    let out = Command::new("uv").args(["python", "find"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let exe = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    let dir = exe.parent()?.to_path_buf();
    dir.is_dir().then_some(dir)
}

/// ワークスペースへ、実行を試みる対象を並べる。PEは`cmd.exe`の複製を使う——
/// `/c echo <token>`で「起動できた」ことが出力に出るうえ、この測定のために新しい
/// バイナリを作らずに済む（対象がcmdであること自体には意味が無い。**workspace内に在る
/// PEである**ことだけが効く）。
fn plant_exec_artifacts(ws: &Path, python_dir: Option<&Path>) -> Result<(), String> {
    let sys32 = PathBuf::from(r"C:\Windows\System32");
    std::fs::copy(sys32.join("cmd.exe"), ws.join("evil.exe"))
        .map_err(|e| format!("copy cmd.exe -> evil.exe: {e}"))?;
    let files: &[(&str, &str)] = &[
        ("evil.ps1", "Write-Output 'HP_C_PS1'\r\n"),
        ("evil_iex.ps1", "Write-Output 'HP_D_IEX'\r\n"),
        ("evil.cmd", "@echo off\r\n@echo HP_E_CMD\r\n"),
        ("evil2.cmd", "@echo off\r\n@echo HP_I_CMDX\r\n"),
        ("evil_readdeny.ps1", "Write-Output 'HP_H_RDENY'\r\n"),
        ("evil.py", "print(\"HP_G_PY\")\r\n"),
    ];
    for (name, body) in files {
        std::fs::write(ws.join(name), body).map_err(|e| format!("write {name}: {e}"))?;
    }
    if let Some(src) = python_dir {
        let script = COPY_PY_SCRIPT
            .replace("@SRC@", &src.display().to_string())
            .replace("@DST@", &ws.join("py").display().to_string());
        powershell(&script)?;
        if !ws.join("py").join("python.exe").is_file() {
            return Err("pythonの複製に失敗した（py\\python.exe が無い）".to_string());
        }
    }
    Ok(())
}

const COPY_PY_SCRIPT: &str =
    "Copy-Item -LiteralPath '@SRC@' -Destination '@DST@' -Recurse -Force; 'copied'";

/// 1ラウンド走らせて、どのトークンが出力に現れたかを返す。
fn run_exec_probe(ws: &Path, case_name: &str, with_python: bool) -> Result<Vec<String>, String> {
    let script =
        EXEC_PROBE_SCRIPT.replace("@PY@", if with_python { EXEC_PROBE_PY_LINE } else { "" });
    let run = run_harness(
        ws,
        &run_shell_script_turns(&script),
        &["--sandbox", "tier2a"],
        case_name,
    );
    if !run.status.success() {
        return Err(format!(
            "harness invocation itself failed ({}): {}",
            run.status, run.stderr
        ));
    }
    let outcome = parse_json_stdout(&run)?;
    let text = outcome.first_tool_result()?.to_string();
    // B-12型の穴を塞ぐ: 「トークンが無い」を「起動できなかった」と読む前に、
    // **スクリプトが最後まで走ったこと**を確かめる。途中で死んでいれば以降は全部
    // 「起動できなかった」に見える。
    if !text.contains("HP_PROBE_DONE") {
        let hint = if text.contains("permission denied by policy") {
            "（run_shellがツール層で拒否されている。プローブ文字列がT-09の危険構文マーカー\
             〔`permission.rs`の`looks_like_allowlist_bypass`〕を踏んでいないか見ること）"
        } else {
            ""
        };
        return Err(format!(
            "プローブスクリプトが最後まで走っていない（HP_PROBE_DONEが無い）。\
             以降のトークンの不在は「起動を拒否された」の証拠にならない{hint}: {text}"
        ));
    }
    eprintln!("[exec-ace] --- round {case_name} raw output ---\n{text}\n[exec-ace] --- end ---");
    Ok(EXEC_PROBES
        .iter()
        .filter(|p| text.contains(p.token))
        .map(|p| p.name.to_string())
        .collect())
}

/// 撤収（`bug-pattern-rules` B-01）。workspace capability ACEは**セッションを跨いで残る**
/// 設計（D-54）なので、ディレクトリを消すだけでは台帳にエントリが残る。
fn exec_ace_teardown(ws: &Path) {
    let out = Command::new(harness_exe())
        .args(["fs", "revoke-workspace"])
        .arg(ws)
        .output();
    match out {
        Ok(o) => eprintln!(
            "[exec-ace] fs revoke-workspace -> {} {}",
            o.status,
            String::from_utf8_lossy(&o.stdout).trim()
        ),
        Err(e) => eprintln!("[exec-ace] fs revoke-workspace failed to spawn: {e}"),
    }
    let _ = std::fs::remove_dir_all(ws);
}

/// **「止まらない」と「出られない」は別の軸である**、を1回の測定で示す。
///
/// §S8が確定させたのは前者（ワークスペース内のexeは走る）だけで、そこから
/// 「だから外へも出られる」と読めてしまう。**読めてしまうのは、2つの軸を別々に測って
/// 別々に報告したからである**（`premise-first-explanation`型7: 機構を説明したら限界を
/// 同じ場所で言う——逆に、限界を言うときは**守れている方も同じ場所で**言う）。
///
/// ここでは**同じ実行の同じ出力**が両方を示す。ワークスペース内へ置いたプローブexeが
///
/// - **起動できたこと**（JSON行が出る＝走った）
/// - **外へ出られないこと**（その行の`ok`が偽）
///
/// を同時に語る。片方だけを別のテストで測ると、また離れて読まれる。
///
/// D-14（`DESIGN-SANDBOX-APPPOLICY.md`）が「起動そのものは止めない。封じ込めで実害を止める」と
/// 決めている以上、**受容している残存リスクの実体を固定するのはこのテストである。**
#[test]
#[ignore = "実Tier2a。dev-elevated-runnerの e2e-exec-ace 経由で走らせること"]
fn tier2a_workspace_exec_runs_but_cannot_reach_the_network() {
    let _ex = cow_exclusive();
    // 宛先はTLSの443を開けている外部ホスト。**中身は取りに行かない**（TCPの接続可否だけを見る）。
    const HOST: &str = "1.1.1.1";
    const PORT: &str = "443";

    // --- 陽性対照: **同じ計器**でコンテナ外からは繋がること。
    // これが落ちたら、中からの失敗を「封じ込めのおかげ」と読んではいけない（B-29）。
    let outside = Command::new(net_probe_exe())
        .args(["raw-connect", HOST, PORT, "--label", "outside"])
        .output()
        .expect("run the probe outside the container");
    let outside_text = String::from_utf8_lossy(&outside.stdout).to_string();
    let outside_ok = outside_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("probe").and_then(|p| p.as_str()) == Some("raw_connect"))
        .and_then(|v| v["ok"].as_bool());
    assert_eq!(
        outside_ok,
        Some(true),
        "対照が落ちた＝コンテナ外からも {HOST}:{PORT} へ繋がらない。\
         この機に外向きの経路が無いので、中からの失敗は何も証明しない。out={outside_text}"
    );

    // --- 本題: ワークスペース**内**へ置いたexeを、サンドボックスから起動する ---
    let name = "exec-ace-net";
    let ws = case_dir("exec-ace-net");
    std::fs::copy(net_probe_exe(), ws.join("netprobe.exe"))
        .expect("copy the probe into the workspace");

    let script = format!(".\\netprobe.exe raw-connect {HOST} {PORT} --label inside");
    let run = run_harness(
        &ws,
        &run_shell_script_turns(&script),
        &["--sandbox", "tier2a"],
        name,
    );
    let outcome = match parse_json_stdout(&run) {
        Ok(v) => v,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("{e}");
        }
    };
    let result_text = outcome.first_tool_result().unwrap_or("").to_string();
    let inside = result_text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .rfind(|v| v.get("probe").and_then(|p| p.as_str()) == Some("raw_connect"));

    let verdict = serde_json::json!({
        "workspace_exe_started": inside.is_some(),
        "workspace_exe_reached_the_network": inside.as_ref().and_then(|v| v["ok"].as_bool()),
        "probe": inside,
    });
    println!("{verdict}");

    let mut failures: Vec<String> = Vec::new();
    // (1) 走ったこと。走っていなければ「出られない」は封じ込めの手柄ではない。
    let Some(probe) = inside else {
        exec_ace_teardown(&ws);
        panic!(
            "ワークスペース内のexeがそもそも起動していない（JSON行が無い）。\
             **このテストが測りたい状況が成立していない**: {result_text}"
        );
    };
    // (2) 出られないこと。
    if probe["ok"].as_bool() != Some(false) {
        failures.push(format!(
            "**ワークスペース内のexeが外部へ到達した。** D-14が受容している残存リスクの前提\
             （起動は止めないが封じ込めで実害を止める）が崩れている: {probe}"
        ));
    }

    if failures.is_empty() {
        exec_ace_teardown(&ws);
    } else {
        eprintln!(
            "[exec-ace-net] 失敗したのでワークスペースを {} に残す",
            ws.display()
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "実Tier2a。dev-elevated-runnerの e2e-exec-ace 経由で走らせること"]
fn tier2a_workspace_exec_ace_matrix() {
    let _ex = cow_exclusive();
    let ws = case_dir("exec-ace");
    let python_dir = uv_python_dir();
    if python_dir.is_none() {
        eprintln!(
            "[exec-ace] このマシンで`uv python find`が解決しなかったので、`evil.py`の経路は\
             **測っていない**（結果表では skipped と表示する）"
        );
    }
    let with_python = python_dir.is_some();

    if let Err(e) = plant_exec_artifacts(&ws, python_dir.as_deref()) {
        exec_ace_teardown(&ws);
        panic!("測定対象を置けなかった: {e}");
    }

    // --- ラウンドA: 既定のACEのまま。全経路が走ることを確かめる ---
    let ran_a = match run_exec_probe(&ws, "exec-ace-round-a", with_python) {
        Ok(v) => v,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("round A: {e}");
        }
    };

    // --- 手術の宛先を決める ---
    let sid = match workspace_capability_sid(&ws) {
        Ok(s) => s,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("workspace capability SIDが引けない: {e}");
        }
    };
    eprintln!("[exec-ace] workspace capability SID = {sid}");

    // 落とす前のマスクは**実物から読む**（`workspace_rwx_mask()`の値をテストへ書き写すと、
    // 製品側が変わったときにテストだけが古い値を測り続ける。B-05）。
    let granted = match capability_allow_mask(&ws.join("evil.exe"), &sid) {
        Ok(m) => m,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("付与済みマスクが読めない: {e}");
        }
    };
    eprintln!("[exec-ace] workspace配下へ実際に付いているマスク = 0x{granted:x}");

    const EXECUTE_FILE: u32 = 0x20;
    const READ_DATA: u32 = 0x1;
    let mut targets: Vec<(&str, u32)> = vec![
        ("evil.exe", EXECUTE_FILE),
        ("evil.ps1", EXECUTE_FILE),
        ("evil_iex.ps1", EXECUTE_FILE),
        ("evil.cmd", EXECUTE_FILE),
        ("evil2.cmd", EXECUTE_FILE),
        ("evil_readdeny.ps1", READ_DATA),
    ];
    if with_python {
        targets.push(("evil.py", EXECUTE_FILE));
    }

    // --- ラウンドB: 対象ファイルへ**明示DENY**を1本足す ---
    for (name, right) in &targets {
        if let Err(e) = add_deny_ace(&ws.join(name), &sid, *right) {
            exec_ace_teardown(&ws);
            panic!("DENY ACEを置けなかった: {e}");
        }
    }
    eprintln!("[exec-ace] {} 件のDENY ACEを置いた", targets.len());
    let ran_b = match run_exec_probe(&ws, "exec-ace-round-b", with_python) {
        Ok(v) => v,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("round B: {e}");
        }
    };

    // --- ラウンドC: capability SID宛**ALLOWから権利を落とす**（D-79が採る形） ---
    for (name, right) in &targets {
        let want = granted & !right;
        if let Err(e) = strip_capability_right(&ws.join(name), &sid, want) {
            exec_ace_teardown(&ws);
            panic!("ALLOWの張り替えに失敗した: {e}");
        }
    }
    eprintln!("[exec-ace] {} 件のALLOWから権利を落とした", targets.len());
    // 手術後のDACLを**丸ごと**残す。ラウンドCの結論（「capability SIDのALLOWが決め手」）は、
    // 「同じファイルがAdministratorsやAuthenticated Usersには依然フルに許可されている」
    // ことと対にして初めて言える。推論ではなく記録にしておく。
    match full_dacl(&ws.join("evil.exe")) {
        Ok(d) => eprintln!("[exec-ace] evil.exe のDACL（手術後）:\n{d}"),
        Err(e) => eprintln!("[exec-ace] evil.exe のDACLを読めなかった: {e}"),
    }
    let ran_c = match run_exec_probe(&ws, "exec-ace-round-c", with_python) {
        Ok(v) => v,
        Err(e) => {
            exec_ace_teardown(&ws);
            panic!("round C: {e}");
        }
    };

    // --- ラウンドCの手術が生き残ったかを読み返す ---
    //
    // preflightが再付与していたら、Cの結果は「手術の効果」として読めない
    // （`test-logic-rules`型A: 設定したことと効いていることは別の事実）。
    let mut surgery_lost: Vec<String> = Vec::new();
    for (name, right) in &targets {
        let want = granted & !right;
        match capability_aces_on(&ws.join(name), &sid) {
            Ok(actual) => {
                let expected = format!("Allow:{want}");
                if actual.trim() != expected {
                    surgery_lost.push(format!(
                        "{name}: ラウンドCの後にcapability ACEが {actual:?} になっている\
                         （期待 {expected:?}）。preflightの再付与に上書きされた疑いがあり、\
                         このファイルのCの結果は読めない"
                    ));
                }
            }
            Err(e) => surgery_lost.push(format!("{name}: 読み返せない: {e}")),
        }
    }

    // --- 判定 ---
    let mut failures: Vec<String> = surgery_lost;
    for probe in EXEC_PROBES {
        let skipped = probe.name == "python-script" && !with_python;
        let a = ran_a.iter().any(|n| n == probe.name);
        let b = ran_b.iter().any(|n| n == probe.name);
        let c = ran_c.iter().any(|n| n == probe.name);
        let word = |x: bool| if x { "ran" } else { "blocked" };
        println!(
            "{}",
            serde_json::json!({
                "probe": probe.name,
                "token": probe.token,
                "round_a_default": if skipped { serde_json::Value::Null } else { a.into() },
                "round_b_explicit_deny": if skipped { serde_json::Value::Null } else { b.into() },
                "round_c_allow_without_the_right":
                    if skipped { serde_json::Value::Null } else { c.into() },
                "expected_b": probe.runs_in_b,
                "expected_c": probe.runs_in_c,
                "why": probe.why,
                "verdict": if skipped {
                    "skipped".to_string()
                } else {
                    format!("A={} B={} C={}", word(a), word(b), word(c))
                },
            })
        );
        if skipped {
            continue;
        }
        if !a {
            failures.push(format!(
                "{}: ラウンドA（既定のACE）で走らなかった。この経路は計器として使えないので、\
                 B・Cの結果も読めない",
                probe.name
            ));
            continue;
        }
        if b != probe.runs_in_b {
            failures.push(format!(
                "{}: ラウンドB（明示DENY）の期待は{}だが実際は{}（想定: {}）",
                probe.name,
                word(probe.runs_in_b),
                word(b),
                probe.why
            ));
        }
        if c != probe.runs_in_c {
            failures.push(format!(
                "{}: ラウンドC（ALLOWから権利を落とす）の期待は{}だが実際は{}（想定: {}）",
                probe.name,
                word(probe.runs_in_c),
                word(c),
                probe.why
            ));
        }
    }

    if failures.is_empty() {
        exec_ace_teardown(&ws);
    } else {
        eprintln!(
            "[exec-ace] 失敗したのでワークスペースを {} に残す（調査用）",
            ws.display()
        );
    }
    assert!(
        failures.is_empty(),
        "workspace exec ACE matrix:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// [⑤'] 遷移MACの強制を、製品の経路で初めて起こす（`--enforce-transitions`）
// ---------------------------------------------------------------------------

/// この回で起こす「外部プログラム」。
///
/// # なぜ`findstr.exe`なのか（`cmd.exe`でも`git`でもなく）
///
/// - **System32の実体のexe**なので、AppContainerから確実に読めて実行できる
///   （`git`はインストール先のACL次第で、「断られた」のか「届かなかった」のかが混ざる）
/// - **`cmd /c`は使えない。** ツール層の危険構文検出（`harness-engine`の
///   `looks_like_allowlist_bypass`）が`accept-all`でも拒否するので、
///   **サンドボックスへ届く前に止まる**——「遷移が断られた」と区別が付かない
/// - 標準入力から受けた行をそのまま出すので、**印を自分で決められる**
fn system_findstr_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\findstr.exe")
}

const TRANSITION_MARKER: &str = "HP_TRANSITION_RAN";

/// 1腕撃って`run_shell`の結果本文を返す。**旗は常に立てる**——立てない側の挙動は
/// 既存のケースが全部測っている。
fn run_transition_arm(ws: &Path, case_name: &str) -> Result<String, String> {
    let script = format!("'{TRANSITION_MARKER}' | findstr.exe HP_TRANSITION");
    let run = run_harness(
        ws,
        &run_shell_script_turns(&script),
        &["--sandbox", "tier2a", "--enforce-transitions"],
        case_name,
    );
    if !run.status.success() {
        return Err(format!(
            "harness itself failed to run ({}). **拒否ではなく起動の失敗である**: {}",
            run.status, run.stderr
        ));
    }
    // 窓口（`can_run_program`）がモデルへ見えていること。強制が効いている回にだけ出る
    // （`startup::transition_tool::should_expose`の3条件）。
    assert_prompt_sane(&run, &["can_run_program"])?;
    let outcome = parse_json_stdout(&run)?;
    let text = outcome.first_tool_result()?.to_string();
    eprintln!(
        "[transition-enforced] --- {case_name} ---\n{text}\n[transition-enforced] --- end ---"
    );
    Ok(text)
}

/// 宣言を`exes`本だけ持つ`policy.json`をワークスペースへ置く。
///
/// **空を渡したら`policy.json`ごと消す。** 「宣言が0本のファイル」と「ファイルが無い」を
/// 同じ入口で表せるようにするためで、残課題#39の測定が**宣言を1本ずつ足していく**形を
/// 採っている（0本から始まる）。空の`transitions`を書いて「0本を宣言した」ことにすると、
/// 編集時検査の対象が増えるだけで得が無い。
///
/// **入口ドメインの名前は`harness-policy`の定数から取る**——綴りを写すと、
/// あちらが変わった日にこのテストだけが「宣言していない」状態で緑になる（`B-13`）。
fn declare_programs(ws: &Path, exes: &[String]) -> Result<(), String> {
    if exes.is_empty() {
        // 置き場は`harness-policy`に聞く（綴りを写さない。`B-05`）。
        let path = harness_policy::policy_file::path(ws);
        match std::fs::remove_file(&path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("policy.jsonを消せない（{}）: {e}", path.display())),
        }
    }
    // **同じ綴りを2本書かない。** 重複した辺は編集時検査を通らず、`policy.json`が
    // まるごと効かなくなる——症状は「宣言したのに断られる」で、宣言側を疑いにくい
    // （2026-09-18に踏んだ。待ち行列の更新行をそのまま足していた）。
    for (i, exe) in exes.iter().enumerate() {
        if exes[..i].iter().any(|d| d.eq_ignore_ascii_case(exe)) {
            return Err(format!("宣言に同じ綴りが2本ある: {exe}"));
        }
    }
    let mut file = harness_policy::policy_file::PolicyFile::default();
    let mut domain =
        harness_policy::policy_file::PolicyDomain::new(harness_policy::policy_file::ENTRY_DOMAIN);
    let edges: Vec<serde_json::Value> = exes
        .iter()
        .map(|exe| {
            serde_json::json!({
                "exe": { "literal": exe },
                "argv": { "any": true },
                "to": harness_policy::policy_file::ENTRY_DOMAIN,
            })
        })
        .collect();
    domain.process = serde_json::from_value(serde_json::json!({ "transitions": edges }))
        .map_err(|e| format!("遷移の宣言が組めない: {e}"))?;
    file.domains.push(domain);
    harness_policy::policy_file::save(ws, &file).map_err(|e| format!("policy.jsonを書けない: {e}"))
}

/// [残課題#39] **書いた宣言が本当に「別ドメインへ渡る形」になっているか**を、書いた後に読み返す。
///
/// # なぜ結果からの推論で済ませないのか
///
/// この測定が新しく振った軸は「遷移先が別のドメインかどうか」1本だけである。
/// **その軸が実際に振れたことを見る検算が無いと、軸を振ったつもりの測定がそのまま
/// 結果として記録される**（`measurement-review`の検問3）。
///
/// たとえば鎖を組む側が`to`を入口ドメインのまま書いていても、**発火する腕は同じように
/// 発火する**——§S64（自己ループで測ったもの）と見分けが付かない。
///
/// 見るのは2つ。**どの辺も自分のドメインへは戻らない**ことと、
/// **遷移先が`min_targets`種類以上ある**ことである。
///
/// # なぜ本数を呼び出し側から渡すのか
///
/// 「何種類あれば跨いだと言えるか」は**測る形で変わる**。鎖を何段も伸ばす腕なら2種類以上で
/// なければ鎖になっていないが、**1段しか宣言しない腕もある**（遷移先が呼び出し元より狭いかを
/// 見る腕）。ここで2を決め打ちすると、**正しく跨いでいる1段の腕が赤くなる**
/// ——2026-09-20に実際に赤くした。
fn assert_chain_crosses_domains(ws: &Path, case_name: &str, min_targets: usize) {
    let policy = harness_policy::policy_file::load(ws)
        .unwrap_or_else(|e| panic!("{case_name}: 書いたばかりの宣言を読み返せない: {e}"));
    let mut targets: Vec<String> = Vec::new();
    for domain in &policy.domains {
        for edge in &domain.process.transitions {
            assert_ne!(
                edge.to, domain.name,
                "{case_name}: 辺が自分のドメインへ戻っている（自己ループ）。\
                 **この測定は§S64と同じものを測っている**ことになり、\
                 「別ドメインを跨いだ」とは言えない: {policy:?}"
            );
            if !targets.contains(&edge.to) {
                targets.push(edge.to.clone());
            }
        }
    }
    assert!(
        targets.len() >= min_targets,
        "{case_name}: 遷移先が{}種類しかない（{min_targets}種類以上を期待）。\
         鎖が途中で終わっているか、すべて同じドメインへ集まっている: 遷移先={targets:?}",
        targets.len()
    );
}

/// [残課題#39] 鎖を**1段ごとに別のドメインへ渡る形**で宣言する。
///
/// # `declare_programs`と何が違うのか
///
/// あちらは全部の辺を**入口ドメインの自己ループ**として書く（`to`が入口自身）。
/// つまり鎖の何段目に居ても遷移元は同じドメインなので、**「どこから起こされたか」で
/// 許否が変わることを1度も測っていない**。
///
/// ここは`hops[i]`の遷移元を「1つ前の段の遷移先」にする。
///
/// ```text
///   declare_programs:  入口 --git--> 入口 --git--> 入口 --findstr--> 入口
///   declare_chain:     入口 --git--> d0  --git--> d1  --findstr--> d2
/// ```
///
/// # 遷移先ドメインは宣言を1件も持たない
///
/// 持たせると**用意できない**——骨格では「既に許可済みの宣言」しか引けないので
/// （`domain_provision`のモジュールdoc）、宣言を足した瞬間にそのドメインへの遷移が
/// `target_domain_not_provisioned`で断られ、**測っているものが遷移の許否ではなくなる**。
///
/// 宣言が空なら権限は入口と等しいので、編集時検査の縮小性（§19.3.4）も通る。
///
/// # 名前を短くしてある理由
///
/// 遷移先ドメインの入れ物の名前は`harness.domain.<セッションの印>.<ドメイン名>`で、
/// **64文字を超えると用意できない**（実機で確認済み。受入の負側がその形を使っている）。
/// セッションの印だけで17文字前後あるので、ここは`d0`・`d1`のような短い名前にする。
fn declare_chain(ws: &Path, hops: &[String]) -> Result<(), String> {
    declare_chain_from(ws, hops, harness_policy::policy_file::ENTRY_DOMAIN)
}

/// [残課題#39] 鎖の出発点を選べる版（測定(c)が**2本目の鎖**を足すのに使う）。
fn declare_chain_from(ws: &Path, hops: &[String], from: &str) -> Result<(), String> {
    let mut file = harness_policy::policy_file::PolicyFile::default();
    add_chain(&mut file, hops, from)?;
    harness_policy::policy_file::save(ws, &file).map_err(|e| format!("policy.jsonを書けない: {e}"))
}

/// 鎖1本を宣言へ足す。**同じドメインが既に在れば辺を足す**（作り直さない）。
fn add_chain(
    file: &mut harness_policy::policy_file::PolicyFile,
    hops: &[String],
    from: &str,
) -> Result<(), String> {
    let mut current = from.to_string();
    for (i, exe) in hops.iter().enumerate() {
        // 遷移先の名前。**出発点ごとに別の綴りにする**——2本の鎖が同じ中継ドメインを
        // 共有してしまうと、測定(c)が「辺か経路か」を判別できなくなる。
        let to = format!("{}d{i}", chain_prefix(from));
        add_edge(file, &current, exe, &to)?;
        current = to;
    }
    Ok(())
}

/// 鎖ごとのドメイン名の接頭辞。入口から伸びる鎖は`d0`・`d1`…、別の出発点は`xd0`・`xd1`…。
fn chain_prefix(from: &str) -> &'static str {
    if from == harness_policy::policy_file::ENTRY_DOMAIN {
        ""
    } else {
        "x"
    }
}

/// 辺を1本足す。遷移元のドメインが無ければ作り、遷移先の定義も（空で）作る。
///
/// **遷移先の定義を作るのを忘れない**——`to`が指す先の定義が無いと、
/// 起動時の用意が「定義が無い」で断り、鎖がそこで切れる。
fn add_edge(
    file: &mut harness_policy::policy_file::PolicyFile,
    from: &str,
    exe: &str,
    to: &str,
) -> Result<(), String> {
    use harness_policy::policy_file::PolicyDomain;

    if !file.domains.iter().any(|d| d.name == to) {
        file.domains.push(PolicyDomain::new(to));
    }
    if !file.domains.iter().any(|d| d.name == from) {
        file.domains.push(PolicyDomain::new(from));
    }
    let domain = file
        .domains
        .iter_mut()
        .find(|d| d.name == from)
        .expect("just inserted");
    let mut edges: Vec<serde_json::Value> = domain
        .process
        .transitions
        .iter()
        .map(|e| serde_json::to_value(e).expect("an existing edge must serialize"))
        .collect();
    edges.push(serde_json::json!({
        "exe": { "literal": exe },
        "argv": { "any": true },
        "to": to,
    }));
    domain.process = serde_json::from_value(serde_json::json!({ "transitions": edges }))
        .map_err(|e| format!("遷移の宣言が組めない（{from} -> {to}）: {e}"))?;
    Ok(())
}

/// **⑤'の測定**: 生成禁止を積んだセッションで、宣言していないプログラムは断られ、
/// **その事実がモデルへ届く**。宣言すれば同じコマンドが通る。
///
/// # 対で撃つ理由（`B-35`）
///
/// 腕1だけだと「全部断る」実装で緑になり、腕2だけだと「全部通す」実装で緑になる。
/// **変えるのは`policy.json`の1行だけ**で、コマンドも旗も同じにする。
///
/// # ここでしか見られないもの
///
/// - **拒否の注記が製品の経路で出ること**（段階6f-3。単体テストが固定しているのは
///   注記の組み立てと、それを出すかの真偽値まで）
/// - **シェルが`powershell5.1(Tier2a)`になっていること**（残課題#50の規則。生成禁止を
///   積むとストアの実行エイリアスは候補から外れる。単体テストが見ているのは候補の並びまで）
#[test]
#[ignore = "starts a real Tier2a session with the transition MAC enforced; run through dev-elevated-run"]
fn enforcing_transitions_denies_undeclared_programs_and_tells_the_model_how_to_fix_it() {
    let ws = case_dir("transition-enforced");
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("workspace dir");

    // --- 腕1: 宣言なし ---
    let denied = run_transition_arm(&ws, "transition-enforced-deny")
        .unwrap_or_else(|e| panic!("腕1（宣言なし）が測れなかった: {e}"));

    let mut failures: Vec<String> = Vec::new();
    // **印の有無で「走ったか」を判定してはいけない**（2026-09-18に実際に踏んだ）。
    // PowerShellは失敗したコマンド行を**そのままエラー本文へ反射する**ので、
    // 起動できなかった回でも印の文字列が出力に現れる。**計器が自分の入力を映している。**
    // だから走ったかどうかは、`run_shell`自身が付ける終了コードの行で見る。
    if denied.contains("[exit code: 0]") {
        failures.push(
            "腕1: 宣言していないプログラムが**走ってしまった**（終了コードが0）。\
             生成禁止が積まれていないか、Daemonが判定していない"
                .to_string(),
        );
    }
    if !denied.contains("Access is denied") && !denied.contains("アクセスが拒否") {
        failures.push(format!(
            "腕1: 断り方が想定と違う。**フックがDaemonへ頼んで断られた**なら\
             `ERROR_ACCESS_DENIED`が返るはずである（`DESIGN-MAC-ENFORCEMENT.md` §10.1.2の\
             「4つの原因に4つの値」）: {denied}"
        ));
    }
    if !denied.contains("[transition:") {
        failures.push(
            "腕1: 断られたのに**注記が出ていない**。モデルには生のWin32エラーしか届かず、\
             宣言の直し方へ辿り着けない（段階6f-3の配線が効いていない）"
                .to_string(),
        );
    }
    if !denied.contains("can_run_program") {
        failures.push(
            "腕1: 注記が窓口（`can_run_program`）を案内していない。案内が無いと、\
             pull方式のツールは永久に呼ばれない"
                .to_string(),
        );
    }
    if !denied.contains("powershell5.1(Tier2a)") {
        failures.push(format!(
            "腕1: シェルが`powershell5.1(Tier2a)`ではない。生成禁止を積む回は、\
             ストアの実行エイリアスを候補から外して実体のexeへ落ちなければならない\
             （残課題#50・§S62）。出力: {denied}"
        ));
    }

    // 待ち行列に残っていること（注記は出たが記録が無い、という状態を作らない）。
    let queue = ws
        .join(".harness")
        .join("transitions")
        .join("pending.jsonl");
    match std::fs::read_to_string(&queue) {
        Ok(text) if text.contains("denied_by_daemon") => {}
        Ok(text) => failures.push(format!(
            "腕1: 待ち行列に拒否の行が無い（{}）: {text:?}",
            queue.display()
        )),
        Err(e) => failures.push(format!(
            "腕1: 待ち行列が読めない（{}）: {e}",
            queue.display()
        )),
    }

    // --- 腕2: 同じコマンドを、宣言してから撃つ ---
    declare_programs(&ws, &[system_findstr_exe()])
        .unwrap_or_else(|e| panic!("腕2の宣言を書けなかった: {e}"));
    let allowed = run_transition_arm(&ws, "transition-enforced-allow")
        .unwrap_or_else(|e| panic!("腕2（宣言あり）が測れなかった: {e}"));

    if !allowed.contains("[exit code: 0]") || !allowed.contains(TRANSITION_MARKER) {
        failures.push(format!(
            "腕2: **宣言したのに走らなかった**。宣言が判定器へ届いていないか、\
             Daemonが起こせていない（終了コード0と印`{TRANSITION_MARKER}`の両方が要る\
             ——印だけだとエラー本文の反射と区別が付かない）: {allowed}"
        ));
    }
    if allowed.contains("[transition:") {
        failures.push(format!(
            "腕2: 断られていないのに注記が出ている。**古い行を読んでいる**か、\
             差分ではなく全件を読んでいる: {allowed}"
        ));
    }

    if failures.is_empty() {
        cleanup_on_success(&ws, &[], "transition-enforced-deny");
        cleanup_on_success(&ws, &[], "transition-enforced-allow");
    } else {
        eprintln!(
            "[transition-enforced] 失敗したのでワークスペースを {} に残す（調査用）",
            ws.display()
        );
    }
    assert!(
        failures.is_empty(),
        "遷移MACの強制（製品経路）:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// [残課題#39] `.git/config`に仕掛けられた発火を、遷移MACは止められるのか
// ---------------------------------------------------------------------------

/// **仕掛けが起きた**ことの印。`findstr.exe`が自分で出す接頭辞で、**大文字である**。
///
/// # なぜこの文字列なら反射に当たらないのか
///
/// §S63で1度踏んだ——計器が自分の入力を映す形である。ここで入力になり得るのは2つで、
/// どちらもこの印を含まない。
///
/// | 何が反射し得るか | 何を映すか | `FINDSTR:`を含むか |
/// |---|---|---|
/// | PowerShellのエラー本文 | モデルが撃ったコマンド行（`git -c safe.directory=* diff`） | 含まない |
/// | gitの起動失敗メッセージ | `.git/config`の値（`C:/Windows/System32/findstr.exe`） | **含まない**（小文字） |
///
/// 照合は大小を区別する（`contains`）。小文字の`findstr.exe`に当たらないのが要である。
const GIT_TRAP_RAN_MARKER: &str = "FINDSTR:";

/// **仕掛けが止められた**ことの印。フックがDaemonへ頼んで断られたときの値
/// （`ERROR_ACCESS_DENIED`。§10.1.2「4つの原因に4つの値」）。
const GIT_TRAP_DENIED_MARKER: &str = "Access is denied";

/// モデルへ渡す台本。**全腕で同じ1手**にする（変えるのは`policy.json`と旗だけ）。
///
/// `-c safe.directory=*`が要るのは、ワークスペースを作るのが昇格したテストプロセスで、
/// サンドボックスの中のgitから見ると所有者が違うためである（既存の`GIT_INJECTION_SCRIPT`が
/// 同じ理由で同じ指定を使っている）。**危険構文検出には掛からない**——
/// `harness-engine`の`looks_like_allowlist_bypass`が見るのは`cmd /c`・`sh -c`・
/// `start-process`等で、この綴りはどれも含まない（含むと、サンドボックスへ届く前に
/// 止まって「遷移が断られた」と区別が付かなくなる）。
///
/// # 素の`git diff`である（2026-09-19に`--no-index`から戻した）
///
/// **素の`git diff`は、比べる元の版を一時ファイルへ書き出してから外部diffを起こす。**
/// 2026-09-18の測定（§S64）ではその一時ファイルがDaemon経由の子で作れず
/// （[BUG-160](../../../docs/bugs/BUG-160.md)。`TEMP`がAppContainerの置き換えを二重に受けた）、
/// **鎖の3段目が遷移MACではなくBUG-160で止まっていた**ので、一時ファイルの要らない
/// `--no-index`で迂回していた。
///
/// **BUG-160が直った（§S65）ので素の形へ戻してある。** 戻す意味は、
/// 素の`git diff`が**一時ファイルの書き出しを経由してから**外部diffを起こすことにある
/// ——迂回していた間は、その経路を1度も通さずに「止められる」と言っていた。
const GIT_TRAP_SCRIPT: &str = "git -c safe.directory=* diff";

/// 仕掛けが起こすプログラム。**System32の実体**を`.git/config`から名指しする。
///
/// # 攻撃者が現実に選べるものは、これしかない（2026-09-18に2つ潰して分かった）
///
/// [BUG-150](../../../docs/bugs/BUG-150.md)が実測した綴りは`touch HIT #`だが、**その形は
/// Tier2aの中では遷移MACが無くても動かない**。潰れ方が2通りあり、どちらも別の機構による。
///
/// | 攻撃者が選びそうなもの | Tier2aの中で何が起きるか | 誰が止めているか |
/// |---|---|---|
/// | `touch HIT #`（シェル経由） | gitが`sh.exe -c`で包む→**`0xC0000142`（DLL初期化失敗）で即死** | msys2がAppContainerで動かない（**偶然**） |
/// | リポジトリ同梱の`.bat`／`.exe` | `Access is denied`で起動できない | ワークスペースの実行ACE（**設計**） |
/// | **System32の実体** | **起動する** | ——（ここが遷移MACの出番） |
///
/// **動かない道具で測ると、遷移MACではなく別の事故を測ることになる。** だから残った1つ、
/// つまり**攻撃者にとっていちばん強い選択肢**で測る。
///
/// # 綴りに空白を入れない
///
/// gitは値に空白や記号があると`sh.exe -c`で包み、包まれた瞬間に上の即死へ落ちる。
/// **1語・空白なし**にしてgitに直接起こさせる（段階0で`start_command`が1本になることを確認）。
/// 区切りが`/`なのは、gitの設定ファイルが`\`をエスケープ記号として読むためである
/// （`C:\Windows\...`と書くと`bad config line`で落ちる。2026-09-18に踏んだ）。
fn git_trap_payload() -> String {
    system_findstr_exe().replace('\\', "/")
}

/// 鎖を辿る上限。**無限に回さないための歯止め**であって、鎖の長さの予想ではない。
///
/// 鎖が何段あるかは**測ってから分かること**なので決め打ちしない——`.git/config`の発火は
/// gitの版と綴りで段数が変わる。段数を先に書くと、版が変わった日に
/// 「拒否されたから止まった」と読み違える。
///
/// 2026-09-18の実測（Git for Windows 2.51.1）は**3段**だった——
/// `cmd\git.exe`（中継役）→`mingw64\bin\git.exe`（本体）→`findstr.exe`（仕掛けの指す先）。
/// **この3は上限ではなく観測値である**（§S64）。
const GIT_TRAP_MAX_HOPS: usize = 8;
/// [残課題#39] 拒否側で**最後の1歩に差し替える別のプログラム**。
///
/// System32の実体で、**仕掛けが実際に起こすものとは違う**綴りにする。
/// 起動できるかどうかが軸ではない（起動する前に断られるべきである）ので、
/// 存在するものなら何でもよい——存在しない綴りにすると
/// 「宣言が食い違ったから断られた」と「実体が無いから起きなかった」が混ざる。
const GIT_TRAP_DECOY_EXE: &str = r"C:\Windows\System32\where.exe";

/// [残課題#39・測り方(c)] **別の出発点**のドメイン名。
///
/// ここから伸びる鎖は「他所の文脈のために宣言した辺」を表す。入口から伸びる鎖が
/// その辺を**横取りできてしまうか**が測りたいことなので、**入口とは別の綴り**にする。
const BORROWED_CHAIN_ORIGIN: &str = "borrowed";

/// **敵対的なリポジトリをcloneした状態**をワークスペースに作る。
///
/// # なぜ`run_shell`経由で書かないのか
///
/// 脅威モデルは「攻撃者が書いた`.git/config`を持つリポジトリを取ってきた」である。
/// `run_shell`経由の`.git/config`書込そのものは2026-09-04にユーザーが受容済みで
/// （`docs/bugs/BUG-150.md`の案C）、**この回で測り直す対象ではない**。
fn plant_git_config_trap(ws: &Path) -> Result<(), String> {
    let payload = git_trap_payload();
    if payload.contains(' ') {
        return Err(format!(
            "仕掛けの綴りに空白がある（{payload}）。gitは空白のある値を`sh.exe -c`で包んで\
             起こすので、仕掛けがmsys2の即死へ落ちて**発火しなくなる**——拒否と区別が付かない"
        ));
    }
    git_seed_repo(ws)?;
    // 比べる1ファイル。**追跡させてから中身を変える**——素の`git diff`が比べるのは
    // 索引と作業ツリーなので、追跡していないファイルは1度も外部diffへ渡らない。
    // **差が無いと外部diffは1度も起きない**ので、起きなければ旗を立てた腕の
    // 「発火しなかった」が拒否の証拠にならない（＝測定が無効になる）。
    std::fs::write(ws.join("a.txt"), "one\n").map_err(|e| format!("a.txtを置けない: {e}"))?;
    plain_git(ws, &["add", "a.txt"])?;
    plain_git(ws, &["commit", "-q", "-m", "a"])?;
    std::fs::write(ws.join("a.txt"), "two\n")
        .map_err(|e| format!("a.txtを書き換えられない: {e}"))?;

    let config = ws.join(".git").join("config");
    let mut text = std::fs::read_to_string(&config)
        .map_err(|e| format!(".git/configを読めない（{}）: {e}", config.display()))?;
    text.push_str(&format!("[diff]\n\texternal = {payload}\n"));
    std::fs::write(&config, text).map_err(|e| format!(".git/configへ書けない: {e}"))
}

/// 1腕撃った結果。
struct GitTrapArm {
    /// 仕掛けの指すプログラムが**実際に走ったか**（[`GIT_TRAP_RAN_MARKER`]）。
    fired: bool,
    /// 起動そのものが**断られたか**（[`GIT_TRAP_DENIED_MARKER`]）。
    ///
    /// `fired`の否定ではない。**両方偽**なら「起きなかったが、断られてもいない」で、
    /// それは仕掛けが発火していない（測定が無効）ことの印である。
    refused: bool,
    /// `run_shell`が返した本文（拒否の注記を含む）。
    text: String,
    /// この腕で**Daemonが**断った実行ファイル。
    denied_by_daemon: Vec<String>,
    /// この腕で**カーネルが**止めた実行ファイル。**今日は購読者が居ないので常に空**
    /// （`harness-sandbox`の`spawnd/transitions.rs`モジュールdoc）。
    /// 空でない日は購読者が入った日であり、そのときは§10.2を読み直すこと。
    denied_by_kernel: Vec<String>,
}

/// 台本を1本撃って、**`run_shell`の本文と、待ち行列に残った拒否**を返す。
struct DeniedArm {
    /// `run_shell`が返した本文（拒否の注記を含む）。
    text: String,
    /// この腕で**Daemonが**断った実行ファイル。**畳まれていない**——同じ種類の拒否は
    /// 「更新行」として何度も追記されるので、宣言へ足す側が畳むこと。
    denied_by_daemon: Vec<String>,
    /// 同じ拒否を`(実行ファイル, 何をすれば通るか)`の対で持つ版。
    ///
    /// # なぜ理由まで運ぶのか（**2026-09-19に、これが無くて誤読しかけた**）
    ///
    /// 宣言へ足しても**通らない拒否がある**。Daemonの`remedy`は理由を3つへ畳んでおり、
    /// そのうち`FixTheDeclaration`（宣言を足せば通る）**以外**は、何本書いても消えない。
    /// 実行ファイル名だけを見ていると、この2つが同じ顔になる——そして
    /// 「新しく断られたものが無い」は**宣言が足りた回**と**足しても効かない拒否が
    /// 残り続けている回**の両方で成り立つので、後者が**収束として記録される**。
    ///
    /// 実際、`vswhere.exe`は宣言した次の段でも断られ続けており、鎖はそこで
    /// **切れていた**（リンカまで降りていない）。名前だけを集めていたので、
    /// 一覧は「10本で収束」と書けてしまう状態だった。
    denied_detail: Vec<(String, String)>,
    /// この腕で**カーネルが**止めた実行ファイル。**今日は購読者が居ないので常に空**。
    denied_by_kernel: Vec<String>,
    /// harness自身（子プロセスではない）がこの腕で出した警告・エラー。
    ///
    /// **`text`とは別の口である。** `text`は子が返したstdoutで、`--fs-allow`の付与が
    /// 失敗したことは**そこには一切出ない**（子は「読めない」としか言えない）。
    /// 付与が効いたのかを読むには起動側の出力が要る——無いと「見えるようにしたつもりで
    /// 見えていない」回を、そのまま結果として書いてしまう。
    harness_stderr: String,
    /// **Spawn Daemonがこの腕で書いた診断**（[`DAEMON_STDERR_ENV`]で拾ったもの）。
    ///
    /// # なぜ3つ目の口が要るのか（**2026-09-19に、これが無くて1往復まるごと失った**）
    ///
    /// 待ち行列に積まれる拒否は`DenyReason`までで、**`SpawnFailed`はそれ以上何も持たない**
    /// ——「辺は許可したが起こせなかった」とは分かるが、`CreateProcess`が何番で落ちたのかは
    /// 積まれない（`harness-sandbox`の`spawnd/mod.rs`が、詳細を要求元へ返すと
    /// パスや構成が漏れるという理由でそう決めている）。中身を書いているのは
    /// **Daemonの標準エラーだけ**で、Daemonはコンソールを持たないので既定では
    /// どこにも届かない。§S67はここで止まり、「宣言しても通らない拒否がある」ところまでしか
    /// 書けなかった。
    ///
    /// harness自身の標準エラー（[`DeniedArm::harness_stderr`]）とも別である——Daemonは
    /// **別プロセス**で、その出力はharnessのパイプへ1バイトも流れない。
    daemon_stderr: String,
}

/// Daemonが書いた診断のうち、**起こそうとして失敗した**行だけを抜く。
///
/// 綴りの正本は`harness-sandbox`の`spawnd/server.rs`（`[spawnd] nested spawn failed for pid N: {e}`）。
/// **`B-05`**（同じ文字列を2箇所に別々に書かない）に抵触するが、あちらは`eprintln!`の
/// フォーマット文字列で定数になっていない。**ここを直すときは向こうも見ること。**
const DAEMON_SPAWN_FAILURE_MARKER: &str = "nested spawn failed";

/// 起こす`harness.exe`へ渡す、Daemonの標準エラーの行き先を指す環境変数。
///
/// **名前は`harness-sandbox`から引く**——テスト側で綴り直すと、変数名を変えた日に
/// 「何も記録されない腕」が静かにできる（そして「失敗が起きなかった」と読まれる）。
use harness_sandbox::tier2a::spawnd::client::DAEMON_STDERR_ENV;

/// 旗の有無だけを変えて台本を1本撃ち、待ち行列を読む。**これが唯一の実装である。**
///
/// # なぜ台本を引数で受けるのか
///
/// 「撃って待ち行列を読む」を測定ごとに複製すると、**片方にだけ落とし穴の対処が入った状態**が
/// 生まれる。ここが持っている対処は3つで、どれも欠けると**測りそこねたことが分からない**形で壊れる。
///
/// 1. **待ち行列は撃つ前に消す。** 残したまま撃つと、前の腕の拒否を今の腕の結果として
///    数える（`B-35`の対を取る測定で、いちばん静かに壊れる形）
/// 2. **あふれたら測定ごと無効にする**（`B-10`）。一覧が欠けたまま「これで全部だ」と
///    読まれるのがいちばん高くつく
/// 3. **解析できない行が1行でもあれば無効にする。** 読めなかった行の中に拒否が居たかは
///    分からないので、「断られなかった」と数えてはいけない
///
/// # `extra_args`（**旗と台本のほかに振ってよい唯一の軸**）
///
/// 遷移MACの測定は「宣言を足す」以外の条件を固定したいが、**遷移MACへ届く手前で止まる
/// 条件**だけは外側から振る必要がある。実例が`--fs-allow`で、道具の実体が
/// サンドボックスから読めなければ起動は1度も試みられず、**遷移MACの一覧には現れない**
/// （§S66）。ここを引数で受けるのは、そのための穴である。
/// **渡さない呼び出し（`&[]`）が既定**で、渡す側は記録へ何を振ったかを書くこと。
fn run_arm_collecting_denials(
    ws: &Path,
    case_name: &str,
    enforce: bool,
    script: &str,
    log_tag: &str,
    extra_args: &[String],
) -> Result<DeniedArm, String> {
    use harness_sandbox::tier2a::spawnd::transitions::{
        pending_path, read_from, remedy, PendingRecord, Remedy,
    };
    use harness_sandbox::tier2a::spawnd::DenyReason;

    let queue = pending_path(ws);
    let _ = std::fs::remove_file(&queue);

    // **腕ごとに1本、撃つ前に消す。** 共用にすると前の腕の失敗が今の腕の説明として読める
    // ——待ち行列を撃つ前に消しているのと同じ理由である（この関数のdocの1番）。
    let daemon_log = scratch_dir().join(format!("{case_name}-spawnd.log"));
    let _ = std::fs::remove_file(&daemon_log);

    let mut args: Vec<&str> = vec!["--sandbox", "tier2a"];
    if enforce {
        args.push("--enforce-transitions");
    }
    args.extend(extra_args.iter().map(String::as_str));
    let run = run_harness_with_env(
        ws,
        &run_shell_script_turns(script),
        &args,
        case_name,
        &[(DAEMON_STDERR_ENV, daemon_log.to_string_lossy().into_owned())],
    );
    if !run.status.success() {
        return Err(format!(
            "harness itself failed to run ({}). **拒否ではなく起動の失敗である**: {}",
            run.status, run.stderr
        ));
    }
    if enforce {
        // 窓口（`can_run_program`）は強制が効いている回にだけモデルへ見える（3条件、段階6e）。
        assert_prompt_sane(&run, &["can_run_program"])?;
    }
    let outcome = parse_json_stdout(&run)?;
    let text = outcome.first_tool_result()?.to_string();

    let tail = read_from(&queue, 0);
    let mut denied_by_daemon = Vec::new();
    let mut denied_by_kernel = Vec::new();
    let mut denied_detail: Vec<(String, String)> = Vec::new();
    let mut spawn_failures = 0usize;
    for record in &tail.records {
        match record {
            PendingRecord::DeniedByDaemon(d) => {
                denied_by_daemon.push(d.exe.clone());
                if matches!(d.reason, DenyReason::SpawnFailed) {
                    spawn_failures += 1;
                }
                // **3つへ畳んだ側を持つ**（`DenyReason`の写しではない）。読む側が要る区別は
                // 「宣言を足せば通るのか」だけで、そこは`remedy`が唯一の定義を持つ（`B-05`）。
                let label = match remedy(&d.reason) {
                    Remedy::FixTheDeclaration => "宣言を足せば通る",
                    Remedy::BlockedUntilHarnessImplementsIt => "harness未実装。宣言しても通らない",
                    Remedy::NotAboutPolicy => "宣言と無関係。宣言しても通らない",
                };
                denied_detail.push((d.exe.clone(), format!("{label}（{:?}）", d.reason)));
            }
            PendingRecord::DeniedByKernel(d) => denied_by_kernel.push(d.exe.clone()),
            // **あふれたら測定を無効にする**（`B-10`）。鎖の一覧が欠けたまま
            // 「これで全部だ」と読まれるのがいちばん高くつく。
            PendingRecord::Overflowed { dropped, .. } => {
                return Err(format!(
                    "{case_name}: 待ち行列が{dropped}件あふれた。**断られた一覧が欠けている**\
                     ので、この腕の結果は使えない"
                ));
            }
        }
    }
    if tail.skipped > 0 {
        return Err(format!(
            "{case_name}: 待ち行列の{}行が解析できなかった。断られた一覧が欠けている",
            tail.skipped
        ));
    }

    // **受け皿が繋がっていないことを「失敗が無かった」と読ませない**（BUG-033型:
    // 「ログが出ない＝通っていない」の前に、出力先がその**プロセスから**書けるかを確かめる）。
    // 待ち行列が`SpawnFailed`を積んでいるなら、Daemonは必ず対応する診断を書いている
    // （`spawnd/server.rs`が同じ分岐で`eprintln!`する）。書かれていないなら、
    // 届いていないのは**環境変数かファイルの側**であり、この腕から理由は読めない。
    let daemon_stderr = std::fs::read_to_string(&daemon_log).unwrap_or_default();
    if spawn_failures > 0 && !daemon_stderr.contains(DAEMON_SPAWN_FAILURE_MARKER) {
        return Err(format!(
            "{case_name}: 待ち行列に`SpawnFailed`が{spawn_failures}件あるのに、Daemonの診断\
             （{DAEMON_STDERR_ENV}={}）に`{DAEMON_SPAWN_FAILURE_MARKER}`の行が1つも無い。\
             **受け皿が繋がっていない**ので、「何で落ちたか」はこの腕からは読めない\
             ——「失敗の理由が無かった」と読まないこと。拾えた中身（{}バイト）:\n{daemon_stderr}",
            daemon_log.display(),
            daemon_stderr.len()
        ));
    }
    for line in daemon_stderr
        .lines()
        .filter(|l| l.contains(DAEMON_SPAWN_FAILURE_MARKER))
    {
        eprintln!("[{log_tag}] {case_name}: Daemonの診断: {line}");
    }

    eprintln!(
        "[{log_tag}] --- {case_name} (enforce={enforce}) ---\n\
         denied_by_daemon={denied_by_daemon:?} denied_by_kernel={denied_by_kernel:?}\n\
         {text}\n[{log_tag}] --- end ---"
    );
    Ok(DeniedArm {
        text,
        denied_by_daemon,
        denied_detail,
        denied_by_kernel,
        harness_stderr: run.stderr,
        daemon_stderr,
    })
}

/// 仕掛け（敵対的な`.git/config`）の腕を1本撃つ。**待ち行列の扱いは
/// [`run_arm_collecting_denials`]が持ち、ここは仕掛け固有の判定だけを足す。**
fn run_git_trap_arm(ws: &Path, case_name: &str, enforce: bool) -> Result<GitTrapArm, String> {
    // **`--fs-allow`は渡さない。** この仕掛けが起こすのはSystem32の実体（`findstr.exe`）と
    // gitで、どちらもサンドボックスから元から見えている——見えるようにする軸を振る必要が無い。
    let arm = run_arm_collecting_denials(ws, case_name, enforce, GIT_TRAP_SCRIPT, "git-trap", &[])?;
    let fired = arm.text.contains(GIT_TRAP_RAN_MARKER);
    let refused = arm.text.contains(GIT_TRAP_DENIED_MARKER);
    eprintln!("[git-trap] {case_name}: fired={fired} refused={refused}");
    Ok(GitTrapArm {
        fired,
        refused,
        text: arm.text,
        denied_by_daemon: arm.denied_by_daemon,
        denied_by_kernel: arm.denied_by_kernel,
    })
}

/// **残課題#39の測定**: 敵対的な`.git/config`に仕掛けられた発火は、遷移MACを積んだ
/// セッションで**目的のプログラムまで届かない**。宣言を足していけば届くようになる。
///
/// # 何を測っているのか（**「gitを禁止できるか」ではない**）
///
/// gitを1本も宣言しなければgitは起動しない。それは自明で、何の役にも立たない。
/// 本題は**gitを許したうえで、その先を止められるか**である。だから宣言を0本から始めて、
/// **断られたものを1つずつ足しながら、どこまで行ったら発火するか**を数える。
///
/// # 段数を決め打ちしない理由
///
/// 発火の鎖が何段あるかは、gitの版と`.git/config`の綴りで変わる。段数を先に書くと、
/// 版が変わった日に「拒否されたから止まった」と読み違える（実際には鎖が1段伸びただけ）。
/// **計器が自分で鎖の深さを測る**形にしてある。
///
/// # 対で撃つ理由（`B-35`）
///
/// 腕Aだけだと「遷移MACが何もしていない」構成でも緑になり、拒否側だけだと
/// 「全部断る」実装でも緑になる。**旗を立てない腕Aで罠が発火すること**と、
/// **全部宣言した段で発火すること**の両方を要求する。
///
/// # ここで測っていないもの（**外挿しないこと**）
///
/// - **遷移の鎖（別ドメインへ渡る形）**。ここが測っているのは**同じドメインの中での許否**まで
///   である。跨ぐ形は[`the_git_config_trap_chain_is_judged_across_domains`]が測る
///   （2026-09-20に足した。それまでは遷移先を別ドメインにできなかった＝残課題#45）
/// - **`diff.external`以外の発火キー**（`core.editor`・`core.sshCommand`・`alias.*`…。
///   `docs/bugs/BUG-150.md`が14件挙げている）。遷移MACから見れば同じ1経路だが、**測っていない**
/// - **CoWモード（`--sandbox tier2a-cow`）との組み合わせ**
#[test]
#[ignore = "starts several real Tier2a sessions with the transition MAC enforced; run through dev-elevated-run"]
fn a_git_config_trap_cannot_reach_its_program_when_transitions_are_enforced() {
    let ws = case_dir("git-config-transition");
    plant_git_config_trap(&ws).unwrap_or_else(|e| panic!("仕掛けを置けなかった: {e}"));

    let mut case_names: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    // --- 腕A: 旗を立てない。**罠が作動することの確認**（計器の検算） ---
    case_names.push("git-trap-unenforced".to_string());
    let unenforced = run_git_trap_arm(&ws, "git-trap-unenforced", false)
        .unwrap_or_else(|e| panic!("腕A（旗なし）が測れなかった: {e}"));
    assert!(
        unenforced.fired,
        "腕A: 旗を立てていないのに仕掛けが発火しなかった。**この測定は無効である**\
         ——以後の腕の「発火しなかった」を拒否の証拠にできない（gitがサンドボックスへ\
         届いていない／差分が無い／仕掛けの綴りが`sh.exe`経由になった、のどれか）。\
         run_shellの本文:\n{}",
        unenforced.text
    );
    assert!(
        !unenforced.refused,
        "腕A: 旗を立てていないのに起動が断られている。**遷移MAC以外の何かが止めている**ので、\
         以後の腕で「断られた」を遷移MACの成果として数えられない。run_shellの本文:\n{}",
        unenforced.text
    );

    // --- 旗を立てて、断られたものを1つずつ宣言していく ---
    let mut declared: Vec<String> = Vec::new();
    let mut chain: Vec<(usize, Vec<String>)> = Vec::new();
    let mut fired_at: Option<usize> = None;

    for hop in 0..GIT_TRAP_MAX_HOPS {
        declare_programs(&ws, &declared)
            .unwrap_or_else(|e| panic!("段{hop}の宣言を書けなかった: {e}"));
        let case_name = format!("git-trap-hop{hop}");
        case_names.push(case_name.clone());
        let arm = run_git_trap_arm(&ws, &case_name, true)
            .unwrap_or_else(|e| panic!("段{hop}が測れなかった: {e}"));

        if hop == 0 {
            // **ここが残課題#39の答えである**——何も宣言していない状態では仕掛けは動かない。
            if arm.fired {
                failures.push(
                    "段0: 宣言が1本も無いのに**仕掛けが発火した**。遷移MACは`.git/config`から\
                     発火した子を無力化できていない（生成禁止が積まれていないか、\
                     フックもカーネルも生成を止めていない）"
                        .to_string(),
                );
            }
            if !arm.refused {
                failures.push(format!(
                    "段0: 発火はしていないが、**断られてもいない**。フックがDaemonへ頼んで\
                     断られたなら`{GIT_TRAP_DENIED_MARKER}`が返るはずである\
                     （§10.1.2「4つの原因に4つの値」）: {}",
                    arm.text
                ));
            }
            if !arm.text.contains("[transition:") {
                failures.push(format!(
                    "段0: 断られたのに**注記が出ていない**。モデルには生のエラーしか届かず、\
                     宣言の直し方へ辿り着けない（段階6f-3の配線）: {}",
                    arm.text
                ));
            }
            if !arm.text.contains("can_run_program") {
                failures.push("段0: 注記が窓口（`can_run_program`）を案内していない".to_string());
            }
            if !arm.text.contains("powershell5.1(Tier2a)") {
                failures.push(format!(
                    "段0: シェルが`powershell5.1(Tier2a)`ではない。生成禁止を積む回は\
                     ストアの実行エイリアスを候補から外す規則（残課題#50・§S62）が効いていない: {}",
                    arm.text
                ));
            }
        }

        if arm.fired {
            fired_at = Some(hop);
            break;
        }

        if !arm.denied_by_kernel.is_empty() {
            // **これは失敗ではない。** 購読者が入った日に初めて現れる行で、現れたら§10.2を読み直す。
            eprintln!(
                "[git-trap] 段{hop}: カーネル拒否の行が現れた（購読者が入った？）: {:?}",
                arm.denied_by_kernel
            );
        }

        // **待ち行列は畳んで読む。** 同じ種類の拒否は「更新行」として何度も追記されるので
        // （`spawnd/transitions.rs`の`Denial::count`）、そのまま宣言へ足すと同じ辺を
        // 何本も書くことになる。**重複した辺を持つ`policy.json`は編集時検査を通らず、
        // 宣言がまるごと効かなくなる**（2026-09-18に踏んだ。段1で「宣言したのに断られる」に見えた）。
        let mut newly: Vec<String> = Vec::new();
        for exe in &arm.denied_by_daemon {
            let known = declared
                .iter()
                .chain(newly.iter())
                .any(|d| d.eq_ignore_ascii_case(exe));
            if !known {
                newly.push(exe.clone());
            }
        }
        chain.push((hop, newly.clone()));
        if newly.is_empty() {
            failures.push(format!(
                "段{hop}: 発火は止まったが、**待ち行列に新しい拒否が1件も無い**。\
                 止めたのがDaemonではない（カーネルが生成そのものを止めたが、\
                 購読者が居ないので記録に残らない）か、そもそも生成が起きていない。\
                 ここまでの宣言: {declared:?}／run_shellの本文:\n{}",
                arm.text
            ));
            break;
        }
        declared.extend(newly);
    }

    match fired_at {
        Some(0) => { /* 上で失敗として積んである */ }
        Some(_) => { /* 対（許可側）が取れた */ }
        None => failures.push(format!(
            "宣言を{}本まで足しても発火しなかった。**対（許可側）が取れていない**——\
             拒否側だけでは「全部断る」実装でも緑になる（`B-35`）。辿った鎖: {chain:?}",
            declared.len()
        )),
    }

    eprintln!(
        "[git-trap] ===== 残課題#39の結果 =====\n\
         旗なしで発火: {}\n\
         段ごとに断られたもの: {chain:?}\n\
         発火した段: {fired_at:?}（宣言{}本）\n\
         [git-trap] ===== ここまで =====",
        unenforced.fired,
        declared.len()
    );

    if failures.is_empty() {
        let names: Vec<&str> = case_names.iter().map(|s| s.as_str()).collect();
        for name in &names {
            cleanup_on_success(&ws, &[], name);
        }
    } else {
        eprintln!(
            "[git-trap] 失敗したのでワークスペースを {} に残す（調査用）",
            ws.display()
        );
    }
    assert!(
        failures.is_empty(),
        "`.git/config`の発火と遷移MAC（残課題#39）:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// 既定の宣言一式の一次データ——**実務に近いセッションが何を宣言しないと動かないか**
// ---------------------------------------------------------------------------

/// 台本に載せる候補。`(プログラム, 実際に打つ行)`。
///
/// # なぜ「打つ行」まで持つのか
///
/// 遷移の宣言は`(実行ファイル, argv)`の対で書ける（[`harness_policy`]の`TransitionEdge`）。
/// **版を聞くだけの行と、実際に仕事をさせる行では、その先で起きる子が違う**
/// ——`cargo --version`は`cargo.exe`しか起こさないが、`cargo build`は`rustc`を起こし、
/// `rustc`はリンカを起こす。**鎖の深さは打つ行で決まる**ので、行ごと持つ。
const SURVEY_CANDIDATES: &[(&str, &str)] = &[
    ("git", "git status --porcelain"),
    ("git", "git --no-pager diff --stat"),
    ("git", "git --no-pager log -1 --oneline"),
    // **鎖が深い1本**。`--offline`なのは、ネットワークの可否を遷移の可否と混ぜないため。
    //
    // **前後を印で挟む。** 「ビルドが通ったか」を出力の有無や終了コードで読もうとすると、
    // `--quiet`の無出力と失敗の無出力が同じ顔になり、しかも`run_shell`が返す終了コードは
    // **台本の最後の行のもの**でこの行のものではない。だから**成果物が在るかをシェル自身に
    // 答えさせる**（既存の`HP_SEE_OK`と同じ作法）。
    //
    // **先に消すのが要である。** ワークスペースは腕と段をまたいで使い回すので、
    // 消さずに撃つと**前の腕が作った成果物**を今の腕の成功として読む。`Remove-Item`も
    // `Test-Path`もコマンドレットなので、子プロセスを1つも起こさない＝遷移の数に混ざらない。
    (
        "cargo",
        "Remove-Item -Force -ErrorAction SilentlyContinue target\\debug\\survey.exe\n\
         cargo build --offline --quiet\n\
         if (Test-Path target\\debug\\survey.exe) { 'HP_BUILD_OK' } else { 'HP_BUILD_NG' }",
    ),
    ("node", "node --version"),
    ("npm", "npm --version"),
    // System32の実体。**正の対照**——これが断られない回は強制が効いていない。
    ("findstr", r"findstr.exe /C:fn src\main.rs"),
];

/// 鎖の段数の上限。**段数は決め打ちしない**（§S64と同じ理由）——ここは暴走を止める栓であって、
/// 「何段あるはずだ」という主張ではない。
const SURVEY_MAX_HOPS: usize = 12;

/// ビルドが最後まで通って成果物ができたときにシェルが出す印。
const SURVEY_BUILD_OK: &str = "HP_BUILD_OK";
/// 成果物ができなかったときにシェルが出す印。**印が片方も出ない回は測れていない**
/// （その行までシェルが到達していない）ので、`OK`の否定として扱ってはいけない。
const SURVEY_BUILD_NG: &str = "HP_BUILD_NG";

/// この機械にそのプログラムが入っているか。
///
/// **入っていないものを台本へ載せない。** 入っていないプログラムは起動そのものが
/// 「見つからない」で終わるので**断られた一覧に現れない**——載せると、
/// 一覧に穴が空いたまま「これで全部だ」と読める（`B-10`）。
fn program_exists_on_host(program: &str) -> bool {
    host_path_of(program).is_some()
}

/// ホスト側でその名前が指す実体のパス（`where.exe`の1行目）。
///
/// # なぜ絶対パスでも撃つのか（**名前が通らない＝MACに届かない、ではない**）
///
/// サンドボックスの中で名前を解決できないプログラムは、**シェルが起動を試みない**ので
/// 遷移MACに届かない。しかしそれは「宣言が要らない」ことを意味しない——
/// **絶対パスで呼べば起動は試みられる**ので、そこで初めて断られる。
/// 名前で撃つ行だけを数えると、**宣言一式に必要な本数を実際より少なく見積もる**。
fn host_path_of(program: &str) -> Option<String> {
    let out = std::process::Command::new("where.exe")
        .arg(program)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// `run_shell`の本文から、**名前を解決できずに起動を試みてすらいない**プログラムを拾う。
///
/// # なぜこれが要るのか（**2026-09-19に踏んだ**）
///
/// 最初の版はホスト側に入っているかだけを見ていた。**入っていても、サンドボックスの中で
/// 名前が解決できなければシェルは起動を試みない**——遷移MACには1度も届かないので、
/// 待ち行列にも現れない。つまり**「断られなかった」と「試してすらいない」が同じ顔になる**。
/// 実際に`cargo`・`node`・`npm`がこれで一覧から消え、**3本しかない一覧を「全部」と読むところ**だった。
///
/// # エラー本文を解析しない理由（**最初の版はそれで検出漏れした**）
///
/// 1つ目の版は`ObjectNotFound: (<名前>:String)`という綴りを探していた。**旗の有無で
/// シェルが変わる**（強制する回はWindows PowerShell 5.1、しない回はpwsh 7。§S62）ので、
/// pwsh 7の簡潔なエラー表示にはその綴りが**1度も現れず**、対照側が「全部解決できた」に見えていた。
/// **検出漏れする判定は、無いより悪い。**
///
/// だから本文を読むのをやめ、**シェル自身に答えさせる**。`Get-Command`はどちらのシェルにもあり、
/// 印は自分で決めた綴りなので翻訳も書式変更も受けない。
fn programs_never_attempted(text: &str, programs: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for program in programs {
        let missing = format!("{SURVEY_PROBE_MISSING} {program}");
        if text.contains(&missing) && !out.iter().any(|p| p == program) {
            out.push((*program).to_string());
        }
    }
    out
}

/// 名前を解決できたときにシェルが出す印。
const SURVEY_PROBE_OK: &str = "HP_PROBE_OK";
/// 名前を解決できなかったときにシェルが出す印。
const SURVEY_PROBE_MISSING: &str = "HP_PROBE_MISSING";
/// 実体のファイルが**サンドボックスから見えている**ときの印。
const SURVEY_SEE_OK: &str = "HP_SEE_OK";
/// 実体のファイルが**サンドボックスから見えていない**ときの印。
const SURVEY_SEE_NO: &str = "HP_SEE_NO";

/// この機械で撃てる行だけを集めて台本にする。戻りは`(台本, 載せなかったプログラム)`。
///
/// 台本は2段になる——**まずサンドボックスの中で名前を解決できるかを申告させ**、そのあと
/// 実際に打つ行を並べる。申告を先に置くのは、**解決できなかったものが「断られなかった」に
/// 化けるのを止める**ためである（[`programs_never_attempted`]）。
fn survey_script_for_this_machine() -> (String, Vec<String>) {
    let mut probes: Vec<String> = Vec::new();
    let mut lines: Vec<&str> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut probed: Vec<&str> = Vec::new();
    for (program, line) in SURVEY_CANDIDATES {
        if !program_exists_on_host(program) {
            if !skipped.iter().any(|s| s == program) {
                skipped.push((*program).to_string());
            }
            continue;
        }
        if !probed.contains(program) {
            probed.push(program);
            // `Get-Command`はコマンドレットなので**子プロセスを1つも起こさない**
            // ——この申告自体が遷移の数に混ざることはない。
            probes.push(format!(
                "if (Get-Command {program} -ErrorAction SilentlyContinue) \
                 {{ '{SURVEY_PROBE_OK} {program}' }} else {{ '{SURVEY_PROBE_MISSING} {program}' }}"
            ));
        }
        lines.push(line);
    }
    // **絶対パスでも1本ずつ撃つ。** 名前が解決できないものは、名前で撃つ行では
    // 遷移MACに届かない（[`host_path_of`]のdoc）。ここで届かせて、
    // 「宣言が要る」のか「そもそも実体を起こせない」のかを分ける。
    let mut by_path: Vec<String> = Vec::new();
    for program in &probed {
        if let Some(abs) = host_path_of(program) {
            // **見えているかを先に聞く。** 絶対パスで撃っても「認識されません」になる場合、
            // 原因は2つある——ファイルが見えていない（読めない）か、見えているが起こせないか。
            // `Test-Path`はコマンドレットなので子を1つも起こさず、**遷移の数に混ざらない**。
            by_path.push(format!(
                "if (Test-Path -LiteralPath '{abs}') \
                 {{ '{SURVEY_SEE_OK} {program}' }} else {{ '{SURVEY_SEE_NO} {program}' }}"
            ));
            by_path.push(format!("& '{abs}' --version"));
        }
    }
    let script = probes
        .iter()
        .map(String::as_str)
        .chain(lines)
        .chain(by_path.iter().map(String::as_str))
        .collect::<Vec<&str>>()
        .join("\n");
    (script, skipped)
}

/// 実務に近いワークスペースを作る——gitの履歴と、**リンカまで降りる最小のcargoプロジェクト**。
fn seed_survey_workspace(ws: &Path) -> Result<(), String> {
    git_seed_repo(ws)?;
    std::fs::create_dir_all(ws.join("src")).map_err(|e| format!("srcを作れない: {e}"))?;
    std::fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"survey\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    )
    .map_err(|e| format!("Cargo.tomlを置けない: {e}"))?;
    std::fs::write(ws.join("src").join("main.rs"), "fn main() {}\n")
        .map_err(|e| format!("main.rsを置けない: {e}"))?;
    // 追跡させておく（`git diff --stat`が何も比べないと、その行は子を1つも起こさない）。
    plain_git(ws, &["add", "Cargo.toml", "src/main.rs"])?;
    plain_git(ws, &["commit", "-q", "-m", "survey fixture"])?;
    std::fs::write(
        ws.join("src").join("main.rs"),
        "fn main() {\n    // touched\n}\n",
    )
    .map_err(|e| format!("main.rsを書き換えられない: {e}"))?;
    Ok(())
}

/// 道具の実体を**サンドボックスから見えるようにする**宣言（`--fs-allow`へ渡す綴り）。
///
/// # なぜこれが「軸」なのか（§S66で分かったこと）
///
/// 2026-09-19の一次データは3本で収束したが、**本数が小さい理由は「足りている」ではなかった**。
/// `cargo`はサンドボックスから実体が読めず、絶対パスで撃っても
/// **プロセス生成が1度も試みられない**——つまり遷移MACの一覧には最初から載っていない。
/// 止めているのは遷移MACではなく**ファイルを読めるかどうか**なので、
/// そこを開けてからでないと「宣言一式は何本か」を測ったことにならない。
///
/// # `C:\Program Files\nodejs`を載せない（**測ってから外した**）
///
/// §S66は`node`・`npm`も「見えない」側に数えていたが、**§S67の対照ではどちらも見えており、
/// 遷移MACが実際に断っている**（`node.exe`・`npm.cmd`が段0の拒否に出る）。実DACLを読むと
/// `C:\Program Files\nodejs`は継承を止めておらず、`ALL APPLICATION PACKAGES`の
/// 読取＋実行を`C:\Program Files`から継承している——**どのAppContainerからでも元から読める**。
/// 見えているものを「見えるようにする」宣言は、振っている軸に1ビットも足さない。
///
/// **そのうえ、この宣言は最後まで通らない。** `--fs-allow`は宣言先の祖先へtraverse ACEを
/// 張る（D-45）が、`C:\Program Files`の所有者は`NT SERVICE\TrustedInstaller`であり、
/// **管理者トークンでも`WRITE_DAC`が無い**。2026-09-19の1回目はここで
/// `アクセスが拒否されました。(0x80070005)`になり、測定が段0で止まった。
/// 通すには`--force-system-acl`（D-19）が要るが、**要らない宣言のために
/// `SeRestorePrivilege`を持ち出すのは、測っているものを変える**。
///
/// # 綴りの決め方
///
/// - 末尾の`\**`は**配下まで**という意味である（D-63。素のパスはそのオブジェクト1個だけを
///   開くので、`cargo.exe`も`rustc.exe`も入っている配下へは1バイトも届かない）
/// - `:rw`を付けない＝`FsAccess::ReadExec`（読取＋実行）。**見えるだけでは起動できない**ので
///   実行が要り、**書けてしまうと測っているものが変わる**（道具の置き場を書き換えられる
///   サンドボックスは、もはや今日のTier2aではない）
///
/// # パスを機械から引く（綴りを写さない）
///
/// `C:\Users\<名前>`を直に書くと、別の機械でこのテストが**黙って0件の付与**になる
/// （存在しないパスはスキップされる）。`CARGO_HOME`／`RUSTUP_HOME`を先に見るのは、
/// この2つが立っている機械では`%USERPROFILE%`配下に実体が無いためである。
///
/// 戻りは`(--fs-allowへ渡す綴り, 実体のディレクトリ)`。**存在しないものは載せず、
/// 載せなかったことを名指しで出す**（`B-10`: 黙って落とすと、付与が効いていない回を
/// 「見えるようにした」と読む）。
fn survey_visibility_grants() -> Vec<(String, PathBuf)> {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let candidates: Vec<PathBuf> = vec![
        std::env::var("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&home).join(".cargo")),
        std::env::var("RUSTUP_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&home).join(".rustup")),
        // **Visual Studioの「場所を検出する」ための置き場**（[BUG-014](../../../docs/bugs/BUG-014.md)）。
        //
        // # なぜVSのインストール先ではなくここなのか（2026-09-19に実DACLで確かめた）
        //
        // VS本体（`C:\Program Files (x86)\Microsoft Visual Studio\**`）は**既にどの
        // AppContainerからも読める**——`ALL APPLICATION PACKAGES`へ読取＋実行が
        // `C:\Program Files (x86)`から継承されている。読めないのは**検出用のDLL**の側で、
        // `C:\ProgramData\Microsoft\VisualStudio\Setup\{x64,x86}\Microsoft.VisualStudio.Setup.Configuration.Native.dll`
        // が住む`C:\ProgramData`は、**どの階層も`ALL APPLICATION PACKAGES`に1ビットも
        // 開いていない**。rustcがMSVCのリンク時に使う`cc`クレートはこのDLLでVSを探すので、
        // 読めないと**リンカの在処が分からない**（`error: linker link.exe not found`）。
        //
        // **`C:\Program Files`のようには失敗しない。** あちらは`NT SERVICE\TrustedInstaller`
        // 所有で管理者でも`WRITE_DAC`が無く、祖先へのtraverse付与で必ず止まる（§S67）。
        // こちらは4階層とも`BUILTIN\Administrators`が`FullControl`を持つ。
        PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
        // **VSが「どこに入っているか」を記録した台帳**（§S70の続き。2026-09-19）。
        //
        // 上の`Setup`を開けても**検出はまだ答えなかった**（`error: linker link.exe not found`）。
        // 原因の候補を3つに分けて読み取りだけで潰したところ、残ったのがここである。
        //
        // | 候補 | 判定 | 根拠 |
        // |---|---|---|
        // | 検出用DLLが読めない | **消えた** | 上の`Setup`への付与が届いており、DLL本体に読取＋実行のACEが継承で付いている |
        // | COMの登録が読めない | **消えた** | 登録キーとその親に`ALL APPLICATION PACKAGES`（`S-1-15-2-1`）の`ReadKey`が継承で付いている |
        // | **所在の台帳が読めない** | **残った** | `…\Packages`・`…\Packages\_Instances`は**app package向けのACEが1本も無い**。中身は実在する（インスタンス2件、各`state.json`） |
        //
        // **`Packages`ごと開けない。** あちらはパッケージの実体が丸ごと入る大きな置き場で、
        // **要ると分かっていない範囲まで開くことになる**。`_Instances`で足りなければ、
        // **足りなかったという測定結果を根拠に**広げる（当てずっぽうで許可を広げると、
        // 開けた範囲が測定の副作用としてそのまま実マシンへ残る）。
        PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Packages\_Instances"),
    ];
    let mut out = Vec::new();
    for dir in candidates {
        if !dir.is_dir() {
            eprintln!(
                "[survey] 見えるようにする対象に載せなかった（この機械に無い）: {}",
                dir.display()
            );
            continue;
        }
        out.push((format!(r"{}\**", dir.display()), dir));
    }
    out
}

/// 宣言を0本から足しながら収束まで撃ち直した、**1掃き**の結果。
struct SurveySweep {
    /// この掃きを何と呼ぶか（記録とログの見出し）。
    label: &'static str,
    /// 段ごとに**新しく**断られた実行ファイル。
    hops: Vec<(usize, Vec<String>)>,
    /// 新しい拒否が出なくなった段。`None`は**上限に当たって止まった**（収束していない）。
    ///
    /// **`Some`は「鎖が終わった」を意味しない。** [`SurveySweep::cut_by`]も併せて読むこと。
    converged_at: Option<usize>,
    /// 最後の段でなお断られていた、**宣言しても通らない**拒否（`(実行ファイル, 理由)`）。
    ///
    /// # これが空でない掃きの一覧は「全部」ではない
    ///
    /// 宣言を足しても消えない拒否は、**次の段でも同じものが断られる**。新しい拒否は
    /// 出ないので[`SurveySweep::converged_at`]は`Some`になるが、鎖はそこで**切れている**
    /// ——その先で起きるはずだった子は1つも現れない。**「収束した」と「鎖が終わった」は
    /// 別の事実**であり、混ぜると§S66と同じ「短い一覧を全部と読む」に戻る。
    cut_by: Vec<(String, String)>,
    /// 鎖を切った拒否について、**Daemonが書いた「何で落ちたか」**
    /// （[`DeniedArm::daemon_stderr`]から抜いた行）。
    ///
    /// **[`SurveySweep::cut_by`]だけでは次の一手が決まらない。** あちらが言えるのは
    /// 「宣言では直らない」までで、`CreateProcess`が何番で落ちたのかを持っているのは
    /// この行だけである——実行ファイルが読めない（`ACCESS_DENIED`）のか、属性の
    /// 組み合わせが悪い（`INVALID_PARAMETER`）のかで、打つ手はまるで違う。
    cut_reasons: Vec<String>,
    /// 最後に宣言していた全部（＝断られた一覧）。
    declared: Vec<String>,
    /// 段0で実体が**見えた**プログラム（`HP_SEE_OK`）。
    visible: Vec<String>,
    /// 段0で実体が**見えなかった**プログラム（`HP_SEE_NO`）。
    invisible: Vec<String>,
    /// 段0で**名前を解決できず、起動を試みてすらいない**プログラム（`HP_PROBE_MISSING`）。
    never_attempted: Vec<String>,
    /// **最後の段でビルドが最後まで通ったか**（`HP_BUILD_OK`／`HP_BUILD_NG`／印が出ない＝`None`）。
    ///
    /// # なぜ収束だけでは足りないのか（2026-09-19に**偽の緑**を踏んだ）
    ///
    /// [`SurveySweep::cut_by`]が空で[`SurveySweep::converged_at`]が`Some`でも、
    /// **鎖が終わったとは限らない**。断られる前に止まる段——たとえばリンカを探す側が
    /// 諦めてしまえば、リンカは**起動を試みられないので拒否に現れない**。
    /// 新しい拒否が出ないまま収束し、**一覧は下限のままなのに緑になる**。
    ///
    /// 実際に踏んだ形: Visual Studioの検出用の置き場を見えるようにしたところ、
    /// 鎖を切っていた`vswhere.exe`は一覧から消えて「切断なし・9本で収束」になったが、
    /// **ビルドは全段で通っていなかった**（`error: linker link.exe not found`）。
    /// 拒否の側だけを見ていると、この状態と「本当に全部そろった」が区別できない。
    built: Option<bool>,
}

/// 宣言を0本から足しては撃ち直し、**新しい拒否が出なくなるまで**回す（1掃き）。
///
/// # なぜ関数にしたのか
///
/// この回で軸が1つ増えた（道具が見えるか）ので、**同じ掃きを2回**回す必要が出た。
/// 掃きを2箇所へ書くと、落とし穴の対処（申告が出ているかの確認・畳んでから足す・
/// 上限で止まったら無効）が**片方にだけ入った状態**が生まれる——それは
/// [`run_arm_collecting_denials`]を1本にしてある理由と同じである。
///
/// `failures`へ積むのは**測定が成立していないとき**だけで、「何本だった」は合否にしない。
fn run_declaration_sweep(
    ws: &Path,
    script: &str,
    label: &'static str,
    extra_args: &[String],
    never_unenforced: &[String],
    // **この掃きでは台本のビルドが最後まで通るはずか。** 道具を隠した対照では通らないのが
    // 正しいので、同じ要求を当てると正しい対照を「測定が成立していない」と言ってしまう。
    expect_build: bool,
    failures: &mut Vec<String>,
) -> SurveySweep {
    let names: Vec<&str> = SURVEY_CANDIDATES.iter().map(|(p, _)| *p).collect();
    let mut sweep = SurveySweep {
        label,
        hops: Vec::new(),
        converged_at: None,
        cut_by: Vec::new(),
        cut_reasons: Vec::new(),
        declared: Vec::new(),
        visible: Vec::new(),
        invisible: Vec::new(),
        never_attempted: Vec::new(),
        built: None,
    };

    for hop in 0..SURVEY_MAX_HOPS {
        declare_programs(ws, &sweep.declared)
            .unwrap_or_else(|e| panic!("[{label}] 段{hop}の宣言を書けなかった: {e}"));
        let case_name = format!("survey-{label}-hop{hop}");
        let arm = run_arm_collecting_denials(ws, &case_name, true, script, "survey", extra_args)
            .unwrap_or_else(|e| panic!("[{label}] 段{hop}が測れなかった: {e}"));

        // **段ごとに上書きする。** 見たいのは「最後の段でビルドが通ったか」である。
        sweep.built = if arm.text.contains(SURVEY_BUILD_OK) {
            Some(true)
        } else if arm.text.contains(SURVEY_BUILD_NG) {
            Some(false)
        } else {
            None
        };

        if hop == 0 {
            // **起動側が何を言ったかを残す。** `--fs-allow`の付与が失敗しても子のstdoutには
            // 出ない（子は「読めない」としか言えない）ので、ここを黙らせると
            // 「見えるようにしたつもりで見えていない」回をそのまま結果にしてしまう。
            for line in arm.harness_stderr.lines() {
                if line.contains("fs-allow") || line.contains("fs allow") {
                    eprintln!("[survey] [{label}] 起動側: {line}");
                }
            }
            // **名前を解決できなかったものは、遷移MACに1度も届いていない。**
            // 一覧から静かに消えるので、ここで拾って測定ごと無効にする（`B-10`）。
            // **申告そのものが出ていない**なら、解決できたかどうかを判定できていない。
            // 「印が無い＝解決できた」と読むと、また静かに短い一覧ができる。
            let unprobed: Vec<&str> = names
                .iter()
                .copied()
                .filter(|p| {
                    !arm.text.contains(&format!("{SURVEY_PROBE_OK} {p}"))
                        && !arm.text.contains(&format!("{SURVEY_PROBE_MISSING} {p}"))
                })
                .collect();
            if !unprobed.is_empty() {
                failures.push(format!(
                    "[{label}] 段0: {unprobed:?} について**名前を解決できたかの申告が1つも出ていない**。\
                     申告の行がシェルへ届いていないので、この一覧が全部かどうかを判定できない"
                ));
            }
            // **見えているか／見えていないか**を要約する。一覧の本数が小さいとき、
            // 「宣言が3本で足りる」のか「3本しか遷移MACまで届いていない」のかは
            // ここでしか分かれない。
            sweep.visible = names
                .iter()
                .copied()
                .filter(|p| arm.text.contains(&format!("{SURVEY_SEE_OK} {p}")))
                .map(str::to_string)
                .collect();
            sweep.invisible = names
                .iter()
                .copied()
                .filter(|p| arm.text.contains(&format!("{SURVEY_SEE_NO} {p}")))
                .map(str::to_string)
                .collect();
            eprintln!(
                "[survey] [{label}] 段0: サンドボックスから**実体が見えた**={:?} / \
                 **見えなかった**={:?}（見えないものは絶対パスで撃っても\
                 遷移MACに届かない——止めているのはファイルを読めるかどうかである）",
                sweep.visible, sweep.invisible
            );

            sweep.never_attempted = programs_never_attempted(&arm.text, &names);
            // **解決できないこと自体は、この測定の失敗ではない**——旗を立てない腕でも同じなら、
            // 遷移MACとは無関係の既存の制約である（宣言を足しても直らない）。
            // **失敗なのは、旗を立てた側でだけ解決できなくなったとき**——強制を入れた代償として
            // 道具が届かなくなったことを意味し、既定へ入れる判断に直接効く。
            let lost_by_enforcing: Vec<&String> = sweep
                .never_attempted
                .iter()
                .filter(|p| !never_unenforced.contains(p))
                .collect();
            // **見えるようにした掃きでは、この差は「後退」ではない。** 旗なしの腕は
            // `--fs-allow`を渡していないので、そちらで解決できなかったものが
            // こちらで解決できるようになるのは想定どおりである（差は逆向きにしか出ない）。
            if !lost_by_enforcing.is_empty() && extra_args.is_empty() {
                failures.push(format!(
                    "[{label}] 段0: {lost_by_enforcing:?} は**旗を立てた側でだけ名前を解決できない**。\
                     旗なしでは解決できているので、強制を入れたこと（＝シェルが\
                     Windows PowerShell 5.1へ替わること、§S62）が原因である。\
                     **宣言では直らない種類の後退**なので、既定へ入れる前に決着させること"
                ));
            }
            if !sweep.never_attempted.is_empty() {
                eprintln!(
                    "[survey] [{label}] 段0: {:?} は**サンドボックスの中で名前を解決できず、\
                     起動を試みてすらいない**。**この一覧は「実務に必要な全部」ではない**\
                     ——遷移MACへ届いていないものがこの数だけ在る。\
                     直すのは宣言ではなく、その置き場を読めるようにする側である",
                    sweep.never_attempted
                );
            }
        }

        if hop == 0 && arm.denied_by_daemon.is_empty() {
            failures.push(format!(
                "[{label}] 段0: 宣言が1本も無いのに**拒否が1件も出ていない**。強制が効いていないか\
                 （旗が渡っていない／生成禁止が積まれていない）、台本がそもそも子を1つも\
                 起こしていない。どちらにせよこの測定は無効である"
            ));
            break;
        }

        if !arm.denied_by_kernel.is_empty() {
            // **失敗ではない。** 購読者が入った日に初めて現れる行である（§10.2）。
            eprintln!(
                "[survey] [{label}] 段{hop}: カーネル拒否の行が現れた: {:?}",
                arm.denied_by_kernel
            );
        }

        // **畳んでから足す。** 同じ拒否は更新行として何度も積まれるので、そのまま足すと
        // `policy.json`が重複した辺を持ち、**宣言がまるごと効かなくなる**（§S64で踏んだ）。
        let mut newly: Vec<String> = Vec::new();
        for exe in &arm.denied_by_daemon {
            let known = sweep
                .declared
                .iter()
                .chain(newly.iter())
                .any(|d| d.eq_ignore_ascii_case(exe));
            if !known {
                newly.push(exe.clone());
            }
        }
        eprintln!(
            "[survey] [{label}] 段{hop}: 宣言済み{}本 → 新しく断られた{}本 {newly:?}",
            sweep.declared.len(),
            newly.len()
        );
        sweep.hops.push((hop, newly.clone()));
        if newly.is_empty() {
            sweep.converged_at = Some(hop);
            // **「新しい拒否が無い」を「鎖が終わった」と読まない。** 宣言しても通らない
            // 種類の拒否は、宣言へ足しても次の段で同じものが出る——新しくはないので
            // ここへ到達するが、その先で起きるはずだった子は1つも現れていない。
            sweep.cut_by = arm
                .denied_detail
                .iter()
                .filter(|(_, reason)| !reason.starts_with("宣言を足せば通る"))
                .cloned()
                .collect();
            sweep.cut_by.dedup();
            // **切れた理由を、切れた事実と同じ段で拾う。** 次の段は撃たないので、
            // ここで拾い損ねるとこの掃きからは二度と読めない。
            sweep.cut_reasons = arm
                .daemon_stderr
                .lines()
                .filter(|l| l.contains(DAEMON_SPAWN_FAILURE_MARKER))
                .map(str::to_string)
                .collect();
            sweep.cut_reasons.dedup();
            break;
        }
        sweep.declared.extend(newly);
    }

    eprintln!("[survey] ===== [{label}] 断られた一覧（宣言へ足した順） =====");
    for (hop, newly) in &sweep.hops {
        for exe in newly {
            eprintln!("[survey]   [{label}] 段{hop}: {exe}");
        }
    }
    eprintln!(
        "[survey] ===== [{label}] 合計{}本 / 収束した段: {:?} / 鎖を切ったもの: {:?} =====",
        sweep.declared.len(),
        sweep.converged_at,
        sweep.cut_by
    );
    for line in &sweep.cut_reasons {
        eprintln!("[survey]   [{label}] 鎖を切った理由: {line}");
    }

    if sweep.converged_at.is_none() {
        failures.push(format!(
            "[{label}] 上限{SURVEY_MAX_HOPS}段まで回しても**新しい拒否が出続けた**。\
             鎖が切れていないので、この一覧は「全部」ではない。ここまでの宣言（{}本）: {:?}",
            sweep.declared.len(),
            sweep.declared
        ));
    }
    // **測定が成立していないので赤にする。** 一覧そのものは正しい（そこまでは本当に断られた）が、
    // **この測定が答えようとしている問い**は「実務に近いセッションを回すのに何本要るか」であり、
    // 鎖が途中で切れている以上その答えは出ていない。緑にすると、次に読む人は
    // 「N本で収束した」だけを持ち帰る——§S66で2回踏んだ「短い一覧を全部と読む」そのものである。
    if !sweep.cut_by.is_empty() {
        failures.push(format!(
            "[{label}] 収束した段（{:?}）で、**宣言しても通らない拒否が残っている**: {:?}。\
             鎖はここで切れており、その先で起きるはずだった子は1つも観測できていない。\
             したがってこの{}本は**下限であって「全部」ではない**。\
             理由が`SpawnFailed`なら辺は許可されていて`CreateProcess`が落ちている\
             （宣言ではなく起こし方の問題）、`NotRegistered`なら呼び出し元がDaemonの\
             Process Tableに載っていない（鎖の深さの問題）——どちらなのかで次の一手が変わる。\
             Daemonが書いた「何で落ちたか」（{}行）: {:?}",
            sweep.converged_at,
            sweep.cut_by,
            sweep.declared.len(),
            sweep.cut_reasons.len(),
            sweep.cut_reasons
        ));
    }
    // **拒否が出なくなっただけでは「全部そろった」と言えない**（2026-09-19に偽の緑を踏んだ）。
    // 断られる前に諦める段があると、その先のプログラムは**起動を試みられないので拒否に現れない**
    // ——新しい拒否が出ないまま収束し、一覧は下限のまま緑になる。
    // **台本が最後まで通ったことを、収束と同じ重さで要求する。**
    //
    // **要求は掃きごとに違う。** 道具を隠した対照の掃きは、ビルドが通らないのが**正しい姿**で
    // ある（cargoの実体が見えないのだから当然そこまで行けない）。そこへ同じ要求を当てると、
    // **計器が正しい対照を「測定が成立していない」と言う**——2026-09-19に1度そうなった。
    match (expect_build, sweep.built) {
        // 通るはずの掃きで通った。健全。
        (true, Some(true)) => {}
        (true, Some(false)) => failures.push(format!(
            "[{label}] 新しい拒否は出なくなった（収束: {:?}・切断なし）が、\
             **台本のビルドは最後まで通っていない**（`{SURVEY_BUILD_NG}`）。\
             リンカのように「探す側が諦めた」プログラムは**起動を試みられないので拒否に現れない**\
             ——したがってこの{}本は**下限であって「全部」ではない**。\
             run_shellの本文でどこで諦めたかを名指しすること",
            sweep.converged_at,
            sweep.declared.len()
        )),
        // **通らないはずの掃きで通ってしまった**＝振っている軸が無い。
        (false, Some(true)) => failures.push(format!(
            "[{label}] 道具を見えるようにしていない掃きで、**ビルドが最後まで通ってしまった**。\
             2つの掃きが同じものを測っており、振っている軸が無い\
             ——`--fs-allow`の残りACEに相乗りしていないかを実DACLで見ること"
        )),
        // 通らないはずの掃きで通らなかった。**これは正しい対照である**（赤にしない）。
        (false, Some(false)) => eprintln!(
            "[survey] [{label}] ビルドは通っていない。**この掃きではそれが正しい**\
             （道具の実体が見えないので、そこまで到達しない）"
        ),
        (_, None) => failures.push(format!(
            "[{label}] ビルドの印が片方も出ていない。台本のcargoの段までシェルが到達して\
             いないので、**一覧が全部かを判定できない**"
        )),
    }
    sweep
}

/// **既定の宣言一式の一次データを測る**（⑤を既定へ入れる準備①）。
///
/// # 何を測っているのか
///
/// 「遷移MACが効くか」ではない（それは§S63と§S64が測った）。ここで測るのは
/// **実務に近いセッションを回すために、宣言へ何本書かないといけないのか**である。
/// 設計書（`plans/DESIGN-MAC-ENFORCEMENT.md`）が「旗を立てた回に何が断られるかを数えることが、
/// 既定の宣言一式の一次データになる」と定めているものの実体化にあたる。
///
/// # 1回撃っただけでは一覧が出揃わない
///
/// **断られた時点でその先が起きない。** gitを断ればgitが起こすはずだった子は現れないので、
/// 宣言を0本から始めて**断られたものを足しては撃ち直す**。新しく断られるものが
/// 無くなった回が「鎖の全段が出た」印である。
///
/// # 掃きは2つある（**振っている軸は「道具が見えるか」1つだけ**）
///
/// §S66の一覧が3本で収束したのは「足りている」からではなかった——`cargo`は
/// サンドボックスから実体が読めず、**遷移MACには1度も届いていなかった**。そこで
/// [`survey_visibility_grants`]で実体を読めるようにした掃きを足し、**同じ台本・同じ反復で
/// 並べて読める**ようにしてある。
///
/// | 掃き | `--fs-allow` | 何を表すか |
/// |---|---|---|
/// | `invisible` | 無し | 今日のTier2aで元から到達できる道具だけ |
/// | `visible` | `.cargo`/`.rustup` | `cargo`まで到達できるようにしたときの一覧 |
///
/// **`invisible`は§S66の再現ではない。** 同じ引数で撃っているが、`node`・`npm`は
/// §S66が「見えない」と記録したのに対してこちらでは見えている
/// （[`survey_visibility_grants`]のdoc）。**2つの測定が食い違っているので、
/// §S66の本数と直接は引き算できない**——並べて読む相手はこの`invisible`の側である。
///
/// **順序は「見えない」が先である。** `--fs-allow`のACEは**harnessの終了後も残る**ので、
/// 先に見える側を撃つと、続く「見えない」側が前の掃きの付与に相乗りしてしまう。
///
/// # これは合否のテストではなく、測定である
///
/// 赤くなるのは**測定が成立していないとき**だけにしてある——旗なしの腕で拒否が出た
/// （遷移MAC以外の何かが止めている）／旗ありの段0で拒否が1件も出ない（強制が効いていない）／
/// 上限まで回っても収束しない／**収束した段に、宣言しても通らない拒否が残っている**
/// （[`SurveySweep::cut_by`]。鎖がそこで切れているので一覧は下限にすぎない）／
/// **2つの掃きが同じものを見ている**（軸を振れていない）。
/// **「何本だった」を合格条件にしない**——機械に入っているものが変われば本数は変わる。
///
/// # このテストが実マシンに残すもの
///
/// [`survey_visibility_grants`]の3ディレクトリへ、**この測定用ワークスペースの宣言から
/// 導出したcapability SID宛の読取＋実行ACE**が残る（`--fs-allow`のACEはセッション終了で
/// 剥がれない）。**剥がさないのは意図した選択**である——剥がすと次にこの測定を回すたびに
/// 18万ノードへのDACL再伝播を払うことになり、かつ「既定の宣言一式」を決める作業自体が
/// この到達性を前提にしている。代わりに、**何を残したかを終わりに必ず出す**
/// （撤収の扉は`harness fs revoke <path>`）。
#[test]
#[ignore = "starts several real Tier2a sessions with the transition MAC enforced; run through dev-elevated-run"]
fn what_a_realistic_session_needs_declared() {
    // `--fs-allow`は`fs-passthrough-ledger.json`へ書く。**保護対象の台帳**なので、
    // 全件を並行実行する`e2e-all`で隣（`tier2a_fs_allow_matrix`等）と撃ち合わないよう、
    // テスト関数の全体で排他ガードを持つ（このファイル冒頭「共有資源の排他」の4番）。
    let ledger = fs_ledger_exclusive();

    let ws = case_dir("declaration-survey");
    seed_survey_workspace(&ws).unwrap_or_else(|e| panic!("仕掛けを置けなかった: {e}"));

    let (script, skipped) = survey_script_for_this_machine();
    assert!(
        !script.is_empty(),
        "台本が空である。候補のプログラムが1つもこの機械に無い（載せなかった: {skipped:?}）"
    );
    eprintln!(
        "[survey] 台本（{}行）:\n{script}\n[survey] この機械に無くて載せなかったもの: {skipped:?}",
        script.lines().count()
    );

    let mut failures: Vec<String> = Vec::new();

    // --- 腕A: 旗を立てない。**今日の既定では拒否が1件も起きない**ことの確認 ---
    let unenforced =
        run_arm_collecting_denials(&ws, "survey-unenforced", false, &script, "survey", &[])
            .unwrap_or_else(|e| panic!("腕A（旗なし）が測れなかった: {e}"));
    if !unenforced.denied_by_daemon.is_empty() {
        failures.push(format!(
            "腕A: 旗を立てていないのに拒否が出ている（{:?}）。**遷移MAC以外の何かが止めている**ので、\
             以後の段の「断られた」を遷移MACの成果として数えられない",
            unenforced.denied_by_daemon
        ));
    }
    // **旗と無関係に名前が解決できないもの**を先に数えておく。旗ありの段0で同じ名前が出たとき、
    // 「遷移MACのせいで起動できない」と読み違えないための対照である。
    let candidate_names: Vec<&str> = SURVEY_CANDIDATES.iter().map(|(p, _)| *p).collect();
    let never_unenforced = programs_never_attempted(&unenforced.text, &candidate_names);
    eprintln!(
        "[survey] 腕A（旗なし）で名前を解決できなかったもの: {never_unenforced:?}\
         ——ここに出るものは**遷移MACとは無関係**である"
    );

    // --- 掃き1: 道具が見えないまま（§S66の再現） ---
    let invisible = run_declaration_sweep(
        &ws,
        &script,
        "invisible",
        &[],
        &never_unenforced,
        // **この掃きではビルドが通らないのが正しい。** 道具の実体が見えないので、
        // そもそもそこまで到達しない。通ってしまったら軸が振れていない。
        false,
        &mut failures,
    );

    // --- 掃き2: 道具の実体を読めるようにしてから ---
    let grants = survey_visibility_grants();
    let grant_args: Vec<String> = grants
        .iter()
        .flat_map(|(spelling, _)| ["--fs-allow".to_string(), spelling.clone()])
        .collect();
    eprintln!(
        "[survey] 見えるようにする宣言（{}件）: {:?}",
        grants.len(),
        grants.iter().map(|(s, _)| s).collect::<Vec<_>>()
    );
    let visible = if grants.is_empty() {
        failures.push(
            "見えるようにする対象が1つもこの機械に無い。**軸を振れていない**ので、\
             2つ目の掃きは1つ目と同じものを測ることになる"
                .to_string(),
        );
        None
    } else {
        Some(run_declaration_sweep(
            &ws,
            &script,
            "visible",
            &grant_args,
            &never_unenforced,
            // **この掃きではビルドが最後まで通るはずである。** 通らないなら、鎖の先で
            // 「探す側が諦めた」ものが在り、一覧は下限のままである。
            true,
            &mut failures,
        ))
    };

    // --- 腕C: 旗なし＋道具が見える。**差し込みの壁が無かったら鎖はどこまで行くか** ---
    //
    // # なぜこの腕で「壁の向こう」が見えるのか
    //
    // 旗を立てない構成では子を**シェル自身**が起こす。Daemonを通らないので、Daemonの入口が
    // 相手のビット数を見ずにx64のDLLを差し込んで失敗する窓（§S68）に**そもそも入らない**。
    // つまり「32bitの子を起こせない」という壁を外した世界がそのまま撃てる——**製品を
    // 1行も変えず、抜け道も作らずに**。
    //
    // # この腕が証明しないこと（**引き算しないこと**）
    //
    // - **Daemon側からx86を差し込めば通る、は証明しない。** ここは差し込み自体が起きない構成である
    // - **旗ありとの差を「遷移MACが持ち込んだ後退」と書けない。** 変えている軸が2つある
    //   （遷移の検査の有無と、差し込みの有無）。1軸の比較ではない
    let beyond_wall = if grant_args.is_empty() {
        None
    } else {
        match run_arm_collecting_denials(
            &ws,
            "survey-unenforced-visible",
            false,
            &script,
            "survey",
            &grant_args,
        ) {
            Ok(arm) => {
                let ok = arm.text.contains(SURVEY_BUILD_OK);
                let ng = arm.text.contains(SURVEY_BUILD_NG);
                eprintln!(
                    "[survey] 腕C（旗なし・道具が見える）: ビルドの印 OK={ok} NG={ng}\n\
                     [survey] 　→ {}",
                    if ok {
                        "**鎖は最後まで通った**。壁は差し込みの1枚だけである"
                    } else if ng {
                        "**別の理由で止まった**。壁はもう1枚ある——出力で名指しを探すこと"
                    } else {
                        "**印が片方も出ていない**＝その行までシェルが到達していない（測れていない）"
                    }
                );
                if !ok && !ng {
                    failures.push(format!(
                        "腕C: ビルドの印が片方も出ていない。台本のcargoの段までシェルが\
                         到達していないので、**壁の向こうを測れていない**。run_shellの本文:\n{}",
                        arm.text
                    ));
                }
                Some((ok, ng, arm))
            }
            Err(e) => {
                failures.push(format!("腕C（旗なし・道具が見える）が測れなかった: {e}"));
                None
            }
        }
    };
    // 腕Cは**拒否が1件も出ない**はずである（旗を立てていない）。出るなら遷移MAC以外が
    // 止めており、「壁の向こう」の観測として読めない。
    if let Some((_, _, arm)) = &beyond_wall {
        if !arm.denied_by_daemon.is_empty() {
            failures.push(format!(
                "腕C: 旗を立てていないのに拒否が出ている（{:?}）。**遷移MAC以外の何かが\
                 止めている**ので、この腕を「壁が無い世界」として読めない",
                arm.denied_by_daemon
            ));
        }
    }

    // --- 軸が実際に振れたかを判定する（**ここが新しい歯**） ---
    if let Some(visible) = &visible {
        // 1. 掃き1で**見えなかったものが1つも無い**なら、2つの掃きは同じ条件である。
        //
        // **この測定は2回目以降も同じ結果になる**（2026-09-19に2回撃って確かめた）。
        // `--fs-allow`のACEは残るが、宛先は**宣言ごとのcapability SID**であり、
        // 旗を渡さない掃きの子はそのcapabilityをトークンへ積んでいない——
        // ACEが在っても1バイトも読めない。だから残った付与に相乗りすることはなく、
        // ここが落ちるのは**宛先SIDの設計が変わった**か、誰かが別経路で
        // `ALL APPLICATION PACKAGES`等の広いACEを置いたときである。
        if invisible.invisible.is_empty() {
            failures.push(format!(
                "掃き`invisible`で**実体が見えなかったプログラムが1つも無い**（見えた={:?}）。\
                 この状態では2つの掃きが同じものを測っており、振っている軸が無い。\
                 `--fs-allow`の残りACEでは（宛先が宣言ごとのcapability SIDなので）こうならない\
                 ——**もっと広い宛先のACEが別経路で置かれていないか**を実DACLで見ること",
                invisible.visible
            ));
        }
        // 2. 掃き1で見えなかったものが、掃き2で見えるようになっていること。
        //    変わらないなら`--fs-allow`の付与が効いておらず、§S66の焼き直しにすぎない。
        let still_invisible: Vec<&String> = invisible
            .invisible
            .iter()
            .filter(|p| visible.invisible.contains(p))
            .collect();
        if !still_invisible.is_empty() {
            failures.push(format!(
                "掃き`visible`でも{still_invisible:?}の実体が見えていない。\
                 **`--fs-allow`の付与が効いていない**ので、この掃きは§S66の焼き直しである。\
                 起動側の`fs-allow`行（上のログ）と`harness fs`の台帳を見ること"
            ));
        }
    }

    // --- 2つの掃きを並べる（記録へ写す元になる） ---
    eprintln!("[survey] ===== 2つの掃きを並べる =====");
    for sweep in [Some(&invisible), visible.as_ref()].into_iter().flatten() {
        eprintln!(
            "[survey]   {:<9} 断られた{}本 / 収束した段={:?} / 段数={} / \
             鎖を切ったもの={:?} / 見えた={:?} / 見えなかった={:?} / 起動を試みてすらいない={:?}",
            sweep.label,
            sweep.declared.len(),
            sweep.converged_at,
            sweep.hops.len(),
            sweep.cut_by,
            sweep.visible,
            sweep.invisible,
            sweep.never_attempted,
        );
        for (hop, newly) in &sweep.hops {
            for exe in newly {
                eprintln!("[survey]     {:<9} 段{hop}: {exe}", sweep.label);
            }
        }
        for line in &sweep.cut_reasons {
            eprintln!("[survey]     {:<9} 鎖を切った理由: {line}", sweep.label);
        }
    }
    eprintln!("[survey] ===== 載せなかったプログラム: {skipped:?} =====");

    // --- 腕C（壁の向こう）の結論を1行で出す ---
    eprintln!("[survey] ===== 壁の向こう（腕C: 旗なし・道具が見える） =====");
    match &beyond_wall {
        None => eprintln!("[survey]     撃っていない（見えるようにする対象がこの機械に無い）"),
        Some((true, _, _)) => eprintln!(
            "[survey]     ビルドは**最後まで通った**。鎖を止めているのは差し込みの1枚だけで、\
             その後ろに別の壁は無い（この台本の範囲では）"
        ),
        Some((_, true, _)) => eprintln!(
            "[survey]     ビルドは**通らなかった**。差し込みの壁を外しても別の理由で止まる\
             ——**壁はもう1枚ある**"
        ),
        Some(_) => eprintln!("[survey]     印が出ておらず、測れていない"),
    }

    // --- 実マシンに何を残したかを出す（剥がさない選択をしたので、必ず言う） ---
    eprintln!("[survey] ===== 実マシンに残した`--fs-allow`の付与 =====");
    for (spelling, dir) in &grants {
        match ledger.entry_for(dir) {
            Ok(Some((managed, workspaces))) => eprintln!(
                "[survey]   {} （宣言={spelling}）: 台帳に在り settings_managed={managed} \
                 参照ワークスペース={workspaces:?} / 撤収は `harness fs revoke \"{}\"`",
                dir.display(),
                dir.display()
            ),
            // **「台帳に無い」を黙らせない**（`B-10`）。付与が失敗した回と、
            // 付与はできたのに記録が漏れた回は、どちらもここで無印になる。
            Ok(None) => eprintln!(
                "[survey]   {} （宣言={spelling}）: **台帳にエントリが無い**\
                 ——付与できなかったか、記録が漏れている",
                dir.display()
            ),
            Err(e) => eprintln!("[survey]   {} : 台帳を読めなかった: {e}", dir.display()),
        }
    }

    assert!(
        failures.is_empty(),
        "測定が成立していない（{}件）:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// **残課題#39の残り**: `.git/config`から発火する鎖を、**1段ごとに別のドメインへ渡る形**で
/// 測る。2026-09-18の測定（§S64）は**同じドメインの中**までしか測れていなかった。
///
/// # なぜ今まで測れなかったのか
///
/// 別のドメインで子を起こすには、そのドメインの実体（専用のpackage SIDとcapabilityの組）が
/// 要る。それを作る発行器が無かったので、別ドメインを指す辺は宣言できても**必ず断られた**
/// （残課題#45／#55）。**2026-09-20に骨格が着地して、初めてこの形が撃てるようになった。**
///
/// # 何を測るのか（**「gitを禁止できるか」ではない**）
///
/// 同じ1手（`git -c safe.directory=* diff`）を、宣言を1段ずつ足しながら撃つ。
/// 違いは**足す辺の`to`だけ**である。
///
/// ```text
///   §S64（測り済み）: 入口 --git--> 入口 --git--> 入口 --findstr--> 入口
///   ここ（新規）    : 入口 --git--> d0  --git--> d1  --findstr--> d2
/// ```
///
/// 段ごとに別のドメインへ渡るので、**「どこから起こされたか」で許否が変わる**かどうかが
/// 初めて見える。
///
/// # 対で撃つ（`B-35`）
///
/// 1. **許可側**: 鎖を全部宣言したら**発火する**。これが無いと、次の拒否側は
///    「全部断る実装」でも緑になる。**別ドメインで起きた子が本当に動けるか**の確認でもある
///    ——用意したドメインに積むのはセッション共通の土台だけなので、
///    「起きたが何もできない」状態があり得る
/// 2. **拒否側**: 最後の1歩だけ別のプログラムを宣言したら**発火しない**（測り方(a)）
///
/// # ここで測っていないもの（**外挿しない**）
///
/// - 測り方(c)（宣言を**辺の集合**として持っているか**経路の集合**として持っているか）は
///   別の腕で撃つ。ここは鎖が跨げることだけを見る
/// - `diff.external`以外の発火キー（[BUG-150](../../../docs/bugs/BUG-150.md)が14件挙げている）
#[test]
#[ignore = "starts several real Tier2a sessions with the transition MAC enforced; run through dev-elevated-run"]
fn the_git_config_trap_chain_is_judged_across_domains() {
    let ws = case_dir("git-config-chain");
    plant_git_config_trap(&ws).unwrap_or_else(|e| panic!("仕掛けを置けなかった: {e}"));

    let mut failures: Vec<String> = Vec::new();

    // --- 鎖を1段ずつ、別ドメインへ渡る形で宣言していく ---
    let mut hops: Vec<String> = Vec::new();
    let mut fired_at: Option<usize> = None;

    for hop in 0..GIT_TRAP_MAX_HOPS {
        declare_chain(&ws, &hops).unwrap_or_else(|e| panic!("段{hop}の宣言を書けなかった: {e}"));
        let case_name = format!("git-chain-hop{hop}");
        let arm = run_git_trap_arm(&ws, &case_name, true)
            .unwrap_or_else(|e| panic!("段{hop}が測れなかった: {e}"));

        if arm.fired {
            fired_at = Some(hop);
            break;
        }

        // **用意できなかったドメインへの遷移と、宣言が無い遷移を混ぜない。**
        // 前者ならharness側の警告に理由が出ているはずで、宣言を足しても直らない。
        if arm.text.contains("target_domain_not_provisioned") {
            failures.push(format!(
                "段{hop}: 遷移先ドメインの**実体を用意できていない**。宣言の不足ではないので、\
                 段を足しても鎖は伸びない。起動時の警告に理由が出ている（`warning: transitions \
                 into the domain ...`）。ここまでの鎖: {hops:?}／本文:\n{}",
                arm.text
            ));
            break;
        }

        let mut newly: Vec<String> = Vec::new();
        for exe in &arm.denied_by_daemon {
            let known = hops
                .iter()
                .chain(newly.iter())
                .any(|d| d.eq_ignore_ascii_case(exe));
            if !known {
                newly.push(exe.clone());
            }
        }
        if newly.is_empty() {
            failures.push(format!(
                "段{hop}: 発火は止まったが、**待ち行列に新しい拒否が1件も無い**。\
                 止めたのがDaemonではない（カーネルが止めたが購読者が居ない）か、\
                 そもそも生成が起きていない。ここまでの鎖: {hops:?}／本文:\n{}",
                arm.text
            ));
            break;
        }
        // **1段につき1本だけ伸ばす。** 2本以上を同じ段へ足すと、その段の遷移元が
        // どちらのドメインなのかが決まらない（鎖ではなく木になる）。
        if newly.len() > 1 {
            eprintln!(
                "[git-chain] 段{hop}: 同じ段で{}件断られた。鎖として測れるのは1本ずつなので、\
                 先頭（{}）だけを足す: {newly:?}",
                newly.len(),
                newly[0]
            );
        }
        hops.push(newly[0].clone());
    }

    // **軸が振れたことを、発火した構成そのもので確かめる**（`measurement-review`検問3）。
    assert_chain_crosses_domains(&ws, "鎖", 2);

    let fired_at = match fired_at {
        Some(hop) => hop,
        None => {
            panic!(
                "**鎖が別ドメインを跨いで伸びなかった。** {GIT_TRAP_MAX_HOPS}段まで宣言しても\
                 発火していない。ここまでの鎖: {hops:?}／積み上がった失敗: {failures:?}"
            );
        }
    };

    // --- 許可側の確認（対の片方。`B-35`） ---
    assert!(
        fired_at > 0,
        "段0（宣言が1本も無い状態）で発火した。遷移MACが`.git/config`から発火した子を\
         1つも止めていない"
    );
    eprintln!("[git-chain] 鎖は{fired_at}段で発火した: {hops:?}");

    // --- 拒否側: **最後の1歩だけ別のプログラム**にする（測り方(a)） ---
    //
    // 鎖の手前は同じまま、最後の段の遷移先で**別のプログラムを宣言する**。
    // 経路の最後が食い違うだけで止まるはずである。
    let mut altered = hops.clone();
    let real_last = altered.pop().expect("鎖は1段以上ある");
    altered.push(GIT_TRAP_DECOY_EXE.to_string());
    declare_chain(&ws, &altered).unwrap_or_else(|e| panic!("拒否側の宣言を書けなかった: {e}"));
    let refused_arm = run_git_trap_arm(&ws, "git-chain-last-hop-swapped", true)
        .unwrap_or_else(|e| panic!("拒否側が測れなかった: {e}"));
    if refused_arm.fired {
        failures.push(format!(
            "**最後の1歩を別のプログラム（{GIT_TRAP_DECOY_EXE}）に差し替えても発火した。**\
             経路の最後が食い違っているのに通っている——宣言した綴りと実際に起きたものが\
             別々に判定されている（本当に起きたのは {real_last}）。本文:\n{}",
            refused_arm.text
        ));
    }
    // **止めたのが遷移MACであることを、断った当人（Daemon）の記録で言う。**
    //
    // gitのstderrの綴りでは判定しない——同じ拒否でも、**鎖のどこで断られたかによって
    // 文面が変わる**。段0ではフックが`ERROR_ACCESS_DENIED`を返すので`Access is denied`だが、
    // 最後の段で断られると**gitが自分の言葉に訳して**`Permission denied`と出す
    // （2026-09-20に実測。この腕は最初そこで赤くなった——**機構は効いていたのに、
    // 計器が別の綴りを探していた**）。
    let refused_the_real_last = refused_arm
        .denied_by_daemon
        .iter()
        .any(|exe| exe.eq_ignore_ascii_case(&real_last));
    if !refused_the_real_last {
        failures.push(format!(
            "拒否側: 発火はしていないが、**Daemonの待ち行列に{real_last}を断った記録が無い**。\
             止めたのが遷移MACだと言えない（カーネルが止めたが購読者が居ない／そもそも\
             生成が起きていない、のどちらか）。断った一覧: {:?}／本文:\n{}",
            refused_arm.denied_by_daemon, refused_arm.text
        ));
    }

    // --- 測り方(c): 宣言は**辺の集合**か、**経路の集合**か ---
    //
    // # これが無いと何が素通りするか
    //
    // ここまでの2本（発火する／最後を差し替えると止まる）は、**どちらの実装でも同じ結果になる**。
    // 判別するには、同じプログラムへの辺を**別の出発点から**宣言しておいて、
    // こちらの経路では宣言していない状態で撃つ。
    //
    // ```text
    //   正しい鎖1（入口から）: 入口 --g0--> d0  --g1--> d1  --囮--> d2
    //   正しい鎖2（別の所から）:  x  --g1--> xd0 --g2--> xd1
    //   実際に走るのは          : 入口 --g0--> g1 --g2-->  ← 最後の1歩はd1から出る
    // ```
    //
    // `d1`は`g2`への辺を持たない。持っているのは`xd0`である。
    // **辺の集合として持っているなら通り、経路の集合として持っているなら断られる。**
    //
    // # ここが「鎖が本当に跨いでいる」ことの証拠でもある
    //
    // 上の2本は、判定器が全部を1つのドメインへ畳んでいても同じ結果になる
    // （§S64の自己ループの測定と見分けが付かない）。この腕が拒否側で成立して初めて、
    // **遷移元のドメインによって答えが変わっている**と言える。
    if hops.len() >= 3 {
        let mut file = harness_policy::policy_file::PolicyFile::default();
        // 鎖1: 入口から。**最後の1歩だけ囮**にして、`g2`への辺をこちら側から消す。
        let mut chain_one = hops.clone();
        let last = chain_one.pop().expect("3段以上ある");
        chain_one.push(GIT_TRAP_DECOY_EXE.to_string());
        add_chain(
            &mut file,
            &chain_one,
            harness_policy::policy_file::ENTRY_DOMAIN,
        )
        .unwrap_or_else(|e| panic!("(c)の鎖1を組めなかった: {e}"));
        // 鎖2: **別の出発点**から、`g1 → g2`をそのまま宣言する。
        add_chain(&mut file, &hops[hops.len() - 2..], BORROWED_CHAIN_ORIGIN)
            .unwrap_or_else(|e| panic!("(c)の鎖2を組めなかった: {e}"));
        harness_policy::policy_file::save(&ws, &file)
            .unwrap_or_else(|e| panic!("(c)の宣言を書けなかった: {e}"));
        assert_chain_crosses_domains(&ws, "(c)", 2);

        let borrowed = run_git_trap_arm(&ws, "git-chain-borrowed-edge", true)
            .unwrap_or_else(|e| panic!("(c)が測れなかった: {e}"));
        if borrowed.fired {
            failures.push(format!(
                "**(c) 別の出発点のために宣言した辺を横取りできた。** `{last}`への辺を\
                 宣言しているのは`{BORROWED_CHAIN_ORIGIN}`から伸びる鎖だけなのに、\
                 入口から伸びる鎖の途中から使えている——宣言を**辺の集合**として持っており、\
                 遷移元のドメインを見ていない。本文:\n{}",
                borrowed.text
            ));
        }
        let refused_here = borrowed
            .denied_by_daemon
            .iter()
            .any(|exe| exe.eq_ignore_ascii_case(&last));
        if !refused_here {
            failures.push(format!(
                "(c): 発火はしていないが、**`{last}`を断った記録が無い**。\
                 止めたのが遷移MACだと言えない。断った一覧: {:?}／本文:\n{}",
                borrowed.denied_by_daemon, borrowed.text
            ));
        }
        eprintln!(
            "[git-chain] (c) 横取り: fired={} 断った一覧={:?}",
            borrowed.fired, borrowed.denied_by_daemon
        );
    } else {
        failures.push(format!(
            "(c)を撃てなかった: 鎖が{}段しかない（3段以上が要る）。鎖: {hops:?}",
            hops.len()
        ));
    }

    assert!(
        failures.is_empty(),
        "残課題#39（鎖・別ドメイン）で{}件の問題が出た:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

/// [残課題#39・§S73の宿題] **遷移先ドメインは、呼び出し元より狭いか。**
///
/// # 何が分からなかったのか
///
/// §S73は「鎖が別のドメインを跨いで判定される」ことまで測ったが、
/// **そこで言えたのは「別のドメインとして判定された」までだった**。
/// 遷移先は宣言を1件も持たないので、積まれるのは**セッション共通の土台**
/// （祖先traverse・spawn要求・workspace・Redirector DLL）だけで、入口と権限が等しい。
/// **権限が実際に狭いことは1度も測っていない。**
///
/// # 測り方——呼び出し元にだけある鍵を1つ作る
///
/// `--fs-allow`でワークスペースの**外**のディレクトリを1つ開ける。この許可は
/// 宣言ごとのcapability SID宛に書かれ（D-54・§22.3）、**セッションのトークンには載るが、
/// 遷移先ドメインの土台には載らない**（`domain_provision::capability_sids_for`は
/// そのドメイン自身の宣言しか引かない）。したがって予測はこうなる。
///
/// | 読む相手 | 入口ドメイン（シェル自身） | 遷移先ドメイン（`findstr`） |
/// |---|---|---|
/// | **外**のファイル（`--fs-allow`で開けた） | 読める | **読めない** ← 狭まりの証拠 |
/// | ワークスペースの中のファイル | 読める | **読める** ← 「何も読めない」ではない |
///
/// # 4つ全部を同じ回で撃つ（`B-35`）
///
/// **右下が無いと、この測定は何も言わない。** 遷移先の子が
/// 「起きたが何も読めない」状態（土台を積み忘れた・そもそも走っていない）でも、
/// 右上は同じ「読めない」になる。**狭いことと、壊れていることを分けるのが右下である。**
///
/// **左側（入口ドメイン）が対照になる。** 外のファイルが誰からも読めないなら、
/// 測っているのは`--fs-allow`が効いていないことであって、ドメインの狭さではない。
///
/// # 子が読めなかった理由を取り違えない
///
/// `findstr`が失敗する理由は2つある——**遷移MACに断られた**（宣言が無い）か、
/// **起きたがファイルを開けなかった**（ACLで拒否された）か。前者なら待ち行列に載るので、
/// **待ち行列に`findstr`が載っていないこと**を同じ回で確かめる。
/// 載っていれば測っているのは狭さではなく宣言漏れである。
#[test]
#[ignore = "grants a real fs-allow ACE and starts Tier2a sessions; run through dev-elevated-run"]
fn a_transition_target_domain_is_narrower_than_the_caller() {
    let _ledger = fs_ledger_exclusive();
    let ws = case_dir("domain-narrowing");
    let outside = fs_allow_case_dir("narrowing");

    const MARKER: &str = "NARROWINGMARKER";
    std::fs::write(outside.join("secret.txt"), format!("{MARKER}\n"))
        .unwrap_or_else(|e| panic!("外のファイルを置けなかった: {e}"));
    std::fs::write(ws.join("inside.txt"), format!("{MARKER}\n"))
        .unwrap_or_else(|e| panic!("中のファイルを置けなかった: {e}"));

    let findstr = format!(
        r"{}\System32\findstr.exe",
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
    );
    // 遷移先は**宣言を1件も持たない**（持たせると用意できず、測っているものが変わる）。
    declare_chain(&ws, std::slice::from_ref(&findstr))
        .unwrap_or_else(|e| panic!("遷移の宣言を書けなかった: {e}"));
    assert_chain_crosses_domains(&ws, "狭まり", 1);

    // **`findstr`へ渡すパスは`\`区切りにする**（2026-09-20に踏んだ）。
    //
    // `/`区切りで渡すと、`findstr`は**権限があっても開けない**——`/`で始まるトークンを
    // 自分のオプションとして食うためである。同じ回で区切りだけを変えて確かめた:
    // 鍵を持たせた構成で、`/`区切りは失敗（終了コード1）、`\`区切りは**成功**（0）した。
    // **`/`のままだと、測っているのは権限ではなく`findstr`の引数解析になる。**
    //
    // `Get-Content`（シェル自身）はどちらの区切りでも同じなので、そちらは影響を受けない。
    let out_dir = outside.display().to_string();
    let in_dir = ws.display().to_string();
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         $a = Get-Content -LiteralPath '{out_dir}\\secret.txt' -Raw; \
         Write-Output ('SHELL_OUTSIDE=' + $(if ($a) {{'OK'}} else {{'DENIED'}})); \
         $b = Get-Content -LiteralPath '{in_dir}\\inside.txt' -Raw; \
         Write-Output ('SHELL_INSIDE=' + $(if ($b) {{'OK'}} else {{'DENIED'}})); \
         findstr /c:{MARKER} '{out_dir}\\secret.txt' | Out-Null; \
         Write-Output ('CHILD_OUTSIDE_RC=' + $LASTEXITCODE); \
         findstr /c:{MARKER} '{in_dir}\\inside.txt' | Out-Null; \
         Write-Output ('CHILD_INSIDE_RC=' + $LASTEXITCODE)"
    );

    let allow = format!(r"{}\**", outside.display());
    let arm = run_arm_collecting_denials(
        &ws,
        "domain-narrowing",
        true,
        &script,
        "narrowing",
        &["--fs-allow".to_string(), allow.clone()],
    )
    .unwrap_or_else(|e| panic!("腕が測れなかった: {e}"));

    // **子が遷移MACに断られていないこと。** 断られていたら、測っているのは狭さではなく宣言漏れ。
    let refused_by_mac = arm
        .denied_by_daemon
        .iter()
        .any(|exe| exe.eq_ignore_ascii_case(&findstr));
    assert!(
        !refused_by_mac,
        "`findstr`が遷移MACに断られている。**この回は狭さを測っていない**——\
         宣言（{findstr}）が効いていないので、子はそもそも起きていない。\
         断った一覧: {:?}／本文:\n{}",
        arm.denied_by_daemon, arm.text
    );

    // `findstr`の終了コード: 0=見つかった（＝読めた）、1=見つからない、2=開けない。
    let cell = |key: &str| -> String {
        arm.text
            .lines()
            .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
            .unwrap_or_else(|| {
                panic!(
                    "`{key}`の行が本文に無い。台本が最後まで走っていない:\n{}",
                    arm.text
                )
            })
    };
    let shell_outside = cell("SHELL_OUTSIDE=");
    let shell_inside = cell("SHELL_INSIDE=");
    let child_outside = cell("CHILD_OUTSIDE_RC=");
    let child_inside = cell("CHILD_INSIDE_RC=");
    eprintln!(
        "[narrowing] シェル(入口): 外={shell_outside} 中={shell_inside}／\
         子(遷移先): 外のRC={child_outside} 中のRC={child_inside}"
    );

    let mut failures: Vec<String> = Vec::new();

    // --- 左列: 入口ドメインは両方読める（対照） ---
    if shell_outside != "OK" {
        failures.push(format!(
            "入口ドメインが**外のファイルを読めていない**（{shell_outside}）。\
             `--fs-allow`が効いていないので、この回は狭さを測っていない\
             ——「誰も読めない」と「遷移先だけ読めない」が区別できない"
        ));
    }
    if shell_inside != "OK" {
        failures.push(format!(
            "入口ドメインが**ワークスペースの中も読めていない**（{shell_inside}）。\
             セッションそのものが壊れている"
        ));
    }

    // --- 右下: 遷移先はワークスペースを読める（「何も読めない」ではないことの証拠） ---
    if child_inside != "0" {
        failures.push(format!(
            "遷移先ドメインの子が**ワークスペースの中も読めていない**（終了コード{child_inside}）。\
             **この回の「外が読めない」は狭さの証拠にならない**——土台（workspace capability）が\
             積まれていないか、子が走っていないだけかもしれない"
        ));
    }

    // --- 右上: 本体。遷移先は外を**開けない** ---
    //
    // **終了コードだけで判定しない。** `findstr`は「見つからなかった」も「開けなかった」も
    // **1**を返す（2026-09-20に実測。2ではない）。前者なら**読めている**ので、
    // 混ぜると結論が反転する。開けなかったときだけ出る`FINDSTR:`の行で決める。
    //
    // **文面では照合しない**——このメッセージは地域化される（この機械では
    // 「開くことができません」）。`FINDSTR:`の接頭辞と**パス**だけを見る。
    let cannot_open = |path: &str| -> bool {
        arm.text
            .lines()
            .any(|l| l.trim_start().starts_with("FINDSTR:") && l.contains(path))
    };
    let outside_file = format!("{out_dir}\\secret.txt");
    let inside_file = format!("{in_dir}\\inside.txt");
    if !cannot_open(&outside_file) {
        failures.push(format!(
            "遷移先の子が外のファイルを**開けなかったと言っていない**（終了コード{child_outside}）。             `findstr`は「見つからない」でも1を返すので、             **これだけでは「読めなかった」と言えない**: {outside_file}"
        ));
    }
    // **対**: 中のファイルでは同じ行が出ないこと。出ていたら、子は何も開けていない
    // ——「狭いから開けない」ではなく「壊れていて開けない」である。
    if cannot_open(&inside_file) {
        failures.push(format!(
            "遷移先の子が**ワークスペースの中も開けていない**。             外が開けないのは狭さの証拠にならない: {inside_file}"
        ));
    }
    if child_outside == "0" {
        failures.push(
            "**遷移先ドメインが、呼び出し元にしか無いはずの許可で外のファイルを読めた。**\
             宣言ごとのcapabilityが遷移先の土台へ漏れている——ドメインを分けても\
             **権限は1ビットも狭まっていない**（§10.1.2が却下した形と同じ結果）"
                .to_string(),
        );
    }

    // --- 反転の対照: **遷移先に同じ鍵を渡すと、読めるようになるか** ---
    //
    // # これが無いと何が言えないか
    //
    // 上の4升だけだと、「遷移先が狭いから読めない」と「遷移先には**そもそも鍵を渡す道が無い**
    // から読めない」を区別できない。**同じ台本のまま、宣言を1つ足すだけで反転する**なら、
    // 読めなかった理由は「その鍵を持っていなかったこと」だと言い切れる。
    //
    // 骨格は**既に許可済みの宣言しか引かない**ので、`--fs-allow`で開けたのと同じパスを
    // 遷移先ドメイン自身の宣言に書けば引けるはずである
    // （`domain_provision::capability_sids_for`）。**この経路が端から端まで通るのは初めて**で、
    // 単体テストは「引けなければ用意しない」側しか測っていない。
    {
        let mut file = harness_policy::policy_file::PolicyFile::default();
        add_edge(
            &mut file,
            harness_policy::policy_file::ENTRY_DOMAIN,
            &findstr,
            "d0",
        )
        .unwrap_or_else(|e| panic!("反転の対照の辺を組めなかった: {e}"));
        // **両側に同じ宣言を置く。** 遷移先にだけ書くと、編集時検査が
        // 「権限が広がる（または狭まることを証明できない）辺」として**宣言ごと拒否する**
        // ——2026-09-20に実際に拒否された。検査が見るのは`policy.json`の宣言だけで、
        // `--fs-allow`で入口側へ渡した鍵は**そこに現れない**ので、遷移先にだけ書くと
        // 片側だけが広いように読める。
        //
        // 入口側の宣言は**この回の挙動を1ビットも変えない**——harness本体はまだ
        // `policy.json`の`fs`を使わないので（残課題#30）、入口の鍵は`--fs-allow`由来のままである。
        //
        // **級は`read_exec`である。** `--fs-allow <path>`（`:rw`無し）が台帳へ登録する級は
        // `FsAccess::ReadExec`で、`read`ではない（`startup/sandbox.rs`の分岐）。
        // `fs.read`で宣言すると鍵の3軸（ワークスペース・パス・級）の級が合わず、
        // **許可済みなのに引けない**——2026-09-20に実際にそれで用意できなかった。
        let declared = format!(r"{}\**", outside.display());
        for name in [harness_policy::policy_file::ENTRY_DOMAIN, "d0"] {
            file.domains
                .iter_mut()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("ドメイン{name}が宣言に無い"))
                .fs
                .read_exec
                .push(declared.clone());
        }
        harness_policy::policy_file::save(&ws, &file)
            .unwrap_or_else(|e| panic!("反転の対照の宣言を書けなかった: {e}"));

        let flipped = run_arm_collecting_denials(
            &ws,
            "domain-narrowing-flipped",
            true,
            &script,
            "narrowing",
            &["--fs-allow".to_string(), allow.clone()],
        )
        .unwrap_or_else(|e| panic!("反転の対照が測れなかった: {e}"));

        // **用意できなかったなら、それは別の事実である。** 「狭いまま」と混ぜない。
        // **用意できなかったことは、起動時の警告で見る。** 本文に出るのは分類器が訳した
        // 文面（「harness未実装」）なので、生の理由の綴りを探しても当たらない
        // ——2026-09-20にそれで素通りした。
        if flipped.harness_stderr.contains("will be refused") {
            failures.push(format!(
                "反転の対照: 遷移先ドメインを**用意できなかった**ので、反転するかを測れていない。\
                 宣言したパスが許可済みとして引けていない（鍵の綴りか級が合っていない）。\
                 起動時の警告:\n{}",
                flipped.harness_stderr
            ));
        } else {
            let flipped_rc = flipped
                .text
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("CHILD_OUTSIDE_RC=")
                        .map(str::to_string)
                })
                .unwrap_or_default();
            let flipped_cannot_open = flipped
                .text
                .lines()
                .any(|l| l.trim_start().starts_with("FINDSTR:") && l.contains(&outside_file));
            eprintln!(
                "[narrowing] 反転の対照（遷移先にも同じ鍵）: 外のRC={flipped_rc} 開けない行={flipped_cannot_open}"
            );
            // **1ビットだけ変えて反転すること**が、狭さの機序を言い切れる唯一の根拠である。
            //
            // 上の4升だけだと「遷移先が狭いから読めない」と「遷移先には**そもそも鍵を渡す道が
            // 無い**から読めない」を区別できない。**同じ台本のまま宣言を1つ足すだけで読める**なら、
            // 読めなかった理由は「その鍵を持っていなかったこと」だと言える。
            //
            // **2026-09-20に初めて取れた。** それまでは`findstr`へ`/`区切りのパスを渡していて、
            // **鍵があっても開けなかった**（`findstr`が`/`で始まるトークンを自分のオプションとして
            // 食う）。区切りを`\`へ直したらこの腕が反転した。
            if flipped_cannot_open || flipped_rc != "0" {
                failures.push(format!(
                    "反転の対照: 遷移先に**同じ鍵を宣言しても読めないまま**である\
                     （RC={flipped_rc}、開けない行={flipped_cannot_open}）。\
                     **上の「読めなかった」を「鍵が無いから」と言い切れない**\
                     ——遷移先には鍵を渡す道そのものが無い可能性が残る。\
                     起動時の警告:\n{}",
                    flipped.harness_stderr
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "狭まりの測定で{}件の問題が出た:\n- {}\n本文:\n{}",
        failures.len(),
        failures.join("\n- "),
        arm.text
    );

    // **測定のために作った外のディレクトリは自分で掃く**（`measurement-review`検問11）。
    // 消すとその配下のACEも一緒に消える。
    let _ = std::fs::remove_dir_all(&outside);
}
