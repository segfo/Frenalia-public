//! Tier2a（AppContainer）のout-of-process E2E回帰テスト。CoWコミット粒度とネットワーク
//! ドメインポリシーの強制機構を、実`harness.exe`（`env!(CARGO_BIN_EXE_harness)`）を起動して
//! 検証する。LLM推論は一切使わない（`--provider mock`、`harness_providers::MockProvider`が
//! 台本化された`run_shell`呼び出しを返す）。
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
) -> HarnessRun {
    // **CoWセッションを作る唯一の入口**（BUG-135）。この関数が唯一であることは数えてある
    // ——このファイルで`--sandbox`を渡すのは16箇所で、16箇所すべてが`run_harness`／
    // `run_harness_with_exe`経由でここへ来る。`harness.exe`を直に起動している他の箇所は
    // 既存セッションを操作するサブコマンド（`apply`・`changes`・`discard`等）で、
    // `--sandbox`を渡さない＝差分層を新規に作らない。
    if extra_args.iter().any(|a| a.contains("tier2a-cow")) {
        assert_cow_exclusive_held("CoWセッションを作る（--sandbox tier2a-cow）");
    }

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
        cwd_arg,
        "--permission-mode",
        "accept-all",
        "--dangerously-allow",
        "--output-format",
        "json",
        "-p",
        "(scripted; prompt text is ignored by the mock provider)",
    ]);
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
    if let Some(dir) = cwd_for_process {
        cmd.current_dir(dir);
    }
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

    // 生JSONを返すメソッドは**置かない**。いま誰も要らないうえ、置けば
    // `raw().to_string().contains(..)`でBUG-137がそのまま復活する口になる。
    // 必要になった時点で、用途を限定した名前のメソッドとして足すこと。
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
                roots.first().expect("at least the profile root must resolve"),
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
fn case_m_new_file_created_and_deleted_within_same_cow_session(ex: &CowExclusive) -> Result<(), String> {
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
fn case_n_ls_merges_preexisting_and_new_files_read_does_not_dirty_ledger(ex: &CowExclusive) -> Result<(), String> {
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
fn case_o_direct_write_into_the_diff_layer_dir_is_recorded(ex: &CowExclusive) -> Result<(), String> {
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
    let ops_text = std::fs::read_to_string(cow_diff_layer_dir(&session).join(".harness-cow-ops.jsonl"))
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
    expect_eq("diff layer content", &diff_layer_content, "modified-by-agent")?;
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
    std::fs::write(ws.join("README.md"), "seed\n")
        .map_err(|e| format!("seed README: {e}"))?;
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
fn run_net_case(
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
) -> Result<(), String> {
    run_net_case_with_exe(
        &harness_exe(),
        name,
        allow_domains,
        case_matrix_case,
        deny_hosts_expected,
    )
}

/// `run_net_case`の`harness.exe`パスを差し替え可能な版（WFP fail-closedケース専用）。
fn run_net_case_with_exe(
    exe: &Path,
    name: &str,
    allow_domains: &[&str],
    case_matrix_case: &str,
    deny_hosts_expected: &[&str],
) -> Result<(), String> {
    run_net_case_with_exe_and_stderr_check(
        exe,
        name,
        allow_domains,
        case_matrix_case,
        deny_hosts_expected,
        None,
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
) -> Result<(), String> {
    let ws = net_case_ws(name);
    let mut extra_args = vec!["--staged"];
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
    run_net_case(
        "net-01-none",
        &[],
        "all-denied",
        &["example.com", "google.com"],
    )
}

fn net_case_02_invalid_domain() -> Result<(), String> {
    run_net_case(
        "net-02-invalid",
        &["invalidexample.com"],
        "all-denied",
        &["example.com", "google.com"],
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
    )
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
    let mut extra_args = vec!["--staged"];
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
fn fs_allow_case_bare_path_grants_the_object_only(ledger: &FsLedgerExclusive) -> Result<(), String> {
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
    let subjects = harness_sandbox::tier2a::win_appcontainer::fs_allow_capability_sids(&target, None);
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
    let user_modify = format!("*{user_sid}:(OI)(CI)(M)");
    let system_owner = format!("*{LOCAL_SYSTEM_SID}");
    icacls_on(dir, &["/inheritance:r"], "drop inherited ACEs")?;
    icacls_on(dir, &["/grant", system_full.as_str()], "grant SYSTEM full")?;
    icacls_on(dir, &["/grant", user_modify.as_str()], "grant user modify")?;
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
        // [測定7] 昇格が要るシステム保護パスの腕。**上の4本はどれも`preflight`の
        // `needs_elevation`へ入らない**（`C:\`直下の書けるパスなので、その場で書けてしまう）ので、
        // 宛先SIDを持ち回す形へ変えた区間はここが唯一の実行経路である。
        // **最後に置いてある**——所有者をLocalSystemへ移す腕なので、先に置くと前の4本が
        // 落ちたときにその残骸と混ざる。
        (
            "elevated-grant-opens-only-the-declared-subject",
            fs_allow_case_the_elevated_grant_opens_only_the_declared_subject,
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

fn chain_launch_case_no_extra_uac_path_is_taken() -> Result<(), String> {
    let ws = case_dir("chain-launch");
    // 3つとも必要な条件である。
    // - `--net-allow-domain`: ドメインポリシーが無いと`netfilterd`自体が起動せず、
    //   連鎖の**親**が存在しない（経路(A)が原理的に成立しない）
    // - `--staged`: 既定のLive staging modeでは`sandbox_dir`が`None`になり、
    //   `fs-audit.jsonl`の置き場が決まらないので収集器はそもそも起動しない
    //   （`run_agent.rs`が「could not resolve a sandbox session directory」と警告して無効化する）
    // - `--policy-learn true`: 収集器を有効にする
    let run = run_harness(
        &ws,
        &run_shell_script_turns("Get-Content -LiteralPath 'C:/Windows/System32/config/SAM' -ErrorAction SilentlyContinue; Write-Output 'ran'"),
        &["--staged", "--policy-learn", "true", "--net-allow-domain", "example.com"],
        "chain-launch",
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

    // 収集器が実際に動いた証拠。`.harness/sandbox/session-*/fs-audit.jsonl`。
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
    let body = std::fs::read_to_string(&audit).map_err(|e| e.to_string())?;
    if body.trim().is_empty() {
        return Err(format!("{} exists but is empty", audit.display()));
    }

    cleanup_on_success(&ws, &[], "chain-launch");
    Ok(())
}

#[test]
#[ignore]
fn tier2a_chain_launch_uses_the_no_extra_uac_path() {
    let cases: Vec<(&str, CaseFn)> =
        vec![("no-extra-uac", chain_launch_case_no_extra_uac_path_is_taken)];
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
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// 2つのワークスペースが同じパスを宣言している間はエントリが生き、両方が宣言を外して初めて
/// 撤収される（D-27の参照カウント）。
fn fs_ledger_case_shared_declaration_is_refcounted(ledger: &FsLedgerExclusive) -> Result<(), String> {
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
fn fs_ledger_case_concurrent_startups_do_not_lose_updates(ledger: &FsLedgerExclusive) -> Result<(), String> {
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
    let shared_entry = ledger.entry_for(&shared)
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
        &["--staged", "--net-allow-domain", "example.com"],
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
    // **`classify_drop`の記録は使えない。** この構成ではWFPのイベント収集を有効化できず
    // （`FwpmEngineSetOption0`が`FWP_E_DYNAMIC_SESSION_IN_PROGRESS` 0x8032000b を返す。
    // 動的セッションからは呼べない）、監査には制御レコードだけが載る。**「dropの記録が無い」を
    // 「dropしていない」と読まないため、ここで理由まで確かめておく**（B-10: 記録の不在は事実の不在ではない）。
    let audit_entries = collect_audit_entries(&ws.join(".harness").join("sandbox"))
        .unwrap_or_else(|e| panic!("{e}"));
    let collection_disabled = audit_entries.iter().any(|e| {
        e.get("reason")
            .and_then(|r| r.as_str())
            .is_some_and(|r| r.starts_with("net_event_collection_enable_failed"))
    });
    let has_drop_445 = audit_entries.iter().any(|e| {
        e.get("reason").and_then(|r| r.as_str()) == Some("classify_drop")
            && e.get("remote_port").and_then(|p| p.as_u64()) == Some(445)
    });
    assert!(
        has_drop_445 || collection_disabled,
        "445のdrop記録も、収集が無効だという制御レコードも無い。\
         **この監査ログは何も言っていない**ので、10013の出どころを主張できない。audit={audit_entries:?}"
    );
    eprintln!(
        "[N8-③-C-WFP] wfp classify_drop記録={has_drop_445} / イベント収集が無効={collection_disabled}"
    );

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
// D-79の付与コスト・2本割りの成否は`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md`のM2が持つ。
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
    let sids: Vec<&str> = found.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
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
    let script = EXEC_PROBE_SCRIPT.replace(
        "@PY@",
        if with_python { EXEC_PROBE_PY_LINE } else { "" },
    );
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
    std::fs::copy(net_probe_exe(), ws.join("netprobe.exe")).expect("copy the probe into the workspace");

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
        eprintln!("[exec-ace-net] 失敗したのでワークスペースを {} に残す", ws.display());
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
