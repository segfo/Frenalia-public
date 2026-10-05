//! `dev-elevated-runner`の共有部分（プロトコル型・入力検証・このランナー固有のパイプ名）。
//!
//! 名前付きパイプIPCの下回り（overlapped I/O・タイムアウト付きread/write・現在ユーザSID限定の
//! DACL）は持たない。`harness_sandbox::win_pipe_ipc`（privhelper・netfilterd・vmsandboxdと共有）を
//! 直接使う（下の`mod win`のdoc）。

use serde::{Deserialize, Serialize};

/// E2E専用のブローカー（[`RunRequest::LaunchPrivhelper`]の実装）。**`KNOWN_TARGETS`とは別の口**で、
/// 唯一クライアント由来の文字列が起動に影響する経路なので、縛りは全部そちらのモジュールが持つ。
///
/// 電文の型（[`PrivhelperLaunchRequest`]）だけは他のワイヤ型と一緒にこのファイルへ置く
/// ——ブローカーの実装は`harness-sandbox`のWindows専用モジュールに依存するが、
/// 型はプラットフォームに依らず直列化できる必要がある。
#[cfg(windows)]
pub mod privhelper_broker;

pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\dev-elevated-runner-";

/// 最終要求からこの時間操作が無ければサーバは自動終了する（タイマーではなく、
/// 「次のクライアント接続を待つ`ConnectNamedPipe`のタイムアウト」として実装する。
/// 退役した%TEMP%キューデーモンの教訓＝生存期間をOSの待機プリミティブに紐付ける、
/// を踏まえたもの。無期限の常駐にはしない）。
pub const IDLE_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(30 * 60);

// 固定ターゲット表は本体が1,000行を超えるので別ファイルに置く（`docs/CODE-STRUCTURE-RULES.md`規則1・規則3）。
mod targets;
pub use targets::KNOWN_TARGETS;

/// クライアント→デーモンの要求。
///
/// **`kind`タグ付きで直列化する。** タグの無い構造体のままフィールドを足すと、古いデーモンが
/// 新しい要求を「知らないフィールドは無視」して**別の要求として実行**し得る。タグを必須に
/// すれば、古い個体は解釈できずに落ちる（無言の取り違えより、はっきり落ちる方を選ぶ）。
/// 電文の型を変えたので、**動いているデーモンは先に止めてから再ビルドする**
/// （`docs/DEV-ENVIRONMENT.md`の`KNOWN_TARGETS`変更手順と同じ）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RunRequest {
    /// 固定テーブルから`cargo`引数列を引いて実行する（`dev-elevated-run.exe <target>`）。
    Target {
        /// `KNOWN_TARGETS`のキーのいずれかと完全一致する必要がある。
        target: String,
    },
    /// **E2E専用**: `harness-privhelper.exe`を昇格したまま起こす（`privhelper_broker`）。
    LaunchPrivhelper(PrivhelperLaunchRequest),
}

/// クライアント（非昇格のharness本体）→デーモンの、privhelper起動要求の中身。
///
/// **パイプ名は実行時に決まる**ので`KNOWN_TARGETS`の固定テーブルでは表せない。これが
/// このデーモンで唯一「クライアント由来の文字列が起動に影響する」経路であり、だからこそ
/// 受信側（`privhelper_broker`）が置き場・ファイル名・中身・パイプ名の形を検査する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivhelperLaunchRequest {
    /// 非昇格側が作って待っている名前付きパイプ（`\\.\pipe\harness-privhelper-...`）。
    pub pipe_name: String,
    /// `harness-privhelper.exe`が置いてあるディレクトリ（`C:\harness-e2e\`配下）。
    pub launcher_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// サーバ側が権威的に検証する（クライアント側でも同じ関数を使うが、クライアントを
/// 信用しない——実際にコマンドを起動するのはサーバ側の`resolve_target`であり、
/// そちらも独立に`KNOWN_TARGETS`の完全一致を要求する）。
pub fn validate_target(target: &str) -> Result<(), String> {
    if KNOWN_TARGETS.iter().any(|(name, _)| *name == target) {
        Ok(())
    } else {
        let known: Vec<&str> = KNOWN_TARGETS.iter().map(|(name, _)| *name).collect();
        Err(format!(
            "unknown target {target:?} (known targets: {known:?})"
        ))
    }
}

/// `target`に対応する固定引数列を返す。`validate_target`と同じ完全一致判定を独立に
/// 行うため、こちらを呼ぶだけでも安全（`validate_target`を呼び忘れても任意引数は
/// 実行されない）。
pub fn resolve_target_args(target: &str) -> Option<&'static [&'static str]> {
    KNOWN_TARGETS
        .iter()
        .find(|(name, _)| *name == target)
        .map(|(_, args)| *args)
}

/// `cargo test`のstdoutから、**実際に実行された**テスト件数（passed + failed）を数える。
///
/// テストハーネスはバイナリごとに
/// `test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 45 filtered out; ...`
/// を1行印字する。複数のテストバイナリが走る対象（`e2e-all`等）では**合計**を返す
/// ——個々のバイナリが0件になるのは正常（`--ignored`が1つも当たらないターゲットがある）で、
/// 「どれも走らなかった」だけが異常だからである。
///
/// `test result:`行が1つも無ければ`None`。これは「0件走った」とは違う状態
/// （テストハーネスがそもそも起動していない＝ビルド失敗等）なので、呼び出し側が
/// 区別できるようにする。
pub fn executed_test_count(stdout: &str) -> Option<u64> {
    let mut total: Option<u64> = None;
    for line in stdout.lines() {
        let Some(summary) = line.trim_start().strip_prefix("test result:") else {
            continue;
        };
        let passed = count_before(summary, "passed").unwrap_or(0);
        let failed = count_before(summary, "failed").unwrap_or(0);
        total = Some(total.unwrap_or(0) + passed + failed);
    }
    total
}

/// `ok. 12 passed; 0 failed; ...`から`label`直前の数値を取り出す。
///
/// 失敗した実行の要約は`FAILED. 10 passed; 2 failed; ...`という形なので、
/// 小文字の`failed`を探せば見出し語の`FAILED.`とは衝突しない。
fn count_before(summary: &str, label: &str) -> Option<u64> {
    let index = summary.find(label)?;
    summary[..index]
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

/// テストターゲットなのに1件も走らなかったら、それは「緑」ではなく**壊れたフィルタ**である。
///
/// `cargo test`はフィルタが1件もマッチしなくてもexit 0を返すため、`KNOWN_TARGETS`の
/// フィルタ文字列がモジュール改名に追随しそこねると、E2E一式が黙って走らなくなる
/// （`docs/bugs/BUG-056.md`。CoW封じ込めE2E 17件が実際にこれを踏んだ）。
/// **「テストが走っていない」は「テストが通った」と外形上区別が付かない**ので、
/// ここで明示的に潰す。
///
/// テストを実行しないターゲット（`workspace-build`・`workspace-clippy`）は対象外。
/// 未知のキーも`Ok`にする——入力検証は[`validate_target`]の責務であり、ここを
/// 意味の違う2つ目のゲートにしない。
pub fn check_tests_actually_ran(target: &str, stdout: &str) -> Result<(), String> {
    let Some(args) = resolve_target_args(target) else {
        return Ok(());
    };
    if args.first() != Some(&"test") {
        return Ok(());
    }
    match executed_test_count(stdout) {
        Some(0) => Err(format!(
            "target {target:?} reported success but ran 0 tests. `cargo test` exits 0 when its \
             filter matches nothing, so this is a broken filter, not a pass. Check the filter for \
             {target:?} in KNOWN_TARGETS (crates/dev-elevated-runner/src/targets.rs) against the \
             actual module/test names -- see docs/bugs/BUG-056.md"
        )),
        None => Err(format!(
            "target {target:?} reported success but its output contains no test-harness summary \
             ('test result:' line). The test binaries probably never started"
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-056の実物。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1
    /// --nocapture win_appcontainer::cow_diagnostics`（改名前のフィルタ）が実際に印字した出力。
    /// **捏造せず実機から採る**——このクラスを閉じる関数が、想像した書式ではなく
    /// 本物の書式を相手にしていることを固定するため。
    const ZERO_TESTS: &str =
        "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                              0 measured; 252 filtered out; finished in 0.00s\n";

    #[test]
    fn a_normal_run_counts_the_tests_it_executed() {
        let stdout = "running 12 tests\n\ntest result: ok. 12 passed; 0 failed; 3 ignored; \
                      0 measured; 45 filtered out; finished in 1.23s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
        assert!(check_tests_actually_ran("cow-diagnostics", stdout).is_ok());
    }

    /// 実行件数であって成功件数ではない。失敗を含む実行は「走った」に数える
    /// （失敗そのものは終了コードが既に伝えている）。見出し語の`FAILED.`を
    /// `failed`と取り違えないことも、ここで一緒に固定される。
    #[test]
    fn a_failing_run_still_counts_as_having_run() {
        let stdout = "test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 4.00s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
    }

    /// 複数のテストバイナリが走る対象（`e2e-all`）では、0件のバイナリが混ざるのは正常。
    /// 判定は合計で行う。
    #[test]
    fn one_empty_binary_among_several_is_not_a_failure() {
        let stdout = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                      0 measured; 7 filtered out; finished in 0.00s\n\nrunning 3 tests\n\n\
                      test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 9.00s\n";
        assert_eq!(executed_test_count(stdout), Some(3));
        assert!(check_tests_actually_ran("e2e-all", stdout).is_ok());
    }

    /// BUG-056そのもの。全バイナリ0件なら、exit 0でも失敗にする。
    #[test]
    fn a_target_that_ran_no_tests_at_all_is_reported_as_broken() {
        assert_eq!(executed_test_count(ZERO_TESTS), Some(0));
        let error = check_tests_actually_ran("cow-diagnostics", ZERO_TESTS)
            .expect_err("0 tests must not be treated as a pass");
        assert!(error.contains("ran 0 tests"), "{error}");
        // 次に踏む人が原因へ最短で行けること（メッセージの中身も契約の一部）。
        assert!(error.contains("KNOWN_TARGETS"), "{error}");
        assert!(error.contains("BUG-056"), "{error}");
    }

    /// テストハーネスが1度も起動しなかった場合は「0件」とは別の失敗として報告する。
    #[test]
    fn output_without_any_harness_summary_is_reported_separately() {
        assert_eq!(
            executed_test_count("error: could not compile `harness-cli`"),
            None
        );
        let error = check_tests_actually_ran("cow-diagnostics", "error: could not compile")
            .expect_err("a missing harness summary must not be treated as a pass");
        assert!(error.contains("no test-harness summary"), "{error}");
    }

    /// テストを実行しないターゲットは対象外（`cargo build`の出力に`test result:`は無い）。
    #[test]
    fn non_test_targets_are_out_of_scope() {
        assert!(check_tests_actually_ran("workspace-build", "    Finished `dev` profile").is_ok());
        assert!(check_tests_actually_ran("workspace-clippy", "").is_ok());
        // 入力検証は`validate_target`の責務なので、未知のキーはここでは判定しない。
        assert!(check_tests_actually_ran("no-such-target", ZERO_TESTS).is_ok());
        assert!(validate_target("no-such-target").is_err());
    }

    /// 2種類の要求が、どちらも自分の`kind`として往復すること（**送る側と受け取る側で
    /// 閉じているかを両方向で見る**、B-03）。
    #[test]
    fn both_request_kinds_round_trip() {
        let target = RunRequest::Target {
            target: "e2e-net-matrix".to_string(),
        };
        let launch = RunRequest::LaunchPrivhelper(PrivhelperLaunchRequest {
            pipe_name: r"\\.\pipe\harness-privhelper-1-0-2".to_string(),
            launcher_dir: std::path::PathBuf::from(r"C:\harness-e2e\scenarioA"),
        });

        for request in [target, launch] {
            let bytes = serde_json::to_vec(&request).unwrap();
            let parsed: RunRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(format!("{parsed:?}"), format!("{request:?}"));
        }
    }

    /// タグの無い**旧形式**は受け付けない。ここが通ってしまうと、要求の種類を取り違えた
    /// まま昇格側が動く（古いクライアントが生きていたときに、無言で別の意味になる）。
    #[test]
    fn a_request_without_a_kind_tag_is_rejected() {
        let legacy = br#"{"target":"e2e-net-matrix"}"#;

        let parsed: Result<RunRequest, _> = serde_json::from_slice(legacy);

        assert!(parsed.is_err(), "an untagged legacy request must not parse");
    }

    /// `KNOWN_TARGETS`の中で`cargo test`を走らせる全ターゲットが、この検知の対象に入ること。
    /// 新しいテストターゲットを足したときに、この検知だけ素通りする形にならないよう固定する。
    #[test]
    fn every_test_target_is_covered_by_the_zero_test_check() {
        for (name, args) in KNOWN_TARGETS {
            if args.first() != Some(&"test") {
                continue;
            }
            assert!(
                check_tests_actually_ran(name, ZERO_TESTS).is_err(),
                "test target {name:?} would silently pass with 0 tests"
            );
        }
    }
}

/// クライアント・デーモン・`privhelper_broker`が共有する、このランナー固有の部品。
///
/// **名前付きパイプIPCの下回り（呼び出しユーザー専有のDACL・オーバーラップドI/O・
/// タイムアウト付きのフレーミング）はここに置かない。** `harness_sandbox::win_pipe_ipc`
/// （privhelper・netfilterd・vmsandboxdと共有）を直接使う。以前はこのモジュールが
/// その一式のコピーを持っていた（`docs/CODE-STRUCTURE-RULES.md`規則5）。
#[cfg(windows)]
pub mod win {
    use super::PIPE_NAME_PREFIX;

    /// デーモンのパイプ名。ユーザーごとに1つで、クライアントはこの決定的な名前でデーモンを探す。
    pub fn pipe_name_for_current_user() -> windows::core::Result<String> {
        Ok(format!(
            "{PIPE_NAME_PREFIX}{}",
            harness_sandbox::win_pipe_ipc::current_user_sid_string()?
        ))
    }
}
