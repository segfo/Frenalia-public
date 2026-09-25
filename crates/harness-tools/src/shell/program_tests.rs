//! `run_program`のテスト。
//!
//! # 引数が一字一句届くことを、どう確かめるか
//!
//! 子として**このテストバイナリ自身**を起こし、[`echo_argv_child`]だけを走らせる。
//! 子は受け取った argv のうち `--` より後ろを、印を付けた1行の JSON で標準出力へ出す。
//! 外部のプログラム（`cmd`・`python`）に頼ると、そのプログラム自身の引数の解釈が混ざり、
//! **何を測っているのか分からなくなる**。
//!
//! 子であることは「argv に素の `--` がある」で見分ける。`cargo test -- …` の `--` は cargo が
//! 取り除くので、通常のテスト実行ではテストバイナリに素の `--` は届かない。
//! **子の環境は許可リストで組み直される**（`harness_sandbox::build_child_env`）ので、
//! 環境変数での合図は使えない。

use super::*;
use harness_core::ShellTier;
use serde_json::json;

/// 子が出す行の印。
const ARGV_MARKER: &str = "<<<run-program-argv>>>";

/// libtest から見たこのテストの名前（`--exact` で1本だけ走らせるため）。
const ECHO_CHILD_TEST: &str = "shell::program::program_tests::echo_argv_child";

/// 子として呼ばれたときだけ、受け取った argv（`--` より後ろ）を印付きで出す。
/// 通常の実行では argv に素の `--` が無いので何もせず緑で終わる。
#[test]
fn echo_argv_child() {
    let args: Vec<String> = std::env::args().collect();
    let Some(split) = args.iter().position(|a| a == "--") else {
        return;
    };
    let payload = &args[split + 1..];
    println!("{ARGV_MARKER}{}", serde_json::to_string(payload).unwrap());
}

/// **シェルなら解釈されてしまう文字**を、1要素ずつ並べた検体。
fn hostile_payload() -> Vec<String> {
    [
        "a;b",
        "c|d",
        "x & del y",
        "\"quoted\"",
        "with space",
        "日本語の引数",
        "",
        r"back\slash\",
        r"trailing\\",
        "--looks-like-a-flag",
        "$env:PATH",
        "%PATH%",
        "`backtick",
        "*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn echo_child_args(payload: &[String]) -> Vec<String> {
    let mut args = vec![
        "--exact".to_string(),
        ECHO_CHILD_TEST.to_string(),
        "--nocapture".to_string(),
        "--quiet".to_string(),
        "--test-threads=1".to_string(),
        "--".to_string(),
    ];
    args.extend(payload.iter().cloned());
    args
}

/// 子の出力から、印の付いた行の JSON を取り出す。
fn echoed_argv(content: &str) -> Vec<String> {
    let line = content
        .lines()
        .find_map(|l| l.strip_prefix(ARGV_MARKER))
        .unwrap_or_else(|| panic!("the echo child did not print its argv:\n{content}"));
    serde_json::from_str(line).unwrap_or_else(|e| panic!("bad argv json ({e}): {line}"))
}

async fn run_echo_child(ctx: &ToolCtx, payload: &[String]) -> ToolOutput {
    let exe = std::env::current_exe().unwrap();
    RunProgramTool::default()
        .call(
            json!({
                "program": exe.to_str().unwrap(),
                "args": echo_child_args(payload),
            }),
            ctx,
        )
        .await
        .unwrap()
}

/// **構造化の保証そのもの**（D-96）: シェルなら解釈される文字が、1要素ずつそのまま届く。Tier0。
#[tokio::test]
async fn argv_arrives_verbatim_at_tier0() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let payload = hostile_payload();

    let out = run_echo_child(&ctx, &payload).await;

    assert!(!out.is_error, "{}", out.content);
    assert_eq!(echoed_argv(&out.content), payload, "{}", out.content);
    assert!(out.content.contains("[exit code: 0]"), "{}", out.content);
    assert!(out.content.contains("[program: "), "{}", out.content);
    assert!(out.content.contains("[tier: "), "{}", out.content);
}

/// 同じ保証を Tier1（制限トークン＋低IL）で。コマンド行を組み立てる関数が別物
/// （`win_common::command_line_for`）なので、Tier0 とは独立に確かめる必要がある。
#[cfg(windows)]
#[tokio::test]
async fn argv_arrives_verbatim_at_tier1() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = tier1_ctx(dir.path().to_path_buf());
    assert_eq!(ctx.shell_tier.tier, ShellTier::Tier1);
    let payload = hostile_payload();

    let out = run_echo_child(&ctx, &payload).await;

    assert!(!out.is_error, "{}", out.content);
    assert_eq!(echoed_argv(&out.content), payload, "{}", out.content);
}

/// 同じ保証を Tier2a（AppContainer）で。**引数は Spawn Daemon との電文を1回通る**ので、
/// Tier1 とは別に確かめる（電文の符号化で空文字列・非ASCII・引用符が崩れないか）。
///
/// **昇格は要らない**（`run_shell`の Tier2a テストと同じく、実 preflight を非昇格で走らせる）。
/// Tier2a が取れない環境では skip する。
///
/// 子にはテストバイナリを**ワークスペースへ写したもの**を使う。AppContainer の子は
/// 許可の付いたファイルしか起こせず、`target/debug`には付いていないため。
/// **写す → preflight（許可の配布）→ 配り終えるのを待つ → 起こす**の順にする——
/// 配り終える前に起こすと、許可の無いファイルとして断られうる。
#[cfg(windows)]
#[tokio::test]
async fn argv_arrives_verbatim_at_tier2a() {
    use crate::shell::test_support::Tier2aScratchWorkspace;
    use harness_core::RequireSandbox;

    let dir = Tier2aScratchWorkspace::new();
    let child_exe = dir.path().join("echo-argv-child.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &child_exe).unwrap();

    let selection = match harness_sandbox::select_tier(
        RequireSandbox::None,
        dir.path(),
        harness_core::SandboxChoice::Tier2a,
        &[],
        None,
        &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
        None,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("skipping Tier2a test: Tier2a is unavailable here ({e})");
            return;
        }
    };
    assert_eq!(selection.tier, ShellTier::Tier2a);
    harness_sandbox::tier2a::win_appcontainer::grant_job::wait_until_done()
        .expect("the background grant walk must finish before launching");

    let mut ctx = ToolCtx::new(dir.path().to_path_buf());
    ctx.shell_tier = selection;
    let daemon = harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
        harness_sandbox::tier2a::spawnd::TransitionPolicy::empty(""),
        harness_sandbox::tier2a::spawnd::ChildProcessPolicy::Unrestricted,
    )
    .expect("Tier2a product path requires a Spawn Daemon");
    let tool = RunProgramTool::with_spawn_daemon(daemon, false);
    let payload = hostile_payload();

    let out = tool
        .call(
            json!({
                "program": child_exe.to_str().unwrap(),
                "args": echo_child_args(&payload),
            }),
            &ctx,
        )
        .await
        .unwrap();

    assert!(!out.is_error, "{}", out.content);
    assert_eq!(echoed_argv(&out.content), payload, "{}", out.content);
    // **本当に Tier2a で起きたか**を出力で確かめる（別の Tier へ落ちて緑、を防ぐ）。
    let tier_line = format!("[tier: {}]", ShellTier::Tier2a.label());
    assert!(out.content.contains(&tier_line), "{}", out.content);
}

/// `shell_tests.rs` の `ctx` と同じ手順で Tier1 を選ぶ（実 Win32 preflight を走らせない）。
#[cfg(windows)]
fn tier1_ctx(root: PathBuf) -> ToolCtx {
    let mut ctx = ToolCtx::new(root.clone());
    let probes = harness_sandbox::shell_tier::Probes {
        tier2a_preflight_override: Some(Err("test fixture: force Tier1".to_string())),
        ..Default::default()
    };
    ctx.shell_tier = harness_sandbox::shell_tier::select_tier_with_probes(
        harness_core::RequireSandbox::None,
        &root,
        harness_core::SandboxChoice::Tier1,
        &[],
        None,
        &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
        None,
        &probes,
    )
    .expect("tier selection without --require-sandbox never fails");
    ctx
}

/// プログラム自身の終了コードがそのまま返る（`run_shell`のような後付けが無い）。
#[tokio::test]
async fn the_programs_own_exit_code_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    #[cfg(windows)]
    let (program, args) = ("cmd", json!(["/c", "exit", "7"]));
    #[cfg(not(windows))]
    let (program, args) = ("sh", json!(["-c", "exit 7"]));

    let out = RunProgramTool::default()
        .call(json!({ "program": program, "args": args }), &ctx)
        .await
        .unwrap();

    assert!(out.is_error, "{}", out.content);
    assert!(out.content.contains("[exit code: 7]"), "{}", out.content);
}

/// **知らない項目は拒否する**（BUG-164 の片側を新しいツールでは最初から作らない）。
#[tokio::test]
async fn unknown_input_fields_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = ToolCtx::new(dir.path().to_path_buf());

    let err = RunProgramTool::default()
        .call(json!({ "program": "git", "command": "x" }), &ctx)
        .await
        .unwrap_err();

    assert!(matches!(err, ToolError::InvalidInput(_)), "{err:?}");
}

/// Tier3 でも道具の説明は同じ（D-108）。以前は「Tier3では使えない」と差し替えていた。
#[test]
fn tier3_describes_run_program_like_every_other_tier() {
    let dir = tempfile::tempdir().unwrap();
    let mut tier3 = ToolCtx::new(dir.path().to_path_buf());
    tier3.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);
    let tier1 = ToolCtx::new(dir.path().to_path_buf());

    let tool = RunProgramTool::default();
    assert_eq!(
        tool.spec_for_ctx(&tier3).description,
        tool.spec_for_ctx(&tier1).description
    );
}

/// 引数の配列を持ったまま常駐デーモンへ渡す（D-108）。**`sh -c` の文字列へ組み直さない**（D-96）。
#[tokio::test]
async fn tier3_sends_the_argument_array_without_rebuilding_a_shell_string() {
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = ToolCtx::new(dir.path().to_path_buf());
    ctx.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);
    ctx.vm_sandbox = Some(std::sync::Arc::new(RecordingExecutor {
        calls: calls.clone(),
        fail_argv: None,
    }));

    let out = RunProgramTool::default()
        .call(
            json!({ "program": "git", "args": ["commit", "-m", "a b; rm -rf /"] }),
            &ctx,
        )
        .await
        .unwrap();

    let seen = calls.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["exec_argv: git|commit|-m|a b; rm -rf /".to_string()],
        "配列のまま届いていない（`exec` へ落ちていれば `sh -c` へ畳まれている）"
    );
    // **ホストのPATHで解決しない**——解決すると Windows の絶対パスが argv[0] になる。
    assert!(out.content.contains("[program: git]"), "{}", out.content);
}

/// 相手が古くて配列を運べないときは、**組み直さずに断る**（D-96・D-108）。
#[tokio::test]
async fn tier3_refuses_rather_than_falling_back_when_the_daemon_is_old() {
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = ToolCtx::new(dir.path().to_path_buf());
    ctx.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);
    ctx.vm_sandbox = Some(std::sync::Arc::new(RecordingExecutor {
        calls: calls.clone(),
        fail_argv: Some("the resident Tier3 daemon is older than this harness".to_string()),
    }));

    let err = RunProgramTool::default()
        .call(json!({ "program": "git", "args": ["status"] }), &ctx)
        .await
        .unwrap_err();

    assert!(
        format!("{err:?}").contains("older than this harness"),
        "{err:?}"
    );
    // 断った後にシェルへ落としていない（`exec` は1度も呼ばれない）。
    let seen = calls.lock().unwrap().clone();
    assert!(seen.iter().all(|c| c.starts_with("exec_argv:")), "{seen:?}");
}

/// どちらの口が呼ばれたかを記録するだけの実行チャネル。
#[derive(Debug)]
struct RecordingExecutor {
    calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// `Some`なら`exec_argv`をこの理由で断る（古い常駐デーモンの模擬）。
    fail_argv: Option<String>,
}

impl harness_core::VmShellExecutor for RecordingExecutor {
    fn exec(
        &self,
        cmd: &str,
        _cwd: &std::path::Path,
        _env: &[(String, String)],
        _timeout: Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        self.calls.lock().unwrap().push(format!("exec: {cmd}"));
        Ok((String::new(), String::new(), Some(0)))
    }

    fn exec_argv(
        &self,
        argv: &[String],
        _cwd: &std::path::Path,
        _env: &[(String, String)],
        _timeout: Duration,
    ) -> Result<(String, String, Option<i32>), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("exec_argv: {}", argv.join("|")));
        match &self.fail_argv {
            Some(reason) => Err(reason.clone()),
            None => Ok((String::new(), String::new(), Some(0))),
        }
    }
}

// ── プログラム名の解決（D-98） ──

/// テスト用の「実行ファイル」を置く。`which`は中身を読まないので空で足りる。
fn touch(path: &std::path::Path) {
    std::fs::write(path, b"").unwrap();
}

#[cfg(windows)]
const EXE: &str = ".exe";
#[cfg(not(windows))]
const EXE: &str = "";

#[cfg(not(windows))]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}
#[cfg(windows)]
fn make_executable(_path: &std::path::Path) {}

fn path_env(dir: &std::path::Path) -> Vec<(String, String)> {
    vec![("PATH".to_string(), dir.to_string_lossy().into_owned())]
}

/// **作業ディレクトリに同名の実行ファイルがあっても、素の名前では拾わない。**
/// ワークスペースへ置かれたファイルに乗っ取られないため。禁止側。
#[test]
fn a_bare_name_is_not_looked_up_in_the_working_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let empty_path_dir = tempfile::tempdir().unwrap();
    let planted = cwd.path().join(format!("planted_tool{EXE}"));
    touch(&planted);
    make_executable(&planted);

    let result = resolve_program("planted_tool", cwd.path(), &path_env(empty_path_dir.path()));

    assert!(result.is_err(), "must not resolve from cwd: {result:?}");
}

/// 許可側と対にする——PATH 上にあれば見つかる。
#[test]
fn a_bare_name_is_found_on_the_path() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let tool = bin.path().join(format!("path_tool{EXE}"));
    touch(&tool);
    make_executable(&tool);

    let found = resolve_program("path_tool", cwd.path(), &path_env(bin.path())).unwrap();

    assert_eq!(
        std::fs::canonicalize(found).unwrap(),
        std::fs::canonicalize(&tool).unwrap()
    );
}

/// 作業ディレクトリのファイルを起こしたいときは、パス区切りを含めて明示する。
#[test]
fn a_relative_path_resolves_from_the_working_directory() {
    let cwd = tempfile::tempdir().unwrap();
    let empty_path_dir = tempfile::tempdir().unwrap();
    let local = cwd.path().join(format!("local_tool{EXE}"));
    touch(&local);
    make_executable(&local);

    let found = resolve_program(
        &format!("./local_tool{EXE}"),
        cwd.path(),
        &path_env(empty_path_dir.path()),
    )
    .unwrap();

    assert_eq!(
        std::fs::canonicalize(found).unwrap(),
        std::fs::canonicalize(&local).unwrap()
    );
}

/// PATH の相対の項目は落とす（`which`がハーネス自身のカレントディレクトリから探してしまうため）。
#[test]
fn relative_path_entries_are_dropped() {
    let abs = tempfile::tempdir().unwrap();
    let joined = std::env::join_paths([
        abs.path().to_path_buf(),
        PathBuf::from("."),
        PathBuf::from("relative").join("dir"),
    ])
    .unwrap();
    let env = vec![("Path".to_string(), joined.to_string_lossy().into_owned())];

    let kept: Vec<PathBuf> = std::env::split_paths(&absolute_path_entries(&env)).collect();

    assert_eq!(kept, vec![abs.path().to_path_buf()]);
}

/// **バッチファイルは起こさない**——cmd.exe が引数を解釈し直すので、配列がそのまま届かない。
#[cfg(windows)]
#[test]
fn a_batch_file_is_refused() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    touch(&bin.path().join("batchy.bat"));
    touch(&bin.path().join("cmdy.CMD"));

    for name in ["batchy", "cmdy"] {
        let err = resolve_program(name, cwd.path(), &path_env(bin.path())).unwrap_err();
        match err {
            ToolError::InvalidInput(msg) => assert!(msg.contains("batch file"), "{msg}"),
            other => panic!("expected InvalidInput for {name}, got {other:?}"),
        }
    }
}

// ── 判定と実行が別物を見ていないか（B-21） ──

/// 実体の名前がインタプリタなのに、頼まれた名前がそうでないなら断る。
#[test]
fn a_disguised_interpreter_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join(format!("cmd{EXE}"));
    touch(&real);

    let err = refuse_disguised_interpreter("innocent", &real).unwrap_err();

    assert!(matches!(err, ToolError::InvalidInput(_)), "{err:?}");
}

/// 許可側と対にする——名前でインタプリタだと分かっているもの・普通のプログラムは通す。
#[test]
fn named_interpreters_and_ordinary_programs_pass_the_recheck() {
    let dir = tempfile::tempdir().unwrap();
    let interpreter = dir.path().join(format!("cmd{EXE}"));
    let ordinary = dir.path().join(format!("git{EXE}"));
    touch(&interpreter);
    touch(&ordinary);

    refuse_disguised_interpreter("cmd", &interpreter).unwrap();
    refuse_disguised_interpreter("git", &ordinary).unwrap();
}

// ── 通信許可の判定（`classify_net_program`） ──

#[test]
fn net_program_decision_matches_the_program_name_only() {
    let allow = vec!["git".to_string()];
    assert_eq!(
        classify_net_program(r"C:\Program Files\Git\cmd\GIT.EXE", &allow),
        crate::shell::NetDecision::Allow
    );
    assert_eq!(
        classify_net_program("cargo", &allow),
        crate::shell::NetDecision::Deny
    );
}

/// **シェルを許可していても、シェル以外のプログラムは通さない**（`run_shell`との違い）。
#[test]
fn allowing_a_shell_does_not_allow_every_program() {
    let allow = vec!["pwsh".to_string()];
    assert_eq!(
        classify_net_program("curl", &allow),
        crate::shell::NetDecision::Deny
    );
    assert_eq!(
        classify_net_program("pwsh", &allow),
        crate::shell::NetDecision::Allow
    );
}
