//! `run_shell`。`plans/DESIGN.md` §ツールシステム「run_shell」・§主なリスクと対策
//! 「Windowsのシェルとパス」、および`plans/DESIGN-SANDBOX.md` §6（M12）参照。
//!
//! **Windowsのシェル選択**（§実装マイルストーン M5）: pwsh7が`PATH`上に見つかればそれを、
//! 無ければ Windows PowerShell 5.1（`powershell.exe`）へフォールバックする。両者は演算子が
//! 異なる（5.1に`&&`/`||`が無い）ため、allowlistのコマンド分解が対象文法に依存する場合に備え
//! **どちらを起動したかを出力へ記録**する（§ツールシステム「シェル選択」）。
//! `-Command`への文字列補間はargvクォートバグを踏むため避け、コマンド文字列は**stdin経由**
//! （`-Command -`）で渡す。`-NoProfile -NonInteractive`を付与する。
//!
//! **M12（シェル隔離Tier）**: 子プロセスのenvは常にallowlist方式のクリーンenv
//! （`harness_sandbox::build_child_env`、D-07）。`ctx.shell_tier`（`harness-cli`が起動時に
//! 1回選択）に応じて実際の隔離機構を切り替える:
//! - Windows Tier1b: Restricted Token + 低IL + Job Object（`harness_sandbox::win_restricted`）。
//! - Linux Tier2: `bwrap`でラップ（`harness_sandbox::linux_bwrap`）。本セッションでは実機未検証
//!   （Windows専用環境、WSL2で別途再検証が必要）。
//! - Tier0（保険・全OS）: 通常spawn + Job Object(Win)/rlimit(unix) + 出力バイト上限。
//!
//! 危険構文（`-EncodedCommand`・`iex`/`Invoke-Expression`・`Start-Process`・`cmd /c`・
//! 入れ子インタプリタ）を検出したら`AcceptEdits`下でも強制的にプロンプトへ落とす
//! （T-09、`harness-engine::permission::looks_like_allowlist_bypass`）。

use std::path::Path;
use std::process::Stdio;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use harness_core::{RiskClass, ShellTier, StagingMode, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::check_relative_path;

use crate::jail_error_to_tool_error;

#[derive(Deserialize)]
struct RunShellInput {
    command: String,
    timeout_ms: Option<u64>,
    cwd: Option<String>,
}

pub struct RunShellTool;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// 出力バイト上限（層5・T-13、Tier0/Tier1b/Tier2いずれでも適用する保険）。
const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

#[async_trait]
impl Tool for RunShellTool {
    fn name(&self) -> &str {
        "run_shell"
    }

    fn description(&self) -> &str {
        "ワークスペース内でシェルコマンドを実行し、stdout+stderr+終了コードを返す。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "実行するシェルコマンド" },
                "timeout_ms": { "type": "integer", "description": "タイムアウト（ミリ秒、省略時120000）" },
                "cwd": { "type": "string", "description": "ワークスペースルートからの相対作業ディレクトリ" }
            },
            "required": ["command"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Exec
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: RunShellInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;

        let cwd = match &input.cwd {
            Some(c) => {
                let rel = check_relative_path(c).map_err(|e| jail_error_to_tool_error(c, e))?;
                ctx.workspace_root.join(rel)
            }
            None => ctx.workspace_root.clone(),
        };

        let dur = Duration::from_millis(input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        let env = harness_sandbox::build_child_env();

        let (out, err, code, shell_label) =
            run_isolated(&input.command, &cwd, &env, dur, ctx.shell_tier.tier).await?;

        let code = code.unwrap_or(-1);
        let mut content = truncate_to_limit(out);
        let err = truncate_to_limit(err);
        if !err.is_empty() {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&err);
        }
        content.push_str(&format!("\n[exit code: {code}]\n[shell: {shell_label}]"));
        content.push_str(&format!("\n[tier: {}]", ctx.shell_tier.tier.label()));
        if let Some(reason) = &ctx.shell_tier.reason {
            content.push_str(&format!(
                " (downgraded from {}: {reason})",
                ctx.shell_tier.downgraded_from.map(|t| t.label()).unwrap_or("?")
            ));
        }
        if ctx.shell_tier.is_unisolated() {
            content.push_str(
                "\n[warning: shell isolation tier is tier0 (best-effort only); \
                 out-of-workspace writes/network egress are not blocked, see plans/DESIGN-SANDBOX.md §9]",
            );
        }
        if !matches!(ctx.staging.mode, StagingMode::Live) {
            content.push_str(
                "\n[warning: staged writes made earlier in this turn may not be visible to this \
                 shell process yet (D-08 simplification, see plans/DESIGN-SANDBOX.md §8-3)]",
            );
        }

        Ok(ToolOutput {
            content,
            is_error: code != 0,
        })
    }
}

fn truncate_to_limit(mut s: String) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        s.truncate(MAX_OUTPUT_BYTES);
        s.push_str("\n[output truncated at 10MiB]");
    }
    s
}

/// Tierに応じて実行経路を切り替える。戻り値は`(stdout, stderr, exit_code, shell_label)`。
/// `exit_code`は`None`ならkill済み（timeout）を表す呼び出し元エラーへ畳み込む。
async fn run_isolated(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
    tier: ShellTier,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    #[cfg(windows)]
    {
        if tier == ShellTier::Tier1a {
            return run_windows_tier1a(command, cwd, env, dur).await;
        }
        if tier == ShellTier::Tier1b {
            return run_windows_tier1b(command, cwd, env, dur).await;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if tier == ShellTier::Tier2 {
            return run_linux_tier2(command, cwd, env, dur).await;
        }
    }
    // Tier0（保険）。上記いずれにも該当しない場合のフォールバックでもある。
    run_tier0(command, cwd, env, dur).await
}

/// 通常のtokio Commandでspawnし、非同期I/O（stdout/stderr並行読み+timeout）を行う共通経路。
/// Windowsは追加でJob Objectへ後付け（kill-on-close）、Unixは`setrlimit`をpre_execで適用する
/// （Tier0の保険機構、`plans/DESIGN-SANDBOX.md` §6.5）。
async fn run_tier0(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let invocation = platform_shell_command(command);
    let mut cmd = invocation.cmd;
    apply_common_command_settings(&mut cmd, cwd, env, invocation.stdin_payload.is_some());

    #[cfg(unix)]
    apply_unix_rlimits(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    #[cfg(windows)]
    {
        if let Some(handle) = child.raw_handle() {
            let _ = harness_sandbox::win_restricted::attach_job_object(handle as isize);
        }
    }

    run_with_pipes(&mut child, invocation.stdin_payload, dur)
        .await
        .map(|(out, err, code)| (out, err, code, invocation.shell_label))
}

#[cfg(target_os = "linux")]
async fn run_linux_tier2(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let session_dir = cwd.join(".harness").join("sandbox").join("tier2");
    let config = harness_sandbox::linux_bwrap::BwrapConfig {
        workspace_root: cwd.to_path_buf(),
        upper_dir: session_dir.join("upper"),
        work_dir: session_dir.join("work"),
    };
    let _ = std::fs::create_dir_all(&config.upper_dir);
    let _ = std::fs::create_dir_all(&config.work_dir);
    let bwrap_args = harness_sandbox::linux_bwrap::build_args(&config);

    let mut cmd = Command::new("bwrap");
    cmd.args(&bwrap_args);
    cmd.arg("--").arg("sh").arg("-c").arg(command);
    apply_common_command_settings(&mut cmd, cwd, env, false);

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    run_with_pipes(&mut child, None, dur)
        .await
        .map(|(out, err, code)| (out, err, code, "bwrap(sh)"))
}

#[cfg(windows)]
async fn run_windows_tier1a(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let _ = std::fs::create_dir_all(cwd);
    let sid = harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    )
    .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    // preflightのsmoke testと同一のシェル解決を使う（pwshのストアアプリ実行エイリアスは
    // AppContainerで起動不可＝`resolve_shell`が実在のpowershell.exeへフォールバックする）。
    let (bin, shell_label) = harness_sandbox::win_appcontainer::resolve_shell();
    let args = ["-NoProfile", "-NonInteractive", "-Command", "-"];
    let cwd_owned = cwd.to_path_buf();
    let env_owned = env.to_vec();

    let child =
        harness_sandbox::win_appcontainer::spawn(&bin, &args, &cwd_owned, &env_owned, true, sid.as_psid())
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child.kill_token();
    let command_owned = command.to_string();

    let handle = tokio::task::spawn_blocking(move || {
        child.write_stdin_read_output_and_wait(Some(&command_owned))
    });

    match timeout(dur, handle).await {
        Ok(Ok(Ok((out, err, code)))) => Ok((out, err, Some(code), shell_label)),
        Ok(Ok(Err(e))) => Err(ToolError::ExecutionFailed(e.to_string())),
        Ok(Err(join_err)) => Err(ToolError::ExecutionFailed(join_err.to_string())),
        Err(_) => {
            kill_token.kill();
            Err(ToolError::ExecutionFailed(format!(
                "command timed out after {}ms",
                dur.as_millis()
            )))
        }
    }
}

#[cfg(windows)]
async fn run_windows_tier1b(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let _ = std::fs::create_dir_all(cwd);
    // cwd1つだけに継承可能な低ILラベルを付与する（非再帰・冪等、モジュールdocの既知の限界参照）。
    let _ = harness_sandbox::win_restricted::set_low_integrity_label(cwd);

    let (bin, shell_label) = if which::which("pwsh").is_ok() {
        ("pwsh", "pwsh(tier1b)")
    } else {
        ("powershell", "powershell5.1(tier1b)")
    };
    let args = ["-NoProfile", "-NonInteractive", "-Command", "-"];
    let cwd_owned = cwd.to_path_buf();
    let env_owned = env.to_vec();

    let child = harness_sandbox::win_restricted::spawn(bin, &args, &cwd_owned, &env_owned, true)
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child.kill_token();
    let command_owned = command.to_string();

    let handle = tokio::task::spawn_blocking(move || {
        child.write_stdin_read_output_and_wait(Some(&command_owned))
    });

    match timeout(dur, handle).await {
        Ok(Ok(Ok((out, err, code)))) => Ok((out, err, Some(code), shell_label)),
        Ok(Ok(Err(e))) => Err(ToolError::ExecutionFailed(e.to_string())),
        Ok(Err(join_err)) => Err(ToolError::ExecutionFailed(join_err.to_string())),
        Err(_) => {
            kill_token.kill();
            Err(ToolError::ExecutionFailed(format!(
                "command timed out after {}ms",
                dur.as_millis()
            )))
        }
    }
}

fn apply_common_command_settings(
    cmd: &mut Command,
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
) {
    cmd.current_dir(cwd);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if want_stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    // タイムアウト到達時にfutureをdropしただけでは子プロセスは残るため、
    // dropと同時にkillされるようにする（設計書「暴走kill」の要件）。
    cmd.kill_on_drop(true);
}

#[cfg(unix)]
fn apply_unix_rlimits(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    // T-13対策（層5・Tier0の保険）: アドレス空間とプロセス数に上限を設ける。
    // fork爆弾やメモリ暴走を完全には防がないが、既定を持たない状態からの改善。
    unsafe {
        cmd.pre_exec(|| {
            let as_limit = libc::rlimit {
                rlim_cur: 2 * 1024 * 1024 * 1024,
                rlim_max: 2 * 1024 * 1024 * 1024,
            };
            libc::setrlimit(libc::RLIMIT_AS, &as_limit);
            let nproc_limit = libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            libc::setrlimit(libc::RLIMIT_NPROC, &nproc_limit);
            Ok(())
        });
    }
}

/// stdin書込+stdout/stderr並行読み+timeoutの共通ロジック（`tokio::process::Child`向け）。
async fn run_with_pipes(
    child: &mut tokio::process::Child,
    stdin_payload: Option<String>,
    dur: Duration,
) -> Result<(String, String, Option<i32>), ToolError> {
    if let Some(payload) = stdin_payload {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
        drop(stdin);
    }

    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    let run = async {
        let stdout_fut = async {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s).await;
            s
        };
        let stderr_fut = async {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s).await;
            s
        };
        let (out, err) = tokio::join!(stdout_fut, stderr_fut);
        let status = child
            .wait()
            .await
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
        Ok::<_, ToolError>((out, err, status.code()))
    };

    match timeout(dur, run).await {
        Ok(Ok((out, err, code))) => Ok((out, err, code)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ToolError::ExecutionFailed(format!(
            "command timed out after {}ms",
            dur.as_millis()
        ))),
    }
}

/// 起動する子プロセスコマンドと、記録用のシェルラベル・stdin経由で渡すコマンド文字列
/// （argvへの文字列補間を避けるためのペイロード、Windowsのみ使用）をまとめたもの。
struct ShellInvocation {
    cmd: Command,
    stdin_payload: Option<String>,
    shell_label: &'static str,
}

/// Unixは`sh -c <command>`（argvの1要素として渡るためWindowsの`-Command`文字列補間問題は無い）。
#[cfg(not(windows))]
fn platform_shell_command(command: &str) -> ShellInvocation {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    ShellInvocation {
        cmd,
        stdin_payload: None,
        shell_label: "sh",
    }
}

/// Windowsはpwsh7優先→Windows PowerShell 5.1フォールバック。コマンド文字列はargvへ
/// 埋め込まず`-Command -`でstdinから渡す（§ツールシステム run_shell「シェル選択」）。
#[cfg(windows)]
fn platform_shell_command(command: &str) -> ShellInvocation {
    let (bin, shell_label) = if which::which("pwsh").is_ok() {
        ("pwsh", "pwsh")
    } else {
        ("powershell", "powershell5.1")
    };
    let mut cmd = Command::new(bin);
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", "-"]);
    ShellInvocation {
        cmd,
        stdin_payload: Some(command.to_string()),
        shell_label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(root: PathBuf) -> ToolCtx {
        let mut ctx = ToolCtx::new(root.clone());
        // `ToolCtx::new`はテスト既定でTier0（プレースホルダ）を積む。実行時は
        // `harness-cli`が起動時に`select_tier`で解決した値を積むため、ここでも
        // 実際のOS隔離Tier選択を再現する（さもないとTier1b経路が単体テストで一切通らない）。
        // `opt_in_tier1a=false`固定（既存Tier1bテストの挙動を変えないため）。
        ctx.shell_tier =
            harness_sandbox::select_tier(harness_core::RequireSandbox::None, &root, false)
                .expect("tier selection without --require-sandbox never fails");
        ctx
    }

    #[tokio::test]
    async fn run_shell_captures_stdout_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        let command = "echo hello";

        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(out.content.contains("[exit code: 0]"));
        assert!(out.content.contains("[tier:"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_records_launched_windows_shell() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        let out = tool
            .call(
                json!({ "command": "Write-Output hello" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(
            out.content.contains("[shell: pwsh(tier1b)]")
                || out.content.contains("[shell: powershell5.1(tier1b)]")
        );
        assert!(out.content.contains("[tier: tier1b]"));
    }

    #[tokio::test]
    async fn run_shell_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        #[cfg(windows)]
        let command = "Start-Sleep -Seconds 5";
        #[cfg(not(windows))]
        let command = "sleep 5";

        let err = tool
            .call(
                json!({ "command": command, "timeout_ms": 200 }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::ExecutionFailed(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier1b_rejects_write_outside_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let outside = std::env::temp_dir().join("harness-m12-outside-test.txt");
        let _ = std::fs::remove_file(&outside);
        let tool = RunShellTool;
        let command = format!(
            "Set-Content -Path '{}' -Value 'blocked' -ErrorAction Stop",
            outside.display()
        );
        let out = tool
            .call(json!({ "command": command }), &ctx(dir.path().to_path_buf()))
            .await
            .unwrap();
        assert!(out.is_error, "write outside the low-IL cwd should fail: {}", out.content);
        assert!(!outside.exists());
    }

    /// Tier1a（AppContainer）の隔離セマンティクスを決定論的に検証する（LLM非依存、絶対パスを
    /// 使いモデルのCWD混乱を排除する）。実際にpreflight（プロファイル作成＋再帰ACL付与＋
    /// smoke-test起動）を走らせ、Tier1aが選択できなかった環境（AppContainer不可）ではskipする。
    /// 実行にはWindows実機＋（この開発機では）管理者権限が要る（`sudo cargo test`）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier1a_contains_writes_and_reads() {
        use harness_core::{RequireSandbox, ShellTier};

        let dir = tempfile::tempdir().unwrap();
        // 実Tier1a preflightを走らせる（`opt_in_tier1a=true`）。AppContainer不可の環境では
        // Tier1bへ降格するので、その場合はテストをskipする（CIやAppContainer無効環境向け）。
        let selection =
            harness_sandbox::select_tier(RequireSandbox::None, dir.path(), true).unwrap();
        if selection.tier != ShellTier::Tier1a {
            eprintln!(
                "skipping tier1a test: preflight downgraded to {} ({:?})",
                selection.tier.label(),
                selection.reason
            );
            return;
        }

        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = selection;
        let tool = RunShellTool;

        // (a) ワークスペース内への書込（絶対パス）→ 成功する（再帰ACL付与でパッケージSIDが
        //     workspace配下に書込可になっている証拠）。
        let inside = dir.path().join("inside.txt");
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Set-Content -Path '{}' -Value hi -ErrorAction Stop",
                        inside.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            !out.is_error,
            "in-workspace write should succeed under tier1a: {}",
            out.content
        );
        assert!(inside.exists(), "in-workspace file was not created: {}", out.content);
        assert!(out.content.contains("[tier: tier1a]"), "{}", out.content);

        // (b) ワークスペース外への書込 → 拒否され、ファイルは作られない（範囲外書込の物理拒否）。
        let outside = std::env::temp_dir().join("harness-tier1a-outside.txt");
        let _ = std::fs::remove_file(&outside);
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Set-Content -Path '{}' -Value blocked -ErrorAction Stop",
                        outside.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            out.is_error,
            "out-of-workspace write should fail under tier1a: {}",
            out.content
        );
        assert!(!outside.exists());

        // (c) T-04: ワークスペース外の機密ファイルのread → 拒否される（Tier1bなら読めてしまう
        //     既知の欠陥がTier1aでは直る、という差分。実`~/.ssh`は使わずダミーで同じ性質を再現）。
        let secret = std::env::temp_dir().join("harness-tier1a-secret.txt");
        std::fs::write(&secret, "topsecret").unwrap();
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Get-Content -Path '{}' -ErrorAction Stop",
                        secret.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        let _ = std::fs::remove_file(&secret);
        assert!(
            !out.content.contains("topsecret"),
            "tier1a must not read outside-workspace secrets (T-04): {}",
            out.content
        );
    }
}
