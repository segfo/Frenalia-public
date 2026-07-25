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

/// アプリ単位network制御（軸1、D-10/D-11）の判定結果。`classify_net_app`が返す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetDecision {
    /// 許可リスト非空だが先頭execが不一致（既定）。
    Deny,
    /// 先頭execは一致したが、連鎖メタ文字（`|`/`&&`/`;`等）を含むため他exe混入の恐れがあり
    /// 安全側で拒否した（D-11の最小許可原則。連鎖内の全execを安全に列挙するのは困難なため）。
    DeniedByChaining,
    /// 先頭execが一致し、連鎖も無い単一コマンド。`internetClient`を付与してよい。
    Allow,
}

/// コマンド文字列の先頭トークンを取り出す（引用符付きなら中身、無ければ空白区切りの最初の語）。
fn first_command_token(command: &str) -> &str {
    let s = command.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("");
    }
    if let Some(rest) = s.strip_prefix('\'') {
        return rest.split('\'').next().unwrap_or("");
    }
    s.split_whitespace().next().unwrap_or("")
}

/// 実行ファイルトークンから比較用のbasename（パス除去・拡張子除去・小文字化）を作る。
fn exe_basename(token: &str) -> String {
    let name = token.rsplit(['\\', '/']).next().unwrap_or(token);
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    stem.to_ascii_lowercase()
}

/// コマンド文字列が連鎖メタ文字（`|`/`&`/`;`/バッククォート/`$(`/改行）を含むかを判定する。
/// 単一`&`（PowerShellの呼び出し演算子等）も安全側で連鎖扱いにする（D-11の最小許可原則）。
fn contains_chaining_metachar(command: &str) -> bool {
    command.contains(['|', '&', ';', '`', '\n']) || command.contains("$(")
}

/// `command`の先頭execが`allow_apps`（basename一致）に含まれるかを判定し、連鎖の有無も
/// 併せて評価する（軸1、D-10/D-11）。`allow_apps`が空なら常に`Deny`（既定・現状維持）。
///
/// **限界（残存リスク、T-15の具体化）**: 判定は外側のコマンド文字列にしか及ばない。
/// `pwsh ./x.ps1`のようにインタプリタ/スクリプトを許可リストへ入れると、中身が呼ぶ通信も
/// 全て通ってしまう（capabilityは子孫プロセスへ全継承）。許可リストには`git`/`npm`等の
/// 具体的で狭い実行ファイル名のみを入れることを前提とする。
fn classify_net_app(command: &str, allow_apps: &[String]) -> NetDecision {
    if allow_apps.is_empty() {
        return NetDecision::Deny;
    }
    let token = first_command_token(command);
    if token.is_empty() {
        return NetDecision::Deny;
    }
    let basename = exe_basename(token);
    let matched = allow_apps
        .iter()
        .any(|allowed| exe_basename(allowed) == basename);
    if !matched {
        return NetDecision::Deny;
    }
    if contains_chaining_metachar(command) {
        return NetDecision::DeniedByChaining;
    }
    NetDecision::Allow
}

#[async_trait]
impl Tool for RunShellTool {
    fn name(&self) -> &str {
        "run_shell"
    }

    fn description(&self) -> &str {
        "ワークスペース内でシェルコマンドを実行し、stdout+stderr+終了コードを返す。\
         ネットワーク許可アプリ（--net-allow-app）を使う場合は、|・&&・;等で他コマンドと連結せず、\
         単一コマンドとして発行すること（連結すると通信が拒否される）。"
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
        let mut env = harness_sandbox::build_child_env();

        // 協調プロキシ（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。
        // `ctx.net_proxy.allow_domains`が空なら`spawn_local_proxy`は何もしない
        // （既定挙動を変えない）。起動時のみ`HTTP_PROXY`/`HTTPS_PROXY`を子envへ足す。
        let proxy = crate::net_proxy::spawn_local_proxy(&ctx.net_proxy)
            .await
            .ok()
            .flatten();
        if let Some(p) = &proxy {
            let proxy_url = format!("http://{}", p.addr);
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                env.push((key.to_string(), proxy_url.clone()));
            }
        }

        let net_decision = classify_net_app(&input.command, &ctx.net_app.allow_apps);

        let (out, err, code, shell_label) = run_isolated(
            &input.command,
            &cwd,
            &env,
            dur,
            ctx.shell_tier.tier,
            net_decision,
            ctx.vm_sandbox.as_ref(),
        )
        .await?;

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
        if !ctx.net_app.allow_apps.is_empty() {
            match (net_decision, ctx.shell_tier.tier) {
                (NetDecision::Allow, ShellTier::Tier1a) => {
                    content.push_str("\n[net: internetClient]");
                }
                (NetDecision::Allow, other_tier) => {
                    content.push_str(&format!(
                        "\n[net: denied (--net-allow-app only takes effect under tier1a; \
                         current tier is {})]",
                        other_tier.label()
                    ));
                }
                (NetDecision::DeniedByChaining, _) => {
                    content.push_str(
                        "\n[net: denied (chained command; issue the trusted app as a single \
                         command without |, &&, ;, & to allow network)]",
                    );
                }
                (NetDecision::Deny, _) => {
                    content.push_str("\n[net: denied]");
                }
            }
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
        if let Some(p) = &proxy {
            let entries = p.audit.entries();
            content.push_str("\n[net-proxy: audit-only, not enforced against raw sockets, see plans/DESIGN-SANDBOX-PRIVSEP.md §3.1]");
            for e in &entries {
                let verdict = if e.allowed { "ALLOW" } else { "DENY" };
                content.push_str(&format!("\n[net-proxy: {verdict} {}]", e.host));
            }
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
#[allow(clippy::too_many_arguments)]
async fn run_isolated(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
    tier: ShellTier,
    net: NetDecision,
    vm_sandbox: Option<&std::sync::Arc<dyn harness_core::VmShellExecutor>>,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    // Tier1a以外はcapability機構自体が無いため`net`を消費しない（呼び出し元のフッタで
    // 「このTierでは無効」と明記する、`call`参照）。
    let _ = &net;
    if tier == ShellTier::Tier3 {
        return run_tier3(command, cwd, env, dur, vm_sandbox).await;
    }
    #[cfg(windows)]
    {
        if tier == ShellTier::Tier1a {
            return run_windows_tier1a(command, cwd, env, dur, net).await;
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

/// Tier3（Hyper-V外層VM + Incusコンテナ）実行経路。他Tierと異なり実プロセスをホスト側に
/// spawnせず、`ctx.vm_sandbox`（`VmSandboxHandle`、`plans/DESIGN-SANDBOX-VMISOLATION.md`）経由で
/// コンテナ内実行に委譲する。同期IPC呼び出しのため`spawn_blocking`で包む
/// （`harness_core::VmShellExecutor`のdocコメント参照）。
async fn run_tier3(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
    vm_sandbox: Option<&std::sync::Arc<dyn harness_core::VmShellExecutor>>,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let executor = vm_sandbox
        .cloned()
        .ok_or_else(|| {
            ToolError::ExecutionFailed(
                "tier3 selected but ToolCtx.vm_sandbox is not set (internal error, harness-cli \
                 should have started a VmSandboxHandle before constructing ToolCtx)"
                    .to_string(),
            )
        })?;
    // `env`（`harness_sandbox::build_child_env`）はWindows向けのallowlist（`PATH`が
    // `C:\Windows\system32;...`等）であり、Linuxコンテナへそのまま転送すると`sh`自体の
    // 解決に使われるPATHがWindows形式で上書きされ、あらゆるコマンドが
    // 「Command not found」（Incus execのargv[0]解決失敗）になる（実機E2Eで発見）。
    // コンテナ側の既定PATHをそのまま使わせるため、Tier3ではホストenvを一切転送しない
    // （TODO: Linux向けのenv許可リストが必要になった場合はPhase 2で再検討する）。
    let _ = env;
    let env: Vec<(String, String)> = Vec::new();
    let command = command.to_string();
    let cwd = cwd.to_path_buf();
    let (stdout, stderr, exit_code) = tokio::task::spawn_blocking(move || {
        executor.exec(&command, &cwd, &env, dur)
    })
    .await
    .map_err(|e| ToolError::ExecutionFailed(format!("tier3 exec task panicked: {e}")))?
    .map_err(ToolError::ExecutionFailed)?;
    Ok((stdout, stderr, exit_code, "incus-exec"))
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
    net: NetDecision,
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

    // アプリ単位network制御（軸1、D-10/D-11）。`Allow`のときのみ`internetClient`を付与する
    // （`DeniedByChaining`/`Deny`はどちらも既定のcapability空＝network全遮断のまま）。
    let net_capability = match net {
        NetDecision::Allow => harness_sandbox::win_appcontainer::NetworkCapability::InternetClient,
        NetDecision::Deny | NetDecision::DeniedByChaining => {
            harness_sandbox::win_appcontainer::NetworkCapability::Deny
        }
    };

    let child = harness_sandbox::win_appcontainer::spawn(
        &bin,
        &args,
        &cwd_owned,
        &env_owned,
        true,
        sid.as_psid(),
        net_capability,
    )
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
        // `opt_in_tier1a=false`・`opt_in_tier3=false`固定（既存Tier1bテストの挙動を変えないため）。
        ctx.shell_tier = harness_sandbox::select_tier(
            harness_core::RequireSandbox::None,
            &root,
            false,
            false,
            &[],
            None,
        )
        .expect("tier selection without --require-sandbox never fails");
        ctx
    }

    #[test]
    fn classify_net_app_denies_when_allowlist_empty() {
        assert_eq!(classify_net_app("git push", &[]), NetDecision::Deny);
    }

    #[test]
    fn classify_net_app_allows_matching_leading_exe() {
        let allow = vec!["git".to_string()];
        assert_eq!(classify_net_app("git push origin main", &allow), NetDecision::Allow);
    }

    #[test]
    fn classify_net_app_matches_case_insensitively_and_ignores_extension_and_path() {
        let allow = vec!["Git".to_string()];
        assert_eq!(
            classify_net_app("C:\\Tools\\Git\\bin\\GIT.EXE push", &allow),
            NetDecision::Allow
        );
        // パスに空白を含む場合は呼び出し側が引用符で囲む前提（先頭トークン抽出は
        // 引用符付き文字列にのみ対応、素の空白区切りではトークンが分断される）。
        assert_eq!(
            classify_net_app("\"C:\\Program Files\\Git\\bin\\GIT.EXE\" push", &allow),
            NetDecision::Allow
        );
    }

    #[test]
    fn classify_net_app_denies_non_matching_leading_exe() {
        let allow = vec!["git".to_string()];
        assert_eq!(classify_net_app("npm install", &allow), NetDecision::Deny);
    }

    #[test]
    fn classify_net_app_denies_by_chaining_even_when_leading_exe_matches() {
        let allow = vec!["git".to_string()];
        assert_eq!(
            classify_net_app("git push | curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
        assert_eq!(
            classify_net_app("git push && curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
        assert_eq!(
            classify_net_app("git push; curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
    }

    #[test]
    fn classify_net_app_handles_quoted_leading_token() {
        let allow = vec!["git".to_string()];
        assert_eq!(
            classify_net_app("\"git\" push origin main", &allow),
            NetDecision::Allow
        );
    }

    #[test]
    fn classify_net_app_denies_empty_command() {
        let allow = vec!["git".to_string()];
        assert_eq!(classify_net_app("", &allow), NetDecision::Deny);
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
            harness_sandbox::select_tier(RequireSandbox::None, dir.path(), true, false, &[], None)
                .unwrap();
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

    /// アプリ単位network制御（軸1、D-10/D-11）の実機E2E。Tier1a配下で、許可リストに一致する
    /// 単一コマンドは`internetClient`が付与されて外向き接続に成功し、それ以外
    /// （不一致・連鎖）はcapability空のまま`WSAEACCES`相当で失敗することを確認する
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md` §10 検証計画1/2/3）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier1a_net_allow_app_grants_and_denies_network() {
        use harness_core::{NetAppPolicy, RequireSandbox, ShellTier};

        let dir = tempfile::tempdir().unwrap();
        let selection =
            harness_sandbox::select_tier(RequireSandbox::None, dir.path(), true, false, &[], None)
                .unwrap();
        if selection.tier != ShellTier::Tier1a {
            eprintln!(
                "skipping tier1a net-allow-app test: preflight downgraded to {} ({:?})",
                selection.tier.label(),
                selection.reason
            );
            return;
        }

        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = selection;
        ctx.net_app = NetAppPolicy {
            allow_apps: vec!["powershell".to_string(), "pwsh".to_string()],
        };
        let tool = RunShellTool;
        // TCPソケットを直接開くprobe（HTTP_PROXYに依存しない、capability機構そのものを見る）。
        let connect_probe = "try { \
            $c = New-Object Net.Sockets.TcpClient; \
            $c.Connect('8.8.8.8', 53); \
            Write-Output 'CONNECT OK'; \
            $c.Close() \
        } catch { Write-Output \"CONNECT FAIL: $_\" }";

        // (a) 許可リスト一致・単一コマンド → internetClient付与 → 接続成功。
        let out = tool
            .call(json!({ "command": connect_probe }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("[net: internetClient]"),
            "allowed single command should be granted internetClient: {}",
            out.content
        );
        assert!(
            out.content.contains("CONNECT OK"),
            "allowed command should be able to open an outbound socket: {}",
            out.content
        );

        // (b) 連鎖コマンド → 先頭execは一致するがdeny側へ倒れる → 接続失敗。
        let chained = format!("{connect_probe}; Write-Output 'chained'");
        let out = tool
            .call(json!({ "command": chained }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("[net: denied (chained command"),
            "chained command must not be granted network even if leading exe matches: {}",
            out.content
        );
        assert!(
            out.content.contains("CONNECT FAIL"),
            "chained command should still be network-denied (capability empty): {}",
            out.content
        );
    }

    /// 協調プロキシ（M12補遺、D-15）の実機E2E。単体テスト（`net_proxy::tests`）はプロキシ
    /// 単体をTCPクライアントから直接叩いて検証したが、これは「`run_shell`が実際に子プロセスへ
    /// `HTTP_PROXY`を注入し、外部ツール（`curl.exe`）がそれを自発的に読んで従う」という
    /// 統合経路まで通しで確認する（`plans/DESIGN-SANDBOX-PRIVSEP.md` §8フェーズ1検証計画:
    /// 「許可ドメインへの通信が成功し監査ログに残ること、未許可ドメインへのCONNECTが
    /// プロキシに拒否されること」）。`curl`がPATHに無い環境ではskipする。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_cooperative_proxy_allows_and_denies_real_curl_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        if which::which("curl").is_err() {
            eprintln!("skipping cooperative proxy test: curl not found on PATH");
            return;
        }

        // ダミーの許可済み宛先サーバ（ループバック）。1リクエストだけ受けて200を返す。
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = target_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["127.0.0.1".to_string()],
        };
        let tool = RunShellTool;

        let command = format!(
            "curl.exe -s -o allowed.txt -w 'ALLOWED_STATUS=%{{http_code}}' http://127.0.0.1:{target_port}/; \
             curl.exe -s -o NUL -w ' DENIED_STATUS=%{{http_code}}' http://notallowed.invalid.example/"
        );
        let out = tool
            .call(json!({ "command": command }), &context)
            .await
            .unwrap();

        assert!(
            out.content.contains("ALLOWED_STATUS=200"),
            "curl through the cooperative proxy to an allowed domain should succeed: {}",
            out.content
        );
        assert!(
            out.content.contains("DENIED_STATUS=403"),
            "curl through the cooperative proxy to a disallowed domain should get 403 from the \
             proxy itself (not a connection failure to notallowed.invalid.example, which does \
             not need to resolve): {}",
            out.content
        );
        assert!(
            out.content.contains("[net-proxy: ALLOW 127.0.0.1]"),
            "audit log should record the allowed request: {}",
            out.content
        );
        assert!(
            out.content.contains("[net-proxy: DENY notallowed.invalid.example]"),
            "audit log should record the denied request: {}",
            out.content
        );

        let allowed_body = std::fs::read_to_string(dir.path().join("allowed.txt")).unwrap();
        assert_eq!(allowed_body, "hello");
    }
}
