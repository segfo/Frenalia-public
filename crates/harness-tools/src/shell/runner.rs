//! Tierごとの隔離機構と話す層——どのOS機構で子プロセスを起こすか。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則3の軸1（どの外部システムと話すか）で`shell.rs`から
//! 切り出した。`run_isolated`が`ctx.shell_tier.tier`で経路を選び、以降は各Tierが自分の機構
//! （Restricted Token / AppContainer / bwrap / Incus / 素のspawn）だけを知る。
//!
//! - Tier3: `harness_core::VmShellExecutor`経由でVM内Incusコンテナへ委譲（実プロセスをspawnしない）
//! - Tier2a: `harness_sandbox::tier2a::win_appcontainer`（package SID + capability SID + Redirector）
//! - Tier1: `harness_sandbox::tier1::win_restricted`（Restricted Token + 低IL + Job Object）
//! - Tier2b: `harness_sandbox::tier2b::linux_bwrap`
//! - Tier0: 素のspawn + Job Object(Win)/rlimit(unix)（保険・全OS）
//!
//! **どのTierを選ぶかはここでは決めない**——`ctx.shell_tier`は`harness-cli`が起動時に1回
//! `select_tier`で解決した値であり、この module はそれに従うだけである。

use std::path::Path;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use harness_core::{ShellTier, ToolError};

#[cfg(windows)]
use super::net_decision::should_grant_tier2a_network_capability;
use super::net_decision::NetDecision;
use super::platform::{decode_console_output, platform_shell_command};
#[cfg(windows)]
use super::platform::{run_shell_bootstrap_stdin, RUN_SHELL_COMMAND_ENV_VAR};

/// Tierに応じて実行経路を切り替える。戻り値は`(stdout, stderr, exit_code, shell_label)`。
/// `exit_code`は`None`ならkill済み（timeout）を表す呼び出し元エラーへ畳み込む。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_isolated(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
    tier: ShellTier,
    net: NetDecision,
    net_proxy_enforced: bool,
    net_domain_policy_requested: bool,
    vm_sandbox: Option<&std::sync::Arc<dyn harness_core::VmShellExecutor>>,
    workspace_root: &Path,
    cow_diff_layer_dir: Option<&Path>,
    granted_passthrough: &[harness_core::GrantedPassthrough],
    #[cfg(windows)] spawn_daemon: Option<&harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    // Tier2a以外はcapability機構自体が無いため`net`を消費しない（呼び出し元のフッタで
    // 「このTierでは無効」と明記する、`call`参照）。
    let _ = &net;
    // `workspace_root`/`cow_diff_layer_dir`（D-30、`--sandbox tier2a-cow`）はWindows Tier2a経路でのみ使う
    // （Redirector DLL注入用のenv注入先パス）。
    #[cfg(not(windows))]
    let _ = (workspace_root, cow_diff_layer_dir, granted_passthrough);
    if tier == ShellTier::Tier3 {
        return run_tier3(command, cwd, env, dur, vm_sandbox).await;
    }
    #[cfg(windows)]
    {
        if tier == ShellTier::Tier2a {
            return run_windows_tier2a(
                command,
                cwd,
                env,
                dur,
                net,
                net_proxy_enforced,
                net_domain_policy_requested,
                workspace_root,
                cow_diff_layer_dir,
                granted_passthrough,
                spawn_daemon,
            )
            .await;
        }
        if tier == ShellTier::Tier1 {
            return run_windows_tier1(command, cwd, env, dur).await;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if tier == ShellTier::Tier2b {
            return run_linux_tier2b(command, cwd, env, dur).await;
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
    let executor = vm_sandbox.cloned().ok_or_else(|| {
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
    let (stdout, stderr, exit_code) =
        tokio::task::spawn_blocking(move || executor.exec(&command, &cwd, &env, dur))
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
    let env_owned: Vec<(String, String)>;
    let env = if let Some((k, v)) = &invocation.extra_env {
        env_owned = env
            .iter()
            .cloned()
            .chain(std::iter::once((k.to_string(), v.clone())))
            .collect();
        env_owned.as_slice()
    } else {
        env
    };
    apply_common_command_settings(&mut cmd, cwd, env, invocation.stdin_payload.is_some());

    #[cfg(unix)]
    apply_unix_rlimits(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    #[cfg(windows)]
    {
        if let Some(handle) = child.raw_handle() {
            let _ = harness_sandbox::tier1::win_restricted::attach_job_object(handle as isize);
        }
    }

    run_with_pipes(&mut child, invocation.stdin_payload, dur)
        .await
        .map(|(out, err, code)| (out, err, code, invocation.shell_label))
}

#[cfg(target_os = "linux")]
async fn run_linux_tier2b(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let session_dir = cwd.join(".harness").join("sandbox").join("tier2b");
    let config = harness_sandbox::tier2b::linux_bwrap::BwrapConfig {
        workspace_root: cwd.to_path_buf(),
        diff_layer_dir: session_dir.join("diff-layer"),
        work_dir: session_dir.join("work"),
    };
    let _ = std::fs::create_dir_all(&config.diff_layer_dir);
    let _ = std::fs::create_dir_all(&config.work_dir);
    let bwrap_args = harness_sandbox::tier2b::linux_bwrap::build_args(&config);

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
#[allow(clippy::too_many_arguments)]
async fn run_windows_tier2a(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
    net: NetDecision,
    net_proxy_enforced: bool,
    net_domain_policy_requested: bool,
    workspace_root: &Path,
    cow_diff_layer_dir: Option<&Path>,
    granted_passthrough: &[harness_core::GrantedPassthrough],
    spawn_daemon: Option<&harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let mut env_owned = env.to_vec();
    // BUG-050: コマンド本体はstdinスクリプトへ文字列として埋め込まず、env経由で渡す
    // （`RUN_SHELL_BOOTSTRAP_SCRIPT`のdoc参照）。`RUN_SHELL_COMMAND_ENV_VAR`はこのクレートの
    // 定数なので、依存の向き上`spawn_shell_in_workspace`の中では積めない（あちらのdoc参照）。
    env_owned.push((RUN_SHELL_COMMAND_ENV_VAR.to_string(), command.to_string()));

    // アプリ単位network制御（軸1、D-10/D-11）。`Allow`のときのみ`internetClient`を付与する
    // （`DeniedByChaining`/`Deny`はどちらも既定のcapability空＝network全遮断のまま）。
    // **判定はここ（純粋関数）、付与は起動側**という分担を崩さない。
    let net_capability = if should_grant_tier2a_network_capability(
        net,
        net_proxy_enforced,
        net_domain_policy_requested,
    ) {
        harness_sandbox::tier2a::win_appcontainer::NetworkCapability::InternetClient
    } else {
        harness_sandbox::tier2a::win_appcontainer::NetworkCapability::Deny
    };

    let request = harness_sandbox::tier2a::win_appcontainer::WorkspaceSpawn {
        cwd: cwd.to_path_buf(),
        env: env_owned,
        workspace_root: workspace_root.to_path_buf(),
        cow_diff_layer_dir: cow_diff_layer_dir.map(|p| p.to_path_buf()),
        granted_passthrough: granted_passthrough.to_vec(),
        net_capability,
    };

    // [BUG-082フォローアップ] `spawn_shell_in_workspace`は内部で`grant_job::wait_until_done`
    // （`std::thread::sleep`で実待ちする**同期**関数、初回は20秒超）を呼ぶ。これを`.await`無しで
    // この`async fn`の中で直接呼ぶと、tokioのワーカースレッドを待ち時間ぶん丸ごと専有してしまう。
    // `dispatch_one`（`harness-engine`）の`tokio::select!`は`tool.call(...)`のpollがここで
    // 止まっている間一切戻ってこられず、並行して待っているはずの`WaitReason`ポーリング
    // （`AgentEvent::ToolProgress`でツールカードへ待機理由を出す機構）が実行機会を得られない
    // ——ステータスバー側（`grant_job::progress()`を直接読むだけの非ブロッキング呼び出し）は
    // 別経路（TUIの描画tick）なので動いて見え、ツールカードだけが更新されないという形で発覚した。
    // `spawn_blocking`でtokioの専用ブロッキングスレッドへ逃がし、このタスク自身は`.await`で
    // 協調的に譲る。
    let spawn_daemon = spawn_daemon.cloned().ok_or_else(|| {
        ToolError::ExecutionFailed(
            "Tier2a run_shell has no Spawn Daemon connection (internal error)".to_string(),
        )
    })?;
    let (child, shell_label) = tokio::task::spawn_blocking(move || {
        harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace_via_daemon(
            &spawn_daemon,
            request,
        )
    })
    .await
    .map_err(|e| ToolError::ExecutionFailed(format!("tier2a spawn task panicked: {e}")))?
    .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child
        .kill_token()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let stdin_bytes = run_shell_bootstrap_stdin();

    let handle = tokio::task::spawn_blocking(move || {
        child.write_stdin_read_output_and_wait(Some(&stdin_bytes))
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
async fn run_windows_tier1(
    command: &str,
    cwd: &Path,
    env: &[(String, String)],
    dur: Duration,
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    let _ = std::fs::create_dir_all(cwd);
    // cwd1つだけに低ILラベルを付与する（非再帰・冪等、モジュールdocの既知の限界参照）。
    //
    // **失敗を握り潰さない**（B-10）。このラベルが付かないと低ILの子はcwd**内**にも書けなくなる
    // ——つまり「Tier1は範囲内なら書ける」という保証そのものが静かに消える。実際、BUG-018の
    // 案Aが入れた不正なSDDLでこの関数はずっと失敗し続けており、ここが`let _ =`だったせいで
    // 誰も気付けなかった。致命的にはしない（D-43と同じくharnessは止めない）が、
    // **事実は必ず出力へ残す**。
    // stdoutは機械可読出力の契約なので使わない（B-24、BUG-064）。診断はstderrへ出す。
    if let Err(e) = harness_sandbox::tier1::win_restricted::set_low_integrity_label(cwd) {
        eprintln!(
            "warning: failed to apply the low-integrity label to the Tier1 cwd ({}): {e}. \
             Writes inside the sandbox cwd will be denied by Mandatory Integrity Control.",
            cwd.display()
        );
    }

    let (bin, shell_label) = if which::which("pwsh").is_ok() {
        ("pwsh", "pwsh(tier1)")
    } else {
        ("powershell", "powershell5.1(tier1)")
    };
    let args = ["-NoProfile", "-NonInteractive", "-Command", "-"];
    let cwd_owned = cwd.to_path_buf();
    let mut env_owned = env.to_vec();
    // BUG-050: コマンド本体はstdinスクリプトへ文字列として埋め込まず、env経由で渡す
    // （`RUN_SHELL_BOOTSTRAP_SCRIPT`のdoc参照）。
    env_owned.push((RUN_SHELL_COMMAND_ENV_VAR.to_string(), command.to_string()));

    let child =
        harness_sandbox::tier1::win_restricted::spawn(bin, &args, &cwd_owned, &env_owned, true)
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child
        .kill_token()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let stdin_bytes = run_shell_bootstrap_stdin();

    let handle = tokio::task::spawn_blocking(move || {
        child.write_stdin_read_output_and_wait(Some(&stdin_bytes))
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
    stdin_payload: Option<Vec<u8>>,
    dur: Duration,
) -> Result<(String, String, Option<i32>), ToolError> {
    if let Some(payload) = stdin_payload {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin
            .write_all(&payload)
            .await
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
        drop(stdin);
    }

    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    let run = async {
        // Phase5-F（`run_shell`不安定性調査）: `AsyncReadExt::read_to_string`は非UTF-8
        // バイト列に遭遇すると`Err`を返し、`let _ =`で握り潰していたため出力が無言で空文字列
        // （exit code 0・出力なし）になっていた。CP932（Shift-JIS）等、UTF-8でない既定コード
        // ページのコンソール出力（日本語ファイル名を含む`dir`等）で確実に踏む。生バイトを
        // 読み切ってから復号する（BUG-051、`decode_console_output`のdoc参照。Tier1/Tier2aの
        // `win_common::decode_console_bytes`と同じ方針を共有する）。
        let stdout_fut = async {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf).await;
            decode_console_output(&buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf).await;
            decode_console_output(&buf)
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
