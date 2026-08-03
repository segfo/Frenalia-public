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
//! - Windows Tier1: Restricted Token + 低IL + Job Object（`harness_sandbox::win_restricted`）。
//! - Linux Tier2b: `bwrap`でラップ（`harness_sandbox::linux_bwrap`）。本セッションでは実機未検証
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
/// 出力バイト上限（層5・T-13、Tier0/Tier1/Tier2bいずれでも適用する保険）。
const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

const RUN_SHELL_DEFAULT_DESCRIPTION: &str =
    "ワークスペース内でシェルコマンドを実行し、stdout+stderr+終了コードを返す。\
         ネットワーク許可アプリ（--net-allow-app）を使う場合は、|・&&・;等で他コマンドと連結せず、\
         単一コマンドとして発行すること（連結すると通信が拒否される）。";

const RUN_SHELL_TIER3_DESCRIPTION: &str =
    "Tier3のLinuxコンテナ内ワークスペースでシェルコマンドを実行し、\
         stdout+stderr+終了コードを返す。コマンドはAlmaLinux VM内のIncusコンテナで`sh -c`として\
         実行されるため、POSIX sh互換の構文とLinuxパスを使うこと。Windows専用コマンドレットや\
         `$env:...`構文は使わない。";

fn run_shell_input_schema(command_description: &str, cwd_description: &str) -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "command": { "type": "string", "description": command_description },
            "timeout_ms": { "type": "integer", "description": "タイムアウト（ミリ秒、省略時120000）" },
            "cwd": { "type": "string", "description": cwd_description }
        },
        "required": ["command"],
        "additionalProperties": false
    })
}

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
    if command.contains(['|', '&', '`', '\n']) || command.contains("$(") {
        return true;
    }
    let mut brace_depth = 0usize;
    for ch in command.chars() {
        match ch {
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ';' if brace_depth == 0 => return true,
            _ => {}
        }
    }
    false
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
    let shell_allowed = allow_apps.iter().any(|allowed| {
        let basename = exe_basename(allowed);
        basename == "powershell" || basename == "pwsh"
    });
    let token = first_command_token(command);
    if token.is_empty() {
        return NetDecision::Deny;
    }
    let basename = exe_basename(token);
    let matched = allow_apps
        .iter()
        .any(|allowed| exe_basename(allowed) == basename)
        || shell_allowed;
    if !matched {
        return NetDecision::Deny;
    }
    if contains_chaining_metachar(command) {
        return NetDecision::DeniedByChaining;
    }
    NetDecision::Allow
}

fn should_grant_tier2a_network_capability(
    net: NetDecision,
    net_proxy_enforced: bool,
    net_domain_policy_requested: bool,
) -> bool {
    if net_domain_policy_requested {
        return net_proxy_enforced;
    }
    net == NetDecision::Allow
}

#[async_trait]
impl Tool for RunShellTool {
    fn name(&self) -> &str {
        "run_shell"
    }

    fn description(&self) -> &str {
        RUN_SHELL_DEFAULT_DESCRIPTION
    }

    fn input_schema(&self) -> serde_json::Value {
        run_shell_input_schema(
            "実行するシェルコマンド",
            "ワークスペースルートからの相対作業ディレクトリ",
        )
    }

    fn spec_for_ctx(&self, ctx: &ToolCtx) -> harness_core::ToolSpec {
        if ctx.shell_tier.tier == ShellTier::Tier3 {
            harness_core::ToolSpec {
                name: self.name().to_string(),
                description: RUN_SHELL_TIER3_DESCRIPTION.to_string(),
                input_schema: run_shell_input_schema(
                    "AlmaLinux VM内のIncusコンテナで`sh -c`へ渡すコマンド。POSIX sh互換の構文とLinuxパスを使う",
                    "`/workspace`からの相対作業ディレクトリ",
                ),
            }
        } else {
            harness_core::ToolSpec {
                name: self.name().to_string(),
                description: self.description().to_string(),
                input_schema: self.input_schema(),
            }
        }
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
        append_path_extra(&mut env, &ctx.run_shell_path_extra);
        // D-14b: モデル実行`git`のhooks/fsmonitor/pagerを無効化する（T-07対策、
        // `harness_sandbox::git_hardening_env`のdoc参照）。envは全子孫プロセスへ自動継承される
        // ため、`git`が孫プロセスとして起動されても届く。
        env.extend(harness_sandbox::git_hardening_env());

        // 協調プロキシ（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15、
        // `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md` §5）。
        // `ctx.net_proxy.domain_policy_enabled`なら、`allow_domains`が空でも全拒否ポリシーとして
        // Proxy/Fake DNS監査経路を起動する。SOCKS5 remote DNSを主経路とする`ALL_PROXY`と、
        // 既存HTTP(S)ツール互換の`HTTP_PROXY`/`HTTPS_PROXY`を子envへ足す。
        let mut net_proxy = ctx.net_proxy.clone();
        if net_proxy.audit_log_path.is_none() {
            if let Some(sandbox_dir) = &ctx.staging.sandbox_dir {
                net_proxy.audit_log_path =
                    Some(ctx.workspace_root.join(sandbox_dir).join("net-audit.jsonl"));
            }
        }
        let proxy = if net_proxy.proxy_addr.is_some() {
            None
        } else {
            crate::net_proxy::spawn_local_proxy(&net_proxy)
                .await
                .ok()
                .flatten()
        };
        let fake_dns = if net_proxy.fake_dns_addr.is_some() {
            None
        } else if net_proxy.domain_policy_enabled {
            crate::fake_dns::spawn_fake_dns(&crate::fake_dns::FakeDnsConfig {
                allow_domains: net_proxy.allow_domains.clone(),
                policy_required: net_proxy.domain_policy_enabled,
                audit_log_path: net_proxy.audit_log_path.clone(),
                preferred_port: None,
            })
            .await
            .ok()
        } else {
            None
        };
        let proxy_addr = net_proxy
            .proxy_addr
            .or_else(|| proxy.as_ref().map(|p| p.addr));
        let fake_dns_addr = net_proxy
            .fake_dns_addr
            .or_else(|| fake_dns.as_ref().map(|dns| dns.addr));
        if let Some(addr) = proxy_addr {
            let http_proxy_url = format!("http://{}", addr);
            let socks_proxy_url = format!("socks5h://{}", addr);
            for key in ["ALL_PROXY", "all_proxy"] {
                env.push((key.to_string(), socks_proxy_url.clone()));
            }
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                env.push((key.to_string(), http_proxy_url.clone()));
            }
        }
        if let Some(addr) = fake_dns_addr {
            env.push(("HARNESS_FAKE_DNS_ADDR".to_string(), addr.to_string()));
        }

        let net_decision = classify_net_app(&input.command, &ctx.net_app.allow_apps);
        let net_domain_policy_requested = ctx.net_proxy.domain_policy_enabled;

        let (out, err, code, shell_label) = run_isolated(
            &input.command,
            &cwd,
            &env,
            dur,
            ctx.shell_tier.tier,
            net_decision,
            ctx.net_proxy.enforced_by_wfp && ctx.net_proxy.domain_policy_enabled,
            net_domain_policy_requested,
            ctx.vm_sandbox.as_ref(),
            &ctx.workspace_root,
            ctx.cow_upper_dir.as_deref(),
            &ctx.shell_tier.granted_passthrough,
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
                ctx.shell_tier
                    .downgraded_from
                    .map(|t| t.label())
                    .unwrap_or("?")
            ));
        }
        if !ctx.net_app.allow_apps.is_empty() {
            match (
                net_domain_policy_requested,
                net_decision,
                ctx.shell_tier.tier,
            ) {
                (true, _, ShellTier::Tier2a) if ctx.net_proxy.enforced_by_wfp => {
                    content.push_str("\n[net: domain policy enforced; --net-allow-app ignored]");
                }
                (true, _, ShellTier::Tier2a) => {
                    content.push_str(
                        "\n[net: denied (domain policy requested but WFP enforcement is unavailable; \
                         --net-allow-app ignored)]",
                    );
                }
                (true, _, other_tier) => {
                    content.push_str(&format!(
                        "\n[net: denied (--net-allow-domain takes precedence over --net-allow-app; \
                         current tier is {})]",
                        other_tier.label()
                    ));
                }
                (false, NetDecision::Allow, ShellTier::Tier2a) => {
                    content.push_str("\n[net: internetClient]");
                }
                (false, NetDecision::Allow, other_tier) => {
                    content.push_str(&format!(
                        "\n[net: denied (--net-allow-app only takes effect under Tier2a; \
                         current tier is {})]",
                        other_tier.label()
                    ));
                }
                (false, NetDecision::DeniedByChaining, _) => {
                    content.push_str(
                        "\n[net: denied (chained command; issue the trusted app as a single \
                         command without |, &&, ;, & to allow network)]",
                    );
                }
                (false, NetDecision::Deny, _) => {
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
        if !matches!(ctx.staging.mode, StagingMode::Live) && !ctx.shell_sees_staged_writes {
            content.push_str(
                "\n[warning: staged writes made earlier in this turn may not be visible to this \
                 shell process yet (D-08 simplification, see plans/DESIGN-SANDBOX.md §8-3)]",
            );
        }
        if proxy_addr.is_some() {
            if ctx.net_proxy.enforced_by_wfp && ctx.shell_tier.tier == ShellTier::Tier2a {
                content.push_str("\n[net-proxy: enforced-by-wfp]");
            } else {
                content.push_str("\n[net-proxy: audit-only, not enforced against raw sockets, see plans/DESIGN-SANDBOX-PRIVSEP.md §3.1]");
            }
            if let Some(p) = &proxy {
                if let Some(path) = p.audit.path() {
                    content.push_str(&format!("\n[net-proxy-audit: {}]", path.display()));
                }
            } else if let Some(path) = &net_proxy.audit_log_path {
                content.push_str(&format!("\n[net-proxy-audit: {}]", path.display()));
            }
            if let Some(p) = &proxy {
                for e in p.audit.entries() {
                    let verdict = if e.allowed { "ALLOW" } else { "DENY" };
                    content.push_str(&format!("\n[net-proxy: {verdict} {}]", e.host));
                }
            }
        }
        if let Some(dns) = &fake_dns {
            content.push_str(&format!(
                "\n[net-fakedns: diagnostic-only addr={}]",
                dns.addr
            ));
            if let Some(path) = dns.audit.path() {
                content.push_str(&format!("\n[net-fakedns-audit: {}]", path.display()));
            }
            for e in dns.audit.entries() {
                content.push_str(&format!(
                    "\n[net-fakedns: QUERY {} {} fake_ip={}]",
                    e.qtype,
                    e.host,
                    e.fake_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "none".to_string())
                ));
            }
        }
        if fake_dns.is_none() {
            if let Some(addr) = net_proxy.fake_dns_addr {
                content.push_str(&format!("\n[net-fakedns: diagnostic-only addr={addr}]"));
                if let Some(path) = &net_proxy.audit_log_path {
                    content.push_str(&format!("\n[net-fakedns-audit: {}]", path.display()));
                }
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

fn append_path_extra(env: &mut Vec<(String, String)>, path_extra: &[String]) {
    if path_extra.is_empty() {
        return;
    }
    let Some((_, path)) = env
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
    else {
        return;
    };
    for entry in path_extra {
        append_path_entry(path, entry);
    }
}

fn append_path_entry(path: &mut String, entry: &str) {
    let entry = entry.trim();
    if entry.is_empty() {
        return;
    }
    if path
        .split(path_separator())
        .any(|existing| path_entries_equal(existing, entry))
    {
        return;
    }
    if !path.is_empty() && !path.ends_with(path_separator()) {
        path.push(path_separator());
    }
    path.push_str(entry);
}

fn path_separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

fn path_entries_equal(a: &str, b: &str) -> bool {
    let a = a.trim().trim_end_matches(['\\', '/']);
    let b = b.trim().trim_end_matches(['\\', '/']);
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
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
    net_proxy_enforced: bool,
    net_domain_policy_requested: bool,
    vm_sandbox: Option<&std::sync::Arc<dyn harness_core::VmShellExecutor>>,
    workspace_root: &Path,
    cow_upper_dir: Option<&Path>,
    granted_passthrough: &[(std::path::PathBuf, bool)],
) -> Result<(String, String, Option<i32>, &'static str), ToolError> {
    // Tier2a以外はcapability機構自体が無いため`net`を消費しない（呼び出し元のフッタで
    // 「このTierでは無効」と明記する、`call`参照）。
    let _ = &net;
    // `workspace_root`/`cow_upper_dir`（D-30、`--cow`）はWindows Tier2a経路でのみ使う
    // （Redirector DLL注入用のenv注入先パス）。
    #[cfg(not(windows))]
    let _ = (workspace_root, cow_upper_dir, granted_passthrough);
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
                cow_upper_dir,
                granted_passthrough,
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
        env_owned = env.iter().cloned().chain(std::iter::once((k.to_string(), v.clone()))).collect();
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
            let _ = harness_sandbox::win_restricted::attach_job_object(handle as isize);
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
    cow_upper_dir: Option<&Path>,
    granted_passthrough: &[(std::path::PathBuf, bool)],
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
    let mut env_owned = env.to_vec();
    // BUG-050: コマンド本体はstdinスクリプトへ文字列として埋め込まず、env経由で渡す
    // （`RUN_SHELL_BOOTSTRAP_SCRIPT`のdoc参照）。
    env_owned.push((RUN_SHELL_COMMAND_ENV_VAR.to_string(), command.to_string()));
    // Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴を
    // Redirector DLLのext capture対象として渡す（境界＝ACLはfs-allowが既に張っている、
    // ここは変更の可視化のためのcapture）。
    let ext_capture_roots: Vec<std::path::PathBuf> = granted_passthrough
        .iter()
        .filter(|(_, writable)| *writable)
        .map(|(path, _)| path.clone())
        .collect();
    let cow = cow_upper_dir.map(|upper_dir| harness_sandbox::win_appcontainer::CowInject {
        workspace_root,
        upper_dir,
        ext_capture_roots: ext_capture_roots.as_slice(),
    });

    // アプリ単位network制御（軸1、D-10/D-11）。`Allow`のときのみ`internetClient`を付与する
    // （`DeniedByChaining`/`Deny`はどちらも既定のcapability空＝network全遮断のまま）。
    let net_capability = if should_grant_tier2a_network_capability(
        net,
        net_proxy_enforced,
        net_domain_policy_requested,
    ) {
        harness_sandbox::win_appcontainer::NetworkCapability::InternetClient
    } else {
        harness_sandbox::win_appcontainer::NetworkCapability::Deny
    };

    let child = harness_sandbox::win_appcontainer::spawn(
        &bin,
        &args,
        &cwd_owned,
        &env_owned,
        true,
        sid.as_psid(),
        net_capability,
        cow,
    )
    .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child.kill_token();
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
    // cwd1つだけに継承可能な低ILラベルを付与する（非再帰・冪等、モジュールdocの既知の限界参照）。
    let _ = harness_sandbox::win_restricted::set_low_integrity_label(cwd);

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

    let child = harness_sandbox::win_restricted::spawn(bin, &args, &cwd_owned, &env_owned, true)
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
    let kill_token = child.kill_token();
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

/// 起動する子プロセスコマンドと、記録用のシェルラベル・stdin経由で渡すブートストラップ・
/// 追加env（Windowsのみ使用）をまとめたもの。
struct ShellInvocation {
    cmd: Command,
    stdin_payload: Option<Vec<u8>>,
    shell_label: &'static str,
    /// BUG-050: コマンド本体を運ぶ追加env（Windowsのみ）。呼び出し元が`env`へ追加してから
    /// spawnする（`git_hardening_env()`と同じ、既存の`env`可変配列に足すだけのパターン）。
    extra_env: Option<(&'static str, String)>,
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
        extra_env: None,
    }
}

/// Windowsはpwsh7優先→Windows PowerShell 5.1フォールバック。コマンド文字列はargvへも
/// stdinスクリプトへも埋め込まず、**env経由**で渡す（BUG-050、§ツールシステム run_shell
/// 「シェル選択」）。stdinへ書くのは`RUN_SHELL_BOOTSTRAP_SCRIPT`という固定の純ASCII文字列
/// だけで、コマンドの中身に一切依存しない。
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
        stdin_payload: Some(run_shell_bootstrap_stdin()),
        shell_label,
        extra_env: Some((RUN_SHELL_COMMAND_ENV_VAR, command.to_string())),
    }
}

/// BUG-050: コマンド本体を運ぶenv変数名。`CreateProcessW`の環境ブロック（UTF-16、
/// `win_common::build_env_block`）を経由するため、CP932等のANSIコードページでは表現できない
/// 文字（絵文字・ハングル・非BMP等）も無損失で子へ渡る。読み取り後は
/// `RUN_SHELL_BOOTSTRAP_SCRIPT`内で`Remove-Item Env:`により孫プロセスへの継承を絶つ。
#[cfg(windows)]
const RUN_SHELL_COMMAND_ENV_VAR: &str = "HARNESS_RUN_SHELL_COMMAND";

/// BUG-049/BUG-050: `-Command -`（stdin経由）で流すブートストラップ。**内容はコマンドに
/// 依存しない固定の純ASCII文字列**であり、これがstdinの符号化問題（BUG-049修正が
/// `WideCharToMultiByte`のベストフィット変換で持ち込んだ検査回避＝BUG-050の根本原因）を
/// 完全に消し去る——stdinへ非ASCIIバイトが一切乗らないため、コードページ変換自体が
/// 不要になる。
///
/// コマンド本体は`RUN_SHELL_COMMAND_ENV_VAR`からenv経由で読み、`[scriptblock]::Create`で
/// 実行する。**判定用の元コマンドは一切変更しない**: `classify_net_app`等の危険構文検査は
/// 呼び出し元で元の`command`文字列に対して行い（`shell.rs`の`classify_net_app`・
/// `harness-engine::permission::looks_like_allowlist_bypass`）、このブートストラップは
/// 検査結果とは独立に常に同じ内容で送られる。
///
/// 実測（Windows PowerShell 5.1・pwsh 7.6.4、`CREATE_NO_WINDOW`下）:
/// 絵文字・非BMP文字（`𠮷`）・複合文字（`が`）を含むコマンド、日本語ファイル名の作成・削除、
/// いずれもバイト完全一致で往復する。ベストフィット変換の検体（`¦`→`|`）も`¦`のまま保たれる。
///
/// また、`-Command -`（stdin経由）実行の終了コードはPowerShellプロセス自身の終了コードで
/// あり、スクリプトが明示的に`exit`しない限り**最後の文（statement）の成否からブール化
/// （0/1）されるだけ**で、ネイティブコマンドの実際の終了コード（例: `7`）は失われる
/// （Phase5-H実測）。末尾の`$LASTEXITCODE`/`$?`判定で、bashの`sh -c`と同じ「最後のコマンドの
/// 終了状態」意味論に揃える。
///
/// Tier0（本関数の呼び出し元`platform_shell_command`）・Tier2a（`run_windows_tier2a`）・
/// Tier1（`run_windows_tier1`）の3経路全てがこの1関数を通す（Tier横断で1箇所に集約し、
/// 個別に実装して食い違うことを防ぐ）。
#[cfg(windows)]
const RUN_SHELL_BOOTSTRAP_SCRIPT: &str = "\
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
$OutputEncoding = [System.Text.Encoding]::UTF8; \
$__harness_cmd = $env:HARNESS_RUN_SHELL_COMMAND; \
Remove-Item Env:HARNESS_RUN_SHELL_COMMAND -ErrorAction SilentlyContinue; \
. ([scriptblock]::Create($__harness_cmd)); \
if ($LASTEXITCODE) { exit $LASTEXITCODE } elseif (-not $?) { exit 1 }
";

#[cfg(windows)]
fn run_shell_bootstrap_stdin() -> Vec<u8> {
    debug_assert!(
        RUN_SHELL_BOOTSTRAP_SCRIPT.is_ascii(),
        "BUG-050: bootstrap must stay pure ASCII so no code-page conversion is ever needed"
    );
    RUN_SHELL_BOOTSTRAP_SCRIPT.as_bytes().to_vec()
}

/// BUG-051: Tier0（本関数）・Tier1・Tier2aが共通で使う出力デコーダ。Windowsでは
/// `harness_sandbox::decode_console_bytes`（起動直後のANSIコードページ由来のメッセージと
/// ブートストラップ適用後のUTF-8が同一ストリーム内で混在し得ることへの対処、`win_common`の
/// doc参照）を通す。Unix（`sh -c`）にはこの種の混在は無いため`from_utf8_lossy`のまま。
fn decode_console_output(bytes: &[u8]) -> String {
    #[cfg(windows)]
    {
        harness_sandbox::decode_console_bytes(bytes)
    }
    #[cfg(not(windows))]
    {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn ctx(root: PathBuf) -> ToolCtx {
        let mut ctx = ToolCtx::new(root.clone());
        // `ToolCtx::new`はテスト既定でTier0（プレースホルダ）を積む。実行時は
        // `harness-cli`が起動時に`select_tier`で解決した値を積むため、ここでも
        // 実際のOS隔離Tier選択を再現する（さもないとTier1経路が単体テストで一切通らない）。
        // WindowsではTier2aがフラグ無しで既定プローブされるため、`--tier1`相当の
        // `opt_in_tier1=true`を指定してTier1へ直接降ろし、
        // 決定論的にする（実Win32 preflightを単体テストで走らせない、既存Tier1テストの
        // 挙動を変えないため）。`opt_in_tier3=false`固定。
        let probes = harness_sandbox::shell_tier::Probes {
            tier2a_preflight_override: Some(Err("test fixture: force Tier1".to_string())),
            ..Default::default()
        };
        ctx.shell_tier = harness_sandbox::shell_tier::select_tier_with_probes(
            harness_core::RequireSandbox::None,
            &root,
            false,
            true,
            &[],
            None,
            &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            &probes,
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
        assert_eq!(
            classify_net_app("git push origin main", &allow),
            NetDecision::Allow
        );
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

    #[test]
    fn append_path_extra_adds_entries_without_duplicates() {
        let mut env = vec![("PATH".to_string(), "C:\\Windows\\System32".to_string())];
        append_path_extra(
            &mut env,
            &[
                "C:\\Users\\me\\.local\\bin".to_string(),
                "C:\\Users\\me\\.local\\bin\\".to_string(),
            ],
        );
        let path = env
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(path.contains("C:\\Windows\\System32"));
        assert!(path.contains("C:\\Users\\me\\.local\\bin"));
        assert_eq!(
            path.split(path_separator())
                .filter(|entry| path_entries_equal(entry, "C:\\Users\\me\\.local\\bin"))
                .count(),
            1
        );
    }

    #[test]
    fn append_path_extra_does_not_create_missing_path() {
        let mut env = vec![("HOME".to_string(), "/home/me".to_string())];
        append_path_extra(&mut env, &["/home/me/.local/bin".to_string()]);
        assert!(env
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("PATH")));
    }

    #[test]
    fn domain_policy_takes_precedence_over_net_allow_app_for_tier2a_capability() {
        assert!(should_grant_tier2a_network_capability(
            NetDecision::Allow,
            false,
            false
        ));
        assert!(!should_grant_tier2a_network_capability(
            NetDecision::Allow,
            false,
            true
        ));
        assert!(should_grant_tier2a_network_capability(
            NetDecision::Deny,
            true,
            true
        ));
        assert!(!should_grant_tier2a_network_capability(
            NetDecision::Deny,
            false,
            true
        ));
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

    #[test]
    fn run_shell_tool_spec_mentions_sh_c_for_tier3() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);

        let spec = RunShellTool.spec_for_ctx(&context);

        assert!(spec.description.contains("`sh -c`"), "{}", spec.description);
        assert!(
            spec.description.contains("POSIX sh互換"),
            "{}",
            spec.description
        );
        assert!(
            !spec.description.contains("PowerShell"),
            "{}",
            spec.description
        );
        let command_description = spec
            .input_schema
            .pointer("/properties/command/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            command_description.contains("`sh -c`"),
            "{}",
            command_description
        );
        let cwd_description = spec
            .input_schema
            .pointer("/properties/cwd/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            cwd_description.contains("/workspace"),
            "{}",
            cwd_description
        );
        assert!(
            cwd_description.contains("相対作業ディレクトリ"),
            "{}",
            cwd_description
        );
        assert!(!cwd_description.contains("ホスト"), "{}", cwd_description);
    }

    #[test]
    fn run_shell_tool_spec_keeps_default_description_for_non_tier3() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier1);

        let spec = RunShellTool.spec_for_ctx(&context);

        assert!(spec.description.contains("--net-allow-app"));
        assert!(!spec.description.contains("Incusコンテナ"));
        let command_description = spec
            .input_schema
            .pointer("/properties/command/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(command_description, "実行するシェルコマンド");
        let cwd_description = spec
            .input_schema
            .pointer("/properties/cwd/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            cwd_description,
            "ワークスペースルートからの相対作業ディレクトリ"
        );
    }

    #[tokio::test]
    async fn run_shell_warns_about_staged_writes_when_child_may_be_stale() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.staging.mode = StagingMode::Staged;
        context.shell_sees_staged_writes = false;

        let out = RunShellTool
            .call(json!({ "command": "echo hello" }), &context)
            .await
            .unwrap();

        assert!(
            out.content.contains("D-08 simplification"),
            "stale child views should keep the D-08 warning: {}",
            out.content
        );
    }

    #[derive(Debug)]
    struct MockVmShellExecutor;

    impl harness_core::VmShellExecutor for MockVmShellExecutor {
        fn exec(
            &self,
            _cmd: &str,
            _cwd: &std::path::Path,
            _env: &[(String, String)],
            _timeout: std::time::Duration,
        ) -> Result<(String, String, Option<i32>), String> {
            Ok(("hello from tier3".to_string(), String::new(), Some(0)))
        }
    }

    #[tokio::test]
    async fn run_shell_suppresses_staged_warning_when_tier3_cifs_sees_staged_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.staging.mode = StagingMode::WorkspaceCommit;
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);
        context.shell_sees_staged_writes = true;
        context.vm_sandbox = Some(Arc::new(MockVmShellExecutor));

        let out = RunShellTool
            .call(json!({ "command": "echo hello" }), &context)
            .await
            .unwrap();

        assert!(out.content.contains("hello from tier3"));
        assert!(out.content.contains("[tier: tier3]"));
        assert!(
            !out.content.contains("D-08 simplification"),
            "Tier3+CIFS live-sharing should not emit the stale-write warning: {}",
            out.content
        );
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
            out.content.contains("[shell: pwsh(tier1)]")
                || out.content.contains("[shell: powershell5.1(tier1)]")
        );
        assert!(out.content.contains("[tier: tier1]"));
    }

    /// Phase5-H回帰テスト: `cmd /c exit 7`単体（ネイティブコマンドの終了コード）が、
    /// PowerShellプロセス自身の終了コードへ正しく伝播すること。修正前は`0`でも`7`でもなく
    /// 常に`1`へブール化されていた（実機確認済み、モジュールdoc「Phase5-H実測」参照）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_propagates_native_exit_code_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        let out = tool
            .call(
                json!({ "command": "cmd /c exit 7" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(out.is_error);
        assert!(out.content.contains("[exit code: 7]"), "{}", out.content);
    }

    /// Phase5-H回帰テスト: 成功時（exit 0）が壊れないこと。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_native_success_exit_code_stays_zero() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        let out = tool
            .call(
                json!({ "command": "cmd /c exit 0" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(out.content.contains("[exit code: 0]"), "{}", out.content);
    }

    /// Phase5-G回帰テスト: 日本語（非ASCII）を含む既存ファイルの内容を読み出す出力が文字化け
    /// （U+FFFD等）せずそのまま返ること。修正前はコンソール既定コードページ（CP932想定）と
    /// われわれの`from_utf8_lossy`読取りが食い違い、非ASCII出力が破壊されていた。
    ///
    /// **既知の残存限界**: この回帰テストはASCIIのみのコマンド文字列（`Get-Content`）が
    /// 非ASCIIファイル内容を読み出すケースに限定している。モデルが日本語literalを
    /// `run_shell`の`command`文字列自体に直接埋め込むケース（例:
    /// `Write-Output 'こんにちは'`）は別の問題（`-Command -`のstdin経由スクリプト読取り側の
    /// コードページ）で、実機確認では出力側の修正だけでは直らなかった（`docs/bugs/`参照）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_returns_japanese_file_content_without_mojibake() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("japanese.txt");
        std::fs::write(&file_path, "こんにちは日本語テスト").unwrap();
        let tool = RunShellTool;
        let out = tool
            .call(
                json!({ "command": format!("Get-Content -Raw '{}'", file_path.display()) }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(
            out.content.contains("こんにちは日本語テスト"),
            "{}",
            out.content
        );
        assert!(!out.content.contains('\u{FFFD}'), "{}", out.content);
    }

    // **調査メモ（Phase5-G、`command`文字列自体への日本語literal直接埋め込み）**:
    // `Write-Output 'こんにちは世界'`のようにモデルが日本語literalを`command`へ直接書く
    // ケースは、実LMStudio E2E（`huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp`、
    // Tier1、`docs/bugs/BUG-030.md`参照）で正しく`こんにちは世界`が返ることを確認した。
    // 一方、同じ入力を`cargo test`経由のユニットテストとして実行すると、`cargo run`で
    // ビルドした`harness.exe`を直接起動した場合とは異なり毎回確実に文字化けする
    // （`cargo test`のプロセス起動コンテキスト固有の再現しない挙動、原因未特定）。
    // 実挙動（E2E）と食い違う不安定なユニットテストを残すよりはbugドキュメントへの記録に
    // 留める方が誠実と判断し、ここには追加しない。

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
    async fn run_shell_tier1_rejects_write_outside_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let outside = std::env::temp_dir().join("harness-m12-outside-test.txt");
        let _ = std::fs::remove_file(&outside);
        let tool = RunShellTool;
        let command = format!(
            "Set-Content -Path '{}' -Value 'blocked' -ErrorAction Stop",
            outside.display()
        );
        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(
            out.is_error,
            "write outside the low-IL cwd should fail: {}",
            out.content
        );
        assert!(!outside.exists());
    }

    /// Tier2a（AppContainer）の隔離セマンティクスを決定論的に検証する（LLM非依存、絶対パスを
    /// 使いモデルのCWD混乱を排除する）。実際にpreflight（プロファイル作成＋再帰ACL付与＋
    /// smoke-test起動）を走らせ、Tier2aが選択できなかった環境（AppContainer不可）ではskipする。
    /// 実行にはWindows実機＋（この開発機では）管理者権限が要る（`sudo cargo test`）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier2a_contains_writes_and_reads() {
        use harness_core::{RequireSandbox, ShellTier};

        let dir = tempfile::tempdir().unwrap();
        // 実Tier2a preflightを走らせる（`opt_in_Tier2a=true`）。AppContainer不可の環境では
        // Tier1へ降格するので、その場合はテストをskipする（CIやAppContainer無効環境向け）。
        let selection =
            harness_sandbox::select_tier(
                RequireSandbox::None,
                dir.path(),
                false,
                false,
                &[],
                None,
                &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            )
            .unwrap();
        if selection.tier != ShellTier::Tier2a {
            eprintln!(
                "skipping Tier2a test: preflight downgraded to {} ({:?})",
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
            "in-workspace write should succeed under Tier2a: {}",
            out.content
        );
        assert!(
            inside.exists(),
            "in-workspace file was not created: {}",
            out.content
        );
        assert!(out.content.contains("[tier: tier2a]"), "{}", out.content);

        // (b) ワークスペース外への書込 → 拒否され、ファイルは作られない（範囲外書込の物理拒否）。
        let outside = std::env::temp_dir().join("harness-Tier2a-outside.txt");
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
            "out-of-workspace write should fail under Tier2a: {}",
            out.content
        );
        assert!(!outside.exists());

        // (c) T-04: ワークスペース外の機密ファイルのread → 拒否される（Tier1なら読めてしまう
        //     既知の欠陥がTier2aでは直る、という差分。実`~/.ssh`は使わずダミーで同じ性質を再現）。
        let secret = std::env::temp_dir().join("harness-Tier2a-secret.txt");
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
            "Tier2a must not read outside-workspace secrets (T-04): {}",
            out.content
        );
    }

    /// アプリ単位network制御（軸1、D-10/D-11）の実機E2E。Tier2a配下で、許可リストに一致する
    /// 単一コマンドは`internetClient`が付与されて外向き接続に成功し、それ以外
    /// （不一致・連鎖）はcapability空のまま`WSAEACCES`相当で失敗することを確認する
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md` §10 検証計画1/2/3）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier2a_net_allow_app_grants_and_denies_network() {
        use harness_core::{NetAppPolicy, RequireSandbox, ShellTier};

        let dir = tempfile::tempdir().unwrap();
        let selection =
            harness_sandbox::select_tier(
                RequireSandbox::None,
                dir.path(),
                false,
                false,
                &[],
                None,
                &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            )
            .unwrap();
        if selection.tier != ShellTier::Tier2a {
            eprintln!(
                "skipping Tier2a net-allow-app test: preflight downgraded to {} ({:?})",
                selection.tier.label(),
                selection.reason
            );
            return;
        }

        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = selection;
        // This E2E is specifically for --net-allow-app / internetClient capability.
        // Domain policy has precedence and intentionally suppresses app-level grants.
        ctx.net_proxy.domain_policy_enabled = false;
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
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let tool = RunShellTool;

        let command = format!(
            "curl.exe -s -w 'ALLOWED_STATUS=%{{http_code}}' http://localhost:{target_port}/; \
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
            out.content.contains("[net-proxy: ALLOW localhost]"),
            "audit log should record the allowed request: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-proxy: DENY notallowed.invalid.example]"),
            "audit log should record the denied request: {}",
            out.content
        );
        assert!(
            out.content.contains("hello"),
            "curl should receive the allowed response body: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn run_shell_net_proxy_starts_fake_dns_diagnostic_agent() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let tool = RunShellTool;

        let out = tool
            .call(
                json!({ "command": "Write-Output $env:HARNESS_FAKE_DNS_ADDR" }),
                &context,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("127.0.0.1:"),
            "fake DNS diagnostic address should be injected into child env: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-fakedns: diagnostic-only addr=127.0.0.1:"),
            "run_shell footer should describe the fake DNS diagnostic agent: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn run_shell_uses_session_scoped_proxy_and_fake_dns_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["example.com".to_string()],
            proxy_addr: Some("127.0.0.1:18080".parse().unwrap()),
            fake_dns_addr: Some("127.0.0.1:18053".parse().unwrap()),
            audit_log_path: Some(dir.path().join("net-audit.jsonl")),
            ..Default::default()
        };
        let tool = RunShellTool;

        let out = tool
            .call(
                json!({
                    "command": "Write-Output $env:ALL_PROXY; Write-Output $env:HARNESS_FAKE_DNS_ADDR"
                }),
                &context,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("socks5h://127.0.0.1:18080"),
            "session proxy address should be injected: {}",
            out.content
        );
        assert!(
            out.content.contains("127.0.0.1:18053"),
            "session Fake DNS address should be injected: {}",
            out.content
        );
        assert!(
            out.content.contains("[net-proxy-audit:"),
            "session proxy footer should still point at the JSONL audit log: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-fakedns: diagnostic-only addr=127.0.0.1:18053]"),
            "session Fake DNS footer should describe the diagnostic agent: {}",
            out.content
        );
    }
}
