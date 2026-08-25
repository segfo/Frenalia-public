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
//! - Windows Tier1: Restricted Token + 低IL + Job Object（`harness_sandbox::tier1::win_restricted`）。
//! - Linux Tier2b: `bwrap`でラップ（`harness_sandbox::tier2b::linux_bwrap`）。本セッションでは実機未検証
//!   （Windows専用環境、WSL2で別途再検証が必要）。
//! - Tier0（保険・全OS）: 通常spawn + Job Object(Win)/rlimit(unix) + 出力バイト上限。
//!
//! 危険構文（`-EncodedCommand`・`iex`/`Invoke-Expression`・`Start-Process`・`cmd /c`・
//! 入れ子インタプリタ）を検出したら`AcceptEdits`下でも強制的にプロンプトへ落とす
//! （T-09、`harness-engine::permission::looks_like_allowlist_bypass`）。
//!
//! # モジュール構成
//!
//! 本体が1,000行（`docs/CODE-STRUCTURE-RULES.md`規則1）を超えたため、規則3の軸1
//! （どの外部システムと話すか）で4つへ分けた。**この`mod.rs`はモデルと話す面だけを持つ**——
//! 入力スキーマ・`Tool` trait実装・結果フッタの組み立て。
//!
//! | モジュール | 話す相手 |
//! |---|---|
//! | [`net_decision`] | 誰とも話さない（アプリ単位network制御の純粋な判定、D-10/D-11） |
//! | [`env`] | 誰とも話さない（`PATH`の合成と出力バイト上限の純粋関数） |
//! | [`runner`] | Tierごとの隔離機構（Restricted Token / AppContainer / bwrap / Incus / 素のspawn） |
//! | [`platform`] | シェル実行ファイルそのもの（起動・stdinブートストラップ・コンソール符号化） |

mod env;
mod net_decision;
mod platform;
mod runner;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::time::Duration;

use harness_core::{RiskClass, ShellTier, StagingMode, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::check_relative_path;

use crate::jail_error_to_tool_error;

use env::{append_path_extra, truncate_to_limit};
use net_decision::classify_net_app;
use platform::{merge_startup_noise, split_shell_startup_noise};
use runner::run_isolated;

/// Tier1でコマンドを走らせる4番目の経路（`harness-policy-editor`の記録モード）が使う。
/// 実体と doc は[`platform`]が持つ——印や変数名の綴りを複製しないため（B-05）。
#[cfg(windows)]
pub use platform::{
    run_shell_bootstrap_stdin, RUN_SHELL_COMMAND_ENV_VAR, RUN_SHELL_OUTPUT_SENTINEL,
};

/// Tier2aでコマンドを走らせる5番目の経路（`harness-policy-editor`のパス2）が使う。
/// **同じ規則に従わせるための公開**であって、判定を作り直させないためのもの（[`net_decision`]）。
pub use net_decision::{should_grant_tier2a_network_capability, NetDecision};

#[derive(Deserialize)]
struct RunShellInput {
    command: String,
    timeout_ms: Option<u64>,
    cwd: Option<String>,
}

pub struct RunShellTool;
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
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
        env.extend(crate::net_proxy::proxy_env_vars(proxy_addr, fake_dns_addr));

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
            ctx.cow_diff_layer_dir.as_deref(),
            &ctx.shell_tier.granted_passthrough,
        )
        .await?;

        let code = code.unwrap_or(-1);
        // シェルがコマンドを走らせる前に吐いた分を切り離す（`RUN_SHELL_OUTPUT_SENTINEL`）。
        // 捨てずにフッターへ回すだけ——混ざったままだと、標準出力を持たないコマンドで
        // 「シェルの起動時警告」が唯一の出力になり、失敗と見分けが付かない。
        let (out_noise, out) = split_shell_startup_noise(&out);
        let (err_noise, err) = split_shell_startup_noise(&err);
        let mut content = truncate_to_limit(out);
        let err = truncate_to_limit(err);
        if !err.is_empty() {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&err);
        }
        content.push_str(&format!("\n[exit code: {code}]\n[shell: {shell_label}]"));
        if let Some(noise) = merge_startup_noise(&out_noise, &err_noise) {
            content.push_str(&format!(
                "\n[shell-startup-noise (コマンドの実行前にシェル自身が出したもの。\
                 コマンドの結果には影響しない): {}]",
                truncate_to_limit(noise).replace('\n', " / ")
            ));
        }
        // 着地したTierだけを出す。**「(downgraded from ...)」はもう付かない**——D-75で
        // 降格が消え、`select_tier`が返した時点で要求どおりのTierに居るためである。
        content.push_str(&format!("\n[tier: {}]", ctx.shell_tier.tier.label()));
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
            // `proxy_addr`が立っている＝`domain_policy_enabled`である（`spawn_local_proxy`は
            // 無効なら`Ok(None)`を返す）。その上で「WFP未成立」の意味はTierで正反対になる——
            // Tier2aでは`should_grant_tier2a_network_capability`がcapability自体を落とすので、
            // 「audit-only（＝通信はできるが強制されない）」ではなく通信が皆無になる。
            // 同じ誤りが起動時警告とシステムプロンプトにもあった。
            if ctx.shell_tier.tier == ShellTier::Tier2a {
                if ctx.net_proxy.enforced_by_wfp {
                    content.push_str("\n[net-proxy: enforced-by-wfp]");
                } else {
                    content.push_str(
                        "\n[net-proxy: unreachable (WFP enforcement unavailable, so Tier2a grants \
                         no network capability at all; the child cannot open any socket, not even \
                         to this proxy)]",
                    );
                }
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

#[cfg(test)]
#[path = "shell_tests.rs"]
mod shell_tests;
