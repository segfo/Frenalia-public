//! 起動パイプラインのMCP部分（M15.5、`plans/DESIGN-MCP.md`）。
//!
//! **この配線は順序が本質である。**
//!
//! ```text
//! 1. plan()      宣言の検証と承認照合（D-39）。未承認は起動対象から外す
//! 2. prepare()   サーバごとのAppContainerプロファイル作成 + preflight（D-38）
//! 3. proxies     network要求のあるサーバごとに専用の協調プロキシを立てる（§3.2）
//! 4. WFP         全プロファイル分の出口ポリシーを一度に適用する（呼び出し元が行う）
//! 5. launch()    実プロセス起動 + initialize/tools/list + ToolRegistryへの登録
//! ```
//!
//! 4と5を入れ替えると、**WFPが効くまでの間サーバが無制限に外へ出られる窓**ができる。
//! 1〜3をまとめた[`prepare_mcp_servers`]と、5だけを行う[`launch_mcp_servers`]に関数を割って
//! あるのはそのためで、間にWFPの適用を挟むことを呼び出し側に強制する形になっている。

use std::path::Path;

use harness_mcp::{ApprovalStore, McpRuntime, McpServerDecl, PreparedServer, SkippedServer};

use super::*;

/// [`prepare_mcp_servers`]の結果。WFP適用を挟んで[`launch_mcp_servers`]へ渡す。
pub(super) struct McpStartup {
    prepared: Vec<PreparedServer>,
    skipped: Vec<SkippedServer>,
    /// サーバ専用の協調プロキシ。**セッション中は保持し続ける必要がある**（dropすると
    /// accept loopが止まり、そのサーバの通信が全て落ちる）。
    proxies: Vec<harness_tools::net_proxy::LocalProxy>,
    /// WFPへ渡すサーバ別の出口ポリシー（D-38）。
    #[cfg(windows)]
    netfilter_entries: Vec<harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy>,
}

impl McpStartup {
    /// WFPへ渡すサーバ別ポリシー。`prepare`の後・WFP適用の前に呼ぶ。
    #[cfg(windows)]
    pub(super) fn netfilter_entries(
        &self,
    ) -> Vec<harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy> {
        self.netfilter_entries.clone()
    }

    /// WFPの出口強制が有効にならなかったとき、**networkを要求しているサーバを起動対象から外す**。
    ///
    /// WFPが無いと、`internetClient` capabilityを持つサーバは専用プロキシを無視して直接外へ
    /// 出られる。「宛先を絞ったつもりで絞れていない」状態を作るくらいなら起動しない
    /// （`run_shell`側の`should_grant_tier2a_network_capability`と同じfail-closed）。
    /// networkを要求していないサーバはcapabilityが空でソケットを作れないので、そのまま残す。
    pub(super) fn drop_servers_needing_egress_enforcement(&mut self) {
        let mut kept = Vec::new();
        for server in std::mem::take(&mut self.prepared) {
            if server.proxy_addr.is_none() {
                kept.push(server);
                continue;
            }
            self.skipped.push(SkippedServer {
                id: server.decl.id.clone(),
                reason: harness_mcp::SkipReason::StartFailed(
                    "this server requests network access, but WFP egress enforcement is not \
                     active this session; refusing to start it with unenforced network access"
                        .to_string(),
                ),
            });
        }
        self.prepared = kept;
        #[cfg(windows)]
        {
            let live: std::collections::BTreeSet<&str> = self
                .prepared
                .iter()
                .map(|s| s.profile_name.as_str())
                .collect();
            self.netfilter_entries
                .retain(|e| live.contains(e.profile.as_str()));
        }
    }
}

/// 手順1〜3。**プロセスはまだ起こさない。**
pub(super) async fn prepare_mcp_servers(
    decls: &[McpServerDecl],
    workspace_root: &Path,
    shell_tier: harness_core::ShellTier,
    interactive: bool,
    audit_log_path: Option<std::path::PathBuf>,
) -> McpStartup {
    let mut startup = McpStartup {
        prepared: Vec::new(),
        skipped: Vec::new(),
        proxies: Vec::new(),
        #[cfg(windows)]
        netfilter_entries: Vec::new(),
    };
    if decls.is_empty() {
        return startup;
    }

    let store = ApprovalStore::in_config_dir();
    let mut plan = McpRuntime::plan(decls, &store.load());

    // 承認経路2（起動時プロンプト）。ヘッドレスでは呼ばない——`DESIGN.md` §パーミッションの
    // 「ヘッドレス時はプロンプトになるものを既定で自動拒否」と同じ規則。
    if interactive {
        crate::cli::mcp_cmd::prompt_for_unapproved(&mut plan, decls, &store);
    }
    startup.skipped = plan.skipped;

    // P-05（`DESIGN-MCP.md` §3.4）: 隔離機構が無い環境ではMCPサーバを起動しない。
    // 「隔離できないので素通しで起動する」という降格は用意しない。
    if !cfg!(windows) || shell_tier != harness_core::ShellTier::Tier2a {
        for decl in plan.approved {
            startup.skipped.push(SkippedServer {
                id: decl.id,
                reason: harness_mcp::SkipReason::IsolationUnavailable(format!(
                    "mcp servers require Tier2a (Windows AppContainer); the current shell \
                     isolation tier is {}",
                    shell_tier.label()
                )),
            });
        }
        return startup;
    }

    #[cfg(windows)]
    for decl in plan.approved {
        let mut prepared = match harness_mcp::sandbox::prepare(&decl, workspace_root) {
            Ok(outcome) => {
                for warning in outcome.warnings {
                    eprintln!("warning: {warning}");
                }
                outcome.prepared
            }
            Err(e) => {
                startup.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason: harness_mcp::SkipReason::IsolationUnavailable(e.to_string()),
                });
                continue;
            }
        };

        // §3.2: network要求のあるサーバには**そのサーバ専用の**協調プロキシを立てる。
        // 宛先の粒度はここが持ち、WFPは「このSIDはこのポートだけ」を強制する。
        let mut entry = harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy {
            profile: prepared.profile_name.clone(),
            allow_loopback_tcp_ports: Vec::new(),
            allow_loopback_udp_ports: Vec::new(),
        };
        if !decl.network.is_deny() {
            let config = harness_core::NetProxyConfig {
                allow_domains: decl.network.allow_domains.clone(),
                domain_policy_enabled: true,
                audit_log_path: audit_log_path.clone(),
                ..Default::default()
            };
            match harness_tools::net_proxy::spawn_local_proxy(&config).await {
                Ok(Some(proxy)) => {
                    entry.allow_loopback_tcp_ports.push(proxy.addr.port());
                    prepared.proxy_addr = Some(proxy.addr);
                    startup.proxies.push(proxy);
                }
                Ok(None) | Err(_) => {
                    // プロキシが立たなければ統制できない。素通しにするくらいなら起動しない。
                    startup.skipped.push(SkippedServer {
                        id: decl.id.clone(),
                        reason: harness_mcp::SkipReason::StartFailed(
                            "could not start the dedicated egress proxy for this server; \
                             refusing to start it with uncontrolled network access"
                                .to_string(),
                        ),
                    });
                    continue;
                }
            }
        }
        startup.netfilter_entries.push(entry);
        startup.prepared.push(prepared);
    }

    startup
}

/// 手順5。**WFPの適用が終わってから呼ぶこと**（モジュールdoc参照）。
///
/// 起動できたサーバのツールを`tools`へ登録し、`ToolCtx`へ載せる事実を返す。
pub(super) fn launch_mcp_servers(
    startup: McpStartup,
    tools: &mut ToolRegistry,
) -> (
    McpRuntime,
    Vec<harness_core::McpServerFact>,
    Vec<harness_tools::net_proxy::LocalProxy>,
) {
    let McpStartup {
        prepared,
        mut skipped,
        proxies,
        #[cfg(windows)]
            netfilter_entries: _,
    } = startup;

    if prepared.is_empty() {
        report_skipped(&skipped);
        return (McpRuntime::default(), Vec::new(), proxies);
    }

    #[cfg(windows)]
    let runtime = McpRuntime::start(
        prepared,
        &harness_mcp::AppContainerTransportFactory,
        env!("CARGO_PKG_VERSION"),
        &mut skipped,
    );
    #[cfg(not(windows))]
    let runtime = {
        let _ = prepared;
        McpRuntime::default()
    };

    for warning in runtime.warnings() {
        eprintln!("warning: {warning}");
    }
    report_skipped(&skipped);

    let facts = runtime.facts();
    for tool in runtime.tools() {
        tools.register(tool);
    }
    if !facts.is_empty() {
        eprintln!(
            "note: mcp servers started: {}",
            runtime.server_ids().join(", ")
        );
    }
    (runtime, facts, proxies)
}

/// 起動しなかったサーバを**必ず**報告する。黙って落とすと、ユーザーは「MCPで裏取りした」
/// つもりで裏取りされていない結論を受け取ることになる（`DESIGN-COGNITION.md` §4.2）。
fn report_skipped(skipped: &[SkippedServer]) {
    for entry in skipped {
        eprintln!("warning: {}", entry.message());
    }
}
