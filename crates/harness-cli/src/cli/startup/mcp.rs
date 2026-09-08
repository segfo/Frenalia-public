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
//!
//! ## Streamable HTTPはこの手順の2〜4を通らない（M15.6、D-50）
//!
//! HTTPサーバはharness本体が喋るので、AppContainerプロファイルも専用プロキシもWFPフィルタも
//! 存在しない。統制は**接続前に済んでいる**——ユーザ層オプトイン・宛先allowlist・平文の可否
//! （D-49、`McpRuntime::plan`が判定）と承認台帳（D-39）である。したがってこのモジュールは
//! 承認済み宣言をトランスポートで振り分け、stdioだけをTier2aのゲートと2〜4へ通す。

use std::path::Path;

use harness_mcp::{
    ApprovalStore, McpGates, McpRuntime, McpServerDecl, McpTransportKind, PreparedServer,
    SkippedServer,
};

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
    ///
    /// 落とすかどうかの判断は`PreparedIsolation::needs_wfp_egress_enforcement`が持つ。
    /// networkを要求していないstdioサーバはcapabilityが空でソケットを作れないので残り、
    /// **Streamable HTTPサーバも残る**——WFPは元からこの経路に関係しない（D-50）。
    pub(super) fn drop_servers_needing_egress_enforcement(&mut self) {
        let mut kept = Vec::new();
        for server in std::mem::take(&mut self.prepared) {
            if !server.isolation.needs_wfp_egress_enforcement() {
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
                .filter_map(|s| s.isolation.profile_name())
                .collect();
            self.netfilter_entries
                .retain(|e| live.contains(e.profile.as_str()));
        }
    }
}

/// 手順1〜3。**プロセスはまだ起こさない。**
pub(super) async fn prepare_mcp_servers(
    decls: &[McpServerDecl],
    gates: &McpGates,
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
    let mut plan = McpRuntime::plan(decls, &store.load(), gates);

    // **宣言の欄が増えて承認が失効したことは、聞き直す前に言う**
    // （`harness_mcp::DECL_FORMAT_VERSION`）。これが無いと、対話では「なぜまた聞かれるのか」、
    // ヘッドレスでは「昨日まで動いていたサーバが黙って起動しなくなった」になる。
    // **サーバごとではなく1回**——理由は全サーバで同じで、繰り返すと本人が宣言を書き換えた
    // 場合との区別が付かない文言が人数分並ぶ。
    if let Some(notice) = plan.format_upgrade_notice() {
        eprintln!("warning: {notice}");
    }

    // 承認経路2（起動時プロンプト）。ヘッドレスでは呼ばない——`DESIGN.md` §パーミッションの
    // 「ヘッドレス時はプロンプトになるものを既定で自動拒否」と同じ規則。
    if interactive {
        crate::cli::mcp_cmd::prompt_for_unapproved(&mut plan, decls, &store);
    }
    startup.skipped = plan.skipped;

    // トランスポートで振り分ける（モジュールdoc）。HTTPは隔離の実体が無いので、
    // Tier2aのゲートも専用プロキシもWFPも通らない（D-50）。
    let (http_decls, stdio_decls): (Vec<_>, Vec<_>) = plan
        .approved
        .into_iter()
        .partition(|d| d.transport == McpTransportKind::StreamableHttp);

    for decl in http_decls {
        match McpRuntime::prepare_http(&decl, gates) {
            Ok(prepared) => startup.prepared.push(prepared),
            // `plan`が同じゲートを既に通しているのでここへ来るのは異常系だが、
            // 落ちるなら起動せずに理由を出す。
            Err(reason) => startup.skipped.push(SkippedServer {
                id: decl.id,
                reason,
            }),
        }
    }

    // P-05（`DESIGN-MCP.md` §3.4）: 隔離機構が無い環境では**stdioの**MCPサーバを起動しない。
    // 「隔離できないので素通しで起動する」という降格は用意しない。
    if !cfg!(windows) || shell_tier != harness_core::ShellTier::Tier2a {
        for decl in stdio_decls {
            startup.skipped.push(SkippedServer {
                id: decl.id,
                reason: harness_mcp::SkipReason::IsolationUnavailable(format!(
                    "stdio mcp servers require Tier2a (Windows AppContainer); the current shell \
                     isolation tier is {}",
                    shell_tier.label()
                )),
            });
        }
        return startup;
    }

    #[cfg(windows)]
    for decl in stdio_decls {
        // [BUG-085] `sandbox::prepare`は**同期**である。ACL書込に加えて、内部で
        // `grant_job::wait_until_done()`（`std::thread::sleep`で最大300秒回る）を通るため、
        // この`async fn`から直接呼ぶとtokioのワーカースレッドを待ち時間ぶん専有する。
        // `run_shell`側（`harness-tools`の`run_windows_tier2a`）は同じ関数を
        // `spawn_blocking`で包む規約を持っていたが、この経路には届いていなかった。
        let decl_for_prepare = decl.clone();
        let workspace_for_prepare = workspace_root.to_path_buf();
        let prepare_result = tokio::task::spawn_blocking(move || {
            harness_mcp::sandbox::prepare(&decl_for_prepare, &workspace_for_prepare)
        })
        .await;
        let prepare_result = match prepare_result {
            Ok(result) => result,
            Err(join_err) => {
                startup.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason: harness_mcp::SkipReason::IsolationUnavailable(format!(
                        "the appcontainer preflight task for this server panicked: {join_err}"
                    )),
                });
                continue;
            }
        };
        let mut prepared = match prepare_result {
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
            profile: prepared
                .isolation
                .profile_name()
                .unwrap_or_default()
                .to_string(),
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
                    prepared.set_proxy_addr(proxy.addr);
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
    #[cfg(windows)] spawn_daemon: Option<&harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
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

    // トランスポート種別で本番の実装を振り分ける唯一の場所（`DefaultTransportFactory`）。
    #[cfg(windows)]
    let factory = match spawn_daemon {
        Some(daemon) => harness_mcp::DefaultTransportFactory::with_spawn_daemon(daemon.clone()),
        None => harness_mcp::DefaultTransportFactory::default(),
    };
    #[cfg(not(windows))]
    let factory = harness_mcp::DefaultTransportFactory::default();
    let runtime = McpRuntime::start(
        prepared,
        &factory,
        env!("CARGO_PKG_VERSION"),
        &mut skipped,
    );

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
