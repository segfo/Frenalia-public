//! [決定69(1)(4)] **Tier2a の通信の許可はどこから来るか**を1か所で決める。
//!
//! # 何のためにあるのか
//!
//! 2026-10-07 まで、`harness.exe`がセッションの中継プロキシへ渡す宛先は`settings.json`の
//! `net.allow_domains`＋`--net-allow-domain`だった。ポリシーエディタが`policy.json`へ書いた
//! 入口のドメインの`net`は、エディタのパス2の中でしか効かなかった（決定64の暫定）。
//!
//! 決定69で**Tier2a はこの出どころを`policy.json`の承認済みの宣言＋`--net-allow-domain`だけにした**。
//! `settings.json`の`net.allow_domains`は Tier2a には効かない（ほかの Tier は作業の一覧の P8 で決め直す）。
//!
//! | 出どころ | Tier2a | ほかの Tier |
//! |---|---|---|
//! | `policy.json`の入口のドメインの`net`（このマシンで承認済み） | **効く** | 効かない（読まない） |
//! | `--net-allow-domain`（その起動だけの一時的な許可。決定69(4)） | 効く | 効く |
//! | `settings.json`の`net.allow_domains` | **効かない**（P8 で決め直す） | 効く |
//!
//! # 2つの入口が同じこれを通る（`B-06`）
//!
//! `harness.exe`の起動（`startup::sandbox`）と`harness prompt`（`cli::workspace_cmd`。モデルへ送る
//! システムプロンプトの下見）が同じ宛先を組む。別々に組むと、**下見と実セッションで見える制約が食い違う**
//! ——下見はそのために在るので、食い違えば道具としての意味が無い。

use std::path::Path;

use harness_sandbox::tier2a::policy_fs::DomainNet;

/// 入口（セッション）の中継プロキシと名前解決の代役。**セッション中は持ち続けること**——
/// `drop`するとaccept loopが止まり、入口の子の通信が全部落ちる。
///
/// 2026-10-07に`run_agent`から**そのまま移した**（P7.6 で起動の手順が増えて本体が上限を超えたため）。
pub(crate) struct SessionAgents {
    /// **読まないが持つ**——`drop`でaccept loopが止まるので、セッション中はここで生かしておく。
    #[allow(dead_code)]
    proxy: Option<harness_tools::net_proxy::LocalProxy>,
    /// 同上（名前解決の代役）。
    #[allow(dead_code)]
    fake_dns: Option<harness_tools::fake_dns::FakeDnsAgent>,
    proxy_addr: Option<std::net::SocketAddr>,
    fake_dns_addr: Option<std::net::SocketAddr>,
}

impl SessionAgents {
    /// WFPのdefault-denyに開けるloopbackの穴（立った分だけ）。
    pub(crate) fn loopback_ports(&self) -> harness_tools::net_proxy::NetLoopbackPorts {
        harness_tools::net_proxy::net_loopback_ports_for_agents(self.proxy_addr, self.fake_dns_addr)
    }
}

/// 入口の中継プロキシと名前解決の代役を起こし、立った宛先を`net_proxy`へ書き戻す。
///
/// **立たなくても起動は止めない**（通信が閉じるだけで、閉じたことは`run_shell`の出力が言う）。
pub(crate) async fn start_session_agents(
    net_proxy: &mut harness_core::NetProxyConfig,
    tier: harness_core::ShellTier,
) -> SessionAgents {
    let session_proxy = if net_proxy.domain_policy_enabled {
        match harness_tools::net_proxy::spawn_local_proxy(net_proxy).await {
            Ok(Some(proxy)) => {
                net_proxy.proxy_addr = Some(proxy.addr);
                Some(proxy)
            }
            Ok(None) => None,
            Err(e) => {
                if tier == harness_core::ShellTier::Tier2a {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; Tier2a domain \
                         enforcement will remain fail-closed instead of opening network: {e}"
                    );
                } else {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; run_shell will try \
                         a per-command proxy instead: {e}"
                    );
                }
                None
            }
        }
    } else {
        None
    };
    let session_fake_dns = if net_proxy.domain_policy_enabled {
        match harness_tools::fake_dns::spawn_fake_dns(&harness_tools::fake_dns::FakeDnsConfig {
            allow_domains: net_proxy.allow_domains.clone(),
            policy_required: net_proxy.domain_policy_enabled,
            audit_log_path: net_proxy.audit_log_path.clone(),
            preferred_port: Some(53),
        })
        .await
        {
            Ok(agent) => {
                net_proxy.fake_dns_addr = Some(agent.addr);
                Some(agent)
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to start session-scoped Fake DNS diagnostic agent; run_shell \
                     will try a per-command Fake DNS agent instead: {e}"
                );
                None
            }
        }
    } else {
        None
    };
    SessionAgents {
        proxy: session_proxy,
        fake_dns: session_fake_dns,
        proxy_addr: net_proxy.proxy_addr,
        fake_dns_addr: net_proxy.fake_dns_addr,
    }
}

/// 入口のシェルが使える通信の宛先と、使えなかった宣言の説明。
#[derive(Debug)]
pub(crate) struct EntryDestinations {
    /// 中継プロキシと名前解決へ渡す宛先（正規化済み・重複なし）。
    pub(crate) allow_domains: Vec<String>,
    /// **使えなかった宣言**（未承認・解釈できない）。呼び出し側は必ず出すこと（`B-10`）。
    pub(crate) warnings: Vec<String>,
}

/// 入口のドメインの通信（[`DomainNet`]）と`--net-allow-domain`から宛先を組む。
///
/// 正規化は`harness.exe`が`settings.json`に掛けているのと同じ関数（`normalize_domain_pattern`）を通す
/// ——通さずに渡すと`DomainPolicy::new`が解釈できない値を黙って捨てる（`B-10`）。
/// `policy.json`の値は`policy_fs::domain_net`が解釈を確かめているので、ここで落ちるのは
/// `--net-allow-domain`の綴りだけである（落ちたら起動を止める＝`Err`）。
pub(crate) fn entry_destinations(
    entry_net: &DomainNet,
    cli_values: &[String],
) -> Result<EntryDestinations, String> {
    let mut allow_domains: Vec<String> = Vec::new();
    for value in entry_net.allow_domains.iter().chain(cli_values) {
        let normalized = harness_core::normalize_domain_pattern(value)
            .map_err(|e| format!("invalid network domain policy: `{value}`: {e}"))?;
        if !allow_domains.contains(&normalized) {
            allow_domains.push(normalized);
        }
    }
    let warnings = entry_net
        .skipped
        .iter()
        .map(|skipped| {
            format!(
                ".harness/policy.json declares the destination {} for the entry domain, but it is \
                 not used this session: {}",
                skipped.value,
                skipped.reason.describe()
            )
        })
        .collect();
    Ok(EntryDestinations {
        allow_domains,
        warnings,
    })
}

/// [決定69(1)] `--require-sandbox=confidential`と`policy.json`の通信の宣言が矛盾していれば、その理由。
///
/// confidential は「外部へ持ち出す経路を作らない」モードなので、**宛先を1つでも開く宣言と両立しない**。
/// `settings.json`と`--net-allow-domain`は`stage_prepare_sandbox`の別の検査が見ているが、**宣言の側を
/// 見ないと穴が残る**（#30 がファイルの宣言で同じ検査を広げたのと同じ形）。
///
/// 遷移先のドメインの宣言も数える——出口（専用の中継プロキシ）を与えるのはこの起動自身である。
/// **判定を分けない**: 入口だけ見ると、遷移先のドメインの宛先が confidential のもとで開く。
pub(crate) fn confidential_conflict(
    require_sandbox: harness_core::RequireSandbox,
    entry_net: &DomainNet,
    domains_net: &[(String, DomainNet)],
) -> Option<String> {
    if require_sandbox != harness_core::RequireSandbox::Confidential {
        return None;
    }
    let mut declared: Vec<&str> = entry_net
        .allow_domains
        .iter()
        .map(String::as_str)
        .collect();
    for (_, net) in domains_net {
        declared.extend(net.allow_domains.iter().map(String::as_str));
    }
    if declared.is_empty() {
        return None;
    }
    Some(format!(
        "network destinations declared in .harness/policy.json ({}) conflict with          --require-sandbox=confidential (confidential mode denies all outbound network          unconditionally; refusing to start rather than silently ignoring the declaration or          weakening the confidentiality guarantee)",
        declared.join(", ")
    ))
}

/// `policy.json`と承認台帳をその場で読んで[`entry_destinations`]を組む（`harness prompt`の下見用）。
///
/// **起動の経路はこちらを使わない**——あちらは`policy.json`を起動時に1回だけ読み、その値を使う（`B-13`）。
/// 読めない`policy.json`は「宣言が無い」として扱う（下見なので起動は止めない。実セッションは
/// `stage_prepare_sandbox`が Tier2a を要求していれば止める）。
pub(crate) fn entry_destinations_from_workspace(
    workspace_root: &Path,
    cli_values: &[String],
) -> Result<EntryDestinations, String> {
    let entry_net = harness_policy::policy_file::load_for_session(workspace_root, &[])
        .ok()
        .and_then(|policy| {
            let approvals =
                harness_sandbox::tier2a::policy_approval::PolicyApprovalStore::in_config_dir()
                    .load();
            let key =
                harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
            policy
                .domain(harness_policy::policy_file::ENTRY_DOMAIN)
                .map(|entry| {
                    harness_sandbox::tier2a::policy_fs::domain_net(entry, &|d| {
                        approvals.is_approved_for_key(&key, d)
                    })
                })
        })
        .unwrap_or_default();
    entry_destinations(&entry_net, cli_values)
}

#[cfg(test)]
#[path = "net_sources_tests.rs"]
mod net_sources_tests;
