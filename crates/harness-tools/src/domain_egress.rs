//! [決定69] **ドメインごとの出口**——通信を宣言したドメインに、専用の中継プロキシ・`internetClient`・
//! WFPの項目を与える（`plans/POLICY-EDITOR-TOMOYO-DIG.md` の決定69、手順は `plans/position-domains/P7.md`）。
//!
//! # 何のためにあるのか
//!
//! 通信の出口は**2つの機構が対で**閉じている——AppContainerの`internetClient` capability（ソケットを作れるか）と
//! WFPの既定拒否（どこへ繋げるか）である。**片方だけ与えると素通しになる**（`internetClient`を持ったまま
//! 既定拒否を失う形は`harness_sandbox::tier2a::wfp`のdocが既知の欠陥として書いている）。だから
//! 決定65の暫定(b) では「通信を宣言するドメインは用意しない」と断っていた。
//!
//! ここはその2つを**順番に**組み立てる場所である。雛形はMCPサーバの隔離（D-38、`plans/DESIGN-MCP.md` §3.2）で、
//! サーバごとに専用プロキシを立て、そのサーバのpackage SIDを条件にしたWFPの項目でそのプロキシのポートだけを許す。
//!
//! # 順序が本質である
//!
//! ```text
//! 1. start_domain_egress()  ドメインごとに中継プロキシを立てる（まだ誰も通信できない）
//! 2. netfilter_entries()    立ったプロキシのポートだけを許すWFPの項目を作る
//! 3. （呼び出し側）          WFPを適用する
//! 4a. attach()   立った ⇒ `internetClient`とプロキシの宛先を遷移先の表へ積む
//! 4b. drop_all() 立たない ⇒ 何も積まずにプロキシを畳む（**出口を持たせない**）
//! ```
//!
//! 4を3より前に置くと、**既定拒否が効くまでの間だけ`internetClient`を持った子が走れる**窓ができる。
//! だから[`EgressPlan::attach`]は「WFPが立った」ことを呼び出し側が知っている場所でだけ呼ぶ——
//! 立たなかった回に[`EgressPlan::drop_all`]を呼ぶのが対である（`B-01`: 対の片方だけ書かない）。
//!
//! # 許可ポートが空の項目を作らない（前例の(2)）
//!
//! `WfpSession::apply`は許可ポートがTCP・UDPとも空だと`NoAddressesResolved`で**失敗**し、
//! `netfilterd`は1件の失敗で**全部の項目**を失敗させる（セッションの出口ごと落ちる）。だから
//! [`EgressPlan::netfilter_entries`]は、プロキシが立ったドメインの項目しか作らない。
//!
//! # ここが持たないもの（限界）
//!
//! - **宛先の単位はホスト名である**（中継プロキシの`evaluate_host`）。ポート・IPアドレスで縛る形は持たない。
//! - **プロキシを通らない通信は、ここでは止まらない**——止めるのはWFPの既定拒否である（`internetClient`を
//!   積むのはWFPが立った回だけ、という上の順序がその担保）。
//! - 名前解決の代役（Fake DNS）はドメインごとに立てない（MCPサーバと同じ）。名前解決は中継プロキシに任せる。

use std::net::SocketAddr;
use std::path::PathBuf;

use harness_core::{DomainPolicy, NetProxyConfig};

use crate::net_proxy::LocalProxy;

/// 1ドメインぶんの「出口を作ってほしい」要求。
#[derive(Debug, Clone)]
pub struct DomainEgressRequest {
    /// `policy.json`のドメインの名前（監査の印とプロキシの持ち主）。
    pub domain: String,
    /// そのドメインのAppContainerプロファイルの名前（WFPの項目の条件。`DomainSpec::name`）。
    pub profile: String,
    /// このマシンで承認済みの宛先（`policy.json`の綴りのまま。正規化はここで通す）。
    pub allow_domains: Vec<String>,
}

/// 立った出口1つ。
#[derive(Debug, Clone)]
pub struct DomainEgress {
    pub domain: String,
    pub profile: String,
    /// 中継プロキシの待受（loopback）。
    pub addr: SocketAddr,
    /// このドメインの子へ渡す環境変数（`net_proxy::proxy_env_vars`と同じ組み立て。Fake DNSは持たない）。
    pub env: Vec<(String, String)>,
}

/// [`start_domain_egress`]の結果。**セッション中は持ち続けること**——`drop`するとプロキシのaccept loopが
/// 止まり、そのドメインの通信が全部落ちる（MCPの`McpStartup::proxies`と同じ理由）。
pub struct EgressPlan {
    egress: Vec<DomainEgress>,
    failed: Vec<(String, String)>,
    proxies: Vec<LocalProxy>,
}

impl EgressPlan {
    /// 立った出口（`policy.json`のドメインの名前の順）。
    pub fn egress(&self) -> &[DomainEgress] {
        &self.egress
    }

    /// 立てられなかったドメインと理由。**呼び出し側は必ず出すこと**（`B-10`: 黙って落とすと、
    /// 宣言したのに通信できない理由が画面のどこにも出ない）。
    pub fn failed(&self) -> &[(String, String)] {
        &self.failed
    }

    /// 1つも立たなかった（出口を持つドメインが無い）。
    pub fn is_empty(&self) -> bool {
        self.egress.is_empty()
    }

    /// そのドメインの中継プロキシの待受（立っていなければ`None`）。
    pub fn addr_of(&self, domain: &str) -> Option<SocketAddr> {
        self.egress
            .iter()
            .find(|e| e.domain == domain)
            .map(|e| e.addr)
    }

    /// WFPへ渡す項目（モジュールdocの手順2）。**立ったプロキシのポートだけ**を許す項目を作る。
    ///
    /// 空の許可ポートの項目は作らない（前例の(2)。`WfpSession::apply`が断り、`netfilterd`が全体を落とす）。
    /// UDPは開けない——中継プロキシはTCPだけを待ち受ける（Fake DNSはドメインごとに立てない）。
    #[cfg(windows)]
    pub fn netfilter_entries(
        &self,
    ) -> Vec<harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy> {
        self.egress
            .iter()
            .map(
                |e| harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy {
                    profile: e.profile.clone(),
                    allow_loopback_tcp_ports: vec![e.addr.port()],
                    allow_loopback_udp_ports: Vec::new(),
                },
            )
            .collect()
    }

    /// **WFPが立った後に**、出口を持つドメインの表へ`internetClient`とプロキシの宛先を積む（手順4a）。
    ///
    /// 戻り値は積んだドメインの名前。表に無いドメイン（用意できなかった）は飛ばす——出口だけ作っても
    /// 使う子が居ない。**同じSIDを2つ積まない**（`SECURITY_CAPABILITIES`に重複があると
    /// `CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ちる。`spawnd::child_plan`の`capabilities_for`と同じ注意）。
    pub fn attach(
        &self,
        domains: &mut [harness_sandbox::tier2a::spawnd::DomainSpec],
    ) -> Vec<String> {
        let mut attached = Vec::new();
        for egress in &self.egress {
            let Some(spec) = domains
                .iter_mut()
                .find(|d| d.policy_domain == egress.domain)
            else {
                continue;
            };
            if !spec
                .capability_sids
                .iter()
                .any(|sid| sid.eq_ignore_ascii_case(harness_sandbox::tier2a::INTERNET_CLIENT_SID))
            {
                spec.capability_sids
                    .push(harness_sandbox::tier2a::INTERNET_CLIENT_SID.to_string());
            }
            spec.proxy_env = egress.env.clone();
            attached.push(egress.domain.clone());
        }
        attached
    }

    /// **WFPが立たなかったときに全部畳む**（手順4b）。戻り値は（ドメイン, 理由）で、呼び出し側が出す。
    ///
    /// 畳むのは「出口を持たせない」ためである——`internetClient`を積まないだけでは、
    /// 立てたプロキシが待ち受けたまま残る（誰も繋げないが、資源を持ち続ける）。
    pub fn drop_all(&mut self, reason: &str) -> Vec<(String, String)> {
        let dropped: Vec<(String, String)> = self
            .egress
            .drain(..)
            .map(|e| (e.domain, reason.to_string()))
            .collect();
        self.proxies.clear();
        dropped
    }
}

/// ドメインごとに中継プロキシを立てる（モジュールdocの手順1）。
///
/// `record_all`が真なら、どのドメインのプロキシも**全部の宛先を通して記録する**
/// （決定64の記録モード。ポリシーエディタのパス2だけが使う）。偽なら承認済みの宛先だけを通す。
///
/// 宛先は`harness_core::normalize_domain_pattern`へ通す——`DomainPolicy::new`は解釈できない値を
/// 黙って捨てるので、そのまま渡すと宣言の一部が消えたまま「宣言どおりに走った」と出る（`B-10`）。
/// 解釈できない値は**そのドメインの出口を作らない**側へ倒す（`policy_fs::domain_net`が先に落としているので、
/// ここへ来るのは通常その値が無い場合だけである）。
pub async fn start_domain_egress(
    wanted: &[DomainEgressRequest],
    audit_log_path: Option<PathBuf>,
    record_all: bool,
) -> EgressPlan {
    let mut plan = EgressPlan {
        egress: Vec::new(),
        failed: Vec::new(),
        proxies: Vec::new(),
    };
    for request in wanted {
        if request.allow_domains.is_empty() {
            // 宛先が無いドメインには出口を作らない（空の許可ポートの項目も作らない。前例の(2)）。
            continue;
        }
        let mut normalized = Vec::new();
        let mut rejected = Vec::new();
        for value in &request.allow_domains {
            match harness_core::normalize_domain_pattern(value) {
                Ok(pattern) if !normalized.contains(&pattern) => normalized.push(pattern),
                Ok(_) => {}
                Err(detail) => rejected.push(format!("{value}: {detail}")),
            }
        }
        if !rejected.is_empty() {
            plan.failed.push((
                request.domain.clone(),
                format!(
                    "this domain declares destinations that cannot be interpreted, so it gets no \
                     egress at all: {}",
                    rejected.join("; ")
                ),
            ));
            continue;
        }
        let config = NetProxyConfig {
            allow_domains: normalized.clone(),
            domain_policy_enabled: true,
            // WFPはこの後で立てる（立たなければ`drop_all`で畳む）。この値はプロキシ自身の判定に使われない。
            enforced_by_wfp: false,
            audit_log_path: audit_log_path.clone(),
            proxy_addr: None,
            fake_dns_addr: None,
            tls_inspection: harness_core::TlsInspection::Sni,
        };
        let policy = if record_all {
            DomainPolicy::record_all()
        } else {
            DomainPolicy::new(normalized)
        };
        match crate::net_proxy::spawn_local_proxy_for_domain(
            &config,
            policy,
            Some(request.domain.clone()),
        )
        .await
        {
            Ok(Some(proxy)) => {
                let addr = proxy.addr;
                plan.proxies.push(proxy);
                plan.egress.push(DomainEgress {
                    domain: request.domain.clone(),
                    profile: request.profile.clone(),
                    addr,
                    // 名前解決の代役は渡さない（ドメインごとには立てないので`None`）。
                    env: crate::net_proxy::proxy_env_vars(Some(addr), None),
                });
            }
            // `domain_policy_enabled`は常に真なので`Ok(None)`は来ないが、**来たら出口なしへ倒す**。
            Ok(None) => plan.failed.push((
                request.domain.clone(),
                "the dedicated egress proxy was not started (domain policy disabled); this domain \
                 gets no egress"
                    .to_string(),
            )),
            Err(e) => plan.failed.push((
                request.domain.clone(),
                format!("could not start the dedicated egress proxy ({e}); this domain gets no egress"),
            )),
        }
    }
    plan
}

#[cfg(test)]
#[path = "domain_egress_tests.rs"]
mod domain_egress_tests;
