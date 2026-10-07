//! [BUG-239] MCPサーバのWFPの項目は**専用プロキシが立ったサーバの分だけ**作る。
//!
//! 測っているのは「`netfilterd`が受け取る一覧に、許可ポートがTCP・UDPとも空の項目が1つも無いこと」
//! と「通信を要求したサーバの項目は、そのサーバ専用プロキシのポートだけを許すこと」の対である。
//! 前者だけだと、項目を1つも作らない（＝通信を要求したサーバの既定拒否まで消える）実装でも緑になる。
//!
//! 空の項目が1つでも混ざると、`WfpSession::apply`が`NoAddressesResolved`で断り、`netfilterd`が
//! 全部の項目を畳んで失敗させる（セッション全体のWFPが立たない）。

use super::*;

/// 宣言を設定ファイルと同じ形から作る（利用者が書く綴りを通す）。
fn decls() -> Vec<McpServerDecl> {
    harness_mcp::parse_mcp_settings(Some(&serde_json::json!({
        "servers": [
            {
                // 通信を要求しないサーバ（いちばん普通の形）。
                "id": "docs",
                "transport": "stdio",
                "command": "C:\\tools\\docs-server.exe",
                "tools": { "search": "read_only" }
            },
            {
                // 通信を要求するサーバ。専用プロキシが1つ立つ。
                "id": "web",
                "transport": "stdio",
                "command": "C:\\tools\\web-server.exe",
                "network": { "allow_domains": ["api.example.com"] },
                "tools": { "fetch": "read_only" }
            }
        ]
    })))
    .expect("the declarations parse")
}

fn decl(id: &str) -> McpServerDecl {
    decls()
        .into_iter()
        .find(|d| d.id == id)
        .expect("declared above")
}

/// `prepare_mcp_servers`が積むのと同じ形の`PreparedServer`。`proxy_port`は専用プロキシの待受
/// （`set_proxy_addr`で埋まる値。通信を要求しないサーバでは立たないので`None`）。
fn prepared(id: &str, proxy_port: Option<u16>) -> PreparedServer {
    let mut server = PreparedServer {
        decl: decl(id),
        isolation: harness_mcp::PreparedIsolation::AppContainer {
            profile_name: format!("harness.mcp.1-2.{id}"),
            proxy_addr: None,
        },
    };
    if let Some(port) = proxy_port {
        server.set_proxy_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    server
}

fn startup(prepared: Vec<PreparedServer>) -> McpStartup {
    McpStartup {
        prepared,
        skipped: Vec::new(),
        proxies: Vec::new(),
    }
}

/// `WfpSession::apply`冒頭のガードと同じ条件（TCP・UDPとも空なら`NoAddressesResolved`）。
fn would_be_refused_by_wfp(entry: &harness_sandbox::tier2a::netfilterd::McpNetfilterPolicy) -> bool {
    entry.allow_loopback_tcp_ports.is_empty() && entry.allow_loopback_udp_ports.is_empty()
}

/// **禁止側**: 通信を要求しないサーバには項目を作らない。作ると空の項目になり、
/// `netfilterd`がセッションの全部の項目を失敗させる。
#[test]
fn a_server_that_requests_no_network_gets_no_wfp_entry() {
    let startup = startup(vec![prepared("docs", None)]);
    let entries = startup.netfilter_entries();
    assert!(
        entries.is_empty(),
        "a server without a network request must not put an entry into ApplyRules: {entries:?}"
    );
}

/// **許可側**: 通信を要求したサーバの項目は、そのサーバのプロファイルを条件に、
/// **専用プロキシのポートだけ**を許す（UDPは開けない）。
#[test]
fn a_server_with_a_dedicated_proxy_gets_exactly_its_proxy_port() {
    let startup = startup(vec![prepared("web", Some(19090))]);
    let entries = startup.netfilter_entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].profile, "harness.mcp.1-2.web");
    assert_eq!(entries[0].allow_loopback_tcp_ports, vec![19090]);
    assert!(entries[0].allow_loopback_udp_ports.is_empty());
}

/// 混ぜたとき: 通信を要求したサーバの分だけが残り、**空の項目は1つも無い**
/// （1つでもあれば`netfilterd`が全体を失敗させる）。
#[test]
fn a_mix_of_servers_never_yields_an_entry_the_wfp_would_refuse() {
    let startup = startup(vec![
        prepared("docs", None),
        prepared("web", Some(19090)),
    ]);
    let entries = startup.netfilter_entries();
    assert_eq!(
        entries
            .iter()
            .map(|e| e.profile.as_str())
            .collect::<Vec<_>>(),
        vec!["harness.mcp.1-2.web"]
    );
    assert!(
        !entries.iter().any(would_be_refused_by_wfp),
        "an entry with no allowed port would make netfilterd fail the whole session: {entries:?}"
    );
}

/// WFPが立たずに通信を要求するサーバを起動対象から外したら、その項目も消える
/// （一覧を別に持っていた頃は`retain`で揃え直していた。いまは起動対象から導くので揃え直す物が無い）。
#[test]
fn dropping_the_servers_that_need_enforcement_drops_their_entries() {
    let mut startup = startup(vec![
        prepared("docs", None),
        prepared("web", Some(19090)),
    ]);
    startup.drop_servers_needing_egress_enforcement();
    assert!(startup.netfilter_entries().is_empty());
    // 通信を要求しないサーバは起動対象に残る（capabilityが無いのでWFPが無くても外へ出られない）。
    assert_eq!(
        startup
            .prepared
            .iter()
            .map(|s| s.decl.id.as_str())
            .collect::<Vec<_>>(),
        vec!["docs"]
    );
}
