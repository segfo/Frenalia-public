//! [決定69] ドメインごとの出口の組み立ての単体試験。**昇格もWFPも要らない**——プロキシはloopbackへ
//! bindするだけで、WFPの項目は組み立てるだけ（実際に張るのは昇格側）。
//!
//! 守っているのは4つ——**宛先のあるドメインだけに出口を作る**こと、**空の許可ポートの項目を作らない**こと、
//! **WFPが立った後にだけ`internetClient`を積む**こと（立たない側の対＝`drop_all`）、**環境変数が
//! そのドメインのプロキシを指す**こと。どれも許可側と禁止側を対にする（`B-35`）。

use super::*;

fn request(domain: &str, allow: &[&str]) -> DomainEgressRequest {
    DomainEgressRequest {
        domain: domain.to_string(),
        profile: format!("harness.domain.1-2.{domain}"),
        allow_domains: allow.iter().map(|v| v.to_string()).collect(),
    }
}

fn spec(policy_domain: &str) -> harness_sandbox::tier2a::spawnd::DomainSpec {
    harness_sandbox::tier2a::spawnd::DomainSpec {
        name: format!("harness.domain.1-2.{policy_domain}"),
        policy_domain: policy_domain.to_string(),
        container_sid: "S-1-15-2-1".to_string(),
        capability_sids: vec!["S-1-15-3-1024-1".to_string()],
        identity: harness_sandbox::tier2a::spawnd::DomainIdentitySpec::OwnPackage,
        proxy_env: Vec::new(),
    }
}

/// 宛先を持つドメインには専用のプロキシが立ち、そのドメインの子へ渡す環境変数がそのプロキシを指す。
#[tokio::test]
async fn a_domain_with_destinations_gets_its_own_proxy_and_env() {
    let plan = start_domain_egress(&[request("ssh", &["example.com"])], None, false).await;

    assert!(plan.failed().is_empty(), "{:?}", plan.failed());
    assert_eq!(plan.egress().len(), 1);
    let egress = &plan.egress()[0];
    assert_eq!(egress.domain, "ssh");
    let http = egress
        .env
        .iter()
        .find(|(name, _)| name == "HTTP_PROXY")
        .map(|(_, value)| value.clone())
        .expect("HTTP_PROXY が無い");
    assert_eq!(http, format!("http://{}", egress.addr));
    assert!(
        !egress.env.iter().any(|(name, _)| name
            == harness_core::FAKE_DNS_ENV_NAME),
        "ドメインごとに名前解決の代役は立てないのに宛先を渡している: {:?}",
        egress.env
    );
}

/// 2つのドメインは**別のポート**を持つ（同じポートだと、WFPの項目でどちらの出口かを分けられない）。
#[tokio::test]
async fn two_domains_get_two_different_ports() {
    let plan = start_domain_egress(
        &[
            request("ssh", &["example.com"]),
            request("fetch", &["other.example.net"]),
        ],
        None,
        false,
    )
    .await;

    assert_eq!(plan.egress().len(), 2, "{:?}", plan.failed());
    assert_ne!(plan.egress()[0].addr.port(), plan.egress()[1].addr.port());
    assert_eq!(plan.addr_of("ssh"), Some(plan.egress()[0].addr));
    assert_eq!(plan.addr_of("fetch"), Some(plan.egress()[1].addr));
    assert_eq!(plan.addr_of("absent"), None);
}

/// **禁止側**: 宛先を1件も持たないドメインには出口を作らない（＝WFPの項目も作らない）。
///
/// 空の許可ポートの項目を積むと、`WfpSession::apply`が`NoAddressesResolved`で断り、
/// `netfilterd`は**1件の失敗で全部の項目を失敗させる**ので、セッションの出口ごと落ちる（前例の(2)）。
#[tokio::test]
async fn a_domain_without_destinations_gets_no_entry() {
    let plan = start_domain_egress(&[request("quiet", &[])], None, false).await;

    assert!(plan.is_empty(), "{:?}", plan.egress());
    assert!(plan.failed().is_empty(), "{:?}", plan.failed());
    #[cfg(windows)]
    assert!(plan.netfilter_entries().is_empty());
}

/// 解釈できない宛先を持つドメインは、**そのドメインごと出口なし**（一部だけ通さない。`B-10`で理由を残す）。
#[tokio::test]
async fn a_domain_with_an_unparsable_destination_gets_no_egress_and_is_reported() {
    let plan = start_domain_egress(&[request("bad", &["127.0.0.1", "example.com"])], None, false).await;

    assert!(plan.is_empty(), "{:?}", plan.egress());
    assert_eq!(plan.failed().len(), 1);
    assert_eq!(plan.failed()[0].0, "bad");
    assert!(
        plan.failed()[0].1.contains("127.0.0.1"),
        "どの宛先が読めなかったかを言っていない: {}",
        plan.failed()[0].1
    );
}

/// WFPの項目は**そのドメインのプロファイル**を名指しし、**自分のプロキシのポートだけ**を許す。
#[cfg(windows)]
#[tokio::test]
async fn netfilter_entries_name_the_profile_and_only_its_own_port() {
    let plan = start_domain_egress(
        &[
            request("ssh", &["example.com"]),
            request("fetch", &["other.example.net"]),
        ],
        None,
        false,
    )
    .await;

    let entries = plan.netfilter_entries();
    assert_eq!(entries.len(), 2);
    for (entry, egress) in entries.iter().zip(plan.egress()) {
        assert_eq!(entry.profile, egress.profile);
        assert_eq!(entry.allow_loopback_tcp_ports, vec![egress.addr.port()]);
        assert!(
            entry.allow_loopback_udp_ports.is_empty(),
            "待ち受けていないUDPの穴を開けている"
        );
    }
    // **他のドメインのポートは入らない**（入ると、宛先を絞ったつもりで絞れていない＝`e2e-mcp`の`other`）。
    assert!(!entries[0]
        .allow_loopback_tcp_ports
        .contains(&plan.egress()[1].addr.port()));
}

/// **許可側**: WFPが立った後の`attach`は`internetClient`とプロキシの宛先を表へ積む（1回だけ）。
#[tokio::test]
async fn attach_adds_internet_client_once_and_sets_the_proxy_env() {
    let plan = start_domain_egress(&[request("ssh", &["example.com"])], None, false).await;
    let mut domains = vec![spec("ssh"), spec("quiet")];

    let attached = plan.attach(&mut domains);
    assert_eq!(attached, vec!["ssh".to_string()]);
    let ssh = &domains[0];
    assert_eq!(
        ssh.capability_sids
            .iter()
            .filter(|sid| *sid == harness_sandbox::tier2a::INTERNET_CLIENT_SID)
            .count(),
        1,
        "internetClient が1つでない（重複すると CreateProcessW が落ちる）: {:?}",
        ssh.capability_sids
    );
    assert!(ssh
        .proxy_env
        .iter()
        .any(|(name, value)| name == "HTTP_PROXY" && value.ends_with(&plan.egress()[0].addr.port().to_string())));

    // **禁止側の対**: 出口を持たないドメインの表は1ビットも変わらない。
    let quiet = &domains[1];
    assert_eq!(quiet.capability_sids, spec("quiet").capability_sids);
    assert!(quiet.proxy_env.is_empty());

    // 2回呼んでも`internetClient`は1つのまま（同じSIDを2つ積まない）。
    plan.attach(&mut domains);
    assert_eq!(
        domains[0]
            .capability_sids
            .iter()
            .filter(|sid| *sid == harness_sandbox::tier2a::INTERNET_CLIENT_SID)
            .count(),
        1
    );
}

/// **禁止側の対**: WFPが立たなかった回は、`internetClient`を1つも積まずにプロキシを畳む（fail-closed）。
#[tokio::test]
async fn drop_all_reports_every_domain_and_adds_no_capability() {
    let mut plan = start_domain_egress(&[request("ssh", &["example.com"])], None, false).await;

    let dropped = plan.drop_all("WFP did not come up");
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].0, "ssh");
    assert!(plan.is_empty());

    let mut domains = vec![spec("ssh")];
    assert!(plan.attach(&mut domains).is_empty());
    assert!(!domains[0]
        .capability_sids
        .iter()
        .any(|sid| sid == harness_sandbox::tier2a::INTERNET_CLIENT_SID));
    assert!(domains[0].proxy_env.is_empty());
    #[cfg(windows)]
    assert!(plan.netfilter_entries().is_empty());
}

/// [決定69 の前例の(7)] ドメインのプロキシが書く監査の行には**持ち主のドメインの印**が載る
/// （読む側がパス2の通信の候補をドメインへ振り分ける鍵）。
#[tokio::test]
async fn an_audit_line_written_by_a_domain_proxy_carries_the_domain() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("net-audit.jsonl");
    let plan = start_domain_egress(
        &[request("ssh", &["example.com"])],
        Some(audit.clone()),
        false,
    )
    .await;
    let addr = plan.egress()[0].addr;

    // 宣言していない宛先へ CONNECT して、拒否の行を1本書かせる（通信そのものは成立しない）。
    let request_line = "CONNECT other.example.net:443 HTTP/1.1\r\nHost: other.example.net:443\r\n\r\n";
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::AsyncWriteExt;
    stream.write_all(request_line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    use tokio::io::AsyncReadExt;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;

    let text = std::fs::read_to_string(&audit).unwrap_or_default();
    let line = text
        .lines()
        .find(|line| line.contains("other.example.net"))
        .unwrap_or_else(|| panic!("監査の行が無い: {text:?}"));
    let value: serde_json::Value = serde_json::from_str(line).expect("JSON");
    assert_eq!(
        value.get("domain").and_then(|v| v.as_str()),
        Some("ssh"),
        "ドメインの印が無い（読む側が入口の候補として数えてしまう）: {line}"
    );
    assert_eq!(value.get("allowed").and_then(|v| v.as_bool()), Some(false));
}
