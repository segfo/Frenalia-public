//! Fake DNS Agent（`plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`
//! §5.4/§7）。SOCKS5/HTTP(S) proxy非対応アプリケーションがOS DNSを使う場合の観測・診断
//! レイヤー。v1ではFake IP宛通信の透過リダイレクトは行わず、問い合わせとFake IP割当を
//! 監査ログへ残す。

use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use harness_core::DomainPolicy;

const DNS_HEADER_LEN: usize = 12;
const FAKE_V4_BASE: u32 = 0xC612_0001; // 198.18.0.1 (RFC 2544 benchmarking range)

#[derive(Debug, Clone, Default)]
pub struct FakeDnsConfig {
    /// Proxyと同じ共通ドメインポリシー。`policy_required=true`かつ空の場合は全拒否。
    pub allow_domains: Vec<String>,
    pub policy_required: bool,
    pub audit_log_path: Option<PathBuf>,
    /// DNS互換の既知ポートを優先したい場合に指定する。bindできない場合は一時ポートへ
    /// フォールバックし、実際の待受ポートは`FakeDnsAgent::addr`に返す。
    pub preferred_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FakeDnsAuditEntry {
    pub timestamp_unix_ms: u128,
    pub kind: &'static str,
    pub protocol: &'static str,
    pub host: String,
    pub qtype: String,
    pub fake_ip: Option<Ipv4Addr>,
    pub allowed: bool,
    pub reason: &'static str,
    pub matched_pattern: Option<String>,
}

/// 1件のDNS問い合わせに対する判定結果（`FakeDnsAuditLog::record_query`へ渡す）。
/// ポリシー評価とFake IP割当の結果をまとめた値で、問い合わせ自体の識別情報
/// （protocol/host/qtype）とは別グループとして持つ。
struct QueryOutcome {
    fake_ip: Option<Ipv4Addr>,
    allowed: bool,
    reason: &'static str,
    matched_pattern: Option<String>,
}

#[derive(Debug, Default)]
pub struct FakeDnsAuditLog {
    entries: Mutex<Vec<FakeDnsAuditEntry>>,
    jsonl_path: Option<PathBuf>,
}

impl FakeDnsAuditLog {
    fn new(jsonl_path: Option<PathBuf>) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            jsonl_path,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.jsonl_path.as_deref()
    }

    fn record_query(
        &self,
        protocol: &'static str,
        host: String,
        qtype: u16,
        outcome: QueryOutcome,
    ) {
        let entry = FakeDnsAuditEntry {
            timestamp_unix_ms: now_unix_ms(),
            kind: "fake_dns",
            protocol,
            host,
            qtype: qtype_name(qtype),
            fake_ip: outcome.fake_ip,
            allowed: outcome.allowed,
            reason: outcome.reason,
            matched_pattern: outcome.matched_pattern,
        };

        if let Some(path) = &self.jsonl_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                if let Ok(line) = serde_json::to_string(&entry) {
                    let _ = writeln!(file, "{line}");
                }
            }
        }

        self.entries.lock().unwrap().push(entry);
    }

    pub fn entries(&self) -> Vec<FakeDnsAuditEntry> {
        self.entries.lock().unwrap().clone()
    }
}

pub struct FakeDnsAgent {
    pub addr: SocketAddr,
    pub audit: Arc<FakeDnsAuditLog>,
    udp_task: tokio::task::JoinHandle<()>,
    tcp_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeDnsAgent {
    fn drop(&mut self) {
        self.udp_task.abort();
        if let Some(task) = &self.tcp_task {
            task.abort();
        }
    }
}

pub async fn spawn_fake_dns(config: &FakeDnsConfig) -> std::io::Result<FakeDnsAgent> {
    spawn_fake_dns_with_policy(config, DomainPolicy::new(config.allow_domains.clone())).await
}

/// 評価に使う[`DomainPolicy`]を外から渡す版。理由は
/// [`crate::net_proxy::spawn_local_proxy_with_policy`]と同じ——設定型へ「全許可」フラグを
/// 足すと通常のCLI/設定経路からそこへ到達できてしまう。
///
/// **Proxyと同じポリシーを渡すこと。** 名前解決だけ通って接続で拒否される（またはその逆の）
/// 食い違いは、記録の取りこぼしになる。
pub async fn spawn_fake_dns_with_policy(
    config: &FakeDnsConfig,
    policy: DomainPolicy,
) -> std::io::Result<FakeDnsAgent> {
    let (tcp_listener, socket) = bind_dns_sockets(config.preferred_port).await?;
    let addr = socket.local_addr()?;
    let audit = Arc::new(FakeDnsAuditLog::new(config.audit_log_path.clone()));
    let state = Arc::new(Mutex::new(FakeDnsState::default()));
    let policy_required = config.policy_required;
    let audit_for_task = audit.clone();
    let state_for_udp = state.clone();
    let policy_for_udp = policy.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            if let Some(response) = handle_dns_query(
                &buf[..n],
                "dns_udp",
                &state_for_udp,
                &audit_for_task,
                &policy_for_udp,
                policy_required,
            ) {
                let _ = socket.send_to(&response, peer).await;
            }
        }
    });
    let tcp_task = Some({
        let state = state.clone();
        let audit = audit.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match tcp_listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let state = state.clone();
                let audit = audit.clone();
                let policy = policy.clone();
                tokio::spawn(async move {
                    let _ =
                        handle_tcp_dns_stream(stream, state, audit, policy, policy_required).await;
                });
            }
        })
    });
    Ok(FakeDnsAgent {
        addr,
        audit,
        udp_task,
        tcp_task,
    })
}

/// Windowsの動的ポート範囲の先頭（既定値。`netsh int ipv4 show dynamicport`）。
const DYNAMIC_PORT_START: u16 = 49152;

/// 候補ポートを跳ばす幅。Windowsの**ポート除外レンジ**（`netsh int ipv4 show
/// excludedportrange`）はプロトコル別で、Hyper-Vが有効な環境ではUDP専用の除外ブロックが
/// **100ポート幅**で多数予約される（この開発機の実測で20本以上）。TCPのport 0割り当ては
/// ほぼ連番なので、除外ブロックに差し掛かると`port 0`のリトライを何度繰り返しても
/// 同じブロックの中で全滅する。ブロック幅より1大きいstrideで候補を選び直せば必ず外へ出る。
const EXCLUSION_BLOCK_STRIDE: u16 = 101;

/// OS任せ（`port 0`）で試す回数。通常はこれで足りる。
const OS_CHOICE_ATTEMPTS: usize = 4;
/// 明示ポートで試す回数（除外ブロックを跨ぐstride付き）。
const STRIDED_ATTEMPTS: usize = 28;

/// `i`番目の候補ポート。起点を時刻由来にして、複数プロセスが同時に起動しても同じ場所で
/// 競合し続けないようにする。
fn strided_candidate_port(seed: u32, i: usize) -> u16 {
    let span = (u16::MAX - DYNAMIC_PORT_START) as u32;
    // seedを先に範囲へ畳んでから足す。`seed + i*stride`のままだと、seedがu32の上限付近の
    // ときにu32側で先に一周してしまい、候補の間隔がstrideより狭くなる（除外ブロックを
    // 跨げなくなる）。
    let base = seed % span;
    let offset = (base + (i as u32) * EXCLUSION_BLOCK_STRIDE as u32) % span;
    DYNAMIC_PORT_START + offset as u16
}

/// TCPとUDPを**同じポート番号**で確保する（DNSの慣習であり、子プロセスへは
/// `HARNESS_FAKE_DNS_ADDR`として1つのaddrしか渡さないため）。
///
/// ペアで取る以上、「TCPは取れたがUDPは取れない」ポートに当たり得る。Windowsの除外レンジは
/// プロトコル別なので、これは異常系ではなく**日常的に起こる**（[`EXCLUSION_BLOCK_STRIDE`]の
/// 説明参照。実測ではFake DNSの起動が`WSAEACCES`(10013)で失敗していた、
/// [BUG-054](../../../docs/bugs/BUG-054.md)）。
async fn bind_dns_sockets(
    preferred_port: Option<u16>,
) -> std::io::Result<(TcpListener, UdpSocket)> {
    if let Some(port) = preferred_port {
        if let Ok(pair) = bind_dns_sockets_on_port(port).await {
            return Ok(pair);
        }
    }
    let mut last_err = None;
    for _ in 0..OS_CHOICE_ATTEMPTS {
        match bind_dns_sockets_on_port(0).await {
            Ok(pair) => return Ok(pair),
            Err(e) => last_err = Some(e),
        }
    }
    // OS任せが続けて失敗した＝割り当てカーソルが除外ブロックに入っている可能性が高い。
    // ブロックを跨ぐ幅で明示的に候補を選び直す。
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for i in 0..STRIDED_ATTEMPTS {
        match bind_dns_sockets_on_port(strided_candidate_port(seed, i)).await {
            Ok(pair) => return Ok(pair),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "failed to bind paired TCP/UDP DNS sockets",
        )
    }))
}

async fn bind_dns_sockets_on_port(port: u16) -> std::io::Result<(TcpListener, UdpSocket)> {
    let tcp = TcpListener::bind(("127.0.0.1", port)).await?;
    let port = tcp.local_addr()?.port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).await?;
    Ok((tcp, udp))
}

async fn handle_tcp_dns_stream(
    mut stream: TcpStream,
    state: Arc<Mutex<FakeDnsState>>,
    audit: Arc<FakeDnsAuditLog>,
    policy: DomainPolicy,
    policy_required: bool,
) -> std::io::Result<()> {
    let len = stream.read_u16().await? as usize;
    if len == 0 || len > 4096 {
        return Ok(());
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet).await?;
    if let Some(response) =
        handle_dns_query(&packet, "dns_tcp", &state, &audit, &policy, policy_required)
    {
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
    }
    Ok(())
}

#[derive(Default)]
struct FakeDnsState {
    names: HashMap<String, Ipv4Addr>,
    next: u32,
}

fn handle_dns_query(
    packet: &[u8],
    protocol: &'static str,
    state: &Arc<Mutex<FakeDnsState>>,
    audit: &FakeDnsAuditLog,
    policy: &DomainPolicy,
    policy_required: bool,
) -> Option<Vec<u8>> {
    let question = parse_question(packet)?;
    let decision = policy.evaluate_host(&question.host);
    let policy_allows = !policy_required || decision.allowed;
    let fake_ip = if question.qtype == 1 && policy_allows {
        Some(assign_fake_ip(state, &question.host))
    } else {
        None
    };
    let reason = if !policy_required {
        if fake_ip.is_some() {
            "fake_ip_assigned"
        } else {
            "query_observed_no_answer"
        }
    } else if !decision.allowed {
        decision.reason
    } else if fake_ip.is_some() {
        "fake_ip_assigned"
    } else {
        "query_observed_no_answer"
    };
    audit.record_query(
        protocol,
        question.host.clone(),
        question.qtype,
        QueryOutcome {
            fake_ip,
            allowed: policy_allows,
            reason,
            matched_pattern: decision.matched_pattern,
        },
    );
    Some(build_response(packet, &question, fake_ip))
}

fn assign_fake_ip(state: &Arc<Mutex<FakeDnsState>>, host: &str) -> Ipv4Addr {
    let mut state = state.lock().unwrap();
    if let Some(ip) = state.names.get(host) {
        return *ip;
    }
    let ip = Ipv4Addr::from(FAKE_V4_BASE.saturating_add(state.next));
    state.next = state.next.saturating_add(1);
    state.names.insert(host.to_string(), ip);
    ip
}

struct DnsQuestion {
    host: String,
    qtype: u16,
    question_end: usize,
}

fn parse_question(packet: &[u8]) -> Option<DnsQuestion> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 || len > 63 || pos + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len]).to_string());
        pos += len;
    }
    if pos + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let host = labels.join(".").trim_end_matches('.').to_ascii_lowercase();
    Some(DnsQuestion {
        host,
        qtype,
        question_end: pos + 4,
    })
}

fn build_response(packet: &[u8], question: &DnsQuestion, fake_ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 32);
    out.extend_from_slice(&packet[0..2]); // ID
    out.extend_from_slice(&0x8180u16.to_be_bytes()); // standard response, recursion available
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(fake_ip.is_some() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&packet[DNS_HEADER_LEN..question.question_end]);

    if let Some(ip) = fake_ip {
        out.extend_from_slice(&[0xC0, 0x0C]); // NAME pointer to first question name
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        other => format!("TYPE{other}"),
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_a(id: u16, host: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn parses_dns_question() {
        let packet = query_a(7, "Example.COM");
        let q = parse_question(&packet).unwrap();
        assert_eq!(q.host, "example.com");
        assert_eq!(q.qtype, 1);
    }

    #[tokio::test]
    async fn fake_dns_answers_a_query_and_audits_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("net-audit.jsonl");
        let agent = spawn_fake_dns(&FakeDnsConfig {
            allow_domains: vec!["example.com".to_string()],
            policy_required: true,
            audit_log_path: Some(audit_path.clone()),
            preferred_port: None,
        })
        .await
        .unwrap();

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client
            .send_to(&query_a(0x1234, "example.com"), agent.addr)
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let (n, _) = client.recv_from(&mut response).await.unwrap();
        assert!(n > DNS_HEADER_LEN);
        assert_eq!(&response[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[n - 4..n], &[198, 18, 0, 1]);

        let entries = agent.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "example.com");
        assert_eq!(entries[0].qtype, "A");
        assert_eq!(entries[0].fake_ip, Some(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(entries[0].allowed);
        assert_eq!(entries[0].reason, "fake_ip_assigned");
        assert_eq!(entries[0].matched_pattern, Some("example.com".to_string()));

        let line = std::fs::read_to_string(audit_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["kind"], "fake_dns");
        assert_eq!(value["protocol"], "dns_udp");
        assert_eq!(value["host"], "example.com");
        assert_eq!(value["fake_ip"], "198.18.0.1");
        assert_eq!(value["allowed"], true);
        assert_eq!(value["reason"], "fake_ip_assigned");
        assert_eq!(value["matched_pattern"], "example.com");
    }

    #[tokio::test]
    async fn fake_dns_answers_tcp_dns_query() {
        let agent = spawn_fake_dns(&FakeDnsConfig {
            allow_domains: vec!["tcp.example.com".to_string()],
            policy_required: true,
            audit_log_path: None,
            preferred_port: None,
        })
        .await
        .unwrap();

        let mut stream = TcpStream::connect(agent.addr).await.unwrap();
        let query = query_a(0x5678, "tcp.example.com");
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut response = vec![0u8; len];
        stream.read_exact(&mut response).await.unwrap();

        assert_eq!(&response[0..2], &0x5678u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[len - 4..len], &[198, 18, 0, 1]);
        let entries = agent.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "tcp.example.com");
        assert_eq!(entries[0].protocol, "dns_tcp");
    }

    #[tokio::test]
    async fn fake_dns_uses_shared_policy_for_denied_domain() {
        let agent = spawn_fake_dns(&FakeDnsConfig {
            allow_domains: vec!["allowed.example".to_string()],
            policy_required: true,
            audit_log_path: None,
            preferred_port: None,
        })
        .await
        .unwrap();

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client
            .send_to(&query_a(0x9999, "denied.example"), agent.addr)
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let (n, _) = client.recv_from(&mut response).await.unwrap();
        assert!(n > DNS_HEADER_LEN);
        assert_eq!(&response[0..2], &0x9999u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);

        let entries = agent.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "denied.example");
        assert_eq!(entries[0].fake_ip, None);
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "domain_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    #[tokio::test]
    async fn fake_dns_rejects_numeric_ip_like_name_by_shared_policy() {
        let agent = spawn_fake_dns(&FakeDnsConfig {
            allow_domains: vec!["2130706433".to_string()],
            policy_required: true,
            audit_log_path: None,
            preferred_port: None,
        })
        .await
        .unwrap();

        let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        client
            .send_to(&query_a(0x7777, "2130706433"), agent.addr)
            .await
            .unwrap();
        let mut response = [0u8; 512];
        let (n, _) = client.recv_from(&mut response).await.unwrap();
        assert!(n > DNS_HEADER_LEN);
        assert_eq!(&response[0..2], &0x7777u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);

        let entries = agent.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "2130706433");
        assert_eq!(entries[0].fake_ip, None);
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "ip_literal_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    /// 候補ポートは動的ポート範囲に収まり、**除外ブロック幅（100）より大きい間隔**で動く。
    /// これが崩れると、Hyper-V由来のUDP除外ブロックに差し掛かったときに全リトライが
    /// 同じブロック内で全滅する（[`EXCLUSION_BLOCK_STRIDE`]のdoc参照）。
    #[test]
    fn strided_candidates_stay_in_range_and_cross_exclusion_blocks() {
        for seed in [0u32, 12_345, u32::MAX] {
            let ports: Vec<u16> = (0..STRIDED_ATTEMPTS)
                .map(|i| strided_candidate_port(seed, i))
                .collect();
            assert!(
                ports.iter().all(|p| *p >= DYNAMIC_PORT_START),
                "動的ポート範囲の外を選ばない: {ports:?}"
            );
            for pair in ports.windows(2) {
                let step = pair[1].abs_diff(pair[0]);
                // 通常はstrideちょうど、範囲を一周する箇所では「span - stride」になる。
                // どちらも除外ブロック幅（100）より大きいことが要件。
                assert!(
                    step > 100,
                    "連続候補が同じ100ポートブロックに留まらないこと: {pair:?} (step={step})"
                );
            }
        }
    }

    #[tokio::test]
    async fn fake_dns_falls_back_when_preferred_port_is_busy() {
        let occupied_tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let occupied_port = occupied_tcp.local_addr().unwrap().port();

        let agent = spawn_fake_dns(&FakeDnsConfig {
            allow_domains: vec!["example.com".to_string()],
            policy_required: true,
            audit_log_path: None,
            preferred_port: Some(occupied_port),
        })
        .await
        .unwrap();

        assert_ne!(
            agent.addr.port(),
            occupied_port,
            "Fake DNS should fall back to an ephemeral port when the preferred port is unavailable"
        );
    }
}
