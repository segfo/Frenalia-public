//! 協調プロキシ（`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。`run_shell`子プロセスへ
//! `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`として注入するローカルフォワードプロキシ。
//!
//! 単体では強制ではない: 環境変数を読まず生ソケットを直接開く子（静的リンクされたツール等）は
//! この制御を素通りできる。Tier1aで`harness-netfilterd`のWFP default-denyと併用できた場合だけ、
//! raw socketはWFP側で拒否され、このプロキシ経由の通信だけが通る。
//!
//! SOCKS5も同じポートで受け付ける。SOCKS5 `ATYP=0x03`（ドメイン名指定）はProxy側で
//! 名前解決するremote DNS経路として扱い、`ATYP=IPv4/IPv6`はドメイン制御を迂回するため既定拒否。
//! HTTP CONNECT/forward proxyのIP literal宛先も、同じ共通ドメインポリシーで既定拒否する。
//!
//! **既知の制約**: 1接続=1リクエストのみ扱う（HTTP keep-aliveの複数リクエスト再利用は
//! 未対応）。CONNECT（HTTPS）はトンネル確立後は宛先ホスト名以降のTLS内容を一切検査しない
//! （検査すればMITM相当になり別の複雑さを持ち込むため、ドメイン単位の可視化に留める設計）。

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use harness_core::{DomainPolicy, NetProxyConfig};

/// リクエスト1件の監査結果。`kind`は将来Fake DNS/WFPイベントを同じJSONLへ載せるための種別。
#[derive(Debug, Clone, Serialize)]
pub struct NetAuditEntry {
    pub timestamp_unix_ms: u128,
    pub kind: &'static str,
    pub protocol: &'static str,
    pub host: String,
    pub port: Option<u16>,
    pub allowed: bool,
    pub reason: &'static str,
    pub matched_pattern: Option<String>,
}

#[derive(Debug, Default)]
pub struct NetAuditLog {
    entries: Mutex<Vec<NetAuditEntry>>,
    jsonl_path: Option<PathBuf>,
}

impl NetAuditLog {
    fn new(jsonl_path: Option<PathBuf>) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            jsonl_path,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.jsonl_path.as_deref()
    }

    fn record_proxy(
        &self,
        protocol: &'static str,
        host: String,
        port: Option<u16>,
        allowed: bool,
        reason: &'static str,
        matched_pattern: Option<String>,
    ) {
        let entry = NetAuditEntry {
            timestamp_unix_ms: now_unix_ms(),
            kind: "proxy",
            protocol,
            host,
            port,
            allowed,
            reason,
            matched_pattern,
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

        // awaitをまたがない同期ロックのみ（std::sync::Mutexを非同期コードで安全に使う条件）。
        self.entries.lock().unwrap().push(entry);
    }

    pub fn entries(&self) -> Vec<NetAuditEntry> {
        self.entries.lock().unwrap().clone()
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// 起動済みローカルプロキシ。Dropでaccept loopを止める。
pub struct LocalProxy {
    pub addr: SocketAddr,
    pub audit: Arc<NetAuditLog>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

/// `config.domain_policy_enabled=false`なら`Ok(None)`。有効なら`allow_domains`が空でも
/// 全拒否ポリシーとして`127.0.0.1`の空きポートへbindし、accept loopを起動する。
pub async fn spawn_local_proxy(config: &NetProxyConfig) -> std::io::Result<Option<LocalProxy>> {
    if !config.domain_policy_enabled {
        return Ok(None);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let audit = Arc::new(NetAuditLog::new(config.audit_log_path.clone()));
    let policy = DomainPolicy::new(config.allow_domains.clone());
    let audit_for_task = audit.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let policy = policy.clone();
            let audit = audit_for_task.clone();
            tokio::spawn(async move {
                let _ = handle_conn(stream, &policy, &audit).await;
            });
        }
    });
    Ok(Some(LocalProxy {
        addr,
        audit,
        accept_task,
    }))
}

/// `host`が`allow_domains`のいずれかに一致するか。`*.example.com`は`example.com`自身と
/// その任意サブドメインに一致する（`web_fetch`のホスト検証と同様、大文字小文字を無視）。
#[cfg(test)]
fn domain_allowed(host: &str, allow_domains: &[String]) -> bool {
    DomainPolicy::new(allow_domains.to_vec())
        .evaluate_host(host)
        .allowed
}

const MAX_HEADER_BYTES: usize = 8 * 1024;

/// リクエスト行+ヘッダを`\r\n\r\n`まで読み、`(header_bytes, leftover)`を返す。`leftover`は
/// ヘッダ境界の直後に既に読めてしまっていたボディ/トンネル開始バイト列（先頭書込に使う）。
async fn read_headers(
    stream: &mut TcpStream,
    initial: Vec<u8>,
) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = initial;
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = find_header_end(&buf) {
            let leftover = buf.split_off(pos);
            return Ok(Some((buf, leftover)));
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Ok(None);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn write_status(stream: &mut TcpStream, code: u16, reason: &str) -> std::io::Result<()> {
    stream
        .write_all(format!("HTTP/1.1 {code} {reason}\r\n\r\n").as_bytes())
        .await
}

async fn handle_conn(
    mut stream: TcpStream,
    policy: &DomainPolicy,
    audit: &NetAuditLog,
) -> std::io::Result<()> {
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).await.is_err() {
        return Ok(());
    }
    if first[0] == 0x05 {
        return handle_socks5(stream, policy, audit).await;
    }

    let Some((header_bytes, leftover)) = read_headers(&mut stream, vec![first[0]]).await? else {
        return Ok(());
    };
    let header_text = String::from_utf8_lossy(&header_bytes);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let headers: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();

    let mut parts = request_line.splitn(3, ' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        write_status(&mut stream, 400, "Bad Request").await?;
        return Ok(());
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target);
        let port = target
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let decision = policy.evaluate_host(host);
        audit.record_proxy(
            "http_connect",
            host.to_string(),
            port,
            decision.allowed,
            decision.reason,
            decision.matched_pattern,
        );
        if !decision.allowed {
            write_status(&mut stream, 403, "Forbidden").await?;
            return Ok(());
        }
        let mut upstream = match TcpStream::connect(target).await {
            Ok(s) => s,
            Err(_) => {
                write_status(&mut stream, 502, "Bad Gateway").await?;
                return Ok(());
            }
        };
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        return Ok(());
    }

    // 平文HTTP（絶対URI形式）: `GET http://host[:port]/path HTTP/1.1`。
    let host_header = headers.iter().find_map(|h| {
        let (k, v) = h.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("host") {
            Some(v.trim().to_string())
        } else {
            None
        }
    });
    let parsed_url = reqwest::Url::parse(target).ok();
    let (host, port, forward_target) = if let Some(u) = &parsed_url {
        let host = u.host_str().unwrap_or("").to_string();
        let port = u.port_or_known_default().unwrap_or(80);
        let mut path = u.path().to_string();
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        (host, port, path)
    } else if let Some(hh) = &host_header {
        let (h, p) = hh
            .split_once(':')
            .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80)))
            .unwrap_or_else(|| (hh.clone(), 80));
        (h, p, target.to_string())
    } else {
        write_status(&mut stream, 400, "Bad Request").await?;
        return Ok(());
    };

    let decision = policy.evaluate_host(&host);
    audit.record_proxy(
        "http",
        host.clone(),
        Some(port),
        decision.allowed,
        decision.reason,
        decision.matched_pattern,
    );
    if !decision.allowed {
        write_status(&mut stream, 403, "Forbidden").await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => {
            write_status(&mut stream, 502, "Bad Gateway").await?;
            return Ok(());
        }
    };
    upstream
        .write_all(format!("{method} {forward_target} HTTP/1.1\r\n").as_bytes())
        .await?;
    for h in &headers {
        upstream.write_all(h.as_bytes()).await?;
        upstream.write_all(b"\r\n").await?;
    }
    upstream.write_all(b"\r\n").await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    // 平文HTTPは1接続=1リクエストのみ扱う（モジュールdoc「既知の制約」）。CONNECTと違い
    // 真のトンネルではないため、レスポンスを片方向で中継したら明示的に接続を閉じる
    // （関数終了で`stream`がdropされFIN送出）。curlの`Proxy-Connection: Keep-Alive`が
    // 次リクエストを同一接続へ載せようとしても、サーバ側クローズを見て新規接続へ
    // 正しくフォールバックする（RFC 7230準拠のクライアントの標準動作）。
    let _ = tokio::io::copy(&mut upstream, &mut stream).await;
    Ok(())
}

async fn handle_socks5(
    mut stream: TcpStream,
    policy: &DomainPolicy,
    audit: &NetAuditLog,
) -> std::io::Result<()> {
    // RFC 1928 greeting: VER, NMETHODS, METHODS...
    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; nmethods[0] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    stream.write_all(&[0x05, 0x00]).await?;

    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    if head[1] != 0x01 {
        write_socks5_reply(&mut stream, 0x07).await?; // Command not supported.
        return Ok(());
    }

    let atyp = head[3];
    let host = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_socks5_reply(&mut stream, 0x08).await?; // Address type not supported.
            return Ok(());
        }
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let decision = policy.evaluate_host(&host);
    audit.record_proxy(
        "socks5",
        host.clone(),
        Some(port),
        decision.allowed,
        decision.reason,
        decision.matched_pattern,
    );
    if !decision.allowed {
        write_socks5_reply(&mut stream, 0x02).await?; // Connection not allowed by ruleset.
        return Ok(());
    }

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => {
            write_socks5_reply(&mut stream, 0x04).await?; // Host unreachable.
            return Ok(());
        }
    };
    write_socks5_reply(&mut stream, 0x00).await?;
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    Ok(())
}

async fn write_socks5_reply(stream: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    // Reply with a dummy IPv4 bind address 0.0.0.0:0. Clients rarely rely on BND.ADDR for CONNECT.
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[test]
    fn domain_allowed_matches_exact_and_wildcard() {
        let allow = vec!["example.com".to_string(), "*.trusted.org".to_string()];
        assert!(domain_allowed("example.com", &allow));
        assert!(domain_allowed("Example.COM", &allow));
        assert!(!domain_allowed("evil.example.com", &allow));
        assert!(domain_allowed("api.trusted.org", &allow));
        assert!(domain_allowed("trusted.org", &allow));
        assert!(!domain_allowed("trusted.org.evil.com", &allow));
        assert!(!domain_allowed("nope.com", &allow));
    }

    #[tokio::test]
    async fn domain_policy_disabled_does_not_spawn_proxy() {
        let config = NetProxyConfig {
            domain_policy_enabled: false,
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap();
        assert!(proxy.is_none());
    }

    #[tokio::test]
    async fn empty_allow_domains_denies_and_audits_by_default() {
        let proxy = spawn_local_proxy(&NetProxyConfig::default())
            .await
            .unwrap()
            .unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 403"),
            "got: {status_line}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "example.com");
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "domain_denied");
    }

    /// 許可ドメインへのCONNECTはトンネルが確立し、監査ログにALLOWで記録される。
    #[tokio::test]
    async fn connect_to_allowed_domain_tunnels_and_audits() {
        // ダミーの「宛先サーバ」を127.0.0.1の別ポートに立てる。
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap(); // echo
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", target_addr.port()).as_bytes(),
            )
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 200"),
            "got: {status_line}"
        );
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "localhost");
        assert!(entries[0].allowed);
    }

    /// 未許可ドメインへのCONNECTは403で拒否され、監査ログにDENYで記録される
    /// （PRIVSEP§8フェーズ1検証計画: 未許可ドメインへのCONNECTがプロキシに拒否されること）。
    #[tokio::test]
    async fn connect_to_disallowed_domain_is_rejected_and_audited() {
        let config = NetProxyConfig {
            allow_domains: vec!["trusted.example".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 403"),
            "got: {status_line}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "evil.example");
        assert!(!entries[0].allowed);
    }

    #[tokio::test]
    async fn connect_to_ip_literal_is_rejected_even_if_listed_and_audited() {
        let config = NetProxyConfig {
            allow_domains: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 403"),
            "got: {status_line}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "127.0.0.1");
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "ip_literal_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    #[tokio::test]
    async fn connect_to_decimal_or_hex_ip_literal_is_rejected_by_same_policy() {
        let config = NetProxyConfig {
            allow_domains: vec!["2130706433".to_string(), "0x7f000001".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        for host in ["2130706433", "0x7f000001"] {
            let mut client = TcpStream::connect(proxy.addr).await.unwrap();
            client
                .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();

            let mut reader = BufReader::new(&mut client);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await.unwrap();
            assert!(
                status_line.starts_with("HTTP/1.1 403"),
                "got for {host}: {status_line}"
            );
        }

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert!(!entry.allowed);
            assert_eq!(entry.reason, "ip_literal_denied");
            assert_eq!(entry.matched_pattern, None);
        }
    }

    #[tokio::test]
    async fn plain_http_ip_literal_is_rejected_by_same_policy() {
        let config = NetProxyConfig {
            allow_domains: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 403"),
            "got: {status_line}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol, "http");
        assert_eq!(entries[0].host, "127.0.0.1");
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "ip_literal_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    #[tokio::test]
    async fn proxy_audit_persists_jsonl_when_path_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("net-audit.jsonl");
        let config = NetProxyConfig {
            allow_domains: vec!["trusted.example".to_string()],
            audit_log_path: Some(audit_path.clone()),
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.starts_with("HTTP/1.1 403"),
            "got: {status_line}"
        );

        let line = std::fs::read_to_string(audit_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["kind"], "proxy");
        assert_eq!(value["protocol"], "http_connect");
        assert_eq!(value["host"], "evil.example");
        assert_eq!(value["port"], 443);
        assert_eq!(value["allowed"], false);
        assert_eq!(value["reason"], "domain_denied");
    }

    #[tokio::test]
    async fn socks5_domain_connect_tunnels_and_audits() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let host = b"localhost";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "SOCKS5 reply: {reply:?}");

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "localhost");
        assert!(entries[0].allowed);
    }

    #[tokio::test]
    async fn socks5_ip_address_is_rejected_and_audited() {
        let config = NetProxyConfig {
            allow_domains: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x02,
            "SOCKS5 IP literal should be denied: {reply:?}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "127.0.0.1");
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "ip_literal_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    #[tokio::test]
    async fn socks5_domain_form_numeric_ip_is_rejected_by_same_policy() {
        let config = NetProxyConfig {
            allow_domains: vec!["2130706433".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        let host = b"2130706433";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x02,
            "SOCKS5 domain-form numeric IP literal should be denied: {reply:?}"
        );

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "2130706433");
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, "ip_literal_denied");
        assert_eq!(entries[0].matched_pattern, None);
    }

    /// 既知の限界（PRIVSEP§3.1で明示）の回帰確認: 環境変数を読まずプロキシを経由しない
    /// 生ソケット接続は、この機構では検知も拒否もされない（バイパスできることを意図的に確認）。
    #[tokio::test]
    async fn raw_socket_bypasses_proxy_entirely_by_design() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let config = NetProxyConfig {
            allow_domains: vec!["only-this-is-allowed.example".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        // プロキシを一切経由せず直接接続する。
        let mut direct = TcpStream::connect(target_addr).await.unwrap();
        direct.write_all(b"hi").await.unwrap();
        let mut echoed = [0u8; 2];
        direct.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hi");

        // プロキシの監査ログには一切現れない（バイパスされたことの確認）。
        assert!(proxy.audit.entries().is_empty());
    }
}
