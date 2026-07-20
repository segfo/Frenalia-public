//! 協調プロキシ（`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。`run_shell`子プロセスへ
//! `HTTP_PROXY`/`HTTPS_PROXY`として注入するローカルフォワードプロキシ。
//!
//! **強制ではない**: 環境変数を読まず生ソケットを直接開く子（静的リンクされたツール等）は
//! この制御を素通りできる。価値は「協調的なツール（curl/pip/npm等の大半）に対する監査ログと
//! ソフトな許可リスト」であり、Tier1a capabilityゲート（D-10、物理遮断）の代替ではない
//! （PRIVSEP §3.1、両者は併用する）。
//!
//! **既知の制約**: 1接続=1リクエストのみ扱う（HTTP keep-aliveの複数リクエスト再利用は
//! 未対応）。CONNECT（HTTPS）はトンネル確立後は宛先ホスト名以降のTLS内容を一切検査しない
//! （検査すればMITM相当になり別の複雑さを持ち込むため、ドメイン単位の可視化に留める設計）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use harness_core::NetProxyConfig;

/// リクエスト1件の監査結果。
#[derive(Debug, Clone)]
pub struct NetAuditEntry {
    pub host: String,
    pub allowed: bool,
}

#[derive(Debug, Default)]
pub struct NetAuditLog(Mutex<Vec<NetAuditEntry>>);

impl NetAuditLog {
    fn record(&self, host: String, allowed: bool) {
        // awaitをまたがない同期ロックのみ（std::sync::Mutexを非同期コードで安全に使う条件）。
        self.0.lock().unwrap().push(NetAuditEntry { host, allowed });
    }

    pub fn entries(&self) -> Vec<NetAuditEntry> {
        self.0.lock().unwrap().clone()
    }
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

/// `config.allow_domains`が空なら`Ok(None)`（既定は何もしない、`run_shell`出力を変えない）。
/// 空でなければ`127.0.0.1`の空きポートへbindし、accept loopをバックグラウンドタスクとして
/// 起動する。
pub async fn spawn_local_proxy(config: &NetProxyConfig) -> std::io::Result<Option<LocalProxy>> {
    if config.allow_domains.is_empty() {
        return Ok(None);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let audit = Arc::new(NetAuditLog::default());
    let allow_domains = config.allow_domains.clone();
    let audit_for_task = audit.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let allow_domains = allow_domains.clone();
            let audit = audit_for_task.clone();
            tokio::spawn(async move {
                let _ = handle_conn(stream, &allow_domains, &audit).await;
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
fn domain_allowed(host: &str, allow_domains: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    allow_domains.iter().any(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == pattern,
        }
    })
}

const MAX_HEADER_BYTES: usize = 8 * 1024;

/// リクエスト行+ヘッダを`\r\n\r\n`まで読み、`(header_bytes, leftover)`を返す。`leftover`は
/// ヘッダ境界の直後に既に読めてしまっていたボディ/トンネル開始バイト列（先頭書込に使う）。
async fn read_headers(stream: &mut TcpStream) -> std::io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::new();
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
    allow_domains: &[String],
    audit: &NetAuditLog,
) -> std::io::Result<()> {
    let Some((header_bytes, leftover)) = read_headers(&mut stream).await? else {
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
        let allowed = domain_allowed(host, allow_domains);
        audit.record(host.to_string(), allowed);
        if !allowed {
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

    let allowed = domain_allowed(&host, allow_domains);
    audit.record(host.clone(), allowed);
    if !allowed {
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
    async fn empty_allow_domains_does_not_spawn_proxy() {
        let config = NetProxyConfig::default();
        let proxy = spawn_local_proxy(&config).await.unwrap();
        assert!(proxy.is_none());
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
            allow_domains: vec!["127.0.0.1".to_string()],
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        client
            .write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target_addr.port()).as_bytes())
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(status_line.starts_with("HTTP/1.1 200"), "got: {status_line}");
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "127.0.0.1");
        assert!(entries[0].allowed);
    }

    /// 未許可ドメインへのCONNECTは403で拒否され、監査ログにDENYで記録される
    /// （PRIVSEP§8フェーズ1検証計画: 未許可ドメインへのCONNECTがプロキシに拒否されること）。
    #[tokio::test]
    async fn connect_to_disallowed_domain_is_rejected_and_audited() {
        let config = NetProxyConfig {
            allow_domains: vec!["trusted.example".to_string()],
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
        assert!(status_line.starts_with("HTTP/1.1 403"), "got: {status_line}");

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "evil.example");
        assert!(!entries[0].allowed);
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
