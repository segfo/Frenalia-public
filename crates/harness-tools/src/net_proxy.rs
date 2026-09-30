//! 協調プロキシ（`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。`run_shell`子プロセスへ
//! `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`として注入するローカルフォワードプロキシ。
//!
//! 単体では強制ではない: 環境変数を読まず生ソケットを直接開く子（静的リンクされたツール等）は
//! この制御を素通りできる。Tier2aで`harness-netfilterd`のWFP default-denyと併用できた場合だけ、
//! raw socketはWFP側で拒否され、このプロキシ経由の通信だけが通る。
//!
//! HTTP(S)経路は`hyper`/`hyper-util`（legacy client + auto server）で実装し、HTTP/1.1の
//! フレーミング（`Content-Length`/`Transfer-Encoding`の併存・重複拒否込み）を正しく扱い、
//! keep-alive接続上の複数リクエストをリクエスト単位でポリシー再評価する。h2c
//! （cleartext HTTP/2、prior knowledge）も同一ポートで受け付ける。上流接続は
//! `scheme+authority`単位でプールし再利用する。SOCKS5も同じポートで受け付ける。
//!
//! SOCKS5 `ATYP=0x03`（ドメイン名指定）はProxy側で名前解決するremote DNS経路として扱い、
//! `ATYP=IPv4/IPv6`はドメイン制御を迂回するため既定拒否。HTTP CONNECT/forward proxyの
//! IP literal宛先も、同じ共通ドメインポリシーで既定拒否する。
//!
//! CONNECT/SOCKS5トンネル確立後は`crate::tunnel::TunnelHandler`（既定`SniTunnelHandler`）へ
//! 委譲する。v1はTLS ClientHelloのSNI/ALPNだけをallowlist評価し、**トンネル内容は復号しない**
//! （検査層は差し替え可能な拡張点であり、将来監査目的の復号層を足す場合は`TunnelHandler`の
//! 別実装を用意すればよい。`crate::tunnel`のモジュールdoc参照）。
//!
//! **既知の制約**: raw socketで環境変数を読まず直接connectする子はそもそもこのプロキシを
//! 経由しない（境界はWFP側、`raw_socket_bypasses_proxy_entirely_by_design`参照）。

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{self, HeaderMap};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use harness_core::{DomainPolicy, NetProxyConfig};

use crate::tunnel::{SniTunnelHandler, Tunnel, TunnelHandler};

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
    /// `protocol="tls_sni"`のとき、トンネル外側（CONNECT/SOCKS5宛先）のホスト名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_host: Option<String>,
    /// `protocol="tls_sni"`のとき、ClientHelloのALPN候補。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    /// `reason`だけでは足りない補足（現状は上流接続失敗のOSエラー文字列）。
    /// **ポリシー判定の結果ではなく、なぜ通信が成立しなかったかの診断情報**を載せる。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
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

    fn push(&self, entry: NetAuditEntry) {
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

    fn record_proxy(
        &self,
        protocol: &'static str,
        host: String,
        port: Option<u16>,
        allowed: bool,
        reason: &'static str,
        matched_pattern: Option<String>,
    ) {
        self.push(NetAuditEntry {
            timestamp_unix_ms: now_unix_ms(),
            kind: "proxy",
            protocol,
            host,
            port,
            allowed,
            reason,
            matched_pattern,
            connect_host: None,
            alpn: None,
            detail: None,
        });
    }

    /// ポリシー上は許可されたのに上流へ接続できなかったことを記録する。
    ///
    /// これが無いと、失敗は`502 Bad Gateway`／SOCKS5の`0x04`という**外向きの結果**にしか
    /// 残らず、原因（名前解決の失敗か、拒否か、到達不能か）が監査ログから完全に消える。
    /// `docs/STATUS.md` Tier2a残課題#6の切り分けが長く止まっていた理由がまさにこれだった
    /// （[BUG-054](../../../docs/bugs/BUG-054.md)）。
    fn record_upstream_failure(
        &self,
        protocol: &'static str,
        host: String,
        port: Option<u16>,
        error: &std::io::Error,
    ) {
        self.push(NetAuditEntry {
            timestamp_unix_ms: now_unix_ms(),
            kind: "proxy",
            protocol,
            host,
            port,
            allowed: false,
            reason: "upstream_connect_failed",
            matched_pattern: None,
            connect_host: None,
            alpn: None,
            detail: Some(format!("{:?}: {error}", error.kind())),
        });
    }

    /// トンネル内で観測したTLS ClientHelloの結果を記録する（`crate::tunnel::SniTunnelHandler`から呼ばれる）。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_tls_sni(
        &self,
        host: String,
        port: Option<u16>,
        allowed: bool,
        reason: &'static str,
        matched_pattern: Option<String>,
        connect_host: Option<String>,
        alpn: Option<Vec<String>>,
    ) {
        self.push(NetAuditEntry {
            timestamp_unix_ms: now_unix_ms(),
            kind: "proxy",
            protocol: "tls_sni",
            host,
            port,
            allowed,
            reason,
            matched_pattern,
            connect_host,
            alpn,
            detail: None,
        });
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

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn incoming_body(body: Incoming) -> BoxBody {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}

fn resp_status(code: StatusCode) -> Response<BoxBody> {
    Response::builder()
        .status(code)
        .body(empty_body())
        .expect("status-only response is always valid")
}

/// hop-by-hopヘッダ（RFC 7230 §6.1、`Connection`が列挙する追加分含む）をリクエスト・
/// レスポンス双方から除去する。`Content-Length`/`Transfer-Encoding`もここで落とし、
/// 実際のフレーミングはhyperがbodyの`size_hint`から再計算する。
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    if let Some(conn) = headers.get(header::CONNECTION) {
        if let Ok(s) = conn.to_str() {
            let extra: Vec<String> = s
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            for name in extra {
                headers.remove(name.as_str());
            }
        }
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    ] {
        headers.remove(name);
    }
}

/// `run_shell`（`crates/harness-tools/src/shell/mod.rs`）とポリシーエディタの記録モード
/// （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）の両方が使う、子プロセスへ注入する環境変数の
/// 純粋な組み立て。`docs/CODE-STRUCTURE-RULES.md`規則5——同じロジックを2箇所に複製しない。
///
/// `proxy_addr`があれば`ALL_PROXY`/`all_proxy`（`socks5h://`、SOCKS5 remote DNSが主経路）と
/// `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy`（`http://`、既存CLI互換）を返す。
/// `fake_dns_addr`があれば`HARNESS_FAKE_DNS_ADDR`（診断用）を加える。どちらも無ければ空。
pub fn proxy_env_vars(
    proxy_addr: Option<SocketAddr>,
    fake_dns_addr: Option<SocketAddr>,
) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(addr) = proxy_addr {
        let http_proxy_url = format!("http://{addr}");
        let socks_proxy_url = format!("socks5h://{addr}");
        for key in ["ALL_PROXY", "all_proxy"] {
            env.push((key.to_string(), socks_proxy_url.clone()));
        }
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.push((key.to_string(), http_proxy_url.clone()));
        }
    }
    if let Some(addr) = fake_dns_addr {
        env.push(("HARNESS_FAKE_DNS_ADDR".to_string(), addr.to_string()));
    }
    env
}

/// WFPのdefault-denyに開ける**loopbackの穴**（プロトコル別のポート一覧）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetLoopbackPorts {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

fn sorted_unique_ports(mut ports: Vec<u16>) -> Vec<u16> {
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// 起動済みのLocal Proxy / Fake DNSのアドレスから、WFPへ渡すloopback許可ポートを決める。
///
/// **プロトコルごとに分けるのが要点**である。ProxyはTCPのみ、Fake DNSはTCP・UDPの両方を
/// 待ち受ける。まとめて両プロトコルへ開けると、Proxyのポート宛のUDPという**誰も待っていない
/// 穴**をdefault-denyに開けることになる。
///
/// `run_shell`のセッション（`harness-cli`の起動パイプライン）と、ポリシーエディタのパス2
/// （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）の両方が使う（`proxy_env_vars`と同じ理由でここに置く
/// ——`docs/CODE-STRUCTURE-RULES.md`規則5）。
pub fn net_loopback_ports_for_agents(
    proxy_addr: Option<SocketAddr>,
    fake_dns_addr: Option<SocketAddr>,
) -> NetLoopbackPorts {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    if let Some(addr) = proxy_addr {
        tcp.push(addr.port());
    }
    if let Some(addr) = fake_dns_addr {
        tcp.push(addr.port());
        udp.push(addr.port());
    }
    NetLoopbackPorts {
        tcp: sorted_unique_ports(tcp),
        udp: sorted_unique_ports(udp),
    }
}

/// `config.domain_policy_enabled=false`なら`Ok(None)`。有効なら`allow_domains`が空でも
/// 全拒否ポリシーとして`127.0.0.1`の空きポートへbindし、accept loopを起動する。
pub async fn spawn_local_proxy(config: &NetProxyConfig) -> std::io::Result<Option<LocalProxy>> {
    spawn_local_proxy_with_policy(config, DomainPolicy::new(config.allow_domains.clone())).await
}

/// 評価に使う[`DomainPolicy`]を外から渡す版。
///
/// **`NetProxyConfig`へ「全許可」フラグを足さないための入口**である。ポリシーエディタの
/// パス2（Tier2aでのドメイン記録、`plans/POLICY-EDITOR-TOMOYO-DIG.md`）は
/// [`DomainPolicy::record_all`]を渡し、1回の完走で到達したドメインを取りこぼさず記録する。
///
/// 設定型（`NetProxyConfig`）側にモードを足さないのは2つの理由による。
///
/// 1. `harness_core::prompt`の`render_net_proxy`が`NetProxyConfig`を`..`無しで完全分解する
///    コンパイル時ゲートを持っており、モデルへ宣言すべき制約かどうかの判断を毎回強制される
///    ——記録モードはそもそもモデルへ送られないので、その判断の対象にすべきではない。
/// 2. より重要な点として、設定ファイル・CLI引数という**通常の経路から「全許可」へ到達できる
///    穴**を開けてしまう。`DomainPolicy`が型でモードを分けている理由そのものである
///    （`harness_core::net_policy`のdoc）。
pub async fn spawn_local_proxy_with_policy(
    config: &NetProxyConfig,
    policy: DomainPolicy,
) -> std::io::Result<Option<LocalProxy>> {
    if !config.domain_policy_enabled {
        return Ok(None);
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let audit = Arc::new(NetAuditLog::new(config.audit_log_path.clone()));
    let policy = Arc::new(policy);
    let tunnel_handler: Arc<dyn TunnelHandler> = match config.tls_inspection {
        harness_core::TlsInspection::Sni => Arc::new(SniTunnelHandler::default()),
    };
    let http_client: LegacyClient<HttpConnector, Incoming> =
        LegacyClient::builder(TokioExecutor::new()).build_http();

    let audit_for_task = audit.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let policy = policy.clone();
            let audit = audit_for_task.clone();
            let tunnel_handler = tunnel_handler.clone();
            let http_client = http_client.clone();
            tokio::spawn(async move {
                let _ = handle_conn(stream, policy, audit, tunnel_handler, http_client).await;
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

/// 新規接続の入口。先頭バイトをpeek（消費しない）してSOCKS5（`0x05`）かHTTP(S)かを
/// 振り分ける。HTTP(S)側はここから先を丸ごとhyperの`auto::Builder`へ渡し、
/// HTTP/1.1のフレーミング・keep-alive・h2cの扱いはhyperに委ねる。
async fn handle_conn(
    stream: TcpStream,
    policy: Arc<DomainPolicy>,
    audit: Arc<NetAuditLog>,
    tunnel_handler: Arc<dyn TunnelHandler>,
    http_client: LegacyClient<HttpConnector, Incoming>,
) -> std::io::Result<()> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }
    if first[0] == 0x05 {
        return handle_socks5(
            stream,
            policy.as_ref(),
            audit.as_ref(),
            tunnel_handler.as_ref(),
        )
        .await;
    }

    let io = TokioIo::new(stream);
    let service = service_fn(move |req: Request<Incoming>| {
        let policy = policy.clone();
        let audit = audit.clone();
        let tunnel_handler = tunnel_handler.clone();
        let http_client = http_client.clone();
        async move { handle_http_request(req, policy, audit, tunnel_handler, http_client).await }
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await;
    Ok(())
}

async fn handle_http_request(
    mut req: Request<Incoming>,
    policy: Arc<DomainPolicy>,
    audit: Arc<NetAuditLog>,
    tunnel_handler: Arc<dyn TunnelHandler>,
    http_client: LegacyClient<HttpConnector, Incoming>,
) -> Result<Response<BoxBody>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, policy, audit, tunnel_handler).await);
    }

    // origin-form（`Host`ヘッダ方式）を絶対URIへ正規化する。HTTP proxyへ送るクライアントは
    // 絶対URI形式（`GET http://host/path HTTP/1.1`）を使うことが多いが、両対応にする。
    if req.uri().authority().is_none() {
        let Some(host_hdr) = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
        else {
            return Ok(resp_status(StatusCode::BAD_REQUEST));
        };
        let pq = req
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
        let new_uri = match Uri::builder()
            .scheme("http")
            .authority(host_hdr)
            .path_and_query(pq)
            .build()
        {
            Ok(u) => u,
            Err(_) => return Ok(resp_status(StatusCode::BAD_REQUEST)),
        };
        *req.uri_mut() = new_uri;
    }

    let Some(authority) = req.uri().authority().cloned() else {
        return Ok(resp_status(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(80);

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
        return Ok(resp_status(StatusCode::FORBIDDEN));
    }

    strip_hop_by_hop(req.headers_mut());
    // 上流は常にHTTP/1.1で話す（h2c/h2はクライアント⇔プロキシ間のみ。上流に平文h2は存在しない
    // 前提のプロトコル変換）。フロント側がh2だった場合、`req.version()`をそのまま転送すると
    // H1専用の`http_client`が`UserUnsupportedVersion`で拒否するため、ここで明示的に揃える。
    *req.version_mut() = http::Version::HTTP_11;
    match http_client.request(req).await {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            Ok(Response::from_parts(parts, incoming_body(body)))
        }
        Err(_) => Ok(resp_status(StatusCode::BAD_GATEWAY)),
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    policy: Arc<DomainPolicy>,
    audit: Arc<NetAuditLog>,
    tunnel_handler: Arc<dyn TunnelHandler>,
) -> Response<BoxBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return resp_status(StatusCode::BAD_REQUEST);
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    let decision = policy.evaluate_host(&host);
    audit.record_proxy(
        "http_connect",
        host.clone(),
        Some(port),
        decision.allowed,
        decision.reason,
        decision.matched_pattern,
    );
    if !decision.allowed {
        return resp_status(StatusCode::FORBIDDEN);
    }

    let upstream = match crate::dial::connect_upstream(host.as_str(), port).await {
        Ok(s) => s,
        Err(e) => {
            audit.record_upstream_failure("http_connect", host.clone(), Some(port), &e);
            return resp_status(StatusCode::BAD_GATEWAY);
        }
    };

    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            let client_io = TokioIo::new(upgraded);
            let tunnel = Tunnel {
                protocol: "http_connect",
                connect_host: host,
                connect_port: port,
                client: Box::new(client_io),
                upstream: Box::new(upstream),
                policy: policy.as_ref(),
                audit: audit.as_ref(),
            };
            let _ = tunnel_handler.handle(tunnel).await;
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("status-only response is always valid")
}

async fn handle_socks5(
    mut stream: TcpStream,
    policy: &DomainPolicy,
    audit: &NetAuditLog,
    tunnel_handler: &dyn TunnelHandler,
) -> std::io::Result<()> {
    // VERバイトは`handle_conn`側でpeek済み（未消費）なので、ここで正式に読む。
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    if ver[0] != 0x05 {
        return Ok(());
    }

    // RFC 1928 greeting: VER(読済み), NMETHODS, METHODS...
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

    let upstream = match crate::dial::connect_upstream(host.as_str(), port).await {
        Ok(s) => s,
        Err(e) => {
            audit.record_upstream_failure("socks5", host.clone(), Some(port), &e);
            write_socks5_reply(&mut stream, 0x04).await?; // Host unreachable.
            return Ok(());
        }
    };
    write_socks5_reply(&mut stream, 0x00).await?;

    let tunnel = Tunnel {
        protocol: "socks5",
        connect_host: host,
        connect_port: port,
        client: Box::new(stream),
        upstream: Box::new(upstream),
        policy,
        audit,
    };
    let _ = tunnel_handler.handle(tunnel).await;
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, BufReader};

    /// WFPへ開けるloopbackの穴は**プロトコルごとに分ける**。まとめて両プロトコルへ開けると、
    /// TCPしか待たないProxyのポート宛にUDPの穴が開く（`harness-cli`から移設したテスト）。
    #[test]
    fn loopback_ports_are_protocol_scoped_for_proxy_and_fake_dns() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18080".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(
            ports,
            NetLoopbackPorts {
                tcp: vec![18053, 18080],
                udp: vec![18053],
            }
        );
    }

    /// 同じポートを両エージェントが使っていても、重複を潰すだけでプロトコルは広げない。
    #[test]
    fn loopback_ports_are_deduplicated_without_widening_protocols() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18053".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(ports.tcp, vec![18053]);
        assert_eq!(ports.udp, vec![18053]);
    }

    /// エージェントが1つも起動していなければ穴も開かない（**default-denyのまま**）。
    #[test]
    fn no_agents_means_no_loopback_holes() {
        let ports = net_loopback_ports_for_agents(None, None);

        assert!(
            ports.tcp.is_empty(),
            "穴が無い＝WFPのdefault-denyがそのまま残る"
        );
        assert!(ports.udp.is_empty());
    }

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

    /// characterization test: `run_shell`（shell.rs）が長年インラインで組み立てていた
    /// env変数の**キー・値・順序**をそのまま固定する。`proxy_env_vars`への抽出前後で
    /// 挙動が変わっていないことをこれで保証する。
    #[test]
    fn proxy_env_vars_matches_the_shape_run_shell_used_to_build_inline() {
        let proxy_addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let fake_dns_addr: SocketAddr = "127.0.0.1:18053".parse().unwrap();

        let env = proxy_env_vars(Some(proxy_addr), Some(fake_dns_addr));

        assert_eq!(
            env,
            vec![
                (
                    "ALL_PROXY".to_string(),
                    "socks5h://127.0.0.1:18080".to_string()
                ),
                (
                    "all_proxy".to_string(),
                    "socks5h://127.0.0.1:18080".to_string()
                ),
                (
                    "HTTP_PROXY".to_string(),
                    "http://127.0.0.1:18080".to_string()
                ),
                (
                    "HTTPS_PROXY".to_string(),
                    "http://127.0.0.1:18080".to_string()
                ),
                (
                    "http_proxy".to_string(),
                    "http://127.0.0.1:18080".to_string()
                ),
                (
                    "https_proxy".to_string(),
                    "http://127.0.0.1:18080".to_string()
                ),
                (
                    "HARNESS_FAKE_DNS_ADDR".to_string(),
                    "127.0.0.1:18053".to_string()
                ),
            ]
        );
    }

    #[test]
    fn proxy_env_vars_omits_proxy_keys_when_proxy_addr_is_none() {
        let fake_dns_addr: SocketAddr = "127.0.0.1:18053".parse().unwrap();
        let env = proxy_env_vars(None, Some(fake_dns_addr));
        assert_eq!(
            env,
            vec![(
                "HARNESS_FAKE_DNS_ADDR".to_string(),
                "127.0.0.1:18053".to_string()
            )]
        );
    }

    #[test]
    fn proxy_env_vars_omits_fake_dns_key_when_fake_dns_addr_is_none() {
        let proxy_addr: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let env = proxy_env_vars(Some(proxy_addr), None);
        assert!(env.iter().all(|(k, _)| k != "HARNESS_FAKE_DNS_ADDR"));
        assert_eq!(env.len(), 6);
    }

    #[test]
    fn proxy_env_vars_is_empty_when_both_addrs_are_none() {
        assert!(proxy_env_vars(None, None).is_empty());
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
    /// トンネル内には非TLSの`hello`を流すため、SNI検査層が2件目の監査エントリ
    /// （`reason=sni_not_tls`）を残す（`crate::tunnel::SniTunnelHandler`が挟まったため）。
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
        assert_eq!(entries.len(), 2, "entries: {entries:?}");
        assert_eq!(entries[0].host, "localhost");
        assert!(entries[0].allowed);
        assert_eq!(entries[1].protocol, "tls_sni");
        assert_eq!(entries[1].reason, "sni_not_tls");
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

    /// SOCKS5経路でもCONNECT経路と同じくトンネル確立後にSNI検査層が挟まり、
    /// 非TLSの`hello`は`sni_not_tls`として2件目の監査エントリになる。
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
        assert_eq!(entries.len(), 2, "entries: {entries:?}");
        assert_eq!(entries[0].host, "localhost");
        assert!(entries[0].allowed);
        assert_eq!(entries[1].protocol, "tls_sni");
        assert_eq!(entries[1].reason, "sni_not_tls");
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

    /// HTTP keep-alive: 1本のTCP接続上で許可→拒否→許可の3リクエストを送り、
    /// 拒否後も接続が維持されリクエストごとに再評価されることを確認する。
    #[tokio::test]
    async fn keepalive_connection_reevaluates_policy_per_request() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_task = accept_count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = target_listener.accept().await else {
                    break;
                };
                accept_count_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (reader, mut writer) = sock.split();
                    let mut reader = BufReader::new(reader);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        if line == "\r\n" {
                            let body = b"ok";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                                body.len()
                            );
                            if writer.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                            if writer.write_all(body).await.is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        let allowed_target = format!("http://localhost:{}/", target_addr.port());
        let denied_target = "http://denied.example/";

        for target in [
            allowed_target.as_str(),
            denied_target,
            allowed_target.as_str(),
        ] {
            client
                .write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
        }

        let mut reader = BufReader::new(&mut client);
        let mut statuses = Vec::new();
        for _ in 0..3 {
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await.unwrap();
            // ヘッダ・ボディを読み飛ばして次のステータス行まで進む。
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await.unwrap();
            statuses.push(status_line);
        }

        assert!(statuses[0].starts_with("HTTP/1.1 200"), "{:?}", statuses);
        assert!(statuses[1].starts_with("HTTP/1.1 403"), "{:?}", statuses);
        assert!(statuses[2].starts_with("HTTP/1.1 200"), "{:?}", statuses);

        // 上流接続はhost:port単位でプールされ、2回の許可リクエストで1本しか使われない。
        assert_eq!(accept_count.load(Ordering::SeqCst), 1);

        let entries = proxy.audit.entries();
        assert_eq!(entries.len(), 3, "entries: {entries:?}");
        assert!(entries[0].allowed);
        assert!(!entries[1].allowed);
        assert!(entries[2].allowed);
    }

    /// `Content-Length`付きPOSTボディが欠落せず上流へ届くことの回帰テスト
    /// （旧実装は平文HTTPパスでリクエストボディを一切転送していなかった）。
    #[tokio::test]
    async fn post_request_body_is_forwarded_completely() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_task = received.clone();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let (reader, mut writer) = sock.split();
            let mut reader = BufReader::new(reader);
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await.unwrap();
            *received_task.lock().unwrap() = body;
            writer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();

        let payload = b"the quick brown fox jumps over the lazy dog";
        let request = format!(
            "POST http://localhost:{}/ HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            target_addr.port(),
            payload.len()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.write_all(payload).await.unwrap();

        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");

        assert_eq!(received.lock().unwrap().as_slice(), payload);
    }

    /// CONNECTトンネル内でSNI不許可ドメインを名乗るClientHelloを送ると、トンネルは
    /// 即座に切断され上流へは何も届かない。監査には`reason=sni_denied`が残る。
    #[tokio::test]
    async fn connect_tunnel_sni_denied_closes_tunnel_and_reaches_no_upstream() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let received_any = Arc::new(AtomicUsize::new(0));
        let received_any_task = received_any.clone();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = target_listener.accept().await {
                let mut buf = [0u8; 16];
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        received_any_task.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });

        // CONNECT先ホストは実際にTCP接続できる必要があるため`localhost`（許可済み）を使い、
        // ClientHelloのSNIだけを許可リスト外の`denied.example`にする（SNI自体は名前解決しない）。
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
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        let hello = build_client_hello("denied.example");
        client.write_all(&hello).await.unwrap();

        // トンネルは閉じられるので、これ以上読んでもEOFになる。
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "tunnel should be closed after sni_denied");

        assert_eq!(
            received_any.load(Ordering::SeqCst),
            0,
            "denied ClientHello must not reach upstream"
        );

        let entries = proxy.audit.entries();
        let sni_entry = entries
            .iter()
            .find(|e| e.protocol == "tls_sni")
            .expect("tls_sni entry");
        assert_eq!(sni_entry.reason, "sni_denied");
        assert!(!sni_entry.allowed);
        assert_eq!(sni_entry.host, "denied.example");
        assert_eq!(sni_entry.connect_host.as_deref(), Some("localhost"));
    }

    /// SNIがCONNECT宛先と異なるが両方許可ドメインの場合は、通信は継続され
    /// `reason=sni_host_mismatch`として監査に残るだけ（拒否しない）。
    #[tokio::test]
    async fn connect_tunnel_sni_host_mismatch_is_allowed_and_audited() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_task = received.clone();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            *received_task.lock().unwrap() = buf[..n].to_vec();
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string(), "allowed-b.example".to_string()],
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
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        let hello = build_client_hello("allowed-b.example");
        client.write_all(&hello).await.unwrap();

        // 少し待って上流へバイトが届くのを許容する。
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !received.lock().unwrap().is_empty(),
            "mismatched-but-allowed SNI should still be piped to upstream"
        );

        let entries = proxy.audit.entries();
        let sni_entry = entries
            .iter()
            .find(|e| e.protocol == "tls_sni")
            .expect("tls_sni entry");
        assert_eq!(sni_entry.reason, "sni_host_mismatch");
        assert!(sni_entry.allowed);
        assert_eq!(sni_entry.host, "allowed-b.example");
        assert_eq!(sni_entry.connect_host.as_deref(), Some("localhost"));
    }

    /// `TunnelHandler`が拡張点として機能することの回帰確認: CONNECT/SOCKS5の受理ロジックを
    /// 一切変えずに検査層を丸ごと差し替えられる（将来の復号層もこの形で追加できる）。
    /// 差し替えたハンドラは呼ばれたことをフラグで示しつつ、実際の中継は
    /// `copy_bidirectional`（`SniTunnelHandler`と同じ中継手段）で行い、
    /// 呼ばれたハンドラが`SniTunnelHandler`ではなくこちらであることをechoで確認する。
    #[tokio::test]
    async fn tunnel_handler_can_be_swapped_without_touching_connect_logic() {
        struct FlagHandler(Arc<AtomicUsize>);

        #[async_trait::async_trait]
        impl TunnelHandler for FlagHandler {
            async fn handle(&self, mut tunnel: Tunnel<'_>) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                let _ =
                    tokio::io::copy_bidirectional(&mut tunnel.client, &mut tunnel.upstream).await;
                Ok(())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let audit = Arc::new(NetAuditLog::new(None));
        let policy = Arc::new(DomainPolicy::new(vec!["localhost".to_string()]));
        let invoked = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn TunnelHandler> = Arc::new(FlagHandler(invoked.clone()));
        let http_client: LegacyClient<HttpConnector, Incoming> =
            LegacyClient::builder(TokioExecutor::new()).build_http();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_conn(stream, policy, audit, handler, http_client).await;
            }
        });

        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", target_addr.port()).as_bytes(),
            )
            .await
            .unwrap();
        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        assert_eq!(invoked.load(Ordering::SeqCst), 1);
    }

    /// h2c（cleartext HTTP/2、prior knowledge）クライアントからのリクエストも
    /// 同一ポートで受け付けられ、許可ドメインへ正しく中継されることを確認する。
    #[tokio::test]
    async fn h2c_prior_knowledge_request_is_proxied() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let (reader, mut writer) = sock.split();
            let mut reader = BufReader::new(reader);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                if line == "\r\n" {
                    break;
                }
            }
            writer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let config = NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let proxy = spawn_local_proxy(&config).await.unwrap().unwrap();

        let stream = TcpStream::connect(proxy.addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri: Uri = format!("http://localhost:{}/", target_addr.port())
            .parse()
            .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    /// SNI検査に使うClientHelloを実際にrustlsで生成する（`sni`拡張のみ最低限、TLS1.2）。
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| {
                let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());
                provider
            });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let mut conn =
            rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
        let mut buf = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut buf).unwrap();
        }
        buf
    }

    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .map(|p| p.signature_verification_algorithms.supported_schemes())
                .unwrap_or_default()
        }
    }
}
