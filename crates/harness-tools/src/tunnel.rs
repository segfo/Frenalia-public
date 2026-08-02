//! CONNECT/SOCKS5トンネルの寿命全体を所有する検査層。v1では`SniTunnelHandler`
//! （ClientHelloの平文部分（SNI/ALPN）だけを見て、あとは復号せず素通しする）のみを実装する。
//!
//! この`TunnelHandler` trait自体は、CONNECT/SOCKS5の受理ロジック（`net_proxy.rs`）を
//! 変更せずに検査層を差し替えられるように設計した拡張点である。将来、監査目的で
//! トンネルを復号（MITM）したい場合は、同じtraitを実装する別のハンドラ（両側のTLSを
//! 終端し、復号したHTTPを監査してから再暗号化して中継する）を用意し、`net_proxy`の
//! 呼び出し元でハンドラの実装を差し替えるだけでよい。ストリームを`Box<dyn AsyncStream>`
//! （具体型に固定しない）にしているのはこのためで、復号層は`client`/`upstream`を
//! `tokio_rustls`の`TlsAcceptor`/`TlsConnector`で包み直せる。
//!
//! 復号層を実際に追加する場合の前提条件は
//! `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`§5.5参照
//! （CA信頼配布・証明書ピンニングするクライアントの破壊・監査ログの機密性・
//! `docs/SECURITY-PRINCIPLES.md`上位原則との整合、の4点）。

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use harness_core::DomainPolicy;

use crate::net_proxy::NetAuditLog;
use crate::tls_sni::{peek_client_hello, SniPeek};

/// トンネル両端が満たすべき能力。`Box<dyn AsyncStream>`はTLS終端後のストリームへ
/// 差し替え可能にするための境界であり、具体的な`TcpStream`/`Upgraded`型に固定しない。
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> AsyncStream for T {}

/// 検査層へ渡す一式。復号層が必要とするものを最初から全部載せておく。
pub struct Tunnel<'a> {
    pub protocol: &'static str,
    pub connect_host: String,
    pub connect_port: u16,
    pub client: Box<dyn AsyncStream>,
    pub upstream: Box<dyn AsyncStream>,
    pub policy: &'a DomainPolicy,
    pub audit: &'a NetAuditLog,
}

#[async_trait]
pub trait TunnelHandler: Send + Sync {
    async fn handle(&self, tunnel: Tunnel<'_>) -> io::Result<()>;
}

/// v1のトンネル検査層: ClientHelloのSNI/ALPNを見てallowlist評価し、監査へ記録した上で
/// 中身は復号せず`copy_bidirectional`で中継する。
pub struct SniTunnelHandler {
    pub sni_timeout: Duration,
    pub max_client_hello_bytes: usize,
}

impl Default for SniTunnelHandler {
    fn default() -> Self {
        Self {
            sni_timeout: Duration::from_secs(5),
            max_client_hello_bytes: 16 * 1024,
        }
    }
}

#[async_trait]
impl TunnelHandler for SniTunnelHandler {
    async fn handle(&self, tunnel: Tunnel<'_>) -> io::Result<()> {
        let Tunnel {
            connect_host,
            connect_port,
            mut client,
            mut upstream,
            policy,
            audit,
            ..
        } = tunnel;

        let (peek, raw) =
            peek_client_hello(&mut client, self.sni_timeout, self.max_client_hello_bytes).await?;

        let mut denied = false;
        match peek {
            SniPeek::Sni { host, alpn } => {
                let decision = policy.evaluate_host(&host);
                let reason = if !decision.allowed {
                    denied = true;
                    "sni_denied"
                } else if !host.eq_ignore_ascii_case(&connect_host) {
                    "sni_host_mismatch"
                } else {
                    "domain_allowed"
                };
                audit.record_tls_sni(
                    host,
                    Some(connect_port),
                    decision.allowed,
                    reason,
                    decision.matched_pattern,
                    Some(connect_host.clone()),
                    Some(alpn),
                );
            }
            SniPeek::NoSni => {
                audit.record_tls_sni(
                    connect_host.clone(),
                    Some(connect_port),
                    true,
                    "sni_absent",
                    None,
                    Some(connect_host.clone()),
                    None,
                );
            }
            SniPeek::NotTls => {
                audit.record_tls_sni(
                    connect_host.clone(),
                    Some(connect_port),
                    true,
                    "sni_not_tls",
                    None,
                    Some(connect_host.clone()),
                    None,
                );
            }
        }

        if denied {
            return Ok(());
        }

        if !raw.is_empty() {
            upstream.write_all(&raw).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok(())
    }
}
