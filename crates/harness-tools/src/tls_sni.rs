//! CONNECT/SOCKS5トンネル確立後、TLS ClientHelloのSNI（Server Name Indication）を
//! 復号せずに覗き見るための最小限のヘルパー。`rustls::server::Acceptor`は
//! ClientHelloのパースだけを行い、`Accepted::into_connection`を呼ばない限り
//! crypto providerも証明書も要らないため、これを流用する。
//!
//! `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`§5.5参照。

use std::time::Duration;

use tokio::io::AsyncReadExt;

const READ_CHUNK: usize = 4096;

/// ClientHelloの覗き見結果。
#[derive(Debug, Clone)]
pub enum SniPeek {
    /// TLS ClientHelloを検出し、SNIを取得できた（ALPNは付随情報、無ければ空）。
    Sni { host: String, alpn: Vec<String> },
    /// TLS ClientHelloではあったがSNI拡張が無かった。
    NoSni,
    /// TLSのClientHelloとして解釈できなかった（非TLSトンネル、タイムアウト、EOF等）。
    NotTls,
}

/// クライアント側ストリームからTLS ClientHelloを読み、SNIを取り出す。
///
/// 読み取った生バイト列は`(peek, raw)`の`raw`としてそのまま返す。呼び出し側はこれを
/// 上流へ書き戻すことで、実際にTLSを終端せずトンネルを継続できる
/// （このモジュールはMITMしない。復号層を追加する場合は`crate::tunnel`の
/// `TunnelHandler`を差し替える）。
pub async fn peek_client_hello<S>(
    stream: &mut S,
    timeout: Duration,
    max_bytes: usize,
) -> std::io::Result<(SniPeek, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut acceptor = rustls::server::Acceptor::default();
    let mut raw = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let mut chunk = [0u8; READ_CHUNK];
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => return Ok((SniPeek::NotTls, raw)),
        };
        if n == 0 {
            return Ok((SniPeek::NotTls, raw));
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > max_bytes {
            return Ok((SniPeek::NotTls, raw));
        }

        let mut slice = &chunk[..n];
        if acceptor.read_tls(&mut slice).is_err() {
            return Ok((SniPeek::NotTls, raw));
        }

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let hello = accepted.client_hello();
                let alpn: Vec<String> = hello
                    .alpn()
                    .map(|protocols| {
                        protocols
                            .filter_map(|p| std::str::from_utf8(p).ok().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                return Ok(match hello.server_name() {
                    Some(host) => (
                        SniPeek::Sni {
                            host: host.to_string(),
                            alpn,
                        },
                        raw,
                    ),
                    None => (SniPeek::NoSni, raw),
                });
            }
            Ok(None) => continue,
            Err(_) => return Ok((SniPeek::NotTls, raw)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    /// 最小のTLS 1.2 ClientHello（SNI=`example.com`、ALPN=`http/1.1`）をrustlsの
    /// クライアント実装で実際に生成し、`peek_client_hello`が同じ値を復元できることを確認する。
    #[tokio::test]
    async fn peek_client_hello_extracts_sni_and_alpn() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );
        let (mut client_io, mut server_io) = duplex(64 * 1024);

        let hello_task = tokio::spawn(async move {
            let config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
                .with_no_client_auth();
            let mut config = config;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let server_name = rustls::pki_types::ServerName::try_from("example.com").unwrap();
            let mut conn =
                rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
            let mut buf = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut buf).unwrap();
            }
            client_io.write_all(&buf).await.unwrap();
        });

        let (peek, raw) = peek_client_hello(&mut server_io, Duration::from_secs(5), 16 * 1024)
            .await
            .unwrap();
        hello_task.await.unwrap();

        assert!(!raw.is_empty());
        match peek {
            SniPeek::Sni { host, alpn } => {
                assert_eq!(host, "example.com");
                assert_eq!(alpn, vec!["http/1.1".to_string()]);
            }
            other => panic!("expected Sni, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn peek_client_hello_returns_not_tls_for_plain_text() {
        let (mut client_io, mut server_io) = duplex(1024);
        client_io
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        drop(client_io);

        let (peek, raw) = peek_client_hello(&mut server_io, Duration::from_secs(2), 16 * 1024)
            .await
            .unwrap();
        assert!(matches!(peek, SniPeek::NotTls));
        assert_eq!(raw, b"GET / HTTP/1.1\r\n\r\n");
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
