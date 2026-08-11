//! 承認の前に**サーバが実際に提示する証明書を見る**（D-52、`plans/DESIGN-MCP.md` §6.2）。
//!
//! `tls_pin`は「この1枚だけを受け入れる」という宣言だが、64桁の16進を見ただけでは何を
//! 承認しようとしているのか判断できない。`harness mcp approve`が発行元・サブジェクト・SAN・
//! 有効期限・指紋を並べて出せるように、TLSハンドシェイクだけを行って証明書を取り出す。
//!
//! ## 何を送らないか
//!
//! **HTTPリクエストは一切送らない。** ハンドシェイクが終わった時点で接続を捨てるので、
//! 宣言されたヘッダ（認証トークン）も、MCPのメッセージも、まだ承認していない相手へは渡らない。
//! 「承認前に繋ぐ」ことの正当性はここに掛かっている。
//!
//! ## なぜ検証しない検証器を使うのか
//!
//! ここでの目的は**判断材料を人へ見せること**であって、信頼の判定ではない。信頼の判定は
//! ユーザーが指紋を見て行い、以後の実接続は[`crate::transport_http`]の検証器
//! （ピン一致 or 通常の証明書検証）が強制する。したがってこの下見は、自己署名でも期限切れでも
//! 名前が合わなくても**中身を見せられなければ意味がない**ので、鎖と名前の検証を通さない。
//!
//! **この検証器を`transport_http`から使ってはならない。** 分けてあるのはそのためで、
//! こちらはHTTPを一言も喋らない経路に閉じている。

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::http_wire::{CertPin, ParsedUrl};
use crate::McpError;

/// 下見のタイムアウト（TCP接続とハンドシェイクの合計）。
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// 提示された証明書のうち、人が承認可否を判断するために要る情報。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCertificate {
    /// この証明書のSHA-256（＝宣言へ書く`tls_pin`の値）。
    pub pin: CertPin,
    /// サブジェクトDN（`CN=mcp.corp.internal, O=...`）。
    pub subject: String,
    /// 発行元DN。自己署名ならサブジェクトと同じになる。
    pub issuer: String,
    /// SANのDNS名・IPアドレス。空なら「SANなし」。
    pub subject_alt_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    /// 発行元とサブジェクトが同一（＝自己署名、いわゆるオレオレ証明書）。
    pub self_signed: bool,
    /// 提示された中間証明書の枚数（0なら単独提示）。
    pub chain_length: usize,
}

impl PresentedCertificate {
    /// 承認プロンプトへ出す複数行。**指紋・発行元・接続先の3点が並ぶ**ことが要件。
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("    subject:     {}\n", self.subject));
        out.push_str(&format!(
            "    issuer:      {}{}\n",
            self.issuer,
            if self.self_signed {
                "  (self-signed)"
            } else {
                ""
            }
        ));
        out.push_str(&format!(
            "    names:       {}\n",
            if self.subject_alt_names.is_empty() {
                "(no subjectAltName -- some platforms fall back to the subject CN, others reject)"
                    .to_string()
            } else {
                self.subject_alt_names.join(", ")
            }
        ));
        out.push_str(&format!(
            "    valid:       {} .. {}\n",
            self.not_before, self.not_after
        ));
        out.push_str(&format!(
            "    chain:       {} certificate(s) presented\n",
            self.chain_length
        ));
        out.push_str(&format!("    sha256:      {}\n", self.pin.to_readable()));
        out
    }
}

/// エンドポイントへTLSハンドシェイクだけ行い、提示された証明書を返す。
///
/// httpのエンドポイント（loopback等）では`Ok(None)`——見るべき証明書が無い。
///
/// **引数が[`Endpoint`]ではなく[`ParsedUrl`]なのは意図的である。** [`Endpoint`]は
/// D-49のゲート（宛先allowlist・平文の可否）を通った証だが、それらは「**接続して喋って
/// よいか**」のゲートである。この関数は一言も喋らないので、同じゲートを課すと
/// 「まだallowlistへ入れていないサーバの証明書を見て、入れるか決める」ができなくなる。
pub fn probe(endpoint: &ParsedUrl) -> Result<Option<PresentedCertificate>, McpError> {
    if !endpoint.is_tls() {
        return Ok(None);
    }
    let host = endpoint.host().to_string();
    let port = endpoint.port();

    let chain = fetch_chain(&host, port)?;
    let Some(end_entity) = chain.first() else {
        return Err(McpError::Io(
            "the server completed the tls handshake without presenting a certificate".to_string(),
        ));
    };
    Ok(Some(parse_presented(end_entity, chain.len())))
}

/// ハンドシェイクを行い、提示された証明書チェーンのDERを取り出す。
fn fetch_chain(host: &str, port: u16) -> Result<Vec<Vec<u8>>, McpError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| McpError::Io(format!("could not configure tls for the probe: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaptureOnlyVerifier { provider }))
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| McpError::Io(format!("{host:?} is not a usable tls server name: {e}")))?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| McpError::Io(format!("could not start the tls handshake: {e}")))?;

    let addr = format!("{host}:{port}");
    let socket_addr = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .map_err(|e| McpError::Io(format!("could not resolve {addr}: {e}")))?
        .next()
        .ok_or_else(|| McpError::Io(format!("{addr} resolved to no addresses")))?;
    let mut socket = TcpStream::connect_timeout(&socket_addr, PROBE_TIMEOUT)
        .map_err(|e| McpError::Io(format!("could not connect to {addr}: {e}")))?;
    socket
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(PROBE_TIMEOUT)))
        .map_err(|e| McpError::Io(format!("could not set the probe timeout: {e}")))?;

    // ハンドシェイクだけ回す。アプリケーションデータは1バイトも書かない。
    while connection.is_handshaking() {
        let (_, _) = connection
            .complete_io(&mut socket)
            .map_err(|e| McpError::Io(format!("tls handshake with {addr} failed: {e}")))?;
    }
    let chain = connection
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
        .unwrap_or_default();

    connection.send_close_notify();
    let _ = connection.complete_io(&mut socket);
    let _ = socket.flush();
    Ok(chain)
}

/// 表示のためだけに証明書を読む。**この結果は信頼の判断に一切入らない**（モジュールdoc）。
fn parse_presented(der: &[u8], chain_length: usize) -> PresentedCertificate {
    let pin = CertPin::of_certificate(der);
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        // 読めなくても指紋は出せる。ピンだけで承認するユーザーの判断材料は残る。
        return PresentedCertificate {
            pin,
            subject: "(unparsable certificate)".to_string(),
            issuer: "(unparsable certificate)".to_string(),
            subject_alt_names: Vec::new(),
            not_before: "(unknown)".to_string(),
            not_after: "(unknown)".to_string(),
            self_signed: false,
            chain_length,
        };
    };

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let mut subject_alt_names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => {
                    subject_alt_names.push((*dns).to_string())
                }
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    subject_alt_names.push(render_ip(bytes))
                }
                other => subject_alt_names.push(format!("{other:?}")),
            }
        }
    }

    PresentedCertificate {
        pin,
        self_signed: subject == issuer,
        subject,
        issuer,
        subject_alt_names,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        chain_length,
    }
}

fn render_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => format!("{bytes:02x?}"),
    }
}

/// 提示された証明書を受け取るためだけの検証器（モジュールdoc参照）。
///
/// ハンドシェイク署名は標準実装へ委譲する——サーバがその証明書の秘密鍵を持っていないなら、
/// 見せられた証明書は「そのサーバのもの」ですらないので、判断材料として出す意味が無い。
#[derive(Debug)]
struct CaptureOnlyVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for CaptureOnlyVerifier {
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
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// httpのエンドポイントには見るべき証明書が無い（loopbackのローカル開発サーバ等）。
    #[test]
    fn a_plaintext_endpoint_has_no_certificate_to_show() {
        let endpoint = crate::http_wire::parse_endpoint_url("http://127.0.0.1:3000/mcp").unwrap();
        assert_eq!(probe(&endpoint).unwrap(), None);
    }

    /// 既定ポートはスキームから補う（`https://host/mcp`で443を引く）。
    #[test]
    fn the_port_defaults_to_the_scheme() {
        let https = crate::http_wire::parse_endpoint_url("https://mcp.corp.example/mcp").unwrap();
        assert_eq!(https.port(), 443);
        let explicit =
            crate::http_wire::parse_endpoint_url("https://mcp.corp.example:8443/mcp").unwrap();
        assert_eq!(explicit.port(), 8443);
    }

    /// 読めない証明書でも指紋だけは出す（ピンで承認する判断材料は残る）。
    #[test]
    fn an_unparsable_certificate_still_yields_its_fingerprint() {
        let presented = parse_presented(b"not a certificate", 1);
        assert_eq!(presented.pin, CertPin::of_certificate(b"not a certificate"));
        assert!(presented.subject.contains("unparsable"));
        assert!(presented
            .describe()
            .contains("sha256:".trim_end_matches(':')));
    }

    #[test]
    fn ip_subject_alt_names_are_rendered_readably() {
        assert_eq!(render_ip(&[127, 0, 0, 1]), "127.0.0.1");
        assert_eq!(render_ip(&[0u8; 16]), "::");
    }
}
