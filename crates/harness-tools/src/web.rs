//! `web_fetch`。`plans/DESIGN.md` §ツールシステム「組み込みツール」`web_fetch`参照。
//!
//! **SSRFガード（無効化不可）**: (1) resolve-and-pin — 全候補IPを自前解決し検証済みIPへ
//! 直接接続（`reqwest::ClientBuilder::resolve`、Hostヘッダは元のホスト名のまま）＝接続時
//! 再解決によるDNSリバインディングを封じる。(2) リダイレクトは`Policy::none()`+手動ループで
//! 毎ホップ再検査（既定追従だと公開URL→IMDSへ誘導され得る）。(3) loopback/link-local/private・
//! IPv6特殊アドレス・数値/別表記IPv4・クラウドメタデータを拒否。(4) 非http(s)スキームは拒否。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};

const DEFAULT_MAX_BYTES: usize = 1_048_576; // 1 MiB
const MAX_REDIRECTS: usize = 5;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct WebFetchInput {
    url: String,
    max_bytes: Option<usize>,
}

pub struct WebFetchTool;

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "URLをHTTP(S) GETで取得する。SSRF対策（プライベート/リンクローカル/メタデータアドレス拒否・DNS再解決固定）を常時適用する。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "取得するhttp(s) URL" },
                "max_bytes": { "type": "integer", "description": "取得する最大バイト数（省略時1MiB）" }
            },
            "required": ["url"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Network
    }

    async fn call(
        &self,
        input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let input: WebFetchInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);

        let mut current_url = reqwest::Url::parse(&input.url)
            .map_err(|e| ToolError::InvalidInput(format!("invalid url: {e}")))?;

        for _ in 0..=MAX_REDIRECTS {
            if current_url.scheme() != "http" && current_url.scheme() != "https" {
                return Err(ToolError::InvalidInput(format!(
                    "only http(s) schemes are allowed: {}",
                    current_url.scheme()
                )));
            }
            let host = current_url
                .host_str()
                .ok_or_else(|| ToolError::InvalidInput("url has no host".to_string()))?
                .to_string();
            let port = current_url
                .port_or_known_default()
                .ok_or_else(|| ToolError::InvalidInput("url has no resolvable port".to_string()))?;

            let ip = resolve_pinned(&host, port).await?;

            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .resolve(&host, SocketAddr::new(ip, port))
                .timeout(FETCH_TIMEOUT)
                .build()
                .map_err(|e| ToolError::ExecutionFailed(format!("client build failed: {e}")))?;

            let resp = client
                .get(current_url.clone())
                .send()
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("request failed: {e}")))?;

            if resp.status().is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        ToolError::ExecutionFailed("redirect without Location header".to_string())
                    })?;
                current_url = current_url.join(location).map_err(|e| {
                    ToolError::ExecutionFailed(format!("invalid redirect target: {e}"))
                })?;
                continue;
            }

            let status = resp.status();
            let bytes = read_body_limited(resp, max_bytes).await?;
            let text = String::from_utf8_lossy(&bytes).to_string();
            return Ok(ToolOutput {
                content: format!("[status: {status}]\n{text}"),
                is_error: !status.is_success(),
            });
        }

        Err(ToolError::ExecutionFailed(format!(
            "too many redirects (> {MAX_REDIRECTS})"
        )))
    }
}

async fn read_body_limited(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ToolError> {
    use futures_util::StreamExt;

    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| ToolError::ExecutionFailed(format!("body read failed: {e}")))?;
        if buf.len() + chunk.len() > max_bytes {
            let remaining = max_bytes.saturating_sub(buf.len());
            buf.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    if truncated {
        buf.extend_from_slice(b"\n[truncated at max_bytes]");
    }
    Ok(buf)
}

/// ホストをDNS解決し、ブロック対象でない最初のIPへ「固定」する
/// （resolve-and-pin、§ツールシステム web_fetch）。
async fn resolve_pinned(host: &str, port: u16) -> Result<IpAddr, ToolError> {
    if is_blocked_hostname(host) {
        return Err(ToolError::InvalidInput(format!("blocked hostname: {host}")));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(ToolError::InvalidInput(format!("blocked address: {ip}")));
        }
        return Ok(ip);
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("dns resolution failed: {e}")))?;

    addrs
        .map(|a| a.ip())
        .find(|ip| !is_blocked_ip(*ip))
        .ok_or_else(|| {
            ToolError::InvalidInput(format!("no non-blocked address resolved for host: {host}"))
        })
}

/// メタデータサービスのホスト名（IPブロックの補強、§ツールシステム web_fetch）。
fn is_blocked_hostname(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "metadata.google.internal" | "metadata" | "instance-data"
    )
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            if v6.is_unique_local() || v6.is_unicast_link_local() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback_and_private_v4() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.5".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_loopback_link_local_and_unique_local() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd00:ec2::254".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_private_v6() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_numeric_ipv4_literal_via_url_normalization() {
        // WHATWG URLホストパース（`url`クレート、reqwest::Url経由）は10進数値等の
        // 別表記IPv4を正準ドット表記へ正規化するため、host_str()の時点で既に "127.0.0.1"。
        let url = reqwest::Url::parse("http://2130706433/").unwrap();
        assert_eq!(url.host_str(), Some("127.0.0.1"));
    }

    #[tokio::test]
    async fn resolve_pinned_rejects_blocked_hostname() {
        let err = resolve_pinned("metadata.google.internal", 80)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn resolve_pinned_rejects_loopback_ip_literal() {
        let err = resolve_pinned("127.0.0.1", 80).await.unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }
}
