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

use harness_core::{parse_tool_input, PermissionSubject};
use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};

const DEFAULT_MAX_BYTES: usize = 1_048_576; // 1 MiB
const MAX_REDIRECTS: usize = 5;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
// 知らない項目は拒否する（BUG-164・D-101）。余分な項目を黙って捨てると、判定だけを騙す細工を
// 最後まで通す部品になる。
#[serde(deny_unknown_fields)]
struct WebFetchInput {
    url: String,
    max_bytes: Option<usize>,
}

/// URLの文字列を解析し、**http/httpsのときだけ**正規化したURLを返す（モジュールdocのガード(4)の入口）。
///
/// `web_fetch`の入口と、会話TUIがリンクを開く前（`harness-tui`の`open_url`）が同じこれを通る——開いてよい形式の
/// 判定を2か所に写さない。返す`Url`の文字列（`as_str`）は正規化した形（スキームとホストは小文字・空白などは
/// `%`で符号化・パスの無いものは`/`）で、検査した値と使う値を別物にしないよう、呼び出し側はこれを使う（B-21）。
/// スキームの無い相対URL（`foo.html`・`//host/path`）は解析できないので断る。
pub fn parse_http_url(raw: &str) -> Result<reqwest::Url, HttpUrlError> {
    let url = reqwest::Url::parse(raw).map_err(HttpUrlError::Invalid)?;
    ensure_http_scheme(&url)?;
    Ok(url)
}

/// [`parse_http_url`]が断った理由。文面（`Display`）は`web_fetch`がモデルへ返す文面と同じ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpUrlError {
    /// URLとして解析できない（相対URLを含む）。中身は`url`クレートの`ParseError`（reqwestは型の名前を再公開して
    /// いないので、`FromStr`の失敗の型として書く）。
    Invalid(<reqwest::Url as std::str::FromStr>::Err),
    /// http/https以外の形式（中身はスキーム）。
    Scheme(String),
}

impl std::fmt::Display for HttpUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid url: {e}"),
            Self::Scheme(scheme) => write!(f, "only http(s) schemes are allowed: {scheme}"),
        }
    }
}

impl std::error::Error for HttpUrlError {}

/// `url`がhttp/httpsか（入口と、リダイレクトの毎ホップで同じこれを通す）。
fn ensure_http_scheme(url: &reqwest::Url) -> Result<(), HttpUrlError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(HttpUrlError::Scheme(other.to_string())),
    }
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

    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        let input: WebFetchInput = parse_tool_input(input)?;
        Ok(PermissionSubject::Text(input.url))
    }

    async fn call(
        &self,
        input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let input: WebFetchInput = parse_tool_input(&input)?;
        let max_bytes = input.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);

        let mut current_url =
            parse_http_url(&input.url).map_err(|e| ToolError::InvalidInput(e.to_string()))?;

        for _ in 0..=MAX_REDIRECTS {
            // リダイレクト先も毎ホップ同じ判定で検査する（モジュールdocのガード(2)）。
            ensure_http_scheme(&current_url).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
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

    /// `parse_http_url`（`web_fetch`の入口の判定。会話TUIがリンクを開く前にも使う）: http/httpsだけを通し、
    /// 正規化した形（スキームとホストは小文字・空白は`%20`・パスの無いものは`/`）を返す。それ以外の形式と、
    /// スキームの無い相対URLは断る。断るときの文面は`web_fetch`が返してきたものと同じ。
    #[test]
    fn parse_http_url_accepts_only_http_and_https_and_normalises() {
        let accepted = [
            ("HTTPS://Example.COM/a b", "https://example.com/a%20b"),
            ("http://e.x", "http://e.x/"),
            ("https://example.com/a?q=1#f", "https://example.com/a?q=1#f"),
        ];
        for (raw, normalised) in accepted {
            let url = parse_http_url(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(url.as_str(), normalised, "{raw}");
        }
        let refused = [
            "file:///C:/x",
            "javascript:alert(1)",
            "ms-msdt:id",
            "search-ms:query=x",
            "data:text/html,x",
            "vbscript:msgbox(1)",
            "mailto:a@b",
            "ftp://e.x/",
            "foo.html",
            "//host/path",
        ];
        for raw in refused {
            assert!(parse_http_url(raw).is_err(), "{raw}");
        }
        assert_eq!(
            parse_http_url("ftp://e.x/").unwrap_err().to_string(),
            "only http(s) schemes are allowed: ftp"
        );
        assert!(parse_http_url("foo.html")
            .unwrap_err()
            .to_string()
            .starts_with("invalid url: "));
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
