//! Streamable HTTP（`plans/DESIGN-MCP.md` §6.2）の**純粋な判断だけ**を持つモジュール。
//!
//! ここにあるのは「接続してよい相手か」「ヘッダをどう組むか」「返ってきたバイト列をどう
//! 区切るか」で、いずれもソケットを開かずに単体テストで固定できる
//! （`docs/CODE-STRUCTURE-RULES.md` 規則3）。実際に喋る側は[`crate::transport_http`]。
//!
//! ## なぜ判定を1関数へ集約するのか
//!
//! [`validate_endpoint`]はスキーム・ホスト・loopback・平文の可否・ドメインallowlistを
//! **1箇所で順序込みで**決める。ゲートを呼び出し側へ散らすと、`harness mcp list`の表示と
//! 起動時の判定と`describe()`の警告文がそれぞれ別の条件を見るようになり、
//! 「一覧では起動できそうに見えるのに起動しない」が生まれる。
//!
//! ## resolve-and-pin をしない理由
//!
//! `web_fetch`（`crates/harness-tools/src/web.rs`）は全候補IPを自前解決して固定するが、
//! あれは**モデルが渡した任意のURL**が内部アドレスへ届くのを防ぐための機構である。こちらの
//! 宛先は「ユーザ層allowlistに載り、`harness mcp approve`され、リダイレクトを追わない」もの
//! だけで、しかもhttpsならTLSが**名前**を検証する。IPを固定しても足せる保証が無い。

use std::collections::BTreeMap;

use harness_core::net_policy::DomainPolicy;

/// [`validate_endpoint`]が参照するセッション側のゲート（D-49）。
///
/// **`Default`は「何も許さない」**（allowlist空・平文不可）。
#[derive(Debug, Clone)]
pub struct EndpointGates {
    /// ユーザ層設定`mcp.http_allow_domains`＋CLI `--mcp-http-allow`の和集合。
    /// **空なら何も通さない**（closed-by-default）。
    pub allow_domains: DomainPolicy,
    /// **平文httpを許すドメイン**（CLIで`--mcp-http-allow http://<host>`と書いたものだけ）。
    /// 設定ファイル・宣言側からは立てられない。
    ///
    /// **全体の真偽値ではなくドメインの集合なのは、緩和を書いた先だけに効かせるためである。**
    /// かつては`--allow-mcp-http-plaintext`という単一の真偽フラグで、1つのホストを平文で
    /// 使いたいだけでも**許可リスト全体**の平文が開いた。緩和の綴りが指しているものより
    /// 広い範囲へ効くのは、`bug-pattern-rules` B-01の「対の片側だけが広い」型である。
    pub plaintext_domains: DomainPolicy,
}

impl Default for EndpointGates {
    fn default() -> Self {
        Self {
            allow_domains: DomainPolicy::new(Vec::new()),
            plaintext_domains: DomainPolicy::new(Vec::new()),
        }
    }
}

/// `--mcp-http-allow <値>`の値1件を「ドメインパターン」と「平文を許すか」へ分解する。
///
/// **値の書式がそのまま緩和の内容になる**（`plans/DESIGN-CLI-OPTIONS.md` §4.9 対象6）。
///
/// | 書き方 | 意味 |
/// |---|---|
/// | `mcp.corp.example` | httpsのみ |
/// | `https://mcp.corp.example` | 同上（スキームを書いても同じ） |
/// | `http://mcp.corp.example` | **そのドメインだけ**平文httpも許す |
/// | `*.corp.example` | サフィックスワイルドカード（`http://*.corp.example`も書ける） |
///
/// **パス・ポート・認証情報が付いていたら拒否する。** ここが受け取るのは宛先の
/// ドメインパターンであってURLではない——`https://mcp.corp.example/mcp`を黙って
/// ドメインだけ取り出すと、「パスまで絞ったつもり」の指定が**ホスト全体の許可**として
/// 通ってしまう（宣言より広い実態になる向きの取り違え）。
pub fn parse_http_allow_value(raw: &str) -> Result<(String, bool), String> {
    let trimmed = raw.trim();
    let (rest, plaintext) = match trimmed
        .split_once("://")
        .map(|(scheme, rest)| (scheme.to_ascii_lowercase(), rest))
    {
        Some((scheme, rest)) if scheme == "http" => (rest, true),
        Some((scheme, rest)) if scheme == "https" => (rest, false),
        Some((scheme, _)) => {
            return Err(format!(
                "--mcp-http-allow {raw:?}: unsupported scheme {scheme:?} (write a domain, or \
                 prefix it with http:// or https://)"
            ))
        }
        None => (trimmed, false),
    };
    if rest.contains('/') || rest.contains(':') || rest.contains('@') || rest.contains('?') {
        return Err(format!(
            "--mcp-http-allow {raw:?}: this flag takes a domain pattern, not a URL (drop the \
             path/port/credentials; URL-granularity allowlisting is a separate mechanism)"
        ));
    }
    let domain = harness_core::normalize_domain_pattern(rest)
        .map_err(|e| format!("--mcp-http-allow {raw:?}: {e}"))?;
    Ok((domain, plaintext))
}

/// 検証済みのエンドポイント。**この型は[`validate_endpoint`]からしか作れない**ので、
/// ゲートを通っていないURLでトランスポートが接続する経路が存在しない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: String,
    host: String,
    /// `host[:port]` + path。認証情報もクエリも含めない、表示専用の文字列。
    display: String,
    is_loopback: bool,
    is_tls: bool,
}

impl Endpoint {
    /// 実際にPOSTするURL（宣言に書かれたまま。正規化で別のURLにしない）。
    pub fn url(&self) -> &str {
        &self.url
    }

    /// allowlist照合・TLS検証の対象になるホスト名。
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn is_loopback(&self) -> bool {
        self.is_loopback
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// システムプロンプト・`harness mcp list`へ出す短い表示（認証情報は含めない）。
    pub fn display(&self) -> &str {
        &self.display
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpWireError {
    #[error("not a valid url: {0}")]
    Unparsable(String),
    #[error("only http and https urls are supported, got {scheme:?}")]
    UnsupportedScheme { scheme: String },
    #[error("the url has no host")]
    NoHost,
    #[error(
        "plaintext http to a remote host sends the declared headers (including any credentials) \
         in the clear; pass --allow-mcp-http-plaintext for this session if that is what you want"
    )]
    PlaintextNotAllowed,
    #[error(
        "host {host:?} is not in the streamable-http allowlist; add it to \"http_allow_domains\" \
         in your user settings.json or pass --allow-mcp-http-domain {host}"
    )]
    HostNotAllowlisted { host: String },
    #[error("{host:?} is an ip literal; the streamable-http allowlist matches domain names only")]
    IpLiteralHost { host: String },
}

/// URLの**形**だけを見る（ゲートは見ない）。宣言の`validate()`から呼ぶ。
///
/// 解析の実装をここ1箇所に持つことで、`decl::validate`が通したURLと
/// [`validate_endpoint`]が接続するURLが食い違わない。
pub fn parse_endpoint_url(url: &str) -> Result<ParsedUrl, HttpWireError> {
    let parsed =
        reqwest::Url::parse(url.trim()).map_err(|e| HttpWireError::Unparsable(e.to_string()))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(HttpWireError::UnsupportedScheme { scheme });
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(HttpWireError::NoHost)?
        .to_ascii_lowercase();
    let display = match parsed.port() {
        Some(port) => format!("{host}:{port}{}", parsed.path()),
        None => format!("{host}{}", parsed.path()),
    };
    Ok(ParsedUrl {
        url: url.trim().to_string(),
        display,
        is_loopback: is_loopback_host(&host),
        is_tls: scheme == "https",
        host,
    })
}

/// [`parse_endpoint_url`]の結果。ゲート判定前なので[`Endpoint`]とは別の型にしてある。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    url: String,
    host: String,
    display: String,
    is_loopback: bool,
    is_tls: bool,
}

impl ParsedUrl {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// 明示ポート、無ければスキーム既定（https=443 / http=80）。
    pub fn port(&self) -> u16 {
        reqwest::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.port_or_known_default())
            .unwrap_or(if self.is_tls { 443 } else { 80 })
    }
}

/// 形とゲートの両方を通す。**接続前に必ずここを通る。**
///
/// 判定順序は「形 → 平文 → allowlist」。平文を先に見るのは、`http://evil.example`のような
/// URLに対して「allowlistに足せば通る」と読める案内を出さないため。
pub fn validate_endpoint(url: &str, gates: &EndpointGates) -> Result<Endpoint, HttpWireError> {
    let parsed = parse_endpoint_url(url)?;

    // loopbackはマシンの外へ出ない。平文もallowlistも免除する——`DomainPolicy`はIPリテラルを
    // 常に拒否するので、免除しないと`http://127.0.0.1:3000/mcp`という最も普通のローカル開発
    // 構成が一切書けなくなる。
    if parsed.is_loopback {
        return Ok(Endpoint {
            url: parsed.url,
            host: parsed.host,
            display: parsed.display,
            is_loopback: true,
            is_tls: parsed.is_tls,
        });
    }

    // 平文は**そのドメインについて**許されているときだけ通す（`http://`付きで書いた分）。
    if !parsed.is_tls && !gates.plaintext_domains.evaluate_host(&parsed.host).allowed {
        return Err(HttpWireError::PlaintextNotAllowed);
    }

    let decision = gates.allow_domains.evaluate_host(&parsed.host);
    if !decision.allowed {
        // `DomainPolicy`はIPリテラルを「パターンとして書けない」ものとして常に拒否する。
        // allowlistに足せば直るかのような案内にならないよう、理由を分ける。
        if harness_core::net_policy::is_ip_literal(&parsed.host) {
            return Err(HttpWireError::IpLiteralHost { host: parsed.host });
        }
        return Err(HttpWireError::HostNotAllowlisted { host: parsed.host });
    }

    Ok(Endpoint {
        url: parsed.url,
        host: parsed.host,
        display: parsed.display,
        is_loopback: false,
        is_tls: parsed.is_tls,
    })
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

// --- ヘッダ ---

/// 宣言のヘッダ値に書かれた`${env:NAME}`を展開する。
///
/// **未定義のenvはエラー**にする。空文字を送ると、サーバからは401が返るだけで
/// 「環境変数を設定し忘れた」という本当の原因がどこにも出ない。
///
/// `lookup`を注入するのは、テストがプロセスのenvを汚さずに固定できるようにするため。
pub fn expand_headers(
    headers: &BTreeMap<String, String>,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>, HeaderError> {
    let mut out = Vec::with_capacity(headers.len());
    for (name, raw) in headers {
        out.push((name.clone(), expand_one(name, raw, lookup)?));
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error(
        "http header {header:?} references the environment variable {var:?}, which is not set in \
         harness's own environment"
    )]
    MissingEnv { header: String, var: String },
    #[error("http header {header:?} has an unterminated ${{env:...}} reference")]
    Unterminated { header: String },
    #[error("http header {header:?} expands to a value that cannot be sent in an http header")]
    UnsendableValue { header: String },
}

const ENV_REF_PREFIX: &str = "${env:";

fn expand_one(
    header: &str,
    raw: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, HeaderError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find(ENV_REF_PREFIX) {
        out.push_str(&rest[..start]);
        let after = &rest[start + ENV_REF_PREFIX.len()..];
        let Some(end) = after.find('}') else {
            return Err(HeaderError::Unterminated {
                header: header.to_string(),
            });
        };
        let var = &after[..end];
        let value = lookup(var).ok_or_else(|| HeaderError::MissingEnv {
            header: header.to_string(),
            var: var.to_string(),
        })?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);

    // 展開結果に制御文字が入るとヘッダ分割になる。envの中身は未検証の外来値なので必ず見る。
    if out.chars().any(|c| c.is_control()) {
        return Err(HeaderError::UnsendableValue {
            header: header.to_string(),
        });
    }
    Ok(out)
}

// --- 証明書ピン（D-52） ---

/// サーバ証明書のDERに対するSHA-256。`sha256:<64桁の16進>`で宣言する。
///
/// **公開鍵ではなく証明書全体のハッシュ**にしてあるのは、ユーザーが手元の道具で同じ値を
/// 出せるからである——`certutil -dump <cert>`の「Cert ハッシュ(sha256)」、
/// `openssl x509 -fingerprint -sha256`、ブラウザの証明書ビューアがどれもこれを表示する。
/// 公開鍵ピン（HPKP流）は鍵を保ったまま証明書を更新できる利点があるが、その値を確かめる
/// 手段が一般的でなく、**ユーザーが照合できないピンは無いのと同じ**である。
#[derive(Clone, PartialEq, Eq)]
pub struct CertPin([u8; 32]);

impl CertPin {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `sha256:aabb...`の表記へ戻す（承認プロンプト・診断用）。
    pub fn to_declaration_string(&self) -> String {
        format!("sha256:{}", hex_lower(&self.0))
    }

    /// 人が目で照合するための表記（4バイトごとに空白）。
    pub fn to_readable(&self) -> String {
        hex_lower(&self.0)
            .as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// 提示された証明書のDERから計算する。
    pub fn of_certificate(der: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }
}

/// ピンの値そのものは秘密ではないが、`Debug`で長い16進が出ると読みにくいので短縮する。
impl std::fmt::Debug for CertPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertPin({}…)", &hex_lower(&self.0)[..16])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("certificate pins must start with \"sha256:\", got {0:?}")]
    UnsupportedAlgorithm(String),
    #[error(
        "a sha256 certificate pin must be exactly 64 hexadecimal characters (32 bytes), got {0}"
    )]
    WrongLength(usize),
    #[error("a certificate pin must be hexadecimal, got {0:?}")]
    NotHex(String),
}

/// `sha256:<hex>`を解釈する。区切りの`:`・` `・`-`（`certutil`や`openssl`の出力に混ざる）は
/// 落としてから読む——**ユーザーが道具の出力をそのまま貼れる**ようにするため。
pub fn parse_cert_pin(declared: &str) -> Result<CertPin, PinError> {
    let trimmed = declared.trim();
    let Some(hex) = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
    else {
        return Err(PinError::UnsupportedAlgorithm(trimmed.to_string()));
    };
    let hex: String = hex
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if hex.len() != 64 {
        return Err(PinError::WrongLength(hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| PinError::NotHex(hex.clone()))?;
    }
    Ok(CertPin(out))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- レスポンスの分類 ---

/// POSTの応答をどう扱うか。ステータスとContent-Typeだけで決まる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    /// 本文がJSON-RPCメッセージ1件。
    Json,
    /// 本文がSSE。`data:`から1件以上のメッセージを取り出す。
    EventStream,
    /// 202など、本文を持たない受理応答（通知を送ったとき）。
    Accepted,
    /// 3xx。**追わない**（D-49）。承認・allowlistの対象は宣言に書かれたホストだけ。
    Redirect,
    /// 404。セッションが失効した可能性がある（MCP仕様）。自動で張り直さない。
    SessionExpired,
    /// それ以外（4xx/5xx、想定外のContent-Type）。
    Failed,
}

pub fn classify_response(status: u16, content_type: Option<&str>) -> ResponseKind {
    if (300..400).contains(&status) {
        return ResponseKind::Redirect;
    }
    if status == 404 {
        return ResponseKind::SessionExpired;
    }
    if !(200..300).contains(&status) {
        return ResponseKind::Failed;
    }
    if status == 202 {
        return ResponseKind::Accepted;
    }
    // Content-Typeは`application/json; charset=utf-8`の形で来る。
    let media = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "application/json" => ResponseKind::Json,
        "text/event-stream" => ResponseKind::EventStream,
        _ => ResponseKind::Failed,
    }
}

// --- SSE ---

/// SSE（`text/event-stream`）から1件ずつJSON-RPCメッセージを取り出す蓄積バッファ。
///
/// バイト→行の分割は[`crate::transport::LineAccumulator`]に任せる（未信頼サーバ相手の
/// 上限をそのまま引き継ぐため）。**空行がイベントの区切り**なので、空行を落とさない
/// [`crate::transport::LineAccumulator::take_raw_line`]を使う。
///
/// `event:`/`id:`/`retry:`/コメント行（`:`始まり）は読み飛ばす。harnessはレジューム
/// （`Last-Event-ID`）を実装しないので`id:`を保持する意味が無い。
#[derive(Debug, Default)]
pub struct SseAccumulator {
    lines: crate::transport::LineAccumulator,
    data: Vec<String>,
    ready: std::collections::VecDeque<String>,
}

impl SseAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.lines.push_bytes(bytes);
    }

    /// 完成したメッセージを1件返す。
    pub fn take_message(&mut self) -> Result<Option<String>, crate::McpError> {
        loop {
            if let Some(message) = self.ready.pop_front() {
                return Ok(Some(message));
            }
            let Some(line) = self.lines.take_raw_line()? else {
                return Ok(None);
            };
            self.feed_line(&line);
        }
    }

    /// ストリームが閉じたときに呼ぶ。終端の空行を送ってこないサーバのために、
    /// 溜まっている`data`を最後のメッセージとして確定させる。
    pub fn finish(&mut self) {
        self.flush_event();
    }

    fn feed_line(&mut self, line: &str) {
        if line.is_empty() {
            self.flush_event();
            return;
        }
        if line.starts_with(':') {
            return; // コメント（keep-alive）
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        if field == "data" {
            self.data.push(value.to_string());
        }
        // event/id/retry/未知フィールドは読み飛ばす（モジュールdoc参照）。
    }

    fn flush_event(&mut self) {
        if self.data.is_empty() {
            return;
        }
        // 仕様どおり複数の`data:`行はLFで連結する。JSON-RPCメッセージは1行で来るのが普通だが、
        // 整形して送るサーバもあるので連結してからパーサへ渡す。
        let message = std::mem::take(&mut self.data).join("\n");
        if !message.trim().is_empty() {
            self.ready.push_back(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `plaintext = true`は「許可した全ドメインを平文でも許す」構成（旧
    /// `--allow-mcp-http-plaintext`と同じ広さ）。ドメインごとに分ける側は
    /// [`plaintext_is_scoped_to_the_domains_written_with_http`]が測る。
    fn gates(domains: &[&str], plaintext: bool) -> EndpointGates {
        let list: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        EndpointGates {
            allow_domains: DomainPolicy::new(list.clone()),
            plaintext_domains: DomainPolicy::new(if plaintext { list } else { Vec::new() }),
        }
    }

    #[test]
    fn a_declared_https_url_on_the_allowlist_is_accepted() {
        let endpoint = validate_endpoint(
            "https://mcp.corp.example/mcp",
            &gates(&["mcp.corp.example"], false),
        )
        .unwrap();
        assert_eq!(endpoint.host(), "mcp.corp.example");
        assert!(endpoint.is_tls());
        assert!(!endpoint.is_loopback());
        assert_eq!(endpoint.display(), "mcp.corp.example/mcp");
    }

    /// **closed-by-default**（D-49）: allowlistが空なら、承認済みでも https でも通らない。
    #[test]
    fn an_empty_allowlist_rejects_every_remote_host() {
        assert_eq!(
            validate_endpoint("https://mcp.corp.example/mcp", &gates(&[], false)),
            Err(HttpWireError::HostNotAllowlisted {
                host: "mcp.corp.example".to_string()
            })
        );
    }

    /// パターン構文は`net.allow_domains`と同一（`DomainPolicy`をそのまま使っている証拠）。
    #[test]
    fn wildcard_patterns_behave_like_the_network_allowlist() {
        let g = gates(&["*.corp.example"], false);
        assert!(validate_endpoint("https://mcp.corp.example/mcp", &g).is_ok());
        assert!(validate_endpoint("https://corp.example/mcp", &g).is_ok());
        assert!(matches!(
            validate_endpoint("https://mcp.corp.example.evil.test/mcp", &g),
            Err(HttpWireError::HostNotAllowlisted { .. })
        ));
    }

    #[test]
    fn a_host_outside_the_allowlist_is_rejected() {
        assert!(matches!(
            validate_endpoint(
                "https://evil.example/mcp",
                &gates(&["mcp.corp.example"], false)
            ),
            Err(HttpWireError::HostNotAllowlisted { .. })
        ));
    }

    /// 平文の判定はallowlistより先。allowlistに足せば通ると誤解させないため。
    #[test]
    fn plaintext_to_a_remote_host_is_rejected_before_the_allowlist_is_consulted() {
        assert_eq!(
            validate_endpoint(
                "http://mcp.corp.example/mcp",
                &gates(&["mcp.corp.example"], false)
            ),
            Err(HttpWireError::PlaintextNotAllowed)
        );
        assert!(
            validate_endpoint(
                "http://mcp.corp.example/mcp",
                &gates(&["mcp.corp.example"], true)
            )
            .is_ok(),
            "--mcp-http-allow http://mcp.corp.example should open exactly this case"
        );
    }

    /// **平文の緩和は、それを書いたドメインの外へ広がらない。**
    ///
    /// `--mcp-http-allow http://legacy.corp.example --mcp-http-allow mcp.corp.example`と
    /// 打ったとき、平文で通ってよいのは前者だけである。かつての
    /// `--allow-mcp-http-plaintext`は単一の真偽フラグで、1件のために打つと
    /// **許可リスト全体**が平文可になっていた。
    #[test]
    fn plaintext_is_scoped_to_the_domains_written_with_http() {
        let gates = EndpointGates {
            allow_domains: DomainPolicy::new(vec![
                "legacy.corp.example".to_string(),
                "mcp.corp.example".to_string(),
            ]),
            plaintext_domains: DomainPolicy::new(vec!["legacy.corp.example".to_string()]),
        };

        // 許可側: `http://`付きで書いたドメインは平文で通る。
        assert!(validate_endpoint("http://legacy.corp.example/mcp", &gates).is_ok());

        // 禁止側: 同じ許可リストに載っていても、平文を書いていないドメインは通らない。
        assert_eq!(
            validate_endpoint("http://mcp.corp.example/mcp", &gates),
            Err(HttpWireError::PlaintextNotAllowed)
        );

        // httpsは両方とも通る（平文の指定はhttpsを狭めない）。
        assert!(validate_endpoint("https://mcp.corp.example/mcp", &gates).is_ok());
        assert!(validate_endpoint("https://legacy.corp.example/mcp", &gates).is_ok());
    }

    /// `--mcp-http-allow`の値の書式（§4.9 対象6）。**許可側と禁止側を対で測る。**
    #[test]
    fn the_allow_value_grammar_accepts_domains_and_rejects_urls() {
        // 許可側。
        assert_eq!(
            parse_http_allow_value("mcp.corp.example"),
            Ok(("mcp.corp.example".to_string(), false))
        );
        assert_eq!(
            parse_http_allow_value("https://mcp.corp.example"),
            Ok(("mcp.corp.example".to_string(), false))
        );
        assert_eq!(
            parse_http_allow_value("http://legacy.corp.example"),
            Ok(("legacy.corp.example".to_string(), true))
        );
        assert_eq!(
            parse_http_allow_value("HTTP://*.Corp.Example"),
            Ok(("*.corp.example".to_string(), true)),
            "スキームもホストも大文字小文字を問わない"
        );

        // 禁止側。**URLを書いたら黙ってホストだけ取り出さない**——「パスまで絞った」と
        // 読める指定が、実態としてホスト全体の許可になるのを防ぐ。
        for bogus in [
            "https://mcp.corp.example/mcp",
            "mcp.corp.example:8443",
            "https://user:pw@mcp.corp.example",
            "ftp://mcp.corp.example",
            "https://203.0.113.10",
            "",
        ] {
            assert!(
                parse_http_allow_value(bogus).is_err(),
                "--mcp-http-allow {bogus:?} must be rejected, not silently narrowed"
            );
        }
    }

    /// loopbackはallowlistにも平文ゲートにも掛からない（モジュールdoc参照）。
    #[test]
    fn loopback_is_exempt_from_both_gates() {
        for url in [
            "http://127.0.0.1:3000/mcp",
            "http://localhost:3000/mcp",
            "http://[::1]:3000/mcp",
        ] {
            let endpoint = validate_endpoint(url, &gates(&[], false))
                .unwrap_or_else(|e| panic!("{url} should be exempt: {e}"));
            assert!(endpoint.is_loopback(), "{url}");
        }
    }

    /// IPリテラルは`DomainPolicy`が構造的に受け付けない。理由を分けて案内する。
    #[test]
    fn a_remote_ip_literal_is_rejected_with_its_own_reason() {
        assert_eq!(
            validate_endpoint(
                "https://203.0.113.10/mcp",
                &gates(&["*.corp.example"], false)
            ),
            Err(HttpWireError::IpLiteralHost {
                host: "203.0.113.10".to_string()
            })
        );
    }

    #[test]
    fn non_http_schemes_and_hostless_urls_are_rejected() {
        assert!(matches!(
            parse_endpoint_url("ftp://example.com/mcp"),
            Err(HttpWireError::UnsupportedScheme { .. })
        ));
        assert!(matches!(
            parse_endpoint_url("file:///c:/mcp"),
            Err(HttpWireError::UnsupportedScheme { .. })
        ));
        assert!(matches!(
            parse_endpoint_url("not a url"),
            Err(HttpWireError::Unparsable(_))
        ));
    }

    // --- ヘッダ ---

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn env_references_are_expanded_at_startup() {
        let headers = [(
            "Authorization".to_string(),
            "Bearer ${env:CORP_MCP_TOKEN}".to_string(),
        )]
        .into_iter()
        .collect();
        let expanded = expand_headers(&headers, &env_of(&[("CORP_MCP_TOKEN", "s3cret")])).unwrap();
        assert_eq!(
            expanded,
            vec![("Authorization".to_string(), "Bearer s3cret".to_string())]
        );
    }

    /// 未定義のenvは黙って空にしない（401だけが返る状態を作らない）。
    #[test]
    fn a_missing_environment_variable_is_an_error_rather_than_an_empty_value() {
        let headers = [(
            "Authorization".to_string(),
            "Bearer ${env:NOPE}".to_string(),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            expand_headers(&headers, &env_of(&[])),
            Err(HeaderError::MissingEnv {
                header: "Authorization".to_string(),
                var: "NOPE".to_string()
            })
        );
    }

    #[test]
    fn literal_values_and_multiple_references_both_work() {
        let headers = [
            ("X-Plain".to_string(), "literal".to_string()),
            ("X-Two".to_string(), "${env:A}/${env:B}".to_string()),
        ]
        .into_iter()
        .collect();
        let expanded = expand_headers(&headers, &env_of(&[("A", "1"), ("B", "2")])).unwrap();
        assert_eq!(expanded[0].1, "literal");
        assert_eq!(expanded[1].1, "1/2");
    }

    /// env の中身は外来値。改行が混ざるとヘッダ分割になるので送る前に落とす。
    #[test]
    fn a_control_character_from_the_environment_is_rejected() {
        let headers = [("X-Bad".to_string(), "${env:EVIL}".to_string())]
            .into_iter()
            .collect();
        assert!(matches!(
            expand_headers(&headers, &env_of(&[("EVIL", "a\r\nX-Injected: 1")])),
            Err(HeaderError::UnsendableValue { .. })
        ));
    }

    #[test]
    fn an_unterminated_reference_is_an_error() {
        let headers = [("X".to_string(), "${env:UNCLOSED".to_string())]
            .into_iter()
            .collect();
        assert!(matches!(
            expand_headers(&headers, &env_of(&[])),
            Err(HeaderError::Unterminated { .. })
        ));
    }

    // --- 証明書ピン（D-52） ---

    const SAMPLE_HEX: &str = "9f6aab9ea64d8e00eeffbc2a5b57aacfecdf76000520fcfb84b0c36d6d113f0f";

    #[test]
    fn a_well_formed_pin_round_trips() {
        let pin = parse_cert_pin(&format!("sha256:{SAMPLE_HEX}")).unwrap();
        assert_eq!(pin.to_declaration_string(), format!("sha256:{SAMPLE_HEX}"));
    }

    /// **ユーザーが道具の出力をそのまま貼れる。** `certutil`は空白区切り、`openssl`は
    /// コロン区切り・大文字で出す。
    #[test]
    fn separators_and_case_from_common_tools_are_accepted() {
        let spaced = "9f6aab9e a64d8e00 eeffbc2a 5b57aacf ecdf7600 0520fcfb 84b0c36d 6d113f0f";
        let colons: String = SAMPLE_HEX
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_uppercase())
            .collect::<Vec<_>>()
            .join(":");

        let expected = parse_cert_pin(&format!("sha256:{SAMPLE_HEX}")).unwrap();
        assert_eq!(
            parse_cert_pin(&format!("sha256:{spaced}")).unwrap(),
            expected
        );
        assert_eq!(
            parse_cert_pin(&format!("SHA256:{colons}")).unwrap(),
            expected
        );
    }

    /// 短い・長い・16進でない・アルゴリズム違いは黙って通さない。
    #[test]
    fn malformed_pins_are_rejected() {
        assert!(matches!(
            parse_cert_pin("sha1:aabb"),
            Err(PinError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            parse_cert_pin(SAMPLE_HEX),
            Err(PinError::UnsupportedAlgorithm(_)),
        ));
        assert!(matches!(
            parse_cert_pin("sha256:aabb"),
            Err(PinError::WrongLength(4))
        ));
        assert!(matches!(
            parse_cert_pin(&format!("sha256:{}", "z".repeat(64))),
            Err(PinError::NotHex(_))
        ));
    }

    /// 証明書のDERから計算した値が、その証明書について宣言すべき文字列と一致する。
    #[test]
    fn the_pin_of_a_certificate_is_its_sha256() {
        // 既知ベクタ: SHA-256("") = e3b0c442...
        let pin = CertPin::of_certificate(b"");
        assert_eq!(
            pin.to_declaration_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// 目視照合用の表記は8桁ごとに区切る（人が読み合わせる前提の表示）。
    #[test]
    fn the_readable_form_is_grouped_for_human_comparison() {
        let pin = parse_cert_pin(&format!("sha256:{SAMPLE_HEX}")).unwrap();
        assert_eq!(
            pin.to_readable(),
            "9f6aab9e a64d8e00 eeffbc2a 5b57aacf ecdf7600 0520fcfb 84b0c36d 6d113f0f"
        );
    }

    // --- 分類 ---

    #[test]
    fn responses_are_classified_by_status_and_content_type() {
        assert_eq!(
            classify_response(200, Some("application/json")),
            ResponseKind::Json
        );
        assert_eq!(
            classify_response(200, Some("application/json; charset=utf-8")),
            ResponseKind::Json
        );
        assert_eq!(
            classify_response(200, Some("text/event-stream")),
            ResponseKind::EventStream
        );
        assert_eq!(classify_response(202, None), ResponseKind::Accepted);
        assert_eq!(classify_response(404, None), ResponseKind::SessionExpired);
        assert_eq!(classify_response(500, None), ResponseKind::Failed);
        assert_eq!(
            classify_response(200, Some("text/html")),
            ResponseKind::Failed
        );
    }

    /// 3xxは`Redirect`として扱い、追従しない（D-49）。
    #[test]
    fn every_redirect_status_is_classified_as_a_redirect() {
        for status in [301, 302, 303, 307, 308] {
            assert_eq!(classify_response(status, None), ResponseKind::Redirect);
        }
    }

    // --- SSE ---

    #[test]
    fn sse_events_are_split_on_blank_lines() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n");
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"a\":1}"));
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"b\":2}"));
        assert_eq!(acc.take_message().unwrap(), None);
    }

    #[test]
    fn sse_frames_split_across_chunk_boundaries_are_reassembled() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b"data: {\"a\"");
        assert_eq!(acc.take_message().unwrap(), None);
        acc.push_bytes(b":1}\n");
        assert_eq!(acc.take_message().unwrap(), None, "no blank line yet");
        acc.push_bytes(b"\n");
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn comments_and_other_fields_are_skipped() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b": keep-alive\nevent: message\nid: 7\nretry: 100\ndata: {\"a\":1}\n\n");
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn multiple_data_lines_are_joined_with_newlines() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b"data: {\ndata:   \"a\": 1\ndata: }\n\n");
        assert_eq!(
            acc.take_message().unwrap().as_deref(),
            Some("{\n  \"a\": 1\n}")
        );
    }

    /// 終端の空行を送らずに閉じるサーバでも、最後のメッセージを落とさない。
    #[test]
    fn a_stream_that_ends_without_a_blank_line_still_yields_its_message() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b"data: {\"a\":1}\n");
        assert_eq!(acc.take_message().unwrap(), None);
        acc.finish();
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    /// CRLFで書くサーバ（`LineAccumulator`が`\r`を落とす）。
    #[test]
    fn crlf_framing_is_handled() {
        let mut acc = SseAccumulator::new();
        acc.push_bytes(b"data: {\"a\":1}\r\n\r\n");
        assert_eq!(acc.take_message().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    /// 改行を送り続けないサーバに無限に付き合わされない（`LineAccumulator`の上限を継承）。
    #[test]
    fn a_server_that_never_terminates_a_line_is_cut_off() {
        let mut acc = SseAccumulator {
            lines: crate::transport::LineAccumulator::with_max_line_bytes(16),
            ..Default::default()
        };
        acc.push_bytes(&[b'x'; 64]);
        assert!(acc.take_message().is_err());
    }
}
