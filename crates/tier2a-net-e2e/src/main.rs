use std::env;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, HOST, USER_AGENT};
use serde_json::{json, Map, Value};

const EXAMPLE_IP: [u8; 4] = [172, 66, 147, 243];
const EXAMPLE_VIRTUAL_HOST: &str = "example.jp";
const USER_AGENT_VALUE: &str = "harness-Tier2a-e2e/1.0";

#[derive(Parser)]
#[command(name = "tier2a-net-e2e")]
#[command(about = "Tier2a network E2E probes as a single Rust binary")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    FetchExample,
    FetchGoogle,
    FetchExampleIpLiterals,
    FetchUrl(FetchUrlArgs),
    RawConnect(RawConnectArgs),
    CaseMatrix {
        #[arg(long = "case")]
        case: CaseKind,
    },
    /// HTTP_PROXY経由の1本のTCP接続に許可→拒否→許可の3リクエストを流し、
    /// keep-alive接続がリクエスト単位で再評価されることを確認する
    /// （`plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`§5.2）。
    KeepaliveReuse(KeepaliveReuseArgs),
    /// CONNECTでトンネルを確立した後、実際のTLS ClientHelloを`--sni`で送り、
    /// トンネルがSNI検査でどう扱われたか（`tunnel_closed`=拒否/`passed_through`=通過）を
    /// 観測する（§5.5 SNI検査、監査`reason=sni_denied`/`sni_host_mismatch`の実機確認用）。
    ConnectSni(ConnectSniArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum CaseKind {
    AllDenied,
    Domains,
    ExampleIp,
    NumericIp,
    All,
}

impl CaseKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::AllDenied => "all-denied",
            Self::Domains => "domains",
            Self::ExampleIp => "example-ip",
            Self::NumericIp => "numeric-ip",
            Self::All => "all",
        }
    }
}

#[derive(Parser, Clone)]
struct FetchUrlArgs {
    url: String,
    #[arg(long, default_value_t = 8.0)]
    timeout: f64,
    #[arg(long, default_value = "")]
    label: String,
    #[arg(long = "host-header", default_value = "")]
    host_header: String,
    #[arg(long = "max-body", default_value_t = 160)]
    max_body: usize,
}

#[derive(Parser, Clone)]
struct KeepaliveReuseArgs {
    allowed_url: String,
    denied_url: String,
    #[arg(long, default_value_t = 8.0)]
    timeout: f64,
}

#[derive(Parser, Clone)]
struct ConnectSniArgs {
    connect_host: String,
    #[arg(long = "connect-port", default_value_t = 443)]
    connect_port: u16,
    #[arg(long)]
    sni: String,
    #[arg(long, default_value_t = 5.0)]
    timeout: f64,
}

#[derive(Parser, Clone)]
struct RawConnectArgs {
    host: String,
    port: u16,
    #[arg(long, default_value_t = 5.0)]
    timeout: f64,
    #[arg(long = "http-host", default_value = "")]
    http_host: String,
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Clone)]
enum Probe {
    FetchUrl(FetchUrlArgs),
    RawConnect(RawConnectArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalized_args());
    let code = match cli.command {
        Command::FetchExample => {
            run_fetch_url(fetch_url_args("https://example.com/", "example.com"))
        }
        Command::FetchGoogle => run_fetch_url(fetch_url_args("https://google.com/", "google.com")),
        Command::FetchExampleIpLiterals => run_fetch_example_ip_literals(),
        Command::FetchUrl(args) => run_fetch_url(args),
        Command::RawConnect(args) => run_raw_connect(args),
        Command::CaseMatrix { case } => run_case_matrix(case),
        Command::KeepaliveReuse(args) => run_keepalive_reuse(args),
        Command::ConnectSni(args) => run_connect_sni(args),
    };
    ExitCode::from(code)
}

fn normalized_args() -> Vec<String> {
    let mut args: Vec<String> = env::args().collect();
    if matches!(args.get(1).map(String::as_str), Some("--case")) {
        args.insert(1, "case-matrix".to_string());
    }
    args
}

fn fetch_url_args(url: &str, label: &str) -> FetchUrlArgs {
    FetchUrlArgs {
        url: url.to_string(),
        timeout: 8.0,
        label: label.to_string(),
        host_header: String::new(),
        max_body: 160,
    }
}

fn run_fetch_example_ip_literals() -> u8 {
    let mut failed = false;
    for (label, url) in example_ip_literal_urls(true) {
        let result = fetch_url_result_with_resolve(
            FetchUrlArgs {
                url: "https://example.com/".to_string(),
                timeout: 8.0,
                label: label.clone(),
                host_header: String::new(),
                max_body: 160,
            },
            Some((
                "example.com".to_string(),
                IpAddr::V4(Ipv4Addr::from(EXAMPLE_IP)),
            )),
        );
        if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            print_json(&result);
            continue;
        }

        let fallback = fetch_url_result(FetchUrlArgs {
            url: url.clone(),
            timeout: 8.0,
            label: format!("{label}-literal-fallback"),
            host_header: EXAMPLE_VIRTUAL_HOST.to_string(),
            max_body: 160,
        });
        failed = true;
        print_json(&result);
        print_json(&fallback);
    }
    if failed {
        30
    } else {
        0
    }
}

fn run_case_matrix(case: CaseKind) -> u8 {
    let mut results = Vec::new();
    for (name, cmd, probe, expect_ok) in probes_for_case(case) {
        let result = match probe {
            Probe::FetchUrl(args) => fetch_url_result(args),
            Probe::RawConnect(args) => raw_connect_result(args),
        };
        let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let exit_code = if ok { 0 } else { 20 };
        let record = json!({
            "cmd": cmd,
            "exit_code": exit_code,
            "expect_ok": expect_ok,
            "matched": ok == expect_ok,
            "name": name,
            "result": result,
            "stderr": "",
        });
        print_json(&record);
        results.push(record);
    }

    let matched = results
        .iter()
        .filter(|record| record.get("matched").and_then(Value::as_bool) == Some(true))
        .count();
    let passed = matched == results.len();
    print_json(&json!({
        "case": case.as_str(),
        "matched": matched,
        "passed": passed,
        "total": results.len(),
    }));

    if passed {
        0
    } else {
        30
    }
}

fn probes_for_case(case: CaseKind) -> Vec<(String, Vec<String>, Probe, bool)> {
    match case {
        CaseKind::Domains => vec![
            fetch_probe("example.com", "https://example.com/", "example.com", true),
            fetch_probe("google.com", "https://google.com/", "google.com", false),
        ],
        CaseKind::AllDenied => vec![
            fetch_probe("example.com", "https://example.com/", "example.com", false),
            fetch_probe("google.com", "https://google.com/", "google.com", false),
        ],
        CaseKind::ExampleIp => {
            let args = RawConnectArgs {
                host: example_ip_string(),
                port: 80,
                timeout: 5.0,
                http_host: EXAMPLE_VIRTUAL_HOST.to_string(),
                label: "example-ip".to_string(),
            };
            vec![(
                "example.com raw IPv4".to_string(),
                vec![
                    "tier2a-net-e2e".to_string(),
                    "raw-connect".to_string(),
                    args.host.clone(),
                    args.port.to_string(),
                    "--http-host".to_string(),
                    args.http_host.clone(),
                    "--label".to_string(),
                    args.label.clone(),
                ],
                Probe::RawConnect(args),
                false,
            )]
        }
        CaseKind::NumericIp => example_ip_literal_urls(false)
            .into_iter()
            .map(|(label, url)| {
                let args = FetchUrlArgs {
                    url,
                    timeout: 8.0,
                    label,
                    host_header: EXAMPLE_VIRTUAL_HOST.to_string(),
                    max_body: 160,
                };
                let cmd = vec![
                    "tier2a-net-e2e".to_string(),
                    "fetch-url".to_string(),
                    args.url.clone(),
                    "--label".to_string(),
                    args.label.clone(),
                    "--host-header".to_string(),
                    args.host_header.clone(),
                ];
                (args.label.clone(), cmd, Probe::FetchUrl(args), false)
            })
            .collect(),
        CaseKind::All => {
            let mut probes = probes_for_case(CaseKind::Domains);
            probes.extend(probes_for_case(CaseKind::ExampleIp));
            probes.extend(probes_for_case(CaseKind::NumericIp));
            probes
        }
    }
}

fn fetch_probe(
    name: &str,
    url: &str,
    label: &str,
    expect_ok: bool,
) -> (String, Vec<String>, Probe, bool) {
    (
        name.to_string(),
        vec![
            "tier2a-net-e2e".to_string(),
            "fetch-url".to_string(),
            url.to_string(),
            "--label".to_string(),
            label.to_string(),
        ],
        Probe::FetchUrl(fetch_url_args(url, label)),
        expect_ok,
    )
}

fn run_fetch_url(args: FetchUrlArgs) -> u8 {
    let result = fetch_url_result(args);
    let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    print_json(&result);
    if ok {
        0
    } else {
        20
    }
}

fn fetch_url_result(args: FetchUrlArgs) -> Value {
    fetch_url_result_with_resolve(args, None)
}

fn fetch_url_result_with_resolve(args: FetchUrlArgs, resolve: Option<(String, IpAddr)>) -> Value {
    let started = Instant::now();
    let mut result = Map::from_iter([
        ("probe".to_string(), json!("fetch_url")),
        ("label".to_string(), json!(args.label)),
        ("url".to_string(), json!(args.url)),
        (
            "host_header".to_string(),
            if args.host_header.is_empty() {
                Value::Null
            } else {
                json!(args.host_header)
            },
        ),
        ("ok".to_string(), json!(false)),
        ("proxy_env".to_string(), json!(interesting_proxy_env())),
    ]);
    if let Some((host, ip)) = &resolve {
        result.insert(
            "resolve".to_string(),
            json!({
                "host": host,
                "ip": ip.to_string(),
            }),
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    headers.insert(ACCEPT, HeaderValue::from_static("text/plain,text/html,*/*"));
    if !args.host_header.is_empty() {
        match HeaderValue::from_str(&args.host_header) {
            Ok(value) => {
                headers.insert(HOST, value);
            }
            Err(err) => {
                result.insert("error_type".to_string(), json!("InvalidHeaderValue"));
                result.insert("error".to_string(), json!(err.to_string()));
                result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
                return Value::Object(result);
            }
        }
    }

    let mut builder = Client::builder().timeout(duration_from_secs(args.timeout));
    if let Some((host, ip)) = resolve {
        let port = if args.url.starts_with("https://") {
            443
        } else {
            80
        };
        builder = builder.resolve(&host, SocketAddr::new(ip, port));
    }

    let response = builder
        .build()
        .and_then(|client| client.get(&args.url).headers(headers).send());

    match response {
        Ok(mut response) => {
            let status = response.status();
            let final_url = response.url().to_string();
            let mut body = Vec::new();
            let read_result = (&mut response)
                .take(args.max_body as u64)
                .read_to_end(&mut body);
            result.insert(
                "ok".to_string(),
                json!(status.is_success() || status.is_redirection()),
            );
            result.insert("status".to_string(), json!(status.as_u16()));
            result.insert(
                "reason".to_string(),
                json!(status.canonical_reason().unwrap_or("")),
            );
            result.insert("final_url".to_string(), json!(final_url));
            result.insert(
                "body_prefix".to_string(),
                json!(String::from_utf8_lossy(&body).to_string()),
            );
            if let Err(err) = read_result {
                result.insert("error_type".to_string(), json!("ReadError"));
                result.insert("error".to_string(), json!(err.to_string()));
            } else if !status.is_success() && !status.is_redirection() {
                result.insert("error_type".to_string(), json!("HTTPError"));
                result.insert(
                    "error".to_string(),
                    json!(format!(
                        "HTTP Error {}: {}",
                        status.as_u16(),
                        status.canonical_reason().unwrap_or("")
                    )),
                );
            }
        }
        Err(err) => {
            result.insert("ok".to_string(), json!(false));
            result.insert("error_type".to_string(), json!("RequestError"));
            result.insert("error".to_string(), json!(err.to_string()));
        }
    }

    result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
    Value::Object(result)
}

fn run_raw_connect(args: RawConnectArgs) -> u8 {
    let result = raw_connect_result(args);
    let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    print_json(&result);
    if ok {
        0
    } else {
        20
    }
}

fn raw_connect_result(args: RawConnectArgs) -> Value {
    let started = Instant::now();
    let mut result = Map::from_iter([
        ("probe".to_string(), json!("raw_connect")),
        ("label".to_string(), json!(args.label)),
        ("host".to_string(), json!(args.host)),
        ("port".to_string(), json!(args.port)),
        ("ok".to_string(), json!(false)),
    ]);

    let addr_result = (args.host.as_str(), args.port)
        .to_socket_addrs()
        .and_then(|mut addrs| {
            addrs.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no socket address resolved")
            })
        });

    match addr_result
        .and_then(|addr| TcpStream::connect_timeout(&addr, duration_from_secs(args.timeout)))
    {
        Ok(mut sock) => {
            let _ = sock.set_read_timeout(Some(duration_from_secs(args.timeout)));
            let _ = sock.set_write_timeout(Some(duration_from_secs(args.timeout)));
            result.insert("ok".to_string(), json!(true));
            result.insert(
                "peer".to_string(),
                json!(format!("{}:{}", args.host, args.port)),
            );
            if !args.http_host.is_empty() {
                let request = format!(
                    "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
                    args.http_host, USER_AGENT_VALUE
                );
                match sock.write_all(request.as_bytes()).and_then(|_| {
                    let mut data = vec![0; 160];
                    sock.read(&mut data).map(|n| {
                        data.truncate(n);
                        data
                    })
                }) {
                    Ok(data) => {
                        result.insert(
                            "response_prefix".to_string(),
                            json!(String::from_utf8_lossy(&data).to_string()),
                        );
                    }
                    Err(err) => {
                        result.insert("error_type".to_string(), json!("IoError"));
                        result.insert("error".to_string(), json!(err.to_string()));
                    }
                }
            }
        }
        Err(err) => {
            result.insert("ok".to_string(), json!(false));
            result.insert("error_type".to_string(), json!("IoError"));
            result.insert("error".to_string(), json!(err.to_string()));
        }
    }

    result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
    Value::Object(result)
}

fn http_proxy_addr_from_env() -> Option<String> {
    for key in ["HTTP_PROXY", "http_proxy"] {
        if let Ok(v) = env::var(key) {
            if let Ok(url) = reqwest::Url::parse(&v) {
                if let Some(host) = url.host_str() {
                    let port = url.port().unwrap_or(80);
                    return Some(format!("{host}:{port}"));
                }
            }
        }
    }
    None
}

fn run_keepalive_reuse(args: KeepaliveReuseArgs) -> u8 {
    let result = keepalive_reuse_result(args);
    let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    print_json(&result);
    if ok {
        0
    } else {
        20
    }
}

fn keepalive_reuse_result(args: KeepaliveReuseArgs) -> Value {
    let started = Instant::now();
    let mut result = Map::from_iter([
        ("probe".to_string(), json!("keepalive_reuse")),
        ("ok".to_string(), json!(false)),
    ]);
    let Some(proxy_addr) = http_proxy_addr_from_env() else {
        result.insert("error_type".to_string(), json!("NoProxyConfigured"));
        result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
        return Value::Object(result);
    };
    result.insert("proxy_addr".to_string(), json!(proxy_addr));

    let outcome = (|| -> std::io::Result<Vec<u16>> {
        let mut stream = TcpStream::connect(&proxy_addr)?;
        stream.set_read_timeout(Some(duration_from_secs(args.timeout)))?;
        stream.set_write_timeout(Some(duration_from_secs(args.timeout)))?;
        let mut reader = std::io::BufReader::new(stream.try_clone()?);
        let mut statuses = Vec::new();
        for url in [
            args.allowed_url.as_str(),
            args.denied_url.as_str(),
            args.allowed_url.as_str(),
        ] {
            // 絶対URI形式なのでプロキシ側の宛先判定は`req.uri()`の authority を使う
            // （Hostヘッダは使われない）が、実サーバの一部は欠落/不一致Hostに敏感なため
            // URLから素直に導出して揃えておく。
            let host_header = reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "x".to_string());
            let request = format!(
                "GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: keep-alive\r\n\r\n"
            );
            stream.write_all(request.as_bytes())?;
            let (status, _headers, _body) = read_http_response(&mut reader)?;
            statuses.push(status);
        }
        Ok(statuses)
    })();

    match outcome {
        Ok(statuses) => {
            let ok =
                statuses.len() == 3 && statuses[0] < 400 && statuses[1] == 403 && statuses[2] < 400;
            result.insert("statuses".to_string(), json!(statuses));
            result.insert("ok".to_string(), json!(ok));
        }
        Err(err) => {
            result.insert("error_type".to_string(), json!("IoError"));
            result.insert("error".to_string(), json!(err.to_string()));
        }
    }
    result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
    Value::Object(result)
}

fn read_http_response(
    reader: &mut std::io::BufReader<TcpStream>,
) -> std::io::Result<(u16, Vec<String>, Vec<u8>)> {
    use std::io::BufRead;
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().ok();
        }
        if let Some(v) = lower.strip_prefix("transfer-encoding:") {
            chunked = v.trim().eq_ignore_ascii_case("chunked");
        }
        headers.push(line.trim_end().to_string());
    }

    // 実サーバ（example.comのCloudflare等）はContent-Lengthを送らずchunkedで返すことが多い。
    // ここでボディ境界を正しく消費しないと、同じkeep-alive接続上の次のリクエストの
    // レスポンスがバイトずれして誤読される（本プローブ自身が発見したバグ、2026-08-02実機E2E）。
    let body = if chunked {
        read_chunked_body(reader)?
    } else {
        let len = content_length.unwrap_or(0);
        let mut buf = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut buf)?;
        }
        buf
    };
    Ok((status, headers, body))
}

/// `Transfer-Encoding: chunked`のボディを完全に読み切る（サイズ行→データ→CRLFを、
/// サイズ0のterminating chunkまで繰り返す。trailerヘッダの有無に関わらず、続く
/// 最終`\r\n`まで読み切って、次のレスポンスの先頭とバイト境界を合わせる）。
fn read_chunked_body(reader: &mut std::io::BufReader<TcpStream>) -> std::io::Result<Vec<u8>> {
    use std::io::BufRead;
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size_str = size_line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size {size_str:?}: {e}"),
            )
        })?;
        if size == 0 {
            // trailerヘッダ(通常は無い)を読み飛ばし、終端の空行まで消費する。
            loop {
                let mut trailer = String::new();
                reader.read_line(&mut trailer)?;
                if trailer == "\r\n" || trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        // 各チャンクの末尾はCRLF。
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    Ok(body)
}

fn run_connect_sni(args: ConnectSniArgs) -> u8 {
    let result = connect_sni_result(args);
    let ok = result.get("ok").and_then(Value::as_bool).unwrap_or(false);
    print_json(&result);
    if ok {
        0
    } else {
        20
    }
}

fn connect_sni_result(args: ConnectSniArgs) -> Value {
    let started = Instant::now();
    let mut result = Map::from_iter([
        ("probe".to_string(), json!("connect_sni")),
        ("connect_host".to_string(), json!(args.connect_host)),
        ("connect_port".to_string(), json!(args.connect_port)),
        ("sni".to_string(), json!(args.sni)),
        ("ok".to_string(), json!(false)),
    ]);
    let Some(proxy_addr) = http_proxy_addr_from_env() else {
        result.insert("error_type".to_string(), json!("NoProxyConfigured"));
        result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
        return Value::Object(result);
    };

    let outcome = (|| -> Result<String, String> {
        let mut stream = TcpStream::connect(&proxy_addr).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(duration_from_secs(args.timeout)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(duration_from_secs(args.timeout)))
            .map_err(|e| e.to_string())?;

        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\n\r\n",
            args.connect_host, args.connect_port
        );
        stream
            .write_all(connect_req.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut reader = std::io::BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut status_line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut status_line).map_err(|e| e.to_string())?;
        if !status_line.starts_with("HTTP/1.1 200") {
            return Ok(format!("connect_rejected:{}", status_line.trim()));
        }
        loop {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).map_err(|e| e.to_string())?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let hello = build_client_hello(&args.sni);
        stream.write_all(&hello).map_err(|e| e.to_string())?;

        let mut buf = [0u8; 64];
        match std::io::Read::read(&mut reader, &mut buf) {
            Ok(0) => Ok("tunnel_closed".to_string()),
            Ok(_) => Ok("passed_through".to_string()),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok("timed_out_no_data".to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    })();

    match outcome {
        Ok(outcome_str) => {
            // I/Oエラー無く決着した（拒否でクローズ／通過してバイトが流れた）ことをもって
            // `ok=true`とする。deny/allowどちらだったかは呼び出し側が`outcome`を見て判定する。
            result.insert("ok".to_string(), json!(true));
            result.insert("outcome".to_string(), json!(outcome_str));
        }
        Err(err) => {
            result.insert("error_type".to_string(), json!("IoError"));
            result.insert("error".to_string(), json!(err));
        }
    }
    result.insert("elapsed_ms".to_string(), json!(elapsed_ms(started)));
    Value::Object(result)
}

/// SNI検査に使うClientHelloを実際にrustlsで生成する（TLS1.2/1.3ネゴシエーション可、
/// 証明書検証はこの用途では行わない——プロキシがトンネルを閉じるか通すかだけを見る）。
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
        .expect("default protocol versions are always valid")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .expect("sni must be a valid DNS name");
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .expect("client connection construction cannot fail here");
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf)
            .expect("writing to a Vec cannot fail");
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

fn interesting_proxy_env() -> Map<String, Value> {
    [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HARNESS_FAKE_DNS_ADDR",
    ]
    .into_iter()
    .filter_map(|key| {
        env::var(key)
            .ok()
            .map(|value| (key.to_string(), json!(value)))
    })
    .collect()
}

fn example_ip_literal_urls(include_dotted: bool) -> Vec<(String, String)> {
    let value = u32::from_be_bytes(EXAMPLE_IP);
    let dotted_octal = EXAMPLE_IP
        .iter()
        .map(|part| format!("0{:o}", part))
        .collect::<Vec<_>>()
        .join(".");
    let mut urls = Vec::new();
    if include_dotted {
        urls.push((
            "example-ip-dotted".to_string(),
            format!("http://{}/", example_ip_string()),
        ));
    }
    urls.extend([
        ("example-ip-decimal".to_string(), format!("http://{value}/")),
        (
            "example-ip-hex".to_string(),
            format!("http://0x{value:08x}/"),
        ),
        (
            "example-ip-octal-dotted".to_string(),
            format!("http://{dotted_octal}/"),
        ),
    ]);
    urls
}

fn example_ip_string() -> String {
    EXAMPLE_IP
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn duration_from_secs(secs: f64) -> Duration {
    Duration::from_secs_f64(secs.max(0.001))
}

fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

fn print_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).expect("probe result must serialize")
    );
}
