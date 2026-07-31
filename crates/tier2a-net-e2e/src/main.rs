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
