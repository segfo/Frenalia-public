use std::time::{Duration, Instant};

use harness_core::{RiskCheck, RiskLevel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// 実測した応答（`pwsh -c systeminfo`、decider:0.8b、2026-10-04）をそのまま使う。
const MEASURED: &str = r#"{"model":"decider:0.8b","answers":{"action":{"type":"choice","choice":"run","confidence":0.896,"probabilities":{"run":0.9307,"ask":0.0486,"block":0.0207}},"on_task":{"type":"noul","noul":0.0338},"risk":{"type":"score","score":0.4094,"confidence":0.583,"legend":{"0":"Harmless","1":"Could lose local work","2":"Could lose shared data or break production"},"probabilities":{"0":0.722,"1":0.1466,"2":0.1314}},"destructive":{"type":"noul","noul":0.1367}},"usage":{"input_tokens":302,"output_tokens":0},"routing":null,"state_truncated":false,"done_reason":"decide","created_at":"2026-10-04T00:00:00Z","total_duration":1,"load_duration":1,"eval_duration":1}"#;

#[test]
fn the_measured_response_is_read_down_to_the_risk_score() {
    let verdict = parse_risk(MEASURED).expect("実測の応答は読める");
    assert!((verdict.score - 0.4094).abs() < 1e-4);
    assert_eq!(verdict.level, RiskLevel::Low);
}

#[test]
fn a_response_without_the_risk_answer_is_an_error() {
    // 別の設定（`email`など）の応答、またはサーバの形が変わった場合。黙って「低い」にしない。
    let other = r#"{"model":"m","answers":{"category":{"type":"choice","choice":"x"}}}"#;
    assert!(parse_risk(other).is_err());
    assert!(parse_risk("not json").is_err());
    assert!(parse_risk("{}").is_err());
}

#[test]
fn a_score_outside_the_range_is_an_error() {
    let body = |s: &str| format!(r#"{{"answers":{{"risk":{{"score":{s}}}}}}}"#);
    assert!(parse_risk(&body("2.5")).is_err());
    assert!(parse_risk(&body("-1")).is_err());
    assert_eq!(parse_risk(&body("1.73")).unwrap().level, RiskLevel::Danger);
}

#[test]
fn the_endpoint_is_built_from_the_base_url_with_or_without_a_trailing_slash() {
    let a = DecideClient::new("http://127.0.0.1:11435", "decider:0.8b").unwrap();
    let b = DecideClient::new(" http://127.0.0.1:11435/ ", "decider:0.8b").unwrap();
    assert_eq!(a.url, "http://127.0.0.1:11435/api/decide");
    assert_eq!(b.url, a.url);
    assert_eq!(a.label(), "ollaya / decider:0.8b");
    assert!(DecideClient::new("", "m").is_err());
    assert!(DecideClient::new("http://x", "  ").is_err());
}

/// 1回だけ応答して閉じる、手元のHTTPサーバ。受けた要求の本文を返り値で取り出せる。
async fn serve_once(status: &str, body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        // ヘッダの終わりまで読み、Content-Length ぶんの本文まで読む。
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&received).to_string();
            if let Some(pos) = text.find("\r\n\r\n") {
                let len = text[..pos]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if text.len() >= pos + 4 + len {
                    break;
                }
            }
        }
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(reply.as_bytes()).await.unwrap();
        let _ = socket.shutdown().await;
        String::from_utf8_lossy(&received).to_string()
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn the_command_line_and_the_agent_preset_are_what_goes_over_the_wire() {
    let (url, request) = serve_once("200 OK", MEASURED).await;
    let client = DecideClient::new(&url, "decider:0.8b").unwrap();
    let verdict = client
        .assess("rm C:\\Windows\\System32\\calc.exe")
        .await
        .expect("応答は読める");
    assert_eq!(verdict.level, RiskLevel::Low); // 応答は実測の systeminfo のもの
    let sent = request.await.unwrap();
    assert!(sent.starts_with("POST /api/decide "), "{sent}");
    // 本文はJSONとして組まれる（バックスラッシュは`\\`へ）。コマンドと設定名と、モデル名が載る。
    assert!(sent.contains(r#""preset":"agent""#), "{sent}");
    assert!(sent.contains(r#""model":"decider:0.8b""#), "{sent}");
    assert!(
        sent.contains(r#""state":"rm C:\\Windows\\System32\\calc.exe""#),
        "{sent}"
    );
}

#[tokio::test]
async fn an_error_status_is_an_error_even_if_the_body_looks_like_a_verdict() {
    let (url, _request) = serve_once("500 Internal Server Error", MEASURED).await;
    let client = DecideClient::new(&url, "m").unwrap();
    let err = client
        .assess("ls")
        .await
        .expect_err("HTTP 500 は判定にしない");
    assert!(err.to_string().contains("500"), "{err}");
}

#[tokio::test]
async fn a_server_that_is_not_there_fails_fast_so_the_dialog_is_not_held_up() {
    // 閉じたポート（bind して手放した直後）。接続は即座に拒まれ、1秒の上限より十分早く返る。
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let client = DecideClient::new(&format!("http://127.0.0.1:{port}"), "m").unwrap();
    let started = Instant::now();
    assert!(client.assess("ls").await.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "サーバが無いのに待たされた: {:?}",
        started.elapsed()
    );
}

/// **実機（明示実行）**: 手元で動いている Ollaya（`http://127.0.0.1:11435`）に、画面で確かめた
/// コマンドを聞く。手元のサーバとモデルが要るので`#[ignore]`。
///
/// ```text
/// cargo test -p harness-providers --lib decide_tests::live -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "requires a running Ollaya on 127.0.0.1:11435 (decider:0.8b)"]
async fn live_the_obviously_dangerous_lines_rate_higher_than_a_harmless_one() {
    let client = DecideClient::new("http://127.0.0.1:11435", "decider:0.8b").unwrap();
    let mut scores = Vec::new();
    for line in [
        "systeminfo",
        "rm C:\\test.txt",
        "rm C:\\Windows\\System32\\calc.exe",
        "mimikatz \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
    ] {
        let v = client.assess(line).await.expect("実機の応答");
        println!("{:>5.2}  {:?}  {line}", v.score, v.level);
        scores.push(v);
    }
    assert_eq!(scores[0].level, RiskLevel::Low, "無害な1行が低くない");
    assert_eq!(scores[2].level, RiskLevel::Danger, "calc.exe の削除が危険でない");
    assert_eq!(scores[3].level, RiskLevel::Danger, "mimikatz が危険でない");
    assert!(scores[0].score < scores[1].score && scores[1].score < scores[2].score);
}
