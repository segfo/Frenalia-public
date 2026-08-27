//! 検証用のMCPサーバ（M15.6、`plans/DESIGN-MCP.md` §6.2）。Streamable HTTPを喋る。
//!
//! ## なぜ別クレートではなく`harness-mcp`のbinなのか
//!
//! `mcp-mock-server`（stdio版）と同じ理由である——独立クレートのbinは誰の依存でもないため、
//! `cargo test --workspace`がテストより先にビルドする保証が無く、クリーンなツリーで
//! 「exeが無い」と落ちる。同じパッケージのbinにすると`CARGO_BIN_EXE_mcp-mock-http-server`で
//! パスが渡り、ビルド順がcargoに保証される。**独立クレートへ戻さないこと。**
//!
//! ## TLSを持たない
//!
//! 平文HTTPのみ・loopbackのみを待ち受ける。証明書検証のテスト（`tests/http_tls.rs`）は
//! この前段にrustlsの終端を1枚立てて素通しさせる形をとる——MCPの応答ロジックを2箇所に
//! 複製しないため（`docs/CODE-STRUCTURE-RULES.md` 規則5）。
//!
//! ## 挙動の切り替え
//!
//! 環境変数`HARNESS_TEST_MCP_HTTP_MODE`で応答の形を変える（stdio版の`HARNESS_TEST_MCP_FAIL_INITIALIZE`と
//! 同じ手口）。ツール構成はstdio版と同じ3種で、D-40の確認がトランスポート非依存であることを示す。
//!
//! | モード | 挙動 |
//! |---|---|
//! | `json`（既定） | `application/json`で1件返す |
//! | `sse` | `text/event-stream`で返す |
//! | `redirect` | 全リクエストに307を返す（harnessは追ってはならない） |
//! | `expire-session` | `initialize`は成功し、以後は404（セッション失効）を返す |
//! | `no-session-id` | `Mcp-Session-Id`を一切発行しない（省略可能であることの確認） |
//! | `fail-initialize` | `initialize`にJSON-RPCエラーを返す |
//! | `server-error` | 全リクエストに500とテキスト本文を返す |
//!
//! 待受ポートは`0`でbindし、`listening on 127.0.0.1:<port>`をstdoutへ1行出す。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

const SESSION_ID: &str = "mock-session-1";

fn main() {
    let mode = std::env::var("HARNESS_TEST_MCP_HTTP_MODE").unwrap_or_else(|_| "json".to_string());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    println!("listening on {addr}");
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if let Err(e) = handle(stream, &mode) {
            eprintln!("mock http server: {e}");
        }
    }
}

struct Request {
    method: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn handle(mut stream: TcpStream, mode: &str) -> std::io::Result<()> {
    let request = match read_request(&mut stream)? {
        Some(request) => request,
        None => return Ok(()),
    };

    // クライアントがセッションを畳むときのDELETE。204で受ける。
    if request.method == "DELETE" {
        return write_response(&mut stream, 204, None, "", &[]);
    }

    if mode == "redirect" {
        return write_response(
            &mut stream,
            307,
            None,
            "",
            &[("Location", "https://elsewhere.example/mcp")],
        );
    }
    if mode == "server-error" {
        return write_response(
            &mut stream,
            500,
            Some("text/plain"),
            "upstream exploded",
            &[],
        );
    }

    let rpc: serde_json::Value = match serde_json::from_str(&request.body) {
        Ok(rpc) => rpc,
        // 壊れた行で落ちない（本物のサーバも落ちるべきではない）。
        Err(_) => return write_response(&mut stream, 400, Some("text/plain"), "bad json", &[]),
    };
    let method = rpc
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or_default();
    let is_initialize = method == "initialize";

    if mode == "expire-session" && !is_initialize {
        return write_response(
            &mut stream,
            404,
            Some("text/plain"),
            "session not found",
            &[],
        );
    }

    // 通知（id無し）には本文を返さない。MCP仕様は202 Acceptedを定める。
    let Some(id) = rpc.get("id").cloned() else {
        return write_response(&mut stream, 202, None, "", &[]);
    };

    let response = match method {
        "initialize" => {
            if mode == "fail-initialize" {
                error_response(id, -32000, "mock server was told to fail initialize")
            } else {
                ok_response(
                    id,
                    serde_json::json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "mcp-mock-http-server", "version": "0.1.0" }
                    }),
                )
            }
        }
        "tools/list" => ok_response(id, tools_list(&request)),
        "tools/call" => {
            let params = rpc.get("params").cloned().unwrap_or_default();
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let arguments = params.get("arguments").cloned().unwrap_or_default();
            match call_tool(&name, &arguments, &request) {
                Ok(result) => ok_response(id, result),
                Err(message) => error_response(id, -32602, &message),
            }
        }
        other => error_response(id, -32601, &format!("method not found: {other}")),
    };

    // `Mcp-Session-Id`は`initialize`の応答で発行する（MCP仕様）。
    let session_header: Vec<(&str, &str)> = if is_initialize && mode != "no-session-id" {
        vec![("Mcp-Session-Id", SESSION_ID)]
    } else {
        Vec::new()
    };

    if mode == "sse" {
        let body = format!("event: message\ndata: {response}\n\n");
        write_response(
            &mut stream,
            200,
            Some("text/event-stream"),
            &body,
            &session_header,
        )
    } else {
        write_response(
            &mut stream,
            200,
            Some("application/json"),
            &response.to_string(),
            &session_header,
        )
    }
}

/// リクエスト行＋ヘッダ＋`Content-Length`分の本文を読む（HTTP/1.1の最小実装）。
fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: Option<&str>,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    if let Some(content_type) = content_type {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    // keep-aliveの状態機械を持たない（テスト用なので1リクエスト1接続で十分）。
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// ツール一覧。**受け取ったヘッダをテストから観測できるように`search`の説明へ埋める**——
/// `Mcp-Session-Id`・`MCP-Protocol-Version`・宣言ヘッダが実際に届いたかを外から確かめる唯一の手段。
fn tools_list(request: &Request) -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "name": "search",
                "description": format!(
                    "seen: session={} protocol={} authorization={}",
                    request.header("mcp-session-id").unwrap_or("(none)"),
                    request.header("mcp-protocol-version").unwrap_or("(none)"),
                    request.header("authorization").unwrap_or("(none)"),
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": { "query": { "type": "string" } },
                    "required": ["query"]
                }
            },
            {
                "name": "create_issue",
                "description": "Create an issue (mock; changes nothing).",
                "inputSchema": {
                    "type": "object",
                    "properties": { "title": { "type": "string" } },
                    "required": ["title"]
                }
            },
            {
                // D-40の確認用: サーバが「read-onlyだ」と自称しても、harnessは宣言だけを見る。
                "name": "claims_read_only",
                "description": "Claims to be read-only via annotations; harness must ignore that.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true }
            }
        ]
    })
}

fn call_tool(
    name: &str,
    arguments: &serde_json::Value,
    request: &Request,
) -> Result<serde_json::Value, String> {
    let text = match name {
        "search" => {
            let query = arguments
                .get("query")
                .and_then(|q| q.as_str())
                .ok_or_else(|| "search requires a string \"query\"".to_string())?;
            // explicit null が除去されていることをクライアント側テストが確認できるよう、
            // 受け取った引数のキーをそのまま返す。
            let keys: Vec<&str> = arguments
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            format!(
                "results for {query} (argument keys: {}; session={})",
                keys.join(","),
                request.header("mcp-session-id").unwrap_or("(none)")
            )
        }
        "create_issue" => {
            let title = arguments
                .get("title")
                .and_then(|t| t.as_str())
                .ok_or_else(|| "create_issue requires a string \"title\"".to_string())?;
            format!("created issue: {title}")
        }
        "claims_read_only" => "this tool claims to be read-only".to_string(),
        other => return Err(format!("unknown tool: {other}")),
    };
    Ok(serde_json::json!({ "content": [ { "type": "text", "text": text } ] }))
}

fn ok_response(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}
