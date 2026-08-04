//! 検証用のMCPサーバ（M15.5、`plans/DESIGN-MCP.md`）。stdioで改行区切りJSON-RPCを話す。
//!
//! ## なぜ別クレートではなく`harness-mcp`のbinなのか
//!
//! `tier2a-mock-netfilterd`に倣って独立クレートにしたところ、`cargo test --workspace`が
//! **`harness-mcp`のテストより先にこのbinをビルドする保証が無い**（誰の依存でもないため）。
//! クリーンなツリーで実際に「exeが無い」でテストが落ちた。同じパッケージのbinにすると、
//! cargoが統合テストの前に必ずビルドし`CARGO_BIN_EXE_mcp-mock-server`でパスを渡すので、
//! 依存関係が型で保証される。**独立クレートへ戻さないこと。**
//!
//! 実装するのはharnessのクライアントが使う4メソッドだけ（`initialize`・
//! `notifications/initialized`・`tools/list`・`tools/call`）。
//!
//! **意図的に3種類のツールを持つ**。承認・パーミッションの分岐を実機で確かめるための役割分担で、
//! 「宣言でread-onlyと宣言されたもの／宣言されていないもの／サーバがread-onlyだと自称するもの」の
//! 3つが揃っていないとD-40（`readOnlyHint`を信じない）を確認できない。
//!
//! | ツール | 役割 |
//! |---|---|
//! | `search` | 宣言でread-onlyにする想定。自動許可される経路の確認 |
//! | `create_issue` | 宣言しない想定。パーミッションゲートに掛かる経路の確認 |
//! | `claims_read_only` | `annotations.readOnlyHint: true`を**自称する**。それでも非read扱いになることの確認 |
//!
//! 環境変数`MCP_MOCK_FAIL_INITIALIZE=1`で`initialize`にエラーを返す（起動失敗時に他のサーバが
//! 巻き込まれないことの確認用）。

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request): Result<serde_json::Value, _> = serde_json::from_str(&line) else {
            // 未知の入力は黙って捨てる（本物のサーバも壊れた行で落ちるべきではない）。
            continue;
        };
        // 通知（id無し）には応答しない。
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or_default();

        let response = match method {
            "initialize" => {
                if std::env::var("MCP_MOCK_FAIL_INITIALIZE").is_ok() {
                    error_response(id, -32000, "mock server was told to fail initialize")
                } else {
                    ok_response(
                        id,
                        serde_json::json!({
                            "protocolVersion": "2025-06-18",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": "mcp-mock-server", "version": "0.1.0" }
                        }),
                    )
                }
            }
            "tools/list" => ok_response(id, tools_list()),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or_default();
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default()
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or_default();
                match call_tool(&name, &arguments) {
                    Ok(result) => ok_response(id, result),
                    Err(message) => error_response(id, -32602, &message),
                }
            }
            other => error_response(id, -32601, &format!("method not found: {other}")),
        };

        if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
            break;
        }
    }
}

fn tools_list() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "name": "search",
                "description": "Search the mock corpus.",
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

fn call_tool(name: &str, arguments: &serde_json::Value) -> Result<serde_json::Value, String> {
    let text = match name {
        "search" => {
            let query = arguments
                .get("query")
                .and_then(|q| q.as_str())
                .ok_or_else(|| "search requires a string \"query\"".to_string())?;
            // explicit null が除去されていることをクライアント側テストが確認できるよう、
            // 受け取った引数のキーをそのまま返す（(f)の効きを外から観測可能にする）。
            let keys: Vec<&str> = arguments
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            format!("results for {query} (argument keys: {})", keys.join(","))
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
