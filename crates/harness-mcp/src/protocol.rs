//! JSON-RPC 2.0 と MCP メソッドのワイヤ形式。
//!
//! ここは**別プロセス（未信頼の第三者コード、`plans/DESIGN-MCP.md` §2）と交換するバイト列**の
//! 定義であり、`netfilterd`のIPC型と同じく「表現を変えるときは意図的な変更だと分かるように」
//! goldenテストで固定する。
//!
//! 実装するのはM15.5に必要な4メソッドだけ（`initialize`・`notifications/initialized`・
//! `tools/list`・`tools/call`）。`resources`/`prompts`/`sampling`/`roots`は対象外。
//!
//! ## 未知フィールドを拒否しない
//!
//! サーバの応答は`#[serde(deny_unknown_fields)]`にしない。MCPはバージョンごとに応答へ項目が
//! 増えるため、知らない項目で全体を落とすと新しいサーバが一切使えなくなる。**代わりに、
//! 使う値は1つずつ検証してから使う**（ツール名は`is_valid_mcp_tool_name`、`RiskClass`は
//! サーバ申告を一切見ない＝D-40）。

use serde::{Deserialize, Serialize};

/// harnessがサポートするMCPプロトコルバージョン（新しい順）。先頭を`initialize`で提案し、
/// サーバがこの一覧のいずれかを返せば継続、それ以外なら接続を打ち切る。
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub fn preferred_protocol_version() -> &'static str {
    SUPPORTED_PROTOCOL_VERSIONS[0]
}

pub const CLIENT_NAME: &str = "harness";

/// 送信するリクエスト（id付き＝応答を待つ）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    pub fn new(id: u64, method: &str, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        }
    }
}

/// 送信する通知（id無し＝応答を待たない）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: &'static str,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcNotification {
    pub fn new(method: &str, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        }
    }
}

/// 受信した1行。応答（id有り）と通知（id無し）を区別する。
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct JsonRpcIncoming {
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcIncoming {
    /// この行が`id`宛の応答か。サーバは`id`を数値でも文字列でも返し得るので、
    /// 送った数値の文字列表現とも突き合わせる。
    pub fn matches_id(&self, id: u64) -> bool {
        match &self.id {
            Some(serde_json::Value::Number(n)) => n.as_u64() == Some(id),
            Some(serde_json::Value::String(s)) => s == &id.to_string(),
            _ => false,
        }
    }

    /// 応答ではない行（サーバからの通知・リクエスト）か。読み飛ばしてよい。
    pub fn is_server_initiated(&self) -> bool {
        self.result.is_none() && self.error.is_none() && self.method.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// --- initialize ---

pub fn initialize_params(client_version: &str) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": preferred_protocol_version(),
        // harnessはサーバ起点の機能（sampling/roots）を一切受け付けない。空で申告する。
        "capabilities": {},
        "clientInfo": { "name": CLIENT_NAME, "version": client_version },
    })
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(default, rename = "serverInfo")]
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

// --- tools/list ---

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ToolsListResult {
    #[serde(default)]
    pub tools: Vec<McpToolDef>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// サーバが申告する1ツール。**`annotations`（`readOnlyHint`等）は意図的に読まない**——
/// 検証できない申告を自動許可の根拠にしないというD-40の帰結で、フィールドを持たないこと自体が
/// 「参照していない」ことの担保になる。
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<serde_json::Value>,
}

// --- tools/call ---

pub fn tools_call_params(name: &str, arguments: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "name": name, "arguments": arguments })
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ToolsCallResult {
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    /// テキスト以外（画像・音声・埋め込みリソース）は、種別だけをテキストとして残す。
    /// M15.5のスコープはテキスト応答で、内容を捨てたことを黙らせない。
    #[serde(other)]
    Other,
}

impl ToolsCallResult {
    /// ツール出力の文字列表現。テキストブロックを連結し、非テキストは種別を明示する。
    pub fn to_text(&self) -> String {
        if self.content.is_empty() {
            return String::new();
        }
        self.content
            .iter()
            .map(|b| match b {
                ContentBlock::Text { text } => text.clone(),
                ContentBlock::Other => {
                    "[non-text content omitted (harness M15.5 handles text blocks only)]"
                        .to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **golden**: `initialize`のワイヤ形式。別プロセスと交換する形なので、変えるときは
    /// 意図的な変更だと分かるようにする（`netfilterd`の同種テストと同じ方針）。
    #[test]
    fn initialize_request_wire_format_is_stable() {
        let req = JsonRpcRequest::new(1, "initialize", Some(initialize_params("0.1.0")));
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"harness","version":"0.1.0"},"protocolVersion":"2025-06-18"}}"#
        );
    }

    #[test]
    fn initialized_notification_wire_format_is_stable() {
        let note = JsonRpcNotification::new("notifications/initialized", None);
        assert_eq!(
            serde_json::to_string(&note).unwrap(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        );
    }

    /// **golden**: `tools/list`。
    #[test]
    fn tools_list_request_wire_format_is_stable() {
        let req = JsonRpcRequest::new(2, "tools/list", Some(serde_json::json!({})));
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#
        );
    }

    /// **golden**: `tools/call`。`arguments`はモデルが返した入力をそのまま運ぶ。
    #[test]
    fn tools_call_request_wire_format_is_stable() {
        let req = JsonRpcRequest::new(
            3,
            "tools/call",
            Some(tools_call_params(
                "search",
                serde_json::json!({ "query": "hello" }),
            )),
        );
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"query":"hello"},"name":"search"}}"#
        );
    }

    #[test]
    fn tools_list_result_parses_and_ignores_unknown_fields() {
        let raw = serde_json::json!({
            "tools": [{
                "name": "search",
                "description": "search the docs",
                "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } } },
                "annotations": { "readOnlyHint": true },
                "somethingNewInAFutureSpec": 42
            }]
        });
        let parsed: ToolsListResult = serde_json::from_value(raw).unwrap();
        assert_eq!(parsed.tools.len(), 1);
        assert_eq!(parsed.tools[0].name, "search");
        assert_eq!(
            parsed.tools[0].description.as_deref(),
            Some("search the docs")
        );
    }

    /// D-40: サーバ申告の`readOnlyHint`は型として持たない（参照しようがない）。
    #[test]
    fn server_declared_read_only_hint_is_not_representable() {
        let json = serde_json::to_string(&serde_json::json!({
            "name": "delete_all", "annotations": { "readOnlyHint": true }
        }))
        .unwrap();
        let def: McpToolDef = serde_json::from_str(&json).unwrap();
        // `McpToolDef`はname/description/inputSchemaしか持たない。hintは読み捨てられる。
        assert_eq!(def.name, "delete_all");
        assert!(def.description.is_none());
    }

    #[test]
    fn tool_call_result_joins_text_blocks() {
        let result: ToolsCallResult = serde_json::from_value(serde_json::json!({
            "content": [{"type":"text","text":"a"},{"type":"text","text":"b"}]
        }))
        .unwrap();
        assert_eq!(result.to_text(), "a\nb");
        assert!(!result.is_error);
    }

    #[test]
    fn non_text_content_is_flagged_rather_than_silently_dropped() {
        let result: ToolsCallResult = serde_json::from_value(serde_json::json!({
            "content": [{"type":"image","data":"...","mimeType":"image/png"}]
        }))
        .unwrap();
        assert!(result.to_text().contains("non-text content omitted"));
    }

    #[test]
    fn is_error_result_is_parsed() {
        let result: ToolsCallResult = serde_json::from_value(serde_json::json!({
            "content": [{"type":"text","text":"boom"}], "isError": true
        }))
        .unwrap();
        assert!(result.is_error);
    }

    #[test]
    fn incoming_distinguishes_responses_notifications_and_errors() {
        let response: JsonRpcIncoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#).unwrap();
        assert!(response.matches_id(7));
        assert!(!response.is_server_initiated());

        let notification: JsonRpcIncoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/message"}"#).unwrap();
        assert!(notification.is_server_initiated());
        assert!(!notification.matches_id(7));

        let error: JsonRpcIncoming = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"nope"}}"#,
        )
        .unwrap();
        assert!(error.matches_id(7));
        assert_eq!(error.error.unwrap().code, -32601);
    }

    /// サーバがidを文字列で返す実装差にも耐える。
    #[test]
    fn string_ids_in_responses_still_match() {
        let response: JsonRpcIncoming =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":"7","result":{}}"#).unwrap();
        assert!(response.matches_id(7));
        assert!(!response.matches_id(8));
    }
}
