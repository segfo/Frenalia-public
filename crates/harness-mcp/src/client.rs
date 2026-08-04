//! 1つのMCPサーバとの長寿命セッション（`plans/DESIGN-MCP.md` §3.3）。
//!
//! `run_shell`のTier2a spawnは「コマンドを渡し、終わるまで待ち、出力を全部読む」一問一答だが、
//! MCP stdioは**プロセスを生かしたまま、リクエストとレスポンスを何度も往復させる**。この型が
//! その往復の側を持つ（プロセスの生存そのものは`Transport`実装＝Job Objectが持つ）。
//!
//! ## 1サーバにつき同時1リクエストへ直列化する
//!
//! JSON-RPCは本来リクエストを多重化できるが、ここではmutexで1往復ずつに直列化する。**未信頼の
//! サーバが相手なので、応答の順序・idの対応・打ち切りの扱いを全部正しく実装する必要がある多重化を
//! 避け、状態機械を「送る→自分宛の応答が来るまで読む」だけに保つ**という判断である。
//! 代償は「同一サーバへの遅い呼び出しが後続を待たせる」ことで、サーバをまたぐ並行性は失わない
//! （サーバごとに別の`McpClient`）。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::protocol::{
    initialize_params, tools_call_params, InitializeResult, JsonRpcIncoming, JsonRpcNotification,
    JsonRpcRequest, McpToolDef, ToolsCallResult, ToolsListResult, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::transport::Transport;
use crate::McpError;

/// `tools/list`のページングが終わらないサーバに付き合わされないための上限。
const MAX_TOOL_LIST_PAGES: usize = 32;

pub struct McpClient {
    server_id: String,
    inner: Mutex<Inner>,
}

struct Inner {
    transport: Box<dyn Transport>,
    next_id: u64,
    closed: bool,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("server_id", &self.server_id)
            .finish_non_exhaustive()
    }
}

impl McpClient {
    pub fn new(server_id: impl Into<String>, transport: Box<dyn Transport>) -> Self {
        Self {
            server_id: server_id.into(),
            inner: Mutex::new(Inner {
                transport,
                next_id: 1,
                closed: false,
            }),
        }
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// `initialize` → `notifications/initialized` → `tools/list`。サーバが申告したツール定義を
    /// 返す（**名前の妥当性検査は呼び出し側＝[`crate::runtime`]が行う**。ここはプロトコルの
    /// 往復だけを担当する）。
    pub fn handshake(
        &self,
        client_version: &str,
        timeout: Duration,
    ) -> Result<Vec<McpToolDef>, McpError> {
        let init: InitializeResult = self.request_as(
            "initialize",
            Some(initialize_params(client_version)),
            timeout,
        )?;
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&init.protocol_version.as_str()) {
            // P-05と同じ倒し方: 分からないものは「たぶん大丈夫」ではなく拒否する。
            return Err(McpError::Unsupported(format!(
                "mcp server {} negotiated protocol version {:?}, which this harness does not \
                 support (supported: {})",
                self.server_id,
                init.protocol_version,
                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
            )));
        }
        self.notify("notifications/initialized", None)?;

        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_LIST_PAGES {
            let params = match &cursor {
                Some(c) => serde_json::json!({ "cursor": c }),
                None => serde_json::json!({}),
            };
            let page: ToolsListResult = self.request_as("tools/list", Some(params), timeout)?;
            tools.extend(page.tools);
            match page.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => return Ok(tools),
            }
        }
        Err(McpError::Protocol(format!(
            "mcp server {} kept paginating tools/list past {MAX_TOOL_LIST_PAGES} pages",
            self.server_id
        )))
    }

    /// `tools/call`。サーバ側のツール名（名前空間を付ける前の名前）を渡す。
    pub fn call_tool(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        timeout: Duration,
    ) -> Result<ToolsCallResult, McpError> {
        self.request_as("tools/call", Some(tools_call_params(tool, arguments)), timeout)
    }

    pub fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if !inner.closed {
                inner.closed = true;
                inner.transport.shutdown();
            }
        }
    }

    /// サーバのstderr（起動失敗の理由がここにしか出ないサーバが多い）。
    pub fn drain_stderr(&self) -> String {
        match self.inner.lock() {
            Ok(mut inner) => inner.transport.take_stderr(),
            Err(_) => String::new(),
        }
    }

    fn request_as<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        timeout: Duration,
    ) -> Result<T, McpError> {
        let value = self.request(method, params, timeout)?;
        serde_json::from_value(value).map_err(|e| {
            McpError::Protocol(format!(
                "mcp server {} returned a malformed {method} result: {e}",
                self.server_id
            ))
        })
    }

    fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        timeout: Duration,
    ) -> Result<serde_json::Value, McpError> {
        let mut inner = self.inner.lock().map_err(|_| McpError::Closed)?;
        if inner.closed {
            return Err(McpError::Closed);
        }
        let id = inner.next_id;
        inner.next_id += 1;

        let request = JsonRpcRequest::new(id, method, params);
        let line = serde_json::to_string(&request)
            .map_err(|e| McpError::Protocol(format!("failed to serialize {method}: {e}")))?;
        inner.transport.send_line(&line)?;

        // **締切は往復全体で1つ**。自分宛でない行（サーバ起点の通知）を読み飛ばす間も同じ
        // 締切を使うので、通知を送り続けるサーバに無限に付き合わされることがない。
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(self.timeout_error(&mut inner, method));
            }
            let raw = match inner.transport.recv_line(remaining) {
                Ok(raw) => raw,
                Err(McpError::Timeout(_)) => return Err(self.timeout_error(&mut inner, method)),
                Err(e) => return Err(e),
            };
            let incoming: JsonRpcIncoming = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(e) => {
                    return Err(McpError::Protocol(format!(
                        "mcp server {} sent a line that is not JSON-RPC ({e}): {}",
                        self.server_id,
                        truncate_for_message(&raw)
                    )))
                }
            };
            if incoming.is_server_initiated() {
                // サーバ起点の通知・リクエスト（`notifications/message`等）は、M15.5では
                // 受け付ける機能が無いので読み飛ばす。応答を返さないことは通知に対しては正しく、
                // サーバ起点リクエストに対しては相手側でタイムアウトするが、harnessが
                // sampling/rootsを`initialize`で申告していない以上そもそも来ない。
                continue;
            }
            if !incoming.matches_id(id) {
                // 直列化しているので、自分以外のidの応答は来ないはず。来たら状態がずれている。
                continue;
            }
            if let Some(err) = incoming.error {
                return Err(McpError::Server {
                    code: err.code,
                    message: err.message,
                });
            }
            return Ok(incoming.result.unwrap_or(serde_json::Value::Null));
        }
    }

    fn notify(&self, method: &str, params: Option<serde_json::Value>) -> Result<(), McpError> {
        let mut inner = self.inner.lock().map_err(|_| McpError::Closed)?;
        if inner.closed {
            return Err(McpError::Closed);
        }
        let note = JsonRpcNotification::new(method, params);
        let line = serde_json::to_string(&note)
            .map_err(|e| McpError::Protocol(format!("failed to serialize {method}: {e}")))?;
        inner.transport.send_line(&line)
    }

    /// タイムアウト時はstderrを添える。これが無いと「サーバが応答しません」しか言えず、
    /// 実際の原因（モジュール解決の失敗・認証エラー等）がユーザーに一切届かない。
    fn timeout_error(&self, inner: &mut Inner, method: &str) -> McpError {
        let stderr = inner.transport.take_stderr();
        let stderr = stderr.trim();
        if stderr.is_empty() {
            McpError::Timeout(format!(
                "mcp server {} did not answer {method} in time (no stderr output)",
                self.server_id
            ))
        } else {
            McpError::Timeout(format!(
                "mcp server {} did not answer {method} in time; stderr: {}",
                self.server_id,
                truncate_for_message(stderr)
            ))
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn truncate_for_message(s: &str) -> String {
    const LIMIT: usize = 2000;
    if s.len() <= LIMIT {
        return s.to_string();
    }
    let mut cut = LIMIT;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}... (truncated)", &s[..cut])
}

#[cfg(test)]
pub(crate) mod test_support {
    //! テスト用の台本トランスポート。**本番コードには隔離なしの通信路を置かない**
    //! （`plans/DESIGN-MCP.md` §3.4の明示オプトイン以外の抜け道を作らない）ため、
    //! `#[cfg(test)]`に閉じている。

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::transport::Transport;
    use crate::McpError;

    /// 「送られた行」を記録し、「返す行」を台本から返すトランスポート。
    #[derive(Default)]
    pub struct ScriptedTransport {
        pub sent: Arc<Mutex<Vec<String>>>,
        pub scripted: VecDeque<Result<String, McpError>>,
        pub stderr: String,
        pub shutdown_calls: Arc<Mutex<usize>>,
    }

    impl ScriptedTransport {
        pub fn new(lines: Vec<String>) -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                scripted: lines.into_iter().map(Ok).collect(),
                stderr: String::new(),
                shutdown_calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl Transport for ScriptedTransport {
        fn send_line(&mut self, line: &str) -> Result<(), McpError> {
            self.sent.lock().unwrap().push(line.to_string());
            Ok(())
        }

        fn recv_line(&mut self, _timeout: Duration) -> Result<String, McpError> {
            self.scripted
                .pop_front()
                .unwrap_or_else(|| Err(McpError::Timeout("scripted transport exhausted".into())))
        }

        fn take_stderr(&mut self) -> String {
            std::mem::take(&mut self.stderr)
        }

        fn shutdown(&mut self) {
            *self.shutdown_calls.lock().unwrap() += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::ScriptedTransport;
    use super::*;
    use std::sync::{Arc, Mutex};

    fn timeout() -> Duration {
        Duration::from_secs(5)
    }

    fn client_with(lines: Vec<&str>) -> (McpClient, Arc<Mutex<Vec<String>>>) {
        let transport = ScriptedTransport::new(lines.into_iter().map(String::from).collect());
        let sent = transport.sent.clone();
        (McpClient::new("docs", Box::new(transport)), sent)
    }

    const INIT_OK: &str =
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"mock","version":"1"}}}"#;

    /// **完了条件のgolden**: `tools/list`の往復。送信バイト列と受信の解釈の両方を固定する。
    #[test]
    fn handshake_sends_initialize_initialized_and_tools_list() {
        let (client, sent) = client_with(vec![
            INIT_OK,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"d","inputSchema":{"type":"object"}}]}}"#,
        ]);

        let tools = client.handshake("0.1.0", timeout()).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "search");

        let sent = sent.lock().unwrap().clone();
        assert_eq!(
            sent,
            vec![
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"harness","version":"0.1.0"},"protocolVersion":"2025-06-18"}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ]
        );
    }

    /// **完了条件のgolden**: `tools/call`の往復。
    #[test]
    fn call_tool_sends_the_expected_request_and_parses_the_result() {
        let (client, sent) = client_with(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"42 hits"}]}}"#,
        ]);

        let result = client
            .call_tool("search", serde_json::json!({ "query": "x" }), timeout())
            .unwrap();
        assert_eq!(result.to_text(), "42 hits");

        assert_eq!(
            sent.lock().unwrap()[0],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"query":"x"},"name":"search"}}"#
        );
    }

    #[test]
    fn server_initiated_notifications_are_skipped_while_waiting_for_a_response() {
        let (client, _sent) = client_with(vec![
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#,
        ]);
        let result = client
            .call_tool("search", serde_json::json!({}), timeout())
            .unwrap();
        assert_eq!(result.to_text(), "ok");
    }

    #[test]
    fn a_json_rpc_error_response_becomes_a_server_error() {
        let (client, _sent) = client_with(vec![
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad args"}}"#,
        ]);
        let err = client
            .call_tool("search", serde_json::json!({}), timeout())
            .unwrap_err();
        assert!(matches!(
            err,
            McpError::Server { code: -32602, ref message } if message == "bad args"
        ));
    }

    /// 未サポートのプロトコルバージョンでは接続を続けない（P-05の倒し方）。
    #[test]
    fn an_unsupported_protocol_version_aborts_the_handshake() {
        let (client, _sent) = client_with(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1999-01-01"}}"#,
        ]);
        assert!(matches!(
            client.handshake("0.1.0", timeout()),
            Err(McpError::Unsupported(_))
        ));
    }

    #[test]
    fn non_json_output_from_the_server_is_reported_as_a_protocol_violation() {
        let (client, _sent) = client_with(vec!["node: command not found"]);
        assert!(matches!(
            client.handshake("0.1.0", timeout()),
            Err(McpError::Protocol(_))
        ));
    }

    /// `tools/list`のページングに従う（`nextCursor`）。
    #[test]
    fn tools_list_pagination_is_followed() {
        let (client, sent) = client_with(vec![
            INIT_OK,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":"p2"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"b"}]}}"#,
        ]);
        let tools = client.handshake("0.1.0", timeout()).unwrap();
        assert_eq!(
            tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(sent.lock().unwrap()[3].contains(r#""cursor":"p2""#));
    }

    /// タイムアウト時はstderrを添えて返す（診断可能性）。
    #[test]
    fn a_timeout_includes_the_server_stderr() {
        let mut transport = ScriptedTransport::new(vec![]);
        transport.stderr = "Error: Cannot find module 'x'".to_string();
        let client = McpClient::new("docs", Box::new(transport));
        let err = client.handshake("0.1.0", timeout()).unwrap_err();
        match err {
            McpError::Timeout(msg) => assert!(msg.contains("Cannot find module"), "{msg}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn shutdown_is_idempotent_and_closes_the_transport_once() {
        let transport = ScriptedTransport::new(vec![]);
        let calls = transport.shutdown_calls.clone();
        let client = McpClient::new("docs", Box::new(transport));
        client.shutdown();
        client.shutdown();
        drop(client);
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn requests_after_shutdown_fail_rather_than_hanging() {
        let (client, _sent) = client_with(vec![]);
        client.shutdown();
        assert!(matches!(
            client.call_tool("x", serde_json::json!({}), timeout()),
            Err(McpError::Closed)
        ));
    }
}
