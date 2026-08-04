//! MCPツールの`Tool` trait への写像（`plans/DESIGN-MCP.md` §5）。
//!
//! モデルから見た姿は組み込みツールと同一である（名前空間`mcp__<server>__<tool>`だけが違う）。
//! ここが持つ判断は2つだけで、どちらも「サーバの自己申告を信じない」という一点に由来する。
//!
//! 1. **`RiskClass`はユーザー宣言による**（D-40）。サーバの`readOnlyHint`等は検証手段が無いので
//!    自動許可の根拠にしない。宣言の無いツールは非readとして扱い、`PermissionArbiter`を必ず通る。
//! 2. **入力の explicit null を送信前に除去する**（`DESIGN.md` §ツールシステム スキーマ生成 (f)）。
//!    自作ツールはserdeの`Option`がnullを吸収するが、MCPは入力Valueを外部サーバへ生転送するため、
//!    明示nullがサーバ側バリデーションで弾かれる。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};

use crate::client::McpClient;
use crate::McpError;

/// 1回の`tools/call`を待つ既定の上限。
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// `ToolRegistry`へ載るMCPツール1件。
pub struct McpTool {
    /// `mcp__<server>__<tool>`。allowlistルール・承認プロンプト・監査ログでもこの表記を使う。
    name: String,
    /// サーバ側のツール名（`tools/call`で送る名前）。
    remote_name: String,
    server_id: String,
    description: String,
    input_schema: serde_json::Value,
    risk: RiskClass,
    client: Arc<McpClient>,
    call_timeout: Duration,
}

impl std::fmt::Debug for McpTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpTool")
            .field("name", &self.name)
            .field("risk", &self.risk)
            .finish_non_exhaustive()
    }
}

impl McpTool {
    pub fn new(
        server_id: &str,
        remote_name: &str,
        description: Option<&str>,
        input_schema: Option<&serde_json::Value>,
        risk: RiskClass,
        client: Arc<McpClient>,
    ) -> Self {
        Self {
            name: crate::decl::namespaced_tool_name(server_id, remote_name),
            remote_name: remote_name.to_string(),
            server_id: server_id.to_string(),
            description: describe(server_id, description),
            input_schema: sanitize_input_schema(input_schema),
            risk,
            client,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn remote_name(&self) -> &str {
        &self.remote_name
    }
}

/// モデルへ見せる説明。**第三者サーバ由来であることを明示する**——`DESIGN-COGNITION.md` §4.3の
/// 接地判定（MCP単独ではConfirmedにできない）を、モデル側でも読み取れるようにするため。
fn describe(server_id: &str, description: Option<&str>) -> String {
    match description {
        Some(d) if !d.trim().is_empty() => {
            format!("[mcp server: {server_id}] {}", d.trim())
        }
        _ => format!("[mcp server: {server_id}] (the server provided no description)"),
    }
}

/// サーバ申告の`inputSchema`を、そのままプロバイダへ渡せる形へ整える。
///
/// **外来スキーマなので中身の正しさは保証しない**（サーバは未信頼）。ここで行うのは、
/// プロバイダが確実に落ちる形（オブジェクトでない・`$schema`が入っている）を避けることだけ。
fn sanitize_input_schema(schema: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(serde_json::Value::Object(map)) = schema else {
        // スキーマ無し/オブジェクトでない申告は「引数なしのオブジェクト」として扱う。
        return serde_json::json!({ "type": "object", "properties": {} });
    };
    let mut map = map.clone();
    map.remove("$schema");
    map.entry("type")
        .or_insert_with(|| serde_json::Value::String("object".to_string()));
    serde_json::Value::Object(map)
}

/// `DESIGN.md` §ツールシステム スキーマ生成 (f): explicit null キーを再帰的に除去する。
///
/// モデルはstrictスキーマの下で「省略」の代わりに明示`null`を返す。自作ツールはserdeの
/// `Option`が吸収するが、**MCPは入力Valueを外部サーバへ生転送するため**、明示nullがサーバ側の
/// バリデーション（例: JSON Schemaの`type: "string"`）で弾かれる。
pub fn strip_explicit_nulls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_explicit_nulls(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            // 配列の要素そのものがnullなのは「値としてのnull」なので消さない（キーではない）。
            serde_json::Value::Array(items.into_iter().map(strip_explicit_nulls).collect())
        }
        other => other,
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn input_schema(&self) -> serde_json::Value {
        self.input_schema.clone()
    }

    /// D-40。**入力に依存しない**——サーバのツールは入力を見ても危険度を判定できないので、
    /// 宣言された値をそのまま返す（`run_shell`のようにコマンド行で判断する余地が無い）。
    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        self.risk
    }

    async fn call(
        &self,
        input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let arguments = strip_explicit_nulls(input);
        let client = self.client.clone();
        let remote_name = self.remote_name.clone();
        let timeout = self.call_timeout;

        // `McpClient`はブロッキング（生HANDLEパイプ）なので、ランタイムのワーカースレッドを
        // 塞がないよう`spawn_blocking`へ逃がす（`VmShellExecutor`経由のTier3 `run_shell`と同じ扱い）。
        let result = tokio::task::spawn_blocking(move || {
            client.call_tool(&remote_name, arguments, timeout)
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("mcp call task failed: {e}")))?;

        match result {
            Ok(call) => Ok(ToolOutput {
                content: call.to_text(),
                is_error: call.is_error,
            }),
            // サーバが返した業務エラー（`isError`ではなくJSON-RPCのerror）はツールのエラーとして
            // モデルへ返す。ハーネス側の障害（タイムアウト・プロトコル違反）と区別できるよう
            // 文言に種別を残す。
            Err(McpError::Server { code, message }) => Ok(ToolOutput {
                content: format!("mcp server error (code {code}): {message}"),
                is_error: true,
            }),
            Err(e) => Err(ToolError::ExecutionFailed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_support::ScriptedTransport;

    fn tool_with(lines: Vec<&str>, risk: RiskClass) -> McpTool {
        let transport = ScriptedTransport::new(lines.into_iter().map(String::from).collect());
        let client = Arc::new(McpClient::new("docs", Box::new(transport)));
        McpTool::new(
            "docs",
            "search",
            Some("search the docs"),
            Some(&serde_json::json!({
                "type": "object",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "properties": { "query": { "type": "string" } }
            })),
            risk,
            client,
        )
    }

    #[test]
    fn the_registered_name_uses_the_provider_safe_namespace() {
        let tool = tool_with(vec![], RiskClass::ReadOnly);
        assert_eq!(tool.name(), "mcp__docs__search");
        assert_eq!(tool.remote_name(), "search");
    }

    #[test]
    fn the_description_marks_the_tool_as_coming_from_a_third_party_server() {
        let tool = tool_with(vec![], RiskClass::ReadOnly);
        assert!(tool.description().starts_with("[mcp server: docs]"));
    }

    #[test]
    fn schema_dollar_schema_is_removed_and_type_is_forced_to_object() {
        let tool = tool_with(vec![], RiskClass::ReadOnly);
        let schema = tool.input_schema();
        assert!(schema.get("$schema").is_none());
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["query"].is_object());
    }

    #[test]
    fn a_server_without_an_input_schema_still_produces_a_usable_object_schema() {
        assert_eq!(
            sanitize_input_schema(None),
            serde_json::json!({ "type": "object", "properties": {} })
        );
        assert_eq!(
            sanitize_input_schema(Some(&serde_json::json!("not an object"))),
            serde_json::json!({ "type": "object", "properties": {} })
        );
    }

    /// D-40: 宣言されたRiskClassをそのまま使い、入力では変わらない。
    #[test]
    fn risk_comes_from_the_declaration_not_the_input() {
        let tool = tool_with(vec![], RiskClass::Network);
        assert_eq!(tool.risk(&serde_json::json!({})), RiskClass::Network);
        assert_eq!(
            tool.risk(&serde_json::json!({ "looks": "harmless" })),
            RiskClass::Network
        );
    }

    /// (f) explicit null 除去。ネストしたオブジェクトにも効く。
    #[test]
    fn explicit_nulls_are_stripped_before_the_request_reaches_the_server() {
        let input = serde_json::json!({
            "query": "x",
            "limit": null,
            "nested": { "a": null, "b": 1 },
            "list": [ { "c": null, "d": 2 } ]
        });
        assert_eq!(
            strip_explicit_nulls(input),
            serde_json::json!({
                "query": "x",
                "nested": { "b": 1 },
                "list": [ { "d": 2 } ]
            })
        );
    }

    /// 配列の要素としてのnullは値なので残す（キーの省略とは別物）。
    #[test]
    fn null_array_elements_are_preserved() {
        assert_eq!(
            strip_explicit_nulls(serde_json::json!({ "xs": [1, null, 2] })),
            serde_json::json!({ "xs": [1, null, 2] })
        );
    }

    #[tokio::test]
    async fn a_successful_call_returns_the_joined_text_content() {
        let tool = tool_with(
            vec![r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hit"}]}}"#],
            RiskClass::ReadOnly,
        );
        let ctx = ToolCtx::new(std::path::PathBuf::from("."));
        let out = tool
            .call(serde_json::json!({ "query": "x", "limit": null }), &ctx)
            .await
            .unwrap();
        assert_eq!(out.content, "hit");
        assert!(!out.is_error);
    }

    /// nullを落としたうえで送っていることを、実際に送られたバイト列で確認する。
    #[tokio::test]
    async fn the_request_sent_to_the_server_contains_no_explicit_nulls() {
        let transport = ScriptedTransport::new(vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#.to_string(),
        ]);
        let sent = transport.sent.clone();
        let client = Arc::new(McpClient::new("docs", Box::new(transport)));
        let tool = McpTool::new("docs", "search", None, None, RiskClass::ReadOnly, client);

        let ctx = ToolCtx::new(std::path::PathBuf::from("."));
        tool.call(serde_json::json!({ "query": "x", "limit": null }), &ctx)
            .await
            .unwrap();

        let line = sent.lock().unwrap()[0].clone();
        assert!(!line.contains("null"), "{line}");
        assert!(line.contains(r#""arguments":{"query":"x"}"#), "{line}");
    }

    /// サーバの業務エラーは`is_error`のツール結果としてモデルへ返す（ループは止めない）。
    #[tokio::test]
    async fn a_json_rpc_error_from_the_server_becomes_an_error_tool_result() {
        let tool = tool_with(
            vec![r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad args"}}"#],
            RiskClass::ReadOnly,
        );
        let ctx = ToolCtx::new(std::path::PathBuf::from("."));
        let out = tool.call(serde_json::json!({}), &ctx).await.unwrap();
        assert!(out.is_error);
        assert!(out.content.contains("bad args"));
    }

    /// ハーネス側の障害（タイムアウト等）は`ToolError`として上げる（サーバの業務エラーと区別）。
    #[tokio::test]
    async fn a_transport_failure_is_a_tool_error_rather_than_an_error_result() {
        let tool = tool_with(vec![], RiskClass::ReadOnly);
        let ctx = ToolCtx::new(std::path::PathBuf::from("."));
        assert!(matches!(
            tool.call(serde_json::json!({}), &ctx).await,
            Err(ToolError::ExecutionFailed(_))
        ));
    }
}
