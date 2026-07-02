use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// プロバイダへ正規化して渡すツール仕様。アダプタが各ワイヤ形式へ再ラップする。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

/// 実行前ゲート（`PermissionArbiter`）が参照するリスク分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    Write,
    Exec,
    Network,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ToolError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("cancelled")]
    Cancelled,
}

/// ツール実行のコンテキスト。ジェイル・キャンセル・イベント通知への足がかり。
/// 具体的な実装（cap-std の `Dir` ハンドル等）は `harness-sandbox`/`harness-engine` が注入する
/// （`harness-core` は「重い依存ゼロ」原則のためワークスペースルートはパスのみで表現する）。
#[derive(Debug, Clone)]
pub struct ToolCtx {
    pub workspace_root: std::path::PathBuf,
}

/// 変動点（ツール実装）を隠す唯一のtrait境界。開いた集合なので trait object で拡張可能。
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// schemars + strict変換で生成する入力スキーマ。
    fn input_schema(&self) -> serde_json::Value;
    /// 実行前ゲート。具体入力（実際のコマンド行/書込先）に基づき申告する。
    fn risk(&self, input: &serde_json::Value) -> RiskClass;
    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError>;
}
