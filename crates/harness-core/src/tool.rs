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

/// 書込ステージング3モード（`plans/DESIGN.md` §書込ステージング3モード、M10）。
/// パーミッション層（`RiskClass`/`PermissionArbiter`）とは直交する軸で、
/// 「許可された書込の実FS効果をどこへ落とすか」だけを決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingMode {
    /// 即実FS（オーバーレイ無し）。
    Live,
    /// 全書込staging、実FSは手動`apply`まで不変（headless/未信頼の既定）。
    Staged,
    /// workspace内はstaging→レビュー&コミット、workspace外は常にsandbox隔離。
    WorkspaceCommit,
}

/// ツールのステージング設定。`explicit`が`true`なら`mode`をそのまま使い、`false`なら
/// パス毎のgit認識型判定（追跡済み・変更ゼロ→live、それ以外→`mode`）に委ねる
/// （`harness-sandbox::SandboxFs`が判定の実体を持つ。`harness-core`は値を運ぶだけ）。
#[derive(Debug, Clone)]
pub struct StagingConfig {
    pub mode: StagingMode,
    pub explicit: bool,
    /// オーバーレイ・マニフェストの置き場所。**`workspace_root`からの相対パス**
    /// （例 `.harness/sandbox/<session-id>`）で持つ。オーバーレイの実体を常にworkspace内に
    /// 置くことで、`WorkspaceJail`（cap-std主ゲート）1つだけで実FS・オーバーレイの両方を
    /// 仲介できる（`harness-sandbox::SandboxFs`参照）。`None`なら純live（オーバーレイを
    /// 一切使わない、既存コードとの後方互換用）。
    pub sandbox_dir: Option<std::path::PathBuf>,
}

impl Default for StagingConfig {
    fn default() -> Self {
        Self {
            mode: StagingMode::Live,
            explicit: false,
            sandbox_dir: None,
        }
    }
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
    /// 書込ステージング設定（M10）。既定（`StagingConfig::default()`）は純live＝
    /// M9までと等価な直接実FSアクセス。
    pub staging: StagingConfig,
}

impl ToolCtx {
    /// live既定（オーバーレイ無し）で`ToolCtx`を作る。既存の`ToolCtx { workspace_root }`
    /// 呼び出し箇所（主にテスト）の置き換え先。
    pub fn new(workspace_root: std::path::PathBuf) -> Self {
        Self {
            workspace_root,
            staging: StagingConfig::default(),
        }
    }
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
