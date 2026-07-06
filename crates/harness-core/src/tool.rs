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

/// 読取スコープの反転モード（`plans/DESIGN-SANDBOX.md` §5、M11）。既定は`Whitelist`
/// （安全既定＝列挙した外部ルートのみ読取可）。`Blacklist`は列挙した禁止パスのみを拒否し、
/// それ以外の外部絶対パスは読取可とする（オプトインの緩和モード）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadMode {
    #[default]
    Whitelist,
    Blacklist,
}

/// 読取スコープ設定（M11）。`harness-sandbox::read_scope::ReadScope`が判定の実体を持つ
/// （`harness-core`は値を運ぶだけ、`StagingConfig`と同じ役割分担）。
#[derive(Debug, Clone, Default)]
pub struct ReadScopeConfig {
    pub mode: ReadMode,
    /// 読取を許可する外部ルート（workspaceは暗黙に含むためここには含めない）。
    /// 既定で直下のみ読取可（掘り下げ不可）。
    pub allow: Vec<std::path::PathBuf>,
    /// 再帰読取を許可する外部ルート。
    pub allow_descend: Vec<std::path::PathBuf>,
    /// 読取禁止（blacklistモードで使用）。絶対パス、またはworkspace内の任意の階層に現れる
    /// 名前（例 `.git`）のいずれかとして解釈する。
    pub deny: Vec<String>,
    /// 掘り下げ禁止（配下をwalkしない）。whitelist/blacklist両モードで使う
    /// （例 `node_modules`・`.git`）。
    pub deny_descend: Vec<String>,
}

/// シェル隔離Tier（M12、`plans/DESIGN-SANDBOX.md` §6）。Tier1'（VHDX）は本フェーズの
/// 対象外（設計書がexperimental/オプトイン枠と位置付ける既定外Tier）。Tier1a（AppContainer）は
/// D-02が定める「既定にせずフラグでオプトイン」の実験的Tierとして実装済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTier {
    /// Linux: bubblewrap（user+mount+network namespace + OverlayFS）。
    Tier2,
    /// Windows: AppContainer（package SID + capability SID）。実験的/フラグ付き
    /// （`--experimental-tier1a`、D-02）。範囲外書込の物理拒否に加え、network を
    /// capabilityゲートでdefault-denyにする（T-04/T-10対策の核）。
    Tier1a,
    /// Windows: Restricted Token + 低Integrity Level + Job Object。
    Tier1b,
    /// 保険（cwd拘束のみ・secret env strip・timeout/出力上限、best-effort）。
    Tier0,
}

impl ShellTier {
    pub fn label(self) -> &'static str {
        match self {
            ShellTier::Tier2 => "tier2",
            ShellTier::Tier1a => "tier1a",
            ShellTier::Tier1b => "tier1b",
            ShellTier::Tier0 => "tier0",
        }
    }
}

/// `--require-sandbox[=confidential]`（`plans/DESIGN-SANDBOX.md` §7 D-03）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequireSandbox {
    #[default]
    None,
    /// 書込拘束以上（Tier1b/Tier1a/Tier2でpass、Tier0で拒否）。
    WriteContainment,
    /// 機密性も要求（Tier1a/Tier2のみpass、Tier1b/Tier0で拒否）。判定の実体は
    /// `harness-sandbox::shell_tier::satisfies`（§8-2の判定表）。
    Confidential,
}

/// `harness-sandbox::shell_tier::select_tier`の結果。`ToolCtx`が運ぶ「値」であり、
/// 判定ロジックの実体（OS能力プローブ）は`harness-sandbox`側にある
/// （`StagingConfig`/`ReadScopeConfig`と同じ役割分担）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTierSelection {
    pub tier: ShellTier,
    pub downgraded_from: Option<ShellTier>,
    pub reason: Option<String>,
}

impl ShellTierSelection {
    pub fn direct(tier: ShellTier) -> Self {
        Self {
            tier,
            downgraded_from: None,
            reason: None,
        }
    }

    pub fn downgraded(from: ShellTier, to: ShellTier, reason: impl Into<String>) -> Self {
        Self {
            tier: to,
            downgraded_from: Some(from),
            reason: Some(reason.into()),
        }
    }

    /// 非隔離（Tier0）かどうか。`run_shell`出力への警告付与判定に使う
    /// （M12受入条件「非隔離時警告」）。
    pub fn is_unisolated(&self) -> bool {
        self.tier == ShellTier::Tier0
    }
}

impl Default for ShellTierSelection {
    /// `ToolCtx::new`（テスト等）向けの既定値。実際の選択は`harness-sandbox::select_tier`が行う。
    fn default() -> Self {
        Self::direct(ShellTier::Tier0)
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
    /// 読取スコープ設定（M11）。既定（`ReadScopeConfig::default()`）はwhitelistかつ
    /// 外部ルート未設定＝M10までと等価（workspace外の絶対パス読取は一切不可）。
    pub read_scope: ReadScopeConfig,
    /// シェル隔離Tier選択結果（M12）。既定（`ShellTierSelection::default()`＝Tier0）は
    /// `harness-sandbox::select_tier`を呼ばないテスト経路向けのプレースホルダで、
    /// 実行時は`harness-cli`が起動時に1回選択した値を積む。
    pub shell_tier: ShellTierSelection,
}

impl ToolCtx {
    /// live既定（オーバーレイ無し）・読取スコープ既定（外部ルート無し）で`ToolCtx`を作る。
    /// 既存の`ToolCtx { workspace_root }`呼び出し箇所（主にテスト）の置き換え先。
    pub fn new(workspace_root: std::path::PathBuf) -> Self {
        Self {
            workspace_root,
            staging: StagingConfig::default(),
            read_scope: ReadScopeConfig::default(),
            shell_tier: ShellTierSelection::default(),
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
