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
/// 対象外。Tier2a（AppContainer）/Tier2b（bubblewrap）は既定の上限Tierとして実装済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTier {
    /// Windows: Hyper-V外層VM（AlmaLinux）+ Incus内層コンテナ（`plans/DESIGN-SANDBOX-VMISOLATION.md`）。
    /// vNIC単位で出口を強制できる唯一のTier。VM起動オーバーヘッドが高いため`--vm-sandbox`
    /// で明示オプトインする。`run_shell`は`ToolCtx.vm_sandbox`経由でコンテナ内実行に
    /// 委譲する（他Tierと異なり実プロセスをホスト側にspawnしない）。
    Tier3,
    /// Linux: bubblewrap（user+mount+network namespace + OverlayFS）。
    Tier2b,
    /// Windows: AppContainer（package SID + capability SID）。範囲外書込の物理拒否に加え、network を
    /// capabilityゲートでdefault-denyにする（T-04/T-10対策の核）。
    Tier2a,
    /// Windows: Restricted Token + 低Integrity Level + Job Object。
    Tier1,
    /// 保険（cwd拘束のみ・secret env strip・timeout/出力上限、best-effort）。
    Tier0,
}

impl ShellTier {
    pub fn label(self) -> &'static str {
        match self {
            ShellTier::Tier3 => "tier3",
            ShellTier::Tier2b => "tier2b",
            ShellTier::Tier2a => "tier2a",
            ShellTier::Tier1 => "tier1",
            ShellTier::Tier0 => "tier0",
        }
    }
}

/// `--require-sandbox[=confidential]`（`plans/DESIGN-SANDBOX.md` §7 D-03）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequireSandbox {
    #[default]
    None,
    /// 書込拘束以上（Tier3/Tier2a/Tier1/Tier2bでpass、Tier0で拒否）。
    WriteContainment,
    /// 機密性も要求（Tier3/Tier2a/Tier2bのみpass、Tier1/Tier0で拒否）。判定の実体は
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
    /// D8（`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺・fs passthrough）: 到達不能だった
    /// `--fs-allow`穴の診断メッセージ一覧。空なら全穴到達可、または該当なし。Tier選択自体
    /// （`tier`/`downgraded_from`）には影響しない（壊れた穴があってもTier2a・workspaceは継続）。
    pub passthrough_warnings: Vec<String>,
    /// D8: 到達不能/付与失敗だったfs passthroughの構造化リスト。
    /// `harness-cli`はこれをユーザグローバル台帳へ記録し、後から`.harness/settings.json`の
    /// `fs.read`/`fs.read_write`/`fs.read_exec`へ追加するための材料として表示する。
    pub denied_passthrough: Vec<(std::path::PathBuf, String, String)>,
    /// `--fs-allow`/`fs.allow`のうち、実際にACE付与が確認できた（既存で十分だった場合を含む）
    /// ルートの一覧（`(path, writable)`）。`harness-cli`側の台帳記録はこれだけを書くことで、
    /// `ACCESS_DENIED`で失敗したのに記録だけ残る「幻の台帳エントリ」を防ぐ
    /// （`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO: --fs-allowの特権分離ヘルパー化」）。
    pub granted_passthrough: Vec<(std::path::PathBuf, bool)>,
    /// WFP連鎖起動（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D シナリオ(A)）を
    /// `preflight`が実際に試みたか。`true`なら呼び出し元（`harness-cli`）は特権分離ヘルパー
    /// 経由で`harness-netfilterd`が起動済み（またはベストエフォートで失敗済み）と見なし、
    /// シナリオ(B)（直接`runas`起動）を重ねて行わない。`false`なら連鎖起動を試みていないため、
    /// ドメインポリシー監査が有効ならシナリオ(B)へフォールバックする必要がある。
    pub netfilterd_chain_attempted: bool,
}

impl ShellTierSelection {
    pub fn direct(tier: ShellTier) -> Self {
        Self {
            tier,
            downgraded_from: None,
            reason: None,
            passthrough_warnings: Vec::new(),
            denied_passthrough: Vec::new(),
            granted_passthrough: Vec::new(),
            netfilterd_chain_attempted: false,
        }
    }

    pub fn downgraded(from: ShellTier, to: ShellTier, reason: impl Into<String>) -> Self {
        Self {
            tier: to,
            downgraded_from: Some(from),
            reason: Some(reason.into()),
            passthrough_warnings: Vec::new(),
            denied_passthrough: Vec::new(),
            granted_passthrough: Vec::new(),
            netfilterd_chain_attempted: false,
        }
    }

    /// D8: fs passthroughの到達不能診断を積む（`direct`/`downgraded`と組み合わせて使う）。
    pub fn with_passthrough_warnings(mut self, warnings: Vec<String>) -> Self {
        self.passthrough_warnings = warnings;
        self
    }

    /// 到達不能/付与失敗だったpassthroughルートの一覧を積む。
    pub fn with_denied_passthrough(
        mut self,
        denied: Vec<(std::path::PathBuf, String, String)>,
    ) -> Self {
        self.denied_passthrough = denied;
        self
    }

    /// 実際にACE付与が確認できたpassthroughルートの一覧を積む（`direct`と組み合わせて使う。
    /// `preflight`が失敗した`downgraded`経路では常に空のまま）。
    pub fn with_granted_passthrough(mut self, granted: Vec<(std::path::PathBuf, bool)>) -> Self {
        self.granted_passthrough = granted;
        self
    }

    /// WFP連鎖起動を`preflight`が試みたかを積む（`direct`と組み合わせて使う）。
    pub fn with_netfilterd_chain_attempted(mut self, attempted: bool) -> Self {
        self.netfilterd_chain_attempted = attempted;
        self
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

/// ドメイン単位network制御設定（`plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`）。
/// `run_shell`子へ`ALL_PROXY=socks5h://...`と`HTTP_PROXY`/`HTTPS_PROXY`を注入するLocal Proxy
/// Agentの許可ドメインを運ぶ。Tier2aでWFP default-deny + loopback実ポート限定allowを併用できる
/// 場合のみ、Proxy非対応の直接connect/raw socketも強制的に遮断できる。WFPが無いTierや
/// `enforced_by_wfp=false`では協調Proxyに留まり、その限界は`run_shell`出力へ明記する。
/// `harness-core`は値を運ぶだけ、判定・Proxy/Fake DNS実体は`harness-tools`、WFP強制は
/// `harness-sandbox`が担う（`StagingConfig`/`ReadScopeConfig`と同じ役割分担）。
#[derive(Debug, Clone)]
pub struct NetProxyConfig {
    /// 許可ドメイン（`*.example.com`形式のサフィックスワイルドカードに対応）。空なら
    /// `domain_policy_enabled=true`のもとで全拒否ポリシーとして扱う。
    pub allow_domains: Vec<String>,
    /// ドメイン単位network制御を起動するか。既定true: 許可ドメインが空でもProxy/Fake DNS/WFP
    /// 監査経路を起動し、全拒否を`net-audit.jsonl`へ残す。falseはテスト・内部互換用。
    pub domain_policy_enabled: bool,
    /// Tier2aでWFP default-deny + loopback allowが有効化されており、Proxy経由通信に必要な
    /// AppContainer network capabilityを安全に付与できるか。falseならfail-closedのため、
    /// `--net-allow-domain`だけではTier2a子へ`internetClient`を付けない。
    pub enforced_by_wfp: bool,
    /// 詳細監査ログのJSONL出力先。`None`なら従来通りプロセス内メモリの短いサマリだけを保持する。
    pub audit_log_path: Option<std::path::PathBuf>,
    /// CLIがセッションスコープで先に起動したLocal Proxy Agentの待受アドレス。`Some`なら
    /// `run_shell`は新規Proxyを起動せず、このアドレスを子プロセスenvへ注入する。
    pub proxy_addr: Option<std::net::SocketAddr>,
    /// CLIがセッションスコープで先に起動したFake DNS Agentの待受アドレス。`Some`なら
    /// `run_shell`は新規Fake DNSを起動せず、このアドレスを診断envへ注入する。
    pub fake_dns_addr: Option<std::net::SocketAddr>,
}

impl Default for NetProxyConfig {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            domain_policy_enabled: true,
            enforced_by_wfp: false,
            audit_log_path: None,
            proxy_addr: None,
            fake_dns_addr: None,
        }
    }
}

/// アプリ単位network制御設定（軸1、`plans/DESIGN-SANDBOX-APPPOLICY.md` D-10/D-11）。
/// Tier2a（AppContainer）で、先頭exe名が`allow_apps`に一致する信頼コマンドにのみ
/// `internetClient` capabilityを付与するための許可リストを運ぶ。空なら常にdeny（既定・
/// 現状維持＝network全遮断）。判定（`classify_net_app`）とcapability適用は`harness-tools`/
/// `harness-sandbox`側で行い、`harness-core`は値を運ぶだけ（`NetProxyConfig`と同じ役割分担）。
///
/// **Tier2a限定**: Tier3/Tier2b/Tier1/Tier0はAppContainer capability機構を持たないため、これらのTierでは`allow_apps`は
/// 効かない（`run_shell`がその旨をフッタに明記する）。
#[derive(Debug, Clone, Default)]
pub struct NetAppPolicy {
    /// 信頼アプリの実行ファイル名リスト（basename・拡張子除去・小文字で照合。例`git`/`npm`）。
    /// インタプリタ/スクリプト名を入れると中身が呼ぶ全通信が通る（T-15、子孫全継承）ため、
    /// 具体的で狭い実行ファイル名のみを推奨する（D-11）。
    pub allow_apps: Vec<String>,
}

/// Tier3（`ShellTier::Tier3`）の`run_shell`実行チャネル。開いた集合（実装は`harness-sandbox`が
/// 持つ、Hyper-V VM + Incusコンテナへの生きたIPCハンドル）を`harness-core`の「重い依存ゼロ」
/// 原則を保ったまま`ToolCtx`へ運ぶためのtrait境界（`LlmProvider`/`Tool`と同じ設計原則、
/// `CLAUDE.md`「変動点を2つのtrait境界に押し込む」参照）。同期メソッドなのは、実体が
/// `harness-sandbox::vmsandboxd::VmSandboxHandle`のブロッキングWin32名前付きパイプIPC
/// （`crate::netfilterd`と同型）であるため。呼び出し元（`harness-tools::shell`）は
/// `tokio::task::spawn_blocking`越しに呼ぶ。
pub trait VmShellExecutor: Send + Sync + std::fmt::Debug {
    /// コンテナ内で`cmd`を実行し、標準出力・標準エラー・終了コードを返す。`cwd`は
    /// ワークスペースルートからの相対パスとしてコンテナ内`/workspace`配下へマッピングされる
    /// （実際のマッピングは`harness-sandbox::vmsandbox`側の責務）。
    fn exec(
        &self,
        cmd: &str,
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String>;
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
    /// 協調プロキシ設定（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。既定
    /// （`NetProxyConfig::default()`＝空allowlistの全拒否監査）はプロキシを起動する。
    pub net_proxy: NetProxyConfig,
    /// アプリ単位network制御（軸1、D-10/D-11）。既定（`NetAppPolicy::default()`＝`allow_apps`空）は
    /// 常にdeny（Tier2a子はcapability空でnetwork全遮断＝現状維持）。
    pub net_app: NetAppPolicy,
    /// `run_shell`子プロセスのclean envにあるPATHへ追記するディレクトリ一覧。設定ファイル由来の
    /// 非シークレット値だけを運び、任意env転送は行わない。
    pub run_shell_path_extra: Vec<String>,
    /// `run_shell`で起動される子が、直前の`write_file`/`edit_file`によるstaging上の変更を
    /// 読めるかどうか。既定はfalse（多くのTierは実FSだけを見る）で、Tier3+CIFSライブ共有の
    /// ようにstaging変更が子から見える経路だけ呼び出し側がtrueへ上書きする。
    pub shell_sees_staged_writes: bool,
    /// Tier3実行チャネル（`ShellTier::Tier3`選択時のみ`Some`）。`net_wfp`（`harness-cli`の
    /// `main()`ローカル変数、`ToolCtx`を経由しない設計）とは異なり、こちらは`run_shell`の
    /// 呼び出しのたびに実際に使われる（VM/コンテナへコマンドを都度送る必要があるため）ので
    /// `ToolCtx`を経由させる。`Arc`は`ToolCtx`が`Clone`である前提（既存フィールドと同様、
    /// 生ハンドルではなく共有可能な参照を運ぶ）。
    pub vm_sandbox: Option<std::sync::Arc<dyn VmShellExecutor>>,
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
            net_proxy: NetProxyConfig::default(),
            net_app: NetAppPolicy::default(),
            run_shell_path_extra: Vec::new(),
            shell_sees_staged_writes: false,
            vm_sandbox: None,
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
    /// モデルへ渡すツール仕様。既定では静的な説明・スキーマを返すが、`run_shell`のように
    /// 実行環境（Tier等）でモデルに見える意味が変わるツールはここを上書きする。
    fn spec_for_ctx(&self, ctx: &ToolCtx) -> ToolSpec {
        let _ = ctx;
        ToolSpec {
            name: self.name().to_string(),
            description: self.description().to_string(),
            input_schema: self.input_schema(),
        }
    }
    /// 実行前ゲート。具体入力（実際のコマンド行/書込先）に基づき申告する。
    fn risk(&self, input: &serde_json::Value) -> RiskClass;
    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError>;
}
