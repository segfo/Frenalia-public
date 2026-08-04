//! harness-mcp: MCPクライアント本体（M15.5）。設計正本は`plans/DESIGN-MCP.md`（D-38〜D-41）。
//!
//! MCPサーバは**harnessが起動する第三者のプロセス**であり、他のどのツールとも性質が違う。
//! 組み込みツールはharness自身のコードで、`run_shell`の子はサンドボックスの中にいる。MCPサーバは
//! そのどちらでもない。したがってこのクレートが持つのは次の3つである。
//!
//! | モジュール | 担当 | `DESIGN-MCP.md` |
//! |---|---|---|
//! | [`decl`] | 宣言の型・検証・承認ハッシュ | §4 |
//! | [`approval`] | 承認台帳（ワークスペース外） | §4.2、D-39 |
//! | [`protocol`] | JSON-RPC 2.0 と MCP メソッドのワイヤ形式 | §6 |
//! | [`transport`] | 通信路の抽象（stdioのみ実装） | §6.1、D-41 |
//! | [`client`] | 1サーバ＝1セッションの往復 | §3.3 |
//! | [`tool`] | `Tool` traitへの写像・`RiskClass` | §5、D-40 |
//! | [`runtime`] | 宣言→承認照合→起動→登録→撤収 | §3・§4 |
//! | `sandbox`（windows） | サーバごとのAppContainerプロファイル | §3、D-38 |
//!
//! ## 起動が2段に割れている理由
//!
//! [`runtime::McpRuntime`]は「プロファイルとプロキシポートを確定させる」段（`prepare`）と
//! 「実際にプロセスを起こす」段（`launch`）に分かれている。**その間にWFPの出口強制を適用する**
//! ためで、1段にまとめるとサーバが出口強制の効いていない窓で動く瞬間ができる。呼び出し側
//! （`harness-cli`の起動パイプライン）はこの順序を守る責任を負う。
//!
//! ## Windows以外
//!
//! 隔離機構（AppContainer）が無い環境ではMCPサーバを**起動しない**（P-05: 能力が無いときは
//! 降格ではなく拒否へ倒す、`DESIGN-MCP.md` §3.4）。`runtime`はそのOSでは常に「起動対象なし＋
//! 理由」を返す。

pub mod approval;
pub mod client;
pub mod decl;
pub mod protocol;
pub mod runtime;
pub mod tool;
pub mod transport;

#[cfg(windows)]
pub mod sandbox;

#[cfg(windows)]
pub mod transport_stdio;

#[cfg(windows)]
pub use transport_stdio::AppContainerTransportFactory;

pub use approval::{ApprovalStore, McpApproval, McpApprovalLedger};
pub use decl::{
    namespaced_tool_name, parse_mcp_settings, McpNetworkDecl, McpServerDecl, McpSettings,
    McpTransportKind, McpWorkspaceAccess,
};
pub use harness_core::McpServerFact;
pub use runtime::{McpRuntime, McpStartupPlan, PreparedServer, SkipReason, SkippedServer};
pub use tool::McpTool;

/// このクレートが返すエラー。
#[derive(Debug, Clone, thiserror::Error)]
pub enum McpError {
    #[error("invalid mcp server declaration: {0}")]
    Decl(#[from] decl::DeclError),
    #[error("failed to start mcp server {id}: {reason}")]
    Spawn { id: String, reason: String },
    #[error("mcp transport i/o failed: {0}")]
    Io(String),
    #[error("timed out waiting for the mcp server: {0}")]
    Timeout(String),
    #[error("mcp protocol violation: {0}")]
    Protocol(String),
    #[error("mcp server returned an error (code {code}): {message}")]
    Server { code: i64, message: String },
    #[error("unsupported by this harness build: {0}")]
    Unsupported(String),
    #[error("the mcp session is closed")]
    Closed,
}
