//! 宣言 → 承認照合 → 起動 → `Tool`登録 → 撤収（`plans/DESIGN-MCP.md` §3・§4）。
//!
//! ## 起動が2段に割れている（順序が本質）
//!
//! ```text
//! 1. plan()        宣言の検証と承認照合。副作用なし・プラットフォーム非依存
//! 2. prepare_all() サーバごとのAppContainerプロファイル作成 + preflight（Windows専用）
//! 3. （呼び出し側）network要求のあるサーバごとに協調プロキシを立て、proxy_addrを埋める
//! 4. （呼び出し側）WFPへ全プロファイルの出口ポリシーを適用する
//! 5. start()       実プロセス起動 + initialize/tools/list + Tool登録
//! ```
//!
//! **4と5を入れ替えてはいけない。** 先にプロセスを起こすと、WFPが効くまでの間サーバが
//! 無制限に外へ出られる窓ができる。この順序を守る責任は呼び出し側（`harness-cli`の起動
//! パイプライン）にあり、そのために2段に割ってある。
//!
//! ## 1サーバの失敗が他を巻き込まない
//!
//! 起動・ハンドシェイクの失敗は`warnings`へ積み、他のサーバは起動し続ける。MCPは「あれば使う」
//! 調査手段であって（`DESIGN-COGNITION.md` §4.2「MCPが未接続/失敗/未設定なら、ローカルファイル
//! 根拠のみで結論してよい」）、1つ落ちたからといってセッション全体を止める理由が無い。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use harness_core::{McpServerFact, Tool};

use crate::approval::McpApprovalLedger;
use crate::client::McpClient;
use crate::decl::{is_valid_mcp_tool_name, McpServerDecl};
use crate::tool::{McpTool, DEFAULT_CALL_TIMEOUT};
use crate::transport::Transport;
use crate::McpError;

/// ハンドシェイク（`initialize`+`tools/list`）を待つ既定の上限。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// [`McpRuntime::plan`]の結果。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpStartupPlan {
    /// 起動してよい宣言（承認台帳と一致したもの）。
    pub approved: Vec<McpServerDecl>,
    /// 起動しないもの（理由付き）。**黙って落とさない**——ユーザーは「MCPが動いていない」
    /// ことに気付けなければ、裏取り無しの結論をMCP裏取り済みと誤解する。
    pub skipped: Vec<SkippedServer>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SkippedServer {
    pub id: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SkipReason {
    /// 承認台帳に一致するエントリが無い（D-39）。`stale`は「同じidの承認はあるが宣言内容が
    /// 変わって失効した」ケースで、ユーザーへの説明を変えるために区別する。
    NotApproved { stale: bool },
    /// 宣言自体が不正（id・ツール名・長さ等）。
    Invalid(String),
    /// 隔離機構が無いOS（P-05、`DESIGN-MCP.md` §3.4）。
    UnsupportedPlatform,
    /// AppContainerプロファイル作成・preflightの失敗。
    IsolationUnavailable(String),
    /// 起動・ハンドシェイクの失敗。
    StartFailed(String),
}

impl SkippedServer {
    /// ユーザーへ出す1行。次に何をすればよいかまで書く。
    pub fn message(&self) -> String {
        match &self.reason {
            SkipReason::NotApproved { stale: false } => format!(
                "mcp server {:?} is declared but not approved; not starting it. Review the \
                 declaration and approve it with `harness mcp approve {}`",
                self.id, self.id
            ),
            SkipReason::NotApproved { stale: true } => format!(
                "mcp server {:?} was approved earlier, but its declaration has changed since \
                 (command/args/env/tools/network/workspace). The approval is void; re-approve \
                 with `harness mcp approve {}` after reviewing what changed",
                self.id, self.id
            ),
            SkipReason::Invalid(why) => {
                format!("mcp server {:?} has an invalid declaration: {why}", self.id)
            }
            SkipReason::UnsupportedPlatform => format!(
                "mcp server {:?} is not started on this platform: harness only isolates mcp \
                 servers with Windows AppContainer, and it refuses to run them unisolated",
                self.id
            ),
            SkipReason::IsolationUnavailable(why) => format!(
                "mcp server {:?} is not started because its sandbox could not be set up: {why}",
                self.id
            ),
            SkipReason::StartFailed(why) => {
                format!("mcp server {:?} failed to start: {why}", self.id)
            }
        }
    }
}

/// 起動準備の済んだサーバ1件。
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedServer {
    pub decl: McpServerDecl,
    /// このサーバ専用のAppContainerプロファイル名（D-38、`harness.mcp.<token>.<id>`）。
    pub profile_name: String,
    /// このサーバ専用の協調プロキシ待受アドレス。`network`要求のあるサーバだけ`Some`。
    /// WFPはこのサーバのpackage SIDに対し**このポートだけ**を許可する（§3.2）。
    pub proxy_addr: Option<SocketAddr>,
}

/// 生きているMCPサーバ1件。
pub struct McpServerSession {
    pub id: String,
    pub client: Arc<McpClient>,
    pub tools: Vec<Arc<dyn Tool>>,
    pub fact: McpServerFact,
}

/// `Transport`の作り方を差し替えるための境界。
///
/// 本番の実装は[`crate::transport_stdio`]（AppContainer子プロセス、Windows専用）だけである。
/// テストが台本トランスポートを差し込めるのはここで、**本番コードに「隔離なしトランスポート」を
/// 置かずに済ませる**ための分割線でもある。
pub trait TransportFactory: Send + Sync {
    fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError>;
}

/// 起動済みMCPサーバ群。`harness-cli`がセッションの生存期間中これを保持し、終了時に
/// [`McpRuntime::shutdown`]を呼ぶ（呼ばなくてもJob Objectがプロセスを落とすが、
/// 明示的に閉じる方が速く確実）。
#[derive(Default)]
pub struct McpRuntime {
    sessions: Vec<McpServerSession>,
    warnings: Vec<String>,
}

impl McpRuntime {
    /// 宣言を検証し、承認台帳と照合する。**副作用なし・プラットフォーム非依存**。
    pub fn plan(decls: &[McpServerDecl], ledger: &McpApprovalLedger) -> McpStartupPlan {
        let mut plan = McpStartupPlan::default();
        let mut seen: std::collections::BTreeSet<String> = Default::default();

        for decl in decls {
            if let Err(e) = decl.validate() {
                plan.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason: SkipReason::Invalid(e.to_string()),
                });
                continue;
            }
            if !seen.insert(decl.id.clone()) {
                plan.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason: SkipReason::Invalid(format!("duplicate server id {:?}", decl.id)),
                });
                continue;
            }
            if ledger.is_approved(decl) {
                plan.approved.push(decl.clone());
            } else {
                plan.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason: SkipReason::NotApproved {
                        stale: ledger.approval_for_id(&decl.id).is_some(),
                    },
                });
            }
        }
        plan
    }

    /// 準備済みサーバを実際に起動し、ツールを登録する。
    ///
    /// 1件の失敗は他を巻き込まず、[`McpRuntime::warnings`]と`skipped`へ積む。
    pub fn start(
        prepared: Vec<PreparedServer>,
        factory: &dyn TransportFactory,
        client_version: &str,
        skipped: &mut Vec<SkippedServer>,
    ) -> Self {
        let mut runtime = McpRuntime::default();
        for server in prepared {
            match Self::start_one(&server, factory, client_version) {
                Ok((session, warnings)) => {
                    runtime.warnings.extend(warnings);
                    runtime.sessions.push(session);
                }
                Err(e) => skipped.push(SkippedServer {
                    id: server.decl.id.clone(),
                    reason: SkipReason::StartFailed(e.to_string()),
                }),
            }
        }
        runtime
    }

    fn start_one(
        server: &PreparedServer,
        factory: &dyn TransportFactory,
        client_version: &str,
    ) -> Result<(McpServerSession, Vec<String>), McpError> {
        let transport = factory.create(server)?;
        let client = Arc::new(McpClient::new(server.decl.id.clone(), transport));
        let defs = client.handshake(client_version, DEFAULT_HANDSHAKE_TIMEOUT)?;

        let mut warnings = Vec::new();
        let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
        let mut tool_names = Vec::new();
        for def in defs {
            // サーバは未信頼（§2）。申告された名前も入力として検証してから使う。
            if !is_valid_mcp_tool_name(&def.name) {
                warnings.push(format!(
                    "mcp server {:?} advertised a tool with an unusable name {:?}; skipping it",
                    server.decl.id, def.name
                ));
                continue;
            }
            if let Err(e) = server.decl.check_namespaced_len(&def.name) {
                warnings.push(format!("mcp server {:?}: {e}; skipping that tool", server.decl.id));
                continue;
            }
            let risk = server.decl.risk_for_tool(&def.name);
            let tool = McpTool::new(
                &server.decl.id,
                &def.name,
                def.description.as_deref(),
                def.input_schema.as_ref(),
                risk,
                client.clone(),
            )
            .with_call_timeout(DEFAULT_CALL_TIMEOUT);
            tool_names.push(tool.name().to_string());
            tools.push(Arc::new(tool));
        }

        let fact = McpServerFact {
            id: server.decl.id.clone(),
            allow_domains: server.decl.network.allow_domains.clone(),
            workspace_access: workspace_access_label(server.decl.workspace).to_string(),
            tool_names: tool_names.clone(),
        };

        Ok((
            McpServerSession {
                id: server.decl.id.clone(),
                client,
                tools,
                fact,
            },
            warnings,
        ))
    }

    /// 登録すべき`Tool`一式（`harness-cli`が`ToolRegistry::register`へ渡す）。
    pub fn tools(&self) -> Vec<Arc<dyn Tool>> {
        self.sessions
            .iter()
            .flat_map(|s| s.tools.iter().cloned())
            .collect()
    }

    /// システムプロンプトへ載せる事実（`harness-core::EnvironmentFacts`）。
    pub fn facts(&self) -> Vec<McpServerFact> {
        self.sessions.iter().map(|s| s.fact.clone()).collect()
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn server_ids(&self) -> Vec<String> {
        self.sessions.iter().map(|s| s.id.clone()).collect()
    }

    /// 全サーバを落とす。冪等。
    pub fn shutdown(&mut self) {
        for session in &self.sessions {
            session.client.shutdown();
        }
        self.sessions.clear();
    }
}

impl Drop for McpRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn workspace_access_label(access: crate::decl::McpWorkspaceAccess) -> &'static str {
    match access {
        crate::decl::McpWorkspaceAccess::None => "none",
        crate::decl::McpWorkspaceAccess::Read => "read",
        crate::decl::McpWorkspaceAccess::ReadWrite => "read-write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::ApprovalStore;
    use crate::client::test_support::ScriptedTransport;
    use crate::decl::{McpNetworkDecl, McpTransportKind, McpWorkspaceAccess};
    use harness_core::RiskClass;
    use std::sync::Mutex;

    fn decl(id: &str) -> McpServerDecl {
        McpServerDecl {
            id: id.to_string(),
            transport: McpTransportKind::Stdio,
            command: "node.exe".to_string(),
            args: vec!["server.js".to_string()],
            env: Default::default(),
            tools: [("search".to_string(), RiskClass::ReadOnly)]
                .into_iter()
                .collect(),
            network: McpNetworkDecl::default(),
            workspace: McpWorkspaceAccess::None,
        }
    }

    fn store() -> (tempfile::TempDir, ApprovalStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ApprovalStore::at_path(dir.path().join("ledger.json"));
        (dir, store)
    }

    /// spawnが呼ばれた回数を数えるファクトリ。「起動しない」を「起動して失敗した」と
    /// 取り違えないために、**呼ばれた回数そのもの**を観測する。
    struct SpyFactory {
        calls: Arc<Mutex<Vec<String>>>,
        script: Vec<String>,
    }

    impl TransportFactory for SpyFactory {
        fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
            self.calls.lock().unwrap().push(prepared.decl.id.clone());
            Ok(Box::new(ScriptedTransport::new(self.script.clone())))
        }
    }

    fn handshake_script(tools_json: &str) -> Vec<String> {
        vec![
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#.to_string(),
            format!(r#"{{"jsonrpc":"2.0","id":2,"result":{{"tools":{tools_json}}}}}"#),
        ]
    }

    fn prepared(decl: McpServerDecl) -> PreparedServer {
        PreparedServer {
            profile_name: format!("harness.mcp.test.{}", decl.id),
            decl,
            proxy_addr: None,
        }
    }

    #[test]
    fn an_approved_declaration_is_planned_for_startup() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load());
        assert_eq!(plan.approved, vec![d]);
        assert!(plan.skipped.is_empty());
    }

    /// **完了条件**: 未承認の宣言ではサーバプロセスを起動しない（D-39）。
    /// 「起動して失敗した」ではなく「一度も起動しなかった」ことを確認する。
    #[test]
    fn an_unapproved_declaration_never_reaches_the_transport_factory() {
        let (_dir, store) = store();
        let plan = McpRuntime::plan(&[decl("docs")], &store.load());
        assert!(plan.approved.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(
            plan.skipped[0].reason,
            SkipReason::NotApproved { stale: false }
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let factory = SpyFactory {
            calls: calls.clone(),
            script: handshake_script("[]"),
        };
        let mut skipped = plan.skipped.clone();
        let prepared_list: Vec<PreparedServer> =
            plan.approved.into_iter().map(prepared).collect();
        let runtime = McpRuntime::start(prepared_list, &factory, "0.1.0", &mut skipped);

        assert!(
            calls.lock().unwrap().is_empty(),
            "the transport factory must never be invoked for an unapproved declaration"
        );
        assert!(runtime.is_empty());
    }

    /// 承認後に宣言が変わった場合は、ユーザーへの説明が変わる（stale）。
    #[test]
    fn a_changed_declaration_is_reported_as_a_void_approval() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);

        let mut changed = d.clone();
        changed.args = vec!["evil.js".to_string()];
        let plan = McpRuntime::plan(&[changed], &store.load());

        assert!(plan.approved.is_empty());
        assert_eq!(
            plan.skipped[0].reason,
            SkipReason::NotApproved { stale: true }
        );
        assert!(plan.skipped[0].message().contains("has changed since"));
    }

    #[test]
    fn an_invalid_declaration_is_skipped_with_a_reason() {
        let (_dir, store) = store();
        let mut bad = decl("docs");
        bad.id = "Bad Id".to_string();
        let plan = McpRuntime::plan(&[bad], &store.load());
        assert!(matches!(plan.skipped[0].reason, SkipReason::Invalid(_)));
    }

    #[test]
    fn duplicate_ids_do_not_both_start() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let plan = McpRuntime::plan(&[d.clone(), d], &store.load());
        assert_eq!(plan.approved.len(), 1);
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn starting_an_approved_server_registers_its_tools_under_the_namespace() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let factory = SpyFactory {
            calls: Arc::new(Mutex::new(Vec::new())),
            script: handshake_script(
                r#"[{"name":"search","description":"d","inputSchema":{"type":"object"}}]"#,
            ),
        };
        let mut skipped = Vec::new();
        let runtime = McpRuntime::start(vec![prepared(d)], &factory, "0.1.0", &mut skipped);

        let tools = runtime.tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name(), "mcp__docs__search");
        assert_eq!(tools[0].risk(&serde_json::json!({})), RiskClass::ReadOnly);
        assert!(skipped.is_empty());
    }

    /// **完了条件**: 無宣言のツールは非read扱いになり、パーミッションゲートを必ず通る（D-40）。
    #[test]
    fn a_tool_without_a_declared_risk_class_is_registered_as_non_read() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let factory = SpyFactory {
            calls: Arc::new(Mutex::new(Vec::new())),
            script: handshake_script(
                r#"[{"name":"create_issue","annotations":{"readOnlyHint":true}}]"#,
            ),
        };
        let mut skipped = Vec::new();
        let runtime = McpRuntime::start(vec![prepared(d)], &factory, "0.1.0", &mut skipped);

        let tools = runtime.tools();
        assert_eq!(tools[0].name(), "mcp__docs__create_issue");
        assert_eq!(
            tools[0].risk(&serde_json::json!({})),
            RiskClass::Network,
            "an undeclared tool must not become read-only just because the server says so"
        );
    }

    /// サーバが不正な名前のツールを申告しても、そのツールだけを落として他は使える。
    #[test]
    fn a_tool_with_an_unusable_name_is_dropped_with_a_warning() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let factory = SpyFactory {
            calls: Arc::new(Mutex::new(Vec::new())),
            script: handshake_script(r#"[{"name":"bad name"},{"name":"search"}]"#),
        };
        let mut skipped = Vec::new();
        let runtime = McpRuntime::start(vec![prepared(d)], &factory, "0.1.0", &mut skipped);

        assert_eq!(runtime.tools().len(), 1);
        assert_eq!(runtime.tools()[0].name(), "mcp__docs__search");
        assert_eq!(runtime.warnings().len(), 1);
    }

    /// 1サーバの起動失敗が他を巻き込まない。
    #[test]
    fn one_server_failing_to_start_does_not_stop_the_others() {
        struct HalfBrokenFactory;
        impl TransportFactory for HalfBrokenFactory {
            fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
                if prepared.decl.id == "broken" {
                    return Err(McpError::Spawn {
                        id: "broken".to_string(),
                        reason: "exe not found".to_string(),
                    });
                }
                Ok(Box::new(ScriptedTransport::new(handshake_script(
                    r#"[{"name":"search"}]"#,
                ))))
            }
        }

        let mut skipped = Vec::new();
        let runtime = McpRuntime::start(
            vec![prepared(decl("broken")), prepared(decl("docs"))],
            &HalfBrokenFactory,
            "0.1.0",
            &mut skipped,
        );

        assert_eq!(runtime.server_ids(), vec!["docs".to_string()]);
        assert_eq!(skipped.len(), 1);
        assert!(matches!(skipped[0].reason, SkipReason::StartFailed(_)));
    }

    #[test]
    fn facts_describe_what_each_server_is_allowed_to_reach() {
        let (_dir, store) = store();
        let mut d = decl("docs");
        d.network.allow_domains = vec!["docs.example.com".to_string()];
        d.workspace = McpWorkspaceAccess::Read;
        store.approve(&d);

        let factory = SpyFactory {
            calls: Arc::new(Mutex::new(Vec::new())),
            script: handshake_script(r#"[{"name":"search"}]"#),
        };
        let mut skipped = Vec::new();
        let runtime = McpRuntime::start(vec![prepared(d)], &factory, "0.1.0", &mut skipped);

        let facts = runtime.facts();
        assert_eq!(facts[0].id, "docs");
        assert_eq!(facts[0].allow_domains, vec!["docs.example.com".to_string()]);
        assert_eq!(facts[0].workspace_access, "read");
        assert_eq!(facts[0].tool_names, vec!["mcp__docs__search".to_string()]);
    }

    #[test]
    fn shutdown_is_idempotent() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let factory = SpyFactory {
            calls: Arc::new(Mutex::new(Vec::new())),
            script: handshake_script(r#"[{"name":"search"}]"#),
        };
        let mut skipped = Vec::new();
        let mut runtime = McpRuntime::start(vec![prepared(d)], &factory, "0.1.0", &mut skipped);
        runtime.shutdown();
        runtime.shutdown();
        assert!(runtime.is_empty());
    }
}
