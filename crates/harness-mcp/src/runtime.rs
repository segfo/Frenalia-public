//! 宣言 → 承認照合 → 起動 → `Tool`登録 → 撤収（`plans/DESIGN-MCP.md` §3・§4）。
//!
//! ## 起動が2段に割れている（順序が本質）
//!
//! ```text
//! 1. plan()        宣言の検証・セッションゲート（D-49）・承認照合。副作用なし・OS非依存
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
//! **2〜4はstdio専用である**（M15.6、D-50）。Streamable HTTPにはAppContainerプロファイルも
//! 専用プロキシもWFPフィルタも存在しない——喋るのはharness本体である。代わりに1で
//! [`McpGates`]の3段ゲートを通り、[`McpRuntime::prepare_http`]が検証済みの`Endpoint`を
//! 持つ[`PreparedServer`]を作る。統制は接続前に完結している。
//!
//! ## 1サーバの失敗が他を巻き込まない
//!
//! 起動・ハンドシェイクの失敗は`warnings`へ積み、他のサーバは起動し続ける。MCPは「あれば使う」
//! 調査手段であって（`DESIGN-COGNITION.md` §4.2「MCPが未接続/失敗/未設定なら、ローカルファイル
//! 根拠のみで結論してよい」）、1つ落ちたからといってセッション全体を止める理由が無い。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use harness_core::{McpServerFact, Tool};

use crate::approval::McpApprovalLedger;
use crate::client::McpClient;
use crate::decl::{is_valid_mcp_tool_name, McpServerDecl, McpTransportKind};
use crate::http_wire::{validate_endpoint, CertPin, Endpoint, EndpointGates, HttpWireError};
use crate::tool::{McpTool, DEFAULT_CALL_TIMEOUT};
use crate::transport::Transport;
use crate::McpError;

/// ハンドシェイク（`initialize`+`tools/list`）を待つ既定の上限。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// セッション側のゲート（`plans/DESIGN-MCP.md` §6.2、D-49）。
///
/// **ここに入る値はユーザ層設定かCLIからしか来ない。** プロジェクト層
/// （`<root>/.harness/settings.json`）に書かれた分は`harness_config::clamp_project_mcp_http_gates`
/// がマージの過程で剥がしている。宣言（`mcp.servers[]`）はリポジトリ同梱でよいが、
/// その宣言を**起動してよいと決める側**は同じ場所から動かせない、というのがD-49の要点。
#[derive(Debug, Clone, Default)]
pub struct McpGates {
    /// `mcp.allow_streamable_http` または `--allow-mcp-http`。既定は無効（D-41）。
    pub streamable_http_enabled: bool,
    /// 宛先allowlist・平文の可否。既定は「何も許さない」。
    pub http_endpoints: EndpointGates,
    /// 私有CAのPEMバンドル（`mcp.http_ca_bundle`）。
    pub http_ca_bundle: Option<PathBuf>,
}

/// [`McpRuntime::plan`]の結果。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpStartupPlan {
    /// 起動してよい宣言（承認台帳と一致したもの）。
    pub approved: Vec<McpServerDecl>,
    /// 起動しないもの（理由付き）。**黙って落とさない**——ユーザーは「MCPが動いていない」
    /// ことに気付けなければ、裏取り無しの結論をMCP裏取り済みと誤解する。
    pub skipped: Vec<SkippedServer>,
    /// **harnessが宣言に欄を増やしたせいで承認が無効になった**サーバのid
    /// （[`crate::decl::DECL_FORMAT_VERSION`]）。
    ///
    /// これらは[`Self::skipped`]にも「未承認」として載る。**こちらは断り文ではなく、
    /// 起動時に1回だけ出す理由の材料**である——サーバごとに理由を繰り返すと、
    /// 本人が宣言を書き換えた場合との区別が付かない文言を人数分並べることになる。
    pub voided_by_format_upgrade: Vec<String>,
}

impl McpStartupPlan {
    /// **宣言の欄が増えたことによる失効を、1回だけ説明する行**（`None`なら起きていない）。
    ///
    /// サーバごとの断り文（[`SkippedServer::message`]）は「宣言はあるが未承認」のままにし、
    /// 理由はここでまとめて言う。**「あなたが宣言を書き換えた」とは書かない**——書き換えたか
    /// どうかを区別する材料を持っていないからで、代わりに
    /// **「承認の前に宣言の全文が出るので、それを見て判断してほしい」**へ寄せる。
    pub fn format_upgrade_notice(&self) -> Option<String> {
        if self.voided_by_format_upgrade.is_empty() {
            return None;
        }
        Some(format!(
            "harness added a new mcp declaration field ({:?}), so every approval recorded before \
             this version of harness no longer matches. {} declared server(s) need re-approval: \
             {}. The full declaration is shown before you approve it -- review it and run \
             `harness mcp approve <id>`",
            crate::decl::DECL_FORMAT_VERSION_ADDED_FIELD,
            self.voided_by_format_upgrade.len(),
            self.voided_by_format_upgrade.join(", ")
        ))
    }
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
    /// 隔離機構が無いOS（P-05、`DESIGN-MCP.md` §3.4）。**stdioにだけ適用する**——
    /// HTTPには隔離すべき子プロセスが無い（D-50）。
    UnsupportedPlatform,
    /// AppContainerプロファイル作成・preflightの失敗。
    IsolationUnavailable(String),
    /// 起動・ハンドシェイクの失敗。
    StartFailed(String),
    /// Streamable HTTPが有効化されていない（D-41/D-49）。既定はこれ。
    StreamableHttpNotEnabled,
    /// 宛先がゲートを通らない（allowlist非該当・平文・IPリテラル等）。
    HttpEndpointRejected(HttpWireError),
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
                 (transport/command/args/env/url/headers/tools/network/workspace). The approval \
                 is void; re-approve with `harness mcp approve {}` after reviewing what changed",
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
            SkipReason::StreamableHttpNotEnabled => format!(
                "mcp server {:?} uses the streamable_http transport, which is off by default. \
                 harness itself makes that connection, so it is NOT covered by the AppContainer \
                 sandbox, the WFP egress filters or the cooperative proxy. Turn it on with \
                 \"mcp\": {{ \"allow_streamable_http\": true }} in your *user* settings.json (a \
                 project's .harness/settings.json cannot turn it on), or pass --allow-mcp-http \
                 for a single run",
                self.id
            ),
            SkipReason::HttpEndpointRejected(why) => format!(
                "mcp server {:?} is not started because harness will not connect to its endpoint: \
                 {why}",
                self.id
            ),
        }
    }
}

/// 起動準備の済んだサーバ1件。
#[derive(Debug, Clone, PartialEq)]
pub struct PreparedServer {
    pub decl: McpServerDecl,
    pub isolation: PreparedIsolation,
}

/// このサーバをどこへ閉じ込めたか。
///
/// **enumにしてあるのは、HTTPに意味の無いプロファイル名を空文字で持たせないため**である。
/// 「隔離されていない」という事実を型で見えるようにしておかないと、`profile_name`を使う
/// 側が黙って空文字を受け取り、隔離があるつもりのコードが書ける。
#[derive(Debug, Clone, PartialEq)]
pub enum PreparedIsolation {
    /// stdio（D-38）。サーバごとの専用AppContainerプロファイルの中で動く。
    AppContainer {
        /// `harness.mcp.<token>.<id>`。
        profile_name: String,
        /// このサーバ専用の協調プロキシ待受アドレス。`network`要求のあるサーバだけ`Some`。
        /// WFPはこのサーバのpackage SIDに対し**このポートだけ**を許可する（§3.2）。
        proxy_addr: Option<SocketAddr>,
    },
    /// Streamable HTTP（§6.2、D-50）。harness本体が喋るので隔離の実体が無い。
    /// 統制はD-49の3段ゲートと承認台帳（D-39）が持ち、それは接続前に済んでいる。
    Direct {
        /// [`validate_endpoint`]を通ったものだけがここに入る。
        endpoint: Endpoint,
        ca_bundle: Option<PathBuf>,
        /// 宣言の`tls_pin`（D-52）。`Some`ならCA連鎖と名前の検証はこれに置き換わる。
        tls_pin: Option<CertPin>,
    },
}

impl PreparedServer {
    /// 専用の協調プロキシが立った後に、その待受アドレスを埋める（起動順序3、§3.2）。
    ///
    /// HTTPサーバに対しては何もしない——AppContainerの外なので、プロキシを指しても
    /// 強制するWFPフィルタが無く、「絞ったつもり」を作るだけになる。
    pub fn set_proxy_addr(&mut self, addr: SocketAddr) {
        if let PreparedIsolation::AppContainer { proxy_addr, .. } = &mut self.isolation {
            *proxy_addr = Some(addr);
        }
    }
}

impl PreparedIsolation {
    /// AppContainerプロファイル名（HTTPなら`None`）。
    pub fn profile_name(&self) -> Option<&str> {
        match self {
            PreparedIsolation::AppContainer { profile_name, .. } => Some(profile_name),
            PreparedIsolation::Direct { .. } => None,
        }
    }

    /// 専用プロキシのアドレス（HTTP、およびnetwork要求の無いstdioなら`None`）。
    pub fn proxy_addr(&self) -> Option<SocketAddr> {
        match self {
            PreparedIsolation::AppContainer { proxy_addr, .. } => *proxy_addr,
            PreparedIsolation::Direct { .. } => None,
        }
    }

    /// WFPの出口強制が無効なセッションで、このサーバを落とす必要があるか。
    ///
    /// - `AppContainer`＋専用プロキシ → **落とす**。`internetClient` capabilityを持つのに
    ///   宛先が強制されない状態になる（`run_shell`側の`should_grant_tier2a_network_capability`
    ///   と同じfail-closed）
    /// - `AppContainer`＋プロキシ無し → capabilityが空でソケットを作れないので残す
    /// - `Direct` → WFPは元から関係しない（harness本体の通信）ので残す
    pub fn needs_wfp_egress_enforcement(&self) -> bool {
        matches!(
            self,
            PreparedIsolation::AppContainer {
                proxy_addr: Some(_),
                ..
            }
        )
    }
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
    /// 宣言を検証し、セッション側のゲート（D-49）と承認台帳（D-39）を照合する。
    /// **副作用なし・プラットフォーム非依存**で、ここで落ちたサーバは
    /// プロセスもTCP接続もTLSハンドシェイクも一度も起こさない。
    ///
    /// **ゲートを承認より先に見る。** 「承認したのに起動しない」より
    /// 「そもそもこの経路が閉じている」の方が、ユーザーが次に取るべき行動に直結する。
    pub fn plan(
        decls: &[McpServerDecl],
        ledger: &McpApprovalLedger,
        gates: &McpGates,
    ) -> McpStartupPlan {
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
            if let Some(reason) = transport_gate(decl, gates) {
                plan.skipped.push(SkippedServer {
                    id: decl.id.clone(),
                    reason,
                });
                continue;
            }
            if ledger.is_approved(decl) {
                plan.approved.push(decl.clone());
            } else {
                // 版が古い承認は`approval_for_id`が返さないので、`stale`は立たない
                // ——断り文は「宣言はあるが未承認」になる。理由は起動時に1行だけ出す。
                if ledger.is_voided_by_format_upgrade(&decl.id) {
                    plan.voided_by_format_upgrade.push(decl.id.clone());
                }
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

    /// Streamable HTTP宣言の`PreparedServer`を作る（D-50: 隔離Tierに依存しない）。
    ///
    /// stdio側の`prepare`（`crate::sandbox`、Windows専用）に対応するもので、こちらは
    /// AppContainerプロファイルもpreflightも要らない代わりに、**接続先ゲートをもう一度通す**。
    /// [`plan`](Self::plan)が既に通しているが、[`Endpoint`]を作れるのがその関数だけなので、
    /// 「ゲートを通っていないURLでは`PreparedServer`を作れない」構造になる。
    pub fn prepare_http(
        decl: &McpServerDecl,
        gates: &McpGates,
    ) -> Result<PreparedServer, SkipReason> {
        let endpoint = validate_endpoint(&decl.url, &gates.http_endpoints)
            .map_err(SkipReason::HttpEndpointRejected)?;
        // 形式は`decl.validate()`が既に通しているが、ここでも読めなければ起動しない
        // （読めないピンを黙って「ピン無し＝通常検証」へ落とさない。D-52はfail-closed）。
        let tls_pin = match &decl.tls_pin {
            Some(raw) => Some(
                crate::http_wire::parse_cert_pin(raw)
                    .map_err(|e| SkipReason::Invalid(format!("unusable \"tls_pin\": {e}")))?,
            ),
            None => None,
        };
        Ok(PreparedServer {
            decl: decl.clone(),
            isolation: PreparedIsolation::Direct {
                endpoint,
                ca_bundle: gates.http_ca_bundle.clone(),
                tls_pin,
            },
        })
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
                warnings.push(format!(
                    "mcp server {:?}: {e}; skipping that tool",
                    server.decl.id
                ));
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
            transport: server.decl.transport.label().to_string(),
            // HTTPは`allow_domains`が空なので、これが無いとシステムプロンプトが
            // 「外向き通信は不可」と嘘を描く（`harness_core::prompt::render_mcp_servers`）。
            endpoint: match &server.isolation {
                PreparedIsolation::AppContainer { .. } => None,
                PreparedIsolation::Direct { endpoint, .. } => Some(endpoint.display().to_string()),
            },
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

/// トランスポート別のセッションゲート（D-49）。通れば`None`。
fn transport_gate(decl: &McpServerDecl, gates: &McpGates) -> Option<SkipReason> {
    match decl.transport {
        // stdioにセッションゲートは無い（隔離そのものが統制なので、Tier判定は呼び出し側）。
        McpTransportKind::Stdio => None,
        McpTransportKind::StreamableHttp => {
            if !gates.streamable_http_enabled {
                return Some(SkipReason::StreamableHttpNotEnabled);
            }
            validate_endpoint(&decl.url, &gates.http_endpoints)
                .err()
                .map(SkipReason::HttpEndpointRejected)
        }
    }
}

/// 本番のトランスポートをトランスポート種別で振り分ける（`harness-cli`が使う唯一の実装）。
///
/// 差し替え境界としての[`TransportFactory`]はそのまま残す——テストが台本トランスポートを
/// 差し込めるのはここで、本番コードに「隔離なしのstdio」を置かずに済ませるための分割線
/// でもある（`plans/DESIGN-MCP.md` §3.4）。
#[derive(Default)]
pub struct DefaultTransportFactory {
    #[cfg(windows)]
    spawn_daemon: Option<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
}

impl DefaultTransportFactory {
    #[cfg(windows)]
    pub fn with_spawn_daemon(
        spawn_daemon: harness_sandbox::tier2a::spawnd::SharedSpawnDaemon,
    ) -> Self {
        Self {
            spawn_daemon: Some(spawn_daemon),
        }
    }
}

impl TransportFactory for DefaultTransportFactory {
    fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
        match prepared.decl.transport {
            McpTransportKind::Stdio => {
                #[cfg(windows)]
                {
                    let Some(daemon) = self.spawn_daemon.as_ref() else {
                        return Err(McpError::Spawn {
                            id: prepared.decl.id.clone(),
                            reason: "MCP stdio has no Spawn Daemon connection (internal error)"
                                .to_string(),
                        });
                    };
                    crate::transport_stdio::AppContainerTransportFactory::with_spawn_daemon(
                        daemon.clone(),
                    )
                    .create(prepared)
                }
                #[cfg(not(windows))]
                {
                    Err(McpError::Unsupported(format!(
                        "mcp server {:?} uses the stdio transport, which harness only isolates \
                         with Windows AppContainer",
                        prepared.decl.id
                    )))
                }
            }
            McpTransportKind::StreamableHttp => {
                crate::transport_http::HttpTransportFactory.create(prepared)
            }
        }
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
    use crate::decl::{McpNetworkDecl, McpProcessAccess, McpTransportKind, McpWorkspaceAccess};
    use harness_core::RiskClass;
    use std::sync::Mutex;

    fn decl(id: &str) -> McpServerDecl {
        McpServerDecl {
            id: id.to_string(),
            transport: McpTransportKind::Stdio,
            command: "node.exe".to_string(),
            args: vec!["server.js".to_string()],
            env: Default::default(),
            url: String::new(),
            headers: Default::default(),
            tls_pin: None,
            tools: [("search".to_string(), RiskClass::ReadOnly)]
                .into_iter()
                .collect(),
            network: McpNetworkDecl::default(),
            workspace: McpWorkspaceAccess::None,
            process: McpProcessAccess::Deny,
        }
    }

    fn http_decl(id: &str, url: &str) -> McpServerDecl {
        McpServerDecl {
            transport: McpTransportKind::StreamableHttp,
            command: String::new(),
            args: Vec::new(),
            url: url.to_string(),
            ..decl(id)
        }
    }

    /// stdioには効かないゲート（stdioの統制は隔離そのもの）。HTTPは既定で全部閉じている。
    fn no_gates() -> McpGates {
        McpGates::default()
    }

    fn http_gates(domains: &[&str], plaintext: bool) -> McpGates {
        let list: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        McpGates {
            streamable_http_enabled: true,
            http_endpoints: EndpointGates {
                allow_domains: harness_core::DomainPolicy::new(list.clone()),
                // `plaintext = true`は「許可した全ドメインを平文でも」＝各ドメインを
                // `--mcp-http-allow http://<host>`で書いた構成と同じ。
                plaintext_domains: harness_core::DomainPolicy::new(if plaintext {
                    list
                } else {
                    Vec::new()
                }),
            },
            http_ca_bundle: None,
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
            isolation: PreparedIsolation::AppContainer {
                profile_name: format!("harness.mcp.test.{}", decl.id),
                proxy_addr: None,
            },
            decl,
        }
    }

    #[test]
    fn an_approved_declaration_is_planned_for_startup() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &no_gates());
        assert_eq!(plan.approved, vec![d]);
        assert!(plan.skipped.is_empty());
    }

    /// **完了条件**: 未承認の宣言ではサーバプロセスを起動しない（D-39）。
    /// 「起動して失敗した」ではなく「一度も起動しなかった」ことを確認する。
    #[test]
    fn an_unapproved_declaration_never_reaches_the_transport_factory() {
        let (_dir, store) = store();
        let plan = McpRuntime::plan(&[decl("docs")], &store.load(), &no_gates());
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
        let prepared_list: Vec<PreparedServer> = plan.approved.into_iter().map(prepared).collect();
        let runtime = McpRuntime::start(prepared_list, &factory, "0.1.0", &mut skipped);

        assert!(
            calls.lock().unwrap().is_empty(),
            "the transport factory must never be invoked for an unapproved declaration"
        );
        assert!(runtime.is_empty());
    }

    /// 承認済みの宣言が、ゲートを通らない理由で落ちたときも**1回も起動しない**ことを、
    /// 同じ観測の仕方（ファクトリの呼び出し回数）で確かめる。
    fn assert_never_reaches_the_factory(decl: McpServerDecl, gates: &McpGates) -> SkipReason {
        let (_dir, store) = store();
        store.approve(&decl);
        let plan = McpRuntime::plan(std::slice::from_ref(&decl), &store.load(), gates);
        assert!(
            plan.approved.is_empty(),
            "the gate must reject this before approval is even consulted"
        );
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let factory = SpyFactory {
            calls: calls.clone(),
            script: handshake_script("[]"),
        };
        let mut skipped = plan.skipped.clone();
        let prepared_list: Vec<PreparedServer> = plan.approved.into_iter().map(prepared).collect();
        let runtime = McpRuntime::start(prepared_list, &factory, "0.1.0", &mut skipped);

        assert!(
            calls.lock().unwrap().is_empty(),
            "no connection may be attempted for a server that failed the gate"
        );
        assert!(runtime.is_empty());
        plan.skipped[0].reason.clone()
    }

    /// **完了条件: 既定で無効**（D-41）。承認済みでも、オプトインが無ければ接続を一度も試みない。
    #[test]
    fn streamable_http_is_off_by_default_and_never_reaches_the_transport_factory() {
        let reason = assert_never_reaches_the_factory(
            http_decl("corp", "https://mcp.corp.example/mcp"),
            &McpGates::default(),
        );
        assert_eq!(reason, SkipReason::StreamableHttpNotEnabled);

        let message = SkippedServer {
            id: "corp".to_string(),
            reason,
        }
        .message();
        // 「どこで有効化すればよいか」まで書く（プロジェクト設定では無理だという点も）。
        assert!(message.contains("--allow-mcp-http"), "{message}");
        assert!(message.contains("user* settings.json"), "{message}");
    }

    /// D-49: 有効化しても、宛先allowlistに載っていなければ接続しない（closed-by-default）。
    #[test]
    fn an_enabled_transport_still_refuses_a_host_outside_the_allowlist() {
        let reason = assert_never_reaches_the_factory(
            http_decl("corp", "https://mcp.corp.example/mcp"),
            &http_gates(&["other.example"], false),
        );
        assert!(
            matches!(
                reason,
                SkipReason::HttpEndpointRejected(HttpWireError::HostNotAllowlisted { .. })
            ),
            "{reason:?}"
        );
    }

    /// D-49: 平文httpはallowlistに載っていても、CLIフラグ無しでは接続しない。
    #[test]
    fn plaintext_http_to_a_remote_host_needs_the_cli_flag() {
        let reason = assert_never_reaches_the_factory(
            http_decl("corp", "http://mcp.corp.example/mcp"),
            &http_gates(&["mcp.corp.example"], false),
        );
        assert!(
            matches!(
                reason,
                SkipReason::HttpEndpointRejected(HttpWireError::PlaintextNotAllowed)
            ),
            "{reason:?}"
        );
    }

    /// 3段すべてを通した宣言は起動対象になり、`Direct`（隔離の実体なし）として準備される。
    #[test]
    fn a_fully_gated_and_approved_http_declaration_is_prepared_without_isolation() {
        let (_dir, store) = store();
        let d = http_decl("corp", "https://mcp.corp.example/mcp");
        store.approve(&d);
        let gates = http_gates(&["mcp.corp.example"], false);

        let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &gates);
        assert_eq!(plan.approved, vec![d.clone()]);
        assert!(plan.skipped.is_empty());

        let prepared = McpRuntime::prepare_http(&d, &gates).unwrap();
        assert_eq!(prepared.isolation.profile_name(), None);
        assert_eq!(prepared.isolation.proxy_addr(), None);
        assert!(
            !prepared.isolation.needs_wfp_egress_enforcement(),
            "WFP has nothing to do with a connection harness itself makes"
        );
    }

    /// loopbackはallowlistにも平文ゲートにも掛からない（ローカル開発用サーバ）。
    #[test]
    fn a_loopback_http_server_starts_with_the_opt_in_alone() {
        let (_dir, store) = store();
        let d = http_decl("local", "http://127.0.0.1:3000/mcp");
        store.approve(&d);
        let gates = McpGates {
            streamable_http_enabled: true,
            ..McpGates::default()
        };
        let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &gates);
        assert_eq!(plan.approved, vec![d], "{:?}", plan.skipped);
    }

    /// **stdioのゲートは変わっていない**（HTTPのオプトインはstdioに影響しない）。
    #[test]
    fn the_http_gates_do_not_change_how_stdio_declarations_are_planned() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        for gates in [no_gates(), http_gates(&[], true)] {
            let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &gates);
            assert_eq!(plan.approved, vec![d.clone()]);
        }
    }

    /// 承認後に宣言が変わった場合は、ユーザーへの説明が変わる（stale）。
    #[test]
    fn a_changed_declaration_is_reported_as_a_void_approval() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);

        let mut changed = d.clone();
        changed.args = vec!["evil.js".to_string()];
        let plan = McpRuntime::plan(&[changed], &store.load(), &no_gates());

        assert!(plan.approved.is_empty());
        assert_eq!(
            plan.skipped[0].reason,
            SkipReason::NotApproved { stale: true }
        );
        assert!(plan.skipped[0].message().contains("has changed since"));
    }

    /// **harnessが宣言の欄を増やしたことによる失効は、「宣言が変わった」と案内しない**
    /// （`crate::decl::DECL_FORMAT_VERSION`）。理由は起動時の1行が持つ。
    #[test]
    fn a_format_upgrade_is_not_reported_as_the_user_changing_the_declaration() {
        let d = decl("docs");
        // 版だけを1つ古くする（ハッシュは一致させたままにして、**版だけ**が効いていることを見る）。
        let ledger = crate::approval::McpApprovalLedger {
            approvals: vec![crate::approval::McpApproval {
                id: d.id.clone(),
                decl_hash: d.approval_hash(),
                approved_at_unix_secs: 0,
                summary: None,
                decl_format_version: Some(crate::decl::DECL_FORMAT_VERSION - 1),
            }],
        };
        let plan = McpRuntime::plan(std::slice::from_ref(&d), &ledger, &no_gates());

        assert!(plan.approved.is_empty(), "版が古い承認で起動している");
        assert_eq!(
            plan.skipped[0].reason,
            SkipReason::NotApproved { stale: false },
            "harnessが欄を増やしたのに「あなたが宣言を変えた」と案内している"
        );
        assert!(!plan.skipped[0].message().contains("has changed since"));

        let notice = plan
            .format_upgrade_notice()
            .expect("理由を出さないと「黙って起動しなくなった」になる");
        assert!(notice.contains("process"), "{notice}");
        assert!(notice.contains("docs"), "{notice}");
    }

    /// **対の側**（`B-35`）: 現行版で承認されていれば、その1行は出ない。
    ///
    /// 片方だけだと「常に出す実装」でも上のテストは通り、毎起動で無関係な警告が出る。
    #[test]
    fn a_current_format_approval_produces_no_upgrade_notice() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &no_gates());
        assert_eq!(plan.approved, vec![d]);
        assert_eq!(plan.format_upgrade_notice(), None);
    }

    /// 一度も承認していない宣言では、この1行は出ない（**失効していないため**）。
    #[test]
    fn a_never_approved_declaration_produces_no_upgrade_notice() {
        let (_dir, store) = store();
        let plan = McpRuntime::plan(&[decl("docs")], &store.load(), &no_gates());
        assert_eq!(plan.format_upgrade_notice(), None);
    }

    #[test]
    fn an_invalid_declaration_is_skipped_with_a_reason() {
        let (_dir, store) = store();
        let mut bad = decl("docs");
        bad.id = "Bad Id".to_string();
        let plan = McpRuntime::plan(&[bad], &store.load(), &no_gates());
        assert!(matches!(plan.skipped[0].reason, SkipReason::Invalid(_)));
    }

    #[test]
    fn duplicate_ids_do_not_both_start() {
        let (_dir, store) = store();
        let d = decl("docs");
        store.approve(&d);
        let plan = McpRuntime::plan(&[d.clone(), d], &store.load(), &no_gates());
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
