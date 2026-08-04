//! 実プロセスのMCPサーバ（`src/bin/mcp-mock-server.rs`）を相手にした往復テスト。
//!
//! `client.rs`の単体テストは台本トランスポートを使うため、**実際に別プロセスと改行区切り
//! JSONを交換できるか**は検証できない。ここがその層を埋める。
//!
//! ## 統合テストである理由（単体テストではだめだった）
//!
//! `CARGO_BIN_EXE_mcp-mock-server`は統合テストにだけ渡される環境変数で、**cargoがこのbinを
//! 先にビルドすることを保証する**。当初はモックサーバを独立クレートにして単体テストから
//! `target/debug/`を直接見に行っていたが、`cargo test --workspace`はビルド順を保証しないため
//! クリーンなツリーで「exeが無い」と落ちた。依存をcargoに保証させる形へ直したのがこのファイル。
//!
//! ## AppContainerを通さない理由
//!
//! 隔離を通す経路（`transport_stdio`）は管理者権限とWindows実機を要し、通常の`cargo test`に
//! 載せられない。ここで確認したいのは**プロトコルとフレーミングが実プロセス相手に成立するか**
//! なので、隔離は`#[ignore]`付きの実機E2E（`harness-sandbox`の`mcp_e2e_tests`）に委ねる。
//!
//! この`StdioProcessTransport`は**テストの中にしか無い**——本番コードに「隔離なしの通信路」を
//! 置かない（`plans/DESIGN-MCP.md` §3.4の明示オプトイン以外の抜け道を作らない）。

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use harness_core::{RiskClass, ToolCtx};
use harness_mcp::approval::ApprovalStore;
use harness_mcp::decl::{McpNetworkDecl, McpServerDecl, McpTransportKind, McpWorkspaceAccess};
use harness_mcp::runtime::{McpRuntime, PreparedServer, SkippedServer, TransportFactory};
use harness_mcp::transport::{LineAccumulator, Transport};
use harness_mcp::McpError;

/// cargoが統合テストの前に必ずビルドし、パスを渡してくれる（モジュールdoc参照）。
const MOCK_SERVER: &str = env!("CARGO_BIN_EXE_mcp-mock-server");

/// テスト専用のstdioトランスポート（モジュールdoc参照）。
struct StdioProcessTransport {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout_rx: Receiver<Vec<u8>>,
    stderr: Arc<Mutex<String>>,
    lines: LineAccumulator,
}

impl StdioProcessTransport {
    fn spawn(env: &[(String, String)]) -> Self {
        let mut command = Command::new(MOCK_SERVER);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            command.env(k, v);
        }
        let mut child = command.spawn().expect("spawn mock mcp server");
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = child.stdout.take().expect("stdout");
        let mut stderr_pipe = child.stderr.take().expect("stderr");

        let (tx, stdout_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        let stderr = Arc::new(Mutex::new(String::new()));
        let stderr_sink = stderr.clone();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr_pipe.read_to_string(&mut text);
            if let Ok(mut sink) = stderr_sink.lock() {
                sink.push_str(&text);
            }
        });

        Self {
            child,
            stdin,
            stdout_rx,
            stderr,
            lines: LineAccumulator::new(),
        }
    }
}

impl Transport for StdioProcessTransport {
    fn send_line(&mut self, line: &str) -> Result<(), McpError> {
        writeln!(self.stdin, "{line}").map_err(|e| McpError::Io(e.to_string()))?;
        self.stdin.flush().map_err(|e| McpError::Io(e.to_string()))
    }

    fn recv_line(&mut self, timeout: Duration) -> Result<String, McpError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.lines.take_line()? {
                return Ok(line);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(McpError::Timeout("mock server did not answer".to_string()));
            }
            match self.stdout_rx.recv_timeout(remaining) {
                Ok(chunk) => self.lines.push_bytes(&chunk),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(McpError::Timeout("mock server did not answer".to_string()))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(McpError::Io("mock server exited".to_string()))
                }
            }
        }
    }

    fn take_stderr(&mut self) -> String {
        self.stderr
            .lock()
            .map(|mut s| std::mem::take(&mut *s))
            .unwrap_or_default()
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct MockServerFactory {
    env: Vec<(String, String)>,
}

impl TransportFactory for MockServerFactory {
    fn create(&self, _prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
        Ok(Box::new(StdioProcessTransport::spawn(&self.env)))
    }
}

fn decl_with(tools: &[(&str, RiskClass)]) -> McpServerDecl {
    McpServerDecl {
        id: "mock".to_string(),
        transport: McpTransportKind::Stdio,
        command: MOCK_SERVER.to_string(),
        args: Vec::new(),
        env: BTreeMap::new(),
        tools: tools
            .iter()
            .map(|(name, risk)| (name.to_string(), *risk))
            .collect(),
        network: McpNetworkDecl::default(),
        workspace: McpWorkspaceAccess::None,
    }
}

fn prepared(decl: McpServerDecl) -> PreparedServer {
    PreparedServer {
        profile_name: "harness.mcp.test.mock".to_string(),
        decl,
        proxy_addr: None,
    }
}

fn start(decl: McpServerDecl, env: Vec<(String, String)>) -> (McpRuntime, Vec<SkippedServer>) {
    let mut skipped = Vec::new();
    let runtime = McpRuntime::start(
        vec![prepared(decl)],
        &MockServerFactory { env },
        "0.1.0",
        &mut skipped,
    );
    (runtime, skipped)
}

/// **完了条件のgolden**: 実プロセス相手に`initialize`→`tools/list`が成立し、宣言した
/// `RiskClass`が付いた状態で名前空間付きのツールが登録される。
#[test]
fn tools_list_against_the_real_mock_server_registers_namespaced_tools() {
    let (runtime, skipped) = start(decl_with(&[("search", RiskClass::ReadOnly)]), Vec::new());
    assert!(skipped.is_empty(), "{skipped:?}");

    let tools = runtime.tools();
    let mut names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "mcp__mock__claims_read_only",
            "mcp__mock__create_issue",
            "mcp__mock__search"
        ]
    );

    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();
    assert_eq!(search.risk(&serde_json::json!({})), RiskClass::ReadOnly);
    assert!(search.description().contains("[mcp server: mock]"));
    assert_eq!(
        search.input_schema()["properties"]["query"]["type"],
        "string"
    );
}

/// **完了条件のgolden**: `tools/call`が実プロセス相手に往復する。
#[tokio::test]
async fn tools_call_against_the_real_mock_server_returns_its_text_content() {
    let (runtime, _skipped) = start(decl_with(&[("search", RiskClass::ReadOnly)]), Vec::new());
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();

    let ctx = ToolCtx::new(std::path::PathBuf::from("."));
    let out = search
        .call(serde_json::json!({ "query": "hello" }), &ctx)
        .await
        .unwrap();
    assert!(!out.is_error, "{out:?}");
    assert!(out.content.contains("results for hello"), "{}", out.content);
}

/// **(f) explicit null 除去が、実際にサーバへ届く引数から消えている**ことを、サーバ側が
/// 受け取ったキー一覧を返してくることで外から確認する。
#[tokio::test]
async fn explicit_nulls_never_reach_the_real_server() {
    let (runtime, _skipped) = start(decl_with(&[("search", RiskClass::ReadOnly)]), Vec::new());
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();

    let ctx = ToolCtx::new(std::path::PathBuf::from("."));
    let out = search
        .call(
            serde_json::json!({ "query": "hello", "limit": null, "cursor": null }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(
        out.content.contains("argument keys: query"),
        "the server must only see the non-null keys: {}",
        out.content
    );
}

/// **完了条件**: 書込系（宣言の無い）MCPツールはパーミッションゲートに掛かる（D-40）。
/// サーバが`readOnlyHint: true`を自称していても変わらない。
#[test]
fn undeclared_and_self_declared_read_only_tools_both_stay_non_read() {
    let (runtime, _skipped) = start(decl_with(&[("search", RiskClass::ReadOnly)]), Vec::new());
    let tools = runtime.tools();

    for name in ["mcp__mock__create_issue", "mcp__mock__claims_read_only"] {
        let tool = tools.iter().find(|t| t.name() == name).unwrap();
        assert_eq!(
            tool.risk(&serde_json::json!({})),
            RiskClass::Network,
            "{name} must not be auto-allowed"
        );
    }
}

/// 起動に失敗したサーバは`skipped`として報告され、ツールは1つも登録されない。
#[test]
fn a_server_that_fails_to_initialize_is_reported_and_registers_nothing() {
    let (runtime, skipped) = start(
        decl_with(&[]),
        vec![("MCP_MOCK_FAIL_INITIALIZE".to_string(), "1".to_string())],
    );
    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].message().contains("failed to start"),
        "{skipped:?}"
    );
}

/// 承認台帳と組み合わせた通し確認: 未承認 → 起動されない、承認後 → 起動する。
#[test]
fn the_same_declaration_starts_only_after_it_is_approved() {
    let dir = tempfile::tempdir().unwrap();
    let store = ApprovalStore::at_path(dir.path().join("ledger.json"));
    let decl = decl_with(&[("search", RiskClass::ReadOnly)]);

    let plan = McpRuntime::plan(std::slice::from_ref(&decl), &store.load());
    assert!(plan.approved.is_empty());

    store.approve(&decl);
    let plan = McpRuntime::plan(std::slice::from_ref(&decl), &store.load());
    assert_eq!(plan.approved.len(), 1);

    let (runtime, skipped) = start(decl, Vec::new());
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}
