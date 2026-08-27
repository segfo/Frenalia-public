//! Streamable HTTPの統合テストが共有する足回り（M15.6）。
//!
//! `http_transport.rs`（プロトコルとフレーミング）と`http_tls.rs`（証明書検証）は別の
//! テストバイナリなので、モックサーバの起動と宣言の組み立てをここへ置いて1実装に保つ
//! （`docs/CODE-STRUCTURE-RULES.md` 規則5）。
//!
//! テストバイナリごとに使う項目が違う（`http_tls.rs`は独自のゲートを組む）ため、
//! 未使用警告は抑止する。

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

use harness_core::RiskClass;
use harness_mcp::decl::{McpNetworkDecl, McpServerDecl, McpTransportKind, McpWorkspaceAccess};
use harness_mcp::http_wire::EndpointGates;
use harness_mcp::runtime::McpGates;

/// cargoが統合テストの前に必ずビルドし、パスを渡してくれる
/// （`src/bin/mcp-mock-http-server.rs`のモジュールdoc参照）。
const MOCK_SERVER: &str = env!("CARGO_BIN_EXE_mcp-mock-http-server");

/// 起動したモックサーバ（平文HTTP・loopback）。dropで確実に落とす。
pub struct MockServer {
    child: Child,
    addr: SocketAddr,
}

impl MockServer {
    pub fn start(mode: &str) -> Self {
        let mut child = Command::new(MOCK_SERVER)
            .env("HARNESS_TEST_MCP_HTTP_MODE", mode)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn mock http mcp server");

        // 待受ポートは`0`でbindしているので、サーバが出す1行目から取る。
        let stdout = child.stdout.take().expect("stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read the listening line");
        let addr: SocketAddr = line
            .trim()
            .strip_prefix("listening on ")
            .unwrap_or_else(|| panic!("unexpected first line from the mock server: {line:?}"))
            .parse()
            .expect("parse the listening address");

        Self { child, addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn decl(url: &str, tools: &[(&str, RiskClass)]) -> McpServerDecl {
    McpServerDecl {
        id: "mock".to_string(),
        transport: McpTransportKind::StreamableHttp,
        command: String::new(),
        args: Vec::new(),
        env: BTreeMap::new(),
        url: url.to_string(),
        headers: BTreeMap::new(),
        tls_pin: None,
        tools: tools
            .iter()
            .map(|(name, risk)| (name.to_string(), *risk))
            .collect(),
        network: McpNetworkDecl::default(),
        workspace: McpWorkspaceAccess::None,
    }
}

/// loopback宛なのでallowlistは空でよい（D-49の免除）。オプトインだけ立てる。
pub fn gates() -> McpGates {
    McpGates {
        streamable_http_enabled: true,
        http_endpoints: EndpointGates::default(),
        http_ca_bundle: None,
    }
}
