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
use std::sync::{Condvar, Mutex};

use harness_core::RiskClass;
use harness_mcp::decl::{
    McpNetworkDecl, McpProcessAccess, McpServerDecl, McpTransportKind, McpWorkspaceAccess,
};
use harness_mcp::http_wire::EndpointGates;
use harness_mcp::runtime::McpGates;

/// cargoが統合テストの前に必ずビルドし、パスを渡してくれる
/// （`src/bin/mcp-mock-http-server.rs`のモジュールdoc参照）。
const MOCK_SERVER: &str = env!("CARGO_BIN_EXE_mcp-mock-http-server");

/// [BUG-162] **モックサーバは同時に1つしか立てない。**
///
/// # なぜ要るのか（測ってから決めた）
///
/// テストは既定で並列に走るので、1つのテストバイナリで**14個のサーバプロセスが同時に生きる**。
/// 機械が混んでいると、その状態で`connect`が21秒待っても繋がらず（`os error 10060`）、
/// 起動が失敗する——症状は「ツールが1つも登録されない」で、プロトコルとは何の関係も無い。
///
/// **2026-09-20に実測した。** 同じテストバイナリを8本同時に走らせると、並列のままなら
/// 8本中2本が落ちる。`--test-threads=1`（＝サーバを1つずつ）にすると**8本とも通る**。
/// 混んでいることそのものではなく、**同時に生きているサーバの数**が効いている。
///
/// # 待ち合わせを個々のテストに書かない
///
/// 制約は**資源の側**にある（サーバが多いと繋がらない）ので、ここで持つ。テストごとに
/// ロックを書く形にすると、次にサーバを使うテストを足す人が書き忘れる——そして
/// **書き忘れた回だけ、たまに落ちる**。
///
/// ここが測っているのはプロトコルとフレーミングであって、**サーバを何本同時に立てられるか
/// ではない**。直列にしても測っているものは1つも変わらない（1本あたり数ミリ秒）。
struct OneServerAtATime;

static SERVER_IN_USE: Mutex<bool> = Mutex::new(false);
static SERVER_FREED: Condvar = Condvar::new();

impl OneServerAtATime {
    fn acquire() -> Self {
        let mut in_use = SERVER_IN_USE.lock().unwrap_or_else(|e| e.into_inner());
        while *in_use {
            in_use = SERVER_FREED.wait(in_use).unwrap_or_else(|e| e.into_inner());
        }
        *in_use = true;
        Self
    }
}

impl Drop for OneServerAtATime {
    fn drop(&mut self) {
        // **panicで巻き戻る途中でもここは走る。** 走らないと、落ちた1本が他を道連れに
        // 永久に待たせる（毒された状態は`into_inner`で通す——守っているのは真偽値1つで、
        // 途中で壊れる不変条件が無い）。
        *SERVER_IN_USE.lock().unwrap_or_else(|e| e.into_inner()) = false;
        SERVER_FREED.notify_one();
    }
}

/// 起動したモックサーバ（平文HTTP・loopback）。dropで確実に落とす。
pub struct MockServer {
    child: Child,
    addr: SocketAddr,
    /// **順番待ちの札。`MockServer`と寿命が同じ**（[`OneServerAtATime`]）。
    /// ここに持たせてあるので、テスト側は何も書かなくてよい。
    _one_at_a_time: OneServerAtATime,
}

impl MockServer {
    pub fn start(mode: &str) -> Self {
        // **子を起こす前に順番を取る**（起こしてから待つと、待っている間サーバが生きている）。
        let one_at_a_time = OneServerAtATime::acquire();
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

        Self {
            child,
            addr,
            _one_at_a_time: one_at_a_time,
        }
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
        process: McpProcessAccess::Deny,
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
