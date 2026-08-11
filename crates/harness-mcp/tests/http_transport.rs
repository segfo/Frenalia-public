//! Streamable HTTP（M15.6、`plans/DESIGN-MCP.md` §6.2）の**実プロセス相手**の往復テスト。
//!
//! `http_wire.rs`の単体テストが固定するのは純粋な判断（宛先ゲート・SSEの区切り・応答の分類）
//! だけで、**実際にHTTPで別プロセスとJSON-RPCを交換できるか**は検証できない。ここがその層。
//!
//! 相手は`src/bin/mcp-mock-http-server.rs`（loopback・平文）。loopbackはD-49のallowlistと
//! 平文ゲートの両方から免除されるので、フラグ無しで通せる。
//!
//! ## 隔離を通さない理由
//!
//! Streamable HTTPには通す隔離が無い（D-50。harness本体が喋る）。したがって
//! stdio側（`mcp_e2e_tests`が実機でAppContainerを確かめている）と違い、ここで確かめるのは
//! プロトコルとフレーミングそのものになる。証明書検証は`tests/http_tls.rs`が持つ。

mod support;

use std::time::Duration;

use harness_core::{RiskClass, ToolCtx};
use harness_mcp::approval::ApprovalStore;
use harness_mcp::decl::McpServerDecl;
use harness_mcp::runtime::{McpRuntime, SkippedServer};
use harness_mcp::transport_http::HttpTransportFactory;

use support::{decl, gates, MockServer};

fn start(decl: McpServerDecl) -> (McpRuntime, Vec<SkippedServer>) {
    let gates = gates();
    let prepared = McpRuntime::prepare_http(&decl, &gates).expect("prepare");
    let mut skipped = Vec::new();
    let runtime = McpRuntime::start(vec![prepared], &HttpTransportFactory, "0.1.0", &mut skipped);
    (runtime, skipped)
}

/// **完了条件のgolden**: `initialize`→`notifications/initialized`→`tools/list`が実プロセス
/// 相手に成立し、宣言した`RiskClass`が付いた名前空間付きツールが登録される。
#[test]
fn a_json_mode_server_completes_the_handshake_and_registers_namespaced_tools() {
    let server = MockServer::start("json");
    let (runtime, skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
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
    assert_eq!(
        search.input_schema()["properties"]["query"]["type"],
        "string"
    );
}

/// **完了条件のgolden**: 同じ往復が`text/event-stream`の応答でも成立する。
#[test]
fn an_sse_mode_server_completes_the_same_handshake() {
    let server = MockServer::start("sse");
    let (runtime, skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}

/// **完了条件のgolden**: `tools/call`がHTTPで往復し、explicit nullは実サーバへ届かない。
#[tokio::test]
async fn tools_call_round_trips_over_http_without_explicit_nulls() {
    let server = MockServer::start("json");
    let (runtime, _skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();

    let ctx = ToolCtx::new(std::path::PathBuf::from("."));
    let out = search
        .call(serde_json::json!({ "query": "hello", "limit": null }), &ctx)
        .await
        .unwrap();
    assert!(!out.is_error, "{out:?}");
    assert!(out.content.contains("results for hello"), "{}", out.content);
    assert!(
        out.content.contains("argument keys: query"),
        "the server must only see the non-null keys: {}",
        out.content
    );
}

/// SSE応答でも`tools/call`の中身が正しく取り出せる（フレーミングの実地確認）。
#[tokio::test]
async fn tools_call_round_trips_over_sse() {
    let server = MockServer::start("sse");
    let (runtime, _skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();

    let ctx = ToolCtx::new(std::path::PathBuf::from("."));
    let out = search
        .call(serde_json::json!({ "query": "sse" }), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("results for sse"), "{}", out.content);
}

/// **セッションとプロトコルバージョンのヘッダが、initialize以降のリクエストへ実際に載る。**
///
/// モックは`tools/list`で受け取ったヘッダを`search`の説明へ埋めて返すので、
/// クライアントが何を送ったかを外から観測できる。
#[test]
fn the_session_id_and_negotiated_protocol_version_are_sent_on_later_requests() {
    let server = MockServer::start("json");
    let (runtime, _skipped) = start(decl(&server.url(), &[]));
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();

    let seen = search.description();
    assert!(seen.contains("session=mock-session-1"), "{seen}");
    assert!(seen.contains("protocol=2025-06-18"), "{seen}");
}

/// 宣言のヘッダ（`${env:...}`展開後）が実際にサーバへ届く。
#[test]
fn declared_headers_reach_the_server() {
    let server = MockServer::start("json");
    let mut d = decl(&server.url(), &[]);
    d.headers.insert(
        "Authorization".to_string(),
        "Bearer ${env:HARNESS_TEST_MCP_HTTP_TOKEN}".to_string(),
    );
    // SAFETY: 単一のテストプロセス内での設定。ここでしか読まない名前を使う。
    std::env::set_var("HARNESS_TEST_MCP_HTTP_TOKEN", "s3cret");

    let (runtime, skipped) = start(d);
    assert!(skipped.is_empty(), "{skipped:?}");
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();
    assert!(
        search.description().contains("authorization=Bearer s3cret"),
        "{}",
        search.description()
    );
}

/// **`Mcp-Session-Id`は任意**。発行しないサーバとも普通に往復できる。
#[test]
fn a_server_that_never_issues_a_session_id_still_works() {
    let server = MockServer::start("no-session-id");
    let (runtime, skipped) = start(decl(&server.url(), &[]));
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}

/// **D-49: リダイレクトは追わない。** 承認とallowlistの対象は宣言に書かれたホストだけで、
/// 追従すればその両方を迂回して別のホストと喋ることになる。
#[test]
fn a_redirect_aborts_the_session_instead_of_being_followed() {
    let server = MockServer::start("redirect");
    let (runtime, skipped) = start(decl(&server.url(), &[]));

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    let message = skipped[0].message();
    assert!(message.contains("does not follow redirects"), "{message}");
    // 誘導先を伝える（ユーザーが「そこが本来の宛先なら url を直す」と判断できるように）。
    assert!(message.contains("elsewhere.example"), "{message}");
}

/// 404（セッション失効）は**黙って張り直さず**、直し方付きのエラーで止まる。
/// 再initializeは`tools/list`をやり直す＝承認済みのツール集合が変わりうるため。
#[test]
fn an_expired_session_fails_closed_with_an_explanation() {
    let server = MockServer::start("expire-session");
    let (runtime, skipped) = start(decl(&server.url(), &[]));

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    let message = skipped[0].message();
    assert!(message.contains("session is gone"), "{message}");
    assert!(
        message.contains("does not silently re-initialize"),
        "{message}"
    );
}

/// 非2xxはエラーになり、**本文が診断へ載る**（原因が届かないと切り分けられない）。
#[test]
fn a_server_error_is_reported_with_its_body() {
    let server = MockServer::start("server-error");
    let (runtime, skipped) = start(decl(&server.url(), &[]));

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].message().contains("HTTP 500"),
        "{:?}",
        skipped[0]
    );
}

/// 起動に失敗したサーバは報告され、ツールを1つも登録しない（stdio側と同じ扱い）。
#[test]
fn a_server_that_fails_to_initialize_registers_nothing() {
    let server = MockServer::start("fail-initialize");
    let (runtime, skipped) = start(decl(&server.url(), &[]));

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].message().contains("failed to start"),
        "{skipped:?}"
    );
}

/// **完了条件**: 宣言の無いツール・サーバが`readOnlyHint`を自称するツールは、どちらも
/// 非read扱いのままパーミッションゲートを通る（D-40。トランスポートに依存しない）。
#[test]
fn undeclared_and_self_declared_read_only_tools_stay_non_read_over_http() {
    let server = MockServer::start("json");
    let (runtime, _skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
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

/// 承認台帳との通し確認（D-39）。ゲートを全部開けても、承認前は起動対象にならない。
#[test]
fn an_http_declaration_starts_only_after_it_is_approved() {
    let server = MockServer::start("json");
    let dir = tempfile::tempdir().unwrap();
    let store = ApprovalStore::at_path(dir.path().join("ledger.json"));
    let d = decl(&server.url(), &[("search", RiskClass::ReadOnly)]);

    let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &gates());
    assert!(plan.approved.is_empty());

    store.approve(&d);
    let plan = McpRuntime::plan(std::slice::from_ref(&d), &store.load(), &gates());
    assert_eq!(plan.approved.len(), 1);

    let (runtime, skipped) = start(d);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}

/// 落ちたサーバへの呼び出しはハングせずエラーになる（`shutdown`後の状態）。
#[tokio::test]
async fn calls_after_shutdown_fail_rather_than_hanging() {
    let server = MockServer::start("json");
    let (mut runtime, _skipped) = start(decl(&server.url(), &[("search", RiskClass::ReadOnly)]));
    let tools = runtime.tools();
    let search = tools
        .iter()
        .find(|t| t.name() == "mcp__mock__search")
        .unwrap();
    runtime.shutdown();

    let ctx = ToolCtx::new(std::path::PathBuf::from("."));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        search.call(serde_json::json!({ "query": "x" }), &ctx),
    )
    .await
    .expect("the call must not hang after shutdown");
    assert!(result.is_err(), "{result:?}");
}
