//! Streamable HTTPトランスポート（`plans/DESIGN-MCP.md` §6.2、D-41/D-49/D-51）。
//!
//! **この経路には§3の統制が効かない。** harness本体はAppContainerの外にあるので、WFPの
//! package SID条件にも協調プロキシにも掛からない。効くのは接続する前の3段ゲート（D-49、
//! [`crate::http_wire::validate_endpoint`]）と承認台帳（D-39）、そして接続時のTLS検証だけである。
//!
//! ## なぜ専用スレッドなのか
//!
//! [`crate::transport::Transport`]は同期APIだが、`harness-cli`の`launch_mcp_servers`は
//! `stage_run_agent`（`async fn`）の中から呼ばれる。asyncコンテキストで`block_on`すると
//! panicするため、**ブロックする側をワーカースレッドへ完全に閉じ込める**。`send_line`は
//! チャネルへ積むだけ、`recv_line`は`recv_timeout`で受けるだけになる。
//! `tests/mock_server.rs`の`StdioProcessTransport`が読取スレッド＋チャネルで同じ形をとる。
//!
//! ## TLS（D-51）
//!
//! 検証は無効化できない。`danger_accept_invalid_certs`を呼ぶ経路も、それを立てられる設定・
//! CLIフラグ・宣言フィールドも存在しない。`crates/harness-sandbox-vm/src/vmsandbox/incus.rs`に
//! Incusの自己署名証明書向けの同フラグがあるが、**あれをここへ持ち込まない**
//! （`docs/CODE-STRUCTURE-RULES.md` 規則5「セキュリティ機構の実装のコピーは特に危険」）。
//! 私有CAはOS証明書ストアか`mcp.http_ca_bundle`（ユーザ層のみ）で通す。
//!
//! ## 実装しないもの（`docs/STATUS.md`が残課題として持つ）
//!
//! - サーバ→クライアントのGET SSEストリーム。harnessは`initialize`でcapabilityを空申告する
//!   ので、サーバ起点で送られてきても行える処理が無い
//! - `Last-Event-ID`によるレジューム
//! - 404（セッション失効）時の自動再initialize。**再initializeは`tools/list`をやり直す＝
//!   承認後にツール集合が変わりうる**ので、fail-closedで止めて明示エラーにする

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::http_wire::{classify_response, CertPin, Endpoint, ResponseKind, SseAccumulator};
use crate::runtime::{PreparedIsolation, PreparedServer, TransportFactory};
use crate::transport::{Transport, DEFAULT_MAX_LINE_BYTES};
use crate::McpError;

/// 1リクエストのヘッダ受信までに待つ上限。本文の到着は`recv_line`側の締切が支配する。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// `shutdown`時の`DELETE`（best-effort）。セッション終了で待たせない程度に短く。
const DELETE_TIMEOUT: Duration = Duration::from_secs(5);

/// 診断バッファの上限。stderrと同じく「最後に何が起きたか」が分かればよい。
const MAX_DIAGNOSTICS_BYTES: usize = 64 * 1024;

/// harnessが自分で組み立てるヘッダ（宣言側からの指定は`decl::validate`が拒否する）。
const HEADER_SESSION_ID: &str = "mcp-session-id";
const HEADER_PROTOCOL_VERSION: &str = "mcp-protocol-version";

/// Streamable HTTPの接続設定。[`crate::runtime::McpGates`]と検証済み[`Endpoint`]から作る。
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub endpoint: Endpoint,
    /// `${env:...}`展開済みのヘッダ。**この値はログにも診断にも出さない。**
    pub headers: Vec<(String, String)>,
    /// 私有CAのPEMバンドル（`mcp.http_ca_bundle`）。無ければOS証明書ストアだけを使う。
    pub ca_bundle: Option<PathBuf>,
    /// サーバ証明書のピン（D-52）。`Some`のとき、CA連鎖と名前の検証はこれに置き換わる。
    pub tls_pin: Option<CertPin>,
}

/// ワーカーへ渡す指示。
enum Command {
    Post(String),
    Shutdown,
}

/// HTTPでMCPサーバと往復するトランスポート。
pub struct HttpTransport {
    to_worker: Option<Sender<Command>>,
    from_worker: Receiver<Result<String, McpError>>,
    diagnostics: Arc<Mutex<String>>,
    protocol_version: Arc<Mutex<Option<String>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Transport for HttpTransport {
    fn send_line(&mut self, line: &str) -> Result<(), McpError> {
        let Some(tx) = self.to_worker.as_ref() else {
            return Err(McpError::Closed);
        };
        tx.send(Command::Post(line.to_string()))
            .map_err(|_| McpError::Closed)
    }

    fn recv_line(&mut self, timeout: Duration) -> Result<String, McpError> {
        match self.from_worker.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(McpError::Timeout(
                "no message arrived from the mcp server".to_string(),
            )),
            Err(RecvTimeoutError::Disconnected) => Err(McpError::Closed),
        }
    }

    fn take_stderr(&mut self) -> String {
        // HTTPにstderrは無い。trait doc の契約（エラー診断のためだけに使う）どおり、
        // 直近のステータス行・本文の先頭・接続/TLSエラーをここへ出す。証明書検証の失敗が
        // ここに出ないと、`McpClient`のタイムアウトメッセージが「応答しません」だけになり、
        // CAの問題なのか到達性の問題なのかを切り分けられない。
        self.diagnostics
            .lock()
            .map(|mut d| std::mem::take(&mut *d))
            .unwrap_or_default()
    }

    fn shutdown(&mut self) {
        if let Some(tx) = self.to_worker.take() {
            let _ = tx.send(Command::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    fn on_protocol_negotiated(&mut self, version: &str) {
        if let Ok(mut slot) = self.protocol_version.lock() {
            *slot = Some(version.to_string());
        }
    }
}

impl Drop for HttpTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl HttpTransport {
    /// ワーカースレッドを起こす。**ここではまだ接続しない**（最初の`send_line`で繋がる）。
    pub fn connect(config: HttpConfig) -> Result<Self, McpError> {
        let (to_worker, worker_rx) = std::sync::mpsc::channel();
        let (worker_tx, from_worker) = std::sync::mpsc::channel();
        let diagnostics = Arc::new(Mutex::new(String::new()));
        let protocol_version = Arc::new(Mutex::new(None));

        let worker_diagnostics = diagnostics.clone();
        let worker_protocol_version = protocol_version.clone();
        let worker = std::thread::Builder::new()
            .name(format!("mcp-http-{}", config.endpoint.host()))
            .spawn(move || {
                run_worker(
                    config,
                    worker_rx,
                    worker_tx,
                    worker_diagnostics,
                    worker_protocol_version,
                );
            })
            .map_err(|e| McpError::Io(format!("could not start the mcp http worker: {e}")))?;

        Ok(Self {
            to_worker: Some(to_worker),
            from_worker,
            diagnostics,
            protocol_version,
            worker: Some(worker),
        })
    }
}

/// ワーカースレッド本体。ここだけがブロックしてよい。
fn run_worker(
    config: HttpConfig,
    commands: Receiver<Command>,
    responses: Sender<Result<String, McpError>>,
    diagnostics: Arc<Mutex<String>>,
    protocol_version: Arc<Mutex<Option<String>>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = responses.send(Err(McpError::Io(format!(
                "could not start the mcp http runtime: {e}"
            ))));
            return;
        }
    };

    let client = match build_client(&config) {
        Ok(client) => client,
        Err(e) => {
            let _ = responses.send(Err(e));
            return;
        }
    };

    let mut session_id: Option<String> = None;

    while let Ok(command) = commands.recv() {
        match command {
            Command::Shutdown => break,
            Command::Post(line) => {
                let outcome = runtime.block_on(post_once(
                    &client,
                    &config,
                    &line,
                    &session_id,
                    &protocol_version,
                    &diagnostics,
                ));
                match outcome {
                    Ok(PostOutcome {
                        new_session,
                        messages,
                    }) => {
                        if let Some(id) = new_session {
                            session_id = Some(id);
                        }
                        // 202（通知への受理応答）はメッセージ0件。`McpClient::notify`は
                        // 応答を読まないので、何も送らないのが正しい。
                        for message in messages {
                            if responses.send(Ok(message)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        if responses.send(Err(e)).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    // MCP仕様: セッションを持っているクライアントは終了時にDELETEを送る**べき**。
    // 落ちても困らない（サーバ側のタイムアウトで消える）のでbest-effortにする。
    if let Some(id) = session_id {
        let _ = runtime.block_on(async {
            client
                .delete(config.endpoint.url())
                .header(HEADER_SESSION_ID, id)
                .timeout(DELETE_TIMEOUT)
                .send()
                .await
        });
    }
}

/// TLSの所在（D-51・D-52）。
fn build_client(config: &HttpConfig) -> Result<reqwest::Client, McpError> {
    let builder = reqwest::Client::builder()
        // 3xxは追わない（D-49）。承認とallowlistの対象は宣言に書かれたホストだけであり、
        // 追従するとその両方を迂回して別のホストと喋ることになる。
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT);
    // `danger_accept_invalid_certs`はここにも他のどこにも無い（モジュールdoc参照）。

    // D-52: ピンがあるときは**ピンだけ**で同一性を決める。CAバンドルもOS証明書ストアも
    // 参照しない（そのどちらにも入っていない証明書を受け入れるための機構なので、
    // 併用すると「どちらで通ったのか」が分からなくなる）。
    if let Some(pin) = &config.tls_pin {
        return build_pinned_client(builder, pin.clone());
    }

    let mut builder = builder.min_tls_version(reqwest::tls::Version::TLS_1_2);
    if let Some(path) = &config.ca_bundle {
        let pem = std::fs::read(path).map_err(|e| {
            McpError::Io(format!(
                "could not read the mcp http ca bundle {}: {e}",
                path.display()
            ))
        })?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| McpError::Io(format!("invalid ca bundle {}: {e}", path.display())))?
        {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder.build().map_err(|e| {
        McpError::Io(format!(
            "could not build the mcp http client: {}",
            describe_with_causes(&e)
        ))
    })
}

/// ピン留めされたクライアント（D-52）。
///
/// `min_tls_version`は使わない——TLS設定を丸ごと差し替えるので、代わりに
/// `with_safe_default_protocol_versions()`（TLS 1.2/1.3のみ）で同じ下限を張る。
fn build_pinned_client(
    builder: reqwest::ClientBuilder,
    pin: CertPin,
) -> Result<reqwest::Client, McpError> {
    let provider = default_crypto_provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            McpError::Io(format!(
                "could not configure tls for the pinned mcp client: {e}"
            ))
        })?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedCertVerifier { pin, provider }))
        .with_no_client_auth();
    // ALPNはhttp/1.1だけを申告する。TLS設定を差し替えるとreqwestの既定の申告が載らないので、
    // 交渉結果とクライアント側の想定がずれない一点に固定する（MCPはHTTP/1.1で足りる）。
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    // **`Some(tls)`ではなく`tls`を渡す。** `tls_backend_preconfigured`は受け取った値を
    // 自分で`Some`へ包んでから`Option<rustls::ClientConfig>`へダウンキャストするので、
    // こちらで包むと`Option<Option<..>>`になり「不明なTLSバックエンド」で落ちる。
    builder.tls_backend_preconfigured(tls).build().map_err(|e| {
        McpError::Io(format!(
            "could not build the pinned mcp http client: {}",
            describe_with_causes(&e)
        ))
    })
}

fn default_crypto_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    // reqwest側が既にプロセス既定を入れていればそれを使う（暗号実装を二重に持たない）。
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return provider.clone();
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let _ = rustls::crypto::CryptoProvider::install_default((*provider).clone());
    provider
}

/// **証明書ピンによる検証**（D-52、`plans/DESIGN-MCP.md` §6.2）。
///
/// 置き換えるのは**CA連鎖と名前の検証だけ**である。ハンドシェイク署名の検証（サーバが
/// その証明書の秘密鍵を実際に持っていることの証明）は標準の実装へそのまま委譲する——
/// ここを外すと、どこかで拾った証明書を提示するだけでピンを満たせてしまう。
///
/// 有効期限も見ない。ピンは「この1枚」という同一性の宣言であり、SSHの`known_hosts`と同じく
/// 期限の概念を持たない（期限切れの社内証明書を通すための機構でもある）。**期限を見ないことは
/// 承認プロンプトに明記される。**
#[derive(Debug)]
struct PinnedCertVerifier {
    pin: CertPin,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if CertPin::of_certificate(end_entity.as_ref()) == self.pin {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct PostOutcome {
    new_session: Option<String>,
    messages: Vec<String>,
}

async fn post_once(
    client: &reqwest::Client,
    config: &HttpConfig,
    body: &str,
    session_id: &Option<String>,
    protocol_version: &Arc<Mutex<Option<String>>>,
    diagnostics: &Arc<Mutex<String>>,
) -> Result<PostOutcome, McpError> {
    let mut request = client
        .post(config.endpoint.url())
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json");
    for (name, value) in &config.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(id) = session_id {
        request = request.header(HEADER_SESSION_ID, id.as_str());
    }
    // `initialize`より後の全リクエストへ付ける（`Transport::on_protocol_negotiated`）。
    if let Some(version) = protocol_version.lock().ok().and_then(|v| v.clone()) {
        request = request.header(HEADER_PROTOCOL_VERSION, version);
    }

    let response = request.body(body.to_string()).send().await.map_err(|e| {
        // 証明書検証の失敗はここに来る。診断へ残さないとユーザーに一切届かない。
        let why = describe_with_causes(&e);
        record(
            diagnostics,
            &format!("request to {} failed: {why}", config.endpoint.display()),
        );
        McpError::Io(format!("mcp http request failed: {why}"))
    })?;

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let new_session = response
        .headers()
        .get(HEADER_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    match classify_response(status, content_type.as_deref()) {
        ResponseKind::Accepted => Ok(PostOutcome {
            new_session,
            messages: Vec::new(),
        }),
        ResponseKind::Json => {
            let body = read_body_limited(response, diagnostics).await?;
            Ok(PostOutcome {
                new_session,
                messages: vec![body],
            })
        }
        ResponseKind::EventStream => {
            let messages = read_event_stream(response).await?;
            Ok(PostOutcome {
                new_session,
                messages,
            })
        }
        ResponseKind::Redirect => {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location header)")
                .to_string();
            record(
                diagnostics,
                &format!("HTTP {status} redirect to {location} (not followed)"),
            );
            Err(McpError::Protocol(format!(
                "the mcp endpoint answered with an HTTP {status} redirect to {location}. harness \
                 does not follow redirects: the approved declaration and the streamable-http \
                 allowlist both name {}, and following the redirect would talk to somewhere else. \
                 Point \"url\" at the final endpoint instead",
                config.endpoint.host()
            )))
        }
        ResponseKind::SessionExpired => {
            record(diagnostics, &format!("HTTP {status} (session expired)"));
            Err(McpError::Protocol(format!(
                "the mcp server at {} returned HTTP 404, which means the session is gone. harness \
                 does not silently re-initialize: that would re-run tools/list and could change \
                 the tool set you approved. Restart harness to start a fresh session",
                config.endpoint.display()
            )))
        }
        ResponseKind::Failed => {
            let body = read_body_limited(response, diagnostics)
                .await
                .unwrap_or_default();
            record(
                diagnostics,
                &format!(
                    "HTTP {status} ({}): {}",
                    content_type.as_deref().unwrap_or("no content-type"),
                    truncate(&body, 2000)
                ),
            );
            Err(McpError::Io(format!(
                "the mcp server at {} answered with HTTP {status}",
                config.endpoint.display()
            )))
        }
    }
}

async fn read_body_limited(
    mut response: reqwest::Response,
    diagnostics: &Arc<Mutex<String>>,
) -> Result<String, McpError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|e| {
            let why = describe_with_causes(&e);
            record(
                diagnostics,
                &format!("reading the response body failed: {why}"),
            );
            McpError::Io(format!("reading the mcp response body failed: {why}"))
        })?;
        let Some(chunk) = chunk else { break };
        if buf.len() + chunk.len() > DEFAULT_MAX_LINE_BYTES {
            return Err(McpError::Protocol(format!(
                "the mcp server sent more than {DEFAULT_MAX_LINE_BYTES} bytes in one response"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// SSE応答から、含まれているJSON-RPCメッセージを全部取り出す。
///
/// リクエストに対する応答としてのストリームなので、サーバは応答を書いたら閉じる。
/// 閉じるまで読み切ってから返す（`recv_line`側の締切はこの`await`に掛かっている）。
async fn read_event_stream(mut response: reqwest::Response) -> Result<Vec<String>, McpError> {
    let mut sse = SseAccumulator::new();
    let mut messages = Vec::new();
    let mut total = 0usize;
    loop {
        let chunk = response.chunk().await.map_err(|e| {
            McpError::Io(format!(
                "reading the mcp event stream failed: {}",
                describe_with_causes(&e)
            ))
        })?;
        let Some(chunk) = chunk else { break };
        total += chunk.len();
        if total > DEFAULT_MAX_LINE_BYTES {
            return Err(McpError::Protocol(format!(
                "the mcp server streamed more than {DEFAULT_MAX_LINE_BYTES} bytes in one response"
            )));
        }
        sse.push_bytes(&chunk);
        while let Some(message) = sse.take_message()? {
            messages.push(message);
        }
    }
    // 終端の空行を送らずに閉じるサーバでも最後の1件を落とさない。
    sse.finish();
    while let Some(message) = sse.take_message()? {
        messages.push(message);
    }
    Ok(messages)
}

/// エラーを原因の連鎖ごと1行にする。
///
/// **`reqwest::Error`の`Display`は原因を含まない。** 証明書検証の失敗はそのままだと
/// `error sending request for url (...)`にしかならず、CAの問題なのか到達性の問題なのかを
/// ユーザーが切り分けられない。実際の理由（`invalid peer certificate: UnknownIssuer`等）は
/// `source()`の先にあるので、そこまで辿って出す。
fn describe_with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    // 連鎖は数段で終わるが、循環した実装に備えて上限を置く。
    for _ in 0..8 {
        let Some(cause) = source else { break };
        let text = cause.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

fn record(diagnostics: &Arc<Mutex<String>>, line: &str) {
    let Ok(mut sink) = diagnostics.lock() else {
        return;
    };
    if sink.len() + line.len() > MAX_DIAGNOSTICS_BYTES {
        sink.clear();
    }
    sink.push_str(line);
    sink.push('\n');
}

fn truncate(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_string();
    }
    let mut cut = limit;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}... (truncated)", &s[..cut])
}

/// 本番の`Transport`実装を作るファクトリ（Streamable HTTP）。
pub struct HttpTransportFactory;

impl TransportFactory for HttpTransportFactory {
    fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
        let PreparedIsolation::Direct {
            endpoint,
            ca_bundle,
            tls_pin,
        } = &prepared.isolation
        else {
            return Err(McpError::Spawn {
                id: prepared.decl.id.clone(),
                reason: "this server was prepared for a sandboxed transport, not for streamable \
                         http"
                    .to_string(),
            });
        };

        // `${env:...}`はharness自身のenvから解決する（サーバ側の設定ではない）。
        let headers =
            expand_declared_headers(&prepared.decl.headers).map_err(|e| McpError::Spawn {
                id: prepared.decl.id.clone(),
                reason: e,
            })?;

        Ok(Box::new(HttpTransport::connect(HttpConfig {
            endpoint: endpoint.clone(),
            headers,
            ca_bundle: ca_bundle.clone(),
            tls_pin: tls_pin.clone(),
        })?))
    }
}

fn expand_declared_headers(
    headers: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    crate::http_wire::expand_headers(headers, &|name| std::env::var(name).ok())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_drained_and_bounded() {
        let sink = Arc::new(Mutex::new(String::new()));
        record(&sink, "HTTP 500");
        assert_eq!(*sink.lock().unwrap(), "HTTP 500\n");

        record(&sink, &"x".repeat(MAX_DIAGNOSTICS_BYTES));
        assert!(
            sink.lock().unwrap().len() <= MAX_DIAGNOSTICS_BYTES + 1,
            "the diagnostics buffer must not grow without bound"
        );
    }

    /// 未定義のenvを参照する宣言は、**接続する前に**失敗する。
    #[test]
    fn a_header_referencing_a_missing_environment_variable_fails_before_connecting() {
        let headers = [(
            "Authorization".to_string(),
            "Bearer ${env:HARNESS_TEST_DEFINITELY_UNSET_TOKEN}".to_string(),
        )]
        .into_iter()
        .collect();
        let err = expand_declared_headers(&headers).unwrap_err();
        assert!(err.contains("HARNESS_TEST_DEFINITELY_UNSET_TOKEN"), "{err}");
    }
}
