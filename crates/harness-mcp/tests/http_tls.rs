//! **D-51の受け入れテスト**: Streamable HTTPのサーバ証明書検証は無効化できない。
//!
//! 設定・CLI・宣言のどこにも「検証しない」を選ぶ手段が無い、というのは実装を読めば分かるが、
//! **それが実際に効いているか**は繋いでみないと分からない。ここは自己署名証明書のTLS終端へ
//! 繋いで失敗することを確かめる。
//!
//! ## 対照を組で置く理由
//!
//! 「失敗した」だけでは、証明書を拒否したのか単に何も繋がっていないのかを区別できない。
//! したがって**同じ証明書をCAとして信頼させた場合に成功する**ことを並べて置く
//! （`mcp_e2e_tests`の隔離E2Eが「拒否」と「許可したら読める」を組にしているのと同じ）。
//!
//! ## TLS終端をテスト側に置く理由
//!
//! モックサーバ（`src/bin/mcp-mock-http-server.rs`）は平文しか喋らない。ここでは
//! その前段にrustlsの終端を1枚立てて素通しさせる——MCPの応答ロジックを2つ持つと、
//! 片方だけ直す事故が起きる（`docs/CODE-STRUCTURE-RULES.md` 規則5）。

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use harness_mcp::decl::McpServerDecl;
use harness_mcp::http_wire::EndpointGates;
use harness_mcp::runtime::{McpGates, McpRuntime, SkippedServer};
use harness_mcp::transport_http::HttpTransportFactory;

use support::{decl, MockServer};

/// 自己署名CAと、それが署名した`127.0.0.1`向けのサーバ証明書。
struct TestCa {
    ca_pem: String,
    server_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn issue_certificates() -> TestCa {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "harness mcp test ca");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed ca");

    // 接続先は`https://127.0.0.1:<port>/mcp`なので、SANはIPで入れる。
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    server_params.subject_alt_names =
        vec![SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))];
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .expect("sign the server certificate");

    TestCa {
        ca_pem: ca.pem(),
        server_chain: vec![server_cert.der().clone(), ca.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
    }
}

// ===== 中継の足跡（残課題#53の計測用） =====
//
// **`relay_one`の失敗は、かつて1件も記録されなかった**（戻り値を`let _ =`で捨てていた）。
// TLS受け入れに残る1%の揺らぎは「繋がった後のやり取りが途中で切れる」形なので、
// **どの区間で切れたか**を数えられないと原因に届かない。
//
// 足跡は2段構えにしてある。
//
// | どこへ | いつ | 何のため |
// |---|---|---|
// | stderr | 中継が失敗したときだけ | **無言失敗をやめる**。1回の`cargo test`でも区間が見える |
// | `HARNESS_TLS_FRONT_TRACE`が指すファイル | 全中継（開始と終了の2行） | 1000回ぶんを機械集計する |
//
// **開始と終了を別の行にするのが要である。** 終了行が無い中継＝**戻ってこなかった中継**で、
// 「落ちた」と「固まった」はそれでしか区別できない（BUG-159の計器が1回ごとに時間切れを
// 付けているのと同じ理由）。

/// 中継1本が**どの区間まで進んだか**。`relay_one`の各`?`に1つずつ対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayStage {
    /// ① TLSの接続を作る
    TlsNew,
    /// ① ハンドシェイクを回し切る（②の読み取りと混ざらないよう明示的に分ける）
    TlsHandshake,
    /// ② 要求を読み切る
    ReadRequest,
    /// ③ 上流へ接続する
    UpstreamConnect,
    /// ③ 上流へ要求を流す
    UpstreamWrite,
    /// ③ 上流の応答をEOFまで読む
    UpstreamRead,
    /// ④ 応答をTLSへ書き戻す
    WriteResponse,
    /// ④ 書き戻しをflushする
    FlushResponse,
}

impl RelayStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::TlsNew => "1-tls-new",
            Self::TlsHandshake => "1-tls-handshake",
            Self::ReadRequest => "2-read-request",
            Self::UpstreamConnect => "3-upstream-connect",
            Self::UpstreamWrite => "3-upstream-write",
            Self::UpstreamRead => "3-upstream-read",
            Self::WriteResponse => "4-write-response",
            Self::FlushResponse => "4-flush-response",
        }
    }
}

/// 失敗した区間と、その場のエラー。
struct RelayFailure {
    stage: RelayStage,
    error: String,
}

fn at(stage: RelayStage) -> impl Fn(std::io::Error) -> RelayFailure {
    move |e| RelayFailure {
        stage,
        error: format!("{e} (kind={:?}, os={:?})", e.kind(), e.raw_os_error()),
    }
}

/// 中継に通し番号を振る（開始行と終了行を突き合わせるため）。
static RELAY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

/// 足跡を1行追記する。**環境変数が無ければ何もしない**（通常の`cargo test`を汚さない）。
fn trace(line: &str) {
    let Ok(path) = std::env::var("HARNESS_TLS_FRONT_TRACE") else {
        return;
    };
    // **1行を1回の`write`で出す。** `writeln!`は書式ごとに`write`を呼ぶので、
    // 同時に走る中継スレッドの行が途中で混ざる（実際に混ざった）。
    let record = format!("{} pid={} {line}\n", now_millis(), std::process::id());
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(record.as_bytes());
    }
}

/// いま自分が属しているテストの名前（libtestがスレッド名に入れる）。
fn current_test() -> String {
    std::thread::current()
        .name()
        .unwrap_or("(unnamed)")
        .to_string()
}

/// 平文モックの前に立つTLS終端。dropで待受を畳む。
struct TlsFront {
    addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// まだ戻ってきていない中継の本数（dropの時点で0でない＝テストが中継を追い越した）。
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

impl TlsFront {
    fn start(ca: &TestCa, upstream: SocketAddr) -> Self {
        // 明示的にproviderを渡す（プロセス既定の暗号プロバイダに依存しない。reqwest側が
        // 何を入れていても、この終端の構成は決定的になる）。
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(ca.server_chain.clone(), ca.server_key.clone_key())
            .expect("server config");
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the tls front");
        let addr = listener.local_addr().expect("local addr");
        // **待受は非ブロッキングで回す**（2026-09-18に直した。下の[`TlsFront::drop`]のdoc）。
        listener
            .set_nonblocking(true)
            .expect("pollable accept loop");

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = shutdown.clone();
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = in_flight.clone();
        let test = current_test();
        trace(&format!("front-start test={test} addr={addr}"));
        let thread = std::thread::spawn(move || {
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        // **受け取った接続はブロッキングへ戻す。** Windowsでは待受の性質を
                        // 継ぐことがあり、継いだままだと`relay_one`の読み書きが
                        // `WouldBlock`で即座に落ちる。
                        let _ = stream.set_nonblocking(false);
                        let config = config.clone();
                        let test = test.clone();
                        let counter = counter.clone();
                        // 1接続1スレッド。テスト用なので同時接続数は高々数本。
                        std::thread::spawn(move || {
                            let id = RELAY_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            trace(&format!("relay-begin id={id} test={test}"));
                            let started = std::time::Instant::now();
                            let outcome = relay_one(stream, config, upstream);
                            let ms = started.elapsed().as_millis();
                            match outcome {
                                Ok(seen) => trace(&format!(
                                    "relay-end id={id} test={test} stage=ok ms={ms} {seen}"
                                )),
                                Err(failure) => {
                                    // **失敗を捨てない。** 環境変数が無くても区間は見える。
                                    // ただし**ハンドシェイクの失敗は正常な結果**である——
                                    // 拒否側のテスト4本は、クライアントが証明書を拒んで
                                    // 警告を送るところまでが期待動作なので、ここで鳴らすと
                                    // 毎回鳴る見張りになる。
                                    if failure.stage != RelayStage::TlsHandshake {
                                        eprintln!(
                                            "tls front relay failed in {} ({test}): {}",
                                            failure.stage.as_str(),
                                            failure.error
                                        );
                                    }
                                    trace(&format!(
                                        "relay-end id={id} test={test} stage={} ms={ms} err={:?}",
                                        failure.stage.as_str(),
                                        failure.error
                                    ));
                                }
                            }
                            counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    // 1接続の失敗で待受を畳まない（次の接続は成立し得る）。
                    Err(_) => {}
                }
            }
        });

        Self {
            addr,
            shutdown,
            thread: Some(thread),
            in_flight,
        }
    }

    fn url(&self) -> String {
        format!("https://{}/mcp", self.addr)
    }
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        // 畳む瞬間に走っている中継の本数を残す。**テストが中継を追い越して終わった**ことは、
        // 失敗した区間だけを見ても分からない（そのとき中継は終了行を書かずに消える）。
        trace(&format!(
            "front-stop test={} addr={} in_flight={}",
            current_test(),
            self.addr,
            self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
        ));
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// # なぜ「起こすためのダミー接続」をやめたのか（2026-09-18に測って直した）
//
// かつてここは**待受をブロッキングで回し、畳むときにダミーの接続を1本張って
// `accept`を起こす**形だった。**その起こし方は取りこぼす。**
//
// ダミーの接続は張った直後に閉じる（`let _ =`で即drop）。待受スレッドがその瞬間
// `accept`の中に居なければ、接続はバックログに積まれ、**閉じられた接続はWindowsでは
// キューから消えることがある**。消えると`accept`は永久に起きず、`join`が返らない
// ——テストが1本、赤にもならずに**固まる**。
//
// **測った**（`tools/tls-flake-loop.sh`、このテストバイナリを1000回）:
//
// | 直す前 | 通る980 / 落ちる11 / **固まる9** |
// |---|---|
//
// 固まったのは毎回違うテストで（9回で5種類）、テスト個別ではなく**この畳み方**の問題である。
// 直した形は**起こす必要が無い**——待受を非ブロッキングにして2msごとに旗を見るので、
// 畳むのは旗1つで決まる（取りこぼす相手が居ない）。
//
// **費用は問題にならない**: 2msの周期はテストの所要（1回0.1秒）に対して無視できる。

/// TLSを剥がして平文モックへ中継し、応答をそのまま返す。
///
/// モックは常に`Content-Length`を付けて`Connection: close`で閉じるので、
/// 「リクエストを読み切る→上流へ流す→EOFまで読む→返す」で足りる。
///
/// 成功したときは足跡へ載せる要約（どのJSON-RPCメソッドを何バイト中継したか）を返す。
/// 失敗したときは**どの区間で切れたか**を返す——`?`で捨てると、残った揺らぎの原因が
/// どの区間にあるのかを数える手段が無くなる。
fn relay_one(
    tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    upstream: SocketAddr,
) -> Result<String, RelayFailure> {
    let connection = rustls::ServerConnection::new(config).map_err(|e| RelayFailure {
        stage: RelayStage::TlsNew,
        error: e.to_string(),
    })?;
    let mut tls = rustls::StreamOwned::new(connection, tcp);
    // ハンドシェイクを明示的に回し切る。`read`に任せると①の失敗が②に化ける。
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(at(RelayStage::TlsHandshake))?;
    }

    let request = read_http_message(&mut tls).map_err(at(RelayStage::ReadRequest))?;
    if request.is_empty() {
        // 証明書の下見（`cert_probe`）はハンドシェイクだけして閉じる。正常な終わり方。
        return Ok("rpc=(handshake-only) req=0 resp=0".to_string());
    }

    let mut up = TcpStream::connect(upstream).map_err(at(RelayStage::UpstreamConnect))?;
    up.write_all(&request).map_err(at(RelayStage::UpstreamWrite))?;
    up.flush().map_err(at(RelayStage::UpstreamWrite))?;
    let mut response = Vec::new();
    up.read_to_end(&mut response)
        .map_err(at(RelayStage::UpstreamRead))?;

    tls.write_all(&response)
        .map_err(at(RelayStage::WriteResponse))?;
    tls.flush().map_err(at(RelayStage::FlushResponse))?;
    Ok(format!(
        "rpc={} req={} resp={}",
        rpc_method(&request),
        request.len(),
        response.len()
    ))
}

/// 中継した本文からJSON-RPCの`method`を拾う（足跡用。**どの往復で切れたか**を見るため）。
fn rpc_method(request: &[u8]) -> String {
    let body = String::from_utf8_lossy(request);
    let Some(rest) = body.split("\"method\":").nth(1) else {
        return "(none)".to_string();
    };
    let rest = rest.trim_start().trim_start_matches('"');
    match rest.find('"') {
        Some(end) => rest[..end].to_string(),
        None => "(unparsed)".to_string(),
    }
}

/// ヘッダ＋`Content-Length`分の本文を読み切る（HTTP/1.1の最小実装）。
///
/// **読み切る前に相手が閉じたら、途中まで読んだものを返さずエラーにする。** 上流のモックは
/// 1接続ずつ順に捌く単線なので、**中途半端な要求を渡すと`read_exact`で永久に待ち続け、
/// そのテストの残り全部が黙って止まる**——足跡の上では区間②の失敗が消え、区間③の
/// 「戻ってこない中継」だけが残るので、どこで切れたのかを数えられなくなる。
/// 1バイトも来ないまま閉じたとき（証明書の下見）は正常なので空を返す。
fn read_http_message(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            if buf.is_empty() {
                return Ok(buf);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("the client closed after {} bytes of a partial request", buf.len()),
            ));
        }
        buf.extend_from_slice(&chunk[..read]);

        let Some(head_end) = find_subsequence(&buf, b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if buf.len() >= head_end + 4 + length {
            return Ok(buf);
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn start(decl: McpServerDecl, gates: &McpGates) -> (McpRuntime, Vec<SkippedServer>) {
    let prepared = McpRuntime::prepare_http(&decl, gates).expect("prepare");
    let mut skipped = Vec::new();
    let runtime = McpRuntime::start(vec![prepared], &HttpTransportFactory, "0.1.0", &mut skipped);
    (runtime, skipped)
}

fn gates_with_ca(ca_bundle: Option<std::path::PathBuf>) -> McpGates {
    McpGates {
        streamable_http_enabled: true,
        // 接続先はloopbackなのでallowlistは免除される（D-49）。ここで測るのはTLSだけ。
        http_endpoints: EndpointGates::default(),
        http_ca_bundle: ca_bundle,
    }
}

/// **D-51**: 信頼されていない証明書のサーバへは接続しない。
#[test]
fn an_untrusted_server_certificate_aborts_the_connection() {
    let ca = issue_certificates();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&ca, mock.addr());

    let (runtime, skipped) = start(decl(&front.url(), &[]), &gates_with_ca(None));

    assert!(
        runtime.tools().is_empty(),
        "a server whose certificate does not verify must not contribute tools"
    );
    assert_eq!(skipped.len(), 1);
    let message = skipped[0].message();
    // 失敗の**理由**がユーザーへ届く（届かないと「応答しません」だけになり、CAの問題なのか
    // 到達性の問題なのかを切り分けられない）。`reqwest::Error`のDisplayは原因を含まないので、
    // トランスポート側で`source()`を辿っている（`transport_http::describe_with_causes`）。
    let lower = message.to_ascii_lowercase();
    assert!(
        lower.contains("certificate"),
        "the failure must name the certificate as the cause: {message}"
    );
    assert!(
        lower.contains("unknownissuer") || lower.contains("unknown issuer"),
        "and it must say the issuer is untrusted, not just that something was wrong: {message}"
    );
}

/// **対照**: 同じ証明書を信頼させれば、同じサーバと普通に往復できる。
///
/// 上のテストの失敗が「そもそも何も繋がっていない」ことの副作用ではない、と示すためのもの。
/// 併せて、私有CAを持つ組織向けの逃げ道（`mcp.http_ca_bundle`）が実際に働くことも確かめる。
#[test]
fn the_same_server_works_once_its_ca_is_trusted() {
    let ca = issue_certificates();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&ca, mock.addr());

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.ca_pem).unwrap();

    let (runtime, skipped) = start(decl(&front.url(), &[]), &gates_with_ca(Some(ca_path)));

    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(
        runtime.tools().len(),
        3,
        "the handshake must complete over TLS once the ca is trusted"
    );
}

/// 読めない・壊れたCAバンドルは、**黙って検証を緩めずに**起動を止める。
#[test]
fn an_unreadable_ca_bundle_fails_closed() {
    let mock = MockServer::start("json");
    let (runtime, skipped) = start(
        decl(&mock.url(), &[]),
        &gates_with_ca(Some(std::path::PathBuf::from(
            "C:/definitely/missing/ca.pem",
        ))),
    );
    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].message().contains("ca bundle"),
        "{:?}",
        skipped[0]
    );
}

/// **いわゆる「オレオレ証明書」**（CAを介さない自己署名のリーフ証明書）も、`http_ca_bundle`へ
/// 置けば信頼できる。私有CAを立てられない小規模な社内サーバのための経路。
///
/// 上の`the_same_server_works_once_its_ca_is_trusted`が確かめているのは「私有**CA**を信頼させる」
/// 側で、こちらは「サーバ証明書そのものを信頼させる」側。実運用で問い合わせが来るのは
/// たいていこちらなので、別ケースとして固定する。
#[test]
fn a_self_signed_leaf_certificate_can_be_trusted_via_the_ca_bundle() {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    params.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]))];
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let bundle = TestCa {
        ca_pem: cert.pem(),
        // チェーンはこの1枚だけ（間にCAが居ない）。
        server_chain: vec![cert.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    };

    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("self-signed.pem");
    std::fs::write(&ca_path, &bundle.ca_pem).unwrap();

    let (runtime, skipped) = start(decl(&front.url(), &[]), &gates_with_ca(Some(ca_path)));
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}

/// **信頼した発行者の証明書でも、別のホスト向けなら拒否する。**
///
/// `http_ca_bundle`は「この発行者を信じる」だけで、「何にでも繋いでよい」ではない。ここが
/// 通ってしまうと、私有CAを1つ信頼させた時点でそのCAが署名した任意の証明書で
/// なりすませることになり、D-49の宛先allowlistもTLSも意味を失う。
#[test]
fn a_certificate_issued_for_another_host_is_rejected_even_from_a_trusted_ca() {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "harness mcp test ca");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca");

    // 接続先は127.0.0.1だが、証明書は別のホスト向け。
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "somewhere.else.example");
    server_params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::from([203, 0, 113, 9])),
        SanType::DnsName("somewhere.else.example".try_into().unwrap()),
    ];
    let server_key = KeyPair::generate().expect("server key");
    let server_cert = server_params.signed_by(&server_key, &ca).expect("sign");

    let bundle = TestCa {
        ca_pem: ca.pem(),
        server_chain: vec![server_cert.der().clone(), ca.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
    };

    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &bundle.ca_pem).unwrap();

    let (runtime, skipped) = start(decl(&front.url(), &[]), &gates_with_ca(Some(ca_path)));

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0].message().contains("NotValidForName"),
        "the name check must be the stated reason: {}",
        skipped[0].message()
    );
}

// ===== D-52: 証明書ピン =====

/// 自己署名リーフと、その`tls_pin`用文字列を返す。
fn self_signed_with_pin() -> (TestCa, String) {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "mcp.corp.internal");
    // **接続先の名前とは合っていない**（社内のオレオレ証明書にありがちな形）。
    // ピンはこれでも通す＝名前検証を置き換えていることの証拠になる。
    params.subject_alt_names = vec![SanType::DnsName("mcp.corp.internal".try_into().unwrap())];
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let pin = harness_mcp::CertPin::of_certificate(cert.der()).to_declaration_string();
    let bundle = TestCa {
        ca_pem: cert.pem(),
        server_chain: vec![cert.der().clone()],
        server_key: rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    };
    (bundle, pin)
}

fn pinned_decl(url: &str, pin: Option<&str>) -> McpServerDecl {
    let mut d = decl(url, &[]);
    d.tls_pin = pin.map(str::to_string);
    d
}

/// **D-52の中核**: ピンが一致すれば、CAも OS証明書ストアも使わずに接続できる。
///
/// 証明書は自己署名で、しかも`CN`/SANは接続先（`127.0.0.1`）と**合っていない**。通常の検証なら
/// 2重に落ちるものが、ピン1つで通る——これが「社内のオレオレ証明書をそのまま使う」経路である。
#[test]
fn a_matching_pin_connects_without_any_ca_and_without_a_matching_name() {
    let (bundle, pin) = self_signed_with_pin();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());

    let decl = pinned_decl(&front.url(), Some(&pin));
    assert_eq!(decl.validate(), Ok(()));

    // `ca_bundle`は**渡さない**（ピンだけで通ることを示すため）。
    let (runtime, skipped) = start(decl, &gates_with_ca(None));
    assert!(skipped.is_empty(), "{skipped:?}");
    assert_eq!(runtime.tools().len(), 3);
}

/// ピンが一致しなければ接続しない。**ピンは検証を緩めるのではなく、別の検証に置き換える。**
#[test]
fn a_mismatched_pin_refuses_the_connection() {
    let (bundle, _real_pin) = self_signed_with_pin();
    let (_other, other_pin) = self_signed_with_pin();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());

    let (runtime, skipped) = start(
        pinned_decl(&front.url(), Some(&other_pin)),
        &gates_with_ca(None),
    );

    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0]
            .message()
            .to_ascii_lowercase()
            .contains("certificate"),
        "{}",
        skipped[0].message()
    );
}

/// ピンが**無い**同じサーバは、これまで通り拒否される（ピンを足したことで既定が緩んでいない）。
#[test]
fn the_same_server_without_a_pin_is_still_rejected() {
    let (bundle, _pin) = self_signed_with_pin();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());

    let (runtime, skipped) = start(pinned_decl(&front.url(), None), &gates_with_ca(None));
    assert!(runtime.tools().is_empty());
    assert_eq!(skipped.len(), 1);
}

/// 承認の前に、**実際に提示された証明書**を読み出せる（`harness mcp approve`がこれを見せる）。
/// 指紋・発行元・サブジェクトの3点が揃うことが要件。
#[test]
fn the_presented_certificate_can_be_inspected_before_approving() {
    let (bundle, pin) = self_signed_with_pin();
    let mock = MockServer::start("json");
    let front = TlsFront::start(&bundle, mock.addr());

    let parsed = harness_mcp::http_wire::parse_endpoint_url(&front.url()).unwrap();
    let presented = harness_mcp::cert_probe::probe(&parsed)
        .expect("probe")
        .expect("an https endpoint must present a certificate");

    // 宣言へ書くべきピンが、そのまま得られる。
    assert_eq!(presented.pin.to_declaration_string(), pin);
    assert!(presented.self_signed, "{presented:?}");
    assert!(
        presented.subject.contains("mcp.corp.internal"),
        "{presented:?}"
    );
    assert_eq!(presented.issuer, presented.subject);
    assert_eq!(
        presented.subject_alt_names,
        vec!["mcp.corp.internal".to_string()]
    );

    let described = presented.describe();
    for expected in ["subject:", "issuer:", "names:", "valid:", "sha256:"] {
        assert!(described.contains(expected), "{described}");
    }
    assert!(described.contains("(self-signed)"), "{described}");
}
