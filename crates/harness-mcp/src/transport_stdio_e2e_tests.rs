//! **製品のstdioトランスポートで起こしたMCPサーバが、Spawn Daemonの要求受付パイプへ
//! 到達できないこと**の実機E2E（`plans/DESIGN-MAC-DOMAIN.md` §22.2.2）。
//!
//! # なぜ`harness-sandbox`側の既存E2Eでは足りないのか
//!
//! `harness-sandbox`の`win_appcontainer::mcp_e2e_tests`はD-38（MCPサーバ隔離）を測っているが、
//! **`spawn`を直接呼んでいて製品のトランスポートを1行も通らない**。したがって
//! [`super::AppContainerTransportFactory`]が渡す[`SpawnRequestAccess`]が
//! `Withhold`から`Grant`へ化けても、あちらは1本も赤くならない。
//!
//! 同じ理由が`harness-sandbox`の`spawnd_e2e_tests`のP3にも当てはまる——あちらは
//! **電文の`DomainSpec`をテストが手で組む**ので、測っているのは「Daemon側のDACLが
//! capabilityで効くか」だけである。**製品のアダプタが実際に積んでいないか**は測れない。
//! ここがその対である（`B-35`）。
//!
//! # 測るのは「届かない」側だけではない
//!
//! 「届かなかった」は、DACLが拒んだとき以外にも成立する。
//!
//! | `last_error` | 意味 | この測定にとって |
//! |---|---|---|
//! | 5（アクセス拒否） | パイプのDACLが拒んだ | **これが測りたいもの** |
//! | 231（`ERROR_PIPE_BUSY`） | 受付インスタンスが空いていなかっただけ | 測れていない（混雑。`plans/handoff/mac-spawn-followup/T1.md`） |
//! | 2（見つからない） | パイプの名前ごと存在しない | 測れていない（Daemonが居ない／名前が違う） |
//!
//! だから`connected: false`では止めず、**理由まで見る**。
//!
//! # 測っていないもの
//!
//! - **`CHILD_PROCESS_RESTRICTED`下での挙動**。積むのは段階⑤。いまの`deny`は
//!   「窓口へ到達できない」だけで、**サーバ自身が直接子を作ることは止めていない**
//! - **`broker`が実際に子を作れること**。窓口の答えは常に`unknown_source_domain`である
//!   （遷移ポリシーの評価は段階E）。ここで測れるのは**宣言で窓口への到達が切り替わること**まで
//! - **Redirector DLLが実際に載ったこと**。注入の成否は`spawn_via_daemon`が
//!   `RedirectorInjection`として返すので、起動できた時点で「載った」は言えるが、
//!   **中で何のフックが設置されたか**はここからは見えない

use std::path::{Path, PathBuf};
use std::time::Duration;

use harness_sandbox::tier2a::session_profile::{begin_session, end_session};
use harness_sandbox::tier2a::spawnd::{ChildProcessPolicy, SharedSpawnDaemon, SpawnRequest};
use harness_sandbox::tier2a::win_appcontainer::revoke_session_grant;

use super::AppContainerTransportFactory;
use crate::decl::{
    McpNetworkDecl, McpProcessAccess, McpServerDecl, McpTransportKind, McpWorkspaceAccess,
};
use crate::runtime::TransportFactory;

/// プローブを置く使い捨てディレクトリ。**`Drop`で消す。**
///
/// # なぜテストバイナリの隣（`target\debug\deps`）をそのまま使わないのか
///
/// MCPのpreflight（`preflight_mcp_server`）は**実行ファイルの親ディレクトリ**へ
/// 継承つきの読取+実行ACEを撒く。`deps`を指すと、リポジトリのビルド生成物（数千ファイル）が
/// まるごとその対象になる。ここが1ファイルだけの専用ディレクトリなら、付けるACEも
/// 消すものも1つで済む。
///
/// # なぜ`%TEMP%`ではないのか
///
/// `%TEMP%`配下は刹那的なパスの巣で、このリポジトリの他のE2Eも避けている
/// （`crates/harness-policy-editor/tests/record_net_e2e.rs`の`ProbeDir`に経緯がある）。
/// 置き場を他のE2Eと揃えて`C:\harness-e2e\`配下にする。
struct ProbeDir(PathBuf);

impl ProbeDir {
    /// `tier2a_proc_probe.exe`をテストバイナリの隣から写して返す。
    ///
    /// 無ければ**skipせずpanicする**——ビルド手順漏れを黙って見逃すと、
    /// 「測っていない」が「測って問題なかった」に化ける。
    fn with_probe() -> (Self, PathBuf) {
        let source = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("current_exe has a parent")
            .join("tier2a_proc_probe.exe");
        assert!(
            source.exists(),
            "tier2a_proc_probe.exe not found at {} -- build and place it first:\n  \
             cargo build -p tier2a-proc-probe\n  \
             Copy-Item target\\debug\\tier2a_proc_probe.exe target\\debug\\deps\\ -Force\n\
             (see docs/DEV-ENVIRONMENT.md)",
            source.display()
        );

        let dir = PathBuf::from(r"C:\harness-e2e").join(format!(
            "mcp-spawn-reach-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!(
                "could not create the probe directory {} ({e}). This test needs a place outside \
                 the repository and outside %TEMP% because the MCP preflight grants an \
                 inheritable ACE on the executable's parent directory",
                dir.display()
            )
        });
        let probe = dir.join("tier2a_proc_probe.exe");
        std::fs::copy(&source, &probe).unwrap_or_else(|e| {
            panic!(
                "could not copy the probe to {} ({e}); a previous run may still be holding it",
                probe.display()
            )
        });
        (Self(dir), probe)
    }
}

impl Drop for ProbeDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!(
                "warning: could not remove the probe directory {} ({e}); remove it by hand",
                self.0.display()
            );
        }
    }
}

/// 子が出した行を、プロセスが終わるまで読み切って1つの文字列にする。
///
/// [`crate::transport::Transport`]は1行ずつしか返さないので、**終わりまで回すのは
/// 呼び出し側の仕事**である。プローブは最後にJSONを1行印字して終了するため、
/// 「閉じるまで読む」が正しい終わり方になる。
/// **抜ける条件は`Err`である**——`Io`なら子が終わってパイプが閉じた（正常な終わり方）、
/// `Timeout`なら出力が止まった。どちらもここでは同じ「もう来ない」なので区別しない。
fn read_until_closed(transport: &mut dyn crate::transport::Transport) -> String {
    let mut out = String::new();
    while let Ok(line) = transport.recv_line(Duration::from_secs(30)) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// 子のstdoutに流れた**最後のJSON行**を採る。
///
/// プローブは1行のJSONを出す約束だが、前置きが混ざり得る（`B-33`。`harness-sandbox`の
/// `last_json_line`と同じ作法だが、あちらは`#[cfg(test)]`のクレート内部関数なので
/// ここからは参照できない）。
fn last_json_line(stdout: &str) -> Option<serde_json::Value> {
    stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line.trim()).ok())
}

/// 要求受付パイプへ送る本物の要求電文。
///
/// **手書きのJSON文字列にしない。** 型から起こせば、電文の綴りが変わったときに
/// ここがコンパイルエラーになる（`spawnd_e2e_tests::spawn_request_payload`と同じ理由）。
fn spawn_request_payload() -> String {
    serde_json::to_string(&SpawnRequest::Spawn {
        // [段階6f-1] **絶対パスで書く。** 相対パスは`MalformedRequest`で早期に断られるので、
        // このテストが見たい「窓口へ届いたか」の答えが変わってしまう。
        image: r"C:\Program Files\Git\cmd\git.exe".to_string(),
        command_line: "\"git.exe\" status".to_string(),
        cwd: "C:/".to_string(),
        env: None,
        handles: Default::default(),
        console: harness_sandbox::tier2a::spawnd::ConsoleNeed::NotNeeded,
        suspended: false,
    })
    .expect("serialize the spawn request")
}

fn probe_decl(
    probe: &Path,
    request_pipe: &str,
    payload: &str,
    process: McpProcessAccess,
) -> McpServerDecl {
    McpServerDecl {
        id: "e2e-spawn-reach".to_string(),
        transport: McpTransportKind::Stdio,
        command: probe.to_string_lossy().into_owned(),
        args: vec![
            "--pipe-client".to_string(),
            request_pipe.to_string(),
            "--pipe-payload".to_string(),
            payload.to_string(),
        ],
        env: Default::default(),
        url: String::new(),
        headers: Default::default(),
        tls_pin: None,
        tools: Default::default(),
        // networkを要求しない＝capability空。**この測定に外向き通信は要らない**ので、
        // 専用プロキシもWFPも立てずに済む。
        network: McpNetworkDecl::default(),
        // §3.2の既定。workspaceへのACEを一切付けない。
        workspace: McpWorkspaceAccess::None,
        process,
    }
}

/// 宣言の`process`を1つ与えて製品の2段を実際に通し、プローブが出したJSONを返す。
///
/// 通るのは製品の起動2段そのものである——[`crate::sandbox::prepare`]（専用プロファイルの
/// 作成と最小ACE）→ [`super::AppContainerTransportFactory::create`]（`spawn_via_daemon`）。
///
/// **`process`以外は2本の呼び出しで同じにする。** 違いが1つだけだから、
/// 結果の違いを宣言に帰せる（違いが2つあると、どちらが効いたのか言えない）。
fn probe_report_for(process: McpProcessAccess, label: &str) -> serde_json::Value {
    // MCPプロファイルはセッションエントリの子としてぶら下がる（D-38）。撤収も同じ経路。
    begin_session().expect("begin session");
    let (_probe_dir, probe) = ProbeDir::with_probe();
    // workspaceは使わない（`workspace: None`）が、`prepare`の引数として要る。
    let workspace = tempfile::tempdir().expect("workspace");

    let daemon = SharedSpawnDaemon::start(
        harness_sandbox::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("the spawn daemon must start");
    eprintln!(
        "[{label}] daemon pid={} request_pipe={}",
        daemon.daemon_pid(),
        daemon.request_pipe()
    );

    let payload = spawn_request_payload();
    let decl = probe_decl(&probe, daemon.request_pipe(), &payload, process);
    let prepared = crate::sandbox::prepare(&decl, workspace.path()).expect("mcp preflight");
    // **`\\.\pipe\`についての警告が1件出るのは想定どおりである**（追いかけないこと）。
    //
    // `sandbox::prepare`の`existing_arg_paths`は「絶対パスで、実在するもの」を引数から拾う。
    // 名前付きパイプは`Path::exists`が真になるので、`--pipe-client`へ渡した窓口の名前が
    // パスとして拾われ、`read_exec_roots`がその親（＝パイプ名前空間の根`\\.\pipe\`）を
    // 付与先の候補にする。`is_force_grant_forbidden`が`canonicalize`に失敗して断るので
    // 実害は無いが、**断っている理由は「パイプ名前空間だから」ではない**。
    // この観察は`plans/handoff/mac-spawn-followup/T2.md`へ本流向けの副産物として書いてある。
    for warning in &prepared.warnings {
        eprintln!("[{label}] preflight warning: {warning}");
    }

    let factory = AppContainerTransportFactory::with_spawn_daemon(daemon.clone());
    let mut transport = factory
        .create(&prepared.prepared)
        .expect("the product stdio transport must start the probe");
    let stdout = read_until_closed(transport.as_mut());
    let stderr = transport.take_stderr();
    transport.shutdown();
    eprintln!("[{label}] stdout={stdout}\nstderr={stderr}");

    // 後始末は**判定より前に**行う（assertで落ちてもプロファイルとACEを残さない）。
    daemon.shutdown();
    let reclaimed = end_session(&revoke_session_grant);
    eprintln!("[{label}] reclaim={reclaimed:?}");

    let report = last_json_line(&stdout).unwrap_or_else(|| {
        panic!(
            "the probe printed no JSON report. It never ran, or its output never reached us -- \
             either way nothing was measured, so this is not evidence of a denial.\n\
             stdout={stdout}\nstderr={stderr}"
        )
    });

    // **自分の的を確かめる。** ここがずれていたら、以下の結論は何も支えていない。
    assert_eq!(
        report.get("pipe").and_then(|v| v.as_str()),
        Some(daemon.request_pipe()),
        "the probe aimed at a different pipe than the daemon's request pipe: {report}"
    );
    assert!(
        report
            .get("attempt_count")
            .and_then(|v| v.as_u64())
            .is_some_and(|n| n >= 1),
        "the probe reported no connection attempt at all; the instrument did not run: {report}"
    );
    report
}

/// **`process: deny`（既定）のMCPサーバは、要求受付パイプへ到達できない**
/// （§22.2.2の「ポリシーで断る」より手前に置かれた二重目のdeny）。
///
/// # 歯があることの確かめ方
///
/// 下の`..._may_reach_the_request_pipe`と**対**である。`transport_stdio.rs`の
/// `match decl.process`を片側へ潰すと、必ずどちらかが赤くなる。
#[test]
#[ignore = "starts a real spawn daemon and an AppContainer child; run through e2e-mcp-spawn-reach"]
fn an_mcp_server_that_declares_process_deny_cannot_reach_the_request_pipe() {
    let report = probe_report_for(McpProcessAccess::Deny, "mcp-spawn-reach/deny");

    assert_eq!(
        report.get("connected").and_then(|v| v.as_bool()),
        Some(false),
        "an MCP server reached the spawn request pipe. §22.2.2 defines the `process` declaration's \
         default as `deny`, and its meaning as 'no spawn-request capability = cannot even reach \
         the pipe'. Check that transport_stdio.rs still passes SpawnRequestAccess::Withhold: \
         {report}"
    );
    // **「届かなかった」だけでは足りない。理由まで見る**（モジュールdocの表）。
    assert_eq!(
        report.get("last_error").and_then(|v| v.as_u64()),
        Some(5),
        "the child failed to reach the pipe for some reason other than access denied (5). \
         231 means the pipe was merely busy and 2 means the name did not exist -- in both cases \
         the DACL's effect was not measured: {report}"
    );
}

/// **`process: broker`を宣言したMCPサーバは、要求受付パイプへ届く**（§22.2.2）。
///
/// # これは「子プロセスを作れる」ことの確認ではない
///
/// 届いた先で返るのは`unknown_source_domain`——「あなたが誰かは分かったが、
/// そのドメインは`policy.json`に宣言されていない」という断りである
/// （MCPサーバの遷移元ドメイン名は宣言idで、このテストは宣言を書かない）。**宣言で
/// 切り替わるのは窓口へ話しかけられるかどうかだけ**で、実際に何かが起こせるように
/// なったわけではない。
///
/// # 上のdeny側との対で1つの主張になる（`B-35`）
///
/// 片側だけだと、**常に届く実装**でも**常に届かない実装**でも片方は緑になる。
/// 2本の違いは宣言の`process`ただ1つなので、結果の違いはそこに帰せる。
#[test]
#[ignore = "starts a real spawn daemon and an AppContainer child; run through e2e-mcp-spawn-reach"]
fn an_mcp_server_that_declares_process_broker_may_reach_the_request_pipe() {
    let report = probe_report_for(McpProcessAccess::Broker, "mcp-spawn-reach/broker");

    assert_eq!(
        report.get("connected").and_then(|v| v.as_bool()),
        Some(true),
        "an MCP server that declared `process: broker` still could not reach the spawn request \
         pipe. Check that transport_stdio.rs maps Broker to SpawnRequestAccess::Grant, and that \
         the spawn-request capability is actually on the child's token: {report}"
    );
    // **届いただけでは足りない。窓口が何と答えたかまで見る。**
    // ここが`not_registered`なら、Process Table（Daemonが持つ生成済みプロセスの台帳）への
    // 登録がResumeより後になっている＝別の欠陥である（§12）。
    let reply = report.get("reply").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        reply.contains("unknown_source_domain"),
        "the request pipe answered something other than `unknown_source_domain`. \
         `not_registered` would mean the child was not in the daemon's process table, which is a \
         different defect than the one this test is about: reply={reply:?} report={report}"
    );
}
