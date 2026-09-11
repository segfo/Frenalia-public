//! stdioトランスポート（§6.1、Windows専用）。AppContainerの箱の中で動くMCPサーバと、
//! 改行区切りJSONで往復する。
//!
//! `DESIGN-MCP.md` §6.1が言う「サーバの外向き通信がWFPと協調プロキシのallowlistに載る」のは
//! この経路だけである。Streamable HTTP（§6.2）ではharness本体が喋るため、AppContainerの外に
//! 出てしまい同じ統制が効かない。
//!
//! ## networkの与え方
//!
//! - 宣言にnetwork要求が無い → `NetworkCapability::Deny`（capability空）。ソケットを1つも作れない
//! - 要求がある → `InternetClient` capability ＋ **そのサーバ専用プロキシのアドレスをenvへ注入**。
//!   WFPはこのサーバのpackage SIDに対しそのプロキシのポートだけを許可しているので、
//!   envを無視して直接外へ出ようとしても落ちる（協調ではなく強制、§3.2）
//!
//! `proxy_addr`が`None`なのにnetworkを要求している宣言は**起動しない**。「プロキシが立たなかった
//! ので素通しで起動する」は、統制が無い状態を静かに作ることになるため（P-05のfail-closed）。

use std::time::{Duration, Instant};

use harness_sandbox::tier2a::spawnd::ConsoleNeed;
use harness_sandbox::tier2a::win_appcontainer::{
    spawn_via_daemon, AppContainerSession, DomainIdentity, NetworkCapability, RedirectorInject,
    SessionError, SpawnRequestAccess,
};

use crate::decl::McpProcessAccess;
use crate::runtime::{PreparedIsolation, PreparedServer, TransportFactory};
use crate::transport::{LineAccumulator, Transport};
use crate::McpError;

/// AppContainer子プロセスとのstdio往復。
pub struct AppContainerStdioTransport {
    session: AppContainerSession,
    lines: LineAccumulator,
}

impl Transport for AppContainerStdioTransport {
    fn send_line(&mut self, line: &str) -> Result<(), McpError> {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        self.session.write_all(&bytes).map_err(session_error)
    }

    fn recv_line(&mut self, timeout: Duration) -> Result<String, McpError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.lines.take_line()? {
                return Ok(line);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(McpError::Timeout(
                    "no complete message arrived from the mcp server".to_string(),
                ));
            }
            let chunk = self.session.read_some(remaining).map_err(session_error)?;
            self.lines.push_bytes(&chunk);
        }
    }

    fn take_stderr(&mut self) -> String {
        self.session.take_stderr()
    }

    fn shutdown(&mut self) {
        self.session.shutdown();
    }
}

fn session_error(e: SessionError) -> McpError {
    match e {
        SessionError::Timeout => {
            McpError::Timeout("the mcp server produced no output in time".to_string())
        }
        SessionError::Closed(reason) => McpError::Io(reason),
        SessionError::Io(reason) => McpError::Io(reason),
    }
}

/// 本番の`Transport`実装を作るファクトリ。
#[derive(Default)]
pub struct AppContainerTransportFactory {
    spawn_daemon: Option<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
}

impl AppContainerTransportFactory {
    pub fn with_spawn_daemon(
        spawn_daemon: harness_sandbox::tier2a::spawnd::SharedSpawnDaemon,
    ) -> Self {
        Self {
            spawn_daemon: Some(spawn_daemon),
        }
    }
}

impl TransportFactory for AppContainerTransportFactory {
    fn create(&self, prepared: &PreparedServer) -> Result<Box<dyn Transport>, McpError> {
        let decl = &prepared.decl;
        let spawn_error = |reason: String| McpError::Spawn {
            id: decl.id.clone(),
            reason,
        };

        // 隔離の実体を持たない`PreparedServer`でこの経路へ来ることはあり得ないが、型で
        // 分けてある以上ここで落とす（空文字のプロファイル名で起動しない）。
        let PreparedIsolation::AppContainer {
            profile_name,
            proxy_addr,
        } = &prepared.isolation
        else {
            return Err(spawn_error(
                "this server was prepared for the streamable-http transport, which has no \
                 AppContainer profile to spawn into"
                    .to_string(),
            ));
        };

        // network要求があるのに専用プロキシが無い場合は起動しない（fail-closed、モジュールdoc）。
        if !decl.network.is_deny() && proxy_addr.is_none() {
            return Err(spawn_error(
                "the declaration requests network access but no dedicated proxy is listening for \
                 this server; refusing to start it unrestricted"
                    .to_string(),
            ));
        }

        let sid = harness_sandbox::tier2a::win_appcontainer::ensure_profile(profile_name)
            .map_err(|e| spawn_error(format!("failed to resolve the sandbox profile: {e}")))?;

        let command = std::path::PathBuf::from(&decl.command);
        let cwd = command
            .parent()
            .filter(|p| !p.as_os_str().is_empty() && p.exists())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);

        let env = build_env(&decl.env, *proxy_addr);
        let args: Vec<&str> = decl.args.iter().map(String::as_str).collect();
        let net = if proxy_addr.is_some() {
            NetworkCapability::InternetClient
        } else {
            NetworkCapability::Deny
        };

        let daemon = self.spawn_daemon.as_ref().ok_or_else(|| {
            spawn_error("MCP stdio has no Spawn Daemon connection (internal error)".to_string())
        })?;
        let child = spawn_via_daemon(
            daemon,
            &decl.id,
            &decl.command,
            &args,
            &cwd,
            &env,
            true, // MCPは双方向なのでstdinが必須。
            sid.as_psid(),
            net,
            // [段階5b] **MCPサーバにもRedirector DLLを注入する。**
            //
            // かつてここは`RedirectorInject::default()`（＝注入しない）を固定で渡しており、
            // 理由も「workspaceを触らないから要らない」と書かれていた。**理由は今も正しいが、
            // 問いが変わった**——段階⑤で`CHILD_PROCESS_RESTRICTED`（OSが子プロセス生成を
            // 拒否する緩和策）を積むと、注入の有無は「誘導が要るか」ではなく
            // 「**子を作れなくなったとき頼む先を持っているか**」の問題になる。
            // フックの入っていないプロセスが1つでも居る状態で⑤は積めない（§8.1）。
            //
            // **CoWの誘導もfault受付も渡さない。** ワークスペースが無いので渡せず、
            // DLL側はそのときファイル系フックを1本も置かない。
            // したがって§5.1.3の「MCP preflightはlazy化の初期対象に含めない」は**そのまま生きている**
            // ——あれは受付（fault-in）の話で、注入そのものの話ではない。
            RedirectorInject::for_tier2a(None, None, None),
            // §22.1.1: D-38でMCPサーバは**サーバごとに専用プロファイル**なので、package SIDが
            // そのままドメインになる。capability群は持たない（§22.2.2で対象外と決着済み）。
            DomainIdentity::OwnPackage,
            // §22.2.2: MCPサーバの`process`宣言が、Spawn Daemonの要求受付パイプへ
            // 到達できるかを決める。**既定は`deny`**で、その意味は「spawn要求用capabilityを
            // 積まない＝パイプに到達すらできない」という二重目のdenyである。
            //
            // **既定を`broker`側へ倒してはいけない。** D-38はMCPサーバを
            // 「ユーザーが宣言した第三者コード」＝系の中で最も信頼していないコードと
            // 位置づけており、そこがDaemonへ話しかけられる状態を、宣言も承認も無いまま
            // 既定にすることになる。`broker`は宣言に書き、承認台帳のハッシュにも入る
            // （`decl.rs`の`McpProcessAccess`）。
            match decl.process {
                McpProcessAccess::Deny => SpawnRequestAccess::Withhold,
                McpProcessAccess::Broker => SpawnRequestAccess::Grant,
            },
            // [段階⑤] **MCPサーバはコンソールを必要としない。** 実体は`npx`・`node`型の
            // プログラムで、実測でもコンソールを要求したのはPowerShellだけだった
            // （`ConsoleNeed`のdocの表）。生成禁止を積んだ構成では`DETACHED_PROCESS`で起こす。
            ConsoleNeed::NotNeeded,
        )
        .map_err(|e| spawn_error(e.to_string()))?;

        let session = child
            .into_session()
            .map_err(|e| spawn_error(e.to_string()))?;

        Ok(Box::new(AppContainerStdioTransport {
            session,
            lines: LineAccumulator::new(),
        }))
    }
}

/// 子プロセスのenvを組み立てる。
///
/// 素通しはallowlist方式（`harness_sandbox::build_child_env`、D-07）で、そこへ宣言のenvと
/// プロキシ設定を重ねる。**宣言のenvが最後**なのは、ユーザーが承認した内容が最終的な決定権を
/// 持つべきだからで、その内容はハッシュとして承認台帳に固定されている（D-39）。
fn build_env(
    declared: &std::collections::BTreeMap<String, String>,
    proxy_addr: Option<std::net::SocketAddr>,
) -> Vec<(String, String)> {
    let mut env = harness_sandbox::build_child_env();
    if let Some(addr) = proxy_addr {
        let http = format!("http://{addr}");
        env.push(("HTTP_PROXY".to_string(), http.clone()));
        env.push(("HTTPS_PROXY".to_string(), http.clone()));
        env.push(("http_proxy".to_string(), http.clone()));
        env.push(("https_proxy".to_string(), http));
        env.push(("ALL_PROXY".to_string(), format!("socks5h://{addr}")));
    }
    for (k, v) in declared {
        env.retain(|(name, _)| name != k);
        env.push((k.clone(), v.clone()));
    }
    env
}

/// **実機E2E**（`#[ignore]`。AppContainerプロファイルという実マシンの共有状態を触る）。
/// 下の`mod tests`が純粋な組み立てだけを見るのに対し、あちらは**この`create`を実際に通して**
/// 子を起こし、要求受付パイプへ届かないことを測る。
#[cfg(all(windows, test))]
#[path = "transport_stdio_e2e_tests.rs"]
mod transport_stdio_e2e_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decl::{McpNetworkDecl, McpServerDecl, McpTransportKind, McpWorkspaceAccess};

    fn declared_env() -> std::collections::BTreeMap<String, String> {
        [("DOCS_ROOT".to_string(), "C:\\docs".to_string())]
            .into_iter()
            .collect()
    }

    fn proxy(addr: &str) -> Option<std::net::SocketAddr> {
        Some(addr.parse().unwrap())
    }

    #[test]
    fn a_server_without_network_gets_no_proxy_variables() {
        let env = build_env(&declared_env(), None);
        assert!(!env
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("HTTP_PROXY")));
        assert!(!env.iter().any(|(k, _)| k == "ALL_PROXY"));
    }

    /// 専用プロキシのアドレスが注入される（宛先を絞るのはそのプロキシ、§3.2）。
    #[test]
    fn a_server_with_network_is_pointed_at_its_own_proxy() {
        let env = build_env(&declared_env(), proxy("127.0.0.1:19090"));
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .unwrap_or_default()
        };
        assert_eq!(get("HTTP_PROXY"), "http://127.0.0.1:19090");
        assert_eq!(get("HTTPS_PROXY"), "http://127.0.0.1:19090");
        assert_eq!(get("ALL_PROXY"), "socks5h://127.0.0.1:19090");
    }

    #[test]
    fn declared_env_is_present_and_wins_over_the_inherited_allowlist() {
        let mut declared = declared_env();
        declared.insert("PATH".to_string(), "C:\\only\\this".to_string());
        let env = build_env(&declared, None);

        let paths: Vec<&str> = env
            .iter()
            .filter(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["C:\\only\\this"],
            "declared env must not be duplicated"
        );
        assert!(env.iter().any(|(k, v)| k == "DOCS_ROOT" && v == "C:\\docs"));
    }

    /// 秘密っぽい環境変数はallowlist側から入らない（D-07。宣言に書いたものだけが渡る）。
    #[test]
    fn secret_looking_inherited_variables_do_not_reach_the_server() {
        let env = build_env(&declared_env(), None);
        assert!(!env
            .iter()
            .any(|(k, _)| k.to_ascii_uppercase().contains("API_KEY")));
    }

    /// HTTP用に用意された`PreparedServer`でstdioのファクトリを呼んでも、空のプロファイル名で
    /// 起動したりせずエラーになる（`PreparedIsolation`を型で分けている理由）。
    #[test]
    fn the_stdio_factory_refuses_a_server_prepared_for_streamable_http() {
        let endpoint = crate::http_wire::validate_endpoint(
            "http://127.0.0.1:3000/mcp",
            &crate::http_wire::EndpointGates::default(),
        )
        .unwrap();
        let prepared = PreparedServer {
            decl: McpServerDecl {
                id: "docs".to_string(),
                transport: McpTransportKind::StreamableHttp,
                command: String::new(),
                args: vec![],
                env: Default::default(),
                url: "http://127.0.0.1:3000/mcp".to_string(),
                headers: Default::default(),
                tls_pin: None,
                tools: Default::default(),
                network: McpNetworkDecl::default(),
                workspace: McpWorkspaceAccess::None,
                process: crate::decl::McpProcessAccess::Deny,
            },
            isolation: PreparedIsolation::Direct {
                endpoint,
                ca_bundle: None,
                tls_pin: None,
            },
        };
        assert!(matches!(
            AppContainerTransportFactory::default().create(&prepared),
            Err(McpError::Spawn { .. })
        ));
    }
}
