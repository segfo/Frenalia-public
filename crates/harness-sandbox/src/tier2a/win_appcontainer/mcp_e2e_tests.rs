//! MCPサーバ隔離（D-38）の実機E2E。`docs/STATUS.md`「MCPクライアント機構」残課題#3/#4に対応する。
//!
//! 自動テストで固定できるのは「どういうポリシーを組み立てたか」までで、**OSが実際にそれを
//! 強制するか**は実機でしか確かめられない。ここが確かめるのは次の2点である。
//!
//! | テスト | 確かめること | 対応する残課題 |
//! |---|---|---|
//! | `e2e_mcp_server_cannot_read_the_workspace_unless_declared` | workspace要求の無いMCPサーバからworkspaceが読めないこと、要求したサーバでも`.harness`は読めないこと | #4 |
//! | `e2e_mcp_servers_get_independent_egress_allowlists` | サーバAのSIDから、サーバBの専用プロキシポートへ到達できないこと | #3 |
//!
//! いずれも`#[ignore]`。前者はAppContainerプロファイル（マシン全体の共有状態）を、後者はさらに
//! 管理者トークンとBFEを要する。**M15.7のETW E2Eと同時に走らせてはならない**
//! （`docs/INDEX.md`「並列にできるのは実装であってE2E実行ではない」）。

use std::path::Path;

use super::*;

/// 子プロセスの作業ディレクトリを用意し、MCPサーバのSIDへ読取+実行を与える。
///
/// **workspaceとは別のディレクトリ**にするのが要点で、これが無いと「workspaceが読めないこと」を
/// 確かめるはずの子プロセスがそもそも起動できない（cwdに到達できない）。実運用でこれに当たるのは
/// サーバの実行ファイルが置かれたディレクトリである（`mcp_preflight::read_exec_roots`）。
fn probe_cwd(sid: PSID) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("probe cwd");
    grant_ace_inheritable_access(dir.path(), sid, FsAccess::ReadExec).expect("grant probe cwd");
    dir
}

/// AppContainer子から`path`を読み、内容かエラーを返す。
fn read_from_sandbox(sid: PSID, cwd: &Path, path: &Path) -> String {
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let command = format!(
        "try {{ Get-Content -Path '{}' -Raw -ErrorAction Stop }} catch {{ Write-Output \"DENIED: $_\" }}",
        path.display()
    );
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        cwd,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        super::RedirectorInject::default(),
        DomainIdentity::OwnPackage,
    )
    .expect("spawn AppContainer child");
    let (stdout, stderr, _code) = child.write_stdin_read_output_and_wait(None).unwrap();
    format!("{stdout}{stderr}")
}

/// テストが作ったプロファイルを消す（ACEはtempdirごと消えるので名前だけ回収する）。
fn delete_profile(name: &str) {
    unsafe {
        let w = crate::win_common::wide(name);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    }
}

/// **残課題#4**: `DESIGN-MCP.md` §3.2「workspaceへACEを一切付けない」がOSレベルで効いていること。
///
/// 3つを一度に確かめる。
///
/// 1. workspace要求の無いサーバは、workspaceの中身を読めない
/// 2. `workspace: read`を宣言したサーバは読める（既定が厳しすぎて使えないわけではないことの確認）
/// 3. **2のサーバでも`.harness`だけは読めない**（P-08）。ここが破れると、承認台帳の隣にある
///    `.harness/settings.json`——つまり**次回起動する宣言そのもの**をMCPサーバが覗ける
#[cfg(windows)]
#[test]
#[ignore = "requires real Windows AppContainer state (machine-wide); do not run alongside the M15.7 ETW E2E"]
fn e2e_mcp_server_cannot_read_the_workspace_unless_declared() {
    // 実運用と同じく、セッションの台帳エントリの下へMCPプロファイルをぶら下げる。
    crate::tier2a::session_profile::begin_session().expect("begin session");

    let workspace = tempfile::tempdir().expect("workspace");
    let secret = workspace.path().join("workspace-secret.txt");
    std::fs::write(&secret, "SECRET_IN_WORKSPACE").unwrap();
    let control_dir = workspace.path().join(".harness");
    std::fs::create_dir_all(&control_dir).unwrap();
    let control_file = control_dir.join("settings.json");
    std::fs::write(&control_file, "{\"mcp\":\"SECRET_IN_HARNESS_CONTROL_DIR\"}").unwrap();

    // --- (1) workspaceを要求していないサーバ ---
    let denied = preflight_mcp_server(&McpPreflightRequest {
        server_id: "e2e-noworkspace",
        command: Path::new(&resolve_shell().0),
        arg_paths: &[],
        workspace: None,
    })
    .expect("preflight (no workspace)");
    let sid_denied = ensure_profile(&denied.profile_name).expect("denied profile sid");
    let cwd_denied = probe_cwd(sid_denied.as_psid());
    let out_denied = read_from_sandbox(sid_denied.as_psid(), cwd_denied.path(), &secret);
    eprintln!("[probe] workspace未要求のMCPサーバがworkspaceを読んだ結果:\n{out_denied}");

    // --- (2)(3) workspace: read を宣言したサーバ ---
    let allowed = preflight_mcp_server(&McpPreflightRequest {
        server_id: "e2e-readworkspace",
        command: Path::new(&resolve_shell().0),
        arg_paths: &[],
        workspace: Some((workspace.path(), FsAccess::Read)),
    })
    .expect("preflight (workspace: read)");
    let sid_allowed = ensure_profile(&allowed.profile_name).expect("allowed profile sid");
    let cwd_allowed = probe_cwd(sid_allowed.as_psid());
    let out_allowed = read_from_sandbox(sid_allowed.as_psid(), cwd_allowed.path(), &secret);
    let out_control = read_from_sandbox(sid_allowed.as_psid(), cwd_allowed.path(), &control_file);
    eprintln!("[probe] workspace:read のMCPサーバがworkspaceを読んだ結果:\n{out_allowed}");
    eprintln!("[probe] 同じサーバが .harness を読んだ結果:\n{out_control}");

    // 後始末（判定より前にやる。assertで落ちてもプロファイルを残さない）。
    let _ = revoke_ace_recursive(workspace.path(), sid_allowed.as_psid());
    for name in [&denied.profile_name, &allowed.profile_name] {
        delete_profile(name);
    }
    let _ = crate::tier2a::session_profile::end_session(&revoke_session_grant);

    assert!(
        !out_denied.contains("SECRET_IN_WORKSPACE"),
        "workspaceを要求していないMCPサーバからworkspaceの中身が読めている（D-38 §3.2が崩れている）:\n{out_denied}"
    );
    assert!(
        out_allowed.contains("SECRET_IN_WORKSPACE"),
        "workspace:readを宣言したのに読めていない（既定が厳しすぎるのではなく壊れている疑い）:\n{out_allowed}"
    );
    assert!(
        !out_control.contains("SECRET_IN_HARNESS_CONTROL_DIR"),
        "workspaceを許可したMCPサーバから .harness が読めている（P-08が崩れている。\
         承認台帳と同じ宣言を覗ける）:\n{out_control}"
    );
}

/// **残課題#3**: サーバごとに別のpackage SIDを持つ結果として、**サーバ別の宛先allowlistが
/// 実際に効いている**こと（D-38、`DESIGN-MCP.md` §3.2の判断B）。
///
/// サーバAとサーバBにそれぞれ専用プロキシのポートを1つずつ割り当て、Aの子プロセスから
/// 「自分のポート」「Bのポート」「外部」の3方向を試す。**Bのポートへ到達できてしまうと、
/// 宛先を絞ったつもりで絞れていない**——AがBの許可ドメインへ出られることになる。
#[cfg(windows)]
#[test]
#[ignore = "requires an elevated administrator token, BFE, and real WFP state; do not run alongside the M15.7 ETW E2E"]
fn e2e_mcp_servers_get_independent_egress_allowlists() {
    use crate::tier2a::wfp::{WfpOptions, WfpSession};

    if !crate::tier2a::privhelper::is_elevated() {
        panic!("MCP per-server WFP E2E requires an elevated administrator token");
    }
    crate::tier2a::session_profile::begin_session().expect("begin session");

    // 各サーバの「専用プロキシ」に見立てたlistener。実運用ではこれが
    // `harness_tools::net_proxy::spawn_local_proxy`のインスタンスで、許可ドメインが別々になる。
    let listener_a = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let listener_b = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    for listener in [&listener_a, &listener_b] {
        listener.set_nonblocking(true).unwrap();
    }
    let accept = |listener: std::net::TcpListener| {
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(_) => return,
                }
            }
        })
    };
    let accept_a = accept(listener_a);
    let accept_b = accept(listener_b);

    let prep_a = preflight_mcp_server(&McpPreflightRequest {
        server_id: "e2e-net-a",
        command: Path::new(&resolve_shell().0),
        arg_paths: &[],
        workspace: None,
    })
    .expect("preflight A");
    let prep_b = preflight_mcp_server(&McpPreflightRequest {
        server_id: "e2e-net-b",
        command: Path::new(&resolve_shell().0),
        arg_paths: &[],
        workspace: None,
    })
    .expect("preflight B");
    let sid_a = ensure_profile(&prep_a.profile_name).expect("sid A");
    let sid_b = ensure_profile(&prep_b.profile_name).expect("sid B");

    // 本番と同じ構造: プロファイルごとに独立したWFPセッション（`netfilterd::serve_inner`が
    // `policy_targets`の各要素に対して`apply_one`を呼ぶのと同じ形）。
    let session_a = WfpSession::apply(
        sid_a.as_psid(),
        &WfpOptions {
            session_profile: prep_a.profile_name.clone(),
            allow_loopback_tcp_ports: vec![port_a],
            allow_loopback_udp_ports: Vec::new(),
            audit_log_path: None,
        },
    )
    .expect("apply WFP for server A");
    let session_b = WfpSession::apply(
        sid_b.as_psid(),
        &WfpOptions {
            session_profile: prep_b.profile_name.clone(),
            allow_loopback_tcp_ports: vec![port_b],
            allow_loopback_udp_ports: Vec::new(),
            audit_log_path: None,
        },
    )
    .expect("apply WFP for server B");

    let cwd = probe_cwd(sid_a.as_psid());
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    // サーバAの子から3方向を試し、結果を1行にまとめて返す。
    let command = format!(
        "function Try-Connect($p) {{ \
           try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', $p); $c.Close(); return $true }} \
           catch {{ return $false }} }}; \
         $own = Try-Connect {port_a}; \
         $other = Try-Connect {port_b}; \
         $ext = $false; \
         try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('8.8.8.8', 53); $c.Close(); $ext = $true }} catch {{ }}; \
         Write-Output \"own=$own other=$other ext=$ext\""
    );
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        cwd.path(),
        &env,
        false,
        sid_a.as_psid(),
        // 実運用でnetworkを要求したサーバと同じ条件（capabilityは付くが、宛先はWFPが絞る）。
        NetworkCapability::InternetClient,
        super::RedirectorInject::default(),
        DomainIdentity::OwnPackage,
    )
    .expect("spawn AppContainer child for server A");
    let (stdout, stderr, code) = child.write_stdin_read_output_and_wait(None).unwrap();
    eprintln!("[probe] サーバAの子からの到達性: code={code}\n{stdout}{stderr}");

    // 後始末（判定より前）。
    let _ = session_a.teardown();
    let _ = session_b.teardown();
    let _ = accept_a.join();
    let _ = accept_b.join();
    for name in [&prep_a.profile_name, &prep_b.profile_name] {
        delete_profile(name);
    }
    let _ = crate::tier2a::session_profile::end_session(&revoke_session_grant);

    assert!(
        stdout.contains("own=True"),
        "サーバAが自分の専用プロキシへ到達できていない（許可側が壊れている）:\n{stdout}{stderr}"
    );
    assert!(
        stdout.contains("other=False"),
        "サーバAからサーバBの専用プロキシへ到達できている。サーバ別の宛先allowlistが\
         成立しておらず、AがBの許可ドメインへ出られる（D-38 §3.2が崩れている）:\n{stdout}{stderr}"
    );
    assert!(
        stdout.contains("ext=False"),
        "MCPサーバから外部への直接connectが通っている（WFPのdefault-denyが効いていない）:\n{stdout}{stderr}"
    );
}
