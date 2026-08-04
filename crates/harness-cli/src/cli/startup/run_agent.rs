//! 起動パイプライン Stage5: エージェント実行（対話TUI / 非対話headless）。
//!
//! Local Proxy/Fake DNS起動・WFPシナリオの最終確定・`ToolCtx`構築・`ConversationState`・
//! TUI/headless分岐と、セッション終了時のnetfilterd teardown。

use super::*;
use super::sandbox::SandboxPrepared;
#[cfg(windows)]
use super::tier3_progress::start_tier3_with_progress;

/// Local Proxy/Fake DNS起動・`ToolCtx`構築・`ConversationState`・TUI/headless分岐。
/// 5段の最終段のため`Result`ではなく`ExitCode`を直接返す。
pub(super) async fn stage_run_agent(sandbox: SandboxPrepared) -> ExitCode {
    let SandboxPrepared {
        cli,
        workspace_root,
        resume_wants_picker,
        provider,
        model,
        max_turns,
        compaction,
        enter_submits,
        tools,
        arbiter,
        cognition,
        sessions_dir,
        mut session,
        session_messages,
        staging_mode,
        sandbox_dir,
        read_scope,
        mut net_proxy,
        net_app,
        run_shell_path_extra,
        fs_passthrough,
        settings_fs_paths,
        wfp_prelude,
        write_mode,
        shell_tier,
    } = sandbox;

    let _session_proxy = if net_proxy.domain_policy_enabled {
        match harness_tools::net_proxy::spawn_local_proxy(&net_proxy).await {
            Ok(Some(proxy)) => {
                net_proxy.proxy_addr = Some(proxy.addr);
                Some(proxy)
            }
            Ok(None) => None,
            Err(e) => {
                if shell_tier.tier == harness_core::ShellTier::Tier2a {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; Tier2a domain \
                         enforcement will remain fail-closed instead of opening network: {e}"
                    );
                } else {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; run_shell will try \
                         a per-command proxy instead: {e}"
                    );
                }
                None
            }
        }
    } else {
        None
    };
    let _session_fake_dns = if net_proxy.domain_policy_enabled {
        match harness_tools::fake_dns::spawn_fake_dns(&harness_tools::fake_dns::FakeDnsConfig {
            allow_domains: net_proxy.allow_domains.clone(),
            policy_required: net_proxy.domain_policy_enabled,
            audit_log_path: net_proxy.audit_log_path.clone(),
            preferred_port: Some(53),
        })
        .await
        {
            Ok(agent) => {
                net_proxy.fake_dns_addr = Some(agent.addr);
                Some(agent)
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to start session-scoped Fake DNS diagnostic agent; run_shell \
                     will try a per-command Fake DNS agent instead: {e}"
                );
                None
            }
        }
    } else {
        None
    };
    let net_loopback_ports =
        net_loopback_ports_for_agents(net_proxy.proxy_addr, net_proxy.fake_dns_addr);

    // WFPシナリオ(A)/(B)/(C)の最終確定。`shell_tier`が実際にTier2aへ着地し、かつ
    // 許可ドメインがあるときだけ有効化する。
    #[cfg(windows)]
    let net_wfp: Option<harness_sandbox::tier2a::netfilterd::NetfilterHandle> = {
        let domain_policy_requested = net_proxy.domain_policy_enabled;
        let tier2a_domain_policy =
            shell_tier.tier == harness_core::ShellTier::Tier2a && domain_policy_requested;
        let session_proxy_ready = net_proxy.proxy_addr.is_some();
        let wfp_needed = tier2a_domain_policy && session_proxy_ready;
        if !wfp_needed {
            if tier2a_domain_policy && !session_proxy_ready {
                eprintln!(
                    "warning: session-scoped local proxy did not start; WFP domain enforcement \
                     will not be enabled and Tier2a run_shell network capability will remain \
                     denied (fail-closed)"
                );
            }
            // シナリオ(C)、または投機的に作ったパイプが結局不要だった場合。`wfp_prelude`を
            // dropするだけで`PreparedPipe`が自動的にパイプを閉じる（後始末コード不要）。
            drop(wfp_prelude);
            None
        } else if shell_tier.netfilterd_chain_attempted {
            // シナリオ(A): privhelperが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
            match wfp_prelude {
                Some(prepared) => {
                    match harness_sandbox::tier2a::netfilterd::NetfilterHandle::connect_after_chain_launch(
                        prepared.into_handle(),
                        harness_sandbox::tier2a::netfilterd::NetfilterPolicy {
                            // D-37: WFPフィルタはこのセッションのpackage SIDだけを条件にする。
                            session_profile:
                                harness_sandbox::tier2a::session_profile::current_profile_name(),
                            allow_loopback_tcp_ports: net_loopback_ports.tcp.clone(),
                            allow_loopback_udp_ports: net_loopback_ports.udp.clone(),
                            audit_log_path: net_proxy.audit_log_path.clone(),
                        },
                    ) {
                        Ok(handle) => Some(handle),
                        Err(e) => {
                            eprintln!(
                                "warning: WFP netfilterd chain-launch handshake failed (network \
                                 egress will only be enforced by the cooperative proxy, Layer1, \
                                 this session): {e}"
                            );
                            None
                        }
                    }
                }
                None => None,
            }
        } else {
            // シナリオ(B): privhelperの連鎖起動は発生しなかった（fs-allowの昇格が不要だった等）。
            // 投機的パイプは使わない（`NetfilterHandle::start`が自前で新規パイプを作るため）、
            // dropして自動的に閉じる。
            drop(wfp_prelude);
            match harness_sandbox::tier2a::netfilterd::NetfilterHandle::start(
                harness_sandbox::tier2a::netfilterd::NetfilterPolicy {
                    session_profile:
                        harness_sandbox::tier2a::session_profile::current_profile_name(),
                    allow_loopback_tcp_ports: net_loopback_ports.tcp.clone(),
                    allow_loopback_udp_ports: net_loopback_ports.udp.clone(),
                    audit_log_path: net_proxy.audit_log_path.clone(),
                },
            ) {
                Ok(handle) => Some(handle),
                Err(e) => {
                    // `should_grant_tier2a_network_capability`（`crates/harness-tools/src/
                    // shell.rs`）は`domain_policy_requested && !enforced_by_wfp`のとき
                    // `NetworkCapability::Deny`を返す。つまりWFP起動失敗時はLayer1協調
                    // プロキシへの縮退ではなく、AppContainer capability自体が付与されず
                    // run_shell子プロセスはソケットを一切生成できない（fail-closed）。
                    eprintln!(
                        "warning: failed to start WFP netfilterd; Tier2a run_shell network \
                         capability will remain denied for this session (fail-closed, no \
                         outbound sockets at all, not merely unenforced): {e}"
                    );
                    None
                }
            }
        }
    };
    #[cfg(not(windows))]
    let _net_wfp: Option<()> = None;
    if let Some(reason) = &shell_tier.reason {
        eprintln!(
            "warning: shell isolation downgraded to {} (from {}): {reason}",
            shell_tier.tier.label(),
            shell_tier.downgraded_from.map(|t| t.label()).unwrap_or("?")
        );
    }
    if shell_tier.tier == harness_core::ShellTier::Tier1 {
        eprintln!(
            "note: shell isolation tier is Tier1; Tier2a (AppContainer) was attempted \
             automatically but unavailable this session (see the warning above for the reason). \
             Tier1 does not protect against reading confidential files outside the workspace \
             or outbound network exfiltration from run_shell child processes \
             (plans/DESIGN-SANDBOX.md §9-1). --require-sandbox=confidential refuses to start \
             at Tier1 rather than silently weakening this guarantee."
        );
    }
    // fs passthrough（D2/D-13）: ACE付与自体は「付けっぱなし」（撤収はユーザ操作
    // `harness fs revoke`に委ねる）。Tier2aが実際に選択された場合のみpreflightがACE付与を
    // 試みたので、そのときだけ台帳に記録する。`granted_passthrough`（実際にACEが確認できた
    // ルートのみ）を基準にする——`fs_passthrough`全件を無条件に記録すると、システム保護パス等で
    // `ACCESS_DENIED`になり実際には付与されなかったエントリまで台帳に載る「幻の台帳エントリ」を
    // 生んでしまうため（`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」）。到達不能だった穴の診断
    // （D8/D9）は`passthrough_warnings`としてこの下で表示する。
    if shell_tier.tier == harness_core::ShellTier::Tier2a {
        for (path, writable) in &shell_tier.granted_passthrough {
            // このエントリが`--force-system-acl`対象だったか（元のfs_passthroughから引く）。
            // forcedなら撤収時も`SeRestorePrivilege`が要るため台帳へ記録しておく。
            let forced = fs_passthrough
                .iter()
                .find(|fp| &fp.path == path)
                .map(|fp| fp.forced)
                .unwrap_or(false);
            let path_str = path.to_string_lossy().into_owned();
            let settings_workspace = settings_fs_paths
                .contains(&path_str)
                .then(|| workspace_root.to_string_lossy().into_owned());
            crate::fs_grants::record_fs_passthrough_grant(
                path,
                *writable,
                forced,
                settings_workspace.as_deref(),
            );
            if forced {
                eprintln!(
                    "WARNING: forced system ACL grant (--force-system-acl, SeRestorePrivilege): {} \
                     [{}] -- a sandbox read ACE was written into a system-protected path by \
                     bypassing its DACL (ownership unchanged). This ACE persists after harness \
                     exits; run `harness fs revoke {}` to undo.",
                    path.display(),
                    if *writable { "rw" } else { "ro" },
                    path.display()
                );
            } else {
                eprintln!(
                    "note: fs-allow granted: {} [{}] (this ACE persists after harness exits; use \
                     `harness fs revoke {}` to undo)",
                    path.display(),
                    if *writable { "rw" } else { "ro" },
                    path.display()
                );
            }
        }
        for (path, access, reason) in &shell_tier.denied_passthrough {
            crate::fs_grants::record_fs_passthrough_denied(path, access, reason);
        }
    }
    for warning in &shell_tier.passthrough_warnings {
        eprintln!("warning: {warning}");
    }

    // Tier3（`plans/DESIGN-SANDBOX-VMISOLATION.md`）: VM+コンテナ起動デーモン
    // （`harness-vmsandboxd`、D-21）の昇格起動・起動待ちはコールドブートで数分かかり得る
    // （`docs/STATUS.md`Tier3残課題#3）ため、無進捗のままここでブロッキングせず、`cli.print`の
    // 分岐後（TUIならターミナル準備画面の中、非対話ならstderr進捗行と共に）まで遅延させる。
    // ここでは`vm_sandbox: None`のまま`ToolCtx`を構築し、各分岐が準備完了後に書き戻す
    // （`system_blocks_for`は`vm_sandbox`を参照しないため後書きで安全、`prompt.rs`参照）。
    if net_wfp.is_some() {
        net_proxy.enforced_by_wfp = true;
    }

    let mut tool_ctx = ToolCtx {
        workspace_root: workspace_root.clone(),
        staging: StagingConfig {
            mode: staging_mode,
            sandbox_dir,
        },
        read_scope,
        shell_sees_staged_writes: shell_sees_staged_writes(&shell_tier),
        shell_tier,
        net_proxy,
        net_app,
        run_shell_path_extra,
        vm_sandbox: None,
        cow_upper_dir: write_mode.upper_dir().map(|p| p.to_path_buf()),
    };

    let mut state = ConversationState::new(harness_engine::system_blocks_for(&tool_ctx));
    state.messages = session_messages;

    let exit_code = match cli.print {
        Some(print) => {
            headless_branch(
                print,
                provider.as_ref(),
                &tools,
                &mut tool_ctx,
                &arbiter,
                &cognition,
                model,
                max_turns,
                compaction,
                cli.output_format,
                cli.tier3_warm,
                cli.tier3_max_sessions.max(1),
                &mut state,
                &mut session,
            )
            .await
        }
        None => {
            tui_branch(
                provider,
                tools,
                tool_ctx,
                arbiter,
                cognition,
                model,
                max_turns,
                compaction,
                cli.provider.label().to_string(),
                state,
                session,
                sessions_dir,
                enter_submits,
                resume_wants_picker,
                cli.tier3_warm,
                cli.tier3_max_sessions.max(1),
            )
            .await
        }
    };

    // セッション終了時のWFP netfilterdのteardown（headless・対話モード共通の末尾）。
    // ここに到達せずにmainが早期returnした場合（このブロックより前のエラーパス）は、
    // `net_wfp`のDropフェイルセーフ（パイプ断検知でdaemon側が自発的にteardownする、
    // `netfilterd.rs`のモジュールdoc参照）に委ねる。Ctrl+C等のシグナル割り込みも同様に
    // フェイルセーフへ委ねる（本ラウンドではシグナルハンドラを追加しない、
    // `~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D手順5参照）。
    // Tier3 VMサンドボックスのteardownは、準備開始をTier3の実際の使用側（TUIは
    // `harness_tui::run`内部、非対話は上の`Some(print)`アーム）へ遅延させたのに合わせて
    // それぞれの分岐内で完結させている（進捗表示のため、`plans/DESIGN-SANDBOX-VMISOLATION.md`
    // 追記・本コミット参照）。早期returnパスは従来通り`VmSandboxHandle`のDropフェイルセーフ
    // （パイプ切断検知でdaemon側が自発的にteardownする）に委ねる。

    #[cfg(windows)]
    if let Some(handle) = net_wfp {
        if let Err(e) = handle.stop() {
            eprintln!("warning: failed to cleanly tear down WFP netfilterd session: {e}");
        }
    }

    // D-37: このセッションのAppContainerプロファイルと、それ宛に付けたACEを撤収する。
    // 撤収順序（ACE→最後にプロファイル）は`session_profile`側が保証する。ここへ到達せずに
    // 落ちた場合（クラッシュ・Ctrl+C）は、次回起動時の`preflight`のGCが同じ経路で回収する
    // ——だからこの呼び出しは「速く片付けるための最適化」であって、正しさの要件ではない。
    #[cfg(windows)]
    harness_sandbox::tier2a::session_profile::end_session(
        &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
    );

    exit_code
}

/// `stage_run_agent`の非対話（`-p`/`--print`）分岐。`tool_ctx`はTier3準備完了後の
/// `vm_sandbox`書き戻しのため`&mut`で受ける。
#[allow(clippy::too_many_arguments)]
async fn headless_branch(
    print: String,
    provider: &dyn LlmProvider,
    tools: &ToolRegistry,
    tool_ctx: &mut ToolCtx,
    arbiter: &PermissionArbiter,
    cognition: &CognitiveOrchestrator,
    model: String,
    max_turns: usize,
    compaction: harness_engine::compaction::CompactionPolicy,
    output_format: OutputFormat,
    tier3_warm: bool,
    tier3_max_sessions: u8,
    state: &mut ConversationState,
    session: &mut harness_engine::SessionStore,
) -> ExitCode {
    let prompt = if print == "-" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("failed to read prompt from stdin: {e}");
            return ExitCode::FAILURE;
        }
        buf
    } else {
        print
    };

    state.push_user_text(prompt);
    if let Err(e) = session.append_messages(&state.messages[state.messages.len() - 1..]) {
        eprintln!(
            "failed to persist session {}: {e}",
            session.path().display()
        );
        return ExitCode::FAILURE;
    }
    let before_run = state.messages.len();

    // Tier3準備（VM+コンテナ起動、コールドブート数分/ウォーム再利用約20秒）を
    // ここで行い、待機中はstderrへ進捗行を出す（TUI分岐は`harness_tui::run`内で
    // 同様の役割を果たす、`crates/harness-tui/src/lib.rs`参照）。
    #[cfg(windows)]
    let vm_sandbox_handle: Option<
        std::sync::Arc<harness_sandbox_vm::vmsandboxd::VmSandboxHandle>,
    > = if tool_ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
        start_tier3_with_progress(
            &tool_ctx.workspace_root,
            &tool_ctx.net_proxy.allow_domains,
            tier3_warm,
            tier3_max_sessions,
        )
        .await
    } else {
        None
    };
    #[cfg(not(windows))]
    let vm_sandbox_handle: Option<std::sync::Arc<()>> = None;

    #[cfg(windows)]
    {
        tool_ctx.vm_sandbox = vm_sandbox_handle
            .clone()
            .map(|h| h as std::sync::Arc<dyn harness_core::VmShellExecutor>);
    }

    let mut stdout = std::io::stdout();
    let exit = run_headless(
        provider,
        state,
        tools,
        tool_ctx,
        arbiter,
        cognition,
        AgentLoopConfig {
            model,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_turns,
            compaction,
        },
        output_format,
        &mut stdout,
    )
    .await;
    let _ = session.append_messages(&state.messages[before_run..]);

    #[cfg(windows)]
    if let Some(handle) = vm_sandbox_handle {
        if let Err(e) = handle.stop() {
            eprintln!("warning: failed to cleanly tear down Tier3 VM sandbox session: {e}");
        }
    }

    exit
}

/// `stage_run_agent`の対話（TUI）分岐。
#[allow(clippy::too_many_arguments)]
async fn tui_branch(
    provider: Box<dyn LlmProvider>,
    tools: ToolRegistry,
    tool_ctx: ToolCtx,
    arbiter: PermissionArbiter,
    cognition: CognitiveOrchestrator,
    model: String,
    max_turns: usize,
    compaction: harness_engine::compaction::CompactionPolicy,
    provider_label: String,
    state: ConversationState,
    session: harness_engine::SessionStore,
    sessions_dir: PathBuf,
    enter_submits: bool,
    resume_wants_picker: bool,
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> ExitCode {
    let log_dir = tool_ctx.workspace_root.join(".harness").join("logs");
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("failed to create log directory {}: {e}", log_dir.display());
        return ExitCode::FAILURE;
    }
    // tracing出力先をファイルへ切り替えた後でなければTUI側の`tracing::debug!`等が
    // 直接stdoutを汚してしまう（§リッチTUI「tracingは全てtracing-appenderでファイルへ」）。
    let _log_guard = harness_tui::init_file_logging(&log_dir);

    let result = harness_tui::run(
        provider,
        tools,
        tool_ctx,
        arbiter,
        cognition,
        model,
        DEFAULT_MAX_TOKENS,
        max_turns,
        compaction,
        provider_label,
        state,
        session,
        sessions_dir,
        enter_submits,
        resume_wants_picker,
        tier3_warm,
        tier3_max_sessions,
    )
    .await;

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tui error: {e}");
            ExitCode::FAILURE
        }
    }
}

