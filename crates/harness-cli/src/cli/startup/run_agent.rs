//! 起動パイプライン Stage5: エージェント実行（対話TUI / 非対話headless）。
//!
//! Local Proxy/Fake DNS起動・WFPシナリオの最終確定・`ToolCtx`構築・`ConversationState`・
//! TUI/headless分岐と、セッション終了時のnetfilterd teardown。

use super::sandbox::SandboxPrepared;
#[cfg(windows)]
use super::tier3_progress::start_tier3_with_progress;
use super::*;

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
        degeneracy,
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
        policy_learn: policy_learn_enabled,
        wfp_prelude,
        write_mode,
        shell_tier,
        mcp_decls,
        mcp_gates,
    } = sandbox;
    let mut tools = tools;

    // Tier2a preflightが成功した後、このhost process用のDaemonを1本だけ起こす。
    // 起動できなければTier2aセッション自体を開始せず、直接spawnへは降格しない。
    #[cfg(windows)]
    let spawn_daemon = if shell_tier.tier == harness_core::ShellTier::Tier2a {
        // [段階⑤] **製品の既定は「生成禁止を積まない」。** 積むと、遷移ポリシーの評価
        // （段階E）が無い今はDaemonの答えが常に「未実装なので断る」になり、
        // サンドボックスの中で外部プログラムが1つも起動できなくなる。
        // 常時適用へ切り替えるのは段階Eが着地してからで、そのときはこの引数ごと消す。
        // [段階6b] **遷移の宣言はharnessが読んでDaemonへ渡す**
        // （`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。**この経路が`policy.json`を読むのは
        // ここが初めてである**——使うのは`process`（遷移の宣言）だけで、`fs`/`net`は
        // 従来どおりharness本体の設定経路に関与しない（`policy_file`のモジュールdoc）。
        //
        // **読めなければTier2aセッションを始めない。** 宣言を持たないDaemonを起こすと、
        // 宣言してある遷移まで拒否される。倒れる向きは同じ「拒否」でも、
        // 原因が読み取り失敗であることは画面から分からない（`B-10`）。
        let transition_policy = match harness_policy::policy_file::load(&workspace_root) {
            Ok(policy) => harness_sandbox::tier2a::spawnd::TransitionPolicy {
                policy,
                workspace_root: workspace_root.to_string_lossy().into_owned(),
            },
            Err(error) => {
                eprintln!("error: could not read the transition policy: {error}");
                let outcome = harness_sandbox::tier2a::session_profile::end_session(
                    &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
                );
                if let Some(summary) = outcome.summary() {
                    eprintln!("note: {summary}");
                }
                return ExitCode::FAILURE;
            }
        };
        match harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
            transition_policy,
            harness_sandbox::tier2a::spawnd::ChildProcessPolicy::Unrestricted,
        ) {
            Ok(daemon) => {
                tools.register(Arc::new(harness_tools::RunShellTool::with_spawn_daemon(
                    daemon.clone(),
                )));
                Some(daemon)
            }
            Err(error) => {
                eprintln!("error: could not start the Tier2a Spawn Daemon: {error}");
                // **Daemonが起こせないならTier2aセッションを始めない**（直接生成へ降格しない、
                // `plans/DESIGN-MAC-PROTOCOL.md` §12）。preflightが既に付けたACEと
                // プロファイルはここで撤収する。
                //
                // [BUG-103] **剥がせなかったノードは名前で出す。** 正常終了の末尾と同じ扱いに
                // する——失敗パスだけ黙ると、撤収が1件も成功しなくても何も出ない状態が
                // 早期returnの側にだけ残る（`B-09`）。
                let outcome = harness_sandbox::tier2a::session_profile::end_session(
                    &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
                );
                if let Some(summary) = outcome.summary() {
                    eprintln!("note: {summary}");
                }
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

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

    // MCP手順1〜3（D-38/D-39、`startup::mcp`のモジュールdoc）: 承認照合 → サーバごとの
    // AppContainerプロファイル作成 → サーバ専用プロキシ起動。**プロセスはまだ起こさない**——
    // 実起動は下のWFP適用が終わってから行う（出口強制の効かない窓を作らないため）。
    let mcp_startup = super::mcp::prepare_mcp_servers(
        &mcp_decls,
        &mcp_gates,
        &workspace_root,
        shell_tier.tier,
        cli.print.is_none(),
        net_proxy.audit_log_path.clone(),
    )
    .await;
    #[cfg(windows)]
    let mcp_netfilter_entries = mcp_startup.netfilter_entries();

    // M15.7: OS監査収集器を**netfilterdの昇格トークンから連鎖起動する**ための接続先を先に作る
    // （追加UACを出さない経路）。netfilterdが起動しない構成ではこのパイプは使われず、
    // dropで閉じて`runas`の直接起動へフォールバックする。
    #[cfg(windows)]
    let policy_learn_prelude: Option<
        harness_sandbox::tier2a::policy_learnd::client::PreparedLearnPipe,
    > = if policy_learn_enabled && shell_tier.tier == harness_core::ShellTier::Tier2a {
        match harness_sandbox::tier2a::policy_learnd::client::prepare_pipe() {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                eprintln!(
                    "warning: could not prepare the policy-learning pipe ({e}); will fall back to                      launching the collector directly (one extra UAC prompt)"
                );
                None
            }
        }
    } else {
        None
    };
    #[cfg(windows)]
    let policy_learn_pipe_name = policy_learn_prelude.as_ref().map(|p| p.name().to_string());

    // 収集器の連鎖起動の結末（BUG-093）。netfilterdが`Applied`の応答で返す。
    // **これが`Launched`でなければ収集器の接続を待たない**——待つと`ConnectNamedPipe`が
    // 60秒タイムアウトしてから同じフォールバックへ着くだけで、その60秒は丸ごと無駄になる。
    #[cfg(windows)]
    let mut collector_chain_report: Option<
        harness_sandbox::tier2a::netfilterd::ChainLaunchReport,
    > = None;

    // WFPシナリオ(A)/(B)/(C)の最終確定。`shell_tier`が実際にTier2aへ着地し、かつ
    // 許可ドメインがあるときだけ有効化する。
    #[cfg(windows)]
    let net_wfp: Option<harness_sandbox::tier2a::netfilterd::NetfilterHandle> = {
        let tier2a_domain_policy =
            shell_tier.tier == harness_core::ShellTier::Tier2a && net_proxy.domain_policy_enabled;
        // 経路選択（`wfp_outcome::plan_wfp`）と文言（`WfpUnavailable::warning`）は副作用を
        // 持たない側へ切り出して単体テストで固定してある。ここに残すのは実際にパイプを消費し
        // daemonを起こす部分だけで、**不成立に終わった経路はすべて`Err(WfpUnavailable)`へ
        // 集まる**——警告を出す`eprintln!`はこのブロックの末尾1箇所しか無い（BUG-111）。
        let outcome: Result<
            Option<harness_sandbox::tier2a::netfilterd::NetfilterHandle>,
            WfpUnavailable,
        > = match plan_wfp(
            tier2a_domain_policy,
            net_proxy.proxy_addr.is_some(),
            shell_tier.netfilterd_chain_attempted,
            wfp_prelude.is_some(),
        ) {
            WfpPlan::NotNeeded => {
                // シナリオ(C)、または投機的に作ったパイプが結局不要だった場合。`wfp_prelude`を
                // dropするだけで`PreparedPipe`が自動的にパイプを閉じる（後始末コード不要）。
                drop(wfp_prelude);
                Ok(None)
            }
            WfpPlan::Denied(path) => {
                drop(wfp_prelude);
                Err(path)
            }
            // シナリオ(A): privhelperが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
            WfpPlan::ChainHandshake => match wfp_prelude {
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
                            // D-38: MCPサーバは別のpackage SIDなので、同じApplyRulesで
                            // サーバごとのフィルタも張る（それぞれ自分の専用プロキシの
                            // ポートだけ許可される）。
                            mcp_profiles: mcp_netfilter_entries.clone(),
                            // M15.7/D-44: 昇格側が`audit_log_path`を検証するための基準。
                            // 渡さないと監査ログが無効化される（fail-safe側）。
                            workspace_root: Some(workspace_root.clone()),
                            chain_launch_policy_learnd: policy_learn_pipe_name.clone(),
                        },
                    ) {
                        Ok((handle, report)) => {
                            collector_chain_report = report;
                            Ok(Some(handle))
                        }
                        Err(failure) => {
                            // **daemonが生き残っていても、ここでは捨てる**（`into_error`）。
                            // harness本体はこの経路を起動シーケンスで1度しか通らない（D-31）ので
                            // 保持しても使う相手が居ない。捨てるとパイプが閉じ、daemonは
                            // フェイルセーフ経路で自発撤収する。保持して再利用するのは
                            // 対話ループを持つポリシーエディタ側（D-56/D-60）だけである。
                            Err(WfpUnavailable::ChainLaunchHandshakeFailed(
                                failure.into_error().to_string(),
                            ))
                        }
                    }
                }
                // `plan_wfp`はパイプが無い組み合わせでは`Denied(ChainLaunchPipeMissing)`を
                // 返すのでここへは到達しない。到達したとしても無言で拒否へ落ちないよう、
                // 同じ経路として説明する（panicさせない側に倒す）。
                None => Err(WfpUnavailable::ChainLaunchPipeMissing),
            },
            // シナリオ(B): privhelperの連鎖起動は発生しなかった（fs-allowの昇格が不要だった等）。
            // 投機的パイプは使わない（`NetfilterHandle::start`が自前で新規パイプを作るため）、
            // dropして自動的に閉じる。**`start`より前にdropすること**——順序を入れ替えると
            // 使わないパイプを開いたまま新しいパイプを作ることになる。
            WfpPlan::DirectStart => {
                drop(wfp_prelude);
                match harness_sandbox::tier2a::netfilterd::NetfilterHandle::start(
                    harness_sandbox::tier2a::netfilterd::NetfilterPolicy {
                        session_profile:
                            harness_sandbox::tier2a::session_profile::current_profile_name(),
                        allow_loopback_tcp_ports: net_loopback_ports.tcp.clone(),
                        allow_loopback_udp_ports: net_loopback_ports.udp.clone(),
                        audit_log_path: net_proxy.audit_log_path.clone(),
                        // D-38: 上のシナリオ(A)と同じ理由でMCPサーバ分も一緒に張る。
                        mcp_profiles: mcp_netfilter_entries.clone(),
                        workspace_root: Some(workspace_root.clone()),
                        chain_launch_policy_learnd: policy_learn_pipe_name.clone(),
                    },
                ) {
                    Ok((handle, report)) => {
                        collector_chain_report = report;
                        Ok(Some(handle))
                    }
                    Err(failure) => {
                        // 上のシナリオ(A)と同じ理由で、生き残ったdaemonはここで捨てる（1度しか
                        // 通らない経路なので保持しても使わない）。
                        Err(WfpUnavailable::DirectStartFailed(
                            failure.into_error().to_string(),
                        ))
                    }
                }
            }
        };
        // **WFPが立たなかったことをユーザーへ説明する唯一の場所。** 文言は経路ごとではなく
        // `WfpUnavailable`が持つ（`wfp_outcome.rs`のモジュールdoc参照）。
        match outcome {
            Ok(handle) => handle,
            Err(path) => {
                eprintln!("{}", path.warning());
                None
            }
        }
    };
    #[cfg(not(windows))]
    let _net_wfp: Option<()> = None;
    // **「降格しました」という警告はもう出ない**（D-75）。降格が起きないので、ここに到達した
    // 時点で要求どおりのTierに居る。弱いTierに居るのはユーザーがそう選んだときだけなので、
    // 告知は「選んだものが何を守らないか」を言う下の2つになった。
    if shell_tier.tier == harness_core::ShellTier::Tier1 {
        eprintln!(
            "note: shell isolation tier is Tier1 because it was requested explicitly \
             (--sandbox tier1). Tier1 does not protect against reading confidential files \
             outside the workspace or outbound network exfiltration from run_shell child \
             processes (plans/DESIGN-SANDBOX.md §9-1). --require-sandbox=confidential refuses \
             to start at Tier1 rather than silently weakening this guarantee."
        );
    }
    if shell_tier.tier == harness_core::ShellTier::Tier0 {
        // **Tier0はもう「落ちる先」ではなく「選ぶ値」である**（D-75）。選んだ本人にだけ出る
        // 告知なので、驚きではなく確認として書く。
        eprintln!(
            "note: shell isolation is disabled because it was requested explicitly \
             (--sandbox tier0). run_shell child processes run with the same privileges as \
             harness itself: they can read and write anywhere your account can, and reach the \
             network. Nothing below the workspace level is enforced this session."
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
        // [BUG-101/§22.3] 台帳の`granted_sid`欄には**何も入れない**（2026-09-01）。
        // この欄が意味するのは「このパスへ**どのpackage SID宛に**ACEを付けたか」で、
        // 撤収側（`revoke_subjects`）は`S-1-15-2-`で始まるSIDしか列挙しない。主体移行が
        // 済んだいま、`--fs-allow`の穴にpackage SID宛のACEは**1本も無い**ので、
        // `None`＝「package SID宛には付与していない」が事実そのものである。
        // 宣言capabilityの撤収は`workspace-capability-ledger.json`の`declaration`欄を
        // 索引にした名前の付いた扉が担う。**移行前の記録はこの欄が積み増しなので消えない。**
        // **台帳の更新は1回にまとめる**（`record_fs_passthrough_grants`のdoc、残課題#37と同型）。
        // `Ledger::update`は1回ごとに全文の読取＋`.bak`への全文コピー＋全文書込を行うので、
        // 1件ずつ呼ぶとエントリ数の2乗でI/Oが増える。実測でこの台帳は66KBあり、宣言が数百件
        // ある構成では数百MBのI/Oになる。**人へ見せる行は1件ずつのまま**——まとめるのは
        // 台帳の書込だけで、どの穴が開いたかの説明は落とさない。
        let records: Vec<crate::fs_grants::FsPassthroughGrantRecord> = shell_tier
            .granted_passthrough
            .iter()
            .map(|granted| {
                let path = &granted.path;
                // [D-63] 宣言側から引くのは**範囲だけ**である。
                // [BUG-119] `forced`は宣言側から引かない——`--force-system-acl`は
                // セッション全域のスイッチで、**そのパスで特権を使ったかという事実ではない**。
                // 組み立ては`FsPassthroughGrantRecord::from_granted`が唯一の定義を持つ。
                let declared = fs_passthrough.iter().find(|fp| &fp.path == path);
                let path_str = path.to_string_lossy().into_owned();
                crate::fs_grants::FsPassthroughGrantRecord::from_granted(
                    granted,
                    declared,
                    settings_fs_paths
                        .contains(&path_str)
                        .then(|| workspace_root.to_string_lossy().into_owned()),
                )
            })
            .collect();
        crate::fs_grants::record_fs_passthrough_grants(&records);

        for granted in &shell_tier.granted_passthrough {
            let path = &granted.path;
            let writable = granted.writable;
            // [BUG-119] 警告も**実際に特権を使った付与にだけ**出す。
            // 「フラグを打ったか」で出していたので、特権が1度も使われていないパスにまで
            // 「DACLをバイパスして書き込んだ」という**事実でない警告**が並んでいた。
            let forced = granted.used_restore_privilege;
            if forced {
                eprintln!(
                    "WARNING: forced system ACL grant (--force-system-acl, SeRestorePrivilege): {} \
                     [{}] -- a sandbox read ACE was written into a system-protected path by \
                     bypassing its DACL (ownership unchanged). This ACE persists after harness \
                     exits; run `harness fs revoke {}` to undo.",
                    path.display(),
                    if writable { "rw" } else { "ro" },
                    path.display()
                );
            } else {
                // [§22.2.1] **この行が言う「終了後も残る」は仕様である。** 宛先SIDが宣言ごとの
                // capability SIDへ移り、共有され得る宣言のACEは永続になった（セッション終了時に
                // 剥がすと、同じワークスペースの並行セッションが互いの許可を落とす）。
                // 消える道は2本しかないので、両方名指しする——片方だけ書くと、
                // `.harness/settings.json`で宣言した人は「消し方が`fs revoke`しか無い」と読む。
                eprintln!(
                    "note: fs-allow granted: {} [{}] (this ACE persists after harness exits by \
                     design; it goes away when the declaration disappears from \
                     .harness/settings.json and harness starts again, or when you run \
                     `harness fs revoke {}`)",
                    path.display(),
                    if writable { "rw" } else { "ro" },
                    path.display()
                );
            }
        }
        // 拒否側も同じ理由で1回にまとめる（付与側だけ直すと、同じ形が片側に残る——`B-02`）。
        crate::fs_grants::record_fs_passthrough_denials(&shell_tier.denied_passthrough);
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

    // M15.7: OS監査によるFSアクセス拒否の収集（`--policy-learn`、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。
    //
    // **`ToolCtx`へは載せない。** 収集器は完全に受動的で`run_shell`の挙動を1つも変えないため、
    // モデルから見える制約は不変であり`EnvironmentFacts`の更新も要らない（`ToolCtx`へ足すと
    // 2段のコンパイル時ゲートが正しく発火してしまう）。`net_wfp`と同じくここでハンドルを持ち、
    // 同じ場所でteardownする。
    //
    // 起動経路は2つ（`privhelper`→`netfilterd`のシナリオ(A)/(B)と同じ構図）:
    // - **(A) 連鎖起動** — netfilterdが自分の昇格トークンのまま起こす。**追加UACなし**
    // - **(B) 直接runas** — netfilterdが居ない/連鎖が失敗したときのフォールバック。UACが1回
    #[cfg(windows)]
    let policy_learn: Option<
        harness_sandbox::tier2a::policy_learnd::client::PolicyLearnHandle,
    > = {
        use harness_sandbox::tier2a::policy_learnd::{client as learn_client, LearnPolicy};

        // 収集できない条件を先に潰し、残った場合だけ起動する。潰す条件ごとに理由を出すのは、
        // 「指定したのに何も集まらない」が黙って起きるのを防ぐため。
        let disabled_reason = if !policy_learn_enabled {
            Some(String::new()) // 明示的に無効。警告は出さない
        } else if shell_tier.tier != harness_core::ShellTier::Tier2a {
            Some(format!(
                "--policy-learn only collects denials from Tier2a (AppContainer) child                  processes; this session is running at {}, so nothing will be collected",
                shell_tier.tier.label()
            ))
        } else if sandbox_dir.is_none() {
            Some(
                "--policy-learn could not resolve a sandbox session directory to write                  fs-audit.jsonl into; collection is disabled this session"
                    .to_string(),
            )
        } else {
            None
        };

        if let Some(reason) = disabled_reason {
            if !reason.is_empty() {
                eprintln!("warning: {reason}");
            }
            drop(policy_learn_prelude);
            None
        } else {
            let sink = workspace_root
                .join(sandbox_dir.as_ref().expect("checked in disabled_reason"))
                .join("fs-audit.jsonl");
            let policy = LearnPolicy {
                session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
                workspace_root: workspace_root.clone(),
                fs_audit_log_path: sink,
                harness_pid: Some(std::process::id()),
                spawn_daemon_pid: spawn_daemon.as_ref().map(|daemon| daemon.daemon_pid()),
                record_all: false,
                // **通常運用ではargvを観測しない**（段階6d、§10.3）。ここはTier2aで走る
                // 普段のセッションなので、生成を見るのはSpawn Daemonであり、argv観測は
                // ポリシー定義モード（エディタのパス1）の候補生成専用の道具である。
                // **枠はマシン全体で8本しかない**ので、要らない経路で取らない。
                capture_argv: false,
            };

            // (A) netfilterdが**実際に収集器を起こせた**ときだけ接続を待つ（BUG-093）。
            //
            // 以前は「netfilterdが居る」だけを条件にしていたため、連鎖起動が失敗していても
            // 60秒待ってからでないと(B)へ移れなかった。昇格側が結末を`Applied`の応答で返す
            // ようになったので、**起きていないと分かっているものを待たない**。
            let chain_launched = collector_chain_report
                .as_ref()
                .is_some_and(|r| r.launched());
            if let Some(harness_sandbox::tier2a::netfilterd::ChainLaunchReport::Failed { reason }) =
                collector_chain_report.as_ref()
            {
                // **黙ってフォールバックしない。** UACが1回増える理由をここで言い切る。
                eprintln!(
                    "warning: netfilterd could not chain-launch the OS audit collector ({reason}); \
                     launching it directly instead (one extra UAC prompt)"
                );
            }
            let chained = match (policy_learn_prelude, net_wfp.is_some() && chain_launched) {
                (Some(prepared), true) => {
                    match learn_client::connect_after_chain_launch(
                        prepared.into_handle(),
                        policy.clone(),
                    ) {
                        Ok(handle) => Some(handle),
                        Err(e) => {
                            eprintln!(
                                "warning: the chain-launched collector did not answer ({e});                                  falling back to launching it directly (one UAC prompt)"
                            );
                            None
                        }
                    }
                }
                (prepared, _) => {
                    drop(prepared);
                    None
                }
            };

            // (B) フォールバック。D-43: 起こせなくても**セッションは止めない**。
            let handle = match chained {
                Some(handle) => Some(handle),
                None => match learn_client::start(policy) {
                    Ok(handle) => Some(handle),
                    Err(e) => {
                        eprintln!(
                            "warning: --policy-learn could not start the OS audit collector                              ({e}); the session continues without it. `harness policy suggest`                              still works from the preflight / network / CoW records."
                        );
                        None
                    }
                },
            };

            if let Some(handle) = handle.as_ref() {
                if !handle.etw_available() {
                    eprintln!(
                        "warning: the policy-learning collector started but could not open an                          ETW session; no denials will be collected this session (the reason is                          recorded in fs-audit.jsonl)"
                    );
                }
            }
            handle
        }
    };

    // MCP手順5（`startup::mcp`のモジュールdoc）: **WFPの適用が終わったここで初めて**
    // サーバのプロセスを起こす。
    //
    // その前に、network要求のあるサーバをWFPの強制なしに起動しないことを確認する。WFPが無いと
    // `internetClient` capabilityを持つサーバは専用プロキシを無視して直接外へ出られるため、
    // 「宛先を絞ったつもりで絞れていない」状態になる。`run_shell`側が
    // `should_grant_tier2a_network_capability`で採っているのと同じfail-closedである。
    let mut mcp_startup = mcp_startup;
    #[cfg(windows)]
    if net_wfp.is_none() {
        mcp_startup.drop_servers_needing_egress_enforcement();
    }
    #[cfg(not(windows))]
    mcp_startup.drop_servers_needing_egress_enforcement();

    let (mut mcp_runtime, mcp_facts, _mcp_proxies) =
        super::mcp::launch_mcp_servers(
            mcp_startup,
            &mut tools,
            #[cfg(windows)]
            spawn_daemon.as_ref(),
        );

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
        cow_diff_layer_dir: write_mode.diff_layer_dir().map(|p| p.to_path_buf()),
        mcp_servers: mcp_facts,
    };

    let mut state = ConversationState::new(harness_engine::system_blocks_for(&tool_ctx));
    state.messages = session_messages;

    // `census`ツール（`plans/PLAN-CENSUS-ENGINE.md`段階3）をここで1箇所だけ登録する。
    // headless/TUI分岐の直前・MCPツール登録より後（`tools`が完成した時点）が唯一の生産
    // コード地点で、`ToolRegistry::with_builtin_tools()`を直接叩くテスト群
    // （`golden_transcript.rs`等）はこの経路を通らないため無改造のまま影響を受けない。
    //
    // `provider`をここで`Arc`化するのは、`census`の`call()`が`'static`な
    // `Arc<dyn LlmProvider>`を要求するため（内側の`TurnExecutor`をツール呼び出しの
    // たびに新しく組み立てる必要があり、外側のスタックフレームより長生きする必要がある）。
    let provider: Arc<dyn LlmProvider> = Arc::from(provider);
    // `census`自身を含まないスナップショット——このクローンを取った**後**に`census`を
    // 登録することで、内側の`TurnExecutor`が`census`を再帰的に呼び出せる経路を構造的に
    // 作らない（`harness_cognition::census::tool`のモジュールdoc「再帰的自己呼び出しの防止」）。
    let inner_tools = Arc::new(tools.clone());
    // 内側のゲートは常に`PermissionArbiter`（headless相当のポリシー判定）を使う。TUIの
    // `InteractiveGate`（モーダル確認）は経由しない——`Phase::Collect`の候補ツールが
    // `ToolSelection::ReadOnly`に限定されている限り、`PermissionArbiter::classify`は
    // gate実装によらず常に`Allow`となるため実害が無い（詳細は`CensusTool`のモジュールdoc）。
    let census_gate: Arc<dyn PermissionGate> = Arc::new(arbiter.clone());
    tools.register(Arc::new(CensusTool::new(
        provider.clone(),
        census_gate,
        inner_tools,
        cognition.budgets().clone(),
        model.clone(),
        compaction.context_window,
    )));

    // `recall`ツール（`plans/PLAN-RECALL-MEMORY.md`段階3）。`census`と異なり内部で新しい
    // `TurnExecutor`を組まない（`search`は決定的検索のみ、`remember`はファイル書込みのみ）
    // ため、再帰対策（レジストリのスナップショット）は不要。`CognitionLevel`に関わらず常時
    // 登録する（未使用時のコストはゼロ、`Off`の等価性を壊さない）。
    tools.register(Arc::new(RecallTool::new(
        cognition.recall_allow_unversioned(),
    )));

    // `/workspace`で選ばれた移動先。ここでは**まだ起動しない**——teardownを全部通した後で
    // 起こす（`startup::relaunch`のモジュールdoc「置き場所が末尾でなければならない」）。
    let mut relaunch_into: Option<PathBuf> = None;
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
                degeneracy,
                cli.output_format,
                sandbox_choice_of(cli.sandbox).wants_warm_tier3(),
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
                degeneracy,
                cli.provider.label().to_string(),
                state,
                session,
                sessions_dir,
                enter_submits,
                resume_wants_picker,
                sandbox_choice_of(cli.sandbox).wants_warm_tier3(),
                &mut relaunch_into,
            )
            .await
        }
    };

    // MCPサーバを落とす（WFPのteardownより前）。**先に喋る側を止める**——WFPを先に外すと、
    // 落ちるまでのわずかな間だけ出口強制の無いサーバが生きていることになる。プロセスの生存自体は
    // Job Objectに紐付いているので、ここを通らずに落ちた場合も道連れで終了する。
    mcp_runtime.shutdown();

    // 子とMCPを止めた後、WFP・収集器より先に生成者を畳む。
    #[cfg(windows)]
    if let Some(daemon) = spawn_daemon.as_ref() {
        daemon.shutdown();
    }

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

    // M15.7: OS監査収集器の撤収。ここへ到達せずに落ちた場合（クラッシュ・Ctrl+C）は、
    // `PolicyLearnHandle`のDropがパイプを閉じ、収集器側の`ReadFile`が`ERROR_BROKEN_PIPE`に
    // なって自発的に撤収する（netfilterdと同じフェイルセーフ）。
    #[cfg(windows)]
    if let Some(handle) = policy_learn {
        match handle.stop() {
            Ok(written) => {
                if written > 0 {
                    eprintln!(
                        "note: --policy-learn recorded {written} denied file access(es); run \
                         `harness policy suggest` to see what to allow"
                    );
                }
            }
            Err(e) => {
                eprintln!("warning: failed to cleanly tear down the policy-learning collector: {e}")
            }
        }
    }

    // D-37: このセッションのAppContainerプロファイルと、それ宛に付けたACEを撤収する。
    // 撤収順序（ACE→最後にプロファイル）は`session_profile`側が保証する。ここへ到達せずに
    // 落ちた場合（クラッシュ・Ctrl+C）は、次回起動時の`preflight`のGCが同じ経路で回収する
    // ——だからこの呼び出しは「速く片付けるための最適化」であって、正しさの要件ではない。
    #[cfg(windows)]
    {
        let outcome = harness_sandbox::tier2a::session_profile::end_session(
            &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
        );
        // [BUG-103] **剥がせなかったノードは名前で出す。** かつてここは戻り値の無い呼び出しで、
        // 撤収が1件も成功しなくても何も出なかった——`%LOCALAPPDATA%\Packages`に継承つきRWDが
        // 残ったまま誰も気付かなかった機序の半分がこれである（B-09）。
        if let Some(summary) = outcome.summary() {
            eprintln!("note: {summary}");
        }
    }

    // `/workspace`: **ここまでの撤収を全部通した後**に起こす（`startup::relaunch`）。
    // 起こせなくても普通に終了するだけ——再起動できないことと端末を壊すことは別である。
    if let Some(workspace) = relaunch_into {
        if let Err(e) = super::relaunch::relaunch_in(&workspace) {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    }

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
    degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    output_format: OutputFormat,
    tier3_warm: bool,
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
    // BUG-075: 生の`len()`を控えるとターン中の圧縮でスライスがパニックする。
    let before_run = state.mark();

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
            degeneracy,
        },
        output_format,
        &mut stdout,
    )
    .await;
    // 圧縮で履歴の先頭が畳まれた場合は、増分追記では足りない——ファイルには畳む前の履歴が
    // 残り続け、`--resume`が圧縮前の長い会話へ戻ってしまう。
    let _ = if state.folded_since(before_run) {
        session.append_checkpoint(&state.messages)
    } else {
        session.append_messages(state.since(before_run))
    };

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
    provider: Arc<dyn LlmProvider>,
    tools: ToolRegistry,
    tool_ctx: ToolCtx,
    arbiter: PermissionArbiter,
    cognition: CognitiveOrchestrator,
    model: String,
    max_turns: usize,
    compaction: harness_engine::compaction::CompactionPolicy,
    degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    provider_label: String,
    state: ConversationState,
    session: harness_engine::SessionStore,
    sessions_dir: PathBuf,
    enter_submits: bool,
    resume_wants_picker: bool,
    tier3_warm: bool,
    // `/workspace`の移動先。TUIが自分でプロセスを起こすと、呼び出し元（`stage_run_agent`）の
    // teardown順序（MCP停止→WFP撤収→policy-learn撤収→`end_session`）を迂回することになるので、
    // 「どこへ移りたいか」だけを持ち帰らせる。
    relaunch_into: &mut Option<PathBuf>,
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
        degeneracy,
        provider_label,
        state,
        session,
        sessions_dir,
        enter_submits,
        resume_wants_picker,
        tier3_warm,
    )
    .await;

    match result {
        Ok(harness_tui::RunOutcome::Quit) => ExitCode::SUCCESS,
        Ok(harness_tui::RunOutcome::Relaunch { workspace }) => {
            *relaunch_into = Some(workspace);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tui error: {e}");
            ExitCode::FAILURE
        }
    }
}
