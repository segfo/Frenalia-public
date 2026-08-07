//! 起動パイプライン Stage4: サンドボックス関連の確定。
//!
//! staging mode・`sandbox_dir`・`read_scope`・net proxy/app・`require_sandbox`・
//! fs passthrough・privhelper昇格・WFP連鎖パイプ・`write_mode`・`select_tier`。

use super::*;
use super::session::SessionOpened;

/// [`stage_prepare_sandbox`]の出力。Stage5（`stage_run_agent`）が必要とする値を運ぶ。
pub(super) struct SandboxPrepared {
    pub(super) cli: Cli,
    pub(super) workspace_root: PathBuf,
    pub(super) resume_wants_picker: bool,
    pub(super) provider: Box<dyn LlmProvider>,
    pub(super) model: String,
    pub(super) max_turns: usize,
    pub(super) compaction: harness_engine::compaction::CompactionPolicy,
    pub(super) degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    pub(super) enter_submits: bool,
    pub(super) tools: ToolRegistry,
    pub(super) arbiter: PermissionArbiter,
    pub(super) cognition: CognitiveOrchestrator,
    pub(super) sessions_dir: PathBuf,
    pub(super) session: harness_engine::SessionStore,
    pub(super) session_messages: Vec<harness_core::Message>,
    pub(super) staging_mode: StagingMode,
    pub(super) sandbox_dir: Option<PathBuf>,
    pub(super) read_scope: harness_core::ReadScopeConfig,
    pub(super) net_proxy: NetProxyConfig,
    pub(super) net_app: harness_core::NetAppPolicy,
    pub(super) run_shell_path_extra: Vec<String>,
    pub(super) fs_passthrough: Vec<harness_sandbox::FsPassthrough>,
    pub(super) settings_fs_paths: std::collections::HashSet<String>,
    /// M15.7: セッション中のOS監査収集を有効にするか（`--policy-learn`→`settings.policy.learn`→false）。
    /// **`ToolCtx`には載せない**——収集器は受動的で`run_shell`の挙動を変えないため。
    pub(super) policy_learn: bool,
    #[cfg(windows)]
    pub(super) wfp_prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe>,
    #[cfg(not(windows))]
    pub(super) wfp_prelude: Option<String>,
    pub(super) write_mode: harness_sandbox::WorkspaceWriteMode,
    pub(super) shell_tier: harness_core::ShellTierSelection,
    /// MCPサーバ宣言（M15.5）。承認照合・起動はStage5（`stage_run_agent`）が、Tier確定と
    /// WFP適用の間で行う（順序が本質、`startup::mcp`のモジュールdoc参照）。
    pub(super) mcp_decls: Vec<harness_mcp::McpServerDecl>,
    /// Streamable HTTPのセッションゲート（M15.6、D-49）。**ユーザ層設定とCLIからしか来ない**
    /// ——プロジェクト層の分は`harness_config::clamp_project_mcp_http_gates`が剥がしている。
    pub(super) mcp_gates: harness_mcp::McpGates,
}

/// staging mode・`sandbox_dir`・`read_scope`・net proxy/app・`require_sandbox`・
/// fs passthrough・privhelper昇格・WFP連鎖パイプ・`write_mode`・`select_tier`。
pub(super) fn stage_prepare_sandbox(session_opened: SessionOpened) -> Result<SandboxPrepared, ExitCode> {
    let SessionOpened {
        cli,
        workspace_root,
        resume_wants_picker,
        settings,
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
        session,
        session_messages,
        forked_from_session_id,
    } = session_opened;

    // `/workspace`の再起動で起こされた子は、ここから先（`select_tier`→`preflight`）へ入る前に
    // 親の終了を待つ。名前付きmutex（workspaceのモードマーカー・CoWのセッションマーカー）は
    // プロセス寿命に紐付いているので、親が生きているうちにpreflightへ入ると「使用中」と
    // 誤判定され得る（`startup::relaunch`のモジュールdoc）。
    if let Some(pid) = cli.wait_for_pid {
        super::relaunch::wait_for_parent_exit(pid);
    }

    // 書込ステージング設定（M10・D-29）。`sandbox_dir`は`session.id()`確定後でなければ組めない
    // ため、ここで`ToolCtx`を構築する。既定（フラグ無指定）を含め`Live`実効時はオーバーレイ
    // 自体を使わない（`sandbox_dir: None`、M9までの直接実FSアクセスとバイト等価・監査ログも
    // 作らない）。書込/読取の実防御はシェル隔離Tier（既定Tier2a=AppContainer）に委ねる。
    let staging_mode = resolve_staging_mode(cli.live, cli.staged, cli.workspace_commit);
    let sandbox_dir = if staging_mode == StagingMode::Live {
        None
    } else {
        Some(sandbox_dir_for_session(&session.id()))
    };
    // **ここで実際に作る。** このディレクトリは`net-audit.jsonl`/`fs-audit.jsonl`の置き場として
    // 昇格ヘルパー（`harness-netfilterd`・`harness-policy-learnd`）へ渡され、受け取った側は
    // D-44の検証で`canonicalize`する——存在しないパスは正規化できないので**起動が失敗する**。
    // 監査ログの書き手はどちらも「最初の1件を書くときに親を`create_dir_all`する」遅延作成
    // （`net_proxy.rs`の`push`）なので、新規ワークスペースでは検証の時点でまだ存在しない。
    // その結果`--net-allow-domain`はWFPを起動できずfail-closed（通信が一切できない）になり、
    // `--policy-learn`は収集器を起動できずに黙って無効化されていた。
    // 遅延作成に頼れるのは書き手が1人のときだけで、**パスを他プロセスへ渡す瞬間から
    // 「存在すること」が契約になる**。
    if let Some(dir) = &sandbox_dir {
        let path = workspace_root.join(dir);
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!(
                "warning: could not create the sandbox session directory {} ({e}); \
                 network/FS audit sinks that depend on it will be unavailable this session",
                path.display()
            );
        }
    }

    // `--fork-session`: 元セッションの未適用変更も分岐先へ持っていく。TUIの`/fork`と同じ
    // `session_scope::fork_overlay`を通す——**同じ状態（forkされたセッション）を作り得る経路が
    // 2つある**ので、片方だけ実装すると「CLIでforkしたときだけ変更が見えない」形の穴になる
    // （`bug-pattern-rules` B-06）。`--cow`のACE付与は`preflight`が後で行うため、ここでは
    // まだ`prepare_scope`のWindows分岐へ入らない`--staged`系だけが対象になる。
    if let Some(source_id) = &forked_from_session_id {
        let template = harness_sandbox::session_scope::ScopeTemplate::new(staging_mode, cli.cow);
        let (from, to) = (
            template.scope_for(source_id),
            template.scope_for(&session.id()),
        );
        match harness_sandbox::session_scope::fork_overlay(&workspace_root, &from, &to) {
            Ok(0) => {}
            Ok(copied) => eprintln!(
                "note: carried {copied} overlay file(s) from {source_id} into the forked session \
                 (unapplied changes stay reviewable in both)"
            ),
            // 会話のforkは既に済んでいる。ここで起動を止めると「forkはできたが起動できない」に
            // なるので、変更が分岐先へ来ていないことだけを名指しして続ける（元セッション側に
            // 残っているので失われてはいない）。
            Err(e) => eprintln!(
                "warning: could not carry {source_id}'s unapplied changes into the forked session \
                 ({e}); they remain reviewable with `harness changes --session {source_id}`"
            ),
        }
    }

    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    // 協調プロキシ設定（M12補遺、D-15）。CLI `--net-allow-domain`（繰り返し）と
    // `.harness/settings.json`の`net.allow_domains`を和集合でマージする（重複除去）。
    let mut net_proxy = settings
        .net
        .clone()
        .unwrap_or_default()
        .to_net_proxy_config();
    if let Err(e) = validate_and_merge_net_allow_domains(&mut net_proxy, &cli.net_allow_domain) {
        eprintln!("error: invalid network domain policy: {e}");
        return Err(ExitCode::FAILURE);
    }
    if net_proxy.audit_log_path.is_none() {
        if let Some(dir) = &sandbox_dir {
            net_proxy.audit_log_path = Some(workspace_root.join(dir).join("net-audit.jsonl"));
        }
    }

    // アプリ単位network制御（軸1、D-10/D-11）。CLI `--net-allow-app`（繰り返し）と
    // `.harness/settings.json`の`net.allow_apps`を和集合でマージする（重複除去、net_proxyと同形）。
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }
    // M15.7: `--policy-learn`が最優先、無指定なら`settings.json`の`policy.learn`、既定false
    // （オプトイン。有効化するとUACが1回出るため、黙って有効にはしない）。
    let policy_learn = cli
        .policy_learn
        .unwrap_or_else(|| settings.policy.clone().unwrap_or_default().learn_enabled());

    let run_shell_path_extra = settings.run_shell.clone().unwrap_or_default().path_extra();

    // MCPサーバ宣言（M15.5）。**ここでは解釈だけ**で、承認照合も起動も行わない
    // （`startup::mcp`のモジュールdoc参照）。綴り間違いは黙って無視せず起動を止める——
    // 「設定したのに効かない」に気付けないと、裏取りしたつもりで裏取りしていない結論を
    // 受け取ることになる。
    let mcp_decls = match harness_mcp::parse_mcp_settings(settings.mcp.as_ref()) {
        Ok(decls) => decls,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // M15.6（D-49）: Streamable HTTPのゲート。`settings.mcp`はここへ来る時点で
    // プロジェクト層の分が剥がされている（`harness_config::clamp_project_mcp_http_gates`）ので、
    // 残っているのはユーザ層の値だけ。そこへCLIフラグを重ねる。
    let mcp_gates = match build_mcp_gates(&cli, settings.mcp.as_ref()) {
        Ok(gates) => gates,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // シェル隔離Tier選択（M12、`plans/DESIGN-SANDBOX.md` §6/§7 D-03）。`--require-sandbox`指定時は
    // 自動降格せず起動を拒否する（既存の`--dangerously-allow`と同じfail-fastパターン）。
    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());

    // confidential（外部持出し経路を作らない明示拒否モード＝通信許可リストを無効化する上位モード）
    // と net-allow-domain/net-allow-app（通信を開く）は意味的に矛盾するため、黙って無視/弱めず起動を拒否する
    // （`--require-sandbox`のsatisfiesと同じfail-fast思想、`plans/DESIGN-SANDBOX-APPPOLICY.md` §7）。
    if require_sandbox == RequireSandbox::Confidential
        && (!net_proxy.allow_domains.is_empty() || !net_app.allow_apps.is_empty())
    {
        eprintln!(
            "error: network allow rules (--net-allow-domain / --net-allow-app / settings net.*) \
             conflict with --require-sandbox=confidential (confidential \
             mode denies all outbound network unconditionally; refusing to start rather than \
             silently ignoring network allow rules or weakening the confidentiality guarantee)"
        );
        return Err(ExitCode::FAILURE);
    }

    // fs passthrough allowlist（軸2・D-13）。CLI `--fs-allow`（繰り返し）と
    // `.harness/settings.json`の`fs.allow`を和集合でマージする（重複除去、net_appと同形）。
    // 各要素は`<path>[:rw]`（末尾`:rw`が無ければread-only既定、D-13）。パスは`workspace_root`
    // 基準で絶対化する（既に絶対パスなら`Path::join`はそのまま採用する）。
    let settings_fs_entries: Vec<(String, harness_config::FsAccess)> =
        settings.fs.clone().unwrap_or_default().to_fs_passthrough();
    // このワークスペースが現在`.harness/settings.json`経由で宣言しているfs passthroughパスの
    // 絶対パス集合（D-27）。`--fs-allow`由来のパスは含めない（対象は設定ファイル経由の宣言のみ）。
    // `fs_passthrough`と同じ`workspace_root.join`で絶対化し、台帳に記録される文字列表現と一致させる。
    let settings_fs_paths: std::collections::HashSet<String> = settings_fs_entries
        .iter()
        .map(|(path, _)| workspace_root.join(path).to_string_lossy().into_owned())
        .collect();
    let mut fs_allow_raw: Vec<(String, harness_config::FsAccess)> = settings_fs_entries;
    for entry in &cli.fs_allow {
        let (path, access) = match entry.strip_suffix(":rw") {
            Some(p) => (p.to_string(), harness_config::FsAccess::ReadWrite),
            None => (entry.clone(), harness_config::FsAccess::ReadExec),
        };
        if !fs_allow_raw.iter().any(|(p, _)| p == &path) {
            fs_allow_raw.push((path, access));
        }
    }
    // --force-system-acl（D-19）はread-only専用（システムディレクトリへの書込強制は危険すぎる）。
    // `:rw`エントリが1つでもあれば起動を拒否する（fail-fast、--require-sandboxのD7と同じ思想）。
    if cli.force_system_acl
        && fs_allow_raw
            .iter()
            .any(|(_, access)| *access == harness_config::FsAccess::ReadWrite)
    {
        eprintln!(
            "error: --force-system-acl requires read-only --fs-allow entries (a :rw entry is \
             present); forcing writable ACEs into system-protected paths is refused. Drop :rw or \
             drop --force-system-acl."
        );
        return Err(ExitCode::FAILURE);
    }
    let fs_passthrough: Vec<harness_sandbox::FsPassthrough> = fs_allow_raw
        .into_iter()
        .map(|(path, access)| harness_sandbox::FsPassthrough {
            path: workspace_root.join(&path),
            access: to_sandbox_fs_access(access),
            forced: cli.force_system_acl,
        })
        .collect();
    if !fs_passthrough.is_empty() && !cfg!(windows) {
        eprintln!(
            "warning: --fs-allow / fs.allow is only supported on Windows (Tier2a); ignored on \
             this OS"
        );
    }

    // fs passthrough ACEのライフサイクル自動整合（D-27）。`.harness/settings.json`から
    // 消えたエントリのうち、どのワークスペースからも参照されなくなったものだけACEを撤収する
    // （複数ワークスペースが同じパスを共有宣言している場合は、他が参照している限り残す）。
    // Tier2aが実際に選択されるかどうかとは独立に、起動のたびに毎回行う（設定変更の反映は
    // Tierの降格有無と無関係のため）。`select_tier`（preflight）より前に行う。
    #[cfg(windows)]
    crate::fs_grants::reconcile_fs_ledger_for_workspace(&workspace_root, &settings_fs_paths);

    // D7: --require-sandboxとの矛盾チェック。write-containmentは範囲外書込を禁じるため:rwのみ
    // 拒否（:roは書込に無関係で許可）。confidentialは範囲外を読めない保証のため:ro/:rwいずれも
    // 拒否する（外部読取穴がconfidentialの機密性保証と正面から矛盾するため、
    // `--net-allow-app`×confidentialと同じfail-fast思想）。
    let fs_has_write = fs_passthrough.iter().any(|fp| fp.access.is_read_write());
    match require_sandbox {
        RequireSandbox::WriteContainment if fs_has_write => {
            eprintln!(
                "error: --fs-allow with :rw conflicts with --require-sandbox (write-containment \
                 forbids writes outside the workspace; use read-only --fs-allow entries instead, \
                 or drop --require-sandbox)"
            );
            return Err(ExitCode::FAILURE);
        }
        RequireSandbox::Confidential if !fs_passthrough.is_empty() => {
            eprintln!(
                "error: --fs-allow conflicts with --require-sandbox=confidential (confidential \
                 mode denies reading outside the workspace unconditionally; even read-only \
                 --fs-allow breaks this guarantee; refusing to start rather than silently \
                 weakening it)"
            );
            return Err(ExitCode::FAILURE);
        }
        _ => {}
    }

    if cli.tier1 && !cfg!(windows) {
        eprintln!("error: --tier1 is only supported on Windows");
        return Err(ExitCode::FAILURE);
    }

    // WFP 出口強制（Layer2、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）の
    // named pipeを、`select_tier`（内部で`preflight`を呼ぶ）より前に用意しておく。
    // Tier2aはフラグ無しで既定プローブされるため、ドメインポリシー監査が有効な場合は常に投機的に用意しておく
    // （そうでなければWFPは不要＝シナリオ(C)、パイプすら作らずUACゼロを保つ）。ここで作った
    // パイプ名は、`preflight`経由で特権分離ヘルパーへ「処理完了後この名前でnetfilterdを
    // 連鎖起動してほしい」という指示として渡す（シナリオ(A)）。実際にTier2aへ降格せずに
    // 終わる、またはprivhelperへの委譲が発生しなかった場合（シナリオ(B)/(C)）は、この
    // パイプは未使用のまま閉じるか、`NetfilterHandle::start`の直接起動へ切り替える
    // （下記`net_wfp`解決を参照）。
    #[cfg(windows)]
    let wfp_prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe> =
        if net_proxy.domain_policy_enabled {
            match harness_sandbox::tier2a::netfilterd::prepare_pipe() {
                Ok(prepared) => Some(prepared),
                Err(e) => {
                    eprintln!(
                        "warning: failed to prepare WFP netfilterd pipe (Layer2 network \
                         enforcement will be unavailable this session, falling back to the \
                         cooperative proxy only): {e}"
                    );
                    None
                }
            }
        } else {
            None
        };
    #[cfg(not(windows))]
    let wfp_prelude: Option<String> = None;
    #[cfg(windows)]
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());
    #[cfg(not(windows))]
    let wfp_chain_pipe: Option<String> = None;

    if cli.cow && !cfg!(windows) {
        eprintln!("error: --cow is only supported on Windows (Tier2a/AppContainer)");
        return Err(ExitCode::FAILURE);
    }
    let write_mode = match resolve_write_mode(cli.cow, &session.id()) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let shell_tier = match select_tier(
        require_sandbox,
        &workspace_root,
        cli.vm_sandbox,
        cli.tier1,
        &fs_passthrough,
        wfp_chain_pipe,
        &write_mode,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return Err(ExitCode::FAILURE);
        }
    };

    Ok(SandboxPrepared {
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
        session,
        session_messages,
        staging_mode,
        sandbox_dir,
        read_scope,
        net_proxy,
        net_app,
        run_shell_path_extra,
        fs_passthrough,
        settings_fs_paths,
        policy_learn,
        wfp_prelude,
        write_mode,
        shell_tier,
        mcp_decls,
        mcp_gates,
    })
}

/// Streamable HTTPのセッションゲート（D-49）を、ユーザ層設定とCLIフラグから組み立てる。
///
/// - 有効化: どちらか一方で足りる（`net_proxy`/`net_app`と同じ「CLIが上乗せ」の形）
/// - 宛先allowlist: 両者の**和集合**。CLIで足せるが、設定から取り除くことはできない
/// - 平文: **CLIだけ**。設定ファイルにも宣言にも同等のスイッチを置かない
fn build_mcp_gates(
    cli: &Cli,
    mcp_settings: Option<&serde_json::Value>,
) -> Result<harness_mcp::McpGates, String> {
    let settings = harness_mcp::parse_mcp_http_gates(mcp_settings)?;

    let mut domains = settings.http_allow_domains;
    for domain in &cli.allow_mcp_http_domain {
        // 構文は`--net-allow-domain`と同一（`normalize_domain_pattern`）。
        let domain = normalize_domain_pattern(domain)?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }

    let enabled = settings.allow_streamable_http || cli.allow_mcp_http;
    if !enabled && (!cli.allow_mcp_http_domain.is_empty() || cli.allow_mcp_http_plaintext) {
        eprintln!(
            "warning: --allow-mcp-http-domain/--allow-mcp-http-plaintext have no effect without \
             --allow-mcp-http (or \"mcp\": {{ \"allow_streamable_http\": true }} in your user \
             settings.json)"
        );
    }

    Ok(harness_mcp::McpGates {
        streamable_http_enabled: enabled,
        http_endpoints: harness_mcp::EndpointGates {
            allow_domains: harness_core::DomainPolicy::new(domains),
            plaintext_allowed: cli.allow_mcp_http_plaintext,
        },
        http_ca_bundle: settings.http_ca_bundle.map(PathBuf::from),
    })
}

