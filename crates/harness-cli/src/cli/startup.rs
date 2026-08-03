//! 起動パイプライン本体。
//!
//! 「昇格チェック → `.env`読込 → 引数parse → 資格情報不要なサブコマンドの早期dispatch →
//! セッション解決 → provider/model → tools/permissions → セッション永続化 →
//! staging/read_scope/net → シェル隔離Tier選択 → 実行」という線形の流れ。

use super::*;


/// [`stage_parse_args`]の出力。Stage2（`stage_configure`）以降が必要とする値だけを運ぶ。
struct ParsedArgs {
    cli: Cli,
    workspace_root: PathBuf,
    resume_id: Option<String>,
    resume_wants_picker: bool,
}

/// 昇格チェック警告・`.env`・`Cli::parse`・`workspace_root`解決・資格情報不要な
/// サブコマンドの早期dispatch・`--resume`の妥当性検査。
///
/// `Err(ExitCode)`は「エラー」に限らない――早期dispatch・`--list-sessions`のように、
/// 正常終了として即座に返すべき`ExitCode`もここに含む（[`run`]側は`Ok`/`Err`を区別せず
/// そのまま返す）。
fn stage_parse_args() -> Result<ParsedArgs, ExitCode> {
    // 本体プロセスが管理者権限で起動されていないかを確認する（D-16、
    // `plans/DESIGN-SANDBOX-PRIVSEP.md` §5.3）。harness本体は常に非管理者トークンで動作する
    // 設計であり、ヘルパー機構が無い間は実害が無いが（WFP/VHDX自体を使わないため）、
    // 「本体が管理者ならヘルパー経由でない直接呼び出しに倒れていないか」を明示的に確認する
    // 材料として警告ログを残す。拒否はしない。
    #[cfg(windows)]
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        eprintln!(
            "warning: harness is running with an elevated (administrator) token. harness is \
             designed to always run as a non-administrator process; privileged operations \
             (e.g. `harness fs grant-traverse`) should go through the privilege-separation \
             helper (D-16, plans/DESIGN-SANDBOX-PRIVSEP.md §5.3), not this elevated \
             process directly."
        );
    }

    // カレントディレクトリの`.env`があれば読み込み、プロセスのenvへ反映する（既存の環境変数は
    // 上書きしない、§設定とシークレット「ユーザ/プロジェクト設定」相当の簡易版）。無ければ無視する。
    let _ = dotenvy::dotenv();

    let mut cli = Cli::parse();

    let workspace_root = match cli.cwd.clone() {
        Some(dir) => dir,
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("failed to resolve current directory: {e}");
                return Err(ExitCode::FAILURE);
            }
        },
    };
    harness_config::ensure_project_settings_file(&workspace_root);

    // `apply`/`changes`/`discard`サブコマンドはプロバイダ資格情報を一切必要としないため、
    // 他のあらゆる検証より前に処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    // `.take()`（`mem::replace`でNoneに戻す）を使うのは、`Commands::Prompt`分岐で`&cli`を
    // 丸ごと借用したいため。単純な`cli.command`のムーブだと`cli.command`フィールドだけが
    // 部分ムーブされ、以降`&cli`が取れなくなる。
    if let Some(cmd) = cli.command.take() {
        return Err(match cmd {
            Commands::Fs { action } => crate::fs_grants::run_fs_subcommand(action),
            Commands::Tier3 { action } => run_tier3_subcommand(action),
            Commands::Cow { action } => run_cow_subcommand(action),
            Commands::Net { action } => run_net_subcommand(action, &workspace_root),
            Commands::Prompt => run_prompt_subcommand(&cli, &workspace_root),
            other => run_sandbox_subcommand(other, &workspace_root),
        });
    }

    // `--list-sessions`はプロバイダ資格情報を一切必要としないため、他のあらゆる検証より前に
    // 処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    if cli.list_sessions {
        let sessions_dir = workspace_root.join(".harness").join("sessions");
        return Err(match harness_engine::SessionStore::list(&sessions_dir) {
            Ok(summaries) => {
                print_session_list(&summaries, cli.output_format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("failed to list sessions in {}: {e}", sessions_dir.display());
                ExitCode::FAILURE
            }
        });
    }

    // 引数なし`--resume`（値省略、空文字列扱い）はヘッドレスでは非対話原則により拒否する。
    // ピッカーはTTYが要る対話TUIでのみ意味を持つ（§非対話モード「ヘッドレスモードは対話
    // プロンプトを一切出さない」）。
    let resume_wants_picker = cli.resume.as_deref() == Some("");
    if resume_wants_picker && cli.print.is_some() {
        eprintln!("--resume without a value opens an interactive picker and is not supported with -p/--print; pass --resume <id> explicitly");
        return Err(ExitCode::FAILURE);
    }
    let resume_id = cli.resume.clone().filter(|s| !s.is_empty());

    if cli.fork_session && resume_id.is_none() && !cli.continue_session {
        eprintln!("--fork-session requires --resume <id> or --continue");
        return Err(ExitCode::FAILURE);
    }
    if cli.fork_session && resume_wants_picker {
        eprintln!("--fork-session cannot be combined with a bare --resume (use the picker's 'f' key instead)");
        return Err(ExitCode::FAILURE);
    }

    Ok(ParsedArgs {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
    })
}

/// [`stage_configure`]の出力。Stage3（`stage_open_session`）以降が必要とする値を運ぶ。
struct Configured {
    cli: Cli,
    workspace_root: PathBuf,
    resume_id: Option<String>,
    resume_wants_picker: bool,
    settings: harness_config::Settings,
    provider: Box<dyn LlmProvider>,
    model: String,
    max_turns: usize,
    enter_submits: bool,
    tools: ToolRegistry,
    arbiter: PermissionArbiter,
}

/// `settings.json`読込・`early_require_sandbox`とconfidentialの矛盾チェック・provider構築・
/// model解決・`ToolRegistry`・allowlist・`PermissionArbiter`。
fn stage_configure(parsed: ParsedArgs) -> Result<Configured, ExitCode> {
    let ParsedArgs {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
    } = parsed;

    // §設定とシークレット「既定 → ユーザ → プロジェクト → CLIフラグ（最優先）」。CLIフラグが
    // 明示されていればそちらを使い、無ければ`settings.json`階層へフォールバックする
    // （`permission_mode`/`output_format`はclapの`default_value_t`で常に値を持つため
    // このフォールバックの対象外、CLI値をそのまま使う）。
    let settings = harness_config::Settings::load(&workspace_root);

    let early_require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());
    if early_require_sandbox == RequireSandbox::Confidential {
        let mut early_net_proxy = settings
            .net
            .clone()
            .unwrap_or_default()
            .to_net_proxy_config();
        if let Err(e) =
            validate_and_merge_net_allow_domains(&mut early_net_proxy, &cli.net_allow_domain)
        {
            eprintln!("error: invalid network domain policy: {e}");
            return Err(ExitCode::FAILURE);
        }
        let mut early_net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
        for app in &cli.net_allow_app {
            if !early_net_app.allow_apps.contains(app) {
                early_net_app.allow_apps.push(app.clone());
            }
        }
        if !early_net_proxy.allow_domains.is_empty() || !early_net_app.allow_apps.is_empty() {
            eprintln!(
                "error: network allow rules (--net-allow-domain / --net-allow-app / settings \
                 net.*) conflict with --require-sandbox=confidential (confidential mode denies \
                 all outbound network unconditionally; refusing to start rather than silently \
                 ignoring network allow rules or weakening the confidentiality guarantee)"
            );
            return Err(ExitCode::FAILURE);
        }
    }

    let provider = match build_provider(
        cli.provider,
        cli.base_url.clone(),
        #[cfg(feature = "e2e-mock")]
        cli.mock_turns.as_deref(),
        #[cfg(feature = "e2e-mock")]
        cli.mock_record_requests.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let model = match resolve_model(cli.model.clone().or(settings.model.clone()), cli.provider) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let max_turns = cli
        .max_turns
        .or(settings.max_turns)
        .unwrap_or(DEFAULT_MAX_TURNS);
    let enter_submits = cli
        .enter_submits
        .or(settings.enter_submits)
        .unwrap_or(false);

    let tools = ToolRegistry::with_builtin_tools();

    // §非対話モード「危険/ワイルドカードは`--dangerously-allow`」: accept-allモードは
    // fail-fastで拒否する（`--dangerously-allow`が無いままの誤起動を防ぐ）。
    if matches!(cli.permission_mode, PermissionModeArg::AcceptAll) && !cli.dangerously_allow {
        eprintln!(
            "--permission-mode accept-all requires --dangerously-allow (see plans/DESIGN.md §非対話モード)"
        );
        return Err(ExitCode::FAILURE);
    }

    let allowlist: Vec<_> = settings
        .allow
        .clone()
        .unwrap_or_default()
        .iter()
        .chain(cli.allow.iter())
        .filter_map(|rule| match parse_allowlist_rule(rule) {
            None => {
                eprintln!("ignoring malformed --allow rule (expected tool:pattern): {rule}");
                None
            }
            Some(r) if crate::is_dangerous_wildcard(&r.pattern) && !cli.dangerously_allow => {
                eprintln!("ignoring wildcard --allow rule without --dangerously-allow: {rule}");
                None
            }
            Some(r) => Some(r),
        })
        .collect();
    let arbiter = PermissionArbiter::new(cli.permission_mode.into(), allowlist);

    Ok(Configured {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
        settings,
        provider,
        model,
        max_turns,
        enter_submits,
        tools,
        arbiter,
    })
}

pub async fn run() -> ExitCode {
    let ParsedArgs {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
    } = match stage_parse_args() {
        Ok(p) => p,
        Err(code) => return code,
    };

    let configured = match stage_configure(ParsedArgs {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
    }) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Configured {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
        settings,
        provider,
        model,
        max_turns,
        enter_submits,
        tools,
        arbiter,
    } = configured;

    // JSONL追記型セッション永続化（M9、§非対話モード「JSONL 追記型セッション永続化
    // （`--resume`/`--continue`）」）。`.harness/sessions/`直下に1ファイル1セッション。
    let sessions_dir = workspace_root.join(".harness").join("sessions");
    if let Err(e) = std::fs::create_dir_all(&sessions_dir) {
        eprintln!(
            "failed to create sessions directory {}: {e}",
            sessions_dir.display()
        );
        return ExitCode::FAILURE;
    }
    let mut session =
        match resolve_session(&sessions_dir, resume_id.as_deref(), cli.continue_session) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };

    // `--fork-session`: 解決済みの元セッションを不変のまま、全履歴を新規セッションへコピーして
    // 以降の追記先を切り替える（Claude Codeの`--fork-session`/`/branch`相当）。
    if cli.fork_session {
        let source_id = session.id();
        match harness_engine::SessionStore::fork_from(&sessions_dir, session.path()) {
            Ok(forked) => {
                eprintln!("forked session {source_id} -> {}", forked.id());
                session = forked;
            }
            Err(e) => {
                eprintln!("failed to fork session {source_id}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // `ConversationState`自体は`tool_ctx`確定後（下記）に組み立てる。systemは`tool_ctx`が運ぶ
    // 環境事実（`harness_engine::system_blocks_for`）から作るため、先に`tool_ctx`が要る
    // （`run_shell`不安定性調査で見つかった「systemが一切送られていない」欠陥への対処、
    // `plans/DESIGN.md` §システムプロンプト参照）。
    let session_messages = match session.load_messages() {
        Ok(msgs) => msgs,
        Err(e) => {
            eprintln!("failed to load session {}: {e}", session.path().display());
            return ExitCode::FAILURE;
        }
    };

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
        return ExitCode::FAILURE;
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
    let run_shell_path_extra = settings.run_shell.clone().unwrap_or_default().path_extra();

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
        return ExitCode::FAILURE;
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
        return ExitCode::FAILURE;
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
            return ExitCode::FAILURE;
        }
        RequireSandbox::Confidential if !fs_passthrough.is_empty() => {
            eprintln!(
                "error: --fs-allow conflicts with --require-sandbox=confidential (confidential \
                 mode denies reading outside the workspace unconditionally; even read-only \
                 --fs-allow breaks this guarantee; refusing to start rather than silently \
                 weakening it)"
            );
            return ExitCode::FAILURE;
        }
        _ => {}
    }

    if cli.tier1 && !cfg!(windows) {
        eprintln!("error: --tier1 is only supported on Windows");
        return ExitCode::FAILURE;
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
        return ExitCode::FAILURE;
    }
    let write_mode = match resolve_write_mode(cli.cow, &session.id()) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
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
            return ExitCode::FAILURE;
        }
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
            crate::fs_grants::record_fs_passthrough_grant(path, *writable, forced, settings_workspace.as_deref());
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
                std::sync::Arc<harness_sandbox::tier3::vmsandboxd::VmSandboxHandle>,
            > = if tool_ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
                start_tier3_with_progress(
                    &tool_ctx.workspace_root,
                    &tool_ctx.net_proxy.allow_domains,
                    cli.tier3_warm,
                    cli.tier3_max_sessions.max(1),
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
                provider.as_ref(),
                &mut state,
                &tools,
                &tool_ctx,
                &arbiter,
                AgentLoopConfig {
                    model,
                    max_tokens: DEFAULT_MAX_TOKENS,
                    max_turns,
                },
                cli.output_format,
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
        None => {
            let log_dir = workspace_root.join(".harness").join("logs");
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
                model,
                DEFAULT_MAX_TOKENS,
                max_turns,
                cli.provider.label().to_string(),
                state,
                session,
                sessions_dir,
                enter_submits,
                resume_wants_picker,
                cli.tier3_warm,
                cli.tier3_max_sessions.max(1),
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

    exit_code
}

/// 非対話モード（`--print`）専用: Tier3 VMサンドボックスの起動をブロッキングのまま
/// （`tokio::task::spawn_blocking`越しに）待ちつつ、`vmsandboxd_progress`の合成進捗
/// （経過時間ベースの推測、daemonの実測値ではない——`harness_sandbox::tier3::vmsandboxd_progress`の
/// モジュールdoc・`plans/DESIGN-SANDBOX-VMISOLATION.md`参照）をstderrへ間引いて出力する。
/// TUI分岐（`harness_tui::run`内の`sandbox_prep::run_prep_screen`）と対になる非対話側の実装。
#[cfg(windows)]
async fn start_tier3_with_progress(
    workspace_root: &std::path::Path,
    allow_domains: &[String],
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> Option<std::sync::Arc<harness_sandbox::tier3::vmsandboxd::VmSandboxHandle>> {
    use harness_sandbox::tier3::vmsandboxd::VmSandboxHandle;
    use harness_sandbox::tier3::vmsandboxd_progress::{run_synthetic_ticker, SandboxPrepEvent};

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SandboxPrepEvent>();
    let ticker = tokio::spawn(run_synthetic_ticker(tx, tier3_warm));

    let workspace_root = workspace_root.to_path_buf();
    let allow_domains = allow_domains.to_vec();
    let start_task = tokio::task::spawn_blocking(move || {
        VmSandboxHandle::start(
            &workspace_root,
            &allow_domains,
            tier3_warm,
            tier3_max_sessions,
        )
    });
    tokio::pin!(start_task);

    // ラベルが変わった時か、同一フェーズ内でも約5秒おきにのみ1行stderrへ出す
    // （250ms間隔のtickerをそのまま出力すると流れすぎる — cadenceはticker側で
    // 一定に保ち、間引きはこの呼び出し側の責務とする）。
    let mut last_label: Option<String> = None;
    let mut last_printed_secs: u64 = 0;

    let result = loop {
        tokio::select! {
            biased;
            res = &mut start_task => break res,
            Some(ev) = rx.recv() => {
                let secs = ev.elapsed.as_secs();
                let label_changed = last_label.as_deref() != Some(ev.label.as_str());
                if label_changed || secs.saturating_sub(last_printed_secs) >= 5 {
                    eprintln!("[sandbox] {} (経過 {secs}秒)", ev.label);
                    last_label = Some(ev.label.clone());
                    last_printed_secs = secs;
                }
            }
        }
    };
    ticker.abort();

    match result {
        Ok(Ok(handle)) => Some(std::sync::Arc::new(handle)),
        Ok(Err(e)) => {
            eprintln!(
                "error: tier3 was selected but the VM sandbox failed to start: {e}\n\
                 run_shell will fail until this is resolved (see \
                 plans/TIER1A-OPEN-ISSUES.md item 9)."
            );
            None
        }
        Err(join_err) => {
            eprintln!("error: tier3 sandbox prep task panicked: {join_err}");
            None
        }
    }
}

