//! ワークスペース系サブコマンド（`changes`/`apply`/`discard`/`resolve`）と`prompt`、
//! およびオーバーレイ/CoW upper_dirの解決。

use super::*;

pub(crate) fn resolve_model(model: Option<String>, kind: ProviderKind) -> Result<String, String> {
    match (model, kind) {
        (Some(m), _) => Ok(m),
        (None, ProviderKind::Anthropic) => Ok(DEFAULT_ANTHROPIC_MODEL.to_string()),
        (None, ProviderKind::Openai) => {
            Err("--model is required when --provider openai is used".into())
        }
        (None, ProviderKind::Lmstudio) => {
            Err("--model is required when --provider lmstudio is used".into())
        }
        #[cfg(feature = "e2e-mock")]
        (None, ProviderKind::Mock) => Ok("mock".to_string()),
    }
}

/// `harness apply`のJSON出力（`--output-format json`）。
#[derive(serde::Serialize)]
struct ApplyReportJson {
    applied: Vec<String>,
    conflicts: Vec<String>,
    ext_blocked: Vec<String>,
    hard_denied: Vec<String>,
}

/// `harness prompt`: 現在のフラグ・`.harness/settings.json`構成から実際に組み立てられる
/// システムプロンプト（`harness_core::EnvironmentFacts`のレンダリング結果）をそのまま
/// 標準出力へ出す（Phase4-4、`run_shell`不安定性調査）。プロバイダ資格情報を一切必要としない
/// （プロンプトは送らない、`run_sandbox_subcommand`と同じ非対話原則）。
///
/// シェル隔離Tierの選択（`select_tier`）は通常起動と同じ実プローブ（Windows AppContainer
/// プロファイル作成等）を伴う点に注意する。これは意図的な設計判断: プローブを省略した
/// 推測値ではなく「実際に送られる」プロンプトを見せるため。`--fs-allow`/`--force-system-acl`
/// （fs passthrough allowlist）はUAC連鎖・台帳記録を伴う複雑な経路のため、この診断コマンドでは
/// サポートしない（指定されていれば無視する旨を1行警告する）。
pub(crate) fn run_prompt_subcommand(cli: &Cli, workspace_root: &Path) -> ExitCode {
    let settings = harness_config::Settings::load(workspace_root);

    let staging_mode = resolve_staging_mode(cli.live, cli.staged, cli.workspace_commit);
    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    let mut net_proxy = settings
        .net
        .clone()
        .unwrap_or_default()
        .to_net_proxy_config();
    if let Err(e) = validate_and_merge_net_allow_domains(&mut net_proxy, &cli.net_allow_domain) {
        eprintln!("error: invalid network domain policy: {e}");
        return ExitCode::FAILURE;
    }
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }
    let run_shell_path_extra = settings.run_shell.clone().unwrap_or_default().path_extra();

    if !cli.fs_allow.is_empty() || cli.force_system_acl || cli.cow {
        eprintln!(
            "note: --fs-allow/--force-system-acl/--cow are ignored by `harness prompt` (fs \
             passthrough and ACL mode are not probed by this diagnostic command); the printed \
             prompt reflects read-scope/net settings only."
        );
    }

    if cli.tier1 && !cfg!(windows) {
        eprintln!("error: --tier1 is only supported on Windows");
        return ExitCode::FAILURE;
    }

    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());
    let shell_tier = match select_tier(
        require_sandbox,
        workspace_root,
        cli.vm_sandbox,
        cli.tier1,
        &[],
        None,
        &WorkspaceWriteMode::DirectRw,
    ) {
        Ok(sel) => sel,
        Err(e) => {
            eprintln!("error: shell tier selection failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let ctx = ToolCtx {
        workspace_root: workspace_root.to_path_buf(),
        staging: StagingConfig {
            mode: staging_mode,
            sandbox_dir: None,
        },
        read_scope,
        shell_sees_staged_writes: shell_sees_staged_writes(&shell_tier),
        shell_tier,
        net_proxy,
        net_app,
        run_shell_path_extra,
        vm_sandbox: None,
        cow_upper_dir: None,
        // `harness prompt`はMCPサーバを起動しない（診断用の読み取り専用コマンドであり、
        // 第三者プロセスを起こす副作用を持たせない）。実行時に何が載るかは`harness mcp list`
        // で確認する。
        mcp_servers: Vec::new(),
    };
    for block in harness_engine::system_blocks_for(&ctx) {
        println!("{}", block.text);
    }
    ExitCode::SUCCESS
}

pub(crate) fn shell_sees_staged_writes(shell_tier: &harness_core::ShellTierSelection) -> bool {
    #[cfg(windows)]
    {
        use harness_sandbox_vm::vmsandbox::{VmSandboxConfig, WorkspaceShareMode};

        shell_tier.tier == harness_core::ShellTier::Tier3
            && VmSandboxConfig::default().workspace_share_mode == WorkspaceShareMode::Cifs
    }
    #[cfg(not(windows))]
    {
        let _ = shell_tier;
        false
    }
}

pub(crate) fn to_sandbox_fs_access(access: harness_config::FsAccess) -> harness_sandbox::FsAccess {
    match access {
        harness_config::FsAccess::Read => harness_sandbox::FsAccess::Read,
        harness_config::FsAccess::ReadWrite => harness_sandbox::FsAccess::ReadWrite,
        harness_config::FsAccess::ReadExec => harness_sandbox::FsAccess::ReadExec,
    }
}

/// `--session <id>`（省略時は最新）から、そのセッションが使ったオーバーレイ置き場を解決する。
/// `--staged`置き場（workspace内`.harness/sandbox/<id>`）を先に試し、無ければ`--cow`置き場
/// （workspace外CoW upperディレクトリ、Windows専用）を試す——1セッションは常にどちらか
/// 一方でしか起動されない（Phase 0の`conflicts_with_all`）ため、両方見つかることはない。
/// どちらも見つからなければ`None`。
pub(crate) fn resolve_session_overlay(
    workspace_root: &Path,
    session: Option<&str>,
) -> Option<(StagingConfig, Option<PathBuf>)> {
    if let Some(sandbox_dir) = resolve_sandbox_dir(workspace_root, session) {
        if workspace_root.join(&sandbox_dir).exists() {
            return Some((
                StagingConfig {
                    mode: StagingMode::Staged,
                    sandbox_dir: Some(sandbox_dir),
                },
                None,
            ));
        }
    }
    if let Some(dir) = cow_upper_dir_checked(session) {
        return Some((StagingConfig::default(), Some(dir)));
    }
    None
}

#[cfg(windows)]
pub(crate) fn cow_upper_dir_checked(session: Option<&str>) -> Option<PathBuf> {
    resolve_cow_upper_dir(session)
}
#[cfg(not(windows))]
pub(crate) fn cow_upper_dir_checked(_session: Option<&str>) -> Option<PathBuf> {
    None
}

/// `apply`/`changes`/`discard`/`resolve`サブコマンドを処理する。プロバイダ資格情報を
/// 一切必要としない（§非対話モード、プロンプトは一切送らない）。CoW一本化（Phase 2）に
/// より`--staged`/`--cow`は同じ`SandboxFs`バックエンドを使うため、単一の`SandboxFs`だけを
/// 組み立てて全サブコマンドで使い回す。
pub(crate) fn run_sandbox_subcommand(cmd: Commands, workspace_root: &Path) -> ExitCode {
    let (session, output_format_and_kind) = match &cmd {
        Commands::Changes { session, output_format } => (session.clone(), Some(*output_format)),
        Commands::Apply { session, output_format, .. } => (session.clone(), Some(*output_format)),
        Commands::Discard { session } => (session.clone(), None),
        Commands::Resolve { session, .. } => (session.clone(), None),
        // `Fs`/`Tier3`/`Prompt`はmain()側でそれぞれ専用の振り分け先へ処理済みで、ここには
        // 到達しない（workspace sandboxのstaging設定を一切必要としないため、`SandboxFs`を開く
        // このパスとは責務が別）。
        Commands::Fs { .. } => {
            unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand")
        }
        Commands::Tier3 { .. } => {
            unreachable!("Commands::Tier3 is dispatched before run_sandbox_subcommand")
        }
        Commands::Cow { .. } => {
            unreachable!("Commands::Cow is dispatched before run_sandbox_subcommand")
        }
        Commands::Net { .. } => {
            unreachable!("Commands::Net is dispatched before run_sandbox_subcommand")
        }
        Commands::Policy { .. } => {
            unreachable!("Commands::Policy is dispatched before run_sandbox_subcommand")
        }
        Commands::Mcp { .. } => {
            unreachable!("Commands::Mcp is dispatched before run_sandbox_subcommand")
        }
        Commands::Prompt => {
            unreachable!("Commands::Prompt is dispatched before run_sandbox_subcommand")
        }
    };

    let Some((staging, cow_upper_dir)) = resolve_session_overlay(workspace_root, session.as_deref())
    else {
        eprintln!("no staged sandbox or CoW upper directory found (nothing to show)");
        return ExitCode::FAILURE;
    };
    let fs = match SandboxFs::open_with_cow(
        workspace_root,
        &staging,
        &harness_core::ReadScopeConfig::default(),
        cow_upper_dir.as_deref(),
    ) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("failed to open sandbox: {e}");
            return ExitCode::FAILURE;
        }
    };

    match cmd {
        Commands::Changes { .. } => {
            let changes = match fs.change_set() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to read changes: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    if let Ok(s) = serde_json::to_string(&changes) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl => {
                    for c in &changes {
                        if let Ok(s) = serde_json::to_string(c) {
                            println!("{s}");
                        }
                    }
                }
                OutputFormat::Text => {
                    if changes.is_empty() {
                        println!("(no changes)");
                    }
                    for c in &changes {
                        println!(
                            "{:<7} {}",
                            format!("{:?}", c.op).to_lowercase(),
                            c.path
                        );
                    }
                    // Phase 4（設計書§19.8）: CoWセッションなら拒否監査ログの件数もフッタに
                    // 出す（`--cow`の書込境界自体はACLが保証しているので、これは可視性のみ）。
                    if let Some(dir) = &cow_upper_dir {
                        let denied = harness_change_ledger::store::read_denied_log(dir);
                        if !denied.is_empty() {
                            println!(
                                "({} workspace-external write attempt(s) were denied by ACL; \
                                 see `harness cow audit`)",
                                denied.len()
                            );
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Commands::Apply {
            only,
            dangerously_allow,
            ..
        } => {
            let report = match fs.apply(&ApplyOptions {
                only_glob: only.as_deref(),
                only_paths: None,
                allow_ext: dangerously_allow,
            }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("apply failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // hard_deniedもconflicts/ext_blocked同様「apply未完了、要注意」の一種として
            // 非ゼロ終了コードに含める（D-05: 設定注入パスは絶対に解除しない）。
            let has_conflicts_or_blocked = !report.conflicts.is_empty()
                || !report.ext_blocked.is_empty()
                || !report.hard_denied.is_empty();
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    let json = ApplyReportJson {
                        applied: report.applied,
                        conflicts: report.conflicts,
                        ext_blocked: report.ext_blocked,
                        hard_denied: report.hard_denied,
                    };
                    if let Ok(s) = serde_json::to_string(&json) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl | OutputFormat::Text => {
                    for p in &report.applied {
                        println!("applied: {p}");
                    }
                    for p in &report.conflicts {
                        println!("conflict (baseline mismatch, not applied): {p}");
                    }
                    for p in &report.ext_blocked {
                        println!("blocked (out-of-workspace, needs --dangerously-allow): {p}");
                    }
                    for p in &report.hard_denied {
                        println!("hard-denied (config-injection path, D-05): {p}");
                    }
                }
            }
            if has_conflicts_or_blocked {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Resolve { always_edit, .. } => {
            let (report, prepared) = match harness_sandbox::resolve::prepare_resolve(&fs) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("resolve failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            for p in &report.applied {
                println!("applied (no conflict): {p}");
            }
            if report.conflicts.is_empty() {
                println!("no conflicts to resolve");
                return ExitCode::SUCCESS;
            }

            let mut resolved = 0usize;
            let mut failed = 0usize;
            for attempt in &prepared.attempts {
                if always_edit || attempt.needs_edit {
                    let mut cmd = match harness_sandbox::resolve::editor_command() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("{}: {e}", attempt.path);
                            failed += 1;
                            continue;
                        }
                    };
                    match cmd.arg(&attempt.merged_path).status() {
                        Ok(s) if s.success() => {}
                        Ok(s) => {
                            eprintln!("{}: editor exited with {s}; skipping", attempt.path);
                            failed += 1;
                            continue;
                        }
                        Err(e) => {
                            eprintln!("{}: failed to launch editor: {e}", attempt.path);
                            failed += 1;
                            continue;
                        }
                    }
                }
                match attempt.finalize(&fs) {
                    Ok(()) => {
                        println!("resolved: {}", attempt.path);
                        resolved += 1;
                    }
                    Err(e) => {
                        eprintln!("{}: failed to finalize: {e}", attempt.path);
                        failed += 1;
                    }
                }
            }
            for s in &prepared.skipped {
                println!("skipped: {} ({})", s.path, s.reason);
                failed += 1;
            }
            println!("{resolved} resolved, {failed} skipped/failed");
            if failed > 0 {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Discard { .. } => {
            if let Some(dir) = &cow_upper_dir {
                if let Some(session_id) = dir.file_name().and_then(|n| n.to_str()) {
                    if cow_session_is_live_checked(session_id) {
                        eprintln!(
                            "session {session_id} is still running; refusing to discard its \
                             CoW changes"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            match fs.discard() {
                Ok(()) => {
                    println!("discarded changes");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("discard failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Fs { .. } => {
            unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand")
        }
        Commands::Tier3 { .. } => {
            unreachable!("Commands::Tier3 is dispatched before run_sandbox_subcommand")
        }
        Commands::Cow { .. } => {
            unreachable!("Commands::Cow is dispatched before run_sandbox_subcommand")
        }
        Commands::Net { .. } => {
            unreachable!("Commands::Net is dispatched before run_sandbox_subcommand")
        }
        Commands::Policy { .. } => {
            unreachable!("Commands::Policy is dispatched before run_sandbox_subcommand")
        }
        Commands::Mcp { .. } => {
            unreachable!("Commands::Mcp is dispatched before run_sandbox_subcommand")
        }
        Commands::Prompt => {
            unreachable!("Commands::Prompt is dispatched before run_sandbox_subcommand")
        }
    }
}

#[cfg(windows)]
pub(crate) fn cow_session_is_live_checked(session_id: &str) -> bool {
    harness_sandbox::tier2a::workspace_ledger::cow_session_is_live(session_id)
}
#[cfg(not(windows))]
pub(crate) fn cow_session_is_live_checked(_session_id: &str) -> bool {
    false
}
