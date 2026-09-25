//! ワークスペース系サブコマンド（`changes`/`apply`/`discard`/`resolve`）と`prompt`、
//! およびオーバーレイ/CoW diff_layer_dirの解決。

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
    /// 台帳のパスの形が不正だったため拒否したエントリ（BUG-062）。`(path, reason)`。
    rejected: Vec<(String, String)>,
    /// オーバーレイに実体はあるが台帳に記録が無く、baselineが不明なため適用を見送った
    /// エントリ（BUG-066）。`--adopt-unledgered`で取り込める。
    unledgered: Vec<String>,
}

/// `harness apply --output-format jsonl`の1行（1件1行）。
///
/// **`kind`の綴りは[`ApplyReportJson`]のフィールド名と同じにする。** 同じ`apply`の結果を
/// `json`と`jsonl`で別の語で呼ぶと、片方だけを見て書いたスクリプトがもう片方で動かない。
///
/// [BUG-132](../../../../docs/bugs/BUG-132.md): 元は`Jsonl`が`Text`と同じアームに畳まれていて、
/// `applied: <path>`のような人間向けの行がそのまま機械可読な契約の中身になっていた。
/// 同じファイルの`changes`は最初から`Jsonl`を分けていたので、**1つのファイルの中で非対称**だった。
#[derive(serde::Serialize)]
struct ApplyLineJson<'a> {
    kind: &'a str,
    path: &'a str,
    /// `rejected`だけが理由を持つ（台帳のパスの形が不正だった理由、BUG-062）。
    /// 他の区分では欄ごと出さない——常に`null`が並ぶと「理由があるはずのもの」に見える。
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

/// CoWセッションの由来（`.harness-cow-session.json`のworkspace_root）。diff_layer_dir自身に
/// 書かれているので、`--cwd`の綴りに依存せずに引ける（Windows専用の`--sandbox tier2a-cow`機構なので
/// 他プラットフォームでは常に`None`）。
pub(crate) fn cow_session_workspace_root(diff_layer_dir: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        // 表示・照合用なので`Ok`だけを見る。**GCはこの形で読まないこと**——
        // 「無い」と「読めない」が潰れると、読めないものを回収してよいと誤判定する
        // （`workspace_ledger::CowMetaRead`のdoc）。
        harness_sandbox::tier2a::workspace_ledger::read_cow_session_meta(diff_layer_dir)
            .ok()
            .map(|m| m.workspace_root.clone())
    }
    #[cfg(not(windows))]
    {
        let _ = diff_layer_dir;
        None
    }
}

/// 拒否監査台帳（`.harness-cow-denied.jsonl`）の要約を出す。
///
/// **workspace内と外を必ず区別する**（[BUG-066](../../../../docs/bugs/BUG-066.md)）。
/// 両者は見た目こそ同じ「ACLに拒否された書込」だが、意味が正反対である:
///
/// * workspace**外**への拒否 → 封じ込めが設計どおり働いた記録。放置してよい。
/// * workspace**内**への拒否 → CoWのリダイレクトが働かなかった記録。書けるはずの場所へ
///   書けなかったのだから、**その変更は失われている**。
///
/// 実際BUG-066のセッションでは、workspace内への書込4件が拒否されていたのに
/// 「14 workspace-external write attempt(s)」と表示され、事実と逆の案内になっていた。
pub(crate) fn print_denied_summary(diff_layer_dir: &Path) {
    let denied = harness_change_ledger::store::read_denied_log(diff_layer_dir);
    if denied.is_empty() {
        return;
    }
    let workspace_root = cow_session_workspace_root(diff_layer_dir);
    let (inside, outside): (Vec<_>, Vec<_>) = denied.iter().partition(|e| {
        workspace_root.as_deref().is_some_and(|root| {
            harness_change_ledger::path_rules::relative_under_root(&e.path, root).is_some()
        })
    });
    if !outside.is_empty() {
        println!(
            "({} workspace-external write attempt(s) were denied by ACL; \
             see `harness cow audit`)",
            outside.len()
        );
    }
    if !inside.is_empty() {
        println!(
            "WARNING: {} write attempt(s) INSIDE the workspace were denied by ACL. The CoW \
             redirect did not work for those writes, so the changes were lost (they are not in \
             the overlay either). See `harness cow audit` and docs/bugs/BUG-066.md.",
            inside.len()
        );
    }
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

    // **起動パイプラインと同じ関数を通す**（`setup::resolve_staging_and_write_mode`）。
    // `--sandbox tier2a-cow`×`--staged`の拒否はその関数が持つので、`harness prompt`だけが
    // 素通りする形にはならない（B-06）。ここで受け取った`write_mode`は下で**使わない**——
    // その理由は下の`note`で本人へも説明している。
    let sandbox_choice: SandboxChoice = sandbox_choice_of(cli.sandbox);
    if let Err(e) = check_sandbox_choice_supported(sandbox_choice) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    // **排他判定だけ**を通す。`harness prompt`はセッションを開かないので CoW 差分層 を必要とせず、
    // 資源の解決まで含む`resolve_staging_and_write_mode`を呼ぶと、使わない`%LOCALAPPDATA%`の
    // 解決失敗でこの読み取り専用コマンドが落ちる。判定は起動パイプラインと同じ関数を通る（B-06）。
    let staging_mode = match resolve_staging_mode_checked(
        sandbox_choice,
        cli.live,
        cli.staged,
        cli.workspace_commit,
    ) {
        Ok(staging_mode) => staging_mode,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
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

    // **何が効いて何が効かないかを、混ぜずに言う。**
    //
    // `--sandbox`のTier要求（どのTierへ着地するか）は`harness prompt`でも**そのまま効く**
    // ——下の`select_tier`へ渡しており、`tier2a`/`tier2a-cow`はTier2aへ届かなければここでも
    // 起動を拒否する。効かないのは`tier2a-cow`の**CoW部分**（workspaceのRO化と差分層への誘導）
    // と、fs passthrough（`--fs-allow`/`--force-system-acl`）である。この診断コマンドは
    // ACLモードの張り替えとUAC連鎖・台帳記録を伴う経路を通さないため、`WorkspaceWriteMode`は
    // `DirectRw`のまま実プローブを行う。
    //
    // つまり印字されるプロンプトは、**CoWの記述だけが実セッションと食い違う**。
    if !cli.fs_allow.is_empty() || cli.force_system_acl || sandbox_choice.wants_cow() {
        eprintln!(
            "note: `harness prompt` does not apply fs passthrough (--fs-allow / \
             --force-system-acl) nor the Copy-on-Write half of `--sandbox tier2a-cow`; the tier \
             requirement itself is honoured, but the printed prompt describes a directly writable \
             workspace and no passthrough roots."
        );
    }

    let require_sandbox = parse_require_sandbox(cli.require_sandbox);
    let shell_tier = match select_tier(
        require_sandbox,
        workspace_root,
        sandbox_choice,
        &[],
        None,
        &WorkspaceWriteMode::DirectRw,
        // D-60: 単発の`harness workspace`コマンドで、常駐daemonは居ない。
        None,
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
        cow_diff_layer_dir: None,
        // `harness prompt`はMCPサーバを起動しない（診断用の読み取り専用コマンドであり、
        // 第三者プロセスを起こす副作用を持たせない）。実行時に何が載るかは`harness mcp list`
        // で確認する。
        mcp_servers: Vec::new(),
        // [段階6e] 同じ理由でSpawn Daemonも起こさない＝**この経路では遷移MACの強制は
        // 効いていない**ので、常に`None`である（`TransitionFacts`のdoc）。
        // 実行時のセッションで何が出るかは`run_agent`側が決める。
        transition_facts: None,
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

/// `--session <id>`（省略時は最新）から、そのセッションが使ったオーバーレイ置き場を解決する。
/// `--staged`置き場（workspace内`.harness/sandbox/<id>`）を先に試し、無ければ`--sandbox tier2a-cow`置き場
/// （workspace外CoW 差分層ディレクトリ、Windows専用）を試す——1セッションは常にどちらか
/// 一方でしか起動されないため、両方見つかることはない。**その保証はclapの`conflicts_with_all`
/// ではなく`setup::resolve_staging_mode_checked`の実行時拒否が持つ**（値依存の排他はclapでは
/// 宣言できないので実行時へ移した）。正しさの論証を、もう存在しない宣言に預けないこと。
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
    if let Some(dir) = cow_diff_layer_dir_checked(session) {
        return Some((StagingConfig::default(), Some(dir)));
    }
    None
}

#[cfg(windows)]
pub(crate) fn cow_diff_layer_dir_checked(session: Option<&str>) -> Option<PathBuf> {
    resolve_cow_diff_layer_dir(session)
}
#[cfg(not(windows))]
pub(crate) fn cow_diff_layer_dir_checked(_session: Option<&str>) -> Option<PathBuf> {
    None
}

/// `apply`/`changes`/`discard`/`resolve`サブコマンドを処理する。プロバイダ資格情報を
/// 一切必要としない（§非対話モード、プロンプトは一切送らない）。CoW一本化（Phase 2）に
/// より`--staged`/`--sandbox tier2a-cow`は同じ`SandboxFs`バックエンドを使うため、単一の`SandboxFs`だけを
/// 組み立てて全サブコマンドで使い回す。
pub(crate) fn run_sandbox_subcommand(cmd: Commands, workspace_root: &Path) -> ExitCode {
    let (session, output_format_and_kind) = match &cmd {
        Commands::Changes {
            session,
            output_format,
        } => (session.clone(), Some(*output_format)),
        Commands::Apply {
            session,
            output_format,
            ..
        } => (session.clone(), Some(*output_format)),
        Commands::Discard { session } => (session.clone(), None),
        Commands::Resolve { session, .. } => (session.clone(), None),
        // `Fs`/`Tier3`/`Prompt`はmain()側でそれぞれ専用の振り分け先へ処理済みで、ここには
        // 到達しない（workspace sandboxのstaging設定を一切必要としないため、`SandboxFs`を開く
        // このパスとは責務が別）。
        Commands::Fs { .. } => {
            unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand")
        }
        Commands::Tier2a { .. } => {
            unreachable!("Commands::Tier2a is dispatched before run_sandbox_subcommand")
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
        Commands::Memory { .. } => {
            unreachable!("Commands::Memory is dispatched before run_sandbox_subcommand")
        }
        Commands::Policy { .. } => {
            unreachable!("Commands::Policy is dispatched before run_sandbox_subcommand")
        }
        Commands::Mcp { .. } => {
            unreachable!("Commands::Mcp is dispatched before run_sandbox_subcommand")
        }
        Commands::Approvals { .. } => {
            unreachable!("Commands::Approvals is dispatched before run_sandbox_subcommand")
        }
        Commands::Prompt => {
            unreachable!("Commands::Prompt is dispatched before run_sandbox_subcommand")
        }
    };

    let Some((staging, cow_diff_layer_dir)) =
        resolve_session_overlay(workspace_root, session.as_deref())
    else {
        eprintln!("no staged sandbox or CoW diff layer directory found (nothing to show)");
        return ExitCode::FAILURE;
    };
    let fs = match SandboxFs::open_with_cow(
        workspace_root,
        &staging,
        &harness_core::ReadScopeConfig::default(),
        cow_diff_layer_dir.as_deref(),
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
                        // BUG-062: applyが拒否する形のパスは、一覧からは消さずに印と理由を
                        // 添えて見せる（D-43「失敗を隠さない」。黙って隠すと、ユーザは
                        // 「何も無かった」と解釈してしまう）。
                        // BUG-066: 台帳に無いオーバーレイ実体も同じ流儀で印を付ける。
                        let mut marks = String::new();
                        if c.unledgered {
                            marks
                                .push_str(" [unledgered: present in the overlay but not recorded]");
                        }
                        if let Some(reason) = &c.rejected {
                            marks.push_str(&format!(" [rejected: {reason}]"));
                        }
                        println!(
                            "{:<7} {}{marks}",
                            format!("{:?}", c.op).to_lowercase(),
                            c.path
                        );
                    }
                    // Phase 4（設計書§19.8）: CoWセッションなら拒否監査ログの件数もフッタに
                    // 出す（`--sandbox tier2a-cow`の書込境界自体はACLが保証しているので、これは可視性のみ）。
                    if let Some(dir) = &cow_diff_layer_dir {
                        print_denied_summary(dir);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Commands::Apply {
            only,
            dangerously_allow,
            adopt_unledgered,
            keep_diff_layer,
            ..
        } => {
            let report = match fs.apply(&ApplyOptions {
                only_glob: only.as_deref(),
                only_paths: None,
                allow_ext: dangerously_allow,
                adopt_unledgered,
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
                || !report.hard_denied.is_empty()
                || !report.rejected.is_empty()
                // BUG-066: 「差分層に実体があるのに適用されなかった」は、黙って成功扱いに
                // してはいけない代表例（そのまま`discard`されると作業が消える）。
                || !report.unledgered.is_empty();
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    let json = ApplyReportJson {
                        applied: report.applied,
                        conflicts: report.conflicts,
                        ext_blocked: report.ext_blocked,
                        hard_denied: report.hard_denied,
                        rejected: report.rejected,
                        unledgered: report.unledgered,
                    };
                    if let Ok(s) = serde_json::to_string(&json) {
                        println!("{s}");
                    }
                }
                // 1件1行。`changes`（同じ`match`の上）と同じ形にしてある（BUG-132）。
                OutputFormat::Jsonl => {
                    let mut lines: Vec<ApplyLineJson> = Vec::new();
                    // **6区分すべてを並べる。** 1つでも落とすと、`json`では見えるものが
                    // `jsonl`では黙って消える（`--output-format`を変えただけで結果が変わる）。
                    for (kind, paths) in [
                        ("applied", &report.applied),
                        ("conflicts", &report.conflicts),
                        ("ext_blocked", &report.ext_blocked),
                        ("hard_denied", &report.hard_denied),
                        ("unledgered", &report.unledgered),
                    ] {
                        for p in paths {
                            lines.push(ApplyLineJson {
                                kind,
                                path: p,
                                reason: None,
                            });
                        }
                    }
                    for (p, reason) in &report.rejected {
                        lines.push(ApplyLineJson {
                            kind: "rejected",
                            path: p,
                            reason: Some(reason),
                        });
                    }
                    for line in &lines {
                        if let Ok(s) = serde_json::to_string(line) {
                            println!("{s}");
                        }
                    }
                }
                OutputFormat::Text => {
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
                    for (p, reason) in &report.rejected {
                        println!(
                            "rejected (malformed ledger path -- the operations ledger may have \
                             been tampered with, see docs/bugs/BUG-062.md): {p} -- {reason}"
                        );
                    }
                    for p in &report.unledgered {
                        println!(
                            "unledgered (in the overlay but not recorded, baseline unknown, not \
                             applied): {p} -- re-run with `--adopt-unledgered` to take it \
                             (see docs/bugs/BUG-066.md)"
                        );
                    }
                }
            }
            if has_conflicts_or_blocked {
                ExitCode::from(4)
            } else {
                // D-82: **完全に適用し切ったCoW差分層はここで畳む。** 作る側（起動時）と
                // 消す側が対になっていないと、CoWを既定にしたときの**最も多い終わり方**
                // （applyして終わる）が1つずつ置き場を残し続ける。台帳は`apply`が
                // `prune_cow_ledger`で空にするが、実体ファイルは残るため、起動時スイープの
                // 安価な空判定（台帳も実体も0）には永久に引っかからない。
                //
                // 条件は上の`has_conflicts_or_blocked`が偽であること——`unledgered`も
                // 含まれるので、「差分層に実体があるのに適用されなかった」ものが1件でも
                // あれば畳まない（BUG-066が守っているもの）。加えて実行中でないこと・
                // D-80のレビュー待ちでないことを`plan_cow_gc`と同じ判定で見る。
                if !keep_diff_layer {
                    finish_cow_diff_layer_after_apply(cow_diff_layer_dir.as_deref());
                }
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
                    // BUG-065: conflict markerが残ったまま書いた場合を「解決済み」と数えない。
                    // 内容は設計方針4どおり書くが、機械可読な signal（この行と終了コード）は
                    // 未解決だと言い切る——stderrの警告とstdoutの集計が食い違うと、
                    // 呼び出し側のスクリプトは成功として素通りしてしまう（BUG-064と同じ型）。
                    Ok(true) => {
                        println!("unresolved: {} (conflict markers remain)", attempt.path);
                        failed += 1;
                    }
                    Ok(false) => {
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
            if let Some(dir) = &cow_diff_layer_dir {
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
        Commands::Tier2a { .. } => {
            unreachable!("Commands::Tier2a is dispatched before run_sandbox_subcommand")
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
        Commands::Memory { .. } => {
            unreachable!("Commands::Memory is dispatched before run_sandbox_subcommand")
        }
        Commands::Policy { .. } => {
            unreachable!("Commands::Policy is dispatched before run_sandbox_subcommand")
        }
        Commands::Mcp { .. } => {
            unreachable!("Commands::Mcp is dispatched before run_sandbox_subcommand")
        }
        Commands::Approvals { .. } => {
            unreachable!("Commands::Approvals is dispatched before run_sandbox_subcommand")
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

/// `apply`が1件も残さず適用し切ったCoW差分層を畳む（D-82の回収点1）。
///
/// **回収してよいかの判定は`plan_cow_gc`と同じものを使う**——ここで「実行中でないか」
/// 「レビュー待ちでないか」を書き直すと、条件が2箇所に分かれて片方だけ古くなる
/// （`bug-pattern-rules` B-13/B-06）。GCが集めた事実の中から、いま適用したセッションの
/// 1件だけを取り出して同じ規則へ通す。
///
/// # [D-82] この経路だけ猶予を0にする、という例外はもう無い
///
/// かつてここは「作りたては見送る」猶予を0に落として呼んでいた（既定の1時間を持ち込むと、
/// 短いセッションでは適用直後にいつまでも片付かないため）。**その猶予は全経路から撤去された**
/// ——守っていた「起動しかけとの競合」は、作る側が生存マーカーを実体より先に握るように
/// なったことで消えている（`workspace_ledger::cow_session_is_live`のdoc）。
/// **この経路と他の2経路（起動時スイープ・`harness cow gc`）が、同じ引数で同じ規則を通る。**
#[cfg(windows)]
fn finish_cow_diff_layer_after_apply(cow_diff_layer_dir: Option<&Path>) {
    use harness_sandbox::tier2a::workspace_ledger as wl;

    let Some(diff_layer_dir) = cow_diff_layer_dir else {
        return;
    };
    let Some(session_id) = diff_layer_dir.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let (facts, _unreachable) = wl::collect_cow_session_facts();
    let Some(fact) = facts.iter().find(|f| f.session_id == session_id) else {
        return;
    };
    // 方針は既定（ネットワーク上は保護）。`apply`は人が明示的に打つ操作だが、
    // **保護の判断まで手動操作で飛ばさない**——飛ばしてよいかを決めるのは設定であって、
    // どのコマンドから来たかではない。
    let verdicts = wl::plan_cow_gc(std::slice::from_ref(fact), wl::CowGcPolicy::default());
    let Some((_, verdict)) = verdicts.first() else {
        return;
    };
    // 適用直後なので、残す理由は「実行中」「レビュー待ち」「メタが読めない」のいずれか。
    // **どれも黙って消してよいものではない**ので、理由を出してそのまま残す。
    //
    // **後片付けの報告はstderrへ出す。** `apply`の結果はstdoutで、`--output-format json`の
    // ときはそこがJSONそのものになる。ここは結果ではなく副次的な後片付けの報告なので、
    // stdoutへ書くと機械可読な出力の末尾に人間向けの行が付いて**パースが壊れる**
    // （[BUG-131](../../../../docs/bugs/BUG-131.md)。下のエラー側は元からstderrだった）。
    if !verdict.collects() {
        eprintln!(
            "note: keeping the CoW diff area for {session_id} because {}",
            verdict.reason()
        );
        return;
    }
    match harness_sandbox::session_scope::remove_overlay_dir(diff_layer_dir) {
        Ok(()) => eprintln!("removed the CoW diff area for {session_id} (nothing left in it)"),
        Err(e) => eprintln!(
            "warning: applied everything, but could not remove the CoW diff area for \
             {session_id}: {e}"
        ),
    }
}

#[cfg(not(windows))]
fn finish_cow_diff_layer_after_apply(_cow_diff_layer_dir: Option<&Path>) {}
