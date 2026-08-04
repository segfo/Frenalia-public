//! 起動パイプライン Stage2: 設定とprovider/tools/permissionsの確定。
//!
//! `settings.json`読込・`require_sandbox`とconfidentialの矛盾チェック・認知段階の検査・
//! provider構築・model解決・`ToolRegistry`・allowlist・`PermissionArbiter`。

use super::*;
use super::parse_args::ParsedArgs;

/// [`stage_configure`]の出力。Stage3（`stage_open_session`）以降が必要とする値を運ぶ。
pub(super) struct Configured {
    pub(super) cli: Cli,
    pub(super) workspace_root: PathBuf,
    pub(super) resume_id: Option<String>,
    pub(super) resume_wants_picker: bool,
    pub(super) settings: harness_config::Settings,
    pub(super) provider: Box<dyn LlmProvider>,
    pub(super) model: String,
    pub(super) max_turns: usize,
    pub(super) compaction: harness_engine::compaction::CompactionPolicy,
    pub(super) enter_submits: bool,
    pub(super) tools: ToolRegistry,
    pub(super) arbiter: PermissionArbiter,
    /// 認知レイヤーの入口（M13時点では`CognitionLevel::Off`＝素朴ループへの委譲のみ）。
    /// 未実装の段階はStage2で弾くため、ここまで来た時点で必ず実行可能な段階になっている。
    pub(super) cognition: CognitiveOrchestrator,
}

/// `settings.json`読込・`early_require_sandbox`とconfidentialの矛盾チェック・provider構築・
/// model解決・`ToolRegistry`・allowlist・`PermissionArbiter`。
pub(super) fn stage_configure(parsed: ParsedArgs) -> Result<Configured, ExitCode> {
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

    // 未実装の認知段階はここで止める。純粋な引数の妥当性検査なので、APIキーの有無や
    // サンドボックス準備・VM起動より**前**に判定する（`--cognition always`を指定したのに
    // 「APIキーがありません」だけが出る、という取り違えを避ける）。
    let cognition_level = cli
        .cognition
        .map(CognitionLevel::from)
        .or_else(|| settings.cognition.clone().and_then(|c| c.default_level))
        .unwrap_or_default();
    // `cognition.budgets`はフェーズ単位の部分上書き（書かなかったフェーズは
    // `plans/DESIGN-COGNITION.md` §3.3の既定表のまま）。
    let phase_budgets = match settings.cognition.as_ref().and_then(|c| c.budgets.as_ref()) {
        Some(overrides) => harness_cognition::PhaseBudgets::default().with_overrides(overrides),
        None => harness_cognition::PhaseBudgets::default(),
    };
    let cognition = match CognitiveOrchestrator::new(cognition_level, phase_budgets) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

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

    // コンテキスト縮約のポリシー（`plans/PLAN-COMPACTION.md`）。CLIフラグ→`settings.json`→
    // プロバイダcapabilityの順で解決する。**比率が逆転していれば黙って直さず起動時に止める**
    // ——`target >= trigger`だと縮約しても閾値を下回らず、毎ターン要約コールを打ち続ける。
    let compaction = match harness_engine::compaction::CompactionPolicy::resolve(
        &provider.capabilities(),
        harness_engine::compaction::CompactionOverrides {
            context_window: cli
                .context_window
                .or(settings.compaction.as_ref().and_then(|c| c.context_window)),
            trigger_ratio: settings.compaction.as_ref().and_then(|c| c.trigger_ratio),
            target_ratio: settings.compaction.as_ref().and_then(|c| c.target_ratio),
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

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
        compaction,
        enter_submits,
        tools,
        arbiter,
        cognition,
    })
}

