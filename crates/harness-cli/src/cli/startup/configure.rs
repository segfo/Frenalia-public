//! 起動パイプライン Stage2: 設定とprovider/tools/permissionsの確定。
//!
//! `settings.json`読込・`require_sandbox`とconfidentialの矛盾チェック・認知段階の検査・
//! provider構築・model解決・`ToolRegistry`・allowlist・`PermissionArbiter`。

use super::parse_args::ParsedArgs;
use super::*;

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
    /// 縮退ガードの移動統計（`plans/DESIGN-COGNITION.md` §11）。**セッション全体で1つ**を
    /// ここで作り、発話ごとに`AgentLoopConfig`へcloneして渡す（中身は`Arc`）。
    /// `degeneracy.enabled:false`なら`None`＝機構ごと無効。
    pub(super) degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    pub(super) enter_submits: bool,
    pub(super) tools: ToolRegistry,
    pub(super) arbiter: PermissionArbiter,
    /// 認知レイヤーの入口（M13時点では`CognitionLevel::Off`＝素朴ループへの委譲のみ）。
    /// 未実装の段階はStage2で弾くため、ここまで来た時点で必ず実行可能な段階になっている。
    pub(super) cognition: CognitiveOrchestrator,
    /// 承認画面の要約（D-100）。`None`なら作らない。
    pub(super) approval_summary: Option<ApprovalSummaryChoice>,
    pub(super) approval_risk: Option<harness_tui::ApprovalRisk>,
}

/// 承認画面の要約をどのプロバイダ・どのモデルで作るか（D-100）。
pub(super) struct ApprovalSummaryChoice {
    /// 要約専用に建てたプロバイダ。`None`なら会話と同じものを使う
    /// （**同じで済むときに2本目を建てない**——資格情報を二重に要求しない）。
    pub(super) provider: Option<Box<dyn LlmProvider>>,
    pub(super) model: String,
    /// 画面へ出す出どころ。**どこへ中身が出たのかを後から見て分かるようにする。**
    pub(super) label: String,
}

/// `settings.json`読込・`early_require_sandbox`とconfidentialの矛盾チェック・provider構築・
/// model解決・`ToolRegistry`・allowlist・`PermissionArbiter`。
pub(super) async fn stage_configure(parsed: ParsedArgs) -> Result<Configured, ExitCode> {
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

    let early_require_sandbox = parse_require_sandbox(cli.require_sandbox);
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
    // `cognition.sources`は内蔵ツールの既定カタログへの上乗せ（M16、§4.2）。宣言の`trust`は
    // 既に`Settings::load`が【T5】の上限へクランプ済みなので、ここでは解釈するだけでよい。
    let source_catalog = build_source_catalog(&settings);
    // `cognition.recall`（`plans/PLAN-RECALL-MEMORY.md`）。省略時は既定（有効・
    // 履歴なし書込みは無効・Stale再検証は無効）。`allow_unversioned`は`Settings::load`が
    // 既にユーザー層限定へ、`stale_reverification`は既にプロジェクト層からの無効化不可へ
    // クランプ済み。
    let recall_settings = settings.cognition.as_ref().and_then(|c| c.recall.as_ref());
    let recall_enabled = recall_settings.and_then(|r| r.enabled).unwrap_or(true);
    let recall_allow_unversioned = recall_settings
        .and_then(|r| r.allow_unversioned)
        .unwrap_or(false);
    let recall_top_k = recall_settings.and_then(|r| r.top_k).unwrap_or(5);
    let recall_stale_reverification = recall_settings
        .and_then(|r| r.stale_reverification)
        .unwrap_or(false);
    let cognition = match CognitiveOrchestrator::new(cognition_level, phase_budgets.clone()) {
        Ok(c) => c.with_catalog(source_catalog).with_recall_settings(
            recall_enabled,
            recall_allow_unversioned,
            recall_top_k,
            recall_stale_reverification,
        ),
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

    // コンテキスト縮約のポリシー（`plans/PLAN-COMPACTION.md`）。分母はCLIフラグ→`settings.json`
    // →**推論サーバへの問い合わせ**→プロバイダcapabilityの順で解決する。
    // **比率が逆転していれば黙って直さず起動時に止める**——`target >= trigger`だと縮約しても
    // 閾値を下回らず、毎ターン要約コールを打ち続ける。
    let explicit_window = cli
        .context_window
        .or(settings.compaction.as_ref().and_then(|c| c.context_window));
    // 明示指定が無いときだけ問い合わせる（ユーザーが書いた値を検出値で上書きしない）。
    // LM Studioの実`n_ctx`はロード設定依存で、capabilityの128,000とは無関係な値になる
    // ——分母が実態と外れていると使用率トリガそのものが意味を持たない。
    let context_window = match explicit_window {
        Some(n) => Some(n),
        None => {
            let detected = provider.detect_context_window(&model).await;
            // 検出できたら**必ず出す**。分母は発火点を決める値なので、黙って決めない。
            if let Some(n) = detected {
                eprintln!(
                    "detected context window: {n} tokens (from the inference server; \
                     override with --context-window or compaction.context_window)"
                );
            }
            detected
        }
    };
    let compaction = match harness_engine::compaction::CompactionPolicy::resolve(
        &provider.capabilities(),
        harness_engine::compaction::CompactionOverrides {
            context_window,
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

    // 認知レイヤーのフェーズ予算を実コンテキスト窓へ詰め直す（`plans/DESIGN-COGNITION.md`
    // §6.6 規則1）。1フェーズ＝会話履歴を持たない独立した`max_in + max_out`なので、この和が
    // 窓を超える構成は起動直後から全コールが超過する。**縮めたことは黙っていない**——
    // ユーザが`cognition.budgets`か`compaction.context_window`を直せる情報を出す。
    let cognition = if cognition_level == CognitionLevel::Off {
        // 素朴ループにフェーズ予算は関係しない（警告もノイズにしかならない）。
        cognition
    } else {
        let (clamped, clamps) = phase_budgets.clamped_to_window(compaction.context_window);
        if !clamps.is_empty() {
            eprintln!(
                "warning: cognition phase budgets do not fit the context window \
                 ({} tokens); clamping:",
                compaction.context_window
            );
            for clamp in &clamps {
                eprintln!("  {clamp}");
            }
        }
        cognition.with_budgets(clamped)
    };

    // 縮退ガード（`plans/DESIGN-COGNITION.md` §11）。統計はセッション全体を寿命とするので、
    // ここで1つだけ作って発話ごとにcloneして配る。
    let degeneracy = resolve_degeneracy(settings.degeneracy.as_ref());

    let tools = ToolRegistry::with_builtin_tools();

    // `accept-all`へ入ってよいか。**ここで1回だけ決め**、起動時のモードとTUIの`/mode`が同じ値を見る
    // （棚卸しの S1-8。以前は TUI から確認を通らずに切り替えられた）。`DESIGN-CLI-OPTIONS.md`の
    // D-74（全自動にしてよい条件は構成から導く）が実装されたら、この値の決め方だけが変わる。
    let accept_all_permitted = cli.dangerously_allow;
    // §非対話モード: accept-allモードはfail-fastで拒否する（`--dangerously-allow`が無いままの誤起動を防ぐ）。
    if matches!(cli.permission_mode, PermissionModeArg::AcceptAll) && !accept_all_permitted {
        eprintln!(
            "--permission-mode accept-all requires --dangerously-allow (see plans/DESIGN.md §非対話モード)"
        );
        return Err(ExitCode::FAILURE);
    }

    let mut arbiter =
        PermissionArbiter::new(cli.permission_mode.into(), vec![], workspace_root.clone())
            .with_accept_all_permitted(accept_all_permitted);
    // 規則の入口は2つ（コマンドライン・ユーザー層設定）。**プロジェクト層の`allow`は入口ではない**
    // （D-95。`Settings::load`が読み込み時に捨てる）。ワイルドカードの解錠フラグは要らない——
    // 残る2つはどちらもユーザー自身が書いたものだからである。読めない規則は黙って別の意味に読まず、
    // 理由を出して無視する。
    for (origin, rules) in [
        ("user settings", settings.allow.clone().unwrap_or_default()),
        ("--allow", cli.allow.clone()),
    ] {
        for rule in rules {
            if let Err(reason) = parse_allowlist_rule(&rule).and_then(|r| arbiter.add_rule(r)) {
                eprintln!("ignoring {origin} rule {rule:?}: {reason}");
            }
        }
    }
    if settings.ignored_project_allow > 0 {
        eprintln!(
            "note: ignored {} allow rule(s) in the project settings (.harness/settings.json); \
             project-level allow rules are never used for auto-approval — put them in your user \
             settings or pass --allow",
            settings.ignored_project_allow
        );
    }
    load_recorded_approvals(&mut arbiter, &workspace_root);
    let approval_summary = resolve_approval_summary(&settings, &cli, &model);
    let approval_risk = resolve_approval_risk(&settings);

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
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        cognition,
        approval_summary,
        approval_risk,
    })
}

/// 承認画面の要約（D-100）の構成を決める。**作れなくても起動は止めない**
/// ——要約は補助であって境界ではないので、無くても実行の可否は変わらない。告知して切る。
fn resolve_approval_summary(
    settings: &harness_config::Settings,
    cli: &Cli,
    conversation_model: &str,
) -> Option<ApprovalSummaryChoice> {
    let approval = settings.approval.clone().unwrap_or_default();
    if !approval.summarize.unwrap_or(true) {
        return None;
    }
    // プロバイダを指定していなければ、会話と同じものをそのまま使う。
    let Some(name) = approval.summary_provider.as_deref() else {
        return Some(ApprovalSummaryChoice {
            provider: None,
            model: approval
                .summary_model
                .unwrap_or_else(|| conversation_model.to_string()),
            label: cli.provider.label().to_string(),
        });
    };
    let Ok(kind) = <ProviderKind as clap::ValueEnum>::from_str(name, true) else {
        eprintln!(
            "note: approval.summary_provider {name:?} is not a provider this harness knows;              the approval screen will show the contents without a summary"
        );
        return None;
    };
    let model = match approval.summary_model.clone() {
        Some(m) => m,
        None => match resolve_model(None, kind) {
            Ok(m) => m,
            Err(_) => {
                eprintln!(
                    "note: approval.summary_provider is set to {name:?} but approval.summary_model                      is not; the approval screen will show the contents without a summary"
                );
                return None;
            }
        },
    };
    match build_provider(
        kind,
        approval.summary_base_url.clone(),
        #[cfg(feature = "e2e-mock")]
        cli.mock_turns.as_deref(),
        #[cfg(feature = "e2e-mock")]
        cli.mock_record_requests.as_deref(),
    ) {
        Ok(provider) => Some(ApprovalSummaryChoice {
            provider: Some(provider),
            model,
            label: name.to_string(),
        }),
        Err(reason) => {
            eprintln!(
                "note: could not set up approval.summary_provider {name:?} ({reason});                  the approval screen will show the contents without a summary"
            );
            None
        }
    }
}

/// 判定モデル（Ollaya）の既定の送り先とモデル。`approval.risk_base_url`・`approval.risk_model`で変える。
const DEFAULT_RISK_BASE_URL: &str = "http://127.0.0.1:11435";
const DEFAULT_RISK_MODEL: &str = "decider:0.8b";

/// 承認画面の危険度判定（外の判定モデル。`harness_core::risk_check`）の構成を決める。
///
/// **既定は無効**で、`approval.risk_check: true`のときだけ使う。**作れなくても起動は止めない**
/// ——判定は補助で、無ければ承認画面も要約も今までと同じなので、告知して切る。
fn resolve_approval_risk(settings: &harness_config::Settings) -> Option<harness_tui::ApprovalRisk> {
    let approval = settings.approval.as_ref()?;
    if !approval.risk_check.unwrap_or(false) {
        return None;
    }
    let base_url = approval
        .risk_base_url
        .as_deref()
        .unwrap_or(DEFAULT_RISK_BASE_URL);
    let model = approval.risk_model.as_deref().unwrap_or(DEFAULT_RISK_MODEL);
    match harness_providers::DecideClient::new(base_url, model) {
        Ok(client) => {
            let label = client.label();
            Some(harness_tui::ApprovalRisk {
                check: std::sync::Arc::new(client),
                label,
            })
        }
        Err(reason) => {
            eprintln!(
                "note: could not set up approval.risk_check ({reason}); \
                 the approval screen is shown without a risk rating"
            );
            None
        }
    }
}

/// ユーザー層の承認台帳（`run-approval-ledger.json`）を読み、判定器へ入れて件数を告知する（D-107）。
///
/// **記録は縛り直さない**（[`PermissionArbiter::add_recorded_rule`]がその理由を持つ）。
/// 入れるのは、このワークスペースに縛られた記録と、ワークスペースに縛られていない記録
/// （インタプリタでない、ワークスペース外の実行ファイル。§3.1）だけである。
/// 他のワークスペースの記録は入れても照合で落ちるだけなので、件数だけ伝える。
///
/// 台帳が読めなくても起動は止めない——記録が無い状態と同じで、聞かれる回数が増えるだけである。
/// その記録を今のワークスペースで使うか。`None`（どのワークスペースでも共通＝インタプリタでない、
/// ワークスペース外の実行ファイル。§3.1）と、今のワークスペースに縛られたものだけを使う。
fn recorded_rule_applies_here(rule_workspace: Option<&str>, here: &str) -> bool {
    match rule_workspace {
        Some(ws) => ws == here,
        None => true,
    }
}

fn load_recorded_approvals(arbiter: &mut PermissionArbiter, workspace_root: &Path) {
    let store = harness_engine::approval_ledger::ApprovalStore::open_default();
    let loaded = store.load_valid();
    let here = harness_core::fold_path_for_rule(&workspace_root.to_string_lossy());
    let (mut here_count, mut elsewhere) = (0usize, 0usize);
    for rule in loaded.rules {
        if recorded_rule_applies_here(rule.workspace(), &here) {
            arbiter.add_recorded_rule(rule);
            here_count += 1;
        } else {
            elsewhere += 1;
        }
    }
    if here_count > 0 || elsewhere > 0 {
        eprintln!(
            "note: loaded {here_count} recorded approval(s) for this workspace \
             ({elsewhere} recorded for other workspaces are not loaded); \
             `harness approvals list` shows them and `harness approvals revoke <n>` removes one"
        );
    }
    if loaded.voided_by_version > 0 || loaded.dropped_invalid > 0 || loaded.unreadable > 0 {
        eprintln!(
            "note: ignored {} recorded approval(s) written in an older format, {} that did not \
             pass validation, and {} that could not be read at all (written in a newer format, or \
             damaged); they are still listed by `harness approvals list` and you will be asked \
             again for those calls",
            loaded.voided_by_version, loaded.dropped_invalid, loaded.unreadable
        );
    }
}

/// `settings.json`の`degeneracy`キーを`DegeneracyDetector`へ解決する
/// （`plans/DESIGN-COGNITION.md` §11.6）。
///
/// `harness-engine`は`harness-config`に依存しないという既存の依存の向き
/// （`CompactionOverrides`と同じ）を保つため、写像はここが持つ。
/// **`enabled:false`は`None`**＝この機構が一切呼ばれない状態にする（黙って弱めるのではなく、
/// 検知器そのものを渡さない形で切る）。
fn resolve_degeneracy(
    settings: Option<&harness_config::DegeneracySettings>,
) -> Option<harness_engine::degeneracy::DegeneracyDetector> {
    use harness_engine::degeneracy::{
        DegeneracyConfig, DegeneracyDetector, NgramConfig, ShortPeriodConfig,
    };

    let s = settings.cloned().unwrap_or_default();
    if !s.is_enabled() {
        return None;
    }
    let d = DegeneracyConfig::default();
    let sp = s.short_period.unwrap_or_default();
    let ng = s.ngram.unwrap_or_default();
    Some(DegeneracyDetector::new(DegeneracyConfig {
        auto_recycle: s.auto_recycle.unwrap_or(d.auto_recycle),
        gate_multiplier: s.gate_multiplier.unwrap_or(d.gate_multiplier),
        recovery_multiplier: s.recovery_multiplier.unwrap_or(d.recovery_multiplier),
        short_period: ShortPeriodConfig {
            window: sp.window.unwrap_or(d.short_period.window),
            max_period: sp.max_period.unwrap_or(d.short_period.max_period),
            min_repeats: sp.min_repeats.unwrap_or(d.short_period.min_repeats),
        },
        ngram: NgramConfig {
            window: ng.window.unwrap_or(d.ngram.window),
            n: ng.n.unwrap_or(d.ngram.n),
            seen_ratio_max: ng.seen_ratio_max.unwrap_or(d.ngram.seen_ratio_max),
            min_hot_sections: ng.min_hot_sections.unwrap_or(d.ngram.min_hot_sections),
            min_hot_sections_suspect: ng
                .min_hot_sections_suspect
                .unwrap_or(d.ngram.min_hot_sections_suspect),
        },
        reasoning_only_ratio: s.reasoning_only_ratio.unwrap_or(d.reasoning_only_ratio),
    }))
}

/// `settings.json`の`cognition.sources`を情報源カタログへ写す（M16、
/// `plans/DESIGN-COGNITION.md` §4.2）。
///
/// 内蔵ツールの既定カタログへの**上乗せ**なので、宣言が無くてもカタログは空にならない
/// （`read_file`等は常に情報源として見える）。文字列の解釈は
/// `harness_cognition::SourceEntry::from_declaration`が持ち、ここは形を変えるだけ。
fn build_source_catalog(settings: &harness_config::Settings) -> harness_cognition::SourceCatalog {
    let declared = settings
        .cognition
        .as_ref()
        .and_then(|c| c.sources.as_ref())
        .map(|sources| {
            sources
                .iter()
                // idの無いエントリは何も指していないので落とす。
                .filter_map(|s| {
                    let id = s.id.as_deref()?;
                    Some(harness_cognition::SourceEntry::from_declaration(
                        id,
                        s.kind.as_deref(),
                        s.use_for.clone().unwrap_or_default(),
                        s.trust.as_deref(),
                        s.freshness.as_deref(),
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    harness_cognition::SourceCatalog::with_builtin_defaults().merged_with(declared)
}

#[cfg(test)]
mod tests {
    //! `resolve_degeneracy`の写像テスト。
    //!
    //! 従来ワークスペースに1件も無かった穴を塞ぐ——「settings.jsonに書いた値が実際に
    //! `DegeneracyConfig`へ届くか」を固定するテストが、`harness-config`側にも
    //! `resolve_degeneracy`側にも存在しなかった（BUG-087調査で判明）。

    use super::*;
    use harness_config::{DegeneracySettings, NgramSettings, ShortPeriodSettings};
    use harness_engine::degeneracy::DegeneracyConfig;

    #[test]
    fn enabled_false_disables_the_detector_entirely() {
        let settings = DegeneracySettings {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(resolve_degeneracy(Some(&settings)).is_none());
    }

    #[test]
    fn no_settings_at_all_uses_the_engine_default() {
        let d = resolve_degeneracy(None).expect("既定はenabled=true");
        assert_eq!(*d.config(), DegeneracyConfig::default());
    }

    #[test]
    fn every_field_set_reaches_the_engine_config_verbatim() {
        let settings = DegeneracySettings {
            enabled: Some(true),
            auto_recycle: Some(true),
            gate_multiplier: Some(2.5),
            recovery_multiplier: Some(4.0),
            short_period: Some(ShortPeriodSettings {
                window: Some(256),
                max_period: Some(16),
                min_repeats: Some(4),
            }),
            ngram: Some(NgramSettings {
                window: Some(2_048),
                n: Some(24),
                seen_ratio_max: Some(0.75),
                min_hot_sections: Some(5),
                min_hot_sections_suspect: Some(2),
            }),
            reasoning_only_ratio: Some(0.4),
        };
        let d = resolve_degeneracy(Some(&settings)).expect("enabled=true");
        let cfg = d.config();
        assert!(cfg.auto_recycle);
        assert_eq!(cfg.gate_multiplier, 2.5);
        assert_eq!(cfg.recovery_multiplier, 4.0);
        assert_eq!(cfg.short_period.window, 256);
        assert_eq!(cfg.short_period.max_period, 16);
        assert_eq!(cfg.short_period.min_repeats, 4);
        assert_eq!(cfg.ngram.window, 2_048);
        assert_eq!(cfg.ngram.n, 24);
        assert_eq!(cfg.ngram.seen_ratio_max, 0.75);
        assert_eq!(cfg.ngram.min_hot_sections, 5);
        assert_eq!(cfg.ngram.min_hot_sections_suspect, 2);
        assert_eq!(cfg.reasoning_only_ratio, 0.4);
    }

    #[test]
    fn partial_ngram_settings_fall_back_field_by_field() {
        // `ngram.n`だけ指定し、他のngramキー（`min_hot_sections`等）は既定へ落ちることを確認する。
        // `NgramSettings`は全フィールド`Option`なので、`..Default::default()`で他を空にできる。
        let settings = DegeneracySettings {
            ngram: Some(NgramSettings {
                n: Some(48),
                ..Default::default()
            }),
            ..Default::default()
        };
        let d = resolve_degeneracy(Some(&settings)).expect("enabled=true");
        let cfg = d.config();
        let default_ngram = DegeneracyConfig::default().ngram;
        assert_eq!(cfg.ngram.n, 48);
        assert_eq!(cfg.ngram.window, default_ngram.window);
        assert_eq!(cfg.ngram.seen_ratio_max, default_ngram.seen_ratio_max);
        assert_eq!(cfg.ngram.min_hot_sections, default_ngram.min_hot_sections);
        assert_eq!(
            cfg.ngram.min_hot_sections_suspect,
            default_ngram.min_hot_sections_suspect
        );
    }

    /// 台帳の記録は、今のワークスペースのものと「どこでも共通」のものだけを使う（D-107）。
    /// 別のワークスペースの記録は入れない——照合で落ちるだけなので判定は変わらないが、
    /// 起動時の件数が他のプロジェクトの分まで混ざると読めなくなる。
    #[test]
    fn only_this_workspace_and_workspace_independent_records_are_loaded() {
        let here = harness_core::fold_path_for_rule("C:/ws/project");
        assert!(recorded_rule_applies_here(Some(&here), &here));
        assert!(recorded_rule_applies_here(None, &here));
        assert!(!recorded_rule_applies_here(
            Some(&harness_core::fold_path_for_rule("C:/ws/other")),
            &here
        ));
        // 区切りと大小は畳んだうえで比べる（Windows）。
        assert!(recorded_rule_applies_here(
            Some(&harness_core::fold_path_for_rule(r"C:\ws\project\")),
            &here
        ));
    }

    /// 設定→要約のプロバイダ選択（D-100）。**既定は会話と同じものを共有する**——同じで済むときに
    /// 2本目を建てない（資格情報を二重に要求しない）。切ったら何も作らない。
    #[test]
    fn the_approval_summary_follows_the_settings() {
        let cli = Cli::parse_from(["harness"]);
        let with = |approval: Option<harness_config::ApprovalSettings>| harness_config::Settings {
            approval,
            ..Default::default()
        };

        // 既定（節なし）: 会話と同じプロバイダ・同じモデル。
        let chosen = resolve_approval_summary(&with(None), &cli, "conv-model").expect("既定は有効");
        assert!(chosen.provider.is_none(), "2本目を建てている");
        assert_eq!(chosen.model, "conv-model");

        // 切った: 何も作らない。
        assert!(resolve_approval_summary(
            &with(Some(harness_config::ApprovalSettings {
                summarize: Some(false),
                ..Default::default()
            })),
            &cli,
            "conv-model"
        )
        .is_none());

        // モデルだけ指定: プロバイダは会話と同じまま、モデルだけ変わる。
        let chosen = resolve_approval_summary(
            &with(Some(harness_config::ApprovalSettings {
                summary_model: Some("small".into()),
                ..Default::default()
            })),
            &cli,
            "conv-model",
        )
        .expect("モデルだけの指定でも有効");
        assert!(chosen.provider.is_none());
        assert_eq!(chosen.model, "small");

        // 別プロバイダ＋モデル: 2本目を建てる。
        let chosen = resolve_approval_summary(
            &with(Some(harness_config::ApprovalSettings {
                summary_provider: Some("lmstudio".into()),
                summary_model: Some("small".into()),
                ..Default::default()
            })),
            &cli,
            "conv-model",
        )
        .expect("別プロバイダの指定が有効");
        assert!(chosen.provider.is_some());
        assert_eq!(chosen.model, "small");
        assert_eq!(chosen.label, "lmstudio");

        // 知らないプロバイダ名: **起動は止めず**、要約だけ切る。
        assert!(resolve_approval_summary(
            &with(Some(harness_config::ApprovalSettings {
                summary_provider: Some("no-such-provider".into()),
                ..Default::default()
            })),
            &cli,
            "conv-model"
        )
        .is_none());
    }

    /// 設定→危険度判定（外の判定モデル）の構成。**既定は無効**——聞くとコマンドの1行がサーバへ出るので、
    /// 設定が無ければ何も作らない（承認画面も要約も今までと同じ）。作れなくても起動は止めない。
    #[test]
    fn the_risk_check_is_off_unless_the_settings_turn_it_on() {
        let with = |approval: Option<harness_config::ApprovalSettings>| harness_config::Settings {
            approval,
            ..Default::default()
        };
        let on = |tweak: fn(&mut harness_config::ApprovalSettings)| {
            let mut a = harness_config::ApprovalSettings {
                risk_check: Some(true),
                ..Default::default()
            };
            tweak(&mut a);
            with(Some(a))
        };

        // 節なし・risk_check なし・偽: 何も作らない（既定は無効）。
        assert!(resolve_approval_risk(&with(None)).is_none());
        assert!(resolve_approval_risk(&with(Some(Default::default()))).is_none());
        assert!(
            resolve_approval_risk(&with(Some(harness_config::ApprovalSettings {
                risk_check: Some(false),
                risk_model: Some("decider:0.8b".into()),
                ..Default::default()
            })))
            .is_none()
        );

        // 有効: 送り先とモデルの既定で作り、出どころを画面用に持つ。
        let chosen = resolve_approval_risk(&on(|_| {})).expect("有効なら作る");
        assert_eq!(chosen.label, "ollaya / decider:0.8b");

        // 指定した送り先・モデルが出どころへ出る（どこへコマンドが出たかが分かる）。
        let chosen = resolve_approval_risk(&on(|a| {
            a.risk_base_url = Some("http://10.0.0.5:11435".into());
            a.risk_model = Some("winnow:e4b".into());
        }))
        .expect("指定どおりに作る");
        assert_eq!(chosen.label, "ollaya / winnow:e4b");

        // 作れない指定（空のモデル名）: 起動は止めず、判定だけ切る。
        assert!(resolve_approval_risk(&on(|a| a.risk_model = Some("  ".into()))).is_none());
    }
}
