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
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        cognition,
    })
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
}
