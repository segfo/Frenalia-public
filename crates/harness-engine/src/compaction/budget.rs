//! 縮約の発火判定と削減目標の算出（純粋・provider非依存）。
//! `plans/PLAN-COMPACTION.md`「発火条件」「ヒステリシス」「既定値とローカル判定」。
//!
//! **この層はLLMコールを一切しない**。判定に使うのは前ターンの実測`Usage`と、それ以降に積んだ
//! メッセージの文字数概算だけである。

use harness_core::{ProviderCapabilities, Usage};

/// ローカル推論サーバ（LMStudio等）の既定閾値。
///
/// クラウドより大幅に低いのは、(1) 宣言された`context_window`がRoPEスケーリング等で名目上
/// 伸ばした値であることが多く後半の文脈が実質参照されない、(2) 実`n_ctx`はサーバのロード設定
/// 依存でモデルカードの最大値とは別、(3) 超過時に400を返さず黙って古いトークンを捨てる実装が
/// ありリアクティブ経路が当てにならない、の3点による（`plans/PLAN-COMPACTION.md`）。
pub const LOCAL_TRIGGER_RATIO: f32 = 0.5;
pub const LOCAL_TARGET_RATIO: f32 = 0.3;
pub const CLOUD_TRIGGER_RATIO: f32 = 0.85;
pub const CLOUD_TARGET_RATIO: f32 = 0.6;

/// (B)超過直前トリガの余裕分。推定が外れる方向へ倒すための固定マージン。
const SAFETY_MARGIN_TOKENS: u64 = 1_024;

/// 未計測分に掛ける安全係数。`estimate_json_tokens`のchars/4は、日本語・エスケープの多い
/// JSON履歴で**過小評価**する（CJKは1文字≒1トークン以上）。実測の`used`には掛けない。
const UNMEASURED_SAFETY_FACTOR: u64 = 2;

/// ポリシー解決前の上書き値。
///
/// `harness-config`の`CompactionSettings`とCLIフラグを`harness-cli`が畳んでここへ渡す。
/// **`harness-engine`は`harness-config`に依存しない**——設定型を知るのは`harness-cli`だけ、
/// というのがこのワークスペースの既存の依存の向き（`harness-cognition`の`PhaseBudgets`も
/// 同じ流儀）。`plans/PLAN-COMPACTION.md`が`resolve`に`&CompactionSettings`を直接渡す形で
/// 書いているのは、この制約に気付く前の記述である。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CompactionOverrides {
    /// 判定の分母。省略時は`ProviderCapabilities.context_window`。
    pub context_window: Option<u32>,
    pub trigger_ratio: Option<f32>,
    pub target_ratio: Option<f32>,
}

/// 解決済みの縮約ポリシー。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompactionPolicy {
    pub trigger_ratio: f32,
    pub target_ratio: f32,
    pub context_window: u32,
}

/// ポリシーが成立しない設定。**黙って直さず起動時に止める**ためのエラー。
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyError {
    /// `target_ratio >= trigger_ratio`。縮約しても閾値を下回らないので毎ターン再発火して振動する。
    TargetNotBelowTrigger { trigger: f32, target: f32 },
    /// 比率が`(0, 1]`の外。
    RatioOutOfRange { name: &'static str, value: f32 },
    /// 分母が0。使用率が定義できない。
    ZeroContextWindow,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::TargetNotBelowTrigger { trigger, target } => write!(
                f,
                "compaction.target_ratio ({target}) must be strictly below \
                 compaction.trigger_ratio ({trigger}); otherwise compaction re-fires every turn"
            ),
            PolicyError::RatioOutOfRange { name, value } => {
                write!(f, "compaction.{name} ({value}) must be within (0, 1]")
            }
            PolicyError::ZeroContextWindow => {
                write!(f, "compaction.context_window must be greater than zero")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl Default for CompactionPolicy {
    /// クラウド既定（0.85/0.6）＋200,000。
    ///
    /// **実行経路は必ず[`CompactionPolicy::resolve`]を通す**（`harness-cli`が起動時に解決して
    /// `AgentLoopConfig`へ載せる）。この`Default`は、プロバイダcapabilityを持たない文脈
    /// ——主にテスト——のための値である。`MockProvider`の`context_window`（200,000）と
    /// 一致させてあるので、既存のgolden testでは使用率トリガが発火せず、M13で固定した
    /// バイト等価性がそのまま保たれる。
    fn default() -> Self {
        Self {
            trigger_ratio: CLOUD_TRIGGER_RATIO,
            target_ratio: CLOUD_TARGET_RATIO,
            context_window: 200_000,
        }
    }
}

impl CompactionPolicy {
    /// capabilityの既定（`local`なら0.5/0.3、そうでなければ0.85/0.6）に上書きを載せて解決する。
    pub fn resolve(
        caps: &ProviderCapabilities,
        overrides: CompactionOverrides,
    ) -> Result<Self, PolicyError> {
        let (default_trigger, default_target) = if caps.local {
            (LOCAL_TRIGGER_RATIO, LOCAL_TARGET_RATIO)
        } else {
            (CLOUD_TRIGGER_RATIO, CLOUD_TARGET_RATIO)
        };

        let policy = Self {
            trigger_ratio: overrides.trigger_ratio.unwrap_or(default_trigger),
            target_ratio: overrides.target_ratio.unwrap_or(default_target),
            context_window: overrides.context_window.unwrap_or(caps.context_window),
        };

        for (name, value) in [
            ("trigger_ratio", policy.trigger_ratio),
            ("target_ratio", policy.target_ratio),
        ] {
            if !(value > 0.0 && value <= 1.0) {
                return Err(PolicyError::RatioOutOfRange { name, value });
            }
        }
        if policy.context_window == 0 {
            return Err(PolicyError::ZeroContextWindow);
        }
        if policy.target_ratio >= policy.trigger_ratio {
            return Err(PolicyError::TargetNotBelowTrigger {
                trigger: policy.trigger_ratio,
                target: policy.target_ratio,
            });
        }
        Ok(policy)
    }

    fn scaled(&self, ratio: f32) -> u64 {
        (f64::from(self.context_window) * f64::from(ratio)) as u64
    }
}

/// 現時点のコンテキスト圧。判定に使った値をすべて保持するのは、**発火理由をログ1行で
/// 説明できるようにする**ため（「使用率0.62が閾値0.5を超えた」「未計測分でhard limitに触れた」）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ContextPressure {
    /// 前ターンの実測`Usage`合算（初回・`--resume`直後は概算）。(A)の分子。
    pub used: u64,
    /// 前ターン以降に積んだ未計測分（安全係数適用済み）。
    pub unmeasured: u64,
    /// 現時点の入力見積り＝`used + unmeasured`。①②が削る対象の総量。
    pub projected_input: u64,
    /// (B)の左辺＝`projected_input + max_tokens + margin`。
    pub projected_total: u64,
    /// (A)の閾値＝`context_window × trigger_ratio`。
    pub policy_limit: u64,
    /// (B)の閾値＝`context_window`。
    pub hard_limit: u64,
    /// 縮約後に目指す水準＝`context_window × target_ratio`。
    pub target: u64,
}

impl ContextPressure {
    /// (A)使用率トリガ。前ターンの**実測値**だけで判定する（推定に依存しない本命の経路）。
    pub fn usage_trigger(&self) -> bool {
        self.used >= self.policy_limit
    }

    /// (B)超過直前トリガ。(A)の分母は前ターンの実測値なので、**そのターンで巨大な`tool_result`が
    /// 1件入って一気に超過する**ケースに追随できない。その取りこぼしの受け皿。
    pub fn overflow_trigger(&self) -> bool {
        self.projected_total >= self.hard_limit
    }

    pub fn should_compact(&self) -> bool {
        self.usage_trigger() || self.overflow_trigger()
    }

    /// 削減目標（トークン）。
    ///
    /// `plans/PLAN-COMPACTION.md`は`used - context_window × target_ratio`と書いているが、
    /// **分子を`projected_input`にしてある**。`used`のままだと、(B)が「巨大な未計測`tool_result`」で
    /// 発火したときに`used`自体は小さいままなので目標が0になり、①②が何も削らずに終わる
    /// ——(B)トリガが機能しなくなる。削るべき対象は実際の入力全体なので、未計測分を含めて数える。
    pub fn target_savings(&self) -> u64 {
        self.projected_input.saturating_sub(self.target)
    }

    /// 使用率（表示・ログ用）。
    pub fn usage_ratio(&self) -> f64 {
        if self.hard_limit == 0 {
            return 0.0;
        }
        self.used as f64 / self.hard_limit as f64
    }
}

/// 圧の評価。
///
/// `last_usage`が`None`（初回ターン・`--resume`/`--continue`直後）は実測値が無いので
/// `fallback_estimate`（`estimate_tokens(&req)`）を`used`の代用にする。
pub fn assess(
    last_usage: Option<Usage>,
    fallback_estimate: u64,
    unmeasured: u64,
    max_tokens: u32,
    policy: &CompactionPolicy,
) -> ContextPressure {
    let used = match last_usage {
        Some(u) => {
            // `cache_read`もウィンドウを占有するので合算する。
            u64::from(u.input)
                + u64::from(u.output)
                + u64::from(u.cache_read)
                + u64::from(u.cache_creation)
        }
        None => fallback_estimate,
    };
    let unmeasured = unmeasured.saturating_mul(UNMEASURED_SAFETY_FACTOR);
    let projected_input = used.saturating_add(unmeasured);
    let projected_total = projected_input
        .saturating_add(u64::from(max_tokens))
        .saturating_add(SAFETY_MARGIN_TOKENS);

    ContextPressure {
        used,
        unmeasured,
        projected_input,
        projected_total,
        policy_limit: policy.scaled(policy.trigger_ratio),
        hard_limit: u64::from(policy.context_window),
        target: policy.scaled(policy.target_ratio),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(local: bool, context_window: u32) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: false,
            forced_tool_choice: false,
            schema_with_thinking: false,
            schema_with_tools: false,
            prompt_caching: false,
            context_window,
            local,
        }
    }

    fn usage(input: u32) -> Usage {
        Usage {
            input,
            output: 0,
            cache_read: 0,
            cache_creation: 0,
        }
    }

    #[test]
    fn local_and_cloud_defaults_differ() {
        let local =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();
        assert_eq!(local.trigger_ratio, LOCAL_TRIGGER_RATIO);
        assert_eq!(local.target_ratio, LOCAL_TARGET_RATIO);
        assert_eq!(local.context_window, 8_192);

        let cloud =
            CompactionPolicy::resolve(&caps(false, 200_000), CompactionOverrides::default())
                .unwrap();
        assert_eq!(cloud.trigger_ratio, CLOUD_TRIGGER_RATIO);
        assert_eq!(cloud.target_ratio, CLOUD_TARGET_RATIO);
    }

    #[test]
    fn overrides_replace_each_default_independently() {
        let p = CompactionPolicy::resolve(
            &caps(true, 128_000),
            CompactionOverrides {
                context_window: Some(32_768),
                trigger_ratio: None,
                target_ratio: Some(0.2),
            },
        )
        .unwrap();
        assert_eq!(p.context_window, 32_768);
        assert_eq!(p.trigger_ratio, LOCAL_TRIGGER_RATIO);
        assert_eq!(p.target_ratio, 0.2);
    }

    /// `target >= trigger`は縮約しても閾値を下回らず毎ターン再発火する。黙って直さず止める。
    #[test]
    fn target_ratio_must_be_strictly_below_trigger_ratio() {
        let err = CompactionPolicy::resolve(
            &caps(true, 8_192),
            CompactionOverrides {
                context_window: None,
                trigger_ratio: Some(0.5),
                target_ratio: Some(0.5),
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            PolicyError::TargetNotBelowTrigger {
                trigger: 0.5,
                target: 0.5
            }
        );
        assert!(err.to_string().contains("re-fires every turn"), "{err}");
    }

    #[test]
    fn ratios_outside_the_unit_interval_are_rejected() {
        for (trigger, target, bad) in [
            (Some(1.5), None, "trigger_ratio"),
            (None, Some(0.0), "target_ratio"),
        ] {
            let err = CompactionPolicy::resolve(
                &caps(true, 8_192),
                CompactionOverrides {
                    context_window: None,
                    trigger_ratio: trigger,
                    target_ratio: target,
                },
            )
            .unwrap_err();
            match err {
                PolicyError::RatioOutOfRange { name, .. } => assert_eq!(name, bad),
                other => panic!("expected RatioOutOfRange for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn zero_context_window_is_rejected() {
        let err =
            CompactionPolicy::resolve(&caps(true, 0), CompactionOverrides::default()).unwrap_err();
        assert_eq!(err, PolicyError::ZeroContextWindow);
    }

    /// (A)は`trigger_ratio`の境界で切り替わる。分母8,192・比率0.5なので閾値は4,096。
    #[test]
    fn usage_trigger_switches_at_the_ratio_boundary() {
        let policy =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();

        let below = assess(Some(usage(4_095)), 0, 0, 512, &policy);
        assert!(!below.usage_trigger());
        assert!(!below.should_compact());

        let at = assess(Some(usage(4_096)), 0, 0, 512, &policy);
        assert!(at.usage_trigger());
        assert!(at.should_compact());
    }

    /// (B)は使用率が閾値未満でも、巨大な未計測分で発火する。
    #[test]
    fn overflow_trigger_fires_on_a_large_unmeasured_chunk_below_the_usage_threshold() {
        let policy =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();

        // used=1,000（使用率0.12＝(A)は不発）だが、未計測4,000は安全係数2倍で8,000になり、
        // max_tokens+marginを足すとhard limit 8,192を越える。
        let p = assess(Some(usage(1_000)), 0, 4_000, 512, &policy);
        assert!(!p.usage_trigger());
        assert!(p.overflow_trigger());
        assert!(p.should_compact());
        assert_eq!(p.unmeasured, 8_000);
    }

    /// (B)経由で発火したとき、削減目標が0にならないこと（`used`基準だと0になり①②が空回りする）。
    #[test]
    fn target_savings_counts_the_unmeasured_bytes_so_the_overflow_trigger_can_act() {
        let policy =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();
        let p = assess(Some(usage(1_000)), 0, 4_000, 512, &policy);

        // target = 8,192 × 0.3 = 2,457。used(1,000) だけなら 0 になってしまう。
        assert_eq!(p.target, 2_457);
        assert_eq!(
            p.used.saturating_sub(p.target),
            0,
            "used基準だと目標が消える"
        );
        assert_eq!(p.target_savings(), 9_000 - 2_457);
    }

    /// 実測`Usage`は4分割すべてを合算する（`cache_read`もウィンドウを占有する）。
    #[test]
    fn used_sums_every_usage_bucket() {
        let policy =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();
        let p = assess(
            Some(Usage {
                input: 100,
                output: 20,
                cache_read: 3_000,
                cache_creation: 5,
            }),
            0,
            0,
            512,
            &policy,
        );
        assert_eq!(p.used, 3_125);
    }

    /// 初回ターン（実測値なし）は概算へフォールバックする。
    #[test]
    fn the_first_turn_falls_back_to_the_estimate() {
        let policy =
            CompactionPolicy::resolve(&caps(true, 8_192), CompactionOverrides::default()).unwrap();
        let p = assess(None, 5_000, 0, 512, &policy);
        assert_eq!(p.used, 5_000);
        assert!(p.usage_trigger());
    }
}
