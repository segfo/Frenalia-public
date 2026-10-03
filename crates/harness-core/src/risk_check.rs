//! 承認画面の危険度判定（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-100 の追記）。
//!
//! # これは境界ではない
//!
//! 外の判定モデル（Ollaya の `agent` 設定。コマンド1行から危険度の数値を返す）の結果を、承認画面の
//! 色・見出しと、要約を書かせるモデルへの一言に使う。**通す・止めるは決めない**——聞くか聞かないかは
//! 判定器（`PermissionArbiter`）のままで、画面は従来どおり人の承認を待つ。判定モデルは、攻撃者が書いた
//! かもしれないコマンドを読んで答えるので、**低いと返っても安全の保証にはならない**（D-100 と同じ理由）。
//! だから[`RiskLevel::Low`]は画面にも要約にも何も足さない。
//!
//! 判定モデルが無い・落ちている・遅いときは、この結果が無いだけで、画面も要約も今までと同じである。

use async_trait::async_trait;

/// 危険度の数値がこの値以上なら[`RiskLevel::Caution`]。
///
/// 初期値。判定モデルの実測（`rm C:\test.txt` が0.93、`rm C:\Users\…\test.txt` が0.90、
/// `systeminfo` が0.13〜0.51）の間に引いた線で、見直すときは**実測を足してから**動かす。
pub const CAUTION_FROM: f32 = 0.8;
/// 危険度の数値がこの値以上なら[`RiskLevel::Danger`]。実測では `calc.exe` の削除が1.73、
/// `mimikatz` が1.72、`cmd del C:\` が1.83。**1.32 のような中間の値もあるので、境界はまだ粗い。**
pub const DANGER_FROM: f32 = 1.5;
/// 判定モデルの数値の範囲（0＝無害、2＝共有物の喪失や本番の破壊）。範囲外は壊れた応答として扱う。
pub const SCORE_MAX: f32 = 2.0;

/// 危険度の段階。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// 低い。**画面にも要約にも何も足さない**（安全の保証ではないので、安全とは書かない）。
    Low,
    /// 注意（ローカルの作業を失い得る程度）。
    Caution,
    /// 危険（共有物の喪失や本番の破壊に届き得る）。
    Danger,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        if score >= DANGER_FROM {
            RiskLevel::Danger
        } else if score >= CAUTION_FROM {
            RiskLevel::Caution
        } else {
            RiskLevel::Low
        }
    }

    /// 画面や要約へ足す価値のある段階か（`Low`は足さない）。
    pub fn is_elevated(self) -> bool {
        self != RiskLevel::Low
    }

    /// 要約を書かせるモデルへ渡す、**固定の英文**。判定モデルが返した文字列は混ぜない
    /// （自由な文字列を system へ入れない）。`Low`は`None`。
    pub fn summary_instruction(self) -> Option<&'static str> {
        match self {
            RiskLevel::Low => None,
            RiskLevel::Caution => Some(
                "An independent risk check rated this material as risky: it could lose local work. \
                 Say so plainly, then describe what it actually does. The rating is an aid, not proof.",
            ),
            RiskLevel::Danger => Some(
                "An independent risk check rated this material as DANGEROUS: it could lose shared \
                 data or break production. Say so plainly first, then describe what it actually \
                 does. The rating is an aid, not proof.",
            ),
        }
    }

    /// 画面に出す理由（判定モデルの3段階の定型に対応する。判定モデルの返した文字列は使わない）。
    pub fn reason_ja(self) -> &'static str {
        match self {
            RiskLevel::Low => "低い",
            RiskLevel::Caution => "ローカルの作業を失い得る",
            RiskLevel::Danger => "共有データを失う・本番を壊し得る",
        }
    }
}

/// 判定の結果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskVerdict {
    /// 判定モデルが返した数値（0〜[`SCORE_MAX`]）。画面に出す。
    pub score: f32,
    pub level: RiskLevel,
}

impl RiskVerdict {
    /// 数値から作る。**範囲外・非数は壊れた応答**として`Err`にする（段階へ丸めて黙って通さない）。
    pub fn from_score(score: f32) -> Result<Self, RiskCheckError> {
        if !score.is_finite() || !(0.0..=SCORE_MAX).contains(&score) {
            return Err(RiskCheckError(format!(
                "危険度の数値が範囲外だった（{score}。0〜{SCORE_MAX}のはず）"
            )));
        }
        Ok(Self {
            score,
            level: RiskLevel::from_score(score),
        })
    }
}

/// 判定を得られなかった理由。画面は出さず、セッションにつき1回だけ会話の記録へ書く。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskCheckError(pub String);

impl std::fmt::Display for RiskCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RiskCheckError {}

/// コマンド1行の危険度を返す部品。実装は`harness-providers`（Ollaya）。
///
/// `LlmProvider`には載せない——文章を作らず、選択肢の確率を返すだけで、`stream()`の形に合わない。
#[async_trait]
pub trait RiskCheck: Send + Sync {
    async fn assess(&self, command_line: &str) -> Result<RiskVerdict, RiskCheckError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_scores_land_on_the_levels_they_were_taken_from() {
        // 実測（Ollaya `agent`、2026-10-04）: 無害〜注意〜危険の各点。
        assert_eq!(RiskLevel::from_score(0.13), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.51), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.90), RiskLevel::Caution);
        assert_eq!(RiskLevel::from_score(0.93), RiskLevel::Caution);
        assert_eq!(RiskLevel::from_score(1.32), RiskLevel::Caution);
        assert_eq!(RiskLevel::from_score(1.72), RiskLevel::Danger);
        assert_eq!(RiskLevel::from_score(1.83), RiskLevel::Danger);
    }

    #[test]
    fn low_adds_nothing_so_it_cannot_be_read_as_a_guarantee() {
        assert!(!RiskLevel::Low.is_elevated());
        assert!(RiskLevel::Low.summary_instruction().is_none());
        assert!(RiskLevel::Caution.summary_instruction().is_some());
        assert!(RiskLevel::Danger.summary_instruction().is_some());
    }

    #[test]
    fn a_broken_number_is_an_error_not_a_level() {
        for bad in [f32::NAN, f32::INFINITY, -0.1, 2.01] {
            assert!(RiskVerdict::from_score(bad).is_err(), "{bad}");
        }
        assert!(RiskVerdict::from_score(0.0).is_ok());
        assert!(RiskVerdict::from_score(2.0).is_ok());
    }
}
