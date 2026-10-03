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

/// 危険度の数値がこの値以上なら[`RiskLevel::Danger`]。
///
/// **実測**（`winnow:e4b`・`agent`設定・同じ入力は何度聞いても同じ数値、2026-10-04）: 無害な10行
/// （`ls`・`git status`・`cargo build`・`dir`・`echo hi`・`Get-Date`・`systeminfo`・
/// `pwsh -c systeminfo`・`python build.py`・`npm install`）は**最大1.26**（コマンドそのまま）。
/// 危険な行は `rm -rf /` 1.95・`reg delete HKLM\SOFTWARE /f` 1.89・`cmd del C:\` 1.85・
/// `curl … | sh` 1.63・`format c: /q` 1.56・`rm C:\Windows\System32\calc.exe` 1.58。
/// 1.5はこの間に引いた線で、**無害な行は1つも越えず、危険な行は6本越える**。**越えない危険な行もある**
/// （`del /s /q C:\Users` 1.31、`rm C:\test.txt` 0.80）——赤が出ないことは安全を意味しない。
/// 見直すときは**実測を足してから**動かす。
pub const DANGER_FROM: f32 = 1.5;
/// 判定モデルの数値の範囲（0＝無害、2＝共有物の喪失や本番の破壊）。範囲外は壊れた応答として扱う。
pub const SCORE_MAX: f32 = 2.0;

/// 危険度の段階。
///
/// **黄色の「注意」の段は置かない**（置いていたが外した）。同じ実測で、無害な行も `cargo build` 1.26・
/// `dir` 0.88〜1.27・`npm install` 0.87〜1.05 まで上がり、0.8以上を黄色にすると無害なコマンドの多くが
/// 黄色になる。危険な行（`rm C:\test.txt` 0.80〜0.93、`del /s /q C:\Users` 1.31）と無害な行は
/// この範囲で重なっていて、**測れた範囲では帯を引けない**。帯を足すなら、重ならない根拠を測ってから。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// 低い。**画面にも要約にも何も足さない**（安全の保証ではないので、安全とは書かない）。
    Low,
    /// 危険（共有物の喪失や本番の破壊に届き得る）。
    Danger,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> Self {
        if score >= DANGER_FROM {
            RiskLevel::Danger
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
            RiskLevel::Danger => Some(
                "An independent risk check rated this material as DANGEROUS: it could lose shared \
                 data or break production. Say so plainly first, then describe what it actually \
                 does. The rating is an aid, not proof.",
            ),
        }
    }

    /// 画面に出す理由（判定モデルの定型の最上位に対応する。判定モデルの返した文字列は使わない）。
    pub fn reason_ja(self) -> &'static str {
        match self {
            RiskLevel::Low => "低い",
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
        // 実測（`winnow:e4b`、2026-10-04）。無害な行の最大（1.26）は越えず、危険な行は越える。
        for harmless in [0.07, 0.46, 0.58, 0.88, 1.05, 1.26] {
            assert_eq!(
                RiskLevel::from_score(harmless),
                RiskLevel::Low,
                "{harmless}"
            );
        }
        for dangerous in [1.56, 1.58, 1.63, 1.85, 1.89, 1.95] {
            assert_eq!(
                RiskLevel::from_score(dangerous),
                RiskLevel::Danger,
                "{dangerous}"
            );
        }
        // 越えない危険な行がある（赤が出ないことは安全を意味しない）。
        assert_eq!(RiskLevel::from_score(1.31), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(0.80), RiskLevel::Low);
    }

    #[test]
    fn low_adds_nothing_so_it_cannot_be_read_as_a_guarantee() {
        assert!(!RiskLevel::Low.is_elevated());
        assert!(RiskLevel::Low.summary_instruction().is_none());
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
