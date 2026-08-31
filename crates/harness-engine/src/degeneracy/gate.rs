//! 異常ゲート — 「疑わしいときだけ厳しく見る」（`plans/DESIGN-COGNITION.md` §11.2）。
//!
//! **時間や出力量の逸脱それ自体は縮退の証拠にならない**（正当な長文回答も同じ症状を示す）ので、
//! 単独の判定には使わず、誤検知しやすい検知器（②④）を**評価するかどうか**のゲートにだけ使う。
//!
//! ```text
//! gate_open = (visible_chars + thinking_chars > median_chars   × gate_multiplier)
//!          OR (elapsed                        > median_elapsed × gate_multiplier)
//! ```
//!
//! 誤検知の抑制を閾値の連続調整ではなく**構造**で行うため、発火理由が常にログ1行で説明できる。
//!
//! # なぜ平均ではなく中央値か
//!
//! 平均を使うと**縮退した実行自体が母集団を汚染して閾値がじわじわ上がり、検知が効かなくなる**
//! （自己敗北的フィードバック）。同じ理由で[`Stats::record_clean`]しか母集団へ入れず、
//! 縮退と判定した実行は捨てる。
//!
//! # なぜ母集団のキーが `(model, max_tokens)` か
//!
//! `TurnExecutor`は設計上フェーズを知らないが、認知レイヤーがフェーズ予算`budget.max_out`を
//! そのまま`max_tokens`に入れている（§6.1）ため、**フェーズを知らないまま実質フェーズ別の統計になる**。
//! 責務境界を崩さずに`Distill`（`max_out=800`）と素朴ループのターン（4096）を別母集団にできる。

use std::collections::HashMap;
use std::time::Duration;

/// 母集団のキー。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatKey {
    pub model: String,
    pub max_tokens: u32,
}

/// 平常時の1コールの観測。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// 可視テキスト＋thinkingの合計文字数。
    pub chars: u64,
    pub elapsed: Duration,
}

/// 中央値を取る母集団の窓（直近何件を見るか）。
const WINDOW: usize = 16;

/// サンプルが窓を満たすまでのフォールバック比率。`max_tokens × 4 × これ`を超えた出力量を
/// 「疑い」とする。`max_tokens`は通常ゆるく設定されるため**固定比率は単独では弱い**。保険としてのみ使う。
const COLD_START_CHAR_RATIO: f64 = 0.75;

/// 経過時間の側でゲートを開くのに必要な絶対下限。
///
/// 比率だけで判定すると、**平常の中央値が極端に小さい母集団（mockプロバイダ・キャッシュヒット・
/// ローカルの短い解釈コール）でゲートが常時開きっぱなしになる**——中央値1msに対して3msかかれば
/// 「平常の3倍」だが、これは何の異常でもない。経過時間のORが拾いたいのは推論サーバのハング・
/// デルタ停止・GPU OOM後の無応答という**秒単位の**故障なので、そこに下限を置く。
///
/// 出力量の側に同じ下限を置かないのは、そちらが`max_tokens`という自然なスケールを持つため。
const MIN_SUSPICIOUS_ELAPSED: Duration = Duration::from_secs(1);

/// `(model, max_tokens)`ごとの移動統計。セッション全体を寿命とし、ディスクへは永続化しない。
#[derive(Debug, Default)]
pub struct Stats {
    windows: HashMap<StatKey, Vec<Sample>>,
}

/// ゲートの判定結果。開いた理由を持つのは、発火時のログ1行を組み立てるため。
#[derive(Debug, Clone, PartialEq)]
pub struct GateVerdict {
    pub open: bool,
    /// 開いた理由（`open == false`なら空）。
    pub reason: String,
}

impl GateVerdict {
    fn closed() -> Self {
        Self {
            open: false,
            reason: String::new(),
        }
    }
}

impl Stats {
    /// **縮退しなかった**コールだけを母集団へ入れる。
    pub fn record_clean(&mut self, key: StatKey, sample: Sample) {
        let w = self.windows.entry(key).or_default();
        w.push(sample);
        if w.len() > WINDOW {
            w.remove(0);
        }
    }

    fn window(&self, key: &StatKey) -> Option<&[Sample]> {
        let w = self.windows.get(key)?;
        (w.len() >= WINDOW).then_some(w.as_slice())
    }

    /// 平常時の所要時間の中央値。窓が埋まっていなければ`None`。
    pub fn median_elapsed(&self, key: &StatKey) -> Option<Duration> {
        let w = self.window(key)?;
        let mut v: Vec<Duration> = w.iter().map(|s| s.elapsed).collect();
        v.sort_unstable();
        Some(v[v.len() / 2])
    }

    /// 平常時の出力量の中央値。窓が埋まっていなければ`None`。
    pub fn median_chars(&self, key: &StatKey) -> Option<u64> {
        let w = self.window(key)?;
        let mut v: Vec<u64> = w.iter().map(|s| s.chars).collect();
        v.sort_unstable();
        Some(v[v.len() / 2])
    }

    /// ②④を評価してよいか。
    pub fn gate(
        &self,
        key: &StatKey,
        chars: u64,
        elapsed: Duration,
        multiplier: f32,
    ) -> GateVerdict {
        let m = f64::from(multiplier).max(0.0);
        match (self.median_chars(key), self.median_elapsed(key)) {
            (Some(mc), Some(me)) => {
                let char_limit = (mc as f64 * m) as u64;
                if chars > char_limit {
                    return GateVerdict {
                        open: true,
                        reason: format!(
                            "出力量が平常の{:.1}倍（{chars}文字 / 中央値{mc}文字）",
                            chars as f64 / mc.max(1) as f64
                        ),
                    };
                }
                let time_limit = me.mul_f64(m).max(MIN_SUSPICIOUS_ELAPSED);
                if elapsed > time_limit {
                    return GateVerdict {
                        open: true,
                        reason: format!(
                            "所要時間が平常の{:.1}倍（{:.1}s / 中央値{:.1}s）",
                            elapsed.as_secs_f64() / me.as_secs_f64().max(0.001),
                            elapsed.as_secs_f64(),
                            me.as_secs_f64()
                        ),
                    };
                }
                GateVerdict::closed()
            }
            // コールドスタート: 中央値が無いので固定比率だけを見る。経過時間側は
            // 比較対象が無いため評価しない（絶対値の閾値を新設すると環境依存の定数が増える）。
            _ => GateVerdict::closed(),
        }
    }

    /// コールドスタート用の固定比率フォールバック。`max_tokens`から直接引く。
    ///
    /// [`Stats::gate`]と別関数なのは、こちらが母集団を必要としない（`&self`すら要らない）ためで、
    /// 呼び出し側は「中央値があればgate、無ければこちら」と1箇所で選ぶ。
    pub fn cold_start_gate(chars: u64, max_tokens: u32) -> GateVerdict {
        let limit = (f64::from(max_tokens) * 4.0 * COLD_START_CHAR_RATIO) as u64;
        if chars > limit {
            GateVerdict {
                open: true,
                reason: format!("出力量{chars}文字が出力枠の目安{limit}文字を超えた（統計未蓄積）"),
            }
        } else {
            GateVerdict::closed()
        }
    }

    /// 母集団が判定に使えるだけ溜まっているか。呼び出し側が
    /// [`Stats::gate`]と[`Stats::cold_start_gate`]を選ぶのに使う。
    pub fn is_warm(&self, key: &StatKey) -> bool {
        self.window(key).is_some()
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod gate_tests;
