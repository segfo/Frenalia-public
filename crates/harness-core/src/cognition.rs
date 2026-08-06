//! 認知レイヤーの段階（Effortスイッチ）。`plans/DESIGN-COGNITION.md` §2。
//!
//! 「開いた集合はtrait object、**閉じた語彙はenum**」（`plans/DESIGN.md` §全体アーキテクチャ）に
//! 従い、段階そのものは共有語彙としてここに置く。実際に段階を解釈して実行するのは
//! `harness-cognition`だが、`harness-config`（`cognition.default_level`のデシリアライズ）・
//! `harness-cli`（`--cognition`）・M18の`AgentEvent::CognitionLevelChanged`も同じ型を要するため、
//! それら全てが既に依存している`harness-core`へ置いて依存の逆流を避ける。

use serde::{Deserialize, Serialize};

/// 認知レイヤーをどこまで働かせるか。
///
/// `plans/DESIGN-COGNITION.md` §2.3の最終形では headless の既定は `Auto` だが、
/// `Auto`の難易度ルータはM17で実装するため、**現時点で実行できるのは`Off`と`Always`**。
/// `Always`はHIVループの「ライト」構成（Orient/Critic/PlannerはM19）で走る。
/// 現在の既定と構成の差は`docs/STATUS.md`が持つ。
///
/// `Census`はHIVとは別の状態機械（`CensusEngine`: Plan→Collect→Distill×N→Join、終了条件は
/// 「worklistが空＝網羅」）で、HIVの終了条件（仮説の判定）では表現できない「対象を全件処理して
/// 終わる」仕事のために`plans/PLAN-CENSUS-ENGINE.md`が設計した（段階2）。`Survey`という語は
/// 「`Census`（全数調査）＋HIV（注目箇所の事実調査）」を合成する将来の外側の型のために予約して
/// あり、現時点のバリアントには使わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionLevel {
    /// 素朴ループのみ（`harness_engine::run_agent_loop`と等価・最速・最安）。
    #[default]
    Off,
    /// ゴール毎に難易度を推定し、素朴ループとHIVループを自動で使い分ける（M17）。
    Auto,
    /// 常にHIVフルループ（M15–M19）。
    Always,
    /// 常に`CensusEngine`（網羅型フェーズパイプライン、`plans/PLAN-CENSUS-ENGINE.md`）。
    Census,
}

impl CognitionLevel {
    /// CLI・設定・イベント表示で使う正規名（`serde`の表現と一致させる）。
    pub fn as_str(self) -> &'static str {
        match self {
            CognitionLevel::Off => "off",
            CognitionLevel::Auto => "auto",
            CognitionLevel::Always => "always",
            CognitionLevel::Census => "census",
        }
    }
}

impl std::fmt::Display for CognitionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HIVループのフェーズ（`plans/DESIGN-COGNITION.md` §3.3）。
///
/// 各フェーズ = **独立した1コール**で、入力は台帳スライスのみ。遷移権限は
/// `harness-cognition`の`HivEngine`（M15）だけが持つ。ここに置くのは`CognitionLevel`と
/// 同じ理由で、`harness-config`（`cognition.budgets`のキー）・`harness-cognition`
/// （組立の入力）・M15の`AgentEvent::PhaseChanged`が同じ語彙を要するため。
///
/// `Ord`は`BTreeMap<Phase, TokenBudget>`のキーにするために導出している（設定の
/// デシリアライズ順に依存しない安定した反復順を得る）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// 状況把握。ゴールの言い換えと未知事項の洗い出し。
    Orient,
    /// 仮説を立てる。反証条件（`predicts`）を必ず伴う。
    Hypothesize,
    /// 調査計画を立て、情報源を叩く。
    Investigate,
    /// ツール/MCPの生出力から、対象仮説に照らした事実を蒸留する。
    Distill,
    /// 証拠で仮説が支持されるか判定する。
    Verify,
    /// 独立コンテキストでの自己批判（§7.2）。
    Critic,
    /// 確証済み仮説に基づき行動を決める。
    Decide,
    /// `CensusEngine`専用（`plans/PLAN-CENSUS-ENGINE.md`段階2）。ユーザーの依頼と対象の
    /// 列挙結果からworklistを組む。HIVの`Orient`とは役割が異なる別バリアント
    /// （`Orient`はM19のHIVフル構成で状況把握として使う予定があり、流用するとプロンプト/
    /// スキーマが将来衝突するため）。
    Plan,
    /// `CensusEngine`専用。worklistの1項目についてツールを叩き、生出力を得る。
    Collect,
    /// `CensusEngine`専用。`notes/*.md`の要約だけを連結し、最終回答を組む。
    Join,
}

impl Phase {
    /// 宣言順（`plans/DESIGN-COGNITION.md` §3.3の表と同じ並び。`Plan`/`Collect`/`Join`は
    /// `plans/PLAN-CENSUS-ENGINE.md`段階2で追加）。設定の既定表を組むとき等に、
    /// 網羅を書き忘れないための単一の列挙点。
    pub const ALL: [Phase; 10] = [
        Phase::Orient,
        Phase::Hypothesize,
        Phase::Investigate,
        Phase::Distill,
        Phase::Verify,
        Phase::Critic,
        Phase::Decide,
        Phase::Plan,
        Phase::Collect,
        Phase::Join,
    ];

    /// 設定キー・イベント表示で使う正規名（`serde`の表現と一致させる）。
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Orient => "orient",
            Phase::Hypothesize => "hypothesize",
            Phase::Investigate => "investigate",
            Phase::Distill => "distill",
            Phase::Verify => "verify",
            Phase::Critic => "critic",
            Phase::Decide => "decide",
            Phase::Plan => "plan",
            Phase::Collect => "collect",
            Phase::Join => "join",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 1コールのトークン予算（`plans/DESIGN-COGNITION.md` §6.1）。
///
/// `max_in`は`ContextAssembler`が台帳スライスをどこまで縮約するかの上限、`max_out`は
/// そのまま`CompletionRequest.max_tokens`になる。「1コールの入力を絞ると精度が上がる」を
/// 仕組みで担保するための、フェーズごとの上限そのもの。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBudget {
    pub max_in: u32,
    pub max_out: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `settings.json`の`cognition.default_level`と`--cognition`の値は同じ綴りで書ける
    /// （どちらもこのsnake_case表現）。
    #[test]
    fn serde_representation_matches_as_str() {
        for level in [
            CognitionLevel::Off,
            CognitionLevel::Auto,
            CognitionLevel::Always,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, format!("\"{}\"", level.as_str()));
            let back: CognitionLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn default_is_off() {
        assert_eq!(CognitionLevel::default(), CognitionLevel::Off);
    }

    /// `settings.json`の`cognition.budgets`はフェーズ名をキーに書ける。`as_str`と`serde`の
    /// 表現がずれると、設定に書いた予算が黙って無視される（キーが一致しないだけで
    /// エラーにならない）ため、両者の一致をここで固定する。
    #[test]
    fn phase_serde_representation_matches_as_str() {
        for phase in Phase::ALL {
            let json = serde_json::to_string(&phase).unwrap();
            assert_eq!(json, format!("\"{}\"", phase.as_str()));
            let back: Phase = serde_json::from_str(&json).unwrap();
            assert_eq!(back, phase);
        }
    }

    /// `Phase::ALL`が全ての判別子を含むこと。`as_str`は`match`で全分岐を書くので、
    /// バリアントを足したときに`ALL`だけ更新し忘れてもコンパイルは通ってしまう。
    #[test]
    fn phase_all_covers_every_variant() {
        let mut sorted = Phase::ALL;
        sorted.sort();
        sorted.iter().zip(sorted.iter().skip(1)).for_each(|(a, b)| {
            assert_ne!(a, b, "Phase::ALL must not contain duplicates");
        });
        assert_eq!(Phase::ALL.len(), 10);
    }

    /// フェーズ予算は設定ファイル（`BTreeMap<Phase, TokenBudget>`）から往復できる。
    #[test]
    fn token_budget_round_trips_as_a_phase_keyed_map() {
        let map = std::collections::BTreeMap::from([(
            Phase::Distill,
            TokenBudget {
                max_in: 4_000,
                max_out: 500,
            },
        )]);
        let json = serde_json::to_string(&map).unwrap();
        assert_eq!(json, r#"{"distill":{"max_in":4000,"max_out":500}}"#);
        let back: std::collections::BTreeMap<Phase, TokenBudget> =
            serde_json::from_str(&json).unwrap();
        assert_eq!(back, map);
    }
}
