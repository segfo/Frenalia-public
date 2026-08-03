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
/// `Auto`の難易度ルータはM17、`Always`のHIVフルループはM15–M19で実装するため、
/// **現時点で実行できるのは`Off`だけ**。現在の既定は`docs/STATUS.md`が持つ。
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
}

impl CognitionLevel {
    /// CLI・設定・イベント表示で使う正規名（`serde`の表現と一致させる）。
    pub fn as_str(self) -> &'static str {
        match self {
            CognitionLevel::Off => "off",
            CognitionLevel::Auto => "auto",
            CognitionLevel::Always => "always",
        }
    }
}

impl std::fmt::Display for CognitionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
}
