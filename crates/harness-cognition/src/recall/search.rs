//! 決定的なbigram検索（純粋関数、LLMコールを使わない）。`plans/PLAN-RECALL-MEMORY.md`
//! 「読出し経路」1番。

use std::collections::HashSet;

use super::checkpoint::CheckpointMeta;

/// [`top_k`]の結果。**「indexが0件」と「N件あるが閾値未満」を区別して報告する**
/// （`bug-pattern-rules` B-12、無音のno-opを避ける）。
pub struct SearchResult {
    /// 検索対象になった全checkpoint数（bigramヒットの有無に関わらず）。
    pub index_size: usize,
    /// 閾値以上の上位K件。
    pub picks: Vec<CheckpointMeta>,
}

const WEIGHT_BIGRAM: f32 = 0.7;
const WEIGHT_TAG: f32 = 0.3;

/// 上位K件（既定5）を機械的に抽出する。**該当0件ならLLMコールを一切行わない**——これは
/// この関数の戻り値が空になることで自然に保証される（呼び出し側は`picks`が空なら
/// `judge::judge`を呼ばない）。
pub fn top_k(query: &str, index: &[CheckpointMeta], k: usize, threshold: f32) -> SearchResult {
    let mut scored: Vec<(f32, &CheckpointMeta)> = index
        .iter()
        .map(|m| (score(query, m), m))
        .filter(|(s, _)| *s >= threshold)
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    SearchResult {
        index_size: index.len(),
        picks: scored.into_iter().take(k).map(|(_, m)| m.clone()).collect(),
    }
}

fn score(query: &str, meta: &CheckpointMeta) -> f32 {
    let text = format!("{} {}", meta.summary, meta.goal_excerpt);
    WEIGHT_BIGRAM * jaccard_bigram(query, &text) + WEIGHT_TAG * tag_match_ratio(query, &meta.tags)
}

fn bigrams(s: &str) -> HashSet<(char, char)> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 2 {
        return HashSet::new();
    }
    chars.windows(2).map(|w| (w[0], w[1])).collect()
}

/// 文字bigramのJaccard係数。単語境界に依存しないので分かち書きの無い日本語ゴール文でも
/// 成立する。
fn jaccard_bigram(a: &str, b: &str) -> f32 {
    let ba = bigrams(a);
    let bb = bigrams(b);
    if ba.is_empty() || bb.is_empty() {
        return 0.0;
    }
    let intersection = ba.intersection(&bb).count();
    let union = ba.union(&bb).count();
    if union == 0 {
        0.0
    } else {
        intersection as f32 / union as f32
    }
}

fn tag_match_ratio(query: &str, tags: &[String]) -> f32 {
    if tags.is_empty() {
        return 0.0;
    }
    let matched = tags.iter().filter(|t| query.contains(t.as_str())).count();
    matched as f32 / tags.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, summary: &str, goal_excerpt: &str) -> CheckpointMeta {
        CheckpointMeta {
            id: id.to_string(),
            created_at_ms: 0,
            tags: vec![],
            summary: summary.to_string(),
            goal_excerpt: goal_excerpt.to_string(),
            sources: vec![],
        }
    }

    /// 分かち書きの無い日本語ゴール文でもbigram一致がヒットする。
    #[test]
    fn japanese_goal_text_matches_via_bigrams() {
        let index = vec![meta(
            "cp-1",
            "認証まわりのバグを修正した",
            "ログインが失敗する原因を調べる",
        )];
        let result = top_k("ログイン失敗の原因を特定する", &index, 5, 0.05);
        assert!(!result.picks.is_empty(), "expected a bigram hit");
        assert_eq!(result.index_size, 1);
    }

    /// 該当0件ならpicksが空になり（＝呼び出し側がLLMコールを打たない条件が成立する）、
    /// かつindex自体は0件ではないことを区別して報告できる。
    #[test]
    fn unrelated_query_yields_no_picks_but_reports_the_index_size() {
        let index = vec![meta("cp-1", "全く無関係なメモ", "別の話題")];
        let result = top_k("ZZZZZZZZ_QQQQQQQQ", &index, 5, 0.5);
        assert!(result.picks.is_empty());
        assert_eq!(result.index_size, 1, "index has entries even though nothing matched");
    }

    #[test]
    fn an_empty_index_is_distinguishable_from_a_below_threshold_miss() {
        let result = top_k("何か", &[], 5, 0.05);
        assert_eq!(result.index_size, 0);
        assert!(result.picks.is_empty());
    }

    #[test]
    fn top_k_limits_the_result_count() {
        let index: Vec<CheckpointMeta> = (0..10)
            .map(|i| meta(&format!("cp-{i}"), "同じテーマの調査結果", "調査の対象は同じ"))
            .collect();
        let result = top_k("同じテーマの調査結果", &index, 3, 0.0);
        assert_eq!(result.picks.len(), 3);
    }
}
