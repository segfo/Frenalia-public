//! checkpoint書込みの唯一の入口。
//!
//! HIVの`Decide`/`BudgetExhausted`到達時・Censusの`Join`到達時・`recall`ツールの`remember`の
//! **3経路が全てこの1関数を通る**（`bug-pattern-rules` B-06「不変条件を変えたなら全経路を
//! 数えたか」）。git subprocess起動＋待機を含むため`tokio::task::spawn_blocking`で包む
//! （設計変更F、B-31: 非同期ランタイム上で同期ブロッキングを直接呼ばない）。
//!
//! **`RecallStore`の解決（`for_workspace`）は呼び出し側の責務**——ここでは行わない。
//! テストで実`%APPDATA%`を汚さないため（`RecallStore::at_root`で注入したストアを直接
//! 渡せるようにする）と、読出し側で既に解決済みの`RecallStore`を書込みでも再利用できる
//! ようにするため（`orchestrator.rs::run_hiv`）の両方の理由による。

use super::checkpoint::Checkpoint;
use super::store::RecallStore;

/// 書込みの結果。**失敗を無音にしない**（設計変更C）——`id`が`None`でも`skipped`に必ず
/// 理由が入る。commitだけ失敗した場合は`id`が`Some`かつ`skipped`にcommit失敗の理由が入る
/// （fail-open、`bug-pattern-rules` B-10）。
pub struct WriteOutcome {
    pub id: Option<String>,
    pub skipped: Option<String>,
}

/// checkpointを1件書く。
pub async fn write_checkpoint(
    store: RecallStore,
    allow_unversioned: bool,
    cp: Checkpoint,
) -> WriteOutcome {
    let joined = tokio::task::spawn_blocking(move || store.append(&cp, allow_unversioned)).await;

    match joined {
        Ok(Ok(outcome)) => WriteOutcome {
            id: Some(outcome.id),
            skipped: outcome.commit_warning,
        },
        Ok(Err(reason)) => WriteOutcome {
            id: None,
            skipped: Some(reason),
        },
        Err(join_err) => WriteOutcome {
            id: None,
            skipped: Some(format!(
                "internal error while writing a checkpoint: {join_err}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::checkpoint::CheckpointMeta;

    fn cp(id: &str) -> Checkpoint {
        Checkpoint {
            meta: CheckpointMeta {
                id: id.to_string(),
                created_at_ms: 1,
                tags: vec![],
                summary: "s".into(),
                goal_excerpt: "g".into(),
                sources: vec![],
            },
            body: "body".to_string(),
        }
    }

    /// `spawn_blocking`経由でも書けること。**テスト注入の`at_root`だけを使い、実
    /// `%APPDATA%`には一切触れない**——`for_workspace`を呼ぶのは本番コード（orchestrator/
    /// tool.rs）の責務であり、この関数自体はどこにも書くかを知らない。
    #[tokio::test]
    async fn writes_through_spawn_blocking() {
        let data_root = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let store = RecallStore::at_root(data_root.path(), ws.path());
        let outcome = write_checkpoint(store, true, cp("cp-1-aaaaaaaa")).await;
        assert_eq!(outcome.id.as_deref(), Some("cp-1-aaaaaaaa"));
    }
}
