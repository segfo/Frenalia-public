//! `Phase::Plan`の出力から worklist を組む。`plans/PLAN-CENSUS-ENGINE.md`段階2。

use crate::schema::PlanOutput;

/// worklistの1項目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorklistItem {
    /// `notes/<id>.md`のファイル名にもなる（`ScratchStore`の`validate_id`を通る形に
    /// [`sanitize_id`]で正規化済み）。
    pub id: String,
    pub query: String,
}

/// `items`が空でないこと・各`id`が空でないことを要求する。空のworklistは
/// 「網羅すべき対象が無かった」ではなく「モデルが列挙結果を無視した」可能性が高いので、
/// 修復指示を添えて再実行させる（§3.4のリジェクト再実行と同じ姿勢）。
pub(crate) fn validate_plan(out: &PlanOutput) -> Result<(), String> {
    if out.items.is_empty() {
        return Err(
            "itemsが空だった。列挙結果（ツール出力）から少なくとも1件のworklist項目を出すこと。"
                .to_string(),
        );
    }
    for (i, item) in out.items.iter().enumerate() {
        if item.id.trim().is_empty() {
            return Err(format!("items[{i}].idが空だった。"));
        }
    }
    Ok(())
}

/// `PlanOutput`をworklistへ変換する。`id`はモデル生成の任意文字列なので、
/// `ScratchStore`のファイル名検証（英数字・`_`・`-`のみ）を通らないものは
/// `item_<index>`へ正規化する——`notes/<id>.md`の書き込みが検証エラーで
/// 静かに失敗し続ける事態を構築時に防ぐ。
pub(crate) fn build_worklist(out: PlanOutput) -> Vec<WorklistItem> {
    out.items
        .into_iter()
        .enumerate()
        .map(|(i, item)| WorklistItem {
            id: sanitize_id(&item.id, i),
            query: item.query,
        })
        .collect()
}

fn sanitize_id(raw: &str, fallback_index: usize) -> String {
    let is_safe = !raw.is_empty()
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if is_safe {
        raw.to_string()
    } else {
        format!("item_{fallback_index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::PlannedItem;

    #[test]
    fn empty_items_are_rejected() {
        let err = validate_plan(&PlanOutput { items: vec![] }).unwrap_err();
        assert!(err.contains("items"), "{err}");
    }

    #[test]
    fn an_empty_id_is_rejected() {
        let err = validate_plan(&PlanOutput {
            items: vec![PlannedItem {
                id: "  ".to_string(),
                query: "q".to_string(),
            }],
        })
        .unwrap_err();
        assert!(err.contains("id"), "{err}");
    }

    #[test]
    fn safe_ids_pass_through_unchanged() {
        let items = build_worklist(PlanOutput {
            items: vec![PlannedItem {
                id: "BUG-077".to_string(),
                query: "q".to_string(),
            }],
        });
        assert_eq!(items[0].id, "BUG-077");
    }

    /// パストラバーサルや区切り文字を含むIDは、`notes/<id>.md`の書き込みが
    /// `ScratchStore::validate_id`で失敗し続けないよう、構築時に安全な形へ倒す。
    #[test]
    fn unsafe_ids_fall_back_to_the_index() {
        let items = build_worklist(PlanOutput {
            items: vec![
                PlannedItem {
                    id: "../escape".to_string(),
                    query: "q0".to_string(),
                },
                PlannedItem {
                    id: "a/b".to_string(),
                    query: "q1".to_string(),
                },
            ],
        });
        assert_eq!(items[0].id, "item_0");
        assert_eq!(items[1].id, "item_1");
    }
}
