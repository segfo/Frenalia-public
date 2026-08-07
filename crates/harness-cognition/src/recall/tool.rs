//! 対話ループから呼べる`recall`ツール。`plans/PLAN-RECALL-MEMORY.md`「配線ポイント」。
//!
//! `census`ツール（[`crate::census::tool::CensusTool`]）と同じ配線パターン。ただし`recall`は
//! 内部で`TurnExecutor`を新しく組まない（`search`は決定的検索のみで判定コールを打たず、
//! `remember`はファイル書込みのみ）ため、`census`が抱える「再帰的自己呼び出しの防止」
//! （自身を除いたレジストリのスナップショット）は不要。
//!
//! `search`は`RiskClass::ReadOnly`、`remember`は`RiskClass::Write`——同じツール名の中で
//! `action`フィールドに応じて`risk()`が動的に変わる（`Tool::risk`が`input`を受け取れる設計を
//! そのまま使う）。

use async_trait::async_trait;
use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};

use super::checkpoint;
use super::search;
use super::store::RecallStore;
use super::write::write_checkpoint;

pub struct RecallTool {
    /// `cognition.recall.allow_unversioned`（設定、ユーザー層限定）。
    allow_unversioned: bool,
}

impl RecallTool {
    pub fn new(allow_unversioned: bool) -> Self {
        Self { allow_unversioned }
    }
}

#[async_trait]
impl Tool for RecallTool {
    fn name(&self) -> &str {
        "recall"
    }

    fn description(&self) -> &str {
        "過去のゴールで得た知見を検索する（search）、または現在分かったことを明示的に\
         記憶させる（remember）。記憶はこのワークスペース内のセッションを横断して永続する。"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "remember"],
                    "description": "search: 過去の記憶を検索する。remember: 本文を記憶させる。"
                },
                "query": {
                    "type": "string",
                    "description": "search用。検索したい内容（自然文でよい）"
                },
                "text": {
                    "type": "string",
                    "description": "remember用。記憶させる本文"
                },
                "tags": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "remember用。検索用タグ（省略可、3〜6語目安）"
                }
            },
            "required": ["action"],
            "additionalProperties": false,
        })
    }

    fn risk(&self, input: &serde_json::Value) -> RiskClass {
        match input.get("action").and_then(|v| v.as_str()) {
            Some("remember") => RiskClass::Write,
            // 未知のactionも安全側（ReadOnly扱いにはしない）——`call()`側で拒否するので、
            // 許可判定はここでは変えない。既知の`search`だけをReadOnlyとする。
            _ => RiskClass::ReadOnly,
        }
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let action = input
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("action is required".to_string()))?;

        match action {
            "search" => self.call_search(input, ctx).await,
            "remember" => self.call_remember(input, ctx).await,
            other => Err(ToolError::InvalidInput(format!("unknown action: {other}"))),
        }
    }
}

impl RecallTool {
    async fn call_search(
        &self,
        input: serde_json::Value,
        ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("query is required for search".to_string()))?;

        let store = match RecallStore::for_workspace(&ctx.workspace_root) {
            Ok(s) => s,
            Err(reason) => {
                return Ok(ToolOutput {
                    is_error: false,
                    content: format!("記憶を検索できなかった（{reason}）。"),
                })
            }
        };
        let index = store.list().map_err(|e| {
            ToolError::ExecutionFailed(format!("failed to list recall index: {e}"))
        })?;
        let result = search::top_k(query, &index, 5, 0.05);

        if result.picks.is_empty() {
            let msg = if result.index_size == 0 {
                "このワークスペースにはまだ記憶が無い。".to_string()
            } else {
                format!(
                    "{}件の記憶を検索したが、関連しそうなものは見つからなかった。",
                    result.index_size
                )
            };
            return Ok(ToolOutput {
                is_error: false,
                content: msg,
            });
        }

        let watermark = store.reviewed_watermark();
        let mut out = String::new();
        for m in &result.picks {
            let reviewed_mark = if store.is_reviewed(m, &watermark) {
                ""
            } else {
                "（未レビュー）"
            };
            out.push_str(&format!("- {}{reviewed_mark}: {}\n", m.id, m.summary));
        }
        Ok(ToolOutput {
            is_error: false,
            content: out,
        })
    }

    async fn call_remember(
        &self,
        input: serde_json::Value,
        ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let text = input
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("text is required for remember".to_string()))?;
        let tags: Vec<String> = input
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let store = match RecallStore::for_workspace(&ctx.workspace_root) {
            Ok(s) => s,
            Err(reason) => {
                return Ok(ToolOutput {
                    is_error: true,
                    content: format!("記憶できなかった: {reason}"),
                })
            }
        };
        let cp = checkpoint::from_manual(text, tags);
        let outcome = write_checkpoint(store, self.allow_unversioned, cp).await;

        match (outcome.id, outcome.skipped) {
            (Some(id), None) => Ok(ToolOutput {
                is_error: false,
                content: format!("記憶した（{id}）。"),
            }),
            (Some(id), Some(warning)) => Ok(ToolOutput {
                is_error: false,
                content: format!("記憶した（{id}）が、履歴化には失敗した: {warning}"),
            }),
            (None, reason) => Ok(ToolOutput {
                is_error: true,
                content: format!(
                    "記憶できなかった: {}",
                    reason.unwrap_or_else(|| "unknown reason".to_string())
                ),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_action_is_a_write_risk() {
        let tool = RecallTool::new(true);
        let risk = tool.risk(&serde_json::json!({ "action": "remember", "text": "x" }));
        assert_eq!(risk, RiskClass::Write);
    }

    #[test]
    fn search_action_is_read_only() {
        let tool = RecallTool::new(true);
        let risk = tool.risk(&serde_json::json!({ "action": "search", "query": "x" }));
        assert_eq!(risk, RiskClass::ReadOnly);
    }

    /// `remember`の入力からパスを一切受け取れないこと（fsジェイル外への唯一の書込ツールに
    /// なるため、書込先はハーネスが採番したIDに固定する。`bug-pattern-rules`
    /// 「新しい書込経路のチェックリスト」P-03相当）。
    #[test]
    fn the_input_schema_has_no_path_like_property() {
        let tool = RecallTool::new(true);
        let schema = tool.input_schema();
        let props = schema["properties"].as_object().unwrap();
        for key in props.keys() {
            assert!(
                !key.to_ascii_lowercase().contains("path"),
                "recall tool input schema must not accept a path: {key}"
            );
        }
    }

    #[tokio::test]
    async fn remember_without_text_is_rejected() {
        let tool = RecallTool::new(true);
        let dir = tempfile::tempdir().unwrap();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let err = tool
            .call(serde_json::json!({ "action": "remember" }), &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }
}
