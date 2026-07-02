use serde::{Deserialize, Serialize};

/// 会話履歴上のメッセージの発話者。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Assistant,
}

/// プロバイダ非依存の会話IRメッセージ。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

/// assistant応答を受信順のブロック列として忠実に再構成するための語彙。
/// 各アダプタの `stream()` はこの型へ正規化する（`plans/DESIGN.md` §プロバイダ抽象）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text(String),
    /// 署名を保持し tool_result 返送時に無改変で返す（Anthropic extended thinking）。
    Thinking {
        text: String,
        signature: Option<String>,
    },
    /// 不透明データ。無改変で往復必須。
    RedactedThinking {
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
    Image {
        media_type: String,
        data: String,
    },
}
