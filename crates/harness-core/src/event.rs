use serde::{Deserialize, Serialize};

use crate::provider::{StopReason, Usage};
use crate::tool::{RiskClass, ToolOutput};

/// engine→frontend の唯一のイベントバス。TUI/ヘッドレスいずれもこれを消費する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    TurnStarted,
    TextDelta {
        text: String,
    },
    ThinkingDelta {
        text: String,
    },
    ToolCallProposed {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    PermissionRequired {
        id: String,
        tool: String,
        risk: RiskClass,
        input: serde_json::Value,
    },
    ToolStarted {
        id: String,
        name: String,
    },
    ToolProgress {
        id: String,
        message: String,
    },
    ToolFinished {
        id: String,
        output: ToolOutput,
    },
    TurnCompleted {
        stop_reason: StopReason,
        usage: Usage,
    },
    Error {
        message: String,
    },
}
