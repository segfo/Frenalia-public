use serde::{Deserialize, Serialize};

use crate::provider::{StopReason, Usage};
use crate::tool::{RiskClass, ToolOutput};

/// engine→frontend の唯一のイベントバス。TUI/ヘッドレスいずれもこれを消費する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    /// `estimated_input_tokens`は、このターンで送信するリクエスト全体（system+messages+tools）を
    /// JSONシリアライズした文字数からの粗い近似（chars/4）。プロバイダの正確なinputトークン数は
    /// `TurnCompleted.usage.input`としてターン完了時にしか届かないため、フロントエンドが
    /// 「送信直後にひとまず概算を出し、完了時に確定値へ置き換える」というライブ表示を
    /// 組み立てられるようにするための値（TUIのステータスバー参照）。
    TurnStarted {
        estimated_input_tokens: u64,
    },
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
    /// ターンがキャンセルされた（Esc、§非対話モード外・M9キャンセル整合）。ストリーム途中なら
    /// 部分assistantは破棄済み、ツール実行中なら残り全ての`tool_use`にcancelledな`tool_result`が
    /// 合成済みで、いずれの場合も`state`は次の`run_agent_loop`呼び出しが400にならない形に保たれる。
    Cancelled,
    /// コンテキスト圧縮が実行された（`/compact`手動起動、または`ProviderError::ContextTooLong`の
    /// リアクティブ経路、M9）。`removed_messages`は要約に畳み込まれ削除された元メッセージ数。
    ContextCompacted {
        removed_messages: usize,
    },
    /// セッションが切り替わった（`/fork`でのFork、`/sessions`ピッカーでの選択、M9拡張）。
    /// `source_id`はForkの場合のみ元セッションIDを持つ（`/sessions`での単純な切替では`None`）。
    SessionSwitched {
        source_id: Option<String>,
        new_id: String,
        message_count: usize,
    },
    Error {
        message: String,
    },
}
