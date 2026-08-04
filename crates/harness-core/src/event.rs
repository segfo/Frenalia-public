use serde::{Deserialize, Serialize};

use crate::cognition::Phase;
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
    /// コンテキスト縮約の①段（`tool_result`の選択的切詰め）が走った
    /// （`plans/PLAN-COMPACTION.md`「縮約の順序」）。
    ///
    /// [`AgentEvent::ContextCompacted`]と**別の変種にしている**のは、あちらが「要約に畳み込まれ
    /// 削除された元メッセージ数」を意味するためで、0メッセージ削除の切詰めを同じ変種で表すと
    /// 嘘になる。モデルが既に見たツール出力を静かに縮めるのは可視化すべき副作用である
    /// （`docs/SECURITY-PRINCIPLES.md` P-04「書込はレビュー可能にする」と同じ発想）。
    ContextShrunk {
        /// 短くした`tool_result`ブロック数。**メッセージ数・ブロック数自体は変わらない**
        /// （`tool_use`との対応を壊さないため）。
        truncated_blocks: usize,
        /// 削減できたトークン概算。
        saved_tokens: u64,
    },
    /// セッションが切り替わった（`/fork`でのFork、`/sessions`ピッカーでの選択、M9拡張）。
    /// `source_id`はForkの場合のみ元セッションIDを持つ（`/sessions`での単純な切替では`None`）。
    SessionSwitched {
        source_id: Option<String>,
        new_id: String,
        message_count: usize,
    },
    /// 認知レイヤーが次のフェーズへ遷移した（`plans/DESIGN-COGNITION.md` §8、M15）。
    /// 遷移権限を持つのは`harness_cognition::hiv::HivEngine`だけで、フロントエンドは
    /// これを表示するだけ（`CognitionLevel::Off`では一度も発行されない）。
    PhaseChanged {
        phase: Phase,
    },
    /// 仮説が台帳へ追加された（M15）。
    ///
    /// 台帳の型（`Hypothesis`/`Evidence`/`Verdict`）は`harness-cognition`にあり、
    /// `harness-core`がそれらに依存すると依存が逆流する。そのため識別子は
    /// `HypId::label()`済みの短い文字列（`"H2"`・`"E3"`）で運ぶ。表示・突き合わせには
    /// これで足り、フロントエンドが台帳の内部表現を知る必要も無くなる。
    HypothesisFormed {
        id: String,
        statement: String,
        /// 反証条件（何が観測されれば偽か）。空の仮説は状態機械が弾くので、ここは常に非空。
        predicts: Vec<String>,
    },
    /// 蒸留された事実が台帳へ追加された（M15）。`source`は`SourceRef::describe()`の1行表現。
    EvidenceAdded {
        id: String,
        claim: String,
        source: String,
    },
    /// 仮説の検証結果が出た（M15）。`verdict`は`"confirms"`/`"refutes"`/`"inconclusive"`、
    /// `promoted`は§3.4の接地チェックまで通って`Confirmed`へ昇格したか。
    VerificationResult {
        hyp: String,
        verdict: String,
        missing: Vec<String>,
        promoted: bool,
    },
    Error {
        message: String,
    },
}
