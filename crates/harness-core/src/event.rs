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
        /// 妥当性の1行表現（`"single_source/trust:high"`、M16）。`Validity::describe()`の結果を
        /// 文字列で運ぶ——台帳の型は`harness-cognition`にあり、ここが依存すると逆流するため
        /// （`HypothesisFormed.id`と同じ理由）。
        validity: String,
    },
    /// 仮説の検証結果が出た（M15）。`verdict`は`"confirms"`/`"refutes"`/`"inconclusive"`、
    /// `promoted`は§3.4の接地チェックまで通って`Confirmed`へ昇格したか。
    VerificationResult {
        hyp: String,
        verdict: String,
        missing: Vec<String>,
        promoted: bool,
        /// 根拠の強さ（`"strong"`/`"moderate"`/`"weak"`/`"ungrounded"`、M16）。
        /// ハーネスが台帳から決定的に算出したもので、モデルの自己申告ではない（§3.4）。
        strength: String,
    },
    /// 縮退したターンを破棄した（`plans/DESIGN-COGNITION.md` §11.4、M21）。
    ///
    /// **このイベントが出たターンはツールを一度も実行していない**——検知はストリーム受信中
    /// （①②④）またはストリーム完了直後（③、`ToolUse`ゼロが発火条件）に起きるため、
    /// ツール実行へ到達しない。したがって捨てたコールは副作用を持たない。
    ///
    /// `next_rung`が`Some`なら回復の梯子（§11.3）を1段登って再送する。`None`なら梯子を
    /// 使い切っており、このターンは`RawTurnResult::Discarded`として呼び出し側へ返る。
    TurnDiscarded {
        kind: DegenerateKind,
        /// 発火理由の1行説明（「疑い状態（出力量が平常の3.4倍）→ 新規性率0.94」）。
        /// §11.2「発火理由が常にログ1行で説明できる」をここで満たす。
        reason: String,
        /// このコールで下流へ実際に流した可視テキストのUTF-8バイト数。
        /// `--output-format text`の下流は自バッファを末尾からこの数だけ切り詰めればよい
        /// （[`discarded_marker`]と同じ値）。
        discarded_bytes: u64,
        /// 次に登る段のラベル。使い切ったら`None`。
        next_rung: Option<String>,
    },
    Error {
        message: String,
    },
}

/// 縮退の種別（`plans/DESIGN-COGNITION.md` §11.1 の検知器4種と1対1）。
///
/// 機構の本体は`harness-engine::degeneracy`にあるが、この enum だけは
/// [`AgentEvent::TurnDiscarded`]が`Serialize`で運ぶため`harness-core`側に置く。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegenerateKind {
    /// ① 短周期反復。直近512文字の最小周期が32以下（`？？？？…`・`・・・・…`）。
    ShortPeriodRepeat,
    /// ② 新規性率の枯渇。直近1024文字の90%超が既出の32-gramに含まれる。
    /// **「長い」ではなく「新しいことを言わなくなった」を測る**ので、正当な長文は通る。
    NoveltyCollapse,
    /// ③ 完走時の無産出。`MaxTokens`で終わったのに`Text`0文字かつ`ToolUse`ゼロ。
    NoOutputAtMaxTokens,
    /// ④ reasoning-only 上限。thinkingだけが出力枠を食い潰し、本文もツールも出ない。
    /// ③を完走前に捕まえる早期版。
    ReasoningOnly,
}

impl DegenerateKind {
    /// [`discarded_marker`]と構造化ログで使う安定した短い名前。
    pub fn as_str(self) -> &'static str {
        match self {
            DegenerateKind::ShortPeriodRepeat => "short_period_repeat",
            DegenerateKind::NoveltyCollapse => "novelty_collapse",
            DegenerateKind::NoOutputAtMaxTokens => "no_output_at_max_tokens",
            DegenerateKind::ReasoningOnly => "reasoning_only",
        }
    }
}

impl std::fmt::Display for DegenerateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `--output-format text`で「直前の出力のどこからが捨てる範囲か」を下流へ伝えるマーカー
/// （`plans/DESIGN-COGNITION.md` §11.4）。
///
/// text形式では`events`が`None`のため[`AgentEvent::TurnDiscarded`]は届かない。かわりに
/// `TurnExecutor`がテキストデルタの経路へこの1行を流す。**書式の宣言点はこの関数1つだけ**にして、
/// 契約が二重化しないようにする。
///
/// `bytes`を載せるのは、終端マーカーだけでは下流が捨てる範囲を復元できないため。
/// 「自分のバッファを末尾から`bytes`バイト切り詰めよ」と自己完結で伝える。梯子を2回登れば
/// 2つのマーカーが順に出るので、下流は順に適用すればよい。
///
/// `\x1e`はASCII RS（record separator）で端末では不可視。**このマーカーは異常時にしか出ないので、
/// 正常時の出力は1バイトも変わらない**（`plans/DESIGN.md` §ヘッドレスで確立した
/// `--output-format text`の契約を壊さない）。
///
/// `reason`は[`DegenerateKind::as_str`]、またはEscキャンセルの[`CANCELLED_REASON`]。
pub fn discarded_marker(reason: &str, bytes: u64) -> String {
    format!("\x1e[harness:discarded bytes={bytes} reason={reason}]\n")
}

/// [`discarded_marker`]の`reason`のうち、縮退ではなくEscキャンセルによる破棄を表すもの。
///
/// キャンセルも意味論は同じ「直前の部分assistantは捨てられた」だが、text形式には
/// これまでなんのマーカーも出ていなかった（§11.4「既存の同型の穴も同時に塞ぐ」）。
pub const CANCELLED_REASON: &str = "cancelled";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_self_describing_and_terminated() {
        let m = discarded_marker(DegenerateKind::ShortPeriodRepeat.as_str(), 1_234);
        assert_eq!(m, "\x1e[harness:discarded bytes=1234 reason=short_period_repeat]\n");
        assert!(m.starts_with('\x1e'), "端末で不可視なRSで始まる");
        assert!(m.ends_with('\n'), "行として完結する");
    }

    /// バイト数が0でも桁が増えても書式が壊れない（下流のパーサが固定長を仮定できない）。
    #[test]
    fn the_marker_survives_any_byte_count() {
        for bytes in [0u64, 9, 10, u64::MAX] {
            let m = discarded_marker(CANCELLED_REASON, bytes);
            assert!(m.contains(&format!("bytes={bytes} ")), "{m}");
            assert!(m.contains("reason=cancelled]"), "{m}");
        }
    }

    /// 種別名は構造化ログとマーカーの両方に出る安定した識別子なので、重複しないこと。
    #[test]
    fn every_kind_has_a_distinct_stable_name() {
        let names = [
            DegenerateKind::ShortPeriodRepeat,
            DegenerateKind::NoveltyCollapse,
            DegenerateKind::NoOutputAtMaxTokens,
            DegenerateKind::ReasoningOnly,
        ]
        .map(DegenerateKind::as_str);
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
        assert!(!unique.contains(&CANCELLED_REASON));
    }
}
