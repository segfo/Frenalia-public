//! 会話に残ったツールの結果1件が**どういう顛末だったか**を見分ける（実行した／断られた／取り消した…）。
//!
//! # 何のためにあるのか
//!
//! 顛末そのもの（[`super::ToolCallDecision`]）は1ステップの中にしか無い。会話の記録（`ContentBlock::ToolResult`）に
//! 残るのは**結果の文と`is_error`だけ**なので、後から読む側——ヘッドレスの JSON（`harness-cli`の`decision`欄）と、
//! 前の文の返事を読む道具（[`crate::past_requests`]）——は**結果の文の頭**で見分けるしかない。
//!
//! だから、その頭の綴りを**ここにだけ**置く。結果の文を書く側（[`super`]のディスパッチ）も同じ定数で書くので、
//! 文言を変えても見分けがずれない（別々に持つと片方だけ変わる、B-05）。
//!
//! # ここが守らないもの
//!
//! - **見分けは文の頭だけで行う。** ツール自身がエラーとして同じ頭の文を返すと、その種類として読まれる
//!   （`is_error`が`false`の結果は常に「実行した」と読むので、成功した出力が拒否に見えることは無い）
//! - **「知らないツール」「引数が JSON として読めない」には専用の種類が無い。** どちらも
//!   [`RecordedOutcome::RanWithError`]に入る（文の頭を見れば分かる）。ヘッドレスの JSON がこれまで
//!   `"allowed"`と報告してきた分類を変えないため

use harness_core::user_reference::TRANSCRIPTION_REFUSAL_PREFIX;

/// 判定器（`PermissionGate`）が拒否した呼び出しへ返す文の頭。
pub const DENIAL_PREFIX: &str = "permission denied by policy";

/// 判定の材料が作れなかった（ツールの入力として読めなかった）呼び出しへ返す文の頭。
/// **判定にも実行にも進んでいない**（D-101）。
pub const INVALID_TOOL_INPUT_PREFIX: &str = "invalid tool input";

/// 先行するツールの実行中にキャンセルされ、**手を付けなかった**呼び出しへ返す文（全文）。
pub const CANCELLED_BEFORE_START: &str = "cancelled by user";

/// 会話に残ったツールの結果1件の顛末。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedOutcome {
    /// 実行して、エラーでない結果が返った。
    Ran,
    /// エラーの結果が返った（実行してエラーになった。知らないツール・読めない引数もここ。[モジュールdoc](self)）。
    RanWithError,
    /// 判定器が拒否した（実行していない）。
    Denied,
    /// 先行する呼び出しの途中でキャンセルされ、手を付けなかった。
    Cancelled,
    /// ツールの入力として読めず、判定にも実行にも進まなかった。
    InvalidInput,
    /// 値を損じて書き写していたので実行しなかった（D-115）。
    RefusedTranscription,
}

impl RecordedOutcome {
    /// 結果の文と`is_error`から見分ける。
    pub fn of(content: &str, is_error: bool) -> Self {
        if !is_error {
            Self::Ran
        } else if content.starts_with(DENIAL_PREFIX) {
            Self::Denied
        } else if content.starts_with(INVALID_TOOL_INPUT_PREFIX) {
            Self::InvalidInput
        } else if content == CANCELLED_BEFORE_START {
            Self::Cancelled
        } else if content.starts_with(TRANSCRIPTION_REFUSAL_PREFIX) {
            Self::RefusedTranscription
        } else {
            Self::RanWithError
        }
    }

    /// モデルへ見せる短い言い方（[`crate::past_requests`]）。
    pub fn label_ja(self) -> &'static str {
        match self {
            Self::Ran => "実行した",
            Self::RanWithError => "エラーが返った",
            Self::Denied => "許可の判定で拒否された",
            Self::Cancelled => "取り消したので実行していない",
            Self::InvalidInput => "入力として読めず実行していない",
            Self::RefusedTranscription => "値の書き写しが損じていたので実行していない",
        }
    }
}

#[cfg(test)]
#[path = "outcome_tests.rs"]
mod tests;
