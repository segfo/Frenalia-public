//! コンテキスト縮約。`plans/DESIGN.md` §エージェントループ「コンテキスト管理」が機構の正本、
//! `plans/PLAN-COMPACTION.md` が実装計画（判定式・縮約順序・ヒステリシス）の正本。
//!
//! # 縮約は「安い順の2段」
//!
//! ```text
//! (A) 使用率トリガ or (B) 超過直前トリガ 成立? ──no──▶ そのまま送信
//!       │yes
//!       ▼
//! ① shrink::shrink_largest_tool_results  … 純粋関数・LLMコール0・会話の流れは逐語保持
//!       │ target 到達?
//!       ▼no
//! ② summarize::compact（ローリング要約）  … LLMコール要・不可逆・prompt cache全ミス
//!       │ target 到達?（②は1回の run_agent_loop で高々1回）
//!       ▼no
//! ③ digest::digest_tool_results          … LLMコール要。①②が構造的に届かない
//!       │                                   **いまのターンの中**を畳む唯一の段
//!       ▼
//! 送信（target に届かなくてもエラーにしない＝リアクティブ経路が受け止める）
//! ```
//!
//! ③が要る理由: ①の保護境界は「いまの外部ユーザターンの先頭」、②のカット位置は必ずターン境界
//! なので、**1ターンの中で`read_file`を20回繰り返して積み上がったぶんにはどちらも触れない**。
//! ③を入れる前の唯一の逃げ場は、リクエストが弾かれた後に走るリアクティブ・フォールバック
//! （保護なし・下限512字の機械的切詰め）だった。
//!
//! ① を先に置く理由は3つある。嵩張っているのがほぼ常に`tool_result`であること。①は
//! **`tool_use`/`tool_result`のブロック対応を壊さない**（ブロックを消さず中身を短くするだけ）ため
//! 400のリスクが構造的に無いこと。そしてprompt cacheのプレフィックスを壊さないこと。②は履歴の
//! 先頭を書き換えるのでキャッシュを全ミスさせる。
//!
//! # モジュール分割の軸
//!
//! `docs/CODE-STRUCTURE-RULES.md` 規則1（1,000行）ではなく**規則3の軸1「どの外部システムと
//! 話すか」**で割ってある。[`budget`]・[`shrink`]は純粋関数でproviderを知らず、モック無しで
//! 単体テストできる。providerに触るのは[`summarize`]と、それを手動経路の順序で束ねる[`manual`]。
//!
//! # 手動`/compact`は順序が逆（②→①）
//!
//! 上の図は自動経路（予防・リアクティブ）のもの。手動`/compact`は②を必ず打つので①を先に試す
//! 意味が無く、逆順にする理由が3つある（[`manual`]のモジュールdocが正本）。

pub mod budget;
pub mod digest;
pub mod manual;
pub mod shrink;
pub mod summarize;
#[cfg(test)]
pub(crate) mod test_support;

use harness_core::{ContentBlock, Message, Role};

pub use budget::{assess, CompactionOverrides, CompactionPolicy, ContextPressure, PolicyError};
pub use digest::{digest_tool_results, DigestOutcome};
pub use manual::{compact_now, ManualOutcome};
pub use shrink::{shrink_largest_tool_results, ShrinkOutcome};
pub use summarize::{compact, Compacted};

/// 逐語保持する直近の外部ユーザターン数。自動経路（②ローリング要約）と手動`/compact`で
/// **同じ値を使う**。
///
/// 同じ値でも残るものは違う。自動経路は送信済みプロンプトが履歴に居る状態で走るので1枠を
/// それが占め、`[要約][直前の1往復][現在のプロンプト…]`になる。手動`/compact`の時点では
/// プロンプトがまだ無いので`[要約][直近2往復]`が残り、次の発話がその後ろに付く。
/// **したがって「両経路で同じ見た目にする」ためにこの値を経路ごとに変えるのは誤り**——
/// 片方を1にすると、そちらから直前のやり取りが消える。
pub const DEFAULT_KEEP_RECENT_TURNS: usize = 2;

/// `messages`中で「外部ユーザプロンプトの開始点」であるインデックス列を返す。
///
/// ツール結果を運ぶ`Role::User`メッセージは`ContentBlock::ToolResult`を含み、
/// `push_user_text`が積む純粋なテキスト1ブロックのメッセージとは形が異なるため区別できる
/// （`ConversationState`にターン境界メタデータを別途持たせる必要がない）。
///
/// [`shrink`]（保護範囲の決定）と[`summarize`]（カット位置・チャンク分割）の両方が使う。
/// **カット・チャンク分割は必ずこの境界で行う**——ターン内部で切ると`tool_use`と`tool_result`の
/// 対応が壊れて次のリクエストが400になる（`plans/DESIGN.md` §プロバイダ抽象）。
pub fn turn_boundaries(messages: &[Message]) -> Vec<usize> {
    messages
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let is_external_prompt = m.role == Role::User
                && m.content.len() == 1
                && matches!(m.content[0], ContentBlock::Text(_));
            is_external_prompt.then_some(i)
        })
        .collect()
}

/// 直近`keep_recent_turns`件の外部ユーザターンの開始index。保護境界として使う。
///
/// 境界がそれ以下しか無ければ`None`（＝保護対象が履歴全体なので触れるものが無い）。
pub(crate) fn protect_boundary(messages: &[Message], keep_recent_turns: usize) -> Option<usize> {
    let boundaries = turn_boundaries(messages);
    if boundaries.len() <= keep_recent_turns {
        return None;
    }
    Some(boundaries[boundaries.len() - keep_recent_turns])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_turn(text: &str) -> Message {
        Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.to_string())],
        }
    }

    #[test]
    fn turn_boundaries_ignores_tool_result_user_messages() {
        let messages = vec![
            user_turn("hi"),
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "1".into(),
                    name: "read_file".into(),
                    input: serde_json::json!({}),
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "1".into(),
                    content: "ok".into(),
                    is_error: false,
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text("done".into())],
            },
            user_turn("next"),
        ];
        assert_eq!(turn_boundaries(&messages), vec![0, 4]);
    }

    #[test]
    fn protect_boundary_is_none_when_everything_is_recent() {
        let messages = vec![user_turn("only turn")];
        assert_eq!(protect_boundary(&messages, 2), None);
    }

    #[test]
    fn protect_boundary_points_at_the_nth_most_recent_turn() {
        let messages = vec![
            user_turn("t1"),
            user_turn("t2"),
            user_turn("t3"),
            user_turn("t4"),
        ];
        assert_eq!(protect_boundary(&messages, 1), Some(3));
        assert_eq!(protect_boundary(&messages, 2), Some(2));
    }
}
