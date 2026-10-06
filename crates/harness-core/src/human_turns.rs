//! 会話の中で**人が書いた文**を見分ける（D-127）。
//!
//! # 何のためにあるのか
//!
//! 会話（`Vec<Message>`）の`Role::User`には、人が書いた文のほかに、ハーネスが積んだ文が混じる。
//!
//! | 文 | 形 | 人が書いた文か |
//! |---|---|---|
//! | 人の依頼（`push_user_text`が積む。Esc で止めた依頼も残る） | 文字の塊1つ | **はい** |
//! | ツールの結果を運ぶ文（素朴ループが積む） | `ToolResult`の塊 | いいえ |
//! | 会話を畳んだ要約（`harness_engine::compaction::summarize`が積む） | 文字の塊1つ・[`FOLD_SUMMARY_PREFIX`]で始まる | いいえ |
//!
//! 「直近の文」「何個前の文」を数えるとき、後の2つを数に入れると、モデルが指す値（`{{val:N}}`）が
//! ツールの出力や要約の中の値へずれる。だから数える対象を**ここ1か所で**決める。
//!
//! # 2つの判定の違い
//!
//! - [`is_single_text_user`] は形だけを見る（`Role::User`で文字の塊1つ）。会話の区切り
//!   （`harness_engine::compaction::turn_boundaries`）はこちらを使う——畳んだ要約も区切りの1つとして数えるため
//! - [`is_human_message`] は上に加えて、畳んだ要約を外す。値の参照（`crate::user_reference`）はこちらを使う
//!
//! # ここが守らないもの
//!
//! - **見分けは形と先頭の綴りだけで行う。** 人が[`FOLD_SUMMARY_PREFIX`]で始まる文を自分で書くと、
//!   要約として扱われて数から外れる（印を状態のフラグにしないのは、`--resume`で復元した会話でも効かせるため）
//! - **畳まれて消えた文は数えられない。** 要約に入った文は会話から消えているので、何個前かも数えられない

use crate::{ContentBlock, Message, Role};

/// 畳んだ要約の文の先頭。**書く側（`harness_engine::compaction::summarize`）と、「これは要約か」を
/// 見る側（同じモジュールの空振り判定と、[`is_human_message`]）が共有する唯一の印**。
///
/// 状態フラグではなく本文の印にしてあるのは、`--resume`で復元した会話でも効かせるため
/// （チェックポイントから復元した会話は「畳んだ回数」を持たず、フラグでは判定できない）。
pub const FOLD_SUMMARY_PREFIX: &str = "[compacted summary of ";

/// `Role::User`で、中身が文字の塊1つだけの文か（形だけを見る）。
///
/// ツールの結果を運ぶ`Role::User`の文は`ContentBlock::ToolResult`を持つので、ここで外れる。
/// **畳んだ要約はここでは外れない**——外すのは[`is_human_message`]。
pub fn is_single_text_user(message: &Message) -> bool {
    message.role == Role::User && matches!(&message.content[..], [ContentBlock::Text(_)])
}

/// 人が書いた文か。[`is_single_text_user`]に加えて、畳んだ要約の文を外す。
pub fn is_human_message(message: &Message) -> bool {
    human_text(message).is_some()
}

/// 人が書いた文なら、その文字列。
fn human_text(message: &Message) -> Option<&str> {
    match (&message.role, &message.content[..]) {
        (Role::User, [ContentBlock::Text(text)]) if !text.starts_with(FOLD_SUMMARY_PREFIX) => {
            Some(text)
        }
        _ => None,
    }
}

/// 人が書いた文1つと、会話の中での位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanTurn<'a> {
    /// `messages`の添字。
    pub index: usize,
    /// 文の中身。
    pub text: &'a str,
}

/// 人が書いた文を**古い順に**全部返す。
pub fn human_turns(messages: &[Message]) -> Vec<HumanTurn<'_>> {
    messages
        .iter()
        .enumerate()
        .filter_map(|(index, m)| human_text(m).map(|text| HumanTurn { index, text }))
        .collect()
}

/// 新しい方から数えて`k`個前の、人が書いた文（`k == 0`が直近の文）。無ければ`None`。
///
/// **新しい方から数える**ので、会話を古い側から畳んでも、残った文の`k`は変わらない。
pub fn nth_back(messages: &[Message], k: usize) -> Option<HumanTurn<'_>> {
    messages
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(index, m)| human_text(m).map(|text| HumanTurn { index, text }))
        .nth(k)
}

#[cfg(test)]
#[path = "human_turns_tests.rs"]
mod tests;
