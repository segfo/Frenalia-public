//! `tool_result`の選択的切詰め（縮約の①段、純粋・provider非依存）。
//! `plans/PLAN-COMPACTION.md`「2. tool_result 選択的切詰め」。
//!
//! # なぜ①が②（要約）より先か
//!
//! - 嵩張っているのはほぼ常に`tool_result`である。
//! - **ブロックを削除せず中身を短くするだけ**なので、`tool_use`と`tool_result`の対応が
//!   構造的に壊れない（対応が崩れると次のリクエストが400になる）。
//! - 履歴の先頭を書き換えないのでprompt cacheのプレフィックスが生き残る。②は全ミスさせる。
//! - LLMコールが要らない。

use harness_core::text::truncate_head_tail;
use harness_core::{ContentBlock, Message};

/// 切詰めの結果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShrinkOutcome {
    /// 実際に短くしたブロック数。**メッセージ数・ブロック数は変わらない**。
    pub blocks: usize,
    /// 削減できたトークン概算（`estimate_json_tokens`と同じchars/4換算）。
    pub saved_tokens: u64,
}

impl ShrinkOutcome {
    pub fn is_noop(&self) -> bool {
        self.blocks == 0
    }
}

/// トークン概算とのchars換算係数（`estimate_json_tokens`のchars/4の逆）。
const CHARS_PER_TOKEN: u64 = 4;

/// 予防経路での切詰め下限。ツール出力は投入時に既に8,000文字へ切られている（`turn.rs`の
/// `MAX_TOOL_OUTPUT_CHARS`）ので、そこからさらに1/4まで許す。
pub const PREVENTIVE_FLOOR_CHARS: usize = 2_000;

/// リアクティブ経路のフォールバックでの切詰め下限。**最後の手段**なので深く削る。
pub const FALLBACK_FLOOR_CHARS: usize = 512;

/// 1ブロックを触るのに見合う最小の削減量。
///
/// 候補は大きい順に処理するので、残り必要量がこれを下回った時点で「ほぼ目標に届いた」と見なして
/// 打ち切る。これが無いと、端数（例: 31文字）のために次の`tool_result`へ省略記号を差し込んで
/// しまう——モデルが見ていた出力を数文字のために壊す割に、削減効果はゼロに等しい。
const MIN_REMOVAL_CHARS: u64 = 256;

/// `messages[..protect_from]`にある`ContentBlock::ToolResult`を、**文字数の大きい順**に
/// `target_savings`トークンぶん削れるまで切り詰める。
///
/// - `protect_from`はこのindex以降を触らない境界（`super::protect_boundary`由来）。直近ターンの
///   ツール出力はモデルがまさに参照中なので削らない。
/// - `floor_chars`より短いブロックは対象にせず、これより短くもしない。
/// - **ブロックは削除しない**。この不変条件が`tool_use`/`tool_result`の対応を守る。
///
/// 目標に届かなくてもエラーにはせず、削れたぶんだけ報告する（呼び出し側が②へ進むか、
/// 届かないまま送信してリアクティブ経路に委ねるかを決める）。
pub fn shrink_largest_tool_results(
    messages: &mut [Message],
    protect_from: usize,
    target_savings: u64,
    floor_chars: usize,
) -> ShrinkOutcome {
    if target_savings == 0 || protect_from == 0 {
        return ShrinkOutcome::default();
    }

    // (メッセージindex, ブロックindex, 現在の文字数) を集める。
    let scope = protect_from.min(messages.len());
    let mut candidates: Vec<(usize, usize, usize)> = Vec::new();
    for (mi, message) in messages[..scope].iter().enumerate() {
        for (bi, block) in message.content.iter().enumerate() {
            if let ContentBlock::ToolResult { content, .. } = block {
                let len = content.chars().count();
                if len > floor_chars {
                    candidates.push((mi, bi, len));
                }
            }
        }
    }
    // 大きい順。同点は元の並び順で安定させる（切詰め結果を決定的にするため）。
    candidates.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));

    let mut outcome = ShrinkOutcome::default();
    let target_chars = target_savings.saturating_mul(CHARS_PER_TOKEN);
    let mut saved_chars: u64 = 0;

    for (mi, bi, len) in candidates {
        let Some(remaining) = target_chars.checked_sub(saved_chars) else {
            break;
        };
        if remaining < MIN_REMOVAL_CHARS {
            break;
        }
        // このブロックから削ってよい上限（下限を割らない範囲）。
        let removable = (len - floor_chars) as u64;
        let to_remove = remaining.min(removable);
        let keep = len.saturating_sub(to_remove as usize).max(floor_chars);

        let ContentBlock::ToolResult { content, .. } = &mut messages[mi].content[bi] else {
            continue;
        };
        let shrunk = truncate_head_tail(content, keep);
        let new_len = shrunk.chars().count();
        if new_len >= len {
            // 省略記号ぶんで却って伸びる場合は触らない（冪等性の代わりの停止条件）。
            continue;
        }
        *content = shrunk;
        saved_chars += (len - new_len) as u64;
        outcome.blocks += 1;
    }

    outcome.saved_tokens = saved_chars / CHARS_PER_TOKEN;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::Role;

    fn tool_result(id: &str, chars: usize) -> ContentBlock {
        ContentBlock::ToolResult {
            tool_use_id: id.to_string(),
            content: "x".repeat(chars),
            is_error: false,
        }
    }

    fn tool_use(id: &str) -> ContentBlock {
        ContentBlock::ToolUse {
            id: id.to_string(),
            name: "read_file".to_string(),
            input: serde_json::json!({}),
        }
    }

    /// `tool_use`と`tool_result`が対になった履歴。`protect_from`を末尾にすれば全体が対象。
    fn history(sizes: &[usize]) -> Vec<Message> {
        let mut messages = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text("go".into())],
        }];
        for (i, size) in sizes.iter().enumerate() {
            let id = format!("call_{i}");
            messages.push(Message {
                role: Role::Assistant,
                content: vec![tool_use(&id)],
            });
            messages.push(Message {
                role: Role::User,
                content: vec![tool_result(&id, *size)],
            });
        }
        messages
    }

    fn result_lengths(messages: &[Message]) -> Vec<usize> {
        messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(|b| match b {
                ContentBlock::ToolResult { content, .. } => Some(content.chars().count()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn shrinks_the_largest_tool_results_first() {
        let mut messages = history(&[3_000, 9_000, 5_000]);
        let n = messages.len();
        // 1,000トークン=4,000文字ぶん削る。最大の9,000から先に削られる。
        let out = shrink_largest_tool_results(&mut messages, n, 1_000, 1_000);

        assert_eq!(out.blocks, 1, "最大の1件で足りるはず");
        let lengths = result_lengths(&messages);
        assert_eq!(lengths[0], 3_000, "小さい方は無傷");
        assert!(lengths[1] < 9_000, "最大のものが縮む");
        assert_eq!(lengths[2], 5_000, "2番目も無傷");
        // 省略記号ぶん目標をわずかに下回る。目標未達はエラーではない（呼び出し側が②へ進む）。
        assert!(out.saved_tokens >= 950, "{}", out.saved_tokens);
    }

    /// 端数のために次のブロックを削りに行かない（`MIN_REMOVAL_CHARS`）。
    /// 数文字の削減のためにモデルが見ていた出力へ省略記号を差し込むのは割に合わない。
    #[test]
    fn a_tiny_remainder_does_not_damage_a_second_block() {
        let mut messages = history(&[5_000, 9_000]);
        let n = messages.len();
        // 9,000から4,000文字削れば目標にほぼ届く。残る端数で5,000側を触らないこと。
        shrink_largest_tool_results(&mut messages, n, 1_000, 1_000);
        assert_eq!(result_lengths(&messages)[0], 5_000, "端数で2件目を触らない");
    }

    /// **この不変条件が400を防ぐ**: ブロックを消さないので`tool_use`との対応が保たれる。
    #[test]
    fn block_and_message_counts_never_change() {
        let mut messages = history(&[9_000, 9_000, 9_000]);
        let before_messages = messages.len();
        let before_blocks: usize = messages.iter().map(|m| m.content.len()).sum();
        let uses_before = messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter(|b| matches!(b, ContentBlock::ToolUse { .. }))
            .count();

        shrink_largest_tool_results(&mut messages, before_messages, 100_000, 512);

        assert_eq!(messages.len(), before_messages);
        assert_eq!(
            messages.iter().map(|m| m.content.len()).sum::<usize>(),
            before_blocks
        );
        assert_eq!(result_lengths(&messages).len(), uses_before);
    }

    #[test]
    fn never_shrinks_below_the_floor() {
        let mut messages = history(&[9_000]);
        let n = messages.len();
        // 到底届かない目標を与えても下限で止まる。
        shrink_largest_tool_results(&mut messages, n, 1_000_000, 2_000);
        let len = result_lengths(&messages)[0];
        assert!(len >= 2_000, "floor を割った: {len}");
    }

    #[test]
    fn blocks_at_or_below_the_floor_are_left_alone() {
        let mut messages = history(&[500]);
        let n = messages.len();
        let out = shrink_largest_tool_results(&mut messages, n, 10_000, 2_000);
        assert!(out.is_noop());
        assert_eq!(result_lengths(&messages), vec![500]);
    }

    /// 保護境界より後ろ（直近ターン）は逐語のまま。
    #[test]
    fn the_protected_tail_is_left_verbatim() {
        let mut messages = history(&[9_000, 9_000]);
        // 最初のtool_result（index 2）までを対象にし、それ以降を保護する。
        let out = shrink_largest_tool_results(&mut messages, 3, 100_000, 512);

        assert_eq!(out.blocks, 1);
        let lengths = result_lengths(&messages);
        assert!(lengths[0] < 9_000);
        assert_eq!(lengths[1], 9_000, "保護範囲は無傷");
    }

    #[test]
    fn zero_target_or_empty_scope_is_a_noop() {
        let mut messages = history(&[9_000]);
        let n = messages.len();
        assert!(shrink_largest_tool_results(&mut messages, n, 0, 512).is_noop());
        assert!(shrink_largest_tool_results(&mut messages, 0, 1_000, 512).is_noop());
        assert_eq!(result_lengths(&messages), vec![9_000]);
    }
}
