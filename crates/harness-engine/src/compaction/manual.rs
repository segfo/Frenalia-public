//! 手動`/compact`（`harness-tui`の`EngineCommand::Compact`）の順序と範囲の正本。
//!
//! # なぜ手動だけ②→①なのか（自動経路は①→②）
//!
//! 自動経路（[`crate::run_agent_loop`]の予防的縮約）が①を先に置くのは「高いLLMコールを打たずに
//! 済むか試す」ためである。**手動では②は必ず打つ**（ユーザーが明示的に要求した操作なので、
//! 安く済ませる分岐が存在しない）ので、その理由は成立しない。代わりに次の3つが順序を決める。
//!
//! 1. **キャンセルの一貫性**（[BUG-074](../../../../docs/bugs/BUG-074.md)）。①は即完了する
//!    不可逆な純粋関数、②は数十秒かかる。①を先にやるとEscで降りたとき「止めたのに直近の
//!    `tool_result`は切り詰められている」になり、「キャンセルなら履歴は無傷」が壊れる。
//! 2. **①の対象が変わる**。手動の①が縮めたいのは②が**消さずに残す側**（直近ターン）である。
//!    ②より先に走らせて`protect_from`を直近ターン境界に置くと、①は「これから要約で消える領域」
//!    だけを削ることになり無意味になる。
//! 3. **要約の質**。②が切り詰め前の履歴を読める。
//!
//! # ①で直近ターンを保護しない理由
//!
//! 自動経路は直近1ターンの`tool_result`を保護する——ループの最中であり、モデルがまさに
//! 参照中の出力を削るのは筋が悪いからである。手動`/compact`が処理される時点では
//! engineループは停止しており（コマンドはターンの合間に処理される）、参照中の出力が存在しない。
//! ユーザーが望んでいるのは「直近の巨大なファイル読み込みも概要だけ持つ」ことなので、
//! ここでは保護境界を置かず、[`SHALLOW_FLOOR_CHARS`]まで削り切る。

use tokio_util::sync::CancellationToken;

use harness_core::{LlmProvider, ProviderError};

use super::shrink::{shrink_largest_tool_results, ShrinkOutcome, SHALLOW_FLOOR_CHARS};
use super::summarize::{compact, Compacted};
use super::DEFAULT_KEEP_RECENT_TURNS;
use crate::ConversationState;

/// [`compact_now`]の結果。②と①のどちらが何をしたかを別々に持つ——呼び出し側は
/// `ContextCompacted`と`ContextShrunk`という**別のイベント**へ写す（0件削除の切詰めを
/// 「要約に畳み込んだ」と報告すると嘘になる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualOutcome {
    pub compacted: Compacted,
    pub shrunk: ShrinkOutcome,
}

/// 手動`/compact`の本体。②ローリング要約 → ①生き残った側の`tool_result`切詰め、の順に行う。
///
/// キャンセルされた場合は①を**行わない**ので、履歴は1バイトも変わらない。
///
/// 逐語で残すターン数は自動経路と同じ[`DEFAULT_KEEP_RECENT_TURNS`]。同じ値でも残るものは違う
/// ——自動経路は送信済みのプロンプトが履歴に居る状態で走るため1枠をそれが占めるが、手動の
/// 時点ではまだ居ないので、直近2往復が丸ごと逐語で残る。
pub async fn compact_now(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    model: &str,
    chunk_tokens: u64,
    cancel: Option<&CancellationToken>,
) -> Result<ManualOutcome, ProviderError> {
    let compacted = compact(
        provider,
        state,
        model,
        DEFAULT_KEEP_RECENT_TURNS,
        chunk_tokens,
        cancel,
    )
    .await?;
    if compacted == Compacted::Cancelled {
        return Ok(ManualOutcome {
            compacted,
            shrunk: ShrinkOutcome::default(),
        });
    }

    // 要約メッセージは`Text`ブロックなので①は触らない。`u64::MAX`は削減目標を置かず
    // 「下限まで削り切る」指定（リアクティブ経路のフォールバックと同じ形）。
    let scope = state.messages.len();
    let shrunk =
        shrink_largest_tool_results(&mut state.messages, scope, u64::MAX, SHALLOW_FLOOR_CHARS);

    Ok(ManualOutcome { compacted, shrunk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::test_support::{
        assistant_text, summary_turn, tool_result_lengths, tool_round, user_turn, MockProvider,
    };
    use harness_core::ContentBlock;

    /// 直近2往復（`DEFAULT_KEEP_RECENT_TURNS`）は逐語で残るが、**その中の`tool_result`は
    /// 下限まで切り詰める**。これが「ファイルリードの概要だけ持つ」の実装。
    ///
    /// 併せて固定する不変条件: ①はブロックを削除しないので`tool_use`との対応が壊れない
    /// （壊れると次のリクエストが400になる）。
    #[tokio::test]
    async fn keeps_the_recent_turns_verbatim_and_shrinks_their_tool_results() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("t0"));
        state.messages.push(assistant_text("reply0"));
        state.messages.push(user_turn("t1"));
        state.messages.extend(tool_round("call_a", 8_000));
        state.messages.push(assistant_text("reply1"));
        state.messages.push(user_turn("t2"));
        state.messages.extend(tool_round("call_b", 8_000));
        state.messages.push(assistant_text("reply2"));
        let tool_uses = state
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter(|b| matches!(b, ContentBlock::ToolUse { .. }))
            .count();

        let provider = MockProvider::new(vec![summary_turn("summary of t0")]);
        let out = compact_now(&provider, &mut state, "mock-model", 1_000_000, None)
            .await
            .unwrap();

        // ②: t0/reply0 が要約1件へ。
        assert_eq!(out.compacted, Compacted::Summarized { removed: 2 });
        assert_eq!(state.messages.len(), 9, "2件が1件へ畳まれた");
        assert_eq!(state.messages[1], user_turn("t1"), "直近2往復は逐語");
        assert_eq!(state.messages[8], assistant_text("reply2"));

        // ①: 生き残った両方の tool_result が下限付近まで縮む。
        assert_eq!(
            out.shrunk.blocks, 2,
            "保護境界を置かないので直近ターンも縮む"
        );
        for len in tool_result_lengths(&state.messages) {
            assert!(
                (2_000..2_100).contains(&len),
                "下限付近まで縮んでいること: {len}"
            );
        }
        // tool_use と tool_result の対応は保たれる。
        assert_eq!(tool_result_lengths(&state.messages).len(), tool_uses);
    }

    /// **②→①の順序を固定する回帰テスト。** キャンセルされたら①も走らないので、履歴は
    /// 1バイトも変わらない（①を先に走らせていたら「止めたのに切り詰められている」になる）。
    #[tokio::test]
    async fn a_cancelled_manual_compaction_leaves_the_history_untouched() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("t{i}")));
            state
                .messages
                .extend(tool_round(&format!("call_{i}"), 8_000));
            state.messages.push(assistant_text("reply"));
        }
        let before = state.messages.clone();

        let provider = MockProvider::new(vec![summary_turn("never used")]);
        let cancel = CancellationToken::new();
        cancel.cancel();

        let out = compact_now(
            &provider,
            &mut state,
            "mock-model",
            1_000_000,
            Some(&cancel),
        )
        .await
        .unwrap();

        assert_eq!(out.compacted, Compacted::Cancelled);
        assert!(out.shrunk.is_noop(), "キャンセル時は切詰めもしない");
        assert_eq!(provider.calls_made(), 0);
        assert_eq!(state.messages, before, "履歴は無傷");
    }

    /// 畳む対象が無くても（発話1回だけ）①は効く。巨大なファイル読み込みの直後に
    /// `/compact`した場合がこれで、**現状はここで1バイトも縮まなかった**。
    #[tokio::test]
    async fn shrinks_even_when_there_is_nothing_to_summarize() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("read these files"));
        state.messages.extend(tool_round("call_a", 8_000));
        state.messages.extend(tool_round("call_b", 8_000));
        state.messages.push(assistant_text("done"));

        let provider = MockProvider::new(vec![]);
        let out = compact_now(&provider, &mut state, "mock-model", 1_000_000, None)
            .await
            .unwrap();

        assert_eq!(out.compacted, Compacted::Summarized { removed: 0 });
        assert_eq!(provider.calls_made(), 0, "要約コールは打たない");
        assert_eq!(out.shrunk.blocks, 2);
        for len in tool_result_lengths(&state.messages) {
            assert!((2_000..2_100).contains(&len), "{len}");
        }
    }

    /// BUG-077: `/compact`を続けて2回押しても、2回目は**要約を要約し直さない**。
    #[tokio::test]
    async fn pressing_compact_twice_does_not_resummarize_the_summary() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("t{i}")));
            state.messages.push(assistant_text("reply"));
        }

        let provider = MockProvider::new(vec![summary_turn("summary of t0")]);
        let first = compact_now(&provider, &mut state, "mock-model", 1_000_000, None)
            .await
            .unwrap();
        assert_eq!(first.compacted, Compacted::Summarized { removed: 2 });
        assert_eq!(provider.calls_made(), 1);
        let after_first = state.messages.clone();

        let second = compact_now(&provider, &mut state, "mock-model", 1_000_000, None)
            .await
            .unwrap();

        assert_eq!(second.compacted, Compacted::Summarized { removed: 0 });
        assert_eq!(provider.calls_made(), 1, "2回目は1本も打たない");
        assert_eq!(state.messages, after_first, "履歴も変わらない");
    }
}
