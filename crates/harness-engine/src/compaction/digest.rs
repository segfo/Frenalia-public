//! ツール出力のdigest（縮約の③段）。**いまのターンの中で膨らんだぶん**を畳む唯一の段。
//!
//! # なぜ①②では届かないのか
//!
//! ①[`shrink`](super::shrink)の保護境界は「いまの外部ユーザターンの先頭」で、②
//! [`summarize`](super::summarize)のカット位置は必ずターン境界である。したがって**1ターンの中で
//! `read_file`を20回繰り返して積み上がった`tool_result`には、どちらも触れない**。
//! 投入時の頭尾切詰め（`turn::MAX_TOOL_OUTPUT_CHARS` = 8,000字）が1件ずつ効くだけなので、
//! 20件読めば16万字≒4万トークンがそのまま残り続ける。
//!
//! これまでの唯一の逃げ場は、リクエストが`ContextTooLong`で弾かれた**後**に走る
//! リアクティブ・フォールバック（保護なし・下限512字の機械的切詰め）だった。つまり
//! **同じ内容は結局失われる**——失われ方が「失敗した後に、機械的に、より深く」だっただけである。
//! この段はそれを「失敗する前に、意味を残して、浅く」へ置き換える。
//!
//! # 形（ブロックは消さない・先頭は逐語で残す）
//!
//! ```text
//! [1] read_file(docs/bugs/BUG-070.md)
//!     # BUG-070: /compactが完了までイベントを出さず…      ← 先頭500字は逐語
//!     --- [harness digest: 5 tool outputs …, 38,412 chars omitted] ---
//!     ・BUG-069〜073はいずれもM09のTUI表示側の欠陥         ← 1回のLLMコールで作ったdigest
//!     ・…
//! [2] read_file(docs/bugs/BUG-071.md)
//!     | ID | BUG-071 |                                     ← 先頭500字は逐語
//!     --- [harness digest: folded into the digest above, 7,912 chars omitted] ---
//! ```
//!
//! - **`ContentBlock`を削除しない**ので`tool_use`との対応が壊れない（400にならない不変条件）。
//! - **先頭を逐語で残す**のは、digestがモデルの生成物であり*完成しているように見えて間違っている*
//!   ことがあるため。ファイルの正体（見出し・宣言・import）が残っていれば取りこぼしに気付ける。
//! - digest済みブロックは[`TOOL_DIGEST_MARKER`]で識別して**二度とdigestしない**（要約の要約を
//!   防ぐ。[BUG-077](../../../../docs/bugs/BUG-077.md)と同じ轍）。
//! - 直近[`KEEP_RECENT_TOOL_RESULTS`]件は対象外。モデルがまさに参照中の出力だからである。
//! - 省略した旨と「正確な本文が要るならツールを再実行せよ」を本文へ書く。パスは`tool_use`側に
//!   残っているので**回復経路がある**。

use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use harness_core::text::truncate_head_tail;
use harness_core::{
    AgentEvent, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role,
    Sampling, StreamEvent, ToolChoice,
};

use crate::{ConversationState, EventSink};

/// digest済みブロックのマーカー。書く側と「これは既にdigestしたか」を見る側が共有する。
///
/// ツール出力自身がこの文字列を含んでいた場合（このファイルを`read_file`した場合など）は
/// digest対象から外れるだけで、害は無い。
pub const TOOL_DIGEST_MARKER: &str = "--- [harness digest:";

/// digestしても逐語で残す先頭の文字数。
pub const VERBATIM_HEAD_CHARS: usize = 500;

/// 直近これだけの`tool_result`は触らない（モデルがまさに参照中の作業対象）。
pub const KEEP_RECENT_TOOL_RESULTS: usize = 2;

/// 1ブロックがdigest対象になる最小の文字数。これ以下はコールに見合わない。
pub const DIGEST_MIN_CHARS: usize = 2_000;

/// バッチ全体でこれだけ溜まっていなければdigestしない。**LLMコール1本の元が取れる量**が
/// 基準で、小さな`grep`を何十回やってもコールは増えない。
pub const DIGEST_MIN_BATCH_CHARS: usize = 12_000;

/// digestの出力上限。ローカルモデルでも1本で収まる長さ。
const DIGEST_MAX_TOKENS: u32 = 1_024;

/// 1回のdigestコールへ載せる入力の**絶対上限**（トークン）。
///
/// `context_window / 4`だけを予算にすると、宣言窓が262,144のような大きな値のとき1バッチが
/// 65,536トークン＝**実質「全部」**になり、digestコール1本のプロンプト処理がローカルモデルで
/// 数分かかる（2026-08-06実測: 232秒）。それは「安く何度も畳む」という③段の性格と正反対で、
/// 縮約のために縮約と同じだけ待つことになる。
///
/// **③は少量を高頻度に**畳む段なので、1回を小さく固定する。溜まり続ける限り次の周回で再び
/// 発火し、digest済みブロックは除外されるので、read×N → digest → read×N → digest… という
/// 形が自然に出る。
pub const DIGEST_BATCH_TOKENS: u64 = 6_000;

/// 抽出型の指示。「要約」ではなく「必要な事実の抜き出し」を求める——推測や結論を書かせると、
/// 元の出力に無いことが履歴に残り、後続のターンがそれを事実として扱う。
const DIGEST_INSTRUCTION: &str =
    "You are compressing the tool outputs above so they fit a smaller \
context window. For each output, extract only what is needed to continue the task stated at the \
top: file paths, identifiers, signatures, key facts, numbers, and error messages — verbatim when \
short. Do not infer, do not draw conclusions, do not restate these instructions. Keep the outputs \
in the given order and label each with its tool call. Be terse.";

/// [`digest_tool_results`]の結果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DigestOutcome {
    /// digestへ差し替えたブロック数。**メッセージ数・ブロック数は変わらない**。
    pub digested_blocks: usize,
    /// 削減できたトークン概算（chars/4換算）。
    pub saved_tokens: u64,
    /// キャンセルされた。この場合**履歴は一切変更されていない**。
    pub cancelled: bool,
}

impl DigestOutcome {
    pub fn is_noop(&self) -> bool {
        self.digested_blocks == 0
    }
}

/// トークン概算とのchars換算係数（`estimate_json_tokens`のchars/4の逆）。
const CHARS_PER_TOKEN: u64 = 4;

/// `messages[turn_start..]`（＝いまのターン）にある大きな`tool_result`を、LLMコール1回で
/// 作ったdigestへ差し替える。
///
/// `chunk_tokens`はdigestコール1本に載せる入力の上限（[`super::summarize::chunk_tokens_for`]と
/// 同じ値を渡す）。候補が多ければ**先頭から予算に収まるぶんだけ**を1バッチにする。残りは
/// 次に圧が高まったときの次のバッチになる——これが「read×5→digest→read×5→digest…」の形。
///
/// キャンセルされたら[`DigestOutcome::cancelled`]で返り、**履歴は変更しない**
/// （[BUG-074](../../../../docs/bugs/BUG-074.md)の規則）。
pub async fn digest_tool_results(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    model: &str,
    turn_start: usize,
    chunk_tokens: u64,
    events: Option<&EventSink>,
    cancel: Option<&CancellationToken>,
) -> Result<DigestOutcome, ProviderError> {
    let batch = select_batch(&state.messages, turn_start, chunk_tokens);
    if batch.is_empty() {
        return Ok(DigestOutcome::default());
    }
    // BUG-078: これからLLMコールを1本打つ。この段は`TurnStarted`より**前**に走るので、
    // 黙っていると「推論は進んでいるのに画面は無反応」になる。**コールが確定してから**出す
    // （バッチが空のときに開始だけ通知すると、何もしていない記録行が残る）。
    crate::emit(events, AgentEvent::ContextCompactionStarted);

    let Some(digest) = call_digest(provider, state, model, turn_start, &batch, cancel).await?
    else {
        return Ok(DigestOutcome {
            cancelled: true,
            ..Default::default()
        });
    };
    if digest.trim().is_empty() {
        // 空のdigestで置き換えると本文を捨てるだけになる。触らない方がましである。
        return Ok(DigestOutcome::default());
    }

    // 書き戻し。digest本文は**バッチ先頭のブロック**へ入れ、後続は先頭逐語＋「上へまとめた」印。
    let omitted_total: usize = batch
        .iter()
        .map(|c| c.chars.saturating_sub(VERBATIM_HEAD_CHARS))
        .sum();
    let count = batch.len();
    let mut saved_chars: u64 = 0;
    let mut digested_blocks = 0;

    for (i, cand) in batch.iter().enumerate() {
        let head = head_of(&state.messages, cand);
        let omitted = cand.chars.saturating_sub(head.chars().count());
        let replacement = if i == 0 {
            format!(
                "{head}\n{TOOL_DIGEST_MARKER} {count} tool outputs in this turn, {omitted_total} \
                 chars omitted. Re-run the tool if you need the exact text.] ---\n{digest}"
            )
        } else {
            format!(
                "{head}\n{TOOL_DIGEST_MARKER} folded into the digest above, {omitted} chars \
                 omitted.] ---"
            )
        };
        let new_len = replacement.chars().count();
        if new_len >= cand.chars {
            // 却って伸びるなら触らない（小さいブロックで起こり得る）。
            continue;
        }
        let ContentBlock::ToolResult { content, .. } =
            &mut state.messages[cand.mi].content[cand.bi]
        else {
            continue;
        };
        *content = replacement;
        saved_chars += (cand.chars - new_len) as u64;
        digested_blocks += 1;
    }

    Ok(DigestOutcome {
        digested_blocks,
        saved_tokens: saved_chars / CHARS_PER_TOKEN,
        cancelled: false,
    })
}

/// digest対象の1ブロック。
struct Candidate {
    mi: usize,
    bi: usize,
    chars: usize,
    /// 対応する`tool_use`の名前と入力（digestの見出しに使う。分からなければ`None`）。
    call: Option<(String, String)>,
}

/// バッチに載せるブロックを選ぶ。**選択規則がこの段の性格を決める**ので1箇所に集約する。
fn select_batch(messages: &[Message], turn_start: usize, chunk_tokens: u64) -> Vec<Candidate> {
    let scope = turn_start.min(messages.len());
    let calls = tool_calls_in(&messages[scope..]);

    let mut candidates: Vec<Candidate> = Vec::new();
    for (offset, message) in messages[scope..].iter().enumerate() {
        for (bi, block) in message.content.iter().enumerate() {
            let ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } = block
            else {
                continue;
            };
            let chars = content.chars().count();
            if chars < DIGEST_MIN_CHARS || content.contains(TOOL_DIGEST_MARKER) {
                continue;
            }
            candidates.push(Candidate {
                mi: scope + offset,
                bi,
                chars,
                call: calls
                    .iter()
                    .find(|(id, _, _)| id == tool_use_id)
                    .map(|(_, name, input)| (name.clone(), input.clone())),
            });
        }
    }

    // 直近の作業対象は残す。
    let keep = KEEP_RECENT_TOOL_RESULTS.min(candidates.len());
    candidates.truncate(candidates.len() - keep);

    if candidates.iter().map(|c| c.chars).sum::<usize>() < DIGEST_MIN_BATCH_CHARS {
        return Vec::new();
    }

    // digestコール自体が超過しないよう、先頭から予算に収まるぶんだけ。窓由来の予算と
    // 絶対上限([`DIGEST_BATCH_TOKENS`])の小さい方を採る——窓が大きいほど1バッチが巨大になり、
    // 1回のdigestが数分かかる形（実測232秒）になってしまうため。
    let budget = (chunk_tokens.min(DIGEST_BATCH_TOKENS) * CHARS_PER_TOKEN) as usize;
    let mut total = 0;
    let mut end = 0;
    for (i, cand) in candidates.iter().enumerate() {
        if end > 0 && total + cand.chars > budget {
            break;
        }
        total += cand.chars;
        end = i + 1;
    }
    candidates.truncate(end);
    candidates
}

/// ターン内の`tool_use`を(id, 名前, 入力JSON)で集める。
fn tool_calls_in(messages: &[Message]) -> Vec<(String, String, String)> {
    messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolUse { id, name, input } => {
                Some((id.clone(), name.clone(), input.to_string()))
            }
            _ => None,
        })
        .collect()
}

/// 逐語で残す先頭。`truncate_head_tail`ではなく**頭だけ**を取る——digestが続くので末尾の
/// 断片は意味を持ちにくく、ファイルの正体は先頭に出るためである。
fn head_of(messages: &[Message], cand: &Candidate) -> String {
    let ContentBlock::ToolResult { content, .. } = &messages[cand.mi].content[cand.bi] else {
        return String::new();
    };
    if content.chars().count() <= VERBATIM_HEAD_CHARS {
        return content.clone();
    }
    content.chars().take(VERBATIM_HEAD_CHARS).collect()
}

/// digestコール1本。`None`はキャンセル。
async fn call_digest(
    provider: &dyn LlmProvider,
    state: &ConversationState,
    model: &str,
    turn_start: usize,
    batch: &[Candidate],
    cancel: Option<&CancellationToken>,
) -> Result<Option<String>, ProviderError> {
    let mut body = String::new();
    if let Some(task) = task_text(&state.messages, turn_start) {
        body.push_str("[the task being worked on]\n");
        // タスク文が長すぎてもdigestコールを膨らませない。
        body.push_str(&truncate_head_tail(&task, 2_000));
        body.push_str("\n\n");
    }
    for (i, cand) in batch.iter().enumerate() {
        let label = match &cand.call {
            Some((name, input)) => format!("{name} {}", truncate_head_tail(input, 200)),
            None => "(unknown tool call)".to_string(),
        };
        let ContentBlock::ToolResult { content, .. } = &state.messages[cand.mi].content[cand.bi]
        else {
            continue;
        };
        body.push_str(&format!(
            "[tool output {} of {} — {label}]\n{content}\n\n",
            i + 1,
            batch.len()
        ));
    }

    let mut req = CompletionRequest {
        system: state.system.clone(),
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text(body)],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text(DIGEST_INSTRUCTION.to_string())],
            },
        ],
        tools: Vec::new(),
        tool_choice: ToolChoice::None,
        output: None,
        parallel_tool_calls: None,
        max_tokens: DIGEST_MAX_TOKENS,
        sampling: Sampling::default(),
        model: model.to_string(),
    };
    if req
        .system
        .iter()
        .any(|s| s.text.contains("Tier3のLinuxコンテナ実行環境"))
    {
        crate::sanitize::completion_request(&mut req);
    }

    let work = async {
        let mut stream = provider.stream(req).await?;
        let mut out = String::new();
        while let Some(event) = stream.next().await {
            if let StreamEvent::TextDelta { text, .. } = event? {
                out.push_str(&text);
            }
        }
        Ok::<String, ProviderError>(out)
    };

    let text = match cancel {
        // `biased`で先にキャンセルを見る。既に発火していればリクエストを1本も出さない。
        Some(token) => tokio::select! {
            biased;
            _ = token.cancelled() => return Ok(None),
            result = work => result?,
        },
        None => work.await?,
    };
    if text.trim().is_empty() {
        // 空のdigestで置き換えると本文を捨てるだけになる。触らない方がまし。
        return Ok(Some(String::new()));
    }
    Ok(Some(text))
}

/// いまのターンのユーザプロンプト本文（digestに「何のために読んだか」を教えるため）。
fn task_text(messages: &[Message], turn_start: usize) -> Option<String> {
    let m = messages.get(turn_start)?;
    if m.role != Role::User {
        return None;
    }
    match m.content.first() {
        Some(ContentBlock::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::test_support::{summary_turn, tool_round, user_turn, MockProvider};
    use crate::compaction::{protect_boundary, DEFAULT_KEEP_RECENT_TURNS};

    /// 「ユーザプロンプト＋`rounds`件のtool_round」だけのターン。
    fn turn_with_reads(rounds: usize, chars: usize) -> ConversationState {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("read the bug catalog"));
        for i in 0..rounds {
            state
                .messages
                .extend(tool_round(&format!("call_{i}"), chars));
        }
        state
    }

    fn digest_scope(state: &ConversationState) -> usize {
        protect_boundary(&state.messages, 1).unwrap_or(0)
    }

    /// 5件読んだ状態でdigestすると、直近2件を除く3件が「先頭逐語＋digest」へ縮む。
    /// ブロック数・メッセージ数は不変（`tool_use`との対応が壊れない）。
    #[tokio::test]
    async fn digests_the_older_tool_results_of_the_current_turn() {
        let mut state = turn_with_reads(5, 8_000);
        let before_messages = state.messages.len();
        let before_blocks: usize = state.messages.iter().map(|m| m.content.len()).sum();
        let scope = digest_scope(&state);

        let provider =
            MockProvider::new(vec![summary_turn("・BUG-070: 進捗が無く連打される\n・…")]);
        let out = digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        assert_eq!(out.digested_blocks, 3, "直近2件は残す");
        assert!(out.saved_tokens > 4_000, "{}", out.saved_tokens);
        assert_eq!(provider.calls_made(), 1, "バッチ全体で1コール");
        assert_eq!(state.messages.len(), before_messages);
        assert_eq!(
            state
                .messages
                .iter()
                .map(|m| m.content.len())
                .sum::<usize>(),
            before_blocks
        );

        let lengths = crate::compaction::test_support::tool_result_lengths(&state.messages);
        assert!(lengths[0] < 2_000, "先頭3件は縮む: {lengths:?}");
        assert_eq!(lengths[3], 8_000, "直近2件は逐語");
        assert_eq!(lengths[4], 8_000);
    }

    /// digest本文はバッチ先頭にだけ入り、残りは「上へまとめた」印になる。
    /// どのブロックにも**先頭の逐語**が残る。
    #[tokio::test]
    async fn the_verbatim_head_survives_and_the_digest_lands_once() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("read them"));
        for i in 0..4 {
            let mut round = tool_round(&format!("call_{i}"), 8_000);
            // 先頭が見分けられる中身にする。
            if let ContentBlock::ToolResult { content, .. } = &mut round[1].content[0] {
                *content = format!("# file {i} header\n{}", "y".repeat(8_000));
            }
            state.messages.extend(round);
        }
        let scope = digest_scope(&state);

        let provider = MockProvider::new(vec![summary_turn("DIGEST-BODY")]);
        digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        let contents: Vec<String> = state
            .messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(|b| match b {
                ContentBlock::ToolResult { content, .. } => Some(content.clone()),
                _ => None,
            })
            .collect();
        assert!(
            contents[0].starts_with("# file 0 header"),
            "{}",
            &contents[0][..40]
        );
        assert!(contents[0].contains("DIGEST-BODY"), "先頭にdigest本文");
        assert!(
            contents[1].starts_with("# file 1 header"),
            "先頭は逐語で残る"
        );
        assert!(contents[1].contains("folded into the digest above"));
        assert!(!contents[1].contains("DIGEST-BODY"), "digestを複製しない");
    }

    /// **1回のdigestは`DIGEST_BATCH_TOKENS`で切れる**（窓が大きくても1本が数分かからない）。
    /// 溢れたぶんは次に圧が高まったときの次のバッチへ回る。
    #[tokio::test]
    async fn a_batch_is_capped_by_the_absolute_budget_even_with_a_huge_window() {
        // 8,000字×6件 → 直近2件を除いた4件が候補。絶対上限6,000トークン=24,000字なので3件で切れる。
        let mut state = turn_with_reads(6, 8_000);
        let scope = digest_scope(&state);
        let provider = MockProvider::new(vec![summary_turn("d1"), summary_turn("d2")]);

        let first = digest_tool_results(&provider, &mut state, "mock", scope, u64::MAX, None, None)
            .await
            .unwrap();
        assert_eq!(first.digested_blocks, 3, "1回で全部やらない");

        // 残った1件（＋新たな溜まり）は次の周回で畳まれる。
        let second =
            digest_tool_results(&provider, &mut state, "mock", scope, u64::MAX, None, None)
                .await
                .unwrap();
        assert!(
            second.is_noop(),
            "残り1件は`DIGEST_MIN_BATCH_CHARS`未満なのでコールしない: {second:?}"
        );
        assert_eq!(provider.calls_made(), 1);
    }

    /// **2回目のdigestは1回目の結果を対象にしない**（要約の要約を防ぐ、BUG-077と同じ轍）。
    /// 新しく読んだぶんだけが次のバッチになる＝read×N→digest→read×N→digestの形。
    #[tokio::test]
    async fn a_second_pass_only_digests_newly_read_output() {
        let mut state = turn_with_reads(5, 8_000);
        let scope = digest_scope(&state);
        let provider = MockProvider::new(vec![summary_turn("d1"), summary_turn("d2")]);
        digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        // さらに5件読む。
        for i in 5..10 {
            state
                .messages
                .extend(tool_round(&format!("call_{i}"), 8_000));
        }
        let out = digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        // 1回目でdigestした3件は候補から外れる（マーカーで識別）。残り＝逐語のまま溜まった
        // 5件（index 3,4と新規5件のうち直近2件を除く）から、絶対上限ぶんの3件を畳む。
        assert_eq!(
            out.digested_blocks, 3,
            "上限で切りつつ、新しく読んだぶんだけを対象にする"
        );
        assert_eq!(provider.calls_made(), 2);
        let lengths = crate::compaction::test_support::tool_result_lengths(&state.messages);
        assert!(
            lengths[0] < 2_000,
            "1回目のdigestは畳み直されない: {lengths:?}"
        );
        assert_eq!(lengths[8], 8_000, "直近2件は逐語のまま");
        assert_eq!(lengths[9], 8_000);
    }

    /// 小さい出力を何十回やってもコールは増えない（`DIGEST_MIN_BATCH_CHARS`）。
    #[tokio::test]
    async fn many_small_outputs_never_trigger_a_call() {
        let mut state = turn_with_reads(20, 300);
        let scope = digest_scope(&state);
        let provider = MockProvider::new(vec![]);

        let out = digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        assert!(out.is_noop());
        assert_eq!(provider.calls_made(), 0);
    }

    /// 予算に収まらないぶんは次のバッチへ回す（digestコール自体を超過させない）。
    #[tokio::test]
    async fn a_batch_is_capped_by_the_call_budget() {
        let mut state = turn_with_reads(6, 8_000);
        let scope = digest_scope(&state);
        let provider = MockProvider::new(vec![summary_turn("d")]);

        // 4,000トークン=16,000字＝8,000字のブロック2件ぶん。
        let out = digest_tool_results(&provider, &mut state, "mock", scope, 4_000, None, None)
            .await
            .unwrap();

        assert_eq!(out.digested_blocks, 2, "予算ぶんだけ");
    }

    /// キャンセルなら**履歴は無傷**（BUG-074の規則）。
    #[tokio::test]
    async fn a_cancelled_digest_leaves_the_history_untouched() {
        let mut state = turn_with_reads(5, 8_000);
        let before = state.messages.clone();
        let scope = digest_scope(&state);
        let provider = MockProvider::new(vec![summary_turn("never used")]);
        let cancel = CancellationToken::new();
        cancel.cancel();

        let out = digest_tool_results(
            &provider,
            &mut state,
            "mock",
            scope,
            1_000_000,
            None,
            Some(&cancel),
        )
        .await
        .unwrap();

        assert!(out.cancelled);
        assert!(out.is_noop());
        assert_eq!(provider.calls_made(), 0);
        assert_eq!(state.messages, before);
    }

    /// ②が畳んだ後の履歴（先頭が要約）でも、いまのターンだけを対象にする。
    #[tokio::test]
    async fn only_the_current_turn_is_in_scope() {
        let mut state = ConversationState::new(Vec::new());
        // 過去のターン（8,000字のtool_result付き）。
        state.messages.push(user_turn("old turn"));
        state.messages.extend(tool_round("old_call", 8_000));
        // いまのターン。
        state.messages.push(user_turn("current turn"));
        for i in 0..4 {
            state
                .messages
                .extend(tool_round(&format!("call_{i}"), 8_000));
        }
        let scope = protect_boundary(&state.messages, 1).unwrap();

        let provider = MockProvider::new(vec![summary_turn("d")]);
        let out = digest_tool_results(&provider, &mut state, "mock", scope, 1_000_000, None, None)
            .await
            .unwrap();

        assert_eq!(out.digested_blocks, 2, "いまのターンの4件から直近2件を除く");
        let lengths = crate::compaction::test_support::tool_result_lengths(&state.messages);
        assert_eq!(lengths[0], 8_000, "過去のターンは①②の担当なので触らない");
        // 保護ターン数の既定を変えてもこのテストの前提が壊れないことを明示する。
        assert_eq!(DEFAULT_KEEP_RECENT_TURNS, 2);
    }
}
