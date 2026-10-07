//! ローリング要約（縮約の②段）。`plans/PLAN-COMPACTION.md`「3. ローリング要約」。
//!
//! **providerに触る唯一の縮約モジュール**。①の切詰め（[`super::shrink`]）で目標に届かなかった
//! ときだけ呼ばれる。不可逆かつprompt cacheを全ミスさせるので、常に最後の手段。

use tokio_util::sync::CancellationToken;

use harness_core::{
    CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role, Sampling,
    ToolChoice,
};

use crate::side_call::{self, EmptyBody};
use crate::ConversationState;

/// 要約コールの出力の上限。見える要約の長さは[`COMPACTION_INSTRUCTION`]の「concisely」が決める。
///
/// 以前は1024だった。考える過程を出すモデルでは上限は考える過程にも数えられ、チャンクが大きいほど
/// 考える過程も長くなるので、本文が始まる前に上限で止まり得た（[BUG-216](../../../../docs/bugs/BUG-216.md)）。
/// 会話の外の呼び出しが共有する値を使う（[`side_call`]のモジュールdoc）。
const COMPACTION_MAX_TOKENS: u32 = side_call::SIDE_CALL_MAX_TOKENS;
const COMPACTION_INSTRUCTION: &str = "Summarize the conversation so far concisely, \
preserving all facts, decisions, file paths, and open tasks that would be needed to continue \
the work. Output only the summary text.";

/// チャンク予算の下限。`context_window / 4`がこれを下回るような極端に小さいウィンドウでも、
/// 1チャンクが1ターンすら入らないほど細切れになるのを防ぐ。
pub const MIN_CHUNK_TOKENS: u64 = 1_024;

/// 畳んだ要約メッセージの先頭。**書く側と「これは過去の要約か」を見る側が共有する唯一のマーカー**
/// （[`compact`]の空振り判定と、その回帰テスト。値の参照が「人が書いた文」から要約を外すのにも使う）。
///
/// 正本は`harness_core::human_turns`にある（値の参照は`harness-core`で人の文を数えるので、
/// 印をこちらに置くと`harness-core`から見えない）。ここは同じ定数の再公開で、コピーではない。
pub use harness_core::human_turns::FOLD_SUMMARY_PREFIX;

/// 要約コールの分割予算を`context_window`から決める。
///
/// 1/4にするのは、チャンク本体に加えて「ここまでの要約」「指示文」「出力`max_tokens`」が
/// 同じウィンドウへ載るため。**要約コール自体が超過しては本末転倒**であり、リアクティブ経路が
/// 最も必要とする場面で最も壊れやすかった従来実装の欠陥がここにあった。
///
/// **出力の上限を1024から4096へ上げた**（[BUG-216](../../../../docs/bugs/BUG-216.md)）ので、窓が
/// 8,192なら チャンク2,048＋上限4,096 で窓の3/4を使い、systemと「ここまでの要約」には残り2,048しか
/// 無い。会話の本体も同じ4096を窓から取っており、同じ構成で同じ扱いになる（ここでは窓に合わせて
/// 上限を縮めていない。[`side_call`]のモジュールdoc「ここが守らないもの」）。
pub fn chunk_tokens_for(context_window: u32) -> u64 {
    (u64::from(context_window) / 4).max(MIN_CHUNK_TOKENS)
}

/// 直近`keep_recent_turns`件の外部ユーザターンより前のメッセージを、provider呼び出し1回で
/// 生成した要約1メッセージに置き換える。カット位置は必ずターン境界（=ターン先頭）なので、
/// ターン内部のtool_use/tool_resultペアが分割されることはない。保持される直近ターンの内容は
/// 一切改変しない（thinking/redacted_thinkingも含め無傷のまま残る）。カットされる側の
/// thinking/redacted_thinkingは要約に取り込まず単純に破棄する（要約後は二度とプロバイダへ
/// 送らないため「無改変で往復」の対象外）。
///
/// 圧縮対象が無ければ（ターン境界が`keep_recent_turns`件以下）何もせず
/// `Ok(Compacted::Summarized { removed: 0 })`を返す。**畳む対象が「過去に畳んだ要約1件」だけの
/// ときも同じ**——要約を要約し直すLLMコールは情報を痩せさせるだけで何も足さない
/// （`/compact`を続けて2回押したときに起きる）。
///
/// # チャンク分割
///
/// カット対象を`chunk_tokens`以内のチャンクへ割り、`要約 = summarize(ここまでの要約, 次のチャンク)`
/// を畳み込む。**分割は必ずターン境界で行う**ので、`tool_use`/`tool_result`のペアがチャンクを
/// またいで割れることはない。1ターン単体が`chunk_tokens`を超える場合はそのターンで1チャンクに
/// する（それ以上割ると不変条件が壊れるため、超過を受け入れる）。
///
/// # 部分要約
///
/// 途中のチャンクで要約コールが失敗したら、**そこまでに得た要約で打ち切って続行する**
/// （全滅させない）。1つも要約が取れないまま失敗した場合だけ`Err`を返す。`plans/PLAN-COMPACTION.md`は
/// 「失敗したことは戻り値に出す」と書いているが、呼び出し元を触らないという同文書の要求と両立しない
/// ため、**部分要約であることは要約テキスト自身に印字**し、戻り値では「全滅か否か」だけを区別する。
///
/// **本文が空で返ったチャンクも失敗として数える**（[BUG-216](../../../../docs/bugs/BUG-216.md)）。
/// 以前は空の本文を要約として受け取っていたので、1つ目のチャンクが空なら履歴の先頭が
/// `(summary unavailable)`の1行に置き換わり（畳んだ件数は成功として報告された）、途中のチャンクが
/// 空ならそれまでの要約が空で上書きされていた。考える過程を出すモデルで、考える過程だけで出力の
/// 上限に達すると起きる。1つ目が空なら`Err`の文に「なぜ空か」（[`EmptyBody`]）を入れて返す。
///
/// # キャンセル（[BUG-074](../../../../docs/bugs/BUG-074.md)）
///
/// `cancel`が発火したらチャンク境界とストリーム受信の両方で降り、[`Compacted::Cancelled`]を返す。
/// **履歴は一切変更されない**——この関数は全チャンクの要約が揃ってから初めて`state.messages`を
/// 書き換えるので、途中で降りれば会話は無傷のまま残る（部分要約で畳んで「途中で止めた」を
/// 気付かせない、という結果にはならない）。
pub async fn compact(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    model: &str,
    keep_recent_turns: usize,
    chunk_tokens: u64,
    cancel: Option<&CancellationToken>,
) -> Result<Compacted, ProviderError> {
    let Some(cut) = foldable_cut(&state.messages, keep_recent_turns) else {
        return Ok(Compacted::Summarized { removed: 0 });
    };

    let head = state.messages[..cut].to_vec();
    let mut summary = String::new();
    let mut truncated_at: Option<usize> = None;
    let ranges = chunk_ranges(&head, chunk_tokens);
    let chunk_count = ranges.len();

    for (i, range) in ranges.into_iter().enumerate() {
        match summarize_chunk(provider, state, model, &summary, &head[range], cancel).await {
            Ok(Some(next)) => summary = next,
            // キャンセルは失敗ではないので、取れた分で畳まずそのまま降りる。
            Ok(None) => return Ok(Compacted::Cancelled),
            // 本文が空のチャンクもプロバイダの失敗と同じに扱う（BUG-216）。`summary`は
            // 上書きしない——空で上書きすると、それまでのチャンクの要約が消える。
            Err(e) => {
                if summary.trim().is_empty() {
                    // 1つも取れていないなら縮約は成立していない。履歴は一切触らず失敗を返す。
                    return Err(e.into_provider_error());
                }
                truncated_at = Some(i);
                break;
            }
        }
    }

    // ここへ来たなら`summary`は空でない——空の本文は上で失敗として扱い、1つ目が失敗すれば
    // 戻っている（`foldable_cut`が`Some`ならチャンクは1つ以上ある）。以前はここで空を
    // `(summary unavailable)`へ置き換えて畳んでおり、履歴が何も残らずに消えた（BUG-216）。
    debug_assert!(!summary.trim().is_empty());
    if let Some(i) = truncated_at {
        summary.push_str(&format!(
            "\n[partial: summarization stopped after {i} of {chunk_count} chunks]"
        ));
    }

    let removed = cut;
    let mut new_messages = vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text(format!(
            "{FOLD_SUMMARY_PREFIX}{removed} earlier messages]\n{summary}"
        ))],
    }];
    new_messages.extend(state.messages.drain(cut..));
    state.messages = new_messages;
    // BUG-075: 添字の意味がここでずれる。控えた位置を読み替えられるよう記録しておく
    // （`messages`を書き換えるのと同じ場所で必ず更新する——離すと必ず片方が漏れる）。
    state.note_prefix_folded(removed);

    Ok(Compacted::Summarized { removed })
}

/// [`compact`]の結果。「畳んだ」と「キャンセルされた」を**別の値**にしてある
/// （[BUG-074](../../../../docs/bugs/BUG-074.md)）。
///
/// 畳む対象が無かった場合も`Summarized { removed: 0 }`なので、`0`をキャンセルの意味に
/// 流用しない。呼び出し側が「要約は走ったが何も減らなかった」と「ユーザーが止めた」を
/// 取り違えると、`ContextCompacted { removed_messages: 0 }`のような**起きていない出来事**を
/// 報告してしまう。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compacted {
    /// 要約が完了し、`removed`件の元メッセージを要約1件へ置き換えた（0なら対象が無かった）。
    Summarized { removed: usize },
    /// 途中でキャンセルされた。**履歴は変更していない。**
    Cancelled,
}

impl Compacted {
    /// 畳んだ元メッセージ数。キャンセルされていれば`None`。
    pub fn removed(self) -> Option<usize> {
        match self {
            Compacted::Summarized { removed } => Some(removed),
            Compacted::Cancelled => None,
        }
    }
}

/// 畳めるカット位置。`None`なら[`compact`]は**providerを1本も呼ばずに**0件で返る。
///
/// [`compact`]の早期returnの条件そのものを外へ出したもの。呼び出し側が
/// 「[`AgentEvent::ContextCompactionStarted`](harness_core::AgentEvent::ContextCompactionStarted)を
/// 出すか」を決めるのに使う——**何もしない縮約を「始まった」と報告しない**ため
/// （[BUG-078](../../../../docs/bugs/BUG-078.md)）。判定を2箇所に書き写すと必ず食い違うので、
/// 条件はこの関数だけが持つ。
pub fn foldable_cut(messages: &[Message], keep_recent_turns: usize) -> Option<usize> {
    let cut = super::protect_boundary(messages, keep_recent_turns)?;
    if cut == 0 || is_only_a_previous_summary(&messages[..cut]) {
        return None;
    }
    Some(cut)
}

/// カット対象が「過去に畳んだ要約1件」だけか（[`FOLD_SUMMARY_PREFIX`]で見る）。
///
/// `/compact`を続けて2回押すと、2回目のカット対象は1回目の要約1件だけになる。そのまま進むと
/// **要約を要約し直すLLMコールが1本走り、情報だけ痩せて`removed: 1`と報告される**
/// （[BUG-077](../../../../docs/bugs/BUG-077.md)）。ここで止める。
fn is_only_a_previous_summary(head: &[Message]) -> bool {
    match head {
        [only] => {
            only.role == Role::User
                && matches!(&only.content[..], [ContentBlock::Text(t)] if t.starts_with(FOLD_SUMMARY_PREFIX))
        }
        _ => false,
    }
}

/// `messages`を`chunk_tokens`以内のチャンクへ割る。**分割点は必ずターン境界**。
///
/// 1ターン単体が予算を超える場合はそのターン単独で1チャンクにする——ターン内部で割ると
/// `tool_use`/`tool_result`の対応が壊れて要約コール自体が400になるので、超過の方を受け入れる。
fn chunk_ranges(messages: &[Message], chunk_tokens: u64) -> Vec<std::ops::Range<usize>> {
    if messages.is_empty() {
        return Vec::new();
    }
    // ターン境界で区切った素の区間列。先頭が境界でなければ[0, 最初の境界)も1区間にする。
    let mut starts = super::turn_boundaries(messages);
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    let segments: Vec<std::ops::Range<usize>> = starts
        .iter()
        .enumerate()
        .map(|(i, &s)| s..starts.get(i + 1).copied().unwrap_or(messages.len()))
        .filter(|r| !r.is_empty())
        .collect();

    // 予算に収まる限り隣接区間を貪欲にまとめる。
    let mut chunks: Vec<std::ops::Range<usize>> = Vec::new();
    for seg in segments {
        let seg_tokens = crate::estimate_messages(&messages[seg.clone()]);
        match chunks.last_mut() {
            Some(last)
                if crate::estimate_messages(&messages[last.start..seg.end]) <= chunk_tokens =>
            {
                last.end = seg.end;
            }
            _ => {
                let _ = seg_tokens;
                chunks.push(seg);
            }
        }
    }
    chunks
}

/// 1チャンクの要約コールが要約を返せなかった理由。
#[derive(Debug)]
enum ChunkError {
    Provider(ProviderError),
    /// 返事は来たが本文が空だった（BUG-216）。
    Empty(EmptyBody),
}

impl ChunkError {
    /// [`compact`]の戻り値（`ProviderError`）へ写す。
    ///
    /// 空の本文はプロバイダの失敗ではないが、`compact`の呼び出し元（`run_agent_loop`・`/compact`）が
    /// 受け取るのは`ProviderError`だけなので、`InvalidRequest`の文に理由を入れて運ぶ。
    /// `run_agent_loop`が`max_turns`の超過（これもプロバイダの失敗ではない）を同じ形で
    /// 返しているのに倣った。文は画面の`AgentEvent::Error`にそのまま出る。
    fn into_provider_error(self) -> ProviderError {
        match self {
            ChunkError::Provider(e) => e,
            ChunkError::Empty(empty) => ProviderError::InvalidRequest {
                msg: format!("会話の要約が空で返ったので、履歴は畳んでいない（{empty}）"),
            },
        }
    }
}

/// 1チャンク分の要約コール。`prev`が空でなければ「ここまでの要約」を先頭に載せて畳み込む。
///
/// `cancel`が発火したら`Ok(None)`。**受信途中でも降りられる**ようにストリームの読み出し全体を
/// レースの対象にしてある——要約は数十秒かかることがあり、「コールの切れ目でしか止まらない」
/// では実用的なキャンセルにならない。`Ok(Some(s))`の`s`は空でない（空なら[`ChunkError::Empty`]）。
async fn summarize_chunk(
    provider: &dyn LlmProvider,
    state: &ConversationState,
    model: &str,
    prev: &str,
    chunk: &[Message],
    cancel: Option<&CancellationToken>,
) -> Result<Option<String>, ChunkError> {
    let mut messages: Vec<Message> = Vec::with_capacity(chunk.len() + 2);
    if !prev.trim().is_empty() {
        messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text(format!(
                "[summary of the conversation before this point]\n{prev}"
            ))],
        });
    }
    messages.extend_from_slice(chunk);
    messages.push(Message {
        role: Role::User,
        content: vec![ContentBlock::Text(COMPACTION_INSTRUCTION.to_string())],
    });

    let mut req = CompletionRequest {
        system: state.system.clone(),
        messages,
        tools: Vec::new(),
        tool_choice: ToolChoice::None,
        output: None,
        parallel_tool_calls: None,
        max_tokens: COMPACTION_MAX_TOKENS,
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
        side_call::collect(provider, req)
            .await
            .map_err(ChunkError::Provider)?
            .into_body()
            .map_err(ChunkError::Empty)
    };

    match cancel {
        // `biased`で先にキャンセルを見る。既に発火していればリクエストを1本も出さずに降りる。
        Some(token) => tokio::select! {
            biased;
            _ = token.cancelled() => Ok(None),
            result = work => result.map(Some),
        },
        None => work.await.map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::test_support::{assistant_text, summary_turn, user_turn, MockProvider};
    use crate::ConversationState;

    #[tokio::test]
    async fn compacts_old_turns_and_keeps_recent_verbatim() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("turn1"));
        state.messages.push(assistant_text("reply1"));
        state.messages.push(user_turn("turn2"));
        state.messages.push(assistant_text("reply2"));
        state.messages.push(user_turn("turn3"));
        state.messages.push(assistant_text("reply3"));

        let provider = MockProvider::new(vec![summary_turn("summary of turn1/turn2")]);

        let removed = compact(&provider, &mut state, "mock-model", 1, 1_000_000, None)
            .await
            .unwrap()
            .removed()
            .expect("キャンセルしていない");

        assert_eq!(removed, 4);
        assert_eq!(state.messages.len(), 3);
        match &state.messages[0].content[0] {
            ContentBlock::Text(t) => assert!(t.contains("summary of turn1/turn2")),
            other => panic!("expected summary text, got {other:?}"),
        }
        // 直近ターン（turn3/reply3）は逐語のまま残る。
        assert_eq!(state.messages[1], user_turn("turn3"));
        assert_eq!(state.messages[2], assistant_text("reply3"));
    }

    #[tokio::test]
    async fn no_op_when_not_enough_turns_to_compact() {
        let mut state = ConversationState::new(Vec::new());
        state.messages.push(user_turn("turn1"));
        state.messages.push(assistant_text("reply1"));

        let provider = MockProvider::new(vec![]);
        let removed = compact(&provider, &mut state, "mock-model", 2, 1_000_000, None)
            .await
            .unwrap()
            .removed()
            .expect("キャンセルしていない");

        assert_eq!(removed, 0);
        assert_eq!(state.messages.len(), 2);
    }

    /// チャンク分割は必ずターン境界で行う。ターン内部で割ると`tool_use`/`tool_result`の
    /// 対応が壊れ、要約コール自体が400になる。
    #[test]
    fn chunk_ranges_never_split_a_turn() {
        let messages = vec![
            user_turn("t1"),
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
                    content: "x".repeat(4_000),
                    is_error: false,
                }],
            },
            assistant_text("done"),
            user_turn("t2"),
            assistant_text("reply2"),
        ];

        // 極小の予算でも、ターン境界（index 0 と 4）以外では割れない。
        let ranges = chunk_ranges(&messages, 1);
        assert_eq!(ranges, vec![0..4, 4..6]);

        // 予算が十分なら1チャンクにまとまる。
        assert_eq!(chunk_ranges(&messages, 1_000_000), vec![0..6]);
        assert!(chunk_ranges(&[], 100).is_empty());
    }

    /// 大きい履歴は複数チャンクへ割られ、要約コールがその回数だけ走る（＝1リクエストに
    /// 履歴を丸ごと載せない＝要約コール自体が超過しない）。
    #[tokio::test]
    async fn a_large_history_is_summarized_chunk_by_chunk() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..4 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text(&"x".repeat(400)));
        }
        state.messages.push(user_turn("recent"));

        let provider = MockProvider::new(vec![
            summary_turn("s1"),
            summary_turn("s2"),
            summary_turn("s3"),
            summary_turn("s4"),
        ]);
        // 1ターン（≒110トークン）ごとに1チャンクへ割れる予算。
        let removed = compact(&provider, &mut state, "mock-model", 1, 120, None)
            .await
            .unwrap()
            .removed()
            .expect("キャンセルしていない");

        assert_eq!(removed, 8);
        assert_eq!(provider.calls_made(), 4, "チャンクごとに1コール");
        match &state.messages[0].content[0] {
            // 畳み込みなので最後のチャンクの要約が残る。
            ContentBlock::Text(t) => assert!(t.contains("s4"), "{t}"),
            other => panic!("expected summary text, got {other:?}"),
        }
    }

    /// 途中のチャンクが失敗しても全滅させず、そこまでの要約で畳む（部分要約と明示する）。
    #[tokio::test]
    async fn a_failure_partway_through_keeps_the_partial_summary() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..4 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text(&"x".repeat(400)));
        }
        state.messages.push(user_turn("recent"));

        let provider = MockProvider::failing_from(vec![summary_turn("s1"), summary_turn("s2")], 2);
        let removed = compact(&provider, &mut state, "mock-model", 1, 120, None)
            .await
            .unwrap()
            .removed()
            .expect("キャンセルしていない");

        assert_eq!(removed, 8, "履歴は畳まれる");
        match &state.messages[0].content[0] {
            ContentBlock::Text(t) => {
                assert!(t.contains("s2"), "取れた分の要約が残る: {t}");
                assert!(t.contains("[partial:"), "部分要約であることを明示する: {t}");
            }
            other => panic!("expected summary text, got {other:?}"),
        }
    }

    /// 1つも要約が取れなければ縮約は成立していない。**履歴を一切触らず**エラーを返す。
    #[tokio::test]
    async fn a_failure_on_the_first_chunk_leaves_the_history_untouched() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text("reply"));
        }
        let before = state.messages.clone();

        let provider = MockProvider::failing_from(vec![], 0);
        let err = compact(&provider, &mut state, "mock-model", 1, 120, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ProviderError::Overloaded));
        assert_eq!(state.messages, before, "失敗時に履歴を壊さない");
    }

    // --- BUG-216: 考える過程だけで上限に達し、本文が空で返ったチャンク ---

    /// **1つ目のチャンクの本文が空なら、履歴を一切触らず、なぜ空かを言って失敗する。**
    /// 以前は空の本文を要約として受け取り、履歴の先頭が`(summary unavailable)`の1行に置き換わって
    /// `removed`が成功として返った（畳んだメッセージの中身はどこにも残らない）。
    #[tokio::test]
    async fn an_empty_first_chunk_leaves_the_history_untouched_and_says_why() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text("reply"));
        }
        let before = state.messages.clone();

        let provider = MockProvider::new(vec![side_call::thinking_then_cut_off(
            &"Let me think about what to keep. ".repeat(100),
        )]);
        let err = compact(&provider, &mut state, "mock-model", 1, 1_000_000, None)
            .await
            .expect_err("本文が空なのに畳んだ");

        assert_eq!(state.messages, before, "空の要約で履歴を置き換えない");
        let ProviderError::InvalidRequest { msg } = &err else {
            panic!("理由を運ばない失敗になった: {err:?}");
        };
        assert!(msg.contains("出力の上限"), "{msg}");
        assert!(msg.contains("考える過程"), "{msg}");
    }

    /// **途中のチャンクの本文が空なら、それまでの要約を残して部分要約として畳む。**
    /// 以前は空の本文で`summary`を上書きし、1つ目のチャンクの要約が消えていた。
    #[tokio::test]
    async fn an_empty_later_chunk_keeps_the_summary_so_far() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..4 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text(&"x".repeat(400)));
        }
        state.messages.push(user_turn("recent"));

        let provider = MockProvider::new(vec![
            summary_turn("s1"),
            side_call::thinking_then_cut_off("hmm"),
            summary_turn("s3"),
            summary_turn("s4"),
        ]);
        let removed = compact(&provider, &mut state, "mock-model", 1, 120, None)
            .await
            .unwrap()
            .removed()
            .expect("キャンセルしていない");

        assert_eq!(removed, 8, "履歴は畳まれる");
        assert_eq!(provider.calls_made(), 2, "空が返ったところで止める");
        match &state.messages[0].content[0] {
            ContentBlock::Text(t) => {
                assert!(t.contains("s1"), "1つ目のチャンクの要約が残る: {t}");
                assert!(t.contains("[partial:"), "部分要約であることを明示する: {t}");
            }
            other => panic!("expected summary text, got {other:?}"),
        }
    }

    /// 要約コールの出力の上限は、考える過程を挟んでも本文まで届く値（会話の外の呼び出しが
    /// 共有する値）である。以前は1024。
    #[tokio::test]
    async fn the_summary_call_leaves_room_for_thinking() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text("reply"));
        }
        let provider = MockProvider::new(vec![summary_turn("s")]);
        compact(&provider, &mut state, "mock-model", 1, 1_000_000, None)
            .await
            .unwrap();
        let seen = provider.max_tokens_seen();
        assert_eq!(seen, vec![side_call::SIDE_CALL_MAX_TOKENS]);
        assert!(seen[0] >= 4_096, "以前の1024へ戻っている: {seen:?}");
    }

    // --- BUG-074: 要約中のEscで降りられる ---

    /// 既にキャンセル済みなら、providerへ**1本もリクエストを出さず**に降りる。
    #[tokio::test]
    async fn an_already_cancelled_compaction_never_calls_the_provider() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..3 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text("reply"));
        }
        let before = state.messages.clone();

        let provider = MockProvider::new(vec![summary_turn("never used")]);
        let cancel = CancellationToken::new();
        cancel.cancel();

        let outcome = compact(&provider, &mut state, "mock-model", 1, 120, Some(&cancel))
            .await
            .unwrap();

        assert_eq!(outcome, Compacted::Cancelled);
        assert_eq!(provider.calls_made(), 0, "1本も出さない");
        assert_eq!(state.messages, before, "履歴は無傷");
    }

    /// 途中でキャンセルされたら、**取れていた要約で畳まない**。部分要約で畳むと
    /// 「止めたのに履歴が変わっている」という取り返しのつかない結果になる
    /// （失敗時の部分要約フォールバックとは意味が違う——あちらはユーザーが待っている）。
    #[tokio::test]
    async fn cancelling_partway_through_does_not_fold_a_partial_summary() {
        let mut state = ConversationState::new(Vec::new());
        for i in 0..4 {
            state.messages.push(user_turn(&format!("turn{i}")));
            state.messages.push(assistant_text(&"x".repeat(400)));
        }
        state.messages.push(user_turn("recent"));
        let before = state.messages.clone();

        let cancel = CancellationToken::new();
        // 1本目のコールの最中にEscを押した状況。2本目に入る前に降りる。
        let provider = MockProvider::cancelling_at(
            vec![summary_turn("s1"), summary_turn("s2"), summary_turn("s3")],
            cancel.clone(),
            0,
        );

        let outcome = compact(&provider, &mut state, "mock-model", 1, 120, Some(&cancel))
            .await
            .unwrap();

        assert_eq!(outcome, Compacted::Cancelled);
        assert_eq!(provider.calls_made(), 1, "降りた後は打たない");
        assert_eq!(state.messages, before, "部分要約で畳まない");
    }

    /// `Summarized { removed: 0 }`（畳む対象が無い）とキャンセルを取り違えない。
    #[test]
    fn nothing_to_compact_is_not_the_same_value_as_cancelled() {
        assert_eq!(Compacted::Summarized { removed: 0 }.removed(), Some(0));
        assert_eq!(Compacted::Cancelled.removed(), None);
        assert_ne!(Compacted::Summarized { removed: 0 }, Compacted::Cancelled);
    }

    #[test]
    fn the_chunk_budget_is_a_quarter_of_the_window_with_a_floor() {
        assert_eq!(chunk_tokens_for(128_000), 32_000);
        assert_eq!(chunk_tokens_for(8_192), 2_048);
        // 極端に小さいウィンドウでも下限で止まる。
        assert_eq!(chunk_tokens_for(1_000), MIN_CHUNK_TOKENS);
    }
}
