//! 会話の外で打つ1回きりのLLM呼び出しが共有する、出力の上限とストリームの読み方
//! （[BUG-214](../../../docs/bugs/BUG-214.md)・[BUG-216](../../../docs/bugs/BUG-216.md)）。
//!
//! 使っているのは3つ——承認画面の要約（[`crate::approval_summary`]）、縮約の②ローリング要約
//! （[`crate::compaction::summarize`]）、③digest（[`crate::compaction::digest`]）。どれも
//! 「道具を渡さずに1回だけ問い合わせ、返ってきた本文を使う」呼び出しで、会話の本体
//! （[`crate::turn`]）と違って縮退ガードも回復の梯子も掛かっていない。だから**本文が空で
//! 返ってきたとき、なぜ空なのかを言えるのはここだけ**である。以前は3つがそれぞれ「本文の差分
//! だけを集める」ループを書いており、止まった理由も考える過程の量も捨てていた。
//!
//! # 出力の上限は「見える本文の長さ」ではない
//!
//! 考える過程（reasoning。OpenAI互換の`reasoning_content`、Anthropicのthinking）を出すモデルでは、
//! `max_tokens`は**考える過程と本文の合計**に掛かる。見える本文の長さを決めているのは各呼び出しの
//! 指示文（「8行まで」「簡潔に」）であって、上限ではない。上限を本文の長さに合わせて小さくすると、
//! 本文が始まる前に考える過程だけで上限に達し、本文が空のまま止まる。
//!
//! 2026-10-03の実測（LMStudio・Qwen3.6 35B系・承認の要約と同じ要求・各1回）: 上限512では
//! 考える過程が512トークン全部を使って本文0文字、上限4096では考える過程505トークン＋本文46トークンで
//! 止まった（所要はどちらも9秒）。
//!
//! だから3つとも`SIDE_CALL_MAX_TOKENS`を使う。**上限は天井であって目標ではない**ので、
//! 短く終わるモデルの所要時間は変わらない。
//!
//! # ここが守らないもの
//!
//! - **上限を上げても、考える過程がそれより長いモデルでは本文は空になる。** そのときは
//!   [`EmptyBody`]で「上限で止まった・考える過程が何文字あった」を返すだけで、やり直しはしない。
//! - **考える過程そのものは止めない。** プロバイダ固有の引数（`/no_think`・`enable_thinking`等）は
//!   送らない——プロバイダごとに名前も効き方も違い、`plans/e2e/RESULTS.md`では`/no_think`を
//!   前置しても考える過程が止まらなかった。
//! - **壊れた出力（反復・巡回）は検知しない。** 縮退ガード（M21）は会話の本体にしか掛かっていない
//!   ので、ここでは上限まで生成させてから止まる。上限を4096にしたので、壊れたときの待ち時間は
//!   1024だったときの約4倍になる（`degeneracy::detect`の見積もりではローカル35Bで50〜100秒）。
//!   どの呼び出しもキャンセルで降りられる。
//! - **コンテキスト窓の小さい構成（4k〜8k）では、入力と上限の合計が窓を超えることがある。**
//!   会話の本体も同じ4096を使っており、同じ構成で同じ扱いになる。ここで窓に合わせて上限を縮めることは
//!   していない。

use std::fmt;

use futures::StreamExt;

use harness_core::{CompletionRequest, LlmProvider, ProviderError, StopReason, StreamEvent};

/// 会話の外で打つ1回きりの呼び出しの出力の上限。
///
/// **会話の本体の既定（`harness-cli`の`DEFAULT_MAX_TOKENS`）と同じ値**にしてある。どちらも
/// 同じモデルが考える過程を挟んでから本文を書く呼び出しで、本体はこの値で本文まで届いている。
/// 見える長さは各呼び出しの指示文が決める（モジュールdoc）。
pub(crate) const SIDE_CALL_MAX_TOKENS: u32 = 4_096;

/// 1回きりの呼び出しの返事を、本文だけでなく「なぜそこで止まったか」まで含めて集めたもの。
pub(crate) struct Collected {
    text: String,
    /// 考える過程（`StreamEvent::ThinkingDelta`）の文字数。中身は使わない。
    thinking_chars: usize,
    /// `StreamEvent::Done`が運んだ止まった理由。届かなかったら`None`。
    stop_reason: Option<StopReason>,
    /// 要求に載せた出力の上限（知らせの文に出す）。
    max_tokens: u32,
}

/// `req`を送り、ストリームを最後まで読む。**本文の差分だけでなく、考える過程の量と止まった理由も
/// 控える**——本文が空だったとき、それを言える材料がここにしか無い。
///
/// キャンセルは呼び出し側が`select!`で包む（3つの呼び出しで既定の扱いが違うため）。
pub(crate) async fn collect(
    provider: &dyn LlmProvider,
    req: CompletionRequest,
) -> Result<Collected, ProviderError> {
    collect_reporting(provider, req, &mut |_| {}).await
}

/// [`collect`]と同じ読み方で、**出力が届くたびに、それまでに受けた出力の文字数の累計**を`on_output`へ渡す。
/// 数えるのは考える過程と本文の両方（会話の「Thinking…」の行が数える量と同じ。`harness-tui`の
/// `current_turn_downstream_chars`）。承認画面の要約の待ちの表示が使う。
pub(crate) async fn collect_reporting(
    provider: &dyn LlmProvider,
    req: CompletionRequest,
    on_output: &mut (dyn FnMut(usize) + Send),
) -> Result<Collected, ProviderError> {
    let max_tokens = req.max_tokens;
    let mut stream = provider.stream(req).await?;
    let mut out = Collected {
        text: String::new(),
        thinking_chars: 0,
        stop_reason: None,
        max_tokens,
    };
    let mut output_chars = 0usize;
    while let Some(event) = stream.next().await {
        match event? {
            StreamEvent::TextDelta { text, .. } => {
                output_chars += text.chars().count();
                out.text.push_str(&text);
                on_output(output_chars);
            }
            StreamEvent::ThinkingDelta { text, .. } => {
                let chars = text.chars().count();
                out.thinking_chars += chars;
                output_chars += chars;
                on_output(output_chars);
            }
            StreamEvent::Done { stop_reason, .. } => out.stop_reason = Some(stop_reason),
            _ => {}
        }
    }
    Ok(out)
}

impl Collected {
    /// 本文を返す。**空（空白だけを含む）なら、なぜ空なのかを返す。** 本文は切り詰めない
    /// （前後の空白をどう扱うかは呼び出し側の都合）。
    pub(crate) fn into_body(self) -> Result<String, EmptyBody> {
        if self.text.trim().is_empty() {
            return Err(EmptyBody {
                stop_reason: self.stop_reason,
                max_tokens: self.max_tokens,
                thinking_chars: self.thinking_chars,
            });
        }
        Ok(self.text)
    }
}

/// 返事は来たが、本文が空だった。**上限で止まったのか、別の理由かを区別して持つ**
/// （[BUG-214](../../../docs/bugs/BUG-214.md)。以前は「空の要約を返した」としか言えず、
/// 原因が画面から読めなかった）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyBody {
    /// 止まった理由。ストリームが`Done`を運ばずに終わったら`None`。
    pub stop_reason: Option<StopReason>,
    /// 要求に載せた出力の上限。
    pub max_tokens: u32,
    /// 考える過程の文字数（トークン数ではない。プロバイダは考える過程のトークン数を運ばない）。
    pub thinking_chars: usize,
}

impl EmptyBody {
    /// 出力の上限で止まったか。
    pub fn hit_output_limit(&self) -> bool {
        self.stop_reason == Some(StopReason::MaxTokens)
    }
}

impl fmt::Display for EmptyBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hit_output_limit() {
            write!(
                f,
                "本文が空のまま出力の上限（{} トークン）に達した",
                self.max_tokens
            )?;
            if self.thinking_chars > 0 {
                write!(
                    f,
                    "——考える過程（{} 文字）で上限を使い切ったとみられる",
                    self.thinking_chars
                )?;
            }
            return Ok(());
        }
        let reason = match &self.stop_reason {
            None => "終わりの合図が届かなかった",
            Some(StopReason::EndTurn) => "end_turn",
            Some(StopReason::ToolUse) => "tool_use",
            Some(StopReason::MaxTokens) => "max_tokens",
            Some(StopReason::StopSequence) => "stop_sequence",
            Some(StopReason::Refusal) => "refusal",
            Some(StopReason::Other(other)) => other.as_str(),
        };
        write!(f, "モデルが空の本文を返した（止まった理由: {reason}")?;
        if self.thinking_chars > 0 {
            write!(f, "、考える過程は {} 文字", self.thinking_chars)?;
        }
        write!(f, "）")
    }
}

impl std::error::Error for EmptyBody {}

/// 考える過程だけを流して、本文が始まる前に出力の上限で止まるストリーム（試験用）。
/// 2026-10-03に実機で見た形（`reasoning_content`だけで`finish_reason: "length"`）をそのまま写す。
#[cfg(test)]
pub(crate) fn thinking_then_cut_off(thinking: &str) -> Vec<StreamEvent> {
    use harness_core::{BlockKind, Usage};
    vec![
        StreamEvent::BlockStart {
            index: usize::MAX,
            kind: BlockKind::Thinking,
        },
        StreamEvent::ThinkingDelta {
            index: usize::MAX,
            text: thinking.to_string(),
        },
        StreamEvent::BlockStop { index: usize::MAX },
        StreamEvent::Done {
            stop_reason: StopReason::MaxTokens,
            usage: Usage::default(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(stop_reason: Option<StopReason>, thinking_chars: usize) -> EmptyBody {
        EmptyBody {
            stop_reason,
            max_tokens: 4_096,
            thinking_chars,
        }
    }

    /// 上限で止まったときだけ「上限」と言い、考える過程があればそれも言う。上限ではないのに
    /// 空だったときは、止まった理由をそのまま出す（「上限」と言わない）。
    #[test]
    fn the_message_tells_the_output_limit_apart_from_other_empty_bodies() {
        let at_limit = empty(Some(StopReason::MaxTokens), 1_750).to_string();
        assert!(
            at_limit.contains("出力の上限（4096 トークン）"),
            "{at_limit}"
        );
        assert!(at_limit.contains("考える過程（1750 文字）"), "{at_limit}");

        let at_limit_without_thinking = empty(Some(StopReason::MaxTokens), 0).to_string();
        assert!(at_limit_without_thinking.contains("出力の上限"));
        assert!(!at_limit_without_thinking.contains("考える過程"));

        let ended = empty(Some(StopReason::EndTurn), 0).to_string();
        assert!(!ended.contains("上限"), "{ended}");
        assert!(ended.contains("end_turn"), "{ended}");

        let cut = empty(None, 12).to_string();
        assert!(cut.contains("終わりの合図が届かなかった"), "{cut}");
        assert!(cut.contains("考える過程は 12 文字"), "{cut}");
    }

    /// 空白だけの本文は空として扱う。本文があれば前後の空白はそのまま返す（切るのは呼び出し側）。
    #[test]
    fn whitespace_only_is_empty_and_a_real_body_is_returned_as_is() {
        let blank = Collected {
            text: "\n  \n".to_string(),
            thinking_chars: 3,
            stop_reason: Some(StopReason::EndTurn),
            max_tokens: 7,
        };
        let err = blank.into_body().unwrap_err();
        assert_eq!(err.max_tokens, 7, "要求に載せた上限を運ぶ");
        assert_eq!(err.thinking_chars, 3);

        let body = Collected {
            text: "\nnetwork access\n".to_string(),
            thinking_chars: 0,
            stop_reason: Some(StopReason::EndTurn),
            max_tokens: 7,
        };
        assert_eq!(body.into_body().unwrap(), "\nnetwork access\n");
    }
}
