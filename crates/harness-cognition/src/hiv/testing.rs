//! テスト専用の[`Executor`]スクリプト。
//!
//! `MockProvider`（`harness-providers`）が`stream()`の**呼び出し順**で応答を返すのに対し、
//! ここは**どのフェーズのコールか**を見て応答を選ぶ。HIVループはフェーズを行き来する
//! （Verifyがinconclusiveなら同じ仮説をもう一度調査する等）ので、順序前提のスクリプトだと
//! 「何回目の呼び出しか」を数え直すたびにテストが壊れ、状態機械の意図が読めなくなるため。
//!
//! フェーズの判別はシステムプロンプト（[`crate::prompts::system_prompt`]）の一致で行う。
//! スキーマ強制の経路（native / ツール強制 / プロンプト埋込）によらず、どのコールでも
//! 判別できる唯一の目印だから。

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use harness_core::{
    CompletionRequest, ContentBlock, Phase, ProviderError, StopReason, ToolOutput, Usage,
};
use harness_engine::{
    CompletedToolCall, EngineError, Executor, RawTurn, RawTurnRequest, RawTurnResult,
    ToolCallDecision, TurnVisibility,
};

/// 1コール分の応答。
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// 構造化出力のテキスト（本文だけ）。
    Text(String),
    /// ツールを1件呼んだターン（`parallel_tool_calls:false`なので実機でも最大1件）。
    Tool {
        name: &'static str,
        input: serde_json::Value,
        output: &'static str,
        text: Option<&'static str>,
    },
    /// ストリーム途中でキャンセルされた。
    CancelledMidStream,
    /// 縮退ガードが回復の梯子を使い切った（M21、`plans/DESIGN-COGNITION.md` §11.4）。
    /// `TurnExecutor`の中で既に再送を試み尽くした後の状態を表す。
    Discarded,
    /// プロバイダ呼び出し自体の失敗。
    Error,
    /// プロバイダが「入力が長すぎる」と言って**ストリーム開始前に**失敗した
    /// （`plans/DESIGN-COGNITION.md` §6.6 規則3）。この形の失敗ではツールは1つも
    /// 実行されていないので、呼び出し側は同じフェーズを組み直して再送してよい。
    ContextTooLong,
}

impl Reply {
    pub(crate) fn tool(name: &'static str, input: serde_json::Value, output: &'static str) -> Self {
        Reply::Tool {
            name,
            input,
            output,
            text: None,
        }
    }
}

/// フェーズごとに応答を返すExecutor。**最後の応答は繰り返す**ので、
/// 「モデルが同じ失敗を続けたらループが止まるか」を有限のスクリプトで書ける。
pub(crate) struct PhaseExecutor {
    replies: BTreeMap<Phase, Vec<Reply>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// フェーズごとの消費位置。
    cursor: BTreeMap<Phase, usize>,
    /// 実際に届いたリクエスト（フェーズ・可視性つき）。
    seen: Vec<Seen>,
}

/// 1コールの記録。
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub phase: Option<Phase>,
    pub req: CompletionRequest,
    pub visibility: TurnVisibility,
}

impl PhaseExecutor {
    pub(crate) fn new(replies: impl IntoIterator<Item = (Phase, Vec<Reply>)>) -> Self {
        Self {
            replies: replies.into_iter().collect(),
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// そのフェーズが何回呼ばれたか。
    pub(crate) fn calls_to(&self, phase: Phase) -> usize {
        self.seen()
            .iter()
            .filter(|s| s.phase == Some(phase))
            .count()
    }

    pub(crate) fn phases(&self) -> Vec<Phase> {
        self.seen().iter().filter_map(|s| s.phase).collect()
    }
}

/// システムプロンプトの一致でフェーズを割り出す。
pub(crate) fn phase_of(req: &CompletionRequest) -> Option<Phase> {
    let first = req.system.first()?;
    Phase::ALL
        .into_iter()
        .find(|p| crate::prompts::system_prompt(*p) == first.text)
}

#[async_trait]
impl Executor for PhaseExecutor {
    async fn raw_turn(&self, r: RawTurnRequest) -> Result<RawTurnResult, EngineError> {
        let phase = phase_of(&r.req);
        let reply = {
            let mut state = self.state.lock().unwrap();
            state.seen.push(Seen {
                phase,
                req: r.req.clone(),
                visibility: r.visibility,
            });
            let phase = phase.expect("every assembled call carries a phase system prompt");
            let replies = self
                .replies
                .get(&phase)
                .unwrap_or_else(|| panic!("no scripted reply for {phase}"));
            let cursor = state.cursor.entry(phase).or_default();
            let index = (*cursor).min(replies.len() - 1);
            *cursor += 1;
            replies[index].clone()
        };

        Ok(match reply {
            Reply::Text(text) => RawTurnResult::Completed(turn(text, Vec::new())),
            Reply::Tool {
                name,
                input,
                output,
                text,
            } => {
                let call = CompletedToolCall {
                    id: format!("call_{name}"),
                    name: name.to_string(),
                    input,
                    output: ToolOutput {
                        content: output.to_string(),
                        is_error: false,
                    },
                    decision: ToolCallDecision::Executed,
                };
                RawTurnResult::Completed(turn(text.unwrap_or_default().to_string(), vec![call]))
            }
            Reply::CancelledMidStream => RawTurnResult::CancelledMidStream,
            Reply::Discarded => RawTurnResult::Discarded {
                kind: harness_core::DegenerateKind::ShortPeriodRepeat,
            },
            Reply::Error => {
                return Err(EngineError::Call(ProviderError::Transport {
                    retriable: false,
                }))
            }
            // `Call`（ストリーム開始前）であることが本質。`Stream`にすると
            // 「途中まで届いた」意味になり、縮小再試行の前提が変わる。
            Reply::ContextTooLong => return Err(EngineError::Call(ProviderError::ContextTooLong)),
        })
    }
}

fn turn(text: String, tool_calls: Vec<CompletedToolCall>) -> RawTurn {
    RawTurn {
        content: vec![ContentBlock::Text(text.clone())],
        text,
        stop_reason: if tool_calls.is_empty() {
            StopReason::EndTurn
        } else {
            StopReason::ToolUse
        },
        tool_calls,
        usage: Usage {
            input: 10,
            output: 5,
            cache_read: 0,
            cache_creation: 0,
        },
        cancelled_mid_tool: false,
    }
}
