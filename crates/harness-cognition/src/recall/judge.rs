//! `Phase::Recall`の1コール: bigram検索でヒットした候補の**要約だけ**を見て、関連性・
//! 再検証要否を判定する。`plans/PLAN-RECALL-MEMORY.md`「読出し経路」2番。

use harness_core::{Phase, ProviderCapabilities, ToolCtx};
use harness_engine::{EventSink, Executor};
use harness_tools::ToolRegistry;
use tokio_util::sync::CancellationToken;

use crate::call::{Conclusion, PhaseRunner};
use crate::context::{ContextAssembler, PhaseInput};
use crate::ledger::LedgerView;
use crate::memory::render::Reduction;
use crate::schema::{RecallOutput, RecallPick};

use super::checkpoint::CheckpointMeta;

/// `Phase::Recall`専用の最小台帳スライス。ゴール文だけを返す（`census::CensusLedger`と
/// 同じ形）。
struct RecallLedger {
    goal_text: String,
}

impl LedgerView for RecallLedger {
    fn render_slice(
        &self,
        phase: Phase,
        _target: Option<&str>,
        _goal: Option<&str>,
        _reduction: Reduction,
    ) -> String {
        match phase {
            Phase::Recall => format!("## 現在のゴール\n\n{}\n", self.goal_text),
            // HIV/Census専用フェーズ。`RecallLedger`はこれらを扱わない。
            Phase::Orient
            | Phase::Hypothesize
            | Phase::Investigate
            | Phase::Distill
            | Phase::Verify
            | Phase::Critic
            | Phase::Decide
            | Phase::Plan
            | Phase::Collect
            | Phase::Join => String::new(),
        }
    }
}

fn validate_recall(out: &RecallOutput) -> Result<(), String> {
    for (i, p) in out.picks.iter().enumerate() {
        if p.relevant && p.id.trim().is_empty() {
            return Err(format!("picks[{i}]: relevant:trueならidが必要。"));
        }
    }
    Ok(())
}

/// 判定コールに要る周辺（`HivContext`/`CensusContext`と同じ形）。
pub struct JudgeContext<'a> {
    pub exec: &'a dyn Executor,
    pub ctx: &'a ToolCtx,
    pub tools: &'a ToolRegistry,
    pub caps: ProviderCapabilities,
    pub events: Option<&'a EventSink>,
    pub cancel: Option<&'a CancellationToken>,
    pub assembler: &'a ContextAssembler,
    pub context_window: u32,
}

/// 判定コールが失敗した理由（1行）。**呼び出し側はこれを`AgentEvent::MemoryRecalled.skipped`
/// へ載せ、ゴールは止めない**（設計変更C、fail-open）。
#[derive(Debug)]
pub struct JudgeError(pub String);

/// 候補の要約だけを1コールに渡し、`(relevant, trust)`の判定を得る。**候補が空なら
/// コールを一切行わない**（読出し経路1番のbigram検索が0件のときにここへ来ない設計と対称）。
pub async fn judge(
    goal_text: &str,
    candidates: &[CheckpointMeta],
    cx: &JudgeContext<'_>,
) -> Result<Vec<RecallPick>, JudgeError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let raw_output = render_candidates(candidates);
    let ledger = RecallLedger {
        goal_text: goal_text.to_string(),
    };
    let runner = PhaseRunner {
        exec: cx.exec,
        ctx: cx.ctx,
        tools: cx.tools,
        caps: cx.caps,
        events: cx.events,
        cancel: cx.cancel,
        assembler: cx.assembler,
        max_schema_retries: 1,
        context_window: cx.context_window,
    };

    let result = runner
        .run::<RecallOutput>(
            Phase::Recall,
            PhaseInput {
                target: None,
                goal: None,
                raw_output: Some(&raw_output),
                repair: None,
            },
            &ledger,
            Conclusion::Required,
            validate_recall,
        )
        .await;

    match result {
        Ok(value) => Ok(value.value.map(|v| v.picks).unwrap_or_default()),
        Err(e) => Err(JudgeError(format!("{e:?}"))),
    }
}

fn render_candidates(candidates: &[CheckpointMeta]) -> String {
    let mut out = String::from("## 過去の記憶の候補（要約のみ、本文は見えない）\n\n");
    for c in candidates {
        out.push_str(&format!(
            "- id={} summary={} tags={}\n",
            c.id,
            c.summary,
            c.tags.join(",")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_candidates_render_a_labelled_header() {
        let s = render_candidates(&[]);
        assert!(s.contains("過去の記憶の候補"));
    }

    #[test]
    fn a_relevant_pick_without_an_id_is_rejected() {
        let out = RecallOutput {
            picks: vec![RecallPick {
                id: "".to_string(),
                relevant: true,
                trust: crate::schema::RecallTrust::Fresh,
            }],
        };
        assert!(validate_recall(&out).is_err());
    }

    #[test]
    fn an_irrelevant_pick_may_omit_the_id() {
        let out = RecallOutput {
            picks: vec![RecallPick {
                id: "".to_string(),
                relevant: false,
                trust: crate::schema::RecallTrust::Ambiguous,
            }],
        };
        assert!(validate_recall(&out).is_ok());
    }
}
