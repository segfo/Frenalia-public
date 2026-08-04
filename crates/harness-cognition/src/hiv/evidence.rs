//! 観測（ツール呼び出しの顛末）を証拠へ変える経路。
//! `plans/DESIGN-COGNITION.md` §4.1（`SourceRef`）・§5（生出力の退避）・§6.2（蒸留）。
//!
//! # 出典はハーネスが決める（モデルの自己申告を使わない）
//!
//! Distillの出力スキーマにも`source`フィールドがあるが、台帳へ載せる[`SourceRef`]は
//! **ハーネスが観測した事実**（どのツールをどの引数で呼び、何が返ったか）から作る。
//! §4.3の接地必須ルールは「Web/ModelPriorだけの主張を`Confirmed`にしない」という
//! 機械チェックで、その判定材料が自己申告だと、モデルが`source`に`"src/lib.rs"`と
//! 書くだけでチェックを通せてしまう。

use harness_core::RiskClass;
use harness_engine::{CompletedToolCall, EventSink, ToolCallDecision};

use crate::memory::types::{Evidence, HypId, RawRef, SourceRef};
use crate::memory::WorkingMemory;
use crate::schema::{DistillOutput, EvidenceRelation};
use crate::scratch::ScratchStore;

/// 1回のツール呼び出しから得た観測。
#[derive(Debug, Clone)]
pub(crate) struct Observation {
    /// ハーネスが割り出した出典。
    pub source: SourceRef,
    /// 蒸留コールへ渡す本文（予算まで機械的に切詰め済み）。
    pub excerpt: String,
    /// scratchへ退避できた場合のポインタ。退避に失敗しても観測自体は捨てない。
    pub raw_ref: Option<RawRef>,
}

/// そのターンで得た観測を取り出す。
///
/// **実行されなかった呼び出し（拒否・未知ツール・引数不正・キャンセル）は観測にしない。**
/// それらの`output`はワークスペースの状態ではなくハーネスのポリシーの説明であり、
/// 事実として蒸留すると「permission denied と書かれていた」が証拠として台帳に載る。
pub(crate) fn observations(
    calls: &[CompletedToolCall],
    risk_of: impl Fn(&CompletedToolCall) -> Option<RiskClass>,
    scratch: Option<&ScratchStore>,
    max_chars: usize,
) -> Vec<Observation> {
    calls
        .iter()
        .filter(|c| c.decision == ToolCallDecision::Executed)
        .map(|call| {
            let source = source_ref_for(call, risk_of(call));
            let raw_ref = scratch.and_then(|s| s.put_raw(&call.id, &call.output.content).ok());
            // scratchへ書けていれば読み戻して切詰める（§6.3のzoom）。書けていなければ
            // 手元の内容をそのまま切詰める——退避の失敗で調査を止める理由は無い。
            let excerpt = raw_ref
                .as_ref()
                .and_then(|r| scratch.and_then(|s| s.zoom(r, max_chars).ok()))
                .unwrap_or_else(|| {
                    harness_core::text::truncate_head_tail(&call.output.content, max_chars)
                });
            Observation {
                source,
                excerpt,
                raw_ref,
            }
        })
        .collect()
}

/// ツール呼び出しから出典を決める。
///
/// ツール名の固定表ではなく`RiskClass`で分けるのは、M16のSourceBroker（情報源カタログ）が
/// ここを置き換えるまでの繋ぎとして、read-onlyツールが増えても壊れないようにするため。
/// 未知のツール名でも「何を触る種類の操作だったか」は`RiskClass`が持っている。
fn source_ref_for(call: &CompletedToolCall, risk: Option<RiskClass>) -> SourceRef {
    let input = &call.input;
    match risk {
        Some(RiskClass::Network) => SourceRef::Web {
            url: string_field(input, &["url"]).unwrap_or_else(|| call.name.clone()),
            // 鮮度評価（§4.3 `Freshness`）はM16。ここでは「いつ取ったか」だけ残す。
            fetched_at: unix_seconds(),
        },
        Some(RiskClass::Exec) => SourceRef::Shell {
            cmd: string_field(input, &["command", "cmd"]).unwrap_or_else(|| call.name.clone()),
            // `ToolOutput`は終了コードを持たない（`is_error`だけ）。観測として意味があるのは
            // 「失敗したか」なので、そこだけを1/0で写す。
            exit: i32::from(call.output.is_error),
        },
        // ReadOnly/Write/未知はいずれもワークスペースのファイルに対する観測として扱う。
        _ => SourceRef::File {
            path: string_field(input, &["path", "file", "pattern", "glob"])
                .unwrap_or_else(|| call.name.clone()),
            lines: line_range(input),
        },
    }
}

fn string_field(input: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| input.get(*k).and_then(|v| v.as_str()))
        .map(str::to_string)
}

/// `read_file`の`offset`/`limit`があれば行範囲にする。無ければ`(0, 0)`＝ファイル全体
/// （`SourceRef::describe`は範囲を出さない）。
fn line_range(input: &serde_json::Value) -> (u32, u32) {
    let offset = input.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = input.get("limit").and_then(|v| v.as_u64());
    match (offset, limit) {
        (0, None) => (0, 0),
        (start, None) => (start as u32, 0),
        (start, Some(len)) => {
            let start = start.max(1);
            (start as u32, (start + len.saturating_sub(1)) as u32)
        }
    }
}

fn unix_seconds() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// 蒸留結果を台帳へ載せ、`EvidenceAdded`を発行する。戻り値は追加できた件数。
pub(crate) fn record_distilled(
    mem: &mut WorkingMemory,
    target: HypId,
    observation: &Observation,
    out: DistillOutput,
    events: Option<&EventSink>,
) -> usize {
    let mut added = 0;
    for distilled in out.evidence {
        if distilled.claim.trim().is_empty() {
            continue;
        }
        let source = observation.source.clone();
        let raw_ref = observation.raw_ref.clone();
        let claim = distilled.claim.clone();
        let link = match distilled.relation {
            EvidenceRelation::Supports => Some((target, true)),
            EvidenceRelation::Refutes => Some((target, false)),
            // どちらでもない観測は仮説へ結び付けずに積む（Orient相当の状況把握）。
            EvidenceRelation::Neutral => None,
        };
        let id = mem.add_evidence(
            move |id| Evidence {
                id,
                claim,
                source,
                raw_ref,
            },
            link,
        );
        harness_engine::emit_event(
            events,
            harness_core::AgentEvent::EvidenceAdded {
                id: id.label(),
                claim: distilled.claim,
                source: observation.source.describe(),
            },
        );
        added += 1;
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::ToolOutput;

    fn call(name: &str, input: serde_json::Value, content: &str) -> CompletedToolCall {
        CompletedToolCall {
            id: format!("call_{name}"),
            name: name.to_string(),
            input,
            output: ToolOutput {
                content: content.to_string(),
                is_error: false,
            },
            decision: ToolCallDecision::Executed,
        }
    }

    #[test]
    fn read_only_calls_become_file_sources() {
        let c = call(
            "read_file",
            serde_json::json!({ "path": "src/lib.rs" }),
            "x",
        );
        assert_eq!(
            source_ref_for(&c, Some(RiskClass::ReadOnly)),
            SourceRef::File {
                path: "src/lib.rs".to_string(),
                lines: (0, 0)
            }
        );
    }

    #[test]
    fn offset_and_limit_become_the_line_range() {
        let c = call(
            "read_file",
            serde_json::json!({ "path": "a.rs", "offset": 10, "limit": 5 }),
            "x",
        );
        assert_eq!(
            source_ref_for(&c, Some(RiskClass::ReadOnly)),
            SourceRef::File {
                path: "a.rs".to_string(),
                lines: (10, 14)
            }
        );
    }

    #[test]
    fn exec_calls_become_shell_sources_carrying_the_failure_bit() {
        let mut c = call(
            "run_shell",
            serde_json::json!({ "command": "cargo test" }),
            "failures: 1",
        );
        c.output.is_error = true;
        assert_eq!(
            source_ref_for(&c, Some(RiskClass::Exec)),
            SourceRef::Shell {
                cmd: "cargo test".to_string(),
                exit: 1
            }
        );
    }

    #[test]
    fn network_calls_become_web_sources() {
        let c = call(
            "web_fetch",
            serde_json::json!({ "url": "https://example.com" }),
            "x",
        );
        let SourceRef::Web { url, .. } = source_ref_for(&c, Some(RiskClass::Network)) else {
            panic!("network tools must be recorded as web sources");
        };
        assert_eq!(url, "https://example.com");
    }

    /// **実行されなかった呼び出しは観測にしない**（拒否理由が事実として台帳に載るのを防ぐ）。
    #[test]
    fn calls_that_never_ran_are_not_observations() {
        let mut denied = call(
            "run_shell",
            serde_json::json!({}),
            "permission denied by policy",
        );
        denied.decision = ToolCallDecision::DeniedByPolicy;
        let mut cancelled = call("read_file", serde_json::json!({}), "cancelled by user");
        cancelled.decision = ToolCallDecision::CancelledBeforeStart;
        let executed = call("read_file", serde_json::json!({ "path": "a" }), "content");

        let obs = observations(
            &[denied, cancelled, executed],
            |_| Some(RiskClass::ReadOnly),
            None,
            1_000,
        );
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].excerpt, "content");
    }

    /// scratchがあれば生出力はそこへ落ち、台帳へは`RawRef`だけが残る（§5）。
    #[test]
    fn raw_output_is_stashed_in_scratch_and_only_the_pointer_survives() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = ScratchStore::open(dir.path()).unwrap();
        let big = "y".repeat(10_000);
        let obs = observations(
            &[call("read_file", serde_json::json!({ "path": "a" }), &big)],
            |_| Some(RiskClass::ReadOnly),
            Some(&scratch),
            200,
        );

        let raw_ref = obs[0].raw_ref.as_ref().unwrap();
        assert_eq!(raw_ref.chars, 10_000);
        assert_eq!(scratch.read_raw(raw_ref).unwrap().chars().count(), 10_000);
        // 蒸留コールへ渡るのは切詰め済みの断片だけ。
        assert!(obs[0].excerpt.chars().count() < 300);
    }

    /// scratchが開けなくても観測は失われない（退避の失敗で調査を止めない）。
    #[test]
    fn observations_survive_without_a_scratch_store() {
        let obs = observations(
            &[call(
                "read_file",
                serde_json::json!({ "path": "a" }),
                "content",
            )],
            |_| Some(RiskClass::ReadOnly),
            None,
            1_000,
        );
        assert_eq!(obs[0].excerpt, "content");
        assert!(obs[0].raw_ref.is_none());
    }

    #[test]
    fn relation_decides_whether_the_evidence_supports_or_refutes() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec!["Yが見える".into()], 0.5);
        let obs = Observation {
            source: SourceRef::File {
                path: "src/lib.rs".to_string(),
                lines: (0, 0),
            },
            excerpt: "raw".to_string(),
            raw_ref: None,
        };

        let added = record_distilled(
            &mut mem,
            h,
            &obs,
            DistillOutput {
                evidence: vec![
                    crate::schema::DistilledEvidence {
                        claim: "支持する事実".to_string(),
                        relation: EvidenceRelation::Supports,
                        source: "モデルの自己申告は使われない".to_string(),
                    },
                    crate::schema::DistilledEvidence {
                        claim: "反証する事実".to_string(),
                        relation: EvidenceRelation::Refutes,
                        source: "https://evil.example".to_string(),
                    },
                    crate::schema::DistilledEvidence {
                        claim: "無関係な事実".to_string(),
                        relation: EvidenceRelation::Neutral,
                        source: String::new(),
                    },
                ],
            },
            None,
        );

        assert_eq!(added, 3);
        let hyp = mem.hypothesis(h).unwrap();
        assert_eq!(hyp.supporting.len(), 1);
        assert_eq!(hyp.refuting.len(), 1);
        // 出典はハーネスの観測が正——モデルが書いたURLは台帳に入らない。
        for e in mem.evidence() {
            assert!(matches!(e.source, SourceRef::File { .. }), "{:?}", e.source);
        }
    }
}
