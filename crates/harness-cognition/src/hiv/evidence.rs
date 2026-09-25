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

use harness_core::{PermissionSubject, RiskClass};
use harness_engine::{CompletedToolCall, EventSink, ToolCallDecision};

use crate::hiv::parse::resolve_contradicts;
use crate::memory::types::{Evidence, HypId, RawRef, SourceRef};
use crate::memory::validity::Validity;
use crate::memory::WorkingMemory;
use crate::schema::{DistillOutput, EvidenceRelation};
use crate::scratch::ScratchStore;
use crate::source::{split_mcp_tool_name, SourceCatalog};

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
/// MCPだけは**ツール名の名前空間**（`crate::source::MCP_PREFIX`、`plans/DESIGN-MCP.md` §5）で判定する
/// ——MCPサーバのツールは`RiskClass`だけ見れば内蔵ツールと区別が付かないが、§4.2の接地優先順位は
/// 「ローカル一次証拠 → MCPで裏取り」という**出所の違い**を要求しており、そこを潰せない。
/// それ以外はツール名の固定表ではなく`RiskClass`で分ける（read-onlyツールが増えても壊れない）。
fn source_ref_for(call: &CompletedToolCall, risk: Option<RiskClass>) -> SourceRef {
    let input = &call.input;
    if let Some((server, tool)) = split_mcp_tool_name(&call.name) {
        return SourceRef::Mcp {
            server: server.to_string(),
            tool: tool.to_string(),
            args_digest: args_digest(input),
        };
    }
    match risk {
        Some(RiskClass::Network) => SourceRef::Web {
            url: string_field(input, &["url"]).unwrap_or_else(|| call.name.clone()),
            // 鮮度評価（§4.3 `Freshness`）はM16。ここでは「いつ取ったか」だけ残す。
            fetched_at: unix_seconds(),
        },
        Some(RiskClass::Exec) => SourceRef::Shell {
            cmd: executed_command(call),
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

/// 実行された呼び出しを1行にする。**判定器が見た材料から作る**（`CompletedToolCall::subject`）。
///
/// # なぜ入力のキーを探さないのか
///
/// 以前はここで `{"command": …}` というキーを探していた。`run_shell` にはそのキーがあるが、
/// **`run_program` には無い**（`{program, args}` である）ので、どの `run_program` 呼び出しも
/// `run_program` という同じ文字列に潰れ、`git status` と `git push --force` が**区別できなかった**。
/// しかも `SourceRef::Shell` は接地の証拠として数えられるので、中身の無い出典が主張を
/// `Confirmed` まで押し上げうる。これは BUG-164（判定に渡す値を入力のキーで選ぶ）と同じ形で、
/// 本番に残っていた最後の1箇所である。
///
/// **この文字列は記憶へ入り、Recall 経由で将来の入力へ戻りうる**（`bug-pattern-rules` B-28）。
/// 載るのはモデルが自分で書いたプログラム名と引数で、会話に既にあるものなので新しい環は作らない。
fn executed_command(call: &CompletedToolCall) -> String {
    match &call.subject {
        Some(PermissionSubject::Program(p)) => p.describe(),
        Some(PermissionSubject::Command(c)) => harness_core::escape_for_display(&c.line),
        // 材料が無い（実行まで進まなかった・材料を持たないツール）ときだけ道具の名前へ落とす。
        _ => call.name.clone(),
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

/// MCP呼び出しの引数のダイジェスト（`SourceRef::Mcp.args_digest`）。
///
/// 用途は監査と「同じ問い合わせをしたか」の判定だけなので、暗号学的強度は要らない。
/// FNV-1aを直に書くのは、ハッシュ依存クレートを増やさずに**バージョンを跨いで安定**させる
/// ため（`DefaultHasher`は標準ライブラリの版で値が変わりうる）。`serde_json::Value`の
/// オブジェクトはキー順が正規化されているので、同じ引数からは必ず同じ文字列になる。
fn args_digest(input: &serde_json::Value) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in input.to_string().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

fn unix_seconds() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

/// 蒸留結果を台帳へ載せ、`EvidenceAdded`を発行する。戻り値は追加できた件数。
///
/// `trust`/`freshness`はカタログが決める（§4.3「信頼度は情報源の宣言 + 種別から決める」）。
/// `grade`は台帳が引き直すので、ここでは触らない。
pub(crate) fn record_distilled(
    mem: &mut WorkingMemory,
    target: HypId,
    observation: &Observation,
    out: DistillOutput,
    catalog: &SourceCatalog,
    events: Option<&EventSink>,
) -> usize {
    let mut added = 0;
    for distilled in out.evidence {
        if distilled.claim.trim().is_empty() {
            continue;
        }
        // 矛盾の申告は**この証拠を積む前**の台帳に対して解決する。積んだ後に解決すると
        // 「自分自身と矛盾する」という申告を弾く根拠がIDの一致だけになり、脆くなる。
        let known: Vec<_> = mem.evidence().iter().map(|e| e.id).collect();
        let conflicts = resolve_contradicts(&distilled.contradicts, &known, None);

        let source = observation.source.clone();
        let raw_ref = observation.raw_ref.clone();
        let claim = distilled.claim.clone();
        let (trust, freshness) = catalog.validity_seed(&observation.source);
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
                validity: Validity::seed(trust, freshness),
                raw_ref,
            },
            link,
        );
        for other in conflicts {
            mem.record_conflict(id, other);
        }
        let validity = mem
            .evidence_by_id(id)
            .map(|e| e.validity.describe(e.source.kind()))
            .unwrap_or_default();
        harness_engine::emit_event(
            events,
            harness_core::AgentEvent::EvidenceAdded {
                id: id.label(),
                claim: distilled.claim,
                source: observation.source.describe(),
                validity,
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

    fn distilled(
        claim: &str,
        relation: EvidenceRelation,
        contradicts: &[&str],
    ) -> crate::schema::DistilledEvidence {
        crate::schema::DistilledEvidence {
            claim: claim.to_string(),
            relation,
            // モデルの自己申告する`source`は台帳へ入らない（このモジュールのdoc）。
            source: "https://evil.example".to_string(),
            contradicts: contradicts.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn call(name: &str, input: serde_json::Value, content: &str) -> CompletedToolCall {
        with_subject(name, input, content, None)
    }

    fn with_subject(
        name: &str,
        input: serde_json::Value,
        content: &str,
        subject: Option<PermissionSubject>,
    ) -> CompletedToolCall {
        CompletedToolCall {
            id: format!("call_{name}"),
            name: name.to_string(),
            input,
            output: ToolOutput {
                content: content.to_string(),
                is_error: false,
            },
            decision: ToolCallDecision::Executed,
            subject,
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

    /// `run_program` の出典は**プログラム名と引数**から作る（判定器が見た材料そのもの）。
    ///
    /// 以前は入力の `command` というキーを探していたので、`run_program` にそのキーが無く、
    /// **どの呼び出しも同じ文字列に潰れていた**——`git status` と `git push --force` が
    /// 区別できず、しかもこの出典は接地の証拠として数えられる。
    #[test]
    fn run_program_sources_carry_the_program_and_its_arguments() {
        let prog = |args: &[&str]| {
            let subject = PermissionSubject::Program(harness_core::ProgramSubject::plain(
                "git",
                args.iter().map(|a| a.to_string()).collect(),
            ));
            with_subject(
                "run_program",
                serde_json::json!({ "program": "git", "args": args }),
                "ok",
                Some(subject),
            )
        };

        let status = source_ref_for(&prog(&["status"]), Some(RiskClass::Exec));
        let force = source_ref_for(&prog(&["push", "--force"]), Some(RiskClass::Exec));
        assert_eq!(
            status,
            SourceRef::Shell {
                cmd: "git status".to_string(),
                exit: 0
            }
        );
        assert_ne!(status, force, "違う呼び出しが同じ出典になっている");

        // 材料が無い呼び出しは道具の名前へ落ちる（対照。ここだけは以前と同じ）。
        let bare = source_ref_for(
            &call("run_program", serde_json::json!({}), "ok"),
            Some(RiskClass::Exec),
        );
        assert_eq!(
            bare,
            SourceRef::Shell {
                cmd: "run_program".to_string(),
                exit: 0
            }
        );
    }

    #[test]
    fn exec_calls_become_shell_sources_carrying_the_failure_bit() {
        let mut c = with_subject(
            "run_shell",
            serde_json::json!({ "command": "cargo test" }),
            "failures: 1",
            Some(PermissionSubject::Command(
                harness_core::CommandSubject::line_only("cargo test"),
            )),
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

    /// **M16**: MCPツールは`RiskClass`ではなく**名前空間**で判定する。
    /// MCPの多くは`RiskClass::Network`だが、§4.2の接地優先順位はwebとMCPを区別する。
    #[test]
    fn mcp_namespaced_tools_become_mcp_sources_regardless_of_their_risk_class() {
        let c = call(
            "mcp__company-docs__search_docs",
            serde_json::json!({ "q": "run_shell" }),
            "spec says powershell",
        );
        for risk in [Some(RiskClass::Network), Some(RiskClass::ReadOnly), None] {
            let SourceRef::Mcp { server, tool, .. } = source_ref_for(&c, risk) else {
                panic!("mcp/ tools must be recorded as MCP sources (risk={risk:?})");
            };
            assert_eq!(
                (server.as_str(), tool.as_str()),
                ("company-docs", "search_docs")
            );
        }
    }

    /// 引数ダイジェストは同じ引数から同じ値、違う引数から違う値になる（監査・同一性判定用）。
    #[test]
    fn the_args_digest_is_stable_and_discriminating() {
        let a = serde_json::json!({ "q": "run_shell", "limit": 5 });
        let b = serde_json::json!({ "limit": 5, "q": "run_shell" });
        let c = serde_json::json!({ "q": "read_file", "limit": 5 });
        // `serde_json::Value`のオブジェクトはキー順が正規化されるので、書き順は影響しない。
        assert_eq!(args_digest(&a), args_digest(&b));
        assert_ne!(args_digest(&a), args_digest(&c));
        assert_eq!(args_digest(&a).len(), 16);
    }

    /// `mcp`で始まるだけの名前（`mcp_helper`等）を誤ってMCP扱いしない。
    #[test]
    fn a_tool_merely_starting_with_mcp_is_not_an_mcp_source() {
        let c = call("mcp_helper", serde_json::json!({ "path": "a.rs" }), "x");
        assert!(matches!(
            source_ref_for(&c, Some(RiskClass::ReadOnly)),
            SourceRef::File { .. }
        ));
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
                    distilled("支持する事実", EvidenceRelation::Supports, &[]),
                    distilled("反証する事実", EvidenceRelation::Refutes, &[]),
                    distilled("無関係な事実", EvidenceRelation::Neutral, &[]),
                ],
            },
            &SourceCatalog::with_builtin_defaults(),
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

    /// **§4.3の矛盾検出**: Distillが挙げたE番号のうち実在するものだけが台帳へ記録される。
    #[test]
    fn declared_contradictions_are_recorded_only_for_evidence_that_exists() {
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
        let catalog = SourceCatalog::with_builtin_defaults();

        record_distilled(
            &mut mem,
            h,
            &obs,
            DistillOutput {
                evidence: vec![distilled("Aと書いてある", EvidenceRelation::Supports, &[])],
            },
            &catalog,
            None,
        );
        let first = mem.evidence()[0].id;

        record_distilled(
            &mut mem,
            h,
            &obs,
            DistillOutput {
                evidence: vec![distilled(
                    "Bと書いてある",
                    EvidenceRelation::Supports,
                    // 実在するものと、存在しないものを混ぜる。
                    &[&first.label(), "E99"],
                )],
            },
            &catalog,
            None,
        );
        let second = mem.evidence()[1].id;

        assert_eq!(
            mem.evidence_by_id(second).unwrap().validity.conflicts,
            vec![first],
            "実在するE番号だけが矛盾として記録される"
        );
        assert_eq!(
            mem.evidence_by_id(first).unwrap().validity.conflicts,
            vec![second],
            "矛盾は双方向に記録される"
        );
    }

    /// `trust`/`freshness`はカタログが決める（§4.3「情報源の宣言 + 種別から決める」）。
    #[test]
    fn validity_is_seeded_from_the_source_catalog() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はX", vec![], 0.5);
        let obs = Observation {
            source: SourceRef::Web {
                url: "https://example.com".to_string(),
                fetched_at: "0".to_string(),
            },
            excerpt: "raw".to_string(),
            raw_ref: None,
        };

        record_distilled(
            &mut mem,
            h,
            &obs,
            DistillOutput {
                evidence: vec![distilled("webの主張", EvidenceRelation::Supports, &[])],
            },
            &SourceCatalog::with_builtin_defaults(),
            None,
        );

        let v = &mem.evidence()[0].validity;
        assert_eq!(v.trust, crate::memory::validity::TrustLevel::Low);
        // webは接地種別ではないので、単独では確証の根拠にならない。
        assert_eq!(v.grade, crate::memory::validity::Grade::Unverified);
    }
}
