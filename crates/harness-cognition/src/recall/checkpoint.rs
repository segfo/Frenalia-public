//! checkpointのデータ型と、台帳からの決定的な変換。`plans/PLAN-RECALL-MEMORY.md`「データモデル」・
//! 「書込み経路」。
//!
//! **書込みはLLMコールを使わない**——要約は`hiv/answer.rs::render`と同じく台帳から決定的に組む。

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::hiv::HivStop;
use crate::memory::types::{HypStatus, SourceKind, SourceRef};
use crate::memory::validity::Freshness;
use crate::memory::WorkingMemory;

/// checkpoint 1件のメタデータ（front matter・`index.jsonl`の1行と同形）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub id: String,
    pub created_at_ms: u64,
    pub tags: Vec<String>,
    pub summary: String,
    pub goal_excerpt: String,
    pub sources: Vec<CheckpointSource>,
}

/// Freshness判定の材料（設計変更④）。`path`はworkspace相対の`/`区切り。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckpointSource {
    pub path: String,
    pub digest: String,
}

/// checkpoint本体（front matter + Markdown本文）。
#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub meta: CheckpointMeta,
    pub body: String,
}

impl Checkpoint {
    /// front matter形式（`---\n{json}\n---\n{body}`）へ直列化する。
    ///
    /// パース・シリアライズは[`Self::to_file_contents`]と[`Self::parse_file_contents`]の
    /// 1関数対に閉じる（`bug-pattern-rules` B-05: 2箇所へ別々に書くと構造がずれる）。
    pub fn to_file_contents(&self) -> String {
        let front = serde_json::to_string_pretty(&self.meta).unwrap_or_default();
        format!("---\n{front}\n---\n{}", self.body)
    }

    /// [`Self::to_file_contents`]の逆変換。
    pub fn parse_file_contents(contents: &str) -> Option<Self> {
        let rest = contents.strip_prefix("---\n")?;
        let end = rest.find("\n---\n")?;
        let front = &rest[..end];
        let body = &rest[end + "\n---\n".len()..];
        let meta: CheckpointMeta = serde_json::from_str(front).ok()?;
        Some(Self {
            meta,
            body: body.to_string(),
        })
    }
}

/// IDを`cp-<epoch millis>-<本文ハッシュ先頭8hex>`で採番する（未決⑤の確定、
/// content-addressed化は見送り）。
fn make_id(created_at_ms: u64, body: &str) -> String {
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    format!("cp-{created_at_ms}-{:08x}", (hasher.finish() as u32))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// HIVの台帳からcheckpointを組む。
///
/// - `HivStop::Decided`は常に書く。`HivStop::BudgetExhausted`はConfirmed仮説が1件以上ある
///   ときだけ書く（確定①）。`Blocked`・`Cancelled`は書かない。
/// - **`SourceKind::Memory`由来の証拠は除外する**（設計変更B）——除外しないと、過去のrecallで
///   注入した記憶がそのまま次のcheckpointへ書き戻され、同じゴールを繰り返すたびに要約が
///   要約を再要約して劣化する自己参照ループになる（`bug-pattern-rules` B-28、BUG-077と同型）。
pub fn from_working_memory(
    goal_text: &str,
    mem: &WorkingMemory,
    stop: &HivStop,
    workspace_root: &Path,
) -> Option<Checkpoint> {
    let confirmed: Vec<_> = mem
        .hypotheses()
        .iter()
        .filter(|h| h.status == HypStatus::Confirmed)
        .collect();

    match stop {
        HivStop::Decided => {}
        HivStop::BudgetExhausted if !confirmed.is_empty() => {}
        HivStop::BudgetExhausted | HivStop::Blocked { .. } | HivStop::Cancelled => return None,
    }

    let mut body = String::new();
    body.push_str("## ゴール\n\n");
    body.push_str(goal_text);
    body.push('\n');

    if !confirmed.is_empty() {
        body.push_str("\n## 確証済みの事実\n\n");
        for h in &confirmed {
            body.push_str(&format!("- {} {}\n", h.id, h.statement));
        }
    }

    if let Some(decision) = mem.decisions().last() {
        body.push_str("\n## 決定\n\n");
        body.push_str(&decision.action);
        body.push('\n');
    }

    let mut sources = Vec::new();
    for h in mem.hypotheses() {
        for eid in h.supporting.iter().chain(h.refuting.iter()) {
            let Some(e) = mem.evidence_by_id(*eid) else {
                continue;
            };
            // 自己参照の遮断（設計変更B）: 過去のrecallが注入した証拠は種にしない。
            if e.source.kind() == SourceKind::Memory {
                continue;
            }
            if let SourceRef::File { path, .. } = &e.source {
                if let Some(digest) = digest_if_under_workspace(workspace_root, path) {
                    sources.push(CheckpointSource {
                        path: path.clone(),
                        digest,
                    });
                }
            }
        }
    }
    sources.sort_by(|a, b| a.path.cmp(&b.path));
    sources.dedup_by(|a, b| a.path == b.path);

    let created_at_ms = now_ms();
    let summary = confirmed
        .first()
        .map(|h| h.statement.clone())
        .unwrap_or_else(|| goal_text.chars().take(80).collect());
    let goal_excerpt: String = goal_text.chars().take(200).collect();
    let id = make_id(created_at_ms, &body);

    Some(Checkpoint {
        meta: CheckpointMeta {
            id,
            created_at_ms,
            tags: Vec::new(),
            summary,
            goal_excerpt,
            sources,
        },
        body,
    })
}

/// Censusの`Join`到達時（`run_census`専用フックのみ、`census`ツール経由では書かない）。
/// `answer`は`census::render_answer`が組んだ最終回答（summary + key_findings）をそのまま
/// 種にする——`CensusOutcome`は`JoinOutput`を個別に保持しないため、二重に持たせない。
pub fn from_census_join(goal_text: &str, answer: &str) -> Checkpoint {
    let mut body = String::new();
    body.push_str("## ゴール\n\n");
    body.push_str(goal_text);
    body.push_str("\n\n## 要約\n\n");
    body.push_str(answer);

    let created_at_ms = now_ms();
    let id = make_id(created_at_ms, &body);
    let goal_excerpt: String = goal_text.chars().take(200).collect();
    let summary: String = answer.chars().take(80).collect();

    Checkpoint {
        meta: CheckpointMeta {
            id,
            created_at_ms,
            tags: Vec::new(),
            summary,
            goal_excerpt,
            sources: Vec::new(),
        },
        body,
    }
}

/// `recall`ツールの`remember`アクション用。ユーザー（またはモデル）が明示的に渡した本文を
/// そのまま記憶する——`WorkingMemory`を経由しないので、自己参照の遮断（設計変更B）は
/// 無関係（そもそも`SourceKind::Memory`証拠を含みようがない）。
pub fn from_manual(text: &str, tags: Vec<String>) -> Checkpoint {
    let created_at_ms = now_ms();
    let id = make_id(created_at_ms, text);
    let summary: String = text.chars().take(80).collect();
    Checkpoint {
        meta: CheckpointMeta {
            id,
            created_at_ms,
            tags,
            summary,
            goal_excerpt: String::new(),
            sources: Vec::new(),
        },
        body: text.to_string(),
    }
}

/// `path`がworkspace配下と確認できたときだけSHA-256を返す（設計変更D: 検証してから使う）。
fn digest_if_under_workspace(workspace_root: &Path, path: &str) -> Option<String> {
    let full = workspace_root.join(path);
    let canonical_root = std::fs::canonicalize(workspace_root).ok()?;
    let canonical_full = std::fs::canonicalize(&full).ok()?;
    if !canonical_full.starts_with(&canonical_root) {
        return None;
    }
    let contents = std::fs::read(&canonical_full).ok()?;
    Some(sha256_hex(&contents))
}

/// checkpointに記録済みのFile出典ダイジェストを再計算して照合する（未決④の確定）。
/// **Freshnessはこの照合が決める**——recall判定コールの`trust`とは独立の、機械的事実。
///
/// - 全一致 → [`Freshness::Fresh`]。
/// - 1件でも不一致・読めない（削除済み等） → [`Freshness::Stale`]。
/// - `meta.sources`が空（＝ダイジェストの記録自体が欠落、手動`remember`・Census由来等） →
///   [`Freshness::Unknown`]（照合材料が無いだけで、古いと決め付けない）。
///
/// **2026-08-07の実測**でこの開発機の記憶23件が全件この形（`sources`空）だった。この状態のまま
/// `Stale`へ倒すと全記憶へ一律に再検証が掛かってしまうため、`Stale`とは区別する
/// （`docs/STATUS.md`認知レイヤー残課題#16）。
///
/// 同期のファイルI/Oを行うので、呼び出し側（`hiv/mod.rs::inject_recall`）が
/// `tokio::task::spawn_blocking`で包む（`bug-pattern-rules` B-31）。
pub(crate) fn freshness_of(workspace_root: &Path, meta: &CheckpointMeta) -> Freshness {
    if meta.sources.is_empty() {
        return Freshness::Unknown;
    }
    let all_match = meta.sources.iter().all(|s| {
        digest_if_under_workspace(workspace_root, &s.path)
            .map(|d| d == s.digest)
            .unwrap_or(false)
    });
    if all_match {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiv::HivStop;
    use crate::memory::types::{Decision, Evidence, Verdict, Verification, VerifyMethod};
    use crate::memory::validity::{Freshness, TrustLevel, Validity};

    fn confirmed_memory() -> WorkingMemory {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("バグを直す", vec![]);
        let h = mem.add_hypothesis(g, "原因はロック順序", vec!["再現条件".into()], 0.8);
        mem.add_evidence(
            |id| Evidence {
                id,
                claim: "逆順にlockを取得".to_string(),
                source: SourceRef::File {
                    path: "src/lib.rs".to_string(),
                    lines: (1, 2),
                },
                validity: Validity::seed(TrustLevel::High, Freshness::Fresh),
                raw_ref: None,
            },
            Some((h, true)),
        );
        mem.record_verification(Verification {
            hyp: h,
            method: VerifyMethod::RunTest,
            verdict: Verdict::Confirms,
            missing: vec![],
            note: "".into(),
        });
        mem.set_hypothesis_status(h, HypStatus::Confirmed);
        mem.add_decision(Decision {
            goal: g,
            action: "lock順を揃える".to_string(),
            based_on: vec![h],
            verify_hint: None,
        });
        mem
    }

    #[test]
    fn decided_always_produces_a_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mem = confirmed_memory();
        let cp = from_working_memory("バグを直す", &mem, &HivStop::Decided, dir.path()).unwrap();
        assert!(cp.body.contains("lock順を揃える"));
        assert!(cp.meta.id.starts_with("cp-"));
    }

    /// 確定①: `BudgetExhausted`はConfirmed仮説が無ければ書かない。
    #[test]
    fn budget_exhausted_without_confirmed_hypotheses_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut mem = WorkingMemory::new();
        mem.add_goal("調査中", vec![]);
        let cp = from_working_memory(
            "調査中",
            &mem,
            &HivStop::BudgetExhausted,
            dir.path(),
        );
        assert!(cp.is_none());
    }

    /// 確定①: `BudgetExhausted`でもConfirmed仮説が1件あれば書く。
    #[test]
    fn budget_exhausted_with_a_confirmed_hypothesis_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let mem = confirmed_memory();
        let cp = from_working_memory("バグを直す", &mem, &HivStop::BudgetExhausted, dir.path());
        assert!(cp.is_some());
    }

    #[test]
    fn blocked_and_cancelled_are_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let mem = confirmed_memory();
        assert!(from_working_memory(
            "g",
            &mem,
            &HivStop::Blocked {
                reason: "x".into()
            },
            dir.path()
        )
        .is_none());
        assert!(from_working_memory("g", &mem, &HivStop::Cancelled, dir.path()).is_none());
    }

    /// front matter往復。
    #[test]
    fn checkpoint_round_trips_through_file_contents() {
        let cp = Checkpoint {
            meta: CheckpointMeta {
                id: "cp-1-aaaaaaaa".to_string(),
                created_at_ms: 1,
                tags: vec!["tag".into()],
                summary: "summary".into(),
                goal_excerpt: "goal".into(),
                sources: vec![CheckpointSource {
                    path: "a.rs".into(),
                    digest: "deadbeef".into(),
                }],
            },
            body: "## body\n\ntext".to_string(),
        };
        let contents = cp.to_file_contents();
        let back = Checkpoint::parse_file_contents(&contents).unwrap();
        assert_eq!(back, cp);
    }

    /// 設計変更B: 自己参照の遮断。過去のrecallが注入した`SourceKind::Memory`証拠は
    /// 次のcheckpointの本文に取り込まれない（同じゴールを2周させると分かる、BUG-077と同型）。
    #[test]
    fn memory_sourced_evidence_is_excluded_from_new_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let mut mem = confirmed_memory();
        let g = mem.goals()[0].id;
        let h2 = mem.add_hypothesis(g, "記憶由来の仮説", vec!["x".into()], 0.5);
        mem.add_evidence(
            |id| Evidence {
                id,
                claim: "過去の記憶: 別の調査で分かったこと".to_string(),
                source: SourceRef::Memory {
                    note_id: "cp-old".to_string(),
                    reviewed: true,
                },
                validity: Validity::seed(TrustLevel::Low, Freshness::Stale),
                raw_ref: None,
            },
            Some((h2, true)),
        );

        let cp = from_working_memory("バグを直す", &mem, &HivStop::Decided, dir.path()).unwrap();
        assert!(!cp.body.contains("過去の記憶: 別の調査で分かったこと"));
        assert!(cp.meta.sources.iter().all(|s| s.path != "cp-old"));
    }

    /// 設計変更D: workspace外のファイルパスはダイジェストを記録しない（検証してから使う）。
    #[test]
    fn sources_outside_the_workspace_are_not_digested() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "x").unwrap();

        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("調べる", vec![]);
        let h = mem.add_hypothesis(g, "h", vec!["p".into()], 0.5);
        mem.add_evidence(
            |id| Evidence {
                id,
                claim: "外部ファイルの内容".to_string(),
                source: SourceRef::File {
                    path: outside
                        .path()
                        .join("secret.txt")
                        .to_string_lossy()
                        .to_string(),
                    lines: (0, 0),
                },
                validity: Validity::seed(TrustLevel::High, Freshness::Fresh),
                raw_ref: None,
            },
            Some((h, true)),
        );
        mem.set_hypothesis_status(h, HypStatus::Confirmed);
        mem.add_decision(Decision {
            goal: g,
            action: "action".to_string(),
            based_on: vec![h],
            verify_hint: None,
        });

        let cp = from_working_memory("調べる", &mem, &HivStop::Decided, dir.path()).unwrap();
        assert!(cp.meta.sources.is_empty());
    }

    /// 未決④: ダイジェスト照合。無改変なら`Fresh`、書換え・削除で`Stale`、
    /// ソース記録自体が欠落（空配列）なら`Unknown`（照合材料が無いだけで「古い」と決め付けない、
    /// `docs/STATUS.md`認知レイヤー残課題#16）。
    #[test]
    fn freshness_of_reflects_the_digest_check() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "original").unwrap();
        let digest = sha256_hex(b"original");
        let meta = CheckpointMeta {
            id: "cp-1-aaaaaaaa".into(),
            created_at_ms: 1,
            tags: vec![],
            summary: "s".into(),
            goal_excerpt: "g".into(),
            sources: vec![CheckpointSource {
                path: "a.rs".into(),
                digest,
            }],
        };
        assert_eq!(freshness_of(dir.path(), &meta), Freshness::Fresh);

        std::fs::write(dir.path().join("a.rs"), "changed").unwrap();
        assert_eq!(freshness_of(dir.path(), &meta), Freshness::Stale);

        std::fs::remove_file(dir.path().join("a.rs")).unwrap();
        assert_eq!(freshness_of(dir.path(), &meta), Freshness::Stale);

        let empty_sources = CheckpointMeta {
            sources: vec![],
            ..meta
        };
        assert_eq!(freshness_of(dir.path(), &empty_sources), Freshness::Unknown);
    }
}
