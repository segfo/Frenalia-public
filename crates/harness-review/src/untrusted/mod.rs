//! 差分層（子が書ける）を読む側。ここから外へ出るのは、厳格に解析した ref と、
//! オブジェクトの置き場の一覧だけである（検算は `objects.rs`、書き出しは `assemble.rs`）。
//!
//! # エージェントから見えていた ref をどう復元するか
//!
//! CoW の中の git は、本体層（本物の `.git`）と差分層を重ねた1つの `.git` を見ていた。
//! 削除はファイルではなく操作台帳の行（`.harness-cow-ops.jsonl` の `delete`）で表される。
//! したがって ref 1本の見え方は、次の順で決まる（git の「ゆるい ref が `packed-refs` に勝つ」
//! と、重ね合わせの「差分層が本体層に勝つ・台帳で消えたものは無い」を合わせたもの）:
//!
//! 1. 台帳でゆるい ref が消されていれば、ゆるい ref は無い
//! 2. 差分層にゆるい ref があればそれ
//! 3. 本物にゆるい ref があればそれ
//! 4. 無ければ `packed-refs`——差分層に `packed-refs` があればそれ、台帳で消されていれば無し、
//!    どちらでもなければ本物の `packed-refs`
//!
//! 本物の側（本体層）は利用者のファイルなので信用して読む。差分層の側は [`refs`] の厳格な
//! 解析だけを通す。

pub(crate) mod objects;
pub(crate) mod refs;
pub(crate) mod walk;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use harness_change_ledger::store::ledger_key_match_form;

use crate::{ReviewError, SkippedRef, IGNORED_SAMPLE_LIMIT};
use objects::ObjectFile;
use refs::{HeadState, RefScope};
pub(crate) use walk::{DiffLayerGit, ReadOutcome};

/// ゆるい ref・`HEAD` の大きさの上限（git が書くのは41バイト）。
const SMALL_FILE_MAX: u64 = 4096;
/// `packed-refs` の大きさの上限。
const PACKED_REFS_MAX: u64 = 64 * 1024 * 1024;

/// 操作台帳が「今は消えている」と言っているパス（`.git` からの相対で問い合わせる）。
pub(crate) struct DeletedPaths(HashSet<String>);

impl DeletedPaths {
    /// 差分層の台帳を1回だけ再生する。
    pub(crate) fn from_ledger(diff_layer_dir: &Path) -> Self {
        Self(
            harness_change_ledger::store::deleted_set(diff_layer_dir)
                .iter()
                .map(|k| ledger_key_match_form(k))
                .collect(),
        )
    }

    fn contains(&self, rel_in_git: &str) -> bool {
        self.0
            .contains(&ledger_key_match_form(&format!(".git/{rel_in_git}")))
    }
}

/// 本物の `.git` の ref（信用してよい側）。
pub(crate) struct RealRefs {
    loose: BTreeMap<String, String>,
    packed: BTreeMap<String, String>,
    head: Option<HeadState>,
    /// 読めなかった本物の ref（symref など）。取り込みの判断からは外し、注意として出す。
    pub(crate) unreadable: Vec<String>,
}

impl RealRefs {
    /// 本物の `.git` から `refs/heads`・`refs/tags`・`packed-refs`・`HEAD` を読む。
    pub(crate) fn read(git_dir: &Path) -> Result<Self, ReviewError> {
        let mut loose = BTreeMap::new();
        let mut unreadable = Vec::new();
        for top in ["refs/heads", "refs/tags"] {
            let mut stack = vec![(git_dir.join(top), top.to_string())];
            while let Some((dir, prefix)) = stack.pop() {
                let entries = match std::fs::read_dir(&dir) {
                    Ok(entries) => entries,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(ReviewError::io(&dir, e)),
                };
                for entry in entries {
                    let entry = entry.map_err(|e| ReviewError::io(&dir, e))?;
                    let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
                    let ft = entry
                        .file_type()
                        .map_err(|e| ReviewError::io(entry.path(), e))?;
                    if ft.is_dir() {
                        stack.push((entry.path(), name));
                    } else if ft.is_file() {
                        let bytes = std::fs::read(entry.path())
                            .map_err(|e| ReviewError::io(entry.path(), e))?;
                        match refs::parse_loose_ref(&bytes) {
                            Ok(oid) => {
                                loose.insert(name, oid);
                            }
                            Err(why) => unreadable.push(format!("{name}: {why}")),
                        }
                    }
                }
            }
        }
        let packed_path = git_dir.join("packed-refs");
        let packed = match std::fs::read(&packed_path) {
            Ok(bytes) => refs::parse_packed_refs(&bytes)
                .map_err(|why| ReviewError::Unsupported(format!("the real packed-refs: {why}")))?
                .into_iter()
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(ReviewError::io(packed_path, e)),
        };
        let head = std::fs::read(git_dir.join("HEAD"))
            .ok()
            .and_then(|b| refs::parse_head(&b).ok());
        Ok(Self {
            loose,
            packed,
            head,
            unreadable,
        })
    }

    /// 本物での今の値（ゆるい ref が `packed-refs` に勝つ）。
    pub(crate) fn value(&self, name: &str) -> Option<&String> {
        self.loose.get(name).or_else(|| self.packed.get(name))
    }

    pub(crate) fn head(&self) -> Option<&HeadState> {
        self.head.as_ref()
    }

    /// `refs/heads/*`・`refs/tags/*` の名前（ゆるい ref と `packed-refs` の和、重複なし）。
    pub(crate) fn names_in_scope(&self) -> Vec<&String> {
        let names: BTreeSet<&String> = self.loose.keys().chain(self.packed.keys()).collect();
        names.into_iter().collect()
    }
}

/// エージェントから見えていた ref。
pub(crate) struct AgentRefs {
    /// `refs/heads/*`・`refs/tags/*` の見え方（取り込み候補）。
    pub(crate) refs: BTreeMap<String, String>,
    /// 取り込まない ref とその理由（形が崩れている・名前が不正・名前空間の外・衝突）。
    pub(crate) skipped: Vec<SkippedRef>,
    pub(crate) head: Option<HeadState>,
    pub(crate) head_problem: Option<String>,
}

/// 差分層と本物を重ねて、エージェントから見えていた ref を復元する（モジュール doc の順）。
pub(crate) fn agent_refs(
    dl: &DiffLayerGit,
    real: &RealRefs,
    deleted: &DeletedPaths,
) -> Result<AgentRefs, ReviewError> {
    let mut skipped = Vec::new();
    let skip = |skipped: &mut Vec<SkippedRef>, name: &str, oid: Option<String>, reason: String| {
        skipped.push(SkippedRef {
            name: name.to_string(),
            oid,
            reason,
        })
    };

    // 差分層のゆるい ref（台帳で消えているものは無いものとして扱う）。
    let (files, links) = dl.walk("refs")?;
    for link in links {
        skip(
            &mut skipped,
            &link,
            None,
            "a link or special file, not read".into(),
        );
    }
    let mut diff_loose: BTreeMap<String, Result<String, String>> = BTreeMap::new();
    for rel in files.into_iter().filter(|rel| !deleted.contains(rel)) {
        let parsed = match dl.read(&rel, SMALL_FILE_MAX)? {
            ReadOutcome::Bytes(bytes) => refs::parse_loose_ref(&bytes),
            ReadOutcome::TooLarge => Err("larger than any ref git writes".into()),
            ReadOutcome::Absent | ReadOutcome::NotAFile => continue,
        };
        diff_loose.insert(rel, parsed);
    }

    // `packed-refs` の見え方。`None` は「本物のものがそのまま見えていた」。
    let agent_packed: Option<BTreeMap<String, String>> = if deleted.contains("packed-refs") {
        Some(BTreeMap::new())
    } else {
        match dl.read("packed-refs", PACKED_REFS_MAX)? {
            ReadOutcome::Bytes(bytes) => Some(
                refs::parse_packed_refs(&bytes)
                    .map_err(|why| {
                        ReviewError::Refused(format!(
                            "the agent's packed-refs is not readable: {why}"
                        ))
                    })?
                    .into_iter()
                    .collect(),
            ),
            ReadOutcome::TooLarge => {
                return Err(ReviewError::Refused(
                    "the agent's packed-refs is larger than the limit".into(),
                ))
            }
            ReadOutcome::Absent => None,
            ReadOutcome::NotAFile => {
                return Err(ReviewError::Refused(
                    "the agent's packed-refs is not a regular file".into(),
                ))
            }
        }
    };

    let mut candidates: BTreeSet<String> = diff_loose.keys().cloned().collect();
    candidates.extend(real.names_in_scope().into_iter().cloned());
    if let Some(packed) = &agent_packed {
        candidates.extend(packed.keys().cloned());
    }

    let mut visible = BTreeMap::new();
    for name in candidates {
        if let Err(why) = refs::check_ref_name(&name) {
            skip(&mut skipped, &name, None, why);
            continue;
        }
        let from_packed = || match &agent_packed {
            Some(packed) => packed.get(&name).cloned(),
            None => real.packed.get(&name).cloned(),
        };
        let value = if deleted.contains(&name) {
            from_packed()
        } else if let Some(parsed) = diff_loose.get(&name) {
            match parsed {
                Ok(oid) => Some(oid.clone()),
                Err(why) => {
                    skip(&mut skipped, &name, None, why.clone());
                    continue;
                }
            }
        } else if let Some(oid) = real.loose.get(&name) {
            Some(oid.clone())
        } else {
            from_packed()
        };
        let Some(oid) = value else { continue };
        match refs::ref_scope(&name) {
            RefScope::Heads | RefScope::Tags => {
                visible.insert(name, oid);
            }
            RefScope::Other => {
                // 本物に元からあるもの（`refs/remotes` 等）で変わっていないものは黙って流す。
                if real.value(&name) != Some(&oid) {
                    skip(
                        &mut skipped,
                        &name,
                        Some(oid),
                        "outside refs/heads and refs/tags; not imported (D-110 vi)".into(),
                    );
                }
            }
        }
    }

    for name in refs::find_ambiguous_names(visible.keys().map(String::as_str)) {
        let oid = visible.remove(&name);
        skip(
            &mut skipped,
            &name,
            oid,
            "collides with another ref on a case-insensitive file system".into(),
        );
    }

    let (head, head_problem) = if deleted.contains("HEAD") {
        (None, Some("HEAD was deleted in the session".to_string()))
    } else {
        match dl.read("HEAD", SMALL_FILE_MAX)? {
            ReadOutcome::Bytes(bytes) => match refs::parse_head(&bytes) {
                Ok(head) => (Some(head), None),
                Err(why) => (None, Some(why)),
            },
            ReadOutcome::Absent => (real.head().cloned(), None),
            ReadOutcome::TooLarge | ReadOutcome::NotAFile => (
                None,
                Some("HEAD in the diff layer is not a small regular file".into()),
            ),
        }
    };

    Ok(AgentRefs {
        refs: visible,
        skipped,
        head,
        head_problem,
    })
}

/// 差分層の `objects/` にあったものの一覧。
#[derive(Default)]
pub(crate) struct ObjectInventory {
    /// （オブジェクト名, `.git` からの相対パス）
    pub(crate) loose: Vec<(String, String)>,
    /// （`pack-<40桁>`, `.git` からの相対パス）
    pub(crate) packs: Vec<(String, String)>,
    pub(crate) ignored: usize,
    pub(crate) ignored_samples: Vec<String>,
}

pub(crate) fn object_inventory(
    dl: &DiffLayerGit,
    deleted: &DeletedPaths,
) -> Result<ObjectInventory, ReviewError> {
    let (files, links) = dl.walk("objects")?;
    let mut inventory = ObjectInventory::default();
    let ignore = |inventory: &mut ObjectInventory, rel: String| {
        inventory.ignored += 1;
        if inventory.ignored_samples.len() < IGNORED_SAMPLE_LIMIT {
            inventory.ignored_samples.push(rel);
        }
    };
    for rel in links {
        ignore(&mut inventory, rel);
    }
    for rel in files.into_iter().filter(|rel| !deleted.contains(rel)) {
        let within = rel.strip_prefix("objects/").unwrap_or(&rel);
        match objects::classify_objects_path(within) {
            ObjectFile::Loose { oid } => inventory.loose.push((oid, rel)),
            ObjectFile::Pack { stem } => inventory.packs.push((stem, rel)),
            ObjectFile::Ignored => ignore(&mut inventory, rel),
        }
    }
    Ok(inventory)
}

/// 本物の `.git` の場所を、ワークスペースから求める。
pub(crate) fn real_git_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".git")
}
