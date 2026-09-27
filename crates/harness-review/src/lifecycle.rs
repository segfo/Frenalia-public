//! レビューの入口2つ（[`prepare_review`]・[`discard_review_artifacts`]）と、その順序。
//!
//! # 何を信じ、何を信じないか
//!
//! - **セッション ID は差分層のフォルダ名から取る**（ハーネスが名付けた）。
//! - **ワークスペースは呼び出し側から受け取る。** セッションメタ（`.harness-cow-session.json`）は
//!   差分層の中にあり、**子が書ける**（再開したセッションの子も）。メタの `workspace_root` とは
//!   突き合わせるだけで、食い違えば断る。
//! - **後始末はメタの `review_ref` を読まない。** 消す ref の名前はセッション ID から組む
//!   （[`SessionId::review_ref_prefix`]）。メタを信じると、子が `refs/heads/main` と書くだけで
//!   後始末が本物の枝を消す。
//!
//! # 順序
//!
//! [`prepare_review`] は**「レビュー待ち」を先に書く**。この印が持つ意味は「この差分層を
//! 回収するな」（D-82）だけなので、先に書いて途中で落ちても、差分層が残る側へ倒れる
//! （D-82「迷ったら回収しない」）。後に書くと、本物に ref と worktree ができた後・印が付く前の
//! 間に回収が走り得る。失敗したときは、そのセッションの ref と worktree を消し、印を元の値へ戻す。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::assemble::assemble;
use crate::import::{delete_review_refs, fetch_into_review_refs};
use crate::launcher::{GitAt, GitLauncher, RealRepo};
use crate::untrusted::refs::HeadState;
use crate::untrusted::{
    agent_refs, object_inventory, real_git_dir, AgentRefs, DeletedPaths, DiffLayerGit, RealRefs,
};
use crate::worktree::{
    create_review_worktree, registered_worktrees, remove_worktree, worktree_dir_name,
};
use crate::{ImportedRef, ObjectTally, ReviewError, ReviewReport};

/// セッション ID（`session-<英数字と->`）。ref 名とフォルダ名へそのまま入るので、形を縛る。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn parse(s: &str) -> Result<Self, ReviewError> {
        let stem = s.strip_prefix("session-").unwrap_or("");
        let ok = (1..=64).contains(&stem.len())
            && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(ReviewError::Refused(format!(
                "{s:?} is not a session id (`session-` followed by letters, digits and `-`)"
            )))
        }
    }

    /// 差分層のフォルダ名から取る（ハーネスが名付けたもの）。
    pub fn from_diff_layer_dir(diff_layer_dir: &Path) -> Result<Self, ReviewError> {
        let name = diff_layer_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        Self::parse(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// このセッションのレビュー用 ref の接頭辞（末尾 `/` 付き。`session-a` と `session-ab` を
    /// 取り違えないため）。
    pub fn review_ref_prefix(&self) -> String {
        format!("refs/harness/review/{}/", self.0)
    }

    /// エージェントから見えていた名前（`refs/heads/x`）に対応するレビュー用 ref。
    pub(crate) fn review_ref_for(&self, name: &str) -> String {
        format!(
            "{}{}",
            self.review_ref_prefix(),
            name.strip_prefix("refs/").unwrap_or(name)
        )
    }
}

/// [`prepare_review`] の入力。置き場の根は呼び出し側が決めて渡す（テストが実マシンの
/// `%LOCALAPPDATA%` に触れないため。本番は [`crate::review_root_for_workspace`] と `%TEMP%`）。
#[derive(Debug, Clone, Copy)]
pub struct ReviewRequest<'a> {
    pub workspace_root: &'a Path,
    pub diff_layer_dir: &'a Path,
    /// レビュー用 worktree を置く根。
    pub review_root: &'a Path,
    /// 取り込み元の一時リポジトリを置く親。
    pub scratch_parent: &'a Path,
}

/// 差分層の git 済みの内容を本物のレビュー用 ref へ取り込み、レビュー用 worktree を作り、
/// セッションを「レビュー待ち」にする（D-110 (iv) の `harness review` の中身）。
///
/// 同じセッションで2回呼んでよい（前回の ref と worktree を消してから作り直す）。
pub fn prepare_review(
    launcher: &GitLauncher,
    req: &ReviewRequest<'_>,
) -> Result<ReviewReport, ReviewError> {
    let sid = SessionId::from_diff_layer_dir(req.diff_layer_dir)?;
    meta::ensure_not_live(&sid)?;
    let saved = meta::check(req.diff_layer_dir, req.workspace_root, &sid)?;
    let real = open_real_repo(launcher, req.workspace_root)?;
    let real_refs = RealRefs::read(&real.git_dir)?;
    let deleted = DeletedPaths::from_ledger(req.diff_layer_dir);
    let diff_git = DiffLayerGit::open(req.diff_layer_dir)?;

    let (agent, inventory) = match &diff_git {
        Some(dl) => (
            agent_refs(dl, &real_refs, &deleted)?,
            object_inventory(dl, &deleted)?,
        ),
        None => (
            AgentRefs {
                refs: real_refs_as_agent_view(&real_refs),
                skipped: Vec::new(),
                head: real_refs.head().cloned(),
                head_problem: None,
            },
            Default::default(),
        ),
    };

    meta::mark_pending(req.diff_layer_dir, &sid)?;
    let result = (|| {
        remove_artifacts(launcher, &real, &sid, &[req.review_root.to_path_buf()])?;
        build(
            launcher,
            req,
            &sid,
            &real,
            &real_refs,
            diff_git.as_ref(),
            &agent,
            &inventory,
        )
    })();
    match result {
        Ok(report) => Ok(report),
        Err(cause) => {
            let mut leftovers = Vec::new();
            if let Err(e) =
                remove_artifacts(launcher, &real, &sid, &[req.review_root.to_path_buf()])
            {
                leftovers.push(e.to_string());
            }
            if let Err(e) = meta::restore(req.diff_layer_dir, saved) {
                leftovers.push(e.to_string());
            }
            if leftovers.is_empty() {
                Err(cause)
            } else {
                Err(ReviewError::CleanupFailed {
                    cause: Box::new(cause),
                    leftovers,
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build(
    launcher: &GitLauncher,
    req: &ReviewRequest<'_>,
    sid: &SessionId,
    real: &RealRepo,
    real_refs: &RealRefs,
    diff_git: Option<&DiffLayerGit>,
    agent: &AgentRefs,
    inventory: &crate::untrusted::ObjectInventory,
) -> Result<ReviewReport, ReviewError> {
    let mut notes: Vec<String> = real_refs
        .unreadable
        .iter()
        .map(|r| format!("a ref in the real repository could not be read: {r}"))
        .collect();
    if let Some(problem) = &agent.head_problem {
        notes.push(format!("the agent's HEAD could not be read: {problem}"));
    }
    let wanted: BTreeMap<String, String> = agent
        .refs
        .iter()
        .filter(|(name, oid)| real_refs.value(name) != Some(*oid))
        .map(|(n, o)| (n.clone(), o.clone()))
        .collect();
    let deleted_in_session: Vec<String> = real_refs
        .names_in_scope()
        .into_iter()
        .filter(|name| !agent.refs.contains_key(*name))
        .filter(|name| !agent.skipped.iter().any(|s| &s.name == *name))
        .cloned()
        .collect();

    let mut objects = ObjectTally {
        ignored_files: inventory.ignored,
        ignored_samples: inventory.ignored_samples.clone(),
        ..Default::default()
    };
    let mut not_imported = agent.skipped.clone();
    let mut imported = Vec::new();
    if let (Some(dl), false) = (diff_git, wanted.is_empty()) {
        let (source, placed) = assemble(
            launcher,
            real,
            dl,
            inventory,
            &wanted,
            req.scratch_parent,
            &mut objects,
        )?;
        not_imported.extend(placed.unplaced);
        let fetched = fetch_into_review_refs(launcher, real, &source, sid, &placed.placed);
        let closed = source.close();
        let fetched = fetched?;
        if let Err(e) = closed {
            notes.push(format!(
                "the temporary source repository was not removed: {e}"
            ));
        }
        for (name, review_ref) in fetched {
            imported.push(ImportedRef {
                oid: placed.placed[&name].clone(),
                base: real_refs.value(&name).cloned(),
                name,
                review_ref,
            });
        }
    }

    let tip = choose_tip(launcher, real, real_refs, agent, &imported, &mut notes)?;
    let path = req
        .review_root
        .join(worktree_dir_name(req.workspace_root, sid));
    let (worktree, withheld) = create_review_worktree(launcher, real, &path, &tip)?;
    Ok(ReviewReport {
        session_id: sid.as_str().to_string(),
        imported,
        not_imported,
        deleted_in_session,
        agent_head: agent.head.as_ref().map(HeadState::describe),
        objects,
        worktree: worktree.path().to_path_buf(),
        worktree_tip: tip,
        withheld_from_disk: withheld,
        notes,
    })
}

/// worktree に出すコミット: エージェントの `HEAD` の枝を取り込んだならその先端、取り込んで
/// いない（変えていない）枝なら本物の値、それ以外は本物の `HEAD`。
fn choose_tip(
    launcher: &GitLauncher,
    real: &RealRepo,
    real_refs: &RealRefs,
    agent: &AgentRefs,
    imported: &[ImportedRef],
    notes: &mut Vec<String>,
) -> Result<String, ReviewError> {
    match &agent.head {
        Some(HeadState::Branch(branch)) => {
            if let Some(found) = imported.iter().find(|r| &r.name == branch) {
                return Ok(found.oid.clone());
            }
            if let (Some(agent_oid), Some(real_oid)) =
                (agent.refs.get(branch), real_refs.value(branch))
            {
                if agent_oid == real_oid {
                    return Ok(real_oid.clone());
                }
            }
            notes.push(format!(
                "the agent's branch {branch} was not imported; the review worktree shows the \
                 real HEAD instead"
            ));
        }
        Some(HeadState::Detached(oid)) => {
            if object_exists(launcher, real, oid)? {
                return Ok(oid.clone());
            }
            notes.push(format!(
                "the agent's HEAD was detached at {oid}, which is not on an imported branch or \
                 tag (only refs/heads/* and refs/tags/* are imported); it stays in the diff layer"
            ));
        }
        None => {}
    }
    let out = launcher.run(
        GitAt::Real(real),
        &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
        None,
    )?;
    let head = out.stdout_text().trim().to_string();
    if out.success && crate::untrusted::refs::is_oid_hex(&head) {
        Ok(head)
    } else {
        Err(ReviewError::Unsupported(
            "the repository has no commit to check out for review".into(),
        ))
    }
}

fn object_exists(launcher: &GitLauncher, real: &RealRepo, oid: &str) -> Result<bool, ReviewError> {
    let spec = format!("{oid}^{{commit}}");
    Ok(launcher
        .run(GitAt::Real(real), &["cat-file", "-e", &spec], None)?
        .success)
}

/// 差分層に `.git` が無いとき、エージェントから見えていた ref は本物そのもの。
fn real_refs_as_agent_view(real_refs: &RealRefs) -> BTreeMap<String, String> {
    real_refs
        .names_in_scope()
        .into_iter()
        .filter_map(|name| real_refs.value(name).map(|oid| (name.clone(), oid.clone())))
        .collect()
}

/// 本物のリポジトリを開く。ワークスペースのルートの `.git` が本物のディレクトリで、
/// SHA-1・files 形式のときだけ扱う。
fn open_real_repo(launcher: &GitLauncher, workspace_root: &Path) -> Result<RealRepo, ReviewError> {
    if !workspace_root.is_absolute() {
        return Err(ReviewError::Refused(format!(
            "{}: the workspace path must be absolute",
            workspace_root.display()
        )));
    }
    let git_dir = real_git_dir(workspace_root);
    match std::fs::symlink_metadata(&git_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReviewError::Unsupported(format!(
                "{}: the workspace root is not a git repository",
                workspace_root.display()
            )))
        }
        Err(e) => return Err(ReviewError::io(&git_dir, e)),
        Ok(m) if m.file_type().is_symlink() => {
            return Err(ReviewError::Unsupported(format!(
                "{}: .git is a link",
                git_dir.display()
            )))
        }
        Ok(m) if !m.is_dir() => {
            return Err(ReviewError::Unsupported(format!(
                "{}: .git is a file (a linked worktree or a submodule), which is not supported yet",
                git_dir.display()
            )))
        }
        Ok(_) => {}
    }
    let real = RealRepo::new_unchecked(workspace_root.to_path_buf(), git_dir);
    let out = launcher.run_ok(
        GitAt::Real(&real),
        &["rev-parse", "--show-object-format", "--show-ref-format"],
        None,
    )?;
    let text = out.stdout_text();
    let formats: Vec<&str> = text.lines().map(str::trim).collect();
    if formats != ["sha1", "files"] {
        return Err(ReviewError::Unsupported(format!(
            "only SHA-1 repositories with the files ref format are supported (this one: {})",
            formats.join(", ")
        )));
    }
    Ok(real)
}

/// [`discard_review_artifacts`] の結果。
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    pub refs_deleted: Vec<String>,
    pub worktrees_removed: Vec<PathBuf>,
    /// 片付けきれなかったもの。**空でなければ呼び出し側は必ず表示する**。空でないとき、
    /// セッションは「レビュー待ち」のまま残す（差分層を回収させない）。
    pub problems: Vec<String>,
}

/// このセッションのレビュー用 ref と worktree を消し、セッションを「済み」にする。
///
/// 承認（git 対応の `apply`）の後と、破棄（`discard`）のときに呼ぶ（呼ぶ配線は段6の後半）。
/// `review_roots` は worktree を置いた根の候補（本番は [`crate::review_root_candidates`]）。
pub fn discard_review_artifacts(
    launcher: &GitLauncher,
    workspace_root: &Path,
    diff_layer_dir: &Path,
    review_roots: &[PathBuf],
) -> Result<CleanupReport, ReviewError> {
    let sid = SessionId::from_diff_layer_dir(diff_layer_dir)?;
    let real = open_real_repo(launcher, workspace_root)?;
    let mut report = CleanupReport::default();
    match remove_artifacts(launcher, &real, &sid, review_roots) {
        Ok((refs, worktrees)) => {
            report.refs_deleted = refs;
            report.worktrees_removed = worktrees;
        }
        Err(e) => report.problems.push(e.to_string()),
    }
    if report.problems.is_empty() {
        if let Err(e) = meta::mark_settled(diff_layer_dir) {
            report.problems.push(e.to_string());
        }
    }
    Ok(report)
}

/// このセッションの ref と、`roots` の下にあるこのセッションの worktree を消す。
fn remove_artifacts(
    launcher: &GitLauncher,
    real: &RealRepo,
    sid: &SessionId,
    roots: &[PathBuf],
) -> Result<(Vec<String>, Vec<PathBuf>), ReviewError> {
    let refs = delete_review_refs(launcher, real, sid)?;
    let name = worktree_dir_name(&real.work_tree, sid);
    let candidates: Vec<PathBuf> = roots.iter().map(|r| r.join(&name)).collect();
    let mut removed = Vec::new();
    for path in registered_worktrees(launcher, real, &candidates)? {
        remove_worktree(launcher, real, &path)?;
        removed.push(path);
    }
    Ok((refs, removed))
}

/// セッションメタ（Windows の CoW にだけある）との付き合い。
#[cfg(windows)]
mod meta {
    use std::path::Path;

    use harness_sandbox::tier2a::workspace_capability::workspace_key;
    use harness_sandbox::tier2a::workspace_ledger::{
        cow_session_is_live, read_cow_session_meta, set_cow_review_state, CowMetaRead,
        CowReviewState,
    };

    use super::SessionId;
    use crate::ReviewError;

    /// 元の値（失敗したときに戻す先）。
    pub(super) type Saved = Option<CowReviewState>;

    pub(super) fn ensure_not_live(sid: &SessionId) -> Result<(), ReviewError> {
        if cow_session_is_live(sid.as_str()) {
            return Err(ReviewError::Refused(format!(
                "{} is still running (or a process that ran it is still open); review it after it ends",
                sid.as_str()
            )));
        }
        Ok(())
    }

    pub(super) fn check(
        diff_layer_dir: &Path,
        workspace_root: &Path,
        sid: &SessionId,
    ) -> Result<Saved, ReviewError> {
        let meta = match read_cow_session_meta(diff_layer_dir) {
            CowMetaRead::Ok(meta) => meta,
            CowMetaRead::Absent => {
                return Err(ReviewError::Refused(format!(
                    "{}: no CoW session metadata; cannot tell which workspace this diff layer belongs to",
                    diff_layer_dir.display()
                )))
            }
            CowMetaRead::Unreadable(why) => {
                return Err(ReviewError::Refused(format!(
                    "the CoW session metadata is unreadable: {why}"
                )))
            }
        };
        if meta.session_id != sid.as_str() {
            return Err(ReviewError::Refused(format!(
                "the diff layer {} records session id {:?}",
                sid.as_str(),
                meta.session_id
            )));
        }
        if workspace_key(Path::new(&meta.workspace_root)) != workspace_key(workspace_root) {
            return Err(ReviewError::Refused(format!(
                "the diff layer belongs to {}, not to {}",
                meta.workspace_root,
                workspace_root.display()
            )));
        }
        Ok(meta.review)
    }

    pub(super) fn mark_pending(diff_layer_dir: &Path, sid: &SessionId) -> Result<(), ReviewError> {
        set(
            diff_layer_dir,
            Some(CowReviewState::Pending {
                review_ref: sid.review_ref_prefix(),
                fetched_at_unix_secs: now(),
            }),
        )
    }

    pub(super) fn restore(diff_layer_dir: &Path, saved: Saved) -> Result<(), ReviewError> {
        set(diff_layer_dir, saved)
    }

    pub(super) fn mark_settled(diff_layer_dir: &Path) -> Result<(), ReviewError> {
        set(
            diff_layer_dir,
            Some(CowReviewState::Settled {
                settled_at_unix_secs: now(),
            }),
        )
    }

    fn set(diff_layer_dir: &Path, state: Option<CowReviewState>) -> Result<(), ReviewError> {
        set_cow_review_state(diff_layer_dir, state).map_err(ReviewError::Refused)
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Windows 以外には CoW の差分層もセッションメタも無い。
#[cfg(not(windows))]
mod meta {
    use std::path::Path;

    use super::SessionId;
    use crate::ReviewError;

    pub(super) type Saved = ();

    pub(super) fn ensure_not_live(_: &SessionId) -> Result<(), ReviewError> {
        Ok(())
    }
    pub(super) fn check(_: &Path, _: &Path, _: &SessionId) -> Result<Saved, ReviewError> {
        Ok(())
    }
    pub(super) fn mark_pending(_: &Path, _: &SessionId) -> Result<(), ReviewError> {
        Ok(())
    }
    pub(super) fn restore(_: &Path, _: Saved) -> Result<(), ReviewError> {
        Ok(())
    }
    pub(super) fn mark_settled(_: &Path) -> Result<(), ReviewError> {
        Ok(())
    }
}
