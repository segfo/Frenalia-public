//! workspace capability ACE の準備を、通常の `preflight` と明示的な前払い CLI で共有する。
//!
//! 高コストなのは root へ ACE を置く同期区間ではなく、その ACE を既存子孫へ伝播し、
//! 継承が止まった箇所を検証・救済する背景ジョブである。このモジュールは「宛先SID・モード・
//! 除外範囲・完走判定」を一組にし、入口ごとに少しずつ違う準備処理が増えるのを防ぐ。

//! # モードの型は[`WorkspaceMode`]ひとつである
//!
//! 本モジュールは当初、独自の`WorkspaceAclMode`という同じ意味の列挙を持っていた。
//! D-84（両モードのcapability SID宛ACEを1回で配る）が`workspace_ledger::WorkspaceMode`を
//! 正本として置いたので、**合流時に片方へ寄せた**——同じ概念の型が2つあると、
//! 綴り（台帳に載る`"rwx"`/`"ro"`）と全モード一覧（`ALL`）が静かにずれる。
//!
//! # 配るのは常に全モードぶんである（D-84）
//!
//! 引数の`mode`が決めるのは**このセッションが名乗るSID**であって、**配るACEの本数ではない**。
//! rootへは`WorkspaceMode::ALL`ぶんのACEを1回の書込で置く——モードを切り替えた瞬間に
//! 26万件を払い直す事故を消すためで、費用はゼロだと実測済み（§S15-1）。
//! 安全性は宛先SIDの側が担保する（`ro`のcapability SIDしか積んでいない子は、隣に`rwx`宛の
//! ACEが載っていても書けない。`plans/handoff/fs-boundary-cost/T-1.md`）。

use std::path::{Path, PathBuf};

use crate::tier2a::workspace_ledger::WorkspaceMode;
use crate::win_common::OwnedSid;

use super::{
    grant_workspace_root_aces_fast, protect_harness_control_dir_from_appcontainer,
    top_level_child_missing_aces, workspace_capability_sid, workspace_mode_mask, AppContainerError,
    OwnedAceGrant,
};

/// 利用者へ見せる workspace 準備状態。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePreparationState {
    /// capability 台帳にこの `(workspace, mode)` がまだ無い。
    Unprepared,
    /// このプロセスの共有ジョブが伝播または検証 walk を実行中。
    Preparing,
    /// 完走記録と実 DACL の浅い検算が両方通った。
    Ready,
    /// capability はあるが、未完走・root 入れ替え・実 DACL 不足のいずれか。
    Stale,
    /// このプロセスの共有ジョブが失敗した。
    Failed(String),
}

/// 同期の root 準備を終え、背景ジョブを安全な時点で開始できる状態。
///
/// `preflight` はこの値を保持したまま他の ACL 作業と smoke test を終え、最後に [`start`] を
/// 呼ぶ。明示的な前払い CLI は直ちに `start` する。これにより、通常起動が守ってきた
/// 「workspace への他の DACL 書込を終えてから背景 walk を始める」という順序を崩さない。
pub(crate) struct WorkspacePreparationPlan {
    canonical_workspace: PathBuf,
    mode: WorkspaceMode,
    /// rootへ置いた**全モードぶん**のACE（D-84）。背景ジョブも同じ集合を配る——
    /// 同期区間とジョブで本数が食い違うと、片方のモードだけACEの無いツリーが出来る。
    ace_grants: Vec<OwnedAceGrant>,
    capability_generation: String,
    protect_sids: Vec<OwnedSid>,
    skip: Vec<PathBuf>,
    needs_descendant_fix: bool,
    state_before: WorkspacePreparationState,
    protected_nodes: super::ControlDirProtection,
}

impl WorkspacePreparationPlan {
    pub(crate) fn needs_descendant_fix(&self) -> bool {
        self.needs_descendant_fix
    }

    pub(crate) fn state_before(&self) -> &WorkspacePreparationState {
        &self.state_before
    }

    pub(crate) fn protected_nodes(&self) -> super::ControlDirProtection {
        self.protected_nodes
    }

    /// 背景の伝播＋検証 walk を開始する。同じ capability generation の要求は既存ジョブへ
    /// 合流し、`false`を返す。
    pub(crate) fn start(self) -> bool {
        if !self.needs_descendant_fix {
            return false;
        }
        super::grant_job::start(super::grant_job::GrantJobRequest {
            root: &self.canonical_workspace,
            ace_grants: self.ace_grants,
            protect_sids: self.protect_sids,
            skip: self.skip,
            workspace: &self.canonical_workspace,
            mode: self.mode.as_str(),
            capability_generation: &self.capability_generation,
            // [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] 明示準備CLI（`harness fs
            // prepare-workspace`）は**常に既定のレーン**である。lazyレーンが在る理由は
            // 「コマンドを待たせないこと」で、ここには待たせる相手が居ない——待つのが
            // 目的の入口なので、総処理量が増えるレーンを選ぶ理由が無い。
            lane: super::grant_job::PreparationLane::FullWalk,
        })
    }
}

/// 現在状態を、台帳だけでなく root 識別子と実 DACL の両方から求める。
pub fn workspace_preparation_state(
    workspace: &Path,
    mode: WorkspaceMode,
) -> Result<WorkspacePreparationState, AppContainerError> {
    let canonical = workspace.canonicalize().map_err(|e| {
        AppContainerError::Preflight(format!(
            "failed to canonicalize workspace root {}: {e}",
            workspace.display()
        ))
    })?;
    let mode_name = mode.as_str();

    if let Some(progress) = super::grant_job::progress_for(&canonical, mode_name) {
        if !progress.finished {
            return Ok(WorkspacePreparationState::Preparing);
        }
        if let Some(error) = progress.error {
            return Ok(WorkspacePreparationState::Failed(error));
        }
    }

    if crate::tier2a::workspace_capability::lookup_capability_name(&canonical, mode_name).is_none()
    {
        return Ok(WorkspacePreparationState::Unprepared);
    }

    let capability = workspace_capability_sid(&canonical, mode_name)?;
    let skip = vec![canonical.join(".harness")];
    let verified = crate::tier2a::workspace_capability::tree_is_verified(&canonical, mode_name);
    let actual_missing =
        top_level_child_missing_aces(&canonical, &[capability.as_psid()], &skip).is_some();
    if verified && !actual_missing {
        return Ok(WorkspacePreparationState::Ready);
    }

    use crate::tier2a::workspace_capability::RecordedWorkspacePreparation;
    Ok(
        match crate::tier2a::workspace_capability::recorded_workspace_preparation(
            &canonical, mode_name,
        ) {
            RecordedWorkspacePreparation::Failed(error) => WorkspacePreparationState::Failed(error),
            RecordedWorkspacePreparation::Preparing
                if crate::tier2a::workspace_ledger::live_modes(&canonical).contains(&mode_name) =>
            {
                WorkspacePreparationState::Preparing
            }
            RecordedWorkspacePreparation::Preparing | RecordedWorkspacePreparation::None => {
                WorkspacePreparationState::Stale
            }
        },
    )
}

/// root の即時付与、`.harness` の保護、背景ジョブ要否判定を共有する実体。
pub(crate) fn plan_workspace_preparation(
    canonical_workspace: &Path,
    mode: WorkspaceMode,
    additional_protect_sids: Vec<OwnedSid>,
) -> Result<WorkspacePreparationPlan, AppContainerError> {
    let state_before = workspace_preparation_state(canonical_workspace, mode)?;
    let mode_name = mode.as_str();
    let capability_generation =
        crate::tier2a::workspace_capability::ensure_capability_name(canonical_workspace, mode_name)
            .map_err(AppContainerError::Preflight)?;
    let capability = workspace_capability_sid(canonical_workspace, mode_name)?;

    // [D-84] rootへは**全モードぶん**を1回の書込で置く。台帳エントリも全モードぶん作られる
    // （`ensure_capability_name`）——撤収は台帳を索引にして剥がすので、**配った本数と
    // 引ける本数が同じ**でなければならない（`B-01`／BUG-101: 記録の無いACEは剥がせない）。
    let ace_grants: Vec<OwnedAceGrant> = WorkspaceMode::ALL
        .iter()
        .map(|m| {
            let name = m.as_str();
            crate::tier2a::workspace_capability::ensure_capability_name(canonical_workspace, name)
                .map_err(AppContainerError::Preflight)?;
            Ok(OwnedAceGrant {
                sid: workspace_capability_sid(canonical_workspace, name)?,
                mask: workspace_mode_mask(*m),
            })
        })
        .collect::<Result<_, AppContainerError>>()?;
    grant_workspace_root_aces_fast(
        canonical_workspace,
        &OwnedAceGrant::borrow_all(&ace_grants),
    )?;

    let mut protect_sids = Vec::with_capacity(1 + additional_protect_sids.len());
    protect_sids.push(capability.clone());
    protect_sids.extend(additional_protect_sids);
    let protect_psids: Vec<_> = protect_sids.iter().map(OwnedSid::as_psid).collect();
    let protected_nodes =
        protect_harness_control_dir_from_appcontainer(canonical_workspace, &protect_psids)?;

    let skip = vec![canonical_workspace.join(".harness")];
    // 検算に使う宛先SIDは**このセッションが名乗るモードの1本**でよい（配るのは全モードだが、
    // 「このモードから見えているか」が判定したいことである）。
    let unreachable_child =
        top_level_child_missing_aces(canonical_workspace, &[capability.as_psid()], &skip);
    let needs_descendant_fix =
        !crate::tier2a::workspace_capability::tree_is_verified(canonical_workspace, mode_name)
            || unreachable_child.is_some();

    Ok(WorkspacePreparationPlan {
        canonical_workspace: canonical_workspace.to_path_buf(),
        mode,
        ace_grants,
        capability_generation,
        protect_sids,
        skip,
        needs_descendant_fix,
        state_before,
        protected_nodes,
    })
}

/// `harness fs prepare-workspace` 用の入口。通常起動と同じ root 準備・背景ジョブを使う。
pub fn start_workspace_preparation(
    workspace: &Path,
    mode: WorkspaceMode,
) -> Result<WorkspacePreparationLaunch, AppContainerError> {
    let canonical = workspace.canonicalize().map_err(|e| {
        AppContainerError::Preflight(format!(
            "failed to canonicalize workspace root {}: {e}",
            workspace.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(AppContainerError::Preflight(format!(
            "workspace root is not a directory: {}",
            canonical.display()
        )));
    }

    // 明示準備は「境界を準備できた」と報告する操作なので、RWXでもACLを保持できない媒体を
    // 成功扱いにしない。通常preflightのRO検査と同じ実測ゲートを使う。
    super::preflight::require_persistent_acl_volume("workspace", &canonical)?;
    crate::tier2a::workspace_ledger::begin_workspace_mode(&canonical, mode.as_str())
        .map_err(AppContainerError::Preflight)?;
    crate::tier2a::workspace_ledger::record_workspace_grant(&canonical, mode.as_str());

    let plan = plan_workspace_preparation(&canonical, mode, Vec::new())?;
    let state_before = plan.state_before().clone();
    let protected_nodes = plan.protected_nodes();
    let needed = plan.needs_descendant_fix();
    let job_started = plan.start();
    Ok(WorkspacePreparationLaunch {
        canonical_workspace: canonical,
        mode,
        state_before,
        state: if needed {
            WorkspacePreparationState::Preparing
        } else {
            WorkspacePreparationState::Ready
        },
        job_started,
        protected_nodes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePreparationLaunch {
    pub canonical_workspace: PathBuf,
    pub mode: WorkspaceMode,
    pub state_before: WorkspacePreparationState,
    pub state: WorkspacePreparationState,
    /// `false`かつ`state == Preparing`なら、同じgenerationの既存ジョブへ合流した。
    pub job_started: bool,
    /// [BUG-145] 保護できたノード数と、**そのうち実際に書いた**ノード数。
    pub protected_nodes: super::ControlDirProtection,
}
