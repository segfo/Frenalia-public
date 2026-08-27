//! workspace capability ACE の準備を、通常の `preflight` と明示的な前払い CLI で共有する。
//!
//! 高コストなのは root へ ACE を置く同期区間ではなく、その ACE を既存子孫へ伝播し、
//! 継承が止まった箇所を検証・救済する背景ジョブである。このモジュールは「主体・モード・
//! 除外範囲・完走判定」を一組にし、入口ごとに少しずつ違う準備処理が増えるのを防ぐ。

use std::path::{Path, PathBuf};

use crate::win_common::OwnedSid;

use super::{
    fs_access_mask, grant_workspace_root_ro_fast, grant_workspace_root_rw_fast,
    protect_harness_control_dir_from_appcontainer, top_level_child_missing_ace,
    workspace_capability_sid, workspace_rwx_mask, AppContainerError, FsAccess,
};

/// 永続 workspace capability が持つアクセス範囲。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceAclMode {
    /// 通常の Tier2a。読み取り・書き込み・実行を許可する。
    Rwx,
    /// Tier2a CoW の実 workspace。読み取り・実行だけを許可する。
    ReadOnly,
}

impl WorkspaceAclMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rwx => "rwx",
            Self::ReadOnly => "ro",
        }
    }

    fn mask(self) -> u32 {
        match self {
            Self::Rwx => workspace_rwx_mask(),
            Self::ReadOnly => fs_access_mask(FsAccess::ReadExec),
        }
    }
}

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
    mode: WorkspaceAclMode,
    capability: OwnedSid,
    capability_generation: String,
    protect_sids: Vec<OwnedSid>,
    skip: Vec<PathBuf>,
    needs_descendant_fix: bool,
    state_before: WorkspacePreparationState,
    protected_nodes: usize,
}

impl WorkspacePreparationPlan {
    pub(crate) fn capability_sid(&self) -> windows::Win32::Security::PSID {
        self.capability.as_psid()
    }

    pub(crate) fn needs_descendant_fix(&self) -> bool {
        self.needs_descendant_fix
    }

    pub(crate) fn state_before(&self) -> &WorkspacePreparationState {
        &self.state_before
    }

    pub(crate) fn protected_nodes(&self) -> usize {
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
            sid: self.capability,
            mask: self.mode.mask(),
            protect_sids: self.protect_sids,
            skip: self.skip,
            workspace: &self.canonical_workspace,
            mode: self.mode.as_str(),
            capability_generation: &self.capability_generation,
        })
    }
}

/// 現在状態を、台帳だけでなく root 識別子と実 DACL の両方から求める。
pub fn workspace_preparation_state(
    workspace: &Path,
    mode: WorkspaceAclMode,
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
        top_level_child_missing_ace(&canonical, capability.as_psid(), &skip).is_some();
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
    mode: WorkspaceAclMode,
    additional_protect_sids: Vec<OwnedSid>,
) -> Result<WorkspacePreparationPlan, AppContainerError> {
    let state_before = workspace_preparation_state(canonical_workspace, mode)?;
    let mode_name = mode.as_str();
    let capability_generation =
        crate::tier2a::workspace_capability::ensure_capability_name(canonical_workspace, mode_name)
            .map_err(AppContainerError::Preflight)?;
    let capability = workspace_capability_sid(canonical_workspace, mode_name)?;

    match mode {
        WorkspaceAclMode::Rwx => {
            grant_workspace_root_rw_fast(canonical_workspace, capability.as_psid())?
        }
        WorkspaceAclMode::ReadOnly => {
            grant_workspace_root_ro_fast(canonical_workspace, capability.as_psid())?
        }
    }

    let mut protect_sids = Vec::with_capacity(1 + additional_protect_sids.len());
    protect_sids.push(capability.clone());
    protect_sids.extend(additional_protect_sids);
    let protect_psids: Vec<_> = protect_sids.iter().map(OwnedSid::as_psid).collect();
    let protected_nodes =
        protect_harness_control_dir_from_appcontainer(canonical_workspace, &protect_psids)?;

    let skip = vec![canonical_workspace.join(".harness")];
    let unreachable_child =
        top_level_child_missing_ace(canonical_workspace, capability.as_psid(), &skip);
    let needs_descendant_fix =
        !crate::tier2a::workspace_capability::tree_is_verified(canonical_workspace, mode_name)
            || unreachable_child.is_some();

    Ok(WorkspacePreparationPlan {
        canonical_workspace: canonical_workspace.to_path_buf(),
        mode,
        capability,
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
    mode: WorkspaceAclMode,
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
    pub mode: WorkspaceAclMode,
    pub state_before: WorkspacePreparationState,
    pub state: WorkspacePreparationState,
    /// `false`かつ`state == Preparing`なら、同じgenerationの既存ジョブへ合流した。
    pub job_started: bool,
    pub protected_nodes: usize,
}
