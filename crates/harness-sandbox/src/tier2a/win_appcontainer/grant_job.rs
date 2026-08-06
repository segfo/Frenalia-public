//! workspaceの救済walkを背景で回すジョブ（D-54）。
//!
//! `preflight`がworkspace rootへ継承ACEを1件付けると、OSが既存子孫へ物理コピーする。これで
//! **ほぼ全ての**ノードが到達可能になるが、保護DACL（`PROTECTED_DACL_SECURITY_INFORMATION`が
//! 立ったノード。[BUG-020](../../../../docs/bugs/BUG-020.md)の残存損害等）の配下だけは継承が
//! 届かない。その救済（[`super::fix_descendants_missing_ace`]）はO(ファイル数)の読取確認で、
//! この開発機のリポジトリでは28万ノード・実測18.5秒かかる。
//!
//! これはワークスペースにつき一度きりだが、その一度は起動を18.5秒止める。rootへの付与
//! （＝workspaceが見えるようになる条件）は既に同期で終わっているので、救済walkだけを背景へ
//! 回してTUIを先に出す。
//!
//! ## 待ち合わせが要る理由（fail-closed）
//!
//! walkが終わるまで、保護DACL配下は**サンドボックスから見えない**。その状態で`run_shell`を
//! 走らせると、モデルには「そのファイルは存在しない/読めない」と見え、原因不明の失敗として
//! 現れる。だから子プロセスを起動する経路は[`wait_until_done`]で完了を待つ——待って失敗
//! するなら、その理由を添えて断る方が、黙って部分的に壊れた世界を見せるより良い。
//!
//! ## DACL書込の競合を避けるための約束
//!
//! このジョブが走っている間、**同じツリーへ別のDACL書込を並行させてはいけない**。
//! `grant_ace_mask`は「読む→ACEを足す→書き戻す」なので、2つのスレッドが同じノードで
//! 交差すると片方のACEが消える。守り方は2つ:
//!
//! 1. `preflight`はACL作業を全て終えてから[`start`]する（fs-allow付与・`.harness/`保護の後）。
//! 2. `.harness/`は[`start`]に渡す`skip`で対象外にする。直前に
//!    `protect_harness_control_dir_from_appcontainer`が剥がした場所で、ここで付け直すと
//!    制御面の保護（D-05/D-09）が無言で外れる。
//! 3. セッション中にworkspaceへACEを足しうる経路（MCPサーバへのworkspace付与、D-38 §3.2）は
//!    先に[`wait_until_done`]を通す。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::win_common::OwnedSid;

/// 待ち合わせの上限。walkが何らかの理由で進まなくなったとき、`run_shell`を永久に止めない
/// ための保険。この開発機の実測（28万ノードで18.5秒）に対して十分な余裕がある。
const WAIT_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceGrantProgress {
    pub done: usize,
    pub total: usize,
    pub finished: bool,
    /// 完了していて、かつ失敗していた場合の理由。
    pub error: Option<String>,
}

impl WorkspaceGrantProgress {
    /// 0〜100の百分率（`total`が未確定のうちは0）。表示専用。
    pub fn percent(&self) -> u16 {
        if self.total == 0 {
            return 0;
        }
        ((self.done.min(self.total) * 100) / self.total) as u16
    }
}

#[derive(Default)]
struct JobState {
    done: AtomicUsize,
    total: AtomicUsize,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
}

/// このプロセスのジョブ。1プロセス＝1workspace＝1モードなので1本で足りる。
static JOB: OnceLock<Arc<JobState>> = OnceLock::new();

/// 救済walkを背景スレッドで開始する。**モジュールdocの「約束」を満たしてから呼ぶこと。**
///
/// 1プロセス1ジョブ（`OnceLock`）。**既に開始済みなら`false`を返して何もしない。**
/// 製品では`preflight`が1回しか呼ばないので常に`true`だが、`preflight`を複数回呼ぶ実機テストが
/// 同じプロセスに同居すると2回目以降は`false`になる——戻り値を捨てると「起動したつもりで
/// 何も走っていない」テストが緑になるので、呼び出し側に見せる。
///
/// 完走したら[`crate::tier2a::workspace_capability::mark_tree_verified`]を立てるので、
/// 次回起動はwalk自体をしない。
#[must_use = "false means the job was not started (another one already claimed this process)"]
pub fn start(
    root: &Path,
    sid: OwnedSid,
    mask: u32,
    skip: Vec<PathBuf>,
    workspace: &Path,
    mode: &str,
) -> bool {
    let state = Arc::new(JobState::default());
    if JOB.set(Arc::clone(&state)).is_err() {
        return false;
    }
    let root = root.to_path_buf();
    let workspace = workspace.to_path_buf();
    let mode = mode.to_string();
    std::thread::spawn(move || {
        let progress_state = Arc::clone(&state);
        let result = super::fix_descendants_missing_ace(
            &root,
            sid.as_psid(),
            mask,
            &skip,
            &move |done, total| {
                progress_state.done.store(done, Ordering::Relaxed);
                progress_state.total.store(total, Ordering::Relaxed);
            },
        );
        match result {
            Ok(_) => {
                crate::tier2a::workspace_capability::mark_tree_verified(&workspace, &mode);
            }
            Err(e) => {
                *state.error.lock().unwrap() = Some(e.to_string());
            }
        }
        // `finished`は最後に立てる。先に立てると、待ち手が`error`を読む前に「成功で終わった」と
        // 判断してしまう（`Ordering::Release`と対の`Acquire`で読む）。
        state.finished.store(true, Ordering::Release);
    });
    true
}

/// 進行中/完了済みのジョブの状態。`None`は「このプロセスではwalkが要らなかった」
/// （＝台帳が完走済みを記録している）ことを意味する。
pub fn progress() -> Option<WorkspaceGrantProgress> {
    let state = JOB.get()?;
    let finished = state.finished.load(Ordering::Acquire);
    Some(WorkspaceGrantProgress {
        done: state.done.load(Ordering::Relaxed),
        total: state.total.load(Ordering::Relaxed),
        finished,
        error: if finished {
            state.error.lock().unwrap().clone()
        } else {
            None
        },
    })
}

/// ジョブの完了を待つ。走っていなければ即座に`Ok`。
///
/// walkが失敗していた場合は`Err`を返す（fail-closed、モジュールdoc参照）。上限
/// （[`WAIT_TIMEOUT`]）を超えた場合も`Err`で、そのときは待ちきれなかったことを理由に添える。
pub fn wait_until_done() -> Result<(), String> {
    let Some(state) = JOB.get() else {
        return Ok(());
    };
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while !state.finished.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            let done = state.done.load(Ordering::Relaxed);
            let total = state.total.load(Ordering::Relaxed);
            return Err(format!(
                "the workspace ACL repair pass is still running after {}s ({done}/{total} nodes); \
                 refusing to run a sandboxed command while part of the workspace may still be \
                 unreachable (D-54)",
                WAIT_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    match state.error.lock().unwrap().clone() {
        Some(e) => Err(format!(
            "the workspace ACL repair pass failed ({e}); part of the workspace may be unreachable \
             from the sandbox (D-54)"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ジョブを開始していないプロセスでは、待ちは即座に通り、進捗も無い
    /// （2回目以降の起動＝台帳が完走済みを記録しているケース）。
    #[test]
    fn without_a_job_waiting_succeeds_immediately_and_there_is_no_progress() {
        assert_eq!(wait_until_done(), Ok(()));
        assert_eq!(progress(), None);
    }

    #[test]
    fn percent_is_clamped_and_safe_before_the_total_is_known() {
        let p = |done, total| WorkspaceGrantProgress {
            done,
            total,
            finished: false,
            error: None,
        };
        assert_eq!(p(0, 0).percent(), 0);
        assert_eq!(p(10, 0).percent(), 0);
        assert_eq!(p(1, 4).percent(), 25);
        assert_eq!(p(9, 4).percent(), 100);
    }
}
