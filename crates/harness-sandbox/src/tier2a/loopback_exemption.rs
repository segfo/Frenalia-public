//! AppContainer loopback exemption（`NetworkIsolation{Get,Set}AppContainerConfig`が読み書きする
//! **マシン全体で1本のリスト**）の所有権管理（D-36、`plans/DESIGN-SANDBOX-APPPOLICY.md`）。
//!
//! AppContainerからホストのloopback（Local Proxy Agent・Fake DNS）へ接続するには、WFPのpermit
//! だけでなくWindowsのAppContainer loopback exemptionも要る。ところがこのリストはマシン全体で
//! 1本しかなく、harnessのAppContainerプロファイル名は固定（`win_appcontainer::CONTAINER_NAME`）
//! なので、**同時に走る全harnessセッションが同一のpackage SIDのexemptionを共有する**。
//!
//! 「自分が追加したかどうか」というプロセスローカルな記憶だけで削除の可否を決めると、次の2つが
//! 同時に壊れる（`docs/bugs/BUG-053.md`）。
//!
//! - **削除しすぎ**: 後発セッションは既にexemptされているのを見て相乗りするだけなので、先行
//!   セッションが先に終了すると、実行中の後発からexemptionが黙って消える（実機で再現済み）。
//! - **削除しなさすぎ**: daemonが`taskkill`等で異常終了すると、誰も削除しないまま残留する。
//!
//! そこで所有権を**プロセス跨ぎの参照カウント**として台帳に持つ。仕組みは既存の2機構の合成で、
//! 新しい発明はしていない。
//!
//! | 部品 | 何に使うか | 出典 |
//! |---|---|---|
//! | [`harness_grant_ledger::Ledger`] | 所有者一覧の永続化（誤削除防止の2層・fail-open込み） | D-33 |
//! | [`harness_grant_ledger::with_named_lock`] | OSリストと台帳を1つの臨界区間で守る（RMWのロストアップデート防止） | D-27 |
//! | 名前付きmutexの生存確認（[`crate::win_common::mutex_exists`]） | 所有者プロセスがまだ生きているか | `workspace_ledger` |
//!
//! **台帳を`%ProgramData%`へ置く理由**: 読み書きするのは昇格した`harness-netfilterd.exe`だけ
//! なので、ユーザープロファイル配下（`%APPDATA%`の既存4台帳）ではなくマシン全体で1本にできる。
//! exemptionリスト自体がマシン全体で1本である以上、それを数える台帳も同じ粒度でなければ
//! 参照カウントが割れる（別ユーザー・別ターミナルセッションのharnessが同時に動く場合）。
//! 所有者マーカーmutexを`Global\`名前空間にするのも同じ理由（作成にはSeCreateGlobalPrivilegeが
//! 要るが、この経路は常に昇格済み）。
//!
//! **fail-closed**: この取得に失敗すると[`crate::tier2a::wfp::WfpSession::apply`]が`Err`を返し、
//! `should_grant_tier2a_network_capability`が`NetworkCapability::Deny`を選ぶ（子プロセスは
//! ソケットを一切作れない）。exemptionが取れないまま通信を許すことはない。

use std::ffi::c_void;
use std::path::PathBuf;

use harness_grant_ledger::{now_unix_secs, with_named_lock, Ledger};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
};
use windows::Win32::Security::{EqualSid, PSID, SID_AND_ATTRIBUTES};

use crate::win_common::{hold_mutex_for_process_lifetime, mutex_exists, sid_to_string, OwnedSid};

/// OSのexemption一覧と台帳の読み書きを丸ごと囲む臨界区間。Get→変更→Setの間に他プロセスが
/// 割り込むと、他プロセスが追加したexemptionを取りこぼす（lost update）。
const EXEMPTION_LOCK: &str = r"Global\harness-loopback-exemption";
/// 台帳ファイル自身のRMWロック（他の4台帳と同じ方針、D-27/R-01）。常に[`EXEMPTION_LOCK`]の
/// 内側でのみ取る。
const LEDGER_LOCK: &str = r"Global\harness-loopback-exemption-ledger";
const LEDGER_FILE: &str = "loopback-exemption-ledger.json";

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct LoopbackExemptionError(String);

impl LoopbackExemptionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

// --- 所有者の生存表明（名前付きmutex） ---

fn owner_mutex_name(owner_id: &str) -> String {
    format!(r"Global\harness-loopback-owner-{owner_id}")
}

/// 所有者プロセスがまだ生きているか。プロセスが正常終了でもクラッシュでも消えると、Windowsが
/// マーカーmutexを破棄するので、この確認だけで死んだ所有者を刈れる。
fn owner_is_live(owner_id: &str) -> bool {
    mutex_exists(&owner_mutex_name(owner_id))
}

/// このプロセス内で一意な所有者ID。`pid`だけだと、死んだ所有者の記録と、pidを再利用した
/// 別プロセスの記録が同名になり得る。`seq`は「1プロセスが複数の所有者を持つ」場合
/// （テスト・将来の複数WFPセッション）に備える。
fn next_owner_id() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{}-{seq}", std::process::id(), now_unix_secs())
}

// --- 台帳 ---

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct LoopbackExemptionLedger {
    #[serde(default)]
    containers: Vec<ContainerEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ContainerEntry {
    /// AppContainer package SIDの文字列表現（`S-1-15-2-...`）。
    sid: String,
    /// このexemptionをharnessが所有しているか（＝最後の所有者が抜けたときに削除してよいか）。
    /// harnessが載せたのでなければ（外部が設定したものに相乗りしているなら）削除しない。
    harness_managed: bool,
    owners: Vec<Owner>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Owner {
    owner_id: String,
    /// 診断用（生存判定には使わない——判定は常にマーカーmutexで行う）。
    pid: u32,
    granted_at_unix_secs: u64,
}

fn ledger_path() -> Result<PathBuf, LoopbackExemptionError> {
    let base = std::env::var_os("ProgramData").ok_or_else(|| {
        LoopbackExemptionError::new(
            "the ProgramData environment variable is not set; cannot locate the shared loopback \
             exemption ledger",
        )
    })?;
    Ok(PathBuf::from(base).join("harness").join(LEDGER_FILE))
}

fn ledger() -> Result<Ledger<LoopbackExemptionLedger>, LoopbackExemptionError> {
    Ok(Ledger::at_path(ledger_path()?, Some(LEDGER_LOCK)))
}

// --- 純粋な判定（Win32もファイルも触らない。ここだけを単体テストで固定する） ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquireAction {
    /// OSのexemption一覧へ自SIDを追加する（自分が最初の所有者）。
    AddToOsList,
    /// 既に載っていて生きた所有者もいる。OSリストは触らず相乗りする。
    JoinExisting,
    /// 既に載っているが生きた所有者が居ない＝異常終了セッションの残留。所有を引き取り、
    /// 自分が最後の所有者になった時点で削除できるようにする（残留の自己修復）。
    AdoptResidue,
}

/// `present_in_os_list`はOSのexemption一覧に自SIDが載っているか、`live_owners`は台帳上の
/// 生きている所有者の数（自分を数える前）。
fn plan_acquire(present_in_os_list: bool, live_owners: usize) -> AcquireAction {
    if !present_in_os_list {
        // 台帳に生存所有者がいてもOS側に無いなら、外部が消したということ。載せ直す。
        AcquireAction::AddToOsList
    } else if live_owners > 0 {
        AcquireAction::JoinExisting
    } else {
        AcquireAction::AdoptResidue
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseAction {
    /// 最後の所有者だったのでOSリストから削除する。
    RemoveFromOsList,
    /// 他に生きている所有者が残っているので触らない（#7の修正点）。
    KeepForOtherOwners,
    /// harnessが載せたものではない（外部所有）ので触らない。
    KeepNotOurs,
}

/// `remaining_live_owners`は自分を除いた生存所有者の数。
fn plan_release(remaining_live_owners: usize, harness_managed: bool) -> ReleaseAction {
    if remaining_live_owners > 0 {
        ReleaseAction::KeepForOtherOwners
    } else if harness_managed {
        ReleaseAction::RemoveFromOsList
    } else {
        ReleaseAction::KeepNotOurs
    }
}

// --- OSのexemption一覧（テストから差し替えられるよう trait 越しに扱う） ---

/// 「あるpackage SIDがloopback exemptionに載っているか／載せる／外す」の3操作。実体は
/// [`Win32ExemptionList`]（要管理者権限）で、単体テストは同じ形のフェイクを渡す。
trait ExemptionList {
    fn contains(&self) -> Result<bool, LoopbackExemptionError>;
    fn add(&self) -> Result<(), LoopbackExemptionError>;
    fn remove(&self) -> Result<(), LoopbackExemptionError>;
}

unsafe fn sid_equals(left: PSID, right: PSID) -> bool {
    EqualSid(left, right).is_ok()
}

unsafe fn current_exemptions() -> Result<Vec<OwnedSid>, LoopbackExemptionError> {
    let mut count = 0u32;
    let mut raw: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
    let status = NetworkIsolationGetAppContainerConfig(&mut count, &mut raw);
    if status != 0 {
        return Err(LoopbackExemptionError::new(format!(
            "NetworkIsolationGetAppContainerConfig failed with Win32 status {status}"
        )));
    }

    let mut sids = Vec::new();
    if !raw.is_null() {
        let slice = std::slice::from_raw_parts(raw, count as usize);
        for entry in slice {
            sids.push(OwnedSid::copy_from(entry.Sid).map_err(|e| {
                LoopbackExemptionError::new(format!("CopySid failed while copying SID: {e}"))
            })?);
        }
        let _ = LocalFree(HLOCAL(raw as *mut c_void));
    }
    Ok(sids)
}

unsafe fn set_exemptions(sids: &[OwnedSid]) -> Result<(), LoopbackExemptionError> {
    let entries: Vec<SID_AND_ATTRIBUTES> = sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: 0,
        })
        .collect();
    let status = NetworkIsolationSetAppContainerConfig(&entries);
    if status != 0 {
        return Err(LoopbackExemptionError::new(format!(
            "NetworkIsolationSetAppContainerConfig failed with Win32 status {status}"
        )));
    }
    Ok(())
}

struct Win32ExemptionList {
    sid: OwnedSid,
}

impl ExemptionList for Win32ExemptionList {
    fn contains(&self) -> Result<bool, LoopbackExemptionError> {
        unsafe {
            Ok(current_exemptions()?
                .iter()
                .any(|existing| sid_equals(existing.as_psid(), self.sid.as_psid())))
        }
    }

    fn add(&self) -> Result<(), LoopbackExemptionError> {
        unsafe {
            let mut current = current_exemptions()?;
            if current
                .iter()
                .any(|existing| sid_equals(existing.as_psid(), self.sid.as_psid()))
            {
                return Ok(());
            }
            current.push(OwnedSid::copy_from(self.sid.as_psid()).map_err(|e| {
                LoopbackExemptionError::new(format!("CopySid failed while copying SID: {e}"))
            })?);
            set_exemptions(&current)
        }
    }

    fn remove(&self) -> Result<(), LoopbackExemptionError> {
        unsafe {
            let mut current = current_exemptions()?;
            current.retain(|existing| !sid_equals(existing.as_psid(), self.sid.as_psid()));
            set_exemptions(&current)
        }
    }
}

// --- 取得・解放（台帳操作の本体。ロックは呼び出し元が握っている前提） ---

fn acquire_in_ledger(
    sid_key: &str,
    owner_id: &str,
    ledger: &Ledger<LoopbackExemptionLedger>,
    is_live: &dyn Fn(&str) -> bool,
    list: &dyn ExemptionList,
) -> Result<AcquireAction, LoopbackExemptionError> {
    let present = list.contains()?;
    ledger.update(|l| {
        let idx = match l.containers.iter().position(|c| c.sid == sid_key) {
            Some(i) => i,
            None => {
                l.containers.push(ContainerEntry {
                    sid: sid_key.to_string(),
                    harness_managed: false,
                    owners: Vec::new(),
                });
                l.containers.len() - 1
            }
        };
        let entry = &mut l.containers[idx];
        // 死んだ所有者（異常終了したdaemon）をここで刈る。
        entry.owners.retain(|o| is_live(&o.owner_id));

        let action = plan_acquire(present, entry.owners.len());
        match action {
            AcquireAction::AddToOsList => {
                list.add()?;
                entry.harness_managed = true;
            }
            AcquireAction::AdoptResidue => {
                // OSリスト上に残っているのは、harnessのプロファイル名から導出された固定SID。
                // 生きた所有者が居ない以上、これは異常終了したharnessセッションの残留なので
                // 所有を引き取る（他者が正当にこのSIDをexemptする理由が無い）。
                entry.harness_managed = true;
            }
            AcquireAction::JoinExisting => {}
        }
        entry.owners.push(Owner {
            owner_id: owner_id.to_string(),
            pid: std::process::id(),
            granted_at_unix_secs: now_unix_secs(),
        });
        Ok(action)
    })
}

fn release_in_ledger(
    sid_key: &str,
    owner_id: &str,
    ledger: &Ledger<LoopbackExemptionLedger>,
    is_live: &dyn Fn(&str) -> bool,
    list: &dyn ExemptionList,
) -> Result<ReleaseAction, LoopbackExemptionError> {
    ledger.update(|l| {
        let Some(idx) = l.containers.iter().position(|c| c.sid == sid_key) else {
            // 台帳に記録が無い（ファイルが消された等）。所有していない可能性がある以上、
            // OSリストへは触らない——他の実行中セッションを巻き込む方が害が大きい。
            // 残留した場合は次のセッションの`AdoptResidue`が引き取る。
            return Ok(ReleaseAction::KeepNotOurs);
        };
        let entry = &mut l.containers[idx];
        entry
            .owners
            .retain(|o| o.owner_id != owner_id && is_live(&o.owner_id));
        let action = plan_release(entry.owners.len(), entry.harness_managed);
        let owners_left = entry.owners.len();
        if action == ReleaseAction::RemoveFromOsList {
            list.remove()?;
        }
        if owners_left == 0 {
            l.containers.remove(idx);
        }
        Ok(action)
    })
}

// --- 公開API（`wfp::WfpSession`から使う） ---

/// 1セッション分のloopback exemption所有権。[`release`]（または`Drop`）まで、このプロセスが
/// 所有者の1人として台帳に載り続ける。
pub(crate) struct LoopbackExemptionGuard {
    sid_key: String,
    owner_id: String,
    list: Win32ExemptionList,
    /// `release`で明示解放済みかどうか（`Drop`での二重解放を防ぐ）。
    released: bool,
}

/// このセッションぶんのloopback exemptionを確保する。既に他セッションが載せていれば相乗りし、
/// 誰も生きていない残留があれば所有を引き取る（モジュールdoc参照）。
pub(crate) fn acquire(
    container_sid: PSID,
) -> Result<LoopbackExemptionGuard, LoopbackExemptionError> {
    let sid_key = sid_to_string(container_sid).map_err(|e| {
        LoopbackExemptionError::new(format!("failed to stringify package SID: {e}"))
    })?;
    let list = Win32ExemptionList {
        sid: unsafe { OwnedSid::copy_from(container_sid) }
            .map_err(|e| LoopbackExemptionError::new(format!("CopySid failed: {e}")))?,
    };
    let owner_id = next_owner_id();
    // 台帳へ載せる**前に**自分の生存マーカーを立てる。逆順にすると、台帳に載った直後・
    // マーカー作成前にクラッシュした場合、生きていない所有者が生きているように見えてしまう。
    hold_mutex_for_process_lifetime(&owner_mutex_name(&owner_id)).map_err(|e| {
        LoopbackExemptionError::new(format!(
            "failed to create loopback exemption owner marker: {e}"
        ))
    })?;
    let ledger = ledger()?;
    with_named_lock(EXEMPTION_LOCK, || {
        acquire_in_ledger(&sid_key, &owner_id, &ledger, &owner_is_live, &list)
    })?;
    Ok(LoopbackExemptionGuard {
        sid_key,
        owner_id,
        list,
        released: false,
    })
}

/// このセッションぶんの所有を手放す。**他に生きている所有者が残っていればOSリストは触らない**。
pub(crate) fn release(mut guard: LoopbackExemptionGuard) -> Result<(), LoopbackExemptionError> {
    guard.released = true;
    let ledger = ledger()?;
    with_named_lock(EXEMPTION_LOCK, || {
        release_in_ledger(
            &guard.sid_key,
            &guard.owner_id,
            &ledger,
            &owner_is_live,
            &guard.list,
        )
    })?;
    Ok(())
}

impl Drop for LoopbackExemptionGuard {
    /// [`release`]を呼ばずに落ちた場合（異常系）でもベストエフォートで所有を手放す。
    /// ここも失敗しうるが、その場合の残留は次セッションの`AdoptResidue`が回収する。
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let Ok(ledger) = ledger() else {
            return;
        };
        let _ = with_named_lock(EXEMPTION_LOCK, || {
            release_in_ledger(
                &self.sid_key,
                &self.owner_id,
                &ledger,
                &owner_is_live,
                &self.list,
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;

    /// OSのexemption一覧のフェイク。`Win32ExemptionList`と同じ3操作だけを持つ。
    #[derive(Default)]
    struct FakeList {
        present: RefCell<bool>,
        adds: RefCell<usize>,
        removes: RefCell<usize>,
        fail_on_add: bool,
    }

    impl FakeList {
        fn with_present(present: bool) -> Self {
            Self {
                present: RefCell::new(present),
                ..Default::default()
            }
        }
    }

    impl ExemptionList for FakeList {
        fn contains(&self) -> Result<bool, LoopbackExemptionError> {
            Ok(*self.present.borrow())
        }
        fn add(&self) -> Result<(), LoopbackExemptionError> {
            if self.fail_on_add {
                return Err(LoopbackExemptionError::new("simulated add failure"));
            }
            *self.adds.borrow_mut() += 1;
            *self.present.borrow_mut() = true;
            Ok(())
        }
        fn remove(&self) -> Result<(), LoopbackExemptionError> {
            *self.removes.borrow_mut() += 1;
            *self.present.borrow_mut() = false;
            Ok(())
        }
    }

    fn test_ledger(dir: &std::path::Path) -> Ledger<LoopbackExemptionLedger> {
        Ledger::at_path(dir.join("loopback-exemption-ledger.json"), None)
    }

    /// 生存所有者の集合を差し替えられる判定関数を作る。
    fn liveness(live: &HashSet<String>) -> impl Fn(&str) -> bool + '_ {
        move |owner_id: &str| live.contains(owner_id)
    }

    const SID: &str = "S-1-15-2-1234567890-1234567890-1234567890-1234567890";

    #[test]
    fn plan_acquire_adds_when_the_sid_is_not_exempt_yet() {
        assert_eq!(plan_acquire(false, 0), AcquireAction::AddToOsList);
        // 台帳に生存所有者がいてもOS側に無いなら載せ直す（外部が消した場合）。
        assert_eq!(plan_acquire(false, 3), AcquireAction::AddToOsList);
    }

    #[test]
    fn plan_acquire_joins_when_another_live_session_owns_it() {
        assert_eq!(plan_acquire(true, 1), AcquireAction::JoinExisting);
    }

    /// #5: 異常終了で残留したexemptionは、次のセッションが所有を引き取る（自己修復）。
    #[test]
    fn plan_acquire_adopts_residue_left_by_a_dead_session() {
        assert_eq!(plan_acquire(true, 0), AcquireAction::AdoptResidue);
    }

    /// #7: 他に生きた所有者が残っていれば絶対に削除しない。
    #[test]
    fn plan_release_keeps_the_exemption_while_other_owners_are_alive() {
        assert_eq!(plan_release(1, true), ReleaseAction::KeepForOtherOwners);
        assert_eq!(plan_release(2, false), ReleaseAction::KeepForOtherOwners);
    }

    #[test]
    fn plan_release_removes_only_as_the_last_harness_owner() {
        assert_eq!(plan_release(0, true), ReleaseAction::RemoveFromOsList);
    }

    /// harnessが載せたものでなければ（外部所有への相乗り）、最後の1人でも削除しない。
    #[test]
    fn plan_release_never_removes_an_exemption_harness_did_not_add() {
        assert_eq!(plan_release(0, false), ReleaseAction::KeepNotOurs);
    }

    /// #7の回帰テスト本体: A取得 → B取得 → A解放でOSリストは維持され、B解放で初めて消える。
    #[test]
    fn two_sessions_share_one_exemption_and_only_the_last_one_removes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = test_ledger(tmp.path());
        let list = FakeList::default();
        let mut live: HashSet<String> = HashSet::new();
        live.insert("A".to_string());
        live.insert("B".to_string());

        assert_eq!(
            acquire_in_ledger(SID, "A", &ledger, &liveness(&live), &list).unwrap(),
            AcquireAction::AddToOsList
        );
        assert_eq!(
            acquire_in_ledger(SID, "B", &ledger, &liveness(&live), &list).unwrap(),
            AcquireAction::JoinExisting
        );
        assert_eq!(*list.adds.borrow(), 1, "2セッションでも追加は1回");

        // 先行Aが先に終了する。Bはまだ生きている。
        live.remove("A");
        assert_eq!(
            release_in_ledger(SID, "A", &ledger, &liveness(&live), &list).unwrap(),
            ReleaseAction::KeepForOtherOwners
        );
        assert!(*list.present.borrow(), "実行中のBからexemptionを奪わない");
        assert_eq!(*list.removes.borrow(), 0);

        // 最後のBが終了して初めて削除される。
        live.remove("B");
        assert_eq!(
            release_in_ledger(SID, "B", &ledger, &liveness(&live), &list).unwrap(),
            ReleaseAction::RemoveFromOsList
        );
        assert!(!*list.present.borrow());
        assert_eq!(*list.removes.borrow(), 1);
        assert!(
            ledger.load().containers.is_empty(),
            "所有者が居なくなったエントリは台帳に残さない"
        );
    }

    /// #5の回帰テスト本体: 台帳に載ったまま死んだ所有者は刈られ、残留exemptionは引き取られて
    /// 次の解放で消える。
    #[test]
    fn residue_from_a_killed_session_is_adopted_and_then_cleaned_up() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = test_ledger(tmp.path());
        let list = FakeList::default();
        let mut live: HashSet<String> = HashSet::new();
        live.insert("killed".to_string());

        acquire_in_ledger(SID, "killed", &ledger, &liveness(&live), &list).unwrap();
        assert!(*list.present.borrow());

        // taskkill相当: 解放されないまま所有者プロセスが消える（マーカーmutexも消える）。
        live.remove("killed");

        let mut next_live: HashSet<String> = HashSet::new();
        next_live.insert("next".to_string());
        assert_eq!(
            acquire_in_ledger(SID, "next", &ledger, &liveness(&next_live), &list).unwrap(),
            AcquireAction::AdoptResidue
        );
        let loaded = ledger.load();
        assert_eq!(
            loaded.containers[0].owners.len(),
            1,
            "死んだ所有者は刈られる"
        );
        assert_eq!(loaded.containers[0].owners[0].owner_id, "next");

        next_live.remove("next");
        assert_eq!(
            release_in_ledger(SID, "next", &ledger, &liveness(&next_live), &list).unwrap(),
            ReleaseAction::RemoveFromOsList
        );
        assert!(
            !*list.present.borrow(),
            "残留は次セッションの終了時に消える"
        );
    }

    /// harnessが載せたのではないエントリ（`harness_managed=false`）は、最後の所有者が抜けても
    /// OSリストから消さない。現在の`acquire`は追加・引き取りのどちらでも`true`にするため、
    /// この状態は今のところ実際には生じないが、`harness_managed`が所有の判断材料として効いて
    /// いること自体を固定しておく（将来「外部が載せたexemptionへ明示的に相乗りする」経路を
    /// 足したときに、この防御が既に在ることを保証する）。
    #[test]
    fn an_externally_owned_exemption_is_never_removed_by_release() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = test_ledger(tmp.path());
        ledger.update(|l| {
            l.containers.push(ContainerEntry {
                sid: SID.to_string(),
                harness_managed: false,
                owners: vec![Owner {
                    owner_id: "me".to_string(),
                    pid: std::process::id(),
                    granted_at_unix_secs: 0,
                }],
            });
        });
        let list = FakeList::with_present(true);
        let live: HashSet<String> = HashSet::new();

        assert_eq!(
            release_in_ledger(SID, "me", &ledger, &liveness(&live), &list).unwrap(),
            ReleaseAction::KeepNotOurs
        );
        assert!(*list.present.borrow(), "外部所有のexemptionは触らない");
        assert_eq!(*list.removes.borrow(), 0);
    }

    /// OSリストへの追加が失敗したら所有者として記録しない（fail-closed。記録だけ残ると、
    /// 実際には載っていないexemptionを「他に所有者がいる」と誤認させる）。
    #[test]
    fn a_failed_os_list_add_does_not_record_an_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = test_ledger(tmp.path());
        let list = FakeList {
            fail_on_add: true,
            ..Default::default()
        };
        let live: HashSet<String> = HashSet::new();

        assert!(acquire_in_ledger(SID, "A", &ledger, &liveness(&live), &list).is_err());
        let loaded = ledger.load();
        assert!(
            loaded
                .containers
                .iter()
                .all(|c| c.owners.iter().all(|o| o.owner_id != "A")),
            "追加に失敗した所有者を台帳へ載せない: {loaded:?}"
        );
    }

    /// 台帳ファイルが消えた（クリーンアップに巻き込まれた等）場合、解放はOSリストへ触らない。
    /// 巻き込みで他セッションのexemptionを奪う方が害が大きいため。残留は次の`AdoptResidue`で回収する。
    #[test]
    fn release_without_a_ledger_entry_leaves_the_os_list_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = test_ledger(tmp.path());
        let list = FakeList::with_present(true);
        let live: HashSet<String> = HashSet::new();

        assert_eq!(
            release_in_ledger(SID, "ghost", &ledger, &liveness(&live), &list).unwrap(),
            ReleaseAction::KeepNotOurs
        );
        assert!(*list.present.borrow());
        assert_eq!(*list.removes.borrow(), 0);
    }

    #[test]
    fn owner_ids_are_unique_within_a_process() {
        let a = next_owner_id();
        let b = next_owner_id();
        assert_ne!(a, b);
        assert!(a.starts_with(&format!("{}-", std::process::id())));
    }

    #[test]
    fn ledger_path_is_machine_global_under_program_data() {
        let path = ledger_path().expect("ProgramData must be set on Windows");
        assert!(path.ends_with(std::path::Path::new("harness").join(LEDGER_FILE)));
    }

    /// BUG-053（`docs/STATUS.md`旧Tier2a残課題#5/#7）の実機回帰テスト。修正前のコードでは
    /// 「A解放後にexemptionが消える」ことを実機で確認済み（`docs/bugs/BUG-053.md`の再現ログ）。
    ///
    /// 実マシンのloopback exemption一覧と`%ProgramData%`の台帳を実際に書き換えるため
    /// `#[ignore]`。実行例（要管理者権限、`dev-elevated-run.exe e2e-loopback-exemption`）:
    /// `cargo test -p harness-sandbox --lib -- --ignored --nocapture loopback`
    #[test]
    #[ignore = "requires administrator token and mutates the machine-global AppContainer loopback exemption list"]
    fn e2e_loopback_exemption_survives_a_concurrent_sessions_teardown() {
        if !crate::tier2a::privhelper::is_elevated() {
            panic!("loopback exemption E2E requires an elevated administrator token");
        }

        let sid = crate::tier2a::win_appcontainer::ensure_profile(
            crate::tier2a::win_appcontainer::CONTAINER_NAME,
        )
        .expect("ensure AppContainer profile");
        let probe = Win32ExemptionList {
            sid: unsafe { OwnedSid::copy_from(sid.as_psid()) }.expect("copy package SID"),
        };
        let exempt_now = || probe.contains().expect("read loopback exemptions");

        let present_before = exempt_now();
        eprintln!("[e2e] exempt before test: {present_before}");

        // セッションA（先行）→ セッションB（後発、同じ共有package SID）の順に取得する。
        let session_a = acquire(sid.as_psid()).expect("session A acquire");
        let session_b = acquire(sid.as_psid()).expect("session B acquire");
        assert!(exempt_now(), "both sessions running: SID must be exempt");

        // 先行Aだけを終了させる。Bはまだ動いている。
        release(session_a).expect("session A release");
        let still_exempt = exempt_now();
        eprintln!("[e2e] exempt after session A release (B still running): {still_exempt}");
        assert!(
            still_exempt,
            "a still-running session must keep its loopback exemption when another session \
             tears down (BUG-053)"
        );

        // 最後の所有者が抜けたときだけ消える。
        release(session_b).expect("session B release");
        let after_all = exempt_now();
        eprintln!("[e2e] exempt after session B release: {after_all}");
        assert_eq!(
            after_all, present_before,
            "after the last owner leaves, the exemption list must be back to its initial state"
        );
    }

    /// 異常終了で残留したexemptionを、次のセッションが引き取って掃除する（旧#5）。所有者
    /// マーカーmutexが生きたままにならないよう、`acquire`が返したガードを`std::mem::forget`で
    /// 落とさずに保持したまま、**台帳から所有者記録だけを消す**ことで「マーカーは消えたのに
    /// exemptionは残っている」＝killされたdaemonと同じ状態を作る。
    #[test]
    #[ignore = "requires administrator token and mutates the machine-global AppContainer loopback exemption list"]
    fn e2e_residue_from_a_killed_session_is_adopted_and_removed() {
        if !crate::tier2a::privhelper::is_elevated() {
            panic!("loopback exemption E2E requires an elevated administrator token");
        }

        let sid = crate::tier2a::win_appcontainer::ensure_profile(
            crate::tier2a::win_appcontainer::CONTAINER_NAME,
        )
        .expect("ensure AppContainer profile");
        let probe = Win32ExemptionList {
            sid: unsafe { OwnedSid::copy_from(sid.as_psid()) }.expect("copy package SID"),
        };
        let exempt_now = || probe.contains().expect("read loopback exemptions");
        let present_before = exempt_now();

        let killed = acquire(sid.as_psid()).expect("acquire");
        assert!(exempt_now());
        // killされたdaemonの再現: 解放せずに所有者記録を「死んだもの」に見せる。
        std::mem::forget(killed);
        let ledger = ledger().expect("ledger");
        ledger.update(|l| {
            for container in &mut l.containers {
                container.owners.clear();
            }
        });
        assert!(exempt_now(), "残留状態を作れていること");

        // 次のセッションが残留を引き取り、終了時に掃除する。
        let next = acquire(sid.as_psid()).expect("acquire after residue");
        release(next).expect("release");
        assert_eq!(
            exempt_now(),
            present_before,
            "残留exemptionは次セッションの終了時に消える（旧#5）"
        );
    }
}
