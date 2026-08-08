//! 記録セッションの同時実行を1本に絞るグローバルロック（決定事項13）。
//!
//! # なぜ要るのか
//!
//! 記録モードのパス2（Tier2a）はマシン全体で共有される状態を触る——AppContainer
//! プロファイル、WFPフィルタ、fs-passthrough台帳。2つの記録セッションが同時に走ると、
//! どちらの観測結果か区別できない監査ログが混ざり、しかも一方の撤収がもう一方の
//! 稼働中の資源を剥がし得る（[BUG-053]と同型）。
//!
//! # 寿命はOSハンドルに紐付ける（グローバルCLAUDE.mdの原則）
//!
//! ロックの実体は**名前付きmutex**であって、ファイルやレジストリの「ロック中フラグ」では
//! ない。プロセスが異常終了してもOSがハンドルを閉じ、mutexは自動的に解放される。
//! フラグ方式だと落ちた瞬間に「誰も使っていないのにロックされたまま」が残り、
//! 手動で消す手順が必要になる（`harness-sandbox`の
//! `tier2a::workspace_ledger`が名前付きmutexで生存判定しているのと同じ理由）。
//!
//! # abandoned mutexは「異常終了の痕跡」であって障害ではない
//!
//! 前のセッションがmutexを保持したまま落ちると、次の`WaitForSingleObject`は
//! `WAIT_ABANDONED`を返す。**これは取得成功である**（所有権は移る）。
//! ただし「前回が正常に終わらなかった」という事実は呼び出し側へ伝える
//! ——パス2で張ったWFPフィルタやACEが残っている可能性があり、
//! 記録を始める前にユーザーへ知らせる価値があるため。黙って握り潰さない（B-10）。

/// ロック取得の結果。
#[derive(Debug, PartialEq, Eq)]
pub enum LockOutcome {
    /// 取得できた。
    Acquired,
    /// 取得できたが、**前のセッションが解放せずに終了していた**（`WAIT_ABANDONED`）。
    /// 前回の記録が異常終了しており、実マシンに撤収されていない副作用
    /// （WFPフィルタ・ACE・AppContainerプロファイル）が残っている可能性がある。
    AcquiredAfterAbandon,
    /// 別の記録セッションが実行中。
    AlreadyHeld,
}

impl LockOutcome {
    /// ユーザーへそのまま出せる説明。**何をすればよいかまで書く**（B-32）
    /// ——「取得できませんでした」だけでは、待てばよいのか操作が要るのか分からない。
    pub fn message(&self) -> &'static str {
        match self {
            LockOutcome::Acquired => "記録セッションを開始しました。",
            LockOutcome::AcquiredAfterAbandon => {
                "記録セッションを開始しました。ただし前回の記録は正常に終了していません\
                 （ロックが解放されずに残っていました）。前回のTier2aパスが張ったWFPフィルタや\
                 FS ACEが撤収されずに残っている可能性があります。気になる場合は一度\
                 `harness fs revoke-workspace`で撤収してから記録し直してください。"
            }
            LockOutcome::AlreadyHeld => {
                "別の記録セッションが実行中のため開始できません。記録モードはマシン全体の\
                 共有状態（AppContainerプロファイル・WFPフィルタ・fs-passthrough台帳）を\
                 触るので同時に1つしか動かせません。先に動いている\
                 harness-policy-editorを終了してから、もう一度お試しください。"
            }
        }
    }

    /// 記録を続行してよいか（`AlreadyHeld`だけが不可）。
    pub fn can_proceed(&self) -> bool {
        !matches!(self, LockOutcome::AlreadyHeld)
    }
}

/// マシン全体で一意なmutex名。`Global\`接頭辞でセッション（ターミナルサービスの
/// ログオンセッション）を跨いで一意にする。
pub const RECORDING_MUTEX_NAME: &str = r"Global\harness-policy-editor-recording";

#[cfg(windows)]
pub use windows_impl::RecordingLock;

#[cfg(windows)]
mod windows_impl {
    use super::{LockOutcome, RECORDING_MUTEX_NAME};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    /// 保持している間だけ記録セッションを走らせてよいことを表すRAIIガード。
    /// `Drop`でmutexを解放する（プロセスが落ちた場合はOSが解放する）。
    pub struct RecordingLock {
        handle: HANDLE,
        /// `Drop`で`ReleaseMutex`すべきか。`AlreadyHeld`のときは所有していないので解放しない。
        owned: bool,
    }

    // HANDLEは単なるカーネルオブジェクトへのハンドル値で、スレッド間で運んでよい
    // （`win_common::SendHandle`・`wfp::WfpSession`と同じ判断）。
    unsafe impl Send for RecordingLock {}

    impl RecordingLock {
        /// ロックの取得を試みる。**ブロックしない**——他が持っていれば即座に
        /// [`LockOutcome::AlreadyHeld`]を返す（UIを固めないため）。
        pub fn try_acquire() -> Result<(Option<Self>, LockOutcome), String> {
            let name: Vec<u16> = RECORDING_MUTEX_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            unsafe {
                let handle = CreateMutexW(None, false, PCWSTR(name.as_ptr()))
                    .map_err(|e| format!("CreateMutexW failed: {e}"))?;
                // タイムアウト0＝ポーリング。待たずに今の所有状況だけを見る。
                let wait = WaitForSingleObject(handle, 0);
                if wait == WAIT_OBJECT_0 {
                    Ok((
                        Some(Self {
                            handle,
                            owned: true,
                        }),
                        LockOutcome::Acquired,
                    ))
                } else if wait == WAIT_ABANDONED {
                    // 所有権は移っている（＝取得成功）。前回が解放せずに落ちた事実だけを伝える。
                    Ok((
                        Some(Self {
                            handle,
                            owned: true,
                        }),
                        LockOutcome::AcquiredAfterAbandon,
                    ))
                } else {
                    let _ = CloseHandle(handle);
                    Ok((None, LockOutcome::AlreadyHeld))
                }
            }
        }
    }

    impl Drop for RecordingLock {
        fn drop(&mut self) {
            unsafe {
                if self.owned {
                    let _ = ReleaseMutex(self.handle);
                }
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AlreadyHeld`だけが続行不可。abandonedは**取得成功**（所有権は移る）。
    #[test]
    fn only_already_held_blocks_the_session() {
        assert!(LockOutcome::Acquired.can_proceed());
        assert!(LockOutcome::AcquiredAfterAbandon.can_proceed());
        assert!(!LockOutcome::AlreadyHeld.can_proceed());
    }

    /// 文言は「次に何をすればよいか」まで書く（B-32）。状態名を並べただけの
    /// 機械的な文字列にしない。
    #[test]
    fn every_outcome_explains_what_to_do_next() {
        assert!(LockOutcome::AlreadyHeld
            .message()
            .contains("終了してから"));
        assert!(LockOutcome::AcquiredAfterAbandon
            .message()
            .contains("revoke-workspace"));
        for outcome in [
            LockOutcome::Acquired,
            LockOutcome::AcquiredAfterAbandon,
            LockOutcome::AlreadyHeld,
        ] {
            assert!(!outcome.message().is_empty());
        }
    }

    /// 1本目を**保持したまま**2本目を試すと`AlreadyHeld`になり、
    /// 1本目をdropすれば再び取得できる（解放が効いていることの確認）。
    ///
    /// **2本目は必ず別スレッドから試す。** Windowsの名前付きmutexは
    /// **同一スレッドに対して再入可能**で、既に所有しているスレッドからの
    /// `WaitForSingleObject`は即座に成功する（所有回数が増えるだけ）。
    /// 同じスレッドで2回呼ぶと`Acquired`が返り、相互排他を検証したことにならない。
    /// 実運用で競合するのは別プロセス同士なので、別スレッドで代表させる。
    #[cfg(windows)]
    #[test]
    fn a_second_acquisition_from_another_thread_is_refused_while_the_first_is_held() {
        let (first, outcome) = RecordingLock::try_acquire().unwrap();
        // 他のプロセスが同じmutexを握っている環境では前提が崩れるので、
        // 取得できたときだけ検証する。
        if outcome != LockOutcome::Acquired {
            return;
        }
        let first = first.expect("Acquired must carry a guard");

        let second_outcome = std::thread::spawn(|| {
            let (guard, outcome) = RecordingLock::try_acquire().unwrap();
            assert!(guard.is_none(), "AlreadyHeld must not hand out a guard");
            outcome
        })
        .join()
        .unwrap();
        assert_eq!(second_outcome, LockOutcome::AlreadyHeld);

        drop(first);

        let third_outcome = std::thread::spawn(|| {
            let (guard, outcome) = RecordingLock::try_acquire().unwrap();
            drop(guard);
            outcome
        })
        .join()
        .unwrap();
        assert_eq!(
            third_outcome,
            LockOutcome::Acquired,
            "the lock must be reacquirable after the holder is dropped"
        );
    }
}
