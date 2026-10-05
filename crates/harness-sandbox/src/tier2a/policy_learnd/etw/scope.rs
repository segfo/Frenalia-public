//! 「このイベントは**このharnessセッションのAppContainer子**のものか」を判定する（M15.7 A-4a）。
//!
//! ETWは**マシン全体**のFSアクセスを流してくる（実測で5.9秒に20万件、`plans/etw-spike/RESULTS.md` §2.1）。
//! そのうち提案の材料になるのは自分のサンドボックス配下のプロセスだけなので、ここで絞る。
//!
//! # 3つの signal を優先順に使う
//!
//! | # | signal | 長所 | 短所 |
//! |---|---|---|---|
//! | 1 | `ProcessStart`の**`PackageFullName`** | プロセス開始時点で確定 | **harnessの`CreateAppContainerProfile`製コンテナでは埋まらない**（実測で確定、RESULTS.md §11）。MSIX/UWPアプリでしか載らない |
//! | 2 | **親が対象なら子も対象**（`ParentProcessID`） | AppContainerトークンは子孫へ無条件に継承される（T-15）ので原理的に正しい | `ProcessStart`を観測できた世代にしか効かない |
//! | 3 | `OpenProcess` + `GetTokenInformation` | 既に走っているプロセスにも効く | **終了済みプロセスには効かない** |
//!
//! **実測の結果、実質的にはsignal 3が起点である**（RESULTS.md §11）。signal 1は harness のコンテナでは
//! 空振りし、signal 2も第1世代をブートストラップできない——`run_shell`の直接の子の親は harness 自身で、
//! それは対象外だからである。signal 2が効くのは「第1世代がsignal 3で確定した後の子孫」に対してで、
//! そこでは`--sandbox tier2a-cow`のRedirector DLL経由で起こる孫・ひ孫まで確実に拾える（T-15の継承が根拠）。
//!
//! そのためprobeは**拒否イベント時ではなく`ProcessStart`時に行う**（[`ScopeTracker::on_process_start_probing`]）。
//! 拒否は対象プロセスの一生のどこで起きるか分からないが、`ProcessStart`の時点ならまだ生きている。
//!
//! # PID再利用
//!
//! PIDは再利用される。`ProcessStart`が運ぶ**`ProcessSequenceNumber`**（単調増加、v3以降）を
//! 世代の識別子として持ち、同じPIDで新しい`ProcessStart`が来たら**前の判定を捨てる**。
//! シーケンス番号が無い版のWindowsでは`CreateTime`相当が無いので、`ProcessStart`の到着順だけで
//! 上書きする（それでも「古い判定が新しいプロセスへ漏れる」ことは防げる）。
//!
//! # 取りこぼしは隠さない
//!
//! 判定できなかったイベントは捨てるが、**捨てた件数は数えて呼び出し側へ返す**
//! （[`ScopeTracker::unresolved_count`]）。収集器はこれを`fs-audit.jsonl`の制御レコードとして
//! 書き出す。D-43のfail-openは「起動を止めない」ことであって「失敗を隠す」ことではない。

use std::collections::HashMap;

use super::session::ProcessStartInfo;

/// 判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerdict {
    /// このセッションのサンドボックス配下。イベントを採用する。
    InScope,
    /// 明確に対象外。捨てる。
    OutOfScope,
    /// 判定できなかった（`ProcessStart`を観測しておらず、照会も失敗した）。
    /// 捨てるが件数を数える。
    Unknown,
}

/// 1プロセスについて分かっていること。
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedProcess {
    in_scope: bool,
    /// PID再利用を見分けるための世代識別子（`ProcessSequenceNumber`、無ければ`None`）。
    sequence: Option<u64>,
}

/// スコープ判定器。**Win32を直接は呼ばない**——`OpenProcess`照会は呼び出し側から
/// クロージャで注入する（[`ScopeTracker::classify`]）。これにより判定ロジック全体が
/// 管理者権限なしに単体テストできる（`docs/CODE-STRUCTURE-RULES.md`規則3）。
#[derive(Debug)]
pub struct ScopeTracker {
    /// このセッションのAppContainerプロファイル名（`harness.shell.sandbox.<token>`）。
    session_profile: String,
    tracked: HashMap<u32, TrackedProcess>,
    /// `OpenProcess`照会の結果キャッシュ（同じPIDへ何度も照会しない）。
    probed: HashMap<u32, bool>,
    unresolved: u64,
    /// signal 1（`PackageFullName`）が一度でも当たったか。当たらなければ収集器は
    /// 「フォールバック経路で動いている」ことを制御レコードへ残す。
    package_name_ever_matched: bool,
    /// harness本体のPID（分かっていれば）。**probeが間に合わなかったときの最後の手掛かり**。
    harness_pid: Option<u32>,
    /// トップレベルAppContainer子の親。Daemon自身は明示的に除外する。
    spawn_daemon_pid: Option<u32>,
    /// 親がharnessだったことを根拠に対象とみなした件数（推定なので数えて可視化する）。
    attributed_by_parentage: u64,
}

impl ScopeTracker {
    pub fn new(session_profile: impl Into<String>) -> Self {
        Self {
            session_profile: session_profile.into(),
            tracked: HashMap::new(),
            probed: HashMap::new(),
            unresolved: 0,
            package_name_ever_matched: false,
            harness_pid: None,
            spawn_daemon_pid: None,
            attributed_by_parentage: 0,
        }
    }

    /// harness本体のPIDを教える。`ProcessStart`は届いたがトークン照会が間に合わなかった
    /// プロセスについて、**親がharnessなら対象とみなす**根拠になる（実測#1の対策）。
    pub fn with_harness_pid(mut self, pid: Option<u32>) -> Self {
        self.harness_pid = pid;
        self
    }

    pub fn with_spawn_daemon_pid(mut self, pid: Option<u32>) -> Self {
        self.spawn_daemon_pid = pid;
        self
    }

    /// 親がharnessであることを根拠に対象とみなした件数（推定の量を可視化する）。
    pub fn attributed_by_parentage_count(&self) -> u64 {
        self.attributed_by_parentage
    }

    /// `Kernel-Process`の`ProcessStart`を1件取り込み、signal 1/2で決まらなければ**その場で**
    /// `probe`へ問い合わせる。
    ///
    /// **拒否イベント時ではなくProcessStart時に問い合わせるのが要点。** 実測（`plans/etw-spike/RESULTS.md` §11）で
    /// harnessの`CreateAppContainerProfile`製コンテナは`PackageFullName`を報告しないと判明したため、
    /// 第1世代を識別できるのは実質このprobeだけになった。そして拒否イベントは対象プロセスの
    /// 一生のどこで起きるか分からない（終了直前かもしれない）のに対し、**`ProcessStart`の時点なら
    /// そのプロセスは定義上まだ生きている**——ETWの配送遅延ぶんの窓は残るが、桁違いに当たりやすい。
    ///
    /// 戻り値はこのプロセスを対象と判定したか。
    pub fn on_process_start_probing(
        &mut self,
        info: &ProcessStartInfo,
        probe: impl FnOnce(u32) -> Option<bool>,
    ) -> bool {
        // harness直下に居るDaemonそのものを、短命救済の親一致で対象へ入れてはいけない。
        if self.spawn_daemon_pid == Some(info.pid) {
            self.probed.insert(info.pid, false);
            self.tracked.insert(
                info.pid,
                TrackedProcess {
                    in_scope: false,
                    sequence: info.process_sequence_number,
                },
            );
            return false;
        }
        if self.on_process_start(info) {
            return true;
        }
        // signal 1（package名）でも 2（親の継承）でも決まらなかった。今なら生きているので聞く。
        match probe(info.pid) {
            Some(true) => {
                self.tracked.insert(
                    info.pid,
                    TrackedProcess {
                        in_scope: true,
                        sequence: info.process_sequence_number,
                    },
                );
                self.probed.insert(info.pid, true);
                true
            }
            Some(false) => {
                self.probed.insert(info.pid, false);
                false
            }
            None => {
                // probeが間に合わなかった（極端に短命なプロセス）。実測では最悪ケースで
                // 12個中12個がここへ落ちた（RESULTS.md §12 #1）。
                //
                // 最後の手掛かりとして**親がharness本体かどうか**を見る。`runas`で起こす昇格
                // ヘルパーの親はAppInfoサービスになるため、harnessの直接の子は実質`run_shell`の
                // AppContainer子だけである。推定なので件数を数えて可視化する。
                if self.is_scope_root(info.parent_pid) {
                    self.attributed_by_parentage = self.attributed_by_parentage.saturating_add(1);
                    self.tracked.insert(
                        info.pid,
                        TrackedProcess {
                            in_scope: true,
                            sequence: info.process_sequence_number,
                        },
                    );
                    return true;
                }
                // **「分からない」を「対象外」として固定しない。** `on_process_start`が
                // signal 1/2で決まらなかったときに暫定で入れた`in_scope: false`をここで取り消す
                // ——残すと、後から拒否イベントが来ても`classify`がキャッシュを読んで
                // 二度とprobeし直さない（この取りこぼしは単体テストが捕まえた）。
                self.tracked.remove(&info.pid);
                false
            }
        }
    }

    /// 親が harness 本体か Spawn Daemon か——**記録の根**（この記録が直接起こしたプロセス）か。
    ///
    /// 短命救済（[`Self::on_process_start_probing`]の`None`の分岐）と、プロセスの木の記録
    /// （`process-audit.jsonl`の`is_scope_root`、決定23(2)）の**両方がこの1つを使う**——
    /// 同じ判定を2か所に書くと、片方だけ直したときに「対象と判定した根」と「木に書いた根」が
    /// 食い違う（`B-05`）。どちらのPIDも分かっていなければ偽（`None`同士を一致と読まない）。
    pub fn is_scope_root(&self, parent_pid: Option<u32>) -> bool {
        let parent_is_host = self.harness_pid.is_some() && parent_pid == self.harness_pid;
        let parent_is_daemon = self.spawn_daemon_pid.is_some() && parent_pid == self.spawn_daemon_pid;
        parent_is_host || parent_is_daemon
    }

    /// `Kernel-Process`の`ProcessStart`を1件取り込む（signal 1 と 2 のみ）。
    ///
    /// 戻り値はこのプロセスを対象と判定したか。
    pub fn on_process_start(&mut self, info: &ProcessStartInfo) -> bool {
        // PID再利用: 同じPIDで新しい世代が来たら前の判定を捨てる。
        // シーケンス番号が両方ある場合のみ比較し、片方でも無ければ「新しい方を採る」。
        if let Some(existing) = self.tracked.get(&info.pid) {
            let is_older = match (existing.sequence, info.process_sequence_number) {
                (Some(old), Some(new)) => new < old,
                _ => false,
            };
            if is_older {
                // 順序が入れ替わって届いた古いイベント。無視する。
                return existing.in_scope;
            }
        }

        // signal 1: PackageFullName がこのセッションのプロファイルに対応するか。
        let by_package = info
            .package_full_name
            .as_deref()
            .is_some_and(|package| package_matches_profile(package, &self.session_profile));
        if by_package {
            self.package_name_ever_matched = true;
        }

        // signal 2: 親が対象なら子も対象。AppContainerトークンは子孫へ無条件に継承される（T-15）ため、
        // 「親が箱の中なら子も箱の中」は原理的に正しい。
        let by_parent = info
            .parent_pid
            .and_then(|parent| self.tracked.get(&parent))
            .is_some_and(|parent| parent.in_scope);

        let in_scope = by_package || by_parent;
        self.tracked.insert(
            info.pid,
            TrackedProcess {
                in_scope,
                sequence: info.process_sequence_number,
            },
        );
        in_scope
    }

    /// FSイベントのPIDを判定する。
    ///
    /// `probe`は signal 3（`OpenProcess`+`TokenAppContainerSid`）。`None`を返したら
    /// 「照会できなかった」（プロセスが既に終了した等）を意味する。
    /// `ProcessStart`で既に分かっているPIDには`probe`を呼ばない。
    pub fn classify(&mut self, pid: u32, probe: impl FnOnce(u32) -> Option<bool>) -> ScopeVerdict {
        if let Some(tracked) = self.tracked.get(&pid) {
            return if tracked.in_scope {
                ScopeVerdict::InScope
            } else {
                ScopeVerdict::OutOfScope
            };
        }
        if let Some(cached) = self.probed.get(&pid) {
            return if *cached {
                ScopeVerdict::InScope
            } else {
                ScopeVerdict::OutOfScope
            };
        }
        match probe(pid) {
            Some(result) => {
                self.probed.insert(pid, result);
                if result {
                    ScopeVerdict::InScope
                } else {
                    ScopeVerdict::OutOfScope
                }
            }
            None => {
                // 照会できなかった。**キャッシュしない**——次のイベントでは開けるかもしれないため。
                self.unresolved = self.unresolved.saturating_add(1);
                ScopeVerdict::Unknown
            }
        }
    }

    /// 判定できずに捨てたイベント数（制御レコードへ書く）。
    pub fn unresolved_count(&self) -> u64 {
        self.unresolved
    }

    /// signal 1（`PackageFullName`）が一度でも効いたか。`false`なら収集器は
    /// フォールバック経路（`OpenProcess`照会）だけで動いている。
    pub fn package_name_ever_matched(&self) -> bool {
        self.package_name_ever_matched
    }

    /// `ProcessStart`から対象と判定済みのPID数（診断用）。
    pub fn in_scope_process_count(&self) -> usize {
        self.tracked.values().filter(|p| p.in_scope).count()
    }
}

/// `PackageFullName`がこのセッションのAppContainerプロファイル名に対応するか。
///
/// **緩めに照合する**のは、`CreateAppContainerProfile`で作ったコンテナの`PackageFullName`が
/// どんな形で報告されるかが未確認だからである（`plans/etw-spike/RESULTS.md` §10.2）。
/// MSIXアプリでは`<name>_<version>_<arch>__<publisherhash>`という形だったので、
/// **プロファイル名そのもの、またはそれを`_`区切りの先頭要素として持つ形**を受け入れる。
///
/// 逆に「部分文字列として含む」だけでは受け入れない——別セッションのプロファイル名
/// （`harness.shell.sandbox.<別token>`）が前方一致で誤爆しないようにするため。
pub fn package_matches_profile(package_full_name: &str, session_profile: &str) -> bool {
    if session_profile.is_empty() {
        return false;
    }
    if package_full_name.eq_ignore_ascii_case(session_profile) {
        return true;
    }
    // `<profile>_...` の形（MSIX風の装飾が付いた場合）。`_`直後で切れていることを要求するので、
    // `harness.shell.sandbox.abc` が `harness.shell.sandbox.abcdef` に一致することはない。
    package_full_name
        .strip_prefix(session_profile)
        .is_some_and(|rest| rest.starts_with('_'))
        || package_full_name
            .get(..session_profile.len())
            .is_some_and(|head| {
                head.eq_ignore_ascii_case(session_profile)
                    && package_full_name[session_profile.len()..].starts_with('_')
            })
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;
