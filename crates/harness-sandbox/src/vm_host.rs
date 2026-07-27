//! Tier3の外層VMを、セッションごとに使い捨てる専有物ではなく**参照カウントされる共有
//! resident資源**として管理する（`DESIGN-SANDBOX-VMISOLATION.md`「実装確定サマリー」項目8、
//! Phase B）。
//!
//! **発見の経緯**: 項目6（1VM常駐+複数コンテナ）はマルチセッションレビューで決定済みだったが、
//! 実装調査で`VmSession::start`が実際にはコールドでもwarmでも**セッションごとに新規VMを
//! 起こしていた**ことが判明した（warmも`Restore-VMSnapshot`で単一VMを1セッション専有し、
//! `WarmLock`でマシン全体を直列化していた）。`VmSandboxConfig::guest_ip`が単一の固定静的IPの
//! ため、構造的に同時に生存できるVMは1台だけであり、daemonをthread-per-session化するだけでは
//! 2本目の`StartSession`が確実に壊れる。本モジュールはその是正であり、VM自体を
//! `attach`/`release`の参照カウントで管理する共有資源へ切り替える。
//!
//! **設計**: daemonプロセス全体で単一の`Mutex<VmHostState>`を持つ。`attach`はロック保持中に
//! 必要ならVM起動（コールドブート、またはwarmテンプレートからの`Restore-VMSnapshot`）まで
//! 完了させてから`IncusClient`を返す——2本目以降のセッションは「VMが起動し切るまで数十秒
//! ブロックされる」だけで、固定IP衝突や`WarmLock`による機能不全より遥かに良い。起動完了後は
//! 他セッションの`attach`は即座に返る（`refcount`を増やして既存の`IncusClient`を複製するだけ）。
//! `IncusClient`は内部が`String`（base_url）・`IpAddr`（Copy）・`reqwest::blocking::Client`
//! （内部Arc、実接続を保持しない設定オブジェクト）のみなので複製は安全（`derive(Clone)`）。
//!
//! **アイドル停止の粒度**: 今回は「refcountが0になったら即座に停止」のみを実装する。連続
//! セッション間でVM起動コストを省くアイドル猶予つきwarm維持は、スコープを抑えるため
//! Phase C以降へ送る（`~/.claude/plans/linked-plotting-pine.md`§1参照）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::vmsandbox::{
    reset_known_hosts_file, run_powershell, wait_for_guest_ready, EgressSession, IncusClient,
    VmError, VmSandboxConfig,
};

/// 常駐VMの固定名（旧`WARM_VM_NAME`を改称・流用。`ensure_warm_template`のcheckpointが
/// 捕捉する対象のVMそのものが、この常駐VM自身になる）。
pub const RESIDENT_VM_NAME: &str = "harness-tier3-resident";
/// 常駐VMの「起動済み・IP疎通済み・Incus trusted」状態を捕捉するproduction checkpoint名。
pub const RESIDENT_CHECKPOINT_NAME: &str = "harness-tier3-resident-base";

/// warm系操作（`ensure_warm_template`/`wait_for_guest_ready`）のタイムアウト定数。
const COLD_BOOT_GUEST_WAIT: Duration = Duration::from_secs(180);
const WARM_RESTORE_GUEST_WAIT: Duration = Duration::from_secs(30);

pub(crate) fn resident_diff_vhdx_path(config: &VmSandboxConfig) -> PathBuf {
    config.vm_work_dir.join("resident.diff.vhdx")
}

enum VmHostState {
    Stopped,
    Running {
        incus: IncusClient,
        diff_vhdx: PathBuf,
        refcount: u32,
        /// 現在egressを構成している全アクティブセッション（`slot` -> (コンテナIP,
        /// 許可ドメイン一覧)）。`configure_egress`/`release_egress`がこの集合全体から
        /// nginx/nftables設定を毎回再生成する（A-8是正、`crate::vmsandbox::apply_egress_ruleset`
        /// のdoc参照）。
        egress_sessions: HashMap<u8, (String, Vec<String>)>,
    },
}

pub struct VmHost {
    state: Mutex<VmHostState>,
}

static GLOBAL: OnceLock<VmHost> = OnceLock::new();

impl VmHost {
    pub fn global() -> &'static VmHost {
        GLOBAL.get_or_init(|| VmHost {
            state: Mutex::new(VmHostState::Stopped),
        })
    }

    /// 常駐VMへ接続する。停止中なら起動（`gc_orphan_sessions`で前回の孤児を先に撤収してから、
    /// `warm`ならcheckpoint経由、そうでなければコールドブート）してから`refcount: 1`で
    /// `Running`へ遷移する。既に起動中ならただ`refcount`を増やして既存の`IncusClient`を
    /// 複製して返す（ロック保持中は起動完了までブロックするが、2本目以降は起動待ちが
    /// 一度も走らないため即座に返る）。
    pub fn attach(&self, config: &VmSandboxConfig, warm: bool) -> Result<IncusClient, VmError> {
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            VmHostState::Running { incus, refcount, .. } => {
                *refcount += 1;
                Ok(incus.clone())
            }
            VmHostState::Stopped => {
                // このdaemonプロセス自身が唯一の常駐daemonである前提（S-2、固定パイプ名の
                // FILE_FLAG_FIRST_PIPE_INSTANCEで保証済み）なので、ここに来る時点で
                // 「現在アクティブなセッションはゼロ」が確定している。前回セッションが
                // daemonクラッシュ等で撤収できず残した孤児（同名の常駐VM）を、固定静的IP
                // 衝突を避けるため新規起動前に必ず撤収する。
                let _ = crate::vmsandbox::gc_orphan_sessions(config, "");

                let (incus, diff_vhdx) = boot_resident_vm(config, warm)?;
                crate::vm_ledger::record_vm_host(RESIDENT_VM_NAME, &diff_vhdx, std::process::id());
                let result = incus.clone();
                *guard = VmHostState::Running {
                    incus,
                    diff_vhdx,
                    refcount: 1,
                    egress_sessions: HashMap::new(),
                };
                Ok(result)
            }
        }
    }

    /// セッション終了時に呼ぶ。`refcount`をデクリメントし、0になったら常駐VMを実際に停止・
    /// 削除する（今回は即時停止のみ、アイドル猶予は実装しない——モジュールdoc参照）。
    /// `_config`は`attach`とのAPI対称性のために受け取るが、`teardown_vm`は固定vm_name+
    /// 保持済みdiff_vhdxのみで完結するため現状未使用。
    pub fn release(&self, _config: &VmSandboxConfig) {
        let mut guard = self.state.lock().unwrap();
        let should_stop = match &mut *guard {
            VmHostState::Running { refcount, .. } => {
                *refcount = refcount.saturating_sub(1);
                *refcount == 0
            }
            VmHostState::Stopped => false,
        };
        if should_stop {
            if let VmHostState::Running { diff_vhdx, .. } =
                std::mem::replace(&mut *guard, VmHostState::Stopped)
            {
                let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);
                crate::vm_ledger::remove_vm_host();
            }
        }
    }

    /// このセッション（`slot`）分のegress許可リストを構成/更新し、**現在アクティブな全
    /// セッション分をまとめて**nginx/nftables設定へ反映する（A-8是正: 1回の呼び出しがVM全体の
    /// 設定を丸ごと再生成するため、単一ロックの下で「集合を更新→再生成」を一体で行う）。
    pub fn configure_egress(
        &self,
        config: &VmSandboxConfig,
        ssh_key: &Path,
        slot: u8,
        container_ip: String,
        allow_domains: Vec<String>,
    ) -> Result<(), VmError> {
        let mut guard = self.state.lock().unwrap();
        let VmHostState::Running { egress_sessions, .. } = &mut *guard else {
            return Err(VmError::Incus(
                "configure_egress called while the resident VM is not running".to_string(),
            ));
        };
        egress_sessions.insert(slot, (container_ip, allow_domains));
        let active = egress_sessions_snapshot(egress_sessions);
        crate::vmsandbox::apply_egress_ruleset(config.guest_ip, ssh_key, &active)
    }

    /// セッション終了時、このセッション（`slot`）分のegress設定を集合から取り除き、残った
    /// アクティブセッション分だけでnginx/nftables設定を再生成する。VMが既に停止済み
    /// （teardownの後半でVM自体もrefcount 0になった場合）なら何もしない。
    pub fn release_egress(&self, config: &VmSandboxConfig, ssh_key: &Path, slot: u8) -> Result<(), VmError> {
        let mut guard = self.state.lock().unwrap();
        let VmHostState::Running { egress_sessions, .. } = &mut *guard else {
            return Ok(());
        };
        egress_sessions.remove(&slot);
        let active = egress_sessions_snapshot(egress_sessions);
        crate::vmsandbox::apply_egress_ruleset(config.guest_ip, ssh_key, &active)
    }

    /// 現在アタッチ中（refcount > 0）かどうか。テスト・診断専用。
    #[cfg(test)]
    fn is_running(&self) -> bool {
        matches!(*self.state.lock().unwrap(), VmHostState::Running { .. })
    }
}

fn egress_sessions_snapshot(sessions: &HashMap<u8, (String, Vec<String>)>) -> Vec<EgressSession> {
    sessions
        .iter()
        .map(|(slot, (container_ip, allow_domains))| EgressSession {
            slot: *slot,
            container_ip: container_ip.clone(),
            allow_domains: allow_domains.clone(),
        })
        .collect()
}

/// 常駐VMを実際に起動する（`VmHost::attach`のStopped分岐専用）。`warm`が真ならcheckpoint
/// テンプレート経由（破損時は1回だけ再provisioningし、それでも失敗すればコールドブートへ
/// フォールバック）、偽なら直接コールドブートする。
fn boot_resident_vm(config: &VmSandboxConfig, warm: bool) -> Result<(IncusClient, PathBuf), VmError> {
    if warm {
        if let Err(e) = ensure_warm_template(config) {
            eprintln!(
                "vm_host: failed to provision warm template, falling back to cold boot: {e}"
            );
            return cold_boot(config);
        }
        match restore_and_wait(config) {
            Ok(result) => return Ok(result),
            Err(e) => {
                eprintln!(
                    "vm_host: warm restore failed ({e}), discarding template and retrying once"
                );
            }
        }
        discard_warm_template(config);
        if let Err(e) = ensure_warm_template(config) {
            eprintln!(
                "vm_host: re-provisioning warm template failed, falling back to cold boot: {e}"
            );
            return cold_boot(config);
        }
        match restore_and_wait(config) {
            Ok(result) => Ok(result),
            Err(e) => {
                eprintln!(
                    "vm_host: warm restore failed again after re-provisioning ({e}), falling \
                     back to cold boot"
                );
                cold_boot(config)
            }
        }
    } else {
        cold_boot(config)
    }
}

fn cold_boot(config: &VmSandboxConfig) -> Result<(IncusClient, PathBuf), VmError> {
    let diff_vhdx = resident_diff_vhdx_path(config);
    std::fs::create_dir_all(&config.vm_work_dir)?;

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
New-VHD -Path '{diff}' -ParentPath '{golden}' -Differencing | Out-Null
New-VM -Name '{name}' -MemoryStartupBytes 2048MB -VHDPath '{diff}' -SwitchName '{switch}' -Generation 2 | Out-Null
Set-VMProcessor -VMName '{name}' -Count 2
Set-VM -Name '{name}' -AutomaticStopAction TurnOff -AutomaticStartAction Nothing
Set-VMFirmware -VMName '{name}' -SecureBootTemplate MicrosoftUEFICertificateAuthority
Start-VM -Name '{name}'
"#,
        diff = diff_vhdx.display(),
        golden = config.golden_vhdx.display(),
        name = RESIDENT_VM_NAME,
        switch = config.switch_name,
    );
    run_powershell(&script)?;

    reset_known_hosts_file()?;
    match wait_for_guest_ready(config, COLD_BOOT_GUEST_WAIT) {
        Ok(incus) => Ok((incus, diff_vhdx)),
        Err(e) => {
            // 実機E2Eで発見済みの教訓（`VmSession::start`の旧コメント参照）: ここで失敗した
            // VMを孤児のまま残すと、固定静的IPの制約上次回起動が必ずIP重複で壊れる。
            let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);
            Err(e)
        }
    }
}

fn restore_and_wait(config: &VmSandboxConfig) -> Result<(IncusClient, PathBuf), VmError> {
    let diff_vhdx = resident_diff_vhdx_path(config);
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
Stop-VM -Name '{name}' -TurnOff -Force -ErrorAction SilentlyContinue
Restore-VMSnapshot -VMName '{name}' -Name '{checkpoint}' -Confirm:$false
Start-VM -Name '{name}' -ErrorAction SilentlyContinue
"#,
        name = RESIDENT_VM_NAME,
        checkpoint = RESIDENT_CHECKPOINT_NAME,
    );
    run_powershell(&script)?;
    reset_known_hosts_file()?;
    let incus = wait_for_guest_ready(config, WARM_RESTORE_GUEST_WAIT)?;
    Ok((incus, diff_vhdx))
}

/// 常駐VM専用のproduction checkpointが既に存在するかを確認する。
fn warm_checkpoint_exists() -> Result<bool, VmError> {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         (Get-VMSnapshot -VMName '{name}' -Name '{checkpoint}' -ErrorAction SilentlyContinue).Name",
        name = RESIDENT_VM_NAME,
        checkpoint = RESIDENT_CHECKPOINT_NAME,
    );
    let stdout = run_powershell(&script)?;
    Ok(!stdout.trim().is_empty())
}

/// 常駐VM専用のcheckpointを用意する（低速パス・一度きり）。既に存在すればスキップする。
/// 無ければ: 差分VHDX作成 → `New-VM`+`Start-VM` → 疎通確認（firstbootの完了を含む長めの
/// タイムアウト） → `Checkpoint-VM`で「完全起動済み・IP疎通済み・Incus trusted」状態を
/// 捕捉する。途中で失敗した場合はVM自体を撤収し、次回呼び出しで最初からやり直せるようにする。
fn ensure_warm_template(config: &VmSandboxConfig) -> Result<(), VmError> {
    if warm_checkpoint_exists()? {
        return Ok(());
    }

    let diff_vhdx = resident_diff_vhdx_path(config);
    std::fs::create_dir_all(&config.vm_work_dir)?;

    // 前回の途中失敗（checkpoint作成前にVMだけ残った等）の後始末。存在しなければ無害に失敗する。
    let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
New-VHD -Path '{diff}' -ParentPath '{golden}' -Differencing | Out-Null
New-VM -Name '{name}' -MemoryStartupBytes 2048MB -VHDPath '{diff}' -SwitchName '{switch}' -Generation 2 | Out-Null
Set-VMProcessor -VMName '{name}' -Count 2
Set-VM -Name '{name}' -AutomaticStopAction TurnOff -AutomaticStartAction Nothing
Set-VMFirmware -VMName '{name}' -SecureBootTemplate MicrosoftUEFICertificateAuthority
Start-VM -Name '{name}'
"#,
        diff = diff_vhdx.display(),
        golden = config.golden_vhdx.display(),
        name = RESIDENT_VM_NAME,
        switch = config.switch_name,
    );
    run_powershell(&script)?;

    if let Err(e) = wait_for_guest_ready(config, COLD_BOOT_GUEST_WAIT) {
        let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);
        return Err(e);
    }

    if let Err(e) = run_powershell(&format!(
        "Checkpoint-VM -Name '{name}' -SnapshotName '{checkpoint}'",
        name = RESIDENT_VM_NAME,
        checkpoint = RESIDENT_CHECKPOINT_NAME,
    )) {
        let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);
        return Err(e);
    }

    Ok(())
}

/// 常駐VM専用のcheckpointテンプレート自体を破棄する（破損検出時）。次回の`ensure_warm_template`
/// 呼び出しで最初からやり直す。
fn discard_warm_template(config: &VmSandboxConfig) {
    let diff_vhdx = resident_diff_vhdx_path(config);
    let _ = crate::vmsandbox::teardown_vm(RESIDENT_VM_NAME, &diff_vhdx);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VmHost::global()`はプロセス全体で単一のインスタンスを返す（`OnceLock`の性質そのものの
    /// 確認。実際のVM起動を伴う`attach`/`release`のE2Eは実機でのみ検証可能）。
    #[test]
    fn global_returns_the_same_instance_across_calls() {
        let a = VmHost::global() as *const VmHost;
        let b = VmHost::global() as *const VmHost;
        assert_eq!(a, b);
    }

    #[test]
    fn fresh_host_starts_stopped_not_running() {
        // 他のテストと同一プロセス内で`GLOBAL`を共有するため、既に別テストがattachしていない
        // 前提が壊れる可能性がある。ここでは`VmHost::global()`を直接使わず、ロジックのみを
        // 独立したインスタンスで確認する。
        let host = VmHost {
            state: Mutex::new(VmHostState::Stopped),
        };
        assert!(!host.is_running());
    }

    #[test]
    fn release_on_stopped_host_is_a_harmless_noop() {
        let host = VmHost {
            state: Mutex::new(VmHostState::Stopped),
        };
        // `release`はconfig引数を使うがStopped状態では参照しない経路のみを通るため、
        // 実際のVM操作は発生しない（PowerShell呼び出しなし）。
        let config = VmSandboxConfig::default();
        host.release(&config);
        assert!(!host.is_running());
    }
}
