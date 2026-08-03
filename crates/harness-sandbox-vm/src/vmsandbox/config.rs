//! Tier3の設定型とプロセス起動の共通ヘルパー。
//!
//! `VmError`（このTier全体のエラー型）・`VmSandboxConfig`（ゴールデン像のパス・ネットワーク
//! 設定等）・`run_powershell`（Hyper-V/SMB操作のshell-out）・`unique_session_id`。

use super::*;

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("powershell command failed: {0}")]
    PowerShell(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("incus api error: {0}")]
    Incus(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::Io(e.to_string())
    }
}

/// ワークスペース共有方式（`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4）。移行期間中の
/// 切り替えフラグ（実機E2Eで問題が出た場合に即座に`CopyInOut`へフォールバックできるように
/// する、プラン記載の移行手順）。既定は`CopyInOut`（既存の実装済み・実績のある経路）のまま。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceShareMode {
    /// 従来方式: セッション境界での`copy_in_workspace`/`copy_out_workspace`（Incus file
    /// push/pull、1ファイル1リクエスト）。大規模ワークスペース（`target/`等）で300秒IPC
    /// タイムアウトを起こす既知の欠陥がある（`plans/TIER1A-OPEN-ISSUES.md`項目9）。
    CopyInOut,
    /// 新方式: WindowsホストでSMB共有を切り、ゲスト内から`mount -t cifs`、Incusの
    /// disk deviceでコンテナへbind-mountするライブ共有。
    Cifs,
}

/// 固定の運用規約（モジュールdoc参照）。
pub struct VmSandboxConfig {
    pub golden_vhdx: PathBuf,
    pub switch_name: String,
    pub guest_ip: IpAddr,
    pub incus_port: u16,
    pub vm_work_dir: PathBuf,
    /// ウォームスタート（`--tier3-warm`、フェーズB）を使うか。既定はfalse（毎回コールドブート）。
    pub warm: bool,
    pub workspace_share_mode: WorkspaceShareMode,
    /// 内部vSwitchのホスト側ゲートウェイIP（`WorkspaceShareMode::Cifs`でSMB共有先として
    /// ゲストから参照する。`plans/vm-spike/RESULTS.md`§3.6で確立した固定値、モジュールdoc
    /// 参照）。`guest_ip`と同じ`/24`の`.1`。
    pub smb_host_ip: IpAddr,
}

impl Default for VmSandboxConfig {
    fn default() -> Self {
        Self {
            golden_vhdx: PathBuf::from(
                r"C:\ProgramData\harness\golden-images\almalinux-golden.vhdx",
            ),
            switch_name: "harness-tier3-outer-internal".to_string(),
            guest_ip: "172.20.100.10".parse().unwrap(),
            incus_port: 8443,
            vm_work_dir: PathBuf::from(r"C:\ProgramData\harness\vm-sessions"),
            warm: false,
            // 実機E2E確認（CIFS共有作成・双方向マウント・disk device bind-mount・
            // ファイアウォールスコープ限定、いずれも実機で確認済み）を経て、`Cifs`を既定に
            // 昇格した。`copy_in_workspace`（旧方式）は`target/`等の大規模ワークスペースで
            // 300秒IPCタイムアウトを起こす既知の欠陥があり（本来の問題）、これが解消される
            // のが今回の目的そのもの。何か問題が出た場合の逃げ道として
            // `HARNESS_TIER3_CIFS_WORKSPACE=0`で旧方式へ明示的に戻せるようにしておく。
            workspace_share_mode: if std::env::var("HARNESS_TIER3_CIFS_WORKSPACE").as_deref()
                == Ok("0")
            {
                WorkspaceShareMode::CopyInOut
            } else {
                WorkspaceShareMode::Cifs
            },
            smb_host_ip: "172.20.100.1".parse().unwrap(),
        }
    }
}

pub(crate) fn run_powershell(script: &str) -> Result<String, VmError> {
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        // **実機で判明した罠**: harnessの管理者権限操作を「常駐管理者PowerShell(pwsh、
        // PowerShell 7)セッションから都度呼ぶ」運用（グローバルCLAUDE.md記載の定石）だと、
        // 起動する`powershell.exe`(Windows PowerShell 5.1)がpwsh7側の`PSModulePath`を
        // そのまま継承し、5.1組み込みの`Microsoft.PowerShell.Security`モジュールがpwsh7の
        // 非互換な同名モジュールに覆い隠される。この状態で`ConvertTo-SecureString`等の
        // 同モジュール由来コマンドレットを叩くと、型データの重複登録エラーを経て
        // 非終端の`CommandNotFoundException`（オートロード失敗）を静かに返し、後続の
        // `New-LocalUser`等が空/nullな入力のまま実行され続けるという壊れ方をする
        // （実機で`ConvertTo-SecureString`のみ再現・特定。`PSModulePath`を子プロセスの
        // 環境から除去すると5.1が自前の既定パスで正しく解決し直ちに解消することを確認済み）。
        .env_remove("PSModulePath")
        .output()
        .map_err(|e| VmError::PowerShell(format!("failed to spawn powershell.exe: {e}")))?;
    if !output.status.success() {
        return Err(VmError::PowerShell(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            harness_sandbox::decode_console_bytes(&output.stderr)
        )));
    }
    Ok(harness_sandbox::decode_console_bytes(&output.stdout).trim().to_string())
}

/// **Phase B実機E2Eで発見したバグ**: `std::process::id()`+ミリ秒タイムスタンプという
/// 旧来の一意性根拠は、「1セッション=1回きりのdaemon起動」だった旧モデルでは
/// （毎回別のPIDになるため）十分だったが、常駐daemonが複数セッションを同一プロセス内の
/// 複数スレッドから処理するようになった今、`std::process::id()`は全セッションで**同じ値**に
/// なる。2セッションがほぼ同時に本関数を呼ぶと同じミリ秒のタイムスタンプになり得るため、
/// 実機E2Eで実際に`session_id`（延いてはコンテナ名）の衝突が発生した
/// （`Instance "harness-harness-tier3-<pid>-<millis>" already exists`）。プロセス内の
/// アトミックカウンタを追加し、同一プロセス・同一ミリ秒でも重複しないようにする
/// （`vmsandboxd::unique_pipe_name`と同じパターン）。
pub(crate) fn unique_session_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "harness-tier3-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        n
    )
}

