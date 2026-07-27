//! Tier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）の実行機構本体
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md`、`plans/vm-spike/RESULTS.md`）。
//!
//! `harness-vmsandboxd`（常駐デーモン、`crate::vmsandboxd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのHyper-V操作を直接呼ばない（D-21）。Incus REST APIはmTLS越しの
//! ネットワーク呼び出しであり管理者権限を要しないが、デーモンプロセス内に閉じて構わないため
//! ここへ同居させる。
//!
//! **Phase 1（`run_shell`統合）+ Phase 2（egress許可リスト統合）は完了・実機E2E確認済み**
//! （`RESULTS.md`§3.9/§3.10）。egress許可リスト（Incus ACL + nftables DNAT + SNI preread
//! プロキシ + 監査ログ）は`allow_domains`が非空の場合のみ構成し、空なら無制限egressのまま
//! （`--net-allow-domain`未指定時の後方互換）。ゴールデン像へのIncusクライアント証明書焼き込み
//! も完了しており、ランタイムはSSH・ペアリング不要でmTLS直結できる。
//!
//! **Phase 3も実装済み（台帳+GC・ウォームスタート）**:
//! - **台帳+次回起動GC（D-24）**: `crate::vm_ledger`が`%APPDATA%\harness\tier3-vm-ledger.json`
//!   へVM生成を記録し、`gc_orphan_sessions`が新規VM起動前（`vmsandboxd::serve_inner`）に
//!   前回セッションの孤児VM・差分VHDXを撤収する。手動運用・障害調査用の明示コマンド
//!   `harness tier3 gc`も用意した（`vmsandboxd::run_gc_only`/`serve_gc`）。
//! - **ウォームスタート**（`--tier3-warm`、既定off）: `ensure_warm_template`が「起動済み・
//!   IP疎通済み・Incus trusted」状態のproduction checkpoint（`WARM_CHECKPOINT_NAME`）を
//!   持つ永続VM（`WARM_VM_NAME`）を一度だけ用意する。`VmSession::start_warm_or_fallback`が
//!   `Restore-VMSnapshot`で毎回このcheckpointへ巻き戻してから起動することで、コールド
//!   ブート（起動+firstboot）のコストを省く。固定静的IPの制約上Tier3は元々同時1セッションが
//!   前提のため、ウォームVMは`WarmLock`（ファイルロック、`vm_work_dir/tier3-warm.lock`）で
//!   直列化する。破損（Restore失敗・疎通タイムアウト等）を検出した場合はテンプレートを
//!   1回だけ破棄して再provisioning、それも失敗すればコールドブートへ自動フォールバックする。
//!
//! **依然として未実装のまま残っている範囲**（`plans/TIER1A-OPEN-ISSUES.md`項目9でフォロー
//! アップする、Phase 3の残り）:
//! - ワークスペース共有はセッション境界でのcopy-in/copy-outのみ（D-22のライブマウントは未実装）。
//!
//! 固定の運用規約（`plans/vm-spike/RESULTS.md`§3.6/§3.7で確立、実機E2E確認済み）:
//! - ゴールデン親VHDX: `C:\ProgramData\harness\golden-images\almalinux-golden.vhdx`
//! - 内部vSwitch: `harness-tier3-outer-internal`（`172.20.100.0/24`、ホスト側ゲートウェイ
//!   `172.20.100.1`、`New-NetNat`によるegress）
//! - ゲスト静的IP: `172.20.100.10`（ゴールデン像へ焼き込み済み、DHCP不要）
//! - Incus API: `172.20.100.10:8443`（mTLS、クライアント証明書はゴールデン像へ焼き込み済み。
//!   `harness-firstboot.sh`のステップ3.5が起動直後に`incus config trust add-certificate`で
//!   自動信頼登録する）
//! - SSHホスト制御チャネル（Phase 2で追加）: `root`鍵認証限定、harness専用ed25519鍵ペアを
//!   `%APPDATA%\harness\config\tier3-ssh\`に保持しゴールデン像へ焼き込み済み。AlmaLinux VM
//!   自体（ホストOS）へnginx/nftables設定を配置・起動するために使う（Incus REST APIはコンテナ
//!   管理のみでVM自体のOS操作はできないため）。

use std::io::Write;
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Deserialize;

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

/// ウォームスタート（production checkpoint + Restore方式、`plans/DESIGN-SANDBOX-VMISOLATION.md`
/// §2.1）で使う固定名。固定静的IPの制約上Tier3は元々同時1セッションのみが成立条件のため、
/// ウォームVMはマシン全体で1つに固定する（`crate::vm_ledger::WARM_VM_NAME`と同じ値を指す
/// 定数だが、循環依存を避けるためここにも定義する）。
pub const WARM_VM_NAME: &str = crate::vm_ledger::WARM_VM_NAME;
/// ウォームVMの「起動済み・IP疎通済み・Incus trusted」状態を捕捉するproduction checkpoint名
/// （`Checkpoint-VM -SnapshotName`）。
pub const WARM_CHECKPOINT_NAME: &str = "harness-warm-base";

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
            workspace_share_mode: if std::env::var("HARNESS_TIER3_CIFS_WORKSPACE").as_deref() == Ok("0") {
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
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// ウォームVM専用の直列化ロック（`vm_work_dir/tier3-warm.lock`）。固定静的IPの制約上、
/// Tier3は元々同時1セッションのみが成立条件（2 VMが同じIPを主張すると破綻する、
/// `VmSession::start`のdoc参照）だが、ウォームVMは複数daemonプロセスから同時に
/// Restore/execされると壊れるため、明示的なファイルロックで直列化する。
///
/// ロックファイルには取得元プロセスのPIDを書き込む。daemonクラッシュでロックファイルだけ
/// 残った場合の回収のため、取得を試みて失敗した際はPIDの生存確認でstaleness判定し
/// （`select_orphans`と同じbelt-and-suspenders思想）、stale であれば削除して再試行する。
pub struct WarmLock {
    path: PathBuf,
}

impl WarmLock {
    /// ロック取得を試みる。取得できるまで一定間隔でリトライし、`timeout`超過でエラーにする。
    pub fn acquire(config: &VmSandboxConfig, timeout: Duration) -> Result<Self, VmError> {
        let path = config.vm_work_dir.join("tier3-warm.lock");
        std::fs::create_dir_all(&config.vm_work_dir)?;
        let deadline = Instant::now() + timeout;
        let poll_interval = Duration::from_millis(500);
        loop {
            if try_create_lock_file(&path).is_ok() {
                return Ok(Self { path });
            }
            if lock_is_stale(&path) {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if Instant::now() >= deadline {
                return Err(VmError::Timeout(format!(
                    "timed out waiting for tier3 warm VM lock: {}",
                    path.display()
                )));
            }
            std::thread::sleep(poll_interval);
        }
    }
}

impl Drop for WarmLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn try_create_lock_file(path: &Path) -> Result<(), VmError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    write!(file, "{}", std::process::id())?;
    Ok(())
}

/// ロックファイルの所有者PIDが既に終了しているかを確認する。読めない/PIDが不正な形式の
/// 場合は安全側（stale扱いしない=false、他プロセスが書き込み中の可能性を尊重する）に倒す。
fn lock_is_stale(path: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<u32>() else {
        return false;
    };
    !process_is_alive(pid)
}

fn process_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

/// ウォームVM専用の差分VHDXパス（`vm_work_dir/warm.diff.vhdx`、セッションごとの
/// `<session_id>.diff.vhdx`とは別枠。ウォームVMはセッションをまたいで生存し続けるため
/// 使い捨てにならない、B3/B5参照）。
pub fn warm_diff_vhdx_path(config: &VmSandboxConfig) -> PathBuf {
    config.vm_work_dir.join("warm.diff.vhdx")
}

fn unique_session_id() -> String {
    format!(
        "harness-tier3-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    )
}

/// クライアント証明書のホスト側保存先（`%APPDATA%\harness\tier3-incus-client\`）。
fn client_cert_dir() -> Result<PathBuf, VmError> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-incus-client"))
        .ok_or_else(|| VmError::Io("could not resolve config dir".to_string()))
}

/// harness専用のIncus mTLSクライアント証明書を用意する（無ければ`openssl`で自己署名生成、
/// あれば再利用）。Phase 1ではこの証明書をホスト側に保持し、`VmSession::start`のたびに
/// Incusサーバーへペアリングする（ゴールデン像への焼き込みは別ラウンド、モジュールdoc参照）。
pub fn ensure_client_cert() -> Result<(PathBuf, PathBuf), VmError> {
    let dir = client_cert_dir()?;
    std::fs::create_dir_all(&dir)?;
    let crt = dir.join("client.crt");
    let key = dir.join("client.key");
    if crt.exists() && key.exists() {
        return Ok((crt, key));
    }
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &key.to_string_lossy(),
            "-out",
            &crt.to_string_lossy(),
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=harness-tier3-client",
        ])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn openssl: {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "openssl req failed with status {status:?}"
        )));
    }
    Ok((crt, key))
}

/// harness専用のSSH鍵ペアのホスト側保存先（`%APPDATA%\harness\config\tier3-ssh\`、
/// `client_cert_dir`と同じ`ProjectDirs::config_dir()`配下）。
fn ssh_keypair_dir() -> Result<PathBuf, VmError> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-ssh"))
        .ok_or_else(|| VmError::Io("could not resolve config dir".to_string()))
}

/// Phase 2: AlmaLinux VM自体（外層ホストOS）へSNIプロキシ・nftablesを設定するための
/// ホスト制御チャネル（`plans/DESIGN-SANDBOX-VMISOLATION.md`が将来像として挙げる
/// hvsocketゲストエージェントの代わりに、SSH鍵認証で代替する。ユーザー承認済みの設計、
/// `plans/TIER1A-OPEN-ISSUES.md`項目9参照）。無ければ`ssh-keygen`で生成し、あれば再利用する。
/// 公開鍵はゴールデン像の`/root/.ssh/authorized_keys`へ焼き込み済み（実機作業）。
pub fn ensure_ssh_keypair() -> Result<PathBuf, VmError> {
    let dir = ssh_keypair_dir()?;
    std::fs::create_dir_all(&dir)?;
    let private_key = dir.join("id_ed25519");
    let public_key = dir.join("id_ed25519.pub");
    if private_key.exists() && public_key.exists() {
        // 既存鍵でも毎回ACLを締め直す（後述の罠を踏んだ既存鍵が残っている場合の救済）。
        harden_private_key_acl(&private_key)?;
        return Ok(private_key);
    }
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "harness-tier3",
            "-f",
        ])
        .arg(&private_key)
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn ssh-keygen: {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "ssh-keygen failed with status {status:?}"
        )));
    }
    harden_private_key_acl(&private_key)?;
    Ok(private_key)
}

/// 秘密鍵ファイルのWindows ACLを本人のみへ締める（Unixの`chmod 600`相当）。
/// **実機で判明した罠**: `ssh-keygen`が作るファイルは既定で親ディレクトリのACLを継承する。
/// このマシンでは`%APPDATA%\harness\config\`の継承ACLに他ユーザー/グループ（例:
/// `CodexSandboxUsers`）への読み取り権限が含まれており、Windows版OpenSSHクライアント
/// （`C:\Windows\System32\OpenSSH\ssh.exe`）はこれを検知すると
/// `UNPROTECTED PRIVATE KEY FILE`警告を出して鍵の使用自体を拒否する（`Permission denied`）。
/// Git BashのMSYS版`ssh.exe`はこのACLチェックをしない/緩いため、bashから手動で`ssh -i`を
/// 叩いた検証では再現せず、原因特定に時間を要した。`icacls`で継承を切り本人のみに絞る。
fn harden_private_key_acl(path: &Path) -> Result<(), VmError> {
    let username = std::env::var("USERNAME")
        .map_err(|_| VmError::Io("USERNAME environment variable not set".to_string()))?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r"])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn icacls (inheritance): {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "icacls /inheritance:r failed with status {status:?}"
        )));
    }
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/grant:r", &format!("{username}:F")])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn icacls (grant): {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "icacls /grant:r failed with status {status:?}"
        )));
    }
    Ok(())
}

/// SSHの`known_hosts`書き込み先（実ファイル）。`plans/vm-spike`のホスト鍵はセッションごとに
/// 再生成される（firstboot）ため検証はしない（`StrictHostKeyChecking=no`）が、その書き込み先
/// **実機で判明した罠**: 当初Unix流に`UserKnownHostsFile=NUL`（Windowsのnullデバイス）を
/// 指定していたところ、Rustの`std::process::Command::new("ssh")`経由（＝`C:\Windows\System32\
/// OpenSSH\ssh.exe`、ネイティブWindows版OpenSSHクライアント）では書き込みに失敗し非ゼロ終了
/// していた（stderrには害の無い"Permanently added..."警告しか出ないため原因特定に時間を要した）。
/// Git BashのMSYS版`ssh.exe`（bashから直接叩いた場合に解決される別バイナリ）ではこの問題が
/// 再現しなかった——ビルドの違いにより`NUL`の扱いが異なる。実在する書き込み可能ファイルへの
/// 実パスを指定することで解消する（`tier3-ssh`ディレクトリ配下、セッションをまたいで蓄積
/// しても実害は無い——検証自体をスキップしているため単なるスクラッチファイル）。
fn known_hosts_file() -> Result<PathBuf, VmError> {
    let dir = ssh_keypair_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("known_hosts"))
}

/// **実機で判明した罠**: `guest_ip`はセッションをまたいで常に同一の固定IP
/// （`VmSandboxConfig::default`参照）だが、SSHホスト鍵はfirstbootのたびに個体ごと
/// 再生成される。`known_hosts_file()`が返す実ファイルへセッションをまたいで書き込みが
/// 蓄積されると、2セッション目以降は同一IPに対し「既知だが鍵が変わった」状態になり、
/// `StrictHostKeyChecking=no`は素通りしない（OpenSSHは「未知のホストへの初回接続」だけを
/// 許容し、MITM疑いのある「鍵が変わった」状態は無条件に拒否するため）。検証自体を最初から
/// 行わない設計（D-20/D-21）である以上、このファイルを残す理由が無いため、セッション開始の
/// たびに空へ戻す。
fn reset_known_hosts_file() -> Result<(), VmError> {
    let path = known_hosts_file()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(VmError::Io(e.to_string())),
    }
}

/// AlmaLinux VM自体（`root`）へSSH鍵認証でコマンドを実行する（`ssh.exe`、Windows 10 1809+
/// 標準搭載のOpenSSHクライアントをshell-out。`run_powershell`と同じ既存パターン、`russh`等の
/// 新規重量依存は追加しない）。ホスト鍵はセッションごとに再生成される（firstboot）ため
/// `StrictHostKeyChecking=no`で検証をスキップする（このVMはharnessが固定管理下ロケーションに
/// 用意し毎セッション使い捨てる前提、D-20/D-21）。
fn ssh_exec(
    host: IpAddr,
    key_path: &Path,
    cmd: &str,
    timeout: Duration,
) -> Result<(String, String, i32), VmError> {
    let known_hosts = known_hosts_file()?;
    let output = std::process::Command::new("ssh")
        .args([
            "-i",
            &key_path.to_string_lossy(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
        ])
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args([
            "-o",
            &format!("ConnectTimeout={}", timeout.as_secs().max(1)),
            &format!("root@{host}"),
            cmd,
        ])
        .output()
        .map_err(|e| VmError::Io(format!("failed to spawn ssh: {e}")))?;
    Ok((
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    ))
}

/// `ssh_exec`の非ゼロ終了を`VmError`へ畳み込む版（設定投入等、成功必須の呼び出し向け）。
fn ssh_exec_checked(host: IpAddr, key_path: &Path, cmd: &str, timeout: Duration) -> Result<String, VmError> {
    let (stdout, stderr, code) = ssh_exec(host, key_path, cmd, timeout)?;
    if code != 0 {
        return Err(VmError::Io(format!(
            "ssh command failed (exit={code}): {cmd}\nstdout={stdout}\nstderr={stderr}"
        )));
    }
    Ok(stdout)
}

/// AlmaLinux VM自体（`root`）へファイルを配置する（`ssh ... 'cat > path'`にstdin経由で
/// 内容を流し込む。Incus内のコンテナではなくVMのホストOS側へ書く点が`IncusClient::push_file`
/// との違い）。
fn ssh_push_file(host: IpAddr, key_path: &Path, contents: &[u8], remote_path: &str) -> Result<(), VmError> {
    let known_hosts = known_hosts_file()?;
    let mut child = std::process::Command::new("ssh")
        .args([
            "-i",
            &key_path.to_string_lossy(),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
        ])
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args([&format!("root@{host}"), &format!("cat > {remote_path}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VmError::Io(format!("failed to spawn ssh: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| VmError::Io("ssh stdin unavailable".to_string()))?
        .write_all(contents)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(VmError::Io(format!(
            "ssh_push_file to {remote_path} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Incus REST APIのmTLSクライアント（`plans/vm-spike/incus_common.py`のRust移植）。
pub struct IncusClient {
    base_url: String,
    host_ip: IpAddr,
    http: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct IncusOperation {
    id: String,
}

impl IncusClient {
    pub fn new(host: IpAddr, port: u16, client_crt: &Path, client_key: &Path) -> Result<Self, VmError> {
        let crt_pem = std::fs::read(client_crt)?;
        let key_pem = std::fs::read(client_key)?;
        let mut pem = crt_pem;
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&key_pem);
        let identity = reqwest::Identity::from_pem(&pem)
            .map_err(|e| VmError::Incus(format!("failed to build client identity: {e}")))?;
        let http = reqwest::blocking::Client::builder()
            .identity(identity)
            .danger_accept_invalid_certs(true) // Incusサーバーの自己署名証明書（spikeと同じ運用）
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| VmError::Incus(format!("failed to build http client: {e}")))?;
        Ok(Self {
            base_url: format!("https://{host}:{port}"),
            host_ip: host,
            http,
        })
    }

    pub fn host_ip(&self) -> IpAddr {
        self.host_ip
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(u16, serde_json::Value), VmError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .map_err(|e| VmError::Incus(format!("request to {url} failed: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .map_err(|e| VmError::Incus(format!("failed to read response body: {e}")))?;
        let value: serde_json::Value = if text.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text)
                .map_err(|e| VmError::Incus(format!("failed to parse response json: {e}")))?
        };
        Ok((status, value))
    }

    /// `GET /1.0`で`auth: trusted`が返るかを確認する（mTLS疎通+信頼確認）。
    pub fn is_trusted(&self) -> Result<bool, VmError> {
        let (_status, value) = self.request(reqwest::Method::GET, "/1.0", None)?;
        Ok(value
            .get("metadata")
            .and_then(|m| m.get("auth"))
            .and_then(|a| a.as_str())
            == Some("trusted"))
    }

    fn wait_operation(&self, op_path: &str, timeout: Duration) -> Result<serde_json::Value, VmError> {
        let wait_path = format!("{op_path}/wait?timeout={}", timeout.as_secs());
        let (status, value) = self.request(reqwest::Method::GET, &wait_path, None)?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "operation wait failed: status={status} body={value}"
            )));
        }
        let metadata = value.get("metadata").cloned().unwrap_or(serde_json::Value::Null);
        let op_status = metadata
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if op_status != "Success" {
            let err = metadata
                .get("err")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown operation error");
            return Err(VmError::Incus(format!("operation did not succeed: {err}")));
        }
        Ok(metadata)
    }

    pub fn create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
        let body = serde_json::json!({
            "name": name,
            "type": "container",
            "source": {
                "type": "image",
                "mode": "pull",
                "server": "https://images.linuxcontainers.org",
                "protocol": "simplestreams",
                "alias": image_alias,
            },
        });
        let (status, value) =
            self.request(reqwest::Method::POST, "/1.0/instances", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_container failed: status={status} body={value}"
            )));
        }
        let op: IncusOperation = serde_json::from_value(
            value.get("operation").cloned().unwrap_or(serde_json::Value::Null),
        )
        .or_else(|_| {
            // 一部のIncusバージョンは`metadata.id`にoperation idを積む。
            serde_json::from_value::<IncusOperation>(
                value.get("metadata").cloned().unwrap_or(serde_json::Value::Null),
            )
        })
        .map_err(|e| VmError::Incus(format!("failed to parse operation id: {e}")))?;
        self.wait_operation(&format!("/1.0/operations/{}", op.id), Duration::from_secs(180))?;
        Ok(())
    }

    pub fn start_container(&self, name: &str) -> Result<(), VmError> {
        let body = serde_json::json!({ "action": "start", "timeout": 30 });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{name}/state"),
            Some(body),
        )?;
        if status != 202 {
            return Err(VmError::Incus(format!(
                "start_container failed: status={status} body={value}"
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    pub fn stop_container(&self, name: &str) -> Result<(), VmError> {
        let body = serde_json::json!({ "action": "stop", "timeout": 30, "force": true });
        let _ = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{name}/state"),
            Some(body),
        )?;
        Ok(())
    }

    pub fn delete_container(&self, name: &str) -> Result<(), VmError> {
        let _ = self.request(
            reqwest::Method::DELETE,
            &format!("/1.0/instances/{name}"),
            None,
        )?;
        Ok(())
    }

    /// `POST /1.0/instances/<name>/exec`（`record-output`方式、websocket不使用）。
    /// `plans/vm-spike/incus_common.py`の`exec_cmd`と同じAPI経路。
    pub fn exec(
        &self,
        name: &str,
        argv: &[&str],
        cwd: &str,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let mut environment = serde_json::Map::new();
        for (k, v) in env {
            environment.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        let body = serde_json::json!({
            "command": argv,
            "cwd": cwd,
            "environment": environment,
            "wait-for-websocket": false,
            "record-output": true,
            "interactive": false,
        });
        let (status, value) = self.request(
            reqwest::Method::POST,
            &format!("/1.0/instances/{name}/exec"),
            Some(body),
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "exec failed to start: status={status} body={value}"
            )));
        }
        let op_id = value
            .get("operation")
            .and_then(|o| o.as_str())
            .map(|s| s.trim_start_matches("/1.0/operations/").to_string())
            .or_else(|| {
                value
                    .get("metadata")
                    .and_then(|m| m.get("id"))
                    .and_then(|i| i.as_str())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| VmError::Incus("exec response has no operation id".to_string()))?;

        let metadata = self.wait_operation(&format!("/1.0/operations/{op_id}"), timeout)?;
        let exec_metadata = metadata.get("metadata");
        let exit_code = exec_metadata
            .and_then(|m| m.get("return"))
            .and_then(|r| r.as_i64())
            .map(|n| n as i32);

        // record-outputの標準出力/標準エラーは、operationのmetadata.outputが持つ実際のhref
        // （例: `/1.0/operations/<id>/logs/1`）から取得する。**実機で判明した罠**: このhrefは
        // `/logs/`（複数形）であり、当初`/log/`（単数形）と誤って決め打ちしていたため常に404に
        // なり、`fetch_exec_log`が「ログ無し=空文字列」としてこれを静かに握りつぶしていた
        // （exit codeは正しく取れるため一見成功したように見え、発見が遅れた）。
        let output = exec_metadata.and_then(|m| m.get("output"));
        let stdout_href = output.and_then(|o| o.get("1")).and_then(|h| h.as_str());
        let stderr_href = output.and_then(|o| o.get("2")).and_then(|h| h.as_str());
        let stdout = self.fetch_exec_log(stdout_href, &op_id, "1")?;
        let stderr = self.fetch_exec_log(stderr_href, &op_id, "2")?;
        Ok((stdout, stderr, exit_code))
    }

    fn fetch_exec_log(&self, href: Option<&str>, op_id: &str, fd: &str) -> Result<String, VmError> {
        let url = match href {
            Some(h) => format!("{}{h}", self.base_url),
            None => format!("{}/1.0/operations/{op_id}/logs/{fd}", self.base_url),
        };
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| VmError::Incus(format!("fetch_exec_log failed: {e}")))?;
        if !resp.status().is_success() {
            // ログが本当に存在しない場合（コマンドが何も出力しなかった等）は空文字列扱いにする。
            return Ok(String::new());
        }
        resp.text()
            .map_err(|e| VmError::Incus(format!("failed to read exec log body: {e}")))
    }

    /// `incus file push`相当（`POST /1.0/instances/<name>/files?path=<path>`）。
    pub fn push_file(&self, name: &str, contents: &[u8], remote_path: &str) -> Result<(), VmError> {
        let url = format!(
            "{}/1.0/instances/{name}/files?path={}",
            self.base_url,
            urlencoding_path(remote_path)
        );
        let resp = self
            .http
            .post(&url)
            .header("X-Incus-mode", "0644")
            .header("X-Incus-type", "file")
            .body(contents.to_vec())
            .send()
            .map_err(|e| VmError::Incus(format!("push_file failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(VmError::Incus(format!(
                "push_file failed: status={} path={remote_path}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// `POST /1.0/network-acls`: 「tcp/443への直接egressを宛先指定なしで許可、それ以外は
    /// コンテナのdevice側でdrop」という許可リストを1本作る（`plans/vm-spike/RESULTS.md`
    /// §3.8で実機実証済みの構成。既存の同名ACLがあれば削除してから作り直す）。
    /// **実機で判明した罠**（`RESULTS.md`§3.8で既知の限界として記録済みだったもの）: tcp/443
    /// のみ許可すると、コンテナ内のDNS解決（UDP/TCP 53）自体がACLでブロックされ、
    /// `wget https://example.com/`のような普通の呼び出しが名前解決の時点で失敗する
    /// （`bad address`）。SNIベースの許可/拒否は実際の443接続でのみ強制されるため、DNS問い合わせ
    /// 自体は宛先を問わず許可しても実害は小さい（漏れる情報は問い合わせたドメイン名のみで、
    /// 実際のデータ疎通は引き続きSNIプロキシが強制する）。
    pub fn create_network_acl(&self, name: &str) -> Result<(), VmError> {
        let _ = self.request(
            reqwest::Method::DELETE,
            &format!("/1.0/network-acls/{name}"),
            None,
        )?;
        let body = serde_json::json!({
            "name": name,
            "description": "harness Tier3 egress allowlist (SNI proxy transparent redirect)",
            "egress": [
                {"action": "allow", "protocol": "tcp", "destination_port": "443", "state": "enabled"},
                {"action": "allow", "protocol": "udp", "destination_port": "53", "state": "enabled"},
                {"action": "allow", "protocol": "tcp", "destination_port": "53", "state": "enabled"},
            ],
            "ingress": [],
        });
        let (status, value) =
            self.request(reqwest::Method::POST, "/1.0/network-acls", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_network_acl failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// コンテナの`eth0`デバイスへACLを適用し、既定egressをdropにする
    /// （`security.acls.default.egress.action=drop`、`RESULTS.md`§3.8）。
    pub fn attach_acl_to_container(&self, container_name: &str, acl_name: &str) -> Result<(), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{container_name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "attach_acl_to_container: failed to fetch instance: status={status} body={value}"
            )));
        }
        let inst = value
            .get("metadata")
            .ok_or_else(|| VmError::Incus("instance response has no metadata".to_string()))?;
        let mut devices = inst
            .get("expanded_devices")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        devices["eth0"] = serde_json::json!({
            "name": "eth0",
            "network": "incusbr0",
            "type": "nic",
            "security.acls": acl_name,
            "security.acls.default.egress.action": "drop",
            "security.acls.default.ingress.action": "allow",
        });
        let config = inst.get("config").cloned().unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let body = serde_json::json!({ "devices": devices, "config": config });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{container_name}"),
            Some(body),
        )?;
        if status == 202 {
            self.wait_operation(
                &format!(
                    "/1.0/operations/{}",
                    value
                        .get("metadata")
                        .and_then(|m| m.get("id"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                ),
                Duration::from_secs(30),
            )?;
        } else if status >= 400 {
            return Err(VmError::Incus(format!(
                "attach_acl_to_container failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// ワークスペースのCIFSライブ共有をコンテナへbind-mountするdisk deviceを追加する
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4のライブ共有方式）。`attach_acl_to_container`
    /// と同じ「GETで`expanded_devices`取得→Rust側でマージ→PUTで丸ごと書き戻す」手順を踏む
    /// （単純な`PATCH`だとdevicesのネストしたマージが期待通り効かない可能性があるため、
    /// 既存のACL付与ロジックが確立した手順に合わせて安全側に倒す）。
    ///
    /// `source`はコンテナが動くAlmaLinux VM自身の中のパス（`mount -t cifs`した先、
    /// 例`/mnt/harness-workspace`）であり、Windowsホスト側のパスではない点に注意。
    pub fn add_disk_device(
        &self,
        container_name: &str,
        device_name: &str,
        source: &str,
        path: &str,
    ) -> Result<(), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{container_name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "add_disk_device: failed to fetch instance: status={status} body={value}"
            )));
        }
        let inst = value
            .get("metadata")
            .ok_or_else(|| VmError::Incus("instance response has no metadata".to_string()))?;
        let mut devices = inst
            .get("expanded_devices")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        devices[device_name] = serde_json::json!({
            "type": "disk",
            "source": source,
            "path": path,
        });
        let config = inst.get("config").cloned().unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let body = serde_json::json!({ "devices": devices, "config": config });
        let (status, value) = self.request(
            reqwest::Method::PUT,
            &format!("/1.0/instances/{container_name}"),
            Some(body),
        )?;
        if status == 202 {
            self.wait_operation(
                &format!(
                    "/1.0/operations/{}",
                    value
                        .get("metadata")
                        .and_then(|m| m.get("id"))
                        .and_then(|i| i.as_str())
                        .unwrap_or("")
                ),
                Duration::from_secs(30),
            )?;
        } else if status >= 400 {
            return Err(VmError::Incus(format!(
                "add_disk_device failed: status={status} body={value}"
            )));
        }
        Ok(())
    }

    /// unprivilegedコンテナのroot（namespace内uid 0）がホスト側（このAlmaLinux VM自身の
    /// ファイルシステム上）で実際に何uid/gidへマップされるかを返す。**実機で判明した罠**:
    /// `incus config get <name> volatile.idmap.base`は常に`0`を返す（無関係な旧フィールド
    /// らしく、実際のマッピングは`volatile.idmap.current`というJSON配列にある）。この値を
    /// CIFSマウントの`uid=/gid=`（`forceuid,forcegid`込み）へ渡さないと、コンテナ内から見た
    /// ホスト実uid 0所有のファイルが`nobody`扱いになり書込みが`Permission denied`になる
    /// （spike検証で発見。`shift=true`によるidmap shiftはCIFSが対応しておらず
    /// `Required idmapping abilities not available`で失敗するため、この静的uid合わせが
    /// 唯一の非特権コンテナ向け解決策）。
    pub fn container_root_host_id(&self, name: &str) -> Result<(u32, u32), VmError> {
        let (status, value) = self.request(
            reqwest::Method::GET,
            &format!("/1.0/instances/{name}"),
            None,
        )?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "container_root_host_id: failed to fetch instance: status={status} body={value}"
            )));
        }
        let idmap_str = value
            .get("metadata")
            .and_then(|m| m.get("config"))
            .and_then(|c| c.get("volatile.idmap.current"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| VmError::Incus(format!("container {name} has no volatile.idmap.current")))?;
        let idmap: Vec<serde_json::Value> = serde_json::from_str(idmap_str)
            .map_err(|e| VmError::Incus(format!("failed to parse volatile.idmap.current: {e}")))?;
        let uid = idmap
            .iter()
            .find(|e| e.get("Isuid").and_then(|v| v.as_bool()) == Some(true) && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0))
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| VmError::Incus(format!("container {name}: no uid mapping for nsid 0")))?;
        let gid = idmap
            .iter()
            .find(|e| e.get("Isgid").and_then(|v| v.as_bool()) == Some(true) && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0))
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| VmError::Incus(format!("container {name}: no gid mapping for nsid 0")))?;
        Ok((uid as u32, gid as u32))
    }

    pub fn pull_file(&self, name: &str, remote_path: &str) -> Result<Vec<u8>, VmError> {
        let url = format!(
            "{}/1.0/instances/{name}/files?path={}",
            self.base_url,
            urlencoding_path(remote_path)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| VmError::Incus(format!("pull_file failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(VmError::Incus(format!(
                "pull_file failed: status={} path={remote_path}",
                resp.status()
            )));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| VmError::Incus(format!("failed to read pulled file: {e}")))
    }
}

fn urlencoding_path(path: &str) -> String {
    // Incus APIのpathクエリパラメータ用の最小限のエンコード（スペース・日本語程度を想定）。
    path.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '.' | '_' | '-' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

/// Incusブリッジ`incusbr0`自身のIP（SNI prereadプロキシのlisten先、`plans/vm-spike/
/// RESULTS.md`§3.2/§3.8で確立した値。AlmaLinux golden像のIncusネットワーク既定設定に依存する
/// ため固定値として扱う）。
const INCUS_BRIDGE_IP: &str = "10.76.180.1";
/// SNI prereadプロキシのlistenポート（Incus自身のリモートAPI`8443`と衝突しない値、
/// `RESULTS.md`§3.2の踏んだ落とし穴参照）。
const SNI_PROXY_PORT: u16 = 8444;
const SNI_PROXY_CONF_PATH: &str = "/root/harness-sni-proxy.conf";
const SNI_PROXY_PID_PATH: &str = "/run/harness-sni-proxy.pid";
const SNI_AUDIT_LOG_PATH: &str = "/var/log/nginx/harness-sni-audit.log";
const NFTABLES_TABLE: &str = "harness_tier3";

/// SNI prereadプロキシのnginx設定を、許可ドメインごとに動的生成する
/// （`plans/vm-spike/RESULTS.md`§3.8で実機実証済みの構成をそのまま踏襲、監査ログ付き）。
fn build_sni_proxy_conf(allow_domains: &[String]) -> String {
    let map_lines: String = allow_domains
        .iter()
        .map(|d| format!("        {d}     \"{d}:443\";\n"))
        .collect();
    let decision_lines: String = allow_domains
        .iter()
        .map(|d| format!("        {d}     \"ALLOW\";\n"))
        .collect();
    format!(
        r#"load_module /usr/lib64/nginx/modules/ngx_stream_module.so;
worker_processes auto;
error_log /var/log/nginx/harness-sni-proxy-error.log warn;
events {{ worker_connections 1024; }}
stream {{
    resolver 1.1.1.1 valid=60s;

    log_format sniaudit '$time_iso8601 client=$remote_addr sni="$ssl_preread_server_name" '
                         'decision=$sni_decision upstream=$upstream_addr '
                         'bytes_sent=$bytes_sent bytes_received=$bytes_received '
                         'duration=$session_time status=$status';
    access_log {SNI_AUDIT_LOG_PATH} sniaudit;

    map $ssl_preread_server_name $sni_upstream {{
{map_lines}        default              "";
    }}
    map $ssl_preread_server_name $sni_decision {{
{decision_lines}        default              "DENY";
    }}

    server {{
        listen {INCUS_BRIDGE_IP}:{SNI_PROXY_PORT};
        ssl_preread on;
        proxy_pass $sni_upstream;
        proxy_connect_timeout 5s;
        proxy_timeout 30s;
    }}
}}
"#
    )
}

/// SNI prereadプロキシ + nftables DNAT（透過リダイレクト）+ コンテナ側Incus ACLを、
/// AlmaLinux VM自体へSSH経由で構成する（`allow_domains`が非空の場合のみ呼ぶ、
/// `plans/vm-spike/RESULTS.md`§3.2/§3.8で実機実証済みの構成のRust化）。
fn setup_egress_allowlist(
    guest_ip: IpAddr,
    ssh_key: &Path,
    incus: &IncusClient,
    container_name: &str,
    allow_domains: &[String],
) -> Result<(), VmError> {
    // 1. nginx SNI prereadプロキシを配置・起動。
    let conf = build_sni_proxy_conf(allow_domains);
    ssh_push_file(guest_ip, ssh_key, conf.as_bytes(), SNI_PROXY_CONF_PATH)?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        "mkdir -p /var/log/nginx",
        Duration::from_secs(10),
    )?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!("nginx -c {SNI_PROXY_CONF_PATH} -g 'pid {SNI_PROXY_PID_PATH};'"),
        Duration::from_secs(10),
    )?;

    // 2. nftables DNAT（コンテナ発の443宛先を透過的にプロキシへリダイレクト）。
    //    既存テーブルがあれば削除してから作り直す（同一VM内での再構成に備える、Phase 2では
    //    セッションごとに新しいVMなので通常は不要だが、べき等性のため）。
    let _ = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("nft delete table ip {NFTABLES_TABLE}"),
        Duration::from_secs(10),
    );
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!("nft add table ip {NFTABLES_TABLE}"),
        Duration::from_secs(10),
    )?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!(
            "nft 'add chain ip {NFTABLES_TABLE} prerouting {{ type nat hook prerouting priority dstnat ; }}'"
        ),
        Duration::from_secs(10),
    )?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!(
            "nft add rule ip {NFTABLES_TABLE} prerouting iifname \"incusbr0\" tcp dport 443 redirect to :{SNI_PROXY_PORT}"
        ),
        Duration::from_secs(10),
    )?;

    // 3. コンテナ側Incus ACL: tcp/443への直接egressを宛先指定なしで許可するだけでよい
    //    （プロキシの存在をコンテナに一切意識させない、`RESULTS.md`§3.8）。
    let acl_name = format!("{container_name}-egress");
    incus.create_network_acl(&acl_name)?;
    incus.attach_acl_to_container(container_name, &acl_name)?;

    Ok(())
}

/// セッション終了時、SNIプロキシの監査ログをホスト側ワークスペースへ書き出す
/// （VMはteardownで消えるため、これが唯一のフォレンジック記録になる。ユーザー要望
/// 「通信の監査」への対応、`plans/vm-spike/RESULTS.md`§3.8参照）。
fn fetch_and_persist_audit_log(
    guest_ip: IpAddr,
    ssh_key: &Path,
    workspace_root: &Path,
    session_id: &str,
) -> Result<(), VmError> {
    let (stdout, _stderr, code) = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("cat {SNI_AUDIT_LOG_PATH} 2>/dev/null"),
        Duration::from_secs(15),
    )?;
    if code != 0 || stdout.is_empty() {
        return Ok(()); // ログが無い（一度も通信が発生しなかった等）場合は何もしない。
    }
    let audit_dir = workspace_root.join(".harness").join("sandbox");
    std::fs::create_dir_all(&audit_dir)?;
    let audit_path = audit_dir.join(format!("tier3-net-audit-{session_id}.log"));
    std::fs::write(audit_path, stdout)?;
    Ok(())
}

/// 稼働中のTier3セッション（VM + コンテナ）を表す。`VmSandboxHandle`（`crate::vmsandboxd`）が
/// デーモンプロセス内で保持し続ける。
pub struct VmSession {
    session_id: String,
    vm_name: String,
    diff_vhdx: PathBuf,
    container_name: String,
    incus: IncusClient,
    /// egress許可リスト（SNIプロキシ+nftables DNAT）を構成した場合のみ`Some`（`allow_domains`
    /// が非空だった場合）。teardown時にこれを見て監査ログ取得の要否を判定する。
    ssh_key: Option<PathBuf>,
    /// ウォームVM（フェーズB、`Self::start_warm`経由）かどうか。`teardown`で撤収経路を
    /// 分岐させる（コールド: VM削除+差分VHDX破棄、ウォーム: checkpointへRestoreして
    /// 次回セッションのために温存する）。
    warm: bool,
    /// ウォームセッションが保持する直列化ロック（B2）。`teardown`（または`Drop`）まで
    /// 保持し続けることでマシン全体で1セッションに排他する。コールドセッションでは`None`。
    warm_lock: Option<WarmLock>,
    /// `WorkspaceShareMode::Cifs`のセッションでのみ`Some`（`smb_share::create_ephemeral_share`
    /// が作った使い捨て共有名・アカウント名）。teardown時にこれを見て`destroy_ephemeral_share`
    /// を呼ぶかどうかを判定する（`CopyInOut`セッションでは`None`のまま）。
    smb_share_name: Option<String>,
    smb_user: Option<String>,
}

const CONTAINER_IMAGE_ALIAS: &str = "alpine/3.21";
const CONTAINER_STATIC_IP: &str = "10.76.180.60/24";
const CONTAINER_GATEWAY: &str = "10.76.180.1";
const WORKSPACE_MOUNT: &str = "/workspace";

/// ゲストが静的IPで応答し、Incus mTLSクライアント証明書が信頼されるまで待つ（コールドブート
/// ・ウォームRestoreの両方から共有、B4/B5参照）。`guest_wait_timeout`は呼び出し側が
/// コールド/ウォームに応じて使い分ける（コールドは起動+firstbootを見込み長め、ウォームは
/// 既に起動済みのはずなので短め、B8参照）。
fn wait_for_guest_ready(
    config: &VmSandboxConfig,
    guest_wait_timeout: Duration,
) -> Result<IncusClient, VmError> {
    // ゲストが静的IPで応答するまでポーリング（`RESULTS.md`§3.7実測: 初回pingから即応答）。
    wait_tcp_reachable(config.guest_ip, config.incus_port, guest_wait_timeout)
        .map_err(|_| VmError::Timeout(format!("guest {} did not come up", config.guest_ip)))?;

    let (client_crt, client_key) = ensure_client_cert()?;
    let incus = IncusClient::new(config.guest_ip, config.incus_port, &client_crt, &client_key)?;

    // ゴールデン像へのクライアント証明書焼き込み（`plans/TIER1A-OPEN-ISSUES.md`項目9）に
    // より、通常はここで既に信頼済み。ただし`wait_tcp_reachable`はTCPポートの疎通
    // （systemdのsocket activationにより、実際のincusdがfirstbootの証明書自動信頼
    // ステップ（harness-firstboot.sh 3.5）を終える前でも即座に受理してしまう）しか見て
    // いないため、起動直後は「ポートは開いているが信頼登録はまだ」という一時的な
    // レースが実機で発生し得る（実機E2Eで発見）。単発チェックにはせず、猶予を持って
    // リトライする。
    let trust_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if incus.is_trusted().unwrap_or(false) {
            break;
        }
        if Instant::now() >= trust_deadline {
            return Err(VmError::Incus(
                "Incus does not trust this client certificate after waiting 60s. \
                 ゴールデン像へのクライアント証明書焼き込みが未完了か、firstbootの \
                 信頼登録ステップが失敗している可能性があります。"
                    .to_string(),
            ));
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    Ok(incus)
}

/// ウォームVM専用のproduction checkpoint（`WARM_CHECKPOINT_NAME`）が既に存在するかを確認する。
fn warm_checkpoint_exists() -> Result<bool, VmError> {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         (Get-VMSnapshot -VMName '{name}' -Name '{checkpoint}' -ErrorAction SilentlyContinue).Name",
        name = WARM_VM_NAME,
        checkpoint = WARM_CHECKPOINT_NAME,
    );
    let stdout = run_powershell(&script)?;
    Ok(!stdout.trim().is_empty())
}

/// ウォームVMのproduction checkpoint（`WARM_CHECKPOINT_NAME`）を用意する（B3、低速パス・
/// 一度きり）。既に存在すればスキップする。無ければ: ウォーム専用の差分VHDXを作成
/// → `New-VM`+`Start-VM` → コールドブート後処理と同じ疎通確認（`wait_for_guest_ready`、
/// firstbootの完了を含む長めのタイムアウト） → `Checkpoint-VM`で「完全起動済み・IP疎通済み・
/// Incus trusted」状態を捕捉する。途中で失敗した場合はウォームVM自体を撤収し、次回呼び出しで
/// 最初からやり直せるようにする（中途半端なVMが`WARM_VM_NAME`として残らないようにする）。
pub fn ensure_warm_template(config: &VmSandboxConfig) -> Result<(), VmError> {
    if warm_checkpoint_exists()? {
        return Ok(());
    }

    let diff_vhdx = warm_diff_vhdx_path(config);
    std::fs::create_dir_all(&config.vm_work_dir)?;

    // 前回の途中失敗（checkpoint作成前にVMだけ残った等）の後始末。存在しなければ無害に失敗する。
    let _ = teardown_vm(WARM_VM_NAME, &diff_vhdx);
    crate::vm_ledger::remove_session(WARM_VM_NAME);

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
        name = WARM_VM_NAME,
        switch = config.switch_name,
    );
    run_powershell(&script)?;

    // ウォームVMも台帳へ記録する（`warm: true`、`select_orphans`のGC対象から除外される、B7）。
    crate::vm_ledger::record_session(WARM_VM_NAME, WARM_VM_NAME, &diff_vhdx, true);

    // firstboot（SSHホスト鍵/machine-id/Incus証明書再生成）を見込み、コールドブートと
    // 同じ長さのタイムアウトで待つ（これは一度きりのprovisioningであり、以降のセッションは
    // このコストを払わない）。
    if let Err(e) = wait_for_guest_ready(config, Duration::from_secs(180)) {
        let _ = teardown_vm(WARM_VM_NAME, &diff_vhdx);
        crate::vm_ledger::remove_session(WARM_VM_NAME);
        return Err(e);
    }

    if let Err(e) = run_powershell(&format!(
        "Checkpoint-VM -Name '{name}' -SnapshotName '{checkpoint}'",
        name = WARM_VM_NAME,
        checkpoint = WARM_CHECKPOINT_NAME,
    )) {
        let _ = teardown_vm(WARM_VM_NAME, &diff_vhdx);
        crate::vm_ledger::remove_session(WARM_VM_NAME);
        return Err(e);
    }

    Ok(())
}

/// `VmSession::attach_to_guest`が構築対象とするVMの識別子一式。コールド/ウォームの両パスで
/// 値の出どころが異なる（コールド: 新規生成したsession_id、ウォーム: 固定の`WARM_VM_NAME`）
/// ため、呼び出し側で組み立ててから渡す（引数過多を避けるための単純な束ね、`clippy::
/// too_many_arguments`対策）。
struct GuestIdentity {
    session_id: String,
    vm_name: String,
    diff_vhdx: PathBuf,
}

/// ウォームテンプレート自体を破棄する（B8、破損検出時）。次回`ensure_warm_template`呼び出しで
/// 最初からやり直す（VM再作成→firstboot→checkpoint再取得）。
fn discard_warm_template(config: &VmSandboxConfig) {
    let diff_vhdx = warm_diff_vhdx_path(config);
    let _ = teardown_vm(WARM_VM_NAME, &diff_vhdx);
    crate::vm_ledger::remove_session(WARM_VM_NAME);
}

impl VmSession {
    /// VM起動→静的IP疎通待ち→Incus mTLS疎通確認→コンテナ作成/起動→ワークスペースcopy-in、
    /// までを一気に行う（`plans/vm-spike/RESULTS.md`§3.7で確立した「Default Switch中継不要」
    /// 経路を前提とする）。
    pub fn start(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        allow_domains: &[String],
    ) -> Result<Self, VmError> {
        let session_id = unique_session_id();
        let vm_name = session_id.clone();
        std::fs::create_dir_all(&config.vm_work_dir)?;
        let diff_vhdx = config.vm_work_dir.join(format!("{session_id}.diff.vhdx"));

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
            name = vm_name,
            switch = config.switch_name,
        );
        run_powershell(&script)?;

        // VM作成成功直後、セッション設定完了前の台帳記録（D-24、`crate::vm_ledger`）。
        // これ以降のいかなる失敗（Incus疎通待ちタイムアウト等）でVMが孤児として残っても、
        // 次回起動時のGC（`gc_orphan_sessions`）が本エントリを見つけて撤収できる。
        crate::vm_ledger::record_session(&session_id, &vm_name, &diff_vhdx, false);

        // ここから先のいかなる失敗も、既に起動済みのVM（+差分VHDX）を孤児として残さないよう
        // teardown_vmを呼んでから返す（実機E2Eで発見: この保証が無いと、cert未検出等の
        // 一時的な失敗でVMだけが残り続け、固定静的IP（172.20.100.10）を使う設計上、次回
        // セッションが新しいVMを起動した際にIP重複が発生し、どちらのVMが応答するか不定に
        // なるという深刻な症状につながる。`plans/TIER1A-OPEN-ISSUES.md`項目9参照）。
        let result = Self::attach_to_guest(
            workspace_root,
            config,
            GuestIdentity { session_id, vm_name: vm_name.clone(), diff_vhdx: diff_vhdx.clone() },
            allow_domains,
            Duration::from_secs(180),
            false,
        );
        if result.is_err() {
            let _ = teardown_vm(&vm_name, &diff_vhdx);
            // `vm_name == session_id`（本関数冒頭の`let vm_name = session_id.clone();`）。
            crate::vm_ledger::remove_session(&vm_name);
        }
        result
    }

    /// [`Self::start`]（コールドブート）と[`Self::start_warm`]（B5、ウォームRestore後）の
    /// 共有パス: ゲストへの疎通確認からコンテナ作成・ワークスペースcopy-inまでを行う。
    /// VM自体の起動（`New-VM`+`Start-VM`、コールド専用）や`Restore-VMSnapshot`（ウォーム専用）
    /// は呼び出し側の責務であり、ここでは扱わない（B4のリファクタリング分離）。
    ///
    /// `guest_wait_timeout`は静的IP疎通待ちのタイムアウトで、コールドブート
    /// （`Self::start`、数十秒〜分オーダーの起動を見込む）とウォーム（`Self::start_warm`、
    /// 既に起動済みのはずなので短い上限で足りる）で異なる値を渡す。失敗時のVM後始末は
    /// 呼び出し側の責務（コールド: [`Self::start`]、ウォーム: [`Self::start_warm`]）。
    fn attach_to_guest(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        identity: GuestIdentity,
        allow_domains: &[String],
        guest_wait_timeout: Duration,
        warm: bool,
    ) -> Result<Self, VmError> {
        let GuestIdentity { session_id, vm_name, diff_vhdx } = identity;
        // 前回セッションの残留ホスト鍵によるSSH拒否を防ぐ（`reset_known_hosts_file`のdoc参照）。
        // このセッションで最初にSSHを使う箇所（egress allowlist設定・CIFS認証情報配布/マウント、
        // いずれも本関数の呼び出し範囲内）より前に1回だけ行う。
        reset_known_hosts_file()?;
        let incus = wait_for_guest_ready(config, guest_wait_timeout)?;

        let container_name = format!("harness-{session_id}");
        incus.create_container(&container_name, CONTAINER_IMAGE_ALIAS)?;
        incus.start_container(&container_name)?;

        // **実機で判明した罠**: `start_container`はIncus APIへstart操作を投げた後
        // 固定500msスリープするだけで、コンテナ内のeth0（veth）が実際に出現するのを待たない。
        // 直後に`ip addr add ... dev eth0`を撃つと稀に"Cannot find device"で失敗するが、
        // 後続コマンドを`;`区切りにしていたため`exec`全体のexit codeは最後の`mkdir -p`の
        // 結果になってしまい、失敗が一切表面化しないまま`/etc/resolv.conf`だけは書かれる
        // （＝DNSサーバは設定されるがIPv4アドレス自体が無く、`wget`が"bad address"で
        // 静かに失敗する）という形で発覚した。eth0の出現をポーリングで待ってから設定する。
        let mut eth0_ready = false;
        for _ in 0..30 {
            let (stdout, _stderr, code) = incus.exec(
                &container_name,
                &["sh", "-c", "ip link show eth0"],
                "/",
                &[],
                Duration::from_secs(5),
            )?;
            if code == Some(0) && stdout.contains("eth0") {
                eth0_ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        if !eth0_ready {
            return Err(VmError::Incus(format!(
                "container {container_name}: eth0 did not appear within timeout"
            )));
        }

        // DHCP不通の既知制約（`RESULTS.md`§段階3）への回避策: 静的IPを直接設定する。
        // **実機で判明した罠(1)**: `ip addr add`で後乗せするだけでは不十分。Alpineの
        // `/etc/network/interfaces`は既定で`iface eth0 inet dhcp`のままであり、ifupdown-ngが
        // 起動したバックグラウンドの`udhcpc -b`がDHCPサーバ不在のまま再試行ループを続けている。
        // このリトライサイクルが手動追加したアドレスをフラッシュしてしまうため、数秒〜十数秒後
        // （LLMのターン往復程度の時間）に静的IPが消え、`wget: bad address`として現れていた
        // （`ip addr add`直後の短時間チェックでは再現しなかったため発見が遅れた）。
        // `ifdown`/`ifup`でifupdown-ng自体にstatic管理させることで、udhcpcのプロセスごと
        // 止めて再発を防ぐ。**実機で判明した罠(1b)**: `ifdown eth0`直後に間を置かず`ifup eth0`を
        // 実行すると、`ifdown`が止めたはずの旧`udhcpc`プロセスがロックファイルをまだ解放しきって
        // おらず`ifup: could not acquire exclusive lock for eth0: Resource temporarily unavailable`
        // で失敗することがある（プロセス終了が非同期のため）。`pkill`で明示的に刈り取ってから
        // 短いリトライループで`ifup`する。
        // **実機で判明した罠(2)**: 静的IP割当はNetworkManager/dhclientを経由しないため
        // `/etc/resolv.conf`が空のままになり、コンテナ内のDNS解決自体が失敗する
        // （`nslookup`が既定の`127.0.0.1`へ問い合わせて`Connection refused`になる）。
        // ACL（`create_network_acl`）でUDP/TCP 53のegressを許可しても、そもそも問い合わせ先の
        // リゾルバが設定されていなければ無意味なため、ここで明示的に設定する
        // （nginx SNIプロキシの`resolver`ディレクティブと同じ`1.1.1.1`に揃える）。
        // 最終判定は`ifup`自身の終了コードではなく`ip -4 addr show eth0`にinetが実在するかで
        // 行う（`&&`連結の最後の条件が全体のexit codeを決めるため、確実に反映される）。
        let interfaces_conf = format!(
            "auto eth0\niface eth0 inet static\n    address {CONTAINER_STATIC_IP}\n    gateway {CONTAINER_GATEWAY}\n"
        );
        // **実機で判明した罠(3)**: コンテナ起動直後、Alpineのopenrc `networking`サービスは
        // eth0の自動DHCPブリングアップをまだ実行中のことがあり（`rc-status`で`networking
        // [starting]`のまま長時間止まる、Incusブリッジ側のIPv4 DHCP応答が遅い/来ない場合に
        // 発生）、この間ifupdown-ngの排他ロックを握ったままになる。**この状態で
        // `rc-service networking stop`を叩くと、openrcのサービスマネージャ自身が
        // 「start処理が終わるまでstopを受け付けない」ため一緒にハングする**（実機で確認：
        // stopコマンド自体が返ってこず、後続の`ifdown`/`pkill`にすら到達しない。openrc経由の
        // 「お行儀の良い」停止要求では、まさにこの詰まった状態を解消できない）。openrcを
        // 経由せず、ロックを握っている実プロセス（自動`ifup`本体・その子の`dhcp`ヘルパー・
        // `udhcpc`）を`pkill -9`で直接強制終了することで、openrc側の「starting」状態が
        // 詰まっていても確実に解放できる（`pkill -9 -x udhcpc`だけでは、まだ`ifup`本体や
        // `dhcp`ヘルパーが生き残ってロックを取り直す可能性があるため、3つとも対象にする）。
        // **実機で判明した罠(3b)**: 当初`pkill -9 -f 'ifup -i'`（コマンドライン全体一致）を
        // 使ったところ、この`pkill`コマンド自身の引数文字列に"ifup -i"という部分文字列が
        // 含まれるため`-f`が**自分自身にもマッチして自殺**した（exit=137=SIGKILL、実機で
        // 再現・特定）。プロセス名の完全一致のつもりで`-x ifup`/`-x dhcp`/`-x udhcpc`
        // （`/proc/<pid>/comm`は確かに"ifup"/"dhcp"/"udhcpc"と一致することを実機確認済み）に
        // 切り替えたが、**それでも対象を1つも殺せず無言で失敗し続けた**（`>/dev/null 2>&1`で
        // 抑制していたため気付くのに時間を要した）。原因はAlpineのbusybox版`pkill`の`-x`が
        // GNU版と異なり`/proc/comm`（basenameのみ）ではなく**フルパス込みの起動名**
        // （`/sbin/udhcpc`等）との完全一致を要求すること（実機で`pkill -9 udhcpc`
        // （`-x`無し、部分一致）なら確実に殺せることを確認して特定）。`-x`を外した部分一致に
        // 変更する（自プロセス自身の`comm`は`sh`のため、`-f`を使わない限りこのパターンで
        // 自己マッチする心配は無い）。
        // **診断強化（原因未特定の実機障害切り分け用）**: 従来は各ステップを`>/dev/null 2>&1`で
        // 抑制していたため、失敗時にstdout/stderrが両方空のままexit codeだけが返り、どのステップで
        // 落ちたか一切判別できなかった（`docs/bugs/`記録予定の障害）。`set -x`で実行トレースを残し、
        // 各ステップ後に`STEP=`マーカーをstdoutへ出す。最終判定も単一の`&&`鎖からifブランチへ
        // 分離し、`FAIL=no-inet`かどうかで「ifupは成功扱いだがIPが付かない」ケースを識別できるように
        // する。失敗が確定した場合のみ、追加の往復を要さず同一execの中で診断ダンプ
        // （アドレス・ルート・interfaces内容・ifupdown-ng状態・`ifup -v`生出力・rc-status・
        // プロセス残存）を出す。**罠(3b)の教訓によりpkillのパターン自体は一切変更しない**
        // （`-f`を足すと自分自身にマッチして自殺する）。
        //
        // **実機診断で判明した罠(4)**: 上記の診断強化により、当初原因不明だった本エクスポート
        // の失敗が次のように特定できた（`docs/bugs/`記録予定）。冒頭の`pkill -9 udhcpc`実行時点
        // では、コンテナ起動直後のopenrc自動DHCPブリングアップがまだudhcpcを起動し切っておらず
        // （`rc-status`が`networking [started]`を返す時点でも、実プロセスの生成は追いついて
        // いないことがある）、直後の`sleep 1`より後にudhcpcが新規生成されて`ifdown`/`ifup`の
        // 排他ロックを握ってしまう。結果、リトライループの大半が
        // `could not acquire exclusive lock for eth0: Resource temporarily unavailable`で
        // 空振りし、ロックがようやく空いた回では今度はifupdown-ng側が「(旧DHCP設定のまま)既に
        // 設定済み」とみなし`ifup: skipping auto interface eth0 (already configured), use
        // --force to force configuration`で**無言のexit 0スキップ**をする。どちらも冒頭1回の
        // `pkill`＋`ifup`（force無し）では防げないため、リトライの**毎周**で
        // `pkill -9 udhcpc`を撃ち直しつつ`ifup --force`で明示的に強制再設定する形へ変える。
        let (stdout, stderr, code) = incus.exec(
            &container_name,
            &[
                "sh",
                "-c",
                &format!(
                    "set -x; \
                     pkill -9 ifup; \
                     pkill -9 dhcp; \
                     pkill -9 udhcpc; \
                     echo 'STEP=pkill-done'; \
                     sleep 1; \
                     printf '%s' '{interfaces_conf}' > /etc/network/interfaces; \
                     echo 'STEP=interfaces-written'; \
                     ifdown eth0; \
                     echo 'STEP=ifdown-done'; \
                     ok=0; i=0; while [ $i -lt 20 ]; do \
                       pkill -9 udhcpc; pkill -9 dhcp; \
                       ifup --force eth0 && {{ ok=1; break; }}; \
                       i=$((i+1)); sleep 1; \
                     done; \
                     echo \"STEP=ifup-loop-done ok=$ok tries=$i\"; \
                     if ip -4 addr show eth0 | grep -q 'inet '; then \
                       echo 'STEP=inet-ok'; \
                       echo 'nameserver 1.1.1.1' > /etc/resolv.conf; \
                       mkdir -p {WORKSPACE_MOUNT}; \
                       echo 'STEP=resolv-and-mkdir-done'; \
                     else \
                       echo 'FAIL=no-inet'; \
                       echo '---diag: ip -4 addr show eth0---'; ip -4 addr show eth0; \
                       echo '---diag: ip -4 route---'; ip -4 route; \
                       echo '---diag: /etc/network/interfaces---'; cat /etc/network/interfaces; \
                       echo '---diag: /run/ifstate/eth0---'; cat /run/ifstate/eth0 2>&1; \
                       echo '---diag: ifup -v eth0---'; ifup -v eth0 2>&1; \
                       echo '---diag: rc-status -a---'; rc-status -a 2>&1; \
                       echo '---diag: ps w---'; ps w; \
                       exit 1; \
                     fi"
                ),
            ],
            "/",
            &[],
            Duration::from_secs(60),
        )?;
        if code != Some(0) {
            return Err(VmError::Incus(format!(
                "container {container_name}: static IP/DNS setup failed (exit={code:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            )));
        }

        // egress許可リスト（SNIプロキシ+nftables DNAT+コンテナACL）は`allow_domains`が
        // 非空の場合のみ構成する。既定（省略時）はPhase 1と同じ無制限egressのまま
        // （既存の`--net-allow-domain`未指定時の挙動を変えない、D-02と同じ「オプトイン」思想）。
        let ssh_key = if allow_domains.is_empty() {
            None
        } else {
            let key = ensure_ssh_keypair()?;
            setup_egress_allowlist(config.guest_ip, &key, &incus, &container_name, allow_domains)?;
            Some(key)
        };

        // ワークスペース共有（`WorkspaceShareMode`、移行期間の切り替えフラグ）。
        // `Cifs`: Windows側でSMB共有→SSH経由でゲストへ認証情報配布→ゲスト内`mount -t cifs`
        // →Incus disk deviceでコンテナへbind-mount、のライブ共有シーケンス。ウォーム
        // セッションでもcheckpoint Restore後の`attach_to_guest`呼び出しのたびに毎回
        // やり直す（使い捨て認証情報をセッションをまたいで使い回さない、D-22のセッション
        // 使い捨て原則を優先、ユーザー確認済み）。
        let (smb_share_name, smb_user) = if config.workspace_share_mode == WorkspaceShareMode::Cifs {
            let (share, user, password) = crate::smb_share::create_ephemeral_share(&session_id, workspace_root)?;
            // `record_session`は`vm_name`をキーに台帳エントリを作る（ウォームセッションでは
            // `vm_name == WARM_VM_NAME`固定、コールドでは`vm_name == session_id`）ため、
            // ここでも`vm_name`をキーに揃える（`session_id`ではない点に注意、B10）。
            crate::vm_ledger::record_smb_share(&vm_name, &share, &user);

            let ssh_key = ensure_ssh_keypair()?;
            let cred_remote = format!("/etc/harness-smb-{session_id}.cred");
            let cred_contents = format!("username={user}\npassword={password}\n");
            ssh_push_file(config.guest_ip, &ssh_key, cred_contents.as_bytes(), &cred_remote)?;
            ssh_exec_checked(
                config.guest_ip,
                &ssh_key,
                &format!("chmod 600 {cred_remote}"),
                Duration::from_secs(10),
            )?;

            // unprivilegedコンテナのroot（namespace uid 0）が実際にホスト側でどのuid/gidへ
            // マップされるかを問い合わせ、CIFSマウントの`uid=/gid=`をそれに合わせる
            // （`container_root_host_id`のdoc参照。`shift=true`によるidmap shiftはCIFSが
            // 対応しておらず使えないため、この静的合わせが唯一の非特権コンテナ向け解決策、
            // spike検証で確認済み）。
            let (host_uid, host_gid) = incus.container_root_host_id(&container_name)?;
            ssh_exec_checked(
                config.guest_ip,
                &ssh_key,
                &format!(
                    "mkdir -p /mnt/harness-workspace && \
                     mount -t cifs //{smb_host}/{share} /mnt/harness-workspace \
                     -o credentials={cred_remote},uid={host_uid},gid={host_gid},forceuid,forcegid,\
                     file_mode=0644,dir_mode=0755,cache=strict,vers=3.1.1",
                    smb_host = config.smb_host_ip,
                ),
                Duration::from_secs(30),
            )?;

            incus.add_disk_device(&container_name, "workspace", "/mnt/harness-workspace", WORKSPACE_MOUNT)?;

            (Some(share), Some(user))
        } else {
            (None, None)
        };

        let session = Self {
            session_id,
            vm_name,
            diff_vhdx,
            container_name,
            incus,
            ssh_key,
            warm,
            warm_lock: None,
            smb_share_name,
            smb_user,
        };
        if config.workspace_share_mode == WorkspaceShareMode::CopyInOut {
            session.copy_in_workspace(workspace_root)?;
        }
        Ok(session)
    }

    /// ウォームRestoreによる高速セッション開始（B5）。`ensure_warm_template`（B3）が
    /// checkpointを用意済みであることが前提（呼び出し側=daemon`serve_inner`がその順序を
    /// 保証する、B9）。`Self::start`（コールドブート）とは異なり、既存のウォームVMを
    /// 直列化ロック（`WarmLock`）で排他しつつcheckpointへ`Restore-VMSnapshot`してから
    /// 起動する。失敗時、コールドブートとは異なり**ウォームVM自体は削除しない**
    /// （破損時のテンプレート再構築・コールドフォールバックは呼び出し側、B8の責務）。
    pub fn start_warm(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        allow_domains: &[String],
        guest_wait_timeout: Duration,
    ) -> Result<Self, VmError> {
        let lock = WarmLock::acquire(config, Duration::from_secs(300))?;

        let diff_vhdx = warm_diff_vhdx_path(config);
        // `Stop-VM`を先に置くことで、直前の`teardown`（`Stop-VM`で明示停止）・想定外の
        // 状態（実行中のまま残った等）のどちらからでも冪等にRestoreできる。checkpointは
        // Running状態で捕捉した（`ensure_warm_template`）ため、`Restore-VMSnapshot`自体が
        // 実行状態への復帰を伴う。後続の`Start-VM`は「既に起動済み」を許容するため
        // `-ErrorAction SilentlyContinue`を付ける（冪等化、状態次第でのエラーを避ける）。
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
Stop-VM -Name '{name}' -TurnOff -Force -ErrorAction SilentlyContinue
Restore-VMSnapshot -VMName '{name}' -Name '{checkpoint}' -Confirm:$false
Start-VM -Name '{name}' -ErrorAction SilentlyContinue
"#,
            name = WARM_VM_NAME,
            checkpoint = WARM_CHECKPOINT_NAME,
        );
        run_powershell(&script)?;

        let session_id = unique_session_id();
        let mut session = Self::attach_to_guest(
            workspace_root,
            config,
            GuestIdentity { session_id, vm_name: WARM_VM_NAME.to_string(), diff_vhdx },
            allow_domains,
            guest_wait_timeout,
            true,
        )?;
        session.warm_lock = Some(lock);
        Ok(session)
    }

    /// ウォームスタートの安全な入口（B8）。`ensure_warm_template`→`start_warm`を試み、
    /// 破損（Restore失敗・疎通タイムアウト・Incus未信頼等）を検出した場合はテンプレートを
    /// 1回だけ破棄して再provisioning→再試行し、それでも失敗すればコールドブート
    /// （`Self::start`）へフォールバックする（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1）。
    /// daemon側（`vmsandboxd::serve_inner`）はTier3+`--tier3-warm`指定時、`Self::start`の
    /// 代わりにこちらを呼ぶ（B9）。
    pub fn start_warm_or_fallback(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        allow_domains: &[String],
    ) -> Result<Self, VmError> {
        // ウォームRestore後は既に起動済みのはずなので、コールドブート（`Self::start`の
        // 180秒、firstbootを見込む）より大幅に短いタイムアウトで足りる。
        const WARM_GUEST_WAIT: Duration = Duration::from_secs(30);

        if let Err(e) = ensure_warm_template(config) {
            eprintln!(
                "start_warm_or_fallback: failed to provision warm template, falling back to \
                 cold boot: {e}"
            );
            return Self::start(workspace_root, config, allow_domains);
        }

        match Self::start_warm(workspace_root, config, allow_domains, WARM_GUEST_WAIT) {
            Ok(session) => return Ok(session),
            Err(e) => {
                eprintln!(
                    "start_warm_or_fallback: warm start failed ({e}), discarding warm template \
                     and retrying once"
                );
            }
        }

        discard_warm_template(config);
        if let Err(e) = ensure_warm_template(config) {
            eprintln!(
                "start_warm_or_fallback: re-provisioning warm template failed, falling back to \
                 cold boot: {e}"
            );
            return Self::start(workspace_root, config, allow_domains);
        }

        match Self::start_warm(workspace_root, config, allow_domains, WARM_GUEST_WAIT) {
            Ok(session) => Ok(session),
            Err(e) => {
                eprintln!(
                    "start_warm_or_fallback: warm start failed again after re-provisioning \
                     ({e}), falling back to cold boot"
                );
                Self::start(workspace_root, config, allow_domains)
            }
        }
    }

    /// ワークスペース全体をコンテナの`/workspace`へpushする（Phase 1: 素朴な全ファイル
    /// 走査。大規模ワークスペースでの性能はPhase 2以降で見直す、TODOとして明記）。
    fn copy_in_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        for entry in walk_files(workspace_root)? {
            let rel = entry
                .strip_prefix(workspace_root)
                .map_err(|e| VmError::Io(e.to_string()))?;
            let remote = format!("{WORKSPACE_MOUNT}/{}", rel.to_string_lossy().replace('\\', "/"));
            if let Some(parent) = std::path::Path::new(&remote).parent() {
                let _ = self.incus.exec(
                    &self.container_name,
                    &["mkdir", "-p", &parent.to_string_lossy()],
                    "/",
                    &[],
                    Duration::from_secs(10),
                );
            }
            let contents = std::fs::read(&entry)?;
            self.incus.push_file(&self.container_name, &contents, &remote)?;
        }
        Ok(())
    }

    /// コンテナの`/workspace`をホストのワークスペースへ書き戻す（セッション終了時、
    /// Teardown経路）。既存ファイルを上書きする（Phase 1の既知の限界、モジュールdoc参照）。
    fn copy_out_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        let (stdout, _stderr, _exit) = self.incus.exec(
            &self.container_name,
            &["sh", "-c", &format!("find {WORKSPACE_MOUNT} -type f")],
            "/",
            &[],
            Duration::from_secs(30),
        )?;
        for line in stdout.lines() {
            let remote = line.trim();
            if remote.is_empty() {
                continue;
            }
            let rel = remote.trim_start_matches(WORKSPACE_MOUNT).trim_start_matches('/');
            let local = workspace_root.join(rel);
            if let Some(parent) = local.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = self.incus.pull_file(&self.container_name, remote)?;
            std::fs::write(&local, bytes)?;
        }
        Ok(())
    }

    /// `run_shell`から呼ばれる実行チャネル本体。`cwd`はワークスペースルートからの相対パスへ
    /// 変換した上で`/workspace`配下へマッピングする。
    pub fn exec(
        &self,
        cmd: &str,
        cwd: &Path,
        workspace_root: &Path,
        env: &[(String, String)],
        timeout: Duration,
    ) -> Result<(String, String, Option<i32>), VmError> {
        let rel_cwd = cwd
            .strip_prefix(workspace_root)
            .unwrap_or_else(|_| Path::new("."));
        let remote_cwd = if rel_cwd.as_os_str().is_empty() || rel_cwd == Path::new(".") {
            WORKSPACE_MOUNT.to_string()
        } else {
            format!("{WORKSPACE_MOUNT}/{}", rel_cwd.to_string_lossy().replace('\\', "/"))
        };
        self.incus
            .exec(&self.container_name, &["sh", "-c", cmd], &remote_cwd, env, timeout)
    }

    pub fn teardown(self, workspace_root: &Path) -> Result<(), VmError> {
        // `WorkspaceShareMode::Cifs`セッションはライブ共有のためワークスペースの中身は
        // 常にホストの実ファイルシステムそのもの（bind-mountを外すだけ）で、明示的な
        // copy-outは不要（`copy_in_workspace`と同じくPhase 1の全ファイルpull往復を避ける、
        // このライブ共有方式を導入した本来の目的）。
        let copy_out_result = if self.smb_share_name.is_some() {
            Ok(())
        } else {
            self.copy_out_workspace(workspace_root)
        };
        // egress許可リストを構成していた場合のみ、VMが消える前に監査ログを回収する
        // （ユーザー要望「通信の監査」対応、失敗してもteardown自体は止めない）。
        if let Some(ssh_key) = &self.ssh_key {
            let _ = fetch_and_persist_audit_log(
                self.incus.host_ip(),
                ssh_key,
                workspace_root,
                &self.session_id,
            );
        }
        let _ = self.incus.stop_container(&self.container_name);
        let _ = self.incus.delete_container(&self.container_name);

        // Windows側の使い捨てSMB共有・ローカルアカウントを破棄する（共有→アカウントの順、
        // `smb_share::destroy_ephemeral_share`のdoc参照）。コンテナ撤収後・VM撤収前に行う
        // （どちらの順でも実害は無いが、共有の実体はWindows側でありVM状態と独立なため
        // ここで先に片付ける）。
        if let (Some(share), Some(user)) = (&self.smb_share_name, &self.smb_user) {
            crate::smb_share::destroy_ephemeral_share(share, user, Some(workspace_root));
        }

        if self.warm {
            // ウォームセッション: VM自体は削除せず、checkpointへRestoreして次回セッションの
            // ために温存する（差分VHDX破棄の代わりに巻き戻すことで、当セッション中の書込みを
            // 破棄する＝D-20「毎回捨てる」不変条件を満たす、§2.1参照）。checkpointは
            // Running状態で捕捉した（`ensure_warm_template`）ため、Restore後は自動的に
            // 実行状態へ戻る。次回`start_warm`の起動を軽くするため、その後`Stop-VM`で
            // 明示的に停止しておく（次回のRestoreがどのみち実行状態へ戻すため、ここでの
            // 停止と次回起動のタイミングは競合しない）。`self.warm_lock`は本関数を抜けて
            // `self`がdropされる際に解放される（`WarmLock::Drop`）。
            let script = format!(
                r#"
$ErrorActionPreference = 'Stop'
Restore-VMSnapshot -VMName '{name}' -Name '{checkpoint}' -Confirm:$false
Stop-VM -Name '{name}' -TurnOff -Force -ErrorAction SilentlyContinue
"#,
                name = WARM_VM_NAME,
                checkpoint = WARM_CHECKPOINT_NAME,
            );
            run_powershell(&script)?;
            return copy_out_result;
        }

        teardown_vm(&self.vm_name, &self.diff_vhdx)?;
        // VM+差分VHDXの撤収が完了した後にのみ台帳から除去する（D-24）。撤収失敗時
        // （`?`で早期returnした場合）は台帳に残したままにし、次回起動時のGCへ委ねる。
        crate::vm_ledger::remove_session(&self.session_id);
        copy_out_result
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// D-24: 台帳+実機照会の両方を突き合わせ、前回セッションの孤児VM・差分VHDXを撤収する
/// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6・§4）。`VmSession::start`が新規VMを
/// 起動し固定静的IP（`config.guest_ip`）を要求する**前**にdaemon側（`serve_inner`）から
/// 呼ぶことで、孤児VMとのIP重複を未然に防ぐ（`VmSession::start`のコメント参照）。
///
/// 個々の撤収に失敗しても処理は止めない（best-effort、`plans/TIER1A-OPEN-ISSUES.md`
/// 項目9）。GC自体の失敗で`StartSession`を失敗させないよう、呼び出し側は戻り値を無視して
/// 構わない設計（stderrへログするのみ）。
pub fn gc_orphan_sessions(config: &VmSandboxConfig, current_session_id: &str) -> Vec<String> {
    let ledger = crate::vm_ledger::load();

    let existing_vm_names = match run_powershell(
        "Get-VM -Name 'harness-tier3-*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name",
    ) {
        Ok(stdout) => stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("gc_orphan_sessions: failed to list Hyper-V VMs, skipping GC this round: {e}");
            return Vec::new();
        }
    };

    let orphans = crate::vm_ledger::select_orphans(&ledger, current_session_id, &existing_vm_names);

    // SMBライブ共有（`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4）のセッション使い捨て共有・
    // アカウントも、孤児VMと一緒に回収する（VM自体が孤児になった時点で、そのVMが使っていた
    // 共有・アカウントも用済みのため）。
    for (share_name, user_name) in crate::vm_ledger::select_smb_orphans(&ledger, &orphans) {
        // 台帳が`workspace_root`自体を記録していないため、孤児回収経路ではNTFS ACEの取り消しは
        // スキップされる（`destroy_ephemeral_share`のdoc参照、既知の限界）。
        crate::smb_share::destroy_ephemeral_share(&share_name, &user_name, None);
    }

    for vm_name in &orphans {
        let diff_vhdx = ledger
            .entries
            .iter()
            .find(|e| &e.vm_name == vm_name)
            .map(|e| PathBuf::from(&e.diff_vhdx))
            .unwrap_or_else(|| config.vm_work_dir.join(format!("{vm_name}.diff.vhdx")));
        if let Err(e) = teardown_vm(vm_name, &diff_vhdx) {
            eprintln!("gc_orphan_sessions: failed to tear down orphan VM {vm_name}: {e}");
        }
        crate::vm_ledger::remove_session(vm_name);
    }

    // 台帳・生存VMのどちらからも参照されなくなった差分VHDXの取りこぼしを一掃する
    // （teardown_vm自体が消し忘れた場合の保険、`vm_work_dir`直下のみを対象にする）。
    let Ok(read_dir) = std::fs::read_dir(&config.vm_work_dir) else {
        return orphans;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(session_part) = file_name.strip_suffix(".diff.vhdx") else {
            continue;
        };
        if session_part == current_session_id
            || session_part == crate::vm_ledger::WARM_VM_NAME
            || existing_vm_names.iter().any(|n| n == session_part)
        {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }

    orphans
}

fn teardown_vm(vm_name: &str, diff_vhdx: &Path) -> Result<(), VmError> {
    let script = format!(
        r#"
Stop-VM -Name '{name}' -TurnOff -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-VM -Name '{name}' -Force -ErrorAction SilentlyContinue
Remove-Item -Path '{diff}' -Force -ErrorAction SilentlyContinue
"#,
        name = vm_name,
        diff = diff_vhdx.display(),
    );
    run_powershell(&script)?;
    Ok(())
}

fn wait_tcp_reachable(ip: IpAddr, port: u16, timeout: Duration) -> Result<(), VmError> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&(ip, port).into(), Duration::from_secs(2)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(VmError::Timeout(format!("{ip}:{port}")));
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, VmError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            // `.harness/`・`.git/`はワークスペース同期の対象外（サンドボックス制御用の
            // メタデータ・VCS内部構造をコンテナへ持ち込まない、Tier1a/Tier2の既存慣習と同じ）。
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == ".harness" || name == ".git" {
                    continue;
                }
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_path_leaves_ascii_alone() {
        assert_eq!(urlencoding_path("/workspace/foo.txt"), "/workspace/foo.txt");
    }

    #[test]
    fn urlencoding_path_escapes_space() {
        assert_eq!(urlencoding_path("/workspace/a b.txt"), "/workspace/a%20b.txt");
    }

    #[test]
    fn build_sni_proxy_conf_maps_allowed_domains_to_allow() {
        let conf = build_sni_proxy_conf(&["example.com".to_string(), "api.example.org".to_string()]);
        assert!(conf.contains("example.com     \"example.com:443\";"));
        assert!(conf.contains("api.example.org     \"api.example.org:443\";"));
        assert!(conf.contains("example.com     \"ALLOW\";"));
        assert!(conf.contains("default              \"\";"));
        assert!(conf.contains("default              \"DENY\";"));
        assert!(conf.contains(&format!("listen {INCUS_BRIDGE_IP}:{SNI_PROXY_PORT};")));
        assert!(conf.contains(&format!("access_log {SNI_AUDIT_LOG_PATH} sniaudit;")));
    }

    #[test]
    fn build_sni_proxy_conf_with_no_domains_only_has_defaults() {
        let conf = build_sni_proxy_conf(&[]);
        assert!(conf.contains("default              \"\";"));
        assert!(conf.contains("default              \"DENY\";"));
        assert!(!conf.contains("ALLOW"));
    }
}
