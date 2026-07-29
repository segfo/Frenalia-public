//! Tier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）の実行機構本体
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md`、`plans/vm-spike/RESULTS.md`）。
//!
//! `harness-vmsandboxd`（常駐デーモン、`crate::vmsandboxd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのHyper-V操作を直接呼ばない（D-21）。Incus REST APIはmTLS越しの
//! ネットワーク呼び出しであり管理者権限を要しないが、デーモンプロセス内に閉じて構わないため
//! ここへ同居させる。
//!
//! **Phase 1（`run_shell`統合）+ Phase 2（出口許可リスト統合）は完了・実機E2E確認済み**
//! （`RESULTS.md`§3.9/§3.10）。出口許可リスト（Incus ACL + nftables DNAT + SNI preread
//! プロキシ + 監査ログ）は`allow_domains`が非空の場合のみ構成し、空なら無制限出口のまま
//! （`--net-allow-domain`未指定時の後方互換）。ゴールデン像へのIncusクライアント証明書焼き込み
//! も完了しており、ランタイムはSSH・ペアリング不要でmTLS直結できる。
//!
//! **Phase 3実装済み（台帳+GC・ウォームスタート）**、**Phase B実装済み（VM共有化・
//! マルチセッション並行化、`DESIGN-SANDBOX-VMISOLATION.md`項目8）**:
//! - **VM共有化（`crate::vm_host::VmHost`）**: 外層VMはもうセッションごとに新規作成される
//!   専有物ではなく、参照カウントされる共有resident資源になった。`VmSession::start`は
//!   `VmHost::attach`（未起動なら起動、起動済みなら`refcount`を増やして即座にアタッチ）を
//!   呼ぶだけで、VM作成コード自体は`vm_host`モジュールへ移動した。ウォームスタート
//!   （`--tier3-warm`）もこの`attach`の内部実装（checkpointからの`Restore-VMSnapshot`）に
//!   統合され、`WarmLock`によるファイルロック直列化は不要になった（daemonプロセス内の
//!   `Mutex`一本で足りる、daemon自体がS-2の固定パイプ名で単一プロセスに保証されているため）。
//! - **台帳+GC（D-24）**: `crate::vm_ledger`のスキーマをVM共有化に合わせて分離した
//!   （単一の`VmHostEntry`＋`workspace_id`単位の`WorkspaceResourceEntry`群）。
//!   `gc_orphan_sessions`は`VmHost::attach`のStopped→Running遷移直前にのみ呼ばれる
//!   （セッション途中で誤って現在生存中のVMを孤児扱いしないため）。
//! - **マルチセッション並行化**: `vmsandboxd::serve_resident`はthread-per-session化され、
//!   `SessionRegistry`が同時実行数上限（既定4・`--tier3-max-sessions`）を管理する。各セッションに
//!   割り当てられる`slot`番号がコンテナの静的IP・SNIプロキシポートの衝突回避に使われる。
//! - **ワークスペース単位資源の参照カウント共有**（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）:
//!   SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウントは`workspace_id`
//!   （`smb_share::compute_workspace_id`）単位で参照カウント共有する。Incusコンテナと
//!   出口許可リストはセッション単位のまま（同一ワークスペースでもコンテナは分ける）。
//!
//! **Tier3残課題の解消済み範囲**:
//! - VM refcountが0になった際、warm運用なら`WarmIdle`へparkして次回warm復帰できる。
//! - SNI監査ログはslot別のVM内ファイルへ分離し、teardown時にセッション別ログとして
//!   `.harness/sandbox/tier3-net-audit-<session_id>.log`へ回収する。
//! - nginx設定の反映は既存プロセスへの`nginx -s reload`を優先し、未起動時だけ新規起動する。
//!
//! ワークスペース共有は`WorkspaceShareMode::Cifs`（SMBライブ共有、Incus disk deviceでのbind-mount）
//! が既定であり、D-22のライブマウントはこの経路で実現済み。`HARNESS_TIER3_CIFS_WORKSPACE=0`で
//! 選べる`WorkspaceShareMode::CopyInOut`（セッション境界でのcopy-in/copy-out）は非既定の
//! フォールバック経路として残っている。
//!
//! 固定の運用規約（`plans/vm-spike/RESULTS.md`§3.6/§3.7で確立、実機E2E確認済み）:
//! - ゴールデン親VHDX: `C:\ProgramData\harness\golden-images\almalinux-golden.vhdx`
//! - 内部vSwitch: `harness-tier3-outer-internal`（`172.20.100.0/24`、ホスト側ゲートウェイ
//!   `172.20.100.1`、`New-NetNat`による出口）
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
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
fn unique_session_id() -> String {
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

/// クライアント証明書のホスト側保存先（`%APPDATA%\harness\config\tier3-incus-client\`）。
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
        .args(["-t", "ed25519", "-N", "", "-C", "harness-tier3", "-f"])
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
pub(crate) fn reset_known_hosts_file() -> Result<(), VmError> {
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
fn ssh_exec_checked(
    host: IpAddr,
    key_path: &Path,
    cmd: &str,
    timeout: Duration,
) -> Result<String, VmError> {
    let (stdout, stderr, code) = ssh_exec(host, key_path, cmd, timeout)?;
    if code != 0 {
        return Err(VmError::Io(format!(
            "ssh command failed (exit={code}): {cmd}\nstdout={stdout}\nstderr={stderr}"
        )));
    }
    Ok(stdout)
}

/// L2（ゲスト側CIFSマウント）の存在と健全性をゲスト自身に問い合わせる（BUG-026の根本修正）。
/// 台帳（L1の正本）はこの判定に使えない——VMは使い捨てだが台帳は`%APPDATA%`に永続するため、
/// 両者がズレると台帳のエントリだけを根拠に「マウント済み」とみなす再利用分岐が
/// `add_disk_device`で"Missing source path"に恒久的に失敗する（`docs/bugs/BUG-026.md`参照）。
/// `mountpoint -q`だけでなく実I/O（`ls`）まで確認するのは、SMBアカウント削除後のstale mount
/// （マウントエントリ自体は残るが認証が通らない状態、状態S5）を「マウント有り」と誤判定
/// しないため。
fn guest_workspace_mount_is_healthy(host: IpAddr, key: &Path, mount_point: &str) -> bool {
    match ssh_exec(
        host,
        key,
        &format!("mountpoint -q {mount_point} && ls {mount_point} >/dev/null 2>&1"),
        Duration::from_secs(15),
    ) {
        Ok((_, _, code)) => code == 0,
        Err(_) => false,
    }
}

/// AlmaLinux VM自体（`root`）へファイルを配置する（`ssh ... 'cat > path'`にstdin経由で
/// 内容を流し込む。Incus内のコンテナではなくVMのホストOS側へ書く点が`IncusClient::push_file`
/// との違い）。
fn ssh_push_file(
    host: IpAddr,
    key_path: &Path,
    contents: &[u8],
    remote_path: &str,
) -> Result<(), VmError> {
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
/// **`Clone`（Phase B、`crate::vm_host::VmHost`）**: 内部は`String`（base_url）・`IpAddr`
/// （Copy）・`reqwest::blocking::Client`（内部Arc、実接続を保持しない設定オブジェクト）のみ
/// なので複製は安全。常駐VMへ複数セッションが同時にアタッチする際、各セッションが同じ
/// resident VMへの接続設定を独立に保持できるようにするために必要。
#[derive(Clone)]
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
    pub fn new(
        host: IpAddr,
        port: u16,
        client_crt: &Path,
        client_key: &Path,
    ) -> Result<Self, VmError> {
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

    fn wait_operation(
        &self,
        op_path: &str,
        timeout: Duration,
    ) -> Result<serde_json::Value, VmError> {
        let wait_path = format!("{op_path}/wait?timeout={}", timeout.as_secs());
        let (status, value) = self.request(reqwest::Method::GET, &wait_path, None)?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "operation wait failed: status={status} body={value}"
            )));
        }
        let metadata = value
            .get("metadata")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
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

    /// **Phase B実機E2Eで発見**: Incus自体が`POST /1.0/instances`（作成）操作を1件ずつしか
    /// 受け付けず、常駐VM上で複数セッションがほぼ同時に`create_container`を呼ぶと
    /// `Failed creating instance record: Instance is busy running a "create" operation`で
    /// 一方が失敗する（旧「1VM=1セッション」前提では同時に1コンテナしか作られないため
    /// 顕在化しなかった）。コンテナ名自体は`session_id`でユニークなので衝突ではなく、
    /// Incus側の直列化待ちにすぎないため、この特定のエラーメッセージに対してのみ短い
    /// バックオフ付きリトライを行う（作成自体は実測0.3秒程度と高速、`RESULTS.md`参照）。
    pub fn create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
        const MAX_ATTEMPTS: u32 = 20;
        let mut last_err = None;
        for attempt in 0..MAX_ATTEMPTS {
            match self.try_create_container(name, image_alias) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("busy running a") {
                        std::thread::sleep(Duration::from_millis(300 + 100 * attempt as u64));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| VmError::Incus("create_container: exhausted retries".to_string())))
    }

    fn try_create_container(&self, name: &str, image_alias: &str) -> Result<(), VmError> {
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
        let (status, value) = self.request(reqwest::Method::POST, "/1.0/instances", Some(body))?;
        if status >= 400 {
            return Err(VmError::Incus(format!(
                "create_container failed: status={status} body={value}"
            )));
        }
        let op: IncusOperation = serde_json::from_value(
            value
                .get("operation")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .or_else(|_| {
            // 一部のIncusバージョンは`metadata.id`にoperation idを積む。
            serde_json::from_value::<IncusOperation>(
                value
                    .get("metadata")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
        })
        .map_err(|e| VmError::Incus(format!("failed to parse operation id: {e}")))?;
        self.wait_operation(
            &format!("/1.0/operations/{}", op.id),
            Duration::from_secs(180),
        )?;
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

    /// `POST /1.0/network-acls`: 「tcp/443への直接出口を宛先指定なしで許可、それ以外は
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

    /// コンテナの`eth0`デバイスへACLを適用し、既定出口をdropにする
    /// （`security.acls.default.出口.action=drop`、`RESULTS.md`§3.8）。
    pub fn attach_acl_to_container(
        &self,
        container_name: &str,
        acl_name: &str,
    ) -> Result<(), VmError> {
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
        let config = inst
            .get("config")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
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
    /// **BUG-026で根本原因を確定**: `Missing source path ... for disk`は「Incus側の
    /// ファイルシステム状態確認の遅延」ではなく、呼び出し側（`attach_to_guest`）が
    /// **台帳の再利用分岐で実際にゲスト側マウントを検証せずここへ来た場合に決定論的に
    /// 発生する**（台帳はWindows側で永続、マウントはVM寿命限りのため両者がズレ得る）。
    /// 根本修正は呼び出し側（`guest_workspace_mount_is_healthy`によるゲスト直接問い合わせ、
    /// `docs/bugs/BUG-026.md`参照）で行うため、ここでのリトライは真にIncus側の短い
    /// ファイルシステム反映遅延（実在するマウントに対する一時的な取りこぼし）だけを
    /// 吸収する短めの回数に留める。
    pub fn add_disk_device(
        &self,
        container_name: &str,
        device_name: &str,
        source: &str,
        path: &str,
    ) -> Result<(), VmError> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = None;
        for attempt in 0..MAX_ATTEMPTS {
            match self.try_add_disk_device(container_name, device_name, source, path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Missing source path") {
                        std::thread::sleep(Duration::from_millis(300 + 200 * attempt as u64));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| VmError::Incus("add_disk_device: exhausted retries".to_string())))
    }

    fn try_add_disk_device(
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
        let config = inst
            .get("config")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
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
            .ok_or_else(|| {
                VmError::Incus(format!("container {name} has no volatile.idmap.current"))
            })?;
        let idmap: Vec<serde_json::Value> = serde_json::from_str(idmap_str)
            .map_err(|e| VmError::Incus(format!("failed to parse volatile.idmap.current: {e}")))?;
        let uid = idmap
            .iter()
            .find(|e| {
                e.get("Isuid").and_then(|v| v.as_bool()) == Some(true)
                    && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0)
            })
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                VmError::Incus(format!("container {name}: no uid mapping for nsid 0"))
            })?;
        let gid = idmap
            .iter()
            .find(|e| {
                e.get("Isgid").and_then(|v| v.as_bool()) == Some(true)
                    && e.get("Nsid").and_then(|v| v.as_i64()) == Some(0)
            })
            .and_then(|e| e.get("Hostid"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                VmError::Incus(format!("container {name}: no gid mapping for nsid 0"))
            })?;
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
pub(crate) const INCUS_BRIDGE_IP: &str = "10.76.180.1";
/// SNI prereadプロキシのlistenポートの基準値。**Phase B**: 常駐VM上に複数セッションが同居する
/// ため、セッションごとに`SNI_PROXY_PORT_BASE + slot`でポートを分ける（`slot`は
/// `vmsandboxd::SessionRegistry`が同時実行数上限の枠として払い出す番号、
/// `crate::vmsandbox::container_static_ip_cidr`と同じ`slot`を共有する）。単一ポートのままだと、
/// 全セッションの許可ドメインが1つの`map`に混ざり、会話単位で出口を絞るというTier3の目的が
/// 崩れる（S-5、DNATは認可ではない）。
pub(crate) const SNI_PROXY_PORT_BASE: u16 = 8444;
const SNI_PROXY_CONF_PATH: &str = "/root/harness-sni-proxy.conf";
const SNI_PROXY_PID_PATH: &str = "/run/harness-sni-proxy.pid";
const SNI_AUDIT_LOG_DIR: &str = "/var/log/nginx/harness-sni-audit";
const NFTABLES_TABLE: &str = "harness_tier3";

fn sni_proxy_port_for_slot(slot: u8) -> u16 {
    SNI_PROXY_PORT_BASE + slot as u16
}

fn sni_audit_log_path_for_slot(slot: u8) -> String {
    format!("{SNI_AUDIT_LOG_DIR}/slot-{slot}.log")
}

/// 常駐VM上で現在出口許可リストを構成中の1セッション分の情報
/// （`crate::vm_host::VmHost`が全アクティブセッション分をまとめて保持する）。
#[derive(Debug, Clone)]
pub(crate) struct EgressSession {
    pub slot: u8,
    pub container_ip: String,
    pub allow_domains: Vec<String>,
}

/// `allow_domains`の入力検証（B-1）。S-2で固定パイプ名IPCが同一ユーザーの任意プロセスへ
/// 開かれた以上、`allow_domains`はもう信頼できる内部値ではなく外部入力として扱う必要がある。
/// nginx設定・nftables/shellコマンドへ生文字列のまま補間されるため、ドメイン名として
/// 妥当な文字集合（英数字・`.`・`-`）と長さ上限のみを許可する。
pub(crate) fn validate_allow_domain(domain: &str) -> Result<(), VmError> {
    const MAX_DOMAIN_LEN: usize = 253; // RFC 1035の全体長上限。
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return Err(VmError::Incus(format!(
            "invalid allow_domain (empty or too long, max {MAX_DOMAIN_LEN}): {domain:?}"
        )));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(VmError::Incus(format!(
            "invalid allow_domain (only [a-zA-Z0-9.-] allowed): {domain:?}"
        )));
    }
    Ok(())
}

/// SNI prereadプロキシのnginx設定を、**現在アクティブな全セッション分**まとめて動的生成する
/// （`plans/vm-spike/RESULTS.md`§3.8の単一セッション版から、Phase Bでセッションごとに
/// 独立した`map`+`server`ブロックへ拡張。2セッション目の設定生成が1セッション目のものを
/// 消してしまう問題（A-8）への是正）。ブロック間で`map`のターゲット変数名が衝突しないよう
/// `slot`をsuffixにする。
fn build_sni_proxy_conf_multi(sessions: &[EgressSession]) -> String {
    let mut server_blocks = String::new();
    for s in sessions {
        let map_lines: String = s
            .allow_domains
            .iter()
            .map(|d| format!("        {d}     \"{d}:443\";\n"))
            .collect();
        let decision_lines: String = s
            .allow_domains
            .iter()
            .map(|d| format!("        {d}     \"ALLOW\";\n"))
            .collect();
        let port = sni_proxy_port_for_slot(s.slot);
        let audit_log = sni_audit_log_path_for_slot(s.slot);
        server_blocks.push_str(&format!(
            r#"
    map $ssl_preread_server_name $sni_upstream_{slot} {{
{map_lines}        default              "";
    }}
    map $ssl_preread_server_name $sni_decision_{slot} {{
{decision_lines}        default              "DENY";
    }}

    server {{
        listen {INCUS_BRIDGE_IP}:{port};
        ssl_preread on;
        proxy_pass $sni_upstream_{slot};
        proxy_connect_timeout 5s;
        proxy_timeout 30s;
        access_log {audit_log} sniaudit;
    }}
"#,
            slot = s.slot,
            audit_log = audit_log,
        ));
    }
    format!(
        r#"load_module /usr/lib64/nginx/modules/ngx_stream_module.so;
worker_processes auto;
error_log /var/log/nginx/harness-sni-proxy-error.log warn;
events {{ worker_connections 1024; }}
stream {{
    resolver 1.1.1.1 valid=60s;

    log_format sniaudit '$time_iso8601 client=$remote_addr sni="$ssl_preread_server_name" '
                         'upstream=$upstream_addr '
                         'bytes_sent=$bytes_sent bytes_received=$bytes_received '
                         'duration=$session_time status=$status';
{server_blocks}}}
"#
    )
}

/// nftables: 全アクティブセッション分のDNAT（コンテナ発の443宛先を各自のSNIプロキシポートへ
/// 透過リダイレクト）+ S-5 filterチェーン（「送信元IPが当該セッションのコンテナIPでない限り、
/// そのセッションのproxyポートへの到達をdrop」）をまとめて再構成する。DNATは認可ではない
/// （コンテナBが直接`10.76.180.1:<Aのポート>`へ繋げばAの許可リストを使えてしまう、または
/// 同一L2での送信元IP詐称でAのDNATに乗れてしまう）ため、filterチェーンが実質的な認可点になる。
fn build_nftables_script(sessions: &[EgressSession]) -> String {
    let mut lines = String::new();
    lines.push_str(&format!("nft add table ip {NFTABLES_TABLE}\n"));
    lines.push_str(&format!(
        "nft 'add chain ip {NFTABLES_TABLE} prerouting {{ type nat hook prerouting priority dstnat ; }}'\n"
    ));
    lines.push_str(&format!(
        "nft 'add chain ip {NFTABLES_TABLE} input {{ type filter hook input priority filter ; policy accept ; }}'\n"
    ));
    for s in sessions {
        let port = sni_proxy_port_for_slot(s.slot);
        lines.push_str(&format!(
            "nft add rule ip {NFTABLES_TABLE} prerouting iifname \"incusbr0\" ip saddr {ip} tcp dport 443 redirect to :{port}\n",
            ip = s.container_ip,
        ));
        // S-5: このセッション専用のproxyポートへは、そのセッションのコンテナIP以外からの
        // 到達をdropする（DNAT経路以外での直接アクセス・送信元IP詐称の両方を塞ぐ）。
        lines.push_str(&format!(
            "nft add rule ip {NFTABLES_TABLE} input ip daddr {INCUS_BRIDGE_IP} tcp dport {port} ip saddr != {ip} drop\n",
            ip = s.container_ip,
        ));
    }
    lines
}

/// SNI prereadプロキシ + nftables DNAT/filter + コンテナ側Incus ACLを、AlmaLinux VM自体へ
/// SSH経由で構成する。**Phase B**: `active_sessions`は呼び出し時点で出口を構成している
/// 全セッション（このセッション自身を含む）——1本の呼び出しが常にVM全体の設定を丸ごと
/// 再生成するため、呼び出し側（`crate::vm_host::VmHost`）が単一ロックの下で
/// 「集合を更新→この関数を呼ぶ」を一体で行う必要がある（さもないと2セッション目の呼び出しが
/// 1セッション目の設定を消す、A-8）。
pub(crate) fn apply_egress_ruleset(
    guest_ip: IpAddr,
    ssh_key: &Path,
    active_sessions: &[EgressSession],
) -> Result<(), VmError> {
    for s in active_sessions {
        for d in &s.allow_domains {
            validate_allow_domain(d)?;
        }
    }

    // 1. nginx SNI prereadプロキシを配置・反映。既に起動中ならreloadし、未起動またはreload
    //    失敗時のみ新規起動する。セッション追加/削除のたびに既存TLS接続を切らないため。
    let conf = build_sni_proxy_conf_multi(active_sessions);
    ssh_push_file(guest_ip, ssh_key, conf.as_bytes(), SNI_PROXY_CONF_PATH)?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!("mkdir -p {SNI_AUDIT_LOG_DIR}"),
        Duration::from_secs(10),
    )?;
    ssh_exec_checked(
        guest_ip,
        ssh_key,
        &format!(
            "if test -f {SNI_PROXY_PID_PATH} && kill -0 $(cat {SNI_PROXY_PID_PATH}) 2>/dev/null; then \
             nginx -c {SNI_PROXY_CONF_PATH} -g 'pid {SNI_PROXY_PID_PATH};' -s reload; \
             else nginx -c {SNI_PROXY_CONF_PATH} -g 'pid {SNI_PROXY_PID_PATH};'; fi"
        ),
        Duration::from_secs(10),
    )?;

    // 2. nftables: 既存テーブルを削除してから全セッション分を作り直す（べき等性、A-8是正）。
    let _ = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("nft delete table ip {NFTABLES_TABLE}"),
        Duration::from_secs(10),
    );
    if !active_sessions.is_empty() {
        let script = build_nftables_script(active_sessions);
        ssh_exec_checked(guest_ip, ssh_key, &script, Duration::from_secs(15))?;
    }

    Ok(())
}

/// コンテナ側Incus ACL: tcp/443への直接出口を宛先指定なしで許可するだけでよい
/// （プロキシの存在をコンテナに一切意識させない、`RESULTS.md`§3.8）。セッション単位で
/// 一度だけ呼べばよく、VM全体の再生成とは独立（コンテナ削除で自動的に消える）。
pub(crate) fn attach_egress_acl(incus: &IncusClient, container_name: &str) -> Result<(), VmError> {
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
    slot: u8,
) -> Result<(), VmError> {
    let remote_log = sni_audit_log_path_for_slot(slot);
    let (stdout, _stderr, code) = ssh_exec(
        guest_ip,
        ssh_key,
        &format!("cat {remote_log} 2>/dev/null"),
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

/// 稼働中のTier3セッション（常駐VM上の1コンテナ）を表す。`VmSandboxHandle`
/// （`crate::vmsandboxd`）がデーモンプロセス内で保持し続ける。**Phase B**: VM自体は
/// `crate::vm_host::VmHost`が参照カウントで管理する共有resident資源になったため、本構造体は
/// もはやVMの識別子（旧`vm_name`/`diff_vhdx`）を保持しない——teardown時にVMを操作するのは
/// `VmHost::release`の責務であり、本構造体が知る必要があるのは自分のコンテナと
/// ワークスペース単位資源（`workspace_id`）だけである。
pub struct VmSession {
    session_id: String,
    /// このセッションが同時実行数上限の枠として払い出された番号（`vmsandboxd::SessionRegistry`
    /// 参照）。コンテナの静的IP・SNIプロキシポートの衝突回避に使う。
    slot: u8,
    /// `short_id(canonicalized workspace_root)`（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）。
    /// SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウントはこのIDで参照カウント共有する。
    workspace_id: String,
    container_name: String,
    incus: IncusClient,
    /// 出口許可リスト（SNIプロキシ+nftables DNAT）を構成した場合のみ`Some`（`allow_domains`
    /// が非空だった場合）。teardown時にこれを見て監査ログ取得・出口設定解除の要否を判定する。
    ssh_key: Option<PathBuf>,
    /// `WorkspaceShareMode::Cifs`のセッションかどうかのフラグを兼ねる（`Some`なら
    /// teardownで`copy_out_workspace`をスキップし、ワークスペース単位資源の参照カウント
    /// 解放を行う）。実際の共有名・アカウント名は台帳の`WorkspaceResourceEntry`が正であり
    /// （`workspace_id`単位で複数セッションが共有し得るため）、本フィールドはteardown時の
    /// 分岐判定にのみ使う。
    smb_share_name: Option<String>,
}

/// ワークスペース単位資源（SMB共有・使い捨てアカウント・NTFS ACE・CIFSマウント）の
/// 「台帳を見て無ければ作成/参照カウント0なら破棄する」判定〜実行を全セッション横断で
/// 直列化するロック（Phase B実機E2Eで発見したTOCTOUバグの是正、`attach_to_guest`/
/// `teardown`のdoc参照）。`workspace_id`単位ではなくプロセス全体で単一にしている理由は、
/// 作成・破棄そのものが高速（数百ms、`RESULTS.md`参照）でありワークスペースをまたいだ
/// 競合が実運用上ほぼ無いため、実装を単純に保つトレードオフを取ったもの。
static WORKSPACE_RESOURCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CONTAINER_IMAGE_ALIAS: &str = "alpine/3.21";
/// コンテナの静的IPのベースオクテット。実際のIPは`10.76.180.{CONTAINER_IP_BASE + slot}/24`
/// （`slot`: 0..同時実行数上限）。**Phase Bで新規発見**: 旧実装は全コンテナに固定
/// `10.76.180.60/24`を割り当てていた（旧「1VM=1セッション」前提では同時に1コンテナしか
/// 存在しないため無害だったが、常駐VM上に複数コンテナが同居する今回の設計ではIP衝突になる）。
const CONTAINER_IP_BASE: u8 = 61;
const CONTAINER_GATEWAY: &str = "10.76.180.1";
const WORKSPACE_MOUNT: &str = "/workspace";

pub(crate) fn container_static_ip_cidr(slot: u8) -> String {
    format!("10.76.180.{}/24", CONTAINER_IP_BASE.saturating_add(slot))
}

pub(crate) fn container_ip(slot: u8) -> String {
    format!("10.76.180.{}", CONTAINER_IP_BASE.saturating_add(slot))
}

/// ゲストが静的IPで応答し、Incus mTLSクライアント証明書が信頼されるまで待つ（コールドブート
/// ・ウォームRestoreの両方から共有、B4/B5参照）。`guest_wait_timeout`は呼び出し側が
/// コールド/ウォームに応じて使い分ける（コールドは起動+firstbootを見込み長め、ウォームは
/// 既に起動済みのはずなので短め、B8参照）。
pub(crate) fn wait_for_guest_ready(
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

/// BUG-026の状態表（`docs/bugs/BUG-026.md`参照）に沿って、ワークスペース単位資源
/// （SMB共有・使い捨てアカウント・NTFS ACE・ゲスト側CIFSマウント）を確保する。
/// 台帳エントリの有無とゲスト側マウントの健全性の組み合わせ（8状態）を
/// Reuse/Repair/CreateFreshの3アクションへ振り分ける。呼び出し側（`attach_to_guest`）が
/// `WORKSPACE_RESOURCE_LOCK`を保持した状態で呼ぶこと。
/// 台帳エントリの有無とゲスト側マウントの健全性の組み合わせ（BUG-026の状態表S0〜S7、
/// `docs/bugs/BUG-026.md`参照）が導くアクション。実SSH/PowerShellに依存しない純関数
/// （[`decide_workspace_action`]）へ切り出し、8状態を表駆動で単体テストできるようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceAction {
    /// S7: 台帳にあり、ゲスト側マウントも健全。そのまま再利用する。
    Reuse,
    /// S4/S5/S6: 台帳にはあるがゲスト側マウントが不健全。修復（パスワードローテーション、
    /// 失敗すれば作り直し）を試みる。
    Repair,
    /// S0〜S3: 台帳に無い。新規作成する（S1/S3で残存マウントがあれば先に外す）。
    CreateFresh,
}

fn decide_workspace_action(existing_present: bool, mount_healthy: bool) -> WorkspaceAction {
    match (existing_present, mount_healthy) {
        (true, true) => WorkspaceAction::Reuse,
        (true, false) => WorkspaceAction::Repair,
        (false, _) => WorkspaceAction::CreateFresh,
    }
}

fn acquire_or_repair_workspace_share(
    workspace_root: &Path,
    workspace_id: &str,
    config: &VmSandboxConfig,
    host_ssh_key: &Path,
    mount_point: &str,
    incus: &IncusClient,
    container_name: &str,
) -> Result<(String, String), VmError> {
    let existing = crate::vm_ledger::load()
        .workspace_resources
        .into_iter()
        .find(|e| e.workspace_id == workspace_id);
    let mount_healthy =
        guest_workspace_mount_is_healthy(config.guest_ip, host_ssh_key, mount_point);
    let action = decide_workspace_action(existing.is_some(), mount_healthy);

    match (action, existing) {
        (WorkspaceAction::Reuse, Some(existing)) => {
            crate::vm_ledger::record_workspace_resource(
                workspace_id,
                workspace_root,
                &existing.smb_share_name,
                &existing.smb_user,
                &existing.smb_user_sid,
            );
            Ok((existing.smb_share_name, existing.smb_user))
        }
        (WorkspaceAction::Repair, Some(existing)) => repair_workspace_share(
            workspace_root,
            workspace_id,
            config,
            host_ssh_key,
            mount_point,
            &existing,
            incus,
            container_name,
        ),
        (WorkspaceAction::CreateFresh, _)
        | (WorkspaceAction::Reuse | WorkspaceAction::Repair, None) => {
            // 後段の`(_, None)`は`decide_workspace_action`の契約上到達し得ない
            // （Reuse/Repairは`existing_present == true`のときにしか返らない）が、
            // 型レベルでは`Option`と`WorkspaceAction`が独立のため網羅性のために置く。
            // 台帳に無いのにマウントだけ残っている（S1/S3、前世代の孤児マウント）場合は、
            // 先に外してから作る。
            if mount_healthy {
                let _ = ssh_exec(
                    config.guest_ip,
                    host_ssh_key,
                    &format!("umount -l {mount_point} 2>/dev/null"),
                    Duration::from_secs(10),
                );
            }
            create_fresh_workspace_share(
                workspace_root,
                workspace_id,
                config,
                host_ssh_key,
                mount_point,
                incus,
                container_name,
            )
        }
    }
}

/// 状態S4/S5/S6の修復。既存のSMB共有・NTFS ACEを流用し、使い捨てアカウントのパスワードだけ
/// ローテーションして再mountする（実リポジトリ規模でも高速、`smb_share::rotate_share_password`
/// のdoc参照）。アカウント自体が既に消えている場合（状態S4/S5、ローテーションが失敗する）は
/// 共有・アカウントを作り直す。
#[allow(clippy::too_many_arguments)]
fn repair_workspace_share(
    workspace_root: &Path,
    workspace_id: &str,
    config: &VmSandboxConfig,
    host_ssh_key: &Path,
    mount_point: &str,
    existing: &crate::vm_ledger::WorkspaceResourceEntry,
    incus: &IncusClient,
    container_name: &str,
) -> Result<(String, String), VmError> {
    match crate::smb_share::rotate_share_password(&existing.smb_user) {
        Ok(password) => {
            remount_workspace_share(
                config,
                host_ssh_key,
                mount_point,
                &existing.smb_share_name,
                &existing.smb_user,
                &password,
                workspace_id,
                incus,
                container_name,
            )?;
            crate::vm_ledger::record_workspace_resource(
                workspace_id,
                workspace_root,
                &existing.smb_share_name,
                &existing.smb_user,
                &existing.smb_user_sid,
            );
            Ok((existing.smb_share_name.clone(), existing.smb_user.clone()))
        }
        Err(_) => {
            // アカウント自体が既に存在しない（状態S4/S5）。共有・アカウントを作り直す
            // （`destroy_ephemeral_share`はbest-effort、無くても無害）。
            crate::smb_share::destroy_ephemeral_share(
                &existing.smb_share_name,
                &existing.smb_user,
                Some(workspace_root),
            );
            create_fresh_workspace_share(
                workspace_root,
                workspace_id,
                config,
                host_ssh_key,
                mount_point,
                incus,
                container_name,
            )
        }
    }
}

/// 状態S0〜S3の新規作成。共有・アカウント・NTFS ACEを新規作成し、マウント成功を確認して
/// から台帳へ記録する（BUG-024層2の教訓: マウント成功前に記録すると、失敗時に
/// 「実体はあるがゲスト側マウントは無い」不整合が台帳に残る）。
fn create_fresh_workspace_share(
    workspace_root: &Path,
    workspace_id: &str,
    config: &VmSandboxConfig,
    host_ssh_key: &Path,
    mount_point: &str,
    incus: &IncusClient,
    container_name: &str,
) -> Result<(String, String), VmError> {
    let (share, user, password, sid) =
        crate::smb_share::create_ephemeral_share(workspace_id, workspace_root)?;
    remount_workspace_share(
        config,
        host_ssh_key,
        mount_point,
        &share,
        &user,
        &password,
        workspace_id,
        incus,
        container_name,
    )?;
    crate::vm_ledger::record_workspace_resource(workspace_id, workspace_root, &share, &user, &sid);
    Ok((share, user))
}

/// cred fileの配布・`mount -t cifs`・`mountpoint -q`での成立確認を行う（Repair/CreateFresh
/// 共通、旧`attach_to_guest`のインライン処理を切り出したもの）。診断強化（`mount`/`dmesg`/
/// `ls`ダンプ）は実機E2Eで`add_disk_device`の"Missing source path"原因調査のために追加した
/// もので、根本原因確定後もマウント失敗時の一次切り分けとして有用なため残す。
#[allow(clippy::too_many_arguments)]
fn remount_workspace_share(
    config: &VmSandboxConfig,
    host_ssh_key: &Path,
    mount_point: &str,
    share: &str,
    user: &str,
    password: &str,
    workspace_id: &str,
    incus: &IncusClient,
    container_name: &str,
) -> Result<(), VmError> {
    let cred_remote = format!("/etc/harness-smb-{workspace_id}.cred");
    let cred_contents = format!("username={user}\npassword={password}\n");
    ssh_push_file(
        config.guest_ip,
        host_ssh_key,
        cred_contents.as_bytes(),
        &cred_remote,
    )?;
    ssh_exec_checked(
        config.guest_ip,
        host_ssh_key,
        &format!("chmod 600 {cred_remote}"),
        Duration::from_secs(10),
    )?;

    // unprivilegedコンテナのroot（namespace uid 0）が実際にホスト側でどのuid/gidへ
    // マップされるかを問い合わせ、CIFSマウントの`uid=/gid=`をそれに合わせる
    // （`container_root_host_id`のdoc参照。`shift=true`によるidmap shiftはCIFSが
    // 対応しておらず使えないため、この静的合わせが唯一の非特権コンテナ向け解決策、
    // spike検証で確認済み）。
    let (host_uid, host_gid) = incus.container_root_host_id(container_name)?;
    ssh_exec_checked(
        config.guest_ip,
        host_ssh_key,
        &format!(
            "set -x; \
             mkdir -p {mount_point} && \
             mount -t cifs //{smb_host}/{share} {mount_point} \
             -o credentials={cred_remote},uid={host_uid},gid={host_gid},forceuid,forcegid,\
             file_mode=0644,dir_mode=0755,cache=strict,vers=3.1.1; \
             if mountpoint -q {mount_point}; then \
               echo STEP=mount-ok; \
             else \
               echo STEP=mount-verify-failed; \
               echo '---diag: mount | grep cifs---'; mount | grep cifs; \
               echo '---diag: dmesg tail---'; dmesg 2>/dev/null | tail -n 20; \
               echo '---diag: ls mount_point---'; ls -la {mount_point}; \
               exit 1; \
             fi",
            smb_host = config.smb_host_ip,
        ),
        Duration::from_secs(30),
    )?;
    Ok(())
}

impl VmSession {
    /// 常駐VM（`crate::vm_host::VmHost`が参照カウントで管理）へアタッチ→コンテナ作成/起動→
    /// ワークスペース資源の確保、までを一気に行う。**Phase B**: VM自体の起動は
    /// `VmHost::attach`が担う。2セッション目以降は既に起動済みのVMへ即座にアタッチするだけで、
    /// 新規VM作成は発生しない。`slot`は`vmsandboxd::SessionRegistry`が同時実行数上限の枠として
    /// 払い出す番号で、コンテナの静的IP・SNIプロキシポートの衝突回避に使う。
    pub fn start(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        allow_domains: &[String],
        warm: bool,
        slot: u8,
    ) -> Result<Self, VmError> {
        let session_id = unique_session_id();
        let incus = crate::vm_host::VmHost::global().attach(config, warm)?;
        let result = Self::attach_to_guest(
            workspace_root,
            config,
            session_id,
            incus,
            allow_domains,
            slot,
        );
        if result.is_err() {
            // VM自体は他セッションが使用中の可能性があるため、ここでは「このセッションの
            // 取り分」を返上するだけでよい（refcountが0になれば`VmHost::release`が実際に
            // VMを停止する）。
            crate::vm_host::VmHost::global().release(config);
        }
        result
    }

    /// ゲストへの疎通確認済み`incus`クライアント（`Self::start`＝`VmHost::attach`が既に
    /// 用意したもの）を受け取り、コンテナ作成からワークスペース資源の確保までを行う。
    fn attach_to_guest(
        workspace_root: &Path,
        config: &VmSandboxConfig,
        session_id: String,
        incus: IncusClient,
        allow_domains: &[String],
        slot: u8,
    ) -> Result<Self, VmError> {
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
        // ACL（`create_network_acl`）でUDP/TCP 53の出口を許可しても、そもそも問い合わせ先の
        // リゾルバが設定されていなければ無意味なため、ここで明示的に設定する
        // （nginx SNIプロキシの`resolver`ディレクティブと同じ`1.1.1.1`に揃える）。
        // 最終判定は`ifup`自身の終了コードではなく`ip -4 addr show eth0`にinetが実在するかで
        // 行う（`&&`連結の最後の条件が全体のexit codeを決めるため、確実に反映される）。
        let interfaces_conf = format!(
            "auto eth0\niface eth0 inet static\n    address {}\n    gateway {CONTAINER_GATEWAY}\n",
            container_static_ip_cidr(slot)
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

        // 出口許可リスト（SNIプロキシ+nftables DNAT+コンテナACL）は`allow_domains`が
        // 非空の場合のみ構成する。既定（省略時）はPhase 1と同じ無制限出口のまま
        // （既存の`--net-allow-domain`未指定時の挙動を変えない、D-02と同じ「オプトイン」思想）。
        // **Phase B（B-1）**: IPCが同一ユーザーの任意プロセスへ開かれた以上`allow_domains`は
        // 外部入力として扱い、`validate_allow_domain`で妥当性を確認してから使う。
        let ssh_key = if allow_domains.is_empty() {
            None
        } else {
            for d in allow_domains {
                validate_allow_domain(d)?;
            }
            let key = ensure_ssh_keypair()?;
            attach_egress_acl(&incus, &container_name)?;
            crate::vm_host::VmHost::global().configure_egress(
                config,
                &key,
                slot,
                container_ip(slot),
                allow_domains.to_vec(),
            )?;
            Some(key)
        };

        let workspace_id = crate::smb_share::compute_workspace_id(workspace_root);

        // ワークスペース共有（`WorkspaceShareMode`、移行期間の切り替えフラグ）。
        // `Cifs`: Windows側でSMB共有→SSH経由でゲストへ認証情報配布→ゲスト内`mount -t cifs`
        // →Incus disk deviceでコンテナへbind-mount、のライブ共有シーケンス。**Phase B**:
        // `workspace_id`単位で参照カウント共有する（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）。
        // 既に他セッションが同じワークスペースの共有・アカウント・CIFSマウントを用意済みなら
        // 新規作成せず参照カウントだけ増やして再利用する。
        //
        // **TOCTOU**: 「台帳を見て既存資源が無ければ作成する」という判定と作成は、
        // `WORKSPACE_RESOURCE_LOCK`で直列化しないと2セッションが同時に「無い」と判定して
        // 同じ`workspace_id`の共有・アカウントを二重作成してしまう（BUG-024）。判定〜
        // 作成/修復〜台帳記録〜`add_disk_device`までを1つのクリティカルセクションにする。
        //
        // **BUG-026**: 台帳（L1、Windows側で永続）だけを根拠に「ゲスト側マウント（L2、
        // VM寿命限り）済み」とみなしてはならない。両者の整合は`decide_workspace_action`が
        // ゲストへ直接問い合わせて判定し（`guest_workspace_mount_is_healthy`）、ズレていれば
        // Repair（パスワードローテーション+再mount）で修復する。さらに`add_disk_device`が
        // 失敗した場合は、直前に増やした/作った台帳エントリを必ず巻き戻す（経路B＝
        // refcount単調増加による自己増殖の遮断）。
        let workspace_lock = WORKSPACE_RESOURCE_LOCK.lock().unwrap();
        let smb_share_name = if config.workspace_share_mode == WorkspaceShareMode::Cifs {
            let mount_point = format!("/mnt/harness-workspace-{workspace_id}");
            let host_ssh_key = ensure_ssh_keypair()?;

            let acquire_result = acquire_or_repair_workspace_share(
                workspace_root,
                &workspace_id,
                config,
                &host_ssh_key,
                &mount_point,
                &incus,
                &container_name,
            );
            let (share, user) = match acquire_result {
                Ok(pair) => pair,
                Err(e) => {
                    // [BUG-028] `add_disk_device`失敗時（下記）と対称: `acquire_or_repair_workspace_share`
                    // 内部（`create_fresh_workspace_share`/`repair_workspace_share`）の失敗が
                    // `record_workspace_resource`後（台帳に記録済み）で起きた場合、ここで
                    // 巻き戻さないと台帳エントリと実体（共有・アカウント・NTFS ACE）の両方が孤児化する。
                    // `record_workspace_resource`前（例: `create_ephemeral_share`自体の失敗）の場合は
                    // `release_workspace_resource`が`None`を返すため何もしない
                    // （そちらは`create_ephemeral_share`自身がbest-effortで後始末済み）。
                    if let Some(removed) =
                        crate::vm_ledger::release_workspace_resource(&workspace_id)
                    {
                        let _ = ssh_exec(
                            config.guest_ip,
                            &host_ssh_key,
                            &format!(
                                "umount -l {mount_point} 2>/dev/null; rm -f /etc/harness-smb-{workspace_id}.cred"
                            ),
                            Duration::from_secs(15),
                        );
                        crate::smb_share::destroy_ephemeral_share(
                            &removed.smb_share_name,
                            &removed.smb_user,
                            Some(Path::new(&removed.workspace_root)),
                        );
                    }
                    drop(workspace_lock);
                    return Err(e);
                }
            };

            if let Err(e) =
                incus.add_disk_device(&container_name, "workspace", &mount_point, WORKSPACE_MOUNT)
            {
                // F3: `add_disk_device`失敗時は、直前に増やした/作ったワークスペース資源の
                // refcountを必ず巻き戻す。ロックはこの巻き戻しの間保持したまま
                // （再取得するとデッドロックする）。
                if let Some(removed) = crate::vm_ledger::release_workspace_resource(&workspace_id) {
                    let _ = ssh_exec(
                        config.guest_ip,
                        &host_ssh_key,
                        &format!(
                            "umount -l {mount_point} 2>/dev/null; rm -f /etc/harness-smb-{workspace_id}.cred"
                        ),
                        Duration::from_secs(15),
                    );
                    crate::smb_share::destroy_ephemeral_share(
                        &removed.smb_share_name,
                        &removed.smb_user,
                        Some(Path::new(&removed.workspace_root)),
                    );
                }
                drop(workspace_lock);
                return Err(e);
            }

            let _ = user; // 台帳（`WorkspaceResourceEntry`）が正であり、ここでは使わない。
            Some(share)
        } else {
            None
        };
        drop(workspace_lock);

        let session = Self {
            session_id,
            slot,
            workspace_id,
            container_name,
            incus,
            ssh_key,
            smb_share_name,
        };
        if config.workspace_share_mode == WorkspaceShareMode::CopyInOut {
            session.copy_in_workspace(workspace_root)?;
        }
        Ok(session)
    }

    /// ワークスペース全体をコンテナの`/workspace`へpushする（Phase 1: 素朴な全ファイル
    /// 走査。大規模ワークスペースでの性能はPhase 2以降で見直す、TODOとして明記）。
    fn copy_in_workspace(&self, workspace_root: &Path) -> Result<(), VmError> {
        for entry in walk_files(workspace_root)? {
            let rel = entry
                .strip_prefix(workspace_root)
                .map_err(|e| VmError::Io(e.to_string()))?;
            let remote = format!(
                "{WORKSPACE_MOUNT}/{}",
                rel.to_string_lossy().replace('\\', "/")
            );
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
            self.incus
                .push_file(&self.container_name, &contents, &remote)?;
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
            let rel = remote
                .trim_start_matches(WORKSPACE_MOUNT)
                .trim_start_matches('/');
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
            format!(
                "{WORKSPACE_MOUNT}/{}",
                rel_cwd.to_string_lossy().replace('\\', "/")
            )
        };
        self.incus.exec(
            &self.container_name,
            &["sh", "-c", cmd],
            &remote_cwd,
            env,
            timeout,
        )
    }

    /// **Phase B**: VM自体はもう`self`が所有していない（`crate::vm_host::VmHost`が参照カウント
    /// で管理する共有resident資源）ため、`config`を受け取って最後に`VmHost::release`を呼ぶ。
    pub fn teardown(self, workspace_root: &Path, config: &VmSandboxConfig) -> Result<(), VmError> {
        // `WorkspaceShareMode::Cifs`セッションはライブ共有のためワークスペースの中身は
        // 常にホストの実ファイルシステムそのもの（bind-mountを外すだけ）で、明示的な
        // copy-outは不要（`copy_in_workspace`と同じくPhase 1の全ファイルpull往復を避ける、
        // このライブ共有方式を導入した本来の目的）。
        let copy_out_result = if self.smb_share_name.is_some() {
            Ok(())
        } else {
            self.copy_out_workspace(workspace_root)
        };
        // 出口許可リストを構成していた場合のみ、VMが消える前に監査ログを回収し、
        // このセッション分の出口設定をVM全体の集合から取り除く（A-8、`VmHost::release_出口`）。
        if let Some(ssh_key) = &self.ssh_key {
            let _ = fetch_and_persist_audit_log(
                self.incus.host_ip(),
                ssh_key,
                workspace_root,
                &self.session_id,
                self.slot,
            );
            let _ = crate::vm_host::VmHost::global().release_egress(config, ssh_key, self.slot);
        }
        let _ = self.incus.stop_container(&self.container_name);
        let _ = self.incus.delete_container(&self.container_name);

        // ワークスペース単位資源（SMB共有・ローカルアカウント・CIFSマウント・NTFS ACE）の
        // 参照カウントをデクリメントする。0になった最後の1セッションだけが実際に破棄する
        // （`DESIGN-SANDBOX-VMISOLATION.md`項目6-a、A-4の構造的解消）。
        if self.smb_share_name.is_some() {
            // `attach_to_guest`の作成判定と同じロックで直列化する（TOCTOU是正、
            // `WORKSPACE_RESOURCE_LOCK`のdoc参照）。
            let _workspace_lock = WORKSPACE_RESOURCE_LOCK.lock().unwrap();
            if let Some(removed) = crate::vm_ledger::release_workspace_resource(&self.workspace_id)
            {
                if let Ok(host_ssh_key) = ensure_ssh_keypair() {
                    let mount_point = format!("/mnt/harness-workspace-{}", self.workspace_id);
                    let cred_remote = format!("/etc/harness-smb-{}.cred", self.workspace_id);
                    // umount+cred削除はbest-effort（VM自体がこの後停止する可能性もあるため、
                    // 失敗してもteardown全体は止めない、`teardown_vm`と同じ方針）。
                    let _ = ssh_exec(
                        config.guest_ip,
                        &host_ssh_key,
                        &format!("umount {mount_point} 2>/dev/null; rm -f {cred_remote}"),
                        Duration::from_secs(15),
                    );
                }
                crate::smb_share::destroy_ephemeral_share(
                    &removed.smb_share_name,
                    &removed.smb_user,
                    Some(Path::new(&removed.workspace_root)),
                );
            }
        }

        crate::vm_host::VmHost::global().release(config);
        copy_out_result
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// D-24: 台帳+実機照会の両方を突き合わせ、前回の孤児resident VM・差分VHDX・ワークスペース
/// 単位資源を撤収する（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6・§4・項目8）。
/// **Phase B**: `crate::vm_host::VmHost::attach`のStopped→Running遷移直前、または
/// `harness tier3 gc`（別プロセス）から呼ばれる。VMが1台の共有resident資源になったため、
/// 孤児判定の単位も「複数の`session_id`エントリ」から「単一のVMホストエントリ」へ変わった——
/// 孤児と判定された場合、そのVMの生存期間中に参照カウントを管理していたdaemonプロセスの
/// `SessionRegistry`ごと消失しているとみなし、台帳上の全`workspace_resources`エントリも
/// 合わせて撤収する。
///
/// **BUG-027対策**: 台帳に記録された`daemon_pid`（このVMを起動した常駐daemon自身のPID）が
/// 生存している間は、そのVM・全`workspace_resources`をGC対象から一切除外する。これが無いと、
/// セッション実行中に別プロセスから`harness tier3 gc`を叩いただけで、稼働中のVM・コンテナ・
/// SMB共有・NTFS ACEを無条件で撤収してしまう（`docs/bugs/BUG-027.md`）。
///
/// **BUG-026対策（F4）**: `workspace_resources`は孤児VMの有無に関わらず無条件で整合させる。
/// 本関数が実際に呼ばれる時点（daemonがVMをこれから起こす瞬間、またはgc専用プロセス）では
/// アクティブセッションは存在しない前提のため、台帳上の全エントリは定義上stale。また、
/// 台帳に記録されていないWindows側実体（`New-LocalUser`名前衝突後の作り直し漏れ等、状態S2/S3）
/// も`smb_share::enumerate_windows_workspace_shares`で直接走査して回収する（旧実装は
/// `orphans.is_empty()`で早期returnし、孤児VMが無い場合`workspace_resources`を一切見ないため、
/// これらを永久に回収できなかった）。
///
/// 個々の撤収に失敗しても処理は止めない（best-effort、`plans/TIER1A-OPEN-ISSUES.md`
/// 項目9）。GC自体の失敗で`StartSession`を失敗させないよう、呼び出し側は戻り値を無視して
/// 構わない設計（stderrへログするのみ）。
pub fn gc_orphan_sessions(config: &VmSandboxConfig, current_session_id: &str) -> Vec<String> {
    let ledger = crate::vm_ledger::load();

    let resident_daemon_alive = ledger
        .vm_host
        .as_ref()
        .map(|h| crate::vm_ledger::is_pid_alive(h.daemon_pid))
        .unwrap_or(false);
    if resident_daemon_alive {
        eprintln!(
            "gc_orphan_sessions: resident daemon (pid still alive) owns the VM; skipping GC \
             this round to avoid tearing down an active session (BUG-027)"
        );
        return Vec::new();
    }

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

    let orphans = crate::vm_ledger::select_orphan_vm_names(&ledger, &existing_vm_names);

    // F4: 孤児VMの有無に関わらず、台帳上のworkspace_resourcesは無条件で整合させる
    // （resident_daemon_aliveでないと確定した以上、アクティブセッションは存在しないため
    // 台帳上の全エントリは定義上stale）。
    for resource in crate::vm_ledger::select_all_workspace_resources(&ledger) {
        crate::smb_share::destroy_ephemeral_share(
            &resource.smb_share_name,
            &resource.smb_user,
            Some(Path::new(&resource.workspace_root)),
        );
    }
    let cleared = crate::vm_ledger::update(|current| {
        current.workspace_resources.clear();
        current.clone()
    });

    // F4: 台帳に載っていないWindows側実体（状態S2/S3）も実体側から直接走査して回収する。
    // 直前のループで台帳追跡分は既に破棄済みのため、ここで見つかるのは真に台帳から
    // 不可視だった孤児のみ。
    for (share, user, path) in crate::smb_share::enumerate_windows_workspace_shares() {
        crate::smb_share::destroy_ephemeral_share(&share, &user, Some(&path));
    }

    if orphans.is_empty() {
        return orphans;
    }

    for vm_name in &orphans {
        // **実機で発見**: `vm_name`から`{vm_name}.diff.vhdx`という命名規則を推測すると、
        // 実際の常駐VMの差分VHDXファイル名（`crate::vm_host::resident_diff_vhdx_path`が
        // 決める固定名`resident.diff.vhdx`）と一致しない。台帳に記録が無い場合
        // （`vm_host`が`None`になった後の再実行等）は、常駐VM名である前提で正しいパスを導く。
        let diff_vhdx = cleared
            .vm_host
            .as_ref()
            .filter(|h| &h.vm_name == vm_name)
            .map(|h| PathBuf::from(&h.diff_vhdx))
            .unwrap_or_else(|| {
                if vm_name == crate::vm_host::RESIDENT_VM_NAME {
                    crate::vm_host::resident_diff_vhdx_path(config)
                } else {
                    config.vm_work_dir.join(format!("{vm_name}.diff.vhdx"))
                }
            });
        if let Err(e) = teardown_vm(vm_name, &diff_vhdx) {
            eprintln!("gc_orphan_sessions: failed to tear down orphan VM {vm_name}: {e}");
        }
    }
    crate::vm_ledger::remove_vm_host();

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
        if session_part == current_session_id || existing_vm_names.iter().any(|n| n == session_part)
        {
            continue;
        }
        let _ = std::fs::remove_file(&path);
    }

    orphans
}

pub(crate) fn teardown_vm(vm_name: &str, diff_vhdx: &Path) -> Result<(), VmError> {
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
        assert_eq!(
            urlencoding_path("/workspace/a b.txt"),
            "/workspace/a%20b.txt"
        );
    }

    #[test]
    fn build_sni_proxy_conf_multi_maps_allowed_domains_to_allow() {
        let sessions = vec![EgressSession {
            slot: 0,
            container_ip: "10.76.180.61".to_string(),
            allow_domains: vec!["example.com".to_string(), "api.example.org".to_string()],
        }];
        let conf = build_sni_proxy_conf_multi(&sessions);
        assert!(conf.contains("example.com     \"example.com:443\";"));
        assert!(conf.contains("api.example.org     \"api.example.org:443\";"));
        assert!(conf.contains("example.com     \"ALLOW\";"));
        assert!(conf.contains("default              \"\";"));
        assert!(conf.contains("default              \"DENY\";"));
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(0)
        )));
    }

    #[test]
    fn build_sni_proxy_conf_multi_with_no_sessions_has_no_server_blocks() {
        let conf = build_sni_proxy_conf_multi(&[]);
        assert!(!conf.contains("ALLOW"));
        assert!(!conf.contains("listen"));
    }

    #[test]
    fn build_sni_proxy_conf_multi_isolates_ports_and_domains_per_slot() {
        let sessions = vec![
            EgressSession {
                slot: 0,
                container_ip: "10.76.180.61".to_string(),
                allow_domains: vec!["a.example.com".to_string()],
            },
            EgressSession {
                slot: 1,
                container_ip: "10.76.180.62".to_string(),
                allow_domains: vec!["b.example.com".to_string()],
            },
        ];
        let conf = build_sni_proxy_conf_multi(&sessions);
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "listen {INCUS_BRIDGE_IP}:{};",
            sni_proxy_port_for_slot(1)
        )));
        // 各セッションのmapに、他セッションのドメインが混ざっていないこと（A-8是正の回帰）。
        let slot0_map_start = conf.find("$sni_upstream_0").unwrap();
        let slot0_map_end = conf.find("$sni_upstream_1").unwrap();
        assert!(conf[slot0_map_start..slot0_map_end].contains("a.example.com"));
        assert!(!conf[slot0_map_start..slot0_map_end].contains("b.example.com"));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(0)
        )));
        assert!(conf.contains(&format!(
            "access_log {} sniaudit;",
            sni_audit_log_path_for_slot(1)
        )));
    }

    #[test]
    fn validate_allow_domain_accepts_normal_domains() {
        assert!(validate_allow_domain("example.com").is_ok());
        assert!(validate_allow_domain("api.example-1.co.jp").is_ok());
    }

    #[test]
    fn validate_allow_domain_rejects_injection_characters() {
        assert!(validate_allow_domain("example.com\";}\nserver{{").is_err());
        assert!(validate_allow_domain("").is_err());
        assert!(validate_allow_domain(&"a".repeat(300)).is_err());
    }

    #[test]
    fn build_nftables_script_adds_dnat_and_s5_filter_drop_per_session() {
        let sessions = vec![EgressSession {
            slot: 2,
            container_ip: "10.76.180.63".to_string(),
            allow_domains: vec!["example.com".to_string()],
        }];
        let script = build_nftables_script(&sessions);
        let port = sni_proxy_port_for_slot(2);
        assert!(script.contains(&format!(
            "ip saddr 10.76.180.63 tcp dport 443 redirect to :{port}"
        )));
        assert!(script.contains(&format!(
            "ip daddr {INCUS_BRIDGE_IP} tcp dport {port} ip saddr != 10.76.180.63 drop"
        )));
    }

    /// BUG-026: 状態表S0〜S7（`docs/bugs/BUG-026.md`参照）の8状態すべてで
    /// `decide_workspace_action`が期待どおりのアクションを返すことを表駆動で検証する。
    /// 台帳の有無×ゲスト側マウントの健全性の2×2の組み合わせ自体は4通りしかない
    /// （S0〜S3はいずれも「台帳無し」に潰れる、S4〜S6はいずれも「台帳有り・不健全」に潰れる）
    /// ため、実際の分岐点は`(existing_present, mount_healthy)`の4通りで尽くされる。
    #[test]
    fn decide_workspace_action_covers_all_four_ledger_mount_combinations() {
        // S7: 台帳有り・マウント健全 → Reuse。
        assert_eq!(decide_workspace_action(true, true), WorkspaceAction::Reuse);
        // S4/S5/S6: 台帳有り・マウント不健全 → Repair。
        assert_eq!(
            decide_workspace_action(true, false),
            WorkspaceAction::Repair
        );
        // S0〜S3: 台帳無し（マウントの有無に関わらず）→ CreateFresh。
        assert_eq!(
            decide_workspace_action(false, true),
            WorkspaceAction::CreateFresh
        );
        assert_eq!(
            decide_workspace_action(false, false),
            WorkspaceAction::CreateFresh
        );
    }

    /// [BUG-026回帰テスト・実機E2E] `%APPDATA%`の台帳へ「workspace_id一致・ゲスト側マウント
    /// 無し」のstale `WorkspaceResourceEntry`（状態S6、`docs/bugs/BUG-026.md`の状態表参照）を
    /// 自己完結で注入し、実際にVM/コンテナを起動して`VmSession::start`の挙動を確認する。
    /// 2026-07-27の実機検証で、修正前はここが初回試行（`add_disk_device`の10回リトライを
    /// 待つまでもなく、VM冷起動・コンテナ作成を経た約44秒後）で"Missing source path"に
    /// 確実に失敗することを確定させた（根本原因: 再利用分岐が台帳の存在だけでゲスト側マウント
    /// 済みとみなし、実際のマウントを検証しない）。修正後はF2のRepair分岐が発火し、
    /// パスワードローテーション+再mountを経て`Ready`相当（`Ok`）まで到達することを確認する。
    #[test]
    #[ignore]
    fn bug026_stale_ledger_entry_without_guest_mount_is_repaired_not_missing_source_path() {
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root must resolve");
        let config = VmSandboxConfig::default();
        let workspace_id = crate::smb_share::compute_workspace_id(&workspace_root);

        // 状態S6を自己完結で構成する: 台帳にだけ（ゲスト側マウント無しで）エントリを作る。
        // `smb_share_name`/`smb_user`/`smb_user_sid`はダミー（実際のWindows資源は作らない）。
        crate::vm_ledger::record_workspace_resource(
            &workspace_id,
            &workspace_root,
            "harness-ws-bug026-repro",
            "hns3-bug026-repro",
            "S-1-5-21-0-0-0-9999",
        );

        let result = VmSession::start(&workspace_root, &config, &[], false, 0);
        match result {
            Err(e) => {
                let msg = e.to_string();
                println!("=== BUG-026 repro: VmSession::start failed: {msg} ===");
                panic!(
                    "expected the Repair branch (F2) to recover from a stale ledger entry \
                     without a guest mount, but VmSession::start still failed: {msg}"
                );
            }
            Ok(session) => {
                println!(
                    "=== BUG-026 repro: VmSession::start recovered via Repair as expected \
                     (session_id={}) ===",
                    session.session_id()
                );
                let _ = session.teardown(&workspace_root, &config);
            }
        }

        // 後始末: 万一パニックした場合も含め、注入した台帳エントリと実資源をGCへ寄せる。
        let _ = crate::vmsandbox::gc_orphan_sessions(&config, "");
    }
}
