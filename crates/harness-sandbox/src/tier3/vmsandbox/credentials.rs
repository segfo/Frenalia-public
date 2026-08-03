//! ホスト側に置く資格情報の生成と保護。話す相手はファイルシステムとNTFS ACL。
//!
//! Incus mTLSのクライアント証明書（`%APPDATA%\harness\config\tier3-incus-client\`）と、
//! 外層VMへのSSH鍵（同`tier3-ssh\`）。秘密鍵は`harden_private_key_acl`で所有者のみへ
//! アクセスを絞る（`ssh.exe`が緩いパーミッションの鍵を拒否するため実用上も必須）。

use super::*;

/// クライアント証明書のホスト側保存先（`%APPDATA%\harness\config\tier3-incus-client\`）。
pub(crate) fn client_cert_dir() -> Result<PathBuf, VmError> {
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
pub(crate) fn ssh_keypair_dir() -> Result<PathBuf, VmError> {
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
pub(crate) fn harden_private_key_acl(path: &Path) -> Result<(), VmError> {
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
pub(crate) fn known_hosts_file() -> Result<PathBuf, VmError> {
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

