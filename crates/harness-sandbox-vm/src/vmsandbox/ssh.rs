//! 外層VM（AlmaLinux）への`ssh.exe`によるコマンド実行。話す相手はWindows同梱のOpenSSH
//! クライアント。
//!
//! `russh`等の重量依存を足さずshell-outで済ませる（`run_powershell`と同じ方針）。ホスト鍵は
//! セッションごとに再生成される（firstboot）ため`StrictHostKeyChecking=no`で検証をスキップする
//! ——このVMはharnessが固定管理下ロケーションに用意し毎セッション使い捨てる前提（D-20/D-21）。

use super::*;

/// AlmaLinux VM自体（`root`）へSSH鍵認証でコマンドを実行する（`ssh.exe`、Windows 10 1809+
/// 標準搭載のOpenSSHクライアントをshell-out。`run_powershell`と同じ既存パターン、`russh`等の
/// 新規重量依存は追加しない）。ホスト鍵はセッションごとに再生成される（firstboot）ため
/// `StrictHostKeyChecking=no`で検証をスキップする（このVMはharnessが固定管理下ロケーションに
/// 用意し毎セッション使い捨てる前提、D-20/D-21）。
pub(crate) fn ssh_exec(
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
        harness_sandbox::decode_console_bytes(&output.stdout),
        harness_sandbox::decode_console_bytes(&output.stderr),
        output.status.code().unwrap_or(-1),
    ))
}

/// `ssh_exec`の非ゼロ終了を`VmError`へ畳み込む版（設定投入等、成功必須の呼び出し向け）。
pub(crate) fn ssh_exec_checked(
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
pub(crate) fn guest_workspace_mount_is_healthy(host: IpAddr, key: &Path, mount_point: &str) -> bool {
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
pub(crate) fn ssh_push_file(
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
            harness_sandbox::decode_console_bytes(&output.stderr)
        )));
    }
    Ok(())
}

