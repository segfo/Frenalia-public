//! ワークスペース単位資源（SMB共有・使い捨てアカウント・NTFS ACE・ゲスト側CIFSマウント）の
//! 確保と修復。
//!
//! 台帳エントリの有無とゲスト側マウントの健全性の組み合わせ8状態（BUG-026の状態表S0〜S7、
//! `docs/bugs/BUG-026.md`）を Reuse / Repair / CreateFresh の3アクションへ振り分ける。
//! 振り分けそのものは実SSH/PowerShellに依存しない純関数（`decide_workspace_action`）で、
//! 8状態を表駆動で単体テストできる。

use super::*;

/// BUG-026の状態表（`docs/bugs/BUG-026.md`参照）に沿って、ワークスペース単位資源
/// （SMB共有・使い捨てアカウント・NTFS ACE・ゲスト側CIFSマウント）を確保する。
/// 台帳エントリの有無とゲスト側マウントの健全性の組み合わせ（8状態）を
/// Reuse/Repair/CreateFreshの3アクションへ振り分ける。呼び出し側（`attach_to_guest`）が
/// `WORKSPACE_RESOURCE_LOCK`を保持した状態で呼ぶこと。
/// 台帳エントリの有無とゲスト側マウントの健全性の組み合わせ（BUG-026の状態表S0〜S7、
/// `docs/bugs/BUG-026.md`参照）が導くアクション。実SSH/PowerShellに依存しない純関数
/// （[`decide_workspace_action`]）へ切り出し、8状態を表駆動で単体テストできるようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceAction {
    /// S7: 台帳にあり、ゲスト側マウントも健全。そのまま再利用する。
    Reuse,
    /// S4/S5/S6: 台帳にはあるがゲスト側マウントが不健全。修復（パスワードローテーション、
    /// 失敗すれば作り直し）を試みる。
    Repair,
    /// S0〜S3: 台帳に無い。新規作成する（S1/S3で残存マウントがあれば先に外す）。
    CreateFresh,
}

pub(crate) fn decide_workspace_action(
    existing_present: bool,
    mount_healthy: bool,
) -> WorkspaceAction {
    match (existing_present, mount_healthy) {
        (true, true) => WorkspaceAction::Reuse,
        (true, false) => WorkspaceAction::Repair,
        (false, _) => WorkspaceAction::CreateFresh,
    }
}

pub(crate) fn acquire_or_repair_workspace_share(
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
pub(crate) fn repair_workspace_share(
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
pub(crate) fn create_fresh_workspace_share(
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
pub(crate) fn remount_workspace_share(
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
