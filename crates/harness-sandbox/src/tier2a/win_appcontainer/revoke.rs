//! AppContainer SIDのACE撤収と、撤収済みであることの検証。
//!
//! 付与側（`acl_grant`）と対になる。DACLからSIDのACEだけを取り除く操作は、継承ACEを
//! 壊さずに明示ACEのみを消す必要があるため`copy_dacl_excluding_sid`を経由する。

use super::*;

/// `ACCESS_ALLOWED_ACE_TYPE`（WinNT.h）。`windows`クレートはこの値を定数として公開して
/// いないため、既知の固定値としてここに置く。
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`（WinNT.h）。Deny ACEもこのクレートが書くので、revoke時は
/// Allow ACEと同じSID照合で取り除く。
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// [BUG-020の修正] `dacl`から`sid`宛のAllow/Deny ACEだけを取り除いた新しいDACLを、
/// 対象外のACEは`GetAce`で読んだ生バイト列のまま`AddAce`でコピーして構築する（trustee・
/// access mask・`AceFlags`——`INHERITED_ACE`を含め——を一切変更しない）。
///
/// **なぜ`SetEntriesInAclW`の`REVOKE_ACCESS`を使わないか**: `REVOKE_ACCESS`は`INHERITED_ACE`
/// フラグ付きのACEを取り除かない（Win32の仕様——継承ACEは継承元でしか正しく取り消せないという
/// 設計）。旧実装はこれを回避するため、`PROTECTED_DACL_SECURITY_INFORMATION`でノード全体を
/// 「凍結」（全ACEを明示化し継承を遮断）してから`REVOKE_ACCESS`をかけていた。しかしこの凍結は
/// 対象`sid`と無関係な他trusteeのACEも含めてノードを継承から永久に切り離す副作用があり、
/// `revoke_ace_recursive`が対象ツリー全体の継承を破壊するバグ（BUG-020、docs/bugs/BUG-020.md）
/// を引き起こした。ここではACEを1件ずつ生のまま読み対象`sid`以外はそのままコピーするため、
/// `INHERITED_ACE`フラグの有無に関わらず対象`sid`だけを正確に取り除ける。DACLの保護状態
/// （`SE_DACL_PROTECTED`）はこの関数の外で呼び出し側が読み取り・維持する（`revoke_ace`参照）。
///
/// Allow/Deny以外のACE種別（このコードベースが自ら書き込むことはない）は
/// trusteeを解釈せず常に保持する（未知の種別を誤って消さない安全側の判断）。
unsafe fn copy_dacl_excluding_sid(
    dacl: *const ACL,
    sid: PSID,
    buf: &mut Vec<u8>,
) -> windows::core::Result<*mut ACL> {
    unsafe {
        let mut size_info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            dacl,
            &mut size_info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )?;

        // 除外は縮む方向にしか働かないため、既存ACLと同じ容量を確保すれば必ず収まる。
        let buf_size = (size_info.AclBytesInUse + size_info.AclBytesFree)
            .max(std::mem::size_of::<ACL>() as u32 + 64);
        buf.resize(buf_size as usize, 0u8);
        let new_dacl = buf.as_mut_ptr() as *mut ACL;
        InitializeAcl(new_dacl, buf_size, ACL_REVISION)?;

        for i in 0..size_info.AceCount {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            GetAce(dacl, i, &mut ace_ptr)?;
            let header = &*(ace_ptr as *const ACE_HEADER);

            let is_target = if header.AceType == ACCESS_ALLOWED_ACE_TYPE
                || header.AceType == ACCESS_DENIED_ACE_TYPE
            {
                // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the Mask/SidStart layout.
                let allowed = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let entry_sid = PSID((&allowed.SidStart) as *const u32 as *mut c_void);
                EqualSid(entry_sid, sid).is_ok()
            } else {
                false
            };

            if !is_target {
                AddAce(
                    new_dacl,
                    ACL_REVISION,
                    u32::MAX, // MAXDWORD相当: 末尾へ追加し既存の並び順を保つ。
                    ace_ptr as *const c_void,
                    header.AceSize as u32,
                )?;
            }
        }

        Ok(new_dacl)
    }
}

/// `set_dacl_single_object`の亜種。DACLの内容に加え、`SE_DACL_PROTECTED`（継承を受け付ける
/// かどうか）も明示的に指定する。`grant_ace_mask`用の`set_dacl_single_object`は意図的に
/// この状態へ触れない（呼び出し元が継承の有無を問わないため）が、`revoke_ace`は「対象sidを
/// 取り除いた後、ノードの継承状態を呼び出し前と同じに保つ」ために必要とする。
unsafe fn set_dacl_single_object_with_protection(
    path: &Path,
    new_dacl: *mut ACL,
    protected: bool,
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            (WRITE_DAC | READ_CONTROL).0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;

        let mut sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
        let result = (|| -> windows::core::Result<()> {
            InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION)?;
            SetSecurityDescriptorDacl(sd_ptr, true, Some(new_dacl as *const _), false)?;
            let protection_flag = if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION | protection_flag, sd_ptr)
        })();

        let _ = CloseHandle(handle);
        result
    }
}

fn remove_sid_aces_and_protect(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(to_err)?;

        let mut new_buf: Vec<u8> = Vec::new();
        let new_dacl = match copy_dacl_excluding_sid(existing_dacl as *const _, sid, &mut new_buf) {
            Ok(dacl) => dacl,
            Err(e) => {
                let _ = LocalFree(HLOCAL(sd.0));
                return Err(to_err(e));
            }
        };
        let _ = LocalFree(HLOCAL(sd.0));
        set_dacl_single_object_with_protection(path, new_dacl, true).map_err(to_err)?;
    }
    Ok(())
}

pub(crate) fn protect_harness_control_dir_from_appcontainer(
    workspace_root: &Path,
    sid: PSID,
) -> Result<(), AppContainerError> {
    let harness_dir = workspace_root.join(".harness");
    if !harness_dir.exists() {
        return Ok(());
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(&harness_dir, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclGrant {
            path: harness_dir.clone(),
            reason: e.to_string(),
        }
    })?;

    for file in &files {
        remove_sid_aces_and_protect(file, sid)?;
    }
    for dir in dirs.iter().rev() {
        remove_sid_aces_and_protect(dir, sid)?;
    }
    Ok(())
}

/// `path`のDACLから、`sid`（trustee）に対する既存ACEを全て取り除く。元は
/// `TIER1A-OPEN-ISSUES.md`課題1のプロファイルtraverse実験（Experiment B）専用の後始末
/// ヘルパだったが、D-13のfs passthrough撤収機構（`fs revoke`）向けに本番昇格した
/// （`revoke_ace_recursive`から使う）。`grant_ace_mask`と対になる。単一ノードのみを対象とする
/// 非再帰の操作であり、`grant_traverse_drive_root`（同じく非再帰・単一ACE）の巻き戻し
/// （`harness fs revoke-traverse`）にもそのまま使う。
///
/// [BUG-020修正] `copy_dacl_excluding_sid`でACEを生のまま読み対象sidだけを除去するため、
/// 継承由来（`INHERITED_ACE`）かどうかを問わず正確に取り除ける。ノードの継承状態
/// （`SE_DACL_PROTECTED`）は呼び出し前後で変更しない（このノードが元々継承を受けていなければ
/// 書き戻し後も受けない、元々継承を受けていれば書き戻し後も受け続ける——ユーザーが独自に
/// 設定した保護状態を巻き込んで変更しない）。
/// D-37: セッションが付けたACEを1件撤収する（`session_profile`の回収経路が注入する処理）。
///
/// プロファイル名からSIDを導出して剥がし、ついでにworkspace一覧台帳からも消す。
/// `session_profile`側はACL APIを知らない（規則3の分割線）ので、その具体をここが持つ。
/// preflightの起動時GCと、CLIのセッション終了時撤収の**両方がこの1本を使う**。
pub fn revoke_session_grant(path: &Path, profile_name: &str) {
    let Ok(sid) = ensure_profile(profile_name) else {
        return;
    };
    let _ = revoke_ace_recursive(path, sid.as_psid());
    crate::tier2a::workspace_ledger::remove_workspace_entry(path);
}

/// AppContainer SIDの文字列接頭辞（`S-1-15-2-<hash…>`）。パッケージSID／capability SIDの
/// うち、`SECURITY_APP_PACKAGE_BASE_RID`(2)で始まるものがAppContainerのパッケージSIDである。
const APPCONTAINER_SID_PREFIX: &str = "S-1-15-2-";

/// `path`に載っているAppContainerパッケージSID宛の明示ACEのうち、`keep_profiles`のどの
/// プロファイルのSIDとも一致しないものを剥がし、剥がしたSID文字列を返す。
///
/// **なぜ「残す側」を名指しするのか**: プロファイルが削除済みのSIDは名前へ逆引きできない
/// （`DeriveAppContainerSidFromAppContainerName`は名前→SIDの一方向）ため、「死んだセッションの
/// SIDを列挙して剥がす」方式は既に残ってしまったACEには効かない。生存しているセッション
/// （`session_profile::live_profile_names`）のSIDだけを残し、それ以外を剥がす向きにする。
///
/// 対象は**呼び出し側が明示した既知パス**に限る（現状はredirector DLL）。マシン全体を
/// 走査する掃除機にはしない——それはこのプロセスが所有していない変更まで巻き込む。
///
/// BUG-059で実マシンに4件残留していた孤立ACEの回収経路。付与側（`preflight`）に保険を
/// 入れて新規発生は止めたが、**既に残っているものは台帳に無いので`fs revoke`では届かない**。
pub fn revoke_stale_appcontainer_aces(
    path: &Path,
    keep_profiles: &[String],
) -> Result<Vec<String>, AppContainerError> {
    let keep: Vec<String> = keep_profiles
        .iter()
        .filter_map(|name| ensure_profile(name).ok())
        .filter_map(|sid| crate::win_common::sid_to_string(sid.as_psid()).ok())
        .collect();

    let mut removed = Vec::new();
    for (sid_string, sid) in appcontainer_sid_aces(path)? {
        if keep.contains(&sid_string) {
            continue;
        }
        revoke_ace(path, sid.as_psid())?;
        removed.push(sid_string);
    }
    Ok(removed)
}

/// `path`のDACLに明示ACEを持つAppContainerパッケージSIDを列挙する（重複除去）。
///
/// `sid_ace_mask`と同じ`GetExplicitEntriesFromAclW`経由で読む（`GetAce`によるACEヘッダの
/// 直接パースより低リスク、同関数のコメント参照）。SIDはWin32が確保した配列の中を指すため、
/// 解放前に[`crate::win_common::OwnedSid`]へコピーして所有権を単純化する。
fn appcontainer_sid_aces(
    path: &Path,
) -> Result<Vec<(String, crate::win_common::OwnedSid)>, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclRevoke {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(to_err)?;

        let mut count: u32 = 0;
        let mut entries: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
        let err = GetExplicitEntriesFromAclW(dacl as *const _, &mut count, &mut entries);
        if let Err(e) = err.ok() {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(to_err(e));
        }

        let mut found: Vec<(String, crate::win_common::OwnedSid)> = Vec::new();
        if !entries.is_null() {
            for entry in std::slice::from_raw_parts(entries, count as usize) {
                if entry.Trustee.TrusteeForm != TRUSTEE_IS_SID {
                    continue;
                }
                let entry_sid = PSID(entry.Trustee.ptstrName.0 as *mut c_void);
                let Ok(sid_string) = crate::win_common::sid_to_string(entry_sid) else {
                    continue;
                };
                if !sid_string.starts_with(APPCONTAINER_SID_PREFIX)
                    || found.iter().any(|(s, _)| s == &sid_string)
                {
                    continue;
                }
                if let Ok(owned) = crate::win_common::OwnedSid::copy_from(entry_sid) {
                    found.push((sid_string, owned));
                }
            }
            let _ = LocalFree(HLOCAL(entries as *mut _));
        }
        let _ = LocalFree(HLOCAL(sd.0));
        Ok(found)
    }
}

/// 祖先traverseの主体（`traverse_capability_sid`）のバイト列を1回だけ導出してキャッシュする。
///
/// `revoke_ace`はツリー全ノードで通る経路なので、ここで`DeriveCapabilitySidsFromName`を
/// 毎回叩くわけにはいかない。導出に失敗した場合（あり得ないが）は`None`を持ち、ガードを
/// 素通りさせる——**判定材料が無いときに撤収を止めると、正当な`fs revoke`まで巻き添えで
/// 失敗する**ので、ここは開ける側へ倒す（境界そのものではなく事故防止のガードであるため）。
fn cached_traverse_capability_sid() -> Option<&'static crate::win_common::OwnedSid> {
    static SID: std::sync::OnceLock<Option<crate::win_common::OwnedSid>> =
        std::sync::OnceLock::new();
    SID.get_or_init(|| traverse_capability_sid().ok()).as_ref()
}

fn is_traverse_capability_sid(sid: PSID) -> bool {
    match cached_traverse_capability_sid() {
        Some(cap) => unsafe { EqualSid(cap.as_psid(), sid).is_ok() },
        None => false,
    }
}

/// [D-48] `path`のtraverse ACEが「traverse台帳に載った永続的な修復」かどうか。
///
/// [BUG-046](../../../../docs/bugs/BUG-046.md): 付与側`grant_ace_mask`には冪等スキップが
/// あり、要求マスクが既存ACEの部分集合なら**何も書かない**。一方この撤収側は所有権の概念を
/// 持たず、誰が付けたACEでも同じように消せる。この非対称のせいで「grantがno-op・revokeだけ
/// 有効」となり、テストが`C:\`の永続ACEを純減させてマシン全体のTier2a FS I/Oを壊した。
fn is_protected_traverse_grant(path: &Path, sid: PSID) -> bool {
    is_traverse_capability_sid(sid) && crate::tier2a::traverse_ledger::is_recorded_traverse_node(path)
}

/// `path`のDACLから`sid`宛の明示ACEを取り除く（D-48のガード付き、通常はこちらを使う）。
///
/// traverse台帳に載ったノードの**capability SID宛ACE**だけは剥がさず`Err`を返す。巻き戻したい
/// ときは名前の付いた扉[`revoke_traverse_grant`]（＝`harness fs revoke-traverse <path>`）を通ること。
/// 「汎用APIでは触れない／名指しの関数でだけ触れる」という非対称が目的で、悪意ある呼び出しを
/// 止めるためのものではない——**更新漏れの巻き添えを止める**ためのものである。
pub fn revoke_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    if is_protected_traverse_grant(path, sid) {
        return Err(AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: format!(
                "refusing to strip the persistent traverse ACE on {} (D-48): this node is \
                 recorded in the traverse ledger, so its capability-SID ACE is a permanent \
                 repair that Tier2a FS I/O depends on machine-wide. Use `harness fs \
                 revoke-traverse <path>` (win_appcontainer::revoke_traverse_grant) if you really \
                 mean to roll it back. See docs/bugs/BUG-046.md",
                path.display()
            ),
        });
    }
    revoke_ace_unguarded(path, sid)
}

/// [`revoke_ace`]の実体（D-48のガードを通らない）。**このモジュールと
/// [`revoke_traverse_grant`]以外から呼ばないこと。**
pub(crate) fn revoke_ace_unguarded(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclRevoke {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(to_err)?;

        let mut new_buf: Vec<u8> = Vec::new();
        let new_dacl = match copy_dacl_excluding_sid(existing_dacl as *const _, sid, &mut new_buf) {
            Ok(dacl) => dacl,
            Err(e) => {
                let _ = LocalFree(HLOCAL(sd.0));
                return Err(to_err(e));
            }
        };

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let control_result = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let _ = LocalFree(HLOCAL(sd.0));
        control_result.map_err(to_err)?;
        let was_protected = control & SE_DACL_PROTECTED.0 != 0;

        set_dacl_single_object_with_protection(path, new_dacl, was_protected).map_err(to_err)?;
    }
    Ok(())
}

/// `root`配下（`root`自身含む）から`sid`のACEを再帰的に取り除く（`grant_ace_recursive`の逆）。
/// D-13のfs passthrough撤収（`harness fs revoke`）本体。`grant_ace_recursive`と同じ
/// `collect_dirs_and_files`（symlinkスキップ済み）を使い再walkするため、付与後に増えた
/// ファイルも含めて現在のツリー全体から取り除く（決定D3: 台帳はルートのみ記録、撤収は再walk）。
///
/// **`root`がファイルのときは単一オブジェクトの撤収1件で終える**（BUG-059の撤収側）。
/// この分岐が無かった頃、`collect_dirs_and_files`の`read_dir`が`ERROR_DIRECTORY`(267)で落ちて
/// **1件も剥がさずに`Err`を返していた**。`end_session`はこの関数を通して撤収するので、
/// ファイルへ付けたACE（`--cow`のredirector DLL・ファイル1件を指す`--fs-allow`）は
/// **台帳に正しく載っていても剥がれない**。付与側だけを直しても孤立ACEは止まらなかった、
/// というのが実機E2Eで判明した順序である（付与側=`grant_ace_inheritable_access`、
/// 記録側=`preflight`、撤収側=ここ、の3つが揃って初めて閉じる）。
pub fn revoke_ace_recursive(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    if root.is_file() {
        return revoke_ace(root, sid);
    }
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclRevoke {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    for file in &files {
        revoke_ace(file, sid)?;
    }
    for dir in &dirs {
        revoke_ace(dir, sid)?;
    }
    Ok(())
}

/// `path`のDACLに`sid`（trustee）への明示ACEが残っていれば、その許可アクセスマスクの
/// 論理和を返す（複数エントリがあり得るため合算）。無ければ`None`。
/// `GetExplicitEntriesFromAclW`は`BuildTrusteeWithSidW`で組み立てるのと同じ`TRUSTEE_W`を
/// 返すため、`grant_ace_mask`/`revoke_ace`が使うAPIと対称な形で読み取れる
/// （`GetAce`によるACEヘッダ直接パースより低リスク）。
pub(crate) fn sid_ace_mask(path: &Path, sid: PSID) -> Result<Option<u32>, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(to_err)?;

        let mut count: u32 = 0;
        let mut entries: *mut EXPLICIT_ACCESS_W = std::ptr::null_mut();
        let err = GetExplicitEntriesFromAclW(dacl as *const _, &mut count, &mut entries);
        if let Err(e) = err.ok() {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(to_err(e));
        }

        let mut mask: Option<u32> = None;
        if !entries.is_null() {
            let slice = std::slice::from_raw_parts(entries, count as usize);
            for entry in slice {
                if entry.Trustee.TrusteeForm == TRUSTEE_IS_SID {
                    let entry_sid = PSID(entry.Trustee.ptstrName.0 as *mut c_void);
                    if EqualSid(entry_sid, sid).is_ok() {
                        mask = Some(mask.unwrap_or(0) | entry.grfAccessPermissions);
                    }
                }
            }
            let _ = LocalFree(HLOCAL(entries as *mut _));
        }
        let _ = LocalFree(HLOCAL(sd.0));
        Ok(mask)
    }
}

/// D4（revoke完全性の検証パス）: `root`配下を再walkし、`sid`のACEがまだ残っている全ノードを
/// 列挙する。空なら完全に撤収できたことの機械的な証拠になる（`fs revoke`が呼ぶ）。
/// ツリー外へ移動されたオブジェクトは検出できない（T-16残余、`TIER1A-OPEN-ISSUES.md`参照）。
pub fn assert_no_sid_ace_recursive(root: &Path, sid: PSID) -> Result<(), Vec<std::path::PathBuf>> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    if collect_dirs_and_files(root, &mut dirs, &mut files).is_err() {
        // rootが既に存在しない（revoke後にユーザが削除した等）場合は「残存無し」として扱う。
        return Ok(());
    }
    let mut remaining = Vec::new();
    for node in dirs.iter().chain(files.iter()) {
        match sid_ace_mask(node, sid) {
            Ok(Some(_)) => remaining.push(node.clone()),
            Ok(None) => {}
            Err(_) => remaining.push(node.clone()),
        }
    }
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(remaining)
    }
}

/// `revoke_passthrough`の3値結果（BUG-016で記録した「revoke側の台帳残留」非対称の解消、
/// BUG-017のroot再プローブの鏡像）。台帳除去の判定を「ツリー全体成功」ではなく「rootのACEが
/// 消えたか」基準にするために導入する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// `root`配下から完全に`sid`のACEを撤収できた。
    FullyRevoked,
    /// `root`自身のACEは撤収できたが、一部の子孫（`NT SERVICE\TrustedInstaller`所有等で
    /// `WRITE_DAC`不可）にACEが残る。**孤立ACEではない**——grantとrevokeは同じ`WRITE_DAC`を
    /// 要するため、rootが消えたのにACEが残る子孫は「こちらが書けない＝元々付与もできていない
    /// ノード」であり、除去残しにはならない。台帳からは除去してよい。
    RootClearedDescendantsBlocked,
    /// `root`自身のACEがまだ残っている（真の失敗、または一過性で再試行の余地あり）。
    /// 台帳には残す。
    Failed,
}

/// `root`配下から`sid`のfs passthrough ACEを撤収し、**rootのACEが消えたか**を権威的に
/// 再プローブして3値で返す（BUG-016で記録した「部分適用エントリのrevoke時、rootのACEは
/// 実際に消えるのに子孫の`Err`で台帳エントリが残る」非対称の解消）。`revoke_ace_recursive`が
/// 途中の子孫で`Err`を返しても、それを最終判定に使わず`sid_ace_mask(root)`で判定する点が要。
/// forced撤収（`SeRestorePrivilege`下）で呼ぶ場合は呼び出し側が`with_restore_privilege`で囲う。
pub fn revoke_passthrough(root: &Path, sid: PSID) -> RevokeOutcome {
    // rootが既に存在しない（revoke後にユーザが削除した等）場合は、実FS上にACEを載せる
    // オブジェクトが無いので完全撤収扱いとし、台帳エントリを掃除できるようにする。
    if !root.exists() {
        return RevokeOutcome::FullyRevoked;
    }
    // 途中の子孫（TrustedInstaller所有等）で失敗しても、後段のroot再プローブで最終判定する。
    let _ = revoke_ace_recursive(root, sid);
    match sid_ace_mask(root, sid) {
        Ok(None) => match assert_no_sid_ace_recursive(root, sid) {
            Ok(()) => RevokeOutcome::FullyRevoked,
            Err(_) => RevokeOutcome::RootClearedDescendantsBlocked,
        },
        // ACEが残っている、またはrootをプローブできない（存在しない等）→台帳に残す。
        _ => RevokeOutcome::Failed,
    }
}

/// `assert_no_sid_ace_recursive`の非再帰版。単一ノード（`path`自身）のみを検証する。
/// `grant_traverse_drive_root`のような非再帰・単一ACEの付与（`revoke_ace`で撤収する対象）は
/// ツリー全体を再walkする必要が無く、むしろ`path`がドライブルートの場合に不要な全走査を
/// 招くため、`assert_no_sid_ace_recursive`を流用せずこちらを使う（`harness fs revoke-traverse`）。
pub fn assert_no_sid_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    match sid_ace_mask(path, sid)? {
        None => Ok(()),
        Some(_) => Err(AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: "sandbox SID ACE still present after revoke".to_string(),
        }),
    }
}
