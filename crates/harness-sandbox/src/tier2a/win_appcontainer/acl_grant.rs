//! AppContainer SIDへのACE付与と、その土台になるDACL低レベル操作。
//!
//! 「境界はACL」（D-01）の実装本体のうち**許可を付ける側**。撤収側は`revoke`、
//! 祖先チェーンへのtraverse付与は`traverse`が持つ。

use super::*;

/// `path`が指すディレクトリ配下を、シンボリックリンク/リパースポイントを辿らずに再帰列挙する。
/// 悪意あるsymlinkを辿ってworkspace外へpackage SIDの書込許可を誤って付与するスコープ逸脱を
/// 防ぐため、`WorkspaceJail::walk_dir`の`is_symlink()`スキップと同じガードを独立に実装する
/// （cap-stdの型保証が及ばない素の`std::fs`再帰のため、明示チェックが必須）。
///
/// **既知の診断精度の限界（安全性には影響しない）**: この関数が返す`io::Result`はどのノードで
/// 失敗したかを含まない（`?`で素通しするだけ）。呼び出し側（`grant_ace_recursive`・
/// `grant_ace_recursive_ro`・`grant_ace_inheritable_ro`）はこのエラーを`root`のパスに紐付けて
/// `AppContainerError::AclGrant`へ包むため、`preflight`の`.exists()`チェック後から実際の
/// walk開始までの間に対象配下のサブディレクトリが削除される（TOCTOU、Time-Of-Check to
/// Time-Of-Use、確認と使用の間に対象が変化する競合）ようなごく稀なケースでは、ユーザーに
/// 表示されるエラーメッセージが「どのノードで`read_dir`が失敗したか」ではなく`root`止まりに
/// なる。スコープが意図せず広がる・誤ったパスへ書き込む等の安全性の問題は無く、純粋に
/// エラーメッセージの特定精度の話に留まる。直す場合は本関数の戻り値を
/// `Result<(), (std::path::PathBuf, std::io::Error)>`のように失敗ノードを含む形へ変更する。
pub(crate) fn collect_dirs_and_files(
    root: &Path,
    dirs: &mut Vec<std::path::PathBuf>,
    files: &mut Vec<std::path::PathBuf>,
) -> std::io::Result<()> {
    dirs.push(root.to_path_buf());
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_dirs_and_files(&path, dirs, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// `path`のDACLへ、既存ACEを保持したまま`sid`へ`access`の許可ACEを`inheritance`付きで
/// マージする。`SetEntriesInAclW`は同一trusteeの既存ACEを置換する仕様のため冪等
/// （再実行しても重複ACEが増えない、`win_restricted::set_low_integrity_label`の冪等性と
/// 同じ性質をDACL版でも担保する）。
/// `new_dacl`を`path`（ファイル/ディレクトリいずれも可）へ、**そのオブジェクト単体にのみ**設定する。
/// `SetNamedSecurityInfoW`（aclapi）は、コンテナのDACLを設定すると子孫全体へauto-inherit再伝播を
/// 走らせる（procmon実測で`SetSecurityFile`が子孫の数だけ発生、実行中プロファイルルート近傍では
/// 365,903件・93秒経っても未完 = 事実上ハング。`plans/TIER1A-PRIVHELPER-HANG.md`参照）。
/// `CreateFileW`でハンドルを取り`SetKernelObjectSecurity`（`NtSetSecurityObject`の薄いラッパ）を
/// 使うと、aclapiのツリー走査・パッケージSID解決RPCを一切経由せず、このオブジェクトのDACLだけを
/// 直接差し替えられる。`grant_ace_recursive_ro`等の**意図的にツリー全体へ伝播/全走査したい既存
/// 経路はこの関数を使わない**（そちらは`SetNamedSecurityInfoW`のままでよい、伝播が目的のため）。
unsafe fn set_dacl_single_object(path: &Path, new_dacl: *mut ACL) -> windows::core::Result<()> {
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
        SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr)
    })();

    let _ = CloseHandle(handle);
    result
}

/// 指定トークンの1特権を有効/無効化する（`AdjustTokenPrivileges`）。`AdjustTokenPrivileges`は
/// 特権がトークンに割り当てられていなくても関数自体は成功（`S_OK`）を返し、
/// `GetLastError`で`ERROR_NOT_ALL_ASSIGNED`を返す仕様のため、有効化時はそれを失敗として扱う。
unsafe fn set_privilege(token: HANDLE, name: PCWSTR, enable: bool) -> windows::core::Result<()> {
    let mut luid = LUID::default();
    LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid)?;
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: if enable {
                SE_PRIVILEGE_ENABLED
            } else {
                TOKEN_PRIVILEGES_ATTRIBUTES(0)
            },
        }],
    };
    AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
    if enable && GetLastError() == ERROR_NOT_ALL_ASSIGNED {
        // トークンが`SeRestorePrivilege`を保持していない（非管理者等）。
        return Err(windows::core::Error::from_win32());
    }
    Ok(())
}

/// `SeRestorePrivilege`を有効化した状態で`f`を実行し、終了後に必ず元へ戻すRAIIガード
/// （D-19、`--force-system-acl`のオプトイン強制付与）。`SeRestorePrivilege`はバックアップ/リストア
/// 用特権で、DACLに関係なく`WRITE_DAC`/`WRITE_OWNER`でオブジェクトを開けるため、
/// `NT SERVICE\TrustedInstaller`所有ノード（Administratorでも`WRITE_DAC`不可）へも
/// **所有権を変えずに**（非破壊で）ACEを書ける。
///
/// **セキュリティ注意（D-19）**: 有効化中はこのプロセスがシステム上の任意オブジェクトの
/// セキュリティ記述子を書き換えられる。呼び出しは特権分離ヘルパー（昇格済み）内の、かつ
/// `--force-system-acl`が明示され`is_force_grant_forbidden`ゲートを通過したforced操作に限る。
/// 特権が有効化できない場合（非管理者等）は`f`をそのまま特権無しで実行する（呼び出し側の
/// grant/revokeが通常どおり`ACCESS_DENIED`で失敗するだけ。ここではpanicも早期returnもしない）。
pub fn with_restore_privilege<T>(f: impl FnOnce() -> T) -> T {
    struct PrivGuard {
        token: HANDLE,
        enabled: bool,
    }
    impl Drop for PrivGuard {
        fn drop(&mut self) {
            unsafe {
                if self.enabled {
                    let _ = set_privilege(self.token, SE_RESTORE_NAME, false);
                }
                if !self.token.is_invalid() {
                    let _ = CloseHandle(self.token);
                }
            }
        }
    }

    let _guard = unsafe {
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(TOKEN_ADJUST_PRIVILEGES.0 | TOKEN_QUERY.0),
            &mut token,
        )
        .is_ok();
        if !opened {
            PrivGuard {
                token: HANDLE::default(),
                enabled: false,
            }
        } else {
            let enabled = set_privilege(token, SE_RESTORE_NAME, true).is_ok();
            PrivGuard { token, enabled }
        }
    };
    f()
    // `_guard`のDropでSeRestorePrivilegeを無効化しトークンを閉じる（fがpanicしても戻る）。
}

/// `a`（対象パス）が`base`配下（`base`自身を含む）かを大文字小文字無視で判定する。
/// 双方canonicalize済みを前提とし、パス成分単位で比較する（文字列の`starts_with`だと
/// `C:\Windows`が`C:\WindowsApps`に誤マッチするため成分比較にする）。
fn path_is_within(a: &Path, base: &Path) -> bool {
    let comps = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let a = comps(a);
    let b = comps(base);
    b.len() <= a.len() && b.iter().zip(a.iter()).all(|(x, y)| x == y)
}

/// `--force-system-acl`（D-19、`SeRestorePrivilege`による強制付与）で触れてはいけない
/// host パスを保守的に拒否する。`SeRestorePrivilege`は全DACLをバイパスするため、既存の
/// jail相対 hard-deny（`overlay`/`permission`/`git`）ではカバーできない host パスに対する
/// **書込前の唯一の防壁**になる（`Some(reason)`なら禁止、`None`なら許可）。
///
/// 保守的な拒否対象:
/// - ドライブルート自体（例 `C:\`）——継承ACEを撒くと影響範囲が全ドライブに及ぶ。
/// - `%SystemRoot%`（通常`C:\Windows`）配下全体——`System32\config`のレジストリハイブ
///   （SAM/SYSTEM/SECURITY/SOFTWARE）等、OSの中核が含まれる。
///
/// 動機となった`...\Start Menu`（`%ProgramData%`配下）や`Program Files`配下の
/// TrustedInstaller所有フォルダはいずれも上記の外なので許可される。
/// canonicalizeに失敗するパスは安全側に倒して拒否する。
pub fn is_force_grant_forbidden(path: &Path) -> Option<String> {
    let canon = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            return Some(format!(
                "cannot canonicalize {} ({e}); refusing forced system-ACL grant",
                path.display()
            ));
        }
    };

    // ドライブルート（Prefix + RootDirのみで、通常成分が無い）を拒否する。
    let has_normal = canon
        .components()
        .any(|c| matches!(c, std::path::Component::Normal(_)));
    if !has_normal {
        return Some(format!(
            "{} is a drive root; refusing forced system-ACL grant (blast radius too large)",
            canon.display()
        ));
    }

    // `%SystemRoot%`（Windowsディレクトリ）配下全体を拒否する。
    if let Some(windir) = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(std::path::PathBuf::from)
    {
        // windir自体をcanonicalizeして比較する（8.3名やcase差を吸収）。
        let windir_canon = std::fs::canonicalize(&windir).unwrap_or(windir);
        if path_is_within(&canon, &windir_canon) {
            return Some(format!(
                "{} is inside the Windows system directory ({}); refusing forced system-ACL grant \
                 (contains registry hives and OS-critical objects)",
                canon.display(),
                windir_canon.display()
            ));
        }
    }

    None
}

pub(crate) fn grant_ace_mask(
    path: &Path,
    sid: PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
) -> Result<(), AppContainerError> {
    // 冪等スキップ: 既にsid宛の明示ACEが要求マスクの上位集合を持っていれば
    // `SetNamedSecurityInfoW`（プロファイルルート近傍で病的に遅くなりうる、BUG-011）を
    // 呼ばずに済ませる。継承フラグの相違までは見ない（`inheritance`は`grant_ace_mask`の
    // 呼び出しパターン上、同一pathへ複数の異なる継承指定で呼ばれることが無いため）。
    if let Ok(Some(existing)) = sid_ace_mask(path, sid) {
        if existing & access == access {
            return Ok(());
        }
    }
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

        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let entries_result =
            SetEntriesInAclW(Some(&[ea]), Some(existing_dacl as *const _), &mut new_dacl).ok();
        if let Err(e) = entries_result {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(to_err(e));
        }

        let set_result = set_dacl_single_object(path, new_dacl);

        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
        set_result.map_err(to_err)?;
    }
    Ok(())
}

/// workspace配下のノードへ read/write/execute/delete を付与する（ディレクトリは継承付き、
/// ファイルは非継承）。`WRITE_DAC`/`WRITE_OWNER`は含めない（sandboxed子が自分でACLを緩める
/// ことを防ぐ多層防御）。
fn grant_ace(path: &Path, sid: PSID, is_dir: bool) -> Result<(), AppContainerError> {
    let access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0;
    let inheritance = if is_dir {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };
    grant_ace_mask(path, sid, access, inheritance)
}

/// `root`配下（`root`自身含む）へ再帰的にpackage SIDの許可ACEを付与する。継承フラグ
/// （`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`）を使うため、`root`自身へのACE付与だけで
/// 新規作成される子孫にも自動継承されるが、**既存の子孫ファイル/ディレクトリ**には遡って
/// 効かないため、`root`付与時点で存在する全ノードへも明示的に付与する（`.git`を除外しない、
/// Tier1の`cwd`全体ラベル付与と整合させる設計判断。理由は`docs/phases/foundation/`参照）。
pub fn grant_ace_recursive(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    for dir in &dirs {
        grant_ace(dir, sid, true)?;
    }
    for file in &files {
        grant_ace(file, sid, false)?;
    }
    Ok(())
}

pub(crate) fn fs_access_mask(access: FsAccess) -> u32 {
    match access {
        FsAccess::Read => FILE_GENERIC_READ.0,
        FsAccess::ReadWrite => FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0,
        FsAccess::ReadExec => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
    }
}

fn grant_ace_access(
    path: &Path,
    sid: PSID,
    is_dir: bool,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    let inheritance = if is_dir {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };
    grant_ace_mask(path, sid, fs_access_mask(access), inheritance)
}

/// workspace配下のノードへ read/execute のみを付与する（`grant_ace`のread-only版、D-13）。
/// `FILE_GENERIC_WRITE`・`DELETE`を含めないため、package SIDはこのルート配下を読取・実行
/// できるが書込・削除はできない（D-13「read-onlyを既定とする」）。
fn grant_ace_ro(path: &Path, sid: PSID, is_dir: bool) -> Result<(), AppContainerError> {
    grant_ace_access(path, sid, is_dir, FsAccess::ReadExec)
}

/// `grant_ace_recursive`のread-only版（D-13、fs passthroughの既定）。
pub fn grant_ace_recursive_ro(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    for dir in &dirs {
        grant_ace_ro(dir, sid, true)?;
    }
    for file in &files {
        grant_ace_ro(file, sid, false)?;
    }
    Ok(())
}

/// `grant_ace_recursive_ro`の高速化版（Phase B-2、`TIER1A-OPEN-ISSUES.md`項目6・制約2）。
/// Experiment L（`docs/phases/foundation/M12-shell-isolation-tiers.md`）の実機検証で、`root`へ継承あり
/// read-only ACEを1件付与するだけで、**付与時点で既に存在する**子孫にもOS側（NTFS）が
/// DACL変更時に伝播させることを確認した（`grant_ace_recursive_ro`直前の旧コメント「既存子孫
/// には遡及しない」という主張は誤りだった）。
///
/// ただし継承をブロックする保護DACL（`PROTECTED_DACL_SECURITY_INFORMATION`が立った子。
/// エクスプローラの「継承を無効にする」操作等で作られうる）が混在するツリーでは、その配下に
/// 伝播が届かない。そのため付与後に全ノードを再walkし、`sid`のACEが実際に届いているか
/// （`sid_ace_mask`で検出、継承経由・明示ACE経由を問わない）を確認し、**届いていないノードだけ**
/// `grant_ace_ro`で個別に明示付与するフォールバックを行う（届いたノードはSetNamedSecurityInfoW
/// を呼ばずに済むため、数GB規模のツリーで大半が継承境界に阻まれず伝播する場合ほど
/// `grant_ace_recursive_ro`の全ノード明示付与より高速になる）。
pub fn grant_ace_inheritable_ro(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace_inheritable_access(root, sid, FsAccess::ReadExec)
}

pub fn grant_ace_inheritable_access(
    root: &Path,
    sid: PSID,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    grant_ace_access(root, sid, true, access)?;

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;

    for dir in &dirs {
        if !matches!(sid_ace_mask(dir, sid), Ok(Some(_))) {
            grant_ace_access(dir, sid, true, access)?;
        }
    }
    for file in &files {
        if !matches!(sid_ace_mask(file, sid), Ok(Some(_))) {
            grant_ace_access(file, sid, false, access)?;
        }
    }
    Ok(())
}

/// `grant_ace_inheritable_ro`のRW版（Tier2aが既定でプローブされるようになったことに伴う
/// `preflight`の高速化）。`grant_ace_recursive`は
/// workspace_root配下の全ノードへ毎回個別に`SetNamedSecurityInfoW`書込を試みる（`grant_ace_mask`
/// 内部の冪等スキップにより実際のWin32書込呼び出し自体は2回目以降省略されるが、読取確認は
/// 変わらず全ノード分発生する）。root へ継承ACEを1件付与するだけで、付与時点で既に存在する
/// 子孫にもNTFSがDACL変更時に伝播させることを`grant_ace_inheritable_ro`側で実機確認済み
/// （このコメント参照）であるため、RW版でも同じ「root 1件書込 + 全ノード読取確認（大半は
/// 継承経由で既に充足）」パターンが使える。書込系Win32呼び出しの回数を大幅に削減できる
/// （BUG-011「プロファイルルート近傍の書込みは病的に遅くなりうる」を踏まえると効果が大きい）。
///
/// **明記するスコープ外**: 大規模ツリーでの全体walk自体のコスト（`collect_dirs_and_files`の
/// readdir + 各ノードの`sid_ace_mask`読取確認）は依然としてO(n)で残る。恒久的な解決
/// （付与済みキャッシュの永続化等）は本ラウンドのスコープ外とし、既知の制約として記録する。
pub fn grant_ace_inheritable_rw(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace(root, sid, true)?;

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;

    for dir in &dirs {
        if !matches!(sid_ace_mask(dir, sid), Ok(Some(_))) {
            grant_ace(dir, sid, true)?;
        }
    }
    for file in &files {
        if !matches!(sid_ace_mask(file, sid), Ok(Some(_))) {
            grant_ace(file, sid, false)?;
        }
    }
    Ok(())
}
