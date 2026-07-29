//! Windows Tier2a: AppContainer（package SID + capability SID）。
//! `plans/DESIGN-SANDBOX.md` §6.3/§7 D-02参照。Windows既定Tier候補。
//!
//! Tier1（`win_restricted`、制限トークン + 低IL）と異なり、Tier2aは**トークンを差し替えず**
//! `CreateProcessW`の拡張属性リストに`SECURITY_CAPABILITIES`を積むことで、呼び出しスレッド
//! 自身のトークンのまま子をAppContainerへ閉じ込める（別メカニズム）。
//!
//! capability配列は既定で空にする（`CreateAppContainerProfile`のcapabilities引数無し・
//! 起動時の`SECURITY_CAPABILITIES.CapabilityCount=0`）。これによりnetworkを含む全
//! capability-gatedリソースがdefault-denyになり、T-10（子の直接ソケット送出）対策の核が成立する。
//! 範囲外書込・範囲外読取もpackage SIDへの明示ACE無しには許可されないため、T-04（`~/.ssh`等の
//! read→exfil）も併せて防ぐ（Tier1が守れない2つの脅威、`plans/DESIGN-SANDBOX.md` §8-1）。
//!
//! **最小スコープ（意図的な割り切り）**: ACL付与対象は`workspace_root`とその配下の
//! セッション専用一時ディレクトリのみ。`.cargo`/`%APPDATA%`/rustup等のツールチェーン
//! グローバルパスへは付与しないため、cargo/rustc/git等の複雑なツールチェーンコマンドは
//! Tier2a下でaccess-deniedになり得る（`docs/phases/foundation/M12-shell-isolation-tiers.md`
//! 追記セクション参照）。
//!
//! **アプリ単位network制御（軸1・D-10/D-11、`plans/DESIGN-SANDBOX-APPPOLICY.md`）**:
//! `spawn`は`NetworkCapability`引数を取り、既定`Deny`（capability空）に対し、信頼クラス
//! （`--net-allow-app`一致）のコマンドにのみ`InternetClient`（`internetClient`=`S-1-15-3-1`）を
//! 1個積んで外向きソケットを開ける。付与はプロセスツリー全体が継承する（T-15）ため、実効境界は
//! 「1 `run_shell`呼び出し=1 networkポリシー」であり、信頼付与は最小コマンド集合に限定するのが前提
//! （D-11）。宛先無差別（宛先単位の細粒度はWFP=管理者、本実装のスコープ外）。

use std::ffi::c_void;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_NOT_ALL_ASSIGNED, HANDLE,
    HLOCAL, INVALID_HANDLE_VALUE, LUID,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertStringSidToSidW, GetExplicitEntriesFromAclW,
    GetNamedSecurityInfoW, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    AclSizeInformation, AddAce, AdjustTokenPrivileges, EqualSid, FreeSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor,
    LookupPrivilegeValueW, SetKernelObjectSecurity, SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
    SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    STARTUPINFOW,
};

use crate::shell_tier::FsPassthrough;
use crate::win_common::{
    build_env_block, clear_inherit, create_job_object, create_pipe_with_sddl, long_path_wide,
    read_two_pipes_to_strings, wide, write_all,
};

/// harness専用のAppContainer名。`%LOCALAPPDATA%\Packages\<container-folder>`と
/// `HKCU\...\AppContainer\Mappings\<SID>`にプロファイルとして保存される
/// （ユーザごとのレジストリハイブ、管理者権限は不要という前提）。
pub const CONTAINER_NAME: &str = "harness.shell.sandbox";

#[derive(Debug, thiserror::Error)]
pub enum AppContainerError {
    #[error("win32 call failed: {0}")]
    Win32(String),
    #[error("failed to grant AppContainer access to {path}: {reason}")]
    AclGrant {
        path: std::path::PathBuf,
        reason: String,
    },
    /// `revoke_ace`/`revoke_ace_recursive`専用のエラー（`AclGrant`の裏対称）。以前は撤収失敗でも
    /// `AclGrant`（Display文言が"failed to **grant**..."固定）を流用していたため、`harness fs
    /// revoke`の失敗メッセージに「grant」という紛らわしい語が出ていた（BUG-017の副次修正）。
    #[error("failed to revoke AppContainer access to {path}: {reason}")]
    AclRevoke {
        path: std::path::PathBuf,
        reason: String,
    },
    #[error("appcontainer preflight failed: {0}")]
    Preflight(String),
}

impl From<windows::core::Error> for AppContainerError {
    fn from(e: windows::core::Error) -> Self {
        AppContainerError::Win32(e.to_string())
    }
}

/// `CreateAppContainerProfile`/`DeriveAppContainerSidFromAppContainerName`が返すSIDは
/// `FreeSid`で解放するのが正しい対（`win_restricted.rs`のSDDL変換結果が`LocalFree`対象なのとは
/// 別系統のアロケータであり、混同しないこと。MSDN記載の注意点）。
pub struct OwnedContainerSid(PSID);

// PSIDは単なるアロケーションへのポインタ値であり、複数スレッド間で値として運ぶこと自体は
// OSレベルで安全（`RestrictedChild`/`AppContainerChild`のHANDLEと同じ理由でSend化する。
// `run_shell`の`spawn_blocking`をまたぐ非同期コードから使うために必要）。
unsafe impl Send for OwnedContainerSid {}

impl OwnedContainerSid {
    pub fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedContainerSid {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeSid(self.0);
        }
    }
}

/// harness専用のAppContainerプロファイルを作成する（既に存在すれば既存SIDを取得するのみ、
/// capability再指定は不要で副作用が無い）。
pub fn ensure_profile(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
    unsafe {
        let name_w = wide(name);
        let display_w = wide("Harness Shell Sandbox");
        let desc_w =
            wide("AppContainer for harness run_shell Tier2a (see plans/DESIGN-SANDBOX.md SS6.3)");

        match CreateAppContainerProfile(
            PCWSTR(name_w.as_ptr()),
            PCWSTR(display_w.as_ptr()),
            PCWSTR(desc_w.as_ptr()),
            None,
        ) {
            Ok(sid) => Ok(OwnedContainerSid(sid)),
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                let sid = DeriveAppContainerSidFromAppContainerName(PCWSTR(name_w.as_ptr()))?;
                Ok(OwnedContainerSid(sid))
            }
            Err(e) => Err(AppContainerError::from(e)),
        }
    }
}

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
fn collect_dirs_and_files(
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

fn grant_ace_mask(
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

/// workspace配下のノードへ read/execute のみを付与する（`grant_ace`のread-only版、D-13）。
/// `FILE_GENERIC_WRITE`・`DELETE`を含めないため、package SIDはこのルート配下を読取・実行
/// できるが書込・削除はできない（D-13「read-onlyを既定とする」）。
fn grant_ace_ro(path: &Path, sid: PSID, is_dir: bool) -> Result<(), AppContainerError> {
    let access = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;
    let inheritance = if is_dir {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };
    grant_ace_mask(path, sid, access, inheritance)
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
/// `experiment_l_inheritable_ace_on_root_vs_recursive_walk`の実機検証で、`root`へ継承あり
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
    grant_ace_ro(root, sid, true)?;

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
            grant_ace_ro(dir, sid, true)?;
        }
    }
    for file in &files {
        if !matches!(sid_ace_mask(file, sid), Ok(Some(_))) {
            grant_ace_ro(file, sid, false)?;
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

/// AppContainer固有のセキュリティ記述子をパイプへ適用する。AppContainerのアクセス制御は
/// 「オブジェクトのDACLにpackage SID（または`ALL APPLICATION PACKAGES`）へのACEが無ければ
/// アクセス不可」という広範なdefault-denyがファイル・レジストリだけでなく名前無しパイプ等の
/// カーネルオブジェクトにも及ぶ可能性が高い（Tier1で実機発見した「既定DACLの匿名パイプは
/// 低ILの子から書けない」現象と同種、`win_restricted.rs`参照）。**これは設計上の予測であり
/// 実機未検証**——最初の実機テストで子のstdout/stderrが空になる/ハングする場合、
/// 真っ先にここを疑う。
fn appcontainer_pipe(sid: PSID) -> windows::core::Result<(HANDLE, HANDLE)> {
    let (read, write) = create_pipe_with_sddl("D:(A;;GA;;;WD)")?;
    unsafe {
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        SetEntriesInAclW(Some(&[ea]), None, &mut new_dacl).ok()?;
        for handle in [read, write] {
            let _ = SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                windows::Win32::Security::PSID::default(),
                windows::Win32::Security::PSID::default(),
                Some(new_dacl as *const _),
                None,
            );
        }
        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
    }
    Ok((read, write))
}

/// spawn済みの子プロセス。`RestrictedChild`（`win_restricted.rs`）と同形のHANDLEベース
/// I/Oラッパ。
pub struct AppContainerChild {
    process: HANDLE,
    job: HANDLE,
    stdin_write: Option<HANDLE>,
    stdout_read: HANDLE,
    stderr_read: HANDLE,
}

unsafe impl Send for AppContainerChild {}

impl AppContainerChild {
    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.process, 1);
        }
    }

    pub fn kill_token(&self) -> KillToken {
        KillToken(self.process)
    }

    pub fn write_stdin_read_output_and_wait(
        mut self,
        stdin_payload: Option<&str>,
    ) -> Result<(String, String, i32), AppContainerError> {
        if let Some(payload) = stdin_payload {
            if let Some(stdin) = self.stdin_write.take() {
                write_all(stdin, payload.as_bytes());
                unsafe {
                    let _ = CloseHandle(stdin);
                }
            }
        } else if let Some(stdin) = self.stdin_write.take() {
            unsafe {
                let _ = CloseHandle(stdin);
            }
        }

        let (out, err) = read_two_pipes_to_strings(self.stdout_read, self.stderr_read);

        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            let mut code: u32 = 0;
            let _ = GetExitCodeProcess(self.process, &mut code);
            Ok((out, err, code as i32))
        }
    }
}

#[derive(Clone, Copy)]
pub struct KillToken(HANDLE);

unsafe impl Send for KillToken {}

impl KillToken {
    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.0, 1);
        }
    }
}

impl Drop for AppContainerChild {
    fn drop(&mut self) {
        unsafe {
            if let Some(h) = self.stdin_write.take() {
                let _ = CloseHandle(h);
            }
            let _ = CloseHandle(self.stdout_read);
            let _ = CloseHandle(self.stderr_read);
            let _ = CloseHandle(self.job);
            let _ = CloseHandle(self.process);
        }
    }
}

/// Tier2a子プロセスへ与えるnetwork capability（D-10、`plans/DESIGN-SANDBOX-APPPOLICY.md` §3）。
/// 既定は`Deny`（capability空=`CapabilityCount 0`、T-10外部持出し全遮断の核）。`InternetClient`は
/// `--net-allow-app`一致の信頼クラスにのみ与えられ、`internetClient`（`S-1-15-3-1`）1個を積んで
/// 外向きソケットを開ける（宛先無差別、T-15でツリー全体が継承）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCapability {
    /// capability空。networkを含む全capability-gatedリソースがdefault-deny（既定・安全側）。
    Deny,
    /// `internetClient`（S-1-15-3-1）を1個だけ積む。外向きソケットのみ許可（宛先無差別）。
    InternetClient,
}

/// AppContainer属性（`SECURITY_CAPABILITIES`）を付けて`CreateProcessW`で子を起動する。
/// Tier1の`CreateProcessAsUserW`+制限トークンとは別方式: トークンは差し替えず、呼び出し
/// スレッド自身のトークンのまま拡張属性リストでAppContainerへ閉じ込める。そのため
/// `SeAssignPrimaryTokenPrivilege`系の罠（BUG-003）はTier2aには存在しない。
///
/// `net`が`InternetClient`のときのみcapability配列に`internetClient` SIDを1個積む。SIDの
/// 生成（`ConvertStringSidToSidW`）と解放（`LocalFree`）はこの関数内に閉じ込め、呼び出し側へ
/// unsafeなSID寿命管理を漏らさない（`spawn_with_capabilities`は診断専用のまま温存）。
pub fn spawn(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
) -> Result<AppContainerChild, AppContainerError> {
    match net {
        NetworkCapability::Deny => spawn_impl(exe, args, cwd, env, want_stdin, container_sid, &[]),
        NetworkCapability::InternetClient => unsafe {
            let mut cap_sid = PSID::default();
            let sid_str = wide("S-1-15-3-1");
            ConvertStringSidToSidW(PCWSTR(sid_str.as_ptr()), &mut cap_sid).map_err(|e| {
                AppContainerError::Win32(format!("ConvertStringSidToSidW(internetClient): {e}"))
            })?;
            let capabilities = [SID_AND_ATTRIBUTES {
                Sid: cap_sid,
                Attributes: 0x0000_0004, // SE_GROUP_ENABLED
            }];
            let result = spawn_impl(
                exe,
                args,
                cwd,
                env,
                want_stdin,
                container_sid,
                &capabilities,
            );
            let _ = LocalFree(HLOCAL(cap_sid.0));
            result
        },
    }
}

/// 診断専用（`experiment_f`、削除拒否問題がゼロcapability固有かを切り分けるため）。
/// 本番の`spawn`は常に`&[]`（capability空、D-02の既定挙動）を渡すため、この関数の存在は
/// 本番のnetwork default-denyという中核の安全保証に一切影響しない。
#[cfg(test)]
pub(crate) fn spawn_with_capabilities(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<AppContainerChild, AppContainerError> {
    spawn_impl(exe, args, cwd, env, want_stdin, container_sid, capabilities)
}

/// AppContainer属性（`SECURITY_CAPABILITIES`）を付けて`CreateProcessW`で子を起動する実体。
/// `capabilities`が空なら`CapabilityCount=0`（本番`spawn`の既定=D-02）、空でなければ
/// 診断専用`spawn_with_capabilities`経由でのみ呼ばれる。
fn spawn_impl(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<AppContainerChild, AppContainerError> {
    // どのWin32呼び出しが失敗したかをエラー文字列に残す（AppContainerの起動は失敗モードが
    // 多く、0x57 ERROR_INVALID_PARAMETER等がどの段で出たかを区別できないと切り分けられない）。
    let step = |label: &'static str, e: windows::core::Error| {
        AppContainerError::Win32(format!("{label}: {e}"))
    };

    let job = create_job_object().map_err(|e| step("create_job_object", e))?;

    let (stdout_read, stdout_write) =
        appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stdout)", e))?;
    clear_inherit(stdout_read);
    let (stderr_read, stderr_write) =
        appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stderr)", e))?;
    clear_inherit(stderr_read);
    let (stdin_read, stdin_write) = if want_stdin {
        let (r, w) =
            appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stdin)", e))?;
        clear_inherit(w);
        (Some(r), Some(w))
    } else {
        (None, None)
    };

    let mut cmdline = format!("\"{exe}\"");
    for a in args {
        cmdline.push(' ');
        cmdline.push('"');
        cmdline.push_str(&a.replace('"', "\\\""));
        cmdline.push('"');
    }
    let mut cmdline_w = wide(&cmdline);
    let cwd_w = wide(&cwd.to_string_lossy());
    let mut env_block = build_env_block(env);

    let mut capabilities_buf = capabilities.to_vec();
    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: container_sid,
        Capabilities: if capabilities_buf.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities_buf.as_mut_ptr()
        },
        CapabilityCount: capabilities_buf.len() as u32,
        Reserved: 0,
    };

    let result: Result<PROCESS_INFORMATION, AppContainerError> = unsafe {
        let mut attr_list_size: usize = 0;
        // 1回目は必要サイズ取得のためだけの呼び出しで、バッファ不足エラーになるのが正常
        // （ERROR_INSUFFICIENT_BUFFER）なので戻り値は捨てる。
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut attr_list_size,
        );
        let mut attr_list_buf = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut c_void);
        let init_result = InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)
            .map_err(|e| step("InitializeProcThreadAttributeList", e));

        init_result.and_then(|()| {
            let update_result = UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(&mut security_capabilities as *mut _ as *const c_void),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
            .map_err(|e| step("UpdateProcThreadAttribute", e));

            let out = update_result.and_then(|()| {
                let startup_info_ex = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: STARTF_USESTDHANDLES,
                        hStdOutput: stdout_write,
                        hStdError: stderr_write,
                        hStdInput: stdin_read.unwrap_or(INVALID_HANDLE_VALUE),
                        ..Default::default()
                    },
                    lpAttributeList: attr_list,
                };

                let mut process_info = PROCESS_INFORMATION::default();
                CreateProcessW(
                    None,
                    PWSTR(cmdline_w.as_mut_ptr()),
                    None,
                    None,
                    true,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    Some(env_block.as_mut_ptr() as *mut _),
                    PCWSTR(cwd_w.as_ptr()),
                    &startup_info_ex.StartupInfo,
                    &mut process_info,
                )
                .map_err(|e| step("CreateProcessW", e))
                .map(|_| process_info)
            });

            DeleteProcThreadAttributeList(attr_list);
            out
        })
    };

    // 呼び出し側プロセスのパイプ端（子へ継承させた側）は、spawn後は不要なので閉じる。
    unsafe {
        let _ = CloseHandle(stdout_write);
        let _ = CloseHandle(stderr_write);
        if let Some(r) = stdin_read {
            let _ = CloseHandle(r);
        }
    }

    let process_info = match result {
        Ok(pi) => pi,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(job);
                let _ = CloseHandle(stdout_read);
                let _ = CloseHandle(stderr_read);
                if let Some(w) = stdin_write {
                    let _ = CloseHandle(w);
                }
            }
            return Err(e);
        }
    };

    unsafe {
        AssignProcessToJobObject(job, process_info.hProcess)
            .map_err(|e| step("AssignProcessToJobObject", e))?;
        let _ = CloseHandle(process_info.hThread);
    }

    Ok(AppContainerChild {
        process: process_info.hProcess,
        job,
        stdin_write,
        stdout_read,
        stderr_read,
    })
}

/// Tier2a（AppContainer）で使うシェルの実行ファイルパスとラベルを解決する。
/// **ストアアプリの実行エイリアス（`WindowsApps`配下の0バイトreparse point）は
/// AppContainerから解決できず`CreateProcessW`が`ERROR_INVALID_PARAMETER`で失敗する**ため、
/// pwshの実体がそこにある場合は使わず、実在の Windows PowerShell 5.1（System32の本物のexe、
/// 決してエイリアスにならない）へフォールバックする。smoke testと`run_shell`本体の両方で
/// この同一解決を使い、「smokeが通ったのに本番で別のexeを使って失敗する」ずれを防ぐ。
pub fn resolve_shell() -> (String, &'static str) {
    if let Ok(p) = which::which("pwsh") {
        let s = p.to_string_lossy();
        if !s.to_ascii_lowercase().contains("windowsapps") {
            return (s.into_owned(), "pwsh(Tier2a)");
        }
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    (
        format!("{system_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        "powershell5.1(Tier2a)",
    )
}

/// FS I/Oプローブ失敗を表す固有の終了コード（`spawn`自体の失敗や、シェル解決の失敗と
/// 区別するためのマーカー。`smoke_test_spawn`と`preflight`の理由文字列組立の両方で使う）。
const FS_PROBE_DENIED_EXIT_CODE: i32 = 3;

/// `probe_dir`（preflightが事前に作成・ACL付与済みのワークスペース内一時ディレクトリ）へ
/// 実際に一時ファイルを作成・読取・削除するPowerShellコマンド。`exit 0`だけを試す旧実装は
/// FileSystemプロバイダの初期化失敗があってもプロセス自体は正常終了してしまい偽陽性となる
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）ため、実FS I/Oまで
/// 一括で試し、成否を終了コードに反映させる。
const FS_IO_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        $p = Join-Path $env:HARNESS_PROBE_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
        New-Item -ItemType File -Path $p -Force | Out-Null; \
        Get-Content -LiteralPath $p | Out-Null; \
        Remove-Item -LiteralPath $p -Force; \
        exit 0 \
    } catch { \
        exit 3 \
    }";

fn smoke_test_spawn(
    sid: PSID,
    workspace_root: &Path,
    probe_dir: &Path,
) -> Result<(), AppContainerError> {
    // 本番run_shellと同じシェル解決を使い、そのシェルがゼロcapabilityのAppContainer内で
    // 実際に起動でき、かつワークスペース内のファイルI/Oまで通ることを確認する
    // （エイリアス回避は`resolve_shell`の責務）。
    let (shell, _) = resolve_shell();
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_PROBE_DIR".to_string(),
        probe_dir.to_string_lossy().into_owned(),
    ));
    let child = spawn(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FS_IO_PROBE_COMMAND,
        ],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
    )
    .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    let (_, _, code) = child
        .write_stdin_read_output_and_wait(None)
        .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    if code == FS_PROBE_DENIED_EXIT_CODE {
        return Err(AppContainerError::Preflight(
            "workspace FS I/O denied inside AppContainer (likely missing traverse ACE on \
             drive root; non-admin cannot grant; see \
             docs/phases/foundation/M12-shell-isolation-tiers.md 追記2/3)"
                .to_string(),
        ));
    }
    if code != 0 {
        return Err(AppContainerError::Preflight(format!(
            "smoke test command exited with unexpected code {code}"
        )));
    }
    Ok(())
}

/// fs passthrough（D-13）の到達性プローブ用コマンド。`FS_IO_PROBE_COMMAND`と同じ
/// 「実I/Oを試し終了コードで判定する」設計だが、catchブロックで例外メッセージをstdoutへ
/// 出す点が異なる（D9: 到達不能時に生エラーを呼び出し元へ返すため）。
const FS_PASSTHROUGH_RO_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        Get-ChildItem -LiteralPath $env:HARNESS_PASSTHROUGH_DIR -ErrorAction Stop | Out-Null; \
        exit 0 \
    } catch { \
        Write-Output $_.Exception.Message; \
        exit 3 \
    }";

/// ro版と同じ設計のrw版（一時ファイルの作成→読取→削除まで試す）。
const FS_PASSTHROUGH_RW_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        $p = Join-Path $env:HARNESS_PASSTHROUGH_DIR ([Guid]::NewGuid().ToString() + '.harness-probe.tmp'); \
        New-Item -ItemType File -Path $p -Force | Out-Null; \
        Get-Content -LiteralPath $p | Out-Null; \
        Remove-Item -LiteralPath $p -Force; \
        exit 0 \
    } catch { \
        Write-Output $_.Exception.Message; \
        exit 3 \
    }";

/// D9: passthroughルートが到達不能だったときの原因診断。生エラーメッセージに加え、
/// **`path`自身からドライブルートまでの全祖先**（`grant_traverse_chain`と同じ列挙順）の
/// traverse ACE有無を実地チェックし、欠けているノードを名指しする。従来はドライブルート
/// 1箇所しか見ていなかったが、`C:\Users\<user>\.cargo`のように中間の祖先（`C:\Users`・
/// `C:\Users\<user>`）が欠けているケースを診断できなかった
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記10で判明）。
/// 修復手順は`harness fs grant-traverse <path>`（連鎖化済み、追記13）を1回提示するだけでよい。
fn diagnose_unreachable_passthrough(sid: PSID, path: &Path, raw_message: &str) -> String {
    let mut chain: Vec<std::path::PathBuf> = path.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    let mut missing = Vec::new();
    for node in &chain {
        match sid_ace_mask(node, sid) {
            Ok(Some(mask)) if mask & FILE_TRAVERSE.0 != 0 && mask & FILE_READ_ATTRIBUTES.0 != 0 => {
            }
            Ok(Some(_)) => missing.push(format!(
                "{} (has a sandbox SID ACE but missing FILE_TRAVERSE|FILE_READ_ATTRIBUTES)",
                node.display()
            )),
            Ok(None) | Err(_) => missing.push(format!(
                "{} (no traverse ACE for the sandbox SID)",
                node.display()
            )),
        }
    }

    if missing.is_empty() {
        return format!(
            "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}); \
             all ancestor traverse ACEs (up to the drive root) look fine, cause unknown \
             (path may not exist, or a read-only file attribute is blocking a :rw request)",
            path.display()
        );
    }
    format!(
        "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}) -- \
         diagnosis: missing traverse ACE on {} ancestor node(s): {} (see \
         docs/phases/foundation/M12-shell-isolation-tiers.md 追記10・追記13). \
         fix (admin, one-time, grants the whole chain in one UAC prompt): \
         harness fs grant-traverse {}",
        path.display(),
        missing.len(),
        missing.join(", "),
        path.display()
    )
}

/// D8: passthroughルート1件へコンテナ内から実I/Oプローブ（疎通テスト）を行う。到達可なら
/// `None`、到達不能なら診断メッセージ（D9）を返す。全体のTier選択には影響しない
/// （`preflight`が結果を警告一覧として集約するだけで、壊れた穴以外は継続する）。
fn probe_passthrough(sid: PSID, workspace_root: &Path, fp: &FsPassthrough) -> Option<String> {
    let (shell, _) = resolve_shell();
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_PASSTHROUGH_DIR".to_string(),
        fp.path.to_string_lossy().into_owned(),
    ));
    let command = if fp.writable {
        FS_PASSTHROUGH_RW_PROBE_COMMAND
    } else {
        FS_PASSTHROUGH_RO_PROBE_COMMAND
    };
    let child = match spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", command],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
    ) {
        Ok(child) => child,
        Err(e) => {
            return Some(format!(
                "fs-allow {} : probe could not start: {e}",
                fp.path.display()
            ));
        }
    };
    match child.write_stdin_read_output_and_wait(None) {
        Ok((_, _, 0)) => None,
        Ok((stdout, _, _code)) => Some(diagnose_unreachable_passthrough(
            sid,
            &fp.path,
            stdout.trim(),
        )),
        Err(e) => Some(format!(
            "fs-allow {} : probe failed: {e}",
            fp.path.display()
        )),
    }
}

/// harness起動時に1回だけ呼ぶ。プロファイル作成→ACL付与→起動smokeテストの一連を行い、
/// いずれか失敗したら理由文字列を返す（`shell_tier::best_effort_tier`がTier1への降格理由
/// としてそのまま使う）。判断は実行前に完結させ、`run_shell`個々の呼び出し中には降格ロジックを
/// 一切持たせない（非冪等コマンドの二重実行を避けるための意図的判断）。
///
/// `passthrough`（D-13、fs passthrough allowlist）は各ルートへACEを付与したうえで到達性を
/// プローブする（D8）。到達不能な穴は`preflight`全体を失敗させず、戻り値の警告一覧に
/// 診断メッセージ（D9）を積むだけに留める（壊れた穴があってもworkspaceと他の穴は動き続ける）。
/// `preflight`の戻り値。`warnings`はD8の到達不能診断（従来どおり）、`granted_passthrough`は
/// **実際にACEが付与された（既存で十分だった場合・部分的にしか適用できなかった場合を含む）**
/// passthroughルートの一覧（`(path, writable)`）。呼び出し側（`harness-cli`の台帳記録）は
/// この一覧だけを台帳へ書くことで、「幻の台帳エントリ」（実際には`ACCESS_DENIED`で失敗した
/// のに記録だけ残る）を防ぐ。逆に、rootへのACE付与自体は成功したが子孫の一部
/// （TrustedInstaller所有等）で失敗した「部分適用」ケースは、`sid_ace_mask`でrootを権威的に
/// プローブして`Ok`/`Err`によらず記録する（BUG-017: 記録漏れが「撤収経路の無い孤立ACE」を
/// 生むため、幻の台帳エントリより孤立ACEの方を重く見て記録側に倒す）。
pub struct PreflightOutcome {
    pub warnings: Vec<String>,
    pub granted_passthrough: Vec<(std::path::PathBuf, bool)>,
    /// `preflight`が特権分離ヘルパーへ`GrantFsAllow`を委譲する経路を実際に通り、その際
    /// `wfp_chain_pipe`が`Some`だったため「処理完了後に`harness-netfilterd`を連鎖起動してほしい」
    /// という指示を実際に添えたかどうか（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D
    /// シナリオ(A)）。連鎖起動の**成否**までは追跡しない（ヘルパー側はベストエフォートでログのみ、
    /// `privhelper.rs`の`serve()`参照）——呼び出し元は、この値が`true`ならnetfilterdとの
    /// ハンドシェイクを試み、タイムアウトすれば「今回は使えなかった」として扱えばよい。
    /// `false`の場合（`needs_elevation`が空だった、または本体が既に管理者で直接付与した等）は
    /// 連鎖起動を試みていないため、呼び出し元はシナリオ(B)（`NetfilterHandle::start`直接起動）へ
    /// フォールバックする必要がある。
    pub netfilterd_chain_attempted: bool,
}

/// `fp`が要求するアクセスのうち、`preflight`が「既に十分」と判定するために必要な最小マスク
/// （`grant_ace`/`grant_ace_ro`が実際に付与するマスクと同じ論理和。継承フラグの相違までは
/// 見ない、`grant_ace_mask`の冪等スキップと同じ考え方）。
fn required_passthrough_mask(writable: bool) -> u32 {
    if writable {
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0
    } else {
        FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0
    }
}

pub fn preflight(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
) -> Result<PreflightOutcome, AppContainerError> {
    let sid = ensure_profile(CONTAINER_NAME)?;
    // Tier2aが既定でプローブされるため、
    // 起動のたびにワークスペース全体へ個別書込を試みる`grant_ace_recursive`ではなく、
    // 高速化版（root継承ACE1件+フォールバック確認walk、`grant_ace_inheritable_rw`のdoc参照）
    // を使う。
    grant_ace_inheritable_rw(workspace_root, sid.as_psid())?;
    let tmp_dir = workspace_root
        .join(".harness")
        .join("sandbox")
        .join("Tier2a-tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    smoke_test_spawn(sid.as_psid(), workspace_root, &tmp_dir)?;

    let mut warnings = Vec::new();
    let mut granted_passthrough: Vec<(std::path::PathBuf, bool)> = Vec::new();
    // 本体プロセス内（非管理者）でACCESS_DENIEDになったエントリ（システム保護パス等）だけを
    // ここへ集め、後段で1回の特権分離ヘルパー要求へまとめる（起動あたりUAC最大1回、
    // `TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」の決定）。
    let mut needs_elevation: Vec<crate::privhelper::FsAllowGrant> = Vec::new();
    let mut netfilterd_chain_attempted = false;

    for fp in passthrough {
        if !fp.path.exists() {
            warnings.push(format!(
                "fs-allow {} : path does not exist, skipped",
                fp.path.display()
            ));
            continue;
        }

        // 事前チェック（決定1）: 既にsid宛のACEが要求マスクの上位集合を持っていれば、
        // 本体内のwalkもprivhelperのUACも一切スキップする（ユーザ所有パスの再実行はUAC無し）。
        let required = required_passthrough_mask(fp.writable);
        let already_sufficient = matches!(sid_ace_mask(&fp.path, sid.as_psid()), Ok(Some(existing)) if existing & required == required);
        if already_sufficient {
            granted_passthrough.push((fp.path.clone(), fp.writable));
            if let Some(diagnosis) = probe_passthrough(sid.as_psid(), workspace_root, fp) {
                warnings.push(diagnosis);
            }
            continue;
        }

        let grant_result = if fp.writable {
            grant_ace_recursive(&fp.path, sid.as_psid())
        } else {
            grant_ace_inheritable_ro(&fp.path, sid.as_psid())
        };
        match grant_result {
            Ok(()) => {
                granted_passthrough.push((fp.path.clone(), fp.writable));
                if let Some(diagnosis) = probe_passthrough(sid.as_psid(), workspace_root, fp) {
                    warnings.push(diagnosis);
                }
            }
            Err(_) => {
                // forced（--force-system-acl, D-19）は host パスの絶対拒否ゲートを**UACの前に**
                // 通す（禁止パスなら昇格させずここで警告に落とす。無駄なUACを出さない二重化）。
                if fp.forced {
                    if let Some(reason) = is_force_grant_forbidden(&fp.path) {
                        warnings.push(format!(
                            "fs-allow {} : forced system-ACL grant refused: {reason}",
                            fp.path.display()
                        ));
                        continue;
                    }
                }
                // 本体（非管理者）内では書けなかった。システム保護パス（所有者がSYSTEM/
                // TrustedInstaller等）の可能性があるため、即座に警告へ落とさず後段の
                // 特権分離ヘルパー経路へ回す。
                needs_elevation.push(crate::privhelper::FsAllowGrant {
                    path: fp.path.clone(),
                    writable: fp.writable,
                    forced: fp.forced,
                });
            }
        }
    }

    if !needs_elevation.is_empty() {
        let elevated = if crate::privhelper::is_elevated() {
            // 本体が既に管理者（§5.3、grant-traverseの`*_direct`と同じ考え方）:
            // ヘルパーを経由せずその場で直接付与する。
            let mut granted = Vec::new();
            let mut failures = Vec::new();
            for entry in &needs_elevation {
                // forcedは書込前に絶対拒否ゲートを通し、通過分のみ`SeRestorePrivilege`下で付与する
                // （dispatch側と同じ防壁。本体が既に管理者の経路でも同一の不変条件を保つ）。
                if entry.forced {
                    if let Some(reason) = is_force_grant_forbidden(&entry.path) {
                        failures.push((entry.path.clone(), reason));
                        continue;
                    }
                }
                let do_grant = || {
                    if entry.writable {
                        grant_ace_recursive(&entry.path, sid.as_psid())
                    } else {
                        grant_ace_inheritable_ro(&entry.path, sid.as_psid())
                    }
                };
                let result = if entry.forced {
                    with_restore_privilege(do_grant)
                } else {
                    do_grant()
                };
                match result {
                    Ok(()) => granted.push(entry.path.clone()),
                    Err(e) => failures.push((entry.path.clone(), e.to_string())),
                }
            }
            Ok((granted, failures))
        } else {
            netfilterd_chain_attempted = wfp_chain_pipe.is_some();
            crate::privhelper::run_privileged_fs_allow_with_netfilterd_chain(
                needs_elevation.clone(),
                wfp_chain_pipe.clone(),
            )
            .map_err(|e| e.to_string())
        };

        match elevated {
            Ok((granted, failures)) => {
                for path in &granted {
                    let writable = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.writable)
                        .unwrap_or(false);
                    granted_passthrough.push((path.clone(), writable));
                    if let Some(fp) = passthrough.iter().find(|fp| &fp.path == path) {
                        if let Some(diagnosis) =
                            probe_passthrough(sid.as_psid(), workspace_root, fp)
                        {
                            warnings.push(diagnosis);
                        }
                    }
                }
                for (path, reason) in &failures {
                    let writable = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.writable)
                        .unwrap_or(false);
                    // BUG-017: grant_ace_recursive/grant_ace_inheritable_roはroot(先頭ノード)から
                    // 順に付与するため、途中の子孫(TrustedInstaller所有等)で失敗しても、rootには
                    // 既にACEが載っている場合がある。「失敗」扱いで台帳へ記録しないと、実FS上には
                    // ACEが残るのに撤収経路が無い孤立ACEになる。rootを権威的にプローブし、ACEが
                    // 実在すれば台帳へ記録して`fs revoke`で後から掃除できるようにする。
                    if matches!(sid_ace_mask(path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough.push((path.clone(), writable));
                        warnings.push(format!(
                            "fs-allow {} : partially applied via privilege-separation helper \
                             (D-16) -- some descendant failed ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            path.display(),
                            path.display()
                        ));
                    } else {
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed (via privilege-separation helper, \
                             D-16): {reason}",
                            path.display()
                        ));
                    }
                }
            }
            Err(reason) => {
                for entry in &needs_elevation {
                    if matches!(sid_ace_mask(&entry.path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough.push((entry.path.clone(), entry.writable));
                        warnings.push(format!(
                            "fs-allow {} : partially applied -- the privilege-separation helper \
                             (D-16) could not fully complete ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            entry.path.display(),
                            entry.path.display()
                        ));
                    } else {
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed: access denied in-process, and the \
                             privilege-separation helper (D-16) could not complete either: {reason}",
                            entry.path.display()
                        ));
                    }
                }
            }
        }
    }

    Ok(PreflightOutcome {
        warnings,
        granted_passthrough,
        netfilterd_chain_attempted,
    })
}

/// `ACCESS_ALLOWED_ACE_TYPE`（WinNT.h）。`windows`クレートはこの値を定数として公開して
/// いないため、既知の固定値としてここに置く。
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// [BUG-020の修正] `dacl`から`sid`宛の`ACCESS_ALLOWED_ACE`だけを取り除いた新しいDACLを、
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
/// `ACCESS_ALLOWED_ACE_TYPE`以外のACE種別（このコードベースが自ら書き込むことはない）は
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

            let is_target = if header.AceType == ACCESS_ALLOWED_ACE_TYPE {
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
pub fn revoke_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
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
pub fn revoke_ace_recursive(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
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
fn sid_ace_mask(path: &Path, sid: PSID) -> Result<Option<u32>, AppContainerError> {
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

/// ドライブルート（例`C:\`）へ、`sid`の`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を単一・非継承で
/// 付与する（D10、`harness fs grant-traverse`本体）。`docs/phases/foundation/
/// M12-shell-isolation-tiers.md`追記8で判明した根本原因（ドライブルートのtraverse ACE欠如、
/// `FILE_TRAVERSE`単独では`Read Attributes`アクセス拒否が残り不十分）の修復そのもの。
/// ドライブルートのDACL変更には`WRITE_DAC`が要るため、非管理者では
/// `AppContainerError::AclGrant`（access denied）を返す（呼び出し側が「管理者で再実行」を促す）。
pub fn grant_traverse_drive_root(drive: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace_mask(
        drive,
        sid,
        FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
        NO_INHERITANCE,
    )
}

/// `target`とその全祖先（ドライブルートまで）へ、`sid`の`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
/// 単一・非継承で付与する（D10連鎖化、`TIER1A-OPEN-ISSUES.md`項目6「多階層祖先traverse ACE不足」の
/// 解消）。`C:\Users\<user>\.cargo`のようにドライブルート直下でないパスをpassthroughする場合、
/// `grant_traverse_drive_root`によるドライブルート単体への付与だけでは足りず、`C:\Users`・
/// `C:\Users\<user>`という中間の祖先にも個別にtraverse ACEが要ることが実機検証で判明した
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記10）。
///
/// `Path::ancestors()`はtarget自身→直近の親→…→ドライブルートの順で返すため、ここでは
/// ドライブルートから`target`へ向かう順（浅い方から深い方）に反転してから1ノードずつ付与する。
/// 祖先を先に開通させてから深いノードへ進む順序にしておけば、途中で失敗しても「到達不能な
/// 深いノードだけ付与済みで、そこへ辿り着くための浅い祖先が未付与」という手戻りしにくい
/// 半端な状態を避けられる。
///
/// 途中のノードで付与に失敗した場合は、そこで打ち切って`Err`を返す。**ただし戻り値の`Vec`には
/// 失敗した時点までに実際に付与が成功したノードを常に含める**（`Result`の成否に関わらず、
/// 呼び出し側は返ってきた`Vec`の全ノードをtraverse台帳へ記録しなければならない。台帳に載らない
/// まま実FS上にACEだけが残る「孤立ACE」を防ぐため。`CLAUDE.md`の台帳誤削除防止の思想と同根）。
pub fn grant_traverse_chain(
    target: &Path,
    sid: PSID,
) -> (Vec<std::path::PathBuf>, Result<(), AppContainerError>) {
    grant_traverse_chain_with_progress(target, sid, |_node, _result, _elapsed| {})
}

/// `grant_traverse_chain`と同じ処理を行うが、各ノードへの付与試行が完了するたびに
/// `on_node(node, result, elapsed)`を呼ぶ。特権分離ヘルパー（D-16、`privhelper.rs`）が
/// ノード別の所要時間をログへ残せるようにするためのフック（BUG-011の遅いプロファイル
/// ルート近傍書込みを、無言のブラックボックスにせず観測可能にする）。既存の
/// `grant_traverse_chain`はこの関数を空クロージャで包んだだけの薄いラッパであり、
/// 呼び出し側（CLI直接実行等）の挙動・シグネチャは変わらない。
pub fn grant_traverse_chain_with_progress(
    target: &Path,
    sid: PSID,
    mut on_node: impl FnMut(&Path, &Result<(), AppContainerError>, std::time::Duration),
) -> (Vec<std::path::PathBuf>, Result<(), AppContainerError>) {
    let mut chain: Vec<std::path::PathBuf> = target.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    let mut granted = Vec::with_capacity(chain.len());
    for node in &chain {
        let started = std::time::Instant::now();
        let result = grant_ace_mask(
            node,
            sid,
            FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
            NO_INHERITANCE,
        );
        on_node(node, &result, started.elapsed());
        if let Err(e) = result {
            return (granted, Err(e));
        }
        granted.push(node.clone());
    }
    (granted, Ok(()))
}

/// `grant_traverse_chain`の付与予定チェーンを、一切書込まずに読み取り専用で列挙する
/// （`harness fs grant-traverse --dry-run`、ユーザーが実書込前に対象ノードと既存ACE有無を
/// 確認できるようにする要件）。各ノードについて、現在`sid`宛の明示ACEがどのマスクを
/// 持っているか（`None`なら無し）を`sid_ace_mask`で読み取るだけで、`SetNamedSecurityInfoW`は
/// 一切呼ばない。`already_sufficient`が`true`のノードは、実行時に`grant_ace_mask`の
/// 冪等スキップ（本ファイル`grant_ace_mask`参照）によって書込みがスキップされる見込み。
pub struct TraversePreviewNode {
    pub path: std::path::PathBuf,
    pub existing_mask: Option<u32>,
    pub already_sufficient: bool,
}

pub fn preview_traverse_chain(target: &Path, sid: PSID) -> Vec<TraversePreviewNode> {
    const REQUIRED: u32 = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
    let mut chain: Vec<std::path::PathBuf> = target.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    chain
        .into_iter()
        .map(|node| {
            let existing_mask = sid_ace_mask(&node, sid).unwrap_or(None);
            let already_sufficient = existing_mask
                .map(|m| m & REQUIRED == REQUIRED)
                .unwrap_or(false);
            TraversePreviewNode {
                path: node,
                existing_mask,
                already_sufficient,
            }
        })
        .collect()
}

/// `TIER1A-OPEN-ISSUES.md`課題1（traverse問題の検証プラン）の診断テスト群。
///
/// いずれも`#[ignore]`（実Win32・実AppContainer・実FS ACL変更を伴う重い/副作用ありの処理のため
/// 通常の`cargo test`では走らない）。`cargo test -p harness-sandbox -- --ignored <test名>`で
/// 個別に実行する。エージェントループ全体を起動せず数秒でイテレーションできる、
/// `docs/phases/foundation/M12-shell-isolation-tiers.md`「追記2 Phase 1」の高速反復ループ本体。
///
/// 実FS I/Oを試みるPowerShellコマンド。本番の`smoke_test_spawn`（`FS_IO_PROBE_COMMAND`、
/// 単一ファイルの作成→読取→削除を終了コードでのみ判定する軽量版）より詳しい観測用で、
/// FileSystemプロバイダ初期化の成否・`Get-ChildItem`/`New-Item`の成否・ドライブ可視性まで
/// stdout全文で一括観測する（`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3の
/// 「本番プローブと診断プローブの判定一致確認」で、この2つが同じ機種で同じ合否になることを
/// `parity_production_probe_matches_diagnostic_probe`で突き合わせる）。
#[cfg(all(windows, test))]
mod traverse_diagnostics {
    use super::*;

    const PROBE_COMMAND: &str = "\
        Set-Location -LiteralPath $env:HARNESS_PROBE_DIR; \
        Write-Output ('CWD=' + (Get-Location).Path); \
        Get-ChildItem | Out-String -Width 200 | Write-Output; \
        New-Item -ItemType File -Path 'probe.txt' -Force | Out-String -Width 200 | Write-Output; \
        Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Out-String -Width 200 | Write-Output; \
        Get-Volume -ErrorAction SilentlyContinue | Out-String -Width 200 | Write-Output";

    /// `dir`をcwdにしてPROBE_COMMANDを実行し、stdout/stderr全文とexit codeをそのまま
    /// 標準出力へ焼き付ける（procmon/AccessChkでの裏取りと突き合わせられるよう、テスト自身は
    /// 成否をアサートしない。観測が目的であり合否判定はここでは行わない）。
    fn run_probe(sid: PSID, dir: &Path) {
        let (shell, label) = resolve_shell();
        println!(
            "=== probe: shell={shell} ({label}), dir={} ===",
            dir.display()
        );
        let mut env = crate::secret_env::build_child_env();
        env.push((
            "HARNESS_PROBE_DIR".to_string(),
            dir.to_string_lossy().into_owned(),
        ));
        let child = spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", PROBE_COMMAND],
            dir,
            &env,
            false,
            sid,
            NetworkCapability::Deny,
        )
        .expect("spawn should succeed even if the shell command itself fails inside");
        let (out, err, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("pipe I/O should not fail");
        println!("--- exit code: {code} ---");
        println!("--- stdout ---\n{out}");
        println!("--- stderr ---\n{err}");
    }

    /// PowerShellのFileSystemプロバイダ固有の挙動（`InitializeDefaultDrives`が全ドライブ列挙を
    /// 試みる）と、NTFSのtraverse-checking自体（シェルに依存しない、`CreateFileW`レベルの
    /// ACCESS_DENIED）を切り分けるための、cmd.exe版プローブ。`resolve_shell`はTier2a本番と
    /// 同じPowerShell解決を返すためここでは使わず、cmd.exeを直接指定する。
    fn run_probe_cmd(sid: PSID, dir: &Path) {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let cmd_exe = format!("{system_root}\\System32\\cmd.exe");
        println!("=== probe(cmd.exe): dir={} ===", dir.display());
        let env = crate::secret_env::build_child_env();
        let child = spawn(
            &cmd_exe,
            &["/d", "/c", "dir"],
            dir,
            &env,
            false,
            sid,
            NetworkCapability::Deny,
        )
        .expect("spawn should succeed even if the shell command itself fails inside");
        let (out, err, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("pipe I/O should not fail");
        println!("--- exit code: {code} ---");
        println!("--- stdout ---\n{out}");
        println!("--- stderr ---\n{err}");
    }

    /// Experiment A: 中立ロケーション対照実験（非侵襲）。
    /// `C:\ProgramData\harness-sandbox-diag\<pid>`（プロファイル外）へpackage SIDのACEを付与し、
    /// そこでのみプローブを走らせる。ユーザープロファイルのACLには一切触れない。
    #[test]
    #[ignore]
    fn experiment_a_neutral_location() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let dir = std::path::PathBuf::from(format!(
            "C:\\ProgramData\\harness-sandbox-diag\\{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create neutral dir");
        grant_ace_recursive(&dir, sid.as_psid()).expect("grant_ace_recursive on neutral dir");
        run_probe(sid.as_psid(), &dir);
        run_probe_cmd(sid.as_psid(), &dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 診断: AppContainer子プロセス自身の実効整合性レベルを観測する（`C:\`のtraverse不要、
    /// `C:\ProgramData`配下の非侵襲実験）。`experiment_d`で発見した`Mandatory Label\Low
    /// Mandatory Level:(NW)`が、削除拒否の真因（DACLではなくMIC）かどうかを切り分ける。
    #[test]
    #[ignore]
    fn experiment_e_integrity_level_probe() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let dir = std::path::PathBuf::from(format!(
            "C:\\ProgramData\\harness-sandbox-diag-e\\{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create neutral dir");
        grant_ace_recursive(&dir, sid.as_psid()).expect("grant_ace_recursive on neutral dir");

        let (shell, _) = resolve_shell();
        let env = crate::secret_env::build_child_env();
        // whoami/Get-ChildItem等FileSystemプロバイダに触れるコマンドはtraverse無しでは
        // 失敗する（M12追記2の既知症状）ため、純粋な.NETトークン列挙のみでMandatory Label
        // SID（S-1-16-*）を取得する。
        let command = "$id = [System.Security.Principal.WindowsIdentity]::GetCurrent(); \
             Write-Output ('User=' + $id.User.Value); \
             $id.Groups | Where-Object { $_.Value -like 'S-1-16-*' } | ForEach-Object { Write-Output ('IntegritySid=' + $_.Value) }";
        let child = spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", command],
            &dir,
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
        )
        .expect("spawn should succeed");
        let (out, err, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("pipe I/O should not fail");
        println!("=== AppContainer child integrity level probe: exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Experiment F: ゼロcapability（`CapabilityCount=0`）自体が削除拒否の原因かを切り分ける
    /// 診断実験。`internetClient`相当のcapabilityを1つだけ付けた場合に`Remove-Item`が通るかを
    /// 確認する。**これはTier2aのnetwork default-deny（T-10対策の核）を一時的に崩す診断専用の
    /// 実験であり、恒久的な挙動変更ではない**（`spawn_with_capabilities`は`#[cfg(test)]`限定）。
    ///
    /// `experiment_c`/`d`と同じく`C:\`ルートへの単一traverse ACEが前提として要る
    /// （`C:\ProgramData`配下であってもtraverse無しではFS I/O自体ができないため、
    /// capability変数だけを切り分けて観測できない。当初`experiment_a`/`e`が非侵襲で動いて
    /// 見えたのは、それらがFileSystemプロバイダに触れないコマンドのみを使っていたためだと
    /// 判明した）。grant〜revoke間はResultのみで構成し必ず原状復帰する。
    #[test]
    #[ignore]
    fn experiment_f_nonempty_capability_delete_probe() {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;

        let drive_root = std::path::PathBuf::from("C:\\");
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let dir = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-f-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create verify workspace under C:\\ (needs admin)");
        grant_ace_recursive(&dir, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

        let traverse_grant = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result: {traverse_grant:?} ===");

        // internetClient capability (S-1-15-3-1) を1つだけ持つcapability配列を組み立てる。
        let cap_result: windows::core::Result<()> = (|| unsafe {
            if traverse_grant.is_err() {
                println!("=== Experiment F skipped: C:\\ traverse grant failed ===");
                return Ok(());
            }
            let mut cap_sid = PSID::default();
            let sid_str = wide("S-1-15-3-1");
            ConvertStringSidToSidW(windows::core::PCWSTR(sid_str.as_ptr()), &mut cap_sid)?;
            let capabilities = [SID_AND_ATTRIBUTES {
                Sid: cap_sid,
                Attributes: 0x0000_0004, // SE_GROUP_ENABLED
            }];

            let (shell, _) = resolve_shell();
            let env = crate::secret_env::build_child_env();
            let command =
                "Remove-Item -LiteralPath 'f-probe.tmp' -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType File -Path 'f-probe.tmp' -Force | Out-Null; \
                 try { Remove-Item -LiteralPath 'f-probe.tmp' -Force; Write-Output 'DELETE OK' } \
                 catch { Write-Output \"DELETE FAIL: $_\" }";
            let child = spawn_with_capabilities(
                &shell,
                &["-NoProfile", "-NonInteractive", "-Command", command],
                &dir,
                &env,
                false,
                sid.as_psid(),
                &capabilities,
            )
            .expect("spawn_with_capabilities should succeed");
            let (out, err, code) = child
                .write_stdin_read_output_and_wait(None)
                .expect("pipe I/O should not fail");
            println!(
                "=== Experiment F (internetClient capability, non-empty): exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}"
            );

            let _ = LocalFree(HLOCAL(cap_sid.0));
            Ok(())
        })();
        if let Err(e) = cap_result {
            println!("=== Experiment F setup failed: {e:?} ===");
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ traverse ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Experiment B: プロファイルtraverse実験（Aで原因が割れなかった場合のみ手動で
    /// `--ignored`指定して実行する。既定のワークスペースの祖先である`C:\Users\<user>`へ
    /// 単一・非継承`FILE_TRAVERSE`を付与し、プローブ後に必ず`revoke_ace`で原状復帰する）。
    /// `HARNESS_PROBE_WORKSPACE`環境変数で実ワークスペースパスを渡す運用とし、既定では
    /// 何もしないダミーガードのみ置く（誤って自動実行されないようにする安全弁）。
    #[test]
    #[ignore]
    fn experiment_b_profile_traverse() {
        let Ok(workspace) = std::env::var("HARNESS_PROBE_WORKSPACE") else {
            eprintln!(
                "skipped: set HARNESS_PROBE_WORKSPACE to the real workspace path to run this experiment"
            );
            return;
        };
        let workspace = std::path::PathBuf::from(workspace);
        let ancestor = dirs_home().expect("resolve profile home (%USERPROFILE%)");

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        grant_ace_mask(
            &ancestor,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        )
        .expect("grant single-ACE FILE_TRAVERSE on profile ancestor");

        run_probe(sid.as_psid(), &workspace);

        revoke_ace(&ancestor, sid.as_psid())
            .expect("revert: revoke_ace on profile ancestor must not fail silently");
    }

    fn dirs_home() -> Option<std::path::PathBuf> {
        std::env::var("USERPROFILE")
            .ok()
            .map(std::path::PathBuf::from)
    }

    /// Experiment C: 「traverse-only仮説」の実証実験（`plans/TIER1A-OPEN-ISSUES.md`
    /// フェーズ2）。**結論（`docs/phases/foundation/M12-shell-isolation-tiers.md`追記5参照）**:
    /// 仮説は部分的にのみ成立する。`C:\`ルートへのtraverse ACE 1本で`cd`/`Get-ChildItem`/
    /// `New-Item`/`Get-Content`は全て回復するが、**`Remove-Item`だけが独立した理由で
    /// アクセス拒否のまま**残り、本番`smoke_test_spawn`（New-Item→Get-Content→Remove-Item→
    /// exit 0、失敗でexit 3）は失敗し続ける。traverse欠如とは別種の、AppContainerにおける
    /// 削除操作固有の権限問題が残っている。
    ///
    /// Experiment Bは`%USERPROFILE%`（`C:\Users\<user>`）1段だけにtraverseを付与して失敗した
    /// （上流の`C:\`・`C:\Users`が塞がったまま）。今回は**祖先チェーンを1段に最小化**するため、
    /// ドライブルート直下の浅いワークスペース`C:\harness-Tier2a-verify-<pid>`を使う。これにより
    /// 唯一のシステムACL変更を「**`C:\`ルートへの単一・非継承`FILE_TRAVERSE`ACE 1本のみ**」に
    /// 絞れる（`C:\Users`以下には一切触れない）。
    ///
    /// grant〜revoke間は`Result`を返す処理のみで構成し（`panic!`する`expect`を挟まない）、
    /// テストが途中失敗しても`C:\`のACEが必ず消えるようにする。プローブ結果自体は
    /// **アサートせず観測に留める**（結論は上記の通り既に確定しているが、この機種固有の
    /// 挙動が将来変化していないかを`--nocapture`で目視確認する診断テストとして残す）。
    #[test]
    #[ignore]
    fn experiment_c_full_chain_traverse_recovers_fs_io() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace =
            std::path::PathBuf::from(format!("C:\\harness-Tier2a-verify-{}", std::process::id()));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        // ワークスペース作成+フルアクセス付与（既存`preflight`と同じ手順）。
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");
        let probe_dir = workspace
            .join(".harness")
            .join("sandbox")
            .join("Tier2a-tmp");
        std::fs::create_dir_all(&probe_dir)
            .expect("create probe dir (inherits ACE from workspace)");

        // 唯一のシステムACL変更: C:\ ルートへの単一ACE。
        let grant_result = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            // 本番プローブ（軽量・終了コードのみ判定、probe_dirはworkspace直下から3階層深い
            // `.harness/sandbox/Tier2a-tmp`）。panicさせずResultで受ける。
            let production_result = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir);
            println!("=== production probe (smoke_test_spawn, deep probe_dir) result: {production_result:?} ===");

            // 追加確認: probe_dirをworkspace自身（1階層のみ）にした場合に成否が変わるかを見る
            // （run_probeがworkspace直下でのI/Oに成功している観測との整合性を取るため）。
            let shallow_result = smoke_test_spawn(sid.as_psid(), &workspace, &workspace);
            println!("=== production probe (smoke_test_spawn, shallow probe_dir=workspace) result: {shallow_result:?} ===");

            // 詳細観測（stdout全文）。
            run_probe(sid.as_psid(), &workspace);
            run_probe_cmd(sid.as_psid(), &workspace);

            // smoke_test_spawnがなぜ失敗するか（New-Item/Get-Content/Remove-Itemのどの段か）
            // をtry/catchの詳細出力付きで観測する。
            let verbose_probe = "\
                $p = Join-Path $env:HARNESS_PROBE_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
                Write-Output \"p=$p\"; \
                try { New-Item -ItemType File -Path $p -Force | Out-Null; Write-Output 'NEW-ITEM OK' } catch { Write-Output \"NEW-ITEM FAIL: $_\" }; \
                try { Get-Content -LiteralPath $p | Out-Null; Write-Output 'GET-CONTENT OK' } catch { Write-Output \"GET-CONTENT FAIL: $_\" }; \
                try { Remove-Item -LiteralPath $p -Force; Write-Output 'REMOVE-ITEM OK' } catch { Write-Output \"REMOVE-ITEM FAIL: $_\" }";
            let (shell, _) = resolve_shell();
            let mut env = crate::secret_env::build_child_env();
            env.push((
                "HARNESS_PROBE_DIR".to_string(),
                workspace.to_string_lossy().into_owned(),
            ));
            let child = spawn(
                &shell,
                &["-NoProfile", "-NonInteractive", "-Command", verbose_probe],
                &workspace,
                &env,
                false,
                sid.as_psid(),
                NetworkCapability::Deny,
            )
            .expect("spawn should succeed");
            let (out, err, code) = child
                .write_stdin_read_output_and_wait(None)
                .expect("pipe I/O should not fail");
            println!("=== verbose New-Item/Get-Content/Remove-Item probe: exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}");

            println!(
                "=== HYPOTHESIS RESULT: traverse-only recovers FS I/O (deep)={} (shallow)={} ===",
                production_result.is_ok(),
                shallow_result.is_ok()
            );
        }

        // 必ず原状復帰: grant成否に関わらずrevokeを試みる（冪等、既存ACE無しでも安全）。
        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ traverse ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// PowerShellコマンドをtry/catchで包み、成否を終了コードのみで判定するヘルパー
    /// （`$LASTEXITCODE`の文字列パースに頼らない、`smoke_test_spawn`と同じ設計原則）。
    /// 失敗時は詳細を`println!`で焼き付ける（観測目的、アサートしない）。
    fn run_probe_bool(sid: PSID, dir: &Path, command: &str) -> bool {
        let wrapped =
            format!("try {{ {command} }} catch {{ Write-Output \"CAUGHT: $_\"; exit 1 }}");
        let (shell, _) = resolve_shell();
        let env = crate::secret_env::build_child_env();
        let child = spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &wrapped],
            dir,
            &env,
            false,
            sid,
            NetworkCapability::Deny,
        )
        .expect("spawn should succeed even if the shell command itself fails inside");
        let (out, err, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("pipe I/O should not fail");
        if code != 0 {
            println!("--- probe failed (exit={code}) ---\nstdout: {out}\nstderr: {err}");
        }
        code == 0
    }

    /// `CreateWellKnownSid`でよく知られたSID（例`WinBuiltinAnyPackageSid`=ALL APPLICATION
    /// PACKAGES、S-1-15-2-1相当）を取得する。呼び出し側バッファ確保方式のため、
    /// `OwnedContainerSid`の`FreeSid`とも`ConvertStringSidToSidW`の`LocalFree`とも異なり
    /// **解放不要**（`Vec<u8>`がスコープを抜ければ自動で片付く、3系統目の解放パターン）。
    fn well_known_sid(
        sid_type: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
    ) -> windows::core::Result<Vec<u8>> {
        use windows::Win32::Security::CreateWellKnownSid;
        // SECURITY_MAX_SID_SIZEは68バイト（MSDN定義）。
        let mut buf = vec![0u8; 68];
        let mut size = buf.len() as u32;
        unsafe {
            CreateWellKnownSid(
                sid_type,
                PSID::default(),
                PSID(buf.as_mut_ptr() as *mut _),
                &mut size,
            )?;
        }
        buf.truncate(size as usize);
        Ok(buf)
    }

    /// Experiment D: `Remove-Item`アクセス拒否（experiment_cで発見）の追加ACE特定。
    /// `plans/TIER1A-OPEN-ISSUES.md`フェーズ3のブロッカーを解消するため、4つの仮説を
    /// 安価な順に試す。experiment_cと同じく`C:\`への単一traverse ACEを前提とし、
    /// grant〜revoke間はResultのみで構成する（panicしない、必ず原状復帰）。
    ///
    /// - H1: 継承ACEの伝播バグ説 — New-Item後のファイルへ直接・非継承でDELETEを再付与
    /// - H2: 親ディレクトリの`FILE_DELETE_CHILD`が要る説（教科書的なORが実際はAND）
    /// - H3: ALL APPLICATION PACKAGES（S-1-15-2-1）へのACEが要る説
    /// - H4: ALL RESTRICTED APPLICATION PACKAGES（S-1-15-2-2、ゼロcapability=LowBox
    ///   restricted判定に伴う二重チェック）が要る説
    #[test]
    #[ignore]
    fn experiment_d_delete_permission_probes() {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::WinBuiltinAnyPackageSid;

        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-d-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        let grant_result = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            // baseline: 何も追加せず、素朴なcreate+deleteが失敗することを確認する
            // （experiment_cの結果と一致するはずの対照）。
            let baseline_ok = run_probe_bool(
                sid.as_psid(),
                &workspace,
                "Remove-Item -LiteralPath 'baseline-probe.tmp' -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType File -Path 'baseline-probe.tmp' -Force | Out-Null; \
                 Remove-Item -LiteralPath 'baseline-probe.tmp' -Force",
            );
            println!("=== BASELINE (no extra ACE) create+delete succeeded = {baseline_ok} ===");

            // H1: 新規ファイルへ直接・非継承でDELETEを再付与してから削除を試みる。
            let h1_file = workspace.join("h1-probe.tmp");
            let h1_create_ok = run_probe_bool(
                sid.as_psid(),
                &workspace,
                "New-Item -ItemType File -Path 'h1-probe.tmp' -Force | Out-Null",
            );
            // 診断: 作成直後のファイルの実DACLを、管理者権限のRustテストプロセス自身から
            // icacls経由で観測する（継承ACEが本当に付いているかの直接証拠）。
            if h1_create_ok {
                let icacls_out = std::process::Command::new("icacls").arg(&h1_file).output();
                match icacls_out {
                    Ok(o) => println!(
                        "=== icacls on freshly-created h1-probe.tmp ===\n{}",
                        String::from_utf8_lossy(&o.stdout)
                    ),
                    Err(e) => println!("=== icacls failed to run: {e} ==="),
                }
            }
            let h1_ok = if h1_create_ok {
                let direct_grant =
                    grant_ace_mask(&h1_file, sid.as_psid(), DELETE.0, NO_INHERITANCE);
                println!("=== H1 direct-grant DELETE on file result: {direct_grant:?} ===");
                direct_grant.is_ok()
                    && run_probe_bool(
                        sid.as_psid(),
                        &workspace,
                        "Remove-Item -LiteralPath 'h1-probe.tmp' -Force",
                    )
            } else {
                println!("=== H1 skipped: could not even create the probe file ===");
                false
            };
            println!("=== H1 (direct non-inherited DELETE on file) succeeded = {h1_ok} ===");

            // H5: icacls出力で観測した`Mandatory Label\Low Mandatory Level:(NW)`が真因か
            // どうかを直接検証する。h1_fileがまだ存在する場合、管理者権限のRustプロセス
            // 自身から`icacls /setintegritylevel Medium`でMandatory LabelをMediumへ
            // 引き上げてから削除を試みる（DACLではなくMICが原因という仮説）。
            let h5_ok = if h1_create_ok && !h1_ok {
                let relabel = std::process::Command::new("icacls")
                    .arg(&h1_file)
                    .arg("/setintegritylevel")
                    .arg("Medium")
                    .output();
                match relabel {
                    Ok(o) if o.status.success() => {
                        println!(
                            "=== H5 icacls /setintegritylevel Medium succeeded: {} ===",
                            String::from_utf8_lossy(&o.stdout)
                        );
                        run_probe_bool(
                            sid.as_psid(),
                            &workspace,
                            "Remove-Item -LiteralPath 'h1-probe.tmp' -Force",
                        )
                    }
                    Ok(o) => {
                        println!(
                            "=== H5 icacls /setintegritylevel failed: stdout={} stderr={} ===",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        );
                        false
                    }
                    Err(e) => {
                        println!("=== H5 icacls could not run: {e} ===");
                        false
                    }
                }
            } else {
                println!("=== H5 skipped (H1 already succeeded or file missing) ===");
                false
            };
            println!("=== H5 (Mandatory Label raised to Medium) succeeded = {h5_ok} ===");

            // H2: 親ディレクトリへFILE_DELETE_CHILDを付与してからcreate+delete。
            let h2_grant = grant_ace_mask(
                &workspace,
                sid.as_psid(),
                windows::Win32::Storage::FileSystem::FILE_DELETE_CHILD.0,
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            );
            println!("=== H2 grant FILE_DELETE_CHILD on workspace result: {h2_grant:?} ===");
            let h2_ok = h2_grant.is_ok()
                && run_probe_bool(
                    sid.as_psid(),
                    &workspace,
                    "Remove-Item -LiteralPath 'h2-probe.tmp' -Force -ErrorAction SilentlyContinue; \
                     New-Item -ItemType File -Path 'h2-probe.tmp' -Force | Out-Null; \
                     Remove-Item -LiteralPath 'h2-probe.tmp' -Force",
                );
            println!("=== H2 (FILE_DELETE_CHILD on parent) succeeded = {h2_ok} ===");
            // H3以降の判定を汚染しないよう、H2で付与したACEを取り消す。
            let _ = revoke_ace(&workspace, sid.as_psid());
            let _ = grant_ace_recursive(&workspace, sid.as_psid());

            // H3: ALL APPLICATION PACKAGES (S-1-15-2-1) へ同マスクを付与。
            let h3_access = FILE_GENERIC_READ.0
                | FILE_GENERIC_WRITE.0
                | FILE_GENERIC_EXECUTE.0
                | DELETE.0
                | windows::Win32::Storage::FileSystem::FILE_DELETE_CHILD.0;
            let h3_ok = match well_known_sid(WinBuiltinAnyPackageSid) {
                Ok(buf) => {
                    let all_app_packages_sid = PSID(buf.as_ptr() as *mut _);
                    let h3_grant = grant_ace_mask(
                        &workspace,
                        all_app_packages_sid,
                        h3_access,
                        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                    );
                    println!("=== H3 grant on ALL APPLICATION PACKAGES result: {h3_grant:?} ===");
                    let ok = h3_grant.is_ok()
                        && run_probe_bool(
                            sid.as_psid(),
                            &workspace,
                            "Remove-Item -LiteralPath 'h3-probe.tmp' -Force -ErrorAction SilentlyContinue; \
                             New-Item -ItemType File -Path 'h3-probe.tmp' -Force | Out-Null; \
                             Remove-Item -LiteralPath 'h3-probe.tmp' -Force",
                        );
                    let _ = revoke_ace(&workspace, all_app_packages_sid);
                    ok
                }
                Err(e) => {
                    println!("=== H3 skipped: CreateWellKnownSid(WinBuiltinAnyPackageSid) failed: {e:?} ===");
                    false
                }
            };
            let _ = grant_ace_recursive(&workspace, sid.as_psid());
            println!("=== H3 (ALL APPLICATION PACKAGES) succeeded = {h3_ok} ===");

            // H4: ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2) へ同マスクを付与。
            let h4_ok = unsafe {
                let mut restricted_sid = PSID::default();
                let sid_str = wide("S-1-15-2-2");
                match ConvertStringSidToSidW(
                    windows::core::PCWSTR(sid_str.as_ptr()),
                    &mut restricted_sid,
                ) {
                    Ok(()) => {
                        let h4_grant = grant_ace_mask(
                            &workspace,
                            restricted_sid,
                            h3_access,
                            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                        );
                        println!("=== H4 grant on ALL RESTRICTED APPLICATION PACKAGES result: {h4_grant:?} ===");
                        let ok = h4_grant.is_ok()
                            && run_probe_bool(
                                sid.as_psid(),
                                &workspace,
                                "Remove-Item -LiteralPath 'h4-probe.tmp' -Force -ErrorAction SilentlyContinue; \
                                 New-Item -ItemType File -Path 'h4-probe.tmp' -Force | Out-Null; \
                                 Remove-Item -LiteralPath 'h4-probe.tmp' -Force",
                            );
                        let _ = revoke_ace(&workspace, restricted_sid);
                        let _ = LocalFree(HLOCAL(restricted_sid.0));
                        ok
                    }
                    Err(e) => {
                        println!(
                            "=== H4 skipped: ConvertStringSidToSidW(S-1-15-2-2) failed: {e:?} ==="
                        );
                        false
                    }
                }
            };
            println!("=== H4 (ALL RESTRICTED APPLICATION PACKAGES) succeeded = {h4_ok} ===");

            println!(
                "=== SUMMARY: baseline={baseline_ok} H1={h1_ok} H5={h5_ok} H2={h2_ok} H3={h3_ok} H4={h4_ok} ==="
            );
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ traverse ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// Experiment G: traverse ACE付与済み環境での網羅的なファイル操作マトリクス。
    /// `experiment_c`/`d`で判明したのは「preflightが使う4操作＋削除」という狭い範囲のみ
    /// だったため、`run_shell`の実運用で呼ばれうる操作（上書き・追記・コピー・リネーム・
    /// 移動・ディレクトリ作成/削除等）を一通り試し、削除以外にも失敗する操作が無いかを
    /// 確認する。新たな仮説検証ではなく、既知の状態（traverse ACE付与済み・削除拒否あり）
    /// を前提にした網羅的な現状把握。各操作は独立に試し、1つの失敗が他の判定を妨げないよう
    /// 前提ファイル/ディレクトリを都度作り直す。結果は
    /// `docs/phases/foundation/M12-shell-isolation-tiers.md`追記7に記録する。
    /// `experiment_g`/`experiment_j`が共有する(操作名, 準備コマンド, 試す操作)一覧。
    /// 準備コマンドは`-ErrorAction SilentlyContinue`で失敗を無視し、常にクリーンな前提から
    /// 試す。
    fn operation_matrix_cases() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "1. New-Item（ファイル作成）",
                "Remove-Item -LiteralPath 'f1.txt' -Force -ErrorAction SilentlyContinue",
                "New-Item -ItemType File -Path 'f1.txt' -Force | Out-Null",
            ),
            (
                "2. Get-Content（読取）",
                "Remove-Item -LiteralPath 'f2.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f2.txt' -Value 'seed'",
                "Get-Content -LiteralPath 'f2.txt' | Out-Null",
            ),
            (
                "3. Set-Content（上書き）",
                "Remove-Item -LiteralPath 'f3.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f3.txt' -Value 'seed'",
                "Set-Content -LiteralPath 'f3.txt' -Value 'overwritten'",
            ),
            (
                "4. Add-Content（追記）",
                "Remove-Item -LiteralPath 'f4.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f4.txt' -Value 'seed'",
                "Add-Content -LiteralPath 'f4.txt' -Value 'appended'",
            ),
            (
                "5. Copy-Item（コピー）",
                "Remove-Item -LiteralPath 'f5-src.txt','f5-dst.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f5-src.txt' -Value 'seed'",
                "Copy-Item -LiteralPath 'f5-src.txt' -Destination 'f5-dst.txt'",
            ),
            (
                "6. Rename-Item（ファイルリネーム）",
                "Remove-Item -LiteralPath 'f6-old.txt','f6-new.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f6-old.txt' -Value 'seed'",
                "Rename-Item -LiteralPath 'f6-old.txt' -NewName 'f6-new.txt'",
            ),
            (
                "7. Move-Item（サブディレクトリへ移動）",
                "Remove-Item -LiteralPath 'f7.txt' -Force -ErrorAction SilentlyContinue; \
                 Remove-Item -LiteralPath 'f7-dir' -Recurse -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f7.txt' -Value 'seed'; \
                 New-Item -ItemType Directory -Path 'f7-dir' -Force | Out-Null",
                "Move-Item -LiteralPath 'f7.txt' -Destination 'f7-dir\\f7.txt'",
            ),
            (
                "8. Remove-Item（ファイル削除）",
                "Remove-Item -LiteralPath 'f8.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f8.txt' -Value 'seed'",
                "Remove-Item -LiteralPath 'f8.txt' -Force",
            ),
            (
                "9. 読取専用属性を付けてから削除",
                "Remove-Item -LiteralPath 'f9.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f9.txt' -Value 'seed'; \
                 Set-ItemProperty -LiteralPath 'f9.txt' -Name IsReadOnly -Value $true",
                "Set-ItemProperty -LiteralPath 'f9.txt' -Name IsReadOnly -Value $false; \
                 Remove-Item -LiteralPath 'f9.txt' -Force",
            ),
            (
                "10. New-Item（ディレクトリ作成）",
                "Remove-Item -LiteralPath 'd10' -Recurse -Force -ErrorAction SilentlyContinue",
                "New-Item -ItemType Directory -Path 'd10' -Force | Out-Null",
            ),
            (
                "11. Get-ChildItem -Recurse（再帰列挙）",
                "Remove-Item -LiteralPath 'd11' -Recurse -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType Directory -Path 'd11\\nested' -Force | Out-Null; \
                 Set-Content -LiteralPath 'd11\\nested\\f.txt' -Value 'seed'",
                "Get-ChildItem -LiteralPath 'd11' -Recurse | Out-Null",
            ),
            (
                "12. Rename-Item（ディレクトリリネーム）",
                "Remove-Item -LiteralPath 'd12-old','d12-new' -Recurse -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType Directory -Path 'd12-old' -Force | Out-Null",
                "Rename-Item -LiteralPath 'd12-old' -NewName 'd12-new'",
            ),
            (
                "13. Remove-Item（空ディレクトリ削除）",
                "Remove-Item -LiteralPath 'd13' -Recurse -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType Directory -Path 'd13' -Force | Out-Null",
                "Remove-Item -LiteralPath 'd13' -Force",
            ),
            (
                "14. Remove-Item -Recurse（非空ディレクトリ削除）",
                "Remove-Item -LiteralPath 'd14' -Recurse -Force -ErrorAction SilentlyContinue; \
                 New-Item -ItemType Directory -Path 'd14' -Force | Out-Null; \
                 Set-Content -LiteralPath 'd14\\f.txt' -Value 'seed'",
                "Remove-Item -LiteralPath 'd14' -Recurse -Force",
            ),
            (
                "15. New-Item -ItemType SymbolicLink（対照、AppContainer外要因で失敗しうる）",
                "Remove-Item -LiteralPath 'f15-link','f15-target.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f15-target.txt' -Value 'seed'",
                "New-Item -ItemType SymbolicLink -Path 'f15-link' -Target 'f15-target.txt' | Out-Null",
            ),
            (
                "16. Test-Path（対照、失敗しないはず）",
                "Remove-Item -LiteralPath 'f16.txt' -Force -ErrorAction SilentlyContinue; \
                 Set-Content -LiteralPath 'f16.txt' -Value 'seed'",
                "if (-not (Test-Path -LiteralPath 'f16.txt')) { throw 'Test-Path returned false' }",
            ),
        ]
    }

    #[test]
    #[ignore]
    fn experiment_g_full_operation_matrix() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-g-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        let grant_result = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            let cases = operation_matrix_cases();
            let mut results = Vec::new();
            for (name, setup, action) in &cases {
                // 準備は成否を問わない（SilentlyContinueで無視、前提が整わなくても実験は続行）。
                let _ = run_probe_bool(sid.as_psid(), &workspace, setup);
                let ok = run_probe_bool(sid.as_psid(), &workspace, action);
                println!("--- {name}: {} ---", if ok { "OK" } else { "FAIL" });
                results.push((*name, ok));
            }

            println!("=== EXPERIMENT G SUMMARY (traverse ACE granted) ===");
            println!("| # | 操作 | 結果 |");
            println!("|---|---|---|");
            for (name, ok) in &results {
                println!("| {name} | {} |", if *ok { "✅ OK" } else { "❌ FAIL" });
            }
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ traverse ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// Experiment J: `experiment_g`の全16操作マトリクスを、H7（`experiment_i`）で判明した
    /// 修正マスク（`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`）で再検証する。`experiment_g`の
    /// 結果（削除/リネーム/移動系7件が失敗）が、修正後は全件成功に変わるかを確認する。
    #[test]
    #[ignore]
    fn experiment_j_full_operation_matrix_with_read_attributes() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-j-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        let access = windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0
            | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0;
        let grant_result = grant_ace_mask(&drive_root, sid.as_psid(), access, NO_INHERITANCE);
        println!("=== C:\\ traverse+read-attributes ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            let cases = operation_matrix_cases();
            let mut results = Vec::new();
            for (name, setup, action) in &cases {
                let _ = run_probe_bool(sid.as_psid(), &workspace, setup);
                let ok = run_probe_bool(sid.as_psid(), &workspace, action);
                println!("--- {name}: {} ---", if ok { "OK" } else { "FAIL" });
                results.push((*name, ok));
            }

            println!("=== EXPERIMENT J SUMMARY (traverse+read-attributes ACE granted) ===");
            println!("| # | 操作 | 結果 |");
            println!("|---|---|---|");
            for (name, ok) in &results {
                println!("| {name} | {} |", if *ok { "✅ OK" } else { "❌ FAIL" });
            }
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// Experiment K: 本番`smoke_test_spawn`（`preflight`が使う実際のプローブ、New-Item→
    /// Get-Content→Remove-Item→exit 0）を、H7の修正マスク（`FILE_TRAVERSE |
    /// FILE_READ_ATTRIBUTES`）で再検証する。`Ok(())`を返せば、フェーズ3（capability機構の
    /// 実機E2E）のブロッカーが解消したことの最終確認になる。
    #[test]
    #[ignore]
    fn experiment_k_smoke_test_spawn_with_read_attributes() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-k-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");
        let probe_dir = workspace
            .join(".harness")
            .join("sandbox")
            .join("Tier2a-tmp");
        std::fs::create_dir_all(&probe_dir)
            .expect("create probe dir (inherits ACE from workspace)");

        let access = windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0
            | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0;
        let grant_result = grant_ace_mask(&drive_root, sid.as_psid(), access, NO_INHERITANCE);
        println!("=== C:\\ traverse+read-attributes ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            let production_result = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir);
            println!("=== production probe (smoke_test_spawn) result: {production_result:?} ===");
            println!(
                "=== H7 FINAL CHECK: smoke_test_spawn succeeded = {} ===",
                production_result.is_ok()
            );
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// procmon実測調査（Tier2a廃止の根拠固め）で共有するプローブスクリプト。
    /// New-Item（対照・成功するはず）→Remove-Item→Rename-Item→Move-Itemを`Write-Output`
    /// マーカー付きで連続実行する。AppContainer内（`experiment_h_procmon_target`）と
    /// AppContainer外の対照（`experiment_h_procmon_control`）の両方から同一文字列を使う。
    const PROCMON_PROBE_SCRIPT: &str = "\
        Write-Output 'MARKER: before-create'; \
        New-Item -ItemType File -Path 'h.txt' -Force | Out-Null; \
        Write-Output 'MARKER: before-remove'; \
        try { Remove-Item -LiteralPath 'h.txt' -Force; Write-Output 'REMOVE OK' } catch { Write-Output \"REMOVE FAIL: $_\" }; \
        Write-Output 'MARKER: before-rename'; \
        New-Item -ItemType File -Path 'h2.txt' -Force | Out-Null; \
        try { Rename-Item -LiteralPath 'h2.txt' -NewName 'h2-renamed.txt'; Write-Output 'RENAME OK' } catch { Write-Output \"RENAME FAIL: $_\" }; \
        Write-Output 'MARKER: before-move'; \
        New-Item -ItemType Directory -Path 'hdir' -Force | Out-Null; \
        New-Item -ItemType File -Path 'h3.txt' -Force | Out-Null; \
        try { Move-Item -LiteralPath 'h3.txt' -Destination 'hdir\\h3.txt'; Write-Output 'MOVE OK' } catch { Write-Output \"MOVE FAIL: $_\" }; \
        Write-Output 'MARKER: done'";

    /// procmon実測対象（AppContainer内）。`C:\`へtraverse ACEを付与し、AppContainer子の
    /// 実PID（`GetProcessId`）を出力してからプローブスクリプトを実行する。procmonは
    /// このテストの実行前に別プロセスとして起動しておき（Bashツール側の手順）、このテストは
    /// 記録対象のイベントを発生させるだけで、procmonの制御そのものには関与しない。
    #[test]
    #[ignore]
    fn experiment_h_procmon_target() {
        use windows::Win32::System::Threading::GetProcessId;

        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-h-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        let grant_result = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            let (shell, _) = resolve_shell();
            let env = crate::secret_env::build_child_env();
            let child = spawn(
                &shell,
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    PROCMON_PROBE_SCRIPT,
                ],
                &workspace,
                &env,
                false,
                sid.as_psid(),
                NetworkCapability::Deny,
            )
            .expect("spawn should succeed");
            let pid = unsafe { GetProcessId(child.process) };
            println!("=== APPCONTAINER_CHILD_PID={pid} ===");
            let (out, err, code) = child
                .write_stdin_read_output_and_wait(None)
                .expect("pipe I/O should not fail");
            println!("=== experiment_h_procmon_target: exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}");
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ traverse ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// procmon対照（AppContainer無し）。同一のプローブスクリプトを、AppContainerを経由せず
    /// 管理者Rustプロセス自身の子として`std::process::Command`で直接実行する。
    /// `C:\`のtraverse ACEは不要（AppContainer外なので既定のNTFS権限で普通に動く）。
    #[test]
    #[ignore]
    fn experiment_h_procmon_control() {
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-h-control-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace)
            .expect("create control workspace under C:\\ (needs admin)");

        let (shell, _) = resolve_shell();
        let child = std::process::Command::new(&shell)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                PROCMON_PROBE_SCRIPT,
            ])
            .current_dir(&workspace)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("control spawn should succeed");
        println!("=== CONTROL_CHILD_PID={} ===", child.id());
        let output = child.wait_with_output().expect("control child should exit");
        println!(
            "=== experiment_h_procmon_control: exit={:?} ===\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// Experiment I: procmon実測（`experiment_h_procmon_target`）で判明した新仮説H7の検証。
    /// 削除/リネーム/移動の直前に`CreateFile "C:\" ACCESS DENIED`（`Desired Access: Read
    /// Attributes, Options: Open Reparse Point`）が観測されており、`grant_ace_mask`で
    /// `C:\`へ付与していたのが`FILE_TRAVERSE`のみ（`FILE_READ_ATTRIBUTES`を含まない）
    /// だったことが原因と推測される。`C:\`への付与マスクに`FILE_READ_ATTRIBUTES`を足すだけで
    /// 削除/リネーム/移動が回復するかを確認する。
    #[test]
    #[ignore]
    fn experiment_i_c_root_read_attributes() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-i-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        // H7: FILE_TRAVERSE単独ではなく、FILE_READ_ATTRIBUTESも合わせて付与する。
        let access = windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0
            | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0;
        let grant_result = grant_ace_mask(&drive_root, sid.as_psid(), access, NO_INHERITANCE);
        println!("=== C:\\ traverse+read-attributes ACE grant result: {grant_result:?} ===");

        if grant_result.is_ok() {
            let (shell, _) = resolve_shell();
            let env = crate::secret_env::build_child_env();
            let child = spawn(
                &shell,
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    PROCMON_PROBE_SCRIPT,
                ],
                &workspace,
                &env,
                false,
                sid.as_psid(),
                NetworkCapability::Deny,
            )
            .expect("spawn should succeed");
            let (out, err, code) = child
                .write_stdin_read_output_and_wait(None)
                .expect("pipe I/O should not fail");
            println!("=== experiment_i_c_root_read_attributes: exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}");

            println!(
                "=== H7 RESULT: REMOVE={} RENAME={} MOVE={} ===",
                out.contains("REMOVE OK"),
                out.contains("RENAME OK"),
                out.contains("MOVE OK"),
            );
        }

        let revoke_result = revoke_ace(&drive_root, sid.as_psid());
        println!("=== C:\\ ACE revoke result: {revoke_result:?} ===");
        revoke_result.expect("revert: revoke_ace on C:\\ must not fail silently (manual recovery: icacls C:\\ /remove:g <container-SID> if this panics)");

        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// 未解決事項2: 本番`smoke_test_spawn`（軽量・終了コードのみ判定）と、この診断モジュールの
    /// `run_probe`（詳細・stdout全文を観測するリッチ版）が、この機種で**同じ合否判定**になる
    /// ことを突き合わせる。両者が食い違う場合、本番プローブの判定精度に疑いが生じるため、
    /// `preflight`をこのままTier1自動降格の唯一の判断根拠として使ってよいかを再検討する必要が
    /// ある（`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）。
    #[test]
    #[ignore]
    fn parity_production_probe_matches_diagnostic_probe() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let dir = std::path::PathBuf::from(format!(
            "C:\\ProgramData\\harness-sandbox-diag\\{}-parity",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create neutral dir");
        grant_ace_recursive(&dir, sid.as_psid()).expect("grant_ace_recursive on neutral dir");

        let production_result = smoke_test_spawn(sid.as_psid(), &dir, &dir);
        println!("=== production probe (smoke_test_spawn) result: {production_result:?} ===");

        run_probe(sid.as_psid(), &dir);

        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            production_result.is_err(),
            "on this machine (no traverse ACE on drive root, non-admin), the production FS I/O \
             probe is expected to fail just like the diagnostic probe above; if it now succeeds \
             the drive-root traverse constraint may have changed and this assertion (and the \
             M12 追記3 findings) should be revisited"
        );
    }

    /// D-13（fs passthrough allowlist）実機E2E: 中立な外部ディレクトリ（workspace外、`grant_ace_recursive`
    /// 済みのworkspaceとは別ルート）へ、まずread-only ACEを付与して子プロセスから読取成功・書込拒否を
    /// 確認し、次にread-write ACEへ差し替えて書込成功を確認、最後に`revoke_ace_recursive`で
    /// 全ノードから撤収して`assert_no_sid_ace_recursive`が0件（`Ok(())`）を返すことを確認する
    /// （D3/D4、`TIER1A-OPEN-ISSUES.md`項目4/6の実証）。`experiment_k`/`parity_production_probe_
    /// matches_diagnostic_probe`と同じく、workspace/外部ルートとも`C:\`直下の浅いパスを使う
    /// （`%TEMP%`のような深いパスは`C:\`祖先1本のtraverse ACE付与だけでは足りず、中間の各祖先
    /// ディレクトリにも個別のtraverse ACEが要るため、M12追記8の検証条件と揃えるのが目的）。
    /// ドライブルートのtraverse ACEが無い機種ではskipする。
    #[test]
    #[ignore]
    fn fs_passthrough_ro_then_rw_then_revoke_cycle() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        // workspace（FS I/Oのgate）とpassthrough対象（中立な外部ルート）は別ディレクトリにする。
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-passthrough-ws-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace).expect("create workspace");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on workspace");
        let probe_dir = workspace
            .join(".harness")
            .join("sandbox")
            .join("Tier2a-tmp");
        std::fs::create_dir_all(&probe_dir).expect("create probe dir");
        if let Err(e) = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir) {
            eprintln!(
                "skipping fs_passthrough_ro_then_rw_then_revoke_cycle: workspace FS I/O gate \
                 failed on this machine ({e:?}); run `harness fs grant-traverse C:\\` as \
                 administrator first (D10)"
            );
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }

        // 外部ルートも`C:\`直下（1階層）にする。`C:\ProgramData\...`のような多階層ネストは
        // 中間の祖先ディレクトリ（`ProgramData`等）にsandbox SID向けtraverse ACEが無く、
        // 別種の未解決問題になり得ることが実機検証で判明した（読取は成功するがrw書込がAccess
        // Deniedになる、`diagnose_unreachable_passthrough`のD9 fallback「cause unknown」経路が
        // 正しく効いた）。M12追記8が検証した「ドライブルート直下1階層」の条件に揃える。
        let external = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-passthrough-ext-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&external).expect("create neutral external dir");
        std::fs::write(external.join("existing.txt"), "pre-existing").expect("seed existing file");

        // 1. read-only付与 -> 読取成功・書込拒否。
        grant_ace_recursive_ro(&external, sid.as_psid()).expect("grant_ace_recursive_ro");
        let ro_probe = FsPassthrough {
            path: external.clone(),
            writable: false,
            forced: false,
        };
        let ro_diagnosis = probe_passthrough(sid.as_psid(), &workspace, &ro_probe);
        assert!(
            ro_diagnosis.is_none(),
            "read probe on read-only passthrough should succeed: {ro_diagnosis:?}"
        );
        let rw_probe_against_ro_grant = FsPassthrough {
            path: external.clone(),
            writable: true,
            forced: false,
        };
        let write_should_fail =
            probe_passthrough(sid.as_psid(), &workspace, &rw_probe_against_ro_grant);
        assert!(
            write_should_fail.is_some(),
            "write probe must fail while only read-only ACE is granted"
        );

        // 2. read-write付与 -> 書込成功。
        grant_ace_recursive(&external, sid.as_psid()).expect("grant_ace_recursive (rw)");
        let rw_probe = FsPassthrough {
            path: external.clone(),
            writable: true,
            forced: false,
        };
        let rw_diagnosis = probe_passthrough(sid.as_psid(), &workspace, &rw_probe);
        assert!(
            rw_diagnosis.is_none(),
            "write probe on read-write passthrough should succeed: {rw_diagnosis:?}"
        );

        // 3. 撤収 -> 再walkで0件（D4検証パス）。
        revoke_ace_recursive(&external, sid.as_psid()).expect("revoke_ace_recursive");
        let remaining = assert_no_sid_ace_recursive(&external, sid.as_psid());
        assert!(
            remaining.is_ok(),
            "sandbox SID ACE must be fully removed after revoke_ace_recursive: {remaining:?}"
        );

        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&external);
    }

    /// `grant_traverse_drive_root`/`revoke_ace`/`assert_no_sid_ace`（いずれも非再帰・単一ノード）の
    /// 往復を確認する（D10の巻き戻し、`harness fs revoke-traverse`本体）。実際のドライブルートは
    /// 対象にせず、テスト実行ユーザー自身が所有者である`tempfile::tempdir()`を対象にする
    /// （所有者は自分のオブジェクトのDACLを自由に変更できるため、`WRITE_DAC`が無い管理者専用の
    /// ドライブルートと違い管理者権限が不要。`docs/explanations/Tier2a-non-admin-limitation.md`
    /// 「なぜ非管理者ユーザーは自分で直せないのか」の所有者の話と対応する）。
    #[test]
    #[ignore]
    fn grant_traverse_then_revoke_traverse_on_neutral_dir() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let dir = tempfile::tempdir().expect("create neutral tempdir (test-user owned)");
        let path = dir.path().to_path_buf();

        grant_traverse_drive_root(&path, sid.as_psid()).expect("grant_traverse_drive_root");
        let mask = sid_ace_mask(&path, sid.as_psid()).expect("sid_ace_mask after grant");
        assert_eq!(
            mask,
            Some(FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0),
            "granted ACE mask must be exactly FILE_TRAVERSE | FILE_READ_ATTRIBUTES"
        );

        revoke_ace(&path, sid.as_psid()).expect("revoke_ace");
        let verified = assert_no_sid_ace(&path, sid.as_psid());
        assert!(
            verified.is_ok(),
            "sandbox SID ACE must be fully removed after revoke_ace: {verified:?}"
        );
    }

    /// `grant_traverse_chain`が祖先を浅い方(ドライブルート)から深い方(target自身)へ、
    /// 重複なく列挙することを確認する（Win32呼び出しを伴わない純粋なパス演算のみ、
    /// クロスプラットフォームで実行可能）。実際のACE付与成否は
    /// `grant_traverse_chain_then_revoke_each_node_on_neutral_tree`（ignore-gated）で確認する。
    #[test]
    fn grant_traverse_chain_orders_ancestors_shallow_to_deep() {
        let target = Path::new(r"C:\Users\example\.cargo");
        let mut chain: Vec<std::path::PathBuf> =
            target.ancestors().map(|p| p.to_path_buf()).collect();
        chain.reverse();
        assert_eq!(
            chain,
            vec![
                std::path::PathBuf::from(r"C:\"),
                std::path::PathBuf::from(r"C:\Users"),
                std::path::PathBuf::from(r"C:\Users\example"),
                std::path::PathBuf::from(r"C:\Users\example\.cargo"),
            ]
        );
    }

    /// `grant_traverse_chain`が多階層のネストしたディレクトリ全てへ個別にACEを付与し、
    /// `revoke_ace`で1件ずつ巻き戻せることを確認する（`TIER1A-OPEN-ISSUES.md`項目6
    /// 「多階層祖先traverse ACE不足」の解消の中核）。
    ///
    /// **[BUG-011の教訓、事故から得た設計]** 当初このテストは`tempfile::tempdir()`
    /// （`%TEMP%`配下）にネストを作っていたが、`%TEMP%`は実際には
    /// `C:\Users\<user>\AppData\Local\Temp\...`という**本物のユーザープロファイルの奥深く**に
    /// あるため、`grant_traverse_chain`が`Path::ancestors()`で祖先を辿ると、`C:\Users`・
    /// `C:\Users\<user>`（ユーザープロファイル本体）にまで実際のDACL変更が及んでしまい、
    /// 実機E2Eで「`C:\Users\<user>`へのDACL変更が数分単位で止まる」という重大インシデントを
    /// 起こした（実行中のプロファイルルートへのSetNamedSecurityInfoWは、ローミングプロファイル・
    /// インデクサ・AV等の割込みで極端に遅くなりうる。強制終了2回により孤立ACEが
    /// `C:\Users`・`C:\Users\<user>`に残置し、`icacls /remove:g`での手動復旧を要した）。
    ///
    /// 修正: 他のignore-gated実験（`experiment_c`等）と同じ`C:\harness-Tier2a-verify-*-<pid>`
    /// パターンを踏襲し、**このテスト専用に新規作成した`C:\`直下のディレクトリ**をネストの
    /// 起点にする。これなら`grant_traverse_chain`の祖先チェーンは`C:\`（既存の永続ACE、
    /// D10の恒久的な修復として意図的に維持されているためrevokeしない）とこのテスト専用ツリー
    /// のみで完結し、実プロファイルツリーには一切触れない。
    ///
    /// `C:\`自体への`WRITE_DAC`が要るため、このテストは`#[ignore]`に加えて**管理者シェルから
    /// の実行が必須**（`sudo cargo test -p harness-sandbox -- --ignored
    /// grant_traverse_chain_then_revoke_each_node_on_neutral_tree`）。
    #[test]
    #[ignore]
    fn grant_traverse_chain_then_revoke_each_node_on_neutral_tree() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let test_root = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-chain-{}",
            std::process::id()
        ));
        let nested = test_root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).expect(
            "create test-owned nested dirs directly under C:\\ (needs admin write on drive root)",
        );

        let (granted, result) = grant_traverse_chain(&nested, sid.as_psid());
        // 掃除は成否に関わらず必ず行う(孤立ACE防止、BUG-011の再発防止そのもの)。
        let cleanup = || {
            // granted[0]はドライブルート(C:\)自身。D10の恒久的な修復として意図的に維持されて
            // いる既存ACEなので、このテストの後始末では**絶対に触らない**。
            for node in granted.iter().skip(1) {
                let _ = revoke_ace(node, sid.as_psid());
            }
            let _ = std::fs::remove_dir_all(&test_root);
        };

        if let Err(e) = &result {
            cleanup();
            panic!("grant_traverse_chain should succeed on a test-owned tree under C:\\: {e:?}");
        }

        // test_root + a + b + c の4ノード(C:\自身は別途、既に前提として存在する)。
        if granted.len() != 5 {
            cleanup();
            panic!("expected 5 granted nodes (C:\\ + test_root + a + b + c), got {granted:?}");
        }
        if granted.last() != Some(&nested) {
            cleanup();
            panic!("last granted node must be the target itself: {granted:?}");
        }

        for node in &granted {
            match sid_ace_mask(node, sid.as_psid()) {
                Ok(mask) if mask == Some(FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0) => {}
                other => {
                    cleanup();
                    panic!(
                        "node {node:?} must have exactly FILE_TRAVERSE | FILE_READ_ATTRIBUTES, got {other:?}"
                    );
                }
            }
        }

        // ドライブルートを除く各ノードでrevoke -> 検証の往復を確認する。
        for node in granted.iter().skip(1) {
            if let Err(e) = revoke_ace(node, sid.as_psid()) {
                cleanup();
                panic!("revoke_ace for {node:?}: {e}");
            }
            if let Err(e) = assert_no_sid_ace(node, sid.as_psid()) {
                cleanup();
                panic!(
                    "sandbox SID ACE must be fully removed from {node:?} after revoke_ace: {e:?}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&test_root);
    }

    /// Experiment L（Phase B、`TIER1A-OPEN-ISSUES.md`項目6のMSVCツールチェーン対応の前段検証）:
    /// `grant_ace_recursive`直前のコメントは「継承フラグ（`CONTAINER_INHERIT_ACE |
    /// OBJECT_INHERIT_ACE`）はルートへのACE付与だけで新規作成される子孫には自動継承されるが、
    /// **付与時点で既に存在する子孫には遡って効かない**」と主張している。しかしWin32のACL継承は
    /// `SetNamedSecurityInfoW`によるDACL変更時にOS側で既存の子孫へも伝播しうるため、この主張が
    /// 実際に正しいかは実測で確かめる必要がある。もしルート1件への継承ありACEだけで既存の深い
    /// ファイルまで読めるなら、`grant_ace_recursive_ro`が行っている全ノード明示付与（MSVC
    /// ツールチェーンのような数GB規模のツリーでは非現実的な所要時間になりうる）を回避できる
    /// 可能性がある。
    ///
    /// 手順: (1) ACE付与より**前**に深いネスト＋既存ファイルを作る（「既存」子孫であることを
    /// 保証するため）。(2) ルート1件だけへ継承ありread-only ACEを付与し、AppContainer子から
    /// 深い既存ファイルの読取を試す。(3) 比較のため、同じ木を`grant_ace_recursive_ro`（全走査）
    /// で付与した場合の所要時間・成否も計測する。結果は`docs/phases/foundation/
    /// M12-shell-isolation-tiers.md`追記13へ数値付きで記録する。
    #[test]
    #[ignore]
    fn experiment_l_inheritable_ace_on_root_vs_recursive_walk() {
        let drive_root = std::path::PathBuf::from("C:\\");
        let root = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-l-{}",
            std::process::id()
        ));
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-l-ws-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        // workspace: spawn実行のための通常のフルアクセス（既存preflightと同じ手順）。
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid())
            .expect("grant_ace_recursive on verify workspace");

        // C:\ 自体へのtraverse ACE（この開発機では既に恒久的に付与済みの可能性が高いが、
        // 実験の独立性のため明示的に確認・付与する。既に付与済みならErrにならず上書きで成功する）。
        let drive_grant = grant_ace_mask(
            &drive_root,
            sid.as_psid(),
            FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
            NO_INHERITANCE,
        );
        println!("=== C:\\ traverse ACE grant result (may already exist): {drive_grant:?} ===");

        // 深いネスト+既存ファイルを、どちらのACE付与よりも前に作る（「既存」子孫であることの保証）。
        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).expect("create nested dirs under passthrough root");
        let deep_file = nested.join("preexisting.txt");
        std::fs::write(&deep_file, b"hello from before any ACE grant")
            .expect("create pre-existing deep file");
        let read_command = format!(
            "Get-Content -LiteralPath '{}' | Out-Null",
            deep_file.display()
        );

        // --- ケース1: ルート1件のみ、継承ありread-only ACE（全走査を回避できるか） ---
        let t0 = std::time::Instant::now();
        let inheritable_grant = grant_ace_ro(&root, sid.as_psid(), true);
        let inheritable_grant_elapsed = t0.elapsed();
        println!("=== EXPERIMENT L case 1 grant result: {inheritable_grant:?} (took {inheritable_grant_elapsed:?}) ===");
        let inheritable_read_ok =
            inheritable_grant.is_ok() && run_probe_bool(sid.as_psid(), &workspace, &read_command);
        println!(
            "=== EXPERIMENT L case 1: root-only inheritable ACE -> deep pre-existing file read: {} ===",
            if inheritable_read_ok { "OK" } else { "FAIL" }
        );
        // 後始末（ケース2へ進む前にルート1件分を剥がす。全走査していないので単一ノードrevokeでよい）。
        let _ = revoke_ace(&root, sid.as_psid());

        // --- ケース2（比較用）: 全ノード明示付与 ---
        let t1 = std::time::Instant::now();
        let recursive_grant = grant_ace_recursive_ro(&root, sid.as_psid());
        let recursive_grant_elapsed = t1.elapsed();
        println!("=== EXPERIMENT L case 2 grant result: {recursive_grant:?} (took {recursive_grant_elapsed:?}) ===");
        let recursive_read_ok =
            recursive_grant.is_ok() && run_probe_bool(sid.as_psid(), &workspace, &read_command);
        println!(
            "=== EXPERIMENT L case 2: full recursive walk -> deep pre-existing file read: {} ===",
            if recursive_read_ok { "OK" } else { "FAIL" }
        );

        println!(
            "=== EXPERIMENT L SUMMARY: inheritable-only read={inheritable_read_ok} (grant {inheritable_grant_elapsed:?}), \
             recursive-walk read={recursive_read_ok} (grant {recursive_grant_elapsed:?}) ==="
        );

        let _ = revoke_ace_recursive(&root, sid.as_psid());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// `TIER1A-OPEN-ISSUES.md`項目6の残課題（MSVCリンク工程`link.exe`の
    /// `STATUS_DLL_INIT_FAILED`）の最小切り分け実験。この開発機のACL調査（`Get-Acl`実測）で、
    /// `C:\Program Files (x86)\Microsoft Visual Studio\...\bin\Hostx64\x64`（`link.exe`本体と
    /// その依存DLLが全て同居するディレクトリ）まで、経路上の全ノードに元々
    /// `APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES`への`ReadAndExecute`が
    /// Windows既定で付いていることが判明した。AppContainerトークンは常にこのウェルノウンSIDを
    /// 暗黙にグループとして持つため、harness自身の狭いコンテナSIDへ個別ACEを追加しなくても
    /// このパスは`--fs-allow`無しで既に読み取り+実行可能なはずである（`grant-traverse`は
    /// `C:\`自体にはこのACEが無いため、`C:\`のみ狭いSIDでの付与が別途必要——これは
    /// `harness fs grant-traverse`で事前に付与済みという前提）。この実験は`--fs-allow`を
    /// 一切使わず、`link.exe`を直接起動して`STATUS_DLL_INIT_FAILED`が再現するかどうかだけを見る。
    #[test]
    #[ignore]
    fn experiment_m_link_exe_dll_load_via_all_app_packages_default() {
        let link_dir = std::path::PathBuf::from(
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64",
        );
        let link_exe = link_dir.join("link.exe");
        assert!(
            link_exe.is_file(),
            "link.exe not found at {}",
            link_exe.display()
        );

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        let env = crate::secret_env::build_child_env();

        let child = spawn(
            &link_exe.to_string_lossy(),
            &[],
            &link_dir,
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
        )
        .expect("spawn(link.exe) call itself should succeed (CreateProcessW returning a handle is separate from the loader later failing DLL init)");
        let (out, err, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("pipe I/O should not fail");
        println!(
            "=== EXPERIMENT M: link.exe exit code = {code} (0x{:08X}) ===",
            code as u32
        );
        println!("--- stdout ---\n{out}");
        println!("--- stderr ---\n{err}");
        println!(
            "=== EXPERIMENT M RESULT: STATUS_DLL_INIT_FAILED (0xC0000142) reproduced = {} ===",
            code as u32 == 0xC000_0142
        );
    }

    /// `TIER1A-PRIVHELPER-HANG.md` Phase 2 の直接計測（procmon裏取り用）。privhelperの
    /// `grant_traverse_chain`が実際に呼ぶのと**同じ**`grant_ace_mask`を、**同じマスク**
    /// （`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`）・**同じ`NO_INHERITANCE`**で、ハングが起きる
    /// ことが分かっている `%USERPROFILE%`（=実行中プロファイルルート、この開発機では
    /// `C:\Users\segfo`）の**単一ノード**へ直接1回だけ呼び、`Instant`で所要時間を計測する。
    /// IPC/UAC/privhelperを一切挟まないため、ハングの原因がOS側の`SetNamedSecurityInfoW`
    /// そのものにあるのか、それ以外（IPC機構）にあるのかを切り分けられる。
    ///
    /// **手順**: 管理者シェル（`WRITE_DAC`が要る）で
    /// `sudo cargo test -p harness-sandbox -- --ignored --exact --nocapture \
    ///  win_appcontainer::traverse_diagnostics::experiment_n_profile_root_direct_write_timing`
    /// を実行する。テストは最初に**自分のPIDを表示して標準入力待ちで一時停止**するので、その間に
    /// procmon（`tools/procmon/Procmon64.exe`）のフィルタをそのPIDに設定してから、Enterを押して
    /// 計測を開始する。**途中でkillしないこと**（有限で遅いだけなのか本当に返らないのかを、
    /// procmonの流れとともに観測するのが目的。`TIER1A-PRIVHELPER-HANG.md`の
    /// 「手動killを裏取りにしない」教訓）。
    ///
    /// **NO_INHERITANCEの含意**: 継承なしACEなので、本来この書込みは子孫へ伝播せず、対象1ノードの
    /// DACL差し替えだけで完了するはず。それでも遅い/返らない場合、procmonで「実際には
    /// プロファイル配下を舐めている」「特定のファイル/レジストリで停滞している」「AV・検索
    /// インデクサ・プロファイルサービスの割込み」等のどれなのかが見える。
    ///
    /// 計測後は同じ単一ノードを`revoke_ace`で戻し、`sid_ace_mask`で消えたことを確認する
    /// （新規に書けてしまった場合の後始末。`/T`のような再帰は一切使わない）。
    #[test]
    #[ignore]
    fn experiment_n_profile_root_direct_write_timing() {
        use std::io::Write;

        let profile = std::env::var("USERPROFILE")
            .expect("USERPROFILE must be set (this experiment targets the running profile root)");
        let target = std::path::PathBuf::from(&profile);
        assert!(
            target.is_dir(),
            "profile root {} is not a directory",
            target.display()
        );

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        // 事前状態: 対象に当該SIDのACEが無いこと（あると冪等スキップされ計測にならない）を確認。
        let before = sid_ace_mask(&target, sid.as_psid());
        println!("=== EXPERIMENT N: target = {} ===", target.display());
        println!(
            "=== EXPERIMENT N: pre-existing sandbox-SID ACE mask = {before:?} (None が理想) ==="
        );
        println!(
            "=== EXPERIMENT N: THIS PROCESS PID = {} ===",
            std::process::id()
        );
        println!(
            "=== EXPERIMENT N: set the procmon filter to PID {} now, then press Enter to start the \
             timed SetNamedSecurityInfoW write (DO NOT kill this process partway) ===",
            std::process::id()
        );
        let _ = std::io::stdout().flush();
        let mut _line = String::new();
        let _ = std::io::stdin().read_line(&mut _line);

        println!("=== EXPERIMENT N: starting grant_ace_mask(NO_INHERITANCE) now ===");
        let _ = std::io::stdout().flush();
        let t0 = std::time::Instant::now();
        let result = grant_ace_mask(
            &target,
            sid.as_psid(),
            FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
            NO_INHERITANCE,
        );
        let elapsed = t0.elapsed();
        println!(
            "=== EXPERIMENT N: grant_ace_mask returned in {elapsed:?}, result = {result:?} ==="
        );

        // 後始末: 新規に書けたぶんの単一ノードだけを戻す（既に他経路が依存している祖先ではなく
        // プロファイルルート単体なので単一ノードrevokeでよい。`/T`は使わない）。
        if result.is_ok() {
            let revoke = revoke_ace(&target, sid.as_psid());
            let after = sid_ace_mask(&target, sid.as_psid());
            println!(
                "=== EXPERIMENT N: cleanup revoke_ace result = {revoke:?}, post-revoke ACE mask = {after:?} (None が理想) ==="
            );
        } else {
            println!("=== EXPERIMENT N: grant failed, nothing to clean up ===");
        }
    }

    /// `TIER1A-PRIVHELPER-HANG.md` Phase 2-6 の**中立パス対照実験**。`experiment_n`と全く同じ
    /// AppContainer-SID・同じマスク（`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`）・同じ`NO_INHERITANCE`で、
    /// ただし対象を**プロファイルツリーの外**（`C:\`直下の新規test所有ディレクトリ
    /// `C:\harness-acltest-<pid>`）にした版。`experiment_n`（プロファイルルート`C:\Users\segfo`）が
    /// 30秒周期でハングした（`SetSecurityFile`書込みIRP未発行、`userenv`/`profext`/`profapi`/
    /// `FirewallAPI`ロード）のに対し、こちらが**速く完走すれば**ハングは**プロファイルルート固有**
    /// （User Profile Service関与）と切り分けられ、Phase 3の「プロファイルルート回避」策が有効になる。
    /// 逆に**同様にハングすれば**AppContainer-SID解決一般（ファイアウォール/LSA関与、パス非依存）
    /// であり、回避では済まない。
    ///
    /// `%TEMP%`/`tempfile`は使わない（BUG-011: それらは実プロファイル奥深くに作られ、対照にならない）。
    /// `C:\`直下の専用ディレクトリを直接作る（管理者権限が要る、他のignore-gated実験と同じパターン）。
    ///
    /// 手順・procmon連携は`experiment_n`と同じ（PID表示→stdin待ち→Enterで計測開始、途中killしない）。
    #[test]
    #[ignore]
    fn experiment_o_neutral_path_direct_write_timing() {
        use std::io::Write;

        let target =
            std::path::PathBuf::from(format!("C:\\harness-acltest-{}", std::process::id()));
        std::fs::create_dir_all(&target)
            .expect("create test-owned dir directly under C:\\ (needs admin write on drive root)");

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        let before = sid_ace_mask(&target, sid.as_psid());
        println!(
            "=== EXPERIMENT O (neutral control): target = {} ===",
            target.display()
        );
        println!(
            "=== EXPERIMENT O: pre-existing sandbox-SID ACE mask = {before:?} (None が理想) ==="
        );
        println!(
            "=== EXPERIMENT O: THIS PROCESS PID = {} ===",
            std::process::id()
        );
        println!(
            "=== EXPERIMENT O: set the procmon filter to PID {} now, then press Enter to start the \
             timed SetNamedSecurityInfoW write (DO NOT kill this process partway) ===",
            std::process::id()
        );
        let _ = std::io::stdout().flush();
        let mut _line = String::new();
        let _ = std::io::stdin().read_line(&mut _line);

        println!("=== EXPERIMENT O: starting grant_ace_mask(NO_INHERITANCE) now ===");
        let _ = std::io::stdout().flush();
        let t0 = std::time::Instant::now();
        let result = grant_ace_mask(
            &target,
            sid.as_psid(),
            FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
            NO_INHERITANCE,
        );
        let elapsed = t0.elapsed();
        println!(
            "=== EXPERIMENT O: grant_ace_mask returned in {elapsed:?}, result = {result:?} ==="
        );

        // 後始末: ACEを剥がし、test所有ディレクトリごと削除する。
        let _ = revoke_ace(&target, sid.as_psid());
        let _ = std::fs::remove_dir_all(&target);
        println!("=== EXPERIMENT O: cleaned up {} ===", target.display());
    }

    /// `path`のDACLに`PROTECTED_DACL_SECURITY_INFORMATION`を立て、祖先からの継承ACEが
    /// このノード配下へ伝播するのを遮断する。**このとき`path`が現在実効的に持つ全ACE
    /// （継承由来含む）を`GetExplicitEntriesFromAclW`で吸い出し、明示ACEとして保持し直す**
    /// ため、Administrators/自分自身等の既存アクセスは失われない（0 ACEにはしない）。
    ///
    /// 当初の実装は`GetExplicitEntriesFromAclW`で現在のACEを吸い出してから`SetEntriesInAclW`で
    /// 組み直す方式だったが、`GetExplicitEntriesFromAclW`は**継承フラグ（`INHERITED_ACE`）が
    /// 立ったACEを一切拾わない**（名前どおり「明示」ACEのみが対象）ため、対象ディレクトリの
    /// ACEが全て継承由来（新規作成した子ディレクトリの典型）の場合は`count=0`になり、
    /// `SetEntriesInAclW(&[], None, ...)`が`new_dacl=NULL`を返してしまう。`SetNamedSecurityInfoW`
    /// に`pDacl=NULL`を渡すと「DACLそのものが無い＝誰でもフルコントロール」という最も危険な
    /// 状態になり、`grant_ace_ro(root)`自体は成功するのに対象ディレクトリのアクセス制御が
    /// 消え去るという事故を招いた（実機の`icacls`出力`"アクセスが設定されていません。すべての
    /// ユーザーがフル コントロールを保持しています。"`で発覚）。
    ///
    /// 修正: ACEを個別に吸い出して再構築する必要は無い。`GetNamedSecurityInfoW`が返す
    /// `existing_dacl`は、継承由来かどうかを問わず**今この瞬間に有効な全ACEが物理的に
    /// 格納された実体**（NTFSは継承ACEを都度計算せず子オブジェクトへ都度複製して保持する）
    /// なので、そのポインタをそのまま`PROTECTED_DACL_SECURITY_INFORMATION`付きで書き戻すだけで
    /// 「今の実効アクセスを凍結しつつ、以後の祖先からの継承だけを遮断する」が実現できる
    /// （`.NET`の`SetAccessRuleProtection(true, true)`が内部で行うのと同じ操作）。
    fn protect_dacl_preserve_inherited(path: &Path) -> windows::core::Result<()> {
        use windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
        unsafe {
            let path_w = wide(&path.to_string_lossy());
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
            .ok()?;

            let result = windows::Win32::Security::Authorization::SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(existing_dacl as *const _),
                None,
            )
            .ok();

            let _ = LocalFree(HLOCAL(sd.0));
            result
        }
    }

    /// Phase B-2の本実装（`grant_ace_inheritable_ro`）の実機検証。experiment_lは継承ONの
    /// 単純ツリー1本しか検証しておらず、「保護DACL（継承を無効にした）子が混在するツリーでも
    /// 全ノードへ読取が届くか」は未確認だった。このテストは(1)通常の子孫（継承伝播で届く）と
    /// (2)`protect_dacl_preserve_inherited`で継承のみ意図的に遮断した子孫（既存の実効アクセスは
    /// 保持したまま、フォールバックの明示付与が要る）を同じツリーに混在させ、
    /// `grant_ace_inheritable_ro`が両方を読めるようにし、かつ`revoke_ace_recursive`で完全に
    /// 撤収できることを確認する。
    #[test]
    #[ignore]
    fn grant_ace_inheritable_ro_falls_back_for_protected_descendant() {
        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-m-ws-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace).expect("create workspace");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on workspace");
        let probe_dir = workspace
            .join(".harness")
            .join("sandbox")
            .join("Tier2a-tmp");
        std::fs::create_dir_all(&probe_dir).expect("create probe dir");
        if let Err(e) = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir) {
            eprintln!(
                "skipping grant_ace_inheritable_ro_falls_back_for_protected_descendant: \
                 workspace FS I/O gate failed on this machine ({e:?}); run `harness fs \
                 grant-traverse C:\\` as administrator first (D10)"
            );
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }

        let root = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-m-{}",
            std::process::id()
        ));

        // 通常branch: root -> normal -> deep -> preexisting.txt（継承伝播で届く想定）。
        let normal_deep = root.join("normal").join("deep");
        std::fs::create_dir_all(&normal_deep).expect("create normal branch");
        let normal_file = normal_deep.join("preexisting.txt");
        std::fs::write(&normal_file, b"reachable via inheritance").expect("seed normal file");

        // 保護branch: root -> protected（既存アクセスは保持したまま継承のみ遮断）-> deep -> blocked.txt。
        let protected_dir = root.join("protected");
        let protected_deep = protected_dir.join("deep");
        std::fs::create_dir_all(&protected_deep).expect("create protected branch");
        let protected_file = protected_deep.join("blocked.txt");
        std::fs::write(&protected_file, b"needs fallback explicit grant")
            .expect("seed protected file");
        protect_dacl_preserve_inherited(&protected_dir)
            .expect("protect_dacl_preserve_inherited on protected dir");

        let grant_result = grant_ace_inheritable_ro(&root, sid.as_psid());
        assert!(
            grant_result.is_ok(),
            "grant_ace_inheritable_ro should succeed on a tree with a protected-DACL child: \
             {grant_result:?}"
        );

        let normal_read_ok = run_probe_bool(
            sid.as_psid(),
            &workspace,
            &format!(
                "Get-Content -LiteralPath '{}' | Out-Null",
                normal_file.display()
            ),
        );
        assert!(
            normal_read_ok,
            "normal branch (reached via inheritance propagation) must be readable"
        );

        let protected_read_ok = run_probe_bool(
            sid.as_psid(),
            &workspace,
            &format!(
                "Get-Content -LiteralPath '{}' | Out-Null",
                protected_file.display()
            ),
        );
        assert!(
            protected_read_ok,
            "protected-DACL branch must be readable via the fallback explicit grant"
        );

        // 完全撤収の確認（D4）。保護フラグ自体は残るが、sid ACEは全ノードから消えるべき。
        revoke_ace_recursive(&root, sid.as_psid()).expect("revoke_ace_recursive");
        let leftover = assert_no_sid_ace_recursive(&root, sid.as_psid());
        assert!(
            leftover.is_ok(),
            "sandbox SID ACE must be fully removed from every node, including the protected \
             branch, after revoke_ace_recursive: {leftover:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    /// [S1スパイク] Tier3のSMB使い捨てワークスペース共有（`crates/harness-sandbox/src/
    /// smb_share.rs`、未コミット作業中）が使い捨てローカルアカウントへNTFSアクセス権を
    /// 付与する手段として`grant_ace_inheritable_rw`/`revoke_ace`を再利用できるかを検証する。
    /// AppContainer SID（`ensure_profile`）ではなく、実際に`New-LocalUser`で作る**通常の
    /// ローカルアカウント**のSIDに対して同じ関数が機能すること、および往復が体感1秒未満で
    /// 終わること（BUG-011の365,903件SetSecurityFile・93秒超という病的な遅さの再発防止、
    /// `grant_ace_mask`が単一オブジェクトAPI経由であることの実機確認）を確かめる。
    ///
    /// `grant_ace_inheritable_rw`自体はルートへの書込みは1回だが、既存子孫への読取確認
    /// walk（`sid_ace_mask`）はO(n)で残ることがdocに明記されている。ここでは(a)小さいツリー
    /// （数ファイル）と(b)実際のワークスペース規模に近いツリー（数百ファイル）の両方を計測し、
    /// どちらも実用的な時間で終わることを確認する。
    #[test]
    #[ignore]
    fn grant_and_revoke_inheritable_rw_for_a_real_local_user_account_is_fast() {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;

        let unique = std::process::id();
        let user = format!("hns3spike{unique}");
        let password = "Sp1ke!Test-Pw-Do-Not-Reuse";

        // 使い捨てローカルアカウントを作成し、SID文字列を取得する
        // （`smb_share.rs::create_ephemeral_share`が実運用でやるのと同じ形、stdin経由で
        // パスワードを渡しコマンドライン上に露出させない）。
        let create_script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
New-LocalUser -Name '{user}' -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
(Get-LocalUser -Name '{user}').SID.Value
"#
        );
        let sid_string = run_powershell_stdin_for_test(&create_script)
            .expect("New-LocalUser + SID lookup must succeed (run under sudo cargo test)");
        assert!(
            !sid_string.is_empty(),
            "expected a non-empty SID string from Get-LocalUser"
        );

        let cleanup_user = || {
            let _ = std::process::Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("Remove-LocalUser -Name '{user}' -ErrorAction SilentlyContinue"),
                ])
                .output();
        };

        let sid_owned = unsafe {
            let sid_w = crate::win_common::wide(&sid_string);
            let mut psid = PSID::default();
            ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid)
                .expect("ConvertStringSidToSidW must parse Get-LocalUser's SID string");
            psid
        };

        // `C:\`直下は既定でBUILTIN\Usersに読み取りが継承付与されていることが多く（使い捨て
        // ローカルアカウントもUsersグループのメンバー）、そこにツリーを置くと「読めた/読めなく
        // なった」がこちらの明示的な付与/取り消しではなく既定のUsers権限に起因するのか区別
        // できない（`/inheritance:r`で継承ACEを剥がす案も試したが、DACLが空になり自分自身の
        // 書込みまで拒否されて壊れた）。ユーザープロファイル配下（`%TEMP%`）はNTFS既定で
        // 所有者+SYSTEM+Administratorsのみに絞られておりBUILTIN\Usersへの既定付与が無いため、
        // ここにツリーを置くことで「読めるかどうかは完全にこちらの明示的な付与/取り消しに
        // 依存する」検証環境になる。
        let spike_base = std::env::temp_dir().join(format!("harness-tier3-spike-s1-{unique}"));

        // (a) 小さいツリー: ルート + 数階層のネストした既存ファイル数個。
        let small_root = spike_base.join("small");
        std::fs::create_dir_all(small_root.join("a").join("b")).expect("create small tree");
        std::fs::write(small_root.join("a").join("b").join("f.txt"), b"hi").expect("seed file");

        // (b) ワークスペース規模に近いツリー: 数百ファイル。
        let big_root = spike_base.join("big");
        for i in 0..20u32 {
            let dir = big_root.join(format!("dir{i}"));
            std::fs::create_dir_all(&dir).expect("create big tree dir");
            for j in 0..20u32 {
                std::fs::write(dir.join(format!("file{j}.txt")), b"payload")
                    .expect("seed big tree file");
            }
        }

        let cleanup_trees = || {
            let _ = std::fs::remove_dir_all(&spike_base);
        };

        // [BUG-020回帰テスト] `small_root/a/b`（ネストしたディレクトリ、必ずしも継承ACEの
        // 直接付与先=rootではない方）のDACLを、grant/revokeサイクルの前後で比較する。
        // 旧実装は`revoke_ace_recursive`が全ノードを`PROTECTED_DACL_SECURITY_INFORMATION`で
        // 恒久的に凍結してしまい、%TEMP%祖先から継承していたSYSTEM/Administrators/所有者の
        // `(I)`フラグが失われた状態のまま戻らなかった（BUG-020）。ここでは`icacls`の生出力
        // （`(I)`フラグの有無を含む）をgrant前とrevoke後で完全一致させることで、この副作用が
        // 再発しないことを機械的に検証する。
        let nested_dir = small_root.join("a").join("b");
        let icacls_output = |path: &Path| -> String {
            std::process::Command::new("icacls")
                .arg(path)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default()
        };
        let baseline_icacls = icacls_output(&nested_dir);

        let result = (|| -> Result<(), String> {
            // ベースライン確認: 付与前は読めないこと（プロファイル配下の既定ACLで隔離されて
            // いることの確認、これが崩れていると以降のgrant/revoke確認が無意味になる）。
            let probe_target_pre = small_root.join("a").join("b").join("f.txt");
            let can_read_before_grant = run_as_local_user(
                &user,
                password,
                &format!(
                    "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                    probe_target_pre.display()
                ),
            );
            if can_read_before_grant {
                return Err(
                    "baseline check failed: the ephemeral local user could already read the \
                     file before any grant — %TEMP% is not isolated from BUILTIN\\Users on \
                     this machine, the rest of this test's conclusions would be meaningless"
                        .to_string(),
                );
            }

            let t0 = std::time::Instant::now();
            grant_ace_inheritable_rw(&small_root, sid_owned)
                .map_err(|e| format!("grant on small tree failed: {e:?}"))?;
            let small_grant_elapsed = t0.elapsed();
            println!(
                "=== S1: small tree grant_ace_inheritable_rw took {small_grant_elapsed:?} ==="
            );
            assert!(
                small_grant_elapsed < std::time::Duration::from_secs(2),
                "small-tree grant must finish well under 1-2s, took {small_grant_elapsed:?}"
            );

            let t1 = std::time::Instant::now();
            grant_ace_inheritable_rw(&big_root, sid_owned)
                .map_err(|e| format!("grant on big tree (400 files) failed: {e:?}"))?;
            let big_grant_elapsed = t1.elapsed();
            println!(
                "=== S1: 400-file tree grant_ace_inheritable_rw took {big_grant_elapsed:?} ==="
            );
            assert!(
                big_grant_elapsed < std::time::Duration::from_secs(5),
                "400-file tree grant must not regress toward BUG-011-style pathological slowness, \
                 took {big_grant_elapsed:?}"
            );

            // revokeもO(n)（物理コピーされたACEを個別に消す、上記コメント参照）であるため、
            // 400ファイル規模での実測値も取っておく（grant/revoke双方のO(n)係数を見るため）。
            let t_big_revoke = std::time::Instant::now();
            revoke_ace_recursive(&big_root, sid_owned)
                .map_err(|e| format!("revoke_ace_recursive on big tree failed: {e:?}"))?;
            let big_revoke_elapsed = t_big_revoke.elapsed();
            println!("=== S1: 400-file tree revoke_ace_recursive took {big_revoke_elapsed:?} ===");

            // 実際にそのローカルアカウントとしてファイルを読める/書けることを確認する
            // （ACEが付いているというだけでなく、実効アクセスとして機能することの確認）。
            let probe_target = small_root.join("a").join("b").join("f.txt");
            let can_read_after_grant =
                run_as_local_user(&user, password, &format!(
                    "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                    probe_target.display()
                ));
            assert!(
                can_read_after_grant,
                "the ephemeral local user must be able to read a pre-existing nested file \
                 after grant_ace_inheritable_rw (this is the actual SMB-share access scenario, \
                 not just ACE presence)"
            );

            let write_target = small_root.join("a").join("b").join("new-from-user.txt");
            let can_write_after_grant =
                run_as_local_user(&user, password, &format!(
                    "try {{ 'written' | Set-Content -LiteralPath '{}' -ErrorAction Stop; exit 0 }} catch {{ exit 1 }}",
                    write_target.display()
                ));
            assert!(
                can_write_after_grant,
                "the ephemeral local user must be able to write a new file under the \
                 inheritable-ACE root after grant_ace_inheritable_rw"
            );

            // [S1発見] `revoke_ace(root)`だけでは不十分だった: NTFSの継承ACEは親への参照
            // ではなく子オブジェクト作成時点で物理的に複製される実体（Phase B-2の知見どおり）
            // であるため、`grant_ace_inheritable_rw`のルート付与は実質的に全既存子孫へ物理コピー
            // を作る（だからこそgrant側はO(1)で済む）。revoke側はこの物理コピーを個別に消す
            // 必要があり、構造的にO(n)にならざるを得ない。`revoke_ace`（非再帰・単一ノード）を
            // 使った初回の実装は、rootのACEは消えても子孫の物理コピーが残るため`f.txt`が読める
            // ままという実機不具合を引き起こした（本テストで実際に検出・修正）。正しくは
            // `revoke_ace_recursive`（既存の再walk版）を使う。
            let t2 = std::time::Instant::now();
            revoke_ace_recursive(&small_root, sid_owned)
                .map_err(|e| format!("revoke_ace_recursive on small tree failed: {e:?}"))?;
            let revoke_elapsed = t2.elapsed();
            println!(
                "=== S1: revoke_ace_recursive (small tree, O(n) walk) took {revoke_elapsed:?} ==="
            );
            assert!(
                revoke_elapsed < std::time::Duration::from_secs(2),
                "revoke_ace_recursive on a small tree must still be fast, took {revoke_elapsed:?}"
            );

            if let Ok(out) = std::process::Command::new("icacls")
                .arg(&probe_target)
                .output()
            {
                println!(
                    "=== S1 DEBUG: icacls on {} after revoke_ace_recursive ===\n{}",
                    probe_target.display(),
                    String::from_utf8_lossy(&out.stdout)
                );
            }

            // [BUG-020回帰assert] grant前後でのDACL完全一致確認（`(I)`フラグの有無を含む）。
            // 一致しなければ、grant/revokeサイクルがこのノードの継承状態を恒久的に変えて
            // しまったことを意味する（`nested_dir`は`grant_ace_inheritable_rw`のroot自身では
            // なく、rootへの付与がNTFSの物理複製で遡及した既存の子孫ノード——BUG-020が
            // 実際に壊していたのはこちら側）。
            let post_revoke_icacls = icacls_output(&nested_dir);
            if post_revoke_icacls != baseline_icacls {
                return Err(format!(
                    "BUG-020 regression: DACL of {} does not match its pre-grant baseline after \
                     grant_ace_inheritable_rw + revoke_ace_recursive (inheritance was not fully \
                     restored)\n--- baseline ---\n{baseline_icacls}\n--- after revoke ---\n{post_revoke_icacls}",
                    nested_dir.display()
                ));
            }

            let can_read_after_revoke =
                run_as_local_user(&user, password, &format!(
                    "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                    probe_target.display()
                ));
            assert!(
                !can_read_after_revoke,
                "after revoke_ace, the ephemeral local user must no longer be able to read \
                 the file (proves the ACE was actually removed, not just the account deleted)"
            );

            Ok(())
        })();

        cleanup_trees();
        cleanup_user();
        result.expect("S1 spike must succeed end-to-end");
    }

    /// パスワードをコマンドライン上に晒さずstdin経由でPowerShellへ渡す
    /// （`smb_share.rs::run_powershell_stdin`と同じ規律をこのテストモジュールでも守る）。
    fn run_powershell_stdin_for_test(script: &str) -> Result<String, String> {
        use std::io::Write;
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
            // `vmsandbox::run_powershell`と同じ罠: 常駐管理者pwsh(7)から起動すると継承した
            // `PSModulePath`のせいで`Microsoft.PowerShell.Security`のオートロードが壊れ、
            // `ConvertTo-SecureString`が非終端エラーで静かに失敗する。
            .env_remove("PSModulePath")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn powershell.exe: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("powershell stdin unavailable")?
            .write_all(script.as_bytes())
            .map_err(|e| e.to_string())?;
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "exit={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// `Start-Process -Credential`でSMBの実効アクセスに近い形（実際のログオンセッション、
    /// AppContainerのspawnヘルパーとは別経路）で1コマンドを実行し、成功/失敗をbool化する。
    /// パスワードはstdin経由ではなく`-Credential`引数化のためこの関数内で組み立てるが、
    /// テスト専用の使い捨てパスワードのみを扱う（本番コード`smb_share.rs`はstdin経由を守る）。
    fn run_as_local_user(user: &str, password: &str, inner_command: &str) -> bool {
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user}', $securePassword)
$p = Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile','-NonInteractive','-Command','{inner}' -WindowStyle Hidden -PassThru -Wait -WorkingDirectory "$env:SystemRoot\Temp"
exit $p.ExitCode
"#,
            inner = inner_command.replace('\'', "''")
        );
        match std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .env_remove("PSModulePath")
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

/// `--force-system-acl`（D-19）の絶対拒否ゲート`is_force_grant_forbidden`の単体テスト。
/// 実FS書込やAdministrator権限を要さない（`canonicalize`と環境変数のみ）ため`#[ignore]`しない。
#[cfg(all(windows, test))]
mod force_grant_gate_tests {
    use super::is_force_grant_forbidden;
    use std::path::{Path, PathBuf};

    fn windir() -> PathBuf {
        std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("windir"))
            .map(PathBuf::from)
            .expect("SystemRoot/windir must be set on Windows")
    }

    #[test]
    fn drive_root_is_forbidden() {
        // canonicalize(C:\)は`\\?\C:\`になり通常成分を持たない=ドライブルート判定。
        let reason = is_force_grant_forbidden(Path::new("C:\\"));
        assert!(reason.is_some(), "drive root must be forbidden: {reason:?}");
    }

    #[test]
    fn windows_system_directory_is_forbidden() {
        let reason = is_force_grant_forbidden(&windir());
        assert!(
            reason.is_some(),
            "the Windows directory itself must be forbidden: {reason:?}"
        );
    }

    #[test]
    fn registry_hive_directory_is_forbidden() {
        let config = windir().join("System32").join("config");
        if !config.exists() {
            return; // 通常存在するが、無い機種ではスキップ（誤検知を避ける）。
        }
        let reason = is_force_grant_forbidden(&config);
        assert!(
            reason.is_some(),
            "System32\\config (registry hives) must be forbidden: {reason:?}"
        );
    }

    #[test]
    fn ordinary_temp_directory_is_allowed() {
        // %TEMP%配下の実在ディレクトリは`%SystemRoot%`外・非ドライブルートなので許可される。
        let dir = std::env::temp_dir();
        if !dir.exists() {
            return;
        }
        let reason = is_force_grant_forbidden(&dir);
        assert!(
            reason.is_none(),
            "an ordinary temp directory must be allowed, got: {reason:?}"
        );
    }

    #[test]
    fn nonexistent_path_is_forbidden_fail_safe() {
        // canonicalizeできないパスは安全側（拒否）に倒す。
        let bogus = windir().join("this-path-should-not-exist-harness-d19-test");
        let reason = is_force_grant_forbidden(&bogus);
        assert!(
            reason.is_some(),
            "a non-canonicalizable path must be refused (fail-safe): {reason:?}"
        );
    }
}
