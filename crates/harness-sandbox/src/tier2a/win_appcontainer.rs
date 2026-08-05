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
use std::path::{Path, PathBuf};

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
    CreateFileW, ReadFile, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, DeleteProcThreadAttributeList, GetCurrentProcess,
    GetExitCodeProcess, GetExitCodeThread, InitializeProcThreadAttributeList, OpenProcessToken,
    ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::shell_tier::{FsAccess, FsPassthrough, WorkspaceWriteMode};
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

/// harnessサンドボックスが共通で携えるcapabilityの名前（D-37）。
///
/// **祖先ディレクトリのtraverse ACEだけ**をこのcapability SID宛に付与する。package SIDが
/// セッションごとに変わっても、祖先への付与は一度きり（＝昇格も一度きり）で済ませるための
/// 逃がし方であり、実機で「capability無しの新package SIDは本番のFS I/O判定に失敗し、
/// capability有りなら成功する」ことを確認したうえで採っている。
///
/// **残存リスク**: capability SIDはトークンへ任意に積めるため、harness以外のプロセスが同じ
/// capability名でAppContainerを作れば同じ祖先をtraverseできる。ただし得られるのは通過と
/// 属性読み取りだけで、内容の読み取りには各パスのACEが別途要る（通常のユーザープロセスが
/// 既に持つ権限と同等）。
pub const TRAVERSE_CAPABILITY_NAME: &str = "harnessSandboxTraverse";

/// [`TRAVERSE_CAPABILITY_NAME`]から導出したcapability SID。祖先traverseの付与先であり、
/// 子プロセス起動時にトークンへ積む値でもある。
pub fn traverse_capability_sid() -> Result<crate::win_common::OwnedSid, AppContainerError> {
    use windows::Win32::Security::DeriveCapabilitySidsFromName;
    let name_w = wide(TRAVERSE_CAPABILITY_NAME);
    unsafe {
        let mut group_sids: *mut PSID = std::ptr::null_mut();
        let mut group_count = 0u32;
        let mut cap_sids: *mut PSID = std::ptr::null_mut();
        let mut cap_count = 0u32;
        DeriveCapabilitySidsFromName(
            PCWSTR(name_w.as_ptr()),
            &mut group_sids,
            &mut group_count,
            &mut cap_sids,
            &mut cap_count,
        )
        .map_err(|e| win32_err("DeriveCapabilitySidsFromName", e))?;

        let owned = if cap_sids.is_null() || cap_count == 0 {
            Err(AppContainerError::Win32(
                "DeriveCapabilitySidsFromName returned no capability SID".to_string(),
            ))
        } else {
            crate::win_common::OwnedSid::copy_from(*cap_sids)
                .map_err(|e| win32_err("CopySid(capability)", e))
        };

        // グループ・capability双方の配列と各要素を解放する（MSDN記載の解放規則）。
        for i in 0..group_count as usize {
            let _ = LocalFree(HLOCAL((*group_sids.add(i)).0 as *mut _));
        }
        let _ = LocalFree(HLOCAL(group_sids as *mut _));
        for i in 0..cap_count as usize {
            let _ = LocalFree(HLOCAL((*cap_sids.add(i)).0 as *mut _));
        }
        let _ = LocalFree(HLOCAL(cap_sids as *mut _));
        owned
    }
}

/// [`ensure_profile`]を直列化する名前付きmutex。
///
/// プロファイル（`CONTAINER_NAME`）はマシン/ユーザー全体で1つの共有資源で、作成と参照が
/// 同時に走ると`CreateAppContainerProfile`／`DeriveAppContainerSidFromAppContainerName`が
/// `E_UNEXPECTED`(0x8000FFFF)を返す（実測: 並列10回中2回失敗・直列10回中0回失敗、
/// [BUG-054](../../../docs/bugs/BUG-054.md)）。プロファイルはユーザー単位のレジストリハイブに
/// 保存されるため`Local\`名前空間で足りる（同一セッションなら非昇格の本体と昇格した
/// `harness-netfilterd`の双方から同じ名前で見える）。
const PROFILE_LOCK: &str = r"Local\harness-appcontainer-profile";

/// Win32呼び出しの失敗に**どのAPIか**を添える。`windows::core::Error`の`Display`は
/// HRESULTの汎用文言（「致命的なエラーです。」等）しか持たず、これだけでは調査が始められない。
fn win32_err(op: &str, e: windows::core::Error) -> AppContainerError {
    AppContainerError::Win32(format!("{op}: {e}"))
}

/// harness専用のAppContainerプロファイルを作成する（既に存在すれば既存SIDを取得するのみ、
/// capability再指定は不要で副作用が無い）。
///
/// 同一プロファイルへの並行アクセスは[`PROFILE_LOCK`]で直列化する。
pub fn ensure_profile(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
    crate::with_named_lock(PROFILE_LOCK, || ensure_profile_locked(name))
}

fn ensure_profile_locked(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
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
                let sid = DeriveAppContainerSidFromAppContainerName(PCWSTR(name_w.as_ptr()))
                    .map_err(|e| win32_err("DeriveAppContainerSidFromAppContainerName", e))?;
                Ok(OwnedContainerSid(sid))
            }
            Err(e) => Err(win32_err("CreateAppContainerProfile", e)),
        }
    }
}


// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則1/3） ---
//
// 分割線は「どのOS機構を触るか」で引いている。公開パス
// （`harness_sandbox::tier2a::win_appcontainer::preflight` 等）を変えないため、各モジュールの
// 公開項目はここでglob再エクスポートする。

mod acl_grant;
mod mcp_preflight;
mod preflight;
mod revoke;
mod spawn;
mod spawn_session;
mod traverse;

pub use acl_grant::*;
pub use mcp_preflight::*;
pub use preflight::*;
pub use revoke::*;
pub use spawn::*;
pub use spawn_session::*;
pub use traverse::*;

// --- テスト群（実Win32・実AppContainerを使う重い回帰テストのため別ファイル） ---
//
// いずれも`#[cfg(test)]`のまま子モジュールへ分割している。`tests/`（統合テスト）へ出すと
// `smoke_test_spawn`・`grant_ace_mask`・`sid_ace_mask`・`probe_passthrough`といった内部関数を
// `pub`にせざるを得ず、公開面を絞る方針と衝突するため（`docs/CODE-STRUCTURE-RULES.md`規則2/4）。

#[cfg(all(windows, test))]
mod ace_grant_revoke_tests;

#[cfg(all(windows, test))]
mod force_grant_gate_tests;

/// D9診断（`describe_passthrough_chain`）の純粋関数テスト。**実機も管理者権限も要らない**
/// ——祖先とleafでSIDの系統が違うこと（D-37、BUG-058）をここで固定する。
#[cfg(all(windows, test))]
mod passthrough_diagnosis_tests;

#[cfg(all(windows, test))]
mod cow_containment_tests;

/// MCPサーバ隔離（D-38）の実機E2E。`docs/STATUS.md`「MCPクライアント機構」残課題#3/#4。
#[cfg(all(windows, test))]
mod mcp_e2e_tests;

/// **診断テスト専用**の口。任意のマスク・継承指定でACEを付ける。
///
/// 本体の`grant_ace_mask`は`pub(crate)`のままにし、ここだけを`#[cfg(test)]`で開ける
/// ——「許可レベル×操作」の真理値表（`policy_learnd::etw::access_matrix_tests`）は
/// マスクを1ビット単位で制御する必要があるが、その自由度を製品コードの公開面へは出さない。
#[cfg(all(windows, test))]
pub(crate) fn grant_ace_mask_for_test(
    path: &std::path::Path,
    sid: windows::Win32::Security::PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
) -> Result<(), AppContainerError> {
    acl_grant::grant_ace_mask(path, sid, access, inheritance)
}
