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
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_NOT_ALL_ASSIGNED, ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LUID,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT,
    SE_KERNEL_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    AclSizeInformation, AddAce, AdjustTokenPrivileges, EqualSid, FreeSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, InitializeAcl, InitializeSecurityDescriptor,
    LookupPrivilegeValueW, SetKernelObjectSecurity, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION,
    ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE,
    LUID_AND_ATTRIBUTES, NO_INHERITANCE, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME,
    SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL,
    WRITE_DAC,
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
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    STARTUPINFOW,
};

use crate::shell_tier::{FsAccess, FsPassthrough, GrantScope, WorkspaceWriteMode};
use crate::tier2a::session_profile::ProfileOwner;
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
    /// [BUG-107] **他プロセスのセッションに属するプロファイルを作ろうとした。**
    ///
    /// 作成点のfail-closed。ここで作ると台帳エントリを持たないプロファイルになり、
    /// `plan_reclaim`が`grants_known: false`と判定して永久に回収を見送る。
    #[error(
        "refusing to create the AppContainer profile {name}: it belongs to session {owner}, not \
         this process ({mine}). Only the owning process may create its own session profile -- \
         others must derive the SID instead (win_appcontainer::derive_profile_sid), because a \
         profile created here would carry no ledger entry and could never be reclaimed \
         (docs/bugs/BUG-107.md)"
    )]
    ForeignSessionProfile {
        name: String,
        owner: String,
        mine: String,
    },
    /// [D-48] **走行中の他セッションがあるうちは祖先traverse ACEを剥がさない。**
    ///
    /// 文面が長いのは、拒否を無言にしないためである（D-48が問題視しているのは
    /// 「剥がす操作が無言で成功する」ことなので、拒否も「使用中です」で終わらせない）。
    /// **どのセッションが生きているかを名指しする**——名前が出れば「閉じる」という出口が
    /// その場で見えるので、`--force`のような逃がし弁を置かずに済む（2026-08-21の決定）。
    #[error(
        "refusing to revoke the traverse ACE on {path}: {} harness session(s) are still running \
         ({}). The ancestor traverse ACE belongs to a capability SID shared by every session \
         (D-37), so revoking it now would strip filesystem access from those running sandboxes -- \
         the kernel re-checks the ACL on every open, so it takes effect immediately. Close them \
         and run this again. There is deliberately no --force: the liveness marker is a kernel \
         mutex held for the owning process's lifetime, so it cannot go stale \
         (plans/DESIGN-SANDBOX-PRIVSEP.md D-48)",
        sessions.len(),
        sessions.join(", ")
    )]
    TraverseRevokeWhileSessionsLive {
        path: std::path::PathBuf,
        sessions: Vec<String>,
    },
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
    capability_sid_from_name(TRAVERSE_CAPABILITY_NAME)
}

/// このworkspace＋モードのFS付与の主体（D-54）。名前は
/// [`crate::tier2a::workspace_capability`]がworkspaceごとのランダム秘密から導出し、
/// マシンローカル台帳（`%APPDATA%\harness\config\`）に保存する。
///
/// **`workspace`はcanonicalize済みを渡すこと**（綴りが違うと別エントリ＝別主体になり、
/// 同じツリーへ2つの主体のACEを撒くことになる）。台帳へまだ無ければここで発行する。
pub fn workspace_capability_sid(
    workspace: &Path,
    mode: &str,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    let name = crate::tier2a::workspace_capability::ensure_capability_name(workspace, mode)
        .map_err(AppContainerError::Preflight)?;
    capability_sid_from_name(&name)
}

/// `--fs-allow`の**宣言1件**のFS付与の主体（§22.3）。
///
/// D-54がworkspaceツリーに対してやったことを、宣言されたパスに対して行う。以前この穴は
/// **セッションのpackage SID**宛だった——package SIDはAppContainer全体で共有されるので、
/// そのACEは同一セッションの**全ドメイン**に効いてしまい、per-domainのFS制御は原理的に
/// 作れなかった（§22.3）。
///
/// 主体は§22.2.0の導出鍵`(秘密, 畳み込み済みパス, access級)`から決まる。したがって
/// **同じ宣言をするドメインは何もしなくても同じSIDを共有し**、1つの宣言パスに載るACEは
/// access級の数（最大3本）で止まる（§22.3.3）。
///
/// **`workspace`はcanonicalize済みを渡すこと**（[`workspace_capability_sid`]と同じ理由）。
/// `declared_path`側の綴りは`declaration_key`が畳むので、呼び出し側で正規化しなくてよい。
///
/// **`access`は実際に付けるアクセスを渡すこと。** CoWでRO降格した場合は降格後の値である
/// ——導出に使った級と実際に書いたマスクがずれると、撤収側は別の主体を探しに行く。
pub fn fs_allow_capability_sid(
    workspace: &Path,
    declared_path: &Path,
    access: FsAccess,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    let name = crate::tier2a::workspace_capability::ensure_declaration_capability_name(
        workspace,
        declared_path,
        access.label(),
    )
    .map_err(AppContainerError::Preflight)?;
    capability_sid_from_name(&name)
}

/// `declared_path`宛に**既に発行済み**の宣言capability SIDを引く（発行はしない）。
///
/// 撤収側（`harness fs revoke <path>`・セッション終了時の自動撤収）が使う。
/// §22.2.1の doctrine どおり、ACLを列挙して主体を推定するのではなく**宣言から導出した
/// SIDを名指しで**剥がすための入口である（`revoke_subjects.rs`の分類器は使わない。
/// あちらはpackage SID専用で、capability SIDを混ぜないことが意図である）。
///
/// `workspace`が`Some`ならそのworkspaceが発行したものだけに絞る（絞らない側の注意は
/// [`crate::tier2a::workspace_capability::declaration_capability_names`]のdoc）。
pub fn fs_allow_capability_sids(
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<crate::win_common::OwnedSid> {
    crate::tier2a::workspace_capability::declaration_capability_names(declared_path, workspace)
        .iter()
        .filter_map(|name| capability_sid_from_name(name).ok())
        .collect()
}

/// CoW差分層（`--sandbox tier2a-cow`の`diff_layer_dir`）のACEを付ける先の access級。
///
/// **`grant_ace_inheritable_rw`が実際に書くマスクと同じ級でなければならない。** あちらは
/// `workspace_rwx_mask()`を書き、それは`fs_access_mask(FsAccess::ReadWriteExec)`と同値である
/// （`acl_grant`の`fs_access_mask`にその旨のコメントがある）。導出に使った級と実際に書いた
/// マスクがずれると、撤収側は**別の主体**を探しに行って何も剥がせない。
pub const COW_DIFF_LAYER_ACCESS: FsAccess = FsAccess::ReadWriteExec;

/// [§22.3.2] CoW差分層のFS付与の主体。**発行する側**（付与経路が使う）。
///
/// # なぜ差分層に専用の仕組みが要らないのか
///
/// 差分層はセッション専有なので、そこへ付ける許可もセッションと同じ寿命でよい。これは
/// 新しい概念を要さない——§22.2.0の導出鍵は`(秘密, 畳み込み済みパス, access級)`であり、
/// **差分層のパスにセッションIDが入っている以上、導出されるcapabilityも自動的にセッション固有に
/// なる**。「セッション限定capability」という別種のSIDを設計に足さないこと（§22.3.2）。
///
/// 実体は`--fs-allow`の宣言1件とまったく同じ扱いである（台帳の`declaration`欄に
/// 畳み込んだ差分層のパスが入る）。**新しい台帳もSIDの新種別も作らない。**
///
/// # 呼び出し元は4つあり、全員が同じ規則を共有していなければならない
///
/// | 何をする側 | どこ | 発行するか |
/// |---|---|---|
/// | 起動時に付ける | `win_appcontainer/preflight.rs`のCoW分岐 | **する**（この関数） |
/// | セッション切替・forkで付ける | `session_scope::prepare_cow_diff_layer` | **する**（この関数） |
/// | 子のトークンへ積む（製品） | `win_appcontainer/launch.rs` | しない（[`lookup_cow_diff_layer_capability_sid`]） |
/// | 子のトークンへ積む（実機テスト） | `win_appcontainer/test_support.rs` | しない（同上） |
///
/// ずれたときの症状は**「ACEは正しく付いているのに子から一切読めない」**で、`ACCESS_DENIED`は
/// 出るが原因はACL側ではなくトークン側にある——最も原因を追いにくい形である（`launch.rs`の
/// モジュールdocが同じことを言っている）。だから導出はこの2本だけが持つ。
///
/// **`workspace`はcanonicalize済みを渡すこと**（[`workspace_capability_sid`]と同じ理由。
/// `workspace_key`は大小・区切り・`\\?\`前置を畳むが、`..`や8.3短縮名は解かない）。
/// `diff_layer_dir`側の綴りは`declaration_key`が畳むので、呼び出し側で正規化しなくてよい。
pub fn cow_diff_layer_capability_sid(
    workspace: &Path,
    diff_layer_dir: &Path,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    let name = crate::tier2a::workspace_capability::ensure_declaration_capability_name(
        workspace,
        diff_layer_dir,
        COW_DIFF_LAYER_ACCESS.label(),
    )
    .map_err(AppContainerError::Preflight)?;
    capability_sid_from_name(&name)
}

/// [§22.3.2] CoW差分層の主体を**引くだけ**（発行しない）。子のトークンへ積む経路が使う。
///
/// [`cow_diff_layer_capability_sid`]との違いは発行の有無だけである。**積む側が発行してしまうと、
/// `preflight`を経ていない差分層に対して台帳エントリが増える**——「読むだけのつもりの呼び出しが
/// 作用を持つ」形で、`B-01`が名指ししている誤りそのものである（`test_support`が
/// workspace本体について`lookup_capability_name`を通しているのと同じ理由）。
///
/// まだ発行されていなければ`None`。呼び出し側は**積まない**——積めないことは
/// `ACCESS_DENIED`＝fail-closedで出るので、無言で広がる向きには倒れない。
/// **access級で絞って引く**（`declaration_capability_names`のようにパスだけで引かない）——
/// 積むべきなのは**付与に使ったのと同じ級の主体**ただ1つだからである。級を無視して引くと、
/// 同じ差分層へ別の級が発行されていた場合に宣言より広い主体を積むことになる。
pub fn lookup_cow_diff_layer_capability_sid(
    workspace: &Path,
    diff_layer_dir: &Path,
) -> Option<crate::win_common::OwnedSid> {
    let name = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
        workspace,
        diff_layer_dir,
        COW_DIFF_LAYER_ACCESS.label(),
    )?;
    capability_sid_from_name(&name).ok()
}

/// [§22.3.1] **昇格側が、受け取った秘密から自分で導出した名前**をSIDへ写す。
///
/// 名前は`declaration_capability_name`が`(秘密, 畳み込み済みパス, access級)`から作ったもので、
/// **IPCで名前やSIDを受け取っているのではない**（`privhelper`モジュールdocの「SIDはIPCで
/// 受け取らず、受信側が自ら導出する」を字義どおり保つ）。形の検証をここでも行うのは、
/// 呼び出し順を間違えて別種の名前が来たときに黙って通さないためである。
pub fn capability_sid_from_declaration_name(
    name: &str,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    if !crate::tier2a::workspace_capability::is_declaration_capability_name(name) {
        return Err(AppContainerError::Preflight(format!(
            "refusing to derive a SID from {name:?}: it is not a declaration capability name"
        )));
    }
    capability_sid_from_name(name)
}

/// 名前からcapability SIDを導出する（`DeriveCapabilitySidsFromName`）。
///
/// **名前を知っている者は誰でもこれを呼べる**（特権不要）。したがって、この関数で導出した
/// SID宛にACEを付けることは「その名前を知る者へその権限を与える」ことと同義であり、
/// 名前の推測しやすさがそのまま権限の境界になる（D-54、`workspace_capability`のdoc）。
fn capability_sid_from_name(name: &str) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    use windows::Win32::Security::DeriveCapabilitySidsFromName;
    let name_w = wide(name);
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
///
/// # 作れるのは「自分のもの」だけ（[BUG-107](../../../docs/bugs/BUG-107.md)）
///
/// 名前からトークンを取り出し（[`session_profile::token_of_profile`]。GCが所有者を決めるのと
/// **同じ関数**）、次の3通りに分ける。
///
/// | 名前 | 扱い |
/// |---|---|
/// | このプロセスのセッションのもの（`run_shell`用・MCP用の両方） | `begin_session()`で**記録してから**作る（B-01） |
/// | **他プロセス**のセッションのもの | `Err`。作らない |
/// | トークンを持たない名前（旧共有`harness.shell.sandbox`） | 従来どおり作る |
///
/// かつてここは「このセッションの名前と一致するときだけ`begin_session()`を呼ぶ」と書いてあった。
/// **その条件は同一プロセス内でしか成立しない** ——他プロセス（昇格した`harness-netfilterd`や
/// `harness-privhelper`）が親のセッション名で呼ぶと、一致しないので黙って素通りし、
/// **台帳エントリを持たないプロファイルだけがOSに残る**。`plan_reclaim`はそれを
/// `grants_known: false`と判定して永久に回収を見送るので、1実行ごとに1件積み上がっていた
/// （実測で確認。`cargo test`のたびに`harness-netfilterd.exe`の子が1件作っていた）。
///
/// 不変条件を「一致したら記録する」から**「一致しなければ作らせない」**へ裏返したのが上表で、
/// これで呼び出し側が増えても記録なしの作成経路が生えない（B-06）。他プロセスが要るのは
/// SIDの値だけなので、[`derive_profile_sid`]（副作用なし・名前からの決定的導出）を使う。
pub fn ensure_profile(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
    // [B-01] **このセッションのプロファイルを作るなら、先に台帳へ登録する。**
    //
    // `CreateAppContainerProfile`はOSに残る資源を作る。台帳エントリの無いプロファイルは
    // `plan_reclaim`が`grants_known: false`と判定して**永久に削除を見送る**——名前を消すと
    // SIDが逆引き不能になり、ACEが残っていた場合に二度と剥がせなくなるためである（BUG-101①）。
    // つまり「記録せずに作る」と、その1件は誰にも回収できないままマシンに残り続ける。
    // 実際この機には66件たまっていた（2026-08-12に手作業で回収）。
    //
    // [BUG-107] 所有者で3分岐する（関数docの表）。判定に使うのは`token_of_profile`——
    // **GCが「誰のものか」を決めるのと同じ関数**なので、作成側と回収側で所有者の定義がずれない。
    match crate::tier2a::session_profile::owner_of_profile(name) {
        // このプロセスのセッション（`run_shell`用でもMCP用でも）。記録してから作る。
        // `begin_session`は生存マーカー（名前付きmutex）も立てるので、作った瞬間から
        // 他プロセスのGCに「死んだセッションの残骸」と誤認されない。
        ProfileOwner::ThisSession => {
            crate::tier2a::session_profile::begin_session()
                .map_err(AppContainerError::Preflight)?;
        }
        // **他プロセスのセッション。作らない。** ここを通していたのがBUG-107の残っていた原因で、
        // 呼び出し側（昇格側のnetfilterd/privhelper）はSIDの値しか要らない。
        ProfileOwner::OtherSession(owner) => {
            return Err(AppContainerError::ForeignSessionProfile {
                name: name.to_string(),
                owner: owner.to_string(),
                mine: crate::tier2a::session_profile::session_token().to_string(),
            })
        }
        // トークンを持たない名前＝旧共有プロファイル（`CONTAINER_NAME`）。セッションを持たない
        // ので記録する相手も居ない。従来どおり作る。
        ProfileOwner::Unowned => {}
    }
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

/// プロファイル名からSIDを導出する。**[`ensure_profile`]と違い、存在しなければ作らない。**
///
/// SIDは名前のハッシュから決定的に導出される（`DeriveAppContainerSidFromAppContainerName`）ので、
/// 登録の有無に関わらず値は同じである。プロファイルが実在するかを問わない**撤収側**は、
/// 必ずこちらを使うこと。
///
/// # なぜ撤収が`ensure_profile`を呼んではいけないのか（[BUG-101](../../../docs/bugs/BUG-101.md)）
///
/// `ensure_profile`は`CreateAppContainerProfile`を呼ぶので、**削除済みのプロファイルを
/// 作り直す**。`harness fs revoke`は`revocable_profile_names()`（＝死んだセッションを含む）の
/// 全部に対してこれを呼んでいたため、**ACEを剥がしに行くコマンドがOSの資源を作っていた**。
/// 撤収は副作用を持たない操作でなければならない（B-01: 撤収は条件付き・作成は無条件、の逆型）。
pub fn derive_profile_sid(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
    unsafe {
        let name_w = wide(name);
        let sid = DeriveAppContainerSidFromAppContainerName(PCWSTR(name_w.as_ptr()))
            .map_err(|e| win32_err("DeriveAppContainerSidFromAppContainerName", e))?;
        Ok(OwnedContainerSid(sid))
    }
}

/// このプロセス（＝このセッション）がfs passthroughのACEを付与するときの**主体のSID文字列**。
///
/// [BUG-101] 付与した主体を台帳へ記録するため（`fs_passthrough_ledger::FsLedgerEntry::granted_sids`）に
/// 要る。記録するのは`preflight`の呼び出し元（`harness-cli`の`run_agent`とポリシーエディタの
/// パス2）だが、**主体を決めているのは`preflight`**なので、両者が同じ値を見ていることを
/// 保証する必要がある。
///
/// ここは`current_profile_name()`からの決定的な導出で、`preflight`が使う
/// `begin_session()`＋`ensure_profile()`と**同じ名前・同じ導出関数**を通る。ずれていないことは
/// `preflight`が実行時に検算する（B-05: コンパイラが守らない複製には実行時の検算を置く）。
/// 導出に失敗したら`None`——記録できなかったことを付与の失敗にはしない。
pub fn current_session_grant_sid() -> Option<String> {
    let name = crate::tier2a::session_profile::current_profile_name();
    let sid = derive_profile_sid(&name).ok()?;
    crate::win_common::sid_to_string(sid.as_psid()).ok()
}

// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則1/3） ---
//
// 分割線は「どのOS機構を触るか」で引いている。公開パス
// （`harness_sandbox::tier2a::win_appcontainer::preflight` 等）を変えないため、各モジュールの
// 公開項目はここでglob再エクスポートする。

mod acl_grant;
/// [残課題#32] **DACLを組んで書く低レベルの口**のうち、「M本のACEを1つのDACLへ畳んで
/// ノードあたり1回だけ書き、既存の子孫まで届かせる」側。`acl_grant`（何をどの主体へ許すかの
/// 決定）とは触るものが違うので分けてある。**globで出さない**——`propagate_merged_dacl`という
/// 名前は、それだけでは`set_dacl_propagating`との違いが分からないため。
mod acl_dacl_write;
/// 初回の救済walkを背景で回すジョブ（D-54）。**globではなく名前空間として公開する**
/// ——`start`/`progress`/`wait_until_done`という短い名前は、それだけでは何のジョブか
/// 分からないため（`grant_job::wait_until_done()`と書けば分かる）。
pub mod grant_job;
/// Tier2a子を起こすまでの前口上（主体の導出・背景walkの待ち・spawn）。`run_shell`と
/// ポリシーエディタのパス2が共有する（モジュールdoc参照）。
mod launch;
mod mcp_preflight;
/// fs passthrough付与の進捗（同期区間からUIへ届ける唯一の口、`grant_job`と同じ形）。
pub mod passthrough_progress;
mod preflight;
/// `preflight`が打つ実機プローブ（実際にAppContainer子を起こしてFS I/Oを試す層）。
/// 決定（どのプローブをどの順で打つか）は`preflight`が持ち、ここは観測だけを持つ。
mod preflight_probe;
mod revoke;
/// 撤収の主体のうち、**宣言（`--fs-allow`）から一意に導出できるもの**を決める層（§22.2.1）。
/// `revoke_subjects`（DACLに実在するpackage SIDを分類する）とは探し方が違うので分けている。
mod revoke_declarations;
/// 撤収の**主体**を決める層（[BUG-101](../../../docs/bugs/BUG-101.md)欠陥②）。
/// 「どのSIDのACEを剥がすか」を、名前から導出したSIDではなく**対象パスのDACLに実在するSID**
/// から決める。`revoke`（剥がし方）とは責務が別なので分けている。
mod revoke_subjects;
mod spawn;
mod spawn_session;
mod traverse;
/// [D-84] workspaceツリーへ配る**ACEの集合**（モード×主体×マスク）と、それを1回の書込で
/// 置く口。`acl_grant`（何をどの主体へ許すかの決定）から分けてあるのは、こちらが扱うのが
/// 「**どのcapability SID宛のACEを何本配るか**」という別の軸だからである
/// （`docs/CODE-STRUCTURE-RULES.md`規則3）。
mod workspace_aces;

pub use acl_grant::*;
pub use launch::*;
pub use mcp_preflight::*;
pub use preflight::*;
pub(crate) use preflight_probe::*;
pub use revoke::*;
pub use revoke_declarations::*;
pub use revoke_subjects::*;
pub use spawn::*;
pub use spawn_session::*;
pub use traverse::*;
pub use workspace_aces::*;

// --- テスト群（実Win32・実AppContainerを使う重い回帰テストのため別ファイル） ---
//
// いずれも`#[cfg(test)]`のまま子モジュールへ分割している。`tests/`（統合テスト）へ出すと
// `smoke_test_spawn`・`grant_ace_mask`・`sid_ace_mask`・`probe_passthrough`といった内部関数を
// `pub`にせざるを得ず、公開面を絞る方針と衝突するため（`docs/CODE-STRUCTURE-RULES.md`規則2/4）。

/// テスト用: **このセッションの**package SID（D-37）。
///
/// `preflight`を呼ぶ実機テストは必ずこれを使い、旧共有プロファイル`CONTAINER_NAME`を
/// 使ってはいけない。D-37でプロファイルはセッション単位になり、`preflight`がworkspace・
/// CoW 差分層・redirector DLLへACEを付ける先も、製品が子プロセスを起動するSID
/// （`harness-tools/src/shell.rs`）も、どちらもセッションSIDになった。テストだけが
/// `CONTAINER_NAME`のまま取り残されると、**`preflight`は正しくACEを付けるのに子はそのACEを
/// 持たない別のSIDで動く**——redirector DLLを読めず`LoadLibraryW`がNULLを返す。
/// これが`docs/STATUS.md`旧Tier2a残課題#7（CoW封じ込めE2E 16/17赤）の正体だった。
/// 製品の`--sandbox tier2a-cow`経路は壊れておらず、E2Eだけが実態を測らなくなっていた。
///
/// `session_token`はプロセス内で固定なので、`preflight`の前後どちらで呼んでも同じSIDになる。
///
/// # **記録してから作る**（2026-08-12に順序を直した）
///
/// `begin_session()`を先に呼ぶ。かつてここは`ensure_profile`だけを呼んでおり、
/// 「`begin_session()`をテストから呼ぶと`cargo test`のたびに台帳エントリとプロファイルが
/// 1件ずつ残る」という理由で**意図的に**そうしてあった。
///
/// **その理屈は逆だった。** 避けたのは記録の方で、OSのリソース（プロファイル）は作り続けて
/// いたので、出来上がるのは「台帳に無い実在プロファイル」——`plan_reclaim`が
/// `grants_known: false`と判定して**永久に削除を見送る**形である（名前を消すとSIDが逆引き
/// 不能になり、もしACEが残っていたら二度と剥がせないため。BUG-101①）。実機に**66件**
/// たまっていた。記録があれば次回のGCが監査つきで回収するので、残るのは高々1件（実行中の
/// 自分のぶん）になる。
///
/// 生存マーカーも同時に立つので、**走っている最中のテストのプロファイルを他プロセスのGCが
/// 消す**競合も閉じる（マーカーはプロセス終了でOSが手放す）。
///
/// これはB-01（資源を作る前に記録を残す）そのもので、`preflight`は最初から
/// `begin_session()` → `ensure_profile`の順で書かれている。テストだけが逆順だった。
#[cfg(all(windows, test))]
fn session_sid() -> OwnedContainerSid {
    // 登録は[`ensure_profile`]が作成点で行う（B-01）。ここが特別扱いをする必要は無い。
    ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("ensure_profile (this session's profile, D-37)")
}

/// テスト間で共有する後始末ユーティリティ（RAIIガード）と、本番と同じcapability構成で
/// 子を起こす`spawn_in_workspace`（D-54）。実装は`test_support.rs`。
///
/// `pub(crate)`なのは、`policy_learnd::etw`の実機テストも同じ`spawn_in_workspace`を使うため
/// （`docs/CODE-STRUCTURE-RULES.md`規則5: 同じヘルパーの写しを作らない）。
#[cfg(all(windows, test))]
pub(crate) mod test_support;

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

/// D-81（差分層はワークスペースと同じボリュームへ置く）を、検証用のNTFSボリューム
/// （VHD）で実際に通す。作成・撤収は要管理者で、`dev-elevated-run.exe vhd-ntfs-create`／
/// `-remove`から回す（対で分けてある理由はモジュールdoc）。
#[cfg(all(windows, test))]
mod vhd_volume_tests;

/// MCPサーバ隔離（D-38）の実機E2E。`docs/STATUS.md`「MCPクライアント機構」残課題#3/#4。
#[cfg(all(windows, test))]
mod mcp_e2e_tests;

/// **ドメイン分離（§22.1.1・案A）の受け入れ測定**。スパイクと違い**本番の`spawn_with_workspace`
/// 経由**で、同一package SIDの別ドメインからプロセス／後発スレッドを開けないことを対で測る。
/// スパイクを消した後もこちらは残す（本番機構の回帰テストであるため）。
#[cfg(all(windows, test))]
mod domain_isolation_tests;

/// **`--fs-allow`の主体移行（§22.3）の受け入れ測定**（`docs/STATUS.md`残課題#20、§22.3.0.2の2条件）。
/// 同じセッションの中で、宣言capabilityを積んだ子だけが宣言パスへ届き・そこにある
/// スクリプトを実行できることを、**積まない子と対で**測る。ACLだけを見る
/// `ace_grant_revoke_tests`とは測る層が違う（あちらはDACL、こちらは子から見た実I/O）。
#[cfg(all(windows, test))]
mod fs_allow_domain_acceptance_tests;

/// **CoW差分層の主体移行（§22.3.2）の受け入れ測定**（`docs/STATUS.md`残課題#20の残り1件）。
/// 差分層のrootにpackage SID宛ACEが0本・capability宛が1本であることと、セッション終了と
/// GCの**両方**でそれが0本へ戻ることを、**実DACLで**測る。子から見た実I/Oは測らない
/// （そちらは`cow_containment_tests`と実機E2E`tier2a_cow_commit_matrix`）。
#[cfg(all(windows, test))]
mod cow_diff_layer_subject_tests;

/// **MAC/Spawn Daemon設計の実現性スパイク**（`plans/mac-spike/RESULTS.md`）。
/// 設計§20の未実測の前提を、実装に着手する前に確定させるための使い捨て測定。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod mac_spike_tests;

/// 同上（S3・S4: capabilityの差が実効で効くか／1トークンに積める本数の上限）。
#[cfg(all(windows, test))]
mod mac_spike_capability_tests;

/// 同上（S5・S6・S7: ハンドル複製と最終パス解決／Jobの封じ込め／要求受付パイプ）。
#[cfg(all(windows, test))]
mod mac_spike_daemon_tests;

/// **T4（残課題#20の分流）**: サンドボックスの子が、本番が今まさに開いている
/// privhelperの要求受付パイプへ届くかを測る。結果は`plans/handoff-issue-20/T4.md`。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod t4_privhelper_pipe_reach_tests;

/// **D-79の受け入れ測定（M2）**: ワークスペース内の実行を宣言制にする実装を入れたら本当に
/// 止まるのか（継承ACEの2本割りが「ディレクトリは辿れる／ファイルは実行できない」を
/// 表現できるか）と、その実行時コスト。計画は`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md` M2、
/// 結果は`plans/mac-spike/RESULTS.md`。**D-79が実装された時点で、本モジュールの真偽側は
/// 本体の回帰テストへ書き直して消す**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod d79_exec_split_tests;

/// 同上（S1b・S2c・S2d: コンソール構成の実ツール確認／既定DACL差し替え＝案A／
/// ドメインごとの別package SID＝案Bのプリフェッチ）。
#[cfg(all(windows, test))]
mod mac_spike_followup_tests;

/// 同上（**§20項目1の2**: mitigationによるカーネル拒否をETWで観測できるか）。
/// `plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`の未解決#9（通常運用中の監視）の入力になる。
///
/// **このファイルだけは昇格して走らせる**（ETWリアルタイムセッションに管理者権限が要る）。
/// 他のmac_spikeは非昇格で回す約束なので、`KNOWN_TARGETS`のキーも分けてある
/// （`spike-mac-mitigation-etw`）。**モジュール名はそのフィルタ文字列と一致していること**
/// （改名するとBUG-056と同じ0件マッチになる）。
#[cfg(all(windows, test))]
mod mac_spike_mitigation_etw_tests;

/// **N1: AppContainerごとの証明書ストア（D-65の層1）の実現性スパイク**
/// （`plans/net-spike/RESULTS.md`・`plans/HANDOFF-N1-CERT-STORE-REDIRECT.md`）。
/// legacy AppContainerでレジストリのリダイレクトが掛かるか／Schannelがそこを読むかを
/// 実装の前に確定させる。**非昇格で回す**（昇格すると親トークンが変わり測る世界が変わる）。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod cert_store_spike_tests;

/// **N8 論点③の対策候補B: AppContainerトークンからSMB（UNC）へ届くか**のスパイク
/// （`plans/net-spike/RESULTS.md` `N8-M1-③`）。**非昇格で回す**。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod unc_reach_spike_tests;

/// **現状1主体でのACL付与コストの基準線**（`plans/mac-spike/RESULTS.md` §S10、
/// `plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md`のM1）。`docs/STATUS.md`残課題#20
/// （ドメイン遷移の足回り）に書かれた「重い」という**推定を実測へ置き換える**ためのもので、
/// あわせて残課題#32（伝播が既存子孫へ届かない疑い）を確定/否定する。
/// **非昇格で回す**（ACEを書くのはテスト自身が作ったツリーだけ）。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod acl_baseline_cost_tests;

/// **遅延実体化（JIT）でACEを1件ずつ配るときの1件あたり費用**
/// （`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`の「次に測ること」1番）。
/// 事前配布（§S12-1の86.5 µs/ノード）に対する損益分岐——「触る割合が何%を切れば
/// JITのほうが安いか」——を出すためのもの。**非昇格で回す**。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod jit_grant_cost_tests;

// **削除済み（2026-08-27）**: 一回性の費用測定3本（`docs/CODE-STRUCTURE-RULES.md`規則2）。
// どれも判定が出たので消した。**測り方と数字は`plans/mac-spike/RESULTS.md`が持つ**——
// 作成時継承の限界費用（T-3＝§S18）・ハンドル手渡しの1件あたり（T-5＝§S20）・
// 部分木を外したときの浮き（§S22）。復元が要るならこのコミットの親から取る。

/// **制限SID（`SidsToRestrict`）を指定したトークンで非管理者のまま子を起こせるか**
/// （`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`の「次に測ること」5番＝案A-3の前提）。
/// BUG-003が確かめた特権免除の特例は制限SIDが`None`のときの実測なので、非空でも
/// 効くかを対照つきで測る。**非昇格で回す**（昇格すると特権を持ってしまい区別が付かない）。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod restricted_sid_probe_tests;

/// **両モードのcapability SID宛ACEを1回で同時に配ったとき、`ro`側の子から
/// 書けてしまわないか**（分流`plans/handoff/fs-boundary-cost/T-1.md`、実測は§S16）。
/// 費用側は§S15-1が「1回にまとめれば無料」と実測済みなので、残る問いは安全性だけである。
/// **非昇格で回す**（昇格すると親トークンが管理者になり、測る世界が実運用とずれる）。
///
/// **一回性の測定だったが、残す**（2026-08-27。`docs/CODE-STRUCTURE-RULES.md`規則2の例外）。
/// 判定が **D-84 という拘束的決定になり、その安全性の不変条件**——「`ro`のcapability SIDしか
/// 持たない子は書けない」——**を実子プロセスで測っているのは本モジュールだけ**だからである。
/// `ace_grant_revoke_tests`の対応するテストはDACLの中身までしか見ておらず、
/// **そこから「だから書けない」を導いてはいけない**（同テストのdocが自分でそう書いている）。
/// **D-84を変更するときは、まずここを回すこと。**
#[cfg(all(windows, test))]
mod dual_ace_mode_switch_tests;

/// **残課題#32の機序を1回で決めるプローブ**（使い捨て）。`acl_baseline_cost_tests`が
/// 「届いていない」を確定させたのに対し、こちらは**なぜ届かないのか**を候補を並べて測る
/// ——直し方が機序で変わるため（モジュールdoc）。**非昇格**。
/// **確定したら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(all(windows, test))]
mod acl_propagation_probe_tests;

/// [`acl_dacl_write`]（1ノードあたりDACL書込1回でM本のACEを配る部品）の受け入れ。
/// **こちらは残す**——残課題#32が再発したら赤くなる回帰である。**非昇格**。
#[cfg(all(windows, test))]
mod acl_dacl_write_tests;

/// **DACLに載るACEの本数の上限**（残課題#20の費用測定M3-b）。1ノードに何本まで入るかと、
/// 当たったときエラーになるのか**黙って切り捨てられるのか**を測る。**非昇格**。
/// 寿命は結果次第——無言の切り捨てが起きるなら常設の回帰へ昇格させる（同ファイルのdoc）。
#[cfg(all(windows, test))]
mod acl_dacl_size_limit_tests;

/// **テスト専用**の口。[`ensure_profile`]の所有者チェック（BUG-107）を迂回して、
/// **他セッションのものに見える名前**のプロファイルを作る。
///
/// 「セッションAのサンドボックスからセッションBのworkspaceが読めないこと」や「プロファイルを
/// 消した後もACEを剥がせること」は、**自分以外のセッションを実際に作らないと測れない**。
/// 製品コードにはその必要が無い（他人のセッションを作る正当な理由が無いのがBUG-107の結論）ので、
/// 公開面は広げずここだけ`#[cfg(test)]`で開ける——`grant_ace_mask_for_test`と同じ扱い。
///
/// **`begin_session`は呼ばない。** 呼ぶと台帳へ載るのは*このプロセス*のトークンで、名前とは
/// 対応しないため回収の手掛かりにならない。ここで作ったプロファイルは**テスト自身が消すこと**。
#[cfg(all(windows, test))]
pub(crate) fn ensure_profile_for_test(name: &str) -> Result<OwnedContainerSid, AppContainerError> {
    crate::with_named_lock(PROFILE_LOCK, || ensure_profile_locked(name))
}

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
