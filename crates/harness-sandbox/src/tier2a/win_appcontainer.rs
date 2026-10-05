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
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::shell_tier::{FsAccess, FsPassthrough, GrantScope, WorkspaceWriteMode};
use crate::tier2a::session_profile::ProfileOwner;
use crate::win_common::{
    build_env_block, clear_inherit, create_job_object, create_pipe_with_sddl, long_path_wide,
    read_two_pipes_to_strings, terminate_job, terminate_job_and_close, wide, write_all, KillToken,
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
    /// [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md`）] Redirector DLLの注入か、resume前の
    /// ハンドシェイクが失敗した。
    ///
    /// **`Win32`と分けているのは、呼び出し側の打つ手が違うからである。** この失敗は
    /// **子がユーザーコードを1行も実行する前**に起きるので、子を捨てて作り直しても
    /// 副作用が二重にならない——lazyレーンはこれを見て「全walkを待ってから**1回だけ**
    /// 通常起動する」へ落ちる（設計書§5.1.3「起動と自動fallback」の3）。
    /// 他の`Win32`失敗と混ぜると、その判定が文字列一致になる（`B-32`: 文言で分岐しない）。
    #[error("redirector injection failed: {0}")]
    RedirectorInjection(String),
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

/// Spawn Daemonの**要求受付パイプへ到達してよい**ことを表すcapabilityの名前（§10.1）。
///
/// # なぜpackage SIDではなくcapabilityなのか
///
/// 要求受付パイプのDACLをセッションのpackage SID宛にすると、**MCPサーバが接続できない**
/// ——D-38によりMCPサーバは**サーバごとに別のpackage SID**を持つためである（§22.2.2）。
/// サーバごとにACEを足す案は、宣言数だけACEが増え撤収も増えるので採らない。
/// capability SID宛なら**ACEは1本で済み、プロファイルがいくつ増えても変わらない**。
///
/// # 積むかどうかが、そのままドメイン単位のスイッチになる
///
/// §22.2.2の`process: deny`を宣言したMCPサーバにはこのcapabilityを積まないので、
/// **パイプに到達すらできない**（`CHILD_PROCESS_RESTRICTED`との二重のdeny）。
///
/// # 名前が固定であることの意味（[`TRAVERSE_CAPABILITY_NAME`]と同じ残存リスク）
///
/// capability SIDは名前から誰でも導出でき、トークンへ任意に積める。したがって
/// **同じユーザーの別プロセスが同じcapability名でAppContainerを作れば、このパイプへ
/// 到達できる**。それでよいのは、パイプのDACLがユーザーSIDでも絞られており、
/// **同一ユーザーの攻撃者は元より同じ権限を持つ**からである。
/// **パイプ名を秘密に数えていない**のと同じ理由で、守っているのはDACLだけである。
pub const SPAWN_REQUEST_CAPABILITY_NAME: &str = "harnessSandboxSpawnRequest";

/// [`SPAWN_REQUEST_CAPABILITY_NAME`]から導出したcapability SID。
///
/// **Daemon（パイプのDACLを組む側）とharness（子のトークンへ積む側）が同じ値を得ることが
/// 前提**なので、名前は定数1つだけが持つ（綴りを2箇所に置かない）。
pub fn spawn_request_capability_sid() -> Result<crate::win_common::OwnedSid, AppContainerError> {
    capability_sid_from_name(SPAWN_REQUEST_CAPABILITY_NAME)
}

/// このworkspace＋モードのFS付与の宛先SID（D-54）。名前は
/// [`crate::tier2a::workspace_capability`]がworkspaceごとのランダム秘密から導出し、
/// マシンローカル台帳（`%APPDATA%\harness\config\`）に保存する。
///
/// **`workspace`はcanonicalize済みを渡すこと**（綴りが違うと別エントリ＝別の宛先SIDになり、
/// 同じツリーへ2つの宛先SIDのACEを撒くことになる）。台帳へまだ無ければここで発行する。
pub fn workspace_capability_sid(
    workspace: &Path,
    mode: &str,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    let name = crate::tier2a::workspace_capability::ensure_capability_name(workspace, mode)
        .map_err(AppContainerError::Preflight)?;
    capability_sid_from_name(&name)
}

/// `--fs-allow`の**宣言1件**のFS付与の宛先SID（§22.3）。
///
/// D-54がworkspaceツリーに対してやったことを、宣言されたパスに対して行う。以前この穴は
/// **セッションのpackage SID**宛だった——package SIDはAppContainer全体で共有されるので、
/// そのACEは同一セッションの**全ドメイン**に効いてしまい、per-domainのFS制御は原理的に
/// 作れなかった（§22.3）。
///
/// 宛先SIDは§22.2.0の導出鍵`(秘密, 畳み込み済みパス, access級)`から決まる。したがって
/// **同じ宣言をするドメインは何もしなくても同じSIDを共有し**、1つの宣言パスに載るACEは
/// access級の数（最大3本）で止まる（§22.3.3）。
///
/// **`workspace`はcanonicalize済みを渡すこと**（[`workspace_capability_sid`]と同じ理由）。
/// `declared_path`側の綴りは`declaration_key`が畳むので、呼び出し側で正規化しなくてよい。
///
/// **`access`は実際に付けるアクセスを渡すこと。** CoWでRO降格した場合は降格後の値である
/// ——導出に使った級と実際に書いたマスクがずれると、撤収側は別の宛先SIDを探しに行く。
pub fn fs_allow_capability_sid(
    workspace: &Path,
    declared_path: &Path,
    access: FsAccess,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    fs_allow_capability_sids_for_declarations(workspace, &[(declared_path, access)])
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            Err(AppContainerError::Preflight(
                "the batched declaration subject issuer returned no result for a single declaration"
                    .to_string(),
            ))
        })
}

/// [残課題#37] [`fs_allow_capability_sid`]の**複数件版で、こちらが実体**である。
/// 宣言N件の宛先SIDを**1回の台帳更新**で確保する。
///
/// 1件ずつ呼ぶと台帳の全文往復をN回払い、台帳が育つほど1件あたりが高くなる
/// （宣言668件で13.46秒、`plans/mac-spike/RESULTS.md` §S42-5）。費用の内訳と、なぜ
/// 複数件版を正にするかは
/// [`crate::tier2a::workspace_capability::ensure_declaration_capabilities`]のdocが持つ。
///
/// 返り値は`declarations`と同じ順・同じ長さで、**失敗は要素ごと**——1件の宛先SIDが作れなくても
/// 他の宣言は続ける（呼び出し元は失敗した宣言だけを拒否に落とす）。
///
/// **`access`は実際に付けるアクセスを渡すこと**（1件版と同じ理由。CoWでRO降格したなら降格後の値）。
pub fn fs_allow_capability_sids_for_declarations(
    workspace: &Path,
    declarations: &[(&Path, FsAccess)],
) -> Vec<Result<crate::win_common::OwnedSid, AppContainerError>> {
    let requests: Vec<(&Path, &str)> = declarations
        .iter()
        .map(|(path, access)| (*path, access.label()))
        .collect();
    crate::tier2a::workspace_capability::ensure_declaration_capabilities(workspace, &requests)
        .into_iter()
        .map(|issued| {
            let capability = issued.map_err(AppContainerError::Preflight)?;
            capability_sid_from_name(&capability.capability_name)
        })
        .collect()
}

/// [§22.9の前提] Redirector DLLのcapabilityの**発行元**として使うパス。
///
/// # ワークスペースではない（2026-09-19に実測で直した）
///
/// 宣言capabilityの鍵は`(発行元, 宣言パス, access級)`である。ここへワークスペースを渡すと、
/// **ワークスペースごとに別の宛先が発行され、同じDLLにACEが1本ずつ増える**。
/// しかもワークスペースが使い捨て（テストの一時ディレクトリ等）だと、台帳のエントリが
/// 消えた後も**ACEだけが残る**——撤収経路の無い孤立ACEで、掃除
/// （`sweep_stale_redirector_dll_aces`）はcapability SIDを意図的に見ない。
///
/// **実際に踏んだ**: 最初の実装はワークスペースを渡しており、実機のE2Eを1周しただけで
/// `harness_redirector.dll`に36本、x86側に4本のcapability ACEが積み上がった。
///
/// DLLは**harnessの設置場所にある1つのファイル**で、どのワークスペースから使っても同じ物である。
/// だから発行元もその設置場所にする——宛先はDLL 1本につき1つに収束し、ドメインを増やしても
/// ワークスペースを増やしても増えない。
fn redirector_capability_issuer(dll: &Path) -> std::path::PathBuf {
    dll.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| dll.to_path_buf())
}

/// [§22.9の前提] Redirector DLLの宛先capabilityを**発行して**返す（`preflight`が使う）。
///
/// 返すのは`(DLLのパス, 発行の結果)`で、**失敗は要素ごと**——1本の宛先が作れなくても
/// もう1本は続ける。`Err`のときは許可を書かないこと（fail-closed。package SIDへ退避すると
/// 「移行したつもりで全ドメインに開く」最悪の形になる）。
pub fn issue_redirector_dll_capabilities() -> Vec<(std::path::PathBuf, Result<String, String>)> {
    let dlls = redirector_dll_paths();
    // **1回の台帳更新でまとめて確保する**（1件ずつだと台帳の全文往復を件数ぶん払う。残課題#37）。
    // 発行元がDLLごとに違い得る（別ディレクトリに置かれた場合）ので、まとめられるのは
    // 同じ発行元のぶんだけである——今日は2本とも同じ隣にあるので1回で済む。
    let issuers: Vec<std::path::PathBuf> = dlls
        .iter()
        .map(|d| redirector_capability_issuer(d))
        .collect();
    let mut out = Vec::with_capacity(dlls.len());
    for (dll, issuer) in dlls.iter().zip(&issuers) {
        let issued = crate::tier2a::workspace_capability::ensure_declaration_capability_name(
            issuer,
            dll,
            FsAccess::ReadExec.label(),
        );
        out.push((dll.clone(), issued));
    }
    out
}

/// [§22.9の前提] Redirector DLLへ**既に発行済み**の宣言capability SIDを引く（発行はしない）。
///
/// # 何のためにあるのか
///
/// DLLの読取+実行ACEは、セッションのpackage SID宛から**宣言宛のcapability SID**へ移った
/// （`preflight`の該当ブロック）。**子のトークンがその宛先を持っていなければDLLを読めず、
/// 注入が失敗して生成ごと落ちる**（注入の失敗は設計上fatal。BUG-116）。ここはそれを積むための
/// 引き口である。
///
/// # 発行しない
///
/// 発行するのは`preflight`だけにしてある。起こす側が発行すると、preflightを経ていない構成に
/// **台帳の記録だけが増える**（CoWの差分層が同じ理由で同じ形を採っている）。
/// 引けなければ空を返す——症状は`ACCESS_DENIED`＝fail-closedで、無言で広がる向きには倒れない。
///
/// **鍵は[`redirector_capability_issuer`]が1箇所で決める。** 発行側と引く側で綴りがずれると、
/// 引けずに空が返り、**子が一切起動しなくなる**（実際に実機で踏んだ形）。
pub fn redirector_dll_capability_sids() -> Vec<crate::win_common::OwnedSid> {
    redirector_dll_paths()
        .into_iter()
        .filter_map(|dll| {
            let name = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
                &redirector_capability_issuer(&dll),
                &dll,
                FsAccess::ReadExec.label(),
            )?;
            capability_sid_from_name(&name).ok()
        })
        .collect()
}

/// 子のトークンへ積む「このドメインのFS到達範囲」。**4種類ある。**
///
/// | 種類 | 誰が所有するか |
/// |---|---|
/// | ワークスペース本体（D-54） | 呼び出し側 |
/// | `--fs-allow`の穴（§22.3） | 呼び出し側 |
/// | CoWの差分層（§22.3.2） | 呼び出し側 |
/// | **Redirector DLL（§22.9の前提）** | **この型** |
///
/// # なぜ4つめだけこの型が引くのか
///
/// **忘れられたからである。2度。** 前の3つは呼び出し側が自分の文脈から作るしか無いが、
/// 4つめは「注入する子なら必ず要る」という定数的な要求で、文脈を持たない。それを
/// 呼び出し側に引かせていたので、組み立て点が2つ（製品の[`launch`]とテスト専用の
/// [`test_support`]）に分かれた時点で**片方だけが欠けた**。
///
/// - 1度目: D-84（ワークスペース本体の宛先が capability SID へ移った回）。
///   テスト側が積まず、`cow-diagnostics`が17/19になった（`test_support`のモジュールdoc）。
/// - 2度目: [BUG-169]。2026-09-19にDLLの宛先がcapability SIDへ移り、製品とdaemonには
///   足されたがテスト側には届かず、**18本が7日間赤のまま**だった。`#[ignore]`なので
///   明示的に撃つまで誰も気付かない。
///
/// **所有をこの型へ寄せるのが「忘れられない」の中身である**——`collect`を呼べば4つめが入り、
/// 呼ばなければ何も手に入らない。呼び出し側に「引くかどうか」の選択肢を残さない。
///
/// # この機構が守らないもの
///
/// **まったく別の方法でトークンを組む経路**は止められない。daemonがドメインを用意する
/// [`domain_provision`]は宛先を**文字列の一覧としてIPCで送る**別表現なので、この型を通らない
/// （あちらは自分で4つめを積んでいる）。「2箇所ちょうど」であることは
/// `redirector_dll_capability_sids`の呼び出しを数えるテストが固定する。
///
/// **[BUG-180] その経路では、3つめ（CoWの差分層）も別の口から来る。** [`domain_provision`]は
/// 差分層を積まない（セッションごとに作り直されるので起動時の表に入れられない）。Daemonが
/// 別ドメインの子を起こすときは、系統の注入設定（`RedirectorSpec::Cow`）が運ぶ差分層のSIDを
/// `spawnd/child_plan.rs`が積む。**上の表の4種類がDaemonの経路でどこから来るか**は
/// `spawnd/child_plan_tests.rs`の`each_of_the_four_capability_kinds_has_a_source_on_the_cross_domain_path`が固定する。
pub(crate) struct DomainCapabilities {
    /// **この型が所有する宛先。** 生存期間をここへ束ねてあるので、[`Self::psids`]が返す
    /// ポインタはこの値より長生きできない。
    redirector: Vec<crate::win_common::OwnedSid>,
    /// 呼び出し側が所有している宛先（上の表の前3つ）。
    caller_owned: Vec<PSID>,
}

impl DomainCapabilities {
    /// 呼び出し側が持っている宛先を受け取り、**Redirector DLLの宛先をここで引いて**束ねる。
    pub(crate) fn collect(caller_owned: Vec<PSID>) -> Self {
        Self {
            // **引くだけで発行しない。** 発行するのは`preflight`だけにしておかないと、
            // preflightを経ていない構成に記録だけが増える（`redirector_dll_capability_sids`のdoc）。
            redirector: redirector_dll_capability_sids(),
            caller_owned,
        }
    }

    /// `SECURITY_CAPABILITIES`へ渡す一覧。**`&self`を借りる**ので、返り値が指す先は
    /// この値より長生きできない（spawnを跨いで持ち回さないこと）。
    pub(crate) fn psids(&self) -> Vec<PSID> {
        let mut out = self.caller_owned.clone();
        out.extend(self.redirector.iter().map(|sid| sid.as_psid()));
        out
    }
}

/// `declared_path`宛に**既に発行済み**の宣言capability SIDを引く（発行はしない）。
///
/// 撤収側（`harness fs revoke <path>`・セッション終了時の自動撤収）が使う。
/// §22.2.1の doctrine どおり、ACLを列挙して宛先SIDを推定するのではなく**宣言から導出した
/// SIDを名指しで**剥がすための入口である（`revoke_subjects.rs`の分類器は使わない。
/// あちらはpackage SID専用で、capability SIDを混ぜないことが意図である）。
///
/// `workspace`が`Some`ならそのworkspaceが発行したものだけに絞る（絞らない側の注意は
/// [`crate::tier2a::workspace_capability::declaration_capability_names`]のdoc）。
pub fn fs_allow_capability_sids(
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<crate::win_common::OwnedSid> {
    fs_allow_capability_sids_indexed(
        &crate::tier2a::workspace_capability::DeclarationIndex::load(),
        declared_path,
        workspace,
    )
}

/// [残課題#37] [`fs_allow_capability_sids`]の、**台帳の写しを渡す版**。
///
/// 複数のパスについて続けて引くときはこちらを使う——単発版はパス1件ごとに台帳を全文読んで
/// 構文解析するので、数百件を取り消す経路では読取が件数ぶん走る。写しの限界（読んだ後に
/// 発行された宛先SIDは見えない）は
/// [`crate::tier2a::workspace_capability::DeclarationIndex`]のdocが持つ。
pub fn fs_allow_capability_sids_indexed(
    index: &crate::tier2a::workspace_capability::DeclarationIndex,
    declared_path: &Path,
    workspace: Option<&Path>,
) -> Vec<crate::win_common::OwnedSid> {
    index
        .capability_names(declared_path, workspace)
        .iter()
        .filter_map(|name| capability_sid_from_name(name).ok())
        .collect()
}

/// CoW差分層（`--sandbox tier2a-cow`の`diff_layer_dir`）のACEを付ける先の access級。
///
/// **`grant_ace_inheritable_rw`が実際に書くマスクと同じ級でなければならない。** あちらは
/// `workspace_rwx_mask()`を書き、それは`fs_access_mask(FsAccess::ReadWriteExec)`と同値である
/// （`acl_grant`の`fs_access_mask`にその旨のコメントがある）。導出に使った級と実際に書いた
/// マスクがずれると、撤収側は**別の宛先SID**を探しに行って何も剥がせない。
pub const COW_DIFF_LAYER_ACCESS: FsAccess = FsAccess::ReadWriteExec;

/// [§22.3.2] CoW差分層のFS付与の宛先SID。**発行する側**（付与経路が使う）。
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
/// | 子のトークンへ積む（製品） | `win_appcontainer/launch.rs` | しない（[`require_cow_diff_layer_capability_sid`]） |
/// | 子のトークンへ積む（実機テスト） | `win_appcontainer/test_support.rs` | しない（同上） |
///
/// **[BUG-180] トークンへ積む場所はもう1つある**——Spawn Daemonが入れ子の子（とくに
/// 別ドメインへ移った子）を起こすときで、`spawnd/child_plan.rs`が積む。ここは**引かない**:
/// 製品の`launch.rs`が引いた値を注入設定（`RedirectorSpec::Cow`）と一緒に送り、Daemonは
/// その値をそのまま使う。**上の表の導出を通らない積む場所**なので、ずれたときの症状は
/// 下と同じ形になる（積む場所の全数は`plans/DESIGN-MAC-DOMAIN.md` §22.3.2の表が持つ）。
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

/// [§22.3.2] CoW差分層の宛先SIDを**引くだけ**（発行しない）。子のトークンへ積む経路が使う。
///
/// [`cow_diff_layer_capability_sid`]との違いは発行の有無だけである。**積む側が発行してしまうと、
/// `preflight`を経ていない差分層に対して台帳エントリが増える**——「読むだけのつもりの呼び出しが
/// 作用を持つ」形で、`B-01`が名指ししている誤りそのものである（`test_support`が
/// workspace本体について`lookup_capability_name`を通しているのと同じ理由）。
///
/// まだ発行されていなければ`None`。呼び出し側は**積まない**——積めないことは
/// `ACCESS_DENIED`＝fail-closedで出るので、無言で広がる向きには倒れない。
/// **access級で絞って引く**（`declaration_capability_names`のようにパスだけで引かない）——
/// 積むべきなのは**付与に使ったのと同じ級の宛先SID**ただ1つだからである。級を無視して引くと、
/// 同じ差分層へ別の級が発行されていた場合に宣言より広い宛先SIDを積むことになる。
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

/// [BUG-180] [`lookup_cow_diff_layer_capability_sid`]の、**引けなければ子を起こさない**版。
///
/// # なぜ「引けなければ積まない」で済ませないのか
///
/// 以前の子を起こす側は、引けなければ積まずにそのまま起こしていた。拒否（`ACCESS_DENIED`）で
/// 止まるので安全側だ、という理屈だったが、**それは書込だけの話だった**。Redirectorは
/// 差分層に在るかを`is_file()`等で確かめており、拒否を「無い」と読む。そのため読取は
/// **変更前の中身を黙って返し**、消したはずのファイルも元の中身で見えた（BUG-180）。
/// 差分層へ届かない子を起こす時点で、見え方が嘘になる。
///
/// 起こす側（製品の`launch`とテスト補助の`test_support`）は**両方ともここを通す**
/// ——BUG-169は、同じ組み立てを2か所で書いて片方だけが欠けた形だった。
pub(crate) fn require_cow_diff_layer_capability_sid(
    workspace: &Path,
    diff_layer_dir: &Path,
) -> Result<crate::win_common::OwnedSid, AppContainerError> {
    lookup_cow_diff_layer_capability_sid(workspace, diff_layer_dir).ok_or_else(|| {
        AppContainerError::Preflight(format!(
            "the CoW diff layer {} has no issued capability for workspace {}; refusing to start \
             a child that cannot reach it (it would read the unmodified workspace without any \
             error, BUG-180). The diff layer is prepared by the sandbox preflight or by a \
             session switch/fork",
            diff_layer_dir.display(),
            workspace.display()
        ))
    })
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
        // このプロセスのセッション（`run_shell`用・MCP用・遷移先ドメイン用のどれも）。記録してから作る。
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

// [§22.3] **`current_session_grant_sid()`は2026-09-01に削除した。**
//
// この関数は「fs passthroughのACEを付与するときの宛先SID」を返し、呼び出し元
// （`harness-cli`の`run_agent`とポリシーエディタのパス2）がそれを
// `fs-passthrough-ledger`の`granted_sid`欄へ書いていた（BUG-101）。
//
// **返していたのはセッションのpackage SIDである。** 主体移行が済んだいま、
// `--fs-allow`の穴にpackage SID宛のACEは1本も無いので、その値を書くと
// **事実と違う記録**になる。呼び出し元は`None`（＝package SID宛には付与していない）を
// 書くようになり、この関数の使い手は0になった。
//
// あわせて`preflight`にあった「台帳へ書く値と実際に使う宛先SIDの一致」の検算も消した——
// 比べる相手が居なくなったので、残しても何も検出しないまま「検算があるから守られている」と
// 読ませるだけである。移行の不変条件のほうは`preflight`末尾が実DACLを読んで測っている。

// --- 責務別サブモジュール（docs/CODE-STRUCTURE-RULES.md 規則1/3） ---
//
// 分割線は「どのOS機構を触るか」で引いている。公開パス
// （`harness_sandbox::tier2a::win_appcontainer::preflight` 等）を変えないため、各モジュールの
// 公開項目はここでglob再エクスポートする。

/// [残課題#32] **DACLを組んで書く低レベルの口**のうち、「M本のACEを1つのDACLへ畳んで
/// ノードあたり1回だけ書き、既存の子孫まで届かせる」側。`acl_grant`（何をどの宛先SIDへ許すかの
/// 決定）とは触るものが違うので分けてある。**globで出さない**——`propagate_merged_dacl`という
/// 名前は、それだけでは`set_dacl_propagating`との違いが分からないため。
mod acl_dacl_write;
mod acl_grant;
/// CoW差分層に残った**引退した身分**宛のACEを剥がす巡回。`revoke_subjects`（誰を剥がすか）
/// とは別の軸——こちらが持つのは**どのパスを見に行くか**である。残課題#35で実機に1か月
/// 残った10件は、判定が届かなかったのではなく、判定器を差分層へ向ける経路が無かった。
mod cow_layer_sweep;
/// 初回の救済walkを背景で回すジョブ（D-54）。**globではなく名前空間として公開する**
/// ——`start`/`progress`/`wait_until_done`という短い名前は、それだけでは何のジョブか
/// 分からないため（`grant_job::wait_until_done()`と書けば分かる）。
pub mod grant_job;
/// Tier2a子を起こすまでの前口上（宛先SIDの導出・背景walkの待ち・spawn）。`run_shell`と
/// ポリシーエディタのパス2が共有する（モジュールdoc参照）。
mod launch;
/// [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] Lazy ACE fault-inの準備器（走査器と単一writer）。
/// **globで出さない**——`scan`/`start`のような短い名前は、それだけでは何の走査か分からない。
mod lazy_grant;
mod mcp_preflight;
mod native_path_policy;
/// fs passthrough付与の進捗（同期区間からUIへ届ける唯一の口、`grant_job`と同じ形）。
pub mod passthrough_progress;
mod preflight;
/// `preflight`が打つ実機プローブ（実際にAppContainer子を起こしてFS I/Oを試す層）。
/// 決定（どのプローブをどの順で打つか）は`preflight`が持ち、ここは観測だけを持つ。
mod preflight_probe;
mod revoke;
/// 撤収する宛先SIDのうち、**宣言（`--fs-allow`）から一意に導出できるもの**を決める層（§22.2.1）。
/// `revoke_subjects`（DACLに実在するpackage SIDを分類する）とは探し方が違うので分けている。
mod revoke_declarations;
/// 撤収の**宛先SID**を決める層（[BUG-101](../../../docs/bugs/BUG-101.md)欠陥②）。
/// 「どのSIDのACEを剥がすか」を、名前から導出したSIDではなく**対象パスのDACLに実在するSID**
/// から決める。`revoke`（剥がし方）とは責務が別なので分けている。
mod revoke_subjects;
/// [#55] **遷移先ドメインの実体を用意する**（`plans/DESIGN-MAC-BROKER.md` §22.9）。
/// 起動時にまとめて用意し、表をSpawn Daemonへ渡す。**新しい許可は1本も付けない**
/// ——既に許可済みの宣言の宛先SIDを引くだけで、引けなければそのドメインは用意しない。
#[cfg(windows)]
pub mod domain_provision;
mod spawn;
/// [段階⑦] その綴りは**アプリの仕組みを通って起きる**か（ストアの実行エイリアス／MSIXの実体）。
///
/// **遷移先にできない綴りを見分けるのに使う**（2026-09-18に実測。`plans/mac-spike/RESULTS.md` §S62）。
/// ここで公開しているのは、ポリシーエディタの遷移画面が**同じ判定**を通す必要があるためである
/// ——別に書くと、画面が「起こせる」と言っているのに実際には断られる形になる（`B-13`）。
pub use spawn::starts_through_the_app_model;
/// Tier2aのシェルの候補。ポリシーエディタの昇格E2Eが、連鎖の途中の段のシェルを`harness.exe`と
/// **同じ判断**で選ぶために公開している（写すと片方だけ変わる、`B-05`）。
pub use spawn::{shell_candidates_from, ShellChoices};
mod spawn_session;
mod traverse;
/// [D-84] workspaceツリーへ配る**ACEの集合**（モード×宛先SID×マスク）と、それを1回の書込で
/// 置く口。`acl_grant`（何をどの宛先SIDへ許すかの決定）から分けてあるのは、こちらが扱うのが
/// 「**どのcapability SID宛のACEを何本配るか**」という別の軸だからである
/// （`docs/CODE-STRUCTURE-RULES.md`規則3）。
mod workspace_aces;
/// workspace capability ACE の準備本体。通常preflightと明示的な前払いCLIが共有する。
mod workspace_prepare;

pub use acl_grant::*;
pub use cow_layer_sweep::*;
pub use launch::*;
pub use mcp_preflight::*;
pub use native_path_policy::*;
pub use preflight::*;
pub(crate) use preflight_probe::*;
pub use revoke::*;
pub use revoke_declarations::*;
pub use revoke_subjects::*;
pub use spawn::*;
pub use spawn_session::*;
pub use traverse::*;
pub use workspace_aces::*;
pub use workspace_prepare::{
    start_workspace_preparation, workspace_preparation_state, WorkspacePreparationLaunch,
    WorkspacePreparationState,
};

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
/// （`harness-tools/src/shell/`）も、どちらもセッションSIDになった。テストだけが
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

/// [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）] Lazy ACE fault-inの**受入**。
/// 「準備が届いていないファイルを、子が待たずに開けるか」を実子プロセスで測る。
#[cfg(all(windows, test))]
mod lazy_fault_in_acceptance_tests;

/// [D-88] 検証3「子孫到達」。**`cargo build`では測れない**ので、ワークスペースの中と
/// OS標準のものだけで多段のプロセスを起こす代用で測る（同ファイルのモジュールdoc）。
#[cfg(all(windows, test))]
mod lazy_descendant_reach_tests;

/// [D-88] **注入できないプロセスがどうなるか**を、注入を意図的に外して測る。
/// 最上位は待つ／子孫は拒否される、という非対称を固定する（同ファイルのモジュールdoc）。
#[cfg(all(windows, test))]
mod lazy_uninjectable_tests;

/// [D-88] 検証6「UX」。**昇格の主条件であるfirst-command-outputのp95**を、現行の全walk待機と
/// ランダム順で比較して測る。**測ったツリーの構成を同じレポートへ併記する**（同ファイルのdoc）。
#[cfg(all(windows, test))]
mod lazy_ux_latency_tests;

#[cfg(all(windows, test))]
mod cancel_descendants_tests;

/// [残課題#52] 1つの実行ファイルにだけPage Heap(Full)を載せる／外す（レジストリ）。
/// **プローブがどこでヒープを壊しているかを出すための道具**で、載せる先は自分たちの
/// テスト用バイナリだけである（同ファイルのモジュールdoc）。
#[cfg(all(windows, test))]
mod page_heap;

/// 段階5（Spawn Daemon本体）の実機受け入れテスト。
///
/// **モジュール名は`KNOWN_TARGETS`の`spawn-daemon`のフィルタ文字列と一致していること**
/// （改名すると0件マッチで黙って緑になる。BUG-056）。
#[cfg(all(windows, test))]
mod spawnd_e2e_tests;

/// **要求受付パイプの混雑の測定**（`docs/STATUS.md`残課題#43）。受け入れではなく観測なので
/// `spawn-daemon`とは別の的（`spawn-daemon-congestion`）から回す——混ぜると受け入れが延び、
/// 合否を持たないものが受け入れの数に混ざる（`spawn-daemon-latency`と同じ扱い）。
///
/// **モジュール名とテスト名は`KNOWN_TARGETS`のフィルタ文字列と一致していること**
/// （改名すると0件マッチで黙って緑になる。BUG-056）。
#[cfg(all(windows, test))]
mod spawnd_load_tests;

#[cfg(all(windows, test))]
mod ace_grant_revoke_tests;

/// **Redirector DLLの孤立ACEを既存の掃除が回収するかの測定**（残課題#23のM1、BUG-112の仮説H1）。
/// 掃除の本体・名簿・射程を、許可側と禁止側を対にして測る。モジュールdocに
/// 「測っていないこと」（強制終了は再現していない・`preflight`を通していない）がある。
#[cfg(all(windows, test))]
mod redirector_dll_sweep_tests;

/// **ドメインをN個用意して片付ける費用の測定**（残課題#55の本体に着手する前）。
/// 「起動時にまとめて用意する」形が払えるかを数字で決めるためのもので、結果は
/// `plans/mac-spike/RESULTS.md` §S72。
///
/// **消す条件は出来事である**——残課題#55が着地し、`plans/DESIGN-MAC-BROKER.md` §22.9の
/// 費用表がこの測定の値で更新されたら、**モジュールごと消す**（隣の`acl_baseline_cost_tests`が
/// 同じ形の先例）。
#[cfg(all(windows, test))]
mod domain_profile_cost_tests;

/// **CoW差分層の巡回が、剥がすべきものだけを剥がすことの回帰**（残課題#35）。
/// 引退した身分は剥がれ、well-knownのSIDと走行中の差分層は触られない、を対で測る。
#[cfg(all(windows, test))]
mod cow_layer_sweep_tests;

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

/// **`--fs-allow`の宛先SID移行（§22.3）の受け入れ測定**（`docs/STATUS.md`残課題#20、§22.3.0.2の2条件）。
/// 同じセッションの中で、宣言capabilityを積んだ子だけが宣言パスへ届き・そこにある
/// スクリプトを実行できることを、**積まない子と対で**測る。ACLだけを見る
/// `ace_grant_revoke_tests`とは測る層が違う（あちらはDACL、こちらは子から見た実I/O）。
#[cfg(all(windows, test))]
mod fs_allow_domain_acceptance_tests;

/// **CoW差分層の宛先SID移行（§22.3.2）の受け入れ測定**（`docs/STATUS.md`残課題#20の残り1件）。
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

/// **D-79の受け入れ測定（M2）**: ワークスペース内の実行を宣言制にする実装を入れたら本当に
/// 止まるのか（継承ACEの2本割りが「ディレクトリは辿れる／ファイルは実行できない」を
/// 表現できるか）と、その実行時コスト。測り方と結果は`plans/mac-spike/RESULTS.md` §S9（M2）。
/// **消す条件は無い（規則2の例外として残す）。** 当初は「D-79が実装されたら真偽側を
/// 本体の回帰テストへ書き直して消す」としていたが、D-79は不採用で決着したので実装されない。
/// 本モジュールは**D-79を覆すときの材料**（前提・形・コスト）として残す——
/// `docs/STATUS.md`サンドボックス周辺 #31 がそう定めている。
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
/// （`plans/net-spike/RESULTS.md` N1・N1（訂正）・N1-②（訂正・決着）・N1-③）。
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

/// **現状の宛先SID 1本でのACL付与コストの基準線**（`plans/mac-spike/RESULTS.md` §S10、M1）。`docs/STATUS.md`残課題#20
/// （ドメイン遷移の足回り）に書かれた「重い」という**推定を実測へ置き換える**ためのもので、
/// あわせて残課題#32（伝播が既存子孫へ届かない疑い）を確定/否定する。
/// **非昇格で回す**（ACEを書くのはテスト自身が作ったツリーだけ）。
/// **一回性の測定だったが、残す**（`docs/CODE-STRUCTURE-RULES.md`規則2の例外）——うち2本が
/// 残課題#32の回帰になった。どれを残しどれを消せるかの内訳はファイル冒頭の表が持つ。
#[cfg(all(windows, test))]
mod acl_baseline_cost_tests;

/// workspace ACLの支払時点を比べる継続測定。作成時継承を無料と仮定せず、生成基準線・
/// root ACE設置後の生成・完成後伝播をランダム順に反復する。**非昇格**。
#[cfg(all(windows, test))]
mod acl_payment_model_tests;

/// 作成時継承案の適用範囲を、実git worktree・build生成物・move-in・保護DACL・reparse pointで
/// 確認する真偽テスト。**非昇格**。
#[cfg(all(windows, test))]
mod acl_creation_inheritance_eligibility_tests;

/// `harness fs prepare-workspace`が使う共有準備本体の実Win32回帰。**非昇格**。
#[cfg(all(windows, test))]
mod workspace_prepare_tests;

// **削除済み（2026-08-27）**: 一回性の費用測定3本（`docs/CODE-STRUCTURE-RULES.md`規則2）。
// どれも判定が出たので消した。**測り方と数字は`plans/mac-spike/RESULTS.md`が持つ**——
// 作成時継承の限界費用（T-3＝§S18）・ハンドル手渡しの1件あたり（T-5＝§S20）・
// 部分木を外したときの浮き（§S22）。復元が要るならこのコミットの親から取る。
//
// **削除済み（2026-09-30）**: 判定の出た一回性の測定5本（同じ規則2）。数字と判定は記録が持つ——
// JITの1件あたり費用（`jit_grant_cost_tests`＝§S13）・制限SID案A-3の成立性
// （`restricted_sid_probe_tests`＝§S14、不成立）・フックがopen 1回へ上乗せする時間
// （`lazy_hook_overhead_tests`＝§S25）・copy-upの一時名化の費用（`copy_up_cost_tests`＝§S76）は
// `plans/mac-spike/RESULTS.md`、privhelperの受付パイプへの到達（`t4_privhelper_pipe_reach_tests`）は
// `plans/handoff-issue-20/T4.md`。T4専用だったプローブのモード2つ（パイプ名の列挙・
// 未使用の名前でのパイプ作成）も同時に外した。復元が要るならこのコミットの親から取る。
//
// **削除済み（2026-09-30）**: `dual_ace_mode_switch_tests`（分流T-1、判定は
// `plans/mac-spike/RESULTS.md` §S16）。2026-08-27に規則2の例外として残していたのは、D-84の
// 安全性の不変条件——「`rwx`宛のACEが同じDACLに同居していても、`ro`のcapability SIDしか
// 持たない子は書けない」——を**実子プロセスで**測っているのがここだけだったからである。
// その確かめは製品の回帰テスト
// `cow_containment_tests::workspace_write_fails_closed_without_redirector_injection`へ移した
// （根に両モードのACEが載っていることを前提として確かめ、同じACLで`rwx`の子は書けることを対で見る）。
// **D-84を変更するときは、まずあのテストを回すこと**（`dev-elevated-run.exe cow-diagnostics`）。
// 許可の中身（`ro`に書込・削除のビットが無い、どのモードも`WRITE_DAC`を持たない）は
// `workspace_aces`の単体テストが毎回固定している。**失ったもの**は、削除・DACLの書き換え・実行の
// 拒否を実子で確かめる部分と、256ノードの深い木での確かめで、復元が要るならこのコミットの親から取る。

//
// **削除済み（2026-09-30）**: 自分で宣言した消す条件を満たした一回性の測定2本（規則2）。
// - `acl_propagation_probe_tests`（残課題#32の機序を決めるプローブ）: 機序は確定し、結論は
//   `plans/mac-spike/RESULTS.md` §S11（T3）へ移してある。回帰は残す側の`acl_dacl_write_tests`と
//   `acl_baseline_cost_tests`のM1が持つ。
// - `acl_dacl_size_limit_tests`（1ノードに載るACEの本数の上限、#20の測定M3-b）: 上限は1,168本で、
//   超えるとエラーで止まり、無言の切り捨ては観測されなかった（§S15-3）。常設の回帰へ格上げする
//   条件（無言の切り捨て）を満たさず、#20が閉じた（2026-09-01）ので消した。
// 復元が要るならこのコミットの親から取る。

/// [`acl_dacl_write`]（1ノードあたりDACL書込1回でM本のACEを配る部品）の受け入れ。
/// **こちらは残す**——残課題#32が再発したら赤くなる回帰である。**非昇格**。
#[cfg(all(windows, test))]
mod acl_dacl_write_tests;

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

/// [BUG-169] 子のトークンへ積む宛先の**組み立て点が増えていないか**をソースで数える。
/// 昇格も実機も要らない（落ちるのが`#[ignore]`のテストだけだと7日間気付かれない、という
/// のがBUG-169の学びである）。
#[cfg(all(windows, test))]
mod domain_capabilities_tests;

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
