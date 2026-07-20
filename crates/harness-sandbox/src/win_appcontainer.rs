//! Windows Tier1a: AppContainer（package SID + capability SID）。
//! `plans/DESIGN-SANDBOX.md` §6.3/§7 D-02参照。実験的・オプトイン（`--experimental-tier1a`）。
//!
//! Tier1b（`win_restricted`、制限トークン + 低IL）と異なり、Tier1aは**トークンを差し替えず**
//! `CreateProcessW`の拡張属性リストに`SECURITY_CAPABILITIES`を積むことで、呼び出しスレッド
//! 自身のトークンのまま子をAppContainerへ閉じ込める（別メカニズム）。
//!
//! capability配列は既定で空にする（`CreateAppContainerProfile`のcapabilities引数無し・
//! 起動時の`SECURITY_CAPABILITIES.CapabilityCount=0`）。これによりnetworkを含む全
//! capability-gatedリソースがdefault-denyになり、T-10（子の直接ソケット送出）対策の核が成立する。
//! 範囲外書込・範囲外読取もpackage SIDへの明示ACE無しには許可されないため、T-04（`~/.ssh`等の
//! read→exfil）も併せて防ぐ（Tier1bが守れない2つの脅威、`plans/DESIGN-SANDBOX.md` §8-1）。
//!
//! **最小スコープ（意図的な割り切り）**: ACL付与対象は`workspace_root`とその配下の
//! セッション専用一時ディレクトリのみ。`.cargo`/`%APPDATA%`/rustup等のツールチェーン
//! グローバルパスへは付与しないため、cargo/rustc/git等の複雑なツールチェーンコマンドは
//! Tier1a下でaccess-deniedになり得る（`docs/phases/foundation/M12-shell-isolation-tiers.md`
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
    CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    SetSecurityInfo, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, FreeSid, NO_INHERITANCE,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows::Win32::System::JobObjects::AssignProcessToJobObject;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::win_common::{
    build_env_block, clear_inherit, create_job_object, create_pipe_with_sddl, read_to_string,
    wide, write_all,
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
        let desc_w = wide(
            "AppContainer for harness run_shell Tier1a (experimental, see plans/DESIGN-SANDBOX.md SS6.3)",
        );

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
fn grant_ace_mask(
    path: &Path,
    sid: PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
) -> Result<(), AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
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

        let set_result = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const _),
            None,
        )
        .ok();

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
/// Tier1bの`cwd`全体ラベル付与と整合させる設計判断。理由は`docs/phases/foundation/`参照）。
pub fn grant_ace_recursive(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files).map_err(|e| AppContainerError::AclGrant {
        path: root.to_path_buf(),
        reason: e.to_string(),
    })?;
    for dir in &dirs {
        grant_ace(dir, sid, true)?;
    }
    for file in &files {
        grant_ace(file, sid, false)?;
    }
    Ok(())
}

/// AppContainer固有のセキュリティ記述子をパイプへ適用する。AppContainerのアクセス制御は
/// 「オブジェクトのDACLにpackage SID（または`ALL APPLICATION PACKAGES`）へのACEが無ければ
/// アクセス不可」という広範なdefault-denyがファイル・レジストリだけでなく名前無しパイプ等の
/// カーネルオブジェクトにも及ぶ可能性が高い（Tier1bで実機発見した「既定DACLの匿名パイプは
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

        let out = read_to_string(self.stdout_read);
        let err = read_to_string(self.stderr_read);

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

/// Tier1a子プロセスへ与えるnetwork capability（D-10、`plans/DESIGN-SANDBOX-APPPOLICY.md` §3）。
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
/// Tier1bの`CreateProcessAsUserW`+制限トークンとは別方式: トークンは差し替えず、呼び出し
/// スレッド自身のトークンのまま拡張属性リストでAppContainerへ閉じ込める。そのため
/// `SeAssignPrimaryTokenPrivilege`系の罠（BUG-003）はTier1aには存在しない。
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
        NetworkCapability::Deny => {
            spawn_impl(exe, args, cwd, env, want_stdin, container_sid, &[])
        }
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
            let result = spawn_impl(exe, args, cwd, env, want_stdin, container_sid, &capabilities);
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
    let step = |label: &'static str, e: windows::core::Error| AppContainerError::Win32(format!("{label}: {e}"));

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

/// Tier1a（AppContainer）で使うシェルの実行ファイルパスとラベルを解決する。
/// **ストアアプリの実行エイリアス（`WindowsApps`配下の0バイトreparse point）は
/// AppContainerから解決できず`CreateProcessW`が`ERROR_INVALID_PARAMETER`で失敗する**ため、
/// pwshの実体がそこにある場合は使わず、実在の Windows PowerShell 5.1（System32の本物のexe、
/// 決してエイリアスにならない）へフォールバックする。smoke testと`run_shell`本体の両方で
/// この同一解決を使い、「smokeが通ったのに本番で別のexeを使って失敗する」ずれを防ぐ。
pub fn resolve_shell() -> (String, &'static str) {
    if let Ok(p) = which::which("pwsh") {
        let s = p.to_string_lossy();
        if !s.to_ascii_lowercase().contains("windowsapps") {
            return (s.into_owned(), "pwsh(tier1a)");
        }
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    (
        format!("{system_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        "powershell5.1(tier1a)",
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

fn smoke_test_spawn(sid: PSID, workspace_root: &Path, probe_dir: &Path) -> Result<(), AppContainerError> {
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
        &["-NoProfile", "-NonInteractive", "-Command", FS_IO_PROBE_COMMAND],
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

/// harness起動時に1回だけ呼ぶ。プロファイル作成→ACL付与→起動smokeテストの一連を行い、
/// いずれか失敗したら理由文字列を返す（`shell_tier::best_effort_tier`がTier1bへの降格理由
/// としてそのまま使う）。判断は実行前に完結させ、`run_shell`個々の呼び出し中には降格ロジックを
/// 一切持たせない（非冪等コマンドの二重実行を避けるための意図的判断）。
pub fn preflight(workspace_root: &Path) -> Result<(), AppContainerError> {
    let sid = ensure_profile(CONTAINER_NAME)?;
    grant_ace_recursive(workspace_root, sid.as_psid())?;
    let tmp_dir = workspace_root
        .join(".harness")
        .join("sandbox")
        .join("tier1a-tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    smoke_test_spawn(sid.as_psid(), workspace_root, &tmp_dir)?;
    Ok(())
}

/// `path`のDACLから、`sid`（trustee）に対する既存ACEを全て取り除く（`REVOKE_ACCESS`）。
/// `TIER1A-OPEN-ISSUES.md`課題1のプロファイルtraverse実験（Experiment B）で、実プロファイルへ
/// 付与した一時ACEを実験後に必ず原状復帰させるための後始末専用ヘルパ。`grant_ace_mask`と対に
/// なるが、恒久機能（`preflight`/`spawn`等）からは呼ばれない診断専用コード。
#[cfg(all(windows, test))]
fn revoke_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    use windows::Win32::Security::Authorization::REVOKE_ACCESS;

    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
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
        .ok()
        .map_err(to_err)?;

        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0,
            grfAccessMode: REVOKE_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let entries_result =
            SetEntriesInAclW(Some(&[ea]), Some(existing_dacl as *const _), &mut new_dacl).ok();
        if let Err(e) = entries_result {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(to_err(e));
        }

        let set_result = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const _),
            None,
        )
        .ok();

        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
        set_result.map_err(to_err)?;
    }
    Ok(())
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
        println!("=== probe: shell={shell} ({label}), dir={} ===", dir.display());
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
    /// ACCESS_DENIED）を切り分けるための、cmd.exe版プローブ。`resolve_shell`はTier1a本番と
    /// 同じPowerShell解決を返すためここでは使わず、cmd.exeを直接指定する。
    fn run_probe_cmd(sid: PSID, dir: &Path) {
        let system_root =
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let cmd_exe = format!("{system_root}\\System32\\cmd.exe");
        println!("=== probe(cmd.exe): dir={} ===", dir.display());
        let env = crate::secret_env::build_child_env();
        let child = spawn(&cmd_exe, &["/d", "/c", "dir"], dir, &env, false, sid, NetworkCapability::Deny)
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
        let child = spawn(&shell, &["-NoProfile", "-NonInteractive", "-Command", command], &dir, &env, false, sid.as_psid(), NetworkCapability::Deny)
            .expect("spawn should succeed");
        let (out, err, code) = child.write_stdin_read_output_and_wait(None).expect("pipe I/O should not fail");
        println!("=== AppContainer child integrity level probe: exit={code} ===\n--- stdout ---\n{out}\n--- stderr ---\n{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Experiment F: ゼロcapability（`CapabilityCount=0`）自体が削除拒否の原因かを切り分ける
    /// 診断実験。`internetClient`相当のcapabilityを1つだけ付けた場合に`Remove-Item`が通るかを
    /// 確認する。**これはTier1aのnetwork default-deny（T-10対策の核）を一時的に崩す診断専用の
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
            "C:\\harness-tier1a-verify-f-{}",
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
            let command = "Remove-Item -LiteralPath 'f-probe.tmp' -Force -ErrorAction SilentlyContinue; \
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

        revoke_ace(&ancestor, sid.as_psid()).expect("revert: revoke_ace on profile ancestor must not fail silently");
    }

    fn dirs_home() -> Option<std::path::PathBuf> {
        std::env::var("USERPROFILE").ok().map(std::path::PathBuf::from)
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
    /// ドライブルート直下の浅いワークスペース`C:\harness-tier1a-verify-<pid>`を使う。これにより
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
        let workspace = std::path::PathBuf::from(format!(
            "C:\\harness-tier1a-verify-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

        // ワークスペース作成+フルアクセス付与（既存`preflight`と同じ手順）。
        std::fs::create_dir_all(&workspace).expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");
        let probe_dir = workspace.join(".harness").join("sandbox").join("tier1a-tmp");
        std::fs::create_dir_all(&probe_dir).expect("create probe dir (inherits ACE from workspace)");

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
            // `.harness/sandbox/tier1a-tmp`）。panicさせずResultで受ける。
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
            env.push(("HARNESS_PROBE_DIR".to_string(), workspace.to_string_lossy().into_owned()));
            let child = spawn(&shell, &["-NoProfile", "-NonInteractive", "-Command", verbose_probe], &workspace, &env, false, sid.as_psid(), NetworkCapability::Deny)
                .expect("spawn should succeed");
            let (out, err, code) = child.write_stdin_read_output_and_wait(None).expect("pipe I/O should not fail");
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
        let wrapped = format!(
            "try {{ {command} }} catch {{ Write-Output \"CAUGHT: $_\"; exit 1 }}"
        );
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
            CreateWellKnownSid(sid_type, PSID::default(), PSID(buf.as_mut_ptr() as *mut _), &mut size)?;
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
            "C:\\harness-tier1a-verify-d-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

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
                let icacls_out = std::process::Command::new("icacls")
                    .arg(&h1_file)
                    .output();
                match icacls_out {
                    Ok(o) => println!(
                        "=== icacls on freshly-created h1-probe.tmp ===\n{}",
                        String::from_utf8_lossy(&o.stdout)
                    ),
                    Err(e) => println!("=== icacls failed to run: {e} ==="),
                }
            }
            let h1_ok = if h1_create_ok {
                let direct_grant = grant_ace_mask(&h1_file, sid.as_psid(), DELETE.0, NO_INHERITANCE);
                println!("=== H1 direct-grant DELETE on file result: {direct_grant:?} ===");
                direct_grant.is_ok()
                    && run_probe_bool(sid.as_psid(), &workspace, "Remove-Item -LiteralPath 'h1-probe.tmp' -Force")
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
                        run_probe_bool(sid.as_psid(), &workspace, "Remove-Item -LiteralPath 'h1-probe.tmp' -Force")
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
            let h3_access =
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0
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
                match ConvertStringSidToSidW(windows::core::PCWSTR(sid_str.as_ptr()), &mut restricted_sid) {
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
                        println!("=== H4 skipped: ConvertStringSidToSidW(S-1-15-2-2) failed: {e:?} ===");
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
            "C:\\harness-tier1a-verify-g-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

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
            "C:\\harness-tier1a-verify-j-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

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
            "C:\\harness-tier1a-verify-k-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");
        let probe_dir = workspace.join(".harness").join("sandbox").join("tier1a-tmp");
        std::fs::create_dir_all(&probe_dir).expect("create probe dir (inherits ACE from workspace)");

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

    /// procmon実測調査（Tier1a廃止の根拠固め）で共有するプローブスクリプト。
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
            "C:\\harness-tier1a-verify-h-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

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
                &["-NoProfile", "-NonInteractive", "-Command", PROCMON_PROBE_SCRIPT],
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
            "C:\\harness-tier1a-verify-h-control-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace).expect("create control workspace under C:\\ (needs admin)");

        let (shell, _) = resolve_shell();
        let child = std::process::Command::new(&shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", PROCMON_PROBE_SCRIPT])
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
            "C:\\harness-tier1a-verify-i-{}",
            std::process::id()
        ));

        let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
        std::fs::create_dir_all(&workspace)
            .expect("create verify workspace under C:\\ (needs admin write on drive root)");
        grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on verify workspace");

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
                &["-NoProfile", "-NonInteractive", "-Command", PROCMON_PROBE_SCRIPT],
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
    /// `preflight`をこのままTier1b自動降格の唯一の判断根拠として使ってよいかを再検討する必要が
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
}
