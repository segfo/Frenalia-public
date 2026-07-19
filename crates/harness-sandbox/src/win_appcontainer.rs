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
//! **将来の拡張余地（未実装）**: `internetClient`（`S-1-15-3-1`）等のcapability SIDを
//! 許可リストとして足す口は、必要になった時点で`ensure_profile`/`spawn`のcapability引数を
//! 空でなくする形で足せる。現時点では使われない拡張ポイントを先回りで作らない。

use std::ffi::c_void;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SE_KERNEL_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, FreeSid, NO_INHERITANCE,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
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

/// AppContainer属性（`SECURITY_CAPABILITIES`、capability無し=既定deny）を付けて
/// `CreateProcessW`で子を起動する。Tier1bの`CreateProcessAsUserW`+制限トークンとは別方式:
/// トークンは差し替えず、呼び出しスレッド自身のトークンのまま拡張属性リストで
/// AppContainerへ閉じ込める。そのため`SeAssignPrimaryTokenPrivilege`系の罠（BUG-003）は
/// Tier1aには存在しない。
pub fn spawn(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
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

    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: container_sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
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
        let child = spawn(&cmd_exe, &["/d", "/c", "dir"], dir, &env, false, sid)
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
