//! AppContainer子プロセスの起動（`CreateProcessW` + `SECURITY_CAPABILITIES`）と、
//! `--cow`時のRedirector DLL注入。
//!
//! 話す相手はWin32のプロセス/パイプAPI。ACLは触らない（付与は`acl_grant`、'撤収は`revoke`）。

use super::*;

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

/// D-30: Redirector DLL（`harness-redirector.dll`）のパス。`harness-privhelper.exe`と同じ規約
/// （`privhelper::helper_exe_path`）で、本体exeと同じディレクトリから探す。cdylibの出力
/// ファイル名はパッケージ名のハイフンをアンダースコアへ変換した`harness_redirector.dll`。
pub(crate) fn redirector_dll_path() -> Result<PathBuf, AppContainerError> {
    let current = std::env::current_exe()
        .map_err(|e| AppContainerError::Win32(format!("current_exe: {e}")))?;
    let dir = current.parent().ok_or_else(|| {
        AppContainerError::Win32("current_exe has no parent directory".to_string())
    })?;
    Ok(dir.join("harness_redirector.dll"))
}

/// D-37: サンドボックスの子プロセスが`LoadLibraryW`で読み込むRedirector DLL（x64と、WOW64孫
/// 向けのx86）のパス。**実在するものだけ**を返す。
///
/// 共有package SIDだった頃は、リポジトリroot（＝workspace）への継承ACEがたまたま
/// `target/debug/*.dll`まで覆っていたため明示的な付与が不要だった。セッションごとにSIDが
/// 変わる今は、そのセッションのSIDへ読取+実行を明示的に与えないと注入が失敗し、`--cow`の
/// 書込が（境界＝ACLは効いたまま）透過的にupperへ落ちなくなる。
pub(crate) fn redirector_dll_paths() -> Vec<PathBuf> {
    let Ok(x64) = redirector_dll_path() else {
        return Vec::new();
    };
    let x86 = x64
        .parent()
        .map(|dir| dir.join("harness_redirector_x86.dll"));
    [Some(x64), x86]
        .into_iter()
        .flatten()
        .filter(|p| p.exists())
        .collect()
}

/// D-30: suspended状態の`process`へRedirector DLLを注入する（設計書§10.2手順8-9）。
/// `VirtualAllocEx`+`WriteProcessMemory`でDLLパス文字列（UTF-16）を対象プロセスへ書き込み、
/// `kernel32!LoadLibraryW`を開始アドレスとする`CreateRemoteThread`でロードさせる。
///
/// **既知の制約**: `CreateRemoteThread`のスレッド開始関数シグネチャは`DWORD`（32bit）を
/// 返す前提だが`LoadLibraryW`は`HMODULE`（64bitポインタ）を返すため、`GetExitCodeThread`で
/// 取得できるのは戻り値の下位32bitのみである。ここでは「非ゼロなら成功」の粗い判定に留め、
/// 正確な初期化完了確認はDLL側が書き込む`HARNESS_COW_READY_HANDLE`（`wait_cow_ready`）に委ねる。
unsafe fn inject_redirector(process: HANDLE) -> Result<(), AppContainerError> {
    let dll_path = redirector_dll_path()?;
    if !dll_path.exists() {
        return Err(AppContainerError::Win32(format!(
            "redirector DLL not found at {} (expected next to the harness executable)",
            dll_path.display()
        )));
    }
    let path_w: Vec<u16> = dll_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let size = path_w.len() * std::mem::size_of::<u16>();

    unsafe {
        let remote_buf = VirtualAllocEx(
            process,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_buf.is_null() {
            return Err(AppContainerError::Win32(
                "VirtualAllocEx(redirector path) failed".to_string(),
            ));
        }

        let write_ok = WriteProcessMemory(
            process,
            remote_buf,
            path_w.as_ptr() as *const c_void,
            size,
            None,
        );
        if write_ok.is_err() {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
            return Err(AppContainerError::Win32(
                "WriteProcessMemory(redirector path) failed".to_string(),
            ));
        }

        let kernel32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let kernel32 = match GetModuleHandleW(PCWSTR(kernel32_name.as_ptr())) {
            Ok(h) => h,
            Err(e) => {
                let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
                return Err(AppContainerError::Win32(format!(
                    "GetModuleHandleW(kernel32.dll): {e}"
                )));
            }
        };
        let load_library_addr =
            GetProcAddress(kernel32, windows::core::PCSTR(c"LoadLibraryW".as_ptr() as *const u8));
        let Some(load_library_addr) = load_library_addr else {
            let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
            return Err(AppContainerError::Win32(
                "GetProcAddress(LoadLibraryW) failed".to_string(),
            ));
        };
        let start_routine: windows::Win32::System::Threading::LPTHREAD_START_ROUTINE =
            Some(std::mem::transmute::<
                *const c_void,
                unsafe extern "system" fn(*mut c_void) -> u32,
            >(load_library_addr as *const c_void));

        let mut thread_id: u32 = 0;
        let remote_thread = CreateRemoteThread(
            process,
            None,
            0,
            start_routine,
            Some(remote_buf),
            0,
            Some(&mut thread_id),
        );
        let remote_thread = match remote_thread {
            Ok(h) => h,
            Err(e) => {
                let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
                return Err(AppContainerError::Win32(format!(
                    "CreateRemoteThread(LoadLibraryW): {e}"
                )));
            }
        };

        // LoadLibraryW自体の完了（≠フック初期化完了、それは`wait_cow_ready`が確認する）を
        // 短時間だけ待つ。DLLロード自体は通常数十ms未満で終わるため5秒で十分。
        WaitForSingleObject(remote_thread, 5000);
        let mut exit_code: u32 = 0;
        let _ = GetExitCodeThread(remote_thread, &mut exit_code);
        let _ = CloseHandle(remote_thread);
        let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);

        if exit_code == 0 {
            return Err(AppContainerError::Win32(
                "LoadLibraryW returned NULL in target process (redirector DLL failed to load)"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// D-30: Redirector DLLが`HARNESS_COW_READY_HANDLE`へ1バイト書き込むのを`timeout`まで待つ
/// （設計書§10.2手順9「DLL初期化完了を確認する」）。別スレッドで`ReadFile`を行い
/// `mpsc::recv_timeout`で待つ——匿名パイプの読み取り端は`WaitForSingleObject`で
/// シグナル状態を待てないため。
fn wait_cow_ready(ready_read: HANDLE, timeout: std::time::Duration) -> Result<(), String> {
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    let handle = SendHandle(ready_read);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let handle = handle;
        let mut buf = [0u8; 1];
        let mut read_bytes = 0u32;
        let ok = unsafe { ReadFile(handle.0, Some(&mut buf), Some(&mut read_bytes), None) };
        let _ = tx.send(ok.is_ok() && read_bytes == 1);
    });
    match rx.recv_timeout(timeout) {
        Ok(true) => Ok(()),
        Ok(false) => Err("redirector DLL signaled failure (hook install did not succeed)".to_string()),
        Err(_) => Err(format!(
            "timed out after {timeout:?} waiting for redirector DLL ready signal"
        )),
    }
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
        stdin_payload: Option<&[u8]>,
    ) -> Result<(String, String, i32), AppContainerError> {
        if let Some(payload) = stdin_payload {
            if let Some(stdin) = self.stdin_write.take() {
                write_all(stdin, payload);
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

/// `--cow`（D-30）時にRedirector DLLを注入するための設定。`spawn`/`spawn_impl`は`Some`の
/// ときのみ、`CREATE_SUSPENDED`起動窓（§10.2）でDLLを注入し、初期化完了イベントを待って
/// から`ResumeThread`する。`None`（既定・D-29）ではこの一連の処理を一切行わない。
#[derive(Debug, Clone, Copy)]
pub struct CowInject<'a> {
    pub workspace_root: &'a Path,
    pub upper_dir: &'a Path,
    /// Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴。
    /// Redirector DLLへ`HARNESS_COW_EXT_ROOTS`として渡し、これら配下への書込も`_ext/<key>`
    /// 経由で操作台帳へcaptureする。空なら`--cow`単体（workspace内のみcapture、既存挙動）。
    pub ext_capture_roots: &'a [PathBuf],
}

/// AppContainer属性（`SECURITY_CAPABILITIES`）を付けて`CreateProcessW`で子を起動する。
/// Tier1の`CreateProcessAsUserW`+制限トークンとは別方式: トークンは差し替えず、呼び出し
/// スレッド自身のトークンのまま拡張属性リストでAppContainerへ閉じ込める。そのため
/// `SeAssignPrimaryTokenPrivilege`系の罠（BUG-003）はTier2aには存在しない。
///
/// `net`が`InternetClient`のときのみcapability配列に`internetClient` SIDを1個積む。SIDの
/// 生成（`ConvertStringSidToSidW`）と解放（`LocalFree`）はこの関数内に閉じ込め、呼び出し側へ
/// unsafeなSID寿命管理を漏らさない。
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
    cow: Option<CowInject<'_>>,
) -> Result<AppContainerChild, AppContainerError> {
    const SE_GROUP_ENABLED: u32 = 0x0000_0004;

    // D-37: package SIDはセッションごとに変わるが、祖先ディレクトリのtraverse ACEは
    // harness共通のcapability SID宛に一度だけ付与してある。そのcapabilityを常にトークンへ
    // 積む（これが無いと、新しいセッションのpackage SIDでは祖先を辿れずFS I/Oが落ちる）。
    // networkのcapability（`internetClient`）とは目的も寿命も直交する。
    let traverse_cap = super::traverse_capability_sid()?;
    let mut capabilities = vec![SID_AND_ATTRIBUTES {
        Sid: traverse_cap.as_psid(),
        Attributes: SE_GROUP_ENABLED,
    }];

    match net {
        NetworkCapability::Deny => {
            spawn_impl(
                exe,
                args,
                cwd,
                env,
                want_stdin,
                container_sid,
                &capabilities,
                cow,
            )
        }
        NetworkCapability::InternetClient => unsafe {
            let mut cap_sid = PSID::default();
            let sid_str = wide("S-1-15-3-1");
            ConvertStringSidToSidW(PCWSTR(sid_str.as_ptr()), &mut cap_sid).map_err(|e| {
                AppContainerError::Win32(format!("ConvertStringSidToSidW(internetClient): {e}"))
            })?;
            capabilities.push(SID_AND_ATTRIBUTES {
                Sid: cap_sid,
                Attributes: SE_GROUP_ENABLED,
            });
            let result = spawn_impl(
                exe,
                args,
                cwd,
                env,
                want_stdin,
                container_sid,
                &capabilities,
                cow,
            );
            let _ = LocalFree(HLOCAL(cap_sid.0));
            result
        },
    }
}

/// AppContainer属性（`SECURITY_CAPABILITIES`）を付けて`CreateProcessW`で子を起動する実体。
/// `capabilities`が空なら`CapabilityCount=0`（本番`spawn`の既定=D-02）。空でない配列を渡す
/// 経路は現在`spawn`の`NetworkCapability::InternetClient`のみ。
#[allow(clippy::too_many_arguments)]
fn spawn_impl(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    capabilities: &[SID_AND_ATTRIBUTES],
    cow: Option<CowInject<'_>>,
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

    // D-30（`--cow`）: Redirector DLL初期化完了をLauncherへ知らせるための子側書込端。
    // `appcontainer_pipe`は既にpackage SIDへのACL付与を済ませているため、名前付きイベントを
    // 別途ACL構成するより既存の実績あるパイプ生成経路を再利用する（stdio 3本と同じ扱い）。
    let ready_pipe = if cow.is_some() {
        let (r, w) =
            appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(cow-ready)", e))?;
        clear_inherit(r);
        Some((r, w))
    } else {
        None
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
    // D-30: CoW有効時、Redirector DLL（`harness-redirector`）へworkspace/upperのパスと
    // 準備完了通知用パイプの生ハンドル値を環境変数経由で渡す。ハンドル値はプロセス作成時に
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`（下記）で継承させるため、子プロセス内でも
    // 同一の数値のまま有効である（Windowsのハンドル継承の仕様）。
    let mut env_owned;
    let env = if let (Some(c), Some((_, ready_write))) = (cow, &ready_pipe) {
        env_owned = env.to_vec();
        env_owned.push((
            "HARNESS_COW_WORKSPACE".to_string(),
            c.workspace_root.to_string_lossy().into_owned(),
        ));
        env_owned.push((
            "HARNESS_COW_UPPER".to_string(),
            c.upper_dir.to_string_lossy().into_owned(),
        ));
        env_owned.push((
            "HARNESS_COW_READY_HANDLE".to_string(),
            (ready_write.0 as usize).to_string(),
        ));
        if !c.ext_capture_roots.is_empty() {
            let joined = c
                .ext_capture_roots
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(";");
            env_owned.push(("HARNESS_COW_EXT_ROOTS".to_string(), joined));
        }
        &env_owned
    } else {
        env
    };
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

    // INV-2（ハンドル継承対策、設計書§23）: `bInheritHandles=true`のまま無制限に継承させず、
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`でstdioの3本（子側の書込/読取端のみ、いずれも
    // `create_pipe_with_sddl`が既に`bInheritHandle=true`で作成済み・親側端は上で`clear_inherit`
    // 済み）に限定する。リスト中の全ハンドルが継承可能である必要があるため、この配列は
    // `STARTUPINFOEXW`のhStdOutput/hStdError/hStdInputと完全に一致させる。
    let mut inherit_handles: Vec<HANDLE> = vec![stdout_write, stderr_write];
    if let Some(r) = stdin_read {
        inherit_handles.push(r);
    }
    if let Some((_, ready_write)) = &ready_pipe {
        inherit_handles.push(*ready_write);
    }

    let result: Result<PROCESS_INFORMATION, AppContainerError> = unsafe {
        let mut attr_list_size: usize = 0;
        // 1回目は必要サイズ取得のためだけの呼び出しで、バッファ不足エラーになるのが正常
        // （ERROR_INSUFFICIENT_BUFFER）なので戻り値は捨てる。属性数2
        // （SECURITY_CAPABILITIES + HANDLE_LIST）。
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            2,
            0,
            &mut attr_list_size,
        );
        let mut attr_list_buf = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut c_void);
        let init_result = InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_list_size)
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
            .map_err(|e| step("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)", e))
            .and_then(|()| {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(inherit_handles.as_mut_ptr() as *const c_void),
                    inherit_handles.len() * std::mem::size_of::<HANDLE>(),
                    None,
                    None,
                )
                .map_err(|e| step("UpdateProcThreadAttribute(HANDLE_LIST)", e))
            });

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
                // `CREATE_SUSPENDED`（設計書§10.2）: メインスレッドを起こす前に
                // `AssignProcessToJobObject`を完了させ、子がJob Object外で孫プロセスを
                // 作れる窓（TOCTOU）を無くす。Phase 2のDLL注入もこの一時停止窓で行う。
                CreateProcessW(
                    None,
                    PWSTR(cmdline_w.as_mut_ptr()),
                    None,
                    None,
                    true,
                    EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_NO_WINDOW
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_SUSPENDED,
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
        if let Some((_, ready_write)) = &ready_pipe {
            let _ = CloseHandle(*ready_write);
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
                if let Some((ready_read, _)) = &ready_pipe {
                    let _ = CloseHandle(*ready_read);
                }
            }
            return Err(e);
        }
    };

    unsafe {
        // suspended状態のうちにJobへ割り当ててからResumeする（INV-2/§10.2）。ここで失敗した
        // 場合、suspendedのままの孤立プロセスを残さないよう強制終了してから返す。
        if let Err(e) = AssignProcessToJobObject(job, process_info.hProcess)
            .map_err(|e| step("AssignProcessToJobObject", e))
        {
            let _ = TerminateProcess(process_info.hProcess, 1);
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            let _ = CloseHandle(job);
            let _ = CloseHandle(stdout_read);
            let _ = CloseHandle(stderr_read);
            if let Some(w) = stdin_write {
                let _ = CloseHandle(w);
            }
            if let Some((ready_read, _)) = &ready_pipe {
                let _ = CloseHandle(*ready_read);
            }
            return Err(e);
        }

        // D-30（`--cow`）: suspended窓でRedirector DLLを注入する（設計書§10.2手順8-10）。
        // 注入または初期化確認に失敗した場合、対象プロセスを終了する（fail-close、
        // §10.2既定・§25.1）。workspace本体はACLで既にRO付与済みのため、この失敗パスは
        // 「透過リダイレクトが効かないまま起動を許す」ことはない——単に起動自体を拒否する。
        if let Some(c) = cow {
            if let Some((ready_read, _)) = ready_pipe {
                let inject_result: Result<(), AppContainerError> =
                    inject_redirector(process_info.hProcess).and_then(|()| {
                        wait_cow_ready(ready_read, std::time::Duration::from_secs(5))
                            .map_err(AppContainerError::Win32)
                    });
                let _ = CloseHandle(ready_read);
                if let Err(e) = inject_result {
                    let _ = TerminateProcess(process_info.hProcess, 1);
                    let _ = CloseHandle(process_info.hThread);
                    let _ = CloseHandle(process_info.hProcess);
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(stdout_read);
                    let _ = CloseHandle(stderr_read);
                    if let Some(w) = stdin_write {
                        let _ = CloseHandle(w);
                    }
                    return Err(AppContainerError::Win32(format!(
                        "cow redirector injection failed for workspace {}: {e}",
                        c.workspace_root.display()
                    )));
                }
            }
        }

        let _ = ResumeThread(process_info.hThread);
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
