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

    /// 子プロセスのPID。M15.7のOS監査収集器が「このETWイベントは誰のものか」を
    /// 突き合わせるのに使う（ETWは`EventHeader.ProcessId`しか運ばないため、
    /// 起動側でPIDを知っておく必要がある）。
    pub fn pid(&self) -> u32 {
        unsafe { windows::Win32::System::Threading::GetProcessId(self.process) }
    }

    /// D-38/`DESIGN-MCP.md` §3.3: 一問一答ではなく、プロセスを生かしたまま何度も往復させる
    /// 長寿命セッションへ変換する（MCP stdio用）。`want_stdin: true`で起動したものだけが
    /// 変換できる——書き込み口が無いセッションは往復できない。
    ///
    /// 変換後はこの`AppContainerChild`のDropを走らせない（ハンドルの所有権が
    /// [`super::spawn_session::AppContainerSession`]へ移るため）。
    pub fn into_session(
        mut self,
    ) -> Result<super::spawn_session::AppContainerSession, AppContainerError> {
        let Some(stdin_write) = self.stdin_write.take() else {
            // ここでErrを返した場合はDropが通常どおり走り、残りのハンドルを閉じる。
            return Err(AppContainerError::Win32(
                "a long-lived session requires a stdin pipe (spawn with want_stdin = true)"
                    .to_string(),
            ));
        };
        let (process, job, stdout_read, stderr_read) =
            (self.process, self.job, self.stdout_read, self.stderr_read);
        std::mem::forget(self);
        Ok(super::spawn_session::AppContainerSession::new(
            process,
            job,
            stdin_write,
            stdout_read,
            stderr_read,
        ))
    }

    /// ストリーミング版: stdin送出後、stdout/stderrを行単位で`OutputEvent`として流しつつ、
    /// プロセス終了を別イベントとして通知する（ポリシーエディタのパス2＝Tier2aでのドメイン記録
    /// のライブ表示用、`plans/POLICY-EDITOR-TOMOYO-DIG.md`参照）。
    ///
    /// 実装はTier1の`RestrictedChild::spawn_streaming`と**同じ関数**を共有する
    /// （`win_common::stream_child_output`）——両者はHANDLEの構成が同形であり、
    /// 「`Exited`と`OutputClosed`を独立させる」「待機スレッドがjobを閉じて居残った子孫を
    /// 巻き取る」という作法をTierごとに書き直すと片方だけ直る事故になる。
    pub fn spawn_streaming(
        mut self,
        stdin_payload: Option<&[u8]>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<crate::win_common::OutputEvent> {
        let stdin_write = self.stdin_write.take();
        let (process, job, stdout_read, stderr_read) =
            (self.process, self.job, self.stdout_read, self.stderr_read);
        std::mem::forget(self);

        crate::win_common::stream_child_output(
            process,
            job,
            stdin_write,
            stdout_read,
            stderr_read,
            stdin_payload,
        )
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

/// Redirector DLLへ渡すルートパスの綴りを揃える（[BUG-066](../../../../docs/bugs/BUG-066.md)）。
///
/// DLLは受け取った文字列で「このパスはworkspace配下か」を判定するため、`--cwd`の綴りが
/// そのまま届くと表記ゆれで照合が外れる。外れると**workspace内への書込が1件残らずACL拒否**に
/// なり（＝`--cow`の透過性が全滅し）、しかもそれが「workspace外への書込が拒否された」ように
/// 見える。ここが`CowInject`を使う唯一の絞り（env・注入blobの両方がこの値から作られる）
/// なので、渡す前に一度だけ揃える:
///
/// - `canonicalize`で相対パス（`--cwd .`）と`..`・8.3短縮名・シンボリックリンクを解決する
/// - `\\?\`前置と末尾区切りを落とす（`normalize_root_spelling`。DLL側の`nt_path_wide`が
///   `\??\`を前置するので、verbatim形のまま渡すと不正なNTパスになる）
///
/// `canonicalize`が失敗する場合（存在しないパス等）は綴りを揃えるだけに留める——ここは
/// 境界ではないので、失敗しても起動を止める理由にはならない（D-01。workspaceはROのまま）。
fn normalize_cow_root(path: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    PathBuf::from(harness_change_ledger::path_rules::normalize_root_spelling(
        &resolved.to_string_lossy(),
    ))
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
    spawn_with_workspace(exe, args, cwd, env, want_stdin, container_sid, net, cow, None)
}

/// [`spawn`]の、**workspaceツリーへのアクセスを与える版**（D-54）。
///
/// workspace本体のACEはworkspace＋モード単位のcapability SID宛に付いている
/// （[`crate::tier2a::workspace_capability`]）ので、workspaceを読み書きする子には
/// そのcapabilityをトークンへ積まないと何も見えない。
///
/// **既定（[`spawn`]）は積まない側**である。積まないと起こるのは`ACCESS_DENIED`＝
/// fail-closedであり、逆向き（うっかり積む）だと境界が黙って消える。実際、MCPサーバは
/// 専用プロファイルで起動し**workspaceを既定で持たない**（D-38 §3.2）——ここが既定で
/// 積む設計だったら、MCPサーバがworkspace全体へ到達していた。
#[allow(clippy::too_many_arguments)]
pub fn spawn_with_workspace(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
    cow: Option<CowInject<'_>>,
    workspace_cap: Option<PSID>,
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
    // D-54: workspaceツリーのACEの主体。呼び出し側が明示したときだけ積む（上記doc）。
    if let Some(sid) = workspace_cap {
        capabilities.push(SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: SE_GROUP_ENABLED,
        });
    }

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
        // BUG-066: 綴りを揃えてから渡す（`normalize_cow_root`のdoc参照）。
        env_owned.push((
            "HARNESS_COW_WORKSPACE".to_string(),
            normalize_cow_root(c.workspace_root).to_string_lossy().into_owned(),
        ));
        env_owned.push((
            "HARNESS_COW_UPPER".to_string(),
            normalize_cow_root(c.upper_dir).to_string_lossy().into_owned(),
        ));
        env_owned.push((
            "HARNESS_COW_READY_HANDLE".to_string(),
            (ready_write.0 as usize).to_string(),
        ));
        if !c.ext_capture_roots.is_empty() {
            let joined = c
                .ext_capture_roots
                .iter()
                .map(|p| normalize_cow_root(p).to_string_lossy().into_owned())
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

#[cfg(test)]
mod normalize_cow_root_tests {
    use super::*;

    /// **BUG-066の追加検証（2026-08-06）**: Redirector DLLへ渡す直前の正規化が、候補だった
    /// 4つの綴りを**同一のcanonical絶対パス**へ畳むこと。ここが効いている限り、DLLは
    /// 表記ゆれを一切見ない（DLL側の`relative_under_root`は二重の保険という位置付けになる）。
    #[test]
    fn every_workspace_root_spelling_folds_to_the_same_canonical_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path();
        let expected = normalize_cow_root(real);
        assert!(expected.is_absolute(), "canonical form must be absolute: {expected:?}");
        assert!(
            !expected.to_string_lossy().starts_with(r"\\?\"),
            "verbatim prefix must be stripped so nt_path_wide can prepend \\??\\: {expected:?}"
        );

        let spellings = [
            PathBuf::from(real.to_string_lossy().to_uppercase()),
            PathBuf::from(format!("{}\\", real.to_string_lossy())),
            PathBuf::from(format!(r"\\?\{}", real.to_string_lossy())),
        ];
        for spelling in spellings {
            assert_eq!(
                normalize_cow_root(&spelling),
                expected,
                "spelling {spelling:?} must fold to the canonical form"
            );
        }
    }

    /// 相対パス（`--cwd .`）は**プロセスのcwdを基準に**絶対化される。実運用では
    /// harnessプロセスのcwdが利用者の意図したworkspaceなので、これが正しい解決になる
    /// （プロセスのcwdは変更しない——並行テストを壊さないため、`current_dir()`と比較する）。
    #[test]
    fn a_relative_root_is_resolved_against_the_process_cwd() {
        let cwd = std::env::current_dir().expect("current_dir");
        assert_eq!(normalize_cow_root(Path::new(".")), normalize_cow_root(&cwd));
        assert!(normalize_cow_root(Path::new(".")).is_absolute());
    }

    /// 存在しないパスは`canonicalize`できないので綴りの正規化だけが効く（起動は止めない、
    /// D-01: ここは境界ではない）。**絶対パスにはならない**ので、この場合はDLL側が
    /// 警告台帳へ`config_workspace_not_absolute`を残す方の防御が働く。
    #[test]
    fn a_nonexistent_relative_path_is_only_spelling_normalized() {
        let normalized = normalize_cow_root(Path::new(r"no-such-dir-9f3a\"));
        assert_eq!(normalized, PathBuf::from("no-such-dir-9f3a"));
        assert!(!normalized.is_absolute());
    }
}
