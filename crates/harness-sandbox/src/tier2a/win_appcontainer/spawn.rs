//! AppContainer子プロセスの起動（`CreateProcessW` + `SECURITY_CAPABILITIES`）と、
//! `--sandbox tier2a-cow`時のRedirector DLL注入。
//!
//! 話す相手はWin32のプロセス/パイプAPI。ACLは触らない（付与は`acl_grant`、'撤収は`revoke`）。

use super::*;

/// 生成禁止とコンソールの語彙は**Spawn Daemonの電文と同じ型**を使う（`B-13`: 正本を2つ
/// 持たない）。あちらは非Windowsでもコンパイルされるので、置き場もあちら側である
/// ——`win_appcontainer`は`#[cfg(windows)]`なので、ここへ置くと電文が参照できない。
use crate::tier2a::spawnd::{ChildProcessPolicy, ConsoleNeed};

/// AppContainer固有のセキュリティ記述子をパイプへ適用する。AppContainerのアクセス制御は
/// 「オブジェクトのDACLにpackage SID（または`ALL APPLICATION PACKAGES`）へのACEが無ければ
/// アクセス不可」という広範なdefault-denyがファイル・レジストリだけでなく名前無しパイプ等の
/// カーネルオブジェクトにも及ぶ可能性が高い（Tier1で実機発見した「既定DACLの匿名パイプは
/// 低ILの子から書けない」現象と同種、`win_restricted.rs`参照）。**これは設計上の予測であり
/// 実機未検証**——最初の実機テストで子のstdout/stderrが空になる/ハングする場合、
/// 真っ先にここを疑う。
///
/// **`pub(crate)`なのは、Spawn Daemon方式ではこのパイプを作るのがharness側だからである**
/// （§10.1「子のstdioパイプを作るプロセス」＝harness）。Daemonへは子側の端の複製だけが渡る。
pub(crate) fn appcontainer_pipe(sid: PSID) -> windows::core::Result<(HANDLE, HANDLE)> {
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
/// 変わる今は、そのセッションのSIDへ読取+実行を明示的に与えないと注入が失敗し、`--sandbox tier2a-cow`の
/// 書込が（境界＝ACLは効いたまま）透過的に差分層へ落ちなくなる。
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
/// リモートスレッドの`LoadLibraryW`が終わるのを待つ上限（ミリ秒）。
///
/// **5秒では足りない構成がある。** 読み込み自体は通常数十msだが、AppContainerの子が同時に
/// 何本も起きている機械（実機E2Eの全件同時実行）では、そこまで待てずに時間切れになりうる。
/// 待ちを伸ばしても、うまくいく場合の所要時間は変わらない——伸びるのは失敗するときだけである。
const LOAD_LIBRARY_WAIT_MS: u32 = 30_000;

pub(crate) unsafe fn inject_redirector(process: HANDLE) -> Result<(), AppContainerError> {
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
        let load_library_addr = GetProcAddress(
            kernel32,
            windows::core::PCSTR(c"LoadLibraryW".as_ptr() as *const u8),
        );
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

        // LoadLibraryW自体の完了（≠フック初期化完了、それは`wait_cow_ready`が確認する）を待つ。
        // **待ちの結果と終了コードの取得結果を両方見る**——どちらも見ていなかった頃は、
        // 3つの別々の出来事が「LoadLibraryWがNULLを返した」という1つの文言に潰れていた
        // （`bug-pattern-rules` B-09/B-10: 失敗を成功に見せない・別物を同じ名前で報告しない）。
        //
        // | 実際に起きたこと | 旧実装の扱い |
        // |---|---|
        // | 待ちが時間切れ | `exit_code`が`STILL_ACTIVE`(259)のまま＝**成功として素通り** |
        // | `GetExitCodeThread`が失敗 | `exit_code`が初期値0のまま＝「NULLを返した」と誤報 |
        // | 本当にNULLを返した | 同上（正しいのはここだけ） |
        let wait = WaitForSingleObject(remote_thread, LOAD_LIBRARY_WAIT_MS);
        let mut exit_code: u32 = 0;
        let exit_code_read = GetExitCodeThread(remote_thread, &mut exit_code);
        let _ = CloseHandle(remote_thread);

        if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
            return Err(AppContainerError::Win32(format!(
                "the redirector DLL was still loading in the target process after {}s \
                 ({}). The machine may be heavily loaded (many AppContainer children starting at \
                 once); injection is fatal by design, so the child is not started.",
                LOAD_LIBRARY_WAIT_MS / 1000,
                dll_path.display()
            )));
        }
        // **待ちが成功したのは`WAIT_OBJECT_0`のときだけである。** ここを`WAIT_TIMEOUT`との
        // 比較だけで済ませると、`WAIT_FAILED`（ハンドルが無効等）のとき終了コードが
        // `STILL_ACTIVE`(259)のまま＝非0なので、**Redirector DLLが入っていない子をそのまま
        // 起こしてしまう**——上の表が潰したはずの「時間切れが成功に見える」と同じ形が、
        // 経路を変えて残っていた（`bug-pattern-rules` B-09、BUG-165の横展開で発見）。
        if wait != windows::Win32::Foundation::WAIT_OBJECT_0 {
            return Err(AppContainerError::Win32(format!(
                "WaitForSingleObject on the LoadLibraryW thread returned 0x{:08x} ({}): {} — \
                 whether the DLL loaded is unknown, so the child is not started",
                wait.0,
                dll_path.display(),
                windows::core::Error::from_win32()
            )));
        }
        // **DLLのパスを解放するのは、スレッドが終わったと分かってから**（BUG-175の横展開）。
        // 上の2つの失敗ではスレッドがまだそれを読んでいるかもしれない。解放せずに返しても、
        // 呼び出し側は子を起こさずに畳むので残らない。
        let _ = VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        if let Err(e) = exit_code_read {
            return Err(AppContainerError::Win32(format!(
                "GetExitCodeThread after LoadLibraryW({}): {e} — whether the DLL loaded is unknown, \
                 so the child is not started",
                dll_path.display()
            )));
        }
        if exit_code == 0 {
            return Err(AppContainerError::Win32(
                describe_load_library_failure(process, &dll_path),
            ));
        }
    }
    Ok(())
}

/// `LoadLibraryW`がNULLを返したときだけ呼ぶ、**実測の診断**。
///
/// # かつてここは嘘をついていた（[BUG-169]）
///
/// 旧実装は「子のトークンに N 本積んだ」と書きながら、その N を**台帳から撃ち直して**
/// 数えていた。渡した数ではないので、**実際は0本なのに「2本積んだ」と報告**していた。
/// 症状を素直に読むと「宛先は渡っているのにDLLが読めない」になり、調査を丸1回ぶん誤らせた
/// ——原因は「渡っていない」側だった。**報告するのは測った値だけにする。**
///
/// # 見るのは2つで、どちらが欠けているかで直し方が違う
///
/// | 欠けている側 | 意味 | 直す場所 |
/// |---|---|---|
/// | 子のトークン | 起こす側が宛先を積んでいない | トークンを組む場所（`DomainCapabilities`） |
/// | DLLのDACL | 許可が付いていない（付与の失敗・撤収のしすぎ） | `preflight`の付与ブロック |
/// | 両方在る | 別の理由（依存DLLの解決失敗・祖先を辿れない等） | この文面の外 |
///
/// **費用は失敗したときだけ払う。** 正常時はここへ来ないので、トークンの読み出しも
/// DACLの列挙も起こらない。
fn describe_load_library_failure(process: HANDLE, dll_path: &Path) -> String {
    let head = format!(
        "LoadLibraryW returned NULL in target process (redirector DLL failed to load): {}",
        dll_path.display()
    );

    let token = child_token_capability_sids(process);
    let dacl = super::capability_sid_aces(dll_path);

    let (token_sids, token_note) = match token {
        Ok(sids) => (Some(sids), String::new()),
        Err(e) => (None, format!(" [could not read the child token: {e}]")),
    };
    let (dacl_sids, dacl_note) = match dacl {
        Ok(subjects) => (
            Some(subjects.into_iter().map(|s| s.sid).collect::<Vec<_>>()),
            String::new(),
        ),
        Err(e) => (None, format!(" [could not read the DLL's DACL: {e}]")),
    };

    // 突き合わせは**両方読めたときだけ**行う。読めなかった側を「無い」と扱うと、
    // 計器の故障を原因として報告することになる。
    let verdict = match (&token_sids, &dacl_sids) {
        (Some(token), Some(dacl)) => {
            let shared: Vec<&String> = dacl
                .iter()
                .filter(|d| token.iter().any(|t| t.eq_ignore_ascii_case(d)))
                .collect();
            if !shared.is_empty() {
                format!(
                    "the child token and the DLL share {} capability SID(s), so the missing piece \
                     is neither the token nor the DACL — look for a dependency the DLL cannot \
                     resolve, or an ancestor directory the child cannot traverse",
                    shared.len()
                )
            } else if dacl.is_empty() {
                "the DLL carries no capability ACE at all, so the grant in preflight did not land \
                 (or was revoked afterwards)"
                    .to_string()
            } else {
                "the DLL's capability ACEs and the child token have nothing in common: the spawn \
                 built the token without the redirector DLL capability (see DomainCapabilities)"
                    .to_string()
            }
        }
        _ => "one of the two sides could not be measured, so no verdict is given".to_string(),
    };

    format!(
        "{head}\n  child token capability SIDs ({}): {}{token_note}\n  \
         capability SIDs on the DLL ({}): {}{dacl_note}\n  verdict: {verdict}",
        token_sids.as_ref().map_or(0, |v| v.len()),
        token_sids.as_ref().map_or_else(|| "?".to_string(), |v| v.join(", ")),
        dacl_sids.as_ref().map_or(0, |v| v.len()),
        dacl_sids.as_ref().map_or_else(|| "?".to_string(), |v| v.join(", ")),
    )
}

/// 子プロセスのトークンが**実際に持っている** capability SID を読む。
///
/// 起こす側の意図（何を積んだつもりか）ではなく、OSが子へ渡した結果を見る。
/// 失敗したら`Err`にして、それを診断の文面へそのまま載せる——計器が壊れたことを
/// 「capabilityが無い」と読み替えない。
fn child_token_capability_sids(process: HANDLE) -> Result<Vec<String>, String> {
    use windows::Win32::Security::{GetTokenInformation, TokenCapabilities, TOKEN_GROUPS};
    use windows::Win32::System::Threading::OpenProcessToken;

    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, windows::Win32::Security::TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("OpenProcessToken: {e}"))?;

    // **ハンドルは必ず閉じる。** ここは失敗の説明を作るために呼ばれるので、漏らすと
    // 「診断がトークンを掴んだまま」になり、後続の後始末が理由不明で失敗する。
    let read = (|| {
        let mut needed: u32 = 0;
        // 1回目は長さを聞くだけ。バッファ不足は期待どおりの失敗なので結果を見ない。
        let _ = unsafe { GetTokenInformation(token, TokenCapabilities, None, 0, &mut needed) };
        if needed == 0 {
            return Err("GetTokenInformation(TokenCapabilities) asked for a zero-sized buffer"
                .to_string());
        }
        // **`u64`の配列で確保する。** `TOKEN_GROUPS`はポインタを含むので8バイト境界が要り、
        // `Vec<u8>`（境界1）を読み替えると整列が保証されない。
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        unsafe {
            GetTokenInformation(
                token,
                TokenCapabilities,
                Some(buf.as_mut_ptr() as *mut c_void),
                needed,
                &mut needed,
            )
        }
        .map_err(|e| format!("GetTokenInformation(TokenCapabilities): {e}"))?;

        let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
        // `Groups`は可変長配列の先頭1要素として宣言されているので、件数ぶん読み直す。
        let entries =
            unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
        Ok(entries
            .iter()
            .filter_map(|g| crate::win_common::sid_to_string(g.Sid).ok())
            .collect())
    })();

    unsafe {
        let _ = CloseHandle(token);
    }
    read
}

/// D-30: Redirector DLLが`HARNESS_COW_READY_HANDLE`へ1バイト書き込むのを`timeout`まで待つ
/// （設計書§10.2手順9「DLL初期化完了を確認する」）。別スレッドで`ReadFile`を行い
/// `mpsc::recv_timeout`で待つ——匿名パイプの読み取り端は`WaitForSingleObject`で
/// シグナル状態を待てないため。
pub(crate) fn wait_cow_ready(
    ready_read: HANDLE,
    timeout: std::time::Duration,
) -> Result<(), String> {
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
        Ok(false) => {
            Err("redirector DLL signaled failure (hook install did not succeed)".to_string())
        }
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
        terminate_job(self.job);
    }

    pub fn kill_token(&self) -> Result<KillToken, AppContainerError> {
        Ok(KillToken::duplicate(self.job)?)
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

impl Drop for AppContainerChild {
    fn drop(&mut self) {
        unsafe {
            if let Some(h) = self.stdin_write.take() {
                let _ = CloseHandle(h);
            }
            let _ = CloseHandle(self.stdout_read);
            let _ = CloseHandle(self.stderr_read);
            terminate_job_and_close(self.job);
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

/// `--sandbox tier2a-cow`（D-30）時にRedirector DLLを注入するための設定。`spawn`/`spawn_impl`は`Some`の
/// ときのみ、`CREATE_SUSPENDED`起動窓（§10.2）でDLLを注入し、初期化完了イベントを待って
/// から`ResumeThread`する。`None`（既定・D-29）ではこの一連の処理を一切行わない。
#[derive(Debug, Clone, Copy)]
pub struct CowInject<'a> {
    pub workspace_root: &'a Path,
    pub diff_layer_dir: &'a Path,
    /// Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴。
    /// Redirector DLLへ`HARNESS_COW_EXT_ROOTS`として渡し、これら配下への書込も`_ext/<key>`
    /// 経由で操作台帳へcaptureする。空なら`--sandbox tier2a-cow`単体（workspace内のみcapture、既存挙動）。
    pub ext_capture_roots: &'a [PathBuf],
}

/// Redirector DLLを注入するかどうかと、注入するなら何を渡すか。
///
/// # なぜ`CowInject`と別に要るのか（[D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md`）]）
///
/// **DLLの注入は長らく`--sandbox tier2a-cow`の専用機構だった**——注入するかどうかが
/// 「CoWか」と同義だったので、`CowInject`が`Some`かどうかがそのまま注入の可否だった。
/// D-88でDirectRw（`run_shell`の既定）にも注入する理由ができたため、
/// **「注入するか」と「CoWか」を別の問いに割る**必要が出た。
///
/// ここが中立な名前なのはそのためで、CoWは**その中の1つの用途**に降りた。
///
/// # 既存の呼び出しを書き換えずに済ませてある
///
/// [`spawn_with_workspace`]は`impl Into<RedirectorInject>`を受けるので、
/// これまでどおり`Option<CowInject>`を渡す呼び出し（実機テスト19箇所）はそのまま通る。
/// **型を広げるために全呼び出しを書き換えると、書き換えの過程で意味が変わった箇所を
/// 見落とす**（`safe-refactoring`の「無言で消えるもの」）ので、変換を1本置いて逃がしてある。
#[derive(Debug, Clone, Copy, Default)]
pub struct RedirectorInject<'a> {
    /// DLLへ渡すworkspace root。**両モードで要る**——DLLはこれで「workspace内か」を
    /// 判定する。`CowInject`も同じ値を持つが、**読むのはここ1つだけ**にしてある
    /// （2箇所から読めると、CoWとlazyで違う綴りが届く形を作れてしまう、`B-13`）。
    /// 変換（[`From`]）がCoW側から埋めるので、呼び出し側が二重に指定する余地は無い。
    pub workspace_root: Option<&'a Path>,
    /// CoWの誘導設定。`None`ならDirectRw（誘導しない＝フックは成功経路で何も判定しない）。
    pub cow: Option<CowInject<'a>>,
    /// [D-88] fault要求の受付パイプ名。`None`ならfault-inしない（今日と同じ挙動）。
    pub broker_pipe: Option<&'a str>,
    /// [段階5b（`plans/DESIGN-MAC-ENFORCEMENT.md` §8.1）] **プロセス生成フックを置くこと
    /// 自体が目的である。**
    ///
    /// 誘導するものも受け付けるものも無くても、これが真なら注入する。段階⑤で
    /// `CHILD_PROCESS_RESTRICTED`（OSが子プロセス生成そのものを拒否する緩和策）を積むと、
    /// サンドボックスの中のプログラムは自力で子を作れなくなり、Spawn Daemonへ頼む形になる。
    /// **その頼み方へ変換するのがこのフック**なので、**フックが入っていないプロセスが
    /// 1つでも居る状態で⑤は積めない**。
    ///
    /// **製品のTier2a生成では常に真である**（[`RedirectorInject::for_tier2a`]）。
    /// 偽のまま残っているのは、注入を測定対象から外したいテストだけである。
    pub process_hooks: bool,
}

impl<'a> RedirectorInject<'a> {
    /// [D-88] DirectRwのlazyレーン向けの構築。
    pub fn lazy(workspace_root: &'a Path, broker_pipe: &'a str) -> Self {
        Self {
            workspace_root: Some(workspace_root),
            cow: None,
            broker_pipe: Some(broker_pipe),
            process_hooks: true,
        }
    }

    /// [段階5b] **製品のTier2a生成が使う唯一の構築口。**
    ///
    /// 誘導（CoW）とfault受付は在るときだけ渡し、**プロセス生成フックは常に要求する**。
    /// 入口を1つにしてあるのは、経路ごとに真偽が分かれると
    /// 「注入されていないプロセスが1つだけ残る」形（BUG-032型）がそこから入るためで、
    /// 実際にMCPの経路が2026-09-07までその状態だった。
    ///
    /// `workspace_root`が`None`でよい——MCPサーバにはワークスペースが無く、
    /// そのときDLLはファイル系フックを1本も置かない。
    pub fn for_tier2a(
        workspace_root: Option<&'a Path>,
        cow: Option<CowInject<'a>>,
        broker_pipe: Option<&'a str>,
    ) -> Self {
        Self {
            // CoWは自分のworkspace rootを持っているので、明示指定が無ければそちらを採る
            // （読むのは1箇所だけにする、`workspace_root`のdoc）。
            workspace_root: workspace_root.or_else(|| cow.map(|c| c.workspace_root)),
            cow,
            broker_pipe,
            process_hooks: true,
        }
    }

    /// 何か1つでも渡すものがあるか。**偽ならDLLを注入しない**——注入だけして何もしない
    /// 状態を作らない（子の中で動くコードは、要らないなら存在しないのが最も安全である）。
    ///
    /// **誘導と受付にはworkspace rootが要る。** DLLは何がworkspaceか分からないまま
    /// 分類できず、分からないまま動かすと「workspace外への書込が拒否された」ように見える形で
    /// 全部が壊れる（BUG-066が実際にそう見えた）。**プロセス生成フックだけは例外**で、
    /// あれはパスを1つも見ないので、ワークスペースを知らなくても正しく働く。
    pub(crate) fn wanted(&self) -> bool {
        self.process_hooks
            || (self.workspace_root.is_some() && (self.cow.is_some() || self.broker_pipe.is_some()))
    }
}

/// **テストが`Option<CowInject>`をそのまま渡せるようにする変換。**
///
/// [段階5b] `process_hooks`は**偽**にする。製品はこの変換を通らず
/// [`RedirectorInject::for_tier2a`]を通るので、ここが偽であることは
/// 「テストの`None`が注入なしのままである」ことだけを意味する
/// （製品呼び出し元が0件であることは`launch.rs`の数え上げテストが固定している）。
impl<'a> From<Option<CowInject<'a>>> for RedirectorInject<'a> {
    fn from(cow: Option<CowInject<'a>>) -> Self {
        Self {
            workspace_root: cow.map(|c| c.workspace_root),
            cow,
            broker_pipe: None,
            process_hooks: false,
        }
    }
}

/// Redirector DLLへ渡すルートパスの綴りを揃える（[BUG-066](../../../../docs/bugs/BUG-066.md)）。
///
/// DLLは受け取った文字列で「このパスはworkspace配下か」を判定するため、`--cwd`の綴りが
/// そのまま届くと表記ゆれで照合が外れる。外れると**workspace内への書込が1件残らずACL拒否**に
/// なり（＝`--sandbox tier2a-cow`の透過性が全滅し）、しかもそれが「workspace外への書込が拒否された」ように
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

/// Redirector DLLへ設定を運ぶ環境変数の名前。**綴りはDLL側と対**
/// （`harness-redirector`の`config.rs`・`init.rs`）。
///
/// # なぜ定数にしてあるのか（2026-09-17、段階6f-1）
///
/// [`augment_redirector_env`]が書く名前と、**呼び出し元の申告から捨てる名前**が
/// 一致していなければならない。サンドボックスの中のプロセスがこれらを自分で立てて
/// Daemonへ渡せると、**孫の誘導先や受付パイプを自分で決められる**——文字列を2箇所に
/// 書くと、片方だけ増やした日にその1つだけが素通りする（`B-13`）。
pub(crate) mod redirector_env {
    pub(crate) const WORKSPACE: &str = "HARNESS_COW_WORKSPACE";
    pub(crate) const PROCESS_HOOKS: &str = "HARNESS_REDIRECTOR_PROCESS_HOOKS";
    pub(crate) const DIFF_LAYER: &str = "HARNESS_COW_DIFF_LAYER";
    pub(crate) const EXT_ROOTS: &str = "HARNESS_COW_EXT_ROOTS";
    pub(crate) const BROKER_PIPE: &str = "HARNESS_LAZY_BROKER_PIPE";
    /// **1回の生成にしか意味が無い値**（注入したDLLが初期化完了を知らせるハンドル）。
    /// 系統の基準envに古い値が残っているので、**使い回さず毎回書き直す**。
    pub(crate) const READY_HANDLE: &str = "HARNESS_COW_READY_HANDLE";
}

/// harnessが所有する環境変数の名前一式。**呼び出し元に名乗らせてはいけないもの**である。
///
/// [`augment_redirector_env`]が書く6つ（[`redirector_env`]）に、Spawn Daemonの窓口名と
/// 注入の抑止リストを足したもの。Daemonはnestedの生成で、**この名前だけは呼び出し元の
/// 申告を捨てて系統の値を使う**（`spawnd::server::env_for_nested`）。
pub(crate) fn harness_owned_env_names() -> [&'static str; 8] {
    [
        redirector_env::WORKSPACE,
        redirector_env::PROCESS_HOOKS,
        redirector_env::DIFF_LAYER,
        redirector_env::EXT_ROOTS,
        redirector_env::BROKER_PIPE,
        redirector_env::READY_HANDLE,
        super::lazy_grant::NO_INJECT_ENV,
        crate::tier2a::spawnd::REQUEST_PIPE_ENV,
    ]
}

/// [BUG-160] **OSがAppContainerの生成のたびに書き換える環境変数の名前**。
///
/// # 何が起きるのか
///
/// `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`を積んで`CreateProcessW`すると、
/// Windowsは渡した環境ブロックの中のこの3つを**渡された`LOCALAPPDATA`から導き直す**。
///
/// ```text
///   LOCALAPPDATA := <渡されたLOCALAPPDATA>\Packages\<パッケージ名>\AC
///   TEMP, TMP    := <渡されたLOCALAPPDATA>\Packages\<パッケージ名>\AC\Temp
/// ```
///
/// **harnessはこの3つを1文字も書いていない。** 書き換えているのはOSである。
///
/// # だから「置き換え済みの値」を渡してはいけない
///
/// AppContainerの中に居るプロセスの環境は、既に1回この変換を受けている。
/// それをそのまま次の`CreateProcessW`へ渡すと**同じ変換が重なり**、
/// `…\AC\Packages\<パッケージ名>\AC\Temp`という存在しない場所を指す。
/// 一時ファイルを作るプログラムが「許可されたのに動かない」形で落ちる。
///
/// 対処は、代理で起こす側（Spawn Daemon）が**系統の基準env**——トップレベルの子を
/// 起こしたときにharnessがOSへ渡した、置き換え前の値——をこの名前に戻すことである
/// （`spawnd::server::env_for_nested`）。
///
/// # この一覧は実測で決めた（**推測で増やさない**）
///
/// 2026-09-19に、生成経路だけを変えた2腕で環境を丸ごと突き合わせて数えた
/// （[§S65](../../../../../plans/mac-spike/RESULTS.md)）。23変数のうち書き換わったのは
/// この3つだけで、`APPDATA`・`USERPROFILE`は**書き換わらなかった**。
///
/// **増えた日は実測が教える。** 突き合わせの受け入れ
/// （`spawnd_e2e_tests::env_substitution_tests`）は名指しの3つではなく
/// **説明できない差が1件でもあれば赤**にしてあるので、OSが別の名前を書き換え始めたら
/// そこで止まる。
pub(crate) fn os_rewritten_env_names() -> [&'static str; 3] {
    ["TEMP", "TMP", "LOCALAPPDATA"]
}

/// Redirectorへ渡す環境を、直接生成とDaemon生成で同じ規則から組み立てる。
pub(crate) fn augment_redirector_env(
    env: &mut Vec<(String, String)>,
    inject: RedirectorInject<'_>,
    ready_write: HANDLE,
) {
    // [段階5b] **ワークスペースは無いことがある**（MCPサーバ）。無いときは変数を置かない
    // ——空文字で置くと、DLL側の`get_env`が空を`None`扱いにするので同じ結果になるが、
    // **「空のworkspaceを渡した」と「渡していない」を子のenvで区別できなくなる**。
    if let Some(workspace) = inject.workspace_root {
        env.push((
            redirector_env::WORKSPACE.to_string(),
            normalize_cow_root(workspace).to_string_lossy().into_owned(),
        ));
    }
    // [段階5b] 誘導も受付も無いとき、DLLはこれが無ければ初期化せずに降りる。
    // **綴りはDLL側と対**（`harness-redirector`の`config::PROCESS_HOOKS_ENV`）。
    // 他の4つと同じくクレートを跨いだ文字列の複製だが、`harness-sandbox`は
    // `harness-redirector`に依存していない（DLLは実行時にロードされるだけ）ので、
    // 型で結べるのはここまでである。
    if inject.process_hooks {
        env.push((redirector_env::PROCESS_HOOKS.to_string(), "1".to_string()));
    }
    if let Some(cow) = inject.cow {
        env.push((
            redirector_env::DIFF_LAYER.to_string(),
            normalize_cow_root(cow.diff_layer_dir)
                .to_string_lossy()
                .into_owned(),
        ));
        if !cow.ext_capture_roots.is_empty() {
            let joined = cow
                .ext_capture_roots
                .iter()
                .map(|path| normalize_cow_root(path).to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(";");
            env.push((redirector_env::EXT_ROOTS.to_string(), joined));
        }
    }
    if let Some(pipe) = inject.broker_pipe {
        env.push((redirector_env::BROKER_PIPE.to_string(), pipe.to_string()));
    }
    if let Ok(list) = std::env::var(super::lazy_grant::NO_INJECT_ENV) {
        if !list.trim().is_empty() {
            env.push((super::lazy_grant::NO_INJECT_ENV.to_string(), list));
        }
    }
    env.push((
        redirector_env::READY_HANDLE.to_string(),
        (ready_write.0 as usize).to_string(),
    ));
}

/// 子プロセスが属する**ドメイン**を名指しするSID（設計書§22.1.1）。
///
/// 子のプロセス／スレッド／トークン既定DACLを「ユーザーSID＋このSID」だけに絞るために使う。
/// **同一package SID内では、これが違えば互いに`OpenProcess`できない**——それがこの型の目的で
/// ある（capability群だけではコード注入を塞げない、[RESULTS.md §S2・§S2c](../../../../plans/mac-spike/RESULTS.md)）。
///
/// **`Option`にせず、必ず選ばせる**。既定値があると呼び出し側が黙って落とせてしまい、
/// 落ちた経路だけが素のDACL（package SID入り）で起動する——それは静かに分離が消える形である。
/// spawn経路が増えたときにコンパイルで気付かせるために、この列挙を引数で受け取る。
#[derive(Clone, Copy)]
pub enum DomainIdentity {
    /// このドメインを識別するcapability SID（例: D-54のworkspace capability）。
    ///
    /// **traverse capabilityを渡してはいけない**——全Tier2a子が共有するので分離にならない。
    Capability(PSID),
    /// **自分のpackage SIDそのものがドメイン**である場合（プロファイルが1ドメインに対応する）。
    /// MCPサーバ（D-38でサーバごとに別プロファイル）とWFPプローブがこれに当たる。
    OwnPackage,
}

impl DomainIdentity {
    /// 子のDACLに載せる宛先SIDの文字列を返す。`container_sid`は`OwnPackage`のときだけ使う。
    fn sid_string(&self, container_sid: PSID) -> Result<String, AppContainerError> {
        let psid = match self {
            DomainIdentity::Capability(sid) => *sid,
            DomainIdentity::OwnPackage => container_sid,
        };
        crate::win_common::sid_to_string(psid)
            .map_err(|e| AppContainerError::Win32(format!("sid_to_string(domain identity): {e}")))
    }
}

/// `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`（`processthreadsapi.h`）。
///
/// `windows` 0.58は`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`（属性の**種類**）は生成して
/// いるが、そこへ入れる**値**の定数は生成していないので、SDKの定義をここに書く。
/// **綴りを2箇所に置かない**——スパイク（`mac_spike_tests.rs`）は自前の定数を持っていたが、
/// 製品側が持つのはこれ1つで、スパイクは測定専用の別世界なのでそのまま残す。
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x0000_0001;

/// SDDL文字列から作ったセキュリティ記述子。**`Drop`で`LocalFree`する**
/// （`ConvertStringSecurityDescriptorToSecurityDescriptorW`が確保したものを解放する義務がある）。
///
/// spawnは`?`で抜ける経路が多いので、手で解放する形にすると経路が増えるたびに漏れる。
struct SecurityDescriptorBuf(windows::Win32::Security::PSECURITY_DESCRIPTOR);

impl SecurityDescriptorBuf {
    fn from_sddl(sddl: &str) -> windows::core::Result<Self> {
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        unsafe {
            let sddl_w = wide(sddl);
            let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
            Ok(Self(sd))
        }
    }

    /// `CreateProcessW`の`lpProcessAttributes`/`lpThreadAttributes`へ渡す形。
    /// **戻り値はこの`SecurityDescriptorBuf`より長生きさせない**（SDを指しているため）。
    fn security_attributes(&self) -> windows::Win32::Security::SECURITY_ATTRIBUTES {
        windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }

    /// `SetTokenInformation(TokenDefaultDacl)`へ渡すDACLポインタ。
    fn dacl(&self) -> windows::core::Result<*mut windows::Win32::Security::ACL> {
        use windows::Win32::Security::GetSecurityDescriptorDacl;
        let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
        let mut present = windows::Win32::Foundation::BOOL::from(false);
        let mut defaulted = windows::Win32::Foundation::BOOL::from(false);
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)? };
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptorBuf {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

/// 子のプロセス／スレッド／トークン既定DACLへ適用するSDDL（設計書§22.1.1）。
///
/// 形は`D:(A;;GA;;;<user sid>)(A;;GA;;;<domain sid>)`の2つのSIDだけである。
///
/// - **package SIDは載せない**。載せると同一package SIDの別ドメインから開けてしまい、
///   この対策の目的そのものが消える（`OwnPackage`のときだけ、package SID＝ドメインなので載る）
/// - **traverse capabilityは載せない**（全Tier2a子が共有する＝分離にならない）
/// - **ユーザーSIDは載せる**。AppContainerでない側（harness自身・昇格した収集器）が引き続き
///   開けるようにするため。**AppContainerの子には効かない**——AppContainerのアクセスチェックは
///   package SIDかcapabilityを別途要求するので、サンドボックスの子はこのACEでは開けない（§S2cで実測）
/// - **SYSTEMは足さない**（§S2cの構成で実際に走ることを確認済みで、根拠なくSIDを増やさない）
fn domain_dacl_sddl(
    domain: DomainIdentity,
    container_sid: PSID,
) -> Result<String, AppContainerError> {
    let user = crate::win_pipe_ipc::current_user_sid_string()
        .map_err(|e| AppContainerError::Win32(format!("current_user_sid_string: {e}")))?;
    let domain_sid = domain.sid_string(container_sid)?;
    Ok(format!("D:(A;;GA;;;{user})(A;;GA;;;{domain_sid})"))
}

/// 実行ファイルと引数から`CreateProcessW`の`lpCommandLine`を組む。**唯一の組み立て点。**
///
/// # なぜ関数として切り出してあるのか
///
/// [§8.2](../../../../plans/DESIGN-MAC-ENFORCEMENT.md)が、遷移の判定に使う文字列と
/// 実際に起こす文字列を**同一の値**にすることを要求している。組み立てが2箇所にあると、
/// 「同じ規則だから同じ結果になるはず」という形になり、同節が名指しで足りないと言っている
/// 状態そのものになる。**Spawn Daemonは、この関数で1回組んだ値を判定にも生成にも渡す。**
///
/// # 引用の規則
///
/// **[`crate::win_common::command_line_for`]が持つ**（3Tier共通。2026-09-17に統合）。
/// かつてここに5行の写しがあり、`tier0`・`tier1`と**同じ間違い**を持っていた
/// ——バックスラッシュと引用符が隣り合う引数で境界がずれる。経緯は共通側のdocにある。
pub(crate) fn command_line_for(exe: &str, args: &[&str]) -> String {
    crate::win_common::command_line_for(exe, args)
}

/// [`create_suspended_in_job`]への入力。引数が多いので構造体で受ける。
pub(crate) struct SuspendedSpawn<'a> {
    /// `CreateProcessW`の`lpCommandLine`へそのまま渡す文字列。
    ///
    /// # なぜ`exe`と`args`ではないのか（2026-09-12、段階6b）
    ///
    /// [§8.2](../../../../plans/DESIGN-MAC-ENFORCEMENT.md)が
    /// **「遷移の判定に使った文字列と`CreateProcess`へ渡す文字列は同一でなければならない」**と
    /// 定めている。ここが`exe`＋`args`を受けて中で組み立てる形だと、判定側も同じ規則で
    /// 組み立てることになり、**「同じ規則で組めば同じ結果になる」では足りない**という
    /// 同節の但し書きにそのまま当たる。**組むのは[`command_line_for`]1箇所にして、
    /// できた値を判定と生成の両方へ渡す。**
    pub command_line: &'a str,
    /// `CreateProcessW`の`lpApplicationName`。**絶対パスであること。**
    ///
    /// # なぜ`Option`なのか（2026-09-17、段階6f-1）
    ///
    /// **経路によって、実行ファイルを誰が決めたかが違う。**
    ///
    /// | 経路 | 値 | なぜ |
    /// |---|---|---|
    /// | harnessが直接／Daemon経由でトップレベルを起こす | `None` | コマンドラインを組むのも解釈させるのも同じharnessで、`exe`はPATH解決に委ねてよい綴りのことがある |
    /// | Daemonがサンドボックスの要求で起こす（nested） | **必ず`Some`** | **判定した実行ファイルと、実際に起きる実行ファイルを同一の値にする**ため。コマンドラインの先頭から実行ファイルを決める規則はOSとこちらで食い違い得る（`spawnd::SpawnRequest::Spawn::image`のdoc） |
    ///
    /// **`None`のとき挙動は段階6f-1より前と1ビットも変わらない。**
    pub application_name: Option<&'a str>,
    pub cwd: &'a Path,
    /// `CREATE_UNICODE_ENVIRONMENT`用に組み立て済みの環境ブロック
    /// （`win_common::build_env_block`が作る）。**呼び出し側が組む**——CoWは
    /// ここへ独自の変数を足すので、組み立てをこの関数へ入れると分岐が持ち込まれる。
    pub env_block: &'a mut Vec<u16>,
    pub container_sid: PSID,
    pub capabilities: &'a [SID_AND_ATTRIBUTES],
    /// **子へ継承させるハンドルの全て**（INV-2、設計書§28）。`hStd*`はこの部分集合であって
    /// 一致ではない（CoWのready pipeはここに載るが`hStd*`のどれでもない）。
    ///
    /// **この配列のハンドルは、`CreateProcessW`の成否によらずこの関数が閉じる。**
    /// 子は自分の複製を持つので、呼び出し側の端はもう要らない。閉じる責任を呼び出し側へ
    /// 残すと、経路が増えるたびに片方だけ漏れる（`B-01`）。
    pub inherit_handles: &'a [HANDLE],
    pub stdout_write: HANDLE,
    pub stderr_write: HANDLE,
    pub stdin_read: Option<HANDLE>,
    /// 子を入れるJob Object。**この関数は所有しない**（失敗しても閉じない）
    /// ——作った側が閉じる。Daemon方式では作る側がharnessなので、
    /// ここで閉じると他人のハンドルを閉じることになる（§10.1.1）。
    pub job: HANDLE,
    pub domain: DomainIdentity,
    /// [段階⑤] 子自身に子プロセス生成を許すか。**製品の既定は`Unrestricted`**で、
    /// `Restricted`を選べるのはいまのところ受入テストだけである（同型のdoc）。
    pub child_process_policy: ChildProcessPolicy,
    /// [段階⑤] 起こすプログラムがコンソールを要るか。**`Unrestricted`のときは効かない**
    /// （どちらでも`CREATE_NO_WINDOW`のまま）。同型のdocに、取り違えたときの壊れ方がある。
    pub console: ConsoleNeed,
}

/// **一時停止のまま子を起こし、Jobへ入れ、トークンの既定DACLを差し替える**（§12の固定順の前半）。
///
/// # なぜ切り出してあるのか
///
/// この手順は`spawn_impl`（harnessが直接起こす経路）と`tier2a::spawnd`（Spawn Daemonが
/// 代理で起こす経路）の**両方**が必要とする。写しを作ると、失敗パスの後始末が2つの綴りに
/// 分かれて片方だけ直る形になる——[BUG-156](../../../../docs/bugs/BUG-156.md)が
/// まさにその形だった（Tier2aだけが正しく書けていて、Tier0/Tier1には後始末が1行も無かった）。
/// `docs/CODE-STRUCTURE-RULES.md`規則5。
///
/// # 何を保証するか
///
/// 返るとき、子は**まだ一時停止したまま**である。`ResumeThread`は呼び出し側が行う——
/// **その間に何を挟むかが経路ごとに違う**からである。
///
/// | 経路 | Resumeの前に挟むもの |
/// |---|---|
/// | `spawn_impl` | Redirector DLLの注入と初期化待ち（D-30・D-88） |
/// | Spawn Daemon | Process Tableへの登録（§12。**締切が最も早い**——子は起きた直後に生成を要求し得る） |
///
/// # 失敗したときに何が起きるか
///
/// **どの段で落ちても、子は残らない。** `CreateProcessW`が失敗すれば子は生成されておらず、
/// それより後で落ちれば`TerminateProcess`する——子は一時停止のままなので**ユーザーコードを
/// 1行も実行していない**（作り直しても副作用が二重にならない、BUG-116）。
/// この関数が閉じるのは**自分が作ったもの**（プロセス／スレッドのハンドル）と
/// `inherit_handles`だけで、Jobと呼び出し側のパイプ端は触らない。
pub(crate) fn create_suspended_in_job(
    request: SuspendedSpawn<'_>,
) -> Result<PROCESS_INFORMATION, AppContainerError> {
    let step = |label: &'static str, e: windows::core::Error| {
        AppContainerError::Win32(format!("{label}: {e}"))
    };

    let mut cmdline_w = wide(request.command_line);
    let cwd_w = wide(&request.cwd.to_string_lossy());
    // [段階6f-1] `lpApplicationName`。**`None`なら今日どおりコマンドライン任せ**である
    // （[`SuspendedSpawn::application_name`]の表）。値は`CreateProcessW`が返るまで生かす。
    let application_name_w = request.application_name.map(wide);

    let mut capabilities_buf = request.capabilities.to_vec();
    let mut security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: request.container_sid,
        Capabilities: if capabilities_buf.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities_buf.as_mut_ptr()
        },
        CapabilityCount: capabilities_buf.len() as u32,
        Reserved: 0,
    };
    let mut inherit_handles = request.inherit_handles.to_vec();

    // §22.1.1 挿入点1: プロセスと**最初のスレッド**のオブジェクトDACL。
    // カーネルオブジェクトのDACLは**生成時**に決まるので、下の`TokenDefaultDacl`差し替えでは
    // この2つに間に合わない（逆に、ここだけでは起動後に生えたスレッドが素のままになる、§S2b）。
    // **2つで1つの対策**である。SDは`CreateProcessW`の呼び出し中だけ生きていればよい。
    let domain_sddl = domain_dacl_sddl(request.domain, request.container_sid)?;
    let domain_sd_for = |what: &'static str| -> Result<SecurityDescriptorBuf, AppContainerError> {
        SecurityDescriptorBuf::from_sddl(&domain_sddl).map_err(|e| {
            AppContainerError::Win32(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW({what}): {e}"
            ))
        })
    };
    let process_sd = domain_sd_for("process")?;
    let thread_sd = domain_sd_for("thread")?;
    let process_sa = process_sd.security_attributes();
    let thread_sa = thread_sd.security_attributes();

    // [段階⑤] 子自身へ「子プロセスを作れない」を積むときだけ、属性が1つ増える。
    // **値の変数は`CreateProcessW`が返るまで生かしておくこと**——`UpdateProcThreadAttribute`は
    // 値をコピーせずポインタを覚えるので、途中で落とすと未定義の値が読まれる。
    let mut child_policy: u32 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let restricted = request.child_process_policy.is_restricted();
    // 数え違えると`UpdateProcThreadAttribute`が`ERROR_INVALID_PARAMETER`で落ちる。
    let attribute_count: u32 = 2 // SECURITY_CAPABILITIES + HANDLE_LIST（常に積む）
        + u32::from(restricted); // CHILD_PROCESS_POLICY

    // コンソールの与え方（§7.1の実測表。[`ConsoleNeed`]のdocに3通りの挙動がある）。
    // **生成禁止を積んでいないなら、今日の綴りをそのまま使う**——`ConsoleNeed`が効くのは
    // `Restricted`と対になったときだけで、既定の経路の挙動を1ビットも変えない。
    let console_flag = match (restricted, request.console) {
        (false, _) => CREATE_NO_WINDOW,
        (true, ConsoleNeed::NotNeeded) => DETACHED_PROCESS,
        // フラグを1つも積まない＝**いま呼び出し側が繋がっているコンソールが子へ渡る**。
        // 繋がっていなければ子はコンソール無しで起き、シェルは無言でexit 0する
        // （借りる義務は[`ConsoleNeed::Required`]のdocが呼び出し側へ課している）。
        (true, ConsoleNeed::Required) => PROCESS_CREATION_FLAGS(0),
    };

    let result: Result<PROCESS_INFORMATION, AppContainerError> = unsafe {
        let mut attr_list_size: usize = 0;
        // 1回目は必要サイズ取得のためだけの呼び出しで、バッファ不足エラーになるのが正常
        // （ERROR_INSUFFICIENT_BUFFER）なので戻り値は捨てる。
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            attribute_count,
            0,
            &mut attr_list_size,
        );
        let mut attr_list_buf = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut c_void);
        let init_result =
            InitializeProcThreadAttributeList(attr_list, attribute_count, 0, &mut attr_list_size)
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
            })
            .and_then(|()| {
                // [段階⑤] ここで初めて遷移が**強制**される。フックを迂回されても、
                // 生成を止めるのはカーネルである（§9「User-mode Hookをセキュリティ境界にしない」）。
                if !restricted {
                    return Ok(());
                }
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                    Some(&mut child_policy as *mut _ as *const c_void),
                    std::mem::size_of::<u32>(),
                    None,
                    None,
                )
                .map_err(|e| step("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)", e))
            });

            let out = update_result.and_then(|()| {
                let startup_info_ex = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: STARTF_USESTDHANDLES,
                        hStdOutput: request.stdout_write,
                        hStdError: request.stderr_write,
                        hStdInput: request.stdin_read.unwrap_or(INVALID_HANDLE_VALUE),
                        ..Default::default()
                    },
                    lpAttributeList: attr_list,
                };

                let mut process_info = PROCESS_INFORMATION::default();
                // `CREATE_SUSPENDED`（設計書§10.2）: メインスレッドを起こす前に
                // `AssignProcessToJobObject`を完了させ、子がJob Object外で孫プロセスを
                // 作れる窓（TOCTOU）を無くす。Phase 2のDLL注入もこの一時停止窓で行う。
                CreateProcessW(
                    application_name_w
                        .as_ref()
                        .map(|name| PCWSTR(name.as_ptr()))
                        .unwrap_or(PCWSTR::null()),
                    PWSTR(cmdline_w.as_mut_ptr()),
                    // §22.1.1 挿入点1（プロセス／最初のスレッドのDACL）。
                    Some(&process_sa as *const _),
                    Some(&thread_sa as *const _),
                    true,
                    EXTENDED_STARTUPINFO_PRESENT
                        | console_flag
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_SUSPENDED,
                    Some(request.env_block.as_mut_ptr() as *mut _),
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
    // **成否によらず閉じる**——子は自分の複製を持っている（この型のdoc）。
    unsafe {
        for handle in request.inherit_handles {
            let _ = CloseHandle(*handle);
        }
    }

    let process_info = result?;

    unsafe {
        // suspended状態のうちにJobへ割り当ててからResumeする（INV-2/§10.2）。ここで失敗した
        // 場合、suspendedのままの孤立プロセスを残さないよう強制終了してから返す。
        if let Err(e) = AssignProcessToJobObject(request.job, process_info.hProcess)
            .map_err(|e| step("AssignProcessToJobObject", e))
        {
            let _ = TerminateProcess(process_info.hProcess, 1);
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            return Err(e);
        }

        // §22.1.1 挿入点2: **Resumeより前に**トークンの既定DACLを差し替える。
        //
        // ここを窓に選ぶ理由は、子がまだ1つもオブジェクトを作っていないからである——起動後に
        // 差し替えても、それまでに生えたスレッドは古い既定DACL（package SID入り）のまま残る。
        // これで「起動後に生えたスレッド」の穴（§S2b）が閉じる。
        //
        // **失敗はfail-closed**（B-10）。差し替わっていないのに起動を続けると、分離したつもりで
        // 素の状態が走る——しかも症状は出ないので誰も気付けない。
        let default_dacl_result = (|| -> Result<(), AppContainerError> {
            use windows::Win32::Security::{
                SetTokenInformation, TokenDefaultDacl, TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL,
            };
            let sd = SecurityDescriptorBuf::from_sddl(&domain_sddl).map_err(|e| {
                AppContainerError::Win32(format!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW(token default dacl): {e}"
                ))
            })?;
            let dacl = sd
                .dacl()
                .map_err(|e| step("GetSecurityDescriptorDacl(token default dacl)", e))?;
            let mut token = HANDLE::default();
            OpenProcessToken(
                process_info.hProcess,
                TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|e| step("OpenProcessToken(TOKEN_ADJUST_DEFAULT)", e))?;
            let info = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
            let set = SetTokenInformation(
                token,
                TokenDefaultDacl,
                &info as *const _ as *const c_void,
                std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
            .map_err(|e| step("SetTokenInformation(TokenDefaultDacl)", e));
            let _ = CloseHandle(token);
            set
        })();
        if let Err(e) = default_dacl_result {
            let _ = TerminateProcess(process_info.hProcess, 1);
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            return Err(e);
        }
    }

    Ok(process_info)
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
    cow: RedirectorInject<'_>,
    domain: DomainIdentity,
) -> Result<AppContainerChild, AppContainerError> {
    spawn_with_workspace(
        exe,
        args,
        cwd,
        env,
        want_stdin,
        container_sid,
        net,
        cow,
        &[],
        domain,
    )
}

/// [`spawn`]の、**このドメインのFS到達範囲をトークンへ積む版**（D-54・§22.3）。
///
/// FSのACEはもう「セッションのpackage SID」宛ではない。workspace本体はworkspace＋モード単位の
/// capability SID宛（D-54）、`--fs-allow`の穴は**宣言ごと**のcapability SID宛（§22.3）である。
/// したがって**そのcapabilityをトークンへ積まない子は、ACEが正しく付いていても1バイトも
/// 読めない**。`domain_caps`はその集合で、§22.1の「ドメイン = (package SID, capabilityの組)」を
/// そのまま表している。
///
/// **既定（[`spawn`]）は空**である。積まないと起こるのは`ACCESS_DENIED`＝fail-closedであり、
/// 逆向き（うっかり積む）だと境界が黙って消える。実際、MCPサーバは専用プロファイルで起動し
/// **workspaceを既定で持たない**（D-38 §3.2）——ここが既定で積む設計だったら、MCPサーバが
/// workspace全体へ到達していた。
///
/// **順序と重複は問わない**（`SECURITY_CAPABILITIES`は集合として扱われる）が、呼び出し側は
/// 「このドメインが宣言したもの」だけを渡すこと。宣言していないcapabilityを混ぜると、
/// §22.3.0.2の受け入れ条件（宣言したドメインだけがパスを見る）がその子について偽になる。
#[allow(clippy::too_many_arguments)]
pub fn spawn_with_workspace<'a>(
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
    // [D-88] `Option<CowInject>`のままでも通る（[`RedirectorInject`]のdoc）。
    inject: impl Into<RedirectorInject<'a>>,
    domain_caps: &[PSID],
    domain: DomainIdentity,
) -> Result<AppContainerChild, AppContainerError> {
    let cow = inject.into();
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
    // D-54・§22.3: このドメインのFS到達範囲。呼び出し側が明示したものだけを積む（上記doc）。
    for sid in domain_caps {
        capabilities.push(SID_AND_ATTRIBUTES {
            Sid: *sid,
            Attributes: SE_GROUP_ENABLED,
        });
    }

    match net {
        NetworkCapability::Deny => spawn_impl(
            exe,
            args,
            cwd,
            env,
            want_stdin,
            container_sid,
            &capabilities,
            cow,
            domain,
        ),
        NetworkCapability::InternetClient => unsafe {
            let mut cap_sid = PSID::default();
            let sid_str = wide(INTERNET_CLIENT_SID);
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
                domain,
            );
            let _ = LocalFree(HLOCAL(cap_sid.0));
            result
        },
    }
}

/// `internetClient` capability（D-10）。**直接生成とDaemon経由で同じ綴りを使う**
/// ——2箇所に文字列を散らすと、片方だけ直った状態が黙って成立する（`B-05`）。
pub(crate) const INTERNET_CLIENT_SID: &str = "S-1-15-3-1";

/// Daemon経由で起こす子に、**spawn要求受付パイプへ到達するcapabilityを積むか**（§10.1）。
///
/// # なぜ`bool`ではないのか
///
/// 呼び出し側の引数が`true`/`false`だけだと、経路を足す人がどちらの意味かを型から読めない。
/// [`DomainIdentity`]が`Option`にせず必ず選ばせているのと同じ理由である
/// ——**既定があると呼び出し側が黙って落とせてしまい、落ちた経路だけが別の姿で起動する。**
///
/// # 何を分けているのか
///
/// このcapability SIDが使われているのは**Daemonの要求受付パイプのDACLだけ**で、
/// ファイルやレジストリのACEには一度も現れない。したがって積むことで広がるのは
/// 「Daemonへ話しかけられるか」の一点であって、権限一般ではない。
/// **それでも既定を「積まない」にしてある**——Daemonはサンドボックスからの入力を
/// 直接解釈する最初のフルトラスト常駐なので、そこへ到達できる相手は宣言した者だけにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnRequestAccess {
    /// 要求受付パイプへ到達できる。段階Eのポリシー評価が入るまでは、届いても
    /// `unknown_source_domain`で断られる（`spawnd::DenyReason`）。
    Grant,
    /// 積まない。**パイプへ到達すらできない**——§22.2.2の`process: deny`が
    /// 「ポリシーで断る」の手前に置く二重目のdenyがこれである。
    Withhold,
}

/// Daemonへ渡すcapability SIDの列を組む。**純粋関数**（Win32を呼ばない）。
///
/// # なぜ切り出してあるのか
///
/// 実機テスト（`spawnd_e2e_tests.rs`のP1・P3）は電文の`DomainSpec`を**テストが手で組んで**
/// おり、測っているのは「Daemon側のDACLがcapabilityで効くか」だけである。
/// **製品のアダプタが実際に積んでいるか**はそこでは測れない——ここを`Withhold`へ倒しても
/// P1もP3も緑のままで、実機では`run_shell`の子が段階⑤で一切spawnできなくなる。
/// 対を受け持つのがこの関数と、直下の単体テストである（`B-35`）。
fn daemon_capability_sids(
    traverse: &str,
    spawn_request: &str,
    domain_caps: &[String],
    net: NetworkCapability,
    access: SpawnRequestAccess,
) -> Vec<String> {
    let mut sids = vec![traverse.to_string()];
    if access == SpawnRequestAccess::Grant {
        sids.push(spawn_request.to_string());
    }
    sids.extend(domain_caps.iter().cloned());
    if net == NetworkCapability::InternetClient {
        sids.push(INTERNET_CLIENT_SID.to_string());
    }
    sids
}

#[cfg(test)]
mod daemon_capability_tests {
    use super::*;

    const TRAVERSE: &str = "S-1-15-3-1024-11";
    const SPAWN_REQUEST: &str = "S-1-15-3-1024-22";

    /// **積むと決めた側**: spawn要求用capabilityが列に入る。
    #[test]
    fn granting_puts_the_spawn_request_capability_on_the_wire() {
        let sids = daemon_capability_sids(
            TRAVERSE,
            SPAWN_REQUEST,
            &[],
            NetworkCapability::Deny,
            SpawnRequestAccess::Grant,
        );
        assert!(
            sids.iter().any(|s| s == SPAWN_REQUEST),
            "積むと指定したのに、要求受付パイプへ届くcapabilityが電文に載っていない。\
             この子は段階⑤で一切spawnできなくなる: {sids:?}"
        );
    }

    /// **対の側**（`B-35`）: 積まないと決めたら列に入らない。
    ///
    /// 片方だけだと、**常に積む実装**でも上のテストは通る。
    #[test]
    fn withholding_keeps_the_spawn_request_capability_off_the_wire() {
        let sids = daemon_capability_sids(
            TRAVERSE,
            SPAWN_REQUEST,
            &[],
            NetworkCapability::Deny,
            SpawnRequestAccess::Withhold,
        );
        assert!(
            !sids.iter().any(|s| s == SPAWN_REQUEST),
            "積まないと指定したのにcapabilityが載っている。\
             Daemonへ話しかけられる相手を宣言で絞れていない: {sids:?}"
        );
        assert!(
            sids.iter().any(|s| s == TRAVERSE),
            "traverse capabilityまで落ちている。落とすと祖先を辿れずFS I/Oが全滅する"
        );
    }

    /// networkのcapabilityは**この決定と直交する**（目的も寿命も別、`spawn_with_workspace`のdoc）。
    #[test]
    fn the_network_capability_is_independent_of_the_spawn_request_decision() {
        for access in [SpawnRequestAccess::Grant, SpawnRequestAccess::Withhold] {
            let sids = daemon_capability_sids(
                TRAVERSE,
                SPAWN_REQUEST,
                &[],
                NetworkCapability::InternetClient,
                access,
            );
            assert!(
                sids.iter().any(|s| s == INTERNET_CLIENT_SID),
                "{access:?}でnetworkのcapabilityが落ちた: {sids:?}"
            );
        }
    }

    /// ドメインが宣言したcapabilityは、どちらの決定でもそのまま通る。
    #[test]
    fn declared_domain_capabilities_pass_through_either_way() {
        let declared = vec!["S-1-15-3-1024-33".to_string()];
        for access in [SpawnRequestAccess::Grant, SpawnRequestAccess::Withhold] {
            let sids = daemon_capability_sids(
                TRAVERSE,
                SPAWN_REQUEST,
                &declared,
                NetworkCapability::Deny,
                access,
            );
            assert!(
                sids.iter().any(|s| s == &declared[0]),
                "{access:?}で宣言済みcapabilityが落ちた: {sids:?}"
            );
        }
    }
}

/// Daemonが返した失敗を、harness側のエラーへ写す。
///
/// # ここが「lazyだけが1回やり直せる」の分岐点である
///
/// `launch.rs`のlazyレーンは[`AppContainerError::RedirectorInjection`]**だけ**を見て、
/// 全walkを待ってから注入なしで1回だけ起動し直す（D-88 §5.1.3）。それ以外は
/// 作り直しても同じなので再試行しない。
///
/// **注入の失敗を`Win32`へ丸めると、lazyの不調がそのままコマンドの失敗に化ける**
/// ——lazyで失われるのは速さだけのはずである。逆に**注入以外を`RedirectorInjection`へ
/// 丸めると、直らない失敗を毎回2回試す**ことになる。どちらも症状が出にくいので、
/// 対で測る（直下のテスト、`B-35`）。
fn daemon_failure_to_error(
    error: crate::tier2a::spawnd::server::SpawnDaemonError,
) -> AppContainerError {
    use crate::tier2a::spawnd::SpawnFailureKind;
    match error.kind {
        SpawnFailureKind::RedirectorInjection => {
            AppContainerError::RedirectorInjection(error.message)
        }
        SpawnFailureKind::Spawn | SpawnFailureKind::Protocol | SpawnFailureKind::Transport => {
            AppContainerError::Win32(error.message)
        }
    }
}

#[cfg(test)]
mod daemon_failure_mapping_tests {
    use super::*;
    use crate::tier2a::spawnd::server::SpawnDaemonError;
    use crate::tier2a::spawnd::SpawnFailureKind;

    fn failure(kind: SpawnFailureKind) -> SpawnDaemonError {
        SpawnDaemonError {
            kind,
            message: "boom".to_string(),
        }
    }

    /// **やり直してよい側**: 注入の失敗だけが、lazyレーンが見るエラーになる。
    #[test]
    fn a_redirector_injection_failure_is_the_one_lazy_can_retry() {
        assert!(
            matches!(
                daemon_failure_to_error(failure(SpawnFailureKind::RedirectorInjection)),
                AppContainerError::RedirectorInjection(_)
            ),
            "注入の失敗が別のエラーへ丸められている。\
             lazyレーンの不調がコマンドそのものの失敗に化ける（D-88 §5.1.3）"
        );
    }

    /// **対の側**（`B-35`）: それ以外はやり直さない。
    ///
    /// 片方だけだと、**常に`RedirectorInjection`を返す実装**でも上のテストは通る
    /// ——そして直らない失敗を毎回2回試すようになる。
    #[test]
    fn every_other_failure_kind_is_not_retryable() {
        for kind in [
            SpawnFailureKind::Spawn,
            SpawnFailureKind::Protocol,
            SpawnFailureKind::Transport,
        ] {
            assert!(
                !matches!(
                    daemon_failure_to_error(failure(kind)),
                    AppContainerError::RedirectorInjection(_)
                ),
                "{kind:?}がやり直し対象になっている。作り直しても同じ失敗を2回踏む"
            );
        }
    }

    /// 失敗の**理由**を落とさない。落とすと、切り分けがDaemonのログ頼みになる。
    #[test]
    fn the_reason_survives_the_mapping() {
        for kind in [
            SpawnFailureKind::RedirectorInjection,
            SpawnFailureKind::Spawn,
            SpawnFailureKind::Protocol,
            SpawnFailureKind::Transport,
        ] {
            assert!(
                daemon_failure_to_error(failure(kind))
                    .to_string()
                    .contains("boom"),
                "{kind:?}で理由の文面が消えた"
            );
        }
    }
}

/// harness側で作るJobとstdioの親側端を、途中失敗でも一括回収する。
struct DaemonSpawnHandles {
    job: Option<HANDLE>,
    stdin_read: Option<HANDLE>,
    stdin_write: Option<HANDLE>,
    stdout_read: Option<HANDLE>,
    stdout_write: Option<HANDLE>,
    stderr_read: Option<HANDLE>,
    stderr_write: Option<HANDLE>,
}

impl DaemonSpawnHandles {
    fn new() -> Self {
        Self {
            job: None,
            stdin_read: None,
            stdin_write: None,
            stdout_read: None,
            stdout_write: None,
            stderr_read: None,
            stderr_write: None,
        }
    }
}

impl Drop for DaemonSpawnHandles {
    fn drop(&mut self) {
        unsafe {
            for handle in [
                self.stdin_read.take(),
                self.stdin_write.take(),
                self.stdout_read.take(),
                self.stdout_write.take(),
                self.stderr_read.take(),
                self.stderr_write.take(),
            ]
            .into_iter()
            .flatten()
            {
                let _ = CloseHandle(handle);
            }
            if let Some(job) = self.job.take() {
                // **`TerminateJobObject`は撃たず、`CloseHandle`だけを行う**
                // （§10.1.1の「spawn失敗時の後始末」の性質。ここへ来るのは生成が失敗した
                // ときだけで、成功時は`job.take()`が先に所有権を子へ渡している）。
                // 失敗時点でこのJobは**空**である——Daemonが起こせていれば子は
                // resume前に明示終了済みなので、kill-on-closeで足りる。
                let _ = CloseHandle(job);
            }
        }
    }
}

/// Job・stdioをharness側で所有したまま、トップレベル生成だけを共有Daemonへ委譲する。
///
/// `spawn_request`・`console`・`policy_domain`は**呼び出し側が必ず選ぶ**
/// （[`SpawnRequestAccess`]・[`ConsoleNeed`]・[`crate::tier2a::spawnd::DomainSpec::policy_domain`]の
/// doc。いずれも既定値を持たない）。
///
/// # `domain_name`と`policy_domain`は別物である（2026-09-12、段階6b）
///
/// 前者はAppContainerプロファイル名／MCPの宣言idで、**記録と診断のためだけ**に使う。
/// 後者は**遷移の判定における遷移元ドメイン名**で、`policy.json`の`domains[].name`と
/// 一致しなければならない。プロファイル名はセッションごとに変わるので、
/// 混ぜると宣言と一致しなくなる。
#[allow(clippy::too_many_arguments)]
pub fn spawn_with_workspace_via_daemon<'a>(
    daemon: &crate::tier2a::spawnd::SharedSpawnDaemon,
    domain_name: &str,
    policy_domain: &str,
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
    inject: impl Into<RedirectorInject<'a>>,
    domain_caps: &[PSID],
    // [BUG-180] CoWで注入するなら**その差分層の宛先SID**。注入設定と一緒にDaemonへ運び、
    // Daemonはこの設定で注入する子（別ドメインへ移った子を含む）に必ず積む。
    // CoWでないなら`None`（[`daemon_redirector_spec`]が組み合わせを検査する）。
    cow_diff_layer_capability: Option<PSID>,
    domain: DomainIdentity,
    spawn_request: SpawnRequestAccess,
    console: ConsoleNeed,
) -> Result<AppContainerChild, AppContainerError> {
    use crate::tier2a::spawnd::{DomainIdentitySpec, DomainSpec, TopLevelSpawn};

    let inject = inject.into();
    let container_sid_string = crate::win_common::sid_to_string(container_sid)
        .map_err(|e| AppContainerError::Win32(format!("sid_to_string(container): {e}")))?;
    let identity = match domain {
        DomainIdentity::Capability(sid) => DomainIdentitySpec::Capability {
            sid: crate::win_common::sid_to_string(sid)
                .map_err(|e| AppContainerError::Win32(format!("sid_to_string(domain): {e}")))?,
        },
        DomainIdentity::OwnPackage => DomainIdentitySpec::OwnPackage,
    };
    let traverse = super::traverse_capability_sid()?;
    let traverse_string = crate::win_common::sid_to_string(traverse.as_psid())
        .map_err(|e| AppContainerError::Win32(format!("sid_to_string(traverse): {e}")))?;
    // **`Withhold`でも導出する。** 導出そのものは副作用の無い名前→SIDの変換で、
    // ここで分岐させると「積まない経路だけ導出が壊れていても気付けない」形になる。
    let spawn_request_sid = super::spawn_request_capability_sid()?;
    let spawn_request_string = crate::win_common::sid_to_string(spawn_request_sid.as_psid())
        .map_err(|e| AppContainerError::Win32(format!("sid_to_string(spawn request): {e}")))?;
    let mut declared_caps = Vec::with_capacity(domain_caps.len());
    for sid in domain_caps {
        declared_caps
            .push(crate::win_common::sid_to_string(*sid).map_err(|e| {
                AppContainerError::Win32(format!("sid_to_string(capability): {e}"))
            })?);
    }
    let capability_sids = daemon_capability_sids(
        &traverse_string,
        &spawn_request_string,
        &declared_caps,
        net,
        spawn_request,
    );
    let cow_diff_layer_capability = cow_diff_layer_capability
        .map(|sid| {
            crate::win_common::sid_to_string(sid).map_err(|e| {
                AppContainerError::Win32(format!("sid_to_string(cow diff layer): {e}"))
            })
        })
        .transpose()?;
    let redirector = daemon_redirector_spec(&inject, cow_diff_layer_capability)?;

    let step = |label: &'static str, e: windows::core::Error| {
        AppContainerError::Win32(format!("{label}: {e}"))
    };
    let mut handles = DaemonSpawnHandles::new();
    handles.job = Some(create_job_object().map_err(|e| step("create_job_object", e))?);
    let (stdout_read, stdout_write) =
        appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stdout)", e))?;
    clear_inherit(stdout_read);
    handles.stdout_read = Some(stdout_read);
    handles.stdout_write = Some(stdout_write);
    let (stderr_read, stderr_write) =
        appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stderr)", e))?;
    clear_inherit(stderr_read);
    handles.stderr_read = Some(stderr_read);
    handles.stderr_write = Some(stderr_write);
    if want_stdin {
        let (stdin_read, stdin_write) =
            appcontainer_pipe(container_sid).map_err(|e| step("appcontainer_pipe(stdin)", e))?;
        clear_inherit(stdin_write);
        handles.stdin_read = Some(stdin_read);
        handles.stdin_write = Some(stdin_write);
    }

    // この3端はSharedSpawnDaemonが成否によらず閉じる契約へ移す。
    let stdout_write = handles
        .stdout_write
        .take()
        .expect("stdout write was created");
    let stderr_write = handles
        .stderr_write
        .take()
        .expect("stderr write was created");
    let stdin_read = handles.stdin_read.take();
    // [段階6f-2] **窓口の名前をここで足さない。** Daemon自身が起こす直前に入れる
    // （`spawnd::server::Shared::request_pipe`のdoc）——トップレベルを起こす経路は
    // 今日3つあり、足す責任を呼び出し側へ配ると4つ目を足す人が忘れられる形になる。
    // 忘れた経路の子は、生成禁止を積んだ瞬間に**理由の見えない形で何も起動できなくなる**。
    let spawned = daemon.spawn_top_level(TopLevelSpawn {
        exe,
        args,
        cwd,
        env,
        domain: DomainSpec {
            name: domain_name.to_string(),
            policy_domain: policy_domain.to_string(),
            container_sid: container_sid_string,
            capability_sids,
            identity,
        },
        job: handles.job.expect("job was created"),
        stdout_write,
        stderr_write,
        stdin_read,
        redirector,
        console,
    });
    let spawned = spawned.map_err(daemon_failure_to_error)?;

    Ok(AppContainerChild {
        process: spawned.process,
        job: handles
            .job
            .take()
            .expect("job ownership transfers to child"),
        stdin_write: handles.stdin_write.take(),
        stdout_read: handles
            .stdout_read
            .take()
            .expect("stdout read ownership transfers to child"),
        stderr_read: handles
            .stderr_read
            .take()
            .expect("stderr read ownership transfers to child"),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_via_daemon<'a>(
    daemon: &crate::tier2a::spawnd::SharedSpawnDaemon,
    domain_name: &str,
    policy_domain: &str,
    exe: &str,
    args: &[&str],
    cwd: &Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: PSID,
    net: NetworkCapability,
    inject: impl Into<RedirectorInject<'a>>,
    domain: DomainIdentity,
    spawn_request: SpawnRequestAccess,
    console: ConsoleNeed,
) -> Result<AppContainerChild, AppContainerError> {
    spawn_with_workspace_via_daemon(
        daemon,
        domain_name,
        policy_domain,
        exe,
        args,
        cwd,
        env,
        want_stdin,
        container_sid,
        net,
        inject,
        &[],
        // CoWで注入する呼び出し元はここを通らない（MCPはプロセス生成フックだけ）。
        // 通したら[`daemon_redirector_spec`]が「CoWなのに宛先SIDが無い」で断る。
        None,
        domain,
        spawn_request,
        console,
    )
}

/// Daemonへ送る注入設定を、harness側で組み立てる。**Win32を呼ばない**ので単体テストできる。
///
/// # 綴りをここで揃える
///
/// **Redirectorへ渡すパスは、電文へ載せる前にharness側で綴りを揃える**
/// （[BUG-066](../../../../docs/bugs/BUG-066.md)）。`normalize_cow_root`は
/// `canonicalize`を使うので**呼び出したプロセスのcwdを基準に相対パスを解決する**——
/// 揃えるのをDaemon側（`augment_redirector_env`）だけに任せると、基準がDaemonのcwdになり、
/// BUG-066の修正が置いた「渡す前に一度だけ揃える唯一の絞り」がプロセス境界で失われる。
/// Daemon側の呼びはそのままでよい（canonical済みの絶対パスは冪等に畳まれる）。
///
/// # [BUG-180] CoWと差分層の宛先SIDは対でしか通さない
///
/// | CoWで注入するか | 宛先SID | 結果 |
/// |---|---|---|
/// | する | ある | 両方を載せた`Cow` |
/// | する | **無い** | **`Err`**——積むものが無いまま注入すると、子は変更前の中身を黙って読む |
/// | しない | **ある** | **`Err`**——引数の取り違えである。黙って捨てると、取り違えた側が気付けない |
/// | しない | 無い | lazy／プロセス生成フック／注入しない（今までどおり） |
pub(crate) fn daemon_redirector_spec(
    inject: &RedirectorInject<'_>,
    cow_diff_layer_capability: Option<String>,
) -> Result<Option<crate::tier2a::spawnd::RedirectorSpec>, AppContainerError> {
    use crate::tier2a::spawnd::RedirectorSpec;

    match (inject.cow, cow_diff_layer_capability) {
        (Some(cow), Some(diff_layer_capability_sid)) => Ok(Some(RedirectorSpec::Cow {
            workspace_root: normalize_cow_root(cow.workspace_root)
                .to_string_lossy()
                .into_owned(),
            diff_layer_dir: normalize_cow_root(cow.diff_layer_dir)
                .to_string_lossy()
                .into_owned(),
            ext_capture_roots: cow
                .ext_capture_roots
                .iter()
                .map(|path| normalize_cow_root(path).to_string_lossy().into_owned())
                .collect(),
            diff_layer_capability_sid,
        })),
        (Some(cow), None) => Err(AppContainerError::Preflight(format!(
            "refusing to inject the CoW redirector for {} without the diff layer's capability \
             SID: a child that cannot reach its diff layer reads the unmodified workspace \
             without any error (BUG-180)",
            cow.diff_layer_dir.display()
        ))),
        (None, Some(sid)) => Err(AppContainerError::Preflight(format!(
            "a CoW diff layer capability ({sid}) was passed for a spawn that does not inject \
             the CoW redirector; the arguments are mixed up (BUG-180)"
        ))),
        (None, None) => Ok(if let Some(pipe) = inject.broker_pipe {
            Some(RedirectorSpec::Lazy {
                workspace_root: normalize_cow_root(
                    inject
                        .workspace_root
                        .expect("lazy redirector requires workspace root"),
                )
                .to_string_lossy()
                .into_owned(),
                broker_pipe: pipe.to_string(),
            })
        } else if inject.process_hooks {
            // [段階5b] 誘導も受付も無い。**それでも注入する**（この変種のdoc）。
            Some(RedirectorSpec::ProcessHooks {
                workspace_root: inject
                    .workspace_root
                    .map(|root| normalize_cow_root(root).to_string_lossy().into_owned()),
            })
        } else {
            None
        }),
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
    cow: RedirectorInject<'_>,
    domain: DomainIdentity,
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

    // D-30（`--sandbox tier2a-cow`）: Redirector DLL初期化完了をLauncherへ知らせるための子側書込端。
    // `appcontainer_pipe`は既にpackage SIDへのACL付与を済ませているため、名前付きイベントを
    // 別途ACL構成するより既存の実績あるパイプ生成経路を再利用する（stdio 3本と同じ扱い）。
    // [D-88] 条件は「CoWか」ではなく「**DLLを注入するか**」になった。DirectRwのlazyレーンも
    // 同じresume前ハンドシェイクを通る（設計書§5.1.3「起動と自動fallback」の2）。
    let ready_pipe = if cow.wanted() {
        let (r, w) = appcontainer_pipe(container_sid)
            .map_err(|e| step("appcontainer_pipe(redirector-ready)", e))?;
        clear_inherit(r);
        Some((r, w))
    } else {
        None
    };

    // D-30: CoW有効時、Redirector DLL（`harness-redirector`）へworkspace/差分層のパスと
    // 準備完了通知用パイプの生ハンドル値を環境変数経由で渡す。ハンドル値はプロセス作成時に
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`（下記）で継承させるため、子プロセス内でも
    // 同一の数値のまま有効である（Windowsのハンドル継承の仕様）。
    let mut env_owned;
    let env = if let Some((_, ready_write)) = &ready_pipe {
        env_owned = env.to_vec();
        augment_redirector_env(&mut env_owned, cow, *ready_write);
        &env_owned
    } else {
        env
    };
    let mut env_block = build_env_block(env);

    // INV-2（ハンドル継承対策、設計書§28）: `bInheritHandles=true`のまま無制限に継承させず、
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`でstdioの3本（子側の書込/読取端のみ、いずれも
    // `create_pipe_with_sddl`が既に`bInheritHandle=true`で作成済み・親側端は上で`clear_inherit`
    // 済み）に限定する。リスト中の全ハンドルが継承可能である必要がある。
    //
    // **この配列は`STARTUPINFOEXW`のhStdOutput/hStdError/hStdInputの「上位集合」である**
    // （一致ではない）。`--sandbox tier2a-cow`時のready pipeの書込端はここに載るが、hStd*のどれでもない
    // ——子へは環境変数`HARNESS_COW_READY_HANDLE`で数値として渡すためである。
    // 不変条件は「**継承されるのはこの配列が全て**」の側であり、hStd*はその部分集合。
    // 継承ハンドルに何らかの検査を掛けるときは、hStd*ではなく**この配列**を対象にすること
    // （hStd*だけを見るとready pipe型の追加ハンドルが素通りする）。
    let mut inherit_handles: Vec<HANDLE> = vec![stdout_write, stderr_write];
    if let Some(r) = stdin_read {
        inherit_handles.push(r);
    }
    if let Some((_, ready_write)) = &ready_pipe {
        inherit_handles.push(*ready_write);
    }

    // 「一時停止で起こす → Jobへ入れる → トークンの既定DACLを差し替える」までは
    // [`create_suspended_in_job`]が行う（Spawn Daemonと共有する本体。同関数のdoc）。
    // **`inherit_handles`に載せたハンドルは、成否によらずあちらが閉じる。**
    let command_line = command_line_for(exe, args);
    let spawned = create_suspended_in_job(SuspendedSpawn {
        command_line: &command_line,
        // [段階6f-1] **この経路はharness自身が呼び出し元である**ので、コマンドライン任せの
        // ままでよい（[`SuspendedSpawn::application_name`]の表）。
        application_name: None,
        cwd,
        env_block: &mut env_block,
        container_sid,
        capabilities,
        inherit_handles: &inherit_handles,
        stdout_write,
        stderr_write,
        stdin_read,
        job,
        domain,
        // [段階⑤] **この経路は生成禁止を積まない。** `spawn_impl`はharnessが直接起こす経路で、
        // 製品のトップレベル生成はもうここを通らない（`launch.rs`の数え上げテスト）。
        // 生成禁止を積むのはSpawn Daemon側だけである——**代わりに起こす人が居ない場所で
        // 生成能力を取り上げると、そこから先が全部止まる**（1枚もの§2の順序の理由）。
        child_process_policy: ChildProcessPolicy::Unrestricted,
        // `Unrestricted`なので効かないが、**既定値を作らないと決めた**ので明示する
        // （[`ConsoleNeed`]のdoc）。この経路が起こすのはシェルである。
        console: ConsoleNeed::Required,
    });

    let process_info = match spawned {
        Ok(pi) => pi,
        Err(e) => {
            // どの段で落ちても、子は生成されていないか**resume前に明示終了済み**である
            // （[`create_suspended_in_job`]のdoc）。したがってここで閉じるのは
            // **この関数が作ったもの**だけでよい——作成途中のJobはkill-on-closeで破棄すれば
            // 足り、親側のパイプ端はもう誰も読まない。
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
        // D-30（`--sandbox tier2a-cow`）: suspended窓でRedirector DLLを注入する（設計書§10.2手順8-10）。
        // 注入または初期化確認に失敗した場合、対象プロセスを終了する（fail-close、
        // §10.2既定・§25.1）。workspace本体はACLで既にRO付与済みのため、この失敗パスは
        // 「透過リダイレクトが効かないまま起動を許す」ことはない——単に起動自体を拒否する。
        //
        // [D-88] **DirectRwのlazyレーンも同じ窓を通る。** ただし失敗の意味が違う——
        // CoWでは透過が丸ごと壊れるので起動を拒む必要があるが、lazyでは失われるのは
        // 速さだけである。**そのぶんの判断は呼び出し側（`launch`）が持つ**：ここは
        // どちらでも「子を殺してErrを返す」に統一し、lazyの呼び出し側がそのErrを見て
        // 全walkを待ってから通常起動へ落とす（設計書§5.1.3「起動と自動fallback」の3。
        // resume前なので子はユーザーコードを1行も実行しておらず、作り直しても副作用が
        // 二重にならない）。
        {
            let workspace_for_error = cow.workspace_root;
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
                    // 注入失敗時の子はresume前に明示終了済みで、孫を生成できない。
                    // 作成途中のJobはkill-on-closeで破棄すれば足りる。
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(stdout_read);
                    let _ = CloseHandle(stderr_read);
                    if let Some(w) = stdin_write {
                        let _ = CloseHandle(w);
                    }
                    return Err(AppContainerError::RedirectorInjection(format!(
                        "redirector injection failed for workspace {}: {e}",
                        workspace_for_error
                            .unwrap_or(Path::new("<unknown>"))
                            .display()
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

/// Tier2aシェルのラベル。`run_shell`の結果末尾（`[shell: ...]`）としてモデルへ出るので、
/// 語彙を勝手に増やさない（増やすなら`harness-tools`側の表示も対で見ること）。
pub(crate) const PWSH_LABEL: &str = "pwsh(Tier2a)";
pub(crate) const POWERSHELL51_LABEL: &str = "powershell5.1(Tier2a)";

/// このプロセスで使うと決まったシェル。[`select_shell_by_probe`]（`preflight_probe`）だけが書き、
/// [`resolve_shell`]だけが読む。
///
/// **workspace単位ではなくプロセス単位で1回**なのは、「どのシェルがこの機のAppContainerで
/// 動くか」がマシン単位の事実だからである（workspaceごとに答えが変わるものではない）。
static SELECTED_SHELL: std::sync::OnceLock<(String, &'static str)> = std::sync::OnceLock::new();

/// シェルの候補と、**姿勢のせいで外したもの**。
///
/// 外した理由を捨てないのは、`preflight`の警告に出すためである——黙って5.1へ落ちると、
/// 「pwsh 7があるのに使われない」が誰にも説明されない（`B-10`）。
pub(crate) struct ShellChoices {
    /// 優先順。**必ず1件以上ある**（5.1は外さない）。
    pub(crate) candidates: Vec<(String, &'static str)>,
    /// 生成禁止を積むために外した綴り（0件が普通）。
    pub(crate) dropped: Vec<String>,
}

/// その綴りは**アプリの仕組みを通って起きる**か（ストアの実行エイリアス／MSIXの実体）。
///
/// # なぜ遷移先にできないのか（2026-09-18に実測。§S62）
///
/// 生成禁止を積んだ子の中から起こす（＝nested）とき、**どちらの綴りも起こせない**。
/// 理由は2つで、どちらもこちら側では直せない。
///
/// | 綴り | 落ちる場所 |
/// |---|---|
/// | 実行エイリアス（`%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`） | `AssignProcessToJobObject`がアクセス拒否。OSが自分のJobへ先に入れるため（§S59） |
/// | MSIXの実体（`%ProgramFiles%\WindowsApps\...\pwsh.exe`） | `CreateProcessW`が`ERROR_INVALID_PARAMETER`。AppContainerからパッケージの実体を直に起こせない（§S1b・§S62） |
///
/// # 判定はパスの**成分**で行う
///
/// 文字列の`starts_with`だと`C:\Windows`が`C:\WindowsApps`に誤マッチする
/// （`acl_grant`のdocが同じ罠を書いている）。
pub fn starts_through_the_app_model(path: &str) -> bool {
    std::path::Path::new(path)
        .components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("WindowsApps"))
}

/// Tier2aで使うシェルの候補を**優先順**で返す（純粋関数。`which`の結果を引数で受ける）。
///
/// 1. `pwsh`（PowerShell 7）。**`WindowsApps`配下の実行エイリアスも、姿勢が素のままなら
///    候補から外さない。** 2026-08-13の実測では、AppContainer内で`CreateProcessW`が
///    通らなかったのはMSIXパッケージの**実体**の方で、エイリアスは6通り
///    （コンソール3構成×mitigation有無）すべてで起動できた（§S1b）。
/// 2. Windows PowerShell 5.1（System32の本物のexe。決してエイリアスにならない）。
///
/// MSIXの実体パスは候補に入れない——上の実測で6通りすべて`ERROR_INVALID_PARAMETER`だった。
///
/// # 生成禁止を積むなら、**遷移先にできる綴りしか選べない**（2026-09-18、残課題#50）
///
/// 積んだ子は自分で子プロセスを作れないので、シェルをもう一度起こすコマンド
/// （`pwsh -c ...`・ビルドスクリプト・フック）は**Daemonへの遷移**になる。
/// アプリの仕組みを通る綴りはその遷移先にできない（[`starts_through_the_app_model`]）ので、
/// **選んだ時点で、そのコマンドは必ず失敗する**。
///
/// **トップレベルは通る**（段階⑤の受け入れが実行エイリアスで緑）。だから
/// 「起動できるか」だけを見て選ぶと、**この失敗は選択の時点では見えない。**
fn shell_candidates_from(
    pwsh: Option<PathBuf>,
    system_root: &str,
    child_process_policy: crate::tier2a::spawnd::ChildProcessPolicy,
) -> ShellChoices {
    let mut candidates: Vec<(String, &'static str)> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    if let Some(pwsh) = pwsh {
        let pwsh = pwsh.to_string_lossy().into_owned();
        if child_process_policy.is_restricted() && starts_through_the_app_model(&pwsh) {
            dropped.push(pwsh);
        } else {
            candidates.push((pwsh, PWSH_LABEL));
        }
    }
    // **5.1は姿勢に関わらず残す。** 落ちる先が無くなる方が、古いシェルを使うより悪い。
    candidates.push((
        format!("{system_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        POWERSHELL51_LABEL,
    ));
    ShellChoices {
        candidates,
        dropped,
    }
}

/// [`shell_candidates_from`]をこの機の実環境へ当てたもの。**必ず1件以上返る**
/// （5.1のパスは実在確認をせずに積む——実在しない機ではプローブが落ちて理由が出る方が、
/// 候補が0件で「なぜ選べなかったか」が消えるより良い）。
///
/// **姿勢はこのプロセスが選んだものを読む**
/// （[`crate::tier2a::spawnd::child_process_policy_for_this_process`]。
/// 宣言が無ければ`PRODUCT_DEFAULT`）。ここで`Unrestricted`と書き下すと、
/// 生成禁止を積む回に**ここだけ取り残される**——そのときサンドボックスの中では
/// シェルを1本も起こせなくなる（残課題#50）。
///
/// **読むのはpreflightの中**（`select_shell_by_probe`）なので、宣言はそれより前に
/// 済んでいなければならない（`declare_child_process_policy`のdocの表）。
pub(crate) fn shell_candidates() -> ShellChoices {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    shell_candidates_from(
        which::which("pwsh").ok(),
        &system_root,
        crate::tier2a::spawnd::child_process_policy_for_this_process(),
    )
}

/// 選択結果をこのプロセスへ固定する。既に固定済みなら**最初の選択が勝つ**（`false`を返す）。
pub(crate) fn remember_selected_shell(selected: (String, &'static str)) -> bool {
    SELECTED_SHELL.set(selected).is_ok()
}

/// Tier2a（AppContainer）で使うシェルの実行ファイルパスとラベルを返す。
///
/// **選択は静的な決め打ちではなく、`preflight`が実際にAppContainer内でシェルを起こして
/// 決める**（`preflight_probe::select_shell_by_probe`）。既定はpwsh 7で、この機で起こせなければ
/// Windows PowerShell 5.1へ落ちる。落ちたことは`PreflightOutcome::warnings`に載る（B-10/B-11）。
///
/// preflightがまだ選んでいない場合は候補の先頭（＝pwsh 7）を返す。**本番でここを通るのは
/// preflightの後だけ**である——`resolve_shell`の非テスト呼び出しは4箇所
/// （`launch.rs`／`preflight_probe.rs`の3つ）で、Tier2aの子を起こす2経路（`run_shell`＝
/// `harness-tools`の`run_windows_tier2a`、ポリシーエディタのパス2＝`record_net`）は
/// どちらも自プロセスで`select_tier`→`preflight`を先に通る。
///
/// smoke testと`run_shell`本体が同じ解決を通るという不変条件は変えていない——読み口が
/// この関数1つだけであることがそれを保っている（「smokeが通ったのに本番で別のexeを使って
/// 失敗する」ずれを防ぐ、[BUG-007](docs/bugs/BUG-007.md)）。
pub fn resolve_shell() -> (String, &'static str) {
    if let Some(selected) = SELECTED_SHELL.get() {
        return selected.clone();
    }
    shell_candidates()
        .candidates
        .into_iter()
        .next()
        .expect("shell_candidates always yields at least PowerShell 5.1")
}

#[cfg(test)]
mod shell_resolution_tests {
    use super::*;

    /// **Aの回帰ガード**: `WindowsApps`配下の実行エイリアスを候補から**外さない**こと。
    ///
    /// 以前はここでパス文字列に`windowsapps`が含まれるかを見て静的に除外していた。
    /// 根拠は[BUG-007](docs/bugs/BUG-007.md)の「AppContainerからエイリアスを解決できない」
    /// だったが、2026-08-13の実測（`plans/mac-spike/RESULTS.md` §S1b）ではエイリアスは
    /// AppContainer内で6通りすべて起動でき、`ERROR_INVALID_PARAMETER`で落ちたのは
    /// MSIXの実体の方だった。**除外が復活したらここが赤くなる。**
    #[test]
    fn the_store_alias_is_a_candidate_not_an_exclusion() {
        let alias = PathBuf::from(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\pwsh.exe");
        let choices = shell_candidates_from(
            Some(alias.clone()),
            r"C:\Windows",
            ChildProcessPolicy::Unrestricted,
        );
        assert_eq!(
            choices
                .candidates
                .first()
                .map(|(path, label)| (path.as_str(), *label)),
            Some((alias.to_string_lossy().as_ref(), PWSH_LABEL)),
            "pwshは実行エイリアスであっても第1候補でなければならない（実測§S1b）"
        );
        assert!(
            choices.dropped.is_empty(),
            "生成禁止を積まない構成で候補を外している。今日の製品の挙動が変わる"
        );
    }

    /// **上の対**（残課題#50、2026-09-18）: 生成禁止を積むなら、アプリの仕組みを通る綴りは
    /// 候補から外れ、**外したことが残る**。
    ///
    /// # この1本が無いと何が起きるか
    ///
    /// 上の1本だけだと「常に外さない」実装で緑のままになり、⑤を既定へ入れた日に
    /// **サンドボックスの中からシェルを1本も起こせなくなる**（§S62。エイリアスは
    /// Jobへ入れられず、MSIXの実体は`CreateProcessW`が拒む）。
    /// トップレベルの起動は通るので、**選択の時点では何も症状が出ない。**
    #[test]
    fn the_store_alias_is_dropped_when_child_process_creation_is_restricted() {
        let alias = PathBuf::from(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\pwsh.exe");
        let choices = shell_candidates_from(
            Some(alias.clone()),
            r"C:\Windows",
            ChildProcessPolicy::Restricted,
        );
        assert_eq!(
            choices
                .candidates
                .iter()
                .map(|(_, label)| *label)
                .collect::<Vec<_>>(),
            vec![POWERSHELL51_LABEL],
            "生成禁止を積むなら、遷移先にできない綴りは候補に残ってはならない"
        );
        assert_eq!(
            choices.dropped,
            vec![alias.to_string_lossy().into_owned()],
            "外した綴りが残っていない。**黙って5.1へ落ちると誰も理由を知らない**（`B-10`）"
        );
    }

    /// **機に依存させない**: MSIで入れたpwsh 7（アプリの仕組みを通らない本物のexe）は、
    /// 生成禁止を積んでも第1候補のまま残る。
    ///
    /// これが無いと、上の1本は「生成禁止ならpwshを常に捨てる」実装でも緑になる。
    #[test]
    fn a_real_pwsh_executable_survives_the_restriction() {
        let real = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        let choices = shell_candidates_from(
            Some(real.clone()),
            r"C:\Windows",
            ChildProcessPolicy::Restricted,
        );
        assert_eq!(
            choices
                .candidates
                .first()
                .map(|(path, label)| (path.as_str(), *label)),
            Some((real.to_string_lossy().as_ref(), PWSH_LABEL)),
            "アプリの仕組みを通らないpwshまで捨てている。外す条件はパスの成分1つである"
        );
        assert!(choices.dropped.is_empty());
    }

    /// `C:\Windows`が`C:\WindowsApps`に誤マッチしないこと（成分で見ている証拠）。
    #[test]
    fn the_app_model_check_compares_path_components_not_prefixes() {
        assert!(starts_through_the_app_model(
            r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe"
        ));
        assert!(starts_through_the_app_model(
            r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\pwsh.exe"
        ));
        assert!(!starts_through_the_app_model(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        assert!(
            !starts_through_the_app_model(r"C:\WindowsApps-mine\tool.exe"),
            "成分ではなく前方一致で見ている。似た名前のディレクトリを巻き込む"
        );
    }

    /// 候補は常に「pwsh → 5.1」の順で、5.1は**必ず最後に残る**。
    /// 5.1が候補から消えると、pwshが起こせない機で落ちる先が無くなる。
    #[test]
    fn powershell51_is_always_the_last_resort() {
        let with_pwsh = shell_candidates_from(
            Some(PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe")),
            r"C:\Windows",
            ChildProcessPolicy::Unrestricted,
        )
        .candidates;
        assert_eq!(with_pwsh.len(), 2, "pwshがある機では候補は2本");
        assert_eq!(
            with_pwsh.last().map(|(path, label)| (path.clone(), *label)),
            Some((
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
                POWERSHELL51_LABEL
            ))
        );

        let without_pwsh =
            shell_candidates_from(None, r"C:\Windows", ChildProcessPolicy::Unrestricted).candidates;
        assert_eq!(
            without_pwsh.len(),
            1,
            "pwshが無い機では候補は5.1だけ（＝プローブを撃つ必要が無い）"
        );
        assert_eq!(without_pwsh[0].1, POWERSHELL51_LABEL);
    }

    /// `SystemRoot`が既定と違う機でも5.1のパスをそこから組み立てる。
    #[test]
    fn powershell51_is_built_from_the_given_system_root() {
        let candidates =
            shell_candidates_from(None, r"D:\WinNT", ChildProcessPolicy::Unrestricted).candidates;
        assert_eq!(
            candidates[0].0,
            r"D:\WinNT\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
    }

    // **選択キャッシュ（`SELECTED_SHELL`）はここでは書かない。** `OnceLock`はプロセス単位で、
    // 単体テストが書くと同じテストバイナリ内の他のテスト（実機テストを含む）が読む
    // 製品の実行時状態を書き換えることになる（BUG-108と同型、B-27）。ここで測るのは
    // 純粋関数だけにし、選択の判定そのものは`preflight_probe::judge_probe`側で測る。
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
        assert!(
            expected.is_absolute(),
            "canonical form must be absolute: {expected:?}"
        );
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

/// [BUG-180] Daemonへ送る注入設定の組み立て。**CoWと差分層の宛先SIDは対でしか通さない。**
#[cfg(test)]
mod daemon_redirector_spec_tests {
    use super::*;
    use crate::tier2a::spawnd::RedirectorSpec;

    const DIFF_LAYER_SID: &str = "S-1-15-3-1024-7";

    fn cow_inject<'a>(ws: &'a Path, diff: &'a Path, ext: &'a [PathBuf]) -> RedirectorInject<'a> {
        RedirectorInject::for_tier2a(
            Some(ws),
            Some(CowInject {
                workspace_root: ws,
                diff_layer_dir: diff,
                ext_capture_roots: ext,
            }),
            None,
        )
    }

    /// CoWで注入するなら、宛先SIDは注入設定の中へ入る。
    #[test]
    fn a_cow_injection_carries_the_diff_layer_capability() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ext = vec![dir.path().join("outside")];
        let spec = daemon_redirector_spec(
            &cow_inject(dir.path(), &dir.path().join("diff"), &ext),
            Some(DIFF_LAYER_SID.to_string()),
        )
        .expect("a CoW injection with its capability is accepted");
        match spec {
            Some(RedirectorSpec::Cow {
                diff_layer_capability_sid,
                ext_capture_roots,
                ..
            }) => {
                assert_eq!(diff_layer_capability_sid, DIFF_LAYER_SID);
                assert_eq!(ext_capture_roots.len(), 1);
            }
            other => panic!("CoWの注入設定になっていない: {other:?}"),
        }
    }

    /// **本体**: CoWなのに宛先SIDが無ければ断る。黙って注入すると、差分層へ届かない子が
    /// 変更前の中身を読む（BUG-180）。
    #[test]
    fn a_cow_injection_without_the_diff_layer_capability_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result =
            daemon_redirector_spec(&cow_inject(dir.path(), &dir.path().join("diff"), &[]), None);
        match result {
            Err(AppContainerError::Preflight(message)) => assert!(
                message.contains("BUG-180"),
                "断った理由が原因を名指していない: {message}"
            ),
            other => panic!("宛先SIDの無いCoWの注入を通した: {other:?}"),
        }
    }

    /// 宛先SIDだけ渡されてCoWでないのは、引数の取り違えである。黙って捨てない。
    #[test]
    fn a_diff_layer_capability_without_a_cow_injection_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = daemon_redirector_spec(
            &RedirectorInject::for_tier2a(Some(dir.path()), None, None),
            Some(DIFF_LAYER_SID.to_string()),
        );
        assert!(
            matches!(result, Err(AppContainerError::Preflight(_))),
            "CoWでない注入に差分層の宛先SIDを渡したのに通った: {result:?}"
        );
    }

    /// **対の側**（`B-35`）: CoWでない注入は今までどおり組み立てる。
    ///
    /// 片方だけだと、「宛先SIDが無ければ常に断る」実装でも上のテストが通る。
    #[test]
    fn non_cow_injections_are_built_as_before() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hooks = daemon_redirector_spec(
            &RedirectorInject::for_tier2a(Some(dir.path()), None, None),
            None,
        )
        .expect("process hooks");
        assert!(
            matches!(hooks, Some(RedirectorSpec::ProcessHooks { .. })),
            "{hooks:?}"
        );

        let lazy = daemon_redirector_spec(&RedirectorInject::lazy(dir.path(), "pipe"), None)
            .expect("lazy");
        assert!(
            matches!(lazy, Some(RedirectorSpec::Lazy { .. })),
            "{lazy:?}"
        );

        let none =
            daemon_redirector_spec(&RedirectorInject::default(), None).expect("no injection");
        assert_eq!(none, None);
    }
}
