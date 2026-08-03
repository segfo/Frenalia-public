//! **呼び出し元の認可**。常駐daemonが、パイプへ接続してきた相手を「本当に自分を起動した
//! 非昇格のharness本体か」と検証し、要求されたワークスペースへの書込権限を確かめる。
//!
//! 常駐daemonは固定名のパイプ（`session_daemon_pipe_name`）でサーバとして待ち受けるため、
//! 同一ユーザーの誰でも名前を知り得る。パイプのDACLを呼び出しユーザー専有にする
//! （`harness_sandbox::win_pipe_ipc::user_only_security_attributes`）だけでは「同一ユーザーの別プロセス」を
//! 排除できないため、次の3段で認可する。
//!
//! 1. **身元検証** — `verify_pipe_client_identity`が、接続元PIDのトークンSIDと実行イメージパスを
//!    照合する（daemon起動時に親から渡された`--owner-sid`/`--owner-exe`と一致するか）。
//! 2. **危険なworkspace_rootの拒否** — `reject_dangerous_workspace_root`が、システムディレクトリ等を
//!    ワークスペースとして要求されても弾く。
//! 3. **実効的な書込権限の確認** — `access_check_write`が、**クライアントのトークンで**
//!    `AccessCheck`を行う。daemonは昇格しているため自分の権限で判定すると常に通ってしまう。
//!
//! Tier3のセキュリティ判定の中核であり、レビュー時にここだけを読めば「daemonが誰の要求を
//! 受け付けるか」が尽きるよう独立したファイルにしている（`docs/CODE-STRUCTURE-RULES.md`規則3）。

use super::*;


/// 指定PIDのプロセスのトークンSIDを取得する（S-2、`verify_pipe_client_identity`専用）。
/// `process_is_alive`（`vmsandbox.rs`）と同じ`PROCESS_QUERY_LIMITED_INFORMATION`で
/// `OpenProcess`する（daemonは昇格済みトークンで動作しており、同一ユーザーの他プロセスを
/// 開くのに十分な権限を持つ）。
pub(super) fn query_process_token_sid(pid: u32) -> Result<String, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut token = HANDLE::default();
        let open_result =
            OpenProcessToken(process, windows::Win32::Security::TOKEN_QUERY, &mut token);
        let _ = CloseHandle(process);
        open_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcessToken({pid}) failed: {e}")))?;
        let result = sid_string_from_token(token).map_err(|e| {
            VmSandboxIpcError::Ipc(format!("sid_string_from_token({pid}) failed: {e}"))
        });
        let _ = CloseHandle(token);
        result
    }
}

/// 指定PIDのプロセスの実行イメージの絶対パスを取得する（S-2、`verify_pipe_client_identity`・
/// `verify_pipe_server_identity`共用）。
pub(super) fn query_process_image_path(pid: u32) -> Result<PathBuf, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(process);
        result.map_err(|e| {
            VmSandboxIpcError::Ipc(format!("QueryFullProcessImageNameW({pid}) failed: {e}"))
        })?;
        buf.truncate(len as usize);
        Ok(PathBuf::from(String::from_utf16_lossy(&buf)))
    }
}

/// `\\?\`プレフィックスの有無・大文字小文字ゆれを無視してパスを比較する（S-2、
/// `QueryFullProcessImageNameW`は`PROCESS_NAME_WIN32`指定時プレフィックス無しの
/// パスを返すが、`std::env::current_exe()`側が付ける可能性もあるため両対応する）。
pub(super) fn paths_equal_ci(a: &Path, b: &Path) -> bool {
    fn normalize(p: &Path) -> String {
        let s = p.to_string_lossy();
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_lowercase()
    }
    normalize(a) == normalize(b)
}

/// daemon側(サーバ)が、`ConnectNamedPipe`成功後に接続してきたクライアントの身元を検証する
/// （S-2）。固定パイプ名化により「パイプ名を知っている」こと自体は認可根拠として機能しなく
/// なるため、(a)対向プロセスの実行イメージパスが起動元harness.exeと一致すること、
/// (b)対向プロセスのトークンSIDが起動元ユーザーのSID(`owner_sid`)と一致すること、の両方を
/// 確認する。(b)はパイプのSDDLと独立した二重チェック（defense-in-depth）。
/// `ImpersonateNamedPipeClient`は意図的に使わない: daemonは既に昇格済みトークンで動作して
/// おり、クライアント側権限へ降格する理由も必要もない。
pub(super) fn verify_pipe_client_identity(
    pipe: HANDLE,
    owner_sid: &str,
    expected_owner_exe: &Path,
) -> Result<u32, VmSandboxIpcError> {
    let mut client_pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) }
        .map_err(|e| VmSandboxIpcError::Ipc(format!("GetNamedPipeClientProcessId failed: {e}")))?;

    let image_path = query_process_image_path(client_pid)?;
    if !paths_equal_ci(&image_path, expected_owner_exe) {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} image path mismatch: got {image_path:?}, expected \
             {expected_owner_exe:?}"
        )));
    }

    let client_sid = query_process_token_sid(client_pid)?;
    if client_sid != owner_sid {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} sid mismatch: got {client_sid}, expected {owner_sid}"
        )));
    }

    Ok(client_pid)
}

/// 親側(クライアント)が、固定パイプへの接続先が本当に正規daemonかをbest-effortで確認する
/// （S-2、パイプスクワッティングへの第一関門）。named pipeにはクライアントがサーバの正当性を
/// 検証する標準APIが無いため、これは診断的な早期拒否に留まる——真の防御は
/// [`verify_pipe_client_identity`]側（daemonが接続してきたクライアントを検証する）にある。
pub(super) fn verify_pipe_server_identity(
    pipe: HANDLE,
    expected_daemon_exe: &Path,
) -> Result<(), VmSandboxIpcError> {
    let mut server_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) }
        .map_err(|e| VmSandboxIpcError::Ipc(format!("GetNamedPipeServerProcessId failed: {e}")))?;
    let image_path = query_process_image_path(server_pid)?;
    if !paths_equal_ci(&image_path, expected_daemon_exe) {
        return Err(VmSandboxIpcError::Rejected(format!(
            "pipe server pid {server_pid} image path mismatch (possible squatting): got \
             {image_path:?}, expected {expected_daemon_exe:?}"
        )));
    }
    Ok(())
}

/// `%SystemRoot%`（通常`C:\Windows`）を正規化して返す（S-2段階4、
/// [`reject_dangerous_workspace_root`]専用）。環境変数が読めない場合は`None`を返し、
/// この一件だけで拒否判定をスキップする（`AccessCheck`側が最終防衛線であるため）。
pub(super) fn system_root_canonical() -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot")?;
    std::fs::canonicalize(root).ok()
}

/// `\\?\`プレフィックスを剥がした文字列表現（[`paths_equal_ci`]のnormalizeと同じ考え方、
/// 拒否リストの判定・エラーメッセージ用）。
fn strip_verbatim_prefix(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// `workspace_root`がドライブルート・システムディレクトリ・UNC/ネットワークパスでないことを
/// 確認する（S-2段階4、拒否リスト。`DESIGN-SANDBOX-VMISOLATION.md`7-a参照）。
/// 認可の本体は[`authorize_workspace_root`]の`AccessCheck`側であり、この関数は
/// 「`AccessCheck`が通ってしまう病的なDACLのマシン」に備えた belt-and-braces に過ぎない。
pub(super) fn reject_dangerous_workspace_root(canonical: &Path) -> Result<(), VmSandboxIpcError> {
    let stripped = strip_verbatim_prefix(canonical);

    // `canonicalize`はUNCパスを`\\?\UNC\server\share`へ正規化する。
    if stripped.starts_with(r"UNC\") || stripped.starts_with(r"\\") {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root must not be a UNC/network path: {stripped}"
        )));
    }

    // ドライブルート（`C:\`等）は`parent()`が`None`になる（プレフィックス+ルート以外の
    // 構成要素を持たないパス）。
    if canonical.parent().is_none() {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root must not be a drive root: {stripped}"
        )));
    }

    if let Some(system_root) = system_root_canonical() {
        if canonical.starts_with(&system_root) {
            return Err(VmSandboxIpcError::Rejected(format!(
                "workspace_root must not be inside the Windows system directory: {stripped}"
            )));
        }
    }

    Ok(())
}

/// クライアントプロセスのトークンを複製し、`AccessCheck`専用のimpersonationレベルトークンを
/// 得る（S-2段階4）。**`ImpersonateNamedPipeClient`は使わない**——ここで作るトークンは
/// [`access_check_write`]（`AccessCheck`Win32 APIの入力）としてのみ渡し、daemon自身の
/// スレッドをクライアント権限へ実際に偽装することはしない。段階3で明記した方針
/// （`verify_pipe_client_identity`のdoc参照）と同じ理由。
pub(super) fn duplicate_client_token_for_access_check(pid: u32) -> Result<HANDLE, VmSandboxIpcError> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcess({pid}) failed: {e}")))?;
        let mut token = HANDLE::default();
        let open_result = OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token);
        let _ = CloseHandle(process);
        open_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("OpenProcessToken({pid}) failed: {e}")))?;

        let mut imp_token = HANDLE::default();
        let dup_result = DuplicateToken(token, SecurityImpersonation, &mut imp_token);
        let _ = CloseHandle(token);
        dup_result
            .map_err(|e| VmSandboxIpcError::Ipc(format!("DuplicateToken({pid}) failed: {e}")))?;
        Ok(imp_token)
    }
}

/// `path`（ファイルオブジェクト）に対して、`token`（impersonationレベル）が書き込みアクセス
/// （`FILE_GENERIC_WRITE`）を持つかを`AccessCheck`で判定する（S-2段階4本体）。
pub(super) fn access_check_write(path: &Path, token: HANDLE) -> Result<bool, VmSandboxIpcError> {
    unsafe {
        let path_w = wide(&path.to_string_lossy());
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
        .ok()
        .map_err(|e| {
            VmSandboxIpcError::Ipc(format!("GetNamedSecurityInfoW({path:?}) failed: {e}"))
        })?;

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ.0,
            GenericWrite: FILE_GENERIC_WRITE.0,
            GenericExecute: FILE_GENERIC_EXECUTE.0,
            GenericAll: FILE_ALL_ACCESS.0,
        };

        let mut privilege_set_buf = [0u8; 1024];
        let mut privilege_set_len = privilege_set_buf.len() as u32;
        let mut granted_access = 0u32;
        let mut access_status = windows::Win32::Foundation::BOOL(0);

        let result = AccessCheck(
            sd,
            token,
            FILE_GENERIC_WRITE.0,
            &mapping,
            Some(privilege_set_buf.as_mut_ptr() as *mut PRIVILEGE_SET),
            &mut privilege_set_len,
            &mut granted_access,
            &mut access_status,
        );
        let _ = LocalFree(HLOCAL(sd.0));
        result.map_err(|e| VmSandboxIpcError::Ipc(format!("AccessCheck({path:?}) failed: {e}")))?;
        Ok(access_status.as_bool())
    }
}

/// `workspace_root`が (a) 実在するディレクトリで、(b) ドライブルート・システムディレクトリ・
/// UNC/ネットワークパスでなく、(c) 接続元クライアントのトークンが既に書き込み権を持つ、
/// の3点を満たすことを確認する（S-2段階4、`DESIGN-SANDBOX-VMISOLATION.md`7-a）。
///
/// [`verify_pipe_client_identity`]が「接続してきたのが正規`harness.exe`である」ことを
/// 検証するのに対し、本関数は「その`harness.exe`が要求している`workspace_root`へ既に
/// アクセス権を持っているか」を検証する——別の不変条件であり、互いを代替しない。固定パイプ名化
/// により同一ユーザーの任意の`harness.exe`起動から`StartSession`が送られ得るようになった以上、
/// 「呼び出し元が既に持つ権限を超えさせない」という不変条件がここでの唯一の実質的な認可点になる
/// （nonceハンドシェイクを不採用とした根拠、同文書7-b参照）。
pub(super) fn authorize_workspace_root(
    client_pid: u32,
    workspace_root: &Path,
) -> Result<(), VmSandboxIpcError> {
    let canonical = std::fs::canonicalize(workspace_root).map_err(|e| {
        VmSandboxIpcError::Rejected(format!(
            "workspace_root does not exist or is not accessible: {workspace_root:?}: {e}"
        ))
    })?;
    if !canonical.is_dir() {
        return Err(VmSandboxIpcError::Rejected(format!(
            "workspace_root is not a directory: {canonical:?}"
        )));
    }

    reject_dangerous_workspace_root(&canonical)?;

    let imp_token = duplicate_client_token_for_access_check(client_pid)?;
    let allowed = access_check_write(&canonical, imp_token);
    unsafe {
        let _ = CloseHandle(imp_token);
    }
    if !allowed? {
        return Err(VmSandboxIpcError::Rejected(format!(
            "client pid {client_pid} does not have write access to workspace_root: {canonical:?}"
        )));
    }
    Ok(())
}
