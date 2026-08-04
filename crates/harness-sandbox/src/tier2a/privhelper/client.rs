//! **非特権側**（harness本体プロセス）から特権分離ヘルパーを呼ぶクライアント。
//!
//! `runas`でヘルパーを昇格起動し（UACダイアログはここで出る）、名前付きパイプで
//! `PrivilegedRequestEnvelope`を1往復して結果を受け取る。このファイルのコードは
//! **管理者権限では動かない**——昇格側の実装は`server`が持つ。信頼境界をファイル境界に
//! 一致させ、「どのコードが昇格した権限で動くのか」をファイル単位で判別できるようにする
//! （`docs/CODE-STRUCTURE-RULES.md`規則3）。

use super::*;



/// ヘルパー実行ファイル（`harness-privhelper.exe`）のパスを、本体exeと同じディレクトリから
/// 解決する（PATH検索に頼らない固定ロケーション、D-16の「小さく独立にビルド・監査可能な
/// 別バイナリ」を確実に本体と対で配布する前提）。
fn helper_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| PrivHelperError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-privhelper.exe"))
}

/// 特権操作をヘルパーへ委譲し、完了まで待つ（client側、非管理者本体から呼ぶ）。
/// 1. 現在ユーザSID限定DACLでnamed pipe serverを作る。
/// 2. `runas`でヘルパーをパイプ名引数付きで昇格起動する（UACが表示される）。
/// 3. ヘルパーの接続を待ち、要求を送信し、応答を受け取る。
///
/// 返り値は「実際にACEが付与されたノードの一覧」（`GrantTraverse`のみ意味を持つ。
/// `RevokeTraverse`成功時は常に空`Vec`）。`Err(PrivHelperError::PartialGrantChain { granted, .. })`
/// の場合も`granted`に途中まで成功したノードが入るため、呼び出し側は`Err`だからと無視せず
/// 中身を確認して台帳へ反映する必要がある（孤立ACE防止）。`GrantFsAllow`はエントリごとに
/// 成否が独立するため、この関数ではなく[`run_privileged_fs_allow`]を使う。
pub fn run_privileged(req: &PrivilegedRequest) -> Result<Vec<PathBuf>, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(req.clone());
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::Ok => Ok(Vec::new()),
        PrivilegedResponse::GrantChain {
            granted,
            error: None,
        } => Ok(granted),
        PrivilegedResponse::GrantChain {
            granted,
            error: Some(reason),
        } => Err(PrivHelperError::PartialGrantChain { granted, reason }),
        PrivilegedResponse::FsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected FsAllowResult response for a non-GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a non-RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a non-GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_fs_allow`の成功値（`granted`パス一覧、`(path, reason)`失敗一覧）。
pub type FsAllowGrantOutcome = (Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `run_privileged_revoke_fs_allow`の成功値（`revoked`完全撤収一覧、`root_cleared`
/// root撤収済み・子孫ブロック一覧、`(path, reason)`失敗一覧）。`revoked`と`root_cleared`は
/// どちらも台帳から除去してよい（`root_cleared`は孤立ACEにならない、`RevokeOutcome`参照）。
pub type FsAllowRevokeOutcome = (Vec<PathBuf>, Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `GrantFsAllow`専用の委譲関数。`run_privileged`と異なりエントリごとの成否（`granted`/
/// `failures`）を両方とも呼び出し側へそのまま返す（1エントリの失敗が「エラー」ではなく
/// 正常な部分結果であるため、`run_privileged`の`Result<Vec<PathBuf>, _>`という単一成功値の
/// 形には馴染まない）。WFP連鎖起動が不要な既存呼び出し元向けの薄いラッパー
/// （[`run_privileged_fs_allow_with_netfilterd_chain`]を`chain_pipe: None`で呼ぶだけ）。
pub fn run_privileged_fs_allow(
    entries: Vec<FsAllowGrant>,
) -> Result<FsAllowGrantOutcome, PrivHelperError> {
    run_privileged_fs_allow_with_netfilterd_chain(entries, None)
}

/// `run_privileged_fs_allow`のWFP連鎖起動対応版（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`
/// 付録D シナリオ(A)）。`chain_pipe`が`Some`なら、ヘルパーはこのACL操作の応答を送った後、
/// 指定named pipeで`harness-netfilterd`を追加起動してから終了する
/// （モジュールdoc「例外: WFP連鎖起動」参照）。
pub fn run_privileged_fs_allow_with_netfilterd_chain(
    entries: Vec<FsAllowGrant>,
    chain_pipe: Option<String>,
) -> Result<FsAllowGrantOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope {
        request: PrivilegedRequest::GrantFsAllow { entries },
        chain_netfilterd_pipe: chain_pipe,
    };
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::FsAllowResult { granted, failures } => Ok((granted, failures)),
        PrivilegedResponse::Ok => Ok((Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => {
            // スキーマ上あり得ないはずの応答だが、fail-safeとして「全て失敗」扱いにはせず
            // grantedをそのまま伝える（孤立ACE防止の原則を維持）。
            Ok((
                granted,
                error.map(|e| vec![(PathBuf::new(), e)]).unwrap_or_default(),
            ))
        }
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_workspace_access`の成功値（traverse付与ノード一覧・traverse失敗理由・
/// fs-allow付与一覧・fs-allow失敗一覧）。
pub type WorkspaceAccessOutcome = (Vec<PathBuf>, Option<String>, Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `GrantWorkspaceAccess`専用の委譲関数（`win_appcontainer::preflight`がtraverse不足を自動検知
/// したときに呼ぶ）。`run_privileged_fs_allow_with_netfilterd_chain`と同じく`chain_pipe`で
/// WFP連鎖起動にも対応する——**新しい特権操作を追加する際の注意点**: 同一起動内で2回目の
/// `run_privileged*`（＝2回目のUAC）を独立に呼び出してはならない。この関数のように、
/// 1回の起動で必要になり得る特権操作をすべて1つの`PrivilegedRequestEnvelope`へ束ねること
/// （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16参照）。
pub fn run_privileged_workspace_access(
    traverse_targets: Vec<PathBuf>,
    fs_allow_entries: Vec<FsAllowGrant>,
    chain_pipe: Option<String>,
) -> Result<WorkspaceAccessOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope {
        request: PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
            // D-37: fs-allowの付与先はこのセッションのpackage SID（名前で渡し、受信側が検証・導出する）。
            session_profile: crate::tier2a::session_profile::current_profile_name(),
        },
        chain_netfilterd_pipe: chain_pipe,
    };
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::WorkspaceAccessResult {
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
        } => Ok((
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
        )),
        PrivilegedResponse::Ok => Ok((Vec::new(), None, Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => {
            Ok((granted, error, Vec::new(), Vec::new()))
        }
        PrivilegedResponse::FsAllowResult { granted, failures } => {
            Ok((Vec::new(), None, granted, failures))
        }
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `RevokeFsAllow`専用の委譲関数（`run_privileged_fs_allow`の裏対称、`BUG-015`参照）。
/// `entries`は`harness fs revoke`/`revoke-all`が本体プロセス内で撤収しきれなかったパス
/// （`forced`情報付き）の一覧。
pub fn run_privileged_revoke_fs_allow(
    entries: Vec<FsAllowRevoke>,
) -> Result<FsAllowRevokeOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeFsAllow { entries });
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::RevokeFsAllowResult {
            revoked,
            root_cleared,
            failures,
        } => Ok((revoked, root_cleared, failures)),
        PrivilegedResponse::Ok => Ok((Vec::new(), Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => Ok((
            granted,
            Vec::new(),
            error.map(|e| vec![(PathBuf::new(), e)]).unwrap_or_default(),
        )),
        PrivilegedResponse::FsAllowResult { granted, failures } => {
            Ok((granted, Vec::new(), failures))
        }
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

fn run_privileged_raw(
    envelope: &PrivilegedRequestEnvelope,
) -> Result<PrivilegedResponse, PrivHelperError> {
    let pipe_name = unique_pipe_name();
    let sid = current_user_sid_string()?;
    let mut sa = user_only_security_attributes(&sid)?;

    let pipe = unsafe {
        let pipe_name_w = wide(&pipe_name);
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        if handle.is_invalid() {
            return Err(PrivHelperError::from(windows::core::Error::from_win32()));
        }
        handle
    };

    let helper_path = helper_exe_path()?;
    // 【重要】ここでヘルパープロセスの終了を待ってはいけない。ヘルパー（`serve`）は
    // 「親から要求を受信する」ことを待っており、親はまだ要求を送っていない。もしここで
    // ヘルパーの終了を待つと、親は「ヘルパー終了待ち」・ヘルパーは「親からの送信待ち」の
    // 循環待機（デッドロック）に陥る（実機のUACテストで実際に発生を確認、`launch_helper_elevated`
    // 内部で`WaitForSingleObject(INFINITE)`していた旧実装のバグ）。プロセスハンドルは
    // IPC完了後に回収する。
    let helper_process = match unsafe { launch_helper_elevated(&helper_path, &pipe_name) } {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };

    let result = run_ipc_exchange(pipe, envelope);

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
        if !helper_process.is_invalid() {
            // ヘルパーは応答送信直後（またはIPCタイムアウト後の異常系）に終了するはずなので、
            // 短いタイムアウトで待つ（既にIPCが完了/断念した後の後始末であり、ここでの待機は
            // デッドロックを起こさない）。
            let wait = WaitForSingleObject(helper_process, 5000);
            if wait != WAIT_OBJECT_0 {
                // 5秒経っても終了しない = staleの疑い。前回セッションで「非昇格からkillできない
                // stale privhelper.exeが残留する」不具合が起きたため、ここで強制終了する。
                // `ShellExecuteExW`(SEE_MASK_NOCLOSEPROCESS)で取得したこのハンドルは、
                // 起動時点で既に十分なアクセス権を保持しているため、非昇格プロセスからでも
                // `TerminateProcess`が成功する（`OpenProcess`を後から呼ぶ経路ではない）。
                let _ = TerminateProcess(helper_process, 1);
                let _ = WaitForSingleObject(helper_process, 2000);
            }
            let _ = CloseHandle(helper_process);
        }
    }

    result
}

/// パイプ接続・要求送信・応答受信の本体（ヘルパープロセスの生死待ちとは独立させる、
/// デッドロック回避のため`run_privileged_raw`から分離）。応答の解釈は行わず、パースした
/// `PrivilegedResponse`をそのまま返す（要求variantごとの解釈は呼び出し元
/// `run_privileged`/`run_privileged_fs_allow`の責務）。
fn run_ipc_exchange(
    pipe: HANDLE,
    envelope: &PrivilegedRequestEnvelope,
) -> Result<PrivilegedResponse, PrivHelperError> {
    connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        PrivHelperError::Ipc(format!(
            "waiting for helper to connect: {e} (helper may not have launched, or UAC is still \
             pending user interaction)"
        ))
    })?;

    let request_bytes = serde_json::to_vec(envelope)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize request: {e}")))?;
    write_framed_timeout(pipe, &request_bytes, REQUEST_WRITE_TIMEOUT)?;

    let response_bytes = read_framed_timeout(pipe, RESPONSE_READ_TIMEOUT).map_err(|e| {
        PrivHelperError::Ipc(format!(
            "{e} (the privileged operation may still be in progress on a slow node — this \
             machine has previously shown pathologically slow DACL writes near the user \
             profile root, see docs/bugs/BUG-011.md; check %APPDATA%\\harness\\privhelper.log \
             for per-node timing)"
        ))
    })?;
    serde_json::from_slice(&response_bytes)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to parse helper response: {e}")))
}

/// `runas`でヘルパーを昇格起動する。ユーザがUACを拒否した場合は`ERROR_CANCELLED`が返るため
/// `ElevationDeclined`へ変換する（親側がハングせず即座にエラーを返せる）。起動した
/// プロセスのハンドルを返すのみで、終了は待たない（呼び出し側がIPC完了後に待つ、
/// デッドロック回避）。
unsafe fn launch_helper_elevated(
    helper_path: &std::path::Path,
    pipe_name: &str,
) -> Result<HANDLE, PrivHelperError> {
    let verb_w = wide("runas");
    let file_w = wide(&helper_path.to_string_lossy());
    let params_w = wide(pipe_name);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let ok = ShellExecuteExW(&mut info);
    if ok.is_err() {
        let err = GetLastError();
        if err == ERROR_CANCELLED {
            return Err(PrivHelperError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(PrivHelperError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }

    Ok(info.hProcess)
}
