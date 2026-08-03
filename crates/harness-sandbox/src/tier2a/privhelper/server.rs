//! **管理者権限側**（`harness-privhelper.exe`として昇格起動されたプロセス）のサーバ実装。
//!
//! `serve`がパイプで1要求を受け取り、`dispatch`が固定スキーマの`PrivilegedRequest`を
//! 実際の特権操作（ACE付与・traverse付与・netfilterd連鎖起動）へ写す。自由形式の
//! コマンド文字列は一切受け付けない（D-16）。
//!
//! このファイルのコードは**昇格したトークンで動く**。信頼境界をファイル境界に一致させて
//! いるため、レビュー時はここだけを見れば「管理者権限で何が実行されうるか」が尽きる
//! （非特権側の呼び出しコードは`client`）。
//!
//! 呼び出し元の認可は、パイプのDACLを呼び出しユーザー専有にすること
//! （`crate::win_pipe_ipc::user_only_security_attributes`）で成立させる。

use super::*;


/// ヘルパー側のファイルログ（`%APPDATA%\harness\config\privhelper.log`、台帳と同じ`config_dir`）。
/// ヘルパーは`runas`+`SW_HIDE`（[`launch_helper_elevated`]参照）で起動されるため
/// `eprintln!`の出力先が無く、UAC/IPCが無応答になった際に「どのノードで何秒かかって
/// いたか」を事後に一切確認できない（前回セッションでUAC不表示/`ERROR_BROKEN_PIPE`が
/// 起きた際、原因の切り分けができなかった実体験に基づく）。台帳ファイル
/// （`fs-passthrough-ledger.json`/`traverse-grant-ledger.json`）には一切触れず、完全に
/// 別ファイルへ追記のみ行う（`CLAUDE.md`の台帳誤削除防止ルールと同じ理由で、既存台帳の
/// 読み書きコードパスとは独立させる）。
mod log {
    use std::io::Write;

    fn log_path() -> Option<std::path::PathBuf> {
        directories::ProjectDirs::from("", "", "harness")
            .map(|d| d.config_dir().join("privhelper.log"))
    }

    /// ログ書込み自体の失敗はヘルパーの処理を止めない（診断用の副次経路であり、ログ書込み
    /// 失敗が特権操作そのものの失敗理由になってはならない）。
    pub fn line(msg: &str) {
        let Some(path) = log_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "[{now_ms}] pid={} {msg}", std::process::id());
        }
    }
}

/// ヘルパー側エントリポイント（`harness-privhelper.exe`のmainから呼ぶ、昇格トークンで実行される）。
/// 親が開いたパイプへclientとして接続し、1件の要求を処理して応答を返し終了する
/// （1起動=1操作、常駐しない）。
pub fn serve(pipe_name: &str) -> Result<(), PrivHelperError> {
    log::line(&format!("serve: starting, pipe={pipe_name}"));
    // FILE_FLAG_OVERLAPPED: 親と同じくオーバーラップドI/Oで受信・送信を有限時間化する
    // （§1c、親が既に諦めて`CloseHandle`した後もこちら側が無期限に`ReadFile`し続けて
    // stale化する事故を防ぐ、常駐しない原則の徹底）。
    let pipe = unsafe {
        let pipe_name_w = wide(pipe_name);
        CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
    };
    let pipe = match pipe {
        Ok(h) => {
            log::line("serve: connected to parent pipe");
            h
        }
        Err(e) => {
            log::line(&format!("serve: CreateFileW failed: {e}"));
            return Err(PrivHelperError::from(e));
        }
    };

    let request_bytes = match read_framed_timeout(pipe, REQUEST_WRITE_TIMEOUT) {
        Ok(b) => {
            log::line(&format!("serve: received request ({} bytes)", b.len()));
            b
        }
        Err(e) => {
            log::line(&format!("serve: read request failed/timed out: {e}"));
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e.into());
        }
    };
    let (response, chain_netfilterd_pipe) =
        match serde_json::from_slice::<PrivilegedRequestEnvelope>(&request_bytes) {
            Ok(envelope) => (dispatch(envelope.request), envelope.chain_netfilterd_pipe),
            Err(e) => {
                log::line(&format!("serve: malformed request: {e}"));
                (
                    PrivilegedResponse::Err(format!(
                        "malformed or unknown request (schema mismatch): {e}"
                    )),
                    None,
                )
            }
        };
    let response_bytes = serde_json::to_vec(&response)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize response: {e}")))?;
    log::line("serve: writing response");
    let write_result = write_framed_timeout(pipe, &response_bytes, RESPONSE_READ_TIMEOUT);
    match &write_result {
        Ok(()) => log::line("serve: response written, exiting"),
        Err(e) => log::line(&format!("serve: write response failed/timed out: {e}")),
    }
    unsafe {
        let _ = CloseHandle(pipe);
    }

    // 応答を送り終えた**後**にのみ連鎖起動する（モジュールdoc「例外: WFP連鎖起動」参照）。
    // ACL操作の成否に関わらず試みる — WFP起動の可否とACL操作の成否は独立した関心事であり、
    // ACL側が失敗したからといって呼び出し元が期待しているWFP起動まで巻き添えで諦める理由はない。
    if let Some(chain_pipe) = chain_netfilterd_pipe {
        log::line(&format!(
            "serve: chain-launching netfilterd, pipe={chain_pipe}"
        ));
        match unsafe { launch_netfilterd_chained(&chain_pipe) } {
            Ok(()) => log::line("serve: netfilterd chain-launch succeeded"),
            Err(e) => log::line(&format!("serve: netfilterd chain-launch failed: {e}")),
        }
    }

    write_result.map_err(Into::into)
}

/// ヘルパー実行ファイルと同じディレクトリから`harness-netfilterd.exe`を解決する
/// （[`helper_exe_path`]と同じロジック、対象exe名だけが異なる）。
fn netfilterd_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| PrivHelperError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-netfilterd.exe"))
}

/// 昇格済みトークンのまま`harness-netfilterd.exe`を子として起動する（`ShellExecuteExW`の
/// `runas`は使わない——既に管理者トークンを持つプロセスからの通常の`CreateProcessW`は、
/// そのトークンをそのまま子へ継承させるため、2回目のUACダイアログは出ない）。起動した
/// プロセスのハンドルは待たない（netfilterdはharnessセッション全体の生存期間中、独立して
/// 常駐し続けるデーモンであり、ヘルパー自身はこの直後に終了する）。
unsafe fn launch_netfilterd_chained(pipe_name: &str) -> Result<(), PrivHelperError> {
    let netfilterd_path = netfilterd_exe_path()?;
    // コマンドラインの第0引数（実行ファイルパス）はCreateProcessWの規約上quoteが要る。
    let cmdline = format!("\"{}\" {}", netfilterd_path.display(), pipe_name);
    let mut cmdline_w = wide(&cmdline);

    let startup_info = windows::Win32::System::Threading::STARTUPINFOW {
        cb: std::mem::size_of::<windows::Win32::System::Threading::STARTUPINFOW>() as u32,
        dwFlags: windows::Win32::System::Threading::STARTF_USESHOWWINDOW,
        wShowWindow: SW_HIDE.0 as u16,
        ..Default::default()
    };
    let mut process_info = windows::Win32::System::Threading::PROCESS_INFORMATION::default();

    windows::Win32::System::Threading::CreateProcessW(
        PCWSTR::null(),
        windows::core::PWSTR(cmdline_w.as_mut_ptr()),
        None,
        None,
        false,
        windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0),
        None,
        PCWSTR::null(),
        &startup_info as *const _,
        &mut process_info,
    )
    .map_err(PrivHelperError::from)?;

    let _ = CloseHandle(process_info.hProcess);
    let _ = CloseHandle(process_info.hThread);
    Ok(())
}

/// `GrantFsAllow`/`GrantWorkspaceAccess`共通の実処理。エントリごとに成否が独立する
/// （`GrantTraverse`のような連鎖ではないため、1エントリの失敗が他エントリを止めない）。
fn grant_fs_allow_entries(
    sid: PSID,
    entries: Vec<FsAllowGrant>,
) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut granted = Vec::new();
    let mut failures = Vec::new();
    for entry in entries {
        let started = std::time::Instant::now();
        // forced（--force-system-acl, D-19）は`SeRestorePrivilege`で全DACLをバイパスして
        // 書くため、書込前に必ず host パスの絶対拒否ゲートを通す（唯一の防壁）。
        if entry.forced {
            if let Some(reason) = win_appcontainer::is_force_grant_forbidden(&entry.path) {
                log::line(&format!(
                    "  entry {} : forced grant REFUSED by deny-gate: {reason}",
                    entry.path.display()
                ));
                failures.push((entry.path, reason));
                continue;
            }
        }
        let do_grant =
            || win_appcontainer::grant_ace_inheritable_access(&entry.path, sid, entry.access);
        // forcedのみ`SeRestorePrivilege`を有効化して実行する（TrustedInstaller所有ノードへも
        // 所有権を変えずにACEを書ける）。非forcedは従来どおり特権無しで実行する。
        let result = if entry.forced {
            win_appcontainer::with_restore_privilege(do_grant)
        } else {
            do_grant()
        };
        match result {
            Ok(()) => {
                log::line(&format!(
                    "  entry {} [{}{}] : granted in {}ms",
                    entry.path.display(),
                    if entry.access.is_read_write() { "rw" } else { "ro" },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                granted.push(entry.path);
            }
            Err(e) => {
                log::line(&format!(
                    "  entry {} [{}{}] : FAILED after {}ms: {e}",
                    entry.path.display(),
                    if entry.access.is_read_write() { "rw" } else { "ro" },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                failures.push((entry.path, e.to_string()));
            }
        }
    }
    (granted, failures)
}

/// `GrantWorkspaceAccess`用: 複数のtraverseターゲット（`--cow`ならworkspace_root・upper_dirの
/// 2つ）を独立に処理する。`GrantTraverse`（単一target）と異なり、1ターゲットのチェーンが
/// 途中で失敗しても他のターゲットの処理は続行する（workspace_rootとupper_dirは別の祖先
/// チェーンであり、片方の失敗がもう片方を無意味にするとは限らないため）。最初に発生した
/// エラーのみ`traverse_error`へ載せる（`target: reason`形式でどのターゲットの失敗か分かるようにする）。
/// いずれの場合も、実際にACEが付与された全ノードを`granted`へ積む（孤立ACE防止、`GrantChain`と
/// 同じ不変条件）。
fn grant_traverse_targets(
    sid: PSID,
    targets: Vec<PathBuf>,
) -> (Vec<PathBuf>, Option<String>) {
    let mut all_granted = Vec::new();
    let mut first_error: Option<String> = None;
    for target in targets {
        let (granted, result) = win_appcontainer::grant_traverse_chain_with_progress(
            &target,
            sid,
            |node, node_result, elapsed| match node_result {
                Ok(()) => log::line(&format!(
                    "  node {} : granted in {}ms",
                    node.display(),
                    elapsed.as_millis()
                )),
                Err(e) => log::line(&format!(
                    "  node {} : FAILED after {}ms: {e}",
                    node.display(),
                    elapsed.as_millis()
                )),
            },
        );
        all_granted.extend(granted);
        if let Err(e) = result {
            if first_error.is_none() {
                first_error = Some(format!("{}: {e}", target.display()));
            }
        }
    }
    (all_granted, first_error)
}

/// 固定スキーマの要求だけを実行する（D-16の核: ここに到達する時点でスキーマ検証済み、
/// 自由形式のコマンド文字列は一切扱わない）。SIDはIPCで受け取らず、安定定数
/// `CONTAINER_NAME`から`ensure_profile`で自ら導出する。
fn dispatch(req: PrivilegedRequest) -> PrivilegedResponse {
    let sid = match win_appcontainer::ensure_profile(CONTAINER_NAME) {
        Ok(sid) => sid,
        Err(e) => {
            log::line(&format!("dispatch: ensure_profile failed: {e}"));
            return PrivilegedResponse::Err(format!("failed to resolve sandbox SID: {e}"));
        }
    };
    match req {
        PrivilegedRequest::GrantTraverse { target } => {
            log::line(&format!(
                "dispatch: GrantTraverse target={}",
                target.display()
            ));
            let (granted, result) = win_appcontainer::grant_traverse_chain_with_progress(
                &target,
                sid.as_psid(),
                |node, node_result, elapsed| match node_result {
                    Ok(()) => log::line(&format!(
                        "  node {} : granted in {}ms",
                        node.display(),
                        elapsed.as_millis()
                    )),
                    Err(e) => log::line(&format!(
                        "  node {} : FAILED after {}ms: {e}",
                        node.display(),
                        elapsed.as_millis()
                    )),
                },
            );
            log::line(&format!(
                "dispatch: GrantTraverse done, {} node(s) granted, error={:?}",
                granted.len(),
                result.as_ref().err()
            ));
            PrivilegedResponse::GrantChain {
                granted,
                error: result.err().map(|e| e.to_string()),
            }
        }
        PrivilegedRequest::RevokeTraverse { path } => {
            log::line(&format!("dispatch: RevokeTraverse path={}", path.display()));
            let result: Result<(), AppContainerError> =
                win_appcontainer::revoke_ace(&path, sid.as_psid())
                    .and_then(|()| win_appcontainer::assert_no_sid_ace(&path, sid.as_psid()));
            log::line(&format!(
                "dispatch: RevokeTraverse done, error={:?}",
                result.as_ref().err()
            ));
            match result {
                Ok(()) => PrivilegedResponse::Ok,
                Err(e) => PrivilegedResponse::Err(e.to_string()),
            }
        }
        PrivilegedRequest::GrantFsAllow { entries } => {
            log::line(&format!(
                "dispatch: GrantFsAllow {} entrie(s)",
                entries.len()
            ));
            let (granted, failures) = grant_fs_allow_entries(sid.as_psid(), entries);
            log::line(&format!(
                "dispatch: GrantFsAllow done, {} granted, {} failed",
                granted.len(),
                failures.len()
            ));
            PrivilegedResponse::FsAllowResult { granted, failures }
        }
        PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
        } => {
            log::line(&format!(
                "dispatch: GrantWorkspaceAccess {} traverse target(s), {} fs-allow entrie(s)",
                traverse_targets.len(),
                fs_allow_entries.len()
            ));
            let (traverse_granted, traverse_error) =
                grant_traverse_targets(sid.as_psid(), traverse_targets);
            let (fs_allow_granted, fs_allow_failures) =
                grant_fs_allow_entries(sid.as_psid(), fs_allow_entries);
            log::line(&format!(
                "dispatch: GrantWorkspaceAccess done, {} traverse node(s) granted (error={:?}), \
                 {} fs-allow granted, {} fs-allow failed",
                traverse_granted.len(),
                traverse_error,
                fs_allow_granted.len(),
                fs_allow_failures.len()
            ));
            PrivilegedResponse::WorkspaceAccessResult {
                traverse_granted,
                traverse_error,
                fs_allow_granted,
                fs_allow_failures,
            }
        }
        PrivilegedRequest::RevokeFsAllow { entries } => {
            log::line(&format!(
                "dispatch: RevokeFsAllow {} path(s)",
                entries.len()
            ));
            let mut revoked = Vec::new();
            let mut root_cleared = Vec::new();
            let mut failures = Vec::new();
            for entry in entries {
                let path = entry.path;
                let started = std::time::Instant::now();
                // forcedなパス（--force-system-aclで付与したACE）は撤収時も`SeRestorePrivilege`が要る。
                let do_revoke = || win_appcontainer::revoke_passthrough(&path, sid.as_psid());
                let outcome = if entry.forced {
                    win_appcontainer::with_restore_privilege(do_revoke)
                } else {
                    do_revoke()
                };
                match outcome {
                    win_appcontainer::RevokeOutcome::FullyRevoked => {
                        log::line(&format!(
                            "  path {} : revoked in {}ms",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        revoked.push(path);
                    }
                    win_appcontainer::RevokeOutcome::RootClearedDescendantsBlocked => {
                        log::line(&format!(
                            "  path {} : root cleared (descendants blocked) in {}ms",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        root_cleared.push(path);
                    }
                    win_appcontainer::RevokeOutcome::Failed => {
                        log::line(&format!(
                            "  path {} : FAILED after {}ms (root ACE still present)",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        failures.push((
                            path,
                            "root ACE still present after revoke attempt".to_string(),
                        ));
                    }
                }
            }
            log::line(&format!(
                "dispatch: RevokeFsAllow done, {} revoked, {} root-cleared, {} failed",
                revoked.len(),
                root_cleared.len(),
                failures.len()
            ));
            PrivilegedResponse::RevokeFsAllowResult {
                revoked,
                root_cleared,
                failures,
            }
        }
    }
}
