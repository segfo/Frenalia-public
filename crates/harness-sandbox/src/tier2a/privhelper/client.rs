//! **非特権側**（harness本体プロセス）から特権分離ヘルパーを呼ぶクライアント。
//!
//! `runas`でヘルパーを昇格起動し（UACダイアログはここで出る）、名前付きパイプで
//! `PrivilegedRequestEnvelope`を1往復して結果を受け取る。このファイルのコードは
//! **管理者権限では動かない**——昇格側の実装は`server`が持つ。信頼境界をファイル境界に
//! 一致させ、「どのコードが昇格した権限で動くのか」をファイル単位で判別できるようにする
//! （`docs/CODE-STRUCTURE-RULES.md`規則3）。

use super::*;

/// ヘルパー実行ファイルの名前。**この綴りの正本**——起こす側（開発用の`dev-elevated-runner`の
/// ブローカー等）が同じ名前を持つ必要があるので、文字列を各所へ複製せずここを参照する（B-05）。
pub const HELPER_EXE_NAME: &str = "harness-privhelper.exe";

/// ヘルパー実行ファイル（`harness-privhelper.exe`）のパスを、本体exeと同じディレクトリから
/// 解決する（PATH検索に頼らない固定ロケーション、D-16の「小さく独立にビルド・監査可能な
/// 別バイナリ」を確実に本体と対で配布する前提）。
fn helper_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| PrivHelperError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join(HELPER_EXE_NAME))
}

/// 特権操作をヘルパーへ委譲し、完了まで待つ（client側、非管理者本体から呼ぶ）。
/// 1. 現在ユーザSID限定DACLでnamed pipe serverを作る。
/// 2. `runas`でヘルパーをパイプ名引数付きで昇格起動する（UACが表示される）。
/// 3. ヘルパーの接続を待ち、要求を送信し、応答を受け取る。
///
/// 返り値は「実際にACEが付与されたノードの一覧」（`GrantTraverse`のみ意味を持つ。
/// `RevokeTraverse`成功時は常に空`Vec`）。`Err(PrivHelperError::PartialGrantChain { granted, .. })`
/// の場合も`granted`に途中まで成功したノードが入るため、呼び出し側は`Err`だからと無視せず
/// 中身を確認して台帳へ反映する必要がある（孤立ACE防止）。fs-allowの付与はエントリごとに
/// 成否が独立するため、この関数ではなく[`run_privileged_workspace_access`]を使う。
pub fn run_privileged(req: &PrivilegedRequest) -> Result<Vec<PathBuf>, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(req.clone());
    match run_privileged_raw(&envelope, None)? {
        PrivilegedResponse::Ok => Ok(Vec::new()),
        PrivilegedResponse::GrantChain {
            granted,
            error: None,
        } => Ok(granted),
        PrivilegedResponse::GrantChain {
            granted,
            error: Some(reason),
        } => Err(PrivHelperError::PartialGrantChain { granted, reason }),
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a non-RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a non-GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeTraverseBatchResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeTraverseBatchResult response for a non-RevokeTraverseBatch request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeWorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeWorkspaceAccessResult response for a non-RevokeWorkspaceAccess \
             request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_revoke_fs_allow`の成功値（`revoked`完全撤収一覧、`root_cleared`
/// root撤収済み・子孫ブロック一覧、`(path, reason)`失敗一覧）。`revoked`と`root_cleared`は
/// どちらも台帳から除去してよい（`root_cleared`は孤立ACEにならない、`RevokeOutcome`参照）。
pub type FsAllowRevokeOutcome = (Vec<PathBuf>, Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `run_privileged_workspace_access`の成功値（traverse付与ノード一覧・traverse失敗理由・
/// fs-allow付与一覧・fs-allow失敗一覧・WFP連鎖起動の結末）。
///
/// 最後の要素は`None`＝依頼していない／`Some(Ok(()))`＝起きた／`Some(Err(reason))`＝
/// 起こせなかった。**呼び出し側はこれを見てシナリオA/Bを決める**（BUG-093）。
pub type WorkspaceAccessOutcome = (
    Vec<PathBuf>,
    Option<String>,
    Vec<PathBuf>,
    Vec<(PathBuf, String)>,
    Option<Result<(), String>>,
);

/// `GrantWorkspaceAccess`専用の委譲関数。**非管理者からのTier2a起動が特権を要するときは、
/// traverse付与・fs-allow昇格・WFP連鎖起動のいずれであっても必ずここを通る**
/// （`win_appcontainer::preflight`はtraverse不足の有無で分岐しない）。`chain_pipe`が`Some`なら、
/// ヘルパーはACL操作の応答を送った後に`harness-netfilterd`を追加起動する
/// （モジュールdoc「例外: WFP連鎖起動」参照）。
/// **新しい特権操作を追加する際の注意点**: 同一起動内で2回目の
/// `run_privileged*`（＝2回目のUAC）を独立に呼び出してはならない。この関数のように、
/// 1回の起動で必要になり得る特権操作をすべて1つの`PrivilegedRequestEnvelope`へ束ねること
/// （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16参照）。
pub fn run_privileged_workspace_access(
    traverse_targets: Vec<PathBuf>,
    fs_allow_entries: Vec<FsAllowGrant>,
    chain_pipe: Option<String>,
    // `chain_launcher`（D-60）: 常駐している昇格プロセスからヘルパーを起こす手段。
    // `None`なら自前で`runas`する（UACが1回）。
    chain_launcher: Option<ChainLauncher<'_>>,
) -> Result<WorkspaceAccessOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope {
        request: PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
        },
        chain_netfilterd_pipe: chain_pipe,
    };
    match run_privileged_raw(&envelope, chain_launcher)? {
        PrivilegedResponse::WorkspaceAccessResult {
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
            netfilterd_chain,
        } => Ok((
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
            netfilterd_chain,
        )),
        // 以下2つは旧ヘルパー（この応答variantを知らない版）との互換経路。連鎖起動の結末を
        // 名乗れないので`None`＝「依頼していない」と同じ扱いにする。**呼び出し側はシナリオB
        // （自前の`runas`）へ落ちる**——起きたと誤解して待つより、UACが1回増える方が良い（P-03）。
        PrivilegedResponse::Ok => Ok((Vec::new(), None, Vec::new(), Vec::new(), None)),
        PrivilegedResponse::GrantChain { granted, error } => {
            Ok((granted, error, Vec::new(), Vec::new(), None))
        }
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeTraverseBatchResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeTraverseBatchResult response for a GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeWorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeWorkspaceAccessResult response for a GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `RevokeFsAllow`専用の委譲関数（付与側＝`run_privileged_workspace_access`の裏対称、
/// `BUG-015`参照）。`entries`は`harness fs revoke`/`revoke-all`が本体プロセス内で
/// 撤収しきれなかったパス（`forced`情報付き）の一覧。
pub fn run_privileged_revoke_fs_allow(
    entries: Vec<FsAllowRevoke>,
) -> Result<FsAllowRevokeOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeFsAllow { entries });
    match run_privileged_raw(&envelope, None)? {
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
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::RevokeTraverseBatchResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeTraverseBatchResult response for a RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::RevokeWorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeWorkspaceAccessResult response for a RevokeFsAllow request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_revoke_traverse_batch`の成功値（撤収できたパス一覧、`(path, reason)`失敗一覧）。
///
/// **台帳から落としてよいのは第1要素だけ**（[`PrivilegedResponse::RevokeTraverseBatchResult`]）。
pub type TraverseRevokeBatchOutcome = (Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `RevokeTraverseBatch`専用の委譲関数——**`harness fs revoke-traverse-all`のUACを1回にする**。
///
/// 付与側（`GrantWorkspaceAccess`の`traverse_targets`）の裏対称である。これが無かった頃、
/// `revoke-traverse-all`は単発の`RevokeTraverse`を台帳の件数だけ呼んでおり、
/// **1エントリにつき1回UACが出た**（`B-02`）。
///
/// 昇格済みで走っているなら**この関数を通さないこと**——呼び出し側が
/// `fs_revoke_traverse_one_direct`を直接ループすればUACは0回で済む。
pub fn run_privileged_revoke_traverse_batch(
    paths: Vec<PathBuf>,
) -> Result<TraverseRevokeBatchOutcome, PrivHelperError> {
    let envelope =
        PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeTraverseBatch { paths });
    match run_privileged_raw(&envelope, None)? {
        PrivilegedResponse::RevokeTraverseBatchResult { revoked, failures } => {
            Ok((revoked, failures))
        }
        // 旧ヘルパー（この要求を知らない版）は要求そのものを拒むので`Err`で返る。
        // ここへ来る`Ok`は「何もしていない」を意味するので、**空の成功にしない**
        // ——空を返すと呼び出し側は「0件撤収できた」と読み、台帳を1件も落とさないまま
        // 成功を報告する（`B-09`: 失敗を成功に見せない）。
        PrivilegedResponse::Ok => Err(PrivHelperError::Ipc(
            "helper answered RevokeTraverseBatch with a bare Ok (no per-path outcome); \
             it is probably an older build that does not know this request"
                .to_string(),
        )),
        PrivilegedResponse::GrantChain { .. } => Err(PrivHelperError::Ipc(
            "unexpected GrantChain response for a RevokeTraverseBatch request".to_string(),
        )),
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a RevokeTraverseBatch request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a RevokeTraverseBatch request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeWorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeWorkspaceAccessResult response for a RevokeTraverseBatch request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_revoke_workspace_access`の成功値（撤収できたworkspace一覧、
/// `(workspace, reason)`失敗一覧）。
///
/// **どちらの一覧も、それ自体では台帳を落とす根拠にならない**
/// （[`PrivilegedResponse::RevokeWorkspaceAccessResult`]）。呼び出し側はrootのDACLを
/// 読み直してから記録を捨てる。
pub type WorkspaceRevokeBatchOutcome = (Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `RevokeWorkspaceAccess`専用の委譲関数——**`harness fs revoke-workspace(-all)`の
/// 昇格経路そのもの**。
///
/// 付与側（[`run_privileged_workspace_access`]）の裏対称である。これが無かった頃、
/// workspace撤収には昇格へ委譲する分岐が**1つも無く**、`BUILTIN\Administrators`所有の
/// ノードでDACLを書けずに終わっていた（[`PrivilegedRequest::RevokeWorkspaceAccess`]のdoc）。
///
/// **昇格済みで走っているならこの関数を通さないこと**——呼び出し側が本体プロセス内で
/// walkすれば、それが既に「管理者としての実行」であり、UACは0回で済む
/// （`run_privileged_revoke_traverse_batch`と同じ規律）。
pub fn run_privileged_revoke_workspace_access(
    entries: Vec<WorkspaceRevoke>,
) -> Result<WorkspaceRevokeBatchOutcome, PrivHelperError> {
    let envelope =
        PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeWorkspaceAccess { entries });
    match run_privileged_raw(&envelope, None)? {
        PrivilegedResponse::RevokeWorkspaceAccessResult { revoked, failures } => {
            Ok((revoked, failures))
        }
        // 旧ヘルパー（この要求を知らない版）は要求そのものを拒むので`Err`で返る。
        // ここへ来る`Ok`は「何もしていない」を意味するので、**空の成功にしない**
        // ——空を返すと呼び出し側は「0件撤収できた」と読む（`B-09`: 失敗を成功に見せない）。
        PrivilegedResponse::Ok => Err(PrivHelperError::Ipc(
            "helper answered RevokeWorkspaceAccess with a bare Ok (no per-workspace outcome); \
             it is probably an older build that does not know this request"
                .to_string(),
        )),
        PrivilegedResponse::GrantChain { .. } => Err(PrivHelperError::Ipc(
            "unexpected GrantChain response for a RevokeWorkspaceAccess request".to_string(),
        )),
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a RevokeWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::RevokeTraverseBatchResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeTraverseBatchResult response for a RevokeWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a RevokeWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// **ヘルパーを起こす代わりの手段**（D-60）。パイプ名を受け取り、`Ok(())`なら
/// 「そのパイプへ接続してくるヘルパーが起きた」ことを意味する。
///
/// 実体は「常駐している`harness-netfilterd`へ連鎖起動を依頼する」クロージャで、
/// **UACが出ない**。`Err(reason)`なら起こせなかったので、呼び出し側は自前の`runas`へ落ちる。
///
/// 型を`&dyn Fn`で受けるのは、`harness-sandbox`の下位モジュールである`privhelper`が
/// `netfilterd`へ依存しないようにするため（依存の向きを一方通行に保つ）。
///
/// **定義本体は`crate::tier2a`（OS非依存の位置）にある。** ここは従来の綴り
/// `privhelper::ChainLauncher`で到達できるようにするための再輸出である——本体をこの
/// Windows専用モジュールに置いていたため、`shell_tier::select_tier`のシグネチャが
/// 非Windowsで解決できず、クレート全体がビルドできなかった。
pub use crate::tier2a::ChainLauncher;

fn run_privileged_raw(
    envelope: &PrivilegedRequestEnvelope,
    chain_launcher: Option<ChainLauncher<'_>>,
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
    // D-60: 常駐している昇格プロセスから起こせるなら、そちらを使う（**UACが出ない**）。
    // 起こせなかったら`runas`へ落ちる——「起こせなかった」を黙って成功にしないこと（B-09）。
    // 連鎖起動で起きた場合、**プロセスハンドルは持たない**（起動者がこちらではないため。
    // netfilterdのシナリオAと同じ扱いで、撤収はヘルパー自身の終了とパイプ切断に委ねる）。
    let chained = match chain_launcher {
        Some(launch) => match launch(&pipe_name) {
            Ok(()) => true,
            Err(reason) => {
                eprintln!(
                    "warning: could not chain-launch the privilege-separation helper from the \
                     resident elevated daemon ({reason}); falling back to runas (one UAC prompt)"
                );
                false
            }
        },
        None => false,
    };

    let helper_process = if chained {
        HANDLE::default()
    } else {
        match unsafe { launch_helper_elevated(&helper_path, &pipe_name) } {
            Ok(h) => h,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(e);
            }
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
    // T-21/D-44: 昇格する前に、その実行ファイルと置き場が非管理者から書けないことを確かめる。
    // ここを検査しないと、`target\debug\harness-privhelper.exe`を書ける中IL のコードが
    // 次のUACで管理者実行を取れる（ローカル特権昇格）。既定は拒否、開発機は
    // `HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS=1`で警告付き続行。
    crate::elevated_launch::verify_elevation_target(helper_path).map_err(|e| {
        PrivHelperError::Win32(format!(
            "refusing to elevate the privilege-separation helper: {e}"
        ))
    })?;

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
