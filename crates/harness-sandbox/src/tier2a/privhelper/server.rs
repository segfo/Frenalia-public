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
    // D-48「走行中のセッションからは剥がさない」のガードは、**この昇格プロセスの中**から
    // 生存判定できることを前提にする。前提が成り立たないと判定は静かに0件へ倒れ、
    // fail-openの穴になる（`plans/HANDOFF-TRAVERSE-REVOKE-GUARD.md`）。
    // 毎回残しておけば、後から「あのとき何件見えていたか」を事後に確かめられる。
    log::line(&format!(
        "serve: session liveness probe: {}",
        crate::tier2a::session_profile::live_probe_report()
    ));
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
    // **応答を送る前に連鎖起動する**（BUG-093の修正）。
    //
    // 以前は応答を送り終えた後に起こし、失敗は`log::line`だけで握り潰していた。その結果、
    // 連鎖起動が落ちても呼び出し元には何も伝わらず、親は`ConnectNamedPipe`が30秒
    // タイムアウトするまで待ってから`NoWfp`でfail-closedしていた——実際にこの機で
    // 2026-08-08に起きている（`privhelper.log`に記録が残っていた）。
    // 結末を応答へ載せれば、親は待たずに自前の`runas`起動（シナリオB）へ移れる
    // （B-09: 多段の副作用は到達点を返す）。
    //
    // **順序を変えても競合は起きない**——起こされたnetfilterdが親の`ConnectNamedPipe`より
    // 先に接続してくる場合は`ERROR_PIPE_CONNECTED`として`win_pipe_ipc::run_overlapped`が
    // 既に成功扱いにしている（2026-07-25にこの経路で実際に踏んで対処済み）。
    //
    // ACL操作の成否に関わらず試みるのは従来どおり — WFP起動の可否とACL操作の成否は独立した
    // 関心事であり、ACL側が失敗したからといって呼び出し元が期待しているWFP起動まで
    // 巻き添えで諦める理由はない。
    let chain_result = chain_netfilterd_pipe.map(|chain_pipe| {
        log::line(&format!(
            "serve: chain-launching netfilterd, pipe={chain_pipe}"
        ));
        // **形の検証は受信側で行う**（P-01: 名前を運ぶのは非特権の親で、親は攻撃者と同じ権限で
        // 動きうる）。起こされたnetfilterdはこの名前を`CreateFileW`で開いて自分の応答を書くので、
        // 任意の名前を通すと「昇格プロセスが攻撃者の選んだ先へ書き込む」プリミティブになる。
        // D-60でnetfilterd側に同じ検証を入れたので、**対称に**こちらへも入れる（B-01）。
        if !crate::win_pipe_ipc::is_harness_pipe_name(&chain_pipe) {
            let reason = "rejected malformed pipe name (not a harness pipe)".to_string();
            log::line(&format!("serve: netfilterd chain-launch refused: {reason}"));
            return Err(reason);
        }
        match unsafe { launch_netfilterd_chained(&chain_pipe) } {
            Ok(()) => {
                log::line("serve: netfilterd chain-launch succeeded");
                Ok(())
            }
            Err(e) => {
                let reason = e.to_string();
                log::line(&format!("serve: netfilterd chain-launch failed: {reason}"));
                Err(reason)
            }
        }
    });
    let response = response.with_netfilterd_chain_result(chain_result);

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
    // T-21/D-44: **この経路はUACを出さない**（既に昇格したトークンをそのまま子へ継承させる）ので、
    // 差し替えられた実行ファイルはユーザーの目に触れずに管理者として走る。runas経路より危険なため、
    // ここでの検査は特に落とせない。
    crate::elevated_launch::verify_elevation_target(&netfilterd_path).map_err(|e| {
        PrivHelperError::Ipc(format!("refusing to chain-launch the WFP daemon: {e}"))
    })?;
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

/// `GrantWorkspaceAccess`のfs-allow部分の実処理。エントリごとに成否が独立する
/// （`GrantTraverse`のような連鎖ではないため、1エントリの失敗が他エントリを止めない）。
///
/// [§22.3.1] **主体はエントリごとに、この関数の中で導出する。** 呼び出し元から1つのSIDを
/// 受け取る形をやめたのは、`--fs-allow`の主体が**宣言ごと**になったからである。導出入力は
/// `(受け取った秘密, **この関数がこれから書き込む当のパス**, access級)`で、パスを
/// 呼び出し元の申告ではなく`entry.path`——実際の書込先——から取るのが要点である
/// （申告されたパスから導出して別のパスへ書くと、束縛が名目だけになる）。
fn grant_fs_allow_entries(entries: Vec<FsAllowGrant>) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut granted = Vec::new();
    let mut failures = Vec::new();
    for entry in entries {
        let started = std::time::Instant::now();
        // **秘密の無い電文は拒否する**（fail-closed）。移行前のビルドが送ってくる形で、
        // 通すと「主体を決められないまま何かへ付与する」ことになる。
        if entry.secret_hex.is_empty() {
            log::line(&format!(
                "  entry {} : REFUSED (no capability secret on the wire; the caller is from before \
                 the capability-SID migration)",
                entry.path.display()
            ));
            failures.push((
                entry.path,
                "no capability secret on the wire (caller predates the capability-SID migration)"
                    .to_string(),
            ));
            continue;
        }
        // **導出は必ずこの側で行う**（`privhelper`モジュールdocの「SIDはIPCで受け取らず、
        // 受信側が自ら導出する」を字義どおり保つ）。畳み込みも受信側の関数を通すので、
        // 呼び出し元が綴りを細工して別の主体を作らせることはできない。
        let name = crate::tier2a::workspace_capability::declaration_capability_name(
            &entry.secret_hex,
            &crate::tier2a::workspace_capability::declaration_key(&entry.path),
            entry.access.label(),
        );
        let sid_owned = match win_appcontainer::capability_sid_from_declaration_name(&name) {
            Ok(sid) => sid,
            Err(e) => {
                log::line(&format!(
                    "  entry {} : FAILED to derive the declaration capability: {e}",
                    entry.path.display()
                ));
                failures.push((entry.path, format!("could not derive the capability SID: {e}")));
                continue;
            }
        };
        let sid = sid_owned.as_psid();
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
        // [D-63] 昇格側も**宣言されたスコープ**で付ける。ここだけ継承ACE固定にすると、
        // システム保護パスへ回ったエントリだけ従来どおりサブツリー全体が開く（B-02）。
        let do_grant =
            || win_appcontainer::grant_ace_scoped(&entry.path, sid, entry.access, entry.scope);
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
                    if entry.access.is_read_write() {
                        "rw"
                    } else {
                        "ro"
                    },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                granted.push(entry.path);
            }
            Err(e) => {
                log::line(&format!(
                    "  entry {} [{}{}] : FAILED after {}ms: {e}",
                    entry.path.display(),
                    if entry.access.is_read_write() {
                        "rw"
                    } else {
                        "ro"
                    },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                failures.push((entry.path, e.to_string()));
            }
        }
    }
    (granted, failures)
}

/// `GrantWorkspaceAccess`用: 複数のtraverseターゲット（`--sandbox tier2a-cow`ならworkspace_root・diff_layer_dirの
/// 2つ）を独立に処理する。`GrantTraverse`（単一target）と異なり、1ターゲットのチェーンが
/// 途中で失敗しても他のターゲットの処理は続行する（workspace_rootとdiff_layer_dirは別の祖先
/// チェーンであり、片方の失敗がもう片方を無意味にするとは限らないため）。最初に発生した
/// エラーのみ`traverse_error`へ載せる（`target: reason`形式でどのターゲットの失敗か分かるようにする）。
/// いずれの場合も、実際にACEが付与された全ノードを`granted`へ積む（孤立ACE防止、`GrantChain`と
/// 同じ不変条件）。
fn grant_traverse_targets(sid: PSID, targets: Vec<PathBuf>) -> (Vec<PathBuf>, Option<String>) {
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
/// 自由形式のコマンド文字列は一切扱わない）。**SIDはIPCで受け取らず、必ずこのバイナリ側で
/// 自ら導出する**——ただしD-37以降、導出先は用途によって2系統ある。
///
/// | 用途 | 主体 | 導出元 |
/// |---|---|---|
/// | 祖先チェーンのtraverse（`GrantTraverse`/`RevokeTraverse`/`GrantWorkspaceAccess`のtraverse部分） | capability SID | `traverse_capability_sid()`（固定名`harnessSandboxTraverse`） |
/// | leafへの読み書きの**付与**（`GrantWorkspaceAccess`のfs-allow部分） | **宣言ごとのcapability SID**（§22.3） | IPCで受けた**秘密**＋**この側が畳み込んだ書込先のパス**＋access級（`grant_fs_allow_entries`） |
/// | leafへの読み書きの**撤収**（`RevokeFsAllow`） | **2系統を順に**——(1) **宣言ごとのcapability SID**（§22.2.1）、(2) 対象パスのDACLに実在するpackage SID | (1) IPCで受けた**秘密**＋**この側が畳み込んだ対象パス**＋access級、(2) `win_appcontainer::revoke_harness_subjects`（名前からは導出しない） |
///
/// **撤収が2系統あるのは、移行の途中に両方が実在し得るからである。** 新しい主体
/// （capability SID）は宣言から一意に導出でき、旧い主体（package SID）は導出できないので
/// DACLから分類するしかない——**探し方が違うので同じ関数にはならない**。どちらか片方でも
/// rootに残っていれば、このパスは「撤収できた」と応答しない。
///
/// traverse側が`CONTAINER_NAME`のpackage SIDのままD-37から取り残されていたのが
/// [BUG-061](../../../../docs/bugs/BUG-061.md)である。**新しいアームを足す人は、上表のどの行に
/// 属するかを決めてから主体を選ぶこと。**
///
/// [BUG-101] 撤収の行が「旧共有package SID固定」だったのをやめた。プロファイルが削除された
/// SIDは名前へ逆引きできないので、名前側から探す方式ではそもそも届かない。いまは対象パスの
/// DACLを読んで、そこに実在する主体だけを分類して剥がす。**この関数はもうpackage SIDを
/// 冒頭で導出しない**——用途ごとに主体が違うので、共有の`sid`変数を置くこと自体が
/// 「どの行のつもりか」を曖昧にしていた。
fn dispatch(req: PrivilegedRequest) -> PrivilegedResponse {
    match req {
        PrivilegedRequest::GrantTraverse { target } => {
            log::line(&format!(
                "dispatch: GrantTraverse target={}",
                target.display()
            ));
            // D-37/BUG-061: 祖先traverseの主体は**capability SID**であって、この関数の冒頭で
            // 導出したpackage SIDではない。`GrantWorkspaceAccess`（下）と同じ導出をここでも行う。
            let traverse_cap = match win_appcontainer::traverse_capability_sid() {
                Ok(cap) => cap,
                Err(e) => {
                    log::line(&format!("dispatch: traverse_capability_sid failed: {e}"));
                    return PrivilegedResponse::Err(format!(
                        "failed to derive the traverse capability SID: {e}"
                    ));
                }
            };
            let (granted, result) = win_appcontainer::grant_traverse_chain_with_progress(
                &target,
                traverse_cap.as_psid(),
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
            // D-48/BUG-061: 撤収も主体はcapability SID。`revoke_traverse_grant`は主体を自ら
            // 導出し、撤収と撤収済み検証を一体で行う（台帳の除去は非昇格の呼び出し元が行う）。
            let result: Result<(), AppContainerError> =
                win_appcontainer::revoke_traverse_grant(&path);
            log::line(&format!(
                "dispatch: RevokeTraverse done, error={:?}",
                result.as_ref().err()
            ));
            match result {
                Ok(()) => PrivilegedResponse::Ok,
                Err(e) => PrivilegedResponse::Err(e.to_string()),
            }
        }
        PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
        } => {
            // [§22.3.1] **要求の中身を素直に書かない。** この要求は宣言capabilityの秘密を
            // 運ぶので、`{req:?}`や個々のフィールドを並べると`privhelper.log`へ秘密が落ちる
            // （このログはユーザーのプロファイル配下に平文で残り続ける）。ここで出すのは
            // **件数だけ**にする。
            log::line(&format!(
                "dispatch: GrantWorkspaceAccess {} traverse target(s), {} fs-allow entrie(s)",
                traverse_targets.len(),
                fs_allow_entries.len()
            ));
            // D-37: 祖先traverseはharness共通のcapability SID宛（固定名から自ら導出、IPC入力に
            // 依存しない）。fs-allowは§22.3.1により宣言ごとのcapability SID宛で、その主体は
            // `grant_fs_allow_entries`が受け取った秘密と書込先のパスから自ら導出する。
            let traverse_cap = match win_appcontainer::traverse_capability_sid() {
                Ok(cap) => cap,
                Err(e) => {
                    log::line(&format!("dispatch: traverse_capability_sid failed: {e}"));
                    return PrivilegedResponse::Err(format!(
                        "failed to derive the traverse capability SID: {e}"
                    ));
                }
            };
            let (traverse_granted, traverse_error) =
                grant_traverse_targets(traverse_cap.as_psid(), traverse_targets);

            // [§22.3.1] **fs-allowの主体はもうセッションプロファイル名から導出しない。**
            // 宣言ごとのcapability SIDへ移したので、名前を受け取って検証する段はここには無く、
            // 導出はエントリごとに`grant_fs_allow_entries`の中で行う（同関数のdoc）。
            let (fs_allow_granted, fs_allow_failures) = grant_fs_allow_entries(fs_allow_entries);
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
                // 連鎖起動は`dispatch`の外（`serve`）で行う。結末は
                // `with_netfilterd_chain_result`が応答を送る直前に埋める。
                netfilterd_chain: None,
            }
        }
        PrivilegedRequest::RevokeFsAllow { entries } => {
            log::line(&format!(
                "dispatch: RevokeFsAllow {} path(s)",
                entries.len()
            ));
            let mut revoked = Vec::new();
            let root_cleared = Vec::new();
            let mut failures = Vec::new();
            for entry in entries {
                let path = entry.path;
                let started = std::time::Instant::now();
                // [§22.2.1] **宣言capabilityは、受け取った秘密からこの側で導出して名指しで剥がす。**
                // 付与（`grant_fs_allow_entries`）とまったく同じ導出を通す——ここだけ別の決め方に
                // すると、同じ宣言なのに付与と撤収で違う主体を見ることになる（B-02）。
                //
                // **空は拒否しない。** 付与側は秘密の無い電文をfail-closedで拒むが、撤収で
                // 止めると剥がせないACEが実マシンに残る。剥がせた／見ていないの区別は、
                // 非昇格側が自分の台帳で実DACLを検算して付ける。
                let declaration_subjects: Vec<crate::win_common::OwnedSid> = entry
                    .subjects
                    .iter()
                    .filter(|s| !s.secret_hex.is_empty())
                    .filter_map(|s| {
                        let name = crate::tier2a::workspace_capability::declaration_capability_name(
                            &s.secret_hex,
                            &crate::tier2a::workspace_capability::declaration_key(&path),
                            s.access.label(),
                        );
                        match win_appcontainer::capability_sid_from_declaration_name(&name) {
                            Ok(sid) => Some(sid),
                            Err(e) => {
                                log::line(&format!(
                                    "  path {} : could not derive a declaration capability: {e}",
                                    path.display()
                                ));
                                None
                            }
                        }
                    })
                    .collect();
                // [BUG-101] package SID側の撤収する主体は**このパスのDACLに実在するharness由来の
                // SID**で決める（旧実装は`ensure_profile(CONTAINER_NAME)`＝旧共有プロファイル固定だった）。
                //
                // **昇格側では台帳の記録（規則3）と未登録SIDの指紋（規則4）は使わない。**
                // `runas`の昇格先が別の管理者アカウントだと`HKCU`が別ハイブになり、分類の
                // 前提（この機の登録簿を見ている）が崩れる。分類できないものは剥がさず、
                // 非昇格側が名指しで報告する（fail-closed）。
                let do_revoke = || {
                    // 宣言capabilityを先に剥がす。どちらの順でも最終状態は同じだが、
                    // 失敗したときに「新しい主体は落ちたのに旧い主体が残った」より
                    // 「旧い主体は落ちたが新しい主体が残った」の方が、次の起動の検算
                    // （§22.3.0の不変条件＝package SID宛が0本）で見つかる側に倒れる。
                    let decl = win_appcontainer::revoke_capability_subjects(
                        &path,
                        &declaration_subjects,
                        &|_, _| {},
                    );
                    let subjects = win_appcontainer::revoke_harness_subjects(&path, &[], &|_, _| {});
                    (decl, subjects)
                };
                let (decl_outcome, outcome) = if entry.forced {
                    // forcedなパス（--force-system-aclで付与したACE）は撤収時も
                    // `SeRestorePrivilege`が要る。
                    win_appcontainer::with_restore_privilege(do_revoke)
                } else {
                    do_revoke()
                };
                // 宣言側の結末は**件数だけ**ログへ出す（秘密を持つ要求なので中身を書かない）。
                match &decl_outcome {
                    Ok(report) => log::line(&format!(
                        "  path {} : declaration capabilities: {} targeted, {} node(s) rewritten, \
                         {} still on the root",
                        path.display(),
                        report.targeted.len(),
                        report.rewritten,
                        report.still_on_root.len()
                    )),
                    Err(e) => log::line(&format!(
                        "  path {} : declaration capability revoke FAILED: {e}",
                        path.display()
                    )),
                }
                // **宣言側が終わっていなければ、このパスは「撤収できた」ではない。**
                // package側だけを見て`revoked`へ積むと、非昇格側は「ヘルパーが片付けた」と
                // 読み、capability宛ACEが残ったまま台帳の記録を捨てにいく（B-09）。
                let decl_left: Vec<String> = match &decl_outcome {
                    Ok(report) => report.still_on_root.clone(),
                    Err(e) => vec![format!("declaration capability revoke failed: {e}")],
                };
                match outcome {
                    Ok(report) if report.unfinished().is_empty() && decl_left.is_empty() => {
                        log::line(&format!(
                            "  path {} : revoked {} subject(s), {} node(s) rewritten in {}ms",
                            path.display(),
                            report.targeted(),
                            report.rewritten(),
                            started.elapsed().as_millis()
                        ));
                        revoked.push(path);
                    }
                    Ok(report) => {
                        let left: Vec<String> = report
                            .unfinished()
                            .iter()
                            .map(|s| s.to_string())
                            .chain(decl_left)
                            .collect();
                        log::line(&format!(
                            "  path {} : FAILED after {}ms (still on the root: {})",
                            path.display(),
                            started.elapsed().as_millis(),
                            left.join(", ")
                        ));
                        failures.push((
                            path,
                            format!(
                                "still on the root after an elevated revoke: {}",
                                left.join(", ")
                            ),
                        ));
                    }
                    Err(e) => {
                        log::line(&format!(
                            "  path {} : FAILED after {}ms ({e})",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        failures.push((path, e.to_string()));
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
