//! ファイル系NTフック本体（`NtCreateFile`・`NtOpenFile`・`NtSetInformationFile`・
//! `NtClose`・`NtQuery*AttributesFile`）。
//!
//! **ここは境界ではない**（D-01）。境界はACLであり、このフック群は`--sandbox tier2a-cow`の透過性
//! （workspaceがRO化されていてもツールがそのまま書けるように見せる）のためだけに存在する。
//! フックが素通りしてもACLがfail-closeするので、失われるのは透過性だけである。
//!
//! # 2つのモードがある（[D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md`）]）
//!
//! | モード | `cow_enabled` | openの前に何をするか |
//! |---|---|---|
//! | CoW（`--sandbox tier2a-cow`） | 真 | 分類して、書込は差分層へ誘導する |
//! | DirectRw + lazy fault-in | 偽 | **何もしない。** 本来のopenを先に呼ぶ |
//!
//! **後者で分類を前に置いてはいけない。** `plans/mac-spike/RESULTS.md` §S25が実測した
//! とおり、差分層の有無を見に行く分類は1 openあたり+28.3 µs（後ろに置けば+1.4 µs）で、
//! §S21の回数（14.5万〜21.9万回）を掛けると**毎セッション4〜6秒**になる。消せるのは
//! 初回の待ち（26万ノードで22.5秒）**だけ**なので、数セッションで元本を割る。
//!
//! fault-inの引き金は`NtCreateFile`・`NtOpenFile`・`NtQuery*AttributesFile`の**3つ**。
//! `NtSetInformationFile`（rename/delete）と`NtClose`を引き金にしないのは、どちらも
//! 「**既に開けたhandle**に対する操作」であって、開く前に割り込む余地が無いからである。

use super::*;

/// 拒否された1回のopenを、受付へ問い合わせて**1回だけ**やり直す。
///
/// # 「1回だけ」を型ではなくこの関数の形で固定している
///
/// `retry`は引数として渡された「もう一度呼ぶ手順」を**高々1回**しか呼ばない。再試行が
/// 再び拒否されても、ここから再帰しない——設計書§5.1.3が
/// 「1 openにつきbroker要求最大1回・元open再試行最大1回」を求めているのがこの形である。
///
/// 呼び出し側は**本来のopenを済ませてから**ここへ来ること（成功経路で呼ばない）。
fn retry_once_after_fault_in<F>(
    cfg: &Config,
    oa: *const OBJECT_ATTRIBUTES,
    retry: F,
) -> Option<NTSTATUS>
where
    F: FnOnce() -> NTSTATUS,
{
    cfg.broker_pipe.as_ref()?;
    // **ここで初めてパスを組む。** 成功経路には1バイトも載らない（§S25）。
    let path = unsafe { object_attributes_path(oa) }?;
    // **明らかにworkspace外なら往復しない。**
    //
    // PowerShellは起動の途中でSystem32やプロファイル配下を大量に開き、拒否されたものが
    // ここへ来る（受入E2Eの実測で**1回の起動あたり92件**）。どれも受付が`Denied`を返すだけの
    // 往復で、受付の行列と要求数の上限を無駄に食う。
    //
    // **これは最適化であって判定ではない。** 受付は届いた要求を必ず自分で検証し直す
    // （`broker`のモジュールdoc「子の言うことを信じない」）ので、ここが緩くても厳しくても
    // 権限は変わらない——**この枝が誤って弾いても、増えるのは1件の拒否であって権限ではない**。
    // 判定が要る側ではないので、綴りの一致だけを見る粗い比較で足りる。
    //
    // 置き場所は**拒否された後**なので、§S25が禁じている「成功経路での分類」には当たらない。
    if !is_inside(&path, &cfg.workspace_root) {
        return None;
    }
    match request_fault_in(cfg, &path) {
        // **`match`を`..`無しで全分岐書く。** 応答の種類が増えたときに、ここが
        // コンパイルエラーになって「やり直すのか諦めるのか」を必ず決めさせる（`B-06`）。
        FaultOutcome::Retry | FaultOutcome::RetryAnyway => Some(retry()),
        FaultOutcome::GiveUp => None,
    }
}

/// `path`が`root`配下（`root`自身を含む）か。**成分単位で、大文字小文字を無視して**比べる。
///
/// 文字列の`starts_with`だと`C:\ws`が`C:\ws-backup`に誤マッチする。ここは往復を省くための
/// 粗い篩なので**誤って通す側は無害**（受付が断る）だが、**誤って弾く側は fault-in が
/// 効かなくなる**ので、そちらへ倒れない書き方を選ぶ。
fn is_inside(path: &Path, root: &Path) -> bool {
    let comps = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let path = comps(path);
    let root = comps(root);
    // rootが空（設定が壊れている）なら篩をかけない——**弾く側へ倒さない**。
    root.is_empty() || (root.len() <= path.len() && root.iter().zip(&path).all(|(a, b)| a == b))
}

pub(crate) unsafe extern "system" fn hooked_nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: FILE_ACCESS_RIGHTS,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *const i64,
    file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
    share_access: FILE_SHARE_MODE,
    create_disposition: NTCREATEFILE_CREATE_DISPOSITION,
    create_options: NTCREATEFILE_CREATE_OPTIONS,
    ea_buffer: *const c_void,
    ea_length: u32,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] DirectRwのlazyレーン: **本来のopenを先に呼び、拒否されてから初めて分類する。**
        // 分類を前に置くと1 openあたり+28.3 µs（§S25、モジュールdoc）。
        if let Some(cfg) = CONFIG.get().filter(|cfg| !cfg.cow_enabled) {
            let hook = CREATE_FILE_HOOK.get().expect("hook installed");
            let call = || unsafe {
                hook.call(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    allocation_size,
                    file_attributes,
                    share_access,
                    create_disposition,
                    create_options,
                    ea_buffer,
                    ea_length,
                )
            };
            let status = call();
            if status != STATUS_ACCESS_DENIED {
                return status;
            }
            return retry_once_after_fault_in(cfg, object_attributes, call).unwrap_or(status);
        }
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                let rel_lower = rel_str.to_ascii_lowercase();
                let is_probe = rel_lower.contains("test.txt") || rel_lower.contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_create_file: rel={rel_str:?} kind={kind:?} desired_access={:#x} \
                         disposition={:#x} options={:#x} is_dir={} write_intent={} diff_layer_exists={}",
                        desired_access.0,
                        create_disposition.0,
                        create_options.0,
                        create_options.0 & 0x0000_0001 != 0, // FILE_DIRECTORY_FILE
                        is_write_intent(desired_access.0, Some(create_disposition.0)),
                        cfg.diff_layer_dir.join(&rel).is_file(),
                    ));
                }
                // BUG-066: 差分層配下の実体を直接開いている＝**既にCoWの行き先**。誘導は
                // 一切せず（差分層の差分層は作らない）、書込意図のときだけ台帳へ記録して
                // 素通しする。tombstone判定（`check_deleted`）も掛けない——あれは
                // 「workspaceをどう見せるか」の論理であって、行き先の実体への直接アクセスに
                // 被せると、削除済みパスの差分層実体を消すことすらできなくなる。
                if kind == TargetKind::DiffLayerAlias {
                    // BUG-171: 台帳へ書くのは本当のopenが成功した後。
                    let record = should_redirect_write(
                        is_write_intent(desired_access.0, Some(create_disposition.0)),
                        create_options.0,
                        Some(create_disposition.0),
                    )
                    .then(|| plan_diff_layer_alias_write(cfg, &rel_str))
                    .flatten();
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            object_attributes,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                    };
                    finish_diff_layer_alias_write(cfg, record, status.is_ok());
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                if let Some(status) = check_deleted(
                    cfg,
                    &rel_str,
                    is_create_capable_disposition(create_disposition.0),
                ) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} check_deleted short-circuit status={status:?}"
                        ));
                    }
                    return status;
                }
                if should_redirect_write(
                    is_write_intent(desired_access.0, Some(create_disposition.0)),
                    create_options.0,
                    Some(create_disposition.0),
                ) {
                    let diff_layer_path = cfg.diff_layer_dir.join(&rel);
                    // BUG-171: 写すのはopenの前（写さないと既存ファイルを開けない）、
                    // 台帳へ書くのはopenが成功した後。
                    // BUG-172: このセッションで消したパスの作り直しなら、元の中身は写さない
                    // （`check_deleted`が作成できる開き方だけを通しているので、ここへ来るのはそれ）。
                    let source = if is_logically_deleted(&rel_str) {
                        CopySource::Nothing
                    } else {
                        CopySource::Workspace
                    };
                    let copied = copy_up(cfg, &rel_str, &path, &diff_layer_path, source);
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                    };
                    finish_copy_up(cfg, copied, status.is_ok());
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} branch=write-redirect \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // 読み取りread-through（設計書§19.3/§19.7「削除済み＞差分層＞workspace」の中間段）:
                // 書込意図が無い開き方（`Get-Content`等）でも、差分層に版があればそちらを読ませる。
                // これが無いと「書いた直後に読み返す」操作が実workspace側（実体が無いか古い）を見て
                // 失敗する（実機E2Eで発見、既存の`cow_diagnostics`はAppContainer外から
                // `std::fs::read_to_string`で確認するだけだったため見逃されていた）。
                if let Some(diff_layer_path) = diff_layer_version_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                    };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} branch=read-through \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // ディレクトリ read-through（BUG-128）: 差分層 にしか無いディレクトリを開くときは
                // 差分層 へ誘導する。無いと read-only の workspace 側を開こうとして ACCESS_DENIED／
                // OBJECT_NAME_NOT_FOUND になり、git の pathspec 解決・列挙が壊れる
                // （`diff_layer_only_dir_path` のdoc参照）。
                //
                // **`FILE_DIRECTORY_FILE` フラグでは絞らない**——git/Cygwin の `lstat` は、対象が
                // ファイルかディレクトリか未確定のまま `FILE_OPEN_FOR_BACKUP_INTENT`（フラグ無し）で
                // 開いて存在と種別を確かめる。フラグで絞ると、この lstat が 差分層 のみのディレクトリを
                // 「存在しない」と誤認し、`git add <path>` が対象を見つけられず何もステージしない
                // （実機ログで確認）。ファイルの read-through（`diff_layer_version_path`）は上で済んでいるので、
                // ここに来る時点で対象はファイルではない＝ディレクトリ判定と衝突しない。
                if let Some(diff_layer_path) = diff_layer_only_dir_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                    };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_create_file: rel={rel_str:?} branch=dir-read-through \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // 差分層にも版が無い（このセッションで一度も触っていない）場合は、これまで通り
                // ハンドル→パス対応表にだけ載せて実workspace側を読ませる（`FILE_DELETE_ON_CLOSE`
                // 無し・この時点では削除予定ではないが、NtClose側での取り除き漏れを防ぐため
                // 対応表自体には登録しておく）。
                let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
                    hook.call(
                        file_handle,
                        desired_access,
                        object_attributes,
                        io_status_block,
                        allocation_size,
                        file_attributes,
                        share_access,
                        create_disposition,
                        create_options,
                        ea_buffer,
                        ea_length,
                    )
                };
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_create_file: rel={rel_str:?} branch=passthrough-no-diff_layer \
                         status={status:?}"
                    ));
                }
                track_new_handle(file_handle, status, &rel_str, create_options.0);
                return status;
            } else if is_write_intent(desired_access.0, Some(create_disposition.0)) {
                // Phase 4（設計書§19.8）: workspace内でもext capture root配下でもない絶対パスへの
                // 書込意図。素通しさせ、実際にACLで拒否された（`STATUS_ACCESS_DENIED`）場合のみ
                // 監査台帳へ記録する（境界自体はACLが既に保証しているので、ここでは何も遮断/
                // 誘導しない——フックは境界にしない、D-01）。
                let hook = CREATE_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
                    hook.call(
                        file_handle,
                        desired_access,
                        object_attributes,
                        io_status_block,
                        allocation_size,
                        file_attributes,
                        share_access,
                        create_disposition,
                        create_options,
                        ea_buffer,
                        ea_length,
                    )
                };
                if status == STATUS_ACCESS_DENIED {
                    record_denied_attempt(cfg, &path, desired_access.0);
                }
                return status;
            }
        }
    }

    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        )
    }
}

/// 呼び出しが成功していれば、生成されたハンドルをハンドル→パス対応表へ登録し、
/// `FILE_DELETE_ON_CLOSE`が立っていれば削除予定集合にも加える（設計書§19.6）。
pub(crate) fn track_new_handle(
    file_handle: *mut HANDLE,
    status: NTSTATUS,
    rel_str: &str,
    create_options: u32,
) {
    if status.is_err() {
        return;
    }
    let handle = unsafe { *file_handle };
    let key = handle.0 as isize;
    handle_paths()
        .lock()
        .unwrap()
        .insert(key, rel_str.to_string());
    if create_options & FILE_DELETE_ON_CLOSE.0 != 0 {
        delete_pending().lock().unwrap().insert(key);
    }
}

pub(crate) unsafe extern "system" fn hooked_nt_open_file(
    file_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    // `NtOpenFile`はcreate dispositionを取らない（常に`FILE_OPEN`相当）ため、write intentは
    // desired_accessのみで判定する。既存ファイルの書込open（copy-up要）が主な対象。
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] DirectRwのlazyレーン（`hooked_nt_create_file`と同じ形・同じ理由）。
        if let Some(cfg) = CONFIG.get().filter(|cfg| !cfg.cow_enabled) {
            let hook = OPEN_FILE_HOOK.get().expect("hook installed");
            let call = || unsafe {
                hook.call(
                    file_handle,
                    desired_access,
                    object_attributes,
                    io_status_block,
                    share_access,
                    open_options,
                )
            };
            let status = call();
            if status != STATUS_ACCESS_DENIED {
                return status;
            }
            return retry_once_after_fault_in(cfg, object_attributes, call).unwrap_or(status);
        }
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                let rel_lower = rel_str.to_ascii_lowercase();
                let is_probe = rel_lower.contains("test.txt") || rel_lower.contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_open_file: rel={rel_str:?} kind={kind:?} \
                         desired_access={desired_access:#x} options={open_options:#x} is_dir={} \
                         write_intent={} diff_layer_exists={}",
                        open_options & 0x0000_0001 != 0, // FILE_DIRECTORY_FILE
                        is_write_intent(desired_access, None),
                        cfg.diff_layer_dir.join(&rel).is_file(),
                    ));
                }
                // BUG-066: 差分層配下の実体を直接開いている（`hooked_nt_create_file`と同じ理由）。
                if kind == TargetKind::DiffLayerAlias {
                    // BUG-171: 台帳へ書くのは本当のopenが成功した後。
                    let record = should_redirect_write(
                        is_write_intent(desired_access, None),
                        open_options,
                        None,
                    )
                    .then(|| plan_diff_layer_alias_write(cfg, &rel_str))
                    .flatten();
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            object_attributes,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    finish_diff_layer_alias_write(cfg, record, status.is_ok());
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // `NtOpenFile`は既存ファイルを開く操作のみ（`FILE_OPEN`相当）のため、
                // 論理削除済みなら常に失敗させる（再作成の余地は無い）。
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} check_deleted short-circuit status={status:?}"
                        ));
                    }
                    return status;
                }
                if should_redirect_write(is_write_intent(desired_access, None), open_options, None)
                {
                    let diff_layer_path = cfg.diff_layer_dir.join(&rel);
                    // BUG-171: `hooked_nt_create_file`と同じ組（写すのは前、書くのは成功の後）。
                    // `NtOpenFile`は作り直せない（削除済みなら直前の`check_deleted`が断る）ので、
                    // 常に元の中身を写す。
                    let copied = copy_up(
                        cfg,
                        &rel_str,
                        &path,
                        &diff_layer_path,
                        CopySource::Workspace,
                    );
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    finish_copy_up(cfg, copied, status.is_ok());
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} branch=write-redirect \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // 読み取りread-through（`hooked_nt_create_file`と同じ理由、設計書§19.3/§19.7）。
                if let Some(diff_layer_path) = diff_layer_version_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} branch=read-through \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // ディレクトリ read-through（BUG-128、`hooked_nt_create_file`と同じ理由。
                // `FILE_DIRECTORY_FILE` では絞らない＝git の lstat に追随する）。
                if let Some(diff_layer_path) = diff_layer_only_dir_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            desired_access,
                            &redirected_oa,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                    };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_open_file: rel={rel_str:?} branch=dir-read-through \
                             diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
                    hook.call(
                        file_handle,
                        desired_access,
                        object_attributes,
                        io_status_block,
                        share_access,
                        open_options,
                    )
                };
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_open_file: rel={rel_str:?} branch=passthrough-no-diff_layer \
                         status={status:?}"
                    ));
                }
                track_new_handle(file_handle, status, &rel_str, open_options);
                return status;
            } else if is_write_intent(desired_access, None) {
                // Phase 4（設計書§19.8）: `hooked_nt_create_file`と同じ理由。
                let hook = OPEN_FILE_HOOK.get().expect("hook installed");
                let status = unsafe {
                    hook.call(
                        file_handle,
                        desired_access,
                        object_attributes,
                        io_status_block,
                        share_access,
                        open_options,
                    )
                };
                if status == STATUS_ACCESS_DENIED {
                    record_denied_attempt(cfg, &path, desired_access);
                }
                return status;
            }
        }
    }

    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            share_access,
            open_options,
        )
    }
}

/// `FILE_DISPOSITION_INFORMATION`/`_EX`から削除フラグを読み取る。
pub(crate) unsafe fn disposition_delete_flag(is_ex: bool, info_ptr: *const c_void) -> bool {
    if is_ex {
        let info = unsafe { &*(info_ptr as *const FILE_DISPOSITION_INFORMATION_EX) };
        info.Flags.0 & FILE_DISPOSITION_DELETE.0 != 0
    } else {
        let info = unsafe { &*(info_ptr as *const FILE_DISPOSITION_INFORMATION) };
        info.DeleteFile.0 != 0
    }
}

/// `FILE_RENAME_INFORMATION`/`_EX`から移動先パスを読み取る。`RootDirectory`が非NULL
/// （ディレクトリハンドル相対）の場合は安全側の素通しとして`None`を返す（設計書§19.6）。
pub(crate) unsafe fn rename_target_path(info_ptr: *const c_void) -> Option<PathBuf> {
    let info = unsafe { &*(info_ptr as *const FILE_RENAME_INFORMATION) };
    if !info.RootDirectory.0.is_null() {
        return None;
    }
    let len_u16 = (info.FileNameLength as usize) / 2;
    if len_u16 == 0 {
        return None;
    }
    let name_ptr = info.FileName.as_ptr();
    let slice = unsafe { std::slice::from_raw_parts(name_ptr, len_u16) };
    let raw = String::from_utf16_lossy(slice);
    strip_nt_prefix(&raw)
}

/// 移動先を差分層配下へ書き換えた`FILE_RENAME_INFORMATION`互換バッファを構築する。
/// `anonymous`（`ReplaceIfExists`/`Flags`共用体）は呼び出し元が指定した値をそのまま複製する
/// （リネームの意味自体は変えず、移動先パスだけを差し替える）。
pub(crate) fn build_rename_info_buffer(
    anonymous: windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION_0,
    new_diff_layer_path: &Path,
) -> (Vec<u8>, usize) {
    let header_offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_wide: Vec<u16> = {
        // `nt_path_wide`と同じ理由で`/`→`\`正規化が必須（Phase 3実機E2Eで発見）。
        let normalized = new_diff_layer_path.to_string_lossy().replace('/', "\\");
        let nt_path = format!(r"\??\{normalized}");
        nt_path.encode_utf16().collect()
    };
    let name_bytes_len = name_wide.len() * 2;
    let buf_len = std::cmp::max(
        std::mem::size_of::<FILE_RENAME_INFORMATION>(),
        header_offset + name_bytes_len,
    );
    let mut buf = vec![0u8; buf_len];
    unsafe {
        let header_ptr = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*header_ptr).Anonymous = anonymous;
        (*header_ptr).RootDirectory = HANDLE::default();
        (*header_ptr).FileNameLength = name_bytes_len as u32;
    }
    let name_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(name_wide.as_ptr() as *const u8, name_bytes_len) };
    buf[header_offset..header_offset + name_bytes_len].copy_from_slice(name_bytes);
    (buf, header_offset + name_bytes_len)
}

/// 名前の変更1回ぶんの、台帳へ書く予定とハンドル対応表の更新（BUG-171）。
/// 本当の変更の結果を[`PendingRename::settle`]へ渡し、成功したときだけ反映する。
#[must_use = "settle() with the real rename's result; dropping it records nothing"]
pub(crate) struct PendingRename {
    handle_key: isize,
    new_rel_str: String,
    old: PendingRecord,
    new: PendingRecord,
}

impl PendingRename {
    /// 成功したら、台帳へ旧パスの`Delete`と新パスの`Create`/`Modify`を書き、以降この
    /// ハンドルへの操作（例: リネーム直後の削除予約）が新パスを指すよう対応表を更新する。
    /// 失敗したら何もしない——元のファイルはそのまま在るので、台帳にもそう残す。
    pub(crate) fn settle(self, cfg: &Config, succeeded: bool) {
        if !succeeded {
            return;
        }
        self.old.settle(cfg, true);
        self.new.settle(cfg, true);
        handle_paths()
            .lock()
            .unwrap()
            .insert(self.handle_key, self.new_rel_str);
    }
}

/// リネーム/移動を検知し、(1) 移動先パスを差分層配下へ書き換え、(2) 台帳へ旧パスの`Delete`と
/// 新パスの`Create`/`Modify`を1件ずつ書く**予定**を作る（設計書§19.4/§19.6）。書き換え後の
/// バッファ・論理長・予定を返す（`None`なら素通し）。
///
/// **台帳へはここで書かない**（BUG-171）。移動先が既にある・共有違反などで本当の変更は
/// 失敗し得るので、書くのは呼び出し側が結果を見た後である。先に書いていた頃は、失敗した
/// 変更の元ファイルが台帳の上で削除済みになり、セッションの中から見えなくなって、
/// `apply`が本物を消しに行った。
pub(crate) unsafe fn rewrite_rename_target(
    cfg: &Config,
    handle_key: isize,
    info_ptr: *const c_void,
) -> Option<(Vec<u8>, usize, PendingRename)> {
    let old_rel = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    let new_path = unsafe { rename_target_path(info_ptr) }?;
    let Classified {
        rel: new_rel,
        ledger_key: new_rel_str,
        kind: _,
    } = classify_target(cfg, &new_path)?;
    // `kind`で分岐しないのは、`DiffLayerAlias`でも`rel`が差分層ルートからの相対なので
    // `diff_layer_dir.join(&new_rel)`が**移動先そのもの**（恒等）になるため。台帳の2行
    // （旧パスDelete＋新パスCreate/Modify）はどちらの種別でも同じように要る。
    let diff_layer_new = cfg.diff_layer_dir.join(&new_rel);
    if let Some(parent) = diff_layer_new.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let anonymous = unsafe { (*(info_ptr as *const FILE_RENAME_INFORMATION)).Anonymous };
    let (buf, len) = build_rename_info_buffer(anonymous, &diff_layer_new);

    let pending = PendingRename {
        handle_key,
        old: PendingRecord::delete(cfg, &old_rel),
        new: PendingRecord::rename_target(cfg, &new_rel_str),
        new_rel_str,
    };
    Some((buf, len, pending))
}

pub(crate) unsafe extern "system" fn hooked_nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *const c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    // 削除予約の申告（ハンドルと、立てるのか下ろすのか）。**本当の設定が成功してから**
    // 削除予約の集合へ反映する（BUG-171）——読み取り専用のファイルなどは設定そのものが
    // 断られ（`STATUS_CANNOT_DELETE`）、実際には消えない。先に集合へ入れていた頃は、
    // 閉じるときに台帳へ`Delete`が書かれ、消えていないファイルが削除済みになっていた。
    let mut disposition_request: Option<(isize, bool)> = None;
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] **DirectRwのlazyレーンでは何もしない。** ここはCoWの削除追跡と
        // rename誘導だけで、差分層が無ければ行き先が無い。**fault-inの引き金にもしない**
        // ——rename/deleteは「既に開けたhandleへの操作」で、開く前に割り込む余地が無い
        // （モジュールdocの引き金の表）。
        if let Some(cfg) = CONFIG.get().filter(|cfg| cfg.cow_enabled) {
            let handle_key = file_handle.0 as isize;
            if !file_information.is_null()
                && (file_information_class == FileDispositionInformation
                    || file_information_class == FileDispositionInformationEx)
            {
                let is_ex = file_information_class == FileDispositionInformationEx;
                let delete_flag = unsafe { disposition_delete_flag(is_ex, file_information) };
                disposition_request = Some((handle_key, delete_flag));
            } else if !file_information.is_null()
                && (file_information_class == FileRenameInformation
                    || file_information_class == FileRenameInformationEx)
            {
                if let Some((buf, len, pending)) =
                    unsafe { rewrite_rename_target(cfg, handle_key, file_information) }
                {
                    let hook = SET_INFO_HOOK.get().expect("hook installed");
                    let status = unsafe {
                        hook.call(
                            file_handle,
                            io_status_block,
                            buf.as_ptr() as *const c_void,
                            len as u32,
                            file_information_class,
                        )
                    };
                    // BUG-171: 台帳へ書くのは本当の変更が成功した後（再入防止ガードの内側で）。
                    pending.settle(cfg, status.is_ok());
                    return status;
                }
            }
        }
    }
    let hook = SET_INFO_HOOK.get().expect("hook installed");
    let status = unsafe {
        hook.call(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
        )
    };
    if let Some((handle_key, delete_flag)) = disposition_request {
        if status.is_ok() {
            let pending = delete_pending();
            let mut g = pending.lock().unwrap();
            if delete_flag {
                g.insert(handle_key);
            } else {
                g.remove(&handle_key);
            }
        }
    }
    status
}

pub(crate) unsafe extern "system" fn hooked_nt_close(handle: HANDLE) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] CoWの台帳記録だけなので、lazyレーンでは何もしない
        // （`hooked_nt_set_information_file`と同じ理由）。
        if let Some(cfg) = CONFIG.get().filter(|cfg| cfg.cow_enabled) {
            let key = handle.0 as isize;
            let rel_opt = handle_paths().lock().unwrap().remove(&key);
            let was_pending = delete_pending().lock().unwrap().remove(&key);
            dir_query_cursor().lock().unwrap().remove(&key);
            if was_pending {
                if let Some(rel) = rel_opt {
                    let baseline = baseline_hash_for(cfg, &rel);
                    append_ledger_entry(cfg, ChangeOp::Delete, &rel, baseline);
                }
            }
        }
    }
    let hook = CLOSE_HOOK.get().expect("hook installed");
    unsafe { hook.call(handle) }
}

pub(crate) unsafe extern "system" fn hooked_nt_query_full_attributes_file(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut windows::Wdk::Storage::FileSystem::FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] **属性照会も引き金に含める**（着手条件6）。増分ビルドはここから始まる
        // ——`cargo`・MSBuildは「入力は出力より新しいか」を全ファイルについて先に調べ、
        // **そのあとで必要なものだけを開く**。含めないと最初の接触が拒否されたまま要求が
        // 飛ばず、コマンドは再試行のないまま失敗する。
        //
        // **限界（設計書§5.1.3の着手条件6が挙げている2つ）**: (a) 祖先を通過できない場合など、
        // 拒否が`ACCESS_DENIED`以外で返る経路がある。(b) 親ディレクトリの一覧権限で子の属性を
        // 得る聞き方（`FindFirstFile`系）は子のDACLを見ないので、そもそもここへ来ない。
        // **どちらも「効き目の大きさ」の話で、含める判断は変わらない。**
        if let Some(cfg) = CONFIG.get().filter(|cfg| !cfg.cow_enabled) {
            let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
            let call = || unsafe { hook.call(object_attributes, file_information) };
            let status = call();
            if status != STATUS_ACCESS_DENIED {
                return status;
            }
            return retry_once_after_fault_in(cfg, object_attributes, call).unwrap_or(status);
        }
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                // 差分層配下の実体そのものへの照会は、見せ方を変えない（素通し）。
                if kind == TargetKind::DiffLayerAlias {
                    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(object_attributes, file_information) };
                }
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} diff_layer_exists={}",
                        cfg.diff_layer_dir.join(&rel).is_file(),
                    ));
                }
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                             check_deleted short-circuit status={status:?}"
                        ));
                    }
                    return status;
                }
                // read-through: `Test-Path`/`.NET File.Exists`が使うこの経路も、差分層に版が
                // あればそちらの属性を返す（設計書§19.3/§19.7、`hooked_nt_create_file`と同じ理由）。
                if let Some(diff_layer_path) = diff_layer_version_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                             branch=read-through diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-diff_layer"
                    ));
                }
            }
        }
    }
    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
}

pub(crate) unsafe extern "system" fn hooked_nt_query_attributes_file(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        // [D-88] 属性照会の引き金（`hooked_nt_query_full_attributes_file`と同じ形・同じ理由）。
        // **2つとも引き金にする**——`Test-Path`と`File.Exists`で降りる先が違うので、
        // 片方だけだと片方のツールでfault-inが効かない（`B-01`: 対の片方だけにしない）。
        if let Some(cfg) = CONFIG.get().filter(|cfg| !cfg.cow_enabled) {
            let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
            let call = || unsafe { hook.call(object_attributes, file_information) };
            let status = call();
            if status != STATUS_ACCESS_DENIED {
                return status;
            }
            return retry_once_after_fault_in(cfg, object_attributes, call).unwrap_or(status);
        }
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                // 差分層配下の実体そのものへの照会は、見せ方を変えない（素通し）。
                if kind == TargetKind::DiffLayerAlias {
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(object_attributes, file_information) };
                }
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} diff_layer_exists={}",
                        cfg.diff_layer_dir.join(&rel).is_file(),
                    ));
                }
                if let Some(status) = check_deleted(cfg, &rel_str, false) {
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_attributes_file: rel={rel_str:?} \
                             check_deleted short-circuit status={status:?}"
                        ));
                    }
                    return status;
                }
                // read-through（`hooked_nt_query_full_attributes_file`と同じ理由）。
                if let Some(diff_layer_path) = diff_layer_version_path(cfg, &rel) {
                    let diff_layer_wide: Vec<u16> = nt_path_wide(&diff_layer_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &diff_layer_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_attributes_file: rel={rel_str:?} \
                             branch=read-through diff_layer_path={diff_layer_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-diff_layer"
                    ));
                }
            }
        }
    }
    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
}
