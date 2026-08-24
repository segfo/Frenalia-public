//! ファイル系NTフック本体（`NtCreateFile`・`NtOpenFile`・`NtSetInformationFile`・
//! `NtClose`・`NtQuery*AttributesFile`）。
//!
//! **ここは境界ではない**（D-01）。境界はACLであり、このフック群は`--sandbox tier2a-cow`の透過性
//! （workspaceがRO化されていてもツールがそのまま書けるように見せる）のためだけに存在する。
//! フックが素通りしてもACLがfail-closeするので、失われるのは透過性だけである。

use super::*;

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
                let is_probe =
                    rel_lower.contains("test.txt") || rel_lower.contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_create_file: rel={rel_str:?} kind={kind:?} desired_access={:#x} \
                         disposition={:#x} options={:#x} is_dir={} write_intent={} upper_exists={}",
                        desired_access.0,
                        create_disposition.0,
                        create_options.0,
                        create_options.0 & 0x0000_0001 != 0, // FILE_DIRECTORY_FILE
                        is_write_intent(desired_access.0, Some(create_disposition.0)),
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                // BUG-066: upper配下の実体を直接開いている＝**既にCoWの行き先**。誘導は
                // 一切せず（upperのupperは作らない）、書込意図のときだけ台帳へ記録して
                // 素通しする。tombstone判定（`check_deleted`）も掛けない——あれは
                // 「workspaceをどう見せるか」の論理であって、行き先の実体への直接アクセスに
                // 被せると、削除済みパスのupper実体を消すことすらできなくなる。
                if kind == TargetKind::UpperAlias {
                    if should_redirect_write(
                        is_write_intent(desired_access.0, Some(create_disposition.0)),
                        create_options.0,
                        Some(create_disposition.0),
                    ) {
                        record_upper_alias_write(cfg, &rel_str);
                    }
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
                    let upper_path = cfg.upper_dir.join(&rel);
                    copy_up(cfg, &rel_str, &path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                            "hooked_nt_create_file: rel={rel_str:?} branch=write-redirect \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // 読み取りread-through（設計書§19.3/§19.7「削除済み＞upper＞workspace」の中間段）:
                // 書込意図が無い開き方（`Get-Content`等）でも、upperに版があればそちらを読ませる。
                // これが無いと「書いた直後に読み返す」操作が実workspace側（実体が無いか古い）を見て
                // 失敗する（実機E2Eで発見、既存の`cow_diagnostics`はAppContainer外から
                // `std::fs::read_to_string`で確認するだけだったため見逃されていた）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // ディレクトリ read-through（BUG-128）: upper にしか無いディレクトリを開くときは
                // upper へ誘導する。無いと read-only の workspace 側を開こうとして ACCESS_DENIED／
                // OBJECT_NAME_NOT_FOUND になり、git の pathspec 解決・列挙が壊れる
                // （`upper_only_dir_path` のdoc参照）。
                //
                // **`FILE_DIRECTORY_FILE` フラグでは絞らない**——git/Cygwin の `lstat` は、対象が
                // ファイルかディレクトリか未確定のまま `FILE_OPEN_FOR_BACKUP_INTENT`（フラグ無し）で
                // 開いて存在と種別を確かめる。フラグで絞ると、この lstat が upper のみのディレクトリを
                // 「存在しない」と誤認し、`git add <path>` が対象を見つけられず何もステージしない
                // （実機ログで確認）。ファイルの read-through（`upper_version_path`）は上で済んでいるので、
                // ここに来る時点で対象はファイルではない＝ディレクトリ判定と衝突しない。
                if let Some(upper_path) = upper_only_dir_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, create_options.0);
                    return status;
                }
                // upperにも版が無い（このセッションで一度も触っていない）場合は、これまで通り
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
                        "hooked_nt_create_file: rel={rel_str:?} branch=passthrough-no-upper \
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
                let is_probe =
                    rel_lower.contains("test.txt") || rel_lower.contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_open_file: rel={rel_str:?} kind={kind:?} \
                         desired_access={desired_access:#x} options={open_options:#x} is_dir={} \
                         write_intent={} upper_exists={}",
                        open_options & 0x0000_0001 != 0, // FILE_DIRECTORY_FILE
                        is_write_intent(desired_access, None),
                        cfg.upper_dir.join(&rel).is_file(),
                    ));
                }
                // BUG-066: upper配下の実体を直接開いている（`hooked_nt_create_file`と同じ理由）。
                if kind == TargetKind::UpperAlias {
                    if should_redirect_write(
                        is_write_intent(desired_access, None),
                        open_options,
                        None,
                    ) {
                        record_upper_alias_write(cfg, &rel_str);
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
                    let upper_path = cfg.upper_dir.join(&rel);
                    copy_up(cfg, &rel_str, &path, &upper_path);
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                            "hooked_nt_open_file: rel={rel_str:?} branch=write-redirect \
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // 読み取りread-through（`hooked_nt_create_file`と同じ理由、設計書§19.3/§19.7）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                             upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    track_new_handle(file_handle, status, &rel_str, open_options);
                    return status;
                }
                // ディレクトリ read-through（BUG-128、`hooked_nt_create_file`と同じ理由。
                // `FILE_DIRECTORY_FILE` では絞らない＝git の lstat に追随する）。
                if let Some(upper_path) = upper_only_dir_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
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
                             upper_path={upper_path:?} status={status:?}"
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
                        "hooked_nt_open_file: rel={rel_str:?} branch=passthrough-no-upper \
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

/// 移動先をupper配下へ書き換えた`FILE_RENAME_INFORMATION`互換バッファを構築する。
/// `anonymous`（`ReplaceIfExists`/`Flags`共用体）は呼び出し元が指定した値をそのまま複製する
/// （リネームの意味自体は変えず、移動先パスだけを差し替える）。
pub(crate) fn build_rename_info_buffer(
    anonymous: windows::Wdk::Storage::FileSystem::FILE_RENAME_INFORMATION_0,
    new_upper_path: &Path,
) -> (Vec<u8>, usize) {
    let header_offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let name_wide: Vec<u16> = {
        // `nt_path_wide`と同じ理由で`/`→`\`正規化が必須（Phase 3実機E2Eで発見）。
        let normalized = new_upper_path.to_string_lossy().replace('/', "\\");
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

/// リネーム/移動を検知し、(1) 移動先パスをupper配下へ書き換え、(2) 台帳へ旧パスの`Delete`と
/// 新パスの`Create`/`Modify`を1件ずつ追記する（設計書§19.4/§19.6）。書き換え後のバッファと
/// 論理長を返す（`None`なら素通し）。
pub(crate) unsafe fn rewrite_rename_target(
    cfg: &Config,
    handle_key: isize,
    info_ptr: *const c_void,
) -> Option<(Vec<u8>, usize)> {
    let old_rel = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    let new_path = unsafe { rename_target_path(info_ptr) }?;
    let Classified {
        rel: new_rel,
        ledger_key: new_rel_str,
        kind: _,
    } = classify_target(cfg, &new_path)?;
    // `kind`で分岐しないのは、`UpperAlias`でも`rel`がupperルートからの相対なので
    // `upper_dir.join(&new_rel)`が**移動先そのもの**（恒等）になるため。台帳の2行
    // （旧パスDelete＋新パスCreate/Modify）はどちらの種別でも同じように要る。
    let upper_new = cfg.upper_dir.join(&new_rel);
    if let Some(parent) = upper_new.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let anonymous = unsafe { (*(info_ptr as *const FILE_RENAME_INFORMATION)).Anonymous };
    let buf = build_rename_info_buffer(anonymous, &upper_new);

    let old_baseline = baseline_hash_for(cfg, &old_rel);
    append_ledger_entry(cfg, ChangeOp::Delete, &old_rel, old_baseline);
    let new_baseline = baseline_hash_for(cfg, &new_rel_str);
    let new_op = if new_baseline.is_some() {
        ChangeOp::Modify
    } else {
        ChangeOp::Create
    };
    append_ledger_entry(cfg, new_op, &new_rel_str, new_baseline);

    // 以降このハンドルに対する操作（例: リネーム直後の削除予約）は新パスを指すべきなので、
    // 対応表を更新しておく。
    handle_paths()
        .lock()
        .unwrap()
        .insert(handle_key, new_rel_str);

    Some(buf)
}

pub(crate) unsafe extern "system" fn hooked_nt_set_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *const c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let Some(cfg) = CONFIG.get() {
            let handle_key = file_handle.0 as isize;
            if !file_information.is_null()
                && (file_information_class == FileDispositionInformation
                    || file_information_class == FileDispositionInformationEx)
            {
                let is_ex = file_information_class == FileDispositionInformationEx;
                let delete_flag = unsafe { disposition_delete_flag(is_ex, file_information) };
                let pending = delete_pending();
                let mut g = pending.lock().unwrap();
                if delete_flag {
                    g.insert(handle_key);
                } else {
                    g.remove(&handle_key);
                }
            } else if !file_information.is_null()
                && (file_information_class == FileRenameInformation
                    || file_information_class == FileRenameInformationEx)
            {
                if let Some((buf, len)) =
                    unsafe { rewrite_rename_target(cfg, handle_key, file_information) }
                {
                    let hook = SET_INFO_HOOK.get().expect("hook installed");
                    return unsafe {
                        hook.call(
                            file_handle,
                            io_status_block,
                            buf.as_ptr() as *const c_void,
                            len as u32,
                            file_information_class,
                        )
                    };
                }
            }
        }
    }
    let hook = SET_INFO_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
        )
    }
}

pub(crate) unsafe extern "system" fn hooked_nt_close(handle: HANDLE) -> NTSTATUS {
    if let Some(_guard) = ReentryGuard::try_acquire() {
        if let Some(cfg) = CONFIG.get() {
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
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                // upper配下の実体そのものへの照会は、見せ方を変えない（素通し）。
                if kind == TargetKind::UpperAlias {
                    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(object_attributes, file_information) };
                }
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} upper_exists={}",
                        cfg.upper_dir.join(&rel).is_file(),
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
                // read-through: `Test-Path`/`.NET File.Exists`が使うこの経路も、upperに版が
                // あればそちらの属性を返す（設計書§19.3/§19.7、`hooked_nt_create_file`と同じ理由）。
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_FULL_ATTR_HOOK.get().expect("hook installed");
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                             branch=read-through upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_full_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-upper"
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
        if let (Some(cfg), Some(path)) = (CONFIG.get(), unsafe {
            object_attributes_path(object_attributes)
        }) {
            if let Some(Classified {
                rel,
                ledger_key: rel_str,
                kind,
            }) = classify_target(cfg, &path)
            {
                // upper配下の実体そのものへの照会は、見せ方を変えない（素通し）。
                if kind == TargetKind::UpperAlias {
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    return unsafe { hook.call(object_attributes, file_information) };
                }
                let is_probe = rel_str.to_ascii_lowercase().contains("test.txt")
                    || rel_str.to_ascii_lowercase().contains("grandchild");
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} upper_exists={}",
                        cfg.upper_dir.join(&rel).is_file(),
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
                if let Some(upper_path) = upper_version_path(cfg, &rel) {
                    let upper_wide: Vec<u16> = nt_path_wide(&upper_path);
                    let (mut redirected_oa, mut redirected_name) =
                        unsafe { build_redirected_oa(object_attributes, &upper_wide) };
                    redirected_oa.ObjectName = &mut redirected_name;
                    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
                    let status = unsafe { hook.call(&redirected_oa, file_information) };
                    if is_probe {
                        debug_log(&format!(
                            "hooked_nt_query_attributes_file: rel={rel_str:?} \
                             branch=read-through upper_path={upper_path:?} status={status:?}"
                        ));
                    }
                    return status;
                }
                if is_probe {
                    debug_log(&format!(
                        "hooked_nt_query_attributes_file: rel={rel_str:?} \
                         branch=passthrough-no-upper"
                    ));
                }
            }
        }
    }
    let hook = QUERY_ATTR_HOOK.get().expect("hook installed");
    unsafe { hook.call(object_attributes, file_information) }
}
