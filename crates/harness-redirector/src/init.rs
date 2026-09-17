//! DLLの初期化とフック設置、およびエントリポイント（`harness_cow_init`・`DllMain`）。
//!
//! 注入スレッドが`harness_cow_init`を呼び、設定blobを読んで全フックを設置してから
//! 親へready通知を返す。

use super::*;

pub(crate) unsafe fn resolve_ntdll_export(name: &str) -> Option<*const c_void> {
    unsafe { resolve_module_export("ntdll.dll", name) }
}

/// `resolve_ntdll_export`の一般化版（Phase 4a、BUG-041修正で追加）。`kernel32.dll`/
/// `kernelbase.dll`からのエクスポート解決にも使う。`GetProcAddress`は転送エクスポート
/// （export forwarder、例えば`kernel32!CreateProcessW`が`KERNELBASE.CreateProcessW`へ転送する
/// 形式）を自動的に解決するため、`kernelbase.dll`から先に解決を試みれば実体のアドレスが
/// 直接得られる。
pub(crate) unsafe fn resolve_module_export(module: &str, name: &str) -> Option<*const c_void> {
    let module_name: Vec<u16> = format!("{module}\0").encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(PCWSTR(module_name.as_ptr())) }.ok()?;
    let name_c = format!("{name}\0");
    let addr = unsafe { GetProcAddress(module, windows::core::PCSTR(name_c.as_ptr())) }?;
    Some(addr as *const c_void)
}

/// 既存の台帳（あれば）を読み、`deleted_paths_state`を組み立てる（設計書§19.7）。DLLは
/// `run_shell`呼び出しのたびに別プロセスへ再ロードされ得るため、台帳ファイルを唯一の正本に
/// して起動のたびに再生する。
pub(crate) fn load_deleted_set(cfg: &Config) {
    let ledger_path = cfg.diff_layer_dir.join(COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read(&ledger_path) else {
        return;
    };
    let text = String::from_utf8_lossy(&contents);
    let entries = parse_ledger(&text);
    let deleted = harness_change_ledger::deleted_paths(&entries);
    *deleted_paths_state().lock().unwrap() = deleted;
    // 起動時に読んだ全内容をオフセットとして記録し、以降`refresh_deleted_set`が同じ範囲を
    // 二重に取り込まないようにする。
    *ledger_read_offset().lock().unwrap() = contents.len() as u64;
}

/// 設定の取得（BUG-045のF2）。注入パラメータ（`harness_cow_init`の引数、非NULLなら正）を
/// 優先し、無ければ環境変数`HARNESS_COW_*`へフォールバックする。Launcherが直接起動する子
/// （`win_appcontainer.rs`の`inject_redirector`）はenv経路、DLL自身が再注入する孫以降は
/// パラメータ経路を通る。
///
/// # Safety
/// `param`は[`deserialize_config_blob`]の要件を満たすこと。
pub(crate) unsafe fn resolve_config(param: *const u8) -> Option<Config> {
    if let Some(cfg) = unsafe { deserialize_config_blob(param) } {
        debug_log(&format!(
            "init: config from injection parameter workspace={:?} diff_layer={:?} ext_roots={:?}",
            cfg.workspace_root, cfg.diff_layer_dir, cfg.ext_capture_roots
        ));
        return Some(finalize_config(cfg));
    }
    debug_log(&format!(
        "init: config from env, HARNESS_COW_WORKSPACE={:?} HARNESS_COW_DIFF_LAYER={:?}",
        get_env("HARNESS_COW_WORKSPACE"),
        get_env("HARNESS_COW_DIFF_LAYER")
    ));
    // [段階5b] **ワークスペースは必須ではなくなった。** プロセス生成フックだけを理由に
    // 注入する相手（MCPサーバ）にはワークスペースが無い。
    let workspace_root = get_env("HARNESS_COW_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_default();
    // [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] **差分層は必須ではなくなった。**
    // DirectRwのlazyレーンには差分層が無く、受付パイプだけがある。
    let diff_layer_dir = get_env("HARNESS_COW_DIFF_LAYER")
        .map(PathBuf::from)
        .unwrap_or_default();
    let broker_pipe = get_env("HARNESS_LAZY_BROKER_PIPE");
    let process_hooks = super::config::process_hooks_from_env();
    let cow_enabled = !diff_layer_dir.as_os_str().is_empty();
    if !cow_enabled && broker_pipe.is_none() && !process_hooks {
        // CoWでもなく受付もフックの要求も無い＝このDLLがやることは無い。**成功にしない**
        // （`parse_config_blob`と同じ判断。理由はあちらのコメント）。
        debug_log("init: no diff layer, no fault broker and no process-hook request, bail");
        return None;
    }
    // 誘導も受付も「workspace内か」を判定するので、**ワークスペースが分からないまま
    // その2つを名乗る設定は受け取らない**（`parse_config_blob`と**同じ判断**。BUG-066は、
    // 照合が全部外れると「workspace外への書込が拒否された」ように見える形で全部が壊れる）。
    if workspace_root.as_os_str().is_empty() && (cow_enabled || broker_pipe.is_some()) {
        debug_log("init: a diff layer or a fault broker was given without a workspace root, bail");
        return None;
    }
    // Phase 3（設計書§19.8）: `;`区切りのDOS形式絶対パス一覧。空文字列要素は無視する
    // （`get_env`が空文字列全体は既に`None`扱いにするが、"C:\a;;C:\b"のような中間の
    // 空要素を防御的に無視する）。
    let ext_capture_roots: Vec<PathBuf> = get_env("HARNESS_COW_EXT_ROOTS")
        .map(|v| {
            v.split(';')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default();
    debug_log(&format!(
        "init: HARNESS_COW_EXT_ROOTS={ext_capture_roots:?}"
    ));
    Some(finalize_config(Config {
        workspace_root,
        diff_layer_dir,
        cow_enabled,
        broker_pipe,
        ext_capture_roots,
        process_hooks,
    }))
}

/// 受け取った設定のルートの綴りを揃え（`normalize_root_spelling`）、**workspace_rootが
/// 絶対パスでなければ警告台帳へ記録する**（[BUG-066](../../../docs/bugs/BUG-066.md)）。
///
/// workspace_rootが相対パス（`--cwd .`等）だと、アプリが渡す絶対パスとの照合が全て外れ、
/// **workspace内への書込が1件残らずACL拒否になる**（＝`--sandbox tier2a-cow`の透過性が全滅する）。
/// それでも「フックは境界ではない」（D-01）以上、ここで起動を止める意味は無い——止めても
/// 止めなくてもworkspaceはROのままで安全性は変わらない。変わるのは**なぜ書けないのかが
/// 分かるかどうか**なので、理由を台帳へ残して続行する（実際BUG-066のセッションでは、
/// この痕跡がどこにも無かったせいで原因の特定に会話ログの発掘が要った）。
pub(crate) fn finalize_config(cfg: Config) -> Config {
    use harness_change_ledger::path_rules::normalize_root_spelling;
    let normalize = |p: &Path| PathBuf::from(normalize_root_spelling(&p.to_string_lossy()));
    let cfg = Config {
        workspace_root: normalize(&cfg.workspace_root),
        // 空の差分層を`normalize`へ通すと空でなくなり得るので、空はそのまま空にする
        // （空であることが`cow_enabled`の根拠なので、綴りの正規化で崩してはいけない）。
        diff_layer_dir: if cfg.diff_layer_dir.as_os_str().is_empty() {
            PathBuf::new()
        } else {
            normalize(&cfg.diff_layer_dir)
        },
        cow_enabled: cfg.cow_enabled,
        broker_pipe: cfg.broker_pipe,
        ext_capture_roots: cfg.ext_capture_roots.iter().map(|p| normalize(p)).collect(),
        process_hooks: cfg.process_hooks,
    };
    // [段階5b] **ワークスペースが無いのは異常ではない。** プロセス生成フックだけを理由に
    // 注入した相手（MCPサーバ）には最初から無く、そのときファイル系フックは1本も置かない
    // ので、照合が外れる余地も無い。ここで警告を出すと、**書き込み先が相対パスになって
    // 相手の作業ディレクトリへ台帳が生える**（`debug_log`が同じ罠を1度踏んでいる）。
    if !cfg.workspace_root.as_os_str().is_empty() && !cfg.workspace_root.is_absolute() {
        append_warning_kind(
            &cfg,
            "config_workspace_not_absolute",
            &format!(
                "HARNESS_COW_WORKSPACE is not an absolute path ({}); every absolute-path write \
                 into the workspace will fail to classify and be denied by the read-only ACL \
                 instead of being redirected to the CoW diff_layer directory (see docs/bugs/BUG-066.md)",
                cfg.workspace_root.display()
            ),
        );
    }
    cfg
}

/// [`init`]を直列化し、**成功だけを確定させる**入口（BUG-045）。既に成功済みなら即`true`
/// （冪等）。失敗は確定させないため、先行した`DllMain`スレッドがenv欠落で失敗しても、
/// 後続の`harness_cow_init(param)`が注入パラメータで再試行できる。
///
/// # Safety
/// `param`は[`resolve_config`]の要件を満たすこと。
pub(crate) unsafe fn ensure_init(param: *const u8) -> bool {
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if INIT_SUCCEEDED.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    let ok = unsafe { init(param) };
    if ok {
        INIT_SUCCEEDED.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    ok
}

/// フック設置本体（`DllMain`からは呼ばない、Loader Lock回避のため専用スレッドから呼ぶ、
/// 設計書§13.4）。設定を読み・フックを設置し、成功したらready通知を送る。
/// 失敗時は通知しない——Launcher側は待機タイムアウトでプロセスを終了する
/// （設計書§10.2 既定・§25.1）。
///
/// 戻り値は「6つのファイルフックの設置まで完了したか」。BUG-045のF1修正前はこの成否が
/// 呼び出し元へ一切伝わらず、フック未設置でも注入側が成功と誤判定していた。直接呼ばず
/// [`ensure_init`]経由で使うこと。
///
/// # Safety
/// `param`は[`resolve_config`]の要件を満たすこと。
pub(crate) unsafe fn init(param: *const u8) -> bool {
    let Some(cfg) = (unsafe { resolve_config(param) }) else {
        return false;
    };
    // [段階5b] **ファイル系フックを置く理由があるか。** CoWの誘導もfault受付も無いなら、
    // あの7本は`NtCreateFile`等の全呼び出しを素通りさせるだけの回り道になる
    // （`file_hooks`のモジュールdocの表: `cow_enabled`が偽のとき成功経路では何もしない。
    // 受付が無ければ失敗経路も`retry_once_after_fault_in`の1行目で戻る）。
    let file_hooks_wanted = cfg.cow_enabled || cfg.broker_pipe.is_some();
    // **フックの設置に失敗したとき、それを致命にしてよいか。**
    //
    // [段階⑤] 条件は「なぜ注入したか」ではなく「**このプロセスは自力で子を作れるか**」である
    // （`docs/STATUS.md`残課題#44の決定）。理由は2つに割れる。
    //
    // - 生成禁止が積まれている（`CHILD_PROCESS_RESTRICTED`）: 自力では子を作れないので、
    //   フックが「Spawn Daemonへ頼む」へ変換する**唯一の経路**になる。置けなければ、
    //   この子は子プロセスを作ることも頼むこともできず**エラーも出さずに何もできなくなる**
    // - 積まれていない（今日の既定）: 自力で子を作れるので、フックが無くても動く。
    //   失われるのは孫への再注入だけで、境界はACLが張ったまま（フックは境界ではない、D-01）
    //
    // **危険が実在するのは前者だけなので、致命にするのも前者だけである。** これで
    // CoW／lazyの今日の挙動は1ビットも変わらない。
    //
    // [段階6f-2] **判定はここに持たない。** 同じ問いをフック側（`spawn_broker`）も引く
    // ——「自力で作れないなら頼む」の分岐がそれである。2箇所で別々に問い合わせると、
    // 片方だけ倒し方を変えた状態が黙って成立する（`B-13`）。
    let self_is_child_process_restricted = crate::spawn_broker::child_process_creation_is_blocked();
    // [段階5b] 加えて、**プロセス生成フックだけを理由に注入した**のなら、置けなかった時点で
    // このDLLは何もしていない——そこでreadyを返すと「入ったが何もしていない」が成功として通る。
    let process_hooks_are_the_only_reason = cfg.process_hooks && !file_hooks_wanted;
    let process_hooks_are_mandatory =
        self_is_child_process_restricted || process_hooks_are_the_only_reason;
    load_deleted_set(&cfg);
    let _ = CONFIG.set(cfg);

    if !file_hooks_wanted {
        debug_log("init: no diff layer and no fault broker; installing process hooks only");
        let installed = install_create_process_hooks();
        if process_hooks_are_mandatory && !installed {
            debug_log(
                "init: the process-creation hooks are mandatory for this process \
                       (child process creation is blocked, or the hooks are the only reason \
                       for this injection), and none could be installed; \
                       bail without signalling ready",
            );
            return false;
        }
        signal_ready();
        return true;
    }

    let create_file_addr = match unsafe { resolve_ntdll_export("NtCreateFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtCreateFile) failed, bail");
            return false;
        }
    };
    let open_file_addr = match unsafe { resolve_ntdll_export("NtOpenFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtOpenFile) failed, bail");
            return false;
        }
    };
    let set_info_addr = match unsafe { resolve_ntdll_export("NtSetInformationFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtSetInformationFile) failed, bail");
            return false;
        }
    };
    let close_addr = match unsafe { resolve_ntdll_export("NtClose") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtClose) failed, bail");
            return false;
        }
    };
    let query_full_attr_addr = match unsafe { resolve_ntdll_export("NtQueryFullAttributesFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryFullAttributesFile) failed, bail");
            return false;
        }
    };
    let query_attr_addr = match unsafe { resolve_ntdll_export("NtQueryAttributesFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryAttributesFile) failed, bail");
            return false;
        }
    };
    let query_dir_addr = match unsafe { resolve_ntdll_export("NtQueryDirectoryFile") } {
        Some(a) => a,
        None => {
            debug_log("init: resolve_ntdll_export(NtQueryDirectoryFile) failed, bail");
            return false;
        }
    };

    let create_file_fn: NtCreateFileFn = unsafe { std::mem::transmute(create_file_addr) };
    let open_file_fn: NtOpenFileFn = unsafe { std::mem::transmute(open_file_addr) };
    let set_info_fn: NtSetInformationFileFn = unsafe { std::mem::transmute(set_info_addr) };
    let close_fn: NtCloseFn = unsafe { std::mem::transmute(close_addr) };
    let query_full_attr_fn: NtQueryFullAttributesFileFn =
        unsafe { std::mem::transmute(query_full_attr_addr) };
    let query_attr_fn: NtQueryAttributesFileFn = unsafe { std::mem::transmute(query_attr_addr) };
    let query_dir_fn: NtQueryDirectoryFileFn = unsafe { std::mem::transmute(query_dir_addr) };

    let create_detour = match unsafe { GenericDetour::new(create_file_fn, hooked_nt_create_file) } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let open_detour = match unsafe { GenericDetour::new(open_file_fn, hooked_nt_open_file) } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let set_info_detour =
        match unsafe { GenericDetour::new(set_info_fn, hooked_nt_set_information_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    let close_detour = match unsafe { GenericDetour::new(close_fn, hooked_nt_close) } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let query_full_attr_detour = match unsafe {
        GenericDetour::new(query_full_attr_fn, hooked_nt_query_full_attributes_file)
    } {
        Ok(d) => d,
        Err(_) => return false,
    };
    let query_attr_detour =
        match unsafe { GenericDetour::new(query_attr_fn, hooked_nt_query_attributes_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    let query_dir_detour =
        match unsafe { GenericDetour::new(query_dir_fn, hooked_nt_query_directory_file) } {
            Ok(d) => d,
            Err(_) => return false,
        };
    if unsafe { create_detour.enable() }.is_err() {
        debug_log("init: create_detour.enable() failed, bail");
        return false;
    }
    if unsafe { open_detour.enable() }.is_err() {
        debug_log("init: open_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
        }
        return false;
    }
    if unsafe { set_info_detour.enable() }.is_err() {
        debug_log("init: set_info_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
        }
        return false;
    }
    if unsafe { close_detour.enable() }.is_err() {
        debug_log("init: close_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
        }
        return false;
    }
    if unsafe { query_full_attr_detour.enable() }.is_err() {
        debug_log("init: query_full_attr_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
        }
        return false;
    }
    if unsafe { query_attr_detour.enable() }.is_err() {
        debug_log("init: query_attr_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
            let _ = query_full_attr_detour.disable();
        }
        return false;
    }
    if unsafe { query_dir_detour.enable() }.is_err() {
        debug_log("init: query_dir_detour.enable() failed, bail");
        unsafe {
            let _ = create_detour.disable();
            let _ = open_detour.disable();
            let _ = set_info_detour.disable();
            let _ = close_detour.disable();
            let _ = query_full_attr_detour.disable();
            let _ = query_attr_detour.disable();
        }
        return false;
    }
    let _ = CREATE_FILE_HOOK.set(create_detour);
    let _ = OPEN_FILE_HOOK.set(open_detour);
    let _ = SET_INFO_HOOK.set(set_info_detour);
    let _ = CLOSE_HOOK.set(close_detour);
    let _ = QUERY_FULL_ATTR_HOOK.set(query_full_attr_detour);
    let _ = QUERY_ATTR_HOOK.set(query_attr_detour);
    let _ = QUERY_DIR_HOOK.set(query_dir_detour);
    debug_log("init: all 7 file hooks installed successfully");

    // BUG-048（F3）: `NtQueryDirectoryFileEx`はWindows 10 1709以降にのみ存在するため、
    // `CreateProcessW`等と同じくベストエフォート（無くても上記7フックの動作には影響しない、
    // 単に`FindFirstFileEx`系の一部経路でマージが効かないだけ＝BUG-047修正前の挙動に戻るだけ）。
    let query_dir_ex_installed = install_query_dir_ex_hook();
    debug_log(&format!(
        "init: install_query_dir_ex_hook done, installed={query_dir_ex_installed}"
    ));

    // Phase 4a（BUG-041修正）: `CreateProcessW`/`CreateProcessAsUserW`フックはベストエフォート。
    // Phase 1-3（直接の子の書込リダイレクト）は実機で確立済みの機能であり、これらのフックが
    // 何らかの理由で設置に失敗しても、上記6フックを巻き戻さずそのまま活かす（孫プロセスへの
    // 再注入だけが働かなくなる＝Phase 4a以前と同じ状態に留まる）。
    //
    // **[段階⑤] ただし生成禁止が積まれているときは別である。** そのとき「ベストエフォート」は
    // 「静かに何もできない子を作ってよい」と同義になる。**上の分岐と同じ条件を使う**
    // ——CoWやlazyの構成でも、生成禁止を積んだ瞬間に危険は同じだけ実在する
    // （`B-06`: 同じ判断を持つ経路は2つあり、2つとも直す）。
    let installed = install_create_process_hooks();
    debug_log(&format!(
        "init: install_create_process_hooks done, create_process_w_hook={} create_process_as_user_w_hook={}",
        CREATE_PROCESS_W_HOOK.get().is_some(),
        CREATE_PROCESS_AS_USER_W_HOOK.get().is_some()
    ));
    if process_hooks_are_mandatory && !installed {
        debug_log(
            "init: child process creation is blocked for this process but no process-creation \
                   hook could be installed; bail without signalling ready",
        );
        return false;
    }

    signal_ready();
    true
}

/// `NtQueryDirectoryFileEx`のベストエフォートフック設置（BUG-048 F3、`init`から呼ばれる）。
/// exportが無い（Windows 10 1709未満）・detour設置/enable失敗のいずれでも`false`を返すだけで、
/// 他の必須7フックには一切影響しない（`NtQueryDirectoryFile`フック単体でも大半の列挙経路は
/// カバーする——`try_merged_dir_query`本体の効果が一部の経路で得られなくなるだけ）。
pub(crate) fn install_query_dir_ex_hook() -> bool {
    let Some(addr) = (unsafe { resolve_ntdll_export("NtQueryDirectoryFileEx") }) else {
        return false;
    };
    let target: NtQueryDirectoryFileExFn = unsafe { std::mem::transmute(addr) };
    let Ok(detour) = (unsafe { GenericDetour::new(target, hooked_nt_query_directory_file_ex) })
    else {
        return false;
    };
    if unsafe { detour.enable() }.is_err() {
        return false;
    }
    QUERY_DIR_EX_HOOK.set(detour).is_ok()
}

/// `CreateProcessW`/`CreateProcessAsUserW`のベストエフォートフック設置（Phase 4a、BUG-041修正、
/// `init`から呼ばれる）。失敗しても他の6フックには一切影響しない（呼び出し元コメント参照）。
/// `kernelbase.dll`から先に解決を試みる（`resolve_module_export`のdoc参照、転送エクスポートの
/// 実体を直接掴むため）。`kernel32.dll`の解決に失敗する環境は無い想定だが、フォールバックとして
/// `kernelbase.dll`側の解決が失敗した場合のみ`kernel32.dll`を試す。
///
/// # 戻り値は`CreateProcessW`が置けたかである
///
/// [段階5b] このフックだけを理由に注入したときは、置けなかったことを呼び出し元が
/// 致命として扱う。**4本すべてではなく`CreateProcessW`を見るのは**、残る3本
/// （`CreateProcessAsUserW`・`CreateProcessA`・`WinExec`）がどれも
/// `CreateProcessW`と同じ本体へ落ちる別名で、環境によっては存在しないことがあるためである
/// （`WinExec`は特に古い口）。**「1本も置けなかった」と「全部は置けなかった」は別**で、
/// 致命にしてよいのは前者だけである。
pub(crate) fn install_create_process_hooks() -> bool {
    for module in ["kernelbase.dll", "kernel32.dll"] {
        if CREATE_PROCESS_W_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessW") } {
                let target: CreateProcessWFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_create_process_w) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_W_HOOK.set(detour);
                    }
                }
            }
        }
        if CREATE_PROCESS_AS_USER_W_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessAsUserW") } {
                let target: CreateProcessAsUserWFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) =
                    unsafe { GenericDetour::new(target, hooked_create_process_as_user_w) }
                {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_AS_USER_W_HOOK.set(detour);
                    }
                }
            }
        }
        // 残課題#5: `CreateProcessA`/`WinExec`も同じベストエフォート方針で追加する
        // （失敗しても他フックには影響しない、モジュールdoc「CreateProcessAFn」参照）。
        if CREATE_PROCESS_A_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "CreateProcessA") } {
                let target: CreateProcessAFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_create_process_a) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = CREATE_PROCESS_A_HOOK.set(detour);
                    }
                }
            }
        }
        if WIN_EXEC_HOOK.get().is_none() {
            if let Some(addr) = unsafe { resolve_module_export(module, "WinExec") } {
                let target: WinExecFn = unsafe { std::mem::transmute(addr) };
                if let Ok(detour) = unsafe { GenericDetour::new(target, hooked_win_exec) } {
                    if unsafe { detour.enable() }.is_ok() {
                        let _ = WIN_EXEC_HOOK.set(detour);
                    }
                }
            }
        }
    }
    CREATE_PROCESS_W_HOOK.get().is_some()
}

/// Launcherが`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`で継承させたパイプ書込端（`HARNESS_COW_READY_HANDLE`
/// に生ハンドル値として渡される、`win_appcontainer.rs`の`appcontainer_pipe`+`wait_cow_ready`と対）へ
/// 1バイト書き込む。ハンドルのcloseはLauncher側が読み取り後に行う（`win_appcontainer.rs:1222`）ため、
/// ここでは書込のみ行い、close責務は持たない。
///
/// BUG-041調査で判明した副次バグ: `HARNESS_COW_READY_HANDLE`はLauncherが直接の子にのみ継承させた
/// パイプハンドル値であり、その子だけに意味を持つ。しかしenv変数はPhase 4aの孫プロセスにも
/// そのまま継承されるため、孫の`init()`が**孫プロセス内では無関係な（あるいは無効な）ハンドル値**
/// へ書き込みを試みてしまう。書き終えた直後に自プロセスのenvから消し、子孫プロセスへ伝播しない
/// ようにする（`HARNESS_COW_WORKSPACE`/`HARNESS_COW_DIFF_LAYER`は孫にも必要なので残す）。
pub(crate) fn signal_ready() {
    let Some(handle_value) =
        get_env("HARNESS_COW_READY_HANDLE").and_then(|v| v.parse::<isize>().ok())
    else {
        return;
    };
    let handle = HANDLE(handle_value as *mut c_void);
    let buf = [1u8];
    unsafe {
        let _ = WriteFile(handle, Some(&buf), None, None);
        std::env::remove_var("HARNESS_COW_READY_HANDLE");
    }
}

/// `DllMain`が起動する内部初期化スレッド。設定は環境変数からしか取れない（`DllMain`は
/// 注入パラメータを受け取れない）ため`param=NULL`で試みる。ここで失敗しても確定はせず、
/// 後続の`harness_cow_init`（注入パラメータ付き）が再試行できる（BUG-045）。
pub(crate) unsafe extern "system" fn init_thread_proc(_param: *mut c_void) -> u32 {
    let _ = unsafe { ensure_init(std::ptr::null()) };
    0
}

/// Phase 4a: 親プロセス側の`hooked_create_process_w`が孫プロセスへ`CreateRemoteThread`で
/// 明示的に呼ぶエクスポート（`#[no_mangle]`必須、`GetProcAddress`で名前解決される）。
/// `DllMain`の内部初期化スレッドとの競合は[`ensure_init`]が吸収するため、呼び出し順は問わない——
/// この関数のリモートスレッドが終了した時点でフック設置の成否が確定していることだけが保証される
/// （`inject_grandchild`の同期点、モジュールdoc参照）。
///
/// `param`は注入側が`VirtualAllocEx`+`WriteProcessMemory`で書き込んだ設定ブロブ
/// （[`serialize_config_blob`]の形式、NULL可）。**戻り値は初期化の実際の成否**（成功=1・失敗=0）で、
/// 注入側は`GetExitCodeThread`でこれを読む。BUG-045のF1修正前は常に1を返しており、フック未設置でも
/// 注入成功と誤判定して警告台帳に何も残らなかった。
///
/// # Safety
/// `CreateRemoteThread`のスレッド開始関数として呼ばれる前提（`LPTHREAD_START_ROUTINE`互換
/// シグネチャ）。`param`は[`deserialize_config_blob`]の要件を満たすこと。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn harness_cow_init(param: *mut c_void) -> u32 {
    if unsafe { ensure_init(param as *const u8) } {
        1
    } else {
        0
    }
}

/// この DLL が**どのソースから作られたか**を示す刻印。`HRBUILDID:` + 64 桁の 16 進 + NUL。
///
/// 値は build script が `harness-build-id` に計算させたもので、**x64 と x86 で同じソースなら
/// 同じ値**になる（アーキテクチャを混ぜていない）。起動側（`harness-sandbox`）は 2 本の DLL の
/// ファイルを読んでこのマーカーを走査し、互いに、そして harness 本体に焼いた期待値と一致するかを
/// 見る。一致しなければ CoW セッションを起こさない。
///
/// **PE を解析せずバイト走査で拾える形**にしてあるのは、照合側が x64 と x86 の両方を同じ
/// コードで扱えるようにするため（エクスポートテーブルの構造は 32/64 で違う）。
const BUILD_ID_BLOB: &str = concat!("HRBUILDID:", env!("HARNESS_REDIRECTOR_BUILD_ID"), "\0");

/// [`BUILD_ID_BLOB`] を**エクスポート関数から参照させる**ためだけの関数。
///
/// 参照が無いと、定数はどこからも使われない文字列として最適化で消え得る。消えると走査側は
/// 「刻印が無い」と判断して fail-closed する——安全側ではあるが、正しくビルドした DLL が
/// 常に弾かれることになるので、ここで参照を固定しておく。
#[unsafe(no_mangle)]
pub extern "system" fn harness_cow_build_id() -> *const u8 {
    BUILD_ID_BLOB.as_ptr()
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
extern "system" fn DllMain(_hinst: HANDLE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        let _ = SELF_MODULE.set(_hinst.0 as usize);
        // Loader Lock回避（設計書§13.4）: `DllMain`内でフック設置を完結させず、専用スレッドへ
        // 委譲する。スレッド生成自体はLoader Lock下でも安全（`CreateThread`はローダを介さない）。
        unsafe {
            let _ = CreateThread(
                None,
                0,
                Some(init_thread_proc),
                None,
                THREAD_CREATION_FLAGS(0),
                None,
            );
        }
    }
    1
}
