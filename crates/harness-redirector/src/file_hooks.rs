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
pub(crate) fn retry_once_after_fault_in<F>(
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
    // 分岐は`NtOpenFile`と共有する（`open_route`のモジュールdoc）。ここは引数を詰めるだけ。
    let hook = CREATE_FILE_HOOK.get().expect("hook installed");
    let real = |oa: *const OBJECT_ATTRIBUTES| unsafe {
        hook.call(
            file_handle,
            desired_access,
            oa,
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
    let req = OpenRequest {
        desired_access: desired_access.0,
        create_disposition: Some(create_disposition.0),
        options: create_options.0,
    };
    unsafe {
        route_open(
            "hooked_nt_create_file",
            file_handle,
            object_attributes,
            req,
            &real,
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
    // `NtOpenFile`はcreate dispositionを取らない（常に`FILE_OPEN`相当）。分岐は`NtCreateFile`と
    // 共有する（`open_route`のモジュールdoc）。Windowsの削除・名前の変更はこちらを通る。
    let hook = OPEN_FILE_HOOK.get().expect("hook installed");
    let real = |oa: *const OBJECT_ATTRIBUTES| unsafe {
        hook.call(
            file_handle,
            desired_access,
            oa,
            io_status_block,
            share_access,
            open_options,
        )
    };
    let req = OpenRequest {
        desired_access,
        create_disposition: None,
        options: open_options,
    };
    unsafe {
        route_open(
            "hooked_nt_open_file",
            file_handle,
            object_attributes,
            req,
            &real,
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

/// 名前の変更1回の行き先（解決しただけで、まだ何もしていない）。
pub(crate) struct RenameTarget {
    old_rel: String,
    /// 移動先の台帳キー（workspace相対パス、`_ext`なら正規化済み絶対パス）。
    new_key: String,
    /// 移動先の、差分層の側の実体パス。本当の名前の変更はここへ向ける。
    diff_layer_new: PathBuf,
    /// 移動先の、ワークスペース（`_ext`なら実パス）の側のパス。差分層に無いとき、
    /// 移動先が論理的に在るかはこちらで決まる。
    counterpart: PathBuf,
}

/// 名前の変更の移動先を解決する（副作用なし）。`None`なら素通し。`RootDirectory`が非NULL
/// （ディレクトリハンドル相対）の場合も素通しにする（設計書§19.6、[`rename_target_path`]）。
unsafe fn resolve_rename_target(
    cfg: &Config,
    handle_key: isize,
    info_ptr: *const c_void,
) -> Option<RenameTarget> {
    let old_rel = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    let new_path = unsafe { rename_target_path(info_ptr) }?;
    let Classified {
        rel: new_rel,
        ledger_key: new_key,
        kind,
    } = classify_target(cfg, &new_path)?;
    // `DiffLayerAlias`でも`rel`は差分層ルートからの相対なので、`diff_layer_dir.join(&new_rel)`が
    // **移動先そのもの**（恒等）になる。ワークスペースの側は同じ相対パスをワークスペースへ当てたもの。
    let counterpart = match kind {
        TargetKind::DiffLayerAlias => cfg.workspace_root.join(&new_rel),
        TargetKind::Workspace | TargetKind::Ext => new_path,
    };
    Some(RenameTarget {
        old_rel,
        new_key,
        diff_layer_new: cfg.diff_layer_dir.join(&new_rel),
        counterpart,
    })
}

/// 名前の変更が既存の移動先を置き換えてよいか。**読む場所が情報クラスで違う**——
/// `FileRenameInformation`は1バイトの`BOOLEAN`で、残りの3バイトは呼び出し元の詰め物（値を持たない）。
/// `FileRenameInformationEx`は32bitのフラグ。
unsafe fn rename_replaces_existing(class: FILE_INFORMATION_CLASS, info_ptr: *const c_void) -> bool {
    let anonymous = unsafe { (*(info_ptr as *const FILE_RENAME_INFORMATION)).Anonymous };
    if class == FileRenameInformationEx {
        let flags = unsafe { anonymous.Flags };
        flags & FILE_RENAME_REPLACE_IF_EXISTS != 0
    } else {
        let replace = unsafe { anonymous.ReplaceIfExists };
        replace.0 != 0
    }
}

/// 名前の変更の移動先について、[`rename_refusal`]が必要な枝でだけ問い合わせる事実。
pub(crate) trait RenameTargetFacts {
    /// 差分層に移動先の実体が在るか。在れば、本当の呼び出しが自分で衝突・拒否を返す。
    fn in_diff_layer(&self) -> bool;
    /// ワークスペース（`_ext`なら実パス）の側に移動先が在るか。
    fn in_workspace(&self) -> bool;
    /// ワークスペースの側の移動先がディレクトリか（[`Self::in_workspace`]が真のときだけ問う）。
    fn workspace_is_dir(&self) -> bool;
    /// 移動先がこのセッションで論理削除されているか（兄弟プロセスの削除も取り込んだうえで）。
    fn is_deleted(&self) -> bool;
}

/// 名前の変更を、本当の呼び出しをする前に断るべきか。断るならその状態を返す
/// （[BUG-176](../../../docs/bugs/BUG-176.md)）。
///
/// 移動先は差分層へ書き換えてから本当の呼び出しをするので、差分層に何も無ければ本当の呼び出しは
/// 成功する——**ワークスペースに移動先が在って、論理的には「在る」のに**、である。以前はそのまま
/// 通しており、上書きを許さない名前の変更でもワークスペースのファイルを黙って置き換えていた
/// （台帳に`Modify`が残り、承認で本物が変わる）。本物のファイルシステムが返すものを返す:
///
/// | 移動先（差分層には無い） | 上書き不可 | 上書き可 |
/// |---|---|---|
/// | ワークスペースにファイル | 衝突 | 通す（置き換え） |
/// | ワークスペースにディレクトリ | 衝突 | **拒否**（ディレクトリはファイルで置き換えられない。NTFSで実測） |
/// | 論理削除済み・どこにも無い | 通す | 通す |
pub(crate) fn rename_refusal(
    replace_if_exists: bool,
    facts: &impl RenameTargetFacts,
) -> Option<NTSTATUS> {
    if facts.in_diff_layer() || !facts.in_workspace() || facts.is_deleted() {
        return None;
    }
    if !replace_if_exists {
        return Some(STATUS_OBJECT_NAME_COLLISION);
    }
    facts.workspace_is_dir().then_some(STATUS_ACCESS_DENIED)
}

/// 実際のファイルシステムと台帳から事実を引く[`RenameTargetFacts`]。
struct LiveRenameFacts<'a> {
    cfg: &'a Config,
    target: &'a RenameTarget,
}

impl RenameTargetFacts for LiveRenameFacts<'_> {
    fn in_diff_layer(&self) -> bool {
        self.target.diff_layer_new.exists()
    }

    fn in_workspace(&self) -> bool {
        self.target.counterpart.exists()
    }

    fn workspace_is_dir(&self) -> bool {
        self.target.counterpart.is_dir()
    }

    fn is_deleted(&self) -> bool {
        is_deleted_after_refresh(self.cfg, &self.target.new_key)
    }
}

/// 解決した移動先を差分層へ向けたバッファを作り、台帳へ旧パスの`Delete`と新パスの
/// `Create`/`Modify`を1件ずつ書く**予定**を作る（設計書§19.4/§19.6）。
///
/// **台帳へはここで書かない**（BUG-171）。移動先が既にある・共有違反などで本当の変更は
/// 失敗し得るので、書くのは呼び出し側が結果を見た後である。先に書いていた頃は、失敗した
/// 変更の元ファイルが台帳の上で削除済みになり、セッションの中から見えなくなって、
/// `apply`が本物を消しに行った。
unsafe fn rewrite_rename_target(
    cfg: &Config,
    handle_key: isize,
    target: RenameTarget,
    info_ptr: *const c_void,
) -> (Vec<u8>, usize, PendingRename) {
    prepare_diff_layer_parent(&target.counterpart, &target.diff_layer_new);
    let anonymous = unsafe { (*(info_ptr as *const FILE_RENAME_INFORMATION)).Anonymous };
    let (buf, len) = build_rename_info_buffer(anonymous, &target.diff_layer_new);
    let pending = PendingRename {
        handle_key,
        old: PendingRecord::delete(cfg, &target.old_rel),
        new: PendingRecord::rename_target(cfg, &target.new_key),
        new_rel_str: target.new_key,
    };
    (buf, len, pending)
}

/// 本当の`NtSetInformationFile`を、情報のバッファと長さだけを差し替えて呼ぶ手順。
pub(crate) type RealSetInfo<'a> = &'a dyn Fn(*const c_void, u32) -> NTSTATUS;

/// 名前の変更1回を、移動先を差分層へ向けて実行する。`None`は素通し（呼び出し側が元の引数のまま
/// 本当の呼び出しをする）。`real`は元の関数を呼ぶ手順で、試験では偽物を渡す。
///
/// # Safety
/// `info_ptr`は`class`の形の`FILE_RENAME_INFORMATION`を指していること。
pub(crate) unsafe fn route_rename(
    cfg: &Config,
    handle_key: isize,
    info_ptr: *const c_void,
    class: FILE_INFORMATION_CLASS,
    real: RealSetInfo<'_>,
) -> Option<NTSTATUS> {
    let target = unsafe { resolve_rename_target(cfg, handle_key, info_ptr) }?;
    let replace_if_exists = unsafe { rename_replaces_existing(class, info_ptr) };
    if let Some(refused) = rename_refusal(
        replace_if_exists,
        &LiveRenameFacts {
            cfg,
            target: &target,
        },
    ) {
        // 本当の呼び出しはしない。何も動いていないので、台帳にも何も書かない。
        return Some(refused);
    }
    let (buf, len, pending) = unsafe { rewrite_rename_target(cfg, handle_key, target, info_ptr) };
    let status = real(buf.as_ptr() as *const c_void, len as u32);
    // BUG-171: 台帳へ書くのは本当の変更が成功した後（再入防止ガードの内側で）。
    pending.settle(cfg, status.is_ok());
    Some(status)
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
                let hook = SET_INFO_HOOK.get().expect("hook installed");
                let real = |info: *const c_void, len: u32| unsafe {
                    hook.call(
                        file_handle,
                        io_status_block,
                        info,
                        len,
                        file_information_class,
                    )
                };
                if let Some(status) = unsafe {
                    route_rename(
                        cfg,
                        handle_key,
                        file_information,
                        file_information_class,
                        &real,
                    )
                } {
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
                // 差分層にだけ在るディレクトリも同じ（BUG-177、`attribute_query_target`）。
                if let Some(diff_layer_path) = attribute_query_target(cfg, &rel) {
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
                // read-through（`hooked_nt_query_full_attributes_file`と同じ理由・同じ関数）。
                if let Some(diff_layer_path) = attribute_query_target(cfg, &rel) {
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

#[cfg(test)]
#[path = "file_hooks_tests.rs"]
mod tests;
