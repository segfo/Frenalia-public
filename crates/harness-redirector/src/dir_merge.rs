//! ディレクトリ列挙のマージ（`NtQueryDirectoryFile`/`NtQueryDirectoryFileEx`）。
//!
//! workspace側とupper_dir側の両方を列挙して1つの結果に見せる。upper側で上書きされた
//! エントリはupper側を優先し、論理削除されたエントリは除外する。BUG-047（セッション中に
//! 新規作成したファイルが`Remove-Item`から見えない）の修正がこの経路。

use super::*;

// BUG-047: ディレクトリ列挙のマージ・マーシャルロジック（フックにもDLL注入にも依存しない
// 純粋関数のみを持つ、`tempfile::tempdir()`だけで単体テスト可能——設計書§7.8「Workspaceと
// Sandboxのディレクトリ列挙をマージして返す」の実装）。

use windows::Wdk::Storage::FileSystem::{
    FileBothDirectoryInformation, FileDirectoryInformation, FileFullDirectoryInformation,
    FileIdBothDirectoryInformation, FileIdFullDirectoryInformation, FileNamesInformation,
    FILE_BOTH_DIR_INFORMATION, FILE_DIRECTORY_INFORMATION, FILE_FULL_DIR_INFORMATION,
    FILE_ID_BOTH_DIR_INFORMATION, FILE_ID_FULL_DIR_INFORMATION, FILE_NAMES_INFORMATION,
};

/// このフックがマージ対象として自前で構築する`FileInformationClass`か（Stage 0の決定）。
/// それ以外（`FileIdExtdDirectoryInformation`等の稀なクラス）は素通しする——このフックは
/// ACL境界ではなく可視性の利便機能であり（`docs/SECURITY-PRINCIPLES.md` P-02）、
/// 対応漏れは修正前の（見えない）挙動に戻るだけで安全側。
pub(super) fn is_supported_class(class: FILE_INFORMATION_CLASS) -> bool {
    matches!(
        class,
        c if c == FileDirectoryInformation
            || c == FileFullDirectoryInformation
            || c == FileBothDirectoryInformation
            || c == FileNamesInformation
            || c == FileIdBothDirectoryInformation
            || c == FileIdFullDirectoryInformation
    )
}

/// base（実workspace/`_ext`実体）側とupper（CoW）側のディレクトリ実体1件分のメタデータ。
#[derive(Clone)]
pub(super) struct MergedEntry {
    pub name: Vec<u16>,
    pub file_attributes: u32,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub end_of_file: i64,
    pub allocation_size: i64,
}

pub(crate) fn read_entries(dir: &Path) -> HashMap<String, std::fs::Metadata> {
    let mut out = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            out.insert(name, meta);
        }
    }
    out
}

pub(crate) fn to_merged_entry(name: &str, meta: &std::fs::Metadata) -> MergedEntry {
    use std::os::windows::fs::MetadataExt as _;
    let end_of_file = meta.len() as i64;
    // NTFSクラスタサイズ相当（4096バイト）へ切り上げる近似値。実クラスタサイズは
    // ボリューム依存だが、このフィールドを厳密参照する呼び出し元は稀なため簡略化する。
    let allocation_size = (end_of_file + 4095) / 4096 * 4096;
    MergedEntry {
        name: name.encode_utf16().collect(),
        file_attributes: meta.file_attributes(),
        creation_time: meta.creation_time() as i64,
        last_access_time: meta.last_access_time() as i64,
        last_write_time: meta.last_write_time() as i64,
        change_time: meta.last_write_time() as i64,
        end_of_file,
        allocation_size,
    }
}

/// `rel_prefix`（`/`区切りのworkspace相対、ルート自身なら空文字列）配下の1階層について、
/// upper側とbase側をマージした一覧を、設計書§7.8の優先順位
/// （1. whiteout済みは除外 2. upper優先 3. 同名upperが無いbaseのみ採用）で返す。
/// 名前の大小無視での重複排除・昇順ソート済み（呼び出し元の複数回呼び出しをまたぐカーソルが
/// 安定した順序を前提にできるようにするため）。
pub(super) fn merge_dir_entries(
    base_dir: &Path,
    upper_dir: &Path,
    deleted: &HashSet<String>,
    rel_prefix: &str,
) -> Vec<MergedEntry> {
    let upper_entries = read_entries(upper_dir);
    let base_entries = read_entries(base_dir);
    let mut seen_lc: HashSet<String> = HashSet::new();
    let mut merged: Vec<(String, std::fs::Metadata)> = Vec::new();

    let child_rel = |name: &str| -> String {
        if rel_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{rel_prefix}/{name}")
        }
    };

    for (name, meta) in upper_entries {
        if deleted.contains(&child_rel(&name)) {
            continue;
        }
        seen_lc.insert(name.to_ascii_lowercase());
        merged.push((name, meta));
    }
    for (name, meta) in base_entries {
        let lc = name.to_ascii_lowercase();
        if seen_lc.contains(&lc) || deleted.contains(&child_rel(&name)) {
            continue;
        }
        seen_lc.insert(lc);
        merged.push((name, meta));
    }
    merged.sort_by_key(|a| a.0.to_ascii_lowercase());
    merged
        .iter()
        .map(|(name, meta)| to_merged_entry(name, meta))
        .collect()
}

/// DOSワイルドカード（`*`＝任意長・`?`＝任意1文字）の簡易大小無視マッチ。`NtQueryDirectoryFile`
/// の`FileName`引数（例: `Get-ChildItem -Filter *.txt`）に対応するための簡略実装——短縮名
/// （8.3形式）の特殊扱い等、DOSワイルドカードの厳密な歴史的仕様までは再現しない
/// （既知の簡略化、Stage 0で観測された実クエリが`*`単体のみだった場合はこの関数自体使われない）。
pub(super) fn wildcard_match(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    fn helper(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => helper(&p[1..], n) || (!n.is_empty() && helper(p, &n[1..])),
            (Some(b'?'), Some(_)) => helper(&p[1..], &n[1..]),
            (Some(pc), Some(nc)) if pc.eq_ignore_ascii_case(nc) => helper(&p[1..], &n[1..]),
            _ => false,
        }
    }
    helper(pattern.as_bytes(), name.as_bytes())
}

pub(crate) fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// 1エントリぶんの可変長レコードをバッファへ書き込む。`header_offset`は
/// `std::mem::offset_of!(T, FileName)`、`write_header`はNextEntryOffset/FileNameLength以外の
/// 固定長フィールドを埋めるクロージャ。戻り値は書き込んだバイト数（8バイト境界に切り上げ済み、
/// 実際に確保する領域はこのバイト数——NTの規約でレコード間に`NextEntryOffset`分のパディングが
/// 入り得るため、次のレコードもこのアライメントを前提にしてよい）。
pub(crate) fn write_record(
    buf: &mut [u8],
    cursor: usize,
    header_offset: usize,
    entry: &MergedEntry,
    write_header: impl FnOnce(*mut u8),
) -> Option<usize> {
    let name_bytes_len = entry.name.len() * 2;
    let record_len = align8(header_offset + name_bytes_len);
    if cursor + record_len > buf.len() {
        return None;
    }
    let ptr = buf[cursor..].as_mut_ptr();
    // ゼロ初期化してから固定長ヘッダ・可変長ファイル名を書く（未使用のパディング部分に
    // 前回の呼び出しの残骸が残らないようにする）。
    unsafe { std::ptr::write_bytes(ptr, 0, record_len) };
    write_header(ptr);
    let name_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(entry.name.as_ptr() as *const u8, name_bytes_len) };
    buf[cursor + header_offset..cursor + header_offset + name_bytes_len]
        .copy_from_slice(name_bytes);
    Some(record_len)
}

/// `merged[start..]`から、`class`の型でバッファへ入るだけレコードを書き込む。
/// `return_single_entry`なら最大1件。戻り値は`(書き込んだバイト数, 消費したエントリ数)`。
/// 全件書ける場合と一部しか書けない場合の両方に対応し、後者でも部分的な書き込み結果を
/// 呼び出し元がそのまま`STATUS_SUCCESS`として返せるようにする（NT既定の挙動——
/// `STATUS_BUFFER_OVERFLOW`は「1件も書けなかった」場合専用）。
pub(super) fn marshal_entries(
    buf: &mut [u8],
    class: FILE_INFORMATION_CLASS,
    merged: &[MergedEntry],
    start: usize,
    return_single_entry: bool,
) -> (usize, usize) {
    let mut cursor = 0usize;
    let mut consumed = 0usize;
    let mut last_record_start: Option<usize> = None;
    for entry in &merged[start..] {
        let header_offset = if class == FileDirectoryInformation {
            std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileName)
        } else if class == FileFullDirectoryInformation {
            std::mem::offset_of!(FILE_FULL_DIR_INFORMATION, FileName)
        } else if class == FileBothDirectoryInformation {
            std::mem::offset_of!(FILE_BOTH_DIR_INFORMATION, FileName)
        } else if class == FileNamesInformation {
            std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName)
        } else if class == FileIdBothDirectoryInformation {
            std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName)
        } else {
            // FileIdFullDirectoryInformation（is_supported_classで既に絞り込み済み）。
            std::mem::offset_of!(FILE_ID_FULL_DIR_INFORMATION, FileName)
        };
        let write_header = |ptr: *mut u8| unsafe {
            if class == FileDirectoryInformation {
                let h = ptr as *mut FILE_DIRECTORY_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).CreationTime = entry.creation_time;
                (*h).LastAccessTime = entry.last_access_time;
                (*h).LastWriteTime = entry.last_write_time;
                (*h).ChangeTime = entry.change_time;
                (*h).EndOfFile = entry.end_of_file;
                (*h).AllocationSize = entry.allocation_size;
                (*h).FileAttributes = entry.file_attributes;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
            } else if class == FileFullDirectoryInformation {
                let h = ptr as *mut FILE_FULL_DIR_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).CreationTime = entry.creation_time;
                (*h).LastAccessTime = entry.last_access_time;
                (*h).LastWriteTime = entry.last_write_time;
                (*h).ChangeTime = entry.change_time;
                (*h).EndOfFile = entry.end_of_file;
                (*h).AllocationSize = entry.allocation_size;
                (*h).FileAttributes = entry.file_attributes;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
                (*h).EaSize = 0;
            } else if class == FileBothDirectoryInformation {
                let h = ptr as *mut FILE_BOTH_DIR_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).CreationTime = entry.creation_time;
                (*h).LastAccessTime = entry.last_access_time;
                (*h).LastWriteTime = entry.last_write_time;
                (*h).ChangeTime = entry.change_time;
                (*h).EndOfFile = entry.end_of_file;
                (*h).AllocationSize = entry.allocation_size;
                (*h).FileAttributes = entry.file_attributes;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
                (*h).EaSize = 0;
                (*h).ShortNameLength = 0;
            } else if class == FileNamesInformation {
                let h = ptr as *mut FILE_NAMES_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
            } else if class == FileIdBothDirectoryInformation {
                let h = ptr as *mut FILE_ID_BOTH_DIR_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).CreationTime = entry.creation_time;
                (*h).LastAccessTime = entry.last_access_time;
                (*h).LastWriteTime = entry.last_write_time;
                (*h).ChangeTime = entry.change_time;
                (*h).EndOfFile = entry.end_of_file;
                (*h).AllocationSize = entry.allocation_size;
                (*h).FileAttributes = entry.file_attributes;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
                (*h).EaSize = 0;
                (*h).ShortNameLength = 0;
                (*h).FileId = 0;
            } else {
                let h = ptr as *mut FILE_ID_FULL_DIR_INFORMATION;
                (*h).FileIndex = consumed as u32;
                (*h).CreationTime = entry.creation_time;
                (*h).LastAccessTime = entry.last_access_time;
                (*h).LastWriteTime = entry.last_write_time;
                (*h).ChangeTime = entry.change_time;
                (*h).EndOfFile = entry.end_of_file;
                (*h).AllocationSize = entry.allocation_size;
                (*h).FileAttributes = entry.file_attributes;
                (*h).FileNameLength = (entry.name.len() * 2) as u32;
                (*h).EaSize = 0;
                (*h).FileId = 0;
            }
        };
        let Some(record_len) = write_record(buf, cursor, header_offset, entry, write_header) else {
            break;
        };
        // 直前のレコードのNextEntryOffsetを、いま書いたレコードの開始位置へ設定する
        // （末尾レコードは0のまま——ゼロ初期化済みバッファ、または後段でリセットする）。
        if let Some(prev_start) = last_record_start {
            let prev_header_offset = header_offset; // 同一class内では固定
            let _ = prev_header_offset;
            let prev_ptr = buf[prev_start..].as_mut_ptr() as *mut u32;
            unsafe { *prev_ptr = (cursor - prev_start) as u32 };
        }
        last_record_start = Some(cursor);
        cursor += record_len;
        consumed += 1;
        if return_single_entry {
            break;
        }
    }
    (cursor, consumed)
}

/// `NtQueryDirectoryFile`/`NtQueryDirectoryFileEx`（BUG-047/BUG-048）共通のマージ・
/// マーシャル本体。`handle_paths()`でトラック済みのディレクトリハンドルに対してのみ、
/// upper/base両方をマージした列挙結果を自前で構築して返す（`Some(status)`）。それ以外
/// （未トラックのハンドル・非対応`FileInformationClass`）は`None`を返し、呼び出し元が
/// 元の関数へ完全に素通しする。
///
/// BUG-048（F3）: `FindFirstFileEx`系（.NETの`Directory.EnumerateFileSystemEntries`が
/// 実際に使う経路を含む）はWindows 10 1709以降`ntdll!NtQueryDirectoryFile`ではなく
/// **`NtQueryDirectoryFileEx`**を叩く（本機のntdllで両exportの存在を確認済み）。
/// BUG-047はマージ実装自体は正しかったが`NtQueryDirectoryFile`しかフックしていなかったため、
/// 実運用の列挙経路の多くを素通りしていた（マージが効いていないように見えるバグとして
/// 再発した）。
#[allow(clippy::too_many_arguments)] // NtQueryDirectoryFile(Ex)両方の引数を素通しする性質上、削れない。
pub(crate) unsafe fn try_merged_dir_query(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
    restart_scan: bool,
) -> Option<NTSTATUS> {
    let _guard = ReentryGuard::try_acquire()?;
    let cfg = CONFIG.get()?;
    let handle_key = file_handle.0 as isize;
    let rel_str = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    if !dir_merge::is_supported_class(file_information_class) {
        return None;
    }
    let (base_dir, upper_dir, rel_prefix) = dir_query_roots(cfg, &rel_str)?;
    refresh_deleted_set(cfg);
    let deleted = deleted_paths_state().lock().unwrap().clone();
    let merged = dir_merge::merge_dir_entries(&base_dir, &upper_dir, &deleted, &rel_prefix);
    let pattern = unsafe { filename_filter_string(file_name) };
    let merged: Vec<dir_merge::MergedEntry> = if pattern.is_empty() {
        merged
    } else {
        merged
            .into_iter()
            .filter(|e| dir_merge::wildcard_match(&pattern, &String::from_utf16_lossy(&e.name)))
            .collect()
    };
    let mut cursors = dir_query_cursor().lock().unwrap();
    let start = if restart_scan {
        0
    } else {
        *cursors.get(&handle_key).unwrap_or(&0)
    };
    if start >= merged.len() {
        unsafe {
            (*io_status_block).Anonymous.Status = STATUS_NO_MORE_FILES;
            (*io_status_block).Information = 0;
        }
        return Some(STATUS_NO_MORE_FILES);
    }
    let buf_len = length as usize;
    let out_buf = unsafe { std::slice::from_raw_parts_mut(file_information as *mut u8, buf_len) };
    let (bytes_written, consumed) = dir_merge::marshal_entries(
        out_buf,
        file_information_class,
        &merged,
        start,
        return_single_entry,
    );
    if consumed == 0 {
        // 先頭1件すら入らないバッファ長（NT既定の「バッファ不足」応答）。
        return Some(STATUS_BUFFER_OVERFLOW);
    }
    cursors.insert(handle_key, start + consumed);
    drop(cursors);
    unsafe {
        (*io_status_block).Anonymous.Status = NTSTATUS(0);
        (*io_status_block).Information = bytes_written;
    }
    Some(NTSTATUS(0))
}

pub(crate) unsafe extern "system" fn hooked_nt_query_directory_file(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: windows::Win32::System::IO::PIO_APC_ROUTINE,
    apc_context: *const c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    return_single_entry: windows::Win32::Foundation::BOOLEAN,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
    restart_scan: windows::Win32::Foundation::BOOLEAN,
) -> NTSTATUS {
    if let Some(status) = unsafe {
        try_merged_dir_query(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry.as_bool(),
            file_name,
            restart_scan.as_bool(),
        )
    } {
        return status;
    }
    let hook = QUERY_DIR_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            return_single_entry,
            file_name,
            restart_scan,
        )
    }
}

/// `NtQueryDirectoryFileEx`用の`QueryFlags`ビット（phnt由来、`windows`クレートは未エクスポート）。
pub(crate) const SL_RESTART_SCAN: u32 = 0x0000_0001;
pub(crate) const SL_RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;

pub(crate) unsafe extern "system" fn hooked_nt_query_directory_file_ex(
    file_handle: HANDLE,
    event: HANDLE,
    apc_routine: windows::Win32::System::IO::PIO_APC_ROUTINE,
    apc_context: *const c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: FILE_INFORMATION_CLASS,
    query_flags: u32,
    file_name: *const windows::Win32::Foundation::UNICODE_STRING,
) -> NTSTATUS {
    if let Some(status) = unsafe {
        try_merged_dir_query(
            file_handle,
            io_status_block,
            file_information,
            length,
            file_information_class,
            query_flags & SL_RETURN_SINGLE_ENTRY != 0,
            file_name,
            query_flags & SL_RESTART_SCAN != 0,
        )
    } {
        return status;
    }
    let hook = QUERY_DIR_EX_HOOK.get().expect("hook installed");
    unsafe {
        hook.call(
            file_handle,
            event,
            apc_routine,
            apc_context,
            io_status_block,
            file_information,
            length,
            file_information_class,
            query_flags,
            file_name,
        )
    }
}

/// `handle_key`（`handle_paths()`のディレクトリハンドル用エントリ、`Classified.ledger_key`）から
/// `(base_dir実体パス, upper_dir実体パス, whiteout集合キーのprefix)`を求める。`baseline_hash_for`
/// と同じく、絶対パスなら`_ext`capture root、そうでなければworkspace相対として扱う
/// （設計書§19.8、Stage 2）。ディレクトリ自体が両側どちらにも存在しない場合は`None`
/// （通常起き得ないが、フックの再入・競合等の異常系での安全側フォールバック用）。
pub(crate) fn dir_query_roots(cfg: &Config, rel_str: &str) -> Option<(PathBuf, PathBuf, String)> {
    if Path::new(rel_str).is_absolute() {
        let key = store::ext_key(rel_str).ok()?;
        let upper_dir = cfg.upper_dir.join("_ext").join(&key);
        Some((
            PathBuf::from(rel_str),
            upper_dir,
            rel_str.replace('\\', "/"),
        ))
    } else {
        let base_dir = cfg.workspace_root.join(rel_str);
        let upper_dir = cfg.upper_dir.join(rel_str);
        Some((base_dir, upper_dir, rel_str.to_string()))
    }
}

/// `NtQueryDirectoryFile`の`FileName`（ワイルドカードフィルタ、任意）引数をRustの`String`へ。
/// NULLまたは空なら「フィルタ無し」を表す空文字列を返す（`dir_merge::wildcard_match`は
/// 空パターンを常に一致として扱う）。
pub(crate) unsafe fn filename_filter_string(
    us: *const windows::Win32::Foundation::UNICODE_STRING,
) -> String {
    if us.is_null() {
        return String::new();
    }
    let us = unsafe { &*us };
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    let len_u16 = (us.Length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) };
    String::from_utf16_lossy(slice)
}

/// 孫プロセスへ再注入が失敗した/未完了だった場合の警告を`.harness-cow-warnings.jsonl`へ
/// 追記する（Q6）。孫の書込みが透過されないことを示すだけで、生成自体は拒否しない。
pub(crate) fn append_warning_entry(cfg: &Config, message: &str) {
    append_warning_kind(cfg, "grandchild_injection_incomplete", message);
}

/// `kind`を指定して警告台帳へ1行追記する（`append_warning_entry`の一般化）。
///
/// 透過性が失われる事象は**必ずここへ痕跡を残す**こと。BUG-066のセッションでは、
/// workspace内への書込が1件もリダイレクトされないまま全てACL拒否されていたのに、
/// なぜそうなったのかを示す記録がどこにも無かった（releaseビルドでは`debug_log`が
/// 定数畳み込みで消えるため、後から追う手段が残らない）。
pub(crate) fn append_warning_kind(cfg: &Config, kind: &str, message: &str) {
    let entry = CowWarningEntry {
        kind,
        message,
        ts_unix_millis: now_millis(),
    };
    if let Ok(mut line) = serde_json::to_string(&entry) {
        line.push('\n');
        let path = cfg.upper_dir.join(COW_WARNINGS_LEDGER_FILENAME);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}
