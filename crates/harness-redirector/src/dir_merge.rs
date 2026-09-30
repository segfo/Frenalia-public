//! ディレクトリ列挙のマージ（`NtQueryDirectoryFile`/`NtQueryDirectoryFileEx`）。
//!
//! workspace側とdiff_layer_dir側の両方を列挙して1つの結果に見せる。差分層側で上書きされた
//! エントリは差分層側を優先し、論理削除されたエントリは除外する。BUG-047（セッション中に
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

/// 本体層（実workspace/`_ext`実体）側と差分層（CoW）側のディレクトリ実体1件分のメタデータ。
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
/// 差分層側と本体層側をマージした一覧を、設計書§7.8の優先順位
/// （1. whiteout済みは除外 2. 差分層優先 3. 同名差分層が無い本体層のみ採用）で返す。
/// 名前の大小無視での重複排除・昇順ソート済み（呼び出し元の複数回呼び出しをまたぐカーソルが
/// 安定した順序を前提にできるようにするため）。
pub(super) fn merge_dir_entries(
    base_layer_dir: &Path,
    diff_layer_dir: &Path,
    deleted: &HashSet<String>,
    rel_prefix: &str,
) -> Vec<MergedEntry> {
    let diff_layer_entries = read_entries(diff_layer_dir);
    let base_layer_entries = read_entries(base_layer_dir);
    let mut seen_lc: HashSet<String> = HashSet::new();
    let mut merged: Vec<(String, std::fs::Metadata)> = Vec::new();

    let child_rel = |name: &str| -> String {
        if rel_prefix.is_empty() {
            name.to_string()
        } else {
            format!("{rel_prefix}/{name}")
        }
    };

    for (name, meta) in diff_layer_entries {
        // 帳簿と外の置き場は差分層の根にしか無い（`rel_prefix`が空＝ワークスペースの根を一覧している）。
        if rel_prefix.is_empty() && is_diff_layer_bookkeeping(&name) {
            continue;
        }
        if deleted.contains(&child_rel(&name)) {
            continue;
        }
        seen_lc.insert(name.to_ascii_lowercase());
        merged.push((name, meta));
    }
    for (name, meta) in base_layer_entries {
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

/// 差分層の根に置かれるCoW自身の帳簿と、ワークスペース外への変更の置き場（`_ext`）か（BUG-181）。
///
/// どちらもワークスペースの中身ではないので、ワークスペースの根の一覧に見せない。帳簿の判定は
/// 変更一覧の走査（`store::scan_diff_layer_content_files`）と同じ規則
/// （[`harness_change_ledger::COW_METADATA_PREFIX`]）を使う——名前の一覧をもう1つ作らない。
///
/// **限界**: `_ext`はこの接頭辞の規則に従っていない名前なので、ワークスペースの根に`_ext`という
/// ディレクトリを新しく作ると、それも一覧から隠れる（差分層の同じ場所を外の置き場と共有しているため。
/// 名前の衝突そのものは`docs/STATUS.md`の残課題が持つ）。
pub(super) fn is_diff_layer_bookkeeping(name: &str) -> bool {
    name.starts_with(harness_change_ledger::COW_METADATA_PREFIX) || name.eq_ignore_ascii_case("_ext")
}

/// `NtQueryDirectoryFile(Ex)`の`FileName`（絞り込みの式）に名前が一致するか（BUG-181）。
///
/// **照合はOS自身の`RtlIsNameInExpression`に任せる。** Win32（`FindFirstFileEx`）は`*.txt`を
/// `<.txt`、`a?c`を`a>c`、`x.*`を`x"*`のようにDOS用の記号へ書き換えてからNTへ渡す
/// （実測は`plans/mac-spike/RESULTS.md` §S78）。`*`と`?`しか知らない照合では`<`が入った時点で
/// 1件も一致しなかった。ファイルシステムと同じ関数を呼べば、記号の意味を自前で写し取らずに済む。
///
/// `filter`は[`upcase_filter`]で大文字化済みであること（`IgnoreCase`を立てて呼ぶときの約束）。
pub(super) fn name_matches_filter(filter: &[u16], name: &[u16]) -> bool {
    match rtl_is_name_in_expression() {
        Some(is_name_in_expression) => {
            let expression = unicode_string_of(filter);
            let name = unicode_string_of(name);
            unsafe {
                is_name_in_expression(
                    &expression,
                    &name,
                    windows::Win32::Foundation::BOOLEAN(1),
                    std::ptr::null(),
                )
            }
            .as_bool()
        }
        // ntdllが必ず持つ関数なので通常は来ない。来たら`*`と`?`だけの照合へ落とす
        // （DOS用の記号は近い意味へ読み替える。境界の周りでは完全には一致しない）。
        None => wildcard_match(
            &String::from_utf16_lossy(filter)
                .replace('<', "*")
                .replace('>', "?")
                .replace('"', "."),
            &String::from_utf16_lossy(name),
        ),
    }
}

/// 絞り込みの式を大文字化する。大文字化はOSの表（`RtlUpcaseUnicodeChar`）で行う——
/// ファイルシステムの大小無視と同じ意味にするため。
pub(super) fn upcase_filter(units: &[u16]) -> Vec<u16> {
    units
        .iter()
        .map(|&c| unsafe { windows::Wdk::System::SystemServices::RtlUpcaseUnicodeChar(c) })
        .collect()
}

type RtlIsNameInExpressionFn = unsafe extern "system" fn(
    *const windows::Win32::Foundation::UNICODE_STRING,
    *const windows::Win32::Foundation::UNICODE_STRING,
    windows::Win32::Foundation::BOOLEAN,
    *const u16,
) -> windows::Win32::Foundation::BOOLEAN;

/// `ntdll!RtlIsNameInExpression`（`windows`クレートは出していない）。1度だけ引いて覚える。
fn rtl_is_name_in_expression() -> Option<RtlIsNameInExpressionFn> {
    static ADDR: OnceLock<Option<usize>> = OnceLock::new();
    let addr = (*ADDR.get_or_init(|| {
        unsafe { crate::init::resolve_ntdll_export("RtlIsNameInExpression") }.map(|p| p as usize)
    }))?;
    Some(unsafe { std::mem::transmute::<usize, RtlIsNameInExpressionFn>(addr) })
}

/// 借りた`u16`の並びを、読むだけの`UNICODE_STRING`として渡す（名前も式も短いので長さは切り詰めで足りる）。
fn unicode_string_of(units: &[u16]) -> windows::Win32::Foundation::UNICODE_STRING {
    let bytes = (units.len() * 2).min(u16::MAX as usize & !1) as u16;
    windows::Win32::Foundation::UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: windows::core::PWSTR(units.as_ptr() as *mut u16),
    }
}

/// 今回の問い合わせで使う位置と絞り込みを決める（BUG-181）。Windowsの約束に合わせる——
/// 絞り込みの名前は、そのハンドルで最初の問い合わせと、最初からやり直す問い合わせでだけ受け取る
/// （続きの問い合わせでは`FileName`がNULLで届くことを実測した。§S78）。
///
/// | 前の状態 | やり直すか | 使う位置 | 使う絞り込み |
/// |---|---|---|---|
/// | 無い（最初の問い合わせ） | どちらでも | 0 | 渡されたもの（無ければ絞らない） |
/// | 在る | やり直す | 0 | 渡されていればそれ、無ければ前のもの |
/// | 在る | 続き | 前の位置 | 前のもの（渡された`FileName`は見ない） |
pub(super) fn next_query_state(
    previous: Option<&DirQueryState>,
    requested: Option<Vec<u16>>,
    restart_scan: bool,
) -> DirQueryState {
    match previous {
        None => DirQueryState {
            next: 0,
            filter: requested,
        },
        Some(prev) if restart_scan => DirQueryState {
            next: 0,
            filter: requested.or_else(|| prev.filter.clone()),
        },
        Some(prev) => prev.clone(),
    }
}

/// 1回の問い合わせへの答え（状態・書いたバイト数・次に覚えておく状態）。
pub(super) struct DirQueryAnswer {
    pub status: NTSTATUS,
    pub bytes_written: usize,
    pub state: DirQueryState,
}

/// 絞り込む前のマージ済み一覧`merged`から、1回の問い合わせへの答えを組む（BUG-181）。
/// フックの本体（[`try_merged_dir_query`]）は、グローバルな設定とハンドルの表を引いてからこれを呼ぶ。
pub(super) fn answer_dir_query(
    merged: Vec<MergedEntry>,
    previous: Option<&DirQueryState>,
    requested: Option<Vec<u16>>,
    restart_scan: bool,
    class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    out_buf: &mut [u8],
) -> DirQueryAnswer {
    let first_query = previous.is_none() || restart_scan;
    let state = next_query_state(previous, requested, restart_scan);
    let visible: Vec<MergedEntry> = match &state.filter {
        None => merged,
        Some(filter) => merged
            .into_iter()
            .filter(|e| name_matches_filter(filter, &e.name))
            .collect(),
    };
    if state.next >= visible.len() {
        // 本物のファイルシステムは、絞り込みに1件も当たらなければ最初の問い合わせで
        // 「該当するファイルが無い」を返し、「もう無い」は読み終えた後にだけ返す（§S78で実測）。
        let status = if first_query && visible.is_empty() && state.filter.is_some() {
            STATUS_NO_SUCH_FILE
        } else {
            STATUS_NO_MORE_FILES
        };
        return DirQueryAnswer {
            status,
            bytes_written: 0,
            state,
        };
    }
    let (bytes_written, consumed) =
        marshal_entries(out_buf, class, &visible, state.next, return_single_entry);
    if consumed == 0 {
        // 先頭1件すら入らないバッファ長（NT既定の「バッファ不足」応答）。位置は進めないが、
        // 絞り込みは覚える——大きいバッファで撃ち直す続きの問い合わせは`FileName`を渡さない。
        return DirQueryAnswer {
            status: STATUS_BUFFER_OVERFLOW,
            bytes_written: 0,
            state,
        };
    }
    DirQueryAnswer {
        status: NTSTATUS(0),
        bytes_written,
        state: DirQueryState {
            next: state.next + consumed,
            filter: state.filter,
        },
    }
}

/// `*`＝任意長・`?`＝任意1文字だけを知る簡易な大小無視の照合。`RtlIsNameInExpression`を
/// 引けないときの予備としてだけ使う（[`name_matches_filter`]）。
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
/// 差分層/本体層の両方をマージした列挙結果を自前で構築して返す（`Some(status)`）。それ以外
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
    // [D-88] ディレクトリのマージはCoW専用（差分層と本体層の2つを重ねて見せる処理）。
    // DirectRwのlazyレーンには重ねる相手が無いので、素通しする。
    let cfg = CONFIG.get().filter(|cfg| cfg.cow_enabled)?;
    let handle_key = file_handle.0 as isize;
    let rel_str = handle_paths().lock().unwrap().get(&handle_key).cloned()?;
    if !dir_merge::is_supported_class(file_information_class) {
        return None;
    }
    let (base_layer_dir, diff_layer_dir, rel_prefix) = dir_query_roots(cfg, &rel_str)?;
    refresh_deleted_set(cfg);
    let deleted = deleted_paths_snapshot();
    let merged =
        dir_merge::merge_dir_entries(&base_layer_dir, &diff_layer_dir, &deleted, &rel_prefix);
    // BUG-128: マージ結果が空で、本体層側にも実体が無い（＝本当に空のディレクトリで、削除隠し
    // でもない）ときは、自前で `STATUS_NO_MORE_FILES` を先頭から返さず、OS 本来の列挙へ素通しする。
    //
    // **なぜ**: 実の `NtQueryDirectoryFile` は空ディレクトリでも先頭で `.`/`..` を返してから
    // `STATUS_NO_MORE_FILES` を返す。我々が先頭で `STATUS_NO_MORE_FILES` を返すと、Cygwin/MSYS の
    // `opendir` が `.`/`..` を1つも得られず `ENOSYS`（Function not implemented）で失敗する
    // （git の空の `.git/objects/pack` で実機再現、`docs/bugs/BUG-128.md`）。空ディレクトリには
    // マージで足すべき 差分層 エントリも隠すべき削除エントリも無いので、素通しは意味論的に等価で
    // 安全。**本体層側に実体がある場合（＝全エントリを削除で隠している whiteout）は素通ししない**
    // ——そちらは隠し続ける必要があるため、従来どおり空を返す。
    if merged.is_empty() && dir_merge::read_entries(&base_layer_dir).is_empty() {
        return None;
    }
    let requested =
        unsafe { filename_filter_units(file_name) }.map(|units| dir_merge::upcase_filter(&units));
    let previous = dir_query_cursor().lock().unwrap().get(&handle_key).cloned();
    let buf_len = length as usize;
    let out_buf = unsafe { std::slice::from_raw_parts_mut(file_information as *mut u8, buf_len) };
    let answer = dir_merge::answer_dir_query(
        merged,
        previous.as_ref(),
        requested,
        restart_scan,
        file_information_class,
        return_single_entry,
        out_buf,
    );
    dir_query_cursor()
        .lock()
        .unwrap()
        .insert(handle_key, answer.state);
    unsafe {
        (*io_status_block).Anonymous.Status = answer.status;
        (*io_status_block).Information = answer.bytes_written;
    }
    Some(answer.status)
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
/// `(base_layer_dir実体パス, diff_layer_dir実体パス, whiteout集合キーのprefix)`を求める。`baseline_hash_for`
/// と同じく、絶対パスなら`_ext`capture root、そうでなければworkspace相対として扱う
/// （設計書§19.8、Stage 2）。ディレクトリ自体が両側どちらにも存在しない場合は`None`
/// （通常起き得ないが、フックの再入・競合等の異常系での安全側フォールバック用）。
pub(crate) fn dir_query_roots(cfg: &Config, rel_str: &str) -> Option<(PathBuf, PathBuf, String)> {
    if Path::new(rel_str).is_absolute() {
        let key = store::ext_key(rel_str).ok()?;
        let diff_layer_dir = cfg.diff_layer_dir.join("_ext").join(&key);
        Some((
            PathBuf::from(rel_str),
            diff_layer_dir,
            rel_str.replace('\\', "/"),
        ))
    } else {
        let base_layer_dir = cfg.workspace_root.join(rel_str);
        let diff_layer_dir = cfg.diff_layer_dir.join(rel_str);
        Some((base_layer_dir, diff_layer_dir, rel_str.to_string()))
    }
}

/// `NtQueryDirectoryFile(Ex)`の`FileName`（絞り込みの式、任意）引数を、届いたままの`u16`の並びで写す。
/// NULLまたは空なら`None`（この問い合わせは絞り込みを渡していない）。**文字列へ直さない**——
/// 対にならないサロゲートを置き換えると、照合する式が別物になる。
pub(crate) unsafe fn filename_filter_units(
    us: *const windows::Win32::Foundation::UNICODE_STRING,
) -> Option<Vec<u16>> {
    if us.is_null() {
        return None;
    }
    let us = unsafe { &*us };
    if us.Buffer.is_null() || us.Length == 0 {
        return None;
    }
    let len_u16 = (us.Length as usize) / 2;
    Some(unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) }.to_vec())
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
        let path = cfg.diff_layer_dir.join(COW_WARNINGS_LEDGER_FILENAME);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
#[path = "dir_merge_tests.rs"]
mod tests;
