//! NTパス（`\??\C:\...`・`\Device\HarddiskVolume3\...`）と Win32 パスの相互変換。
//!
//! フックが受け取る`OBJECT_ATTRIBUTES`はNT名前空間のパスを持つため、workspace/upper_dirの
//! 判定に使えるWin32パスへ直す必要がある。相対オープン（`RootDirectory`ハンドル + 相対名）は
//! ハンドルからNTデバイスパスを引いて解決する。

use super::*;

/// `OBJECT_ATTRIBUTES.ObjectName`（`UNICODE_STRING`、UTF-16・非NUL終端）をRustの`String`へ。
///
/// `RootDirectory`が有効（相対open、いわゆるopenat方式）の場合は、`GetFinalPathNameByHandleW`
/// で`RootDirectory`ハンドルの完全パスを解決し、`ObjectName`（ハンドル起点からの相対パス）を
/// 連結して絶対パスへ組み立てる（BUG-033/BUG-041調査で判明: `cmd.exe`の`>`リダイレクトが
/// この方式でファイルを開くため、これを解決しないと孫プロセスの書込みがworkspace RO ACLへ
/// 素通しされ、fail-closeで消える——実機ログで実証済み）。`GetFinalPathNameByHandleW`は
/// 既存の（他プロセスではなく自プロセス内で有効な）ハンドルに対するクエリのみで新規に
/// ファイルを開かないため、`ReentryGuard`配下から呼んでも`NtCreateFile`/`NtOpenFile`への
/// 再帰は起きない。
pub(crate) unsafe fn object_attributes_path(oa: *const OBJECT_ATTRIBUTES) -> Option<PathBuf> {
    if oa.is_null() {
        return None;
    }
    let oa = unsafe { &*oa };
    let root_dir_value = oa.RootDirectory.0 as isize;
    let is_relative = !oa.RootDirectory.is_invalid() && root_dir_value != 0;
    let raw_name = if !oa.ObjectName.is_null() {
        let us = unsafe { &*oa.ObjectName };
        if us.Buffer.is_null() || us.Length == 0 {
            String::new()
        } else {
            let len_u16 = (us.Length as usize) / 2;
            let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, len_u16) };
            String::from_utf16_lossy(slice)
        }
    } else {
        String::new()
    };
    if raw_name.to_ascii_lowercase().contains("test.txt")
        || raw_name.to_ascii_lowercase().contains("grandchild")
    {
        debug_log(&format!(
            "object_attributes_path: root_dir={root_dir_value:#x} is_relative={is_relative} \
             raw_name={raw_name:?}"
        ));
    }
    if is_relative {
        return unsafe { resolve_relative_object_attributes_path(oa.RootDirectory, &raw_name) };
    }
    if raw_name.is_empty() {
        return None;
    }
    strip_nt_prefix(&raw_name)
}

/// `object_attributes_path`のopenat方式（`RootDirectory`相対）分岐本体（BUG-033修正）。
///
/// **`GetFinalPathNameByHandleW`/`QueryDosDeviceW`は使わない**: 当初`GetFinalPathNameByHandleW`
/// で`root`をDOS絶対パスへ解決しようとしたが、実機でAppContainer内から呼ぶと常に
/// `ERROR_ACCESS_DENIED`になった（内部で生のボリュームデバイス`\\.\C:`相当を開くため、
/// workspace/upperのACLだけを許可されたパッケージSIDには許可されない）。次に
/// `ntdll!NtQueryObject`でNTデバイスパス（例: `\Device\HarddiskVolume3\Users\...`、ドライブ
/// 文字なし）を得た上で、ドライブ文字→NTデバイス名の対応を`QueryDosDeviceW`のシステム全体
/// 列挙で作ろうとしたが、これもAppContainerからは1件も返らない（実機で確認、`\??\`
/// シンボリックリンク名前空間そのものがパッケージSIDから見えない）。
///
/// かわりに、**このDLLが最初から知っている2つのDOS絶対パス（`cfg.workspace_root`・
/// `cfg.upper_dir`）自身を自分で開いてNTデバイスプレフィックスを逆算**する
/// （`known_root_nt_prefixes`）。システム全体のドライブ列挙が不要になり、workspace/upper
/// 配下だけを解決できれば十分というこのDLLのスコープ（workspace外は既存の設計通り
/// 安全側で素通し）とも一致する。
pub(crate) unsafe fn resolve_relative_object_attributes_path(
    root: HANDLE,
    raw_name: &str,
) -> Option<PathBuf> {
    // 実機回帰テストで発見した誤検知: Windows Defender/AMSIプロバイダ（`MpOav.dll`等）が
    // レジストリのREG_EXPAND_SZ値を展開せずそのまま`NtCreateFile`の`ObjectName`へ渡すことがあり、
    // その結果`raw_name`が`%SystemDrive%\ProgramData\...\MpOav.dll`という**未展開の環境変数文字列を
    // 含む見せかけの相対パス**になる。`root`（この呼び出しでは偶然workspaceのCWDハンドル）と
    // 連結すると構文上は「workspace配下」に見えてしまい、無関係なシステムDLLの読み込みが
    // 誤って変更として記録・リダイレクトされる（実機`cow_ledger_records_single_session_changes_and_applies_cleanly`
    // で`%SystemDrive%/...`という台帳エントリとして再現）。`%`はcmd.exeの`>`リダイレクト等
    // 正規の相対ファイル名には現れないため、含む場合は解決不能として安全側で素通しする。
    //
    // **出所はAMSIに限らない**（BUG-104）。Windowsの既知フォルダ解決も同じ形を作る——
    // `HKLM\...\ProfileList`の`ProgramData`が`%SystemDrive%\ProgramData`というREG_EXPAND_SZで、
    // 子のenvに`SystemDrive`が無いと`ExpandEnvironmentStringsW`が未展開のまま返すため。
    // なお**このガードが守っているのは台帳であって、実体の作成ではない**: BUG-104の現物は
    // `--sandbox tier2a-cow`ではないセッション（Redirector未ロード）で作られており、原因はenv allowlistの
    // 欠落側にあった。そちらは`harness-sandbox`の`secret_env.rs`で修正済み。
    if raw_name.contains('%') {
        return None;
    }
    let cfg = CONFIG.get()?;
    let Some(nt_device_path) = (unsafe { query_object_name(root) }) else {
        // **AppContainer内では「ハンドルの名前を引くOS API」が当てにならない**（BUG-128）。
        // `GetFinalPathNameByHandleW`・`QueryDosDeviceW`（このモジュール冒頭のdoc）に続いて、
        // `NtQueryObject`もパッケージSIDから見えないハンドルに対して失敗する。OSに後から聞く
        // 代わりに、**このDLL自身が開いた瞬間に記録したハンドル→パス対応表**（`handle_paths()`）を
        // 引く。git/MSYSはオブジェクトストアをopenat方式（`RootDirectory`＋相対名）で開くため、
        // これが無いと`.git/objects/pack`の解決に失敗し、`git commit`が
        // `.git/objects/pack: Function not implemented`で完走しなかった（BUG-128の症状）。
        return resolve_relative_via_handle_map(cfg, root, raw_name);
    };
    let Some(root_path) = nt_device_path_to_known_root(cfg, &nt_device_path) else {
        debug_log(&format!(
            "resolve_relative_object_attributes_path: nt_device_path_to_known_root failed for \
             nt_device_path={nt_device_path:?}"
        ));
        return None;
    };
    let rel = raw_name.trim_start_matches('\\');
    if rel.is_empty() {
        Some(root_path)
    } else {
        Some(root_path.join(rel.replace('/', "\\")))
    }
}

/// `NtQueryObject`が失敗したときのフォールバック（BUG-128）。`root`ハンドルを、フックが
/// 開いた瞬間に登録した対応表（`handle_paths()`：ハンドル→`Classified::ledger_key`）から引き、
/// 親ディレクトリの実体パスへ復元して相対名を連結する。
///
/// **ledger_keyの解釈は`dir_query_roots`と同じ規約**にそろえる——絶対パスなら`_ext` capture
/// root、そうでなければworkspace相対（`docs/CODE-STRUCTURE-RULES.md`規則5：同じ判定を2箇所で
/// 別々に育てない）。返すのは絶対パスで、呼び出し側の`classify_target`が通常どおり再分類・
/// リダイレクトする（＝親ハンドルがworkspace側かupper側かを問わず、子openは論理パスとして
/// 扱われ、書込は改めてupperへ誘導される）。
///
/// **対応表に無いハンドルは`None`**（安全側の素通し）。境界はACLなので、透過が効かなければ
/// 失敗が見えるだけで穴は開かない（D-01）。
fn resolve_relative_via_handle_map(cfg: &Config, root: HANDLE, raw_name: &str) -> Option<PathBuf> {
    let key = root.0 as isize;
    // 対応表に無いハンドルは `None`（安全側の素通し）。ここへ来る大半は、プロセス生成の
    // 内部で開かれる（このDLLが分類していない）ハンドルへの空名 open で、解決できなくても
    // 透過が効かないだけ＝境界はACLが守る（D-01）。ログは解決できたときだけ出す（ミスは多い）。
    let parent_rel = handle_paths().lock().unwrap().get(&key).cloned()?;
    let resolved = reconstruct_handle_relative_path(&cfg.workspace_root, &parent_rel, raw_name);
    debug_log(&format!(
        "resolve_relative_via_handle_map: root {key:#x} -> parent_rel={parent_rel:?} \
         raw_name={raw_name:?} resolved={resolved:?}"
    ));
    Some(resolved)
}

/// 親ディレクトリの`ledger_key`（対応表の値）と相対名から、子の実体パスを組み立てる純関数。
/// グローバル状態に触れないので単体テストできる（`resolve_relative_via_handle_map`から切り出し）。
///
/// 規約は`dir_query_roots`と同じ: `parent_rel`が絶対パスなら`_ext` capture root としてそのまま、
/// そうでなければworkspace相対。相対名は先頭の`\`を落とし`/`→`\`へ正規化して連結する。
fn reconstruct_handle_relative_path(
    workspace_root: &Path,
    parent_rel: &str,
    raw_name: &str,
) -> PathBuf {
    let base = if Path::new(parent_rel).is_absolute() {
        PathBuf::from(parent_rel)
    } else {
        workspace_root.join(parent_rel)
    };
    let child = raw_name.trim_start_matches('\\').replace('/', "\\");
    if child.is_empty() {
        base
    } else {
        base.join(child)
    }
}

/// `ntdll!NtQueryObject(handle, ObjectNameInformation, ...)`。カーネルのオブジェクトマネージャに
/// 記録されているハンドルの名前（ファイルハンドルの場合はNTデバイスパス）を問い合わせる。
/// `windows`クレートは`ObjectNameInformation`定数自体はエクスポートしていないため
/// （`ObjectBasicInformation`=0・`ObjectTypeInformation`=2のみ生成済み）、phnt由来の値1を
/// 直接リテラルで持つ。
pub(crate) unsafe fn query_object_name(handle: HANDLE) -> Option<String> {
    const OBJECT_NAME_INFORMATION_CLASS: OBJECT_INFORMATION_CLASS = OBJECT_INFORMATION_CLASS(1);
    let mut buf = vec![0u8; 1024];
    let mut return_length: u32 = 0;
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION_CLASS,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            Some(&mut return_length),
        )
    };
    if status.is_err() {
        return None;
    }
    let info = unsafe { &*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION) };
    let name = &info.Name;
    if name.Buffer.is_null() || name.Length == 0 {
        return None;
    }
    let len_u16 = (name.Length as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(name.Buffer.0, len_u16) };
    Some(String::from_utf16_lossy(slice))
}

/// `cfg.workspace_root`・`cfg.upper_dir`それぞれについて、自分でその絶対パスを開き
/// `query_object_name`でNTデバイスパス（例: `\Device\HarddiskVolume3\Users\...\workspace`、
/// ルート自身の完全パス）を取得してキャッシュする。プロセス生存中にドライブ構成が変わる
/// ことは無い想定で1度だけ計算する（BUG-033修正）。
pub(crate) fn known_root_nt_paths(cfg: &'static Config) -> &'static [(String, PathBuf)] {
    static CACHE: OnceLock<Vec<(String, PathBuf)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = Vec::new();
        for root in [cfg.workspace_root.clone(), cfg.upper_dir.clone()] {
            if let Some(nt_name) = query_own_nt_device_path(&root) {
                out.push((nt_name, root));
            }
        }
        out
    })
}

/// `root`（このDLLが既に知っているDOS絶対パス）を`FILE_FLAG_BACKUP_SEMANTICS`付きで開き
/// （ディレクトリを`CreateFileW`系で開くにはこのフラグが要る）、`query_object_name`で
/// そのハンドル自身の完全なNTデバイスパスを取得する（`known_root_nt_paths`参照）。
pub(crate) fn query_own_nt_device_path(root: &Path) -> Option<String> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .ok()?;
    let handle = HANDLE(file.as_raw_handle());
    unsafe { query_object_name(handle) }
}

/// NTデバイスパス（例: `\Device\HarddiskVolume3\Users\...`）を、`known_root_nt_paths`の
/// 対応表と比較し、既知ルート（`workspace_root`または`upper_dir`）自身か、その配下かを
/// 判定してDOS絶対パスへ変換する（BUG-033修正）。
pub(crate) fn nt_device_path_to_known_root(cfg: &'static Config, nt_path: &str) -> Option<PathBuf> {
    let nt_lc = nt_path.to_ascii_lowercase();
    for (root_nt_path, dos_root) in known_root_nt_paths(cfg) {
        let root_nt_lc = root_nt_path.to_ascii_lowercase();
        if nt_lc == root_nt_lc {
            return Some(dos_root.clone());
        }
        if nt_lc.starts_with(&format!("{root_nt_lc}\\")) {
            let rest = &nt_path[root_nt_path.len() + 1..];
            return Some(dos_root.join(rest.replace('/', "\\")));
        }
    }
    None
}

pub(crate) fn strip_nt_prefix(raw: &str) -> Option<PathBuf> {
    // NTパスプレフィックス（`\??\`＝DOSデバイスパス, `\\?\`は通常Win32層でしか現れないが
    // 念のため対応）を剥がしてDOS形式へ正規化する（§16の最小サブセット）。
    let stripped = raw
        .strip_prefix(r"\??\")
        .or_else(|| raw.strip_prefix(r"\\?\"))
        .unwrap_or(raw);
    Some(PathBuf::from(stripped))
}

#[cfg(test)]
mod handle_map_reconstruction_tests {
    use super::reconstruct_handle_relative_path;
    use std::path::{Path, PathBuf};

    /// git のオブジェクトストアは openat 方式（親ディレクトリのハンドル + 相対名）で開く。
    /// 親 `.git/objects` のハンドルから子 `pack` を解決する典型ケース（BUG-128 の中心）。
    #[test]
    fn joins_workspace_relative_parent_with_child() {
        let ws = Path::new(r"C:\ws");
        assert_eq!(
            reconstruct_handle_relative_path(ws, ".git/objects", "pack"),
            PathBuf::from(r"C:\ws\.git/objects\pack")
        );
    }

    /// 相対名の先頭 `\` は落とし、`/` は `\` へ正規化する（多段の相対名も連結できる）。
    #[test]
    fn strips_leading_backslash_and_normalizes_slashes() {
        let ws = Path::new(r"C:\ws");
        assert_eq!(
            reconstruct_handle_relative_path(ws, ".git", r"\objects/ab/cdef"),
            PathBuf::from(r"C:\ws\.git\objects\ab\cdef")
        );
    }

    /// 相対名が空（ハンドルそのものを指す open）のときは親をそのまま返す。
    #[test]
    fn empty_child_returns_the_parent_itself() {
        let ws = Path::new(r"C:\ws");
        assert_eq!(
            reconstruct_handle_relative_path(ws, ".git/objects", ""),
            PathBuf::from(r"C:\ws\.git/objects")
        );
    }

    /// 親が絶対パス（`_ext` capture root の実体パス）なら workspace は前置しない
    /// （`dir_query_roots` と同じ規約）。
    #[test]
    fn absolute_parent_is_used_verbatim_like_ext_capture_root() {
        let ws = Path::new(r"C:\ws");
        assert_eq!(
            reconstruct_handle_relative_path(ws, r"D:\shared\tools", "x.dll"),
            PathBuf::from(r"D:\shared\tools\x.dll")
        );
    }
}
