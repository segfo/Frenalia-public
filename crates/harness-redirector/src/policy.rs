//! 「この操作をリダイレクトすべきか」の判定。副作用を持たない純粋な分類。
//!
//! 書込意図の判定（`DesiredAccess`と`CreateDisposition`）と、対象パスが
//! workspace内 / `--fs-allow`のext root / それ以外 のどれに属するかの分類を行う。

use super::*;

/// `desired_access`/`create_disposition`から「変更操作か」を判定する（設計書§15の最小
/// サブセット）。`GENERIC_WRITE`の有無だけで判定しない——DELETE単体・APPEND単体も
/// 変更操作として扱う。`create_disposition`は`NtCreateFile`のみが持つ（`NtOpenFile`は
/// 常に`FILE_OPEN`相当のため`None`を渡す）。
/// BUG-048: `FILE_GENERIC_WRITE`は使わない——`GENERIC_WRITE`をファイルへマップした結果の
/// 複合マスクで、`SYNCHRONIZE`(0x10_0000)・`READ_CONTROL`(0x2_0000)を含む。Win32の
/// `CreateFileW`は**読み取り専用**openでも常に`SYNCHRONIZE`を要求する（同期I/O前提のため）ため、
/// これを含むマスクで判定すると`Get-ChildItem`のディレクトリopenや`Get-Content`の読み取りopen
/// まで「書込意図あり」と誤判定してしまう（実機で確認: `desired_access=0x100001`
/// `=FILE_LIST_DIRECTORY|SYNCHRONIZE`が`write_intent=true`になっていた）。書込を意味する
/// ビットだけを明示的に列挙すること。
pub(crate) fn is_write_intent(desired_access: u32, create_disposition: Option<u32>) -> bool {
    const FILE_SUPERSEDE: u32 = 0;
    const FILE_OVERWRITE: u32 = 4;
    const FILE_OVERWRITE_IF: u32 = 5;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    let write_mask = FILE_WRITE_DATA.0
        | FILE_APPEND_DATA.0
        | FILE_WRITE_ATTRIBUTES.0
        | FILE_WRITE_EA.0
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;
    if desired_access & write_mask != 0 {
        return true;
    }
    matches!(
        create_disposition,
        Some(FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF)
    )
}

/// `create_disposition`が「対象が存在しなくても作成する」種別かどうか（`FILE_SUPERSEDE`=0・
/// `FILE_CREATE`=2・`FILE_OPEN_IF`=3・`FILE_OVERWRITE_IF`=5）。論理削除済みパスへの再作成
/// （削除の取り消し）を判定するために使う（設計書§19.7）。
pub(crate) fn is_create_capable_disposition(create_disposition: u32) -> bool {
    matches!(create_disposition, 0 | 2 | 3 | 5)
}

/// BUG-048（F2）: `write_intent`が立っていても、`create_options`に`FILE_DIRECTORY_FILE`が
/// 付いた**ディレクトリのopen**は、新規作成dispositionでない限りcopy-up/リダイレクト対象から
/// 除外する。`Remove-Item`のパス解決やcwdの保持等、既存ディレクトリを`DELETE`/
/// `WRITE_ATTRIBUTES`アクセス込みで開くケースがあり、これをリダイレクトすると
/// `upper_dir`側に実体の無いディレクトリを開こうとして失敗したり、`copy_up`が
/// （ファイルではないため中身を伴わない）偽の`create`/`modify`エントリを台帳へ積んだりする
/// （実機で`ls .harness`後に`.harness-cow-ops.jsonl`へ`create .harness`が誤記録されるのを確認）。
/// `NtOpenFile`は`create_disposition`を持たない（常に`FILE_OPEN`相当）ため`None`を渡すと
/// 常に除外側になる——既存ディレクトリを開くだけの操作しか無いことと整合する。
pub(crate) fn should_redirect_write(
    write_intent: bool,
    create_options: u32,
    create_disposition: Option<u32>,
) -> bool {
    if !write_intent {
        return false;
    }
    let is_dir_open = create_options & FILE_DIRECTORY_FILE.0 != 0;
    if !is_dir_open {
        return true;
    }
    matches!(create_disposition, Some(d) if is_create_capable_disposition(d))
}

/// `path`が`upper_dir`配下でなくworkspace配下であれば、workspaceルートからの相対パスを返す。
/// upper_dir配下は絶対に対象外とする（誤ってupperをworkspaceとして再変換すると無限
/// リダイレクトになる、設計書§9）。
pub(crate) fn workspace_relative(cfg: &Config, path: &Path) -> Option<PathBuf> {
    let path_lc = path.to_string_lossy().to_ascii_lowercase();
    let upper_lc = cfg.upper_dir.to_string_lossy().to_ascii_lowercase();
    if path_lc.starts_with(&upper_lc) {
        return None;
    }
    let ws_lc = cfg.workspace_root.to_string_lossy().to_ascii_lowercase();
    let is_under_workspace = path_lc == ws_lc
        || (path_lc.starts_with(&ws_lc) && path_lc.as_bytes().get(ws_lc.len()) == Some(&b'\\'));
    if !is_under_workspace {
        return None;
    }
    path.strip_prefix(&cfg.workspace_root).ok().map(|p| p.to_path_buf())
}

pub(crate) fn rel_to_string(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// `path`が`ext_capture_roots`のいずれか配下であれば、`(ext_key, 正規化済み絶対パス文字列)`を
/// 返す（Phase 3、設計書§19.8）。`workspace_relative`と同じ大小無視・パス区切り境界判定。
pub(crate) fn ext_relative(cfg: &Config, path: &Path) -> Option<(String, String)> {
    let path_lc = path.to_string_lossy().to_ascii_lowercase();
    for root in &cfg.ext_capture_roots {
        let root_lc = root.to_string_lossy().to_ascii_lowercase();
        let is_under = path_lc == root_lc
            || (path_lc.starts_with(&root_lc) && path_lc.as_bytes().get(root_lc.len()) == Some(&b'\\'));
        if is_under {
            let original = store::normalize_abs_path(&path.to_string_lossy());
            let key = store::ext_key(&original).ok()?;
            return Some((key, original));
        }
    }
    None
}

/// `workspace_relative`/`ext_relative`の判定結果を統一する。`rel`は`cfg.upper_dir.join(&rel)`で
/// 常に正しいupper側実体パスになる（workspace内なら`<rel>`そのまま、`_ext`ならcapture root配下
/// への写像`_ext/<key>`）。`ledger_key`は操作台帳・`check_deleted`・ハンドル対応表で使う識別子
/// （workspace内ならworkspace相対パス、`_ext`なら正規化済み絶対パス文字列——host側`apply()`が
/// `workspace_root.join(&path)`でそのまま実ターゲットを求められる形、設計書§19.8）。
pub(crate) struct Classified {
    pub(crate) rel: PathBuf,
    pub(crate) ledger_key: String,
}

pub(crate) fn classify_target(cfg: &Config, path: &Path) -> Option<Classified> {
    if let Some(rel) = workspace_relative(cfg, path) {
        let ledger_key = rel_to_string(&rel);
        return Some(Classified { rel, ledger_key });
    }
    let (key, original) = ext_relative(cfg, path)?;
    Some(Classified {
        rel: Path::new("_ext").join(&key),
        ledger_key: original,
    })
}
