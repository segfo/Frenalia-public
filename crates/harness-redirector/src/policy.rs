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
    if relative_under(&cfg.upper_dir, path).is_some() {
        return None;
    }
    relative_under(&cfg.workspace_root, path).map(|rel| rel_path_buf(&rel))
}

/// パス1本が`root`配下かを判定し、配下なら相対部分（`/`区切り、`root`自身なら空文字列）を返す。
///
/// **判定と相対部分の算出を必ず1つの規則で行う**ため、実体は
/// `harness_change_ledger::path_rules::relative_under_root`（host側の照合と共有）へ委譲する。
/// [BUG-066](../../../docs/bugs/BUG-066.md): 旧実装は「配下か」を小文字化した文字列の前置詞
/// 一致で見ながら、相対部分を`Path::strip_prefix`（成分単位・**case-sensitive**）で求めていた。
/// 大小が1文字違うだけで「配下と判定したのに`None`」になり、呼び出し側からはworkspace外と
/// 区別が付かない＝**CoWのリダイレクトが黙って止まり、ACL拒否だけが残る**。末尾区切り・
/// `\??\`/`\\?\`前置・`/`混在も同じ理由で共有ヘルパ側が吸収する。
fn relative_under(root: &Path, path: &Path) -> Option<String> {
    harness_change_ledger::path_rules::relative_under_root(
        &path.to_string_lossy(),
        &root.to_string_lossy(),
    )
}

/// `/`区切りの相対パス文字列を、`upper_dir.join()`で使える`PathBuf`（`\`区切り）へ。
fn rel_path_buf(rel: &str) -> PathBuf {
    PathBuf::from(rel.replace('/', "\\"))
}

/// `path`が`upper_dir`配下（＝**既にCoWの行き先そのもの**）であれば、upperルートからの
/// 相対パス（`/`区切り）を返す。CoW自身の帳簿（`.harness-cow-*`、upper直下）は`None`＝
/// 完全に対象外にする（台帳・監査ログ自身の読み書きを「変更」として記録しないため）。
pub(crate) fn upper_relative(cfg: &Config, path: &Path) -> Option<String> {
    let rel = relative_under(&cfg.upper_dir, path)?;
    if rel.is_empty() {
        return None;
    }
    let top = rel.split('/').next().unwrap_or("");
    if top.starts_with(harness_change_ledger::COW_METADATA_PREFIX) {
        return None;
    }
    Some(rel)
}

pub(crate) fn rel_to_string(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

/// `path`が`ext_capture_roots`のいずれか配下であれば、`(ext_key, 正規化済み絶対パス文字列)`を
/// 返す（Phase 3、設計書§19.8）。`workspace_relative`と同じ大小無視・パス区切り境界判定。
pub(crate) fn ext_relative(cfg: &Config, path: &Path) -> Option<(String, String)> {
    for root in &cfg.ext_capture_roots {
        if relative_under(root, path).is_some() {
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
    pub(crate) kind: TargetKind,
}

/// 対象パスの種別。`UpperAlias`だけリダイレクトの扱いが違う（既に行き先に居るので
/// 誘導しない＝記録だけする）ため、呼び出し側が分岐できるよう明示的に持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// workspace配下。upperへ誘導する（従来どおり）。
    Workspace,
    /// `--fs-allow`のext capture root配下。`_ext/<key>`へ誘導する（Phase 3）。
    Ext,
    /// **upper_dir配下＝workspaceパスの別名**（[BUG-066](../../../docs/bugs/BUG-066.md)）。
    ///
    /// upper_dirはサンドボックス子へRW付与されているので、子は`<upper>\<rel>`を直接指定して
    /// 書ける（実際にモデルが`Set-Content <upper>\merge-demo.txt`をやった）。同じ実ファイルを
    /// 指す2通りの綴りなのだから、**同じ台帳キーの操作として同一視する**のが一貫している。
    /// 誘導先を作り直す（＝upperのupper）必要は無い——既に行き先だからである。
    UpperAlias,
}

pub(crate) fn classify_target(cfg: &Config, path: &Path) -> Option<Classified> {
    // upperを最初に見る（workspace配下にupperを置く構成でも、行き先側の解釈を優先する）。
    if let Some(rel) = upper_relative(cfg, path) {
        // `_ext/<key>`配下の別名は対象外にする。`ext_key`はドライブ文字を小文字化するため
        // 絶対パスへ逆写像すると台帳の綴りと食い違い、同じファイルが2エントリに割れる。
        // こちらはhost側の実体走査（`store::scan_upper_content_files`）が拾う。
        if rel.starts_with("_ext/") {
            return None;
        }
        return Some(Classified {
            rel: rel_path_buf(&rel),
            ledger_key: rel,
            kind: TargetKind::UpperAlias,
        });
    }
    if let Some(rel) = workspace_relative(cfg, path) {
        let ledger_key = rel_to_string(&rel);
        return Some(Classified {
            rel,
            ledger_key,
            kind: TargetKind::Workspace,
        });
    }
    let (key, original) = ext_relative(cfg, path)?;
    Some(Classified {
        rel: Path::new("_ext").join(&key),
        ledger_key: original,
        kind: TargetKind::Ext,
    })
}
