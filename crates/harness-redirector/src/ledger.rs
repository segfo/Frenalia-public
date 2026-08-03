//! CoW操作台帳への追記・copy-up・リダイレクト先`OBJECT_ATTRIBUTES`の組み立て。
//!
//! upper_dirに版が無いファイルへの書込は、まずworkspaceから copy-up してから
//! リダイレクトする。論理削除（tombstone）の集合もここで管理する。

use super::*;

/// `ledger_key`（`Classified::ledger_key`、workspace相対パスまたは`_ext`の正規化済み絶対パス）を、
/// そのセッションで最初に触った瞬間の実内容ハッシュへ解決する（キャッシュ済みならそれを返す、
/// 設計書§19.5）。権威となる計算・baselineミラー書込は`harness_change_ledger::store`（`_ext`は
/// `baseline_hash_and_mirror_ext`、workspace内は`baseline_hash_and_mirror`）が唯一の実装
/// （host内蔵ツール`write_file`/`edit_file`側も同じ関数を呼ぶ、BUG-042の再発防止）——ここでの
/// `baseline_cache`はDLLのホットパス向けのメモ化に過ぎない。`ledger_key`が絶対パスかどうかで
/// `_ext`かworkspace内かを判定する（workspace相対パスは`check_relative_path`相当の生成元
/// （`workspace_relative`）が絶対パスを作らないため、この判定で一意に決まる）。
pub(crate) fn baseline_hash_for(cfg: &Config, ledger_key: &str) -> Option<String> {
    let cache = baseline_cache();
    let mut guard = cache.lock().unwrap();
    if let Some(v) = guard.get(ledger_key) {
        return v.clone();
    }
    let hash = if Path::new(ledger_key).is_absolute() {
        store::ext_key(ledger_key)
            .ok()
            .and_then(|key| store::baseline_hash_and_mirror_ext(&cfg.upper_dir, ledger_key, &key))
    } else {
        store::baseline_hash_and_mirror(&cfg.upper_dir, &cfg.workspace_root, ledger_key)
    };
    guard.insert(ledger_key.to_string(), hash.clone());
    hash
}

/// 台帳（`<upper_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記し、メモリ上の削除済み集合も
/// 更新する。追記の実体は`store::append_entry`（host側と共有、設計書§19.2「追記の並行性」）。
pub(crate) fn append_ledger_entry(cfg: &Config, op: ChangeOp, rel: &str, baseline_hash: Option<String>) {
    store::append_entry(&cfg.upper_dir, op, rel, baseline_hash);
    let deleted = deleted_paths_state();
    let mut g = deleted.lock().unwrap();
    match op {
        ChangeOp::Delete => {
            g.insert(rel.to_string());
        }
        ChangeOp::Create | ChangeOp::Modify => {
            g.remove(rel);
        }
    }
}

/// copy-up（設計書§18の最小サブセット、一時ファイル+原子renameは省略——初期実装として
/// 単純上書きコピーを採用する。並行copy-upの競合は許容し、後勝ちで構わない
/// スコープに留める）。実際にupperへコピー/新規作成した瞬間（冪等チェックを通過して実際に
/// 作業した瞬間）にCreate/Modifyを1件台帳へ追記する（設計書§19.6）。
pub(crate) fn copy_up(cfg: &Config, rel: &str, workspace_path: &Path, upper_path: &Path) {
    if upper_path.exists() {
        return;
    }
    let baseline_hash = baseline_hash_for(cfg, rel);
    if let Some(parent) = upper_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if workspace_path.is_file() {
        let _ = std::fs::copy(workspace_path, upper_path);
    }
    let op = if baseline_hash.is_some() { ChangeOp::Modify } else { ChangeOp::Create };
    append_ledger_entry(cfg, op, rel, baseline_hash);
}

// `copy_up`（`std::fs::copy`/`create_dir_all`）はWin32のCreateFileW等を経由するため、
// パッチ済みの`ntdll!NtCreateFile`/`NtOpenFile`を通って自分自身のフック関数へ再入する
// （このDLLだけでなくプロセス内の全呼び出し元がパッチ済みの実体を叩くため、フック関数の内部から
// 発行したファイルI/Oも同じフック関数へ戻ってくる）。`classify`はupper_dir配下を除外するため
// 単純な無限ループにはならない設計だったが、実機検証でスタックオーバーフローを確認した
// （再帰の呼び出し系列は未特定）。分類・copy-upロジックはスレッドごとに一度だけ働けばよく、
// 再入時は素通し（元のcopy-up呼び出しが要求した実パスをそのまま使わせる）が正しい振る舞いのため、
// スレッドローカルな再入ガードで内側の分類・copy-upロジックを止める。新設した
// `NtSetInformationFile`/`NtClose`フックの台帳I/Oもこのガードで挟む（設計書§19.6）。
thread_local! {
    static IN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) struct ReentryGuard;

impl ReentryGuard {
    pub(crate) fn try_acquire() -> Option<Self> {
        IN_HOOK.with(|f| {
            if f.get() {
                None
            } else {
                f.set(true);
                Some(ReentryGuard)
            }
        })
    }
}

impl Drop for ReentryGuard {
    fn drop(&mut self) {
        IN_HOOK.with(|f| f.set(false));
    }
}

/// `upper_path`（DOS形式の絶対パス）を、NT名前空間で有効な`\??\`プレフィックス付きUTF-16
/// （NUL終端込み）へ変換する。`object_attributes_path`は読み取り時に`\??\`/`\\?\`を剥がして
/// DOS形式へ正規化するが、書き戻すNT-levelの`ObjectName`は逆にNTデバイス名前空間の完全パス
/// （`\??\`プレフィックス）が必須——プレフィックス無しのDOSパスをそのまま渡すと
/// `NtCreateFile`から見て不正な名前になり`STATUS_OBJECT_NAME_INVALID`（「指定されたパスは
/// 無効です」）で失敗する（実機検証で確認）。
///
/// **`/`→`\`正規化が必須**（Phase 3実機E2Eで発見）: `classify_target`のPhase 3 `_ext`分岐は
/// `store::ext_key()`が返す`/`区切りのキー文字列（例`"c/harness-.../probe.txt"`）を
/// `PathBuf::join`で連結するが、`PathBuf::join`は引数中の`/`を`\`へ**変換しない**
/// （`Path`のcomponent解析は`/`も区切りとして認識するが、`to_string_lossy()`が返す生の
/// 内部表現は連結時の元の区切り文字をそのまま保持する）。Win32層（`CreateFileW`等、
/// `std::fs`はこちらを使う）は`/`を`\`と同様に解釈するため気付きにくいが、NT名前空間
/// （`NtCreateFile`が見るのはこちら）は`/`を区切りとして認識せず不正な名前として拒否する
/// （実機E2Eで`STATUS_OBJECT_NAME_INVALID`を確認）。ここで一括正規化することで、
/// 呼び出し元がどう`PathBuf`を組み立てても安全にする。
pub(crate) fn nt_path_wide(upper_path: &Path) -> Vec<u16> {
    let normalized = upper_path.to_string_lossy().replace('/', "\\");
    let nt_path = format!(r"\??\{normalized}");
    nt_path.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `object_attributes`をupper側の完全パス（`upper_wide`、`nt_path_wide`済み）へ向け直した
/// `OBJECT_ATTRIBUTES`/`UNICODE_STRING`のペアを組み立てる。呼び出し元は両方を同じスコープで
/// 保持し（`UNICODE_STRING.Buffer`が`upper_wide`を指すため`upper_wide`自体も生存させること）、
/// `oa.ObjectName = &mut name;`してから使うこと（Rustの借用は関数境界を越えて返せないため）。
/// 書込リダイレクト・読み取りリダイレクト（read-through）・属性照会リダイレクトの4箇所で
/// 同じ組み立てが必要なため一本化した（設計書§19.6/§19.7）。
pub(crate) unsafe fn build_redirected_oa(
    object_attributes: *const OBJECT_ATTRIBUTES,
    upper_wide: &[u16],
) -> (OBJECT_ATTRIBUTES, windows::Win32::Foundation::UNICODE_STRING) {
    let mut redirected_oa = unsafe { *object_attributes };
    let redirected_name = windows::Win32::Foundation::UNICODE_STRING {
        Length: ((upper_wide.len() - 1) * 2) as u16,
        MaximumLength: (upper_wide.len() * 2) as u16,
        Buffer: windows::core::PWSTR(upper_wide.as_ptr() as *mut u16),
    };
    redirected_oa.RootDirectory = HANDLE::default();
    (redirected_oa, redirected_name)
}

/// `rel`（workspace相対）のupper側実体パスを返す（存在すれば）。読み取りread-through判定
/// （設計書§19.3/§19.7「削除済み＞upper＞workspace」の中間段）に使う。
pub(crate) fn upper_version_path(cfg: &Config, rel: &Path) -> Option<PathBuf> {
    let upper_path = cfg.upper_dir.join(rel);
    if upper_path.is_file() {
        Some(upper_path)
    } else {
        None
    }
}

/// 台帳ファイルの、前回同期以降に追記された**完全な行だけ**を取り込み、`deleted_paths_state`
/// を増分更新する（設計書§19.2）。`FILE_APPEND_DATA`による1行1書込みという既存の追記規律
/// （書く側、本ファイル`append_ledger_entry`）により、途中まで書かれた行（末尾に`\n`が無い）は
/// 次回の呼び出しまで無視して安全に据え置ける——サイズが前回と変わっていなければファイルI/O
/// すらしないため、フックのホットパスでのコストは兄弟プロセスが実際に書いた場合のみ発生する。
pub(crate) fn refresh_deleted_set(cfg: &Config) {
    let ledger_path = cfg.upper_dir.join(COW_OPS_LEDGER_FILENAME);
    let mut offset_guard = ledger_read_offset().lock().unwrap();
    let Ok(contents) = std::fs::read(&ledger_path) else {
        return;
    };
    let len = contents.len() as u64;
    if len <= *offset_guard {
        // 変化なし、または（想定外だが）縮小。縮小はスコープ外として無視する。
        return;
    }
    let new_bytes = &contents[*offset_guard as usize..];
    let Some(last_nl) = new_bytes.iter().rposition(|&b| b == b'\n') else {
        // 完全な行がまだ1つも届いていない（書込み途中）。オフセットは進めない。
        return;
    };
    let complete = &new_bytes[..=last_nl];
    let text = String::from_utf8_lossy(complete);
    let entries = parse_ledger(&text);
    let mut deleted = deleted_paths_state().lock().unwrap();
    for entry in &entries {
        match entry.op {
            ChangeOp::Delete => {
                deleted.insert(entry.path.clone());
            }
            ChangeOp::Create | ChangeOp::Modify => {
                deleted.remove(&entry.path);
            }
        }
    }
    *offset_guard += complete.len() as u64;
}

/// 論理削除済み集合を確認し、必要なら書換後の`NTSTATUS`を返す（`Some`なら即returnすべき）。
/// 作成可能なdispositionでの再作成は集合から除去して`None`（通常処理へ継続）を返す。
pub(crate) fn check_deleted(cfg: &Config, rel: &str, allow_recreate: bool) -> Option<NTSTATUS> {
    refresh_deleted_set(cfg);
    let deleted = deleted_paths_state();
    let mut g = deleted.lock().unwrap();
    if !g.contains(rel) {
        return None;
    }
    if allow_recreate {
        g.remove(rel);
        None
    } else {
        Some(STATUS_OBJECT_NAME_NOT_FOUND)
    }
}
