//! CoW操作台帳への追記・copy-up・リダイレクト先`OBJECT_ATTRIBUTES`の組み立て。
//!
//! diff_layer_dirに版が無いファイルへの書込は、まずworkspaceから copy-up してから
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
        store::ext_key(ledger_key).ok().and_then(|key| {
            store::baseline_hash_and_mirror_ext(&cfg.diff_layer_dir, ledger_key, &key)
        })
    } else {
        store::baseline_hash_and_mirror(&cfg.diff_layer_dir, &cfg.workspace_root, ledger_key)
    };
    guard.insert(ledger_key.to_string(), hash.clone());
    hash
}

/// 台帳（`<diff_layer_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記し、メモリ上の削除済み集合も
/// 更新する。追記の実体は`store::append_entry`（host側と共有、設計書§19.2「追記の並行性」）。
pub(crate) fn append_ledger_entry(
    cfg: &Config,
    op: ChangeOp,
    rel: &str,
    baseline_hash: Option<String>,
) {
    store::append_entry(&cfg.diff_layer_dir, op, rel, baseline_hash);
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

/// 台帳へ書く**予定**の1件（[BUG-171](../../../docs/bugs/BUG-171.md)）。
///
/// 記録の中身（どの操作か・最初に触った時点の中身の指紋）は本当の操作の前に決めてよいが、
/// **書くのは、本当の操作が成功したと分かってから**である（設計書§19.6「実際に…した瞬間に追記する」）。
/// 先に書くと、操作が失敗したときに台帳だけが「起きた」と言う。台帳は一覧（`harness changes`）・
/// 承認（`harness apply`）・セッションの中の見え方（削除済みの集合）の唯一の材料なので、
/// 3つが揃って実体と食い違う——実際に、存在しないファイルを消しただけで中身の無い`create`が残り、
/// 失敗した名前の変更と断られた削除では、元のファイルが台帳の上で削除済みになった。
///
/// 書く・書かないは[`Self::settle`]に本当の操作の結果を渡して決める。**呼ばずに捨てると何も書かない**
/// ——結果が分からないまま「起きた」とは言わない側へ倒すため。
#[must_use = "settle() with the real operation's result; dropping it writes nothing"]
pub(crate) struct PendingRecord {
    op: ChangeOp,
    rel: String,
    baseline_hash: Option<String>,
}

impl PendingRecord {
    /// `rel`の最初の接触として書く予定を作る。workspace側に元があれば`Modify`、無ければ`Create`。
    fn first_touch(cfg: &Config, rel: &str) -> Self {
        let baseline_hash = baseline_hash_for(cfg, rel);
        let op = if baseline_hash.is_some() {
            ChangeOp::Modify
        } else {
            ChangeOp::Create
        };
        Self {
            op,
            rel: rel.to_string(),
            baseline_hash,
        }
    }

    /// 名前の変更の旧パス（`Delete`）として書く予定を作る。
    pub(crate) fn delete(cfg: &Config, rel: &str) -> Self {
        Self {
            op: ChangeOp::Delete,
            rel: rel.to_string(),
            baseline_hash: baseline_hash_for(cfg, rel),
        }
    }

    /// 名前の変更の新パスとして書く予定を作る（[`Self::first_touch`]と同じ判定）。
    pub(crate) fn rename_target(cfg: &Config, rel: &str) -> Self {
        Self::first_touch(cfg, rel)
    }

    /// 本当の操作の結果を受け取り、成功したときだけ台帳へ書く。
    pub(crate) fn settle(self, cfg: &Config, succeeded: bool) {
        if succeeded {
            append_ledger_entry(cfg, self.op, &self.rel, self.baseline_hash);
        }
    }
}

/// [`copy_up`]が差分層へ用意したもの。本当のopenの結果とともに[`finish_copy_up`]へ渡す。
#[must_use = "pass it to finish_copy_up() with the real open's result"]
pub(crate) struct CopyUp {
    record: PendingRecord,
    /// この呼び出しでworkspaceから写した実体（写さなかったなら`None`）。
    copied: Option<PathBuf>,
}

/// copy-upでworkspaceの元の中身を写すか。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CopySource {
    /// 写す（通常）。既存ファイルを書込で開くには、差分層に同じ中身が要る。
    Workspace,
    /// 写さない。**このセッションで論理削除したパスを作り直す**とき（[BUG-172](../../../docs/bugs/BUG-172.md)）
    /// ——論理的にはファイルは無いので、作り直したファイルは空から始まる。写すと、追記で作り直せば
    /// 「元の中身＋追記」、`CreateNew`で作り直せば写したばかりのコピーとぶつかって失敗し、
    /// 消したはずのファイルが生き返る。
    Nothing,
}

/// copy-up（設計書§18の最小サブセット、一時ファイル+原子renameは省略——初期実装として
/// 単純上書きコピーを採用する。並行copy-upの競合は許容し、後勝ちで構わない
/// スコープに留める）。
///
/// **ここでは台帳へ書かない**（BUG-171）。書く予定を返し、本当のopenの結果を見た
/// [`finish_copy_up`]が書く。差分層に既に実体があれば「このセッションで既に触った」ので
/// 何もせず`None`を返す（この判定があるので、`apply`は適用した実体を差分層から消している、BUG-034）。
pub(crate) fn copy_up(
    cfg: &Config,
    rel: &str,
    workspace_path: &Path,
    diff_layer_path: &Path,
    source: CopySource,
) -> Option<CopyUp> {
    if diff_layer_path.exists() {
        return None;
    }
    let record = PendingRecord::first_touch(cfg, rel);
    if let Some(parent) = diff_layer_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let copied = (source == CopySource::Workspace
        && workspace_path.is_file()
        && std::fs::copy(workspace_path, diff_layer_path).is_ok())
    .then(|| diff_layer_path.to_path_buf());
    Some(CopyUp { record, copied })
}

/// `rel`がこのセッションで論理削除されているか（削除済み集合に入っているか）。
/// 読むだけで、集合は変えない。直前に[`check_deleted`]が台帳の増分を取り込んでいる前提で使う。
pub(crate) fn is_logically_deleted(rel: &str) -> bool {
    deleted_paths_state().lock().unwrap().contains(rel)
}

/// [`copy_up`]の後始末。本当のopenが成功したときだけ台帳へ書く（設計書§19.6）。
///
/// 失敗したときは、この呼び出しで写した実体を差分層から消す。残すと、次に同じパスを
/// 書込で開いたとき[`copy_up`]が「既に触った」と判定して**その回を台帳へ書かない**
/// （台帳に無い実体として一覧には出るが、元の中身の指紋を失うので`apply`の衝突検出が効かない）。
/// 消せなかったら警告台帳へ残す（黙って捨てない）。空のディレクトリは一覧に出ないので残してよい。
pub(crate) fn finish_copy_up(cfg: &Config, copy_up: Option<CopyUp>, open_succeeded: bool) {
    let Some(CopyUp { record, copied }) = copy_up else {
        return;
    };
    if !open_succeeded {
        if let Some(path) = copied {
            if let Err(e) = std::fs::remove_file(&path) {
                append_warning_kind(
                    cfg,
                    "copy_up_rollback_failed",
                    &format!(
                        "the open that copied {} into the diff layer failed, and removing the copy \
                         failed too ({e}); the next write to {} will not be recorded in the ledger",
                        path.display(),
                        record.rel
                    ),
                );
            }
        }
    }
    record.settle(cfg, open_succeeded);
}

/// 差分層配下の実体へ**直接**書かれた1件（＝`copy_up`を経由しない書込）を、workspace側と
/// 同じ台帳キーで記録する予定を作る（[BUG-066](../../../docs/bugs/BUG-066.md)）。
/// 書くのは本当のopenの結果を見た[`finish_diff_layer_alias_write`]である（BUG-171）。
///
/// diff_layer_dirはサンドボックス子へRW付与されており、`<差分層>\<rel>`という綴りで書けば
/// ACLも通るしフックの誘導も要らない。実際にモデルが`Set-Content <差分層>\merge-demo.txt`を
/// 実行し、差分層には編集後の内容があるのに台帳が空＝`changes`/`apply`から見えない状態になった。
/// 同じ実ファイルを指す2通りの綴りなのだから、**同じ台帳キーの操作として記録する**。
/// baselineは`baseline_hash_for`が解決する（台帳に既存エントリがあればそれ、無ければ
/// 実workspace側の現在内容＝セッション開始時点の姿。workspaceはROなので後から変わらない）。
///
/// 同一パスの2回目以降はプロセス内の集合で抑止する（`copy_up`の`diff_layer_path.exists()`と同じ
/// 役割）。**集合へ入れるのも成功した後**——先に入れると、失敗した1回がその後の成功した書込の
/// 記録まで止める。兄弟プロセスや`copy_up`との重複追記は起こり得るが、`replay`はパス単位で畳むので
/// 実害は無い（初回のbaselineが権威という規律も`baseline_hash_for`側で保たれる）。
pub(crate) fn plan_diff_layer_alias_write(cfg: &Config, rel: &str) -> Option<PendingRecord> {
    if diff_layer_alias_already_recorded(rel) {
        return None;
    }
    Some(PendingRecord::first_touch(cfg, rel))
}

/// [`plan_diff_layer_alias_write`]の後始末。openが成功し、かつこのプロセスでまだ誰も書いて
/// いなければ台帳へ書く（同じパスを複数のスレッドが同時に開いたときに2行にしないため、
/// 集合への登録と書込の判定を1回の`insert`で行う）。
pub(crate) fn finish_diff_layer_alias_write(
    cfg: &Config,
    record: Option<PendingRecord>,
    open_succeeded: bool,
) {
    let Some(record) = record else {
        return;
    };
    let first = open_succeeded && diff_layer_alias_first_touch(&record.rel);
    record.settle(cfg, first);
}

// `copy_up`（`std::fs::copy`/`create_dir_all`）はWin32のCreateFileW等を経由するため、
// パッチ済みの`ntdll!NtCreateFile`/`NtOpenFile`を通って自分自身のフック関数へ再入する
// （このDLLだけでなくプロセス内の全呼び出し元がパッチ済みの実体を叩くため、フック関数の内部から
// 発行したファイルI/Oも同じフック関数へ戻ってくる）。`classify`はdiff_layer_dir配下を除外するため
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

/// `diff_layer_path`（DOS形式の絶対パス）を、NT名前空間で有効な`\??\`プレフィックス付きUTF-16
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
pub(crate) fn nt_path_wide(diff_layer_path: &Path) -> Vec<u16> {
    let normalized = diff_layer_path.to_string_lossy().replace('/', "\\");
    let nt_path = format!(r"\??\{normalized}");
    nt_path.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `object_attributes`を差分層側の完全パス（`diff_layer_wide`、`nt_path_wide`済み）へ向け直した
/// `OBJECT_ATTRIBUTES`/`UNICODE_STRING`のペアを組み立てる。呼び出し元は両方を同じスコープで
/// 保持し（`UNICODE_STRING.Buffer`が`diff_layer_wide`を指すため`diff_layer_wide`自体も生存させること）、
/// `oa.ObjectName = &mut name;`してから使うこと（Rustの借用は関数境界を越えて返せないため）。
/// 書込リダイレクト・読み取りリダイレクト（read-through）・属性照会リダイレクトの4箇所で
/// 同じ組み立てが必要なため一本化した（設計書§19.6/§19.7）。
pub(crate) unsafe fn build_redirected_oa(
    object_attributes: *const OBJECT_ATTRIBUTES,
    diff_layer_wide: &[u16],
) -> (
    OBJECT_ATTRIBUTES,
    windows::Win32::Foundation::UNICODE_STRING,
) {
    let mut redirected_oa = unsafe { *object_attributes };
    let redirected_name = windows::Win32::Foundation::UNICODE_STRING {
        Length: ((diff_layer_wide.len() - 1) * 2) as u16,
        MaximumLength: (diff_layer_wide.len() * 2) as u16,
        Buffer: windows::core::PWSTR(diff_layer_wide.as_ptr() as *mut u16),
    };
    redirected_oa.RootDirectory = HANDLE::default();
    (redirected_oa, redirected_name)
}

/// `rel`（workspace相対）の差分層側実体パスを返す（存在すれば）。読み取りread-through判定
/// （設計書§19.3/§19.7「削除済み＞差分層＞workspace」の中間段）に使う。
pub(crate) fn diff_layer_version_path(cfg: &Config, rel: &Path) -> Option<PathBuf> {
    let diff_layer_path = cfg.diff_layer_dir.join(rel);
    if diff_layer_path.is_file() {
        Some(diff_layer_path)
    } else {
        None
    }
}

/// ディレクトリの読み取りopen向けの read-through（BUG-128）。差分層 側に**ディレクトリとして**
/// 実体があり、かつ workspace 側に無いとき、その 差分層 ディレクトリのパスを返す。
///
/// **なぜ要るか**: git/MSYS は、このセッションで新規作成した 差分層 だけに在るディレクトリ
/// （例: `.github`・`.github/workflows`）を open して pathspec を解決したり中身を列挙したりする。
/// これをリダイレクトしないと、読取専用の workspace 側（そこには存在しない）を開こうとして
/// `STATUS_ACCESS_DENIED`／`OBJECT_PATH_NOT_FOUND` になり、`git add` が対象を見つけられず何も
/// ステージしない（実機ログで確認、`docs/bugs/BUG-128.md`）。
///
/// **workspace 側にも在るディレクトリは対象外（`None`）＝従来どおり素通し**。素通しでも open は
/// 成功し、列挙は `try_merged_dir_query` が 差分層 をマージするので、見え方は変わらない。ここで
/// 差分層 へ誘導するのは「差分層 にしか無い」場合だけに限る（既存挙動を変えないため）。
pub(crate) fn diff_layer_only_dir_path(cfg: &Config, rel: &Path) -> Option<PathBuf> {
    let diff_layer_path = cfg.diff_layer_dir.join(rel);
    if diff_layer_path.is_dir() && !cfg.workspace_root.join(rel).is_dir() {
        Some(diff_layer_path)
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
    let ledger_path = cfg.diff_layer_dir.join(COW_OPS_LEDGER_FILENAME);
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
/// 作成可能なdispositionでの再作成は`None`（通常処理へ継続）を返す。
///
/// **再作成でも、ここでは集合から外さない**（[BUG-172](../../../docs/bugs/BUG-172.md)、BUG-171と同じ形）。
/// 外れるのは、作り直しのopenが成功して台帳へ`Create`/`Modify`が書かれたとき
/// （[`append_ledger_entry`]）である。先に外していた頃は、作り直しのopenが失敗しても
/// 削除済みの印だけが消え、以後セッションの中からworkspaceの元のファイルが見えていた
/// （台帳は「削除済み」のまま＝一覧と見え方が食い違う）。呼び出し側は[`is_logically_deleted`]で
/// 「作り直しか」を知り、元の中身を写さない（[`CopySource::Nothing`]）。
pub(crate) fn check_deleted(cfg: &Config, rel: &str, allow_recreate: bool) -> Option<NTSTATUS> {
    if !is_deleted_after_refresh(cfg, rel) || allow_recreate {
        return None;
    }
    Some(STATUS_OBJECT_NAME_NOT_FOUND)
}

/// `rel`が論理削除済みか。兄弟プロセスが台帳へ書いた削除を先に取り込んでから見る
/// （[`check_deleted`]と同じ読み方。openの分岐は判定と写し元の選び方をこの1回の答えで行う）。
pub(crate) fn is_deleted_after_refresh(cfg: &Config, rel: &str) -> bool {
    refresh_deleted_set(cfg);
    is_logically_deleted(rel)
}

/// BUG-171: 台帳へ書くのは本当の操作が成功した後。フックは実プロセスへ注入しないと動かないので、
/// ここでは「操作の前に用意する側」と「結果を受けて書く側」の組を、結果を手で渡して固定する。
/// 実プロセスでの確認は CoW 行列の U・V・W（`crates/harness-cli/tests/tier2a_e2e.rs`）。
///
/// パス名は`bug171-`で始めて他のテストと重ねない——`baseline_hash_for`のキャッシュと
/// 差分層を直接開いたときの記録済み集合は、プロセスに1つしか無い。削除（`Delete`）は書かない
/// （削除済み集合もプロセスに1つで、別のテストがその中身を見ている）。
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cow_fixture as fixture, ledger_ops};

    /// 存在しないファイルを書込で開いて失敗した（削除のためのopenが「ファイルが無い」で返った）
    /// ときは、台帳に何も書かず、差分層にも何も残さない。作成できたopenなら`Create`を書く（許可側）。
    #[test]
    fn a_failed_open_of_a_missing_file_records_nothing_and_a_successful_one_records_create() {
        let (_ws, _diff_layer, cfg) = fixture();
        let rel = "bug171-missing.txt";
        let ws_path = cfg.workspace_root.join(rel);
        let diff_path = cfg.diff_layer_dir.join(rel);

        let prepared = copy_up(&cfg, rel, &ws_path, &diff_path, CopySource::Workspace);
        assert!(prepared.is_some(), "the first touch must prepare a record");
        finish_copy_up(&cfg, prepared, false);
        assert!(
            ledger_ops(&cfg, rel).is_empty(),
            "BUG-171: a failed open must not leave a create for a file that was never made"
        );
        assert!(!diff_path.exists());

        let prepared = copy_up(&cfg, rel, &ws_path, &diff_path, CopySource::Workspace);
        std::fs::write(&diff_path, "created by the real open").unwrap();
        finish_copy_up(&cfg, prepared, true);
        assert_eq!(ledger_ops(&cfg, rel), [ChangeOp::Create]);
    }

    /// 既存ファイルを写した後でopenが失敗したら、写した実体を消す。残すと次の書込が
    /// 「既に触った」と判定されて台帳に載らない（`apply`が適用済みの実体を消すのと同じ理由、BUG-034）。
    #[test]
    fn a_failed_open_after_copying_rolls_back_the_copy_so_the_next_write_is_recorded() {
        let (_ws, _diff_layer, cfg) = fixture();
        let rel = "bug171-existing.txt";
        let ws_path = cfg.workspace_root.join(rel);
        let diff_path = cfg.diff_layer_dir.join(rel);
        std::fs::write(&ws_path, "base").unwrap();

        let prepared = copy_up(&cfg, rel, &ws_path, &diff_path, CopySource::Workspace);
        assert!(
            diff_path.is_file(),
            "copy_up must copy the existing file before the open (the open needs it)"
        );
        finish_copy_up(&cfg, prepared, false);
        assert!(
            ledger_ops(&cfg, rel).is_empty(),
            "BUG-171: a failed open must not leave a modify"
        );
        assert!(
            !diff_path.exists(),
            "the copy made for the failed open must be removed"
        );

        let prepared = copy_up(&cfg, rel, &ws_path, &diff_path, CopySource::Workspace);
        assert!(
            prepared.is_some(),
            "after the rollback, the next write must count as the first touch again"
        );
        finish_copy_up(&cfg, prepared, true);
        assert_eq!(ledger_ops(&cfg, rel), [ChangeOp::Modify]);
        assert_eq!(std::fs::read_to_string(&diff_path).unwrap(), "base");
    }

    /// BUG-172: このセッションで消したパスを作り直すときは、workspaceに元のファイルが在っても
    /// 写さない（作り直したファイルは空から始まる）。記録は元が在ったので`Modify`（元の中身の指紋つき）
    /// ——`apply`はその指紋で本物が変わっていないことを確かめてから、新しい中身で置き換える。
    #[test]
    fn recreating_a_deleted_path_does_not_copy_the_original_back() {
        let (_ws, _diff_layer, cfg) = fixture();
        let rel = "bug172-recreated.txt";
        let ws_path = cfg.workspace_root.join(rel);
        let diff_path = cfg.diff_layer_dir.join(rel);
        std::fs::write(&ws_path, "original").unwrap();

        let prepared = copy_up(&cfg, rel, &ws_path, &diff_path, CopySource::Nothing);
        assert!(
            !diff_path.exists(),
            "BUG-172: the original must not be copied back for a recreate"
        );
        std::fs::write(&diff_path, "new").unwrap(); // 作り直しのopenが作ったもの
        finish_copy_up(&cfg, prepared, true);
        assert_eq!(ledger_ops(&cfg, rel), [ChangeOp::Modify]);
        assert_eq!(std::fs::read_to_string(&diff_path).unwrap(), "new");
    }

    /// 差分層を直接開く経路も同じ組。失敗した回は書かず、**記録済みの印も付けない**
    /// ——付けると、その後の成功した書込が記録されない。成功した2回目は1行だけ書く。
    #[test]
    fn a_failed_diff_layer_alias_open_neither_records_nor_marks_the_path() {
        let (_ws, _diff_layer, cfg) = fixture();
        let rel = "bug171-alias.txt";

        let planned = plan_diff_layer_alias_write(&cfg, rel);
        assert!(planned.is_some());
        finish_diff_layer_alias_write(&cfg, planned, false);
        assert!(ledger_ops(&cfg, rel).is_empty(), "BUG-171");

        let planned = plan_diff_layer_alias_write(&cfg, rel);
        assert!(
            planned.is_some(),
            "a failed open must not mark the path as already recorded"
        );
        finish_diff_layer_alias_write(&cfg, planned, true);
        assert_eq!(ledger_ops(&cfg, rel), [ChangeOp::Create]);
        assert!(
            plan_diff_layer_alias_write(&cfg, rel).is_none(),
            "once recorded, later touches in this process are not recorded again"
        );
    }
}
