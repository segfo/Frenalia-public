//! workspace本体（`preflight`が毎回付与するRW/RO継承ACE）とCoW diff_layer_dirの生存管理。
//!
//! 「今このworkspace/diff_layer_dirを使っている他のharnessセッションが生きているか」の判定に、
//! プロセスIDを台帳へ書いて自分でliveness確認する方式ではなく、Windowsの**名前付きmutex**を
//! 使う。名前付きmutexは、作成したプロセスが（正常終了でもクラッシュでも）いなくなると
//! Windows自身が自動的にオブジェクトを破棄するため、「まだ誰かが開いているか」を
//! `OpenMutexW`で聞くだけでliveness確認ができ、PID生存確認のような手作業のロジックが要らない。
//!
//! workspaceには、アクセスモード別に名前を分けたmutexを用意する（[`KNOWN_MODES`]）。同じ
//! workspaceに対して異なるモード（例: 通常起動のRWXと`--sandbox tier2a-cow`のRO）を同時に
//! 動かすことは、[`begin_workspace_mode`]が起動時に他モードの生存を確認して拒否している。
//!
//! ## 拒否の根拠（**2026-08-26に事実へ合わせて書き直した**）
//!
//! **旧・記述は「ACE（ファイルに1つしか付けられない）の意味がセッション間で食い違うため」
//! だったが、括弧の中が事実と違う。** DACLには同じファイルへ複数の主体宛ACEが同時に載り、
//! 互いに干渉せず独立に効く（`plans/handoff/fs-boundary-cost/T-1.md`が実測。同一ノードで
//! 上限1,168本まで載ることも`plans/mac-spike/RESULTS.md` §S15-3が測っている）。
//! 実際、[D-84](../../../../plans/DESIGN-SANDBOX-APPPOLICY.md)以降は**両モードのcapability SID宛ACEが
//! 常に同時に載っている**——それでも`ro`のcapability SIDしか持たない子は書けない（トークンに無い主体宛の
//! ACEはアクセス判定で読み飛ばされる）。
//!
//! **残る根拠はACLではなく一貫性である。** `--sandbox tier2a-cow`のセッションは
//! 「workspace本体は動かない」を前提に差分層を積む。同じworkspaceで並走するRWXセッションが
//! 本体を書き換えると、その差分は**動く土台の上に積まれた**ものになり、`harness cow apply`が
//! 何へ適用されるのかを言えなくなる。
//!
//! **規則そのものを残すか撤廃するかは、ここでは決めていない**（`plans/handoff/fs-boundary-cost/U-2.md`
//! 「本流が決めること」）。この節が直したのは**根拠の文**だけである。
//!
//! CoW diff_layer_dirはセッション専有なので、セッションIDを名前に含めたmutexを1つ持つだけでよい
//! （他モードとの衝突チェックは不要、生きているかどうかの確認にのみ使う）。
//!
//! この生存確認とは別に、`workspace-grant-ledger.json`へ「これまで許可を付けたことがある
//! workspaceパス」を記録する。こちらは`harness fs list`/`revoke-workspace-all`が対象を
//! 列挙するための一覧に過ぎず、安全性（撤収してよいか）の判定には使わない
//! （安全性は常にmutexで判定する）。

use std::path::{Path, PathBuf};

// 生存確認そのもの（`mutex_exists`・`hold_mutex_for_process_lifetime`）は、同じ手法を使う
// `loopback_exemption`と共有するため`crate::win_common`が持つ（規則5・コピーを作らない）。
use crate::win_common::{hold_mutex_for_process_lifetime, mutex_exists};

/// workspaceのアクセスモード。**「このworkspaceへ何を許すか」の語彙**であって、
/// 「いまどのモードで走っているか」ではない——[D-84]以降、`preflight`は**全モードのcapability SID宛
/// ACEを毎回まとめて配る**ので、走っているモードと配るモードは別の話になった。
///
/// # なぜ文字列ではなく型なのか
///
/// モードごとに決まる事実が2つある——**mutexの名前**（ここ）と**ツリーへ配るアクセスマスク**
/// （`win_appcontainer::workspace_mode_mask`）。文字列で持つと、モードを1つ足したときに
/// **どちらか片方だけ追随する**（`B-06`: 不変条件を変えたら全経路を数えたか）。
/// 列挙にしておけば、バリアントを足した瞬間にマスク側の`match`が非網羅になって
/// **コンパイルが落ちる**——数え上げを人間の記憶から外すのがここの目的である。
///
/// 台帳（`workspace_capability`）とmutex名には[`Self::as_str`]の値がそのまま載るので、
/// **綴りを変えると既存の台帳エントリと突き合わなくなる**（変えないこと）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceMode {
    /// 通常起動。workspace本体へ直接書ける（`WorkspaceWriteMode::DirectRw`）。
    Rwx,
    /// `--sandbox tier2a-cow`。workspace本体は読取専用で、書込はCoW差分層へ逃がす。
    Ro,
}

impl WorkspaceMode {
    /// **全モード**。[D-84]で両モードのcapability SID宛ACEを配る側と、`harness fs revoke-workspace`が
    /// 剥がす側の**両方**がここを回る（`B-01`: 付与と撤収を同じ一覧から引く）。
    pub const ALL: [WorkspaceMode; 2] = [Self::Rwx, Self::Ro];

    /// 台帳・mutex名に載る綴り。**既存の台帳と突き合うので変えないこと。**
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rwx => "rwx",
            Self::Ro => "ro",
        }
    }

    /// 台帳から読み出した綴りを型へ戻す。知らない綴り（将来の版が書いた・手で壊された）は
    /// `None`——**勝手にどれかへ倒さない**（倒すと、知らないモードのACEを別モードのマスクで
    /// 上書きし得る）。
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == s)
    }
}

/// 現在サポートするworkspaceアクセスモードの**綴りの一覧**（[`WorkspaceMode::ALL`]の文字列版）。
///
/// 型が使える場所では[`WorkspaceMode`]を使うこと。ここが残っているのは、台帳の欄が
/// `String`で、綴りの側で突き合わせる呼び出しがあるためである。**2つが食い違わないことは
/// `the_string_vocabulary_matches_the_enum`が固定する。**
pub const KNOWN_MODES: &[&str] = &["rwx", "ro"];

#[cfg(test)]
mod mode_vocabulary_tests {
    use super::*;

    /// [`KNOWN_MODES`]と[`WorkspaceMode::ALL`]は**同じ集合を同じ順で**表す。
    ///
    /// 2つある理由は台帳の欄が`String`だからで、**同じ事実の綴りが2箇所にある**（`B-05`）。
    /// 片方だけにモードを足すと、たとえば`fs revoke-workspace`は新しいモードのcapability SIDを
    /// 引かないまま「全部剥がした」と報告する——**剥がせないACEが残る**（BUG-101と同型）。
    /// コンパイラはここを守らないので、テストで固定する。
    #[test]
    fn the_string_vocabulary_matches_the_enum() {
        let from_enum: Vec<&str> = WorkspaceMode::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            from_enum, KNOWN_MODES,
            "KNOWN_MODESとWorkspaceMode::ALLがずれている。モードを足すときは両方に足すこと"
        );
    }

    /// 往復する（許可側）。**`parse`が常に`None`を返す実装でも上のテストは緑になる**ので
    /// 対で置く（`B-35`）。
    #[test]
    fn every_mode_round_trips_through_its_spelling() {
        for mode in WorkspaceMode::ALL {
            assert_eq!(WorkspaceMode::parse(mode.as_str()), Some(mode));
        }
    }

    /// 拒否側。知らない綴りはどれにも倒さない。
    #[test]
    fn an_unknown_spelling_does_not_fall_back_to_a_mode() {
        assert_eq!(WorkspaceMode::parse("rx"), None);
        assert_eq!(WorkspaceMode::parse("RWX"), None);
        assert_eq!(WorkspaceMode::parse(""), None);
    }
}

/// パスをWindowsカーネルオブジェクト名として安全に使える文字列へ変換する（英数字以外は`_`）。
/// 呼び出し元は事前にcanonicalizeしたパスを渡すこと（大文字小文字・相対/絶対の違いによる
/// 意図しない別名化を防ぐため）。
fn sanitize_path_for_object_name(path: &Path) -> String {
    path.to_string_lossy()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn mode_mutex_name(path_key: &str, mode: &str) -> String {
    format!("Local\\harness-ws-{mode}-{path_key}")
}

fn setup_lock_name(path_key: &str) -> String {
    format!("Local\\harness-ws-setup-{path_key}")
}

/// `path`（canonicalize済み）に対して`mode`でのアクセスを開始してよいか確認し、よければ
/// そのモード専用のmutexを作ってプロセス終了まで保持する。他のモードが既に使用中なら
/// `Err`で理由を返し、呼び出し元（`preflight`）は起動を拒否する。
///
/// 「他モードの生存確認」と「自モードのmutex作成」の2手順は、`with_named_lock`（1個の
/// セットアップ用ロック）で挟んで直列化する。挟まないと、2つのharnessプロセスがほぼ同時に
/// 異なるモードで起動した場合、どちらも「他モードは無い」と同時に判定してしまいチェックを
/// すり抜ける（早い者勝ちの事故）。セットアップ用ロックは処理中だけ保持しすぐ解放され、
/// 長期保持するのは自モードのmutexだけになる。
pub fn begin_workspace_mode(path: &Path, mode: &str) -> Result<(), String> {
    debug_assert!(
        KNOWN_MODES.contains(&mode),
        "unknown workspace mode: {mode}"
    );
    let key = sanitize_path_for_object_name(path);
    crate::with_named_lock(&setup_lock_name(&key), || {
        for other in KNOWN_MODES.iter().filter(|m| **m != mode) {
            if mutex_exists(&mode_mutex_name(&key, other)) {
                return Err(format!(
                    "workspace {} is already in use in '{other}' mode by another harness \
                     session; cannot start in '{mode}' mode concurrently (mixing access modes \
                     on the same workspace is not allowed)",
                    path.display()
                ));
            }
        }
        hold_mutex_for_process_lifetime(&mode_mutex_name(&key, mode))
            .map_err(|e| format!("failed to create workspace mode marker: {e}"))
    })
}

/// `path`について、いずれかのモードのmutexが今も生きているか（＝使用中のセッションが
/// あるか）。生きているモード名の一覧を返す（空なら安全に撤収してよい）。
pub fn live_modes(path: &Path) -> Vec<&'static str> {
    let key = sanitize_path_for_object_name(path);
    KNOWN_MODES
        .iter()
        .copied()
        .filter(|mode| mutex_exists(&mode_mutex_name(&key, mode)))
        .collect()
}

/// CoW diff_layer_dirはセッション専有のため、セッションIDだけで名前が決まる。
fn cow_session_mutex_name(session_id: &str) -> String {
    format!("Local\\harness-cow-{session_id}")
}

/// `--sandbox tier2a-cow`起動時に呼ぶ。セッション専用mutexを作ってプロセス終了まで保持する。
pub fn hold_cow_session_marker(session_id: &str) -> windows::core::Result<()> {
    hold_mutex_for_process_lifetime(&cow_session_mutex_name(session_id))
}

/// そのセッションのCoW diff_layer_dirがまだ使用中（＝そのセッションのharnessプロセスが
/// 生きている）かどうか。
pub fn cow_session_is_live(session_id: &str) -> bool {
    mutex_exists(&cow_session_mutex_name(session_id))
}

// --- workspace一覧台帳（安全性判定には使わない、`fs list`/`revoke-workspace-all`用） ---

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceLedgerEntry {
    pub path: String,
    pub mode: String,
    pub granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceLedger {
    pub entries: Vec<WorkspaceLedgerEntry>,
}

/// ファイル入出力（誤削除防止の2層・fail-open）は`harness-grant-ledger`の`Ledger<T>`が持つ。
///
/// この台帳は一覧表示専用で安全性判定には使わない（安全性は常に名前付きmutexで判定する、
/// モジュールdoc参照）が、`Local\harness-workspace-grant-ledger`でread-modify-writeを
/// 直列化する（`fs-passthrough-ledger.json`/`tier3-vm-ledger.json`と同じ方針、R-01）。
fn ledger() -> &'static harness_grant_ledger::Ledger<WorkspaceLedger> {
    static LEDGER: std::sync::OnceLock<harness_grant_ledger::Ledger<WorkspaceLedger>> =
        std::sync::OnceLock::new();
    LEDGER.get_or_init(|| {
        harness_grant_ledger::Ledger::in_config_dir(
            "workspace-grant-ledger.json",
            Some("Local\\harness-workspace-grant-ledger"),
        )
    })
}

pub fn load_workspace_ledger() -> WorkspaceLedger {
    ledger().load()
}

pub fn save_workspace_ledger(ledger_value: &WorkspaceLedger) {
    ledger().save(ledger_value);
}

/// `preflight`成功時に呼ぶ。台帳は一覧表示専用なので、既存エントリは単純に上書きする
/// （安全性判定には使わないため、モードの食い違い自体はここでは警告のみに留める）。
pub fn record_workspace_grant(path: &Path, mode: &str) {
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = harness_grant_ledger::now_unix_secs();
    ledger().update(|l| {
        if let Some(entry) = l
            .entries
            .iter_mut()
            .find(|e| harness_grant_ledger::same_ledger_path(&e.path, &path_str))
        {
            entry.mode = mode.to_string();
            entry.granted_at_unix_secs = granted_at;
        } else {
            l.entries.push(WorkspaceLedgerEntry {
                path: path_str,
                mode: mode.to_string(),
                granted_at_unix_secs: granted_at,
            });
        }
    });
}

pub fn remove_workspace_entry(path: &Path) {
    let path_str = path.to_string_lossy().into_owned();
    ledger().update(|l| {
        l.entries
            .retain(|e| !harness_grant_ledger::same_ledger_path(&e.path, &path_str))
    });
}

/// `should_remove`がtrueを返したパスのエントリを落とす（`harness fs prune`、D-53）。
/// 返り値は実際に落としたパスの一覧。
///
/// **判定は呼び出し側が持ち、本関数はロックと永続化だけを持つ。** 台帳ファイルを所有するのは
/// このモジュールなので、CLI側で`load`→`save`する形にはしない（複数`harness.exe`同時起動下の
/// lost updateを避ける、R-01）。
///
/// この台帳は`preflight`成功のたびに追記される一方、撤収（`revoke-workspace`）を明示的に
/// 呼ばない限り誰も消さないため、使い捨てワークスペースを繰り返すと際限なく積もる
/// （実測で1,043件・155KB）。**使用中かどうかの判定はここでは行わない**——生存判定は常に
/// 名前付きmutex（[`live_modes`]）が持つというモジュールdocの方針を崩さないためで、
/// そもそも実在しないパスに生きたセッションは在り得ない。
pub fn prune_workspace_entries(should_remove: impl Fn(&Path) -> bool) -> Vec<String> {
    ledger().update(|l| {
        let mut removed = Vec::new();
        l.entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        removed
    })
}

// --- CoW diff_layer_dirのセッションメタデータ・列挙（`harness cow`サブコマンド用） ---

/// diff_layer_dir直下に置く、セッションの由来（どのworkspaceのものか）を記録する小さなマーカー
/// ファイル。diff_layer_dirがどこにあっても自己完結して読めるように、グローバル台帳ではなく
/// diff_layer_dir自身の中に置く（台帳が壊れる/消えても`workspace_root`が分からなくならないため）。
pub const COW_SESSION_META_FILENAME: &str = ".harness-cow-session.json";

/// D-80のレビュー・ライフサイクル上の位置。**GCが「回収してはいけない」を知る唯一の材料**。
///
/// D-80は「差分層の`.git`→実リポジトリのレビュー用refへ`git fetch`→人が自分のエディタで
/// 読む→承認してmerge」と決めた。その途中にある差分層を回収すると、**人がまだ見ていない
/// エージェントの作業が黙って消える**。実装（分流T-C）はこの欄を埋めるだけでよく、
/// 埋め忘れても穴が開かない向きにしてある——GCは`Pending`を回収しないだけでなく、
/// **この型を解釈できない形のmetaも回収しない**（[`CowMetaRead::Unreadable`]）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CowReviewState {
    /// レビューへ出した（fetch済み）が、まだ承認も破棄もされていない。**回収しない。**
    Pending {
        review_ref: String,
        fetched_at_unix_secs: u64,
    },
    /// 承認（merge）または破棄まで済んだ。差分層としては用済み。
    Settled { settled_at_unix_secs: u64 },
}

/// diff_layer_dir直下のセッションメタ。
///
/// **`deny_unknown_fields`が効いている理由を消さないこと。** 新しいharnessが書いたmetaを
/// 古いharnessが読むと、知らない欄があるだけで**パースが失敗する**。失敗は
/// [`CowMetaRead::Unreadable`]になり、GCは「判定不能なので回収しない」へ倒れる——
/// つまり将来この構造体へ欄が増えても、**古いバイナリが新しい意味を取りこぼして
/// 消してしまうことがない**（前方安全）。緩めると、たとえばT-Cが足したレビュー状態を
/// 古いharnessが「無い＝レビュー中でない」と読んで回収する。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowSessionMeta {
    pub session_id: String,
    pub workspace_root: String,
    pub created_at_unix_secs: u64,
    /// D-80のレビュー状態。無い＝一度もレビューへ出していない。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<CowReviewState>,
    /// D-81で差分層をワークスペースのボリュームへ置けず`%LOCALAPPDATA%`へ戻した理由。
    /// 後から「なぜこの差分層だけ別ボリュームに居るのか」を追えるようにするために残す。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_layer_root_fell_back: Option<String>,
}

/// [`read_cow_session_meta`]の結果。**3値であることが要点。**
///
/// 以前は`Option<CowSessionMeta>`で、「ファイルが無い」と「壊れている／知らない形」が
/// どちらも`None`へ潰れていた。GCにとってこの2つは**正反対の意味**を持つ——
/// 前者は「何も無い殻」なので回収してよく、後者は「中身が読めていない」ので回収してはいけない。
/// 潰したままGCを載せると、壊れたmetaを持つ差分層が優先的に消える。
#[derive(Debug, Clone)]
pub enum CowMetaRead {
    Ok(Box<CowSessionMeta>),
    /// メタファイルが存在しない。
    Absent,
    /// 存在するが読めない・解釈できない（壊れている、または**このバイナリが知らない形**）。
    Unreadable(String),
}

impl CowMetaRead {
    /// 中身が要るだけの呼び出し向け（表示など）。**GCはこれを使わないこと**——
    /// `Absent`と`Unreadable`が再び潰れる。
    pub fn ok(&self) -> Option<&CowSessionMeta> {
        match self {
            CowMetaRead::Ok(m) => Some(m),
            _ => None,
        }
    }
}

/// `preflight`が`--sandbox tier2a-cow`のdiff_layer_dir作成直後に呼ぶ。
///
/// **既にレビュー状態が書かれていたら消さない。** 同じセッションIDで再開（`--resume`）すると
/// ここがもう一度走るので、素直に上書きするとD-80のレビュー待ちが**起動しただけで消える**
/// ——次のGCがその差分層を回収してよいものと判定する。既存を読んで引き継ぐ。
pub fn write_cow_session_meta(diff_layer_dir: &Path, workspace_root: &Path, session_id: &str) {
    let existing = read_cow_session_meta(diff_layer_dir);
    // 読めないmetaは**上書きしない**。中身が分からないものを、分かっているつもりの値で
    // 潰すと、判定不能（＝回収しない）だったものが判定可能（＝回収してよい）へ変わる。
    if matches!(existing, CowMetaRead::Unreadable(_)) {
        return;
    }
    let previous = existing.ok().cloned();
    let meta = CowSessionMeta {
        session_id: session_id.to_string(),
        workspace_root: workspace_root.to_string_lossy().into_owned(),
        created_at_unix_secs: previous
            .as_ref()
            .map(|p| p.created_at_unix_secs)
            .unwrap_or_else(harness_grant_ledger::now_unix_secs),
        review: previous.as_ref().and_then(|p| p.review.clone()),
        diff_layer_root_fell_back: previous.and_then(|p| p.diff_layer_root_fell_back),
    };
    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = std::fs::write(diff_layer_dir.join(COW_SESSION_META_FILENAME), json);
    }
}

/// セッションメタを読む。**`Absent`と`Unreadable`を区別して返す**（[`CowMetaRead`]のdoc参照）。
pub fn read_cow_session_meta(diff_layer_dir: &Path) -> CowMetaRead {
    let path = diff_layer_dir.join(COW_SESSION_META_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(s) => match serde_json::from_str::<CowSessionMeta>(&s) {
            Ok(meta) => CowMetaRead::Ok(Box::new(meta)),
            Err(e) => CowMetaRead::Unreadable(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CowMetaRead::Absent,
        Err(e) => CowMetaRead::Unreadable(format!("{}: {e}", path.display())),
    }
}

/// CoW差分層の根（複数）とセッションID→置き場の写像は
/// [`crate::session_scope`]が正本である。ここから再公開しているのは、`harness cow`系
/// サブコマンドがこのモジュール越しに引いているためで、**定義を2つ持たないことが目的**
/// （`bug-pattern-rules` B-05）。
pub use crate::session_scope::{cow_profile_diff_layer_root, cow_diff_layer_dir_in, cow_diff_layer_roots};

/// 見つかった差分層1件（棚卸しの単位）。
///
/// **IDだけを返す形にしない。** D-81で根が複数になったので、IDから置き場を引き直すには
/// 全根を探す必要がある——呼び出し側にそれをやらせると、根の組み立てが各所へ散る
/// （B-05）。見つけた時点の置き場をそのまま持って回る。
#[derive(Debug, Clone)]
pub struct CowSessionDir {
    pub session_id: String,
    pub diff_layer_dir: PathBuf,
}

/// これまでに作られた全セッションの差分層を、**全部の根**から列挙する。
///
/// 2つ目の返り値は「到達できなかったボリュームの数」。0件という結果が
/// 「本当に無い」のか「材料が見えていない」のかを呼び出し側が区別できるようにするため、
/// **黙って飛ばさない**（`shared-state-exclusion` 問6）。
pub fn list_cow_sessions() -> (Vec<CowSessionDir>, usize) {
    let (roots, unreachable) = cow_diff_layer_roots();
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Ok(session_id) = entry.file_name().into_string() else {
                continue;
            };
            found.push(CowSessionDir {
                diff_layer_dir: entry.path(),
                session_id,
            });
        }
    }
    (found, unreachable)
}

/// `diff_layer_dir`配下にあるファイルの相対パス一覧を返す（CoW自身の帳簿は除外する）。
/// diff_layer_dirには実際に触られたファイルしか存在しないため、この一覧がそのままworkspace本体
/// に対する変更点になる。
///
/// 走査規則は`harness_change_ledger::store::scan_diff_layer_content_files`が唯一の実装
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。以前はここに独自の走査があり、除外していたのが
/// セッションメタと操作台帳の2つだけだったため、denied/warnings台帳やbaselineミラーまで
/// 「変更されたファイル」として数えていた（`harness cow list`の`changed_files=`が過大）。
pub fn list_cow_diff_layer_files(diff_layer_dir: &Path) -> Vec<PathBuf> {
    harness_change_ledger::store::scan_diff_layer_content_files(diff_layer_dir)
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

/// `diff_layer_dir`直下の操作台帳（`.harness-cow-ops.jsonl`）を読み、現在の論理的な変更一覧を返す
/// （`harness changes`・apply/discardの入力）。CoW一本化（Phase 2）により、実体は
/// `harness_change_ledger::store::replay_ledger`（`--staged`のオーバーレイディレクトリにも
/// 同じ関数を使う、`SandboxFs::change_set`参照）そのもの。台帳が無ければ空（変更なし）を返す。
pub fn read_cow_ledger(diff_layer_dir: &Path) -> Vec<harness_change_ledger::CowChange> {
    harness_change_ledger::store::replay_ledger(diff_layer_dir)
}

/// `apply`が実際にworkspace本体へ反映した`applied_paths`を台帳から取り除く（適用済みの
/// 変更が`harness changes`に永続的に残り続けるのを防ぐ）。実体は`store::prune_ledger`。
pub fn prune_cow_ledger(diff_layer_dir: &Path, applied_paths: &[String]) -> std::io::Result<()> {
    harness_change_ledger::store::prune_ledger(diff_layer_dir, applied_paths);
    Ok(())
}

// --- 差分層の回収（GC、D-82） -----------------------------------------------------------

/// 「差分層を作る」と「差分層を掃く」を直列化するロックの名前。
///
/// **両側で取らなければ意味が無い。** `preflight`（と`session_scope`の切替経路）は
/// `create_dir_all(差分層)` → ACE付与 → メタ書込 → **最後に**生存マーカー、の順で進むので、
/// その間ずっと「ディレクトリは在るが生存マーカーはまだ無い」窓が開いている。並行して走る
/// 別の`harness.exe`のGCがこの窓を覗くと**起動しかけのセッションが空の殻に見える**。
/// 掃く側だけがロックを取っても、何も直列化されない（`bug-pattern-rules` B-18・
/// `shared-state-exclusion` 問1）。
pub const COW_GC_LOCK_NAME: &str = "Local\\harness-cow-gc";

/// 作成からこの秒数が経つまでは回収しない（既定1時間）。
///
/// **これは主たる機構ではなく保険である。** 起動しかけとの競合を本当に止めているのは
/// [`COW_GC_LOCK_NAME`]の方で、こちらは`with_named_lock`が**ロックを取れなかったときに
/// ロック無しで処理を実行する**（fail-open、`harness-grant-ledger`のdoc）ことへの二重の網。
/// ロックだけに預けると、その fail-open の日に起動しかけの差分層が消える。
pub const COW_GC_DEFAULT_GRACE_SECS: u64 = 60 * 60;

/// 差分層1つについて、判定に要る事実だけを集めたもの。
///
/// **Win32もFSも型に含めない。** 採取（[`collect_cow_session_facts`]）と判定
/// （[`plan_cow_gc`]）を分けてあるので、判定は`cargo test`で普通に検算できる。
/// 同じ理由で純関数にしてある`session_profile::without_session`の前例に倣う。
#[derive(Debug, Clone)]
pub struct CowSessionFacts {
    pub session_id: String,
    pub diff_layer_dir: PathBuf,
    /// 生存マーカー（名前付きmutex）が在る＝そのセッションのharnessがまだ動いている。
    pub is_live: bool,
    /// メタが壊れている、または**このバイナリが知らない形**をしている。
    pub meta_unreadable: bool,
    /// D-80のレビュー待ち（fetch済み・未承認）。
    pub review_pending: bool,
    /// 操作台帳を再生して残る変更の件数。
    pub pending_changes: usize,
    /// 差分層配下に実在する内容ファイルの件数（台帳に記録されていない直書きも含む）。
    pub content_files: usize,
    /// メタの作成時刻。メタが無い／読めない場合は**ディレクトリの更新時刻で代用する**
    /// （採取側の責務）。起動しかけの差分層はまだメタを持たないので、ここが埋まらないと
    /// grace が効かない。
    pub created_at_unix_secs: u64,
    /// 元のワークスペース（表示用。判定には使わない）。
    pub workspace_root: Option<String>,
    /// この差分層が**ネットワーク上のボリューム**に載っているか。
    ///
    /// 判定そのものは[`plan_cow_gc`]が設定（[`CowGcPolicy`]）と突き合わせて行う。ここは
    /// **観測された事実だけ**を持つ——事実の採取と規則の適用を混ぜないための分け方である。
    pub volume_is_remote: bool,
}

/// 回収の方針。**既定が安全側**であることが要点で、設定を読まない呼び出し元でも
/// ネットワーク上の差分層は保護される。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowGcPolicy {
    /// ネットワーク上のボリュームにある差分層を自動回収から外す。
    pub protect_network_volumes: bool,
}

impl Default for CowGcPolicy {
    fn default() -> Self {
        Self {
            protect_network_volumes: true,
        }
    }
}

/// 差分層1つに対する判定。**回収してよいのは[`CowGcVerdict::Collect`]だけ**で、
/// 残りは全部「なぜ残したか」を表す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowGcVerdict {
    /// 何も残っていない殻。回収する。
    Collect,
    /// そのセッションがまだ動いている。
    KeepRunning,
    /// **設定で「消さない」と宣言されている置き場にある。**
    ///
    /// 例外の分岐ではなく、他の状態と同じ1本の判定として通る——回収を呼ぶ側が
    /// 「ここだけ特別に飛ばす」を書かずに済み、経路が増えても掛け忘れが起きない。
    KeepProtected,
    /// D-80のレビュー待ち。**人がまだ見ていない。**
    KeepReviewPending,
    /// メタが読めない＝中身の意味が分からない。
    KeepUndecidable,
    /// 未適用の変更を抱えている。自動では消さない（明示指定でのみ回収対象になる）。
    KeepHasChanges,
    /// 作ったばかり。起動しかけとの競合を避けるため見送る。
    KeepTooYoung,
}

impl CowGcVerdict {
    pub fn collects(self) -> bool {
        matches!(self, CowGcVerdict::Collect)
    }

    /// 「変更を抱えているだけ」か。`harness cow gc --with-changes`が対象を広げる先。
    pub fn is_only_holding_changes(self) -> bool {
        matches!(self, CowGcVerdict::KeepHasChanges)
    }

    /// 人へ見せる理由（`shared-state-exclusion` 問6: 見送りを黙らせない）。
    pub fn reason(self) -> &'static str {
        match self {
            CowGcVerdict::Collect => "nothing left in it",
            CowGcVerdict::KeepRunning => "that session is still running",
            CowGcVerdict::KeepProtected => {
                "it is on a network volume, which is protected from automatic collection by                  default (set cow.gc.protect_network_volumes=false in your user settings.json                  to allow it)"
            }
            CowGcVerdict::KeepReviewPending => {
                "waiting for review (D-80); nobody has looked at it yet"
            }
            CowGcVerdict::KeepUndecidable => {
                "its session metadata cannot be read, so what it holds is unknown"
            }
            CowGcVerdict::KeepHasChanges => "it still holds unapplied changes",
            CowGcVerdict::KeepTooYoung => "it was created just now (a session may be starting up)",
        }
    }
}

/// 回収してよいものを決める**規則そのもの**（純関数）。
///
/// # 迷ったら回収しない
///
/// ここで守っているのはセキュリティ境界ではなく事故防止のガードだが、**ガードしている操作が
/// 「削除」で不可逆**なので、`shared-state-exclusion` の既定（ガードは通す側へ倒す）とは
/// 逆に倒す。残す代償はKB単位、消す代償はエージェントの作業の消失である。
///
/// 判定の順序は「残す理由が強いものから」。同じ差分層が複数の理由に当たることは普通にあり、
/// 報告に出るのは最初に当たった1つなので、**人が次に取る手が変わる順**に並べてある
/// （動いている→待てばよい／レビュー待ち→見ればよい／読めない→調べる／変更あり→applyするか捨てる）。
pub fn plan_cow_gc(
    facts: &[CowSessionFacts],
    now_unix_secs: u64,
    grace_secs: u64,
    policy: CowGcPolicy,
) -> Vec<(String, CowGcVerdict)> {
    facts
        .iter()
        .map(|f| {
            let verdict = if f.is_live {
                CowGcVerdict::KeepRunning
            } else if policy.protect_network_volumes && f.volume_is_remote {
                CowGcVerdict::KeepProtected
            } else if f.review_pending {
                CowGcVerdict::KeepReviewPending
            } else if f.meta_unreadable {
                CowGcVerdict::KeepUndecidable
            } else if f.pending_changes > 0 || f.content_files > 0 {
                CowGcVerdict::KeepHasChanges
            } else if now_unix_secs.saturating_sub(f.created_at_unix_secs) < grace_secs {
                CowGcVerdict::KeepTooYoung
            } else {
                CowGcVerdict::Collect
            };
            (f.session_id.clone(), verdict)
        })
        .collect()
}

/// 実在する全差分層について、判定に要る事実を集める（採取側。Win32とFSに触る）。
pub fn collect_cow_session_facts() -> (Vec<CowSessionFacts>, usize) {
    let (dirs, unreachable) = list_cow_sessions();
    // ボリューム種別の問い合わせは**根ごとに1回**。セッション数ぶん撃つと、
    // 差分層が数百件ある環境で起動時スイープが目に見えて重くなる。
    let mut volume_is_remote: std::collections::HashMap<PathBuf, bool> =
        std::collections::HashMap::new();
    let facts = dirs
        .into_iter()
        .map(|d| {
            let root = d
                .diff_layer_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| d.diff_layer_dir.clone());
            let is_remote = *volume_is_remote.entry(root.clone()).or_insert_with(|| {
                #[cfg(windows)]
                {
                    // **採れなければ「リモートかもしれない」側へ倒す。** ここで守っているのは
                    // 削除しないことなので、分からないなら保護する方が安全である。
                    crate::win_common::volume_mount_point_of(&root)
                        .and_then(|m| crate::win_common::volume_capability(&m))
                        .map(|c| c.is_remote)
                        .unwrap_or(true)
                }
                #[cfg(not(windows))]
                {
                    false
                }
            });
            let meta = read_cow_session_meta(&d.diff_layer_dir);
            let dir_mtime = std::fs::metadata(&d.diff_layer_dir)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|dur| dur.as_secs())
                .unwrap_or(0);
            CowSessionFacts {
                is_live: cow_session_is_live(&d.session_id),
                meta_unreadable: matches!(meta, CowMetaRead::Unreadable(_)),
                review_pending: matches!(
                    meta.ok().and_then(|m| m.review.as_ref()),
                    Some(CowReviewState::Pending { .. })
                ),
                pending_changes: read_cow_ledger(&d.diff_layer_dir).len(),
                content_files: list_cow_diff_layer_files(&d.diff_layer_dir).len(),
                // メタが無い／読めないときはディレクトリの更新時刻で代用する。ここを
                // 0のままにすると、**メタを書く前の起動しかけ**が常にgraceの外になる。
                created_at_unix_secs: meta
                    .ok()
                    .map(|m| m.created_at_unix_secs)
                    .filter(|t| *t > 0)
                    .unwrap_or(dir_mtime),
                workspace_root: meta.ok().map(|m| m.workspace_root.clone()),
                volume_is_remote: is_remote,
                session_id: d.session_id,
                diff_layer_dir: d.diff_layer_dir,
            }
        })
        .collect();
    (facts, unreachable)
}

/// 回収の1件分の結果。**失敗を成功へ潰さない**（`bug-pattern-rules` B-09）。
#[derive(Debug, Clone)]
pub struct CowGcOutcome {
    pub collected: Vec<String>,
    pub kept: Vec<(String, CowGcVerdict)>,
    pub failures: Vec<(String, String)>,
    /// 到達できなかったボリュームの数（媒体が抜かれている等）。
    /// **0件回収の意味が2つに割れるのを防ぐために持つ。**
    pub unreachable_volumes: usize,
}

/// 差分層を実際に回収する。`dry_run`なら1件も消さずに判定だけを返す。
///
/// `also_collect`は「規則の上では残すが、人が明示的に回収を指示したもの」を通す述語
/// （`harness cow gc --with-changes`）。**規則そのものは変えない**——例外は呼び出し側の
/// 意思として外から渡し、`plan_cow_gc`が「安全に回収してよい」と言う範囲は不変に保つ。
pub fn run_cow_gc(
    dry_run: bool,
    grace_secs: u64,
    policy: CowGcPolicy,
    also_collect: &dyn Fn(&CowSessionFacts, CowGcVerdict) -> bool,
) -> CowGcOutcome {
    harness_grant_ledger::with_named_lock(COW_GC_LOCK_NAME, || {
        let (facts, unreachable_volumes) = collect_cow_session_facts();
        let now = harness_grant_ledger::now_unix_secs();
        let verdicts = plan_cow_gc(&facts, now, grace_secs, policy);
        let mut outcome = CowGcOutcome {
            collected: Vec::new(),
            kept: Vec::new(),
            failures: Vec::new(),
            unreachable_volumes,
        };
        for (fact, (session_id, verdict)) in facts.iter().zip(verdicts) {
            debug_assert_eq!(fact.session_id, session_id);
            if !verdict.collects() && !also_collect(fact, verdict) {
                outcome.kept.push((session_id, verdict));
                continue;
            }
            if dry_run {
                outcome.collected.push(session_id);
                continue;
            }
            match crate::session_scope::remove_overlay_dir(&fact.diff_layer_dir) {
                Ok(()) => outcome.collected.push(session_id),
                Err(e) => outcome.failures.push((session_id, e.to_string())),
            }
        }
        outcome
    })
}

#[cfg(test)]
mod cow_gc_tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const GRACE: u64 = 3600;

    /// 「何も残っていない・実行中でない・作りたてでもない」差分層の素の事実。
    /// 各テストは**1つだけ**を動かして、その1つが判定を変えることを測る。
    fn empty_and_old() -> CowSessionFacts {
        CowSessionFacts {
            session_id: "session-1".into(),
            diff_layer_dir: PathBuf::from("C:/x/session-1"),
            is_live: false,
            meta_unreadable: false,
            review_pending: false,
            pending_changes: 0,
            content_files: 0,
            created_at_unix_secs: NOW - GRACE * 24,
            workspace_root: Some("C:/ws".into()),
            volume_is_remote: false,
        }
    }

    fn verdict(f: CowSessionFacts) -> CowGcVerdict {
        plan_cow_gc(&[f], NOW, GRACE, CowGcPolicy::default())[0].1
    }

    /// **許可側**。ここが動かないとGCは何もしない機能になる（拒否側だけのテストでは
    /// 「全部残す」実装でも緑になる、`test-logic-rules`）。
    #[test]
    fn an_empty_finished_diff_area_is_collected() {
        assert_eq!(verdict(empty_and_old()), CowGcVerdict::Collect);
    }

    #[test]
    fn a_running_session_is_never_collected() {
        let mut f = empty_and_old();
        f.is_live = true;
        assert_eq!(verdict(f), CowGcVerdict::KeepRunning);
    }

    /// D-80の線。**人がまだ見ていない差分層を消さない。**
    #[test]
    fn a_diff_area_waiting_for_review_is_never_collected() {
        let mut f = empty_and_old();
        f.review_pending = true;
        assert_eq!(verdict(f), CowGcVerdict::KeepReviewPending);
    }

    /// レビュー待ちは**実行中でなくても・空に見えても**残る。この2つが重なった状態こそ
    /// 「回収してよさそうに見えるが回収してはいけない」ものである。
    #[test]
    fn review_pending_outranks_looking_empty() {
        let mut f = empty_and_old();
        f.review_pending = true;
        f.pending_changes = 0;
        f.content_files = 0;
        assert!(!verdict(f).collects());
    }

    /// メタが読めない＝中身の意味が分からない。**判定不能は残す側へ倒す**（不可逆な操作のガード）。
    #[test]
    fn an_unreadable_session_metadata_keeps_the_diff_area() {
        let mut f = empty_and_old();
        f.meta_unreadable = true;
        assert_eq!(verdict(f), CowGcVerdict::KeepUndecidable);
    }

    #[test]
    fn pending_ledger_changes_keep_the_diff_area() {
        let mut f = empty_and_old();
        f.pending_changes = 1;
        assert_eq!(verdict(f), CowGcVerdict::KeepHasChanges);
    }

    /// 台帳が空でも**実体ファイルがあれば残す**。Redirectorは境界ではない（D-01）ので、
    /// 子は台帳を経由せず直接置ける——台帳だけを見ると、その作業が黙って消える（BUG-066）。
    #[test]
    fn content_files_without_a_ledger_entry_still_keep_the_diff_area() {
        let mut f = empty_and_old();
        f.pending_changes = 0;
        f.content_files = 1;
        assert_eq!(verdict(f), CowGcVerdict::KeepHasChanges);
    }

    /// 作りたては見送る。**起動しかけのセッション**は「ディレクトリは在るが生存マーカーは
    /// まだ無い」状態を通るので、空の殻と見分けが付かない。
    #[test]
    fn a_freshly_created_diff_area_is_left_alone() {
        let mut f = empty_and_old();
        f.created_at_unix_secs = NOW - 1;
        assert_eq!(verdict(f), CowGcVerdict::KeepTooYoung);
    }


    /// **既定でネットワーク上の差分層を回収しない。** 常時接続が普通なので「到達できない＝
    /// 判定不能」の安全網が働かず、しかも他のマシンが作ったものが混じり得る。
    #[test]
    fn a_diff_area_on_a_network_volume_is_protected_by_default() {
        let mut f = empty_and_old();
        f.volume_is_remote = true;
        assert_eq!(verdict(f), CowGcVerdict::KeepProtected);
    }

    /// **許可側と対で測る**。設定で保護を外せば、他の状態と同じ扱いに戻る
    /// ——保護は例外の分岐ではなく、1本の判定に載った1つの状態である。
    #[test]
    fn turning_the_protection_off_puts_a_network_volume_back_on_the_normal_path() {
        let mut f = empty_and_old();
        f.volume_is_remote = true;
        let policy = CowGcPolicy {
            protect_network_volumes: false,
        };
        assert_eq!(
            plan_cow_gc(&[f], NOW, GRACE, policy)[0].1,
            CowGcVerdict::Collect
        );
    }

    /// 保護は`--with-changes`では外れない。あの指定が広げるのは「変更を抱えているだけ」の
    /// ものだけで、**保護を外す唯一の口は設定である**（口を2つ持つと、片方だけ直る）。
    #[test]
    fn the_protection_is_not_reachable_through_the_with_changes_escape_hatch() {
        let mut f = empty_and_old();
        f.volume_is_remote = true;
        f.pending_changes = 1;
        let v = verdict(f);
        assert_eq!(v, CowGcVerdict::KeepProtected);
        assert!(
            !v.is_only_holding_changes(),
            "--with-changes が拾う集合に入ってはいけない"
        );
    }

    /// 実行中は保護より先に報告する（人が次に取る手が違う——待てばよいのか、設定の話なのか）。
    #[test]
    fn a_running_session_is_reported_as_running_even_on_a_protected_volume() {
        let mut f = empty_and_old();
        f.volume_is_remote = true;
        f.is_live = true;
        assert_eq!(verdict(f), CowGcVerdict::KeepRunning);
    }

    /// 回収しないと判定したものは**必ず理由を持つ**（`shared-state-exclusion` 問6）。
    #[test]
    fn every_kept_verdict_can_explain_itself() {
        for v in [
            CowGcVerdict::KeepRunning,
            CowGcVerdict::KeepProtected,
            CowGcVerdict::KeepReviewPending,
            CowGcVerdict::KeepUndecidable,
            CowGcVerdict::KeepHasChanges,
            CowGcVerdict::KeepTooYoung,
        ] {
            assert!(!v.collects());
            assert!(!v.reason().is_empty());
        }
    }

    /// **前方安全**: このバイナリが知らない欄を持つメタは「読めない」になる。
    /// 緩めると、将来T-Cが足したレビュー状態を古いharnessが「無い＝レビュー中でない」と
    /// 読んで回収してしまう。
    #[test]
    fn session_metadata_from_a_newer_harness_is_treated_as_unreadable() {
        let json = r#"{"session_id":"s","workspace_root":"C:/ws","created_at_unix_secs":1,
                       "some_future_field":true}"#;
        assert!(serde_json::from_str::<CowSessionMeta>(json).is_err());
    }

    /// 逆向き（許可側）: いまの形は読める。上のテストが「常に読めない」で緑にならないようにする。
    #[test]
    fn session_metadata_written_by_this_harness_round_trips() {
        let meta = CowSessionMeta {
            session_id: "s".into(),
            workspace_root: "C:/ws".into(),
            created_at_unix_secs: 1,
            review: Some(CowReviewState::Pending {
                review_ref: "refs/harness/review/s".into(),
                fetched_at_unix_secs: 2,
            }),
            diff_layer_root_fell_back: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: CowSessionMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.review, meta.review);
    }
}
