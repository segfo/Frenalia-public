//! CoW セッションで git 済みになった内容を、人がレビューできる形へ取り込む（D-80・D-110）。
//!
//! # 何のためにあるか
//!
//! CoW（`--sandbox tier2a-cow`）の中でエージェントが `git commit` すると、その結果は差分層の
//! `.git` に**ばらばらのファイル**として残る。普通の `harness apply` はそれを本物へ書かない
//! （D-110 (v)。パスの前方一致の拒否リストでは、オブジェクト＋ref の移動・`refs/replace`・
//! alternates・入れ子の `.git` を運ぶ経路を塞げないため）。**git 済みの内容が本物へ入る入口は、
//! このクレートが作る1本だけ**にする:
//!
//! ```text
//! 差分層の .git（子が書ける）──検算してコピー──▶ 一時 bare（ハーネスが組む）
//!                                                  │ alternates ─▶ 本物の objects だけ
//!                                                  └─ git fetch ─▶ 本物の refs/harness/review/<session-id>/…
//!                                                                    └─ worktree ─▶ レビュー用のフォルダ
//! ```
//!
//! 人はレビュー用のフォルダを自分のエディタで開き、`git log`・`git diff` で読む
//! （ハーネスは diff・マージの画面を作らない。D-80 の責務境界）。
//!
//! # 入口は2つ
//!
//! - [`prepare_review`]: 取り込んで worktree を作り、セッションを「レビュー待ち」にする。
//! - [`discard_review_artifacts`]: レビュー用の ref と worktree を消し、「済み」にする。
//!
//! TUI と CLI はどちらもこの2つを呼ぶ（同じ経路を2本作らない。BUG-032 と同じ型の穴を避ける）。
//! **配線はまだ無い**——段6の後半が `harness review`・git 対応の `apply`・TUI へ繋ぐ。
//!
//! # 信頼の境界
//!
//! `untrusted` モジュールだけが差分層を読む。そこから外へ出るのは、検算を通ったバイト列と
//! 厳格に解析した ref だけである。git を起動するのは `launcher` だけで、差分層の `.git` を
//! git dir として渡す口はそこに無い（[`launcher`] のモジュール doc）。

mod assemble;
mod import;
pub mod launcher;
mod lifecycle;
mod untrusted;
mod worktree;

use std::path::PathBuf;

pub use launcher::{GitLauncher, RealRepo, ReviewWorktree};
pub use lifecycle::{
    discard_review_artifacts, prepare_review, CleanupReport, ReviewRequest, SessionId,
};
pub use worktree::{
    is_review_danger_path, review_profile_root, review_root_candidates, review_root_for_workspace,
    worktree_dir_name, REVIEW_PLACEMENT,
};

/// レビュー経路のエラー。
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("git is unavailable: {0}")]
    GitUnavailable(String),
    #[error("{command} failed (exit {code:?}): {stderr}")]
    GitFailed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    /// このリポジトリの形はまだ扱えない（SHA-256・reftable・`.git` がファイル等）。
    #[error("unsupported repository: {0}")]
    Unsupported(String),
    /// 安全に進められないので断った（セッションが動いている・メタが食い違う等）。
    #[error("refused: {0}")]
    Refused(String),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// 操作は終了コード0で終わったが、読み返すと期待した状態になっていない。
    #[error("the result did not match what was requested: {0}")]
    Mismatch(String),
    /// 失敗の後の巻き戻しも一部失敗した。`leftovers` は**必ず表示する**（本物に ref・worktree が
    /// 残っている、またはレビュー状態を戻せていない）。
    #[error("{cause}; undoing it also failed: {leftovers:?}")]
    CleanupFailed {
        cause: Box<ReviewError>,
        leftovers: Vec<String>,
    },
}

impl ReviewError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        ReviewError::Io {
            path: path.into(),
            source,
        }
    }
}

/// 取り込んだ ref 1本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRef {
    /// エージェントから見えていた名前（`refs/heads/feature`）。
    pub name: String,
    /// 本物に作ったレビュー用の ref（`refs/harness/review/<session-id>/heads/feature`）。
    pub review_ref: String,
    pub oid: String,
    /// 取り込んだ時点の本物の同じ名前の値（無ければ新しい枝・タグ）。`git log <base>..<review_ref>`
    /// の `<base>` にあたる。
    pub base: Option<String>,
}

/// 取り込まなかった ref 1本と、その理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRef {
    pub name: String,
    pub oid: Option<String>,
    pub reason: String,
}

/// 差分層のオブジェクトをどう扱ったか。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectTally {
    /// 検算を通して一時リポジトリへ入れたゆるいオブジェクトの数。
    pub loose_copied: usize,
    /// 検算で落としたゆるいオブジェクト（名前, 理由）。
    pub loose_rejected: Vec<(String, String)>,
    /// 索引を作り直して入れた pack の数。
    pub packs_indexed: usize,
    /// 本物に同じ名前があったので省いた pack の数（本体層のコピー。alternates で届く）。
    pub packs_already_present: usize,
    /// 検査で落とした pack（名前, 理由）。
    pub packs_rejected: Vec<(String, String)>,
    /// 読まずに捨てたファイルの数（`.idx`・commit-graph・`info/*`・`tmp_*` 等）。
    pub ignored_files: usize,
    /// 捨てたファイルの例（最大 [`IGNORED_SAMPLE_LIMIT`] 件）。
    pub ignored_samples: Vec<String>,
}

/// [`ObjectTally::ignored_samples`] に残す件数の上限。
pub const IGNORED_SAMPLE_LIMIT: usize = 20;

/// [`prepare_review`] の結果。
#[derive(Debug, Clone)]
pub struct ReviewReport {
    pub session_id: String,
    pub imported: Vec<ImportedRef>,
    pub not_imported: Vec<SkippedRef>,
    /// エージェントが消した枝・タグ（本物には在るが、エージェントからは見えなくなっていた）。
    /// 取り込みでは何もしない——消すかどうかは承認の側が決める。
    pub deleted_in_session: Vec<String>,
    /// エージェントの `HEAD` がどこを指していたか（`refs/heads/x` か、切り離された oid）。
    pub agent_head: Option<String>,
    pub objects: ObjectTally,
    pub worktree: PathBuf,
    /// worktree を作ったコミット。
    pub worktree_tip: String,
    /// worktree のディスクへ書き出さなかった危険パス（D-110 (i)）。`git diff` では見える。
    pub withheld_from_disk: Vec<String>,
    /// 表示すべき注意（置き場の降格など）。
    pub notes: Vec<String>,
}
