//! `RecallStore`: checkpoint本体・index・git履歴化・reviewedウォーターマークの実体。
//! `plans/PLAN-RECALL-MEMORY.md`「アーキテクチャ」。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::checkpoint::{sha256_hex, Checkpoint, CheckpointMeta};
use super::git;
use crate::fsname::validate_id;

/// `<data_dir>/memory/<workspace-key>/`直下に置く、元ワークスペースへの逆引き情報。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkspaceMeta {
    workspace_root: String,
    created_at_ms: u64,
}

/// `RecallStore::list_all_workspaces`の1件（`memory gc`用）。
#[derive(Debug, Clone)]
pub struct WorkspaceSummary {
    pub dir: PathBuf,
    pub workspace_root: String,
    pub checkpoint_count: usize,
}

/// レビュー済みウォーターマーク（`reviewed.json`、git管理外）。`(created_at_ms, id)`の
/// 辞書式比較で未レビュー集合を決定的に定義する（B-07: `created_at_ms`だけでは並行
/// セッションが同一ミリ秒で書いたときに順序が決まらない）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReviewedWatermark {
    pub created_at_ms: u64,
    pub id: String,
}

impl ReviewedWatermark {
    fn key(&self) -> (u64, &str) {
        (self.created_at_ms, self.id.as_str())
    }
}

/// checkpointの書込みに成功した結果。commitの失敗は書込み自体の失敗とは区別する
/// （書込み経路のfail-open方針、`bug-pattern-rules` B-10）。
pub struct AppendOutcome {
    pub id: String,
    /// `Some`なら「書けたがgit履歴化には失敗した」の理由。
    pub commit_warning: Option<String>,
}

pub struct RecallStore {
    dir: PathBuf,
    workspace_root: PathBuf,
}

impl RecallStore {
    /// `directories::ProjectDirs`の`data_dir()`配下`memory/`を解決する
    /// （`config_dir()`＝`*-ledger.json`群とは別系統。checkpointは「このユーザーが積み上げた
    /// 調査知見」なのでローミング対象＝`data_dir()`を使う）。`ProjectDirs`が解決できない環境
    /// （一部のCI等）では理由付きで`Err`。
    ///
    /// **データルートを決める唯一の関数**——[`Self::for_workspace`]と`harness memory gc`
    /// （`RecallStore::data_root`を直接呼ぶ）の2経路が共有する。置き場を差し替える口を
    /// 増やすときはここだけを変える（`bug-pattern-rules` B-06）。
    pub fn data_root() -> Result<PathBuf, String> {
        // out-of-process E2E（`harness-cli`の`tests/recall_e2e.rs`）専用の逃がし口。
        // **既定ビルドにはコンパイルされない**（`e2e-test-hooks` feature、`--mock-turns`と
        // 同じ「既定オフのテストフック」の前例に乗せる）。実`%APPDATA%`を汚さずに、
        // 記憶ディレクトリの中身をテストから直接assertするために要る。
        #[cfg(feature = "e2e-test-hooks")]
        if let Some(root) = std::env::var_os("HARNESS_TEST_RECALL_DATA_ROOT") {
            return Ok(PathBuf::from(root));
        }
        directories::ProjectDirs::from("", "", "harness")
            .map(|d| d.data_dir().join("memory"))
            .ok_or_else(|| {
                "cannot resolve the user's data directory (directories::ProjectDirs)".to_string()
            })
    }

    /// `directories::ProjectDirs`の`data_dir()`配下`memory/<workspace-key>/`を指す
    /// ストアを作る。`ProjectDirs`が解決できない環境（一部のCI等）では理由付きで`Err`。
    pub fn for_workspace(workspace_root: &Path) -> Result<Self, String> {
        Ok(Self::at_root(&Self::data_root()?, workspace_root))
    }

    /// テスト注入用: データルートを明示する（`docs/CODE-STRUCTURE-RULES.md`規則6）。
    pub fn at_root(data_root: &Path, workspace_root: &Path) -> Self {
        let key = workspace_key(workspace_root);
        Self {
            dir: data_root.join(key),
            workspace_root: workspace_root.to_path_buf(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn checkpoints_dir(&self) -> PathBuf {
        self.dir.join("checkpoints")
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index.jsonl")
    }

    fn checkpoint_path(&self, id: &str) -> io::Result<PathBuf> {
        validate_id(id)?;
        Ok(self.checkpoints_dir().join(format!("{id}.md")))
    }

    fn lock_name(&self) -> String {
        // ディレクトリ名自体が既にworkspace-keyのダイジェストなので、そのまま使う。
        let key = self
            .dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        format!("Local\\harness-recall-{key}")
    }

    /// ディレクトリ構成を整え、`meta.json`・`.gitignore`を用意し、gitがあれば`git init`し、
    /// `index.jsonl`と`checkpoints/*.md`の件数を照合して不一致なら再構築する（設計変更D）。
    pub fn open(&self) -> io::Result<()> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || self.open_locked())
    }

    fn open_locked(&self) -> io::Result<()> {
        std::fs::create_dir_all(self.checkpoints_dir())?;

        let meta_path = self.dir.join("meta.json");
        if !meta_path.exists() {
            let meta = WorkspaceMeta {
                workspace_root: self.workspace_root.to_string_lossy().to_string(),
                created_at_ms: now_ms(),
            };
            if let Ok(s) = serde_json::to_string_pretty(&meta) {
                std::fs::write(&meta_path, s)?;
            }
        }

        let gitignore_path = self.dir.join(".gitignore");
        if !gitignore_path.exists() {
            std::fs::write(&gitignore_path, "reviewed.json\n*.json.bak\n")?;
        }

        if git::git_available() {
            let _ = git::ensure_repo(&self.dir);
        }

        self.reconcile_index_locked()?;
        Ok(())
    }

    /// `index.jsonl`の行数と`checkpoints/*.md`のファイル数が食い違っていたら再構築する。
    fn reconcile_index_locked(&self) -> io::Result<()> {
        let md_count = self.list_checkpoint_files()?.len();
        let index_count = self.read_index_locked().map(|v| v.len()).unwrap_or(0);
        if md_count != index_count {
            self.rebuild_index_locked()?;
        }
        Ok(())
    }

    fn list_checkpoint_files(&self) -> io::Result<Vec<PathBuf>> {
        let dir = self.checkpoints_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(path);
            }
        }
        Ok(out)
    }

    /// `checkpoints/*.md`から`index.jsonl`を再生成する。SSOT（`.md`）から派生キャッシュを
    /// 作り直すだけなので、破損・並行書込みの競合を自己修復できる（設計変更D）。
    pub fn rebuild_index(&self) -> io::Result<()> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || self.rebuild_index_locked())
    }

    fn rebuild_index_locked(&self) -> io::Result<()> {
        let mut metas = Vec::new();
        for path in self.list_checkpoint_files()? {
            let contents = std::fs::read_to_string(&path)?;
            if let Some(cp) = Checkpoint::parse_file_contents(&contents) {
                metas.push(cp.meta);
            }
        }
        metas.sort_by(|a, b| (a.created_at_ms, &a.id).cmp(&(b.created_at_ms, &b.id)));
        let mut buf = String::new();
        for m in &metas {
            if let Ok(line) = serde_json::to_string(m) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        std::fs::write(self.index_path(), buf)
    }

    fn read_index_locked(&self) -> io::Result<Vec<CheckpointMeta>> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let contents = std::fs::read_to_string(path)?;
        Ok(contents
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// checkpointを1件書く。**書込みの唯一の入口**——`recall::write::checkpoint_goal`
    /// （HIVのDecide/BudgetExhausted・Censusの`Join`・`remember`ツールの3経路が共有する）
    /// からのみ呼ばれる想定（設計変更F）。
    ///
    /// gitが無く`allow_unversioned`も無効なら`Err`（何も書かない）。gitはあるが`commit`に
    /// 失敗した場合は、**checkpoint自体は書けているので`Ok`のまま`commit_warning`へ理由を
    /// 載せる**（fail-open、`bug-pattern-rules` B-10）。
    pub fn append(
        &self,
        cp: &Checkpoint,
        allow_unversioned: bool,
    ) -> Result<AppendOutcome, String> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || {
            self.append_locked(cp, allow_unversioned)
        })
    }

    fn append_locked(
        &self,
        cp: &Checkpoint,
        allow_unversioned: bool,
    ) -> Result<AppendOutcome, String> {
        validate_id(&cp.meta.id).map_err(|e| e.to_string())?;
        self.open_locked().map_err(|e| e.to_string())?;

        let has_git = git::git_available();
        if !has_git && !allow_unversioned {
            return Err(
                "git not found in PATH; set cognition.recall.allow_unversioned in your user \
                 settings.json to write without history, or install git"
                    .to_string(),
            );
        }

        // 1. 本体（SSOT）を書く。
        let path = self
            .checkpoint_path(&cp.meta.id)
            .map_err(|e| e.to_string())?;
        std::fs::write(&path, cp.to_file_contents()).map_err(|e| e.to_string())?;

        // 2. indexへ追記する（失敗しても次回`open`のrebuildが自己修復する。B-15の順序で
        //    本体書込みの後に置いてある）。
        if self.append_index_line(&cp.meta).is_err() {
            let _ = self.rebuild_index_locked();
        }

        // 3. gitがあればcommitする。
        let commit_warning = if has_git {
            git::ensure_repo(&self.dir)
                .and_then(|_| {
                    git::commit_all(
                        &self.dir,
                        &format!("checkpoint: {}", first_line(&cp.meta.summary)),
                    )
                })
                .err()
        } else {
            None
        };

        Ok(AppendOutcome {
            id: cp.meta.id.clone(),
            commit_warning,
        })
    }

    fn append_index_line(&self, meta: &CheckpointMeta) -> io::Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(meta)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.index_path())?;
        writeln!(f, "{line}")
    }

    /// `index.jsonl`の全件（自動整合チェック込み）。
    pub fn list(&self) -> io::Result<Vec<CheckpointMeta>> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || {
            self.reconcile_index_locked()?;
            self.read_index_locked()
        })
    }

    /// 1件の本体を読む。**`id`はindex.jsonl由来かもしれない外来文字列として検証してから
    /// パス要素にする**（設計変更D、`bug-pattern-rules` P-01・BUG-062と同型）。
    pub fn read(&self, id: &str) -> io::Result<Checkpoint> {
        let path = self.checkpoint_path(id)?;
        let contents = std::fs::read_to_string(path)?;
        Checkpoint::parse_file_contents(&contents)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed checkpoint file"))
    }

    /// 1件を削除する（ファイル削除＋index再構築。gitがあれば削除もコミット）。
    pub fn discard(&self, id: &str) -> Result<(), String> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || {
            let path = self.checkpoint_path(id).map_err(|e| e.to_string())?;
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
            self.rebuild_index_locked().map_err(|e| e.to_string())?;
            if git::git_available() {
                let _ = git::ensure_repo(&self.dir);
                let _ = git::commit_all(&self.dir, &format!("discard: {id}"));
            }
            Ok(())
        })
    }

    /// このワークスペースの記憶ディレクトリを丸ごと削除する（設計変更G）。
    pub fn forget(&self) -> io::Result<()> {
        harness_grant_ledger::with_named_lock(&self.lock_name(), || {
            if self.dir.exists() {
                std::fs::remove_dir_all(&self.dir)?;
            }
            Ok(())
        })
    }

    fn reviewed_ledger(&self) -> harness_grant_ledger::Ledger<ReviewedWatermark> {
        harness_grant_ledger::Ledger::at_path(self.dir.join("reviewed.json"), None)
    }

    /// このマシン上の全ワークスペースの記憶ディレクトリを一覧する（`memory gc`用）。
    /// **削除は一切行わない**——`元ワークスペースが存在するか`の判定は呼び出し側の責務にせず、
    /// ここでは列挙だけにとどめる（未マウントのネットワークドライブと本当に削除された
    /// ワークスペースを区別できないため、`bug-pattern-rules` B-14）。
    pub fn list_all_workspaces(data_root: &Path) -> io::Result<Vec<WorkspaceSummary>> {
        if !data_root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(data_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            let meta_path = dir.join("meta.json");
            let workspace_root = std::fs::read_to_string(&meta_path)
                .ok()
                .and_then(|s| serde_json::from_str::<WorkspaceMeta>(&s).ok())
                .map(|m| m.workspace_root)
                .unwrap_or_else(|| "(unknown)".to_string());
            let checkpoint_count = std::fs::read_dir(dir.join("checkpoints"))
                .map(|it| it.filter_map(|e| e.ok()).count())
                .unwrap_or(0);
            out.push(WorkspaceSummary {
                dir,
                workspace_root,
                checkpoint_count,
            });
        }
        out.sort_by(|a, b| a.workspace_root.cmp(&b.workspace_root));
        Ok(out)
    }

    pub fn reviewed_watermark(&self) -> ReviewedWatermark {
        self.reviewed_ledger().load()
    }

    pub fn mark_reviewed(&self, watermark: ReviewedWatermark) {
        self.reviewed_ledger().save(&watermark);
    }

    /// `watermark`より新しい（＝未レビューの）checkpoint一覧。
    pub fn unreviewed(&self) -> io::Result<Vec<CheckpointMeta>> {
        let watermark = self.reviewed_watermark();
        let all = self.list()?;
        Ok(all
            .into_iter()
            .filter(|m| (m.created_at_ms, m.id.as_str()) > watermark.key())
            .collect())
    }

    /// `created_at_ms`とidが`watermark`以下（＝レビュー済み）か。
    pub fn is_reviewed(&self, meta: &CheckpointMeta, watermark: &ReviewedWatermark) -> bool {
        (meta.created_at_ms, meta.id.as_str()) <= watermark.key()
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 綴りを畳んでからSHA-256の先頭32hexを取る（設計変更E）。末尾の区切り（`C:\ws\`と`C:\ws`）は
/// [`normalize_root_spelling`](harness_change_ledger::path_rules::normalize_root_spelling)で
/// 先に落としてから[`fold_for_comparison`](harness_change_ledger::path_rules::fold_for_comparison)
/// で大小・区切り文字を畳む——後者だけでは末尾区切りの有無までは吸収しないため。
fn workspace_key(workspace_root: &Path) -> String {
    use harness_change_ledger::path_rules::{fold_for_comparison, normalize_root_spelling};
    let normalized = normalize_root_spelling(&workspace_root.to_string_lossy());
    let folded = fold_for_comparison(&normalized);
    sha256_hex(folded.as_bytes())[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(workspace: &Path) -> (tempfile::TempDir, RecallStore) {
        let data_root = tempfile::tempdir().unwrap();
        let s = RecallStore::at_root(data_root.path(), workspace);
        (data_root, s)
    }

    /// 設計変更E: 綴りの畳み込み(`C:\ws` と `c:/WS/`)が同一のworkspace-keyになる。
    #[test]
    fn spelling_variants_fold_to_the_same_key() {
        let a = workspace_key(Path::new(r"C:\ws"));
        let b = workspace_key(Path::new("c:/WS/"));
        assert_eq!(a, b);
    }

    #[test]
    fn append_then_list_round_trips() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        let cp = super::super::checkpoint::Checkpoint {
            meta: CheckpointMeta {
                id: "cp-1-aaaaaaaa".to_string(),
                created_at_ms: 100,
                tags: vec![],
                summary: "s".into(),
                goal_excerpt: "g".into(),
                sources: vec![],
            },
            body: "body".to_string(),
        };
        let outcome = s.append(&cp, true).unwrap();
        assert_eq!(outcome.id, "cp-1-aaaaaaaa");
        let list = s.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "cp-1-aaaaaaaa");
        let read_back = s.read("cp-1-aaaaaaaa").unwrap();
        assert_eq!(read_back.body, "body");
    }

    /// 設計変更D: 本体`.md`を1件消すと次の`open`（＝`list`が内部で呼ぶ）でindexが自己修復する。
    #[test]
    fn deleting_a_checkpoint_body_triggers_index_self_repair() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        for i in 0..3 {
            let cp = super::super::checkpoint::Checkpoint {
                meta: CheckpointMeta {
                    id: format!("cp-{i}-aaaaaaaa"),
                    created_at_ms: i as u64,
                    tags: vec![],
                    summary: "s".into(),
                    goal_excerpt: "g".into(),
                    sources: vec![],
                },
                body: "body".to_string(),
            };
            s.append(&cp, true).unwrap();
        }
        assert_eq!(s.list().unwrap().len(), 3);

        // indexをバイパスして本体だけ直接消す（実運用で起きる不整合を模す）。
        std::fs::remove_file(s.checkpoints_dir().join("cp-1-aaaaaaaa.md")).unwrap();
        let list = s.list().unwrap();
        assert_eq!(list.len(), 2, "list() should self-heal via rebuild_index");
    }

    /// 設計変更D: index行のIDに`../`が混ざっていても`checkpoints/`の外を読まない。
    #[test]
    fn traversal_in_an_id_read_from_the_index_is_rejected() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        s.open().unwrap();
        let err = s.read("../../evil").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn discard_removes_the_checkpoint_and_rebuilds_the_index() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        let cp = super::super::checkpoint::Checkpoint {
            meta: CheckpointMeta {
                id: "cp-1-aaaaaaaa".to_string(),
                created_at_ms: 1,
                tags: vec![],
                summary: "s".into(),
                goal_excerpt: "g".into(),
                sources: vec![],
            },
            body: "body".to_string(),
        };
        s.append(&cp, true).unwrap();
        s.discard("cp-1-aaaaaaaa").unwrap();
        assert!(s.list().unwrap().is_empty());
    }

    /// B-07: 同一ミリ秒の2件が`(created_at_ms, id)`で決定的に順序付く。
    #[test]
    fn watermark_ordering_is_deterministic_for_the_same_millisecond() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        for id in ["cp-5-bbbbbbbb", "cp-5-aaaaaaaa"] {
            let cp = super::super::checkpoint::Checkpoint {
                meta: CheckpointMeta {
                    id: id.to_string(),
                    created_at_ms: 5,
                    tags: vec![],
                    summary: "s".into(),
                    goal_excerpt: "g".into(),
                    sources: vec![],
                },
                body: "body".to_string(),
            };
            s.append(&cp, true).unwrap();
        }
        let watermark = ReviewedWatermark {
            created_at_ms: 5,
            id: "cp-5-aaaaaaaa".to_string(),
        };
        let unreviewed = s.unreviewed_after(&watermark);
        assert_eq!(unreviewed, vec!["cp-5-bbbbbbbb".to_string()]);
    }

    /// `memory forget`は既定で何も削除しない世界（`memory gc`）とは別物——1ワークスペース分の
    /// 明示的な削除であることを確認する。
    #[test]
    fn forget_removes_the_entire_workspace_directory() {
        let ws = tempfile::tempdir().unwrap();
        let (_data, s) = store(ws.path());
        s.open().unwrap();
        assert!(s.dir().exists());
        s.forget().unwrap();
        assert!(!s.dir().exists());
    }

    impl RecallStore {
        fn unreviewed_after(&self, watermark: &ReviewedWatermark) -> Vec<String> {
            self.list()
                .unwrap()
                .into_iter()
                .filter(|m| (m.created_at_ms, m.id.as_str()) > watermark.key())
                .map(|m| m.id)
                .collect()
        }
    }
}
