//! 記録セッションの置き場と、そこに残すマニフェスト。
//!
//! # 置き場が`.harness/sandbox/`配下でなければならない理由
//!
//! 監査ログを書くのは**昇格した収集器**で、その書込先は昇格側が
//! `harness_sandbox::elevated_launch::validate_audit_sink_path`で検証する
//! ——`<workspace>/.harness/sandbox/`配下でなければ拒否される。非昇格の親が指定した
//! 任意パスへ管理者権限で追記できてしまうと、それは任意パス追記プリミティブそのものだからである。
//! したがって記録セッションのディレクトリは**この場所以外に置けない**（好みの問題ではない）。
//!
//! 検証は親ディレクトリを`canonicalize`するので、**`StartCollect`を送る前にディレクトリが
//! 実在していなければならない**。[`RecordSessionDir::create`]が先に作る理由がこれ。
//!
//! # 正本はJSONLであってマニフェストではない
//!
//! `fs-audit.jsonl`が観測の唯一の正本で、[`RecordManifest`]は「いつ・どのコマンドを・
//! どの条件で記録したか」という**文脈**と、後から計算し直せない事実（終了コード・
//! 収集器が起動できたか）だけを持つ。候補の集計値はここに保存しない——
//! `show`は毎回JSONLから計算し直す（同じ事実の正本を2つ持たない、B-13）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 記録セッションのディレクトリ名の接頭辞。`.harness/sandbox/`には会話セッションの
/// ディレクトリ（`session-<id>`）も並ぶので、接頭辞で見分ける。
pub const RECORD_DIR_PREFIX: &str = "policy-editor-";
/// 収集器が書く監査ログのファイル名（deny-onlyの`harness policy learn`と同じ名前）。
pub const AUDIT_LOG_FILE_NAME: &str = "fs-audit.jsonl";
/// 記録セッションのマニフェスト。
pub const MANIFEST_FILE_NAME: &str = "record-session.json";

/// マニフェストの形式。読む側が想定外の形を黙って解釈しないように持つ。
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// 記録セッションの進行状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// 記録中。**このまま残っていたら異常終了である**（正常な経路は必ず上書きする）。
    Running,
    /// 対象コマンドが終了し、収集器も撤収した。
    Finished,
    /// ユーザーのキャンセル、またはタイムアウトで打ち切った。
    Canceled,
    /// 記録を開始できなかった（収集器の起動失敗・Tier1のspawn失敗）。
    Failed,
}

impl RecordStatus {
    pub fn label(self) -> &'static str {
        match self {
            RecordStatus::Running => "記録中（このまま残っていれば異常終了）",
            RecordStatus::Finished => "完了",
            RecordStatus::Canceled => "中断",
            RecordStatus::Failed => "失敗",
        }
    }
}

/// 記録セッション1回分の文脈。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordManifest {
    pub schema_version: u32,
    pub id: String,
    /// Tier1で走らせたコマンド（そのままの綴り）。
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub started_unix_ms: u64,
    pub status: RecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// 収集器（`harness-policy-learnd.exe`）が起動できたか。
    pub collector_started: bool,
    /// ETWセッションが実際に張れたか。`false`なら**何も観測できていない**
    /// ——「拒否が0件だった」と区別できないと、fail-openは単なる隠蔽になる（D-43）。
    pub etw_available: bool,
    /// 収集器の自己申告による書込件数。JSONLの実際の行数とは独立の事実として残す
    /// （食い違ったら、それ自体が調査の手掛かりになる）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_written: Option<u64>,
    /// 記録中に起きた、ユーザーへ伝える価値のある事実（低ILラベルの付与失敗等）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl RecordManifest {
    pub fn new(
        id: impl Into<String>,
        command: impl Into<String>,
        cwd: &Path,
        workspace_root: &Path,
        started_unix_ms: u64,
    ) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            id: id.into(),
            command: command.into(),
            cwd: cwd.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
            started_unix_ms,
            status: RecordStatus::Running,
            finished_unix_ms: None,
            exit_code: None,
            collector_started: false,
            etw_available: false,
            collector_written: None,
            warnings: Vec::new(),
        }
    }
}

/// 記録セッション1回分のディレクトリ。
#[derive(Debug, Clone)]
pub struct RecordSessionDir {
    path: PathBuf,
    id: String,
}

impl RecordSessionDir {
    /// ディレクトリを作る。**`StartCollect`より前に呼ぶ**（モジュールdoc参照）。
    pub fn create(workspace_root: &Path, id: &str) -> std::io::Result<Self> {
        let path = sandbox_root(workspace_root).join(format!("{RECORD_DIR_PREFIX}{id}"));
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            id: id.to_string(),
        })
    }

    /// 既存のディレクトリを開く（`show`用。作らない）。
    pub fn open(workspace_root: &Path, id: &str) -> Option<Self> {
        let path = sandbox_root(workspace_root).join(format!("{RECORD_DIR_PREFIX}{id}"));
        path.is_dir().then_some(Self {
            path,
            id: id.to_string(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.path.join(AUDIT_LOG_FILE_NAME)
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.path.join(MANIFEST_FILE_NAME)
    }

    /// マニフェストを書く（上書き）。**失敗しても記録そのものは止めない**が、
    /// 呼び出し側が事実を表示できるよう`Err`は返す（握り潰さない、B-10）。
    pub fn write_manifest(&self, manifest: &RecordManifest) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(self.manifest_path(), json)
    }

    pub fn read_manifest(&self) -> Option<RecordManifest> {
        let text = std::fs::read_to_string(self.manifest_path()).ok()?;
        serde_json::from_str(&text).ok()
    }
}

/// `<workspace>/.harness/sandbox`。
pub fn sandbox_root(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".harness").join("sandbox")
}

/// 記録セッションを新しい順（`started_unix_ms`の降順）に列挙する。
///
/// マニフェストが読めないディレクトリは飛ばす——記録の途中で電源が落ちた場合など、
/// ディレクトリだけがある状態は起こり得る。
pub fn list_sessions(workspace_root: &Path) -> Vec<(RecordSessionDir, RecordManifest)> {
    let Ok(entries) = std::fs::read_dir(sandbox_root(workspace_root)) else {
        return Vec::new();
    };
    let mut sessions: Vec<(RecordSessionDir, RecordManifest)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            let id = name.strip_prefix(RECORD_DIR_PREFIX)?;
            let dir = RecordSessionDir {
                path: path.clone(),
                id: id.to_string(),
            };
            let manifest = dir.read_manifest()?;
            Some((dir, manifest))
        })
        .collect();
    sessions.sort_by_key(|(_, manifest)| std::cmp::Reverse(manifest.started_unix_ms));
    sessions
}

/// 最も新しい記録セッション。
pub fn latest_session(workspace_root: &Path) -> Option<(RecordSessionDir, RecordManifest)> {
    list_sessions(workspace_root).into_iter().next()
}

pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sandbox_root(dir.path())).unwrap();
        dir
    }

    /// 監査ログの置き場は`<workspace>/.harness/sandbox/policy-editor-<id>/`でなければ
    /// 昇格側に拒否される（モジュールdoc）。**その形を固定する。**
    #[test]
    fn the_audit_log_lives_where_the_elevated_side_will_accept_it() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-1").unwrap();

        let sink = dir.audit_log_path();
        assert!(sink.starts_with(sandbox_root(ws.path())));
        assert_eq!(sink.file_name().unwrap(), AUDIT_LOG_FILE_NAME);
        assert!(
            dir.path().is_dir(),
            "the directory must exist before StartCollect (validate_audit_sink_path canonicalizes it)"
        );
    }

    /// マニフェストは書いて読み戻せる（往復）。
    #[test]
    fn the_manifest_round_trips() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-2").unwrap();
        let mut manifest = RecordManifest::new(
            "abc-2",
            "cargo build",
            Path::new("C:/work"),
            ws.path(),
            1_700_000_000_000,
        );
        manifest.status = RecordStatus::Finished;
        manifest.exit_code = Some(0);
        manifest.collector_started = true;
        manifest.etw_available = true;
        manifest.collector_written = Some(42);
        manifest.warnings.push("low-IL label failed".to_string());

        dir.write_manifest(&manifest).unwrap();
        let read_back = dir.read_manifest().expect("manifest must be readable");

        assert_eq!(read_back.id, "abc-2");
        assert_eq!(read_back.command, "cargo build");
        assert_eq!(read_back.status, RecordStatus::Finished);
        assert_eq!(read_back.exit_code, Some(0));
        assert_eq!(read_back.collector_written, Some(42));
        assert_eq!(read_back.warnings, vec!["low-IL label failed".to_string()]);
    }

    /// **開始時点で`Running`として書く**ので、異常終了したセッションは`Running`のまま残る。
    /// これを「完了」と区別できることが、後から見たときに嘘をつかない条件（B-09）。
    #[test]
    fn a_session_that_never_finished_stays_visible_as_running() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-3").unwrap();
        let manifest = RecordManifest::new("abc-3", "sleep 999", ws.path(), ws.path(), 1);
        dir.write_manifest(&manifest).unwrap();

        let (_, read_back) = latest_session(ws.path()).expect("one session");
        assert_eq!(read_back.status, RecordStatus::Running);
        assert!(read_back.finished_unix_ms.is_none());
    }

    /// 列挙は新しい順で、会話セッションのディレクトリ（`session-*`）は混ざらない。
    #[test]
    fn sessions_are_listed_newest_first_and_conversation_dirs_are_ignored() {
        let ws = workspace();
        for (id, started) in [("old", 100u64), ("new", 300), ("mid", 200)] {
            let dir = RecordSessionDir::create(ws.path(), id).unwrap();
            dir.write_manifest(&RecordManifest::new(
                id,
                "cmd",
                ws.path(),
                ws.path(),
                started,
            ))
            .unwrap();
        }
        // 会話セッションのディレクトリ（別機構が作る）は記録セッションではない。
        std::fs::create_dir_all(sandbox_root(ws.path()).join("session-42")).unwrap();

        let ids: Vec<String> = list_sessions(ws.path())
            .into_iter()
            .map(|(_, m)| m.id)
            .collect();

        assert_eq!(ids, vec!["new", "mid", "old"]);
    }

    /// マニフェストが無いディレクトリは列挙されない（記録の途中で落ちてディレクトリだけ
    /// 残った場合。**壊れた入力で止まらない**、D-43）。
    #[test]
    fn a_directory_without_a_manifest_is_skipped_instead_of_failing() {
        let ws = workspace();
        RecordSessionDir::create(ws.path(), "no-manifest").unwrap();

        assert!(list_sessions(ws.path()).is_empty());
        assert!(latest_session(ws.path()).is_none());
    }

    /// `open`は作らない（`show`が存在しないidを指定したときに空のディレクトリを
    /// 増やさない）。
    #[test]
    fn open_does_not_create_the_directory() {
        let ws = workspace();
        assert!(RecordSessionDir::open(ws.path(), "missing").is_none());
        assert!(!sandbox_root(ws.path())
            .join(format!("{RECORD_DIR_PREFIX}missing"))
            .exists());
    }
}
