//! JSONL追記型セッション永続化（M9、`plans/DESIGN.md` L349「JSONL 追記型セッション永続化
//! （`--resume`/`--continue`）」）。`harness-cli`（ヘッドレス）と`harness-tui`（対話）の
//! 両方から使う共有ロジックのため、両方が既に依存している`harness-engine`に置く。
//!
//! 1ファイル1セッション、1行1`Message`のJSONL。ファイル名は生成時刻ベース
//! （`session-{unix_millis}.jsonl`）で、`--resume <id>`はこの`{unix_millis}`部分を指定する。

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use harness_core::Message;

pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    /// `dir`直下に新規セッションファイルを作る（ディレクトリ自体は呼び出し側が
    /// `create_dir_all`済みであることを前提とする）。
    pub fn create_new(dir: &Path) -> io::Result<Self> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let path = dir.join(format!("session-{millis}.jsonl"));
        File::create(&path)?;
        Ok(Self { path })
    }

    /// 既存のセッションファイルを明示パスで開く（`--resume <id>`用、`id`から組み立てた
    /// パスは呼び出し側が用意する）。
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// `dir`直下の`session-*.jsonl`のうち更新日時が最も新しいものを開く（`--continue`用）。
    /// 1件も無ければ`Ok(None)`。
    pub fn resume_latest(dir: &Path) -> io::Result<Option<Self>> {
        let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;
        if !dir.exists() {
            return Ok(None);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
                newest = Some((path, modified));
            }
        }
        Ok(newest.map(|(path, _)| Self { path }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 会話IDとして表示に使う程度のセッション識別子（ファイル名からstemを取り出す）。
    pub fn id(&self) -> String {
        self.path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// `--resume <id>`が受け取り得る2形式（`session-<millis>`そのもの、または`<millis>`
    /// だけ）を`dir`直下のファイルパスへ正規化する。存在確認は呼び出し側が行う。
    pub fn resolve_path(dir: &Path, id: &str) -> PathBuf {
        let stem = id.strip_prefix("session-").unwrap_or(id);
        dir.join(format!("session-{stem}.jsonl"))
    }

    /// `source`が指す既存セッションの全メッセージを、新規に作成したセッションファイルへ
    /// コピーする（`--fork-session`/`/fork`用）。`source`自体は一切変更しない。
    pub fn fork_from(dir: &Path, source: &Path) -> io::Result<Self> {
        let forked = Self::create_new(dir)?;
        let messages = Self::open(source.to_path_buf()).load_messages()?;
        forked.append_messages(&messages)?;
        Ok(forked)
    }

    /// `dir`直下の全セッションを更新日時降順で列挙する（`--list-sessions`/`/sessions`用）。
    pub fn list(dir: &Path) -> io::Result<Vec<SessionSummary>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            let store = Self { path: path.clone() };
            let messages = store.load_messages().unwrap_or_default();
            let first_prompt = messages
                .iter()
                .find(|m| m.role == harness_core::Role::User)
                .and_then(|m| {
                    m.content.iter().find_map(|b| match b {
                        harness_core::ContentBlock::Text(t) => Some(t.clone()),
                        _ => None,
                    })
                })
                .map(|t| truncate_chars(&t, 60))
                .unwrap_or_default();
            out.push(SessionSummary {
                id: store.id(),
                path,
                modified,
                message_count: messages.len(),
                first_prompt,
            });
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.modified));
        Ok(out)
    }

    /// `msgs`を1行1メッセージのJSONLとして追記する。
    pub fn append_messages(&self, msgs: &[Message]) -> io::Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        for m in msgs {
            let line = serde_json::to_string(m)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }

    /// 保存済みの全メッセージを順番通りに読み出す（`--resume`/`--continue`の会話復元用）。
    pub fn load_messages(&self) -> io::Result<Vec<Message>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = io::BufReader::new(file);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let msg: Message = serde_json::from_str(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.push(msg);
        }
        Ok(out)
    }
}

/// `--list-sessions`/`/sessions`向けの1セッション分の要約。
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub path: PathBuf,
    pub modified: SystemTime,
    pub message_count: usize,
    pub first_prompt: String,
}

/// 文字数（バイト数ではない）で切り詰め、超過分は`...`で示す。
fn truncate_chars(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::{ContentBlock, Role};

    fn msg(text: &str) -> Message {
        Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.to_string())],
        }
    }

    #[test]
    fn round_trips_messages_through_append_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        store.append_messages(&[msg("hello")]).unwrap();
        store.append_messages(&[msg("world")]).unwrap();

        let loaded = store.load_messages().unwrap();
        assert_eq!(loaded, vec![msg("hello"), msg("world")]);
    }

    #[test]
    fn resume_latest_picks_most_recently_modified_session() {
        let dir = tempfile::tempdir().unwrap();
        let first = SessionStore::create_new(dir.path()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let second = SessionStore::create_new(dir.path()).unwrap();
        second.append_messages(&[msg("second")]).unwrap();

        let latest = SessionStore::resume_latest(dir.path()).unwrap().unwrap();
        assert_eq!(latest.path(), second.path());
        assert_ne!(latest.path(), first.path());
    }

    #[test]
    fn resume_latest_returns_none_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(SessionStore::resume_latest(&missing).unwrap().is_none());
    }

    #[test]
    fn resolve_path_accepts_bare_and_prefixed_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        let id = store.id();
        let bare = id.strip_prefix("session-").unwrap();

        assert_eq!(SessionStore::resolve_path(dir.path(), &id), *store.path());
        assert_eq!(SessionStore::resolve_path(dir.path(), bare), *store.path());
    }

    #[test]
    fn fork_from_copies_messages_and_leaves_source_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let source = SessionStore::create_new(dir.path()).unwrap();
        source
            .append_messages(&[msg("hello"), msg("world")])
            .unwrap();

        let forked = SessionStore::fork_from(dir.path(), source.path()).unwrap();
        assert_ne!(forked.path(), source.path());
        assert_eq!(
            forked.load_messages().unwrap(),
            vec![msg("hello"), msg("world")]
        );

        forked.append_messages(&[msg("only in fork")]).unwrap();
        assert_eq!(
            source.load_messages().unwrap(),
            vec![msg("hello"), msg("world")]
        );
        assert_eq!(forked.load_messages().unwrap().len(), 3);
    }

    #[test]
    fn list_sorts_by_modified_desc_and_summarizes_first_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let older = SessionStore::create_new(dir.path()).unwrap();
        older.append_messages(&[msg("older prompt")]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let newer = SessionStore::create_new(dir.path()).unwrap();
        newer.append_messages(&[msg(&"x".repeat(100))]).unwrap();

        let summaries = SessionStore::list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].id, newer.id());
        assert_eq!(summaries[0].message_count, 1);
        assert_eq!(summaries[0].first_prompt.chars().count(), 63); // 60文字+"..."
        assert_eq!(summaries[1].id, older.id());
        assert_eq!(summaries[1].first_prompt, "older prompt");
    }

    #[test]
    fn list_returns_empty_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(SessionStore::list(&missing).unwrap().is_empty());
    }
}
