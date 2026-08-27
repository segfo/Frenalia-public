//! JSONL追記型セッション永続化（M9、`plans/DESIGN.md` L349「JSONL 追記型セッション永続化
//! （`--resume`/`--continue`）」）。`harness-cli`（ヘッドレス）と`harness-tui`（対話）の
//! 両方から使う共有ロジックのため、両方が既に依存している`harness-engine`に置く。
//!
//! 1ファイル1セッション、1行1レコードのJSONL。ファイル名は`session-{id}.jsonl`で、
//! `--resume <id>`はこの`{id}`部分（接頭辞ごとでも可）を指定する。
//!
//! `{id}`は**UUIDv7**（[`new_session_id`]）。先頭が生成時刻なので文字列のまま生成順に並び、
//! 残りの乱数で一意になる。**セキュリティIDではない**——理由と限界は[`new_session_id`]のdocが持つ。
//! **旧形式（`session-<unixミリ秒>.jsonl`）はそのまま読める。** IDから時刻を数値として
//! 取り出している箇所は無く、一覧と`--continue`の並べ替えはファイルの更新時刻で行っている。
//!
//! # レコードは2種類（[`Line`]）
//!
//! - **`Message`行**（既定・従来からの形）: 会話に増えたメッセージをそのまま追記する。
//! - **チェックポイント行**: `{"kind":"checkpoint","messages":[…]}`。**そこまでの内容を
//!   すべて置き換える**。コンテキスト圧縮が履歴の先頭を畳んだ時点で書き、`--resume`が
//!   圧縮前の長い履歴へ戻ってしまうのを防ぐ。
//!
//! 「畳んだ件数」ではなく履歴全体を書くのは、縮約の①（`tool_result`の本文切詰め）が
//! **件数を変えずに内容だけ変える**操作であり、件数の記録では表現できないからである。

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use harness_core::{ContentBlock, Message, Role};

/// 新規セッションIDを何回まで振り直すか。
///
/// **衝突は現実には起きない**（UUIDv7は先頭48ビットが生成時刻で、残りに74ビットの乱数が入る）。
/// この上限は「起きないはずのことが起きたときに黙って回り続けない」ためのもので、
/// ここに当たるのは採番器そのものが壊れているときだけである。
const MAX_SESSION_ID_ATTEMPTS: usize = 10;

/// 新しいセッションIDを1つ作る（UUIDv7）。
///
/// # なぜUUIDv7か
///
/// 満たしたい性質が2つある——**生成時刻の順に並べられる**ことと、**一意である**こと。
/// UUIDv7は先頭48ビットがunixミリ秒なので、文字列のまま並べれば生成順になる（従来の
/// `session-<ミリ秒>`が持っていた性質を保つ）。残りが乱数なので、**時刻を捏造せずに**
/// 一意にできる——旧実装は衝突を`millis += 1`で避けており、IDが名乗る時刻が実際とずれていた。
///
/// # **これはセキュリティIDではない。予測不能性が要る判断に使わないこと。**
///
/// UUIDv7は**生成時刻をそのまま含む**ため、いつ作られたかが値から読め、当てにいく範囲も狭い。
/// 識別と順序づけのためのIDであって、秘密ではない。
///
/// このIDを消費しているのは4つで、いずれも**当てられて困らない**用途である。
///
/// 1. セッションファイル名（`session-<id>.jsonl`）
/// 2. `--resume <id>` / `--continue` の指定
/// 3. CoW差分層のフォルダ名
/// 4. CoW生存マーカー（名前付きmutex）の名前
///
/// **4だけは限界がある。** IDを当てられる同一マシンのプロセスは、先回りしてその名前の
/// mutexを作れる。すると死んだセッションが「生きている」と誤判定され、差分層が回収され
/// なくなる（**掃除の妨害**であって、権限が広がる方向ではない）。UUIDv7で当てるのは
/// 現実的でなくなるが、**原理的に塞がるわけではない**——塞ぐならマーカー名を秘密から
/// 導出することになる。
///
/// 予測不能性が本当に要る場所は**別系統**になっている。workspace capabilityの秘密は
/// OSの暗号乱数（`BCryptGenRandom`）から作られる。**そちらへこのIDを混ぜないこと。**
fn new_session_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub struct SessionStore {
    path: PathBuf,
}

/// JSONL1行の中身。**`Message`を先に置くことが必須**——`untagged`は上から順に試すので、
/// 従来の`{"role":…,"content":…}`行が先に解け、`role`を持たないチェックポイント行だけが
/// 次の候補へ落ちる（既存のセッションファイルを無変更で読める）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Line {
    Message(Message),
    Checkpoint(Checkpoint),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Checkpoint {
    kind: CheckpointKind,
    messages: Vec<Message>,
}

/// 書き込み用の借用版（履歴全体を`clone`せずに1行へ書くため。読み出しは[`Checkpoint`]）。
#[derive(Serialize)]
struct CheckpointRef<'a> {
    kind: CheckpointKind,
    messages: &'a [Message],
}

/// レコード種別。将来別種を足すときの識別子で、いまは1つだけ。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointKind {
    Checkpoint,
}

/// ファイルを1パス解釈した結果。
#[derive(Default)]
struct Loaded {
    /// チェックポイントを解決した後の履歴（`--resume`が復元するもの）。
    messages: Vec<Message>,
    /// **生の`Message`行**に最初に現れたUser/Textの本文（一覧のタイトル用）。解決後の先頭は
    /// 圧縮の要約になり得るので、そちらをタイトルにすると`[compacted summary of …]`が並ぶ。
    first_user_text: Option<String>,
}

impl SessionStore {
    /// `dir`直下の新規セッションの**名前を決める**（ディレクトリ自体は呼び出し側が
    /// `create_dir_all`済みであることを前提とする）。
    ///
    /// **ファイルはここでは作らない**（[BUG-073](../../../docs/bugs/BUG-073.md)）。実体は
    /// 最初の[`SessionStore::append_messages`]で作られるので、**1件も発話しなかったセッションは
    /// ディスク上に存在しない**。起動して`/sessions`で別の会話へ移っただけ、`/clear`した直後に
    /// 終了しただけ、といった操作で空ファイルが積もらなくなる（空セッションは復元しても何も
    /// 得られないので、取っておく理由が無い）。
    ///
    /// 既に実体があるIDは避ける。遅延生成では名前を予約できないが、**既存の会話へ追記して
    /// しまう**ことだけは防げる（従来の`File::create`は同名を切り詰めていたので、この点は
    /// むしろ良くなる）。
    ///
    /// **衝突したら振り直す。時刻を進めない。** かつては同一ミリ秒の衝突を`millis += 1`で
    /// 避けていたが、それは**IDが名乗る生成時刻を実際とずらす**うえ、再試行に上限が無かった。
    /// いまは[`new_session_id`]（UUIDv7）で振り直し、[`MAX_SESSION_ID_ATTEMPTS`]回で
    /// 打ち切って失敗する。
    pub fn create_new(dir: &Path) -> io::Result<Self> {
        Self::create_new_with(dir, new_session_id)
    }

    /// [`create_new`]の本体。**採番器を差し替えられる形にしてあるのはテストのため**——
    /// 「衝突したら振り直す」「N回で諦める」は、実際に衝突するIDを注入しないと測れない
    /// （UUIDv7の自然な衝突を待つことはできない）。
    fn create_new_with(dir: &Path, mut mint: impl FnMut() -> String) -> io::Result<Self> {
        for _ in 0..MAX_SESSION_ID_ATTEMPTS {
            let path = dir.join(format!("session-{}.jsonl", mint()));
            if !path.exists() {
                return Ok(Self { path });
            }
        }
        // **黙って回り続けない。** 上限に当たるのは採番器が壊れているときだけなので、
        // 使い回して既存の会話を壊すより、ここで止まる方が良い（fail-closed）。
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not mint an unused session id in {} attempts under {}",
                MAX_SESSION_ID_ATTEMPTS,
                dir.display()
            ),
        ))
    }

    /// 既存のセッションファイルを明示パスで開く（`--resume <id>`用、`id`から組み立てた
    /// パスは呼び出し側が用意する）。
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// `dir`直下の`session-*.jsonl`のうち更新日時が最も新しいものを開く（`--continue`用）。
    /// 1件も無ければ`Ok(None)`。
    ///
    /// BUG-073: **空のファイルは飛ばす。** `--continue`は「直前の会話の続き」を意味するので、
    /// 中身の無いファイルを選んでも要求を満たせない（新しく作られるセッションはそもそも
    /// 遅延生成で実体を持たないが、この修正より前に作られた0バイトのファイルが残り得る）。
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
            let meta = entry.metadata()?;
            if meta.len() == 0 {
                continue;
            }
            let modified = meta.modified()?;
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
    ///
    /// BUG-073: **メッセージが1件も無いセッションは載せない。** 選んでも復元するものが無く、
    /// 一覧では`(0 msgs)`の無名の行として並ぶだけで、どれが本当の会話かを見分ける邪魔になる。
    /// 新規セッションは遅延生成（[`SessionStore::create_new`]）で実体を持たないため通常は
    /// 現れないが、この修正より前に作られた0バイトのファイルはここで落とす。
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
            let loaded = store.read().unwrap_or_default();
            if loaded.messages.is_empty() {
                continue;
            }
            // タイトルは**生の`Message`行**の最初のプロンプト。解決後の先頭を使うと、圧縮済みの
            // セッションが揃って`[compacted summary of …]`という題名になり見分けられない。
            let first_prompt = loaded
                .first_user_text
                .map(|t| truncate_chars(&t, 60))
                .unwrap_or_default();
            out.push(SessionSummary {
                id: store.id(),
                path,
                modified,
                // 復元される件数（＝チェックポイント解決後）を出す。
                message_count: loaded.messages.len(),
                first_prompt,
            });
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.modified));
        Ok(out)
    }

    /// `msgs`を1行1メッセージのJSONLとして追記する。
    pub fn append_messages(&self, msgs: &[Message]) -> io::Result<()> {
        let lines = msgs
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.append_lines(&lines)
    }

    /// その時点の履歴全体を**チェックポイント**1行として追記する。読み出し時、この行より前の
    /// 内容はすべて捨てられる。
    ///
    /// コンテキスト圧縮が履歴の先頭を畳んだときに呼ぶ。増分追記だけではファイルに畳む前の
    /// 履歴が残り続け、`--resume`が圧縮前の長い会話へ戻ってしまう。
    ///
    /// **空なら何も書かない。** 書くと「発話0件なのに実体があるセッション」ができ、
    /// [`SessionStore::resume_latest`]は0バイトのファイルだけを飛ばすので`--continue`が
    /// それを選んでしまう（[BUG-073](../../../docs/bugs/BUG-073.md)の不変条件）。
    pub fn append_checkpoint(&self, msgs: &[Message]) -> io::Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let line = serde_json::to_string(&CheckpointRef {
            kind: CheckpointKind::Checkpoint,
            messages: msgs,
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.append_lines(&[line])
    }

    /// 1回のopenで複数行を追記する。ファイルの遅延生成（BUG-073）もここに集約する。
    fn append_lines(&self, lines: &[String]) -> io::Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        for line in lines {
            writeln!(file, "{line}")?;
        }
        Ok(())
    }

    /// 保存済みの全メッセージを順番通りに読み出す（`--resume`/`--continue`の会話復元用）。
    /// チェックポイント行があれば、そこまでの内容は捨てて畳み直す。
    pub fn load_messages(&self) -> io::Result<Vec<Message>> {
        Ok(self.read()?.messages)
    }

    /// ファイルを1パスで解釈する。[`load_messages`](SessionStore::load_messages)と
    /// [`list`](SessionStore::list)が共有する唯一の読み出し口。
    fn read(&self) -> io::Result<Loaded> {
        if !self.path.exists() {
            return Ok(Loaded::default());
        }
        let file = File::open(&self.path)?;
        let reader = io::BufReader::new(file);
        let mut loaded = Loaded::default();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: Line = serde_json::from_str(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            match record {
                Line::Message(msg) => {
                    if loaded.first_user_text.is_none() && msg.role == Role::User {
                        loaded.first_user_text = msg.content.iter().find_map(|b| match b {
                            ContentBlock::Text(t) => Some(t.clone()),
                            _ => None,
                        });
                    }
                    loaded.messages.push(msg);
                }
                // **それまでの蓄積を丸ごと置き換える**（これがチェックポイントの意味）。
                Line::Checkpoint(cp) => loaded.messages = cp.messages,
            }
        }
        Ok(loaded)
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

    // --- BUG-073: 会話していない空セッションを残さない ---

    /// 名前を決めるだけで実体は作らない。1件も発話しなければディスクに何も残らない。
    #[test]
    fn create_new_does_not_touch_the_disk_until_the_first_message() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        assert!(
            !store.path().exists(),
            "空のセッションが実体を持ってはいけない"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);

        store.append_messages(&[msg("hello")]).unwrap();
        assert!(store.path().exists(), "最初の発話で初めて作られる");
    }

    /// 空セッションは一覧にも`--continue`にも現れない（0バイトの遺物ファイルも同様）。
    #[test]
    fn an_empty_session_is_invisible_to_list_and_continue() {
        let dir = tempfile::tempdir().unwrap();
        let real = SessionStore::create_new(dir.path()).unwrap();
        real.append_messages(&[msg("real conversation")]).unwrap();

        // 修正前の`create_new`が作っていた0バイトファイルを再現する（新しい方が
        // 更新日時では勝つので、飛ばさないと`--continue`がこちらを選んでしまう）。
        std::thread::sleep(std::time::Duration::from_millis(10));
        let stale = dir.path().join("session-9999999999999.jsonl");
        File::create(&stale).unwrap();

        let summaries = SessionStore::list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 1, "{summaries:?}");
        assert_eq!(summaries[0].id, real.id());

        let latest = SessionStore::resume_latest(dir.path()).unwrap().unwrap();
        assert_eq!(latest.path(), real.path());
    }

    /// 遅延生成では名前を予約できないので、既に実体がある名前は避ける
    /// （避けないと他プロセスの会話へ追記してしまう）。
    #[test]
    fn create_new_avoids_a_name_that_already_has_content() {
        let dir = tempfile::tempdir().unwrap();
        let first = SessionStore::create_new(dir.path()).unwrap();
        first.append_messages(&[msg("first")]).unwrap();

        let second = SessionStore::create_new(dir.path()).unwrap();
        assert_ne!(second.path(), first.path());
        second.append_messages(&[msg("second")]).unwrap();
        assert_eq!(first.load_messages().unwrap(), vec![msg("first")]);
    }

    #[test]
    fn list_returns_empty_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(SessionStore::list(&missing).unwrap().is_empty());
    }

    // --- セッションIDの採番（UUIDv7・衝突したら振り直す・上限で諦める） ---

    /// **許可側。** 詰まったIDを返し続ける採番器でも、上限の**手前**で空きが出れば通る。
    /// 禁止側（下）だけ書くと「常に失敗する」実装でも緑になる（`test-logic-rules`）。
    #[test]
    fn a_colliding_id_is_reminted_until_a_free_one_comes_up() {
        let dir = tempfile::tempdir().unwrap();
        // 先に「埋まっている」名前を作っておく。
        for taken in ["taken-1", "taken-2"] {
            std::fs::write(dir.path().join(format!("session-{taken}.jsonl")), b"x").unwrap();
        }
        let mut minted = vec!["free", "taken-2", "taken-1"];
        let store =
            SessionStore::create_new_with(dir.path(), || minted.pop().unwrap().to_string()).unwrap();
        assert_eq!(store.id(), "session-free");
    }

    /// **禁止側。** 常に同じIDを返す壊れた採番器では、上限で諦めて失敗する
    /// ——旧実装はここが上限の無い`while`で、黙って回り続けた。
    #[test]
    fn minting_gives_up_after_the_attempt_limit_instead_of_looping_forever() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("session-stuck.jsonl"), b"x").unwrap();

        let mut calls = 0usize;
        // `expect_err`を使わないのは、`SessionStore`に`Debug`を実装させないため
        // （テストの都合で製品側の型に derive を足さない）。
        let result = SessionStore::create_new_with(dir.path(), || {
            calls += 1;
            "stuck".to_string()
        });
        let Err(err) = result else {
            panic!("a minter that never yields a free id must fail, not spin");
        };

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        // **回数まで測る。** 「失敗した」だけだと、1回で諦めても上限まで粘っても緑になる。
        assert_eq!(calls, MAX_SESSION_ID_ATTEMPTS);
    }

    /// 採番したIDは**生成順に文字列として並ぶ**（UUIDv7の先頭が生成時刻であることに依存する
    /// 唯一の性質。旧`session-<ミリ秒>`が持っていたものを保つ）。
    #[test]
    fn minted_ids_sort_in_creation_order() {
        let ids: Vec<String> = (0..8).map(|_| new_session_id()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "UUIDv7は生成順に並ぶはず: {ids:?}");
        // 一意でもあること（順序だけ見ると、同じ値を返す実装でも上が通る）。
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "採番が重複した: {ids:?}");
    }

    /// **旧形式のセッションが読めなくなっていないこと。** IDの形を変えたので、
    /// 既にディスクにある`session-<unixミリ秒>.jsonl`が置き去りになると被害が大きい。
    #[test]
    fn a_legacy_millisecond_session_is_still_resolvable_listable_and_resumable() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = SessionStore::open(SessionStore::resolve_path(dir.path(), "1700000000000"));
        legacy.append_messages(&[msg("old")]).unwrap();

        // `--resume`（接頭辞あり・なしの両形）
        for id in ["1700000000000", "session-1700000000000"] {
            let reopened = SessionStore::open(SessionStore::resolve_path(dir.path(), id));
            assert_eq!(reopened.load_messages().unwrap(), vec![msg("old")], "id={id}");
        }
        // 一覧と`--continue`
        assert_eq!(SessionStore::list(dir.path()).unwrap().len(), 1);
        let latest = SessionStore::resume_latest(dir.path()).unwrap().unwrap();
        assert_eq!(latest.load_messages().unwrap(), vec![msg("old")]);
    }

    // --- コンテキスト圧縮のチェックポイント（`--resume`が圧縮後から始まる） ---

    #[test]
    fn a_checkpoint_replaces_everything_written_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        store
            .append_messages(&[msg("t1"), msg("r1"), msg("t2"), msg("r2")])
            .unwrap();

        // 圧縮: 先頭3件を要約1件へ畳んだ状態を書く。
        store
            .append_checkpoint(&[msg("[compacted summary of 3 earlier messages]"), msg("r2")])
            .unwrap();
        // その後の発話は従来どおり増分で積む。
        store.append_messages(&[msg("t3")]).unwrap();

        assert_eq!(
            store.load_messages().unwrap(),
            vec![
                msg("[compacted summary of 3 earlier messages]"),
                msg("r2"),
                msg("t3")
            ]
        );
    }

    /// 2回目の圧縮でも壊れない（後から書いたチェックポイントが勝つ）。
    #[test]
    fn the_last_checkpoint_wins() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        store.append_messages(&[msg("t1")]).unwrap();
        store.append_checkpoint(&[msg("first fold")]).unwrap();
        store.append_messages(&[msg("t2")]).unwrap();
        store.append_checkpoint(&[msg("second fold")]).unwrap();

        assert_eq!(store.load_messages().unwrap(), vec![msg("second fold")]);
    }

    /// 一覧のタイトルは**生の行の最初のプロンプト**。解決後の先頭を使うと、圧縮済みの
    /// セッションが揃って`[compacted summary of …]`という題名になり見分けられない。
    #[test]
    fn a_checkpoint_does_not_become_the_session_title() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        store
            .append_messages(&[msg("original first prompt"), msg("r1"), msg("t2")])
            .unwrap();
        store
            .append_checkpoint(&[msg("[compacted summary of 2 earlier messages]"), msg("t2")])
            .unwrap();

        let summaries = SessionStore::list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].first_prompt, "original first prompt");
        assert_eq!(summaries[0].message_count, 2, "復元される件数を出す");
    }

    /// BUG-073の不変条件: 発話0件のセッションはディスク上に存在してはいけない。
    #[test]
    fn an_empty_checkpoint_never_creates_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::create_new(dir.path()).unwrap();
        store.append_checkpoint(&[]).unwrap();
        assert!(!store.path().exists());
        assert!(SessionStore::resume_latest(dir.path()).unwrap().is_none());
    }

    /// `/fork`は「解決後の履歴」を引き継ぐ（圧縮された状態から分岐する）。
    #[test]
    fn fork_after_a_checkpoint_copies_the_compacted_state() {
        let dir = tempfile::tempdir().unwrap();
        let source = SessionStore::create_new(dir.path()).unwrap();
        source.append_messages(&[msg("t1"), msg("r1")]).unwrap();
        source.append_checkpoint(&[msg("folded")]).unwrap();

        let forked = SessionStore::fork_from(dir.path(), source.path()).unwrap();
        assert_eq!(forked.load_messages().unwrap(), vec![msg("folded")]);
    }
}
