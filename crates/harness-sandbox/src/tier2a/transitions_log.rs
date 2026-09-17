//! `.harness/transitions/`へ積む記録の共通部品——**畳んでから書く**の実装（段階6c・6d）。
//!
//! # 何のためにあるのか
//!
//! このディレクトリには**2種類の記録**が積まれ、段階⑦の遷移画面が両方を読む。
//!
//! | ファイル | 何の観測か | 書き手 | 昇格するか |
//! |---|---|---|---|
//! | `pending.jsonl` | **拒否**された遷移（[`super::spawnd::transitions`]） | Spawn Daemon | しない |
//! | `observed.jsonl` | **起きた**生成＝辺の候補（[`super::policy_learnd::observed`]） | 収集器 | する |
//!
//! **どちらも数え方が同じでなければならない。** 同じ画面が両方を読むので、片方だけ
//! `count`の意味が違うと読み手が取り違える（`B-13`: 規則の正本を2つ持たない）。
//! だから**畳み込み・追記の時機・あふれの数え方・書込失敗の巻き戻しをここ1箇所へ置き**、
//! 行の形（何を鍵にし、どんなJSONを書くか）だけを[`FoldedLine`]で各記録に持たせる。
//!
//! # 「畳んでから書く」とは何か
//!
//! 観測1件につき1行書くと量が破綻する（`cargo build`1回で数千のプロセスが起きる）。
//! そこで**種類ごとに1行**にし、同じ種類が繰り返し起きたら回数を増やして**たまに**
//! 更新行を追記する。読む側は同じ鍵の行を畳んで**最後の1つ**を採る。
//!
//! 1. **1件目は即時に追記する。** 書き手が強制終了されても「それが起きた」事実は残る
//! 2. 2件目以降は数えるだけで、**前回書いた数の2倍**に達したときに更新行を追記する
//!
//! 2倍にしているのは、量を回数の対数へ抑えつつ**時計に依存しない**ためである
//! （一定間隔で書く形にすると、テストが待ち時間に依存して不安定になる）。
//!
//! # 限界（同じ場所で言う）
//!
//! **書き手が強制終了されると`count`は最後に書いた値まで戻る。** 失われるのは回数であって、
//! **それが起きた事実は失われない**（1件目を即時に書いているため）。

use std::collections::HashMap;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 待ち行列の置き場（ワークスペースからの相対）。
///
/// **`.harness`配下から動かさないこと。** 自己参照ループ——記録の産物が次の記録の候補に
/// なること——を断っているのは`harness_policy_editor::exclusion::is_harness_control_path`で、
/// 同関数が見るのは**パス要素`.harness`だけ**である。ここを動かした瞬間、
/// 記録そのものが「サンドボックスから触りたいファイル」の候補として提案され始める。
const TRANSITIONS_DIR: &str = "transitions";

/// 畳み込みで覚えておく**種類**の上限。
///
/// 超えた分は覚えず、数だけ数えてあふれとして1行報告する。
/// **上限を置くのは、要求がフックからも来るようになった日（6f）に備えてである**
/// ——`cargo build`1回で数千のプロセスが起きるので、種類が無制限だと書き手のメモリが
/// 要求元の都合で伸びる。
pub const MAX_DISTINCT_KEYS: usize = 1_024;

/// argvが切り詰められている疑いの閾値（UTF-16単位）。
///
/// `Microsoft-Windows-Security-Mitigations`が運ぶ呼び出し元のコマンドラインは
/// **1,024 UTF-16単位で切られる**。ちょうどこの長さの値は「たまたまこの長さだった」のか
/// 「切られた」のかが区別できないので、**リテラルの辺の候補にしてはいけない**
/// （`plans/DESIGN-MAC.md` §5.1(6)）。判定をここに置くのは、書く側と読む側で
/// 閾値が食い違わないようにするためである。
const ARGV_TRUNCATION_UTF16_UNITS: usize = 1_024;

/// 待ち行列のディレクトリ。
pub fn transitions_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".harness").join(TRANSITIONS_DIR)
}

/// argvが切り詰められている疑いがあるか。
///
/// **「ちょうど閾値」だけを疑う。** 超えているものは切られていない（切られていれば
/// ちょうどになる）ので、`>=`ではなく`==`である。
pub fn argv_is_possibly_truncated(argv: &str) -> bool {
    argv.encode_utf16().count() == ARGV_TRUNCATION_UTF16_UNITS
}

/// 1種類ぶんの数え上げ。**行を組み立てる側（[`FoldedLine::line`]）が読む。**
#[derive(Debug, Clone)]
pub struct Folded {
    pub count: u64,
    /// 最後に**ファイルへ書いた**ときの`count`。次に書くのは`written_at * 2`に達したとき。
    written_at: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub argv_truncation: bool,
}

/// [`FoldingLog::record`]が実際に何をしたか。
///
/// **`Result<(), _>`へ潰さない**（`B-09`）。「畳んだだけで書いていない」と「書いた」が
/// 区別できないと、受け入れテストが「常に書く」実装でも「一度も書かない」実装でも通る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Recorded {
    /// 新しい種類だったので、その場で1行追記した。
    AppendedFirst,
    /// 既にある種類の回数を増やし、しきい値に達したので更新行を追記した。
    AppendedUpdate { count: u64 },
    /// 回数を増やしただけ。追記していない。
    FoldedOnly { count: u64 },
    /// 種類の上限に達していたので、これを種類として覚えなかった（回数だけ数えた）。
    DroppedByCap,
}

/// 書けなかった理由。
///
/// **呼び出し側が握り潰さないように`Result`で返す**（`B-10`）。ただし
/// **これを理由に本来の判定や収集を変えてはいけない**——記録は境界ではない（`P-07`）。
#[derive(Debug)]
pub struct QueueError {
    pub path: PathBuf,
    pub message: String,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for QueueError {}

/// この記録は、**何を鍵にして畳み、どんな行を書くのか**。
///
/// 畳み方と追記の時機は[`FoldingLog`]が持つので、実装側が決めるのはこの2つだけである。
pub trait FoldedLine {
    /// 畳み込みの鍵。**同じ鍵の観測は1つの種類として数える。**
    type Key: Clone + Eq + Hash;

    /// 1種類ぶんを1行のJSONへ組み立てる（末尾の改行は[`FoldingLog`]が付ける）。
    fn line(key: &Self::Key, folded: &Folded) -> Result<String, serde_json::Error>;

    /// 種類の上限を超えて**覚えられなかった回数**を報告する行。
    ///
    /// **あふれを黙って捨てない**（`B-10`）。捨てた件数を残さないと、
    /// 「その観測は起きなかった」と読まれる。
    fn overflow_line(dropped: u64, last_ts: u64) -> Result<String, serde_json::Error>;
}

#[derive(Debug)]
struct State<K> {
    entries: HashMap<K, Folded>,
    /// 上限に達したために覚えられなかった観測の**回数**。
    dropped: u64,
    /// そのうち、既にあふれとして報告済みの回数。
    dropped_reported: u64,
}

impl<K> Default for State<K> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            dropped: 0,
            dropped_reported: 0,
        }
    }
}

/// 追記に失敗したときに、どこまで戻すか。
#[derive(Debug, Clone, Copy)]
enum Rollback {
    Nothing,
    /// 新しい種類として覚えたのを取り消す（次の同じ観測がもう一度「1件目」になる）。
    Forget,
    /// 「ここまで書いた」の印を元へ戻す。
    RestoreWrittenAt(u64),
}

/// 畳んでから書く記録。**書き手が1つ持ち、全てのスレッドが共有する。**
#[derive(Debug)]
pub struct FoldingLog<T: FoldedLine> {
    path: PathBuf,
    state: Mutex<State<T::Key>>,
    _line: std::marker::PhantomData<fn() -> T>,
}

impl<T: FoldedLine> FoldingLog<T> {
    /// 積む先を決めて作る。**ファイルはまだ触らない。**
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(State::default()),
            _line: std::marker::PhantomData,
        }
    }

    /// 積む先。診断とテスト用。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 観測1件を積む（書くかどうかは[`FoldingLog`]のdocの時機に従う）。
    ///
    /// `argv`は切り詰めの疑いを立てるためだけに受け取る——**鍵の一部かどうかは
    /// 呼び出し側の決めごと**なので、ここでは鍵に触らない。
    pub fn record(
        &self,
        key: T::Key,
        argv: &str,
        now_ms: u64,
    ) -> Result<Recorded, QueueError> {
        let (outcome, line, rollback) = {
            let mut state = self.lock();
            match state.entries.get_mut(&key) {
                Some(folded) => {
                    folded.count += 1;
                    folded.last_ts = now_ms;
                    if folded.count >= folded.written_at.saturating_mul(2) {
                        let previous = folded.written_at;
                        folded.written_at = folded.count;
                        let count = folded.count;
                        let line = T::line(&key, folded).map_err(|e| self.err(e.to_string()))?;
                        (
                            Recorded::AppendedUpdate { count },
                            Some(line),
                            Rollback::RestoreWrittenAt(previous),
                        )
                    } else {
                        (
                            Recorded::FoldedOnly {
                                count: folded.count,
                            },
                            None,
                            Rollback::Nothing,
                        )
                    }
                }
                None => {
                    if state.entries.len() >= MAX_DISTINCT_KEYS {
                        state.dropped += 1;
                        (Recorded::DroppedByCap, None, Rollback::Nothing)
                    } else {
                        let folded = Folded {
                            count: 1,
                            written_at: 1,
                            first_ts: now_ms,
                            last_ts: now_ms,
                            argv_truncation: argv_is_possibly_truncated(argv),
                        };
                        let line = T::line(&key, &folded).map_err(|e| self.err(e.to_string()))?;
                        state.entries.insert(key.clone(), folded);
                        (Recorded::AppendedFirst, Some(line), Rollback::Forget)
                    }
                }
            }
        };

        if let Some(line) = line {
            if let Err(e) = self.append(&line) {
                self.roll_back(&key, rollback);
                return Err(e);
            }
        }
        Ok(outcome)
    }

    /// 書けなかったときに、**次の機会に書き直せる状態へ戻す**（`B-15`: 記録は実体の完成後）。
    ///
    /// 戻さないと、1回の書込失敗でその種類が**永久に記録へ現れなくなる**——
    /// 覚えている側は「書いた」と思っているので、二度と書こうとしない。
    fn roll_back(&self, key: &T::Key, rollback: Rollback) {
        let mut state = self.lock();
        match rollback {
            Rollback::Nothing => {}
            Rollback::Forget => {
                state.entries.remove(key);
            }
            Rollback::RestoreWrittenAt(previous) => {
                if let Some(folded) = state.entries.get_mut(key) {
                    folded.written_at = previous;
                }
            }
        }
    }

    /// 畳むときに、**まだ書いていない回数を全部書き出す**。
    ///
    /// 戻り値は追記した行数。**`Result<(), _>`へ潰さない**——0行だったことと
    /// 書けなかったことが区別できないと、後から「積まれていない」の原因が追えない（`B-09`）。
    pub fn flush(&self, now_ms: u64) -> Result<usize, QueueError> {
        // **「書いた」印を付けるのは追記が成功した後である**（`B-15`）。先に付けてから
        // 途中で失敗すると、まだ書いていない回数が「書いた」ことにされて永久に失われる。
        let stale: Vec<(T::Key, String, u64)> = {
            let state = self.lock();
            state
                .entries
                .iter()
                .filter(|(_, folded)| folded.count != folded.written_at)
                .map(|(key, folded)| {
                    T::line(key, folded)
                        .map(|line| (key.clone(), line, folded.count))
                        .map_err(|e| self.err(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut written = 0usize;
        for (key, line, count) in stale {
            self.append(&line)?;
            written += 1;
            let mut state = self.lock();
            if let Some(folded) = state.entries.get_mut(&key) {
                folded.written_at = count;
            }
        }

        let dropped = {
            let state = self.lock();
            (state.dropped > state.dropped_reported).then_some(state.dropped)
        };
        if let Some(dropped) = dropped {
            let line = T::overflow_line(dropped, now_ms).map_err(|e| self.err(e.to_string()))?;
            self.append(&line)?;
            written += 1;
            self.lock().dropped_reported = dropped;
        }
        Ok(written)
    }

    /// 1行追記する。
    ///
    /// # 毎回開き直す
    ///
    /// 掴みっぱなしにしない。**畳み込みのおかげで追記は回数の対数にしかならない**ので、
    /// 開き直す費用は問題にならない。掴んだままにすると、ユーザーがファイルを消したときに
    /// 「書いているつもりで誰にも見えない場所へ書き続ける」状態になる。
    ///
    /// # 親ディレクトリは本来ここで作られない
    ///
    /// 置き場は**非特権のharnessが先に作る**（§10.2、[BUG-109](../../../../docs/bugs/BUG-109.md)）。
    /// ここの`create_dir_all`は先行作成が失敗したときの保険である。
    /// **昇格した書き手（収集器）がこれで作ると所有者が`BUILTIN\Administrators`になり、
    /// 次回以降の`.harness/**`の保護が完成しなくなる**——だから先行作成の側を落とさない。
    fn append(&self, line: &str) -> Result<(), QueueError> {
        use std::io::Write;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| self.err(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| self.err(e.to_string()))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| self.err(e.to_string()))
    }

    fn err(&self, message: String) -> QueueError {
        QueueError {
            path: self.path.clone(),
            message,
        }
    }

    /// 毒されたロックでも先へ進む。**記録が壊れても本来の判定・収集は止めない**
    /// ——記録は境界ではない（`P-07`）。
    fn lock(&self) -> std::sync::MutexGuard<'_, State<T::Key>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}
