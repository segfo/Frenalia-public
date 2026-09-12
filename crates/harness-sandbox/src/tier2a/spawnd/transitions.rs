//! [段階6c] 拒否の待ち行列（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2）。
//!
//! # 何のためにあるのか
//!
//! 段階6bでSpawn Daemonが遷移を拒否するようになったが、**拒否は要求元のプロセスへ返るだけで
//! どこにも残らない**。残らないと2つが区別できない——「拒否された」のか「そもそもその生成が
//! 起きなかった」のか。さらにユーザーから見ると、何を`policy.json`へ書けば通るようになるのかの
//! 手掛かりが1つも無い。
//!
//! そこで拒否を`<workspace>/.harness/transitions/pending.jsonl`へ1行1 JSONで積む。
//! 後でポリシーエディタの遷移画面（段階⑦）がこれを読み、「これを許可しますか」と聞く。
//!
//! # 行は2つの軸で読む（2026-09-12に確定）
//!
//! | 軸 | どこが持つか | 値 |
//! |---|---|---|
//! | **誰が拒否したか** | 行の`kind` | `denied_by_daemon` / `denied_by_kernel` |
//! | **何をすれば直るか** | 行に**持たない**。[`remedy`]が理由から計算する | [`Remedy`]の3つ |
//!
//! **`kind`へ3つ目の値を足さない。** §10.2が`kind`を「拒否した側」の軸として定義しており、
//! そこへ「何で直るか」を混ぜると2つの軸が1つに潰れる——カーネル側にも
//! 「宣言では直せない拒否」が生まれた日に表現できなくなる。
//!
//! **分類を行に保存しない。** 保存すると正本が2つになり（`B-13`）、しかも分類の規則を直したとき
//! 過去の行だけが古い分類を持ち続ける。理由さえ構造のまま残っていれば、分類はいつでも計算できる。
//!
//! # 「観測していない」を既定値で埋めない
//!
//! `from_domain`と`cwd`は**Daemon経由の拒否でしか取れない**。カーネル拒否
//! （OSが生成そのものを止めたもの）ではこの2つが手に入らないので、[`Option`]にして`null`を書く。
//! 空文字や`0`で埋めると「観測していない」と「観測したが空だった」が区別できなくなる
//! （`P-11`「観測が無い項目に0件と書かない」）。**欄そのものは必ず出す**——
//! 欄ごと省くと、古い版が書いた行と区別できない。
//!
//! # ここが持たないもの
//!
//! - **許可した生成の記録**。§10.2の別のシンクで、置き場も別に決める
//! - **却下印（`dismissed.json`）**。書くのは非特権のポリシーエディタだけで、
//!   その書き手が生まれる回（段階⑦）に作る
//! - **カーネル拒否を購読する常駐プロセス**。欄は在るが購読者は居ない（下記）
//!
//! # カーネル側の行は、今日は1件も書かれない
//!
//! カーネル拒否が起きるのは生成禁止（`CHILD_PROCESS_RESTRICTED`）を積んだときだけで、
//! **製品コードは3箇所とも[`super::ChildProcessPolicy::Unrestricted`]を渡している**
//! （2026-09-12に数えた）。購読を張るのは⑤を製品の既定へ入れる回（6fの後）である。
//! **それでも欄をいま決めるのは、ファイルの形が後から変えられないからである**——
//! 費用の話ではない。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::DenyReason;

/// 待ち行列の置き場（ワークスペースからの相対）。
///
/// **`.harness`配下から動かさないこと。** 自己参照ループ——記録の産物が次の記録の候補に
/// なること——を断っているのは`harness_policy_editor::exclusion::is_harness_control_path`で、
/// 同関数が見るのは**パス要素`.harness`だけ**である。ここを動かした瞬間、
/// 待ち行列そのものが「サンドボックスから触りたいファイル」の候補として提案され始める。
const TRANSITIONS_DIR: &str = "transitions";

/// 拒否の観測を積むファイル。
const PENDING_FILE: &str = "pending.jsonl";

/// 畳み込みで覚えておく**種類**の上限。
///
/// 超えた分は覚えず、数だけ数えて[`PendingRecord::Overflowed`]で1行報告する。
/// **上限を置くのは、要求がフックからも来るようになった日（6f）に備えてである**
/// ——`cargo build`1回で数千のプロセスが起きるので、種類が無制限だとDaemonのメモリが
/// 要求元の都合で伸びる。
const MAX_DISTINCT_KEYS: usize = 1_024;

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

/// 拒否の観測を積むファイル。
///
/// **昇格側もDaemonもパスを受け取らない。** `workspace_root`から導出する——非昇格の親が
/// 指定した任意のパスへ別プロセスが追記する構造は、その別プロセスが昇格した瞬間に
/// **管理者権限での任意パス追記プリミティブそのもの**になる（`P-01`、§10.2）。
/// 既存の監査シンクが同じ理由で同じ形を採っており、**2本目のプリミティブを作らない**。
pub fn pending_path(workspace_root: &Path) -> PathBuf {
    transitions_dir(workspace_root).join(PENDING_FILE)
}

/// 待ち行列の1行。
///
/// **`kind`が答えるのは「誰が拒否したか」だけである**（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingRecord {
    /// Spawn Daemonがポリシー評価の結果として断った。
    DeniedByDaemon(Denial),
    /// OSカーネルが生成そのものを止めた（`CHILD_PROCESS_RESTRICTED`）。
    ///
    /// **今日これを書く者は居ない**（モジュールdoc）。欄だけが先に在る。
    DeniedByKernel(Denial),
    /// 畳み込みが覚えられる種類の上限（[`MAX_DISTINCT_KEYS`]）を超えた。
    ///
    /// **あふれを黙って捨てない**（`B-10`）。捨てた件数を残さないと、
    /// 「その拒否は起きなかった」と読まれる。
    Overflowed {
        /// 覚えられずに捨てた拒否の件数（**種類の数ではなく回数**）。
        dropped: u64,
        last_ts: u64,
    },
}

/// 拒否1種類の観測。
///
/// **1件に1行ではなく、種類ごとに1行**である（§10.2）。同じ種類が繰り返し起きたときは
/// [`Denial::count`]が増え、更新行が追記される。読む側は同じ鍵の行を畳んで**最後の1つ**を採る。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    /// 呼び出し元のドメイン名（`policy.json`の`domains[].name`）。
    ///
    /// **`None`は「観測していない」**——カーネル拒否にはこの情報が無い。
    /// また、Daemon経由でも呼び出し元がProcess Tableに載っていなければ
    /// ドメインが決まらないので`None`になる（[`DenyReason::NotRegistered`]）。
    pub from_domain: Option<String>,
    /// 起こそうとした実行ファイル。
    pub exe: String,
    /// 起こそうとしたコマンドライン（§8.2で判定に使ったのと同一の値）。
    pub argv: String,
    /// 呼び出し元の実cwd。**`None`は「観測していない」**（カーネル拒否では取れない）。
    pub cwd: Option<String>,
    /// 拒否の理由。**構造のまま運ぶ。文字列へ潰さない。**
    ///
    /// 潰すと「宣言が無いのか、ドメインを知らないのか、cwdが違うのか」が消える——
    /// その区別が**そのまま「ユーザーが何を直せばよいか」**である。
    pub reason: DenyReason,
    /// この種類が観測された回数。
    pub count: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    /// argvが切り詰められている疑いがあるか（[`ARGV_TRUNCATION_UTF16_UNITS`]）。
    ///
    /// **Daemon経由の拒否では常に`false`**——要求受付パイプが運ぶコマンドラインは
    /// 切られていない。真になり得るのはカーネル拒否の側だけである。
    pub argv_truncation: bool,
}

/// この拒否は、**何をすれば通るようになるのか**。
///
/// # なぜ行に保存しないのか
///
/// [`DenyReason`]から計算できるからである。保存すると正本が2つになり（`B-13`）、
/// 分類の規則を直したときに過去の行だけが古い分類を持ち続ける。
///
/// # なぜ[`DenyReason`]の写しではないのか
///
/// 拒否の理由は5つあるが、**読む側が要る区別は3つしかない**。理由の語彙は
/// [`DenyReason`]のまま運び、これはそれを3つへ畳んだ**読む側の分類**である。
/// 1対1に対応させると語彙が2つになり、理由を1つ増やしたとき片方だけが古くなる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// `policy.json`に宣言を足す／直せば、次は通る。
    ///
    /// **「解決済みか」の突き合わせを掛けてよいのはこれだけである**（§10.2は
    /// 「解決済みを書き戻さず、`policy.json`と突き合わせて読む側が計算する」と定めている）。
    FixTheDeclaration,
    /// **【暫定】** 宣言は足りている。harness側がまだ実装していないので、いま何を書いても通らない。
    ///
    /// # これに突き合わせを掛けてはいけない
    ///
    /// 辺は一致するので、突き合わせると**「解決済み」と出る**。画面から消え、機械は拒否し
    /// 続ける——症状の出ない誤りになる。だから常に未解決側へ置く。
    ///
    /// # いつ消えるか
    ///
    /// `plans/DESIGN-MAC-BROKER.md` §22.9（ドメイン単位のプロファイル発行器）が着地した日に、
    /// [`DenyReason::TargetDomainNotProvisioned`]ごと消える。**そのとき[`remedy`]は
    /// コンパイルできなくなる**——同関数は`_ =>`を持たないので、変種を消すと腕が浮く。
    /// 消し忘れようがない形にしてある（§10.1.2の「まとめて消す」一覧の4点目）。
    BlockedUntilHarnessImplementsIt,
    /// 宣言とも実装とも関係ない。要求元が壊れた要求を送ったか、Daemonが呼び出し元を知らない。
    ///
    /// **宣言候補として画面に出さない。** 出すと、直しようのない記録に
    /// 「宣言を直せ」の顔をさせることになる。
    NotAboutPolicy,
}

/// 拒否の理由を、[`Remedy`]の3つへ畳む。
///
/// **`_ =>`（その他）を書かないこと。** 理由が1つ増えたとき、ここがコンパイルエラーになって
/// 「その拒否はどちらなのか」を必ず選ばされるのが、この関数の効き目の本体である。
/// 既定へ倒せる形にすると、新しい理由が黙って「宣言を直せ」の側に混ざる。
pub fn remedy(reason: &DenyReason) -> Remedy {
    use harness_policy::transition::TransitionDenial;
    match reason {
        // 呼び出し元が台帳に無い／PIDが再利用されていた。Daemonの状態の問題であって、
        // 宣言をどう書いても変わらない。
        DenyReason::NotRegistered | DenyReason::PidReused => Remedy::NotAboutPolicy,
        // 電文が壊れている・長すぎる・接続元がAppContainerの外だった。要求元の問題。
        DenyReason::MalformedRequest => Remedy::NotAboutPolicy,
        // 辺は許可だったが`CreateProcess`が落ちた。**宣言は既に足りている**ので、
        // 宣言候補として出すと直しようのない記録になる。
        DenyReason::SpawnFailed => Remedy::NotAboutPolicy,
        // [暫定] §22.9が着地したらこの腕ごと消える（[`Remedy::BlockedUntilHarnessImplementsIt`]）。
        DenyReason::TargetDomainNotProvisioned { .. } => Remedy::BlockedUntilHarnessImplementsIt,
        // 判定器が断ったもの。**ここも`_ =>`を書かない**——判定器が理由を増やしたとき、
        // 新しい理由が黙って「宣言を直せ」に混ざるのを止める。
        DenyReason::Transition { denial } => match denial {
            TransitionDenial::UnknownSourceDomain
            | TransitionDenial::NoMatchingEdge
            | TransitionDenial::AmbiguousPattern { .. }
            | TransitionDenial::CwdMismatch { .. } => Remedy::FixTheDeclaration,
        },
    }
}

/// argvが切り詰められている疑いがあるか。
///
/// **「ちょうど閾値」だけを疑う。** 超えているものは切られていない（切られていれば
/// ちょうどになる）ので、`>=`ではなく`==`である。
pub fn argv_is_possibly_truncated(argv: &str) -> bool {
    argv.encode_utf16().count() == ARGV_TRUNCATION_UTF16_UNITS
}

/// 拒否1件について、**観測できた事実**。
///
/// # なぜ[`Option`]の欄があるのか
///
/// **経路によって取れるものが違う**（§10.2）。Daemon経由の拒否では呼び出し元ドメインも
/// 実cwdも取れるが、カーネル拒否（OSが生成そのものを止めたもの）では取れない。
/// **`Option`にしてあることで、書き手は「無い」を明示的に選ばされる**——
/// 空文字を渡して「観測した結果が空だった」に見せかける経路を作らない（`P-11`）。
///
/// この型を1つにしてあるのは、**カーネル側の書き手が来たときに同じ形で積ませる**ためである。
/// 経路ごとに別の引数列を作ると、片方だけが欄を増やして2つの経路の差が消える。
pub struct Observation<'a> {
    /// 呼び出し元のドメイン名（`policy.json`の`domains[].name`）。`None`は観測していない。
    pub from_domain: Option<&'a str>,
    /// 起こそうとした実行ファイル。
    pub exe: &'a str,
    /// 判定に使ったのと同一のコマンドライン（§8.2）。
    pub argv: &'a str,
    /// 呼び出し元の実cwd。`None`は観測していない。
    pub cwd: Option<&'a str>,
    /// 拒否の理由。**構造のまま渡す。**
    pub reason: &'a DenyReason,
}

/// 畳み込みの鍵。**同じ鍵の拒否は1つの種類として数える。**
///
/// 理由まで鍵に入れるのは、同じコマンドが**別の理由で**断られたときに1行へ混ざらない
/// ようにするためである（直し方が違うものを1行にすると、片方の直し方しか分からない）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    kernel: bool,
    from_domain: Option<String>,
    exe: String,
    argv: String,
    cwd: Option<String>,
    reason: DenyReason,
}

/// 追記に失敗したときに、どこまで戻すか。
#[derive(Debug, Clone, Copy)]
enum Rollback {
    Nothing,
    /// 新しい種類として覚えたのを取り消す（次の同じ拒否がもう一度「1件目」になる）。
    Forget,
    /// 「ここまで書いた」の印を元へ戻す。
    RestoreWrittenAt(u64),
}

/// 1種類ぶんの数え上げ。
#[derive(Debug, Clone)]
struct Folded {
    count: u64,
    /// 最後に**ファイルへ書いた**ときの`count`。次に書くのは`written_at * 2`に達したとき。
    written_at: u64,
    first_ts: u64,
    last_ts: u64,
    argv_truncation: bool,
}

/// [`TransitionQueue::record`]が実際に何をしたか。
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
    /// 種類の上限に達していたので、この拒否を種類として覚えなかった（回数だけ数えた）。
    DroppedByCap,
}

/// 書けなかった理由。
///
/// **呼び出し側が握り潰さないように`Result`で返す**（`B-10`）。ただし
/// **これを理由に生成要求の応答を変えてはいけない**——記録は境界ではない（`P-07`）。
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

/// 拒否の待ち行列。**Daemonが1つ持ち、全ての要求受付スレッドが共有する。**
#[derive(Debug)]
pub struct TransitionQueue {
    path: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    entries: HashMap<Key, Folded>,
    /// 上限に達したために覚えられなかった拒否の**回数**。
    dropped: u64,
    /// そのうち、既に[`PendingRecord::Overflowed`]として報告済みの回数。
    dropped_reported: u64,
}

impl TransitionQueue {
    /// `workspace_root`から置き場を導出して作る。**ファイルはまだ触らない。**
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            path: pending_path(workspace_root),
            state: Mutex::new(State::default()),
        }
    }

    /// 積む先。診断とテスト用。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Daemonが拒否した1件を積む。
    ///
    /// # 書くのはいつか（**タイマーを持たない**）
    ///
    /// 1. **1件目は即時に追記する。** Daemonが強制終了されても「その拒否があった」事実は残る
    /// 2. 2件目以降は数えるだけで、**前回書いた数の2倍**に達したときに更新行を追記する
    ///
    /// 2倍にしているのは、ログ量を回数の対数に抑えつつ**時計に依存しない**ためである
    /// （一定間隔で書く形にすると、テストが待ち時間に依存して不安定になる）。
    ///
    /// # 限界
    ///
    /// **Daemonが強制終了されると`count`は最後に書いた値まで戻る。** 失われるのは回数であって、
    /// **拒否があった事実は失われない**（1件目を即時に書いているため）。
    pub fn record_daemon_denial(
        &self,
        observation: Observation<'_>,
        now_ms: u64,
    ) -> Result<Recorded, QueueError> {
        self.record(false, observation, now_ms)
    }

    fn record(
        &self,
        kernel: bool,
        observation: Observation<'_>,
        now_ms: u64,
    ) -> Result<Recorded, QueueError> {
        let argv = observation.argv;
        let key = Key {
            kernel,
            from_domain: observation.from_domain.map(str::to_string),
            exe: observation.exe.to_string(),
            argv: argv.to_string(),
            cwd: observation.cwd.map(str::to_string),
            reason: observation.reason.clone(),
        };

        let (outcome, line, rollback) = {
            let mut state = self.lock();
            match state.entries.get_mut(&key) {
                Some(folded) => {
                    folded.count += 1;
                    folded.last_ts = now_ms;
                    if folded.count >= folded.written_at.saturating_mul(2) {
                        let previous = folded.written_at;
                        folded.written_at = folded.count;
                        let record = record_of(&key, folded);
                        (
                            Recorded::AppendedUpdate {
                                count: folded.count,
                            },
                            Some(record),
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
                        let record = record_of(&key, &folded);
                        state.entries.insert(key.clone(), folded);
                        (Recorded::AppendedFirst, Some(record), Rollback::Forget)
                    }
                }
            }
        };

        if let Some(record) = line {
            if let Err(e) = self.append(&record) {
                self.roll_back(&key, rollback);
                return Err(e);
            }
        }
        Ok(outcome)
    }

    /// 書けなかったときに、**次の機会に書き直せる状態へ戻す**（`B-15`: 記録は実体の完成後）。
    ///
    /// 戻さないと、1回の書込失敗でその種類が**永久に待ち行列へ現れなくなる**——
    /// 覚えている側は「書いた」と思っているので、二度と書こうとしない。
    fn roll_back(&self, key: &Key, rollback: Rollback) {
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

    /// Daemonを畳むときに、**まだ書いていない回数を全部書き出す**。
    ///
    /// 戻り値は追記した行数。**`Result<(), _>`へ潰さない**——0行だったことと
    /// 書けなかったことが区別できないと、後から「積まれていない」の原因が追えない（`B-09`）。
    pub fn flush(&self, now_ms: u64) -> Result<usize, QueueError> {
        // **「書いた」印を付けるのは追記が成功した後である**（`B-15`）。先に付けてから
        // 途中で失敗すると、まだ書いていない回数が「書いた」ことにされて永久に失われる。
        let stale: Vec<(Key, PendingRecord, u64)> = {
            let state = self.lock();
            state
                .entries
                .iter()
                .filter(|(_, folded)| folded.count != folded.written_at)
                .map(|(key, folded)| (key.clone(), record_of(key, folded), folded.count))
                .collect()
        };

        let mut written = 0usize;
        for (key, record, count) in stale {
            self.append(&record)?;
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
            self.append(&PendingRecord::Overflowed {
                dropped,
                last_ts: now_ms,
            })?;
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
    /// 置き場は**非特権のharnessが先に作る**（§10.2、[BUG-109](../../../../../docs/bugs/BUG-109.md)）。
    /// ここの`create_dir_all`は先行作成が失敗したときの保険で、**Daemonは昇格していない**ので
    /// ここで作っても所有者は同じユーザーになる。昇格した購読者が来る日には、
    /// そちら側で同じことをしてはいけない。
    fn append(&self, record: &PendingRecord) -> Result<(), QueueError> {
        use std::io::Write;

        let mut line = serde_json::to_string(record).map_err(|e| self.err(e.to_string()))?;
        line.push('\n');

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| self.err(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| self.err(e.to_string()))?;
        file.write_all(line.as_bytes())
            .map_err(|e| self.err(e.to_string()))
    }

    fn err(&self, message: String) -> QueueError {
        QueueError {
            path: self.path.clone(),
            message,
        }
    }

    /// 毒されたロックでも先へ進む。**待ち行列が壊れても生成の判定は止めない**
    /// ——記録は境界ではない（`P-07`）。
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn record_of(key: &Key, folded: &Folded) -> PendingRecord {
    let denial = Denial {
        from_domain: key.from_domain.clone(),
        exe: key.exe.clone(),
        argv: key.argv.clone(),
        cwd: key.cwd.clone(),
        reason: key.reason.clone(),
        count: folded.count,
        first_ts: folded.first_ts,
        last_ts: folded.last_ts,
        argv_truncation: folded.argv_truncation,
    };
    if key.kernel {
        PendingRecord::DeniedByKernel(denial)
    } else {
        PendingRecord::DeniedByDaemon(denial)
    }
}

#[cfg(test)]
#[path = "transitions_tests.rs"]
mod transitions_tests;
