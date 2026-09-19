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
//! **製品の既定はそれを積まない**（[`super::ChildProcessPolicy::PRODUCT_DEFAULT`]。
//! 2026-09-18に、製品でDaemonを起こす2つのホストとシェルの選び方の**3箇所とも**
//! その定数を読む形へ畳んだ）。購読を張るのは⑤を製品の既定へ入れる回（6fの後）である。
//! **それでも欄をいま決めるのは、ファイルの形が後から変えられないからである**——
//! 費用の話ではない。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::DenyReason;
use crate::tier2a::transitions_log::{FoldedLine, Folded, FoldingLog, ReadLine};
pub use crate::tier2a::transitions_log::{
    argv_is_possibly_truncated, transitions_dir, QueueError, Recorded,
};

/// 拒否の観測を積むファイル。
const PENDING_FILE: &str = "pending.jsonl";

/// 拒否の観測を積むファイル。
///
/// **昇格側もDaemonもパスを受け取らない。** `workspace_root`から導出する——非昇格の親が
/// 指定した任意のパスへ別プロセスが追記する構造は、その別プロセスが昇格した瞬間に
/// **管理者権限での任意パス追記プリミティブそのもの**になる（`P-01`、§10.2）。
/// 既存の監査シンクが同じ理由で同じ形を採っており、**2本目のプリミティブを作らない**。
pub fn pending_path(workspace_root: &Path) -> PathBuf {
    transitions_dir(workspace_root).join(PENDING_FILE)
}

/// [段階6f-3] 待ち行列の**続きだけ**を読んだ結果（§19.3.8）。
///
/// 待ち行列は追記専用なので、前回読んだ位置から先だけを読めば「その間に積まれたもの」が分かる。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct QueueTail {
    /// 読めた行。**壊れた行は黙って飛ばす**——書き手が追記の途中で落ちた場合に、
    /// 以後の読み取りが永久に止まるのを避ける（`B-10`との兼ね合いは[`QueueTail::skipped`]が持つ）。
    pub records: Vec<PendingRecord>,
    /// 次に読み始める位置。**最後の改行までしか進めない**——追記の途中を読んで
    /// しまった場合に、その行を二度と読めなくなるのを避ける。
    pub next_offset: u64,
    /// 解析できずに飛ばした行数。**黙って捨てない**（`B-10`）。
    pub skipped: usize,
}

/// [段階6f-3] 待ち行列を`offset`から先だけ読む（§19.3.8）。
///
/// # ファイルが短くなっていたら先頭から読み直す
///
/// 待ち行列は追記専用だが、**ワークスペースごと作り直されることはある**。
/// 長さが`offset`より短いなら別のファイルなので、位置を信じずに先頭から読む
/// ——信じると、新しいファイルの先頭部分を永久に読み飛ばす。
///
/// # 無いファイルは空である（失敗ではない）
///
/// Daemonが起動していない構成では存在しない。**呼び出し元はそれを「拒否が無い」として扱う**
/// ——ただし「Daemonへ書き出しを頼めなかった」とは区別すること（あちらは注記を出さない）。
pub fn read_from(path: &Path, offset: u64) -> QueueTail {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(path) else {
        return QueueTail::default();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = if len < offset { 0 } else { offset };
    if file.seek(SeekFrom::Start(start)).is_err() {
        return QueueTail::default();
    }
    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return QueueTail::default();
    }
    // **最後の改行までしか採らない。** 追記の途中を読んだ行は次回に回す。
    let complete = match buffer.iter().rposition(|b| *b == b'\n') {
        Some(index) => index + 1,
        None => 0,
    };
    let mut records = Vec::new();
    let mut skipped = 0usize;
    for line in buffer[..complete].split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<PendingRecord>(line) {
            Ok(record) => records.push(record),
            Err(_) => skipped += 1,
        }
    }
    QueueTail {
        records,
        next_offset: start + complete as u64,
        skipped,
    }
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
    /// # いつ消えるか（**2026-09-20に見直した**）
    ///
    /// 当初は「§22.9（ドメイン単位のプロファイル発行器）が着地した日に
    /// [`DenyReason::TargetDomainNotProvisioned`]ごと消える」としていた。
    /// **§22.9の骨格は着地したが、この分類は残っている。**
    ///
    /// 骨格の後も**用意できないドメインはある**——通信を宣言している（harnessが未実装）・
    /// 宣言が許可済みでない（ユーザーが直せる）・入れ物の名前にできない（ユーザーが直せる）。
    /// **拒否の理由はどれだったかを運ばない**ので、分類器からは区別できない。
    /// 保守的にこちら側へ倒してある（逆へ倒すと、直しようのない拒否に「宣言を直せ」と言う）。
    ///
    /// **消えるのは、通信を含めてどのドメインも用意できるようになった日**である。
    /// そのとき[`remedy`]はコンパイルできなくなる——同関数は`_ =>`を持たないので、
    /// 変種を消すと腕が浮く（§10.1.2の一覧の4点目。**残す理由**もそこに書いてある）。
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
        // [#55の骨格が着地した後も残る] **拒否の理由は「用意できなかった理由」まで運ばない。**
        //
        // 骨格の後、用意できない原因は3つある——通信を宣言している（harnessが未実装）・
        // 宣言が許可済みでない（ユーザーが直せる）・入れ物の名前にできない（ユーザーが直せる）。
        // **この変種はどれだったかを持たない**ので、分類器からは区別できない。
        // 直せる場合の案内は**起動時の警告**が持つ（`domain_provision`の`skipped`）。
        //
        // 保守的に「いま何を書いても通らない」側へ倒してある——逆へ倒すと、
        // 直しようのない拒否に「宣言を直せ」と言うことになる。
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
///
/// **`pub`なのは[`FoldedLine`]の関連型として現れるからで、外から組み立てる型ではない**
/// （フィールドは非公開のまま）。積むときは[`Observation`]を渡す。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    kernel: bool,
    from_domain: Option<String>,
    exe: String,
    argv: String,
    cwd: Option<String>,
    reason: DenyReason,
}

/// 畳み方と追記の時機は[`FoldingLog`]が持つ。ここが決めるのは**鍵と行の形**だけである。
impl FoldedLine for PendingRecord {
    type Key = Key;

    fn line(key: &Key, folded: &Folded) -> Result<String, serde_json::Error> {
        serde_json::to_string(&record_of(key, folded))
    }

    fn overflow_line(dropped: u64, last_ts: u64) -> Result<String, serde_json::Error> {
        serde_json::to_string(&PendingRecord::Overflowed { dropped, last_ts })
    }

    /// **[`record_of`]の逆写像**（鍵 → 行 の逆）。すぐ下に並べてあるのは、
    /// 片方だけ欄が増えたときに見つかるようにするためである。
    fn classify(&self) -> ReadLine<Key> {
        let (kernel, denial) = match self {
            PendingRecord::DeniedByDaemon(denial) => (false, denial),
            PendingRecord::DeniedByKernel(denial) => (true, denial),
            PendingRecord::Overflowed { dropped, .. } => {
                return ReadLine::Overflow { dropped: *dropped }
            }
        };
        ReadLine::Kind(Key {
            kernel,
            from_domain: denial.from_domain.clone(),
            exe: denial.exe.clone(),
            argv: denial.argv.clone(),
            cwd: denial.cwd.clone(),
            reason: denial.reason.clone(),
        })
    }
}

/// 拒否を**畳んで全部読む**（段階⑦の遷移画面）。
///
/// **[`read_from`]と用途が違う。** あちらは`run_shell`が「そのコマンドの間に積まれた分」だけを
/// 見るためのもので畳まない。こちらは後から全部を見るので、同じ種類を1行へ畳む。
/// 置き場は`workspace_root`から導出する（[`pending_path`]）——**読む側も綴りを写さない**。
pub fn read_folded(
    workspace_root: &Path,
) -> Result<crate::tier2a::transitions_log::FoldedRead<PendingRecord>, QueueError> {
    crate::tier2a::transitions_log::read_folded(&pending_path(workspace_root))
}

/// 拒否の待ち行列。**Daemonが1つ持ち、全ての要求受付スレッドが共有する。**
///
/// **畳み方・追記の時機・あふれの数え方・書込失敗の巻き戻しは
/// [`crate::tier2a::transitions_log`]が持つ**（同じディレクトリへ積む候補の記録と
/// 数え方を揃えるため。§10.2・§10.3）。ここが持つのは拒否に固有の形だけである。
#[derive(Debug)]
pub struct TransitionQueue {
    log: FoldingLog<PendingRecord>,
}

impl TransitionQueue {
    /// `workspace_root`から置き場を導出して作る。**ファイルはまだ触らない。**
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            log: FoldingLog::new(pending_path(workspace_root)),
        }
    }

    /// 積む先。診断とテスト用。
    pub fn path(&self) -> &Path {
        self.log.path()
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

        self.log.record(key, argv, now_ms)
    }

    /// **まだ書いていない回数を全部書き出す。**
    ///
    /// 戻り値は追記した行数。**`Result<(), _>`へ潰さない**——0行だったことと
    /// 書けなかったことが区別できないと、後から「積まれていない」の原因が追えない（`B-09`）。
    ///
    /// # 呼ぶ者は2つある（2026-09-18に1つ増えた）
    ///
    /// | 誰が | いつ | なぜ |
    /// |---|---|---|
    /// | Daemon自身 | 畳むとき | 落ちる前に回数を残す |
    /// | **[段階6f-3] harness** | `run_shell`が待ち行列を読む直前 | **ファイルのカウントは実際より遅れる**（上の「2倍に達したときだけ書く」）。呼ばないと、断られたのにモデルへ何も出ない回が生まれる |
    ///
    /// **時機そのものは変えていない。** 常時書く形に戻すと`cargo build`1回で数千行になる
    /// ——畳み込みが避けている当のものである。頼まれたときだけ足す。
    pub fn flush(&self, now_ms: u64) -> Result<usize, QueueError> {
        self.log.flush(now_ms)
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
