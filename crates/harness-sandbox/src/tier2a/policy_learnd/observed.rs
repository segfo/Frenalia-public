//! [段階6d] 観測した生成＝**遷移の辺の候補**（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.3）。
//!
//! # 何のためにあるのか
//!
//! 段階6cの待ち行列（`pending.jsonl`）は**断られた遷移**を積むが、辺の候補そのものは作らない。
//! 「このプログラムは普段どのプログラムをどんな引数で起こすのか」は、**まだ何も禁じていない
//! 状態で1回走らせて観測する**しかない。それがポリシーエディタのパス1であり、その観測を
//! `observed.jsonl`へ積むのが本モジュールである。
//!
//! # 1件の候補を作るのに、2つのETWセッションが要る
//!
//! **実行ファイルの綴りとコマンドラインは、別々の系統からしか取れない**（実測、
//! `plans/etw-spike/RESULTS.md` §22.4）。
//!
//! | 要るもの | どちらから取れるか | なぜ片方では足りないか |
//! |---|---|---|
//! | **exe**（フルパス） | マニフェスト側（`Kernel-Process`の`ImageName`） | MOF側の`ImageFileName`は**葉の名前だけ**（`cmd.exe`）。遷移の宣言はフルパスで書く |
//! | **argv**（コマンドライン） | MOF側（`Process_V4_TypeGroup1.CommandLine`） | マニフェスト側は**全43イベントのどの版にもコマンドラインの欄が無い** |
//!
//! だから本モジュールは**pidで2つを突き合わせる**。`argv[0]`を実行ファイルの代わりに使わない
//! ——測定では呼び出し元が書いた綴りそのまま（`"powershell"`）で届いており、
//! **実行ファイルの同一性を`argv[0]`から取ってはならない**（同§22.4の1）。
//!
//! # 突き合わせに失敗したものを、黙って捨てない
//!
//! 2つのセッションは別々に配送されるので、**MOF側が先に届く**ことがある。そのときpidは
//! まだマニフェスト側の台帳に無い。これを即座に捨てると「観測されなかった辺」と
//! 「突き合わせに間に合わなかった辺」が区別できなくなる（§10.3が塞いだ形そのもの）ので、
//! **次のドレインまで持ち越して1度やり直し**、それでも解けなければ**数えて制御レコードへ出す**。
//!
//! # ここが持たないもの
//!
//! - **スコープ判定**。既存の[`super::etw::scope::ScopeTracker`]が持つ（`harness_pid`起点の
//!   親子継承）。**同じ判定を2つ作らない**——片方だけ直したときに、FSの記録と候補の記録で
//!   「対象」の意味が食い違う
//! - **NTパスの変換**。[`super::etw::parse::to_settings_path`]が持つ
//! - **畳み込みと追記の時機**。[`crate::tier2a::transitions_log`]が持つ（拒否の待ち行列と
//!   同じ数え方にするため）

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::tier2a::transitions_log::{
    argv_is_possibly_truncated, transitions_dir, FoldedLine, Folded, FoldingLog, QueueError,
    Recorded,
};

/// 候補を積むファイル。
const OBSERVED_FILE: &str = "observed.jsonl";

/// 突き合わせに間に合わなかった観測を、次のドレインまで持ち越す上限。
///
/// **持ち越しは1回だけ**（[`ObservedCandidates::observe`]）なので、ここに溜まるのは
/// 「直前のドレインで解けなかったもの」だけである。それでも上限を置くのは、
/// マニフェスト側のプロバイダが丸ごと落ちている場合に**全件が毎回持ち越されて伸び続ける**
/// ためで、あふれた分は捨てずに[`ArgvStats::unresolved`]へ数える。
const MAX_CARRIED_OVER: usize = 4_096;

/// 候補を積むファイル。
///
/// **昇格側はパスを受け取らない。** `workspace_root`から導出する——非昇格の親が指定した
/// 任意のパスへ昇格プロセスが追記する構造は、**管理者権限での任意パス追記プリミティブ
/// そのもの**だからである（`P-01`、§10.2）。既存の監査シンクが同じ理由で同じ形を採っており、
/// **2本目のプリミティブを作らない**。
pub fn observed_path(workspace_root: &Path) -> PathBuf {
    transitions_dir(workspace_root).join(OBSERVED_FILE)
}

/// 候補の1行。
///
/// **`kind`は「何の観測か」を答える。** 拒否の待ち行列（`pending.jsonl`）の`kind`が
/// 「誰が拒否したか」を答えるのと**別の軸**だが、混ざらない——ファイルが別であり、
/// 値の集合も重ならない。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservedRecord {
    /// 実際に起きた生成を1種類ぶん。
    ObservedSpawn(Spawn),
    /// 畳み込みが覚えられる種類の上限を超えた。
    ///
    /// **あふれを黙って捨てない**（`B-10`）。捨てた件数を残さないと、
    /// 「その生成は起きなかった」と読まれる。
    Overflowed { dropped: u64, last_ts: u64 },
}

/// 観測した生成1種類。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spawn {
    /// 起こした側の実行ファイル（フルパス）。
    ///
    /// **`None`は「観測していない」**——記録を始める前から動いていたプロセスが親だと、
    /// その実行ファイルはどちらのセッションにも現れない。記録対象のコマンド自身
    /// （親がharness本体）がこの形になる。空文字で埋めない（`P-11`）。
    pub parent_exe: Option<String>,
    /// 起きた側の実行ファイル（フルパス）。**マニフェスト側から取る**（モジュールdoc）。
    pub exe: String,
    /// 起きた側のコマンドライン。**MOF側から取る**（同上）。
    pub argv: String,
    /// この種類が観測された回数。
    pub count: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    /// argvが切り詰められている疑いがあるか。**真ならリテラルの辺の候補にしない**
    /// （`plans/DESIGN-MAC.md` §5.1(6)）。閾値の正本は[`crate::tier2a::transitions_log`]。
    pub argv_truncation: bool,
}

/// 畳み込みの鍵。**同じ鍵の生成は1つの種類として数える。**
///
/// 親まで鍵に入れるのは、**同じコマンドが別の親から起きたときに1行へ混ざらない**ように
/// するためである（辺は`(遷移元, exe, argv)`の3つ組なので、親が違えば別の辺になる）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    parent_exe: Option<String>,
    exe: String,
    argv: String,
}

impl FoldedLine for ObservedRecord {
    type Key = Key;

    fn line(key: &Key, folded: &Folded) -> Result<String, serde_json::Error> {
        serde_json::to_string(&ObservedRecord::ObservedSpawn(Spawn {
            parent_exe: key.parent_exe.clone(),
            exe: key.exe.clone(),
            argv: key.argv.clone(),
            count: folded.count,
            first_ts: folded.first_ts,
            last_ts: folded.last_ts,
            argv_truncation: folded.argv_truncation,
        }))
    }

    fn overflow_line(dropped: u64, last_ts: u64) -> Result<String, serde_json::Error> {
        serde_json::to_string(&ObservedRecord::Overflowed { dropped, last_ts })
    }
}

/// MOF側から取り出した観測1件（pidとコマンドラインだけ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgvEvent {
    pub pid: u32,
    pub argv: String,
}

/// pidを引いた結果。**呼び出し側（収集器）がスコープ判定と実行像の解決を担う。**
///
/// ここを`Option`ひとつにしないのは、**3つの「書かない理由」を区別するため**である——
/// 対象外／まだ分からない／対象だが実行ファイルの綴りが出せない。区別を潰すと、
/// 制御レコードが「何件落としたか」しか言えなくなり、**原因の側が消える**（`B-10`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// 記録の対象。`exe`が`None`なら実行像の綴りを出せなかった（未知のボリューム）。
    InScope {
        exe: Option<String>,
        parent_exe: Option<String>,
    },
    /// 記録の対象ではない（この記録が起こしたプロセスの子孫ではない）。
    OutOfScope,
    /// まだ判定できない（マニフェスト側のイベントがこのpidについてまだ届いていない）。
    Unknown,
}

/// 書けなかった観測の内訳。**制御レコードへ出す**（D-43: 取りこぼしを隠さない）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArgvStats {
    /// コマンドラインの欄が空だった観測。
    pub without_command_line: u64,
    /// 記録の対象外だった観測（正常。診断のために数える）。
    pub out_of_scope: u64,
    /// 持ち越してもpidを引けなかった観測。
    pub unresolved: u64,
    /// 対象だったが実行像の綴りを出せなかった観測（未知のボリューム）。
    pub without_exe: u64,
    /// 実際に積んだ観測（種類ではなく件数）。
    pub recorded: u64,
}

/// 観測した候補を積む。**収集器が1世代につき1つ持つ。**
pub struct ObservedCandidates {
    log: FoldingLog<ObservedRecord>,
    /// 突き合わせに間に合わず、次のドレインでやり直すもの（モジュールdoc）。
    carried_over: Vec<ArgvEvent>,
    stats: ArgvStats,
}

impl ObservedCandidates {
    /// `workspace_root`から置き場を導出して作る。**ファイルはまだ触らない。**
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            log: FoldingLog::new(observed_path(workspace_root)),
            carried_over: Vec::new(),
            stats: ArgvStats::default(),
        }
    }

    /// 積む先。診断とテスト用。
    pub fn path(&self) -> &Path {
        self.log.path()
    }

    pub fn stats(&self) -> ArgvStats {
        self.stats
    }

    /// 1バッチ分の観測を積む。解けなかったものは**次の呼び出しへ持ち越す**。
    ///
    /// `resolve`はpidを引く関数で、スコープ判定と実行像の解決は呼び出し側が行う
    /// （モジュールdoc「ここが持たないもの」）。
    ///
    /// **戻り値は書込の失敗だけ。** 観測が対象外だった・解けなかったは失敗ではないので
    /// [`ArgvStats`]に数えて`Ok`を返す——ここでエラーにすると、収集そのものが
    /// 記録の都合で止まる（`P-07`: 記録は境界ではない）。
    pub fn observe(
        &mut self,
        events: Vec<ArgvEvent>,
        mut resolve: impl FnMut(u32) -> Resolution,
        now_ms: u64,
    ) -> Result<(), QueueError> {
        // **持ち越し分を先に処理する。** 後回しにすると、同じpidの新しい観測のほうが
        // 先に書かれて`first_ts`が逆転する。
        let carried = std::mem::take(&mut self.carried_over);
        let mut first_error = None;
        for event in carried.into_iter().chain(events) {
            // 持ち越しは1回だけ——ここで解けなければ数えて捨てる（無限に溜めない）。
            let retry = self.carried_over.len() < MAX_CARRIED_OVER;
            if let Err(e) = self.record_one(event, &mut resolve, now_ms, retry) {
                // **最初の失敗で打ち切らない。** 1件書けなかったせいで残りの観測まで
                // 落とすと、失敗の影響が「その1件」から「そのバッチ全部」へ広がる。
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn record_one(
        &mut self,
        event: ArgvEvent,
        resolve: &mut impl FnMut(u32) -> Resolution,
        now_ms: u64,
        may_carry_over: bool,
    ) -> Result<(), QueueError> {
        match resolve(event.pid) {
            Resolution::OutOfScope => {
                self.stats.out_of_scope = self.stats.out_of_scope.saturating_add(1);
                Ok(())
            }
            Resolution::Unknown => {
                if may_carry_over {
                    self.carried_over.push(event);
                } else {
                    self.stats.unresolved = self.stats.unresolved.saturating_add(1);
                }
                Ok(())
            }
            Resolution::InScope {
                exe: None,
                parent_exe: _,
            } => {
                // **生のNTパスを載せない。** 読む側で「宣言へ書ける値」と誤解され得る
                // （既存のFS記録が同じ理由で同じ扱いにしている）。
                self.stats.without_exe = self.stats.without_exe.saturating_add(1);
                Ok(())
            }
            Resolution::InScope {
                exe: Some(exe),
                parent_exe,
            } => {
                let key = Key {
                    parent_exe,
                    exe,
                    argv: event.argv.clone(),
                };
                // **上限に達して覚えられなかったものを「積んだ」と数えない**——
                // その件数は共通部品があふれとして別に報告する（`B-10`）。
                if self.log.record(key, &event.argv, now_ms)? != Recorded::DroppedByCap {
                    self.stats.recorded = self.stats.recorded.saturating_add(1);
                }
                Ok(())
            }
        }
    }

    /// 記録を畳むときに、**まだ書いていない回数と、解けなかった件数を確定させる**。
    ///
    /// 戻り値は追記した行数（`B-09`: 0行だったことと書けなかったことを区別する）。
    pub fn finish(&mut self, now_ms: u64) -> Result<usize, QueueError> {
        // 持ち越したまま終わったものは、**もう解ける機会が無い**ので数え切る。
        let stranded = self.carried_over.len() as u64;
        self.carried_over.clear();
        self.stats.unresolved = self.stats.unresolved.saturating_add(stranded);
        self.log.flush(now_ms)
    }

    /// コマンドラインの欄が空だった観測を数える（呼び出し側が判定する）。
    pub fn count_missing_command_line(&mut self) {
        self.stats.without_command_line = self.stats.without_command_line.saturating_add(1);
    }
}

/// argvが切り詰められている疑いがあるか（読む側が使う。閾値の正本は共通部品）。
pub fn argv_possibly_truncated(argv: &str) -> bool {
    argv_is_possibly_truncated(argv)
}

#[cfg(test)]
#[path = "observed_tests.rs"]
mod observed_tests;
