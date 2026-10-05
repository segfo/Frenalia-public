//! 記録1回のあいだに観測したプロセスの**インスタンスの表**（昇格側、決定23(5)）。
//!
//! # 何のためにあるのか
//!
//! 収集プロセスは`ProcessStart`（マニフェスト側の`Kernel-Process`）で知ったプロセスの素性
//! （実行ファイル・親）を、後から届く通知へ付ける。かつての表（`server.rs`の`ProcessTree`）は
//! **pid だけを鍵にした上書きの表**で、同じ pid が使い回されると、前のプロセスのアクセスにも
//! 後のプロセスの素性が付いた（2秒ごとのまとまりの中で起きても区別できなかった）。
//!
//! この表はそれを広げたもので、**3つ目の表ではない**（決定23(5)「新設は書き出す型だけ。
//! メモリ上の表は既存を広げる」）。インスタンスを届いた順に1回ずつ持ち、2通りに引く。
//! **親は番号（`ProcessSequenceNumber`）のまま`process-audit.jsonl`へ書き、木に組むのは読む側である**
//! （`harness_policy::process_tree`）——pid で引き直さない（決定65の追記(3)）。番号の表（`by_seq`）は
//! 同じ番号を二重に入れないための索引として残っている。
//!
//! | 引き方 | 鍵 | 使う人 |
//! |---|---|---|
//! | [`ProcessInstances::at`] | pid ＋時刻（その時刻より前に始まった最も新しいもの） | FS の記録を書く2か所（`flush_batch`・`flush_batch_record_all`） |
//! | [`ProcessInstances::near`] | pid ＋時刻の窓（両端を含む） | MOF 側のコマンドラインの結び付け（`process_audit.rs`、2ms の窓） |
//!
//! # インスタンスを外さない（限界）
//!
//! `ProcessStop`は解読しないので、終わったプロセスも表に残る。**表は記録1回（`Generation`）ごとに
//! 捨てる**（D-56）ので、メモリは記録1回のあいだにマシン全体で起きた`ProcessStart`の数に比例する
//! ——旧`ProcessTree`も上限の無い pid の表で、上限が無いことは変わらない。
//! 決定65の追記(4)の「番号で外す」は外すときの作法で、外すこと自体はこの段では行わない。
//!
//! 外さないことの帰結として、**開始を取りこぼした pid の再利用**（後のプロセスの開始が届かなかった）
//! では、後のプロセスのアクセスが前のインスタンスに付く。これは旧表でも同じで、通し番号の無い
//! 版（`ProcessStart` v0〜v2）でも同じである。

use std::collections::HashMap;

use harness_policy::process_event::ParentSeqSource;

use super::etw::parse::to_settings_path;
use super::etw::session::ProcessStartInfo;

/// `ProcessStart`から拾ったプロセスのインスタンス1つ。
///
/// スコープ判定（`ScopeTracker`）とは別に持つ。あちらが答えるのは「対象か」だけで、
/// 「誰の子か・何の実行ファイルか」は保持しない——判定に不要な情報を判定器へ足すと、
/// 判定の単体テストがツリー表示の都合で壊れるようになる。判定の**答え**（`in_scope`・
/// `is_scope_root`）はここへ写して持つ（判定そのものは写さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessIdentity {
    /// `ProcessSequenceNumber`（同一性）。`ProcessStart` v0〜v2 には無い。
    pub(super) seq: Option<u64>,
    /// 親の番号（ETWの`ParentProcessSequenceNumber`の欄。0 は`None`へ寄せた後）。
    pub(super) parent_seq: Option<u64>,
    /// `parent_seq`の出どころ（[`ParentSeqSource::from_etw_field`]の結果）。
    pub(super) parent_seq_source: ParentSeqSource,
    pub(super) pid: u32,
    pub(super) parent_pid: Option<u32>,
    /// 実行像を設定の綴りへ寄せたもの。寄せられなければ`None`（生のNTパスを載せない）。
    pub(super) image_name: Option<String>,
    /// `ProcessStart`の時刻（Unixミリ秒）。
    pub(super) start_unix_ms: u64,
    /// 開始の時点でこの記録の対象と判定したか（`ScopeTracker::on_process_start_probing`の戻り値）。
    pub(super) in_scope: bool,
    /// 記録の根か（`ScopeTracker::is_scope_root(parent_pid)`）。
    pub(super) is_scope_root: bool,
}

/// インスタンスの表。届いた順に追記するだけで、外さない（モジュールdoc）。
#[derive(Debug, Default)]
pub(super) struct ProcessInstances {
    /// 届いた順。添字が[`Self::get`]の鍵になる（追記しかしないので、添字は動かない）。
    all: Vec<ProcessIdentity>,
    by_seq: HashMap<u64, usize>,
    /// 同じ pid の開始を**開始時刻の昇順**で（同じ時刻は届いた順）。
    by_pid: HashMap<u32, Vec<usize>>,
}

impl ProcessInstances {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// 1つ入れて、表の添字を返す。**同じ`seq`が2回来たら2回目は入れない**（`None`）——
    /// 同じインスタンスを2つの節点として書かないため。`seq`の無いものは毎回入れる。
    pub(super) fn insert(&mut self, identity: ProcessIdentity) -> Option<usize> {
        if let Some(seq) = identity.seq {
            if self.by_seq.contains_key(&seq) {
                return None;
            }
        }
        let index = self.all.len();
        let start = identity.start_unix_ms;
        if let Some(seq) = identity.seq {
            self.by_seq.insert(seq, index);
        }
        let same_pid = self.by_pid.entry(identity.pid).or_default();
        // **届いた順ではなく開始時刻で並べる**——2つのまとまりをまたいで届く順が入れ替わっても、
        // 「その時刻より前に始まった最も新しいもの」が引けるようにする。
        let position = same_pid.partition_point(|&i| self.all[i].start_unix_ms <= start);
        same_pid.insert(position, index);
        self.all.push(identity);
        Some(index)
    }

    /// **FS の記録用**: pid が同じで、開始が`at_unix_ms`以前のうち最も新しいもの。
    ///
    /// 同じまとまりの中で pid が使い回されても、アクセスの時刻で正しいインスタンスに付く。
    /// `at_unix_ms`に`u64::MAX`を渡すと「その pid の最も新しい開始」になる（旧`ProcessTree`の`get`）。
    pub(super) fn at(&self, pid: u32, at_unix_ms: u64) -> Option<&ProcessIdentity> {
        let same_pid = self.by_pid.get(&pid)?;
        let position = same_pid.partition_point(|&i| self.all[i].start_unix_ms <= at_unix_ms);
        let index = *same_pid.get(position.checked_sub(1)?)?;
        Some(&self.all[index])
    }

    /// **引数の結び付け用**: pid が同じで、開始が`at_unix_ms ± window_ms`（両端を含む）のものの添字。
    pub(super) fn near(&self, pid: u32, at_unix_ms: u64, window_ms: u64) -> Vec<usize> {
        let Some(same_pid) = self.by_pid.get(&pid) else {
            return Vec::new();
        };
        let low = at_unix_ms.saturating_sub(window_ms);
        let high = at_unix_ms.saturating_add(window_ms);
        same_pid
            .iter()
            .copied()
            .filter(|&i| (low..=high).contains(&self.all[i].start_unix_ms))
            .collect()
    }

    pub(super) fn get(&self, index: usize) -> &ProcessIdentity {
        &self.all[index]
    }

    pub(super) fn len(&self) -> usize {
        self.all.len()
    }
}

/// `ProcessStart`1件を表へ入れる。**実行像は設定パスへ寄せてから**入れる。
///
/// ETWが報告する`ImageName`はNT形式（`\Device\HarddiskVolume3\...`）である。ファイル名側
/// （`FileName`）は既に[`to_settings_path`]を通しているのに実行像だけ生のままだったため、
/// 読む側は同じJSONLの中に2種類の綴りを持つことになっていた。**変換はボリューム対応表を
/// 持っているこちら側（昇格側）でしかできない**——非昇格の読み手は`\Device\HarddiskVolumeN`が
/// どのドライブかを知らない。
///
/// 変換できないもの（未知のボリューム）は`None`にする。**生のNTパスを載せない**のは、
/// それが読む側で「設定へ書ける値」と誤解され得るからで、代わりに件数を制御レコードへ出す——
/// **戻り値が真なら、寄せられなかったインスタンスを表へ入れた**（呼び出し側が`Dropped.images`を数える）。
///
/// `in_scope`・`is_scope_root`は呼び出し側が`ScopeTracker`に聞いた答えをそのまま渡す
/// （判定をここで作り直さない）。
pub(super) fn remember(
    instances: &mut ProcessInstances,
    start: &ProcessStartInfo,
    volumes: &[(String, String)],
    in_scope: bool,
    is_scope_root: bool,
) -> bool {
    let (image_name, unconvertible) = match start.image_name.as_deref() {
        Some(raw) => match to_settings_path(raw, volumes) {
            Some(path) => (Some(path), false),
            None => (None, true),
        },
        None => (None, false),
    };
    let (parent_seq, parent_seq_source) =
        ParentSeqSource::from_etw_field(start.parent_process_sequence_number);
    let inserted = instances.insert(ProcessIdentity {
        seq: start.process_sequence_number,
        parent_seq,
        parent_seq_source,
        pid: start.pid,
        parent_pid: start.parent_pid,
        image_name,
        start_unix_ms: start.timestamp_unix_ms,
        in_scope,
        is_scope_root,
    });
    inserted.is_some() && unconvertible
}

#[cfg(test)]
#[path = "instances_tests.rs"]
mod instances_tests;
