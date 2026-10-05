//! `process-audit.jsonl`——**記録したプロセスの木**を書く（昇格側、決定23(3)(4)）。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタは、記録したプロセスの木の「位置」ごとに遷移先のドメインを割り当てる
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`の決定65）。そのためには「どのインスタンスが、どの
//! インスタンスから、どの実行ファイルとコマンドラインで起きたか」が1行ずつ要る。型は
//! `harness_policy::process_event`にあり（書く側と読む側が同じ型を使う）、本モジュールは
//! **それを組み立てて書く側**である。
//!
//! # 1行を作るのに、2つの購読を結び付ける
//!
//! | 要るもの | どちらから | 本モジュールでの扱い |
//! |---|---|---|
//! | 実行ファイル・親の番号・自分の番号 | マニフェスト側（`Kernel-Process`の`ProcessStart`） | [`ProcessInstances`]（`server.rs`が埋める表）から読む |
//! | コマンドライン | MOF側（`Process`クラスの`Start`） | [`ProcessAudit::drain`]が受け取る |
//!
//! 結び付けは「**pid が同じで、開始の時刻の差が ±[`ARGV_WINDOW_MS`]（両端を含む）**のインスタンスが
//! ちょうど1つ」のときだけ行う（決定65の追記(4)、`plans/etw-spike/RESULTS.md` §24.5）。2つ以上なら
//! **結び付けない**（`AmbiguousWithinWindow`。誤って細分化するより、分からないと書く）。pid だけで
//! 引かないのは、pid が使い回されるからである（§23.1）。
//!
//! # 届く順は保証されない——持ち越しは1回、あふれは数える
//!
//! 2つの購読は別々に配送されるので、どちらが先に届くかは決まっていない。
//!
//! - **インスタンスが先に届いた**: 引数を待つ（[`MAX_AWAITING`]件まで）。次のドレインまで1回だけ
//!   持ち越し、それでも来なければ`Missing{NoArgvObserved}`で書く。インスタンスは**捨てない**
//!   （捨てると「そのコマンドは走らなかった」と区別が付かない、§19.3.11）
//! - **MOF側が先に届いた**: 次のドレインまで1回だけ持ち越す（[`MAX_UNPAIRED_MOF`]件まで）。
//!   それでも相手が無ければ数える
//!
//! あふれた分は待たずに決めて数える（`waiting_overflowed`）。[`ProcessAudit::finish`]は持ち越さずに
//! 全部書き切り、歩留まりを`process-audit.jsonl`の制御レコードとして書く（決定23(4)。0件の項目は
//! 書かない）。
//!
//! # DCStart は結び付けない
//!
//! MOFの`DCStart`（`EventType` 3）は、セッションを張った瞬間に**既に居た全プロセス**を列挙する
//! rundownである。記録の木の節点（記録中に起きた開始）ではないので、結び付けずに数えるだけにする
//! （`dcstart_excluded`）。かつての結び付け（`server.rs`の`resolve_for_candidate`）はこれを区別せず、
//! 表に無い pid のたびにスコープ判定の「判定できなかった」の数を増やしていた
//! （[BUG-228](../../../../docs/bugs/BUG-228.md)）。
//!
//! # `observed.jsonl`は同じ結び付けの結果から書く（暫定）
//!
//! 遷移の辺の候補（`observed.rs`）は、ここで結び付けた結果を**答えの決まった`Resolution`**で
//! 1件ずつ渡して書く（書式は変えない）。`Resolution::Unknown`を渡さないのは、それを渡すと
//! `observe`の中の持ち越しに入り、次の呼び出しで別のプロセスとして解決されるからである。
//! `observed.jsonl`は P4.8 で読む側ごと消える暫定の記録（決定65の寿命）。
//!
//! # 限界（同じ場所で言う）
//!
//! - **行の順序は開始順を保証しない。** 読む側は全部読んでから木を組む
//! - `ProcessSequenceNumber`を持てない版（`ProcessStart` v0〜v2）のインスタンスは書けない
//!   （同一性が無い）。数える（`without_sequence_number`）
//! - 記録を止める瞬間にマニフェスト側に残っていた開始は拾わない（`server.rs`の`finish`。P2 では
//!   触らない既存の非対称）。その相手の MOF の開始は`mof_start_without_instance`に数える

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use harness_policy::process_event::{
    ArgvBinding, ArgvMissingReason, ArgvTruncation, ParentSeqSource, ProcessAuditRecord,
    ProcessInstance, PROCESS_AUDIT_SCHEMA_VERSION,
};

use super::etw::mof::{MofProcessStart, EVENT_TYPE_PROCESS_DC_START};
use super::instances::ProcessInstances;
use super::observed::{ArgvEvent, ArgvStats, ObservedCandidates, Resolution};
use crate::tier2a::transitions_log::{argv_truncation_from_utf16, QueueError};

/// 結び付けの時刻の窓（±、両端を含む）。決定65の追記(4)（実測の根拠は`RESULTS.md` §24.5）。
pub(super) const ARGV_WINDOW_MS: u64 = 2;
/// 引数を待つインスタンスの上限。前例は`etw/mof.rs`の`PENDING_CREATE_CAPACITY`（4,096）。
const MAX_AWAITING: usize = 4_096;
/// 相手のインスタンスを待つ MOF の開始の上限（同上）。
const MAX_UNPAIRED_MOF: usize = 4_096;

/// MOF の開始1件の結び付け先。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pairing {
    /// 窓の中にちょうど1つ（表の添字）。
    Exact(usize),
    /// 窓の中に2つ以上。どれの引数か決めない。
    Ambiguous(Vec<usize>),
    /// 窓の中に無い（まだ届いていないか、取りこぼした）。
    NoInstance,
}

/// MOF の開始1件を、pid が同じで開始が ±[`ARGV_WINDOW_MS`] のインスタンスへ結び付ける（純粋関数）。
pub(super) fn pair(instances: &ProcessInstances, pid: u32, at_unix_ms: u64) -> Pairing {
    let found = instances.near(pid, at_unix_ms, ARGV_WINDOW_MS);
    match found.as_slice() {
        [] => Pairing::NoInstance,
        [only] => Pairing::Exact(*only),
        _ => Pairing::Ambiguous(found),
    }
}

/// 歩留まり。[`ProcessAudit::finish`]が0でないものを制御レコードとして書く。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ProcessAuditStats {
    /// 書いたインスタンスの行。
    pub(super) written: u64,
    /// コマンドラインを結び付けた（`Exact`）。
    pub(super) exact: u64,
    /// 持ち越しても MOF の開始が来なかった（`Missing{NoArgvObserved}`）。
    pub(super) no_argv_observed: u64,
    /// 窓の中に候補が2つ以上（`Missing{AmbiguousWithinWindow}`）。
    pub(super) ambiguous: u64,
    /// 結び付いたがコマンドラインの欄が無かった（`Missing{NoCommandLineField}`）。
    pub(super) no_command_line_field: u64,
    /// 1,024 UTF-16単位ちょうど（`Suspected`）。
    pub(super) suspected_truncation: u64,
    /// 1,024単位ちょうどで末尾が対にならない高位サロゲート（`Certain`）。
    pub(super) certain_truncation: u64,
    /// 親の番号の欄が無い・0（`parent_seq_source: unresolved`で書いた）。
    pub(super) parent_unresolved: u64,
    /// 対象のインスタンスだが`ProcessSequenceNumber`が無く、書けなかった。
    pub(super) without_sequence_number: u64,
    /// 結び付けずに数えた MOF の`DCStart`（記録を始める前から居たプロセス）。
    pub(super) dcstart_excluded: u64,
    /// 持ち越しても相手のインスタンスが無かった MOF の開始。
    pub(super) mof_without_instance: u64,
    /// 同じインスタンスへ2件目の MOF の開始が結び付いた（`observed.jsonl`へ二重に入れない）。
    pub(super) bound_twice: u64,
    /// インスタンスを`NoArgvObserved`で書いた後に、その MOF の開始が届いた（`observed.jsonl`へは入れる）。
    pub(super) argv_after_settled: u64,
    /// 待ちの上限を超えたので、待たずに決めた（インスタンスか MOF の開始）。
    pub(super) overflowed: u64,
    /// 書けなかった行（版の行・インスタンス・制御）。
    pub(super) write_failed: u64,
}

/// 引数を待つインスタンス（表の添字と、1回持ち越したか）。
#[derive(Debug, Clone, Copy)]
struct Awaiting {
    index: usize,
    carried: bool,
}

/// `process-audit.jsonl`の書き手。**収集の1世代（`Generation`）につき1つ**で、引数の観測を張れた世代
/// だけが持つ（`server.rs`）。
pub(super) struct ProcessAudit {
    /// `process_audit_path(検証済みの fs-audit のパス)`。
    path: PathBuf,
    /// `observed.jsonl`の積み先（同じ結び付けの結果から書く、暫定）。
    candidates: ObservedCandidates,
    /// 表（[`ProcessInstances`]）のどこまで見たか。
    cursor: usize,
    /// 引数待ちの対象インスタンス。
    awaiting: Vec<Awaiting>,
    /// 相手のインスタンスがまだ無い MOF の開始（1回持ち越したか）。
    unpaired: Vec<(MofProcessStart, bool)>,
    /// MOF の開始が1件でも結び付いたインスタンス（`observed.jsonl`へ二重に入れないため）。
    bound: HashSet<usize>,
    stats: ProcessAuditStats,
}

impl ProcessAudit {
    /// 版の行を書いて始める。`write_line`は1行追記して成否を返す（`server.rs`の`append_line`）。
    pub(super) fn start(
        path: PathBuf,
        candidates: ObservedCandidates,
        write_line: &dyn Fn(&str) -> bool,
    ) -> Self {
        let mut audit = Self {
            path,
            candidates,
            cursor: 0,
            awaiting: Vec::new(),
            unpaired: Vec::new(),
            bound: HashSet::new(),
            stats: ProcessAuditStats::default(),
        };
        audit.write(
            &ProcessAuditRecord::Header {
                schema_version: PROCESS_AUDIT_SCHEMA_VERSION,
            },
            write_line,
        );
        audit
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// 1回のドレイン。表に増えたインスタンスと、届いた MOF の開始を結び付け、決まったものを書く。
    ///
    /// **戻り値は`observed.jsonl`の書込の失敗だけ**（最初の1つ）。結び付かなかったことは失敗では
    /// ないので数えるだけ（`P-07`: 記録の都合で収集を止めない）。
    pub(super) fn drain(
        &mut self,
        instances: &ProcessInstances,
        mof: Vec<MofProcessStart>,
        now_ms: u64,
        write_line: &dyn Fn(&str) -> bool,
    ) -> Result<(), QueueError> {
        self.pass(instances, mof, now_ms, write_line, true)
    }

    /// 何も持ち越さずに全部書き切り、歩留まりを制御レコードとして`process-audit.jsonl`へ書き、
    /// `observed.jsonl`を畳む。返す`ArgvStats`は`fs-audit.jsonl`側の既存の統計（`record_argv_stats`）に渡す。
    pub(super) fn finish(
        mut self,
        instances: &ProcessInstances,
        mof: Vec<MofProcessStart>,
        now_ms: u64,
        write_line: &dyn Fn(&str) -> bool,
    ) -> (ArgvStats, ProcessAuditStats, Result<usize, QueueError>) {
        let pass = self.pass(instances, mof, now_ms, write_line, false);
        self.write_controls(now_ms, write_line);
        let flushed = self.candidates.finish(now_ms);
        let result = match pass {
            Err(e) => Err(e),
            Ok(()) => flushed,
        };
        (self.candidates.stats(), self.stats, result)
    }

    /// `drain`と`finish`の本体。`may_carry`が偽なら何も持ち越さない。
    fn pass(
        &mut self,
        instances: &ProcessInstances,
        mof: Vec<MofProcessStart>,
        now_ms: u64,
        write_line: &dyn Fn(&str) -> bool,
        may_carry: bool,
    ) -> Result<(), QueueError> {
        let mut settled: Vec<(usize, ArgvBinding)> = Vec::new();
        let mut first_error = None;

        // 1. 表に増えたインスタンスのうち対象のものを、引数待ちへ。
        for index in self.cursor..instances.len() {
            let identity = instances.get(index);
            if !identity.in_scope {
                continue;
            }
            if identity.seq.is_none() {
                // 同一性が無いので書けない。`observed.jsonl`へは 2. で入れる。
                self.stats.without_sequence_number += 1;
                continue;
            }
            if self.awaiting.len() >= MAX_AWAITING {
                self.stats.overflowed += 1;
                self.stats.no_argv_observed += 1;
                settled.push((index, missing(ArgvMissingReason::NoArgvObserved)));
                continue;
            }
            self.awaiting.push(Awaiting {
                index,
                carried: false,
            });
        }
        self.cursor = instances.len();

        // 2. MOF の開始を、持ち越し分 → 今回分の順に1件ずつ。
        let carried = std::mem::take(&mut self.unpaired);
        let incoming = carried
            .into_iter()
            .chain(mof.into_iter().map(|start| (start, false)));
        for (start, was_carried) in incoming {
            if start.event_type == EVENT_TYPE_PROCESS_DC_START {
                self.stats.dcstart_excluded += 1;
                continue;
            }
            let Some(pid) = start.pid else {
                self.candidates.count_missing_command_line();
                continue;
            };
            match pair(instances, pid, start.timestamp_unix_ms) {
                Pairing::NoInstance => {
                    if may_carry && !was_carried {
                        if self.unpaired.len() < MAX_UNPAIRED_MOF {
                            self.unpaired.push((start, true));
                            continue;
                        }
                        self.stats.overflowed += 1;
                    }
                    self.stats.mof_without_instance += 1;
                    self.count_unmatched(&start);
                }
                Pairing::Ambiguous(found) => {
                    for index in found {
                        if let Some(position) = self.awaiting.iter().position(|a| a.index == index) {
                            self.awaiting.remove(position);
                            self.stats.ambiguous += 1;
                            settled.push((index, missing(ArgvMissingReason::AmbiguousWithinWindow)));
                        }
                    }
                    self.count_unmatched(&start);
                }
                Pairing::Exact(index) => {
                    if let Err(e) = self.bind(instances, index, start, now_ms, &mut settled) {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }

        // 3. 決まらなかった引数待ち: 1回だけ持ち越し、それでも来なければ「観測されなかった」で書く。
        for waiting in std::mem::take(&mut self.awaiting) {
            if may_carry && !waiting.carried {
                self.awaiting.push(Awaiting {
                    index: waiting.index,
                    carried: true,
                });
            } else {
                self.stats.no_argv_observed += 1;
                settled.push((waiting.index, missing(ArgvMissingReason::NoArgvObserved)));
            }
        }

        // 4. 決まったものを1行ずつ書く。
        for (index, argv) in settled {
            self.write_instance(instances, index, argv, write_line);
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// `Exact`の結び付け1件。`observed.jsonl`へは**答えの決まった`Resolution`**で1件だけ渡す。
    fn bind(
        &mut self,
        instances: &ProcessInstances,
        index: usize,
        start: MofProcessStart,
        now_ms: u64,
        settled: &mut Vec<(usize, ArgvBinding)>,
    ) -> Result<(), QueueError> {
        let identity = instances.get(index);
        let pid = identity.pid;
        // **コマンドラインの無い開始は、どの分岐でも1回だけ数える**（旧`drain_argv`と同じ数え方）。
        if start.command_line.is_none() {
            self.candidates.count_missing_command_line();
        }
        if !identity.in_scope {
            return match start.command_line {
                Some(argv) => self.candidates.observe(
                    vec![ArgvEvent { pid, argv }],
                    |_| Resolution::OutOfScope,
                    now_ms,
                ),
                None => Ok(()),
            };
        }
        if !self.bound.insert(index) {
            // 同じインスタンスへ2件目。`observed.jsonl`へ二重に入れない。
            self.stats.bound_twice += 1;
            return Ok(());
        }
        match self.awaiting.iter().position(|a| a.index == index) {
            Some(position) => {
                self.awaiting.remove(position);
                let binding = match &start.command_line {
                    Some(command_line) => {
                        let truncation = truncation_of(&start, command_line);
                        match truncation {
                            ArgvTruncation::None => {}
                            ArgvTruncation::Suspected => self.stats.suspected_truncation += 1,
                            ArgvTruncation::Certain => self.stats.certain_truncation += 1,
                        }
                        self.stats.exact += 1;
                        ArgvBinding::Exact {
                            command_line: command_line.clone(),
                            truncation,
                        }
                    }
                    None => {
                        self.stats.no_command_line_field += 1;
                        missing(ArgvMissingReason::NoCommandLineField)
                    }
                };
                settled.push((index, binding));
            }
            // 番号の無いインスタンスは`process-audit.jsonl`に書けないが、`observed.jsonl`へは入れる。
            None if identity.seq.is_none() => {}
            // 番号があるのに待っていない＝もう書いた（持ち越しを超えた・待ちがあふれた）。
            None => self.stats.argv_after_settled += 1,
        }
        match start.command_line {
            Some(argv) => {
                let resolution = Resolution::InScope {
                    exe: identity.image_name.clone(),
                    // **親は番号で引く**（pid で引き直さない、決定65の追記(3)）。記録の根の親
                    // （harness 本体）は記録を始める前から居るので表に無く、`None`になる。
                    parent_exe: identity
                        .parent_seq
                        .and_then(|seq| instances.by_seq(seq))
                        .and_then(|parent| parent.image_name.clone()),
                };
                self.candidates.observe(
                    vec![ArgvEvent { pid, argv }],
                    move |_| resolution.clone(),
                    now_ms,
                )
            }
            None => Ok(()),
        }
    }

    /// 結び付けられなかった MOF の開始を、`fs-audit.jsonl`側の既存の数え方で1回だけ数える。
    fn count_unmatched(&mut self, start: &MofProcessStart) {
        if start.command_line.is_some() {
            self.candidates.count_unresolved();
        } else {
            self.candidates.count_missing_command_line();
        }
    }

    fn write_instance(
        &mut self,
        instances: &ProcessInstances,
        index: usize,
        argv: ArgvBinding,
        write_line: &dyn Fn(&str) -> bool,
    ) {
        let identity = instances.get(index);
        // 引数待ちへ入れるのは番号のあるものだけなので、ここで`None`は来ない。
        let Some(seq) = identity.seq else {
            return;
        };
        if identity.parent_seq_source == ParentSeqSource::Unresolved {
            self.stats.parent_unresolved += 1;
        }
        let record = ProcessAuditRecord::Instance(ProcessInstance {
            seq,
            parent_seq: identity.parent_seq,
            parent_seq_source: identity.parent_seq_source,
            pid: identity.pid,
            parent_pid: identity.parent_pid,
            image_path: identity.image_name.clone(),
            argv,
            is_scope_root: identity.is_scope_root,
            timestamp_unix_ms: identity.start_unix_ms,
        });
        if self.write(&record, write_line) {
            self.stats.written += 1;
        }
    }

    /// 歩留まりを制御レコードとして書く。**要約の1行は必ず書き、0件の項目は書かない**
    /// ——全部書くと、実際に落ちているものが並びに埋もれる（`record_argv_stats`と同じ作法）。
    /// 要約が在ることは「記録が最後まで畳まれた」ことの印にもなる。
    fn write_controls(&mut self, now_ms: u64, write_line: &dyn Fn(&str) -> bool) {
        let s = self.stats;
        let window = ARGV_WINDOW_MS;
        let mut reasons = vec![format!(
            "process_tree_summary: written={} argv_exact={}",
            s.written, s.exact
        )];
        let counted = [
            (s.no_argv_observed, format!(
                "argv_not_observed: {} in-scope process(es) got no command line from the MOF Process \
                 class after one carry-over (argv: missing, no_argv_observed)",
                s.no_argv_observed
            )),
            (s.ambiguous, format!(
                "argv_ambiguous_within_window: {} in-scope process(es) had two or more same-pid starts \
                 within +/-{window} ms, so no command line was bound (argv: missing, \
                 ambiguous_within_window)",
                s.ambiguous
            )),
            (s.no_command_line_field, format!(
                "argv_no_command_line_field: {} in-scope process(es) were matched to a MOF start that \
                 carried no command line (an older Process event version)",
                s.no_command_line_field
            )),
            (s.suspected_truncation, format!(
                "argv_truncation_suspected: {} command line(s) are exactly 1,024 UTF-16 units long and \
                 may have been cut",
                s.suspected_truncation
            )),
            (s.certain_truncation, format!(
                "argv_truncation_certain: {} command line(s) are 1,024 UTF-16 units long and end in an \
                 unpaired high surrogate, so they were cut",
                s.certain_truncation
            )),
            (s.parent_unresolved, format!(
                "parent_sequence_unresolved: {} instance(s) carried no ParentProcessSequenceNumber \
                 (missing or 0), so parent_seq is absent",
                s.parent_unresolved
            )),
            (s.without_sequence_number, format!(
                "without_sequence_number: {} in-scope process start(s) carried no ProcessSequenceNumber \
                 (ProcessStart v0-v2) and were not written",
                s.without_sequence_number
            )),
            (s.dcstart_excluded, format!(
                "dcstart_excluded: {} MOF rundown event(s) (DCStart: processes that already existed when \
                 the recording started) were not bound",
                s.dcstart_excluded
            )),
            (s.mof_without_instance, format!(
                "mof_start_without_instance: {} MOF process start(s) matched no Kernel-Process start \
                 within +/-{window} ms after one carry-over",
                s.mof_without_instance
            )),
            (s.bound_twice, format!(
                "argv_bound_twice: {} MOF process start(s) matched an instance that already had one; \
                 ignored",
                s.bound_twice
            )),
            (s.argv_after_settled, format!(
                "argv_after_settled: {} MOF process start(s) arrived after their instance had been \
                 written without a command line",
                s.argv_after_settled
            )),
            (s.overflowed, format!(
                "waiting_overflowed: {} entr(ies) were settled without waiting for their counterpart \
                 (more than {MAX_AWAITING} waiting)",
                s.overflowed
            )),
            (s.write_failed, format!(
                "write_failed: {} line(s) could not be written to this file",
                s.write_failed
            )),
        ];
        reasons.extend(counted.into_iter().filter(|(n, _)| *n > 0).map(|(_, text)| text));
        for reason in reasons {
            self.write(
                &ProcessAuditRecord::Control {
                    reason,
                    timestamp_unix_ms: now_ms,
                },
                write_line,
            );
        }
    }

    /// 1行書く。失敗は数える（`write_failed`）。
    fn write(&mut self, record: &ProcessAuditRecord, write_line: &dyn Fn(&str) -> bool) -> bool {
        let written = match record.to_jsonl_line() {
            Ok(line) => write_line(&line),
            Err(_) => false,
        };
        if !written {
            self.stats.write_failed += 1;
        }
        written
    }
}

fn missing(reason: ArgvMissingReason) -> ArgvBinding {
    ArgvBinding::Missing { reason }
}

/// 切り詰めを**生の UTF-16 単位で**判定する（`String`からは判定し直さない、`argv_truncation_from_utf16`）。
/// 単位数が無い（作り物の入力）ときだけ、文字列から数え直す。
fn truncation_of(start: &MofProcessStart, command_line: &str) -> ArgvTruncation {
    let len = start
        .command_line_utf16_len
        .unwrap_or_else(|| command_line.encode_utf16().count());
    let last = start
        .command_line_tail_units
        .as_ref()
        .and_then(|tail| tail.last().copied());
    argv_truncation_from_utf16(len, last)
}

#[cfg(test)]
#[path = "process_audit_tests.rs"]
mod process_audit_tests;
