//! [`super`]（`process-audit.jsonl`の書き手）の単体テスト。
//!
//! **ETWもファイルの書込先も使わない**——`write_line`には行を`RefCell<Vec<String>>`へ積む閉包を渡し、
//! 積んだ行は読む側の本物の関数（`harness_policy::process_event::parse_process_audit`）で読み戻す
//! （書いた形を読む側が読めることまで一緒に測る）。`observed.jsonl`だけは一時ディレクトリへ書く。

use std::cell::RefCell;
use std::path::Path;

use harness_policy::process_event::{
    parse_process_audit, ArgvBinding, ArgvMissingReason, ArgvTruncation, ParentSeqSource,
    ProcessAuditLog, ProcessInstance,
};

use super::super::etw::mof::{MofProcessStart, EVENT_TYPE_PROCESS_DC_START, EVENT_TYPE_PROCESS_START};
use super::super::etw::session::ProcessStartInfo;
use super::super::instances::{remember, ProcessInstances};
use super::super::observed::{ObservedRecord, Spawn};
use super::*;

/// 記録の根の親（harness 本体）の pid。
const HOST: u32 = 10;

/// マニフェスト側の`ProcessStart`1件。実行像は`C:\tools\<name>.exe`。
fn manifest(pid: u32, seq: u64, parent_seq: Option<u64>, name: &str, at_ms: u64) -> ProcessStartInfo {
    ProcessStartInfo {
        pid,
        parent_pid: Some(HOST),
        image_name: Some(format!(r"C:\tools\{name}.exe")),
        package_full_name: None,
        process_sequence_number: Some(seq),
        parent_process_sequence_number: parent_seq,
        timestamp_unix_ms: at_ms,
    }
}

/// 表へ入れる。`in_scope`・`is_scope_root`は収集器が`ScopeTracker`に聞いた答えの代わり。
fn add(instances: &mut ProcessInstances, start: &ProcessStartInfo, in_scope: bool, is_root: bool) {
    remember(instances, start, &[], in_scope, is_root);
}

/// MOF側の開始1件を、**生の UTF-16 単位から**`etw/mof.rs`と同じ形で組む（文字列・単位数・末尾8単位）。
fn mof_units(pid: u32, units: &[u16], at_ms: u64) -> MofProcessStart {
    MofProcessStart {
        event_type: EVENT_TYPE_PROCESS_START,
        version: 4,
        pid: Some(pid),
        parent_pid: Some(HOST),
        session_id: Some(1),
        flags: None,
        image_file_name: None,
        command_line: Some(String::from_utf16_lossy(units)),
        package_full_name: None,
        unique_process_key: None,
        timestamp_unix_ms: at_ms,
        command_line_utf16_len: Some(units.len()),
        command_line_tail_units: Some(units[units.len().saturating_sub(8)..].to_vec()),
        application_id_utf16: None,
        application_id_ansi: None,
    }
}

fn mof(pid: u32, command_line: &str, at_ms: u64) -> MofProcessStart {
    let units: Vec<u16> = command_line.encode_utf16().collect();
    mof_units(pid, &units, at_ms)
}

fn dcstart(pid: u32, command_line: &str, at_ms: u64) -> MofProcessStart {
    MofProcessStart {
        event_type: EVENT_TYPE_PROCESS_DC_START,
        ..mof(pid, command_line, at_ms)
    }
}

/// 書いた行を積む先と、その閉包。
struct Sink {
    lines: RefCell<Vec<String>>,
}

impl Sink {
    fn new() -> Self {
        Self {
            lines: RefCell::new(Vec::new()),
        }
    }

    fn write(&self) -> impl Fn(&str) -> bool + '_ {
        |line: &str| {
            self.lines.borrow_mut().push(line.to_string());
            true
        }
    }

    /// 読む側の本物の関数で読み戻す。
    fn parsed(&self) -> ProcessAuditLog {
        let mut text = self.lines.borrow().join("\n");
        text.push('\n');
        parse_process_audit(&text).expect("書いた process-audit.jsonl を読む側が読めない")
    }

    fn instances(&self) -> Vec<ProcessInstance> {
        self.parsed().instances
    }
}

fn audit(workspace: &Path, sink: &Sink) -> ProcessAudit {
    ProcessAudit::start(
        workspace.join("process-audit.jsonl"),
        ObservedCandidates::new(workspace),
        &sink.write(),
    )
}

fn observed_spawns(workspace: &Path) -> Vec<Spawn> {
    let path = super::super::observed::observed_path(workspace);
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| match serde_json::from_str(line).expect("観測の行が読めない") {
            ObservedRecord::ObservedSpawn(spawn) => Some(spawn),
            ObservedRecord::Overflowed { .. } => None,
        })
        .collect()
}

fn argv_of(instance: &ProcessInstance) -> &ArgvBinding {
    &instance.argv
}

fn exact(command_line: &str, truncation: ArgvTruncation) -> ArgvBinding {
    ArgvBinding::Exact {
        command_line: command_line.to_string(),
        truncation,
    }
}

fn missing(reason: ArgvMissingReason) -> ArgvBinding {
    ArgvBinding::Missing { reason }
}

/// **1行目は版の行**で、読む側（`parse_process_audit`）はそれが無いファイルを読まない。
#[test]
fn the_header_is_the_first_line() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "cmd", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    assert_eq!(
        sink.lines.borrow().as_slice(),
        [r#"{"kind":"header","schema_version":1}"#],
        "始めた時点で書くのは版の行だけ"
    );
    audit
        .drain(&instances, vec![mof(100, "cmd /c x", 10)], 20, &sink.write())
        .unwrap();

    let lines = sink.lines.borrow().clone();
    assert_eq!(lines[0], r#"{"kind":"header","schema_version":1}"#);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(sink.instances().len(), 1);
}

/// **差 2ms は結び付く**（窓の端を含む）。`observed.jsonl`にも同じ結び付けの結果が1種類入る。
#[test]
fn a_start_within_the_window_binds_the_command_line() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "cmd", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![mof(100, "cmd /c build", 12)], 20, &sink.write())
        .unwrap();

    let written = sink.instances();
    assert_eq!(written.len(), 1);
    assert_eq!(argv_of(&written[0]), &exact("cmd /c build", ArgvTruncation::None));
    let spawns = observed_spawns(tmp.path());
    assert_eq!(spawns.len(), 1, "{spawns:?}");
    assert_eq!(spawns[0].exe, "C:/tools/cmd.exe");
    assert_eq!(spawns[0].argv, "cmd /c build");
}

/// **差 3ms は結び付かない**——インスタンスは持ち越しの後に「観測されなかった」で書かれ、
/// MOF の開始は相手の無いものとして数える（`observed.jsonl`にも入らない）。
#[test]
fn a_start_outside_the_window_is_not_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "cmd", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![mof(100, "cmd /c build", 13)], 20, &sink.write())
        .unwrap();
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    let written = sink.instances();
    assert_eq!(written.len(), 1);
    assert_eq!(argv_of(&written[0]), &missing(ArgvMissingReason::NoArgvObserved));
    assert_eq!(stats.mof_without_instance, 1);
    assert_eq!(argv_stats.unresolved, 1);
    assert!(observed_spawns(tmp.path()).is_empty());
}

/// **窓の中に同じ pid の候補が2つあれば結び付けない**（どれの引数か決めない、§19.3.11）。
#[test]
fn two_instances_within_the_window_are_ambiguous() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, true);
    add(&mut instances, &manifest(100, 2, None, "b", 11), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![mof(100, "a --x", 10)], 20, &sink.write())
        .unwrap();
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    let written = sink.instances();
    assert_eq!(written.len(), 2);
    for instance in &written {
        assert_eq!(
            argv_of(instance),
            &missing(ArgvMissingReason::AmbiguousWithinWindow),
            "{instance:?}"
        );
    }
    assert_eq!(stats.ambiguous, 2);
    assert_eq!(stats.exact, 0);
    assert_eq!(argv_stats.unresolved, 1, "結び付かなかったコマンドラインとして1回数える");
    assert!(observed_spawns(tmp.path()).is_empty(), "どちらの辺としても書かない");
}

/// **引数の来ないインスタンスは1回だけ持ち越し、次のドレインで「観測されなかった」で書く。**
/// `finish`は持ち越さずに書き切る。
#[test]
fn an_instance_without_argv_is_written_after_one_carry_over() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit.drain(&instances, Vec::new(), 20, &sink.write()).unwrap();
    assert!(sink.instances().is_empty(), "1回目のドレインでは待つ");

    audit.drain(&instances, Vec::new(), 22, &sink.write()).unwrap();
    let written = sink.instances();
    assert_eq!(written.len(), 1, "2回目のドレインで書く");
    assert_eq!(argv_of(&written[0]), &missing(ArgvMissingReason::NoArgvObserved));

    // `finish`: 新しく来たインスタンスを、持ち越さずにその場で書き切る。
    add(&mut instances, &manifest(200, 2, None, "b", 30), true, false);
    let (_, stats, _) = audit.finish(&instances, Vec::new(), 40, &sink.write());
    let written = sink.instances();
    assert_eq!(written.len(), 2);
    assert_eq!(written[1].seq, 2);
    assert_eq!(argv_of(&written[1]), &missing(ArgvMissingReason::NoArgvObserved));
    assert_eq!(stats.no_argv_observed, 2);
}

/// **MOF側が先に届いたら1回だけ持ち越し、次のドレインで届いたインスタンスと結び付ける。**
#[test]
fn a_mof_start_that_arrives_before_its_instance_is_retried_once() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![mof(100, "git status", 10)], 20, &sink.write())
        .unwrap();
    assert!(sink.instances().is_empty());

    // 次のドレインでマニフェスト側が届いた。
    add(&mut instances, &manifest(100, 1, None, "git", 10), true, true);
    audit.drain(&instances, Vec::new(), 22, &sink.write()).unwrap();
    let written = sink.instances();
    assert_eq!(written.len(), 1);
    assert_eq!(argv_of(&written[0]), &exact("git status", ArgvTruncation::None));
    assert_eq!(observed_spawns(tmp.path()).len(), 1);

    // 対の側: 持ち越しは1回だけ——2回のドレインを待っても相手が来なければ数える。
    audit
        .drain(&instances, vec![mof(300, "late", 50)], 60, &sink.write())
        .unwrap();
    audit.drain(&instances, Vec::new(), 62, &sink.write()).unwrap();
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 70, &sink.write());
    assert_eq!(stats.mof_without_instance, 1);
    assert_eq!(argv_stats.unresolved, 1);
}

/// **切り詰めは UTF-16 の単位で判定する**（`plans/etw-spike/RESULTS.md` §23.3）。
///
/// 末尾の対にならない高位サロゲートは、`String`へ落とすと置換文字に潰れて見えなくなる。
/// MOF側の生の単位（`command_line_tail_units`）で判定していることを、確定・疑い・なしの3つと、
/// 「末尾が対になっていれば確定ではない」で固定する。
#[test]
fn truncation_is_judged_on_utf16_units() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    let ascii = |n: usize| vec![u16::from(b'a'); n];
    let mut cut_mid_pair = ascii(1_023);
    cut_mid_pair.push(0xD842); // 𠮷 の高位だけが残った
    let mut whole_pair = ascii(1_022);
    whole_pair.extend([0xD842, 0xDFB7]); // 𠮷 が対のまま収まった
    let cases: [(u32, Vec<u16>, ArgvTruncation); 4] = [
        (100, ascii(1_023), ArgvTruncation::None),
        (200, ascii(1_024), ArgvTruncation::Suspected),
        (300, cut_mid_pair, ArgvTruncation::Certain),
        (400, whole_pair, ArgvTruncation::Suspected),
    ];
    for (i, (pid, _, _)) in cases.iter().enumerate() {
        add(&mut instances, &manifest(*pid, i as u64 + 1, None, "x", 10), true, false);
    }

    let mut audit = audit(tmp.path(), &sink);
    let starts = cases.iter().map(|(pid, units, _)| mof_units(*pid, units, 10)).collect();
    audit.drain(&instances, starts, 20, &sink.write()).unwrap();
    let (_, stats, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    let written = sink.instances();
    for (pid, _, expected) in &cases {
        let instance = written.iter().find(|i| i.pid == *pid).expect("書かれている");
        match argv_of(instance) {
            ArgvBinding::Exact { truncation, .. } => {
                assert_eq!(truncation, expected, "pid {pid}")
            }
            other => panic!("pid {pid}: {other:?}"),
        }
    }
    assert_eq!((stats.suspected_truncation, stats.certain_truncation), (2, 1));
    // 判定の関数そのもの（`String`を経由しない入口）。
    assert_eq!(argv_truncation_from_utf16(1_024, Some(0xDBFF)), ArgvTruncation::Certain);
    assert_eq!(argv_truncation_from_utf16(1_024, Some(0xDC00)), ArgvTruncation::Suspected);
    assert_eq!(argv_truncation_from_utf16(1_025, Some(0xD842)), ArgvTruncation::None);
}

/// **記録の対象外のインスタンスは書かない**——`process-audit.jsonl`は記録した木だけを持つ。
/// 対の側（`B-35`）: 対象のインスタンスは書かれる（「何も書かない」実装でも上が緑にならないように）。
#[test]
fn out_of_scope_instances_are_not_written() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "inside", 10), true, true);
    add(&mut instances, &manifest(200, 2, None, "outside", 10), false, false);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(
            &instances,
            vec![mof(100, "inside -x", 10), mof(200, "outside -y", 10)],
            20,
            &sink.write(),
        )
        .unwrap();
    let (argv_stats, _, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    let written = sink.instances();
    assert_eq!(written.len(), 1, "{written:?}");
    assert_eq!(written[0].seq, 1);
    assert_eq!(argv_stats.out_of_scope, 1, "対象外も`observed`側の数え方では数える");
    let spawns = observed_spawns(tmp.path());
    assert_eq!(spawns.len(), 1);
    assert_eq!(spawns[0].argv, "inside -x");
}

/// **根の印と、親の番号の出どころをそのまま運ぶ**（決定23(2)・決定65の追記(2)）。
///
/// 親の欄が無い・0 の子は`parent_seq`を書かず`unresolved`、欄があれば`etw-field`で番号を書く。
/// `observed.jsonl`の親の実行ファイルは**番号で**引く（pid で引き直さない）。
#[test]
fn the_scope_root_and_the_parent_source_are_carried() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, Some(0), "root", 10), true, true);
    add(&mut instances, &manifest(200, 2, Some(1), "child", 20), true, false);
    // 根の pid 100 を使い回した別のプロセス（記録の対象外）。pid で親を引くとこちらに当たる。
    add(&mut instances, &manifest(100, 3, None, "impostor", 25), false, false);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(
            &instances,
            vec![mof(100, "root", 10), mof(200, "child --go", 20)],
            40,
            &sink.write(),
        )
        .unwrap();
    let (_, stats, _) = audit.finish(&instances, Vec::new(), 50, &sink.write());

    let written = sink.instances();
    let root = written.iter().find(|i| i.seq == 1).unwrap();
    let child = written.iter().find(|i| i.seq == 2).unwrap();
    assert!(root.is_scope_root);
    assert_eq!((root.parent_seq, root.parent_seq_source), (None, ParentSeqSource::Unresolved));
    assert!(!child.is_scope_root);
    assert_eq!((child.parent_seq, child.parent_seq_source), (Some(1), ParentSeqSource::EtwField));
    assert_eq!(child.image_path.as_deref(), Some("C:/tools/child.exe"));
    assert_eq!(child.parent_pid, Some(HOST));
    assert_eq!(stats.parent_unresolved, 1);

    let spawns = observed_spawns(tmp.path());
    let child_spawn = spawns.iter().find(|s| s.argv == "child --go").unwrap();
    assert_eq!(child_spawn.parent_exe.as_deref(), Some("C:/tools/root.exe"));
}

/// **歩留まりは制御レコードで書き、0件の項目は書かない**（決定23(4)）。要約の1行は必ず書く。
#[test]
fn counts_are_written_as_control_records_and_zero_counts_are_not() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, true);
    add(&mut instances, &manifest(200, 2, Some(1), "b", 10), true, false);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(
            &instances,
            vec![mof(100, "a", 10), dcstart(999, "svchost -k x", 1)],
            20,
            &sink.write(),
        )
        .unwrap();
    let (_, _, result) = audit.finish(&instances, Vec::new(), 30, &sink.write());
    result.expect("observed.jsonl を畳めた");

    let controls = sink.parsed().controls;
    assert_eq!(
        controls[0], "process_tree_summary: written=2 argv_exact=1",
        "{controls:?}"
    );
    let has = |key: &str| controls.iter().any(|c| c.starts_with(key));
    assert!(has("argv_not_observed: 1 "), "{controls:?}");
    assert!(has("parent_sequence_unresolved: 1 "), "{controls:?}");
    assert!(has("dcstart_excluded: 1 "), "{controls:?}");
    // 0件の項目は書かない。
    for zero in [
        "argv_ambiguous_within_window",
        "argv_no_command_line_field",
        "argv_truncation_suspected",
        "argv_truncation_certain",
        "without_sequence_number",
        "mof_start_without_instance",
        "argv_bound_twice",
        "argv_after_settled",
        "waiting_overflowed",
        "write_failed",
    ] {
        assert!(!has(zero), "0件の {zero} が書かれた: {controls:?}");
    }
}

/// **DCStart は結び付けずに数える**——同じ pid・同じ時刻のインスタンスが居ても、それは記録中に
/// 起きた開始ではない。インスタンスは持ち越しの後に「観測されなかった」で書かれる。
#[test]
fn dcstart_is_excluded_and_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![dcstart(100, "a --old", 10)], 20, &sink.write())
        .unwrap();
    audit.drain(&instances, Vec::new(), 22, &sink.write()).unwrap();
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    let written = sink.instances();
    assert_eq!(written.len(), 1);
    assert_eq!(argv_of(&written[0]), &missing(ArgvMissingReason::NoArgvObserved));
    assert_eq!(stats.dcstart_excluded, 1);
    assert_eq!(stats.exact, 0);
    assert_eq!(argv_stats.without_command_line, 0, "DCStart はどの数にも入れない");
    assert_eq!(argv_stats.unresolved, 0);
    assert!(observed_spawns(tmp.path()).is_empty());
}

/// **[BUG-228] 相手の無い MOF の開始は1回だけ数え、DCStart は「結び付かなかった」に数えない。**
///
/// 旧実装（`server.rs`の`resolve_for_candidate`）は、表に無い pid のたびにスコープ判定へ問い合わせ、
/// 「判定できなかった」の数（`fs-audit.jsonl`の`unresolved_process_scope`）を**ドレインのたびに**
/// 増やしていた（持ち越しが上限まで繰り返されるため、記録が長いほど増える）。いまの書き手は
/// スコープ判定を受け取らないので、その数へ触れる道そのものが無い（構造で塞いだ）。ここで固定するのは
/// こちら側の数——ドレインを重ねても増えないこと、DCStart が混ざらないこと。
#[test]
fn an_unmatched_mof_start_is_counted_once_and_dcstart_is_not_counted_as_unresolved() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let instances = ProcessInstances::new();

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(
            &instances,
            vec![dcstart(4242, "svchost -k netsvcs", 1), mof(5000, "orphan --x", 5)],
            10,
            &sink.write(),
        )
        .unwrap();
    for now in [12, 14, 16] {
        audit.drain(&instances, Vec::new(), now, &sink.write()).unwrap();
    }
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 20, &sink.write());

    assert_eq!(argv_stats.unresolved, 1, "相手の無い開始は1件として1回だけ数える");
    assert_eq!(stats.mof_without_instance, 1);
    assert_eq!(stats.dcstart_excluded, 1);
    assert_eq!(argv_stats.without_command_line, 0);
}

/// 同じインスタンスへ2件目の MOF の開始が結び付いても、`observed.jsonl`へ二重に入れない。
#[test]
fn a_second_mof_start_for_the_same_instance_is_counted_not_recorded_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let sink = Sink::new();
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, true);

    let mut audit = audit(tmp.path(), &sink);
    audit
        .drain(&instances, vec![mof(100, "a 1", 10), mof(100, "a 1", 11)], 20, &sink.write())
        .unwrap();
    let (argv_stats, stats, _) = audit.finish(&instances, Vec::new(), 30, &sink.write());

    assert_eq!(sink.instances().len(), 1);
    assert_eq!(stats.bound_twice, 1);
    assert_eq!(argv_stats.recorded, 1, "1つのインスタンスの観測は1件");
}

/// `pair`は窓に入る数で3つに分かれる（純粋関数）。
#[test]
fn pair_splits_by_the_number_of_instances_in_the_window() {
    let mut instances = ProcessInstances::new();
    add(&mut instances, &manifest(100, 1, None, "a", 10), true, false);
    add(&mut instances, &manifest(100, 2, None, "b", 13), true, false);

    assert_eq!(pair(&instances, 100, 10), Pairing::Exact(0));
    assert_eq!(pair(&instances, 100, 15), Pairing::Exact(1));
    assert_eq!(pair(&instances, 100, 12), Pairing::Ambiguous(vec![0, 1]));
    assert_eq!(pair(&instances, 100, 20), Pairing::NoInstance);
    assert_eq!(pair(&instances, 101, 10), Pairing::NoInstance);
}
