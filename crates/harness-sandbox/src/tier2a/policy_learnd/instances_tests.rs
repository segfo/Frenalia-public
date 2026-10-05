//! [`super`]（インスタンスの表）の単体テスト。ETWも Win32 も使わない。

use super::*;

/// 試験用の`ProcessStart`。実行像は設定の綴りへ寄せられる形（`C:\…`）にしてある。
fn start(pid: u32, seq: Option<u64>, parent_seq: Option<u64>, at_ms: u64) -> ProcessStartInfo {
    ProcessStartInfo {
        pid,
        parent_pid: Some(1),
        image_name: Some(format!(r"C:\tools\p{pid}-{}.exe", seq.unwrap_or(0))),
        package_full_name: None,
        process_sequence_number: seq,
        parent_process_sequence_number: parent_seq,
        timestamp_unix_ms: at_ms,
    }
}

fn table(starts: &[ProcessStartInfo]) -> ProcessInstances {
    let mut instances = ProcessInstances::new();
    for s in starts {
        remember(&mut instances, s, &[], true, false);
    }
    instances
}

/// **同じ pid が使い回されても、アクセスの時刻で正しいインスタンスに付く。**
///
/// 旧表（pid → 素性の上書き）は、後の開始が届いた瞬間に前のプロセスのアクセスにも後の素性を
/// 付けた。ここでは「後の開始より前の時刻」が前のインスタンスに当たることを固定する。
#[test]
fn a_reused_pid_is_attributed_by_start_time() {
    let instances = table(&[start(100, Some(1), None, 10), start(100, Some(2), None, 50)]);

    assert_eq!(instances.at(100, 30).and_then(|i| i.seq), Some(1));
    assert_eq!(instances.at(100, 60).and_then(|i| i.seq), Some(2));
    // 開始の境界ちょうどはそのインスタンス（開始の時刻以前＝含む）。
    assert_eq!(instances.at(100, 50).and_then(|i| i.seq), Some(2));
    // どの開始よりも前のアクセスは、どのインスタンスにも付けない（推測で埋めない）。
    assert!(instances.at(100, 5).is_none());
    // 旧`ProcessTree::get`と同じ「その pid の最も新しい開始」。
    assert_eq!(instances.at(100, u64::MAX).and_then(|i| i.seq), Some(2));
    // 知らない pid は無い。
    assert!(instances.at(101, 60).is_none());
}

/// **届いた順が入れ替わっても、開始時刻で並ぶ**（2つのまとまりをまたいで後の開始が先に届いた場合）。
#[test]
fn starts_that_arrive_out_of_order_are_still_ordered_by_start_time() {
    let instances = table(&[start(100, Some(2), None, 50), start(100, Some(1), None, 10)]);

    assert_eq!(instances.at(100, 30).and_then(|i| i.seq), Some(1));
    assert_eq!(instances.at(100, 60).and_then(|i| i.seq), Some(2));
}

/// 同じ番号は1回しか入らない（同じインスタンスを2つの節点にしない）。
#[test]
fn the_same_sequence_number_is_inserted_once() {
    let mut instances = ProcessInstances::new();
    let first = ProcessIdentity {
        seq: Some(7),
        parent_seq: None,
        parent_seq_source: ParentSeqSource::Unresolved,
        pid: 100,
        parent_pid: None,
        image_name: None,
        start_unix_ms: 10,
        in_scope: true,
        is_scope_root: false,
    };

    assert_eq!(instances.insert(first.clone()), Some(0));
    assert_eq!(instances.insert(first.clone()), None, "同じ番号が2回入った");
    assert_eq!(instances.len(), 1);

    // 対の側（`B-35`）: 番号の無いもの（`ProcessStart` v0〜v2）は重ねて入る——
    // 同じものか区別する手段が無いので、片方を黙って捨てない。
    let unnumbered = ProcessIdentity { seq: None, ..first };
    assert_eq!(instances.insert(unnumbered.clone()), Some(1));
    assert_eq!(instances.insert(unnumbered), Some(2));
    assert_eq!(instances.len(), 3);
}

/// **親は番号で引く。pid で引き直さない**（決定65の追記(3)）。
///
/// 親の pid が使い回された後に pid で引くと、後から来た別のプロセスが親に見える。
#[test]
fn the_parent_is_looked_up_by_sequence_number_not_by_pid() {
    let instances = table(&[
        start(100, Some(1), None, 10),    // 親
        start(200, Some(2), Some(1), 20), // 子（親の番号 1）
        start(100, Some(3), None, 30),    // 親の pid 100 を使い回した別のプロセス
    ]);

    let child = instances.at(200, 40).expect("子が引ける");
    let parent = instances
        .by_seq(child.parent_seq.expect("親の番号がある"))
        .expect("親が引ける");
    assert_eq!(parent.seq, Some(1));
    assert_eq!(parent.image_name.as_deref(), Some("C:/tools/p100-1.exe"));

    // 対照: 同じ時点で pid から引くと、使い回した別のプロセスに当たる（これを使わない理由）。
    assert_eq!(instances.at(100, 40).and_then(|i| i.seq), Some(3));
    assert!(instances.by_seq(99).is_none());
}

/// 時刻の窓は**両端を含み、それより外は含まない**（決定65の追記(4)の 2ms）。
#[test]
fn near_includes_both_ends_of_the_window_and_nothing_beyond() {
    let instances = table(&[
        start(100, Some(1), None, 100),
        start(100, Some(2), None, 107),
        start(200, Some(3), None, 103),
    ]);
    let seqs = |found: Vec<usize>| -> Vec<Option<u64>> {
        found.into_iter().map(|i| instances.get(i).seq).collect()
    };

    // 差 2ms は入る（両側）。
    assert_eq!(seqs(instances.near(100, 102, 2)), vec![Some(1)]);
    assert_eq!(seqs(instances.near(100, 98, 2)), vec![Some(1)]);
    // 差 3ms は入らない（両側）。
    assert!(instances.near(100, 103, 2).is_empty());
    assert!(instances.near(100, 97, 2).is_empty());
    // 窓に2つ入れば2つとも返す（曖昧かどうかを決めるのは呼び出し側）。
    assert_eq!(seqs(instances.near(100, 104, 4)), vec![Some(1), Some(2)]);
    // pid が違うものは時刻が合っていても入らない。
    assert!(instances.near(300, 103, 2).is_empty());
    // 時刻 0 の近くで下へあふれない。
    assert!(instances.near(100, 0, 2).is_empty());
}

/// 親の欄が 0 のときは「無い」と同じに記録する（0 を番号として書くと、読む側が本物の親として引く）。
#[test]
fn a_zero_parent_field_is_recorded_as_unresolved() {
    let instances = table(&[
        start(100, Some(1), Some(0), 10),
        start(200, Some(2), None, 10),
        start(300, Some(3), Some(1), 10),
    ]);

    let zero = instances.at(100, 10).unwrap();
    assert_eq!((zero.parent_seq, zero.parent_seq_source), (None, ParentSeqSource::Unresolved));
    let missing = instances.at(200, 10).unwrap();
    assert_eq!(
        (missing.parent_seq, missing.parent_seq_source),
        (None, ParentSeqSource::Unresolved)
    );
    // 対の側: 欄があれば ETW の欄として持つ。
    let present = instances.at(300, 10).unwrap();
    assert_eq!(
        (present.parent_seq, present.parent_seq_source),
        (Some(1), ParentSeqSource::EtwField)
    );
}

/// 寄せられない実行像は載せず、**表へ入れたときだけ**真を返す（呼び出し側が数える）。
#[test]
fn an_unconvertible_image_is_reported_once_per_inserted_instance() {
    let mut instances = ProcessInstances::new();
    let mut raw = start(100, Some(1), None, 10);
    raw.image_name = Some(r"\Device\HarddiskVolume999\tool.exe".to_string());

    assert!(remember(&mut instances, &raw, &[], true, false));
    assert!(instances.at(100, 10).unwrap().image_name.is_none(), "生のNTパスを載せた");
    // 同じインスタンスがもう1回届いても、2回数えない。
    assert!(!remember(&mut instances, &raw, &[], true, false));
    // 対の側: 寄せられるものは偽で、設定の綴りで載る。
    assert!(!remember(&mut instances, &start(200, Some(2), None, 10), &[], true, false));
    assert_eq!(
        instances.at(200, 10).unwrap().image_name.as_deref(),
        Some("C:/tools/p200-2.exe")
    );
}
