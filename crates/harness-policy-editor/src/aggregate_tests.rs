//! [`crate::aggregate`]の単体テスト。record-all特有の性質——**許可も候補になる**・
//! `.harness`は候補にしない・取りこぼしを隠さない——を固定する。

use super::*;
use harness_config::FsAccess;

fn observed(path: &str, access: FsAccess, allowed: bool, ts: u64) -> FsAuditEvent {
    FsAuditEvent::observed(
        FsAuditKind::Etw,
        path,
        access,
        allowed,
        if allowed { "observed" } else { "denied" },
        ts,
    )
}

/// **record-allの核心**: 成功したアクセスも候補になる。deny-onlyの
/// `normalize_fs_audit`はこれを捨てるため、記録モードは自前で畳み込む必要がある。
#[test]
fn allowed_accesses_become_candidates_not_just_denials() {
    let mut agg = Aggregate::new();
    agg.add_event(&observed("C:/work/Cargo.toml", FsAccess::Read, true, 1));
    agg.add_event(&observed("C:/work/src/lib.rs", FsAccess::Read, true, 2));

    assert_eq!(agg.allowed, 2);
    assert_eq!(agg.denied, 0);
    assert_eq!(agg.candidates().len(), 2);
    assert!(!agg.proposals(Generalization::None).is_empty());
}

/// 同じ`(パス, access)`は畳まれ、件数が積み上がる。
#[test]
fn repeated_accesses_to_the_same_path_are_folded_with_a_count() {
    let mut agg = Aggregate::new();
    for ts in 1..=5 {
        agg.add_event(&observed("C:/work/Cargo.toml", FsAccess::Read, true, ts));
    }

    assert_eq!(agg.events_seen, 5);
    assert_eq!(agg.candidates().len(), 1);
    assert_eq!(agg.candidates()[0].count, 5);
}

/// access種別が違えば別候補（P-03: 要求された権限を超えて与えない）。
#[test]
fn different_access_kinds_stay_separate_candidates() {
    let mut agg = Aggregate::new();
    agg.add_event(&observed("C:/work/a.txt", FsAccess::Read, true, 1));
    agg.add_event(&observed("C:/work/a.txt", FsAccess::ReadWrite, true, 2));

    assert_eq!(agg.candidates().len(), 2);
}

/// **`.harness`配下は候補にせず、件数を出す。** 提案してはいけない対象（P-08）であり、
/// かつ記録の産物自身がそこにあるため自己参照ループの原因になる。
#[test]
fn harness_control_directory_paths_are_excluded_and_counted() {
    let mut agg = Aggregate::new();
    agg.add_event(&observed("C:/work/src/lib.rs", FsAccess::Read, true, 1));
    agg.add_event(&observed(
        "C:/work/.harness/sandbox/policy-editor-x/fs-audit.jsonl",
        FsAccess::Read,
        true,
        2,
    ));
    agg.add_event(&observed("C:/work/.harness/settings.json", FsAccess::Read, true, 3));

    assert_eq!(agg.candidates().len(), 1, "残るのは.harness外の1件だけ");
    assert_eq!(agg.excluded_control_dir, 2);
    // 除外しても「観測した」事実は消さない。
    assert_eq!(agg.events_seen, 3);
    assert_eq!(agg.allowed, 3);

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("除外"), "{text}");
    assert!(text.contains("2件"), "{text}");
}

/// `.harness`の判定はパス要素単位で、区切り文字と大小に依存しない。
/// `.harnessrc`のような別名を巻き込まないことも同時に固定する（過剰一致の防止）。
#[test]
fn the_control_directory_predicate_matches_a_path_component_only() {
    assert!(is_harness_control_path("C:/work/.harness/settings.json"));
    assert!(is_harness_control_path(r"C:\work\.HARNESS\settings.json"));
    assert!(is_harness_control_path("C:/other-repo/.harness/x"));
    assert!(!is_harness_control_path("C:/work/.harnessrc"));
    assert!(!is_harness_control_path("C:/work/harness/settings.json"));
    assert!(!is_harness_control_path("C:/work/src/lib.rs"));
}

/// 収集器の制御レコードは候補にせず、**必ず見せる**（「収集できていない」と
/// 「拒否が0件だった」を区別できないと、fail-openは隠蔽になる、D-43）。
#[test]
fn collector_control_records_are_surfaced_not_turned_into_candidates() {
    let mut agg = Aggregate::new();
    agg.add_event(&FsAuditEvent::control(
        "etw_session_start_failed: access denied",
        1,
    ));

    assert!(agg.candidates().is_empty());
    assert_eq!(agg.collector_notes.len(), 1);
    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("収集器からの報告"), "{text}");
    assert!(text.contains("etw_session_start_failed"), "{text}");
}

/// 解釈できなかった行は数えて表示する（黙って捨てない、B-09）。
#[test]
fn unparsable_lines_are_counted_and_shown() {
    let mut agg = Aggregate::new();
    agg.add_unparsable(3);

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("解釈できなかった行 3件"), "{text}");
}

/// 1件も観測できなかったことは、「候補なし」ではなく**異常の可能性**として伝える。
#[test]
fn an_empty_recording_says_so_instead_of_looking_like_a_clean_run() {
    let agg = Aggregate::new();
    let text = render(&agg, Generalization::None, 10);

    assert!(text.contains("1件も観測できませんでした"), "{text}");
}

/// 拒否があったときは、Tier1固有の拒否とTier2aで要る許可の違いを注記する
/// （BUG-087の設計メモ: 低ILラベルは継承しないのでサブディレクトリ内は書けない）。
#[test]
fn denials_carry_a_note_that_tier1_denials_differ_from_tier2a_needs() {
    let mut agg = Aggregate::new();
    agg.add_event(&observed("C:/work/sub/out.txt", FsAccess::ReadWrite, false, 1));

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("Tier1での拒否"), "{text}");
}

/// **打ち切るなら残件数を必ず出す。** 黙って切ると、見えている分が全部だと誤解される。
#[test]
fn a_truncated_proposal_list_reports_how_many_were_hidden() {
    let mut agg = Aggregate::new();
    for i in 0..10 {
        agg.add_event(&observed(
            &format!("C:/work/dir{i}/file.txt"),
            FsAccess::Read,
            true,
            i as u64,
        ));
    }

    let text = render(&agg, Generalization::None, 3);
    assert!(text.contains("他 7件"), "{text}");
}

/// プロセスツリーは親子関係で入れ子になり、親が観測範囲外のものは根になる。
#[test]
fn the_process_tree_nests_children_under_observed_parents() {
    let mut agg = Aggregate::new();
    let parent = observed("C:/work/a.txt", FsAccess::Read, true, 1)
        .with_process(200, Some("pwsh.exe".to_string()))
        .with_parent_process(100); // 100は観測範囲外＝200が根になる
    let child = observed("C:/work/b.txt", FsAccess::Read, true, 2)
        .with_process(300, Some("cmd.exe".to_string()))
        .with_parent_process(200);
    agg.add_event(&parent);
    agg.add_event(&child);

    let tree = agg.process_tree();
    assert_eq!(tree.len(), 2);
    assert_eq!((tree[0].0, tree[0].1), (0, 200));
    assert_eq!((tree[1].0, tree[1].1), (1, 300));

    let text = render_process_tree(&agg);
    assert!(text.contains("pwsh.exe"), "{text}");
    assert!(text.contains("cmd.exe"), "{text}");
}

/// PID再利用で親子が閉路になっても、ツリー構築は止まらず**1件も落とさない**。
/// 根が1つも無いので素朴な走査では全件が消えるが、それは黙った取りこぼしになる（B-09）。
#[test]
fn a_cycle_in_the_parentage_does_not_hang_or_drop_processes() {
    let mut agg = Aggregate::new();
    agg.add_event(
        &observed("C:/a", FsAccess::Read, true, 1)
            .with_process(1, None)
            .with_parent_process(2),
    );
    agg.add_event(
        &observed("C:/b", FsAccess::Read, true, 2)
            .with_process(2, None)
            .with_parent_process(1),
    );

    let tree = agg.process_tree();
    let pids: Vec<u32> = tree.iter().map(|(_, pid, _)| *pid).collect();
    assert_eq!(pids.len(), 2, "閉路の中のプロセスも表示から消さない: {pids:?}");
    assert!(pids.contains(&1) && pids.contains(&2));
}
