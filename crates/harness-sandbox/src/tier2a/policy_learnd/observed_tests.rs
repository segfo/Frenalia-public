//! [段階6d] 観測した候補（`observed.jsonl`）の単体テスト。
//!
//! **Win32を呼ばないので昇格は要らない**（`cargo test -p harness-sandbox --lib`に入る）。
//! 実機でしか測れないもの——「実際にコマンドを走らせるとargvが行になる」「枠が無いと
//! 記録が始まらない」——は`win_appcontainer::policy_learn_argv_e2e_tests`が持つ。

use std::collections::HashMap;
use std::path::Path;

use super::*;

fn read_records(path: &Path) -> Vec<ObservedRecord> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("観測の行が読めない"))
        .collect()
}

fn spawns(path: &Path) -> Vec<Spawn> {
    read_records(path)
        .into_iter()
        .filter_map(|record| match record {
            ObservedRecord::ObservedSpawn(spawn) => Some(spawn),
            ObservedRecord::Overflowed { .. } => None,
        })
        .collect()
}

fn in_scope(exe: &str, parent_exe: Option<&str>) -> Resolution {
    Resolution::InScope {
        exe: Some(exe.to_string()),
        parent_exe: parent_exe.map(str::to_string),
    }
}

fn event(pid: u32, argv: &str) -> ArgvEvent {
    ArgvEvent {
        pid,
        argv: argv.to_string(),
    }
}

/// 候補の行は`.harness/transitions/`に積まれる。
///
/// **`.harness`配下であることが自己参照ループを断つ**——`is_harness_control_path`が
/// 候補から外すのは**パス要素`.harness`だけ**を見ているので、ここを動かした瞬間に
/// 観測の産物が次の記録の候補として提案され始める（`B-28`）。
#[test]
fn candidates_live_next_to_the_denial_queue_under_the_harness_control_directory() {
    let workspace = Path::new("C:/work");
    let path = observed_path(workspace);

    assert!(
        path.components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new(".harness")),
        "{}",
        path.display()
    );
    assert_eq!(
        path,
        crate::tier2a::spawnd::transitions::pending_path(workspace)
            .parent()
            .unwrap()
            .join("observed.jsonl"),
        "拒否の待ち行列と同じディレクトリに並べる（§10.3）"
    );
}

/// 1件目は即時に1行になり、`exe`と`argv`は別々の出どころのまま載る。
#[test]
fn the_first_spawn_of_a_kind_is_written_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(
            vec![event(100, r#""cmd.exe" /c build"#)],
            |_| in_scope("C:/Windows/System32/cmd.exe", Some("C:/tools/make.exe")),
            7,
        )
        .expect("write");

    let written = spawns(candidates.path());
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].exe, "C:/Windows/System32/cmd.exe");
    assert_eq!(written[0].parent_exe.as_deref(), Some("C:/tools/make.exe"));
    assert_eq!(written[0].argv, r#""cmd.exe" /c build"#);
    assert_eq!(written[0].count, 1);
    assert_eq!(written[0].first_ts, 7);
    assert_eq!(candidates.stats().recorded, 1);
}

/// **同じコマンドでも親が違えば別の辺である。**
///
/// 遷移の宣言は`(遷移元, exe, argv)`の3つ組なので、親を鍵から外すと**別々の辺が1行へ
/// 混ざり**、承認したつもりのない辺まで一緒に通ることになる。
#[test]
fn the_same_command_from_a_different_parent_is_a_different_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(
            vec![event(100, "git status")],
            |_| in_scope("C:/git.exe", Some("C:/a.exe")),
            1,
        )
        .expect("write");
    candidates
        .observe(
            vec![event(101, "git status")],
            |_| in_scope("C:/git.exe", Some("C:/b.exe")),
            2,
        )
        .expect("write");

    let written = spawns(candidates.path());
    assert_eq!(written.len(), 2, "親が違うのに1行へ畳まれている");
    assert_eq!(written[0].count, 1);
    assert_eq!(written[1].count, 1);
}

/// 繰り返しは畳まれ、**前回書いた数の2倍**でだけ更新行が出る（拒否の待ち行列と同じ規則）。
#[test]
fn repeats_are_folded_and_written_when_the_count_doubles() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());
    let resolve = |_: u32| in_scope("C:/git.exe", None);

    for tick in 0..4u64 {
        candidates
            .observe(vec![event(100, "git status")], resolve, tick)
            .expect("write");
    }

    let written = spawns(candidates.path());
    // 1件目(即時) → 2件目(1*2) → 4件目(2*2)。3件目では書かない。
    assert_eq!(
        written.iter().map(|s| s.count).collect::<Vec<_>>(),
        vec![1, 2, 4]
    );
    // 読む側は同じ鍵の最後の行を採る。
    assert_eq!(written.last().unwrap().count, 4);
}

/// 記録の対象外（この記録が起こしたプロセスの子孫でないもの）は行にならない。
///
/// **対の側**（`B-35`）: これが無いと「全部書く」実装でも上のテストは緑になり、
/// マシン全体のプロセスが候補として提案される。
#[test]
fn processes_outside_the_recording_are_not_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(
            vec![event(999, "notepad.exe")],
            |_| Resolution::OutOfScope,
            1,
        )
        .expect("write");

    assert!(spawns(candidates.path()).is_empty());
    assert_eq!(candidates.stats().out_of_scope, 1);
    assert_eq!(candidates.stats().recorded, 0);
}

/// **突き合わせに間に合わなかったものは、次のドレインでやり直される。**
///
/// 2つのETWセッションは別々に配送されるので、MOF側が先に届くことがある。
/// 即座に捨てると「観測されなかった辺」と「間に合わなかった辺」が区別できなくなる。
#[test]
fn an_event_that_arrives_before_its_process_start_is_retried_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());
    // マニフェスト側の台帳に見立てる（届いたpidだけが引ける）。
    let mut known: HashMap<u32, &str> = HashMap::new();

    // 1回目: まだマニフェスト側が届いていない。
    candidates
        .observe(vec![event(100, "git status")], |_| Resolution::Unknown, 1)
        .expect("write");
    assert!(spawns(candidates.path()).is_empty());
    assert_eq!(candidates.stats().unresolved, 0, "まだ諦めていない");

    // 2回目: 届いたので解ける。
    known.insert(100, "C:/git.exe");
    known.insert(101, "C:/git.exe");
    candidates
        .observe(
            vec![event(101, "git log")],
            |pid| match known.get(&pid) {
                Some(exe) => in_scope(exe, None),
                None => Resolution::Unknown,
            },
            2,
        )
        .expect("write");

    let written = spawns(candidates.path());
    assert_eq!(written.len(), 2, "持ち越した観測が書かれていない");
    assert!(written.iter().any(|s| s.argv == "git status"));
}

/// 持ち越したまま記録が終わったものは、**数え切ってから畳む**。
///
/// 数えずに捨てると、制御レコードが「候補0件」と「突き合わせに失敗して0件」を
/// 同じ顔で報告する（`B-10`）。
#[test]
fn events_never_matched_are_counted_at_the_end() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(vec![event(100, "git status")], |_| Resolution::Unknown, 1)
        .expect("write");
    candidates.finish(2).expect("flush");

    assert_eq!(candidates.stats().unresolved, 1);
    assert!(spawns(candidates.path()).is_empty());
}

/// 対象だが実行像の綴りを出せないものは、**生のNTパスを載せずに数える**。
#[test]
fn a_process_whose_image_path_is_not_expressible_is_counted_not_written() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(
            vec![event(100, "x.exe")],
            |_| Resolution::InScope {
                exe: None,
                parent_exe: Some("C:/a.exe".to_string()),
            },
            1,
        )
        .expect("write");

    assert!(spawns(candidates.path()).is_empty());
    assert_eq!(candidates.stats().without_exe, 1);
}

/// 切り詰めの疑いは、**ちょうど閾値のときだけ**立つ（閾値の正本は共通部品）。
#[test]
fn argv_truncation_is_flagged_on_the_written_line() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());
    let exactly = "a".repeat(1024);
    let longer = "a".repeat(1025);

    candidates
        .observe(vec![event(100, &exactly)], |_| in_scope("C:/a.exe", None), 1)
        .expect("write");
    candidates
        .observe(vec![event(101, &longer)], |_| in_scope("C:/b.exe", None), 2)
        .expect("write");

    let written = spawns(candidates.path());
    assert!(written[0].argv_truncation, "ちょうど1024で疑いが立たない");
    assert!(!written[1].argv_truncation, "超えているものまで疑っている");
}

/// 1件書けなくても、**そのバッチの残りは書く**。
///
/// 打ち切ると、失敗の影響が「その1件」から「そのバッチ全部」へ広がる。
#[test]
fn a_failed_write_does_not_drop_the_rest_of_the_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());
    // 積み先をディレクトリで塞ぐ（追記が必ず失敗する）。
    std::fs::create_dir_all(candidates.path()).unwrap();

    let result = candidates.observe(
        vec![event(100, "a"), event(101, "b")],
        |_| in_scope("C:/a.exe", None),
        1,
    );

    assert!(result.is_err(), "書けなかったことが伝わっていない");
    // 2件とも試したこと（1件目で止まっていないこと）は、統計ではなく
    // **やり直せる状態に戻っている**ことで確かめる——塞ぎを外せば両方が書ける。
    std::fs::remove_dir(candidates.path()).unwrap();
    candidates
        .observe(
            vec![event(100, "a"), event(101, "b")],
            |_| in_scope("C:/a.exe", None),
            2,
        )
        .expect("write");
    let written = spawns(candidates.path());
    assert_eq!(
        written.len(),
        2,
        "書込に失敗した種類が「書いた」ことにされ、二度と現れない"
    );
}

/// 行の形を固定する（**別プロセスが読む**ので、綴りが変わると無言で読めなくなる）。
#[test]
fn the_observed_line_has_a_stable_wire_format() {
    let record = ObservedRecord::ObservedSpawn(Spawn {
        parent_exe: None,
        exe: "C:/git.exe".to_string(),
        argv: "git status".to_string(),
        count: 2,
        first_ts: 1,
        last_ts: 3,
        argv_truncation: false,
    });

    assert_eq!(
        serde_json::to_string(&record).unwrap(),
        r#"{"kind":"observed_spawn","parent_exe":null,"exe":"C:/git.exe","argv":"git status","count":2,"first_ts":1,"last_ts":3,"argv_truncation":false}"#
    );
    assert_eq!(
        serde_json::to_string(&ObservedRecord::Overflowed {
            dropped: 5,
            last_ts: 9
        })
        .unwrap(),
        r#"{"kind":"overflowed","dropped":5,"last_ts":9}"#
    );
}

// ---------------------------------------------------------------------------
// 読む側（段階⑦の遷移画面）
// ---------------------------------------------------------------------------

/// **書いたものが読み戻せる。** 同じ種類の更新行は1行へ畳まれ、**最後の回数**になる。
///
/// # なぜ書き手を通して測るのか
///
/// 畳み込みの鍵は書く側（`observe`）と読む側（`classify`）の**2箇所**にある。
/// 手で行を並べて読むテストだと、**両方が同じようにずれていても緑になる**。
/// 実際に書かせてから読むことでしか、その食い違いは見つからない。
#[test]
fn reading_back_folds_the_update_lines_into_one_kind() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());
    let resolve = |_: u32| in_scope("C:/git.exe", None);

    for tick in 0..4u64 {
        candidates
            .observe(vec![event(100, "git status")], resolve, tick)
            .expect("write");
    }
    // ファイルには3行ある（1件目・2件目・4件目）。
    assert_eq!(spawns(candidates.path()).len(), 3);

    let read = read_folded(tmp.path()).expect("読めない");
    assert_eq!(read.records.len(), 1, "更新行が別の種類として残っている");
    assert_eq!(read.skipped, 0);
    assert_eq!(read.dropped, 0);
    match &read.records[0] {
        ObservedRecord::ObservedSpawn(spawn) => assert_eq!(spawn.count, 4),
        other => panic!("種類の行ではない: {other:?}"),
    }
}

/// **対の側**（`B-35`）: 別の種類まで1行へ潰さない。
///
/// これが無いと「全部を1行へ畳む」実装でも上のテストは緑になり、
/// 画面には候補が常に1本しか出ない。
#[test]
fn reading_back_keeps_different_kinds_apart() {
    let tmp = tempfile::tempdir().unwrap();
    let mut candidates = ObservedCandidates::new(tmp.path());

    candidates
        .observe(
            vec![event(100, "git status")],
            |_| in_scope("C:/git.exe", Some("C:/pwsh.exe")),
            1,
        )
        .expect("write");
    candidates
        .observe(
            vec![event(101, "git status")],
            |_| in_scope("C:/git.exe", Some("C:/cmd.exe")),
            2,
        )
        .expect("write");

    let read = read_folded(tmp.path()).expect("読めない");
    assert_eq!(read.records.len(), 2, "親が違えば別の辺である");
}

/// あふれの報告は**種類ではない**。累計を持つので、2回出ても二重に数えない。
#[test]
fn an_overflow_report_is_not_a_kind_and_is_not_counted_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let path = observed_path(tmp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // 書き手は「その時点までの累計」を書く（`FoldingLog::flush`）。
    std::fs::write(
        &path,
        "{\"kind\":\"overflowed\",\"dropped\":3,\"last_ts\":1}\n\
         {\"kind\":\"overflowed\",\"dropped\":7,\"last_ts\":2}\n",
    )
    .unwrap();

    let read = read_folded(tmp.path()).expect("読めない");
    assert!(read.records.is_empty(), "あふれの行が候補として出ている");
    assert_eq!(read.dropped, 7, "累計を足し合わせて二重に数えている");
}

/// **無いファイルは空である（失敗ではない）。** まだ1度も記録していない構成がこれになる。
#[test]
fn a_missing_file_reads_as_empty_rather_than_failing() {
    let tmp = tempfile::tempdir().unwrap();
    let read = read_folded(tmp.path()).expect("無いファイルが失敗になっている");
    assert!(read.records.is_empty());
    assert_eq!(read.skipped, 0);
}

/// 壊れた行は**数えて飛ばす**。黙って捨てると「その生成は起きなかった」と読まれる（`B-10`）。
#[test]
fn unparsable_lines_are_counted_not_silently_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let path = observed_path(tmp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "これはJSONではない\n\
         {\"kind\":\"observed_spawn\",\"parent_exe\":null,\"exe\":\"C:/git.exe\",\
         \"argv\":\"git status\",\"count\":1,\"first_ts\":1,\"last_ts\":1,\"argv_truncation\":false}\n",
    )
    .unwrap();

    let read = read_folded(tmp.path()).expect("読めない");
    assert_eq!(read.records.len(), 1);
    assert_eq!(read.skipped, 1, "壊れた行が数えられていない");
}

/// 書いている途中の末尾は**行として読まない**。読むと理由の無い警告が画面に出る。
#[test]
fn a_half_written_last_line_is_not_reported_as_broken() {
    let tmp = tempfile::tempdir().unwrap();
    let path = observed_path(tmp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "{\"kind\":\"observed_spawn\",\"parent_exe\":null,\"exe\":\"C:/git.exe\",\
         \"argv\":\"git status\",\"count\":1,\"first_ts\":1,\"last_ts\":1,\"argv_truncation\":false}\n\
         {\"kind\":\"observed_sp",
    )
    .unwrap();

    let read = read_folded(tmp.path()).expect("読めない");
    assert_eq!(read.records.len(), 1);
    assert_eq!(read.skipped, 0, "書きかけの末尾を壊れた行として数えている");
}
