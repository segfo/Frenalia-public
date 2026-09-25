//! 承認の台帳の回帰テスト。内部関数（`is_valid_rule`・`collect_garbage`）へ触れるため
//! `#[cfg(test)]`のまま別ファイルへ分けている（`docs/CODE-STRUCTURE-RULES.md`規則2）。
//!
//! **実際のユーザー層（`%APPDATA%`・`%LOCALAPPDATA%`）は一切触らない**——[`ApprovalStore::at`]で
//! 一時ディレクトリへ逃がす（`bug-pattern-rules` B-27: 後始末を製品にさせない）。

use super::*;

fn store() -> (tempfile::TempDir, ApprovalStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ApprovalStore::at(
        dir.path().join("run-approval-ledger.json"),
        dir.path().join("snapshots"),
    );
    (dir, store)
}

/// 台帳のファイルを書き換える（台帳は書いた後に読取専用属性を付けるので、先に外す）。
fn rewrite_ledger(path: &Path, f: impl FnOnce(String) -> String) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms).unwrap();
    std::fs::write(path, f(text)).unwrap();
}

fn bound(rel: &str, sha: &str) -> BoundFile {
    BoundFile {
        rel_path: rel.to_string(),
        sha256: sha.repeat(64 / sha.len()),
        dir_listing_sha256: Some("b".repeat(64)),
    }
}

fn script_rule(sha: &str) -> RecordedRule {
    RecordedRule::RunProgram(ProgramRule {
        program: "python".into(),
        args: vec![ArgPattern::Exact("build.py".into())],
        resolved: Some("C:/Python/python.exe".into()),
        files: vec![bound("build.py", sha)],
        workspace: Some("c:/ws".into()),
    })
}

fn preview(text: &str) -> FilePreview {
    FilePreview {
        rel_path: "build.py".into(),
        text: text.to_string(),
        truncated: false,
    }
}

/// 記録して読み直せる。同じ呼び出しを承認し直すと置き換わる（2件にならない）。
#[test]
fn an_approval_round_trips_and_re_approval_replaces_it() {
    let (_dir, store) = store();
    assert!(store.load_valid().rules.is_empty());

    store.record(script_rule("a"), &[preview("v1")]).unwrap();
    let loaded = store.load_valid();
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.voided_by_version, 0);
    assert_eq!(loaded.dropped_invalid, 0);

    // 中身が変わって承認し直した（引数は同じ）。古い記録は残さない。
    store.record(script_rule("c"), &[preview("v2")]).unwrap();
    let loaded = store.load_valid();
    assert_eq!(loaded.rules.len(), 1, "{:?}", loaded.rules);
    assert_eq!(loaded.rules[0], script_rule("c"));
}

/// 形の版が違う記録は無かったものとして扱い、件数を返す（告知するため）。
#[test]
fn a_record_from_another_format_version_is_void() {
    let (dir, store) = store();
    store.record(script_rule("a"), &[]).unwrap();
    rewrite_ledger(&dir.path().join("run-approval-ledger.json"), |text| {
        text.replace(
            &format!("\"format_version\": {FORMAT_VERSION}"),
            "\"format_version\": 0",
        )
    });

    let loaded = store.load_valid();
    assert!(loaded.rules.is_empty());
    assert_eq!(loaded.voided_by_version, 1);
    // 一覧には残る（取り消せる）。
    assert_eq!(store.list().len(), 1);
}

/// 読む側で検証する——穴を持つインタプリタ・ワークスペースに縛られていない・形の崩れたハッシュ・
/// 制御文字・ワークスペースを抜けるパスは捨てる。正しい記録は残る（対照）。
#[test]
fn records_that_do_not_pass_validation_are_dropped_on_load() {
    let valid = script_rule("a");
    assert!(is_valid_rule(&valid));

    let mut with_hole = match valid.clone() {
        RecordedRule::RunProgram(r) => r,
        _ => unreachable!(),
    };
    with_hole.args = vec![ArgPattern::Hole];
    assert!(!is_valid_rule(&RecordedRule::RunProgram(with_hole)));

    let mut unbound_workspace = match valid.clone() {
        RecordedRule::RunProgram(r) => r,
        _ => unreachable!(),
    };
    unbound_workspace.workspace = None;
    assert!(!is_valid_rule(&RecordedRule::RunProgram(unbound_workspace)));

    let mut bad_hash = match valid.clone() {
        RecordedRule::RunProgram(r) => r,
        _ => unreachable!(),
    };
    bad_hash.files[0].sha256 = "nope".into();
    assert!(!is_valid_rule(&RecordedRule::RunProgram(bad_hash)));

    let mut control_char = match valid.clone() {
        RecordedRule::RunProgram(r) => r,
        _ => unreachable!(),
    };
    control_char.args = vec![ArgPattern::Exact("build\u{202E}.py".into())];
    assert!(!is_valid_rule(&RecordedRule::RunProgram(control_char)));

    let mut escaping = match valid.clone() {
        RecordedRule::RunProgram(r) => r,
        _ => unreachable!(),
    };
    escaping.files[0].rel_path = "../outside.py".into();
    assert!(!is_valid_rule(&RecordedRule::RunProgram(escaping)));

    // run_shell はワークスペースに縛られていなければならない。
    assert!(!is_valid_rule(&RecordedRule::RunShell(ShellRule {
        line: "cargo test".into(),
        files: vec![],
        workspace: None,
    })));
    assert!(is_valid_rule(&RecordedRule::RunShell(ShellRule {
        line: "cargo test".into(),
        files: vec![],
        workspace: Some("c:/ws".into()),
    })));

    // 読み込みが捨てた件数を数える。
    let (dir, store) = store();
    store.record(valid, &[]).unwrap();
    rewrite_ledger(&dir.path().join("run-approval-ledger.json"), |text| {
        text.replace("\"build.py\"", "\"../outside.py\"")
    });
    let loaded = store.load_valid();
    assert!(loaded.rules.is_empty());
    assert_eq!(loaded.dropped_invalid, 1);
}

/// 取り消すと消える。全部取り消すと件数を返す。
#[test]
fn approvals_can_be_revoked_one_by_one_or_all_at_once() {
    let (_dir, store) = store();
    store.record(script_rule("a"), &[]).unwrap();
    store
        .record(
            RecordedRule::RunShell(ShellRule {
                line: "cargo test".into(),
                files: vec![],
                workspace: Some("c:/ws".into()),
            }),
            &[],
        )
        .unwrap();
    assert_eq!(store.list().len(), 2);

    assert!(store.revoke(9).is_err());
    let removed = store.revoke(0).unwrap();
    assert!(matches!(
        removed.parsed.unwrap().rule,
        RecordedRule::RunProgram(_)
    ));
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.revoke_all(), 1);
    assert!(store.list().is_empty());
}

/// 差分用の写しは、承認したときに見せた中身を返す。壊れていれば理由を返す（判定には影響しない）。
/// どの記録からも参照されなくなった写しは消える。
#[test]
fn snapshots_are_kept_for_diffs_verified_on_read_and_collected_when_unreferenced() {
    let (dir, store) = store();
    let rule = script_rule("a");
    store.record(rule.clone(), &[preview("v1")]).unwrap();
    assert_eq!(
        store.previous_snapshot(&rule, "build.py").unwrap().unwrap(),
        "v1"
    );
    assert!(store.previous_snapshot(&rule, "other.py").is_none());

    // 写しを書き換えると「壊れている」と分かる（読む側で照合する）。
    let snap_dir = dir.path().join("snapshots");
    let snap = std::fs::read_dir(&snap_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    std::fs::write(snap.path(), "tampered").unwrap();
    let err = store
        .previous_snapshot(&rule, "build.py")
        .unwrap()
        .unwrap_err();
    assert!(err.contains("corrupted"), "{err}");

    // 中身を変えて承認し直すと、古い写しは参照されなくなるので消える。
    store.record(script_rule("c"), &[preview("v2")]).unwrap();
    let names: Vec<String> = std::fs::read_dir(&snap_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");

    // 取り消すと写しも残らない。
    store.revoke_all();
    assert_eq!(std::fs::read_dir(&snap_dir).unwrap().count(), 0);
}

/// 写しの置き場にある**写しの名前の形をしていないファイル**は消さない（他人のファイルを消さない）。
#[test]
fn garbage_collection_only_touches_files_it_wrote() {
    let (dir, store) = store();
    let snap_dir = dir.path().join("snapshots");
    std::fs::create_dir_all(&snap_dir).unwrap();
    std::fs::write(snap_dir.join("notes.txt"), "not mine").unwrap();
    std::fs::write(snap_dir.join("deadbeef.txt"), "short name, not a hash").unwrap();

    store.record(script_rule("a"), &[preview("v1")]).unwrap();
    store.revoke_all();

    assert!(snap_dir.join("notes.txt").exists());
    assert!(snap_dir.join("deadbeef.txt").exists());
}

/// **読めない記録が1件混ざっても、他の記録を道連れにしない**（D-107）。
///
/// 台帳は丸ごと1回で読むので、以前は1件の型不一致がファイル全体のパース失敗になり、控えへ落ち、
/// そこも駄目なら**全件消えて**いた。将来この形へ種類を1つ足した新しいハーネスと、古いハーネスが
/// 同じ機械に居るのは普通のことである。
#[test]
fn a_record_that_cannot_be_read_does_not_take_the_others_with_it() {
    let (dir, store) = store();
    store.record(script_rule("a"), &[]).unwrap();
    store
        .record(
            RecordedRule::RunShell(ShellRule {
                line: "cargo test".into(),
                files: vec![],
                workspace: Some("c:/ws".into()),
            }),
            &[],
        )
        .unwrap();

    // 1件目を「新しい形」（この版が知らない綴り）へ差し替える。
    rewrite_ledger(&dir.path().join("run-approval-ledger.json"), |text| {
        text.replace("\"run_program\"", "\"run_container\"")
    });

    // **前はこの1件で全件失っていた。** ファイル全体を一度に型付けすると、いまでもここで落ちる
    // ——落ちる事実そのものを固定しておく（生のまま持つ形へ戻したら、この行が無意味になる前に
    // 下の assert が落ちる）。
    #[derive(serde::Deserialize)]
    struct WholeAtOnce {
        #[allow(dead_code)]
        approvals: Vec<RunApproval>,
    }
    let text = std::fs::read_to_string(dir.path().join("run-approval-ledger.json")).unwrap();
    assert!(
        serde_json::from_str::<WholeAtOnce>(&text).is_err(),
        "この JSON は丸ごと型付けすると落ちる、という前提が崩れている"
    );

    let loaded = store.load_valid();
    assert_eq!(loaded.unreadable, 1);
    assert_eq!(
        loaded.rules.len(),
        1,
        "残りは読めている: {:?}",
        loaded.rules
    );

    // 一覧には並びを保ったまま出る——**番号で指せなければ取り消せない**。
    let listed = store.list();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].parsed.is_none());
    assert!(listed[1].parsed.is_some());

    // その1件も取り消せる。取り消した後は残りだけになる。
    let removed = store.revoke(0).unwrap();
    assert!(removed.parsed.is_none());
    assert_eq!(store.list().len(), 1);
    assert_eq!(store.load_valid().rules.len(), 1);
}

/// 読めない記録が参照している写しは消さない（型が分からないだけで、見せていた中身を捨てない）。
#[test]
fn a_snapshot_referenced_by_an_unreadable_record_survives_collection() {
    let (dir, store) = store();
    store.record(script_rule("a"), &[preview("v1")]).unwrap();
    let snap_dir = dir.path().join("snapshots");
    assert_eq!(std::fs::read_dir(&snap_dir).unwrap().count(), 1);

    rewrite_ledger(&dir.path().join("run-approval-ledger.json"), |text| {
        text.replace("\"run_program\"", "\"run_container\"")
    });
    // 別の承認を記録すると後始末が走るが、読めない記録の写しは残る。
    store
        .record(
            RecordedRule::RunShell(ShellRule {
                line: "cargo test".into(),
                files: vec![],
                workspace: Some("c:/ws".into()),
            }),
            &[],
        )
        .unwrap();
    assert_eq!(
        std::fs::read_dir(&snap_dir).unwrap().count(),
        1,
        "読めない記録の写しまで消している"
    );
}

/// 対照: 全部読めなければ空になる（読めるものが1つも無いのだから、それは正しい）。
#[test]
fn an_entirely_unreadable_ledger_yields_nothing() {
    let (dir, store) = store();
    store.record(script_rule("a"), &[]).unwrap();
    rewrite_ledger(&dir.path().join("run-approval-ledger.json"), |text| {
        text.replace("\"run_program\"", "\"run_container\"")
    });
    let loaded = store.load_valid();
    assert!(loaded.rules.is_empty());
    assert_eq!(loaded.unreadable, 1);
    assert_eq!(store.list().len(), 1, "一覧には残る（取り消せる）");
}
