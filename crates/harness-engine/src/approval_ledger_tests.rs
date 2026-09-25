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
    assert!(matches!(removed.rule, RecordedRule::RunProgram(_)));
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
