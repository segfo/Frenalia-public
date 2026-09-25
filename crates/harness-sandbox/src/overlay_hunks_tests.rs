//! [`crate::overlay_hunks`]（ハンク単位レビュー材料・部分適用）のテスト。
//!
//! 実FSを触るのでtempdirを使う。管理者権限は不要。

use std::path::Path;

use harness_change_ledger::{store, ChangeOp};
use harness_core::{ReadScopeConfig, StagingConfig, StagingMode};

use super::*;
use crate::overlay::ApplyOptions;

fn staged_fs(workspace_root: &Path) -> SandboxFs {
    SandboxFs::open(
        workspace_root,
        &StagingConfig {
            mode: StagingMode::Staged,
            sandbox_dir: Some(std::path::PathBuf::from(".harness/sandbox/s1")),
        },
    )
    .unwrap()
}

fn cow_fs(workspace_root: &Path, diff_layer_dir: &Path) -> SandboxFs {
    SandboxFs::open_with_cow(
        workspace_root,
        &StagingConfig::default(),
        &ReadScopeConfig::default(),
        Some(diff_layer_dir),
    )
    .unwrap()
}

fn numbered(range: std::ops::Range<usize>) -> String {
    range.map(|i| format!("line{i}\n")).collect()
}

/// 離れた2箇所を変えた「元／変更後」の組（ハンクがちょうど2つになる）。
fn two_hunk_pair() -> (String, String) {
    let old = numbered(0..30);
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line25\n", "CHANGED25\n");
    (old, new)
}

fn entry_for(fs: &SandboxFs, path: &str) -> ChangeEntry {
    fs.change_set()
        .unwrap()
        .into_iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("no change entry for {path}"))
}

fn selection<'a>(path: &'a str, review: &FileReview, accepted: &'a [usize]) -> HunkSelection<'a> {
    HunkSelection {
        path,
        workspace_hash: review.workspace_hash.clone().unwrap_or_default(),
        overlay_hash: review.overlay_hash.clone().unwrap_or_default(),
        accepted,
    }
}

/// 実workspaceに`old`があり、オーバーレイに`new`が書かれた状態のstaged構成を作る。
fn staged_with_modification(dir: &Path, rel: &str, old: &str, new: &str) -> SandboxFs {
    std::fs::write(dir.join(rel), old).unwrap();
    let fs = staged_fs(dir);
    fs.write_string(rel, new).unwrap();
    fs
}

#[test]
fn review_file_splits_a_modification_into_hunks_and_records_both_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);

    let review = fs.review_file(&entry_for(&fs, "a.txt"));
    assert_eq!(review.hunks.len(), 2, "hunks: {:#?}", review.hunks);
    assert_eq!(review.hunk_block, None);
    assert!(review.hunks_selectable());
    assert_eq!(
        review.workspace_hash,
        Some(harness_change_ledger::hash_bytes(old.as_bytes()))
    );
    assert_eq!(
        review.overlay_hash,
        Some(harness_change_ledger::hash_bytes(new.as_bytes()))
    );
}

#[test]
fn apply_hunks_writes_only_the_accepted_hunk_and_leaves_the_rest_in_the_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    let report = fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();
    assert_eq!(report.applied, vec!["a.txt".to_string()]);
    assert!(report.conflicts.is_empty() && report.rejected.is_empty());

    let workspace = std::fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert!(workspace.contains("CHANGED2\n"));
    assert!(!workspace.contains("CHANGED25\n"));
    assert!(workspace.contains("line25\n"));

    // rejectしたハンクは非破壊: オーバーレイは変更後の内容をまるごと持ったまま残る。
    assert_eq!(fs.overlay_content("a.txt").as_deref(), Some(new.as_str()));
    let entry = entry_for(&fs, "a.txt");
    assert_eq!(entry.op, ChangeOp::Modify);
}

#[test]
fn a_partial_apply_is_not_mistaken_for_someone_elses_edit_on_the_next_apply() {
    // baseline張り替え（`store::rebase_baseline`）の検証。これを怠ると、自分が書いた内容が
    // 「セッション中に人が実workspaceを編集した」と誤検知され、残りのハンクを適用できない。
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));
    fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();

    // 残りをファイル単位で適用する。
    let report = fs
        .apply(&ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        })
        .unwrap();
    assert!(
        report.conflicts.is_empty(),
        "conflicts: {:?}",
        report.conflicts
    );
    assert_eq!(report.applied, vec!["a.txt".to_string()]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        new
    );
    assert!(fs.change_set().unwrap().is_empty());
}

#[test]
fn the_remaining_hunk_can_also_be_applied_hunkwise_after_a_partial_apply() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let first = fs.review_file(&entry_for(&fs, "a.txt"));
    fs.apply_hunks(&selection("a.txt", &first, &[0])).unwrap();

    // 開き直すと、残ったハンクだけが差分として見える。
    let second = fs.review_file(&entry_for(&fs, "a.txt"));
    assert_eq!(second.hunks.len(), 1, "hunks: {:#?}", second.hunks);
    let report = fs.apply_hunks(&selection("a.txt", &second, &[0])).unwrap();
    assert_eq!(report.applied, vec!["a.txt".to_string()]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        new
    );
    // 全ハンクを採り切ったので、通常のapplyと同じ後始末（台帳から消える）になる。
    assert!(fs.change_set().unwrap().is_empty());
    assert!(fs.overlay_content("a.txt").is_none());
}

#[test]
fn accepting_every_hunk_cleans_up_like_a_whole_file_apply() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    fs.apply_hunks(&selection("a.txt", &review, &[0, 1]))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        new
    );
    assert!(fs.change_set().unwrap().is_empty());
    assert!(fs.overlay_content("a.txt").is_none());
}

#[test]
fn accepting_nothing_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    let report = fs.apply_hunks(&selection("a.txt", &review, &[])).unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        old
    );
    assert_eq!(fs.change_set().unwrap().len(), 1);
}

#[test]
fn a_workspace_edit_after_the_panel_opened_falls_to_conflicts_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    // パネルを開いた後で人が実workspace側を編集した。
    let edited_by_hand = format!("{old}trailing\n");
    std::fs::write(dir.path().join("a.txt"), &edited_by_hand).unwrap();

    let report = fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();
    assert_eq!(report.conflicts, vec!["a.txt".to_string()]);
    assert!(report.applied.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        edited_by_hand,
        "1バイトも書き換えてはならない"
    );
}

#[test]
fn an_overlay_edit_after_the_panel_opened_falls_to_conflicts_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    // レビュー中にエージェントが同じファイルをもう一度書いた。
    fs.write_string("a.txt", &format!("{new}more\n")).unwrap();

    let report = fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();
    assert_eq!(report.conflicts, vec!["a.txt".to_string()]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        old
    );
}

#[test]
fn partial_apply_preserves_crlf_on_untouched_lines() {
    let dir = tempfile::tempdir().unwrap();
    let old = format!("{}x\r\n{}", numbered(0..10), numbered(10..30));
    let new = old
        .replace("line1\n", "CHANGED1\n")
        .replace("line25\n", "CHANGED25\n");
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));
    assert_eq!(review.hunks.len(), 2);

    fs.apply_hunks(&selection("a.txt", &review, &[1])).unwrap();
    let workspace = std::fs::read_to_string(dir.path().join("a.txt")).unwrap();
    assert!(workspace.contains("x\r\n"), "workspace: {workspace:?}");
    assert!(workspace.contains("CHANGED25\n"));
    assert!(workspace.contains("line1\n"));
}

#[test]
fn hunk_apply_still_hits_the_d09_hard_deny_gate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join(".git/config"), numbered(0..30)).unwrap();
    let fs = staged_fs(dir.path());
    let tampered = numbered(0..30).replace("line2\n", "[core]\n");
    fs.stage_like_a_child_for_test(".git/config", &tampered)
        .unwrap();

    let entry = entry_for(&fs, ".git/config");
    let review = fs.review_file(&entry);
    let report = fs
        .apply_hunks(&selection(".git/config", &review, &[0]))
        .unwrap();
    assert_eq!(report.hard_denied, vec![".git/config".to_string()]);
    assert!(report.applied.is_empty());
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".git/config")).unwrap(),
        numbered(0..30)
    );
}

#[test]
fn hunk_apply_refuses_a_ledger_path_that_escapes_the_workspace() {
    // BUG-062形（台帳のpathが敵対的な綴り）。`apply`と同じく実FSへ触る前に弾く。
    let ws = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    let fs = cow_fs(ws.path(), diff_layer.path());
    store::append_entry(
        diff_layer.path(),
        ChangeOp::Modify,
        "x/../../escape.txt",
        Some("deadbeef".to_string()),
    );

    let review = FileReview {
        workspace_hash: Some("deadbeef".into()),
        overlay_hash: Some("deadbeef".into()),
        ..Default::default()
    };
    let report = fs
        .apply_hunks(&selection("x/../../escape.txt", &review, &[0]))
        .unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.rejected.len(), 1);
    assert!(
        report.rejected[0].1.contains("escapes"),
        "reason: {}",
        report.rejected[0].1
    );
}

#[test]
fn hunk_apply_refuses_a_path_that_is_not_a_change_in_this_session() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
    let fs = staged_fs(dir.path());

    let review = FileReview {
        workspace_hash: Some("deadbeef".into()),
        overlay_hash: Some("deadbeef".into()),
        ..Default::default()
    };
    let report = fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert!(report.rejected[0].1.contains("no such change"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        "hello"
    );
}

#[test]
fn create_and_delete_are_whole_file_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gone.txt"), numbered(0..5)).unwrap();
    let fs = staged_fs(dir.path());
    fs.write_string("fresh.txt", numbered(0..5).as_str())
        .unwrap();
    fs.remove("gone.txt").unwrap();

    let created = fs.review_file(&entry_for(&fs, "fresh.txt"));
    assert_eq!(created.hunk_block, Some(HunkBlock::Create));
    assert!(!created.hunks_selectable());
    // 表示自体は出る（全行追加として見える）。
    assert!(created.hunks.iter().all(|h| h
        .lines
        .iter()
        .all(|l| l.kind == crate::textdiff::DiffKind::Added)));

    let deleted = fs.review_file(&entry_for(&fs, "gone.txt"));
    assert_eq!(deleted.hunk_block, Some(HunkBlock::Delete));
    assert!(deleted.hunks.iter().all(|h| h
        .lines
        .iter()
        .all(|l| l.kind == crate::textdiff::DiffKind::Removed)));

    let report = fs
        .apply_hunks(&selection("fresh.txt", &created, &[0]))
        .unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert!(!dir.path().join("fresh.txt").exists());
}

#[test]
fn unledgered_overlay_files_are_whole_file_only() {
    let ws = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("a.txt"), numbered(0..10)).unwrap();
    // 台帳を経由せず差分層へ直接置かれた版（BUG-066の状況）。
    std::fs::write(
        diff_layer.path().join("a.txt"),
        numbered(0..10).replace("line2\n", "X\n"),
    )
    .unwrap();
    let fs = cow_fs(ws.path(), diff_layer.path());

    let entry = entry_for(&fs, "a.txt");
    assert!(entry.unledgered);
    let review = fs.review_file(&entry);
    assert_eq!(review.hunk_block, Some(HunkBlock::Unledgered));

    let report = fs.apply_hunks(&selection("a.txt", &review, &[0])).unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(
        std::fs::read_to_string(ws.path().join("a.txt")).unwrap(),
        numbered(0..10)
    );
}

#[test]
fn non_utf8_content_is_preview_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), [0x00, 0xff, 0xfe, b'\n']).unwrap();
    let fs = staged_fs(dir.path());
    // オーバーレイ側はUTF-8だが、workspace側が読めないので降格する。
    fs.write_string("bin.dat", "text\n").unwrap();

    let review = fs.review_file(&entry_for(&fs, "bin.dat"));
    assert_eq!(review.hunk_block, Some(HunkBlock::NonUtf8));
    let report = fs
        .apply_hunks(&selection("bin.dat", &review, &[0]))
        .unwrap();
    assert_eq!(report.rejected.len(), 1);
}

#[test]
fn a_hunk_index_out_of_range_is_rejected_instead_of_silently_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = two_hunk_pair();
    let fs = staged_with_modification(dir.path(), "a.txt", &old, &new);
    let review = fs.review_file(&entry_for(&fs, "a.txt"));

    let report = fs
        .apply_hunks(&selection("a.txt", &review, &[0, 7]))
        .unwrap();
    assert_eq!(report.rejected.len(), 1);
    assert!(report.rejected[0].1.contains("out of range"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
        old
    );
}
