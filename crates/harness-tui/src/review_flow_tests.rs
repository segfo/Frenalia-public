//! レビュー面の通しテスト: **実FS上のオーバーレイ**に対して、変更パネルを開く
//! （[`build_change_rows`]）→キーを打ってハンクを選ぶ（[`AppState::on_key`]）→
//! 実際に適用する（[`apply_commit_selection`]）までを1本で確かめる。
//!
//! 両端（`harness-sandbox`のハンク計算・部分適用、`harness-tui`のパネル操作）はそれぞれの
//! 単体テストが固定しているが、**この2つを繋ぐ配線**——パネルが持ち回るハッシュとハンク番号が、
//! 適用側の再計算と同じものを指しているか——はここでしか通らない。「見たものが適用される」
//! という契約そのものなので、クレートを跨いででも実物で確かめる。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_core::{StagingConfig, StagingMode};

use super::*;

fn code(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn staging(sandbox_dir: &str) -> StagingConfig {
    StagingConfig {
        mode: StagingMode::Staged,
        sandbox_dir: Some(PathBuf::from(sandbox_dir)),
    }
}

fn numbered(range: std::ops::Range<usize>) -> String {
    range.map(|i| format!("line{i}\n")).collect()
}

#[test]
fn opening_the_panel_choosing_one_hunk_and_committing_applies_exactly_that_hunk() {
    let ws = tempfile::tempdir().unwrap();
    let staging = staging(".harness/sandbox/s1");

    // 実workspaceのファイルを、離れた2箇所で書き換える（＝ハンク2つ）。
    let old = numbered(0..30);
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line25\n", "CHANGED25\n");
    std::fs::write(ws.path().join("a.txt"), &old).unwrap();
    let fs = open_panel_fs(ws.path(), &staging, None).unwrap();
    fs.write_string("a.txt", &new).unwrap();

    // パネルを開く。
    let rows = build_change_rows(&fs, fs.change_set().unwrap());
    assert_eq!(rows.len(), 1);
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(rows);
    assert_eq!(
        app.review_panel.as_ref().unwrap().rows[0]
            .review
            .hunks
            .len(),
        2
    );

    // Tabでdiffペインへ、↓で2つ目のハンクへ、Enterでreject、cでコミット。
    app.on_key(code(KeyCode::Tab));
    app.on_key(code(KeyCode::Down));
    app.on_key(code(KeyCode::Enter));
    let Some(Action::CommitChanges(selection)) =
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
    else {
        panic!("expected CommitChanges");
    };

    let report = apply_commit_selection(&fs, &selection).unwrap();
    assert_eq!(report.applied, vec!["a.txt".to_string()]);
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);

    // 画面で選んだ1つ目のハンクだけが実workspaceへ入り、2つ目はオーバーレイに残る。
    let applied = std::fs::read_to_string(ws.path().join("a.txt")).unwrap();
    assert!(applied.contains("CHANGED2\n"));
    assert!(!applied.contains("CHANGED25\n"));
    assert_eq!(fs.overlay_content("a.txt").as_deref(), Some(new.as_str()));

    // 開き直すと残り1ハンクだけが見え、conflict誤検知も無い。
    let rows = build_change_rows(&fs, fs.change_set().unwrap());
    assert_eq!(rows[0].review.hunks.len(), 1);
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(rows);
    let Some(Action::CommitChanges(selection)) =
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
    else {
        panic!("expected CommitChanges");
    };
    // ハンクを1つもrejectしていないので、ファイル単位の適用になる。
    assert_eq!(selection.whole_files, vec!["a.txt".to_string()]);
    let report = apply_commit_selection(&fs, &selection).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        std::fs::read_to_string(ws.path().join("a.txt")).unwrap(),
        new
    );
    assert!(fs.change_set().unwrap().is_empty());
}

#[test]
fn an_edit_between_opening_the_panel_and_committing_is_refused_as_a_conflict() {
    let ws = tempfile::tempdir().unwrap();
    let staging = staging(".harness/sandbox/s1");
    let old = numbered(0..30);
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line25\n", "CHANGED25\n");
    std::fs::write(ws.path().join("a.txt"), &old).unwrap();
    let fs = open_panel_fs(ws.path(), &staging, None).unwrap();
    fs.write_string("a.txt", &new).unwrap();

    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(build_change_rows(&fs, fs.change_set().unwrap()));
    app.on_key(code(KeyCode::Tab));
    app.on_key(code(KeyCode::Down));
    app.on_key(code(KeyCode::Enter)); // 2つ目のハンクをreject

    // レビュー中に人が実workspaceを編集した。
    let by_hand = format!("{old}appended by a human\n");
    std::fs::write(ws.path().join("a.txt"), &by_hand).unwrap();

    let Some(Action::CommitChanges(selection)) =
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
    else {
        panic!("expected CommitChanges");
    };
    let report = apply_commit_selection(&fs, &selection).unwrap();
    assert_eq!(report.conflicts, vec!["a.txt".to_string()]);
    assert!(report.applied.is_empty());
    assert_eq!(
        std::fs::read_to_string(ws.path().join("a.txt")).unwrap(),
        by_hand
    );
}
