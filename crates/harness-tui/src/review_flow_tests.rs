//! レビュー面の通しテスト: **実FS上のオーバーレイ**に対して、変更パネルを開く
//! （[`build_change_rows`]）→キーを打ってハンクを選ぶ（[`AppState::on_key`]）→
//! 実際に適用する（[`apply_commit_selection`]）までを1本で確かめる。
//!
//! 両端（`harness-sandbox`のハンク計算・部分適用、`harness-tui`のパネル操作）はそれぞれの
//! 単体テストが固定しているが、**この2つを繋ぐ配線**——パネルが持ち回るハッシュとハンク番号が、
//! 適用側の再計算と同じものを指しているか——はここでしか通らない。「見たものが適用される」
//! という契約そのものなので、クレートを跨いででも実物で確かめる。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_core::StagingMode;
use harness_sandbox::session_scope::{ScopeTemplate, SessionScope};

use super::*;

fn code(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn staging(session_id: &str) -> SessionScope {
    ScopeTemplate::new(StagingMode::Staged, false).scope_for(session_id)
}

fn numbered(range: std::ops::Range<usize>) -> String {
    range.map(|i| format!("line{i}\n")).collect()
}

#[test]
fn opening_the_panel_choosing_one_hunk_and_committing_applies_exactly_that_hunk() {
    let ws = tempfile::tempdir().unwrap();
    let staging = staging("s1");

    // 実workspaceのファイルを、離れた2箇所で書き換える（＝ハンク2つ）。
    let old = numbered(0..30);
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line25\n", "CHANGED25\n");
    std::fs::write(ws.path().join("a.txt"), &old).unwrap();
    let fs = open_panel_fs(ws.path(), &staging).unwrap();
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
    let staging = staging("s1");
    let old = numbered(0..30);
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace("line25\n", "CHANGED25\n");
    std::fs::write(ws.path().join("a.txt"), &old).unwrap();
    let fs = open_panel_fs(ws.path(), &staging).unwrap();
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

// ---------------------------------------------------------------- セッション切替

/// セッションごとに1オーバーレイを作る（`/sessions`で行き来する状況の再現）。
fn seed_session(ws: &std::path::Path, session_id: &str, file: &str, content: &str) -> SessionScope {
    let scope = staging(session_id);
    let fs = open_panel_fs(ws, &scope).unwrap();
    fs.write_string(file, content).unwrap();
    scope
}

/// `/sessions`の本体: **`review_scope`を差し替えると、パネルが見るオーバーレイが変わる**。
/// これが効かない限り、セッションを移っても起動時セッションの変更を見続ける（本件の症状）。
#[test]
fn adopting_another_sessions_scope_switches_what_the_panel_shows() {
    let ws = tempfile::tempdir().unwrap();
    let a = seed_session(ws.path(), "session-a", "from-a.txt", "a\n");
    let b = seed_session(ws.path(), "session-b", "from-b.txt", "b\n");

    let mut app = AppState::new("mock".into(), "mock-model".into());
    let mut review_scope = a.clone();
    app.note_scope(overlay_label(&review_scope), "session-a");

    let rows = build_change_rows(
        &open_panel_fs(ws.path(), &review_scope).unwrap(),
        open_panel_fs(ws.path(), &review_scope).unwrap().change_set().unwrap(),
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "from-a.txt");

    let unapplied = adopt_scope(&mut app, ws.path(), &mut review_scope, b.clone());
    assert_eq!(unapplied, 1);
    assert_eq!(review_scope, b);

    let fs = open_panel_fs(ws.path(), &review_scope).unwrap();
    let rows = build_change_rows(&fs, fs.change_set().unwrap());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "from-b.txt", "切替後もセッションAの変更を見ている");
}

/// B-22: スコープが変わったら**開いているパネルを閉じる**。旧オーバーレイの行を見ながら
/// 新オーバーレイへcommitする経路を構造的に塞ぐ（`c`は適用時にFSを開き直すため）。
#[test]
fn switching_the_scope_closes_a_panel_that_is_still_open() {
    let ws = tempfile::tempdir().unwrap();
    let a = seed_session(ws.path(), "session-a", "from-a.txt", "a\n");
    let b = seed_session(ws.path(), "session-b", "from-b.txt", "b\n");

    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.note_scope(overlay_label(&a), "session-a");
    let fs = open_panel_fs(ws.path(), &a).unwrap();
    app.open_changes_panel(build_change_rows(&fs, fs.change_set().unwrap()));
    assert!(app.review_panel.is_some());

    let mut review_scope = a;
    adopt_scope(&mut app, ws.path(), &mut review_scope, b);
    assert!(app.review_panel.is_none(), "旧オーバーレイの行が残っている");
}

/// パネルの見出しに、いま見ているオーバーレイのセッションIDが出る（B-22/B-32）。
#[test]
fn the_panel_title_names_the_overlay_it_shows() {
    let ws = tempfile::tempdir().unwrap();
    let a = seed_session(ws.path(), "session-a", "from-a.txt", "a\n");
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.note_scope(overlay_label(&a), "session-a");
    let fs = open_panel_fs(ws.path(), &a).unwrap();
    app.open_changes_panel(build_change_rows(&fs, fs.change_set().unwrap()));
    assert_eq!(app.review_panel.as_ref().unwrap().title, "changes — session-a");
}

/// `/fork`: オーバーレイをコピーして分岐する。**両方に同じ変更がある**。
#[test]
fn forking_copies_the_overlay_so_both_branches_have_the_change() {
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("a.txt"), "old\n").unwrap();
    let src = seed_session(ws.path(), "session-src", "a.txt", "new\n");

    let template = ScopeTemplate::new(StagingMode::Staged, false);
    let mut app = AppState::new("mock".into(), "mock-model".into());
    let mut review_scope = src.clone();
    app.note_scope(overlay_label(&review_scope), "session-src");

    let dst = template.scope_for("session-fork");
    harness_sandbox::session_scope::prepare_scope(ws.path(), &dst).unwrap();
    let copied = harness_sandbox::session_scope::copy_overlay(
        &review_scope.overlay_dir(ws.path()).unwrap(),
        &dst.overlay_dir(ws.path()).unwrap(),
    )
    .unwrap();
    assert!(copied > 0, "何もコピーされていない");
    adopt_scope(&mut app, ws.path(), &mut review_scope, dst.clone());

    for scope in [&src, &dst] {
        let fs = open_panel_fs(ws.path(), scope).unwrap();
        let rows = build_change_rows(&fs, fs.change_set().unwrap());
        assert_eq!(rows.len(), 1, "{}", scope.session_id);
        assert_eq!(rows[0].label, "a.txt");
    }
}

/// `/fork`後に片方をapplyすると、もう片方は**conflictとして弾かれる**（二重適用の防止）。
/// 台帳のbaselineは両方とも「fork前のworkspace内容」を指しているので、先に適用した側が
/// workspaceを書き換えた時点で後続のハッシュ照合が合わなくなる。
#[test]
fn applying_one_forked_branch_makes_the_other_conflict_instead_of_applying_twice() {
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("a.txt"), "old\n").unwrap();
    let src = seed_session(ws.path(), "session-src", "a.txt", "new\n");

    let dst = ScopeTemplate::new(StagingMode::Staged, false).scope_for("session-fork");
    harness_sandbox::session_scope::prepare_scope(ws.path(), &dst).unwrap();
    harness_sandbox::session_scope::copy_overlay(
        &src.overlay_dir(ws.path()).unwrap(),
        &dst.overlay_dir(ws.path()).unwrap(),
    )
    .unwrap();

    // 分岐先で適用する。
    let fs_dst = open_panel_fs(ws.path(), &dst).unwrap();
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(build_change_rows(&fs_dst, fs_dst.change_set().unwrap()));
    let Some(Action::CommitChanges(selection)) =
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE))
    else {
        panic!("expected CommitChanges");
    };
    let report = apply_commit_selection(&fs_dst, &selection).unwrap();
    assert_eq!(report.applied, vec!["a.txt".to_string()]);
    assert_eq!(std::fs::read_to_string(ws.path().join("a.txt")).unwrap(), "new\n");

    // 元の分岐から同じ変更をもう一度適用しようとしても、workspaceは既に書き換わっている。
    // ここが素通りすると「同じ変更が2回入る」ことになる。
    let fs_src = open_panel_fs(ws.path(), &src).unwrap();
    let report = fs_src
        .apply(&harness_sandbox::ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        })
        .unwrap();
    assert!(report.applied.is_empty(), "二重適用された: {report:?}");
}

/// `--live`では切り替えるオーバーレイが無い。`/sessions`しても副作用ゼロで、
/// ステータスバーにも`overlay=`を出さない。
#[test]
fn switching_sessions_in_live_mode_is_a_no_op() {
    let ws = tempfile::tempdir().unwrap();
    let template = ScopeTemplate::new(StagingMode::Live, false);
    let scope = template.scope_for("session-x");
    assert!(scope.is_live());
    assert_eq!(overlay_label(&scope), "");
    assert_eq!(harness_sandbox::session_scope::prepare_scope(ws.path(), &scope).unwrap(), 0);
    assert!(!ws.path().join(".harness").exists());
}
