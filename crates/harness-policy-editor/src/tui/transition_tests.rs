//! [段階⑦] 承認待ち画面の遷移タブの状態遷移テスト。
//!
//! **端末は要らない**（`App`はratatuiを持たず、描画は別モジュール）。
//! 実際に`.harness/transitions/*.jsonl`をtempdirへ置いて読ませる。

use super::*;

use std::path::Path;

use crossterm::event::KeyModifiers;
use harness_policy::transition_listing;
use harness_sandbox::tier2a::policy_learnd::observed::{observed_path, ObservedRecord, Spawn};

fn write_observed(ws: &Path, spawns: &[(&str, &str)]) {
    let path = observed_path(ws);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut text = String::new();
    for (exe, argv) in spawns {
        let record = ObservedRecord::ObservedSpawn(Spawn {
            parent_exe: Some("C:/pwsh.exe".to_string()),
            exe: exe.to_string(),
            argv: argv.to_string(),
            count: 1,
            first_ts: 1,
            last_ts: 1,
            argv_truncation: false,
        });
        text.push_str(&serde_json::to_string(&record).unwrap());
        text.push('\n');
    }
    std::fs::write(&path, text).unwrap();
}

fn app_at(ws: &Path) -> App {
    App::new(ws.to_path_buf(), harness_core::RequireSandbox::None)
}

fn press(app: &mut App, code: KeyCode) {
    app.on_transition_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn declared_rows(ws: &Path) -> Vec<transition_listing::Row> {
    let file = policy_file::load(ws).expect("policy.jsonが読めない");
    let text = ws.to_string_lossy().into_owned();
    let input = file.transition_graph_input(Some(&text), &[]);
    transition_listing::rows(&input, ENTRY_DOMAIN).expect("一覧が作れない")
}

/// **今日測った台本がそのまま一覧になる。**
///
/// 受け入れの本体（`plans/mac-spike/RESULTS.md` §S71の11本）。観測の行を置いたら、
/// そのぶんだけ候補が出ること——1本でも落ちると、宣言一式が下限のままになる。
#[test]
fn the_eleven_programs_measured_today_all_show_up_as_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    // §S71で実際に降りた鎖（名前で呼ぶと中継役を踏むものは綴りが2つある）。
    let measured = [
        ("C:/Program Files/Git/cmd/git.exe", "git --version"),
        ("C:/Program Files/Git/mingw64/bin/git.exe", "git --version"),
        ("C:/Users/x/.cargo/bin/cargo.exe", "cargo build"),
        (
            "C:/Users/x/.rustup/toolchains/stable/bin/cargo.exe",
            "cargo build",
        ),
        ("C:/Program Files/nodejs/node.exe", "node -v"),
        ("C:/Program Files/nodejs/npm.cmd", "npm -v"),
        ("C:/Windows/System32/cmd.exe", "cmd /c npm"),
        ("C:/Windows/System32/findstr.exe", "findstr fn"),
        (
            "C:/Users/x/.rustup/toolchains/stable/bin/rustc.exe",
            "rustc x",
        ),
        ("C:/VS/bin/link.exe", "link x.o"),
        ("C:/VS/bin/VCTIP.exe", "vctip"),
    ];
    write_observed(tmp.path(), &measured);

    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();

    assert_eq!(
        app.pending.observed.len(),
        11,
        "観測した候補が11本出ていない"
    );
    assert_eq!(
        app.pending.visible().len(),
        11,
        "保留中の一覧に11本出ていない（すべて未宣言のはず）"
    );
    assert!(
        app.pending.notes.is_empty(),
        "読めなかった行がある: {:?}",
        app.pending.notes
    );
}

/// 選んで確定すると`policy.json`へ届き、**モデルが見るのと同じ一覧**に出る。
#[test]
fn selecting_and_confirming_writes_the_edge_to_the_policy_file() {
    let tmp = tempfile::tempdir().unwrap();
    write_observed(tmp.path(), &[("C:/git.exe", "git status")]);

    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();

    press(&mut app, KeyCode::Char(' '));
    assert_eq!(app.pending.approve.len(), 1, "Spaceで選べていない");
    // **aは確認を出すだけで、まだ書かない。**
    press(&mut app, KeyCode::Char('a'));
    assert!(app.modal.is_some(), "確認ダイアログが出ていない");
    assert!(
        policy_file::load(tmp.path()).unwrap().domains.is_empty(),
        "確認の前に書いている"
    );

    app.commit_transition();
    let rows = declared_rows(tmp.path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].exe, "C:/git.exe");
    // 予約は使い切る（次の操作へ持ち越さない）。
    assert!(app.pending.approve.is_empty());
}

/// **対の側**（`B-01`）: 宣言済みの行はその場で外せる。
#[test]
fn an_already_declared_row_can_be_unchecked_and_removed() {
    let tmp = tempfile::tempdir().unwrap();
    write_observed(tmp.path(), &[("C:/git.exe", "git status")]);

    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();
    press(&mut app, KeyCode::Char(' '));
    app.commit_transition();

    // 宣言済みになったので、保留中の一覧からは消える。
    assert!(
        app.pending.visible().is_empty(),
        "宣言済みが保留中に残っている"
    );
    // `f`で「全部」にすると出る。**隠していることが分かる形**（`B-09`）。
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.pending.visible().len(), 1);

    press(&mut app, KeyCode::Char(' '));
    assert_eq!(app.pending.remove.len(), 1, "取り消しを予約できていない");
    app.commit_transition();

    assert!(
        declared_rows(tmp.path()).is_empty(),
        "取り消したのに宣言が残っている"
    );
}

/// 引数を絞る切り替えは、**選んでからでないと効かない**（理由も言う。`B-32`）。
#[test]
fn narrowing_the_argv_requires_selecting_the_row_first() {
    let tmp = tempfile::tempdir().unwrap();
    write_observed(tmp.path(), &[("C:/git.exe", "git config --list")]);

    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();

    press(&mut app, KeyCode::Char('u'));
    assert!(app.pending.narrow.is_empty());
    assert!(
        app.status.contains("先にSpace"),
        "理由を言っていない: {}",
        app.status
    );

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    app.commit_transition();

    assert_eq!(
        declared_rows(tmp.path())[0].argv,
        "git config --list",
        "引数が絞られていない"
    );
}

/// **既定は「任意の引数」である**（対の側。`B-35`）。
///
/// これが無いと「常に観測した引数で絞る」実装でも上のテストは緑になり、
/// 実行のたびに変わる引数（一時ディレクトリ等）では**二度と一致しない辺**ができる。
#[test]
fn the_default_is_any_argument_not_the_observed_one() {
    let tmp = tempfile::tempdir().unwrap();
    write_observed(tmp.path(), &[("C:/git.exe", "git config --list")]);

    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();
    press(&mut app, KeyCode::Char(' '));
    app.commit_transition();

    assert_eq!(
        declared_rows(tmp.path())[0].argv,
        transition_listing::ANY_ARGV
    );
}

/// 壊れた候補ファイルは**空一覧ではなく理由**になる（`B-10`）。
#[test]
fn a_broken_candidate_file_is_reported_rather_than_shown_as_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let path = observed_path(tmp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "これはJSONではない\n").unwrap();

    let mut app = app_at(tmp.path());
    app.reload_transitions();

    assert!(app.pending.observed.is_empty());
    assert!(
        app.pending
            .notes
            .iter()
            .any(|n| n.contains("読めなかった行")),
        "壊れた行を黙って捨てている: {:?}",
        app.pending.notes
    );
}

/// 候補が1件も無いときは、**何も起きない理由を言う**（`B-32`）。
#[test]
fn pressing_space_with_no_rows_says_why_nothing_happened() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_at(tmp.path());
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();

    press(&mut app, KeyCode::Char(' '));
    assert!(!app.status.is_empty(), "黙って何も起きていない");
}

/// `F2`はタブを巡回する（`Tab`は承認待ち画面の項目移動のまま）。
#[test]
fn the_f2_key_cycles_the_three_tabs_of_the_pending_screen() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_at(tmp.path());
    let f2 = KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE);

    app.on_key(f2);
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(
        app.pending.tab.0,
        PendingTab::FsNet,
        "最初は従来の画面である"
    );
    app.on_key(f2);
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsObserved);
    app.on_key(f2);
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsDenied);
    app.on_key(f2);
    assert_eq!(app.pending.tab.0, PendingTab::FsNet, "3つで一周していない");
}
