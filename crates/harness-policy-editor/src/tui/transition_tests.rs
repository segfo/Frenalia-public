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
    // 巡回は「保留中 → 却下済み → 全部」なので2回押す。宣言済みの行は却下済みの段には入らない。
    press(&mut app, KeyCode::Char('f'));
    assert!(
        app.pending.visible().is_empty(),
        "宣言済みが却下済みの段に出ている"
    );
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.pending.filter, PendingFilter::All);
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

// --- 却下（`dismissed.json`。決定62「却下印の永続化を実装した」） -----------------------

/// 遷移タブに入った状態のエディタを作る（観測の候補を読み込み済み）。
fn observed_tab_with(ws: &Path, spawns: &[(&str, &str)]) -> App {
    write_observed(ws, spawns);
    let mut app = app_at(ws);
    app.pending.tab = Tab(PendingTab::TransitionsObserved);
    app.reload_transitions();
    app
}

/// 選択中の行の実行ファイル（借用を切るため複製して返す）。
fn selected_exe(app: &App) -> String {
    app.pending.visible()[app.pending.row()].exe.clone()
}

/// `a`で確認を出してから確定する（`y`を押したのと同じ経路）。
fn confirm(app: &mut App) {
    press(app, KeyCode::Char('a'));
    assert!(
        matches!(
            app.modal.as_ref().map(|m| m.confirm),
            Some(Confirm::Transition)
        ),
        "確認ダイアログが出ていない: {}",
        app.status
    );
    app.modal = None;
    app.commit_transition();
}

fn visible_exes(app: &App) -> Vec<String> {
    app.pending.visible().iter().map(|c| c.exe.clone()).collect()
}

/// 却下すると保留中から消えて「却下済み」に出る。「全部」には出る。
/// **見出しの件数が3段とも合う**（`B-09`: 「無い」と「隠している」を区別する）。
#[test]
fn dismissing_moves_a_row_from_pending_to_dismissed_and_the_counts_follow() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(
        tmp.path(),
        &[("C:/a.exe", "a"), ("C:/b.exe", "b"), ("C:/c.exe", "c")],
    );
    // 1本は承認して宣言済みにする（どちらの段にも入らず「全部」にだけ出る行）。
    press(&mut app, KeyCode::Char(' '));
    confirm(&mut app);
    // 残り2本のうち先頭を却下する。
    let dismissed = selected_exe(&app);
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(app.pending.dismiss.len(), 1, "x で却下を予約できていない");
    // **確定するまでは書かない**（予約→確定の流れ）。
    assert!(!transition_dismissed::path(tmp.path()).exists());
    confirm(&mut app);

    let counts = app.pending.counts(PendingTab::TransitionsObserved);
    assert_eq!(
        counts,
        Counts {
            pending: 1,
            dismissed: 1,
            total: 3
        }
    );
    assert!(
        !visible_exes(&app).contains(&dismissed),
        "却下したのに保留中に残っている"
    );
    assert_eq!(app.pending.visible().len(), counts.pending);

    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.pending.filter, PendingFilter::Dismissed);
    assert_eq!(visible_exes(&app), vec![dismissed.clone()]);
    assert_eq!(app.pending.visible().len(), counts.dismissed);

    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.pending.filter, PendingFilter::All);
    assert_eq!(app.pending.visible().len(), counts.total);
    assert!(visible_exes(&app).contains(&dismissed));

    press(&mut app, KeyCode::Char('f'));
    assert_eq!(
        app.pending.filter,
        PendingFilter::Pending,
        "3段で一周していない"
    );
}

/// **対の側**（`B-01`）: 却下を取り消すと保留中へ戻る——片方向の操作にしない（決定62）。
#[test]
fn undismissing_brings_the_row_back_to_pending() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(tmp.path(), &[("C:/a.exe", "a"), ("C:/b.exe", "b")]);
    let target = selected_exe(&app);
    press(&mut app, KeyCode::Char('x'));
    confirm(&mut app);
    assert_eq!(app.pending.visible().len(), 1);

    press(&mut app, KeyCode::Char('f')); // 却下済み
    assert_eq!(visible_exes(&app), vec![target.clone()]);
    press(&mut app, KeyCode::Char('x'));
    assert_eq!(
        app.pending.undismiss.len(),
        1,
        "却下の取り消しを予約できていない"
    );
    confirm(&mut app);

    assert!(app.pending.visible().is_empty(), "却下済みの段に残っている");
    press(&mut app, KeyCode::Char('f')); // 全部
    press(&mut app, KeyCode::Char('f')); // 保留中
    assert!(visible_exes(&app).contains(&target), "保留中へ戻っていない");
    assert_eq!(
        app.pending
            .counts(PendingTab::TransitionsObserved)
            .dismissed,
        0
    );
    assert!(transition_dismissed::load(tmp.path()).unwrap().is_empty());
}

/// 保存して**エディタを開き直しても**却下が残る（決定62が新設するのはこの永続化だけ）。
#[test]
fn a_dismissal_survives_reopening_the_editor() {
    let tmp = tempfile::tempdir().unwrap();
    let mut first = observed_tab_with(tmp.path(), &[("C:/a.exe", "a"), ("C:/b.exe", "b")]);
    let target = selected_exe(&first);
    press(&mut first, KeyCode::Char('x'));
    confirm(&mut first);
    drop(first);

    let mut second = app_at(tmp.path());
    second.pending.tab = Tab(PendingTab::TransitionsObserved);
    second.reload_transitions();
    assert!(
        !visible_exes(&second).contains(&target),
        "開き直したら保留中へ戻った"
    );
    assert_eq!(
        second
            .pending
            .counts(PendingTab::TransitionsObserved)
            .dismissed,
        1
    );
}

/// 壊れた`dismissed.json`は**警告付きで空として読む**（保留中に多く出る側）。
/// 書く段では**何も書かずに止まり**、壊れた中身を上書きしない。
#[test]
fn a_broken_dismissed_file_is_reported_read_as_empty_and_not_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let path = transition_dismissed::path(tmp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "壊れている").unwrap();

    let mut app = observed_tab_with(tmp.path(), &[("C:/a.exe", "a"), ("C:/b.exe", "b")]);
    assert!(
        app.pending
            .notes
            .iter()
            .any(|n| n.contains("却下印を読めない")),
        "壊れた却下印を黙って空にしている: {:?}",
        app.pending.notes
    );
    assert_eq!(app.pending.visible().len(), 2, "読めないのに行を隠している");

    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("理由を出していない");
    assert_eq!(
        modal.confirm,
        Confirm::ReadOnly,
        "壊れているのに書く確認を出している"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "壊れている");
}

/// **一括承認の手段は増えていない**（決定62・決定51）。
///
/// どの1キーを押しても、承認の予約は高々1件しか増えない。`X`（まとめて却下）は
/// 却下だけを増やし、承認を1件も増やさない。**対の側**として、`X`が実際に全件を却下へ
/// 入れることも確かめる（何もしない`X`でも上の条件は緑になるため）。
#[test]
fn no_single_key_reserves_more_than_one_approval_but_x_dismisses_them_all() {
    let tmp = tempfile::tempdir().unwrap();
    let rows = [("C:/a.exe", "a"), ("C:/b.exe", "b"), ("C:/c.exe", "c")];
    let mut keys: Vec<KeyCode> = (0x20u8..0x7f).map(|b| KeyCode::Char(b as char)).collect();
    keys.extend([
        KeyCode::Enter,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Insert,
        KeyCode::Delete,
    ]);
    for code in keys {
        let mut app = observed_tab_with(tmp.path(), &rows);
        press(&mut app, code);
        assert!(
            app.pending.approve.len() <= 1,
            "{code:?} で承認の予約が{}件増えた",
            app.pending.approve.len()
        );
    }

    let mut app = observed_tab_with(tmp.path(), &rows);
    press(&mut app, KeyCode::Char('X'));
    assert_eq!(
        app.pending.dismiss.len(),
        3,
        "X が表示中の保留中を全部却下していない"
    );
    assert!(app.pending.approve.is_empty());
}

/// まとめての却下は、**承認を予約した行を黙って裏返さない**（飛ばして、飛ばした件数を言う）。
#[test]
fn bulk_dismissal_skips_rows_reserved_for_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(
        tmp.path(),
        &[("C:/a.exe", "a"), ("C:/b.exe", "b"), ("C:/c.exe", "c")],
    );
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('X'));

    assert_eq!(app.pending.approve.len(), 1, "承認の予約が消えた");
    assert_eq!(app.pending.dismiss.len(), 2);
    assert!(
        app.status.contains("除きました"),
        "飛ばしたことを言っていない: {}",
        app.status
    );
}

/// 1つの行に「許す」と「許さない」を同時に予約させない（どちらの順で押しても）。
#[test]
fn approval_and_dismissal_are_never_reserved_together_on_one_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(tmp.path(), &[("C:/a.exe", "a")]);

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('x'));
    assert!(
        app.pending.approve.is_empty(),
        "却下したのに承認の予約が残っている"
    );
    assert_eq!(app.pending.dismiss.len(), 1);

    press(&mut app, KeyCode::Char(' '));
    assert!(
        app.pending.dismiss.is_empty(),
        "承認したのに却下の予約が残っている"
    );
    assert_eq!(app.pending.approve.len(), 1);
}

/// 却下済みの行は**選び直して許せる**。許したら却下印も外れる
/// （後で宣言を取り消したときに「却下済み」として戻ってこない）。
#[test]
fn approving_a_dismissed_row_writes_the_edge_and_clears_its_mark() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(tmp.path(), &[("C:/git.exe", "git status")]);
    press(&mut app, KeyCode::Char('x'));
    confirm(&mut app);

    press(&mut app, KeyCode::Char('f')); // 却下済み
    assert_eq!(app.pending.visible().len(), 1);
    press(&mut app, KeyCode::Char(' '));
    confirm(&mut app);

    assert_eq!(declared_rows(tmp.path()).len(), 1, "宣言へ届いていない");
    assert!(
        transition_dismissed::load(tmp.path()).unwrap().is_empty(),
        "許したのに却下印が残っている"
    );
}

/// 却下だけを確定するダイアログは、**書く先が`dismissed.json`だけであること**と
/// **却下が何を変えないか**を言う（`B-32`: 文言は実装の一部）。`policy.json`の明細は出さない。
#[test]
fn the_dismissal_confirmation_names_its_file_and_says_what_it_does_not_change() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(tmp.path(), &[("C:/git.exe", "git status")]);
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Char('a'));

    let modal = app.modal.as_ref().expect("確認ダイアログが出ていない");
    let text = modal.lines.join("\n");
    assert!(
        text.contains(&transition_dismissed::path(tmp.path()).display().to_string()),
        "書く先を言っていない:\n{text}"
    );
    assert!(
        text.contains(transition_dismissed::NOTICE),
        "却下が何を変えないかを言っていない:\n{text}"
    );
    assert!(
        !text.contains(&policy_file::path(tmp.path()).display().to_string()),
        "書かない policy.json を明細に出している:\n{text}"
    );
    assert_eq!(modal.title, "この1件を書きますか？");
}

/// 宣言済みの行は却下できない。**何も起きない理由を言う**（`B-32`）。
#[test]
fn x_on_a_declared_row_says_why_nothing_happened() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = observed_tab_with(tmp.path(), &[("C:/git.exe", "git status")]);
    press(&mut app, KeyCode::Char(' '));
    confirm(&mut app);
    press(&mut app, KeyCode::Char('f')); // 却下済み
    press(&mut app, KeyCode::Char('f')); // 全部

    press(&mut app, KeyCode::Char('x'));
    assert!(app.pending.dismiss.is_empty());
    assert!(
        app.status.contains("宣言済み"),
        "理由を言っていない: {}",
        app.status
    );
}

/// 却下は**2つのタブで同じ印**を見る——同じ`(exe, argv)`は、承認でも同じ辺になるため。
#[test]
fn a_dismissal_in_the_observed_tab_also_covers_the_same_program_in_the_denied_tab() {
    use harness_policy::transition::TransitionDenial;
    use harness_sandbox::tier2a::spawnd::transitions::{pending_path, Denial, PendingRecord};
    use harness_sandbox::tier2a::spawnd::DenyReason;

    let tmp = tempfile::tempdir().unwrap();
    let denial = PendingRecord::DeniedByDaemon(Denial {
        from_domain: Some(ENTRY_DOMAIN.to_string()),
        exe: "C:/git.exe".to_string(),
        argv: "git status".to_string(),
        cwd: None,
        reason: DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge,
        },
        count: 1,
        first_ts: 1,
        last_ts: 1,
        argv_truncation: false,
    });
    let queue = pending_path(tmp.path());
    std::fs::create_dir_all(queue.parent().unwrap()).unwrap();
    std::fs::write(
        &queue,
        format!("{}\n", serde_json::to_string(&denial).unwrap()),
    )
    .unwrap();

    let mut app = observed_tab_with(tmp.path(), &[("C:/git.exe", "git status")]);
    press(&mut app, KeyCode::Char('x'));
    confirm(&mut app);

    app.cycle_pending_tab(false);
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsDenied);
    assert_eq!(app.pending.denied.len(), 1);
    assert!(
        app.pending.visible().is_empty(),
        "拒否のタブでは保留中に残っている"
    );
    assert_eq!(
        app.pending.counts(PendingTab::TransitionsDenied).dismissed,
        1
    );
}
