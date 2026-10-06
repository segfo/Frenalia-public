//! 位置の木の`s`（Strict）と`w`（作業ディレクトリ）の試験（決定67(3)〜(5)。P5.10.2）。
//!
//! 書けるかは判定器（規則(e)(i)(d)）に聞くので、禁止側は「呼び出し元が書ける場所（ワークスペース）にスクリプトを置く」
//! 「固定していない」形で作り、許可側は「書けない架空の場所（`C:\tools`）」で作る。

use crossterm::event::KeyCode;

use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::position_domains::PositionSource;
use harness_policy::transition::ArgvMatcher;

use crate::position_view::position_view_tests::{child, root, with_command_line, workspace, CMD};
use crate::position_view::EdgeVerdict;
use crate::tui::declared_transitions::ListedRow;
use crate::tui::position_split::position_split_tests::{
    open, press, rows, select_to, two_scripts, MV, PYTHON,
};
use crate::tui::text_input::TextInput;
use crate::tui::transition::PendingTab;

/// 選んでいる位置の（Strict か, 辺に書く作業ディレクトリ）。
fn strict_and_cwd(app: &crate::tui::state::App) -> (bool, Option<String>) {
    let positions = app.pending.positions.as_ref().unwrap();
    let index = positions.selected_index().expect("選んでいる行");
    let position = &positions.view.assignment.positions[index];
    (positions.is_strict(position), positions.edge_cwd(position))
}

/// 開いて`python`を選び、`u`で分けて`python-mv`の行を選んだところ。
fn split_and_select_mv(ws: &std::path::Path) -> crate::tui::state::App {
    let mut app = open(ws, &two_scripts());
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    select_to(&mut app, "python-mv");
    app
}

/// **許可側の一周**: 分けた行で`s`を押すと Strict になり、作業ディレクトリは候補（引数の絶対パスのスクリプトのフォルダ）。
/// 行に［Strict］と作業ディレクトリが出る。確定の明細に Strict の印・作業ディレクトリ・「移ってから呼ぶ」・スキーマ版3への
/// 上がりが出て、`y`で`strict: true`のドメインと、引数のリテラル・作業ディレクトリつきの辺を1回の保存で書く。読み直すと
/// その行は既にある辺になる（作業ディレクトリを宣言した辺を割り当てが引ける。P5.10.1）。
#[test]
fn s_makes_a_split_row_strict_and_the_commit_writes_the_mark_and_the_fixed_edge() {
    let ws = workspace();
    let mut app = split_and_select_mv(ws.path());
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(
        strict_and_cwd(&app),
        (true, Some(r"C:\tools".to_string())),
        "{}",
        app.status
    );
    assert!(app.status.contains("移ってから呼ぶ"), "{}", app.status);
    assert!(
        !app.status.contains("推定"),
        "絶対パスのスクリプトなので推定ではない: {}",
        app.status
    );

    press(&mut app, KeyCode::Char('a'));
    let dialog = app.modal.as_ref().expect("確認ダイアログ").lines.join("\n");
    for needle in [
        "Strict の印を付けるドメイン 1個",
        "python-mv",
        r"作業ディレクトリ C:\tools",
        "移ってから呼ぶ",
        "［Strict］",
        "スキーマ版が 1→3",
    ] {
        assert!(dialog.contains(needle), "{needle} が無い:\n{dialog}");
    }
    press(&mut app, KeyCode::Char('y'));

    let file = policy_file::load(ws.path()).expect("読める（検査に通った）");
    assert!(file.domain("python-mv").expect("遷移先").strict);
    assert!(
        !file.domain("python-remove").expect("遷移先").strict,
        "Strict にしていない行"
    );
    let edge = file
        .domain(ENTRY_DOMAIN)
        .expect("入口")
        .process
        .transitions
        .iter()
        .find(|e| e.to == "python-mv")
        .expect("python-mv への辺")
        .clone();
    assert_eq!(edge.argv, ArgvMatcher::Literal(MV.to_string()));
    assert_eq!(edge.cwd.as_deref(), Some(r"C:\tools"));

    press(&mut app, KeyCode::Char('f'));
    let positions = app.pending.positions.as_ref().unwrap();
    assert!(
        positions
            .view
            .assignment
            .positions
            .iter()
            .any(|p| p.to_domain == "python-mv" && p.source == PositionSource::ExistingEdge),
        "書いた Strict の辺が既にある辺として引けない: {:?} / {:?}",
        positions.view.assignment.positions,
        positions.view.notes
    );
    assert!(positions.view.assignment.unassigned.is_empty());
}

/// **禁止側**: 呼び出し元が書ける場所（ワークスペース）のスクリプトは、Strict にすると規則(i)に落ちるので Strict にせず
/// 判定器の理由を言う（エディタで写さない）。予約は残る。`w`で作業ディレクトリを書けない場所へ直しても、スクリプト
/// そのものが書けるので断られる（対: 書けない場所のスクリプトは通る＝上の試験）。
#[test]
fn s_refuses_a_script_the_caller_can_write_with_the_checkers_reason() {
    let ws = workspace();
    let script = ws.path().join("job.py");
    let line = format!("python {}", script.display());
    let mut app = open(
        ws.path(),
        &[root(1, CMD), with_command_line(child(2, 1, PYTHON), &line)],
    );
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    assert_eq!(
        rows(&app),
        vec![("python-job".to_string(), Some(line.clone()), true)]
    );

    press(&mut app, KeyCode::Char('s'));
    assert!(!strict_and_cwd(&app).0);
    assert!(app.status.contains("Strict にしません"), "{}", app.status);
    assert!(
        app.status.contains("can write"),
        "判定器の理由が出ていない: {}",
        app.status
    );
    assert!(rows(&app)[0].2, "予約は残す");

    press(&mut app, KeyCode::Char('w'));
    app.pending.positions.as_mut().unwrap().editing = Some(TextInput::new(r"C:\tools"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(strict_and_cwd(&app), (false, Some(r"C:\tools".to_string())));
    press(&mut app, KeyCode::Char('s'));
    assert!(
        !strict_and_cwd(&app).0,
        "スクリプトが書けるので Strict にできない"
    );
}

/// **相対パスのスクリプトの候補は推定**（決定67(3)）: 実行ファイルのフォルダを出し、行と状態に「推定」と添える。
/// `w`で宣言すると推定ではなくなる。空のまま`Enter`で宣言を外すと、Strict の行は候補へ戻る。
#[test]
fn a_relative_script_gets_an_estimated_cwd_that_w_can_replace_and_clear() {
    let ws = workspace();
    let mut app = open(
        ws.path(),
        &[
            root(1, CMD),
            with_command_line(child(2, 1, PYTHON), "python run.py"),
        ],
    );
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(
        strict_and_cwd(&app),
        (true, Some("C:/Python312".to_string())),
        "{}",
        app.status
    );
    assert!(app.status.contains("（推定）"), "{}", app.status);

    press(&mut app, KeyCode::Char('w'));
    let prefilled = app
        .pending
        .positions
        .as_ref()
        .unwrap()
        .editing
        .as_ref()
        .map(|i| i.text().to_string());
    assert_eq!(
        prefilled.as_deref(),
        Some("C:/Python312"),
        "欄は今の値（候補）で始まる"
    );
    assert!(app.status.contains("推定"), "{}", app.status);
    app.pending.positions.as_mut().unwrap().editing = Some(TextInput::new(r"C:\jobs"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        strict_and_cwd(&app),
        (true, Some(r"C:\jobs".to_string())),
        "{}",
        app.status
    );
    assert!(!app.pending.positions.as_ref().unwrap().editing_cwd);

    press(&mut app, KeyCode::Char('w'));
    app.pending.positions.as_mut().unwrap().editing = Some(TextInput::new(""));
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        strict_and_cwd(&app),
        (true, Some("C:/Python312".to_string()))
    );
    assert!(app.status.contains("候補"), "{}", app.status);

    // Strict をやめると、宣言していない行は作業ディレクトリを書かない（普通の辺は呼び出し元の場所を引き継ぐ）。
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(strict_and_cwd(&app), (false, None), "{}", app.status);
}

/// `s`・`w`は引数を固定した（分けた）行だけ。分けていない行・既にある辺の行では何もせず理由を言う。
/// 拒否のタブでは位置の木のキーだと言う（`o`の前例、`B-32`）。
#[test]
fn s_and_w_need_a_split_row_and_say_why_elsewhere() {
    let ws = workspace();
    let mut app = open(ws.path(), &two_scripts());
    press(&mut app, KeyCode::Char('s'));
    assert!(
        app.status.contains("u で引数を記録どおりに固定"),
        "{}",
        app.status
    );
    press(&mut app, KeyCode::Char('w'));
    assert!(
        app.status.contains("u で引数を記録どおりに固定"),
        "{}",
        app.status
    );
    let positions = app.pending.positions.as_ref().unwrap();
    assert!(positions.strict.is_empty() && positions.editing.is_none());

    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsDenied);
    press(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("位置の木"), "{}", app.status);
}

/// **宣言画面の`s`も、入る辺が位置の木の`s`で書いた Strict の辺なら通る**（決定67。判定器が「固定してあり、呼び出し元が
/// 書けない」と答える）。外して付け直せる。
#[test]
fn the_declared_screen_s_accepts_a_strict_edge_written_by_the_position_tree() {
    let ws = workspace();
    let mut app = split_and_select_mv(ws.path());
    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Char('y'));
    assert!(
        policy_file::load(ws.path())
            .unwrap()
            .domain("python-mv")
            .unwrap()
            .strict
    );

    press(&mut app, KeyCode::F(3));
    press(&mut app, KeyCode::F(3));
    let strict_of = |ws: &std::path::Path| {
        policy_file::load(ws)
            .unwrap()
            .domain("python-mv")
            .unwrap()
            .strict
    };
    for expected in [false, true] {
        let state = &app.declared_transitions;
        let target = state
            .rows()
            .iter()
            .position(
                |row| matches!(row, ListedRow::Domain(d) if state.domains[*d].name == "python-mv"),
            )
            .expect("python-mv の見出し");
        app.declared_transitions.row = target;
        press(&mut app, KeyCode::Char('s'));
        press(&mut app, KeyCode::Char('a'));
        press(&mut app, KeyCode::Char('y'));
        assert_eq!(strict_of(ws.path()), expected, "{}", app.status);
    }
}

/// 位置の行の判定は、Strict の印を当てた宣言で聞いている（判定器が Strict の行を「書ける」と答え、印を外すと広げる向きの
/// 判定に戻る）。Strict の辺は呼び出し元が子を通して使える権限に数えない（決定66の追記）ので、Strict の行は広げない。
#[test]
fn a_strict_row_is_judged_with_the_mark_applied() {
    let ws = workspace();
    let mut app = split_and_select_mv(ws.path());
    press(&mut app, KeyCode::Char('s'));
    let positions = app.pending.positions.as_ref().unwrap();
    let index = positions.selected_index().unwrap();
    assert_eq!(
        positions.verdicts[index],
        EdgeVerdict::Writable,
        "{:?}",
        positions.verdicts
    );
}
