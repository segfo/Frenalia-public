//! 位置の木の`u`（引数を固定してコマンドラインごとの行に分ける。決定67）の試験（P5.10.2）。
//!
//! 端末は要らない（状態は`App`、描画は`TestBackend`）。記録セッションは一時ディレクトリに作り、`process-audit.jsonl`と
//! `fs-audit.jsonl`を実際に書く（補助は`position_view_tests`・`position_candidates_tests`と共有する）。

use std::collections::BTreeSet;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::position_domains::PositionSource;
use harness_policy::process_event::{ArgvBinding, ArgvMissingReason, ProcessInstance};
use harness_policy::transition::ArgvMatcher;

use crate::position_candidates::position_candidates_tests::{fs_event, write_fs_events};
use crate::position_view::position_view_tests::{
    child, root, seed_position_record, with_command_line, workspace, CMD,
};
use crate::tui::state::App;
use crate::tui::transition::PendingTab;

pub(crate) const PYTHON: &str = "C:/Python312/python.exe";
pub(crate) const MV: &str = r"python C:\tools\mv.py C:\a\test.txt C:\a\test1.txt";
pub(crate) const REMOVE: &str = r"python C:\tools\remove.py C:\a\test1.txt";

pub(crate) fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

/// 決定67の発端の例: 入口（cmd）から同じ`python.exe`で`mv.py`（seq 2）と`remove.py`（seq 3）。
pub(crate) fn two_scripts() -> Vec<ProcessInstance> {
    vec![
        root(1, CMD),
        with_command_line(child(2, 1, PYTHON), MV),
        with_command_line(child(3, 1, PYTHON), REMOVE),
    ]
}

/// 記録を作り、`F2`で FS/ネットのタブ（候補を作る）、もう一度`F2`で「遷移・観測から」へ。
pub(crate) fn open(ws: &Path, instances: &[ProcessInstance]) -> App {
    let (dir, _) = seed_position_record(ws, "s1", instances);
    write_fs_events(
        &dir,
        &[
            fs_event("C:/a/root.txt", Some(1), CMD),
            fs_event("C:/a/test.txt", Some(2), PYTHON),
            fs_event("C:/a/test1.txt", Some(3), PYTHON),
            // 子の cmd（記録に居るときだけ。居なければ「記録の木に無い番号」として数えるだけ）。
            fs_event("C:/a/shared.txt", Some(4), CMD),
            fs_event("C:/a/shared.txt", Some(5), CMD),
        ],
    );
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsObserved);
    app
}

/// 見えている行の（遷移先, 書く辺の引数, 選んでいるか）。
pub(crate) fn rows(app: &App) -> Vec<(String, Option<String>, bool)> {
    let positions = app.pending.positions.as_ref().expect("位置の木");
    positions
        .visible()
        .into_iter()
        .map(|row| {
            let position = &positions.view.assignment.positions[row.position];
            (
                positions.destination_name(position).to_string(),
                position.fixed_command_line.clone(),
                positions.is_reserved(position),
            )
        })
        .collect()
}

/// 遷移先が`to`の行を選ぶ。
pub(crate) fn select_to(app: &mut App, to: &str) {
    let index = rows(app)
        .iter()
        .position(|(name, _, _)| name == to)
        .unwrap_or_else(|| panic!("{to} の行が無い: {:?}", rows(app)));
    app.pending.positions.as_mut().expect("位置の木").row = index;
}

/// ファイルの候補の（ドメイン, 値）。
fn candidates(app: &App) -> BTreeSet<(String, String)> {
    let view = app.view.as_ref().expect("候補");
    view.proposals
        .iter()
        .zip(&view.domains)
        .map(|(p, d)| (d.clone().unwrap_or_default(), p.value.clone()))
        .collect()
}

fn candidate_id(app: &App, domain: &str, value: &str) -> String {
    let view = app.view.as_ref().expect("候補");
    view.proposals
        .iter()
        .zip(&view.domains)
        .find(|(p, d)| d.as_deref() == Some(domain) && p.value == value)
        .map(|(p, _)| p.id.clone())
        .unwrap_or_else(|| panic!("候補が無い: [{domain}] {value}"))
}

fn screen(app: &App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(200, 40)).expect("test terminal");
    terminal
        .draw(|frame| {
            crate::tui::draw(frame, app);
        })
        .expect("描画は落ちてはいけない");
    let buffer = terminal.backend().buffer();
    (0..40)
        .map(|y| {
            (0..200)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// **`u`で選んだ位置をコマンドラインごとの行（それぞれ別のドメイン）に分け、もう一度で戻す**（決定67(1)）。分けた行は
/// 選んだまま・書く辺の引数は記録したコマンドラインのリテラル・名前はスクリプトの語幹。画面の行に固定した引数が出る。
#[test]
fn u_splits_a_script_runner_into_one_row_per_command_line_and_back() {
    let ws = workspace();
    let mut app = open(ws.path(), &two_scripts());
    assert_eq!(rows(&app), vec![("python".to_string(), None, false)]);

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    assert_eq!(
        rows(&app),
        vec![
            ("python-mv".to_string(), Some(MV.to_string()), true),
            ("python-remove".to_string(), Some(REMOVE.to_string()), true),
        ],
        "{}",
        app.status
    );
    assert!(app.status.contains("2行へ分けました"), "{}", app.status);
    let shown = screen(&app);
    assert!(shown.contains(r"python C:\tools\mv.py"), "{shown}");

    // 戻す（分けた行のどちらで押しても同じ位置へ戻る）。
    select_to(&mut app, "python-remove");
    press(&mut app, KeyCode::Char('u'));
    assert_eq!(
        rows(&app),
        vec![("python".to_string(), None, true)],
        "{}",
        app.status
    );
    assert!(
        app.status.contains("1行（任意の引数）へ戻しました"),
        "{}",
        app.status
    );
}

/// **欠けたコマンドラインが1つでもあれば分けない**（決定67(2)）。件数を言い、集合にも入れない。
/// `Space`で選ぶ前の`u`は理由を言うだけ（`o`と同じ前例）。
#[test]
fn u_refuses_a_position_with_a_missing_command_line_and_needs_a_selection() {
    let ws = workspace();
    let mut instances = two_scripts();
    instances.push(ProcessInstance {
        argv: ArgvBinding::Missing {
            reason: ArgvMissingReason::NoArgvObserved,
        },
        ..child(4, 1, PYTHON)
    });
    let mut app = open(ws.path(), &instances);
    press(&mut app, KeyCode::Char('u'));
    assert!(app.status.contains("先にSpace"), "{}", app.status);

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    assert!(app.status.contains("分けられません"), "{}", app.status);
    assert!(
        app.status.contains("引数が結び付かなかった起動 1回"),
        "{}",
        app.status
    );
    let positions = app.pending.positions.as_ref().unwrap();
    assert!(positions.split.is_empty());
    assert_eq!(rows(&app), vec![("python".to_string(), None, true)]);
}

/// **ファイルの候補も同じ集合で分ける**（決定67の検問2）——分けたドメインへ、そのドメインの起動が触った分だけ。
/// 予約は、名前とインスタンスが変わらなかったドメイン（入口）の分だけ引き継ぎ、分けたドメインの分は外して件数を言う。
/// 候補のドメインはどれも位置の木の遷移先か入口（辺の作らないドメインへ振り分けない）。
#[test]
fn the_file_candidates_follow_the_split_and_only_unchanged_domains_keep_their_selection() {
    let ws = workspace();
    let mut app = open(ws.path(), &two_scripts());
    let before = candidates(&app);
    assert!(before.contains(&("python".to_string(), "C:/a/test.txt".to_string())));
    assert!(before.contains(&("python".to_string(), "C:/a/test1.txt".to_string())));
    let entry = candidate_id(&app, ENTRY_DOMAIN, "C:/a/root.txt");
    let python = candidate_id(&app, "python", "C:/a/test.txt");
    app.accepted.insert(entry);
    app.accepted.insert(python);

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    let after = candidates(&app);
    assert!(after.contains(&("python-mv".to_string(), "C:/a/test.txt".to_string())));
    assert!(after.contains(&("python-remove".to_string(), "C:/a/test1.txt".to_string())));
    assert!(
        !after.contains(&("python-remove".to_string(), "C:/a/test.txt".to_string())),
        "remove.py のドメインに mv.py の書いたファイルが入ってはいけない"
    );
    assert!(
        !after.iter().any(|(d, _)| d == "python"),
        "分ける前のドメインは残らない"
    );
    let destinations: BTreeSet<String> = rows(&app).into_iter().map(|(to, _, _)| to).collect();
    for (domain, _) in &after {
        assert!(
            domain == ENTRY_DOMAIN || destinations.contains(domain),
            "候補のドメイン {domain} は位置の木の遷移先にも入口にも無い"
        );
    }
    // 予約: 入口の分は残り、分けたドメインの分は外れる。
    let kept: Vec<String> = app.accepted.iter().cloned().collect();
    assert_eq!(
        kept,
        vec![candidate_id(&app, ENTRY_DOMAIN, "C:/a/root.txt")]
    );
    assert!(
        app.status.contains("ファイルの候補の予約 1件を外しました"),
        "{}",
        app.status
    );

    // 記録を開き直しても（セッション一覧で Enter）、候補は位置の木と同じ集合で作る。
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::FsNet);
    app.edit_focus = crate::tui::state::EditField::Sessions;
    press(&mut app, KeyCode::Enter);
    assert!(candidates(&app).contains(&("python-mv".to_string(), "C:/a/test.txt".to_string())));
    assert!(!candidates(&app).iter().any(|(d, _)| d == "python"));

    // 戻すと候補も1つのドメインへ戻る。
    press(&mut app, KeyCode::F(2));
    select_to(&mut app, "python-mv");
    press(&mut app, KeyCode::Char('u'));
    assert!(candidates(&app).contains(&("python".to_string(), "C:/a/test1.txt".to_string())));
}

/// **名前が同じでもインスタンスが変わったドメインの予約は外す**（黙って別の起動の分へ付け替えない）。python の子の
/// cmd は、分ける前は mv.py と remove.py の両方の子（ドメイン cmd）だが、分けると mv.py の子が cmd、remove.py の子が
/// cmd-2 になる。分ける前に cmd で選んだ`shared.txt`は、同じ名前の cmd にも候補があるが、外す。
#[test]
fn a_same_name_domain_whose_launches_changed_drops_its_selection() {
    let ws = workspace();
    let mut instances = two_scripts();
    instances.push(with_command_line(
        child(4, 2, CMD),
        "cmd /c type C:\\a\\shared.txt",
    ));
    instances.push(with_command_line(
        child(5, 3, CMD),
        "cmd /c type C:\\a\\shared.txt",
    ));
    let mut app = open(ws.path(), &instances);
    let shared = candidate_id(&app, "cmd", "C:/a/shared.txt");
    app.accepted.insert(shared);
    select_to(&mut app, "python");
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    let after = candidates(&app);
    assert!(after.contains(&("cmd".to_string(), "C:/a/shared.txt".to_string())));
    assert!(after.contains(&("cmd-2".to_string(), "C:/a/shared.txt".to_string())));
    assert!(
        app.accepted.is_empty(),
        "インスタンスの変わった cmd の予約が残っている: {:?}",
        app.accepted
    );
    assert!(
        app.status.contains("ファイルの候補の予約 1件を外しました"),
        "{}",
        app.status
    );
}

/// **分けた行を確定すると、引数のリテラルの辺が書かれ、読み直すと既にある辺の行になる**（決定67(1)）。書かなかった
/// 分けた行は分けたまま（集合は確定の後も残る——ファイルの候補と食い違わないため）。
#[test]
fn committing_split_rows_writes_literal_edges_and_reloading_finds_them() {
    let ws = workspace();
    let mut app = open(ws.path(), &two_scripts());
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    // remove の行は選ばない（mv だけを書く）。
    select_to(&mut app, "python-remove");
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('a'));
    let dialog = app.modal.as_ref().expect("確認ダイアログ").lines.join("\n");
    assert!(dialog.contains(MV), "{dialog}");
    assert!(!dialog.contains("remove.py"), "{dialog}");
    press(&mut app, KeyCode::Char('y'));

    let file = policy_file::load(ws.path()).expect("読める");
    let entry = file.domain(ENTRY_DOMAIN).expect("入口");
    assert_eq!(
        entry.process.transitions.len(),
        1,
        "{:?}",
        entry.process.transitions
    );
    assert_eq!(
        entry.process.transitions[0].argv,
        ArgvMatcher::Literal(MV.to_string())
    );
    assert_eq!(entry.process.transitions[0].to, "python-mv");

    // 読み直した木: mv は既にある辺、remove は分けたまま（新規）。
    press(&mut app, KeyCode::Char('f'));
    let positions = app.pending.positions.as_ref().unwrap();
    let shape: Vec<(String, Option<String>, PositionSource)> = positions
        .view
        .assignment
        .positions
        .iter()
        .map(|p| (p.to_domain.clone(), p.fixed_command_line.clone(), p.source))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("python-mv".to_string(), None, PositionSource::ExistingEdge),
            (
                "python-remove".to_string(),
                Some(REMOVE.to_string()),
                PositionSource::Proposed
            ),
        ]
    );
    assert!(!positions.split.is_empty(), "書いた後も分ける集合は残る");
}
