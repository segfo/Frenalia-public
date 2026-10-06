//! 承認待ち（`F2`）の「遷移・観測から」を位置の木で見せる画面の試験（P4.3）。
//!
//! **端末は要らない**（描画は`TestBackend`で1フレーム描いてセルを読む）。記録セッションは一時ディレクトリに
//! 作り、`process-audit.jsonl`を実際に書く（補助は`position_view_tests`と共有する）。`F2`を2回押して
//! 観測のタブに入る——利用者と同じ道を通す（記録の一覧を読むのは FS/ネットのタブに入ったとき）。

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::process_event::ProcessInstance;
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

use crate::position_view::position_view_tests::{
    child, root, seed_position_record, seed_record, user_example, with_command_line, workspace,
    CALC, CMD, MSPAINT, PWSH,
};
use crate::position_view::{position_edges, EdgeVerdict, PositionKey};
use crate::tui::state::App;
use crate::tui::transition::PendingTab;

fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

/// `F2`で承認待ち（FS/ネット）に入り、もう一度`F2`で「遷移・観測から」へ。
fn open_observed_tab(ws: &Path) -> App {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsObserved);
    app
}

fn app_with_record(ws: &Path, instances: &[ProcessInstance]) -> App {
    seed_position_record(ws, "s1", instances);
    open_observed_tab(ws)
}

/// 見えている行の（字下げ, 実行ファイル, 遷移先）。
fn rows(app: &App) -> Vec<(usize, String, String)> {
    let positions = app.pending.positions.as_ref().expect("位置の木が出ている");
    positions
        .visible()
        .into_iter()
        .map(|row| {
            let position = &positions.view.assignment.positions[row.position];
            (
                row.depth,
                position.exe.clone(),
                positions.destination_name(position).to_string(),
            )
        })
        .collect()
}

fn key_of(app: &App, exe: &str) -> PositionKey {
    let positions = app.pending.positions.as_ref().expect("位置の木");
    let position = positions
        .view
        .assignment
        .positions
        .iter()
        .find(|p| p.exe == exe)
        .expect("その実行ファイルの位置");
    crate::position_view::key_of(position)
}

/// 見えている行の中で`exe`の行を選ぶ。
fn select(app: &mut App, exe: &str) {
    let index = rows(app)
        .iter()
        .position(|(_, e, _)| e == exe)
        .expect("その行が見えている");
    app.pending.positions.as_mut().expect("位置の木").row = index;
}

/// 描いた画面の行。**全角文字の後ろのセルは空白として読める**ので、比べる側は[`squash`]で空白を落とす。
fn screen(app: &App) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(160, 40)).expect("test terminal");
    terminal
        .draw(|frame| {
            crate::tui::draw(frame, app);
        })
        .expect("描画は落ちてはいけない");
    let buffer = terminal.backend().buffer();
    (0..40)
        .map(|y| {
            (0..160)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

/// 空白を落とす（全角文字の後ろのセルと、桁をそろえる空白を無視して比べるため）。
fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// **位置の情報がある記録は、位置の木で見せる**（決定65の困りごと2）。行は木の順・字下げは段数・遷移先と
/// 出どころと回数が出る。見出しにどの記録かを出す。
#[test]
fn a_position_record_is_shown_as_an_indented_tree_with_destinations() {
    let ws = workspace();
    let app = app_with_record(ws.path(), &user_example());

    assert_eq!(
        rows(&app),
        vec![
            (0, PWSH.to_string(), "pwsh".to_string()),
            (1, CALC.to_string(), "calc".to_string()),
            (1, MSPAINT.to_string(), "mspaint".to_string()),
        ]
    );

    let lines = screen(&app);
    assert!(
        lines
            .iter()
            .any(|l| squash(l).contains("位置ごとの遷移（記録:s1）")),
        "見出しに記録が出ていない:\n{}",
        lines.join("\n")
    );
    let pwsh = lines
        .iter()
        .find(|l| l.contains("pwsh.exe") && l.contains("[ ]"))
        .expect("pwsh の行");
    assert!(squash(pwsh).contains("2回→pwsh新規"), "{pwsh}");
    let calc = lines
        .iter()
        .find(|l| l.contains("calc.exe") && l.contains("[ ]"))
        .expect("calc の行");
    assert!(squash(calc).contains("→calc新規"), "{calc}");
    // 子の行は親の行より1段（2桁）深く字下げされる。
    let indent = |line: &str| line.find('[').expect("チェックの記号");
    assert_eq!(indent(calc), indent(pwsh) + 2, "{pwsh}\n{calc}");
}

/// ストアアプリの仕組みを通る綴りは、行に理由を出し、`Space`で予約できない（理由を言う、`B-32`）。
#[test]
fn a_store_app_position_says_why_it_cannot_start() {
    let ws = workspace();
    const STORE: &str =
        "C:/Program Files/WindowsApps/Microsoft.WindowsCalculator_11.0_x64/CalculatorApp.exe";
    let mut app = app_with_record(ws.path(), &[root(1, CMD), child(2, 1, STORE)]);

    let lines = screen(&app);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("CalculatorApp.exe") && squash(l).contains("起こせない")),
        "{}",
        lines.join("\n")
    );
    press(&mut app, KeyCode::Char(' '));
    assert!(app.pending.positions.as_ref().unwrap().approve.is_empty());
    assert!(app.status.contains("ストアアプリ"), "{}", app.status);
}

/// [P5.10.2] `u`は引数を記録どおりに固定して**コマンドラインごとの行に分ける**（決定67。P5.10 までは1通りのときだけ
/// 「絞る」だった）。相対パスの引数を固定した行は、作業ディレクトリが無いと検査に落ちる（規則(d)、DESIGN-MAC §5.1(5)。
/// 相対かどうかはエディタが判定しない＝`check_all`の文言をそのまま出す）——分けたうえで選ばず、理由を言う。前の`u`は
/// 「このエディタは作業ディレクトリを宣言しない」ので絞らずに断っていたが、`w`という直し方ができた: 作業ディレクトリを
/// 宣言すると書ける。対の側: 絶対パスだけの引数なら、分けた行は選んだまま。
#[test]
fn splitting_a_position_with_a_relative_argument_needs_a_cwd() {
    const TOOL: &str = "C:/x/tool.exe";
    const RELATIVE: &str = "\"C:/x/tool.exe\" ./input.txt";
    let ws = workspace();
    let relative = with_command_line(child(2, 1, TOOL), RELATIVE);
    let mut app = app_with_record(ws.path(), &[root(1, CMD), relative]);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    {
        let positions = app.pending.positions.as_ref().unwrap();
        let position = &positions.view.assignment.positions[0];
        assert_eq!(position.fixed_command_line.as_deref(), Some(RELATIVE));
        assert!(positions.approve.is_empty(), "検査に落ちる行は選ばない");
        assert!(
            matches!(&positions.verdicts[0], EdgeVerdict::Rejected { detail } if detail.contains("relative path")),
            "{:?}",
            positions.verdicts
        );
    }
    assert!(app.status.contains("検査に落ちる"), "{}", app.status);
    assert!(app.status.contains("w で作業ディレクトリ"), "{}", app.status);

    // `w`で作業ディレクトリ（候補は実行ファイルのフォルダ）を宣言すると書ける。
    press(&mut app, KeyCode::Char('w'));
    assert_eq!(
        app.pending.positions.as_ref().unwrap().editing.as_ref().map(|i| i.text().to_string()),
        Some("C:/x".to_string())
    );
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char(' '));
    let positions = app.pending.positions.as_ref().unwrap();
    assert!(positions.approve.contains(&key_of(&app, TOOL)), "{}", app.status);
    assert_eq!(positions.verdicts[0], EdgeVerdict::Writable);

    let ws = workspace();
    let absolute = with_command_line(child(2, 1, TOOL), "\"C:/x/tool.exe\" C:/x/input.txt");
    let mut app = app_with_record(ws.path(), &[root(1, CMD), absolute]);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    let positions = app.pending.positions.as_ref().unwrap();
    assert!(positions.view.assignment.positions[0].fixed_command_line.is_some());
    assert!(
        positions.approve.contains(&key_of(&app, TOOL)),
        "{}",
        app.status
    );
}

/// **位置の情報が無い記録は、観測のタブに注記だけを出す**（決定65の細目6。P4.8 で平らな候補の
/// 一覧は記録の側ごと消えたので、行は1つも出ない）。
/// 対の側: 位置の情報がある記録では木が出て、注記は出ない。
#[test]
fn an_old_record_without_process_audit_shows_only_a_note() {
    let ws = workspace();
    seed_record(ws.path(), "old");
    let app = open_observed_tab(ws.path());
    assert!(app.pending.positions.is_none());
    assert!(app.pending.visible().is_empty(), "行が出ている");
    assert!(
        app.pending
            .notes
            .iter()
            .any(|n| n.contains("この記録には位置の情報がありません")),
        "{:?}",
        app.pending.notes
    );

    let ws = workspace();
    let app = app_with_record(ws.path(), &user_example());
    assert!(app.pending.positions.is_some());
    assert!(!app
        .pending
        .notes
        .iter()
        .any(|n| n.contains("この記録には位置の情報がありません")));
}

/// **遷移先の欄は選んだ位置の遷移先を直す。名前を変えると、子の行の遷移元も一緒に変わる**（名前ごと置き換える）。
#[test]
fn the_destination_field_renames_the_selected_position_and_its_children_follow() {
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "ps");
    press(&mut app, KeyCode::Enter);

    let positions = app.pending.positions.as_ref().unwrap();
    assert!(positions.editing.is_none(), "Enter で欄から出る");
    assert_eq!(
        rows(&app),
        vec![
            (0, PWSH.to_string(), "ps".to_string()),
            (1, CALC.to_string(), "calc".to_string()),
            (1, MSPAINT.to_string(), "mspaint".to_string()),
        ],
        "{}",
        app.status
    );
    // 書く辺: pwsh の辺は ps へ、calc・mspaint の辺は ps から。
    let edges = position_edges(
        &positions.view.assignment,
        &positions.renamed,
        &positions.discard_output,
        &std::collections::BTreeMap::new(),
    );
    let edge_of = |exe: &str| {
        edges
            .iter()
            .find(|e| {
                e.edge.exe == harness_policy::transition::ExeMatcher::Literal(exe.to_string())
            })
            .expect("辺")
    };
    assert_eq!(edge_of(PWSH).edge.to, "ps");
    assert_eq!(edge_of(PWSH).from_domain, ENTRY_DOMAIN);
    assert_eq!(edge_of(CALC).from_domain, "ps");
    assert_eq!(edge_of(MSPAINT).from_domain, "ps");
}

/// 既にある辺の行は、遷移先の欄で名前を変えず理由を言う（遷移先は`policy.json`の辺が決めている）。
/// 呼び出し元と同じ名前は「凍結中（決定65）」で断る。
#[test]
fn an_existing_edge_cannot_be_renamed_and_a_self_loop_name_is_frozen() {
    let ws = workspace();
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(editor_edge(PWSH, ArgvMatcher::Any(AnyMarker), "pwsh"));
    file.domains.push(entry);
    file.domains.push(PolicyDomain::new("pwsh"));
    policy_file::save(ws.path(), &file).expect("保存");
    let mut app = app_with_record(ws.path(), &user_example());

    // 既にある辺の行は「書くもの」に入らないので、全部を出してから選ぶ。
    press(&mut app, KeyCode::Char('f'));
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Tab);
    assert!(app.pending.positions.as_ref().unwrap().editing.is_none());
    assert!(app.status.contains("既にある辺"), "{}", app.status);
    press(&mut app, KeyCode::Char(' '));
    assert!(app.pending.positions.as_ref().unwrap().approve.is_empty());
    assert!(app.status.contains("宣言済みです"), "{}", app.status);

    // calc の遷移元は pwsh。同じ名前は自己ループ辺になるので断る。
    select(&mut app, CALC);
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "pwsh");
    press(&mut app, KeyCode::Enter);
    assert!(app.pending.positions.as_ref().unwrap().renamed.is_empty());
    assert!(app.status.contains("凍結中"), "{}", app.status);
}

/// `Space`で書ける位置を予約し、**`a`で1つの確認ダイアログ（まだ書かない）、`y`で選んだ位置の辺を1回に書く**（P4.5）。
/// 遷移元の違う辺（`workspace-shell`から pwsh、pwsh から calc）も同じ確定に入る。`n`なら何も書かない。
/// `x`は位置の行では何もせず理由を言う（却下印は観測した`(exe, 引数)`ごと、P4.md 前例の表の10）。
#[test]
fn space_then_a_then_y_writes_the_position_edges_in_one_confirmation() {
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Char(' '));
    select(&mut app, CALC);
    press(&mut app, KeyCode::Char(' '));
    assert!(app
        .pending
        .positions
        .as_ref()
        .unwrap()
        .approve
        .contains(&key_of(&app, CALC)));

    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert_eq!(modal.confirm, crate::tui::state::Confirm::Position);
    for from in ["遷移元ドメイン workspace-shell", "遷移元ドメイン pwsh"] {
        assert!(modal.lines.iter().any(|l| l.contains(from)), "{from}: {:?}", modal.lines);
    }
    assert!(!policy_file::path(ws.path()).exists(), "ダイアログを出しただけで書いた");
    press(&mut app, KeyCode::Char('n'));
    assert!(!policy_file::path(ws.path()).exists(), "n で書いた");

    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Char('y'));
    let file = policy_file::load(ws.path()).expect("書いたはず");
    let to = |name: &str| -> Vec<String> {
        file.domain(name)
            .map(|d| d.process.transitions.iter().map(|e| e.to.clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(to(ENTRY_DOMAIN), vec!["pwsh".to_string()], "{}", app.status);
    assert_eq!(to("pwsh"), vec!["calc".to_string()]);
    assert!(app.pending.positions.as_ref().unwrap().approve.is_empty(), "書いた予約が残っている");

    press(&mut app, KeyCode::Char('x'));
    assert!(app.status.contains("却下"), "{}", app.status);
    assert_eq!(app.pending.dismiss.len(), 0);
}

/// **エディタが前に書いた自己ループ辺は、確認ダイアログに置き換えを出し、`y`のときだけ置き換える**（決定65 Q7・D-42）。
/// `n`なら`policy.json`は1バイトも変わらない。`y`で自己ループ辺が消えて位置の辺だけが残る。
#[test]
fn a_self_loop_replacement_is_shown_in_the_dialog_and_written_only_on_y() {
    let ws = workspace();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(editor_edge(PWSH, ArgvMatcher::Any(AnyMarker), ENTRY_DOMAIN));
    let mut file = PolicyFile::default();
    file.domains.push(entry);
    policy_file::save(ws.path(), &file).expect("手で書いた自己ループ辺");
    let before = std::fs::read(policy_file::path(ws.path())).unwrap();

    let mut app = app_with_record(ws.path(), &[root(1, CMD), child(2, 1, PWSH)]);
    select(&mut app, PWSH);
    let destination = {
        let positions = app.pending.positions.as_ref().unwrap();
        let position = positions
            .view
            .assignment
            .positions
            .iter()
            .find(|p| p.exe == PWSH)
            .unwrap();
        assert_eq!(
            position.source,
            harness_policy::position_domains::PositionSource::ReplacesSelfLoop
        );
        positions.destination_name(position).to_string()
    };
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert!(
        modal.lines.iter().any(|l| l.contains("置き換える自己ループ辺")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("workspace-shell の")
            && l.contains("pwsh.exe")
            && l.contains("→ workspace-shell")),
        "{:?}",
        modal.lines
    );
    press(&mut app, KeyCode::Char('n'));
    assert_eq!(std::fs::read(policy_file::path(ws.path())).unwrap(), before);

    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Char('y'));
    let file = policy_file::load(ws.path()).expect("load");
    let edges = &file.domain(ENTRY_DOMAIN).unwrap().process.transitions;
    assert_eq!(edges.len(), 1, "{edges:?} / {}", app.status);
    assert_eq!(edges[0].to, destination);
}

/// 1フレーム描いて描画で分かったこと（押せる場所）を状態へ書き戻し、行ごとの文字列を返す（`tui::run`と同じ）。
fn frame(app: &mut App) -> Vec<String> {
    let mut feedback = crate::tui::DrawFeedback::default();
    let mut terminal = Terminal::new(TestBackend::new(160, 40)).expect("test terminal");
    terminal
        .draw(|f| feedback = crate::tui::draw(f, app))
        .expect("描画は落ちてはいけない");
    let buffer = terminal.backend().buffer();
    let lines = (0..40)
        .map(|y| {
            (0..160)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();
    app.apply_draw_feedback(feedback);
    lines
}

/// `exe`の行のチェックの記号の位置（記号の前は枠線と空白だけなので、文字の位置＝桁）。
fn mark_cell(lines: &[String], exe: &str) -> (u16, u16) {
    let (y, line) = lines
        .iter()
        .enumerate()
        .find(|(_, l)| l.contains(exe) && l.contains("[ ]"))
        .expect("その行が描かれている");
    let x = line.chars().position(|c| c == '[').expect("チェックの記号");
    (x as u16, y as u16)
}

fn click(app: &mut App, (column, row): (u16, u16)) {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let now = std::time::Instant::now();
    for kind in [
        MouseEventKind::Down(MouseButton::Left),
        MouseEventKind::Up(MouseButton::Left),
    ] {
        app.on_mouse(
            MouseEvent {
                kind,
                column,
                row,
                modifiers: KeyModifiers::NONE,
            },
            now,
        );
    }
}

/// 位置の行を押すとその行が選ばれ、`[ ]`を押すと`Space`と同じ（`tui::pointer`の`ListId::Positions`）。
#[test]
fn clicking_a_position_row_and_its_mark_does_what_the_keys_do() {
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    let lines = frame(&mut app);
    let (x, y) = mark_cell(&lines, "mspaint.exe");
    click(&mut app, (x + 6, y));
    let positions = app.pending.positions.as_ref().unwrap();
    assert_eq!(positions.row, 2, "押した行が選ばれていない");
    assert!(positions.approve.is_empty(), "行を押しただけで予約した");

    let lines = frame(&mut app);
    click(&mut app, mark_cell(&lines, "calc.exe"));
    let positions = app.pending.positions.as_ref().unwrap();
    assert_eq!(positions.row, 1);
    assert!(
        positions.approve.contains(&key_of(&app, CALC)),
        "{}",
        app.status
    );
}

/// **子が親の持たないファイルを触る位置は広げる遷移として書ける**（決定66。決定65(6) の暫定「P5 まで書けない」を
/// 外した）。FS/ネットのタブで子のドメインの候補（`C:/secret/x`）を選ぶと、観測のタブのその位置は判定器が広げると
/// 答え、行と説明欄が「呼び出し元が子を通して使えるようになる権限」を言い、`Space`で予約できる（予約の文言も同じことを
/// 言う）。対の側: 選ぶ前は狭める向きで、行に「広げる」は出ない。
#[test]
fn a_widening_position_can_be_reserved_and_says_what_it_hands_over() {
    use crate::position_candidates::position_candidates_tests::{fs_event, write_fs_events};
    let ws = workspace();
    let (dir, _) = seed_position_record(ws.path(), "s1", &[root(1, CMD), child(2, 1, CALC)]);
    write_fs_events(
        &dir,
        &[
            fs_event("C:/a/x", Some(1), CMD),
            fs_event("C:/secret/x", Some(2), CALC),
        ],
    );

    // 対の側（選ぶ前）: 書ける見込みで、広げない。
    let mut app = open_observed_tab(ws.path());
    assert!(
        !screen(&app).iter().any(|l| squash(l).contains("広げる")),
        "{}",
        screen(&app).join("\n")
    );
    press(&mut app, KeyCode::Char(' '));
    assert!(
        app.pending
            .positions
            .as_ref()
            .unwrap()
            .approve
            .contains(&key_of(&app, CALC)),
        "{}",
        app.status
    );

    // FS/ネットのタブで calc のドメインの候補を選んでから、観測のタブへ戻る。
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    let view = app.view.as_ref().expect("候補");
    let id = view
        .proposals
        .iter()
        .zip(&view.domains)
        .find(|(p, d)| p.value == "C:/secret/x" && d.as_deref() == Some("calc"))
        .map(|(p, _)| p.id.clone())
        .expect("calc のドメインの候補");
    app.accepted.insert(id); // FS/ネットのタブの Space と同じ集合
    press(&mut app, KeyCode::F(2));
    let positions = app.pending.positions.as_ref().unwrap();
    let calc = positions
        .view
        .assignment
        .positions
        .iter()
        .position(|p| p.exe == CALC)
        .unwrap();
    assert!(
        matches!(
            positions.verdicts[calc],
            crate::position_view::EdgeVerdict::Widens { .. }
        ),
        "{:?}",
        positions.verdicts
    );
    let lines = screen(&app);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("calc.exe") && squash(l).contains("広げる")),
        "{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| squash(l).contains("P5まで")),
        "{}",
        lines.join("\n")
    );
    // 説明欄（選んでいる位置）に、子を通して使えるようになる権限そのものが出る。
    select(&mut app, CALC);
    let lines = screen(&app);
    assert!(
        lines.iter().any(|l| squash(l).contains("C:/secret/x")),
        "{}",
        lines.join("\n")
    );
    press(&mut app, KeyCode::Char(' '));
    assert!(
        app.pending
            .positions
            .as_ref()
            .unwrap()
            .approve
            .contains(&key_of(&app, CALC)),
        "{}",
        app.status
    );
    assert!(app.status.contains("広げる"), "{}", app.status);
}

/// **位置ごとのドメインの記録では、「遷移・拒否から」のタブの`a`も、位置の辺と拒否からの予約を1つの確定にまとめる**
/// （承認待ちのどのタブで`a`を押しても、別のタブの予約を黙って残さない。`B-32`）。拒否からの予約の遷移先は
/// 平らな一覧の遷移先の欄、遷移元は P4.6 までは入口のドメイン。
#[test]
fn a_on_the_denied_tab_of_a_position_record_writes_positions_and_denials_together() {
    use harness_policy::transition::TransitionDenial;
    use harness_sandbox::tier2a::spawnd::transitions::{pending_path, Denial, PendingRecord};
    use harness_sandbox::tier2a::spawnd::DenyReason;

    let ws = workspace();
    let denial = PendingRecord::DeniedByDaemon(Denial {
        from_domain: Some(ENTRY_DOMAIN.to_string()),
        exe: "C:/Users/x/tools/hostname.exe".to_string(),
        argv: "hostname".to_string(),
        cwd: None,
        reason: DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge,
        },
        count: 1,
        first_ts: 1,
        last_ts: 1,
        argv_truncation: false,
    });
    let queue = pending_path(ws.path());
    std::fs::create_dir_all(queue.parent().unwrap()).unwrap();
    std::fs::write(&queue, format!("{}\n", serde_json::to_string(&denial).unwrap())).unwrap();

    let mut app = app_with_record(ws.path(), &[root(1, CMD), child(2, 1, PWSH)]);
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsDenied);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Tab);
    type_text(&mut app, "hn");
    press(&mut app, KeyCode::Enter);

    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert_eq!(modal.confirm, crate::tui::state::Confirm::Position, "{:?}", modal.lines);
    assert!(
        modal.lines.iter().any(|l| l.contains("hostname.exe") && l.contains("→ hn")),
        "{:?}",
        modal.lines
    );
    press(&mut app, KeyCode::Char('y'));
    let file = policy_file::load(ws.path()).expect("書いたはず");
    let mut to: Vec<String> = file
        .domain(ENTRY_DOMAIN)
        .unwrap()
        .process
        .transitions
        .iter()
        .map(|e| e.to.clone())
        .collect();
    to.sort();
    assert_eq!(to, vec!["hn".to_string(), "pwsh".to_string()], "{}", app.status);
    assert!(app.pending.approve.is_empty(), "拒否からの予約が残っている");
}

/// [P5.5] **`o`で選んだ位置の子の出力を捨てる設定にし、確定でその辺だけが`"output":"discard"`で書かれる**（決定66(4)）。
///
/// - 選んでいない行の`o`は何もせず理由を言う（`u`と同じ。出力の設定は書く辺の形なので、書かない行には持てない）
/// - 行に「出力:捨てる」が出て、確認の明細の辺にも出る。**捨てる辺を書くと`policy.json`の版が3へ上がり、古い
///   `harness.exe`は読込で断る**——確認の明細でそれを言う
/// - 対（`B-35`）: 同じ確定の`o`を押していない位置の辺は既定の「返す」で書かれる
#[test]
fn o_discards_the_output_of_the_selected_position_and_only_that_edge_is_written_so() {
    use harness_policy::transition::ChildOutput;
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Char('o'));
    assert!(app.status.contains("先にSpace"), "{}", app.status);
    assert!(app.pending.positions.as_ref().unwrap().discard_output.is_empty());

    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('o'));
    assert!(app.status.contains("出力を捨て"), "{}", app.status);
    assert!(app
        .pending
        .positions
        .as_ref()
        .unwrap()
        .discard_output
        .contains(&key_of(&app, PWSH)));
    let drawn = screen(&app);
    let row = drawn
        .iter()
        .find(|line| line.contains("pwsh.exe") && squash(line).contains("新規"))
        .expect("pwsh の行");
    assert!(squash(row).contains("出力:捨てる"), "{row}");
    let calc_row = drawn
        .iter()
        .find(|line| line.contains("calc.exe") && squash(line).contains("新規"))
        .expect("calc の行");
    assert!(!squash(calc_row).contains("出力:捨てる"), "{calc_row}");

    select(&mut app, CALC);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert!(
        modal
            .lines
            .iter()
            .any(|l| l.contains("pwsh.exe") && l.contains("子の出力を捨てる")),
        "{:?}",
        modal.lines
    );
    assert!(
        !modal
            .lines
            .iter()
            .any(|l| l.contains("calc.exe") && l.contains("子の出力を捨てる")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal
            .lines
            .iter()
            .any(|l| l.contains("スキーマ版") && l.contains("harness.exe")),
        "版3へ上がることを言っていない: {:?}",
        modal.lines
    );
    press(&mut app, KeyCode::Char('y'));
    let file = policy_file::load(ws.path()).expect("書いたはず");
    let output_to = |from: &str, to: &str| {
        file.domain(from)
            .and_then(|d| d.process.transitions.iter().find(|e| e.to == to))
            .map(|e| e.output)
            .expect("その辺がある")
    };
    assert_eq!(output_to(ENTRY_DOMAIN, "pwsh"), ChildOutput::Discard, "{}", app.status);
    assert_eq!(output_to("pwsh", "calc"), ChildOutput::Return);
    assert_eq!(file.schema_version, 3);
    assert!(
        app.pending.positions.as_ref().unwrap().discard_output.is_empty(),
        "書いた設定が残っている"
    );
}

/// [P5.5] **`o`をもう一度押すと返す設定へ戻り、選ぶのをやめると捨てる設定も落ちる**（書かない行に設定を残さない）。
#[test]
fn o_toggles_back_and_unreserving_a_position_drops_its_output_setting() {
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    select(&mut app, PWSH);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::Char('o'));
    assert!(app.status.contains("出力を返し"), "{}", app.status);
    assert!(app.pending.positions.as_ref().unwrap().discard_output.is_empty());

    press(&mut app, KeyCode::Char('o'));
    press(&mut app, KeyCode::Char(' '));
    assert!(app.pending.positions.as_ref().unwrap().approve.is_empty());
    assert!(
        app.pending.positions.as_ref().unwrap().discard_output.is_empty(),
        "選ぶのをやめた位置に出力の設定が残っている"
    );
}

/// [P5.5] **拒否からのタブの`o`は何もせず理由を言う**（出力の切り替えは位置の木だけ。`B-32`）。
#[test]
fn o_on_the_denied_tab_says_it_works_only_in_the_position_tree() {
    let ws = workspace();
    let mut app = app_with_record(ws.path(), &user_example());
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.pending.tab.0, PendingTab::TransitionsDenied);
    press(&mut app, KeyCode::Char('o'));
    assert!(app.status.contains("位置の木"), "{}", app.status);
}
