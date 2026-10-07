//! 確認ダイアログの`y`＝書いて留まる・`p`＝書いてパス2へ進む（P6.7。`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定68(3)と前例の(10)）の試験。
//!
//! 端末は要らない（状態は`App`、描画は`TestBackend`）。`p`を受けるのはファイルの確定（`Confirm::Approval`）と位置の確定
//! （`Confirm::Position`）だけで、残る4種では何もしない（ダイアログも閉じない）。ファイルの確定の`y`／`p`は`edit_tests`が持つ。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use harness_policy::policy_file::{self, ENTRY_DOMAIN};

use crate::position_view::position_view_tests::workspace;
use crate::session_dir::NetMode;
use crate::tui::edit::pass2_domains_tests::{open_pass2, press, select, CHILD};
use crate::tui::modal::PASS2_HINT;
use crate::tui::position_split::position_split_tests;
use crate::tui::state::{App, Confirm, Modal, Pass, Screen};

/// 描いた画面の文字を、空白を落として1つにつなぐ（`TestBackend`は全角1文字を2セル〔文字＋空白〕で持つ）。
fn screen(app: &App) -> String {
    screen_at(app, 160, 40)
}

fn screen_at(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| {
            crate::tui::draw(frame, app);
        })
        .expect("描画は落ちてはいけない");
    let buffer = terminal.backend().buffer();
    let text: String = (0..height)
        .flat_map(|y| (0..width).map(move |x| (x, y)))
        .map(|at| buffer[at].symbol().to_string())
        .collect();
    text.split_whitespace().collect()
}

/// 確認ダイアログ6種の全部と、`p`を受けるか（**表はここ1つ**。種類を足したら`offers_pass2`の`match`と一緒にここも直す）。
const KINDS: [(Confirm, bool); 6] = [
    (Confirm::ReadOnly, false),
    (Confirm::Approval, true),
    (Confirm::DeclaredChanges, false),
    (Confirm::Transition, false),
    (Confirm::DeclaredTransitions, false),
    (Confirm::Position, true),
];

fn with_dialog(ws: &std::path::Path, confirm: Confirm) -> App {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    app.modal = Some(Modal {
        title: "確かめる".to_string(),
        lines: vec!["中身".to_string()],
        confirm,
    });
    app
}

/// [決定68(3)] **位置の確定のダイアログでも`y`は書いて留まり、`p`は書いてパス2へ進む**（ファイルの確定と同じ意味。決定62）。
/// パス2の記録を確定した`p`は通信を強制するパス2を、パス1の記録なら記録するパス2を用意する（記録のパスで決める今の規則）。
/// コマンドと作業ディレクトリは開いている記録のマニフェストから。
#[test]
fn y_and_p_in_the_position_dialog() {
    let answer = |key: char| {
        let ws = workspace();
        let mut app = open_pass2(ws.path());
        select(&mut app, CHILD, "C:/b/child.txt");
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.modal.as_ref().map(|m| m.confirm), Some(Confirm::Position));
        press(&mut app, KeyCode::Char(key));
        assert!(app.modal.is_none());
        let file = policy_file::load(ws.path()).expect("policy.json");
        let child = file.domain(CHILD).expect("子").fs.read.clone();
        (app, ws, child)
    };

    let (stay, _ws, written) = answer('y');
    assert_eq!(written, vec!["C:/b/child.txt".to_string()]);
    assert_eq!(stay.screen, Screen::Edit, "y は留まる");
    assert_eq!(stay.pass, Pass::One);
    assert!(stay.status.contains("書きました"), "{}", stay.status);
    assert!(stay.status.contains(PASS2_HINT), "{}", stay.status);

    let (moved, ws, written) = answer('p');
    assert_eq!(written, vec!["C:/b/child.txt".to_string()], "p も同じ中身を書く");
    assert_eq!(moved.screen, Screen::Record, "p はパス2へ進む");
    assert_eq!(moved.pass, Pass::Two);
    assert_eq!(moved.net_mode, NetMode::Declared, "パス2の記録を承認した次は強制");
    assert_eq!(moved.command.text(), "powershell -c child");
    assert_eq!(moved.cwd.text(), ws.path().display().to_string());
    assert!(moved.status.contains("書きました"), "{}", moved.status);

    // パス1の位置の記録の`p`は、通信を記録するパス2を用意する。
    let ws = workspace();
    let mut app = position_split_tests::open(ws.path(), &position_split_tests::two_scripts());
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('a'));
    assert_eq!(
        app.modal.as_ref().map(|m| m.confirm),
        Some(Confirm::Position),
        "{}",
        app.status
    );
    press(&mut app, KeyCode::Char('p'));
    let file = policy_file::load(ws.path()).expect("policy.json");
    assert_eq!(
        file.domain(ENTRY_DOMAIN).expect("入口").process.transitions.len(),
        1
    );
    assert_eq!(
        (app.screen, app.pass, app.net_mode),
        (Screen::Record, Pass::Two, NetMode::RecordAll)
    );
}

/// **書けなかった`p`はパス2へ進まない**——ダイアログを見ている間に`policy.json`が壊れた（別の経路で書き換わった）と、
/// `p`は書く直前に作り直した確定で断られ、承認待ちの画面のまま理由を出す（書けていない宣言でパス2を始めさせない）。
/// 位置の確定とファイルの確定の両方で。
#[test]
fn p_after_a_write_that_fails_stays_on_the_screen() {
    // 位置の確定（パス2の分けた記録）。
    let ws = workspace();
    let mut app = open_pass2(ws.path());
    select(&mut app, CHILD, "C:/b/child.txt");
    press(&mut app, KeyCode::Char('a'));
    assert_eq!(app.modal.as_ref().map(|m| m.confirm), Some(Confirm::Position));
    std::fs::write(policy_file::path(ws.path()), "{ broken").expect("壊す");
    press(&mut app, KeyCode::Char('p'));
    assert!(app.modal.is_none());
    assert_eq!((app.screen, app.pass), (Screen::Edit, Pass::One), "{}", app.status);
    assert!(!app.status.contains(PASS2_HINT), "{}", app.status);

    // ファイルの確定（1つの一覧の記録＝記録の無いパス2。書く先はドメイン欄）。
    let ws = workspace();
    let (dir, _) = crate::position_candidates::position_candidates_tests::seed_pass2_record(ws.path(), "p2", None);
    crate::position_candidates::position_candidates_tests::write_fs_events(
        &dir,
        &[crate::position_candidates::position_candidates_tests::denial("C:/a/x.txt", Some(10))],
    );
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    app.edit_focus = crate::tui::state::EditField::Proposals;
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('a'));
    assert_eq!(app.modal.as_ref().map(|m| m.confirm), Some(Confirm::Approval), "{}", app.status);
    std::fs::create_dir_all(policy_file::path(ws.path()).parent().unwrap()).unwrap();
    std::fs::write(policy_file::path(ws.path()), "{ broken").expect("壊す");
    press(&mut app, KeyCode::Char('p'));
    assert!(app.modal.is_none());
    assert_eq!((app.screen, app.pass), (Screen::Edit, Pass::One), "{}", app.status);
}

/// **`p`を受けるのはファイルの確定と位置の確定だけ**——残る4種では`p`（`P`も）を押しても何も書かず、ダイアログも閉じない。
/// `Ctrl`・`Alt`付きの`p`は、受けるダイアログでも何もしない（BUG-212 の`y`と同じ）。
#[test]
fn p_does_nothing_in_the_other_dialogs() {
    for (kind, offers) in KINDS {
        assert_eq!(kind.offers_pass2(), offers, "{kind:?}");
        if offers {
            continue;
        }
        for code in [KeyCode::Char('p'), KeyCode::Char('P')] {
            let ws = workspace();
            let mut app = with_dialog(ws.path(), kind);
            press(&mut app, code);
            assert!(app.modal.is_some(), "{kind:?} で {code:?} がダイアログを閉じた");
            assert_eq!(app.screen, Screen::Record, "{kind:?}");
            assert_eq!(app.pass, Pass::One, "{kind:?} で {code:?} がパス2を用意した");
            assert!(
                !policy_file::path(ws.path()).exists(),
                "{kind:?} で何かを書いた"
            );
        }
    }
    for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
        let ws = workspace();
        let mut app = open_pass2(ws.path());
        select(&mut app, CHILD, "C:/b/child.txt");
        press(&mut app, KeyCode::Char('a'));
        app.on_key(KeyEvent::new(KeyCode::Char('p'), modifiers));
        assert!(app.modal.is_some(), "{modifiers:?}+p で閉じた");
        let file = policy_file::load(ws.path()).expect("policy.json");
        assert!(file.domain(CHILD).expect("子").fs.read.is_empty());
    }
}

/// **ボタンは`p`を受けるダイアログでだけ3つ**（`y=書いて留まる`・`p=書いてパス2へ`・`n / Esc=やめる`）。他の確認は今までどおり
/// `y=書く`・`n / Esc=やめる`、読むだけのダイアログは`Enter / Esc=閉じる`。
#[test]
fn the_dialog_shows_both_choices_only_where_it_offers_them() {
    for (kind, offers) in KINDS {
        let ws = workspace();
        let text = screen(&with_dialog(ws.path(), kind));
        let has = |label: &str| text.contains(&label.split_whitespace().collect::<String>());
        if offers {
            assert!(
                has("y=書いて留まる") && has("p=書いてパス2へ") && has("n / Esc=やめる"),
                "{kind:?}:\n{text}"
            );
            assert!(!has("y=書く"), "{kind:?}:\n{text}");
        } else if kind.asks() {
            assert!(has("y=書く") && has("n / Esc=やめる"), "{kind:?}:\n{text}");
            assert!(!has("p=") && !has("書いて留まる"), "{kind:?}:\n{text}");
        } else {
            assert!(has("Enter / Esc=閉じる"), "{kind:?}:\n{text}");
            assert!(!has("p="), "{kind:?}:\n{text}");
        }
    }
}

/// **ボタン3つのダイアログは、本文が収まらなくても3つとも押せて、何行目かを出す。** ボタン3つは52桁を取るので、88桁の枠では
/// 下辺の右の送り方の案内（`↑↓ PgUp/PgDn・ホイールで送る`）が収まらず「N〜M/T行」だけになる（限界。ボタン2つの確認は
/// 案内まで出る——対の側）。
#[test]
fn a_long_dialog_with_three_buttons_still_shows_every_button_and_the_line_position() {
    for (width, height) in [(80u16, 24u16), (120, 40)] {
        for (kind, offers) in [(Confirm::Approval, true), (Confirm::Transition, false)] {
            let ws = workspace();
            let mut app = with_dialog(ws.path(), kind);
            app.modal.as_mut().expect("ダイアログ").lines =
                (0..60).map(|i| format!("  + fs.read = C:/x/{i}")).collect();
            let text = screen_at(&app, width, height);
            let at = format!("{kind:?} {width}×{height}");
            assert!(text.contains("/60行"), "{at}: {text}");
            assert!(text.contains("n/Esc=やめる"), "{at}: {text}");
            if offers {
                assert!(
                    text.contains("y=書いて留まる") && text.contains("p=書いてパス2へ"),
                    "{at}: {text}"
                );
            } else {
                assert!(
                    text.contains("ホイールで送る"),
                    "ボタン2つの確認は送り方の案内まで出る {at}: {text}"
                );
            }
        }
    }
}
