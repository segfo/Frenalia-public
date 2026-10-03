//! 画面の文章をマウスで選んで写す試験（`tui::select`）。`pointer_tests`の子として置き、押す位置の探し方
//! （描いた画面のセルの文字から取る）を共有する。
//!
//! 製品の入口（`tui::handle_event_at`・`tui::tick`）へ座標付きのイベントを入れ、イベントのたびに描き直す
//! （イベントループと同じ）。写るはずの文章は**元の文章（確認ダイアログへ入れた行・出力へ流した行）から**作る。
//! 実物のクリップボードには書かない——写す文章は[`Action::Copy`]で受け取る。

use std::time::Instant;

use super::*;
use crate::tui::state::Modal;

/// 確認ダイアログ（書き込みの確認）を開いた承認待ちの画面。本文は`lines`。
fn with_modal(ws: &std::path::Path, lines: Vec<String>) -> App {
    let mut app = edit_screen_with_a_tree(ws);
    app.modal = Some(Modal {
        title: "承認の確認".to_string(),
        lines,
        confirm: Confirm::Approval,
    });
    app
}

/// 1つのイベントを時刻`now`で入れて、描き直す（イベントループと同じ）。
fn event_then_frame(
    app: &mut App,
    kind: MouseEventKind,
    at: (u16, u16),
    now: Instant,
) -> Option<Action> {
    let action = mouse_at(app, kind, at, now);
    frame(app, SIZE.0, SIZE.1);
    action
}

/// `from`で押し、`to`までずらして離す。
fn drag(app: &mut App, from: (u16, u16), to: (u16, u16)) {
    let now = Instant::now();
    event_then_frame(app, MouseEventKind::Down(MouseButton::Left), from, now);
    event_then_frame(app, MouseEventKind::Drag(MouseButton::Left), to, now);
    event_then_frame(app, MouseEventKind::Up(MouseButton::Left), to, now);
}

fn ctrl_c(app: &mut App) -> Option<Action> {
    handle_event(
        app,
        crossterm::event::Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
    )
}

fn copied(action: Option<Action>) -> Option<String> {
    match action {
        Some(Action::Copy(text)) => Some(text),
        _ => None,
    }
}

/// 折り返して3行以上になる1行（語は`word00`〜`word39`）。
fn long_line() -> String {
    (0..40)
        .map(|i| format!("word{i:02}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// **折り返して描いた1行は改行の入らない元の1行に戻り、複数行は`CRLF`でつながる。** 全角文字の右半分で離しても
/// 文字は割れない。枠線は入らない（確認ダイアログの本文）。
#[test]
fn a_wrapped_modal_line_is_copied_as_one_line_and_lines_join_with_crlf() {
    let ws = workspace();
    let long = long_line();
    let mut app = with_modal(
        ws.path(),
        vec!["first line".into(), long.clone(), "全角の行です".into()],
    );
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let body = modal_box(&grid, &app);
    let from = cell_of(&grid, Some(body), "word00", None);
    let to = cell_of(&grid, Some(body), "word39", None);
    assert!(to.1 >= from.1 + 2, "折り返していない（試験の前提）");
    drag(&mut app, from, (to.0 + 5, to.1));
    assert_eq!(copied(ctrl_c(&mut app)).as_deref(), Some(long.as_str()));
    assert!(app.modal.is_some(), "写しただけで確認ダイアログが閉じた");

    let first = cell_of(&grid, Some(body), "first", None);
    let wide = cell_of(&grid, Some(body), "角", None);
    drag(&mut app, first, (wide.0 + 1, wide.1));
    assert_eq!(
        copied(ctrl_c(&mut app)).as_deref(),
        Some(format!("first line\r\n{long}\r\n全角").as_str())
    );
}

/// **選んでいるときの`Ctrl+C`と右クリックは写して終了しない。選んでいないときの`Ctrl+C`は今までどおり終了**、
/// 右クリックは何もしない（許可側と禁止側の対）。
#[test]
fn ctrl_c_and_the_right_button_copy_only_while_something_is_selected() {
    let ws = workspace();
    let mut app = with_modal(ws.path(), vec!["alpha beta".into()]);
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let at = cell_of(&grid, Some(modal_box(&grid, &app)), "alpha", None);
    assert!(mouse(
        &mut app,
        MouseEventKind::Down(MouseButton::Right),
        at.0,
        at.1
    )
    .is_none());
    drag(&mut app, at, (at.0 + 4, at.1));
    assert_eq!(
        copied(mouse(
            &mut app,
            MouseEventKind::Down(MouseButton::Right),
            0,
            0
        ))
        .as_deref(),
        Some("alpha")
    );
    drag(&mut app, at, (at.0 + 4, at.1));
    assert_eq!(copied(ctrl_c(&mut app)).as_deref(), Some("alpha"));
    assert_eq!(
        action_kind(&ctrl_c(&mut app)),
        "終了",
        "選んでいない`Ctrl+C`が終了しない"
    );
}

/// **枠の下の外までずらすと送られ、押したときには見えていなかった行まで選べる。** ポインタを止めていても、
/// 時間が進めば送り続ける（`tui::tick`）。
#[test]
fn dragging_below_a_box_scrolls_it_and_selects_lines_that_were_off_screen() {
    let ws = workspace();
    let lines: Vec<String> = (0..80).map(|i| format!("row {i:02}")).collect();
    let mut app = with_modal(ws.path(), lines.clone());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let body = modal_box(&grid, &app);
    let screen: String = grid.iter().map(|row| row.concat()).collect();
    assert!(
        !screen.contains("row 79"),
        "試験の前提: 最後の行は見えていない"
    );
    let start = Instant::now();
    event_then_frame(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        cell_of(&grid, Some(body), "row 03", None),
        start,
    );
    event_then_frame(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        (body.x + 3, body.bottom() + 1),
        start,
    );
    assert!(app.modal_scroll > 0, "下の外へずらしたのに送られていない");
    for step in 1..=40u32 {
        tick(
            &mut app,
            start + harness_term::select::AUTO_SCROLL_EVERY * step,
        );
        frame(&mut app, SIZE.0, SIZE.1);
    }
    event_then_frame(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        (body.x + 3, body.bottom() + 1),
        start,
    );
    assert_eq!(
        copied(ctrl_c(&mut app)),
        Some(lines[3..].join("\r\n")),
        "最後の行まで選べていない"
    );
}

/// **記録中の出力を選んだ後に新しい出力が流れ込んでも、選んだ文章は変わらない。**
#[test]
fn the_selected_output_does_not_change_when_new_output_streams_in() {
    let ws = workspace();
    let mut app = running_record_screen(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let output = boxed(&grid, " コマンドの出力");
    let at = cell_of(&grid, Some(output), "Compiling", None);
    drag(&mut app, at, (at.0 + 21, at.1));
    for i in 0..60 {
        app.on_worker(WorkerMsg::Pass1(RecordEvent::Stdout(format!(
            "Compiling crate{i}\n"
        ))));
        frame(&mut app, SIZE.0, SIZE.1);
    }
    assert_eq!(
        copied(ctrl_c(&mut app)).as_deref(),
        Some("Compiling harness-core")
    );
    assert!(app.is_running(), "写しただけで記録が止まった");
}

/// **選んでいる間の`Esc`は選択を外すだけ**（確認ダイアログを閉じない。`Esc`の二度押しにも数えない）。
/// もう一度押せば今までどおり閉じる。
#[test]
fn escape_first_drops_the_selection() {
    let ws = workspace();
    let mut app = with_modal(ws.path(), vec!["alpha beta".into()]);
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let at = cell_of(&grid, Some(modal_box(&grid, &app)), "alpha", None);
    drag(&mut app, at, (at.0 + 4, at.1));
    press(&mut app, KeyCode::Esc);
    assert!(
        app.modal.is_some(),
        "選択を外す`Esc`で確認ダイアログが閉じた"
    );
    assert!(
        app.last_esc.is_none(),
        "選択を外す`Esc`を二度押しの1回目に数えた"
    );
    assert_eq!(action_kind(&ctrl_c(&mut app)), "終了", "選択が外れていない");
    let mut app = with_modal(ws.path(), vec!["alpha beta".into()]);
    frame(&mut app, SIZE.0, SIZE.1);
    press(&mut app, KeyCode::Esc);
    assert!(app.modal.is_none(), "選んでいない`Esc`で閉じない");
}

/// **ヘルプの文章は選べて、選んでいる間はヘルプが閉じない。** 写すとヘルプは開いたまま。
#[test]
fn the_help_can_be_selected_without_closing_it() {
    let ws = workspace();
    let mut app = edit_screen_with_a_tree(ws.path());
    press(&mut app, KeyCode::F(4));
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let at = cell_of(
        &grid,
        Some(boxed(&grid, " ヘルプ")),
        "harness-policy-editor",
        None,
    );
    drag(&mut app, at, (at.0 + 20, at.1));
    assert!(app.help, "ドラッグでヘルプが閉じた");
    assert_eq!(
        copied(ctrl_c(&mut app)).as_deref(),
        Some("harness-policy-editor")
    );
    assert!(app.help, "写しただけでヘルプが閉じた");
}

/// 写した結果は知らせの行に出る（書けなければ理由。黙って失敗しない）。キー案内の`Ctrl+C`は、写せる間だけ`コピー`。
#[test]
fn the_result_and_the_hint_follow_what_can_be_copied() {
    let ws = workspace();
    let mut app = with_modal(ws.path(), vec!["alpha beta".into()]);
    app.note_copied("ab\r\nc", Ok(()));
    assert_eq!(app.status, "4文字をコピーしました");
    app.note_copied(
        "abc",
        Err("ほかのアプリがクリップボードを使っています".into()),
    );
    assert!(
        app.status.starts_with("コピーできませんでした"),
        "{}",
        app.status
    );
    assert!(app.status.contains("ほかのアプリ"), "{}", app.status);

    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let keys: String = grid[usize::from(SIZE.1 - 1)].concat();
    assert!(squash(&keys).contains("Ctrl+C終了"), "{keys}");
    let at = cell_of(&grid, Some(modal_box(&grid, &app)), "alpha", None);
    drag(&mut app, at, (at.0 + 4, at.1));
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let keys: String = grid[usize::from(SIZE.1 - 1)].concat();
    assert!(squash(&keys).contains("Ctrl+Cコピー"), "{keys}");
}
