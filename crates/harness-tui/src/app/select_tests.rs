//! 画面の文章をマウスで選んで写す試験（`app::select`）。
//!
//! 親（`pointer_tests`）と同じく**製品の入口を通す**——画面は製品の描画で描いて書き戻し、マウスとキーは
//! [`AppState::handle_event`]（時刻を渡すときは`handle_event_at`）へ入れる。押す位置は**描いた画面のセルの文字から**取り、
//! 写るはずの文章は**元の文章（transcriptへ入れた文字列）から**作る（当たり判定と同じ計算で期待値を作らない）。
//! イベントのたびに描き直す（製品のイベントループと同じ）。実物のクリップボードには書かない——写す文章は
//! [`Action::Copy`]で受け取る。

use super::*;
use crate::app::ToolCardStatus;

/// 1つのイベントを入れて、製品のループと同じく描き直す。
fn event_then_draw(app: &mut AppState, kind: MouseEventKind, at: (u16, u16), now: Instant) -> Step {
    let step = mouse_at(app, kind, at, now);
    draw(app);
    step
}

/// `from`で押し、`to`までずらして離す（各イベントの後に描き直す）。
fn drag(app: &mut AppState, from: (u16, u16), to: (u16, u16)) {
    let now = Instant::now();
    for (kind, at) in [
        (MouseEventKind::Down(MouseButton::Left), from),
        (MouseEventKind::Drag(MouseButton::Left), to),
        (MouseEventKind::Up(MouseButton::Left), to),
    ] {
        event_then_draw(app, kind, at, now);
    }
}

/// `Ctrl+C`を押して、写す文章が返ればそれを返す（返らなければ`None`。そのときは別の操作が起きている）。
fn ctrl_c(app: &mut AppState) -> (Option<String>, String) {
    let action = press_key(
        app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    match action {
        Some(Action::Copy(text)) => (Some(text), String::new()),
        other => (None, shown(&other)),
    }
}

fn app_with_items(items: &[&str]) -> AppState {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for item in items {
        app.transcript
            .push(TranscriptItem::Assistant((*item).to_string()));
    }
    app
}

/// 折り返して3行以上になる1行（語は`word00`〜`word39`）。
fn long_line() -> String {
    (0..40)
        .map(|i| format!("word{i:02}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// (a) **折り返して描いた1行を選んで写すと、改行の入らない元の1行が書かれる。** 枠線・スクロールバーは入らない。
#[test]
fn a_wrapped_line_is_copied_back_as_the_one_original_line() {
    let long = long_line();
    let mut app = app_with_items(&["before", &long, "after"]);
    let screen = draw(&mut app);
    let (first_x, first_y) = screen.find("word00");
    let (last_x, last_y) = screen.find("word39");
    assert!(last_y >= first_y + 2, "折り返していない（試験の前提）");
    drag(&mut app, (first_x, first_y), (last_x + 5, last_y));
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some(long.as_str()));
    let copied = copied.unwrap_or_default();
    assert!(!copied.contains('│') && !copied.contains('█') && !copied.contains('\n'));
}

/// (b) **複数行は`CRLF`でつながり、全角文字の右半分から選んでも文字は割れない。**
#[test]
fn several_lines_join_with_crlf_and_wide_characters_stay_whole() {
    let mut app = app_with_items(&["日本語の行その一", "二行目も全角です"]);
    let screen = draw(&mut app);
    let (x, y) = screen.find("本");
    let to = screen.find("目");
    // 「本」の右半分（全角の2桁目）で押す。
    drag(&mut app, (x + 1, y), (to.0 + 1, to.1));
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("本語の行その一\r\n二行目"));
}

/// (c) **枠の下端を越えてずらすと送られ、押したときには画面の外だった行まで選べる。** ポインタを止めていても
/// 時間が進めば送り続ける（描画の合図`tick`）。
#[test]
fn dragging_past_the_bottom_scrolls_and_selects_lines_that_were_off_screen() {
    let mut app = app_with_transcript(100);
    app.scroll_lines(15);
    let before = draw(&mut app);
    assert!(
        before.try_find("transcript line 90").is_none(),
        "試験の前提: 90行目は画面の外"
    );
    let from = before.find("transcript line 70");
    let start = Instant::now();
    event_then_draw(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        from,
        start,
    );
    // 画面の一番下（入力欄の下辺）までずらす＝transcriptの枠の下の外。
    event_then_draw(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        (10, HEIGHT - 1),
        start,
    );
    assert_eq!(
        app.scroll_offset(),
        12,
        "下の外へずらしたのに送られていない"
    );
    for step in 1..=4u32 {
        app.tick_at(start + harness_term::select::AUTO_SCROLL_EVERY * step);
        draw(&mut app);
    }
    assert_eq!(app.scroll_offset(), 0, "止めている間に送り続けていない");
    event_then_draw(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        (10, HEIGHT - 1),
        start,
    );
    let (copied, _) = ctrl_c(&mut app);
    let copied = copied.expect("選んだ文章が写る");
    let want: Vec<String> = (70..100).map(|i| format!("transcript line {i}")).collect();
    assert_eq!(copied, want.join("\r\n"));
}

/// (d) **選んでいるときの`Ctrl+C`は写して終了しない。選んでいないときは今までどおり終了する。** 右クリックも同じく、
/// 選んでいるときだけ写す（選んでいないときは何もしない）。
#[test]
fn ctrl_c_and_the_right_button_copy_only_while_something_is_selected() {
    let mut app = app_with_transcript(5);
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 2");
    drag(&mut app, (x, y), (x + 9, y));
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("transcript"), "{other}");
    assert!(!app.should_quit, "写したのに終了した");
    // 写したら選択は外れるので、次の`Ctrl+C`は終了（禁止側と許可側の対）。
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(copied, None);
    assert_eq!(other, shown(&Some(Action::Quit)));
    assert!(app.should_quit);

    let mut app = app_with_transcript(5);
    let screen = draw(&mut app);
    let right = MouseEventKind::Down(MouseButton::Right);
    assert!(
        matches!(
            mouse(&mut app, right, screen.find("line 1")),
            Step::Unchanged
        ),
        "選んでいない右クリックで何か起きた"
    );
    let (x, y) = screen.find("transcript line 3");
    drag(&mut app, (x, y), (x + 16, y));
    match mouse(&mut app, right, (1, 1)) {
        Step::Handled(Some(Action::Copy(text))) => assert_eq!(text, "transcript line 3"),
        other => panic!("右クリックで写さなかった: {other:?}"),
    }
    assert!(!app.should_quit);
}

/// (e) **ずらさずに離したクリックは今までどおりに働き、選択を作らない。** ボタンや押せる行の上で押してずらしても
/// 選び始めない（押した瞬間のクリックは起きる）。
#[test]
fn a_click_or_a_drag_from_a_button_selects_nothing() {
    let mut app = app_with_transcript(100);
    app.scroll_lines(5);
    let screen = draw(&mut app);
    let at = screen.find("transcript line 80");
    drag(&mut app, at, at);
    assert!(!app.has_copyable_selection(), "クリックで選択ができた");
    // さかのぼり中の案内（押すと最新へ）は押した瞬間に働き、そこからずらしても選ばない。
    drag(&mut app, screen.find("[5"), at);
    assert_eq!(app.scroll_offset(), 0, "案内のクリックが働いていない");
    assert!(!app.has_copyable_selection(), "押せる場所から選び始めた");

    // 承認ダイアログの候補の行も押せる場所。
    let mut app = pending_app(5);
    press(&mut app, KeyCode::Char('a'));
    let screen = draw(&mut app);
    let candidate = screen.find("[ ] [2] 5");
    let cursor_before = approval_state(&app);
    drag(&mut app, candidate, screen.find("承認が必要です"));
    assert_ne!(
        approval_state(&app),
        cursor_before,
        "候補のクリックが働いていない"
    );
    assert!(!app.has_copyable_selection());
}

/// (f) **選んだ後に応答が流れ込んでも、選んだ文章は変わらない**（色も同じ文章に付いたまま）。
#[test]
fn text_streaming_in_does_not_change_what_was_selected() {
    let mut app = app_with_transcript(10);
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 4");
    let to = screen.find("transcript line 6");
    drag(&mut app, (x, y), (to.0 + 16, to.1));
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    for i in 0..15 {
        app.apply(AgentEvent::TextDelta {
            text: format!("streamed {i}\n"),
        });
        draw(&mut app);
    }
    let screen = draw(&mut app);
    // 末尾に貼り付いているので文章は上へ動いた。色は動いた先の同じ文章に付いている。
    let (sx, sy) = screen.find("transcript line 5");
    assert_ne!(sy, y + 1, "試験の前提: 表示が動いていない");
    assert_eq!(
        screen.style((sx, sy)).bg,
        Some(Color::Blue),
        "色が文章から外れた"
    );
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(
        copied.as_deref(),
        Some("transcript line 4\r\ntranscript line 5\r\ntranscript line 6")
    );
}

/// **選んだ範囲の文章が変わったら選択を外す**（違う文章を写さない）。折り畳みを切り替えると同じ位置に別の文章が来る。
#[test]
fn a_selection_whose_text_changed_is_dropped_instead_of_copying_something_else() {
    let mut app = app_with_transcript(2);
    app.transcript.push(TranscriptItem::ToolCard {
        id: "t1".into(),
        name: "run_shell".into(),
        input: "{}".into(),
        status: ToolCardStatus::Done {
            is_error: false,
            output: "out1\nout2\nout3".into(),
        },
    });
    app.transcript
        .push(TranscriptItem::Assistant("after the tool".into()));
    let screen = draw(&mut app);
    let (x, y) = screen.find("after the tool");
    drag(&mut app, (x, y), (x + 13, y));
    assert!(app.has_copyable_selection());
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
    );
    draw(&mut app);
    assert!(
        !app.has_copyable_selection(),
        "文章が変わったのに選択が残った"
    );
}

/// (g) **入力欄にキーボードの選択があるときの`Ctrl+C`は、入力欄の選択を写す**（終了しない）。見出しの案内も、
/// 写せる間だけ`Ctrl-C=コピー`。写したら選択は外れて`Ctrl-C=終了`に戻る。
#[test]
fn ctrl_c_copies_the_input_selection() {
    let mut app = app_with_transcript(3);
    type_text(&mut app, "hello world");
    for _ in 0..5 {
        press_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
    }
    let screen = draw(&mut app);
    assert!(
        screen.try_find("Ctrl-C=コピー").is_some(),
        "{}",
        screen.text()
    );
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("world"));
    assert!(!app.should_quit);
    assert_eq!(app.input, "hello world", "写しただけで入力が変わった");
    let screen = draw(&mut app);
    assert!(
        screen.try_find("Ctrl-C=終了").is_some(),
        "{}",
        screen.text()
    );
}

/// **マウスの選択と入力欄の選択は同時に持たない**（後から作ったほうが残る）。
#[test]
fn the_mouse_and_input_selections_never_coexist() {
    let mut app = app_with_transcript(5);
    type_text(&mut app, "abc");
    press_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 1");
    drag(&mut app, (x, y), (x + 9, y));
    assert_eq!(
        app.selection_range(),
        None,
        "ドラッグで入力欄の選択が外れていない"
    );
    press_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
    assert!(app.selection_range().is_some());
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(
        copied.as_deref(),
        Some("c"),
        "入力欄の選択を作ったのにマウスの選択が写った"
    );
}

/// (h) **クリップボードへ書けなかったら、失敗を知らせる**（transcriptの枠の上辺）。書けたら文字数を知らせる。
/// 理由が長くて上辺に入り切らなくても、失敗したことは切らずに出す（末尾を`…`で切る）。知らせは次にキーを押すと消える。
#[test]
fn the_result_of_copying_is_shown_and_a_failure_is_not_silent() {
    let mut app = app_with_transcript(3);
    app.note_copied("abc", Err("ほかのアプリが使用中（5回試しました）".into()));
    let screen = draw(&mut app);
    let (x, y) = screen.find("コピーできませんでした");
    assert_eq!(y, 0, "transcriptの枠の上辺に出ていない");
    assert_eq!(screen.style((x, y)).fg, Some(Color::Red));
    assert!(screen.try_find("5回試しました").is_some());

    app.note_copied("abc", Err("長い理由".repeat(40)));
    let screen = draw(&mut app);
    assert_eq!(
        screen.find("コピーできませんでした").1,
        0,
        "長い理由で知らせが消えた"
    );
    assert!(screen.row(0).contains('…'), "{}", screen.row(0));

    app.note_copied("ab\r\nc", Ok(()));
    let screen = draw(&mut app);
    assert!(
        screen.try_find("4文字をコピーしました").is_some(),
        "{}",
        screen.text()
    );
    press(&mut app, KeyCode::Char('x'));
    let screen = draw(&mut app);
    assert!(
        screen.try_find("コピーしました").is_none(),
        "キーを押しても消えない"
    );
}

/// **選んでいる間の`Esc`は選択を外すだけ**（中断も承認ダイアログの拒否もしない）。もう一度押せば今までどおり。
#[test]
fn escape_first_drops_the_selection() {
    let mut app = running_app();
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 1");
    drag(&mut app, (x, y), (x + 9, y));
    assert_eq!(shown(&press(&mut app, KeyCode::Esc)), shown(&None));
    assert!(!app.has_copyable_selection());
    assert_eq!(
        shown(&press(&mut app, KeyCode::Esc)),
        shown(&Some(Action::Cancel))
    );

    // 承認ダイアログの本文を選んでいるときの`Esc`は、ダイアログを閉じない。
    let mut app = pending_app(5);
    let screen = draw(&mut app);
    let (x, y) = screen.find("program: git");
    drag(&mut app, (x, y), (x + 11, y));
    assert!(app.has_copyable_selection());
    press(&mut app, KeyCode::Esc);
    assert!(
        app.pending_permission.is_some(),
        "選択を外す`Esc`で拒否した"
    );
    press(&mut app, KeyCode::Esc);
    assert!(
        app.pending_permission.is_none(),
        "2回目の`Esc`が拒否にならない"
    );
}

/// **承認ダイアログの本文は、エスケープして描いた見えている形のまま写る**（見えない制御文字を素で写さない）。
#[test]
fn the_approval_body_is_copied_as_it_is_shown() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    let mut view = PermissionView::new(
        "perm-0".to_string(),
        "run_program".to_string(),
        RiskClass::Exec,
        PermissionSubject::Program(ProgramSubject::plain(
            "gp\u{202E}yp.exe",
            vec!["x".to_string()],
        )),
        "{}".to_string(),
        None,
        "C:/ws".to_string(),
    );
    view.opened_at = Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
    app.pending_permission = Some(view);
    let screen = draw(&mut app);
    let (x, y) = screen.find("program: gp");
    let shown_line = r"program: gp\u{202E}yp.exe";
    drag(
        &mut app,
        (x, y),
        (x + shown_line.chars().count() as u16 - 1, y),
    );
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some(shown_line));
    assert!(
        app.pending_permission.is_some(),
        "写しただけで承認ダイアログが閉じた"
    );
}

/// **承認ダイアログが開いている間も、外に見えているtranscriptは選べる**（ホイールで送れるのと同じ）。ダイアログの中は
/// 後ろのtranscriptではなくダイアログの本文が選ばれる。
#[test]
fn the_transcript_outside_an_open_dialog_can_still_be_selected() {
    let mut app = pending_app(40);
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 1");
    drag(&mut app, (x, y), (x + 9, y));
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("transcript"));
    assert!(app.pending_permission.is_some());
}

/// **レビューパネルの差分の文章も選べる**（押すと差分ペインへフォーカスも移る——今までどおり）。
#[test]
fn the_review_diff_can_be_selected_and_pressing_it_focuses_the_pane() {
    let mut app = review_app(three_rows());
    let screen = draw(&mut app);
    assert_eq!(panel(&app).focus, ReviewFocus::List);
    let (x, y) = screen.find("  line0");
    let to = screen.find("  line1");
    drag(&mut app, (x, y), (to.0 + 6, to.1));
    assert_eq!(
        panel(&app).focus,
        ReviewFocus::Diff,
        "差分を押してもフォーカスが移らない"
    );
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("  line0\r\n  line1"));
    assert!(app.review_panel.is_some());
}

/// **選んだ文字は背景が青で、色の入れ替え（押されているボタン・一覧のいまの行の見た目）ではない。**
#[test]
fn selected_characters_look_selected_not_reversed() {
    let mut app = app_with_transcript(5);
    let screen = draw(&mut app);
    let (x, y) = screen.find("transcript line 2");
    drag(&mut app, (x, y), (x + 9, y));
    let screen = draw(&mut app);
    let look = screen.style((x, y));
    assert_eq!(look.bg, Some(Color::Blue));
    assert!(!look.add_modifier.contains(Modifier::REVERSED));
    assert_ne!(
        screen.style((x + 11, y)).bg,
        Some(Color::Blue),
        "選んでいない文字まで色が付いた"
    );
}
