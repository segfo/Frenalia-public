//! `Esc`の二度押しで閉じる試験（`app::quit`）。`Ctrl+C`は終了に使わない（`app::select`）。
//!
//! 親（`pointer_tests`）と同じく**製品の入口を通す**——キーとマウスは[`AppState::handle_event_at`]へ時刻を付けて入れ、
//! 窓の長さは`harness_term::double_esc::WINDOW`から作る（実時間で待たない）。画面は製品の描画で描いて読む。

use crossterm::event::KeyEventKind;
use harness_term::double_esc::{armed_notice, CTRL_C_NOTICE, WINDOW};

use super::*;
use crate::app::BusyEnd;

const MS: Duration = Duration::from_millis(1);

/// キー`code`の押下を時刻`now`で製品の入口へ入れる。
fn key_at(app: &mut AppState, code: KeyCode, now: Instant) -> Option<Action> {
    match app.handle_event_at(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)), now) {
        Step::Handled(action) => action,
        Step::Unchanged => panic!("キーの押下が描き直さない扱いになった"),
    }
}

fn esc_at(app: &mut AppState, now: Instant) -> Option<Action> {
    key_at(app, KeyCode::Esc, now)
}

fn ctrl_c_at(app: &mut AppState, now: Instant) -> Option<Action> {
    match app.handle_event_at(
        Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        now,
    ) {
        Step::Handled(action) => action,
        Step::Unchanged => panic!("キーの押下が描き直さない扱いになった"),
    }
}

fn idle_app() -> AppState {
    app_with_transcript(3)
}

/// (a) **何もしていないときの`Esc`を1秒以内に2回で終了する。境目（ちょうど1秒）は内側、1ミリ秒でも過ぎたら終了しない**
/// （過ぎた2回目は新しい1回目になり、その窓の中の次の`Esc`で終了する——禁止側と許可側の対）。
#[test]
fn two_quiet_escapes_within_the_window_quit_and_the_boundary_is_inside() {
    let t0 = Instant::now();
    let mut app = idle_app();
    assert_eq!(
        shown(&esc_at(&mut app, t0)),
        shown(&None),
        "1回目で何か起きた"
    );
    assert!(!app.should_quit, "1回目で終了した");
    assert_eq!(
        shown(&esc_at(&mut app, t0 + WINDOW)),
        shown(&Some(Action::Quit))
    );
    assert!(app.should_quit);

    let mut app = idle_app();
    esc_at(&mut app, t0);
    let late = t0 + WINDOW + MS;
    assert_eq!(
        shown(&esc_at(&mut app, late)),
        shown(&None),
        "窓の外で終了した"
    );
    assert!(!app.should_quit);
    assert_eq!(
        shown(&esc_at(&mut app, late + WINDOW)),
        shown(&Some(Action::Quit)),
        "窓の外の2回目が新しい1回目にならない"
    );
}

/// **キーを離したことは数え直しにしない**——Windowsのコンソールは押下と離上の両方を送るので、離上で数え直すと
/// `Esc`の二度押しが一度も成立しない。
#[test]
fn a_key_release_between_the_escapes_does_not_start_over() {
    let t0 = Instant::now();
    let mut app = idle_app();
    esc_at(&mut app, t0);
    let mut release = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    release.kind = KeyEventKind::Release;
    assert!(matches!(
        app.handle_event_at(Event::Key(release), t0 + MS),
        Step::Unchanged
    ));
    assert_eq!(
        shown(&esc_at(&mut app, t0 + 2 * MS)),
        shown(&Some(Action::Quit))
    );
}

/// (b) **他の働きをした`Esc`は数えない**——応答・`/compact`を止めた、承認ダイアログで拒否した、レビューパネルを閉じた、
/// 選んだ文章を外した`Esc`。どの場合も、**何もしていない`Esc`を1回押して数え始めた後で**その状態にし（応答が始まる・
/// 承認を求められる等はキーを押さずに起きる）、他の働きをする`Esc`を押す。その`Esc`で終了せず（2回目に数えない）、
/// 先の1回目も消えて（直後の`Esc`1回では終了しない）、もう1回で終了する。時刻はどれも窓の中（窓が理由で終了しない
/// のではないことを確かめるため）。選択だけは、選ぶクリックがそれ自体で数え直しにする（`another_key_or_a_click_…`）。
#[test]
fn an_escape_that_did_something_else_is_not_counted() {
    let t0 = Instant::now();
    // それぞれ、その状態にして、他の働きをさせる`Esc`を時刻`at`に押し、何もしていない状態へ戻す。
    type Case = (&'static str, fn(&mut AppState, Instant));
    let cases: [Case; 5] = [
        ("応答の中断", |app, at| {
            app.apply(AgentEvent::TurnStarted {
                estimated_input_tokens: 0,
            });
            assert_eq!(shown(&esc_at(app, at)), shown(&Some(Action::Cancel)));
            app.apply(AgentEvent::Cancelled);
        }),
        ("/compactの中断", |app, at| {
            assert!(app.begin_busy("Compacting context"));
            app.apply(AgentEvent::ContextCompactionStarted);
            assert_eq!(shown(&esc_at(app, at)), shown(&Some(Action::Cancel)));
            app.end_busy(BusyEnd::Stopped);
        }),
        ("承認ダイアログの拒否", |app, at| {
            app.pending_permission = Some(approval_view());
            assert!(matches!(esc_at(app, at), Some(Action::Respond(..))));
            assert!(
                app.pending_permission.is_none(),
                "試験の前提: 拒否していない"
            );
        }),
        ("レビューパネルを閉じる", |app, at| {
            app.open_changes_panel(three_rows());
            assert_eq!(shown(&esc_at(app, at)), shown(&None));
            assert!(app.review_panel.is_none(), "試験の前提: 閉じていない");
        }),
        ("選んだ文章を外す", |app, at| {
            let screen = draw(app);
            let (x, y) = screen.find("transcript line 1");
            for (kind, place) in [
                (MouseEventKind::Down(MouseButton::Left), (x, y)),
                (MouseEventKind::Drag(MouseButton::Left), (x + 9, y)),
                (MouseEventKind::Up(MouseButton::Left), (x + 9, y)),
            ] {
                mouse_at(app, kind, place, at);
                draw(app);
            }
            assert!(app.has_copyable_selection(), "試験の前提: 選べていない");
            assert_eq!(shown(&esc_at(app, at)), shown(&None));
            assert!(!app.has_copyable_selection(), "試験の前提: 外れていない");
        }),
    ];
    for (case, enter_and_escape) in cases {
        let mut app = idle_app();
        assert_eq!(shown(&esc_at(&mut app, t0)), shown(&None), "{case}: 1回目");
        enter_and_escape(&mut app, t0 + MS);
        assert!(
            !app.should_quit,
            "{case}: 他の働きをした`Esc`を2回目に数えた"
        );
        assert_eq!(
            shown(&esc_at(&mut app, t0 + 2 * MS)),
            shown(&None),
            "{case}: 他の働きをした`Esc`で1回目が消えていない"
        );
        assert!(!app.should_quit, "{case}");
        assert_eq!(
            shown(&esc_at(&mut app, t0 + 3 * MS)),
            shown(&Some(Action::Quit)),
            "{case}: 何もしていない`Esc`の2回で終了しない"
        );
    }
}

/// (b) **応答中の`Esc`は何度押しても中断で、終了に転ばない**（止めたつもりで連打した人が終了しない）。
#[test]
fn escapes_while_a_turn_runs_keep_cancelling_and_never_quit() {
    let t0 = Instant::now();
    let mut app = running_app();
    for i in 0..5u32 {
        assert_eq!(
            shown(&esc_at(&mut app, t0 + i * MS)),
            shown(&Some(Action::Cancel))
        );
    }
    assert!(!app.should_quit);
}

/// (c) **`Esc`の間に別のキー・クリックが挟まったら数え直す。** 挟まっても生き残る作りにすると、無関係な操作のあとの
/// `Esc`1回で突然終了する。
#[test]
fn another_key_or_a_click_between_the_escapes_starts_over() {
    let t0 = Instant::now();
    // 別のキー（入力欄に文字が入る）。
    let mut app = idle_app();
    esc_at(&mut app, t0);
    key_at(&mut app, KeyCode::Char('a'), t0 + MS);
    assert_eq!(shown(&esc_at(&mut app, t0 + 2 * MS)), shown(&None));
    assert!(!app.should_quit, "別のキーを挟んだのに終了した");
    assert_eq!(app.input, "a");

    // 押せる場所のクリック（入力欄の見出しの`Enter=改行`）。
    let mut app = idle_app();
    let screen = draw(&mut app);
    esc_at(&mut app, t0);
    mouse_at(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        screen.find("Enter=改行"),
        t0 + MS,
    );
    assert_eq!(shown(&esc_at(&mut app, t0 + 2 * MS)), shown(&None));
    assert!(!app.should_quit, "クリックを挟んだのに終了した");

    // キーを押さないクリック（さかのぼり中の案内——押すと最新へ戻る）。
    let mut app = app_with_transcript(100);
    app.scroll_lines(5);
    let screen = draw(&mut app);
    esc_at(&mut app, t0);
    mouse_at(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        screen.find("[5"),
        t0 + MS,
    );
    assert_eq!(
        app.scroll_offset(),
        0,
        "試験の前提: 案内のクリックが働いていない"
    );
    assert_eq!(shown(&esc_at(&mut app, t0 + 2 * MS)), shown(&None));
    assert!(
        !app.should_quit,
        "キーを押さないクリックを挟んだのに終了した"
    );

    // 文章の上のクリック（選び始めの押下）。
    let mut app = idle_app();
    let screen = draw(&mut app);
    esc_at(&mut app, t0);
    let at = screen.find("transcript line 1");
    mouse_at(
        &mut app,
        MouseEventKind::Down(MouseButton::Left),
        at,
        t0 + MS,
    );
    mouse_at(&mut app, MouseEventKind::Up(MouseButton::Left), at, t0 + MS);
    assert_eq!(shown(&esc_at(&mut app, t0 + 2 * MS)), shown(&None));
    assert!(!app.should_quit, "文章のクリックを挟んだのに終了した");
}

/// (d) **`Ctrl+C`は、何も選んでいなければどの状態でも終了しない。** 何もしないのではなく、終了の仕方を知らせる
/// （押しても無反応にしない、B-23(c)）。選んでいれば写す（許可側。写す中身は`select_tests`）。
#[test]
fn ctrl_c_never_quits_and_says_how_to_quit() {
    let t0 = Instant::now();
    let cases: [(&str, AppState); 4] = [
        ("待機中", idle_app()),
        ("応答中", running_app()),
        ("承認ダイアログ", pending_app(3)),
        ("レビューパネル", review_app(three_rows())),
    ];
    for (case, mut app) in cases {
        let before = approval_state(&app);
        let review_open = app.review_panel.is_some();
        assert_eq!(shown(&ctrl_c_at(&mut app, t0)), shown(&None), "{case}");
        assert!(!app.should_quit, "{case}: `Ctrl+C`で終了した");
        assert_eq!(
            approval_state(&app),
            before,
            "{case}: 承認ダイアログが変わった"
        );
        assert_eq!(
            app.review_panel.is_some(),
            review_open,
            "{case}: レビューパネルが閉じた"
        );
        assert_eq!(
            app.edge_notice.as_ref().map(|n| n.text.as_str()),
            Some(CTRL_C_NOTICE),
            "{case}: 選んでいない`Ctrl+C`が無反応"
        );
    }
    // 知らせはtranscriptの枠の上辺に出る。
    let mut app = idle_app();
    ctrl_c_at(&mut app, t0);
    assert_eq!(draw(&mut app).find(CTRL_C_NOTICE).1, 0);

    // 選んでいれば写す（終了しない）。
    let mut app = idle_app();
    type_text(&mut app, "hi");
    key_at(&mut app, KeyCode::Home, t0);
    press_key(&mut app, KeyEvent::new(KeyCode::End, KeyModifiers::SHIFT));
    assert_eq!(
        shown(&ctrl_c_at(&mut app, t0)),
        shown(&Some(Action::Copy("hi".to_string())))
    );
    assert!(!app.should_quit);
}

/// (e) **1回目の`Esc`で、もう一度押せば終了することをtranscriptの枠の上辺に知らせる。** 窓の中は出したまま、窓が過ぎたら
/// 描画の合図（`tick`）で消える。別のキーを押しても消える。
#[test]
fn the_first_escape_says_a_second_one_quits_until_the_window_passes() {
    let t0 = Instant::now();
    let mut app = idle_app();
    esc_at(&mut app, t0);
    assert_eq!(
        draw(&mut app).find(&armed_notice()).1,
        0,
        "上辺に出ていない"
    );
    app.tick_at(t0 + WINDOW);
    assert!(
        draw(&mut app).try_find(&armed_notice()).is_some(),
        "窓の中で消えた"
    );
    app.tick_at(t0 + WINDOW + MS);
    assert!(
        draw(&mut app).try_find(&armed_notice()).is_none(),
        "窓が過ぎても残った（押しても終了しないのに「もう一度で終了」と言い続ける）"
    );

    let mut app = idle_app();
    esc_at(&mut app, t0);
    key_at(&mut app, KeyCode::Char('x'), t0 + MS);
    assert!(draw(&mut app).try_find(&armed_notice()).is_none());

    // 別の知らせ（写した結果）が出ているときは、窓が過ぎてもそちらを消さない。
    let mut app = idle_app();
    esc_at(&mut app, t0);
    app.note_copied("abc", Ok(()));
    app.tick_at(t0 + WINDOW + MS);
    assert!(app.edge_notice.is_some(), "写した結果の知らせを消した");
}

/// **入力欄の見出しの`Esc×2=終了`は、`Esc`の二度押しで終了する状態でだけ出る**（効く操作を案内する、B-32）。
/// 見出しを決める判定（`esc_would_count`）と数える側（`on_key`の分岐の順）は別々に書いてあるので、ずれていないことを
/// 状態ごとに固定する: 出ているなら2回で終了し、2回で終了しないなら出ていない。
#[test]
fn the_quit_hint_is_shown_only_where_two_escapes_quit() {
    let t0 = Instant::now();
    let compacting = || {
        let mut app = idle_app();
        app.begin_busy("Compacting context");
        app.apply(AgentEvent::ContextCompactionStarted);
        app
    };
    let queued = || {
        let mut app = idle_app();
        app.begin_busy("Compacting context");
        app
    };
    let selecting_input = || {
        let mut app = idle_app();
        type_text(&mut app, "hi");
        press_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
        app
    };
    let cases: [(&str, AppState); 7] = [
        ("待機中", idle_app()),
        ("応答中", running_app()),
        ("/compactの実行中", compacting()),
        ("/compactのキュー待ち", queued()),
        ("承認ダイアログ", pending_app(3)),
        ("レビューパネル", review_app(three_rows())),
        ("入力欄の選択", selecting_input()),
    ];
    let mut shown_somewhere = false;
    for (case, mut app) in cases {
        let hinted = app
            .input_key_hints()
            .iter()
            .any(|hint| hint.label == "Esc×2=終了");
        esc_at(&mut app, t0);
        esc_at(&mut app, t0 + MS);
        if hinted {
            assert!(app.should_quit, "{case}: 案内が出ているのに2回で終了しない");
            shown_somewhere = true;
        }
        if !app.should_quit {
            assert!(!hinted, "{case}: 2回で終了しないのに案内が出ている");
        }
    }
    assert!(
        shown_somewhere,
        "どの状態でも案内が出ない（試験が何も測っていない）"
    );
}
