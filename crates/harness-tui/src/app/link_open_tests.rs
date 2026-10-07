//! リンクを開く試験（`app::link_open`と`crate::ui`の`link_tooltip`の押す場所。計画書`plans/PLAN-TUI-IMPROVEMENTS.md`
//! §3.3〜§3.5・§0のT11b）。親（`link_hover_tests`）の道具（吹き出しを出す・探す）を使うので、ここの子にする。
//!
//! 親と同じく**製品の入口を通す**——製品の描画で描いて書き戻し、マウスは`AppState::handle_event`へ入れ、押す位置は
//! 描いた画面のセルの文字から取る。開くURLの期待値は**書いたURLの文字列**で持つ（製品の判定の関数で作らない）。
//! **本物のブラウザは開かない**——状態は開くURLを[`Action::OpenUrl`]で返すだけで、開くのはイベントループ
//! （`crate::open_url`）。

use unicode_width::UnicodeWidthChar;

use super::*;

/// Ctrlを押したまま左ボタンを押し、製品のループと同じく描き直す。返った操作を返す。
fn ctrl_click(app: &mut AppState, (column, row): (u16, u16)) -> Option<Action> {
    let step = app.handle_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::CONTROL,
    }));
    draw(app);
    match step {
        Step::Handled(action) => action,
        Step::Unchanged => panic!("Ctrl＋クリックが描き直さない扱いになった"),
    }
}

/// 修飾キー無しで左ボタンを押し、描き直す。
fn plain_click(app: &mut AppState, at: (u16, u16)) -> Option<Action> {
    let action = click(app, at);
    draw(app);
    action
}

/// 開くURL（[`Action::OpenUrl`]でなければ`None`）。
fn opened(action: &Option<Action>) -> Option<String> {
    match action {
        Some(Action::OpenUrl(url)) => Some(url.as_str().to_string()),
        _ => None,
    }
}

/// そのセルに下線が付いているか（押せる見た目）。
fn underlined(screen: &Screen, at: (u16, u16)) -> bool {
    screen.style(at).add_modifier.contains(Modifier::UNDERLINED)
}

/// リンクを指して吹き出しを出し、描いた画面を返す。
fn hover(app: &mut AppState, at: (u16, u16)) -> Screen {
    moved(app, at);
    draw(app)
}

/// 開かない形式として断るリンク先（計画書§3.5。既定のアプリへ渡る形式・スキームの無い相対URL）。
const REFUSED: [&str; 9] = [
    "file:///C:/x",
    "javascript:alert(1)",
    "ms-msdt:id",
    "search-ms:query=x",
    "data:text/html,x",
    "vbscript:msgbox(1)",
    "mailto:a@b",
    "foo.html",
    "//host/path",
];

/// **リンクの文字をCtrl＋クリックすると、そのURLを開く**（[`Action::OpenUrl`]）。吹き出しを出していなくても（マウスを
/// 動かさずに押しても）押したセルのリンクで決める。**範囲選択は始めない**——押したまま動かして離しても何も選んでいない。
#[test]
fn ctrl_clicking_a_link_opens_it_and_selects_nothing() {
    let mut app = one_link();
    let screen = draw(&mut app);
    let (x, y) = screen.find("リンク");
    let action = ctrl_click(&mut app, (x + 2, y));
    assert_eq!(opened(&action).as_deref(), Some(URL), "{}", shown(&action));
    assert!(!app.selection.is_held(), "Ctrl＋クリックで選び始めた");

    let now = Instant::now();
    event_then_draw(
        &mut app,
        MouseEventKind::Drag(MouseButton::Left),
        (x + 5, y),
        now,
    );
    event_then_draw(
        &mut app,
        MouseEventKind::Up(MouseButton::Left),
        (x + 5, y),
        now,
    );
    let (copied, _) = ctrl_c(&mut app);
    assert_eq!(copied, None, "Ctrl＋クリックから動かして文字を選んだ");
}

/// **普通のクリックは、リンクの上でも範囲選択を始める**（今までどおり。開かない）。ずらして離せばリンクの文字を選べる。
#[test]
fn a_plain_click_on_a_link_starts_a_selection_and_opens_nothing() {
    let mut app = one_link();
    let screen = draw(&mut app);
    let (x, y) = screen.find("リンク");
    let action = plain_click(&mut app, (x, y));
    assert!(action.is_none(), "普通のクリックで{}", shown(&action));
    assert!(app.selection.is_held(), "普通のクリックで選び始めない");
    let last = (right_after(&screen, "リンク").0 - 2, y);
    let now = Instant::now();
    event_then_draw(&mut app, MouseEventKind::Drag(MouseButton::Left), last, now);
    event_then_draw(&mut app, MouseEventKind::Up(MouseButton::Left), last, now);
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("リンク"), "{other}");
}

/// **リンクでない文字をCtrl＋クリックしたときは、今までどおり範囲選択を始める**（何も開かない。Ctrlはリンクの上でだけ
/// 意味を持つ）。
#[test]
fn ctrl_clicking_text_that_is_not_a_link_starts_a_selection_as_before() {
    let mut app = one_link();
    let screen = draw(&mut app);
    let action = ctrl_click(&mut app, screen.find("リンクの無い行"));
    assert!(action.is_none(), "{}", shown(&action));
    assert!(
        app.selection.is_held(),
        "リンクでない文字のCtrl＋クリックで選び始めない"
    );
    assert_eq!(app.edge_notice, None);
}

/// **折り返しで2行に分かれたリンクは、どちらの行をCtrl＋クリックしても同じURLを開く。**
#[test]
fn ctrl_clicking_either_part_of_a_wrapped_link_opens_the_same_url() {
    let url = "https://b.x/";
    let mut app = app_with_items(&[&format!(
        "{} [二つ目のとても長いリンク]({url}) 後",
        "あ".repeat(46)
    )]);
    let screen = draw(&mut app);
    let first = screen.find("二つ");
    let last = screen.find("リンク");
    assert_eq!(
        last.1,
        first.1 + 1,
        "折り返していない（試験の前提）:\n{}",
        screen.text()
    );
    assert_eq!(
        opened(&ctrl_click(&mut app, first)).as_deref(),
        Some(url),
        "1行目"
    );
    assert_eq!(
        opened(&ctrl_click(&mut app, last)).as_deref(),
        Some(url),
        "2行目"
    );
}

/// **吹き出しのURLを押すと開く。** URLには押せる見た目（下線）が付き、括弧には付かない。押せるのは下線の付いた
/// URLだけで、括弧を押しても何も起きない（下の文字も選ばない——吹き出しは下を覆う）。
#[test]
fn clicking_the_url_in_the_tooltip_opens_it() {
    let mut app = one_link();
    let screen = draw(&mut app);
    let tip = hover(&mut app, screen.find("リンク"));
    let at = tip.find(&label(URL));
    assert!(!underlined(&tip, at), "括弧に下線が付いた");
    let url_cells = (1..=URL.len() as u16).map(|dx| (at.0 + dx, at.1));
    for cell in url_cells {
        assert!(underlined(&tip, cell), "URLの{cell:?}に下線が無い");
    }
    let close = (at.0 + label(URL).width() as u16 - 1, at.1);
    assert!(!underlined(&tip, close), "閉じ括弧に下線が付いた");
    assert!(
        is_tooltip_look(tip.style((at.0 + 1, at.1))),
        "吹き出しの色が変わった"
    );

    let action = plain_click(&mut app, at);
    assert!(action.is_none(), "括弧で{}", shown(&action));
    assert!(!app.selection.is_held(), "吹き出しの下の文字を選び始めた");

    let action = plain_click(&mut app, (at.0 + 4, at.1));
    assert_eq!(opened(&action).as_deref(), Some(URL), "{}", shown(&action));
    assert!(!app.selection.is_held());
}

/// **開くURLと吹き出しに出すURLは、正規化した同じ文字列**——スキームとホストを小文字にし、空白などを`%`で符号化した
/// 形（実際にブラウザへ渡す形）を見せてから開く（B-21: 見せた値と使う値を別物にしない）。
#[test]
fn the_shown_and_opened_url_is_the_normalised_one() {
    let normalised = "https://example.com/a%20b";
    let mut app = app_with_items(&["前 [リンク](<HTTPS://Example.COM/a b>) 後", "下の行"]);
    let screen = draw(&mut app);
    let (x, y) = screen.find("リンク");
    let tip = hover(&mut app, (x, y));
    let at = tip
        .try_find(&label(normalised))
        .unwrap_or_else(|| panic!("正規化した形が出ていない:\n{}", tip.text()));
    assert_eq!(
        opened(&plain_click(&mut app, (at.0 + 3, at.1))).as_deref(),
        Some(normalised)
    );
    assert_eq!(
        opened(&ctrl_click(&mut app, (x, y))).as_deref(),
        Some(normalised)
    );
}

/// **http/https以外の形式とスキームの無い相対URLは開かない**（計画書§3.5）。吹き出しには「開けない形式」と書いたURLを
/// 出し、下線を付けず、押しても何も起きない。リンクの文字をCtrl＋クリックしても開かず、**開かない理由を上辺に知らせる**
/// （黙って何もしないと壊れて見える。B-10）。範囲選択も始めない（Ctrl＋クリックはリンクを狙った操作）。
#[test]
fn links_that_are_not_http_or_https_are_never_opened() {
    for raw in REFUSED {
        let mut app = app_with_items(&[&format!("前 [リンク]({raw}) 後"), "下の行"]);
        let screen = draw(&mut app);
        let (x, y) = screen.find("リンク");
        let tip = hover(&mut app, (x, y));
        let text = format!("(開けない形式: {raw})");
        let at = tip
            .try_find(&text)
            .unwrap_or_else(|| panic!("{raw}: 開けない印が出ていない:\n{}", tip.text()));
        let mut cell = at.0;
        for c in text.chars() {
            assert!(
                !underlined(&tip, (cell, at.1)),
                "{raw}: 開けない吹き出しに下線"
            );
            cell += c.width().unwrap_or(0) as u16;
        }

        let action = plain_click(&mut app, (at.0 + text.width() as u16 - 3, at.1));
        assert!(
            action.is_none(),
            "{raw}: 吹き出しを押して{}",
            shown(&action)
        );
        assert_eq!(
            app.edge_notice, None,
            "{raw}: 押せないはずの吹き出しが押せた"
        );

        let action = ctrl_click(&mut app, (x, y));
        assert!(
            action.is_none(),
            "{raw}: Ctrl＋クリックで{}",
            shown(&action)
        );
        assert!(
            !app.selection.is_held(),
            "{raw}: Ctrl＋クリックで選び始めた"
        );
        let notice = app
            .edge_notice
            .clone()
            .unwrap_or_else(|| panic!("{raw}: 知らせが無い"));
        assert!(
            notice.text.contains("開けない形式") && notice.text.contains(raw),
            "{raw}: {notice:?}"
        );
    }
}

/// 許可側の対照（B-35）: 断る形式の試験と同じ組み立てで、`http`と`https`は開く。
#[test]
fn http_and_https_links_built_the_same_way_are_opened() {
    for url in ["http://e.x/p", "https://e.x/p"] {
        let mut app = app_with_items(&[&format!("前 [リンク]({url}) 後"), "下の行"]);
        let screen = draw(&mut app);
        let (x, y) = screen.find("リンク");
        assert_eq!(opened(&ctrl_click(&mut app, (x, y))).as_deref(), Some(url));
    }
}

/// **承認ダイアログが開いている間は、外に見えているtranscriptのリンクをCtrl＋クリックしても開かない**（吹き出しを出さない
/// ので、URLを見ないまま開くことになる）。今までどおり文字を選び始める。閉じれば開ける（許可側）。
#[test]
fn ctrl_click_opens_nothing_while_the_approval_dialog_is_open() {
    let mut app = app_with_items(&[&format!("[リンク]({URL})"), "下の行"]);
    app.pending_permission = Some(approval_view());
    let screen = draw(&mut app);
    let at = screen.try_find("リンク").unwrap_or_else(|| {
        panic!(
            "ダイアログの外にリンクが見えていない（試験の前提）:\n{}",
            screen.text()
        )
    });
    let action = ctrl_click(&mut app, at);
    assert!(opened(&action).is_none(), "{}", shown(&action));

    app.selection.clear();
    app.pending_permission = None;
    draw(&mut app);
    assert_eq!(opened(&ctrl_click(&mut app, at)).as_deref(), Some(URL));
}

/// **開いた結果を上辺に知らせる**（写した結果と同じ場所・同じ色の使い分け）。開けなかったときは理由を出し、黙らない
/// （B-10）。
#[test]
fn the_result_of_opening_is_shown_and_a_failure_is_not_silent() {
    let mut app = one_link();
    let url = crate::open_url::OpenableUrl::parse(URL).expect("開けるURL");
    app.note_opened(&url, Err("ShellExecuteW: 31（関連付けが無い）".to_string()));
    let screen = draw(&mut app);
    let (x, y) = screen.find("開けませんでした");
    assert_eq!(y, 0, "transcriptの枠の上辺に出ていない");
    assert_eq!(screen.style((x, y)).fg, Some(Color::Red));
    assert!(
        screen.try_find("関連付けが無い").is_some(),
        "{}",
        screen.text()
    );

    app.note_opened(&url, Ok(()));
    let screen = draw(&mut app);
    let (x, y) = screen.find("既定のブラウザへ渡しました");
    assert_eq!(screen.style((x, y)).fg, Some(Color::Green));
    assert!(screen.try_find(URL).is_some(), "{}", screen.text());
}
