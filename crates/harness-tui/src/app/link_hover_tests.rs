//! リンクの吹き出しの試験（`app::link_hover`と`crate::ui`の`link_tooltip`。計画書`plans/PLAN-TUI-IMPROVEMENTS.md`
//! §3・§0のT11a）。リンクの区間を返すのは整形する実装だけなので、整形する実装を選んだビルドでだけ置く
//! （`crate::markdown::formatting_only`）。
//!
//! 親（`select_tests`）と同じく**製品の入口を通す**——製品の描画で描いて書き戻し、マウスは`AppState::handle_event`へ
//! 入れ、指す位置は描いた画面のセルの文字から取る。吹き出しに出るはずの文字は**元のURL**から作る（描いた結果から
//! 期待値を作らない）。イベントのたびに描き直す（製品のイベントループと同じ）。

use unicode_width::UnicodeWidthStr;

use super::*;

/// ボタンを押さずにマウスを`at`へ動かした（修飾キー無し）。
fn moved(app: &mut AppState, at: (u16, u16)) -> Step {
    moved_with(app, at, KeyModifiers::NONE)
}

/// ボタンを押さずに、修飾キー`modifiers`を押したままマウスを`at`へ動かした（T10の実測で、VS Codeの端末では
/// Ctrlを押したままの移動も届く）。
fn moved_with(app: &mut AppState, (column, row): (u16, u16), modifiers: KeyModifiers) -> Step {
    app.handle_event(Event::Mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column,
        row,
        modifiers,
    }))
}

/// 描き直しの合図を返したか。
fn handled(step: Step) -> bool {
    matches!(step, Step::Handled(None))
}

/// 吹き出しに出る文字（`(URL)`）。
fn label(url: &str) -> String {
    format!("({url})")
}

/// 吹き出しの見た目（ステータスバーと同じ、灰色の地に黒い文字）。
fn is_tooltip_look(style: Style) -> bool {
    style.fg == Some(Color::Black) && style.bg == Some(Color::Gray)
}

/// `text`が描かれた場所の右隣のセル（`text`の最後の文字の後ろ）。
fn right_after(screen: &Screen, text: &str) -> (u16, u16) {
    let (x, y) = screen.find(text);
    (x + text.width() as u16, y)
}

/// 2つの画面で、記号か見た目が違うセル。
fn changed_cells(a: &Screen, b: &Screen) -> Vec<(u16, u16)> {
    let mut changed = Vec::new();
    for (y, (row_a, row_b)) in a.0.iter().zip(&b.0).enumerate() {
        for x in 0..row_a.len() {
            if row_a[x] != row_b[x] || a.1[y][x] != b.1[y][x] {
                changed.push((x as u16, y as u16));
            }
        }
    }
    changed
}

/// 1行の吹き出しが`at`から`width`桁に描かれたときに変わってよいセル。
fn cells_of(at: (u16, u16), width: usize) -> Vec<(u16, u16)> {
    (0..width as u16).map(|dx| (at.0 + dx, at.1)).collect()
}

const URL: &str = "https://example.com/a";

fn one_link() -> AppState {
    app_with_items(&[&format!("前 [リンク]({URL}) 後"), "リンクの無い行"])
}

/// **リンクの上へ動くと、リンクの最後の文字のすぐ右に`(URL)`が重なって出る**。変わるのは吹き出しのセルだけ——文章の
/// 並びも、ほかのセルの文字と見た目も変わらない。吹き出しは灰色の地に黒い文字（ステータスバーと同じ）。
/// **リンクの外へ動くと消え**、画面はホバーする前と1セルも違わない。
#[test]
fn hovering_a_link_shows_its_url_right_after_it_and_moving_off_removes_it() {
    let mut app = one_link();
    let before = draw(&mut app);
    let (x, y) = before.find("リンク");
    let at = right_after(&before, "リンク");

    assert!(
        handled(moved(&mut app, (x + 2, y))),
        "リンクの上へ動いたのに描き直さない"
    );
    let shown = draw(&mut app);
    assert_eq!(shown.find(&label(URL)), at, "\n{}", shown.text());
    assert!(is_tooltip_look(shown.style(at)));
    assert_eq!(
        changed_cells(&before, &shown),
        cells_of(at, label(URL).width()),
        "吹き出しの外のセルが変わった"
    );

    let (ox, oy) = before.find("リンクの無い行");
    assert!(
        handled(moved(&mut app, (ox + 2, oy))),
        "リンクの外へ動いたのに描き直さない"
    );
    let gone = draw(&mut app);
    assert_eq!(gone.try_find("(https://"), None, "\n{}", gone.text());
    assert_eq!(
        changed_cells(&before, &gone),
        [],
        "消えた後の画面がホバーする前と違う"
    );
}

/// **吹き出しの上へ動いても出たまま**（T11bでURLを押す場所になる。リンクから吹き出しへ動く間に消えないように）。
/// 吹き出しからも外れると消える。
#[test]
fn the_tooltip_stays_while_the_pointer_is_on_it() {
    let mut app = one_link();
    let before = draw(&mut app);
    let (x, y) = before.find("リンク");
    let at = right_after(&before, "リンク");
    moved(&mut app, (x, y));
    draw(&mut app);
    assert!(
        !handled(moved(&mut app, (at.0 + 5, at.1))),
        "吹き出しの上で描き直しの合図を返した"
    );
    let still = draw(&mut app);
    assert_eq!(still.find(&label(URL)), at, "吹き出しの上へ動いたら消えた");
    let beyond = at.0 + label(URL).width() as u16 + 3;
    assert!(handled(moved(&mut app, (beyond, at.1))));
    assert_eq!(draw(&mut app).try_find("(https://"), None);
}

/// **再描画の合図は、指しているリンクが変わったときだけ**（計画書§3.3。`only_events_that_can_change_something_are_redrawn`の
/// リンクの側）。同じリンクの中を動く・リンクの無い所を動くのは描き直さない（マウスを動かすたびに描き続けない）。
/// Ctrlを押したままの移動も同じ（T11bのCtrl＋クリックの前に、指しているリンクを見せる）。
#[test]
fn moving_redraws_only_when_the_hovered_link_changes() {
    for modifiers in [KeyModifiers::NONE, KeyModifiers::CONTROL] {
        let mut app = one_link();
        let screen = draw(&mut app);
        let (x, y) = screen.find("リンク");
        let (ox, oy) = screen.find("リンクの無い行");
        let steps = [
            ((ox, oy), false, "リンクの無い所"),
            ((x, y), true, "リンクの上へ"),
            ((x + 4, y), false, "同じリンクの中"),
            ((ox, oy), true, "リンクの外へ"),
            ((ox + 4, oy), false, "リンクの無い所の中"),
        ];
        for (at, expected, what) in steps {
            assert_eq!(
                handled(moved_with(&mut app, at, modifiers)),
                expected,
                "{what}（{modifiers:?}）"
            );
            draw(&mut app);
        }
    }
}

/// **折り返しで2行に分かれたリンクは、どちらの行を指しても、吹き出しはリンクの最後の文字の後ろ**（最後の行）に出る。
/// 1行目から2行目へ動いても同じリンクなので描き直さない。
#[test]
fn a_wrapped_link_shows_the_tooltip_after_its_last_part_from_either_part() {
    let url = "https://b.x";
    let mut app = app_with_items(&[&format!(
        "{} [二つ目のとても長いリンク]({url}) 後",
        "あ".repeat(46)
    )]);
    let screen = draw(&mut app);
    let (first_x, first_y) = screen.find("二つ");
    let (last_x, last_y) = screen.find("リンク");
    assert_eq!(
        last_y,
        first_y + 1,
        "折り返していない（試験の前提）:\n{}",
        screen.text()
    );
    let at = right_after(&screen, "リンク");

    assert!(handled(moved(&mut app, (first_x, first_y))));
    assert_eq!(draw(&mut app).find(&label(url)), at, "1行目を指したとき");
    assert!(
        !handled(moved(&mut app, (last_x, last_y))),
        "同じリンクの2行目へ動いて描き直した"
    );
    assert_eq!(draw(&mut app).find(&label(url)), at, "2行目を指したとき");
}

/// **右端で入り切らなければ次の行**に、枠の内側の右端に揃えて出す。
#[test]
fn near_the_right_edge_the_tooltip_goes_to_the_next_row() {
    let url = "https://e.x/abc";
    let mut app = app_with_items(&[&format!("{} [端]({url})", "x".repeat(90)), "下の行"]);
    let screen = draw(&mut app);
    let (x, y) = screen.find("端");
    moved(&mut app, (x, y));
    let shown = draw(&mut app);
    // 枠の内側は1〜98桁（右の枠線は99桁）。吹き出しの最後の文字を98桁に置く。
    let width = label(url).width() as u16;
    assert_eq!(
        shown.find(&label(url)),
        (99 - width, y + 1),
        "\n{}",
        shown.text()
    );
}

/// **枠の内側より長いURLは、頭を残して末尾を`…`で切る**（どこへ飛ぶかを決めるスキームとホストを見せる）。閉じ括弧は残す。
#[test]
fn a_url_longer_than_the_transcript_is_cut_at_the_end() {
    let url = format!("https://example.com/{}", "p".repeat(150));
    let mut app = app_with_items(&[&format!("[長い]({url})"), "下の行"]);
    let screen = draw(&mut app);
    let (x, y) = screen.find("長い");
    moved(&mut app, (x, y));
    let shown = draw(&mut app);
    // 枠の内側の98桁いっぱい: `(`・URLの頭95文字・`…`・`)`。
    let cut = format!("({}…)", &url[..95]);
    assert_eq!(shown.find(&cut), (1, y + 1), "\n{}", shown.text());
}

/// **一番下の行のリンクで次の行が無ければ、1つ上の行**に出す（枠の外には出さない）。
#[test]
fn on_the_bottom_row_the_tooltip_goes_to_the_row_above() {
    let url = "https://e.x/abc";
    let mut items: Vec<String> = (0..40).map(|i| format!("行{i}")).collect();
    items.push(format!("{} [端]({url})", "x".repeat(90)));
    let items: Vec<&str> = items.iter().map(String::as_str).collect();
    let mut app = app_with_items(&items);
    let screen = draw(&mut app);
    let (x, y) = screen.find("端");
    assert_eq!(
        screen.cell((x, y + 1)),
        "─",
        "一番下の行ではない（試験の前提）"
    );
    moved(&mut app, (x, y));
    let width = label(url).width() as u16;
    assert_eq!(draw(&mut app).find(&label(url)), (99 - width, y - 1));
}

/// **承認ダイアログが開いている間は出さない**——ダイアログの外に見えているtranscriptのリンクを指しても、描き直しの
/// 合図も吹き出しも無い。閉じれば、同じ所を指して出る（許可側）。
#[test]
fn no_tooltip_while_the_approval_dialog_is_open() {
    let mut app = app_with_items(&[&format!("[リンク]({URL})"), "下の行"]);
    app.pending_permission = Some(approval_view());
    let screen = draw(&mut app);
    let at = screen.try_find("リンク").unwrap_or_else(|| {
        panic!(
            "ダイアログの外にリンクが見えていない（試験の前提）:\n{}",
            screen.text()
        )
    });
    assert!(
        !handled(moved(&mut app, at)),
        "ダイアログが開いているのに描き直しの合図を返した"
    );
    assert_eq!(draw(&mut app).try_find("(https://"), None);

    app.pending_permission = None;
    draw(&mut app);
    let shown = draw(&mut app);
    assert!(
        shown.try_find(&label(URL)).is_some(),
        "閉じた後に出ない:\n{}",
        shown.text()
    );
}

/// **選び終えた範囲は、ホバーしても外れない**（吹き出しは描いた画面の上に重ねるだけで、選んだ文章の地図を変えない）。
/// 選んでいる途中（左ボタンを押している間）は出さず、離すと出る。
#[test]
fn hovering_keeps_a_finished_selection_and_waits_while_selecting() {
    let mut app = app_with_items(&[&format!("前 [リンク]({URL}) 後"), "選ぶ行です"]);
    let screen = draw(&mut app);
    drag(&mut app, screen.find("選ぶ"), screen.find("です"));
    moved(&mut app, screen.find("リンク"));
    let shown = draw(&mut app);
    assert!(shown.try_find(&label(URL)).is_some());
    assert_eq!(
        shown.style(screen.find("選ぶ")).bg,
        Some(Color::Blue),
        "選んだ色が消えた"
    );
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some("選ぶ行で"), "{other}");

    // リンクの文字の上で押している間は出さない（選び始めるかもしれない）。離すと出る。
    let now = Instant::now();
    let at = screen.find("リンク");
    event_then_draw(&mut app, MouseEventKind::Down(MouseButton::Left), at, now);
    assert_eq!(
        draw(&mut app).try_find("(https://"),
        None,
        "押している間に出た"
    );
    event_then_draw(&mut app, MouseEventKind::Up(MouseButton::Left), at, now);
    assert!(
        draw(&mut app).try_find(&label(URL)).is_some(),
        "離した後に出ない"
    );
}

/// **流れ込んで文字が動いても、止まったマウスの下のリンクを描くたびに引き直す**——下端に貼り付いたtranscriptに
/// 行が足されると文章が上へずれる。マウスの下へ別のリンクが来れば吹き出しはそのリンクのものになり、リンクでない文字が
/// 来れば消える（マウスは動かしていない）。
#[test]
fn streaming_text_under_a_still_pointer_re_resolves_the_link() {
    let mut app = app_with_items(&(0..30).map(|_| "前の行").collect::<Vec<_>>());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta {
        text: "前 [一つ目](https://a.x) 後\n\n空き\n\n前 [二つ目](https://b.x) 後".to_string(),
    });
    let screen = draw(&mut app);
    let (x, y) = screen.find("一つ目");
    moved(&mut app, (x + 2, y));
    assert_eq!(
        draw(&mut app).find("(https://a.x)"),
        right_after(&screen, "一つ目")
    );

    // 4行足す——4行下にあった「二つ目」がマウスの下へ来る。
    app.apply(AgentEvent::TextDelta {
        text: "\n\n追加\n\n追加".to_string(),
    });
    let moved_up = draw(&mut app);
    assert_eq!(
        moved_up.find("二つ目"),
        (x, y),
        "文章が4行ずれていない（試験の前提）"
    );
    assert_eq!(moved_up.try_find("(https://a.x)"), None);
    assert_eq!(
        moved_up.find("(https://b.x)"),
        right_after(&moved_up, "二つ目")
    );

    // さらに2行——マウスの下はリンクでない文字。
    app.apply(AgentEvent::TextDelta {
        text: "\n\n終わり".to_string(),
    });
    let off = draw(&mut app);
    assert_eq!(off.try_find("(https://"), None, "\n{}", off.text());
}

/// **画像の代わりの文字は、画像のURLへのリンク**（リンクの書式で描くので、指せば吹き出しが出る。見た目と動きを揃える）。
#[test]
fn an_image_alt_text_shows_the_image_url() {
    let url = "https://e.x/a.png";
    let mut app = app_with_items(&[&format!("![図の説明]({url})")]);
    let screen = draw(&mut app);
    moved(&mut app, screen.find("図の説明"));
    assert_eq!(
        draw(&mut app).find(&label(url)),
        right_after(&screen, "図の説明")
    );
}
