//! マウスのクリックとホイールの回帰テスト（`app::pointer`）。
//!
//! **製品と同じ入口を通す**——画面は製品の描画（`crate::ui::render`）で描いて`apply_draw_feedback`で書き戻し、
//! マウスのイベントは製品のイベントループと同じ[`AppState::handle_event`]へ入れる。押す位置は**描いた画面のセルの
//! 文字から**取る（当たり判定と同じ計算で期待値を作らない——ポリシーエディタのBUG-194の教訓）。期待する状態は、
//! 同じ操作をキーで行った別の`AppState`から作る（クリックが「キーを押したのと同じ」であることを測る）。

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use harness_core::{FilePreview, PermissionSubject, ProgramSubject, RiskClass};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::*;
use crate::app::{
    ApprovalStage, PermissionView, PreviousCopy, ReviewPanelState, ReviewRow, ReviewTarget,
    TranscriptItem, MODAL_INPUT_GRACE,
};

const WIDTH: u16 = 100;
const HEIGHT: u16 = 30;

/// 描いた画面。行ごとに、各セルの記号。
struct Screen(Vec<Vec<String>>);

impl Screen {
    /// `text`が描かれている最初の場所（その最初の文字のセル）。全角文字は2セルを占めるので、
    /// 行の文字列の中の位置ではなく、セルの位置で返す。
    fn find(&self, text: &str) -> (u16, u16) {
        self.try_find(text)
            .unwrap_or_else(|| panic!("「{text}」が画面に無い:\n{}", self.text()))
    }

    fn try_find(&self, text: &str) -> Option<(u16, u16)> {
        for (y, row) in self.0.iter().enumerate() {
            // 文字ごとに、それが描かれたセルの桁を持つ。全角文字の後ろのセル（2桁目）は読まない。
            let mut line = String::new();
            let mut columns = Vec::new();
            let mut second_half = false;
            for (x, symbol) in row.iter().enumerate() {
                if std::mem::take(&mut second_half) {
                    continue;
                }
                for c in symbol.chars() {
                    line.push(c);
                    columns.push(x);
                }
                second_half = unicode_width::UnicodeWidthStr::width(symbol.as_str()) == 2;
            }
            if let Some(byte) = line.find(text) {
                let index = line[..byte].chars().count();
                return Some((columns[index] as u16, y as u16));
            }
        }
        None
    }

    fn cell(&self, (x, y): (u16, u16)) -> &str {
        &self.0[usize::from(y)][usize::from(x)]
    }

    fn text(&self) -> String {
        self.0
            .iter()
            .map(|row| row.concat())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 見出しが`title`で始まる枠の右の枠線（角を除く、上から下まで。下の角は`┘`か仕切りの`┤`）。
    fn right_border(&self, title: &str) -> Vec<String> {
        let (x, top) = self.find(title);
        let row = &self.0[usize::from(top)];
        let right = (usize::from(x)..row.len())
            .find(|&c| row[c] == "┐")
            .expect("右上の角");
        (usize::from(top) + 1..self.0.len())
            .map(|y| self.0[y][right].clone())
            .take_while(|cell| cell != "┘" && cell != "┤")
            .collect()
    }
}

/// 製品と同じ形で1フレーム描き、描いて分かったことを状態へ書き戻す（`crate::run`の描画ループと同じ順）。
fn draw(app: &mut AppState) -> Screen {
    let mut term = Terminal::new(TestBackend::new(WIDTH, HEIGHT)).expect("test terminal");
    let mut feedback = DrawFeedback::default();
    term.draw(|f| feedback = crate::ui::render(f, app))
        .expect("draw");
    app.apply_draw_feedback(feedback);
    let buffer = term.backend().buffer();
    Screen(
        (0..HEIGHT)
            .map(|y| {
                (0..WIDTH)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect()
            })
            .collect(),
    )
}

fn mouse(app: &mut AppState, kind: MouseEventKind, (column, row): (u16, u16)) -> Step {
    app.handle_event(Event::Mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }))
}

fn click(app: &mut AppState, at: (u16, u16)) -> Option<Action> {
    match mouse(app, MouseEventKind::Down(MouseButton::Left), at) {
        Step::Handled(action) => action,
        Step::Unchanged => panic!("左クリックが描き直さない扱いになった"),
    }
}

fn wheel(app: &mut AppState, at: (u16, u16), up: bool) {
    let kind = if up {
        MouseEventKind::ScrollUp
    } else {
        MouseEventKind::ScrollDown
    };
    assert!(matches!(mouse(app, kind, at), Step::Handled(None)));
}

fn press_key(app: &mut AppState, key: KeyEvent) -> Option<Action> {
    match app.handle_event(Event::Key(key)) {
        Step::Handled(action) => action,
        Step::Unchanged => panic!("キーの押下が描き直さない扱いになった"),
    }
}

fn press(app: &mut AppState, code: KeyCode) -> Option<Action> {
    press_key(app, KeyEvent::new(code, KeyModifiers::NONE))
}

/// 返った操作の比べ方（`Action`は比較を実装していないので、中身ごと文字にする）。
fn shown(action: &Option<Action>) -> String {
    format!("{action:?}")
}

fn app_with_transcript(lines: usize) -> AppState {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for i in 0..lines {
        app.transcript
            .push(TranscriptItem::Assistant(format!("transcript line {i}")));
    }
    app
}

/// 入力を捨てる窓（D-106）を過ぎた承認待ち。`git log -n 5`（毎回変わってよい引数の候補は`log`と`5`）。
/// 縛ったファイルの中身と前回の写しを持たせ、`[v]`・`[f]`も出す。
fn approval_view() -> PermissionView {
    let mut subject = ProgramSubject::plain(
        "git",
        vec!["log".to_string(), "-n".to_string(), "5".to_string()],
    );
    subject.previews = vec![FilePreview {
        rel_path: "notes.txt".to_string(),
        text: "new text".to_string(),
        truncated: false,
    }];
    let mut view = PermissionView::new(
        "perm-0".to_string(),
        "run_program".to_string(),
        RiskClass::Exec,
        PermissionSubject::Program(subject),
        "{}".to_string(),
        None,
        "C:/ws".to_string(),
    );
    view.previous = Some(vec![PreviousCopy {
        rel_path: "notes.txt".to_string(),
        text: Ok("old text".to_string()),
    }]);
    view.opened_at = Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
    view
}

fn pending_app(transcript: usize) -> AppState {
    let mut app = app_with_transcript(transcript);
    app.pending_permission = Some(approval_view());
    app
}

/// 承認待ちの状態（段・開いている枠・選んだ穴・候補のカーソル・送り位置）と、承認待ちが残っているか。
fn approval_state(app: &AppState) -> String {
    match &app.pending_permission {
        Some(v) => format!(
            "{:?} {:?} {:?} {} {}",
            v.stage,
            v.pane,
            v.selected_holes(),
            v.cursor(),
            v.scroll
        ),
        None => "閉じた".to_string(),
    }
}

// --- 承認ダイアログ ---

/// **選ぶ段の各ボタンは、そのキーを押したのと同じ。** `[y]`（一度だけ許可）も押せる——ポリシーエディタの確認画面の
/// `y=書く`をクリックで押せるようにしたのに倣う。返る操作と、ダイアログに残る状態の両方を比べる。
#[test]
fn clicking_each_approval_button_does_what_its_key_does() {
    for (label, code) in [
        ("[y]", KeyCode::Char('y')),
        ("[a]", KeyCode::Char('a')),
        ("[n]", KeyCode::Char('n')),
        ("[d]", KeyCode::Char('d')),
        ("[v]", KeyCode::Char('v')),
        ("[f]", KeyCode::Char('f')),
    ] {
        let mut clicked = pending_app(5);
        let screen = draw(&mut clicked);
        let by_click = click(&mut clicked, screen.find(label));

        let mut pressed = pending_app(5);
        let by_key = press(&mut pressed, code);

        assert_eq!(shown(&by_click), shown(&by_key), "{label}");
        assert_eq!(
            approval_state(&clicked),
            approval_state(&pressed),
            "{label}"
        );
    }
    // 許可側の確かめ: `[y]`は実際に応答を返す（何も起きないクリックどうしを比べて緑、ではない）。
    let mut app = pending_app(5);
    let screen = draw(&mut app);
    let action = click(&mut app, screen.find("[y]"));
    assert!(
        matches!(action, Some(Action::Respond(ref id, harness_engine::Decision::Allow)) if id == "perm-0"),
        "{action:?}"
    );
}

/// **開いてから300ms未満のクリックは、キーと同じく捨てる**（D-106）。窓を過ぎれば同じクリックが効く（対）。
#[test]
fn a_click_within_the_grace_window_is_discarded_like_a_key() {
    let mut app = pending_app(5);
    app.pending_permission.as_mut().expect("承認待ち").opened_at = Instant::now();
    let screen = draw(&mut app);
    assert!(click(&mut app, screen.find("[y]")).is_none());
    assert!(click(&mut app, screen.find("[a]")).is_none());
    assert_eq!(
        app.pending_permission.as_ref().map(|v| v.stage),
        Some(ApprovalStage::Choose),
        "確認の一段へも進まない"
    );

    app.pending_permission.as_mut().expect("承認待ち").opened_at =
        Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
    let screen = draw(&mut app);
    assert!(matches!(
        click(&mut app, screen.find("[y]")),
        Some(Action::Respond(..))
    ));
    assert!(app.pending_permission.is_none());
}

/// 確認の段: **候補の行を押すと、そこへ移って`Space`を押したのと同じ**。`Enter 確定`・`Esc 戻る`もキーと同じ。
#[test]
fn the_confirm_stage_candidates_and_buttons_work_like_their_keys() {
    let mut clicked = pending_app(5);
    press(&mut clicked, KeyCode::Char('a'));
    let screen = draw(&mut clicked);
    // 候補は`  [ ] [0] log`と`  [ ] [2] 5`。2つ目を押す。
    click(&mut clicked, screen.find("[ ] [2] 5"));

    let mut pressed = pending_app(5);
    press(&mut pressed, KeyCode::Char('a'));
    press(&mut pressed, KeyCode::Down);
    press(&mut pressed, KeyCode::Char(' '));
    assert_eq!(approval_state(&clicked), approval_state(&pressed));
    assert_eq!(
        clicked
            .pending_permission
            .as_ref()
            .map(|v| v.selected_holes()),
        Some(vec![2]),
        "押した候補が穴になっていない"
    );

    // 確定。
    let screen = draw(&mut clicked);
    let by_click = click(&mut clicked, screen.find("Enter 確定"));
    let by_key = press(&mut pressed, KeyCode::Enter);
    assert_eq!(shown(&by_click), shown(&by_key));
    assert!(
        matches!(by_click, Some(Action::RespondRemember(_, ref holes)) if holes == &[2]),
        "{by_click:?}"
    );

    // 戻る。
    let mut app = pending_app(5);
    press(&mut app, KeyCode::Char('a'));
    let screen = draw(&mut app);
    assert!(click(&mut app, screen.find("Esc 戻る")).is_none());
    assert_eq!(
        app.pending_permission.as_ref().map(|v| v.stage),
        Some(ApprovalStage::Choose)
    );
}

/// **承認待ちの間のホイールは、ポインタの位置で分かれる**——ダイアログの上ならダイアログの本文を、外に見えている
/// transcriptの上ならtranscriptを送る（基盤フェーズM09の「承認待ちの間も前の会話を読み返せる」を保つ。
/// ポリシーエディタはここが違い、重ねた枠が開いている間は後ろを送らない）。
#[test]
fn mouse_scroll_works_even_while_permission_modal_is_pending() {
    let mut app = pending_app(100);
    // 本文が枠に入り切らないよう、引数を60個にする。
    app.pending_permission = Some({
        let mut view = PermissionView::new(
            "perm-0".to_string(),
            "run_program".to_string(),
            RiskClass::Exec,
            PermissionSubject::Program(ProgramSubject::plain(
                "git",
                (0..60).map(|i| format!("arg{i}")).collect(),
            )),
            "{}".to_string(),
            None,
            "C:/ws".to_string(),
        );
        view.opened_at = Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
        view
    });
    let screen = draw(&mut app);
    // transcriptの枠の中で、ダイアログより左に見えている所。
    let (dialog_left, _) = screen.find("承");
    let outside = (dialog_left / 2, 2);
    assert!(
        screen.cell(outside) != "│",
        "試験の前提: そこはtranscriptの中"
    );
    wheel(&mut app, outside, true);
    assert_eq!(
        app.scroll_offset(),
        3,
        "外に見えているtranscriptが送られない"
    );
    assert_eq!(app.pending_permission.as_ref().map(|v| v.scroll), Some(0));

    // ダイアログの本文の上で回すと、ダイアログが送られ、transcriptは動かない。
    let inside = screen.find("[3] arg3");
    wheel(&mut app, inside, false);
    assert_eq!(app.pending_permission.as_ref().map(|v| v.scroll), Some(3));
    assert_eq!(app.scroll_offset(), 3);
    // ダイアログのボタンの上でも、本文が送られる（ボタンはクリックだけを受ける）。
    let screen = draw(&mut app);
    wheel(&mut app, screen.find("[n]"), false);
    assert_eq!(app.pending_permission.as_ref().map(|v| v.scroll), Some(6));
}

/// **承認待ちの間、後ろの画面は押せない**——入力欄の`Esc=中断`を押しても、承認ダイアログの`Esc`（拒否）には
/// ならない。transcriptの本文・ダイアログの中の何も無い所も、何も変えない。
#[test]
fn nothing_behind_the_approval_dialog_or_off_its_buttons_can_be_clicked() {
    let mut app = pending_app(100);
    let screen = draw(&mut app);
    let before = approval_state(&app);
    for place in [
        screen.find("Esc=中断"),
        screen.find("Ctrl-C"),
        (1, 2),
        screen.find("program: git"),
        screen.find("PageUp/PageDown ス"),
    ] {
        assert!(click(&mut app, place).is_none(), "{place:?}");
        assert_eq!(approval_state(&app), before, "{place:?}");
        assert!(!app.should_quit);
    }
}

/// **スクロールバーは本文が入り切らないときだけ出る**（承認ダイアログの本文の右の枠線）。
#[test]
fn the_approval_scrollbar_appears_only_when_the_body_overflows() {
    let mut short = pending_app(0);
    let border = draw(&mut short).right_border("承");
    assert!(border.iter().all(|c| c == "│"), "{border:?}");

    let mut long = pending_app(0);
    long.pending_permission
        .as_mut()
        .expect("承認待ち")
        .on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
    if let Some(view) = long.pending_permission.as_mut() {
        if let PermissionSubject::Program(p) = &mut view.subject {
            p.previews[0].text = (0..80).map(|i| format!("content {i}\n")).collect();
        }
    }
    let border = draw(&mut long).right_border("承");
    assert!(border.iter().any(|c| c == "█"), "{border:?}");
}

// --- transcriptと入力欄 ---

/// **transcriptの「さかのぼり中」の案内を押すと末尾へ戻る**。transcriptの本文を押しても何も起きない（対）。
#[test]
fn the_scrolled_back_notice_returns_to_the_latest_lines() {
    let mut app = app_with_transcript(100);
    app.scroll_lines(5);
    let screen = draw(&mut app);
    assert!(click(&mut app, screen.find("transcript line 90")).is_none());
    assert_eq!(app.scroll_offset(), 5, "本文を押しただけで戻った");
    assert!(click(&mut app, screen.find("[5")).is_none());
    assert_eq!(app.scroll_offset(), 0);
    // 戻った後は案内が消え、そこは押せない。
    let screen = draw(&mut app);
    assert!(screen.try_find("[5").is_none());
}

/// **transcriptのスクロールバーは入り切らないときだけ出る**（右の枠線）。
#[test]
fn the_transcript_scrollbar_appears_only_when_it_overflows() {
    let mut short = app_with_transcript(3);
    assert!(draw(&mut short)
        .right_border("transcript")
        .iter()
        .all(|c| c == "│"));
    let mut long = app_with_transcript(100);
    assert!(draw(&mut long)
        .right_border("transcript")
        .iter()
        .any(|c| c == "█"));
}

/// **入力欄の見出しのキー案内は、そのキーを押したのと同じ**（`Esc=中断`・送信・`Ctrl-C=終了`）。
/// `PageUp/PageDown=スクロール`は1つのキーに決まらないので押せない。
#[test]
fn the_input_title_hints_press_their_keys() {
    let mut app = app_with_transcript(3);
    let screen = draw(&mut app);
    assert!(matches!(
        click(&mut app, screen.find("Esc=中断")),
        Some(Action::Cancel)
    ));
    assert!(click(&mut app, screen.find("PageUp/PageDown=")).is_none());
    assert_eq!(app.scroll_offset(), 0);

    for c in "hi".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    let mut by_key = app_with_transcript(3);
    for c in "hi".chars() {
        press(&mut by_key, KeyCode::Char(c));
    }
    let screen = draw(&mut app);
    let sent = click(&mut app, screen.find("Shift+Enter=送信"));
    let expected = press_key(
        &mut by_key,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
    );
    assert_eq!(shown(&sent), shown(&expected));
    assert!(
        matches!(sent, Some(Action::Submit(ref text)) if text == "hi"),
        "{sent:?}"
    );

    let screen = draw(&mut app);
    assert!(matches!(
        click(&mut app, screen.find("Ctrl-C")),
        Some(Action::Quit)
    ));
    assert!(app.should_quit);
}

/// **ポインタが動いただけ・キーを離しただけのイベントは描き直さない**（`Step::Unchanged`）。押下とホイールは
/// 何にも当たらない場所でも描き直す（今までどおり）。
#[test]
fn only_events_that_can_change_something_are_redrawn() {
    let mut app = app_with_transcript(3);
    draw(&mut app);
    for kind in [
        MouseEventKind::Moved,
        MouseEventKind::Up(MouseButton::Left),
        MouseEventKind::Drag(MouseButton::Left),
        MouseEventKind::Down(MouseButton::Right),
    ] {
        assert!(
            matches!(mouse(&mut app, kind, (5, 5)), Step::Unchanged),
            "{kind:?}"
        );
    }
    for kind in [
        MouseEventKind::Down(MouseButton::Left),
        MouseEventKind::ScrollUp,
        MouseEventKind::ScrollDown,
    ] {
        assert!(
            matches!(mouse(&mut app, kind, (5, 5)), Step::Handled(_)),
            "{kind:?}"
        );
    }
    let mut release = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
    release.kind = crossterm::event::KeyEventKind::Release;
    assert!(matches!(
        app.handle_event(Event::Key(release)),
        Step::Unchanged
    ));
    assert_eq!(app.input, "", "離したキーが入力された");
    assert!(matches!(
        app.handle_event(Event::Resize(80, 20)),
        Step::Handled(None)
    ));
}

// --- レビューパネル ---

/// 離れた2箇所を書き換えた（ハンク2つの）行。`lines`行のファイル。
fn review_row(label: &str, lines: usize) -> ReviewRow {
    let old: String = (0..lines).map(|i| format!("line{i}\n")).collect();
    let new = old
        .replace("line2\n", "CHANGED2\n")
        .replace(&format!("line{}\n", lines - 5), "CHANGED_LATE\n");
    ReviewRow {
        label: label.to_string(),
        badge: 'M',
        review: harness_sandbox::FileReview {
            hunks: harness_sandbox::textdiff::diff_hunks(&old, &new),
            hunk_block: None,
            workspace_hash: Some(format!("ws-{label}")),
            overlay_hash: Some(format!("ov-{label}")),
        },
        target: ReviewTarget::Change {
            path: label.to_string(),
        },
    }
}

/// 1行おきに50行を書き換えた、差分ペインに入り切らない1つのハンクを持つ行。
fn long_row(label: &str) -> ReviewRow {
    let old: String = (0..80)
        .map(|i| {
            format!(
                "line{i}
"
            )
        })
        .collect();
    let new: String = (0..80)
        .map(|i| match (10..60).contains(&i) && i % 2 == 0 {
            true => format!(
                "CHANGED{i}
"
            ),
            false => format!(
                "line{i}
"
            ),
        })
        .collect();
    ReviewRow {
        review: harness_sandbox::FileReview {
            hunks: harness_sandbox::textdiff::diff_hunks(&old, &new),
            ..review_row(label, 30).review
        },
        ..review_row(label, 30)
    }
}

fn review_app(rows: Vec<ReviewRow>) -> AppState {
    let mut app = app_with_transcript(100);
    app.open_changes_panel(rows);
    app
}

fn three_rows() -> Vec<ReviewRow> {
    vec![
        review_row("a.txt", 30),
        review_row("b.txt", 30),
        review_row("c.txt", 30),
    ]
}

fn panel(app: &AppState) -> &ReviewPanelState {
    app.review_panel
        .as_ref()
        .expect("レビューパネルが開いている")
}

/// パネルの状態（選択・フォーカス・行と各ハンクの取り込み・ハンクのカーソル・差分の送り位置）。
fn panel_state(app: &AppState) -> String {
    match &app.review_panel {
        Some(p) => {
            let mut rejected: Vec<_> = p.rejected.iter().copied().collect();
            rejected.sort();
            let mut hunks: Vec<_> = p
                .rejected_hunks
                .iter()
                .map(|(row, set)| {
                    let mut set: Vec<_> = set.iter().copied().collect();
                    set.sort();
                    (*row, set)
                })
                .collect();
            hunks.sort();
            format!(
                "選択{} {:?} 外す{rejected:?} ハンク{hunks:?} カーソル{} 送り{}",
                p.selected, p.focus, p.hunk_cursor, p.diff_scroll
            )
        }
        None => "閉じた".to_string(),
    }
}

/// **一覧の行を押すと選ぶ（`↓`と同じ）。取り込みの印を押すと、その行を選んで`Enter`と同じ。**
#[test]
fn clicking_a_review_row_and_its_mark_works_like_the_keys() {
    let mut clicked = review_app(three_rows());
    let screen = draw(&mut clicked);
    assert!(click(&mut clicked, screen.find("c.txt")).is_none());
    let mut pressed = review_app(three_rows());
    press(&mut pressed, KeyCode::Down);
    press(&mut pressed, KeyCode::Down);
    assert_eq!(panel_state(&clicked), panel_state(&pressed));
    assert_eq!(panel(&clicked).selected, 2);

    let screen = draw(&mut clicked);
    assert!(click(&mut clicked, screen.find("[x] M b.txt")).is_none());
    press(&mut pressed, KeyCode::Up);
    press(&mut pressed, KeyCode::Enter);
    assert_eq!(panel_state(&clicked), panel_state(&pressed));
    assert!(
        panel(&clicked).rejected.contains(&1),
        "印を押した行が外れていない"
    );
}

/// **ペインを押すとそちらへフォーカスが移る（`Tab`と同じ）。** 差分のハンクの見出しを押すとそのハンクを選び
/// （差分は送らない——押した見出しが動かない）、見出しの印を押すとそのハンクを選んで`Enter`と同じ。
#[test]
fn clicking_the_diff_pane_and_its_hunk_headers() {
    let mut clicked = review_app(three_rows());
    let screen = draw(&mut clicked);
    // 差分の文脈の行（見出しではない所）を押す。
    click(&mut clicked, screen.find("line0"));
    let mut pressed = review_app(three_rows());
    press(&mut pressed, KeyCode::Tab);
    assert_eq!(panel_state(&clicked), panel_state(&pressed));
    assert_eq!(panel(&clicked).focus, ReviewFocus::Diff);

    // 一覧を押すと、一覧へ戻る（`Tab`）。
    let screen = draw(&mut clicked);
    click(&mut clicked, screen.find("changes"));
    assert_eq!(panel(&clicked).focus, ReviewFocus::List);

    // 2つ目のハンクの見出し。
    let screen = draw(&mut clicked);
    let header = screen.find("hunk 2/2");
    let before = panel(&clicked).diff_scroll;
    click(&mut clicked, header);
    assert_eq!(panel(&clicked).focus, ReviewFocus::Diff);
    assert_eq!(panel(&clicked).hunk_cursor, 1);
    assert_eq!(
        panel(&clicked).diff_scroll,
        before,
        "押した見出しが送られて動いた"
    );
    let screen = draw(&mut clicked);
    assert_eq!(screen.find("hunk 2/2"), header, "押した見出しが動いた");

    // 見出しの印。
    click(&mut clicked, screen.find("[x] hunk 2/2"));
    assert!(
        panel(&clicked).is_hunk_rejected(0, 1),
        "印を押したハンクが外れていない"
    );
    let mut pressed = review_app(three_rows());
    press(&mut pressed, KeyCode::Tab);
    press(&mut pressed, KeyCode::Down);
    press(&mut pressed, KeyCode::Enter);
    assert_eq!(
        panel(&clicked).rejected_hunks,
        panel(&pressed).rejected_hunks
    );
}

/// **パネルの案内の`c=commit`・`Esc=close`はそのキーと同じ。`x=discard-all`は押せない**（確認なしに全部捨てる
/// 一括の操作なので、キーでだけ押せる）。`↑↓ select`も押せない。
#[test]
fn the_review_hints_press_their_keys_except_discard_all() {
    let mut clicked = review_app(three_rows());
    let screen = draw(&mut clicked);
    for label in ["x=discard-all", "↑↓ select"] {
        assert!(click(&mut clicked, screen.find(label)).is_none(), "{label}");
        assert!(clicked.review_panel.is_some(), "{label}");
    }
    let committed = click(&mut clicked, screen.find("c=commit"));
    let mut pressed = review_app(three_rows());
    let expected = press(&mut pressed, KeyCode::Char('c'));
    assert_eq!(shown(&committed), shown(&expected));
    assert!(
        matches!(committed, Some(Action::CommitChanges(_))),
        "{committed:?}"
    );

    let mut app = review_app(three_rows());
    let screen = draw(&mut app);
    assert!(click(&mut app, screen.find("Esc=close")).is_none());
    assert!(app.review_panel.is_none());
}

/// **パネルが開いている間のホイールもポインタの位置で分かれる**——差分ペインは差分を、一覧は選択を、外に
/// 見えているtranscriptはtranscriptを送る。後ろの入力欄は押せない。
#[test]
fn the_wheel_under_the_review_panel_moves_what_is_under_the_pointer() {
    let mut app = review_app(vec![long_row("a.txt"), long_row("b.txt")]);
    let screen = draw(&mut app);
    wheel(&mut app, screen.find("line10"), false);
    assert_eq!(panel(&app).diff_scroll, 3);
    draw(&mut app);
    assert_eq!(
        panel(&app).diff_scroll,
        3,
        "入り切らない差分なので、描いた後も送った位置のまま"
    );
    assert_eq!(app.scroll_offset(), 0);

    let screen = draw(&mut app);
    wheel(&mut app, screen.find("a.txt"), false);
    assert_eq!(panel(&app).selected, 1);

    let screen = draw(&mut app);
    let (panel_left, _) = screen.find("changes");
    wheel(&mut app, (panel_left / 2, 1), true);
    assert_eq!(
        app.scroll_offset(),
        3,
        "外に見えているtranscriptが送られない"
    );

    let screen = draw(&mut app);
    let before = panel_state(&app);
    assert!(click(&mut app, screen.find("Esc=中断")).is_none());
    assert_eq!(panel_state(&app), before);
}

/// [BUG-204] **差分ペインは最後の行が枠の一番下に来るところまで送れ、その先へは行かない。** 送り位置は描いて
/// 分かる上限で切り詰められ、入り切らないときだけ右の枠線にスクロールバーが出る。
#[test]
fn the_diff_pane_scrolls_to_its_last_line_at_the_bottom_and_shows_a_scrollbar() {
    let mut short = review_app(three_rows());
    let screen = draw(&mut short);
    assert!(screen.right_border("diff").iter().all(|c| c == "│"));

    let mut app = review_app(vec![long_row("a.txt")]);
    let screen = draw(&mut app);
    assert!(screen.right_border("diff").iter().any(|c| c == "█"));
    // 差分ペインの見出しの上で回す（見出しの行もペインの中。本文は送ると動くので、動かない所で回す）。
    for _ in 0..50 {
        let screen = draw(&mut app);
        wheel(&mut app, screen.find("diff"), false);
    }
    let screen = draw(&mut app);
    let stopped = panel(&app).diff_scroll;
    // 一番下まで送った画面に、差分の最後の行が出ている。
    let view = panel(&app).diff_view();
    let Some(crate::app::ReviewDiffLine::Line(_, last)) = view.last() else {
        panic!("最後の行が差分の行でない");
    };
    assert!(
        screen.try_find(&format!("  {last}")).is_some(),
        "{}",
        screen.text()
    );
    assert!(usize::from(stopped) < view.len() - 1);
    // 戻すと、1刻み（3行）ですぐ動く（先で回した分が溜まっていない。BUG-076）。
    let screen = draw(&mut app);
    wheel(&mut app, screen.find("diff"), true);
    assert_eq!(panel(&app).diff_scroll, stopped - 3);
}

/// **一覧は枠より下の行を黙って切らない**——選んだ行は必ず見え、入り切らないときは右の枠線にスクロールバーが
/// 出る。見えている行を押せば、その行が選ばれる。
#[test]
fn a_long_review_list_keeps_the_selected_row_visible() {
    let rows: Vec<ReviewRow> = (0..40)
        .map(|i| review_row(&format!("file{i:02}.txt"), 30))
        .collect();
    let mut app = review_app(rows);
    let screen = draw(&mut app);
    assert!(screen.right_border("changes").iter().any(|c| c == "█"));
    assert!(
        screen.try_find("file39.txt").is_none(),
        "試験の前提: 末尾は窓の外"
    );
    for _ in 0..39 {
        press(&mut app, KeyCode::Down);
    }
    let screen = draw(&mut app);
    assert!(
        screen.try_find(">[x] M file39.txt").is_some(),
        "選んだ行が見えない:\n{}",
        screen.text()
    );
    // 窓の中を上へ動いても、一覧は滑らず選択が動く（表示を始める位置を持ち越している）。
    press(&mut app, KeyCode::Up);
    let moved = draw(&mut app);
    assert_eq!(moved.find("file39.txt").1, screen.find("file39.txt").1);
    click(&mut app, moved.find("file35.txt"));
    assert_eq!(panel(&app).selected, 35);
}
