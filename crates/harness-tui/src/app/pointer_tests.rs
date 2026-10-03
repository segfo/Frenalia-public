//! マウスのクリックとホイールの回帰テスト（`app::pointer`）。
//!
//! **製品と同じ入口を通す**——画面は製品の描画（`crate::ui::render`）で描いて`apply_draw_feedback`で書き戻し、
//! マウスのイベントは製品のイベントループと同じ[`AppState::handle_event`]へ入れる。押す位置は**描いた画面のセルの
//! 文字から**取る（当たり判定と同じ計算で期待値を作らない——ポリシーエディタのBUG-194の教訓）。期待する状態は、
//! 同じ操作をキーで行った別の`AppState`から作る（クリックが「キーを押したのと同じ」であることを測る）。

use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use harness_core::{AgentEvent, FilePreview, PermissionSubject, ProgramSubject, RiskClass};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier, Style};
use ratatui::Terminal;

use super::*;
use crate::app::{
    ApprovalStage, PermissionView, PreviousCopy, ReviewPanelState, ReviewRow, ReviewTarget,
    TranscriptItem, MODAL_INPUT_GRACE,
};

const WIDTH: u16 = 100;
const HEIGHT: u16 = 30;

/// 描いた画面。行ごとに、各セルの記号と見た目（背景・太字などの`Style`）。
struct Screen(Vec<Vec<String>>, Vec<Vec<Style>>);

impl Screen {
    /// `text`が描かれている最初の場所（その最初の文字のセル）。全角文字は2セルを占めるので、
    /// 行の文字列の中の位置ではなく、セルの位置で返す。
    fn find(&self, text: &str) -> (u16, u16) {
        self.try_find(text)
            .unwrap_or_else(|| panic!("「{text}」が画面に無い:\n{}", self.text()))
    }

    fn try_find(&self, text: &str) -> Option<(u16, u16)> {
        for y in 0..self.0.len() {
            let (line, columns) = self.line(y);
            if let Some(byte) = line.find(text) {
                let index = line[..byte].chars().count();
                return Some((columns[index] as u16, y as u16));
            }
        }
        None
    }

    /// `y`行目の文字と、文字ごとにそれが描かれたセルの桁。全角文字の後ろのセル（2桁目）は読まない。
    fn line(&self, y: usize) -> (String, Vec<usize>) {
        let mut line = String::new();
        let mut columns = Vec::new();
        let mut second_half = false;
        for (x, symbol) in self.0[y].iter().enumerate() {
            if std::mem::take(&mut second_half) {
                continue;
            }
            for c in symbol.chars() {
                line.push(c);
                columns.push(x);
            }
            second_half = unicode_width::UnicodeWidthStr::width(symbol.as_str()) == 2;
        }
        (line, columns)
    }

    fn cell(&self, (x, y): (u16, u16)) -> &str {
        &self.0[usize::from(y)][usize::from(x)]
    }

    /// そのセルの見た目。
    fn style(&self, (x, y): (u16, u16)) -> Style {
        self.1[usize::from(y)][usize::from(x)]
    }

    /// `y`行目の文字（[`Self::line`]と同じ読み方）。
    fn row(&self, y: u16) -> String {
        self.line(usize::from(y)).0
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
    draw_sized(app, WIDTH, HEIGHT)
}

/// [`draw`]を`width`×`height`の端末で。
fn draw_sized(app: &mut AppState, width: u16, height: u16) -> Screen {
    let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    let mut feedback = DrawFeedback::default();
    term.draw(|f| feedback = crate::ui::render(f, app))
        .expect("draw");
    app.apply_draw_feedback(feedback);
    let buffer = term.backend().buffer();
    Screen(
        grid(width, height, |x, y| buffer[(x, y)].symbol().to_string()),
        grid(width, height, |x, y| buffer[(x, y)].style()),
    )
}

fn grid<T>(width: u16, height: u16, cell: impl Fn(u16, u16) -> T) -> Vec<Vec<T>> {
    (0..height)
        .map(|y| (0..width).map(|x| cell(x, y)).collect())
        .collect()
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

/// `screen`に描かれた`label`の各文字のセルの見た目（同じものは1つにまとめる。全部同じなら1要素）。
/// 全角文字の後ろのセル（2桁目）は読まない——ratatuiはそこを既定の見た目へ戻し、端末は前のセルの文字で覆う。
fn label_looks(screen: &Screen, label: &str) -> Vec<Style> {
    let (_, y) = screen.find(label);
    let (line, columns) = screen.line(usize::from(y));
    let start = line[..line.find(label).expect("同じ行にある")]
        .chars()
        .count();
    let mut looks: Vec<Style> = columns[start..start + label.chars().count()]
        .iter()
        .map(|&x| screen.style((x as u16, y)))
        .collect();
    looks.dedup();
    looks
}

/// ボタンの見た目（`harness_term::button::active`。会話画面のボタンの色はシアン）か。
fn is_button(look: &Style) -> bool {
    look.bg == Some(Color::Cyan)
        && look.fg == Some(Color::Black)
        && look.add_modifier.contains(Modifier::BOLD)
}

/// **承認ダイアログの押せる選択肢はボタンとして描かれ、押せない案内は文字のまま**（2026-10-03、括弧書きの選択肢が
/// 押せる場所に見えないとユーザーが実機で指摘した）。選ぶ段と確認の段の両方。見た目は描いたセルの背景と太字で見る。
#[test]
fn the_approval_choices_are_buttons_and_the_plain_hints_are_text() {
    let mut app = pending_app(5);
    let screen = draw(&mut app);
    for label in [
        "[y] 一度だけ許可",
        "[a] 恒久的に承認",
        "[n] 拒否",
        "[d] このセッション中は拒否",
        "[v] 中身",
        "[f] 差分",
    ] {
        let looks = label_looks(&screen, label);
        assert!(
            looks.len() == 1 && is_button(&looks[0]),
            "選ぶ段の「{label}」がボタンでない: {looks:?}"
        );
    }
    let scroll = label_looks(&screen, "PageUp/PageDown スクロール");
    assert!(
        scroll.iter().all(|look| !is_button(look)),
        "押せない案内がボタンに見える: {scroll:?}"
    );

    press(&mut app, KeyCode::Char('a'));
    let screen = draw(&mut app);
    for label in ["Enter 確定", "Esc 戻る", "Space 毎回変わってよい引数にする"] {
        let looks = label_looks(&screen, label);
        assert!(
            looks.len() == 1 && is_button(&looks[0]),
            "確認の段の「{label}」がボタンでない: {looks:?}"
        );
    }
    assert!(
        label_looks(&screen, "↑↓ 移動")
            .iter()
            .all(|l| !is_button(l)),
        "押せない「↑↓ 移動」がボタンに見える"
    );
}

/// **入力欄の「送信」「中断」と承認ダイアログの選択肢は、同じ1つの見た目を通る**（共通にした部品が、後から片方だけ
/// 触って別の見た目へ戻らないように。`docs/CODE-STRUCTURE-RULES.md`§5.1の「共通性そのものを固定する」）。
#[test]
fn the_input_buttons_and_the_approval_choices_share_one_look() {
    let mut app = pending_app(5);
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.input = "hi".to_string();
    let screen = draw(&mut app);
    let send = label_looks(&screen, "Shift+Enter=送信");
    let cancel = label_looks(&screen, "Esc=中断");
    let allow = label_looks(&screen, "[y] 一度だけ許可");
    assert_eq!(send, allow);
    assert_eq!(cancel, allow);
    // ボタンの左右の余白（1桁）も同じ見た目で、ボタンの外（枠線）は違う。
    let (x, y) = screen.find("Shift+Enter=送信");
    assert_eq!(screen.style((x - 1, y)), allow[0], "左の余白");
    assert!(!is_button(&screen.style((x - 2, y))), "ボタンの間の1桁");
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

/// **承認待ちの間、後ろの画面は押せない**——入力欄の「中断」ボタンを押しても、承認ダイアログの`Esc`（拒否）には
/// ならない。「送信」ボタンも送らない。transcriptの本文・ダイアログの中の何も無い所も、何も変えない。
#[test]
fn nothing_behind_the_approval_dialog_or_off_its_buttons_can_be_clicked() {
    let mut app = pending_app(100);
    // 承認を求められるのはターンの途中なので、後ろの入力欄には「中断」が出ている。入力があれば「送信」も押せる形。
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.input = "hi".to_string();
    let screen = draw(&mut app);
    let before = approval_state(&app);
    for place in [
        screen.find("Esc=中断"),
        screen.find("Shift+Enter=送信"),
        screen.find("Ctrl-C"),
        (1, 2),
        screen.find("program: git"),
        screen.find("PageUp/PageDown ス"),
    ] {
        assert!(click(&mut app, place).is_none(), "{place:?}");
        assert_eq!(approval_state(&app), before, "{place:?}");
        assert!(!app.should_quit);
        assert_eq!(app.input, "hi", "{place:?}: 後ろの送信が効いた");
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

/// 入力欄の枠の上辺と下辺の行（上辺は見出しの`input`がある行。ごく狭い端末では括弧から先が切れる）。
fn input_edges(screen: &Screen) -> (u16, u16) {
    let top = screen.find("input").1;
    let bottom = (top + 1..)
        .take_while(|&y| usize::from(y) < screen.0.len())
        .find(|&y| screen.cell((0, y)) == "└")
        .expect("入力欄の左下の角");
    (top, bottom)
}

/// 入力の状態（送った後に何が残るか）。
fn input_state(app: &AppState) -> String {
    format!(
        "{:?} {} {}",
        app.input,
        app.input_cursor,
        app.transcript.len()
    )
}

fn type_text(app: &mut AppState, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

/// **入力欄の見出しに残ったキー案内は、そのキーを押したのと同じ**（`Enter=改行`・`Ctrl-C=終了`）。
/// `PageUp/PageDown=スクロール`は1つのキーに決まらないので押せない。**送信と中断は見出しから外れて**、
/// 下辺のボタンにだけある（同じ操作を2か所に並べない）。
#[test]
fn the_input_title_hints_press_their_keys() {
    let mut app = app_with_transcript(3);
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    type_text(&mut app, "hi");
    let screen = draw(&mut app);
    let (top, _) = input_edges(&screen);
    let title = screen.row(top);
    assert!(
        !title.contains("送") && !title.contains("中") && !title.contains("Esc"),
        "見出しに送信・中断が残っている: {title}"
    );

    // `Enter=改行`を押すと、Enterを押したのと同じく改行が入る。
    let mut by_key = app_with_transcript(3);
    by_key.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    type_text(&mut by_key, "hi");
    assert!(click(&mut app, screen.find("Enter=改行")).is_none());
    assert!(press(&mut by_key, KeyCode::Enter).is_none());
    assert_eq!(input_state(&app), input_state(&by_key));
    assert_eq!(app.input, "hi\n");

    let screen = draw(&mut app);
    assert!(click(&mut app, screen.find("PageUp/PageDown=")).is_none());
    assert_eq!(app.scroll_offset(), 0);

    let screen = draw(&mut app);
    assert!(matches!(
        click(&mut app, screen.find("Ctrl-C")),
        Some(Action::Quit)
    ));
    assert!(app.should_quit);
}

/// **入力欄の下辺の右に「中断」「送信」のボタンがあり、送信は右下の角のすぐ左で終わる**（ユーザーが指した場所）。
/// 見出しの行には無い。
#[test]
fn the_send_and_cancel_buttons_sit_on_the_bottom_right_of_the_input_box() {
    let mut app = app_with_transcript(3);
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    type_text(&mut app, "hi");
    let screen = draw(&mut app);
    let (_, bottom) = input_edges(&screen);
    let (send_x, send_y) = screen.find("Shift+Enter=送信");
    let (cancel_x, cancel_y) = screen.find("Esc=中断");
    assert_eq!((send_y, cancel_y), (bottom, bottom), "下辺に無い");
    assert!(cancel_x < send_x, "中断が送信の左に無い");
    // 送信の文言の後ろは、余白の1桁、そして右下の角。
    let edge = screen.row(bottom);
    assert!(
        edge.ends_with("Shift+Enter=送信 ┘"),
        "送信が右下の角の手前で終わっていない: {edge}"
    );
    assert_eq!(screen.cell((WIDTH - 1, bottom)), "┘");
}

/// **「送信」ボタンは、送信キーを押したのと同じ**——送るキーは端末と設定で変わり（VS Codeの統合ターミナルは
/// `Alt+Enter`、`enter_submits`なら素の`Enter`）、ボタンの文言とキーはそれに合わせて変わる。返る操作と、送った後の
/// 入力欄・transcriptの両方を、キーで送った別の`AppState`と比べる。
#[test]
fn the_send_button_sends_like_the_send_key() {
    type Setup = fn(&mut AppState);
    let cases: [(&str, Setup, &str, KeyEvent); 3] = [
        (
            "既定",
            |_| {},
            "Shift+Enter=送信",
            KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
        ),
        (
            "VS Code",
            |app| app.host_is_vscode = true,
            "Alt+Enter=送信",
            KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT),
        ),
        (
            "enter_submits",
            |app| app.enter_submits = true,
            "Enter=送信",
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        ),
    ];
    for (case, setup, label, key) in cases {
        let mut clicked = app_with_transcript(3);
        setup(&mut clicked);
        type_text(&mut clicked, "hi");
        let screen = draw(&mut clicked);
        let sent = click(&mut clicked, screen.find(label));

        let mut pressed = app_with_transcript(3);
        setup(&mut pressed);
        type_text(&mut pressed, "hi");
        let expected = press_key(&mut pressed, key);

        assert_eq!(shown(&sent), shown(&expected), "{case}");
        assert!(
            matches!(sent, Some(Action::Submit(ref text)) if text == "hi"),
            "{case}: {sent:?}"
        );
        assert_eq!(input_state(&clicked), input_state(&pressed), "{case}");
        assert_eq!(clicked.input, "", "{case}: 送った後に入力が残った");
    }
    // `enter_submits`では、素のEnterは送信なので見出しに`Enter=改行`を出さない。
    let mut app = app_with_transcript(3);
    app.enter_submits = true;
    let screen = draw(&mut app);
    assert!(screen.try_find("Enter=改行").is_none(), "{}", screen.text());
}

/// **入力が空白だけの間、「送信」は薄く描かれ、押しても何も起きない**（送信キーも何もしない）。
/// 打てば同じ場所で押せる見た目に変わり、押すと送る（対）。押せないことは、描いたセルの背景で見る。
#[test]
fn the_send_button_is_dim_and_does_nothing_while_the_input_is_blank() {
    for blank in ["", "   ", "\n"] {
        let mut app = app_with_transcript(3);
        app.input = blank.to_string();
        app.input_cursor = blank.chars().count();
        let screen = draw(&mut app);
        let at = screen.find("Shift+Enter=送信");
        let look = screen.style(at);
        assert_eq!(
            look.bg,
            Some(Color::DarkGray),
            "{blank:?}: 薄く描かれていない"
        );
        assert!(!look.add_modifier.contains(Modifier::BOLD), "{blank:?}");
        let before = input_state(&app);
        assert!(click(&mut app, at).is_none(), "{blank:?}");
        assert_eq!(
            input_state(&app),
            before,
            "{blank:?}: 押せないはずの送信で何か変わった"
        );
    }

    let mut app = app_with_transcript(3);
    let blank_at = draw(&mut app).find("Shift+Enter=送信");
    type_text(&mut app, "hi");
    let screen = draw(&mut app);
    let at = screen.find("Shift+Enter=送信");
    assert_eq!(at, blank_at, "打つと送信の場所が動いた");
    assert_eq!(
        screen.style(at).bg,
        Some(Color::Cyan),
        "押せる見た目になっていない"
    );
    assert!(screen.style(at).add_modifier.contains(Modifier::BOLD));
    assert!(matches!(click(&mut app, at), Some(Action::Submit(_))));
}

/// **「中断」は止めるものが走っている間だけ出る**——応答中のターン（`TurnStarted`〜`TurnCompleted`）と、
/// 走り始めた`/compact`の要約。キューで待っているだけの要約では出ない（`Esc`がまだそれに届かない）。
/// 押すと`Esc`を押したのと同じ。出たり消えたりしても「送信」の場所は動かない。
#[test]
fn the_cancel_button_appears_only_while_something_can_be_cancelled() {
    let mut app = app_with_transcript(3);
    let idle = draw(&mut app);
    assert!(
        idle.try_find("中断").is_none(),
        "走っていないのに中断が出た"
    );
    let send_at = idle.find("Shift+Enter=送信");

    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    let running = draw(&mut app);
    assert_eq!(
        running.find("Shift+Enter=送信"),
        send_at,
        "送信の場所が動いた"
    );
    let cancel_at = running.find("Esc=中断");
    assert_eq!(running.style(cancel_at).bg, Some(Color::Cyan));

    let mut by_key = app_with_transcript(3);
    by_key.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    let clicked = click(&mut app, cancel_at);
    let pressed = press(&mut by_key, KeyCode::Esc);
    assert_eq!(shown(&clicked), shown(&pressed));
    assert!(matches!(clicked, Some(Action::Cancel)), "{clicked:?}");

    // ターンが終われば消える。
    app.apply(AgentEvent::Cancelled);
    assert!(draw(&mut app).try_find("中断").is_none());

    // `/compact`: キューで待っている間は出ず、走り始めたら出る。
    let mut compacting = app_with_transcript(3);
    assert!(compacting.begin_busy("Compacting context"));
    assert!(
        draw(&mut compacting).try_find("中断").is_none(),
        "キュー待ちで出た"
    );
    compacting.apply(AgentEvent::ContextCompactionStarted);
    let screen = draw(&mut compacting);
    assert!(matches!(
        click(&mut compacting, screen.find("Esc=中断")),
        Some(Action::Cancel)
    ));
}

/// **狭い端末でも、見出しの項目とボタンは途中で切れない。** 見出しは後ろの項目から丸ごと落として`… 他N件`と数を出し、
/// ボタンはキーを落とした短い文言（`中断`・`送信`）にし、それも入らなければ出さない。見出し（上辺）とボタン（下辺）は
/// 別の行なので重ならない。短い文言になっても押せば送る。
#[test]
fn a_narrow_terminal_never_cuts_a_title_item_or_a_button() {
    let titles = ["Enter=改行", "PageUp/PageDown=スクロール", "Ctrl-C=終了"];
    for width in [100u16, 60, 45, 30, 20, 14, 8] {
        let mut app = app_with_transcript(3);
        app.apply(AgentEvent::TurnStarted {
            estimated_input_tokens: 0,
        });
        type_text(&mut app, "hi");
        let screen = draw_sized(&mut app, width, 12);
        let (top, bottom) = input_edges(&screen);

        // 見出し: 各項目は丸ごと出るか、まったく出ないか。落とした数を`他N件`で言う。
        let title = screen.row(top);
        let shown_titles = titles.iter().filter(|t| title.contains(*t)).count();
        for t in titles {
            let head: String = t.chars().take(3).collect();
            assert!(
                title.contains(t) || !title.contains(&head),
                "{width}桁: 見出しの「{t}」が途中で切れた: {title}"
            );
        }
        let dropped = titles.len() - shown_titles;
        if dropped > 0 && title.contains(')') {
            assert!(
                title.contains(&format!("他{dropped}件")),
                "{width}桁: 落とした数を言っていない: {title}"
            );
        }

        // ボタン: 長い文言の2つ・短い文言の2つ・無し、のどれか。中途半端な文言は無い。
        let edge = screen.row(bottom);
        let long = edge.contains("Esc=中断") && edge.contains("Shift+Enter=送信");
        let short = !long && edge.contains("中断") && edge.contains("送信");
        let none = !edge.contains('断') && !edge.contains('信') && !edge.contains("Esc");
        assert!(long || short || none, "{width}桁: ボタンが切れた: {edge}");
        assert!(
            !title.contains('信') && !title.contains('断'),
            "{width}桁: {title}"
        );
        match width {
            100 | 60 | 45 => assert!(long, "{width}桁: 長い文言が入るはず: {edge}"),
            30 | 20 => assert!(short, "{width}桁: 短い文言が入るはず: {edge}"),
            _ => assert!(none, "{width}桁: 入らないボタンを描いた: {edge}"),
        }
        if short {
            assert!(
                matches!(
                    click(&mut app, screen.find("送信")),
                    Some(Action::Submit(_))
                ),
                "{width}桁: 短い文言の送信が押せない"
            );
        }
    }
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

    // 後ろの入力欄の「中断」ボタン（ターンの途中にパネルを開いた形）。
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
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
