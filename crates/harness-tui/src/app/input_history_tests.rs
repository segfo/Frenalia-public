//! 入力欄の履歴（`app::input_history`）の試験。積み方は[`InputHistory`]を直接、↑↓の効き方はキーを
//! [`AppState::on_key`]へ入れて確かめる。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_core::AgentEvent;

use super::super::{Action, MODAL_INPUT_GRACE};
use super::*;

fn app() -> AppState {
    AppState::new("mock".into(), "mock-model".into())
}

fn press(app: &mut AppState, code: KeyCode) -> Option<Action> {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// 文字を打つ（`\n`は素のEnter＝改行。`enter_submits`の既定は偽）。
fn type_text(app: &mut AppState, text: &str) {
    for c in text.chars() {
        if c == '\n' {
            press(app, KeyCode::Enter);
        } else {
            press(app, KeyCode::Char(c));
        }
    }
}

/// 文を打って送信キー（Alt+Enter）で送る。
fn send(app: &mut AppState, text: &str) -> Option<Action> {
    type_text(app, text);
    app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT))
}

fn ctrl(app: &mut AppState, c: char, extra: KeyModifiers) {
    app.on_key(KeyEvent::new(
        KeyCode::Char(c),
        KeyModifiers::CONTROL | extra,
    ));
}

fn draft(text: &str) -> InputDraft {
    InputDraft {
        text: text.to_string(),
        cursor: 1,
        undo: vec![(String::new(), 0)],
        redo: Vec::new(),
        last_edit_was_insert: true,
    }
}

// ---- 積み方（`InputHistory`を直接） ----

/// 空白だけの文と、直前に積んだ文と同じ文は積まない。離れた位置の同じ文は積む。
#[test]
fn blank_and_consecutive_duplicate_texts_are_not_recorded() {
    let mut history = InputHistory::default();
    for text in ["a", "  \n\t", "", "a", "b", "a"] {
        history.record(text);
    }
    assert_eq!(history.entries(), ["a", "b", "a"]);
}

/// 最大[`MAX_ENTRIES`]件。ちょうど上限までは捨てず、超えたら最も古い文から捨てる。
#[test]
fn at_most_max_entries_are_kept_dropping_the_oldest() {
    let mut history = InputHistory::default();
    for i in 0..MAX_ENTRIES {
        history.record(&i.to_string());
    }
    assert_eq!(history.entries().len(), MAX_ENTRIES);
    assert_eq!(history.entries()[0], "0");

    history.record(&MAX_ENTRIES.to_string());
    let entries = history.entries();
    assert_eq!(entries.len(), MAX_ENTRIES);
    assert_eq!(entries[0], "1", "最も古い文が捨てられる");
    assert_eq!(entries[MAX_ENTRIES - 1], MAX_ENTRIES.to_string());
}

/// 書きかけは見始めたときに1回だけ退避し、最も新しい文を過ぎたら返す。履歴が空なら何も退避しない。
#[test]
fn older_saves_the_draft_once_and_newer_hands_it_back() {
    let mut history = InputHistory::default();
    assert_eq!(
        history.older(|| panic!("空の履歴で書きかけを退避した")),
        None
    );
    assert!(!history.is_browsing());
    assert_eq!(history.newer(), None, "見ていなければ↓は何もしない");

    history.record("one");
    history.record("two");
    assert_eq!(history.older(|| draft("wip")).as_deref(), Some("two"));
    assert_eq!(
        history
            .older(|| panic!("見ている間に書きかけを退避し直した"))
            .as_deref(),
        Some("one")
    );
    assert_eq!(history.older(|| unreachable!()), None, "最も古い文で止まる");
    assert!(history.is_browsing(), "止まっても見続けている");

    assert_eq!(history.newer(), Some(Newer::Entry("two".into())));
    assert_eq!(history.newer(), Some(Newer::Draft(draft("wip"))));
    assert!(!history.is_browsing());
    assert_eq!(history.newer(), None);
}

/// 送ったら見るのをやめ、退避した書きかけは捨てる。
#[test]
fn recording_ends_browsing_and_drops_the_draft() {
    let mut history = InputHistory::default();
    history.record("one");
    history.older(|| draft("wip"));
    history.record("one");
    assert!(!history.is_browsing());
    assert_eq!(history.newer(), None);
    assert_eq!(history.entries(), ["one"]);
}

// ---- ↑↓の効き方（キーを`AppState::on_key`へ） ----

/// ↑で前の文を呼び戻し、↓で戻ると書きかけがカーソルとundo/redoごと戻る（戻した後の`Ctrl+Z`は書きかけの
/// 最後の編集を取り消す）。
#[test]
fn up_recalls_previous_and_down_restores_the_draft_with_cursor_and_undo() {
    let mut app = app();
    send(&mut app, "first");
    send(&mut app, "second");
    // 書きかけ: "abc"と打ってBackspace（undoが2単位）、カーソルを1つ左へ。
    type_text(&mut app, "abc");
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Left);
    assert_eq!((app.input.as_str(), app.input_cursor), ("ab", 1));

    press(&mut app, KeyCode::Up);
    assert_eq!((app.input.as_str(), app.input_cursor), ("second", 6));
    press(&mut app, KeyCode::Up);
    assert_eq!((app.input.as_str(), app.input_cursor), ("first", 5));
    press(&mut app, KeyCode::Down);
    assert_eq!((app.input.as_str(), app.input_cursor), ("second", 6));

    press(&mut app, KeyCode::Down);
    assert_eq!((app.input.as_str(), app.input_cursor), ("ab", 1));
    ctrl(&mut app, 'z', KeyModifiers::NONE);
    assert_eq!(
        (app.input.as_str(), app.input_cursor),
        ("abc", 3),
        "Backspaceを取り消す"
    );
    ctrl(&mut app, 'z', KeyModifiers::SHIFT);
    assert_eq!(app.input, "ab", "redoも戻っている");
    ctrl(&mut app, 'z', KeyModifiers::NONE);
    ctrl(&mut app, 'z', KeyModifiers::NONE);
    assert_eq!(app.input, "", "打った分も取り消せる");
}

/// `/`で始まる命令も積む——打ち間違えて弾かれた命令を呼び戻して直せる。
#[test]
fn slash_commands_are_recalled_too() {
    let mut app = app();
    assert!(
        send(&mut app, "/modle x").is_none(),
        "知らない命令は送らない"
    );
    send(&mut app, "/fork");
    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "/fork");
    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "/modle x");
}

/// 直前と同じ文は積まず、離れた位置の同じ文は積む。空白だけの送信（送られない）も積まない。
#[test]
fn consecutive_duplicates_and_blank_submits_are_skipped_on_send() {
    let mut app = app();
    send(&mut app, "same");
    send(&mut app, "same");
    send(&mut app, "other");
    send(&mut app, "same");
    assert!(send(&mut app, "   ").is_none());
    assert_eq!(app.input_history.entries(), ["same", "other", "same"]);
}

/// 呼び戻した文を編集したら、それが新しい書きかけになる——続く↓は履歴へ入らず、退避していた前の書きかけは
/// 捨てる。次の↑で退避されるのは編集した文。
#[test]
fn editing_a_recalled_entry_makes_it_the_draft() {
    let mut app = app();
    send(&mut app, "one");
    send(&mut app, "two");
    type_text(&mut app, "wip");

    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "two");
    type_text(&mut app, "x");
    assert_eq!(app.input, "twox");
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "twox", "編集した後の↓は履歴へ入らない");

    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "two");
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "twox", "退避されたのは編集した文");
}

/// 呼び戻した文を送ったら、退避した書きかけは捨てる（シェルと同じ）。同じ文が続くので積み増さない。
#[test]
fn sending_a_recalled_entry_drops_the_draft() {
    let mut app = app();
    send(&mut app, "one");
    type_text(&mut app, "wip");
    press(&mut app, KeyCode::Up);
    match app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)) {
        Some(Action::Submit(text)) => assert_eq!(text, "one"),
        other => panic!("expected Submit, got {other:?}"),
    }
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "", "書きかけへは戻らない");
    assert_eq!(app.input_history.entries(), ["one"]);
}

/// 複数行の文: 古い側へ呼び戻したらカーソルは1行目の末尾なので、続く↑はすぐ次の古い文へ進む。逆の↓は文の中の
/// 行を移ってから新しい側へ進む。新しい側へ呼び戻したらカーソルは末尾なので、↑は文の中の行を移る。
#[test]
fn multi_line_entries_continue_in_the_same_direction_and_move_lines_in_the_other() {
    let mut app = app();
    send(&mut app, "older");
    send(&mut app, "l1\nl2\nl3");
    send(&mut app, "newest");

    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "newest");
    press(&mut app, KeyCode::Up);
    assert_eq!((app.input.as_str(), app.input_cursor), ("l1\nl2\nl3", 2));
    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "older", "1行目の末尾から続けて↑で次の古い文へ");

    press(&mut app, KeyCode::Down);
    assert_eq!(
        (app.input.as_str(), app.input_cursor),
        ("l1\nl2\nl3", 8),
        "末尾"
    );
    press(&mut app, KeyCode::Up);
    assert_eq!(
        (app.input.as_str(), app.input_cursor),
        ("l1\nl2\nl3", 5),
        "↑は行を移る"
    );
    press(&mut app, KeyCode::Up);
    assert_eq!((app.input.as_str(), app.input_cursor), ("l1\nl2\nl3", 2));

    press(&mut app, KeyCode::Down);
    assert_eq!(
        (app.input.as_str(), app.input_cursor),
        ("l1\nl2\nl3", 5),
        "↓も行を移る"
    );
    press(&mut app, KeyCode::Down);
    assert_eq!((app.input.as_str(), app.input_cursor), ("l1\nl2\nl3", 8));
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "newest", "最終行から新しい側へ");
}

/// 履歴があっても、書きかけの2行目以降の↑は行を移る（1行目に来てから初めて履歴へ）。
#[test]
fn up_on_a_later_line_moves_lines_even_with_history() {
    let mut app = app();
    send(&mut app, "one");
    type_text(&mut app, "a\nb");
    press(&mut app, KeyCode::Up);
    assert_eq!((app.input.as_str(), app.input_cursor), ("a\nb", 1));
    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "one");
}

/// 承認ダイアログ・レビューパネルが開いている間の↑↓はそちらが受け、履歴は動かない。閉じれば履歴が動く。
#[test]
fn overlays_take_up_and_down_before_the_history() {
    let mut app = app();
    send(&mut app, "one");
    type_text(&mut app, "wip");

    app.apply(AgentEvent::PermissionRequired {
        id: "perm-0".into(),
        tool: "run_shell".into(),
        risk: harness_core::RiskClass::Exec,
        input: serde_json::json!({"command": "ls"}),
        subject: harness_core::PermissionSubject::Command(harness_core::CommandSubject::line_only(
            "ls",
        )),
    });
    let view = app.pending_permission.as_mut().expect("modal");
    view.opened_at =
        std::time::Instant::now() - MODAL_INPUT_GRACE - std::time::Duration::from_millis(1);
    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "wip");
    assert!(!app.input_history.is_browsing());
    assert!(matches!(
        press(&mut app, KeyCode::Char('n')),
        Some(Action::Respond(..))
    ));

    app.open_changes_panel(Vec::new());
    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "wip");
    assert!(!app.input_history.is_browsing());
    press(&mut app, KeyCode::Esc);
    assert!(app.review_panel.is_none());

    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "one", "閉じた後は履歴が動く");
}

/// 履歴を動かしたら選択（`Shift+矢印`のアンカー）を外す——呼び戻すときも、書きかけへ戻るときも。
#[test]
fn a_history_step_clears_the_selection_anchor() {
    let mut app = app();
    send(&mut app, "one");
    type_text(&mut app, "ab");
    app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
    assert!(app.selection_range().is_some());

    press(&mut app, KeyCode::Up);
    assert_eq!(app.input, "one");
    assert_eq!(app.input_selection_anchor, None);

    app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));
    assert!(app.selection_range().is_some());
    press(&mut app, KeyCode::Down);
    assert_eq!(app.input, "ab");
    assert_eq!(app.input_selection_anchor, None);
}
