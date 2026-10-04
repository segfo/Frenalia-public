//! 描き直しを次の`TICK`へ回してよいイベントの判定（[`super::defers_redraw`]）の回帰テスト。
//!
//! 守りたいのは2つ——**ペーストで届く文字キーは回す**（回さないと、1文字ごとに全画面を描いて読み出しが
//! 追いつかず、端末の入力バッファから文字が落ちる）ことと、**それ以外は回さない**（描いて初めて分かることを
//! 持ち越すと、スクロールの上限が効かず、マウスが前の画面の場所で当たる）こと。

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};

use super::defers_redraw;

fn key(code: KeyCode, modifiers: KeyModifiers) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

/// **ペーストで届くもの**（修飾なし・Shiftだけの文字キー）は回す。base64の行に出る文字で確かめる。
#[test]
fn the_characters_a_paste_delivers_defer_their_redraw() {
    for c in ['p', 'w', 'A', 'B', '3', '+', '/', '=', ' ', '-', 'あ'] {
        assert!(
            defers_redraw(&key(KeyCode::Char(c), KeyModifiers::NONE)),
            "{c:?}"
        );
    }
    assert!(defers_redraw(&key(KeyCode::Char('A'), KeyModifiers::SHIFT)));
}

/// **それ以外は回さない。** 描いて初めて分かること（遡れる上限・押せる場所）を持ち越さない。
#[test]
fn everything_else_still_redraws_at_once() {
    let deferred: Vec<String> = [
        key(KeyCode::Enter, KeyModifiers::NONE),
        key(KeyCode::Enter, KeyModifiers::ALT),
        key(KeyCode::Backspace, KeyModifiers::NONE),
        key(KeyCode::PageUp, KeyModifiers::NONE),
        key(KeyCode::PageDown, KeyModifiers::NONE),
        key(KeyCode::Up, KeyModifiers::NONE),
        key(KeyCode::Esc, KeyModifiers::NONE),
        key(KeyCode::Char('c'), KeyModifiers::CONTROL),
        key(KeyCode::Char('o'), KeyModifiers::CONTROL),
        key(KeyCode::Char('v'), KeyModifiers::CONTROL),
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }),
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }),
        Event::Resize(80, 24),
        Event::FocusGained,
    ]
    .into_iter()
    .filter(defers_redraw)
    .map(|e| format!("{e:?}"))
    .collect();
    assert_eq!(deferred, Vec::<String>::new());
}

/// キーを**離した**ことは回さない（そもそも何も変えないが、押下だけを回す形を固定しておく）。
#[test]
fn a_key_release_is_not_deferred() {
    let release = Event::Key(KeyEvent {
        code: KeyCode::Char('a'),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    });
    assert!(!defers_redraw(&release));
}
