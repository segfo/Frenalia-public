//! `app`モジュール（状態・入力編集・イベント消費・コマンド解析）の回帰テスト。
//! 内部関数（`parse_slash_command`・`submit_input`・`char_byte_index`等）へ触れるため、
//! `tests/`ではなく`#[cfg(test)]`のまま別ファイルへ分けている（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use super::*;

fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

fn code(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn parses_fork_and_sessions_slash_commands() {
    assert_eq!(parse_slash_command("/fork"), Ok(SlashCommand::Fork));
    assert_eq!(parse_slash_command("/sessions"), Ok(SlashCommand::Sessions));
}

#[test]
fn parses_fsstage_subcommands() {
    assert_eq!(
        parse_slash_command("/fsstage"),
        Ok(SlashCommand::FsStage(FsStageCommand::List))
    );
    assert_eq!(
        parse_slash_command("/fsstage list"),
        Ok(SlashCommand::FsStage(FsStageCommand::List))
    );
    assert_eq!(
        parse_slash_command("/fsstage commit"),
        Ok(SlashCommand::FsStage(FsStageCommand::Open))
    );
    assert_eq!(
        parse_slash_command("/fsstage commit a/b.txt"),
        Ok(SlashCommand::FsStage(FsStageCommand::CommitFile(
            "a/b.txt".to_string()
        )))
    );
    assert_eq!(
        parse_slash_command("/fsstage commit_all"),
        Ok(SlashCommand::FsStage(FsStageCommand::CommitAll))
    );
    assert_eq!(
        parse_slash_command("/fsstage discard"),
        Ok(SlashCommand::FsStage(FsStageCommand::Discard))
    );
    assert_eq!(
        parse_slash_command("/fsstage resolve"),
        Ok(SlashCommand::FsStage(FsStageCommand::Resolve(None)))
    );
    assert_eq!(
        parse_slash_command("/fsstage resolve a/b.txt"),
        Ok(SlashCommand::FsStage(FsStageCommand::Resolve(Some(
            "a/b.txt".to_string()
        ))))
    );
    assert!(parse_slash_command("/fsstage nope").is_err());
}

#[test]
fn submit_input_routes_fsstage_to_dedicated_actions_not_slash() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.input = "/fsstage commit_all".to_string();
    let action = app.submit_input();
    assert!(matches!(action, Some(Action::CommitAllChanges)));

    app.input = "/fsstage commit report.txt".to_string();
    let action = app.submit_input();
    assert!(matches!(
        action,
        Some(Action::CommitChanges(paths)) if paths == vec!["report.txt".to_string()]
    ));

    app.input = "/fsstage discard".to_string();
    let action = app.submit_input();
    assert!(matches!(action, Some(Action::DiscardChanges)));

    app.input = "/fsstage commit".to_string();
    let action = app.submit_input();
    assert!(matches!(action, Some(Action::OpenChangesPanel)));

    app.input = "/fsstage".to_string();
    let action = app.submit_input();
    assert!(matches!(action, Some(Action::ListChanges)));
}

#[test]
fn rejects_unknown_slash_command() {
    assert_eq!(
        parse_slash_command("/nope"),
        Err("unknown command: /nope".to_string())
    );
}

/// 左矢印でカーソルを戻してから文字を打つと、末尾ではなくカーソル位置に挿入される
/// （Backspace/Deleteも同様にカーソル基準で動くことを確認する）。
#[test]
fn left_right_arrows_move_cursor_for_mid_string_editing() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    assert_eq!(app.input, "hello");
    assert_eq!(app.input_cursor, 5);

    // "hello" -> "hel|lo" (2文字戻る)
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    assert_eq!(app.input_cursor, 3);

    app.on_key(key('X'));
    assert_eq!(app.input, "helXlo");
    assert_eq!(app.input_cursor, 4);

    // 右矢印は文字列末尾でクランプされる。
    for _ in 0..10 {
        app.on_key(code(KeyCode::Right));
    }
    assert_eq!(app.input_cursor, 6);

    // Backspaceはカーソル直前を、Deleteはカーソル位置の文字を削る。
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Backspace));
    assert_eq!(app.input, "helXo");
    assert_eq!(app.input_cursor, 4);

    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "heXo");
    assert_eq!(app.input_cursor, 2);
}

/// HomeとEndでカーソルが行頭/行末へ一気に移動する。
#[test]
fn home_and_end_keys_jump_cursor_to_line_boundaries() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Home));
    assert_eq!(app.input_cursor, 0);

    app.on_key(key('X'));
    assert_eq!(app.input, "Xhello");
    assert_eq!(app.input_cursor, 1);

    app.on_key(code(KeyCode::End));
    assert_eq!(app.input_cursor, 6);

    app.on_key(key('Y'));
    assert_eq!(app.input, "XhelloY");
    assert_eq!(app.input_cursor, 7);
}

/// 素のEnterが改行を挿入するようになった（複数行入力）ため、Home/Endは行全体ではなく
/// 現在行だけを対象にする。
#[test]
fn home_end_operate_on_current_line_in_multiline_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "ab".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Enter)); // 改行(既定): "ab\n"
    for c in "cde".chars() {
        app.on_key(key(c));
    }
    assert_eq!(app.input, "ab\ncde");
    assert_eq!(app.input_cursor, 6);

    // カーソルは2行目("cde")の末尾。Homeは2行目の先頭(3)へ、1行目の先頭(0)へは行かない。
    app.on_key(code(KeyCode::Home));
    assert_eq!(app.input_cursor, 3);

    app.on_key(code(KeyCode::End));
    assert_eq!(app.input_cursor, 6);

    // 1行目の末尾(改行の直前)にカーソルを移動してからHome/Endすると、1行目の範囲(0..2)に収まる。
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    assert_eq!(app.input_cursor, 2); // "ab|\ncde"

    app.on_key(code(KeyCode::Home));
    assert_eq!(app.input_cursor, 0);
    app.on_key(code(KeyCode::End));
    assert_eq!(app.input_cursor, 2);
}

/// Up/Downで行をまたいでカーソルが移動し、列(行頭からの文字数)を可能な限り維持する
/// （短い行へ移動するときはその行の長さでクランプする）。
#[test]
fn up_down_arrows_move_between_lines_preserving_column() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "abcde".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Enter)); // "abcde\n"
    for c in "xy".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Enter)); // "abcde\nxy\n"
    for c in "z".chars() {
        app.on_key(key(c));
    }
    assert_eq!(app.input, "abcde\nxy\nz");

    // カーソルは3行目("z")の末尾(列0からの1文字目)。Upで2行目("xy")の同じ列(1)へ。
    app.on_key(code(KeyCode::Up));
    assert_eq!(app.input_cursor, 6 + 1); // "xy"の開始(6)+列1

    // さらにUpすると1行目("abcde")、列1のまま維持される。
    app.on_key(code(KeyCode::Up));
    assert_eq!(app.input_cursor, 1);

    // 先頭行でのUpは何もしない。
    app.on_key(code(KeyCode::Up));
    assert_eq!(app.input_cursor, 1);

    // Endで1行目の末尾(列5)へ行ってからDownすると、2行目("xy"、長さ2)の列はクランプされ2になる。
    app.on_key(code(KeyCode::End));
    assert_eq!(app.input_cursor, 5);
    app.on_key(code(KeyCode::Down));
    assert_eq!(app.input_cursor, 6 + 2); // "xy"の末尾(列2、クランプ)

    // 3行目("z"、長さ1)へ: 列はクランプされ1(=末尾)になる。
    app.on_key(code(KeyCode::Down));
    assert_eq!(app.input_cursor, app.input.chars().count());

    // 最終行でのDownは何もしない。
    let cursor_at_last_line = app.input_cursor;
    app.on_key(code(KeyCode::Down));
    assert_eq!(app.input_cursor, cursor_at_last_line);
}

/// 左矢印は先頭で、Backspace/Deleteは範囲外では何もせずパニックしない
/// （マルチバイト文字混じりの入力でも文字境界を跨がない）。
#[test]
fn cursor_edits_clamp_at_boundaries_and_handle_multibyte_chars() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Backspace));
    assert_eq!(app.input_cursor, 0);
    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "");

    for c in "例あ".chars() {
        app.on_key(key(c));
    }
    assert_eq!(app.input_cursor, 2);
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Backspace));
    assert_eq!(app.input, "あ");
    assert_eq!(app.input_cursor, 0);
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn shift(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::SHIFT)
}

fn alt(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::ALT)
}

/// Ctrl+Aで全選択し、Deleteを押すと入力が全消去される。
#[test]
fn ctrl_a_selects_all_then_delete_clears_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(ctrl('a'));
    assert_eq!(app.selection_range(), Some((0, 5)));

    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "");
    assert_eq!(app.input_cursor, 0);
    assert_eq!(app.selection_range(), None);
}

/// Ctrl+Aで全選択した状態で文字を打つと、選択範囲全体がその1文字に置き換わる。
#[test]
fn ctrl_a_selects_all_then_typing_replaces_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(ctrl('a'));
    app.on_key(key('X'));
    assert_eq!(app.input, "X");
    assert_eq!(app.input_cursor, 1);
    assert_eq!(app.selection_range(), None);
}

/// Shift+矢印で選択範囲が伸縮し、選択中のBackspace/Delete/文字入力が範囲全体に効く。
#[test]
fn shift_arrows_extend_and_shrink_selection() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    // カーソルは末尾(5)。Shift+Leftを3回で"lo"を選択(範囲2..5)。
    app.on_key(shift(KeyCode::Left));
    app.on_key(shift(KeyCode::Left));
    app.on_key(shift(KeyCode::Left));
    assert_eq!(app.selection_range(), Some((2, 5)));

    // Shift+Rightで1文字縮む(範囲3..5)。
    app.on_key(shift(KeyCode::Right));
    assert_eq!(app.selection_range(), Some((3, 5)));

    // 選択中に文字入力すると範囲("lo")がその1文字に置き換わる。
    app.on_key(key('Z'));
    assert_eq!(app.input, "helZ");
    assert_eq!(app.input_cursor, 4);
    assert_eq!(app.selection_range(), None);

    // 選択→Backspace/Deleteでも範囲削除になることを確認。
    app.on_key(shift(KeyCode::Left));
    app.on_key(shift(KeyCode::Left));
    assert_eq!(app.selection_range(), Some((2, 4)));
    app.on_key(code(KeyCode::Backspace));
    assert_eq!(app.input, "he");
    assert_eq!(app.input_cursor, 2);
}

/// 選択中にShift無しの矢印を押すと、1文字動くのではなく選択範囲の端へ収縮する。
#[test]
fn unshifted_arrow_after_selection_collapses_to_edge_without_deleting() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(shift(KeyCode::Left));
    app.on_key(shift(KeyCode::Left));
    assert_eq!(app.selection_range(), Some((3, 5)));

    app.on_key(code(KeyCode::Left));
    assert_eq!(app.input, "hello");
    assert_eq!(app.input_cursor, 3);
    assert_eq!(app.selection_range(), None);

    app.on_key(shift(KeyCode::Right));
    app.on_key(shift(KeyCode::Right));
    assert_eq!(app.selection_range(), Some((3, 5)));

    app.on_key(code(KeyCode::Right));
    assert_eq!(app.input, "hello");
    assert_eq!(app.input_cursor, 5);
    assert_eq!(app.selection_range(), None);
}

/// Shift+Home/Endで行頭/行末までの選択範囲を作れる。
#[test]
fn shift_home_end_select_to_line_boundaries() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Left));
    app.on_key(code(KeyCode::Left));
    assert_eq!(app.input_cursor, 3);

    app.on_key(shift(KeyCode::Home));
    assert_eq!(app.selection_range(), Some((0, 3)));

    app.on_key(code(KeyCode::Right));
    assert_eq!(app.input_cursor, 3);
    assert_eq!(app.selection_range(), None);

    app.on_key(shift(KeyCode::End));
    assert_eq!(app.selection_range(), Some((3, 5)));
}

fn ctrl_shift(c: char) -> KeyEvent {
    KeyEvent::new(
        KeyCode::Char(c),
        KeyModifiers::CONTROL | KeyModifiers::SHIFT,
    )
}

/// ユーザー報告の再現: 「ああああ消したいところあああ」でカーソルを`ろ`（インデックス10）
/// に置きShift+Leftを7回押すと、選択範囲が「消したいところ」7文字ちょうどになり
/// （`ろ`自身もブロックカーソルの初回選択で含まれる）、Deleteで過不足なく消える。
#[test]
fn shift_left_selection_start_includes_char_under_cursor() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "ああああ消したいところあああ".chars() {
        app.on_key(key(c));
    }
    // カーソルを`ろ`(インデックス10)の上へ: 末尾(14)から4つ左へ。
    for _ in 0..4 {
        app.on_key(code(KeyCode::Left));
    }
    assert_eq!(app.input_cursor, 10);

    for _ in 0..7 {
        app.on_key(shift(KeyCode::Left));
    }
    assert_eq!(app.selection_range(), Some((4, 11)));

    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "あああああああ");
}

/// 回帰確認: カーソルが`消`の上にある状態からのShift+右矢印は、従来通り初回で
/// `消`自身を選択に含める（左矢印の修正が右矢印の挙動を変えていないことの確認）。
#[test]
fn shift_right_selection_start_still_includes_char_under_cursor() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "ああああ消したいところあああ".chars() {
        app.on_key(key(c));
    }
    for _ in 0..10 {
        app.on_key(code(KeyCode::Left));
    }
    assert_eq!(app.input_cursor, 4);

    for _ in 0..7 {
        app.on_key(shift(KeyCode::Right));
    }
    assert_eq!(app.selection_range(), Some((4, 11)));

    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "あああああああ");
}

/// 「幽霊アンカー」バグの再現+修正確認: Shift+Rightで選択を広げた後、反対方向へ
/// Shift+Leftを押し戻してアンカー==カーソルに一致させる（選択が見た目上消える）。
/// この状態でBackspace/文字入力/Shift無し矢印を経由しても、内部の`anchor`が
/// クリアされていないと後続のShift+矢印が古いアンカーを再利用してしまい、
/// ユーザーの現在のカーソル位置からの新規選択にならない（今回の修正対象）。
#[test]
fn shift_selection_anchor_resets_after_returning_to_start() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Home));
    assert_eq!(app.input_cursor, 0);

    // "h"を選択してから押し戻し、アンカー==カーソルに一致させる（見た目上は選択なし）。
    app.on_key(shift(KeyCode::Right));
    app.on_key(shift(KeyCode::Left));
    assert_eq!(app.selection_range(), None);
    assert_eq!(app.input_cursor, 0);

    // 選択なしのUnshifted移動を経由して幽霊アンカーが残っていないことを確認。
    app.on_key(code(KeyCode::Right));
    assert_eq!(app.input_cursor, 1);
    assert_eq!(app.selection_range(), None);

    // 直後のShift+Rightは、古いアンカー(0)ではなく「今のカーソル位置(1)」から
    // 新規に選択を開始しなければならない。
    app.on_key(shift(KeyCode::Right));
    assert_eq!(app.selection_range(), Some((1, 2)));
}

/// 同様に、Backspace/文字入力を経由した場合も幽霊アンカーが残らないことを確認する。
#[test]
fn ghost_anchor_does_not_survive_backspace_or_typing() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Home));
    app.on_key(shift(KeyCode::Right));
    app.on_key(shift(KeyCode::Left));
    assert_eq!(app.selection_range(), None);

    // Backspaceは先頭なので何もしないが、幽霊アンカーは残らない。
    app.on_key(code(KeyCode::Backspace));
    app.on_key(key('X'));
    assert_eq!(app.input, "Xhello");
    assert_eq!(app.input_cursor, 1);
    assert_eq!(app.selection_range(), None);

    app.on_key(shift(KeyCode::Right));
    assert_eq!(app.selection_range(), Some((1, 2)));
}

/// Ctrl+Zで直前の編集を取り消し、Ctrl+Shift+Zでやり直せる。
#[test]
fn ctrl_z_undoes_last_insert_and_ctrl_shift_z_redoes() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    app.on_key(code(KeyCode::Backspace));
    assert_eq!(app.input, "h");

    app.on_key(ctrl('z'));
    assert_eq!(app.input, "hi");
    assert_eq!(app.input_cursor, 2);

    app.on_key(ctrl_shift('z'));
    assert_eq!(app.input, "h");
}

/// 連続する単純タイピングは1つのUndo単位にまとまる（1文字ずつ戻らない）。
#[test]
fn ctrl_z_coalesces_consecutive_plain_typing_into_one_undo_step() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(ctrl('z'));
    assert_eq!(app.input, "");
    assert_eq!(app.input_cursor, 0);

    // Undoできる履歴が無い状態でのCtrl+Zは何もしない。
    app.on_key(ctrl('z'));
    assert_eq!(app.input, "");
}

/// 選択範囲のBackspace削除・文字置換もそれぞれ1つのUndo単位として取り消せる。
#[test]
fn ctrl_z_undoes_selection_delete_and_replace() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hello".chars() {
        app.on_key(key(c));
    }
    app.on_key(ctrl('a'));
    app.on_key(code(KeyCode::Delete));
    assert_eq!(app.input, "");

    app.on_key(ctrl('z'));
    assert_eq!(app.input, "hello");

    app.on_key(ctrl('a'));
    app.on_key(key('X'));
    assert_eq!(app.input, "X");

    app.on_key(ctrl('z'));
    assert_eq!(app.input, "hello");
}

/// 同一ターン内の`TextDelta`は直前の`Assistant`項目へ連結され、`TurnStarted`を挟むと
/// 新しい項目として積まれる（§リッチTUI「ストリーミング描画」）。
#[test]
fn text_deltas_within_a_turn_accumulate_into_one_item() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta { text: "hel".into() });
    app.apply(AgentEvent::TextDelta { text: "lo".into() });

    assert_eq!(app.transcript.len(), 1);
    match &app.transcript[0] {
        TranscriptItem::Assistant(s) => assert_eq!(s, "hello"),
        other => panic!("expected Assistant item, got {other:?}"),
    }

    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage::default(),
    });
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta {
        text: "next turn".into(),
    });
    assert_eq!(app.transcript.len(), 2);
}

/// `ToolCallProposed`でカードが積まれ、`ToolFinished`で同じ`id`のカードのstatusが
/// 更新される（§リッチTUI「ツールカード」）。
#[test]
fn tool_card_transitions_from_running_to_done() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::ToolCallProposed {
        id: "call_1".into(),
        name: "read_file".into(),
        input: serde_json::json!({"path": "a.txt"}),
    });
    match &app.transcript[0] {
        TranscriptItem::ToolCard { status, .. } => {
            assert!(matches!(status, ToolCardStatus::Running))
        }
        other => panic!("expected ToolCard, got {other:?}"),
    }

    app.apply(AgentEvent::ToolFinished {
        id: "call_1".into(),
        output: ToolOutput {
            content: "hello".into(),
            is_error: false,
        },
    });
    match &app.transcript[0] {
        TranscriptItem::ToolCard { status, .. } => match status {
            ToolCardStatus::Done { is_error, output } => {
                assert!(!is_error);
                assert_eq!(output, "hello");
            }
            ToolCardStatus::Running => panic!("expected Done"),
        },
        other => panic!("expected ToolCard, got {other:?}"),
    }
}

/// `PermissionRequired`はモーダル状態を立て、モーダル表示中は`y/n/a/d`のみを消費して
/// `Action::Respond`を返す（§リッチTUI「承認ダイアログ」の`[y]/[n]/[a]/[d]`）。
#[test]
fn permission_modal_consumes_only_decision_keys() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::PermissionRequired {
        id: "perm-0".into(),
        tool: "run_shell".into(),
        risk: RiskClass::Exec,
        input: serde_json::json!({"command": "echo hi"}),
    });
    assert!(app.pending_permission.is_some());

    // モーダル表示中は通常の文字入力ボックスへは書き込まれない。
    assert!(app.on_key(key('x')).is_none());
    assert!(app.input.is_empty());

    let action = app.on_key(key('a')).expect("expected an action");
    match action {
        Action::Respond(id, decision) => {
            assert_eq!(id, "perm-0");
            assert_eq!(decision, Decision::AllowAndRemember);
        }
        _ => panic!("expected Respond action"),
    }
    assert!(app.pending_permission.is_none());
}

/// Shift+Enterは送信キー。Windows Terminal/conhostではSHIFT修飾が実際に届くため送信になる
/// （VS Code統合ターミナルではShift修飾が失われ素のEnterとして届くため改行のままになる——
/// それはcrossterm/xterm.js側の挙動であり、`on_key`にはSHIFT付きのイベントが渡る前提）。
#[test]
fn shift_enter_submits_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    let action = app.on_key(shift(KeyCode::Enter));
    match action {
        Some(Action::Submit(text)) => assert_eq!(text, "hi"),
        other => panic!("expected Submit action, got {other:?}"),
    }
    assert!(app.input.is_empty());
}

/// `enter_submits`フラグが立っていても、Shift+Enterは（Alt+Enterと同様）常に送信のまま。
#[test]
fn shift_enter_submits_even_when_enter_submits_flag_enabled() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.enter_submits = true;
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    let action = app.on_key(shift(KeyCode::Enter));
    match action {
        Some(Action::Submit(text)) => assert_eq!(text, "hi"),
        other => panic!("expected Submit action, got {other:?}"),
    }
    assert!(app.input.is_empty());
}

/// 既定（`enter_submits == false`）では、素のEnterは送信せず入力欄へ改行を挿入し、送信は
/// Alt+Enterで行う（複数行プロンプトの組み立て）。
#[test]
fn enter_inserts_newline_by_default_and_alt_enter_submits() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    assert!(!app.enter_submits);
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    assert!(app.on_key(code(KeyCode::Enter)).is_none());
    assert_eq!(app.input, "hi\n");
    assert_eq!(app.input_cursor, 3);

    for c in "there".chars() {
        app.on_key(key(c));
    }
    assert_eq!(app.input, "hi\nthere");

    let action = app.on_key(alt(KeyCode::Enter));
    match action {
        Some(Action::Submit(text)) => assert_eq!(text, "hi\nthere"),
        other => panic!("expected Submit action, got {other:?}"),
    }
    assert!(app.input.is_empty());
}

/// Alt+Enterは送信キー。VS Code統合ターミナルでも物理Alt+EnterはネイティブにESC+CRとして
/// 送られ、crosstermがESCプレフィックスをAlt修飾と解釈するため、keybindingの細工なしに
/// Alt+Enterとして届く（`on_key`のEnter分岐のコメント参照）。
#[test]
fn alt_enter_submits_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    let action = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
    match action {
        Some(Action::Submit(text)) => assert_eq!(text, "hi"),
        other => panic!("expected Submit action, got {other:?}"),
    }
    assert!(app.input.is_empty());
}

/// `enter_submits`フラグが立っている（後方互換モード）と、素のEnterも送信する。
#[test]
fn enter_submits_when_flag_enabled() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.enter_submits = true;
    for c in "hi".chars() {
        app.on_key(key(c));
    }
    let action = app.on_key(code(KeyCode::Enter));
    match action {
        Some(Action::Submit(text)) => assert_eq!(text, "hi"),
        other => panic!("expected Submit action, got {other:?}"),
    }
    assert!(app.input.is_empty());
}

#[test]
fn submitting_input_returns_transcript_to_latest() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.scroll_lines(12);
    for c in "hi".chars() {
        app.on_key(key(c));
    }

    let action = app.on_key(alt(KeyCode::Enter));

    assert!(matches!(action, Some(Action::Submit(text)) if text == "hi"));
    assert_eq!(app.scroll_offset, 0);
}

#[test]
fn scroll_lines_clamps_at_zero_and_saturates_upward() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    assert_eq!(app.scroll_offset, 0);
    app.scroll_lines(-5);
    assert_eq!(app.scroll_offset, 0, "should not go below 0");
    app.scroll_lines(3);
    assert_eq!(app.scroll_offset, 3);
    app.scroll_lines(-1);
    assert_eq!(app.scroll_offset, 2);
}

#[test]
fn page_up_and_page_down_keys_scroll_by_a_page_without_emitting_an_action() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    let action = app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert!(action.is_none());
    assert!(app.scroll_offset > 0);

    let after_up = app.scroll_offset;
    let action = app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    assert!(action.is_none());
    assert!(app.scroll_offset < after_up);
}

#[test]
fn ctrl_o_toggles_fold_and_defaults_to_collapsed() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    assert!(app.collapsed, "default should be collapsed");

    let action = app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    assert!(action.is_none());
    assert!(!app.collapsed);

    app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
    assert!(app.collapsed);
}

#[test]
fn ctrl_o_returns_transcript_to_latest() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.scroll_lines(1);

    let action = app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));

    assert!(action.is_none());
    assert!(!app.collapsed);
    assert_eq!(app.scroll_offset, 0);
}

#[test]
fn mouse_wheel_scrolls_up_and_down() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.on_mouse(MouseEventKind::ScrollUp);
    assert_eq!(app.scroll_offset, 3);
    app.on_mouse(MouseEventKind::ScrollDown);
    assert_eq!(app.scroll_offset, 0);
    app.on_mouse(MouseEventKind::ScrollDown);
    assert_eq!(app.scroll_offset, 0, "should not go below 0");
}

/// スクロール操作は承認モーダル表示中でも通る（過去ログ閲覧を妨げないため、
/// `on_key`のモーダルガードとは独立に処理される）。
#[test]
fn mouse_scroll_works_even_while_permission_modal_is_pending() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::PermissionRequired {
        id: "perm-0".into(),
        tool: "run_shell".into(),
        risk: RiskClass::Exec,
        input: serde_json::json!({"command": "echo hi"}),
    });
    assert!(app.pending_permission.is_some());

    app.on_mouse(MouseEventKind::ScrollUp);
    assert_eq!(app.scroll_offset, 3);
}

/// `TurnStarted`でUpstream概算・ライブ状態がセットされ、`TextDelta`/`ThinkingDelta`で
/// Downstreamの文字数概算が積み上がり、`TurnCompleted`でセッション累計へ確定値が
/// 合算されて`turn_in_flight`が`false`に戻ることを確認する（リアルタイムトークン表示）。
#[test]
fn tracks_live_token_estimates_and_accumulates_session_usage() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 42,
    });
    assert!(app.turn_in_flight);
    assert_eq!(app.current_turn_upstream_estimate, 42);
    assert_eq!(app.current_turn_downstream_chars, 0);

    app.apply(AgentEvent::ThinkingDelta {
        text: "abcd".into(),
    });
    assert_eq!(app.current_turn_downstream_chars, 4);
    app.apply(AgentEvent::TextDelta {
        text: "hello".into(),
    });
    assert_eq!(app.current_turn_downstream_chars, 9);

    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage {
            input: 10,
            output: 5,
            cache_read: 1,
            cache_creation: 2,
        },
    });
    assert!(!app.turn_in_flight);
    assert_eq!(
        app.session_usage,
        Usage {
            input: 10,
            output: 5,
            cache_read: 1,
            cache_creation: 2
        }
    );

    // 2ターン目は既存の累計へ加算される。
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 7,
    });
    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage {
            input: 3,
            output: 2,
            cache_read: 0,
            cache_creation: 0,
        },
    });
    assert_eq!(
        app.session_usage,
        Usage {
            input: 13,
            output: 7,
            cache_read: 1,
            cache_creation: 2
        }
    );
}

/// thinkingを使ったターンでは、本文が届いた時点で「考え中」インジケータが消え、
/// `(thought for ...)`という記録行がtranscriptへ1つだけ残ることを確認する。
#[test]
fn thinking_progress_leaves_a_record_when_thinking_was_used() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    assert!(app.thinking_progress.is_some());

    app.apply(AgentEvent::ThinkingDelta { text: "hmm".into() });
    assert!(
        app.thinking_progress.is_some(),
        "still thinking, indicator stays"
    );

    app.apply(AgentEvent::TextDelta {
        text: "answer".into(),
    });
    assert!(
        app.thinking_progress.is_none(),
        "indicator clears once real content starts"
    );

    let thought_notes = app
        .transcript
        .iter()
        .filter(|item| matches!(item, TranscriptItem::Info(s) if s.starts_with("(thought for")))
        .count();
    assert_eq!(thought_notes, 1);
}

/// thinkingを使わなかったターンでは、本文到達時にインジケータが黙って消えるだけで
/// `(thought for ...)`の記録行は残らない（ノイズを避けるため）。
#[test]
fn no_thought_record_when_thinking_was_not_used() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta {
        text: "immediate answer".into(),
    });
    assert!(app.thinking_progress.is_none());

    let thought_notes = app
        .transcript
        .iter()
        .filter(|item| matches!(item, TranscriptItem::Info(s) if s.starts_with("(thought for")))
        .count();
    assert_eq!(thought_notes, 0);
}

/// ツール呼び出しだけで本文が無いまま終わるターンでも、安全網として
/// `thinking_progress`が確実に片付くことを確認する。
#[test]
fn tool_call_without_text_still_clears_thinking_progress() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::ToolCallProposed {
        id: "call_1".into(),
        name: "read_file".into(),
        input: serde_json::json!({}),
    });
    assert!(app.thinking_progress.is_none());
}

/// LMStudio等のローカルモデルが応答冒頭に送ってくる意味の無い改行だけのデルタ
/// （例:`"\n\n"`）は、まだ非空白の内容が届いていないので蓄積されず、「考え中」
/// インジケータも消えずに残ることを確認する（消えた場所に空行だけが残る問題の回帰防止）。
#[test]
fn leading_whitespace_only_deltas_are_dropped_and_indicator_stays() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });

    app.apply(AgentEvent::TextDelta {
        text: "\n\n".into(),
    });
    assert!(
        app.thinking_progress.is_some(),
        "still waiting for real content"
    );
    assert!(
        app.transcript.is_empty(),
        "whitespace-only delta must not create an item"
    );

    app.apply(AgentEvent::TextDelta {
        text: "Hello".into(),
    });
    assert!(
        app.thinking_progress.is_none(),
        "indicator clears once real content arrives"
    );
    assert_eq!(app.transcript.len(), 1);
    assert!(matches!(&app.transcript[0], TranscriptItem::Assistant(s) if s == "Hello"));
}

/// 非空白の内容が複数のデルタに分かれて届く通常ケースは引き続き1つのAssistant項目へ
/// 連結されることを確認する（回帰防止）。
#[test]
fn subsequent_text_deltas_still_append_to_the_same_assistant_item() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta { text: "Hel".into() });
    app.apply(AgentEvent::TextDelta { text: "lo".into() });

    assert_eq!(app.transcript.len(), 1);
    assert!(matches!(&app.transcript[0], TranscriptItem::Assistant(s) if s == "Hello"));
}

fn change_row(path: &str) -> ChangeRow {
    ChangeRow {
        entry: harness_sandbox::ChangeEntry {
            op: harness_sandbox::ManifestOp::Create,
            path: path.to_string(),
            baseline_hash: None,
        },
        diff: Vec::new(),
    }
}

/// 変更パネル表示中はCtrl+C等を含む通常のキー処理を一切通さず、パネル専用の
/// キーだけを処理する（承認モーダルと同じ排他パターン、§リッチTUI「変更パネル」）。
#[test]
fn changes_panel_consumes_keys_and_ignores_normal_input() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![change_row("a.txt"), change_row("b.txt")]);

    // 通常なら文字入力になるはずのキーもパネル表示中は`input`へ反映されない。
    assert!(app.on_key(key('z')).is_none());
    assert_eq!(app.input, "");
}

/// ↑↓でパネルの選択行が動き、末尾/先頭でクランプされる。
#[test]
fn changes_panel_up_down_moves_selection_and_clamps() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![
        change_row("a.txt"),
        change_row("b.txt"),
        change_row("c.txt"),
    ]);

    app.on_key(code(KeyCode::Up)); // 先頭でのUpは0のまま
    assert_eq!(app.changes_panel.as_ref().unwrap().selected, 0);

    app.on_key(code(KeyCode::Down));
    app.on_key(code(KeyCode::Down));
    assert_eq!(app.changes_panel.as_ref().unwrap().selected, 2);

    app.on_key(code(KeyCode::Down)); // 末尾でのDownは2のまま
    assert_eq!(app.changes_panel.as_ref().unwrap().selected, 2);
}

/// Enter/Spaceで選択中のエントリのaccept/reject（`rejected`集合への出し入れ）がトグルする。
#[test]
fn changes_panel_enter_toggles_reject_for_selected_entry() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![change_row("a.txt"), change_row("b.txt")]);

    app.on_key(code(KeyCode::Enter));
    assert!(app.changes_panel.as_ref().unwrap().rejected.contains(&0));

    app.on_key(code(KeyCode::Enter));
    assert!(!app.changes_panel.as_ref().unwrap().rejected.contains(&0));
}

/// `c`でコミット: reject印を付けたエントリを除いたパス集合が`Action::CommitChanges`として
/// 返り、パネルは閉じる。
#[test]
fn changes_panel_commit_excludes_rejected_entries_and_closes_panel() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![change_row("a.txt"), change_row("b.txt")]);
    app.on_key(code(KeyCode::Enter)); // a.txtをreject

    let action = app.on_key(key('c'));
    assert!(
        matches!(action, Some(Action::CommitChanges(paths)) if paths == vec!["b.txt".to_string()])
    );
    assert!(app.changes_panel.is_none());
}

/// `x`で全破棄: `Action::DiscardChanges`が返り、パネルは閉じる。
#[test]
fn changes_panel_discard_returns_action_and_closes_panel() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![change_row("a.txt")]);

    let action = app.on_key(key('x'));
    assert!(matches!(action, Some(Action::DiscardChanges)));
    assert!(app.changes_panel.is_none());
}

/// Escでパネルを閉じる（何もコミット/破棄しない）。
#[test]
fn changes_panel_esc_closes_without_action() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.open_changes_panel(vec![change_row("a.txt")]);

    let action = app.on_key(code(KeyCode::Esc));
    assert!(action.is_none());
    assert!(app.changes_panel.is_none());
}

// --- 縮退ガード（M21、`plans/DESIGN-COGNITION.md` §11.4） ---

fn discarded(next_rung: Option<&str>) -> AgentEvent {
    AgentEvent::TurnDiscarded {
        kind: harness_core::DegenerateKind::ShortPeriodRepeat,
        reason: "直近512文字の最小周期が1文字（512回反復）".into(),
        discarded_bytes: 42,
        next_rung: next_rung.map(str::to_string),
    }
}

/// 縮退した応答は**画面から消える**。捨てた出力が残っていると、再試行の本文と
/// 連結して読めてしまう（§11.4「当該assistant部分の表示を破棄して再描画」）。
#[test]
fn a_discarded_turn_rewinds_the_transcript_to_the_start_of_the_attempt() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TextDelta {
        text: "前のターンの回答".into(),
    });
    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage::default(),
    });

    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta {
        text: "壊れかけた出力".into(),
    });
    app.apply(discarded(Some("jitter")));

    // 前のターンは残り、このターンの本文だけが消えて記録行に置き換わる。
    assert_eq!(app.transcript.len(), 2, "{:?}", app.transcript);
    assert!(
        matches!(&app.transcript[0], TranscriptItem::Assistant(s) if s == "前のターンの回答")
    );
    let TranscriptItem::Info(line) = &app.transcript[1] else {
        panic!("expected an Info line, got {:?}", app.transcript[1]);
    };
    assert!(line.contains("[縮退]"), "{line}");
    assert!(line.contains("short_period_repeat"), "{line}");
    assert!(line.contains("再試行: jitter"), "{line}");

    // 再送の本文は新しい項目として積まれる（記録行へ連結しない）。
    app.apply(AgentEvent::TextDelta {
        text: "落ち着いた回答".into(),
    });
    assert_eq!(app.transcript.len(), 3);
    assert!(matches!(&app.transcript[2], TranscriptItem::Assistant(s) if s == "落ち着いた回答"));
}

/// 同じターンで2回破棄されても、**1回目の記録行は消えない**。消えると
/// 「何回捨てたのか」がユーザから見えなくなる。
#[test]
fn repeated_discards_within_one_turn_keep_every_record_line() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta { text: "壊れ1".into() });
    app.apply(discarded(Some("jitter")));
    app.apply(AgentEvent::TextDelta { text: "壊れ2".into() });
    app.apply(discarded(None));

    assert_eq!(app.transcript.len(), 2, "{:?}", app.transcript);
    for item in &app.transcript {
        let TranscriptItem::Info(line) = item else {
            panic!("expected only record lines, got {item:?}");
        };
        assert!(line.contains("[縮退]"), "{line}");
    }
    assert!(
        matches!(&app.transcript[1], TranscriptItem::Info(l) if l.contains("使い切った")),
        "{:?}",
        app.transcript[1]
    );
    // 捨てた本文はどちらも残っていない。
    let all = format!("{:?}", app.transcript);
    assert!(!all.contains("壊れ1"), "{all}");
    assert!(!all.contains("壊れ2"), "{all}");
}
