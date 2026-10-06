//! transcriptの行の組み立て（[`transcript_lines`]）の試験——assistantの返答を`crate::markdown`越しに描く配線
//! （描くときに流入中でない返答を終えること・行と同じ数の印を返すこと）。

use std::time::Instant;

use harness_core::{AgentEvent, StopReason, Usage};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::*;
use crate::app::AssistantText;

/// 製品と同じ入口（[`render`]）で1フレーム描く。
fn draw(app: &AppState) {
    let mut term = Terminal::new(TestBackend::new(100, 30)).expect("test terminal");
    term.draw(|f| {
        render(f, app);
    })
    .expect("draw");
}

/// assistantの返答それぞれが終えられているか（transcriptの順。ほかの項目は飛ばす）。
fn finished(app: &AppState) -> Vec<bool> {
    app.transcript
        .iter()
        .filter_map(|item| match item {
            TranscriptItem::Assistant(text) => Some(text.is_finished()),
            _ => None,
        })
        .collect()
}

fn text(text: &str) -> AgentEvent {
    AgentEvent::TextDelta {
        text: text.to_string(),
    }
}

/// **描くと、流入中の項目（ターンが開いていて最後の項目）を除くassistantの返答が全部終えられる。** 流入中の項目は、
/// ターンが閉じた後に描いたときに終えられる。割り込み（thinking）で分かれた前半は、もう足されないので終えられる
/// （BUG-232の形）。描かなければ誰も終えない。
#[test]
fn drawing_finishes_every_assistant_item_except_the_one_streaming_in() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.transcript
        .push(TranscriptItem::Assistant(AssistantText::new("前の返答")));
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(text("前半"));
    app.apply(AgentEvent::ThinkingDelta {
        text: "考え".to_string(),
    });
    app.apply(text("後半"));
    assert_eq!(finished(&app), [false, false, false], "描く前に終えている");

    draw(&app);
    assert_eq!(finished(&app), [true, true, false]);

    app.apply(text("の続き"));
    draw(&app);
    assert_eq!(finished(&app), [true, true, false], "流入中の項目を終えた");

    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage::default(),
    });
    draw(&app);
    assert_eq!(
        finished(&app),
        [true, true, true],
        "ターンが閉じた後に描いても終えていない"
    );
}

/// **印は行と同じ数で、いまの描き方（原文のまま）では全部`Break`**——どの種類の項目と、末尾の一時行
/// （`Thinking…`・バックグラウンド処理）が混じっても。畳んでいても広げていても。
#[test]
fn every_line_gets_exactly_one_join() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.push_user_prompt("質問".to_string());
    app.transcript
        .push(TranscriptItem::Assistant(AssistantText::new(
            "1行目\n2行目\n\n4行目",
        )));
    app.transcript
        .push(TranscriptItem::Thinking("考え\n続き".to_string()));
    app.transcript.push(TranscriptItem::ToolCard {
        id: "t1".to_string(),
        name: "run_shell".to_string(),
        input: "{}".to_string(),
        status: ToolCardStatus::Done {
            is_error: false,
            output: "a\nb".to_string(),
        },
    });
    app.transcript
        .push(TranscriptItem::Assistant(AssistantText::new("")));
    app.transcript.push(TranscriptItem::Error("e".to_string()));
    app.transcript.push(TranscriptItem::Info("i".to_string()));
    app.thinking_progress = Some(Instant::now());
    assert!(app.begin_busy("Compacting context"));
    for collapsed in [true, false] {
        let (lines, joins) = transcript_lines(&app, collapsed, 98);
        assert_eq!(joins.len(), lines.len(), "畳んでいる={collapsed}");
        assert!(
            joins.iter().all(|join| *join == LineJoin::Break),
            "畳んでいる={collapsed}: {joins:?}"
        );
    }
}
