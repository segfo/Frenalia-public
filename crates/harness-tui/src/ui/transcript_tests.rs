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
    draw_at(app, 100);
}

/// [`draw`]を幅`width`の端末で（高さは30行）。
fn draw_at(app: &AppState, width: u16) {
    let mut term = Terminal::new(TestBackend::new(width, 30)).expect("test terminal");
    term.draw(|f| {
        render(f, app);
    })
    .expect("draw");
}

/// 行の文字だけ（書式を除く）。
fn texts(lines: &[Line<'_>]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect()
        })
        .collect()
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

/// **印は行と同じ数で、幅に収まる行だけなら全部`Break`**——どの種類の項目と、末尾の一時行
/// （`Thinking…`・バックグラウンド処理）が混じっても。畳んでいても広げていても。どの実装でも同じ（返答の行は
/// どれも98桁に収まるので、実装が分けた続きの行は無い）。
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

/// **空のassistantの返答は、空の1行の場所を取る**（どの実装でも同じ。`crate::markdown`のFacadeの規則）。
#[test]
fn an_empty_assistant_reply_takes_one_empty_line() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.transcript.push(TranscriptItem::Info("前".to_string()));
    app.transcript
        .push(TranscriptItem::Assistant(AssistantText::new("")));
    app.transcript.push(TranscriptItem::Info("後".to_string()));
    let (lines, joins) = transcript_lines(&app, false, 98);
    assert_eq!(texts(&lines), ["前", "", "後"]);
    assert_eq!(joins, vec![LineJoin::Break; 3]);
}

/// **assistantの返答のほかは、Markdownに見える記号があっても整形しない**——ユーザーの入力・thinking・ツールの入力と
/// 出力・知らせの行・エラーの行は、`**`も`#`もそのまま描く（計画書§1.7「対象はassistantの返答だけ」）。
#[test]
fn markdown_marks_outside_assistant_replies_stay_raw() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.push_user_prompt("**入力** の `x`".to_string());
    app.transcript
        .push(TranscriptItem::Thinking("**考え** # 見出し".to_string()));
    app.transcript.push(TranscriptItem::ToolCard {
        id: "t1".to_string(),
        name: "run_shell".to_string(),
        input: "**引数**".to_string(),
        status: ToolCardStatus::Done {
            is_error: false,
            output: "- **出力**".to_string(),
        },
    });
    app.transcript
        .push(TranscriptItem::Info("**知らせ**".to_string()));
    app.transcript
        .push(TranscriptItem::Error("**エラー**".to_string()));
    let (lines, _) = transcript_lines(&app, false, 98);
    assert_eq!(
        texts(&lines),
        [
            "> **入力** の `x`",
            "  **考え** # 見出し",
            "┌─ tool: run_shell ─────",
            "│ input: **引数**",
            "│ - **出力**",
            "└─────────────────────",
            "**知らせ**",
            "error: **エラー**",
        ]
    );
}

/// 計画書§1.9の分け方（`"# He"`・`"llo\n"`・`"\nThis "`・`"is **bo"`・`"ld**"`）。
const DELTAS: [&str; 5] = ["# He", "llo\n", "\nThis ", "is **bo", "ld**"];

/// 細切れに流れ込む返答の画面: 1つ届くたびに描き、終えた後のtranscriptの行。
fn streamed(on_frame: &mut impl FnMut(usize, &[Line<'static>])) -> Vec<Line<'static>> {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    for (k, delta) in DELTAS.iter().enumerate() {
        app.apply(text(delta));
        draw(&app);
        on_frame(k, &transcript_lines(&app, false, 98).0);
    }
    app.apply(AgentEvent::TurnCompleted {
        stop_reason: StopReason::EndTurn,
        usage: Usage::default(),
    });
    draw(&app);
    transcript_lines(&app, false, 98).0
}

/// **流れ込む返答は届いた分だけその都度描かれ、終えた後の画面は、全文を一度に渡したのと同じ**（どの実装でも同じ）。
#[test]
fn a_streamed_reply_is_drawn_as_it_arrives_and_ends_like_the_whole_reply_at_once() {
    let newest = ["He", "Hello", "This", "bo", "bold"];
    let last = streamed(&mut |k, lines| {
        let shown = texts(lines).concat();
        assert!(
            shown.contains(newest[k]),
            "{k}個目が届いた画面に「{}」が無い: {shown:?}",
            newest[k]
        );
    });

    let mut whole = AppState::new("mock".into(), "mock-model".into());
    whole
        .transcript
        .push(TranscriptItem::Assistant(AssistantText::new(
            DELTAS.concat(),
        )));
    draw(&whole);
    assert_eq!(last, transcript_lines(&whole, false, 98).0);
}

crate::markdown::formatting_only! {
    /// **[整形する実装] 閉じていない`**`は記号のまま見え、閉じる`**`が届いた瞬間に太字になる**（計画書§1.7。
    /// CommonMarkどおり）。見出しは流れ込みの途中から見出しの書式で描く。
    #[test]
    fn a_streamed_reply_turns_bold_when_the_closing_marks_arrive() {
        streamed(&mut |k, lines| {
            let spans: Vec<_> = lines.iter().flat_map(|line| line.spans.iter()).collect();
            let bold = |word: &str| {
                spans.iter().any(|span| {
                    span.content.contains(word) && span.style.add_modifier.contains(Modifier::BOLD)
                })
            };
            match k {
                0 => assert!(bold("He"), "見出しの書式になっていない: {spans:?}"),
                3 => {
                    assert!(texts(lines).concat().contains("**bo"), "閉じていない記号が消えた");
                    assert!(!bold("bo"), "閉じる前に太字になった");
                }
                4 => {
                    assert!(bold("bold"), "閉じたのに太字にならない: {spans:?}");
                    assert!(!texts(lines).concat().contains("**"), "記号が残った");
                }
                _ => {}
            }
        });
    }

    /// 1行ずつ確かめる返答（幅を超える日本語のリスト項目・英語の段落・URL・コードの行・表・入れ子・引用）。
    const WIDE_REPLIES: [&str; 7] = [
        "- これは画面の幅を超える長い日本語のリスト項目です。描画部品が自分で折り返すので、二行目以降は記号の幅だけ字下げされます。さらに続きます。\n",
        "The quick brown fox jumps over the lazy dog, and then it keeps running far beyond the edge of the screen while the dog keeps sleeping.\n",
        "See https://example.com/a/very/long/path/that/never/ends/and/keeps/going/far/beyond/the/edge/index.html?query=1 for details.\n",
        "```\nlet value = some_function_with_a_long_name(argument_one, argument_two, argument_three, argument_four);\n```\n",
        "| 名前 | 説明 |\n|---|---|\n| 長い名前の列 | とても長い説明の文章がこの列に入りますとても長い説明の文章がこの列に入ります |\n",
        "- 親の項目\n  - 子の項目です。長い説明が続いて、画面の幅を超えて折り返されます。長い説明が続いて、画面の幅を超えて折り返されます。\n",
        "> 引用です。長い文章は折り返されても縦線を保ちます。長い文章は折り返されても縦線を保ちます。長い文章は折り返されても縦線を保ちます。\n",
    ];

    /// **[整形する実装] assistantの返答の各行は、transcriptでちょうど1行に描かれる**（描画部品が幅に合わせて分けた行を、
    /// 共有の折り返し部品が二重に折り返さない。計画書§1.9の不変条件をtranscriptの側から）。端末の幅を変えて描き直しても
    /// 同じで、元の幅へ戻すと最初と同じ行になる。
    #[test]
    fn every_assistant_line_takes_exactly_one_row_at_any_terminal_width() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for reply in WIDE_REPLIES {
            app.transcript
                .push(TranscriptItem::Assistant(AssistantText::new(reply)));
        }
        let mut first = None;
        for width in [100u16, 60, 100] {
            draw_at(&app, width);
            let inner = width - 2;
            let (lines, joins) = transcript_lines(&app, false, inner);
            assert!(
                joins.iter().any(|join| matches!(join, LineJoin::Continues { .. })),
                "幅{width}で1行も分けていない（試験の前提）"
            );
            let rows = harness_term::wrap::line_rows(lines.clone(), inner);
            for (line, rows) in lines.iter().zip(&rows) {
                assert_eq!(*rows, 1, "幅{width}で2行以上に描かれた行: {line:?}");
            }
            match &first {
                None => first = Some(lines),
                Some(first) if width == 100 => {
                    assert_eq!(&lines, first, "元の幅へ戻すと最初と違う");
                }
                Some(_) => {}
            }
        }
    }
}
