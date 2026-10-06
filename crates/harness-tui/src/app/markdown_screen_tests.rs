//! assistantの返答を**整形する実装で**描いた画面と、その範囲選択・コピーの試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`
//! §0のT9）。整形する実装を選んだビルドでだけ置く（`crate::markdown::formatting_only`）。
//!
//! 親（`select_tests`）と同じく製品の入口を通す——製品の描画で描き、マウスとキーは`AppState::handle_event`へ入れ、
//! 押す位置は描いた画面のセルの文字から取る。整形した結果の文字（記号`• `・見出しの`#`を外した文字）は、計画書§1.2の
//! 図と描画部品の特性化試験（`crate::markdown`の中）が決めたものを、ここでは画面とコピーの側から確かめる。

use super::*;

/// transcriptの枠の内側の行（左上の角の下から、左下の角の上まで）。枠線と、右の枠線の上のスクロールバーは除き、
/// 行末の空白も除く。
fn transcript_rows(screen: &Screen) -> Vec<String> {
    (1..)
        .map(|y| screen.row(y))
        .take_while(|row| !row.starts_with('└'))
        .map(|row| {
            let mut chars: Vec<char> = row.chars().collect();
            chars.remove(0);
            chars.pop();
            chars.into_iter().collect::<String>().trim_end().to_string()
        })
        .collect()
}

/// 見出し・太字・コード・リンク・箇条書き・コードブロックを含む返答。
const FORMATTED: &str = "# 見出し\n\n**太字** と `code` と [リンク](https://example.com)\n\n- 項目 1\n- 項目 2\n\n```rust\nlet x = 1;\n```\n";

/// **assistantの返答は整形して描く**——記号（`#`・`**`・`` ` ``・`[…](…)`・フェンス）は描かず、見出しはシアンの太字、
/// 太字は太字、コードはコードの色、リンクは青の下線（URLは文中に出さない）、箇条書きは`• `で描く。
#[test]
fn assistant_markdown_is_drawn_formatted() {
    let mut app = app_with_items(&[FORMATTED]);
    let screen = draw(&mut app);
    let rows = transcript_rows(&screen);
    assert_eq!(
        rows[..10],
        [
            "見出し",
            "",
            "太字 と code と リンク",
            "",
            "• 項目 1",
            "• 項目 2",
            "",
            "let x = 1;",
            "",
            "",
        ],
        "{}",
        screen.text()
    );

    let heading = screen.style(screen.find("見出し"));
    assert_eq!(heading.fg, Some(Color::Cyan));
    assert!(heading.add_modifier.contains(Modifier::BOLD));
    assert!(screen
        .style(screen.find("太字"))
        .add_modifier
        .contains(Modifier::BOLD));
    assert_eq!(
        screen.style(screen.find("code")).fg,
        Some(Color::Indexed(180))
    );
    let link = screen.style(screen.find("リンク"));
    assert_eq!(link.fg, Some(Color::Blue));
    assert!(link.add_modifier.contains(Modifier::UNDERLINED));
    assert_eq!(
        screen.style(screen.find("let x = 1;")).fg,
        Some(Color::Indexed(180))
    );
    // 整形しない文字には見た目が付かない（許可側だけでなく、付けすぎていないこと）。
    let between = screen.style(screen.find(" と "));
    assert_eq!(
        (between.fg, between.add_modifier),
        (Some(Color::Reset), Modifier::empty())
    );
}

/// 箇条書きの1項目。transcriptの幅（本文97桁）で3行以上に折り返す長さで、最後は「終わり。」。
const LONG_ITEM: &str = "これは画面の幅を超える長い日本語のリスト項目です。描画部品が自分で折り返すので、二行目以降は記号の幅だけ字下げされます。コピーすると元の一行に戻ります。さらに長く続けて、三行目まで折り返させます。ここで終わり。";

/// **画面の幅を超える日本語のリスト項目は、続きの行を記号`• `の幅だけ字下げして折り返す**（継続インデント）。
/// **項目の文字を全部選んで写すと、改行も字下げも入らない元の1行になる**（描画部品が分けた行は`LineJoin`で
/// つながる。計画書§2）。
#[test]
fn a_long_japanese_list_item_wraps_with_a_hanging_indent_and_copies_as_one_line() {
    let mut app = app_with_items(&[&format!("- {LONG_ITEM}\n")]);
    let screen = draw(&mut app);
    let (x0, y0) = screen.find("これは");
    let (_, last) = screen.find("終わり。");
    assert_eq!(x0, 3, "記号`• `の後ろから始まらない:\n{}", screen.text());
    assert_eq!(screen.cell((1, y0)), "•");
    assert!(last >= y0 + 2, "3行以上に折り返していない（試験の前提）");
    for y in y0 + 1..=last {
        assert_eq!(
            (screen.cell((1, y)), screen.cell((2, y))),
            (" ", " "),
            "{y}行目が記号の幅だけ字下げされていない:\n{}",
            screen.text()
        );
        assert_ne!(screen.cell((3, y)), " ", "{y}行目の字下げが深すぎる");
    }

    let (x, y) = screen.find("終わり。");
    drag(&mut app, (x0, y0), (x + 7, y));
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(copied.as_deref(), Some(LONG_ITEM), "{other}");
}

/// **ブロックをまたいで写すと、本当の行の区切り（ブロックの間の空行・項目の間）は`CRLF`になる**。写るのは描いた文字
/// （見出しの`#`は無く、箇条書きは`• `）。
#[test]
fn copying_across_blocks_gives_crlf_at_the_real_line_breaks() {
    let mut app = app_with_items(&["# 見出し\n\n段落の文。\n\n- 項目 1\n- 項目 2\n"]);
    let screen = draw(&mut app);
    let (x, y) = screen.find("項目 2");
    drag(&mut app, screen.find("見出し"), (x + 5, y));
    let (copied, other) = ctrl_c(&mut app);
    assert_eq!(
        copied.as_deref(),
        Some("見出し\r\n\r\n段落の文。\r\n\r\n• 項目 1\r\n• 項目 2"),
        "{other}"
    );
}

/// **[整形する実装での見え方] Markdownに見える記号を含むassistantの返答**（`super::MARKDOWN_LOOKING`。整形しない実装の
/// ビルドでは、同じ文章が記号のまま描かれ原文のまま写ることを`super::markdown_looking_assistant_text_is_drawn_and_copied_verbatim`
/// が確かめる）。
///
/// T5で「今の見え方」として固定した試験を、T9で整形する実装へ差し替えたので**意図して書き換えた**——記号は描かれず、
/// 写ると描いた文字になる（原文ではない）。幅を超える長い行は描画部品が全角文字の間で分け、写すと1行に戻る。
#[test]
fn markdown_looking_assistant_text_is_formatted_and_copied_as_drawn() {
    let mut app = app_with_items(&[MARKDOWN_LOOKING]);
    let screen = draw(&mut app);
    let long = MARKDOWN_LOOKING.lines().last().expect("行がある");
    let drawn = [
        "見出し",
        "",
        "太字 と code と 斜体",
        "",
        "• item 1",
        "  • 入れ子の item",
        "",
        "1. 番号付き",
        "",
        "│ 引用の行",
        "",
        "    let x = 1;",
        "",
    ];
    let rows = transcript_rows(&screen);
    assert_eq!(rows[..drawn.len()], drawn, "{}", screen.text());
    // 長い行は2行に分かれ（全角48文字＝96桁で本文の97桁に収まる）、つなぐと原文の1行になる。
    let first = drawn.len();
    assert_eq!(rows[first].chars().count(), 48, "{}", screen.text());
    assert_eq!(format!("{}{}", rows[first], rows[first + 1]), long);
    assert_eq!(rows[first + 2], "", "長い行が2行より多く分かれた");

    let (x, y) = screen.find_last("行です。");
    drag(&mut app, (1, 1), (x + 7, y));
    let (copied, other) = ctrl_c(&mut app);
    let mut want = drawn.join("\r\n");
    want.push_str("\r\n");
    want.push_str(long);
    assert_eq!(copied.as_deref(), Some(want.as_str()), "{other}");
}

/// **Markdownとしては何も描かない返答（参照リンクの定義だけ）も、空の1行の場所を取る**（返答があったことが画面から
/// 消えない。`crate::markdown`のFacadeの規則で、どの実装でも同じ）。
#[test]
fn a_reply_that_markdown_draws_as_nothing_still_takes_one_empty_line() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.transcript
        .push(TranscriptItem::Info("前の知らせ".into()));
    app.transcript
        .push(TranscriptItem::Assistant(AssistantText::new(
            "[a]: https://example.com\n",
        )));
    app.transcript
        .push(TranscriptItem::Info("後の知らせ".into()));
    let screen = draw(&mut app);
    assert_eq!(
        transcript_rows(&screen)[..3],
        ["前の知らせ", "", "後の知らせ"],
        "{}",
        screen.text()
    );
}

/// **BUG-232の割り込みでコードブロックの途中が別の項目に分かれたら、項目ごとに独立に描く**（計画書§0のT9で決めた）。
///
/// 流入中にthinking（や知らせの行）が入ると、後の文章は新しいassistantの項目として始まる（`app::events`の
/// `TextDelta`。BUG-232の直し方）。前の項目は閉じていないフェンスのままコードブロックとして描き、後の項目は
/// 文書の頭から描く——後の項目の最初の行（本当はコードの続き）は段落になり、閉じるはずのフェンスは新しい
/// コードブロックを開く。
///
/// 前の項目と続けて1つの文書として解析する案は採らなかった。割り込みはまれで（計画書§5）、続けて解析すると、
/// 画面では間にthinkingが挟まっているのに1つの文書として描くことになり、項目ごとにMarkdownの描き手を1つ持つ形
/// （`AssistantText`）を崩して、項目をまたいで解析の状態を渡す口が要る。
#[test]
fn an_interruption_inside_a_code_fence_splits_the_reply_and_each_part_is_drawn_on_its_own() {
    let mut app = AppState::new("mock".into(), "mock-model".into());
    app.apply(AgentEvent::TurnStarted {
        estimated_input_tokens: 0,
    });
    app.apply(AgentEvent::TextDelta {
        text: "```rust\nlet a = 1;\n".to_string(),
    });
    draw(&mut app);
    app.apply(AgentEvent::ThinkingDelta {
        text: "考え中".to_string(),
    });
    app.apply(AgentEvent::TextDelta {
        text: "let b = 2;\n```\nafter\n".to_string(),
    });
    let screen = draw(&mut app);
    assert_eq!(
        transcript_rows(&screen)[..5],
        [
            "let a = 1;",
            "  (thinking, 3 chars, Ctrl+O to expand)",
            "let b = 2;",
            "",
            "after"
        ],
        "{}",
        screen.text()
    );
    let code = Some(Color::Indexed(180));
    assert_eq!(screen.style(screen.find("let a = 1;")).fg, code);
    assert_ne!(
        screen.style(screen.find("let b = 2;")).fg,
        code,
        "後の項目の頭がコードとして描かれた（前の項目と続けて解析している）"
    );
    assert_eq!(screen.style(screen.find("after")).fg, code);
}
