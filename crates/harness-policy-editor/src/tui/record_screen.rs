//! 記録画面の描画。
//!
//! 実行中は**3つの枠を分ける**——進行（収集器・撤収・警告）、コマンドの出力、そして
//! シェルがコマンドを走らせる前に吐いた起動時ノイズ。最後の1つを本体の出力へ混ぜると、
//! 出力を持たないコマンド（`echo x > file`等）で「唯一の出力＝ノイズ」になり、成功が失敗に
//! 見える（BUG-086・B-33）。切り分けは`record`側が済ませているので、ここは混ぜないだけでよい。

use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::state::{
    format_elapsed, progress_bar, spinner_frame, App, Pass, RecordField, RunState,
};
use crate::tui::text_input::TextInput;

/// 入力欄のラベル幅（全角6文字ぶん）。
const LABEL_WIDTH: u16 = 12;

/// 戻り値はこの描画で判明したさかのぼり上限（[`ScrollLimits`]）。
/// 呼び出し側が`App::clamp_scroll`へ渡す（BUG-076と同じ理由。`scrollback`のdoc）。
pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> ScrollLimits {
    let chunks = record_rows(area);
    draw_form(frame, chunks[0], app);
    match app.run.as_ref() {
        Some(run) => draw_progress(frame, chunks[1], run),
        None => {
            draw_notice(frame, chunks[1], app);
            ScrollLimits::default()
        }
    }
}

/// 記録画面の縦割り（フォーム／本文）。**描画とマウスの当たり判定が同じ関数を通る**
/// ——別々に計算すると、片方だけ直したときに「見えている枠と反応する枠がずれる」。
fn record_rows(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::vertical([Constraint::Length(7), Constraint::Min(3)]).split(area)
}

/// 記録画面の本文（フォームの下）。[`progress_areas`]へ渡す矩形で、テストからも使う。
pub fn record_body_area(area: Rect) -> Rect {
    record_rows(area)[1]
}

/// 実行中に出る3つの枠の位置。[`draw_progress`]と[`scroll_target`]が共有する。
pub struct ProgressAreas {
    pub log: Rect,
    pub output: Rect,
    pub noise: Option<Rect>,
}

/// 実行中の枠割りを計算する（**純粋関数**。描画と当たり判定の唯一の正本）。
///
/// 枠の有無が`run`の中身で変わる（警告が無ければ枠を割かない・起動時ノイズが無ければ
/// 割かない）ので、当たり判定側も同じ`run`を見なければ一致しない。
pub fn progress_areas(area: Rect, run: &RunState) -> ProgressAreas {
    let columns =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    let left = if run.warnings.is_empty() {
        Layout::vertical([Constraint::Length(4), Constraint::Min(3)]).split(columns[0])
    } else {
        Layout::vertical([
            Constraint::Length(4),
            Constraint::Max(10),
            Constraint::Min(3),
        ])
        .split(columns[0])
    };
    let log = left[left.len() - 1];

    let right = if run.noise.is_empty() {
        vec![columns[1]]
    } else {
        Layout::vertical([Constraint::Min(3), Constraint::Length(5)])
            .split(columns[1])
            .to_vec()
    };

    ProgressAreas {
        log,
        output: right[0],
        noise: right.get(1).copied(),
    }
}

/// ホイールの位置から、どの枠のスクロール位置を動かすかを決める。
///
/// 実行中でなければどの枠も無い（`None`）——待機画面は1枚のParagraphで、
/// さかのぼる対象が無い。
pub fn scroll_target(area: Rect, app: &App, column: u16, row: u16) -> Option<ScrollPane> {
    let run = app.run.as_ref()?;
    let body = record_body_area(area);
    let areas = progress_areas(body, run);
    let at = Position::new(column, row);
    if areas.output.contains(at) {
        return Some(ScrollPane::Output);
    }
    if areas.log.contains(at) {
        return Some(ScrollPane::Log);
    }
    if areas.noise.is_some_and(|r| r.contains(at)) {
        return Some(ScrollPane::Noise);
    }
    None
}

/// スクロールできる枠の識別子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollPane {
    Log,
    Output,
    Noise,
}

fn draw_form(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" 記録 ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    // パス選択。フォーカスがあるときだけ ←/→ の案内を出す。
    let pass_focused = app.record_focus == RecordField::Pass;
    let mut pass_line = vec![
        Span::styled(pad_label("パス"), label_style(pass_focused)),
        Span::styled(
            app.pass.label().to_string(),
            Style::default().fg(Color::White),
        ),
    ];
    if pass_focused {
        pass_line.push(Span::styled(
            "   ←/→ で切替",
            Style::default().fg(Color::DarkGray),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(pass_line)), rows[0]);

    draw_input(
        frame,
        rows[1],
        "コマンド",
        &app.command,
        app.record_focus == RecordField::Command,
    );
    draw_input(
        frame,
        rows[2],
        "作業ディレクトリ",
        &app.cwd,
        app.record_focus == RecordField::Cwd,
    );
    if app.pass == Pass::Two {
        draw_input(
            frame,
            rows[3],
            "ドメイン",
            &app.run_domain,
            app.record_focus == RecordField::Domain,
        );
    }

    if let Some(run) = app.run.as_ref() {
        draw_phase(frame, rows[4], run);
    }
}

/// いま何を待っているのかの1行。会話TUI（`harness-tui`の準備画面）と同じ形
/// ——スピナー・経過`MM:SS`・段階名。**測れる進捗は測って出し、測れないものは経過だけ**に
/// する（合成した進捗を出すと、止まっているのに進んでいるように見える）。
fn draw_phase(frame: &mut Frame, area: Rect, run: &RunState) {
    let elapsed = run.elapsed();
    // 終わった記録はスピナーを回さない（回っていると「まだ動いている」と読まれる）。
    let mut spans = if run.finished {
        vec![
            Span::styled("✓ ", Style::default().fg(Color::Green)),
            Span::styled(
                match run.aborted {
                    Some(_) => "記録を打ち切りました".to_string(),
                    None => "記録が終わりました".to_string(),
                },
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   所要 {}", format_elapsed(elapsed)),
                Style::default().fg(Color::Gray),
            ),
        ]
    } else {
        vec![
            Span::styled(
                format!("{} ", spinner_frame(elapsed)),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                run.phase.label().to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   経過 {}", format_elapsed(elapsed)),
                Style::default().fg(Color::Gray),
            ),
        ]
    };
    if let Some(ratio) = run.phase_progress().filter(|_| !run.finished) {
        spans.push(Span::styled(
            format!("   {}", progress_bar(ratio, 16)),
            Style::default().fg(Color::Cyan),
        ));
    }
    if let Some(detail) = run.phase_detail().filter(|_| !run.finished) {
        spans.push(Span::styled(
            format!(" {detail}"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if run.events > 0 {
        spans.push(Span::styled(
            format!("   観測 {}件", run.events),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if run.stop_requested {
        spans.push(Span::styled(
            "   [停止を要求済み]",
            Style::default().fg(Color::Red),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_input(frame: &mut Frame, area: Rect, label: &str, input: &TextInput, focused: bool) {
    let line = Line::from(vec![
        Span::styled(pad_label(label), label_style(focused)),
        Span::styled(
            input.text().to_string(),
            if focused {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
    if focused {
        // カーソルは端末側に置く（入力位置と見た目が食い違わないよう桁で数える）。
        frame.set_cursor_position(Position::new(
            area.x + LABEL_WIDTH + input.cursor_col(),
            area.y,
        ));
    }
}

fn pad_label(label: &str) -> String {
    let width = unicode_width::UnicodeWidthStr::width(label) as u16;
    let pad = LABEL_WIDTH.saturating_sub(width) as usize;
    format!("{label}{}", " ".repeat(pad))
}

fn label_style(focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

/// 実行前に「何が起きるか」を出す。**UACが何回出るか・マシンに何が残るか**が判断材料なので、
/// 文言は実行する側（`record`/`record_net`）が持つものをそのまま見せる。
fn draw_notice(frame: &mut Frame, area: Rect, app: &App) {
    let mut text = app.pass.elevation_notice();
    if app.pass == Pass::Two {
        text.push_str(
            "\n\nTier2aへ着地しない場合とWFPが立たない場合は中止します\
             ——強制の無い観測を「記録できた」とは言わないためです。",
        );
    }
    text.push_str("\n\nEnter で開始します。");
    // 待機中に出たライブラリの警告（TUIが預かったstderr）は、黙って捨てずにここへ出す。
    if !app.notices.is_empty() {
        text.push_str("\n\n--- このプロセスの標準エラー出力 ---\n");
        for line in &app.notices {
            text.push_str(line);
            text.push('\n');
        }
    }
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 実行するとどうなるか "),
        ),
        area,
    );
}

fn draw_progress(frame: &mut Frame, area: Rect, run: &RunState) -> ScrollLimits {
    let columns =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    // 進行ログの一番上に「いま何を待っているのか」を出す。**無言の待ちは「壊れた」と読まれる**。
    // 終わったあとは待っていないので、代わりに**次にできること**を出す（画面は自動で
    // 動かさないので、ここが唯一の道案内になる）。
    // **対応が要る事実は専用の枠へ出す。** 進行ログは末尾だけを見せる窓なので、早い段階で
    // 出た警告（実行ファイルへ届かない等）は実行が終わる頃には流れて**見えなくなる**。
    // 実際にそうなった——`cargo test`が`Access is denied`で落ちたとき、原因と次の操作は
    // 進行ログに出ていたのにユーザーの画面には残っていなかった。
    // **無いときは枠を割かない**（空枠は何も伝えない。起動時ノイズの枠と同じ方針）。
    //
    // 枠の位置そのものは[`progress_areas`]が持つ（マウスの当たり判定と同じ計算を通すため）。
    // ここで再計算しているのは、警告枠のように**描画にしか使わない**中間の枠である。
    let left = if run.warnings.is_empty() {
        Layout::vertical([Constraint::Length(4), Constraint::Min(3)]).split(columns[0])
    } else {
        Layout::vertical([
            Constraint::Length(4),
            // 警告は数行で終わるものが多いが、実行ファイルの診断は3〜4行ある。
            Constraint::Max(10),
            Constraint::Min(3),
        ])
        .split(columns[0])
    };
    let areas = progress_areas(area, run);
    let log_area = areas.log;
    let (header_title, header_color, header_text) = if run.finished {
        (
            " 終わりました ",
            Color::Green,
            format!(
                "所要 {}。結果はこの画面に残ります（画面を往復しても消えません）。\n\
                 F2 / Ctrl+N で候補一覧へ。Enter でもう一度実行できます。",
                format_elapsed(run.elapsed())
            ),
        )
    } else {
        (
            " いま待っているもの ",
            Color::Cyan,
            format!(
                "{}（この段階の経過 {}）\n{}",
                run.phase.label(),
                format_elapsed(run.phase_started.elapsed()),
                run.phase.hint()
            ),
        )
    };
    frame.render_widget(
        Paragraph::new(header_text)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(header_color))
                    .title(header_title),
            ),
        left[0],
    );

    if !run.warnings.is_empty() {
        // **末尾ではなく先頭から出す。** 最初に出た警告がたいてい原因そのもの（後続の
        // 失敗はその結果）なので、あふれたときに残すべきは古い方である。
        let shown = left[1].height.saturating_sub(2) as usize;
        let mut lines: Vec<Line<'static>> = run
            .warnings
            .iter()
            .flat_map(|w| {
                w.lines()
                    .map(|l| Line::raw(l.to_string()))
                    .collect::<Vec<_>>()
            })
            .take(shown)
            .collect();
        let total: usize = run.warnings.iter().map(|w| w.lines().count()).sum();
        if total > shown && shown > 0 {
            // **省略したことを黙らない**（B-09）。全文は記録セッションのマニフェストに残る。
            lines.pop();
            lines.push(Line::raw(format!(
                "… 他 {}行（全文は record-session.json の warnings）",
                total - shown + 1
            )));
        }
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(format!(" ⚠ 対応が要ります（{}件） ", run.warnings.len())),
            ),
            left[1],
        );
    }

    // 描画と上限の算出は`harness_term::scrollback`が持つ（会話TUIのtranscriptと共有）。
    // **戻り値の上限を呼び出し側へ返す**――描画側だけでクランプすると、先頭まで
    // 遡った後も回した分だけ内部の値が伸び続け、下へ戻すときに空回りする（BUG-076）。
    let log_limit =
        harness_term::scrollback::render(
            frame,
            log_area,
            all_lines(&run.log),
            Block::default().borders(Borders::ALL).title(
                harness_term::scrollback::title_with_scroll(" 進行 ", run.log_scroll, SCROLL_HINT),
            ),
            run.log_scroll,
        );

    let output_title = match (run.exit_code, run.dropped) {
        (Some(code), 0) => format!(" コマンドの出力（exit {code}） "),
        (Some(code), dropped) => format!(" コマンドの出力（exit {code}・古い{dropped}行は省略） "),
        (None, 0) => " コマンドの出力 ".to_string(),
        (None, dropped) => format!(" コマンドの出力（古い{dropped}行は省略） "),
    };
    let output_limit = harness_term::scrollback::render(
        frame,
        areas.output,
        all_lines(&run.output),
        Block::default()
            .borders(Borders::ALL)
            .title(harness_term::scrollback::title_with_scroll(
                &output_title,
                run.output_scroll,
                SCROLL_HINT,
            )),
        run.output_scroll,
    );

    let mut noise_limit = 0;
    if let Some(noise_area) = areas.noise {
        noise_limit = harness_term::scrollback::render(
            frame,
            noise_area,
            all_lines(&run.noise),
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(harness_term::scrollback::title_with_scroll(
                    " シェル起動時のノイズ（コマンドの出力ではありません） ",
                    run.noise_scroll,
                    SCROLL_HINT,
                )),
            run.noise_scroll,
        );
    }

    ScrollLimits {
        log: log_limit,
        output: output_limit,
        noise: noise_limit,
    }
}

/// さかのぼり中のタイトルに出す戻し方。
const SCROLL_HINT: &str = "下へホイールで戻る";

/// 1フレーム描いて判明した、各枠のさかのぼり上限。
#[derive(Debug, Default, Clone, Copy)]
pub struct ScrollLimits {
    pub log: u16,
    pub output: u16,
    pub noise: u16,
}

/// 枠の全行を`Line`へ写す（窓切りはしない）。
///
/// **以前はここで末尾 N 行だけを取っていたが、それが不具合の正体だった**――
/// 数えていたのが折り返し**前**のバッファ行で、`Wrap`が効いている枠では
/// 1行が何行にもなるため、スクロール量と見えているものがずれた（cargoのビルドログは
/// 長い行が多い）。切り出しは`harness_term::scrollback::render`に任せる――あちらは
/// `Paragraph::line_count`で**折り返し後**の行を数える（会話TUIのtranscriptと同じ機構）。
fn all_lines(buffer: &std::collections::VecDeque<String>) -> Vec<Line<'static>> {
    buffer.iter().map(|line| Line::raw(line.clone())).collect()
}
