//! `AppState`から毎フレーム全ウィジェットを再描画する（即時モード、§リッチTUI）。
//!
//! レビューパネル（1画面を占める自己完結した面）の描画だけは[`review`]へ分けている
//! （`docs/CODE-STRUCTURE-RULES.md`規則3）。
//!
//! 描くついでに、押せる場所とホイールで送れる枠を**描いたその矩形で**登録して返す（`crate::app::pointer`）。

mod approval;
mod review;

pub(crate) use approval::render_permission_modal;

use crossterm::event::KeyEvent;
use harness_term::button::Press;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{
    spinner_glyph, wait_figures, AppState, Click, DrawFeedback, InputButton, KeyHint, NoticeTone,
    Targets, ToolCardStatus, TranscriptItem, WaitClock, Wheel, SPINNER_FRAMES,
};

/// 入力欄が自動で伸びる最大行数。これを超えると内部スクロールする（カーソル行が
/// 常に見えるよう毎フレーム再計算する。transcriptの`scroll_offset`のような永続的な
/// スクロール状態は入力欄には持たせない）。
const MAX_INPUT_VISIBLE_LINES: u16 = 6;

/// 1フレーム描画し、**この描画で判明したこと**（送れる上限・一覧の表示位置・押せる場所）を返す
/// （[BUG-076](../../../docs/bugs/BUG-076.md)）。総行数は折り畳み状態と端末幅に依存するため
/// 描画時にしか決まらない。呼び出し側は戻り値を`AppState::apply_draw_feedback`へ渡し、状態そのものを
/// 切り詰める——ここで表示だけ止めても、状態は青天井に伸び続けてしまう。
pub fn render(f: &mut Frame, app: &AppState) -> DrawFeedback {
    // 複数行入力（既定でEnterが改行を挿入するようになったため）にあわせ、入力欄の高さを
    // 行数に応じて`MAX_INPUT_VISIBLE_LINES`まで自動で伸ばす（それ以上は内部スクロール）。
    // **行数は折り返した後で数える**（[`input_rows`]）——長い1行も幅で折り返して全部見えるようにしたので、
    // `\n`の数で数えると高さが足りず、貼った値の続きが見えないままになる。
    let input_rows = input_rows(&app.input, input_text_width(f.area().width, app) as usize);
    let input_height = (input_rows.len() as u16).clamp(1, MAX_INPUT_VISIBLE_LINES) + 2; // +2=枠線
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(input_height),
        ])
        .split(f.area());

    // 押せる場所と送れる枠は描いた順に登録する（後から登録したものが上。重ねる枠は最後）。
    let mut targets = Targets::default();
    let mut feedback = DrawFeedback {
        transcript: render_transcript(f, root[0], app, &mut targets),
        ..DrawFeedback::default()
    };
    render_status(f, root[1], app);
    let input = render_input_row(
        f,
        root[2],
        app,
        &input_rows,
        &mut targets,
        &mut feedback.input_buttons,
    );

    if let Some(pending) = &app.pending_permission {
        behind_overlay(&mut targets, f.area(), root[0]);
        feedback.approval = Some(approval::render_permission_modal(
            f,
            f.area(),
            pending,
            &app.press,
            &mut targets,
            &app.selection,
            // 要約の待ちの行は「Thinking…」の行と同じ回る記号を使う（2つが別々に回らないように）。
            WaitClock {
                spinner_frame: app.spinner_frame,
                now: std::time::Instant::now(),
            },
        ));
    } else if let Some(panel) = &app.review_panel {
        behind_overlay(&mut targets, f.area(), root[0]);
        feedback.review = Some(review::render_review_panel(
            f,
            f.area(),
            panel,
            &mut targets,
            &app.selection,
        ));
    } else if app.selection_range().is_none() {
        // 端末の実カーソルを入力欄の入力末尾へ明示的に置く。ratatuiは`set_cursor_position`を
        // 呼ばない限りカーソルを隠したままにするため、これを怠るとOS/端末のIME（日本語等の
        // 変換候補ウィンドウ）が「前回カーソルがあった場所」（起動直後は画面右下等）に出てしまい、
        // 入力ボックスと無関係な位置に文字が表示されるように見える不具合が起きる。
        //
        // 選択中はあえて呼ばない: 端末のブロックカーソルは選択終端の直後の文字セルに重なって
        // 描画されるため、選択ハイライト（背景色）と隣接して見分けが付きにくく、選択範囲外の
        // 1文字まで選択されているかのような「幽霊」誤認を招く（実際にBackspace/Deleteしても
        // その文字は削除されず取り残される）。選択中はIMEの変換候補位置よりも選択範囲の
        // 視認性を優先する。
        //
        // 置くのは入力欄の枠の中（右のボタンを除いた幅）。行全体で数えると、長い行のカーソルがボタンの上へ出る。
        set_input_cursor(f, input, app, &input_rows);
    }

    feedback.targets = targets;
    feedback
}

/// 承認ダイアログ・レビューパネルを重ねる前に呼ぶ。**後ろの画面は押せなくし、transcriptだけはホイールで
/// 送れるまま、文章も選べるまま残す**（承認待ちの間も前の会話を読み返し、写せるように。`crate::app::pointer`・
/// `crate::app::select`のモジュールdoc）。
/// 重ねる枠は、この後に自分の矩形を覆ってから（`Targets::cover`）自分の場所を登録する——覆わないと、
/// 枠の中で何も登録していない場所（余白・案内の行）でホイールを回したときに、後ろのtranscriptが送られる。
fn behind_overlay(targets: &mut Targets, screen: Rect, transcript: Rect) {
    targets.cover(screen);
    targets.wheel(transcript, Wheel::Transcript);
    targets.lift_text(&Wheel::Transcript);
}

/// キー案内の項目の間の桁数（承認ダイアログとレビューパネルの案内の行）。
pub(super) const HINT_GAP: u16 = 3;

/// 会話画面のボタンの色。入力欄の右の「送信」「中断」と承認ダイアログの選択肢で同じにする（見た目を揃える）。
const BUTTON_COLOR: Color = Color::Cyan;

/// 入力欄の右にボタンを置いても、入力欄に残す幅（枠線2桁＋文字。`harness_term::button::KEEP_TEXT_WIDTH`）。
const MIN_INPUT_WIDTH: u16 = harness_term::button::KEEP_TEXT_WIDTH + 2;

/// キー案内の項目の見せ方。
#[derive(Debug, Clone, Copy)]
pub(super) enum HintLook<'a> {
    /// どの項目も案内の文字として描く（押せるかどうかで見た目を変えない。レビューパネルの案内。
    /// ポリシーエディタのキー案内と同じ）。ボタンの形ではないので、押されている形も無い。
    Text(Style),
    /// **押せる項目はボタン**（`harness_term::button::span`。ポリシーエディタの確認ダイアログのボタンと同じ部品）
    /// として描く（承認ダイアログの選択肢。2026-10-03、ユーザーが実機で
    /// 括弧書きの`[y] 一度だけ許可`を押せる場所に見えないと指摘した）。押せない項目（`PageUp/PageDown スクロール`・
    /// `↑↓ 移動`）は暗い文字のまま——1つのキーに決まらない案内で、ボタンの形にすると押せそうに見える。
    /// 押した瞬間からは押されている形で描く（`AppState::press`。`app::pointer`のモジュールdoc）。
    Buttons(&'a Press<Click>),
}

/// キー案内の項目を押したときの動き。ボタンとして描く項目は[`Click::Button`]（その値がボタンの名前になり、押されている
/// 形が付く）、文字のままの項目は[`Click::Key`]。**見た目を選ぶ[`hint_spans`]と登録する[`draw_hints`]が同じこれを通る**
/// ——別々に組むと、押されている形が登録した値と違う名前に付く。
fn hint_click(look: HintLook, key: KeyEvent) -> Click {
    match look {
        HintLook::Text(_) => Click::Key(key),
        HintLook::Buttons(_) => Click::Button(key),
    }
}

/// キー案内の項目を描く文字列（`look`の見せ方で）。**描く[`draw_hints`]と数える[`hint_rows`]が同じこれを通る**
/// ——ボタンは文言の左右に余白を持つので、別々に組むと数えた行数と描いた行数がずれる（押されている形は幅を変えない）。
fn hint_spans(hints: &[KeyHint], look: HintLook) -> Vec<Span<'static>> {
    hints
        .iter()
        .map(|hint| match (look, hint.key) {
            (HintLook::Text(style), _) => Span::styled(hint.label.clone(), style),
            (HintLook::Buttons(press), Some(key)) => harness_term::button::span(
                &hint.label,
                BUTTON_COLOR,
                press.look(&hint_click(look, key), true),
            ),
            (HintLook::Buttons(_), None) => {
                Span::styled(hint.label.clone(), Style::default().fg(Color::DarkGray))
            }
        })
        .collect()
}

/// キー案内の項目を`area`へ並べて描き（入り切らない項目は次の行の頭へ。項目の途中では割らない。
/// `harness_term::row::draw_wrapped`）、押せる項目をそのキーを押す場所として登録する。
/// 何行要るかは[`hint_rows`]が同じ置き方で数える。
pub(super) fn draw_hints(
    f: &mut Frame,
    area: Rect,
    hints: &[KeyHint],
    look: HintLook,
    targets: &mut Targets,
) {
    let drawn = harness_term::row::draw_wrapped(f, area, &hint_spans(hints, look), HINT_GAP);
    register_hints(targets, hints, &drawn, |key| hint_click(look, key));
}

/// [`draw_hints`]が`width`桁で何行使うか。
pub(super) fn hint_rows(hints: &[KeyHint], look: HintLook, width: u16) -> u16 {
    harness_term::row::wrapped_rows(&hint_spans(hints, look), HINT_GAP, width)
}

/// 描いた項目の矩形`drawn`（`hints`と同じ順）のうち、押せる項目を、押すと`click`（キー→動き）になる場所として登録する。
/// 2回続けて押す項目（`KeyHint::twice`。`Esc×2=終了`）は[`Click::KeyTwice`]——入力欄の見出し（案内の文字のまま描く）にしか
/// 無い。
fn register_hints(
    targets: &mut Targets,
    hints: &[KeyHint],
    drawn: &[Rect],
    click: impl Fn(KeyEvent) -> Click,
) {
    for (hint, rect) in hints.iter().zip(drawn) {
        if let Some(key) = hint.key {
            let pressed = if hint.twice {
                Click::KeyTwice(key)
            } else {
                click(key)
            };
            targets.click(*rect, pressed);
        }
    }
}

/// Tier3サンドボックス準備中の待機画面（`sandbox_prep::run_prep_screen`から呼ばれる）。
/// `latest`は合成進捗ticker（`harness_sandbox_vm::vmsandboxd_progress`、経過時間からの推測——
/// daemonの実測値ではない、モジュールdoc参照）からの最新イベント。初回tick到達前（`None`）
/// でも画面を空白にせず、スピナーと接続中の文言を出す。
#[cfg(windows)]
pub fn render_prep_screen(
    f: &mut Frame,
    latest: Option<&harness_sandbox_vm::vmsandboxd_progress::SandboxPrepEvent>,
    warm_requested: bool,
) {
    let rect = centered_rect(60, 30, f.area());
    harness_term::overlay::clear(f, rect);

    let (elapsed, label) = match latest {
        Some(ev) => (ev.elapsed, ev.label.as_str()),
        None => (std::time::Duration::ZERO, "接続しています…"),
    };
    let spinner = SPINNER_FRAMES[(elapsed.as_millis() / 100) as usize % SPINNER_FRAMES.len()];
    let total_secs = elapsed.as_secs();
    let (mm, ss) = (total_secs / 60, total_secs % 60);

    let caveat = if warm_requested {
        "（通常20秒程度で完了しますが、状態によっては数分かかる場合があります）"
    } else {
        "（初回起動は3分程度かかる場合があります）"
    };

    let lines = vec![
        Line::from(Span::styled(
            format!("{spinner} Tier3 サンドボックスを準備しています…"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("経過 {mm:02}:{ss:02}")),
        Line::from(label.to_string()),
        Line::from(""),
        Line::from(Span::styled(caveat, Style::default().fg(Color::DarkGray))),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title("sandbox preparing");
    harness_term::wrap::Wrapped::new(lines)
        .block(block)
        .render(f, rect);
}

/// 入力欄の画面1行分。`input`の文字インデックスの範囲（半開区間）。
///
/// **折り返した結果の1行**であって、`\n`で区切った1行ではない。入力欄の高さ・描く行・カーソルの置き場所の
/// 3つが同じこれを見る——別々に数えると、折り返した行数と描いた行数がずれて、カーソルが文字と違う場所に出る（`B-05`）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct InputRow {
    /// この行が持つ文字の範囲（半開区間）。
    range: std::ops::Range<usize>,
    /// 行の終わりが**改行か入力の末尾**か（`false`は幅で折り返した継ぎ目）。カーソルがちょうど行末に居るとき、
    /// どちらの行に置くかがこれで決まる（[`input_cursor_row`]）。
    hard: bool,
}

/// `input`を、幅`width`桁の入力欄に収まる画面1行ずつへ割る（[`InputRow`]）。
///
/// - `\n`で切ったうえで、**`width`桁を超える行は文字の途中でも折り返す**（2026-10-04、ユーザーの指示。
///   長いbase64を貼ると幅のぶんしか見えず、残りが入っていないように見えた）。語の切れ目では折り返さない
///   ——コマンドの行には空白が無いことがあり、空白で折ると貼った値がどこで切れたのか読めなくなる
/// - 全角文字は2桁として数える（画面の見た目に合わせる。[`set_input_cursor`]のIMEの位置も同じ数え方）
/// - 空の行・空の入力も**1行として残す**（0行にすると入力欄が消える）
fn input_rows(input: &str, width: usize) -> Vec<InputRow> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut at = 0usize; // 見ている文字のインデックス
    for line in input.split('\n') {
        let mut start = at; // いま組んでいる画面1行の、先頭の文字インデックス
        let mut used = 0usize; // いま組んでいる画面1行が使った桁数
        for c in line.chars() {
            let w = UnicodeWidthStr::width(c.to_string().as_str()).max(1);
            if used + w > width && at > start {
                rows.push(InputRow {
                    range: start..at,
                    hard: false, // 幅で折り返した継ぎ目
                });
                start = at;
                used = 0;
            }
            used += w;
            at += 1;
        }
        rows.push(InputRow {
            range: start..at,
            hard: true, // 改行か入力の末尾
        });
        at += 1; // `\n`の分
    }
    rows
}

/// `cursor`（先頭からの文字数）が何行目（[`input_rows`]の何番目）にあるか。
///
/// 行末にちょうど居るときの置き場所は、行の終わり方で変わる。**折り返した継ぎ目なら次の行の先頭**
/// （次に打つ文字が出る場所と同じ）、**改行・入力の末尾ならその行の末尾**（改行の手前に居るので、次の行へ送らない）。
fn input_cursor_row(rows: &[InputRow], cursor: usize) -> usize {
    rows.iter()
        .position(|row| cursor < row.range.end || (cursor == row.range.end && row.hard))
        .unwrap_or(rows.len().saturating_sub(1))
}

/// カーソル行が常に表示範囲(`visible`行分)に収まるような表示開始行を計算する。
fn input_scroll_start(cursor_line: usize, visible: usize) -> usize {
    if cursor_line >= visible {
        cursor_line + 1 - visible
    } else {
        0
    }
}

/// `input`を[`input_rows`]で割った画面1行ずつにし、各行を選択ハイライト（あれば）付きで`Line`に変換する。
/// `Frame`非依存の純粋関数（`diff.rs`と同様、単体テストしやすくするため描画から分離する）。
/// `selection`はバッファ全体を通した文字インデックスの`(start, end)`（半開区間）。
fn build_input_lines(
    input: &str,
    selection: Option<(usize, usize)>,
    rows: &[InputRow],
) -> Vec<Line<'static>> {
    let chars: Vec<char> = input.chars().collect();
    let mut lines = Vec::new();
    for row in rows {
        let (line_start, line_end) = (row.range.start, row.range.end.min(chars.len()));
        let line_str: String = chars[line_start..line_end].iter().collect();
        let local_selection = selection.and_then(|(sel_start, sel_end)| {
            let s = sel_start.max(line_start);
            let e = sel_end.min(line_end);
            if s < e {
                Some((s - line_start, e - line_start))
            } else {
                None
            }
        });
        let line = match local_selection {
            Some((s, e)) => {
                let chars: Vec<char> = line_str.chars().collect();
                let before: String = chars[..s].iter().collect();
                let selected: String = chars[s..e].iter().collect();
                let after: String = chars[e..].iter().collect();
                Line::from(vec![
                    Span::raw(before),
                    // 端末のブロックカーソル（多くの場合これも反転表示）と見分けが付くよう、
                    // 選択ハイライトは`REVERSED`ではなく明示的な背景色にする。選択終端の直後の
                    // セルにカーソルが重なると、`REVERSED`同士では選択範囲がその1文字分
                    // 余分に見え、実際は未選択の文字まで削除されるつもりで消し漏らす
                    // 「幽霊」誤認を招くため。色はマウスで選んだ文章と同じ（`harness_term::select::SELECTED`）。
                    Span::styled(selected, harness_term::select::SELECTED),
                    Span::raw(after),
                ])
            }
            None => Line::from(line_str.to_string()),
        };
        lines.push(line);
    }
    lines
}

fn set_input_cursor(f: &mut Frame, area: Rect, app: &AppState, rows: &[InputRow]) {
    let visible = area.height.saturating_sub(2).max(1) as usize;
    let cursor_line = input_cursor_row(rows, app.input_cursor);
    let scroll_start = input_scroll_start(cursor_line, visible);
    let line_start = rows.get(cursor_line).map_or(0, |row| row.range.start);
    // 枠線ぶん+1、カーソル行の行頭からカーソルまでの表示幅ぶん右へ（全角文字は2セル分として
    // IME側の位置計算と一致させる。§リッチTUI「入力ボックス」）。
    let prefix: String = app
        .input
        .chars()
        .skip(line_start)
        .take(app.input_cursor.saturating_sub(line_start))
        .collect();
    let col_width = UnicodeWidthStr::width(prefix.as_str()) as u16;
    let row = (cursor_line - scroll_start) as u16;
    let x = area.x + 1 + col_width;
    let y = area.y + 1 + row;
    f.set_cursor_position((
        x.min(area.x + area.width.saturating_sub(2)),
        y.min(area.y + area.height.saturating_sub(2)),
    ));
}

/// `collapsed`が`true`のとき、ツールカードの入力/出力本文とthinkingブロックの全文を
/// ヘッダ/要約1行だけに畳む（`Ctrl+O`トグル、Claude Code CLI相当の折り畳み表示）。
fn transcript_lines(app: &AppState, collapsed: bool) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for item in &app.transcript {
        match item {
            TranscriptItem::User(text) => {
                lines.push(Line::from(Span::styled(
                    format!("> {text}"),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
            }
            TranscriptItem::Assistant(text) => {
                for l in text.lines() {
                    lines.push(Line::from(l.to_string()));
                }
                if text.is_empty() {
                    lines.push(Line::from(""));
                }
            }
            TranscriptItem::Thinking(text) => {
                if collapsed {
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  (thinking, {} chars, Ctrl+O to expand)",
                            text.chars().count()
                        ),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    )));
                } else {
                    for l in text.lines() {
                        lines.push(Line::from(Span::styled(
                            format!("  {l}"),
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                }
            }
            TranscriptItem::ToolCard {
                name,
                input,
                status,
                ..
            } => {
                if collapsed {
                    let (glyph, color, summary) = match status {
                        ToolCardStatus::Running { wait_reason: None } => {
                            ("⚙".to_string(), Color::Yellow, "running".to_string())
                        }
                        // [BUG-082フォローアップ] 背景条件で待たされている間は理由を出す
                        // （ユーザーには起動失敗と区別が付かないため、`docs/bugs/BUG-082.md`）。
                        ToolCardStatus::Running {
                            wait_reason: Some(reason),
                        } => ("⏳".to_string(), Color::Yellow, reason.clone()),
                        ToolCardStatus::Done { is_error, output } => {
                            let lines = output.lines().count().max(1);
                            if *is_error {
                                ("✗".to_string(), Color::Red, format!("{lines} lines"))
                            } else {
                                ("✓".to_string(), Color::Green, format!("{lines} lines"))
                            }
                        }
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{glyph} tool: {name} ({summary}, Ctrl+O to expand)"),
                        Style::default().fg(color),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("┌─ tool: {name} ─────"),
                        Style::default().fg(Color::Yellow),
                    )));
                    lines.push(Line::from(format!("│ input: {input}")));
                    match status {
                        ToolCardStatus::Running { wait_reason: None } => {
                            lines.push(Line::from(Span::styled(
                                "│ ... running",
                                Style::default().fg(Color::Yellow),
                            )));
                        }
                        // [BUG-082フォローアップ] 待機理由を明示する。開発者は「初回起動は
                        // workspace ACL伝播を待つ」と知っているが、一般利用者にとって理由の
                        // 無い数十秒の沈黙は起動失敗と区別が付かない（`docs/bugs/BUG-082.md`）。
                        ToolCardStatus::Running {
                            wait_reason: Some(reason),
                        } => {
                            lines.push(Line::from(Span::styled(
                                format!("│ ... waiting: {reason}"),
                                Style::default().fg(Color::Yellow),
                            )));
                        }
                        ToolCardStatus::Done { is_error, output } => {
                            let color = if *is_error { Color::Red } else { Color::Green };
                            for l in output.lines() {
                                lines.push(Line::from(Span::styled(
                                    format!("│ {l}"),
                                    Style::default().fg(color),
                                )));
                            }
                        }
                    }
                    lines.push(Line::from(Span::styled(
                        "└─────────────────────",
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }
            TranscriptItem::Error(message) => {
                lines.push(Line::from(Span::styled(
                    format!("error: {message}"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            }
            TranscriptItem::Info(message) => {
                lines.push(Line::from(Span::styled(
                    message.clone(),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }
    }

    // 「Thinking…」進捗インジケータ: `app.transcript`本体には積まない一時的な行。
    // 本文/ツール呼び出しが届いた時点で`app.thinking_progress`が`None`に戻るため、
    // 次フレームからは自然に消え、実際の応答（既に上のループで描画済み）に置き換わって見える。
    if let Some(started) = app.thinking_progress {
        let glyph = spinner_glyph(app.spinner_frame);
        let figures = wait_figures(app.current_turn_downstream_chars, started.elapsed());
        lines.push(Line::from(Span::styled(
            format!("{glyph} Thinking… {figures}"),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }

    // BUG-070: `/compact`のようなターン外のバックグラウンド処理も、走っていることが
    // 見えないとユーザーは「効いていない」と思って連打してしまう。同じ位置・同じ見た目で
    // 出す（新しい語彙を覚えさせない）。
    //
    // BUG-071: ただし**まだ走っていない**なら`(queued)`と断る。engineは単一タスクで
    // ターンとコマンドを直列に処理するので、ターン実行中に送った`/compact`はキューで待つ。
    // ここで区別しないと、上の`Thinking…`と並んで2本のスピナーが回り、**同時に処理されて
    // いるように見えてしまう**。
    if let Some(busy) = &app.busy_progress {
        let glyph = spinner_glyph(app.spinner_frame);
        let elapsed = busy.elapsed().as_secs_f32();
        let queued = if busy.is_running() { "" } else { " (queued)" };
        lines.push(Line::from(Span::styled(
            format!("{glyph} {}{queued}… ({elapsed:.1}s)", busy.label),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }

    lines
}

/// 戻り値は`scroll_offset`の上限（[`render`]がそのまま返す）。
///
/// 枠全体をホイールで送れる場所として登録する。さかのぼっている間だけ見出しに出る「さかのぼり中」の案内は、
/// 押すと末尾へ戻る（見出しを`Block`に持たせず、上辺へ自分で描いて描いた場所を登録する）。
fn render_transcript(f: &mut Frame, area: Rect, app: &AppState, targets: &mut Targets) -> u16 {
    // 末尾追従の描画と上限の算出は`harness_term::scrollback`が持つ
    // （ポリシーエディタの記録画面と共有。同局のdoc参照）。
    // 戻り値の上限を`AppState::apply_draw_feedback`へ渡すのは呼び出し側の責務（BUG-076）。
    let lines = transcript_lines(app, app.collapsed);
    let max = harness_term::scrollback::render_with_bar(
        f,
        area,
        lines,
        Block::default().borders(Borders::ALL),
        app.scroll,
        Style::default(),
        harness_term::select::Selectable::new(targets, Wheel::Transcript, &app.selection),
    );
    targets.wheel(area, Wheel::Transcript);
    let notice =
        harness_term::scrollback::scrolled_notice(app.scroll, "下へホイールかここを押すと最新へ")
            .unwrap_or_default();
    let edge = harness_term::row::top_edge(area);
    // 写した結果・終了の仕方の知らせも上辺に出す（中身を動かさない。`crate::app::select`・`crate::app::quit`の
    // モジュールdoc）。入り切らなければ末尾を`…`で切る——失敗したこと（頭の「コピーできませんでした」）は必ず見える。
    let head = "transcript ";
    let room = usize::from(edge.width).saturating_sub(head.width() + notice.width());
    let told = match &app.edge_notice {
        Some(told) => Span::styled(
            fit_width(&format!("[{}] ", told.text), room),
            Style::default().fg(match told.tone {
                NoticeTone::Done => Color::Green,
                NoticeTone::Failed => Color::Red,
                NoticeTone::Hint => Color::Yellow,
            }),
        ),
        None => Span::raw(""),
    };
    let title = [Span::raw(head), Span::raw(notice), told];
    let drawn = harness_term::row::draw(f, edge, &title);
    targets.click(drawn[1], Click::ScrollToLatest);
    max
}

/// `text`を表示幅`width`桁に収める。入り切らなければ末尾を`…`にして切る（切ったことを黙らない）。
fn fit_width(text: &str, width: usize) -> String {
    use unicode_width::UnicodeWidthChar;

    if text.width() <= width {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if used + w + 1 > width {
            break;
        }
        out.push(c);
        used += w;
    }
    if width > 0 {
        out.push('…');
    }
    out
}

/// ステータスバーに出すモデル名の上限文字数。超えた分は中間を省略する。
///
/// ローカル推論サーバのモデル名は長くなりがちで（`qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp`
/// のように45文字を超える）、そのまま出すとステータスバーの他の項目——`stop=`やトークン数——が
/// 画面右端で切れて読めなくなる。
const MODEL_LABEL_MAX_CHARS: usize = 25;

/// `s`が`max_chars`を超える場合、**中間**を`…`1文字に置き換えて全体をちょうど`max_chars`に収める。
///
/// 末尾を落とす素朴な切詰めにしないのは、モデル名では前（系列名）と後ろ（版・量子化）の
/// **両端が識別に効く**ため。`qwen3.6-35b-…-v2-apex-mtp`のように、どの系列のどの版かが
/// 残る形にする。
///
/// 文字数（`chars().count()`）で数える。バイト数で切ると日本語を含む名前で境界が壊れる
/// （`harness_core::text::truncate_head_tail`と同じ理由。あちらは改行と件数付きの注記を挟む
/// **本文向け**で、1行に収めたいラベルには使えないためここで別に持つ）。
fn elide_middle(s: &str, max_chars: usize) -> String {
    let total = s.chars().count();
    if total <= max_chars {
        return s.to_string();
    }
    // `…`自身が1文字使うので、収まらないなら省略記号だけにする。
    if max_chars <= 1 {
        return "…".to_string();
    }
    let keep = max_chars - 1;
    let head_len = keep / 2;
    let tail_len = keep - head_len;
    let head: String = s.chars().take(head_len).collect();
    let tail: String = s.chars().skip(total - tail_len).collect();
    format!("{head}…{tail}")
}

/// ステータスバーの「いまどこを見ているか」の部分（`ws=…` と `overlay=…`）。
///
/// **オーバーレイのセッションIDが会話のそれと違うときは併記する。** `/clear`は会話だけを
/// 捨ててオーバーレイを引き継ぐ設計なので、この食い違いは正当だが黙っていてはいけない
/// ——「いま見ている変更は、いまの会話が作ったものではない」ことが画面から分かる必要がある
/// （BUG-072と同型の誤解を防ぐ。`bug-pattern-rules` B-22/B-32）。
///
/// `--live`ではオーバーレイが存在しないので`overlay=`自体を出さない（無いものの名前を
/// 出すと「あるのに空」と読めてしまう）。
fn scope_label(app: &AppState) -> String {
    let ws = if app.workspace_label.is_empty() {
        String::new()
    } else {
        format!(" | ws={}", app.workspace_label)
    };
    let Some(overlay) = &app.overlay_session_id else {
        return ws;
    };
    if overlay == &app.conversation_session_id {
        format!("{ws} | overlay={overlay}")
    } else {
        format!(
            "{ws} | overlay={overlay} (会話={})",
            app.conversation_session_id
        )
    }
}

fn render_status(f: &mut Frame, area: Rect, app: &AppState) {
    let stop = app
        .last_stop_reason
        .as_ref()
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "-".to_string());
    // ストリーミング中（`turn_in_flight`）は文字数ベースの概算値を"≈"付きでライブ表示し、
    // ターン完了後は`last_usage`の確定値を表示する（リアルタイムトークン表示、Upstream/Downstream）。
    let turn_tokens = if app.turn_in_flight {
        format!(
            "in≈{} out≈{}",
            app.current_turn_upstream_estimate,
            app.current_turn_downstream_chars / 4
        )
    } else {
        format!("in={} out={}", app.last_usage.input, app.last_usage.output)
    };
    // 何かがツール実行を待たせている間だけ出る。現状の源はD-54/BUG-082のworkspace背景ジョブ
    // （rootへの伝播＋保護DACL配下の救済walk）で、この間`run_shell`は完了を待つので、
    // 「TUIは出ているのにコマンドが動き出さない」理由がここで見える。
    //
    // **どの背景ジョブかも、件数を出せる段かも、ここでは分岐しない**（R-01）。表示文字列は
    // 源が作る。ここに`total > 0`のような判定を置くと、表示面を増やすたびに同じ判定が
    // 複製される（旧実装はTUIと`grant_job`の両方に持っていた）。
    let acl = match &app.wait_state {
        Some(state) => format!(" | {}", state.label),
        None => String::new(),
    };
    let text = format!(
        " {} | model={} | stop={} | tokens turn({turn_tokens}) session(in={} out={}){}{acl}",
        app.provider_label,
        elide_middle(&app.model, MODEL_LABEL_MAX_CHARS),
        stop,
        app.session_usage.input,
        app.session_usage.output,
        scope_label(app),
    );
    let paragraph = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::Black).bg(Color::Gray),
    )));
    f.render_widget(paragraph, area);
}

/// 入力欄の行を描く——左に入力欄、右に枠付きの「送信」（応答中は「中断」も）。戻り値は入力欄の矩形
/// （IMEのカーソルを置く場所。[`set_input_cursor`]）。
///
/// ```text
/// ┌input (Enter=改行, PageUp/PageDown=スクロール)────────────────────┐┌──────────┐┌──────────┐
/// │こんにちは                                                        ││   送信   ││   中断   │
/// └──────────────────────────────────────────────────────────────────┘└Alt+Enter─┘└───Esc────┘
/// ```
///
/// - **ボタンは入力欄の右隣に、枠で囲んで置く**（`AppState::input_buttons`。2026-10-03、ユーザーが実機を見て図を描いた
///   ——「ボタンってわかるようにしたい。枠みたいなの書ける？」）。下辺に対応するキーを添える。部品はポリシーエディタの
///   「記録」の枠の右のボタンと同じ（`harness_term::button::place_framed`）。押せるボタンだけを、そのキーを押す場所として
///   登録する（`Click::InputButton`。動いた直後は捨てる——`app::pointer`のモジュールdoc）。
/// - **入力欄が複数行で高くなっても、ボタンは右下の3行**（`place_framed`が行の下端にそろえる）。入力欄は上へ伸びる
///   ので、送信の位置は行数で変わらない。
/// - **狭い端末では**、入力欄に[`MIN_INPUT_WIDTH`]桁を残せる形を選ぶ——キーを添える形 → キーを落とした短い形 → 置かない
///   （置かないときは入力欄が行の幅いっぱい。キーは今までどおり効く）。
///
/// 描いたボタン（押せないものも）は`drawn`へ文言と矩形を入れる（`DrawFeedback::input_buttons`）。
/// 入力欄の右のボタンを、描く形（`harness_term::button::Framed`）と押したときの動きに組む。
///
/// **折り返しの幅を測る[`input_text_width`]と、実際に描く[`render_input_row`]が同じこれを通る**——別々に組むと、
/// 測った幅と描いた幅がずれて、折り返しの位置が1桁狂う（`B-05`）。押したときの動き（押せないボタンは`None`）も
/// ここで作る——**見た目を選ぶ名前と登録する値を同じ`InputButton`から取る**（別々に組むと、押されている形が登録した
/// 値と違う名前に付く。`app::pointer`のモジュールdoc）。押せないボタンにも名前を渡す——押した結果押せなくなった
/// 「送信」を、押されている形が戻るまで押されている形で描くため（`harness_term::button::Press::look`）。
fn input_framed(app: &AppState) -> (Vec<Option<Click>>, Vec<harness_term::button::Framed<'_>>) {
    let buttons = app.input_buttons();
    let clicks: Vec<Option<Click>> = buttons.iter().map(InputButton::click).collect();
    let framed = buttons
        .iter()
        .map(|b| harness_term::button::Framed {
            label: b.label,
            key: b.key_label,
            look: app.press.look(&b.name(), b.pressable),
        })
        .collect();
    (clicks, framed)
}

/// 入力欄の中に文字を置ける幅（枠線を除く）。端末の幅`total`から、右のボタンが取る分を引く。
///
/// **ボタンの置き方は高さに依らない**（`place_framed`は高さが`FRAMED_HEIGHT`以上かだけを見る）ので、入力欄の高さが
/// 決まる前にこれで測れる——高さは折り返した行数から決まるので、先に幅が要る。
fn input_text_width(total: u16, app: &AppState) -> u16 {
    let (_, framed) = input_framed(app);
    let probe = Rect::new(0, 0, total, harness_term::button::FRAMED_HEIGHT);
    let (input, _) = harness_term::button::place_framed(probe, &framed, MIN_INPUT_WIDTH);
    input.width.saturating_sub(2) // 枠線
}

fn render_input_row(
    f: &mut Frame,
    area: Rect,
    app: &AppState,
    rows: &[InputRow],
    targets: &mut Targets,
    drawn: &mut Vec<(&'static str, Rect)>,
) -> Rect {
    let buttons = app.input_buttons();
    let (clicks, framed) = input_framed(app);
    let (input, row) = harness_term::button::place_framed(area, &framed, MIN_INPUT_WIDTH);
    render_input(f, input, app, rows, targets);
    if let Some(row) = row {
        for ((button, click), rect) in buttons.iter().zip(clicks).zip(row.draw(f, BUTTON_COLOR)) {
            if let Some(click) = click {
                targets.click(rect, click);
            }
            drawn.push((button.label, rect));
        }
    }
    input
}

/// 入力欄を描く（右のボタンは[`render_input_row`]）。
///
/// **上辺の見出しは、キーボードの人のための案内**（`AppState::input_key_hints`）。押せる項目はそのキーを押す場所として
/// 登録する（9064b30から。区切りと括弧は押せない）。送信と中断は右のボタンにあるので見出しには無い
/// ——同じ操作を2か所に並べない（ポリシーエディタの確認ダイアログが`y=書く`を見出しからボタンへ移したのと同じ）。
/// 項目の途中では切らない（[`input_title`]）。
fn render_input(
    f: &mut Frame,
    area: Rect,
    app: &AppState,
    rows: &[InputRow],
    targets: &mut Targets,
) {
    let hints = app.input_key_hints();
    let top = harness_term::row::top_edge(area);
    let (title, at) = input_title(&hints, top.width);
    let block = Block::default().borders(Borders::ALL);

    let visible = area.height.saturating_sub(2).max(1) as usize;
    let cursor_line = input_cursor_row(rows, app.input_cursor);
    let scroll_start = input_scroll_start(cursor_line, visible);
    let visible_lines: Vec<Line> = build_input_lines(&app.input, app.selection_range(), rows)
        .into_iter()
        .skip(scroll_start)
        .take(visible)
        .collect();

    let paragraph = Paragraph::new(visible_lines).block(block);
    f.render_widget(paragraph, area);
    let drawn = harness_term::row::draw(f, top, &title);
    // 落とした項目は幅0（押せない。`Targets::click`は幅0を登録しない）。
    let drawn: Vec<Rect> = at
        .into_iter()
        .map(|i| i.map_or_else(Rect::default, |i| drawn[i]))
        .collect();
    register_hints(targets, &hints, &drawn, Click::Key);
}

/// 入力欄の見出し`input (項目, 項目, …)`を、上辺の幅`width`に収まる形で組む。戻り値は見出しのspanと、
/// 各項目（`hints`と同じ順）がそのspanの何番目か（落とした項目は`None`）。
///
/// 入り切らなければ**後ろの項目から丸ごと落とし**、落とした数を`… 他N件`で出す（ポリシーエディタのキー案内の
/// `fit_key_hints`と同じ規則——項目の途中で切ると残った文字が別のキーに読め、黙って落とすと省略が見えない。B-09）。
/// 並びの頭ほど残る。先頭は`Enter=改行`（`AppState::input_key_hints`）——Enterで送れると思って押すと改行になるので、
/// いちばん知らせたい。
/// 項目を全部落としても入らない幅では、そのまま描いて右で切れる（描画が落ちないことだけを保つ）。
fn input_title(hints: &[KeyHint], width: u16) -> (Vec<Span<'static>>, Vec<Option<usize>>) {
    let compose = |kept: usize| {
        let mut title = vec![Span::raw("input (")];
        let mut at = vec![None; hints.len()];
        for (i, hint) in hints[..kept].iter().enumerate() {
            if i > 0 {
                title.push(Span::raw(", "));
            }
            at[i] = Some(title.len());
            title.push(Span::raw(hint.label.clone()));
        }
        if kept < hints.len() {
            if kept > 0 {
                title.push(Span::raw(", "));
            }
            title.push(Span::raw(format!("… 他{}件", hints.len() - kept)));
        }
        title.push(Span::raw(")"));
        (title, at)
    };
    (0..=hints.len())
        .rev()
        .map(compose)
        .find(|(title, _)| harness_term::row::width(title) <= width)
        .unwrap_or_else(|| compose(0))
}

pub(super) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::widgets::Wrap;

    fn line_texts(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    /// 上限以下はそのまま。1文字も足さない（短いモデル名に`…`が付いて見えるのは誤り）。
    #[test]
    fn a_name_that_fits_is_returned_verbatim() {
        assert_eq!(elide_middle("claude-opus-5", 25), "claude-opus-5");
        assert_eq!(elide_middle(&"x".repeat(25), 25), "x".repeat(25));
    }

    /// 長い名前は**ちょうど上限の文字数**に収まり、系列名と版の両端が残る。
    #[test]
    fn a_long_name_keeps_both_ends_and_fits_exactly() {
        let out = elide_middle("qwen3.6-35b-a3b-uncensored-genesis-v2-apex-mtp", 25);
        assert_eq!(out.chars().count(), 25, "{out}");
        assert_eq!(out, "qwen3.6-35b-…-v2-apex-mtp");
    }

    /// マルチバイト文字の途中で切らない（バイト数で切るとパニックする）。
    #[test]
    fn a_multibyte_name_is_cut_on_character_boundaries() {
        let out = elide_middle(&"あ".repeat(100), 25);
        assert_eq!(out.chars().count(), 25, "{out}");
        assert!(out.starts_with("ああ") && out.ends_with("ああ"), "{out}");
    }

    /// 省略記号すら入らない上限でもパニックせず、上限を超えない。
    #[test]
    fn a_degenerate_limit_does_not_panic_or_overflow() {
        assert_eq!(elide_middle("abcdef", 1), "…");
        assert_eq!(elide_middle("abcdef", 0), "…");
        assert_eq!(elide_middle("abcdef", 2).chars().count(), 2);
    }

    /// 折り返さない幅（十分広い）での行割り。既存の試験が`\n`だけで割っていた頃と同じ結果になる幅を使う。
    fn unwrapped(input: &str) -> Vec<InputRow> {
        input_rows(input, 1_000)
    }

    /// 行の範囲だけを取り出す（行の終わり方は`the_cursor_sits_at_the_start_of_the_next_row_at_a_wrap`が見る）。
    fn ranges(rows: &[InputRow]) -> Vec<std::ops::Range<usize>> {
        rows.iter().map(|r| r.range.clone()).collect()
    }

    #[test]
    fn build_input_lines_splits_on_newlines_and_highlights_selection_within_a_line() {
        let input = "hello\nworld";
        // グローバル文字インデックス(1, 4) = "hello"内の"ell"。
        let lines = build_input_lines(input, Some((1, 4)), &unwrapped(input));
        assert_eq!(
            line_texts(&lines),
            vec!["hello".to_string(), "world".to_string()]
        );

        assert_eq!(lines[0].spans.len(), 3);
        assert_eq!(lines[0].spans[0].content, "h");
        assert_eq!(lines[0].spans[1].content, "ell");
        assert_eq!(
            lines[0].spans[1].style,
            Style::default().bg(Color::Blue).fg(Color::White)
        );
        assert_eq!(lines[0].spans[2].content, "o");

        // 2行目("world")は選択範囲に含まれないので単一スパンのまま。
        assert_eq!(lines[1].spans.len(), 1);
        assert_eq!(lines[1].spans[0].content, "world");
    }

    #[test]
    fn build_input_lines_selection_spanning_multiple_lines_highlights_each_locally() {
        // グローバル(3, 7) = "abc|de\nfg" のうち "d","e","\n","f" ... 実際は"\n"は
        // どちらの行にも属さないため、1行目は"de"(ローカル3..5)、2行目は"f"(ローカル0..1)
        // がそれぞれハイライトされる。
        let input = "abcde\nfghij";
        let lines = build_input_lines(input, Some((3, 7)), &unwrapped(input));

        // before/selected/afterの3スパン固定（未選択部分が空文字列でも省略されない）。
        assert_eq!(lines[0].spans.len(), 3);
        assert_eq!(lines[0].spans[0].content, "abc");
        assert_eq!(lines[0].spans[1].content, "de");
        assert_eq!(
            lines[0].spans[1].style,
            Style::default().bg(Color::Blue).fg(Color::White)
        );
        assert_eq!(lines[0].spans[2].content, "");

        assert_eq!(lines[1].spans.len(), 3);
        assert_eq!(lines[1].spans[0].content, "");
        assert_eq!(lines[1].spans[1].content, "f");
        assert_eq!(
            lines[1].spans[1].style,
            Style::default().bg(Color::Blue).fg(Color::White)
        );
        assert_eq!(lines[1].spans[2].content, "ghij");
    }

    #[test]
    fn build_input_lines_without_selection_produces_one_span_per_line() {
        let lines = build_input_lines("a\nb\nc", None, &unwrapped("a\nb\nc"));
        assert_eq!(
            line_texts(&lines),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        for line in &lines {
            assert_eq!(line.spans.len(), 1);
        }
    }

    #[test]
    fn input_cursor_line_and_current_line_start_track_newlines() {
        let input = "ab\ncd\nef";
        let rows = unwrapped(input);
        assert_eq!(ranges(&rows), vec![0..2, 3..5, 6..8]);
        assert_eq!(input_cursor_row(&rows, 0), 0);
        assert_eq!(input_cursor_row(&rows, 2), 0); // "ab"の直後、まだ0行目
        assert_eq!(input_cursor_row(&rows, 3), 1); // "\n"を跨いだ
        assert_eq!(input_cursor_row(&rows, 8), 2);

        // カーソル行の先頭（`set_input_cursor`が桁を数える起点）。
        let start = |cursor| rows[input_cursor_row(&rows, cursor)].range.start;
        assert_eq!(start(0), 0);
        assert_eq!(start(2), 0);
        assert_eq!(start(3), 3);
        assert_eq!(start(8), 6);
    }

    /// **長い1行は幅で折り返す**（2026-10-04、ユーザーの指示）。`\n`の無い入力でも、幅のぶんで画面の行が増える。
    #[test]
    fn a_long_line_is_wrapped_at_the_width() {
        let input = "abcdefghij"; // 10文字
        assert_eq!(ranges(&input_rows(input, 4)), vec![0..4, 4..8, 8..10]);
        assert_eq!(
            ranges(&input_rows(input, 10)),
            vec![0..10],
            "ちょうど収まる幅では折り返さない"
        );
        assert_eq!(ranges(&input_rows(input, 1_000)), vec![0..10]);
        // `\n`で切ったうえで、長い行だけを折り返す（短い行はそのまま）。
        assert_eq!(
            ranges(&input_rows("ab\ncdefg\nh", 3)),
            vec![0..2, 3..6, 6..8, 9..10]
        );
    }

    /// **空の行・空の入力も1行として残す**（0行にすると入力欄が消える）。
    #[test]
    fn empty_input_and_empty_lines_still_take_one_row() {
        assert_eq!(ranges(&input_rows("", 10)), vec![0..0]);
        assert_eq!(ranges(&input_rows("\n", 10)), vec![0..0, 1..1]);
        assert_eq!(ranges(&input_rows("a\n\nb", 10)), vec![0..1, 2..2, 3..4]);
        // 幅0でもパニックせず、1桁として割る。
        assert_eq!(ranges(&input_rows("ab", 0)), vec![0..1, 1..2]);
    }

    /// 全角文字は2桁として数える（画面の見た目に合わせる）。桁の途中では割らない。
    #[test]
    fn full_width_characters_count_as_two_columns() {
        assert_eq!(ranges(&input_rows("あいう", 4)), vec![0..2, 2..3]);
        assert_eq!(ranges(&input_rows("あaい", 3)), vec![0..2, 2..3]);
    }

    /// 折り返した継ぎ目にカーソルがあるときは、**次の行の先頭**にする（次に打つ文字が出る場所と同じ）。
    /// 入力の末尾では最後の行に残る。
    #[test]
    fn the_cursor_sits_at_the_start_of_the_next_row_at_a_wrap() {
        let rows = input_rows("abcdefghij", 4); // [0..4, 4..8, 8..10]
        assert_eq!(input_cursor_row(&rows, 3), 0);
        assert_eq!(input_cursor_row(&rows, 4), 1, "継ぎ目は次の行の先頭");
        assert_eq!(input_cursor_row(&rows, 8), 2);
        assert_eq!(input_cursor_row(&rows, 10), 2, "末尾は最後の行");
    }

    /// 折り返した行にも選択のハイライトが掛かる（行をまたぐ選択は、各行の内側だけを塗る）。
    #[test]
    fn a_selection_is_highlighted_across_wrapped_rows() {
        let input = "abcdefgh";
        let rows = input_rows(input, 4); // [0..4, 4..8]
        let lines = build_input_lines(input, Some((2, 6)), &rows);
        assert_eq!(
            line_texts(&lines),
            vec!["abcd".to_string(), "efgh".to_string()]
        );
        assert_eq!(lines[0].spans[1].content, "cd");
        assert_eq!(lines[1].spans[1].content, "ef");
    }

    #[test]
    fn input_scroll_start_follows_cursor_line_once_it_exceeds_visible_window() {
        assert_eq!(input_scroll_start(0, 6), 0);
        assert_eq!(input_scroll_start(5, 6), 0);
        assert_eq!(input_scroll_start(6, 6), 1);
        assert_eq!(input_scroll_start(9, 6), 4);
    }

    #[test]
    fn paragraph_line_count_accounts_for_wrapped_transcript_lines() {
        let lines = vec![Line::from("1234567890abcdefghij")];
        let wrapped = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .line_count(10);

        assert_eq!(wrapped, 2);
    }
}

#[cfg(test)]
mod scope_label_tests {
    use super::*;

    fn app_with(ws: &str, overlay: Option<&str>, conversation: &str) -> AppState {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.workspace_label = ws.to_string();
        app.note_scope(overlay.unwrap_or(""), conversation);
        app
    }

    /// 通常（`/sessions`直後など）はオーバーレイと会話が同じセッション。併記しない。
    #[test]
    fn the_overlay_is_shown_once_when_it_matches_the_conversation() {
        let app = app_with("harness", Some("session-a"), "session-a");
        assert_eq!(scope_label(&app), " | ws=harness | overlay=session-a");
    }

    /// `/clear`後は会話だけが新しくなる。**この食い違いは正当だが黙ってはいけない**
    /// ——「いま見ている変更は、いまの会話が作ったものではない」が画面から分かる必要がある。
    #[test]
    fn a_mismatch_after_clear_is_spelled_out() {
        let app = app_with("harness", Some("session-a"), "session-b");
        assert_eq!(
            scope_label(&app),
            " | ws=harness | overlay=session-a (会話=session-b)"
        );
    }

    /// `--live`はオーバーレイを持たないので`overlay=`自体を出さない（無いものの名前を出すと
    /// 「あるのに空」と読めてしまう）。
    #[test]
    fn live_mode_shows_no_overlay_field_at_all() {
        let app = app_with("harness", None, "session-a");
        assert_eq!(scope_label(&app), " | ws=harness");
    }

    /// ステータスバー本体に実際に載ること（`scope_label`だけ直して繋ぎ忘れる形を防ぐ）。
    #[test]
    fn the_status_bar_actually_renders_the_scope() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let app = app_with("harness", Some("session-a"), "session-b");
        let mut term = Terminal::new(TestBackend::new(200, 3)).unwrap();
        term.draw(|f| {
            let area = f.area();
            render_status(f, area, &app);
        })
        .unwrap();
        // 全角文字は2セルを占め、片方が空になるので素朴な連結では「会 話」と割れる。
        // ここで確かめたいのは「`scope_label`がステータスバーに実際に載っているか」なので、
        // ASCII部分だけを見る（文言そのものは`scope_label`の各テストが固定している）。
        let screen: String = term
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(screen.contains("ws=harness"), "{screen}");
        assert!(screen.contains("overlay=session-a"), "{screen}");
        assert!(screen.contains("=session-b"), "{screen}");
    }
}

/// 重ねて描く枠と折り返して描く本文の枠線（ポリシーエディタと同じ欠けがこの画面にもあった）。
///
/// - [BUG-198](../../../../docs/bugs/BUG-198.md)の形: 後ろの画面の全角文字が重ねた枠の左隣から始まると、
///   左の枠線のセルが全角文字の後半として端末へ送られない。
/// - [BUG-200](../../../../docs/bugs/BUG-200.md)の形: ratatuiの単語折り返しは行末の全角文字で1桁はみ出し、
///   右の枠線を覆う。
///
/// どちらも画面のセルは`TestBackend`が**受け取った差分**から読む（端末と同じ形で欠ける）。
#[cfg(test)]
mod border_tests {
    use super::*;
    use crate::app::PermissionView;
    use harness_core::{PermissionSubject, ProgramSubject, RiskClass};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// ratatuiの単語折り返しが`width`桁の場所で1桁はみ出す1行（`harness_term`の試験の同名の関数と同じ作り方）。
    fn spilling_line(width: u16) -> String {
        let width = usize::from(width);
        let head = if width % 2 == 1 { "a" } else { "ab" };
        let wide = (width - head.len()) / 2;
        format!("{head} {}", "あ".repeat(wide))
    }

    fn approval(args: &[String]) -> PermissionView {
        PermissionView::new(
            "perm-0".to_string(),
            "run_program".to_string(),
            RiskClass::Exec,
            PermissionSubject::Program(ProgramSubject::plain("git", args.to_vec())),
            "{}".to_string(),
            None,
            "C:/ws".to_string(),
        )
    }

    /// 画面全体を1フレーム描き、セルの格子（行ごとに1セル1記号）を返す。
    fn screen(app: &AppState, width: u16, height: u16) -> Vec<Vec<String>> {
        let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        term.draw(|f| {
            render(f, app);
        })
        .expect("draw");
        let buffer = term.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect()
            })
            .collect()
    }

    /// 見出しの最初の文字が`first`の枠の矩形（左右の桁と上下の行）。左上の角の直後に見出しが来る。
    fn drawn_box(grid: &[Vec<String>], first: &str) -> (usize, usize, usize, usize) {
        for (top, row) in grid.iter().enumerate() {
            if let Some(left) =
                (0..row.len().saturating_sub(1)).find(|&x| row[x] == "┌" && row[x + 1] == first)
            {
                let right = (left + 1..row.len())
                    .find(|&x| row[x] == "┐")
                    .expect("右上の角が無い");
                let bottom = (top + 1..grid.len())
                    .find(|&y| grid[y][right] == "┘")
                    .expect("右下の角が無い");
                return (left, right, top, bottom);
            }
        }
        panic!("見出しが「{first}…」の枠が無い");
    }

    /// 枠の右の枠線のうち、角を除いた行で欠けているもの。
    ///
    /// 枠線は`│`のほか、承認ダイアログの本文と選択肢の仕切りの右端（`┤`）でもよい。全角文字に覆われた桁は、
    /// そのどちらでもない（全角文字の後半の空白になる）。
    fn broken_right_border(
        grid: &[Vec<String>],
        right: usize,
        top: usize,
        bottom: usize,
    ) -> Vec<String> {
        (top + 1..bottom)
            .filter(|&y| grid[y][right] != "│" && grid[y][right] != "┤")
            .map(|y| format!("{y}行目: 「{}」 / {}", grid[y][right], grid[y].concat()))
            .collect()
    }

    /// 後ろのtranscriptに、`symbol`だけの行を1桁ずつずらして並べる。
    fn app_with_transcript(symbol: &str) -> AppState {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for i in 0..40 {
            let pad = if i % 2 == 0 { "" } else { " " };
            app.transcript.push(TranscriptItem::Assistant(format!(
                "{pad}{}",
                symbol.repeat(30)
            )));
        }
        app
    }

    /// [BUG-198の形] **後ろのtranscriptに全角文字が並んでいても、承認ダイアログの左の枠線はどの行でも欠けない。**
    /// 枠の位置は、半角だけを並べた画面で描いたときのセルから読む（全角の画面では、読むのに使う角が欠け得る）。
    #[test]
    fn the_approval_modal_keeps_its_left_border_over_a_wide_transcript() {
        let mut failures = Vec::new();
        for width in [120u16, 119, 100] {
            let mut narrow = app_with_transcript("x");
            narrow.pending_permission = Some(approval(&["status".to_string()]));
            let reference = screen(&narrow, width, 30);
            let (left, _, top, bottom) = drawn_box(&reference, "承");
            let mut wide = app_with_transcript("あ");
            wide.pending_permission = Some(approval(&["status".to_string()]));
            let grid = screen(&wide, width, 30);
            for (y, row) in grid.iter().enumerate().take(bottom + 1).skip(top) {
                // 期待する左の枠線は、半角だけの画面で同じ桁に描かれたもの（角・縦線・本文と選択肢の仕切りの`├`）。
                let want = reference[y][left].as_str();
                assert!(
                    ["┌", "│", "├", "└"].contains(&want),
                    "{width}桁 {y}行目: 半角の画面で左の枠線が読めない: 「{want}」"
                );
                if row[left] != want {
                    failures.push(format!(
                        "{width}桁 {y}行目: 「{}」 / {}",
                        row[left],
                        row.concat()
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "承認ダイアログの左の枠線が欠けた:\n{}",
            failures.join("\n")
        );
    }

    /// [BUG-200の形] **transcriptの行末の全角文字が、右の枠線を覆わない。**
    #[test]
    fn the_transcript_keeps_its_right_border_when_a_line_ends_with_a_wide_character() {
        for width in [120u16, 119] {
            let mut app = AppState::new("mock".into(), "mock-model".into());
            app.transcript
                .push(TranscriptItem::Assistant(spilling_line(width - 2)));
            let grid = screen(&app, width, 20);
            let (_, right, top, bottom) = drawn_box(&grid, "t");
            let broken = broken_right_border(&grid, right, top, bottom);
            assert!(
                broken.is_empty(),
                "{width}桁: transcriptの右の枠線が欠けた:\n{}",
                broken.join("\n")
            );
        }
    }

    /// [BUG-200の形] **承認ダイアログの本文の行末の全角文字が、右の枠線を覆わない。**
    /// 引数の行（`  [0] <引数>`）が、枠の中の最後の1桁から始まる全角文字で終わるようにする。
    #[test]
    fn the_approval_modal_keeps_its_right_border_when_an_argument_ends_with_a_wide_character() {
        for width in [120u16, 119] {
            let mut probe = AppState::new("mock".into(), "mock-model".into());
            probe.pending_permission = Some(approval(&["status".to_string()]));
            let (left, right, _, _) = drawn_box(&screen(&probe, width, 30), "承");
            let inner = right - left - 1;
            // 「  [0] 」の6桁の後ろに置く語。最後の全角文字が、枠の中の最後の1桁から始まる。
            let filler = if (inner - 6) % 2 == 0 { "x" } else { "" };
            let wide = (inner - 5 - filler.len()) / 2;
            let arg = format!("{filler}{}", "あ".repeat(wide));
            assert_eq!(
                6 + filler.len() + 2 * wide,
                inner + 1,
                "台本の前提が崩れた（はみ出す形の行になっていない）"
            );
            let mut app = AppState::new("mock".into(), "mock-model".into());
            app.pending_permission = Some(approval(&[arg]));
            let grid = screen(&app, width, 30);
            let (_, right, top, bottom) = drawn_box(&grid, "承");
            let broken = broken_right_border(&grid, right, top, bottom);
            assert!(
                broken.is_empty(),
                "{width}桁: 承認ダイアログの右の枠線が欠けた:\n{}",
                broken.join("\n")
            );
        }
    }

    /// **重ねる枠の消し方と、折り返して描く本文は、どれも`harness_term`を通る**（ポリシーエディタと共有）。
    /// `Clear`・`Wrap`・`line_count`を直接使う箇所が1つでもあると、そこだけ欠けが戻るか、数えた行数と
    /// 描いた行数が食い違う。各ファイルの、末尾の試験モジュールより前だけを数える。
    #[test]
    fn every_overlay_and_wrapped_text_goes_through_harness_term() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths = vec![root];
        let mut offenders = Vec::new();
        while let Some(path) = paths.pop() {
            if path.is_dir() {
                paths.extend(
                    std::fs::read_dir(&path)
                        .expect("read_dir")
                        .map(|entry| entry.expect("entry").path()),
                );
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read");
            let lines: Vec<&str> = source.lines().collect();
            // `#[cfg(test)]`の直後が`mod 名前 {`なら、そこから先は試験モジュール。
            let end = (0..lines.len())
                .find(|&i| {
                    lines[i].trim() == "#[cfg(test)]"
                        && lines
                            .get(i + 1)
                            .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
                })
                .unwrap_or(lines.len());
            let body = lines[..end].join("\n");
            for needle in ["Wrap {", "line_count(", "render_widget(Clear"] {
                let count = body.matches(needle).count();
                if count > 0 {
                    offenders.push(format!("{}: {needle} ×{count}", path.display()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "harness_term を通さずに重ねる・折り返す箇所がある:\n{}",
            offenders.join("\n")
        );
    }
}
