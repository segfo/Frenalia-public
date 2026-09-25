//! `AppState`から毎フレーム全ウィジェットを再描画する（即時モード、§リッチTUI）。
//!
//! レビューパネル（1画面を占める自己完結した面）の描画だけは[`review`]へ分けている
//! （`docs/CODE-STRUCTURE-RULES.md`規則3）。

mod approval;
mod review;

pub(crate) use approval::render_permission_modal;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{AppState, ToolCardStatus, TranscriptItem, SPINNER_FRAMES};

/// 入力欄が自動で伸びる最大行数。これを超えると内部スクロールする（カーソル行が
/// 常に見えるよう毎フレーム再計算する。transcriptの`scroll_offset`のような永続的な
/// スクロール状態は入力欄には持たせない）。
const MAX_INPUT_VISIBLE_LINES: u16 = 6;

/// 1フレーム描画し、**この描画で判明した`scroll_offset`の上限**を返す
/// （[BUG-076](../../../docs/bugs/BUG-076.md)）。総行数は折り畳み状態と端末幅に依存するため
/// 描画時にしか決まらない。呼び出し側は戻り値で`AppState::clamp_scroll`を呼び、状態そのものを
/// 切り詰める——ここで表示だけ止めても、状態は青天井に伸び続けてしまう。
pub fn render(f: &mut Frame, app: &AppState) -> Ceilings {
    // 複数行入力（既定でEnterが改行を挿入するようになったため）にあわせ、入力欄の高さを
    // 行数に応じて`MAX_INPUT_VISIBLE_LINES`まで自動で伸ばす（それ以上は内部スクロール）。
    let input_line_count = app.input.split('\n').count() as u16;
    let input_height = input_line_count.clamp(1, MAX_INPUT_VISIBLE_LINES) + 2; // +2=枠線
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(input_height),
        ])
        .split(f.area());

    let max_scroll = render_transcript(f, root[0], app);
    render_status(f, root[1], app);
    render_input(f, root[2], app);

    let mut modal_scroll = 0;
    if let Some(pending) = &app.pending_permission {
        modal_scroll = approval::render_permission_modal(f, f.area(), pending);
    } else if let Some(panel) = &app.review_panel {
        review::render_review_panel(f, f.area(), panel);
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
        set_input_cursor(f, root[2], app);
    }

    Ceilings {
        transcript: max_scroll,
        modal: modal_scroll,
    }
}

/// 1フレーム描いて初めて分かるスクロールの上限。**面ごとに別々に持つ**——1つの値にまとめると、
/// モーダルを開いた瞬間に transcript の上限がモーダルのもので上書きされる。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ceilings {
    pub transcript: u16,
    pub modal: u16,
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
    f.render_widget(Clear, rect);

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
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, rect);
}

/// `input_cursor`（先頭からの文字数）が何行目（0始まり、`\n`の数）にあるか。
fn input_cursor_line(input: &str, cursor: usize) -> usize {
    input.chars().take(cursor).filter(|&c| c == '\n').count()
}

/// `input_cursor`が属する行の開始文字インデックス（直前の`\n`の直後、無ければ0）。
fn input_current_line_start(input: &str, cursor: usize) -> usize {
    input
        .chars()
        .take(cursor)
        .enumerate()
        .filter(|&(_, c)| c == '\n')
        .last()
        .map(|(i, _)| i + 1)
        .unwrap_or(0)
}

/// カーソル行が常に表示範囲(`visible`行分)に収まるような表示開始行を計算する。
fn input_scroll_start(cursor_line: usize, visible: usize) -> usize {
    if cursor_line >= visible {
        cursor_line + 1 - visible
    } else {
        0
    }
}

/// `input`を`\n`で分割し、各行を選択ハイライト（あれば）付きで`Line`に変換する。
/// `Frame`非依存の純粋関数（`diff.rs`と同様、単体テストしやすくするため描画から分離する）。
/// `selection`はバッファ全体を通した文字インデックスの`(start, end)`（半開区間）。
fn build_input_lines(input: &str, selection: Option<(usize, usize)>) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line_start = 0usize;
    for line_str in input.split('\n') {
        let line_len = line_str.chars().count();
        let line_end = line_start + line_len;
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
                    // 「幽霊」誤認を招くため。
                    Span::styled(selected, Style::default().bg(Color::Blue).fg(Color::White)),
                    Span::raw(after),
                ])
            }
            None => Line::from(line_str.to_string()),
        };
        lines.push(line);
        line_start = line_end + 1; // `\n`の分1つ進める
    }
    lines
}

fn set_input_cursor(f: &mut Frame, area: Rect, app: &AppState) {
    let visible = area.height.saturating_sub(2).max(1) as usize;
    let cursor_line = input_cursor_line(&app.input, app.input_cursor);
    let scroll_start = input_scroll_start(cursor_line, visible);
    let line_start = input_current_line_start(&app.input, app.input_cursor);
    // 枠線ぶん+1、カーソル行の行頭からカーソルまでの表示幅ぶん右へ（全角文字は2セル分として
    // IME側の位置計算と一致させる。§リッチTUI「入力ボックス」）。
    let prefix: String = app
        .input
        .chars()
        .skip(line_start)
        .take(app.input_cursor - line_start)
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
        let glyph = SPINNER_FRAMES[app.spinner_frame % SPINNER_FRAMES.len()];
        let tokens = app.current_turn_downstream_chars / 4;
        let elapsed = started.elapsed().as_secs_f32();
        lines.push(Line::from(Span::styled(
            format!("{glyph} Thinking… (~{tokens} tokens, {elapsed:.1}s)"),
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
        let glyph = SPINNER_FRAMES[app.spinner_frame % SPINNER_FRAMES.len()];
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
fn render_transcript(f: &mut Frame, area: Rect, app: &AppState) -> u16 {
    // 末尾追従の描画と上限の算出は`harness_term::scrollback`が持つ
    // （ポリシーエディタの記録画面と共有。同局のdoc参照）。
    // 戻り値の上限を`AppState::clamp_scroll`へ渡すのは呼び出し側の責務（BUG-076）。
    let lines = transcript_lines(app, app.collapsed);
    let title = harness_term::scrollback::title_with_scroll(
        "transcript ",
        app.scroll,
        "下へホイールで戻る",
    );
    harness_term::scrollback::render(
        f,
        area,
        lines,
        Block::default().borders(Borders::ALL).title(title),
        app.scroll,
    )
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

fn render_input(f: &mut Frame, area: Rect, app: &AppState) {
    let title = if app.enter_submits {
        "input (Enter=送信, Esc=中断, PageUp/PageDown=スクロール, Ctrl-C=終了)"
    } else if app.host_is_vscode {
        "input (Enter=改行, Alt+Enter=送信, Esc=中断, PageUp/PageDown=スクロール, Ctrl-C=終了)"
    } else {
        "input (Enter=改行, Shift+Enter=送信, Esc=中断, PageUp/PageDown=スクロール, Ctrl-C=終了)"
    };
    let block = Block::default().borders(Borders::ALL).title(title);

    let visible = area.height.saturating_sub(2).max(1) as usize;
    let cursor_line = input_cursor_line(&app.input, app.input_cursor);
    let scroll_start = input_scroll_start(cursor_line, visible);
    let visible_lines: Vec<Line> = build_input_lines(&app.input, app.selection_range())
        .into_iter()
        .skip(scroll_start)
        .take(visible)
        .collect();

    let paragraph = Paragraph::new(visible_lines).block(block);
    f.render_widget(paragraph, area);
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

    #[test]
    fn build_input_lines_splits_on_newlines_and_highlights_selection_within_a_line() {
        let input = "hello\nworld";
        // グローバル文字インデックス(1, 4) = "hello"内の"ell"。
        let lines = build_input_lines(input, Some((1, 4)));
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
        let lines = build_input_lines(input, Some((3, 7)));

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
        let lines = build_input_lines("a\nb\nc", None);
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
        assert_eq!(input_cursor_line(input, 0), 0);
        assert_eq!(input_cursor_line(input, 2), 0); // "ab"の直後、まだ0行目
        assert_eq!(input_cursor_line(input, 3), 1); // "\n"を跨いだ
        assert_eq!(input_cursor_line(input, 8), 2);

        assert_eq!(input_current_line_start(input, 0), 0);
        assert_eq!(input_current_line_start(input, 2), 0);
        assert_eq!(input_current_line_start(input, 3), 3);
        assert_eq!(input_current_line_start(input, 8), 6);
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
