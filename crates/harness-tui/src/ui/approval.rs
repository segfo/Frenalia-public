//! 承認モーダルの描画（D-106）。状態とキー処理は[`crate::app::approval`]が持つ。
//!
//! **枠に入りきらない中身は切り捨てずにスクロールさせる。** 承認は「見たものを許す」操作なので、
//! 見えていないものが黙って切れている画面で決めさせてはいけない。折り返すので
//! 実際に何行になるかは端末の幅が決まるまで分からず、上限は**描いた後に**呼び出し側が
//! 状態へ反映する（transcript と同じ形。[BUG-076](../../../docs/bugs/BUG-076.md)）。
//!
//! # 本文の枠と、選択肢の枠
//!
//! ```text
//! ┌承認が必要です──────────────────────┐
//! │run_program（Exec）                  █   ← 本文。入り切らないときだけ右の枠線にスクロールバー
//! │…                                    │
//! ├──────── 1〜12/40行  ↑↓ PgUp/PgDn・ホイールで送る ┤   ← 本文の枠の下辺（位置の案内）＝仕切り
//! │ [y] 一度だけ許可     [a] …     [n] 拒否  │   ← 選択肢。本文と一緒には送らない。押せるものはボタン
//! │ [v] 中身    PageUp/PageDown スクロール   │   ← 押せない案内（1つのキーに決まらない）は文字のまま
//! └─────────────────────────────────────┘
//! ```
//!
//! 選択肢のボタンは入力欄の「送信」「中断」と同じ見た目（`super::button`。2026-10-03、括弧書きの選択肢が押せる場所に
//! 見えないとユーザーが実機で指摘した）。並べ方は変えていない——入り切らない項目は次の行の頭へ送り、項目の途中では割らない。
//!
//! 本文はポリシーエディタの確認ダイアログ・ヘルプと同じ送れる枠の部品（`harness_term::scrollable`）で描く——
//! 送る上限は「最後の行が枠の一番下」、入り切らないときだけスクロールバーと「N〜M/T行」を出す。
//! 選択肢を本文の枠の外（仕切りの下）に置くのは、位置の案内を本文の枠の下辺に出し、選択肢を押し出させないため。
//!
//! 選択肢の各項目と、確認の段の「毎回変わってよい引数」の候補の行は、**描いたその場所で**押せる場所として登録する
//! （`crate::app::pointer`）。枠の全体はホイールで本文を送る場所になる。本文の文章はマウスで選んで写せる
//! （候補の行は押せる場所なので、そこからは選び始めない。`crate::app::select`）。

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;

use crate::app::{ApprovalStage, Click, LineStyle, PermissionView, Targets, WaitClock, Wheel};
use harness_core::RiskLevel;
use harness_sandbox::textdiff::DiffKind;
use harness_term::button::Press;
use harness_term::select::{Selectable, Selection};

/// 承認モーダルを描き、**この描画で判明したスクロールの上限**を返す。押せる場所と送れる枠を`targets`へ登録する
/// （呼び出し側は、後ろの画面を先に覆っておく。`crate::ui::render`）。選択肢のボタンのうち、いま押されているもの
/// （`press`。`AppState::press`）は押されている形で描く。`clock`は要約の待ちの行（回る記号と経過秒）に使う。
pub fn render_permission_modal(
    f: &mut Frame,
    area: Rect,
    pending: &PermissionView,
    press: &Press<Click>,
    targets: &mut Targets,
    selection: &Selection<Wheel>,
    clock: WaitClock,
) -> u16 {
    let rect = super::centered_rect(84, 70, area);
    // 後ろのtranscriptの全角文字が枠の左隣から始まっても左の枠線が欠けないよう、共有の部品で消す
    // （ポリシーエディタと同じ。`harness_term::overlay`）。
    harness_term::overlay::clear(f, rect);
    // 枠の中は、どこで回しても本文を送る（ボタンの上でも。クリックとホイールは別々に引く）。
    targets.cover(rect);
    targets.wheel(rect, Wheel::Approval);

    let body = pending.body(clock);
    let candidates: Vec<Option<usize>> = body.iter().map(|line| line.candidate).collect();
    let mut lines: Vec<Line> = body.into_iter().map(styled).collect();
    // `edit_file`の差分だけは材料（書込先パス）に写らないので、ここで足す。
    if pending.stage == ApprovalStage::Choose {
        if let Some(diff) = &pending.edit_diff {
            lines.push(Line::from(""));
            for d in diff {
                let (prefix, color) = match d.kind {
                    DiffKind::Context => (" ", Color::Gray),
                    DiffKind::Removed => ("-", Color::Red),
                    DiffKind::Added => ("+", Color::Green),
                };
                lines.push(Line::from(Span::styled(
                    format!("{prefix} {}", harness_core::escape_for_display(&d.text)),
                    Style::default().fg(color),
                )));
            }
        }
    }

    let style = Style::default().fg(Color::White).bg(Color::Black);
    // **選択肢は本文と一緒にスクロールさせない。** 枠の下辺の見出しに入れると、選択肢そのものが端で切れる
    // （日本語は1文字2桁なので、すぐ幅を超える）。
    //
    // **並べてから高さを決める。** 幅の狭い端末では、入り切らない選択肢を次の行へ送る（項目の途中では割らない。
    // 「[d] このセッション中は拒否」が2行に割れると、どこまでが1つの押せる場所か分からない）。
    //
    // **押せる選択肢はボタンとして描く**（入力欄の「送信」「中断」と同じ部品。`super::HintLook::Buttons`）。
    let groups = pending.key_hints();
    let hint_width = rect.width.saturating_sub(2);
    let hint_rows: u16 = groups
        .iter()
        .map(|group| super::hint_rows(group, super::HintLook::Buttons(press), hint_width))
        .sum();
    // 本文の枠は少なくとも枠線2行＋本文1行を残す。選択肢の枠は選択肢の行＋下の枠線。
    let hint_rows = hint_rows.min(rect.height.saturating_sub(4));
    let body_area = Rect {
        height: rect.height.saturating_sub(hint_rows + 1),
        ..rect
    };
    let hint_area = Rect {
        y: body_area.bottom(),
        height: rect.height - body_area.height,
        ..rect
    };

    // 外の判定モデルが注意以上と見たコマンドは、見出しと枠線の色を変える（赤＝危険、黄＝注意）。
    // 判定が無い・低いときは今までと同じ見た目（`PermissionView::title`）。
    let (title_text, elevated) = pending.title();
    let (title_style, border_style) = match elevated {
        Some(RiskLevel::Danger) => (
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Red),
        ),
        Some(RiskLevel::Caution) => (
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Yellow),
        ),
        _ => (Style::default(), Style::default()),
    };
    // 本文の枠の下辺は、選択肢の枠との仕切りになる（左右の角を`├`/`┤`にして、1つの枠に見せる）。
    let body_block = Block::default()
        .borders(Borders::ALL)
        .border_set(symbols::border::Set {
            bottom_left: symbols::line::VERTICAL_RIGHT,
            bottom_right: symbols::line::VERTICAL_LEFT,
            ..symbols::border::PLAIN
        })
        .title(Span::styled(title_text, title_style))
        .border_style(border_style)
        .style(style);
    let drawn = harness_term::scrollable::draw_with_buttons(
        f,
        body_area,
        lines,
        body_block,
        pending.scroll,
        harness_term::scrollable::Look {
            how: pending.scroll_keys(),
            notice: Style::default().fg(Color::DarkGray),
            bar: Style::default().fg(Color::White),
        },
        &[],
        Selectable::new(targets, Wheel::Approval, selection),
    );
    for (line, candidate) in drawn.lines.iter().zip(&candidates) {
        if let Some(row) = candidate {
            targets.click(*line, Click::Candidate(*row));
        }
    }

    let hint_block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
        .border_style(border_style)
        .style(style);
    let mut hint_inner = hint_block.inner(hint_area);
    f.render_widget(hint_block, hint_area);
    for group in &groups {
        let rows = super::hint_rows(group, super::HintLook::Buttons(press), hint_inner.width)
            .min(hint_inner.height);
        super::draw_hints(
            f,
            Rect {
                height: rows,
                ..hint_inner
            },
            group,
            super::HintLook::Buttons(press),
            targets,
        );
        hint_inner.y += rows;
        hint_inner.height -= rows;
    }
    drawn.max_top
}

fn styled(line: crate::app::ApprovalLine) -> Line<'static> {
    let style = match line.style {
        LineStyle::Normal => Style::default(),
        LineStyle::Heading => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        LineStyle::Dim => Style::default().fg(Color::DarkGray),
        LineStyle::Warn => Style::default().fg(Color::Yellow),
        LineStyle::Danger => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        LineStyle::Caution => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        LineStyle::Added => Style::default().fg(Color::Green),
        LineStyle::Removed => Style::default().fg(Color::Red),
        LineStyle::Selected => Style::default().add_modifier(Modifier::REVERSED),
    };
    Line::from(Span::styled(line.text, style))
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use crate::app::PermissionView;
    use harness_core::{PermissionSubject, ProgramSubject, RiskClass};

    fn view(args: &[&str]) -> PermissionView {
        PermissionView::new(
            "perm-0".to_string(),
            "run_program".to_string(),
            RiskClass::Exec,
            PermissionSubject::Program(ProgramSubject::plain(
                "git",
                args.iter().map(|a| a.to_string()).collect(),
            )),
            "{}".to_string(),
            None,
            "C:/ws".to_string(),
        )
    }

    /// 待ちの行を描く時刻（要約を待っていない画面では使われない）。
    fn clock() -> crate::app::WaitClock {
        crate::app::WaitClock {
            spinner_frame: 0,
            now: std::time::Instant::now(),
        }
    }

    fn rendered(pending: &PermissionView) -> String {
        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| {
            super::render_permission_modal(
                f,
                f.area(),
                pending,
                &Default::default(),
                &mut Default::default(),
                &Default::default(),
                clock(),
            );
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 呼び出しと選択肢が実際に画面へ出る。
    #[test]
    fn the_modal_draws_the_call_and_the_choices() {
        let screen = rendered(&view(&["status"]));
        // 日本語は1文字2桁で描かれる（画面バッファでは文字の間に空セルが入る）ので、
        // 突き合わせるのは ASCII の部分にする。
        assert!(screen.contains("program: git"), "{screen}");
        assert!(screen.contains("[0] status"), "{screen}");
        assert!(screen.contains("[y]") && screen.contains("[a]"), "{screen}");
        assert!(screen.contains("[n]") && screen.contains("[d]"), "{screen}");
        assert!(screen.contains("PageUp/PageDown"), "{screen}");
    }

    /// 枠に入りきらない中身はスクロールできる（**上限は描いてみるまで分からない**ので、
    /// 描画が返す値で状態を切り詰める。BUG-076 と同じ形）。
    #[test]
    fn a_long_call_scrolls_instead_of_being_cut_off() {
        let many: Vec<String> = (0..60).map(|i| format!("arg{i}")).collect();
        let mut pending = view(&many.iter().map(|s| s.as_str()).collect::<Vec<_>>());

        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        let mut ceiling = 0;
        term.draw(|f| {
            ceiling = super::render_permission_modal(
                f,
                f.area(),
                &pending,
                &Default::default(),
                &mut Default::default(),
                &Default::default(),
                clock(),
            )
        })
        .unwrap();
        assert!(
            ceiling > 0,
            "content taller than the box must be scrollable"
        );

        // 一番下まで送っても落ちず、末尾の引数が見える。
        pending.clamp_scroll(ceiling);
        pending.scroll = ceiling;
        let screen = rendered(&pending);
        assert!(screen.contains("[59] arg59"), "{screen}");
    }

    /// **狭い端末でも選択肢が切れない。** 日本語は1文字2桁なので、折り返さずに1行へ並べると
    /// 「このセッション中は拒否」の尻が黙って消える（実際に一度そうなった）。
    #[test]
    fn the_choices_are_not_cut_off_on_a_narrow_terminal() {
        let mut term = Terminal::new(TestBackend::new(70, 24)).unwrap();
        let pending = view(&["status"]);
        term.draw(|f| {
            super::render_permission_modal(
                f,
                f.area(),
                &pending,
                &Default::default(),
                &mut Default::default(),
                &Default::default(),
                clock(),
            );
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        // 全角は「文字＋空セル」で置かれるので、空白を落としてから突き合わせる。
        let collapsed: String = (0..buffer.area.height)
            .flat_map(|y| (0..buffer.area.width).map(move |x| (x, y)))
            .map(|(x, y)| buffer[(x, y)].symbol().to_string())
            .collect::<String>()
            .replace(' ', "");
        assert!(collapsed.contains("このセッション中は拒否"), "{collapsed}");
        assert!(collapsed.contains("一度だけ許可"), "{collapsed}");
    }

    /// 双方向制御を含む引数は、生のまま端末へ流さない（D-106）。
    #[test]
    fn bidi_control_characters_never_reach_the_terminal() {
        let screen = rendered(&view(&["gp\u{202E}yp.exe"]));
        assert!(!screen.contains('\u{202E}'), "{screen}");
        assert!(screen.contains(r"gp\u{202E}yp.exe"), "{screen}");
    }
}
