//! 承認モーダルの描画（D-106）。状態とキー処理は[`crate::app::approval`]が持つ。
//!
//! **枠に入りきらない中身は切り捨てずにスクロールさせる。** 承認は「見たものを許す」操作なので、
//! 見えていないものが黙って切れている画面で決めさせてはいけない。折り返す（[`Wrap`]）ので
//! 実際に何行になるかは端末の幅が決まるまで分からず、上限は**描いた後に**呼び出し側が
//! 状態へ反映する（transcript と同じ形。[BUG-076](../../../docs/bugs/BUG-076.md)）。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;

use crate::app::{ApprovalStage, LineStyle, PermissionView};
use harness_sandbox::textdiff::DiffKind;

/// 承認モーダルを描き、**この描画で判明したスクロールの上限**を返す。
pub fn render_permission_modal(f: &mut Frame, area: Rect, pending: &PermissionView) -> u16 {
    let rect = super::centered_rect(84, 70, area);
    // 後ろのtranscriptの全角文字が枠の左隣から始まっても左の枠線が欠けないよう、共有の部品で消す
    // （ポリシーエディタと同じ。`harness_term::overlay`）。
    harness_term::overlay::clear(f, rect);

    let mut lines: Vec<Line> = pending.body().into_iter().map(styled).collect();
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

    let block = Block::default()
        .borders(Borders::ALL)
        .title("承認が必要です")
        .style(Style::default().fg(Color::White).bg(Color::Black));
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    // **選択肢は枠の中に固定で置き、本文と一緒にスクロールさせない。** 枠の下辺の見出しに
    // 入れると、選択肢そのものが端で切れる（日本語は1文字2桁なので、すぐ幅を超える）。
    let hints: Vec<Line> = pending
        .key_hints()
        .into_iter()
        .map(|h| Line::from(Span::styled(h, Style::default().fg(Color::DarkGray))))
        .collect();
    // **折り返してから高さを決める。** 日本語は1文字2桁なので、幅の狭い端末では
    // 「[d] このセッション中は拒否」のような選択肢が黙って端で切れる。
    //
    // 数える幅と描く幅は`harness_term::wrap`が揃える（行末の全角文字が右の枠線を覆わないよう、
    // どちらも右端の1桁を空ける。BUG-200）。
    let hint_height = harness_term::wrap::rows(hints.clone(), inner.width)
        .min(inner.height.saturating_sub(1) as usize) as u16;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(hint_height)])
        .split(inner);

    let total =
        u16::try_from(harness_term::wrap::rows(lines.clone(), parts[0].width)).unwrap_or(u16::MAX);
    let max_scroll = total.saturating_sub(parts[0].height);
    harness_term::wrap::Wrapped::new(lines)
        .scroll(pending.scroll.min(max_scroll))
        .render(f, parts[0]);
    harness_term::wrap::Wrapped::new(hints).render(f, parts[1]);
    max_scroll
}

fn styled(line: crate::app::ApprovalLine) -> Line<'static> {
    let style = match line.style {
        LineStyle::Normal => Style::default(),
        LineStyle::Heading => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        LineStyle::Dim => Style::default().fg(Color::DarkGray),
        LineStyle::Warn => Style::default().fg(Color::Yellow),
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

    fn rendered(pending: &PermissionView) -> String {
        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| {
            super::render_permission_modal(f, f.area(), pending);
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
        term.draw(|f| ceiling = super::render_permission_modal(f, f.area(), &pending))
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
            super::render_permission_modal(f, f.area(), &pending);
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
