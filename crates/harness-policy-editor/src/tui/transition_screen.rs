//! [段階⑦] 承認待ち画面（`F2`）の**遷移2タブ**の描画。状態遷移は[`crate::tui::transition`]。
//!
//! **チェックの記号は[`crate::tui::checkbox_tree`]から借りる**——`[x]`が「許される」を
//! 意味することは3つのタブで同じで、記号だけ別にすると読み手が取り違える。
//! 借りないのは行の組み立て（[`crate::tui::checkbox_tree::row_line`]）で、あちらは木の行
//! （インデントと開閉記号）を前提にしている。**ここは平坦な一覧である**
//! （理由は`crate::tui::transition`のモジュールdoc）。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::transition_candidates::{Candidate, Declared, Source};
use crate::tui::checkbox_tree::Mark;
use crate::tui::state::App;
use crate::tui::transition::{PendingFilter, PendingTab};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(7)]).split(area);
    let offset = draw_list(frame, chunks[0], app);
    draw_notes(frame, chunks[1], app);
    crate::tui::DrawFeedback {
        candidate_list_offset: Some(offset),
        ..Default::default()
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
fn draw_list(frame: &mut Frame, area: Rect, app: &App) -> usize {
    let tab = app.pending.tab.0;
    let (pending, total) = app.pending.counts(tab);
    // **件数を必ず見出しに出す**——「無い」と「隠している」が区別できないと、
    // 黙って捨てているのと同じである（`B-09`）。
    let title = format!(
        " {}: 保留中 {pending}件 / 全{total}件（表示: {}） ",
        tab.label(),
        app.pending.filter.label()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);

    let visible = app.pending.visible();
    if visible.is_empty() {
        frame.render_widget(
            Paragraph::new(empty_text(tab, app.pending.filter, total))
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
        return app.candidate_list_offset;
    }

    let items: Vec<ListItem> = visible
        .iter()
        .map(|candidate| ListItem::new(vec![row_line(app, candidate)]))
        .collect();

    let mut state = ListState::default().with_offset(app.candidate_list_offset);
    state.select(Some(app.pending.row()));
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
    state.offset()
}

/// 1行を組み立てる。
///
/// **`[x]`は「確定したらこのプログラムを起こせる」**という意味に統一してある
/// ——いま宣言済みで取り消し予約もしていない行も、これから承認する行も`[x]`である。
/// 記号が状態ではなく**結果**を表すので、候補画面・宣言画面と同じ読み方ができる。
fn row_line<'a>(app: &App, candidate: &'a Candidate) -> Line<'a> {
    let (mark, tail) = mark_and_tail(app, candidate);
    let mut spans = vec![
        mark.span(),
        Span::raw(format!(" {:<18}", candidate.exe_file_name())),
        Span::styled(
            format!(" {:<36}", argv_label(app, candidate)),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            format!(" {:>5}回", candidate.count),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    spans.push(Span::styled(
        format!("  {}", source_label(candidate)),
        Style::default().fg(Color::DarkGray),
    ));
    spans.extend(tail);
    Line::from(spans)
}

/// チェックの記号と、行末に足す注記。
fn mark_and_tail<'a>(app: &App, candidate: &Candidate) -> (Mark, Vec<Span<'a>>) {
    match &candidate.declared {
        Declared::No | Declared::UnknownSourceDomain => {
            if app.pending.is_reserved(candidate) {
                (
                    Mark::All,
                    vec![Span::styled(
                        "  ← 許します".to_string(),
                        Style::default().fg(Color::Green),
                    )],
                )
            } else {
                (Mark::None, Vec::new())
            }
        }
        Declared::ByThisEdge {
            to_domain,
            runnable_now,
            ..
        } => {
            if app.pending.is_unreserved(candidate) {
                return (
                    Mark::None,
                    vec![Span::styled(
                        "  ← 取り消します".to_string(),
                        Style::default().fg(Color::Red),
                    )],
                );
            }
            let mut tail = vec![Span::styled(
                format!("  宣言済み → {to_domain}"),
                Style::default().fg(Color::Green),
            )];
            if !*runnable_now {
                // **一覧に出ているのに撃つと断られる、を黙らせない**（§10.1.2の暫定）。
                tail.push(Span::styled(
                    "  ［いまは起こせない］".to_string(),
                    Style::default().fg(Color::Yellow),
                ));
            }
            (Mark::All, tail)
        }
        // **外せないものは`[-]`**（操作の対象が無い）。記号と操作を一致させる。
        Declared::ByAPattern { exe, .. } => (
            Mark::NotApplicable,
            vec![Span::styled(
                format!("  パターンの宣言が覆っています（{exe}）"),
                Style::default().fg(Color::DarkGray),
            )],
        ),
        Declared::CwdMismatch { declared } => (
            Mark::NotApplicable,
            vec![Span::styled(
                format!("  作業ディレクトリが宣言（{declared}）と違います"),
                Style::default().fg(Color::Yellow),
            )],
        ),
        Declared::Ambiguous { matched } => (
            Mark::NotApplicable,
            vec![Span::styled(
                format!("  パターンの宣言が{matched}本一致していて決められません"),
                Style::default().fg(Color::Yellow),
            )],
        ),
    }
}

/// 引数の欄。**既定は「任意の引数」で、それは観測より広い**ので、絞ったときだけ実際の値を出す。
fn argv_label(app: &App, candidate: &Candidate) -> String {
    match &candidate.declared {
        Declared::ByThisEdge { argv, .. } => argv.display().to_string(),
        _ if app.pending.is_narrowed(candidate) => truncate(&candidate.argv, 34),
        _ => harness_policy::transition_listing::ANY_ARGV.to_string(),
    }
}

fn source_label(candidate: &Candidate) -> String {
    match &candidate.source {
        Source::Observed {
            parent_exe: Some(p),
        } => {
            format!("← {}", file_name(p))
        }
        Source::Observed { parent_exe: None } => "← （記録の入口）".to_string(),
        Source::Denied {
            by_kernel: true, ..
        } => "カーネルが拒否".to_string(),
        Source::Denied { from_domain, .. } => match from_domain {
            Some(domain) => format!("拒否（{domain}から）"),
            None => "拒否".to_string(),
        },
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

/// 画面の幅に収める。**切ったことが分かる形**にする（黙って切ると別の値に見える）。
fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let kept: String = value.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// 行が1つも無いときの文面。**「本当に無い」と「フィルタで隠れている」を区別する**（`B-09`）。
fn empty_text(tab: PendingTab, filter: PendingFilter, total: usize) -> String {
    if total > 0 && filter == PendingFilter::Pending {
        return format!(
            "保留中の候補はありません（全{total}件はすべて宣言済みです）。\n\
             f を押すと「全部」になり、宣言済みも出ます。"
        );
    }
    match tab {
        PendingTab::TransitionsObserved => "観測した生成がありません。\n\
             F1の記録画面で**パス1**（隔離なし）で1回走らせると、そのとき起きたプログラムが\n\
             ここへ候補として並びます。"
            .to_string(),
        // **この画面のフラグを案内しない。** 遷移の強制を積むのは`harness`側の旗で、
        // ここに綴りを書くと、読んだ人がポリシーエディタへ打って弾かれる（BUG-122と同型）。
        PendingTab::TransitionsDenied => "断られた生成がありません。\n\
             harness側で遷移の強制を有効にしたセッションで、宣言していないプログラムを\n\
             起こそうとすると、ここへ並びます。"
            .to_string(),
        // このタブはこの画面で描かない（`tui::mod`が振り分ける）。
        PendingTab::FsNet => String::new(),
    }
}

fn draw_notes(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" この画面 ");
    let mut text = String::new();

    let reserved = app.pending.approve.len();
    let removing = app.pending.remove.len();
    if reserved == 0 && removing == 0 {
        text.push_str("Spaceで選ぶ／uで引数の広さを切替／fで表示の切替／rで読み直し／aで確定。\n");
    } else {
        text.push_str(&format!(
            "許可 {reserved}件・取り消し {removing}件を予約中。**aを押すまで何も書きません。**\n"
        ));
    }
    // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
    text.push_str(crate::transition_approve::ACE_NOTICE);

    // **読めなかった・あふれた事実を黙らせない**（`B-10`）。
    for note in &app.pending.notes {
        text.push('\n');
        text.push_str(note);
    }

    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        area,
    );
}
