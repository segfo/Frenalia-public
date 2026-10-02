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
use ratatui::widgets::{Block, Borders, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::transition_candidates::{Candidate, Declared, Source};
use crate::tui::checkbox_tree::Mark;
use crate::tui::pointer::{register_rows, Click, Field, Hot, ListId, Targets};
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::App;
use crate::tui::transition::{Counts, PendingFilter, PendingTab};
use crate::tui::wrap;

/// 下の枠（「この画面」）の高さの下限（枠線2＋中身6）。中身はACEの注記2行・予約の案内1行・
/// 選択中のフルパス2行で、折り返さずに収まる端末ではこの高さのまま割り付けが変わらない。
const NOTES_FLOOR: u16 = 8;

/// 遷移先の欄・一覧の行・`[x]`は押せる場所として、下の枠はホイールで送る枠として、描いた矩形で登録する
/// （`tui::pointer`）。
pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let notes = notes_text(app);
    let chunks = split(area, &notes);
    let mut feedback = crate::tui::DrawFeedback::default();
    draw_destination(frame, chunks[0], app);
    feedback
        .targets
        .click(chunks[0], Click::Field(Field::Destination));
    feedback.candidate_list_offset = Some(draw_list(frame, chunks[1], app, &mut feedback.targets));
    // 入り切らない分はホイールで送る（`tui::scroll`）。
    feedback
        .targets
        .wheel(chunks[2], Wheel::Panel(Panel::TransitionNotes));
    feedback.panels.set(
        Panel::TransitionNotes,
        harness_term::scrollable::draw(
            frame,
            chunks[2],
            notes,
            Block::default().borders(Borders::ALL).title(" この画面 "),
            app.panels.top(Panel::TransitionNotes),
            wrap::panel_look(Style::default()),
        ),
    );
    feedback
}

/// 遷移先の欄・一覧・下の枠の割り付け。押せる場所・送れる枠は、ここで出した矩形へ描いたものをそのまま登録する
/// （BUG-194。`tui::pointer`）。
///
/// 下の枠は**中身を折り返した行数ぶん**の高さを取る（BUG-192。`tui::wrap`）。以前は8行固定で、
/// 狭い端末で注記が折り返すと下から黙って切れていた。上限は本文の半分（一覧を潰さない）で、
/// それでも入らない分はホイールで送る——最初に見える順序は[`notes_text`]のdocが持つ。
/// 上の3行は遷移先ドメインの欄（2026-10-01。承認待ちのFS/ネットタブのドメイン欄と同じ高さ）。
fn split(area: Rect, notes: &str) -> std::rc::Rc<[Rect]> {
    let height = wrap::box_height(notes, area.width, NOTES_FLOOR, area.height / 2);
    Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(height),
    ])
    .split(area)
}

/// 遷移先ドメインの欄。**名前の横に、`harness.exe`が用意する見込みを出す**——書いた後で
/// 「起こせない」と知るのでは遅い（用意されない遷移先は、書けても断られ続ける）。
fn draw_destination(frame: &mut Frame, area: Rect, app: &App) {
    let destination = &app.pending.destination;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if destination.focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(" 遷移先ドメイン（Tab で編集。確定すると、許す遷移はすべてここへ向く） ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let warn = app.destination_needs_attention();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                destination.input.text().to_string(),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                format!("   {}", app.destination_label()),
                Style::default().fg(if warn { Color::Yellow } else { Color::DarkGray }),
            ),
        ])),
        inner,
    );
    if destination.focused {
        frame.set_cursor_position(ratatui::layout::Position::new(
            inner.x + destination.input.cursor_col(),
            inner.y,
        ));
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
/// 描いた行と`[x]`は押せる場所として登録する。
fn draw_list(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) -> usize {
    let tab = app.pending.tab.0;
    let counts = app.pending.counts(tab);
    // **件数を必ず見出しに出す**——「無い」と「隠している」が区別できないと、
    // 黙って捨てているのと同じである（`B-09`）。**3段とも出す**——いま見ていない段の件数が
    // 無いと、却下したものが消えたのか隠れているのか分からない。
    let title = format!(
        " {}: 保留中 {}件 / 却下済み {}件 / 全{}件（表示: {}） ",
        tab.label(),
        counts.pending,
        counts.dismissed,
        counts.total,
        app.pending.filter.label()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);

    let visible = app.pending.visible();
    if visible.is_empty() {
        harness_term::wrap::Wrapped::new(empty_text(tab, app.pending.filter, counts))
            .block(block)
            .render(frame, area);
        return app.candidate_list_offset;
    }

    // **同じ実行ファイル名が2つ以上あるときだけ、置き場を添える**（下記[`exe_label`]）。
    let ambiguous = ambiguous_file_names(&visible);
    let lines: Vec<Line> = visible
        .iter()
        .map(|candidate| row_line(app, candidate, &ambiguous))
        .collect();
    // チェックの記号は行の先頭のspan（[`row_line`]）。
    let hot: Vec<Hot> = lines
        .iter()
        .map(|line| Hot::of(&line.spans, Some(0), None))
        .collect();
    let items: Vec<ListItem> = lines.into_iter().map(ListItem::new).collect();

    let mut state = ListState::default().with_offset(app.candidate_list_offset);
    state.select(Some(app.pending.row()));
    let rows = harness_term::list::draw(
        frame,
        area,
        items,
        Some(block),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut state,
    );
    register_rows(targets, ListId::Transitions, &rows, &hot);
    state.offset()
}

/// 1行を組み立てる。**チェックの記号は先頭のspanに置く**（押せる場所を求めるのに使う。[`draw_list`]）。
///
/// **`[x]`は「確定したらこのプログラムを起こせる」**という意味に統一してある
/// ——いま宣言済みで取り消し予約もしていない行も、これから承認する行も`[x]`である。
/// 記号が状態ではなく**結果**を表すので、候補画面・宣言画面と同じ読み方ができる。
fn row_line<'a>(
    app: &App,
    candidate: &'a Candidate,
    ambiguous: &std::collections::HashSet<String>,
) -> Line<'a> {
    let (mark, tail) = mark_and_tail(app, candidate);
    let mut spans = vec![
        mark.span(),
        Span::raw(format!(" {:<24}", exe_label(candidate, ambiguous))),
        Span::styled(
            format!(" {:<28}", argv_label(app, candidate)),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            format!(" {:>4}回", candidate.count),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    spans.push(Span::styled(
        format!("  {}", source_label(candidate)),
        Style::default().fg(Color::DarkGray),
    ));
    spans.extend(tail);
    // **綴りそのものが起こせないなら、宣言の有無とは別に言う**
    // ——「宣言済み」だけを出すと、起こせるものとして読まれる。
    if candidate.startable.note().is_some() {
        spans.push(Span::styled(
            "  ［この綴りは起こせない］".to_string(),
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

/// チェックの記号と、行末に足す注記。
///
/// **却下した行は`[ ]`**——却下は「起こせない」ままにしておく決定なので、記号の意味
/// （`[x]`＝確定すると起こせる）と食い違わない。却下の状態は行末の言葉で言う（決定60）。
fn mark_and_tail<'a>(app: &App, candidate: &Candidate) -> (Mark, Vec<Span<'a>>) {
    let (mark, mut tail) = declared_mark_and_tail(app, candidate);
    tail.extend(dismissal_tail(app, candidate));
    (mark, tail)
}

/// 却下印と却下の予約の注記。
fn dismissal_tail<'a>(app: &App, candidate: &Candidate) -> Vec<Span<'a>> {
    let pending = &app.pending;
    if pending.is_dismiss_reserved(candidate) {
        return vec![Span::styled(
            "  ← 却下します".to_string(),
            Style::default().fg(Color::Magenta),
        )];
    }
    if !pending.is_dismissed(candidate) {
        return Vec::new();
    }
    if pending.is_undismiss_reserved(candidate) || pending.is_reserved(candidate) {
        // 承認を予約した却下済みの行も、確定で印が外れる（`reserved_dismissals`）。
        return vec![Span::styled(
            "  ← 却下を取り消します".to_string(),
            Style::default().fg(Color::Yellow),
        )];
    }
    // **宣言が後から入った行の古い印は、宣言が優先していることを言う**（決定62の(5)）。
    // 隠すと、宣言を取り消した日に理由の分からないまま「却下済み」へ戻って見える。
    let text = if candidate.is_approvable() {
        "  却下済み"
    } else {
        "  却下印あり（宣言が優先）"
    };
    vec![Span::styled(
        text.to_string(),
        Style::default().fg(Color::DarkGray),
    )]
}

/// 宣言の状態から決まる記号と注記。
fn declared_mark_and_tail<'a>(app: &App, candidate: &Candidate) -> (Mark, Vec<Span<'a>>) {
    match &candidate.declared {
        Declared::No | Declared::UnknownSourceDomain => {
            if app.pending.is_reserved(candidate) {
                // **どこへ移るかを行に出す**——遷移先は欄で選ぶので、行だけ見ても分かるようにする。
                (
                    Mark::All,
                    vec![Span::styled(
                        format!("  ← 許します → {}", app.pending.destination.name()),
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
                // **一覧に出ているのに撃つと断られる、を黙らせない。** 理由は見込みの表が持つ
                // （2026-10-01から「別ドメインだから」ではなく「遷移先が用意されないから」）。
                let reason = app
                    .pending
                    .outlooks
                    .get(to_domain.as_str())
                    .map(|o| o.short_label())
                    .unwrap_or_else(|| "用意されない見込み".to_string());
                tail.push(Span::styled(
                    format!("  ［起こせない: {reason}］"),
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

/// 一覧の中で**2つ以上の行が同じ実行ファイル名を持つ**もの（小文字化して比較）。
///
/// これを取るのは、**名前だけでは別のプログラムを見分けられない**ことがあるためである。
/// `git`は名前で呼ぶと中継役の実体を踏むので、実測では別の場所にある`git.exe`が2本並んだ。
fn ambiguous_file_names(visible: &[&Candidate]) -> std::collections::HashSet<String> {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for candidate in visible {
        *seen
            .entry(candidate.exe_file_name().to_ascii_lowercase())
            .or_insert(0) += 1;
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, _)| name)
        .collect()
}

/// 実行ファイルの欄。
///
/// **同じ名前が2つ以上あるときだけ、置いてあるフォルダ名を添える**（`git.exe (cmd)`）。
/// 常に添えると、区別が要らない行まで長くなって幅を食う。**フルパスは下の枠**（選択中の行）
/// と確定のダイアログに出るので、ここは「どれとどれが別物か」が分かれば足りる。
fn exe_label(candidate: &Candidate, ambiguous: &std::collections::HashSet<String>) -> String {
    let name = candidate.exe_file_name();
    if !ambiguous.contains(&name.to_ascii_lowercase()) {
        return name.to_string();
    }
    match parent_dir_name(&candidate.exe) {
        Some(dir) => format!("{name} ({dir})"),
        None => name.to_string(),
    }
}

/// 実行ファイルが置いてあるフォルダの名前（末尾の1要素だけ）。
fn parent_dir_name(exe: &str) -> Option<&str> {
    let cut = exe.rfind(['\\', '/'])?;
    let parent = &exe[..cut];
    let start = parent.rfind(['\\', '/']).map_or(0, |i| i + 1);
    let name = &parent[start..];
    (!name.is_empty()).then_some(name)
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
fn empty_text(tab: PendingTab, filter: PendingFilter, counts: Counts) -> String {
    if filter == PendingFilter::Dismissed {
        return format!(
            "却下した候補はありません（全{}件・保留中 {}件）。\n\
             保留中の行で x を押して a で確定すると、ここへ移ります。\n\
             却下は表示だけの印で、policy.json も ACL も変わりません。",
            counts.total, counts.pending
        );
    }
    if counts.total > 0 && filter == PendingFilter::Pending {
        return format!(
            "保留中の候補はありません（全{}件のうち 却下済み {}件・宣言済みなど {}件）。\n\
             f を押すと「却下済み」→「全部」の順に切り替わり、隠れているものが出ます。",
            counts.total,
            counts.dismissed,
            counts.total - counts.dismissed
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

/// この枠の中身。
///
/// # 並びは「最初に見えていなければならない順」である
///
/// 枠の高さは中身を折り返した行数ぶん取る（[`split`]）が、一覧に半分を残す上限があり、
/// **それを超えた分はホイールで送らないと見えない**（枠の下辺に「N〜M/T行」が出る。`tui::wrap::draw_scrollable`）。
/// だから(1)ACEの注記（何が起きないかの宣言。常に出す）→(2)予約件数→(3)読めなかった事実→
/// (4)選択中のフルパス、の順に置く。**4が送った先にあるのは許容できるが、1が隠れると嘘になる。**
fn notes_text(app: &App) -> String {
    // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
    let mut text = format!("{}\n", crate::transition_approve::ACE_NOTICE);

    let pending = &app.pending;
    if pending.destination.focused {
        text.push_str("遷移先ドメインを入力中です（Enter か Tab で一覧へ戻る）。\n");
    } else if pending.reserved_count() == 0 {
        text.push_str(
            "Spaceで選ぶ／Tabで遷移先／xで却下／uで引数の広さ／fで表示の切替／rで読み直し／aで確定。\n",
        );
    } else {
        // **強調の記号を文字として書かない。** 端末では`**`はそのまま星印として出る
        // （2026-09-19に実機で確認）。強調が要るなら色か記号で表す。
        text.push_str(&format!(
            "許可 {}件・取り消し {}件・却下 {}件・却下の取り消し {}件を予約中\
             （aを押すまで何も書きません）。\n",
            pending.approve.len(),
            pending.remove.len(),
            pending.dismiss.len(),
            pending.undismiss.len()
        ));
    }

    // **読めなかった・あふれた事実を黙らせない**（`B-10`）。
    for note in &app.pending.notes {
        text.push_str(note);
        text.push('\n');
    }

    // **選択中の行のフルパス。** 一覧は実行ファイル名しか出さないので、
    // **同じ名前の別プログラムが並ぶと見分けられない**（`git`は名前で呼ぶと中継役の実体を
    // 踏むので、実測で2本並んだ）。確定のダイアログには全パスが出るので誤って書くことは
    // 無いが、**選んでいる最中に分からない**のは困る。
    if let Some(candidate) = app.pending.visible().get(app.pending.row()) {
        // **起こせない綴りは、パスより先に理由を言う**（入り切らないときは下が送った先になるため）。
        if let Some(note) = candidate.startable.note() {
            text.push_str(note);
            text.push('\n');
        }
        text.push_str(&format!("選択中: {}\n", candidate.exe));
        text.push_str(&format!("  観測された引数: {}", candidate.argv));
    }
    text
}

#[cfg(test)]
mod transition_screen_tests {
    use super::*;
    use crate::transition_candidates::{Candidate, Declared, Source};

    fn candidate(exe: &str) -> Candidate {
        Candidate {
            exe: exe.to_string(),
            argv: "x".to_string(),
            count: 1,
            last_ts: 1,
            argv_truncation: false,
            source: Source::Observed { parent_exe: None },
            declared: Declared::No,
            startable: crate::transition_candidates::Startable::AsFarAsWeKnow,
        }
    }

    /// 同じ名前が2つあるときだけ、置き場を添える。
    ///
    /// **常に添えると幅を食う**ので、要るときだけにしてある。対で測るのは、
    /// 「常に添える」実装でも「一度も添えない」実装でも片方だけなら緑になるためである。
    #[test]
    fn the_folder_is_shown_only_when_two_rows_share_a_file_name() {
        let a = candidate("C:/Program Files/Git/cmd/git.exe");
        let b = candidate("C:/Program Files/Git/mingw64/bin/git.exe");
        let alone = candidate("C:/Windows/System32/findstr.exe");
        let visible = vec![&a, &b, &alone];

        let ambiguous = ambiguous_file_names(&visible);
        assert_eq!(exe_label(&a, &ambiguous), "git.exe (cmd)");
        assert_eq!(exe_label(&b, &ambiguous), "git.exe (bin)");
        assert_eq!(
            exe_label(&alone, &ambiguous),
            "findstr.exe",
            "重なっていない行にまで置き場を添えている"
        );
    }

    /// 大文字小文字だけが違う綴りも**同じ名前**として扱う（Windowsは区別しない）。
    #[test]
    fn the_comparison_ignores_case() {
        let a = candidate("C:/a/GIT.EXE");
        let b = candidate("C:/b/git.exe");
        let visible = vec![&a, &b];

        assert_eq!(ambiguous_file_names(&visible).len(), 1);
        assert_eq!(
            exe_label(&a, &ambiguous_file_names(&visible)),
            "GIT.EXE (a)"
        );
    }

    /// 置き場が取れない綴りでは、名前だけに戻す（**行を壊さない**）。
    #[test]
    fn a_path_without_a_parent_folder_falls_back_to_the_bare_name() {
        let bare = candidate("git.exe");
        let other = candidate("C:/a/git.exe");
        let visible = vec![&bare, &other];
        let ambiguous = ambiguous_file_names(&visible);

        assert_eq!(exe_label(&bare, &ambiguous), "git.exe");
        assert_eq!(parent_dir_name("git.exe"), None);
        assert_eq!(parent_dir_name("C:/a/git.exe"), Some("a"));
        assert_eq!(parent_dir_name(r"C:\a\b\git.exe"), Some("b"));
    }
}
