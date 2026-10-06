//! 宣言画面（`F3`）の遷移のタブの描画。状態と操作は[`crate::tui::declared_transitions`]
//! （2026-10-05、`plans/position-domains/P4.md`のP4.2）。
//!
//! **チェックの記号は[`crate::tui::checkbox_tree::Mark`]から借りる**——`[x]`＝いま宣言されていて残る、
//! `[ ]`＝取り消しを予約した（ファイル・通信のタブと同じ意味）。木の行の組み立て（`checkbox_tree::row_line`）は
//! 借りない。ここはドメインの見出しとその辺の2段だけで、開閉が無い（開閉の記号を描くと、押しても何も起きない記号になる）。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, ListItem, ListState};
use ratatui::Frame;

use harness_policy::transition::LongestChain;

use crate::tui::checkbox_tree::Mark;
use crate::tui::declared_transitions::{edge_text, DeclaredTransitionsState, ListedRow};
use crate::tui::pointer::{register_rows, Hot, ListId, Targets};
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::App;
use crate::tui::transition_screen::{file_name, truncate};
use crate::tui::wrap;

/// 説明欄の高さの下限（枠の2行を含む）。中身が収まる端末では、この高さのまま割り付けが変わらない。
const NOTES_FLOOR: u16 = 8;

/// 説明欄に並べる、選んだドメインの届く範囲の権限の上限（それより多ければ件数だけ言う）。
const RIGHTS_SHOWN: usize = 5;

/// 一覧の行と`[x]`は押せる場所として、説明欄はホイールで送る枠として、描いた矩形で登録する（`tui::pointer`）。
pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let notes = notes_text(app);
    // 説明欄は中身を折り返した行数ぶん（上限は本文の半分。`declared_screen`と同じ。BUG-192）。
    let height = wrap::box_height(notes.as_str(), area.width, NOTES_FLOOR, area.height / 2);
    let [list, notes_area] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(height)]).areas(area);
    let mut feedback = crate::tui::DrawFeedback::default();
    feedback.declared_transitions_list_offset =
        Some(draw_list(frame, list, app, &mut feedback.targets));
    feedback
        .targets
        .wheel(notes_area, Wheel::Panel(Panel::DeclaredTransitionNotes));
    feedback.panels.set(
        Panel::DeclaredTransitionNotes,
        harness_term::scrollable::draw(
            frame,
            notes_area,
            notes,
            Block::default().borders(Borders::ALL).title(" この画面 "),
            app.panels.top(Panel::DeclaredTransitionNotes),
            wrap::panel_look(Style::default()),
            harness_term::select::Selectable::new(
                &mut feedback.targets,
                Wheel::Panel(Panel::DeclaredTransitionNotes),
                &app.selection,
            ),
        ),
    );
    feedback
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
fn draw_list(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) -> usize {
    let state = &app.declared_transitions;
    let title = format!(
        " 遷移の宣言: ドメイン {}個・辺 {}本（取り消し予約 {}本）／policy.json ",
        state.domains.len(),
        state.edge_count(),
        state.remove.len()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);
    if state.domains.is_empty() {
        // **「空」と「読めなかった」を混ぜない。** 読めなかった理由は説明欄（`notes`）に出ている（`B-10`）。
        harness_term::wrap::Wrapped::new(
            "遷移の宣言はありません（policy.json にドメインが無い。読めなかったときは下の「この画面」に理由）。\n\
             承認待ち（F2）の遷移タブで承認すると、ここにドメインごとに並びます。",
        )
        .block(block)
        .render(frame, area);
        return state.list_offset;
    }

    let mut hot = Vec::new();
    let items: Vec<ListItem> = state
        .rows()
        .into_iter()
        .map(|row| {
            let (line, mark_span) = match row {
                ListedRow::Domain(domain) => (header_line(state, domain), 0),
                ListedRow::Edge { domain, edge } => (edge_line(state, domain, edge), 1),
            };
            hot.push(Hot::of(&line.spans, Some(mark_span), None));
            ListItem::new(line)
        })
        .collect();
    let mut list_state = ListState::default().with_offset(state.list_offset);
    list_state.select(Some(state.row));
    let drawn = harness_term::list::draw(
        frame,
        area,
        items,
        Some(block),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut list_state,
    );
    register_rows(targets, ListId::DeclaredTransitions, &drawn, &hot);
    list_state.offset()
}

/// ドメインの見出しの行: `[x] [<ドメイン>]  届く範囲: … ／ 起動で届く: … ／ 最長の連鎖: …`（記号は先頭のspan）。
fn header_line(state: &DeclaredTransitionsState, domain: usize) -> Line<'static> {
    let entry = &state.domains[domain];
    let kept = entry
        .edges
        .iter()
        .filter(|row| !state.is_reserved(&entry.name, &row.edge))
        .count();
    let shape = &entry.shape;
    let reachable = if shape.reachable.is_empty() {
        "なし".to_string()
    } else {
        shape.reachable.join(", ")
    };
    let mut spans = vec![
        Mark::of(entry.edges.len(), kept).span(),
        Span::styled(
            format!(" [{}]", entry.name),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    // [P5.5] Strict の印（決定66の追記）。入る辺の入力を固定するモードなので、名前の直後に出す。
    if entry.strict {
        spans.push(Span::styled(
            " ［Strict］",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        format!(
            "  届く範囲: ファイル {}件・通信 {}件 ／ 起動で届く: {reachable} ／ 最長の連鎖: {}",
            shape.rights.fs.len(),
            shape.rights.net.len(),
            chain_text(&shape.longest_chain)
        ),
        Style::default().fg(Color::Gray),
    ));
    match state.strict.get(&entry.name) {
        Some(true) => spans.push(Span::styled("  ← Strict を付けます", Style::default().fg(Color::Red))),
        Some(false) => spans.push(Span::styled("  ← Strict を外します", Style::default().fg(Color::Green))),
        None => {}
    }
    Line::from(spans)
}

/// 辺の行: `  [x] <exe のファイル名> <引数> → <遷移先>  <起こせる／起こせません（理由）>`（記号は2つ目のspan）。
fn edge_line(state: &DeclaredTransitionsState, domain: usize, edge: usize) -> Line<'static> {
    let entry = &state.domains[domain];
    let row = &entry.edges[edge];
    let listed = &row.row;
    let reserved = state.is_reserved(&entry.name, &row.edge);
    let exe = if listed.exe_is_pattern {
        format!("{}（パターン）", listed.exe)
    } else {
        file_name(&listed.exe).to_string()
    };
    let argv = if listed.argv_is_pattern {
        format!("{}（パターン）", truncate(&listed.argv, 28))
    } else {
        truncate(&listed.argv, 34)
    };
    let mut spans = vec![
        Span::raw("  "),
        if reserved { Mark::None } else { Mark::All }.span(),
        Span::raw(format!(" {exe:<24}")),
        Span::styled(format!(" {argv:<28}"), Style::default().fg(Color::Gray)),
        Span::raw(format!(" → {}", listed.to_domain)),
    ];
    spans.push(match state.not_runnable_reason(listed) {
        None => Span::styled("  起こせる", Style::default().fg(Color::DarkGray)),
        Some(reason) => Span::styled(
            format!("  起こせません（{reason}）"),
            Style::default().fg(Color::Yellow),
        ),
    });
    if row.self_loop {
        spans.push(Span::styled(
            "  ⟲ 自己ループ辺（手書き。エディタは書きません——決定65）",
            Style::default().fg(Color::Magenta),
        ));
    }
    if reserved {
        spans.push(Span::styled(
            "  ← 取り消します",
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

/// 最長の連鎖の綴り。閉路は**元のドメインへ戻るところまで**書く（`[A, B]`を「A → B → A」と読ませる）。
fn chain_text(chain: &LongestChain) -> String {
    match chain {
        LongestChain::Finite { steps: 0, .. } => "0段".to_string(),
        LongestChain::Finite { steps, path } => format!("{steps}段（{}）", path.join(" → ")),
        LongestChain::Unbounded { cycle } => {
            let around: Vec<&str> = cycle
                .iter()
                .chain(cycle.first())
                .map(String::as_str)
                .collect();
            format!("上限なし（閉路: {}）", around.join(" → "))
        }
    }
}

/// 説明欄（「この画面」）の中身。高さを決めるのにも描くのにも同じ文を使う。
///
/// 並びは(1)操作の案内か予約件数 →(2)読めなかった・検査に落ちた事実 →(3)選んでいる行の詳細 →(4)ACLが変わらない
/// ことの注記（ファイル・通信のタブの説明欄と同じ並び）。
fn notes_text(app: &App) -> String {
    let state = &app.declared_transitions;
    let mut text = String::new();
    if state.remove.is_empty() && state.strict.is_empty() {
        text.push_str(
            "Spaceで取り消しを予約（ドメインの見出しの行なら、そのドメインの辺をまとめて）／sでドメインの Strict の\
             付け外し／aで確定／rで読み直し／F3でファイル・通信のタブへ。辺を足すのは承認待ち（F2）の遷移タブです。\n",
        );
    } else {
        text.push_str(&format!(
            "{}本の取り消しと Strict の付け外し {}件を予約中（aを押すまで何も書きません）。\n",
            state.remove.len(),
            state.strict.len()
        ));
    }
    for note in &state.notes {
        text.push_str(note);
        text.push('\n');
    }
    match state.rows().get(state.row) {
        Some(ListedRow::Domain(domain)) => {
            let entry = &state.domains[*domain];
            let rights = &entry.shape.rights;
            text.push_str(&format!(
                "選択中: ドメイン {}（辺 {}本）。そこへ遷移すると届く範囲の権限:\n",
                entry.name,
                entry.edges.len()
            ));
            // [P5.5] 2つのモードのどちらか（決定66の追記）。正本の使い分けはヘルプ（F4）と決定66の追記。
            text.push_str(if entry.strict {
                "  Strict: 入る辺は入力を固定した辺だけ（決めた操作だけが走り、呼び出し元は中身を選べません）。s で外せます\n"
            } else {
                "  普通のモード: 入る辺の子を、呼び出し元はこのドメインの権限の範囲で自由に動かせます。s で Strict にできます\n"
            });
            if rights.is_empty() {
                text.push_str("  なし（共通の土台だけ）\n");
            }
            let all: Vec<String> = rights
                .fs
                .iter()
                .map(|(value, access)| format!("  {access} {value}"))
                .chain(rights.net.iter().map(|host| format!("  通信 {host}")))
                .collect();
            for line in all.iter().take(RIGHTS_SHOWN) {
                text.push_str(line);
                text.push('\n');
            }
            if all.len() > RIGHTS_SHOWN {
                text.push_str(&format!("  …ほか {}件\n", all.len() - RIGHTS_SHOWN));
            }
        }
        Some(ListedRow::Edge { domain, edge }) => {
            let entry = &state.domains[*domain];
            text.push_str(&format!(
                "選択中: 遷移元 {} の辺 {}\n",
                entry.name,
                edge_text(&entry.edges[*edge].edge)
            ));
        }
        None => {}
    }
    // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
    text.push_str(crate::transition_approve::ACE_NOTICE);
    text
}
