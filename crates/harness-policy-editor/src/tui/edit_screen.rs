//! 編集画面の描画（記録セッションの一覧・候補一覧・注記）。
//!
//! 候補一覧は対話的なリストなので自前で描くが、**注記（観測件数・除外件数・収集器からの報告・
//! 拒否の読み方）はCLIと同じ`render_notes`をそのまま出す**。同じ事実の説明を2箇所に
//! 持つと片方だけが直る（規則5・B-05）。

use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::tui::checkbox_tree::{FOLD_SPAN, MARK_SPAN};
use crate::tui::pointer::{register_rows, Click, Field, Hot, ListId, Targets};
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::{App, EditField};
use crate::tui::wrap;

/// 一覧の行・`[x]`・`▾`/`▸`・ドメイン欄は押せる場所として、注記の枠はホイールで送る枠として、描いた矩形で
/// 登録する（`tui::pointer`）。
pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let (panel, title, notes) = notes_content(app);
    let areas = split(area, &notes);
    let mut feedback = crate::tui::DrawFeedback::default();
    let targets = &mut feedback.targets;
    let session_list_offset = draw_sessions(frame, areas.sessions, app, targets);
    draw_domain(frame, areas.domain, app);
    targets.click(areas.domain, Click::Field(Field::Domain));
    let candidate_list_offset = draw_proposals(frame, areas.proposals, app, targets);
    // 入り切らない分はホイールで送る（`tui::scroll`）。
    targets.wheel(areas.notes, Wheel::Panel(panel));
    feedback.session_list_offset = Some(session_list_offset);
    feedback.candidate_list_offset = Some(candidate_list_offset);
    feedback.panels.set(
        panel,
        harness_term::scrollable::draw(
            frame,
            areas.notes,
            notes,
            Block::default().borders(Borders::ALL).title(title),
            app.panels.top(panel),
            wrap::panel_look(Style::default()),
            harness_term::select::Selectable::new(targets, Wheel::Panel(panel), &app.selection),
        ),
    );
    feedback
}

/// 承認待ち（FS/ネット）の枠の位置。
struct Areas {
    sessions: Rect,
    domain: Rect,
    proposals: Rect,
    notes: Rect,
}

/// 画面の割り付け。押せる場所・送れる枠は、ここで出した矩形へ描いたものをそのまま登録する（BUG-194。`tui::pointer`）。
///
/// 注記の枠は**中身を折り返した行数ぶん**の高さを取る（BUG-192。`tui::wrap`）。以前は9行固定で、
/// 入り切らない分が黙って切れていた。上限は右の列の半分（候補一覧を潰さない）で、プロセスツリーの
/// ように長いものはそこで止まり、入らない分はホイールで送る。
fn split(area: Rect, notes: &str) -> Areas {
    let columns =
        Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)]).split(area);
    let notes_height =
        wrap::box_height(notes, columns[1].width, NOTES_FLOOR, columns[1].height / 2);
    let rows = Layout::vertical([
        Constraint::Length(3),            // ドメイン名
        Constraint::Min(5),               // 候補一覧
        Constraint::Length(notes_height), // 注記 or プロセスツリー
    ])
    .split(columns[1]);
    Areas {
        sessions: columns[0],
        domain: rows[0],
        proposals: rows[1],
        notes: rows[2],
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
/// 描いた行は、押すとその記録を選ぶ場所として登録する（記録が無いときの案内の行は押せない）。
fn draw_sessions(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) -> usize {
    let items: Vec<ListItem> = if app.sessions.is_empty() {
        vec![ListItem::new(Line::styled(
            "（記録がありません。F1でコマンドを記録してください）",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.sessions
            .iter()
            .map(|entry| {
                let manifest = &entry.manifest;
                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(
                            format!("pass{} ", manifest.pass),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::styled(
                            manifest.status.label().to_string(),
                            Style::default().fg(status_color(manifest.status)),
                        ),
                    ]),
                    Line::styled(
                        format!("  {}", truncate(&manifest.command, 34)),
                        Style::default().fg(Color::Gray),
                    ),
                ])
            })
            .collect()
    };
    // **offsetをフレームをまたいで保つ**（`App::session_list_offset`のdoc）。
    let mut state = ListState::default().with_offset(app.session_list_offset);
    if !app.sessions.is_empty() {
        state.select(Some(app.selected_session));
    }
    let rows = harness_term::list::draw(
        frame,
        area,
        items,
        Some(
            Block::default()
                .borders(Borders::ALL)
                .border_style(focus_style(app.edit_focus == EditField::Sessions))
                .title(" 記録セッション（新しい順） "),
        ),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut state,
    );
    if !app.sessions.is_empty() {
        register_rows(targets, ListId::Sessions, &rows, &[]);
    }
    // ratatuiが選択を見せるために動かしたoffsetを返す（呼び出し側が保存する）。
    state.offset()
}

fn status_color(status: crate::session_dir::RecordStatus) -> Color {
    use crate::session_dir::RecordStatus;
    match status {
        RecordStatus::Finished => Color::Green,
        RecordStatus::Running => Color::Yellow,
        RecordStatus::Canceled => Color::Magenta,
        RecordStatus::Failed => Color::Red,
    }
}

fn draw_domain(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.edit_focus == EditField::Domain;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(focused))
        .title(if app.view.as_ref().is_some_and(|view| view.by_position()) {
            // P4.4: 位置ごとのドメインの記録では、候補ごとに書く先のドメインが決まっている。
            " ドメイン（この記録は位置ごとにドメインが決まっています（欄は使いません）） "
        } else {
            " ドメイン（このコマンドに何を許すか、の単位） "
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(Line::styled(
            app.domain.text().to_string(),
            Style::default().fg(Color::White),
        )),
        inner,
    );
    if focused {
        frame.set_cursor_position(Position::new(inner.x + app.domain.cursor_col(), inner.y));
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
/// 描いた行・`[x]`・`▾`/`▸`は押せる場所として登録する（ロック行は押せない。カーソルが乗らないのと同じ）。
fn draw_proposals(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) -> usize {
    let visible = app.visible_proposals();
    // **隠している件数を必ず出す**（B-09）。既定のフィルタは承認できるものだけなので、
    // 出していないものがあることが分からないと「候補が少ない」と誤解される。
    let title = match app.view.as_ref() {
        Some(view) => format!(
            " 候補: {} {}件（全{}件・承認不可 {}件）／選択 {}件 ",
            app.filter.label(),
            visible.len(),
            view.proposals.len(),
            view.blocked_count(),
            // **`R`の再帰指定もここに数える**（`App::selected_count`）。チェックだけを数えると、
            // 再帰だけを指定したユーザーに「選択 0件」と見えて承認できないと誤解させる。
            app.selected_count()
        ),
        None => " 許可ルールの候補 ".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(app.edit_focus == EditField::Proposals))
        .title(title);

    // [BUG-103] workspaceの**ロック行**。候補一覧の上に固定で1行出し、カーソルは乗せない。
    //
    // workspace配下は候補にしない（パス2が起動時にツリー全体へRWXを付与済み、D-54）が、
    // **黙って消すと「なぜ自分のリポジトリが出ないのか」が分からない**。かといって選択可能に
    // すると、外せるように見えて実際には外せない（付与はpreflightが無条件に行う）。
    // そこで「見えるが操作対象ではない」形にする——`[x]`解除不可の実装は、
    // **そもそもカーソルが乗らない**こと（＝行番号の勘定に入らないこと）で担保する（B-06）。
    // ratatuiの`List`は選択位置を`app.selected_row`で持つので、ここへ行を足すと
    // 添字が1つずれる。ずらさないために、ブロックの内側を割って別ウィジェットとして描く。
    let locked = app.view.as_ref().and_then(workspace_lock_line);

    let Some(view) = app.view.as_ref() else {
        frame.render_widget(
            Paragraph::new("記録セッションを選んでください").block(block),
            area,
        );
        // 一覧を描いていないので表示位置は進まない（保存されている値をそのまま返す）。
        return app.candidate_list_offset;
    };
    if visible.is_empty() {
        let text = if view.proposals.is_empty() {
            "（候補なし）下の注記に理由が出ています".to_string()
        } else {
            // **「無い」と「隠している」を区別する**（B-09）。
            format!(
                "（このフィルタに該当する候補はありません。全{}件のうち承認不可 {}件・f で切替）",
                view.proposals.len(),
                view.blocked_count()
            )
        };
        // **候補が0件のときこそロック行を出す。** ここが空欄だと「何も許可されていない」と
        // 読めてしまうが、実際にはworkspaceツリー全体が既に覆われている。
        let mut lines = locked.unwrap_or_default();
        lines.push(Line::raw(""));
        lines.push(Line::raw(text));
        harness_term::wrap::Wrapped::new(lines)
            .block(block)
            .render(frame, area);
        return app.candidate_list_offset;
    }

    // パスの木として描く。1本道は畳んであるので、意味のある分岐だけが行になる。
    let rows = app.tree.rows(&app.expanded);
    // 行ごとの`[x]`と`▾`/`▸`の位置（押せる場所。spanの並びは`checkbox_tree::row_line`と同じ）。
    let mut hot = Vec::with_capacity(rows.len());
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let node = app.tree.node(row.node);
            let indent = "  ".repeat(row.depth);
            let has_children = app.tree.has_children(row.node);
            let opened = app.expanded.contains(&node.key);

            // 配下の選択状況（全部／一部／なし）。一部だけ選ばれている状態が見えないと、
            // 「まとめて選んだあと個別に外す」使い方ができない。
            //
            // **スペースが実際に触る集合と同じものを数える**（`bulk_selectable_proposals`）。
            // `subtree_proposals`で数えると、子を持つノード自身の候補（D-62でスペースの
            // 対象外にしたもの）が分母に入り、**全部選んでも`[x]`にならない**——表示と操作が
            // 食い違うと、ユーザーは「選べていない」と読んで押し続けることになる。
            let under = app.tree.bulk_selectable_proposals(row.node);
            let approvable: Vec<&usize> = under.iter().filter(|i| !view.too_broad[**i]).collect();
            // **宣言済みのものも「入っている」側に数える。** 数えないと、承認済みの実行ファイルが
            // 毎回`[ ]`で現れて、同じ場所へ二重にチェックを付けることになる。
            let selected = approvable
                .iter()
                .filter(|i| app.candidate_is_on(***i))
                .count();
            let mark = if approvable.is_empty() {
                "[-]"
            } else if selected == approvable.len() {
                "[x]"
            } else if selected > 0 {
                "[~]"
            } else {
                "[ ]"
            };

            let mut spans = vec![
                Span::raw(indent.clone()),
                Span::styled(
                    mark.to_string(),
                    Style::default().fg(match mark {
                        "[x]" => Color::Green,
                        "[~]" => Color::Yellow,
                        _ => Color::DarkGray,
                    }),
                ),
                Span::styled(
                    if !has_children {
                        "  ".to_string()
                    } else if opened {
                        " ▾".to_string()
                    } else {
                        " ▸".to_string()
                    },
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(format!(" {}", node.label)),
            ];
            hot.push(Hot::of(
                &spans,
                Some(MARK_SPAN),
                has_children.then_some((FOLD_SPAN, opened)),
            ));
            // [D-63] 再帰指定。**書かれる値そのもの（`/**`）を出す**——「再帰」という語より、
            // 実際にpolicy.jsonへ入る文字列を見せた方が誤解が無い。色は赤（この1行が他の全部より
            // 重い操作なので、一覧の中で埋もれてはいけない）。
            if app.recursive.contains(&node.key) {
                spans.push(Span::styled(
                    "/**".to_string(),
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(ratatui::style::Modifier::BOLD),
                ));
                spans.push(Span::styled(
                    "  ← 配下すべて＋今後の追加分".to_string(),
                    Style::default().fg(Color::Red),
                ));
            }
            if has_children {
                spans.push(Span::styled(
                    format!("  （配下 {}件", node.total),
                    Style::default().fg(Color::DarkGray),
                ));
                if node.approvable != node.total {
                    spans.push(Span::styled(
                        format!("・承認可 {}件", node.approvable),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                spans.push(Span::styled("）", Style::default().fg(Color::DarkGray)));
            }

            let mut lines = vec![Line::from(spans)];
            // このノード自身が候補なら、key・観測回数・固有の警告をぶら下げる。
            for index in &node.proposals {
                let proposal = &view.proposals[*index];
                let too_broad = view.too_broad[*index];
                let mut detail = vec![
                    Span::raw(format!("{indent}      ")),
                    Span::styled(
                        format!("{:<8}", proposal.id),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        proposal.key.dotted().to_string(),
                        Style::default().fg(if too_broad {
                            Color::DarkGray
                        } else {
                            Color::Cyan
                        }),
                    ),
                    Span::styled(
                        format!("  （観測 {}回）", proposal.observed_count()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ];
                if too_broad {
                    detail.push(Span::styled(
                        "  [広すぎる・承認不可]",
                        Style::default().fg(Color::Red),
                    ));
                }
                // **なぜこの行にチェックが入っているのかを言う。** 宣言済みだからチェックが
                // 入っているのに理由が無いと、「自分が選んだのか」「もう許可されているのか」が
                // 区別できず、外していいのかも判断できない。
                let declared =
                    app.declared_targets_for(&app.candidate_domain(*index), &proposal.value);
                if !declared.is_empty() {
                    let keys: Vec<&str> = declared.iter().map(|t| t.key.dotted()).collect();
                    let reserved = declared.iter().all(|t| app.unapproved.contains(t));
                    detail.push(Span::styled(
                        if reserved {
                            format!("  ← 宣言済み（{}）を取り消します", keys.join("・"))
                        } else {
                            format!("  ← 宣言済み: {}", keys.join("・"))
                        },
                        Style::default().fg(if reserved { Color::Red } else { Color::Green }),
                    ));
                }
                lines.push(Line::from(detail));
                // 自分自身の宣言は無いが、**親の宣言に覆われている**場合。ここに`[x]`を付けると
                // 「外せば消える」ように見えて嘘になる（消えるのは親で、兄弟の許可も一緒に消える）
                // ので、注記だけにする。
                if declared.is_empty() {
                    let domain_name = app.candidate_domain(*index);
                    if let Some(domain) =
                        app.declared_policy.as_ref().and_then(|f| f.domain(&domain_name))
                    {
                        if let Some((key, covering)) =
                            domain.covering_fs_declaration(&proposal.value)
                        {
                            lines.push(Line::styled(
                                format!(
                                    "{indent}      ⊂ {covering}（{}）に覆われています\
                                     ——外すなら F3 の宣言画面でその行を外してください",
                                    key.dotted()
                                ),
                                Style::default().fg(Color::DarkGray),
                            ));
                        }
                    }
                }
                // 行に出すのは**この候補に固有の警告**だけ（全候補共通のものは下の注記へ1度だけ）。
                for warning in view.row_warnings(proposal) {
                    lines.push(Line::styled(
                        format!("{indent}      ! {warning}"),
                        Style::default().fg(Color::Red),
                    ));
                }
            }
            ListItem::new(lines)
        })
        .collect();

    // **offsetをフレームをまたいで保つ**――毎回0へ戻すと選択行が窓の端へ
    // 貼り付き、カーソルが窓の中を動かない（`App::candidate_list_offset`のdoc）。
    let mut state = ListState::default().with_offset(app.candidate_list_offset);
    state.select(Some(app.selected_row));
    let highlight = Style::default().add_modifier(Modifier::REVERSED);

    let drawn = match locked {
        // ロック行はブロックの内側の先頭を占め、リストはその下に描く。
        //
        // **高さはロック行を折り返した行数ぶん取る**（BUG-192。`tui::wrap`）。以前は2行固定で、
        // 2行目の説明（約110桁）が枠の幅で折り返すと、後ろの「配下 N件は候補にしません」——
        // 候補に出ない理由——が黙って切れていた。リストには最低1行を残す。
        Some(lines) => {
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let lock_rows = u16::try_from(wrap::rows(lines.clone(), inner.width))
                .unwrap_or(u16::MAX)
                .min(inner.height.saturating_sub(1));
            let rows =
                Layout::vertical([Constraint::Length(lock_rows), Constraint::Min(1)]).split(inner);
            harness_term::wrap::Wrapped::new(lines).render(frame, rows[0]);
            harness_term::list::draw(frame, rows[1], items, None, highlight, &mut state)
        }
        None => harness_term::list::draw(frame, area, items, Some(block), highlight, &mut state),
    };
    register_rows(targets, ListId::Proposals, &drawn, &hot);
    state.offset()
}

/// [BUG-103] workspaceのロック行（`[x]` 解除不可）。
///
/// **除外0件でも出す。** 「候補が無い」と「既に覆われている」は別の事実で、後者を黙ると
/// ユーザーは前者だと読む（B-09）。workspace rootが分からないとき（FSの集計が無い＝
/// ネットワークだけの記録）は出さない——嘘の行を作るよりは何も言わない方がよい。
fn workspace_lock_line(view: &crate::tui::state::SessionView) -> Option<Vec<Line<'static>>> {
    let fs = view.data.fs.as_ref()?;
    let root = fs.rules().workspace_root().display().to_string();
    let hidden = fs.excluded_session_workspace;
    Some(vec![
        Line::from(vec![
            Span::styled("[x]", Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled(root, Style::default().fg(Color::White)),
        ]),
        Line::styled(
            format!(
                "     このセッションのworkspace: 起動時にツリー全体へ読み書き実行を付与済み\
                 ・解除できません（配下 {hidden}件は候補にしません）"
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

/// 注記の枠の高さの下限（枠の2行を含む）。中身が収まる端末では、この高さのまま割り付けが変わらない。
const NOTES_FLOOR: u16 = 9;

/// 注記の枠の中身・見出し・送り位置の置き場（高さを決めるのにも描くのにも同じ文を使う）。
///
/// 注記とプロセスツリーは同じ枠に`t`で切り替えて出すが、**送り位置は別に持つ**（`tui::scroll::Panel`のdoc）。
fn notes_content(app: &App) -> (Panel, &'static str, String) {
    match (app.view.as_ref(), app.show_tree) {
        (Some(view), true) => (
            Panel::EditProcessTree,
            " 観測したプロセス（t で注記へ戻る） ",
            view.tree.clone(),
        ),
        (Some(view), false) => {
            let mut text = view.notes.clone();
            // 全候補に共通の警告は、候補の数だけ繰り返さずここへ1度だけ出す。
            for warning in &view.common_warnings {
                text.push_str(&format!("\n全候補に共通: {warning}\n"));
            }
            (
                Panel::EditNotes,
                " 記録の読み方（t でプロセスツリー） ",
                text,
            )
        }
        (None, _) => (Panel::EditNotes, " 記録の読み方 ", String::new()),
    }
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut out: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        out.push('…');
    }
    out
}
