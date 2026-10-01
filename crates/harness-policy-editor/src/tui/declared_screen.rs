//! 宣言画面（`F3`）の描画。状態遷移は[`crate::tui::declared`]。
//!
//! **候補画面と同じ部品で描く**（[`crate::tui::checkbox_tree`]）——チェックの記号・行の
//! 組み立て・選択の移動は共通で、この画面が足すのは「どのドメインの宣言か」だけである
//! （`docs/CODE-STRUCTURE-RULES.md`§5.1）。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::checkbox_tree::{self, Mark};
use crate::tui::state::App;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    // 説明欄は「操作の案内1行＋未承認の案内（折り返して最大2行）＋取り消しの注記4行」が入る高さ
    // （枠の2行を足して9）。足りないと注記の末尾が黙って切れる。
    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(9)]).split(area);
    let declared_list_offset = draw_tree(frame, chunks[0], app);
    draw_notes(frame, chunks[1], app);
    crate::tui::DrawFeedback {
        declared_list_offset: Some(declared_list_offset),
        ..Default::default()
    }
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
fn draw_tree(frame: &mut Frame, area: Rect, app: &App) -> usize {
    let title = format!(
        " 承認済みの宣言: {}件（このマシンで未承認 {}件・承認予約 {}件・取り消し予約 {}件）／policy.json ",
        app.declared.len(),
        app.declared_approval.not_approved.len(),
        app.declared_approval.reserved.len(),
        app.unapproved.len()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);

    if app.declared.is_empty() {
        // **「空」と「読めなかった」を混ぜない。** 読めなかった場合は`reload_declared`が
        // `status`へ理由を出しており、ここは空のときの案内だけを持つ（D-43）。
        frame.render_widget(
            Paragraph::new(
                "承認済みの宣言はありません（policy.jsonが無い、または宣言が空です）。\n\
                 F1で記録し、F2で候補を承認するとここに並びます。",
            )
            .wrap(Wrap { trim: false })
            .block(block),
            area,
        );
        // 一覧を描いていないので表示位置は進まない。
        return app.declared_list_offset;
    }

    let rows = app.declared_tree.rows(&app.declared_expanded);
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            let node = row.node;
            let under = app.declared_tree.subtree_proposals(node);
            // **`[x]`＝いま許可されている（このまま残る）／`[ ]`＝取り消しを予約した。**
            // 候補画面のチェックと同じ意味に揃えてある（チェックが入っている＝許可される）。
            let kept = under
                .iter()
                .filter(|i| {
                    app.declared
                        .get(**i)
                        .is_some_and(|t| !app.unapproved.contains(t))
                })
                .count();
            let mark = Mark::of(under.len(), kept);
            let opened = app
                .declared_expanded
                .contains(&app.declared_tree.node(node).path);

            // この画面固有の追記＝ドメイン名とキー（葉のときだけ）。
            let mut extra = Vec::new();
            if under.len() == 1 {
                if let Some(target) = app.declared.get(under[0]) {
                    extra.push(Span::styled(
                        format!("  [{}] {}", target.domain, target.key.dotted()),
                        Style::default().fg(Color::Gray),
                    ));
                    if app.unapproved.contains(target) {
                        extra.push(Span::styled(
                            "  ← 取り消します",
                            Style::default().fg(Color::Red),
                        ));
                    } else if app.declared_approval.reserved.contains(target) {
                        extra.push(Span::styled(
                            "  ← このマシンで承認します",
                            Style::default().fg(Color::Green),
                        ));
                    } else if app.declared_approval.not_approved.contains(target) {
                        // [D-112] **許可が付かないことを行そのものに出す。** 出さないと、
                        // 宣言にあるのに読めない理由がどこにも見えない。
                        extra.push(Span::styled(
                            "  （このマシンで未承認——許可は付きません。yで承認）",
                            Style::default().fg(Color::Yellow),
                        ));
                    }
                }
            }
            ListItem::new(vec![checkbox_tree::row_line(
                &app.declared_tree,
                node,
                row.depth,
                opened,
                mark,
                extra,
            )])
        })
        .collect();

    // **offsetをフレームをまたいで保つ**（`App::declared_list_offset`のdoc）。
    let mut state = ListState::default().with_offset(app.declared_list_offset);
    state.select(Some(app.declared_row));
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
    state.offset()
}

fn draw_notes(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" この画面 ");
    let mut text = String::new();
    if app.unapproved.is_empty() {
        text.push_str("→←で展開／Spaceでこの配下をまとめて取り消し予約／Aで全件／aで確定。\n");
        if !app.declared_approval.not_approved.is_empty() {
            text.push_str(&format!(
                "このマシンで未承認の宣言が{}件あります（リポジトリに同梱・手書き・以前の承認）。\
                 許可は付きません。yで配下をまとめて承認を予約できます。\n",
                app.declared_approval.not_approved.len()
            ));
        }
    } else {
        // **強調の記号を文字として書かない。** 端末では`**`はそのまま星印として出る
        // （2026-09-19に遷移の画面で実機確認し、写した元のこちらも直した）。
        text.push_str(&format!(
            "{}件の取り消しを予約中（aを押すまで何も書きません）。\n",
            app.unapproved.len()
        ));
    }
    // 文言の持ち主は`unapprove`（表示側で書き写さない）。
    text.push_str(crate::unapprove::ACE_NOTICE);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        area,
    );
}
