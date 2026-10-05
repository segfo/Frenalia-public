//! 宣言画面（`F3`）の描画。状態遷移は[`crate::tui::declared`]。
//!
//! **候補画面と同じ部品で描く**（[`crate::tui::checkbox_tree`]）——チェックの記号・行の
//! 組み立て・選択の移動は共通で、この画面が足すのは「どのドメインの宣言か」だけである
//! （`docs/CODE-STRUCTURE-RULES.md`§5.1）。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, ListItem, ListState};
use ratatui::Frame;

use crate::tui::checkbox_tree::{self, Mark, FOLD_SPAN, MARK_SPAN};
use crate::tui::pointer::{register_rows, Hot, ListId, Targets};
use crate::tui::scroll::{Panel, Wheel};
use crate::tui::state::App;
use crate::tui::wrap;

/// 説明欄の高さの下限（枠の2行を含む）。中身が収まる端末では、この高さのまま割り付けが変わらない。
const NOTES_FLOOR: u16 = 10;

/// 一覧の行・`[x]`・`▾`/`▸`は押せる場所として、説明欄はホイールで送る枠として、描いた矩形で登録する
/// （`tui::pointer`）。
pub fn draw(frame: &mut Frame, area: Rect, app: &App) -> crate::tui::DrawFeedback {
    let notes = notes_text(app);
    let chunks = split(area, &notes);
    let mut feedback = crate::tui::DrawFeedback::default();
    feedback.declared_list_offset = Some(draw_tree(frame, chunks[0], app, &mut feedback.targets));
    // 入り切らない分はホイールで送る（`tui::scroll`）。
    feedback
        .targets
        .wheel(chunks[1], Wheel::Panel(Panel::DeclaredNotes));
    feedback.panels.set(
        Panel::DeclaredNotes,
        harness_term::scrollable::draw(
            frame,
            chunks[1],
            notes,
            Block::default().borders(Borders::ALL).title(" この画面 "),
            app.panels.top(Panel::DeclaredNotes),
            wrap::panel_look(Style::default()),
            harness_term::select::Selectable::new(
                &mut feedback.targets,
                Wheel::Panel(Panel::DeclaredNotes),
                &app.selection,
            ),
        ),
    );
    feedback
}

/// 一覧と説明欄の割り付け。押せる場所・送れる枠は、ここで出した矩形へ描いたものをそのまま登録する
/// （BUG-194。`tui::pointer`）。
///
/// 説明欄は**中身を折り返した行数ぶん**の高さを取る（BUG-192。`tui::wrap`）。
/// 以前は「操作の案内（折り返して最大2行）＋未承認の案内（折り返して最大2行）＋取り消しの注記4行」
/// と手で数えた固定の10行で、端末が狭くて注記まで折り返すと、注記の末尾
/// （「消した宣言にはこの先許可が付きません」）が黙って切れていた。手で数えた行数は、
/// 文言を足すたびにも端末の幅が変わるたびにもずれる。
/// 上限は本文の半分（一覧を潰さない）。それでも入らない分はホイールで送る。
fn split(area: Rect, notes: &str) -> std::rc::Rc<[Rect]> {
    let height = wrap::box_height(notes, area.width, NOTES_FLOOR, area.height / 2);
    Layout::vertical([Constraint::Min(3), Constraint::Length(height)]).split(area)
}

/// 戻り値はratatuiが選択を見せるために定めた表示開始位置（呼び出し側が保存する）。
/// 描いた行・`[x]`・`▾`/`▸`は押せる場所として登録する。
fn draw_tree(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) -> usize {
    let title = format!(
        " 承認済みの宣言: {}件（このマシンで未承認 {}件・承認予約 {}件・付け替え予約 {}件・取り消し予約 {}件）／policy.json ",
        app.declared.len(),
        app.declared_approval.not_approved.len(),
        app.declared_approval.reserved.len(),
        // キー案内の`a 確定（…）`と同じく、取り消しが勝つ分を除いた実際に書く件数で数える。
        app.declared_reassign.effective(&app.unapproved).len(),
        app.unapproved.len()
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);

    if app.declared.is_empty() {
        // **「空」と「読めなかった」を混ぜない。** 読めなかった場合は`reload_declared`が
        // `status`へ理由を出しており、ここは空のときの案内だけを持つ（D-43）。
        harness_term::wrap::Wrapped::new(
            "承認済みの宣言はありません（policy.jsonが無い、または宣言が空です）。\n\
             F1で記録し、F2で候補を承認するとここに並びます。",
        )
        .block(block)
        .render(frame, area);
        // 一覧を描いていないので表示位置は進まない。
        return app.declared_list_offset;
    }

    let rows = app.declared_tree.rows(&app.declared_expanded);
    // 行ごとの`[x]`と`▾`/`▸`の位置（押せる場所。spanの並びは`checkbox_tree::row_line`）。
    let mut hot = Vec::with_capacity(rows.len());
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
                .contains(&app.declared_tree.node(node).key);

            // 付け替えの予約の印。**`c`・`R`が効くのはこの行自身の宣言（1件のとき）**なので、
            // 配下を持つディレクトリの行でも、その行自身の宣言を付け替えるなら出す。
            // 取り消しを予約した宣言では出さない——確定では取り消しが勝つので、出すと書かれない
            // 付け替えが見えてしまう（`DeclaredReassignState::effective`）。
            let own = &app.declared_tree.node(node).proposals;
            let reassign_span = (own.len() == 1)
                .then(|| app.declared.get(own[0]))
                .flatten()
                .filter(|target| !app.unapproved.contains(*target))
                .and_then(|target| app.declared_reassign.reserved.get(target))
                .map(|(key, value)| {
                    Span::styled(
                        format!("  → {} {} に付け替えます", key.dotted(), value),
                        Style::default().fg(Color::Magenta),
                    )
                });

            // この画面固有の追記＝ドメイン名とキー（葉のときだけ。ドメインの見出しの配下がちょうど1件でも、
            // 見出しの行には出さない——その1件の行が下に同じものを出す）。
            let mut extra = Vec::new();
            let leaf = under.len() == 1 && !app.declared_tree.node(node).is_domain_header;
            if !leaf {
                extra.extend(reassign_span.clone());
            }
            if leaf {
                if let Some(target) = app.declared.get(under[0]) {
                    extra.push(Span::styled(
                        format!("  [{}] {}", target.domain, target.key.dotted()),
                        Style::default().fg(Color::Gray),
                    ));
                    // 承認の印と**並べて**出す（同じ行で`y`と`c`を両方予約できる）。
                    extra.extend(reassign_span);
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
            let line =
                checkbox_tree::row_line(&app.declared_tree, node, row.depth, opened, mark, extra);
            hot.push(Hot::of(
                &line.spans,
                Some(MARK_SPAN),
                app.declared_tree
                    .has_children(node)
                    .then_some((FOLD_SPAN, opened)),
            ));
            ListItem::new(vec![line])
        })
        .collect();

    // **offsetをフレームをまたいで保つ**（`App::declared_list_offset`のdoc）。
    let mut state = ListState::default().with_offset(app.declared_list_offset);
    state.select(Some(app.declared_row));
    let drawn = harness_term::list::draw(
        frame,
        area,
        items,
        Some(block),
        Style::default().add_modifier(Modifier::REVERSED),
        &mut state,
    );
    register_rows(targets, ListId::Declared, &drawn, &hot);
    state.offset()
}

/// 説明欄（「この画面」）の中身。高さを決めるのにも描くのにも同じ文を使う。
fn notes_text(app: &App) -> String {
    let mut text = String::new();
    if app.unapproved.is_empty() {
        text.push_str(
            "→←で展開／Spaceでこの配下をまとめて取り消し予約／Aで全件／\
             cで種類・Rで ** を付け替え（1行ずつ）／rで読み直し／aで確定。\
             F3で遷移のタブ（ドメインごとの辺と遷移の形）へ。\n",
        );
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
    text
}
