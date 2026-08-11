//! チェックボックス付きパス木の**表示と操作**を、候補画面（`F2`）と宣言画面（`F4`）で共有する。
//!
//! # なぜ共有するのか（`docs/CODE-STRUCTURE-RULES.md`§5.1）
//!
//! 承認（候補にチェックを付ける）と取り消し（宣言のチェックを外す）は**対の操作**で、
//! ユーザーがやることも見るものも同じ——木を辿り、配下をまとめて選び、確認してから確定する。
//! 別々に書くと、片方に付いた改善がもう片方へ届かない（実際に一度そうなった: 宣言画面を
//! 平坦なリストで作ってしまい、**`ProposalTree`が解決したはずの問題を作り直していた**
//! ——`cargo`ドメインの宣言は実測668件で、平坦に並べると「この下をまとめて取り消す」という
//! 判断そのものができない）。
//!
//! # ここに置くもの／置かないもの
//!
//! 置くのは**両方の画面で同じもの**——チェックの記号と色、行の組み立て、選択位置の移動。
//! 置かないのは**行に固有の説明**（候補は観測回数と警告、宣言は由来）で、それは各画面が足す。
//! 木そのものの構造（1本道の畳み込み・件数集計）は[`super::proposal_tree`]が持つ（純粋・
//! ratatui非依存のまま保つ）。

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use super::proposal_tree::ProposalTree;

/// 木の1行に付くチェックの状態。
///
/// **「一部だけ選ばれている」が見えないと、まとめて選んだあと個別に外す使い方ができない。**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// 配下すべてが入っている。
    All,
    /// 一部だけ入っている。
    Partial,
    /// 1件も入っていない。
    None,
    /// 操作の対象になるものが配下に無い（承認できない候補だけ、など）。
    NotApplicable,
}

impl Mark {
    /// 「操作できる件数」と「そのうち入っている件数」から決める。
    pub fn of(selectable: usize, selected: usize) -> Self {
        if selectable == 0 {
            Mark::NotApplicable
        } else if selected == selectable {
            Mark::All
        } else if selected > 0 {
            Mark::Partial
        } else {
            Mark::None
        }
    }

    pub fn glyph(self) -> &'static str {
        match self {
            Mark::All => "[x]",
            Mark::Partial => "[~]",
            Mark::None => "[ ]",
            Mark::NotApplicable => "[-]",
        }
    }

    /// 色は補助であって唯一の手掛かりにしない（記号が本体）。
    pub fn color(self) -> Color {
        match self {
            Mark::All => Color::Green,
            Mark::Partial => Color::Yellow,
            Mark::None | Mark::NotApplicable => Color::DarkGray,
        }
    }

    pub fn span(self) -> Span<'static> {
        Span::styled(self.glyph(), Style::default().fg(self.color()))
    }
}

/// 木の1行（インデント・チェック・開閉記号・ラベル・配下の件数）を組み立てる。
///
/// `extra`は画面ごとの追記（候補なら何も足さない、宣言なら件数の言い換えなど）。
pub fn row_line<'a>(
    tree: &ProposalTree,
    node: usize,
    depth: usize,
    opened: bool,
    mark: Mark,
    extra: Vec<Span<'a>>,
) -> Line<'a> {
    let has_children = tree.has_children(node);
    let node_ref = tree.node(node);
    let mut spans = vec![
        Span::raw("  ".repeat(depth)),
        mark.span(),
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
        Span::raw(format!(" {}", node_ref.label)),
    ];
    if has_children {
        spans.push(Span::styled(
            format!("  （配下 {}件", node_ref.total),
            Style::default().fg(Color::DarkGray),
        ));
        if node_ref.approvable != node_ref.total {
            spans.push(Span::styled(
                format!("・対象 {}件", node_ref.approvable),
                Style::default().fg(Color::DarkGray),
            ));
        }
        spans.push(Span::styled("）", Style::default().fg(Color::DarkGray)));
    }
    spans.extend(extra);
    Line::from(spans)
}

/// 選択位置を動かす（行数でクランプ）。**両方の画面が同じ関数を通る**ので、
/// 片方だけ`PageUp`が効かない・端で止まらない、といった差が生まれない。
pub fn move_row(selected: &mut usize, rows: usize, delta: isize) {
    if rows == 0 {
        *selected = 0;
        return;
    }
    let next = *selected as isize + delta;
    *selected = next.clamp(0, rows as isize - 1) as usize;
}

/// 行数が減ったときに選択位置を範囲内へ戻す。
pub fn clamp_row(selected: &mut usize, rows: usize) {
    if *selected >= rows {
        *selected = rows.saturating_sub(1);
    }
}

#[cfg(test)]
#[path = "checkbox_tree_tests.rs"]
mod checkbox_tree_tests;
