//! レビューパネルの骨格（`plans/PLAN-VSCODE-REVIEW.md` §`ReviewPanel`抽象）。
//!
//! 一覧選択・行のaccept/reject・diffペインのスクロール・ハンク間移動・ハンク単位の
//! accept/rejectという**骨格は、レビュー対象が何であるかを一切知らない**。面ごとに違うのは
//! 次の3つだけで、いずれも状態の値として持つ（型やロジックの分岐にしない）。
//!
//! | 面ごとに違うもの | どこに置くか |
//! |---|---|
//! | 一覧の見出し・キー説明 | [`ReviewPanelState::title`]・[`ReviewPanelState::key_hint`] |
//! | `x`（全破棄）を提供するか | [`ReviewPanelState::allow_discard_all`] |
//! | `c`の結果を何のアクションへ写すか | [`ReviewTarget`]で分岐する[`commit_selection`] |
//!
//! 現在の唯一の面はCoW/Staged（[`ReviewPanelState::changes`]）。Recall記憶のレビュー面
//! （`plans/PLAN-RECALL-MEMORY.md`段階4）は、[`ReviewTarget`]に`Memory`を足し、
//! 対応するコンストラクタと写像を足すことで載る——骨格には触らない。

use std::collections::{HashMap, HashSet};

use crossterm::event::{KeyCode, KeyEvent};

use harness_sandbox::textdiff::DiffKind;
use harness_sandbox::FileReview;

/// `PgUp`/`PgDn`1回あたりのdiffペインのスクロール行数（端末の実高さはここでは分からないので
/// 固定値で近似する。transcript側の`PAGE_SCROLL_LINES`と同じ考え方）。
const DIFF_PAGE_LINES: u16 = 10;

/// レビュー対象の実体。**骨格はこの中身を見ない**——`c`を押した結果を具体的なアクションへ
/// 写すとき（[`commit_selection`]）だけが分岐する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewTarget {
    /// CoW/Staged面: オーバーレイの未適用変更1件。`path`は操作台帳に載っている綴り。
    Change { path: String },
}

/// 一覧の1行。
#[derive(Debug, Clone)]
pub struct ReviewRow {
    /// 一覧に出す文字列（CoW面はパス）。
    pub label: String,
    /// 行頭に出す1文字の種別印（CoW面は`A`/`M`/`D`）。
    pub badge: char,
    /// diffペインの材料（ハンク・両側ハッシュ・ハンク操作の可否）。
    pub review: FileReview,
    pub target: ReviewTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewFocus {
    List,
    Diff,
}

/// `c`を押したときに骨格が返す、**面に依存しない**選択結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewOutcome {
    pub rows: Vec<AcceptedRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRow {
    pub index: usize,
    /// この行でacceptされたハンク番号。`None`は「行まるごとaccept」（ハンク単位操作が
    /// 使えない行、または1つもrejectしなかった行）。
    pub accepted_hunks: Option<Vec<usize>>,
}

/// パネルのキー処理が呼び出し側（[`crate::AppState`]）へ返す命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewCommand {
    /// `c`（主アクション）。
    Primary(ReviewOutcome),
    /// `x`（全破棄）。[`ReviewPanelState::allow_discard_all`]が真の面でのみ出る。
    DiscardAll,
    /// `Esc`。
    Close,
}

/// diffペインに出す1行（描画は`ui::review`が色を付けるだけ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewDiffLine {
    /// ハンク見出し（`[x] hunk 1/2  @@ -1,7 +1,7 @@`）。`selected`はハンクカーソルの位置。
    Header {
        hunk: usize,
        accepted: bool,
        selected: bool,
        text: String,
    },
    /// ハンク間で省略した共通行の件数。
    Skipped(String),
    Line(DiffKind, String),
    /// ハンク単位操作が使えない理由など、差分そのものではない注記。
    Note(String),
}

/// ハンク単位のaccept/rejectを提供する[`ReviewPanelState`]の本体。
#[derive(Debug, Clone)]
pub struct ReviewPanelState {
    pub rows: Vec<ReviewRow>,
    /// 一覧ペインの見出し（面ごとの語彙）。
    pub title: String,
    /// 見出しに添えるキー説明（面ごとの語彙）。
    pub key_hint: String,
    /// `x`（全破棄）を提供するか（面ごとの語彙）。
    pub allow_discard_all: bool,
    pub selected: usize,
    /// 行単位でrejectした行のインデックス（既定は全件accept、印を付けたものだけ除外する）。
    pub rejected: HashSet<usize>,
    /// 行ごとにrejectしたハンク番号。`rejected`（行単位）とは独立で、行をacceptしたときだけ効く。
    pub rejected_hunks: HashMap<usize, HashSet<usize>>,
    pub focus: ReviewFocus,
    /// diffフォーカス中のハンクカーソル（選択行のハンク番号）。
    pub hunk_cursor: usize,
    pub diff_scroll: u16,
}

impl ReviewPanelState {
    /// CoW/Staged面（オーバーレイの未適用変更）のインスタンス。
    ///
    /// `overlay_session_id`は**どのセッションのオーバーレイを見ているか**（`--live`では`None`）。
    /// `/sessions`で切り替えられるようになった以上、見出しに出ていないと「いま何をコミット
    /// しようとしているのか」が画面から分からない（`bug-pattern-rules` B-22）。
    pub fn changes(rows: Vec<ReviewRow>, overlay_session_id: Option<&str>) -> Self {
        let title = match overlay_session_id {
            Some(id) => format!("changes — {id}"),
            None => "changes".to_string(),
        };
        Self {
            rows,
            title,
            key_hint: "↑↓ select, Enter/Space toggle, Tab diff, PgUp/PgDn scroll, c=commit, \
                       x=discard-all, Esc=close"
                .to_string(),
            allow_discard_all: true,
            selected: 0,
            rejected: HashSet::new(),
            rejected_hunks: HashMap::new(),
            focus: ReviewFocus::List,
            hunk_cursor: 0,
            diff_scroll: 0,
        }
    }

    pub fn selected_row(&self) -> Option<&ReviewRow> {
        self.rows.get(self.selected)
    }

    /// 選択中の行のハンク数（ハンク単位操作が使えない行では0を返す＝カーソルが動かない）。
    fn selectable_hunk_count(&self) -> usize {
        match self.selected_row() {
            Some(row) if row.review.hunks_selectable() => row.review.hunks.len(),
            _ => 0,
        }
    }

    pub fn is_hunk_rejected(&self, row: usize, hunk: usize) -> bool {
        self.rejected_hunks
            .get(&row)
            .is_some_and(|set| set.contains(&hunk))
    }

    fn toggle_hunk(&mut self, row: usize, hunk: usize) {
        let set = self.rejected_hunks.entry(row).or_default();
        if !set.remove(&hunk) {
            set.insert(hunk);
        }
    }

    /// `c`が返す選択結果。行rejectを除き、残った行についてacceptハンクを数え上げる。
    pub fn outcome(&self) -> ReviewOutcome {
        let rows = self
            .rows
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.rejected.contains(i))
            .map(|(i, row)| {
                let rejected = self.rejected_hunks.get(&i);
                let has_hunk_rejection = rejected.is_some_and(|set| !set.is_empty());
                let accepted_hunks = if row.review.hunks_selectable() && has_hunk_rejection {
                    Some(
                        (0..row.review.hunks.len())
                            .filter(|h| !self.is_hunk_rejected(i, *h))
                            .collect(),
                    )
                } else {
                    None
                };
                AcceptedRow {
                    index: i,
                    accepted_hunks,
                }
            })
            .collect();
        ReviewOutcome { rows }
    }

    /// diffペインに出す行列（見出し・省略・差分行・注記）。描画とテストが同じものを見る。
    pub fn diff_view(&self) -> Vec<ReviewDiffLine> {
        let Some(row) = self.selected_row() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Some(block) = row.review.hunk_block {
            out.push(ReviewDiffLine::Note(format!("({})", block.reason())));
        }
        let total = row.review.hunks.len();
        let selectable = row.review.hunks_selectable();
        let mut prev_end: Option<usize> = None;
        for (i, hunk) in row.review.hunks.iter().enumerate() {
            if let Some(end) = prev_end {
                let skipped = hunk.old_start.saturating_sub(end);
                if skipped > 0 {
                    out.push(ReviewDiffLine::Skipped(format!(
                        "… {skipped} lines skipped"
                    )));
                }
            }
            let accepted = !self.is_hunk_rejected(self.selected, i);
            let mark = if !selectable {
                "   "
            } else if accepted {
                "[x]"
            } else {
                "[ ]"
            };
            out.push(ReviewDiffLine::Header {
                hunk: i,
                accepted,
                selected: selectable && self.focus == ReviewFocus::Diff && self.hunk_cursor == i,
                text: format!("{mark} hunk {}/{}  {}", i + 1, total, hunk.header()),
            });
            for line in &hunk.lines {
                out.push(ReviewDiffLine::Line(line.kind, line.text.clone()));
            }
            prev_end = Some(hunk.old_start + hunk.old_len);
        }
        if out.is_empty() {
            out.push(ReviewDiffLine::Note("(no textual difference)".to_string()));
        }
        out
    }

    /// `diff_view()`の中で各ハンク見出しが何行目に出るか（ハンクカーソル移動時の追従用）。
    fn hunk_header_offsets(&self) -> Vec<u16> {
        self.diff_view()
            .iter()
            .enumerate()
            .filter_map(|(i, line)| match line {
                ReviewDiffLine::Header { .. } => Some(i as u16),
                _ => None,
            })
            .collect()
    }

    fn max_diff_scroll(&self) -> u16 {
        (self.diff_view().len() as u16).saturating_sub(1)
    }

    fn scroll_diff(&mut self, delta: i32) {
        let next = if delta >= 0 {
            self.diff_scroll.saturating_add(delta as u16)
        } else {
            self.diff_scroll.saturating_sub((-delta) as u16)
        };
        self.diff_scroll = next.min(self.max_diff_scroll());
    }

    /// ハンクカーソルの位置がdiffペインの先頭に来るようスクロールを合わせる。
    fn follow_hunk_cursor(&mut self) {
        if let Some(offset) = self.hunk_header_offsets().get(self.hunk_cursor) {
            self.diff_scroll = (*offset).min(self.max_diff_scroll());
        }
    }

    fn select_row(&mut self, next: usize) {
        self.selected = next.min(self.rows.len().saturating_sub(1));
        // 行が変われば見えているdiffも変わる。前の行のスクロール位置・ハンクカーソルを
        // 持ち越すと、開いた瞬間に何も無い場所を見ていることになる。
        self.hunk_cursor = 0;
        self.diff_scroll = 0;
    }

    /// パネル表示中のキー入力。パネルが消費したら`None`、呼び出し側の処理が要るときだけ
    /// [`ReviewCommand`]を返す。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        match key.code {
            KeyCode::Esc => Some(ReviewCommand::Close),
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    ReviewFocus::List => ReviewFocus::Diff,
                    ReviewFocus::Diff => ReviewFocus::List,
                };
                if self.focus == ReviewFocus::Diff {
                    self.hunk_cursor = 0;
                    self.follow_hunk_cursor();
                }
                None
            }
            KeyCode::PageUp => {
                self.scroll_diff(-(DIFF_PAGE_LINES as i32));
                None
            }
            KeyCode::PageDown => {
                self.scroll_diff(DIFF_PAGE_LINES as i32);
                None
            }
            KeyCode::Up => {
                match self.focus {
                    ReviewFocus::List => self.select_row(self.selected.saturating_sub(1)),
                    ReviewFocus::Diff => {
                        self.hunk_cursor = self.hunk_cursor.saturating_sub(1);
                        self.follow_hunk_cursor();
                    }
                }
                None
            }
            KeyCode::Down => {
                match self.focus {
                    ReviewFocus::List => self.select_row(self.selected + 1),
                    ReviewFocus::Diff => {
                        let last = self.selectable_hunk_count().saturating_sub(1);
                        self.hunk_cursor = (self.hunk_cursor + 1).min(last);
                        self.follow_hunk_cursor();
                    }
                }
                None
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                match self.focus {
                    ReviewFocus::List => {
                        let idx = self.selected;
                        if !self.rejected.remove(&idx) {
                            self.rejected.insert(idx);
                        }
                    }
                    ReviewFocus::Diff => {
                        // ハンク単位操作が使えない行では何もしない（ファイル単位のみ）。
                        if self.selectable_hunk_count() > 0 {
                            let (row, hunk) = (self.selected, self.hunk_cursor);
                            self.toggle_hunk(row, hunk);
                        }
                    }
                }
                None
            }
            KeyCode::Char('c') => Some(ReviewCommand::Primary(self.outcome())),
            KeyCode::Char('x') if self.allow_discard_all => Some(ReviewCommand::DiscardAll),
            _ => None,
        }
    }
}

/// CoW/Staged面の選択結果を、適用側（`SandboxFs::apply` / `SandboxFs::apply_hunks`）が
/// そのまま使える形へ写す。**面ごとの語彙が現れる唯一の場所**。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitSelection {
    /// ファイルまるごと適用する対象（`ApplyOptions::only_paths`へ渡す）。
    pub whole_files: Vec<String>,
    /// ハンクを選んで適用する対象（`SandboxFs::apply_hunks`へ1件ずつ渡す）。
    pub partial: Vec<PartialFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFile {
    pub path: String,
    /// パネルを開いた時点の両側ハッシュ（適用側がTOCTOU照合に使う）。
    pub workspace_hash: String,
    pub overlay_hash: String,
    pub accepted_hunks: Vec<usize>,
}

pub fn commit_selection(rows: &[ReviewRow], outcome: &ReviewOutcome) -> CommitSelection {
    let mut selection = CommitSelection::default();
    for accepted in &outcome.rows {
        let Some(row) = rows.get(accepted.index) else {
            continue;
        };
        let ReviewTarget::Change { path } = &row.target;
        match &accepted.accepted_hunks {
            None => selection.whole_files.push(path.clone()),
            // 全ハンクをrejectした＝この行については何も適用しない（オーバーレイに残す）。
            Some(hunks) if hunks.is_empty() => {}
            Some(hunks) => selection.partial.push(PartialFile {
                path: path.clone(),
                // ハンク選択可能な行では必ず両方`Some`。万一欠けていても捏造せず空を渡し、
                // 適用側のハッシュ照合に`conflicts`として弾かせる。
                workspace_hash: row.review.workspace_hash.clone().unwrap_or_default(),
                overlay_hash: row.review.overlay_hash.clone().unwrap_or_default(),
                accepted_hunks: hunks.clone(),
            }),
        }
    }
    selection
}
