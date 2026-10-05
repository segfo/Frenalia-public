//! 承認待ち（`F2`）の「遷移・観測から」の**位置の行**——選んでいる記録のプロセスの木の位置ごとに、遷移先と書けない
//! 理由を並べ、予約を持つ（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65、`plans/position-domains/P4.md`の P4.3）。
//!
//! ```text
//!   ┌ 位置ごとの遷移（記録: s1） 書くもの 3件 / 全 3件（表示: 書くもの（未宣言）） ┐
//!   │ [ ] pwsh.exe     (any arguments)   2回 → pwsh     新規                       │
//!   │   [ ] calc.exe   (any arguments)   1回 → calc     新規                       │
//!   │   [ ] mspaint.exe (any arguments)  1回 → mspaint  新規                       │
//!   └──────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # いつ出るか
//!
//! FS/ネットのタブのセッション一覧で選んでいる記録が`process-audit.jsonl`を持つとき（[`crate::position_view::load`]が
//! `Some`）。持たない記録（パス2・2026-10-05より前のパス1）は今までの平らな一覧に注記を添える（決定65の細目6）。
//! 「遷移・拒否から」のタブはいつも平らな一覧である（拒否は記録の木と結び付かない）。
//!
//! # 判定を写さない（`B-13`）
//!
//! 位置・遷移先は割り当て（`harness_policy::position_domains`）、書けるかは[`crate::position_view::verdicts`]
//! （判定器）が答える。この画面は並べて予約を持つだけで、名前の検査も入れ物の名前の関数
//! （[`domain_profile_name_problem`]）を呼ぶ。
//!
//! # まだ書かない（寿命: P4.5）
//!
//! 位置の辺は、ドメインごとのファイルの宣言と一緒に1回の確定で書く（P4.5 の`position_approve`）。それまで`a`は
//! 位置の予約があれば理由を言って何も書かない（`B-32`）。
//!
//! # 限界
//!
//! - 遷移先の名前を既にあるドメインの名前へ付け替えることはできない（別の位置と同じドメインになり深さを区別しなく
//!   なる）。同じ記録の別の位置の名前とも重ねられない。
//! - 記録を替えると予約・付け替えは捨てる（位置の鍵は記録ごとに作り直すので、別の記録の行を指しうる）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent};

use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_policy::position_domains::{Position, PositionSource};
use harness_sandbox::tier2a::domain_profile_name_problem;

use crate::position_view::{
    self, can_narrow, key_of, position_edges, renamed_name, EdgeVerdict, PositionKey, PositionRow,
    PositionView,
};
use crate::transition_candidates::Startable;
use crate::tui::checkbox_tree;
use crate::tui::state::{edit_text, Action, App, Screen};
use crate::tui::text_input::TextInput;
use crate::tui::transition::PendingTab;
use crate::tui::transition_screen::file_name;

/// 位置の情報が無い記録に添える注記（決定65の細目6）。
pub(super) const NO_POSITIONS: &str = "この記録には位置の情報がありません（process-audit.jsonl が無い——\
     パス2・2026-10-05より前の記録）。「遷移・観測から」は平らな一覧で見せています（決定65の細目6）";

/// 位置の行に何を出すか。`f`で2段を巡回する。**件数は見出しに両方出す**（「無い」と「隠している」を区別する、`B-09`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PositionFilter {
    /// 書くもの（既にある辺でない位置）。**既定**——開いた人が最初に見たいのは、まだ決めていないもの
    /// （平らな一覧の既定が「保留中のみ」なのと同じ）。
    #[default]
    Writes,
    /// 既にある辺の位置も含めて全部。
    All,
}

impl PositionFilter {
    pub fn label(self) -> &'static str {
        match self {
            PositionFilter::Writes => "書くもの（未宣言）",
            PositionFilter::All => "全部",
        }
    }

    fn next(self) -> Self {
        match self {
            PositionFilter::Writes => PositionFilter::All,
            PositionFilter::All => PositionFilter::Writes,
        }
    }
}

/// 位置の行の状態（`PendingState::positions`。`state.rs`へは足さない）。
#[derive(Debug)]
pub struct PositionsState {
    pub view: PositionView,
    /// 読み直したときの`policy.json`（判定を取り直すのに使う。読み直すたびに作り直す）。
    pub policy: PolicyFile,
    /// 各位置の判定（[`crate::position_view::Assignment::positions`]と同じ並び）。予約・付け替え・絞り方を変えたら
    /// 取り直す（[`PositionsState::refresh_verdicts`]）。
    pub verdicts: Vec<EdgeVerdict>,
    /// 承認の予約（位置の鍵）。
    pub approve: BTreeSet<PositionKey>,
    /// そのうち記録どおりのコマンドラインに絞るもの（`u`）。既定は任意の引数（決定65 Q2）。
    pub narrow: BTreeSet<PositionKey>,
    /// 遷移先の名前の付け替え（割り当ての名前 → 新しい名前）。**名前ごと**当てるので、子の行の遷移元も変わる。
    pub renamed: BTreeMap<String, String>,
    /// 見えている行での選択位置。
    pub row: usize,
    pub filter: PositionFilter,
    /// 遷移先の欄に居る間の入力（`Tab`で入り、`Enter`で決める）。
    pub editing: Option<TextInput>,
}

impl PositionsState {
    fn new(view: PositionView, policy: PolicyFile) -> Self {
        Self {
            view,
            policy,
            verdicts: Vec::new(),
            approve: BTreeSet::new(),
            narrow: BTreeSet::new(),
            renamed: BTreeMap::new(),
            row: 0,
            filter: PositionFilter::default(),
            editing: None,
        }
    }

    /// いま見えている行（フィルタ適用後、木の順）。
    pub fn visible(&self) -> Vec<&PositionRow> {
        self.view
            .rows
            .iter()
            .filter(|row| match self.filter {
                PositionFilter::Writes => {
                    self.view.assignment.positions[row.position].source
                        != PositionSource::ExistingEdge
                }
                PositionFilter::All => true,
            })
            .collect()
    }

    /// 見出しの件数（書くもの, 全部）。
    pub fn counts(&self) -> (usize, usize) {
        let writes = self
            .view
            .assignment
            .positions
            .iter()
            .filter(|p| p.source != PositionSource::ExistingEdge)
            .count();
        (writes, self.view.rows.len())
    }

    /// 付け替えを当てた遷移先。
    pub fn destination_name<'a>(&'a self, position: &'a Position) -> &'a str {
        renamed_name(&self.renamed, &position.to_domain)
    }

    /// 付け替えを当てた遷移元（親の行の名前を変えると、ここも変わる）。
    pub fn source_name<'a>(&'a self, position: &'a Position) -> &'a str {
        renamed_name(&self.renamed, &position.from_domain)
    }

    /// 選んでいる行の位置の添字。
    pub fn selected_index(&self) -> Option<usize> {
        self.visible().get(self.row).map(|row| row.position)
    }

    pub fn is_reserved(&self, position: &Position) -> bool {
        self.approve.contains(&key_of(position))
    }

    pub fn is_narrowed(&self, position: &Position) -> bool {
        can_narrow(position) && self.narrow.contains(&key_of(position))
    }

    /// 判定を取り直し、**書けなくなった位置の予約を外す**（外した件数を返す）。
    fn refresh_verdicts(&mut self, workspace_root: &Path) -> usize {
        let edges = position_edges(&self.view.assignment, &self.renamed, &self.narrow);
        self.verdicts = position_view::verdicts(&self.policy, workspace_root, &edges, &[]);
        let writable: BTreeSet<PositionKey> = self
            .view
            .assignment
            .positions
            .iter()
            .zip(&self.verdicts)
            .filter(|(_, verdict)| verdict.is_writable())
            .map(|(position, _)| key_of(position))
            .collect();
        let before = self.approve.len();
        self.approve.retain(|key| writable.contains(key));
        let narrow = &mut self.narrow;
        let approve = &self.approve;
        narrow.retain(|key| approve.contains(key));
        before - self.approve.len()
    }

    /// 同じ記録を読み直したとき、前の予約・付け替え・表示を引き継ぐ（消えた位置の分は落とす）。
    fn carry_over(&mut self, previous: PositionsState) {
        let keys: BTreeSet<PositionKey> =
            self.view.assignment.positions.iter().map(key_of).collect();
        let proposed: BTreeSet<&str> = self
            .view
            .assignment
            .positions
            .iter()
            .filter(|p| p.source != PositionSource::ExistingEdge)
            .map(|p| p.to_domain.as_str())
            .collect();
        self.approve = previous
            .approve
            .into_iter()
            .filter(|k| keys.contains(k))
            .collect();
        self.narrow = previous
            .narrow
            .into_iter()
            .filter(|k| keys.contains(k))
            .collect();
        self.renamed = previous
            .renamed
            .into_iter()
            .filter(|(from, _)| proposed.contains(from.as_str()))
            .collect();
        self.filter = previous.filter;
        self.row = previous.row;
    }

    /// 付け替えの名前の問題（`None`は使える）。**見せて断るためだけ**——書けるかの最後の判断は確定（P4.5）が
    /// 入れ物の名前の検査と編集時検査で決める。
    fn rename_problem(&self, index: usize, name: &str) -> Option<String> {
        let position = &self.view.assignment.positions[index];
        if name == self.source_name(position) {
            return Some(
                "呼び出し元と同じドメインです。自己ループ辺は凍結中のため書けません（決定65）"
                    .to_string(),
            );
        }
        if let Some(problem) = domain_profile_name_problem(name) {
            return Some(format!("この名前は使えません: {problem}"));
        }
        let folded = name.to_ascii_lowercase();
        if let Some(existing) = self
            .policy
            .domains
            .iter()
            .map(|d| d.name.as_str())
            .chain([ENTRY_DOMAIN])
            .find(|existing| existing.to_ascii_lowercase() == folded)
        {
            return Some(format!(
                "policy.json に同じ名前のドメイン「{existing}」があります。位置ごとのドメインは新しい名前に\
                 してください（既にあるドメインへ向けると、別の位置と同じドメインになり深さを区別しなくなる）"
            ));
        }
        let taken = self
            .view
            .assignment
            .positions
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .any(|(_, other)| self.destination_name(other).to_ascii_lowercase() == folded);
        taken.then(|| format!("この記録の別の位置が「{name}」を使っています"))
    }
}

/// 選んでいる行の写し（借用を切るため）。
struct Selected {
    index: usize,
    position: Position,
    verdict: EdgeVerdict,
    startable: Startable,
    to: String,
}

impl App {
    /// 選んでいる記録の位置の木を読み直す（`reload_transitions`が呼ぶ）。**位置の木を出すなら真**——偽なら呼び出し側は
    /// 平らな一覧を読む。位置の情報が無い・作れない理由は`notes`に出す（`B-10`）。
    pub(super) fn reload_positions(&mut self, file: &PolicyFile, notes: &mut Vec<String>) -> bool {
        let previous = self.pending.positions.take();
        let Some(loaded) = self
            .selected_session()
            .map(|entry| position_view::load(&entry.dir, &entry.manifest, file))
        else {
            return false;
        };
        let view = match loaded {
            Ok(Some(view)) => view,
            Ok(None) => {
                notes.push(NO_POSITIONS.to_string());
                return false;
            }
            Err(e) => {
                notes.push(format!(
                    "位置の木を作れませんでした（平らな一覧で見せています）: {e}"
                ));
                return false;
            }
        };
        let mut state = PositionsState::new(view, file.clone());
        // 同じ記録なら予約を引き継ぐ。**記録を替えたら捨てる**（候補を作り直す操作で承認の予約を空にするのと同じ）。
        if let Some(previous) = previous.filter(|p| p.view.session_id == state.view.session_id) {
            state.carry_over(previous);
        }
        state.refresh_verdicts(&self.workspace_root);
        let rows = state.visible().len();
        checkbox_tree::clamp_row(&mut state.row, rows);
        self.pending.positions = Some(state);
        true
    }

    /// 位置の行に居るときのキー（`on_transition_key`が振り分ける）。
    pub(super) fn on_position_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self
            .pending
            .positions
            .as_ref()
            .is_some_and(|p| p.editing.is_some())
        {
            self.on_position_destination_key(key);
            return None;
        }
        // [BUG-212] `Ctrl`・`Alt`付きの文字キーは素の文字の操作ではない（宣言画面の遷移タブと同じ）。
        if harness_term::is_chorded_char(&key) {
            return None;
        }
        let rows = self.positions_visible_len();
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => self.focus_position_destination(),
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => self.move_position_row(rows, -1),
            KeyCode::Down => self.move_position_row(rows, 1),
            KeyCode::PageUp => self.move_position_row(rows, -10),
            KeyCode::PageDown => self.move_position_row(rows, 10),
            KeyCode::Char(' ') => self.toggle_selected_position(),
            KeyCode::Char('u') => self.toggle_selected_position_argv(),
            // 前例の表の10: 却下印は観測した（exe, 引数）1種類ごとの印で、位置は記録ごとに作り直す。1対1にならない
            // 印を作らない。何も起きないので理由を言う（`B-32`）。
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.status = "位置の行は却下できません（却下印は観測した実行ファイルと引数ごとの印で、\
                               位置は記録のたびに作り直すため）。書かない位置は選ばずにおけば何も書きません"
                    .to_string();
            }
            KeyCode::Char('f') => {
                if let Some(positions) = self.pending.positions.as_mut() {
                    positions.filter = positions.filter.next();
                    let rows = positions.visible().len();
                    checkbox_tree::clamp_row(&mut positions.row, rows);
                    self.status = format!("表示: {}", positions.filter.label());
                }
            }
            KeyCode::Char('r') => {
                self.reload_transitions();
                self.status = "遷移の候補を読み直しました".to_string();
            }
            KeyCode::Char('a') => {
                let reserved = self
                    .pending
                    .positions
                    .as_ref()
                    .map_or(0, |p| p.approve.len());
                if reserved > 0 {
                    // 寿命: P4.5 で`position_approve`の1回の確定にまとめたら、この分岐を消す。
                    self.status = format!(
                        "位置ごとの承認は P4.5 で1回の確定にまとめます。いまは書けません（位置の予約 {reserved}件は\
                         残しています。拒否からの予約は「遷移・拒否から」のタブの a で確定できます）"
                    );
                } else {
                    self.request_transition_commit();
                }
            }
            _ => {}
        }
        None
    }

    /// 位置の行を出しているか（「遷移・観測から」のタブで、選んでいる記録に位置の情報がある）。
    pub fn shows_positions(&self) -> bool {
        self.pending.tab.0 == PendingTab::TransitionsObserved && self.pending.positions.is_some()
    }

    fn positions_visible_len(&self) -> usize {
        self.pending
            .positions
            .as_ref()
            .map_or(0, |p| p.visible().len())
    }

    /// 位置の行の選択を`by`だけ動かす（クリックで行を選ぶのもこれを通る。`tui::pointer`）。
    pub(super) fn move_position_row(&mut self, rows: usize, by: isize) {
        if let Some(positions) = self.pending.positions.as_mut() {
            checkbox_tree::move_row(&mut positions.row, rows, by);
        }
    }

    fn selected_position(&self) -> Option<Selected> {
        let positions = self.pending.positions.as_ref()?;
        let index = positions.selected_index()?;
        let position = positions.view.assignment.positions[index].clone();
        let startable = positions
            .view
            .rows
            .iter()
            .find(|row| row.position == index)
            .map_or(Startable::AsFarAsWeKnow, |row| row.startable);
        Some(Selected {
            index,
            to: positions.destination_name(&position).to_string(),
            verdict: positions
                .verdicts
                .get(index)
                .cloned()
                .unwrap_or(EdgeVerdict::Writable),
            position,
            startable,
        })
    }

    /// 行が無いときに言うこと（フィルタで隠れているのか、本当に無いのかを区別する、`B-09`）。
    fn no_position_message(&self) -> String {
        match self.pending.positions.as_ref().map(|p| p.filter) {
            Some(PositionFilter::Writes) => {
                "書く位置がありません（f で全部を出すと、宣言済みの位置も出ます）".to_string()
            }
            _ => "この記録には割り当てた位置がありません（注記の件数を見てください）".to_string(),
        }
    }

    /// 選んでいる位置を承認する／やめる（**予約。書くのは確定**）。書けない位置は理由を言う。
    fn toggle_selected_position(&mut self) {
        let Some(selected) = self.selected_position() else {
            self.status = self.no_position_message();
            return;
        };
        let name = file_name(&selected.position.exe).to_string();
        if selected.position.source == PositionSource::ExistingEdge
            || selected.verdict == EdgeVerdict::AlreadyDeclared
        {
            self.status = format!("{name} は宣言済みです。取り消しは宣言画面（F3）の遷移タブで");
            return;
        }
        if let Some(note) = selected.startable.note() {
            self.status = format!("{name}: {note}");
            return;
        }
        if let Some(note) = selected.verdict.note() {
            self.status = format!("{name}: {note}");
            return;
        }
        let key = key_of(&selected.position);
        let workspace_root = self.workspace_root.clone();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        if positions.approve.remove(&key) {
            if positions.narrow.remove(&key) {
                positions.refresh_verdicts(&workspace_root);
            }
            self.status = format!("{name} の承認をやめました");
        } else {
            positions.approve.insert(key);
            self.status = format!("{name} を許します（→ {}）", selected.to);
        }
    }

    /// 選んでいる位置の引数の広さを切り替える（任意の引数 ⇄ 記録どおりのコマンドライン）。
    ///
    /// 絞った辺が検査に落ちるなら（相対パスの引数を含む等）、**判定器の理由を言って絞らない**——相対かどうかを
    /// ここで判定しない（`B-13`）。このエディタは作業ディレクトリを宣言しないので、その直し方は取れない。
    fn toggle_selected_position_argv(&mut self) {
        let Some(selected) = self.selected_position() else {
            self.status = self.no_position_message();
            return;
        };
        let name = file_name(&selected.position.exe).to_string();
        if selected.position.source == PositionSource::ExistingEdge {
            self.status = format!(
                "{name} は宣言済みの辺の行です（引数の広さは policy.json の辺が決めています）"
            );
            return;
        }
        let key = key_of(&selected.position);
        let workspace_root = self.workspace_root.clone();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        if !positions.approve.contains(&key) {
            self.status =
                "先にSpaceで選んでください（選んだ行の引数の広さを切り替えます）".to_string();
            return;
        }
        if positions.narrow.remove(&key) {
            positions.refresh_verdicts(&workspace_root);
            self.status = format!("{name}: 任意の引数を許します");
            return;
        }
        let position = &selected.position;
        if !can_narrow(position) {
            self.status = if position.argv_truncated > 0 {
                format!(
                    "{name}: コマンドラインが切り詰められている疑いのある起動が{}回あるので、記録どおりには\
                     絞れません（DESIGN-MAC §5.1(6)。任意の引数のまま）",
                    position.argv_truncated
                )
            } else if position.argv_missing > 0 {
                format!(
                    "{name}: 引数が結び付かなかった起動が{}回あるので、記録どおりには絞れません（任意の引数のまま）",
                    position.argv_missing
                )
            } else {
                format!(
                    "{name}: 記録したコマンドラインが{}通りあるので、1つに絞れません（任意の引数のまま）",
                    position.command_lines.len()
                )
            };
            return;
        }
        positions.narrow.insert(key.clone());
        positions.refresh_verdicts(&workspace_root);
        let verdict = positions
            .verdicts
            .get(selected.index)
            .cloned()
            .unwrap_or(EdgeVerdict::Writable);
        if verdict.is_writable() {
            self.status = format!(
                "{name}: この引数のときだけ許します（{}）",
                position.command_lines[0]
            );
            return;
        }
        // 絞ると書けない。絞りを戻し、予約も元どおりにする（取り直しで外れた予約を戻す）。
        positions.narrow.remove(&key);
        positions.approve.insert(key);
        positions.refresh_verdicts(&workspace_root);
        let detail = match verdict {
            EdgeVerdict::Widens { detail } | EdgeVerdict::Rejected { detail } => detail,
            EdgeVerdict::AlreadyDeclared | EdgeVerdict::Writable => String::new(),
        };
        self.status = format!(
            "{name}: 記録どおりに絞ると検査に落ちるので絞れません（任意の引数のままにします。\
             このエディタは作業ディレクトリを宣言しない）。検査の理由: {detail}"
        );
    }

    /// `Tab`: 選んでいる位置の遷移先の欄へ入る。新しく提案した位置だけ（既にある辺の遷移先は`policy.json`が決める）。
    fn focus_position_destination(&mut self) {
        let Some(selected) = self.selected_position() else {
            self.status = self.no_position_message();
            return;
        };
        let name = file_name(&selected.position.exe).to_string();
        match selected.position.source {
            PositionSource::ExistingEdge => {
                self.status = format!(
                    "{name} は既にある辺の行です。遷移先は policy.json の辺が決めています\
                     （変えるなら宣言画面（F3）の遷移タブで取り消してから記録し直してください）"
                );
            }
            PositionSource::Proposed | PositionSource::ReplacesSelfLoop => {
                if let Some(positions) = self.pending.positions.as_mut() {
                    positions.editing = Some(TextInput::new(""));
                }
                self.status = format!(
                    "{name} の遷移先の新しい名前を入れてください（いま: {}。Enter で決める・空のまま Enter でやめる）",
                    selected.to
                );
            }
        }
    }

    /// 遷移先の欄に居るときのキー。**1文字キーを操作に取らない**（名前が打てなくなる）。
    fn on_position_destination_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab => self.apply_position_rename(),
            // 入力欄に居ても画面を離れられるようにする（平らな一覧の遷移先の欄と同じ）。打ちかけの名前は捨てる。
            KeyCode::Esc => {
                if let Some(positions) = self.pending.positions.as_mut() {
                    positions.editing = None;
                }
                self.screen = Screen::Record;
            }
            _ => {
                if let Some(input) = self
                    .pending
                    .positions
                    .as_mut()
                    .and_then(|p| p.editing.as_mut())
                {
                    edit_text(input, key);
                }
            }
        }
    }

    /// 欄の名前を選んでいる位置の遷移先にする（名前ごと付け替えるので、子の行の遷移元も変わる）。
    fn apply_position_rename(&mut self) {
        let workspace_root = self.workspace_root.clone();
        let selected = self.selected_position();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        let text = positions
            .editing
            .take()
            .map(|input| input.text().trim().to_string())
            .unwrap_or_default();
        let Some(selected) = selected else {
            return;
        };
        let name = file_name(&selected.position.exe).to_string();
        if text.is_empty() {
            self.status = format!("{name} の遷移先は変えませんでした（いま: {}）", selected.to);
            return;
        }
        if text == selected.to {
            self.status = format!("{name} の遷移先は {text} のままです");
            return;
        }
        if let Some(problem) = positions.rename_problem(selected.index, &text) {
            self.status = format!("{name}: {problem}（遷移先は {} のままです）", selected.to);
            return;
        }
        let original = selected.position.to_domain.clone();
        if text == original {
            positions.renamed.remove(&original);
        } else {
            positions.renamed.insert(original, text.clone());
        }
        positions.refresh_verdicts(&workspace_root);
        self.status = format!(
            "{name} の遷移先を {text} にしました（この位置から起きる子の遷移元も {text} になります）"
        );
    }
}

#[cfg(test)]
#[path = "transition_positions_tests.rs"]
mod transition_positions_tests;
