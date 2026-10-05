//! [段階⑦] 承認待ち画面（`F2`）の**遷移の2タブ**——「観測から」と「拒否から」
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定62）。
//!
//! ```text
//!   ┌ F2 承認待ち ────────────────────────────────────────┐
//!   │ Tab で切替:  FS/ネット │ 遷移・観測から │ 遷移・拒否から │
//!   │                                                      │
//!   │  [ ] cargo.exe   (任意の引数)      観測 12回           │
//!   │  [x] git.exe     (任意の引数)      宣言済み            │
//!   └──────────────────────────────────────────────────────┘
//! ```
//!
//! # なぜ2つを同じ画面のタブにするのか
//!
//! 出どころは違う（片方は隔離せずに観測したもの、片方は断られたもの）が、
//! **ユーザーがやることは同じ**である——選んで、許す。画面を分けると同じ操作を2箇所に
//! 実装することになる（決定62、`docs/CODE-STRUCTURE-RULES.md`§5.1）。
//!
//! # 遷移元ドメインは固定である。遷移先は欄で選ぶ
//!
//! 遷移元は[`ENTRY_DOMAIN`]（`workspace-shell`）を使う。**記録画面のドメイン欄とは混ぜない**
//! ——あちらは「パス2で記録中のドメイン名」で由来が違い、入口ドメインが固定なのは
//! `run_shell`経路だけである（`policy_file::ENTRY_DOMAIN`のdoc）。混ぜると、
//! **Daemonが一度も見ないドメインへ遷移を書く**ことになる。
//!
//! 遷移先は`Tab`で入る欄で選ぶ（2026-10-01。既定は遷移元と同じ。[`super::transition_destination`]）。
//!
//! # 木にしない（`F2`のFS/ネットのタブとの違い）
//!
//! FS側が[`super::proposal_tree::ProposalTree`]を使うのは、実測849件のパスが平坦だと
//! 「この下をまとめて許す」という判断ができないからである。**遷移の行はパスではなく
//! プログラム**で、今日測った候補は11件だった。木にする理由（階層が読めない）が立たないので
//! 平坦な一覧にする。チェックの記号と選択の移動は[`super::checkbox_tree`]を通す
//! ——そこは対の操作と同じものである。
//!
//! # ここが持たないもの
//!
//! - **候補の組み立てと「もう宣言済みか」**: [`crate::transition_candidates`]
//! - **書く／消す**: [`crate::transition_approve`]
//! - **確定（確認ダイアログを出し、`y`で`policy.json`と却下印へ書く）**: [`super::transition_commit`]
//! - **却下印（`dismissed.json`）の読み書き**: [`super::transition_dismissed`]
//! - **描画**: [`super::transition_screen`]

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use harness_policy::policy_file::{self, ENTRY_DOMAIN};

use crate::transition_approve::EdgeRef;
use crate::transition_candidates::{
    from_denials, from_observations, Candidate, Declared, DeclaredEdges,
};
use crate::tui::checkbox_tree;
use crate::tui::state::{Action, App, Screen};
use crate::tui::transition_dismissed::{self, Dismissals};

// `transition_tests`は`use super::*`で確認ダイアログの種類（`Confirm`）を引く。確定の半分を
// [`super::transition_commit`]へ移した後も、試験を書き換えずに済むようここから引けるようにしておく
// （`plans/position-domains/P4.md`のP4.0）。
#[cfg(test)]
use crate::tui::state::Confirm;

/// 承認待ち画面（`F2`）のタブ。**決定62**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingTab {
    /// 記録セッションが観測したファイル・通信の候補（従来の編集画面）。
    FsNet,
    /// パス1が観測した遷移の候補（`observed.jsonl`）。
    TransitionsObserved,
    /// Spawn Daemonが断った遷移の要求（`pending.jsonl`）。
    TransitionsDenied,
}

impl PendingTab {
    pub fn label(self) -> &'static str {
        match self {
            PendingTab::FsNet => "FS/ネット",
            PendingTab::TransitionsObserved => "遷移・観測から",
            PendingTab::TransitionsDenied => "遷移・拒否から",
        }
    }

    /// `F2`で巡回する次のタブ（タブの行もこの順に並べる。`tui::draw_pending_tabs`）。
    pub(crate) fn next(self) -> Self {
        match self {
            PendingTab::FsNet => PendingTab::TransitionsObserved,
            PendingTab::TransitionsObserved => PendingTab::TransitionsDenied,
            PendingTab::TransitionsDenied => PendingTab::FsNet,
        }
    }

    fn prev(self) -> Self {
        match self {
            PendingTab::FsNet => PendingTab::TransitionsDenied,
            PendingTab::TransitionsObserved => PendingTab::FsNet,
            PendingTab::TransitionsDenied => PendingTab::TransitionsObserved,
        }
    }

    pub fn is_transition(self) -> bool {
        !matches!(self, PendingTab::FsNet)
    }
}

/// 一覧に何を出すか。`f`で「保留中 → 却下済み → 全部」を巡回する（決定62）。
///
/// **件数を必ず見出しに出す**こと——「無い」と「隠している」が区別できないと、
/// 黙って捨てているのと同じである（`B-09`、決定29と同じ形）。3段の件数は[`PendingState::counts`]が持つ。
///
/// # 3つの段は重ならない
///
/// 「保留中」と「却下済み」は、どちらも**まだ宣言されていない**行（[`Candidate::is_approvable`]）を
/// 却下印の有無で2つに割ったものである。宣言済みの行は**却下印が残っていても**どちらにも入らず、
/// 「全部」にだけ出る——宣言されているかどうかは`policy.json`と判定器が答える正本で、
/// 却下印は表示の好みにすぎない（決定62「却下印の永続化を実装した」の(5)）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PendingFilter {
    /// まだ宣言されておらず、却下もしていないものだけ。**既定はこちら**——一覧を開いた人が
    /// 最初に見たいのは「まだ決めていないもの」である。
    #[default]
    Pending,
    /// 却下したもの（まだ宣言されていないもの）だけ。**ここで選び直せる**——`Space`で承認を、
    /// `x`で却下の取り消しを予約できる（却下を片方向の操作にしない）。
    Dismissed,
    /// 宣言済みも含めて全部。
    All,
}

impl PendingFilter {
    pub fn label(self) -> &'static str {
        match self {
            PendingFilter::Pending => "保留中のみ",
            PendingFilter::Dismissed => "却下済み",
            PendingFilter::All => "全部",
        }
    }

    fn next(self) -> Self {
        match self {
            PendingFilter::Pending => PendingFilter::Dismissed,
            PendingFilter::Dismissed => PendingFilter::All,
            PendingFilter::All => PendingFilter::Pending,
        }
    }
}

/// 見出しに出す件数（3段それぞれ）。**「無い」と「隠している」を区別する**（`B-09`）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// まだ宣言されておらず、却下もしていない。
    pub pending: usize,
    /// まだ宣言されておらず、却下した。
    pub dismissed: usize,
    /// 全部（宣言済み・パターンに覆われている等も含む）。
    pub total: usize,
}

/// 候補の同一性＝**観測された`(exe, argv)`の組**。
///
/// 予約（承認する／引数を絞る）をこの組で持つ。**書く辺そのもの（[`EdgeRef`]）で持たない**
/// ——引数を絞るかどうかで辺は変わるが、**ユーザーが指している行は同じ**だからである。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CandidateKey {
    pub exe: String,
    pub argv: String,
}

impl CandidateKey {
    pub(super) fn of(candidate: &Candidate) -> Self {
        Self {
            exe: candidate.exe.clone(),
            argv: candidate.argv.clone(),
        }
    }
}

/// 承認待ち画面の状態のうち、**遷移の2タブが持つぶん**。
///
/// `App`はこれを1フィールドで持つ。`state.rs`は本体1,953行で規則1（1,000行）を既に
/// 超えているので、**新しい状態をあちらへ足さない**。
#[derive(Debug, Default)]
pub struct PendingState {
    pub tab: Tab,
    /// 観測の候補（`observed.jsonl`）。
    pub observed: Vec<Candidate>,
    /// 拒否の候補（`pending.jsonl`）。
    pub denied: Vec<Candidate>,
    /// 宣言済みの辺（**モデルが見るのと同じ一覧**）。
    pub declared_rows: Vec<harness_policy::transition_listing::Row>,
    /// 読めなかった・飛ばした・あふれた事実。**黙らせない**（`B-10`）。
    pub notes: Vec<String>,
    pub observed_row: usize,
    pub denied_row: usize,
    /// 承認の予約。
    pub approve: BTreeSet<CandidateKey>,
    /// そのうち「観測された引数のときだけ許す」もの。既定は任意の引数（＝この集合の外）。
    pub narrow: BTreeSet<CandidateKey>,
    /// 取り消しの予約（**宣言に書かれている辺**で指す）。
    pub remove: BTreeSet<EdgeRef>,
    pub filter: PendingFilter,
    /// いまの却下印（`dismissed.json`）。**読めなかったら空**で、理由は`notes`に出る。
    pub dismissed: Dismissals,
    /// 却下の予約。**承認の予約（`approve`）とは同じ行に同時に立たない**——片方を立てると
    /// もう片方を外す（「許す」と「許さない」を同時に予約させない）。
    pub dismiss: BTreeSet<CandidateKey>,
    /// 却下の取り消しの予約（保留中へ戻す）。
    pub undismiss: BTreeSet<CandidateKey>,
    /// 承認する辺の遷移先（欄。既定は遷移元と同じ）。
    pub destination: super::transition_destination::DestinationField,
    /// `policy.json`の各ドメインを`harness.exe`が用意する見込み（読み直すたびに作り直す）。
    pub outlooks: std::collections::BTreeMap<String, crate::transition_destination::Outlook>,
}

/// [`PendingState::tab`]の既定を`FsNet`にするための薄い包み。
///
/// `Default`が要るのは`App`が`Default`で組み立てられるためで、**既定は従来の画面**である
/// ——画面を開いた人が、いきなり見慣れないタブに居ることにならない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tab(pub PendingTab);

impl Default for Tab {
    fn default() -> Self {
        Tab(PendingTab::FsNet)
    }
}

impl PendingState {
    /// いま見えている候補（フィルタ適用後）。
    pub fn visible(&self) -> Vec<&Candidate> {
        let all = match self.tab.0 {
            PendingTab::TransitionsDenied => &self.denied,
            _ => &self.observed,
        };
        all.iter()
            .filter(|c| match self.filter {
                PendingFilter::Pending => c.is_approvable() && !self.is_dismissed(c),
                PendingFilter::Dismissed => c.is_approvable() && self.is_dismissed(c),
                PendingFilter::All => true,
            })
            .collect()
    }

    /// この候補は却下印を持っているか（**宣言済みかどうかは見ない**。段の振り分けは[`Self::visible`]）。
    ///
    /// 遷移元は画面が辺を書く先（[`ENTRY_DOMAIN`]）で比べる——承認と同じ3つ組である
    /// （`transition_dismissed`のモジュールdoc）。
    pub fn is_dismissed(&self, candidate: &Candidate) -> bool {
        self.dismissed
            .contains(ENTRY_DOMAIN, &candidate.exe, &candidate.argv)
    }

    /// この候補は却下を予約されているか。
    pub fn is_dismiss_reserved(&self, candidate: &Candidate) -> bool {
        self.dismiss.contains(&CandidateKey::of(candidate))
    }

    /// この候補は却下の取り消しを予約されているか。
    pub fn is_undismiss_reserved(&self, candidate: &Candidate) -> bool {
        self.undismiss.contains(&CandidateKey::of(candidate))
    }

    /// いま選ばれている行の位置（タブごとに覚える）。
    pub fn row(&self) -> usize {
        match self.tab.0 {
            PendingTab::TransitionsDenied => self.denied_row,
            _ => self.observed_row,
        }
    }

    pub(crate) fn row_mut(&mut self) -> &mut usize {
        match self.tab.0 {
            PendingTab::TransitionsDenied => &mut self.denied_row,
            _ => &mut self.observed_row,
        }
    }

    /// この候補は承認予約されているか。
    pub fn is_reserved(&self, candidate: &Candidate) -> bool {
        self.approve.contains(&CandidateKey::of(candidate))
    }

    /// この候補は「観測された引数のときだけ」に絞る予約がされているか。
    pub fn is_narrowed(&self, candidate: &Candidate) -> bool {
        self.narrow.contains(&CandidateKey::of(candidate))
    }

    /// この候補の宣言は取り消し予約されているか。
    pub fn is_unreserved(&self, candidate: &Candidate) -> bool {
        candidate
            .removal_ref()
            .is_some_and(|target| self.remove.contains(&target))
    }

    /// 見出しに出す件数（**「無い」と「隠している」を区別する**。`B-09`）。
    ///
    /// 振り分けは[`Self::visible`]と同じ条件である——別の条件で数えると、見出しの件数と
    /// `f`で切り替えた先の行数が食い違う。
    pub fn counts(&self, tab: PendingTab) -> Counts {
        let all = match tab {
            PendingTab::TransitionsDenied => &self.denied,
            _ => &self.observed,
        };
        let undecided = all.iter().filter(|c| c.is_approvable());
        let dismissed = undecided.clone().filter(|c| self.is_dismissed(c)).count();
        Counts {
            pending: undecided.count() - dismissed,
            dismissed,
            total: all.len(),
        }
    }

    /// 予約の件数（承認・取り消し・却下・却下の取り消し）。**キーの案内と下の枠が同じ数を出す。**
    pub fn reserved_count(&self) -> usize {
        self.approve.len() + self.remove.len() + self.dismiss.len() + self.undismiss.len()
    }
}

impl App {
    /// 遷移の候補と宣言を読み直す。**予約は保つ**——読み直しは表示を最新にする操作で、
    /// ユーザーの意思を捨てる操作ではない（`reload_declared`と同じ作法）。
    /// ただし**もう存在しない宣言への取り消し予約**は落とす。
    pub fn reload_transitions(&mut self) {
        let workspace_root = self.workspace_root.clone();
        let mut notes: Vec<String> = Vec::new();

        let file = match policy_file::load(&workspace_root) {
            Ok(file) => file,
            Err(e) => {
                // **読めないことを黙って空一覧にしない**（`B-10`）。
                // 空と壊れているは別の事実で、後者は候補を1件も承認できない状態である。
                self.pending.observed.clear();
                self.pending.denied.clear();
                self.pending.declared_rows.clear();
                self.pending.outlooks.clear();
                self.pending.notes = vec![format!("policy.jsonを読めませんでした: {e}")];
                return;
            }
        };
        // 遷移先ごとの用意の見込み（`harness.exe`と同じ付与の関数・同じ承認台帳。ここで1回だけ読む）。
        let grants = crate::transition_destination::grants_on_this_machine(&workspace_root);
        self.pending.outlooks =
            crate::transition_destination::outlooks(&file, ENTRY_DOMAIN, &grants);
        let provisioned = crate::transition_destination::provisioned_names(&self.pending.outlooks);
        let workspace = workspace_root.to_string_lossy().into_owned();
        let declared = match DeclaredEdges::build(&file, &workspace, ENTRY_DOMAIN, &provisioned) {
            Ok(declared) => declared,
            Err(e) => {
                self.pending.observed.clear();
                self.pending.denied.clear();
                self.pending.declared_rows.clear();
                self.pending.notes = vec![format!("遷移の宣言を読めませんでした: {e}")];
                return;
            }
        };
        self.pending.declared_rows = declared.rows().to_vec();

        self.pending.observed =
            match harness_sandbox::tier2a::policy_learnd::observed::read_folded(&workspace_root) {
                Ok(read) => {
                    push_read_notes(&mut notes, "観測", read.dropped, read.skipped);
                    from_observations(&read.records, &declared)
                }
                Err(e) => {
                    notes.push(format!("observed.jsonlを読めませんでした: {e}"));
                    Vec::new()
                }
            };
        self.pending.denied =
            match harness_sandbox::tier2a::spawnd::transitions::read_folded(&workspace_root) {
                Ok(read) => {
                    push_read_notes(&mut notes, "拒否", read.dropped, read.skipped);
                    from_denials(&read.records, &declared)
                }
                Err(e) => {
                    notes.push(format!("pending.jsonlを読めませんでした: {e}"));
                    Vec::new()
                }
            };
        // 却下印。**読めなくても一覧は出す**——印は表示だけに効くので、空として扱えば
        // 保留中に多く出る側へ倒れるだけで、権限は1つも増えない。**ただし黙らせない**（`B-10`）。
        self.pending.dismissed = match transition_dismissed::load(&workspace_root) {
            Ok(dismissed) => dismissed,
            Err(e) => {
                notes.push(format!(
                    "却下印を読めないので、却下したものも保留中に出しています。\
                     直すか消すまで却下は保存できません（{e}）"
                ));
                Dismissals::default()
            }
        };
        self.pending.notes = notes;

        // 却下の予約のうち、**もう印の状態が予約どおりになっているもの**を落とす
        // （別のエディタが先に同じものを却下した・取り消した場合に、何も変えない予約が残らない）。
        let dismissed = self.pending.dismissed.clone();
        self.pending
            .dismiss
            .retain(|k| !dismissed.contains(ENTRY_DOMAIN, &k.exe, &k.argv));
        self.pending
            .undismiss
            .retain(|k| dismissed.contains(ENTRY_DOMAIN, &k.exe, &k.argv));

        // 消えた宣言への取り消し予約を落とす（別経路で消えていた場合に、消せない予約が残らない）。
        let alive: BTreeSet<EdgeRef> = self
            .pending
            .observed
            .iter()
            .chain(self.pending.denied.iter())
            .filter_map(Candidate::removal_ref)
            .collect();
        self.pending.remove.retain(|target| alive.contains(target));

        let rows = self.pending.visible().len();
        checkbox_tree::clamp_row(self.pending.row_mut(), rows);
    }

    /// 承認待ち画面のタブを巡回する（`F2`。`App::on_key`）。
    pub(crate) fn cycle_pending_tab(&mut self, backward: bool) {
        self.select_pending_tab(if backward {
            self.pending.tab.0.prev()
        } else {
            self.pending.tab.0.next()
        });
    }

    /// 承認待ち画面のタブを`tab`にする。**`F2`の巡回とタブのクリックが同じこれを通る**（入ったときの読み直しを
    /// 2か所に持たない。`tui::pointer`）。
    pub(crate) fn select_pending_tab(&mut self, tab: PendingTab) {
        self.pending.tab = Tab(tab);
        if tab.is_transition() {
            // **入るたびに読み直す。** 記録し直した後にタブへ来ても古い一覧が出ない。
            self.reload_transitions();
        }
    }

    pub(crate) fn on_transition_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        // 遷移先の欄に居る間は、文字キーを名前の入力に回す（FS/ネットタブのドメイン欄と同じ）。
        if self.pending.destination.focused {
            self.on_destination_key(key);
            return None;
        }
        let rows = self.pending.visible().len();
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => self.focus_destination(),
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => checkbox_tree::move_row(self.pending.row_mut(), rows, -1),
            KeyCode::Down => checkbox_tree::move_row(self.pending.row_mut(), rows, 1),
            KeyCode::PageUp => checkbox_tree::move_row(self.pending.row_mut(), rows, -10),
            KeyCode::PageDown => checkbox_tree::move_row(self.pending.row_mut(), rows, 10),
            KeyCode::Char(' ') => self.toggle_selected_transition(),
            // **却下は`x`、表示中をまとめて却下は`X`**（決定62「却下印の永続化を実装した」の(1)）。
            // `d`にしないのは、同じ`F2`の「FS/ネット」タブで`d`が「この行自身も選ぶ」＝**許可を
            // 足す向き**だからである。同じ画面のタブ間で向きが逆になるキーを増やさない
            // （決定62が挙げた問題2「`a`が画面によって正反対」と同じ形を作らない）。
            KeyCode::Char('x') => self.toggle_selected_dismissal(),
            KeyCode::Char('X') => self.reserve_visible_dismissals(),
            KeyCode::Char('u') => self.toggle_selected_argv_width(),
            KeyCode::Char('f') => {
                self.pending.filter = self.pending.filter.next();
                let rows = self.pending.visible().len();
                checkbox_tree::clamp_row(self.pending.row_mut(), rows);
                self.status = format!("表示: {}", self.pending.filter.label());
            }
            KeyCode::Char('r') => {
                self.reload_transitions();
                self.status = "遷移の候補を読み直しました".to_string();
            }
            KeyCode::Char('a') => self.request_transition_commit(),
            _ => {}
        }
        None
    }

    /// いま選ばれている候補を複製して返す（借用を切るため）。
    fn selected_candidate(&self) -> Option<Candidate> {
        self.pending
            .visible()
            .get(self.pending.row())
            .map(|c| (*c).clone())
    }

    /// 選択中の行を、承認する／取り消す／やめる。
    ///
    /// **1つのキーが向きを変える**のは、行が既に「許されているかどうか」を表しているためで、
    /// 候補画面の`Space`と同じ意味である（`[x]`＝いま許す／`[ ]`＝許さない）。
    fn toggle_selected_transition(&mut self) {
        let Some(candidate) = self.selected_candidate() else {
            // **何も起きない理由を言う**（`B-32`）。
            self.status = no_rows_message(self.pending.filter);
            return;
        };
        let key = CandidateKey::of(&candidate);
        match &candidate.declared {
            Declared::No | Declared::UnknownSourceDomain => {
                if self.pending.approve.remove(&key) {
                    self.pending.narrow.remove(&key);
                    self.status = format!("{} の承認をやめました", candidate.exe_file_name());
                } else {
                    // **「許す」と「許さない」を同時に予約させない。**
                    self.pending.dismiss.remove(&key);
                    self.pending.approve.insert(key);
                    // 却下済みの行を選び直したときは、確定で却下印も外れることを言う
                    // （[`Self::reserved_dismissals`]が承認した行の印を外す）。
                    self.status = if self.pending.is_dismissed(&candidate) {
                        format!(
                            "{} を許します（aで確定すると却下印も外れます）",
                            candidate.exe_file_name()
                        )
                    } else {
                        format!("{} を許します（aで確定）", candidate.exe_file_name())
                    };
                }
            }
            Declared::ByThisEdge { .. } => {
                let Some(target) = candidate.removal_ref() else {
                    return;
                };
                if self.pending.remove.remove(&target) {
                    self.status = format!("{} の取り消しをやめました", candidate.exe_file_name());
                } else {
                    self.pending.remove.insert(target);
                    self.status = format!(
                        "{} の宣言を取り消します（aで確定）",
                        candidate.exe_file_name()
                    );
                }
            }
            // **外せないものは、外せない理由を言う**（黙って何も起きないと壊れて見える）。
            Declared::ByAPattern { exe, .. } => {
                self.status = format!(
                    "パターンの宣言（{exe}）が覆っています。外すとこの行に見えていない\
                     プログラムの許可も消えるので、宣言画面（F3）で取り消してください"
                );
            }
            Declared::CwdMismatch { declared } => {
                self.status = format!(
                    "宣言はありますが、作業ディレクトリが違います（宣言: {declared}）。\
                     承認しても直りません"
                );
            }
            Declared::Ambiguous { matched } => {
                self.status = format!(
                    "パターンの宣言が{matched}本一致していて、どれを与えるか決められません。\
                     宣言画面（F3）で減らしてください"
                );
            }
        }
    }

    /// 選択中の行の**引数の広さ**を切り替える（任意の引数 ⇄ 観測された引数だけ）。
    fn toggle_selected_argv_width(&mut self) {
        let Some(candidate) = self.selected_candidate() else {
            self.status = no_rows_message(self.pending.filter);
            return;
        };
        let key = CandidateKey::of(&candidate);
        if !self.pending.approve.contains(&key) {
            self.status =
                "先にSpaceで選んでください（選んだ行の引数の広さを切り替えます）".to_string();
            return;
        }
        if self.pending.narrow.remove(&key) {
            self.status = format!("{}: 任意の引数を許します", candidate.exe_file_name());
            return;
        }
        if !candidate.can_narrow_to_this_argv() {
            // **切り詰めの疑いがある観測をリテラルにしない**（§5.1(6)）。
            // 書けてしまうと、二度と一致しない辺ができる。
            self.status = format!(
                "{}: この観測はコマンドラインが切り詰められている疑いがあるので、\
                 引数を絞れません",
                candidate.exe_file_name()
            );
            return;
        }
        self.pending.narrow.insert(key);
        self.status = format!(
            "{}: この引数のときだけ許します（{}）",
            candidate.exe_file_name(),
            candidate.argv
        );
    }

    /// 選択中の行を却下する／却下をやめる／却下を取り消す（**予約。書くのは`a`の確定**）。
    ///
    /// - 保留中の行: 却下を予約する（もう一度押すとやめる）。承認の予約が立っていたら外す
    /// - 却下済みの行: 却下の取り消しを予約する（保留中へ戻す。もう一度押すとやめる）
    /// - 宣言済みなど承認の対象でない行: 却下するものが無いので、**理由を言う**（`B-32`）
    fn toggle_selected_dismissal(&mut self) {
        let Some(candidate) = self.selected_candidate() else {
            self.status = no_rows_message(self.pending.filter);
            return;
        };
        let key = CandidateKey::of(&candidate);
        let name = candidate.exe_file_name().to_string();
        // 印があれば、宣言済みかどうかに関わらず外せる（宣言が後から入った行の古い印も消せる）。
        if self.pending.is_dismissed(&candidate) {
            if self.pending.undismiss.remove(&key) {
                self.status = format!("{name} の却下の取り消しをやめました");
            } else {
                self.pending.undismiss.insert(key);
                self.status = format!("{name} の却下を取り消します（aで確定すると保留中へ戻ります）");
            }
            return;
        }
        if !candidate.is_approvable() {
            self.status = if candidate.is_removable() {
                format!("{name} は宣言済みなので却下できません（許可を外すなら Space で取り消しを予約）")
            } else {
                format!("{name} は承認の対象ではないので、却下するものがありません")
            };
            return;
        }
        if self.pending.dismiss.remove(&key) {
            self.status = format!("{name} の却下をやめました");
            return;
        }
        // **「許す」と「許さない」を同時に予約させない。**
        let was_approving = self.pending.approve.remove(&key);
        self.pending.narrow.remove(&key);
        self.pending.dismiss.insert(key);
        self.status = format!(
            "{name} を却下します（aで確定。f で「却下済み」にすると見られ、選び直せます）{}",
            if was_approving {
                "。承認の予約は外しました"
            } else {
                ""
            }
        );
    }

    /// 表示中の保留中の行を**まとめて**却下する（予約）。
    ///
    /// **一括却下は許し、一括承認は許さない**（決定62。決定51の非対称——減らす向きを面倒にすると
    /// 安全な回復手段が失われ、増やす向きを楽にすると読まずに与えることになる）。
    /// 却下は権限を増やす向きではない。
    ///
    /// **承認を予約している行は飛ばす**（ユーザーが明示的に「許す」と選んだものを、まとめての
    /// 操作で黙って裏返さない）。飛ばした件数は言う。
    fn reserve_visible_dismissals(&mut self) {
        let targets: Vec<CandidateKey> = self
            .pending
            .visible()
            .into_iter()
            .filter(|c| c.is_approvable() && !self.pending.is_dismissed(c))
            .map(CandidateKey::of)
            .collect();
        let mut added = 0usize;
        let mut skipped_approving = 0usize;
        for key in targets {
            if self.pending.approve.contains(&key) {
                skipped_approving += 1;
                continue;
            }
            if self.pending.dismiss.insert(key) {
                added += 1;
            }
        }
        self.status = match (added, skipped_approving) {
            (0, 0) => "表示中に、却下できる保留中の候補がありません".to_string(),
            (added, 0) => {
                format!("表示中の保留中 {added}件を却下します（aで確定 / x で個別に戻せます）")
            }
            (added, skipped) => format!(
                "表示中の保留中 {added}件を却下します（aで確定 / x で個別に戻せます）。\
                 承認を予約中の{skipped}件は除きました"
            ),
        };
    }
}

/// 読み取りで落ちたもの・あふれたものを注記にする。**0件なら何も言わない。**
fn push_read_notes(notes: &mut Vec<String>, what: &str, dropped: u64, skipped: usize) {
    if dropped > 0 {
        notes.push(format!(
            "{what}: 種類が多すぎて覚えきれなかったぶんが{dropped}回ぶんあります\
             （その生成は一覧に出ていません）"
        ));
    }
    if skipped > 0 {
        notes.push(format!("{what}: 読めなかった行が{skipped}行あります"));
    }
}

/// 行が1つも無いときに言うこと。**フィルタで隠れているのか、本当に無いのかを区別する**（`B-09`）。
fn no_rows_message(filter: PendingFilter) -> String {
    match filter {
        PendingFilter::Pending => "保留中の候補がありません（f で切り替えると、却下したもの・\
                                   宣言済みも出ます）"
            .to_string(),
        PendingFilter::Dismissed => {
            "却下した候補はありません（保留中の行で x を押すと、ここへ移ります）".to_string()
        }
        PendingFilter::All => {
            "候補がありません（パス1で記録すると、起きたプロセスがここへ出ます）".to_string()
        }
    }
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod transition_tests;
