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
//! # 遷移元ドメインは固定である
//!
//! [`ENTRY_DOMAIN`]（`workspace-shell`）を使う。**記録画面のドメイン欄とは混ぜない**
//! ——あちらは「パス2で記録中のドメイン名」で由来が違い、入口ドメインが固定なのは
//! `run_shell`経路だけである（`policy_file::ENTRY_DOMAIN`のdoc）。混ぜると、
//! **Daemonが一度も見ないドメインへ遷移を書く**ことになる。
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
//! - **描画**: [`super::transition_screen`]

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use harness_policy::policy_file::{self, ENTRY_DOMAIN};

use crate::transition_approve::{self, EdgeRef, TransitionRequest};
use crate::transition_candidates::{
    from_denials, from_observations, Candidate, Declared, DeclaredEdges, Startable,
};
use crate::tui::checkbox_tree;
use crate::tui::state::{Action, App, Confirm, Modal, Screen};

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

    fn next(self) -> Self {
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

/// 一覧に何を出すか。**件数を必ず見出しに出す**こと——「無い」と「隠している」が
/// 区別できないと、黙って捨てているのと同じである（`B-09`、決定29と同じ形）。
///
/// # 却下済みの段がまだ無い
///
/// 決定62は「保留中 → 却下済み → 全部」の3段を巡回すると定めているが、
/// **却下印（`dismissed.json`）の永続化はまだ実装していない**（段階⑦の残り）。
/// 無い段を空で出すと「却下したものが消えた」と読まれるので、**段そのものを置かない**。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PendingFilter {
    /// まだ宣言されていないものだけ。**既定はこちら**——一覧を開いた人が最初に見たいのは
    /// 「まだ決めていないもの」である。
    #[default]
    Pending,
    /// 宣言済みも含めて全部。
    All,
}

impl PendingFilter {
    pub fn label(self) -> &'static str {
        match self {
            PendingFilter::Pending => "保留中のみ",
            PendingFilter::All => "全部",
        }
    }

    fn next(self) -> Self {
        match self {
            PendingFilter::Pending => PendingFilter::All,
            PendingFilter::All => PendingFilter::Pending,
        }
    }
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
    fn of(candidate: &Candidate) -> Self {
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
                PendingFilter::Pending => c.is_approvable(),
                PendingFilter::All => true,
            })
            .collect()
    }

    /// いま選ばれている行の位置（タブごとに覚える）。
    pub fn row(&self) -> usize {
        match self.tab.0 {
            PendingTab::TransitionsDenied => self.denied_row,
            _ => self.observed_row,
        }
    }

    fn row_mut(&mut self) -> &mut usize {
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
    pub fn counts(&self, tab: PendingTab) -> (usize, usize) {
        let all = match tab {
            PendingTab::TransitionsDenied => &self.denied,
            _ => &self.observed,
        };
        (all.iter().filter(|c| c.is_approvable()).count(), all.len())
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
                self.pending.notes = vec![format!("policy.jsonを読めませんでした: {e}")];
                return;
            }
        };
        let workspace = workspace_root.to_string_lossy().into_owned();
        let declared = match DeclaredEdges::build(&file, &workspace, ENTRY_DOMAIN) {
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
        self.pending.notes = notes;

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

    /// 承認待ち画面のタブを巡回する。**どのタブでも同じキー**（`Tab`/`Shift+Tab`）。
    pub(crate) fn cycle_pending_tab(&mut self, backward: bool) {
        self.pending.tab = Tab(if backward {
            self.pending.tab.0.prev()
        } else {
            self.pending.tab.0.next()
        });
        if self.pending.tab.0.is_transition() {
            // **入るたびに読み直す。** 記録し直した後にタブへ来ても古い一覧が出ない。
            self.reload_transitions();
        }
    }

    pub(crate) fn on_transition_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        let rows = self.pending.visible().len();
        match key.code {
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => checkbox_tree::move_row(self.pending.row_mut(), rows, -1),
            KeyCode::Down => checkbox_tree::move_row(self.pending.row_mut(), rows, 1),
            KeyCode::PageUp => checkbox_tree::move_row(self.pending.row_mut(), rows, -10),
            KeyCode::PageDown => checkbox_tree::move_row(self.pending.row_mut(), rows, 10),
            KeyCode::Char(' ') => self.toggle_selected_transition(),
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
                    self.pending.approve.insert(key);
                    self.status = format!("{} を許します（aで確定）", candidate.exe_file_name());
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

    /// 承認・取り消しの内容を組み立てて確認ダイアログを出す（**まだ書かない**）。
    fn request_transition_commit(&mut self) {
        let (approve, remove) = self.reserved_edges();
        if approve.is_empty() && remove.is_empty() {
            self.status =
                "Spaceで選んでから a を押してください（選んだものが1件もありません）".to_string();
            return;
        }
        let request = TransitionRequest {
            workspace_root: &self.workspace_root,
            from_domain: ENTRY_DOMAIN,
            approve: &approve,
            remove: &remove,
            record_session: None,
            now_unix_ms: now_unix_ms(),
        };
        let plan = match transition_approve::plan(&request) {
            Ok(plan) => plan,
            Err(e) => {
                self.modal = Some(Modal {
                    title: "書けません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        };

        let mut lines = vec![
            format!("{}:", policy_file::path(&self.workspace_root).display()),
            format!("遷移元ドメイン: {ENTRY_DOMAIN}"),
            String::new(),
        ];
        if !plan.added.is_empty() {
            lines.push(format!("許す遷移 {}件:", plan.added.len()));
            for edge in &plan.added {
                lines.push(format!(
                    "  + {} {} → {}",
                    edge.exe,
                    edge.argv.display(),
                    plan.to_domain
                ));
                // **書く直前に、その綴りが起こせないことを言う。**
                // 一覧でも出しているが、ここは**取り消しの効かない操作の直前**なので繰り返す。
                if let Some(note) = Startable::of(&edge.exe).note() {
                    lines.push(format!("      ⚠ {note}"));
                }
            }
        }
        if !plan.removed.is_empty() {
            lines.push(format!("取り消す遷移 {}件:", plan.removed.len()));
            for edge in &plan.removed {
                lines.push(format!("  - {} {}", edge.exe, edge.argv.display()));
            }
        }
        if !plan.already_declared.is_empty() {
            lines.push(format!(
                "既に宣言されていて増えないもの: {}件",
                plan.already_declared.len()
            ));
        }
        if !plan.not_found.is_empty() {
            lines.push(format!(
                "宣言に無くて消えないもの: {}件",
                plan.not_found.len()
            ));
        }
        lines.push(String::new());
        // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
        lines.extend(transition_approve::ACE_NOTICE.lines().map(str::to_string));
        if !plan.added.is_empty() {
            lines.push(String::new());
            lines.extend(
                transition_approve::SELF_LOOP_NOTICE
                    .lines()
                    .map(str::to_string),
            );
        }

        self.modal = Some(Modal {
            title: format!(
                "この{}件を書きますか？",
                plan.added.len() + plan.removed.len()
            ),
            lines,
            confirm: Confirm::Transition,
        });
        self.modal_scroll = 0;
    }

    /// 確認後に実際に書く。
    ///
    /// **`plan`は作り直す**——ダイアログを見ている間に`policy.json`が別の経路
    /// （CLI・手編集）で変わっていた場合に、古い読み込み結果で上書きしないため
    /// （候補画面・宣言画面と同じ作法）。
    pub(crate) fn commit_transition(&mut self) {
        let (approve, remove) = self.reserved_edges();
        let request = TransitionRequest {
            workspace_root: &self.workspace_root,
            from_domain: ENTRY_DOMAIN,
            approve: &approve,
            remove: &remove,
            record_session: None,
            now_unix_ms: now_unix_ms(),
        };
        let plan = match transition_approve::plan(&request) {
            Ok(plan) => plan,
            Err(e) => {
                self.status = format!("書けませんでした: {e}");
                return;
            }
        };
        match transition_approve::commit(&self.workspace_root, &plan) {
            Ok(true) => {
                self.status = format!(
                    "遷移の宣言を更新しました（許可 {}件 / 取り消し {}件。ACLは変わりません）",
                    plan.added.len(),
                    plan.removed.len()
                );
                self.pending.approve.clear();
                self.pending.narrow.clear();
                self.pending.remove.clear();
                self.reload_transitions();
            }
            Ok(false) => {
                self.status =
                    "変わるものがありませんでした（policy.jsonは書いていません）".to_string();
                self.pending.approve.clear();
                self.pending.narrow.clear();
                self.pending.remove.clear();
                self.reload_transitions();
            }
            Err(e) => self.status = format!("policy.jsonを書けませんでした: {e}"),
        }
    }

    /// 予約から、実際に書く／消す辺を組み立てる。
    ///
    /// **予約は候補の同一性で持ち、辺はここで作る**——引数を絞るかどうかは辺の形を変えるが、
    /// ユーザーが指している行は同じだからである（[`CandidateKey`]のdoc）。
    fn reserved_edges(&self) -> (Vec<EdgeRef>, Vec<EdgeRef>) {
        let approve = self
            .pending
            .observed
            .iter()
            .chain(self.pending.denied.iter())
            .filter(|c| self.pending.is_reserved(c))
            .map(|c| c.approval_ref(self.pending.is_narrowed(c)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let remove = self.pending.remove.iter().cloned().collect();
        (approve, remove)
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
        PendingFilter::Pending => {
            "保留中の候補がありません（f で「全部」にすると宣言済みも出ます）".to_string()
        }
        PendingFilter::All => {
            "候補がありません（パス1で記録すると、起きたプロセスがここへ出ます）".to_string()
        }
    }
}

/// 承認に添える時刻。**測定にも判定にも使わない**（由来の記録だけ）。
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod transition_tests;
