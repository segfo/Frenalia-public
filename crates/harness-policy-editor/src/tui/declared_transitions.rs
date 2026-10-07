//! 宣言画面（`F3`）の**遷移のタブ**——ドメインごとに、書かれている遷移の辺と遷移の形（届く範囲の権限・起動で
//! 届くドメイン・最長の連鎖）を見せ、辺を取り消す（2026-10-05、`plans/position-domains/P4.md`のP4.2、決定65 Q12）。
//!
//! ```text
//!   │  ファイル・通信    遷移   F3 で切替                                                    │
//!   │ [x] [workspace-shell]  届く範囲: ファイル 1件・通信 0件 ／ 起動で届く: pwsh ／ 最長の連鎖: 1段（…） │
//!   │   [x] pwsh.exe   (any arguments)   → pwsh  起こせる                                      │
//!   │   [ ] cmd.exe    (any arguments)   → workspace-shell  起こせる  ⟲ 自己ループ辺（…）  ← 取り消します │
//! ```
//!
//! # 何のためにあるのか
//!
//! 遷移の宣言（`policy.json`の各ドメインの`process.transitions`）を見られる画面は、承認待ちの遷移タブが入口の
//! ドメイン（`workspace-shell`）の辺を「宣言済み」として出すところだけだった。**別のドメインの辺・そのドメインへ
//! 遷移すると何ができるか・何段まで連鎖するか・手で書いた自己ループ辺**はどこにも出なかった。記録した木の位置ごとに
//! ドメインを分けると（決定65(1)）ドメインと辺が記録のたびに増えるので、宣言を1本ずつ読んで頭の中で辿らせない。
//!
//! # 判定はしない（並べるだけ）
//!
//! - 辺の行は**モデル向けのツールと同じ一覧**（`transition_listing::rows`）。2つ作るとモデルとユーザーで見えるものがずれる
//! - 遷移の形は`transition::shape`、自己ループ辺は`transition::self_loops`（P3c）
//! - 「いま起こせるか」の見込みは承認待ちの遷移タブと同じ表（`transition_destination::outlooks`）。遷移元は入口の
//!   ドメインで1回だけ作る——用意されるかは遷移先の宣言で決まり、遷移元に依らない（自己ループは表を引かずに起こせる）。
//!   入口のドメインは`harness.exe`が遷移先として用意しない（`PolicyFile::transition_target_domains`）ので、そこへ戻る
//!   辺は起こせない
//!
//! # 取り消しの指し方は、書かれている辺そのもの
//!
//! `(遷移元, 辺の中身)`で予約し、確定で等しい辺を消す（`transition_approve::plan_removals`）。手で書いた辺には
//! パターン・作業ディレクトリ・環境変数の差分があり、承認待ちの指し方（`EdgeRef`＝リテラルの exe と引数）では
//! 指せない。位置（添字）では指さない——読み直しで位置がずれる。
//!
//! # 遷移の検査に落ちる`policy.json`も一覧にする
//!
//! `policy_file::load`は検査に落ちるファイルを断るので、それしか無いとエディタのどの画面からも見えず、直す手段が
//! 無い。この画面は`policy_file::load_for_repair`で読み、落ちた理由を注記に出す。検査に落ちる辺を取り消せば書ける
//! （取り消した後も落ちるなら`policy_file::save`が断り、何も書かない）。
//!
//! # キー（決定62: 同じ画面のタブで同じキーに逆の意味を持たせない）
//!
//! `Space`（辺の行＝その辺の取り消しを予約／やめる。ドメインの見出し＝そのドメインの辺をまとめて。決定51で一括の
//! 取り消しは許す）・`s`（ドメインの見出し＝Strict の印の付け外しを予約。P5.5、決定66の追記）・`a`（確認ダイアログ）・
//! `r`（読み直し）・`Esc`（記録画面へ）・`F3`（タブを戻す。`tui::state`）。
//! **`A`・`y`・`c`・`R`はファイル・通信のタブのキーなので、ここでは何もせず理由を言う**——ここで別の意味を持たせると、
//! 決定62が挙げた問題2（`a`が画面によって正反対）と同じ形を同じ画面の中に作る。
//!
//! # 限界
//!
//! - ACLは変わらない（遷移の宣言は付与の対象を持たない。`transition_approve::ACE_NOTICE`）
//! - 辺を足す・書き換える操作は無い。足すのは承認待ち（`F2`）の遷移タブで、書き換えは取り消してから足し直す
//! - 「起こせる」は`harness.exe`が次に起動したときの見込みで、いま動いているセッションの事実ではない
//! - 描画は[`super::declared_transitions_screen`]

use std::collections::{BTreeMap, BTreeSet};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::transition::{
    self, ArgvMatcher, ExeMatcher, GraphError, GraphInput, TransitionEdge, TransitionShape,
};
use harness_policy::transition_listing::{self, Row};

use crate::transition_approve::{self, RemovalPlan, StrictChange};
use crate::transition_destination::Outlook;
use crate::tui::checkbox_tree;
use crate::tui::state::{Action, App, Confirm, Modal, Screen};
use crate::tui::transition_commit::now_unix_ms;

/// 宣言画面（`F3`）のタブ。`F3`をもう一度押すと巡回する（決定65 Q12。承認待ちの`F2`と同じ作り）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeclaredTab {
    /// 承認済みのファイル・通信の宣言（従来の宣言画面。`tui::declared`）。**既定はこちら**——画面を開いた人が、
    /// いきなり見慣れないタブに居ることにならない（承認待ちのタブの既定と同じ）。
    #[default]
    Declarations,
    /// 遷移の宣言（このモジュール）。
    Transitions,
}

impl DeclaredTab {
    pub fn label(self) -> &'static str {
        match self {
            DeclaredTab::Declarations => "ファイル・通信",
            DeclaredTab::Transitions => "遷移",
        }
    }

    /// `F3`で巡回する次のタブ（タブの行もこの順に並べる。`tui::sub_tabs`）。
    pub(crate) fn next(self) -> Self {
        match self {
            DeclaredTab::Declarations => DeclaredTab::Transitions,
            DeclaredTab::Transitions => DeclaredTab::Declarations,
        }
    }

    pub fn is_transitions(self) -> bool {
        matches!(self, DeclaredTab::Transitions)
    }
}

/// 予約の鍵にする辺の中身（`TransitionEdge`は`Ord`を持たないので、全部の欄を書き出した綴りで並べる）。
///
/// **比べるのは中身**で、同じ中身の辺は同じ鍵になる——確定はそれを全部消す
/// （`transition_approve::apply_removals`）。綴りは`Debug`の出力（欄は文字列・列挙・`Option`・`BTreeMap`だけで、
/// 決まった順に出る）。このプロセスの中で比べるだけで、保存しない。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransitionEdgeKey(String);

impl TransitionEdgeKey {
    pub fn of(edge: &TransitionEdge) -> Self {
        Self(format!("{edge:?}"))
    }
}

/// 遷移元1つぶん（ドメインの見出しの行と、その辺の行）。
#[derive(Debug, Clone)]
pub struct DomainTransitions {
    pub name: String,
    /// [P5.5] いまの Strict の印（`policy.json`のドメインの`strict`。決定66の追記）。
    pub strict: bool,
    /// そのドメインから見た遷移の形（P3c の`shape`。検査に落ちる宣言でも答える）。
    pub shape: TransitionShape,
    /// 宣言の順。
    pub edges: Vec<DeclaredEdgeRow>,
}

/// 辺1本の行。
#[derive(Debug, Clone)]
pub struct DeclaredEdgeRow {
    /// 書かれている辺そのもの（取り消しはこれと等しい辺を消す）。
    pub edge: TransitionEdge,
    /// モデル向けのツールと同じ一覧の1行（`transition_listing::rows`。並びは`transitions`と同じ）。
    pub row: Row,
    /// 遷移先が遷移元と同じ辺（自己ループ辺。`transition::self_loops`の答え）。
    pub self_loop: bool,
}

/// 一覧の1行。並びはドメインの名前の順で、見出しの直後にそのドメインの辺が宣言の順に続く。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedRow {
    Domain(usize),
    Edge { domain: usize, edge: usize },
}

/// 宣言画面のタブと、遷移のタブの状態（`App::declared_transitions`）。
#[derive(Debug, Default)]
pub struct DeclaredTransitionsState {
    /// いまのタブ。**他の画面へ行っても覚えている**（承認待ちの`PendingState::tab`と同じ）。
    pub tab: DeclaredTab,
    /// ドメインの名前の順。**[`App::reload_declared_transitions`]が作り直す**（描画のたびに読まない）。
    pub domains: Vec<DomainTransitions>,
    /// 一覧（[`Self::rows`]）での選択位置。
    pub row: usize,
    /// 取り消しの予約（遷移元と、書かれている辺の中身）。
    pub remove: BTreeSet<(String, TransitionEdgeKey)>,
    /// [P5.5] Strict の印の付け外しの予約（ドメイン名 → 付けるなら真）。いまの印と違う値だけが入る。
    pub strict: BTreeMap<String, bool>,
    /// 読めなかった・検査に落ちた事実。**黙らせない**（`B-10`）。
    pub notes: Vec<String>,
    /// 一覧の表示開始位置（フレームをまたいで保つ。`App::declared_list_offset`のdoc）。
    pub list_offset: usize,
    /// 遷移先ごとの用意の見込み（起こせない辺に理由を添える。読み直すたびに作り直す）。
    pub outlooks: BTreeMap<String, Outlook>,
}

impl DeclaredTransitionsState {
    /// 一覧の行（ドメインの見出しと辺）。
    pub fn rows(&self) -> Vec<ListedRow> {
        let mut rows = Vec::new();
        for (domain, entry) in self.domains.iter().enumerate() {
            rows.push(ListedRow::Domain(domain));
            rows.extend((0..entry.edges.len()).map(|edge| ListedRow::Edge { domain, edge }));
        }
        rows
    }

    /// 全ドメインの辺の本数。
    pub fn edge_count(&self) -> usize {
        self.domains.iter().map(|d| d.edges.len()).sum()
    }

    /// この辺は取り消しを予約されているか。
    pub fn is_reserved(&self, domain: &str, edge: &TransitionEdge) -> bool {
        self.remove
            .contains(&(domain.to_string(), TransitionEdgeKey::of(edge)))
    }

    /// [P5.5] 予約している Strict の印の付け外し（ドメインの名前の順）。確定はこれも`plan_removals`へ渡す。
    pub(crate) fn reserved_strict(&self) -> Vec<StrictChange> {
        self.strict
            .iter()
            .map(|(name, strict)| (name.clone(), *strict))
            .collect()
    }

    /// 予約している辺（一覧の順。同じ中身は1回だけ）。確定はこれを`plan_removals`へ渡す。
    pub(crate) fn reserved_edges(&self) -> Vec<(String, TransitionEdge)> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for domain in &self.domains {
            for row in &domain.edges {
                let key = (domain.name.clone(), TransitionEdgeKey::of(&row.edge));
                if self.remove.contains(&key) && seen.insert(key) {
                    out.push((domain.name.clone(), row.edge.clone()));
                }
            }
        }
        out
    }

    /// 起こせない辺の理由（起こせるなら`None`）。**一覧に出ているのに撃つと断られる、を黙らせない**
    /// （承認待ちの遷移タブの「起こせない」と同じ表）。
    pub fn not_runnable_reason(&self, row: &Row) -> Option<String> {
        if row.runnable_now {
            return None;
        }
        if row.to_domain == ENTRY_DOMAIN {
            return Some("入口のドメインは遷移先として用意されません".to_string());
        }
        Some(match self.outlooks.get(&row.to_domain) {
            Some(outlook) => outlook.short_label(),
            None => "遷移先のドメインが policy.json にありません".to_string(),
        })
    }

    fn clear_listing(&mut self, note: String) {
        self.domains.clear();
        self.outlooks.clear();
        self.notes = vec![note];
        self.row = 0;
    }
}

/// 辺1本を確認ダイアログと説明欄に出す綴り（実行ファイルは全パス。作業ディレクトリ・環境変数の差分も言う）。
pub(super) fn edge_text(edge: &TransitionEdge) -> String {
    let exe = match &edge.exe {
        ExeMatcher::Literal(value) => value.clone(),
        ExeMatcher::Pattern(pattern) => format!("{pattern}（パターン）"),
    };
    let argv = match &edge.argv {
        ArgvMatcher::Literal(value) => value.clone(),
        ArgvMatcher::Pattern(pattern) => format!("{pattern}（パターン）"),
        ArgvMatcher::Any(_) => transition_listing::ANY_ARGV.to_string(),
    };
    let mut text = format!("{exe} {argv} → {}", edge.to);
    if let Some(cwd) = &edge.cwd {
        text.push_str(&format!("（作業ディレクトリ: {cwd}）"));
    }
    if edge.env.as_ref().is_some_and(|env| !env.is_empty()) {
        text.push_str("（環境変数の差分あり）");
    }
    text.push_str(crate::exposure_view::output_suffix(edge.output));
    text
}

/// `policy.json`の全ドメインの一覧を作る。**判定は呼ぶだけ**（モジュールdoc）。落ちるのは同じ名前のドメインが
/// 2つあるとき（`GraphError::DuplicateDomain`）だけ。
fn listing(
    input: &GraphInput<'_>,
    provisioned: &BTreeSet<String>,
) -> Result<Vec<DomainTransitions>, GraphError> {
    let loops: BTreeSet<(String, usize)> = transition::self_loops(input)
        .into_iter()
        .map(|l| (l.domain, l.edge_index))
        .collect();
    let mut views: Vec<_> = input.domains.iter().collect();
    views.sort_by(|a, b| a.name.cmp(b.name));
    views
        .into_iter()
        .map(|view| {
            let rows = transition_listing::rows(input, view.name, provisioned)?;
            let edges = view
                .process
                .transitions
                .iter()
                .zip(rows)
                .enumerate()
                .map(|(index, (edge, row))| DeclaredEdgeRow {
                    edge: edge.clone(),
                    row,
                    self_loop: loops.contains(&(view.name.to_string(), index)),
                })
                .collect();
            Ok(DomainTransitions {
                name: view.name.to_string(),
                strict: view.strict,
                shape: transition::shape(input, view.name)?,
                edges,
            })
        })
        .collect()
}

/// ファイル・通信のタブにしか効かないキーを遷移のタブで押したときの理由（モジュールdoc「キー」）。
fn files_tab_only(letter: char) -> String {
    let what = match letter {
        'A' => "全件の取り消し",
        'y' => "このマシンでの承認（遷移の宣言にはありません——ACLが変わらないため）",
        _ => "付け替え（辺を変えるときは、取り消してから承認待ち〔F2〕の遷移タブで承認し直してください）",
    };
    format!(
        "{letter} はファイル・通信のタブのキー（{what}）で、遷移のタブでは何もしません。\
         ドメインの見出しの行で Space を押すと、そのドメインの辺をまとめて取り消しを予約できます"
    )
}

impl App {
    /// `F3`。**宣言画面に居ればタブを回し**、他の画面からなら今までどおり入る（最後に居たタブへ。決定65 Q12、
    /// 承認待ちの`F2`と同じ作り）。
    pub(crate) fn press_f3(&mut self) {
        if self.screen == Screen::Declared {
            self.select_declared_tab(self.declared_transitions.tab.next());
        } else {
            self.screen = Screen::Declared;
            self.on_enter_screen();
        }
    }

    /// 宣言画面のタブを`tab`にする。**`F3`の巡回とタブのクリックが同じこれを通る**（`tui::pointer`）。
    /// 入るたびに読み直す（画面へ入るのと同じ準備＝`App::on_enter_screen`を通す。別の経路で変わった宣言を古いまま
    /// 出さない）。
    pub(crate) fn select_declared_tab(&mut self, tab: DeclaredTab) {
        self.declared_transitions.tab = tab;
        self.on_enter_screen();
    }

    /// `policy.json`を読み直して遷移の一覧を作る。**取り消しの予約は保つ**——読み直しは表示を最新にする操作で、
    /// ユーザーの意思を捨てる操作ではない（`reload_declared`と同じ作法）。ただし**もう無い辺への予約**は落とす。
    pub fn reload_declared_transitions(&mut self) {
        let workspace_root = self.workspace_root.clone();
        let state = &mut self.declared_transitions;
        let (file, rejections) = match policy_file::load_for_repair(&workspace_root) {
            Ok(read) => read,
            Err(e) => {
                // **読めないことを黙って空一覧にしない**（`B-10`）。空と壊れているは別の事実である。
                state.clear_listing(format!("policy.jsonを読めませんでした: {e}"));
                return;
            }
        };
        let workspace = workspace_root.to_string_lossy().into_owned();
        let input = file.transition_graph_input(Some(&workspace), &[]);
        // 用意の見込み（`harness.exe`と同じ付与の関数・同じ承認台帳。ここで1回だけ読む）。
        let checks = crate::transition_destination::MachineChecks::for_workspace(&workspace_root);
        state.outlooks = crate::transition_destination::outlooks(&file, ENTRY_DOMAIN, &checks);
        let provisioned = crate::transition_destination::provisioned_names(&state.outlooks);
        state.domains = match listing(&input, &provisioned) {
            Ok(domains) => domains,
            Err(e) => {
                state.clear_listing(format!("遷移の宣言を読めませんでした: {e}"));
                return;
            }
        };
        state.notes.clear();
        if !rejections.is_empty() {
            state.notes.push(format!(
                "この policy.json は遷移の検査に落ちます（harness.exe もこのエディタの他の画面も読めません。\
                 落ちている辺を取り消すと直せます）: {}",
                rejections.join("; ")
            ));
        }
        let alive: BTreeSet<(String, TransitionEdgeKey)> = state
            .domains
            .iter()
            .flat_map(|d| {
                d.edges
                    .iter()
                    .map(|e| (d.name.clone(), TransitionEdgeKey::of(&e.edge)))
            })
            .collect();
        state.remove.retain(|key| alive.contains(key));
        // 印の予約も、もう無いドメインと、いまの印と同じになったもの（別の経路で付け替わった）は落とす。
        let marks: BTreeMap<&str, bool> = state
            .domains
            .iter()
            .map(|d| (d.name.as_str(), d.strict))
            .collect();
        state
            .strict
            .retain(|name, strict| marks.get(name.as_str()).is_some_and(|now| now != strict));
        let rows = state.rows().len();
        checkbox_tree::clamp_row(&mut state.row, rows);
    }

    pub(crate) fn on_declared_transition_key(&mut self, key: KeyEvent) -> Option<Action> {
        // `Ctrl`・`Alt`付きの文字は、素の文字の操作ではない（BUG-212）。
        if key.kind != KeyEventKind::Press || harness_term::is_chorded_char(&key) {
            return None;
        }
        let rows = self.declared_transitions.rows().len();
        let row = &mut self.declared_transitions.row;
        match key.code {
            // 記録画面へ戻る（他の画面の`Esc`と対）。2回連続なら終了するが、その判定は`on_key`側。
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => checkbox_tree::move_row(row, rows, -1),
            KeyCode::Down => checkbox_tree::move_row(row, rows, 1),
            KeyCode::PageUp => checkbox_tree::move_row(row, rows, -10),
            KeyCode::PageDown => checkbox_tree::move_row(row, rows, 10),
            KeyCode::Char(' ') => self.toggle_declared_transition_removal(),
            KeyCode::Char('s') => self.toggle_declared_strict(),
            KeyCode::Char('a') => self.request_declared_transition_removals(),
            KeyCode::Char('r') => {
                self.reload_declared_transitions();
                self.status = "遷移の宣言を読み直しました".to_string();
            }
            KeyCode::Char(letter @ ('A' | 'y' | 'c' | 'R')) => self.status = files_tab_only(letter),
            _ => {}
        }
        None
    }

    /// 選択中の行の取り消しを予約する／やめる。見出しの行ならそのドメインの辺をまとめて（ファイル・通信のタブの
    /// `Space`と同じく、1本も予約していなければ全部を予約し、そうでなければ全部をやめる）。
    fn toggle_declared_transition_removal(&mut self) {
        let state = &self.declared_transitions;
        let Some(selected) = state.rows().get(state.row).copied() else {
            // **何も起きない理由を言う**（`B-32`）。
            self.status =
                "遷移の宣言がありません（policy.json にドメインがありません）".to_string();
            return;
        };
        let key_of = |name: &str, row: &DeclaredEdgeRow| {
            (name.to_string(), TransitionEdgeKey::of(&row.edge))
        };
        let (label, targets) = match selected {
            ListedRow::Edge { domain, edge } => {
                let entry = &state.domains[domain];
                let row = &entry.edges[edge];
                (
                    format!("遷移元 {} の辺「{}」", entry.name, edge_text(&row.edge)),
                    vec![key_of(&entry.name, row)],
                )
            }
            ListedRow::Domain(domain) => {
                let entry = &state.domains[domain];
                if entry.edges.is_empty() {
                    self.status = format!(
                        "{} には辺がありません（取り消すものがありません）",
                        entry.name
                    );
                    return;
                }
                (
                    format!("遷移元 {} の辺 {}本", entry.name, entry.edges.len()),
                    entry
                        .edges
                        .iter()
                        .map(|row| key_of(&entry.name, row))
                        .collect(),
                )
            }
        };
        let remove = &mut self.declared_transitions.remove;
        if targets.iter().all(|target| !remove.contains(target)) {
            remove.extend(targets);
            self.status = format!("{label}を取り消します（aで確定）");
        } else {
            for target in &targets {
                remove.remove(target);
            }
            self.status = format!("{label}の取り消しをやめました");
        }
    }

    /// [P5.5] 選択中のドメインの見出しで、Strict の印の付け外しを予約する／やめる（`s`。決定66の追記）。
    ///
    /// **付けると入る辺が検査に落ちるなら予約しない**——判定器の理由を言う（`transition_approve::strict_rejections`。
    /// このエディタは入力を固定した辺を書かないので、エディタが書いた辺が入るドメインには付けられない）。
    fn toggle_declared_strict(&mut self) {
        let state = &self.declared_transitions;
        let Some(ListedRow::Domain(domain)) = state.rows().get(state.row).copied() else {
            self.status = "s はドメインの見出しの行で押してください（Strict はドメインに付ける印で、そのドメインへ\
                           入る辺に効きます）"
                .to_string();
            return;
        };
        let (name, current) = (state.domains[domain].name.clone(), state.domains[domain].strict);
        if name == ENTRY_DOMAIN {
            self.status = format!(
                "{name} は入口のドメインで、遷移先になりません（harness.exe が遷移先として用意しない）。\
                 Strict の印は意味を持たないので付けません"
            );
            return;
        }
        if self.declared_transitions.strict.remove(&name).is_some() {
            self.status = format!("{name} の Strict の付け外しをやめました");
            return;
        }
        let wanted = !current;
        let mut changes = self.declared_transitions.reserved_strict();
        changes.push((name.clone(), wanted));
        let removals = self.declared_transitions.reserved_edges();
        match transition_approve::strict_rejections(&self.workspace_root, &removals, &changes) {
            Ok(new) if new.is_empty() => {
                self.declared_transitions.strict.insert(name.clone(), wanted);
                self.status = if wanted {
                    format!(
                        "{name} に Strict を付けます（aで確定）。入る辺は入力を固定しないと書けなくなり、\
                         呼び出し元はその辺の子を操れなくなります"
                    )
                } else {
                    format!(
                        "{name} の Strict を外します（aで確定）。入る辺は普通のモードになり、呼び出し元は子を通して\
                         {name} の権限を使えるようになります（確定の画面に出ます）"
                    )
                };
            }
            Ok(new) => {
                let what = if wanted { "付けられません" } else { "外せません" };
                self.status = format!(
                    "{name} に Strict を{what}——変えると次の辺が遷移の検査に落ちます（Strict のドメインへ入る辺は、\
                     引数をリテラルに・作業ディレクトリを宣言し、それと固定したファイルを呼び出し元が書けない場所に\
                     置く必要があります。このエディタはそういう辺を書けないので、辺を取り消すか policy.json に手で\
                     書いてください）。検査の理由: {}{}",
                    new[0],
                    match new.len() {
                        1 => String::new(),
                        n => format!("（ほか {}件）", n - 1),
                    }
                );
            }
            Err(e) => self.status = format!("Strict を確かめられませんでした: {e}"),
        }
    }

    /// 取り消しと Strict の印の付け外しの確認ダイアログを出す（**まだ書かない**）。
    fn request_declared_transition_removals(&mut self) {
        let removals = self.declared_transitions.reserved_edges();
        let strict = self.declared_transitions.reserved_strict();
        if removals.is_empty() && strict.is_empty() {
            self.status = "取り消す辺を Space で選ぶか、ドメインの見出しで s を押してから a を押してください\
                           （ドメインの見出しの行で Space を押すと、そのドメインの辺をまとめて選べます）"
                .to_string();
            return;
        }
        // 予約してから確定までの間に別の経路で`policy.json`が変わったかもしれないので、印の検査を取り直す。
        if let Ok(new) =
            transition_approve::strict_rejections(&self.workspace_root, &removals, &strict)
        {
            if !new.is_empty() {
                self.modal = Some(Modal {
                    title: "書けません（何も書いていません）".to_string(),
                    lines: std::iter::once(
                        "Strict の印を変えると、次の辺が遷移の検査に落ちます:".to_string(),
                    )
                    .chain(new)
                    .collect(),
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        }
        match transition_approve::plan_removals(
            &self.workspace_root,
            &removals,
            &strict,
            now_unix_ms(),
        ) {
            Ok(plan) => {
                self.modal = Some(Modal {
                    title: "この内容で書きますか？".to_string(),
                    lines: removal_lines(&self.workspace_root, &plan),
                    confirm: Confirm::DeclaredTransitions,
                });
                self.modal_scroll = 0;
            }
            Err(e) => {
                self.modal = Some(Modal {
                    title: "取り消せません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
            }
        }
    }

    /// 確認後に書く。**`plan`は作り直す**——ダイアログを見ている間に`policy.json`が別の経路（CLI・手編集・
    /// 承認待ちの確定）で変わっていた場合に、古い読み込み結果で上書きしないため（`commit_transition`と同じ作法）。
    pub(crate) fn commit_declared_transition_removals(&mut self) {
        let removals = self.declared_transitions.reserved_edges();
        let strict = self.declared_transitions.reserved_strict();
        let result =
            transition_approve::plan_removals(&self.workspace_root, &removals, &strict, now_unix_ms())
                .and_then(|plan| {
                    transition_approve::commit_removals(&self.workspace_root, &plan)
                        .map(|written| (written, plan))
                });
        match result {
            Ok((written, plan)) => {
                let missing = match plan.not_found.len() {
                    0 => String::new(),
                    n => format!("。宣言に無くて消えないもの {n}件（別の経路で消えていました）"),
                };
                self.status = if written {
                    let done: Vec<String> = [
                        (!plan.removed.is_empty())
                            .then(|| format!("{}本の遷移の宣言を取り消し", plan.removed.len())),
                        (!plan.strict.is_empty())
                            .then(|| format!("Strict の印を{}件付け替え", plan.strict.len())),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();
                    format!("{}ました（ACLは変わりません）{missing}", done.join("、"))
                } else {
                    format!(
                        "取り消せる辺がありませんでした（policy.json は変えていません）{missing}"
                    )
                };
                self.declared_transitions.remove.clear();
                self.declared_transitions.strict.clear();
                self.reload_declared_transitions();
                // 承認待ちの遷移タブの「宣言済み」も古くなる。
                self.reload_transitions();
            }
            // **書けなかったことを黙らない。** 予約は残す（直して確定し直せるように）。
            Err(e) => {
                self.status = format!("取り消せませんでした: {e}");
                self.reload_declared_transitions();
            }
        }
    }
}

/// 確認ダイアログの行。**遷移元ごとに**、消す辺を全パスで並べる（遷移元を取り違えて消さないことを読んでから`y`）。
fn removal_lines(workspace_root: &std::path::Path, plan: &RemovalPlan) -> Vec<String> {
    let mut lines = vec![format!("{}:", policy_file::path(workspace_root).display())];
    // [P5.5] 印の付け外しは判断材料（呼び出し元が子を操れるかが変わる）なので、辺の明細より先に出す。
    if !plan.strict.is_empty() {
        lines.push(String::new());
        lines.push(format!("Strict の印 {}件:", plan.strict.len()));
        for (name, strict) in &plan.strict {
            lines.push(if *strict {
                format!("  + Strict を付ける: {name}（入る辺は入力を固定しないと書けなくなります）")
            } else {
                format!("  - Strict を外す: {name}（入る辺は普通のモード——呼び出し元は子を通して {name} の権限を使えます）")
            });
        }
    }
    if !plan.strict_not_found.is_empty() {
        lines.push(format!(
            "policy.json に無いドメイン（別の経路で消えていました。何もしません）: {}",
            plan.strict_not_found.join(", ")
        ));
    }
    lines.extend(crate::exposure_view::lines(&plan.widening));
    lines.push(String::new());
    lines.push(format!("取り消す遷移の辺 {}本:", plan.removed.len()));
    let mut current: Option<&str> = None;
    for (from, edge) in &plan.removed {
        if current != Some(from.as_str()) {
            lines.push(format!("遷移元ドメイン {from}:"));
            current = Some(from.as_str());
        }
        lines.push(format!("  - {}", edge_text(edge)));
    }
    if !plan.not_found.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "policy.json に無い辺 {}本（別の経路で消えていました。何もしません）:",
            plan.not_found.len()
        ));
        for (from, edge) in &plan.not_found {
            lines.push(format!("  ? [{from}] {}", edge_text(edge)));
        }
    }
    lines.push(String::new());
    // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
    lines.extend(transition_approve::ACE_NOTICE.lines().map(str::to_string));
    lines
}

#[cfg(test)]
#[path = "declared_transitions_tests.rs"]
mod declared_transitions_tests;
