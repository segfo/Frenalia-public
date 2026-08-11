//! 編集画面の状態遷移（[`crate::tui::state::App`]の続き）。
//!
//! 記録済みのセッションを開き、候補を選び、`policy.json`へ承認するところまで。
//!
//! # 承認は「決める」と「書く」の2段のまま使う
//!
//! [`crate::approve`]は`plan`（何も書かずに差分を返す）と`commit`（それを書く）に分かれており、
//! CLIはその間で確認プロンプトを出す。TUIも**同じ2段**をモーダルで使う。`y`を押した時点で
//! `plan`をもう一度作り直すのは、差分を見せている間に`policy.json`が別の経路で変わっていた
//! 場合に、古い読み込み結果で上書きしないため（承認は和集合マージなので作り直しても安全）。
//!
//! # idは一般化の度合いで変わる
//!
//! `--generalize`を切り替えると提案idは付け直される（`approve`のエラー文がそう明記している）。
//! 選択を残したまま度合いだけ変えると、**ユーザーが選んだつもりのものと違う候補が承認される**。
//! 切り替え時は選択を破棄し、破棄した事実を必ず出す。

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use harness_policy::Generalization;

use crate::approve::{self, ApproveRequest, PathClass};
use crate::policy_file;
use crate::tui::proposal_tree::ProposalTree;
use crate::tui::state::{
    edit_text, Action, App, Confirm, EditField, Modal, Pass, RecordField, Screen, SessionData,
    SessionView,
};

/// 失敗した記録を開いたとき、注記の**先頭**に出す理由。成功した記録では空文字を返す。
///
/// 承認する場所（この画面）に理由が無いと、ユーザーは「候補が0件なのはなぜか」を
/// 進行ログの流れた先へ探しに行くことになる。文言そのものはマニフェストが持つ（規則5）。
fn failure_note_block(manifest: &crate::session_dir::RecordManifest) -> String {
    match manifest.failure_note() {
        Some(note) => format!("{note}\n\n"),
        None => String::new(),
    }
}

impl App {
    /// 選択中のセッションを開いて候補を作る。**保存済みの集計値は使わず**、監査JSONLから
    /// 毎回計算し直す（正本はJSONLだけ、B-13）。
    pub fn open_selected_session(&mut self) {
        self.accepted.clear();
        // 手で変えたaccessは候補と一緒に捨てる（idの指す先が変わるので持ち越せない）。
        self.hand_changed.clear();
        self.selected_row = 0;
        // 選択を先頭へ戻すなら**表示位置も戻す**（対の片方だけ書かない）。
        // 残すと、短い一覧へ切り替えたときに窓だけが下へ取り残される。
        self.candidate_list_offset = 0;
        // 別の記録に移ったら展開状態は持ち越さない（前の記録のパスは出てこない）。
        self.expanded.clear();
        self.show_tree = false;

        let Some(entry) = self.sessions.get(self.selected_session) else {
            self.view = None;
            return;
        };
        let manifest = entry.manifest.clone();

        // パス2の記録は**ネットワークとFSの両方**を見せる。
        //
        // 以前はネットワークだけだった（当時のパス2は`fs-audit.jsonl`を書かなかったので、
        // FSの候補一覧を出しても常に0件だった）。段階4でdeny-only収集器を配線してからは、
        // **「なぜコマンドが失敗したか」の答えはFS側にある**——実際、`cargo test`が
        // `Access is denied`で落ちたとき、ユーザーには「次に何を許可すればいいのか」を
        // 見る場所が1つも無かった。FSを**先**に並べるのはそのためである。
        //
        // idは衝突しない（`generalize`はFS候補へ`fs-N`、ドメイン候補へ`net-N`を振る）。
        // 収集器が動いていない古い記録では`from_log`が空を返すので、従来どおりの表示になる。
        let view = if manifest.pass == 2 {
            let net = crate::net_aggregate::from_log(&entry.dir.net_audit_log_path());
            let fs = crate::aggregate::from_session(&entry.dir, &manifest);

            // **FS欄は収集器が起きなかったときこそ出す。** 「観測していません（収集器を
            // 起動できませんでした）」と「拒否は0件でした」は別の事実で、区別できなければ
            // fail-openは単なる隠蔽になる（D-43）——`render_fs_denials`はその書き分けを
            // 持っているのに、**呼び出しを`collector_started`で囲んでいたせいで、
            // 起きなかったときだけ何も出ない**という正反対の挙動になっていた。
            // 実運用（BUG-093）で「編集画面に拒否の一覧が出てこない」として現れた。
            let mut notes = failure_note_block(&manifest);
            notes.push_str(&crate::record_net::render_fs_denials(
                &fs,
                manifest.collector_started,
                manifest.etw_available,
            ));
            notes.push('\n');
            // **注記も収集器の生死で隠さない。** FS候補は観測だけから作られるものではなく、
            // 実行前診断が名指しした実行ファイルは収集器が起きなくても候補になる。
            // 囲んだままだと、その候補が**なぜそこに在るのか**の説明だけが消える（D-43・B-09）。
            // 何も観測できていないことは`render_notes`自身が言う。
            notes.push_str(&crate::aggregate::render_notes(&fs));
            notes.push('\n');
            notes.push_str(&crate::net_aggregate::render_notes(&net));

            let tree = crate::aggregate::render_process_tree(&fs);
            // **両方を保持する。** 片方だけ持つと、`g`で作り直したときにもう片方の候補が
            // 消える（`SessionData`のdoc）。並び（FSが先）も同じ関数が1つだけ持つ。
            let data = SessionData {
                fs: Some(Box::new(fs)),
                net: Some(Box::new(net)),
            };
            let proposals = data.proposals(self.generalization);
            SessionView::new(data, notes, tree, proposals)
        } else {
            let aggregate = crate::aggregate::from_session(&entry.dir, &manifest);
            let mut notes = failure_note_block(&manifest);
            // 収集器そのものが動いていない場合は、候補が0件である理由がここにしか無い（D-43）。
            if !manifest.collector_started {
                notes.push_str(
                    "警告: この記録では収集器が起動していません（FSアクセスは記録されていません）\n",
                );
            } else if !manifest.etw_available {
                notes.push_str(
                    "警告: この記録ではETWセッションが張れていません（何も観測できていません）\n",
                );
            }
            notes.push_str(&crate::aggregate::render_notes(&aggregate));
            let tree = crate::aggregate::render_process_tree(&aggregate);
            let data = SessionData {
                fs: Some(Box::new(aggregate)),
                net: None,
            };
            let proposals = data.proposals(self.generalization);
            SessionView::new(data, notes, tree, proposals)
        };
        self.view = Some(view);
        self.rebuild_tree();

        // ドメイン名の既定値。パス2の記録なら記録時のドメイン、パス1ならコマンドから決める
        // （規則はCLIと同じ関数を通す）。
        let default = manifest
            .domain
            .clone()
            .unwrap_or_else(|| policy_file::default_domain_name(&manifest.command));
        self.domain.set_text(default);
        // ドメインが決まったので、`[x]`として重ねる宣言を読む。**候補を作り直す経路の全部で
        // 呼ぶ**（ここ・ドメイン名の打ち替え・確定後・画面へ入ったとき）——1つ漏れると
        // その経路だけ古い宣言で判定することになる。
        self.unapproved.clear();
        self.refresh_declared_overlay();
    }

    fn recompute_proposals(&mut self) {
        let mode = self.generalization;
        if let Some(view) = self.view.take() {
            let proposals = view.data.proposals(mode);
            // 共通の警告は候補の顔ぶれで変わるので、作り直す（`new`を通す）。
            self.view = Some(SessionView::new(
                view.data, view.notes, view.tree, proposals,
            ));
        }
        self.selected_row = 0;
        // 選択を先頭へ戻すなら**表示位置も戻す**（対の片方だけ書かない）。
        // 残すと、短い一覧へ切り替えたときに窓だけが下へ取り残される。
        self.candidate_list_offset = 0;
        self.rebuild_tree();
    }

    pub(crate) fn on_edit_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        match key.code {
            KeyCode::Tab => {
                self.edit_focus = match self.edit_focus {
                    EditField::Sessions => EditField::Proposals,
                    EditField::Proposals => EditField::Domain,
                    EditField::Domain => EditField::Sessions,
                };
                return None;
            }
            KeyCode::BackTab => {
                self.edit_focus = match self.edit_focus {
                    EditField::Sessions => EditField::Domain,
                    EditField::Proposals => EditField::Sessions,
                    EditField::Domain => EditField::Proposals,
                };
                return None;
            }
            _ => {}
        }

        // ドメイン名の入力中は、1文字キーを操作に取られると名前が打てない。
        if self.edit_focus == EditField::Domain {
            match key.code {
                KeyCode::Enter => self.edit_focus = EditField::Proposals,
                // 入力欄に居ても画面を離れられるようにする（Escだけは操作として通す）。
                KeyCode::Esc => self.screen = Screen::Record,
                _ => {
                    edit_text(&mut self.domain, key);
                    // **ドメイン名を変えたら重ねを作り直す。** `[x]`はこの名前の宣言に基づく
                    // ので、作り直さないと**別ドメインの宣言を消しに行く**（打ち替えた後の
                    // `unapproved`が古い名前のままになる）。予約も捨てる——指していた宣言が
                    // 別ドメインのものになるため、意思として引き継げない。
                    self.unapproved.clear();
                    self.refresh_declared_overlay();
                }
            }
            return None;
        }

        match key.code {
            // 記録画面のEscと対。F1/F2が届かない端末でも行き来できるようにする。
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Right if self.edit_focus == EditField::Proposals => self.expand_or_descend(),
            KeyCode::Left if self.edit_focus == EditField::Proposals => self.collapse_or_ascend(),
            KeyCode::Enter if self.edit_focus == EditField::Sessions => {
                self.open_selected_session();
                self.edit_focus = EditField::Proposals;
            }
            KeyCode::Char(' ') if self.edit_focus == EditField::Proposals => {
                self.toggle_selected_subtree()
            }
            KeyCode::Char('c') if self.edit_focus == EditField::Proposals => {
                self.cycle_selected_access()
            }
            KeyCode::Char('g') => self.cycle_generalization(),
            KeyCode::Char('f') => self.cycle_filter(),
            KeyCode::Char('t') => self.show_tree = !self.show_tree,
            KeyCode::Char('r') => {
                // 読み直すと候補を作り直すので、手で変えたaccessは戻る（`open_selected_session`が
                // 消す）。**戻ったことを言う**——黙って戻ると、変えたつもりのまま承認しに行く。
                let had_hand_changes = !self.hand_changed.is_empty();
                self.reload_sessions();
                self.open_selected_session();
                self.status = if had_hand_changes {
                    "記録セッションを読み直しました（手で変えたaccessは元に戻りました）".to_string()
                } else {
                    "記録セッションを読み直しました".to_string()
                };
            }
            KeyCode::Char('a') => self.request_approval(),
            _ => {}
        }
        None
    }

    /// いま一覧に出ている候補（フィルタ後）の`proposals`への添字。
    pub(crate) fn visible_proposals(&self) -> Vec<usize> {
        self.view
            .as_ref()
            .map(|view| view.visible(self.filter))
            .unwrap_or_default()
    }

    /// フィルタ後の候補からパス木を組み立て直す。**展開状態は保つ**（作り直すたびに
    /// 開いていた場所が閉じると、一般化の度合いを比べる作業ができない）。
    pub(crate) fn rebuild_tree(&mut self) {
        let visible = self.visible_proposals();
        self.tree = match self.view.as_ref() {
            Some(view) => ProposalTree::build(&view.proposals, &visible, &view.too_broad),
            None => ProposalTree::default(),
        };
        // 初回は根だけ開けておく（全部閉じていると何も見えず、全部開くと平坦な一覧に戻る）。
        if self.expanded.is_empty() {
            self.expanded.extend(self.tree.paths_at_depth(1));
        }
        self.clamp_row();
    }

    fn clamp_row(&mut self) {
        let rows = self.tree.rows(&self.expanded).len();
        if self.selected_row >= rows {
            self.selected_row = rows.saturating_sub(1);
        }
    }

    /// 選択中の行が指すノード。
    pub(crate) fn selected_node(&self) -> Option<usize> {
        self.tree
            .rows(&self.expanded)
            .get(self.selected_row)
            .map(|row| row.node)
    }

    fn move_selection(&mut self, delta: isize) {
        let (len, current) = match self.edit_focus {
            EditField::Sessions => (self.sessions.len(), self.selected_session),
            EditField::Proposals => (self.tree.rows(&self.expanded).len(), self.selected_row),
            EditField::Domain => return,
        };
        if len == 0 {
            return;
        }
        let next = (current as isize + delta).clamp(0, len as isize - 1) as usize;
        match self.edit_focus {
            EditField::Sessions => {
                if next != self.selected_session {
                    self.selected_session = next;
                    // セッションを移ったら中身も入れ替える（選択だけ動いて表示が古いままにしない）。
                    self.open_selected_session();
                }
            }
            EditField::Proposals => self.selected_row = next,
            EditField::Domain => {}
        }
    }

    /// `→`: 閉じていれば開く。既に開いていれば最初の子へ降りる。
    fn expand_or_descend(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        if !self.tree.has_children(node) {
            return;
        }
        let path = self.tree.node(node).path.clone();
        if self.expanded.insert(path) {
            return;
        }
        // 既に開いている → 子へ移動する（行番号は1つ下）。
        self.selected_row += 1;
        self.clamp_row();
    }

    /// `←`: 開いていれば閉じる。既に閉じていれば親へ戻る。
    fn collapse_or_ascend(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        let path = self.tree.node(node).path.clone();
        if self.expanded.remove(&path) {
            self.clamp_row();
            return;
        }
        let Some(parent) = self.tree.parent(node) else {
            return;
        };
        if let Some(position) = self
            .tree
            .rows(&self.expanded)
            .iter()
            .position(|row| row.node == parent)
        {
            self.selected_row = position;
        }
    }

    /// スペースキー: **選択中のノードの配下（自分を含む）をまとめて**選択／解除する。
    ///
    /// 葉ならその候補1件、ディレクトリならその下の全部が対象になる。全部が既に選択済みなら
    /// 解除、そうでなければ選択（部分選択の状態から押したら「全部選ぶ」が期待だろう）。
    ///
    /// **広すぎる値は入れない。** `approve::plan`は1件でも混ざると何も書かずに全部を拒否するので、
    /// 一括選択でそれを混ぜると、選び直しが必要になったことすら分かりにくい。
    fn toggle_selected_subtree(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        let Some(view) = self.view.as_ref() else {
            return;
        };
        let under = self.tree.subtree_proposals(node);
        let approvable: Vec<&harness_policy::RuleProposal> = under
            .iter()
            .filter(|i| !view.too_broad[**i])
            .map(|i| &view.proposals[*i])
            .collect();
        let blocked = under.len() - approvable.len();

        if approvable.is_empty() {
            // ここには承認できるものが1件も無い。**なぜ何も起きないのかを言う**（B-32）。
            self.status = match under.first().map(|i| &view.proposals[*i]) {
                Some(proposal) => match harness_policy::breadth::check(proposal).message() {
                    Some(reason) => format!("{} は承認できません: {reason}", proposal.value),
                    None => "この配下に承認できる候補はありません".to_string(),
                },
                None => "この配下に候補はありません".to_string(),
            };
            return;
        }

        // **チェックの意味は「確定後に許可されているか」の1つに統一する。** したがって
        // 「入っている」には承認予定（`accepted`）と**既に宣言されているもの**の両方が入り、
        // 外す操作は前者なら選択解除・後者なら**宣言の取り消しの予約**になる。
        let all_selected = approvable.iter().all(|p| self.proposal_is_on(p));
        let ids: Vec<String> = approvable.iter().map(|p| p.id.clone()).collect();
        // 宣言側の対象は**宣言のキー**で作る（候補のキーとは違い得る。`declared_targets_for`）。
        let declared: Vec<crate::unapprove::UnapproveTarget> = approvable
            .iter()
            .flat_map(|p| self.declared_targets_for(&p.value))
            .collect();
        let label = self.tree.node(node).path.clone();
        if all_selected {
            for id in &ids {
                self.accepted.remove(id);
            }
            let unapproving = declared.len();
            for target in declared {
                self.unapproved.insert(target);
            }
            self.status = format!("{label} の配下 {}件の選択を解除しました", ids.len());
            if unapproving > 0 {
                // **宣言を消すことになる**のは、選択を外すのとは重さが違う操作なので必ず言う。
                self.status.push_str(&format!(
                    "（うち {unapproving}件は承認済みの宣言です——aで確定すると policy.json から消えます）"
                ));
            }
        } else {
            for id in &ids {
                self.accepted.insert(id.clone());
            }
            // 取り消しを予約していたものを付け直したなら、予約を取り下げる。
            for target in &declared {
                self.unapproved.remove(target);
            }
            self.status = format!("{label} の配下 {}件を選択しました", ids.len());
        }
        if blocked > 0 {
            // 混ぜなかったことを黙っていると、「選んだつもり」との差が最後まで見えない。
            self.status
                .push_str(&format!("（承認できない {blocked}件は除きました）"));
        }
    }

    /// `c`キー: **選択した行の候補のaccessを巡回させる**（`read → read_write → read_exec`）。
    ///
    /// # なぜ手で変えられる必要があるのか
    ///
    /// ETWは読取と実行を区別できない（RESULTS.md §17）ので、実行ファイルへのアクセスは
    /// `fs.read`として観測される。`fs.read`をいくら承認しても`FILE_GENERIC_EXECUTE`は付かず
    /// （`acl_grant::fs_access_mask`）、コマンドは`Access is denied`で落ち続ける。
    /// 実行前診断が名指しできた1件はD-57の追記で候補になるが、**その先で起動される実体**
    /// （rustupのshimが呼ぶtoolchain側のexeなど）は観測からは`read`の顔でしか出てこない。
    /// 「これは実行だ」と判断できるのは人間なので、判断を入力できる口がここに要る。
    ///
    /// # 作り直すのは警告と幅の判定
    ///
    /// どちらも`key`で変わる（`fs.read_write`の書込封じ込め注意・`breadth`の
    /// `MACHINE_WIDE_INSTALL_ROOTS`は書きだけ拒否する）。表示側で書き換えず
    /// [`harness_policy::generalize::restate_access`]と`SessionView::new`に作らせる（B-05）。
    fn cycle_selected_access(&mut self) {
        let Some(node) = self.selected_node() else {
            self.status = "候補がありません".to_string();
            return;
        };
        let label = self.tree.node(node).path.clone();
        let indices = self.tree.node(node).proposals.clone();
        let Some(view) = self.view.as_ref() else {
            return;
        };
        if indices.is_empty() {
            // **何も起きない理由を言う**（B-32）。木のノードは候補そのものとは限らない。
            self.status = format!(
                "{label} はディレクトリの行です（候補の行を選んでから c を押してください）"
            );
            return;
        }

        // どれをどう変えるかを先に決める（借用を分けるため。ここでは何も書き換えない）。
        let mut planned: Vec<(usize, harness_policy::SettingsKey)> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        for index in indices {
            let proposal = &view.proposals[index];
            let Some(next) = proposal.key.next_fs_access() else {
                skipped.push(format!(
                    "{} はFSの候補ではないので変えられません",
                    proposal.key.dotted()
                ));
                continue;
            };
            // 同じ値に移動先のkeyが既にあるなら作らない。作ると同じ設定値の候補が2行並び、
            // 観測回数も割れる（`generalize::merge_same_key_and_value`が展開時に防いでいるのと
            // 同じ事故を、手の操作で作らない）。
            let collides = view.proposals.iter().enumerate().any(|(other, candidate)| {
                other != index
                    && candidate.key == next
                    && candidate.value.eq_ignore_ascii_case(&proposal.value)
            });
            if collides {
                skipped.push(format!(
                    "{} は既に候補にあります（{}）",
                    next.dotted(),
                    proposal.value
                ));
                continue;
            }
            planned.push((index, next));
        }

        if planned.is_empty() {
            self.status = if skipped.is_empty() {
                format!("{label}: 変えられる候補がありません")
            } else {
                format!("{label}: 変えませんでした——{}", skipped.join(" / "))
            };
            return;
        }

        // 候補を差し替えて、`too_broad`と共通警告を作り直す（`SessionView::new`を通す）。
        let Some(view) = self.view.take() else {
            return;
        };
        let mut proposals = view.proposals;
        let mut changed: Vec<String> = Vec::new();
        for (index, next) in planned {
            proposals[index] = harness_policy::generalize::restate_access(&proposals[index], next);
            self.hand_changed.insert(proposals[index].id.clone());
            changed.push(format!("{} を {}", proposals[index].value, next.dotted()));
        }
        let rebuilt = SessionView::new(view.data, view.notes, view.tree, proposals);

        // **承認できなくなったものは選択から外す。** 1件でも混ざると`approve::plan`は
        // 何も書かずに全部を拒否するので、黙って残すと承認そのものが通らなくなる。
        let mut unselected = 0usize;
        for (index, proposal) in rebuilt.proposals.iter().enumerate() {
            if rebuilt.too_broad[index] && self.accepted.remove(&proposal.id) {
                unselected += 1;
            }
        }
        let now_hidden = rebuilt
            .proposals
            .iter()
            .enumerate()
            .any(|(index, proposal)| {
                self.hand_changed.contains(&proposal.id)
                    && !self.filter.accepts(rebuilt.too_broad[index])
            });
        self.view = Some(rebuilt);
        self.rebuild_tree();

        let mut status = format!(
            "{} にしました（accessは手で選んだ扱いになります）",
            changed.join(" / ")
        );
        if unselected > 0 {
            status.push_str(&format!(
                "。**この値は{unselected}件が広すぎて承認できません**——選択から外しました"
            ));
        }
        if now_hidden {
            status.push_str(&format!(
                "。いまの一覧（{}）には出ないので f で切り替えてください",
                self.filter.label()
            ));
        }
        if !skipped.is_empty() {
            status.push_str(&format!("。変えなかったもの: {}", skipped.join(" / ")));
        }
        self.status = status;
    }

    /// 一覧に出す範囲を切り替える（承認できるもの → できないもの → 全部）。
    pub(crate) fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected_row = 0;
        // 選択を先頭へ戻すなら**表示位置も戻す**（対の片方だけ書かない）。
        // 残すと、短い一覧へ切り替えたときに窓だけが下へ取り残される。
        self.candidate_list_offset = 0;
        self.rebuild_tree();
        let visible = self.visible_proposals().len();
        self.status = format!("一覧: {}（{visible}件）", self.filter.label());
    }

    /// 一般化の度合いを回す。**選択は破棄する**（モジュールdoc参照）。
    fn cycle_generalization(&mut self) {
        self.generalization = match self.generalization {
            Generalization::None => Generalization::Directory,
            Generalization::Directory => Generalization::Auto,
            Generalization::Auto => Generalization::None,
        };
        let had_selection = !self.accepted.is_empty();
        // 手で変えたaccessも一緒に消える（候補そのものを作り直すため）。**黙って消さない**。
        let had_hand_changes = !self.hand_changed.is_empty();
        self.accepted.clear();
        self.hand_changed.clear();
        self.recompute_proposals();
        let label = crate::aggregate::generalization_label(self.generalization);
        self.status = match (had_selection, had_hand_changes) {
            (_, true) => format!(
                "一般化の度合いを {label} にしました（候補を作り直すので、選択と手で変えたaccessは元に戻しました）"
            ),
            (true, false) => {
                format!("一般化の度合いを {label} にしました（idが振り直されるので選択は解除しました）")
            }
            (false, false) => format!("一般化の度合いを {label} にしました"),
        };
    }

    /// 承認の差分を作ってモーダルで見せる。**ここでは何も書かない。**
    fn request_approval(&mut self) {
        let Some(view) = self.view.as_ref() else {
            self.status = "開いている記録がありません".to_string();
            return;
        };
        // **取り消しだけの確定も通す。** チェックを外す操作は`accepted`を増やさないので、
        // ここで`accepted`の空だけを見て弾くと「外したのに確定できない」になる。
        if self.accepted.is_empty() && self.unapproved.is_empty() {
            self.status =
                "承認する候補をスペースで選んでください（全件受理のショートハンドはありません）"
                    .to_string();
            return;
        }
        let Some(entry) = self.sessions.get(self.selected_session) else {
            return;
        };
        let domain = self.domain.text().trim().to_string();
        if domain.is_empty() {
            self.status = "ドメイン名を入力してください（Tabで入力欄へ移動）".to_string();
            self.edit_focus = EditField::Domain;
            return;
        }

        let accept_ids: Vec<String> = self.accepted.iter().cloned().collect();
        // **承認が0件でも進む。** チェックを外しただけの確定（取り消しのみ）では`accepted`が
        // 空で、`approve::plan`は`NoIds`を返す——これをエラーとして扱うと「外したのに確定
        // できない」になる。承認の段はここでは**任意**である。
        let plan = if accept_ids.is_empty() {
            None
        } else {
            let request = ApproveRequest {
                workspace_root: &self.workspace_root,
                proposals: &view.proposals,
                accept_ids: &accept_ids,
                require_sandbox: harness_core::RequireSandbox::None,
                domain: &domain,
                command: Some(&entry.manifest.command),
                cwd: Some(&entry.manifest.cwd),
                record_session: Some(&entry.manifest.id),
                now_unix_ms: crate::session_dir::now_unix_ms(),
            };
            match approve::plan(&request) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    // 部分適用はしない——1件でも通らなければ何も書かずに理由だけ出す。
                    self.modal = Some(Modal {
                        title: "承認できません（何も書いていません）".to_string(),
                        lines: e.to_string().lines().map(str::to_string).collect(),
                        confirm: Confirm::ReadOnly,
                    });
                    return;
                }
            }
        };

        // **判断材料を先に、明細を後に置く。** 687件の明細が先だと、マシンに何が残るのか
        // （＝承認するかどうかを決める唯一の材料）を読むのに延々と送ることになる。
        let mut lines = vec![format!(
            "{}:",
            policy_file::path(&self.workspace_root).display()
        )];
        lines.push(format!(
            "  ドメイン: {domain}{}",
            if plan.as_ref().is_some_and(|p| p.report.created_domain) {
                "（新規）"
            } else {
                ""
            }
        ));

        // 承認する分の判断材料は、承認が1件でもあるときだけ出す（取り消しのみの確定では
        // 「workspace外: なし」のような無関係な行を並べない）。
        if let Some(plan) = plan.as_ref() {
            // **承認の実質的な判断材料**: 実際にマシンのACLを変えるのはworkspace外の分だけ。
            let outside: Vec<&str> = plan
                .accepted
                .iter()
                .zip(&plan.classes)
                .filter(|(_, class)| **class == PathClass::OutsideWorkspace)
                .map(|(p, _)| p.value.as_str())
                .collect();
            let inside = plan
                .classes
                .iter()
                .filter(|c| **c == PathClass::InsideWorkspace)
                .count();
            lines.push(String::new());
            if inside > 0 {
                lines.push(format!(
                    "  workspace配下 {inside}件: Tier2aのworkspace許可が既に覆うため、ACEの追加は要りません"
                ));
            }
            if outside.is_empty() {
                lines.push("  workspace外: なし（このマシンのACLは変わりません）".to_string());
            } else {
                lines.push(format!(
                    "  workspace外 {}件: パス2がこのルートへ実際にACEを付けます——**マシンに残る変更**です",
                    outside.len()
                ));
                for value in &outside {
                    lines.push(format!("    {value}"));
                }
            }
            // **観測が言ったことと、ユーザーが判断したことを分けて見せる。** `c`でaccessを変えた
            // 候補は「そう観測された」わけではないので、書く前に件数と内訳を出す（D-42・B-09）。
            let hand_changed: Vec<&str> = plan
                .accepted
                .iter()
                .filter(|p| self.hand_changed.contains(&p.id))
                .map(|p| p.value.as_str())
                .collect();
            if !hand_changed.is_empty() {
                lines.push(String::new());
                lines.push(format!(
                    "  手で access を変えた候補 {}件（観測ではなくあなたの判断です）:",
                    hand_changed.len()
                ));
                for value in &hand_changed {
                    lines.push(format!("    {value}"));
                }
            }

            for warning in &plan.warnings {
                lines.push(format!("  ! {warning}"));
            }

            lines.extend(group_by_key(
                &plan.report.added,
                &plan.report.already_present,
            ));
        }

        // **外したチェック（＝取り消す宣言）を、足す側と同じ確認画面に出す。** 別の画面で
        // 聞くと、1回の`a`で2種類のことが起きるのに片方しか読まずに`y`を押せてしまう。
        let unapprove_plan = if self.unapproved.is_empty() {
            None
        } else {
            let targets: Vec<crate::unapprove::UnapproveTarget> =
                self.unapproved.iter().cloned().collect();
            match crate::unapprove::plan(&self.workspace_root, &targets) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    self.modal = Some(Modal {
                        title: "取り消せません（何も書いていません）".to_string(),
                        lines: e.to_string().lines().map(str::to_string).collect(),
                        confirm: Confirm::ReadOnly,
                    });
                    return;
                }
            }
        };
        let removing = unapprove_plan.as_ref().map_or(0, |p| p.removed.len());
        if let Some(plan) = unapprove_plan.as_ref() {
            lines.push(String::new());
            lines.push(format!(
                "取り消す宣言 {}件（チェックを外した分）:",
                removing
            ));
            for target in &plan.removed {
                lines.push(format!("    - {} {}", target.key.dotted(), target.value));
            }
            lines.push(String::new());
            lines.extend(crate::unapprove::ACE_NOTICE.lines().map(str::to_string));
        }

        // 「承認で増えるものが無い」かどうか（承認自体をしていない場合も含む）。
        let adds_nothing = plan.as_ref().is_none_or(|p| p.report.is_empty());
        if adds_nothing && removing == 0 {
            lines.push(String::new());
            lines.push("（承認済みの内容に変化はありません。何も書きません）".to_string());
            self.modal = Some(Modal {
                title: "変化なし".to_string(),
                lines,
                confirm: Confirm::ReadOnly,
            });
            return;
        }

        self.modal = Some(Modal {
            // **何が起きるのかをタイトルで出す。** 取り消しが混ざる確定を「承認の確認」とだけ
            // 書くと、消える宣言があることが本文を読むまで分からない。
            title: if removing > 0 && adds_nothing {
                format!("{removing}件の宣言を取り消します")
            } else if removing > 0 {
                format!("承認と、{removing}件の宣言の取り消し")
            } else {
                "承認の確認".to_string()
            },
            lines,
            confirm: Confirm::Approval,
        });
        self.modal_scroll = 0;
    }

    /// モーダルで`y`が押されたときに実際に書く。**planを作り直してから**書く（モジュールdoc）。
    pub(crate) fn commit_approval(&mut self) {
        let Some(view) = self.view.as_ref() else {
            return;
        };
        let Some(entry) = self.sessions.get(self.selected_session) else {
            return;
        };
        let domain = self.domain.text().trim().to_string();
        let accept_ids: Vec<String> = self.accepted.iter().cloned().collect();
        let pass_of_record = entry.manifest.pass;
        let command = entry.manifest.command.clone();
        let cwd = entry.manifest.cwd.clone();

        // **承認が0件でも取り消しは書く。** `accepted`が空だと`approve::plan`は`NoIds`を返すので、
        // ここで一律にエラー扱いすると**取り消しだけの確定が黙って落ちる**
        // （`request_approval`が確認を出したのに何も起きない、という形になる）。
        if !accept_ids.is_empty() {
            let request = ApproveRequest {
                workspace_root: &self.workspace_root,
                proposals: &view.proposals,
                accept_ids: &accept_ids,
                require_sandbox: harness_core::RequireSandbox::None,
                domain: &domain,
                command: Some(&entry.manifest.command),
                cwd: Some(&entry.manifest.cwd),
                record_session: Some(&entry.manifest.id),
                now_unix_ms: crate::session_dir::now_unix_ms(),
            };
            let plan = match approve::plan(&request) {
                Ok(plan) => plan,
                Err(e) => {
                    self.status = e.to_string();
                    return;
                }
            };
            if let Err(e) = approve::commit(&self.workspace_root, &plan) {
                self.status = e.to_string();
                return;
            }
        }

        // **外したチェック（＝宣言の取り消し）も同じ確定で書く。** 片方だけ書くと、画面上は
        // 外れているのに`policy.json`には残る（B-01: 対の片方だけ実装しない）。
        // 承認を先に書いてから取り消す順序にしてあるのは、`approve`が和集合マージなので
        // 逆順だと「今回外したものを承認が書き戻す」ことが起こり得るためである。
        let mut unapproved_note = String::new();
        if !self.unapproved.is_empty() {
            let targets: Vec<crate::unapprove::UnapproveTarget> =
                self.unapproved.iter().cloned().collect();
            match crate::unapprove::plan(&self.workspace_root, &targets).and_then(|plan| {
                let removed = plan.removed.len();
                crate::unapprove::commit(&self.workspace_root, &plan).map(|_| removed)
            }) {
                Ok(removed) => {
                    self.unapproved.clear();
                    if removed > 0 {
                        unapproved_note = format!(
                            "／宣言 {removed}件を取り消しました（ACEは次のパス2開始時に撤収）"
                        );
                    }
                }
                // **書けなかったことを黙らない。** 承認だけ通って取り消しが落ちた状態は、
                // 画面の見た目と`policy.json`がずれている状態そのものである。
                Err(e) => unapproved_note = format!("／**取り消しは失敗しました**: {e}"),
            }
        }
        // 宣言が変わったので重ねを作り直す（作り直さないと外した行が`[x]`のまま残る）。
        self.refresh_declared_overlay();

        let written = policy_file::path(&self.workspace_root)
            .display()
            .to_string();
        if pass_of_record == 2 {
            // パス2の候補（許可ドメイン）を承認した。次は宣言だけを許す**ポリシー強制モード**での
            // 検証だが、その実行系（テスト画面）はまだ無い。**あるように見せない。**
            self.status = format!(
                "書きました: {written}{unapproved_note}。宣言したドメインだけを許して検証する\
                 「テスト」画面はまだ実装していません"
            );
            return;
        }

        // ガイド: FSの穴を承認したら、次はパス2（ここで初めてACEが付く）。
        self.pass = Pass::Two;
        self.run_domain.set_text(domain.clone());
        self.command.set_text(command);
        self.cwd.set_text(cwd.display().to_string());
        self.screen = Screen::Record;
        self.record_focus = RecordField::Command;
        self.status = format!(
            "書きました: {written}{unapproved_note}。次はパス2（ドメイン {domain}）——\
             **ここで初めてACEが付きます**。Enterで開始"
        );
    }
}

/// 差分を**access種別ごとにまとめて**並べる。
///
/// `+ fs.read = <パス>`を1行ずつ出すと、687件では同じ`fs.read =`が687回並び、
/// 「どの種別を何件許すのか」という一番知りたいことが読み取れない。種別を見出しにして
/// パスをぶら下げる。
///
/// **既にある分は件数だけ**にする——変更ではないので明細を出しても判断は変わらず、
/// これから増える分（＝承認の対象）が埋もれる。中身が知りたければ`policy.json`そのものを読む。
fn group_by_key(
    added: &[(&'static str, String)],
    already_present: &[(&'static str, String)],
) -> Vec<String> {
    // 表示順は`SettingsKey`の並び（read → read_write → read_exec → net）に合わせて固定する
    // ——実行のたびに順序が変わると差分を見比べられない。
    const ORDER: &[&str] = &[
        "fs.read",
        "fs.read_write",
        "fs.read_exec",
        "net.allow_domains",
    ];
    let mut lines = Vec::new();

    for key in ORDER {
        let values: Vec<&str> = added
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect();
        if values.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("  {key}  ＋{}件", values.len()));
        for value in values {
            lines.push(format!("      {value}"));
        }
    }

    let mut present_lines = Vec::new();
    for key in ORDER {
        let count = already_present.iter().filter(|(k, _)| k == key).count();
        if count > 0 {
            present_lines.push(format!("  {key}  {count}件は既にあります（変更なし）"));
        }
    }
    if !present_lines.is_empty() {
        lines.push(String::new());
        lines.extend(present_lines);
    }

    lines
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod edit_tests;
