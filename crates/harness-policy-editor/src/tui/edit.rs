//! 編集画面の状態遷移（[`crate::tui::state::App`]の続き）。
//!
//! 記録済みのセッションを開き、候補を選ぶところまで。
//!
//! 承認の確定（確認ダイアログを出し、`y`で`policy.json`へ書く）は[`super::edit_commit`]が持つ
//! （2026-10-05に移した。`plans/position-domains/P4.md`のP4.0）。
//!
//! # 「まとめて選ぶ」と「広げる」を別のキーに分ける（D-62）
//!
//! 候補は**観測された値そのまま**で、パスの一般化はしない。まとめて選びたいという要求は
//! 値ではなく**表示**（[`super::proposal_tree::ProposalTree`]）で満たす——親行でスペースを押すと
//! 配下の候補が個別に選ばれる。値を書き換えないので、選んだ件数と開く範囲が一致する。
//!
//! ただし祖先チェーンのオープンで**ディレクトリ自身が拒否として観測される**ことがあり、
//! その候補だけは値がディレクトリになる（＝承認するとサブツリー全体が開く）。これを
//! スペースへ混ぜると「画面にはN行しか見えていないのに全部開く」になるので、
//! スペースの対象から外し、`d`（[`App::toggle_node_itself`]）で明示的に選ばせる。
//! 外したことも、`d`という出口があることも、その場で必ず出す（B-32）。

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::policy_file;
use crate::tui::proposal_tree::ProposalTree;
use crate::tui::state::{edit_text, Action, App, EditField, Screen, SessionData, SessionView};

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
            // 候補の取り込み口は**その記録を走らせたモード**で決まる（決定64）。欄が無い古い記録は記録モード。
            let net = crate::net_aggregate::from_log(
                &entry.dir.net_audit_log_path(),
                manifest.net_mode(),
            );
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
                manifest.net_mode(),
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
            let proposals = data.proposals();
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
            let proposals = data.proposals();
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
            KeyCode::Char('d') if self.edit_focus == EditField::Proposals => {
                self.toggle_node_itself()
            }
            KeyCode::Char('R') if self.edit_focus == EditField::Proposals => {
                self.toggle_recursive()
            }
            KeyCode::Char('f') => self.cycle_filter(),
            KeyCode::Char('t') => self.show_tree = !self.show_tree,
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

    /// 選択を`delta`行動かす（`↑↓`・`PgUp/PgDn`、一覧の行のクリック。`tui::pointer`）。
    pub(crate) fn move_selection(&mut self, delta: isize) {
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

    /// スペースキー: **選択中のノードの配下をまとめて**選択／解除する。
    ///
    /// 葉ならその候補1件、ディレクトリならその下の全部が対象になる。全部が既に選択済みなら
    /// 解除、そうでなければ選択（部分選択の状態から押したら「全部選ぶ」が期待だろう）。
    ///
    /// **広すぎる値は入れない。** `approve::plan`は1件でも混ざると何も書かずに全部を拒否するので、
    /// 一括選択でそれを混ぜると、選び直しが必要になったことすら分かりにくい。
    ///
    /// # 子を持つノード自身の候補は**含めない**（D-62）
    ///
    /// 祖先チェーンのオープンで**ディレクトリ自身が拒否として観測される**ことがあり、その場合
    /// そのノードは「構造」であると同時に「値がディレクトリの候補」でもある。これを一括選択へ
    /// 混ぜると、画面には配下のファイルがN行見えているのに、承認されるのは**サブツリー全体**に
    /// なる（ディレクトリへの付与は継承ACE）。**見えている行数と実際に開く範囲が食い違う**ので、
    /// スペースは配下だけを対象にし、ノード自身は`d`（[`Self::toggle_node_itself`]）で
    /// 明示的に選ばせる。
    fn toggle_selected_subtree(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        let Some(view) = self.view.as_ref() else {
            return;
        };
        let under = self.tree.bulk_selectable_proposals(node);
        let approvable: Vec<&harness_policy::RuleProposal> = under
            .iter()
            .filter(|i| !view.too_broad[**i])
            .map(|i| &view.proposals[*i])
            .collect();
        let blocked = under.len() - approvable.len();

        if approvable.is_empty() {
            // ここには承認できるものが1件も無い。**なぜ何も起きないのかを言う**（B-32）。
            // ノード自身が候補（＝ディレクトリ自身が観測された）ときは、`d`という出口も言う
            // ——出口を言わない警告は半分しか役に立たない。
            let own_is_a_candidate =
                self.tree.has_children(node) && !self.tree.node(node).proposals.is_empty();
            self.status = match under.first().map(|i| &view.proposals[*i]) {
                Some(proposal) => match harness_policy::breadth::check(proposal).message() {
                    Some(reason) => format!("{} は承認できません: {reason}", proposal.value),
                    None => "この配下に承認できる候補はありません".to_string(),
                },
                None if own_is_a_candidate => format!(
                    "{} の配下に候補はありません（このディレクトリ自身は候補ですが、\
                     承認すると配下すべてが開くので d で明示的に選んでください）",
                    self.tree.node(node).path
                ),
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
        // **このノード自身を外したことも言う**（D-62・B-32）。黙って外すと、承認したつもりの
        // ディレクトリが入っていないことに最後まで気付けない——「選んだつもり」との差は
        // 広い方向にも狭い方向にも見えている必要がある。
        if self.tree.has_children(node) && !self.tree.node(node).proposals.is_empty() {
            self.status.push_str(&format!(
                "（{label} 自身は入れていません——承認すると配下すべてが開くので、要るなら d で選んでください）"
            ));
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

    /// `d`キー: **このノード自身の候補だけ**を選択／解除する（D-62）。
    ///
    /// スペース（[`Self::toggle_selected_subtree`]）が子を持つノード自身を対象外にするので、
    /// ディレクトリ自身が観測された候補を選ぶ道はここだけになる。**選ぶと配下すべてが開く**
    /// ——継承ACEなので、いま見えていないファイルと将来作られるファイルも含む。だから
    /// 「まとめて選ぶ」とは別のキーに分けてある。
    fn toggle_node_itself(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        let Some(view) = self.view.as_ref() else {
            return;
        };
        let own = self.tree.node(node).proposals.clone();
        if own.is_empty() {
            self.status =
                "この行そのものは候補ではありません（配下を選ぶならスペース）".to_string();
            return;
        }
        let approvable: Vec<&harness_policy::RuleProposal> = own
            .iter()
            .filter(|i| !view.too_broad[**i])
            .map(|i| &view.proposals[*i])
            .collect();
        if approvable.is_empty() {
            self.status = match harness_policy::breadth::check(&view.proposals[own[0]]).message() {
                Some(reason) => format!(
                    "{} は承認できません: {reason}",
                    view.proposals[own[0]].value
                ),
                None => "この候補は承認できません".to_string(),
            };
            return;
        }

        let all_selected = approvable.iter().all(|p| self.proposal_is_on(p));
        let ids: Vec<String> = approvable.iter().map(|p| p.id.clone()).collect();
        let declared: Vec<crate::unapprove::UnapproveTarget> = approvable
            .iter()
            .flat_map(|p| self.declared_targets_for(&p.value))
            .collect();
        let label = self.tree.node(node).path.clone();
        if all_selected {
            for id in &ids {
                self.accepted.remove(id);
            }
            for target in declared {
                self.unapproved.insert(target);
            }
            self.status = format!("{label} 自身の選択を解除しました");
        } else {
            for id in ids {
                self.accepted.insert(id);
            }
            for target in &declared {
                self.unapproved.remove(target);
            }
            // **何を選んだのかを正確に言う**（B-32）。件数ではなく「範囲」が判断材料である。
            // [D-63] 素の宣言が開くのは**そのオブジェクト1つだけ**になった（付与層で非継承ACE
            // になる）。ここで「配下すべて」と言うと、実際より広く伝えることになる。
            self.status = format!(
                "{label} 自身を選びました（開くのはこの行のパスだけです。配下も要るなら R）"
            );
        }
    }

    /// `R`キー: このディレクトリを**再帰**で許可する印を付ける／外す（D-63）。
    ///
    /// 承認時に`<path>/**`という値の宣言として合成される（[`Self::recursive_proposals`]）。
    /// **押せるのは子を持つノードだけ**——木の中で確実にディレクトリだと言えるのがそれだからである
    /// （葉が実体としてディレクトリかどうかは、木の情報だけでは分からない。存在しないパスや
    /// 消えたパスをstatしに行くと、UIの応答がファイルシステムに引きずられる）。
    ///
    /// 構造ノード（そのフォルダ自身は観測されていない）にも付けられる。付けられないと
    /// `.rustup/toolchains`のように**中のファイルだけが観測された**ケースが救えず、
    /// ユーザーは数百件を個別に承認するか、サンドボックスを切るかの二択になる。
    fn toggle_recursive(&mut self) {
        let Some(node) = self.selected_node() else {
            return;
        };
        if !self.tree.has_children(node) {
            self.status =
                "再帰にできるのはディレクトリの行だけです（この行自身を許すなら d）".to_string();
            return;
        }
        let path = self.tree.node(node).path.clone();
        if self.recursive.remove(&path) {
            self.status = format!("{path} の再帰指定を外しました");
            return;
        }
        // **広すぎる値は印を付ける段階で止める**（承認時に弾くと、選び直しが要ることに
        // その場で気付けない）。判定は`breadth`の同じ関数を通す。
        //
        // **承認で作られるのと同じaccess種別で見る。** かつてここは`FsRead`固定で判定して
        // いたが、`recursive_proposals`は**配下に観測された種別ごとに1本ずつ**作るので、
        // 書込が観測されたサブツリーでは「印は付くのに、承認では弾かれる`fs.read_write`の
        // 宣言」が生まれていた（`**`＋書込は`breadth`が拒否する）。判定に使う集合を
        // `recursive_keys_for`へ寄せ、印を付ける側と作る側が**同じ答え**を見るようにする（B-06）。
        let value = format!("{path}/**");
        for key in self.recursive_keys_for(node) {
            if let Some(reason) = harness_policy::breadth::check_value(key, &value).message() {
                self.status = format!("{value} は再帰にできません（{}）: {reason}", key.dotted());
                return;
            }
        }
        self.recursive.insert(path.clone());
        let under = self.tree.subtree_proposals(node).len();
        // **何を選んだのかを範囲で言う**（B-32）。件数だけでは「見えている分」と読まれる。
        self.status = format!(
            "{value} を再帰で許可します（いま見えている{under}件だけでなく、\
             このフォルダ配下すべてと今後作られるファイルが対象です）"
        );
    }

    /// `<path>/**`として合成されるaccess種別（配下に観測された種別の集合）。
    ///
    /// **印を付けてよいかの判定（[`Self::toggle_recursive`]）と、実際に合成する側
    /// （[`Self::recursive_proposals`]）が同じ集合を見るための1箇所。** 別々に数えると、
    /// 「印は付いたのに承認では弾かれる種別」が生まれる（B-06・`CODE-STRUCTURE-RULES`§5.0）。
    ///
    /// 配下に候補が1件も無いノード（全部フィルタで隠れている等）は`fs.read`を既定にする。
    fn recursive_keys_for(&self, node: usize) -> Vec<harness_policy::generalize::SettingsKey> {
        let Some(view) = self.view.as_ref() else {
            return vec![harness_policy::generalize::SettingsKey::FsRead];
        };
        let mut keys: Vec<harness_policy::generalize::SettingsKey> = self
            .tree
            .subtree_proposals(node)
            .into_iter()
            .map(|i| view.proposals[i].key)
            .filter(|k| *k != harness_policy::generalize::SettingsKey::NetAllowDomains)
            .collect();
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            keys.push(harness_policy::generalize::SettingsKey::FsRead);
        }
        keys
    }

    /// `R`で印を付けたノードを、承認へ流す**合成された提案**にする（D-63）。
    ///
    /// 実在の候補ではないのでidは`rec-N`にする（`fs-N`と衝突させない）。access種別は
    /// **配下に観測された種別ごとに1本ずつ**作る——1本へ寄せると、`read`しか要らなかった経路まで
    /// 書込可になる（P-03、本モジュールが一般化でしないのと同じ理由）。配下に候補が1件も
    /// 無いノード（全部フィルタで隠れている等）は`fs.read`を既定にする。
    pub(crate) fn recursive_proposals(&self) -> Vec<harness_policy::RuleProposal> {
        let Some(view) = self.view.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut seq = 0usize;
        // 木のノードを引き直す（`recursive`はパスで持っているので、木が作り直されても残る）。
        for path in &self.recursive {
            let Some(node) = (0..self.tree.len()).find(|i| &self.tree.node(*i).path == path) else {
                continue;
            };
            let keys = self.recursive_keys_for(node);
            let evidence: Vec<_> = self
                .tree
                .subtree_proposals(node)
                .into_iter()
                .flat_map(|i| view.proposals[i].evidence.clone())
                .collect();
            for key in keys {
                seq += 1;
                out.push(harness_policy::RuleProposal {
                    id: format!("rec-{seq}"),
                    key,
                    value: format!("{path}/**"),
                    evidence: evidence.clone(),
                    warnings: vec![
                        "recursive: this covers everything under the folder, including files \
                         created there later"
                            .to_string(),
                    ],
                });
            }
        }
        out
    }

    /// いま「選んでいる」ものの件数。**選ぶ手段はチェック（`Space`/`d`）と再帰指定（`R`）の
    /// 2つある**ので、両方を数える。
    ///
    /// 数え漏らすと、`R`だけを付けたユーザーに「選択 0件」と見えて**承認できないと誤解させる**
    /// （実際には承認される。実運用でこの取り違えが起きた）。`request_approval`のガードは
    /// 最初から両方を見ているので、**表示だけが取り残されていた**——選ぶ手段を増やしたら、
    /// 選択の有無を見る場所を全部数える（B-06）。`accepted`は候補id、`recursive`はノードのパスを
    /// 持つ別々の集合なので、二重に数えることはない。
    pub(crate) fn selected_count(&self) -> usize {
        self.accepted.len() + self.recursive.len()
    }
}

#[cfg(test)]
#[path = "edit_tests.rs"]
mod edit_tests;
