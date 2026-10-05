//! 宣言画面（[`crate::tui::state::Screen::Declared`]）の状態遷移。
//!
//! `policy.json`の承認済み宣言を一覧し、取り消す。**記録セッションを一切参照しない**ので、
//! ログが1件も無くても開ける——「間違って承認したのですぐ消したい」「検証のため全部消したい」は
//! 記録があるかどうかとは無関係の操作である。
//!
//! # 候補画面と同じ部品で作る（`docs/CODE-STRUCTURE-RULES.md`§5.1）
//!
//! 承認（候補にチェックを付ける）と取り消し（宣言のチェックを外す）は対の操作で、やることも
//! 見るものも同じである。したがって**同じ[`crate::tui::proposal_tree::ProposalTree`]と
//! 同じ[`crate::tui::checkbox_tree`]**（チェックの記号・行の組み立て・選択の移動）を通す。
//!
//! 最初は平坦なリストで作ってしまい、**`ProposalTree`が候補側で解決したはずの問題を
//! 作り直していた**——`cargo`ドメインの宣言は実測668件で、平坦に並べると
//! 「この下をまとめて取り消す」という判断そのものができない。
//!
//! # ACEはここでは剥がさない
//!
//! 理由は[`crate::unapprove`]のモジュールdocにある（付与がパス2開始時なので、撤収も同じ
//! ライフサイクル点に置く）。この画面が変えるのは`policy.json`だけで、確定してもUACは出ない。
//!
//! # [D-112] このマシンでの承認（`y`）
//!
//! `policy.json`には、このマシンで承認していない宣言も入り得る（リポジトリに同梱されていたもの・
//! 手で書いたもの・承認台帳ができる前に承認したもの）。それらには許可が付かないので、行に
//! 「このマシンで未承認」と出し、`y`で配下の未承認の宣言を承認の予約に入れる（`a`で確定）。
//! 確定は[`crate::approve_declared`]を通るので、候補の承認と同じ検査（`--require-sandbox`・
//! 広すぎる値・候補にしない規則）が掛かり、断ったものは確認の画面に理由ごと出る。
//!
//! # 一括取り消しがあるのに一括承認が無いのは意図的
//!
//! D-42が禁じているのは「読まずに権限を**与える**」ことである。こちらは権限を**減らす**向きなので
//! 同じ制約は掛からない——減らす側を面倒にすると、「とりあえず全部消してやり直す」という
//! 安全な回復手段が失われる。
//!
//! # 付け替え（`c`・`R`）
//!
//! 宣言1件の種類と`**`を変える予約（[`declared_reassign`]）。確定は[`crate::reassign`]を通り、
//! 承認の状態を引き継ぎ、承認と同じ検査を掛ける。確定の順は「承認 → 付け替え → 取り消し」
//! （権限を減らす側が後）。

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::tui::checkbox_tree;
use crate::tui::proposal_tree::{ProposalTree, TreeItem};
use crate::tui::state::{Action, App, Confirm, Modal, Screen};
use crate::unapprove::{self, UnapproveTarget};

/// [D-112] 宣言画面の「このマシンでの承認」の状態（`App::declared_approval`）。
#[derive(Debug, Default)]
pub struct DeclaredApprovalState {
    /// このマシンで未承認のファイル宣言。**[`App::reload_declared`]が作り直す**（描画のたびに
    /// 台帳を読まない）。
    pub not_approved: std::collections::BTreeSet<UnapproveTarget>,
    /// 承認を予約した宣言（`y`）。`not_approved`に入っているものだけが入る。
    pub reserved: std::collections::BTreeSet<UnapproveTarget>,
}

impl App {
    /// `policy.json`を読み直して木を組み立てる。**取り消しの予約は保つ**——読み直しは
    /// 表示を最新にする操作で、ユーザーの意思を捨てる操作ではない。ただし予約のうち
    /// **もう存在しない宣言**は落とす（別の経路で消えていた場合に、消せない予約が残らないように）。
    pub fn reload_declared(&mut self) {
        let file = match crate::policy_file::load(&self.workspace_root) {
            Ok(file) => file,
            Err(e) => {
                // 読めないことを黙って空一覧にしない（B-10）。空と壊れているは別の事実である。
                self.declared = Vec::new();
                self.declared_tree = ProposalTree::default();
                self.status = format!("policy.jsonを読めませんでした: {e}");
                return;
            }
        };
        self.declared = unapprove::all_targets(&file);
        self.rebuild_declared_tree();

        // 存在しない宣言への予約を落とす（取り消しも付け替えも同じ規則で）。
        let alive: std::collections::BTreeSet<UnapproveTarget> =
            self.declared.iter().cloned().collect();
        self.unapproved.retain(|target| alive.contains(target));
        self.declared_reassign
            .reserved
            .retain(|from, _| alive.contains(from));

        // [D-112] このマシンで未承認の宣言を数え直す。予約は**まだ未承認のもの**だけ残す
        // （別の経路で承認済みになった宣言を、もう一度承認する予約として持ち歩かない）。
        let approvals = crate::approval_store::approval_store().load();
        let workspace_key =
            harness_sandbox::tier2a::policy_approval::approval_workspace_key(&self.workspace_root);
        self.declared_approval.not_approved = self
            .declared
            .iter()
            .filter(|target| {
                target.key.fs_access().is_some_and(|access| {
                    !approvals.is_approved_for_key(
                        &workspace_key,
                        harness_sandbox::tier2a::policy_approval::DeclarationRef {
                            domain: &target.domain,
                            value: &target.value,
                            access,
                        },
                    )
                })
            })
            .cloned()
            .collect();
        let not_approved = &self.declared_approval.not_approved;
        self.declared_approval
            .reserved
            .retain(|target| not_approved.contains(target));
    }

    /// 宣言の木を組み立て直す。**候補画面と同じ`ProposalTree`**を使う。
    fn rebuild_declared_tree(&mut self) {
        let items: Vec<TreeItem<'_>> = self
            .declared
            .iter()
            .map(|t| TreeItem {
                key: t.key,
                value: &t.value,
                domain: Some(&t.domain),
            })
            .collect();
        let visible: Vec<usize> = (0..items.len()).collect();
        // 宣言に「広すぎて承認できない」は無い（既に承認された結果なので全件が操作対象）。
        let too_broad = vec![false; items.len()];
        self.declared_tree = ProposalTree::from_items(&items, &visible, &too_broad);
        // 初回は根だけ開けておく（候補画面と同じ作法。ドメインの段があれば見出しとその直下の根）。
        if self.declared_expanded.is_empty() {
            self.declared_expanded
                .extend(self.declared_tree.initially_open());
        }
        checkbox_tree::clamp_row(
            &mut self.declared_row,
            self.declared_tree.rows(&self.declared_expanded).len(),
        );
    }

    /// 選択中の行が指すノード。
    fn selected_declared_node(&self) -> Option<usize> {
        self.declared_tree
            .rows(&self.declared_expanded)
            .get(self.declared_row)
            .map(|row| row.node)
    }

    pub(crate) fn on_declared_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        // キーの割り当ても候補画面に揃える（→/←で展開・Spaceで配下をまとめて・aで確定）。
        let rows = self.declared_tree.rows(&self.declared_expanded).len();
        match key.code {
            // 記録画面へ戻る（他の画面のEscと対）。2回連続なら終了するが、その判定は`on_key`側。
            KeyCode::Esc => self.screen = Screen::Record,
            KeyCode::Up => checkbox_tree::move_row(&mut self.declared_row, rows, -1),
            KeyCode::Down => checkbox_tree::move_row(&mut self.declared_row, rows, 1),
            KeyCode::PageUp => checkbox_tree::move_row(&mut self.declared_row, rows, -10),
            KeyCode::PageDown => checkbox_tree::move_row(&mut self.declared_row, rows, 10),
            KeyCode::Right => self.expand_or_descend_declared(),
            KeyCode::Left => self.collapse_or_ascend_declared(),
            KeyCode::Char(' ') => self.toggle_declared_subtree(),
            KeyCode::Char('A') => self.reserve_all_declared(),
            KeyCode::Char('y') => self.toggle_declared_approval_subtree(),
            // 付け替え。キーは候補画面の`c`・`R`と同じ（`reassign`のモジュールdoc）。
            KeyCode::Char('c') => self.cycle_declared_access(),
            KeyCode::Char('R') => self.toggle_declared_recursive(),
            KeyCode::Char('r') => {
                self.reload_declared();
                self.status = "policy.jsonを読み直しました".to_string();
            }
            KeyCode::Char('a') => self.request_declared_changes(),
            _ => {}
        }
        None
    }

    fn expand_or_descend_declared(&mut self) {
        let Some(node) = self.selected_declared_node() else {
            return;
        };
        let key = self.declared_tree.node(node).key.clone();
        if self.declared_tree.has_children(node) && !self.declared_expanded.contains(&key) {
            self.declared_expanded.insert(key);
        } else if self.declared_tree.has_children(node) {
            self.declared_row += 1;
            checkbox_tree::clamp_row(
                &mut self.declared_row,
                self.declared_tree.rows(&self.declared_expanded).len(),
            );
        }
    }

    fn collapse_or_ascend_declared(&mut self) {
        let Some(node) = self.selected_declared_node() else {
            return;
        };
        let key = self.declared_tree.node(node).key.clone();
        if self.declared_expanded.contains(&key) {
            self.declared_expanded.remove(&key);
            return;
        }
        // 閉じていれば親へ戻る。
        if let Some(parent) = self.declared_tree.parent(node) {
            let rows = self.declared_tree.rows(&self.declared_expanded);
            if let Some(index) = rows.iter().position(|row| row.node == parent) {
                self.declared_row = index;
            }
        }
    }

    /// 選択中のノードの配下をまとめて取り消し予約する／やめる。
    ///
    /// **候補画面の`Space`と同じ意味**（`[x]`＝いま許可されている／`[ ]`＝外した）。
    fn toggle_declared_subtree(&mut self) {
        let Some(node) = self.selected_declared_node() else {
            // **何も起きない理由を言う**（B-32）。
            self.status = "宣言がありません（policy.jsonは空です）".to_string();
            return;
        };
        let under = self.declared_tree.subtree_proposals(node);
        let targets: Vec<UnapproveTarget> = under
            .iter()
            .filter_map(|i| self.declared.get(*i).cloned())
            .collect();
        if targets.is_empty() {
            self.status = "この配下に宣言はありません".to_string();
            return;
        }
        let label = self.declared_tree.node(node).path.clone();
        // 全部が「残る」状態＝1件も予約されていないなら、まとめて予約する。
        let all_kept = targets.iter().all(|t| !self.unapproved.contains(t));
        if all_kept {
            let count = targets.len();
            for target in targets {
                self.unapproved.insert(target);
            }
            self.status = format!("{label} の配下 {count}件を取り消します（aで確定）");
        } else {
            for target in &targets {
                self.unapproved.remove(target);
            }
            self.status = format!("{label} の配下 {}件の取り消しをやめました", targets.len());
        }
    }

    /// [D-112] 選択中のノードの配下で**このマシンで未承認の宣言**を、承認の予約に入れる／外す。
    ///
    /// 候補画面の`Space`と同じく配下をまとめて選ぶが、**全件を一度に選ぶキーは無い**
    /// （決定51: 一括承認は許さない）。
    fn toggle_declared_approval_subtree(&mut self) {
        let Some(node) = self.selected_declared_node() else {
            self.status = "宣言がありません（policy.jsonは空です）".to_string();
            return;
        };
        let targets: Vec<UnapproveTarget> = self
            .declared_tree
            .subtree_proposals(node)
            .iter()
            .filter_map(|i| self.declared.get(*i))
            .filter(|t| self.declared_approval.not_approved.contains(*t))
            .cloned()
            .collect();
        if targets.is_empty() {
            // **何も起きない理由を言う**（B-32）。
            self.status = "この配下に、このマシンで未承認の宣言はありません".to_string();
            return;
        }
        let label = self.declared_tree.node(node).path.clone();
        let all_reserved = targets
            .iter()
            .all(|t| self.declared_approval.reserved.contains(t));
        if all_reserved {
            for target in &targets {
                self.declared_approval.reserved.remove(target);
            }
            self.status = format!("{label} の配下 {}件の承認をやめました", targets.len());
        } else {
            let count = targets.len();
            for target in targets {
                self.declared_approval.reserved.insert(target);
            }
            self.status = format!("{label} の配下 {count}件をこのマシンで承認します（aで確定）");
        }
    }

    /// 全ドメインの全宣言を取り消し予約する（モジュールdocの「一括取り消し」）。
    fn reserve_all_declared(&mut self) {
        if self.declared.is_empty() {
            self.status = "宣言がありません（policy.jsonは空です）".to_string();
            return;
        }
        let count = self.declared.len();
        for target in self.declared.clone() {
            self.unapproved.insert(target);
        }
        self.status = format!("全{count}件を取り消します（aで確定 / Spaceで個別に戻せます）");
    }

    /// 承認・付け替え・取り消しの確認ダイアログを出す（**まだ書かない**）。
    fn request_declared_changes(&mut self) {
        if self.unapproved.is_empty()
            && self.declared_approval.reserved.is_empty()
            && self.declared_reassign.reserved.is_empty()
        {
            self.status = "取り消す宣言をスペースで、このマシンで承認する宣言をyで、\
                           付け替える宣言をcかRで選んでください\
                           （Aで全件取り消し、Spaceとyは配下まとめて、cとRは1行ずつ）"
                .to_string();
            return;
        }
        // [D-112] 承認の分。断った宣言は**確認の画面に理由ごと出す**（黙って落とさない、B-10）。
        let approval_plan = match self.declared_approval_plan() {
            Ok(plan) => plan,
            Err(e) => {
                self.modal = Some(Modal {
                    title: "承認できません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        };
        let approval_lines = declared_approval_lines(&approval_plan);
        // 付け替えの分。**同じ確定で先に承認する宣言を渡す**——承認は付け替えより先に書くので、
        // 渡さないと「承認してから付け替える」宣言を「未承認のまま」と見せてしまう（`reassign::plan`）。
        let reassign_lines = match crate::reassign::plan(
            &self.workspace_root,
            &self.declared_reassign.effective(&self.unapproved),
            self.require_sandbox,
            &approval_plan.approve,
        ) {
            Ok(plan) => declared_reassign::reassign_lines(&plan),
            Err(e) => {
                self.modal = Some(Modal {
                    title: "付け替えられません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        };
        let targets: Vec<UnapproveTarget> = self.unapproved.iter().cloned().collect();
        let plan = match unapprove::plan(&self.workspace_root, &targets) {
            Ok(plan) => plan,
            Err(e) => {
                self.modal = Some(Modal {
                    title: "取り消せません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        };

        let mut lines = vec![
            format!(
                "{}:",
                crate::policy_file::path(&self.workspace_root).display()
            ),
            String::new(),
        ];
        lines.extend(approval_lines);
        lines.extend(reassign_lines);
        if !plan.removed.is_empty() {
            lines.push(format!("取り消す宣言 {}件:", plan.removed.len()));
        }
        for target in &plan.removed {
            lines.push(format!(
                "  - [{}] {} {}",
                target.domain,
                target.key.dotted(),
                target.value
            ));
        }
        if !plan.emptied_domains.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "宣言が空になるドメイン: {}",
                plan.emptied_domains.join(", ")
            ));
            lines.push(
                "  （ドメイン自体は残します——宣言なしでパス2を走らせて、本当に拒否されることを\
                 確かめられるようにするため）"
                    .to_string(),
            );
        }
        if !plan.removed.is_empty() {
            lines.push(String::new());
            // 文言の持ち主は`unapprove`（表示側で書き写さない）。
            lines.extend(crate::unapprove::ACE_NOTICE.lines().map(str::to_string));
        }

        self.modal = Some(Modal {
            title: "この内容で書きますか？".to_string(),
            lines,
            confirm: Confirm::DeclaredChanges,
        });
        self.modal_scroll = 0;
    }

    /// [D-112] 承認の予約から、承認の内容を決める（**何も書かない**）。
    fn declared_approval_plan(
        &self,
    ) -> Result<crate::approve_declared::DeclaredApprovalPlan, crate::approve_declared::ApproveDeclaredError>
    {
        let targets: Vec<UnapproveTarget> =
            self.declared_approval.reserved.iter().cloned().collect();
        if targets.is_empty() {
            return Ok(Default::default());
        }
        crate::approve_declared::plan(&self.workspace_root, &targets, self.require_sandbox)
    }

    /// 確認後に実際に書く——**承認 → 付け替え → 取り消し**の順に書く。同じ宣言を承認と取り消しの
    /// 両方で予約していたら取り消しが勝つ（`unapprove::commit`が承認も消す）。付け替えと取り消しの
    /// 両方なら付け替えは書かない（`DeclaredReassignState::effective`）。権限を減らす側が後に来る。
    ///
    /// 付け替えを承認の**後**に置くのは、「このマシンで承認してから付け替える」予約（`y`と`c`を同じ行に）
    /// で承認が付け替えた後の値へ引き継がれるようにするため（`reassign`のモジュールdoc）。
    pub(crate) fn commit_declared_changes(&mut self) {
        let mut notes = Vec::new();
        if !self.declared_approval.reserved.is_empty() {
            // **`plan`は作り直す**（下の取り消しと同じ理由）。
            match self
                .declared_approval_plan()
                .and_then(|plan| {
                    let refused = plan.refused.len() + plan.not_found.len();
                    crate::approve_declared::commit(&self.workspace_root, &plan)
                        .map(|count| (count, refused))
                }) {
                Ok((count, refused)) => {
                    self.declared_approval.reserved.clear();
                    notes.push(format!("{count}件をこのマシンで承認しました"));
                    if refused > 0 {
                        notes.push(format!("{refused}件は承認しませんでした（確認の画面の理由を参照）"));
                    }
                }
                // **書けなかったことを黙らない。** 取り消しは続けて試みる（独立した操作である）。
                Err(e) => notes.push(format!("承認は失敗しました: {e}")),
            }
        }
        let reassignments = self.declared_reassign.effective(&self.unapproved);
        if !reassignments.is_empty() {
            // **`plan`は作り直す**（取り消しと同じ理由）。承認は上で台帳へ書いたので、先に承認した宣言を
            // 渡す必要は無い——台帳そのものを読む（書けなかった承認を「書けた」と見なさない）。
            match crate::reassign::plan(
                &self.workspace_root,
                &reassignments,
                self.require_sandbox,
                &[],
            )
            .and_then(|plan| {
                let refused = plan.refused.len() + plan.not_found.len();
                crate::reassign::commit(&self.workspace_root, &plan).map(|count| (count, refused))
            }) {
                Ok((count, refused)) => {
                    self.declared_reassign.reserved.clear();
                    if count > 0 {
                        notes.push(format!(
                            "{count}件の宣言を付け替えました（ACLは次のパス2開始時に変わります）"
                        ));
                    }
                    if refused > 0 {
                        notes.push(format!(
                            "{refused}件は付け替えませんでした（確認の画面の理由を参照）"
                        ));
                    }
                }
                Err(e) => notes.push(format!("付け替えは失敗しました: {e}")),
            }
        }
        if !self.unapproved.is_empty() {
            self.commit_unapproval();
            notes.push(self.status.clone());
        } else {
            self.reload_declared();
            self.refresh_declared_overlay();
        }
        self.status = notes.join("／");
    }

    /// 取り消しを書く。**`plan`は作り直す**——ダイアログを見ている間に`policy.json`が
    /// 別の経路（CLI・手編集）で変わっていた場合に、古い読み込み結果で上書きしないため
    /// （編集画面の承認と同じ作法）。
    fn commit_unapproval(&mut self) {
        let targets: Vec<UnapproveTarget> = self.unapproved.iter().cloned().collect();
        let plan = match unapprove::plan(&self.workspace_root, &targets) {
            Ok(plan) => plan,
            Err(e) => {
                self.status = format!("取り消せませんでした: {e}");
                return;
            }
        };
        match unapprove::commit(&self.workspace_root, &plan) {
            Ok(true) => {
                self.status = format!(
                    "{}件の宣言を取り消しました（ACEは次のパス2開始時に撤収します）",
                    plan.removed.len()
                );
                self.unapproved.clear();
                self.reload_declared();
                // 編集画面の`[x]`重ねも古くなるので作り直す（宣言が変わった＝重ねの入力が変わった）。
                self.refresh_declared_overlay();
            }
            Ok(false) => {
                self.status =
                    "取り消せる宣言がありませんでした（policy.jsonは変えていません）".to_string();
                self.unapproved.clear();
                self.reload_declared();
            }
            Err(e) => self.status = format!("policy.jsonを書けませんでした: {e}"),
        }
    }
}

/// [D-112] 確認の画面の「承認」の部分。**断ったものと無かったものも理由ごと出す**（B-09）。
fn declared_approval_lines(plan: &crate::approve_declared::DeclaredApprovalPlan) -> Vec<String> {
    let mut lines = Vec::new();
    if !plan.approve.is_empty() {
        lines.push(format!("このマシンで承認する宣言 {}件:", plan.approve.len()));
        for target in &plan.approve {
            lines.push(format!(
                "  + [{}] {} {}",
                target.domain,
                target.key.dotted(),
                target.value
            ));
        }
        lines.push(
            "  （承認すると、次のパス2とharness.exeの起動でこの宣言に許可が付きます）".to_string(),
        );
    }
    for (target, reason) in &plan.refused {
        lines.push(format!(
            "  ✗ 承認しない: [{}] {} {}: {reason}",
            target.domain,
            target.key.dotted(),
            target.value
        ));
    }
    for target in &plan.not_found {
        lines.push(format!(
            "  ? policy.jsonに無い: [{}] {} {}",
            target.domain,
            target.key.dotted(),
            target.value
        ));
    }
    if !lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// 付け替え（`c`・`R`）の予約と確認の画面の行。この画面の状態遷移の一部なので、このモジュールの
/// 子に置く（選択中の行を引く関数を共有するため）。
#[path = "declared_reassign.rs"]
pub(crate) mod declared_reassign;

#[cfg(test)]
#[path = "declared_tests.rs"]
mod declared_tests;
