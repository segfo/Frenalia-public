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
//! # 一括取り消しがあるのに一括承認が無いのは意図的
//!
//! D-42が禁じているのは「読まずに権限を**与える**」ことである。こちらは権限を**減らす**向きなので
//! 同じ制約は掛からない——減らす側を面倒にすると、「とりあえず全部消してやり直す」という
//! 安全な回復手段が失われる。

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::tui::checkbox_tree;
use crate::tui::proposal_tree::{ProposalTree, TreeItem};
use crate::tui::state::{Action, App, Confirm, Modal, Screen};
use crate::unapprove::{self, UnapproveTarget};

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

        // 存在しない宣言への予約を落とす。
        let alive: std::collections::BTreeSet<UnapproveTarget> =
            self.declared.iter().cloned().collect();
        self.unapproved.retain(|target| alive.contains(target));
    }

    /// 宣言の木を組み立て直す。**候補画面と同じ`ProposalTree`**を使う。
    fn rebuild_declared_tree(&mut self) {
        let items: Vec<TreeItem<'_>> = self
            .declared
            .iter()
            .map(|t| TreeItem {
                key: t.key,
                value: &t.value,
            })
            .collect();
        let visible: Vec<usize> = (0..items.len()).collect();
        // 宣言に「広すぎて承認できない」は無い（既に承認された結果なので全件が操作対象）。
        let too_broad = vec![false; items.len()];
        self.declared_tree = ProposalTree::from_items(&items, &visible, &too_broad);
        // 初回は根だけ開けておく（候補画面と同じ作法）。
        if self.declared_expanded.is_empty() {
            self.declared_expanded
                .extend(self.declared_tree.paths_at_depth(1));
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
            KeyCode::Char('r') => {
                self.reload_declared();
                self.status = "policy.jsonを読み直しました".to_string();
            }
            KeyCode::Char('a') => self.request_unapproval(),
            _ => {}
        }
        None
    }

    fn expand_or_descend_declared(&mut self) {
        let Some(node) = self.selected_declared_node() else {
            return;
        };
        let path = self.declared_tree.node(node).path.clone();
        if self.declared_tree.has_children(node) && !self.declared_expanded.contains(&path) {
            self.declared_expanded.insert(path);
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
        let path = self.declared_tree.node(node).path.clone();
        if self.declared_expanded.contains(&path) {
            self.declared_expanded.remove(&path);
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

    /// 取り消しの確認ダイアログを出す（**まだ書かない**）。
    fn request_unapproval(&mut self) {
        if self.unapproved.is_empty() {
            self.status = "取り消す宣言をスペースで選んでください（Aで全件、Spaceで配下まとめて）"
                .to_string();
            return;
        }
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
        lines.push(format!("取り消す宣言 {}件:", plan.removed.len()));
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
        lines.push(String::new());
        // 文言の持ち主は`unapprove`（表示側で書き写さない）。
        lines.extend(crate::unapprove::ACE_NOTICE.lines().map(str::to_string));

        self.modal = Some(Modal {
            title: format!("この{}件を取り消しますか？", plan.removed.len()),
            lines,
            confirm: Confirm::Unapproval,
        });
        self.modal_scroll = 0;
    }

    /// 確認後に実際に書く。**`plan`は作り直す**——ダイアログを見ている間に`policy.json`が
    /// 別の経路（CLI・手編集）で変わっていた場合に、古い読み込み結果で上書きしないため
    /// （編集画面の承認と同じ作法）。
    pub(crate) fn commit_unapproval(&mut self) {
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
