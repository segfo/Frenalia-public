//! 承認待ち（`F2`）の位置の木の **`u`＝引数を記録どおりに固定し、コマンドラインごとの行（それぞれ別ドメイン）に分ける**
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定67(1)(2)、手順は`plans/position-domains/P5.md`の P5.10.2）。
//!
//! # 何のためにあるのか
//!
//! 位置は（親のドメイン, 実行ファイル）で決まるので、同じインタプリタで別のスクリプトを動かすと全部のスクリプトの権限が
//! 1つのドメインに集まる（`python mv.py`と`python remove.py`が同じドメインなら、remove.py の不具合で mv.py の権限の
//! ファイルも消せる）。引数を記録どおりに固定した位置は、Spawn Daemon が起動ごとに行き先を決められるので、
//! コマンドラインごとに辺もドメインも分ける。
//!
//! # 分けるのは割り当て、画面は集合を持つだけ（`B-13`）
//!
//! 分けるかの判定・名前・既にある辺の引き方は割り当て（`harness_policy::position_domains::assign_domains`の`split`）が
//! 持つ。画面は「分ける位置の集合」（[`PositionsState::split`]）を持ち、**位置の木とファイルの候補を同じ集合で作り直す**
//! ——違う集合で作ると、候補が辺の作らないドメインへ振り分けられる（決定67の検問2）。
//!
//! # 予約の引き継ぎ（決定67の検問9(iv)）
//!
//! - 選んでいた行を分けると、分けた行は全部選んだまま（出力を捨てる設定も引き継ぐ）。戻すときも同じ。
//! - 分けたことで遷移元の名前が変わる子の行の予約は外し、件数を言う（1つの行が2つになるので、どちらへ付け替えるかを
//!   画面が決めない）。
//! - ファイルの候補の予約（選択・`R`・手で変えた access）は、**名前とインスタンスが変わらなかったドメインの分だけ**
//!   引き継ぎ、他は外して件数を言う。分ける前のドメインは無くなるので、黙って別のドメインへ付け替えない。
//!
//! # 限界
//!
//! - 分けた行は記録したコマンドラインだけを通す（記録に無い引数で同じスクリプトを呼ぶと`NoMatchingEdge`）。
//! - 相対パスの引数を持つ行は、普通のモードでも作業ディレクトリの宣言が要る（規則(d)。`w`。[`super::position_strict`]）。
//! - `u`のたびに割り当てとファイルの候補を全部作り直す（増分ではない。費用は未測定——記録を開くときと同じ計算）。

use std::collections::{BTreeMap, BTreeSet};

use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::position_domains::{split_key, Assignment, PositionSource, SplitPositions};

use crate::position_view::{key_of, PositionKey};
use crate::tui::state::App;
use crate::tui::transition_positions::PositionsState;
use crate::tui::transition_screen::file_name;

impl App {
    /// 選んでいる記録で使う分ける位置の集合（位置の木と同じ。**別の記録の位置の木の集合は使わない**）。
    pub(super) fn position_split_for(&self, session_id: &str) -> SplitPositions {
        self.pending
            .positions
            .as_ref()
            .filter(|positions| positions.view.session_id == session_id)
            .map(|positions| positions.split.clone())
            .unwrap_or_default()
    }

    /// 位置の木を読み直すときの分ける集合: 前の状態が今選んでいる記録のものならその集合、違えば空。
    pub(super) fn position_split_of(&self, previous: Option<&PositionsState>) -> SplitPositions {
        let Some(id) = self
            .selected_session()
            .map(|entry| entry.manifest.id.as_str())
        else {
            return SplitPositions::new();
        };
        previous
            .filter(|positions| positions.view.session_id == id)
            .map(|positions| positions.split.clone())
            .unwrap_or_default()
    }

    /// `u`: 選んでいる行（`Space`で選んだもの）の引数を記録どおりに固定してコマンドラインごとの行に分ける。分けた行で
    /// 押すと元の1行（任意の引数）へ戻す。
    pub(super) fn toggle_selected_position_split(&mut self) {
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
        let Some(positions) = self.pending.positions.as_ref() else {
            return;
        };
        if !positions.approve.contains(&key_of(&selected.position)) {
            self.status = "先にSpaceで選んでください（選んだ行の引数を記録どおりに固定し、コマンドラインごとの行に\
                           分けます）"
                .to_string();
            return;
        }
        let target = split_key(&selected.position);
        let joining = selected.position.fixed_command_line.is_some();
        let position = &selected.position;
        if !joining && !position.can_split() {
            // 決定67(2)。振り分けられない起動を残さない（判定は割り当てと同じ`can_split`）。
            self.status = format!(
                "{name}: 引数が結び付かなかった起動 {}回・切り詰めの疑いのある起動 {}回があるので、コマンドラインごとには\
                 分けられません（振り分けられない起動を残さないため——決定67(2)。任意の引数のまま）",
                position.argv_missing, position.argv_truncated
            );
            return;
        }

        // 引き継ぎの材料（読み直すと位置の鍵が変わる）。
        let old_assignment = positions.view.assignment.clone();
        let reserved_before = positions.approve.clone();
        let old_rows: BTreeSet<PositionKey> = old_assignment
            .positions
            .iter()
            .filter(|p| split_key(p) == target)
            .map(key_of)
            .collect();
        let discard = old_rows
            .iter()
            .any(|k| positions.discard_output.contains(k));
        let had_strict = old_rows.iter().any(|k| positions.strict.contains(k));

        let file = match policy_file::load(&self.workspace_root) {
            Ok(file) => file,
            Err(e) => {
                self.status = format!("policy.jsonを読めないので分け方を変えませんでした: {e}");
                return;
            }
        };
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        if joining {
            positions.split.remove(&target);
        } else {
            positions.split.insert(target.clone());
        }
        let mut notes = Vec::new();
        if !self.reload_positions(&file, &mut notes) {
            self.status = format!("位置の木を作り直せませんでした: {}", notes.join(" / "));
            return;
        }
        let fs_dropped = self.rebuild_position_candidates(&old_assignment);

        let workspace_root = self.workspace_root.clone();
        let extra_fs = self.position_extra_fs();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        let new_rows: Vec<PositionKey> = positions
            .view
            .assignment
            .positions
            .iter()
            .filter(|p| split_key(p) == target && p.source != PositionSource::ExistingEdge)
            .map(key_of)
            .collect();
        for key in &new_rows {
            positions.approve.insert(key.clone());
            if discard {
                positions.discard_output.insert(key.clone());
            }
        }
        let unselectable = positions.refresh_verdicts(&workspace_root, &extra_fs);
        let lost_children = reserved_before
            .iter()
            .filter(|k| !old_rows.contains(*k) && !positions.approve.contains(*k))
            .count();
        // 選択を分けた（戻した）最初の行へ。
        if let Some(first) = new_rows.first() {
            let visible = positions.visible();
            if let Some(row) = visible.iter().position(|row| {
                key_of(&positions.view.assignment.positions[row.position]) == *first
            }) {
                positions.row = row;
            }
        }
        let names: Vec<String> = new_rows.iter().map(|(_, _, to)| to.clone()).collect();

        let mut status = if joining {
            format!(
                "{name} を1行（任意の引数）へ戻しました（→ {}）{}",
                names.join("・"),
                if had_strict {
                    "。Strict の指定は外れました（Strict にできるのは引数を固定した行だけ）"
                } else {
                    ""
                }
            )
        } else {
            format!(
                "{name} を記録どおりのコマンドラインごとに{}行へ分けました（→ {}）。各行の辺は引数をリテラルで固定し、\
                 記録に無い引数では起こせません（決定67）",
                new_rows.len(),
                names.join("・")
            )
        };
        if unselectable > 0 {
            status.push_str(&format!(
                "。{unselectable}行は検査に落ちるので選んでいません——相対パスの引数があれば w で作業ディレクトリを\
                 宣言してください（理由は説明欄）"
            ));
        }
        if lost_children > 0 {
            status.push_str(&format!(
                "。遷移元の名前が変わった子の行の予約 {lost_children}件を外しました（選び直してください）"
            ));
        }
        if fs_dropped > 0 {
            status.push_str(&format!(
                "。ファイルの候補の予約 {fs_dropped}件を外しました（分けたドメインで選び直してください）"
            ));
        }
        self.status = status;
    }

    /// ファイルの候補（FS/ネットのタブ）を、位置の木と同じ分ける集合で作り直す。予約は**名前とインスタンスが変わらなかった
    /// ドメインの分だけ**引き継ぎ、外した件数を返す（モジュールdoc）。
    fn rebuild_position_candidates(&mut self, old_assignment: &Assignment) -> usize {
        let Some(positions) = self.current_positions() else {
            return 0;
        };
        let split = positions.split.clone();
        let changed = changed_domains(old_assignment, &positions.view.assignment);
        let Some(entry) = self.selected_session() else {
            return 0;
        };
        let rebuilt =
            super::edit::pass1_view(&entry.dir, &entry.manifest, &self.workspace_root, &split);
        let Some(old_view) = self.view.as_ref() else {
            self.view = Some(rebuilt);
            self.rebuild_tree();
            return 0;
        };
        let old_single = old_view.domains.iter().flatten().next().cloned();

        // 古い候補の予約を（ドメイン, 値, access）で控える（候補の番号は作り直すと変わる）。
        let described = |id: &str| {
            old_view
                .proposals
                .iter()
                .zip(&old_view.domains)
                .find(|(p, _)| p.id == id)
                .map(|(p, d)| (d.clone(), p.value.clone(), p.key))
        };
        let accepted: Vec<_> = self
            .accepted
            .iter()
            .filter_map(|id| described(id))
            .collect();
        let hand_changed: Vec<_> = self
            .hand_changed
            .iter()
            .filter_map(|id| described(id))
            .collect();
        let marks: Vec<(Option<String>, String)> = self
            .recursive
            .iter()
            .filter_map(|key| {
                let node = (0..self.tree.len()).find(|i| &self.tree.node(*i).key == key)?;
                let node = self.tree.node(node);
                Some((
                    node.domain.clone().or_else(|| old_single.clone()),
                    node.path.clone(),
                ))
            })
            .collect();
        let before = self.accepted.len() + self.recursive.len();
        let unchanged =
            |domain: &Option<String>| domain.as_ref().is_none_or(|d| !changed.contains(d));

        // 手で変えた access は、変わらなかったドメインの同じ値へ当て直す。
        let mut proposals = rebuilt.proposals;
        let mut new_hand_changed = BTreeSet::new();
        for (domain, value, key) in hand_changed.iter().filter(|(d, _, _)| unchanged(d)) {
            if let Some(index) = proposals
                .iter()
                .zip(&rebuilt.domains)
                .position(|(p, d)| d == domain && &p.value == value)
            {
                proposals[index] =
                    harness_policy::generalize::restate_access(&proposals[index], *key);
                new_hand_changed.insert(proposals[index].id.clone());
            }
        }
        let view = crate::tui::state::SessionView::new(
            rebuilt.data,
            rebuilt.notes,
            rebuilt.tree,
            proposals,
            rebuilt.domains,
        );
        let mut new_accepted = BTreeSet::new();
        for (domain, value, key) in accepted.iter().filter(|(d, _, _)| unchanged(d)) {
            if let Some(index) = view
                .proposals
                .iter()
                .zip(&view.domains)
                .position(|(p, d)| d == domain && &p.value == value && p.key == *key)
            {
                if !view.too_broad[index] {
                    new_accepted.insert(view.proposals[index].id.clone());
                }
            }
        }
        let new_single = view.domains.iter().flatten().next().cloned();
        self.view = Some(view);
        self.accepted = new_accepted;
        self.hand_changed = new_hand_changed;
        self.rebuild_tree();
        let mut new_marks = std::collections::HashSet::new();
        for (domain, path) in marks.iter().filter(|(d, _)| unchanged(d)) {
            if let Some(node) = (0..self.tree.len()).find(|i| {
                let node = self.tree.node(*i);
                !node.is_domain_header
                    && &node.path == path
                    && &node.domain.clone().or_else(|| new_single.clone()) == domain
            }) {
                new_marks.insert(self.tree.node(node).key.clone());
            }
        }
        self.recursive = new_marks;
        before.saturating_sub(self.accepted.len() + self.recursive.len())
    }
}

/// 名前かインスタンスが変わったドメイン（どちらかの割り当てにしか無い名前と、インスタンスの集合が違う名前）。
fn changed_domains(old: &Assignment, new: &Assignment) -> BTreeSet<String> {
    let members = |assignment: &Assignment| {
        let mut out: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for root in &assignment.roots {
            out.entry(ENTRY_DOMAIN.to_string())
                .or_default()
                .insert(root.seq);
        }
        for position in &assignment.positions {
            out.entry(position.to_domain.clone())
                .or_default()
                .extend(position.instances.iter().copied());
        }
        out
    };
    let (old, new) = (members(old), members(new));
    old.keys()
        .chain(new.keys())
        .filter(|name| old.get(*name) != new.get(*name))
        .cloned()
        .collect()
}

#[cfg(test)]
#[path = "position_split_tests.rs"]
pub(super) mod position_split_tests;
