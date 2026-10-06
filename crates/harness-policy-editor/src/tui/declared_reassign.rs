//! 宣言画面（`F3`）の付け替え——`c`（種類を変える）と`R`（`**`を付け外しする）。
//! 何を書くか・承認をどう扱うかは[`crate::reassign`]が持ち、ここは予約と表示だけを持つ。
//!
//! # 1行ずつ予約し、`a`で確定する
//!
//! 取り消し（`Space`）・このマシンでの承認（`y`）と同じく、押した時点では予約するだけで、`a`の確認の
//! 画面で確定する。**配下をまとめて付け替えるキーは無い**——付け替えは権限を広げ得るので、
//! 決定51（権限を増やす向きは1件ずつ読ませる）に従う。キーは候補画面と同じ`c`・`R`にそろえる
//! （対になる操作は同じ操作で、`docs/CODE-STRUCTURE-RULES.md`§5.1）。
//!
//! # 押した瞬間に断る
//!
//! 付け替えた後の値が承認と同じ検査（`reassign::refusal`）で断られるなら、予約せずに理由を出す。
//! `c`は断られた種類を飛ばして次の種類へ進む——`**`の値では`read_write`が幅の検査で断られる
//! （`**`＋書込）ので、飛ばさないと`read_exec`へ進めない。確定の時点でも同じ検査をもう一度掛ける
//! （予約してから`policy.json`が変わることがある）。
//!
//! # 宣言が複数ある行では使えない（まだ無いもの）
//!
//! 木の1行は**同じパスの宣言をまとめて**持つ（同じ値の`read`と`read_exec`、別ドメインの同じ値）。
//! どれを付け替えるかを選ぶ表示がまだ無いので、その行では断って理由を言う。まとめて付け替えると、
//! 1回のキーで複数の宣言を広げることになる（上の決定51）。

use std::collections::{BTreeMap, BTreeSet};

use harness_policy::generalize::SettingsKey;
use harness_policy::normalize::declared_scope;

use crate::approve_declared::ApprovalChecks;
use crate::reassign::{self, Reassignment, ReassignPlan};
use crate::tui::state::App;
use crate::unapprove::UnapproveTarget;

/// 宣言画面の付け替えの予約（`App::declared_reassign`）。
#[derive(Debug, Default)]
pub struct DeclaredReassignState {
    /// 鍵は`policy.json`の行（付け替える前）、値は付け替えた後の`(種類, 値)`。
    ///
    /// **鍵を`(ドメイン, キー, 値)`で持つ**のは取り消し・承認の予約と同じ理由（木を作り直しても
    /// 意味が変わらない）。ドメインは値に持たない——付け替えでドメインは変えられない
    /// （[`crate::reassign::Reassignment`]）。
    pub reserved: BTreeMap<UnapproveTarget, (SettingsKey, String)>,
}

impl DeclaredReassignState {
    /// 確定へ渡す付け替え。**取り消しを予約した宣言は除く**——同じ宣言を両方で予約したら取り消しが
    /// 勝つ（承認と取り消しの両方で予約したときと同じく、権限を減らす側を優先する）。
    ///
    /// **確認の画面と書く処理が同じこれを通す**——除外を片方だけに書くと、確認の画面に出なかった
    /// 付け替えが書かれる（D-63で`request_approval`にだけ再帰を足して`commit_approval`に足し忘れた
    /// のと同じ形、B-06）。
    pub fn effective(&self, unapproved: &BTreeSet<UnapproveTarget>) -> Vec<Reassignment> {
        self.reserved
            .iter()
            .filter(|(from, _)| !unapproved.contains(*from))
            .map(|(from, (key, value))| Reassignment {
                from: from.clone(),
                key: *key,
                value: value.clone(),
            })
            .collect()
    }
}

impl App {
    /// `c`: 選択中の行の宣言の**種類**を巡回させる予約をする（`read → read_write → read_exec`）。
    ///
    /// 巡回の順は候補画面の`c`と同じ[`SettingsKey::next_fs_access`]が持つ（B-05）。
    pub(crate) fn cycle_declared_access(&mut self) {
        let Some(from) = self.declaration_to_reassign("c") else {
            return;
        };
        let (mut key, value) = self.reassigned(&from);
        let checks = ApprovalChecks::for_workspace(&self.workspace_root, self.require_sandbox);
        let existing = self.reassign_collision_targets(&from);
        let mut skipped = Vec::new();
        // 種類は3つなので、いまの種類以外は2つ。2つとも断られたら変えられない。
        for _ in 0..2 {
            let Some(next) = key.next_fs_access() else {
                break;
            };
            key = next;
            if key == from.key && value.eq_ignore_ascii_case(&from.value) {
                self.declared_reassign.reserved.remove(&from);
                self.status = format!(
                    "{} を元の {} に戻しました（付け替えの予約をやめました）",
                    from.value,
                    from.key.dotted()
                );
                return;
            }
            match reassign::refusal(&checks, &existing, &from, key, &value) {
                Some(reason) => skipped.push(format!("{}: {reason}", key.dotted())),
                None => {
                    self.reserve_reassignment(&from, key, value, &skipped);
                    return;
                }
            }
        }
        // **何も起きない理由を言う**（B-32）。
        self.status = format!(
            "{} の種類は変えられません——{}",
            value,
            skipped.join(" / ")
        );
    }

    /// `R`: 選択中の行の宣言の`**`を付け外しする予約をする（D-63: 素のパス＝そのオブジェクト1つ、
    /// `**`＝配下すべてと今後作られるもの）。
    pub(crate) fn toggle_declared_recursive(&mut self) {
        let Some(from) = self.declaration_to_reassign("R") else {
            return;
        };
        let (key, current) = self.reassigned(&from);
        let Some(value) = reassign::toggle_recursive(&current) else {
            self.status = format!(
                "{current} は ** を付け外しできない形です（途中にワイルドカードがある等）"
            );
            return;
        };
        if key == from.key && value.eq_ignore_ascii_case(&from.value) {
            self.declared_reassign.reserved.remove(&from);
            self.status = format!("{} に戻しました（付け替えの予約をやめました）", from.value);
            return;
        }
        let checks = ApprovalChecks::for_workspace(&self.workspace_root, self.require_sandbox);
        let existing = self.reassign_collision_targets(&from);
        if let Some(reason) = reassign::refusal(&checks, &existing, &from, key, &value) {
            self.status = format!("{value} にはできません: {reason}");
            return;
        }
        self.reserve_reassignment(&from, key, value, &[]);
    }

    /// 付け替えの予約を入れ、**何がどう変わるのかを範囲で言う**（B-32。候補画面の`R`と同じ作法）。
    fn reserve_reassignment(
        &mut self,
        from: &UnapproveTarget,
        key: SettingsKey,
        value: String,
        skipped: &[String],
    ) {
        let widens = reassign::widens(from, key, &value);
        let scope = if declared_scope(&value).is_recursive() {
            "配下すべてと今後作られるもの"
        } else {
            "そのパス1つだけ"
        };
        let mut status = format!(
            "{} {} → {} {}（{scope}）にします。{}aで確定",
            from.key.dotted(),
            from.value,
            key.dotted(),
            value,
            if widens { "権限が広がります。" } else { "" }
        );
        if !skipped.is_empty() {
            status.push_str(&format!("（飛ばした種類: {}）", skipped.join(" / ")));
        }
        self.declared_reassign
            .reserved
            .insert(from.clone(), (key, value));
        self.status = status;
    }

    /// `c`・`R`の対象になる宣言（選択中の行がちょうど1件の**ファイル宣言**を指すとき）。
    /// 対象にならないときは理由を`status`へ出して`None`（B-32）。
    fn declaration_to_reassign(&mut self, key_label: &str) -> Option<UnapproveTarget> {
        let Some(node) = self.selected_declared_node() else {
            self.status = "宣言がありません（policy.jsonは空です）".to_string();
            return None;
        };
        let label = self.declared_tree.node(node).path.clone();
        let own = self.declared_tree.node(node).proposals.clone();
        match own.as_slice() {
            [] => {
                self.status = format!(
                    "{label} はディレクトリの行です（宣言の行を選んでから {key_label} を押してください。\
                     まとめて付け替えるキーはありません）"
                );
                None
            }
            [index] => {
                let target = self.declared.get(*index)?.clone();
                if target.key.fs_access().is_none() {
                    self.status = "ネットワークの宣言は付け替えられません".to_string();
                    return None;
                }
                if self.unapproved.contains(&target) {
                    self.status = format!(
                        "{} は取り消しを予約中です（Space で戻してから {key_label} を押してください）",
                        target.value
                    );
                    return None;
                }
                Some(target)
            }
            several => {
                self.status = format!(
                    "{label} には宣言が{}件あります（種類かドメインが違う）。どれを付け替えるかを選ぶ\
                     表示がまだ無いので、この行では {key_label} を使えません",
                    several.len()
                );
                None
            }
        }
    }

    /// いま予約している付け替えた後の`(種類, 値)`（予約が無ければ元のまま）。
    fn reassigned(&self, from: &UnapproveTarget) -> (SettingsKey, String) {
        self.declared_reassign
            .reserved
            .get(from)
            .cloned()
            .unwrap_or_else(|| (from.key, from.value.clone()))
    }

    /// 衝突を見る相手——いまの宣言全部と、**他の行で予約した付け替えた後の値**。
    /// 後者を数えないと、2つの行を同じ値へ付け替える予約が確定の時点まで通ってしまう。
    fn reassign_collision_targets(&self, from: &UnapproveTarget) -> Vec<UnapproveTarget> {
        let mut out = self.declared.clone();
        out.extend(
            self.declared_reassign
                .reserved
                .iter()
                .filter(|(other, _)| *other != from)
                .map(|(other, (key, value))| UnapproveTarget {
                    domain: other.domain.clone(),
                    key: *key,
                    value: value.clone(),
                }),
        );
        out
    }
}

/// 確認の画面の「付け替え」の部分。**断ったものと無かったものも理由ごと出す**（B-09）。
///
/// 権限が広がるものを先に別建てで出す——候補画面が「手で access を変えた候補」を別建てにするのと
/// 同じく、観測ではなく人の判断で広げたものを、書く前に読ませる（決定47）。
pub(crate) fn reassign_lines(plan: &ReassignPlan) -> Vec<String> {
    let mut lines = Vec::new();
    if !plan.changes.is_empty() {
        let widening = plan.changes.iter().filter(|c| c.widens).count();
        lines.push(format!(
            "付け替える宣言 {}件（うち権限が広がるもの {widening}件）:",
            plan.changes.len()
        ));
        // 広がるもの → 狭まるもの、の順。
        for widens in [true, false] {
            for change in plan.changes.iter().filter(|c| c.widens == widens) {
                lines.push(format!(
                    "  ~ [{}] {} {} → {} {}",
                    change.from.domain,
                    change.from.key.dotted(),
                    change.from.value,
                    change.to.key.dotted(),
                    change.to.value
                ));
                lines.push(format!(
                    "      {}{}",
                    if change.widens {
                        "権限が広がります。"
                    } else {
                        "権限は広がりません。"
                    },
                    if change.carries_approval {
                        "このマシンで承認済みのまま付け替えます"
                    } else {
                        "未承認のまま付け替えます（yで承認するまで許可は付きません）"
                    }
                ));
            }
        }
    }
    for (reassignment, reason) in &plan.refused {
        lines.push(format!(
            "  ✗ 付け替えない: [{}] {} {} → {} {}: {reason}",
            reassignment.from.domain,
            reassignment.from.key.dotted(),
            reassignment.from.value,
            reassignment.key.dotted(),
            reassignment.value
        ));
    }
    for reassignment in &plan.not_found {
        lines.push(format!(
            "  ? policy.jsonに無い: [{}] {} {}",
            reassignment.from.domain,
            reassignment.from.key.dotted(),
            reassignment.from.value
        ));
    }
    // 付け替えで遷移が広がるなら、その辺と呼び出し元が子を通して使えるようになる権限（決定66）。
    lines.extend(crate::exposure_view::lines(&plan.widening));
    if !plan.changes.is_empty() {
        lines.push(String::new());
        // 文言の持ち主は`reassign`（表示側で書き写さない）。
        lines.extend(reassign::ACE_NOTICE.lines().map(str::to_string));
    }
    if !lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
#[path = "declared_reassign_tests.rs"]
mod declared_reassign_tests;
