//! [段階⑦] 承認待ち画面（`F2`）の遷移タブの**遷移先ドメインの欄**（2026-10-01）。
//!
//! ```text
//!   ┌ 遷移先ドメイン（Tab で編集） ───────────────────────────┐
//!   │ workspace-shell     同じドメインの中で起こす（用意は要らない） │
//!   └──────────────────────────────────────────────────────┘
//! ```
//!
//! # 欄は1つで、1回の確定の全部の辺に効く
//!
//! 承認待ちの「FS/ネット」タブのドメイン欄が「この承認で書くドメイン」を1つ持ち、`Tab`で入って
//! `Enter`で戻るのと**同じ形**にした（決定62: 出どころが違っても操作系をそろえる）。
//! 別々の遷移先へ分けたいときは、遷移先を変えて確定を2回に分ける。
//!
//! # 欄は空で始まる（2026-10-05、決定65）
//!
//! かつては最初から[`ENTRY_DOMAIN`]（呼び出し元）が入っていて、欄に触らずに確定した辺はすべて
//! 自己ループ辺になった。自己ループ辺は深さを区別しなくなる書き方で、決定65(3)で凍結したので、
//! 欄は空で始める。呼び出し元と同じ名前を入れると欄の横に理由を出し、確定は
//! [`crate::transition_approve::plan`]が書く前に断る（**判定はそこ1か所**。欄は見せるだけ）。
//! 別ドメインは利用者が名前を入れたときだけ書く——**承認は常に利用者の明示操作**（D-42）。
//!
//! # ここが持たないもの
//!
//! - **用意される見込み**: [`crate::transition_destination`]（`harness.exe`と同じ付与の関数を通す）
//! - **書けるかの最終判断**: [`crate::transition_approve::plan`]（名前の検査・編集時検査）

use crossterm::event::{KeyCode, KeyEvent};

use harness_policy::policy_file::ENTRY_DOMAIN;
use harness_sandbox::tier2a::domain_profile_name_problem;

use crate::transition_approve::TransitionPlan;
use crate::transition_destination::Outlook;
use crate::tui::state::{edit_text, App, Screen};
use crate::tui::text_input::TextInput;

/// 遷移先ドメインの欄。
#[derive(Debug)]
pub struct DestinationField {
    pub input: TextInput,
    /// 欄に入っている（文字キーが名前の入力になる）。
    pub focused: bool,
}

impl Default for DestinationField {
    fn default() -> Self {
        Self {
            input: TextInput::new(""),
            focused: false,
        }
    }
}

impl DestinationField {
    /// 書く遷移先の名前（前後の空白は落とす。FS/ネットタブのドメイン欄と同じ）。
    pub fn name(&self) -> &str {
        self.input.text().trim()
    }
}

impl App {
    /// `Tab`: 一覧から遷移先の欄へ入る。
    pub(crate) fn focus_destination(&mut self) {
        self.pending.destination.focused = true;
        self.status = "遷移先ドメインの名前を入れてください（Enter か Tab で一覧へ戻る）".to_string();
    }

    /// 遷移先の欄に居るときのキー。**1文字キーを操作に取らない**（`a`が確定になると名前が打てない）。
    pub(crate) fn on_destination_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab => {
                self.pending.destination.focused = false;
                self.status = format!(
                    "遷移先: {}（{}）",
                    self.pending.destination.name(),
                    self.destination_label()
                );
            }
            // 入力欄に居ても画面を離れられるようにする（FS/ネットタブのドメイン欄と同じ）。
            KeyCode::Esc => self.screen = Screen::Record,
            _ => edit_text(&mut self.pending.destination.input, key),
        }
    }

    /// いまの遷移先の見込み。**表を引くだけで台帳を読まない**（表は[`App::reload_transitions`]が
    /// 作り直す）——描画のたびに承認台帳を読まないため。
    ///
    /// `policy.json`に無い名前は「宣言の無いドメイン」として答える（確定すると作るため）。
    pub fn destination_outlook(&self) -> Outlook {
        outlook_from_table(&self.pending, self.pending.destination.name())
    }

    /// 遷移先の名前の問題（空・呼び出し元と同じ＝自己ループ辺・入れ物の名前にできない）。
    ///
    /// 自己ループ辺の判定は**見せるためだけ**にここでも引く——書くかどうかは
    /// [`crate::transition_approve::plan`]が決める（`SelfLoopFrozen`）。
    fn destination_name_problem(&self) -> Option<String> {
        let name = self.pending.destination.name();
        if name.is_empty() {
            return Some("空です。名前を入れてください".to_string());
        }
        if name == ENTRY_DOMAIN {
            return Some(
                "呼び出し元と同じドメインです。自己ループ辺は凍結中のため書けません（決定65）"
                    .to_string(),
            );
        }
        domain_profile_name_problem(name).map(|problem| format!("この名前は使えません: {problem}"))
    }

    /// 遷移先の欄を目立たせるか（名前に問題がある・用意されない見込み）。
    pub fn destination_needs_attention(&self) -> bool {
        self.destination_name_problem().is_some() || !self.destination_outlook().is_provisioned()
    }

    /// 遷移先の欄と状態行に出す一言。**名前にできないなら、それを先に言う**。
    pub fn destination_label(&self) -> String {
        let name = self.pending.destination.name();
        if let Some(problem) = self.destination_name_problem() {
            return problem;
        }
        let mut label = self.destination_outlook().short_label();
        if name != ENTRY_DOMAIN && !self.pending.outlooks.contains_key(name) {
            label.push_str("。policy.json に無いので、確定すると宣言の無いドメインとして作ります");
        }
        label
    }

    /// 確定の直前に、足す辺の遷移先について言うこと（**何が起きるかを全部**）。
    pub(crate) fn destination_notice_lines(&self, plan: &TransitionPlan) -> Vec<String> {
        let mut lines = Vec::new();
        if plan.created_to_domain {
            lines.push(format!(
                "遷移先ドメイン {} は policy.json に無いので、宣言の無いドメインとして作ります。",
                plan.to_domain
            ));
        }
        lines.extend(self.outlook_notice_lines(&plan.to_domain));
        lines
    }

    /// 遷移先`to_domain`を`harness.exe`が用意する見込みの説明（表を引くだけ）。平らな一覧の確定と、位置ごとのドメインの
    /// 確定（`tui::position_commit`。拒否からの予約の遷移先）が同じこれを出す。
    pub(crate) fn outlook_notice_lines(&self, to_domain: &str) -> Vec<String> {
        outlook_from_table(&self.pending, to_domain).notice_lines(to_domain)
    }

    /// 足す辺があるのに遷移先が空なら、理由を言って`None`（**何も書かない**。`B-32`）。
    pub(crate) fn destination_for_commit(&mut self, adding: bool) -> Option<String> {
        let name = self.pending.destination.name().to_string();
        if adding && name.is_empty() {
            self.status =
                "遷移先ドメインが空です（Tab で欄へ移って、呼び出し元と別のドメイン名を入れてください）"
                    .to_string();
            return None;
        }
        Some(name)
    }
}

/// 表から見込みを引く（呼び出し元と同じなら自己ループ、表に無ければ宣言の無いドメイン）。
fn outlook_from_table(pending: &crate::tui::transition::PendingState, name: &str) -> Outlook {
    if name == ENTRY_DOMAIN {
        return Outlook::SameDomain;
    }
    pending
        .outlooks
        .get(name)
        .cloned()
        .unwrap_or(Outlook::Provisioned { declarations: 0 })
}
