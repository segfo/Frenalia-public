//! 確認ダイアログ（[`Modal`]）と、`y`を押したときに何を書くか（[`Confirm`]）。
//!
//! 2026-10-05に`tui::state`からそのまま移した（`state.rs`は本体1,000行を超えているので、確認の種類を
//! 足す前に置き場を分けた。`plans/position-domains/P4.md`のP4.2）。`y`・`p`を受けるのは`App::on_modal_key`
//! （`tui::state`。振り分けは1行で、中身は[`App::on_commit_key`]）、受けた後に種類ごとの書く処理を振り分けるのは
//! [`App::commit_confirmed`]（ここ。P4.5 の準備で`state.rs`から移した）、描くのは`tui::draw_modal`である。
//! `p`＝書いてパス2へ進む（[`AfterCommit`]）は 2026-10-07 に足した（`plans/position-domains/P6.md`の P6.7）。

use crate::tui::state::App;

/// 確認ダイアログ。**書く前に必ず差分を見せる**（`approve`のplan/commitの2段をUIで使う）。
///
/// 差分は一括選択で数百行になりうるので、**操作の案内は本文ではなく枠へ書く**
/// （本文の最後に置くと、収まらなかったときに`y`を押せばよいことが画面から消える）。
pub struct Modal {
    pub title: String,
    pub lines: Vec<String>,
    /// `y`を押したときに**何を書くのか**。
    pub confirm: Confirm,
}

/// 確認ダイアログの`y`が実行する操作。
///
/// # なぜ`bool`ではないのか
///
/// 以前は`confirm: bool`で、`y`は常に承認（`commit_approval`）を呼んでいた。書き込みの種類が
/// 2つ（承認と取り消し）になった時点で、`bool`では**どちらを書くのかがモーダルを開いた側の
/// 暗黙の文脈に消える**——取り消しの確認で`y`を押したら承認が走る、という取り違えが
/// 型では止まらなくなる。何を書くのかをモーダル自身に持たせる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// 読むだけ（エラー・報告）。`y`では何も起きず、Enterで閉じる。
    ReadOnly,
    /// 候補の承認（と、同時に予約された宣言の取り消し）を書く。編集画面の`a`。
    Approval,
    /// 宣言画面の`a`。**このマシンでの承認（`y`で予約した分）と宣言の取り消し（`Space`で予約した分）**を
    /// 書く。編集画面の`Approval`が承認と取り消しを1回で確定するのと同じ形にしてある。
    DeclaredChanges,
    /// [段階⑦] 遷移の宣言を足す／消す。承認待ち画面の遷移タブの`a`。
    ///
    /// **`Approval`と分けてあるのは、書く先も確認の文面も違うから**である
    /// （あちらは`fs`/`net`の宣言とACEの予告、こちらは`process`の辺と「ACLは変わらない」）。
    /// 1つにまとめると、確定の腕がどちらの意味だったか判別できなくなる。
    Transition,
    /// 宣言画面（`F3`）の遷移タブの`a`。**遷移の辺の取り消し**（遷移元ごと、書かれている辺そのもので指す）と、
    /// **Strict の印の付け外し**（`s`。P5.5）を1回の保存で書く（2026-10-05、`plans/position-domains/P4.md`のP4.2）。
    ///
    /// `Transition`と分けてあるのは、指し方と書く関数が違うから（あちらは入口のドメインの辺を`EdgeRef`で足す／消す、
    /// こちらは遷移元が何個でも`transition_approve::plan_removals`で消すだけ）。
    DeclaredTransitions,
    /// 位置ごとのドメインの記録の`a`（承認待ちのどのタブからでも）。**ドメインごとのファイルの宣言・位置の辺・拒否からの
    /// 予約・取り消し・却下印を1回の確定で書く**（2026-10-05、`plans/position-domains/P4.md`のP4.5。
    /// `crate::position_approve`）。
    ///
    /// `Approval`・`Transition`と分けてあるのは、書く関数が違い（`policy.json`を1回だけ保存する）、確認の文面に
    /// 自己ループ辺の置き換えが出るから（`y`は置き換えへの同意でもある。決定65 Q7）。
    Position,
}

impl Confirm {
    /// `y`/`n`を聞く形か（枠の色と案内文が使う）。
    pub fn asks(self) -> bool {
        !matches!(self, Confirm::ReadOnly)
    }
}

impl Confirm {
    /// `p`（書いてパス2へ進む）を受けるか。ファイルの確定と位置の確定だけ（決定68(3)）——残る4種は書いた後にパス2へ
    /// 進む理由が無い（読むだけ・このマシンでの承認や取り消し・遷移の辺だけ）。**`_`を書かない**（種類を足した日に選ばされる）。
    pub fn offers_pass2(self) -> bool {
        match self {
            Confirm::Approval | Confirm::Position => true,
            Confirm::ReadOnly
            | Confirm::DeclaredChanges
            | Confirm::Transition
            | Confirm::DeclaredTransitions => false,
        }
    }
}

/// 確定の後にどこへ行くか（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定68(3)）。
///
/// **確定の既定は暫定（決定68）**——`y`＝[`AfterCommit::Stay`]を既定にしたのは「連続して承認する」使い方と「承認1回で
/// パス2へ進みたい」使い方の両方があり、どちらを既定にするかは使ってから決めるため。変える箇所はここ（[`App::on_commit_key`]の
/// キーの振り分け）・確認ダイアログのボタン（`tui::draw_modal`）・ヘルプの1行で、どれも同じ綴りで`rg`に当たる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterCommit {
    /// 書いて、承認待ちの画面に留まる（`y`）。
    Stay,
    /// 書いて、記録画面に次のパス2を用意する（`p`。Enter で始める）。
    Pass2,
}

/// `y`で書いて留まったときの知らせの末尾（ファイルの確定と位置の確定が同じこれを付ける）。
pub(crate) const PASS2_HINT: &str = "（p で書くとパス2へ進みます）";

impl App {
    /// 確認ダイアログの`y`・`p`（`App::on_modal_key`が振り分ける）。`p`は[`Confirm::offers_pass2`]のダイアログでだけ書き、
    /// 他のダイアログでは何もしない（閉じもしない）。読むだけのダイアログでは`y`も何もしない。
    pub(crate) fn on_commit_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;
        let Some(kind) = self.modal.as_ref().map(|m| m.confirm).filter(|k| k.asks()) else {
            return;
        };
        let after = match code {
            KeyCode::Char('y' | 'Y') => AfterCommit::Stay,
            KeyCode::Char('p' | 'P') if kind.offers_pass2() => AfterCommit::Pass2,
            _ => return,
        };
        self.modal = None;
        self.modal_scroll = 0;
        // **何を書くのかはモーダルが持っている**（開いた画面を推測しない）。
        self.commit_confirmed(kind, after);
    }

    /// 確認ダイアログで`y`（`p`）が押されたとき、ダイアログが持つ種類（[`Confirm`]）の書く処理を呼ぶ。`after`を使うのは
    /// [`Confirm::offers_pass2`]の2種だけ。
    ///
    /// **`_`を書かない**——種類を足した日に、ここで書く処理を必ず選ばされる。
    pub(crate) fn commit_confirmed(&mut self, kind: Confirm, after: AfterCommit) {
        match kind {
            Confirm::Approval => self.commit_approval(after),
            Confirm::DeclaredChanges => self.commit_declared_changes(),
            Confirm::Transition => self.commit_transition(),
            Confirm::DeclaredTransitions => self.commit_declared_transition_removals(),
            Confirm::Position => self.commit_position(after),
            Confirm::ReadOnly => {}
        }
    }
}

#[cfg(test)]
#[path = "modal_tests.rs"]
mod modal_tests;
