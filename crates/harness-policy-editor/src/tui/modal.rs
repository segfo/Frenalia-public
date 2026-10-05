//! 確認ダイアログ（[`Modal`]）と、`y`を押したときに何を書くか（[`Confirm`]）。
//!
//! 2026-10-05に`tui::state`からそのまま移した（`state.rs`は本体1,000行を超えているので、確認の種類を
//! 足す前に置き場を分けた。`plans/position-domains/P4.md`のP4.2）。`y`を受けて書く処理を振り分けるのは
//! `App::on_modal_key`（`tui::state`）、描くのは`tui::draw_modal`である。

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
    /// 宣言画面（`F3`）の遷移タブの`a`。**遷移の辺の取り消し**（遷移元ごと、書かれている辺そのもので指す）を書く
    /// （2026-10-05、`plans/position-domains/P4.md`のP4.2）。
    ///
    /// `Transition`と分けてあるのは、指し方と書く関数が違うから（あちらは入口のドメインの辺を`EdgeRef`で足す／消す、
    /// こちらは遷移元が何個でも`transition_approve::plan_removals`で消すだけ）。
    DeclaredTransitions,
}

impl Confirm {
    /// `y`/`n`を聞く形か（枠の色と案内文が使う）。
    pub fn asks(self) -> bool {
        !matches!(self, Confirm::ReadOnly)
    }
}
