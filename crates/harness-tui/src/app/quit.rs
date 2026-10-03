//! `Esc`を1秒以内に2回で閉じる（2026-10-03、ユーザー「コピーするために`Ctrl+C`を何回も押しちゃうと終了しちゃうから、
//! `Esc`を2回で終了できるようにしたい。ポリシーエディタも同じ仕組みにしてほしい」）。判定と窓の長さはポリシーエディタと
//! 共有する`harness_term::double_esc`が持ち、決めたことの正本は`plans/POLICY-EDITOR-TOMOYO-DIG.md`の
//! 「終了の操作を`Esc`の二度押しにそろえた」。
//!
//! # どの`Esc`を数えるか
//!
//! `Esc`はいちばん内側のものから効く。**数えるのは、そのどれにも当たらなかった`Esc`だけ**で、当たった`Esc`は数え直しに
//! なる（止めたつもりで2回押した人が終了に転ばない——ポリシーエディタの「記録中の`Esc`は数えない」と同じ理由）。
//!
//! 1. 選んでいる文章を外す（`app::select`）
//! 2. 承認ダイアログ（拒否・戻る。開いた直後の300msに捨てた`Esc`も含む——ダイアログが受けたキー）
//! 3. レビューパネルを閉じる
//! 4. 走っている応答・`/compact`の要約を止める（[`AppState::can_cancel`]）
//! 5. **どれでもない → 二度押しの1回目・2回目**（[`AppState::count_quiet_esc`]）
//!
//! 数え直しは経路ごとに書かない。キーを受けるたびに入口（`AppState::on_key_at`）が1回目を取り出して捨てた状態にし、
//! 5だけが戻す——経路を足しても、書き忘れた経路は「数え直し」の側に倒れる。`Esc`以外のキーも同じく数え直しになり、
//! クリック（押す場所を押したとき・文章を押したとき）も数え直す（`app::pointer`・`app::select`）。
//!
//! # 知らせ
//!
//! 1回目でtranscriptの枠の上辺に「もう一度 Esc を押すと終了します（1秒以内）」を出し（写した結果と同じ場所。
//! [`super::EdgeNotice`]）、窓が過ぎたら消す（[`AppState::tick`]）。`Ctrl+C`を選ばずに押したときは同じ場所に
//! 「終了は Esc を2回」を出す（`app::select`）。入力欄の見出しの`Esc×2=終了`は、数えられる間だけ出す
//! （[`AppState::input_key_hints`]）。
//!
//! # 限界
//!
//! - **応答が中断を受け付けずに走り続けると、`Esc`は毎回中断に使われ、終了に数えられない。** 以前は`Ctrl+C`で抜けられた
//!   ——この画面に、走っているものを止めずに閉じるキーは無い（ポリシーエディタは記録中の終了に`Ctrl+Q`を持つ）。
//! - セッションのピッカー（`crate::picker`）は別のループで、`Esc`はピッカーを閉じて会話画面へ戻る（数えない——閉じた
//!   `Esc`は他の働きをした`Esc`）。ピッカーの`Ctrl+C`は以前から何もしない。
//! - 端末の大きさが小さく、重ねた枠がtranscriptの上辺まで覆っているときは知らせが見えない（写した結果と同じ）。

use std::time::Instant;

use harness_term::double_esc::{armed_notice, DoubleEsc};

use super::{Action, AppState, EdgeNotice};

impl AppState {
    /// いま`Esc`を押したら、二度押しに数えられるか（重ねた枠も止めるものも無い）。入力欄の見出しの`Esc×2=終了`を出すかを
    /// 決める（効く操作を案内する、B-32）。**数える側の判定はこれを使わない**（`on_key_after_selection`の分岐の順そのもの）
    /// ——ずれていないことは試験`the_quit_hint_is_shown_only_where_two_escapes_quit`が固定する。選んでいる文章は見ない
    /// （選んでいる間は見出しが`Ctrl-C=コピー`になる）。
    pub(super) fn esc_would_count(&self) -> bool {
        self.pending_permission.is_none() && self.review_panel.is_none() && !self.can_cancel()
    }

    /// 何もしていない`Esc`を`now`に押した（モジュールdocの5）。2回目なら終了、1回目なら覚えて知らせを出す。
    /// `esc`は入口で取り出した1回目（`AppState::on_key_at`）。
    pub(super) fn count_quiet_esc(&mut self, mut esc: DoubleEsc, now: Instant) -> Option<Action> {
        if esc.press(now) {
            self.should_quit = true;
            return Some(Action::Quit);
        }
        self.double_esc = esc;
        self.edge_notice = Some(EdgeNotice::hint(armed_notice()));
        None
    }

    /// 窓が過ぎた1回目を捨て、1回目の知らせが出たままなら消す（描画の合図ごと。`AppState::tick_at`）。
    pub(super) fn expire_quiet_esc(&mut self, now: Instant) {
        if self.double_esc.expire(now)
            && self
                .edge_notice
                .as_ref()
                .is_some_and(|notice| notice.text == armed_notice())
        {
            self.edge_notice = None;
        }
    }
}

// 試験は`quit_tests.rs`（描き方・押し方の道具を使うので、`select_tests`と同じく`pointer_tests`の子）。
