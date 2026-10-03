//! `Esc`の二度押しで画面を閉じる（2026-10-03。会話TUIとポリシーエディタが共有）。
//!
//! ユーザーの依頼（2026-10-03）:「コピーするために`Ctrl+C`を何回も押しちゃうと終了しちゃうから、`Esc`を2回で終了できるように
//! したい。ポリシーエディタも同じ仕組みにしてほしい」。それまで会話画面の`Ctrl+C`は即終了で、ポリシーエディタは`Esc`の
//! 二度押しと`Ctrl+C`の両方で終了していた。いまは**どちらの画面も`Ctrl+C`を終了に使わない**（選んでいる文章を写すだけ。
//! `select`）。決めたことの正本は`plans/POLICY-EDITOR-TOMOYO-DIG.md`の「終了の操作を`Esc`の二度押しにそろえた」。
//!
//! # 規則（2つの画面で同じ。だから判定と窓の長さをここに1つだけ持つ）
//!
//! - **[`WINDOW`]（1秒）以内に2回。** ちょうど1秒は内側（終了する）。
//! - **数えるのは、他の働きをしなかった`Esc`だけ。** 選択を外した・重ねた枠（承認ダイアログ・レビューパネル・確認ダイアログ・
//!   ヘルプ）を閉じた・応答や記録を止めた`Esc`は、数え直しになる——止めたつもりで2回押した人が終了に転ばない
//!   （ポリシーエディタの決定52「記録中の`Esc`は数えない」と同じ理由）。どの`Esc`が「他の働きをした」かは画面ごとに違う
//!   ので、呼び出し側が決める（数えるときだけ[`DoubleEsc::press`]を呼び、それ以外は[`DoubleEsc::reset`]）。
//! - **`Esc`以外のキーとクリックが挟まったら数え直す**——挟まっても生き残る作りにすると、無関係な操作のあとの`Esc`1回で
//!   突然終了する。
//! - **1回目で、もう一度押せば終了することを知らせる**（[`armed_notice`]）。窓が過ぎたら知らせを消す（[`DoubleEsc::expire`]）。
//! - **`Ctrl+C`で何も選んでいないときは、終了の仕方を知らせる**（[`CTRL_C_NOTICE`]。押しても無反応にしない、B-23(c)）。
//!
//! 時刻は外から渡す（`button::Press`と同じ。試験は時刻を作って渡し、実時間で待たない）。
//!
//! # 限界
//!
//! - 端末の生モードでは`Ctrl+C`はシグナルではなくキーとして届く（`TerminalGuard`）。イベントループが止まっているときは、
//!   以前の`Ctrl+C`もこの二度押しも効かない——そこは変わらない。
//! - **`Esc`がずっと他の働きをし続ける間は終了できない。** 会話画面で、中断を受け付けずに走り続ける応答があると、`Esc`は
//!   毎回中断に使われて数えられない（以前は`Ctrl+C`で抜けられた）。ポリシーエディタの記録中は、`Ctrl+Q`が撤収を待って
//!   閉じる（`Esc`は停止）。

use std::time::{Duration, Instant};

/// 2回目の`Esc`を待つ長さ。**この値の持ち主はここ1つ**（知らせの文言もここから作る）。
pub const WINDOW: Duration = Duration::from_secs(1);

/// `Ctrl+C`を押したが写せる文章が無いときの知らせ（モジュールdoc）。
pub const CTRL_C_NOTICE: &str =
    "選んでいる文章がありません——Ctrl+C はコピーだけで、終了は Esc を2回です";

/// 1回目の`Esc`の後に出す知らせ（モジュールdoc）。窓の長さは[`WINDOW`]から作る。
pub fn armed_notice() -> String {
    format!(
        "もう一度 Esc を押すと終了します（{}秒以内）",
        WINDOW.as_secs()
    )
}

/// `previous`に押した`Esc`の後、`now`に押した`Esc`が2回目に当たるか（[`WINDOW`]の中。境目は内側）。
pub fn is_double(previous: Option<Instant>, now: Instant) -> bool {
    previous.is_some_and(|first| now.saturating_duration_since(first) <= WINDOW)
}

/// `Esc`の二度押しの数え方（1回目を押した時刻だけを持つ）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DoubleEsc {
    first: Option<Instant>,
}

impl DoubleEsc {
    /// 他の働きをしなかった`Esc`を`now`に押した。2回目（[`WINDOW`]の中）なら`true`を返して数え直す。そうでなければ
    /// `now`を1回目として覚えて`false`（窓の外の2回目は、新しい1回目になる）。
    pub fn press(&mut self, now: Instant) -> bool {
        if is_double(self.first, now) {
            self.first = None;
            true
        } else {
            self.first = Some(now);
            false
        }
    }

    /// 数え直す（`Esc`以外のキー・クリック・他の働きをした`Esc`）。
    pub fn reset(&mut self) {
        self.first = None;
    }

    /// 1回目を押していて、`now`はまだ2回目を待っている窓の中か。
    pub fn is_armed(&self, now: Instant) -> bool {
        is_double(self.first, now)
    }

    /// 窓が過ぎた1回目を捨てる。捨てたら`true`——呼び出し側は1回目の知らせ（[`armed_notice`]）を消す。
    pub fn expire(&mut self, now: Instant) -> bool {
        if self.first.is_some() && !self.is_armed(now) {
            self.first = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// **窓の中の2回目で`true`、境目（ちょうど[`WINDOW`]）も内側。** 1回目は`false`。
    #[test]
    fn a_second_press_inside_the_window_is_the_double() {
        let t0 = Instant::now();
        let mut esc = DoubleEsc::default();
        assert!(!esc.press(t0), "1回目で終了した");
        assert!(esc.press(t0 + WINDOW), "境目の2回目が数えられない");
        // 数え直しているので、続けてもう1回押しても終了しない（3回目は新しい1回目）。
        assert!(!esc.press(t0 + WINDOW + MS));
    }

    /// **窓の外の2回目は終了せず、新しい1回目になる**（その後の窓の中の押下で終了する。禁止側と許可側の対）。
    #[test]
    fn a_second_press_outside_the_window_starts_over() {
        let t0 = Instant::now();
        let mut esc = DoubleEsc::default();
        esc.press(t0);
        let late = t0 + WINDOW + MS;
        assert!(!esc.press(late), "窓の外の2回目で終了した");
        assert!(esc.is_armed(late), "窓の外の2回目が新しい1回目にならない");
        assert!(esc.press(late + WINDOW));
    }

    /// **数え直したら、次の`Esc`は1回目。**
    #[test]
    fn reset_starts_over() {
        let t0 = Instant::now();
        let mut esc = DoubleEsc::default();
        esc.press(t0);
        esc.reset();
        assert!(!esc.is_armed(t0));
        assert!(!esc.press(t0), "数え直したのに2回目に数えた");
    }

    /// **窓の中は捨てず、過ぎたら1度だけ捨てる**（知らせを消す合図は1回。1回目を押していないときは何もしない）。
    #[test]
    fn expire_drops_only_a_first_press_whose_window_has_passed() {
        let t0 = Instant::now();
        let mut esc = DoubleEsc::default();
        assert!(!esc.expire(t0), "押していないのに捨てた");
        esc.press(t0);
        assert!(!esc.expire(t0 + WINDOW), "窓の中で捨てた");
        assert!(esc.is_armed(t0 + WINDOW));
        assert!(esc.expire(t0 + WINDOW + MS));
        assert!(!esc.expire(t0 + WINDOW + MS), "2度捨てた");
        assert!(!esc.press(t0 + WINDOW + MS), "捨てた1回目で終了した");
    }

    /// 知らせは窓の長さをこの値から作る（文言へ数字を複製しない、B-05）。
    #[test]
    fn the_notice_states_the_window() {
        assert!(armed_notice().contains(&format!("{}秒", WINDOW.as_secs())));
        assert!(CTRL_C_NOTICE.contains("Esc を2回"));
    }
}
