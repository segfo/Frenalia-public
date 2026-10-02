//! 送れる枠の位置と、ホイールがどの枠を送るかの当たり判定（2026-10-02、ユーザーが実機で見て希望した）。
//!
//! # 送れる枠は3種類あり、位置の持ち方と送る手段が違う
//!
//! | 枠 | 位置の持ち方 | 送る手段 |
//! |---|---|---|
//! | 記録画面の進行・コマンドの出力・起動時ノイズ | 下端からの距離（新着に追従する。`harness_term::scrollback`） | ホイール |
//! | 確認ダイアログ | 上端からの位置（`App::modal_scroll`） | `↑↓`・`PgUp/PgDn`・`Home/End`・ホイール |
//! | 説明欄とヘルプ（[`Panel`]） | 上端からの位置（[`PanelScroll`]） | ホイールだけ |
//!
//! 説明欄とヘルプを上端から持つのは、確認ダイアログと同じく**先頭から読ませる**枠だからである
//! （記録画面の3枠は新着を追うログなので下端から持つ）。描き方（送る上限・スクロールバー・下辺の
//! 「N〜M/T行」）は確認ダイアログと同じ部品（`tui::wrap::draw_scrollable`）を通る。
//!
//! # 説明欄はキーで送らない
//!
//! 承認待ち（FS/ネット・遷移）と宣言の画面では、説明欄が一覧と同じ画面にあり、`↑↓`・`PgUp/PgDn`は一覧の
//! 選択に使われている。記録画面ではそれらは空いているが、文字キーと`Home/End`は入力欄が食い、
//! そこだけ`PgUp/PgDn`を説明欄の送りにすると**同じキーが画面によって別の意味になる**（記録中は送れる枠が
//! 5つあり、どれを送るかもキーでは決まらない）。承認待ちのドメイン欄・遷移先の欄も入力中は文字キーを食う。
//! **4つの画面のどこでも同じ意味で効くキーが残っていない**ので、キーを足さずに済むホイールだけにした——
//! 記録画面の3枠も、`↑↓`が空いていたのにキーを足さずホイールだけを入れている（`tui::run`のイベントループの
//! コメント）。ヘルプも「何かキーを押すと閉じる」を変えず、ホイールでだけ送る。
//!
//! # 当たり判定は描いた枠そのもの（BUG-194）
//!
//! どの枠を送るかは、各画面の描画が**枠を描いたその矩形で**登録したもの（`tui::pointer::Targets`）から引く
//! （クリックと同じ登録。`tui::pointer`のモジュールdoc）。**当たり判定のために割り付けを写さない**——写すと、
//! 中身で高さが変わる説明欄の位置を2か所で揃え続けることになる。2026-10-02の夕方までは、イベントのたびに
//! 画面全体の割り付け（`tui::screen_rows`）と各画面の割り付けの関数を呼び直して枠の位置を出していた。
//! 同じ関数を通していたので位置は一致していたが、クリックを足すときに当たり判定を1つの登録へ寄せた。
//!
//! # 重ねた枠が開いている間は、ポインタの位置に関係なくその枠を送る
//!
//! キー入力もその間は重ねた側だけが受ける（`App::on_key`）。後ろの枠を送ると、見えないところで位置が変わり、
//! 閉じたときに読んでいた場所が失われる（BUG-194）。確認ダイアログとヘルプが両方開いているときは、上に描かれる
//! 確認ダイアログを送る（`tui::draw`はヘルプの後に確認ダイアログを描き、キーも確認ダイアログが先に受ける）。
//! 重ねた枠は描くときに画面全体を覆い（`Targets::cover`）、画面全体をその枠のホイールの場所として登録する。
//!
//! # 上限は描くまで分からない（BUG-076・BUG-196）
//!
//! 説明欄の行数は枠の幅で折り返した後の数なので、ホイールを受けた時点では送れる上限が決まらない。
//! [`PanelScroll::wheel`]は上限を掛けずに進め、描画が[`PanelLimits`]で上限を返し、
//! `App::apply_draw_feedback`が[`PanelScroll::clamp`]で切り詰める。**その描画で描かなかった説明欄の上限は0**
//! （[`PanelLimits`]の既定値）なので、画面を離れたりヘルプを閉じたりすると先頭へ戻る。記録画面の3枠も、
//! ほかの画面を描いている間は上限0（`record_screen::ScrollLimits`の既定値）で切り詰められて末尾へ戻るので、
//! 同じ振る舞いである。
//!
//! # 限界
//!
//! - **キーボードだけでは説明欄とヘルプを送れない**（マウスを使うか、端末を広げる）。
//! - 送れることを言うのは、入り切らない枠の下辺（「N〜M/T行  ホイールで送る」）とスクロールバーだけで、
//!   キー案内の行には出さない（送れるときに、その枠の上でだけ言う。キー案内の項目も増やさない）。

use crate::tui::record_screen::ScrollPane;
use crate::tui::state::App;

/// 送れる説明欄。**中身が別物の欄には別の値を割り当てる**（承認待ちの注記とプロセスツリーは同じ場所に
/// `t`で切り替えて出すが、位置を共有すると、切り替えた先が途中から始まる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    /// ヘルプ（`F4`）。画面に重ねる枠。
    Help,
    /// 記録画面の「実行するとどうなるか」（記録を始める前だけ出る）。
    RecordNotice,
    /// 記録画面の見出し枠（「いま待っているもの」／「終わりました」）。
    RecordHeader,
    /// 記録画面の警告枠（「⚠ 対応が要ります」）。
    RecordWarnings,
    /// 承認待ち（FS/ネット）の「記録の読み方」。
    EditNotes,
    /// 承認待ち（FS/ネット）の「観測したプロセス」（`t`で注記と切り替える）。
    EditProcessTree,
    /// 承認待ち（遷移の2タブ）の「この画面」。
    TransitionNotes,
    /// 宣言画面の「この画面」。
    DeclaredNotes,
}

impl Panel {
    /// 全部の説明欄。**宣言の順に並べる**（位置の配列の添字が宣言の順番だから。種類を足したらここにも足す）。
    pub const ALL: [Panel; 8] = [
        Panel::Help,
        Panel::RecordNotice,
        Panel::RecordHeader,
        Panel::RecordWarnings,
        Panel::EditNotes,
        Panel::EditProcessTree,
        Panel::TransitionNotes,
        Panel::DeclaredNotes,
    ];

    fn slot(self) -> usize {
        self as usize
    }
}

/// 説明欄の数。
const PANELS: usize = Panel::ALL.len();

/// ホイール1刻みで送る行数（端末の既定の送り量。記録画面の3枠・会話TUIと同じ値）。
const WHEEL_ROWS: u16 = harness_term::scrollback::WHEEL_SCROLL_LINES as u16;

/// 説明欄ごとの送り位置（枠の一番上に見せる、折り返した後の表示行）。既定は全部先頭。
///
/// **上限はここでは掛けない**——描くまで分からないため（モジュールdoc）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PanelScroll([u16; PANELS]);

impl PanelScroll {
    pub fn top(&self, panel: Panel) -> u16 {
        self.0[panel.slot()]
    }

    /// ホイール1刻み。`up`が真なら先頭の向き。
    pub fn wheel(&mut self, panel: Panel, up: bool) {
        wheel_top(&mut self.0[panel.slot()], up);
    }

    /// 直近の描画で分かった上限まで切り詰める。**描かなかった説明欄は0へ戻る**（モジュールdoc）。
    pub fn clamp(&mut self, limits: PanelLimits) {
        for (top, max) in self.0.iter_mut().zip(limits.0) {
            *top = (*top).min(max);
        }
    }
}

/// 1フレーム描いて分かった、説明欄ごとの送れる上限。**既定は全部0**（＝その描画で描かなかった）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PanelLimits([u16; PANELS]);

impl PanelLimits {
    pub fn set(&mut self, panel: Panel, max: u16) {
        self.0[panel.slot()] = max;
    }
}

/// 上端から持つ送り位置をホイール1刻みぶん動かす（説明欄と確認ダイアログが共有する）。`up`が真なら先頭の向き。
pub fn wheel_top(top: &mut u16, up: bool) {
    *top = if up {
        top.saturating_sub(WHEEL_ROWS)
    } else {
        top.saturating_add(WHEEL_ROWS)
    };
}

/// ホイールで送る枠。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    /// 確認ダイアログ（`App::modal_scroll`）。
    Modal,
    /// 説明欄かヘルプ（`App::panels`）。
    Panel(Panel),
    /// 記録画面の進行・出力・起動時ノイズ（`RunState`の`Scrollback`）。
    Record(ScrollPane),
}

impl App {
    /// ポインタの下の枠をホイール1刻み送る。どの枠かは`App::on_mouse`が描いた枠の登録から引いて渡す
    /// （モジュールdoc）。送る対象の無い場所では呼ばれない——「反応しない」ことは「壊れている」ではなく
    /// 「そこは送る対象ではない」であり、外した位置で別の枠が動くほうが混乱する。
    pub(crate) fn on_wheel(&mut self, target: Wheel, up: bool) {
        match target {
            Wheel::Modal => wheel_top(&mut self.modal_scroll, up),
            Wheel::Panel(panel) => self.panels.wheel(panel, up),
            Wheel::Record(pane) => {
                let Some(run) = self.run.as_mut() else {
                    return;
                };
                let scroll = match pane {
                    ScrollPane::Log => &mut run.log_scroll,
                    ScrollPane::Output => &mut run.output_scroll,
                    ScrollPane::Noise => &mut run.noise_scroll,
                };
                // 送り量は`harness_term::scrollback`が持つ（会話TUIと共通）。
                scroll.wheel(up);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **説明欄ごとに位置の置き場が1つずつある。** 位置は宣言の順番を添字にした配列で持つので、
    /// 種類を足して[`Panel::ALL`]に足し忘れると、配列の外を指して落ちる。
    #[test]
    fn every_panel_has_its_own_slot() {
        for (slot, panel) in Panel::ALL.into_iter().enumerate() {
            assert_eq!(panel.slot(), slot, "{panel:?}が宣言の順に並んでいない");
            // 種類を足すとここが網羅でなくなって落ちる。そのとき`Panel::ALL`にも足す。
            match panel {
                Panel::Help
                | Panel::RecordNotice
                | Panel::RecordHeader
                | Panel::RecordWarnings
                | Panel::EditNotes
                | Panel::EditProcessTree
                | Panel::TransitionNotes
                | Panel::DeclaredNotes => {}
            }
        }
    }

    /// **回した分を溜めない**（BUG-076）。上限を超えて回した分は描いた後に切り詰められ、
    /// 戻すときに空回りしない。描かなかった欄は先頭へ戻る。
    #[test]
    fn clamping_keeps_no_rows_beyond_the_limit_and_resets_panels_not_drawn() {
        let mut scroll = PanelScroll::default();
        for _ in 0..10 {
            scroll.wheel(Panel::DeclaredNotes, false);
            scroll.wheel(Panel::Help, false);
        }
        let mut limits = PanelLimits::default();
        limits.set(Panel::DeclaredNotes, 4);
        scroll.clamp(limits);
        assert_eq!(scroll.top(Panel::DeclaredNotes), 4);
        assert_eq!(
            scroll.top(Panel::Help),
            0,
            "描かなかった欄が先頭へ戻っていない"
        );

        scroll.wheel(Panel::DeclaredNotes, true);
        assert_eq!(scroll.top(Panel::DeclaredNotes), 4 - WHEEL_ROWS);
        scroll.wheel(Panel::DeclaredNotes, true);
        assert_eq!(scroll.top(Panel::DeclaredNotes), 0, "先頭より前へ行った");
    }
}
