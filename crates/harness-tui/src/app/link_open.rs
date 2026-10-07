//! transcriptのリンクを開く——押したリンクを開いてよいかを決めて[`Action::OpenUrl`]を返し、開いた結果を知らせる
//! （計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§3.3〜§3.5・§0のT11b）。開く呼び出しそのもの（`ShellExecuteW`）と
//! 開いてよいURLの型は`crate::open_url`、どのリンクを指しているかは`app::link_hover`、吹き出しの押す場所は
//! `crate::ui`の`link_tooltip`が持つ。
//!
//! # 開く操作は2つ
//!
//! - **リンクの文字の`Ctrl`＋クリック**。修飾キーが見えるのはマウスの事象を受け取る`AppState::on_mouse`だけ
//!   （押せる場所の地図`harness_term::pointer::Targets::resolve`は修飾キーを見ない）なので、そこで決める——地図を引いて
//!   **transcriptの文字の上**（普通のクリックなら範囲選択を始める所）と分かったときだけ、押したセルのリンク
//!   （[`AppState::link_at_cell`]。吹き出しを出すのと同じ関数を、直前に描いた画面で引く）を開く押し方
//!   （[`Click::OpenLink`]）に変える。押せる場所は今までどおり文字より先に当たる。リンクの文字は押せる場所として
//!   登録しない（登録すると普通のクリックで範囲選択を始められなくなる。計画書§3.3）。
//! - **吹き出しのURLのクリック**。吹き出しを描くときに、下線を付けたURLの部分を押せる場所として登録する
//!   （開ける形式のときだけ）。
//!
//! どちらも[`Click::OpenLink`]（書かれたままのリンク先）として`on_click`を通り、ここの[`AppState::open_link`]1つで
//! 開いてよいかを決める——吹き出しが押せる場所を登録したことを、開いてよい証拠にしない（判定を呼び出し側の作法に
//! 任せない。B-20）。押せる場所を押したのと同じく、選んでいた文章は外れ、範囲選択は始まらない。
//!
//! # 普通のクリックは今までどおり
//!
//! リンクの上でも範囲選択を始める（計画書§3.1）。リンクでない文字の`Ctrl`＋クリックも今までどおり範囲選択を始める。
//!
//! # 開かないもの
//!
//! - http/https以外の形式とスキームの無い相対URL（`crate::open_url`）。吹き出しには「開けない形式」と書いて押せる場所に
//!   しない。リンクの文字を`Ctrl`＋クリックしたときは、開かない理由をtranscriptの枠の上辺に出す（黙って何もしないと
//!   壊れて見える。B-10）。
//! - 承認ダイアログ・レビューパネルが開いている間（吹き出しを出さないので、URLを見ないまま開くことになる。
//!   `app::link_hover`の「出さないとき」）。外に見えているtranscriptの`Ctrl`＋クリックは今までどおり範囲選択を始める。
//!
//! # 知らせ
//!
//! 開いた結果（[`AppState::note_opened`]）は、写した結果と同じtranscriptの枠の上辺に、同じ色の使い分けで出す
//! （`app::select`の「知らせを出す場所」）。写した結果と同じく成功も出す。

use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use harness_term::pointer::Pointer;

use super::{Action, AppState, Click, EdgeNotice, Wheel};
use crate::open_url::{self, OpenableUrl};

impl AppState {
    /// 押したリンク（書かれたままのリンク先`raw`）を開く操作。開いてよい形式なら[`Action::OpenUrl`]、そうでなければ
    /// 開かない理由を知らせて`None`（モジュールdoc「開かないもの」）。
    pub(super) fn open_link(&mut self, raw: &str) -> Option<Action> {
        match OpenableUrl::parse(raw) {
            Ok(url) => Some(Action::OpenUrl(url)),
            Err(reason) => {
                tracing::debug!(%raw, %reason, "link not opened");
                self.edge_notice = Some(EdgeNotice::hint(open_url::refused_notice(raw)));
                None
            }
        }
    }

    /// `Ctrl`＋左ボタンでtranscriptの文字の上を押したなら、押したセルのリンクを開く押し方に変える（モジュールdoc
    /// 「開く操作は2つ」）。`pointed`は直前に描いた画面の地図で引いた結果。それ以外はそのまま返す。
    pub(super) fn ctrl_press_on_link(
        &self,
        event: &MouseEvent,
        pointed: Option<Pointer<Click, Wheel>>,
    ) -> Option<Pointer<Click, Wheel>> {
        let ctrl_press = event.kind == MouseEventKind::Down(MouseButton::Left)
            && event.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl_press && matches!(pointed, Some(Pointer::Text(Wheel::Transcript))) {
            let link = self.link_at_cell(
                (event.column, event.row),
                self.links.overlaid,
                &self.pointer,
                &self.links.links,
            );
            if let Some(link) = link {
                return Some(Pointer::Click(Click::OpenLink(link.url().to_string())));
            }
        }
        pointed
    }

    /// 開いた結果（イベントループが開いた後に呼ぶ。`crate::open_url::open_and_note`）。
    pub fn note_opened(&mut self, url: &OpenableUrl, result: Result<(), String>) {
        self.edge_notice = Some(EdgeNotice::outcome(open_url::notice(url, &result), &result));
    }
}
