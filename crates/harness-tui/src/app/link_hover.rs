//! transcriptのリンクの上にマウスがある間、リンクの直後に`(URL)`の吹き出しを重ねて出す（計画書
//! `plans/PLAN-TUI-IMPROVEMENTS.md`§3・§0のT11a）——**どのリンクを指しているかを決める**側。描くのは`crate::ui`の
//! `link_tooltip`。
//!
//! # 何のためにあるのか
//!
//! リンクの文字は青の下線で描き、URLは文中に出さない（計画書§0.1の決定）。どこへ飛ぶリンクかを、指したときだけ見せる。
//! 文中へ差し込まず重ねて描くのは、transcriptが下端を基準に送るので、行が増えるとリンクがマウスの下から外れて
//! ちらつき、近くの範囲選択も外れるため（計画書§3.2）。
//!
//! # 決め方——マウスの位置だけを覚え、描くたびに引き直す
//!
//! 覚えるのは**最後に届いたマウスの事象のセル**（`AppState::mouse_cell`）だけで、どのリンクを指しているかは描くたびに、
//! その描画の文字の地図（`harness_term::pointer::Targets::text_at`）とリンクの区間で引き直す。範囲選択のドラッグの端
//! （`harness_term::select`の`Head::Pointer`）と同じ形で、流れ込みで文字が動いても・送っても、止まったマウスの下の
//! リンクを指す（吹き出しは文字について動くか、消える）。
//!
//! 引くのは[`AppState::hovered_link`]の1つだけ。描画（`crate::ui::render`）は**これから描く画面**の地図とリンクで、
//! マウスの事象（[`AppState::hovered_link_changed`]）は**直前に描いた画面**の分（[`LinkFrame`]）で引く——同じ関数を
//! 通すので、描いた吹き出しと再描画の合図の判定が食い違わない。
//!
//! # 再描画の合図
//!
//! ボタンを押さない移動（`Moved`）は今まで「何も変わっていない」で、描き直さなかった（マウスを動かすたびに描き続けない
//! ため。`app::pointer`）。いまは**指しているリンクが直前に描いた画面と変わったときだけ**描き直しの合図を返す。同じリンクの
//! 中を動く・リンクの無い所を動くのは今までどおり描き直さない。合図を返さなくても、33msごとの描画（`crate::run`の
//! `TICK`）が引き直すので、遅れても1フレームで追いつく。
//!
//! # 吹き出しの上にマウスがある間は、出したまま
//!
//! 吹き出しのURLは計画書のT11bで押せる場所になる（押すと開く）。リンクの文字から吹き出しへ動かす間に消えないよう、
//! **直前に描いた吹き出しの矩形の上なら、同じリンクを指している**とみなす（そのリンクがまだ画面にある間）。
//!
//! # 出さないとき
//!
//! - 承認ダイアログ・レビューパネルが開いている間（`crate::ui::render`が重ねる枠を描いた画面）。後ろに見えている
//!   transcriptのリンクを指しても出さない
//! - 文章の上で左ボタンを押している間（選んでいる途中）——選んでいる文字を隠さない。入力欄の選択中は端末のカーソルを
//!   置かない（`crate::ui::render`）のと同じく、選んでいる範囲を見せるのを先にする
//!
//! # 限界
//!
//! - **マウスが端末の外へ出たことは届かない**（crosstermに知らせが無い）。リンクの上から端末の外へ出ると、最後のセルの
//!   リンクの吹き出しが残る（中へ戻って動かせば引き直す）
//! - 吹き出しはその下の文字を隠す（計画書§1.7）
//! - 端末がボタンを押さない移動を届けないと（計画書のT10でまだ測っていない端末）、ホイールやクリックをしたときにしか出ない
//! - 対象はassistantの返答のリンクだけ（リンクの区間を返すのは整形する実装だけ。`crate::markdown`）

use harness_term::select::Pos;
use ratatui::layout::{Position, Rect};

use super::{AppState, Targets, Wheel};
use crate::markdown::LinkSpan;

/// 指しているリンク——折り返しで分かれた区間（[`LinkSpan::continues`]でつながる区間。行の順）をまとめた1つのリンク。
/// **同じリンクかどうかはこの値で比べる**（URLと、transcriptの中の位置。区間の全部）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HoveredLink(Vec<LinkSpan>);

impl HoveredLink {
    /// リンク先。
    pub(crate) fn url(&self) -> &str {
        &self.0[0].url
    }

    /// 区間（行の順。1つ以上）。
    pub(crate) fn parts(&self) -> &[LinkSpan] {
        &self.0
    }
}

/// 1フレーム描いて分かったリンクのこと（`DrawFeedback::links`。マウスの事象はこれで引く）。
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkFrame {
    /// transcriptのリンクの区間（行はtranscriptの行。`crate::ui`の`transcript_lines`）。
    pub links: Vec<LinkSpan>,
    /// 重ねる枠（承認ダイアログ・レビューパネル）を描いた画面か（モジュールdoc「出さないとき」）。
    pub overlaid: bool,
    /// その画面で指していたリンク。
    pub hovered: Option<HoveredLink>,
    /// その画面で描いた吹き出しの矩形（`hovered`のもの。入り切らずに描けなければ`None`）。
    pub tooltip: Option<Rect>,
}

impl AppState {
    /// マウスが指しているリンク（モジュールdoc「決め方」）。`overlaid`はその画面に重ねる枠を描くか、`targets`と`links`は
    /// その画面の文字の地図とリンクの区間——描画はこれから描く画面の分を、マウスの事象は直前に描いた画面の分を渡す。
    /// 直前に描いた吹き出しの上なら、そのリンク（まだ画面にあれば）。
    pub(crate) fn hovered_link(
        &self,
        overlaid: bool,
        targets: &Targets,
        links: &[LinkSpan],
    ) -> Option<HoveredLink> {
        if overlaid || self.selection.is_held() {
            return None;
        }
        let (column, row) = self.mouse_cell?;
        if let (Some(shown), Some(rect)) = (&self.links.hovered, self.links.tooltip) {
            if rect.contains(Position::new(column, row)) {
                let first = &shown.parts()[0];
                let still = link_at(
                    links,
                    Pos {
                        line: first.line,
                        offset: first.start,
                    },
                );
                if still.as_ref() == Some(shown) {
                    return still;
                }
            }
        }
        let at = targets.text_at(&Wheel::Transcript, column, row)?;
        link_at(links, at)
    }

    /// マウスの事象を受けた後、指しているリンクが直前に描いた画面と変わったか（変わったら描き直す。モジュールdoc
    /// 「再描画の合図」）。直前に描いた画面の地図とリンクで引く。
    pub(crate) fn hovered_link_changed(&self) -> bool {
        let now = self.hovered_link(self.links.overlaid, &self.pointer, &self.links.links);
        now != self.links.hovered
    }
}

/// 位置`at`の文字を含むリンク（折り返しで分かれた区間もまとめる）。リンクの文字でなければ`None`。
fn link_at(links: &[LinkSpan], at: Pos) -> Option<HoveredLink> {
    let index = links
        .iter()
        .position(|link| link.line == at.line && (link.start..link.end).contains(&at.offset))?;
    let mut first = index;
    while first > 0 && continues(&links[first - 1], &links[first]) {
        first -= 1;
    }
    let mut last = index;
    while last + 1 < links.len() && continues(&links[last], &links[last + 1]) {
        last += 1;
    }
    Some(HoveredLink(links[first..=last].to_vec()))
}

/// `after`が`before`と同じリンクの続きか。印（[`LinkSpan::continues`]）に加えて、URLと行が続いていることも見る——
/// 印の付いた区間の前の区間が落とされていても（`crate::markdown`が行の外を指す区間を捨てたとき）、別のリンクへつながない。
fn continues(before: &LinkSpan, after: &LinkSpan) -> bool {
    after.continues && after.url == before.url && after.line == before.line + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(line: usize, start: usize, end: usize, url: &str, continues: bool) -> LinkSpan {
        LinkSpan {
            line,
            start,
            end,
            url: url.to_string(),
            continues,
        }
    }

    fn at(line: usize, offset: usize) -> Pos {
        Pos { line, offset }
    }

    /// 区間の中の文字はそのリンク、区間の端（`end`）と外は`None`。続きの印でつながる区間は、どれを指しても同じ1つの
    /// リンク。印が無ければ、URLが同じでも隣の行でも別のリンク。印があってもURLか行が続かなければつながない。
    #[test]
    fn a_position_finds_the_whole_link_it_belongs_to() {
        let links = [
            span(0, 2, 5, "https://a.x", false),
            span(1, 0, 4, "https://a.x", true),
            span(2, 0, 3, "https://a.x", false),
            span(4, 0, 2, "https://b.x", true),
        ];
        let wrapped = HoveredLink(links[..2].to_vec());
        assert_eq!(link_at(&links, at(0, 2)), Some(wrapped.clone()));
        assert_eq!(link_at(&links, at(1, 3)), Some(wrapped.clone()));
        assert_eq!(wrapped.url(), "https://a.x");
        assert_eq!(link_at(&links, at(0, 5)), None, "区間の端");
        assert_eq!(link_at(&links, at(0, 1)), None, "区間の前");
        assert_eq!(link_at(&links, at(3, 0)), None, "リンクの無い行");
        assert_eq!(
            link_at(&links, at(2, 0)),
            Some(HoveredLink(vec![links[2].clone()])),
            "印の無い次の行は別のリンク"
        );
        assert_eq!(
            link_at(&links, at(4, 1)),
            Some(HoveredLink(vec![links[3].clone()])),
            "行もURLも続かない印はつながない"
        );
    }
}
