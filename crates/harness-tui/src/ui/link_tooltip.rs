//! transcriptのリンクを指している間、リンクの直後に`(URL)`の吹き出しを重ねて描く（計画書
//! `plans/PLAN-TUI-IMPROVEMENTS.md`§3・§0のT11a）。どのリンクを指しているかは`crate::app`の`link_hover`が決める。
//! ここが持つのは置き場所・切り方・見た目と、描いた場所の登録。
//!
//! # 置き場所
//!
//! - リンクの**最後の文字**（折り返しで分かれたリンクは、最後の行の最後の文字）のすぐ右。transcriptの枠の内側に
//!   入り切ればその行
//! - 入り切らなければ**次の行**に、できるだけ同じ桁から。右へはみ出す分は左へずらし、枠の内側の右端に揃える。次の行が
//!   枠の外（一番下の行）なら1つ上の行。どちらも無ければ（枠の内側が1行）同じ行
//! - リンクの最後の文字が送って見えなくなっていれば、見えている最後の文字の右（マウスの下の文字は見えている）
//!
//! # 切り方
//!
//! 枠の内側の幅より長い`(URL)`は、URLの**頭を残して末尾を`…`で切り**、閉じ括弧は残す。transcriptの上辺の知らせ
//! （`super::fit_width`）と同じ切り方で、頭（スキームとホスト——どこへ飛ぶか）が必ず見える（計画書§3.5の「開く前に
//! 本当のURLが見える」）。
//!
//! # 見た目
//!
//! ステータスバーと同じ灰色の地に黒い文字（`super::STATUS_STYLE`）。文章の上に重なったことが分かり、リンクの青とも
//! 範囲選択の白地に青（`harness_term::select::SELECTED`）とも見分けが付く。押せる見た目（下線）はまだ付けない——押して
//! 開くのは計画書のT11bで、押せないうちから押せそうに見せない（押せない案内をただの文字にした計画書§4.2と同じ）。
//!
//! # 重ねるだけで、ほかのセルを変えない
//!
//! 描く前に`harness_term::overlay::clear`で矩形を空ける。文章の並びも、文字の地図（範囲選択・マウスの当たり判定）も
//! 変えない。描いた矩形は覆った場所として登録する（`Targets::cover`）——吹き出しの上のクリックは下の文字へ届かない
//! （範囲選択も始めない）。
//!
//! # 限界
//!
//! - 吹き出しの下の文字は見えない（計画書§1.7）
//! - 吹き出しの左端に後ろの全角文字が掛かると、その全角文字は空白になる（`harness_term::overlay::clear`の約束。
//!   BUG-198——半分だけ残すと枠線が欠けて見える）。吹き出しの外で変わり得るのはそのセルだけ

use harness_term::select::Pos;
use ratatui::layout::Rect;
use ratatui::text::Span;
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

use crate::app::{AppState, HoveredLink, LinkFrame, Targets, Wheel};
use crate::markdown::LinkSpan;

/// 指しているリンクがあれば吹き出しを描き、この描画のリンクのことを返す（`DrawFeedback::links`）。`overlaid`はこの描画で
/// 重ねる枠を描いたか（描いたなら出さない）、`inner`はtranscriptの枠の内側、`links`はこの描画のtranscriptのリンクの区間。
/// `targets`はこの描画で登録したもの（文字の地図を引き、吹き出しを覆った場所として足す）。
pub(super) fn draw(
    f: &mut Frame,
    app: &AppState,
    overlaid: bool,
    inner: Rect,
    links: Vec<LinkSpan>,
    targets: &mut Targets,
) -> LinkFrame {
    let hovered = app.hovered_link(overlaid, targets, &links);
    let tooltip = hovered.as_ref().and_then(|link| {
        let anchor = last_drawn_cell(targets, link)?;
        let text = label(link.url(), inner.width)?;
        let rect = place(anchor, inner, u16::try_from(text.width()).ok()?)?;
        harness_term::overlay::clear(f, rect);
        harness_term::row::draw(f, rect, &[Span::styled(text, super::STATUS_STYLE)]);
        targets.cover(rect);
        // 計画書のT11b: 吹き出しのURLを押すと開く。押す場所はここで、覆った後に`targets.click(rect, …)`で登録する
        // （覆う前に登録すると覆いの下になる）。押せる見た目（下線）もそのとき足す。
        Some(rect)
    });
    LinkFrame {
        links,
        overlaid,
        hovered,
        tooltip,
    }
}

/// リンクの、見えている最後の文字を描いたセル（モジュールdoc「置き場所」）。1文字も見えていなければ`None`。
fn last_drawn_cell(targets: &Targets, link: &HoveredLink) -> Option<Rect> {
    link.parts().iter().rev().find_map(|part| {
        (part.start..part.end).rev().find_map(|offset| {
            targets.text_cell(
                &Wheel::Transcript,
                Pos {
                    line: part.line,
                    offset,
                },
            )
        })
    })
}

/// 幅`width`桁に収めた`(URL)`（モジュールdoc「切り方」）。括弧と`…`も入らない幅（3桁未満）なら`None`。
fn label(url: &str, width: u16) -> Option<String> {
    let width = usize::from(width);
    (width >= 3).then(|| format!("({})", super::fit_width(url, width - 2)))
}

/// 幅`width`桁の吹き出しを置く1行の矩形（モジュールdoc「置き場所」）。`anchor`はリンクの最後の文字のセル、`area`は
/// transcriptの枠の内側。`area`に入らない幅なら`None`。
fn place(anchor: Rect, area: Rect, width: u16) -> Option<Rect> {
    if area.is_empty() || width == 0 || width > area.width {
        return None;
    }
    let after = anchor.right();
    if after >= area.x && after.saturating_add(width) <= area.right() {
        return Some(Rect::new(after, anchor.y, width, 1));
    }
    let x = after.min(area.right() - width).max(area.x);
    let y = if anchor.y.saturating_add(1) < area.bottom() {
        anchor.y + 1
    } else if anchor.y > area.y {
        anchor.y - 1
    } else {
        anchor.y
    };
    Some(Rect::new(x, y, width, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 枠の内側が1行しか無いときは同じ行（右端に揃える）。枠の内側より広い吹き出しは置かない。
    #[test]
    fn place_stays_on_the_row_when_the_area_has_one_row_and_refuses_what_does_not_fit() {
        let area = Rect::new(1, 1, 20, 1);
        assert_eq!(
            place(Rect::new(15, 1, 1, 1), area, 10),
            Some(Rect::new(11, 1, 10, 1))
        );
        assert_eq!(
            place(Rect::new(2, 1, 1, 1), area, 10),
            Some(Rect::new(3, 1, 10, 1)),
            "入り切れば右隣"
        );
        assert_eq!(place(Rect::new(2, 1, 1, 1), area, 21), None);
        assert_eq!(place(Rect::new(2, 1, 1, 1), Rect::default(), 3), None);
    }

    /// 3桁未満には括弧と`…`も入らないので描かない。ちょうど入る長さは切らない。
    #[test]
    fn label_keeps_the_parentheses_and_cuts_only_what_does_not_fit() {
        assert_eq!(label("https://e.x", 2), None);
        assert_eq!(label("https://e.x", 3).as_deref(), Some("(…)"));
        assert_eq!(label("https://e.x", 13).as_deref(), Some("(https://e.x)"));
        assert_eq!(label("https://e.x", 12).as_deref(), Some("(https://e…)"));
    }
}
