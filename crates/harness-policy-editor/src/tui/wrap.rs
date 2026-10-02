//! 折り返す枠の行数を数え、枠に入り切らなかった分を黙らせない部品（[BUG-192](../../../../docs/bugs/BUG-192.md)）。
//!
//! # 何のためにあるのか
//!
//! このエディタの文はほとんどが日本語で、日本語は1文字2桁なので、枠の幅を超える行はすぐ出る。
//! 枠の高さ・「続きがあるか」・送る量を**折り返す前の行数**で数えると、折り返した分だけ
//! 下が**黙って**切れる——確認ダイアログでは権限の注意（「配下へ付いた継承ACEは残って効き続けます」）が
//! 確定の前に見えなくなった。その数え方が画面ごとに別々に書かれていたので、ここで1つにする。
//!
//! # 数え方は描画と同じ折り返し器
//!
//! [`rows`]は`Paragraph::line_count`（ratatuiの`WordWrapper`）で数える。描くときも
//! `Wrap { trim: false }`で同じ折り返し器を通すので、全角・空白での折り返しを含めて**数えた行数と
//! 描いた行数が一致する**。幅を自分で足し算すると、空白で切る規則の分だけ描画とずれる
//! （会話TUIの承認ダイアログと`harness_term::scrollback`が先に同じ選択をしている）。
//!
//! # 限界
//!
//! - **折り返し方そのものは変えていない。** ratatuiの単語折り返しは空白で切り、日本語の禁則を見ない。
//!   英数字の後ろに空白の無い長い日本語が続くと、英数字だけの短い行が残る（「注:」だけの行など）。
//! - **送れない枠（説明欄・ヘルプ）は、入り切らなかった行数を言うだけ**で、残りを読ませる手段は
//!   持たない。読むには端末を広げる。送れるのは確認ダイアログだけである（[`Window`]・[`draw_scrolled`]）。

use ratatui::layout::{Margin, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};
use ratatui::Frame;

/// `text`を`width`桁で折り返したときの表示行数。
///
/// **`Wrap { trim: false }`で描く枠には、必ずこれで数える**（モジュールdoc）。
/// 幅0は1桁として数える（会話TUIの承認ダイアログと同じ扱い。幅0の枠には何も描かれない）。
pub(super) fn rows<'a>(text: impl Into<Text<'a>>, width: u16) -> usize {
    Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .line_count(width.max(1))
}

/// 枠付きの説明欄の高さ（枠線の2行を含む）。中身を`width`桁の枠で折り返した行数ぶん取る。
///
/// - **`floor`より低くしない。** 収まる中身で画面の割り付けが動かないように、今までの固定の高さを渡す。
/// - **`ceiling`を超えない。** 隣の一覧を潰さないための上限で、呼び出し側が決める
///   （説明欄は一覧と高さを分け合うので、一覧に半分を残す値を渡している）。超えた分は
///   [`draw_box`]が行数で言う。
pub(super) fn box_height<'a>(
    text: impl Into<Text<'a>>,
    width: u16,
    floor: u16,
    ceiling: u16,
) -> u16 {
    let wanted = rows(text, width.saturating_sub(2)).saturating_add(2);
    u16::try_from(wanted)
        .unwrap_or(u16::MAX)
        .clamp(floor, ceiling.max(floor))
}

/// 折り返す枠を描き、**入り切らなかった行数を枠の下辺に出す**（黙って切らない、`B-09`）。
///
/// 送れない枠（説明欄・ヘルプ）に使う。送れる枠（確認ダイアログ）は、何行目を見ているかを自分で出す。
pub(super) fn draw_box<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
) {
    let text = text.into();
    let inner = block.inner(area);
    let hidden = rows(text.clone(), inner.width).saturating_sub(usize::from(inner.height));
    let block = if hidden == 0 {
        block
    } else {
        block.title_bottom(overflow_notice(hidden))
    };
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        area,
    );
}

/// 入り切らなかった行数の案内。**残りがあることが分からないと、読み切ったつもりで判断してしまう**。
fn overflow_notice(hidden: usize) -> Line<'static> {
    Line::styled(
        format!(" 下の{hidden}行が枠に収まっていません（端末を広げると見えます） "),
        Style::default().fg(Color::Yellow),
    )
    .right_aligned()
}

/// 送れる枠で、いま見せている範囲（[BUG-196](../../../../docs/bugs/BUG-196.md)）。
/// **数えるのはどれも折り返した後の表示行**で、[`rows`]・`Paragraph::scroll`・下辺の「N〜M/T行」と同じ単位である。
///
/// # 送る上限は「本文の最後の行が枠の一番下の行に来たところ」
///
/// 上限は`total - visible`。以前の確認ダイアログは最後の行が枠の一番上に来るまで送れたので、
/// 末尾では枠がほぼ空になり、どこまで読めば終わりかが分からなかった。本文が枠に収まるなら上限は0で、送れない。
///
/// # 上限は描くまで分からない
///
/// 総行数は枠の幅で折り返した結果なので、キーを受けた時点では決まらない。だからキーの側は上限を
/// 掛けずに進め、描画が[`Self::max_top`]を返し、呼び出し側が状態を切り詰める
/// （`harness_term::scrollback`・会話TUIの承認ダイアログと同じ形。描画の側だけで切り詰めると、
/// 末尾で押した分が状態に溜まって戻すときに空回りする——BUG-076）。
///
/// `harness_term::scrollback::Scrollback`を流用しないのは向きが逆だからである。あちらは**下端からの距離**で
/// 持ち、既定は末尾に貼り付く（新着に追従するログ用）。確認ダイアログは**先頭から**読ませる
/// （決定33: 判断材料を明細より前に置いている）ので、上端からの位置で持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Window {
    /// 本文を折り返した後の行数。
    pub total: usize,
    /// 枠の中に見える行数。
    pub visible: usize,
    /// 枠の一番上に見せる表示行（0始まり）。**上限で切り詰め済み**。
    pub top: usize,
}

impl Window {
    /// `scroll`は状態が持つ送り量。上限を超えていても、ここでは描く位置だけを上限へ切り詰める。
    pub(super) fn new(total: usize, visible: usize, scroll: u16) -> Self {
        let top = usize::from(scroll).min(total.saturating_sub(visible));
        Self {
            total,
            visible,
            top,
        }
    }

    /// 送れる上限（最後の行が枠の一番下の行に来るときの[`Self::top`]）。
    pub(super) fn max_top(self) -> usize {
        self.total.saturating_sub(self.visible)
    }

    /// 本文が枠に収まらない（＝送れる）か。
    pub(super) fn overflows(self) -> bool {
        self.total > self.visible
    }
}

/// 送れる枠を描く。本文を[`Window::top`]行目から見せ、**収まらないときだけ右の枠線の上にスクロールバーを出す**。
///
/// # スクロールバーは枠線の上に描く
///
/// 内側に描くと本文の右端の1桁を潰すので、折り返しの幅を1桁減らし、[`rows`]で数える幅もそれに
/// 合わせることになる。枠線の上なら本文の幅は変わらず、数えた行数と描いた行数の一致（モジュールdoc）に
/// 触らない。線は枠線と同じ記号・同じ色にし、つまみだけを`█`にするので、収まらないときは
/// 右の枠線の一部がつまみに変わって見える。上下の矢印は付けない（つまみが端に付いたことで先頭・末尾を
/// 言うため。矢印を付けると、端に付いても矢印との間に線が残る）。
///
/// **送れることはスクロールバーだけでは伝わらない**（キーで送れることは絵から読めない）ので、
/// 下辺の「↑↓ PgUp/PgDn で送る」は呼び出し側が引き続き出す。
pub(super) fn draw_scrolled<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    window: Window,
    bar: Style,
) {
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(window.top).unwrap_or(u16::MAX), 0))
            .block(block),
        area,
    );
    if !window.overflows() {
        return;
    }
    // ratatuiの`ScrollbarState`は「送れる位置の数」と「見えている量」で数える。位置は0〜上限の
    // `上限+1`通り、見えている量は`visible`——こう渡すと、先頭でつまみが一番上、上限で一番下に付く。
    let mut state = ScrollbarState::new(window.max_top() + 1)
        .position(window.top)
        .viewport_content_length(window.visible);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some(symbols::line::VERTICAL))
            .thumb_symbol(symbols::block::FULL)
            .style(bar),
        // 右の枠線のうち、上下の角を除いた部分。
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}
