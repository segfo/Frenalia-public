//! 折り返す枠の行数を数え、枠に入り切らなかった分を送って読ませる部品（[BUG-192](../../../../docs/bugs/BUG-192.md)）。
//!
//! # 何のためにあるのか
//!
//! このエディタの文はほとんどが日本語で、日本語は1文字2桁なので、枠の幅を超える行はすぐ出る。
//! 枠の高さ・「続きがあるか」・送る量を**折り返す前の行数**で数えると、折り返した分だけ
//! 下が**黙って**切れる——確認ダイアログでは権限の注意（「配下へ付いた継承ACEは残って効き続けます」）が
//! 確定の前に見えなくなった。その数え方が画面ごとに別々に書かれていたので、ここで1つにする。
//!
//! # 数え方は描画と同じ折り返し器（`harness_term::wrap`）
//!
//! [`rows`]は`Paragraph::line_count`（ratatuiの`WordWrapper`）で数える。描くときも同じ折り返し器を
//! 通すので、全角・空白での折り返しを含めて**数えた行数と描いた行数が一致する**。幅を自分で足し算すると、
//! 空白で切る規則の分だけ描画とずれる（会話TUIの承認ダイアログと`harness_term::scrollback`が先に
//! 同じ選択をしている）。
//!
//! 数える幅と描く幅は、会話TUIと共有する`harness_term::wrap`が1か所で決める。どちらも**右端の1桁を空ける**
//! ——ratatuiの折り返しは行末の全角文字で1桁はみ出し、右の枠線を覆うため（[BUG-200](../../../../docs/bugs/BUG-200.md)）。
//! このエディタで`Wrap`や`line_count`を直接使わない（`render_tests`が数えている）。
//!
//! # 入り切らない枠はどれも同じ部品で送る（[`draw_scrollable`]）
//!
//! 確認ダイアログ・ヘルプ・各画面の説明欄は、入り切らないとき同じ形になる——送る上限は「本文の最後の行が
//! 枠の一番下に来たところ」（[`Window`]。BUG-196）、右の枠線の上にスクロールバー、下辺に「N〜M/T行」と
//! 送り方。違うのは送り方（確認ダイアログはキーとホイール、説明欄とヘルプはホイールだけ。`tui::scroll`）と
//! 色だけで、それは[`Look`]で渡す。以前は説明欄とヘルプが送れず、入り切らない行数を言うだけだった。
//!
//! # 限界
//!
//! - **折り返し方そのものは変えていない。** ratatuiの単語折り返しは空白で切り、日本語の禁則を見ない。
//!   英数字の後ろに空白の無い長い日本語が続くと、英数字だけの短い行が残る（「注:」だけの行など）。
//! - 送れることを言うのは、入り切らない枠の下辺とスクロールバーだけである（キー案内の行には出さない）。

use ratatui::layout::{Margin, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;

/// `text`を`width`桁の場所へ折り返して描いたときの表示行数。**折り返して描く場所は、必ずこれで数える**
/// （描くのは`harness_term::wrap::Wrapped`。数える幅と描く幅は同じ。モジュールdoc）。
pub(super) use harness_term::wrap::rows;
use harness_term::wrap::Wrapped;

/// 枠付きの説明欄の高さ（枠線の2行を含む）。中身を`width`桁の枠で折り返した行数ぶん取る。
///
/// - **`floor`より低くしない。** 収まる中身で画面の割り付けが動かないように、今までの固定の高さを渡す。
/// - **`ceiling`を超えない。** 隣の一覧を潰さないための上限で、呼び出し側が決める
///   （説明欄は一覧と高さを分け合うので、一覧に半分を残す値を渡している）。超えた分は
///   [`draw_scrollable`]で送って読む。
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

/// 送れる枠の見せ方。入り切らないときにだけ使う（入り切る枠は今までと1セルも変わらない）。
#[derive(Debug, Clone, Copy)]
pub(super) struct Look {
    /// 下辺の「N〜M/T行」の後ろに添える送り方。**効く手段だけを書く**（B-32）。
    pub how: &'static str,
    /// 下辺の「N〜M/T行」の色。
    pub notice: Style,
    /// スクロールバーの色。**枠線と同じ色を渡す**（スクロールバーは右の枠線の上に描くので、
    /// 違う色にすると枠線の途中で色が変わる）。
    pub bar: Style,
}

impl Look {
    /// 説明欄とヘルプ。ホイールだけで送る（`tui::scroll`のモジュールdoc）。`border`は枠線の色。
    ///
    /// 位置の案内を黄色にするのは、以前の「下のN行が枠に収まっていません」と同じく、**残りがあることを
    /// 読み落とさせない**ためである（読み切ったつもりで判断してしまう）。
    pub(super) fn panel(border: Style) -> Self {
        Self {
            how: "ホイールで送る",
            notice: Style::default().fg(Color::Yellow),
            bar: border,
        }
    }
}

/// 送れる枠を描き、**この描画で分かった送れる上限**を返す（確認ダイアログ・ヘルプ・説明欄が共有する）。
///
/// `top`は状態が持つ送り量（枠の一番上に見せる表示行）。上限を超えていても、描く位置だけを上限へ切り詰める。
/// 呼び出し側は戻り値を`DrawFeedback`で状態へ返し、状態の側を切り詰める（[`Window`]のdoc。BUG-076）。
///
/// 本文が入り切らないときだけ、下辺の右に「N〜M/T行  送り方」を出し、右の枠線の上にスクロールバーを出す。
/// 入り切るときは何も足さない。下辺が狭い枠では送り方を落とす（[`Window::notice`]）。
pub(super) fn draw_scrollable<'a>(
    frame: &mut Frame,
    area: Rect,
    text: impl Into<Text<'a>>,
    block: Block<'a>,
    top: u16,
    look: Look,
) -> u16 {
    let text = text.into();
    let inner = block.inner(area);
    let window = Window::new(
        rows(text.clone(), inner.width),
        usize::from(inner.height),
        top,
    );
    // 下辺のうち、左右の角を除いた幅。
    let block = match window.notice(look.how, area.width.saturating_sub(2)) {
        Some(notice) => block.title_bottom(Line::styled(notice, look.notice).right_aligned()),
        None => block,
    };
    Wrapped::new(text)
        .block(block)
        .scroll(u16::try_from(window.top).unwrap_or(u16::MAX))
        .render(frame, area);
    if window.overflows() {
        draw_scrollbar(frame, area, window, look.bar);
    }
    u16::try_from(window.max_top()).unwrap_or(u16::MAX)
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
/// 総行数は枠の幅で折り返した結果なので、キーやホイールを受けた時点では決まらない。だから受けた側は上限を
/// 掛けずに進め、描画が[`Self::max_top`]を返し、呼び出し側が状態を切り詰める
/// （`harness_term::scrollback`・会話TUIの承認ダイアログと同じ形。描画の側だけで切り詰めると、
/// 末尾で押した分が状態に溜まって戻すときに空回りする——BUG-076）。
///
/// `harness_term::scrollback::Scrollback`を流用しないのは向きが逆だからである。あちらは**下端からの距離**で
/// 持ち、既定は末尾に貼り付く（新着に追従するログ用）。確認ダイアログ・説明欄は**先頭から**読ませる
/// （決定33: 判断材料を明細より前に置いている）ので、上端からの位置で持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    /// 本文を折り返した後の行数。
    total: usize,
    /// 枠の中に見える行数。
    visible: usize,
    /// 枠の一番上に見せる表示行（0始まり）。**上限で切り詰め済み**。
    top: usize,
}

impl Window {
    /// `scroll`は状態が持つ送り量。上限を超えていても、ここでは描く位置だけを上限へ切り詰める。
    fn new(total: usize, visible: usize, scroll: u16) -> Self {
        let top = usize::from(scroll).min(total.saturating_sub(visible));
        Self {
            total,
            visible,
            top,
        }
    }

    /// 送れる上限（最後の行が枠の一番下の行に来るときの[`Self::top`]）。
    fn max_top(self) -> usize {
        self.total.saturating_sub(self.visible)
    }

    /// 本文が枠に収まらない（＝送れる）か。
    fn overflows(self) -> bool {
        self.total > self.visible
    }

    /// 下辺に出す「いま何行目から何行目を見ているか」と送り方。**残りがあることが分からないと、
    /// 読み切ったつもりで判断してしまう**（B-09）。本文が収まっていれば`None`（何も出さない）。
    ///
    /// `room`は下辺に使える桁数。**入らなければ送り方を落とし、それでも入らなければ出さない**——右寄せの見出しは
    /// 入り切らないと**左から**切れるので、「1〜3/10行」の頭の行番号が消えて別の範囲に読める
    /// （記録画面の見出し枠は左の列の45%しか幅が無く、80桁未満の端末でそうなる）。落としても
    /// スクロールバーは残る。
    fn notice(self, how: &str, room: u16) -> Option<String> {
        use unicode_width::UnicodeWidthStr;

        if !self.overflows() {
            return None;
        }
        let position = format!(
            "{}〜{}/{}行",
            (self.top + 1).min(self.total),
            (self.top + self.visible).min(self.total),
            self.total
        );
        [format!(" {position}  {how} "), format!(" {position} ")]
            .into_iter()
            .find(|notice| notice.width() <= usize::from(room))
    }
}

/// 右の枠線の上にスクロールバーを描く。
///
/// # スクロールバーは枠線の上に描く
///
/// 内側に描くと、本文の右端に空けてある1桁（行末の全角文字のはみ出し用。BUG-200）を潰すので、
/// 折り返しの幅をさらに減らし、[`rows`]で数える幅もそれに合わせることになる。枠線の上なら本文の幅は
/// 変わらず、数えた行数と描いた行数の一致（モジュールdoc）に触らない。線は枠線と同じ記号・同じ色にし、つまみだけを`█`にするので、収まらないときは
/// 右の枠線の一部がつまみに変わって見える。上下の矢印は付けない（つまみが端に付いたことで先頭・末尾を
/// 言うため。矢印を付けると、端に付いても矢印との間に線が残る）。
///
/// **送れることはスクロールバーだけでは伝わらない**（キーやホイールで送れることは絵から読めない）ので、
/// 下辺の「N〜M/T行」に送り方を添える（[`Look::how`]）。
fn draw_scrollbar(frame: &mut Frame, area: Rect, window: Window, bar: Style) {
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
