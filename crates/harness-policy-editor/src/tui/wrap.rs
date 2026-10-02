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
//!   持たない。読むには端末を広げる。送れるのは確認ダイアログだけである。

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};
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
