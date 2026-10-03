//! ボタン——押せる項目を、注釈ではなく**押せるもの**として見せる見た目と置き方
//! （会話TUIとポリシーエディタが共有する）。形は2つある。
//!
//! - **辺に載せるボタン**（[`active`]・[`draw_left`]）——枠の辺や案内の行に並べる、背景色付きの1行。
//!   ダイアログの選択肢（会話TUIの承認ダイアログ・ポリシーエディタの確認ダイアログ）に使う。ダイアログの中には
//!   枠で囲む高さが無い。
//! - **枠付きのボタン**（[`Framed`]・[`place_framed`]）——欄の右隣に置く、枠で囲んだ3行の独立したボタン。
//!   会話TUIの入力欄の「送信」「中断」と、ポリシーエディタの「記録」の枠の「記録を開始」「停止」に使う。
//!
//! # 何のためにあるのか
//!
//! キー案内の文字（`Esc=中断`・`[y] 一度だけ許可`）は、クリックで押せても注釈にしか見えない——2026-10-03に
//! ユーザーが会話画面を実機で見て「括弧の中に注釈があるからその注釈としてしかとらえられない」と指摘した。
//! 押せることを形で見せるため、背景色・黒文字・太字に左右1桁の余白を付けた**ボタン**として描く。
//! 見た目はポリシーエディタの確認ダイアログの下辺のボタン（`y=書く`）が先に持っていたもので、会話TUIの入力欄と
//! 承認ダイアログも同じ見た目を要るので、ここへ置いた（`scrollable`・`overlay`を移したのと同じ理由。
//! `docs/CODE-STRUCTURE-RULES.md`§5.0）。
//!
//! 同じ日に入力欄の下辺の右へその形の「送信」を載せたところ、ユーザーが実機を見て図を描き、「ボタンと分かるように
//! 枠で囲んだものを入力欄の右に置いてほしい」と希望した。それが枠付きのボタンである（下の節）。
//!
//! # いまは押せないボタンは薄く描く（[`Framed::pressable`]）
//!
//! 押しても何も起きない間だけ押せないボタンは、枠も文字も暗い灰色にして太字をやめる。押す場所も登録しない
//! （呼び出し側の責務）。消さずに残すのは、**ボタンの置き場所そのものを見せておく**ため——押せない間にボタンが
//! 消えると、最初に画面を見たときに何を押せばよいのか分からない。
//! 辺に載せるボタンには押せない形が無い。
//!
//! **いまこの形を使う画面は無い。** 2026-10-03までは会話画面の「送信」が、入力欄が空白だけの間この形だった。
//! ユーザーがポリシーエディタと見比べて「ボタンの色が違う。ポリシーエディタに合わせられる？」と言い（灰色の「送信」と
//! シアンの「記録を開始」。色の指定は同じで、違いはこの形かどうかだけだった）、「送信」もエディタの「記録を開始」と同じく
//! いつも押せる形にして、空のまま押したら理由を出すようにした（押しても無反応にしない、B-23(c)）。形そのものは、
//! 押せない間があるボタンを置くときのために部品に残す。
//!
//! # 辺に載せるボタンの並べ方
//!
//! ボタンの間は[`GAP`]桁空け、**その桁には何も描かない**——枠線の上に並べれば、ボタンの間に枠線が見える
//! （隣り合うボタンが1本の帯に見えない）。[`draw_left`]は**ボタンの途中で切らない**
//! （`row::draw_wrapped`・ポリシーエディタのキー案内の`fit_key_hints`と同じ規則）。途中で切れたボタンは、
//! 残った文字が別の操作に読める。
//!
//! # 枠付きのボタン
//!
//! ```text
//! ┌input (Enter=改行, …)──────────────────┐┌──────────┐┌──────────┐
//! │                                       ││   送信   ││   中断   │
//! └───────────────────────────────────────┘└Alt+Enter─┘└───Esc────┘
//! ```
//!
//! - **枠の中央に文言、下辺の中央に対応するキー**（ユーザーの図のとおり）。中央に置いて割り切れない1桁は右へ寄せる。
//! - **1列のボタンは同じ幅にそろえる**。幅は、文言の左右に3桁ずつの余白を取った幅と、下辺のキーの幅の大きい方
//!   （`送信`と`Alt+Enter`なら10桁＋枠線2桁）。ボタンの間は空けない（枠線どうしが並ぶ）。
//! - **欄の下端にそろえる**（[`place_framed`]）。入力欄が複数行で高くなっても、ボタンは右下の3行のまま動かない
//!   ——直前の形（入力欄の下辺の右に載せた送信）とユーザーの「入力欄の右下に送信ボタンがある」という見方が右下で、
//!   入力欄は上へ伸びるので、下端にそろえれば送信の位置が行数で変わらない。
//! - **狭いときは、隣の欄に`keep`桁を残せる形を選ぶ**: キーを添える形 → キーを落とした短い形（文言の左右に1桁）
//!   → 置かない、の順（辺に載せるボタンの長い文言→短い文言→描かない、と同じ並び）。途中で切れたボタンは描かない。
//! - 押せる形は枠と文言をボタンの色で描き、文言を太字にする。押せない形は枠・文言・キーを暗い灰色で、太字にしない。
//!
//! # 限界
//!
//! - 色は呼び出し側が選ぶ。押せるかどうかは色と太字で見せる——色を持たない端末では、押せるボタンと押せない
//!   ボタンの違いは太字だけになる。
//! - 押したときの見た目の変化（押下中の反転など）は無い。クリックは押した瞬間に効く（`crate::pointer`）。
//! - 枠付きのボタンは、ボタンの数が変わると列の幅が変わり、ボタンの位置が動く（ユーザーの図では「中断」が「送信」の
//!   右に並ぶので、出入りすると「送信」が動く）。動いた直後の押し間違いを捨てるかは呼び出し側が決める
//!   （会話TUIの`app::pointer`）。

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

/// ボタンの間の桁数（何も描かない）。
pub const GAP: u16 = 1;

/// 押せるボタン（`color`の背景に黒の太字。文言の左右に1桁ずつ余白を付ける）。
pub fn active(label: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

/// `buttons`を[`GAP`]桁ずつ空けて並べたときの幅（ボタンが無ければ0）。
pub fn row_width(buttons: &[Span]) -> u16 {
    let gaps = u16::try_from(buttons.len().saturating_sub(1))
        .unwrap_or(u16::MAX)
        .saturating_mul(GAP);
    crate::row::width(buttons).saturating_add(gaps)
}

/// `buttons`を`area`の1行目へ左から[`GAP`]桁ずつ空けて描き、それぞれが描かれた矩形を返す（同じ数・同じ順）。
/// 入り切らないボタンは描かず、幅0の矩形を返す（押せない。モジュールdocの並べ方）。
pub fn draw_left(frame: &mut Frame, area: Rect, buttons: &[Span]) -> Vec<Rect> {
    let row = Rect {
        height: area.height.min(1),
        ..area
    };
    crate::row::draw_wrapped(frame, row, buttons, GAP)
}

/// 枠付きのボタン1つ（モジュールdocの「枠付きのボタン」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framed<'a> {
    /// 枠の中央の文言（`送信`）。
    pub label: &'a str,
    /// 下辺の中央に添えるキー（`Alt+Enter`）。幅が足りないときは添えない（[`place_framed`]）。
    pub key: &'a str,
    /// いま押せるか。押せないものは枠も文字も暗い灰色で描く（押す場所を登録しないのは呼び出し側）。
    pub pressable: bool,
}

/// 枠付きのボタンの高さ（上辺・文言・下辺）。
pub const FRAMED_HEIGHT: u16 = 3;

/// 枠付きのボタンの列を右に置いても、隣の欄に残す文字の桁数。呼び出し側は、これに欄の枠線や見出しの桁を足して
/// [`place_framed`]の`keep`にする（会話TUIの入力欄・ポリシーエディタの「記録」の枠が同じ値を使う）。
///
/// 前例の無い値で、20桁は「打った文字が全角10文字ぶんは見える」から選んだ。これより狭いと、ボタンを短い形に
/// するか置かない。
pub const KEEP_TEXT_WIDTH: u16 = 20;

/// キーを添える形で、文言の左右に取る余白の桁数（ユーザーの図の`   送信   `）。
const LABEL_PAD: u16 = 3;

/// 表示桁で数えた幅。
fn width_of(text: &str) -> u16 {
    u16::try_from(text.width()).unwrap_or(u16::MAX)
}

/// 1列のボタンに共通の、枠の内側の幅（列で一番広いものにそろえる）。
fn inner_width(buttons: &[Framed], with_keys: bool) -> u16 {
    buttons
        .iter()
        .map(|button| {
            let label = width_of(button.label);
            if with_keys {
                label
                    .saturating_add(2 * LABEL_PAD)
                    .max(width_of(button.key))
            } else {
                label.saturating_add(2)
            }
        })
        .max()
        .unwrap_or(0)
}

/// [`place_framed`]が置いた、枠付きのボタンの列。[`Self::draw`]で描く。
#[derive(Debug, Clone, Copy)]
pub struct FramedRow<'a> {
    buttons: &'a [Framed<'a>],
    area: Rect,
    with_keys: bool,
    button_width: u16,
}

/// `area`の右端に`buttons`を横に並べる場所を取り、**残り（左側）**と置いた列を返す。
///
/// 左側に`keep`桁以上が残る形のうち、キーを添える形 → 添えない短い形、の順に最初に入るものを選ぶ。どちらも入らない
/// とき・`area`の高さが[`FRAMED_HEIGHT`]に満たないとき・ボタンが無いときは列を置かず、`area`をそのまま返す。
/// 列は`area`の下端にそろえる（モジュールdoc）。左側は`area`と同じ高さ。
pub fn place_framed<'a>(
    area: Rect,
    buttons: &'a [Framed<'a>],
    keep: u16,
) -> (Rect, Option<FramedRow<'a>>) {
    if buttons.is_empty() || area.height < FRAMED_HEIGHT {
        return (area, None);
    }
    let count = u16::try_from(buttons.len()).unwrap_or(u16::MAX);
    for with_keys in [true, false] {
        let button_width = inner_width(buttons, with_keys).saturating_add(2);
        let width = button_width.saturating_mul(count);
        if area.width.saturating_sub(width) < keep || width > area.width {
            continue;
        }
        let rest = Rect {
            width: area.width - width,
            ..area
        };
        let row = Rect::new(
            rest.right(),
            area.bottom() - FRAMED_HEIGHT,
            width,
            FRAMED_HEIGHT,
        );
        return (
            rest,
            Some(FramedRow {
                buttons,
                area: row,
                with_keys,
                button_width,
            }),
        );
    }
    (area, None)
}

impl FramedRow<'_> {
    /// 列全体の矩形（枠線を含む。高さは[`FRAMED_HEIGHT`]）。
    pub fn area(&self) -> Rect {
        self.area
    }

    /// 下辺にキーを添える形か（`false`は幅が足りずにキーを落とした短い形）。
    pub fn with_keys(&self) -> bool {
        self.with_keys
    }

    /// 列を左から描き、ボタンごとに描いた矩形（枠線を含む）を返す（[`place_framed`]へ渡した`buttons`と同じ数・同じ順）。
    /// 押せるボタンは`color`で描く。押す場所の登録は呼び出し側が、押せるボタンについてだけ行う。
    /// 画面からはみ出すボタンは描かず、幅0の矩形を返す（押せない。[`place_framed`]が返した列なら起きない）。
    pub fn draw(&self, frame: &mut Frame, color: Color) -> Vec<Rect> {
        let screen = frame.area();
        let mut x = self.area.x;
        self.buttons
            .iter()
            .map(|button| {
                let rect = Rect::new(x, self.area.y, self.button_width, FRAMED_HEIGHT);
                x = x.saturating_add(self.button_width);
                if rect.intersection(screen) != rect {
                    return Rect::new(rect.x, rect.y, 0, 0);
                }
                draw_framed(frame, rect, button, self.with_keys, color);
                rect
            })
            .collect()
    }
}

/// 枠付きのボタン1つを`rect`（高さ[`FRAMED_HEIGHT`]、幅は文言とキーが入る幅）へ描く。
fn draw_framed(frame: &mut Frame, rect: Rect, button: &Framed, with_keys: bool, color: Color) {
    let (border, label) = if button.pressable {
        (
            Style::default().fg(color),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )
    } else {
        let dim = Style::default().fg(Color::DarkGray);
        (dim, dim)
    };
    frame.render_widget(
        Block::default().borders(Borders::ALL).border_style(border),
        rect,
    );
    let inner = rect.width.saturating_sub(2);
    let mut centered = |text: &str, y: u16, style: Style| {
        let x = rect.x + 1 + inner.saturating_sub(width_of(text)) / 2;
        frame
            .buffer_mut()
            .set_stringn(x, y, text, usize::from(inner), style);
    };
    centered(button.label, rect.y + 1, label);
    if with_keys {
        centered(button.key, rect.bottom() - 1, border);
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;

    use super::*;

    /// `y`行目の`x`桁から`width`桁の文字。全角文字の後ろのセル（2桁目）は読まない（ratatuiはそこを空白にする）。
    fn text_at(buffer: &Buffer, x: u16, y: u16, width: u16) -> String {
        let mut text = String::new();
        let mut skip = false;
        for column in x..x + width {
            let symbol = buffer[(column, y)].symbol();
            if std::mem::take(&mut skip) {
                continue;
            }
            skip = symbol.width() == 2;
            text.push_str(symbol);
        }
        text
    }

    fn long() -> Vec<Span<'static>> {
        vec![
            active("Esc=中断", Color::Cyan),
            active("Alt+Enter=送信", Color::Cyan),
        ]
    }

    /// 左寄せでも、入り切らないボタンは幅0（途中で切らない）。
    #[test]
    fn left_aligned_buttons_that_do_not_fit_are_not_drawn() {
        let buttons = long();
        let mut term = Terminal::new(TestBackend::new(20, 1)).expect("test terminal");
        let mut rects = Vec::new();
        term.draw(|f| rects = draw_left(f, f.area(), &buttons))
            .expect("draw");
        assert_eq!(rects[0], Rect::new(0, 0, buttons[0].width() as u16, 1));
        assert_eq!(rects[1].width, 0, "{rects:?}");
        assert_eq!(
            row_width(&buttons),
            rects[0].width + GAP + buttons[1].width() as u16
        );
        assert_eq!(row_width(&[]), 0);
    }

    // --- 枠付きのボタン ---

    fn send(pressable: bool) -> Framed<'static> {
        Framed {
            label: "送信",
            key: "Alt+Enter",
            pressable,
        }
    }

    fn cancel() -> Framed<'static> {
        Framed {
            label: "中断",
            key: "Esc",
            pressable: true,
        }
    }

    /// 枠付きのボタンを`width`×`height`の端末の全体へ`keep`桁を残して置いて描き、残り・列・描いた矩形・画面を返す。
    fn framed(
        buttons: &[Framed],
        width: u16,
        height: u16,
        keep: u16,
    ) -> (Rect, Option<(Rect, bool)>, Vec<Rect>, Buffer) {
        let mut term = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        let mut placed = (Rect::default(), None, Vec::new());
        term.draw(|f| {
            let (rest, row) = place_framed(f.area(), buttons, keep);
            let drawn = row.map(|row| row.draw(f, Color::Cyan)).unwrap_or_default();
            placed = (rest, row.map(|row| (row.area(), row.with_keys())), drawn);
        })
        .expect("draw");
        (
            placed.0,
            placed.1,
            placed.2,
            term.backend().buffer().clone(),
        )
    }

    /// 描いた列の3行（列の左端から右端まで）。
    fn rows(buffer: &Buffer, row: Rect) -> [String; 3] {
        [0, 1, 2].map(|dy| text_at(buffer, row.x, row.y + dy, row.width))
    }

    /// **ユーザーの図のとおりに描く**——枠の中央に文言、下辺の中央にキー（割り切れない1桁は右へ）。1つでも2つでも。
    /// 期待値はユーザーが描いた図の文字そのもの（幅の計算から作らない）。
    #[test]
    fn framed_buttons_look_like_the_users_drawing() {
        let (rest, row, drawn, buffer) = framed(&[send(true)], 60, 3, 0);
        let (row, with_keys) = row.expect("置けるはず");
        assert!(with_keys);
        assert_eq!(
            rows(&buffer, row),
            ["┌──────────┐", "│   送信   │", "└Alt+Enter─┘"].map(String::from)
        );
        assert_eq!(drawn, vec![row], "描いた矩形が描いた枠と違う");
        assert_eq!(row.right(), 60, "右端にそろっていない");
        assert_eq!(
            rest,
            Rect::new(0, 0, 48, 3),
            "残りがボタンの左隣で終わっていない"
        );

        let (_, row, drawn, buffer) = framed(&[send(true), cancel()], 60, 3, 0);
        let (row, _) = row.expect("置けるはず");
        assert_eq!(
            rows(&buffer, row),
            [
                "┌──────────┐┌──────────┐",
                "│   送信   ││   中断   │",
                "└Alt+Enter─┘└───Esc────┘",
            ]
            .map(String::from)
        );
        assert_eq!(drawn.len(), 2);
        assert_eq!(drawn[0].right(), drawn[1].x, "ボタンの間を空けない");
        for rect in &drawn {
            assert_eq!(
                (rect.width, rect.height),
                (12, 3),
                "描いた矩形が枠と違う: {drawn:?}"
            );
            assert_eq!(buffer[(rect.x, rect.y)].symbol(), "┌");
            assert_eq!(buffer[(rect.right() - 1, rect.bottom() - 1)].symbol(), "┘");
        }
    }

    /// **1列のボタンは同じ幅**——キーが長いボタン（`Shift+Enter`）に、短いボタンもそろう。
    #[test]
    fn buttons_in_one_row_share_the_widest_width() {
        let shift = Framed {
            key: "Shift+Enter",
            ..send(true)
        };
        let (_, row, drawn, buffer) = framed(&[shift, cancel()], 60, 3, 0);
        let (row, _) = row.expect("置けるはず");
        assert_eq!(
            rows(&buffer, row),
            [
                "┌───────────┐┌───────────┐",
                "│   送信    ││   中断    │",
                "└Shift+Enter┘└────Esc────┘",
            ]
            .map(String::from)
        );
        assert_eq!(drawn[0].width, drawn[1].width);
    }

    /// 押せるボタンは枠と文言がボタンの色で、文言が太字。押せないボタンは枠・文言・キーが暗い灰色で、太字でない。
    #[test]
    fn a_framed_button_that_cannot_be_pressed_is_dim() {
        for (pressable, color, bold) in [(true, Color::Cyan, true), (false, Color::DarkGray, false)]
        {
            let (_, _, drawn, buffer) = framed(&[send(pressable)], 30, 3, 0);
            let rect = drawn[0];
            let corner = &buffer[(rect.x, rect.y)];
            let label = (rect.x..rect.right())
                .map(|x| &buffer[(x, rect.y + 1)])
                .find(|cell| cell.symbol() == "送")
                .expect("文言");
            let key = (rect.x..rect.right())
                .map(|x| &buffer[(x, rect.bottom() - 1)])
                .find(|cell| cell.symbol() == "A")
                .expect("キー");
            assert_eq!(
                (corner.fg, label.fg, key.fg),
                (color, color, color),
                "押せる={pressable}"
            );
            assert_eq!(
                label.modifier.contains(Modifier::BOLD),
                bold,
                "押せる={pressable}"
            );
        }
    }

    /// **狭いときは、キーを添える形 → キーを落とした短い形 → 置かない**。どの形でも左に`keep`桁が残り、ボタンは途中で
    /// 切れない。置かないときは全体を返す。
    #[test]
    fn a_narrow_area_falls_back_to_short_buttons_and_then_to_none() {
        let buttons = [send(true), cancel()];
        // キーを添える形は12桁×2、短い形は8桁×2。残す桁は10。
        for (width, want) in [
            (34u16, Some(true)),
            (33, Some(false)),
            (26, Some(false)),
            (25, None),
        ] {
            let (rest, row, drawn, buffer) = framed(&buttons, width, 3, 10);
            assert_eq!(row.map(|(_, keys)| keys), want, "{width}桁");
            match row {
                Some((row, _)) => {
                    assert!(rest.width >= 10, "{width}桁: 残りが{}桁", rest.width);
                    assert_eq!(
                        rest.right(),
                        row.x,
                        "{width}桁: 残りとボタンが重なるか離れた"
                    );
                    assert_eq!(row.right(), width);
                }
                None => {
                    assert_eq!(rest, Rect::new(0, 0, width, 3), "{width}桁");
                    assert!(drawn.is_empty());
                }
            }
            if want == Some(false) {
                let (row, _) = row.expect("短い形");
                assert_eq!(
                    rows(&buffer, row),
                    ["┌──────┐┌──────┐", "│ 送信 ││ 中断 │", "└──────┘└──────┘",].map(String::from),
                    "{width}桁"
                );
            }
        }
    }

    /// **高い場所では下端にそろえる**（残りは全体の高さのまま）。3行に満たない場所・ボタンが無いときは置かない。
    #[test]
    fn framed_buttons_sit_at_the_bottom_and_need_three_rows() {
        let (rest, row, drawn, buffer) = framed(&[send(true)], 40, 7, 0);
        let (row, _) = row.expect("置けるはず");
        assert_eq!((row.y, row.height), (4, 3), "下端にそろっていない");
        assert_eq!(rest.height, 7);
        assert_eq!(buffer[(drawn[0].x, 4)].symbol(), "┌");
        assert_eq!(
            text_at(&buffer, row.x, 0, row.width).trim(),
            "",
            "ボタンの上に何か描いた"
        );

        let (rest, row, _, _) = framed(&[send(true)], 40, 2, 0);
        assert!(row.is_none());
        assert_eq!(rest, Rect::new(0, 0, 40, 2));
        let (rest, row, _, _) = framed(&[], 40, 3, 0);
        assert!(row.is_none());
        assert_eq!(rest, Rect::new(0, 0, 40, 3));
    }
}
