//! ボタン——押せる項目を、注釈ではなく**押せるもの**として見せる見た目と置き方
//! （会話TUIとポリシーエディタが共有する）。**押すと1回だけ動作が起きる**部品で、並んだ中から1つを選んで選んだ見た目が
//! 残るタブ（[`crate::tab`]）とは別の部品である（2026-10-03、ユーザーの指示「『タブ』と『ボタン』はUX的な意味合いは
//! 別」。違いの表は`tab`のモジュールdoc）。形は2つある。
//!
//! - **辺に載せるボタン**（[`span`]・[`draw_left`]）——枠の辺や案内の行に並べる、背景色付きの1行。
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
//! # 見た目は3つ（[`Look`]）——普通・押されている・押せない
//!
//! どちらの形も、同じ3つの見た目を持つ。呼び出し側はボタンごとに[`Press::look`]で選んで渡す。
//!
//! | 見た目 | 辺に載せるボタン（[`span`]） | 枠付きのボタン（[`Framed`]） |
//! |---|---|---|
//! | 普通 | ボタンの色の背景に黒の太字 | 枠と文言をボタンの色で、文言は太字 |
//! | 押されている | 普通の形の文字色と背景色を入れ替える（塗りが抜ける） | 普通の形の文字色と背景色を入れ替える（枠の中までボタンの色で塗る） |
//! | 押せない | 暗い灰色の文字（太字にしない） | 枠・文言・キーを暗い灰色で（太字にしない） |
//!
//! # 押した瞬間の見た目（[`Press`]）
//!
//! ボタンを押した瞬間（マウスの左ボタンを押した瞬間。クリックはそこで効く——[`crate::pointer`]）に、そのボタンを
//! **押されている形**で描く（2026-10-03、ユーザー「クリックしたらそのクリックした瞬間に色変えられたりします？」）。
//! 押されている形は普通の形の文字色と背景色を入れ替えたもの（`Modifier::REVERSED`。端末の既定の背景色が何色でも、
//! そのまま入れ替わる）なので、普通の形とも押せない形とも見分けが付く。
//!
//! - **動作は今までどおり押した瞬間に起きる**（離した瞬間に変えない）。見た目だけが、離すまで残る。
//! - **最低でも[`PRESSED_AT_LEAST`]は残す。** 押した瞬間に動作して画面が変わる（「送信」を押すと入力欄が空になる、
//!   「記録を開始」を押すと「停止を予約」に変わる）ので、離した瞬間に戻すと、素早いクリックでは押した色が描かれる前に
//!   消える。離していて、押してからこの長さが過ぎたら戻す（[`Press::up`]・[`Press::tick`]）——呼び出し側は、時間が
//!   進んだら`tick`を呼んで描き直す（会話画面は33msごとの描画の合図、ポリシーエディタはイベントを待つ100msの区切りで）。
//! - **押されている見た目は、ボタンの名前に付く**（`Press<K>`の`K`。何を同じボタンとみなすかは呼び出し側が決める）。
//!   押した後でボタンの位置が動いても押したボタンに付いて動き、その場所へ来た別のボタンには付かない（会話画面の
//!   「送信」は、応答が始まると現れる「中断」に押されて左へずれる）。押した結果ボタンが消えたら（閉じた確認ダイアログ）、
//!   それ自体が押した反応なので何も付かない。
//! - 押されていないうちから押せないボタンは押されている形にならない（押す場所が無いので押せない）。**押した結果
//!   押せなくなったボタンは、押されている形が戻るまで押されている形のまま**で、戻ったら押せない形になる（[`Press::look`]）
//!   ——会話画面の「送信」は押すと入力欄が空になって押せなくなるので、押した瞬間に押せない形へ変えると押した色が一度も
//!   見えない（「記録を開始」を押して文言が変わっても同じ名前にしているのと同じ理由）。2026-10-06に、「送信」を空の間
//!   押せない形に戻したときに決めた（それまでは押せないボタンをいつも押せない形にしていたが、押せない形を使う画面が
//!   無い間に決めたものだった）。
//! - タブには付けない（[`crate::tab`]）。押したタブが選ばれた見た目に変わり、それが残ること自体が押した反応である。
//!
//! # いまは押せないボタンは薄く描く（[`Look::Disabled`]）
//!
//! 押しても何も起きない間だけ押せないボタンは、枠も文字も暗い灰色にして太字をやめる。押す場所も登録しない
//! （呼び出し側の責務）。消さずに残すのは、**ボタンの置き場所そのものを見せておく**ため——押せない間にボタンが
//! 消えると、最初に画面を見たときに何を押せばよいのか分からない。
//!
//! **いまこの形を使うのは2か所**——会話画面の「送信」（入力欄が空白だけの間）と、ポリシーエディタの「記録を開始」
//! （コマンド欄が空の間）。どちらも押しても何も起きない間で、押せる見た目にすると壊れて見える（効く操作だけを案内する、
//! B-32）。2026-10-03〜10-06は、ユーザーが2つの画面のボタンの色の違い（灰色の「送信」とシアンの「記録を開始」）を
//! 指摘したのに合わせて「送信」もいつも押せる形にし、両方とも空のまま押したら理由を1行出していたが、2026-10-06に
//! ユーザーが「空の送信・空の記録の開始では何も出さない」と決め、「送信」をこの形に戻し、「記録を開始」もこの形に
//! した（`plans/PLAN-TUI-IMPROVEMENTS.md`§4.1）。
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
//! - 見た目は上の表のとおり（普通・押されている・押せない）。
//!
//! # 限界
//!
//! - 色は呼び出し側が選ぶ。押せるかどうかは色と太字で見せる——色を持たない端末では、押せるボタンと押せない
//!   ボタンの違いは太字だけになる（押されている形は文字色と背景色の入れ替えなので、色を持たない端末でも見える）。
//! - 押してから外へずらしても取り消せない（動作は押した瞬間に済んでいる）。押されている形は、離すか、ボタンを押さずに
//!   ポインタが動くか、別の場所を押すまで残る——**離したことを報告しない端末では、ポインタが次に動くまで残る**。
//! - 押されている形を戻すのは、呼び出し側が時間の進みを伝えたとき（[`Press::tick`]）か、離したとき（[`Press::up`]）。
//!   最低時間が過ぎてから戻るまでは、呼び出し側が次に描くまで（会話画面で最大33ms、ポリシーエディタで最大100ms）遅れる。
//! - 枠付きのボタンは、ボタンの数が変わると列の幅が変わり、ボタンの位置が動く（ユーザーの図では「中断」が「送信」の
//!   右に並ぶので、出入りすると「送信」が動く）。同じ場所でボタンの働きが入れ替わることもある（ポリシーエディタの
//!   「記録を開始」⇄「停止を予約」「停止」）。動いた直後・入れ替わった直後の押し間違いを捨てるかは呼び出し側が決める
//!   （会話TUIの`app::pointer`、ポリシーエディタの`tui::pointer`。どちらも300ms捨てる）。

use std::time::{Duration, Instant};

use crossterm::event::{MouseButton, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

/// ボタンの間の桁数（何も描かない）。
pub const GAP: u16 = 1;

/// ボタンの見た目（モジュールdocの表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    /// 押せる。
    Normal,
    /// いま押されている（[`Press`]）。
    Pressed,
    /// いまは押せない（薄く描く。押す場所も登録しない）。
    Disabled,
}

impl Look {
    /// 普通の形を`base`とした、この見た目の文字の色と修飾（押されている形は`base`の文字色と背景色を入れ替える）。
    fn style(self, base: Style) -> Style {
        match self {
            Look::Normal => base,
            Look::Pressed => base.add_modifier(Modifier::REVERSED),
            Look::Disabled => Style::default().fg(Color::DarkGray),
        }
    }
}

/// 辺に載せるボタン1つ（文言の左右に1桁ずつ余白を付ける）。普通の形は`color`の背景に黒の太字（モジュールdocの表）。
pub fn span(label: &str, color: Color, look: Look) -> Span<'static> {
    let normal = Style::default()
        .fg(Color::Black)
        .bg(color)
        .add_modifier(Modifier::BOLD);
    Span::styled(format!(" {label} "), look.style(normal))
}

/// 押されている形を、離してからも残す長さの下限（押した瞬間から数える。モジュールdoc「押した瞬間の見た目」）。
///
/// 前例の無い値で、150msに決めた——素早いクリックは押してから離すまで100ms前後で、押した瞬間に動作して画面が変わる
/// ボタンでは、離した瞬間に戻すと押した色が描かれる前に消える。会話画面は33msごと、ポリシーエディタは100msごとに描き直す
/// ので、どちらでも少なくとも1回は押した形が描かれる長さにした（それより長いと、連打したときに前の押下の色が残って見える）。
pub const PRESSED_AT_LEAST: Duration = Duration::from_millis(150);

/// いま押されているボタン（多くても1つ）。`K`はボタンの名前で、何を同じボタンとみなすかは呼び出し側が決める
/// （会話画面はクリックで起こす動き`Click`の値、ポリシーエディタは押すと文言の変わる「記録を開始」⇄「停止」を
/// 1つのボタンとみなす名前）。
///
/// 時刻は外から渡す（`now`）。呼び出し側はイベントを受けた時刻・描き直しの合図の時刻を渡し、試験は時刻を作って渡す
/// （実時間で待たない。ポリシーエディタの`state::is_double_esc`と同じ形）。
#[derive(Debug, Clone)]
pub struct Press<K> {
    held: Option<Held<K>>,
}

#[derive(Debug, Clone)]
struct Held<K> {
    button: K,
    /// 押した時刻。
    at: Instant,
    /// 離したか（離していなければ、最低時間が過ぎても戻さない）。
    released: bool,
}

impl<K> Default for Press<K> {
    fn default() -> Self {
        Self { held: None }
    }
}

impl<K: PartialEq> Press<K> {
    /// `button`を押した。前に押していたボタンは離したことになる（押せるのは1つだけ）。
    /// **呼び出し側は、押して動作が起きるときだけ呼ぶ**——押しても捨てるクリック（動いた直後のボタン・開いた直後の
    /// ダイアログ）に押した色を付けると、何かが起きたように見える。
    pub fn down(&mut self, button: K, now: Instant) {
        self.held = Some(Held {
            button,
            at: now,
            released: false,
        });
    }

    /// マウスのボタンを離した。押してから[`PRESSED_AT_LEAST`]が過ぎていれば押されている形を戻して真を返す
    /// （描き直しが要る）。過ぎていなければ離したことだけを覚え、過ぎたときに[`Self::tick`]が戻す。
    pub fn up(&mut self, now: Instant) -> bool {
        if let Some(held) = self.held.as_mut() {
            held.released = true;
        }
        self.tick(now)
    }

    /// マウスのイベントの種類を渡す。左ボタンの押下・離上と、どのボタンも押さずに動いたことは、どれも「前に押していた
    /// ボタンはもう離されている」ことを表すので[`Self::up`]を呼ぶ（離したことを報告しない端末でも、次に動かすか押せば
    /// 戻る）。戻して描き直しが要るなら真。押下でボタンを押したなら、この後で[`Self::down`]を呼ぶ。
    pub fn pointer(&mut self, kind: MouseEventKind, now: Instant) -> bool {
        match kind {
            MouseEventKind::Down(MouseButton::Left)
            | MouseEventKind::Up(MouseButton::Left)
            | MouseEventKind::Moved => self.up(now),
            _ => false,
        }
    }

    /// 時間が進んだ。離していて、押してから[`PRESSED_AT_LEAST`]が過ぎていれば押されている形を戻して真を返す
    /// （描き直しが要る）。
    pub fn tick(&mut self, now: Instant) -> bool {
        let done = self.held.as_ref().is_some_and(|held| {
            held.released && now.saturating_duration_since(held.at) >= PRESSED_AT_LEAST
        });
        if done {
            self.held = None;
        }
        done
    }

    /// ボタン`button`の見た目。`pressable`はいま押せるか。
    ///
    /// いま押されているボタンなら、**押せなくても**[`Look::Pressed`]（押した結果押せなくなったボタン。モジュールdoc
    /// 「押した瞬間の見た目」）。押されていなければ、押せるなら[`Look::Normal`]、押せないなら[`Look::Disabled`]。
    /// 押せないボタンの名前も渡す——名前が無いと、押した結果押せなくなったボタンを見分けられない。
    pub fn look(&self, button: &K, pressable: bool) -> Look {
        let held = self
            .held
            .as_ref()
            .is_some_and(|held| held.button == *button);
        match (held, pressable) {
            (true, _) => Look::Pressed,
            (false, true) => Look::Normal,
            (false, false) => Look::Disabled,
        }
    }
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
    /// 見た目（[`Press::look`]で選ぶ）。押せない形（[`Look::Disabled`]）は枠も文字も暗い灰色で描く（押す場所を
    /// 登録しないのは呼び出し側）。
    pub look: Look,
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
    let border = button.look.style(Style::default().fg(color));
    let label = match button.look {
        Look::Disabled => border,
        _ => border.add_modifier(Modifier::BOLD),
    };
    // 押されている形は枠の中（文言の左右の余白）まで入れ替える（ボタン全体が塗られて見える）。
    if button.look == Look::Pressed {
        frame.buffer_mut().set_style(rect, border);
    }
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
            span("Esc=中断", Color::Cyan, Look::Normal),
            span("Alt+Enter=送信", Color::Cyan, Look::Normal),
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

    fn send(look: Look) -> Framed<'static> {
        Framed {
            label: "送信",
            key: "Alt+Enter",
            look,
        }
    }

    fn cancel() -> Framed<'static> {
        Framed {
            label: "中断",
            key: "Esc",
            look: Look::Normal,
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
        let (rest, row, drawn, buffer) = framed(&[send(Look::Normal)], 60, 3, 0);
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

        let (_, row, drawn, buffer) = framed(&[send(Look::Normal), cancel()], 60, 3, 0);
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
            ..send(Look::Normal)
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

    /// **枠付きのボタンの3つの見た目**——普通は枠と文言がボタンの色で文言が太字。押されている形は同じ色に文字色と背景色の
    /// 入れ替え（`REVERSED`）が枠・文言・キー・**文言の左右の余白まで**付く（ボタン全体が塗られて見える）。押せない形は
    /// 枠・文言・キーが暗い灰色で、太字も入れ替えも無い。3つとも文字と位置は同じ（見た目だけが変わる）。
    #[test]
    fn a_framed_button_has_three_looks() {
        let mut texts = Vec::new();
        for (look, color, bold, reversed) in [
            (Look::Normal, Color::Cyan, true, false),
            (Look::Pressed, Color::Cyan, true, true),
            (Look::Disabled, Color::DarkGray, false, false),
        ] {
            let (_, row, drawn, buffer) = framed(&[send(look)], 30, 3, 0);
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
            // 文言の左の余白（枠線の右隣）。
            let padding = &buffer[(rect.x + 1, rect.y + 1)];
            assert_eq!(padding.symbol(), " ");
            assert_eq!(
                (corner.fg, label.fg, key.fg),
                (color, color, color),
                "{look:?}"
            );
            assert_eq!(label.modifier.contains(Modifier::BOLD), bold, "{look:?}");
            for (what, cell) in [
                ("枠", corner),
                ("文言", label),
                ("キー", key),
                ("余白", padding),
            ] {
                assert_eq!(
                    cell.modifier.contains(Modifier::REVERSED),
                    reversed,
                    "{look:?}: {what}"
                );
            }
            texts.push(rows(&buffer, row.expect("置けるはず").0));
        }
        assert!(texts.windows(2).all(|pair| pair[0] == pair[1]), "{texts:?}");
    }

    /// **辺に載せるボタンの3つの見た目**——普通はボタンの色の背景に黒の太字、押されている形はそれに入れ替え（`REVERSED`）、
    /// 押せない形は暗い灰色の文字。文字と幅はどれも同じ（並べた行の幅・折り返しが見た目で変わらない）。
    #[test]
    fn an_edge_button_has_three_looks() {
        let normal = span("y=書く", Color::Yellow, Look::Normal);
        let pressed = span("y=書く", Color::Yellow, Look::Pressed);
        let disabled = span("y=書く", Color::Yellow, Look::Disabled);
        assert_eq!(
            (normal.style.fg, normal.style.bg),
            (Some(Color::Black), Some(Color::Yellow))
        );
        assert!(normal.style.add_modifier.contains(Modifier::BOLD));
        assert!(!normal.style.add_modifier.contains(Modifier::REVERSED));
        assert_eq!(
            pressed.style,
            normal.style.add_modifier(Modifier::REVERSED),
            "押されている形は普通の形の入れ替え"
        );
        assert_eq!(disabled.style, Style::default().fg(Color::DarkGray));
        for button in [&normal, &pressed, &disabled] {
            assert_eq!(button.content, " y=書く ");
        }
    }

    // --- 押した瞬間の見た目 ---

    /// **押した瞬間に押されている形になり、離していても[`PRESSED_AT_LEAST`]が過ぎるまでは戻らず、過ぎたら戻る。**
    /// 押していないボタンは普通の形のまま。時刻は作って渡す。
    ///
    /// **押せないボタン**は、押されていなければ押せない形。**押した結果押せなくなったボタン**（会話画面の「送信」は押すと
    /// 入力欄が空になって押せなくなる）は、押されている形が戻るまで押されている形で、戻ったら押せない形（2026-10-06。
    /// それまでは押せないボタンをいつも押せない形にしていたが、押せない形を使う画面が無い間に決めたもので、「送信」を
    /// 押せない形に戻すと押した色が一度も見えなくなった）。
    #[test]
    fn a_press_shows_until_released_and_at_least_the_minimum_time() {
        let t0 = Instant::now();
        let mut press: Press<&str> = Press::default();
        assert_eq!(press.look(&"送信", true), Look::Normal);
        assert_eq!(
            press.look(&"送信", false),
            Look::Disabled,
            "押していない、押せないボタン"
        );
        press.down("送信", t0);
        assert_eq!(press.look(&"送信", true), Look::Pressed);
        assert_eq!(
            press.look(&"送信", false),
            Look::Pressed,
            "押した結果押せなくなったボタン"
        );
        assert_eq!(
            press.look(&"中断", true),
            Look::Normal,
            "押していないボタン"
        );
        assert_eq!(
            press.look(&"中断", false),
            Look::Disabled,
            "押していない、押せないボタン"
        );

        // 最低時間の前に離した: 離したことだけ覚えて、まだ戻さない。
        let early = t0 + PRESSED_AT_LEAST - Duration::from_millis(1);
        assert!(!press.up(t0 + Duration::from_millis(80)));
        assert!(!press.tick(early));
        assert_eq!(press.look(&"送信", true), Look::Pressed);
        assert_eq!(press.look(&"送信", false), Look::Pressed);
        // 過ぎたら戻る（押せなくなったボタンは押せない形へ）。
        assert!(press.tick(t0 + PRESSED_AT_LEAST));
        assert_eq!(press.look(&"送信", true), Look::Normal);
        assert_eq!(press.look(&"送信", false), Look::Disabled);
        assert!(!press.tick(t0 + PRESSED_AT_LEAST), "戻した後は何も変えない");
    }

    /// **離していなければ、最低時間が過ぎても戻さない**（押している間は押されている形）。過ぎてから離すと、その場で
    /// 戻して真を返す（描き直しが要る）。
    #[test]
    fn a_held_press_stays_until_it_is_released() {
        let t0 = Instant::now();
        let mut press: Press<&str> = Press::default();
        press.down("記録", t0);
        assert!(!press.tick(t0 + Duration::from_secs(5)));
        assert_eq!(press.look(&"記録", true), Look::Pressed);
        assert!(press.up(t0 + Duration::from_secs(5)));
        assert_eq!(press.look(&"記録", true), Look::Normal);
    }

    /// **左ボタンを離す・ボタンを押さずに動く・別の場所を押すは、どれも離したことになる**（離したことが報告されない端末
    /// でも戻る）。ドラッグ（押したまま動く）・右ボタン・ホイールは離したことにならない。別のボタンを押せば、押されて
    /// いるのはそちらだけになる。
    #[test]
    fn the_pointer_events_that_mean_released() {
        let t0 = Instant::now();
        let later = t0 + PRESSED_AT_LEAST;
        for kind in [
            MouseEventKind::Up(MouseButton::Left),
            MouseEventKind::Moved,
            MouseEventKind::Down(MouseButton::Left),
        ] {
            let mut press: Press<&str> = Press::default();
            press.down("送信", t0);
            assert!(press.pointer(kind, later), "{kind:?}");
            assert_eq!(press.look(&"送信", true), Look::Normal, "{kind:?}");
        }
        for kind in [
            MouseEventKind::Drag(MouseButton::Left),
            MouseEventKind::Up(MouseButton::Right),
            MouseEventKind::Down(MouseButton::Right),
            MouseEventKind::ScrollDown,
        ] {
            let mut press: Press<&str> = Press::default();
            press.down("送信", t0);
            assert!(!press.pointer(kind, later), "{kind:?}");
            assert!(!press.tick(later), "{kind:?}: 離したことになった");
            assert_eq!(press.look(&"送信", true), Look::Pressed, "{kind:?}");
        }
        let mut press: Press<&str> = Press::default();
        press.down("送信", t0);
        press.down("中断", t0 + Duration::from_millis(10));
        assert_eq!(press.look(&"送信", true), Look::Normal);
        assert_eq!(press.look(&"中断", true), Look::Pressed);
    }

    /// **狭いときは、キーを添える形 → キーを落とした短い形 → 置かない**。どの形でも左に`keep`桁が残り、ボタンは途中で
    /// 切れない。置かないときは全体を返す。
    #[test]
    fn a_narrow_area_falls_back_to_short_buttons_and_then_to_none() {
        let buttons = [send(Look::Normal), cancel()];
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
        let (rest, row, drawn, buffer) = framed(&[send(Look::Normal)], 40, 7, 0);
        let (row, _) = row.expect("置けるはず");
        assert_eq!((row.y, row.height), (4, 3), "下端にそろっていない");
        assert_eq!(rest.height, 7);
        assert_eq!(buffer[(drawn[0].x, 4)].symbol(), "┌");
        assert_eq!(
            text_at(&buffer, row.x, 0, row.width).trim(),
            "",
            "ボタンの上に何か描いた"
        );

        let (rest, row, _, _) = framed(&[send(Look::Normal)], 40, 2, 0);
        assert!(row.is_none());
        assert_eq!(rest, Rect::new(0, 0, 40, 2));
        let (rest, row, _, _) = framed(&[], 40, 3, 0);
        assert!(row.is_none());
        assert_eq!(rest, Rect::new(0, 0, 40, 3));
    }
}
