//! 画面に出ている文章をマウスで選ぶ（会話TUIとポリシーエディタが共有する。2026-10-03）。
//!
//! # 何のためにあるのか
//!
//! 2つの画面は、ホイールとクリックを受け取るために、起動時に端末へ「マウスの操作をアプリへ渡す」よう頼んでいる
//! （[`crate::TerminalGuard`]の`EnableMouseCapture`）。そのため端末自身の文字選択はふつうのドラッグでは働かず、
//! Shiftを押しながらのドラッグで選べても、枠線やスクロールバーまで一緒に選ばれ、画面の外は選べず、折り返した所に
//! 改行が入る（VS Codeの統合ターミナルでは、選んだ後の右クリックもアプリへ渡ってしまい、クリップボードへ入らない）。
//! そこで**選ぶこと・写すことをアプリ側で持つ**。選んだ文章は、描いた枠のセルではなく**描いた文章そのもの**から
//! 取り出す——枠線・スクロールバー・余白は入らず、折り返して描いた1行は元の1行に戻る（[`map`]）。
//!
//! # 使い方
//!
//! 1. 状態として[`Selection`]を1つ持つ。枠の名前`W`は、その枠をホイールで送るときの名前（[`crate::pointer::Targets`]の
//!    `W`）をそのまま使う——選べる枠はどれも送れる枠で、枠の外へドラッグしたときはホイールと同じ送り方で送るため。
//! 2. 送れる枠（[`crate::scrollable`]・[`crate::scrollback`]）を描くときに[`Selectable`]を渡す。枠は選んでいる範囲に
//!    選択の色（[`SELECTED`]）を付けて描き、**どの文字を画面のどこに描いたか**を押せる場所と一緒に登録する。
//!    長い1行を自分で複数の`Line`へ分けて描く文章（字下げを保つ折り返し）は、[`Selectable::joined`]で
//!    「どの行が前の行の続きか」（[`LineJoin`]）を渡す——写すと元の1行に戻る。
//! 3. 描き終えたら[`Selection::after_draw`]（その描画で決まった範囲の端と文章を受け取る）。
//! 4. マウス: 枠の上で左ボタンを押したら（[`crate::pointer::Pointer::Text`]）[`Selection::press`]、押したまま動いたら
//!    [`Selection::drag`]、離したら[`Selection::release`]。時間が進んだら[`Selection::tick`]（枠の外で止めている間も送る）。
//! 5. 写すとき（`Ctrl+C`・右クリック）は[`Selection::copy`]。返った文章をクリップボードへ書くのは呼び出し側
//!    （[`crate::clipboard::write`]）——状態は端末の外の世界に触らない。
//!
//! # 押した瞬間のクリックは変えない
//!
//! クリックは今までどおり押した瞬間に効く（[`crate::pointer`]）。選び始めるのは、**押せる場所ではない**文章の上で押して、
//! 別のセルへずらしたときだけ。ずらさずに離したら何も選ばない（[`Selection::release`]がその枠を返すので、
//! 「離したら閉じる」のような扱いは呼び出し側が決める）。ボタンや押せる行の上で押してずらしても選び始めない。
//!
//! # 選んだ範囲は文章の位置で持つ
//!
//! 範囲は「描いた`Text`の何行目の何文字目」で持つ（[`map::Pos`]）。送っても、末尾に応答が流れ込んでも、選んだ文章は
//! ずれない。ドラッグ中の今の端だけは**ポインタのセル**で持ち、描くたびにその描画で引き直す——送ったり流れ込んだり
//! した後も、いまポインタの下にある文字を指す。
//!
//! **選んだ範囲の文章が描き直しで変わったら、選択を外す**（[`Selection::after_draw`]）。折り畳みの切り替え
//! ・会話の差し替え・古い行の切り捨てで同じ位置に別の文章が来たとき、色を付けた所と写すものが食い違わないように
//! するため（違う文章を写すより、選び直させるほうがよい）。その枠を描かなくなったとき（重ねた枠を閉じた・画面を
//! 移った）も外す。
//!
//! # 限界
//!
//! - 選べるのは送れる枠（[`crate::scrollable`]・[`crate::scrollback`]）の文章だけ。押せる行を持つ一覧
//!   （[`crate::list`]）・入力欄・キー案内は選べない。
//! - 選んでいる範囲は1つだけ（別の枠を選び始めると前の範囲は外れる）。
//! - 端は文字単位（単語・行単位の選び方は無い）。
//! - 選んだ後に範囲を伸ばし直すことはできない（押し直すと新しく選び始める）。
//! - **右クリックで写せるのは、端末が右クリックをアプリへ渡すときだけ。** VS Codeの統合ターミナルは、既定
//!   （`terminal.integrated.rightClickBehavior`が`copyPaste`）では右クリックを自分で受け、端末自身の選択が無ければ
//!   クリップボードの中身を貼り付ける——アプリ側の選択は端末からは見えないので、選んでいても貼り付けになり、
//!   アプリには届かない（2026-10-03、ユーザーが実機で確かめた。同じ時に`Ctrl+C`では写せた）。アプリの側からは
//!   止められないので、案内は`Ctrl+C`を主にする。設定を`nothing`にすれば右クリックがアプリへ届くが、ふだんの
//!   シェルで右クリックの貼り付けが使えなくなるので勧めない。

pub(crate) mod map;

use std::time::{Duration, Instant};

use ratatui::style::{Color, Style};

use crate::pointer::Targets;
pub(crate) use map::TextMap;
use map::{Head, Hit, Mark};

/// 選んだ文字の見た目。**明示的な背景色**で、文字色と背景色の入れ替え（`Modifier::REVERSED`）は使わない——
/// 入れ替えは一覧の「いまの行」と押されているボタン（[`crate::button::Look::Pressed`]）の見た目で、選んだ範囲と
/// 見分けが付かなくなる。色は会話TUIの入力欄のキーボードでの選択と同じ（同じ「選んでいる」を同じ見た目にする）。
/// 送れる枠の文字に重ねるときは、入れ替えの行（承認ダイアログの候補のカーソル）にあっても入れ替えを外して
/// 同じ見た目にする（[`map`]）。
pub const SELECTED: Style = Style::new().fg(Color::White).bg(Color::Blue);

/// ドラッグ中にポインタが枠の上下の外にある間、枠をホイール1刻みぶん送る間隔。
///
/// ポリシーエディタのイベントループの1周（100ms）と同じにした——どちらの画面でも同じ速さで送られる
/// （会話画面の描画の合図は33msごとだが、そこに合わせるとエディタだけ遅くなる）。
pub const AUTO_SCROLL_EVERY: Duration = Duration::from_millis(100);

/// 描いた`Text`の1行が、前の行とどうつながるか（写すときだけ使う。描く見た目は変えない）。
///
/// # 何のためにあるのか
///
/// 字下げを保ったまま折り返すために、**描画部品が自分で長い1行を幅に合わせて複数の`Line`へ分ける**ことがある
/// （Markdownのリスト項目・引用の続きの行は、2行目以降も項目の字下げの位置から始まる）。範囲選択で写すときは
/// `Line`の間に改行を入れるので、何もしなければ、画面で分けた位置ごとに改行と字下げの空白が入って写る。
/// 分けた側がこの印で「この行は前の行の続き」と伝えると、写すときに元の1行へ戻す——前の行との間に改行を入れず、
/// この行の頭の字下げ（`indent`文字）を写さない。選択の色も字下げには付けない（色を付けた所と写る文字を揃える）。
///
/// 描いた`Text`はフレームをまたいで残らず、写す文章は描くたびにその場で取り出す（[`map`]）ので、印は描くときに
/// [`Selectable::joined`]で渡す。
///
/// # 限界
///
/// - 語の切れ目の空白は、分けた側が**前の行の末尾に残す**ものとして扱う（つなぐときに空白を足さない）。
///   英語の語の間で分けて空白を落とすと、つないだ語が詰まって写る。
/// - `indent`は文字（書記素）の数で数え、桁の数ではない（[`map::Pos`]と同じ数え方）。字下げの中身が空白かどうかは見ない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineJoin {
    /// 前の行とは別の行（写すとき、前の行との間に改行を入れる）。
    #[default]
    Break,
    /// 前の行の続き（描画部品が幅に合わせて分けた行）。写すとき、前の行との間に改行を入れず、
    /// 行の頭の`indent`文字（続きの行に付けた字下げ）を写さない。
    Continues {
        /// 行の頭の字下げの文字の数（[`map::Pos`]の`offset`と同じく、描かれる書記素で数える）。
        indent: usize,
    },
}

/// 送れる枠を描くときに渡すもの（モジュールdocの2）。`surface`はその枠の名前、`selection`は画面が持つ選択。
pub struct Selectable<'s, C, W> {
    pub targets: &'s mut Targets<C, W>,
    pub surface: W,
    pub selection: &'s Selection<W>,
    /// 描く`Text`の行ごとの、前の行とのつながり（[`LineJoin`]）。空なら全部`Break`（[`Self::new`]の既定）。
    pub(crate) joins: &'s [LineJoin],
}

impl<'s, C, W> Selectable<'s, C, W> {
    /// 全部の行を`Break`として写す（行の間に改行を入れる）。続きの行を持つ文章は[`Self::joined`]で印を足す。
    pub fn new(targets: &'s mut Targets<C, W>, surface: W, selection: &'s Selection<W>) -> Self {
        Self {
            targets,
            surface,
            selection,
            joins: &[],
        }
    }

    /// 描く`Text`の行ごとの、前の行とのつながりを渡す（[`LineJoin`]）。**`joins`は描く`Text`の行と同じ数**にする
    /// （空なら全部`Break`。数が違うのは呼び出し側の誤りで、デバッグビルドでは描くときに止まる）。
    pub fn joined(self, joins: &'s [LineJoin]) -> Self {
        Self { joins, ..self }
    }
}

/// 枠をホイール1刻みぶん送ってほしい（ドラッグ中にポインタが枠の外へ出た）。`up`が真なら先頭の向き。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scroll<W> {
    pub surface: W,
    pub up: bool,
}

/// [`Selection::drag`]の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dragged<W> {
    /// このドラッグで選び始めた（押した所から初めてずれた）。
    pub started: bool,
    /// 枠を送ってほしい。
    pub scroll: Option<Scroll<W>>,
}

/// 画面が持つ選択（モジュールdoc）。`W`は枠の名前。
#[derive(Debug, Clone)]
pub struct Selection<W> {
    state: State<W>,
}

impl<W> Default for Selection<W> {
    fn default() -> Self {
        Self { state: State::Idle }
    }
}

#[derive(Debug, Clone)]
enum State<W> {
    Idle,
    /// 文章の上で押した。まだずらしていない。
    Pressed {
        surface: W,
        anchor: Hit,
        at: (u16, u16),
    },
    /// 押したまま、押した所からずらしている。
    Dragging {
        surface: W,
        anchor: Hit,
        pointer: (u16, u16),
        /// 直前の描画で決まった端と文章（範囲が空なら`None`）。
        drawn: Option<(Hit, String)>,
        /// 枠の外で最後に送った時刻。
        scrolled_at: Option<Instant>,
    },
    /// 選んだ（離した）。
    Selected {
        surface: W,
        anchor: Hit,
        head: Hit,
        text: String,
    },
}

impl<W: Clone + PartialEq> Selection<W> {
    /// 何かを選んでいるか、選んでいる途中（押している）か。`Esc`はこれが真なら選択を外すだけにする。
    pub fn is_active(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// 文章の上で左ボタンを押したまま（離したかどうかを見る必要がある）。
    pub fn is_held(&self) -> bool {
        matches!(self.state, State::Pressed { .. } | State::Dragging { .. })
    }

    /// 写せる文章がある（選んでいる範囲が空でない）。
    pub fn has_text(&self) -> bool {
        match &self.state {
            State::Dragging { drawn, .. } => drawn.is_some(),
            State::Selected { .. } => true,
            State::Idle | State::Pressed { .. } => false,
        }
    }

    /// 選んでいる（選び始めた）枠。
    pub fn surface(&self) -> Option<&W> {
        match &self.state {
            State::Idle => None,
            State::Pressed { surface, .. }
            | State::Dragging { surface, .. }
            | State::Selected { surface, .. } => Some(surface),
        }
    }

    /// 選択を外す。
    pub fn clear(&mut self) {
        self.state = State::Idle;
    }

    /// 枠`surface`を描くときの、選んでいる範囲の決め方（その枠を選んでいなければ`None`）。
    pub(crate) fn mark(&self, surface: &W) -> Option<Mark> {
        match &self.state {
            State::Dragging {
                surface: s,
                anchor,
                pointer,
                ..
            } if s == surface => Some(Mark {
                anchor: *anchor,
                head: Head::Pointer(pointer.0, pointer.1),
            }),
            State::Selected {
                surface: s,
                anchor,
                head,
                ..
            } if s == surface => Some(Mark {
                anchor: *anchor,
                head: Head::Fixed(*head),
            }),
            _ => None,
        }
    }

    /// 枠`surface`の文章の上で左ボタンを押した（直前に描いた画面の`targets`で引いた。[`crate::pointer::Pointer::Text`]）。
    /// 前の選択は外れる。描いた文字が1つも無い枠なら何も始めない。
    pub fn press<C>(&mut self, targets: &Targets<C, W>, surface: W, column: u16, row: u16) {
        self.state = match targets
            .text_map(&surface)
            .and_then(|map| map.hit(column, row))
        {
            Some(anchor) => State::Pressed {
                surface,
                anchor,
                at: (column, row),
            },
            None => State::Idle,
        };
    }

    /// 左ボタンを押したままポインタが`(column, row)`へ動いた。押した所から別のセルへずれたら選び始める。
    /// ポインタが枠の上下の外なら、その向きへ送ってほしいと返す（[`AUTO_SCROLL_EVERY`]に1回）。
    pub fn drag<C>(
        &mut self,
        targets: &Targets<C, W>,
        column: u16,
        row: u16,
        now: Instant,
    ) -> Dragged<W> {
        let mut started = false;
        if let State::Pressed {
            surface,
            anchor,
            at,
        } = &self.state
        {
            if *at != (column, row) {
                self.state = State::Dragging {
                    surface: surface.clone(),
                    anchor: *anchor,
                    pointer: (column, row),
                    drawn: None,
                    scrolled_at: None,
                };
                started = true;
            }
        }
        if let State::Dragging { pointer, .. } = &mut self.state {
            *pointer = (column, row);
        }
        Dragged {
            started,
            scroll: self.edge_scroll(targets, now),
        }
    }

    /// 左ボタンを離した。ずらしていたなら選んだ範囲が残り（直前の描画で色を付けた範囲。空なら残らない）、
    /// **ずらさずに離したなら、押した枠を返す**（文章の上のただのクリック。呼び出し側が扱いを決める）。
    pub fn release(&mut self) -> Option<W> {
        match std::mem::replace(&mut self.state, State::Idle) {
            State::Pressed { surface, .. } => Some(surface),
            State::Dragging {
                surface,
                anchor,
                drawn: Some((head, text)),
                ..
            } => {
                self.state = State::Selected {
                    surface,
                    anchor,
                    head,
                    text,
                };
                None
            }
            State::Selected {
                surface,
                anchor,
                head,
                text,
            } => {
                self.state = State::Selected {
                    surface,
                    anchor,
                    head,
                    text,
                };
                None
            }
            State::Idle | State::Dragging { drawn: None, .. } => None,
        }
    }

    /// 時間が進んだ。ドラッグ中にポインタを枠の上下の外で止めている間も送り続ける（[`Self::drag`]と同じ間隔）。
    pub fn tick<C>(&mut self, targets: &Targets<C, W>, now: Instant) -> Option<Scroll<W>> {
        self.edge_scroll(targets, now)
    }

    fn edge_scroll<C>(&mut self, targets: &Targets<C, W>, now: Instant) -> Option<Scroll<W>> {
        let State::Dragging {
            surface,
            pointer,
            scrolled_at,
            ..
        } = &mut self.state
        else {
            return None;
        };
        let area = targets.text_map(surface)?.area();
        let up = if pointer.1 < area.y {
            true
        } else if pointer.1 >= area.bottom() {
            false
        } else {
            return None;
        };
        if scrolled_at.is_some_and(|at| now.saturating_duration_since(at) < AUTO_SCROLL_EVERY) {
            return None;
        }
        *scrolled_at = Some(now);
        Some(Scroll {
            surface: surface.clone(),
            up,
        })
    }

    /// 1フレーム描いた後に呼ぶ（`targets`はその描画で登録したもの）。ドラッグ中なら、その描画で決まった端と文章を
    /// 受け取る。選んだ後なら、**選んだ範囲の文章が変わっていないか**を見て、変わっていれば外す。選んでいた枠を
    /// 描かなかったら外す（モジュールdoc）。
    pub fn after_draw<C>(&mut self, targets: &Targets<C, W>) {
        let Some(surface) = self.surface().cloned() else {
            return;
        };
        let Some(map) = targets.text_map(&surface) else {
            self.state = State::Idle;
            return;
        };
        let marked = map.marked();
        match &mut self.state {
            State::Dragging { drawn, .. } => {
                *drawn = marked
                    .filter(|m| !m.text.is_empty())
                    .map(|m| (m.head, m.text.clone()));
            }
            State::Selected { text, .. } => {
                if marked.map(|m| m.text.as_str()) != Some(text.as_str()) {
                    self.state = State::Idle;
                }
            }
            State::Idle | State::Pressed { .. } => {}
        }
    }

    /// 選んでいる文章を取り出して選択を外す（写すとき）。改行はクリップボードの形（`\r\n`）にしてある。
    /// 写せる文章が無ければ`None`で、選択はそのまま。
    pub fn copy(&mut self) -> Option<String> {
        let text = match &self.state {
            State::Dragging {
                drawn: Some((_, text)),
                ..
            }
            | State::Selected { text, .. } => text.clone(),
            _ => return None,
        };
        self.state = State::Idle;
        Some(crate::clipboard::crlf(&text))
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::text::Line;
    use ratatui::widgets::{Block, Borders};
    use ratatui::Terminal;

    use super::*;

    const LOOK: crate::scrollable::Look = crate::scrollable::Look {
        how: "ホイールで送る",
        notice: Style::new(),
        bar: Style::new(),
    };

    /// 40行の本文を、10行の枠に`top`から描き、その描画で登録したものを返す。
    fn paint(selection: &mut Selection<&'static str>, top: u16) -> Targets<(), &'static str> {
        let lines: Vec<Line> = (0..40).map(|i| Line::raw(format!("line {i:02}"))).collect();
        let mut targets: Targets<(), &str> = Targets::default();
        let mut term = Terminal::new(TestBackend::new(20, 12)).expect("test terminal");
        term.draw(|frame| {
            crate::scrollable::draw(
                frame,
                frame.area(),
                lines,
                Block::default().borders(Borders::ALL),
                top,
                LOOK,
                Selectable::new(&mut targets, "box", selection),
            );
        })
        .expect("draw");
        selection.after_draw(&targets);
        targets
    }

    /// 押してずらさずに離したら何も選ばず、押した枠を返す（ただのクリック）。
    #[test]
    fn a_press_without_moving_selects_nothing() {
        let mut selection = Selection::default();
        let targets = paint(&mut selection, 0);
        selection.press(&targets, "box", 3, 2);
        assert!(selection.is_held());
        assert!(!selection.drag(&targets, 3, 2, Instant::now()).started);
        assert_eq!(selection.release(), Some("box"));
        assert!(!selection.is_active());
        assert_eq!(selection.copy(), None);
    }

    /// ずらすと選び始め、描いた後に範囲の文章が決まり、離すと残る。写すと外れる。
    #[test]
    fn dragging_selects_and_releasing_keeps_it() {
        let mut selection = Selection::default();
        let targets = paint(&mut selection, 0);
        // 1行目（y=1）の「line 00」の頭から、2行目の「line 01」の末尾の文字まで。
        selection.press(&targets, "box", 1, 1);
        assert!(selection.drag(&targets, 7, 2, Instant::now()).started);
        assert!(!selection.has_text(), "描く前はまだ範囲が決まっていない");
        let targets = paint(&mut selection, 0);
        assert!(selection.has_text());
        assert_eq!(selection.release(), None);
        let _ = paint(&mut selection, 0);
        assert_eq!(selection.copy().as_deref(), Some("line 00\r\nline 01"));
        assert!(!selection.is_active());
        drop(targets);
    }

    /// 枠の下の外へずらすと、間隔をあけて下へ送ってほしいと返す。止めていても時間が進めば送り続ける。
    #[test]
    fn dragging_below_the_box_asks_to_scroll_down_at_an_interval() {
        let mut selection = Selection::default();
        let targets = paint(&mut selection, 0);
        let start = Instant::now();
        selection.press(&targets, "box", 2, 3);
        let below = selection.drag(&targets, 2, 11, start);
        assert_eq!(
            below.scroll,
            Some(Scroll {
                surface: "box",
                up: false
            })
        );
        assert_eq!(
            selection.drag(&targets, 3, 11, start).scroll,
            None,
            "間隔より早い"
        );
        assert_eq!(
            selection.tick(&targets, start + AUTO_SCROLL_EVERY / 2),
            None
        );
        assert_eq!(
            selection.tick(&targets, start + AUTO_SCROLL_EVERY),
            Some(Scroll {
                surface: "box",
                up: false
            })
        );
        // 枠の中へ戻れば送らない。
        selection.drag(&targets, 3, 5, start + AUTO_SCROLL_EVERY * 3);
        assert_eq!(
            selection.tick(&targets, start + AUTO_SCROLL_EVERY * 4),
            None
        );
        // 上の外へ出れば上へ。
        assert_eq!(
            selection
                .drag(&targets, 3, 0, start + AUTO_SCROLL_EVERY * 5)
                .scroll,
            Some(Scroll {
                surface: "box",
                up: true
            })
        );
    }

    /// 選んだ範囲の文章が描き直しで変わったら外す。描かなくなったら外す。変わらなければ残る（許可側）。
    #[test]
    fn the_selection_is_dropped_when_its_text_changes_or_its_box_is_gone() {
        let mut selection = Selection::default();
        let targets = paint(&mut selection, 0);
        selection.press(&targets, "box", 1, 1);
        selection.drag(&targets, 4, 1, Instant::now());
        let _ = paint(&mut selection, 0);
        selection.release();
        let _ = paint(&mut selection, 5);
        assert!(selection.has_text(), "送っただけで外れた");

        // 同じ位置に別の文章を描く。
        let mut targets: Targets<(), &str> = Targets::default();
        let mut term = Terminal::new(TestBackend::new(20, 12)).expect("test terminal");
        term.draw(|frame| {
            crate::scrollable::draw(
                frame,
                frame.area(),
                vec![Line::raw("other text")],
                Block::default().borders(Borders::ALL),
                0,
                LOOK,
                Selectable::new(&mut targets, "box", &selection),
            );
        })
        .expect("draw");
        selection.after_draw(&targets);
        assert!(!selection.is_active(), "文章が変わったのに残った");

        let targets = paint(&mut selection, 0);
        selection.press(&targets, "box", 1, 1);
        selection.drag(&targets, 4, 1, Instant::now());
        selection.after_draw(&Targets::<(), &str>::default());
        assert!(!selection.is_active(), "枠を描かなくなったのに残った");
    }

    /// 選べる文章を描く2つの部品（`prepare`を呼ぶ2か所）。
    #[derive(Debug, Clone, Copy)]
    enum Renderer {
        /// 末尾追従の枠（会話TUIのtranscript。[`crate::scrollback::render_with_bar`]）。
        Scrollback,
        /// 先頭から読ませる枠（承認ダイアログ等。[`crate::scrollable::draw`]）。
        Scrollable,
    }

    /// 項目の続きの行を持つ3行を`renderer`で描く。`joins`が`Some`なら`.joined`で渡す。
    fn paint_log(
        selection: &mut Selection<&'static str>,
        joins: Option<&[LineJoin]>,
        renderer: Renderer,
    ) -> Targets<(), &'static str> {
        let lines = vec![
            Line::raw("- the first item "),
            Line::raw("  continues here"),
            Line::raw("- the second item"),
        ];
        let mut targets: Targets<(), &str> = Targets::default();
        let mut term = Terminal::new(TestBackend::new(30, 8)).expect("test terminal");
        term.draw(|frame| {
            let on = Selectable::new(&mut targets, "log", selection);
            let on = match joins {
                Some(joins) => on.joined(joins),
                None => on,
            };
            let block = Block::default().borders(Borders::ALL);
            match renderer {
                Renderer::Scrollback => {
                    crate::scrollback::render_with_bar(
                        frame,
                        frame.area(),
                        lines,
                        block,
                        crate::scrollback::Scrollback::default(),
                        Style::new(),
                        on,
                    );
                }
                Renderer::Scrollable => {
                    crate::scrollable::draw(frame, frame.area(), lines, block, 0, LOOK, on);
                }
            }
        })
        .expect("draw");
        selection.after_draw(&targets);
        targets
    }

    /// 1行目の頭から3行目の末尾の文字までをドラッグで選んで写す。
    fn drag_all_and_copy(joins: Option<&[LineJoin]>, renderer: Renderer) -> Option<String> {
        let mut selection = Selection::default();
        let targets = paint_log(&mut selection, joins, renderer);
        selection.press(&targets, "log", 1, 1);
        assert!(selection.drag(&targets, 17, 3, Instant::now()).started);
        let _ = paint_log(&mut selection, joins, renderer);
        assert_eq!(selection.release(), None);
        let _ = paint_log(&mut selection, joins, renderer);
        selection.copy()
    }

    /// **印を渡した続きの行は、写すと前の行に付く**（改行は`Break`の行の前だけ、字下げは落ちる）。
    /// 会話TUIのtranscriptの描き方（`scrollback::render_with_bar`）と、先頭から読ませる枠の描き方の両方で確かめる
    /// （印が`prepare`へ届く経路はこの2つ）。同じ画面を印なしで描けば、今までどおり行ごとに改行が入る（対照）。
    #[test]
    fn a_continuation_line_is_copied_as_one_line_through_both_renderers() {
        let joins = [
            LineJoin::Break,
            LineJoin::Continues { indent: 2 },
            LineJoin::Break,
        ];
        for renderer in [Renderer::Scrollback, Renderer::Scrollable] {
            assert_eq!(
                drag_all_and_copy(Some(&joins), renderer).as_deref(),
                Some("- the first item continues here\r\n- the second item"),
                "{renderer:?}"
            );
            assert_eq!(
                drag_all_and_copy(None, renderer).as_deref(),
                Some("- the first item \r\n  continues here\r\n- the second item"),
                "{renderer:?}"
            );
        }
    }

    /// 押せる場所が上にある所で押しても、文章の上ではない（`Targets`が押せる場所を返す）。
    #[test]
    fn the_area_registered_is_the_inside_of_the_box() {
        let mut selection = Selection::default();
        let targets = paint(&mut selection, 0);
        assert_eq!(
            targets.text_map(&"box").map(|m| m.area()),
            Some(Rect::new(1, 1, 18, 10))
        );
    }
}
