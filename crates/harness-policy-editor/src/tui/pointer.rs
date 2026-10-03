//! マウスのクリックとホイール（2026-10-02）。**押せる場所と送れる枠は、描くときに登録する**
//! （土台は会話TUIと共有する`harness_term::pointer`）。
//!
//! # 当たり判定は、描いた矩形そのもの
//!
//! 各画面の描画が、タブ・一覧の行・`[x]`・`▾`/`▸`・入力欄・キー案内の項目・記録の枠のボタン・確認ダイアログのボタンを
//! **描いたその矩形で**[`Targets`]へ登録し、フレームごとに`App::pointer`へ書き戻す
//! （`App::apply_draw_feedback`）。マウスのイベントは、直前に描いたその登録で引く。
//! ホイールの当たり判定も同じ登録を通る——以前は画面の割り付けをイベントのたびに計算し直していたが
//! （`tui::scroll`のdoc）、クリックと同じ登録へ寄せた。当たり判定のために割り付けを写さない（BUG-194）。
//!
//! 直前に描いた画面で引いてよいのは、イベントループが**イベントを1つ処理するたびに描き直す**からである
//! （`tui::run`）。端末の大きさが変わったときも、`Resize`を受けた次の周回で描き直してから次のイベントを読む。
//!
//! # クリックは、キーを押したのと同じ処理を呼ぶ
//!
//! クリック用の処理は書かない（同じ操作を2か所に持つと、片方だけ直る）。[`Click`]はどれも、
//! 次のどちらかで終わる。
//!
//! - **キーを押す**（`App::on_key`）——キー案内の項目・記録の枠のボタン（記録の開始・停止。[`Click::Button`]）・確認ダイアログのボタン・`[x]`（`Space`）・
//!   `▾`/`▸`（`←`/`→`）・入力欄（`Tab`で入るのと同じ）・一番上のタブ（`F1`〜`F3`）。
//! - **キーが呼ぶのと同じ関数を、行の差だけ動かして呼ぶ**——一覧の行を選ぶとき。`↓`をN回押す形にしないのは、
//!   記録セッションの一覧では選択が動くたびにその記録を開き直す（`move_selection`）ので、途中の記録を全部
//!   読むことになるためである。
//!
//! 承認待ちのタブ（FS/ネット・遷移・観測から・遷移・拒否から）は、`F2`の巡回が使う
//! `App::select_pending_tab`を、選んだタブで呼ぶ。
//!
//! # 押せないもの（決めたこと）
//!
//! - **一括の操作**（宣言画面の`A 全件`・遷移タブの`X 表示中を却下`）はキーだけで押せる。クリックには付けない
//!   ——決定51は「一括承認は許さない」を、まとめての操作は読んでから押させる、という形で守っている。
//!   クリックは押し間違えやすく、1回で全件の予約が変わる操作をそこへ置かない。
//! - `↑↓ 選択`・`→← 展開/折畳`・`ホイール …`の案内は、1つのキーに決まらないので押せない（行や記号を押す）。
//! - 確認ダイアログの外側は押せない（書き込みの確認は`y`か`n`/`Esc`を選ばせる。決定32）。
//!
//! # 重ねた枠が開いている間は後ろを押せない
//!
//! 確認ダイアログとヘルプは、描くときに画面全体を覆ってから（`Targets::cover`）自分の場所を登録する
//! （`tui::open_overlay`）。キー入力もその間は重ねた側だけが受ける（`App::on_key`）のと同じ形である。
//! ヘルプは「何かキーを押すと閉じる」ので、クリックでも閉じる（どこを押しても、何でもないキーを
//! 押したのと同じ。[`Click::CloseHelp`]）。
//!
//! # 入力欄に居るときにキー案内を押したら
//!
//! 承認待ちのドメイン欄・遷移先の欄では、文字キーは名前の入力になる。キー案内の`a 承認`を押して
//! 名前に`a`が入るのは押した意図と違うので、**文字キーを押す項目は、先に欄から出る**（`Enter`。
//! 欄から一覧へ戻る既存のキー）。一覧の行を押したときも同じく欄から出る。
//!
//! # 「記録」の枠の右のボタンは、働きが変わった直後の300msだけ押せない（[BUG-210](../../../../docs/bugs/BUG-210.md)）
//!
//! このボタンは同じ場所で働きが入れ替わる——記録していない間は「記録を開始」（`Enter`）、記録中は「停止を予約」「停止」
//! （`Esc`）、止められない段階（ドレイン・撤収）では無い（`key_hints::record_buttons`）。クリックは押した瞬間に効き、
//! ループは1周に1イベントで毎周描き直すので、そのままでは「記録を開始」をダブルクリックした2回目が「停止を予約」に当たって
//! 始めたばかりの記録の停止を予約し、記録が終わった瞬間に「停止」を押すと戻ってきた「記録を開始」に当たって次の記録を始める。
//! 押した人が狙ったのは入れ替わる前のボタンである。
//!
//! そこで、ボタンの**働き**（押すキー。無ければ無いこと）が変わったら、その時刻を覚え（[`ButtonShift`]）、そこから
//! [`BUTTON_SHIFT_GRACE`]の間はこのボタンのクリックを捨てる。会話画面の入力欄の右のボタン（「送信」「中断」）が
//! 動いた直後の300msを捨てているのと同じ考え方で、**キーは捨てない**——`Enter`・`Esc`は押す場所を狙わないので、
//! ボタンが入れ替わっても押し間違いにならない。
//!
//! - **変わったことは、イベントループが1周ごとに呼ぶ`tui::tick`が見る**（描く直前。ループは毎周、workerの知らせを
//!   引き取ってから`tick`を呼ぶ）。だからクリックやキーで変わった場合も、記録が終わって勝手に戻った場合も、次のイベントを
//!   読む前に必ず見ている。会話画面は描いたボタンの矩形を前の画面と比べる（`apply_draw_feedback`）が、こちらは働きを
//!   状態から引く——ボタンはいつも1つで、同じ右下に入れ替わって出る（幅は文言で変わる）ので、矩形を比べなくても働きを
//!   比べれば足りる。時刻を引数で受ける`tick`で数えるので、試験が時刻を作って渡せる。
//! - **起動直後の最初の働きは「変わった」と数えない**（最初に見た働きを覚えるだけ。起動直後のクリックを捨てない）。
//! - 捨てたクリックは、押せる場所の外を押したのと同じく**何もしない**——押されている形も付けない（何も起きないのに
//!   押したように見える）。1回目のクリックで付いた押されている形は、ボタンの名前に付いているのでそのまま残る。
//!
//! # 押したボタンは、押した瞬間に色を変える
//!
//! 「記録」の枠の右のボタンと確認ダイアログのボタン（どちらもボタンの部品`harness_term::button`で描く）は、押した瞬間から
//! 押されている形（色の入れ替え）で描く（2026-10-03、ユーザー「クリックしたらそのクリックした瞬間に色変えられたりします？」。
//! 会話画面の「送信」「中断」・承認ダイアログの選択肢と同じ部品・同じ規則）。離していて、押してから
//! `harness_term::button::PRESSED_AT_LEAST`（150ms）が過ぎたら戻す。動作は今までどおり押した瞬間に起きる。
//!
//! - 押されている形は**ボタンの名前**（[`ButtonId`]）に付く。「記録を開始」を押すと同じ場所が「停止を予約」に変わるが、
//!   同じボタンなので押されている形のまま描く。確認ダイアログのボタンは押すとダイアログが閉じるので、閉じたこと自体が
//!   押した反応になる（閉じた後ろに見える「記録を開始」は、同じキー`Enter`を押すボタンでも名前が違うので押されている形に
//!   ならない）。
//! - **押しても捨てるクリックには付けない**——働きが変わった直後の「記録」の枠の右のボタン（上の節）。
//! - 時間で戻すのはイベントループ（`tui::run`）が1周ごとに呼ぶ`tui::tick`。ループはイベントを待つ間も100msごとに
//!   1周して描き直すので、戻すための描き直しの仕組みを新しく足していない。
//! - **キー案内の項目・タブ・一覧の行には付けない**——キー案内は案内の文字のまま描いている（ボタンの形ではない）。
//!   タブは押すと選ばれた見た目が残る部品（`harness_term::tab`）なので、それが押した反応になる。
//!
//! # 限界
//!
//! - クリックは左ボタンを押した瞬間に効く（離したときではない）。押してから外へずらして取り消すことはできない。
//!   文章の上で押してずらしたときの選択とコピーは`tui::select`が持つ（ヘルプの文章の上だけは、離したときに閉じる）。
//! - 入力欄を押しても、押した桁へカーソルは移らない（`Tab`で入ったときと同じく、カーソルはそのまま）。
//! - キーボードの`Esc`の後にクリックを挟むと、`Esc`の二度押し（終了）の続きは切れる（キーと同じ規則）。
//! - 確認ダイアログのボタンには、開いた直後の窓を置かない——開くのは利用者の操作（`a`・`y`等）だけで、狙っていない
//!   ところへ勝手に現れることが無いから（会話画面の承認ダイアログはモデルが勝手に開くので窓がある。D-106）。
//! - 「記録」の枠の右のボタンの窓は、`tui::tick`が働きの変化を見た時刻から数える。`tick`を呼ぶのはイベントループ
//!   （`tui::run`）だけで、ループそのものは試験していない（端末を要る）。

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use harness_term::pointer::Pointer;
use ratatui::layout::Rect;
use ratatui::text::Span;

use crate::tui::checkbox_tree;
use crate::tui::scroll::Wheel;
use crate::tui::state::{Action, App, EditField, RecordField, Screen};
use crate::tui::transition::PendingTab;

/// 1フレームで描いた、押せる場所と送れる枠。
pub type Targets = harness_term::pointer::Targets<Click, Wheel>;

/// クリックで起こすこと。どれもキーの処理を呼ぶ（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Click {
    /// 一番上のタブ。いまの画面なら何もしない。
    Screen(Screen),
    /// 承認待ちのタブ。いまのタブなら何もしない。
    PendingTab(PendingTab),
    /// 一覧の行を選ぶ。
    Row(ListId, usize),
    /// 行の`[x]`/`[ ]`。その行を選んで`Space`。
    Mark(ListId, usize),
    /// 行の`▾`/`▸`。その行を選んで、開いていたなら`←`、閉じていたなら`→`。`open`は描いたときの状態。
    Fold {
        list: ListId,
        row: usize,
        open: bool,
    },
    /// 入力欄（`Tab`で入るのと同じ状態にする）。
    Field(Field),
    /// キーを順に押す（キー案内の項目。案内の文字のまま描いているので、押されている形は無い）。
    Keys(Vec<KeyEvent>),
    /// ボタン（記録の枠のボタン・確認ダイアログのボタン）。`key`を押し（[`Self::Keys`]と同じ処理）、押した瞬間から
    /// そのボタンを押されている形で描く（`App::press`。モジュールdoc「押したボタンは、押した瞬間に色を変える」）。
    Button { id: ButtonId, key: KeyEvent },
    /// ヘルプを閉じる（何でもないキーを押す）。
    CloseHelp,
}

/// ボタンの名前（押されている形をどのボタンに付けるか。`harness_term::button::Press`）。**押した結果、同じ場所で文言が
/// 変わるボタンは同じ名前**にする——「記録」の枠の右のボタンは「記録を開始」を押すと「停止を予約」「停止」に変わるが、
/// 押した手が見ているのは同じボタンで、文言が変わった瞬間に押した色が消えると、押した色が一度も見えない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonId {
    /// 「記録」の枠の右のボタン（「記録を開始」⇄「停止を予約」「停止」。いつも1つ——`key_hints::record_buttons`）。
    Record,
    /// 確認ダイアログの下辺のボタン（文言で見分ける。押すとダイアログが閉じるものは、閉じたこと自体が押した反応になる）。
    Modal(&'static str),
}

/// 「記録」の枠の右のボタンの働きが変わってから、そのボタンのクリックを捨てる長さ（モジュールdoc）。
///
/// 会話画面の入力欄の右のボタンが動いた直後の窓（`harness-tui`の`app::pointer::BUTTON_SHIFT_GRACE`）と同じ300ms。
/// あちらは新しい値を立てず、承認ダイアログを開いた直後の窓（D-106の`MODAL_INPUT_GRACE`）を参照している。
/// このエディタは`harness-tui`に依存しないので、同じ長さをここに持つ（共有の部品`harness_term::button`へ移すと、
/// D-106の値の持ち主が描画の部品になるか、会話画面の側で300msの定義が2つに割れる）。
pub(crate) const BUTTON_SHIFT_GRACE: Duration = Duration::from_millis(300);

/// 「記録」の枠の右のボタンの働き（押すキー）が最後に変わった時刻（モジュールdoc「働きが変わった直後の300msだけ押せない」）。
/// 時刻は外から渡す（`harness_term::button::Press`・`harness_term::double_esc`と同じ。試験は時刻を作って渡す）。
#[derive(Debug, Default)]
pub struct ButtonShift {
    /// 最後に見た働き（ボタンが無ければ`None`）。外側の`None`は、まだ1度も見ていない（起動直後）。
    seen: Option<Option<KeyEvent>>,
    /// 働きが最後に変わった時刻。
    changed_at: Option<Instant>,
}

impl ButtonShift {
    /// いまの働きを`now`に見た。前に見た働きと違えば、その時刻を覚える。**最初に見た働きは「変わった」と数えない**。
    pub(crate) fn observe(&mut self, work: Option<KeyEvent>, now: Instant) {
        if self.seen.is_some_and(|was| was != work) {
            self.changed_at = Some(now);
        }
        self.seen = Some(work);
    }

    /// `now`に押したクリックを受けるか（働きが変わってから[`BUTTON_SHIFT_GRACE`]が過ぎているか、一度も変わっていない）。
    pub(crate) fn accepts_click(&self, now: Instant) -> bool {
        self.changed_at
            .is_none_or(|at| now.saturating_duration_since(at) >= BUTTON_SHIFT_GRACE)
    }
}

/// 押せる行を持つ一覧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListId {
    /// 承認待ち（FS/ネット）の記録セッション。
    Sessions,
    /// 承認待ち（FS/ネット）の候補の木。
    Proposals,
    /// 承認待ちの遷移タブの一覧。
    Transitions,
    /// 宣言画面の木。
    Declared,
}

/// 押せる入力欄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// 記録画面の欄（パス・コマンド・作業ディレクトリ・ドメイン）。
    Record(RecordField),
    /// 承認待ち（FS/ネット）のドメイン欄。
    Domain,
    /// 承認待ちの遷移タブの遷移先ドメインの欄。
    Destination,
}

/// 修飾キー無しのキー。
pub(crate) fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// 一覧の1項目の、押せる記号の位置（項目の1行目の左端から何桁目に、何桁）。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Hot {
    mark: Option<(u16, u16)>,
    /// 開閉の記号と、描いたときに開いていたか。
    fold: Option<(u16, u16, bool)>,
}

impl Hot {
    /// 項目の1行目`spans`のうち、`mark`番目のspanがチェック、`fold`番目のspanが開閉の記号（`bool`は開いているか）。
    /// 位置は`harness_term::row::spans_in`（ratatuiが行を描く規則）で求める。
    pub(crate) fn of(spans: &[Span], mark: Option<usize>, fold: Option<(usize, bool)>) -> Self {
        let columns = harness_term::row::spans_in(Rect::new(0, 0, u16::MAX, 1), spans);
        let at = |index: usize| columns.get(index).map(|rect| (rect.x, rect.width));
        Self {
            mark: mark.and_then(at),
            fold: fold.and_then(|(index, open)| at(index).map(|(x, width)| (x, width, open))),
        }
    }
}

/// 描かれた行を登録する。行全体＝その行を選ぶ、チェック＝`Space`、開閉＝`←`/`→`（後から登録した記号が行より上）。
/// `hot`は`items`の順（`Row::index`で引く）。
pub(crate) fn register_rows(
    targets: &mut Targets,
    list: ListId,
    rows: &[harness_term::list::Row],
    hot: &[Hot],
) {
    for row in rows {
        targets.click(row.area, Click::Row(list, row.index));
        let Some(hot) = hot.get(row.index) else {
            continue;
        };
        let cell = |x: u16, width: u16| {
            Rect::new(row.area.x.saturating_add(x), row.area.y, width, 1).intersection(row.area)
        };
        if let Some((x, width)) = hot.mark {
            targets.click(cell(x, width), Click::Mark(list, row.index));
        }
        if let Some((x, width, open)) = hot.fold {
            targets.click(
                cell(x, width),
                Click::Fold {
                    list,
                    row: row.index,
                    open,
                },
            );
        }
    }
}

impl App {
    /// マウスのイベント（左クリックとホイール）。直前に描いた画面の登録（`self.pointer`）で引く。
    /// 押せる場所・送れる枠の外では**何もしない**——外した位置で別のものが動くほうが混乱する。
    ///
    /// 左ボタンの押下・離上とボタンを押さない移動は、前に押したボタンを離したことを表すので、まず押されている形を
    /// 戻すかを見る（`harness_term::button::Press::pointer`）。`now`はイベントを受けた時刻。
    ///
    /// 文章の上（押せる場所ではない所）で押したら、文章を選び始める（`tui::select`）。押したままの移動と離上・右クリックは
    /// 選択が先に受ける。それ以外の場所を押したら、押した場所の動きを起こしてから、選んでいた文章を外す。
    pub fn on_mouse(&mut self, event: MouseEvent, now: Instant) -> Option<Action> {
        self.press.pointer(event.kind, now);
        if let Some(handled) = self.on_selection_mouse(event, now) {
            return handled;
        }
        let pressed = event.kind == MouseEventKind::Down(MouseButton::Left);
        let action = match self.pointer.resolve(&event) {
            Some(Pointer::Wheel { target, up }) => {
                self.on_wheel(target, up);
                return None;
            }
            Some(Pointer::Text(surface)) => {
                self.press_text(surface, event.column, event.row);
                return None;
            }
            Some(Pointer::Click(click)) => self.on_click(click, now),
            None => None,
        };
        if pressed {
            self.selection.clear();
        }
        action
    }

    fn on_click(&mut self, click: Click, now: Instant) -> Option<Action> {
        // 「記録」の枠の右のボタンは、働きが変わった直後（`BUTTON_SHIFT_GRACE`）なら捨てる（モジュールdoc、BUG-210）。
        // 押せる場所の外を押したのと同じく何もしない——押されている形も付けず、`Esc`の二度押しの続きも切らない。
        if matches!(
            click,
            Click::Button {
                id: ButtonId::Record,
                ..
            }
        ) && !self.record_shift.accepts_click(now)
        {
            return None;
        }
        // クリックは`Esc`ではない。`Esc`の二度押し（終了）の途中に挟まったら続きを切る
        // （`on_key`が`Esc`以外のキーで切るのと同じ規則。キーを押すクリックは`on_key`がもう一度判定する）。
        self.double_esc.reset();
        match click {
            Click::Keys(keys) => self.press_keys(&keys, now),
            // ここへ来たボタンは押して動作が起きるので、押されている形にする（捨てるクリックは上で返している）。
            Click::Button { id, key } => {
                self.press.down(id, now);
                self.press_keys(&[key], now)
            }
            Click::Screen(screen) => {
                if self.screen == screen {
                    return None;
                }
                self.on_key(key(KeyCode::F(match screen {
                    Screen::Record => 1,
                    Screen::Edit => 2,
                    Screen::Declared => 3,
                })))
            }
            Click::PendingTab(tab) => {
                if self.pending.tab.0 != tab {
                    self.select_pending_tab(tab);
                }
                None
            }
            Click::Field(field) => {
                self.focus_field(field);
                None
            }
            Click::Row(list, row) => {
                self.select_row(list, row);
                None
            }
            Click::Mark(list, row) => {
                self.select_row(list, row);
                self.on_key(key(KeyCode::Char(' ')))
            }
            Click::Fold { list, row, open } => {
                self.select_row(list, row);
                self.on_key(key(if open { KeyCode::Left } else { KeyCode::Right }))
            }
            // ヘルプは「何かキーを押すと閉じる」（`on_key`）。閉じ方を2か所に持たないよう、何でもないキーを押す。
            Click::CloseHelp => self.on_key(key(KeyCode::Null)),
        }
    }

    /// キー案内の項目・ボタンが押すキーを押す。文字キーを押すなら先に入力欄から出る（モジュールdoc）。`now`はクリックの
    /// 時刻（`Esc×2 終了`の2回の`Esc`は同じ時刻に押したことになる）。
    fn press_keys(&mut self, keys: &[KeyEvent], now: Instant) -> Option<Action> {
        if keys.iter().any(types_text) {
            self.leave_text_field();
        }
        self.press_all(keys, now)
    }

    /// キーを順に押す。途中で操作（記録の開始・終了）が返ったら、そこで止めて返す。
    fn press_all(&mut self, keys: &[KeyEvent], now: Instant) -> Option<Action> {
        for &pressed in keys {
            if let Some(action) = self.on_key_at(pressed, now) {
                return Some(action);
            }
        }
        None
    }

    /// 承認待ちの入力欄（ドメイン欄・遷移先の欄）に居るなら、`Enter`で一覧へ戻る（モジュールdoc）。
    fn leave_text_field(&mut self) {
        if self.screen != Screen::Edit {
            return;
        }
        let in_field = if self.pending.tab.0.is_transition() {
            self.pending.destination.focused
        } else {
            self.edit_focus == EditField::Domain
        };
        if in_field {
            self.on_key(key(KeyCode::Enter));
        }
    }

    /// 承認待ち（FS/ネット）の項目を`Tab`で`target`まで送る（`Tab`は項目を巡回するだけで、ほかに何もしない）。
    fn focus_edit(&mut self, target: EditField) {
        for _ in 0..3 {
            if self.edit_focus == target {
                return;
            }
            self.on_key(key(KeyCode::Tab));
        }
    }

    /// 入力欄を押した——`Tab`で入るのと同じ状態にする。
    fn focus_field(&mut self, field: Field) {
        match field {
            Field::Record(target) => {
                // 記録画面の`Tab`は欄を巡回するだけ。描いた欄はどれも巡回に入っている（ドメイン欄はパス2でだけ描く）。
                for _ in 0..4 {
                    if self.record_focus == target {
                        return;
                    }
                    self.on_key(key(KeyCode::Tab));
                }
            }
            Field::Domain => self.focus_edit(EditField::Domain),
            Field::Destination => {
                if !self.pending.destination.focused {
                    self.on_key(key(KeyCode::Tab));
                }
            }
        }
    }

    /// 一覧の`row`行目を選ぶ。`↑↓`・`PgUp/PgDn`が呼ぶのと同じ関数を、行の差で呼ぶ（モジュールdoc）。
    fn select_row(&mut self, list: ListId, row: usize) {
        self.leave_text_field();
        let delta = |current: usize| row as isize - current as isize;
        match list {
            ListId::Sessions => {
                self.focus_edit(EditField::Sessions);
                self.move_selection(delta(self.selected_session));
            }
            ListId::Proposals => {
                self.focus_edit(EditField::Proposals);
                self.move_selection(delta(self.selected_row));
            }
            ListId::Transitions => {
                let rows = self.pending.visible().len();
                let current = self.pending.row();
                checkbox_tree::move_row(self.pending.row_mut(), rows, delta(current));
            }
            ListId::Declared => {
                let rows = self.declared_tree.rows(&self.declared_expanded).len();
                let by = delta(self.declared_row);
                checkbox_tree::move_row(&mut self.declared_row, rows, by);
            }
        }
    }
}

/// 入力欄に居ると文字として入ってしまうキーか。
fn types_text(pressed: &KeyEvent) -> bool {
    matches!(pressed.code, KeyCode::Char(_)) && !pressed.modifiers.contains(KeyModifiers::CONTROL)
}
