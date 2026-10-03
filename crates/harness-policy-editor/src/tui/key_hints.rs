//! 画面の一番下のキー案内。押せるキーだけを出す（**効かない操作を案内しない**。B-32）。
//!
//! 各項目は**クリックでそのキーを押せる**（2026-10-02。`tui::pointer`）。項目の文言と押すキーは
//! [`KeyHint`]の1つに並べて持つ——文言だけを持ってキーを別の表で引くと、文言を変えたときに
//! 押すキーだけが古くなる（B-05）。キーを持たない項目（`↑↓ 選択`のように1つのキーに決まらないもの・
//! 一括の操作）は押せない（`tui::pointer`のモジュールdoc）。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Span;
use ratatui::Frame;

use crate::tui::pointer::{key, Click, Targets};
use crate::tui::state::{App, Screen};

/// キー案内の1項目。`keys`が空なら押せない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeyHint {
    pub label: String,
    /// クリックしたときに順に押すキー。
    pub keys: Vec<KeyEvent>,
}

/// 押せる項目。`label`の頭に書いたキーを`code`に渡す。
fn press(label: impl Into<String>, code: KeyCode) -> KeyHint {
    KeyHint {
        label: label.into(),
        keys: vec![key(code)],
    }
}

/// 押せない項目（1つのキーに決まらない・一括の操作）。
fn shown(label: impl Into<String>) -> KeyHint {
    KeyHint {
        label: label.into(),
        keys: Vec::new(),
    }
}

/// 画面ごとのキー案内。押せるキーだけを出す。**効かない操作を案内しない**（B-32）。
///
/// 全画面に共通の案内（[`common_keys`]）はここに含めない——幅が足りないときの扱いが
/// 違うからである（[`fit_key_hints`]）。
pub(super) fn screen_keys(app: &App) -> Vec<KeyHint> {
    let mut keys: Vec<KeyHint> = Vec::new();
    match app.screen {
        Screen::Record => {
            // 枠が出ている間だけ案内する（実行前は遡る対象が無い）。ホイールは
            // **見えていないと誰も試さない**ので、キー以外でもここへ出す（B-32）。
            if app.run.is_some() {
                keys.push(shown("ホイール 枠内をさかのぼる"));
            }
            // 記録の開始と停止はここに無い——「記録」の枠の右の枠付きのボタン（[`record_buttons`]）へ移した。
            if !app.is_running() {
                // 終わった記録の結果を見ている間も、次の操作は同じ（もう一度実行する／
                // 候補を見に行く）。**押せるものを隠さない**——結果を読んだ後に何をすれば
                // よいかが画面から消えると、そこで手が止まる。
                keys.push(press("Tab 項目移動", KeyCode::Tab));
                if app.has_finished_run() {
                    keys.push(press("F2 候補を見る", KeyCode::F(2)));
                }
                keys.push(press("Esc 編集画面へ", KeyCode::Esc));
            }
        }
        // 遷移のタブは操作が違う。**効かない操作を案内しない**（`B-32`）。
        //
        // # 並びは「押す頻度と重要度」の順である（2026-09-19、実機で見つけた）
        //
        // **この行は折り返さない。** 幅が足りないと**末尾から黙って切れる**ので、
        // 並び順がそのまま「消えてよい順」になる。実際に100桁ほどの端末で試したところ
        // `a 確定` が画面の外へ出ており、**予約したものを書き込むキーだけが見えない**
        // という形になっていた。だから状態を変える2つ（`Space`・`a`）を先頭へ置き、
        // 文言も短くしてある。切り捨てそのものは全画面に共通の性質で、ここでは直していない。
        // 却下（`x`）も予約を変えるキーなので`a`の直後に置く。まとめての却下（`X`）は頻度が
        // 低いので`f`の後ろ——**まとめて承認するキーは無い**（決定62・決定51）。
        Screen::Edit if app.pending.tab.0.is_transition() => {
            keys.push(press("Space 選ぶ/外す", KeyCode::Char(' ')));
            let reserved = app.pending.reserved_count();
            if reserved == 0 {
                keys.push(press("a 確定", KeyCode::Char('a')));
            } else {
                // 予約件数を出す（何件書かれるのかが確定の直前まで見えている必要がある）。
                keys.push(press(format!("a 確定（{reserved}件）"), KeyCode::Char('a')));
            }
            keys.push(press("x 却下/戻す", KeyCode::Char('x')));
            keys.push(press("u 引数の広さ", KeyCode::Char('u')));
            // 遷移先の欄（2026-10-01）。確定の中身を変える設定なので、`u`と同じ並びに置く。
            keys.push(press("Tab 遷移先", KeyCode::Tab));
            keys.push(press(
                format!("f 表示: {}", app.pending.filter.label()),
                KeyCode::Char('f'),
            ));
            // 一括の操作はクリックに付けない（`tui::pointer`のモジュールdoc）。
            keys.push(shown("X 表示中を却下"));
            keys.push(shown("↑↓ 選択"));
            keys.push(press("r 読み直し", KeyCode::Char('r')));
            keys.push(press("F2 タブ切替", KeyCode::F(2)));
            keys.push(press("Esc 戻る", KeyCode::Esc));
        }
        Screen::Edit => {
            keys.push(press("Esc 記録画面へ", KeyCode::Esc));
            keys.push(press("F2 タブ切替", KeyCode::F(2)));
            keys.push(press("Tab 項目移動", KeyCode::Tab));
            keys.push(shown("↑↓ 選択"));
            keys.push(shown("→← 展開/折畳"));
            keys.push(press("Space この配下をまとめて選択", KeyCode::Char(' ')));
            keys.push(press("c access変更", KeyCode::Char('c')));
            keys.push(press("d この行自身も選ぶ", KeyCode::Char('d')));
            keys.push(press("R 再帰(**)", KeyCode::Char('R')));
            keys.push(press(
                format!("f 一覧: {}", app.filter.label()),
                KeyCode::Char('f'),
            ));
            keys.push(press("t プロセスツリー", KeyCode::Char('t')));
            keys.push(press("a 承認", KeyCode::Char('a')));
        }
        Screen::Declared => {
            keys.push(press("Esc 記録画面へ", KeyCode::Esc));
            keys.push(shown("↑↓ 選択"));
            keys.push(press("Space 取り消しを予約", KeyCode::Char(' ')));
            // 一括の操作はクリックに付けない（`tui::pointer`のモジュールdoc）。
            keys.push(shown("A 全件"));
            // [D-112] 未承認の宣言があるときだけ出す（無いときに押しても何も起きない）。
            if !app.declared_approval.not_approved.is_empty() {
                keys.push(press("y このマシンで承認を予約", KeyCode::Char('y')));
            }
            // 付け替え（1行ずつ）。キーは候補画面の`c`・`R`と同じ。
            keys.push(press("c 種類を変える", KeyCode::Char('c')));
            keys.push(press("R ** の付け外し", KeyCode::Char('R')));
            keys.push(press("r 読み直し", KeyCode::Char('r')));
            // 予約件数を出す（何件が変わるのかが確定の直前まで見えている必要がある）。
            // 付け替えは取り消しが勝つ分を除いた、実際に書く件数で数える。
            let counts = [
                (app.declared_approval.reserved.len(), "承認"),
                (
                    app.declared_reassign.effective(&app.unapproved).len(),
                    "付け替え",
                ),
                (app.unapproved.len(), "取り消し"),
            ];
            let parts: Vec<String> = counts
                .iter()
                .filter(|(count, _)| *count > 0)
                .map(|(count, what)| format!("{count}件を{what}"))
                .collect();
            if parts.is_empty() {
                keys.push(press("a 確定", KeyCode::Char('a')));
            } else {
                keys.push(press(
                    format!("a 確定（{}）", parts.join("・")),
                    KeyCode::Char('a'),
                ));
            }
        }
    }
    keys
}

/// 「記録」の枠の右の枠付きのボタン1つ（[`record_buttons`]。`harness_term::button::Framed`で描く）。
/// 文言・下辺に添えるキーの綴り・押すキーを1つに並べて持つ（[`KeyHint`]と同じ理由。B-05）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordButton {
    /// 枠の中の文言（`記録を開始`）。
    pub label: &'static str,
    /// 枠の下辺に添えるキーの綴り（`Enter`）。
    pub key_label: &'static str,
    /// クリックしたときに押すキー。
    pub key: KeyEvent,
}

/// 記録画面の「記録」の枠の右隣に置く枠付きのボタン（`record_screen`が描く。2026-10-03）。
///
/// 会話画面（`harness.exe`）の入力欄の右隣に枠で囲んだ「送信」「中断」を置いたのと同じ形・同じ部品
/// （`harness_term::button::place_framed`）——ユーザーが会話画面を実機で見て図を描き、「ボタンと分かるように枠で
/// 囲んだものを右に」と希望した。このエディタの記録のコマンド欄も、同じ日に枠の下辺へ載せたボタンだった。
///
/// - 実行前は「記録を開始」（下辺に`Enter`）。コマンドが空でも押せる——押すと開始できない理由が出る
///   （`App::start_recording`。押しても無反応にしない、B-23(c)）。
/// - 実行中は、止められるときだけ「停止」／「停止を予約」（下辺に`Esc`。効かない操作を案内しない。B-32）。
/// - 同じ場所で働きが入れ替わるので、入れ替わった直後の300msのクリックは捨てる（ここが返すキーを`tui::tick`が毎周見る。
///   `tui::pointer`のモジュールdoc、[BUG-210](../../../../docs/bugs/BUG-210.md)）。
///
/// キー案内の行（[`screen_keys`]）には出さない——同じ操作を2か所に並べない（会話画面の見出しから送信・中断を外したのと同じ）。
pub(super) fn record_buttons(app: &App) -> Vec<RecordButton> {
    let button = |label, key_label, code| RecordButton {
        label,
        key_label,
        key: key(code),
    };
    let Some(run) = app.run.as_ref().filter(|_| app.is_running()) else {
        return vec![button("記録を開始", "Enter", KeyCode::Enter)];
    };
    if run.phase.stop_takes_effect_now() {
        vec![button("停止", "Esc", KeyCode::Esc)]
    } else if run.phase.stop_can_be_queued() {
        vec![button("停止を予約", "Esc", KeyCode::Esc)]
    } else {
        Vec::new()
    }
}

/// 全画面に共通のキー案内。画面ごとの項目の後ろに並べる。
///
/// **Esc×2は案内しないと見つけられない。** 単押しは画面遷移なので、二度押しが終了である
/// ことは画面から推測できない。クリックでは`Esc`を2回続けて押す（キーで二度押ししたのと同じ。
/// 記録中は`Esc`が停止なので、キーと同じく終了しない）。
pub(super) fn common_keys() -> [KeyHint; 3] {
    [
        press("F4 ヘルプ", KeyCode::F(4)),
        KeyHint {
            label: "Esc×2 終了".to_string(),
            keys: vec![key(KeyCode::Esc), key(KeyCode::Esc)],
        },
        KeyHint {
            label: "Ctrl+C 終了".to_string(),
            keys: vec![KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)],
        },
    ]
}

/// キー案内の項目の区切り。
pub(super) const KEY_SEPARATOR: &str = "  |  ";

/// キー案内の行を描き、押せる項目をそのキーを押す場所として登録する（`tui::pointer`）。
pub(super) fn draw(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) {
    let style = Style::default().fg(Color::DarkGray);
    let hints = fit_key_hints(&screen_keys(app), usize::from(area.width));
    let mut spans = Vec::with_capacity(hints.len() * 2);
    let mut at = Vec::with_capacity(hints.len());
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(KEY_SEPARATOR, style));
        }
        at.push(spans.len());
        spans.push(Span::styled(hint.label.clone(), style));
    }
    let drawn = harness_term::row::draw(frame, area, &spans);
    for (hint, index) in hints.iter().zip(at) {
        if !hint.keys.is_empty() {
            targets.click(drawn[index], Click::Keys(hint.keys.clone()));
        }
    }
}

/// キー案内の1行を`width`桁に収め、描く項目を順に返す（区切りを入れて並べた幅が`width`以下）。
///
/// # 共通の案内（ヘルプ・終了）は削らない（2026-10-01、実機で見つけた）
///
/// この行は折り返さず、幅が足りないと**末尾から黙って切れる**。以前は共通の案内を
/// 画面ごとの項目の後ろへそのまま足していたので、**画面ごとの項目が多いほど、ヘルプと
/// 終了の案内から先に消えた**——承認待ちの遷移タブは約200桁を要し、全画面に近い幅でも
/// `… | Esc 戻る | F4`で切れて`Esc×2 終了`が見えなかった。
///
/// だから収まらないときは、**画面ごとの項目を後ろから丸ごと落とし**、落とした件数を
/// `… 他N件`で出してから共通の案内を置く。
///
/// - **後ろから落とす**のは、画面ごとの並びが「押す頻度と重要度」の順だからである
///   （遷移タブの並びのコメント。並び順がそのまま「消えてよい順」になっている）。
/// - **項目の途中で切らない。** `F4`だけが残るような切れ方は、別のキーに読める。
/// - **件数を出す**のは、省略したことを黙らないためである（B-09）。落とした項目はヘルプ（`F4`）に載っている。
///   だから`… 他N件`を押すとヘルプが開く（`F4`を押したのと同じ）。
///
/// 全部収まるときは以前と1文字も変わらない。共通の案内そのものより狭い端末では、
/// 共通の案内も末尾から切れる（描画が落ちないことだけを保つ）。
fn fit_key_hints(screen: &[KeyHint], width: usize) -> Vec<KeyHint> {
    use unicode_width::UnicodeWidthStr;

    let line = |kept: &[KeyHint], omitted: Option<KeyHint>| -> Vec<KeyHint> {
        kept.iter()
            .cloned()
            .chain(omitted)
            .chain(common_keys())
            .collect()
    };
    let width_of = |hints: &[KeyHint]| -> usize {
        hints
            .iter()
            .map(|hint| hint.label.as_str())
            .collect::<Vec<_>>()
            .join(KEY_SEPARATOR)
            .width()
    };
    let full = line(screen, None);
    if width_of(&full) <= width {
        return full;
    }
    // 画面ごとの項目を後ろから1件ずつ落とし、収まった時点で止める。
    for kept in (0..screen.len()).rev() {
        let omitted = press(format!("… 他{}件", screen.len() - kept), KeyCode::F(4));
        let fitted = line(&screen[..kept], Some(omitted));
        if width_of(&fitted) <= width {
            return fitted;
        }
    }
    // 画面ごとの項目を全部落としても収まらない幅。共通の案内だけを出す。
    line(&[], None)
}
