//! 記録・編集・宣言の3画面のTUI（`plans/POLICY-EDITOR-TOMOYO-DIG.md`）。
//!
//! ```text
//!   ┌ F1 記録 ─────────────────┐        ┌ F2 承認待ち ──────────────┐
//!   │ パス1: 隔離なしでFSを記録   │ ──記録─▶│ 候補を選ぶ → policy.jsonへ │
//!   │ パス2: Tier2aでドメイン  │◀─承認── │ 承認（差分を見てから書く） │
//!   └──────────────────────────┘        │ タブ: FS/ネット │ 遷移・観測 │
//!                                       │       │ 遷移・拒否          │
//!                                       └─────────────┬─────────────┘
//!                                                     │ 宣言済みは[x]で重なる
//!                                       ┌ F3 宣言 ────┴─────────────┐
//!                                       │ policy.jsonの宣言を取り消す │
//!                                       │ （記録が無くても開ける）    │
//!                                       └───────────────────────────┘
//! ```
//!
//! 画面は`F1`/`F2`/`F3`と`Ctrl+N`（巡回）でいつでも行き来できる（決定13: 記録し直す・過去の記録を
//! 別の一般化度合いで見直す、をいつでも行える）。矢印は**次にやることの提案**であって
//! 一方通行ではない。**ヘルプは`F4`**で、`F2`をもう一度押すと承認待ちのタブが切り替わる
//! （決定62。`Tab`は承認待ち画面が項目移動に使っているので奪えない——詳細は`state::App::on_key`）。
//!
//! **マウスでも操作できる**（2026-10-02）——タブ・一覧の行と`[x]`・`▾`/`▸`・入力欄・キー案内の項目・確認ダイアログの
//! ボタンを押すと、対応するキーを押したのと同じになり、ホイールはポインタの下の枠を送る。当たり判定は、描いた矩形を
//! 描くときにそのまま登録したもの（[`pointer`]。土台は会話TUIと共有する`harness_term::pointer`）。
//!
//! # 承認待ちは3つのタブを持つ（決定62、段階⑦）
//!
//! ファイル・通信の候補と、**遷移（どのプログラムが何を起こしてよいか）**の候補は
//! 出どころが違うが、**ユーザーがやることは同じ**である——選んで、許す。だから画面を
//! 分けずにタブにする。遷移の2タブは[`transition`]（状態）と[`transition_screen`]（描画）が持つ。
//!
//! # 承認と取り消しはどちらもチェックボックスで表す
//!
//! 編集画面の候補行には、**もう`policy.json`が宣言している値**が`[x]`で重なる。同じ場所へ
//! 二重に承認しないためと、間違って承認したものをその場で外せるようにするためである。
//! 一方、**記録に出てこない宣言**（前に承認したが今回のコマンドが触らなかったもの）は
//! 宣言画面（`F3`）が受け持つ——そちらは`policy.json`だけを入力にするので、記録が1件も無くても
//! 開ける。「ログを取らずに消す」経路がこれである。
//!
//! # `Esc`を1秒以内に2回でプログラムを終了する
//!
//! `Esc`の単押しは記録画面へ戻る（画面遷移）で、`Ctrl+N`も遷移に使う。終了の口が無くなるので、
//! `Esc`の二度押しを終了に割り当てている（判定は[`state::is_double_esc`]、時間は
//! [`state::ESC_QUIT_WINDOW`]）。
//!
//! # テスト（宣言どおりの強制での検証）は、別の画面ではなくパス2の「強制」で行う
//!
//! 「`policy.json`の宣言だけを許可してTier2aで走らせ、想定外の拒否を見る」実行は、
//! 記録画面の「パス」欄で選ぶパス2の強制モードである（決定64、[`crate::record_net::NetMode`]）。
//! 別のタブを足さなかったのは、走らせ方（Tier2a・ACE・WFP）がパス2とまったく同じで、
//! 違うのが中継プロキシと名前解決へ渡す許可リストだけだからである。
//! **強制で効くのはこの試験実行の中だけ**で、`harness.exe`本体はまだ`policy.json`の
//! `net.allow_domains`で通信を許さない——ヘルプにもそう書く。
//!
//! # なぜ同期のイベントループなのか
//!
//! 駆動する対象（[`crate::record`]・[`crate::record_net`]）が同期ブロッキング関数なので、
//! asyncにしても`spawn_blocking`相当のスレッドへ逃がす形は変わらない（B-31）。
//! `crossterm::event::poll`でティックを作り、workerからのメッセージは毎周回で引き取る。

pub mod state;

mod checkbox_tree;
mod declared;
mod declared_screen;
mod edit;
mod edit_screen;
/// 画面の一番下のキー案内（項目はクリックでそのキーを押せる）。
mod key_hints;
/// マウスのクリックとホイール。押せる場所と送れる枠は描くときに登録する（2026-10-02）。
mod pointer;
mod proposal_tree;
pub mod record_screen;
/// 送れる枠（説明欄・ヘルプ・確認ダイアログ・記録画面の3枠）の位置と、ホイールで送ること（2026-10-02）。
mod scroll;
mod text_input;
/// [段階⑦] 承認待ち画面（`F2`）の遷移2タブの状態遷移。
pub mod transition;
/// [段階⑦] 遷移タブで却下した候補の印（`dismissed.json`）。**表示だけに効く**
/// （強制・`policy.json`・ACL・モデルへの注記のどれにも効かない）。読み書きするのはこの画面だけ。
pub mod transition_dismissed;
/// [段階⑦] 遷移タブの遷移先ドメインの欄（2026-10-01。それまでは遷移先を呼び出し元に固定していた）。
mod transition_destination;
mod transition_screen;
mod worker;
/// 折り返す枠の行数を数え、入り切らなかった分を送って読ませる部品（BUG-192）。
mod wrap;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders};
use ratatui::{Frame, Terminal};

use pointer::{Click, Targets};
use scroll::Wheel;
use state::{Action, App, Screen};
use transition::PendingTab;

/// **1フレーム描いて初めて分かること。** 呼び出し側が[`App::apply_draw_feedback`]で状態へ書き戻す。
///
/// 描画時にしか決まらない値が3種類ある。
///
/// 1. さかのぼり・送りの上限（記録画面の3枠・確認ダイアログ・説明欄とヘルプ。折り返し後の行数は枠の幅に
///    依存する。`harness_term::scrollback`・`tui::scroll`のdoc）
/// 2. 一覧の表示開始位置（ratatuiが「選択を見せる」ために動かした結果）
/// 3. 押せる場所とホイールで送れる枠（描いた矩形そのもの。`tui::pointer`）
///
/// どれも**書き戻さないと壊れる**——1を怠ると端で空回りし（BUG-076）、
/// 2を怠るとカーソルが窓の中を動かず一覧の方が滑り、3を怠るとマウスが前の画面の場所で当たる。
#[derive(Debug, Default, Clone)]
pub struct DrawFeedback {
    pub scroll: record_screen::ScrollLimits,
    /// 確認ダイアログを送れる上限（本文の最後の行が枠の一番下に来る位置。[BUG-196](../../../../docs/bugs/BUG-196.md)）。
    /// `None`＝確認ダイアログを描いていない（触らない）。
    pub modal_scroll_max: Option<u16>,
    /// 説明欄とヘルプを送れる上限。**描かなかった欄は0**（既定値）で、書き戻すとその欄は先頭へ戻る
    /// （`tui::scroll`のモジュールdoc）。
    pub panels: scroll::PanelLimits,
    /// `None`＝この画面はその一覧を描いていない（触らない）。
    pub session_list_offset: Option<usize>,
    pub candidate_list_offset: Option<usize>,
    pub declared_list_offset: Option<usize>,
    /// この描画で描いた、押せる場所と送れる枠（重なりは描いた順。後が上）。
    pub targets: Targets,
}

/// 描画とworkerの取り込みの間隔。キー入力はこの待ちの中で拾う。
const TICK: Duration = Duration::from_millis(100);

/// TUIを起動する。呼び出し側は標準入出力が端末であることを確認しておくこと
/// （パイプ・リダイレクトで端末制御を始めない）。
/// `require_sandbox`はCLIのルート引数から解決した値（[BUG-127](../../../../docs/bugs/BUG-127.md)）。
/// **TUIはサブコマンド無しの既定経路**なので、`approve`サブコマンドにしか宣言の口が無いと
/// 主経路だけがゲートを素通りする。
pub fn run(
    workspace_root: PathBuf,
    require_sandbox: harness_core::RequireSandbox,
) -> io::Result<()> {
    // パス2が開けた穴（workspace外へのACE）は**TUIを閉じるまで**保つ。同じSIDのまま2回目を
    // 走らせれば`preflight`の`already_sufficient`が効き、付与もUACも丸ごとスキップされる。
    // 落ちた場合は次回起動時の`gc_dead_sessions`が回収する（`SessionGrants`のdoc）。
    //
    // # なぜ`_guard`・`stderr`より先に宣言するのか（撤収を見えるようにするため）
    //
    // Rustは宣言の逆順にdropするので、**ここで宣言したものは最後にdropする**。
    // 以前はこれを`_guard`（端末復帰）と`stderr`（`StderrCapture`）より後に宣言していたため、
    // 撤収の出力が (1) `StderrCapture`にまだ預けられていてログファイルへ吸われ、
    // (2) オルタネートスクリーンのまま（かつイベントループは既に抜けていてフレームも描かれない）
    // という二重の理由で**一度もユーザーに見えていなかった**。数十秒かかる操作が無言で走る
    // ことになり、ユーザーからは「撤収の進捗が見えない」として報告された。
    //
    // `app`（`wfp`）より後にdropする関係は**保たれている**——それが要るのは、netfilterdの
    // `Teardown`がAppContainerプロファイルの削除より先に走らなければならないから（フィルタが
    // そのプロファイルのpackage SIDを条件にしている）。ここで変えたのは`_guard`/`stderr`との
    // 相対順だけである。
    let _grants = crate::record_net::SessionGrants::hold();
    // ライブラリが`eprintln!`で直接端末へ書くと、こちらのフレームの上に重なって表示が壊れる
    // （`verify_elevation_target`のD-44警告が実際にそうなる）。TUIの間だけstderrを預かる
    // （部品は会話TUIと共有する`harness_term::stderr_capture`）。
    //
    // **`_guard`より先に作る**（＝`_guard`より後にdropする）。`Drop`は読み残しを本物のstderrへ
    // 書き戻すので、端末を返す前に戻すと書き戻しがオルタネートスクリーンの上に出て消える
    // （`app`のdropで走るWFPの撤収の警告がそこに当たる）。`_grants`より後なのは上の理由のまま。
    let mut stderr = harness_term::stderr_capture::StderrCapture::start(
        &crate::session_dir::sandbox_root(&workspace_root),
        "policy-editor-tui-stderr",
    );
    // raw mode／オルタネートスクリーン／panic hookの復帰は`harness-term`が持つ（会話TUIと共有）。
    let _guard = harness_term::TerminalGuard::enter()?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // **入った直後に必ず消す。** オルタネートスクリーンは端末が保持しているので、直前に別の
    // TUI（`harness.exe`）が同じ端末で使っていれば、その内容が残ったまま入ることになる。
    // ratatuiは自分の前フレーム（起動時は空白）との差分しか書かないため、こちらが触らない
    // セルには他人の描画が残り続ける。
    term.clear()?;

    // **`_grants`より後**に作る。WFPの出口強制daemon（D-56）も同じくTUIを閉じるまで生かすが、
    // その`Teardown`はAppContainerプロファイルの削除（`SessionGrants`のDrop）より**先**に
    // 走らなければならない——フィルタはそのプロファイルのpackage SIDを条件にしているため。
    // Rustは宣言の逆順にdropするので、この順序がそのまま撤収順になる（`App`が`wfp`を持つ）。
    let mut app = App::new(workspace_root, require_sandbox);
    // 預かれなかったことは黙らない（ライブラリの警告で画面が崩れることがある、と1度だけ言う）。
    if let Some(reason) = stderr.start_error() {
        app.notice(harness_term::stderr_capture::start_failure_notice(reason));
    }

    // **昇格は起動直後に済ませる**（起動時前倒し）。遅延させると、UACが「準備が終わった
    // あと」＝無音が続いた後に出て見逃される——実測で1度そうなり、記録が丸ごと失敗した
    // （`App::prewarm_netfilterd`のdoc）。
    //
    // **プロンプトが出る理由を先に1フレーム描いてから**呼ぶ。UACのダイアログは別ウィンドウ
    // なので、何も出ていない画面の上に突然現れると「何に対する承認なのか」が分からない。
    app.status =
        "起動時の昇格: これからUACが1回出ます（承認すると、このセッション中はもう出ません）"
            .to_string();
    // 戻り値はクロージャの外へ捕まえる（`Terminal::draw`は`()`しか返せない）。
    // 会話TUI（`harness-tui`の`lib.rs`）と同じ形。
    let mut feedback = DrawFeedback::default();
    term.draw(|frame| feedback = draw(frame, &app))?;
    app.apply_draw_feedback(std::mem::take(&mut feedback));
    app.prewarm_netfilterd();

    loop {
        app.drain_worker();
        for line in stderr.poll() {
            app.note_external(line);
        }
        if app.should_exit() {
            break;
        }
        // **描画で判明した上限を状態へ戻す。** これを怠ると、先頭まで遡った後も
        // 回した分だけ内部の値が伸び続け、下へ戻すときに同じ回数だけ空回りする（BUG-076）。
        term.draw(|frame| feedback = draw(frame, &app))?;
        app.apply_draw_feedback(std::mem::take(&mut feedback));

        // **イベントは1周に1つだけ読み、読んだら必ず描き直す。** マウスの当たり判定は直前に描いた画面の
        // 登録で引く（`tui::pointer`）ので、2つ目のイベントを描かずに処理すると、1つ目で変わった画面ではなく
        // その前の画面の場所で当たる。リサイズも同じく、次の周回で描き直してから次のイベントを読む。
        if !event::poll(TICK)? {
            continue;
        }
        match handle_event(&mut app, event::read()?) {
            Some(Action::Quit) => break,
            Some(Action::StartPass1(request)) => {
                app.attach_handle(worker::spawn_pass1(*request));
            }
            Some(Action::StartPass2(request)) => {
                app.attach_handle(worker::spawn_pass2(*request));
            }
            None => {}
        }
    }

    // **撤収を画面の中でやる。** `SessionGrants`のDrop任せにすると、走るのはこのループを
    // 抜けた後＝もうフレームを描けない場所なので、進捗は素のstderrへ流すしかなくなる
    // （実測686件で686行の滝になった）。付与と同じゲージで見せるために、ここで明示的に
    // 撤収する（`docs/CODE-STRUCTURE-RULES.md`§5.1）。Dropは保険として残り、
    // ここを通っていれば対象0件で何もしない。
    app.begin_teardown();
    term.draw(|frame| feedback = draw(frame, &app))?;
    let mut last_draw = std::time::Instant::now();
    let revoked = _grants.release(&mut |done, total, path| {
        app.on_teardown_progress(done, total, path);
        // **毎件描き直さない。** 686件を毎回全画面描画すると撤収自体より描画が重くなる。
        // 100ms（`TICK`と同じ間隔）ごとに1回で、人が見るには十分速い。
        if last_draw.elapsed() >= TICK {
            let _ = term.draw(|frame| {
                feedback = draw(frame, &app);
            });
            last_draw = std::time::Instant::now();
        }
    });
    if revoked > 0 {
        // 最後の1フレームは必ず描く（`N/N`で終わったことが見えないと、途中で止まったように見える）。
        app.finish_teardown(revoked);
        term.draw(|frame| feedback = draw(frame, &app))?;
    }
    Ok(())
}

/// イベント1つを状態へ渡す。**イベントループ（[`run`]）と試験が同じこれを通る**（製品の入口）。
///
/// キーは`App::on_key`、マウスは`App::on_mouse`（クリックとホイール。当たり判定は直前に描いた画面の登録）。
/// クリックで起きる操作（記録の開始・終了）もキーと同じ[`Action`]で返る。リサイズ・貼り付けは何もしない
/// （リサイズは次の描画で反映される）。
pub(crate) fn handle_event(app: &mut App, event: Event) -> Option<Action> {
    match event {
        Event::Key(key) => app.on_key(key),
        Event::Mouse(mouse) => app.on_mouse(mouse),
        _ => None,
    }
}

/// 画面全体の縦割り（タブ1行・本体・知らせ・キー案内1行）。
struct ScreenRows {
    tabs: Rect,
    body: Rect,
    status: Rect,
    keys: Rect,
}

/// 画面全体を[`ScreenRows`]に割る（[`draw`]）。マウスの当たり判定は、この割り付けで描いたものを
/// そのまま登録する（`tui::pointer`。[BUG-194](../../../../docs/bugs/BUG-194.md)）。
///
/// BUG-194の前は、当たり判定が**端末全体を本体として**記録画面の割り付けを計算していた。反応する枠は
/// 見えている枠より1行上にずれ、下は知らせの行とキー案内の行まで伸びていた。知らせの行は折り返して
/// 複数行になる（BUG-192）ので、別々に持つとずれ方も毎回変わる。
/// `area`は端末全体。知らせの高さは中身と幅で決まるので`app`も受ける。
fn screen_rows(area: Rect, app: &App) -> ScreenRows {
    let status = status_text(app);
    let chunks = Layout::vertical([
        Constraint::Length(1),                            // タブ
        Constraint::Min(3),                               // 本体
        Constraint::Length(status_height(&status, area)), // 知らせ（折り返す）
        Constraint::Length(1),                            // キーの案内
    ])
    .split(area);
    ScreenRows {
        tabs: chunks[0],
        body: chunks[1],
        status: chunks[2],
        keys: chunks[3],
    }
}

fn draw(frame: &mut Frame, app: &App) -> DrawFeedback {
    let area = frame.area();
    let rows = screen_rows(area, app);

    // 送れる枠（記録画面の3枠・説明欄）の上限は**描画してみないと分からない**
    // （折り返し後の行数は枠の幅に依存する）ので、各画面から受け取って呼び出し側へ返す。
    // 押せる場所と送れる枠も、各画面が描いた矩形で登録して返す（`tui::pointer`）。重なりは描いた順
    // （後が上）なので、画面の上に重ねるヘルプと確認ダイアログは最後に描いて登録する。
    let mut feedback = match app.screen {
        Screen::Record => record_screen::draw(frame, rows.body, app),
        // 承認待ち画面は3つのタブを持つ（決定62）。タブの行を本体の一番上に置き、遷移の2タブは別の描き手。
        Screen::Edit => {
            let [tabs, body] =
                Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(rows.body);
            let mut feedback = if app.pending.tab.0.is_transition() {
                transition_screen::draw(frame, body, app)
            } else {
                edit_screen::draw(frame, body, app)
            };
            draw_pending_tabs(frame, tabs, app, &mut feedback.targets);
            feedback
        }
        Screen::Declared => declared_screen::draw(frame, rows.body, app),
    };
    draw_tabs(frame, rows.tabs, app, &mut feedback.targets);
    draw_status(frame, rows.status, status_text(app));
    key_hints::draw(frame, rows.keys, app, &mut feedback.targets);

    if app.help {
        let top = app.panels.top(scroll::Panel::Help);
        let max = draw_help(frame, area, top, &mut feedback.targets);
        feedback.panels.set(scroll::Panel::Help, max);
    }
    if let Some(modal) = app.modal.as_ref() {
        // 送りの上限も描いて初めて分かる（折り返し後の行数）。記録画面の枠と同じく状態へ返す。
        feedback.modal_scroll_max = Some(draw_modal(
            frame,
            area,
            modal,
            app.modal_scroll,
            &mut feedback.targets,
        ));
    }
    feedback
}

/// タブの見た目（一番上の画面のタブと、承認待ちのタブで同じ）。
fn tab_style(active: bool) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

/// 一番上の行（画面のタブ）。タブはクリックでその画面へ移る場所として登録する（`F1`〜`F3`を押したのと同じ）。
fn draw_tabs(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) {
    let screens = [
        (Screen::Record, " F1 記録 "),
        (Screen::Edit, " F2 承認待ち "),
        (Screen::Declared, " F3 宣言 "),
    ];
    let mut spans = Vec::new();
    let mut at = Vec::new();
    for (i, (screen, label)) in screens.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        at.push(spans.len());
        spans.push(Span::styled(*label, tab_style(app.screen == *screen)));
    }
    spans.push(Span::styled(
        "  Ctrl+N で切替",
        Style::default().fg(Color::DarkGray),
    ));
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        format!("workspace: {}", app.workspace_root.display()),
        Style::default().fg(Color::DarkGray),
    ));
    let drawn = harness_term::row::draw(frame, area, &spans);
    for ((screen, _), index) in screens.iter().zip(at) {
        targets.click(drawn[index], Click::Screen(*screen));
    }
}

/// 承認待ち（`F2`）のタブの行（2026-10-02）。並びは`F2`で巡回する順（[`PendingTab`]の`next`）。
///
/// それまでタブは画面に出ておらず、どのタブに居るかは遷移タブの一覧の見出しにしか無かった
/// （FS/ネットのタブでは何も出ていなかった）。クリックで切り替えるには押す場所が要るので、決定62の図と
/// 同じく承認待ちの本体の一番上に1行で並べる。押すと`F2`の巡回と同じ処理でそのタブへ移る。
fn draw_pending_tabs(frame: &mut Frame, area: Rect, app: &App, targets: &mut Targets) {
    // タブの一覧を別に持たない（`F2`の巡回の順そのものを辿る。片方だけ足すと並びがずれる）。
    let mut tabs = vec![PendingTab::FsNet];
    loop {
        let next = tabs[tabs.len() - 1].next();
        if next == PendingTab::FsNet {
            break;
        }
        tabs.push(next);
    }
    let mut spans = Vec::new();
    let mut at = Vec::new();
    for (i, tab) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        at.push(spans.len());
        spans.push(Span::styled(
            format!(" {} ", tab.label()),
            tab_style(app.pending.tab.0 == *tab),
        ));
    }
    spans.push(Span::styled(
        "  F2 で切替",
        Style::default().fg(Color::DarkGray),
    ));
    let drawn = harness_term::row::draw(frame, area, &spans);
    for (tab, index) in tabs.iter().zip(at) {
        targets.click(drawn[index], Click::PendingTab(*tab));
    }
}

/// 知らせの行（キー案内の1行上）に出す文。
fn status_text(app: &App) -> Text<'static> {
    Text::styled(app.status.clone(), Style::default().fg(Color::Yellow))
}

/// 知らせの行の高さ。**折り返して全文を出す**（[BUG-192](../../../../docs/bugs/BUG-192.md)）。
///
/// 以前は1行固定で折り返さず、右端で黙って切れていた。知らせは文の後ろに注意を置くことが多く
/// （付け替えの「…にします。権限が広がります。」）、切れると**いちばん読ませたい部分から消える**。
/// 1行に収まる知らせは今までどおり1行で、本文の割り付けは変わらない。
///
/// 上限は、タブとキー案内に1行ずつ、本文に最低3行（`draw`の`Min(3)`）を残した高さ。
/// それより低い端末では切れる（そこまで低いと本文も読めない）。
fn status_height(status: &Text, area: Rect) -> u16 {
    let ceiling = area.height.saturating_sub(5).max(1);
    u16::try_from(wrap::rows(status.clone(), area.width))
        .unwrap_or(u16::MAX)
        .clamp(1, ceiling)
}

fn draw_status(frame: &mut Frame, area: Rect, status: Text<'static>) {
    // 数える幅（`status_height`の`wrap::rows`）と同じ幅で折り返す（BUG-200）。
    harness_term::wrap::Wrapped::new(status).render(frame, area);
}

/// ヘルプの本文（`F4`）。試験が末尾の行まで読めるかを見るので、関数の外に置く。
const HELP_TEXT: &str = "\
harness-policy-editor — LLMを介さずに「このコマンドに何を許すか」を決める道具

記録は2パスで行います（FSのpermissiveさとネットワーク強制は同一トークンでは両立しない
ため、同時にではなく順番に使います）:
  パス1  隔離なし（Tier0）で触ったファイルを全部記録する（UAC 1回）
  中間   候補を承認して .harness/policy.json へ書く（このマシンには何も残らない）
  パス2  Tier2a（AppContainer＋WFP＋Proxy）で接続したドメインを記録する（UAC 最大2回）
         **ACEが実際に付くのはここだけ**です
         記録画面の「パス」欄の ←/→ で、パス2の通信の扱いを2つから選べます:
           記録  通信先を全部許して、使った宛先を集める
           強制  policy.json の net.allow_domains だけを許し、ほかは断る
                 （宣言の外で断られた宛先が候補に出る＝宣言の過不足を確かめる）

画面の行き来（3通り。使える方をどうぞ）
  Esc          記録画面へ戻る（記録中は「停止」が優先されます）
  **Esc を1秒以内に2回でこのプログラムを終了します**（記録中なら撤収を待ちます）
  Ctrl+N       記録 → 承認待ち → 宣言 → 記録 と巡回
  F1 / F2 / F3 記録 / 承認待ち / 宣言 を直接指定（F4 はこのヘルプ）
  F2 をもう一度押すと、承認待ちの**タブ**が切り替わります
               （FS/ネット → 遷移・観測から → 遷移・拒否から）
  **VS Codeの統合ターミナルではF1がコマンドパレットに奪われて届きません。**
  その場合は Esc か Ctrl+N を使ってください。
  記録と承認は独立しています。記録し終えてから承認へ進む一方通行ではありません。

承認待ちの「遷移」タブ — どのプログラムが何を起こしてよいか
  ファイルやネットワークの許可とは**別のポリシー**です。こちらが決めるのは
  「そのプログラムを起こしてよいか」で、**確定しても実マシンのACLはいま1ビットも変わりません**。
  ただし別ドメインへの遷移を書くと、harness.exe は遷移を強制する起動で、そのドメインの
  承認済みのファイル宣言に許可を付けます（遷移先になったドメインだけが対象のため）。
  出どころが2つあります——「観測から」はパス1で実際に起きたプロセス、
  「拒否から」は強制中に断られた生成です。どちらも操作は同じです。
  Space  選ぶ／外す（未宣言なら許可を予約、宣言済みなら取り消しを予約）
  u      引数の広さを切り替える（既定は「任意の引数」。観測された引数だけに絞れます）
         **コマンドラインが切り詰められている疑いがある観測は絞れません**
         ——切れた値で宣言すると、二度と一致しない辺になります。
  Tab    遷移先ドメインの欄へ入る（Enter か Tab で一覧へ戻る）。確定すると、許す遷移は
         すべてこのドメインへ向きます。既定は呼び出し元と同じ workspace-shell です。
         別の名前にすると、起こした子はそのドメインの権限で動きます（policy.json に無い
         名前なら、宣言の無いドメインとして作ります）。欄の横に harness.exe がそのドメインを
         用意する見込みが出ます——通信を宣言している・このマシンで未承認の宣言がある
         ドメインは用意されず、書けても断られ続けます（確定の前にも ⚠ で出ます）。
         遷移先が呼び出し元より広い権限に届く遷移は書けません（作業ディレクトリの固定が
         要り、このエディタはそれを宣言しないため）。名前は英数字と「-」だけです。
  x      却下する／却下を取り消す（「許可しない」と決めた印。a で確定すると
         .harness/transitions/dismissed.json に残り、次からは保留中に出ません）
  X      表示中の保留中をまとめて却下（まとめて承認するキーはありません）
         却下は表示だけの印です。policy.json も ACL も変わらず、強制中の拒否も
         止まりません。f で「却下済み」を開けば、Space で許可・x で保留中へ戻せます。
  f      表示（保留中 → 却下済み → 全部）   r 読み直し   a 確定
  [x]=確定するとこのプログラムを起こせる  [ ]=起こせない  [-]=この行からは操作できない

宣言画面（F3）— いま何を許可し続けているか
  policy.json に書かれている宣言そのものを並べます。**記録が1件も無くても開けます**
  ——「間違って承認したのですぐ消したい」「検証のため全部消したい」は記録とは無関係の操作です。
  Space  取り消しを予約（ドメインの行なら配下をまとめて）
  A      全ドメインの全宣言を予約（**一括承認はありませんが一括取り消しはあります**——
         禁じているのは読まずに権限を「与える」ことで、減らす向きは安全側だからです）
  y      このマシンで未承認の宣言を、承認する予約に入れる（配下をまとめて。全件を一度に選ぶ
         キーはありません）。リポジトリに同梱されていた・手で書いた・承認台帳ができる前に
         承認した宣言には、このマシンで承認するまで許可が付きません（行に印が出ます）
  c      宣言の種類を変える（read→read_write→read_exec の巡回。1行ずつ）
  R      宣言の ** を付け外し（付ける＝配下すべて／外す＝そのパスだけ）
         承認済みなら承認済みのまま、未承認なら未承認のまま付け替わります
         承認と同じ検査を通します（広すぎる値などにはできません）
         ** を外しても配下の継承ACEは残ることがあります（確定の画面に出ます）
  a      確定（差分を見てから y。承認・付け替え・取り消しを1回で書きます）
  [x]=宣言されている（このまま残る）  [ ]=取り消しを予約した
  **取り消してもACLはその場では変わりません。** 付与済みのACEは、次にパス2を開始したとき、
  または harness.exe を起動したときに撤収されます（そのワークスペースが使用中のときは
  見送ります）。このマシンでの承認は、取り消した時点で消えます。

候補一覧（編集画面）— パスの木として出します
  →     開く（開いていれば子へ降りる）
  ←     閉じる（閉じていれば親へ戻る）
  Space そのパスの配下をまとめて選択／解除（葉ならその1件）
        [x]=配下すべて選択  [~]=一部だけ選択  [ ]=未選択  [-]=承認できるものが無い
        **候補は観測された値そのままで、親ディレクトリへ畳みません。** 3件見えていれば
        承認されるのも3件です（見えている行数と実際に開く範囲が一致します）。
  d     その行**自身**を選ぶ／外す
        祖先チェーンのオープンで、ディレクトリ自身が拒否として観測されることがあります。
        その候補は値がディレクトリですが、**開くのはそのフォルダ自身だけ**です（非継承ACE）。
        配下のファイルは別のオブジェクトなので、これでは読めません——配下も要るなら R。
        Spaceの一括選択には混ぜていないので、要るときだけこのキーで明示的に選んでください。
  R     そのディレクトリを**再帰**で許可する（`<パス>/**` として宣言に書きます）
        観測されたファイルを1件ずつ承認するのが既定ですが、rustcのツールチェーンのように
        **数百ファイルを読み、更新のたびにパスが変わる**置き場ではそれが現実的でありません。
        そういう場所だけこのキーで明示的に広げてください。行は赤で `/**` 付きに変わります。
        中のファイルだけが観測されていて、そのフォルダ自身は候補になっていない行にも押せます。
        （画面を戻って入り直すと、セッション一覧は読み直されます——専用の読み直しキーは
        ありません。開いている候補と選択はそのまま残ります。）
  c     その行の access を変える（read → read_write → read_exec の巡回）
        OS監査は**読取と実行を区別できない**ので、実行ファイルへのアクセスも fs.read として
        観測されます。fs.read をいくら承認しても実行権は付かない（Access is denied のまま）
        ので、実行だと分かっているものは read_exec に変えてから承認してください。
        変えたことは承認前の確認画面に出ます。r（読み直し）で元に戻ります。
  f 一覧の範囲   t プロセスツリー   r 読み直し   a 承認
  枝分かれの無い1本道（C:/Users/<誰か>/AppData/Local など）は1行に畳んであります。
  既定では**承認できる候補だけ**を出します。広すぎる値（C:/ や C:/Users のような、
  受理するとサンドボックスの意味が消える範囲）は f で切り替えると見られます。
  隠している件数は候補一覧の見出しに出ています。

マウス
  クリック  タブ（F1〜F3 と承認待ちのタブ）・一覧の行・[x] / [ ]・▸ / ▾・入力欄・
            下のキー案内・確認画面の y=書く と n / Esc=やめる を押せます
            （どれもキーを押したのと同じ動きです。入力欄は Tab で入ったのと同じ）
            一括の操作（宣言画面の A・遷移タブの X）はキーでだけ押せます
  ホイール  ポインタの下の枠を送ります（ヘルプか確認画面が開いている間はそれを送ります）
  ヘルプはクリックでも閉じます。

停止（Esc）が効く範囲
  停止フラグを見ているのは、対象コマンドを回しているループの中だけです。収集器の起動
  （UACの応答待ち）・ETWのウォームアップ・終了後のドレインの間は見ていません。その区間で
  押した停止は「予約」になり、コマンドが始まった直後に打ち切られます。

まだ無いもの
  宣言どおりに走らせて確かめる専用の画面はありません。パス2の「強制」で行います。
  強制で効くのはこの試験実行の中だけで、harness.exe 本体はまだ policy.json の
  net.allow_domains で通信を許しません（本体では settings.json の net.allow_domains が効く）。
  policy.jsonのパスそのものの書き換えは未実装です（種類と ** は宣言画面の c・R で
  付け替えられ、宣言の取り消しは宣言画面の Space で予約できます）。

CLIも同じことができます: record / approve / record-net / show / sessions
";

/// ヘルプの枠の幅（端末がこれより狭ければ端末の幅）。
const HELP_WIDTH: u16 = 78;

/// ヘルプ（`F4`）を描き、送れる上限を返す（`top`は送り位置。`App::panels`）。
///
/// 開いている間は、画面のどこでホイールを回してもヘルプを送り、どこを押しても閉じる
/// （「何かキーを押すと閉じる」と同じ。`tui::pointer`）。後ろの画面は押せない（[`open_overlay`]）。
fn draw_help(frame: &mut Frame, area: Rect, top: u16, targets: &mut Targets) -> u16 {
    // **高さは本文から数える。** 固定値（26行）だった頃、本文はとうに44行あり
    // 半分以上が枠の外で切れていた——ヘルプに書いたのに読めない状態は「書いていない」のと
    // 同じである（B-09）。行数を手で持つと本文を足すたびにまたずれるので持たない（B-05）。
    //
    // **数えるのは折り返した後の行である**（BUG-192）。本文の行数で数えていた間は、
    // 枠の幅を超える行が折り返した分だけ、背の高い端末でも末尾が切れていた。
    let width = HELP_WIDTH.min(area.width);
    let rows = wrap::rows(HELP_TEXT, width.saturating_sub(2));
    let height = u16::try_from(rows).unwrap_or(u16::MAX).saturating_add(2);
    let screen = area;
    let area = open_overlay(frame, screen, width, height, targets);
    targets.wheel(screen, Wheel::Panel(scroll::Panel::Help));
    targets.click(screen, Click::CloseHelp);
    // 端末が低くて収まらない分は、ホイールで送る（`tui::scroll`）。キーは今までどおり、どれでも閉じる。
    harness_term::scrollable::draw(
        frame,
        area,
        HELP_TEXT,
        Block::default()
            .borders(Borders::ALL)
            .title(" ヘルプ（何かキーを押すかクリックすると閉じます） "),
        top,
        wrap::panel_look(Style::default()),
    )
}

/// 確認ダイアログの枠の幅（端末がこれより狭ければ端末の幅）。
const MODAL_WIDTH: u16 = 88;

/// 確認ダイアログ。
///
/// **操作の案内は本文ではなく枠（下辺）に置く。** 本文の最後に置くと、差分が長くて収まらない
/// ときに`y`を押せばよいことが画面から消える——実際に「確認画面は出たが、承認されたのか
/// 分からない」という形で踏んだ。長い差分は`↑↓/PgUp/PgDn`で送れるようにし、いま何行目を
/// 見ているかも出す（残りがあることが分からないと、読み切ったつもりで判断してしまう）。
///
/// # 行は折り返した後で数える（[BUG-192](../../../../docs/bugs/BUG-192.md)）
///
/// 本文は枠の幅で折り返す。以前は枠の高さ・「続きがあるか」・何行目かを**折り返す前の行数**で
/// 数えていたので、枠より長い行が折り返した分だけ下が枠の外へ出て切れ、送れるという案内も
/// 出なかった——上の「読み切ったつもり」がそのまま起きた（宣言の付け替えの確認で、
/// 「配下へ付いた継承ACEは残って効き続けます」が確定の前に見えなかった）。いまは3つとも
/// 折り返した後の行で数える（[`wrap::rows`]。描画と同じ折り返し器）。
///
/// # 送るのは「本文の最後の行が枠の一番下の行に来たところ」まで（[BUG-196](../../../../docs/bugs/BUG-196.md)）
///
/// `scroll`は**折り返した後の表示行**で、枠の一番上に見せる行である（下辺の「N〜M/T行」と同じ単位）。
/// 上限は描いて初めて分かるので、描く側（[`wrap::draw_scrollable`]）が切り詰めて描き、**上限を返す**——呼び出し側が
/// [`DrawFeedback::modal_scroll_max`]で状態へ書き戻す（`App::apply_draw_feedback`）。以前は上限が
/// 「最後の行が枠の一番上に来る位置」で、末尾では枠がほぼ空になるまで送れた。
/// 収まらないときだけ右の枠線の上にスクロールバーを出す。説明欄・ヘルプと同じ部品で描く。
///
/// ホイールでも送れる（`tui::scroll`）ので、下辺の送り方にホイールも書く——**見えていないと誰も試さない**
/// （記録画面のキー案内が「ホイール 枠内をさかのぼる」を出しているのと同じ理由）。
///
/// # 下辺の操作の案内はボタンとしても押せる（2026-10-02）
///
/// `y=書く`・`n / Esc=やめる`（読むだけのダイアログは`Enter / Esc=閉じる`）は、クリックでそのキーを
/// 押せる。**`a`で確認ダイアログを開いてから書く2段構えは変えない**——押せるようになったのは2段目の`y`で、
/// 1段目の`a`を押さずに書くことはできない。ボタンは枠の見出しではなく自分で下辺へ描き、描いた位置を
/// 登録する（`harness_term::scrollable::draw_with_buttons`）。見た目は見出しに置いていた頃と同じで、
/// 下辺の右の「N〜M/T行」はボタンの残りの幅に収まる形を選ぶ（ボタンを覆わない）。
/// ダイアログの外側は押せない（決定32: 書き込みの確認は`y`か`n`/`Esc`を選ばせる）。
///
/// **末尾の空行は数えも描きもしない。** 明細の組み立ては節の区切りに空行を足すので（付け替えの明細など）、
/// 後ろに何も続かないと本文が空行で終わる。数えると、末尾まで送ったときの一番下の行が空行になり、
/// 「どこで終わったのか」がまた見えなくなる。組み立ては画面ごとに何か所もあるので、描く側の1か所で落とす
/// （`modal.lines`そのものは変えない）。
fn draw_modal(
    frame: &mut Frame,
    area: Rect,
    modal: &state::Modal,
    scroll: u16,
    targets: &mut Targets,
) -> u16 {
    let written = modal
        .lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |last| last + 1);
    let text: Vec<Line> = modal.lines[..written]
        .iter()
        .map(|l| Line::raw(l.as_str()))
        .collect();
    let width = MODAL_WIDTH.min(area.width);
    let total = wrap::rows(text.clone(), width.saturating_sub(2));
    // 枠の2行と下の余白2行（折り返さない本文では以前と同じ高さになる）。
    let height = u16::try_from(total)
        .unwrap_or(u16::MAX)
        .saturating_add(4)
        .min(area.height.saturating_sub(2));
    let screen = area;
    let area = open_overlay(frame, screen, width, height.max(6), targets);
    // 開いている間は、画面のどこでホイールを回しても確認ダイアログを送る（`tui::scroll`）。
    targets.wheel(screen, Wheel::Modal);

    // ボタンとその間（見た目は1つの見出しだった頃の「 y=書く   n / Esc=やめる 」と同じ）。
    let buttons: &[(&str, Option<KeyCode>)] = if modal.confirm.asks() {
        &[
            (" y=書く ", Some(KeyCode::Char('y'))),
            (" ", None),
            (" n / Esc=やめる ", Some(KeyCode::Char('n'))),
        ]
    } else {
        &[(" Enter / Esc=閉じる ", Some(KeyCode::Enter))]
    };
    let color = if modal.confirm.asks() {
        Color::Yellow
    } else {
        Color::Red
    };
    let button_style = Style::default()
        .fg(Color::Black)
        .bg(color)
        .add_modifier(Modifier::BOLD);
    let spans: Vec<Span> = buttons
        .iter()
        .map(|(label, _)| Span::styled(*label, button_style))
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(format!(" {} ", modal.title));
    let drawn = harness_term::scrollable::draw_with_buttons(
        frame,
        area,
        text,
        block,
        scroll,
        harness_term::scrollable::Look {
            how: "↑↓ PgUp/PgDn・ホイールで送る",
            notice: Style::default().fg(Color::DarkGray),
            bar: Style::default().fg(color),
        },
        &spans,
    );
    for ((_, code), rect) in buttons.iter().zip(drawn.buttons) {
        if let Some(code) = code {
            targets.click(rect, Click::Keys(vec![pointer::key(*code)]));
        }
    }
    drawn.max_top
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod render_tests;

/// 後ろの画面の上に枠を重ねる場所を空ける。**後ろの画面に重ねて描く枠（確認ダイアログ・ヘルプ）は
/// どれもここを通る。** `area`の中央に`width`×`height`を取って中を消し、その矩形を返す。
///
/// 消し方は会話TUIと共有する`harness_term::overlay::clear`が持つ——`Clear`は矩形の中しか消さないので、
/// 後ろの画面の全角文字が枠の左隣から始まると左の枠線が端末へ届かない。その全角文字も消す
/// （[BUG-198](../../../../docs/bugs/BUG-198.md)。理由と採らなかった直し方は同モジュールのdoc）。
///
/// **マウスでも後ろを押せなくする**——`area`（画面全体）を覆う（`Targets::cover`）。開いている間に後ろの
/// 一覧やタブが押せると、見えないところで状態が変わる（キー入力も重ねた側だけが受ける。`App::on_key`）。
/// 重ねた枠の押せる場所は、呼び出し側がこの後に登録する。
fn open_overlay(
    frame: &mut Frame,
    area: Rect,
    width: u16,
    height: u16,
    targets: &mut Targets,
) -> Rect {
    targets.cover(area);
    let overlay = centered(area, width, height);
    harness_term::overlay::clear(frame, overlay);
    overlay
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}
