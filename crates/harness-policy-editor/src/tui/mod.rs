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
mod proposal_tree;
pub mod record_screen;
mod stderr_capture;
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
/// 折り返す枠の行数を数え、入り切らなかった分を黙らせない部品（BUG-192）。
mod wrap;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use state::{Action, App, Screen};

/// **1フレーム描いて初めて分かること。** 呼び出し側が[`App::apply_draw_feedback`]で状態へ書き戻す。
///
/// 描画時にしか決まらない値が2種類ある。
///
/// 1. さかのぼりの上限（折り返し後の行数は枠の幅に依存する。`harness_term::scrollback`のdoc）
/// 2. 一覧の表示開始位置（ratatuiが「選択を見せる」ために動かした結果）
///
/// どちらも**書き戻さないと壊れる**——1を怠ると先頭で空回りし（BUG-076）、
/// 2を怠るとカーソルが窓の中を動かず一覧の方が滑る。
#[derive(Debug, Default, Clone, Copy)]
pub struct DrawFeedback {
    pub scroll: record_screen::ScrollLimits,
    /// `None`＝この画面はその一覧を描いていない（触らない）。
    pub session_list_offset: Option<usize>,
    pub candidate_list_offset: Option<usize>,
    pub declared_list_offset: Option<usize>,
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
    // raw mode／オルタネートスクリーン／panic hookの復帰は`harness-term`が持つ（会話TUIと共有）。
    let _guard = harness_term::TerminalGuard::enter()?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    // **入った直後に必ず消す。** オルタネートスクリーンは端末が保持しているので、直前に別の
    // TUI（`harness.exe`）が同じ端末で使っていれば、その内容が残ったまま入ることになる。
    // ratatuiは自分の前フレーム（起動時は空白）との差分しか書かないため、こちらが触らない
    // セルには他人の描画が残り続ける。
    term.clear()?;

    // ライブラリが`eprintln!`で直接端末へ書くと、こちらのフレームの上に重なって表示が壊れる
    // （`verify_elevation_target`のD-44警告が実際にそうなる）。TUIの間だけstderrを預かる。
    let mut stderr = stderr_capture::StderrCapture::start(&workspace_root);
    // **`_grants`より後**に作る。WFPの出口強制daemon（D-56）も同じくTUIを閉じるまで生かすが、
    // その`Teardown`はAppContainerプロファイルの削除（`SessionGrants`のDrop）より**先**に
    // 走らなければならない——フィルタはそのプロファイルのpackage SIDを条件にしているため。
    // Rustは宣言の逆順にdropするので、この順序がそのまま撤収順になる（`App`が`wfp`を持つ）。
    let mut app = App::new(workspace_root, require_sandbox);

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
    app.apply_draw_feedback(feedback);
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
        app.apply_draw_feedback(feedback);

        if !event::poll(TICK)? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => match app.on_key(key) {
                Some(Action::Quit) => break,
                Some(Action::StartPass1(request)) => {
                    app.attach_handle(worker::spawn_pass1(*request));
                }
                Some(Action::StartPass2(request)) => {
                    app.attach_handle(worker::spawn_pass2(*request));
                }
                None => {}
            },
            // **ホイールはポインタの下の枠をさかのぼる。**
            //
            // `↑/↓`は項目移動、`←/→`はパス切替で既に埋まっているので、キーを増やさずに
            // 済むホイールだけを入れている。枠の当たり判定は描画とまったく同じ計算を通す
            // （`record_screen::scroll_target`が画面全体の割り付け[`screen_rows`]から辿る）
            // ——別々に持つと「見えている枠と反応する枠」がずれる（BUG-194は実際にずれていた）。
            // 端末の大きさはここで聞き直すので、位置を状態に持ち越さない。
            Event::Mouse(mouse) => {
                let delta = match mouse.kind {
                    event::MouseEventKind::ScrollUp => Some(true),
                    event::MouseEventKind::ScrollDown => Some(false),
                    _ => None,
                };
                if let Some(up) = delta {
                    app.on_scroll(term.size()?, mouse.column, mouse.row, up);
                }
            }
            // リサイズは次のdrawで反映される。
            Event::Resize(_, _) | Event::Paste(_) => {}
            _ => {}
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

/// 画面全体の縦割り（タブ1行・本体・知らせ・キー案内1行）。
struct ScreenRows {
    tabs: Rect,
    body: Rect,
    status: Rect,
    keys: Rect,
}

/// 画面全体を[`ScreenRows`]に割る。**描画（[`draw`]）とマウスの当たり判定
/// （`record_screen::scroll_target`）が同じこの関数を通る**（[BUG-194](../../../../docs/bugs/BUG-194.md)）。
///
/// 以前はこの割り付けを描画だけが持ち、当たり判定は**端末全体を本体として**記録画面の割り付けを
/// 計算していた。反応する枠は見えている枠より1行上にずれ、下は知らせの行とキー案内の行まで
/// 伸びていた。知らせの行は折り返して複数行になる（BUG-192）ので、別々に持つとずれ方も毎回変わる。
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

    draw_tabs(frame, rows.tabs, app);
    // 記録画面だけがさかのぼれる枠を持つ。上限は**描画してみないと分からない**
    // （折り返し後の行数は枠の幅に依存する）ので、ここで受け取って呼び出し側へ返す。
    let feedback = match app.screen {
        Screen::Record => DrawFeedback {
            scroll: record_screen::draw(frame, rows.body, app),
            ..Default::default()
        },
        // 承認待ち画面は3つのタブを持つ（決定62）。遷移の2タブは別の描き手。
        Screen::Edit if app.pending.tab.0.is_transition() => {
            transition_screen::draw(frame, rows.body, app)
        }
        Screen::Edit => edit_screen::draw(frame, rows.body, app),
        Screen::Declared => declared_screen::draw(frame, rows.body, app),
    };
    draw_status(frame, rows.status, status_text(app));
    draw_keys(frame, rows.keys, app);

    if app.help {
        draw_help(frame, area);
    }
    if let Some(modal) = app.modal.as_ref() {
        draw_modal(frame, area, modal, app.modal_scroll);
    }
    feedback
}

fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let active = Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let idle = Style::default().fg(Color::Gray);
    let line = Line::from(vec![
        Span::styled(
            " F1 記録 ",
            if app.screen == Screen::Record {
                active
            } else {
                idle
            },
        ),
        Span::raw(" "),
        Span::styled(
            " F2 承認待ち ",
            if app.screen == Screen::Edit {
                active
            } else {
                idle
            },
        ),
        Span::raw(" "),
        Span::styled(
            " F3 宣言 ",
            if app.screen == Screen::Declared {
                active
            } else {
                idle
            },
        ),
        Span::styled("  Ctrl+N で切替", Style::default().fg(Color::DarkGray)),
        Span::raw("   "),
        Span::styled(
            format!("workspace: {}", app.workspace_root.display()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
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
    frame.render_widget(Paragraph::new(status).wrap(Wrap { trim: false }), area);
}

/// 画面ごとのキー案内。押せるキーだけを出す。**効かない操作を案内しない**（B-32）。
///
/// 全画面に共通の案内（[`COMMON_KEYS`]）はここに含めない——幅が足りないときの扱いが
/// 違うからである（[`fit_key_hints`]）。
fn screen_keys(app: &App) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    match app.screen {
        Screen::Record => {
            // 枠が出ている間だけ案内する（実行前は遡る対象が無い）。ホイールは
            // **見えていないと誰も試さない**ので、キー以外でもここへ出す（B-32）。
            if app.run.is_some() {
                keys.push("ホイール 枠内をさかのぼる".to_string());
            }
            if app.is_running() {
                let run = app.run.as_ref().expect("is_running implies a run");
                if run.phase.stop_takes_effect_now() {
                    keys.push("Esc 停止".to_string());
                } else if run.phase.stop_can_be_queued() {
                    keys.push("Esc 停止を予約".to_string());
                }
            } else {
                // 終わった記録の結果を見ている間も、次の操作は同じ（もう一度実行する／
                // 候補を見に行く）。**押せるものを隠さない**——結果を読んだ後に何をすれば
                // よいかが画面から消えると、そこで手が止まる。
                keys.push("Tab 項目移動".to_string());
                keys.push("Enter 記録を開始".to_string());
                if app.has_finished_run() {
                    keys.push("F2 候補を見る".to_string());
                }
                keys.push("Esc 編集画面へ".to_string());
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
            keys.push("Space 選ぶ/外す".to_string());
            let reserved = app.pending.reserved_count();
            if reserved == 0 {
                keys.push("a 確定".to_string());
            } else {
                // 予約件数を出す（何件書かれるのかが確定の直前まで見えている必要がある）。
                keys.push(format!("a 確定（{reserved}件）"));
            }
            keys.push("x 却下/戻す".to_string());
            keys.push("u 引数の広さ".to_string());
            // 遷移先の欄（2026-10-01）。確定の中身を変える設定なので、`u`と同じ並びに置く。
            keys.push("Tab 遷移先".to_string());
            keys.push(format!("f 表示: {}", app.pending.filter.label()));
            keys.push("X 表示中を却下".to_string());
            keys.push("↑↓ 選択".to_string());
            keys.push("r 読み直し".to_string());
            keys.push("F2 タブ切替".to_string());
            keys.push("Esc 戻る".to_string());
        }
        Screen::Edit => {
            keys.push("Esc 記録画面へ".to_string());
            keys.push("F2 タブ切替".to_string());
            keys.push("Tab 項目移動".to_string());
            keys.push("↑↓ 選択".to_string());
            keys.push("→← 展開/折畳".to_string());
            keys.push("Space この配下をまとめて選択".to_string());
            keys.push("c access変更".to_string());
            keys.push("d この行自身も選ぶ".to_string());
            keys.push("R 再帰(**)".to_string());
            keys.push(format!("f 一覧: {}", app.filter.label()));
            keys.push("t プロセスツリー".to_string());
            keys.push("a 承認".to_string());
        }
        Screen::Declared => {
            keys.push("Esc 記録画面へ".to_string());
            keys.push("↑↓ 選択".to_string());
            keys.push("Space 取り消しを予約".to_string());
            keys.push("A 全件".to_string());
            // [D-112] 未承認の宣言があるときだけ出す（無いときに押しても何も起きない）。
            if !app.declared_approval.not_approved.is_empty() {
                keys.push("y このマシンで承認を予約".to_string());
            }
            // 付け替え（1行ずつ）。キーは候補画面の`c`・`R`と同じ。
            keys.push("c 種類を変える".to_string());
            keys.push("R ** の付け外し".to_string());
            keys.push("r 読み直し".to_string());
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
                keys.push("a 確定".to_string());
            } else {
                keys.push(format!("a 確定（{}）", parts.join("・")));
            }
        }
    }
    keys
}

/// 全画面に共通のキー案内。画面ごとの項目の後ろに並べる。
///
/// **Esc×2は案内しないと見つけられない。** 単押しは画面遷移なので、二度押しが終了である
/// ことは画面から推測できない。
const COMMON_KEYS: [&str; 3] = ["F4 ヘルプ", "Esc×2 終了", "Ctrl+C 終了"];

/// キー案内の項目の区切り。
const KEY_SEPARATOR: &str = "  |  ";

fn draw_keys(frame: &mut Frame, area: Rect, app: &App) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            fit_key_hints(&screen_keys(app), area.width as usize),
            Style::default().fg(Color::DarkGray),
        )),
        area,
    );
}

/// キー案内の1行を`width`桁に収める。
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
/// - **件数を出す**のは、省略したことを黙らないためである（`record_screen`の警告枠の
///   `… 他 N行`と同じ。B-09）。落とした項目はヘルプ（`F4`）に載っている。
///
/// 全部収まるときは以前と1文字も変わらない。共通の案内そのものより狭い端末では、
/// 共通の案内も末尾から切れる（描画が落ちないことだけを保つ）。
fn fit_key_hints(screen: &[String], width: usize) -> String {
    use unicode_width::UnicodeWidthStr;

    let line = |kept: &[String], omitted: Option<&str>| -> String {
        kept.iter()
            .map(String::as_str)
            .chain(omitted)
            .chain(COMMON_KEYS)
            .collect::<Vec<_>>()
            .join(KEY_SEPARATOR)
    };
    let full = line(screen, None);
    if full.width() <= width {
        return full;
    }
    // 画面ごとの項目を後ろから1件ずつ落とし、収まった時点で止める。
    for kept in (0..screen.len()).rev() {
        let omitted = format!("… 他{}件", screen.len() - kept);
        let fitted = line(&screen[..kept], Some(&omitted));
        if fitted.width() <= width {
            return fitted;
        }
    }
    // 画面ごとの項目を全部落としても収まらない幅。共通の案内だけを出す。
    line(&[], None)
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

fn draw_help(frame: &mut Frame, area: Rect) {
    // **高さは本文から数える。** 固定値（26行）だった頃、本文はとうに44行あり
    // 半分以上が枠の外で切れていた——ヘルプに書いたのに読めない状態は「書いていない」のと
    // 同じである（B-09）。行数を手で持つと本文を足すたびにまたずれるので持たない（B-05）。
    //
    // **数えるのは折り返した後の行である**（BUG-192）。本文の行数で数えていた間は、
    // 枠の幅を超える行が折り返した分だけ、背の高い端末でも末尾が切れていた。
    let width = HELP_WIDTH.min(area.width);
    let rows = wrap::rows(HELP_TEXT, width.saturating_sub(2));
    let height = u16::try_from(rows).unwrap_or(u16::MAX).saturating_add(2);
    let area = centered(area, width, height);
    frame.render_widget(Clear, area);
    // ヘルプは送れない（何かキーを押すと閉じる）。端末が低くて収まらない分は、行数を枠に出す。
    wrap::draw_box(
        frame,
        area,
        HELP_TEXT,
        Block::default()
            .borders(Borders::ALL)
            .title(" ヘルプ（何かキーを押すと閉じます） "),
    );
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
/// `scroll`は**`modal.lines`の何行目から見せるか**である（`App::on_modal_key`がその行数で
/// 上限を掛ける）。ratatuiの`scroll`は折り返した後の行で数えるので、手前の行が折り返した分を
/// 足して直してから渡す——そのまま渡すと、折り返しの多い本文では`End`が末尾に届かない。
/// **限界**: 送る単位が`modal.lines`の1行なので、1行だけで枠の高さを超える行は途中を見られない
/// （枠は最低でも4行あり、確認の本文の1行はそこまで長くない）。
fn draw_modal(frame: &mut Frame, area: Rect, modal: &state::Modal, scroll: u16) {
    let text: Vec<Line> = modal.lines.iter().map(|l| Line::raw(l.as_str())).collect();
    let width = MODAL_WIDTH.min(area.width);
    let text_width = width.saturating_sub(2);
    let total = wrap::rows(text.clone(), text_width);
    // 枠の2行と下の余白2行（折り返さない本文では以前と同じ高さになる）。
    let height = u16::try_from(total)
        .unwrap_or(u16::MAX)
        .saturating_add(4)
        .min(area.height.saturating_sub(2));
    let area = centered(area, width, height.max(6));
    frame.render_widget(Clear, area);

    let visible = area.height.saturating_sub(2) as usize;
    // 見せ始める`modal.lines`の行 → その手前が折り返して占める表示行。
    let first = usize::from(scroll).min(text.len());
    let top = wrap::rows(text[..first].to_vec(), text_width);
    let keys = if modal.confirm.asks() {
        " y=書く   n / Esc=やめる "
    } else {
        " Enter / Esc=閉じる "
    };
    let position = if total > visible {
        format!(
            " {}〜{}/{}行  ↑↓ PgUp/PgDn で送る ",
            (top + 1).min(total),
            (top + visible).min(total),
            total
        )
    } else {
        String::new()
    };

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if modal.confirm.asks() {
            Color::Yellow
        } else {
            Color::Red
        }))
        .title(format!(" {} ", modal.title))
        .title_bottom(Line::styled(
            keys,
            Style::default()
                .fg(Color::Black)
                .bg(if modal.confirm.asks() {
                    Color::Yellow
                } else {
                    Color::Red
                })
                .add_modifier(Modifier::BOLD),
        ));
    if !position.is_empty() {
        block = block.title_bottom(
            Line::styled(position, Style::default().fg(Color::DarkGray)).right_aligned(),
        );
    }
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(top).unwrap_or(u16::MAX), 0))
            .block(block),
        area,
    );
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod render_tests;

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
