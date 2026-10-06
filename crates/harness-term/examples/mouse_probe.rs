//! T10（`plans/PLAN-TUI-IMPROVEMENTS.md`§0・§3.3）: 端末がマウスの事象をアプリへどう渡すかを、実機で確かめるための小さなプログラム。
//!
//! 会話TUIと同じ入り方（[`harness_term::TerminalGuard::enter`]——生モード・代替画面・マウスの受け取りを有効にする）で
//! 端末を握り、届いたマウスの事象を画面に出す。確かめたいのは2つ:
//!
//! - (a) ボタンを押さずにマウスを動かした事象（`MouseEventKind::Moved`）が届くか——リンクのホバーに要る
//! - (b) マウスの事象に Ctrl が載るか（Ctrl を押しながらの左クリック）——リンクを開く操作に要る
//!
//! 使い方: `cargo run -p harness-term --example mouse_probe -- <名前>`（名前は測った端末とシェル。例: `conhost-cmd`・
//! `wt-pwsh`・`vscode-pwsh`。省略してよい）。`q` か `Esc` で終わり、終わった後の画面に集計を出し、同じ集計を
//! ワークスペースの [`LOG`]（`target/_logs/mouse_probe.log`。gitの管理外）へ追記する——画面に出しただけでは
//! 測った人が貼らない限り読めないため。製品のコードからは使わない。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::cursor::MoveTo;
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::queue;
use crossterm::terminal::{Clear, ClearType};

/// 届いたマウスの事象の数。
#[derive(Default)]
struct Tally {
    moved: u32,
    moved_ctrl: u32,
    left_down: u32,
    left_down_ctrl: u32,
    drag: u32,
    other: u32,
}

/// 画面に残す直近の事象の数。
const RECENT: usize = 15;

/// 集計を追記するファイル（ワークスペースの`target/`の下。どのディレクトリから動かしても同じ場所）。
const LOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/_logs/mouse_probe.log"
);

fn main() -> io::Result<()> {
    let label = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "(名前なし)".to_string());
    let mut tally = Tally::default();
    let mut recent: Vec<String> = Vec::new();
    {
        let _guard = harness_term::TerminalGuard::enter()?;
        draw(&tally, &recent)?;
        loop {
            match event::read()? {
                Event::Key(key)
                    if key.kind == KeyEventKind::Press
                        && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) =>
                {
                    break;
                }
                Event::Mouse(mouse) => {
                    let ctrl = mouse.modifiers.contains(KeyModifiers::CONTROL);
                    match mouse.kind {
                        MouseEventKind::Moved => {
                            tally.moved += 1;
                            tally.moved_ctrl += u32::from(ctrl);
                        }
                        MouseEventKind::Down(MouseButton::Left) => {
                            tally.left_down += 1;
                            tally.left_down_ctrl += u32::from(ctrl);
                        }
                        MouseEventKind::Drag(_) => tally.drag += 1,
                        _ => tally.other += 1,
                    }
                    recent.push(format!(
                        "{:?}  桁{} 行{}  修飾 {:?}",
                        mouse.kind, mouse.column, mouse.row, mouse.modifiers
                    ));
                    if recent.len() > RECENT {
                        recent.remove(0);
                    }
                    draw(&tally, &recent)?;
                }
                _ => {}
            }
        }
    }
    // 端末を返した後の普通の画面に出し、同じものをファイルへ追記する。
    let lines = summary(&tally);
    for line in &lines {
        println!("{line}");
    }
    match append_log(&label, &lines) {
        Ok(()) => println!("集計を {} へ追記しました（名前: {label}）", LOG),
        // 書けなかったことは黙らせない（画面の集計は上に出ている）。
        Err(err) => println!("集計をファイルへ書けませんでした: {err}（{LOG}）"),
    }
    Ok(())
}

/// 集計を[`LOG`]の末尾へ足す。1回分は「区切りの行・測った時刻（UNIX秒）・名前・集計」。
fn append_log(label: &str, lines: &[String]) -> io::Result<()> {
    let path = Path::new(LOG);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    writeln!(file, "---- {unix} {label}")?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

/// 画面を描き直す（生モードなので、行ごとにカーソルを動かして書く）。
fn draw(tally: &Tally, recent: &[String]) -> io::Result<()> {
    let mut out = io::stdout();
    queue!(out, Clear(ClearType::All))?;
    let mut lines = vec![
        "マウスの事象の確かめ（q か Esc で終わる）".to_string(),
        "1. ボタンを押さずにマウスを動かす".to_string(),
        "2. Ctrl を押しながら左クリックする（数回）".to_string(),
        "3. 普通に左クリックする（数回）".to_string(),
        String::new(),
    ];
    lines.extend(summary(tally));
    lines.push(String::new());
    lines.push("直近の事象:".to_string());
    lines.extend(recent.iter().cloned());
    for (row, line) in lines.iter().enumerate() {
        let row = u16::try_from(row).unwrap_or(u16::MAX);
        queue!(out, MoveTo(0, row))?;
        write!(out, "{line}")?;
    }
    out.flush()
}

/// 集計の数行。どの端末で測ったかが分かるように、端末を見分ける環境変数も添える。
fn summary(tally: &Tally) -> Vec<String> {
    let term_program = std::env::var("TERM_PROGRAM").unwrap_or_else(|_| "(無し)".to_string());
    let windows_terminal = if std::env::var_os("WT_SESSION").is_some() {
        "有り"
    } else {
        "無し"
    };
    vec![
        format!("端末: TERM_PROGRAM={term_program} / WT_SESSION {windows_terminal}"),
        format!(
            "(a) ボタンを押さない移動（Moved）: {} 回（うち Ctrl 付き {} 回）",
            tally.moved, tally.moved_ctrl
        ),
        format!(
            "(b) 左ボタンを押した: {} 回（うち Ctrl 付き {} 回）",
            tally.left_down, tally.left_down_ctrl
        ),
        format!("ドラッグ: {} 回 / その他: {} 回", tally.drag, tally.other),
    ]
}
