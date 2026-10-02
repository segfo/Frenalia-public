//! 端末の生モード/オルタネートスクリーンをRAII+panic hookで必ず復帰させる
//! （`plans/DESIGN.md` §リッチTUI「端末復帰」）。
//!
//! `harness-tui`（会話TUI）と`harness-policy-editor`（ポリシーエディタTUI）が共有する。
//! 前者から後者を参照させないのは、ポリシーエディタが**会話エージェントとは独立した
//! 2つ目のバイナリ**だからで、コピーにしないのは端末復帰が「壊れても例外が出ない」
//! 種類のロジックだからである（`docs/CODE-STRUCTURE-RULES.md`規則5）。

/// 行を押せる一覧（ratatuiの`List`で描き、各項目が描かれた矩形を返す）。
pub mod list;
/// 後ろの画面の上に枠を重ねる場所を空ける（会話TUIとポリシーエディタの、重ねて描く枠が共有。BUG-198）。
pub mod overlay;
/// クリックとホイールの当たり判定（描いた矩形と押されたときの動きを、描くついでに登録して引く）。
pub mod pointer;
/// 1行に並べて描く項目（タブ・キー案内・ボタン）と、それぞれが描かれた場所。
pub mod row;
/// 先頭から読ませる送れる枠（送る上限・スクロールバー・位置の案内・下辺のボタン）。
pub mod scrollable;
/// 末尾追従のスクロール表示（会話TUIのtranscriptとポリシーエディタの記録画面が共有）。
pub mod scrollback;
/// 折り返して描く本文の、数える幅と描く幅（会話TUIとポリシーエディタが共有。BUG-200）。
pub mod wrap;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags,
    PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, EnterAlternateScreen,
    LeaveAlternateScreen,
};

/// レガシー端末プロトコルでは素のEnterとShift+Enterがどちらも修飾キー無しの
/// Enterとして届き区別できない。Kitty Keyboard Protocol対応端末（kitty/WezTerm/
/// 新しめのWindows Terminal等）でのみ拡張フラグを有効化し、Shift+Enterを
/// 区別可能にする。非対応端末では呼び出し側が従来通りShift無しEnterとして扱う。
static KEYBOARD_ENHANCEMENT_ENABLED: AtomicBool = AtomicBool::new(false);

/// `TERM_PROGRAM=vscode`かどうか（大小無視）。表示専用（入力欄のヒント文字列で
/// Alt+Enter/Shift+Enterどちらを案内するか）に使う判定で、キー処理の分岐には使わない
/// ——送信キーの実際の挙動はSHIFT修飾が届くか否かで自然に決まるため、誤検出しても
/// 動作は壊れずヒント文言がずれるだけに留まる。
pub fn host_is_vscode() -> bool {
    std::env::var("TERM_PROGRAM")
        .map(|v| v.eq_ignore_ascii_case("vscode"))
        .unwrap_or(false)
}

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enter_screen()?;
        install_panic_hook();
        Ok(Self)
    }

    /// 外部エディタ（`git merge-file`のconflict marker解消、`harness-tui`の`resolve.rs`参照）の
    /// ような対話子プロセスへ端末を明け渡す前に呼ぶ。代替スクリーン・raw mode・マウスキャプチャを
    /// 一時的に解除するだけで、`Drop`と違いpanic hookは触らない（プロセス自体は継続するため）。
    /// `resume()`と対で使うこと——`suspend()`だけ呼んで`resume()`を呼ばずに終了すると、
    /// 端末が生モードのまま残る。
    pub fn suspend(&self) -> io::Result<()> {
        leave_screen()
    }

    /// `suspend()`で明け渡した端末を取り戻す。呼び出し側は戻り値に関わらず、その後
    /// 強制再描画（`ratatui::Terminal::clear()`等）を行うこと（エディタが残した内容を消すため）。
    pub fn resume(&self) -> io::Result<()> {
        enter_screen()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = leave_screen();
    }
}

fn enter_screen() -> io::Result<()> {
    enable_raw_mode()?;
    // マウスホイールでのスクロール用（`harness-tui`の`AppState::on_mouse`参照）。
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    if supports_keyboard_enhancement().unwrap_or(false) {
        execute!(
            io::stdout(),
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        )?;
        KEYBOARD_ENHANCEMENT_ENABLED.store(true, Ordering::SeqCst);
    }
    Ok(())
}

fn leave_screen() -> io::Result<()> {
    if KEYBOARD_ENHANCEMENT_ENABLED.swap(false, Ordering::SeqCst) {
        execute!(io::stdout(), PopKeyboardEnhancementFlags)?;
    }
    disable_raw_mode()?;
    execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen)?;
    Ok(())
}

/// panicで`TerminalGuard::drop`が走らない経路（unwind前にprintされる等）に備え、
/// デフォルトのpanic hookの前に端末復帰を差し込む。
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = leave_screen();
        default_hook(info);
    }));
}

/// [BUG-200] ratatuiの単語折り返しが`width`桁の場所で1桁はみ出す1行（試験用）。
///
/// 「短い語・空白・全角だけの語」で、全角の語の最後の文字がちょうど最後の1桁から始まる形
/// （ポリシーエディタのヘルプの1行目と同じ形）。折り返しは「いまの文字を足す前の幅」で
/// あふれを判定するので、この行は折り返されずに`width + 1`桁になる。
#[cfg(test)]
pub(crate) fn spilling_line(width: u16) -> String {
    let width = usize::from(width);
    let head = if width % 2 == 1 { "a" } else { "ab" };
    let wide = (width - head.len()) / 2;
    format!("{head} {}", "あ".repeat(wide))
}
