//! 端末の生モード/オルタネートスクリーンをRAII+panic hookで必ず復帰させる
//! （§リッチTUI「端末復帰」）。

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
/// 区別可能にする。非対応端末では`app.rs`側が従来通りShift無しEnterとして扱う。
static KEYBOARD_ENHANCEMENT_ENABLED: AtomicBool = AtomicBool::new(false);

pub struct TerminalGuard;

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        // マウスホイールでのtranscriptスクロール用（`AppState::on_mouse`参照）。
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        if supports_keyboard_enhancement().unwrap_or(false) {
            execute!(
                io::stdout(),
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )?;
            KEYBOARD_ENHANCEMENT_ENABLED.store(true, Ordering::SeqCst);
        }
        install_panic_hook();
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

fn restore() {
    if KEYBOARD_ENHANCEMENT_ENABLED.swap(false, Ordering::SeqCst) {
        let _ = execute!(io::stdout(), PopKeyboardEnhancementFlags);
    }
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
}

/// panicで`TerminalGuard::drop`が走らない経路（unwind前にprintされる等）に備え、
/// デフォルトのpanic hookの前に端末復帰を差し込む。
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        default_hook(info);
    }));
}
