//! 端末の生モード/オルタネートスクリーンをRAII+panic hookで必ず復帰させる
//! （`plans/DESIGN.md` §リッチTUI「端末復帰」）。例外は、呼び出し側が[`contain_panic`]で「この中のpanicは
//! 受け止めて続ける」と宣言した範囲だけ。
//!
//! `harness-tui`（会話TUI）と`harness-policy-editor`（ポリシーエディタTUI）が共有する。
//! 前者から後者を参照させないのは、ポリシーエディタが**会話エージェントとは独立した
//! 2つ目のバイナリ**だからで、コピーにしないのは端末復帰が「壊れても例外が出ない」
//! 種類のロジックだからである（`docs/CODE-STRUCTURE-RULES.md`規則5）。

/// ボタン——枠の辺へ並べる1行の形と、欄の右隣に置く枠付きの形（会話TUIとポリシーエディタが共有）。
pub mod button;
/// 選んだ文章をクリップボードへ書く（WindowsのAPIを直接使う。会話TUIとポリシーエディタが共有）。
pub mod clipboard;
/// `Esc`の二度押しで画面を閉じる（判定と窓の長さ。会話TUIとポリシーエディタが共有）。
pub mod double_esc;
/// 追記されていくファイルの追記追従読み（ポリシーエディタの監査ログと、預かった標準エラーが共有）。
pub mod line_tail;
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
/// 画面に出ている文章をマウスで選ぶ（送れる枠の文章。会話TUIとポリシーエディタが共有）。
pub mod select;
/// 画面を握っている間、このプロセスの標準エラーを預かって画面の中へ出す（会話TUIとポリシーエディタが共有。BUG-206）。
pub mod stderr_capture;
/// タブ——並んだ中から1つを選び、いまどれを開いているかを示し続ける（ボタンとは別の部品。ポリシーエディタが使う）。
pub mod tab;
/// 折り返して描く本文の、数える幅と描く幅（会話TUIとポリシーエディタが共有。BUG-200）。
pub mod wrap;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, KeyCode, KeyEvent, KeyModifiers,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
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

/// Windows の表示言語（`GetUserDefaultUILanguage`の LANGID）。取れなければ`None`。Windows 以外では常に`None`。
///
/// 会話画面が承認ダイアログの要約の言語を決めるのに使う（ユーザーの文から言語が決まらないときの倒し先。
/// `harness_engine::approval_summary::SummaryLanguage`）。**判定には使わない**——表示の言語を選ぶだけで、
/// 外れても要約が別の言語で出るだけに留まる。
pub fn ui_language_id() -> Option<u16> {
    #[cfg(windows)]
    {
        // SAFETY: 引数を取らず、呼び出し元の状態を読み書きしない（ユーザーの設定を返すだけ）。
        let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        (id != 0).then_some(id)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// `Ctrl`か`Alt`を押しながらの文字キーか（[BUG-212]）。
///
/// 重ねた枠（承認ダイアログ・レビューパネル・確認ダイアログ）は文字のキーで決める（`y`=許可・`c`=commit等）。
/// キーの種類（`KeyCode::Char`）だけを見ると、`Ctrl+C`（コピーのつもり）が`c`=commitとして、`Ctrl+Y`が`y`=許可として
/// 効く。**押した人が狙ったのは別の操作**なので、そうした枠は先頭でこれが真のキーを捨てる。`Shift`は数えない
/// （大文字は別の文字として届く）。
///
/// [BUG-212]: ../../../docs/bugs/BUG-212.md
pub fn is_chorded_char(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char(_))
        && key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
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
/// デフォルトのpanic hookの前に端末復帰を差し込む。**[`contain_panic`]の範囲の中で起きたpanicでは戻さない**
/// （受け止めて続けるため。[`on_panic`]）。
fn install_panic_hook() {
    chain_panic_hook(|| {
        let _ = leave_screen();
    });
}

/// いまのpanicのフックの前に`restore`（端末を戻す）を差し込む。呼ぶ順と、戻すかどうかは[`on_panic`]が決める。
/// 製品の`restore`は端末を戻す（[`install_panic_hook`]）。試験は戻した回数を数えるものを渡す。
fn chain_panic_hook(restore: impl Fn() + Send + Sync + 'static) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        on_panic(&restore, || previous(info));
    }));
}

/// panicのフックの中身。[`contain_panic`]の範囲の外なら端末を戻し（`restore`）、それから元のフックに報告させる
/// （`report`）。範囲の中では戻さずに報告だけさせる（[`contain_panic`]の「止めるのは端末を戻すことだけ」）。
///
/// 戻してから報告するのは、報告の文面（既定では標準エラー）をオルタネートスクリーンの上に書くと、画面を返した
/// 瞬間に消えて読めないため（今までの順）。
fn on_panic(restore: impl FnOnce(), report: impl FnOnce()) {
    if !panic_is_contained() {
        restore();
    }
    report();
}

thread_local! {
    /// このスレッドで[`contain_panic`]の中にいる深さ（入れ子を数える）。0なら範囲の外。
    static CONTAINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`contain_panic`]の範囲。作ると印を1つ立て、捨てると1つ倒す——`f`がpanicしても、しなくても倒れる。
struct Contained;

impl Contained {
    fn enter() -> Self {
        CONTAINED.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for Contained {
    fn drop(&mut self) {
        let _ = CONTAINED.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// `f`を呼び、中で起きたpanicを受け止めて`Err`（panicの中身）で返す。**範囲の中で起きたpanicでは、panicのフック
/// （[`TerminalGuard::enter`]が差し込むもの）が端末を戻さない**——TUIは画面を握ったまま描き続けられる。
///
/// # 何のためにあるのか
///
/// 端末を戻すフックはpanicの**巻き戻しより前**に走る。だから`catch_unwind`で受け止めても、受け止める前に端末は
/// 戻っていて（生モード・オルタネートスクリーン・マウスの取り込みが外れる）、TUIは壊れた画面のまま続くことになる。
/// そこで「この中のpanicは受け止める」という印をこのスレッドに立ててから`f`を呼び、フックはその印を見て端末を
/// 戻すのを止める（[`on_panic`]）。会話TUIが、外から持ち込んだ部品（Markdownの解析器）が落ちても、その返答だけを
/// 原文のまま描く形へ落として続けるのに使う。**ポリシーエディタは使わない**——使わない限り、フックは今までどおり
/// 必ず端末を戻す。
///
/// # 止めるのは端末を戻すことだけ
///
/// panicの報告（元のフック。既定では標準エラーへの文面と場所）は、範囲の中でも呼ぶ。TUIが画面を握っている間は、
/// 標準エラーは[`stderr_capture`]が預かって画面の中に`[stderr]`の行として出す（「panicのメッセージもここを
/// 通る」）ので、受け止めたpanicも黙らない。
///
/// # 呼び出し側の約束
///
/// - **受け止めた後は、`f`が触っていた状態を使わずに捨てる。** panicは処理の途中で起きるので、状態は途中までしか
///   変わっていないことがある（`f`に`UnwindSafe`を求めない代わりの約束）
/// - 印はスレッドごと。別のスレッドで起きたpanicは受け止めない
///
/// # 限界
///
/// - **`panic = "abort"`でビルドすると受け止められない。** そのときは印を見ず（[`panic_is_contained`]が常に偽）、
///   今までどおり端末を戻してから終わる——戻さずに終わると、端末が生モードのまま残るため
/// - `f`の中の値の後始末（`Drop`）が、巻き戻しの途中でさらにpanicすると、プロセスはabortする（Rustの規則）。
///   そのときは印が立ったままなので、**端末を戻さずに終わる**
pub fn contain_panic<R>(f: impl FnOnce() -> R) -> std::thread::Result<R> {
    let _contained = Contained::enter();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
}

/// このスレッドがいま[`contain_panic`]の中にいるか（いまpanicが起きたら、フックが端末を戻さないか）。
///
/// `panic = "abort"`のビルドでは常に偽（受け止められないので、端末を戻す側へ倒す）。スレッドの後始末の途中で
/// 印が読めないときも偽。
pub fn panic_is_contained() -> bool {
    cfg!(panic = "unwind") && CONTAINED.try_with(|depth| depth.get() > 0).unwrap_or(false)
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

#[cfg(test)]
#[path = "contain_tests.rs"]
mod contain_tests;
