//! 選んだ文章をクリップボードへ書く（会話TUIとポリシーエディタが共有する。2026-10-03）。
//!
//! # 端末を通さず、WindowsのAPIで書く
//!
//! 書き込みはWindowsのクリップボードのAPIを直接使う（`OpenClipboard`→`EmptyClipboard`→`SetClipboardData(CF_UNICODETEXT)`→
//! `CloseClipboard`）。端末にクリップボードへ書かせる制御文字（OSC 52）は、端末が対応しているか・許可しているかで
//! 黙って効かないことがあり、効いたかどうかもアプリからは分からない。APIなら失敗が戻り値で分かる。
//!
//! # 開けなければ数回やり直し、それでも駄目なら失敗を返す
//!
//! クリップボードは同時に1つのアプリしか開けない。ほかのアプリ（クリップボードの履歴・リモートデスクトップ等）が
//! 一瞬握っていると`OpenClipboard`が失敗するので、[`ATTEMPTS`]回まで[`RETRY_WAIT`]ずつ待ってやり直す。
//! それでも開けなければ`Err`で理由を返す——**黙って失敗しない**（呼び出し側は[`notice`]で画面に出す。B-23(c)）。
//! 開けた後の失敗（メモリを取れない・書き込みを断られた）はやり直さずにそのまま返す。
//!
//! # 書くのは呼び出し側の選んだ時だけ
//!
//! 選択の状態（[`crate::select::Selection`]）は文章を返すだけで、ここを呼ばない。呼ぶのは画面のイベントループで、
//! 試験は画面の状態だけを動かすので、**試験から実物のクリップボードに書くことは無い**。
//!
//! # 限界
//!
//! - 書くのは文字列（`CF_UNICODETEXT`）だけ。色や書式は写さない。
//! - Windows以外では書かない（`Err`で理由を返す）。
//! - やり直しの間は呼び出したスレッドが止まる（最長でおよそ[`ATTEMPTS`]×[`RETRY_WAIT`]）。非同期のループからは
//!   ブロッキング用のスレッドで呼ぶこと（B-31）。

use std::time::Duration;

/// `OpenClipboard`を試す回数。
pub const ATTEMPTS: u32 = 5;
/// 開けなかったときに次に試すまで待つ時間。
pub const RETRY_WAIT: Duration = Duration::from_millis(20);

/// 改行をクリップボードの形（`\r\n`）にする。もう`\r\n`になっているものは変えない。
pub fn crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous = None;
    for c in text.chars() {
        if c == '\n' && previous != Some('\r') {
            out.push('\r');
        }
        out.push(c);
        previous = Some(c);
    }
    out
}

/// 写した文字の数（改行`\r\n`は1文字と数える）。
pub fn chars(text: &str) -> usize {
    text.chars().count() - text.matches("\r\n").count()
}

/// 写した結果を画面に出す1行（2つの画面で同じ文面）。
pub fn notice(text: &str, result: &Result<(), String>) -> String {
    match result {
        Ok(()) => format!("{}文字をコピーしました", chars(text)),
        Err(reason) => format!("コピーできませんでした（{reason}）"),
    }
}

/// `text`をクリップボードへ書く（改行は[`crlf`]で`\r\n`にしてから渡す）。モジュールdoc。
pub fn write(text: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        write_with(text, imp::write_once, std::thread::sleep)
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        Err("この OS ではクリップボードへ書けません（Windows だけが対応しています）".to_string())
    }
}

/// 1回の書き込みの失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))] // Windows以外の製品では書かない（試験だけが使う）。
enum Failure {
    /// クリップボードを開けなかった（ほかのアプリが握っている）。やり直す。
    Busy(String),
    /// 開けた後で失敗した。やり直さない。
    Failed(String),
}

/// [`write`]の本体。`once`が1回書く（UTF-16で末尾にNULを付けたもの）、`sleep`が待つ。どちらも試験が差し替える。
#[cfg_attr(not(windows), allow(dead_code))] // Windows以外の製品では書かない（試験だけが使う）。
fn write_with(
    text: &str,
    mut once: impl FnMut(&[u16]) -> Result<(), Failure>,
    mut sleep: impl FnMut(Duration),
) -> Result<(), String> {
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        match once(&units) {
            Ok(()) => return Ok(()),
            Err(Failure::Failed(reason)) => return Err(reason),
            Err(Failure::Busy(reason)) => last = reason,
        }
        if attempt < ATTEMPTS {
            sleep(RETRY_WAIT);
        }
    }
    Err(format!(
        "ほかのアプリがクリップボードを使っています（{ATTEMPTS}回試しました。{last}）"
    ))
}

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    use super::Failure;

    /// `CF_UNICODETEXT`（UTF-16の文字列。`Win32_System_Ole`の定数だが、そのために大きな機能を足さない）。
    const CF_UNICODETEXT: u32 = 13;

    /// クリップボードを開いて`units`（末尾にNULを付けたUTF-16）だけを置き、閉じる。
    pub(super) fn write_once(units: &[u16]) -> Result<(), Failure> {
        // 持ち主のウィンドウは無し（コンソールのアプリなので）。
        // SAFETY: 引数は持ち主無しを表すヌルのハンドル。開けたら下で必ず閉じる。
        unsafe { OpenClipboard(HWND::default()) }
            .map_err(|e| Failure::Busy(format!("OpenClipboard: {e}")))?;
        let result = put(units);
        // SAFETY: 上で開いたクリップボードを閉じる。
        let _ = unsafe { CloseClipboard() };
        result
    }

    /// 開いているクリップボードを空にして`units`を置く。
    fn put(units: &[u16]) -> Result<(), Failure> {
        // SAFETY: このスレッドがクリップボードを開いている（`write_once`）。
        unsafe { EmptyClipboard() }.map_err(|e| Failure::Failed(format!("EmptyClipboard: {e}")))?;
        let bytes = std::mem::size_of_val(units);
        // SAFETY: 移動できるメモリを`bytes`だけ取る。置けなかったときは下で返す。
        let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }
            .map_err(|e| Failure::Failed(format!("GlobalAlloc: {e}")))?;
        // SAFETY: 取ったばかりのメモリを固定して、`bytes`だけ書く（取った大きさと同じ）。
        let target = unsafe { GlobalLock(memory) };
        if target.is_null() {
            // SAFETY: 取ったメモリを返す（まだクリップボードへ渡していない）。
            let _ = unsafe { GlobalFree(memory) };
            return Err(Failure::Failed("GlobalLock failed".to_string()));
        }
        // SAFETY: `target`は`bytes`以上の書き込める領域で、`units`とは重ならない。
        unsafe {
            std::ptr::copy_nonoverlapping(units.as_ptr(), target.cast::<u16>(), units.len());
        }
        // 固定を外す。最後の固定を外すと「失敗」（エラー無し）を返すのがこのAPIの決まりなので、結果は見ない。
        // SAFETY: 上で固定したメモリ。
        let _ = unsafe { GlobalUnlock(memory) };
        // SAFETY: 置けたらメモリの持ち主はシステムになる。置けなかったら自分で返す。
        match unsafe { SetClipboardData(CF_UNICODETEXT, HANDLE(memory.0)) } {
            Ok(_) => Ok(()),
            Err(e) => {
                // SAFETY: クリップボードへ渡せなかったので、まだ自分の持ち物。
                let _ = unsafe { GlobalFree(memory) };
                Err(Failure::Failed(format!("SetClipboardData: {e}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 改行は`\r\n`になる。もう`\r\n`のものは二重にしない。全角は割れない。
    #[test]
    fn line_breaks_become_crlf_once() {
        assert_eq!(crlf("a\nb"), "a\r\nb");
        assert_eq!(crlf("a\r\nb\n"), "a\r\nb\r\n");
        assert_eq!(crlf("あ\nい"), "あ\r\nい");
        assert_eq!(crlf("one line"), "one line");
    }

    /// 写した文字の数は、改行を1文字として数える。
    #[test]
    fn the_count_treats_a_line_break_as_one_character() {
        assert_eq!(chars("ab\r\nあ"), 4);
        assert_eq!(notice("ab\r\nあ", &Ok(())), "4文字をコピーしました");
    }

    /// 書くのはUTF-16で、末尾にNULが付く。1回目で書ければ待たない。
    #[test]
    fn the_text_is_written_as_utf16_with_a_terminating_nul() {
        let mut written = Vec::new();
        let mut waited = 0;
        let result = write_with(
            "aあ\r\n",
            |units| {
                written = units.to_vec();
                Ok(())
            },
            |_| waited += 1,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(written, vec![0x61, 0x3042, 0x0D, 0x0A, 0]);
        assert_eq!(waited, 0);
    }

    /// 開けないときはやり直し、途中で開ければ書ける（許可側）。
    #[test]
    fn a_busy_clipboard_is_retried_until_it_opens() {
        let mut tries = 0;
        let mut waited = Vec::new();
        let result = write_with(
            "x",
            |_| {
                tries += 1;
                if tries < 3 {
                    Err(Failure::Busy("held by another app".into()))
                } else {
                    Ok(())
                }
            },
            |wait| waited.push(wait),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(tries, 3);
        assert_eq!(waited, vec![RETRY_WAIT; 2]);
    }

    /// **開けないまま回数を使い切ったら、理由付きで失敗を返す**（黙って成功に見せない）。
    #[test]
    fn a_clipboard_that_never_opens_is_reported_as_a_failure() {
        let mut tries = 0;
        let result = write_with(
            "x",
            |_| {
                tries += 1;
                Err(Failure::Busy("OpenClipboard: access denied".into()))
            },
            |_| {},
        );
        assert_eq!(tries, ATTEMPTS);
        let reason = result.expect_err("失敗のはず");
        assert!(reason.contains("ほかのアプリ"), "{reason}");
        assert!(reason.contains("access denied"), "{reason}");
        assert!(notice("x", &Err(reason)).starts_with("コピーできませんでした"));
    }

    /// 開けた後の失敗はやり直さない。
    #[test]
    fn a_failure_after_opening_is_not_retried() {
        let mut tries = 0;
        let result = write_with(
            "x",
            |_| {
                tries += 1;
                Err(Failure::Failed("SetClipboardData: denied".into()))
            },
            |_| {},
        );
        assert_eq!(tries, 1);
        assert_eq!(result, Err("SetClipboardData: denied".to_string()));
    }
}
