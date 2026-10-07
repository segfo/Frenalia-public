//! transcriptのリンクを既定のブラウザで開く（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§3.4・§3.5・§0のT11b）。
//! どのリンクを押したか・開いてよいかを決めるのは`crate::app`の`link_open`、ここが持つのは**開いてよいURLの型**と、
//! **Windowsに開かせる呼び出し**と、結果の文面。
//!
//! # 開いてよいのはhttpとhttpsだけ——型で縛り、開く直前にもう一度確かめる
//!
//! リンクを書くのはモデルである。`ms-msdt:`・`search-ms:`のように既定のアプリへ渡る形式は攻撃に使われた実績があり、
//! `file:`・`javascript:`・`data:`も開かない。判定は`web_fetch`と同じ`harness_tools::parse_http_url`を借りる
//! （判定を写さない）。スキームの無い相対URL（`foo.html`）も、解析できないので開かない。
//!
//! - [`OpenableUrl`]はその判定を通してしか作れない（中身は非公開）。開く処理（[`open`]）はこの型しか受け取らないので、
//!   検査していない文字列は渡せない。
//! - そのうえで[`open`]は渡す直前にもう一度同じ判定を通し、正規化した形がそのまま戻ることまで確かめる（B-20——
//!   判定を呼び出し側の作法に任せない。型の保証は、このモジュールの中で値を組み立てる変更が入ると黙って崩れる）。
//! - 中身は**正規化した形**（スキームとホストは小文字・空白などは`%`で符号化・パスの無いものは`/`）。吹き出しに
//!   出すのも、ブラウザへ渡すのもこの同じ文字列（B-21——見せた値と開く値を別物にしない。国際化ドメインは`xn--`の形で
//!   見えるので、よく似た字のドメインも見分けられる）。
//!
//! # 開くのはイベントループで、ブロッキング用のスレッド
//!
//! 状態（`crate::app::AppState`）は開くURLを`Action::OpenUrl`で返すだけで、ここを呼ばない（クリップボードの
//! `Action::Copy`と同じ形）。イベントループ（`crate::run`）が[`open_and_note`]で`ShellExecuteW`をブロッキング用の
//! スレッドで呼ぶ（既定のアプリを起こすまで戻らないことがある。B-31）。だから**試験は本物のブラウザを開かない**——
//! 試験が動かすのは状態と、開く呼び出しを差し替えた`open_with`だけ。
//!
//! # 開けたか・開けなかったかを知らせる
//!
//! 端末の機能（OSC 8のリンク）ではなくWindowsのAPIを使うのは、失敗が戻り値で分かるから（クリップボードで端末の機能
//! ではなくAPIを選んだのと同じ。`harness_term::clipboard`の冒頭）。結果はtranscriptの枠の上辺に出す（[`notice`]。
//! 写した結果と同じ場所）。成功は「既定のブラウザへ渡しました」——`ShellExecuteW`が成功を返すのは既定のアプリへ
//! 渡せたところまでで、ページが表示されたかまでは分からない。
//!
//! # COMを初期化してから呼ぶ
//!
//! `ShellExecuteW`は、関連付けによってはCOMで起こすシェル拡張へ処理を渡すので、Microsoftのドキュメントは呼ぶ前に
//! COMを初期化するよう求めている（`COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE`）。呼ぶたびに初期化し、
//! 初期化できたときだけ呼んだ後に戻す（ブロッキング用のスレッドは使い回されるので、残さない）。別の形で初期化済みの
//! スレッドでは初期化できないが、そのまま呼ぶ。
//!
//! # この機構の限界（計画書§3.5）
//!
//! - **会話TUIはサンドボックスの外でユーザーの権限で動いている**ので、開いたブラウザもサンドボックスの外で動く。
//!   守っているのは「開く前に本当のURLが見える（吹き出し）」「明示の操作（リンクの文字の`Ctrl`＋クリック・
//!   吹き出しのURLのクリック）でしか開かない」「形式の制限（http/httpsだけ）」の3つで、**開いた先のページの中身は
//!   守らない**。httpも断らない。ドメインの許可の一覧は持たない。
//! - 吹き出しを見ないまま`Ctrl`＋クリックで開けることがある——ボタンを押さない移動を届けない端末（吹き出しが出ない）・
//!   吹き出しが入らないほど狭い枠。開くのは押したセルのリンクのURLに限られる。
//! - Windows以外では開かない（`Err`で理由を返す）。

use harness_tools::HttpUrlError;

use crate::app::AppState;

/// http/httpsだと確かめ、正規化したURL（モジュールdoc）。[`Self::parse`]を通してしか作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenableUrl(String);

impl OpenableUrl {
    /// 書かれたままのリンク先`raw`を確かめる。http/httpsなら正規化した形で返し、それ以外は断る
    /// （`harness_tools::parse_http_url`。断る理由もそのまま返す）。
    pub fn parse(raw: &str) -> Result<Self, HttpUrlError> {
        harness_tools::parse_http_url(raw).map(|url| Self(url.as_str().to_string()))
    }

    /// 正規化した形（吹き出しに出し、ブラウザへ渡す文字列）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 開かない形式のリンクに添える印（吹き出しと、`Ctrl`＋クリックしたときの知らせ）。
pub const REFUSED_MARK: &str = "開けない形式";

/// 開いた結果を画面に出す1行（transcriptの枠の上辺。モジュールdoc「開けたか・開けなかったかを知らせる」）。
/// URLは後ろに置く（入り切らないときは末尾から切られるので、何が起きたかが先に見える）。
pub fn notice(url: &OpenableUrl, result: &Result<(), String>) -> String {
    match result {
        Ok(()) => format!("既定のブラウザへ渡しました: {}", url.as_str()),
        Err(reason) => format!("開けませんでした（{reason}）: {}", url.as_str()),
    }
}

/// 開かない形式のリンクを`Ctrl`＋クリックしたときの知らせ（黙って何もしないと壊れて見える。B-10）。
pub fn refused_notice(raw: &str) -> String {
    format!("{REFUSED_MARK}のリンクは開きません（開くのは http と https だけ）: {raw}")
}

/// `url`を既定のブラウザで開く（`ShellExecuteW`の`open`）。**呼んだスレッドを止め得る**ので、非同期のループからは
/// [`open_and_note`]を使う。
pub fn open(url: &OpenableUrl) -> Result<(), String> {
    #[cfg(windows)]
    {
        open_with(url, imp::shell_execute)
    }
    #[cfg(not(windows))]
    {
        let _ = url;
        Err("この OS ではブラウザを開けません（Windows だけが対応しています）".to_string())
    }
}

/// イベントループが`Action::OpenUrl`を受けたときに呼ぶ。ブロッキング用のスレッドで[`open`]し、結果を状態へ渡す
/// （`AppState::note_opened`）。
pub(crate) async fn open_and_note(app: &mut AppState, url: OpenableUrl) {
    let target = url.clone();
    let result = tokio::task::spawn_blocking(move || open(&target))
        .await
        .unwrap_or_else(|e| Err(format!("開く処理のスレッドが止まりました: {e}")));
    app.note_opened(&url, result);
}

/// [`open`]の本体。`execute`が開く呼び出し（`ShellExecuteW`。戻り値はその戻り値の数）で、試験が差し替える。
/// 渡す直前にもう一度判定を通す（モジュールdoc）。
#[cfg_attr(not(windows), allow(dead_code))] // Windows以外の製品では開かない（試験だけが使う）。
fn open_with(url: &OpenableUrl, execute: impl FnOnce(&str) -> isize) -> Result<(), String> {
    match OpenableUrl::parse(url.as_str()) {
        Ok(again) if again == *url => {}
        Ok(again) => {
            return Err(format!(
                "開く直前の検査で断りました（正規化した形と違います: {}）",
                again.as_str()
            ))
        }
        Err(e) => return Err(format!("開く直前の検査で断りました（{e}）")),
    }
    let code = execute(url.as_str());
    // `ShellExecuteW`は32より大きい値を成功として返し、32以下は失敗の理由の数（Win32のドキュメント）。
    if code > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW: {code}（{}）", shell_failure(code)))
    }
}

/// `ShellExecuteW`が返した失敗の数の意味（Win32のドキュメントの`SE_ERR_*`・`ERROR_*`）。知らない数も空にしない。
#[cfg_attr(not(windows), allow(dead_code))] // Windows以外の製品では開かない（試験だけが使う）。
fn shell_failure(code: isize) -> &'static str {
    match code {
        0 => "メモリかリソースが足りません",
        2 | 3 => "開くアプリが見つかりません",
        5 => "アクセスが拒否されました",
        8 => "メモリが足りません",
        11 => "開くアプリの形式が正しくありません",
        26 => "共有違反が起きました",
        27 => "関連付けが不完全です",
        28..=30 => "DDE のやり取りに失敗しました",
        31 => "http/https を開くアプリが関連付けられていません",
        32 => "必要な DLL が見つかりません",
        _ => "理由の分からない失敗です",
    }
}

#[cfg(windows)]
mod imp {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// `url`を`ShellExecuteW(open)`へ渡し、戻り値の数を返す（モジュールdoc「COMを初期化してから呼ぶ」）。
    pub(super) fn shell_execute(url: &str) -> isize {
        let file: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: 予約の引数は無し。初期化できたら（`S_OK`・`S_FALSE`）下で必ず戻す。
        let com =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        // SAFETY: `file`は末尾にNULを付けたUTF-16で、呼んでいる間生きている。持ち主のウィンドウは無し（コンソールの
        // アプリなので）。引数と作業ディレクトリは渡さない。
        let instance = unsafe {
            ShellExecuteW(
                HWND::default(),
                w!("open"),
                PCWSTR(file.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if com.is_ok() {
            // SAFETY: 上で初期化できたCOMを戻す（同じスレッド・1回ずつ）。
            unsafe { CoUninitialize() };
        }
        instance.0 as isize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// http/httpsだけを、正規化した形で通す。断る形式は`harness-tools`の判定と同じ（ここで一覧を持たない——一覧は
    /// `harness_tools::parse_http_url`の試験が持つ。ここでは代表を通して、借りていることを確かめる）。
    #[test]
    fn only_http_and_https_become_openable_and_are_normalised() {
        assert_eq!(
            OpenableUrl::parse("HTTPS://Example.COM/a b").map(|u| u.as_str().to_string()),
            Ok("https://example.com/a%20b".to_string())
        );
        assert_eq!(
            OpenableUrl::parse("http://e.x").map(|u| u.as_str().to_string()),
            Ok("http://e.x/".to_string())
        );
        for raw in [
            "javascript:alert(1)",
            "file:///C:/x",
            "ms-msdt:id",
            "foo.html",
        ] {
            assert!(OpenableUrl::parse(raw).is_err(), "{raw}");
        }
    }

    /// **開く直前にもう一度検査する**（計画書のT11b「開く直前にも検査する」。B-20）——検査を通らずに作った値
    /// （モジュールの中でしか作れない）は、開く処理を呼ばずに断る。正規化していない形も断る（見せた形と開く形を
    /// 別物にしない）。
    #[test]
    fn opening_checks_again_and_refuses_values_that_skipped_the_check() {
        for forged in [
            "javascript:alert(1)",
            "file:///C:/x",
            "HTTPS://Example.COM/a b",
            "foo.html",
        ] {
            let mut called = false;
            let result = open_with(&OpenableUrl(forged.to_string()), |_| {
                called = true;
                42
            });
            assert!(!called, "{forged}: 検査を通らない値で開く処理を呼んだ");
            let reason = result.expect_err(forged);
            assert!(reason.contains("開く直前の検査"), "{forged}: {reason}");
        }
    }

    /// 許可側の対照: 検査を通った値は、その文字列のまま開く処理へ渡し、`ShellExecuteW`の戻り値が32より大きければ成功。
    /// 32以下は失敗で、数を理由に含める（黙らない。B-10）。
    #[test]
    fn opening_passes_the_normalised_string_and_maps_the_shell_result() {
        let url = OpenableUrl::parse("https://example.com/a").expect("開けるURL");
        let mut passed = String::new();
        let ok = open_with(&url, |s| {
            passed = s.to_string();
            33
        });
        assert_eq!(ok, Ok(()));
        assert_eq!(passed, "https://example.com/a");
        for code in [0, 2, 31, 32] {
            let reason = open_with(&url, |_| code).expect_err("32以下は失敗");
            assert!(
                reason.contains(&format!("ShellExecuteW: {code}")),
                "{code}: {reason}"
            );
            assert!(reason.contains(shell_failure(code)), "{code}: {reason}");
        }
    }

    /// `ShellExecuteW`の失敗の数は、知っているものは意味を添え、知らないものも「分からない」と書く（空にしない）。
    #[test]
    fn shell_failures_are_described() {
        assert!(shell_failure(31).contains("関連付け"));
        assert!(shell_failure(5).contains("アクセス"));
        assert!(!shell_failure(17).is_empty());
    }

    /// 知らせの文面: 成功は「渡した」（ブラウザが表示したかは分からない——`ShellExecuteW`が成功を返すのは既定のアプリへ
    /// 渡せたところまで）、失敗は理由、断ったときは形式の制限。どれもURLを含む。
    #[test]
    fn notices_say_what_happened_and_include_the_url() {
        let url = OpenableUrl::parse("https://e.x/p").expect("開けるURL");
        let done = notice(&url, &Ok(()));
        assert!(
            done.contains("既定のブラウザへ渡しました") && done.contains("https://e.x/p"),
            "{done}"
        );
        let failed = notice(&url, &Err("理由".to_string()));
        assert!(
            failed.contains("開けませんでした（理由）") && failed.contains("https://e.x/p"),
            "{failed}"
        );
        let refused = refused_notice("javascript:x");
        assert!(
            refused.contains(REFUSED_MARK)
                && refused.contains("http")
                && refused.contains("javascript:x"),
            "{refused}"
        );
    }
}
