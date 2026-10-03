//! TUIが画面を握っている間、このプロセスの**標準エラー出力を預かる**（会話TUIとポリシーエディタが共有）。
//!
//! # なぜ要るのか
//!
//! TUIが動いている最中に走るライブラリ側のコードは、警告を`eprintln!`で直接出す。TUIは同じ端末を
//! 使っているため、この書込はフレームの上に重なって表示を壊す。ratatuiは自分が描いた内容しか
//! 覚えていないので、**横から書き込まれた文字は消されずに残る**。実例は2つ:
//! ポリシーエディタでは`harness_sandbox::elevated_launch::verify_elevation_target`のD-44警告
//! （`target\debug`は必ずユーザー書込可なので開発機では毎回出る）、会話TUIでは`run_shell`の
//! Tier1が作業フォルダへ低ILラベルを付けられなかったときの警告（[BUG-206]）。
//!
//! 出どころは1箇所ではない（数えた件数はBUG-206が持つ。件数はここへ写さない——増え続けるので古くなる）。
//! 呼び出し側を1つずつ直すのではなく**端末とライブラリの間で受け止める**。
//! 差し替えはプロセスの標準エラーのハンドルそのものなので、**差し替えた後に起こした子プロセス**で、
//! 標準エラーを継承するもの（`Stdio::inherit`）の出力も同じ預かり先へ入る。
//!
//! # 握り潰さない
//!
//! 預かった内容は呼び出し側が[`StderrCapture::poll`]で引き取って画面の中に出す（[`shown`]の形で）。
//! さらに`Drop`では、**まだ読んでいない分を本物の標準エラーへ書き戻してから**終わる——panicの
//! メッセージもここを通るので、書き戻さないと「TUIが落ちたのに理由がどこにも無い」状態になる（B-10）。
//! 改行で終わっていない最後の断片も書き戻す（[`crate::line_tail::LineTail::drain`]）。
//!
//! 預かりを始められなかったときも黙らない——理由を[`StderrCapture::start_error`]で返すので、
//! 呼び出し側は「画面が崩れることがある」と1度だけ画面に出す。
//!
//! # 端末より先に預かり、端末を返した後に戻す
//!
//! **[`crate::TerminalGuard`]より先に作る**こと（Rustは宣言の逆順にdropするので、後に戻ることになる）。
//! 逆にすると、`Drop`の書き戻しがまだオルタネートスクリーンの上に出て、端末を返した瞬間に消える
//! ——panicの理由や、ループを抜けた後に走る撤収の警告が、書き戻したのに読めない。
//!
//! # 守らないもの
//!
//! - **差し替える前に起こした子プロセス**は、元の端末のハンドルを持ったままである。
//!   いまの`harness.exe`でTUIより前に起こして生かしておく子は、どれも端末へ書かない形で起こしている
//!   ——Spawn Daemonはコンソールを持たせず（`DETACHED_PROCESS`）、昇格ヘルパーは`runas`で起こすので
//!   ハンドルを継承せず、MCPサーバは標準エラーをパイプで受けている。この形が崩れたら、ここは効かない。
//! - **標準出力は預からない**。ratatuiの描画そのものが`io::stdout()`なので、同じことをすると画面が消える。
//! - **Windows以外では預からない**（[`StderrCapture::start_error`]がそう言う）。
//!
//! # 置き場
//!
//! 呼び出し側が渡す。どちらのTUIもワークスペースの`.harness/`の下（P-08の制御ディレクトリ側）を
//! 渡している。`%TEMP%`はこのマシンではサンドボックスアカウントからも書けるので、そこへ置くと
//! 第三者が画面へ行を混ぜられる（表示だけの話ではあるが、置き場を選べるなら弱い方を選ばない）。
//!
//! [BUG-206]: ../../../docs/bugs/BUG-206.md

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use crate::line_tail::LineTail;

/// 預かった1行を画面に出すときの形。**2つのTUIで同じ綴りにする**（片方だけ印が違うと、
/// 同じ警告が画面によって別物に見える）。
pub fn shown(line: &str) -> String {
    format!("[stderr] {line}")
}

/// 預かりを始められなかったことを画面に出す1行（2つのTUIで同じ文面）。
///
/// 次に何が起きるか（画面に文字が残る）と、そうなったら何をすればよいか（端末の大きさを変える）を言う
/// ——ratatuiは端末の大きさが変わると画面を全部消して描き直す（`Terminal::resize`が`clear`を呼ぶ）。
pub fn start_failure_notice(reason: &str) -> String {
    format!(
        "[stderr] could not capture the standard error output ({reason}). Warnings written there \
         may be drawn over this screen and stay as broken characters; resize the terminal window \
         to redraw it."
    )
}

/// stderrの預かり。[`StderrCapture::start`]で差し替え、`Drop`で必ず戻す。
pub struct StderrCapture {
    /// 預かれなかったときは、その理由（`Err`）。
    #[cfg(windows)]
    inner: Result<Inner, String>,
}

#[cfg(windows)]
struct Inner {
    /// 差し替える前のハンドル。戻すために持つ。
    original: windows::Win32::Foundation::HANDLE,
    /// 書き込み先。**落とすとハンドルが閉じる**ので、差し替えている間は持ち続ける。
    _sink: std::fs::File,
    tail: LineTail,
    path: PathBuf,
}

impl StderrCapture {
    /// `dir`の下に`<name>-<プロセスID>.log`を作り、標準エラーをそこへ向ける。
    ///
    /// **失敗しても止めない**——預かれないだけで、TUIは動く（表示が壊れる可能性が残るが、
    /// 起動できないよりはよい）。理由は[`Self::start_error`]で引ける。
    pub fn start(dir: &Path, name: &str) -> Self {
        #[cfg(windows)]
        {
            Self {
                inner: Inner::start(dir, name),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (dir, name);
            Self {}
        }
    }

    /// 預かりを始められなかった理由。預かっているなら`None`。
    pub fn start_error(&self) -> Option<&str> {
        #[cfg(windows)]
        {
            self.inner.as_ref().err().map(String::as_str)
        }
        #[cfg(not(windows))]
        {
            Some(
                "not implemented on this OS (only the Windows build redirects the standard error \
                 handle)",
            )
        }
    }

    /// 前回以降に書かれた行を引き取る。
    pub fn poll(&mut self) -> Vec<String> {
        #[cfg(windows)]
        {
            match self.inner.as_mut() {
                Ok(inner) => inner.tail.poll(),
                Err(_) => Vec::new(),
            }
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }
}

#[cfg(windows)]
impl Inner {
    fn start(dir: &Path, name: &str) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE};

        std::fs::create_dir_all(dir)
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
        let path = dir.join(format!("{name}-{}.log", std::process::id()));
        let sink = std::fs::File::create(&path)
            .map_err(|e| format!("could not create {}: {e}", path.display()))?;

        // 差し替える前のハンドルを先に取る（取れないなら戻せないので差し替えない）。
        let original = match unsafe { GetStdHandle(STD_ERROR_HANDLE) } {
            Ok(handle) => handle,
            Err(e) => {
                drop(sink);
                let _ = std::fs::remove_file(&path);
                return Err(format!("GetStdHandle(STD_ERROR_HANDLE) failed: {e}"));
            }
        };
        let replacement = HANDLE(sink.as_raw_handle());
        if let Err(e) = unsafe { SetStdHandle(STD_ERROR_HANDLE, replacement) } {
            drop(sink);
            let _ = std::fs::remove_file(&path);
            return Err(format!("SetStdHandle(STD_ERROR_HANDLE) failed: {e}"));
        }

        Ok(Self {
            original,
            _sink: sink,
            tail: LineTail::new(&path),
            path,
        })
    }
}

#[cfg(windows)]
impl Drop for Inner {
    fn drop(&mut self) {
        use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

        // **先に戻す。** この後の`eprintln!`が本物の端末へ出る必要がある。
        let _ = unsafe { SetStdHandle(STD_ERROR_HANDLE, self.original) };
        for line in self.tail.drain() {
            eprintln!("{line}");
        }
        // 消せなかったら言う——ワークスペースの`.harness/`に残るので、黙ると起動のたびに積もる（B-10）。
        // 差し替えた後に起こした子がまだ握っていても、共有削除で開いているので消える（閉じた時点で実体が消える）。
        if let Err(e) = std::fs::remove_file(&self.path) {
            eprintln!(
                "note: could not remove the captured standard error file {}: {e}",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 画面に出す形は2つのTUIで同じ（印で「誰が言ったか」が分かる）。
    #[test]
    fn a_captured_line_is_shown_with_the_stderr_mark() {
        assert_eq!(shown("warning: x"), "[stderr] warning: x");
    }

    /// **標準エラーへの書込が差し替え先へ行くことを実測で確かめる**（B-29）。Rustの標準
    /// ライブラリが書込のたびに`GetStdHandle`を引き直すかどうかは実装依存で、引き直さないなら
    /// `SetStdHandle`は効かない——効かなければ画面は壊れたままなので、この1点が仕組みの全部である。
    ///
    /// **`eprintln!`では測れない。** libtestは`std::io::set_output_capture`でマクロの出力先を
    /// 横取りするため、テストの中では`eprintln!`はOSハンドルまで届かない（最初にこれで
    /// 空振りした）。マクロと`stderr().write_all`は最終的に同じ`Stderr::write`——つまり
    /// `GetStdHandle`を引く同じ経路——へ落ちるので、横取りの無い側で測る。本番（libtestが
    /// 居ない普通のプロセス）ではマクロもこの経路を通る。
    ///
    /// **注意**: 差し替えはプロセス全体に効く。cargoはテストをスレッドで並列実行するので、
    /// 差し替えるテストが2本あると互いの差し替えを踏み合う（実際に踏んだ——2本に分けていた
    /// ときは、片方のDropがもう片方の書込中にハンドルを戻して不定期に落ちた）。
    /// **差し替えを行うテストはこのテストバイナリでこの1本だけにする**こと。他のテストのstderrが
    /// この窓の間だけ預かり先へ入るのは避けられないが、`contains`で見る限り害は無い（読み残しは
    /// Dropが本物のstderrへ書き戻す）。
    #[cfg(windows)]
    #[test]
    fn redirected_stderr_is_captured_written_back_and_restored() {
        use std::io::Write;

        let ws = tempfile::tempdir().expect("tempdir");
        let path;
        {
            let mut capture = StderrCapture::start(ws.path(), "harness-term-test-stderr");
            assert_eq!(capture.start_error(), None, "預かりを始められること");
            path = capture
                .inner
                .as_ref()
                .expect("差し替えられなければ、TUIの表示は壊れたままになる")
                .path
                .clone();
            assert!(
                path.starts_with(ws.path()),
                "呼び出し側が渡した置き場に作る: {}",
                path.display()
            );

            let _ = std::io::stderr().write_all(b"captured-warning-line\n");
            let lines = capture.poll();
            assert!(
                lines.iter().any(|l| l.contains("captured-warning-line")),
                "標準エラーへの書込が預かり先へ届いていない: {lines:?}"
            );

            // 読まないまま終わる分（panicのメッセージがこれにあたる）はDropが拾う。
            let _ = std::io::stderr().write_all(b"unread-line\n");
            assert!(
                std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .contains("unread-line"),
                "預かりファイルに残っている前提"
            );
        }
        assert!(
            !path.exists(),
            "預かり用のファイルは終了時に片付ける: {}",
            path.display()
        );
    }

    /// 下の試験が自分自身を子プロセスとして起こし直すときに渡す、預かり先のディレクトリ。
    /// **試験専用なので`HARNESS_TEST_`で始める**（D-86。`harness-cli`の`env_var_naming`が見張る）。
    #[cfg(windows)]
    const PROBE_CHILD_DIR_ENV: &str = "HARNESS_TEST_STDERR_CAPTURE_PROBE_DIR";

    /// [`writes_never_reach_the_original_stderr_while_captured`]の子プロセス側。
    ///
    /// **普段の`cargo test`では何もしない**（環境変数が無ければすぐ戻る。差し替えを行うテストを
    /// このバイナリで1本に保つため）。親が`--exact`でこの1本だけを`--nocapture`付きで起こしたときにだけ、
    /// 本番と同じ形（libtestの横取りが無い`eprintln!`と、標準エラーを継承する孫プロセス）で書く。
    #[cfg(windows)]
    #[test]
    fn probe_child_writes_while_captured() {
        let Ok(dir) = std::env::var(PROBE_CHILD_DIR_ENV) else {
            return;
        };
        let mut capture = StderrCapture::start(Path::new(&dir), "probe");
        assert_eq!(capture.start_error(), None);
        eprintln!("from-eprintln-macro");
        let status = std::process::Command::new("cmd")
            .args(["/d", "/c", "echo from-grandchild>&2"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .expect("run cmd");
        assert!(status.success());
        for line in capture.poll() {
            println!("POLLED:{line}");
        }
        eprintln!("unread-at-exit");
        drop(capture);
        eprintln!("after-restore");
    }

    /// **[BUG-206]の本体: 預かっている間は、元の標準エラー（＝端末）へ1バイトも届かない。**
    ///
    /// 上の試験はlibtestの中で`write_all`を使って測っているが、本番で画面を崩したのは`eprintln!`と、
    /// 標準エラーを継承する子プロセスである。テストの中の`eprintln!`はlibtestに横取りされるので、
    /// 自分自身を子プロセスとして`--nocapture`で起こし直し、子の標準エラー（＝子にとっての端末）を
    /// パイプで受けて、**何が届いて何が届かなかったか**を外から測る。
    ///
    /// 対で見る: 預かった間の2行は「端末に届かない」かつ「預かり先から引き取れる」、
    /// 読み残しと戻した後の行は「端末に届く」（握り潰さない）。
    #[cfg(windows)]
    #[test]
    fn writes_never_reach_the_original_stderr_while_captured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "stderr_capture::tests::probe_child_writes_while_captured",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROBE_CHILD_DIR_ENV, dir.path())
            .output()
            .expect("re-run this test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let both = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
        assert!(out.status.success(), "子の試験が落ちた:\n{both}");

        assert!(
            stdout.contains("POLLED:from-eprintln-macro"),
            "`eprintln!`が預かり先から引き取れない:\n{both}"
        );
        assert!(
            stdout.contains("POLLED:from-grandchild"),
            "標準エラーを継承した孫の出力が預かり先から引き取れない:\n{both}"
        );
        assert!(
            !stderr.contains("from-eprintln-macro") && !stderr.contains("from-grandchild"),
            "預かっている間に書いた行が元の標準エラー（端末）へ届いた——画面が崩れる:\n{both}"
        );
        assert!(
            stderr.contains("unread-at-exit"),
            "読み残しが元の標準エラーへ書き戻されていない（握り潰し）:\n{both}"
        );
        assert!(
            stderr.contains("after-restore"),
            "戻した後の書込が元の標準エラーへ届かない:\n{both}"
        );
    }

    /// 置き場を作れなければ**差し替えずに**理由を返す（ハンドルには触らないので、並列のテストを踏まない）。
    #[cfg(windows)]
    #[test]
    fn a_capture_that_cannot_start_says_why_instead_of_staying_silent() {
        let ws = tempfile::tempdir().expect("tempdir");
        // ディレクトリを作るはずの場所にファイルを置いておく。
        let blocked = ws.path().join("not-a-directory");
        std::fs::write(&blocked, b"").expect("write");

        let mut capture = StderrCapture::start(&blocked, "harness-term-test-stderr");
        let reason = capture.start_error().expect("始められなかった理由を返す");
        assert!(
            reason.contains("not-a-directory"),
            "理由にはどこで失敗したかが入る: {reason}"
        );
        assert!(capture.poll().is_empty());
    }
}
