//! TUIが画面を握っている間、このプロセスの**標準エラー出力を預かる**。
//!
//! # なぜ要るのか
//!
//! 記録の途中で走るライブラリ側のコードは、警告を`eprintln!`で直接出す。実例が
//! `harness_sandbox::elevated_launch::verify_elevation_target`のD-44警告で、
//! `target\debug`は必ずユーザー書込可なので**開発機では毎回出る**。TUIは同じ端末を
//! 使っているため、この書込はフレームの上に重なって表示を壊す（実際に壊れた）。
//!
//! 出どころは1箇所ではない（privhelper・netfilterd・収集器クライアントもそれぞれ警告を出す）
//! ので、呼び出し側を1つずつ直すのではなく**端末とライブラリの間で受け止める**。
//!
//! # 握り潰さない
//!
//! 預かった内容は進行ログへ流す。さらに[`Drop`]では、**まだ読んでいない分を本物の標準エラーへ
//! 書き戻してから**終わる——panicのメッセージもここを通るので、書き戻さないと
//! 「TUIが落ちたのに理由がどこにも無い」状態になる（B-10）。
//!
//! # 標準出力は預からない
//!
//! ratatuiの描画そのものが`io::stdout()`である。同じことをすると画面が消える。
//!
//! # 置き場
//!
//! `<workspace>/.harness/sandbox/`（P-08の制御ディレクトリ側）。`%TEMP%`はこのマシンでは
//! サンドボックスアカウントからも書けるので、そこへ置くと第三者が進行ログへ行を混ぜられる
//! （表示だけの話ではあるが、置き場を選べるなら弱い方を選ばない）。

use std::path::{Path, PathBuf};

use crate::audit_tail::AuditTail;

/// stderrの預かり。`start`で差し替え、`Drop`で必ず戻す。
pub struct StderrCapture {
    inner: Option<Inner>,
}

struct Inner {
    /// 差し替える前のハンドル。戻すために持つ。
    original: windows::Win32::Foundation::HANDLE,
    /// 書き込み先。**落とすとハンドルが閉じる**ので、差し替えている間は持ち続ける。
    _sink: std::fs::File,
    tail: AuditTail,
    path: PathBuf,
}

impl StderrCapture {
    /// 差し替えを試みる。**失敗しても止めない**——預かれないだけで、TUIは動く
    /// （表示が壊れる可能性が残るが、起動できないよりはよい）。
    pub fn start(workspace_root: &Path) -> Self {
        Self {
            inner: Inner::start(workspace_root),
        }
    }

    /// 前回以降に書かれた行を引き取る。
    pub fn poll(&mut self) -> Vec<String> {
        match self.inner.as_mut() {
            Some(inner) => inner.tail.poll(),
            None => Vec::new(),
        }
    }
}

impl Inner {
    fn start(workspace_root: &Path) -> Option<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE};

        let dir = crate::session_dir::sandbox_root(workspace_root);
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(format!(
            "policy-editor-tui-stderr-{}.log",
            std::process::id()
        ));
        let sink = std::fs::File::create(&path).ok()?;

        // 差し替える前のハンドルを先に取る（取れないなら戻せないので差し替えない）。
        let original = unsafe { GetStdHandle(STD_ERROR_HANDLE) }.ok()?;
        let replacement = HANDLE(sink.as_raw_handle());
        unsafe { SetStdHandle(STD_ERROR_HANDLE, replacement) }.ok()?;

        Some(Self {
            original,
            _sink: sink,
            tail: AuditTail::new(&path),
            path,
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

        // **先に戻す。** この後の`eprintln!`が本物の端末へ出る必要がある。
        let _ = unsafe { SetStdHandle(STD_ERROR_HANDLE, self.original) };
        for line in self.tail.poll() {
            eprintln!("{line}");
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// **差し替えを行うテストはこの1本だけにする**こと。他のテストのstderrがこの窓の間だけ
    /// 預かり先へ入るのは避けられないが、`contains`で見る限り害は無い（読み残しはDropが
    /// 本物のstderrへ書き戻す）。
    #[test]
    fn redirected_stderr_is_captured_written_back_and_restored() {
        use std::io::Write;

        let ws = tempfile::tempdir().expect("tempdir");
        let path;
        {
            let mut capture = StderrCapture::start(ws.path());
            path = capture
                .inner
                .as_ref()
                .expect("差し替えられなければ、TUIの表示は壊れたままになる")
                .path
                .clone();

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
}
