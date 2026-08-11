//! `harness fs`の撤収コマンドが共有する進捗表示。
//!
//! [BUG-082フォローアップ]で`fs revoke-workspace`に入れたものを、[BUG-101]の修正で
//! `fs revoke`/`revoke-all`からも使えるようにここへ移した。**対になる操作の片方にだけ
//! UIが在る状態を作らない**（`docs/CODE-STRUCTURE-RULES.md` §5.1）——撤収はツリー全walkで、
//! 対象が`%TEMP%`や`.cargo`だと数千〜数万ノードになる。無反応のまま待たせると
//! ユーザーは止まったと判断する（B-23(a)）。

use std::io::Write;

/// 止めるまで`stderr`へスピナー（TUIと同じ点字フレーム、`harness-tui`の`SPINNER_FRAMES`と
/// 同一）を1行で回し続けるバックグラウンドスレッド。
///
/// 撤収はSID解決や`collect_dirs_and_files`（対象数が定まるまで進捗を出せないディレクトリ
/// 走査）の間、無反応に見える区間を持つ——ユーザーからの実機報告（コマンド実行後、最初の
/// 1行が出るまで長く待たされる）を受けて追加した。`Drop`でスレッドを止め、行を空白で
/// 上書きしてから`\r`だけ残す（次の出力がスピナーの残骸と混ざらないように）。
pub(crate) struct Spinner {
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    pub(crate) fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_thread = std::sync::Arc::clone(&running);
        let handle = std::thread::spawn(move || {
            const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let mut i = 0usize;
            while running_thread.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!("\r{} {label}", FRAMES[i % FRAMES.len()]);
                let _ = std::io::stderr().flush();
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });
        Self {
            running,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // 直前のスピナー行を空白で上書きしてから復帰する。次にこの行へ書く側
        // （数値進捗・完了メッセージ）がスピナーの残骸を引きずらないようにするため。
        eprint!("\r{}\r", " ".repeat(120));
        let _ = std::io::stderr().flush();
    }
}

/// 「対象数が定まるまではスピナー、定まったら同じ行を数値進捗で上書きする」進捗表示。
///
/// `revoke_sids_recursive`/`revoke_workspace_sids_recursive`はどちらも、walkが終わって
/// 総数が確定した時点で1回`(0, total)`を呼ぶ約束になっている。その最初の1回でスピナーを
/// 止める（`RefCell`は進捗コールバックが`&dyn Fn`のため——このプロセスはシングルスレッドで
/// 呼ぶので`Mutex`は要らない）。
pub(crate) struct WalkProgress {
    spinner: std::cell::RefCell<Option<Spinner>>,
    label: String,
    last: std::cell::Cell<usize>,
}

impl WalkProgress {
    pub(crate) fn start(scan_label: &str, label: impl Into<String>) -> Self {
        Self {
            spinner: std::cell::RefCell::new(Some(Spinner::start(scan_label.to_string()))),
            label: label.into(),
            last: std::cell::Cell::new(0),
        }
    }

    /// `revoke_*_recursive`へ渡すコールバック。
    pub(crate) fn on_progress(&self, done: usize, total: usize) {
        drop(self.spinner.borrow_mut().take());
        self.last.set(done);
        let percent = (done.min(total) * 100).checked_div(total).unwrap_or(0);
        eprint!(
            "\r{}: {done}/{total} node(s) checked ({percent}%)   ",
            self.label
        );
        let _ = std::io::stderr().flush();
    }

    /// 最後に報告した処理済みノード数（部分完了の報告に使う）。
    pub(crate) fn last_reported(&self) -> usize {
        self.last.get()
    }

    /// 進捗行を畳んで、以後の出力が同じ行を汚さないようにする。
    pub(crate) fn finish(self) {
        drop(self.spinner.into_inner());
        eprintln!();
    }
}
