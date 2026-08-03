//! Tier3 VMサンドボックスの起動待ち画面。`picker.rs`と同じ流儀で、呼び出し側が既に
//! `TerminalGuard::enter()`済みの`term`/`term_events`を借りて描画する。
//!
//! ここで表示する進捗は`harness_sandbox::tier3::vmsandboxd_progress`が生成する**経過時間ベースの
//! 合成データ**であり、daemon（`vmsandboxd`）の実測値ではない（同モジュールのdoc参照）。

use std::io::{self, Stdout};
use std::path::Path;
use std::sync::Arc;

use crossterm::event::EventStream;
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use harness_sandbox::tier3::vmsandboxd::VmSandboxHandle;
use harness_sandbox::tier3::vmsandboxd_progress::{run_synthetic_ticker, SandboxPrepEvent};

/// `term`/`term_events`は呼び出し側が既に`TerminalGuard::enter`済みであることを前提とする
/// （`picker::run_picker`と同じ契約）。戻り値`None`はVM起動失敗（呼び出し側は既存の警告文言
/// を出し、Tier3無しで処理を継続する現行方針を維持する）。
pub async fn run_prep_screen(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    term_events: &mut EventStream,
    workspace_root: &Path,
    allow_domains: &[String],
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> io::Result<Option<Arc<VmSandboxHandle>>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SandboxPrepEvent>();
    let ticker = tokio::spawn(run_synthetic_ticker(tx, tier3_warm));

    let workspace_root = workspace_root.to_path_buf();
    let allow_domains = allow_domains.to_vec();
    let start_task = tokio::task::spawn_blocking(move || {
        VmSandboxHandle::start(
            &workspace_root,
            &allow_domains,
            tier3_warm,
            tier3_max_sessions,
        )
    });
    tokio::pin!(start_task);

    let mut latest: Option<SandboxPrepEvent> = None;
    term.draw(|f| crate::ui::render_prep_screen(f, latest.as_ref(), tier3_warm))?;

    let result = loop {
        tokio::select! {
            biased;
            res = &mut start_task => break res,
            Some(ev) = rx.recv() => {
                latest = Some(ev);
                term.draw(|f| crate::ui::render_prep_screen(f, latest.as_ref(), tier3_warm))?;
            }
            // 準備待ち中も端末イベント（主にリサイズ）を読み捨てて詰まらせない。キー入力は
            // daemon側にキャンセルAPIが無いため本ラウンドでは受け付けない（既存挙動同様、
            // 完了/失敗を待つのみ）。
            _ = term_events.next() => {}
        }
    };
    ticker.abort();

    match result {
        Ok(Ok(handle)) => Ok(Some(Arc::new(handle))),
        Ok(Err(e)) => {
            eprintln!(
                "error: tier3 was selected but the VM sandbox failed to start: {e}\n\
                 run_shell will fail until this is resolved (see \
                 plans/TIER1A-OPEN-ISSUES.md item 9)."
            );
            Ok(None)
        }
        Err(join_err) => {
            eprintln!("error: tier3 sandbox prep task panicked: {join_err}");
            Ok(None)
        }
    }
}
