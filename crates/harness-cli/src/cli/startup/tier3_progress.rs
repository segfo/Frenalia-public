//! 非対話モード（`--print`）でのTier3準備の進捗表示。
//!
//! TUI分岐（`harness_tui::run`内の`sandbox_prep::run_prep_screen`）と対になる実装。

/// 非対話モード（`--print`）専用: Tier3 VMサンドボックスの起動をブロッキングのまま
/// （`tokio::task::spawn_blocking`越しに）待ちつつ、`vmsandboxd_progress`の合成進捗
/// （経過時間ベースの推測、daemonの実測値ではない——`harness_sandbox_vm::vmsandboxd_progress`の
/// モジュールdoc・`plans/DESIGN-SANDBOX-VMISOLATION.md`参照）をstderrへ間引いて出力する。
/// TUI分岐（`harness_tui::run`内の`sandbox_prep::run_prep_screen`）と対になる非対話側の実装。
#[cfg(windows)]
pub(super) async fn start_tier3_with_progress(
    workspace_root: &std::path::Path,
    allow_domains: &[String],
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> Option<std::sync::Arc<harness_sandbox_vm::vmsandboxd::VmSandboxHandle>> {
    use harness_sandbox_vm::vmsandboxd::VmSandboxHandle;
    use harness_sandbox_vm::vmsandboxd_progress::{run_synthetic_ticker, SandboxPrepEvent};

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

    // ラベルが変わった時か、同一フェーズ内でも約5秒おきにのみ1行stderrへ出す
    // （250ms間隔のtickerをそのまま出力すると流れすぎる — cadenceはticker側で
    // 一定に保ち、間引きはこの呼び出し側の責務とする）。
    let mut last_label: Option<String> = None;
    let mut last_printed_secs: u64 = 0;

    let result = loop {
        tokio::select! {
            biased;
            res = &mut start_task => break res,
            Some(ev) = rx.recv() => {
                let secs = ev.elapsed.as_secs();
                let label_changed = last_label.as_deref() != Some(ev.label.as_str());
                if label_changed || secs.saturating_sub(last_printed_secs) >= 5 {
                    eprintln!("[sandbox] {} (経過 {secs}秒)", ev.label);
                    last_label = Some(ev.label.clone());
                    last_printed_secs = secs;
                }
            }
        }
    };
    ticker.abort();

    match result {
        Ok(Ok(handle)) => Some(std::sync::Arc::new(handle)),
        Ok(Err(e)) => {
            eprintln!(
                "error: tier3 was selected but the VM sandbox failed to start: {e}\n\
                 run_shell will fail until this is resolved (see \
                 plans/TIER1A-OPEN-ISSUES.md item 9)."
            );
            None
        }
        Err(join_err) => {
            eprintln!("error: tier3 sandbox prep task panicked: {join_err}");
            None
        }
    }
}
