//! `harness tier2a`サブコマンド（`plans/DESIGN-CLI-OPTIONS.md` §3.3・§4.9 対象1）。
//! 死んだセッションが残したAppContainerプロファイルの回収と、生存判定の内訳表示。
//!
//! **機構は元から在って、口だけが無かった。** 回収（[`gc_dead_sessions_reporting`]）は
//! preflightの中でしか走らず、生存プローブの内訳（[`live_probe_report`]）はprivhelper側
//! からしか出せなかった——つまり**新しいharnessを起動しない限り回収も診断もできない**。
//! Tier3には`harness tier3 gc`があるので、対称になるようこちらにも置く。
//!
//! [`gc_dead_sessions_reporting`]: harness_sandbox::tier2a::session_profile::gc_dead_sessions_reporting
//! [`live_probe_report`]: harness_sandbox::tier2a::session_profile::live_probe_report

use super::*;

/// `harness tier2a`の各操作。Windows専用機構（AppContainer）のため、Windows以外では
/// エラーで終了する（`harness tier3`・`harness fs`と同じ扱い）。
#[cfg(windows)]
pub(crate) fn run_tier2a_subcommand(action: Tier2aAction) -> ExitCode {
    use harness_sandbox::tier2a::session_profile;
    use harness_sandbox::tier2a::win_appcontainer::revoke_session_grant;

    match action {
        Tier2aAction::NativePathSupport => {
            use harness_sandbox::tier2a::win_appcontainer::probe_native_path_policy;
            let probe = probe_native_path_policy();
            println!("windows_build={:?}", probe.windows_build);
            println!("verdict={:?}", probe.verdict);
            println!("create_export_present={}", probe.create_export_present);
            println!("query_export_present={}", probe.query_export_present);
            println!("query_succeeded={}", probe.query_succeeded);
            println!("sandbox_capabilities={:?}", probe.sandbox_capabilities);
            println!("psec_exports_complete={}", probe.psec_exports_complete);
            println!("detail={}", probe.detail);
            println!(
                "production_eligible=false (experimental API; RO/RW, child process, stdio, Job, WFP, .harness denial, and host-DACL invariance E2E are still required)"
            );
            ExitCode::SUCCESS
        }
        Tier2aAction::Gc => {
            // preflightの起動時GCと**同じ関数・同じ内訳**を通す（判定を2箇所に書かない）。
            let outcome = session_profile::gc_dead_sessions_reporting(&revoke_session_grant);
            match outcome.summary() {
                // **回収の内訳は必ず出す**（B-11）。とくに「付与内容が台帳から復元できないので
                // 削除を見送った」件数は、放っておくと積もる一方なのに無言だと誰も気付けない。
                Some(summary) => println!("{summary}"),
                None => println!("(no dead Tier2a sessions to reclaim)"),
            }
            // CoW差分層に残った引退した身分のACEも同じ口で剥がす（残課題#35）。**セッション台帳を
            // 索引にする上の回収では届かない**——差分層は台帳の`granted_paths`に載らないので、
            // 見に行く経路がここにしか無い。自動側の配線は`harness-cli`の起動経路にある
            // （`sweep_stale_aces_on_cow_diff_areas`。なぜ`preflight`ではないかは同関数のdoc）。
            let sweep = harness_sandbox::tier2a::win_appcontainer::sweep_diff_layer_aces();
            match sweep.summary() {
                Some(summary) => println!("{summary}"),
                None => println!(
                    "(examined {} copy-on-write diff area(s), skipped {} still running; no stale \
                     AppContainer ACEs found)",
                    sweep.examined, sweep.skipped_live
                ),
            }
            ExitCode::SUCCESS
        }
        Tier2aAction::List => {
            // 件数だけでは「0件」の意味が2つに割れる（本当に走っていない／材料が見えていない）。
            // `live_probe_report`は段ごとの内訳をそのまま持っているので、加工せずに出す。
            println!("{}", session_profile::live_probe_report());
            ExitCode::SUCCESS
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn run_tier2a_subcommand(_action: Tier2aAction) -> ExitCode {
    eprintln!("error: Tier2a (AppContainer isolation) is Windows-only");
    ExitCode::FAILURE
}
