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
        Tier2aAction::Gc => {
            // preflightの起動時GCと**同じ関数・同じ内訳**を通す（判定を2箇所に書かない）。
            let outcome = session_profile::gc_dead_sessions_reporting(&revoke_session_grant);
            match outcome.summary() {
                // **回収の内訳は必ず出す**（B-11）。とくに「付与内容が台帳から復元できないので
                // 削除を見送った」件数は、放っておくと積もる一方なのに無言だと誰も気付けない。
                Some(summary) => println!("{summary}"),
                None => println!("(no dead Tier2a sessions to reclaim)"),
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
