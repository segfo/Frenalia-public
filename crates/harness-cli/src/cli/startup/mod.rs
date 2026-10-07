//! 起動パイプライン本体。
//!
//! 「昇格チェック → `.env`読込 → 引数parse → 資格情報不要なサブコマンドの早期dispatch →
//! セッション解決 → provider/model → tools/permissions → セッション永続化 →
//! staging/read_scope/net → シェル隔離Tier選択 → 実行」という線形の流れ。

use std::process::ExitCode;

use super::*;

mod configure;
/// `.env`の読み込み。**リポジトリ同梱の`.env`は読まない**（BUG-115）。
mod dotenv;
mod mcp;
/// [決定69(1)(4)] Tier2a の入口のシェルが使える通信の宛先をどこから取るか（`policy.json`の承認済みの宣言＋
/// `--net-allow-domain`）。起動（`sandbox`）と`harness prompt`（`workspace_cmd`）が同じこれを通る。
mod net_sources;
mod parse_args;
/// [#30] `policy.json`のファイル宣言から付ける許可を決め、付いた結果を宣言の一覧ごとに振り分ける。
/// **windows専用にしない**——決める部分も振り分ける部分も純粋で、単体テストできることが要である。
/// `/workspace`（`harness_tui::RunOutcome::Relaunch`）の再起動と、その引数の組み立て。
mod relaunch;
mod run_agent;
mod sandbox;
mod session;
mod tier3_progress;
/// [段階6e] 遷移MACについてモデルへ何を見せるかの判定（§19.3.8）。**windows専用にしない**
/// ——判定も一覧の組み立ても純粋で、**昇格もWin32も無しに単体テストできることが要**である。
mod transition_tool;
/// [#55] 遷移先ドメインの用意とSpawn Daemonの起動（`run_agent.rs`から移した。P7.1）。**順序が本質**で、
/// 用意とDaemonの起動の間にドメインごとの中継プロキシとWFPの適用が入る（同モジュールのdoc）。
#[cfg(windows)]
mod transitions;
/// WFP（Layer2出口強制）の経路選択と、立たなかったときの説明文。
#[cfg(windows)]
mod wfp_outcome;

use configure::stage_configure;
/// [決定69(1)] `harness prompt`（下見）が、起動と**同じ関数**で入口の通信の宛先を組むための口。
pub(crate) use net_sources::entry_destinations_from_workspace;
use parse_args::stage_parse_args;
use run_agent::stage_run_agent;
use sandbox::stage_prepare_sandbox;
use session::stage_open_session;
#[cfg(windows)]
// `TIER2A_NET_DENIED`自体はここへは持ち込まない——文言の組み立ては`WfpUnavailable::warning`
// だけが行い、呼び出し側は組み立て済みの1行を出すだけ、という分担を壊さないため。
use wfp_outcome::{plan_wfp, WfpPlan, WfpUnavailable};

pub async fn run() -> ExitCode {
    let parsed = match stage_parse_args() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let configured = match stage_configure(parsed).await {
        Ok(c) => c,
        Err(code) => return code,
    };
    let session_opened = match stage_open_session(configured) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let sandbox_prepared = match stage_prepare_sandbox(session_opened) {
        Ok(s) => s,
        Err(code) => return code,
    };
    stage_run_agent(sandbox_prepared).await
}
