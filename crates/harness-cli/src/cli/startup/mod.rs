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
mod parse_args;
/// `/workspace`（`harness_tui::RunOutcome::Relaunch`）の再起動と、その引数の組み立て。
mod relaunch;
mod run_agent;
mod sandbox;
mod session;
mod tier3_progress;
/// [段階6e] 遷移MACについてモデルへ何を見せるかの判定（§19.3.8）。**windows専用にしない**
/// ——判定も一覧の組み立ても純粋で、**昇格もWin32も無しに単体テストできることが要**である。
mod transition_tool;
/// WFP（Layer2出口強制）の経路選択と、立たなかったときの説明文。
#[cfg(windows)]
mod wfp_outcome;

use configure::stage_configure;
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
