//! 起動パイプライン本体。
//!
//! 「昇格チェック → `.env`読込 → 引数parse → 資格情報不要なサブコマンドの早期dispatch →
//! セッション解決 → provider/model → tools/permissions → セッション永続化 →
//! staging/read_scope/net → シェル隔離Tier選択 → 実行」という線形の流れ。

use std::process::ExitCode;

use super::*;

mod configure;
mod mcp;
mod parse_args;
mod run_agent;
mod sandbox;
mod session;
mod tier3_progress;

use configure::stage_configure;
use parse_args::stage_parse_args;
use run_agent::stage_run_agent;
use sandbox::stage_prepare_sandbox;
use session::stage_open_session;

pub async fn run() -> ExitCode {
    let parsed = match stage_parse_args() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let configured = match stage_configure(parsed) {
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
