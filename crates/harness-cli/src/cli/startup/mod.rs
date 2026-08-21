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
/// `/workspace`（`harness_tui::RunOutcome::Relaunch`）の再起動と、その引数の組み立て。
mod relaunch;
mod run_agent;
mod sandbox;
mod session;
mod tier3_progress;

use configure::stage_configure;
use parse_args::stage_parse_args;
use run_agent::stage_run_agent;
use sandbox::stage_prepare_sandbox;
use session::stage_open_session;

/// Tier2a + ドメインポリシー要求下でWFP（Layer2）が立たなかったとき、**どの不成立経路でも
/// 共通で起きる帰結**の説明。`should_grant_tier2a_network_capability`
/// （`crates/harness-tools/src/shell/net_decision.rs`）は`domain_policy_requested &&
/// !enforced_by_wfp`のとき`NetworkCapability::Deny`を返すため、結果はLayer1協調プロキシへの
/// 縮退**ではなく**AppContainer capability自体の不付与＝`run_shell`の子プロセスはソケットを
/// 1つも作れず、協調プロキシへのloopback到達すらできない（fail-closed）。
///
/// **経路ごとに文言を書かず定数へ集約している理由**: 別々に書くと片方だけが実態へ追随し、
/// もう片方が古い説明のまま残る。実際にシナリオ(B)（`NetfilterHandle::start`失敗）だけが
/// 正され、シナリオ(A)（privhelper連鎖起動後のハンドシェイク失敗）は「Layer1協調プロキシが
/// 強制する」という誤った説明のまま取り残されていた。
///
/// **この文字列はE2Eの契約である。** `crates/harness-cli/tests/tier2a_e2e.rs`が2通りに使う——
/// case 07/10は**存在**をfail-closedの証拠にし、`tier2a_smb445_layer2`は**不在**を
/// 「capability拒否分岐を通っていない＝445の拒否はWFPの手柄だ」の証拠にする。全経路が
/// この同一文言を出すことで、後者の不在チェックが拒否経路を漏れなく覆う。
///
/// **拒否が確定していない箇所でこの句を使わないこと**——証拠としての意味が薄れる。
#[cfg(windows)]
pub const TIER2A_NET_DENIED: &str =
    "Tier2a run_shell network capability will remain denied for this session (fail-closed, no \
     outbound sockets at all, not merely unenforced)";

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
