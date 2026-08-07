//! [BUG-082フォローアップ] ツール呼び出しが実際の処理へ入る前に無反応へ見える理由の集約。
//!
//! `harness-engine`のツール実行ループは、ツール呼び出しが返るまでの間これを定期的に
//! ポーリングし、`Some`が返ったら`AgentEvent::ToolProgress`としてツールカードへ流す
//! （`crates/harness-engine/src/turn/mod.rs`の`dispatch_one`）。**呼び出し側はどの背景条件が
//! 存在するかを一切知らない**——新しい待機理由（例: 昇格ヘルパーの起動待ち）が増えたら、
//! ここへ`WaitReason`実装を1つ足すだけでよく、`harness-engine`側の変更は要らない
//! （`docs/CODE-STRUCTURE-RULES.md`規則5、`harness_core::tool::WaitReason`のdoc参照）。

use harness_core::tool::WaitReasons;

/// 現在登録されている全ての待機要因源。
#[cfg(windows)]
pub fn known_wait_reasons() -> WaitReasons {
    WaitReasons::new(vec![std::sync::Arc::new(
        harness_sandbox::tier2a::win_appcontainer::grant_job::WorkspaceAclWaitReason,
    )])
}

/// D-54のworkspace ACL背景ジョブはWindows専用（`win_appcontainer`モジュール自体が
/// `#[cfg(windows)]`）のため、他OSでは既知の待機理由が無い。
#[cfg(not(windows))]
pub fn known_wait_reasons() -> WaitReasons {
    WaitReasons::default()
}
