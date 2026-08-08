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
///
/// **消費者は2経路ある**。(1) `harness-engine`のツール実行ループ（ツールカードへ
/// `AgentEvent::ToolProgress`を流す、`turn/mod.rs`）と、(2) TUIのステータスバー
/// （`harness-tui`の描画tick）。**どちらも同じこの関数を通す**——以前(2)は
/// `grant_job::progress()`を直接読んでおり、具象が上位層へ漏れ上がったうえに
/// 「終わっていたら出さない」判定が二重実装になっていた（`refactor-perspectives` R-01）。
///
/// レジストリは`OnceLock`で1回だけ組む。TUIの描画tickは**33ms**なので、呼ばれるたびに
/// `Vec`と`Arc`を組み直すのは無駄（`WaitReasons`は`Arc`の浅いcloneで安価）。登録される
/// 源は全てステートレス（実状態は`grant_job`側のグローバルにある）ので、使い回して問題ない。
fn registry() -> &'static WaitReasons {
    static REGISTRY: std::sync::OnceLock<WaitReasons> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(build_wait_reasons)
}

pub fn known_wait_reasons() -> WaitReasons {
    registry().clone()
}

#[cfg(windows)]
fn build_wait_reasons() -> WaitReasons {
    WaitReasons::new(vec![std::sync::Arc::new(
        harness_sandbox::tier2a::win_appcontainer::grant_job::WorkspaceAclWaitReason,
    )])
}

/// D-54のworkspace ACL背景ジョブはWindows専用（`win_appcontainer`モジュール自体が
/// `#[cfg(windows)]`）のため、他OSでは既知の待機理由が無い。
#[cfg(not(windows))]
fn build_wait_reasons() -> WaitReasons {
    WaitReasons::default()
}
