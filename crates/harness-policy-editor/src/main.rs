//! `harness-policy-editor`: TOMOYO風ポリシーエディタの起動点。
//!
//! 設計は`harness_policy_editor`のlib.rs（記録2パス・3状態UI）を参照。
//!
//! **現状は骨格のみ**。記録セッションの排他（[`RecordingLock`]）まで配線してあり、
//! TUI本体（記録／編集／テストの3画面）はこれから実装する。
//! 未実装の部分を「動いているように見せない」ため、ここでは何をするクレートかと
//! 現在の到達点を表示して終了する。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use harness_policy_editor::RecordingLock;

    // 記録セッションはマシン全体の共有状態（AppContainerプロファイル・WFPフィルタ・
    // fs-passthrough台帳）を触るので、起動時点で排他を取る。
    let (guard, outcome) = match RecordingLock::try_acquire() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("harness-policy-editor: failed to check the recording lock: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    println!("{}", outcome.message());
    if !outcome.can_proceed() {
        return std::process::ExitCode::FAILURE;
    }
    debug_assert!(guard.is_some(), "a proceedable outcome must carry the guard");

    println!();
    println!("harness-policy-editor はまだ実装途中です（骨格のみ）。");
    println!("完成している部分:");
    println!("  - 記録セッションの排他（グローバル名前付きmutex、異常終了の検知つき）");
    println!("  - 監査JSONLの追記追従読み（audit_tail）");
    println!("  - Tier1のストリーミング実行API（harness-sandbox側）");
    println!("  - ETW record-allモード（拒否だけでなく成功アクセスも記録）");
    println!("  - ネットワーク全許可モード（パス2の学習用、harness-core側）");
    println!("これから実装する部分: 記録／編集／テストの3画面（TUI）と、その間の遷移。");

    // `guard`はここでdropされ、mutexが解放される。
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "harness-policy-editor はWindows専用です（Tier1の制限トークン・Tier2aの\
         AppContainer・ETW・WFPに依存しているため）。"
    );
    std::process::ExitCode::FAILURE
}
