//! このエディタが使う、`policy.json`のファイル宣言の承認台帳（D-112）の置き場を1つに決める。
//!
//! # なぜ1つの関数にするのか
//!
//! 台帳を読み書きする箇所は複数ある——候補の承認（`approve::commit`）・宣言の取り消し
//! （`unapprove::commit`）・試験実行で付ける一覧（`record_net`）・承認時の件数の警告
//! （`approve::plan`）。それぞれが`PolicyApprovalStore::in_config_dir()`を直接呼ぶと、
//! **単体試験が本物の`%APPDATA%`の台帳へ書く**（実マシンの共有状態を試験が触る形。
//! `bug-pattern-rules`の方式6）。置き場を決める場所を1つにして、試験では試験ごとの一時ファイルへ
//! 向ける。
//!
//! # 試験の置き場はスレッドごと
//!
//! `cargo test`は試験1本ごとにスレッドを立てるので、スレッドローカルな一時ディレクトリにすると
//! 試験同士が同じ台帳を踏まない（並列でも、前の試験の承認が残らない）。
//!
//! # 守らないもの
//!
//! `tests/`の統合試験と実機E2Eはこのクレートを試験としてではなく普通にビルドするので、
//! **本物の台帳を使う**。実機E2Eはそれが目的（承認してからパス2を走らせる一連を測る）なので、
//! 後始末は製品の取り消し操作で行う。

use harness_sandbox::tier2a::policy_approval::PolicyApprovalStore;

/// このプロセスの承認台帳。
pub fn approval_store() -> PolicyApprovalStore {
    #[cfg(not(test))]
    {
        PolicyApprovalStore::in_config_dir()
    }
    #[cfg(test)]
    {
        test_store()
    }
}

#[cfg(test)]
fn test_store() -> PolicyApprovalStore {
    thread_local! {
        static DIR: tempfile::TempDir = tempfile::tempdir().expect("tempdir for the approval ledger");
    }
    DIR.with(|dir| PolicyApprovalStore::at_path(dir.path().join("policy-approval-ledger.json")))
}
