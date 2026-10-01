//! harness-policy-learnd: OS監査によるFSアクセス拒否の収集器（M15.7、
//! `plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。
//!
//! `harness.exe`が`runas`で昇格起動する別バイナリ。引数に受け取ったnamed pipe名へclientとして
//! 接続し、`StartCollect`でETWセッションを張ったら**常駐を続け**、`Teardown`（または親の
//! クラッシュによるパイプ切断）を受けてセッションを撤収してから終了する。
//!
//! `harness-privhelper`（1起動=1操作で即終了）と違って常駐するのは、ETWリアルタイム
//! セッションが「エンジンハンドルを保持するプロセスが生きている間だけ有効」だからで、
//! これは`harness-netfilterd`がWFPで常駐するのと同じ理由である。
//!
//! **`harness-netfilterd`とは別プロセスにした理由**はモジュールdoc
//! （`harness_sandbox::tier2a::policy_learnd`）を参照。要点は、netfilterdが
//! 「ドメインポリシー有効時」にしか起動せず、FS学習だけが欲しい場面には居ないこと。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    // [残課題#68] **引数を読むより先に掛ける。** このプロセスは管理者権限で動き、
    // ワークスペース配下（サンドボックスの中のコードが書ける場所）のパスを開く。
    // 一度掛けると外せないので、何かを開く前のここで1回だけ呼ぶ
    // （掛ける相手と掛けない相手の一覧は`process_hardening`のモジュールdocが持つ）。
    harness_sandbox::process_hardening::harden_elevated_helper("harness-policy-learnd");

    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: harness-policy-learnd.exe <named-pipe-name>");
            return std::process::ExitCode::FAILURE;
        }
    };
    match harness_sandbox::tier2a::policy_learnd::server::serve(&pipe_name) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("harness-policy-learnd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("harness-policy-learnd is Windows-only (ETW-based FS denial collector, M15.7)");
    std::process::ExitCode::FAILURE
}
