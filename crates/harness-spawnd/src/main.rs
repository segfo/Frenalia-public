//! harness-spawnd: ドメイン遷移MACのSpawn Daemon（`plans/DESIGN-MAC-ENFORCEMENT.md`§10.1、
//! `plans/DESIGN-MAC-PROTOCOL.md`§12）。
//!
//! `harness.exe`が**昇格せずに**`CreateProcessW`で起こす別バイナリ。引数に受け取った
//! 制御パイプへclientとして接続し、サンドボックスの中のプロセスに代わって子プロセスを
//! 生成する唯一の窓口として常駐する。制御パイプが閉じる（＝親が終わるかクラッシュする）と
//! 畳んで終了する。
//!
//! # なぜharness本体のスレッドではないのか
//!
//! シェルを起こすときにコンソール保持プロセスのコンソールを`AttachConsole`で借り、直後に
//! `FreeConsole`する必要がある（§7.1.1）。これはプロセス単位の操作なので、harness本体が
//! やると**harness自身のコンソール（TUIの出力先）が外れる**。理由の全文は§10.1にある。
//!
//! # `harness-netfilterd`との違い
//!
//! 形（別バイナリ・パイプ名を引数で受ける・寿命をパイプに紐付ける）は同じだが、
//! **こちらは昇格しない**。AppContainerの子を起こすのに管理者権限は要らず、昇格すると
//! 子の整合性レベルが本番と変わる（`B-08`）。

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: harness-spawnd.exe <control-pipe-name>");
            return std::process::ExitCode::FAILURE;
        }
    };
    match harness_sandbox::tier2a::spawnd::server::serve(&pipe_name) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // **コンソールを持たないので、この出力は誰にも届かない可能性が高い。**
            // 呼び出し側が理由を知る経路は制御パイプの応答（`ControlResponse::Failed`）で、
            // ここは最後の手掛かりとして残しているだけである。
            eprintln!("harness-spawnd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("harness-spawnd is Windows-only (domain transition MAC spawn daemon)");
    std::process::ExitCode::FAILURE
}
