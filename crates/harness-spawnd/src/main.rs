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
    use harness_sandbox::tier2a::spawnd::console_holder;

    const USAGE: &str = "usage: harness-spawnd.exe <control-pipe-name> <unrestricted|restricted>\n\
                         usage: harness-spawnd.exe --console-holder";

    let pipe_name = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("{USAGE}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // [段階⑤] **第2の姿: コンソール保持プロセス**（`plans/DESIGN-MAC-ENFORCEMENT.md`§7.1.1）。
    //
    // 別のバイナリを増やさないのは、**居場所の規約を2つに増やさない**ためである
    // ——`harness-spawnd.exe`は既に「`harness.exe`の隣」と決まっており、Daemonは
    // 自分自身のパスからこれを起こす（`console_holder::launch_holder`）。
    // 何をするかはあちらのモジュールdocが持つ（**ここへ複製しない**）。
    if pipe_name == console_holder::CONSOLE_HOLDER_ARG {
        return match console_holder::run_as_console_holder() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("harness-spawnd --console-holder: {e}");
                std::process::ExitCode::FAILURE
            }
        };
    }
    // [段階⑤] **省略を許さない。** 「無ければ今日の既定」にすると、常時適用へ切り替えた日に
    // 引数を渡していない経路だけが黙って旧い姿勢で立ち上がる（同関数のdoc）。
    // 知らない綴りも同じ扱いで、ここで止める。
    let child_process_policy = match std::env::args().nth(2) {
        Some(arg) => match harness_sandbox::tier2a::spawnd::ChildProcessPolicy::from_arg(&arg) {
            Some(policy) => policy,
            None => {
                eprintln!("harness-spawnd: unknown child process policy {arg:?}\n{USAGE}");
                return std::process::ExitCode::FAILURE;
            }
        },
        None => {
            eprintln!("{USAGE}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match harness_sandbox::tier2a::spawnd::server::serve(&pipe_name, child_process_policy) {
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
