//! Tier2a WFP fail-closed E2E専用のフォールト注入バイナリ。本物の`harness-netfilterd.exe`と
//! 同じ引数規約（argv[1] = named pipe名）だけを真似る。
//!
//! **2つの故障モードを持つ**（自分の実行ファイルの隣に置かれた`mock-mode`ファイルで選ぶ）。どちらも
//! `crates/harness-sandbox/src/tier2a/netfilterd.rs`の`connect_and_apply`を失敗させるが、
//! **通る分岐が違う**——ここが分けてある理由である。
//!
//! | モード | 挙動 | `connect_and_apply`が通る分岐 | 現実の対応物 |
//! |---|---|---|---|
//! | `drop`（既定） | 接続後すぐハンドルを閉じる | I/O失敗（`ERROR_BROKEN_PIPE`） | daemonが起動直後に落ちた |
//! | `reject` | `ApplyRules`を読んでから`NetfilterResponse::Err`を返す | `NetfilterResponse::Err` → `NetfilterError::Rejected` | **daemonは応答するがWFPを開けない**（BFEサービス停止・`FwpmEngineOpen0`の失敗） |
//!
//! `reject`が要る理由は`docs/STATUS.md`のTier2a残課題#2にある。`drop`側だけでは
//! 「daemonが応答を返せる状態で、その応答が失敗を告げる」経路が一度も通らない。
//! WFPが張れていないのにcapabilityだけ与えると**サンドボックスされて見えるのに出口が全開**に
//! なるため、この分岐もfail-closedであることを機械的に固定する必要がある。
//!
//! 本物の`harness-netfilterd`（`crates/harness-netfilterd`）は変更しない。このバイナリは
//! `docs/DEV-ENVIRONMENT.md`が指示する通常のharnessビルド成果物には含まれず、E2Eテストが
//! 明示的にビルドし、一時ディレクトリへ`harness-netfilterd.exe`という名前で配置して使う。
//!
//! フレーム形式（`[4バイトLE長][ペイロード]`）と`NetfilterResponse`のJSON表現は
//! `harness-sandbox`側の定義を**意図的に手写し**している。モックが製品クレートへ依存すると、
//! 「製品側の型を変えたらモックも一緒に変わって、変更に気付けない」という本末転倒になるため
//! （モックは製品のワイヤ契約に対する独立した観測者でいてほしい）。
//! ワイヤ形式を変えたときはこのファイルも直す必要がある——それは仕様変更の検知として正しい。
//!
//! **D-56（プロトコルを「1往復」から「`Teardown`までの要求の連続」へ変えた）では、このモックを
//! 変えていない。直し忘れではない。** どちらのモードも**最初の1往復で失敗させる**故障注入であり、
//! 親側（`connect_and_apply`）は`Applied`以外を受けた時点でパイプを閉じて返る——2件目の要求は
//! 決して送られてこないので、ループ化はここへ届かない。逆に言うと、このモックが観測しているのは
//! 「ハンドシェイクが失敗したとき親がfail-closedへ倒れるか」だけであり、**再利用の経路は
//! 一切測っていない**。そちらは`netfilterd.rs`の`protocol_tests`（偽daemon）と
//! `reuse_e2e`（実daemon＋実WFP）が持つ。

#[cfg(windows)]
mod imp {
    use std::io::{Read as _, Write as _};
    use std::iter::once;
    use std::os::windows::io::FromRawHandle as _;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    /// `NetfilterResponse::Err(msg)`のJSON表現（serdeの外部タグ付き列挙）を直書きする。
    ///
    /// 文言は実daemonがWFPを開けなかったときのもの（`serve_inner`の
    /// `NetfilterResponse::Err(format!("failed to apply WFP rules: {e}"))`）に寄せてある。
    /// **JSONライブラリを使わずリテラルで持つ**のは、このクレートの依存を増やさないためと、
    /// ワイヤ形式を手写ししているというモジュールdocの方針に合わせるため（エスケープが要る
    /// 文字は含めない）。
    const REJECT_RESPONSE: &str = concat!(
        r#"{"Err":"failed to apply WFP rules: mock fault injection "#,
        r#"(simulating a stopped Base Filtering Engine / FwpmEngineOpen0 failure)"}"#
    );

    /// `ApplyRules`を1フレーム読み捨ててから`Err`応答を1フレーム返す。
    ///
    /// **要求を読み切ってから返す**のが重要で、読まずに書くと親側の`write_framed_timeout`が
    /// 完了せず、`drop`モードと区別がつかない失敗（I/O層のエラー）になってしまう。
    ///
    /// パイプハンドルは`std::fs::File`へ包んで読み書きする（`windows`クレートの
    /// `Win32_System_IO` featureを増やさずに済む。クライアント側は同期ハンドルなので
    /// 素のRead/Writeで足りる）。**`File`のDropがハンドルを閉じる**ので、呼び出し側で
    /// `CloseHandle`してはいけない。
    fn reject(handle: HANDLE) -> Result<(), String> {
        let mut pipe = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut _) };

        let mut len_buf = [0u8; 4];
        pipe.read_exact(&mut len_buf)
            .map_err(|e| format!("reading request length: {e}"))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            pipe.read_exact(&mut payload)
                .map_err(|e| format!("reading request payload: {e}"))?;
        }

        let response = REJECT_RESPONSE.as_bytes();
        pipe.write_all(&(response.len() as u32).to_le_bytes())
            .map_err(|e| format!("writing response length: {e}"))?;
        pipe.write_all(response)
            .map_err(|e| format!("writing response payload: {e}"))?;
        pipe.flush().map_err(|e| format!("flushing: {e}"))?;
        Ok(())
    }

    pub fn run() -> std::process::ExitCode {
        let Some(pipe_name) = std::env::args().nth(1) else {
            eprintln!("usage: tier2a-mock-netfilterd.exe <named-pipe-name>");
            return std::process::ExitCode::FAILURE;
        };
        // モードは**環境変数ではなく自分の隣のファイル**から読む。このモックは
        // `launch_daemon_elevated`（`ShellExecuteExW(runas)`）経由で起動されることがあり、
        // その場合プロセスを生成するのはAppInfoサービスなので、テストプロセスの環境変数は
        // 継承されない。テストはモックを専用ディレクトリへコピーしてから使う
        // （`wfp_fail_closed_launcher_exe`）ので、そこへ1ファイル置くのが確実である。
        let mode = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|d| d.join("mock-mode")))
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
            .trim()
            .to_string();
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(once(0)).collect();

        // サーバ側(`prepare_pipe`)が`launch_daemon_elevated`より先にパイプを作っているため、
        // 通常は初回で接続できる。念のため数回だけ短い間隔でリトライする(それでも「即座に
        // 終了する」という設計意図は保たれる、待つのは最大でも数十ミリ秒)。
        for _ in 0..5 {
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    Default::default(),
                    None,
                )
            };
            let Ok(h) = handle else {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            };
            let result = if mode == "reject" {
                // `reject`はハンドルを`std::fs::File`へ移す（Dropで閉じる）ので、
                // ここでは`CloseHandle`しない——二重クローズになる。
                reject(h)
            } else {
                // `drop`（既定）: 何も送受信せず即座に閉じる。サーバ側の次のI/Oが
                // `ERROR_BROKEN_PIPE`ですぐ失敗するようにするのが目的。
                unsafe {
                    let _ = CloseHandle(h);
                }
                Ok(())
            };
            return match result {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tier2a-mock-netfilterd: {mode} mode failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        eprintln!("tier2a-mock-netfilterd: failed to connect to {pipe_name}");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    imp::run()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("tier2a-mock-netfilterd is Windows-only");
    std::process::ExitCode::FAILURE
}
