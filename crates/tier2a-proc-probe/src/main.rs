//! Tier2a `--sandbox tier2a-cow`（D-30）の子・孫・ひ孫プロセス封じ込めE2Eテスト用プローブ。
//!
//! 自分自身の世代番号（`--gen`）とビット幅チェーンの残り（`--chain`）を引数で受け取り、
//! (1) FS検査（workspace内のcreate/modify/delete/rename）・(2) 脱走試行
//! （workspace外への書込・読取）・(3) ネットワーク到達性・(4) 自プロセスの識別情報
//! （bitness・token integrity level・AppContainer package SID・Redirector DLLロード有無）
//! を実行したのち、`--chain`が空でなければ先頭のビット幅に対応するexeを次世代として起動し、
//! その子のstdout（同形式のJSON）を自分の結果へネストして最後にJSONを1行だけ標準出力へ出す。
//!
//! `cargo test`側（`crates/harness-sandbox/src/win_appcontainer.rs`の`cow_diagnostics`）が
//! 実FS（workspace本体・CoW 差分層ディレクトリ・警告台帳）を直接調べて封じ込めの成否を判定する
//! ため、このJSONはあくまで二次的な説明用（どの世代でどの操作がどう失敗したか）。i686
//! （WOW64孫世代）でもビルドできることが必須要件のため、依存はwindows/serde_json最小限に
//! 絞ってあり、CLI引数パースも手書き（clap等は使わない）。

use std::env;
use std::fs;
use std::io::Write as _;
use std::io::{self};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

mod load_library;
mod spawn_via;
#[cfg(windows)]
mod try_runas;
#[cfg(windows)]
mod winid;

// --- MAC/Spawn Daemon設計の実現性スパイク専用モード（`plans/mac-spike/RESULTS.md`）。
// いずれも通常の検査（FS・脱走・ネット・再帰spawn）を行わない短絡モードで、
// `try_runas`・`load_library`と同じ位置付け。判定が出たら削除する
// （`docs/CODE-STRUCTURE-RULES.md`規則2「一回性の調査実験をテストとして残さない」）。
mod console_share;
mod object_reach;
mod open_bench;
mod pipe_client;
mod spawn_matrix;
mod spike_handles;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_NET_TARGET: &str = "1.1.1.1:443";
const DEFAULT_DNS_NAME: &str = "example.com";
const WATCHDOG_EXIT_CODE: i32 = 97;

struct Args {
    gen: u32,
    chain: Vec<String>,
    x64_exe: Option<PathBuf>,
    x86_exe: Option<PathBuf>,
    outside_read: Option<PathBuf>,
    net_target: String,
    dns_name: String,
    timeout_secs: u64,
    /// 次世代を起動するとき`HARNESS_COW_*`環境変数を落とす（BUG-045のF2の再現・回帰用）。
    /// Redirector DLLの設定伝播が環境変数ではなく注入パラメータで行われることを検証するため、
    /// 「途中の世代が自前のenv blockを組み立てて子を起動する」実アプリの挙動を模擬する。
    sanitize_env: bool,
    /// 特権昇格ヘルパー(D-16)レビュー用: 指定時、通常のFS/脱走/ネット検査は行わず、
    /// `ShellExecuteExW(runas)`をAppContainer内から試みた結果だけをJSONで報告する
    /// （`try_runas`モジュールdoc参照）。値は`harness-privhelper.exe`の絶対パス。
    try_runas: Option<String>,
    /// Tier2a残課題#5（`CreateProcessA`/`WinExec`直接フック）検証用: 指定時、通常のFS/脱走/
    /// ネット検査は行わず、`(モード, コマンドライン)`で指定されたコマンドを`CreateProcessA`
    /// または`WinExec`で直接起動した結果だけをJSONで報告する（`spawn_via`モジュールdoc参照）。
    spawn_via: Option<(String, String)>,
    /// `docs/STATUS.md` Tier2a残課題#7の切り分け用: 指定時、通常の検査は行わず、指定パスの
    /// DLLを`LoadLibraryW`でロードした結果と`GetLastError`だけをJSONで報告する
    /// （`load_library`モジュールdoc参照）。
    load_library: Option<String>,
    /// MAC設計§20項目1: プロセス生成の全経路を試し、どれが拒否されるかを報告する
    /// （`spawn_matrix`モジュールdoc参照）。値はマーカーファイルを書くディレクトリ。
    spawn_matrix: Option<String>,
    /// MAC設計§20項目10: 別ドメイン/別プロファイルのオブジェクトへ到達できるかを型ごとに
    /// 試す（`object_reach`モジュールdoc参照）。1つでも指定されたらこのモードになる。
    reach: object_reach::ReachSpec,
    reach_mode: bool,
    /// MAC設計§22.6.2: 呼び出し元役。ファイルを開いてハンドル値を申告し、生きたまま待つ。
    hold_file: Option<String>,
    /// MAC設計§22.6.2: 遷移先の子役。自分のstdoutへ書くだけ。
    emit: Option<String>,
    /// MAC設計§20項目3: 渡された（継承した）プロセスハンドル値で待機と終了コード取得を試す。
    use_process_handle: Option<usize>,
    /// MAC設計§10.1: 要求受付パイプへクライアントとして接続し1往復する。
    pipe_client: Option<String>,
    /// `--pipe-client`が送る本文を差し替える。
    ///
    /// **既定（`None`）は`spawn-request-from-pid-<pid>`のまま**——スパイクS7が
    /// その綴りをassertしているので変えられない。Spawn Daemon本体（段階5）の受け入れ
    /// テストは本物の要求電文（JSON）を送る必要があるので、そこだけ差し替える。
    pipe_payload: Option<String>,
    /// D-88（Lazy ACE fault-in）の着手条件: Redirector DLLのフックが**成功するopen**へ
    /// 上乗せする時間を、同一プロセスの「載せる前／載せた後」で測る（`open_bench`モジュールdoc）。
    open_bench: Option<open_bench::Spec>,
    /// MAC設計§7.1.1の測定3: 同じコンソールに繋がったプロセス同士が互いの画面バッファを
    /// 読めるか・互いを落とせるか（`console_share`モジュールdoc）。
    console_share: Option<console_share::Spec>,
    /// 上記スパイクモードが結果を書き出すファイル（stdoutを読み切れない経路のため）。
    report_file: Option<String>,
    /// スパイクモードが「生きたまま待つ」秒数（`hold_file`と単独指定時のアイドル）。
    idle_secs: Option<u64>,
    /// MAC設計§7.1.1の測定7: 自分に届く`CTRL_C_EVENT`/`CTRL_BREAK_EVENT`を握り潰してから走る。
    /// **保持プロセス役の腕で使う**——撃たれても生き残るかを、守らない腕と対にして測る。
    console_guard_ctrl: bool,
    /// MAC設計§7.1.1の測定8: 「`CTRL_C_EVENT`を無視する」継承属性を自分についてどうするか
    /// （`console_share::apply_ctrl_c_mode`）。**どのモードの腕でも使える。**
    console_ctrl_c_mode: console_share::CtrlCMode,
}

fn parse_args() -> Args {
    let mut gen = 1u32;
    let mut chain: Vec<String> = Vec::new();
    let mut x64_exe = None;
    let mut x86_exe = None;
    let mut outside_read = None;
    let mut net_target = DEFAULT_NET_TARGET.to_string();
    let mut dns_name = DEFAULT_DNS_NAME.to_string();
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    let mut sanitize_env = false;
    let mut try_runas = None;
    let mut spawn_via = None;
    let mut load_library = None;
    let mut spawn_matrix = None;
    let mut reach = object_reach::ReachSpec::default();
    let mut reach_mode = false;
    let mut hold_file = None;
    let mut emit = None;
    let mut use_process_handle = None;
    let mut pipe_client = None;
    let mut pipe_payload = None;
    let mut report_file = None;
    let mut idle_secs = None;
    let mut bench_inside: Option<String> = None;
    let mut bench_outside: Option<String> = None;
    let mut bench_dll: Option<String> = None;
    let mut bench_iters: usize = 20_000;
    let mut console_write: Option<String> = None;
    let mut console_read = false;
    let mut console_ctrl_break = false;
    let mut console_ctrl_c = false;
    let mut console_ctrl_receipt: Option<String> = None;
    let mut console_ctrl_cleanup: Option<String> = None;
    let mut console_ctrl_c_mode = console_share::CtrlCMode::Inherit;
    let mut console_watch_input = false;
    let mut console_idle_secs: u64 = 0;
    let mut console_mode = false;
    let mut console_guard_ctrl = false;

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut next = || it.next().unwrap_or_default();
        match arg.as_str() {
            "--gen" => gen = next().parse().unwrap_or(1),
            "--chain" => {
                let v = next();
                chain = if v.is_empty() {
                    Vec::new()
                } else {
                    v.split(',').map(|s| s.to_string()).collect()
                };
            }
            "--x64-exe" => x64_exe = Some(PathBuf::from(next())),
            "--x86-exe" => x86_exe = Some(PathBuf::from(next())),
            "--outside-read" => outside_read = Some(PathBuf::from(next())),
            "--net-target" => net_target = next(),
            "--dns-name" => dns_name = next(),
            "--timeout-secs" => timeout_secs = next().parse().unwrap_or(DEFAULT_TIMEOUT_SECS),
            "--sanitize-env" => sanitize_env = true,
            "--try-runas" => try_runas = Some(next()),
            "--spawn-via-createprocessa" => {
                spawn_via = Some(("createprocessa".to_string(), next()))
            }
            "--spawn-via-winexec" => spawn_via = Some(("winexec".to_string(), next())),
            "--load-library" => load_library = Some(next()),
            // --- MACスパイク用（`plans/mac-spike/RESULTS.md`） ---
            "--spawn-matrix" => spawn_matrix = Some(next()),
            "--reach-process" => {
                reach.process = next().parse().ok();
                reach_mode = true;
            }
            "--reach-thread" => {
                if let Ok(tid) = next().parse() {
                    reach.threads.push(tid);
                }
                reach_mode = true;
            }
            "--reach-pipe" => {
                reach.pipes.push(next());
                reach_mode = true;
            }
            "--reach-create-pipe-instance" => {
                reach.create_pipe_instances.push(next());
                reach_mode = true;
            }
            // --- T4（`plans/handoff-issue-20/T4.md`）: 名前が秘密として成立するか・
            // 名前を先取りできるか。どちらも「開けるか」とは別の問いなので別の的にする。
            "--reach-pipe-enumerate" => {
                reach.enumerate_pipes = true;
                reach_mode = true;
            }
            "--reach-create-pipe-new" => {
                reach.create_new_pipes.push(next());
                reach_mode = true;
            }
            "--reach-object" => {
                reach.objects.push(next());
                reach_mode = true;
            }
            "--hold-file" => hold_file = Some(next()),
            "--emit" => emit = Some(next()),
            "--use-process-handle" => use_process_handle = next().parse().ok(),
            "--pipe-client" => pipe_client = Some(next()),
            "--pipe-payload" => pipe_payload = Some(next()),
            "--report-file" => report_file = Some(next()),
            "--idle-secs" => idle_secs = next().parse().ok(),
            "--open-bench" => bench_inside = Some(next()),
            "--open-bench-outside" => bench_outside = Some(next()),
            "--open-bench-dll" => bench_dll = Some(next()),
            "--open-bench-iters" => {
                if let Ok(v) = next().parse::<usize>() {
                    bench_iters = v.max(1);
                }
            }
            // §7.1.1測定3。**どれか1つでも指定されたらコンソールモード**にする——
            // 「読むだけ」「撃つだけ」の腕があるので、書く引数を必須にできない。
            "--console-write" => {
                console_write = Some(next());
                console_mode = true;
            }
            "--console-read" => {
                console_read = true;
                console_mode = true;
            }
            "--console-ctrl-break" => {
                console_ctrl_break = true;
                console_mode = true;
            }
            "--console-ctrl-c" => {
                console_ctrl_c = true;
                console_mode = true;
            }
            // §7.1.1測定8。**受け取る側**の腕（撃つ側と同じモードに同居させるのは、
            // コンソールへの載り方・レポートの出し方・待ち方が全部共通だからである）。
            "--console-ctrl-receipt" => {
                console_ctrl_receipt = Some(next());
                console_mode = true;
            }
            // **`console_mode`を立てない。** 保持プロセス役（`--idle-secs`で待つ腕）でも
            // 使うので、画面バッファを触るモードへ落とすと測る対象が別物になる。
            // **後に書いたほうが勝つ**（両方指定は測定の取り違えなので、レポートの
            // `ctrl_c_mode`を見れば実際に効いたほうが分かる）。
            "--console-ctrl-accept" => console_ctrl_c_mode = console_share::CtrlCMode::Accept,
            "--console-ctrl-ignore" => console_ctrl_c_mode = console_share::CtrlCMode::Ignore,
            "--console-watch-input" => {
                console_watch_input = true;
                console_mode = true;
            }
            "--console-ctrl-cleanup" => {
                console_ctrl_cleanup = Some(next());
                console_mode = true;
            }
            "--console-idle-secs" => {
                console_idle_secs = next().parse().unwrap_or(0);
                console_mode = true;
            }
            // §7.1.1測定7。**`console_mode`を立てない**——この引数を付ける相手は
            // 保持プロセス役（`--idle-secs`で待つだけの腕）であり、画面バッファを触る
            // `console_share`モードへ落とすと測る対象が別物になる。
            "--console-guard-ctrl" => console_guard_ctrl = true,
            _ => {}
        }
    }

    let console_share = console_mode.then_some(console_share::Spec {
        write: console_write,
        read: console_read,
        ctrl_break: console_ctrl_break,
        ctrl_c: console_ctrl_c,
        ctrl_receipt: console_ctrl_receipt,
        ctrl_cleanup: console_ctrl_cleanup,
        watch_input: console_watch_input,
        // 実際の適用は`main`が全モード共通で1回行う。ここは置き場だけ用意しておく。
        ctrl_c_mode: "inherit",
        idle_secs: console_idle_secs,
    });

    let open_bench = bench_inside.map(|inside| open_bench::Spec {
        inside,
        outside: bench_outside,
        iters: bench_iters,
        dll: bench_dll,
    });

    Args {
        gen,
        chain,
        x64_exe,
        x86_exe,
        outside_read,
        net_target,
        dns_name,
        timeout_secs,
        sanitize_env,
        try_runas,
        spawn_via,
        load_library,
        spawn_matrix,
        reach,
        reach_mode,
        hold_file,
        emit,
        use_process_handle,
        pipe_client,
        pipe_payload,
        open_bench,
        console_share,
        report_file,
        idle_secs,
        console_guard_ctrl,
        console_ctrl_c_mode,
    }
}

fn compiled_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "unknown"
    }
}

fn fs_op(op: &str, path: &Path, result: std::io::Result<()>) -> Value {
    match result {
        Ok(()) => {
            json!({"op": op, "path": path.display().to_string(), "ok": true, "os_error": null})
        }
        Err(e) => json!({
            "op": op,
            "path": path.display().to_string(),
            "ok": false,
            "os_error": e.raw_os_error(),
            "error": e.to_string(),
        }),
    }
}

fn run_fs_checks(tag: &str) -> Vec<Value> {
    let mut out = Vec::new();

    let new_path = PathBuf::from(format!("{tag}-new.txt"));
    out.push(fs_op(
        "create",
        &new_path,
        fs::write(&new_path, format!("created-by-{tag}")),
    ));

    let seed_path = PathBuf::from(format!("{tag}-seed.txt"));
    out.push(fs_op(
        "modify",
        &seed_path,
        fs::write(&seed_path, format!("modified-by-{tag}")),
    ));

    let del_path = PathBuf::from(format!("{tag}-del.txt"));
    out.push(fs_op("delete", &del_path, fs::remove_file(&del_path)));

    let ren_from = PathBuf::from(format!("{tag}-ren.txt"));
    let ren_to = PathBuf::from(format!("{tag}-ren2.txt"));
    out.push(fs_op("rename", &ren_from, fs::rename(&ren_from, &ren_to)));

    out
}

fn run_escape_checks(tag: &str, outside_read: Option<&Path>) -> Vec<Value> {
    let mut out = Vec::new();

    let windows_target = PathBuf::from(format!("C:\\Windows\\harness-escape-{tag}.txt"));
    out.push(fs_op(
        "escape-write-windows",
        &windows_target,
        fs::write(&windows_target, "should-not-be-writable"),
    ));

    if let Some(profile) = env::var_os("USERPROFILE") {
        let profile_target = PathBuf::from(profile).join(format!("harness-escape-{tag}.txt"));
        out.push(fs_op(
            "escape-write-userprofile",
            &profile_target,
            fs::write(&profile_target, "should-not-be-writable"),
        ));
    } else {
        out.push(json!({
            "op": "escape-write-userprofile", "path": null, "ok": false,
            "os_error": null, "error": "USERPROFILE not set",
        }));
    }

    if let Ok(cwd) = env::current_dir() {
        if let Some(parent) = cwd.parent() {
            let parent_target = parent.join(format!("harness-escape-{tag}.txt"));
            out.push(fs_op(
                "escape-write-parent",
                &parent_target,
                fs::write(&parent_target, "should-not-be-writable"),
            ));
        }
    }

    let win_ini = PathBuf::from("C:\\Windows\\win.ini");
    out.push(fs_op(
        "escape-read-baseline",
        &win_ini,
        fs::read(&win_ini).map(|_| ()),
    ));

    if let Some(outside) = outside_read {
        out.push(fs_op(
            "escape-read-outside",
            outside,
            fs::read(outside).map(|_| ()),
        ));
    }

    out
}

fn run_net_checks(net_target: &str, dns_name: &str) -> Value {
    let connect_started = Instant::now();
    let connect_result = net_target
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .ok_or_else(|| "could not resolve net-target as socket address".to_string())
        .and_then(|addr| {
            TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())
        });
    let connect_ok = connect_result.is_ok();
    let connect_error = connect_result.err();

    let resolve_started = Instant::now();
    let resolve_result = format!("{dns_name}:0")
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.to_string()).collect::<Vec<_>>())
        .map_err(|e| e.to_string());
    let resolve_ok = resolve_result.is_ok();
    let (resolved_addrs, resolve_error) = match resolve_result {
        Ok(addrs) => (addrs, None),
        Err(e) => (Vec::new(), Some(e)),
    };

    json!({
        "connect": {
            "target": net_target,
            "ok": connect_ok,
            "error": connect_error,
            "elapsed_ms": connect_started.elapsed().as_millis(),
        },
        "resolve": {
            "name": dns_name,
            "ok": resolve_ok,
            "addrs": resolved_addrs,
            "error": resolve_error,
            "elapsed_ms": resolve_started.elapsed().as_millis(),
        },
    })
}

fn spawn_child(args: &Args, tag_prefix_gen: u32) -> Value {
    let Some((next_arch, rest)) = args.chain.split_first() else {
        return json!({"requested": null, "ok": true, "reason": "chain empty, this is the last generation"});
    };

    let exe = match next_arch.as_str() {
        "x64" => args.x64_exe.clone(),
        "x86" => args.x86_exe.clone(),
        other => {
            return json!({"requested": other, "ok": false, "error": format!("unknown arch in chain: {other}")});
        }
    };
    let Some(exe) = exe else {
        return json!({
            "requested": next_arch, "ok": false,
            "error": format!("no exe path provided for arch {next_arch}"),
        });
    };
    if !exe.exists() {
        return json!({
            "requested": next_arch, "ok": false,
            "error": format!("probe exe not found at {}", exe.display()),
        });
    }

    let mut cmd = Command::new(&exe);
    cmd.arg("--gen").arg((tag_prefix_gen + 1).to_string());
    cmd.arg("--chain").arg(rest.join(","));
    if let Some(x64) = &args.x64_exe {
        cmd.arg("--x64-exe").arg(x64);
    }
    if let Some(x86) = &args.x86_exe {
        cmd.arg("--x86-exe").arg(x86);
    }
    if let Some(outside) = &args.outside_read {
        cmd.arg("--outside-read").arg(outside);
    }
    cmd.arg("--net-target").arg(&args.net_target);
    cmd.arg("--dns-name").arg(&args.dns_name);
    cmd.arg("--timeout-secs").arg(args.timeout_secs.to_string());
    if args.sanitize_env {
        cmd.arg("--sanitize-env");
        // 実アプリが`CreateProcessW`へ自前のenv blockを渡す状況の模擬（BUG-045のF2）。
        // Redirector DLLの設定が環境変数に依存していれば、この時点で以降の全世代の
        // リダイレクトが失われる。
        for key in [
            "HARNESS_COW_WORKSPACE",
            "HARNESS_COW_DIFF_LAYER",
            "HARNESS_COW_EXT_ROOTS",
            "HARNESS_COW_READY_HANDLE",
        ] {
            cmd.env_remove(key);
        }
    }
    if let Ok(cwd) = env::current_dir() {
        cmd.current_dir(cwd);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let child_json: Option<Value> = stdout
                .lines()
                .rev()
                .find_map(|line| serde_json::from_str(line).ok());
            json!({
                "requested": next_arch,
                "ok": true,
                "exe": exe.display().to_string(),
                "exit_code": output.status.code(),
                "child": child_json,
                "child_stderr": stderr,
            })
        }
        Err(e) => json!({
            "requested": next_arch, "ok": false,
            "exe": exe.display().to_string(),
            "error": e.to_string(),
        }),
    }
}

/// アイドルモードで**後から**1本スレッドを作り、そのOSスレッドIDを返す（MACスパイクS2b）。
/// 起動後に生えるスレッドは`lpThreadAttributes`の対象外なので、既定のDACLを持つ。
#[cfg(windows)]
fn spawn_idle_thread(secs: u64) -> u32 {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
        let _ = tx.send(id);
        std::thread::sleep(Duration::from_secs(secs));
    });
    rx.recv_timeout(Duration::from_secs(5)).unwrap_or(0)
}

#[cfg(not(windows))]
fn spawn_idle_thread(_secs: u64) -> u32 {
    0
}

/// アイドルモードで**起動後に**名前付きmutexを1つ作り、その名前を返す（MACスパイクS2c）。
/// スレッドと同じく、後から作るカーネルオブジェクトのDACLはトークンの既定DACLから来る
/// ——「既定DACLを差し替えれば後から生えるものにも効く」かを、この的で測る。
/// ハンドルは意図的に閉じない（プロセスが生きている間、名前を有効に保つため）。
#[cfg(windows)]
fn create_idle_mutex() -> String {
    use windows::core::PCWSTR;
    use windows::Win32::System::Threading::CreateMutexW;
    let name = format!("harness-mac-spike-idle-{}", std::process::id());
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    match unsafe { CreateMutexW(None, false, PCWSTR(name_w.as_ptr())) } {
        Ok(_handle) => name,
        Err(_) => String::new(),
    }
}

#[cfg(not(windows))]
fn create_idle_mutex() -> String {
    String::new()
}

fn spawn_watchdog(timeout_secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        std::process::exit(WATCHDOG_EXIT_CODE);
    });
}

fn main() -> ExitCode {
    let mut args = parse_args();
    spawn_watchdog(args.timeout_secs);

    // **`CTRL_C_EVENT`の扱いは、どのモードよりも先に1回だけ決める。**
    // モードごとに書くと片方だけ直る事故になる（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
    let ctrl_c_mode = console_share::apply_ctrl_c_mode(args.console_ctrl_c_mode);
    if let Some(spec) = args.console_share.as_mut() {
        spec.ctrl_c_mode = ctrl_c_mode;
    }

    // **どのモードよりも先に掛ける。** レポートを書く前に掛かっていないと、
    // 「レポートが見えた＝もう守られている」と読めなくなり、テスト側は撃ってよい時点を
    // 判定できない（守りが立つ前に撃つと、測っているのは守りではなく競走になる）。
    // `None`は「頼まれていない」、`Some(false)`は「頼まれたが掛からなかった」——
    // 観測していない欄を既定値で埋めない（`P-11`）。
    let ctrl_guard = args
        .console_guard_ctrl
        .then(console_share::guard_self_from_ctrl_events);

    #[cfg(windows)]
    if let Some(helper_path) = &args.try_runas {
        let report = try_runas::try_runas(helper_path);
        println!(
            "{}",
            serde_json::to_string(&report).expect("try_runas report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if let Some(dll) = &args.load_library {
        let report = load_library::run(dll);
        println!(
            "{}",
            serde_json::to_string(&report).expect("load_library report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if let Some((mode, cmdline)) = &args.spawn_via {
        let report = spawn_via::run(mode, cmdline);
        println!(
            "{}",
            serde_json::to_string(&report).expect("spawn_via report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    // --- MACスパイク用の短絡モード（`plans/mac-spike/RESULTS.md`） ---
    if let Some(marker_dir) = &args.spawn_matrix {
        let report = spawn_matrix::run(marker_dir);
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        println!(
            "{}",
            serde_json::to_string(&report).expect("spawn_matrix report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if args.reach_mode {
        let report = object_reach::run(&args.reach);
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        println!(
            "{}",
            serde_json::to_string(&report).expect("object_reach report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if let Some(spec) = &args.console_share {
        let report = console_share::run(spec);
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        println!(
            "{}",
            serde_json::to_string(&report).expect("console_share report must serialize")
        );
        // **出し切ってから待つ。** 待っている間にCtrl+Breakで落とされると、
        // バッファに残った出力は失われる（「落とされた」と「動かなかった」が区別できなくなる）。
        let _ = io::stdout().flush();
        console_share::idle(spec);
        return ExitCode::SUCCESS;
    }

    if let Some(path) = &args.hold_file {
        let _ = spike_handles::hold_file(
            path,
            args.report_file.as_deref(),
            args.idle_secs.unwrap_or(10),
        );
        return ExitCode::SUCCESS;
    }

    if let Some(text) = &args.emit {
        let report = spike_handles::emit(text);
        // stdoutは「Daemon役が絞って渡したハンドル」なので、レポートはstdoutへ**出さない**
        // （出すと測定対象のファイルに混ざる、B-33）。
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        return ExitCode::SUCCESS;
    }

    #[cfg(windows)]
    if let Some(raw) = args.use_process_handle {
        let report = spike_handles::use_process_handle(raw, args.report_file.as_deref());
        println!(
            "{}",
            serde_json::to_string(&report).expect("use_process_handle report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if let Some(spec) = &args.open_bench {
        let report = open_bench::run(spec);
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        println!(
            "{}",
            serde_json::to_string(&report).expect("open_bench report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    if let Some(pipe) = &args.pipe_client {
        let report = pipe_client::run(
            pipe,
            args.pipe_payload.as_deref(),
            args.report_file.as_deref(),
        );
        println!(
            "{}",
            serde_json::to_string(&report).expect("pipe_client report must serialize")
        );
        return ExitCode::SUCCESS;
    }

    // 単独の`--idle-secs`は「生きているだけ」の子（§10.1.1のJob試験用）。
    //
    // **起動後に自分で作ったスレッドのIDも報告する**（MACスパイクS2b）。
    // `CreateProcessW`の`lpThreadAttributes`が効くのは**最初のスレッドだけ**なので、
    // 「プロセスとスレッドのDACLを絞れば相互アクセスを塞げる」という候補機構が、
    // 後から生えたスレッドにも効くのかはこれを撃たないと分からない。
    if let Some(secs) = args.idle_secs {
        let extra_thread_id = spawn_idle_thread(secs);
        let extra_mutex = create_idle_mutex();
        let report = json!({
            "mode": "idle",
            "pid": std::process::id(),
            "extra_thread_id": extra_thread_id,
            "extra_mutex": extra_mutex,
            // **腕は自分で名乗る。** 記録を後から読む人が、守った腕と守らない腕を
            // 起動引数の記憶ではなくレポートの中身で区別できるようにする。
            "ctrl_guard": ctrl_guard,
            "ctrl_c_mode": ctrl_c_mode,
        });
        if let Some(path) = &args.report_file {
            let _ = fs::write(path, report.to_string());
        }
        println!("{report}");
        std::thread::sleep(Duration::from_secs(secs));
        return ExitCode::SUCCESS;
    }

    let arch = compiled_arch();
    let tag = format!("gen{}-{arch}", args.gen);

    let identity = winid::collect_identity();

    let fs_results = run_fs_checks(&tag);
    let escape_results = run_escape_checks(&tag, args.outside_read.as_deref());
    let net_result = run_net_checks(&args.net_target, &args.dns_name);
    let spawn_result = spawn_child(&args, args.gen);

    let report = json!({
        "gen": args.gen,
        "tag": tag,
        "sanitize_env": args.sanitize_env,
        "identity": identity,
        "fs": fs_results,
        "escape": escape_results,
        "net": net_result,
        "spawn": spawn_result,
    });

    println!(
        "{}",
        serde_json::to_string(&report).expect("probe report must serialize")
    );
    ExitCode::SUCCESS
}
