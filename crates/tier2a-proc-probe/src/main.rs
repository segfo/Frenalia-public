//! Tier2a `--cow`（D-30）の子・孫・ひ孫プロセス封じ込めE2Eテスト用プローブ。
//!
//! 自分自身の世代番号（`--gen`）とビット幅チェーンの残り（`--chain`）を引数で受け取り、
//! (1) FS検査（workspace内のcreate/modify/delete/rename）・(2) 脱走試行
//! （workspace外への書込・読取）・(3) ネットワーク到達性・(4) 自プロセスの識別情報
//! （bitness・token integrity level・AppContainer package SID・Redirector DLLロード有無）
//! を実行したのち、`--chain`が空でなければ先頭のビット幅に対応するexeを次世代として起動し、
//! その子のstdout（同形式のJSON）を自分の結果へネストして最後にJSONを1行だけ標準出力へ出す。
//!
//! `cargo test`側（`crates/harness-sandbox/src/win_appcontainer.rs`の`cow_diagnostics`）が
//! 実FS（workspace本体・CoW upperディレクトリ・警告台帳）を直接調べて封じ込めの成否を判定する
//! ため、このJSONはあくまで二次的な説明用（どの世代でどの操作がどう失敗したか）。i686
//! （WOW64孫世代）でもビルドできることが必須要件のため、依存はwindows/serde_json最小限に
//! 絞ってあり、CLI引数パースも手書き（clap等は使わない）。

use std::env;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

mod load_library;
mod spawn_via;
#[cfg(windows)]
mod winid;
#[cfg(windows)]
mod try_runas;

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
            "--spawn-via-createprocessa" => spawn_via = Some(("createprocessa".to_string(), next())),
            "--spawn-via-winexec" => spawn_via = Some(("winexec".to_string(), next())),
            "--load-library" => load_library = Some(next()),
            _ => {}
        }
    }

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
        Ok(()) => json!({"op": op, "path": path.display().to_string(), "ok": true, "os_error": null}),
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
    out.push(fs_op(
        "rename",
        &ren_from,
        fs::rename(&ren_from, &ren_to),
    ));

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
            TcpStream::connect_timeout(&addr, Duration::from_secs(2))
                .map_err(|e| e.to_string())
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
            "HARNESS_COW_UPPER",
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

fn spawn_watchdog(timeout_secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        std::process::exit(WATCHDOG_EXIT_CODE);
    });
}

fn main() -> ExitCode {
    let args = parse_args();
    spawn_watchdog(args.timeout_secs);

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
