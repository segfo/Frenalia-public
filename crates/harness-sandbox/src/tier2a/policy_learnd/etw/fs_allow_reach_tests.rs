//! **`--fs-allow`で許可したパスへ、サンドボックスは本当に到達できるのか**の実測
//! （`plans/PLAN-M15.7-FOLLOWUP.md` W1）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-fs-allow-reach
//! ```
//!
//! # 何を確かめたいのか
//!
//! `--fs-allow <path>`は`path`自身へセッションpackage SIDのACEを付けるが、
//! **`path`の祖先には何も付けない**（`preflight.rs`の`traverse_targets`は
//! workspace／CoW 差分層の親だけから作られる）。一方`plans/etw-spike/RESULTS.md` §17.6・§18.1で
//! 判明したとおり、`Remove-Item`/`Move-Item`/`cmd`は祖先ディレクトリを「通過」ではなく
//! **オープン**する。したがって次が起こり得る。
//!
//! > 明示的に許可したはずのパスなのに、削除・移動・`cmd`経由の読取ができない。
//!
//! 本テストはこれを**実測で決着させる**ために書かれた（結果は`plans/etw-spike/RESULTS.md` §19:
//! 読み・書き・実行・`cmd`経由の読取は通り、**削除と移動だけが祖先で拒否される**）。
//!
//! **D-45（`plans/DESIGN-SANDBOX-APPPOLICY.md`）でこの穴は塞がれた**——`preflight`が
//! `--fs-allow`エントリの**親**も`traverse_targets`へ入れるようになった。したがって現在は
//! 条件(a)（＝`preflight`を通しただけ＝製品そのもの）でも7操作すべてが成功しなければならず、
//! 本テストは**測定であると同時にD-45の受け入れテスト**になっている（下記のassert）。
//! 条件(b)（手動で`grant_traverse_chain`）はD-45後は実質的に冪等な操作で、
//! 「(a)で既に開通していること」の裏取りとして残してある。
//!
//! # 併せて測る軸: CoW redirector DLL（`docs/STATUS.md` Tier2a残課題#7）
//!
//! CoW封じ込めE2E 17件中16件が`redirector DLL failed to load`で落ちている。`preflight`は
//! DLLファイル自身へセッションSIDの`ReadExec`を付けるが、そこへ到達するための
//! `target`・`target\debug`・`target\debug\deps`のcapability SID traverseは誰も付与しない
//! ——**`--fs-allow`とまったく同じ形の穴**である。同じ測定の中で確かめておけば、
//! W2の決定1つで両方が片付くかどうかが分かる。
//!
//! # 測り方（RESULTS.md §18.5、3回踏んだ交絡への対処）
//!
//! - **`%TEMP%`を使わない。** この機の`%TEMP%`祖先は2026-07-31に付与済みで、
//!   「祖先が未付与」という条件そのものが作れない
//! - `C:\harness-fsallow-<pid>\a\b\...`のように**十分深く・未付与が保証できる**場所へ置く。
//!   作った直後なのでcapability SIDのACEが無いことは構造的に保証されるが、
//!   **測る前に`preview_traverse_chain`で確認し、付与済みだったら測定を中止する**
//! - 対象ファイルだけでなく**プローブツリー配下の全拒否**を出す。祖先・親・移動先で
//!   落ちている方がむしろ多い
//! - **成功しなければならないセル**（workspace内）と**失敗しなければならないセル**
//!   （fs-allowしていない深い未付与パス）を必ず混ぜる。全滅は測定不備、全成功は
//!   「未付与のつもりが付与済み」の合図
//!
//! # マシンの状態
//!
//! 条件(b)は**永続capability SID**のACEを書く。テストは`Drop`ガードで
//! **元から付与されていなかったノードだけ**を撤収する（`grant_traverse_chain`は冪等スキップした
//! ノードも戻り値に含めるため、戻り値をそのまま撤収対象にすると元から在ったACEまで剥がす）。

use crate::shell_tier::{FsAccess, FsPassthrough, GrantScope, WorkspaceWriteMode};
// D-54: `preflight`が付けるworkspace ACEの主体はworkspace capability SIDなので、子を起こす側は
// 本番（`run_shell`）と同じくそれをトークンへ積む必要がある。素の`spawn`だとworkspaceが
// 一切見えず、測定そのものが成立しない（`spawn_in_workspace`のdoc参照）。
use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
use crate::tier2a::win_appcontainer::{
    grant_ace_inheritable_access, preflight, preview_traverse_chain, probe_passthrough,
    redirector_dll_paths, resolve_shell, traverse_capability_sid, NetworkCapability,
};

use super::parse::to_settings_path;
use super::session::EtwFsSession;
use super::volumes::drive_letter_map;

const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
const DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// 1操作。`@P@`が対象パス、`@T@`が移動先、`@OK@`/`@NG@`が結果出力に置き換わる。
/// **トークンを`@`で挟むのは誤置換を防ぐため**（`access_matrix_tests`と同じ規約）。
struct Op {
    name: &'static str,
    /// 対象ファイル名。`None`なら対象はディレクトリ自身（列挙）。
    file: Option<&'static str>,
    /// この操作を成立させるために対象へ要るアクセス権。fs-allowのエントリを分けるのに使う。
    needs_exec: bool,
    script: &'static str,
}

/// **`Move-Item`の移動先は同じディレクトリ内の別名にしない**——別ディレクトリへの移動が
/// 「`Create`段を通り越しうる唯一の経路」であり（RESULTS.md §18.3）、移動先ディレクトリの
/// オープンが起きる形にしないと測る意味が無い。
const OPS: [Op; 7] = [
    Op {
        name: "read_dotnet",
        file: Some("read_dotnet.txt"),
        needs_exec: false,
        script: "try { Get-Content -LiteralPath '@P@' -ErrorAction Stop | Out-Null; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "read_netfx",
        file: Some("read_netfx.txt"),
        needs_exec: false,
        script: "try { [System.IO.File]::ReadAllBytes('@P@') | Out-Null; @OK@ } catch { @NG@ }",
    },
    // `cmd`は祖先を**オープン**する（§17.6）。祖先未付与でこれが落ちるなら、それがまさに
    // 「明示的に許可したのに`cmd`経由で読めない」の正体である。
    Op {
        name: "read_cmd",
        file: Some("read_cmd.txt"),
        needs_exec: false,
        script: "& cmd.exe /c \"type @P@\" 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { @OK@ } else { @NG@ }",
    },
    Op {
        name: "write_dotnet",
        file: Some("write_dotnet.txt"),
        needs_exec: false,
        script: "try { Add-Content -LiteralPath '@P@' -Value 'x' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "delete",
        file: Some("delete.txt"),
        needs_exec: false,
        script: "try { Remove-Item -LiteralPath '@P@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "move",
        file: Some("move.txt"),
        needs_exec: false,
        script: "try { Move-Item -LiteralPath '@P@' -Destination '@T@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "exec",
        file: Some("exec.exe"),
        needs_exec: true,
        script: "try { & '@P@' /c exit 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { @OK@ } else { @NG@ } } catch { @NG@ }",
    },
];

/// 1セル＝(条件, 操作, 実際に叩くパス, 移動先)。
struct Cell {
    condition: &'static str,
    op: &'static Op,
    path: std::path::PathBuf,
    dest: std::path::PathBuf,
}

/// 測定中に付与した**永続**capability SID ACEを、パニック時でも必ず剥がす。
///
/// 元から`already_sufficient`だったノードは決して入れない——`grant_traverse_chain`は
/// 冪等スキップしたノードも戻り値へ含めるため、戻り値をそのまま撤収対象にすると
/// 測定前から在ったACEまで剥がしてしまう（`plans/PLAN-M15.7-FOLLOWUP.md`「マシン状態の変更と復旧」）。
struct TraverseRestore {
    sid: crate::win_common::OwnedSid,
    granted_by_us: Vec<std::path::PathBuf>,
}

impl Drop for TraverseRestore {
    fn drop(&mut self) {
        for node in self.granted_by_us.iter().rev() {
            // D-48: 撤収対象は台帳へ記録済みのノードなので、汎用の`revoke_ace`は拒否する
            // （BUG-046のガード）。ここは「自分が付けたぶんだけ剥がす」ことを`grant_chain`で
            // 保証したうえで巻き戻す正当な経路なので、名前の付いた扉を通る。
            match crate::tier2a::win_appcontainer::revoke_traverse_grant(node) {
                Ok(()) => {
                    crate::tier2a::traverse_ledger::remove_traverse_grant(node);
                    println!("  restored (revoked traverse): {}", node.display());
                }
                // パスが既に消えているならACEも一緒に消えている（剥がす対象が無い）。
                // ここで台帳エントリを残すと、実在しないパスを指すphantomが積み上がる
                // ——実際にW1の測定はこの経路で2件残した。台帳は「harnessがACEを付けた場所」の
                // 記録なので、対象が消えた時点で記録も消すのが正しい。
                Err(e) if !node.exists() => {
                    crate::tier2a::traverse_ledger::remove_traverse_grant(node);
                    println!(
                        "  restored (path already gone, ledger entry dropped): {} ({e})",
                        node.display()
                    );
                }
                Err(e) => println!(
                    "  !! FAILED to revoke traverse on {} : {e} -- run \
                     `harness fs revoke-traverse {}` manually",
                    node.display(),
                    node.display()
                ),
            }
        }
    }
}

impl TraverseRestore {
    fn new(sid: crate::win_common::OwnedSid) -> Self {
        Self {
            sid,
            granted_by_us: Vec::new(),
        }
    }

    /// `target`の祖先チェーン（`target`自身を含む）へtraverseを付与し、**今回新たに付与した
    /// ノードだけ**を撤収リストへ積む。
    fn grant_chain(&mut self, target: &std::path::Path) {
        let before = preview_traverse_chain(target, self.sid.as_psid());
        let newly: Vec<std::path::PathBuf> = before
            .iter()
            .filter(|n| !n.already_sufficient)
            .map(|n| n.path.clone())
            .collect();
        let (granted, result) =
            crate::tier2a::win_appcontainer::grant_traverse_chain(target, self.sid.as_psid());
        if let Err(e) = result {
            println!(
                "  !! grant_traverse_chain({}) failed: {e}",
                target.display()
            );
        }
        // 台帳へ記録するのは**今回新たに付与したノードだけ**にする。`grant_traverse_chain`は
        // 冪等スキップしたノードも戻り値へ含めるため、戻り値をそのまま記録すると
        // 「測定前から在った付与」の時刻まで書き換えてしまい、撤収対象（`granted_by_us`）とも
        // ずれる。記録と撤収は同じ集合でなければ、片方だけ残るphantomが生まれる。
        for node in newly {
            if granted.contains(&node) && !self.granted_by_us.contains(&node) {
                crate::tier2a::traverse_ledger::record_traverse_grant(&node);
                self.granted_by_us.push(node);
            }
        }
    }
}

fn print_chain(label: &str, target: &std::path::Path, sid: windows::Win32::Security::PSID) {
    println!("--- traverse chain ({label}): {} ---", target.display());
    for node in preview_traverse_chain(target, sid) {
        println!(
            "  {:<5} mask={:>10} {}",
            if node.already_sufficient {
                "OK"
            } else {
                "MISS"
            },
            node.existing_mask
                .map(|m| format!("{m:#010x}"))
                .unwrap_or_else(|| "(none)".to_string()),
            node.path.display()
        );
    }
}

/// `dir`配下に全操作分のプローブファイルを作る（`exec`はコピーした`cmd.exe`）。
fn seed_probe_files(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).expect("create the probe dir");
    for op in &OPS {
        let Some(file) = op.file else { continue };
        let path = dir.join(file);
        if file.ends_with(".exe") {
            std::fs::copy(r"C:\Windows\System32\cmd.exe", &path).expect("copy the probe exe");
        } else {
            std::fs::write(&path, b"payload").expect("create the probe file");
        }
    }
}

/// セル群から子プロセス用のPowerShellスクリプトを組み立てる。
fn build_script(cells: &[Cell]) -> String {
    let mut script = String::from("$ErrorActionPreference='SilentlyContinue';\n");
    for cell in cells {
        let body = cell
            .op
            .script
            .replace(
                "@OK@",
                &format!("Write-Output '{}|{}|OK'", cell.condition, cell.op.name),
            )
            .replace(
                "@NG@",
                &format!(
                    "Write-Output ('{}|{}|FAIL last=' + $LASTEXITCODE)",
                    cell.condition, cell.op.name
                ),
            )
            .replace("@P@", &cell.path.display().to_string())
            .replace("@T@", &cell.dest.display().to_string());
        script.push_str(&body);
        script.push('\n');
    }
    script
}

/// `access_matrix_tests`と同じ子孫PID閉包（T-15の「親が対象なら子も対象」をここでも作る）。
/// `cmd.exe`経由の操作は子(PowerShell)ではなく孫のPIDで拒否が出るため、これが無いと
/// 「拒否0件」に見えてしまう。
fn process_family(
    child_pid: u32,
    starts: &[super::session::ProcessStartInfo],
) -> std::collections::HashSet<u32> {
    let mut family = std::collections::HashSet::new();
    family.insert(child_pid);
    loop {
        let before = family.len();
        for s in starts {
            if s.parent_pid.is_some_and(|p| family.contains(&p)) {
                family.insert(s.pid);
            }
        }
        if family.len() == before {
            break;
        }
    }
    family
}

/// 1フェーズ分（ETW開始 → 子で全セル実行 → drain → セルごとの結果と全拒否を印字）。
/// 戻り値は`(条件|操作 -> OK/FAIL)`の対応表。
fn run_phase(
    phase: &str,
    session_sid: windows::Win32::Security::PSID,
    workspace: &std::path::Path,
    cells: &[Cell],
    probe_trees: &[std::path::PathBuf],
) -> std::collections::BTreeMap<String, String> {
    let session = EtwFsSession::start(&format!("harness-policy-learn-fs-allow-reach-{phase}"))
        .expect("ETW session");
    std::thread::sleep(WARMUP);

    let script = build_script(cells);
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace,
        &env,
        false,
        session_sid,
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the AppContainer child");
    let child_pid = child.pid();
    let output = child.write_stdin_read_output_and_wait(None);

    std::thread::sleep(DRAIN);
    let (starts, denials) = session.drain();
    let outcome = session.stop();
    let family = process_family(child_pid, &starts);

    println!("=== [{phase}] operation results (child pid={child_pid}) ===");
    let mut results = std::collections::BTreeMap::new();
    match &output {
        Ok((stdout, stderr, code)) => {
            for line in stdout.lines().filter(|l| l.contains('|')) {
                let line = line.trim();
                println!("  {line}");
                let mut parts = line.splitn(3, '|');
                if let (Some(cond), Some(op), Some(res)) =
                    (parts.next(), parts.next(), parts.next())
                {
                    results.insert(format!("{cond}|{op}"), res.to_string());
                }
            }
            if !stderr.trim().is_empty() {
                println!("  (stderr) {}", stderr.trim());
            }
            println!("  (exit code {code})");
        }
        Err(e) => println!("  child failed: {e}"),
    }

    // **プローブツリー配下の全拒否**を出す（対象ファイルだけを見ると、祖先で落ちているのを
    // 「対象で拒否された」と読み違える。3回踏んだ交絡、RESULTS.md §18.5）。
    let volumes = drive_letter_map();
    let trees: Vec<String> = probe_trees
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/").to_lowercase())
        .collect();
    println!("=== [{phase}] ALL Create-stage denials under the probe trees ===");
    let mut under_tree: Vec<(String, u32, u32)> = denials
        .iter()
        .filter_map(|d| {
            let p = to_settings_path(&d.file_name, &volumes)?;
            let lower = p.to_lowercase();
            trees
                .iter()
                .any(|t| lower.starts_with(t))
                .then_some((p, d.pid, d.create_options))
        })
        .collect();
    under_tree.sort();
    under_tree.dedup();
    for (path, pid, opts) in &under_tree {
        let who = if *pid == child_pid {
            "child"
        } else if family.contains(pid) {
            "descendant"
        } else {
            "OUTSIDE-FAMILY"
        };
        println!("  {path}  (pid={pid} {who}, CreateOptions={opts:#010x})");
    }
    if under_tree.is_empty() {
        println!("  (none)");
    }

    println!("=== [{phase}] denials hit by the family OUTSIDE the probe trees ===");
    let mut outside: Vec<(u32, String)> = denials
        .iter()
        .filter(|d| family.contains(&d.pid))
        .filter_map(|d| {
            let p = to_settings_path(&d.file_name, &volumes)?;
            let lower = p.to_lowercase();
            (!trees.iter().any(|t| lower.starts_with(t))).then_some((d.pid, p))
        })
        .collect();
    outside.sort();
    outside.dedup();
    for (pid, path) in outside.iter().take(40) {
        println!("  pid={pid} {path}");
    }
    if outside.is_empty() {
        println!("  (none)");
    }

    println!(
        "=== [{phase}] events={} lost={} denials={} ===",
        outcome.seen_events,
        outcome.events_lost,
        denials.len()
    );
    results
}

/// `docs/STATUS.md` Tier2a残課題#7の切り分け: **注入機構を通さずに**、AppContainerの子自身に
/// `LoadLibraryW`を呼ばせて`GetLastError`を取る。
///
/// #7の症状（`LoadLibraryW returned NULL in target process`）は`inject_redirector`が
/// `CreateRemoteThread`のスレッド終了コードだけを見ているために出るもので、**Win32エラーコードが
/// 一切残らない**。原因の候補（ACL/権利・依存DLL・ビット数・注入タイミング）を分けるには、
/// 「そもそもこのAppContainerはこのDLLをロードできるのか」を独立に測るしかない。
///
/// プローブexeは`workspace`（このセッションのSIDへRWで付与済み）へコピーして実行する。
/// `target\debug\deps`の到達性という別問題を測定に混ぜないための措置である。
fn probe_load_library_in_appcontainer(
    label: &str,
    session_sid: windows::Win32::Security::PSID,
    workspace: &std::path::Path,
    dll: &std::path::Path,
) -> String {
    let source = {
        let current = std::env::current_exe().expect("current_exe");
        current
            .parent()
            .expect("current_exe has parent")
            .join("tier2a_proc_probe.exe")
    };
    if !source.exists() {
        let msg = format!("(skipped: {} not found)", source.display());
        println!("  [{label}] {msg}");
        return msg;
    }
    let staged = workspace.join("load-library-probe.exe");
    if let Err(e) = std::fs::copy(&source, &staged) {
        let msg = format!("(skipped: could not stage the probe exe: {e})");
        println!("  [{label}] {msg}");
        return msg;
    }

    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &staged.to_string_lossy(),
        &[
            "--load-library",
            &dll.to_string_lossy(),
            "--timeout-secs",
            "20",
        ],
        workspace,
        &env,
        false,
        session_sid,
        NetworkCapability::Deny,
        None,
    );
    let out = match child {
        Ok(child) => match child.write_stdin_read_output_and_wait(None) {
            Ok((stdout, stderr, code)) => {
                let line = stdout
                    .lines()
                    .rev()
                    .find(|l| l.trim_start().starts_with('{'))
                    .unwrap_or("")
                    .to_string();
                if line.is_empty() {
                    format!("(no JSON; exit={code} stderr={})", stderr.trim())
                } else {
                    line
                }
            }
            Err(e) => format!("(probe I/O failed: {e})"),
        },
        Err(e) => format!("(spawn failed: {e})"),
    };
    println!("  [{label}] {out}");
    out
}

#[test]
#[ignore = "requires administrator rights (ETW), creates an AppContainer profile and grants \
            persistent capability-SID traverse ACEs (revoked on drop); run via \
            dev-elevated-run.exe etw-fs-allow-reach"]
fn fs_allow_reachability_with_ungranted_ancestors() {
    let capability = traverse_capability_sid().expect("traverse capability SID");
    // 撤収後の確認用にもう1本持っておく（`TraverseRestore`が1本目を所有して消費するため）。
    let capability_check = traverse_capability_sid().expect("traverse capability SID");

    // --- workspaceは`C:\`直下（浅い）にする。深いと workspace 側の祖先事情が混ざる ---
    let root = std::path::PathBuf::from(format!("C:\\harness-fsallow-{}", std::process::id()));
    let workspace = root.join("ws");
    // fs-allow対象は**十分深く**置く。`a\b`の2段が未付与の祖先になる。
    let allow_rw = root.join("a").join("b").join("allowed_rw");
    let allow_rx = root.join("a").join("b").join("allowed_rx");
    // 条件(d): fs-allowしない深い未付与パス（**失敗しなければならない対照**）。
    let never_allowed = root.join("a").join("b").join("never_allowed");

    std::fs::create_dir_all(&workspace).expect("create the workspace");
    for dir in [&allow_rw, &allow_rx, &never_allowed] {
        seed_probe_files(dir);
        std::fs::create_dir_all(dir.join("dest")).expect("create the move destination");
    }
    let control = workspace.join("control");
    seed_probe_files(&control);
    std::fs::create_dir_all(control.join("dest")).expect("create the move destination");
    // (a)と(b)で同じファイルを使い回せない（削除・移動が消費する）ので、条件ごとに複製する。
    let allow_rw_b = allow_rw.join("phase_b");
    let allow_rx_b = allow_rx.join("phase_b");
    for dir in [&allow_rw_b, &allow_rx_b] {
        seed_probe_files(dir);
        std::fs::create_dir_all(dir.join("dest")).expect("create the move destination");
    }

    // --- 開始前アサート: 祖先が未付与であること（条件(a)の成立条件） ---
    print_chain("before, fs-allow target", &allow_rw, capability.as_psid());
    let created_nodes = [&root, &root.join("a"), &root.join("a").join("b"), &allow_rw];
    for node in created_nodes {
        let sufficient = preview_traverse_chain(node, capability.as_psid())
            .last()
            .is_some_and(|n| n.already_sufficient);
        assert!(
            !sufficient,
            "condition (a) requires an UNGRANTED ancestor chain, but {} already carries a \
             traverse ACE for the capability SID -- the measurement would be meaningless; \
             investigate before re-running",
            node.display()
        );
    }

    // --- CoW redirector DLLの現状（STATUS #7と同じクラスかの判定材料） ---
    let dlls = redirector_dll_paths();
    println!("=== CoW redirector DLL candidates: {} ===", dlls.len());
    for dll in &dlls {
        print_chain("before, redirector DLL", dll, capability.as_psid());
    }

    // --- preflight（＝製品の`--fs-allow`経路そのもの）を通す ---
    let passthrough = vec![
        FsPassthrough {
            path: allow_rw.clone(),
            access: FsAccess::ReadWrite,
            forced: false,
            scope: GrantScope::Recursive,
        },
        FsPassthrough {
            path: allow_rx.clone(),
            access: FsAccess::ReadExec,
            forced: false,
            scope: GrantScope::Recursive,
        },
    ];
    let outcome = preflight(
        &workspace,
        &passthrough,
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("package SID");

    println!("=== D8/D9 as reported by preflight (condition a) ===");
    println!("  granted_passthrough = {:?}", outcome.granted_passthrough);
    if outcome.warnings.is_empty() {
        println!("  warnings: (none) -- D8 did NOT fire");
    }
    for w in &outcome.warnings {
        println!("  warning: {w}");
    }
    for (path, access, reason) in &outcome.denied_passthrough {
        println!("  denied: {} [{access}] {reason}", path.display());
    }

    // [BUG-057の回帰] `--fs-allow`で付与したパスは**session ledgerに載っていなければならない**。
    // 載っていないと`end_session`の自動撤収から漏れ、「fs passthroughはセッション終了で失効する」
    // （D-37の仕様、`docs/STATUS.md`が不変条件として明記）が破れる。
    // `fs-passthrough-ledger.json`（`harness fs revoke`が見る方）には載るので、手動撤収だけは
    // 効く——**自動撤収だけが静かに漏れる**という気付きにくい形の欠陥だった。
    let recorded = crate::tier2a::session_profile::granted_paths_for_current_session();
    println!("=== session ledger after preflight: {recorded:?} ===");
    for fp in &passthrough {
        let path_str = fp.path.to_string_lossy().into_owned();
        assert!(
            recorded.contains(&path_str),
            "BUG-057: {} was granted by preflight but is not in the session ledger, so \
             `end_session` will not revoke it (recorded = {recorded:?})",
            fp.path.display()
        );
    }

    // 条件(d)のプローブツリーへは何も与えない。`never_allowed`はfs-allowにも入れていない。

    // --- CoW redirector DLL: `preflight`のCoW分岐とまったく同じ呼び出しを再現する ---
    //
    // `preflight.rs`は`grant_ace_inheritable_access(&dll, sid, ReadExec)`を呼ぶだけで、
    // 祖先traverseは誰も付けない。ここではその状態のまま読めるかを測り、条件(b)で
    // 祖先を開通させたあとにもう一度測る。**両者の差がSTATUS #7の答えになる。**
    println!("=== redirector DLL: reproducing preflight's CoW-branch grant ===");
    for dll in &dlls {
        println!("  {}", dll.display());
        println!(
            "    session SID ACE before: {:?}",
            crate::tier2a::win_appcontainer::sid_ace_mask(dll, sid.as_psid())
        );
        // [BUG-059の回帰] ファイルを渡しても`Ok`が返ること。修正前はACEを付けた**後**に
        // `collect_dirs_and_files`の`read_dir`が`ERROR_DIRECTORY`(267)で落ちて`Err`になり、
        // `preflight`がそれを失敗扱いにするため撤収経路の無い孤立ACEが残っていた。
        let granted = grant_ace_inheritable_access(dll, sid.as_psid(), FsAccess::ReadExec);
        println!("    grant_ace_inheritable_access -> {granted:?}");
        assert!(
            granted.is_ok(),
            "BUG-059: granting a file must not report failure: {granted:?}"
        );
        // `preflight`のCoW分岐と同じく台帳へ記録する（記録しないと`end_session`で剥がれず、
        // このテスト自身が孤立ACEの発生源になる）。
        crate::tier2a::session_profile::record_granted_path(dll);
        println!(
            "    session SID ACE after : {:?}",
            crate::tier2a::win_appcontainer::sid_ace_mask(dll, sid.as_psid())
        );
    }

    // --- STATUS #7の切り分け: 注入機構抜きでDLLをロードできるか（条件(a)＝祖先未付与） ---
    println!("=== [a] LoadLibraryW from inside the AppContainer (STATUS #7 triage) ===");
    let load_a: Vec<String> = dlls
        .iter()
        .map(|dll| probe_load_library_in_appcontainer("a", sid.as_psid(), &workspace, dll))
        .collect();

    // --- フェーズA: 条件(a) fs-allowのみ / (c) workspace内 / (d) 未許可 / DLL現状 ---
    let mut cells_a = Vec::new();
    for op in &OPS {
        let dir = if op.needs_exec { &allow_rx } else { &allow_rw };
        cells_a.push(Cell {
            condition: "a_fsallow",
            op,
            path: dir.join(op.file.unwrap_or("")),
            dest: dir.join("dest"),
        });
        cells_a.push(Cell {
            condition: "c_workspace",
            op,
            path: control.join(op.file.unwrap_or("")),
            dest: control.join("dest"),
        });
        cells_a.push(Cell {
            condition: "d_unallowed",
            op,
            path: never_allowed.join(op.file.unwrap_or("")),
            dest: never_allowed.join("dest"),
        });
    }
    // read_netfx（`[IO.File]::ReadAllBytes`）はLoadLibraryに最も近い素の読取。
    let dll_read_op = &OPS[1];
    for dll in &dlls {
        cells_a.push(Cell {
            condition: "dll_asis",
            op: dll_read_op,
            path: dll.clone(),
            dest: dll.clone(),
        });
    }

    let mut probe_trees = vec![root.clone()];
    probe_trees.extend(
        dlls.iter()
            .filter_map(|d| d.parent().map(std::path::Path::to_path_buf)),
    );
    let results_a = run_phase("A", sid.as_psid(), &workspace, &cells_a, &probe_trees);

    // --- 条件(b)へ移る: 祖先チェーンへtraverseを付与する（永続。Dropで撤収） ---
    let mut restore = TraverseRestore::new(capability);
    println!("=== granting traverse for condition (b) ===");
    restore.grant_chain(&allow_rw);
    restore.grant_chain(&allow_rx);
    for dll in &dlls {
        restore.grant_chain(dll);
    }
    println!("  newly granted by this test: {:?}", restore.granted_by_us);
    print_chain("after grant", &allow_rw, restore.sid.as_psid());
    for dll in &dlls {
        print_chain("after grant, redirector DLL", dll, restore.sid.as_psid());
    }

    // D9をもう一度撃つ。**W9(BUG-058)の実機確認を兼ねる**——祖先が正常になった状態で
    // 「祖先が無い」と言い続けるなら診断はまだ壊れている。
    println!("=== D8/D9 re-probed after the traverse grant (condition b) ===");
    for fp in &passthrough {
        match probe_passthrough(sid.as_psid(), restore.sid.as_psid(), None, &[], &workspace, fp) {
            None => println!("  {} : reachable (D8 passed)", fp.path.display()),
            Some(diagnosis) => println!("  {} : {diagnosis}", fp.path.display()),
        }
    }

    // --- フェーズB: 条件(b) ---
    let mut cells_b = Vec::new();
    for op in &OPS {
        let dir = if op.needs_exec {
            &allow_rx_b
        } else {
            &allow_rw_b
        };
        cells_b.push(Cell {
            condition: "b_traverse",
            op,
            path: dir.join(op.file.unwrap_or("")),
            dest: dir.join("dest"),
        });
    }
    // 同じDLLをもう一度読む。**`dll_asis`との差だけが祖先traverseの寄与**である
    // （セッションSIDのファイルACEはフェーズAの前に済ませてあり、ここでは変えない）。
    for dll in &dlls {
        cells_b.push(Cell {
            condition: "dll_traverse",
            op: dll_read_op,
            path: dll.clone(),
            dest: dll.clone(),
        });
    }
    println!("=== [b] LoadLibraryW from inside the AppContainer (after ancestor traverse) ===");
    let load_b: Vec<String> = dlls
        .iter()
        .map(|dll| probe_load_library_in_appcontainer("b", sid.as_psid(), &workspace, dll))
        .collect();

    let results_b = run_phase("B", sid.as_psid(), &workspace, &cells_b, &probe_trees);

    // --- 行列 ---
    println!("=== MATRIX (condition x operation) ===");
    println!(
        "  {:<14} {:<12} {:<12} {:<12} {:<12}",
        "op", "a_fsallow", "b_traverse", "c_workspace", "d_unallowed"
    );
    for op in &OPS {
        let cell = |cond: &str, src: &std::collections::BTreeMap<String, String>| {
            src.get(&format!("{cond}|{}", op.name))
                .cloned()
                .unwrap_or_else(|| "(no output)".to_string())
        };
        println!(
            "  {:<14} {:<12} {:<12} {:<12} {:<12}",
            op.name,
            cell("a_fsallow", &results_a),
            cell("b_traverse", &results_b),
            cell("c_workspace", &results_a),
            cell("d_unallowed", &results_a),
        );
    }
    println!("=== redirector DLL (STATUS #7): read via [IO.File]::ReadAllBytes ===");
    println!(
        "  dll_asis   (session SID file ACE only, ancestors NOT granted) = {}",
        results_a
            .get("dll_asis|read_netfx")
            .map(String::as_str)
            .unwrap_or("(no output)")
    );
    println!(
        "  dll_traverse (same file ACE + ancestor traverse)             = {}",
        results_b
            .get("dll_traverse|read_netfx")
            .map(String::as_str)
            .unwrap_or("(no output)")
    );

    println!(
        "HOW TO READ: if a_fsallow FAILs where b_traverse succeeds, the blocker is the ancestor \
         traverse chain that `--fs-allow` never grants -- i.e. W2 option A (add fs-allow ancestors \
         to traverse_targets) closes it. If both FAIL, the leaf mask or something else is the \
         cause and option A would not help."
    );

    println!("=== STATUS #7 triage: LoadLibraryW inside the AppContainer ===");
    for (i, dll) in dlls.iter().enumerate() {
        println!("  {}", dll.display());
        println!(
            "    (a) ancestors NOT granted : {}",
            load_a.get(i).map(String::as_str).unwrap_or("(none)")
        );
        println!(
            "    (b) ancestors granted     : {}",
            load_b.get(i).map(String::as_str).unwrap_or("(none)")
        );
    }
    println!(
        "HOW TO READ #7: `ok:true` in (a) means the AppContainer CAN load this DLL, so the \
         `LoadLibraryW returned NULL` seen by cow_containment_tests comes from the INJECTION \
         mechanism (CreateRemoteThread into a CREATE_SUSPENDED process), not from the DLL or its \
         ACL. `last_error:5` = access/rights, `126` = a dependency is unreachable, `193` = bitness, \
         `1114` = the DLL's own initialisation failed."
    );

    // --- 必須の対照 ---
    // 1) 成功しなければならないセル: workspace内の読み書き・削除・移動。
    //    全滅したら「対象の性質」ではなく測定の不備である。
    for op_name in [
        "read_dotnet",
        "read_netfx",
        "write_dotnet",
        "delete",
        "move",
    ] {
        let key = format!("c_workspace|{op_name}");
        let value = results_a
            .get(&key)
            .map(String::as_str)
            .unwrap_or("(missing)");
        assert!(
            value.starts_with("OK"),
            "control (c) must succeed inside the workspace, but {key} = {value}; the measurement \
             is not valid -- fix the setup before reading anything else in this output"
        );
    }
    // 2) 失敗しなければならないセル: fs-allowしていない深い未付与パスの読取。
    //    成功したら「未付与のつもりが付与済み」＝測定不成立である。
    //    **D-45後も、これはFAILのままでなければならない**——祖先のtraverseは「通過」しか
    //    与えないので、fs-allowしていない兄弟ディレクトリの中身は読めてはいけない。
    //    ここが通り出したらD-45が権限を広げすぎたということである。
    let key = "d_unallowed|read_dotnet".to_string();
    let value = results_a
        .get(&key)
        .map(String::as_str)
        .unwrap_or("(missing)");
    assert!(
        value.starts_with("FAIL"),
        "control (d) must fail on a path that was never granted, but {key} = {value}; something \
         already grants access to {} -- the 'ungranted' premise does not hold",
        never_allowed.display()
    );

    // 3) [D-45の受け入れ] 条件(a)＝`preflight`を通しただけ＝**製品そのもの**で、7操作すべてが
    //    成功しなければならない。D-45以前はここで`delete`と`move`がFAILしていた
    //    （RESULTS.md §19.2）。`--fs-allow`の親を`traverse_targets`へ入れる変更が効いていれば
    //    OKへ変わる。変わらないなら、決定は実装できていない。
    for op_name in [
        "read_dotnet",
        "read_netfx",
        "read_cmd",
        "write_dotnet",
        "delete",
        "move",
        "exec",
    ] {
        let key = format!("a_fsallow|{op_name}");
        let Some(value) = results_a.get(&key) else {
            continue;
        };
        assert!(
            value.starts_with("OK"),
            "D-45 regression: `--fs-allow` alone must now allow every operation, but {key} = \
             {value}. Before D-45 `delete`/`move` failed here because nothing granted traverse to \
             the fs-allow ancestors (RESULTS.md §19.2); if they fail again, preflight's \
             traverse_targets no longer includes the fs-allow parents"
        );
    }

    // [BUG-059の回帰] DLLへ載せたACEは台帳に載っているので、**`end_session`が剥がす**。
    // 修正前はここで明示的に剥がしていた——テスト側で手当てしていたということは、製品側では
    // 誰も剥がしていなかったということである（実機に4件残留していた）。
    println!("=== end_session must revoke the redirector DLL ACEs by itself ===");
    let _ = crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );
    for dll in &dlls {
        let remaining = crate::tier2a::win_appcontainer::sid_ace_mask(dll, sid.as_psid());
        println!("  {} -> {remaining:?}", dll.display());
        assert!(
            matches!(remaining, Ok(None)),
            "BUG-059: end_session must remove this session's ACE from {} but it is still \
             there ({remaining:?}) -- that is exactly how the 4 orphaned ACEs accumulated",
            dll.display()
        );
    }
    println!("=== restoring machine state ===");
    drop(restore);
    for dll in &dlls {
        print_chain(
            "after restore, redirector DLL",
            dll,
            capability_check.as_psid(),
        );
    }
    let _ = std::fs::remove_dir_all(&root);

    // **D-45以降、祖先traverseを付けるのは`preflight`自身**（`TraverseRestore`ではない）。
    // その付与は`traverse_ledger`へ永続記録されるが、プローブツリーはたった今消したので、
    // 残せば「実在しないパスを指すエントリ」＝phantomになる（実際にW1の測定は2件残した）。
    // 台帳は「harnessがACEを付けた場所」の記録なので、対象が消えた時点で記録も消す。
    let root_prefix = root.to_string_lossy().to_ascii_lowercase();
    for entry in crate::tier2a::traverse_ledger::load_traverse_ledger().entries {
        if entry.path.to_ascii_lowercase().starts_with(&root_prefix) {
            println!(
                "  pruning traverse-ledger entry for the deleted probe tree: {}",
                entry.path
            );
            crate::tier2a::traverse_ledger::remove_traverse_grant(std::path::Path::new(
                &entry.path,
            ));
        }
    }
}
