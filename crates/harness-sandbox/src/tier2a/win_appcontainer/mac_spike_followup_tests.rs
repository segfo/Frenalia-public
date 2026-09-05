//! **MAC/Spawn Daemon設計の実現性スパイク（追測: S1b・S2c・S2d）**。結果の正本は
//! `plans/mac-spike/RESULTS.md`。
//!
//! バッチ1・2の結果を受けて、**設計の分岐点に直接効く3つ**を測る。
//!
//! | # | 問い | これで決まること |
//! |---|---|---|
//! | S1b | コンソール無し／継承で、実際のツール（pwsh7・node・git・cargo）は動くか。シェルの失敗はAppContainer固有か | mitigation下のコンソール設計（§7.1） |
//! | S2c | トークンの**既定DACL**を差し替えれば、後から生えるスレッド／オブジェクトにも効くか | **案A**（同一package SIDのままドメイン分離できるか） |
//! | S2d | capability SID宛のACEは**別package SIDから**も効くか。プロファイル生成のコストは | **案B**（ドメインごとに別package SID）の実現可能性と費用 |
//!
//! S2dは**将来のためのプリフェッチ**である。§22.8はドメインごとの別package SIDを
//! 「traverse・workspace ACEがドメイン数倍になる」という理由で却下したが、その後の決定で
//! ACEの宛先SIDは全部capability SIDへ移った（D-37・D-54・§22.3）。**capability SID宛のACEが
//! package SIDに依存しないなら、却下理由の大半は消える**——それをいま測っておけば、
//! 将来ここへ戻ってきたときに測り直さずに済む。
//!
//! 実行（**昇格しないこと**）:
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture mac_spike_followup_tests
//! ```

use super::mac_spike_tests::{
    forget_workspace_capability, last_json_line, probe_exe, workspace_capability_for, SpikeConsole,
    SpikeSpawn,
};
use super::*;

/// このテストが的にする実ツール。**見つからないものは黙って飛ばさず、見つからなかったと出す**
/// （B-10。「測っていない」と「動かなかった」を同じ空欄にしない）。
fn tools_under_test() -> Vec<(String, String, Vec<String>)> {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let mut tools: Vec<(String, String, Vec<String>)> = Vec::new();

    // 既定シェル（このマシンでは Windows PowerShell 5.1 へフォールバックしている）。
    let (shell, label) = resolve_shell();
    tools.push((
        label.to_string(),
        shell,
        vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "Write-Output TOOL-RAN; exit 7".into(),
        ],
    ));

    // pwsh 7。**このマシンではMSIX（ストア）版**なので、入口が2つある。
    //
    // - `%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`: 実行エイリアス（**0バイトの
    //   reparse point**）。`resolve_shell`はこれを避ける——「AppContainerから解決できず
    //   `CreateProcessW`が`ERROR_INVALID_PARAMETER`で失敗する」とdocに書いてある
    // - `C:\Program Files\WindowsApps\Microsoft.PowerShell_<ver>_x64__8wekyb3d8bbwe\pwsh.exe`:
    //   パッケージの実体
    //
    // **両方を測る。** docの記述は文書であって実コードの実測ではないうえ、
    // 「エイリアスが駄目」と「pwsh 7自体が駄目」は別の話であり、
    // 実体で動くならmitigation下のシェルとして使える可能性が残る。
    let pwsh_args = vec![
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        "Write-Output TOOL-RAN; exit 7".to_string(),
    ];
    let alias = format!(
        "{}\\Microsoft\\WindowsApps\\pwsh.exe",
        std::env::var("LOCALAPPDATA").unwrap_or_default()
    );
    if std::path::Path::new(&alias).exists() {
        tools.push(("pwsh7-alias".into(), alias, pwsh_args.clone()));
    } else {
        eprintln!("[S1b] pwsh7の実行エイリアスが無いので測定対象から外した");
    }
    match msix_pwsh_path() {
        Some(real) => tools.push(("pwsh7-msix実体".into(), real, pwsh_args.clone())),
        None => eprintln!("[S1b] pwsh7のMSIX実体を特定できなかったので測定対象から外した"),
    }
    for candidate in [
        format!("{}\\PowerShell\\7\\pwsh.exe", program_files()),
        format!("{}\\PowerShell\\7-preview\\pwsh.exe", program_files()),
    ] {
        if std::path::Path::new(&candidate).exists() {
            tools.push(("pwsh7-msi".into(), candidate, pwsh_args.clone()));
            break;
        }
    }

    tools.push((
        "cmd".into(),
        format!("{system_root}\\System32\\cmd.exe"),
        vec!["/c".into(), "echo TOOL-RAN".into()],
    ));

    for (label, exe, args) in [
        (
            "node",
            "node",
            vec!["-e".to_string(), "console.log('TOOL-RAN')".to_string()],
        ),
        ("git", "git", vec!["--version".to_string()]),
        ("cargo", "cargo", vec!["--version".to_string()]),
    ] {
        match which::which(exe) {
            Ok(path) => tools.push((label.into(), path.to_string_lossy().into_owned(), args)),
            Err(_) => eprintln!("[S1b] {label} はこのマシンに無いので測定対象から外した"),
        }
    }
    tools
}

fn program_files() -> String {
    std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string())
}

/// MSIX（ストア）版 pwsh 7 の**実体**のパス。
///
/// `C:\Program Files\WindowsApps`はDACLで列挙が拒否されるが、**パッケージのディレクトリ名を
/// 知っていれば`Test-Path`は通る**（実測）。名前はバージョンを含むので、ここでは既知の
/// 発行者ID（`8wekyb3d8bbwe`）で候補を組み立てて実在するものを採る。見つからなければ`None`。
fn msix_pwsh_path() -> Option<String> {
    let root = format!("{}\\WindowsApps", program_files());
    // 列挙できる環境ならそれが一番確実（できない環境では下の`Get-AppxPackage`へ落ちる）。
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("Microsoft.PowerShell_") && name.ends_with("_x64__8wekyb3d8bbwe") {
                let exe = format!("{root}\\{name}\\pwsh.exe");
                if std::path::Path::new(&exe).exists() {
                    return Some(exe);
                }
            }
        }
    }
    // 列挙できない場合は`Get-AppxPackage`に聞く（非昇格で通る）。
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-AppxPackage Microsoft.PowerShell).InstallLocation",
        ])
        .output()
        .ok()?;
    let location = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if location.is_empty() {
        return None;
    }
    let exe = format!("{location}\\pwsh.exe");
    std::path::Path::new(&exe).exists().then_some(exe)
}

/// S1b: mitigation下でどのコンソール構成なら実ツールが動くか。
///
/// **AppContainerの有無も軸に入れる**——シェルがコンソール無しで何もしないのが
/// AppContainer固有なのかWindows一般なのかで、設計の逃がし方が変わる（B-29）。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s1b_which_console_setup_lets_real_tools_run_under_the_mitigation() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut caps: Vec<PSID> = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps.push(cap.as_psid());
    }

    let mut rows: Vec<String> = Vec::new();
    for (label, exe, args) in tools_under_test() {
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        for (world, no_appcontainer) in [("AppContainer", false), ("素のユーザー", true)] {
            for restricted in [false, true] {
                for console in [
                    SpikeConsole::NoWindow,
                    SpikeConsole::Detached,
                    SpikeConsole::Inherit,
                ] {
                    let spawned = SpikeSpawn {
                        exe: &exe,
                        args: &args_ref,
                        cwd: workspace.path(),
                        container_sid: sid.as_psid(),
                        capabilities: &caps,
                        child_process_restricted: restricted,
                        stdout_override: None,
                        extra_inherit: &[],
                        process_sddl: None,
                        thread_sddl: None,
                        token_default_dacl_sddl: None,
                        no_appcontainer,
                        console,
                    }
                    .spawn();
                    let row = match spawned {
                        Ok(mut child) => {
                            let (out, err, code) = child.wait_and_read();
                            let ran = out.contains("TOOL-RAN")
                                || out.contains("git version")
                                || out.contains("cargo ");
                            format!(
                                "{label:14} {world:12} restricted={restricted:5} console={console:?}\
                                 \t走った={ran:5} exit={code} (0x{:08X}) out={:?} err={:?}",
                                code as u32,
                                out.chars().take(60).collect::<String>(),
                                err.chars().take(60).collect::<String>(),
                            )
                        }
                        Err(e) => format!(
                            "{label:14} {world:12} restricted={restricted:5} console={console:?}\
                             \tspawn失敗: {e}"
                        ),
                    };
                    eprintln!("[S1b] {row}");
                    rows.push(row);
                }
            }
        }
    }

    // この行列そのものが結論なので、assertは**測定が成立したこと**だけを守る（B-27）。
    assert!(
        rows.len() >= 12,
        "測定行が少なすぎる（ツールが1つも見つからなかった可能性）: {}",
        rows.len()
    );
}

/// S2c（**案A**）: トークンの既定DACLを差し替えると、後から生えるスレッドと
/// 後から作られる名前付きオブジェクトにも効くか。
///
/// 対で測る（B-35）——**同じドメイン**（同じcapabilityを持つ）からは開けること、
/// **別ドメイン**からは開けないこと。前者が壊れると、ツールが自分の子と共有するオブジェクトが
/// 開けなくなり互換性を壊す。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s2c_swapping_the_token_default_dacl_closes_the_later_object_hole() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // ドメインAの capability（＝このドメインの身分証）。既定DACLにはこれだけを載せる。
    let domain_a = super::capability_sid_from_name(&format!(
        "harness-mac-spike-domainA-{}",
        std::process::id()
    ))
    .expect("derive domain A capability");
    let domain_a_sid_str =
        crate::win_common::sid_to_string(domain_a.as_psid()).expect("domain A sid string");
    let user_sid = crate::win_pipe_ipc::current_user_sid_string().expect("current user sid");
    // 既定DACL: ユーザー（Daemon役が触れるように）＋ドメインAのcapability。**package SIDは載せない**。
    let default_dacl = format!("D:(A;;GA;;;{user_sid})(A;;GA;;;{domain_a_sid_str})");

    let mut caps_a: Vec<PSID> = vec![traverse.as_psid(), domain_a.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps_a.push(cap.as_psid());
    }

    let report = workspace.path().join("s2c-target.json");
    let report_str = report.to_string_lossy().into_owned();
    let target = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--idle-secs",
            "20",
            "--timeout-secs",
            "60",
            "--report-file",
            &report_str,
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_a,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        // プロセスと最初のスレッドはS2bで塞げることが分かっているので、同じSDDLで塞ぐ。
        process_sddl: Some(&default_dacl),
        thread_sddl: Some(&default_dacl),
        // **本題**: 後から生えるものに効かせるための既定DACL差し替え。
        token_default_dacl_sddl: Some(&default_dacl),
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the domain-A target (既定DACL差し替えが失敗したらここでErrになる)");

    let mut extra_tid: u64 = 0;
    let mut extra_mutex = String::new();
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(&report) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                extra_tid = v
                    .get("extra_thread_id")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                extra_mutex = v
                    .get("extra_mutex")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                if extra_tid != 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        extra_tid != 0,
        "的が後から生やしたスレッドのIDを報告しなかった"
    );
    eprintln!(
        "[S2c] 的: pid={} 後発tid={extra_tid} 後発mutex={extra_mutex:?}",
        target.pid()
    );

    let reach_args: Vec<String> = vec![
        "--reach-process".into(),
        target.pid().to_string(),
        "--reach-thread".into(),
        target.thread_id().to_string(),
        "--reach-thread".into(),
        extra_tid.to_string(),
        "--reach-object".into(),
        format!("mutex:{extra_mutex}"),
        "--timeout-secs".into(),
        "60".into(),
    ];
    let reach_args_ref: Vec<&str> = reach_args.iter().map(|s| s.as_str()).collect();

    // 攻撃側2種: 別ドメイン（capabilityを持たない）と、同じドメイン（capabilityを持つ）。
    let mut results: Vec<(&str, serde_json::Value)> = Vec::new();
    for (label, caps) in [
        ("別ドメイン", vec![traverse.as_psid()]),
        ("同じドメイン", vec![traverse.as_psid(), domain_a.as_psid()]),
    ] {
        let mut attacker = SpikeSpawn {
            exe: &probe_str,
            args: &reach_args_ref,
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities: &caps,
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            console: SpikeConsole::NoWindow,
        }
        .spawn()
        .expect("spawn the attacker");
        let (out, err, _) = attacker.wait_and_read();
        eprintln!("[S2c] {label}: {out}\nstderr={err}");
        let v = last_json_line(&out)
            .unwrap_or_else(|| panic!("{label}のプローブがJSONを出さなかった: {out}"));
        results.push((label, v));
    }
    drop(target);

    let ok_of = |v: &serde_json::Value, kind: &str, access: &str, target: &str| -> Option<bool> {
        super::mac_spike_tests::reach_attempt_ok(v, kind, access, Some(target))
    };
    let other = &results[0].1;
    let same = &results[1].1;
    let extra_tid_s = extra_tid.to_string();
    let mutex_target = format!("mutex:{extra_mutex}");

    eprintln!(
        "[S2c] 別ドメイン: 後発スレッド={:?} 後発mutex={:?} プロセス={:?}",
        ok_of(other, "thread", "THREAD_ALL_ACCESS", &extra_tid_s),
        ok_of(other, "named-object", "mutex", &mutex_target),
        ok_of(
            other,
            "process",
            "PROCESS_VM_WRITE",
            &target_pid_string(&results)
        ),
    );
    eprintln!(
        "[S2c] 同じドメイン: 後発スレッド={:?} 後発mutex={:?}",
        ok_of(same, "thread", "THREAD_ALL_ACCESS", &extra_tid_s),
        ok_of(same, "named-object", "mutex", &mutex_target),
    );

    // **案Aの成否はこの1行で決まる。**
    assert_eq!(
        ok_of(other, "thread", "THREAD_ALL_ACCESS", &extra_tid_s),
        Some(false),
        "既定DACLを差し替えても、別ドメインから**後から生えたスレッド**を開けてしまう。\
         案Aでは§22.8の穴を塞げない（案Bへ行く必要がある）。report={other}"
    );
    // **案Aの限界（実測）**: スレッドには効くが、**名前付きカーネルオブジェクトには効かない**。
    // AppContainerの名前付きオブジェクトは package SID ごとの専用ディレクトリ
    // （`\Sessions\N\AppContainerNamedObjects\<package SID>`）に作られ、そこに置かれた
    // オブジェクトへは同じpackage SIDの別ドメインから到達できる。トークンの既定DACLを
    // 差し替えてもここは閉じなかった。**測った事実をそのまま固定する**（逆転したら測り直す合図）。
    assert_eq!(
        ok_of(other, "named-object", "mutex", &mutex_target),
        Some(true),
        "別ドメインから名前付きmutexが開けなくなった。RESULTS.md §S2cの結論\
         （案Aはプロセス/スレッドには効くが名前付きオブジェクトには効かない）を測り直すこと。\
         report={other}"
    );
    // **互換性の対**（B-35）: 同じドメインからは今までどおり開けること。ここが壊れると、
    // ツールが自分の子と共有するオブジェクトが開けなくなり、案Aは可用性を壊す。
    assert_eq!(
        ok_of(same, "thread", "THREAD_ALL_ACCESS", &extra_tid_s),
        Some(true),
        "同じドメイン（同じcapability）からも後発スレッドを開けなくなった。\
         案Aは同一ドメイン内の共有まで壊すので、このままでは使えない。report={same}"
    );
}

/// `--reach-process`の的として渡したPIDを、レポートから引き直す（表示用）。
fn target_pid_string(results: &[(&str, serde_json::Value)]) -> String {
    results
        .first()
        .and_then(|(_, v)| v.get("attempts"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.get("target"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string()
}

/// S2d（**案Bのプリフェッチ**）: ドメインごとに別package SIDにしたとき、
/// §22.8が却下理由に挙げたコストが本当に掛かるのか。
///
/// 測るのは2点。
///
/// 1. **capability SID宛のACEは別package SIDからも効くか**（効くなら、FSのACEは
///    ドメイン数倍にならない＝却下理由の大半が消える）
/// 2. プロファイルを1つ増やす実コスト（`ensure_profile`の所要時間）
#[test]
#[ignore = "creates extra AppContainer profiles (deleted by the test); run NON-elevated with --test-threads=1"]
fn s2d_per_domain_package_sids_do_not_multiply_the_fs_aces() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");

    // ドメイン専用のcapabilityと、その宛先のACEを1本だけ張ったファイル。
    let domain_cap =
        super::capability_sid_from_name(&format!("harness-mac-spike-domB-{}", std::process::id()))
            .expect("derive domain capability");
    let secret = workspace.path().join("s2d-secret.txt");
    std::fs::write(&secret, "SECRET_FOR_DOMAIN").expect("seed");
    grant_ace_mask_for_test(
        workspace.path(),
        domain_cap.as_psid(),
        FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
        windows::Win32::Security::ACE_FLAGS(0),
    )
    .expect("grant traverse");
    grant_ace_mask_for_test(
        &secret,
        domain_cap.as_psid(),
        FILE_GENERIC_READ.0 | FILE_TRAVERSE.0,
        windows::Win32::Security::ACE_FLAGS(0),
    )
    .expect("grant read");

    // ドメインごとの専用プロファイル（＝案Bの姿）を2つ作る。
    let mut profiles: Vec<(String, OwnedContainerSid, u128)> = Vec::new();
    for domain in ["doma", "domb"] {
        let name = format!("harness.macspike.{domain}.{}", std::process::id());
        let started = std::time::Instant::now();
        let sid = super::ensure_profile_for_test(&name).expect("create the domain profile");
        let elapsed = started.elapsed().as_millis();
        eprintln!("[S2d] プロファイル {name} を作成: {elapsed}ms");
        profiles.push((name, sid, elapsed));
    }
    // 後始末は判定より先に登録する（assertで落ちてもプロファイルを残さない）。
    let names: Vec<String> = profiles.iter().map(|(n, _, _)| n.clone()).collect();
    let _profile_guard = super::test_support::scopeguard(move || unsafe {
        for name in &names {
            let w = wide(name);
            let _ =
                windows::Win32::Security::Isolation::DeleteAppContainerProfile(PCWSTR(w.as_ptr()));
        }
    });

    let (shell, _) = resolve_shell();
    let command = format!(
        "try {{ Write-Output (Get-Content -Path '{}' -Raw -ErrorAction Stop) }} \
         catch {{ Write-Output DENIED }}",
        secret.display()
    );
    let mut table: Vec<(String, bool, bool)> = Vec::new();
    for (name, profile_sid, _) in &profiles {
        for (with_cap, label) in [(true, "capabilityあり"), (false, "capabilityなし")] {
            let mut caps: Vec<PSID> = vec![traverse.as_psid()];
            if with_cap {
                caps.push(domain_cap.as_psid());
            }
            let mut child = SpikeSpawn {
                exe: &shell,
                args: &["-NoProfile", "-NonInteractive", "-Command", &command],
                cwd: workspace.path(),
                container_sid: profile_sid.as_psid(),
                capabilities: &caps,
                child_process_restricted: false,
                stdout_override: None,
                extra_inherit: &[],
                process_sddl: None,
                thread_sddl: None,
                token_default_dacl_sddl: None,
                no_appcontainer: false,
                console: SpikeConsole::NoWindow,
            }
            .spawn()
            .expect("spawn the per-domain child");
            let (out, err, _) = child.wait_and_read();
            let read_ok = out.contains("SECRET_FOR_DOMAIN");
            eprintln!("[S2d] {name} / {label}: 読めた={read_ok} out={out:?} err={err:?}");
            table.push((format!("{name}/{label}"), with_cap, read_ok));
        }
    }

    let creation_ms: Vec<u128> = profiles.iter().map(|(_, _, ms)| *ms).collect();
    eprintln!("[S2d] プロファイル作成コスト: {creation_ms:?} ms");

    // **プリフェッチの本題**: capability宛ACEはpackage SIDに依存しないこと。
    for (label, with_cap, read_ok) in &table {
        if *with_cap {
            assert!(
                *read_ok,
                "capability SID宛のACEが、別のpackage SIDのプロファイルからは効かなかった（{label}）。\
                 案B（ドメインごとに別package SID）はFSのACEをドメイン数倍にすることになり、\
                 §22.8の却下理由が今も有効ということになる。table={table:?}"
            );
        } else {
            assert!(
                !*read_ok,
                "capabilityを積んでいないのに読めた（{label}）。測定の前提が崩れている。table={table:?}"
            );
        }
    }
}
