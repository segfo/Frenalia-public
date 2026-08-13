//! **§22.1.1（案A: `TokenDefaultDacl`差し替え）の受け入れ測定**。
//!
//! 効くこと自体は実現性スパイクで測ってある（`plans/mac-spike/RESULTS.md` §S2c）が、
//! あれは`SpikeSpawn`——`spawn_impl`の必要部分をコピーした測定用の起動器——での測定である。
//! ここで測るのは**本番の`spawn_with_workspace`経由**で同じ分離が成立することで、
//! 「スパイクでは効いたが本番の配線では効いていない」を検出する（B-08: 1経路の確認を
//! 網羅の証明にしない）。
//!
//! **対で測る**（B-35）——別ドメインからは開けないことと、**同じドメインからは開ける**ことの
//! 両方を見る。後者が壊れると、ツールが自分の子とオブジェクトを共有できなくなる（互換性の破壊）。
//! 拒否側だけを見るテストは、機構が効きすぎて全部拒否になっているときも緑になる。
//!
//! 実行（**昇格しないこと**。昇格するとホストのトークンが変わり、測る世界が実運用とずれる。B-08）:
//!
//! ```text
//! cargo build -p tier2a-proc-probe
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture domain_isolation_tests
//! ```

use super::mac_spike_tests::{last_json_line, probe_exe};
use super::*;

/// 1回の`OpenProcess`/`OpenThread`試行の結果（`(種別, アクセスマスク名, 開けたか, last_error)`）。
type ReachAttempt = (String, String, bool, u64);

/// 的の`OpenProcess`/`OpenThread`結果を、攻撃側のドメインごとに集めた形。
fn reach_attempts(report: &serde_json::Value) -> Vec<ReachAttempt> {
    report
        .get("attempts")
        .and_then(|a| a.as_array())
        .map(|attempts| {
            attempts
                .iter()
                .map(|a| {
                    (
                        a.get("kind").and_then(|k| k.as_str()).unwrap_or("").into(),
                        a.get("access")
                            .and_then(|k| k.as_str())
                            .unwrap_or("")
                            .into(),
                        a.get("ok").and_then(|k| k.as_bool()).unwrap_or(false),
                        a.get("last_error").and_then(|k| k.as_u64()).unwrap_or(0),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 本番経路で起こした子のプロセスオブジェクトのDACLをSDDLで読む。
///
/// **ホスト（テストプロセス）から開けること自体が測定対象**でもある——§22.1.1が
/// 「ユーザーSIDは載せる」と決めたのは、harness自身・昇格した収集器が引き続き子を
/// 開けるようにするためで、ここが開けなければその決定が実装に届いていない。
fn process_object_sddl(pid: u32) -> String {
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    unsafe {
        // `READ_CONTROL`（DACLを読む権利）を足す。`PROCESS_QUERY_INFORMATION`だけでは
        // `GetSecurityInfo`が`ERROR_ACCESS_DENIED`になる。
        const READ_CONTROL: u32 = 0x0002_0000;
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(READ_CONTROL),
            false,
            pid,
        )
        .expect(
            "the host (running as the user) must still be able to open the child — \
             §22.1.1 puts the user SID into the DACL exactly for this",
        );
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()
        .expect("GetSecurityInfo(process DACL)");
        let mut out = windows::core::PWSTR::null();
        let mut len: u32 = 0;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            Some(&mut len),
        )
        .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW");
        let sddl = out.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(out.0 as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
        let _ = CloseHandle(handle);
        sddl
    }
}

/// **本番経路**（`spawn_with_workspace`）で起こした子に対し、同一package SIDの
/// 別ドメインからは`OpenProcess`/`OpenThread`が通らず、同じドメインからは通ること。
///
/// **後から生えたスレッド**を的に含めるのが肝である（§S2b）。プロセスと最初のスレッドは
/// `lpProcessAttributes`/`lpThreadAttributes`だけでも塞がるが、起動後に生えたスレッドは
/// トークンの既定DACL由来なので、`SetTokenInformation`（挿入点2）が抜けているとここだけが開く。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn the_production_spawn_path_closes_cross_domain_process_and_thread_access() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let sid = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile");
    let canonical = workspace
        .path()
        .canonicalize()
        .unwrap_or_else(|_| workspace.path().to_path_buf());
    // ドメインA＝このworkspaceのcapability（本番のシェルが使うのと同じ導出、D-54）。
    let cap_a = super::workspace_capability_sid(&canonical, "rwx").expect("workspace capability");
    // ドメインB＝別のcapability。**同じpackage SID**のまま、ドメインだけが違う状態を作る
    // ——§S2が「素通りする」と実測したのがこの構成である。
    let cap_b = super::capability_sid_from_name(&format!(
        "harness-domain-isolation-b-{}",
        std::process::id()
    ))
    .expect("derive domain B capability");

    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let report = workspace.path().join("domain-isolation-target.json");
    let report_str = report.to_string_lossy().into_owned();
    let env = crate::secret_env::build_child_env();

    let target = spawn_with_workspace(
        &probe_str,
        &[
            "--idle-secs",
            "20",
            "--timeout-secs",
            "60",
            "--report-file",
            &report_str,
        ],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
        Some(cap_a.as_psid()),
        DomainIdentity::Capability(cap_a.as_psid()),
    )
    .expect("spawn the domain-A target through the production path");
    let target_pid = target.pid();

    // 後から生えたスレッドのIDを的にするため、プローブが報告するまで待つ。
    let mut extra_tid: u64 = 0;
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(&report) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                extra_tid = v
                    .get("extra_thread_id")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                if extra_tid != 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_ne!(
        extra_tid, 0,
        "的のプローブが「後から生えたスレッド」を報告しなかった（測定が成立していない）"
    );

    // §22.1.1 受け入れ2: プロセスオブジェクトのDACLの外形。
    let sddl = process_object_sddl(target_pid);
    let package_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package sid string");
    let cap_a_sid = crate::win_common::sid_to_string(cap_a.as_psid()).expect("cap A sid string");
    eprintln!("[C] target process DACL = {sddl}");
    assert!(
        sddl.contains(&cap_a_sid),
        "ドメイン識別capability宛のACEが無い（DACLが差し替わっていない）: {sddl}"
    );
    assert!(
        !sddl.contains(&package_sid),
        "package SID宛のACEが残っている＝同一package SIDの別ドメインから開ける: {sddl}"
    );

    let reach_args: Vec<String> = vec![
        "--reach-process".into(),
        target_pid.to_string(),
        "--reach-thread".into(),
        extra_tid.to_string(),
        "--timeout-secs".into(),
        "60".into(),
    ];
    let reach_args_ref: Vec<&str> = reach_args.iter().map(|s| s.as_str()).collect();

    let mut results: Vec<(&str, Vec<ReachAttempt>)> = Vec::new();
    for (label, cap) in [("別ドメイン", &cap_b), ("同じドメイン", &cap_a)] {
        let attacker = spawn_with_workspace(
            &probe_str,
            &reach_args_ref,
            workspace.path(),
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
            None,
            Some(cap.as_psid()),
            DomainIdentity::Capability(cap.as_psid()),
        )
        .unwrap_or_else(|e| panic!("spawn the {label} attacker: {e}"));
        let (out, err, _) = attacker
            .write_stdin_read_output_and_wait(None)
            .expect("read the attacker output");
        eprintln!("[C] {label}: {out}\nstderr={err}");
        let report = last_json_line(&out)
            .unwrap_or_else(|| panic!("{label}のプローブがJSONを出さなかった: {out}"));
        results.push((label, reach_attempts(&report)));
    }
    target.kill();

    let cross = &results[0].1;
    let same = &results[1].1;
    assert!(
        !cross.is_empty() && cross.len() == same.len(),
        "両側で同じ数の試行を測れていない: cross={cross:?} same={same:?}"
    );

    // 別ドメイン: 全マスクが拒否（5＝ACCESS_DENIED）であること。
    for (kind, access, ok, last_error) in cross {
        assert!(
            !ok,
            "別ドメインから {kind}({access}) が開けた——ドメイン分離が成立していない"
        );
        assert_eq!(
            *last_error, 5,
            "別ドメインの {kind}({access}) は ACCESS_DENIED(5) で拒否されるべき（実測 {last_error}）"
        );
    }

    // 同じドメイン: 開けること（**この対が無いと、機構が効きすぎている場合も緑になる**、B-35）。
    for (kind, access, ok, last_error) in same {
        assert!(
            ok,
            "同じドメインから {kind}({access}) が開けない（last_error={last_error}）——\
             ツールが自分の子とオブジェクトを共有できなくなる"
        );
    }
}
