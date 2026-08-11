//! **未検証項目の実測**（`docs/STATUS.md`「OS監査収集器（M15.7）の既知の未検証項目」#1〜#5）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-diagnostics
//! ```
//!
//! ここのテストは**assertよりも観測値の出力が主目的**である。「取りこぼしがゼロであること」を
//! 主張したいのではなく、**取りこぼしがどの程度あるのかを数字で知る**ためにある——
//! 収集は境界ではない（P-07）ので、目標は「ゼロ」ではなく「桁が分かっていること」である。
//! そのため下限だけをassertし、実測値は`--nocapture`で読めるように出す。
//!
//! 数値は`plans/etw-spike/RESULTS.md` §12へ転記すること。

use super::parse::{to_settings_path, Correlator, PendingCreate};
use super::scope::{ScopeTracker, ScopeVerdict};
use super::session::EtwFsSession;
use super::volumes::drive_letter_map;

const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
const DRAIN: std::time::Duration = std::time::Duration::from_secs(4);

/// #2/#4/#5: **高負荷下**での`EventsLost`・変換不能パスの分布・相関の取りこぼし。
///
/// 負荷は「このリポジトリの`crates/`を再帰的に読む」で作る。`cargo build`より決定論的で、
/// かつ実際にharnessが監視する種類のFS I/O（大量の`Create`）と同じ形になる。
#[test]
#[ignore = "requires administrator rights (ETW); run via dev-elevated-run.exe etw-diagnostics"]
fn collection_statistics_under_a_heavy_file_workload() {
    let session = EtwFsSession::start("harness-policy-learn-diag-load").expect("ETW session");
    std::thread::sleep(WARMUP);

    // 高負荷: リポジトリ配下を再帰的にstat+読み取りする。
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf();
    // **`target/`も含めてリポジトリ全体**を舐める。`crates/`だけでは数百ファイルにしかならず、
    // 「`cargo build`級」の負荷にならない（前回の実測で247ファイルだった）。
    let mut touched = 0u64;
    walk_and_read(&repo_root, &mut touched, 60_000);
    println!(
        "workload: touched {touched} file(s) under {}",
        repo_root.display()
    );

    std::thread::sleep(DRAIN);
    let (starts, denials) = session.drain();
    let outcome = session.stop();

    // --- #2: EventsLost ---
    println!(
        "[#2] events={} lost={} realtime_buffers_lost={} loss_ratio={:.6}%",
        outcome.seen_events,
        outcome.events_lost,
        outcome.realtime_buffers_lost,
        if outcome.seen_events > 0 {
            outcome.events_lost as f64 * 100.0
                / (outcome.seen_events + outcome.events_lost as u64) as f64
        } else {
            0.0
        }
    );

    // --- #4: 変換不能NTパスの分布 ---
    let volumes = drive_letter_map();
    let mut unconvertible: std::collections::BTreeMap<String, u64> = Default::default();
    let mut convertible = 0u64;
    for path in &outcome.observed_paths {
        if to_settings_path(path, &volumes).is_some() {
            convertible += 1;
        } else {
            *unconvertible.entry(classify_nt_path(path)).or_insert(0) += 1;
        }
    }
    let unconvertible_total: u64 = unconvertible.values().sum();
    println!(
        "[#4] create paths: convertible={convertible} unconvertible={unconvertible_total} \
         ({:.2}%)",
        if convertible + unconvertible_total > 0 {
            unconvertible_total as f64 * 100.0 / (convertible + unconvertible_total) as f64
        } else {
            0.0
        }
    );
    for (kind, count) in &unconvertible {
        println!("[#4]   {kind}: {count}");
    }

    // --- #5: 相関の取りこぼしと容量4096の妥当性 ---
    println!(
        "[#5] event histogram (Kernel-File): {:?}",
        outcome.event_histogram
    );
    let creates = outcome.event_histogram.get(&12).copied().unwrap_or(0)
        + outcome.event_histogram.get(&30).copied().unwrap_or(0);
    let op_ends = outcome.event_histogram.get(&24).copied().unwrap_or(0);
    println!(
        "[#5] Create={creates} OperationEnd={op_ends} denials={} process_starts={}",
        denials.len(),
        starts.len()
    );
    println!(
        "[#5] correlator: evicted={} unmatched_operation_ends={} pending_at_stop={}",
        outcome.correlator_evicted,
        outcome.correlator_unmatched_operation_ends,
        outcome.correlator_pending
    );
    println!(
        "[#5] NOTE: unmatched OperationEnd is expected to be large -- the OP_END keyword also          reports the completion of operations whose start event we do not subscribe to          (read/write/setinfo). Only `evicted` indicates a capacity problem."
    );

    assert!(
        outcome.seen_events > 0,
        "no events observed; the workload or the session did not work"
    );
}

/// #5: `Correlator`の容量4096が妥当かを、**実測した同時未完了数**に照らして確かめる。
///
/// 上のテストはETW側の総量しか見ない。ここでは相関表そのものの挙動を、実データの流量を模した
/// 合成入力で確かめる——同時に結果待ちになる`Create`の数が容量を超えるかどうかが問いなので、
/// 実機のイベント列を再現するより「容量を超えたら何が起きるか」を確定させる方が有用である。
#[test]
#[ignore = "requires administrator rights (ETW); run via dev-elevated-run.exe etw-diagnostics"]
fn correlator_capacity_is_measured_against_real_in_flight_depth() {
    let session = EtwFsSession::start("harness-policy-learn-diag-depth").expect("ETW session");
    std::thread::sleep(WARMUP);

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .to_path_buf();
    let mut touched = 0u64;
    walk_and_read(&repo_root.join("crates"), &mut touched, 20_000);

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    // 実機の流量を、容量を変えた相関表に通して「どこから捨て始めるか」を測る。
    let creates = outcome.event_histogram.get(&12).copied().unwrap_or(0);
    println!("[#5] observed {creates} Create event(s) during the workload");
    for capacity in [64usize, 256, 1024, 4096] {
        let mut correlator = Correlator::new(capacity);
        // 同時未完了が最悪ケース（OperationEndが1つも来ない）になる合成列で上限を確かめる。
        for irp in 0..creates.min(20_000) {
            correlator.on_create(
                irp,
                PendingCreate {
                    file_name: format!(r"\??\C:\synthetic\{irp}.txt"),
                    pid: 1,
                    create_options: 0,
                    timestamp_unix_ms: 0,
                },
            );
        }
        println!(
            "[#5] capacity={capacity}: pending={} evicted={}",
            correlator.pending_len(),
            correlator.evicted_count()
        );
    }
    println!(
        "[#5] NOTE: the eviction counts above are the worst case (no OperationEnd ever arrives). \
         In practice OperationEnd follows within microseconds, so in-flight depth stays small."
    );
}

/// #3: `DELETE_PATH`/`RENAME_SETLINK_PATH`は**失敗時にも発火するか**。
///
/// 発火するなら、削除・リネームの拒否も収集できる（現状は`Create`の拒否しか拾っていない）。
/// 発火しないなら、それらの拒否は原理的に拾えないことが確定する。
#[test]
#[ignore = "requires administrator rights (ETW); run via dev-elevated-run.exe etw-diagnostics"]
fn do_delete_and_rename_events_fire_when_the_operation_is_denied() {
    const KERNEL_FILE_KEYWORD_DELETE_PATH: u64 = 0x400;
    const KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH: u64 = 0x800;

    let dir = tempfile::tempdir().expect("tempdir");
    let locked_dir = dir.path().join("locked");
    std::fs::create_dir(&locked_dir).expect("create the locked dir");
    let victim = locked_dir.join("etw-diag-delete-me.txt");
    std::fs::write(&victim, b"x").expect("create the victim file");

    // **ファイル単体へのDENYでは削除を止められない**——親ディレクトリの`FILE_DELETE_CHILD`が
    // あれば消せてしまう（前回の実測で`delete attempt: Ok(())`になり、テストの前提が崩れていた）。
    // 親ディレクトリ側の削除権（DC=DELETE_CHILD）も拒否して初めて失敗する。
    let user = std::env::var("USERNAME").expect("USERNAME");
    for (target, perms) in [
        (victim.clone(), "(D,WDAC,WO,WA,W)"),
        (locked_dir.clone(), "(DC,D)"),
    ] {
        let output = std::process::Command::new("icacls")
            .arg(&target)
            .arg("/deny")
            .arg(format!("{user}:{perms}"))
            .output()
            .expect("icacls");
        assert!(
            output.status.success(),
            "icacls on {} failed: {}",
            target.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let session = EtwFsSession::start_with_extra_keywords(
        "harness-policy-learn-diag-delete",
        KERNEL_FILE_KEYWORD_DELETE_PATH | KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH,
    )
    .expect("ETW session with delete/rename keywords");
    std::thread::sleep(WARMUP);

    let delete_result = std::fs::remove_file(&victim);
    let rename_result = std::fs::rename(&victim, locked_dir.join("renamed.txt"));
    println!("[#3] delete attempt: {delete_result:?}");
    println!("[#3] rename attempt: {rename_result:?}");
    assert!(
        delete_result.is_err() && rename_result.is_err(),
        "the delete/rename must actually FAIL for this measurement to mean anything          (delete={delete_result:?}, rename={rename_result:?})"
    );

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    // 26=DeletePath / 27=RenamePath / 28=SetLinkPath / 18=SetDelete / 19=Rename
    println!("[#3] event histogram: {:?}", outcome.event_histogram);
    for (id, name) in [
        (18u16, "SetDelete"),
        (19, "Rename"),
        (26, "DeletePath"),
        (27, "RenamePath"),
        (28, "SetLinkPath"),
    ] {
        println!(
            "[#3]   id={id} ({name}): {}",
            outcome.event_histogram.get(&id).copied().unwrap_or(0)
        );
    }
    // **本命の確認**: 削除/リネームの拒否が、既存の`Create`+`OperationEnd`経路で拾えているか。
    // 拾えているなら`DELETE_PATH`等のキーワードを追加で開ける必要は無い。
    let volumes = drive_letter_map();
    let expected = victim.to_string_lossy().replace('\\', "/");
    let captured: Vec<_> = outcome
        .denials
        .iter()
        .filter(|d| {
            to_settings_path(&d.file_name, &volumes)
                .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
        })
        .collect();
    println!(
        "[#3] denials captured through Create+OperationEnd for the victim path: {}",
        captured.len()
    );
    for denial in &captured {
        println!("[#3]   {denial:?}");
    }
    println!(
        "[#3] CONCLUSION: DeletePath/RenamePath being ~0 while the denial DOES appear above means \
         the denial happens at OPEN time (remove_file/rename open the file with DELETE access \
         first), so the existing Create+OperationEnd path already covers it and the extra \
         keywords are unnecessary."
    );

    assert!(outcome.seen_events > 0, "no Kernel-File events observed");

    // 後始末: DENYを外さないとtempdirを消せない。
    let _ = std::process::Command::new("icacls")
        .arg(&locked_dir)
        .arg("/remove:d")
        .arg(&user)
        .output();
    let _ = std::process::Command::new("icacls")
        .arg(&victim)
        .arg("/remove:d")
        .arg(&user)
        .output();
}

/// #1: **極端に短命な第1世代プロセス**の帰属率。
///
/// `ProcessStart`時のprobeが間に合わなかった分は帰属できず捨てられる。その割合を数える
/// ——「ゼロであること」ではなく「どのくらいか」を知るためのテスト。
#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe etw-diagnostics"]
fn attribution_rate_for_very_short_lived_children() {
    use crate::shell_tier::WorkspaceWriteMode;
    use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
    use crate::tier2a::win_appcontainer::{preflight, NetworkCapability};

    const CHILDREN: usize = 12;

    let workspace = tempfile::tempdir().expect("workspace");
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("sid");

    let session = EtwFsSession::start("harness-policy-learn-diag-shortlived").expect("ETW session");
    std::thread::sleep(WARMUP);

    // 即死する子を連続で起こす（`cmd /c exit`は起動して即終了する最短のもの）。
    let mut spawned_pids = Vec::new();
    let env = crate::secret_env::build_child_env();
    for _ in 0..CHILDREN {
        match spawn_in_workspace(
            "cmd.exe",
            &["/c", "exit"],
            workspace.path(),
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
            None,
        ) {
            Ok(child) => {
                spawned_pids.push(child.pid());
                let _ = child.write_stdin_read_output_and_wait(None);
            }
            Err(e) => println!("[#1] spawn failed: {e}"),
        }
    }
    println!("[#1] spawned {} short-lived children", spawned_pids.len());

    // 全部終わってから1回だけドレインする＝**最悪ケース**（子は全員もう死んでいる）。
    let mut worst_case =
        ScopeTracker::new(profile.clone()).with_harness_pid(Some(std::process::id()));
    std::thread::sleep(DRAIN);
    let (starts, _denials) = session.drain();
    for start in &starts {
        worst_case.on_process_start_probing(
            start,
            crate::tier2a::policy_learnd::server::probe_pid_in_container,
        );
    }
    let mut tracker = worst_case;
    let outcome = session.stop();

    let attributed = spawned_pids
        .iter()
        .filter(|pid| tracker.classify(**pid, |_| None) == ScopeVerdict::InScope)
        .count();
    let saw_process_start = spawned_pids
        .iter()
        .filter(|pid| starts.iter().any(|s| s.pid == **pid))
        .count();
    println!(
        "[#1] spawned={} ProcessStart observed={} attributed={} (worst case: all already exited)",
        spawned_pids.len(),
        saw_process_start,
        attributed
    );
    println!(
        "[#1] of which attributed by parentage (harness is the parent, probe too late): {}",
        tracker.attributed_by_parentage_count()
    );
    println!(
        "[#1] events={} lost={}",
        outcome.seen_events, outcome.events_lost
    );
    println!(
        "[#1] NOTE: this is the WORST case -- every child had already exited before the drain. \
         In a real session the drain runs every 2s while children are working."
    );

    let _ = crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );
}

/// NTパスを「なぜ変換できなかったか」で分類する（#4の分布を読むため）。
fn classify_nt_path(path: &str) -> String {
    for prefix in [
        r"\Device\NamedPipe",
        r"\Device\Mup",
        r"\Device\LanmanRedirector",
        r"\Device\HarddiskVolume",
        r"\Device\Afd",
        r"\Device\ConDrv",
        r"\Device\KsecDD",
        r"\Device\DeviceApi",
        r"\Device\Nsi",
        r"\Device\CNG",
    ] {
        if path.starts_with(prefix) {
            return prefix.to_string();
        }
    }
    if path.starts_with(r"\Device\") {
        return r"\Device\<other>".to_string();
    }
    if path.starts_with(r"\??\Volume{") {
        return r"\??\Volume{GUID}".to_string();
    }
    if path.is_empty() {
        return "<empty>".to_string();
    }
    "<other>".to_string()
}

/// 再帰的にファイルを読む（`Create`を大量に発生させる負荷）。
fn walk_and_read(dir: &std::path::Path, touched: &mut u64, limit: u64) {
    if *touched >= limit {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *touched >= limit {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_and_read(&path, touched, limit);
        } else {
            let _ = std::fs::metadata(&path);
            let _ = std::fs::File::open(&path);
            *touched += 1;
        }
    }
}

/// #6/#c: **`Microsoft-Windows-Security-Auditing`を harness 自身のETWセッションで購読できるか。**
///
/// 4656（`A handle to an object was requested`）は`ObjectName`＋`AccessMask`＋`ProcessId`を持ち、
/// **ETWのKernel-Fileでは原理的に取れない`DesiredAccess`**を運ぶ（RESULTS.md §3.2/§6.4）。
/// ただしこのプロバイダは扱いが特殊で、OSの`EventLog-Security`セッションだけが有効化できる
/// 可能性がある。その場合は「Securityイベントログを読む」という別実装になり、今の収集器の
/// 構造（ETWセッション1本）とは別物になる。
///
/// **採否を論じる前に、まずここを確かめる。** 監査ポリシー（`auditpol`）には一切触らないので、
/// このテストはマシンの状態を何も変えない。
///
/// なお`ERROR_SUCCESS`が返っても「イベントが流れてくる」ことは意味しない——4656は監査ポリシーと
/// SACL（またはGlobal Object Access Auditing）が設定されていなければそもそも生成されない。
/// ここで分かるのは「有効化を拒否されるか否か」だけである。
#[test]
#[ignore = "requires administrator rights (ETW); run via dev-elevated-run.exe etw-diagnostics"]
fn can_harness_subscribe_to_the_security_auditing_provider() {
    use super::session::try_enable_provider;

    // `{54849625-5478-4994-A5BA-3E3B0328C30D}`（実測: `Get-WinEvent -ListProvider`）
    let security_auditing =
        windows::core::GUID::from_u128(0x5484_9625_5478_4994_A5BA_3E3B_0328_C30D);
    // 対照群: 既に購読できると分かっているプロバイダ（Kernel-File）。
    let kernel_file = super::parse::KERNEL_FILE_PROVIDER_GUID;

    let control = try_enable_provider("harness-policy-learn-diag-control", kernel_file)
        .expect("control session");
    println!("[#c] EnableTraceEx2(Kernel-File)        = {control:?}  (control: known to work)");

    let target = try_enable_provider("harness-policy-learn-diag-secaudit", security_auditing)
        .expect("target session");
    println!("[#c] EnableTraceEx2(Security-Auditing)  = {target:?}");

    // **有効化が通ることは配送を意味しない。** 実際に届くかを数える。
    // 併せて現在の監査ポリシーを読み取り専用で確認する（`/get`は何も変更しない）——
    // 「届かなかった」が「配送されない」なのか「そもそも生成されていない」なのかを
    // 切り分けるのに要る。
    // `auditpol`の出力はローカライズされていてコンソールコードページで返るので、
    // `decode_console_bytes`（BUG-051で入れたデコーダ）を通す。
    if let Ok(policy) = std::process::Command::new("auditpol")
        .args(["/get", "/category:*"])
        .output()
    {
        let text = crate::win_common::decode_console_bytes(&policy.stdout);
        // 「監査なし」でない行だけを出す（言語に依存しないよう、空でない設定列を持つ行を拾う）。
        let interesting: Vec<String> = text
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| {
                let t = l.trim();
                !t.is_empty()
                    && !t.starts_with("システム")
                    && !t.starts_with("System")
                    && l.starts_with("  ")
            })
            .take(60)
            .collect();
        println!(
            "[#c] current audit policy (read-only, {} line(s)):",
            interesting.len()
        );
        for line in &interesting {
            println!("[#c]   {}", line.trim());
        }
    }

    // **決定的な切り分け**: 同じ12秒の窓でSecurityイベントログに実際に何件書かれたかを見る。
    // ログには書かれているのに我々のETWセッションへ0件なら、「生成されていない」ではなく
    // 「このセッションへは配送されない」が答えになる。読み取りのみ。
    let security_log_record = || -> Option<u64> {
        let out = std::process::Command::new("pwsh")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop).RecordId",
            ])
            .output()
            .ok()?;
        crate::win_common::decode_console_bytes(&out.stdout)
            .trim()
            .parse::<u64>()
            .ok()
    };
    let security_log_before = security_log_record();

    // 窓の途中で**監査イベントを1件わざと発生させる**。上のポリシーダンプで
    // 「ログオン: 成功および失敗」が有効なことを確認済みなので、存在しないアカウントでの
    // ネットワークログオン失敗が4625を1件生む。**監査ポリシーは変更しない**し、存在しない
    // アカウントなのでロックアウトも起きない（ロックアウトは実在アカウントにしか働かない）。
    let trigger = std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let _ = std::process::Command::new("net")
            .args([
                "use",
                r"\\127.0.0.1\IPC$",
                "/user:harness-etw-probe-nonexistent",
                "bogus-password-for-audit-probe",
            ])
            .output();
    });

    let probe_window = std::time::Duration::from_secs(12);
    let (status, received) = super::session::count_provider_events(
        "harness-policy-learn-diag-secaudit-recv",
        security_auditing,
        probe_window,
    )
    .expect("delivery probe");
    let _ = trigger.join();
    let security_log_after = security_log_record();
    println!(
        "[#c] delivery probe: enable={status:?} events_received={received} over {}s",
        probe_window.as_secs()
    );
    match (security_log_before, security_log_after) {
        (Some(before), Some(after)) => println!(
            "[#c] Security event log RecordId {before} -> {after} ({} record(s) written during              the same window)",
            after.saturating_sub(before)
        ),
        _ => println!("[#c] could not read the Security event log record id (inconclusive)"),
    }
    let (_, control_received) = super::session::count_provider_events(
        "harness-policy-learn-diag-control-recv",
        kernel_file,
        std::time::Duration::from_secs(3),
    )
    .expect("control delivery probe");
    println!("[#c] control (Kernel-File) events_received={control_received} over 3s");

    if received > 0 {
        println!(
            "[#c] RESULT: Security-Auditing events DO reach a private harness session              ({received} received). Consuming 4656 from our own ETW session is therefore              possible; what remains is the audit policy configuration and the volume."
        );
    } else {
        let written = match (security_log_before, security_log_after) {
            (Some(before), Some(after)) => Some(after.saturating_sub(before)),
            _ => None,
        };
        match written {
            Some(n) if n > 0 => println!(
                "[#c] RESULT (DECISIVE): zero events reached our session while the Security event                  log gained {n} record(s) in the same window, and the control provider delivered                  {control_received}. The audit subsystem WAS producing events; they just do not                  reach a private harness session. **harness cannot consume 4656 from its own ETW                  session** -- it would have to read the Security event log instead, which is a                  different design from the current one-ETW-session collector."
            ),
            Some(_) => println!(
                "[#c] RESULT (inconclusive): zero events reached our session, but the Security                  event log also gained nothing in the same window -- so we cannot tell whether                  the provider refuses to deliver or simply had nothing to report. Re-run while                  something that generates audit events happens, or enable a subcategory first."
            ),
            None => println!(
                "[#c] RESULT (inconclusive): zero events reached our session and the Security                  event log could not be read for comparison."
            ),
        }
    }

    if target == windows::Win32::Foundation::ERROR_SUCCESS {
        println!(
            "[#c] RESULT: enabling was NOT refused. This does not prove events would arrive -- \
             4656 is only generated when the audit policy + SACL (or Global Object Access \
             Auditing) are configured. The next step, if we ever want DesiredAccess, is to \
             configure `auditpol /resourceSACL` and measure the volume."
        );
    } else {
        println!(
            "[#c] RESULT: enabling was REFUSED ({target:?}). harness cannot consume 4656 from its \
             own real-time session; it would have to read the Security event log instead, which \
             is a different implementation from the current one-ETW-session collector. This \
             settles the question without touching the audit policy."
        );
    }

    // 対照群が通っていることを確かめる（通らないならテスト自体が無意味）。
    assert_eq!(
        control,
        windows::Win32::Foundation::ERROR_SUCCESS,
        "the control provider (Kernel-File) could not be enabled; this run proves nothing"
    );
}
