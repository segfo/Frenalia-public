//! **MAC/Spawn Daemon設計の実現性スパイク（バッチ2: S5・S6・S7、バッチ4のgo/no-go）**。
//! 結果の正本は
//! `plans/mac-spike/RESULTS.md`、設計の正本は設計書§22.6.2（「改A」6手順）・§10.1.1（Job）・
//! §10.1（要求受付パイプ）である。
//!
//! バッチ1は「mitigationとcapabilityが効くか」を測った。ここで測るのは
//! **Daemon方式を実装できるか**——Daemonが持つべき3つの能力が実機で成立するか、である。
//!
//! | # | 問い | 否だったときに崩れるもの |
//! |---|---|---|
//! | S5 | Daemon役が呼び出し元のハンドルを複製し、実体のパスを解決し、権限を絞って子へ渡せるか | §22.6.2「改A」（採らなかった案C＝全出力中継へ戻る） |
//! | S6 | Jobの封じ込めがDaemon方式（＝複製ハンドルが1本増える）でも保てるか | §10.1.1（キャンセルを`TerminateJobObject`へ変える根拠） |
//! | S7 | capability SID宛ACEを持つ名前付きパイプへ、サンドボックスから往復できるか | §10.1（要求受付パイプそのもの） |
//!
//! 実行（**昇格しないこと**）:
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture mac_spike_daemon_tests
//! ```

use std::ffi::c_void;

use windows::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS,
};
use windows::Win32::System::Console::{AttachConsole, FreeConsole, GetConsoleProcessList};
use windows::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
};

use super::mac_spike_tests::{
    last_json_line, probe_exe, workspace_capability_for, SpikeChild, SpikeConsole, SpikeSpawn,
    SuspendedSpikeChild,
};
use super::*;

/// 実験用workspaceを1つ用意し、`preflight`まで通した状態を返す。
fn spike_workspace() -> (
    tempfile::TempDir,
    OwnedContainerSid,
    Vec<crate::win_common::OwnedSid>,
) {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let mut caps = vec![traverse_capability_sid().expect("traverse capability")];
    if let Some(cap) = workspace_capability_for(workspace.path()) {
        caps.push(cap);
    }
    (workspace, sid, caps)
}

/// `AttachConsole`の区間を抜けるとき、成功・失敗のどちらでもDaemon役を切り離す。
/// コンソールへの接続はプロセス単位なので、後続の腕へ状態を持ち越さないためのガードである。
struct ConsoleDetachGuard;

impl Drop for ConsoleDetachGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeConsole();
        }
    }
}

/// Daemon役がコンソールを借りるか。**借りない腕は「借用が効いている」ことの対照**である
/// ——借りずに同じスクリプトを撃って印が出てしまうなら、保持プロセスと`conhost`を
/// ドメインごとに1本持つ費用（§22.9）の前提そのものが崩れる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleLoan {
    Attach,
    NoAttach,
}

/// `CREATE_SUSPENDED`で作った子を、いつ動かし始めるか。
///
/// **設計書§7.1.1の疑似コードは`FreeConsole`を`CreateProcessW`の直後に置いている**ので、
/// そこに書かれた順序は[`Self::AfterDetach`]である。一方2026-09-04の初回測定は
/// [`Self::InsideWindow`]で通していた（`SpikeSpawn::spawn`がResumeまで含んでいたため）。
/// この2つは同じではない——子のDLL初期化はResumeの後に走るので、
/// [`Self::AfterDetach`]では§7.1が`0xC0000142`を観測した場所が**窓の外**に来る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumePoint {
    InsideWindow,
    AfterDetach,
}

/// 1腕の構成（軸は3つ。**1腕につき1軸だけ動かす**、B-29）。
#[derive(Debug, Clone, Copy)]
struct ArmSpec {
    label: &'static str,
    holder_console: SpikeConsole,
    loan: ConsoleLoan,
    resume_at: ResumePoint,
}

/// 起こした子を、動かす前に受け取るか動かした後に受け取るか。
enum SpawnedArm {
    Running(SpikeChild),
    Suspended(SuspendedSpikeChild),
}

#[derive(Debug)]
struct AttachedShellRun {
    console_processes: Vec<u32>,
    stdout: String,
    stderr: String,
    exit_code: i32,
    marker: Option<String>,
}

impl AttachedShellRun {
    /// **シェルが実際に走ったか。** `CreateProcessW`の成功値ではなく、
    /// 標準出力の印・別ファイルの印・終了コードの3つが揃ったことで数える。
    ///
    /// コンソールの構成員の件数はここに含めない——それは「借りられたか」の検算であって、
    /// 「走ったか」とは別の事実だからである（借りない腕ではそもそも0件になる）。
    fn actually_ran(&self) -> bool {
        self.exit_code == 37
            && self.stdout.contains("HARNESS-ATTACH-CONSOLE-STDOUT")
            && self.marker.as_deref().map(str::trim) == Some("HARNESS-ATTACH-CONSOLE-MARKER")
    }

    /// 走ったシェルが、**その場で子プロセスを起こそうとして拒否されたか**。
    ///
    /// これが無いと、この回の証拠は「AppContainerのシェルが借りたコンソールで走った」までしか
    /// 語らない。§7.1.1が問うているのは`CHILD_PROCESS_RESTRICTED`との**組み合わせ**なので、
    /// 同じ1回の出力に「走った」と「子は作れない」の両方を語らせる。
    fn child_creation(&self) -> Option<&str> {
        self.stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("HARNESS-ATTACH-CONSOLE-CHILD="))
    }

    /// 拒否の**理由の型**まで印にする（`CHILD-DENIED-<例外型名>`）。
    /// 「起こせなかった」だけだと、mitigationで拒否されたのか実行ファイルが見つからなかったのかを
    /// 後から区別できない。
    fn child_creation_denied(&self) -> bool {
        self.child_creation()
            .is_some_and(|outcome| outcome.starts_with("CHILD-DENIED-"))
    }

    /// **§7.1.1測定5**: 子の標準ハンドルがパイプのまま保たれているか（`stdin/stdout/stderr`の順）。
    ///
    /// コンソールを借りて起こすと、子の標準ハンドルにコンソールハンドルが混入し得る。
    /// 混入すると、`STARTF_USESTDHANDLES`＋パイプという前提の上に乗っている出力の読み方
    /// （起動時ノイズの切り出し・stderrの境界印）が静かに変わる。
    ///
    /// **親側でパイプから読めていることは、この問いに答えない**——親が読めていても、
    /// 子の中では別のハンドルが標準出力として見えている可能性が残る。だから**子の内側で**測る。
    fn stdio_redirected(&self) -> Option<&str> {
        self.stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("HARNESS-ATTACH-CONSOLE-STDIO="))
    }

    /// stderrのうち、**既知の起動時ノイズを除いた**残り。
    ///
    /// この測定が探しているのは「無言の失敗が混ざっていないか」であって、
    /// PowerShellが起動時に必ず出す既知の1行ではない。`is_empty()`で直に見ると、
    /// **測る世界を昇格した回に固定してしまう**——下の1行は**非昇格の回でだけ出る**
    /// （2026-09-05の実測。昇格して測った2026-09-04の回では出ていない）。
    ///
    /// **除くのは名指しした行だけである。** 前方一致や「警告らしい行」で落とすと、
    /// 本当に見たい無言の失敗まで一緒に消える。
    fn unexpected_stderr(&self) -> Vec<&str> {
        const KNOWN_STARTUP_NOISE: &[&str] = &[
            // AppContainerの子はドライブを列挙できないので、pwshの`FileSystem`プロバイダ初期化が
            // 失敗する。実行そのものには影響しない（同じ回で実行印・終了コード・子の拒否が揃う）。
            "Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' \
             provider failed.",
        ];
        self.stderr
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !KNOWN_STARTUP_NOISE.contains(line))
            .collect()
    }
}

fn wait_until_holder_is_ready(holder: &SpikeSpawn<'_>, report: &std::path::Path) -> SpikeChild {
    let child = holder.spawn().expect("spawn the console holder");
    for _ in 0..100 {
        if std::fs::read_to_string(report)
            .map(|body| body.contains("\"mode\":\"idle\""))
            .unwrap_or(false)
        {
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!(
        "console holder did not report readiness: pid={} report={:?}",
        child.pid(),
        std::fs::read_to_string(report).ok()
    );
}

fn run_restricted_shell_while_attached(
    arm: &ArmSpec,
    holder_pid: u32,
    shell: &str,
    workspace: &std::path::Path,
    container_sid: PSID,
    capabilities: &[PSID],
    marker_path: &std::path::Path,
) -> Result<AttachedShellRun, String> {
    let marker_literal = marker_path.to_string_lossy().replace('\'', "''");
    // **二重引用符を1つも使わない。** `SpikeSpawn`のコマンドライン組み立ては各引数を`"`で
    // 括るので、スクリプト側に`"`があると引用が壊れる。
    let script = format!(
        "$c='CHILD-UNKNOWN'; \
         try {{ \
           $si=[System.Diagnostics.ProcessStartInfo]::new('cmd.exe','/c exit 5'); \
           $si.UseShellExecute=$false; \
           $p=[System.Diagnostics.Process]::Start($si); $p.WaitForExit(); $c='CHILD-RAN' \
         }} catch {{ \
           $e=$_.Exception.GetBaseException(); \
           $c='CHILD-DENIED-' + $e.GetType().Name + '-' + $e.NativeErrorCode \
         }}; \
         Set-Content -LiteralPath '{marker_literal}' -Value 'HARNESS-ATTACH-CONSOLE-MARKER'; \
         Write-Output ('HARNESS-ATTACH-CONSOLE-CHILD=' + $c); \
         Write-Output ('HARNESS-ATTACH-CONSOLE-STDIO=' + [Console]::IsInputRedirected \
           + '/' + [Console]::IsOutputRedirected + '/' + [Console]::IsErrorRedirected); \
         Write-Output HARNESS-ATTACH-CONSOLE-STDOUT; exit 37"
    );
    let args = ["-NoProfile", "-NonInteractive", "-Command", script.as_str()];

    let (console_processes, spawned) = {
        // Daemonの既定状態（コンソール未接続）を作る。既に未接続なら失敗するが、
        // その状態が目的なので無視する。
        unsafe {
            let _ = FreeConsole();
        }
        let _detach = match arm.loan {
            ConsoleLoan::Attach => {
                unsafe {
                    AttachConsole(holder_pid).map_err(|e| {
                        format!("AttachConsole(holder_pid={holder_pid}) failed: {e}")
                    })?;
                }
                Some(ConsoleDetachGuard)
            }
            // 借りない腕。以降Daemon役はどのコンソールにも属さないまま子を起こす。
            ConsoleLoan::NoAttach => None,
        };

        let process_ids = match arm.loan {
            ConsoleLoan::Attach => {
                let mut process_ids = vec![0u32; 16];
                let count = unsafe { GetConsoleProcessList(&mut process_ids) } as usize;
                if count == 0 {
                    return Err(
                        "GetConsoleProcessList returned 0 after AttachConsole succeeded".into(),
                    );
                }
                if count > process_ids.len() {
                    // バッファが足りないとAPIは所要数だけを返して中身を書かない。
                    // 黙って切り詰めると「載っていない」と読めてしまうので失敗させる。
                    return Err(format!(
                        "console has more members than the probe buffer: need={count} buffer={}",
                        process_ids.len()
                    ));
                }
                process_ids.truncate(count);
                if !process_ids.contains(&holder_pid) || !process_ids.contains(&std::process::id())
                {
                    return Err(format!(
                        "attached console membership is inconsistent: holder={holder_pid} daemon={} members={process_ids:?}",
                        std::process::id()
                    ));
                }
                process_ids
            }
            ConsoleLoan::NoAttach => Vec::new(),
        };

        let spawned = SpikeSpawn {
            exe: shell,
            args: &args,
            cwd: workspace,
            container_sid,
            capabilities,
            child_process_restricted: true,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            // 親（Daemon役）が上で借りたコンソールを、そのまま継承する。借りていない腕では
            // 親にコンソールが無いので、子もコンソールを持たない。
            console: SpikeConsole::Inherit,
        }
        .spawn_suspended()
        .map(|suspended| match arm.resume_at {
            // 窓の内側で動かす。子のDLL初期化はDaemon役が接続したまま走る。
            ResumePoint::InsideWindow => SpawnedArm::Running(suspended.resume()),
            // 窓の外で動かす。ここではまだ止めたまま持ち出す。
            ResumePoint::AfterDetach => SpawnedArm::Suspended(suspended),
        });
        (process_ids, spawned)
        // `_detach`がここで動き、Daemon役をコンソールから切り離す。
    };

    let mut child = match spawned.map_err(|e| format!("restricted shell spawn failed: {e}"))? {
        SpawnedArm::Running(child) => child,
        // **設計書§7.1.1どおりの順序**: 窓を閉じてから動かす。
        SpawnedArm::Suspended(suspended) => suspended.resume(),
    };
    let (stdout, stderr, exit_code) = child.wait_and_read();
    let marker = std::fs::read_to_string(marker_path).ok();
    Ok(AttachedShellRun {
        console_processes,
        stdout,
        stderr,
        exit_code,
        marker,
    })
}

/// §7.1.1のgo/no-go: Daemon役が保持プロセスのコンソールを`AttachConsole`で借りた状態で、
/// `CHILD_PROCESS_RESTRICTED`を積んだAppContainerシェルがコマンドを実行できるか。
///
/// **4腕で測る。** 本命（`EXACT`）は設計どおり`CREATE_NO_WINDOW`で起こした保持プロセスへ
/// 接続し、窓の内側で子を動かす。残り3腕はそこから軸を1つだけ変えた対照である。
///
/// | 腕 | 本命との差 | これが無いと何が言えなくなるか |
/// |---|---|---|
/// | `CONTROL` | 保持プロセスを`CREATE_NEW_CONSOLE`（非表示）で起こす | 本命が落ちたとき、原因が保持プロセスの作り方か`AttachConsole`以降かを分けられない |
/// | `NO_LOAN` | コンソードを借りずに同じスクリプトを撃つ | 「借りたコンソールが効いている」が言えない（走った理由が借用と無関係かもしれない） |
/// | `DESIGN_ORDER` | `FreeConsole`の**後**で子を動かす | 設計書§7.1.1が描いている順序を測っていない。子のDLL初期化——§7.1が`0xC0000142`を観測した場所——が窓の外に来る |
///
/// あわせて、走ったシェルにその場で子プロセスを起こさせ、拒否されることを同じ出力で見る。
/// これが無いと、この回の証拠は「AppContainerのシェルが走った」までしか語らない。
#[test]
// **昇格しても非昇格でも通るが、結論の射程は非昇格の回にある**（本番のDaemonは昇格しない）。
// 昇格した回とはstderrが違う——非昇格ではpwshの`FileSystem`プロバイダ初期化の警告が1行出る
// （`unexpected_stderr`のdoc）。`spike-mac-console-attach`は昇格経路の固定ターゲットとして残して
// あるが、**測る世界が変わることを承知で使うこと**（B-08）。
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn go_no_go_attach_console_restricted_shell_runs() {
    let measure_lock = std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-attach");
    std::fs::create_dir_all(
        measure_lock
            .parent()
            .expect("measurement lock has a parent"),
    )
    .expect("create the serialized measurement lock parent");
    std::fs::create_dir(measure_lock).unwrap_or_else(|e| {
        panic!(
            "測定ロックを取得できない（並列測定または前回残骸を確認する）: path={measure_lock:?} error={e}"
        )
    });
    let _measure_lock_cleanup = super::test_support::scopeguard(|| {
        std::fs::remove_dir(measure_lock).ok();
    });

    let (workspace, sid, caps) = spike_workspace();
    let workspace_canonical = workspace
        .path()
        .canonicalize()
        .expect("canonicalize the spike workspace");
    let cleanup_workspace = workspace_canonical.clone();
    let cleanup_session_token = crate::tier2a::session_profile::session_token().to_string();
    let cleanup_session_token_for_assert = cleanup_session_token.clone();
    let _cleanup = super::test_support::scopeguard(move || {
        let outcome =
            crate::tier2a::session_profile::end_session(&super::revoke::revoke_session_grant);
        eprintln!(
            "[MAC-CONSOLE-GO-NO-GO] cleanup session={cleanup_session_token}: {:?}",
            outcome.summary()
        );
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!(
                "[MAC-CONSOLE-GO-NO-GO] cleanup could not remove workspace {cleanup_workspace:?}: {e}"
            );
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    let (shell, shell_label) = resolve_shell();

    let run_arm = |arm: &ArmSpec| -> Result<AttachedShellRun, String> {
        let holder_report = workspace.path().join(format!("{}-holder.json", arm.label));
        let holder_report_str = holder_report.to_string_lossy().into_owned();
        let holder_args = [
            "--idle-secs",
            "30",
            "--timeout-secs",
            "60",
            "--report-file",
            holder_report_str.as_str(),
        ];
        let holder_spec = SpikeSpawn {
            exe: &probe_str,
            args: &holder_args,
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities: &[],
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: true,
            console: arm.holder_console,
        };
        let holder = wait_until_holder_is_ready(&holder_spec, &holder_report);
        let marker = workspace.path().join(format!("{}-marker.txt", arm.label));
        let result = run_restricted_shell_while_attached(
            arm,
            holder.pid(),
            &shell,
            workspace.path(),
            sid.as_psid(),
            &caps_psid,
            &marker,
        );
        drop(holder);
        result
    };

    // 4腕。**隣の腕とは軸を1つだけ変えてある**（B-29）。
    const EXACT: ArmSpec = ArmSpec {
        label: "exact-create-no-window",
        holder_console: SpikeConsole::NoWindow,
        loan: ConsoleLoan::Attach,
        resume_at: ResumePoint::InsideWindow,
    };
    // EXACTから`resume_at`だけを変えた腕。設計書§7.1.1の疑似コードはこちらの順序である。
    const DESIGN_ORDER: ArmSpec = ArmSpec {
        label: "design-resume-after-detach",
        holder_console: SpikeConsole::NoWindow,
        loan: ConsoleLoan::Attach,
        resume_at: ResumePoint::AfterDetach,
    };
    // EXACTから保持プロセスの作り方だけを変えた腕（計器の対照）。
    const CONTROL: ArmSpec = ArmSpec {
        label: "control-create-new-console",
        holder_console: SpikeConsole::NewHidden,
        loan: ConsoleLoan::Attach,
        resume_at: ResumePoint::InsideWindow,
    };
    // EXACTからコンソールを借りるかだけを変えた腕（借用が効いていることの対照）。
    const NO_LOAN: ArmSpec = ArmSpec {
        label: "control-no-console-loan",
        holder_console: SpikeConsole::NoWindow,
        loan: ConsoleLoan::NoAttach,
        resume_at: ResumePoint::InsideWindow,
    };

    // **子の起動失敗でWindowsのエラーダイアログを出させない。**
    // 「コンソールを借りない」腕は設計上`0xC0000142`で落ちるのが期待値なので、抑止しないと
    // 測定が人のクリック待ちになる——無人で回せない測定器は、それ自体が欠陥である。
    // エラーモードはプロセス単位で、**子へ継承される**。取得した旧値は必ず戻す（付与と撤収は対）。
    let previous_error_mode = unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
    };
    let _restore_error_mode = super::test_support::scopeguard(move || unsafe {
        SetErrorMode(previous_error_mode);
    });

    // **どのシェルの実体を測ったかを記録へ残す。** ラベルだけでは、§S1bがpwsh 7と5.1・
    // Storeエイリアスと実体を区別している記録と突き合わせられない。
    eprintln!("[MAC-CONSOLE-GO-NO-GO] shell={shell_label} path={shell}");

    // 全腕を先に測る。結果がNoでも、対照を続けて測れるよう即時assertしない。
    let exact = run_arm(&EXACT);
    eprintln!("[MAC-CONSOLE-GO-NO-GO] exact holder / shell={shell_label}: {exact:?}");
    let design_order = run_arm(&DESIGN_ORDER);
    eprintln!("[MAC-CONSOLE-GO-NO-GO] resume-after-detach / shell={shell_label}: {design_order:?}");
    let control = run_arm(&CONTROL);
    eprintln!("[MAC-CONSOLE-GO-NO-GO] control holder / shell={shell_label}: {control:?}");
    let no_loan = run_arm(&NO_LOAN);
    eprintln!("[MAC-CONSOLE-GO-NO-GO] no console loan / shell={shell_label}: {no_loan:?}");

    let control = control.unwrap_or_else(|e| {
        panic!("計器の対照が成立しないためgo/no-goを判定できない: shell={shell_label} error={e}")
    });
    assert!(
        control.actually_ran(),
        "確実にコンソールを持つ対照でもmitigation付きシェルが実行印を残さなかった。\
         本命のNo判定には使えない: shell={shell_label} observation={control:?}"
    );

    let exact = exact.unwrap_or_else(|e| {
        panic!(
            "NO-GO: 設計どおりCREATE_NO_WINDOWで起こした保持プロセスのコンソールを借りられない: \
             shell={shell_label} error={e}; control={control:?}"
        )
    });
    assert!(
        exact.actually_ran(),
        "NO-GO: AttachConsole後にmitigation付きAppContainerシェルが実行印とexit 37を返さなかった: \
         shell={shell_label} observation={exact:?}; control={control:?}"
    );

    // **緩和策が実際に効いていたことを、同じ1回の出力で語らせる。**
    // これが無いと、走ったのは「ただのAppContainerシェル」かもしれない（§7.1.1が問うている
    // のは`CHILD_PROCESS_RESTRICTED`との組み合わせである）。
    for (label, run) in [("exact", &exact), ("control", &control)] {
        assert!(
            run.child_creation_denied(),
            "走ったシェルが子プロセスを起こせてしまった＝この回はmitigationが効いていない。\
             GOの根拠にできない: arm={label} child={:?} observation={run:?}",
            run.child_creation()
        );
    }

    // **借りたコンソールが効いていることの対照。** 借りずに同じスクリプトを撃って印が出るなら、
    // 保持プロセスと`conhost`をドメインごとに持つ費用の前提（§7.1・§22.9）が崩れる。
    // その場合は設計判断へ戻すべきなので、ここは緑にしない。
    let no_loan = no_loan.unwrap_or_else(|e| {
        panic!(
            "コンソールを借りない腕が起動そのものに失敗した（借用の効果を判定できない）: \
             shell={shell_label} error={e}"
        )
    });
    assert!(
        !no_loan.actually_ran(),
        "コンソールを借りなくてもmitigation付きシェルが完走した。§7.1.1の保持プロセスは\
         この経路には要らない可能性があるので、設計判断へ戻すこと: \
         shell={shell_label} observation={no_loan:?}",
    );

    // **設計書§7.1.1の順序（窓を閉じてから動かす）でも成立するか。**
    // ここが落ちるなら、実装は「窓はResumeまで」に広げる必要がある——広げると、
    // サンドボックス側のシェルが走っている間だけDaemonが同じコンソールに残るので、
    // §7.1.1がCtrl+Cを理由に避けた状態を受け入れることになる。どちらを採るかは設計の判断。
    let design_order = design_order.unwrap_or_else(|e| {
        panic!(
            "NO-GO(設計順): FreeConsoleの後にResumeすると起動できない: \
             shell={shell_label} error={e}; exact={exact:?}"
        )
    });
    assert!(
        design_order.actually_ran() && design_order.child_creation_denied(),
        "NO-GO(設計順): 窓を閉じてから動かすと実行印が揃わない。§7.1.1の疑似コードは\
         この順序を描いているので、設計かコードのどちらかを直すこと: \
         shell={shell_label} observation={design_order:?}; exact={exact:?}"
    );

    // 借りた3腕は「Daemon役＋保持プロセスの2人だけ」であること、借りない腕は0件であることを
    // 読み返す。**印だけ見ていると、どのコンソールで走ったのかが記録に残らない。**
    // stderrも合わせてここで見る——Debug出力へ出しているだけでは、次に非空になっても緑のままになる。
    for (label, run) in [
        ("exact", &exact),
        ("design-resume-after-detach", &design_order),
        ("control", &control),
    ] {
        assert_eq!(
            run.console_processes.len(),
            2,
            "借りたコンソールの構成員がDaemon役と保持プロセスの2人ではない: \
             arm={label} members={:?}",
            run.console_processes
        );
        assert!(
            run.unexpected_stderr().is_empty(),
            "mitigation付きシェルがstderrへ**既知の起動時ノイズ以外**を出した\
             （無言の失敗が混ざっていないか確認する）: arm={label} unexpected={:?} stderr={:?}",
            run.unexpected_stderr(),
            run.stderr
        );
        // **§7.1.1測定5**: コンソールを借りて起こしても、子の標準ハンドルはパイプのままか。
        // 3本とも「リダイレクトされている」＝コンソールハンドルが混入していない、である。
        // 1本でもコンソールになっていると、出力の読み方（起動時ノイズの切り出し・stderrの
        // 境界印）が乗っている前提が静かに変わる。
        assert_eq!(
            run.stdio_redirected(),
            Some("True/True/True"),
            "コンソールを借りた子の標準ハンドルにコンソールが混入している（stdin/stdout/stderr）。\
             §7.1.1の「入出力はコンソールを経由しない」が実機で成立していない: \
             arm={label} observation={run:?}"
        );
    }
    assert!(
        no_loan.console_processes.is_empty(),
        "コンソールを借りない腕なのに構成員が観測された（腕の前提が崩れている）: {:?}",
        no_loan.console_processes
    );

    // 成功時はDrop任せにせずここで撤収し、その結果を同じテスト内で読み返す。失敗時にも
    // scopeguardが同じ処理を行うため、測定結果が赤でも実マシンへ残骸を増やさない。
    drop(_cleanup);
    assert!(
        !workspace_canonical.exists(),
        "測定workspaceが撤収後も残っている: {workspace_canonical:?}"
    );
    assert!(
        !crate::tier2a::session_profile::ledger_session_tokens_for_test()
            .contains(&cleanup_session_token_for_assert),
        "測定セッションの台帳エントリが撤収後も残っている: {cleanup_session_token_for_assert}"
    );
    assert!(
        !crate::tier2a::workspace_ledger::load_workspace_ledger()
            .entries
            .iter()
            .any(|entry| std::path::Path::new(&entry.path) == workspace_canonical),
        "測定workspaceの一覧台帳エントリが撤収後も残っている: {workspace_canonical:?}"
    );
    // ロックも読み返す。**残ると次回の測定が「並列測定または前回残骸」で止まる**ので、
    // 撤収を握り潰したまま緑にしない（撤収の自己検算は4つで1組である）。
    drop(_measure_lock_cleanup);
    assert!(
        !measure_lock.exists(),
        "測定ロックが撤収後も残っている（次回の測定が並列と誤判定する）: {measure_lock:?}"
    );
}

/// `NtQueryObject(ObjectBasicInformation)`で許可アクセスマスクを取る（§22.6.2手順3）。
/// `windows`クレートのWdk名前空間はこのクレートで有効化していないので、ntdllから直に引く。
fn granted_access(handle: HANDLE) -> Option<u32> {
    #[repr(C)]
    #[derive(Default)]
    struct PublicObjectBasicInformation {
        attributes: u32,
        granted_access: u32,
        handle_count: u32,
        pointer_count: u32,
        reserved: [u32; 10],
    }
    type NtQueryObject = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
    unsafe {
        let ntdll = GetModuleHandleW(PCWSTR(wide("ntdll.dll").as_ptr())).ok()?;
        let proc = GetProcAddress(
            ntdll,
            windows::core::PCSTR(c"NtQueryObject".as_ptr() as *const u8),
        )?;
        let query: NtQueryObject = std::mem::transmute(proc);
        let mut info = PublicObjectBasicInformation::default();
        let mut len = 0u32;
        let status = query(
            handle,
            0, // ObjectBasicInformation
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<PublicObjectBasicInformation>() as u32,
            &mut len,
        );
        if status < 0 {
            return None;
        }
        Some(info.granted_access)
    }
}

/// `GetFinalPathNameByHandleW`。Daemon役（AppContainerの外）でのみ動く（§22.6.2の注記）。
fn final_path(handle: HANDLE) -> Result<String, u32> {
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
    let mut buf = vec![0u16; 4096];
    let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) };
    if len == 0 {
        return Err(unsafe { GetLastError() }.0);
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// S5: §22.6.2「改A」の6手順（複製→最終パス解決→マスク取得→照合→絞って複製→子へ渡す）が
/// 実機で成立するか。
///
/// **呼び出し元が申告するのはハンドル値（数値）だけ**という設計をそのまま写している。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s5_daemon_can_duplicate_resolve_and_narrow_a_callers_handle() {
    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // 呼び出し元役: workspace内のファイルを書込で開いて、ハンドル値だけを申告する。
    let target_file = workspace.path().join("s5-target.txt");
    let target_file_str = target_file.to_string_lossy().into_owned();
    let report = workspace.path().join("s5-report.json");
    let report_str = report.to_string_lossy().into_owned();
    let caller = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--hold-file",
            &target_file_str,
            "--report-file",
            &report_str,
            "--idle-secs",
            "20",
            "--timeout-secs",
            "60",
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
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
    .expect("spawn the caller child");

    let mut raw_handle: u64 = 0;
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(&report) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                raw_handle = v.get("handle").and_then(|h| h.as_u64()).unwrap_or(0);
                if raw_handle != 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        raw_handle != 0,
        "呼び出し元役がハンドル値を申告しなかった（{}）",
        std::fs::read_to_string(&report).unwrap_or_default()
    );

    // --- 手順1: Daemon役（このテストプロセス）へ複製する ---
    let mut duplicated = HANDLE::default();
    let dup_ok = unsafe {
        DuplicateHandle(
            caller.process(),
            HANDLE(raw_handle as usize as *mut c_void),
            GetCurrentProcess(),
            &mut duplicated,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    eprintln!("[S5] 手順1 DuplicateHandle(呼び出し元→Daemon): {dup_ok:?}");
    assert!(
        dup_ok.is_ok(),
        "Daemon役が呼び出し元のハンドルを複製できない。§22.6.2「改A」の手順1が成立しない: {dup_ok:?}"
    );

    // --- 手順2: 最終パスを解決する ---
    let resolved = final_path(duplicated);
    eprintln!("[S5] 手順2 GetFinalPathNameByHandleW: {resolved:?}");
    let resolved = resolved.expect("final path must resolve for a file handle");
    let expected = target_file.canonicalize().unwrap_or(target_file.clone());
    assert!(
        resolved.to_ascii_lowercase().contains(
            &expected
                .to_string_lossy()
                .to_ascii_lowercase()
                .replace("\\\\?\\", "")
        ),
        "解決した最終パスが対象と一致しない: resolved={resolved} expected={}",
        expected.display()
    );

    // --- 手順3: 許可アクセスマスクを取る ---
    let mask = granted_access(duplicated);
    eprintln!(
        "[S5] 手順3 NtQueryObject(GrantedAccess) = {mask:?} ({:?})",
        mask.map(|m| format!("{m:#x}"))
    );
    assert!(
        mask.is_some(),
        "NtQueryObjectで許可アクセスマスクを取れない。手順3が成立しない"
    );

    // --- 手順5-6: 権限を絞って複製し、遷移先の子へstdoutとして渡す ---
    let mut narrowed = HANDLE::default();
    let narrow_ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            duplicated,
            GetCurrentProcess(),
            &mut narrowed,
            FILE_GENERIC_WRITE.0,
            true, // 子へ継承させる
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    };
    eprintln!("[S5] 手順5 絞った複製 (FILE_GENERIC_WRITE, inheritable): {narrow_ok:?}");
    assert!(
        narrow_ok.is_ok(),
        "権限を絞った複製に失敗した: {narrow_ok:?}"
    );
    eprintln!(
        "[S5] 絞った後のGrantedAccess = {:?}",
        granted_access(narrowed).map(|m| format!("{m:#x}"))
    );

    let mut receiver = SpikeSpawn {
        exe: &probe_str,
        args: &["--emit", "HELLO-FROM-DOMAIN-B"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
        child_process_restricted: false,
        stdout_override: Some(narrowed),
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the receiver child");
    let (_out, err, code) = receiver.wait_and_read();
    eprintln!("[S5] 受け手の子: exit={code} stderr={err:?}");

    // --- パスを持たない型では手順2が失敗すること（§22.6.2「適用範囲」の根拠） ---
    let (pipe_read, pipe_write) = create_pipe_with_sddl("D:(A;;GA;;;WD)(A;;GA;;;AC)")
        .expect("anonymous-ish pipe for the negative case");
    let pipe_path = final_path(pipe_read);
    eprintln!("[S5] pipeハンドルへのGetFinalPathNameByHandleW: {pipe_path:?}");
    unsafe {
        let _ = CloseHandle(pipe_read);
        let _ = CloseHandle(pipe_write);
        let _ = CloseHandle(narrowed);
        let _ = CloseHandle(duplicated);
    }
    drop(caller);

    let written = std::fs::read_to_string(&target_file).unwrap_or_default();
    eprintln!("[S5] 対象ファイルの中身: {written:?}");
    assert!(
        written.contains("HELLO-FROM-DOMAIN-B"),
        "絞って渡したハンドルへ遷移先の子が書けていない。§22.6.2「改A」の手順6が成立しない: \
         content={written:?}"
    );
    assert!(
        pipe_path.is_err(),
        "pipeハンドルから最終パスが取れてしまった。§22.6.2「適用範囲」（fileハンドルにしか\
         適用できない）の前提が変わる: {pipe_path:?}"
    );
}

/// S6: Jobの封じ込めが「複製ハンドルが1本増えた」状態でも保てるか（§10.1.1）。
///
/// §10.1.1は「Daemonが複製を持つとハンドルが1本残るので、harnessが閉じても子孫が死なない」
/// という**予測**を根拠に、キャンセルを`TerminateJobObject`へ変えると決めた。その予測を測る。
///
/// **限界**: 複製の保持者はこのテストプロセス自身であって、別プロセスのDaemonではない。
/// kill-on-closeは「最後のハンドルが閉じたとき」に発火する仕様なので、**保持者が誰かは
/// 関係しない**——が、Daemonが別プロセスから`AssignProcessToJobObject`できるかは
/// **この測定では分からない**（RESULTS.mdへ限界として明記する）。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s6_job_containment_survives_a_duplicated_job_handle() {
    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    let mut child = SpikeSpawn {
        exe: &probe_str,
        args: &["--idle-secs", "25", "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
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
    .expect("spawn the job child");

    // Daemon役が持つぶんの複製（§10.1.1「系統Jobハンドルの複製をDaemonへ渡す」）。
    let mut job_dup = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.job(),
            GetCurrentProcess(),
            &mut job_dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .expect("duplicate the job handle");

    // **生存確認用のプロセスハンドルは、childを畳む前に複製しておく**。
    // `SpikeChild::drop`はプロセスハンドルも閉じるので、閉じた後の`GetExitCodeProcess`は
    // 「死んだ」ではなく「無効なハンドル」を返す——最初の測定でこれを踏み、
    // 機構の失敗と測定の失敗を取り違えかけた（B-29）。
    let mut process = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.process(),
            GetCurrentProcess(),
            &mut process,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .expect("duplicate the process handle for liveness checks");
    let pid = child.pid();
    let alive = |label: &str| -> bool {
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(process, &mut code) }.is_ok();
        eprintln!("[S6] {label}: GetExitCodeProcess ok={ok} code={code} (259=STILL_ACTIVE)");
        code == 259
    };
    assert!(
        alive("spawn直後"),
        "子が起動していない（測定の前提が崩れている）"
    );

    // harness役が**jobハンドルだけ**を閉じる（stdioのパイプは開けたまま）。
    // 変数を1つに絞らないと、子の死因が「kill-on-close」なのか「パイプが閉じた」なのか
    // 区別できない——最初の測定では`drop(child)`で両方を同時に閉じてしまい、
    // 子がexit 101（Rustのpanic終了コード＝stdout書込失敗）で死んだのを
    // 「kill-on-closeが発火した」と読み違えかけた（B-29）。
    let harness_job = child.take_job();
    unsafe {
        let _ = CloseHandle(harness_job);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let survived = alive("harness役がjobハンドルを閉じた後");

    // 明示的な`TerminateJobObject`（§10.1.1が新しいキャンセル手段として選んだもの）。
    let terminate = unsafe { windows::Win32::System::JobObjects::TerminateJobObject(job_dup, 1) };
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut code_after = 0u32;
    let _ = unsafe { GetExitCodeProcess(process, &mut code_after) };
    eprintln!("[S6] TerminateJobObject: {terminate:?} → 子のexit_code={code_after}");
    unsafe {
        let _ = CloseHandle(job_dup);
        let _ = CloseHandle(process);
    }

    assert!(
        survived,
        "複製ハンドルが1本残っているのに kill-on-close が発火して子が死んだ。\
         §10.1.1の前提（Daemonが複製を持つとharnessが閉じても子孫が死なない）が誤りになる。pid={pid}"
    );
    assert!(
        terminate.is_ok(),
        "TerminateJobObjectが失敗した。§10.1.1の新しいキャンセル手段が成立しない: {terminate:?}"
    );
    assert_ne!(
        code_after, 259,
        "TerminateJobObject後も子が生きている。キャンセルが効いていない。pid={pid}"
    );
}

/// S7: 要求受付パイプ（§10.1）。**capability SID宛ACEを持つ名前付きパイプへ、
/// サンドボックスから往復できるか**を、`win_pipe_ipc`と同じフレーム形式で測る。
///
/// 対で測る（B-35）——capabilityを積んだ子は往復でき、**積まない子は到達すらできない**こと。
/// 後者が成立すれば、§22.2.2の`process: deny`が「パイプに到達できない」という二重のdenyになる。
#[test]
#[ignore = "spawns real AppContainer children and creates a named pipe; run NON-elevated with --test-threads=1"]
fn s7_request_pipe_is_reachable_only_with_the_spawn_capability() {
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // spawn要求用capability（§10.1で「session package SIDではなくcapability SID宛」と決めたもの）。
    let spawn_cap = super::capability_sid_from_name(&format!(
        "harness-mac-spike-spawnreq-{}",
        std::process::id()
    ))
    .expect("derive the spawn-request capability");
    let cap_sid_string =
        crate::win_common::sid_to_string(spawn_cap.as_psid()).expect("capability sid string");
    let user_sid = crate::win_pipe_ipc::current_user_sid_string().expect("current user sid");

    // **`FILE_CREATE_PIPE_INSTANCE`(0x4)を含めない**マスク（§10.1）。
    // `FILE_GENERIC_WRITE`(0x120116)はこのビットを含むので、そのまま与えてはいけない。
    const READ_WRITE_WITHOUT_CREATE_INSTANCE: u32 = 0x0012_019B;
    let sddl = format!(
        "D:(A;;GA;;;{user_sid})(A;;0x{:x};;;{cap_sid_string})",
        READ_WRITE_WITHOUT_CREATE_INSTANCE
    );
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide(&sddl).as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .expect("convert the request-pipe SDDL");
    let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let pipe_name = crate::win_pipe_ipc::unique_pipe_name("mac-spike-request");
    let pipe_name_w = wide(&pipe_name);
    // `FILE_FLAG_FIRST_PIPE_INSTANCE`（§10.1の占拠対策）。定数は`Storage::FileSystem`にある。
    let first_instance = windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
    let server = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | first_instance,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            4,
            4096,
            4096,
            0,
            Some(&sa as *const _),
        )
    };
    assert!(!server.is_invalid(), "要求受付パイプを作れなかった: {sddl}");
    let _pipe_guard = super::test_support::scopeguard(|| unsafe {
        let _ = CloseHandle(server);
        let _ = LocalFree(HLOCAL(sd.0));
    });

    // サーバ役: 1往復だけして終わる（`win_pipe_ipc`と同じ長さプレフィックス形式）。
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    let server_handle = SendHandle(server);
    let server_thread = std::thread::spawn(move || {
        let h = server_handle;
        unsafe {
            let _ = ConnectNamedPipe(h.0, None);
            let mut len_buf = [0u8; 4];
            let mut read = 0u32;
            if ReadFile(h.0, Some(&mut len_buf), Some(&mut read), None).is_err() || read != 4 {
                return String::new();
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len.min(4096)];
            let _ = ReadFile(h.0, Some(&mut body), Some(&mut read), None);
            let request = String::from_utf8_lossy(&body[..read as usize]).into_owned();
            let reply = b"spawn-denied-by-policy";
            let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(reply);
            let mut written = 0u32;
            let _ = WriteFile(h.0, Some(&frame), Some(&mut written), None);
            request
        }
    });

    // --- 対の測定: capabilityを積んだ子（往復できるはず） ---
    let mut caps_with: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    caps_with.push(spawn_cap.as_psid());
    let mut client = SpikeSpawn {
        exe: &probe_str,
        args: &["--pipe-client", &pipe_name, "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_with,
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
    .expect("spawn the capable client");
    let (out_with, err_with, _) = client.wait_and_read();
    eprintln!("[S7] capabilityあり: {out_with}\nstderr={err_with}");
    let report_with = last_json_line(&out_with)
        .unwrap_or_else(|| panic!("capableクライアントがJSONを出さなかった: {out_with}"));
    let seen_request = server_thread.join().unwrap_or_default();
    eprintln!("[S7] サーバが受け取った要求: {seen_request:?}");

    // --- capabilityを積まない子（到達できないはず） ---
    let caps_without: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let mut client_without = SpikeSpawn {
        exe: &probe_str,
        args: &["--pipe-client", &pipe_name, "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_without,
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
    .expect("spawn the incapable client");
    let (out_without, _, _) = client_without.wait_and_read();
    eprintln!("[S7] capabilityなし: {out_without}");
    let report_without = last_json_line(&out_without)
        .unwrap_or_else(|| panic!("incapableクライアントがJSONを出さなかった: {out_without}"));

    let connected = |v: &serde_json::Value| v.get("connected").and_then(|c| c.as_bool());
    assert_eq!(
        connected(&report_with),
        Some(true),
        "spawn要求用capabilityを積んだ子が要求受付パイプへ接続できない。§10.1のDACL設計が\
         成立しない: {report_with}"
    );
    assert!(
        seen_request.contains("spawn-request-from-pid-"),
        "サーバ側が要求を受け取れていない（フレーム形式が往復していない）: {seen_request:?}"
    );
    assert_eq!(
        report_with.get("reply_ok").and_then(|c| c.as_bool()),
        Some(true),
        "応答を読めていない（1往復が成立していない）: {report_with}"
    );
    assert_eq!(
        connected(&report_without),
        Some(false),
        "capabilityを積んでいない子が要求受付パイプへ到達できた。§22.2.2の`process: deny`が\
         「パイプに到達すらできない」という二重のdenyにならない: {report_without}"
    );
}

// ---------------------------------------------------------------------------
// §7.1.1 測定4: サンドボックスからコンソール保持プロセスへ到達できないこと
// ---------------------------------------------------------------------------

/// 保持プロセスは「コンソールを持つためだけの、mitigationを積んでいないプロセス」である。
/// **サンドボックスの中からここへ到達できると、機構全体が無意味になる**——乗っ取った側は
/// `CHILD_PROCESS_RESTRICTED`を積んでいないプロセスを手に入れ、そこから制限なくプロセスを
/// 生成できるからである。§7.1.1が「保持プロセスをサンドボックス内に置かない」と決めた
/// 理由がそれで、この測定はその決定が実機で成立していることを確かめる。
///
/// **対で測る**（`B-35`）。拒否側だけを見ると、**プローブが壊れていて全部に失敗していても緑になる**。
/// 同じプローブ・同じ引数を**サンドボックスの外**からも撃ち、そちらでは開けることを見る。
///
/// | 撃つ側 | 期待 | これが無いと言えなくなること |
/// |---|---|---|
/// | AppContainerの子（＝サンドボックス） | 全マスクで**拒否** | — |
/// | AppContainerでない子（対照） | 少なくとも1つで**成功** | 「拒否されたのは境界のおかげ」（計器が生きている証拠が無い） |
///
/// **この測定が語らないこと**（§7.1.1の他の項目）。到達できないことは言うが、
/// 同じコンソールに繋がったシェル同士が互いを読めるか（測定3）は別の問いである。
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn holder_process_is_out_of_reach_from_the_sandbox() {
    let measure_lock = std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-holder-reach");
    std::fs::create_dir_all(
        measure_lock
            .parent()
            .expect("measurement lock has a parent"),
    )
    .expect("create the serialized measurement lock parent");
    std::fs::create_dir(measure_lock).unwrap_or_else(|e| {
        panic!(
            "測定ロックを取得できない（並列測定または前回残骸を確認する）: path={measure_lock:?} error={e}"
        )
    });
    let _measure_lock_cleanup = super::test_support::scopeguard(|| {
        std::fs::remove_dir(measure_lock).ok();
    });

    let (workspace, sid, caps) = spike_workspace();
    let workspace_canonical = workspace
        .path()
        .canonicalize()
        .expect("canonicalize the spike workspace");
    let cleanup_workspace = workspace_canonical.clone();
    let _cleanup = super::test_support::scopeguard(move || {
        let outcome =
            crate::tier2a::session_profile::end_session(&super::revoke::revoke_session_grant);
        eprintln!("[MAC-HOLDER-REACH] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[MAC-HOLDER-REACH] cleanup could not remove workspace: {e}");
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // **どの世界で測ったかを記録へ残す**（`measurement-review`の「構成の記録」）。
    // 昇格して測ると保持プロセスの整合性レベルが本番（非昇格のDaemonが作る）と変わるので、
    // この1行が無いと後から結果の射程を判定できない。
    eprintln!(
        "[MAC-HOLDER-REACH] elevated={} pid={}",
        crate::tier2a::privhelper::is_elevated(),
        std::process::id()
    );

    // 保持プロセス。§7.1.1どおり**サンドボックスの外**（AppContainerでない・capabilityを
    // 1つも持たない）で、`CREATE_NO_WINDOW`＝窓を出さずにコンソールを割り当てる形で起こす。
    let holder_report = workspace.path().join("holder-reach-holder.json");
    let holder_report_str = holder_report.to_string_lossy().into_owned();
    let holder_args = [
        "--idle-secs",
        "30",
        "--timeout-secs",
        "60",
        "--report-file",
        holder_report_str.as_str(),
    ];
    let holder_spec = SpikeSpawn {
        exe: &probe_str,
        args: &holder_args,
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &[],
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: true,
        console: SpikeConsole::NoWindow,
    };
    let holder = wait_until_holder_is_ready(&holder_spec, &holder_report);
    let holder_pid = holder.pid();
    let holder_tid = holder.thread_id();
    eprintln!("[MAC-HOLDER-REACH] holder pid={holder_pid} tid={holder_tid}");

    let reach_args: Vec<String> = vec![
        "--reach-process".into(),
        holder_pid.to_string(),
        "--reach-thread".into(),
        holder_tid.to_string(),
        "--timeout-secs".into(),
        "60".into(),
    ];
    let reach_args_ref: Vec<&str> = reach_args.iter().map(|s| s.as_str()).collect();

    // 撃つ側2種。**軸はAppContainerかどうかの1つだけ**（`B-29`）——引数もexeもcwdも同じにする。
    let mut reports: Vec<(&str, serde_json::Value)> = Vec::new();
    for (label, no_appcontainer, capabilities) in [
        ("sandbox", false, caps_psid.as_slice()),
        ("outside", true, [].as_slice()),
    ] {
        let mut attacker = SpikeSpawn {
            exe: &probe_str,
            args: &reach_args_ref,
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities,
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer,
            console: SpikeConsole::NoWindow,
        }
        .spawn()
        .unwrap_or_else(|e| panic!("spawn the {label} probe: {e}"));
        let (stdout, stderr, code) = attacker.wait_and_read();
        eprintln!("[MAC-HOLDER-REACH] {label}: exit={code} stderr={stderr}\n{stdout}");
        let report = last_json_line(&stdout)
            .unwrap_or_else(|| panic!("{label} probe produced no JSON: {stdout}"));
        reports.push((label, report));
    }
    // 判定より先に畳む（assertで落ちても保持プロセスを残さない）。
    drop(holder);

    let sandbox = &reports[0].1;
    let outside = &reports[1].1;
    let holder_pid_s = holder_pid.to_string();
    let holder_tid_s = holder_tid.to_string();
    let ok = |v: &serde_json::Value, kind: &str, access: &str, target: &str| {
        super::mac_spike_tests::reach_attempt_ok(v, kind, access, Some(target))
    };

    // **先に対照を判定する。** 計器が死んでいるなら、拒否側の結果は何も語らない。
    let outside_query = ok(
        outside,
        "process",
        "PROCESS_QUERY_LIMITED_INFORMATION",
        &holder_pid_s,
    );
    assert_eq!(
        outside_query,
        Some(true),
        "対照（AppContainerでない子）からも保持プロセスを開けない。プローブか的が壊れており、\
         サンドボックス側の拒否を「境界のおかげ」と読めない: outside={outside}"
    );

    // 本命。**全マスクで拒否**であることを、マスクごとに名指しで確かめる
    // ——「1つ拒否された」では、残りが開いている可能性を排除できない。
    const PROCESS_MASKS: &[&str] = &[
        "PROCESS_QUERY_LIMITED_INFORMATION",
        "PROCESS_QUERY_INFORMATION",
        "PROCESS_VM_READ",
        "PROCESS_VM_WRITE",
        "PROCESS_CREATE_THREAD",
        "PROCESS_DUP_HANDLE",
        "PROCESS_ALL_ACCESS",
    ];
    for mask in PROCESS_MASKS {
        assert_eq!(
            ok(sandbox, "process", mask, &holder_pid_s),
            Some(false),
            "サンドボックスからコンソール保持プロセスを {mask} で開けた。\
             §7.1.1の「保持プロセスをサンドボックス内に置かない」が実機で成立していない\
             ＝乗っ取れば制限なしのプロセス生成能力が手に入る: sandbox={sandbox}"
        );
    }

    // スレッドも対で見る。プロセスを閉じてもスレッドが開けば`SetThreadContext`で乗っ取れる
    // （§S2bが同じ形の穴を実測している）。
    const THREAD_MASKS: &[&str] = &[
        "THREAD_QUERY_LIMITED_INFORMATION",
        "THREAD_SUSPEND_RESUME",
        "THREAD_SET_CONTEXT",
        "THREAD_ALL_ACCESS",
    ];
    for mask in THREAD_MASKS {
        assert_eq!(
            ok(sandbox, "thread", mask, &holder_tid_s),
            Some(false),
            "サンドボックスから保持プロセスのスレッドを {mask} で開けた: sandbox={sandbox}"
        );
    }
}

/// `unexpected_stderr`が**既知の1行だけ**を除いていることを、実機を使わずに固定する。
///
/// **この検算が無いと、除外規則が広すぎても測定は緑のままになる**——実機の回は既知の1行しか
/// 出さないので、「全部除いている」実装と区別が付かない（B-27: 歯があることを確かめる）。
#[test]
fn the_known_startup_noise_filter_only_removes_that_one_line() {
    let run = |stderr: &str| AttachedShellRun {
        console_processes: Vec::new(),
        stdout: String::new(),
        stderr: stderr.to_string(),
        exit_code: 0,
        marker: None,
    };
    const NOISE: &str = "Attempting to perform the InitializeDefaultDrives operation on the \
                         'FileSystem' provider failed.";

    assert!(
        run(&format!("{NOISE}\r\n")).unexpected_stderr().is_empty(),
        "既知の起動時ノイズだけの回が「想定外あり」になっている"
    );
    assert_eq!(
        run(&format!("{NOISE}\r\nsomething else went wrong\r\n")).unexpected_stderr(),
        vec!["something else went wrong"],
        "既知の1行と一緒に出た別の行まで消えている（無言の失敗を見逃す）"
    );
    // **前方一致で消していないこと。** 既知の行に何かが続く形は別の事実なので残す。
    assert_eq!(
        run(&format!("{NOISE} and then it crashed\r\n")).unexpected_stderr(),
        vec![format!("{NOISE} and then it crashed")],
        "既知の行を接頭辞として扱っており、続きが付いた行まで消えている"
    );
    assert!(
        run("\r\n  \r\n").unexpected_stderr().is_empty(),
        "空行だけの回が「想定外あり」になっている"
    );
}

/// `stdio_redirected`が拾うのは**その印の行だけ**であること。
#[test]
fn the_stdio_marker_is_read_from_its_own_line() {
    let run = AttachedShellRun {
        console_processes: Vec::new(),
        stdout: "HARNESS-ATTACH-CONSOLE-CHILD=CHILD-DENIED-Win32Exception-367\r\n\
                 HARNESS-ATTACH-CONSOLE-STDIO=True/True/True\r\n\
                 HARNESS-ATTACH-CONSOLE-STDOUT\r\n"
            .to_string(),
        stderr: String::new(),
        exit_code: 37,
        marker: None,
    };
    assert_eq!(run.stdio_redirected(), Some("True/True/True"));
    assert_eq!(
        run.child_creation(),
        Some("CHILD-DENIED-Win32Exception-367"),
        "印が2つ並んだときに隣の行を拾っている"
    );

    let missing = AttachedShellRun {
        console_processes: Vec::new(),
        stdout: "HARNESS-ATTACH-CONSOLE-STDOUT\r\n".to_string(),
        stderr: String::new(),
        exit_code: 37,
        marker: None,
    };
    assert_eq!(
        missing.stdio_redirected(),
        None,
        "印が無い回を`Some`で返すと、測っていないことを測ったことにできてしまう"
    );
}
