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

use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS,
};
use windows::Win32::System::Console::{AttachConsole, FreeConsole, GetConsoleProcessList};
use windows::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
};
use windows::Win32::System::Threading::GetProcessHandleCount;

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

/// 起こした子のレポートに印が現れるまで待つ。**現れないまま時間切れなら落とす。**
///
/// 仕掛かっていない相手を撃っても、測っているのは「届くか」ではなく競走になる。
/// だから「撃ってよい時点」は待ち時間ではなく**相手の申告**で決める。
fn wait_until_report_contains(pid: u32, report: &std::path::Path, marker: &str) {
    for _ in 0..100 {
        if std::fs::read_to_string(report)
            .map(|body| body.contains(marker))
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!(
        "child did not report readiness: pid={pid} marker={marker} report={:?}",
        std::fs::read_to_string(report).ok()
    );
}

fn wait_until_holder_is_ready(holder: &SpikeSpawn<'_>, report: &std::path::Path) -> SpikeChild {
    let child = holder.spawn().expect("spawn the console holder");
    wait_until_report_contains(child.pid(), report, "\"mode\":\"idle\"");
    child
}

/// 1本のコンソールへ次々と腕を載せるときの、**腕ごとに変わらない部分**。
///
/// 借りて、起こして、すぐ返す——設計書§7.1.1の窓と同じ形である。**返さないと、
/// 測っているこのプロセス自身が`CTRL_BREAK_EVENT`の巻き添えで落ちる**ので、
/// `AttachConsole`から`CreateProcessW`までをこの型の中に閉じ、呼び出し側へ
/// コンソールを持たせたまま帰らせない。
///
/// [`run_restricted_shell_while_attached`]との違いは的である——あちらは
/// `CHILD_PROCESS_RESTRICTED`を積んだ**シェル**を1本走らせて印を読む。こちらは
/// プローブを腕として何本も載せる（読む・書く・撃つ・待つ）。
struct ConsoleArms<'a> {
    /// ログ行の接頭辞。**測定ごとに変える**（同じ回の出力を後から選り分けるため）。
    tag: &'a str,
    probe: &'a str,
    cwd: &'a std::path::Path,
    container_sid: PSID,
    holder_pid: u32,
}

impl ConsoleArms<'_> {
    /// 腕を1本起こして、走らせたまま返す（的・撃ち手のように「生きている間に見る」腕用）。
    fn spawn(
        &self,
        label: &str,
        args: &[&str],
        capabilities: &[PSID],
        no_appcontainer: bool,
        console: SpikeConsole,
    ) -> Result<SpikeChild, String> {
        unsafe {
            let _ = FreeConsole();
        }
        let holder_pid = self.holder_pid;
        let _detach = if console == SpikeConsole::Inherit {
            unsafe {
                AttachConsole(holder_pid)
                    .map_err(|e| format!("{label}: AttachConsole({holder_pid}) failed: {e}"))?;
            }
            Some(ConsoleDetachGuard)
        } else {
            None
        };
        SpikeSpawn {
            exe: self.probe,
            args,
            cwd: self.cwd,
            container_sid: self.container_sid,
            capabilities,
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer,
            console,
        }
        .spawn()
        .map_err(|e| format!("{label}: spawn failed: {e}"))
    }

    /// 腕を1本起こして終わるまで待ち、レポート（最後のJSON行）を返す。
    fn read(
        &self,
        label: &str,
        args: &[&str],
        capabilities: &[PSID],
        no_appcontainer: bool,
        console: SpikeConsole,
    ) -> serde_json::Value {
        let mut child = self
            .spawn(label, args, capabilities, no_appcontainer, console)
            .unwrap_or_else(|e| panic!("{e}"));
        let (stdout, stderr, code) = child.wait_and_read();
        let tag = self.tag;
        eprintln!("[{tag}] {label}: exit={code} stderr={stderr}\n{stdout}");
        last_json_line(&stdout).unwrap_or_else(|| panic!("{label} produced no JSON: {stdout}"))
    }
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

// ---------------------------------------------------------------------------
// §7.1.1 測定2: attach/detachの往復に耐えるか
// ---------------------------------------------------------------------------

/// このプロセスが現在開いているカーネルハンドルの本数。
///
/// **`None`は「0本」ではなく「数えられなかった」である。** 混ぜると、計器が死んだ回を
/// 「漏れていない」と読むことになる。
fn open_handle_count() -> Option<u32> {
    let mut count: u32 = 0;
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) }
        .ok()
        .map(|()| count)
}

/// `AttachConsole`→`FreeConsole`を1往復ぶん、`cycles`回繰り返す。
/// **設計書§7.1.1の窓と同じ順序**で、中身（`CreateProcessW`）だけを抜いてある。
///
/// 途中で失敗したら**何回目かを添えて**返す——「何回目で壊れたか」は「壊れた」より強い事実で、
/// 実装が窓を開ける上限を決めるのに要る。
fn cycle_console_loan(holder_pid: u32, cycles: u32) -> Result<(), String> {
    for i in 0..cycles {
        unsafe {
            // 既定状態（未接続）へ戻す。既に未接続なら失敗するが、その状態が目的なので無視する。
            let _ = FreeConsole();
            AttachConsole(holder_pid)
                .map_err(|e| format!("AttachConsole failed on cycle {i} of {cycles}: {e}"))?;
        }
        // **借りられたことを毎回確かめる。** `AttachConsole`が成功を返しても、構成員に
        // 自分が載っていなければ借りられていない（無言失敗、B-10）。
        let mut process_ids = [0u32; 8];
        let count = unsafe { GetConsoleProcessList(&mut process_ids) } as usize;
        if count == 0 || count > process_ids.len() {
            unsafe {
                let _ = FreeConsole();
            }
            return Err(format!(
                "console membership is unreadable on cycle {i} of {cycles}: count={count}"
            ));
        }
        if !process_ids[..count].contains(&std::process::id()) {
            unsafe {
                let _ = FreeConsole();
            }
            return Err(format!(
                "attached but not a member on cycle {i} of {cycles}: members={:?}",
                &process_ids[..count]
            ));
        }
        unsafe {
            FreeConsole()
                .map_err(|e| format!("FreeConsole failed on cycle {i} of {cycles}: {e}"))?;
        }
    }
    Ok(())
}

/// **§7.1.1測定2**: コンソールの貸し借りを繰り返してもDaemon役が壊れないか。
///
/// 設計書は窓（`AttachConsole`〜`CreateProcessW`〜`FreeConsole`）を**spawnのたびに**開け閉めすると
/// 決めている。壊れるなら窓を広げる——つまりDaemonがコンソールに繋がったままになり、
/// **サンドボックスから`GenerateConsoleCtrlEvent`でDaemonを落とせる形**を受け入れることになる。
/// §7.1.1はまさにそれを避けて窓を閉じたので、ここが崩れると設計判断へ戻る。
///
/// **3つを別々に見る。**
///
/// 1. 往復そのものがN回とも成功するか（失敗したら**何回目か**を返す）
/// 2. ハンドルが残らないか（開始・中間・終了の3点で数える。2点だと「漏れて戻った」と区別できない）
/// 3. **N回の後に実際にシェルが走るか**——1と2が通っても「借りられるが子が動かない」があり得る
///
/// **計器の歯**（`B-27`）: わざとハンドルを漏らすループを同じ回の中で回し、カウンタが実際に
/// 動くことを確かめる。**これが無いと「増えなかった」は「カウンタが動かない」と区別できない。**
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn attach_detach_cycles_do_not_leak_handles_or_break_the_console_loan() {
    // **Nの決め方**: コンソールが要るのは**シェルだけ**（`DETACHED_PROCESS`で起こす
    // node・git・MCPサーバはこの窓を通らない）。1セッションが出す`run_shell`の回数に上限は
    // 無いので、「実運用より多い側」を選ぶしかない。500回なら、1往復につきハンドルが1本でも
    // 漏れれば**+500**として見える——下のSLACKとは2桁違うので取り違えは起きない。
    const CYCLES: u32 = 500;
    // ハンドル数は他の要因（ログのファイル・スレッド）でも数本動く。
    const SLACK: u32 = 32;
    // 計器の歯で意図的に漏らす本数。SLACKより十分大きく取る（でなければ「歯があること」と
    // 「揺らぎ」が区別できない）。
    const DELIBERATE_LEAK: u32 = 256;

    let measure_lock = std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-cycles");
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
        eprintln!("[MAC-CONSOLE-CYCLES] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[MAC-CONSOLE-CYCLES] cleanup could not remove workspace: {e}");
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
    eprintln!(
        "[MAC-CONSOLE-CYCLES] elevated={} shell={shell_label} cycles={CYCLES}",
        crate::tier2a::privhelper::is_elevated()
    );

    let holder_report = workspace.path().join("cycles-holder.json");
    let holder_report_str = holder_report.to_string_lossy().into_owned();
    let holder_args = [
        "--idle-secs",
        "120",
        "--timeout-secs",
        "180",
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

    // --- 1と2: 往復とハンドル数 -------------------------------------------------
    let before = open_handle_count().expect("GetProcessHandleCount(before)");
    let first_half = cycle_console_loan(holder_pid, CYCLES / 2);
    let middle = open_handle_count().expect("GetProcessHandleCount(middle)");
    let second_half = cycle_console_loan(holder_pid, CYCLES / 2);
    let after = open_handle_count().expect("GetProcessHandleCount(after)");
    // 借りたままにしない（以降の腕は既定状態＝未接続から始める）。
    unsafe {
        let _ = FreeConsole();
    }
    eprintln!(
        "[MAC-CONSOLE-CYCLES] handles before={before} middle={middle} after={after} \
         (first_half={first_half:?} second_half={second_half:?})"
    );

    // --- 計器の歯: わざと漏らすと本当に増えるか ---------------------------------
    let leak_before = open_handle_count().expect("GetProcessHandleCount(leak before)");
    let mut leaked: Vec<HANDLE> = Vec::with_capacity(DELIBERATE_LEAK as usize);
    for _ in 0..DELIBERATE_LEAK {
        let mut dup = HANDLE::default();
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &mut dup,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok.is_ok() {
            leaked.push(dup);
        }
    }
    let leak_after = open_handle_count().expect("GetProcessHandleCount(leak after)");
    for h in leaked.drain(..) {
        unsafe {
            let _ = CloseHandle(h);
        }
    }
    let leak_growth = leak_after.saturating_sub(leak_before);
    eprintln!(
        "[MAC-CONSOLE-CYCLES] deliberate leak: before={leak_before} after={leak_after} \
         growth={leak_growth} (leaked {DELIBERATE_LEAK})"
    );
    assert!(
        leak_growth >= DELIBERATE_LEAK / 2,
        "わざと{DELIBERATE_LEAK}本漏らしてもハンドル数が{leak_growth}しか増えない。\
         カウンタが動いていないので、往復のあとで「増えなかった」と言っても意味が無い"
    );

    // --- 判定（往復とハンドル数） -----------------------------------------------
    first_half.unwrap_or_else(|e| {
        panic!("コンソールの貸し借りが前半で壊れた（窓を毎spawn開閉できない）: {e}")
    });
    second_half.unwrap_or_else(|e| {
        panic!("コンソールの貸し借りが後半で壊れた（回数を重ねると壊れる形）: {e}")
    });
    let growth = after.saturating_sub(before);
    assert!(
        growth <= SLACK,
        "{CYCLES}往復でハンドルが{growth}本増えた（許容{SLACK}）。1往復につき漏れているなら\
         約{CYCLES}本になるので、窓を毎spawn開閉する設計が成り立たない: \
         before={before} middle={middle} after={after}"
    );

    // --- 3: 回数を重ねた後でも、実際にシェルが走るか -----------------------------
    // **1と2が通っても、これが落ちることはあり得る**（借りられるが子が動かない）。
    const AFTER_CYCLES: ArmSpec = ArmSpec {
        label: "after-cycles",
        holder_console: SpikeConsole::NoWindow,
        loan: ConsoleLoan::Attach,
        resume_at: ResumePoint::InsideWindow,
    };
    let previous_error_mode = unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
    };
    let _restore_error_mode = super::test_support::scopeguard(move || unsafe {
        SetErrorMode(previous_error_mode);
    });
    let marker = workspace.path().join("cycles-marker.txt");
    let run = run_restricted_shell_while_attached(
        &AFTER_CYCLES,
        holder_pid,
        &shell,
        workspace.path(),
        sid.as_psid(),
        &caps_psid,
        &marker,
    );
    drop(holder);
    let run = run.unwrap_or_else(|e| {
        panic!("{CYCLES}往復の後にシェルを起こせなくなった: shell={shell_label} error={e}")
    });
    eprintln!("[MAC-CONSOLE-CYCLES] after {CYCLES} cycles: {run:?}");
    assert!(
        run.actually_ran() && run.child_creation_denied(),
        "{CYCLES}往復の後は借りられるがシェルが完走しない（状態が残っている）: \
         shell={shell_label} observation={run:?}"
    );
    assert_eq!(
        run.stdio_redirected(),
        Some("True/True/True"),
        "{CYCLES}往復の後に子の標準ハンドルへコンソールが混入した: observation={run:?}"
    );
}

// ---------------------------------------------------------------------------
// §7.1.1 測定6: コンソールを持たせる費用
// ---------------------------------------------------------------------------

/// `iters`回まわして1回あたりのマイクロ秒を返す。
///
/// **1回だけ測って割らない。** 1回の呼び出しはタイマの分解能と同じ桁になり得るので、
/// 「速い」と「測れていない」が区別できなくなる。
fn micros_per_op(iters: u32, mut op: impl FnMut()) -> f64 {
    let start = std::time::Instant::now();
    for _ in 0..iters {
        op();
    }
    start.elapsed().as_secs_f64() * 1e6 / f64::from(iters)
}

/// 標本の最小・中央・最大。**1点で報告しない**（散らばりが分からないと外挿してしまう）。
fn spread(mut samples: Vec<f64>) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in timing samples"));
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let median = samples[samples.len() / 2];
    (min, median, max)
}

/// **§7.1.1測定6**: コンソールを持たせる費用。**シェル起動の増分**を決める。
///
/// 測るのは2つで、**掛かる頻度が違う**。
///
/// | 何を | 頻度 |
/// |---|---|
/// | 保持プロセス＋`conhost`を1本立てる | ドメインにつき1回（[§22.9](DESIGN-MAC-BROKER.md)の費用表に載る） |
/// | `FreeConsole`→`AttachConsole`→`FreeConsole`の窓 | **シェルのspawnごと**。`DETACHED_PROCESS`で起こす大多数は通らない |
///
/// **ドリフトの対照を同じ回で撮る。** 同じ形のループをコンソール操作抜きで回し、
/// ループそのものの費用を引けるようにする——引かないと、測っているのが窓なのか
/// `for`ループなのか分からない。
///
/// **この測定が言わないこと**: 「シェル1本の起動がコンソールのせいでいくら増えたか」は
/// **測れない**。比べる相手（コンソール無しで走るmitigation付きシェル）が存在しないためである
/// ——[§S46b](mac-spike/RESULTS.md)のとおり、借りない腕は起動そのものに失敗する。
/// ここで出るのは**窓の費用**であって、シェル起動の総額ではない。
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn console_loan_cost_is_measured_for_the_holder_and_for_the_per_spawn_window() {
    // 窓の反復回数。500往復まで壊れないことは測定2で確かめてあるので、費用側はその範囲で厚く撮る。
    const WINDOW_ITERS: u32 = 2_000;
    // 窓の標本数（1標本＝WINDOW_ITERS回の平均）。散らばりを出すために複数撮る。
    const WINDOW_SAMPLES: usize = 5;
    // 保持プロセスを立て直す回数。1回では分解能と区別が付かない。
    const HOLDER_SAMPLES: usize = 5;

    let measure_lock = std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-cost");
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
        eprintln!("[MAC-CONSOLE-COST] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[MAC-CONSOLE-COST] cleanup could not remove workspace: {e}");
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });
    let _ = caps;
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    eprintln!(
        "[MAC-CONSOLE-COST] elevated={} window_iters={WINDOW_ITERS} samples={WINDOW_SAMPLES}",
        crate::tier2a::privhelper::is_elevated()
    );

    // --- (a) 保持プロセス＋conhostを1本立てる費用 --------------------------------
    // **`CREATE_NO_WINDOW`での起動と、`"mode":"idle"`を読めるまで**を1回分とする。
    // 「起動して制御が返るまで」ではなく「使えるようになるまで」が、Daemonが実際に待つ時間である。
    let mut holder_ms: Vec<f64> = Vec::with_capacity(HOLDER_SAMPLES);
    let mut last_holder: Option<SpikeChild> = None;
    for i in 0..HOLDER_SAMPLES {
        let report = workspace.path().join(format!("cost-holder-{i}.json"));
        let report_str = report.to_string_lossy().into_owned();
        let args = [
            "--idle-secs",
            "120",
            "--timeout-secs",
            "180",
            "--report-file",
            report_str.as_str(),
        ];
        let spec = SpikeSpawn {
            exe: &probe_str,
            args: &args,
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
        let start = std::time::Instant::now();
        let child = wait_until_holder_is_ready(&spec, &report);
        holder_ms.push(start.elapsed().as_secs_f64() * 1e3);
        // 最後の1本だけ残して窓の測定に使う。残りはここで畳む。
        last_holder = Some(child);
        if i + 1 < HOLDER_SAMPLES {
            last_holder = None;
        }
    }
    let holder = last_holder.expect("the last holder is kept for the window measurement");
    let holder_pid = holder.pid();
    let (h_min, h_med, h_max) = spread(holder_ms.clone());
    eprintln!(
        "[MAC-CONSOLE-COST] holder+conhost ready: min={h_min:.1}ms median={h_med:.1}ms \
         max={h_max:.1}ms samples={holder_ms:?}"
    );

    // --- (b) 窓（FreeConsole → AttachConsole → FreeConsole）の1回あたり ----------
    // **本番の窓と同じ3呼び出しだけを回す。** 測定2が使っている構成員の読み返しは
    // ここでは回さない（あれは検算であって、本番の窓には無い）。
    let mut window_us: Vec<f64> = Vec::with_capacity(WINDOW_SAMPLES);
    let mut drift_us: Vec<f64> = Vec::with_capacity(WINDOW_SAMPLES);
    let mut attach_failures: u32 = 0;
    for _ in 0..WINDOW_SAMPLES {
        window_us.push(micros_per_op(WINDOW_ITERS, || unsafe {
            let _ = FreeConsole();
            if AttachConsole(holder_pid).is_err() {
                attach_failures += 1;
            }
            let _ = FreeConsole();
        }));
        // ドリフトの対照。**同じ形のループ**で、コンソール操作だけを抜く。
        drift_us.push(micros_per_op(WINDOW_ITERS, || {
            std::hint::black_box(std::process::id());
        }));
    }
    unsafe {
        let _ = FreeConsole();
    }
    drop(holder);

    let (w_min, w_med, w_max) = spread(window_us.clone());
    let (d_min, d_med, d_max) = spread(drift_us.clone());
    eprintln!(
        "[MAC-CONSOLE-COST] window(Free+Attach+Free): min={w_min:.1}us median={w_med:.1}us \
         max={w_max:.1}us samples={window_us:?}"
    );
    eprintln!(
        "[MAC-CONSOLE-COST] drift(loop only): min={d_min:.3}us median={d_med:.3}us \
         max={d_max:.3}us samples={drift_us:?}"
    );
    eprintln!(
        "[MAC-CONSOLE-COST] window minus drift (median) = {:.1}us per shell spawn",
        w_med - d_med
    );

    // --- 検算: 測っているものが本当に走ったか -----------------------------------
    // **`AttachConsole`が失敗した回が混ざっていると、速いのは「何もしていないから」になる。**
    assert_eq!(
        attach_failures, 0,
        "窓の測定中にAttachConsoleが{attach_failures}回失敗した。\
         失敗した回が混ざった平均は費用として読めない"
    );
    // ループそのものの費用が窓の費用と同じ桁なら、測っているのは窓ではない。
    assert!(
        w_med > d_med * 10.0,
        "窓の費用({w_med:.3}us)がループの費用({d_med:.3}us)と同じ桁である。\
         この数字はコンソール操作の費用として読めない"
    );
    // 保持プロセスの起動が0msなら、`wait_until_holder_is_ready`が待っていない＝測れていない。
    assert!(
        h_min > 0.0,
        "保持プロセスの起動が0msと出た。準備完了を待てていない: samples={holder_ms:?}"
    );
}

// ---------------------------------------------------------------------------
// §7.1.1 測定3: 同じコンソールに繋がったプロセス同士が干渉できるか
// ---------------------------------------------------------------------------

/// `console_share`モードのレポートから試行1件を引く。
///
/// **`ok`だけでなくレコードごと返す**——読み取りの腕では`text`まで見たいので、
/// 真偽だけに畳むと「読めたが中身が違う」を落とすことになる。
fn console_attempt<'a>(report: &'a serde_json::Value, kind: &str) -> Option<&'a serde_json::Value> {
    report
        .get("attempts")?
        .as_array()?
        .iter()
        .find(|a| a.get("kind").and_then(|k| k.as_str()) == Some(kind))
}

/// 読み取りの腕が、探している印を実際に見たか。
///
/// `None`＝読み取りの試行そのものがレポートに無い（プローブが撃っていない）。
/// **「読めなかった」と混同しない。**
fn console_read_saw(report: &serde_json::Value, marker: &str) -> Option<bool> {
    let attempt = console_attempt(report, "console-read")?;
    if attempt.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        return Some(false);
    }
    Some(
        attempt
            .get("text")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t.contains(marker)),
    )
}

/// **§7.1.1測定3**: 1本のコンソールを2つのドメインで共有したとき、互いに干渉できるか。
///
/// **決まるのは保持プロセスの分割単位である。** ファイル・ネットワーク・プロセスはドメインごとに
/// 分けてあるので、コンソールだけが横断チャネルとして残ると、そこがいちばん弱い辺になる。
///
/// **結論は両方向に効く。**
///
/// - 読める／落とせる → 保持プロセスは**ドメインごとに1本**要る（[§22.9](DESIGN-MAC-BROKER.md)の費用表がそのまま）
/// - サンドボックスから画面バッファへ**触れない** → 通り道が無いので**共有できる余地**が出る（費用が減る）
///
/// **腕は5つで、隣とは軸を1つだけ変える**（`B-29`）。
///
/// | 腕 | AppContainerか | ドメイン | コンソール | 役割 |
/// |---|---|---|---|---|
/// | `writer` | はい | A | 借りる | 印を書き、**自分で読み返す**（書けたことの検算） |
/// | `same-domain` | はい | A | 借りる | 同じドメインなら読めるか |
/// | `other-domain` | はい | **B** | 借りる | **本命** |
/// | `no-console` | はい | A | **持たない** | 効いているのがコンソール参加であることの対照 |
/// | `outside` | **いいえ** | – | 借りる | **計器が生きていることの対照**。ここが読めないなら他の腕の「読めない」は何も語らない |
///
/// **書けたことを先に確かめる。** `writer`が自分で読み返せていなければ、他の腕が
/// 「読めなかった」ことはコンソールの性質を語らない（測っていないだけである）。
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn one_console_shared_by_two_domains_is_measured_for_read_and_ctrl_break() {
    const MARKER: &str = "HARNESS-CONSOLE-SHARE-MARKER";

    let measure_lock = std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-share");
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
        eprintln!("[MAC-CONSOLE-SHARE] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[MAC-CONSOLE-SHARE] cleanup could not remove workspace: {e}");
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });

    // ドメインAとドメインBの身分証。**この1本だけが2つの腕の差である。**
    let pid = std::process::id();
    let domain_a = super::capability_sid_from_name(&format!("harness-console-share-A-{pid}"))
        .expect("derive domain A capability");
    let domain_b = super::capability_sid_from_name(&format!("harness-console-share-B-{pid}"))
        .expect("derive domain B capability");
    let mut caps_a: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let mut caps_b = caps_a.clone();
    caps_a.push(domain_a.as_psid());
    caps_b.push(domain_b.as_psid());

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    eprintln!(
        "[MAC-CONSOLE-SHARE] elevated={}",
        crate::tier2a::privhelper::is_elevated()
    );

    let holder_report = workspace.path().join("share-holder.json");
    let holder_report_str = holder_report.to_string_lossy().into_owned();
    let holder_args = [
        "--idle-secs",
        "120",
        "--timeout-secs",
        "180",
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
    eprintln!("[MAC-CONSOLE-SHARE] holder pid={holder_pid}");

    let arms = ConsoleArms {
        tag: "MAC-CONSOLE-SHARE",
        probe: &probe_str,
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        holder_pid,
    };
    let spawn_arm = |label: &str,
                     args: &[&str],
                     capabilities: &[PSID],
                     no_appcontainer: bool,
                     console: SpikeConsole|
     -> Result<SpikeChild, String> {
        arms.spawn(label, args, capabilities, no_appcontainer, console)
    };
    let read_arm = |label: &str,
                    args: &[&str],
                    capabilities: &[PSID],
                    no_appcontainer: bool,
                    console: SpikeConsole|
     -> serde_json::Value {
        arms.read(label, args, capabilities, no_appcontainer, console)
    };

    // --- 腕1: 書いて自分で読み返す（書けたことの検算） --------------------------
    let writer = read_arm(
        "writer(domainA)",
        &[
            "--console-write",
            MARKER,
            "--console-read",
            "--timeout-secs",
            "60",
        ],
        &caps_a,
        false,
        SpikeConsole::Inherit,
    );
    // --- 腕2〜5: 読むだけ -------------------------------------------------------
    let read_args = ["--console-read", "--timeout-secs", "60"];
    let same_domain = read_arm(
        "same-domain(A)",
        &read_args,
        &caps_a,
        false,
        SpikeConsole::Inherit,
    );
    let other_domain = read_arm(
        "other-domain(B)",
        &read_args,
        &caps_b,
        false,
        SpikeConsole::Inherit,
    );
    let no_console = read_arm(
        "no-console(A)",
        &read_args,
        &caps_a,
        false,
        SpikeConsole::Detached,
    );
    let outside = read_arm(
        "outside(instrument)",
        &read_args,
        &[],
        true,
        SpikeConsole::Inherit,
    );

    let membership = |r: &serde_json::Value| {
        r.get("membership")
            .and_then(|m| m.get("attached"))
            .and_then(|a| a.as_bool())
    };
    eprintln!(
        "[MAC-CONSOLE-SHARE] attached? writer={:?} same={:?} other={:?} nocon={:?} outside={:?}",
        membership(&writer),
        membership(&same_domain),
        membership(&other_domain),
        membership(&no_console),
        membership(&outside),
    );
    eprintln!(
        "[MAC-CONSOLE-SHARE] saw marker? writer={:?} same={:?} other={:?} nocon={:?} outside={:?}",
        console_read_saw(&writer, MARKER),
        console_read_saw(&same_domain, MARKER),
        console_read_saw(&other_domain, MARKER),
        console_read_saw(&no_console, MARKER),
        console_read_saw(&outside, MARKER),
    );

    // --- 腕6: 撃たなければ的は生き残るか（**Ctrl+Breakの対照**） ----------------
    // これが無いと、あとで的が死んだのを「Ctrl+Breakのせい」と言えない
    // ——待ち時間で勝手に終わっていただけかもしれない。
    let idle_args = [
        "--console-write",
        MARKER,
        "--console-idle-secs",
        "25",
        "--timeout-secs",
        "90",
    ];
    let control_target = spawn_arm(
        "ctrl-break control(domainA, 撃たない)",
        &idle_args,
        &caps_a,
        false,
        SpikeConsole::Inherit,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let control_wait = unsafe { WaitForSingleObject(control_target.process(), 5_000) };
    let control_survived = control_wait != WAIT_OBJECT_0;
    eprintln!("[MAC-CONSOLE-SHARE] control target survived 5s without a break: {control_survived}");
    drop(control_target);

    // --- 腕7・8: Ctrl+Breakで相手を落とせるか -----------------------------------
    // 的は**生きたまま待つ**腕。落とされれば早く終わり、落とされなければ待ち切る。
    let target = spawn_arm(
        "ctrl-break target(domainA)",
        &idle_args,
        &caps_a,
        false,
        SpikeConsole::Inherit,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // 的が実際にコンソールへ載って待ち始めるまで少しだけ待つ（載る前に撃つと何も測れない）。
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let attacker = read_arm(
        "ctrl-break attacker(domainB)",
        &["--console-ctrl-break", "--timeout-secs", "60"],
        &caps_b,
        false,
        SpikeConsole::Inherit,
    );
    let ctrl_break_sent = console_attempt(&attacker, "console-ctrl-break")
        .and_then(|a| a.get("ok").and_then(|o| o.as_bool()));

    // 的が落ちたか。**待ち切ったら落ちていない**（`--console-idle-secs 25`のうち5秒しか待たない）。
    let wait = unsafe { WaitForSingleObject(target.process(), 5_000) };
    let target_died = wait == WAIT_OBJECT_0;
    // 保持プロセスも同じコンソールの構成員なので、巻き添えを別に見る
    // ——保持プロセスが落ちるとコンソールごと消えるので、脅威としては的より重い。
    let holder_wait = unsafe { WaitForSingleObject(holder.process(), 100) };
    let holder_died = holder_wait == WAIT_OBJECT_0;
    eprintln!(
        "[MAC-CONSOLE-SHARE] ctrl-break sent={ctrl_break_sent:?} target_died={target_died} \
         holder_died={holder_died}"
    );
    drop(target);
    drop(holder);

    // --- 判定 -------------------------------------------------------------------
    // **計器から先に見る。** 外の対照が読めないなら、他の腕の「読めない」は何も語らない。
    assert_eq!(
        console_read_saw(&outside, MARKER),
        Some(true),
        "AppContainerでない対照からも画面バッファを読めない。プローブか仕込みが壊れており、\
         サンドボックス側の結果を読んではいけない: outside={outside}"
    );
    // **書けたことの検算は、書いた本人ではなく外の腕が担う。**
    // 実測では**サンドボックスの中からは読み返せない**（下記）ので、
    // 「書いた本人が読み返す」を検算に使うと、書けているのに測定が成立しなくなる。
    // 上の`outside`のassertが真であること自体が「印が画面バッファに載った」の証拠である。
    let write_ok = console_attempt(&writer, "console-write")
        .and_then(|a| a.get("ok").and_then(|o| o.as_bool()));
    assert_eq!(
        write_ok,
        Some(true),
        "サンドボックスの中から画面バッファへ書けなかった。書けていないなら、\
         他の腕が読めなかったことは何も語らない: writer={writer}"
    );

    // コンソールを持たない腕は`CONOUT$`をそもそも開けないはず。
    // **ここが真なら、効いているのはコンソール参加ではない。**
    let no_console_open = console_attempt(&no_console, "conout-open")
        .and_then(|a| a.get("ok").and_then(|o| o.as_bool()));
    assert_eq!(
        no_console_open,
        Some(false),
        "コンソールを継承していない子が`CONOUT$`を開けた。この測定は\
         「コンソール参加による干渉」を測れていない: no_console={no_console}"
    );

    // --- 読み取り: サンドボックスの中からは**ドメインを問わず**閉じている -------
    // **実測をそのまま固定する**（逆転したら測り直す合図。値の解釈は`RESULTS.md`が持つ）。
    let read_ok = |r: &serde_json::Value| {
        console_attempt(r, "console-read").and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
    };
    for (label, report) in [
        ("writer(A)", &writer),
        ("same-domain(A)", &same_domain),
        ("other-domain(B)", &other_domain),
    ] {
        assert_eq!(
            read_ok(report),
            Some(false),
            "サンドボックスの中から画面バッファを読めた（腕={label}）。\
             §S48が測った「書けるが読めない」が逆転しているので、\
             保持プロセスの分割単位を測り直すこと: {report}"
        );
    }
    // **ドメインの違いは読み取りの可否を変えない。** 変わったなら、コンソールが
    // capabilityで守られていることになり、設計の前提が変わる。
    assert_eq!(
        read_ok(&same_domain),
        read_ok(&other_domain),
        "ドメインの違いだけで画面バッファの読み取り可否が変わった: \
         same={same_domain} other={other_domain}"
    );

    // --- Ctrl+Break: 撃てるし、的も**保持プロセスも**落ちる ---------------------
    // 対照を先に見る。撃たなくても的が5秒で終わるなら、下の`target_died`は何も語らない。
    assert!(
        control_survived,
        "Ctrl+Breakを撃っていない的が5秒で終わった。落ちたことを「撃ったから」と読めない"
    );
    assert_eq!(
        ctrl_break_sent,
        Some(true),
        "Ctrl+Breakを撃てていない。落ちなかったことを「守られている」と読めない: {attacker}"
    );
    assert!(
        target_died,
        "別ドメインからCtrl+Breakを撃っても的が落ちなかった。\
         §7.1.1が可用性の脅威として挙げた形が成立しないので、記録と設計を見直すこと"
    );
    // **これがこの測定でいちばん重い事実である。** 保持プロセスが落ちるとコンソールごと消え、
    // そのコンソールを共有していた**全ドメイン**がシェルを起こせなくなる。
    assert!(
        holder_died,
        "Ctrl+Breakで保持プロセスが落ちなかった。§S48が測った「巻き添えで保持プロセスごと消える」\
         が成立しないなら、保持プロセスの分割単位の根拠が変わる"
    );
}

/// 1ラウンド分の観測（守った保持プロセスと守らない保持プロセスを、同じ回で1本ずつ撃つ）。
struct GuardRound {
    /// ラウンドの間だけ生かしておく保持プロセス。**守った側は撃たれた後も使う**ので返す。
    holder: SpikeChild,
    /// 保持プロセスが自分で名乗った構成（`ctrl_guard`）。
    holder_report: serde_json::Value,
    ctrl_break_sent: Option<bool>,
    target_died: bool,
    holder_died: bool,
}

/// §7.1.1の測定7: **保持プロセスは`SetConsoleCtrlHandler`で自分を守れるか。**
///
/// [§S48](../../../../../plans/mac-spike/RESULTS.md)が測ったのは「**撃った側**が自分を守れる」
/// ことだけで（計器がそれで自分を守っていた）、**撃たれる側**が同じ手で守れるかは撮っていない。
/// 仕組みは同じなので通る見込みは高いが、**未測定を根拠に「塞がっている」と書くと、
/// 既知の対処を解決済みの根拠に使う形**（`plan-review-gates`検問6）をそのまま踏む。
///
/// | 腕 | 保持プロセス | 撃つイベント | これが無いと何が言えなくなるか |
/// |---|---|---|---|
/// | `unguarded/break`（対照＝計器の歯） | ハンドラ**無し** | `CTRL_BREAK_EVENT` | 「生き残った」を「ハンドラのおかげ」と読めない。§S48の再現を**同じ回で**取る |
/// | `guarded/break` | ハンドラ**有り** | `CTRL_BREAK_EVENT` | 本命 |
/// | `guarded/ctrl-c` | ハンドラ有り | **`CTRL_C_EVENT`** | 守りが**片方の種類にしか効かない**なら「サンドボックスから届く経路が塞がった」と書けない |
/// | 的のシェル（全ラウンド） | ハンドラ無し | — | イベントが実際に配達されたことを言えない。守った腕で保持プロセスが生き残っても、「撃てていなかっただけ」と区別できない |
/// | 撃たれた後の再利用 | ハンドラ有り | — | 「生きているが壊れている」を排除できない。生き残ったコンソールで実際にシェルを1本完走させる |
///
/// **撃たない対照は置いていない。** §S48が既に「撃たなければ的は5秒生き残る」を測っており、
/// 本測定では**同じラウンドの的が落ちること**が配達の証拠を兼ねるためである。
///
/// # `CTRL_C_EVENT`のラウンドは、守りについて何も言わない（実測、2026-09-05）
///
/// 撃つこと自体は成功する（`ok=true`）のに、**守っていない的も落ちなかった**（3回とも）。
/// 配達の証拠が取れないので、**同じラウンドで保持プロセスが生き残ったことを
/// 「ハンドラのおかげ」と読んではいけない**——効かないイベントを撃っただけかもしれない。
///
/// **したがってこのラウンドが固定しているのは「この構成では`CTRL_C_EVENT`が
/// 守っていない相手にも効かなかった」という事実だけ**である。逆転したら、この腕は
/// 初めて守りについての結論を持つ（そのときは記録を更新する）。
/// `unguarded/ctrl-c`の腕を足していないのは、**このラウンドの的がまさに
/// 守っていないプロセス**であり、同じことを2度測ることになるためである。
///
/// 実行（**昇格しないこと**。昇格すると保持プロセスの整合性レベルが本番と変わる、`B-08`）:
///
/// ```text
/// cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture \
///   console_holder_survives_ctrl_break_when_it_guards_itself
/// ```
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn console_holder_survives_ctrl_break_when_it_guards_itself() {
    const TAG: &str = "MAC-CONSOLE-HOLDER-GUARD";

    // 測定ロックは**この測定専用の名前**にする。§S48の測定と同じ名前にすると、
    // 2つが並行に走った回に必ず片方が「前回残骸」と読める形で落ちる。
    let measure_lock =
        std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-holder-guard");
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
        eprintln!("[{TAG}] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[{TAG}] cleanup could not remove workspace: {e}");
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });

    // 的と撃ち手を別ドメインにするのは、**§S48から軸を1つだけ変える**ためである
    // （あちらも別ドメインから撃っている）。同じドメインにすると、変わった軸が
    // 「守りの有無」と「ドメインが同じか」の2つになる。
    let pid = std::process::id();
    let domain_a = super::capability_sid_from_name(&format!("harness-holder-guard-A-{pid}"))
        .expect("derive domain A capability");
    let domain_b = super::capability_sid_from_name(&format!("harness-holder-guard-B-{pid}"))
        .expect("derive domain B capability");
    let mut caps_a: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let mut caps_b = caps_a.clone();
    caps_a.push(domain_a.as_psid());
    caps_b.push(domain_b.as_psid());

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    eprintln!(
        "[{TAG}] elevated={}",
        crate::tier2a::privhelper::is_elevated()
    );

    // `event_arg`は撃ち手へ渡す引数、`attempt_kind`はそのレポートに現れる試行名。
    // **2つを別々に渡している**のは、綴りをテスト側で組み立てるとプローブ側の綴りと
    // 静かにずれるためである（ずれると「撃てていない」ではなく「見つからない」で落ちる）。
    // `accept`は保持プロセスと的の**両方**から「Ctrl+Cを無視する」継承属性を外す腕。
    // 外さないと`CTRL_C_EVENT`はハンドラを呼ばずに捨てられるので（[§S50](mac-spike/RESULTS.md)）、
    // **守りが効いたのか弾が届いていないのかが割れない**。
    let run_round = |label: &str,
                     guard: bool,
                     accept: bool,
                     event_arg: &str,
                     attempt_kind: &str|
     -> GuardRound {
        let holder_report_path = workspace
            .path()
            .join(format!("{}-holder.json", label.replace('/', "-")));
        let holder_report_str = holder_report_path.to_string_lossy().into_owned();
        let mut holder_args = vec![
            "--idle-secs",
            "120",
            "--timeout-secs",
            "180",
            "--report-file",
            holder_report_str.as_str(),
        ];
        if guard {
            holder_args.push("--console-guard-ctrl");
        }
        if accept {
            holder_args.push("--console-ctrl-accept");
        }
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
            // 保持プロセスはサンドボックスの**外**（§7.1.1）。ここを変えると測る対象が別物になる。
            no_appcontainer: true,
            console: SpikeConsole::NoWindow,
        };
        // **レポートが見えた時点で守りは既に掛かっている**（プローブがハンドラを
        // 最初に掛けてからレポートを書く）ので、この待ちが「撃ってよい時点」を兼ねる。
        let holder = wait_until_holder_is_ready(&holder_spec, &holder_report_path);
        let holder_pid = holder.pid();
        let holder_report: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&holder_report_path).expect("read the holder report"),
        )
        .expect("the holder report is JSON");
        eprintln!("[{TAG}] {label}: holder pid={holder_pid} report={holder_report}");

        let arms = ConsoleArms {
            tag: TAG,
            probe: &probe_str,
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            holder_pid,
        };

        // 的は**両ラウンドとも守らない**。ここが落ちることが「イベントが配達された」の印になる。
        let mut target_args = vec!["--console-idle-secs", "25", "--timeout-secs", "90"];
        if accept {
            // **的からも外す。** 的が受け取れないと、落ちないことが配達の証拠にならない。
            target_args.push("--console-ctrl-accept");
        }
        let target = arms
            .spawn(
                &format!("{label}/target(domainA)"),
                &target_args,
                &caps_a,
                false,
                SpikeConsole::Inherit,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        // 的がコンソールへ載って待ち始めるまで待つ（載る前に撃つと何も測れない）。
        std::thread::sleep(std::time::Duration::from_millis(1500));

        let attacker = arms.read(
            &format!("{label}/attacker(domainB)"),
            &[event_arg, "--timeout-secs", "60"],
            &caps_b,
            false,
            SpikeConsole::Inherit,
        );
        let ctrl_break_sent = console_attempt(&attacker, attempt_kind)
            .and_then(|a| a.get("ok").and_then(|o| o.as_bool()));

        // **待ち切ったら落ちていない**（的は25秒待つ腕で、こちらは5秒しか待たない）。
        let target_died = unsafe { WaitForSingleObject(target.process(), 5_000) } == WAIT_OBJECT_0;
        let holder_died = unsafe { WaitForSingleObject(holder.process(), 100) } == WAIT_OBJECT_0;
        eprintln!(
            "[{TAG}] {label}: sent={ctrl_break_sent:?} target_died={target_died} \
             holder_died={holder_died}"
        );
        drop(target);

        GuardRound {
            holder,
            holder_report,
            ctrl_break_sent,
            target_died,
            holder_died,
        }
    };

    // **対照を先に撃つ。** §S48の再現をこの回の中で取ってから本命へ進む。
    const BREAK: (&str, &str) = ("--console-ctrl-break", "console-ctrl-break");
    const CTRL_C: (&str, &str) = ("--console-ctrl-c", "console-ctrl-c");
    let control = run_round("unguarded/break", false, false, BREAK.0, BREAK.1);
    drop(control.holder);
    let guarded = run_round("guarded/break", true, false, BREAK.0, BREAK.1);
    let guarded_ctrl_c = run_round("guarded/ctrl-c", true, false, CTRL_C.0, CTRL_C.1);
    // **設計にとっての本命。** 「Ctrl+Cを無視する」継承属性を保持プロセスと的の両方から外し、
    // **Ctrl+Cが実際に配達される世界**で握り潰しが効くかを見る。本番のDaemonが何を受け継ぐかは
    // 分からないので、**受け取れる側に倒した世界でも守れる**ことが要る。
    let guarded_accept_ctrl_c = run_round("guarded+accept/ctrl-c", true, true, CTRL_C.0, CTRL_C.1);

    // --- 判定 -------------------------------------------------------------------
    // **腕が別物であることを先に見る。** 引数が無視されていると、2ラウンドは同じものになり、
    // 以下の比較は何も語らない。
    let ctrl_guard = |report: &serde_json::Value| report.get("ctrl_guard").cloned();
    assert_eq!(
        ctrl_guard(&control.holder_report),
        Some(serde_json::Value::Null),
        "守らない側の保持プロセスが`ctrl_guard`を名乗っている。2つのラウンドが\
         同じ構成になっている疑いがあるので、結果を読んではいけない: {}",
        control.holder_report
    );
    for (label, round) in [
        ("guarded/break", &guarded),
        ("guarded/ctrl-c", &guarded_ctrl_c),
        ("guarded+accept/ctrl-c", &guarded_accept_ctrl_c),
    ] {
        assert_eq!(
            ctrl_guard(&round.holder_report),
            Some(serde_json::Value::Bool(true)),
            "守る側の保持プロセスでハンドラが掛かっていない（腕={label}。\
             `--console-guard-ctrl`が届いていないか失敗した）。この回は測定になっていない: {}",
            round.holder_report
        );
    }

    // 計器: 撃てていないなら、落ちなかったことを「守られている」と読めない。
    for (label, sent, target_died) in [
        (
            "unguarded/break",
            control.ctrl_break_sent,
            Some(control.target_died),
        ),
        (
            "guarded/break",
            guarded.ctrl_break_sent,
            Some(guarded.target_died),
        ),
        // **`CTRL_C_EVENT`のラウンドでは的の死を要求しない。** 守っていない的も
        // 落ちないことが実測されており（下でその事実の側を固定する）、ここで要求すると
        // 「配達されなかった」を「機構が壊れた」として報告することになる。
        ("guarded/ctrl-c", guarded_ctrl_c.ctrl_break_sent, None),
        // **属性を外したラウンドでは要求する。** 外せば配達されることが§S50で分かっており、
        // 的が落ちることがこのラウンドの配達の証拠そのものになる。
        (
            "guarded+accept/ctrl-c",
            guarded_accept_ctrl_c.ctrl_break_sent,
            Some(guarded_accept_ctrl_c.target_died),
        ),
    ] {
        // **「撃てなかった」と「撃とうとすらしなかった」を分ける。** `None`は撃ち手の
        // レポートにその試行が1件も無いこと＝**プローブがその引数を知らない**印で、
        // 原因はたいてい`tier2a_proc_probe.exe`が古いことである（`cargo test`は
        // このバイナリを作り直さない。`docs/DEV-ENVIRONMENT.md`）。
        assert!(
            sent.is_some(),
            "撃ち手のレポートに制御イベントの試行が無い（腕={label}）。\
             `cargo build -p tier2a-proc-probe`でプローブを作り直したか確認すること"
        );
        assert_eq!(sent, Some(true), "制御イベントを撃てていない（腕={label}）");
        // 配達の証拠。**守った側でもここは落ちる**——落ちなければ、
        // 保持プロセスが生き残ったのは守りではなく不発のせいかもしれない。
        if let Some(target_died) = target_died {
            assert!(
                target_died,
                "撃ったのに的が落ちなかった（腕={label}）。イベントが配達されていないので、\
                 保持プロセス側の結果は何も語らない"
            );
        }
    }

    // **実測をそのまま固定する。** `CTRL_C_EVENT`は撃てるのに、守っていない的にも効かない。
    // これが逆転したら`guarded/ctrl-c`は初めて守りについての結論を持つので、
    // **測り直して記録（§S49）を更新する合図**にする。
    assert!(
        !guarded_ctrl_c.target_died,
        "`CTRL_C_EVENT`で的が落ちた。2026-09-05の実測（3回とも落ちない）と逆なので、\
         この腕は守りについて語れるようになっている。記録を更新すること"
    );

    // 歯: 守らない保持プロセスは落ちる（§S48の再現）。
    assert!(
        control.holder_died,
        "守っていない保持プロセスが落ちなかった。§S48が測った向きが再現していないので、\
         守った側が生き残っても「ハンドラのおかげ」と読めない"
    );

    // 本命。**`CTRL_BREAK_EVENT`についてだけ**、配達の証拠と対で言える。
    assert!(
        !guarded.holder_died,
        "`SetConsoleCtrlHandler`を掛けた保持プロセスも`CTRL_BREAK_EVENT`で落ちた。\
         設計書§7.1.1の決定1（保持プロセスが制御イベントを握り潰す）が成立しないので、\
         落とされた後の立て直し（決定2）だけが残る防御になる"
    );
    // こちらは**配達の証拠が無いので単独では何も語らない**（上の`target_died`と対で読む）。
    // それでも見るのは、逆転したとき——守った保持プロセスだけが落ちたとき——が
    // 「ハンドラが種類によっては有害」という別の事実になるためである。
    assert!(
        !guarded_ctrl_c.holder_died,
        "`CTRL_C_EVENT`で、守った保持プロセスだけが落ちた（同じラウンドの的は生きている）。\
         ハンドラが種類によっては守るどころか落としていることになるので、測り直すこと"
    );
    // **設計にとっての本命。** 「Ctrl+Cを無視する」継承属性を外し、同じラウンドの的が
    // 落ちる（＝確かに配達されている）世界で、守った保持プロセスが生き残ること。
    // これが成り立つので、決定1は**Daemonが何を受け継ぐかに依存しない**。
    assert!(
        !guarded_accept_ctrl_c.holder_died,
        "`CTRL_C_EVENT`が実際に配達される世界（無視する属性を外した）で、\
         握り潰しを入れた保持プロセスが落ちた。設計書§7.1.2の決定1は\
         「受け継ぐものに依存しない」と書けなくなるので、決定1と§S51を書き直すこと"
    );

    // --- 生き残ったコンソールは、まだ使えるか -----------------------------------
    // **「生きているが壊れている」を排除する。** 保持プロセスが生き残っても、
    // コンソールがシェルの起動に使えなければ可用性は同じだけ失われている。
    let (shell, shell_label) = resolve_shell();
    let marker_path = workspace.path().join("guarded-reuse-marker.txt");
    let reuse = run_restricted_shell_while_attached(
        &ArmSpec {
            label: "GUARDED_REUSE",
            holder_console: SpikeConsole::NoWindow,
            loan: ConsoleLoan::Attach,
            resume_at: ResumePoint::AfterDetach,
        },
        // **最後に撃たれた保持プロセス**を使う（2種類とも浴びた後のコンソールを見る）。
        guarded_ctrl_c.holder.pid(),
        &shell,
        workspace.path(),
        sid.as_psid(),
        &caps_a,
        &marker_path,
    )
    .unwrap_or_else(|e| {
        panic!("撃たれた後のコンソールでシェルを起こせなかった（shell={shell_label}）: {e}")
    });
    eprintln!(
        "[{TAG}] reuse: ran={} child={:?} stdio={:?} exit={} members={:?}",
        reuse.actually_ran(),
        reuse.child_creation(),
        reuse.stdio_redirected(),
        reuse.exit_code,
        reuse.console_processes,
    );
    assert!(
        reuse.actually_ran(),
        "撃たれた後のコンソールでシェルが完走しなかった。保持プロセスは生き残ったが\
         コンソールとしては壊れているので、守りは可用性を守っていない: {reuse:?}"
    );
    // 同じ1回で「mitigationが効いていた」ことも押さえる（§7.1.1のgo/no-goと同じ形）。
    assert!(
        reuse.child_creation_denied(),
        "撃たれた後のコンソールで走ったシェルが子プロセスを起こせてしまった。\
         `CHILD_PROCESS_RESTRICTED`が効いていない回なので、成立の証拠にならない: {reuse:?}"
    );
    drop(guarded.holder);
    drop(guarded_ctrl_c.holder);
    drop(guarded_accept_ctrl_c.holder);
}

/// 受け取る側が制御イベントを受け取ったときに走るハンドラの終了コード。
///
/// **`tier2a-proc-probe`の`console_share::CTRL_HANDLED_EXIT_CODE`と同じ値を書いてある。**
/// クレートが違うので型で繋げられない——**片方だけ変えると、この測定は「ハンドラを通った」を
/// 見落として「OSに殺された」と読む**。変えるときは両方を直すこと。
const CTRL_HANDLED_EXIT_CODE: u32 = 43;

/// 後始末で書き切られる印（同じく`console_share::CLEANUP_MARKER`と同じ値）。
const CTRL_CLEANUP_MARKER: &str = "HARNESS-CTRL-CLEANUP-COMPLETE";

/// 1ラウンド分の観測（受け取る側に何が残ったか）。
struct DeliveryRound {
    /// 起動時に受け取る側が出したレポート（自分の構成を名乗る）。
    setup: serde_json::Value,
    /// 受け取りの記録（1行1 JSON）。仕掛けた時点の1行は必ず在るので、
    /// **「在るか」ではなく「受け取った行が在るか」で判定する**。
    receipt: Option<String>,
    /// 撃つ**直前**に読んだ後始末ファイルの中身。**空でなければこのラウンドは何も語らない。**
    cleanup_before: String,
    /// 撃った**後**の後始末ファイルの中身。
    cleanup_after: String,
    /// 撃ち手が「撃てた」と申告したか（撃たないラウンドでは`None`）。
    sent: Option<bool>,
    exited: bool,
    exit_code: u32,
}

impl DeliveryRound {
    /// **制御イベントを受け取った行が在るか。** 仕掛けた時点の行は撃たなくても在るので、
    /// ファイルの有無では判定できない。
    fn received(&self) -> bool {
        self.receipt
            .as_deref()
            .is_some_and(|body| body.contains("\"kind\":\"received\""))
    }
}

/// §7.1.1の測定8: **`CTRL_C_EVENT`は届いているのか。**
///
/// [§S49](../../../../../plans/mac-spike/RESULTS.md)（測定7）は`CTRL_C_EVENT`について
/// 何も言えなかった——撃つのは成功するのに、守っていない相手すら落ちなかったので、
/// 「そもそも届いていない」と「届いたが既定の反応が終了ではない」が潰れたままだった。
/// **死ぬかどうかで測っていたから**である。
///
/// そこで**受け取ったことを自分で記録して終わる子**を的に置き、指標を「死んだか」から
/// 「受け取ったか」へ変える。あわせて、その子は待っている間バッファに残していた印を
/// ハンドラの中で書き切るので、**後始末が最後まで走ったか**も同じ回で分かる。
///
/// | ラウンド | 撃つもの | これが無いと何が言えなくなるか |
/// |---|---|---|
/// | `no-shot`（対照） | 撃たない | 「ファイルが勝手に埋まらない」が言えず、他の2つの結果を読めない |
/// | `break`（計器の歯） | `CTRL_BREAK_EVENT` | 記録が付かなかったとき、計器の故障と「届いていない」を区別できない |
/// | `ctrl-c`（本命） | `CTRL_C_EVENT` | — |
///
/// **保持プロセスは握り潰し付きで立てる**（[§S49](../../../../../plans/mac-spike/RESULTS.md)で
/// 測った性質に乗っている）。ラウンドの途中でコンソールが消えると、撃った後の読み取りが
/// 「消えたから読めない」と「書かれなかったから読めない」に割れてしまう。
///
/// 実行（**昇格しないこと**、`B-08`）:
///
/// ```text
/// cargo build -p tier2a-proc-probe
/// cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture \
///   control_event_delivery_and_cleanup_are_measured_with_a_handling_child
/// ```
#[test]
#[ignore = "touches real AppContainer state; run non-elevated (see plans/mac-spike/RESULTS.md)"]
fn control_event_delivery_and_cleanup_are_measured_with_a_handling_child() {
    const TAG: &str = "MAC-CONSOLE-CTRL-DELIVERY";

    let measure_lock =
        std::path::Path::new(r"C:\harness-e2e\_measure-lock\mac-console-ctrl-delivery");
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
        eprintln!("[{TAG}] cleanup: {:?}", outcome.summary());
        super::mac_spike_tests::forget_workspace_capability(&cleanup_workspace);
        if let Err(e) = std::fs::remove_dir_all(&cleanup_workspace) {
            eprintln!("[{TAG}] cleanup could not remove workspace: {e}");
        }
        if !cleanup_workspace.exists() {
            crate::tier2a::workspace_ledger::remove_workspace_entry(&cleanup_workspace);
        }
    });

    // 受け取る側と撃ち手を別ドメインにするのは§S49と同じ配置——ここから変える軸は
    // 「的が受け取りを記録するかどうか」だけである。
    let pid = std::process::id();
    let domain_a = super::capability_sid_from_name(&format!("harness-ctrl-delivery-A-{pid}"))
        .expect("derive domain A capability");
    let domain_b = super::capability_sid_from_name(&format!("harness-ctrl-delivery-B-{pid}"))
        .expect("derive domain B capability");
    let mut caps_a: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let mut caps_b = caps_a.clone();
    caps_a.push(domain_a.as_psid());
    caps_b.push(domain_b.as_psid());

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    eprintln!(
        "[{TAG}] elevated={}",
        crate::tier2a::privhelper::is_elevated()
    );

    // `outside`は受け取り手をサンドボックスの**外**に置く腕。**撃ち手は全ラウンド同じ**なので、
    // 変わる軸は「受け取り手がAppContainerか」の1つだけになる——ここで結果が割れれば、
    // 届かない理由はAppContainerの側にある。
    // `accept`は受け取る側が**上流から受け継いだ「Ctrl+Cを無視する」属性を自分だけ外す**腕。
    // Microsoftの文書がその属性の存在と継承を明記しているので、外して結果が変わるかを撃つ。
    let run_round = |label: &str,
                     shot: Option<(&str, &str)>,
                     outside: bool,
                     accept: bool|
     -> DeliveryRound {
        // 保持プロセスは握り潰し付き。ラウンドの間、コンソールを保たせる。
        let holder_report = workspace.path().join(format!("{label}-holder.json"));
        let holder_report_str = holder_report.to_string_lossy().into_owned();
        let holder_args = [
            "--idle-secs",
            "120",
            "--timeout-secs",
            "180",
            "--console-guard-ctrl",
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
        let arms = ConsoleArms {
            tag: TAG,
            probe: &probe_str,
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            holder_pid: holder.pid(),
        };

        // 受け取る側（子2）。**3つのファイルを使う**——起動の申告・受け取りの記録・後始末。
        let child_report = workspace.path().join(format!("{label}-child.json"));
        let receipt_path = workspace.path().join(format!("{label}-receipt.txt"));
        let cleanup_path = workspace.path().join(format!("{label}-cleanup.txt"));
        let child_report_str = child_report.to_string_lossy().into_owned();
        let receipt_str = receipt_path.to_string_lossy().into_owned();
        let cleanup_str = cleanup_path.to_string_lossy().into_owned();
        let mut child_args = vec![
            "--console-ctrl-receipt",
            receipt_str.as_str(),
            "--console-ctrl-cleanup",
            cleanup_str.as_str(),
            "--report-file",
            child_report_str.as_str(),
            "--console-idle-secs",
            "20",
            "--timeout-secs",
            "60",
        ];
        if accept {
            // 付けない腕は**上流から受け継いだまま**で走る（比較の基準）。
            child_args.push("--console-ctrl-accept");
        }
        let child = arms
            .spawn(
                &format!("{label}/receiver(domainA)"),
                &child_args,
                if outside { &[] } else { &caps_a },
                outside,
                SpikeConsole::Inherit,
            )
            .unwrap_or_else(|e| panic!("{e}"));

        // **仕掛かるまで待つ。** 時間で待つのではなく、相手が「ハンドラを入れた」と
        // 申告するのを待つ（仕掛かる前に撃つと、測るのは届くかどうかではなく競走になる）。
        wait_until_report_contains(child.pid(), &child_report, "\"handler\":true");
        let setup: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&child_report).expect("read the receiver report"),
        )
        .expect("the receiver report is JSON");

        // 撃つ直前の後始末ファイル。**ここが空でなければ、このラウンドは何も語らない。**
        let cleanup_before = std::fs::read_to_string(&cleanup_path).unwrap_or_default();

        let sent = shot.map(|(event_arg, attempt_kind)| {
            let attacker = arms.read(
                &format!("{label}/attacker(domainB)"),
                &[event_arg, "--timeout-secs", "60"],
                &caps_b,
                false,
                SpikeConsole::Inherit,
            );
            console_attempt(&attacker, attempt_kind)
                .and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
                .unwrap_or_else(|| {
                    panic!(
                        "撃ち手のレポートに`{attempt_kind}`の試行が無い（腕={label}）。\
                         `cargo build -p tier2a-proc-probe`でプローブを作り直したか確認すること: {attacker}"
                    )
                })
        });

        // **待ち切ったら終わっていない**（受け取る側は20秒待つ腕で、こちらは5秒しか待たない）。
        let exited = unsafe { WaitForSingleObject(child.process(), 5_000) } == WAIT_OBJECT_0;
        let mut exit_code: u32 = 0;
        let _ = unsafe { GetExitCodeProcess(child.process(), &mut exit_code) };

        let receipt = std::fs::read_to_string(&receipt_path).ok();
        let cleanup_after = std::fs::read_to_string(&cleanup_path).unwrap_or_default();
        eprintln!(
            "[{TAG}] {label}: sent={sent:?} exited={exited} exit_code={exit_code} \
             receipt={receipt:?} cleanup_before={cleanup_before:?} cleanup_after={cleanup_after:?}"
        );
        // **待たずに畳む。** 受け取る側は20秒待つ腕なので、終わるまで待つと
        // 撃たれなかったラウンドで毎回20秒を捨てることになる。Jobを閉じれば畳まれる。
        drop(child);
        drop(holder);

        DeliveryRound {
            setup,
            receipt,
            cleanup_before,
            cleanup_after,
            sent,
            exited,
            exit_code,
        }
    };

    const BREAK: (&str, &str) = ("--console-ctrl-break", "console-ctrl-break");
    const CTRL_C: (&str, &str) = ("--console-ctrl-c", "console-ctrl-c");
    let no_shot = run_round("no-shot", None, false, false);
    let break_round = run_round("break", Some(BREAK), false, false);
    let ctrl_c_round = run_round("ctrl-c", Some(CTRL_C), false, false);
    // 受け取り手をサンドボックスの外へ出した対。**この2本が揃って初めて**
    // 「届かない理由がAppContainerの側にあるか」を割れる——外でも受け取れないなら、
    // 原因はサンドボックスより手前（プロセスグループや親から継承する設定）にある。
    let outside_break = run_round("outside-break", Some(BREAK), true, false);
    let outside_ctrl_c = run_round("outside-ctrl-c", Some(CTRL_C), true, false);
    // **原因そのものを名指しで撃つ腕。** Microsoftの文書が言う「Ctrl+Cを無視する継承属性」を
    // 受け取る側で外し、同じCtrl+Cを撃つ。ここで受け取れれば、原因はその属性だと確定する。
    let accept_ctrl_c = run_round("accept-ctrl-c", Some(CTRL_C), false, true);

    // --- 判定 -------------------------------------------------------------------
    // **計器から先に見る。** 仕掛かっていないラウンドの結果は何も語らない。
    for (label, round) in [
        ("no-shot", &no_shot),
        ("break", &break_round),
        ("ctrl-c", &ctrl_c_round),
        ("outside-break", &outside_break),
        ("outside-ctrl-c", &outside_ctrl_c),
        ("accept-ctrl-c", &accept_ctrl_c),
    ] {
        let armed = round.setup.get("ctrl_receipt");
        assert_eq!(
            armed
                .and_then(|r| r.get("handler"))
                .and_then(|h| h.as_bool()),
            Some(true),
            "受け取る側にハンドラが入っていない（腕={label}）。この回は測定になっていない: {}",
            round.setup
        );
        assert_eq!(
            armed
                .and_then(|r| r.get("cleanup_open"))
                .and_then(|h| h.as_bool()),
            Some(true),
            "後始末の対象を開けていない（腕={label}）。完走したかを判定できない: {}",
            round.setup
        );
        // **撃つ前は空。** ここが崩れると「中身が在る＝ハンドラが走った」が読めなくなる。
        assert!(
            round.cleanup_before.is_empty(),
            "撃つ前から後始末のファイルに中身がある（腕={label}）。\
             待っている間はバッファに残る、という前提が崩れているので結果を読んではいけない: {:?}",
            round.cleanup_before
        );
    }

    // **どのラウンドでも「Ctrl+Cを無視する属性」の状態が申告どおりであること。**
    // ここが食い違うと、`accept-ctrl-c`とその他の差が何の差か分からなくなる。
    let ctrl_c_mode = |round: &DeliveryRound| {
        round
            .setup
            .get("ctrl_receipt")
            .and_then(|r| r.get("ctrl_c_mode"))
            .and_then(|m| m.as_str())
            .map(str::to_string)
    };
    assert_eq!(
        ctrl_c_mode(&ctrl_c_round).as_deref(),
        Some("inherit"),
        "基準の腕が「受け継いだまま」になっていない: {}",
        ctrl_c_round.setup
    );
    assert_eq!(
        ctrl_c_mode(&accept_ctrl_c).as_deref(),
        Some("accept"),
        "属性を外す腕で外せていない（`SetConsoleCtrlHandler(NULL, FALSE)`が失敗した）。\
         この回は原因を測れていない: {}",
        accept_ctrl_c.setup
    );

    // 対照: 撃たなければ何も起きない。**ファイルは勝手に埋まらない。**
    assert!(
        !no_shot.received(),
        "撃っていないのに受け取りの記録ができている: {:?}",
        no_shot.receipt
    );
    assert!(
        no_shot.cleanup_after.is_empty(),
        "撃っていないのに後始末のファイルが埋まっている。\
         「中身が在る＝ハンドラが走った」と読めなくなる: {:?}",
        no_shot.cleanup_after
    );
    assert!(
        !no_shot.exited,
        "撃っていないのに受け取る側が5秒で終わった。落ちたことを「撃ったから」と読めない"
    );

    // 計器の歯: `CTRL_BREAK_EVENT`は届くと分かっているので、**必ず記録が付くはず**である。
    assert_eq!(
        break_round.sent,
        Some(true),
        "`CTRL_BREAK_EVENT`を撃てていない"
    );
    assert!(
        break_round.received(),
        "`CTRL_BREAK_EVENT`で受け取りの記録ができていない。届くと分かっているイベントで\
         記録が残らないなら、この計器は「届いた」を観測できない: {:?}",
        break_round.receipt
    );
    let break_receipt = break_round.receipt.as_deref().unwrap_or_default();
    assert!(
        break_receipt.contains("CTRL_BREAK_EVENT"),
        "受け取りの記録が別の種類になっている: {break_receipt:?}"
    );
    assert!(
        break_round.cleanup_after.contains(CTRL_CLEANUP_MARKER),
        "後始末が最後まで走らなかった（`CTRL_BREAK_EVENT`）。\
         バッファに残していた印がディスクへ届いていない: {:?}",
        break_round.cleanup_after
    );
    assert_eq!(
        break_round.exit_code, CTRL_HANDLED_EXIT_CODE,
        "ハンドラを通って終わったなら終了コードは{CTRL_HANDLED_EXIT_CODE}のはず。\
         `0xC000013A`ならOSの既定で終わらされている: {}",
        break_round.exit_code
    );

    // --- 本命: `CTRL_C_EVENT`は届いているのか ------------------------------------
    //
    // **答えは「届いていない」だった**（2026-09-05の実測。3回とも同じ向き）。撃つのは成功し、
    // 同じ器で`CTRL_BREAK_EVENT`は記録されるのに、`CTRL_C_EVENT`ではハンドラが1度も走らない。
    // §S49が残した2択——「そもそも届いていない」と「届いたが既定の反応が終了ではない」——の
    // **前者**である。
    //
    // 以下は**実測をそのまま固定している**。逆転したらこの経路は初めて脅威になり得るので、
    // 記録（§S50）と設計書§7.1.2の決定1を測り直す合図にする。
    assert_eq!(
        ctrl_c_round.sent,
        Some(true),
        "`CTRL_C_EVENT`を撃てていない"
    );
    assert!(
        !ctrl_c_round.received(),
        "`CTRL_C_EVENT`で受け取りの記録ができた。2026-09-05の実測（届かない）と逆なので、\
         この経路は届くようになっている。§S50と設計書§7.1.2の決定1を測り直すこと: {:?}",
        ctrl_c_round.receipt
    );
    assert!(
        ctrl_c_round.cleanup_after.is_empty(),
        "`CTRL_C_EVENT`で後始末が走った。受け取りの記録が無いのに後始末だけ走るのは\
         辻褄が合わないので、計器を疑うこと: {:?}",
        ctrl_c_round.cleanup_after
    );
    assert!(
        !ctrl_c_round.exited,
        "`CTRL_C_EVENT`で受け取る側が終わった。ハンドラを通っていない（記録が無い）のに\
         終わったなら、OSの既定で終わらされている——§S49の「守っていない的も落ちない」と逆である"
    );

    // --- 届かない理由はどこにあるのか（受け取り手をサンドボックスの外へ出した対） -----
    assert_eq!(
        outside_break.sent,
        Some(true),
        "外の受け取り手へ`CTRL_BREAK_EVENT`を撃てていない"
    );
    assert!(
        outside_break.received(),
        "サンドボックスの外の受け取り手でも`CTRL_BREAK_EVENT`の記録ができていない。\
         この腕は計器として働いていないので、下の`outside-ctrl-c`の結果は何も語らない: {:?}",
        outside_break.receipt
    );
    assert_eq!(
        outside_ctrl_c.sent,
        Some(true),
        "外の受け取り手へ`CTRL_C_EVENT`を撃てていない"
    );
    // **サンドボックスの外でも届かなかった**（2026-09-05の実測。3回とも同じ向き）。
    // つまり届かない理由はAppContainerの側には無く、**もっと手前**——プロセスグループか、
    // 親から受け継ぐ「Ctrl+Cを無視する」状態——にある。
    //
    // **この向きは結論を弱める側に効く。** 原因がサンドボックスに無いということは、
    // 親が変われば結果も変わり得るということで、**本番（親がSpawn Daemon）へは持ち越せない**。
    // だから設計書§7.1.2は握り潰しに寄りかからず、決定2（立て直し）を置いたままにする。
    assert!(
        !outside_ctrl_c.received(),
        "サンドボックスの外の受け取り手だけが`CTRL_C_EVENT`を受け取った。\
         届かない理由がAppContainerの側にあることになるので、記録（§S50）と\
         設計書§7.1.2の決定1を書き直すこと: {:?}",
        outside_ctrl_c.receipt
    );

    // --- 原因を名指しで撃つ ------------------------------------------------------
    // Microsoftの文書（`GenerateConsoleCtrlEvent`のRemarks）はこう書いている——
    // 「`SetConsoleCtrlHandler`は**継承される属性**を立てられ、それが立っているプロセスへ
    // `CTRL_C_EVENT`を送っても**ハンドラは呼ばれない**。`CTRL_BREAK_EVENT`は常に呼ばれる」。
    // **この属性を受け取る側で外して同じCtrl+Cを撃つ**のがこの腕である。
    assert_eq!(
        accept_ctrl_c.sent,
        Some(true),
        "属性を外した受け取り手へ`CTRL_C_EVENT`を撃てていない"
    );
    // **答えは「属性が原因」だった**（2026-09-05の実測。3回とも同じ向き）。外した腕だけ
    // `CTRL_C_EVENT`が届き、後始末も完走し、終了コードもハンドラ側の値になる。
    //
    // **設計にとってはこれが本命の結果である。** 届かないのは偶然でもサンドボックスのおかげでも
    // なく、**親が持っていて子が受け継ぐ属性**のせいだと分かった。したがってDaemonは
    // それを**意図して立てられる**（§7.1.2の決定1）。
    assert!(
        accept_ctrl_c.received(),
        "「Ctrl+Cを無視する」属性を外しても`CTRL_C_EVENT`が届かない。\
         2026-09-05の実測と逆で、原因はこの属性ではないことになる。\
         §S50と設計書§7.1.2の決定1を測り直すこと: {:?}",
        accept_ctrl_c.receipt
    );
    let accept_receipt = accept_ctrl_c.receipt.as_deref().unwrap_or_default();
    assert!(
        accept_receipt.contains("CTRL_C_EVENT"),
        "属性を外した腕の記録が別の種類になっている: {accept_receipt:?}"
    );
    assert!(
        accept_ctrl_c.cleanup_after.contains(CTRL_CLEANUP_MARKER),
        "属性を外した腕で後始末が完走しなかった: {:?}",
        accept_ctrl_c.cleanup_after
    );
    assert_eq!(
        accept_ctrl_c.exit_code, CTRL_HANDLED_EXIT_CODE,
        "属性を外した腕がハンドラを通らずに終わった: {}",
        accept_ctrl_c.exit_code
    );
}
