//! 段階5（Spawn Daemon本体）の実機受け入れテスト。実ACLを変更するため昇格ランナーから
//! 直列実行する（`dev-elevated-run.exe spawn-daemon`）。
//!
//! # 何を合格条件にしているのか
//!
//! 解説の1枚もの（`docs/guide/11a-mac-enforcement-map.md`§3）が段階③に課しているのは
//! **対で2本を2組**である。片方だけだと、「全部拒否する」実装でも「全部届かない」実装でも
//! 緑になってしまう（`B-35`）。
//!
//! | 組 | 通るはず | 通らないはず |
//! |---|---|---|
//! | 到達性 | spawn要求用capabilityを積んだ子 → **要求受付パイプ** | 同じ子 → **制御パイプ**／capabilityを積まない子 → 要求受付パイプ |
//! | 台帳 | Daemonが起こした子 → **「台帳に無い」ではない**理由で断られる | harnessが直接起こした子 → **「台帳に無い」** |
//!
//! **2組目が肝である。** 「拒否された」だけを見ると、Daemonが常に拒否していても合格する。
//! 拒否の**理由**が変わることを見て初めて、台帳の判定が生きていると言える。
//!
//! # ここで測っていないもの
//!
//! - **遷移が許可されること**。段階5にポリシー評価は無く、答えは常に拒否である
//!   （段階Eが入るまでは`policy_not_implemented`が正しい応答）
//! - **`CHILD_PROCESS_RESTRICTED`下での動作**。積むのは段階⑤
//!
//! # 測っている世界が本番と1つだけ違う（**limitation**）
//!
//! これらは昇格ランナーから走るので、**テストの中のDaemonは昇格したトークンで動く**。
//! 本番のDaemonは非昇格である（`client::launch_daemon`は`runas`を使わない）。
//!
//! **ここで見ている事実は、その差に依存しない**——パイプのDACLはユーザーSIDと
//! capability SID宛で、どちらも昇格で変わらないからである。**依存し得るのは
//! 子の整合性レベル**で、昇格して測った回と非昇格の回で挙動が違った前例がある
//! （§S47。pwshの起動時警告）。**この4本はそこを判定に使っていない。**
//!
//! 昇格が要るのはDaemonのためではなく、workspaceの実ACLを触る`preflight`のためである。

use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

use super::test_support::{cleanup_workspace, TestDirGuard};
use super::*;
use crate::cancel_descendants::{
    assert_cancel_completes, prepare_descendant, DescendantOutput, DescendantProbe,
};
use crate::tier2a::spawnd::client::{SpawnDaemonHandle, SpawnedChild, TopLevelSpawn};
use crate::tier2a::spawnd::{DomainIdentitySpec, DomainSpec};

/// 1ケース分の実マシン資源。**失敗した経路でも同じ順で畳む**（`test-logic-rules`型F）。
struct Case {
    daemon: Option<SpawnDaemonHandle>,
    canonical_workspace: std::path::PathBuf,
    dir: Option<TestDirGuard>,
}

impl Drop for Case {
    fn drop(&mut self) {
        // Daemonを先に畳む。畳む前にACEを剥がすと、生きている子がworkspaceを
        // 触れなくなって「機構の失敗」に見える。
        drop(self.daemon.take());
        cleanup_workspace(&self.canonical_workspace);
        drop(self.dir.take());
    }
}

/// workspaceを1つ用意し、preflightを通し、Daemonを起こす。
fn setup(label: &str) -> (Case, OwnedContainerSid, Vec<crate::win_common::OwnedSid>) {
    let guard = TestDirGuard::create(label);
    let workspace = guard.path().to_path_buf();
    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed: {e:?}"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("workspace preparation must finish");
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let profile = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile must exist");

    // 子が本番と同じ範囲へ到達できるようにする**このドメイン固有のもの**だけを返す。
    //
    // **traverse capabilityはここに入れない。** `spawn_with_workspace`（harnessが直接
    // 起こす経路）はD-37に従って**自分で**先頭へ積むので、ここでも積むと同じSIDが2つ並ぶ
    // ——`CreateProcessW`が`ERROR_INVALID_PARAMETER`(0x80070057)で落ちる。
    // Daemon経由の経路は自動で積まないので、そちらは[`domain_spec`]が明示的に足す。
    let mut caps: Vec<crate::win_common::OwnedSid> = Vec::new();
    if let Some(cap) = super::mac_spike_tests::workspace_capability_for(&workspace) {
        caps.push(cap);
    }

    let daemon = SpawnDaemonHandle::start().expect("the spawn daemon must start");
    eprintln!(
        "[spawnd] daemon pid={} request_pipe={}",
        daemon.daemon_pid(),
        daemon.request_pipe()
    );

    (
        Case {
            daemon: Some(daemon),
            canonical_workspace: canonical,
            dir: Some(guard),
        },
        profile,
        caps,
    )
}

/// テスト用のドメイン記述。**package SIDそのものをドメインにする**
/// （このセッションのプロファイルは1ドメインに対応する。§22.1.1の`OwnPackage`）。
///
/// **traverse capabilityをここで足す。** Daemonは受け取った一覧をそのまま積むだけで、
/// D-37の「全Tier2a子が共通で携える」を自分では知らない——`spawn_with_workspace`が
/// 自動で積むぶんを、Daemon経由では呼び出し側が明示する形になる。
fn domain_spec(
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    extra: Option<&crate::win_common::OwnedSid>,
) -> DomainSpec {
    let traverse = traverse_capability_sid().expect("traverse capability");
    let mut capability_sids: Vec<String> = std::iter::once(&traverse)
        .chain(caps.iter())
        .map(|c| crate::win_common::sid_to_string(c.as_psid()).expect("capability sid to string"))
        .collect();
    if let Some(extra) = extra {
        capability_sids
            .push(crate::win_common::sid_to_string(extra.as_psid()).expect("extra sid to string"));
    }
    DomainSpec {
        name: "spawnd-e2e".to_string(),
        container_sid: crate::win_common::sid_to_string(profile.as_psid())
            .expect("container sid to string"),
        capability_sids,
        identity: DomainIdentitySpec::OwnPackage,
    }
}

/// Daemonに子を起こしてもらい、**その子のstdout/stderrと終了コード**を返す。
///
/// パイプとJobを作るのはこちら（harness役）である（§10.1「子のstdioパイプを作るプロセス」）。
fn spawn_via_daemon(
    daemon: &SpawnDaemonHandle,
    profile: &OwnedContainerSid,
    workspace: &std::path::Path,
    domain: DomainSpec,
    args: &[&str],
) -> (SpawnedChild, HANDLE, String, String) {
    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (stdout_read, stdout_write) =
        appcontainer_pipe(profile.as_psid()).expect("stdout pipe for the daemon-spawned child");
    crate::win_common::clear_inherit(stdout_read);
    let (stderr_read, stderr_write) =
        appcontainer_pipe(profile.as_psid()).expect("stderr pipe for the daemon-spawned child");
    crate::win_common::clear_inherit(stderr_read);
    // 系統Jobを作るのは**harness**である（§10.1.1）。Daemonへは複製が渡り、
    // こちらの原本はキャンセル用に持ち続ける。
    let job = crate::win_common::create_job_object().expect("lineage job");

    let child = daemon
        .spawn_top_level(TopLevelSpawn {
            exe: &probe_str,
            args,
            cwd: workspace,
            env: &crate::secret_env::build_child_env(),
            domain,
            job,
            stdout_write,
            stderr_write,
            stdin_read: None,
        })
        .expect("the daemon must spawn the top-level child");

    let (out, err) = crate::win_common::read_two_pipes_to_strings(stdout_read, stderr_read);
    (child, job, out, err)
}

/// 子の応答JSON（`--pipe-client`が最後の行に出す）から1つの欄を読む。
fn report_field(stdout: &str, field: &str) -> Option<serde_json::Value> {
    super::mac_spike_tests::last_json_line(stdout).and_then(|v| v.get(field).cloned())
}

/// 要求受付パイプへ送る本物の要求電文（`SpawnRequest::Spawn`）。
fn spawn_request_payload() -> String {
    serde_json::to_string(&crate::tier2a::spawnd::SpawnRequest::Spawn {
        exe: "git.exe".to_string(),
        args: vec!["status".to_string()],
        cwd: "C:/".to_string(),
    })
    .expect("serialize the spawn request")
}

/// 子が返した拒否理由を取り出す。
fn deny_reason(stdout: &str) -> Option<String> {
    let reply = report_field(stdout, "reply")?;
    let reply = reply.as_str()?;
    let parsed: serde_json::Value = serde_json::from_str(reply).ok()?;
    parsed.get("reason")?.as_str().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// 組1: 到達性（要求受付パイプへは届く／制御パイプへは届かない）
// ---------------------------------------------------------------------------

/// **P1・P5**: spawn要求用capabilityを積んだ子が要求受付パイプへ**届き**、
/// Daemonが起こした子なので**「台帳に無い」ではない**理由で断られる。
///
/// この1本が組1の許可側と組2の許可側を兼ねる——同じ子で同じ1往復を見るので、
/// 「届いた」と「台帳に居た」が**別々の測定で食い違う**ことがない（型7の逆向き）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_daemon_spawned_child_reaches_the_request_pipe_and_is_denied_by_policy_not_by_the_table() {
    let (case, profile, caps) = setup("spawnd-p1");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let payload = spawn_request_payload();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, Some(&spawn_cap)),
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd P1] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "spawn要求用capabilityを積んだ子が要求受付パイプへ接続できない。\
         §10.1のDACL設計が成立しない: {out}"
    );
    assert_eq!(
        report_field(&out, "reply_ok").and_then(|v| v.as_bool()),
        Some(true),
        "応答を読めていない（1往復が成立していない）: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("policy_not_implemented"),
        "Daemonが起こした子なのに「台帳に無い」で断られている。\
         §12のProcess Table登録がResumeより前に効いていない（BUG-116の形）: {out}"
    );
    drop(case);
}

/// **P2**（組1の拒否側）: 同じcapabilityを積んだ子でも、**制御パイプへは届かない**。
///
/// 制御パイプはユーザーSID専有DACLのままである（§10.1）。AppContainerのアクセスチェックは
/// ユーザーの許可と package/capability の許可の**交差**なので、package SIDにも
/// capabilityにも宛てていないこのパイプへは到達できない。**ここが破れると、
/// サンドボックスがharnessと同じ特権クライアントとして振る舞える。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_control_pipe_stays_unreachable_from_inside_the_sandbox() {
    let (case, profile, caps) = setup("spawnd-p2");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let control = daemon.control_pipe_name().to_string();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, Some(&spawn_cap)),
        &["--pipe-client", &control, "--timeout-secs", "60"],
    );
    eprintln!("[spawnd P2] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(false),
        "サンドボックスの中から制御パイプへ到達できた。\
         「特権クライアントとサンドボックスの区別をDACLで引く」（§10.1・P-01）が破れている: {out}"
    );
    drop(case);
}

/// **P3**（組1の拒否側その2）: spawn要求用capabilityを**積まない**子は、
/// 要求受付パイプにも届かない。
///
/// これが成立して初めて、§22.2.2の`process: deny`が「パイプに到達すらできない」という
/// 二重のdenyになる——capabilityを積むかどうかが、そのままドメイン単位のスイッチである。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_child_without_the_spawn_capability_cannot_reach_the_request_pipe() {
    let (case, profile, caps) = setup("spawnd-p3");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let payload = spawn_request_payload();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        // **`spawn_cap`を積まない**のがこの測定の全部である。
        domain_spec(&profile, &caps, None),
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd P3] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(false),
        "spawn要求用capabilityを積んでいない子が要求受付パイプへ到達できた。\
         capabilityがドメイン単位のスイッチになっていない（§10.1）: {out}"
    );
    drop(case);
}

// ---------------------------------------------------------------------------
// 組2: 台帳（在るPIDと無いPIDで拒否の理由が変わる）
// ---------------------------------------------------------------------------

/// **P4**（組2の拒否側）: **Daemonを通さずに**起こした子は、capabilityを積んでいても
/// 「台帳に無い」で断られる。
///
/// P1と対になる——同じcapability・同じ電文で、**違うのは誰が起こしたかだけ**である。
/// この差が理由に出なければ、Daemonは「常に同じ返事をしている」ことになる（`B-35`）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_child_the_daemon_did_not_spawn_is_denied_as_not_registered() {
    let (case, profile, caps) = setup("spawnd-p4");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let payload = spawn_request_payload();

    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let mut domain_caps: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    domain_caps.push(spawn_cap.as_psid());

    // **harnessが直接起こす**（Daemonを通らないのでProcess Tableに載らない）。
    let child = spawn_with_workspace(
        &probe_str,
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
        &workspace,
        &crate::secret_env::build_child_env(),
        false,
        profile.as_psid(),
        NetworkCapability::Deny,
        None,
        &domain_caps,
        DomainIdentity::OwnPackage,
    )
    .expect("spawn the unregistered child directly");
    let (out, err, _) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the unregistered child output");
    eprintln!("[spawnd P4] stdout={out}\nstderr={err}");

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "対照の前提が崩れている——capabilityを積んだ子は到達できるはず（P1と同じ条件）: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("not_registered"),
        "Daemonが起こしていない子が「台帳に無い」以外の理由で断られている。\
         §12の既定拒否が効いていないか、拒否理由が1つに丸まっている: {out}"
    );
    drop(case);
}

// ---------------------------------------------------------------------------
// ②が作った不変条件を、③が壊していないか
// ---------------------------------------------------------------------------

/// **P6**: Daemonが起こした子は**harnessが作った系統Job**に入っており、
/// harnessからのキャンセルで**孫まで死ぬ**。
///
/// **③で最も壊れやすいのがここである。** Daemonが系統Jobの複製を1本持つので、
/// ②より前の実装（最後の取っ手を閉じるとOSが中身を始末する形）なら、
/// キャンセルは**例外もエラーも出さずに**効かなくなっていた。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer descendant; run through spawn-daemon"]
fn cancelling_a_daemon_spawned_lineage_still_kills_the_grandchild() {
    let (case, profile, caps) = setup("spawnd-p6");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    let (script, pid_file) =
        prepare_descendant(&workspace, DescendantOutput::RedirectedToFile, true);
    let shell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string();

    let (stdout_read, stdout_write) = appcontainer_pipe(profile.as_psid()).expect("stdout pipe");
    crate::win_common::clear_inherit(stdout_read);
    let (stderr_read, stderr_write) = appcontainer_pipe(profile.as_psid()).expect("stderr pipe");
    crate::win_common::clear_inherit(stderr_read);
    let job = crate::win_common::create_job_object().expect("lineage job");

    let child = daemon
        .spawn_top_level(TopLevelSpawn {
            exe: &shell,
            args: &["-NoProfile", "-NonInteractive", "-Command", &script],
            cwd: &workspace,
            env: &crate::secret_env::build_child_env(),
            domain: domain_spec(&profile, &caps, None),
            job,
            stdout_write,
            stderr_write,
            stdin_read: None,
        })
        .expect("the daemon must spawn the shell");

    let descendant = DescendantProbe::wait_for_pid_file(&pid_file);
    // **キャンセル前に孫が確かに生きていたことを、同じテストでassertする**——
    // これが無いと「孫がそもそも起動していない」実装でも緑になる。
    descendant.assert_alive();

    let kill = crate::win_common::KillToken::duplicate(job).expect("duplicate the lineage job");
    // `HANDLE`は`Send`ではないので、専用スレッドへ渡す前に最小ラッパで包む
    // （`win_common::SendHandle`。読み手はEOFまで読むだけなのでスレッド越しでも安全）。
    let out_pipe = crate::win_common::SendHandle(stdout_read);
    let err_pipe = crate::win_common::SendHandle(stderr_read);
    assert_cancel_completes("daemon-spawned lineage cancellation", move || {
        let (out_pipe, err_pipe) = (out_pipe, err_pipe);
        kill.kill();
        let _ = crate::win_common::read_two_pipes_to_strings(out_pipe.0, err_pipe.0);
    });
    descendant.assert_exited_after_cancel();

    unsafe {
        let _ = CloseHandle(child.process);
        let _ = CloseHandle(job);
    }
    drop(case);
}

/// **P7**: 制御パイプを閉じるとDaemonが終わる（§10.1「寿命は親が保持するハンドルに紐付ける」）。
///
/// **タイマーにも完了メッセージにも依存しない**ことがこの節の決定なので、
/// `Shutdown`を送らずに落として測る。
#[test]
#[ignore = "starts a real spawn daemon; run through spawn-daemon"]
fn dropping_the_handle_ends_the_daemon() {
    let daemon = SpawnDaemonHandle::start().expect("the spawn daemon must start");
    let pid = daemon.daemon_pid();
    assert!(pid != 0, "DaemonのPIDが返っていない（Readyが届いていない）");

    // **落とす前に生きていたことを、同じテストで確かめる**（`B-35`）。
    // これが無いと、Daemonが**そもそも起動していない**実装でも下のassertが通る
    // ——`wait_for_process_exit`は開けないPIDを「もう居ない」として真を返すからである。
    assert!(
        !crate::win_common::wait_for_process_exit(pid, 0),
        "ハンドルを落とす前にDaemon（pid={pid}）が既に居ない。\
         測定の前提が崩れている（下の「終わった」が何も意味しなくなる）"
    );

    drop(daemon);

    // ハンドルは既に閉じたので、PIDから開き直して終了を待つ。
    assert!(
        crate::win_common::wait_for_process_exit(pid, 10_000),
        "制御パイプを閉じてもDaemon（pid={pid}）が終わらない。\
         寿命がパイプに紐付いていない（§10.1）"
    );
}

/// **P8**: Daemonが落ちた後の生成要求は、**識別可能なエラー**になる（§10.1）。
///
/// この節は「回復手段は用意しない／失敗は識別可能なエラーにしてログへ出す」と決めている。
/// **測っているのは「無言で成功しないこと」と「返ってくること」**である——
/// ハングすれば`run_shell`はタイムアウトまで返らず、静かに成功すれば
/// 呼び出し側は起きてもいない子を待つ。
///
/// **どの段で落ちるかまでは固定しない。** Daemonのプロセスが消えた瞬間に、
/// ハンドルの複製も制御パイプの書込も等しく失敗する——どちらで落ちても
/// 「識別可能なエラーが返る」という約束は満たされる。段を固定すると、
/// 実装の内部順序を変えただけでこのテストが赤くなる。
#[test]
#[ignore = "starts a real spawn daemon; run through spawn-daemon"]
fn a_spawn_request_after_the_daemon_died_fails_loudly() {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let daemon = SpawnDaemonHandle::start().expect("the spawn daemon must start");
    let pid = daemon.daemon_pid();

    // Daemonを外から落とす（クラッシュの模擬）。
    unsafe {
        let handle =
            OpenProcess(PROCESS_TERMINATE, false, pid).expect("open the daemon to kill it");
        let _ = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
    }
    assert!(
        crate::win_common::wait_for_process_exit(pid, 10_000),
        "落としたはずのDaemon（pid={pid}）がまだ生きている。測定の前提が崩れている"
    );

    // AppContainerは要らない（Daemonが死んでいるので、そこまで到達しない）。
    let job = crate::win_common::create_job_object().expect("job");
    let (stdout_read, stdout_write) =
        crate::win_common::create_inheritable_pipe().expect("stdout pipe");
    let (stderr_read, stderr_write) =
        crate::win_common::create_inheritable_pipe().expect("stderr pipe");

    let result = daemon.spawn_top_level(TopLevelSpawn {
        exe: r"C:\Windows\System32\cmd.exe",
        args: &["/c", "exit", "0"],
        cwd: std::path::Path::new(r"C:\"),
        env: &[],
        domain: DomainSpec {
            name: "dead-daemon".to_string(),
            container_sid: "S-1-15-2-1-2-3".to_string(),
            capability_sids: Vec::new(),
            identity: DomainIdentitySpec::OwnPackage,
        },
        job,
        stdout_write,
        stderr_write,
        stdin_read: None,
    });

    let message = match result {
        Ok(child) => {
            unsafe {
                let _ = CloseHandle(child.process);
            }
            panic!(
                "Daemonが死んでいるのに生成が成功したと報告された。\
                 呼び出し側は起きてもいない子を待つことになる（`B-10`）"
            );
        }
        Err(e) => e.to_string(),
    };
    eprintln!("[spawnd P8] error={message}");
    assert!(
        !message.trim().is_empty(),
        "エラーが空文字である。**理由の分からない失敗は無言失敗と同じ**（§10.1）"
    );

    unsafe {
        let _ = CloseHandle(stdout_read);
        let _ = CloseHandle(stderr_read);
        let _ = CloseHandle(job);
    }
}

/// 子の終了を待ち、harness側のハンドルを閉じる。
fn wait_and_close(child: &SpawnedChild, job: HANDLE) {
    unsafe {
        let _ = WaitForSingleObject(child.process, 60_000);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(child.process, &mut code);
        eprintln!("[spawnd] child pid={} exit={code}", child.pid);
        let _ = CloseHandle(child.process);
        let _ = CloseHandle(job);
    }
    // 実マシンの後始末に少しだけ猶予を与える（Jobのkill-on-closeが走る）。
    std::thread::sleep(Duration::from_millis(200));
}
