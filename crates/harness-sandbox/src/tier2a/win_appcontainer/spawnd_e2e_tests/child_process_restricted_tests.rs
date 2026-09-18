//! 段階⑤（子プロセス生成の禁止）の実機受け入れ。
//!
//! # 何を合格条件にしているのか
//!
//! **積んだ側だけを測ると、何も起動できない実装でも緑になる。** だから4本のうち
//! 3本が対になっている——同じワークスペース・同じドメインで、
//! **生成禁止を積んだ回と積まない回を並べる**（`B-35`）。
//!
//! | 測ること | 積んだ回 | 積まない回（対照） |
//! |---|---|---|
//! | サンドボックスの子が**自力で**子プロセスを作る | **作れない**（6経路とも） | **作れる** |
//! | 同じ子が**要求受付パイプへ頼む** | **届いて`unknown_source_domain`** | 同じ |
//! | **シェル**が起動してコマンドを実行し終了コードを返す | **返す**（コンソールを借りるので） | 同じ |
//!
//! **2行目が肝である。** 生成能力を取り上げただけで窓口へ届かなくなっていたら、
//! 段階E（遷移ポリシーの評価）が着地しても誰も子を得られない——
//! 「取り上げる」と「代わりに起こす口を残す」は別の事実で、両方を1回の測定で押さえる。
//!
//! # ここで測っていないもの（**limitation**）
//!
//! - **許可された遷移が通ること。** 遷移ポリシーの評価は未実装で、答えは常に拒否である
//!   （段階Eが入るまで`unknown_source_domain`が正しい応答）
//! - **注入したがフックが載らない子**。`docs/STATUS.md`残課題#44が要求している実測で、
//!   その状態を作る仕掛けをまだ持っていない
//! - **保持プロセスが制御イベントで落ちないこと**。握り潰しは実装したが、
//!   サンドボックスから撃つ腕はここに無い（測定としては`plans/mac-spike/RESULTS.md`§S49が持つ）

use std::time::Duration;

use super::super::*;
use super::{domain_spec, report_field, setup_with_policy, spawn_request_payload, Case};
use crate::tier2a::spawnd::client::SpawnDaemonHandle;
use crate::tier2a::spawnd::{ChildProcessPolicy, ConsoleNeed};

/// 1本の子を起こして、標準出力・標準エラー・終了コードを取る。
///
/// [`super::start_top_level`]との違いは**待ち方だけ**である——あちらは子とJobを返して
/// 呼び出し側に待たせるが、ここでは終了コードまで取って返す
/// （「シェルが本当にコマンドを実行したか」を終了コードで見るため）。
///
/// [段階6f-2] `redirector`が要るのは、**フックが載っているかで結果が反転する腕**が
/// あるからである（プロセス生成フックが無い子は、生成禁止の下で何もできない）。
fn spawn_and_collect(
    daemon: &SpawnDaemonHandle,
    profile: &OwnedContainerSid,
    workspace: &std::path::Path,
    domain: crate::tier2a::spawnd::DomainSpec,
    exe: &str,
    args: &[&str],
    console: ConsoleNeed,
) -> Result<(String, String, u32), String> {
    let (child, job, out, err) = super::start_top_level(
        daemon,
        profile,
        workspace,
        super::TopLevelArm {
            exe,
            args,
            domain,
            console,
            redirector: None,
            extra_env: Vec::new(),
        },
    );
    let code = super::wait_and_close_with_code(&child, job);
    Ok((out, err, code))
}

/// `--spawn-matrix`が実際に子を作れた経路の本数（＝マーカーが生まれた数）。
///
/// **戻り値の`api_ok`だけを数えない。** `WinExec`のように拒否の理由コードを持たない経路が
/// あるので、**実際に子が走った証拠（マーカーファイル）**で数える
/// （`plans/mac-spike/RESULTS.md`§S1が同じ数え方をしている）。
fn markers_written(marker_dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(marker_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// 生成禁止を積んだ／積まない で、サンドボックスの子が**自力で子プロセスを作れるか**が
/// 反転することを1本で測る（組の本体）。
///
/// **片方だけだと意味を持たない。** 積んだ側だけを見ると「そもそも起動できていない」
/// 実装でも緑になり、積まない側だけを見ると強制が1ビットも効いていなくても緑になる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_mitigation_flips_whether_a_sandboxed_child_can_create_processes_itself() {
    let mut restricted_markers: Option<Vec<String>> = None;
    let mut unrestricted_markers: Option<Vec<String>> = None;

    for policy in [
        ChildProcessPolicy::Unrestricted,
        ChildProcessPolicy::Restricted,
    ] {
        let label = format!("spawnd-s5-matrix-{}", policy.as_arg());
        let (case, profile, caps) = setup_with_policy(&label, policy);
        let daemon = case.daemon.as_ref().expect("case owns the daemon");
        let workspace = case
            .dir
            .as_ref()
            .expect("case owns the dir")
            .path()
            .to_path_buf();
        // マーカーの置き場は**ワークスペースの中**にする。外だと子が書けず、
        // 「生成禁止が効いた」と「書込が拒否された」が区別できなくなる。
        let marker_dir = workspace.join("spawn-markers");
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_str = marker_dir.to_string_lossy().into_owned();
        let probe = super::super::mac_spike_tests::probe_exe();
        let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

        let outcome = spawn_and_collect(
            daemon,
            &profile,
            &workspace,
            domain_spec(&profile, &caps, None),
            &probe_str,
            &[
                "--spawn-matrix",
                &marker_str,
                // **`taskscheduler`を外して撃つ**（報告が残る形。同名の定数のdoc）。
                // この的はその経路について何も判定していないので、測るものは減らない。
                "--spawn-matrix-methods",
                super::MATRIX_METHODS_WITHOUT_TASKSCHEDULER,
                "--timeout-secs",
                "60",
            ],
            ConsoleNeed::NotNeeded,
        );
        let (out, err, _code) = outcome.expect("the probe itself must start in both arms");
        eprintln!("[spawnd S5 {}] stdout={out}\nstderr={err}", policy.as_arg());

        let markers = markers_written(&marker_dir);
        match policy {
            ChildProcessPolicy::Unrestricted => unrestricted_markers = Some(markers),
            ChildProcessPolicy::Restricted => restricted_markers = Some(markers),
        }
        drop(case);
    }

    let unrestricted = unrestricted_markers.expect("the control arm ran");
    let restricted = restricted_markers.expect("the enforcing arm ran");

    // **対照が先である。** 対照が空なら計器が死んでいるので、
    // 強制側の空は何も意味しない（型: 計器を疑う）。
    assert!(
        !unrestricted.is_empty(),
        "対照（生成禁止を積まない回）で子プロセスが1つも作れていない。\
         測定器が死んでいるので、強制側の結果は何も意味しない。\
         markers={unrestricted:?}"
    );
    assert!(
        restricted.is_empty(),
        "生成禁止を積んだのに、サンドボックスの子が自力で子プロセスを作れている。\
         カーネルが拒否していない＝段階⑤の強制が成立していない。\
         markers={restricted:?}（対照では {unrestricted:?} が生まれた）"
    );
}

/// **タスクスケジューラのブローカー経路は、AppContainerから子を作れない。**
///
/// # なぜ単独で撃つのか
///
/// この経路の`CoCreateInstance`は、AppContainerの中で`combase.dll`→`ntdll.dll`の
/// ヒープ経路を壊し、**プローブごと落とす**（OS内部の欠陥。`plans/mac-spike/RESULTS.md`§S61）。
/// 他の7本と同じ回で撃つと、落ちた回はそれらの報告まで失われる。だから**この1本だけ**を
/// 別のプロセスで撃つ。
///
/// # 落ちても赤くしない。**落ちるとも決めつけない**
///
/// 素の（Page Heapを載せない）回では、落ちずに`0x80040154`（クラスが登録されていません）で
/// 返ることもある。**どちらでも結論は同じ**——子は生まれない。だから終了コードを判定に使わない。
///
/// # 判定は2つを**対で**見る
///
/// | 見るもの | 無いと何が起きるか |
/// |---|---|
/// | 足跡`starting taskscheduler`が出ている | **撃つ前に落ちた回**を「到達できなかった」と読んでしまう |
/// | マーカーが1つも無い | そもそも塞がっているかを見ていない |
///
/// **片方だけでは成立しない。** マーカーが無いことは、撃っていなくても成り立つ。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_task_scheduler_broker_is_out_of_reach_even_though_it_crashes_the_probe() {
    let (case, profile, caps) =
        setup_with_policy("spawnd-s5-taskschd", ChildProcessPolicy::Restricted);
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker_dir = workspace.join("spawn-markers");
    std::fs::create_dir_all(&marker_dir).expect("marker dir");
    let marker_str = marker_dir.to_string_lossy().into_owned();
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (out, err, code) = spawn_and_collect(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, None),
        &probe_str,
        &[
            "--spawn-matrix",
            &marker_str,
            "--spawn-matrix-methods",
            "taskscheduler",
            "--timeout-secs",
            "60",
        ],
        ConsoleNeed::NotNeeded,
    )
    .expect("the probe itself must start");
    eprintln!("[spawnd S5 taskschd] exit={code:#010x}\nstdout={out}\nstderr={err}");

    assert!(
        err.contains("[spawn-matrix] starting taskscheduler"),
        "この経路を撃った跡が無い。撃つ前に落ちた回を『到達できなかった』と\
         読まないための検問である。stderr={err}"
    );
    assert!(
        markers_written(&marker_dir).is_empty(),
        "タスクスケジューラ経由で子が生まれている＝ブローカー生成で\
         サンドボックスを抜けられる。markers={:?}",
        markers_written(&marker_dir)
    );

    drop(case);
}

/// 生成能力を取り上げても、**要求受付パイプへは届く**。
///
/// これが破れると、段階E（遷移ポリシーの評価）が着地しても誰も子を得られない。
/// **「取り上げる」と「代わりに起こす口を残す」は別の事実である。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_restricted_child_still_reaches_the_request_pipe() {
    let (case, profile, caps) =
        setup_with_policy("spawnd-s5-reach", ChildProcessPolicy::Restricted);
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let payload = spawn_request_payload();
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (out, err, _code) = spawn_and_collect(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, Some(&spawn_cap)),
        &probe_str,
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
        ConsoleNeed::NotNeeded,
    )
    .expect("the probe must start even with child process creation blocked");
    eprintln!("[spawnd S5 reach] stdout={out}\nstderr={err}");

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "生成禁止を積んだ子が要求受付パイプへ接続できない。\
         取り上げたまま頼む口が無い状態＝段階Eが着地しても誰も子を得られない: {out}"
    );
    assert_eq!(
        super::deny_reason(&out).as_deref(),
        Some("unknown_source_domain"),
        "届いてはいるが、断られ方が「遷移ポリシーが未実装」ではない。\
         台帳の判定かDACLのどちらかが変わっている: {out}"
    );
    drop(case);
}

/// 生成禁止を積んだ**シェル**が、保持プロセスのコンソールを借りて起動し、
/// コマンドを実行して終了コードを返す（§7.1.1の成立条件そのもの）。
///
/// **終了コードだけで判定しない。** コンソールが無いとPowerShellは
/// 「何も実行せず終了コード0」で終わるので、`0`は成功にも無言失敗にも見える。
/// だから**実行印を標準出力へ出させ、印と終了コードの両方**を見る（§S1bと同じ判定）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_restricted_shell_borrows_a_console_and_actually_runs_its_command() {
    let (case, profile, caps) =
        setup_with_policy("spawnd-s5-shell", ChildProcessPolicy::Restricted);
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    const MARKER: &str = "HARNESS-S5-SHELL-RAN";
    const EXIT_CODE: u32 = 37;
    let (shell_exe, _shell_kind) = super::super::resolve_shell();
    let script = format!("Write-Output '{MARKER}'; exit {EXIT_CODE}");

    let (out, err, code) = spawn_and_collect(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, None),
        &shell_exe,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        ConsoleNeed::Required,
    )
    .expect("the shell must start when the daemon lends it a console");
    eprintln!("[spawnd S5 shell] exit={code} stdout={out}\nstderr={err}");

    assert!(
        out.contains(MARKER),
        "生成禁止を積んだシェルが実行印を出していない。コンソールを借りられていないと、\
         PowerShellは何も実行せず終了コード0で終わる（§7.1の無言失敗）: stdout={out} stderr={err}"
    );
    assert_eq!(
        code, EXIT_CODE,
        "実行印は出たのに終了コードが伝わっていない: stdout={out} stderr={err}"
    );
    drop(case);
}

/// コンソール保持プロセスを外から強制終了しても、**次のシェル要求で立て直される**
/// （§7.1.2の決定2「借りる直前に、無ければ作る」の1本化）。
///
/// **同じ経路で初回作成と立て直しが起きることを、1本のテストで見る。** 別経路にすると、
/// 立て直しだけが3つ目の経路として取り残される。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_console_holder_is_rebuilt_after_it_is_killed() {
    let (case, profile, caps) =
        setup_with_policy("spawnd-s5-rebuild", ChildProcessPolicy::Restricted);
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    const MARKER: &str = "HARNESS-S5-REBUILD";
    let (shell_exe, _shell_kind) = super::super::resolve_shell();
    let script = format!("Write-Output '{MARKER}'; exit 11");
    let args = ["-NoProfile", "-NonInteractive", "-Command", script.as_str()];

    // 1回目——ここで保持プロセスが生まれる。
    let (first_out, _, first_code) = spawn_and_collect(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, None),
        &shell_exe,
        &args,
        ConsoleNeed::Required,
    )
    .expect("the first shell must start");
    assert!(
        first_out.contains(MARKER) && first_code == 11,
        "1回目のシェルが走っていない。立て直しの測定が成立しない: {first_out}"
    );

    // 保持プロセスを外から落とす。**名前で探す**——Daemonは別プロセスなので、
    // テストからはそのハンドルを持っていない。
    let killed = kill_console_holders(daemon.daemon_pid());
    assert!(
        killed > 0,
        "コンソール保持プロセスが1つも見つからなかった。\
         生成禁止を積んだシェルを起こしたのに保持プロセスが居ないなら、\
         コンソールを借りずに起こしている（＝この測定が別のものを見ている）"
    );

    // 2回目——立て直されて、同じように走るはず。
    let (second_out, second_err, second_code) = spawn_and_collect(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, None),
        &shell_exe,
        &args,
        ConsoleNeed::Required,
    )
    .expect("the second shell must start after the holder was rebuilt");
    eprintln!("[spawnd S5 rebuild] killed={killed} exit={second_code} stdout={second_out}");

    assert!(
        second_out.contains(MARKER) && second_code == 11,
        "保持プロセスを落とした後、シェルが走らなくなった。\
         §7.1.2の決定2（借りる直前に、無ければ作る）が効いていない: \
         stdout={second_out} stderr={second_err}"
    );
    drop(case);
}

/// `<daemon_pid>`が親である`harness-spawnd.exe`（＝保持プロセス）を終了させ、その件数を返す。
///
/// **Daemon自身は落とさない。** 親PIDで絞るので、同じ名前でも制御パイプを持つDaemon本体は
/// 対象にならない（あれの親はこのテストプロセスである）。
fn kill_console_holders(daemon_pid: u32) -> usize {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let mut killed = 0usize;
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return 0;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ParentProcessID == daemon_pid {
                    if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, entry.th32ProcessID) {
                        if TerminateProcess(handle, 1).is_ok() {
                            killed += 1;
                        }
                        let _ = CloseHandle(handle);
                    }
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    // 落ちきるまで少し待つ（次の要求で「生きている」と誤判定させない）。
    std::thread::sleep(Duration::from_millis(300));
    killed
}

/// このモジュールが`Case`を使っていることをコンパイラへ示すための束縛。
/// （`setup_with_policy`の戻り値の型で使っているので、未使用の輸入にはならない。）
#[allow(dead_code)]
fn _case_type_is_used(case: Case) -> Case {
    case
}
