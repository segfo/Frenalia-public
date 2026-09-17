//! [段階6f-2] **フックがDaemonへ頼むようになったこと**の実機受け入れ。
//!
//! # 6f-1と何が違うのか
//!
//! ```text
//!   6f-1: プローブ ──自分で組んだ電文──→ Daemon      （Daemon側が運べるか）
//!   6f-2: プローブ ─CreateProcessW→ フック ─電文→ Daemon （フックが組めるか）
//! ```
//!
//! 6f-1の受け入れは**プローブがフックの役を演じて**いた。ここではプローブは
//! `CreateProcessW`を呼ぶだけで、電文を組むのは**Redirector DLL**である。
//! だからこの回のテストは、**DLLを注入した子**（`RedirectorSpec::ProcessHooks`）で撃つ。
//!
//! # 合格条件は「3つの腕」と「対の2本」である
//!
//! | 測ること | 期待 |
//! |---|---|
//! | 生成禁止＋**辺を宣言** | 頼んで**起きる**（マーカーが生まれる） |
//! | 生成禁止＋**宣言なし** | 断られて**1つも生まれない**（判定はDaemonが持ったまま） |
//! | **生成禁止を積まない**＋宣言なし | **自分で起こして生まれる**（今日の挙動が1ビットも変わらない） |
//!
//! **3つ目が要である。** これが無いと「常に頼む」実装で上2つが緑のまま通り、
//! 宣言を1つも書いていない今日の製品が**何も起動できなくなる**。
//!
//! # フックを迂回する経路は、迂回したままでよい
//!
//! `ntdll!NtCreateUserProcess`を直に叩く経路はフックを通らないので、カーネルが拒否する。
//! **それが正しい**（D-01: フックは境界ではない）——だから「宣言した回でも、この経路の
//! マーカーは生まれない」ことを同じ測定の中で見る。
//!
//! # 判定に**プローブ自身の報告を使わない**（計器の既知の不安定）
//!
//! `--spawn-matrix`のプローブは、AppContainerの中で**ときどき最後に落ちる**
//! （`0xC0000374`＝ヒープ破壊。2026-09-17に確認）。**段階6f-2が持ち込んだものではない**
//! ——注入を1つも行わない段階⑤の腕でも出るし、**この回の変更を全部外した基準線でも出る**
//! （`git stash`して測り直した）。落ちるのは8経路すべてを試し終えた後なので、
//! **マーカーは全部書かれている。**
//!
//! だから合否は**マーカーの有無だけ**で決める——プローブの報告（標準出力のJSON）は
//! 落ちた回には出ないので、そこに合否を預けると計器の不安定がそのまま赤になる。
//!
//! **2026-09-18、落ちる場所は特定した**（`page_heap_fault_tests`。Page Heap(Full)の下で
//! 測ると、**タスクスケジューラのCOM活性化の中**で`combase.dll`→`ntdll.dll`のヒープ経路が
//! 解放済み／範囲外を読んでいる。プローブ自身のコードはスタックに無い）。
//! **ただし元の`0xC0000374`と同じ欠陥かは未証明**なので、ここの判定は変えない。
//! 記録は`docs/STATUS.md`の残課題#52と`plans/mac-spike/RESULTS.md`§S61にある。
//!
//! # ここで測っていないもの（**limitation**）
//!
//! - **拒否がモデルへ届くこと**（§19.3.8の表の2つ目）。段階6f-3
//! - **標準の3本以外の継承ハンドル**が子へ渡ること。運べない（`spawn_broker`のモジュールdoc）
//! - **ストアの実行エイリアスへの遷移**。Jobへ入れられない（残課題#50）ので、
//!   シェルは`WindowsPowerShell\v1.0`の実体を使う

use super::transition_acceptance_tests::{cmd_exe, policy_with_edges, windows_powershell_51};
use super::*;
use crate::tier2a::spawnd::RedirectorSpec;

/// この回の腕が必ず使う注入の指定。**ワークスペースは渡すが、誘導も受付も無い**
/// ——プロセス生成フックを置くためだけの注入である（段階5b）。
fn process_hooks(workspace: &std::path::Path) -> Option<RedirectorSpec> {
    Some(RedirectorSpec::ProcessHooks {
        workspace_root: Some(workspace.to_string_lossy().into_owned()),
    })
}

/// **DLLの診断の受け皿**（`harness-redirector`の`config::DEBUG_LOG_ENV`と対の綴り）。
///
/// サンドボックスの中のDLLは、差分層が無い構成では`%TEMP%`へ書こうとして**失敗する**
/// （AppContainerの子はユーザーの`%TEMP%`にACEを持たない）。**張らないと、
/// フックが何をしたのかはどこにも残らない**——6f-1でDaemonのstderrに同じ口を作ったのと同じ形。
const REDIRECTOR_LOG_ENV: &str = "HARNESS_REDIRECTOR_DEBUG_LOG";

/// DLLを注入したプローブを起こして、標準出力を返す。
///
/// **要求受付capabilityを必ず積む**——積まないとフックが窓口へ届かず、
/// 「変換できなかった」と「届かなかった」が混ざる。
fn run_probe_with_hooks(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    args: &[&str],
) -> (String, String) {
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    // **受け皿はワークスペースの中へ置く。** ここはこのドメインが書ける唯一の場所で、
    // かつ`Case`が畳むときに一緒に消える。
    let redirector_log = workspace.join("redirector.log");

    let (child, job, out, err) = super::start_top_level(
        daemon,
        profile,
        &workspace,
        super::TopLevelArm {
            exe: &probe_str,
            args,
            domain: domain_spec(profile, caps, Some(&spawn_cap)),
            // プローブ自身はコンソールを要らない。**起こす子の要否とは別の軸**である。
            console: ConsoleNeed::NotNeeded,
            redirector: process_hooks(&workspace),
            extra_env: vec![(
                REDIRECTOR_LOG_ENV.to_string(),
                redirector_log.to_string_lossy().into_owned(),
            )],
        },
    );
    super::wait_and_close(&child, job);
    // **読めたら必ず出す。** 落ちたときに「フックが何をしたか」を後から読める唯一の場所である。
    if let Ok(log) = std::fs::read_to_string(&redirector_log) {
        eprintln!("[6f-2 redirector log]\n{log}");
    }
    (out, err)
}

/// `--spawn-matrix`が実際に子を作れた経路の名前（マーカーファイルが生まれたもの）。
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

/// **フックを置いてある4つのAPI**。この4つは頼めていなければならない。
///
/// `createprocessasuserw`を入れているのは、AppContainerの中でも**トークンの複製に成功する**
/// ことが測ってあるためである（[§S1](../../../../../../plans/mac-spike/RESULTS.md)の
/// 7構成すべてで成功。`ERROR_PRIVILEGE_NOT_HELD`は1件も出ていない）。
/// 頼むときトークンは落ちるが、AppContainerの中で得られるのは自分のトークンの複製だけなので
/// 起きる子の文脈は変わらない（`harness-redirector`の`spawn_broker`のモジュールdoc）。
///
/// **`shellexecuteexw`はここに入れない。** 2026-09-17の実測では**フック経由で起きた**
/// （生成禁止＋宣言ありでマーカーが生まれた）ので、あれはプロセス内で`CreateProcessW`を
/// 呼んでいる。ただし**こちらが名前でフックしているAPIではない**ので、Windowsの実装が
/// ブローカー経由へ変わればこの回路は消える——合否をそこに預けない（測って記録はする）。
const HOOKED_METHODS: &[&str] = &[
    "createprocessw.txt",
    "createprocessa.txt",
    "winexec.txt",
    "createprocessasuserw.txt",
];

/// **生成禁止を積んだときだけ頼み、頼んだ先の判定に従う。**
///
/// 3つの腕を1回のテストで撃つ（それぞれ実機のワークスペース作成とDaemon起動を伴うので、
/// 分けると同じ土台を3回払う）。**どの腕で落ちたかは表明のメッセージが名指しする。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_hook_asks_the_daemon_only_when_the_kernel_blocks_creation() {
    struct Arm {
        label: &'static str,
        policy: ChildProcessPolicy,
        declare_cmd: bool,
    }
    let arms = [
        Arm {
            label: "restricted-declared",
            policy: ChildProcessPolicy::Restricted,
            declare_cmd: true,
        },
        Arm {
            label: "restricted-undeclared",
            policy: ChildProcessPolicy::Restricted,
            declare_cmd: false,
        },
        Arm {
            label: "unrestricted-undeclared",
            policy: ChildProcessPolicy::Unrestricted,
            declare_cmd: false,
        },
    ];

    let mut seen: Vec<(&'static str, Vec<String>)> = Vec::new();
    for arm in arms {
        let (case, profile, caps) = setup_with_policy_and_transitions(
            &format!("spawnd-6f2-{}", arm.label),
            arm.policy,
            |_workspace| {
                if arm.declare_cmd {
                    policy_with_edges(E2E_POLICY_DOMAIN, &[&cmd_exe()])
                } else {
                    harness_policy::policy_file::PolicyFile::default()
                }
            },
        );
        let workspace = case
            .dir
            .as_ref()
            .expect("case owns the dir")
            .path()
            .to_path_buf();
        // マーカーの置き場は**ワークスペースの中**にする。外だと子が書けず、
        // 「拒否された」と「書込が拒否された」が区別できなくなる。
        let marker_dir = workspace.join("spawn-markers");
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_str = marker_dir.to_string_lossy().into_owned();

        let (out, err) = run_probe_with_hooks(
            &case,
            &profile,
            &caps,
            &["--spawn-matrix", &marker_str, "--timeout-secs", "60"],
        );
        eprintln!("[6f-2 {}] stdout={out}\nstderr={err}", arm.label);
        let markers = markers_written(&marker_dir);
        eprintln!("[6f-2 {}] markers={markers:?}", arm.label);
        seen.push((arm.label, markers));
        drop(case);
    }

    let markers_of = |label: &str| -> Vec<String> {
        seen.iter()
            .find(|(l, _)| *l == label)
            .map(|(_, m)| m.clone())
            .unwrap_or_default()
    };

    // **対照が先である**（型: 計器を疑う）。生成禁止を積まない回で1つも生まれないなら、
    // 測っているのはフックではなく別の壊れ方である。
    let unrestricted = markers_of("unrestricted-undeclared");
    for method in HOOKED_METHODS {
        assert!(
            unrestricted.iter().any(|m| m == method),
            "生成禁止を積まない回で`{method}`の子が生まれていない。\
             **今日の挙動が変わってしまっている**（フックが頼む形になっているか、\
             注入そのものが壊れている）。markers={unrestricted:?}"
        );
    }

    let declared = markers_of("restricted-declared");
    for method in HOOKED_METHODS {
        assert!(
            declared.iter().any(|m| m == method),
            "生成禁止を積み、辺も宣言したのに`{method}`の子が生まれていない。\
             フックがDaemonへ頼めていない（変換・窓口への到達・判定のどれか）。\
             markers={declared:?}"
        );
    }
    assert!(
        !declared.iter().any(|m| m == "ntcreateuserprocess.txt"),
        "フックを迂回する経路で子が生まれている。カーネルの生成禁止が効いていない\
         ＝フックが境界になってしまっている（D-01違反）。markers={declared:?}"
    );

    let undeclared = markers_of("restricted-undeclared");
    assert!(
        undeclared.is_empty(),
        "宣言していないのに子が生まれている。**フックが頼まずに自分で起こしたか、\
         Daemonが判定していない**——どちらでも遷移MACが1ビットも効いていない。\
         markers={undeclared:?}（宣言した回では {declared:?} が生まれた）"
    );
}

/// **透過の中身**: フック経由で起こした子の出力が**呼び出し元が開いたハンドル**へ落ち、
/// 返ったハンドルで待てて終了コードが読め、**呼び出し元が置いた環境変数**が子に見える。
///
/// # 1本で4つ見ているのはなぜか
///
/// 4つとも「**フックが呼び出し元の持ち物を運べたか**」という同じ問いの側面で、
/// 別々にすると同じ実機の起動を4回払う。**ただし表明は分ける。**
///
/// 6f-1のT4と**同じ判定**である（あちらはプローブが電文を組み、こちらはフックが組む）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_callers_belongings_travel_through_the_hook() {
    const MARKER_VALUE: &str = "HARNESS-6F2-ENV-REACHED";
    const EXIT_CODE: u32 = 7;

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f2-belongings",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edges(E2E_POLICY_DOMAIN, &[&cmd_exe()]),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let stdout_file = workspace.join("hooked-child-stdout.txt");
    let stdout_str = stdout_file.to_string_lossy().into_owned();
    // **`lpApplicationName`は渡さない**（`--spawn-image`を指定しない）。
    // 実行ファイルの解決までフックの仕事にするのが、透過の本体である。
    let command_line = format!(
        "\"{}\" /c echo %HARNESS_6F2_ENV% & exit {EXIT_CODE}",
        cmd_exe()
    );

    let (out, err) = run_probe_with_hooks(
        &case,
        &profile,
        &caps,
        &[
            "--spawn-transparently",
            "none",
            "--spawn-command-line",
            &command_line,
            "--spawn-stdout",
            &stdout_str,
            "--spawn-set-env",
            &format!("HARNESS_6F2_ENV={MARKER_VALUE}"),
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[6f-2 belongings] stdout={out}\nstderr={err}");

    assert_eq!(
        report_field(&out, "created").and_then(|v| v.as_bool()),
        Some(true),
        "`CreateProcessW`が失敗している。フックが頼めていない\
         （`last_error`が233なら窓口へ届いていない、5ならDaemonが断った、\
         2なら実行ファイルを解決できなかった）: {out}"
    );
    assert_eq!(
        report_field(&out, "waited_ok").and_then(|v| v.as_bool()),
        Some(true),
        "返ってきたプロセスハンドルで待てていない。\
         `PROCESS_INFORMATION`に入れたハンドルが子を指していない: {out}"
    );
    assert_eq!(
        report_field(&out, "child_exit_code").and_then(|v| v.as_u64()),
        Some(EXIT_CODE as u64),
        "終了コードが呼び出し元へ伝わっていない: {out}"
    );

    let written = std::fs::read_to_string(&stdout_file).unwrap_or_default();
    assert!(
        written.contains(MARKER_VALUE),
        "呼び出し元が開いたハンドルへ子の出力が落ちていない、または\
         **呼び出し元がプロセス内で置いた環境変数が子へ届いていない**。\
         前者ならファイルが空、後者なら`%HARNESS_6F2_ENV%`がそのまま出る: \
         file={written:?} stdout={out}"
    );
}

/// **コンソール要否は呼び出し元の生成フラグから導かれる**（§10.1.2の決定2）。
///
/// # 対で撃つ（`B-35`）
///
/// 片側だけだと意味を持たない——`required`固定の実装も`not_needed`固定の実装も、
/// 片側では緑になる。しかも**取り違えの向きが違う**: 前者は起動失敗、
/// 後者は**終了コード0の無言失敗**である。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_creation_flags_decide_whether_the_nested_shell_gets_a_console() {
    const MARKER: &str = "HARNESS-6F2-SHELL-RAN";
    const EXIT_CODE: u32 = 11;

    let shell = windows_powershell_51();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f2-console",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edges(E2E_POLICY_DOMAIN, &[&shell]),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let script = format!("Write-Output '{MARKER}'; exit {EXIT_CODE}");
    let command_line = crate::tier2a::win_appcontainer::command_line_for(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    );

    // フラグ無し → `required` → 保持プロセスのコンソールを借りる → 走る。
    let plain_out_file = workspace.join("shell-plain.txt");
    let (plain, plain_err) = run_probe_with_hooks(
        &case,
        &profile,
        &caps,
        &[
            "--spawn-transparently",
            "none",
            "--spawn-command-line",
            &command_line,
            "--spawn-stdout",
            &plain_out_file.to_string_lossy(),
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[6f-2 console none] stdout={plain}\nstderr={plain_err}");

    // `CREATE_NO_WINDOW` → `not_needed` → コンソールを借りない → **何も実行せずexit 0**。
    let quiet_out_file = workspace.join("shell-no-window.txt");
    let (quiet, quiet_err) = run_probe_with_hooks(
        &case,
        &profile,
        &caps,
        &[
            "--spawn-transparently",
            "no-window",
            "--spawn-command-line",
            &command_line,
            "--spawn-stdout",
            &quiet_out_file.to_string_lossy(),
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[6f-2 console no-window] stdout={quiet}\nstderr={quiet_err}");

    let plain_written = std::fs::read_to_string(&plain_out_file).unwrap_or_default();
    assert!(
        plain_written.contains(MARKER),
        "フラグを1つも付けていない呼び出しなのに、シェルが実行印を出していない。\
         コンソールを借りられていないと、PowerShellは**何も実行せず終了コード0**で終わる\
         （§7.1の無言失敗）: file={plain_written:?} report={plain}"
    );
    assert_eq!(
        report_field(&plain, "child_exit_code").and_then(|v| v.as_u64()),
        Some(EXIT_CODE as u64),
        "実行印は出たのに終了コードが伝わっていない: {plain}"
    );

    let quiet_written = std::fs::read_to_string(&quiet_out_file).unwrap_or_default();
    assert!(
        !quiet_written.contains(MARKER),
        "`CREATE_NO_WINDOW`を指定した呼び出しでもシェルが走っている。\
         **導出が効いていない**（常に`required`を送っている）ので、\
         コンソールを要らない子まで保持プロセスのコンソールを掴む: \
         file={quiet_written:?} report={quiet}"
    );
    assert_eq!(
        report_field(&quiet, "child_exit_code").and_then(|v| v.as_u64()),
        Some(0),
        "コンソール無しのPowerShellは**0で終わる**のが§7.1の実測である。\
         別の値なら、測っているものが違う: {quiet}"
    );
}

