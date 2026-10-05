//! [BUG-230] 遷移の強制の下で`cmd.exe`が次のプログラムを起こせない件の、**原因を決める測定**。
//!
//! # 何を決めるのか
//!
//! `cmd.exe`が受け取ったエラー5（`ERROR_ACCESS_DENIED`）を**誰が返したのか**。
//! Redirector DLLのフックが5を返すのは「Daemonが断ったという返事を受け取ったとき」だけ
//! （`harness-redirector`の`BrokerFailure::last_error`）なのに、2026-10-05の実機（P4.8）では
//! 拒否の待ち行列が空だった。**中の段のDLLの診断ログ**（プロセスID付き）を読めば、
//! フックが呼ばれたか・頼んだか・返事が何だったかが1行ずつ残る。
//!
//! ```text
//! プローブ（DLL入り・生成禁止）
//!    └─ CreateProcessW「<中の段> … <葉>」 ─フック→Daemon─▶ 中の段（cmd.exe / powershell.exe 5.1）
//!                                                          └─ 葉を起こす ─フック→Daemon─▶ 葉（hostname.exe）
//! ```
//!
//! # 腕（1本ごとにワークスペースとDaemonを作り直す）
//!
//! | 腕 | 中の段 | 葉への辺 | 役割 |
//! |---|---|---|---|
//! | `cmd-declared` | `cmd.exe /d /c <葉>` | あり | 本命: この小さな形でも再現するか |
//! | `ps-declared` | `powershell.exe -Command <葉>` | あり | 対照: 中の段を替えれば葉が動く（形が正しい） |
//! | `cmd-undeclared` | `cmd.exe /d /c <葉>` | なし | 本命: `cmd.exe`の要求がDaemonへ届くか |
//! | `ps-undeclared` | `powershell.exe -Command <葉>` | なし | 対照: この形で待ち行列に1行が書かれる（計器の検算） |
//! | `cmd-dir` | `cmd.exe /d /c dir <プローブ> & dir <葉>` | — | 観測: ドメインの中から2つのファイルが**見えるか**（`dir`は内部コマンドで子を起こさない） |
//!
//! # 葉を`hostname.exe`にしてある理由（2026-10-05の1回目で分かったこと）
//!
//! 1回目は葉を試験用のプローブ（`target\debug\deps`）にした。**PowerShellの対照の腕まで失敗した**
//! ——PowerShellは葉を「コマンドとして認識できない」と言い、`cmd.exe`は「アクセスが拒否されました。」
//! と言い、どちらの中の段でもフックの行は1行も出なかった。プローブは外（Daemon）から起こす分には
//! 動くが、**ドメインの中のプログラムがそのファイルを探すと見えない**らしい（`cmd-dir`はこの読みを
//! 確かめる腕）。葉の置き場で失敗を作ると、P4.8の失敗とは別のものを測ってしまうので、
//! P4.8と同じ置き場（System32）の`hostname.exe`にした。葉が動いたかは、中の段の標準出力に
//! この機のホスト名が出たかで見る。
//!
//! **合否にするのは計器の検算と対照の腕だけ。** `cmd.exe`の腕は観測を決まった形で印字する
//! ——ここで知りたいのは「どう壊れているか」であって、壊れていること自体は既に分かっている。
//!
//! # 計器の検算（落ちたら、その回の`cmd.exe`の腕は読まない）
//!
//! - **Daemonの標準エラーの受け皿に書けること。** 宣言の無い遷移を断ってもDaemonは標準エラーへ
//!   1行も書かない（書くのは読めない要求・固定辺の拒否・起動の失敗・待ち行列の書込失敗等だけ）。
//!   だから腕の最後に**JSONとして読めない要求**を1件投げ、受け皿にその行が出ることを確かめる。
//!   P4.8の「0バイト」は、この検算が無かったので何の証拠にもならなかった。
//! - **DLLの診断ログが書け、DLLがデバッグビルドであること**（プローブ自身のPIDで`init:`と
//!   `brokered pid=<中の段>`）。リリースビルドのDLLは1行も書かない（`config::debug_log`）。
//! - **中の段にDLLが入り、中の段からもログへ書けること**（中の段のPIDで`init:`）。
//!   PowerShellの腕ではさらに`brokering`が出ること（中の段のフックの行が届く経路の対照）。
//! - **待ち行列に書かれること**（`ps-undeclared`で`NoMatchingEdge`が1件）。
//!
//! # 測っていないもの
//!
//! - harness.exe（`run_shell`）の経路そのもの。あちらでは`HARNESS_REDIRECTOR_DEBUG_LOG`が
//!   子へ渡る前の許可リスト（`build_child_env`）で落ちるのでDLLのログを張れない。
//!   ここで再現しても、harness.exeで同じ原因かは**推定**である。
//! - 中の段が遷移先の**別のドメイン**で動く形（P4.8はそうだった）。ここは自己ループだけ。
//!   この形で再現しなければ、それを1つ足した腕で撃ち直す。
//!
//! # 寿命: 判定が出たら消す
//!
//! 原因が確定して修正が入ったら、`cmd.exe`を中の段に置く腕だけを受け入れ
//! （`transparent_hook_tests.rs`）へ移し、**このファイルと昇格キー`spawn-daemon-cmd-nested`、
//! `spawn-daemon`の`--skip`を一緒に消す**。結論は`docs/bugs/BUG-230.md`と
//! `plans/mac-spike/RESULTS.md`が持つ（`docs/CODE-STRUCTURE-RULES.md`規則2の使い捨ての側）。

use crate::tier2a::spawnd::transitions::PendingRecord;

use super::transition_acceptance_tests::{
    ask_daemon, cmd_exe, policy_with_edges, windows_powershell_51,
};
use super::transition_queue_tests::{daemon_denial, queue_records};
use super::transparent_hook_tests::{redirector_log_path, run_probe_with_hooks};
use super::*;

/// 葉（`hostname.exe`）のフルパス。**`%SystemRoot%`から組む**（`cmd_exe`と同じ理由）。
fn hostname_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\hostname.exe")
}

/// 葉が動いたときに中の段の標準出力に出るはずの文字列。**サンドボックスの外で同じ葉を走らせて得る**
/// ——`COMPUTERNAME`はNetBIOS名なので、`hostname.exe`が出すDNSのホスト名と一致する保証が無い。
fn expected_hostname() -> String {
    let out = std::process::Command::new(hostname_exe())
        .output()
        .expect("hostname.exe must run outside the sandbox");
    let name = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
    assert!(!name.is_empty(), "サンドボックスの外でhostname.exeが何も出さなかった");
    name
}

/// Daemonの標準エラーの受け皿に必ず1行書かせるための、**JSONとして読めない**要求。
const UNREADABLE_REQUEST: &str = "BUG-230: this is not a spawn request";

/// Daemonが読めない要求を受けたときに標準エラーへ書く行の頭
/// （`spawnd::server`の`serve_request_connection`。綴りが変わればこの検算が赤くなる）。
const UNREADABLE_LINE: &str = "[spawnd] unreadable spawn request from the sandbox";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Middle {
    Cmd,
    WindowsPowerShell,
}

/// 中の段に何をさせるか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// 葉を起こす。
    RunLeaf,
    /// [1回目の読みの確かめ] プローブと葉の両方を`dir`する（子を起こさない）。
    ListBoth,
}

struct Arm {
    label: &'static str,
    middle: Middle,
    body: Body,
    declare_leaf: bool,
}

/// 1本の腕で観測したもの。**表明の前に全腕ぶんを印字する**——1本目の検算で落ちると、
/// 残りの腕の観測まで読めなくなる。
struct Observed {
    label: &'static str,
    middle: Middle,
    body: Body,
    declare_leaf: bool,
    leaf_path: String,
    probe_report: String,
    middle_pid: Option<u64>,
    probe_pid: Option<u64>,
    leaf_ran: bool,
    middle_output: String,
    log_lines: Vec<String>,
    queue: Vec<PendingRecord>,
    daemon_stderr: String,
}

impl Observed {
    /// DLLの診断ログのうち、指定したPIDが書いた行（書式は`[<ms> pid=<pid>] <msg>`）。
    fn lines_of(&self, pid: Option<u64>) -> Vec<&str> {
        let Some(pid) = pid else {
            return Vec::new();
        };
        let tag = format!(" pid={pid}]");
        self.log_lines
            .iter()
            .filter(|l| l.contains(&tag))
            .map(String::as_str)
            .collect()
    }

    /// 中の段とプローブのどちらでもないPIDが書いた行（葉など）。
    fn lines_of_others(&self) -> Vec<&str> {
        let known: Vec<String> = [self.probe_pid, self.middle_pid]
            .iter()
            .flatten()
            .map(|pid| format!(" pid={pid}]"))
            .collect();
        self.log_lines
            .iter()
            .filter(|l| !known.iter().any(|tag| l.contains(tag.as_str())))
            .map(String::as_str)
            .collect()
    }

    fn print(&self) {
        let middle = match self.middle {
            Middle::Cmd => "cmd.exe",
            Middle::WindowsPowerShell => "powershell.exe 5.1",
        };
        let mut text = format!(
            "\n===== [bug230 {}] 中の段={middle} させること={:?} 葉への辺={} =====\n",
            self.label,
            self.body,
            if self.declare_leaf { "あり" } else { "なし" },
        );
        text += &format!(
            "葉が動いたか（中の段の出力にホスト名）: {}\n",
            self.leaf_ran
        );
        text += &format!("プローブの報告: {}\n", self.probe_report.trim());
        text += &format!(
            "中の段の標準出力・標準エラー:\n{}\n",
            indent(&self.middle_output)
        );
        text += &format!(
            "DLLログ（プローブ pid={:?}）:\n{}\n",
            self.probe_pid,
            indent(&self.lines_of(self.probe_pid).join("\n"))
        );
        text += &format!(
            "DLLログ（中の段 pid={:?}）:\n{}\n",
            self.middle_pid,
            indent(&self.lines_of(self.middle_pid).join("\n"))
        );
        text += &format!(
            "DLLログ（その他のPID）:\n{}\n",
            indent(&self.lines_of_others().join("\n"))
        );
        text += &format!("待ち行列（{}行）:\n", self.queue.len());
        for record in &self.queue {
            text += &format!("  {record:?}\n");
        }
        let other_stderr: Vec<&str> = self
            .daemon_stderr
            .lines()
            .filter(|l| !l.contains(UNREADABLE_LINE))
            .collect();
        text += &format!(
            "Daemonの標準エラー（検算の行を除く）:\n{}\n",
            indent(&other_stderr.join("\n"))
        );
        eprintln!("{text}");
    }
}

fn indent(text: &str) -> String {
    if text.trim().is_empty() {
        return "  （無し）".to_string();
    }
    text.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// 行の頭`[<ms> pid=<pid>]`からPIDを読む。
fn pid_of(line: &str) -> Option<u64> {
    let rest = line.split_once(" pid=")?.1;
    rest.split_once(']')?.0.parse().ok()
}

fn run_arm(arm: &Arm, expected_hostname: &str) -> Observed {
    let leaf_str = hostname_exe();
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let middle_exe = match arm.middle {
        Middle::Cmd => cmd_exe(),
        Middle::WindowsPowerShell => windows_powershell_51(),
    };

    let (mut case, profile, caps) = setup_with_policy_and_transitions(
        &format!("spawnd-bug230-{}", arm.label),
        ChildProcessPolicy::Restricted,
        |_workspace| {
            let mut exes = vec![middle_exe.as_str()];
            if arm.declare_leaf {
                exes.push(leaf_str.as_str());
            }
            policy_with_edges(E2E_POLICY_DOMAIN, &exes)
        },
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let middle_output = workspace.join("middle-output.txt");
    let middle_output_str = middle_output.to_string_lossy().into_owned();

    // **引用符を使わない前提を確かめる。** `cmd /c`は引用符を取り除く規則を持つので、
    // 引用符を書くと「`cmd.exe`が起こせない」と「`cmd`が引用符を剥がして別の行にした」が混ざる。
    for path in [&leaf_str, &middle_exe, &probe_str] {
        assert!(
            !path.contains(' '),
            "この測定は引用符を使わずに行を組むので、空白を含むパスでは成立しない: {path}"
        );
    }
    let command_line = match (arm.middle, arm.body) {
        // `/d`はAutoRun（`cmd`起動時にレジストリのコマンドを走らせる設定）を切るだけで、
        // 子の起こし方は変えない。P4.8と同じ形にそろえる。
        (Middle::Cmd, Body::RunLeaf) => format!("{middle_exe} /d /c {leaf_str}"),
        (Middle::Cmd, Body::ListBoth) => {
            format!("{middle_exe} /d /c dir {probe_str} & dir {leaf_str}")
        }
        (Middle::WindowsPowerShell, Body::RunLeaf) => {
            format!("{middle_exe} -NoProfile -NonInteractive -Command {leaf_str}")
        }
        (Middle::WindowsPowerShell, Body::ListBoth) => {
            unreachable!("`dir`で見え方を確かめる腕は`cmd.exe`だけに置く")
        }
    };

    let (out, err) = run_probe_with_hooks(
        &case,
        &profile,
        &caps,
        &[
            // `lpApplicationName`は渡さない（解決までフックに任せる。P4.8の入口シェルと同じ形）。
            "--spawn-transparently",
            "none",
            "--spawn-command-line",
            &command_line,
            "--spawn-stdout",
            &middle_output_str,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[bug230 {}] probe stdout={out}\nprobe stderr={err}", arm.label);

    // プローブは中の段を待ってから終わり、中の段（`cmd /c`・`-Command`）は葉を待ってから終わる
    // ので、ここでは中の段の出力は書き終わっている。
    let middle_output_text = std::fs::read(&middle_output)
        .map(|bytes| crate::win_common::decode_console_bytes(&bytes))
        .unwrap_or_else(|e| format!("（読めない: {e}）"));
    let leaf_ran = arm.body == Body::RunLeaf
        && middle_output_text
            .to_lowercase()
            .lines()
            .any(|l| l.trim() == expected_hostname);
    let log = std::fs::read_to_string(redirector_log_path(&workspace)).unwrap_or_default();
    let log_lines: Vec<String> = log.lines().map(str::to_string).collect();

    let middle_pid = report_field(&out, "child_pid").and_then(|v| v.as_u64());
    // プローブ自身のPIDは「中の段を起こした」行の頭から読む（プローブの報告には載っていない）。
    let probe_pid = middle_pid.and_then(|middle| {
        let needle = format!("brokered pid={middle} ");
        log_lines
            .iter()
            .find(|l| l.contains(&needle))
            .and_then(|l| pid_of(l))
    });

    // [検算] Daemonの標準エラーの受け皿に、この回のDaemonが実際に書けること。
    let _ = ask_daemon(&case, &profile, &caps, UNREADABLE_REQUEST);
    // **Daemonを止めてから読む**（`Case`のdropと同じ順）。待ち行列は`Case`が生きているうちに読む。
    drop(case.daemon.take());
    let queue = queue_records(&case);
    let daemon_stderr = std::fs::read_to_string(&case.daemon_log).unwrap_or_default();
    drop(case);

    Observed {
        label: arm.label,
        middle: arm.middle,
        body: arm.body,
        declare_leaf: arm.declare_leaf,
        leaf_path: leaf_str,
        probe_report: out,
        middle_pid,
        probe_pid,
        leaf_ran,
        middle_output: middle_output_text,
        log_lines,
        queue,
        daemon_stderr,
    }
}

/// 計器の検算と対照の腕の期待。**崩れたものを全部数えて返す**（1つ目で止めない）。
fn instrument_failures(o: &Observed) -> Vec<String> {
    let mut failures = Vec::new();
    let label = o.label;

    if !o.daemon_stderr.contains(UNREADABLE_LINE) {
        failures.push(format!(
            "{label}: Daemonの標準エラーの受け皿に、わざと投げた読めない要求の行が無い。\
             **受け皿という計器が壊れている**ので、この回の「標準エラーに何も無い」は読めない。\
             中身: {:?}",
            o.daemon_stderr
        ));
    }
    let Some(middle_pid) = o.middle_pid else {
        failures.push(format!(
            "{label}: プローブが中の段を起こせていない（報告に`child_pid`が無い）。\
             中の段より手前で壊れているので、中の段の観測が無い: {}",
            o.probe_report.trim()
        ));
        return failures;
    };
    let probe = o.lines_of(o.probe_pid);
    if o.probe_pid.is_none() || !probe.iter().any(|l| l.contains("] init: ")) {
        failures.push(format!(
            "{label}: プローブ自身のDLLログに`init:`と`brokered pid={middle_pid}`が揃っていない。\
             **DLLのログが書けていないか、DLLがリリースビルド**（リリースは1行も書かない）なので、\
             中の段の「行が無い」を読めない"
        ));
    }
    let middle = o.lines_of(Some(middle_pid));
    if !middle.iter().any(|l| l.contains("] init: ")) {
        failures.push(format!(
            "{label}: 中の段（pid={middle_pid}）のDLLログに`init:`が無い。DLLが入っていないか、\
             中の段からログへ書けない——どちらでも、中の段の「フックの行が無い」は読めない"
        ));
    }

    if o.middle == Middle::WindowsPowerShell {
        if !middle.iter().any(|l| l.contains(": brokering ")) {
            failures.push(format!(
                "{label}: 対照の腕で、中の段のPowerShellのフックが頼んだ行（`brokering`）が無い。\
                 中の段のフックの行がログへ届く経路そのものが成立していない"
            ));
        }
        if o.declare_leaf && !o.leaf_ran {
            failures.push(format!(
                "{label}: 対照の腕（中の段がPowerShell・葉への辺あり）で葉が動いていない。\
                 **この形そのものが壊れている**ので、`cmd.exe`の腕の「葉が動かない」は読めない"
            ));
        }
        if !o.declare_leaf {
            let denials: Vec<_> = o
                .queue
                .iter()
                .filter(|r| matches!(r, PendingRecord::DeniedByDaemon(_)))
                .map(daemon_denial)
                .filter(|d| {
                    d.from_domain.as_deref() == Some(E2E_POLICY_DOMAIN)
                        && d.reason
                            == crate::tier2a::spawnd::DenyReason::Transition {
                                denial:
                                    harness_policy::transition::TransitionDenial::NoMatchingEdge,
                            }
                })
                .collect();
            if denials.len() != 1 {
                failures.push(format!(
                    "{label}: 対照の腕（中の段がPowerShell・葉への辺なし）で、待ち行列に\
                     `({E2E_POLICY_DOMAIN}, 葉, NoMatchingEdge)`がちょうど1件ではない（{}件）。\
                     **待ち行列という計器が壊れている**ので、`cmd.exe`の腕の「待ち行列が空」は読めない。\
                     葉={} 全行={:?}",
                    denials.len(),
                    o.leaf_path,
                    o.queue
                ));
            }
        }
    }
    failures
}

/// **測定**: 中の段を`cmd.exe`とPowerShellで入れ替え、葉への辺の有無を振った4本と、
/// `cmd.exe`の中から2つのファイルの見え方を確かめる1本を撃ち、
/// `cmd.exe`の腕で中の段のフックが何をしたかを印字する。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer children; run through spawn-daemon-cmd-nested"]
fn what_the_hook_inside_cmd_does_when_cmd_starts_the_next_program() {
    let arms = [
        Arm {
            label: "cmd-declared",
            middle: Middle::Cmd,
            body: Body::RunLeaf,
            declare_leaf: true,
        },
        Arm {
            label: "ps-declared",
            middle: Middle::WindowsPowerShell,
            body: Body::RunLeaf,
            declare_leaf: true,
        },
        Arm {
            label: "cmd-undeclared",
            middle: Middle::Cmd,
            body: Body::RunLeaf,
            declare_leaf: false,
        },
        Arm {
            label: "ps-undeclared",
            middle: Middle::WindowsPowerShell,
            body: Body::RunLeaf,
            declare_leaf: false,
        },
        Arm {
            label: "cmd-dir",
            middle: Middle::Cmd,
            body: Body::ListBoth,
            declare_leaf: false,
        },
    ];

    let expected_hostname = expected_hostname();
    eprintln!("[bug230] 葉が動いたら出るはずのホスト名: {expected_hostname}");
    let observed: Vec<Observed> = arms
        .iter()
        .map(|arm| run_arm(arm, &expected_hostname))
        .collect();
    for o in &observed {
        o.print();
    }

    let failures: Vec<String> = observed.iter().flat_map(instrument_failures).collect();
    assert!(
        failures.is_empty(),
        "計器の検算または対照の腕が{}件崩れた。**この回の`cmd.exe`の腕の観測は読まない**:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}
