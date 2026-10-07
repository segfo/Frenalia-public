//! 広げる遷移（決定66）の昇格E2E。**エディタが入力を固定せずに書いた「広げる辺」で、
//! `harness.exe --enforce-transitions`の子が、そのドメインの権限で実際に動くか**を本番の経路で確かめる
//! （`plans/position-domains/P5.md`の Task P5.7）。**管理者権限が要る**（パス1の収集器が張る ETW の
//! リアルタイムセッションと、Tier2a の準備が付ける祖先 traverse・宣言の ACE のため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-widening`。事前に`cargo build --workspace`と
//! `cargo build -p harness-cli --features e2e-mock`（手順と、違うビルドを黙って撃たない確かめは
//! `position_domains_e2e.rs`と同じ。部品は[`common`]）。
//!
//! # 何を測るのか
//!
//! 決定66は守る線を「入力の固定」から「子のドメインの権限（OSが強制する）」へ移した。
//! その線が実機で効いているなら、次の2つが**同時に**成り立つ——(1) 子は呼び出し元の持たない権限を
//! 使える（広い）、(2) 子の権限はそのドメインの宣言を超えない（上限がある）。P5.4b の受け入れ
//! （`spawn-daemon`）が測ったのは標準入出力の受け渡しで、「広がる」は判定器の数え方での広がりだった
//! （子が実際に広い権限を使えたかは測っていない）。この試験はそこを測る。
//!
//! # 書く辺（パス1で記録し、エディタの画面で位置ごとに承認する）
//!
//! ```text
//! 入口のシェル（workspace-shell）─ 中の段のシェル（powershell）: 目印のファイルを読める。出力を返す
//!                                └ cmd.exe（cmd）            : 目印のファイルを読める。出力を捨てる（o）
//! ```
//!
//! - 目印のファイルは**ワークスペースの外**（[`marker_dir`]）。入口のドメインは読めない
//! - 記録で2つの子が目印を読むので、FS/ネットのタブに子のドメインごとの読み取りの候補が出る。それを
//!   選び（cmd には`type`が一覧する目印のディレクトリも。[`wanted_declarations`]。`accepted`へ入れる。`tui/edit_tests.rs`の`a_on_the_fs_tab_of_a_position_record_writes_files_and_edges_together`
//!   と同じ）、観測のタブで2つの位置を`Space`、cmd の位置で`o`、`a`→`y`で1回に書く。どちらの辺も
//!   **判定器が「広げる」と判定し**（`EdgeVerdict::Widens`）、確認の明細に「広がる遷移 2本」が出ることを確かめる
//! - **出力を捨てる辺に`cmd.exe`を使う**——位置の鍵は（親のドメイン, 実行ファイル）なので、同じ`powershell.exe`で
//!   返す辺と捨てる辺を1本ずつ作れない。`cmd.exe`は葉（自分の中で`type`と`>`だけを使い、次の段を起こさない）
//!   なので、中の段に置けない件（BUG-230）には当たらない
//!
//! # 腕（`B-35`: 通る側と断る側、測りたい差だけを変えた対照を同じ回で）
//!
//! | 腕 | 行 | 期待 |
//! |---|---|---|
//! | ① 子が読む | 入口 → powershell が目印を読む | 子が走った印と目印の中身が返る・拒否0件 |
//! | ② 対照 | 入口が同じ目印を直接読む | 目印の中身が返らない（**①が子の広い権限を測った証拠**） |
//! | ③ 標準入力 | 入口が印を流し込み → powershell が読んで印字 | 子が加工した印（`GOT:…`）が返る |
//! | ④ 出力を捨てる | 入口 → cmd が目印を印字し、同じ中身を`ran.txt`へ書く | 出力に目印が無い・`ran.txt`に目印がある（空の出力が「走らなかった」でない対照） |
//! | ⑤ 記録に無い起動 | 入口 → powershell → hostname | `pending.jsonl`に遷移元＝powershell・`no_matching_edge`がちょうど1件 |
//! | ⑥ 子の通信 | 入口が`example.com`へ取りに行き、続けて powershell が同じことをする（`--net-allow-domain example.com`） | 入口は届き、子は届かない。子も同じプロキシの宛先を知っている |
//!
//! ⑥は**未測定だったことを測る**腕である（P5.md の「リスク・注意」）。子は呼び出し元の環境変数を引き継ぐので
//! `HTTP_PROXY`も届く。子の package SID からセッションのプロキシ（loopback）へ届かないなら、子の通信は
//! 閉じている。入口が同じ回・同じ書き方で届くことを先に見る——届かないなら、子の失敗は子のドメインのせいだと
//! 言えない（`measurement-review`の計器の検問）。サンドボックスの外からの到達性も先に見る（`tier2a_e2e.rs`の
//! `liveness_gate`と同じ考え方。届かなければ判定不能として落とす）。
//!
//! # 後始末（`test-logic-rules`の型F。製品の経路で戻す）
//!
//! 承認した2つの読み取りの宣言は、エディタの CLI の`unapprove --all`で取り消し、`harness.exe`をもう一度
//! 起こして剥がす（`record_net_e2e.rs`の`an_executable_that_cannot_be_started_becomes_a_read_exec_candidate_and_then_runs`
//! と同じ流れ）。取り消した後の回で**子が目印を読めなくなる**こと（①の差の原因が宣言だったこと）と、
//! 目印のファイルの DACL に capability SID の ACE が残っていないことを見る。最後に、`harness.exe`が作った
//! AppContainer プロファイルが撃つ前より増えていないことを見る（`position_domains_e2e.rs`と同じ）。
//!
//! # 言えないこと
//!
//! - Strict の辺はこの試験に無い（P5.7 の腕に無い。エディタは作業ディレクトリを宣言しないので Strict の
//!   ドメインへ入る辺を書けない）。Strict の辺の Daemon の扱いは`spawn-daemon`の`fixed_input_tests`・
//!   `edge_stdio_tests`が測る
//! - ⑥が見るのは「子からセッションのプロキシへの HTTP」だけで、生のソケット（プロキシを通らない接続）は
//!   別に測っていない（子のドメインは通信を宣言しないので`internetClient`を持たない＝`domain_provision.rs`）
//!
//! # ワークスペースの置き場
//!
//! `C:\harness-e2e\policy-editor-widening`、目印は`C:\harness-e2e\_widening-marker`（どちらも`%TEMP%`の外。
//! `%TEMP%`配下は候補にしない規則がある＝BUG-103）。緑なら消し、赤なら調査のため残す。

#![cfg(windows)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::event::KeyCode;
use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::transition::{ChildOutput, ExeMatcher, TransitionDenial};
use harness_policy_editor::position_view::EdgeVerdict;
use harness_policy_editor::tui::state::{App, Confirm};
use harness_sandbox::tier2a::spawnd::DenyReason;

use common::{
    acl_sddl, case_dir, child_named, count_sid_prefix, expect_no_denials, file_name, fold,
    harness_exe, harness_profiles, middle_shell, nonce, press, ps_run, record_tree, run_arm,
    run_arm_with, scope_root, scratch_dir, system32, unapprove_all, Arm, MiddleShell, Script,
    CASE_ROOT,
};

/// ワークスペースの名前。
const CASE: &str = "policy-editor-widening";
/// 出力を捨てる辺の子（[`cmd_exe`]）の実行ファイル名と、割り当てで付くドメインの名前（葉名）。
const CMD_EXE: &str = "cmd.exe";
const CMD_DOMAIN: &str = "cmd";
/// ⑥で取りに行く宛先（`tier2a_e2e.rs`の通信の行列と同じ）。
const NET_HOST: &str = "example.com";

/// 目印のファイルの置き場（**ワークスペースの外**。名前をワークスペースの名前で始めない——
/// `C:/harness-e2e/policy-editor-widening-…`はワークスペースの綴りを前方一致で含んでしまう）。
fn marker_dir() -> PathBuf {
    Path::new(CASE_ROOT).join("_widening-marker")
}

fn cmd_exe() -> String {
    system32(CMD_EXE)
}

/// 撃つ行と、それぞれの期待に使う印。
struct Plan {
    secret_path: String,
    /// 目印のファイルの中身（**どの行にも綴りとして現れない**。現れると、エラーの文面が行を引用しただけで
    /// 「読めた」と数えてしまう）。
    secret: String,
    stdin_marker: String,
    ran_path: PathBuf,
    child_reads: Script,
    entry_reads: Script,
    child_echoes_stdin: Script,
    discarding_child: Script,
    child_starts_unrecorded: Script,
    network: Script,
}

/// 子が走ったことの印。行には`'CHILD_' + 'RAN'`と割って書く（行の引用で当たらないように）。
const CHILD_RAN: &str = "CHILD_RAN";
/// ③で子が標準入力の各行の頭に付ける印。
const ECHO_PREFIX: &str = "GOT:";

fn plan(shell: &MiddleShell, ws: &Path) -> Plan {
    let secret_path = marker_dir().join("secret.txt");
    let ran_path = ws.join("ran.txt");
    let nonce = nonce();
    let secret = format!("WIDENING_SECRET_{nonce}");
    let stdin_marker = format!("WIDENING_STDIN_{nonce}");
    let secret_text = secret_path.to_string_lossy().into_owned();
    let ran_text = ran_path.to_string_lossy().into_owned();
    // cmd の`/c`の引数は PowerShell が二重引用符で囲んで渡す。中に二重引用符を書かずに済むよう、
    // 空白を含まない置き場だけを使う。
    for path in [&secret_text, &ran_text] {
        assert!(
            !path.contains(' '),
            "この試験の置き場は空白を含まない前提: {path}"
        );
    }
    let hostname = system32("hostname.exe");
    Plan {
        child_reads: Script {
            name: "1-child-reads-the-marker",
            line: ps_run(
                shell,
                &format!(
                    "Write-Output ('CHILD_' + 'RAN'); Get-Content -LiteralPath '{secret_text}'"
                ),
            ),
        },
        entry_reads: Script {
            name: "2-entry-reads-the-marker",
            line: format!("Get-Content -LiteralPath '{secret_text}'"),
        },
        child_echoes_stdin: Script {
            name: "3-stdin-reaches-the-child",
            line: format!(
                "'{stdin_marker}' | {}",
                ps_run(shell, "$input | ForEach-Object { 'GOT:' + $_ }")
            ),
        },
        discarding_child: Script {
            name: "4-discarding-child",
            line: format!(
                // 2つ目の`type`の標準エラーも`ran.txt`へ（読めなかったら、その理由が報告に出る）。
                "& '{}' /d /c 'type {secret_text} & type {secret_text} > {ran_text} 2>&1'",
                cmd_exe()
            ),
        },
        child_starts_unrecorded: Script {
            name: "5-child-starts-an-unrecorded-program",
            line: ps_run(shell, &format!("& '{hostname}'")),
        },
        network: Script {
            name: "6-child-network",
            line: format!(
                "{}; {}",
                net_probe("ENTRY"),
                ps_run(shell, &net_probe("CHILD"))
            ),
        },
        secret_path: secret_text,
        secret,
        stdin_marker,
        ran_path,
    }
}

/// `example.com`へプロキシ（`HTTP_PROXY`）経由で取りに行き、`<tag>:PROXY=…`と`<tag>:NET_OK <状態>`か
/// `<tag>:NET_FAIL <理由>`を印字する PowerShell の1行。印は行の中で割って書く（行の引用で当たらないように）。
///
/// **進捗表示を切る**（`$ProgressPreference`）。Windows PowerShell 5.1 の`Invoke-WebRequest`は進捗バーを
/// コンソールの画面バッファへ書こうとし、サンドボックスの中ではそれが「コンソール出力バッファーの読み取り中に
/// Win32 内部エラー "Access is denied" 0x5」で落ちる（2026-10-06の1回目の実測。入口の対照がこれで落ち、
/// 通信を測る前に判定不能になった）。
fn net_probe(tag: &str) -> String {
    format!(
        "$ProgressPreference = 'SilentlyContinue'; \
         Write-Output ('{tag}:PRO' + 'XY=' + $env:HTTP_PROXY); \
         try {{ $r = Invoke-WebRequest -Uri 'http://{NET_HOST}/' -Proxy $env:HTTP_PROXY -UseBasicParsing -TimeoutSec 20; \
         Write-Output ('{tag}:NET_' + 'OK ' + $r.StatusCode) }} \
         catch {{ Write-Output ('{tag}:NET_' + 'FAIL ' + $_.Exception.Message) }}"
    )
}

#[test]
#[ignore = "requires administrator rights (records pass 1 with the ETW collector and runs harness.exe with --enforce-transitions); run through dev-elevated-run"]
fn a_widening_edge_written_by_the_editor_lets_the_child_use_its_own_domain_and_no_more() {
    let harness = harness_exe();
    let shell = middle_shell();
    let hostname_output = hostname_outside_the_sandbox();
    let ws = case_dir(CASE);
    std::fs::create_dir_all(ws.join(".harness").join("sandbox")).unwrap();
    let plan = plan(&shell, &ws);
    let marker = marker_dir();
    let _ = std::fs::remove_dir_all(&marker);
    std::fs::create_dir_all(&marker).expect("create marker dir");
    std::fs::write(&plan.secret_path, &plan.secret).expect("write marker file");
    let mut failures: Vec<String> = Vec::new();

    // 基準線。**ここを取らないと、あとで数えた ACE が「元から在った分」と区別できない**
    // （`record_net_e2e.rs`と同じ）。作り直した直後なので capability SID の ACE は無いはず。
    let baseline = acl_sddl(Path::new(&plan.secret_path));
    eprintln!("[widening] 目印の SDDL（撃つ前）: {baseline}");
    assert_eq!(
        count_sid_prefix(&baseline, "S-1-15-3-"),
        0,
        "前提: 作り直した目印に capability SID の ACE があってはならない: {baseline}"
    );

    // --- 1・2. 記録して位置ごとに承認する ------------------------------------------------
    let record_dir = record(&ws, &shell, &plan);
    approve(&ws, &shell, &record_dir, &plan);
    check_written(&ws, &shell, &plan);

    // --- 3. harness.exe --enforce-transitions で撃つ ---------------------------------------
    let profiles_before = harness_profiles();

    // ① 子が目印を読める（広い）。
    let arm = run_arm(&harness, &ws, CASE, &plan.child_reads);
    arm.print(plan.child_reads.name);
    if !arm.result.contains(CHILD_RAN) {
        failures.push(format!(
            "{}: **子（{}）が走っていない。** 広がる辺の遷移そのものが通っていない。拒否: {:?}",
            plan.child_reads.name, shell.domain, arm.denials
        ));
    }
    if !arm.result.contains(&plan.secret) {
        failures.push(format!(
            "{}: 子が目印の中身を返していない（ドメインの宣言が子に付いていない？）。本文:\n{}",
            plan.child_reads.name, arm.result
        ));
    }
    expect_no_denials(&mut failures, plan.child_reads.name, &arm);
    // 宣言が実 DACL へ付いたこと（型A: 設定ではなく結果を見る）。package SID 宛ては0本のまま（残課題#20）。
    let granted = acl_sddl(Path::new(&plan.secret_path));
    eprintln!("[widening] 目印の SDDL（①の後）: {granted}");
    if count_sid_prefix(&granted, "S-1-15-3-") == 0 {
        failures.push(format!(
            "①の後の目印に capability SID の ACE が無い——①で読めたなら別の理由で読めている: {granted}"
        ));
    }
    if count_sid_prefix(&granted, "S-1-15-2-") != 0 {
        failures.push(format!(
            "①の後の目印に package SID の ACE がある（宛先は宣言ごとの capability SID のはず）: {granted}"
        ));
    }

    // ② 対照: 入口は同じファイルを読めない（①の差が子のドメインの権限であること）。
    let arm = run_arm(&harness, &ws, CASE, &plan.entry_reads);
    arm.print(plan.entry_reads.name);
    if arm.result.contains(&plan.secret) {
        failures.push(format!(
            "{}: **入口のシェルが目印を直接読めた。** ①は子の広い権限を測っていない。本文:\n{}",
            plan.entry_reads.name, arm.result
        ));
    }
    expect_no_denials(&mut failures, plan.entry_reads.name, &arm);

    // ③ 標準入力が広がる子に届く（決定66(3)）。子が頭に`GOT:`を付けた行に印があれば、印は子の標準入力を
    // 通っている（行そのものは`'GOT:' + $_`と割って書いてあるので、行の引用では当たらない）。
    //
    // **`GOT:`と印のあいだに2文字が挟まる**（2026-10-06の実測）。`run_shell`のブートストラップ
    // （`harness-tools`の`RUN_SHELL_BOOTSTRAP_SCRIPT`）が`$OutputEncoding = [System.Text.Encoding]::UTF8`を
    // 置くので、Windows PowerShell 5.1 は外部プログラムへのパイプの先頭に UTF-8 の BOM を書き、子は
    // それを自分の入力のコードページで2文字として読む。広げる遷移とは関係の無い`run_shell`の性質なので、
    // ここでは印が届いたかだけを見て、挟まった文字は報告に出す。
    let arm = run_arm(&harness, &ws, CASE, &plan.child_echoes_stdin);
    arm.print(plan.child_echoes_stdin.name);
    let echoed =
        arm.result.lines().map(str::trim).find(|line| {
            line.starts_with(ECHO_PREFIX) && line.contains(plan.stdin_marker.as_str())
        });
    match echoed {
        Some(line) => {
            let between = &line[ECHO_PREFIX.len()..line.find(plan.stdin_marker.as_str()).unwrap()];
            eprintln!(
                "[widening] {}: 子が返した行 {line:?}（{ECHO_PREFIX} と印のあいだ: {:?}）",
                plan.child_echoes_stdin.name,
                between.chars().map(|c| c as u32).collect::<Vec<_>>()
            );
        }
        None => failures.push(format!(
            "{}: 子が標準入力の印を読んで返していない（{ECHO_PREFIX} で始まり {} を含む行が無い）。本文:\n{}",
            plan.child_echoes_stdin.name, plan.stdin_marker, arm.result
        )),
    }
    expect_no_denials(&mut failures, plan.child_echoes_stdin.name, &arm);

    // ④ 出力を捨てる辺（決定66(4)）。空の出力が「走らなかった」でないことを`ran.txt`で見る。
    let _ = std::fs::remove_file(&plan.ran_path);
    let arm = run_arm(&harness, &ws, CASE, &plan.discarding_child);
    arm.print(plan.discarding_child.name);
    if arm.result.contains(&plan.secret) {
        failures.push(format!(
            "{}: **出力を捨てる辺なのに、子の出力（目印）が返った。** 本文:\n{}",
            plan.discarding_child.name, arm.result
        ));
    }
    match std::fs::read_to_string(&plan.ran_path) {
        Ok(text) if text.contains(&plan.secret) => {}
        Ok(text) => failures.push(format!(
            "{}: 子が書いた {} に目印が無い（子が目印を読めていない）: {text:?}",
            plan.discarding_child.name,
            plan.ran_path.display()
        )),
        Err(e) => failures.push(format!(
            "{}: 子が {} を書いていない（{e}）——空の出力が「捨てた」なのか「走らなかった」なのか言えない",
            plan.discarding_child.name,
            plan.ran_path.display()
        )),
    }
    expect_no_denials(&mut failures, plan.discarding_child.name, &arm);

    // ⑤ 広がる子が記録に無いプログラムを起こすと、子のドメインから断る。
    let arm = run_arm(&harness, &ws, CASE, &plan.child_starts_unrecorded);
    arm.print(plan.child_starts_unrecorded.name);
    let expected = (
        Some(shell.domain.clone()),
        "hostname.exe".to_string(),
        DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge,
        },
    );
    if arm.denials != vec![expected.clone()] {
        failures.push(format!(
            "{}: 断った記録が期待（{expected:?}）とちょうど1件で一致しない: {:?}",
            plan.child_starts_unrecorded.name, arm.denials
        ));
    }
    if arm.result.to_ascii_lowercase().contains(&hostname_output) {
        failures.push(format!(
            "{}: 断られるはずの hostname の出力（{hostname_output}）が届いた。本文:\n{}",
            plan.child_starts_unrecorded.name, arm.result
        ));
    }

    // ⑥ 子の通信。外からの到達性 → 入口（同じ回・同じ書き方の対照）→ 子、の順に読む。
    match reachable_outside_the_sandbox() {
        Err(reason) => failures.push(format!(
            "{}: 判定不能——サンドボックスの外から {NET_HOST} へ届かない（{reason}）。子の通信は測れていない",
            plan.network.name
        )),
        Ok(()) => {
            let arm = run_arm_with(
                &harness,
                &ws,
                CASE,
                &plan.network,
                &["--net-allow-domain", NET_HOST],
            );
            arm.print(plan.network.name);
            failures.extend(judge_network(plan.network.name, &arm));
            expect_no_denials(&mut failures, plan.network.name, &arm);
        }
    }

    // --- 4. 後始末: 宣言を取り消して起こし直す（製品の経路で剥がす） ----------------------
    for domain in [shell.domain.as_str(), CMD_DOMAIN] {
        unapprove_all(&ws, domain);
    }
    let after = Script {
        name: "7-child-reads-after-unapprove",
        line: plan.child_reads.line.clone(),
    };
    let arm = run_arm(&harness, &ws, CASE, &after);
    arm.print(after.name);
    if !arm.result.contains(CHILD_RAN) {
        failures.push(format!(
            "{}: 取り消した後の回で子が走っていない（辺は残しているので走るはず）。拒否: {:?}",
            after.name, arm.denials
        ));
    }
    if arm.result.contains(&plan.secret) {
        failures.push(format!(
            "{}: **宣言を取り消した後も子が目印を読めた。** ①の差の原因が宣言だと言えない。本文:\n{}",
            after.name, arm.result
        ));
    }
    let revoked = acl_sddl(Path::new(&plan.secret_path));
    eprintln!("[widening] 目印の SDDL（取り消して起こし直した後）: {revoked}");
    if count_sid_prefix(&revoked, "S-1-15-3-") != 0 {
        failures.push(format!(
            "宣言を取り消して harness.exe を起こし直しても、目印に capability SID の ACE が残った: {revoked}"
        ));
    }

    let left: Vec<String> = harness_profiles()
        .difference(&profiles_before)
        .cloned()
        .collect();
    if !left.is_empty() {
        failures.push(format!(
            "harness.exe の終了後に AppContainer プロファイルが残った: {left:?}"
        ));
    }

    assert!(
        failures.is_empty(),
        "広げる遷移の強制で{}件の問題（ワークスペース {} と目印 {} を調査のため残す）:\n- {}",
        failures.len(),
        ws.display(),
        marker.display(),
        failures.join("\n- ")
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&marker);
    let _ = std::fs::remove_dir_all(scratch_dir(CASE));
}

/// ⑥の読み方。**入口が届かない回は、子の失敗を数えない**（計器の失敗。判定不能として言う）。
fn judge_network(name: &str, arm: &Arm) -> Vec<String> {
    let mut failures = Vec::new();
    let proxy_of = |tag: &str| {
        let prefix = format!("{tag}:PROXY=");
        arm.result
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
    };
    let entry_proxy = proxy_of("ENTRY");
    let child_proxy = proxy_of("CHILD");
    eprintln!(
        "[widening] {name}: 入口の HTTP_PROXY={entry_proxy:?}／子の HTTP_PROXY={child_proxy:?}"
    );
    if !arm.result.contains("ENTRY:NET_OK 200") {
        failures.push(format!(
            "{name}: 判定不能——**入口のシェルが同じ回に {NET_HOST} へ届いていない**ので、子の失敗が子のドメインの\
             せいだと言えない。本文:\n{}",
            arm.result
        ));
        return failures;
    }
    if arm.result.contains("CHILD:NET_OK") {
        failures.push(format!(
            "{name}: **子（遷移先のドメイン）がセッションのプロキシ経由で {NET_HOST} へ届いた。** 子の通信は\
             閉じていない（事実として記録する。P7 の範囲）。本文:\n{}",
            arm.result
        ));
    }
    if !arm.result.contains("CHILD:NET_FAIL") {
        failures.push(format!(
            "{name}: 子が通信を試した印（CHILD:NET_FAIL）が無い——子が走っていない。本文:\n{}",
            arm.result
        ));
    }
    match (&entry_proxy, &child_proxy) {
        (Some(entry), Some(child)) if !entry.is_empty() && entry == child => {}
        _ => failures.push(format!(
            "{name}: 子が入口と同じプロキシの宛先を知らない（入口 {entry_proxy:?}／子 {child_proxy:?}）——子の失敗が\
             「宛先を知らない」からなのか「届かない」からなのか言えない"
        )),
    }
    failures
}

/// サンドボックスの外（このテストのプロセス）から`example.com`へ届くか。届かなければ⑥は判定不能。
fn reachable_outside_the_sandbox() -> Result<(), String> {
    let script = format!(
        "$ProgressPreference = 'SilentlyContinue'; \
         try {{ $r = Invoke-WebRequest -Uri 'http://{NET_HOST}/' -UseBasicParsing -TimeoutSec 20; \
         Write-Output ('NET_' + 'OK ' + $r.StatusCode) }} \
         catch {{ Write-Output ('NET_' + 'FAIL ' + $_.Exception.Message) }}"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell.exe を起こせない: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("NET_OK 200") {
        Ok(())
    } else {
        Err(text.trim().to_string())
    }
}

/// hostname をサンドボックスの外で1回撃った出力（比べる相手。綴りを推測しない）。
fn hostname_outside_the_sandbox() -> String {
    let exe = system32("hostname.exe");
    let out = Command::new(&exe)
        .output()
        .unwrap_or_else(|e| panic!("{exe} を起こせない: {e}"));
    let text = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_ascii_lowercase();
    assert!(!text.is_empty(), "{exe} の出力が空");
    text
}

// --- 記録と承認 ----------------------------------------------------------------------

/// ①と④の行を続けて1回記録する（記録と強制で同じ行を撃つ）。木に「根 → 中の段」と「根 → cmd」が
/// あることを確かめる（**無ければ収集の失敗**。後の承認と強制の判定の前提が崩れる）。
fn record(ws: &Path, shell: &MiddleShell, plan: &Plan) -> PathBuf {
    let script = Script {
        name: "record-two-children",
        line: format!("{}; {}", plan.child_reads.line, plan.discarding_child.line),
    };
    let (dir, tree) = record_tree(ws, &script, &plan.secret.to_ascii_lowercase());
    let root = scope_root(&tree);
    child_named(&tree.instances, root, &shell.exe);
    child_named(&tree.instances, root, CMD_EXE);
    dir
}

/// 目印を読んだ候補を2つの子のドメインで選び、観測のタブで2つの位置を予約し（cmd の位置は`o`で出力を
/// 捨てる）、`a`→`y`で1回に書く。**どちらの位置も判定器が「広げる」と判定する**ことを確かめる。
fn approve(ws: &Path, shell: &MiddleShell, record_dir: &Path, plan: &Plan) {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    let selected = app.selected_session().expect("記録が選ばれている");
    assert_eq!(
        selected.dir.path(),
        record_dir,
        "選んでいる記録がいま記録したものではない"
    );

    // FS/ネットのタブ: 子のドメインの、目印を読んだ候補（`tui/edit_tests.rs`の`candidate_id`と同じ引き方）。
    let children = [shell.domain.as_str(), CMD_DOMAIN];
    let wanted = wanted_declarations(shell, plan);
    let view = app.view.as_ref().expect("候補の一覧が開いている");
    let mut picked: Vec<(String, String, String)> = Vec::new();
    for (proposal, domain) in view.proposals.iter().zip(&view.domains) {
        let Some(domain) = domain.as_deref() else {
            continue;
        };
        if children.contains(&domain) {
            eprintln!(
                "[widening] 候補: {} [{domain}] {:?} = {}",
                proposal.id, proposal.key, proposal.value
            );
            let value = fold(&proposal.value);
            if wanted.iter().any(|(d, v)| d == domain && v == &value) {
                picked.push((domain.to_string(), value, proposal.id.clone()));
            }
        }
    }
    for (domain, value) in &wanted {
        let ids = picked
            .iter()
            .filter(|(d, v, _)| d == domain && v == value)
            .count();
        assert_eq!(
            ids, 1,
            "ドメイン {domain} の {value} の候補がちょうど1つでない: {picked:?}"
        );
    }
    for (_, _, id) in &picked {
        app.accepted.insert(id.clone());
    }

    // 観測のタブ: 入口から2つの子への位置。
    press(&mut app, KeyCode::F(2));
    let positions = app.pending.positions.as_ref().unwrap_or_else(|| {
        panic!(
            "位置の木が出ていない（観測のタブの注記: {:?}）",
            app.pending.notes
        )
    });
    let rows: Vec<(String, String, String, EdgeVerdict)> = positions
        .visible()
        .iter()
        .map(|row| {
            let position = &positions.view.assignment.positions[row.position];
            (
                position.from_domain.clone(),
                file_name(&position.exe),
                position.to_domain.clone(),
                positions.verdicts[row.position].clone(),
            )
        })
        .collect();
    let mut reserved = Vec::new();
    for (i, (from, exe, to, verdict)) in rows.iter().enumerate() {
        let current = app.pending.positions.as_ref().unwrap();
        assert_eq!(current.row, i, "選択が行を1つずつ下りていない");
        eprintln!("[widening] 位置: {from} --{exe}--> {to} {verdict:?}");
        let ours = from == ENTRY_DOMAIN && (exe == &shell.exe || exe == CMD_EXE);
        if ours {
            assert!(
                matches!(verdict, EdgeVerdict::Widens { .. }),
                "位置 {exe} が「広げる」と判定されていない（子のドメインの読み取りの候補が判定に入っていない？）: {verdict:?}"
            );
            press(&mut app, KeyCode::Char(' '));
            if exe == CMD_EXE {
                assert_eq!(to, CMD_DOMAIN, "cmd の位置のドメインの名前が想定と違う");
                press(&mut app, KeyCode::Char('o'));
            } else {
                assert_eq!(
                    to, &shell.domain,
                    "中の段の位置のドメインの名前が想定と違う"
                );
            }
            reserved.push(exe.clone());
        }
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(
        reserved.len(),
        2,
        "書く位置の数が違う（見えている行: {rows:?}）"
    );
    let positions = app.pending.positions.as_ref().unwrap();
    assert_eq!(
        positions.approve.len(),
        2,
        "予約の数が押した数と違う: {}",
        app.status
    );
    assert_eq!(
        positions.discard_output.len(),
        1,
        "出力を捨てる予約が cmd の1つでない: {}",
        app.status
    );

    press(&mut app, KeyCode::Char('a'));
    let modal = app
        .modal
        .as_ref()
        .unwrap_or_else(|| panic!("確認ダイアログが出ない: {}", app.status));
    assert_eq!(modal.confirm, Confirm::Position);
    eprintln!("[widening] 確認ダイアログ:\n{}", modal.lines.join("\n"));
    let count = |needle: &str| modal.lines.iter().filter(|l| l.contains(needle)).count();
    assert_eq!(
        count("広がる遷移 2本"),
        1,
        "明細に広がる遷移2本が出ていない"
    );
    assert_eq!(
        count("出力を返すので、子が読めるものは呼び出し元へ渡ります"),
        1
    );
    assert_eq!(count("子の出力は捨てる設定です"), 1);
    press(&mut app, KeyCode::Char('y'));
    assert!(app.modal.is_none(), "y でダイアログが閉じない");
    eprintln!("[widening] 確定の後: {}", app.status);
    assert!(
        app.pending
            .positions
            .as_ref()
            .is_some_and(|p| p.approve.is_empty()),
        "書いた予約が残っている（書けなかった？）: {}",
        app.status
    );
}

/// `policy.json`に書かれた辺と宣言が、承認したとおりか（入口から2本・出力の設定・子のドメインの目印）。
fn check_written(ws: &Path, shell: &MiddleShell, plan: &Plan) {
    let file = policy_file::load(ws).expect("policy.json を読める");
    let entry = file.domain(ENTRY_DOMAIN).expect("入口のドメイン");
    let mut edges: Vec<(String, String, ChildOutput)> = entry
        .process
        .transitions
        .iter()
        .map(|edge| {
            let exe = match &edge.exe {
                ExeMatcher::Literal(path) => file_name(path),
                other => panic!("エディタがリテラルでない辺を書いた: {other:?}"),
            };
            (exe, edge.to.clone(), edge.output)
        })
        .collect();
    // `ChildOutput`は順序を持たないので、実行ファイル名で並べる。
    edges.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = vec![
        (
            CMD_EXE.to_string(),
            CMD_DOMAIN.to_string(),
            ChildOutput::Discard,
        ),
        (shell.exe.clone(), shell.domain.clone(), ChildOutput::Return),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(edges, expected, "入口のドメインの辺が承認したとおりでない");
    let secret = fold(&plan.secret_path);
    for (child, value) in wanted_declarations(shell, plan) {
        let domain = file
            .domain(&child)
            .unwrap_or_else(|| panic!("ドメイン {child} が無い"));
        let declared: Vec<&String> = domain
            .fs
            .read
            .iter()
            .chain(&domain.fs.read_write)
            .chain(&domain.fs.read_exec)
            .collect();
        eprintln!("[widening] ドメイン {child} の宣言: {declared:?}");
        assert!(
            declared.iter().any(|v| fold(v) == value),
            "ドメイン {child} に {value} の宣言が無い: {declared:?}"
        );
    }
    assert!(
        file.domain(ENTRY_DOMAIN).is_some_and(|d| !d
            .fs
            .read
            .iter()
            .chain(&d.fs.read_write)
            .any(|v| fold(v) == secret)),
        "入口のドメインに目印の宣言がある（②の対照が成り立たない）"
    );
}

/// 子のドメインごとに承認する宣言（ドメイン, 畳んだ値）。どちらの子も目印のファイルを読む。
///
/// **cmd には目印のディレクトリ（そのオブジェクト1個。D-63）も足す。** `type`は引数をワイルドカードとして
/// 展開するのでディレクトリを一覧してから開く（2026-10-06の1回目の実測: ファイルだけを承認すると、cmd は
/// 走って`ran.txt`を作るが中身が空だった。記録も cmd についてだけ目印のディレクトリの読み取りを観測している）。
/// PowerShell の`Get-Content -LiteralPath`はファイルを直に開くので要らない。
fn wanted_declarations(shell: &MiddleShell, plan: &Plan) -> Vec<(String, String)> {
    let secret = fold(&plan.secret_path);
    let marker_dir = format!("{}/", fold(&marker_dir().to_string_lossy()));
    vec![
        (shell.domain.clone(), secret.clone()),
        (CMD_DOMAIN.to_string(), secret),
        (CMD_DOMAIN.to_string(), marker_dir),
    ]
}
