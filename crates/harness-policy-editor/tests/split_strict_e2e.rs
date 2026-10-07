//! 引数を固定した位置の分割と Strict の辺（決定67）の昇格E2E。**エディタの`u`でコマンドラインごとに分けた辺と、
//! `s`で書いた Strict の辺が、`harness.exe --enforce-transitions`の下で意図どおりに効くか**を本番の経路で確かめる
//! （`plans/position-domains/P5.md`の Task P5.10.3）。**管理者権限が要る**（パス1の収集器が張る ETW の
//! リアルタイムセッションと、Tier2a の準備が付ける祖先 traverse・宣言の ACE のため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-split-strict`。事前に`cargo build --workspace`と
//! `cargo build -p harness-cli --features e2e-mock`（手順と、違うビルドを黙って撃たない確かめは
//! `position_domains_e2e.rs`と同じ。部品は[`common`]）。
//!
//! # 何を測るのか
//!
//! 決定67は2つの困りごとを解いた。(1) 位置は（親のドメイン, 実行ファイル）で決まるので、同じインタプリタで
//! 別のスクリプトを動かすと全部のスクリプトの権限が1つのドメインに集まる——引数を記録どおりに固定した位置は、
//! コマンドラインごとに辺もドメインも分ける。(2) Strict の辺（引数のリテラル＋作業ディレクトリの宣言）を
//! エディタで書けなかった——`s`と`w`で書く。単体試験は割り当て・書く辺の形・判定器の答えを見ている。
//! この試験は、書いた辺を **Spawn Daemon と OS が実際に強制するか**を測る。
//!
//! # 書く辺（パス1で1回記録し、エディタの画面で`u`で分け、1行を`s`で Strict にして承認する）
//!
//! ```text
//! 入口のシェル（workspace-shell）─ powershell -File <ws>\scripts\a.ps1      → powershell-a: a の目印を読める
//!                                ├ powershell -File <ws>\scripts\b.ps1      → powershell-b: b の目印を読める
//!                                └ powershell -File <Strict の置き場>\s.ps1 → powershell-s（Strict）: s の目印と
//!                                                                             s.ps1 を読める。作業ディレクトリ＝置き場
//! ```
//!
//! - 3つの起動は**同じ親（入口）から同じ実行ファイル**なので、分けなければ1つの位置（ドメイン`powershell`）になる。
//!   `u`で3行（`<葉名>-<スクリプトの語幹>`）に分かれ、各行の辺は記録したコマンドラインのリテラルを持つ
//! - スクリプトは**絶対パスで呼ぶ**（相対パスで記録すると、分けた行は規則(d)で作業ディレクトリの宣言が要る。
//!   P5.10.2 の記録）
//! - 目印のファイルは**ワークスペースの外**（[`marker_dir`]）——遷移先のドメインはどれもワークスペースを
//!   見られる（`domain_provision.rs`の共通の土台）ので、分けたことの差はワークスペースの外でしか測れない
//! - Strict の置き場（[`strict_dir`]）は`C:\`直下——呼び出し元（入口のドメイン）が書けない場所でないと`s`が断る
//!   （規則(i)。前例は`spawn-daemon`の`fixed_input_tests`の`strict_cwd`）。ワークスペースや`%TEMP%`の下は使えない
//!
//! # 腕（`B-35`: 通る側と断る側、測りたい差だけを変えた対照を同じ回で）
//!
//! | 腕 | 行 | 期待 |
//! |---|---|---|
//! | ① a | 入口が環境変数を置き、印を流し込んで a.ps1 | a が走り a の目印を返す・b の目印は読めない・印（標準入力）と環境変数が届く・拒否0件 |
//! | ② b（対照） | 入口が b.ps1 | b が走り b の目印を返す・**a の目印は読めない**（①で a が読めた同じファイル）・拒否0件 |
//! | ③ 記録に無いスクリプト | 入口が c.ps1（同じ powershell.exe） | `pending.jsonl`に（入口, powershell.exe, `no_matching_edge`）がちょうど1件・c は走らない |
//! | ④ Strict・移って呼ぶ | 入口が環境変数を置き、宣言した場所へ`Set-Location`してから印を流し込んで s.ps1 | s が走り s の目印を返す・作業ディレクトリは宣言の場所・**標準入力も入口の環境変数も届かない**・拒否0件 |
//! | ⑤ Strict・移らずに呼ぶ | 入口が同じ s.ps1 をワークスペースから | `pending.jsonl`に（入口, powershell.exe, `cwd_mismatch`〔宣言＝置き場・実際＝ワークスペース〕）がちょうど1件・s は走らない |
//!
//! ①の「標準入力と環境変数が届く」は④の対照である（普通の辺では届き、Strict の辺では届かない。決定66(3)(5)と追記）。
//!
//! # 後始末（`test-logic-rules`の型F。製品の経路で戻す）
//!
//! 承認した宣言はエディタの CLI の`unapprove --all`で3つのドメインとも取り消し、`harness.exe`をもう一度起こして剥がす
//! （`widening_transitions_e2e.rs`と同じ流れ）。取り消した後の回で a が自分の目印を読めなくなること（①の差の原因が
//! 宣言だったこと）と、目印・s.ps1 の DACL に capability SID の ACE が残っていないことを見る。最後に、`harness.exe`が
//! 作った AppContainer プロファイルが撃つ前より増えていないことを見る。
//!
//! # 言えないこと
//!
//! - 中の段は PowerShell 5.1 だけ（この機の`pwsh`はストアアプリで遷移先にできない。P4.8・P5.7 と同じ）
//! - Strict の辺の作業ディレクトリは候補（絶対パスのスクリプトのフォルダ）のまま書く。`w`で直す経路と、相対パスの
//!   スクリプトの推定の候補は単体試験（`tui/position_strict_tests.rs`）だけが見る
//! - 分けた位置の下の段（分けたドメインから先の起動）は撃っていない（単体試験
//!   `the_descendants_of_a_split_position_start_from_the_split_domain`だけ）
//!
//! # ワークスペースの置き場
//!
//! `C:\harness-e2e\policy-editor-split-strict`、目印は`C:\harness-e2e\_split-marker`、Strict の置き場は
//! `C:\harness-Tier2a-verify-p5-10-strict`（どれも`%TEMP%`の外。BUG-103）。緑なら消し、赤なら調査のため残す。

#![cfg(windows)]

mod common;

use std::path::{Path, PathBuf};

use crossterm::event::KeyCode;
use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::process_event::{ArgvBinding, ProcessAuditLog};
use harness_policy::transition::{ArgvMatcher, ExeMatcher, TransitionDenial};
use harness_policy_editor::position_view::EdgeVerdict;
use harness_policy_editor::tui::state::{App, Confirm};
use harness_sandbox::tier2a::spawnd::transitions::{
    pending_path, read_from, Denial, PendingRecord,
};
use harness_sandbox::tier2a::spawnd::DenyReason;

use common::{
    acl_sddl, case_dir, count_sid_prefix, expect_no_denials, file_name, fold, harness_exe,
    harness_profiles, middle_shell, nonce, press, record_tree, run_arm, scope_root, scratch_dir,
    unapprove_all, Arm, MiddleShell, Script, CASE_ROOT,
};

/// ワークスペースの名前。
const CASE: &str = "policy-editor-split-strict";
/// 子が走ったことの印の接頭辞（`A_RAN`等。スクリプトの中では`'A_' + 'RAN'`と割って書く）。
const RAN: &str = "_RAN";
/// 子が標準入力の各行の頭に付ける印（`widening_transitions_e2e.rs`の③と同じ）。
const ECHO_PREFIX: &str = "GOT:";
/// 入口が置き、子が印字する環境変数の名前。
const CALLER_ENV: &str = "P510_CALLER";

/// 目印のファイルの置き場（**ワークスペースの外**。名前をワークスペースの名前で始めない——前方一致で含んでしまう）。
fn marker_dir() -> PathBuf {
    Path::new(CASE_ROOT).join("_split-marker")
}

/// Strict の辺のスクリプトと作業ディレクトリの置き場。**呼び出し元が書けない場所**（`C:\`直下。入口のドメインの
/// package SID にも workspace capability にも ACE を付けない）。前例は`fixed_input_tests`の`strict_cwd`
/// （`C:\harness-Tier2a-verify-<label>-<pid>`）。名前に pid を入れないのは、祖先 traverse の台帳の行を回ごとに
/// 増やさないため（P5.7 の目印の置き場`_widening-marker`と同じ。直列化の印で同時に2回は撃たない）。
fn strict_dir() -> PathBuf {
    PathBuf::from(r"C:\harness-Tier2a-verify-p5-10-strict")
}

/// 1つのスクリプト（置き場・目印・割り当てで付くドメインの名前）。
struct Job {
    /// `A`・`B`・`S`（印の接頭辞）。
    tag: &'static str,
    script: PathBuf,
    secret_path: PathBuf,
    /// 目印のファイルの中身（**どの行にもスクリプトにも綴りとして現れない**）。
    secret: String,
    /// `u`で分けた行のドメインの名前（`<葉名>-<語幹>`）。
    domain: String,
}

/// 撃つ行と、それぞれの期待に使う印。
struct Plan {
    a: Job,
    b: Job,
    s: Job,
    /// 記録しないスクリプト（③）。
    c_script: PathBuf,
    stdin_a: String,
    stdin_s: String,
    caller_env: String,
    a_runs: Script,
    b_runs: Script,
    c_runs: Script,
    s_from_its_dir: Script,
    s_from_elsewhere: Script,
}

fn job(tag: &'static str, dir: &Path, shell: &MiddleShell, nonce: &str) -> Job {
    let stem = tag.to_ascii_lowercase();
    Job {
        tag,
        script: dir.join(format!("{stem}.ps1")),
        secret_path: marker_dir().join(format!("{stem}-secret.txt")),
        secret: format!("SPLIT_SECRET_{tag}_{nonce}"),
        domain: format!("{}-{stem}", shell.domain),
    }
}

/// 中の段のシェルにスクリプトを絶対パスで走らせる綴り。PowerShell は子のコマンドラインを
/// `"<exe>" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script>`の形に組む（パス1の`pwsh`と
/// 強制の 5.1 で同じ綴りになることを 2026-10-07 に外で確かめた）。`-ExecutionPolicy Bypass`が無いと既定の
/// 実行ポリシーでスクリプトが走らない。
fn run_script(shell: &MiddleShell, script: &Path) -> String {
    format!(
        "& '{}' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '{}'",
        shell.path,
        script.display()
    )
}

fn plan(shell: &MiddleShell, ws: &Path) -> Plan {
    let nonce = nonce();
    let scripts = ws.join("scripts");
    let a = job("A", &scripts, shell, &nonce);
    let b = job("B", &scripts, shell, &nonce);
    let s = job("S", &strict_dir(), shell, &nonce);
    let c_script = scripts.join("c.ps1");
    let stdin_a = format!("SPLIT_STDIN_A_{nonce}");
    let stdin_s = format!("SPLIT_STDIN_S_{nonce}");
    let caller_env = format!("SPLIT_CALLER_{nonce}");
    let set_env = format!("$env:{CALLER_ENV} = '{caller_env}'");
    let strict = strict_dir().display().to_string();
    Plan {
        a_runs: Script {
            name: "1-a-reads-its-own-marker",
            line: format!("{set_env}; '{stdin_a}' | {}", run_script(shell, &a.script)),
        },
        b_runs: Script {
            name: "2-b-cannot-read-a",
            line: run_script(shell, &b.script),
        },
        c_runs: Script {
            name: "3-unrecorded-script",
            line: run_script(shell, &c_script),
        },
        s_from_its_dir: Script {
            name: "4-strict-from-the-declared-cwd",
            line: format!(
                "{set_env}; Set-Location -LiteralPath '{strict}'; '{stdin_s}' | {}",
                run_script(shell, &s.script)
            ),
        },
        s_from_elsewhere: Script {
            name: "5-strict-from-elsewhere",
            line: format!("{set_env}; '{stdin_s}' | {}", run_script(shell, &s.script)),
        },
        a,
        b,
        s,
        c_script,
        stdin_a,
        stdin_s,
        caller_env,
    }
}

/// スクリプトの本文。走った印・作業ディレクトリ・入口の環境変数を印字し、自分の目印（と、あれば他の目印）を読み、
/// 最後に標準入力を`GOT:`付きで返す。**標準入力を読むのは、呼び出す行が必ず印を流し込むスクリプトだけ**——
/// 流し込まない行で読むと、受け継いだ入口の標準入力で止まり得る。
///
/// **標準入力は`$input`ではなく`[Console]::In`で読む**（2026-10-07の1回目の実測）。Strict の辺の子は標準入力に
/// 無効なハンドル（`INVALID_HANDLE_VALUE`）を受け取り、Windows PowerShell 5.1 は`$input`を使う`-File`の
/// スクリプトを**起動の時点で**`ハンドルが無効です。パラメーター名:handle`（終了コード1）で落とす——スクリプトの
/// 1行目も走らない。サンドボックスの外で同じハンドルを渡して再現した（`$input`を使わないスクリプトは走る・`NUL`を
/// 渡せば`$input`も空で走る）。Strict の辺の子に PowerShell の`$input`が使えないことは`docs/STATUS.md`へ残し、
/// ここは「届いたか」だけを、無効なハンドルでも空を返す`[Console]::In`で測る（普通の辺の①と同じ読み方で、④の対照になる）。
fn script_body(job: &Job, other: Option<&Job>, reads_stdin: bool) -> String {
    let tag = job.tag;
    let mut lines = vec![
        format!("Write-Output ('{tag}_' + 'RAN')"),
        "Write-Output ('CWD=' + [Environment]::CurrentDirectory)".to_string(),
        format!("Write-Output ('ENV=' + $env:{CALLER_ENV})"),
        format!(
            "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop }} catch {{ Write-Output ('{tag}_OWN_' + 'FAIL ' + $_.Exception.Message) }}",
            job.secret_path.display()
        ),
    ];
    if let Some(other) = other {
        lines.push(format!(
            "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop }} catch {{ Write-Output ('{tag}_OTHER_' + 'FAIL ' + $_.Exception.Message) }}",
            other.secret_path.display()
        ));
    }
    if reads_stdin {
        lines.push(format!(
            "try {{ [Console]::In.ReadToEnd() -split \"`r?`n\" | Where-Object {{ $_ }} | ForEach-Object {{ 'GOT:' + $_ }} }} catch {{ Write-Output ('{tag}_STDIN_' + 'ERR ' + $_.Exception.Message) }}"
        ));
    }
    lines.join("\r\n") + "\r\n"
}

/// 目印・スクリプトの置き場を作り直す（前の回の残りを今回の証拠として読まない）。
fn lay_out(plan: &Plan) {
    for dir in [marker_dir(), strict_dir()] {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("{} を作れない: {e}", dir.display()));
    }
    std::fs::create_dir_all(plan.a.script.parent().unwrap()).expect("create scripts dir");
    for job in [&plan.a, &plan.b, &plan.s] {
        std::fs::write(&job.secret_path, &job.secret).expect("write marker file");
    }
    std::fs::write(&plan.a.script, script_body(&plan.a, Some(&plan.b), true)).unwrap();
    std::fs::write(&plan.b.script, script_body(&plan.b, Some(&plan.a), false)).unwrap();
    std::fs::write(&plan.s.script, script_body(&plan.s, None, true)).unwrap();
    std::fs::write(&plan.c_script, "Write-Output ('C_' + 'RAN')\r\n").unwrap();
}

#[test]
#[ignore = "requires administrator rights (records pass 1 with the ETW collector and runs harness.exe with --enforce-transitions); run through dev-elevated-run"]
fn split_rows_give_each_script_its_own_domain_and_a_strict_row_runs_only_from_its_declared_cwd() {
    let harness = harness_exe();
    let shell = middle_shell();
    let ws = case_dir(CASE);
    std::fs::create_dir_all(ws.join(".harness").join("sandbox")).unwrap();
    let plan = plan(&shell, &ws);
    lay_out(&plan);
    let mut failures: Vec<String> = Vec::new();

    // 基準線（作り直した直後なので capability SID の ACE は無いはず。`widening_transitions_e2e.rs`と同じ）。
    let watched = watched_files(&plan);
    for path in &watched {
        let sddl = acl_sddl(path);
        assert_eq!(
            count_sid_prefix(&sddl, "S-1-15-3-"),
            0,
            "前提: 作り直した {} に capability SID の ACE があってはならない: {sddl}",
            path.display()
        );
    }

    // --- 1・2. 記録して、分けて、Strict にして承認する ---------------------------------------
    let record_dir = record(&ws, &shell, &plan);
    let fixed = approve(&ws, &shell, &record_dir, &plan);
    check_written(&ws, &shell, &plan, &fixed);

    // --- 3. harness.exe --enforce-transitions で撃つ ---------------------------------------
    let profiles_before = harness_profiles();

    // ① a は自分の目印だけを読める。標準入力と入口の環境変数が届く（普通の辺。④の対照）。
    let arm = run_arm(&harness, &ws, CASE, &plan.a_runs);
    arm.print(plan.a_runs.name);
    expect_ran(&mut failures, plan.a_runs.name, &arm, &plan.a);
    expect_reads_own_marker(&mut failures, plan.a_runs.name, &arm, &plan.a);
    expect_cannot_read(&mut failures, plan.a_runs.name, &arm, &plan.a, &plan.b);
    match echoed_line(&arm, &plan.stdin_a) {
        Some(line) => eprintln!("[split-strict] {}: 子が返した行 {line:?}", plan.a_runs.name),
        None => failures.push(format!(
            "{}: 普通の辺の子に標準入力の印が届いていない（{ECHO_PREFIX} で始まり {} を含む行が無い）。本文:\n{}",
            plan.a_runs.name, plan.stdin_a, arm.result
        )),
    }
    match env_line(&arm) {
        Some(line) if line.contains(&plan.caller_env) => {}
        other => failures.push(format!(
            "{}: 普通の辺の子に入口の環境変数 {CALLER_ENV} が届いていない（決定66(5)は呼び出し元＋差分）: {other:?}",
            plan.a_runs.name
        )),
    }
    expect_no_denials(&mut failures, plan.a_runs.name, &arm);
    // 宣言が実 DACL へ付いたこと（型A: 設定ではなく結果を見る）。package SID 宛ては0本のまま（残課題#20）。
    let granted = acl_sddl(&plan.a.secret_path);
    eprintln!("[split-strict] a の目印の SDDL（①の後）: {granted}");
    if count_sid_prefix(&granted, "S-1-15-3-") == 0 || count_sid_prefix(&granted, "S-1-15-2-") != 0
    {
        failures.push(format!(
            "①の後の a の目印に宣言の capability SID の ACE が無い、または package SID の ACE がある: {granted}"
        ));
    }

    // ② 対照: b は自分の目印を読めるが、①で a が読めた a の目印は読めない（分けたので a の権限が b に無い）。
    let arm = run_arm(&harness, &ws, CASE, &plan.b_runs);
    arm.print(plan.b_runs.name);
    expect_ran(&mut failures, plan.b_runs.name, &arm, &plan.b);
    expect_reads_own_marker(&mut failures, plan.b_runs.name, &arm, &plan.b);
    expect_cannot_read(&mut failures, plan.b_runs.name, &arm, &plan.b, &plan.a);
    expect_no_denials(&mut failures, plan.b_runs.name, &arm);

    // ③ 記録に無いスクリプト（同じ powershell.exe・同じ親）は、分けた辺のどれにも当たらない。
    let arm = run_arm(&harness, &ws, CASE, &plan.c_runs);
    arm.print(plan.c_runs.name);
    expect_one_denial(
        &mut failures,
        plan.c_runs.name,
        &ws,
        &shell,
        |denial| matches!(denial, TransitionDenial::NoMatchingEdge),
        "no_matching_edge",
    );
    if arm.result.contains(&format!("C{RAN}")) {
        failures.push(format!(
            "{}: 断られるはずの c.ps1 が走った。本文:\n{}",
            plan.c_runs.name, arm.result
        ));
    }

    // ④ Strict の辺: 宣言した場所へ移って呼ぶと通る。標準入力と入口の環境変数は届かない。
    let arm = run_arm(&harness, &ws, CASE, &plan.s_from_its_dir);
    arm.print(plan.s_from_its_dir.name);
    expect_ran(&mut failures, plan.s_from_its_dir.name, &arm, &plan.s);
    expect_reads_own_marker(&mut failures, plan.s_from_its_dir.name, &arm, &plan.s);
    let cwd = arm
        .result
        .lines()
        .find_map(|line| line.trim().strip_prefix("CWD=").map(str::to_string));
    if cwd.as_deref().map(fold) != Some(fold(&strict_dir().display().to_string())) {
        failures.push(format!(
            "{}: Strict の辺の子の作業ディレクトリが宣言の場所（{}）でない: {cwd:?}",
            plan.s_from_its_dir.name,
            strict_dir().display()
        ));
    }
    if arm.result.contains(plan.stdin_s.as_str()) {
        failures.push(format!(
            "{}: **Strict の辺の子に標準入力の印が届いた。** Strict の辺は標準入力を断つ（決定66の追記・BUG-161）。本文:\n{}",
            plan.s_from_its_dir.name, arm.result
        ));
    }
    match env_line(&arm) {
        Some(line) if !line.contains(&plan.caller_env) => {
            eprintln!("[split-strict] {}: 子の {line:?}", plan.s_from_its_dir.name)
        }
        other => failures.push(format!(
            "{}: Strict の辺の子に入口の環境変数が届いた、または子が印字していない（Strict は基準＋差分。決定66の追記）: {other:?}",
            plan.s_from_its_dir.name
        )),
    }
    expect_no_denials(&mut failures, plan.s_from_its_dir.name, &arm);

    // ⑤ Strict の辺: 移らずに（ワークスペースから）呼ぶと、宣言と違う作業ディレクトリとして断る（決定67(4)）。
    let arm = run_arm(&harness, &ws, CASE, &plan.s_from_elsewhere);
    arm.print(plan.s_from_elsewhere.name);
    let declared = fold(&strict_dir().display().to_string());
    let actual = fold(&ws.display().to_string());
    expect_one_denial(
        &mut failures,
        plan.s_from_elsewhere.name,
        &ws,
        &shell,
        |denial| {
            matches!(denial, TransitionDenial::CwdMismatch { declared: d, actual: a }
                if fold(d) == declared && fold(a).trim_end_matches('/') == actual)
        },
        "cwd_mismatch（宣言＝Strict の置き場・実際＝ワークスペース）",
    );
    if arm.result.contains(&format!("S{RAN}")) {
        failures.push(format!(
            "{}: 宣言と違う作業ディレクトリから呼んだ Strict の辺の子が走った。本文:\n{}",
            plan.s_from_elsewhere.name, arm.result
        ));
    }

    // --- 4. 後始末: 宣言を取り消して起こし直す（製品の経路で剥がす） ----------------------
    for job in [&plan.a, &plan.b, &plan.s] {
        unapprove_all(&ws, &job.domain);
    }
    let after = Script {
        name: "6-a-after-unapprove",
        line: plan.a_runs.line.clone(),
    };
    let arm = run_arm(&harness, &ws, CASE, &after);
    arm.print(after.name);
    expect_ran(&mut failures, after.name, &arm, &plan.a);
    if arm.result.contains(&plan.a.secret) {
        failures.push(format!(
            "{}: **宣言を取り消した後も a が自分の目印を読めた。** ①の差の原因が宣言だと言えない。本文:\n{}",
            after.name, arm.result
        ));
    }
    for path in &watched {
        let sddl = acl_sddl(path);
        eprintln!(
            "[split-strict] {} の SDDL（取り消して起こし直した後）: {sddl}",
            path.display()
        );
        if count_sid_prefix(&sddl, "S-1-15-3-") != 0 {
            failures.push(format!(
                "宣言を取り消して harness.exe を起こし直しても、{} に capability SID の ACE が残った: {sddl}",
                path.display()
            ));
        }
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
        "分けた辺と Strict の辺の強制で{}件の問題（ワークスペース {}・目印 {}・Strict の置き場 {} を調査のため残す）:\n- {}",
        failures.len(),
        ws.display(),
        marker_dir().display(),
        strict_dir().display(),
        failures.join("\n- ")
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(marker_dir());
    let _ = std::fs::remove_dir_all(strict_dir());
    let _ = std::fs::remove_dir_all(scratch_dir(CASE));
}

/// DACL を見張るファイル（3つの目印と、Strict の辺のスクリプト）。
fn watched_files(plan: &Plan) -> Vec<PathBuf> {
    vec![
        plan.a.secret_path.clone(),
        plan.b.secret_path.clone(),
        plan.s.secret_path.clone(),
        plan.s.script.clone(),
    ]
}

fn expect_ran(failures: &mut Vec<String>, name: &str, arm: &Arm, job: &Job) {
    if !arm.result.contains(&format!("{}{RAN}", job.tag)) {
        failures.push(format!(
            "{name}: **子（{}）が走っていない。** 拒否: {:?}／本文:\n{}",
            job.domain, arm.denials, arm.result
        ));
    }
}

fn expect_reads_own_marker(failures: &mut Vec<String>, name: &str, arm: &Arm, job: &Job) {
    if !arm.result.contains(&job.secret) {
        failures.push(format!(
            "{name}: 子（{}）が自分の目印 {} を返していない（ドメインの宣言が子に付いていない？）。本文:\n{}",
            job.domain,
            job.secret_path.display(),
            arm.result
        ));
    }
}

/// `job`の子が`other`の目印を読めない（中身が返らず、読もうとして失敗した印がある）。
fn expect_cannot_read(failures: &mut Vec<String>, name: &str, arm: &Arm, job: &Job, other: &Job) {
    if arm.result.contains(&other.secret) {
        failures.push(format!(
            "{name}: **{} の子が {} の目印を読めた。** 分けたドメインに別のスクリプトの権限が入っている。本文:\n{}",
            job.domain, other.domain, arm.result
        ));
    }
    let tried = format!("{}_OTHER_FAIL", job.tag);
    match arm.result.lines().find(|line| line.contains(&tried)) {
        Some(line) => eprintln!("[split-strict] {name}: {}", line.trim()),
        None => failures.push(format!(
            "{name}: {} の子が {} の目印を読もうとして失敗した印（{tried}）が無い——読めなかったのか読まなかったのか言えない",
            job.domain, other.domain
        )),
    }
}

/// `GOT:`で始まり`marker`を含む行（`GOT:`と印のあいだに BOM の2文字が挟まる。`widening_transitions_e2e.rs`の③）。
fn echoed_line<'a>(arm: &'a Arm, marker: &str) -> Option<&'a str> {
    arm.result
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(ECHO_PREFIX) && line.contains(marker))
}

fn env_line(arm: &Arm) -> Option<String> {
    arm.result
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("ENV="))
        .map(str::to_string)
}

/// 待ち行列に、入口のドメインから中の段の実行ファイルを断った記録がちょうど1種類あり、理由が`expected`に当たる。
///
/// **呼び出し元の PowerShell 5.1 の再試行は数えない。** 5.1 は外部プログラムの起動が失敗すると、実行ファイルを
/// 引数の先頭へ重ねたコマンドライン（`"<exe>" "<exe>" -NoProfile …`）でもう一度起こそうとする
/// （`NativeCommandProcessor`の`FindExecutable`による再試行）。その2回目は記録したコマンドラインと違うので
/// `no_matching_edge`で断られ、待ち行列にもう1種類載る（2026-10-07の実測: ⑤で`cwd_mismatch`の後に
/// `no_matching_edge`。2回目の実測で生の行を出し、実行ファイルが重なっていることを確かめた）。続く3回目
/// （`ShellExecute`での再試行）は元のコマンドラインなので、最初の種類の回数が2へ上がる。生の行を全部出したうえで、
/// **実行ファイルが2回現れる`no_matching_edge`の行だけ**を外し、種類ごとに数える。
fn expect_one_denial(
    failures: &mut Vec<String>,
    name: &str,
    ws: &Path,
    shell: &MiddleShell,
    expected: impl Fn(&TransitionDenial) -> bool,
    what: &str,
) {
    let tail = read_from(&pending_path(ws), 0);
    let mut primary = Vec::new();
    for record in &tail.records {
        let PendingRecord::DeniedByDaemon(denial) = record else {
            failures.push(format!(
                "{name}: Daemon の拒否でない行が積まれた: {record:?}"
            ));
            continue;
        };
        let retry = is_powershell_retry(denial, shell);
        eprintln!(
            "[split-strict] {name}: 待ち行列の行{}: from={:?} exe={:?} reason={:?} argv={:?} cwd={:?} count={}",
            if retry { "（PowerShell 5.1 の再試行）" } else { "" },
            denial.from_domain,
            denial.exe,
            denial.reason,
            denial.argv,
            denial.cwd,
            denial.count
        );
        if retry {
            continue;
        }
        // 同じ種類の2行目以降は回数を上げた更新行（待ち行列の畳み方）。種類ごとに最後の行だけを残す。
        match primary.iter().position(|seen: &&Denial| {
            seen.from_domain == denial.from_domain
                && seen.exe == denial.exe
                && seen.argv == denial.argv
                && seen.reason == denial.reason
        }) {
            Some(at) => primary[at] = denial,
            None => primary.push(denial),
        }
    }
    let ok = match primary.as_slice() {
        [denial] => {
            denial.from_domain.as_deref() == Some(ENTRY_DOMAIN)
                && file_name(&denial.exe) == shell.exe
                && matches!(&denial.reason, DenyReason::Transition { denial } if expected(denial))
        }
        _ => false,
    };
    if !ok {
        failures.push(format!(
            "{name}: 断った記録（再試行を除く）が期待（{ENTRY_DOMAIN} から {} を {what}）とちょうど1件で一致しない: {primary:?}",
            shell.exe
        ));
    }
}

/// PowerShell 5.1 の起動の再試行（[`expect_one_denial`]の doc）: `no_matching_edge`で、コマンドラインに実行ファイルが2回現れる。
fn is_powershell_retry(denial: &Denial, shell: &MiddleShell) -> bool {
    matches!(
        denial.reason,
        DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge
        }
    ) && fold(&denial.argv).matches(shell.exe.as_str()).count() >= 2
}

// --- 記録と承認 ----------------------------------------------------------------------

/// 3つのスクリプトを続けて1回記録する（強制の①④と同じ行。③の c は記録しない）。木に根の子として
/// 3つの`powershell.exe`があり、それぞれのコマンドラインが自分のスクリプトを持つことを確かめる
/// （**無ければ収集の失敗**。後の分割の前提が崩れる）。
fn record(ws: &Path, shell: &MiddleShell, plan: &Plan) -> PathBuf {
    let script = Script {
        name: "record-three-scripts",
        line: format!(
            "{}; {}; {}",
            plan.a_runs.line, plan.b_runs.line, plan.s_from_its_dir.line
        ),
    };
    let (dir, tree) = record_tree(ws, &script, &plan.a.secret.to_ascii_lowercase());
    for job in [&plan.a, &plan.b, &plan.s] {
        recorded_command_line(&tree, shell, &job.script);
    }
    dir
}

/// 根の子のうち、実行ファイルが中の段で、コマンドラインが`script`を含むもの（無ければ落とす）。
fn recorded_command_line(tree: &ProcessAuditLog, shell: &MiddleShell, script: &Path) -> String {
    let root = scope_root(tree);
    let wanted = fold(&script.display().to_string());
    tree.instances
        .iter()
        .filter(|i| i.parent_seq == Some(root.seq))
        .filter(|i| i.image_path.as_deref().map(file_name).as_deref() == Some(shell.exe.as_str()))
        .find_map(|i| match &i.argv {
            ArgvBinding::Exact { command_line, .. } if fold(command_line).contains(&wanted) => {
                Some(command_line.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "木に {wanted} を走らせた {} が根の子として無い（または引数が結び付いていない）——収集の失敗",
                shell.exe
            )
        })
}

/// 見えている行の（遷移元, 実行ファイル名, 遷移先, 固定したコマンドライン, 判定, 選んでいるか）。
type Row = (String, String, String, Option<String>, EdgeVerdict, bool);

fn rows(app: &App) -> Vec<Row> {
    let positions = app.pending.positions.as_ref().expect("位置の木");
    positions
        .visible()
        .iter()
        .map(|row| {
            let position = &positions.view.assignment.positions[row.position];
            (
                position.from_domain.clone(),
                file_name(&position.exe),
                positions.destination_name(position).to_string(),
                position.fixed_command_line.clone(),
                positions.verdicts[row.position].clone(),
                positions.is_reserved(position),
            )
        })
        .collect()
}

/// `pick`に当たる行を選ぶ（**分けると行の並びと選択が変わるので、行は名前で選ぶ**。`position_split_tests::select_to`と同じ）。
fn select(app: &mut App, pick: impl Fn(&Row) -> bool) {
    let index = rows(app)
        .iter()
        .position(pick)
        .unwrap_or_else(|| panic!("選ぶ行が無い: {:#?}", rows(app)));
    app.pending.positions.as_mut().expect("位置の木").row = index;
}

/// 観測のタブで入口 → 中の段の位置を`Space`→`u`で3行に分け、分けたドメインの目印（s はスクリプトも）の候補を選び、
/// s の行を`s`で Strict にして、`a`→`y`で1回に書く。分けた行の（遷移先 → 固定したコマンドライン）を返す。
fn approve(
    ws: &Path,
    shell: &MiddleShell,
    record_dir: &Path,
    plan: &Plan,
) -> Vec<(String, String)> {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    let selected = app.selected_session().expect("記録が選ばれている");
    assert_eq!(
        selected.dir.path(),
        record_dir,
        "選んでいる記録がいま記録したものではない"
    );
    press(&mut app, KeyCode::F(2));
    eprintln!("[split-strict] 分ける前の行: {:#?}", rows(&app));
    let ours = |row: &Row| row.0 == ENTRY_DOMAIN && row.1 == shell.exe;
    select(&mut app, |row| ours(row) && row.3.is_none());
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Char('u'));
    eprintln!("[split-strict] u の後: {}", app.status);
    assert!(
        app.status.contains("3行へ分けました"),
        "3行に分かれていない: {}",
        app.status
    );
    assert!(
        !app.status.contains("検査に落ちる"),
        "分けた行が検査に落ちた: {}",
        app.status
    );
    let split: Vec<Row> = rows(&app).into_iter().filter(|row| ours(row)).collect();
    eprintln!("[split-strict] 分けた行: {split:#?}");
    let mut fixed: Vec<(String, String)> = Vec::new();
    for job in [&plan.a, &plan.b, &plan.s] {
        let row = split
            .iter()
            .find(|row| row.2 == job.domain)
            .unwrap_or_else(|| {
                panic!("{} の行が無い（名前が`<葉名>-<語幹>`でない？）", job.domain)
            });
        let line = row
            .3
            .clone()
            .expect("分けた行は固定したコマンドラインを持つ");
        assert!(
            fold(&line).contains(&fold(&job.script.display().to_string())),
            "{} の行が自分のスクリプトのコマンドラインを固定していない: {line}",
            job.domain
        );
        assert!(row.5, "分けた行 {} が選ばれたままでない", job.domain);
        fixed.push((job.domain.clone(), line));
    }
    assert_eq!(split.len(), 3, "入口 → 中の段の行が3つでない: {split:#?}");

    // FS/ネットのタブの候補は`u`で分けたドメインへ作り直されている（決定67の検問2）。
    let wanted = wanted_declarations(plan);
    let view = app.view.as_ref().expect("候補の一覧が開いている");
    let mut picked: Vec<(String, String, String)> = Vec::new();
    for (proposal, domain) in view.proposals.iter().zip(&view.domains) {
        let Some(domain) = domain.as_deref() else {
            continue;
        };
        if [&plan.a, &plan.b, &plan.s]
            .iter()
            .any(|job| job.domain == domain)
        {
            eprintln!(
                "[split-strict] 候補: {} [{domain}] {:?} = {}",
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

    // s の行を Strict に（作業ディレクトリは候補＝絶対パスのスクリプトのフォルダ）。
    select(&mut app, |row| ours(row) && row.2 == plan.s.domain);
    press(&mut app, KeyCode::Char('s'));
    eprintln!("[split-strict] s の後: {}", app.status);
    let positions = app.pending.positions.as_ref().unwrap();
    let index = positions.selected_index().expect("選んでいる行");
    let position = &positions.view.assignment.positions[index];
    assert!(
        positions.is_strict(position),
        "s で Strict にならない: {}",
        app.status
    );
    assert_eq!(
        positions.edge_cwd(position),
        Some(strict_dir().display().to_string()),
        "作業ディレクトリの候補が絶対パスのスクリプトのフォルダでない: {}",
        app.status
    );
    for row in rows(&app).iter().filter(|row| ours(row)) {
        let strict = row.2 == plan.s.domain;
        assert!(
            if strict {
                row.4 == EdgeVerdict::Writable
            } else {
                matches!(row.4, EdgeVerdict::Widens { .. })
            },
            "{} の判定が想定（Strict は Writable・他は Widens）と違う: {:?}",
            row.2,
            row.4
        );
    }

    press(&mut app, KeyCode::Char('a'));
    let modal = app
        .modal
        .as_ref()
        .unwrap_or_else(|| panic!("確認ダイアログが出ない: {}", app.status));
    assert_eq!(modal.confirm, Confirm::Position);
    eprintln!("[split-strict] 確認ダイアログ:\n{}", modal.lines.join("\n"));
    let text = modal.lines.join("\n");
    let count = |needle: &str| modal.lines.iter().filter(|l| l.contains(needle)).count();
    assert_eq!(
        count("広がる遷移 2本"),
        1,
        "明細に広がる遷移2本（a と b）が出ていない"
    );
    assert_eq!(
        count("新しく Strict になる辺 1本"),
        1,
        "明細に Strict の辺1本が出ていない"
    );
    for needle in [
        "Strict の印を付けるドメイン 1個".to_string(),
        format!("作業ディレクトリ {}", strict_dir().display()),
        "移ってから呼ぶ".to_string(),
    ] {
        assert!(text.contains(&needle), "明細に {needle} が無い");
    }
    for (_, line) in &fixed {
        assert!(
            text.contains(line.as_str()),
            "明細に分けた辺のコマンドライン {line} が無い"
        );
    }
    press(&mut app, KeyCode::Char('y'));
    assert!(app.modal.is_none(), "y でダイアログが閉じない");
    eprintln!("[split-strict] 確定の後: {}", app.status);
    assert!(
        app.pending
            .positions
            .as_ref()
            .is_some_and(|p| p.approve.is_empty()),
        "書いた予約が残っている（書けなかった？）: {}",
        app.status
    );
    fixed
}

/// `policy.json`に書かれた辺・印・宣言が、承認したとおりか。
fn check_written(ws: &Path, shell: &MiddleShell, plan: &Plan, fixed: &[(String, String)]) {
    let file = policy_file::load(ws).expect("policy.json を読める");
    let entry = file.domain(ENTRY_DOMAIN).expect("入口のドメイン");
    let mut edges: Vec<(String, String, String, Option<String>)> = entry
        .process
        .transitions
        .iter()
        .map(|edge| {
            let exe = match &edge.exe {
                ExeMatcher::Literal(path) => file_name(path),
                other => panic!("エディタがリテラルでない実行ファイルの辺を書いた: {other:?}"),
            };
            let argv = match &edge.argv {
                ArgvMatcher::Literal(line) => line.clone(),
                other => panic!("分けた行の辺の引数がリテラルでない: {other:?}"),
            };
            (edge.to.clone(), exe, argv, edge.cwd.clone())
        })
        .collect();
    edges.sort();
    let mut expected: Vec<(String, String, String, Option<String>)> = fixed
        .iter()
        .map(|(to, line)| {
            let cwd = (to == &plan.s.domain).then(|| strict_dir().display().to_string());
            (to.clone(), shell.exe.clone(), line.clone(), cwd)
        })
        .collect();
    expected.sort();
    assert_eq!(edges, expected, "入口のドメインの辺が承認したとおりでない");
    for job in [&plan.a, &plan.b, &plan.s] {
        let domain = file
            .domain(&job.domain)
            .unwrap_or_else(|| panic!("ドメイン {} が無い", job.domain));
        assert_eq!(
            domain.strict,
            job.domain == plan.s.domain,
            "ドメイン {} の Strict の印が承認したとおりでない",
            job.domain
        );
    }
    for (child, value) in wanted_declarations(plan) {
        let domain = file.domain(&child).expect("分けたドメイン");
        let declared: Vec<&String> = domain
            .fs
            .read
            .iter()
            .chain(&domain.fs.read_write)
            .chain(&domain.fs.read_exec)
            .collect();
        eprintln!("[split-strict] ドメイン {child} の宣言: {declared:?}");
        assert!(
            declared.iter().any(|v| fold(v) == value),
            "ドメイン {child} に {value} の宣言が無い: {declared:?}"
        );
    }
    let secrets: Vec<String> = [&plan.a, &plan.b, &plan.s]
        .iter()
        .map(|job| fold(&job.secret_path.display().to_string()))
        .collect();
    let leaked: Vec<&String> = entry
        .fs
        .read
        .iter()
        .chain(&entry.fs.read_write)
        .chain(&entry.fs.read_exec)
        .filter(|v| secrets.contains(&fold(v)))
        .collect();
    assert!(
        leaked.is_empty(),
        "入口のドメインに目印の宣言がある（②の対照が成り立たない）: {leaked:?}"
    );
}

/// 分けたドメインごとに承認する宣言（ドメイン, 畳んだ値）。a・b は自分の目印だけ（スクリプトはワークスペースの中で、
/// 遷移先のドメインはワークスペースを見られる）。s は自分の目印と、ワークスペースの外にある s.ps1。
fn wanted_declarations(plan: &Plan) -> Vec<(String, String)> {
    let value = |path: &Path| fold(&path.display().to_string());
    vec![
        (plan.a.domain.clone(), value(&plan.a.secret_path)),
        (plan.b.domain.clone(), value(&plan.b.secret_path)),
        (plan.s.domain.clone(), value(&plan.s.secret_path)),
        (plan.s.domain.clone(), value(&plan.s.script)),
    ]
}
