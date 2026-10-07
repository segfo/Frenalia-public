//! 位置ごとのパス2（決定68）の昇格E2E。**パス2を本番の`harness.exe --enforce-transitions`と同じ形（入口から・遷移を
//! 強制して）で走らせ、断られたファイル操作を、起こした子のドメインへ振り分けて候補にできるか**を本番の経路で確かめる
//! （`plans/position-domains/P6.md`の Task P6.8）。**管理者権限が要る**（WFP の出口強制 daemon・収集器の ETW・
//! 宣言の ACE のため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-pass2-domains`。事前に`cargo build --workspace`（部品は[`common`]）。
//!
//! # 何を測るのか
//!
//! 決定68は3つの困りごとを解いた。(1) パス2が本番と違う形（記録中の1ドメインから・遷移先を用意せず・生成禁止なし）で
//! 走っていた (2) 同じプロセスの2回目のパス2が最初のパス2の宣言で判定していた (3) パス2で断られたファイル操作が、
//! どのドメインの子のものか分からなかった。単体試験は振り分けの関数・記録の読み方・Daemon の書く点（`spawn-daemon`の
//! 受け入れ試験）までを見ている。この試験は、**エディタ・Spawn Daemon・収集器を本番の組み合わせで回したときに、
//! Daemon が記録した子の通し番号と ETW が拒否の行に付けた通し番号が同じ値になるか**（決定68の限界「未測定」）と、
//! それで候補がドメインごとに分かれるかを測る。
//!
//! # 宣言（`policy.json`を手で書き、ファイルの宣言はエディタの`approve-declared`でこの機に承認する）
//!
//! ```text
//! 入口（workspace-shell）─ <中の段のシェル>（引数は任意）→ p6-child: 目印 child.txt を読める
//! ```
//!
//! 目印は**ワークスペースの外**（[`marker_dir`]）——遷移先のドメインはどれもワークスペースを見られるので、
//! ドメインの差はワークスペースの外でしか測れない（`split_strict_e2e.rs`と同じ）。
//!
//! # 腕（`B-35`: 通る側と断る側を同じ回で）
//!
//! 同じ1回のパス2（CLI の`record-net`、`--domain`なし）で:
//!
//! | 腕 | 行 | 期待 |
//! |---|---|---|
//! | ① | 入口が中の段のシェルを起こし、子が child.txt を読む | 子の中身が返る（遷移先の宣言が子に付いた） |
//! | ② | 同じ子が other.txt を読む | 読めない。その拒否が **`p6-child`の候補**に出る（`show`の`[p6-child]`） |
//! | ③ | 入口が child.txt を直接読む | 読めない（①の対照）。その拒否が**入口の候補**に出る |
//! | ④ | 入口が記録に無い`whoami.exe`を起こす | `pending.jsonl`に（入口, whoami.exe, `no_matching_edge`）だけ |
//! | ⑤ | `spawn-audit.jsonl`と`fs-audit.jsonl` | 入口のトップレベルと`p6-child`の行がちょうど1つずつ。②の拒否の行の通し番号は`p6-child`の行の番号、③の拒否の行の番号は入口の行の番号と一致する |
//! | ⑥ | 撃った後の AppContainer プロファイル | その回のエディタが作ったものが残っていない（P6.3） |
//!
//! ⑤は向きの違う2組（子の拒否↔子の行、入口の拒否↔入口の行）で見る——片方だけだと、「全部の拒否に同じ番号が付く」
//! 取り違えでも通る。
//!
//! 続けて、宣言を取り消して CLI のパス2をもう1回撃ち（開始時の取り消しで child.txt の ACE が剥がれる。後始末）、
//! 最後に**同じプロセスでパス2を2回**（⑦、`record_net`を直接呼ぶ。`record_net_e2e.rs`の2回目の試験の形）撃つ:
//! 1回目は`whoami.exe`の辺が無く断られ、`policy.json`へ入口から入口への辺を書いてから2回目に通る（Daemon を
//! 起こし直したので2回目の宣言が効く。決定68の困りごと2）。Daemon のプロセスIDが2回で違うことも数える。
//! ⑦を後始末の後に置くのは、試験のプロセスがワークスペースの「使用中」の印をプロセスが終わるまで持つためである
//! ——先に撃つと、後始末のパス2が「使用中なので取り消しを見送る」（`record_net/session_grants.rs`の限界）。
//!
//! # 言えないこと
//!
//! - 中の段は、この機で`harness.exe`が選ぶシェル（ストアアプリの`pwsh`しか無ければ PowerShell 5.1。決定68の限界）
//! - 通信の候補のドメインごとの振り分け（P7）と、画面の見た目（`TestBackend`の試験だけ）
//! - Daemon が起こした入れ子の、さらに下の段（子の子）の通し番号
//!
//! # 置き場
//!
//! ワークスペース`C:\harness-e2e\policy-editor-pass2-domains`、目印`C:\harness-e2e\_pass2-domains-marker`（名前に
//! プロセスIDを入れない——祖先 traverse の台帳の行を回ごとに増やさない。P5.7・P5.10.3 と同じ）。緑なら消し、
//! 赤なら調査のため残す。

#![cfg(windows)]

mod common;

use std::path::{Path, PathBuf};

use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::spawn_audit::{SpawnAuditRecord, SPAWN_AUDIT_FILE};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher, TransitionDenial};
use harness_policy::{FsAuditEvent, FsAuditKind};
use harness_policy_editor::session_dir::{AUDIT_LOG_FILE_NAME, MANIFEST_FILE_NAME};
use harness_sandbox::tier2a::spawnd::client::DAEMON_STDERR_ENV;
use harness_sandbox::tier2a::spawnd::DenyReason;

use common::{
    acl_sddl, case_dir, count_sid_prefix, daemon_denials, editor_exe, file_name, fold,
    harness_profiles, middle_shell, nonce, place_netfilterd_next_to_the_test_binary,
    profiles_added_since, ps_run, record_dirs, record_net_cli, scratch_dir,
    spawn_daemons_started_by_this_process, system32, unapprove_all, MiddleShell, CASE_ROOT,
};

/// ワークスペースの名前。
const CASE: &str = "policy-editor-pass2-domains";
/// 遷移先のドメイン。
const CHILD: &str = "p6-child";

/// 待ち行列の Daemon の拒否（遷移元, 実行ファイル名, 理由）。[`daemon_denials`]の戻り値の形。
type Denials = Vec<(Option<String>, String, DenyReason)>;

/// 目印のファイルの置き場（**ワークスペースの外**。名前をワークスペースの名前で始めない——前方一致で含んでしまう）。
fn marker_dir() -> PathBuf {
    Path::new(CASE_ROOT).join("_pass2-domains-marker")
}

/// 撃つ行と、期待に使う印。
struct Plan {
    shell: MiddleShell,
    child_txt: PathBuf,
    other_txt: PathBuf,
    /// 目印の中身（**どの行にも綴りとして現れない**）。
    child_secret: String,
    other_secret: String,
    /// ①〜④を1回で撃つ行。
    line: String,
}

/// 撃つ行。印は`'A_' + 'B'`と割って書く——行の本文がどこかへ写っても、走った結果と取り違えない。
fn plan(shell: MiddleShell) -> Plan {
    let nonce = nonce();
    let child_txt = marker_dir().join("child.txt");
    let other_txt = marker_dir().join("other.txt");
    let read = |label: &str, path: &Path, fail: &str| {
        format!(
            "try {{ ('{label}_' + 'READ:') + (Get-Content -LiteralPath '{}' -ErrorAction Stop) }} \
             catch {{ ('{fail}_' + 'FAIL ') + $_.Exception.Message }}",
            path.display()
        )
    };
    // ①② 子（p6-child）が自分の目印と、宣言していない目印を読む。
    let child_script = format!(
        "Write-Output ('P6_CHILD_' + 'RAN'); {}; {}",
        read("CHILD", &child_txt, "CHILD_OWN"),
        read("CHILD", &other_txt, "CHILD_OTHER")
    );
    // ③ 入口が子の目印を直接読む。④ 記録に無い whoami.exe を起こす。
    let line = format!(
        "{}; {}; whoami.exe",
        ps_run(&shell, &child_script),
        read("ENTRY", &child_txt, "ENTRY_CHILD")
    );
    Plan {
        shell,
        child_txt,
        other_txt,
        child_secret: format!("P6_CHILD_SECRET_{nonce}"),
        other_secret: format!("P6_OTHER_SECRET_{nonce}"),
        line,
    }
}

/// `policy.json`の綴り（エディタが書く`/`区切り）。承認台帳はこの綴りで照合する。
fn declared_value(path: &Path) -> String {
    harness_policy::normalize::normalize_path(&path.display().to_string())
}

/// 入口 →（中の段のシェル）→ p6-child の辺と、p6-child の child.txt の読み取り。入口はファイルを宣言しない。
fn write_policy(ws: &Path, plan: &Plan) {
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.commands.push(plan.line.clone());
    entry.cwd = Some(ws.to_path_buf());
    entry.process.transitions.push(editor_edge(
        &plan.shell.path,
        ArgvMatcher::Any(AnyMarker),
        CHILD,
    ));
    let mut child = PolicyDomain::new(CHILD);
    child.fs.read.push(declared_value(&plan.child_txt));
    let mut file = PolicyFile::default();
    file.domains.push(entry);
    file.domains.push(child);
    policy_file::save(ws, &file).unwrap_or_else(|e| panic!("policy.jsonを書けない: {e}"));
}

/// 宣言をこの機で承認する（D-112。承認していない宣言には許可が付かず、遷移先のドメインごと用意されない）。
fn approve_declared(ws: &Path, plan: &Plan) {
    let output = std::process::Command::new(editor_exe())
        .args([
            "approve-declared",
            "--domain",
            CHILD,
            "--workspace",
            &ws.to_string_lossy(),
            "--fs",
            &declared_value(&plan.child_txt),
            "--access",
            "read",
            "--yes",
        ])
        .output()
        .expect("approve-declared should run");
    eprintln!(
        "[pass2-domains] approve-declared\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "approve-declared が失敗した");
}

/// このマシンのユーザー名（`whoami.exe`の出力。AppContainer の中の`whoami.exe`も同じ綴りを返す）。小文字で。
fn whoami_name() -> String {
    let output = std::process::Command::new(system32("whoami.exe"))
        .output()
        .expect("whoami.exe should run");
    let name = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    assert!(!name.is_empty(), "whoami.exe が何も返さない");
    name
}

/// 許可した生成の記録の`spawned`の行（1行目は版の行）。読めない行は落とす（黙って捨てない、`B-10`）。
fn spawned(record_dir: &Path) -> Vec<(Option<u64>, String, String, bool)> {
    let text = std::fs::read_to_string(record_dir.join(SPAWN_AUDIT_FILE)).unwrap_or_else(|e| {
        panic!(
            "{SPAWN_AUDIT_FILE} を読めない（{}）: {e}",
            record_dir.display()
        )
    });
    eprintln!("[pass2-domains] --- {SPAWN_AUDIT_FILE} ---\n{text}");
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let record: SpawnAuditRecord = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!(
                "{SPAWN_AUDIT_FILE} の{}行目が読めない: {e}: {line}",
                index + 1
            )
        });
        match record {
            SpawnAuditRecord::Header { .. } if index == 0 => {}
            SpawnAuditRecord::Spawned {
                process_sequence_number,
                domain,
                exe,
                top_level,
                ..
            } => out.push((process_sequence_number, domain, file_name(&exe), top_level)),
            other => panic!("{SPAWN_AUDIT_FILE} に想定外の行: {other:?}"),
        }
    }
    out
}

/// 収集器が書いた拒否の行（パス, 通し番号）。
fn denials(record_dir: &Path) -> Vec<(String, Option<u64>)> {
    let text = std::fs::read_to_string(record_dir.join(AUDIT_LOG_FILE_NAME)).unwrap_or_default();
    text.lines()
        .filter_map(|line| serde_json::from_str::<FsAuditEvent>(line).ok())
        .filter(|event| event.kind == FsAuditKind::Etw && !event.allowed)
        .filter_map(|event| Some((fold(event.path.as_deref()?), event.process_sequence_number)))
        .collect()
}

/// エディタの CLI の`show`（最新の記録・全件）。
fn show(ws: &Path) -> String {
    let output = std::process::Command::new(editor_exe())
        .args(["show", "--workspace", &ws.to_string_lossy(), "--limit", "0"])
        .output()
        .expect("show should run");
    assert!(
        output.status.success(),
        "show が失敗した: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// `show`の候補の行のうち、ドメインの見出しが`domain`で、値が`path`のもの。
fn candidate_in<'a>(shown: &'a str, domain: &str, path: &Path) -> Option<&'a str> {
    let value = fold(&path.display().to_string());
    shown.lines().map(str::trim_start).find(|line| {
        line.starts_with("fs-")
            && line.contains(&format!("[{domain}]"))
            && fold(line).contains(&value)
    })
}

/// whoami.exe を入口から断った記録だけか（PowerShell 5.1 は起動の失敗を引数を変えて再試行するので、
/// 同じ実行ファイルの`no_matching_edge`が複数種類積まれ得る。`split_strict_e2e.rs`の`expect_one_denial`）。
fn only_whoami_denied(denials: &[(Option<String>, String, DenyReason)]) -> bool {
    !denials.is_empty()
        && denials.iter().all(|(from, exe, reason)| {
            from.as_deref() == Some(ENTRY_DOMAIN)
                && exe == "whoami.exe"
                && matches!(
                    reason,
                    DenyReason::Transition {
                        denial: TransitionDenial::NoMatchingEdge
                    }
                )
        })
}

#[test]
#[ignore = "requires administrator rights (WFP netfilterd, the ETW collector and declaration ACEs); run through dev-elevated-run e2e-policy-editor-pass2-domains"]
fn a_pass2_from_the_entry_attributes_each_denial_to_the_domain_that_spawned_it() {
    let plan = plan(middle_shell());
    let ws = case_dir(CASE);
    std::fs::create_dir_all(ws.join(".harness").join("sandbox")).unwrap();
    let scratch = scratch_dir(CASE);
    let _ = std::fs::remove_dir_all(marker_dir());
    std::fs::create_dir_all(marker_dir()).expect("create marker dir");
    std::fs::write(&plan.child_txt, &plan.child_secret).expect("write child.txt");
    std::fs::write(&plan.other_txt, &plan.other_secret).expect("write other.txt");
    let mut failures: Vec<String> = Vec::new();

    // 基準線（作り直した直後なので capability SID の ACE は無いはず）。
    for path in [&plan.child_txt, &plan.other_txt] {
        let sddl = acl_sddl(path);
        assert_eq!(
            count_sid_prefix(&sddl, "S-1-15-3-"),
            0,
            "前提: 作り直した {} に capability SID の ACE があってはならない: {sddl}",
            path.display()
        );
    }
    write_policy(&ws, &plan);
    approve_declared(&ws, &plan);
    let whoami = whoami_name();
    let profiles_before = harness_profiles();
    eprintln!(
        "[pass2-domains] 撃つ前の harness の族の AppContainer プロファイル: {}件",
        profiles_before.len()
    );

    // --- 1回目の CLI のパス2（①〜⑥） ------------------------------------------------------
    let before = record_dirs(&ws);
    let _ = std::fs::remove_file(harness_sandbox::tier2a::spawnd::transitions::pending_path(
        &ws,
    ));
    let daemon_log = scratch.join("pass2-spawnd.log");
    let _ = std::fs::remove_file(&daemon_log);
    let (output, editor_pid) = record_net_cli(
        &ws,
        &plan.line,
        &[],
        &[(DAEMON_STDERR_ENV, daemon_log.as_path())],
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    eprintln!(
        "[pass2-domains] --- record-net（pid {editor_pid}） stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n\
         --- Spawn Daemon の標準エラー ---\n{}",
        std::fs::read_to_string(&daemon_log).unwrap_or_default()
    );
    assert!(output.status.success(), "record-net が失敗した（上の出力）");
    assert!(
        stderr.contains("Tier2aへ着地しました"),
        "Tier2a へ着地していない——以下は何も測っていない: {stderr}"
    );
    let provisioned =
        harness_policy_editor::record_net::domains_provisioned_line(&[CHILD.to_string()], 0);
    if !stderr.contains(&provisioned) {
        failures.push(format!(
            "遷移先のドメインを用意した行（{provisioned}）が無い"
        ));
    }

    // ① 子は自分の目印を読める（遷移先の宣言が子に付いた）。
    if !stdout.contains(&format!("CHILD_READ:{}", plan.child_secret)) {
        failures.push(format!(
            "①: 子（{CHILD}）が自分の目印 {} を返していない（遷移が通っていないか、宣言が子に付いていない）",
            plan.child_txt.display()
        ));
    }
    // ② 子は宣言していない目印を読めない。
    if stdout.contains(&plan.other_secret) || !stdout.contains("CHILD_OTHER_FAIL") {
        failures.push(format!(
            "②: 子が {} を読めた、または読もうとして失敗した印（CHILD_OTHER_FAIL）が無い",
            plan.other_txt.display()
        ));
    }
    // ③ 入口は子の目印を直接読めない（①の対照）。
    if stdout.contains(&format!("ENTRY_READ:{}", plan.child_secret))
        || !stdout.contains("ENTRY_CHILD_FAIL")
    {
        failures.push(format!(
            "③: 入口が子の目印 {} を読めた、または読もうとして失敗した印（ENTRY_CHILD_FAIL）が無い",
            plan.child_txt.display()
        ));
    }
    // ④ 記録に無い whoami.exe は入口から断られる（走らない）。
    let pending = daemon_denials(&ws, "④");
    eprintln!("[pass2-domains] 待ち行列の拒否: {pending:?}");
    if !only_whoami_denied(&pending) {
        failures.push(format!(
            "④: 待ち行列が（入口 {ENTRY_DOMAIN}, whoami.exe, no_matching_edge）だけになっていない: {pending:?}"
        ));
    }
    if stdout.to_ascii_lowercase().contains(&whoami) {
        failures
            .push("④: 断られるはずの whoami.exe が走った（出力にユーザー名がある）".to_string());
    }

    let new_dirs: Vec<PathBuf> = record_dirs(&ws).difference(&before).cloned().collect();
    assert_eq!(
        new_dirs.len(),
        1,
        "新しい記録のディレクトリがちょうど1つでない: {new_dirs:?}"
    );
    let record_dir = &new_dirs[0];
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(record_dir.join(MANIFEST_FILE_NAME)).expect("manifest"),
    )
    .expect("manifest json");
    if manifest["pass"] != 2
        || manifest["status"] != "finished"
        || manifest["domain"] != ENTRY_DOMAIN
    {
        failures.push(format!(
            "マニフェストがパス2・finished・入口で閉じていない: {manifest}"
        ));
    }

    // ⑤ 許可した生成の記録と、拒否の行の通し番号。
    let spawns = spawned(record_dir);
    let entry_rows: Vec<_> = spawns
        .iter()
        .filter(|s| s.3 && s.1 == ENTRY_DOMAIN)
        .collect();
    let child_rows: Vec<_> = spawns
        .iter()
        .filter(|s| !s.3 && s.1 == CHILD && s.2 == plan.shell.exe)
        .collect();
    let (entry_seq, child_seq) = match (entry_rows.as_slice(), child_rows.as_slice()) {
        ([entry], [child]) if spawns.len() == 2 => (entry.0, child.0),
        _ => {
            failures.push(format!(
                "⑤: 許可した生成の記録が「入口のトップレベル1行と {CHILD} の {} の1行」になっていない: {spawns:?}",
                plan.shell.exe
            ));
            (None, None)
        }
    };
    let audit = denials(record_dir);
    for (path, seq) in &audit {
        eprintln!("[pass2-domains] 拒否の行: seq={seq:?} path={path}");
    }
    let other = fold(&plan.other_txt.display().to_string());
    let child_value = fold(&plan.child_txt.display().to_string());
    let other_rows: Vec<&Option<u64>> = audit
        .iter()
        .filter(|(p, _)| *p == other)
        .map(|(_, s)| s)
        .collect();
    match child_seq {
        Some(seq) if !other_rows.is_empty() && other_rows.iter().all(|s| **s == Some(seq)) => eprintln!(
            "[pass2-domains] ⑤: 子の拒否 {}行の通し番号 = 子の行の番号 {seq}（Daemon と ETW が一致）",
            other_rows.len()
        ),
        _ => failures.push(format!(
            "⑤: ②の拒否の行（{other_rows:?}）の通し番号が {CHILD} の行の番号（{child_seq:?}）と一致しない、または拒否の行が無い"
        )),
    }
    let entry_rows_seen = audit
        .iter()
        .filter(|(p, s)| *p == child_value && entry_seq.is_some() && *s == entry_seq)
        .count();
    if entry_rows_seen == 0 {
        failures.push(format!(
            "⑤: ③の拒否の行（child.txt）に入口の行の番号（{entry_seq:?}）を持つものが無い: {audit:?}"
        ));
    }
    if child_seq.is_some()
        && audit
            .iter()
            .any(|(p, s)| *p == child_value && *s == child_seq)
    {
        failures.push(
            "⑤: 子が自分の目印（child.txt）で断られた行がある——宣言が子に付き切っていない"
                .to_string(),
        );
    }

    // ②③ の候補がドメインごとに分かれる（`show`のパス2の枝も`position_candidates::load`を通る。P6.6）。
    let shown = show(&ws);
    eprintln!("[pass2-domains] --- show ---\n{shown}");
    if candidate_in(&shown, CHILD, &plan.other_txt).is_none() {
        failures.push(format!(
            "②: {CHILD} の候補に {} が無い",
            plan.other_txt.display()
        ));
    }
    if candidate_in(&shown, ENTRY_DOMAIN, &plan.child_txt).is_none() {
        failures.push(format!(
            "③: 入口の候補に {} が無い",
            plan.child_txt.display()
        ));
    }
    if candidate_in(&shown, CHILD, &plan.child_txt).is_some() {
        failures.push(format!(
            "{CHILD} の候補に、宣言済みの {} がある",
            plan.child_txt.display()
        ));
    }

    // 宣言が実 DACL へ付いたこと（型A）。package SID 宛ては0本のまま（残課題#20）。
    let granted = acl_sddl(&plan.child_txt);
    eprintln!("[pass2-domains] child.txt の SDDL（1回目の後）: {granted}");
    if count_sid_prefix(&granted, "S-1-15-3-") == 0 || count_sid_prefix(&granted, "S-1-15-2-") != 0
    {
        failures.push(format!(
            "child.txt に宣言の capability SID の ACE が無い、または package SID の ACE がある: {granted}"
        ));
    }

    // ⑥ その回のエディタが作った AppContainer プロファイルが残っていない。
    check_profiles(
        &mut failures,
        "⑥ 1回目の CLI のパス2",
        &profiles_before,
        editor_pid,
    );

    // --- 後始末: 宣言を取り消して CLI のパス2をもう1回（開始時の取り消しで ACE が剥がれる） ----------
    unapprove_all(&ws, CHILD);
    let (output, cleanup_pid) =
        record_net_cli(&ws, "Write-Output ('P6_CLEANUP_' + 'RAN')", &[], &[]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    eprintln!("[pass2-domains] --- 後始末のパス2（pid {cleanup_pid}） stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
    if !output.status.success() || !stdout.contains("P6_CLEANUP_RAN") {
        failures.push("後始末のパス2が走っていない（上の出力）".to_string());
    }
    for path in [&plan.child_txt, &plan.other_txt] {
        let sddl = acl_sddl(path);
        eprintln!(
            "[pass2-domains] {} の SDDL（取り消した後）: {sddl}",
            path.display()
        );
        if count_sid_prefix(&sddl, "S-1-15-3-") != 0 || count_sid_prefix(&sddl, "S-1-15-2-") != 0 {
            failures.push(format!(
                "宣言を取り消してパス2を撃っても {} に capability SID か package SID の ACE が残った: {sddl}",
                path.display()
            ));
        }
    }
    check_profiles(
        &mut failures,
        "後始末のパス2",
        &profiles_before,
        cleanup_pid,
    );

    // --- ⑦ 同じプロセスでパス2を2回: 後から書いた辺が2回目に効く --------------------------------
    second_pass2_sees_the_edge_written_after_the_first(&mut failures, &ws, &whoami);
    check_profiles(
        &mut failures,
        "⑦ プロセス内のパス2",
        &profiles_before,
        std::process::id(),
    );

    assert!(
        failures.is_empty(),
        "位置ごとのパス2で{}件の問題（ワークスペース {}・目印 {} を調査のため残す）:\n- {}",
        failures.len(),
        ws.display(),
        marker_dir().display(),
        failures.join("\n- ")
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(marker_dir());
    let _ = std::fs::remove_dir_all(&scratch);
}

/// `pid`のプロセスが作った harness の族の AppContainer プロファイルが残っていないか。別のプロセスが作った分は
/// 判定に入れずに出す（同じ機の別の作業ツリーの`harness.exe`など。[`profiles_added_since`]）。
fn check_profiles(
    failures: &mut Vec<String>,
    name: &str,
    before: &std::collections::BTreeSet<String>,
    pid: u32,
) {
    let (ours, others) = profiles_added_since(before, pid);
    eprintln!(
        "[pass2-domains] {name}: 残ったプロファイル（pid {pid} のもの）{ours:?}・別のプロセスが作ったもの（判定に入れない）{others:?}・\
         今の harness の族 {}件",
        harness_profiles().len()
    );
    if !ours.is_empty() {
        failures.push(format!(
            "{name}: その回が作った AppContainer プロファイルが残った: {ours:?}"
        ));
    }
}

/// ⑦: 同じプロセスで`record_net`を2回呼ぶ。1回目は`whoami.exe`の辺が無く断られ、`policy.json`へ入口から入口への辺を
/// 書いてから2回目に通る。Daemon はパス2のたびに起こし直す（決定68 の前例の(3)）ので、2回目の宣言が効く。
fn second_pass2_sees_the_edge_written_after_the_first(
    failures: &mut Vec<String>,
    ws: &Path,
    whoami: &str,
) {
    use harness_policy_editor::record_net::{
        record_net, NetMode, NetRecordEvent, RecordNetRequest, SessionGrants, SharedNetfilter,
        SharedSpawnDaemon,
    };

    place_netfilterd_next_to_the_test_binary();
    // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る（同一プロセスなので自分で立てる）。
    std::env::set_var("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1");
    let command = "whoami.exe";
    // **宣言順が撤収順を決める**（`record_net_e2e.rs`の2回目の試験と同じ持ち方。D-56）。ブロックを抜けると全部畳む。
    {
        let _grants = SessionGrants::hold();
        let wfp = SharedNetfilter::hold();
        let collector = harness_policy_editor::record::SharedCollector::hold();
        let spawn_daemon = SharedSpawnDaemon::hold();
        let never_cancel = || false;
        let run = |label: &str| -> (PathBuf, String, Denials) {
            let _ = std::fs::remove_file(
                harness_sandbox::tier2a::spawnd::transitions::pending_path(ws),
            );
            let request = RecordNetRequest {
                command,
                cwd: ws,
                workspace_root: ws,
                timeout: Some(std::time::Duration::from_secs(120)),
                cancel: &never_cancel,
                wfp: &wfp,
                collector: &collector,
                spawn_daemon: &spawn_daemon,
                net_mode: NetMode::RecordAll,
            };
            let mut stdout = String::new();
            let mut on_event = |event: NetRecordEvent| match event {
                NetRecordEvent::Stdout(line) => {
                    stdout.push_str(&line);
                    stdout.push('\n');
                }
                NetRecordEvent::Warning(message) => {
                    eprintln!("[pass2-domains] {label} [warn] {message}")
                }
                _ => {}
            };
            let outcome = record_net(&request, &mut on_event)
                .unwrap_or_else(|e| panic!("⑦ {label}: record_net が失敗した: {e}"));
            eprintln!(
                "[pass2-domains] ⑦ {label}: exit={:?} stdout={stdout:?}",
                outcome.exit_code
            );
            (outcome.session_dir, stdout, daemon_denials(ws, label))
        };
        let whoami_rows = |dir: &Path| {
            spawned(dir)
                .into_iter()
                .filter(|s| s.2 == "whoami.exe")
                .collect::<Vec<_>>()
        };

        let (dir, stdout, pending) = run("1回目");
        let daemons_first = spawn_daemons_started_by_this_process();
        eprintln!("[pass2-domains] ⑦ 1回目: 拒否 {pending:?}・Spawn Daemon {daemons_first:?}");
        if !only_whoami_denied(&pending)
            || stdout.to_ascii_lowercase().contains(whoami)
            || !whoami_rows(&dir).is_empty()
        {
            failures.push(format!(
                "⑦ 1回目: 辺の無い whoami.exe が入口から no_matching_edge で断られていない（拒否 {pending:?}）、または走った"
            ));
        }

        // 入口から入口への辺を足す（Daemon は表を引かず、呼び出し元の実体で起こす）。
        let mut file = policy_file::load(ws).expect("policy.json を読める");
        file.domains
            .iter_mut()
            .find(|d| d.name == ENTRY_DOMAIN)
            .expect("入口のドメイン")
            .process
            .transitions
            .push(editor_edge(
                &system32("whoami.exe"),
                ArgvMatcher::Any(AnyMarker),
                ENTRY_DOMAIN,
            ));
        policy_file::save(ws, &file)
            .unwrap_or_else(|e| panic!("辺を足した policy.json を書けない: {e}"));

        let (dir, stdout, pending) = run("2回目");
        let daemons_second = spawn_daemons_started_by_this_process();
        let rows = whoami_rows(&dir);
        eprintln!("[pass2-domains] ⑦ 2回目: 拒否 {pending:?}・Spawn Daemon {daemons_second:?}・whoami の生成 {rows:?}");
        if !pending.is_empty() || !stdout.to_ascii_lowercase().contains(whoami) {
            failures.push(format!(
                "⑦ 2回目: 辺を書いた whoami.exe が走っていない（拒否 {pending:?}・出力 {stdout:?}）——Daemon が1回目の宣言のまま？"
            ));
        }
        if !matches!(rows.as_slice(), [(Some(_), domain, _, false)] if domain == ENTRY_DOMAIN) {
            failures.push(format!(
                "⑦ 2回目: 許可した生成の記録に whoami.exe の入れ子の行（入口・番号つき）がちょうど1つない: {rows:?}"
            ));
        }
        if !(daemons_first.len() == 1
            && daemons_second.len() == 1
            && daemons_first.is_disjoint(&daemons_second))
        {
            failures.push(format!(
                "⑦: Spawn Daemon が起こし直されていない（1回目 {daemons_first:?}・2回目 {daemons_second:?}）"
            ));
        }
    }
}
