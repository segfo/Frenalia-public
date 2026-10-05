//! 収集プロセスがプロセスの木を書くことの昇格E2E（**要管理者権限**。
//! `dev-elevated-run.exe policy-learn-process-tree`。ポリシーエディタの決定65・決定23、作業の一覧の P2e）。
//!
//! # ここでしか測れないもの
//!
//! 単体試験（`process_audit_tests`・`instances_tests`）は、結び付けの規則と行の形を**作り物の通知**で
//! 固定する。次の4つは実機でしか成立しない。
//!
//! 1. ETWの`ParentProcessSequenceNumber`が、**本番の経路**（パス1と同じ record-all＋引数の観測。
//!    `Kernel-Process`は FS のセッションに相乗りしている）でも親のインスタンスの番号を指し、
//!    深さ3の鎖が番号だけで組める（`plans/etw-spike/RESULTS.md` §24.7 が未測定として残した2軸）
//! 2. 2つの購読（マニフェスト側＝実行ファイルと親の番号、MOF側＝コマンドライン）の時刻の差が
//!    2ms の窓に入り、各段の引数が`Exact`で結び付く（決定65の追記(4)。§24 は別のセッションで測った）
//! 3. `fs-audit.jsonl`の行が、アクセスした当のインスタンスの通し番号を持つ（決定23(6)）
//! 4. 記録の子孫でないプロセスは木に入らない
//!
//! **木の形（1）と引数（2）は別々の源で確かめる。** 鎖の段はマニフェスト側の欄（親の番号・実行ファイル）
//! だけで辿り、引数はそのあとで段ごとに照合する——引数で段を探すと、窓が外れたときに「鎖が組めない」と
//! 「引数が結び付かない」が同じ失敗に見える（`measurement-review` の検問10）。
//!
//! # 撃ち方
//!
//! ```text
//! cargo build --workspace --exclude dev-elevated-runner
//! target/debug/dev-elevated-run.exe policy-learn-process-tree
//! ```
//!
//! **`harness-policy-learnd.exe`はテストのビルドでは作り直されない**（`argv_e2e_tests`のモジュール doc）。
//! 古い個体は`process-audit.jsonl`を書かないので、依頼側が「older build … process tree」で断る。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use harness_policy::event::FsAuditEvent;
use harness_policy::process_event::{
    parse_process_audit, ArgvBinding, ParentSeqSource, ProcessAuditLog, ProcessInstance,
};

use super::argv_e2e_tests::policy_for;
use super::process_audit_path;

/// 観測が配送され始めるまでの待ち（`argv_e2e_tests`と同じ値）。
const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
/// 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上）。
const DRAIN: std::time::Duration = std::time::Duration::from_secs(4);
/// WMI が起こす対照のプロセスが走り終わるのを待つ上限。
const CONTROL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// 1回ぶんの`cmd /c cmd /c cmd /c type <目印>`。
struct Run {
    /// 目印のファイル名（`run-a-<pid>.txt`）。3段すべてのコマンドラインに現れる。
    marker: String,
    path: PathBuf,
    /// このプロセスが起こした根の pid（`Child::id`）。根を探す鍵の1つ。
    root_pid: u32,
}

/// 木を1行ずつ人が読める形にする（失敗の文面と、`--nocapture`で残す実機の木）。
fn describe(log: &ProcessAuditLog) -> String {
    let mut out = String::new();
    for i in &log.instances {
        let argv = match &i.argv {
            ArgvBinding::Exact {
                command_line,
                truncation,
            } => format!("Exact({truncation:?}) {command_line}"),
            ArgvBinding::Missing { reason } => format!("Missing({reason:?})"),
        };
        out.push_str(&format!(
            "  seq={} parent_seq={:?}({:?}) pid={} parent_pid={:?} root={} image={:?} argv={}\n",
            i.seq,
            i.parent_seq,
            i.parent_seq_source,
            i.pid,
            i.parent_pid,
            i.is_scope_root,
            i.image_path,
            argv
        ));
    }
    for c in &log.controls {
        out.push_str(&format!("  control: {c}\n"));
    }
    out.push_str(&format!("  skipped_lines: {}\n", log.skipped_lines));
    out
}

fn command_line(instance: &ProcessInstance) -> Option<&str> {
    match &instance.argv {
        ArgvBinding::Exact { command_line, .. } => Some(command_line),
        ArgvBinding::Missing { .. } => None,
    }
}

fn is_cmd(instance: &ProcessInstance) -> bool {
    instance
        .image_path
        .as_deref()
        .is_some_and(|image| image.to_ascii_lowercase().ends_with("/cmd.exe"))
}

/// 親の番号が`parent`の番号で、実行ファイルが`cmd.exe`のインスタンス（＝鎖の次の段）を
/// **ちょうど1つ**返す。引数は見ない（木の形をマニフェスト側だけで辿る）。
fn only_cmd_child<'a>(
    log: &'a ProcessAuditLog,
    parent: &ProcessInstance,
    stage: &str,
    tree: &str,
) -> &'a ProcessInstance {
    let children: Vec<&ProcessInstance> = log
        .instances
        .iter()
        .filter(|i| i.parent_seq == Some(parent.seq) && is_cmd(i))
        .collect();
    assert_eq!(
        children.len(),
        1,
        "{stage}: 親の番号が {} を指す cmd.exe がちょうど1つではない（{} 個）。\
         欄が親を指していないか、開始を取りこぼした:\n{tree}",
        parent.seq,
        children.len()
    );
    children[0]
}

/// 段の引数を照合する: 欄の出どころが`etw-field`・引数が`Exact`・目印を含む・`/c`の数。
fn assert_stage(instance: &ProcessInstance, run: &Run, slash_c: usize, stage: &str, tree: &str) {
    assert_eq!(
        instance.parent_seq_source,
        ParentSeqSource::EtwField,
        "{stage}: 親の番号が欄から取れていない:\n{tree}"
    );
    let Some(line) = command_line(instance) else {
        panic!(
            "{stage}（seq={}）の引数が結び付いていない。2つの購読の時刻が 2ms の窓に入らなかった\
             可能性がある（制御レコードの argv_not_observed・mof_start_without_instance を見る）:\n{tree}",
            instance.seq
        );
    };
    assert!(
        line.contains(&run.marker),
        "{stage}（seq={}）の引数に目印 {} が無い: {line}\n{tree}",
        instance.seq,
        run.marker
    );
    assert_eq!(
        line.to_ascii_lowercase().matches("/c").count(),
        slash_c,
        "{stage}（seq={}）の`/c`の数が段と合わない（別の段の引数が結び付いた）: {line}\n{tree}",
        instance.seq
    );
}

fn fs_audit_events(sink: &Path) -> Vec<FsAuditEvent> {
    std::fs::read_to_string(sink)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<FsAuditEvent>(line)
                .unwrap_or_else(|e| panic!("fs-audit.jsonl の行が読めない（{e}）: {line}"))
        })
        .collect()
}

fn ends_with_ignore_case(path: Option<&str>, suffix: &str) -> bool {
    path.is_some_and(|path| {
        path.to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase())
    })
}

/// **記録中に起こした深さ3の`cmd`の鎖が、通し番号で辿れる木として書かれる。**
///
/// 2回走らせ、各回について: 根（このプロセスの直接の子）→2段目→3段目が親の番号だけで1本に辿れる／
/// 各段の引数が`Exact`で、`/c`の数が段と合う／2回の6つの番号が相異なる／3段目が読んだ目印のファイルの
/// `fs-audit.jsonl`の行がすべて3段目の番号を持つ。あわせて対照として、WMI（`Win32_Process.Create`）に
/// 起こさせた**子孫でない**プロセスが木にも`fs-audit.jsonl`にも入らないこと——そのプロセスが記録の間に
/// 本当に走ったことは、それが書いたファイルで確かめる（走っていなければ「入らない」は何も言えない）。
#[test]
#[ignore = "requires administrator (starts real ETW sessions); run via dev-elevated-runner"]
fn a_three_deep_cmd_chain_is_recorded_as_a_tree_with_sequence_numbers() {
    let _ = super::reuse_tests::ensure_collector_next_to_test_binary();
    let workspace = tempfile::tempdir().expect("tempdir");
    let sink_dir = workspace
        .path()
        .join(".harness")
        .join("sandbox")
        .join("g-1");
    std::fs::create_dir_all(&sink_dir).expect("create sink dir");
    let sink = sink_dir.join("fs-audit.jsonl");
    let me = std::process::id();

    // 1. 目印のファイル。**記録を始める前に作る**——このプロセス自身の書込を記録の時間に入れない。
    let mut runs: Vec<Run> = ["a", "b"]
        .into_iter()
        .map(|name| {
            let marker = format!("run-{name}-{me}.txt");
            let path = workspace.path().join(&marker);
            std::fs::write(&path, format!("process-tree-e2e {name}")).expect("write the marker");
            Run {
                marker,
                path,
                root_pid: 0,
            }
        })
        .collect();
    let nondesc_marker = format!("nondesc-{me}");
    let nondesc_file = workspace.path().join(format!("{nondesc_marker}.txt"));

    let mut session = super::client::CollectorSession::new();
    let started = session
        .start(
            None,
            false,
            policy_for(workspace.path(), &sink_dir, true),
            None,
        )
        .expect("start the collector with argv capture");
    assert!(
        started.etw_available,
        "FS側のETWセッションが張れていない＝管理者権限で走っていない。この状態の緑は何も証明しない"
    );
    std::thread::sleep(WARMUP);

    // 2. このプロセスの直接の子として起こす（パス1で harness が対象のコマンドを起こすのと同じ形）。
    for run in &mut runs {
        let mut child = Command::new("cmd.exe")
            .args(["/c", "cmd", "/c", "cmd", "/c", "type"])
            .arg(&run.path)
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn cmd.exe");
        run.root_pid = child.id();
        let status = child.wait().expect("wait for cmd.exe");
        assert!(status.success(), "{} の鎖が失敗した: {status}", run.marker);
    }

    // 3. 対照: 子孫でないプロセス（親は WmiPrvSE.exe）。目印を'nondesc-'+'<pid>'に割るのは、
    //    powershell 自身（これは子孫）のコマンドラインに結合した目印を出さないため。
    let script = format!(
        "$m='nondesc-'+'{me}'; $p=Join-Path '{}' ($m+'.txt'); \
         (Invoke-CimMethod -ClassName Win32_Process -MethodName Create \
         -Arguments @{{CommandLine=('cmd.exe /c echo '+$m+' > '+$p)}}).ReturnValue",
        workspace.path().display()
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("spawn powershell");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "Win32_Process.Create が成功しなかった（stderr: {}）",
        String::from_utf8_lossy(&output.stderr)
    );
    let deadline = std::time::Instant::now() + CONTROL_DEADLINE;
    while !nondesc_file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        nondesc_file.exists(),
        "WMI に起こさせた対照のプロセスが記録の間に走らなかった（{} が無い）。\
         「子孫でないものは入らない」をこの回では何も言えない",
        nondesc_file.display()
    );

    std::thread::sleep(DRAIN);
    session.stop().expect("stop the recording");
    drop(session);

    // 4. 読む。版の行が読めること自体が版の検算。
    let audit_path = process_audit_path(&sink);
    let text = std::fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("{} が読めない: {e}", audit_path.display()));
    let log = parse_process_audit(&text).expect("process-audit.jsonl が版の行で始まる");
    let tree = describe(&log);
    eprintln!("--- process-audit.jsonl ---\n{tree}");
    assert_eq!(log.skipped_lines, 0, "読めない行がある:\n{tree}");
    assert!(
        log.controls
            .iter()
            .any(|c| c.starts_with("process_tree_summary:")),
        "要約の制御レコードが無い＝木の書き手が最後まで畳まれていない:\n{tree}"
    );

    // 5. 各回の鎖を、親の番号と実行ファイルだけで辿ってから、段ごとに引数を照合する。
    let mut seqs = Vec::new();
    let mut innermost = Vec::new();
    for run in &runs {
        let roots: Vec<&ProcessInstance> = log
            .instances
            .iter()
            .filter(|i| i.is_scope_root && i.parent_pid == Some(me) && i.pid == run.root_pid)
            .collect();
        assert_eq!(
            roots.len(),
            1,
            "{}: 記録の根（このプロセス {me} の子 pid={}）がちょうど1つではない:\n{tree}",
            run.marker,
            run.root_pid
        );
        let root = roots[0];
        let second = only_cmd_child(&log, root, &format!("{} の2段目", run.marker), &tree);
        let third = only_cmd_child(&log, second, &format!("{} の3段目", run.marker), &tree);
        assert_stage(root, run, 3, &format!("{} の根", run.marker), &tree);
        assert_stage(second, run, 2, &format!("{} の2段目", run.marker), &tree);
        assert_stage(third, run, 1, &format!("{} の3段目", run.marker), &tree);
        // 3段目の子は無い（`type`は内部コマンド）。
        let below: Vec<&ProcessInstance> = log
            .instances
            .iter()
            .filter(|i| i.parent_seq == Some(third.seq))
            .filter(|i| is_cmd(i) || command_line(i).is_some_and(|l| l.contains(&run.marker)))
            .collect();
        assert!(
            below.is_empty(),
            "{}: 3段目の下に cmd か目印を持つ子がある: {below:?}\n{tree}",
            run.marker
        );
        seqs.extend([root.seq, second.seq, third.seq]);
        innermost.push(third.seq);
    }

    // 6. 2回の6つの番号がすべて相異なる（pid ではなくインスタンスを数えている）。
    let mut distinct = seqs.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 6, "番号が重なった: {seqs:?}\n{tree}");

    // 7. 子孫だけが書かれている: どのインスタンスも根か、親の番号が同じファイルの中にある。
    let written: std::collections::HashSet<u64> = log.instances.iter().map(|i| i.seq).collect();
    for i in &log.instances {
        assert!(
            i.is_scope_root || i.parent_seq.is_some_and(|p| written.contains(&p)),
            "根でも記録の中の親の子でもないインスタンスが書かれた（seq={}）:\n{tree}",
            i.seq
        );
        assert!(
            !command_line(i).is_some_and(|l| l.contains(&nondesc_marker)),
            "子孫でないプロセス（WMI が起こしたもの）が木に入った（seq={}）:\n{tree}",
            i.seq
        );
    }

    // 8. 3段目が読んだ目印の行は、すべて3段目の番号を持つ。対照のファイルの行は無い。
    let events = fs_audit_events(&sink);
    for (run, seq) in runs.iter().zip(&innermost) {
        let lines: Vec<&FsAuditEvent> = events
            .iter()
            .filter(|e| ends_with_ignore_case(e.path.as_deref(), &run.marker))
            .collect();
        assert!(
            !lines.is_empty(),
            "{} を読んだ行が fs-audit.jsonl に無い（{} 行あった）",
            run.marker,
            events.len()
        );
        for line in &lines {
            assert_eq!(
                line.process_sequence_number,
                Some(*seq),
                "{} の行が3段目（seq={seq}）以外の番号を持つ: {line:?}\n{tree}",
                run.marker
            );
        }
        eprintln!(
            "{}: fs-audit.jsonl の {} 行がすべて seq={seq}",
            run.marker,
            lines.len()
        );
    }
    let nondesc_lines = events
        .iter()
        .filter(|e| ends_with_ignore_case(e.path.as_deref(), &format!("{nondesc_marker}.txt")))
        .count();
    assert_eq!(
        nondesc_lines, 0,
        "子孫でないプロセスのファイル操作が fs-audit.jsonl に入った"
    );
}
