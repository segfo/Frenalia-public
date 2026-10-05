//! パス1（Tier0のrecord-all記録）の実機E2E。**管理者権限が要る**
//! （収集器が張るETWリアルタイムセッションのため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-record`
//! （`crates/dev-elevated-runner/src/lib.rs`の`KNOWN_TARGETS`にキーを登録済み）。
//!
//! # なぜ`record()`を直接呼ばず、ビルド済みバイナリを起動するのか
//!
//! 収集器の実行ファイルは`current_exe()`の**隣**から解決される
//! （`policy_learnd::client::collector_exe_path`。PATHからは探さない）。cargo testの
//! `current_exe`は`target/debug/deps/<test>-<hash>.exe`なので、隣に
//! `harness-policy-learnd.exe`が居ない——ライブラリを直接呼ぶ形では**本番と同じ解決経路を
//! 通れない**。`CARGO_BIN_EXE_*`でビルド済みの`harness-policy-editor.exe`を起動すれば、
//! 実運用とまったく同じ配置・同じ解決経路で走る。
//!
//! # 何を確かめるか（B-27: 歯のあるテストにする）
//!
//! 1. 子プロセスの出力が記録モードを**通り抜けて**届く（境界印の切り分けが出力を食わない）
//! 2. record-allが**成功したアクセス**を拾う（deny-onlyなら0件になる）——読んだファイルが候補に出る
//! 3. `.harness`配下が候補に出ない（P-08・自己参照ループの防止）
//! 4. 記録セッションのマニフェストが`finished`で閉じる（`running`のまま残らない）
//! 5. 同じ記録のディレクトリにプロセスの木（`process-audit.jsonl`、決定23）が書かれ、記録の根がある。
//!    読んだファイルの`fs-audit.jsonl`の行は、その木の中のインスタンスの通し番号を持つ（P2e）

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use harness_policy::event::FsAuditEvent;
use harness_policy::process_event::{parse_process_audit, PROCESS_AUDIT_FILE};

fn editor_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness-policy-editor")
}

#[test]
#[ignore = "requires administrator rights (the collector opens an ETW real-time session)"]
fn recording_a_command_captures_the_files_it_read_and_never_proposes_the_control_directory() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    std::fs::create_dir_all(workspace_root.join(".harness").join("sandbox")).unwrap();

    // 記録対象が読むファイルと、**読んでも候補にしてはいけない**ファイル。
    //
    // **印のファイルはworkspaceの外・`%TEMP%`の外へ置く。** `exclusion.rs`の規則4が
    // 「このセッションのworkspace配下」を、規則5が「`%TEMP%`配下（ルート自身を含む）」を
    // **候補から外す**ので、workspace内（`tempfile::tempdir()`なので`%TEMP%`配下でもある）に
    // 置いたファイルは、正しく観測できていても候補には出ない。
    // かつてここはworkspace内に置いており、その決定が入った時点から赤のままだった
    // （BUG-153）。**候補に出ることを測りたいなら、候補になり得る場所へ置く。**
    let external =
        std::path::PathBuf::from(format!("C:\\harness-e2e-record-{}", std::process::id()));
    std::fs::create_dir_all(&external).expect("create the external read target");
    let _external_cleanup = RemoveDirOnDrop(external.clone());
    let marker = external.join("policy-editor-e2e-marker.txt");
    std::fs::write(&marker, b"marker-content").unwrap();
    let control_file = workspace_root.join(".harness").join("settings.json");
    std::fs::write(&control_file, b"{}").unwrap();

    // 両方読ませる。`.harness`側も実際に読ませることで、「観測はしたが候補にしない」
    // という区別が効いていることを確かめられる。
    let command = format!(
        "Get-Content -Raw '{}'; Get-Content -Raw '{}'",
        marker.display(),
        control_file.display()
    );

    let output = Command::new(editor_exe())
        .args([
            "record",
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--cwd",
            &workspace_root.to_string_lossy(),
            "--limit",
            "0",
            "--",
            &command,
        ])
        // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .output()
        .expect("the policy editor binary should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "record should succeed: {stdout}\n{stderr}"
    );

    // 1. 子プロセスの出力が届いている（境界印の切り分けが本文を食っていない）。
    assert!(
        stdout.contains("marker-content"),
        "the child's stdout must reach the caller: {stdout}"
    );

    // 2. record-allが成功アクセスを拾っている。
    //
    // **workspace側を`||`の逃げ道にしない。** かつては「印のファイル名 **または** workspaceの
    // パス」で合格にしていたが、workspaceは規則4で候補から外れるので後者は永久に偽であり、
    // 実質は前者1本だった。いまは印を候補になり得る場所へ置いてあるので、名指しで測る。
    assert!(
        stdout.contains("policy-editor-e2e-marker.txt"),
        "the file the command read must appear among the candidates (deny-only would show none): \
         {stdout}"
    );

    // 3. `.harness`配下は候補にしない（**提案の行だけ**を見る。監査ログのパスや除外の
    //    注記にも`.harness`は当然出てくるので、それらを含む範囲で判定すると必ず誤検出する）。
    let proposal_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| is_proposal_line(line))
        .collect();
    assert!(
        !proposal_lines.is_empty(),
        "record-all must produce at least one candidate: {stdout}"
    );
    for line in &proposal_lines {
        assert!(
            !line.contains(".harness"),
            "the harness control directory must never be proposed (P-08): {line}"
        );
    }
    // **文言はリテラルで持たない。** ここはかつて`除外: .harness`を探しており、実装が
    // `除外: harnessの制御ディレクトリ配下`へ書き直されたあと、**テストだけが古い綴りを
    // 探し続けて赤のまま**だった（BUG-153）。定数を参照すれば、文言を直した側に自動で追随する。
    assert!(
        stdout.contains(harness_policy_editor::aggregate::EXCLUDED_CONTROL_DIR_NOTICE),
        "the excluded count must be reported instead of silently dropped: {stdout}"
    );

    // 4. マニフェストが閉じている（`running`のまま残らない）。
    let manifest = read_only_manifest(workspace_root);
    assert_eq!(
        manifest["status"], "finished",
        "the manifest must be closed out: {manifest}"
    );
    assert!(
        manifest["collector_started"].as_bool().unwrap_or(false),
        "the elevated collector must have started: {manifest}"
    );
    assert!(
        manifest["etw_available"].as_bool().unwrap_or(false),
        "the ETW session must have been opened (are we elevated?): {manifest}"
    );

    // 5. プロセスの木が本番の経路で書かれている（決定23。依頼側が先に作り、収集プロセスが書く）。
    let record_dir = only_record_dir(workspace_root);
    let audit_path = record_dir.join(PROCESS_AUDIT_FILE);
    let audit_text = std::fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("{} must exist: {e}", audit_path.display()));
    let tree =
        parse_process_audit(&audit_text).expect("process-audit.jsonl starts with its header");
    eprintln!("--- process-audit.jsonl ---\n{audit_text}");
    assert!(
        tree.instances.iter().any(|i| i.is_scope_root),
        "the recording's root process must be in the process tree: {tree:?}"
    );
    assert!(
        tree.controls
            .iter()
            .any(|c| c.starts_with("process_tree_summary:")),
        "the tree writer must have been closed out (summary control record): {tree:?}"
    );
    // 読んだファイルの行は、木の中のインスタンスの通し番号を持つ（`fs-audit.jsonl`と木を番号で結べる）。
    let seqs: std::collections::HashSet<u64> = tree.instances.iter().map(|i| i.seq).collect();
    let marker_lines: Vec<FsAuditEvent> =
        std::fs::read_to_string(record_dir.join("fs-audit.jsonl"))
            .expect("fs-audit.jsonl")
            .lines()
            .filter_map(|line| serde_json::from_str::<FsAuditEvent>(line).ok())
            .filter(|e| {
                e.path
                    .as_deref()
                    .is_some_and(|p| p.ends_with("policy-editor-e2e-marker.txt"))
            })
            .collect();
    assert!(
        !marker_lines.is_empty(),
        "the marker read must be in fs-audit.jsonl"
    );
    for line in &marker_lines {
        assert!(
            line.process_sequence_number
                .is_some_and(|seq| seqs.contains(&seq)),
            "the marker read must carry a sequence number found in the process tree: {line:?}"
        );
    }
}

/// 提案1件の行か（`  fs-12    fs.read = ...`）。理由の行（`! ...`）と要約行は除く。
fn is_proposal_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("fs-") || trimmed.starts_with("net-")) && trimmed.contains(" = ")
}

/// 記録セッションが1つだけあることを前提に、そのマニフェストを読む。
fn read_only_manifest(workspace_root: &Path) -> serde_json::Value {
    let path = only_record_dir(workspace_root).join("record-session.json");
    let text = std::fs::read_to_string(&path).expect("record-session.json");
    serde_json::from_str(&text).expect("record-session.json is JSON")
}

/// 記録セッションのディレクトリ（`record-session.json`を持つもの）が1つだけあることを確かめて返す。
fn only_record_dir(workspace_root: &Path) -> PathBuf {
    let sandbox = workspace_root.join(".harness").join("sandbox");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&sandbox)
        .expect("sandbox dir")
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("record-session.json").is_file())
        .collect();
    assert_eq!(
        dirs.len(),
        1,
        "expected exactly one recording session under {}",
        sandbox.display()
    );
    dirs.remove(0)
}

/// テストがassertで落ちても、`C:\`直下に作った読み取り対象を必ず消す（`型F`）。
/// 末尾の`let _ = remove_dir_all`は正常終了時にしか走らない。
struct RemoveDirOnDrop(std::path::PathBuf);

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
