//! パス1（Tier1のrecord-all記録）の実機E2E。**管理者権限が要る**
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

#![cfg(windows)]

use std::path::Path;
use std::process::Command;

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
    let marker = workspace_root.join("policy-editor-e2e-marker.txt");
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
    assert!(
        stdout.contains("policy-editor-e2e-marker.txt")
            || stdout.contains(&workspace_root.to_string_lossy().replace('\\', "/")),
        "the file the command read must appear among the candidates (deny-only would show none): \
         {stdout}"
    );

    // 3. `.harness`配下は候補にしない（**提案の行だけ**を見る。監査ログのパスや除外の
    //    注記にも`.harness`は当然出てくるので、それらを含む範囲で判定すると必ず誤検出する）。
    let proposal_lines: Vec<&str> = stdout.lines().filter(|line| is_proposal_line(line)).collect();
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
    assert!(
        stdout.contains("除外: .harness"),
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
}

/// 提案1件の行か（`  fs-12    fs.read = ...`）。理由の行（`! ...`）と要約行は除く。
fn is_proposal_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("fs-") || trimmed.starts_with("net-")) && trimmed.contains(" = ")
}

/// 記録セッションが1つだけあることを前提に、そのマニフェストを読む。
fn read_only_manifest(workspace_root: &Path) -> serde_json::Value {
    let sandbox = workspace_root.join(".harness").join("sandbox");
    let mut manifests: Vec<serde_json::Value> = std::fs::read_dir(&sandbox)
        .expect("sandbox dir")
        .flatten()
        .filter_map(|entry| {
            let path = entry.path().join("record-session.json");
            let text = std::fs::read_to_string(path).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    assert_eq!(
        manifests.len(),
        1,
        "expected exactly one recording session under {}",
        sandbox.display()
    );
    manifests.remove(0)
}
