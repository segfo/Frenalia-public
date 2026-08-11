//! `show`が**マニフェストに残った事実を実際に画面へ出すか**を、ビルド済みバイナリで確かめる。
//! **管理者権限は要らない**（記録は走らせず、置いたマニフェストを読ませるだけ）。
//!
//! # なぜライブラリのテストで済ませないのか
//!
//! 記録側だけ直して表示側が繋がっていない、という壊れ方を2度踏んでいる（B-08）。
//! 直近では、パス2の実行前診断がマニフェストへ正しく記録されていたのに**TUIがどこにも
//! 描画していなかった**（BUG-093の(a)）。「残っている」と「見える」は別の事実なので、
//! 表示までを1本の経路として通す。
//!
//! # 何を確かめるか
//!
//! 1. 失敗した記録では**理由が出る**（`error`/`error_kind`が画面に届く）
//! 2. 成功した記録では**理由が出ない**（対で固定する。片側だけだと「常に出る」実装でも緑になる、B-35）
//! 3. 理由の欄が入る前に書かれた古いマニフェストでも、`show`が落ちず「記録されていません」と言う

#![cfg(windows)]

use std::path::Path;
use std::process::{Command, Output};

use harness_policy_editor::session_dir::{self, RecordManifest, RecordSessionDir, RecordStatus};

fn editor_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness-policy-editor")
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(session_dir::sandbox_root(dir.path())).unwrap();
    dir
}

fn show(workspace_root: &Path, id: &str) -> Output {
    Command::new(editor_exe())
        .args(["show", "--workspace", &workspace_root.to_string_lossy(), id])
        .output()
        .expect("the policy editor binary should run")
}

fn pass2_manifest(id: &str, workspace_root: &Path) -> RecordManifest {
    let mut manifest = RecordManifest::new(
        id,
        "cargo test",
        workspace_root,
        workspace_root,
        1_700_000_000_000,
    );
    manifest.pass = 2;
    manifest.domain = Some("cargo".to_string());
    manifest
}

#[test]
fn a_failed_recording_shows_why_it_failed() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "show-failed").unwrap();
    let mut manifest = pass2_manifest("show-failed", ws.path());
    manifest.fail(
        1_700_000_001_000,
        "no_wfp",
        &"WFPの出口強制（harness-netfilterd）を起動できませんでした: engine busy",
    );
    dir.write_manifest(&manifest).unwrap();

    let output = show(ws.path(), "show-failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "show must not fail on a failed recording: {stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("記録できなかった理由"),
        "the reason must reach the screen: {stderr}"
    );
    assert!(stderr.contains("no_wfp"), "{stderr}");
    assert!(stderr.contains("engine busy"), "{stderr}");
}

/// 対の側。**成功した記録に理由の行が出てはいけない**——出ると、うまくいった実行が
/// 失敗したように読める。
#[test]
fn a_finished_recording_shows_no_failure_reason() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "show-ok").unwrap();
    let mut manifest = pass2_manifest("show-ok", ws.path());
    manifest.status = RecordStatus::Finished;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).unwrap();

    let output = show(ws.path(), "show-ok");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains("記録できなかった理由"),
        "a successful recording must not carry a failure line: {stderr}"
    );
}

/// 理由の欄が入る前に書かれたマニフェスト（実マシンに3件ある形）。**読めること**と、
/// 「理由が空だった」ではなく「記録されていない」と言うことの両方を見る（D-43）。
#[test]
fn a_manifest_from_before_the_reason_field_still_shows_something_honest() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "show-legacy").unwrap();
    let legacy = r#"{
        "schema_version": 1,
        "id": "show-legacy",
        "pass": 2,
        "domain": "cargo",
        "command": "cargo test",
        "cwd": "C:\\w",
        "workspace_root": "C:\\w",
        "started_unix_ms": 1786239920284,
        "status": "failed",
        "finished_unix_ms": 1786240063296,
        "collector_started": false,
        "etw_available": false,
        "warnings": []
    }"#;
    std::fs::write(dir.manifest_path(), legacy).unwrap();

    let output = show(ws.path(), "show-legacy");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("記録されていません"), "{stderr}");
}
