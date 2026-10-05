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
//! 4. 位置の情報がある記録（`process-audit.jsonl`を持つパス1）では、`show`が候補ごとに書く先のドメインを出し、
//!    `approve --domain`を何も書かずに断る（P4.5。CLI が画面と同じ候補の作り方に繋がっているか）。`approve`が
//!    書く側はここでは撃たない——統合試験は本物の承認台帳（`%APPDATA%`）を使うので、書く側は
//!    `position_approve_tests`（試験ごとの一時台帳）が持つ

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

/// パス1の記録を作り、プロセスの木（cmd が根、その子の pwsh）と、それぞれの通し番号で読んだファイルを書く。
///
/// 形は`process-audit.jsonl`・`fs-audit.jsonl`の書式そのもの（ライブラリの試験の補助
/// `position_view_tests::seed_position_record`・`position_candidates_tests::write_fs_events`の写し。統合試験からは
/// `cfg(test)`の補助を呼べない）。書式が変わればここも読めなくなり、下の2本が赤くなる。
fn seed_position_record(workspace_root: &Path, id: &str) {
    use harness_policy::process_event::{
        ArgvBinding, ArgvTruncation, ParentSeqSource, ProcessAuditRecord, ProcessInstance,
        PROCESS_AUDIT_SCHEMA_VERSION,
    };
    let dir = RecordSessionDir::create(workspace_root, id).unwrap();
    let mut manifest = RecordManifest::new(id, "cmd /c pwsh", workspace_root, workspace_root, 100);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).unwrap();

    let instance = |seq: u64, parent: u64, image: &str, root: bool| ProcessInstance {
        seq,
        parent_seq: Some(parent),
        parent_seq_source: ParentSeqSource::EtwField,
        pid: seq as u32,
        parent_pid: Some(parent as u32),
        image_path: Some(image.to_string()),
        argv: ArgvBinding::Exact {
            command_line: format!("\"{image}\""),
            truncation: ArgvTruncation::None,
        },
        is_scope_root: root,
        timestamp_unix_ms: 1_700_000_000_000 + seq,
    };
    let mut audit = ProcessAuditRecord::Header {
        schema_version: PROCESS_AUDIT_SCHEMA_VERSION,
    }
    .to_jsonl_line()
    .unwrap();
    audit.push('\n');
    for record in [
        instance(1, 9_000, "C:/Windows/System32/cmd.exe", true),
        instance(2, 1, "C:/Program Files/PowerShell/7/pwsh.exe", false),
    ] {
        audit.push_str(&ProcessAuditRecord::Instance(record).to_jsonl_line().unwrap());
        audit.push('\n');
    }
    std::fs::write(dir.process_audit_path(), audit).unwrap();

    let mut fs = String::new();
    for (path, seq) in [("C:/a/x", 1u64), ("C:/b/y", 2)] {
        let mut event = harness_policy::FsAuditEvent::observed(
            harness_policy::FsAuditKind::Etw,
            path,
            harness_config::FsAccess::Read,
            true,
            "record_all",
            1_700_000_000_000,
        );
        event.process_sequence_number = Some(seq);
        event.process_id = Some(seq as u32);
        fs.push_str(&event.to_jsonl_line().unwrap());
        fs.push('\n');
    }
    std::fs::write(dir.audit_log_path(), fs).unwrap();
}

/// **位置の情報がある記録では、`show`が候補ごとに書く先のドメインを出す**（画面と同じ番号・同じドメイン）。
#[test]
fn a_position_record_shows_each_candidates_domain() {
    let ws = workspace();
    seed_position_record(ws.path(), "s1");
    let output = show(ws.path(), "s1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("[workspace-shell] fs.read = C:/a/x"), "{stdout}");
    assert!(stdout.contains("[pwsh] fs.read = C:/b/y"), "{stdout}");
}

/// **位置の情報がある記録の`approve --domain`は、何も書かずに断る**（1つのドメインへ全部書くと、位置ごとに分けた
/// 意味が黙って消える）。`policy.json`は作られない。
#[test]
fn approving_a_position_record_with_a_domain_flag_writes_nothing() {
    let ws = workspace();
    seed_position_record(ws.path(), "s1");
    let output = Command::new(editor_exe())
        .args([
            "approve",
            "s1",
            "--workspace",
            &ws.path().to_string_lossy(),
            "--domain",
            "cmd",
            "--accept",
            "fs-1",
            "--yes",
        ])
        .output()
        .expect("the policy editor binary should run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("--domain は付けないでください"), "{stderr}");
    assert!(!harness_policy_editor::policy_file::path(ws.path()).exists());
}
