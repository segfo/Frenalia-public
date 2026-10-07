//! [`super`]（Daemon 側の許可した生成の記録の書き手）の試験。昇格もパイプも要らない。

use super::*;

/// 記録のディレクトリの名前（`policy-editor-<セッション>-<連番>`）は受け付ける。
#[test]
fn a_plain_record_dir_name_is_accepted() {
    assert_eq!(record_dir_name_problem("policy-editor-1234-5678-1"), None);
}

/// **パスの1要素でない名前は断る**——断らないと、ホストが指定した任意の場所へ Daemon が追記する。
#[test]
fn separators_dot_prefixes_and_empty_names_are_refused() {
    for name in [
        "",
        ".",
        "..",
        "..\\x",
        "a\\b",
        "a/b",
        "C:x",
        ".hidden",
        "a\u{0}b",
    ] {
        assert!(
            record_dir_name_problem(name).is_some(),
            "{name:?} must be refused"
        );
    }
}

fn record_dir(workspace: &Path, name: &str) -> PathBuf {
    let dir = workspace.join(".harness").join("sandbox").join(name);
    std::fs::create_dir_all(&dir).expect("record dir");
    dir
}

/// 名前を受け取らなかった（`harness.exe`）なら何も書かず、ファイルも作らない。
#[test]
fn without_a_record_nothing_is_written() {
    let ws = tempfile::tempdir().expect("tempdir");
    let audit = SpawnAudit::open(&ws.path().to_string_lossy(), None).expect("open");
    audit.spawned_with(1, Some(2), "d", "C:/x.exe", true);
    audit.finish();
    assert!(!ws.path().join(".harness").exists());
}

/// **ファイルが無ければ断り、作らない**（作るのはホスト。書き手にファイルを作らせない）。
#[test]
fn a_missing_file_is_refused_instead_of_created() {
    let ws = tempfile::tempdir().expect("tempdir");
    let dir = record_dir(ws.path(), "policy-editor-1-1");
    let error = SpawnAudit::open(&ws.path().to_string_lossy(), Some("policy-editor-1-1"))
        .err()
        .expect("must refuse");
    assert!(error.contains("does not exist"), "{error}");
    assert!(!dir.join(SPAWN_AUDIT_FILE).exists(), "the daemon created the file");
}

/// 版の行を先に書き、上限を超えた生成は書かずに数え、畳むときに1行だけ報告する。読む側の関数で読み戻せる。
#[test]
fn lines_beyond_the_cap_are_counted_and_reported_once() {
    let ws = tempfile::tempdir().expect("tempdir");
    let dir = record_dir(ws.path(), "policy-editor-1-2");
    std::fs::write(dir.join(SPAWN_AUDIT_FILE), b"").expect("precreate");
    let audit =
        SpawnAudit::open_with_limit(&ws.path().to_string_lossy(), Some("policy-editor-1-2"), 2)
            .expect("open");
    audit.spawned_with(10, Some(100), "workspace-shell", "C:/sh.exe", true);
    audit.spawned_with(11, None, "child", "C:/c.exe", false);
    audit.spawned_with(12, Some(102), "child", "C:/c.exe", false);
    audit.finish();
    audit.finish();
    let text = std::fs::read_to_string(dir.join(SPAWN_AUDIT_FILE)).expect("read");
    let log = harness_policy::spawn_audit::parse_spawn_audit(&text).expect("parse");
    assert_eq!(log.spawned, 2, "{text}");
    assert_eq!(log.without_sequence_number, 1);
    assert_eq!(log.dropped, 1, "{text}");
    assert_eq!(
        log.domains_by_sequence.get(&100).map(String::as_str),
        Some("workspace-shell")
    );
    assert_eq!(text.matches("\"overflow\"").count(), 1, "{text}");
}

/// 自分のプロセスハンドルで通し番号が取れる（0 は「番号が無い」なので返らない）。**Daemon が起こした子の値と ETW の値の
/// 一致は、ここでは測らない**（P6 の昇格E2E）。
#[test]
fn the_sequence_number_of_this_process_is_found() {
    let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let seq = process_sequence_number(process).expect("query");
    assert_ne!(seq, 0);
}
