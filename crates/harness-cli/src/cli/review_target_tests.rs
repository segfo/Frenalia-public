//! `review_target`のテスト。**差分層の根は必ず一時フォルダを渡す**（実機の`%LOCALAPPDATA%`を
//! 読まない・消さない。モジュールdoc）。

use super::*;

const SESSION: &str = "session-1700000000001";

/// ワークスペースと差分層の根を、別々の一時フォルダに作る。
fn workspace_and_cow_root() -> (tempfile::TempDir, tempfile::TempDir) {
    (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
}

/// 起動時と同じ関数で、このセッションの監査の置き場を作る（段4が全セッションで作るもの）。
fn prepare_audit_dir_like_startup(ws: &Path, session_id: &str) -> PathBuf {
    let rel = harness_sandbox::session_scope::prepare_session_audit_dir(ws, session_id)
        .expect("prepare the session audit directory");
    ws.join(rel)
}

/// CoWのセッションが起動時に作る差分層（由来ファイル付き）を、一時の根の下に作る。
#[cfg(windows)]
fn cow_diff_layer(root: &Path, ws: &Path, session_id: &str) -> PathBuf {
    let dir = harness_sandbox::session_scope::cow_diff_layer_dir_in(root, session_id);
    std::fs::create_dir_all(&dir).unwrap();
    harness_sandbox::tier2a::workspace_ledger::write_cow_session_meta(&dir, ws, session_id);
    dir
}

/// `--staged`のセッションの置き場に、承認待ちの操作を1件置く。
fn staged_overlay_with_one_change(ws: &Path, session_id: &str) -> PathBuf {
    let dir = ws.join(harness_sandbox::session_scope::sandbox_dir_for_session(
        session_id,
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME),
        "{\"op\":\"create\",\"path\":\"a.txt\",\"baseline_hash\":null,\"ts_unix_millis\":1}\n",
    )
    .unwrap();
    dir
}

fn cow_target(diff_layer: &Path) -> Option<(StagingConfig, Option<PathBuf>)> {
    Some((StagingConfig::default(), Some(diff_layer.to_path_buf())))
}

// --- 段4: 監査の置き場を全セッションで作っても、変更一覧の対象を取り違えない ---

/// **CoWのセッションは、監査の置き場があっても差分層で見る。**
///
/// 段4で監査の置き場を全セッションに作るようになった。変更一覧の側がそれを
/// 「`--staged`の置き場」と読むと、一覧は空、`apply`は0件、`discard`は監査ログを消して
/// 差分層を残す。
#[cfg(windows)]
#[test]
fn a_cow_session_with_an_audit_dir_is_reviewed_through_its_diff_layer() {
    let (ws, root) = workspace_and_cow_root();
    prepare_audit_dir_like_startup(ws.path(), SESSION);
    let diff_layer = cow_diff_layer(root.path(), ws.path(), SESSION);

    assert_eq!(
        resolve_session_overlay_in(ws.path(), Some(SESSION), &[root.path().to_path_buf()]),
        cow_target(&diff_layer),
        "--session <id> で指定したCoWのセッションが、監査の置き場のせいでstagedと読まれた"
    );
    assert_eq!(
        resolve_session_overlay_in(ws.path(), None, &[root.path().to_path_buf()]),
        cow_target(&diff_layer),
        "--session を省いたとき、最新のCoWのセッションが監査の置き場のせいでstagedと読まれた"
    );
}

/// **Liveのセッションには見せる変更が無い。`discard`は失敗で終わり、監査ログは残る。**
///
/// 取り違えたときの実害がいちばん大きいのはここである——`discard`は置き場を
/// フォルダごと消すので、消えるのは承認待ちの変更ではなく監査ログになる。
#[test]
fn discarding_a_live_session_keeps_its_audit_log() {
    let ws = tempfile::tempdir().unwrap();
    let audit_dir = prepare_audit_dir_like_startup(ws.path(), SESSION);
    let log = audit_dir.join("net-audit.jsonl");
    std::fs::write(&log, "{\"kind\":\"proxy\",\"allowed\":false}\n").unwrap();

    let code = run_sandbox_subcommand_in(
        Commands::Discard {
            session: Some(SESSION.to_string()),
        },
        ws.path(),
        &[],
    );

    assert_eq!(code, ExitCode::FAILURE, "Liveのセッションに破棄する変更は無い");
    assert!(log.is_file(), "監査ログが消えた: {}", log.display());
}

/// **ポリシーエディタの記録を、最新のstagedのセッションと取り違えない。**
///
/// `.harness/sandbox/`には会話セッションの置き場のほかに`policy-editor-*`（パス1・2の記録）も
/// 並ぶ。名前を問わず最新のフォルダを選ぶと、`harness discard`が記録ごと消す。
#[test]
fn a_policy_editor_recording_is_never_taken_for_the_latest_staged_session() {
    let ws = tempfile::tempdir().unwrap();
    let recording = ws
        .path()
        .join(".harness")
        .join("sandbox")
        .join("policy-editor-4242-1700000000-1");
    std::fs::create_dir_all(&recording).unwrap();
    std::fs::write(recording.join("record-session.json"), "{}").unwrap();

    assert_eq!(resolve_session_overlay_in(ws.path(), None, &[]), None);
}

/// **許可側の対照**（`B-35`）: `--staged`のセッションは、指定しても省いても今までどおり選ばれる。
/// 禁止側だけだと、staged の解決そのものが死んでいても上の3本は緑のままになる。
#[test]
fn a_staged_session_is_still_reviewed_through_its_overlay() {
    let ws = tempfile::tempdir().unwrap();
    prepare_audit_dir_like_startup(ws.path(), SESSION);
    staged_overlay_with_one_change(ws.path(), SESSION);
    let expected = Some((
        StagingConfig {
            mode: StagingMode::Staged,
            sandbox_dir: Some(harness_sandbox::session_scope::sandbox_dir_for_session(
                SESSION,
            )),
        },
        None,
    ));

    assert_eq!(
        resolve_session_overlay_in(ws.path(), Some(SESSION), &[]),
        expected
    );
    assert_eq!(resolve_session_overlay_in(ws.path(), None, &[]), expected);
}
