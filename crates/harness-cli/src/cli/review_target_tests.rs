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

// --- 段4以前からの穴: 変更一覧の対象の選び方 ---

/// 差分層に承認待ちの新規ファイルを1件置く（実体＋操作台帳）。
#[cfg(windows)]
fn stage_created_file_in_diff_layer(diff_layer: &Path, rel: &str, content: &str) {
    let path = diff_layer.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    let entry = harness_change_ledger::CowOpEntry {
        op: harness_change_ledger::ChangeOp::Create,
        path: rel.to_string(),
        baseline_hash: None,
        ts_unix_millis: 1_700_000_000_000,
    };
    let mut line = serde_json::to_string(&entry).unwrap();
    line.push('\n');
    std::fs::write(
        diff_layer.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME),
        line,
    )
    .unwrap();
}

/// 更新時刻の順序をはっきりさせる（同じ時刻に並ぶと「最新」の判定が運任せになる）。
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(50));
}

/// **`--session`を省いたら、このワークスペースの差分層だけを候補にする。**
///
/// かつては全ワークスペースを通して最新の差分層を選んでいた。別のリポジトリで後から
/// 作業すると、こちらで打った`harness apply`がそのリポジトリの変更をこちらへ書き、
/// `harness discard`がそちらの作業を消した。
#[cfg(windows)]
#[test]
fn without_a_session_only_this_workspaces_diff_layers_are_candidates() {
    let (ws, root) = workspace_and_cow_root();
    let other_ws = tempfile::tempdir().unwrap();
    let mine = cow_diff_layer(root.path(), ws.path(), "session-1700000000001");
    tick();
    cow_diff_layer(root.path(), other_ws.path(), "session-1700000000002");

    assert_eq!(
        resolve_session_overlay_in(ws.path(), None, &[root.path().to_path_buf()]),
        cow_target(&mine)
    );
}

/// **由来が分からない差分層は、`--session`を省いたときの候補にしない。**
/// どのワークスペースのものか確かめられないものへ、黙って`apply`/`discard`を向けない。
#[cfg(windows)]
#[test]
fn a_diff_layer_of_unknown_origin_is_not_picked_by_default() {
    let (ws, root) = workspace_and_cow_root();
    std::fs::create_dir_all(harness_sandbox::session_scope::cow_diff_layer_dir_in(
        root.path(),
        SESSION,
    ))
    .unwrap();

    assert_eq!(
        resolve_session_overlay_in(ws.path(), None, &[root.path().to_path_buf()]),
        None
    );
}

/// **古い`--staged`のセッションより、新しいCoWのセッションを選ぶ。**
/// かつてはstagedを先に探すだけだったので、放置されたstagedの置き場が1つあると
/// その後のCoWのセッションが`--session`無しでは一度も選ばれなかった。
#[cfg(windows)]
#[test]
fn the_newest_session_wins_across_staged_and_cow() {
    let (ws, root) = workspace_and_cow_root();
    staged_overlay_with_one_change(ws.path(), "session-1700000000001");
    tick();
    let newer_cow = cow_diff_layer(root.path(), ws.path(), "session-1700000000002");

    assert_eq!(
        resolve_session_overlay_in(ws.path(), None, &[root.path().to_path_buf()]),
        cow_target(&newer_cow)
    );
}

/// **`--session <stem>`（`session-`抜き）はCoWでも通る。** stagedでは元から通っていた。
#[cfg(windows)]
#[test]
fn a_session_stem_finds_a_cow_diff_layer() {
    let (ws, root) = workspace_and_cow_root();
    let diff_layer = cow_diff_layer(root.path(), ws.path(), SESSION);

    assert_eq!(
        resolve_session_overlay_in(ws.path(), Some("1700000000001"), &[root.path().to_path_buf()]),
        cow_target(&diff_layer)
    );
}

/// **同じセッションIDにstagedの置き場とCoWの差分層の両方があるとき**（別のモードで再開した）、
/// stagedに承認待ちが無ければCoWを選ぶ。常にstagedを選ぶと、空のstagedの置き場の陰で
/// CoWの変更に`--session`からは一度も届かない。
#[cfg(windows)]
#[test]
fn an_empty_staged_overlay_does_not_hide_the_cow_diff_layer_of_the_same_session() {
    let (ws, root) = workspace_and_cow_root();
    std::fs::create_dir_all(
        ws.path()
            .join(harness_sandbox::session_scope::sandbox_dir_for_session(SESSION)),
    )
    .unwrap();
    let diff_layer = cow_diff_layer(root.path(), ws.path(), SESSION);

    assert_eq!(
        resolve_session_overlay_in(ws.path(), Some(SESSION), &[root.path().to_path_buf()]),
        cow_target(&diff_layer)
    );
}

/// 対の側: stagedに承認待ちがあるなら、そちらを先に見せる（両方とも失われない）。
#[cfg(windows)]
#[test]
fn a_pending_staged_overlay_is_shown_before_the_cow_diff_layer_of_the_same_session() {
    let (ws, root) = workspace_and_cow_root();
    staged_overlay_with_one_change(ws.path(), SESSION);
    cow_diff_layer(root.path(), ws.path(), SESSION);

    let (staging, cow) =
        resolve_session_overlay_in(ws.path(), Some(SESSION), &[root.path().to_path_buf()])
            .expect("the staged overlay is found");
    assert_eq!(staging.mode, StagingMode::Staged);
    assert_eq!(cow, None);
}

/// **別のワークスペースの差分層を、今のワークスペースへ`apply`しない。**
///
/// `--session`で明示しても、記録されたワークスペースが今も在るなら拒否する（そちらで
/// `--cwd`を付けて打てばよい）。通すと、別のリポジトリの新規ファイルがこちらに書かれる
/// ——新規作成には比べる元の姿が無いので、ずれを検出する仕組みにも掛からない。
#[cfg(windows)]
#[test]
fn applying_another_workspaces_diff_layer_is_refused() {
    let (ws, root) = workspace_and_cow_root();
    let other_ws = tempfile::tempdir().unwrap();
    let theirs = cow_diff_layer(root.path(), other_ws.path(), SESSION);
    stage_created_file_in_diff_layer(&theirs, "from-the-other-repo.txt", "x");

    let code = run_sandbox_subcommand_in(
        Commands::Apply {
            session: Some(SESSION.to_string()),
            only: None,
            dangerously_allow: false,
            adopt_unledgered: false,
            keep_diff_layer: true,
            output_format: OutputFormat::Text,
        },
        ws.path(),
        &[root.path().to_path_buf()],
    );

    assert_eq!(code, ExitCode::FAILURE);
    assert!(
        !ws.path().join("from-the-other-repo.txt").exists(),
        "別のワークスペースの変更が今のワークスペースへ書かれた"
    );
    assert!(
        theirs.join("from-the-other-repo.txt").is_file(),
        "拒否したのに差分層の中身が消えた"
    );
}

/// 許可側の対照: 見るだけ（`changes`）なら、別のワークスペースの差分層も`--session`で指定できる。
#[cfg(windows)]
#[test]
fn another_workspaces_diff_layer_can_still_be_listed_by_session() {
    let (ws, root) = workspace_and_cow_root();
    let other_ws = tempfile::tempdir().unwrap();
    let theirs = cow_diff_layer(root.path(), other_ws.path(), SESSION);

    assert_eq!(
        resolve_session_overlay_in(ws.path(), Some(SESSION), &[root.path().to_path_buf()]),
        cow_target(&theirs)
    );
}
