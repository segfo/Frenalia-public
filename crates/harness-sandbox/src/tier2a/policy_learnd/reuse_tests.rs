//! D-56 段階2（収集器daemonの寿命をプロセスへ合わせる）のテスト。
//!
//! **昇格を要さない範囲だけをここに置く。** ETWセッションを実際に張る機構E2Eは
//! `dev-elevated-runner`から回す（`docs/DEV-ENVIRONMENT.md`）。ここで固定するのは
//! 「プロトコルが要求の連続を捌けること」と「再利用失敗の分岐」である。

use std::path::PathBuf;

use super::client::daemon_is_dead;
use super::{LearnError, LearnRequest, LearnResponse};
use crate::win_pipe_ipc::{connect_with_timeout, read_framed_timeout, write_framed_timeout};

fn short_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(20)
}

/// 再利用に失敗したとき、起こし直す価値があるかの真理値表。
///
/// **`Rejected`で起こし直してはいけない**——受信側は生きていて要求を拒んだのだから、
/// 起こし直しても同じ拒否に着く。増えるのはUACの回数だけである。
#[test]
fn only_a_dead_daemon_is_worth_restarting() {
    assert!(!daemon_is_dead(&LearnError::Rejected("bad path".into())));

    assert!(daemon_is_dead(&LearnError::Ipc("broken pipe".into())));
    assert!(daemon_is_dead(&LearnError::Win32("handle invalid".into())));
    assert!(daemon_is_dead(&LearnError::ElevationDeclined("uac".into())));
    assert!(daemon_is_dead(&LearnError::UnsafeLaunchTarget(
        "writable dir".into()
    )));
}

/// **テストバイナリの隣にある実`harness-policy-learnd.exe`が、段階2のプロトコルを喋るか。**
///
/// 非昇格で走る（収集していない状態の`StopCollect`はETWへ一度も触らない）。
///
/// これは**古いdaemonを黙って測ることの検出器**でもある。実daemonを起動するテストは
/// `target/debug/harness-policy-learnd.exe`をコピーして使うが、`cargo test -p harness-sandbox`は
/// 別パッケージであるそのバイナリを**リビルドしない**——ライブラリだけ直してビルドし忘れると、
/// 直したはずの挙動を確かめたつもりで前のビルドを測ることになる（netfilterd側の同型テストと
/// 同じ理由。BUG-056の「0件マッチで緑」と同じクラスの事故を防ぐ）。
///
/// 旧プロトコルのdaemonは:
/// - `StopCollect`というバリアントを知らないので`Err`を返し、
/// - そもそも1往復固定なので`StartCollect`以外の最初の要求で終了する。
#[test]
fn the_real_collector_next_to_the_test_binary_speaks_the_reusable_protocol() {
    let collector = ensure_collector_next_to_test_binary();
    let prepared = super::client::prepare_pipe().expect("prepare pipe");
    let pipe_name = prepared.name().to_string();
    let server = prepared.into_handle();

    let mut child = std::process::Command::new(&collector)
        .arg(&pipe_name)
        .spawn()
        .expect("spawn the real policy-learnd");
    connect_with_timeout(server, short_timeout()).expect("the collector should connect");

    let ask = |request: LearnRequest| -> LearnResponse {
        let bytes = serde_json::to_vec(&request).expect("serialize");
        write_framed_timeout(server, &bytes, short_timeout()).expect("write request");
        let response = read_framed_timeout(server, short_timeout()).expect("read response");
        serde_json::from_slice(&response).expect("parse response")
    };

    match ask(LearnRequest::StopCollect) {
        LearnResponse::Stopped { written } => assert_eq!(written, 0),
        other => panic!(
            "the collector next to the test binary answered {other:?} to StopCollect. It is \
             almost certainly a stale build that predates D-56 stage 2 -- run \
             `cargo build --workspace` and re-run. Without this check, the tests that drive the \
             real collector would silently measure the previous binary."
        ),
    }
    // **畳んだあとも接続が生きている**ことまで確かめる（1往復固定ならここで切れている）。
    match ask(LearnRequest::Teardown) {
        LearnResponse::TornDown { denials_written } => assert_eq!(denials_written, 0),
        other => panic!("expected TornDown after StopCollect, got {other:?}"),
    }

    let status = child.wait().expect("wait for the collector");
    assert!(
        status.success(),
        "the collector should exit cleanly after a Teardown: {status:?}"
    );
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(server);
    }
}

/// [BUG-098] **記録の切れ目で黙って消えない。** 1件受けたあとの待機は時間で打ち切らない。
///
/// # これが本体である（D-56の目的そのもの）
///
/// D-56が消したかったのは「ポリシーエディタが1回の起動で記録を何度も走らせるのに、
/// 実行のたびにdaemonを起こし直してUACが出る」だった。**ユーザーが出力を見て考えている時間**を
/// 待てなければ、その決定は成立しない。
///
/// 旧実装は待機中も60秒で打ち切って**終了していた**。60秒考えると収集器が消え、
/// 次の記録でパイプが切れているので起こし直し＝UACが1回増える。
///
/// # なぜ実際に待つのか（短くできない）
///
/// 旧実装と新実装の違いは**60秒を越えたところにしか現れない**。縮めるには製品側へ
/// 「テスト用に短くする口」を足すことになるが、それは**昇格したプロセスの寿命を
/// 外から縮められる口**であり、作らない。だからこのテストは実時間で待つ。
///
/// `#[ignore]`なのは実行時間のためで、昇格は要らない（`StopCollect`はETWへ一度も触らない）。
#[test]
#[ignore = "waits out the old 60s idle timeout in real time; run via dev-elevated-runner policy-learnd-reuse"]
fn the_collector_survives_a_gap_longer_than_the_handshake_timeout() {
    let collector = ensure_collector_next_to_test_binary();
    let prepared = super::client::prepare_pipe().expect("prepare pipe");
    let pipe_name = prepared.name().to_string();
    let server = prepared.into_handle();

    let mut child = std::process::Command::new(&collector)
        .arg(&pipe_name)
        .spawn()
        .expect("spawn the real policy-learnd");
    connect_with_timeout(server, short_timeout()).expect("the collector should connect");

    // **失敗を`String`へ畳む。** ここで見たいのは「応答が返るか」だけで、返らなかったときの
    // 種別（書込で落ちたか読取で落ちたか）は結論を変えない——どちらもdaemonが消えた証拠である。
    let ask = |request: LearnRequest| -> Result<LearnResponse, String> {
        let bytes = serde_json::to_vec(&request).expect("serialize");
        write_framed_timeout(server, &bytes, short_timeout())
            .map_err(|e| format!("write failed: {e}"))?;
        let response = read_framed_timeout(server, short_timeout())
            .map_err(|e| format!("read failed: {e}"))?;
        Ok(serde_json::from_slice(&response).expect("parse response"))
    };

    // 1件目を受けさせる。**ここを通ってからが「待機中」である**（1件目だけは短く待つ側に
    // 留まるので、これを送らないと旧実装と同じ時間で畳まれて測定にならない）。
    match ask(LearnRequest::StopCollect).expect("first request") {
        LearnResponse::Stopped { .. } => {}
        other => panic!("expected Stopped for the first request, got {other:?}"),
    }

    // ハンドシェイク待ちの時間（60秒）より確実に長く空ける。
    std::thread::sleep(std::time::Duration::from_secs(75));

    // **まだ生きているか。** 旧実装ではここでプロセスが消えており、書込か読取が失敗する。
    let after_the_gap = ask(LearnRequest::StopCollect);
    let still_alive = matches!(after_the_gap, Ok(LearnResponse::Stopped { .. }));

    // 生死を確かめてから畳む（畳む要求自体も、生きていなければ通らない）。
    let teardown = ask(LearnRequest::Teardown);
    let _ = child.wait();
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(server);
    }

    assert!(
        still_alive,
        "[BUG-098] the collector went away during a 75s gap between recordings. \
         D-56 binds this daemon's lifetime to the calling process, not to a timer -- a daemon \
         that expires while the user is reading the output re-creates the extra UAC prompt that \
         D-56 was written to remove. got {after_the_gap:?}"
    );
    assert!(
        matches!(teardown, Ok(LearnResponse::TornDown { .. })),
        "the connection must still carry a Teardown after the gap: {teardown:?}"
    );
}

/// **壊れた要求1件で接続を畳まない。** 畳むと、回復可能な失敗がUACの追加1回になる。
///
/// 併せて「拒否されたあとも要求を受け付ける」ことを固定する——ここが切れていると、
/// 検証に落ちた`StartCollect`のたびにdaemonを起こし直すことになる。
#[test]
fn a_rejected_request_does_not_kill_the_connection() {
    let collector = ensure_collector_next_to_test_binary();
    let prepared = super::client::prepare_pipe().expect("prepare pipe");
    let pipe_name = prepared.name().to_string();
    let server = prepared.into_handle();

    let mut child = std::process::Command::new(&collector)
        .arg(&pipe_name)
        .spawn()
        .expect("spawn the real policy-learnd");
    connect_with_timeout(server, short_timeout()).expect("the collector should connect");

    let ask = |request: LearnRequest| -> LearnResponse {
        let bytes = serde_json::to_vec(&request).expect("serialize");
        write_framed_timeout(server, &bytes, short_timeout()).expect("write request");
        let response = read_framed_timeout(server, short_timeout()).expect("read response");
        serde_json::from_slice(&response).expect("parse response")
    };

    // 昇格側の`validate_request`が必ず弾く形（プロファイル名が規約外）。
    let rejected = ask(LearnRequest::StartCollect(super::LearnPolicy {
        session_profile: "not-a-harness-profile".to_string(),
        workspace_root: PathBuf::from("C:/work"),
        fs_audit_log_path: PathBuf::from("C:/work/.harness/sandbox/x/fs-audit.jsonl"),
        harness_pid: None,
        spawn_daemon_pid: None,
        record_all: false,
        capture_argv: false,
    }));
    assert!(
        matches!(rejected, LearnResponse::Err(_)),
        "an invalid profile name must be refused: {rejected:?}"
    );

    // **接続はまだ生きている。**
    match ask(LearnRequest::Teardown) {
        LearnResponse::TornDown { .. } => {}
        other => panic!("the connection must survive a rejected request, got {other:?}"),
    }

    let status = child.wait().expect("wait for the collector");
    assert!(status.success(), "{status:?}");
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(server);
    }
}

/// **機構E2E（要管理者権限）**: 実収集器を`StartCollect → StopCollect → StartCollect →
/// Teardown`と駆動し、**世代の状態が持ち越されない**ことを確かめる。
///
/// 固定するのは3点:
/// 1. 2回目の`StartCollect`でもETWセッションが**張り直される**（`etw_available == true`）。
///    張り直していなければ、`StopCollect`で止めたセッションのまま2回目が始まっている。
/// 2. 2回目の書込先は**2回目に渡したsink**である（1回目のJSONLは伸びない）。
///    持ち越すと「記録1回＝1ディレクトリ」が崩れ、前の記録が今回の候補に混ざる。
/// 3. `Teardown`まで**1本の接続**で通る（1往復固定なら途中で切れる）。
///
/// `etw_available`を真だと主張するのがこのテストが昇格を要する理由である
/// ——非昇格ではfail-openで偽が返り、応答の形だけ見るテストは緑のまま通ってしまう（B-35）。
#[test]
#[ignore = "requires administrator (starts a real ETW session); run via dev-elevated-runner"]
fn a_second_generation_starts_a_fresh_session_and_a_fresh_sink() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let sink_dir = workspace.path().join(".harness").join("sandbox");
    let first = sink_dir.join("gen-1");
    let second = sink_dir.join("gen-2");
    std::fs::create_dir_all(&first).expect("create gen-1");
    std::fs::create_dir_all(&second).expect("create gen-2");

    let policy_for = |dir: &std::path::Path| super::LearnPolicy {
        session_profile: crate::tier2a::session_profile::current_profile_name(),
        workspace_root: workspace.path().to_path_buf(),
        fs_audit_log_path: dir.join("fs-audit.jsonl"),
        harness_pid: Some(std::process::id()),
        spawn_daemon_pid: None,
        record_all: false,
        capture_argv: false,
    };

    let mut session = super::client::CollectorSession::new();
    let started = session
        .start(None, false, policy_for(&first), None)
        .expect("start the collector (UAC)");
    assert!(
        started.etw_available,
        "the ETW session must actually be established -- if this is false the test is running \
         without administrator rights and proves nothing"
    );
    assert!(!started.reused, "the first start cannot be a reuse");

    session.stop().expect("stop the first generation");

    let restarted = session
        .start(None, false, policy_for(&second), None)
        .expect("start the second generation (must not prompt for UAC)");
    assert!(
        restarted.reused,
        "the second generation must reuse the running daemon (this is the same statement as \
         'no UAC prompt appeared')"
    );
    assert!(
        restarted.etw_available,
        "the ETW session has to be re-established for the second generation"
    );

    let first_len_before = std::fs::metadata(first.join("fs-audit.jsonl"))
        .map(|m| m.len())
        .unwrap_or(0);
    // 2世代目で観測される何かを起こす（このプロセス自身のFS I/Oはスコープ外なので、
    // ここで確かめられるのは「1世代目のsinkが伸びない」ことである——それが持ち越しの症状）。
    std::thread::sleep(std::time::Duration::from_millis(500));
    session.stop().expect("stop the second generation");

    let first_len_after = std::fs::metadata(first.join("fs-audit.jsonl"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert_eq!(
        first_len_before, first_len_after,
        "the second generation must not write into the first generation's audit log"
    );
    assert!(
        second.join("fs-audit.jsonl").exists(),
        "the second generation must write into its own directory"
    );
    // dropで`Teardown`が飛ぶ（1本の接続で全部通ったことの確認を兼ねる）。
    drop(session);
}

/// 実`harness-policy-learnd.exe`をテストバイナリの隣へ置く（netfilterd側と同じ理由・同じ形）。
///
/// `client::collector_exe_path`は**本体exeと同じディレクトリ**から解決するが、テストから見た
/// 「本体exe」は`target/debug/deps/`のテストバイナリなので、そのままでは空振りする。
/// **見つからないことを`SKIP`で流さない**——「テストが走っていない」と「テストが通った」が
/// 区別できなくなる（BUG-056）。
/// **段階6dのE2E（`argv_e2e_tests`）も同じものを使う。** コピーを作ると、
/// 「古いビルドを黙って測らない」という性質を片方だけ直す日が来る。
pub(super) fn ensure_collector_next_to_test_binary() -> PathBuf {
    static PLACED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PLACED
        .get_or_init(place_collector_next_to_test_binary)
        .clone()
}

fn place_collector_next_to_test_binary() -> PathBuf {
    let current = std::env::current_exe().expect("resolve the test binary path");
    let dir = current.parent().expect("test binary has a parent");
    let target = dir.join("harness-policy-learnd.exe");
    let build_output = dir
        .parent() // target/debug/deps -> target/debug
        .map(|dir| dir.join("harness-policy-learnd.exe"));

    let Some(source) = build_output.filter(|p| p.exists()) else {
        assert!(
            target.exists(),
            "harness-policy-learnd.exe was found neither next to the test binary ({}) nor in the \
             cargo output directory above it. Run `cargo build --workspace` first.",
            target.display()
        );
        return target;
    };

    // 既に同じものがあるならコピーしない（実行中のdaemonがあると上書きに失敗する）。
    // **サイズか更新時刻が違えば必ず上書きする**——古いコピーを黙って測ると、直したはずの
    // 挙動を確かめたつもりで前のビルドを測ることになる。
    let same = (|| -> Option<bool> {
        let (a, b) = (
            std::fs::metadata(&source).ok()?,
            std::fs::metadata(&target).ok()?,
        );
        Some(a.len() == b.len() && a.modified().ok()? == b.modified().ok()?)
    })()
    .unwrap_or(false);
    if !same {
        std::fs::copy(&source, &target).unwrap_or_else(|e| {
            panic!(
                "failed to place a fresh {} next to the test binary ({e}). If a previous \
                 harness-policy-learnd.exe is still running, stop it and re-run.",
                target.display()
            )
        });
    }
    target
}
