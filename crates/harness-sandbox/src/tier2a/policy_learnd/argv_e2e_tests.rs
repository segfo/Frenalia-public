//! [段階6d] argv観測の機構E2E（**要管理者権限**。`dev-elevated-run.exe policy-learn-argv`）。
//!
//! # ここでしか測れないもの
//!
//! 単体テスト（`observed_tests`・`client_tests`）は**行の形と断り方**を固定するが、
//! 次の2つは実機でしか成立しない。
//!
//! 1. **実際に起こしたコマンドのコマンドラインが`observed.jsonl`の行になる**
//!    ——2つのETWセッション（マニフェスト＝実行ファイルのフルパス、MOF＝コマンドライン）が
//!    両方張れて、pidで突き合わせが成立して初めて1行になる。単体では全部作り物になる
//! 2. **枠が無ければ記録が始まらない**（§10.3 fail-closed）——`ERROR_NO_SYSTEM_RESOURCES`は
//!    マシン全体の資源が埋まったときにしか返らない
//!
//! # 撃ち方
//!
//! ```text
//! target/debug/dev-elevated-run.exe policy-learn-argv
//! ```
//!
//! **`harness-policy-learnd.exe`はテストのビルドでは作り直されない。** 収集器側へ効く変更を
//! したら先に`cargo build --workspace --exclude dev-elevated-runner`を撃つこと
//! （`reuse_tests`の`the_real_collector_next_to_the_test_binary_speaks_the_reusable_protocol`が
//! 古いビルドを測っていないかの検出器になっている）。

use std::path::Path;

use super::etw::mof::MofFsSession;
use super::observed::{observed_path, ObservedRecord, Spawn};
use super::LearnPolicy;

/// 観測が配送され始めるまでの待ち（既存スパイクの実測値と同じ）。
const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
/// 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上）。
const DRAIN: std::time::Duration = std::time::Duration::from_secs(4);

/// `process_audit_e2e_tests`も同じ形で呼ぶ（写さない）。
pub(super) fn policy_for(workspace: &Path, sink_dir: &Path, capture_argv: bool) -> LearnPolicy {
    LearnPolicy {
        session_profile: crate::tier2a::session_profile::current_profile_name(),
        workspace_root: workspace.to_path_buf(),
        fs_audit_log_path: sink_dir.join("fs-audit.jsonl"),
        harness_pid: Some(std::process::id()),
        spawn_daemon_pid: None,
        // パス1と同じ形（隔離せず全アクセスを録る）。
        record_all: true,
        capture_argv,
    }
}

/// **測る前に、測る相手が現行のビルドであることを確かめる。**
///
/// `CollectorSession`は**本体exeと同じディレクトリ**から収集器を解決するが、テストから見た
/// 「本体exe」は`target/debug/deps/`のテストバイナリである。そこに置かれたコピーは
/// `cargo test -p harness-sandbox`では作り直されないので、**古い個体を測ることがある**
/// （実際に1回踏んだ——版ずれの検問が先に火を噴いた）。
/// 置き直しは`reuse_tests`の実装をそのまま使う（同じ性質の複製を作らない）。
fn fresh_collector_next_to_the_test_binary() {
    let _ = super::reuse_tests::ensure_collector_next_to_test_binary();
}

fn spawns(path: &Path) -> Vec<Spawn> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| match serde_json::from_str::<ObservedRecord>(line) {
            Ok(ObservedRecord::ObservedSpawn(spawn)) => Some(spawn),
            Ok(ObservedRecord::Overflowed { .. }) => None,
            Err(e) => panic!("候補の行が読めない（{e}）: {line}"),
        })
        .collect()
}

/// **記録中に起こしたコマンドのargvが候補の行になる。**
///
/// 固定するのは3点。
///
/// 1. 行が出ること（2つのセッションが張れて、pidで突き合わせが成立したこと）
/// 2. `exe`が**フルパス**であること——MOFの`ImageFileName`は葉の名前しか持たないので、
///    ここが`cmd.exe`だけなら**突き合わせをやめてMOF側の値を載せている**
/// 3. `argv`に起こしたときの引数がそのまま入っていること
#[test]
#[ignore = "requires administrator (starts real ETW sessions); run via dev-elevated-runner"]
fn a_command_started_during_the_recording_becomes_a_candidate() {
    fresh_collector_next_to_the_test_binary();
    let workspace = tempfile::tempdir().expect("tempdir");
    let sink_dir = workspace.path().join(".harness").join("sandbox").join("g-1");
    std::fs::create_dir_all(&sink_dir).expect("create sink dir");
    let marker = format!("harness-argv-e2e-{}", std::process::id());

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
        "FS側のETWセッションが張れていない＝管理者権限で走っていない。この状態の緑は何も\
         証明しない"
    );

    std::thread::sleep(WARMUP);
    // **このプロセスの直接の子**として起こす（パス1でharnessが対象コマンドを起こすのと同じ形。
    // スコープ判定は`harness_pid`からの親子継承で決まる）。
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "echo", &marker])
        .status()
        .expect("spawn cmd.exe");
    assert!(status.success());
    std::thread::sleep(DRAIN);

    session.stop().expect("stop the recording");
    drop(session);

    let path = observed_path(workspace.path());
    let written = spawns(&path);
    let found = written
        .iter()
        .find(|spawn| spawn.argv.contains(&marker))
        .unwrap_or_else(|| {
            panic!(
                "起こしたコマンドのargvが候補になっていない。{} 行あった: {:#?}\n\
                 （制御レコード側の理由は {} を見る）",
                written.len(),
                written,
                sink_dir.join("fs-audit.jsonl").display()
            )
        });

    let exe = found.exe.to_ascii_lowercase();
    assert!(
        exe.ends_with("cmd.exe") && exe.contains(':'),
        "exeがフルパスでない（{}）。MOF側の`ImageFileName`は葉の名前しか持たないので、\
         これは突き合わせをやめてMOFの値を載せている",
        found.exe
    );
    assert!(
        found.argv.contains("echo"),
        "argvが起こしたときの綴りを保っていない: {}",
        found.argv
    );
}

/// **枠が無ければ記録は始まらない**（§10.3 fail-closed）。
///
/// argv観測はprivate system loggerを1本使い、この枠は**マシン全体で8本**しかない。
/// 埋まった状態で`StartCollect`を投げ、**収集器が「始めなかった」と答える**ことを固定する。
///
/// # 対照を先に撃つ（**この測定が成立する条件**）
///
/// **断り方は、枠が無いときと収集器の版が古いときで同じ変種になる。** だから
/// 「断られた」だけでは、どちらが起きたのか言えない——実際に1回、版ずれの側で
/// この測定が緑になりかけた。そこで**枠を埋める前に1回成功させる**（正の対照）。
/// 成功すれば、そのあとの失敗は**枠が無いこと以外に説明が付かない**。
///
/// **前提が作れなかったときに緑で流さない**——枠を埋め切れなければ、この測定は
/// 「fail-closedが効いた」ことを何も言えないので、その旨を出して落とす（BUG-056の型）。
#[test]
#[ignore = "requires administrator (exhausts the machine-wide system logger slots); run via dev-elevated-runner"]
fn a_recording_is_refused_when_no_system_logger_slot_is_left() {
    fresh_collector_next_to_the_test_binary();

    // --- 正の対照: 枠が空いているうちは始められる -------------------------------
    let control_ws = tempfile::tempdir().expect("tempdir");
    let control_sink = control_ws.path().join(".harness").join("sandbox").join("c");
    std::fs::create_dir_all(&control_sink).expect("create sink dir");
    {
        let mut control = super::client::CollectorSession::new();
        control
            .start(
                None,
                false,
                policy_for(control_ws.path(), &control_sink, true),
                None,
            )
            .expect(
                "枠が空いている状態でも記録を始められない。断りの原因が「枠が無いこと」だと\
                 言えないので、このあとの測定は成立しない（収集器の版が古い可能性が高い）",
            );
        control.stop().expect("stop the control recording");
    }

    // 枠を取れるだけ取る。**上限は8本**なので、それ以上は回さない。
    let mut hogs = Vec::new();
    for i in 0..8 {
        let name = format!("harness-argv-e2e-hog-{}-{i}", std::process::id());
        match MofFsSession::start_process_only(&name) {
            Ok(session) => hogs.push(session),
            Err(_) => break,
        }
    }
    // 前提の確認: **いま新しく1本取れないこと**。取れるなら枠が空いており、
    // このあとの`StartCollect`は成功してしまう（＝この測定は成立していない）。
    let probe_name = format!("harness-argv-e2e-probe-{}", std::process::id());
    let probe = MofFsSession::start_process_only(&probe_name);
    let precondition_established = probe.is_err();
    if let Ok(session) = probe {
        // 取れてしまったので、片付けてから落ちる（**張りっぱなしにしない**）。
        let _ = session.stop();
    }
    if !precondition_established {
        for session in hogs {
            let _ = session.stop();
        }
        panic!(
            "system loggerの枠を埋め切れなかったので、fail-closedが効くかを測れていない。\
             `logman query -ets`で誰が枠を持っているかを見てから撃ち直すこと"
        );
    }

    let workspace = tempfile::tempdir().expect("tempdir");
    let sink_dir = workspace.path().join(".harness").join("sandbox").join("g-1");
    std::fs::create_dir_all(&sink_dir).expect("create sink dir");

    let mut session = super::client::CollectorSession::new();
    let result = session.start(
        None,
        false,
        policy_for(workspace.path(), &sink_dir, true),
        None,
    );

    // **必ず片付けてから判定する**（assertで抜けても枠を返す）。
    for hog in hogs {
        let _ = hog.stop();
    }

    let error = match result {
        Ok(started) => panic!(
            "枠が無いのに記録が始まった（etw_available={}）。fail-closedが効いていない\
             ——この記録は候補を1件も出せない",
            started.etw_available
        ),
        Err(e) => e,
    };
    assert!(
        matches!(
            error,
            super::LearnError::ArgvCaptureUnavailable(_)
        ),
        "断り方が専用の変種で返っていない（呼び出し側はこの失敗だけ記録を中止する）: {error:?}"
    );
    // **候補のファイルは残さない**（先行作成はするが、記録は始まっていない）。
    let path = observed_path(workspace.path());
    assert!(
        spawns(&path).is_empty(),
        "始まらなかった記録が候補を書いている: {}",
        path.display()
    );
}
