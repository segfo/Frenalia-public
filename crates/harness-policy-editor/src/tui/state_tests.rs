//! 記録画面まわりの状態遷移テスト（端末もworkerスレッドも使わない）。
//!
//! `on_key`は副作用を[`Action`]として返すだけなので、UACも実機のETWも要らずに
//! 「押したときに何が起きるか／何が起きないか」を固定できる。

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::*;
use crate::record::{RecordError, RecordEvent, RecordOutcome};
use crate::session_dir::{self, RecordManifest, RecordSessionDir, RecordStatus};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(ch: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(session_dir::sandbox_root(dir.path())).expect("sandbox root");
    dir
}

fn app_with(ws: &tempfile::TempDir) -> App {
    App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None)
}

fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        app.on_key(key(KeyCode::Char(ch)));
    }
}

/// 記録を1本「開始した」状態にする（workerは起こさない）。
fn start_pass1(app: &mut App, command: &str) -> Option<Action> {
    app.record_focus = RecordField::Command;
    type_text(app, command);
    app.on_key(key(KeyCode::Enter))
}

/// Enterで記録が始まる（＝許可側。禁止側だけ書くと、開始経路が丸ごと死んでいても緑になる、B-35）。
#[test]
fn pressing_enter_with_a_command_starts_pass1() {
    let ws = workspace();
    let mut app = app_with(&ws);

    let action = start_pass1(&mut app, "cargo build");

    match action {
        Some(Action::StartPass1(request)) => {
            assert_eq!(request.command, "cargo build");
            assert_eq!(request.workspace_root, ws.path().to_path_buf());
        }
        _ => panic!("Enterで記録が始まらなければ、この画面は何の役にも立たない"),
    }
    assert!(app.is_running(), "開始したら実行中として扱う");
}

/// コマンドが空なら開始しない。**押しても無反応にはしない**——理由を出す（B-32）。
#[test]
fn pressing_enter_without_a_command_explains_instead_of_starting() {
    let ws = workspace();
    let mut app = app_with(&ws);

    let action = app.on_key(key(KeyCode::Enter));

    assert!(action.is_none());
    assert!(!app.is_running());
    assert!(
        app.status.contains("コマンドを入力"),
        "無言で何も起きないと、壊れているのか入力が足りないのか区別できない: {}",
        app.status
    );
}

/// 実行中の二重起動は止める。**止めた理由と、止め方（Esc）を出す**（B-23(c)）。
#[test]
fn starting_a_second_recording_while_one_runs_is_refused_with_a_reason() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("1本目は始まる");

    let action = app.on_key(key(KeyCode::Enter));

    assert!(action.is_none(), "2本目を起こしてはいけない");
    assert!(app.status.contains("記録中"), "status: {}", app.status);
    assert!(
        app.status.contains("Esc"),
        "止め方を書かないと、ユーザーは待つしかないと思う: {}",
        app.status
    );
}

/// **停止がその場で効くのはコマンド実行中だけ。** それ以外の区間で押した停止は「予約」になる
/// ——`cancel`を読むのは`pump_child`のループの中だけだからである（B-23(b)・B-32）。
#[test]
fn stopping_while_warming_up_is_queued_not_immediate() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::WarmingUp(
        std::time::Duration::from_millis(1500),
    )));

    app.on_key(key(KeyCode::Esc));

    assert_eq!(app.run.as_ref().unwrap().phase, RunPhase::WarmingUp);
    assert!(app.run.as_ref().unwrap().stop_requested);
    assert!(
        app.status.contains("予約"),
        "この区間の停止は即時ではない。そう言わないと「効かない」と誤解される: {}",
        app.status
    );
}

#[test]
fn stopping_while_the_command_runs_takes_effect_immediately() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));

    app.on_key(key(KeyCode::Esc));

    assert_eq!(app.run.as_ref().unwrap().phase, RunPhase::Running);
    assert!(app.run.as_ref().unwrap().stop_requested);
    assert!(app.status.contains("停止を要求"), "status: {}", app.status);
}

/// ドレイン中は押しても何も起きない。**「押せば止まる」と見せない**（B-32）。
#[test]
fn stopping_while_draining_says_why_it_cannot_stop() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Exited(0)));

    app.on_key(key(KeyCode::Esc));

    assert_eq!(app.run.as_ref().unwrap().phase, RunPhase::Draining);
    assert!(
        !app.run.as_ref().unwrap().stop_requested,
        "効かないのに「要求済み」と見せない"
    );
    assert!(
        app.status.contains("停止できません"),
        "status: {}",
        app.status
    );
}

/// シェル起動時のノイズはコマンドの出力と**別の枠**へ入る（BUG-086・B-33）。
#[test]
fn startup_noise_never_lands_in_the_command_output() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "echo hoge > test.txt").expect("開始");

    app.on_worker(WorkerMsg::Pass1(RecordEvent::StartupNoise(
        "警告: プロバイダの読み込みに失敗\n".to_string(),
    )));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Exited(0)));

    let run = app.run.as_ref().unwrap();
    assert_eq!(run.noise.len(), 1);
    assert!(
        run.output.is_empty(),
        "出力の無い成功で、ノイズが唯一の出力になると成功が失敗に見える"
    );
}

/// 監査イベントは件数だけ数える（`cargo build`規模だと数千件届く）。
#[test]
fn audit_events_are_counted_rather_than_kept() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");

    for _ in 0..3 {
        app.on_worker(WorkerMsg::Pass1(RecordEvent::Access(Box::new(
            harness_policy::FsAuditEvent::observed(
                harness_policy::FsAuditKind::Etw,
                r"C:\x\y.txt",
                harness_config::FsAccess::Read,
                true,
                "record_all",
                1,
            ),
        ))));
    }

    assert_eq!(app.run.as_ref().unwrap().events, 3);
}

/// 記録が終わっても**画面は動かさず、結果を出したまま**次にやることを案内する。
///
/// 以前は編集画面へ自動で移っていたが、そうすると**コマンドの実行結果を一度も読めない**
/// ——ユーザーから「実行結果が見られません」「勝手に入るのは良くない仕様ですね」と
/// 指摘された。候補は裏で開いておくので`F2`は即座に出る（進める準備はするが、進むかは
/// 操作した人が決める）。
#[test]
fn finishing_pass1_keeps_the_result_on_screen_and_only_suggests_the_edit_screen() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "sess-new").expect("session dir");
    let mut manifest = RecordManifest::new("sess-new", "cargo build", ws.path(), ws.path(), 10);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    std::fs::write(
        dir.audit_log_path(),
        format!(
            "{}\n",
            harness_policy::FsAuditEvent::observed(
                harness_policy::FsAuditKind::Etw,
                r"C:\Users\me\.cargo\registry\x.rs",
                harness_config::FsAccess::Read,
                true,
                "record_all",
                1,
            )
            .to_jsonl_line()
            .expect("jsonl")
        ),
    )
    .expect("audit log");

    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1Done(Box::new(Ok(RecordOutcome {
        session_id: "sess-new".to_string(),
        session_dir: dir.path().to_path_buf(),
        audit_log_path: dir.audit_log_path(),
        exit_code: Some(0),
        aborted: None,
        collector_started: true,
        etw_available: true,
        collector_written: Some(1),
        warnings: Vec::new(),
        aggregate: crate::aggregate::Aggregate::new(
            crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ),
        ),
    }))));

    assert!(!app.is_running());
    assert_eq!(
        app.screen,
        Screen::Record,
        "実行結果を読む前に画面を動かさない（勝手に遷移しない）"
    );
    assert!(
        app.has_finished_run(),
        "終わった記録の結果は画面に残っていなければならない"
    );
    assert_eq!(
        app.selected_session().map(|s| s.manifest.id.as_str()),
        Some("sess-new")
    );
    let view = app
        .view
        .as_ref()
        .expect("候補は裏で開いておく（F2が即座に出る）");
    assert!(
        !view.proposals.is_empty(),
        "候補が出ていなければ、承認する対象が無く編集画面へ進む意味がない"
    );
    assert!(
        app.status.contains("F2"),
        "画面を動かさない以上、次にやることは文言で案内するしかない: {}",
        app.status
    );

    // **画面を往復しても結果は消えない**（ユーザー報告1件目）。
    let output_before = app.run.as_ref().unwrap().output.clone();
    app.on_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
    assert_eq!(app.screen, Screen::Edit);
    app.on_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE));
    assert_eq!(app.screen, Screen::Record);
    assert!(
        app.has_finished_run(),
        "編集画面へ行って戻ってきたら結果が消えていた（記録の目的そのものが読めなくなる）"
    );
    assert_eq!(
        app.run.as_ref().unwrap().output,
        output_before,
        "コマンドの出力は往復しても同じでなければならない"
    );
}

/// 次の記録を開始したら、前回の結果は新しい実行へ**置き換わる**（残り続けない）。
#[test]
fn starting_another_recording_replaces_the_previous_result() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Stdout("前回の出力".into())));
    app.on_worker(WorkerMsg::Pass1Done(Box::new(Ok(RecordOutcome {
        session_id: "sess-old".to_string(),
        session_dir: ws.path().to_path_buf(),
        audit_log_path: ws.path().join("fs-audit.jsonl"),
        exit_code: Some(0),
        aborted: None,
        collector_started: true,
        etw_available: true,
        collector_written: None,
        warnings: Vec::new(),
        aggregate: crate::aggregate::Aggregate::new(
            crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ),
        ),
    }))));
    assert!(app.has_finished_run());

    start_pass1(&mut app, "cargo test").expect("2回目の開始");
    assert!(app.is_running(), "2回目は実行中として扱う");
    assert!(
        app.run.as_ref().unwrap().output.is_empty(),
        "前回の出力が新しい実行の枠に残っていてはいけない"
    );
}

/// 異常終了は**そのまま伝える**（候補が不完全かもしれない、という判断材料になる）。
#[test]
fn a_nonzero_exit_code_is_reported_after_the_recording() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1Done(Box::new(Ok(RecordOutcome {
        session_id: "missing".to_string(),
        session_dir: ws.path().to_path_buf(),
        audit_log_path: ws.path().join("fs-audit.jsonl"),
        exit_code: Some(101),
        aborted: None,
        collector_started: true,
        etw_available: true,
        collector_written: None,
        warnings: Vec::new(),
        aggregate: crate::aggregate::Aggregate::new(
            crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ),
        ),
    }))));

    assert!(app.status.contains("101"), "status: {}", app.status);
}

/// 失敗したときは編集画面へ進まない（見るものが無い）。理由は残す。
#[test]
fn a_failed_recording_stays_on_the_record_screen_with_the_reason() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");

    app.on_worker(WorkerMsg::Pass1Done(Box::new(Err(RecordError::NoShell))));

    assert_eq!(app.screen, Screen::Record);
    assert!(!app.is_running());
    assert!(app.status.contains("PowerShell"), "status: {}", app.status);
    // **⚠欄にも残す。** `status`は次の操作で上書きされる1行なので、そこにしか無いと
    // 「何が足りなかったか」は数秒で画面から消える（BUG-093の(a)と同じ形）。
    let warnings = &app
        .run
        .as_ref()
        .expect("run is kept after a failure")
        .warnings;
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("no_shell") && w.contains("PowerShell")),
        "the reason must stay in the warning panel: {warnings:?}"
    );
}

/// 対の側: **成功したときに⚠欄へ理由を積まない**（積むと、通った実行が失敗に見える）。
#[test]
fn a_successful_recording_adds_no_failure_line_to_the_warning_panel() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");

    app.on_worker(WorkerMsg::Pass1Done(Box::new(Ok(RecordOutcome {
        session_id: "s-ok".to_string(),
        session_dir: ws.path().to_path_buf(),
        audit_log_path: ws.path().join("fs-audit.jsonl"),
        exit_code: Some(0),
        aborted: None,
        collector_started: true,
        etw_available: true,
        collector_written: Some(0),
        warnings: Vec::new(),
        aggregate: crate::aggregate::Aggregate::new(
            crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ),
        ),
    }))));

    let warnings = &app.run.as_ref().expect("run is kept").warnings;
    assert!(
        !warnings.iter().any(|w| w.contains("記録できなかった理由")),
        "{warnings:?}"
    );
}

/// 実行中の終了要求（`Ctrl+Q`）は**その場で抜けない**——収集器の撤収とマニフェストの確定が終わってから。
/// 記録中の`Esc`は停止で二度押しに数えないので、記録中に閉じる口はこれだけである（`Ctrl+C`は終了に使わない）。
#[test]
fn quitting_while_recording_waits_for_the_teardown() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));

    let action = app.on_key(ctrl('q'));

    assert!(action.is_none(), "実行中に即座に終了してはいけない");
    assert!(!app.should_exit(), "撤収が終わるまでは抜けない");
    assert!(app.run.as_ref().unwrap().stop_requested, "停止は要求する");

    app.on_worker(WorkerMsg::Pass1Done(Box::new(Err(RecordError::NoShell))));
    assert!(app.should_exit(), "撤収が終わったら抜ける");
}

/// 実行していないときの終了は即座でよい。
#[test]
fn quitting_while_idle_exits_immediately() {
    let ws = workspace();
    let mut app = app_with(&ws);

    assert!(matches!(app.on_key(ctrl('q')), Some(Action::Quit)));
}

/// **`Ctrl+C`は、何も選んでいなければ終了しない**（2026-10-03。コピーのつもりの連打で終わっていた——
/// `harness_term::double_esc`）。待機中も記録中も、終了も停止も予約もせず、終了の仕方を知らせの行に出す
/// （押しても無反応にしない、B-23(c)）。記録中の終了は`Ctrl+Q`のまま（上の試験。禁止側と許可側の対）。
#[test]
fn ctrl_c_neither_quits_nor_stops_and_says_how_to_quit() {
    let ws = workspace();
    let mut app = app_with(&ws);
    assert!(
        app.on_key(ctrl('c')).is_none(),
        "待機中の`Ctrl+C`で終了した"
    );
    assert_eq!(app.status, harness_term::double_esc::CTRL_C_NOTICE);

    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    for _ in 0..3 {
        assert!(app.on_key(ctrl('c')).is_none());
    }
    assert!(!app.quit_after_run, "記録中の`Ctrl+C`で終了を予約した");
    assert!(
        !app.run.as_ref().unwrap().stop_requested,
        "記録中の`Ctrl+C`で記録を止めた"
    );
    assert_eq!(app.status, harness_term::double_esc::CTRL_C_NOTICE);
}

/// [決定68(2)] パス2が画面から要るのは**コマンドだけ**になった（ドメインは選ばない——常に入口から始める）。
/// コマンドが無ければ始まらず、コマンド欄へ戻して理由を言う（禁止側。許可側は次の試験）。
///
/// 以前は「承認済みのドメインが無ければ始まらない」を測っていた（ドメイン欄の名前を`policy.json`で引いていた）。
#[test]
fn pass2_refuses_to_start_without_a_command() {
    let ws = workspace();
    let mut app = app_with(&ws);
    app.pass = Pass::Two;
    app.record_focus = RecordField::Cwd;

    let action = app.on_key(key(KeyCode::Enter));

    assert!(action.is_none());
    assert!(!app.is_running());
    assert_eq!(app.record_focus, RecordField::Command, "コマンド欄へ戻す");
    assert!(
        app.status.contains("コマンド"),
        "何が足りないのかを言う: {}",
        app.status
    );
}

/// [決定68(2)] **ドメインを選ばずにパス2が始まる**（許可側。B-35の対）。`policy.json`が無くても画面は止めない
/// ——始める場所は入口で、宣言を読むのは記録の側（`record_net`。読めなければそこで理由ごと失敗する）。
///
/// 以前は「承認済みのドメインならパス2は始まる」（ドメイン欄に`cargo`を打ち、要求に載ることを見ていた）。
#[test]
fn pass_two_starts_without_choosing_a_domain() {
    let ws = workspace();
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "前提: policy.json が無い"
    );

    let mut app = app_with(&ws);
    app.pass = Pass::Two;
    app.record_focus = RecordField::Command;
    type_text(&mut app, "cargo build");

    match app.on_key(key(KeyCode::Enter)) {
        Some(Action::StartPass2(request)) => {
            assert_eq!(request.command, "cargo build");
            assert_eq!(request.net_mode, NetMode::RecordAll, "既定は記録");
        }
        _ => panic!("コマンドがあればパス2は始まる"),
    }
    assert!(app.is_running());
}

/// [決定64] 「パス」欄で選んだ通信の扱いが、そのまま記録の要求に載る（画面だけ変わって
/// 実行は全許可のまま、にしない）。
#[test]
fn pass2_carries_the_chosen_net_mode_into_the_request() {
    let ws = workspace();
    let mut policy = crate::policy_file::PolicyFile::default();
    // [決定68(2)] 通信の宣言は入口のドメインのもの。
    let mut domain = crate::policy_file::PolicyDomain::new(crate::policy_file::ENTRY_DOMAIN);
    domain.net.allow_domains.push("crates.io".to_string());
    policy.domains.push(domain);
    crate::policy_file::save(ws.path(), &policy).expect("policy.json");

    let mut app = app_with(&ws);
    app.pass = Pass::Two;
    app.net_mode = NetMode::Declared;
    app.record_focus = RecordField::Command;
    type_text(&mut app, "cargo fetch");

    match app.on_key(key(KeyCode::Enter)) {
        Some(Action::StartPass2(request)) => {
            assert_eq!(request.net_mode, NetMode::Declared);
        }
        _ => panic!("コマンドがあればパス2は始まる"),
    }
}

/// [決定64] 「パス」欄は パス1 → パス2（記録）→ パス2（強制）→ パス1 と巡回する。
/// `→`とSpaceは進み、`←`は戻る（新しいキーを足さずに3つを選ぶ）。
#[test]
fn the_pass_field_cycles_through_record_and_enforce() {
    let ws = workspace();
    let mut app = app_with(&ws);
    app.record_focus = RecordField::Pass;
    assert_eq!((app.pass, app.net_mode), (Pass::One, NetMode::RecordAll));

    app.on_key(key(KeyCode::Right));
    assert_eq!((app.pass, app.net_mode), (Pass::Two, NetMode::RecordAll));
    app.on_key(key(KeyCode::Char(' ')));
    assert_eq!((app.pass, app.net_mode), (Pass::Two, NetMode::Declared));
    app.on_key(key(KeyCode::Right));
    assert_eq!(
        (app.pass, app.net_mode),
        (Pass::One, NetMode::RecordAll),
        "パス1へ戻ると強制の選択は持ち越さない"
    );

    app.on_key(key(KeyCode::Left));
    assert_eq!((app.pass, app.net_mode), (Pass::Two, NetMode::Declared));
    app.on_key(key(KeyCode::Left));
    assert_eq!((app.pass, app.net_mode), (Pass::Two, NetMode::RecordAll));
}

/// 画面はいつでも切り替えられる（順序を強制しない、決定13）。実行中でも編集画面を見られる。
#[test]
fn the_screens_can_be_switched_at_any_time_even_while_recording() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");

    app.on_key(key(KeyCode::F(2)));
    assert_eq!(app.screen, Screen::Edit);
    app.on_key(key(KeyCode::F(1)));
    assert_eq!(app.screen, Screen::Record);
    assert!(app.is_running(), "画面を移っても記録は続いている");
}

/// **F1/F2/F3が端末に届かない環境がある**（VS Codeの統合ターミナルはF1をコマンドパレットへ奪う）。
/// 修飾キー付きの予備（Ctrl+N）で**すべての画面へ**行けること——1画面でも巡回から漏れると、
/// その画面はそういう端末では開けない。
#[test]
fn the_screens_can_be_switched_without_the_function_keys() {
    let ws = workspace();
    let mut app = app_with(&ws);

    app.on_key(ctrl('n'));
    assert_eq!(app.screen, Screen::Edit);
    app.on_key(ctrl('n'));
    assert_eq!(app.screen, Screen::Declared, "宣言画面も巡回に入っている");
    app.on_key(ctrl('n'));
    assert_eq!(app.screen, Screen::Record, "一周して戻る");
}

/// 画面は`F1`→`F2`→`F3`の**連番**で、ヘルプは`F4`である（決定62。段階⑦で並べ替えた）。
///
/// **対で測る**（`B-35`）——片方だけだと、両方が同じ画面を開く実装でも緑になる。
#[test]
fn f3_opens_the_declared_screen_and_f4_opens_the_help() {
    let ws = workspace();
    let mut app = app_with(&ws);

    app.on_key(key(KeyCode::F(3)));
    assert_eq!(app.screen, Screen::Declared, "F3が宣言画面になっていない");
    assert!(!app.help, "宣言画面を開くつもりでヘルプが出ている");

    app.on_key(key(KeyCode::F(4)));
    assert!(app.help, "F4でヘルプが出ていない");
    assert_eq!(app.screen, Screen::Declared, "ヘルプが画面を動かしている");
}

/// Escでも行き来できる（必ず届くキー）。ただし**記録中は停止が優先**で、画面は動かさない
/// ——止めたつもりが画面だけ変わる、が一番困る。
#[test]
fn escape_switches_screens_but_stops_the_recording_first() {
    let ws = workspace();
    let mut app = app_with(&ws);

    app.on_key(key(KeyCode::Esc));
    assert_eq!(app.screen, Screen::Edit, "待機中は画面切替");
    // **間に別のキーを挟む。** Escを続けて2回押すと終了になる（下のテスト）ので、
    // 「1回ずつの遷移」を測るにはタイマーを切っておく必要がある。
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Esc));
    assert_eq!(app.screen, Screen::Record);

    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    app.on_key(key(KeyCode::Esc));

    assert_eq!(app.screen, Screen::Record, "記録中は画面を動かさない");
    assert!(app.run.as_ref().unwrap().stop_requested, "停止が優先");
}

/// `Esc`を連続で2回押したら終了する（画面が3つになり、EscもCtrl+Nも遷移に使うため）。
#[test]
fn two_escapes_in_a_row_quit() {
    let ws = workspace();
    let mut app = app_with(&ws);

    assert!(app.on_key(key(KeyCode::Esc)).is_none(), "1回目は遷移だけ");
    assert!(
        matches!(app.on_key(key(KeyCode::Esc)), Some(Action::Quit)),
        "2回目で終了する"
    );
}

/// **間に別のキーが挟まったら数え直す。** 挟まっても生き残る作りにすると、無関係な操作の
/// あとの`Esc`1回で突然終了する（ドラッグ選択のアンカーで踏んだのと同型の穴）。
#[test]
fn an_intervening_key_cancels_the_double_escape() {
    let ws = workspace();
    let mut app = app_with(&ws);

    app.on_key(key(KeyCode::Esc));
    app.on_key(key(KeyCode::Down));
    assert!(
        app.on_key(key(KeyCode::Esc)).is_none(),
        "1回目として数え直すので終了しない"
    );
}

/// **記録中の`Esc`は停止のままで、終了に転ばない。** 止めたいときに連打されやすいキーなので、
/// ここで終了に転ぶと「止めたつもりがプログラムごと終わる」ことになる。
#[test]
fn two_escapes_do_not_quit_while_a_recording_is_running() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));

    assert!(app.on_key(key(KeyCode::Esc)).is_none());
    assert!(
        app.on_key(key(KeyCode::Esc)).is_none(),
        "記録中は2回押しても終了しない（停止のまま）"
    );
    assert!(!app.quit_after_run, "終了を予約もしない");
}

/// しきい値の外なら終了しない。境目（ちょうど1秒）は内側。時刻を渡す入口（`on_key_at`）があるので**待たずに測れる**
/// （窓の長さは会話画面と共有する`harness_term::double_esc::WINDOW`）。
#[test]
fn escapes_further_apart_than_the_window_do_not_quit() {
    use harness_term::double_esc::WINDOW;
    let ws = workspace();
    let t0 = std::time::Instant::now();
    let ms = std::time::Duration::from_millis(1);

    let mut app = app_with(&ws);
    assert!(app.on_key_at(key(KeyCode::Esc), t0).is_none());
    assert!(
        app.on_key_at(key(KeyCode::Esc), t0 + WINDOW + ms).is_none(),
        "窓の外の2回目で終了した"
    );
    assert!(
        matches!(
            app.on_key_at(key(KeyCode::Esc), t0 + WINDOW + ms + WINDOW),
            Some(Action::Quit)
        ),
        "窓の外の2回目が新しい1回目にならない"
    );

    let mut app = app_with(&ws);
    app.on_key_at(key(KeyCode::Esc), t0);
    assert!(
        matches!(
            app.on_key_at(key(KeyCode::Esc), t0 + WINDOW),
            Some(Action::Quit)
        ),
        "境目の2回目で終了しない"
    );
}

/// **キーを離したことは数え直しにしない**——Windowsのコンソールは押下と離上の両方を送るので、離上で数え直すと
/// `Esc`の二度押しが一度も成立しない。
#[test]
fn a_key_release_between_the_escapes_does_not_start_over() {
    let ws = workspace();
    let mut app = app_with(&ws);
    let t0 = std::time::Instant::now();
    app.on_key_at(key(KeyCode::Esc), t0);
    let mut release = key(KeyCode::Esc);
    release.kind = crossterm::event::KeyEventKind::Release;
    assert!(app.on_key_at(release, t0).is_none());
    assert!(matches!(
        app.on_key_at(key(KeyCode::Esc), t0),
        Some(Action::Quit)
    ));
}

/// **確認ダイアログ・ヘルプを閉じた`Esc`は数えない**——閉じた直後に`Esc`を1回押しても終了せず（それが1回目）、
/// もう1回で終了する。時刻はどれも窓の中（窓が理由で終了しないのではないことを確かめるため）。
#[test]
fn an_escape_that_closed_a_dialog_or_the_help_is_not_counted() {
    let ws = workspace();
    let t0 = std::time::Instant::now();
    for case in ["確認ダイアログ", "ヘルプ"] {
        let mut app = app_with(&ws);
        // 1回目を数えた状態から開く（開くキーで数え直しになるので、ここでは状態を直接作る）。
        app.on_key_at(key(KeyCode::Esc), t0);
        app.screen = Screen::Record;
        match case {
            "確認ダイアログ" => {
                app.modal = Some(Modal {
                    title: "確認".to_string(),
                    lines: vec!["本文".to_string()],
                    confirm: Confirm::ReadOnly,
                })
            }
            _ => app.help = true,
        }
        assert!(app.on_key_at(key(KeyCode::Esc), t0).is_none(), "{case}");
        assert!(
            app.modal.is_none() && !app.help,
            "{case}: 試験の前提: 閉じていない"
        );
        assert!(
            app.on_key_at(key(KeyCode::Esc), t0).is_none(),
            "{case}: 閉じた`Esc`を数えた"
        );
        assert!(
            matches!(app.on_key_at(key(KeyCode::Esc), t0), Some(Action::Quit)),
            "{case}: 何もしていない`Esc`の2回で終了しない"
        );
    }
}

/// **1回目の`Esc`で、もう一度押せば終了することを知らせの行に出す。** 窓の中は出したまま、窓が過ぎたら描画の合図
/// （`tui::tick`）で消す。ほかの知らせに書き換わっていたら、そちらは消さない。
#[test]
fn the_first_escape_says_a_second_one_quits_until_the_window_passes() {
    use harness_term::double_esc::{armed_notice, WINDOW};
    let ws = workspace();
    let t0 = std::time::Instant::now();
    let ms = std::time::Duration::from_millis(1);

    let mut app = app_with(&ws);
    app.status.clear();
    app.on_key_at(key(KeyCode::Esc), t0);
    assert_eq!(app.status, armed_notice());
    crate::tui::tick(&mut app, t0 + WINDOW);
    assert_eq!(app.status, armed_notice(), "窓の中で消えた");
    crate::tui::tick(&mut app, t0 + WINDOW + ms);
    assert_eq!(
        app.status, "",
        "窓が過ぎても残った（押しても終了しないのに「もう一度で終了」と言い続ける）"
    );

    let mut app = app_with(&ws);
    app.on_key_at(key(KeyCode::Esc), t0);
    app.status = "別の知らせ".to_string();
    crate::tui::tick(&mut app, t0 + WINDOW + ms);
    assert_eq!(app.status, "別の知らせ", "ほかの知らせを消した");
}

/// 記録画面の入力欄はTabで巡回する。[決定68(2)] **パス2もパス1と同じ3つ**（パス・コマンド・作業ディレクトリ）——
/// パス2のドメイン欄は無くなった（始める場所の行は編集できないので巡回に入らない）。
///
/// 以前は「パス1ではドメイン欄を飛ばし、パス2では作業ディレクトリの次がドメイン欄」を測っていた。
#[test]
fn tab_cycles_the_same_three_fields_in_both_passes() {
    let ws = workspace();
    let mut app = app_with(&ws);
    app.record_focus = RecordField::Pass;

    app.on_key(key(KeyCode::Tab));
    assert_eq!(app.record_focus, RecordField::Command);
    app.on_key(key(KeyCode::Tab));
    assert_eq!(app.record_focus, RecordField::Cwd);
    app.on_key(key(KeyCode::Tab));
    assert_eq!(app.record_focus, RecordField::Pass);

    app.pass = Pass::Two;
    app.record_focus = RecordField::Cwd;
    app.on_key(key(KeyCode::Tab));
    assert_eq!(
        app.record_focus,
        RecordField::Pass,
        "パス2でも作業ディレクトリの次はパス欄へ戻る"
    );
    app.on_key(key(KeyCode::BackTab));
    assert_eq!(app.record_focus, RecordField::Cwd, "逆回りも同じ3つ");
}

/// 経過表示・スピナーは会話TUI（`harness-tui`）と同じ形にする。
#[test]
fn the_progress_header_matches_the_conversation_tui() {
    use crate::tui::state::{format_elapsed, progress_bar, spinner_frame};
    use std::time::Duration;

    assert_eq!(format_elapsed(Duration::from_secs(0)), "00:00");
    assert_eq!(format_elapsed(Duration::from_secs(42)), "00:42");
    assert_eq!(format_elapsed(Duration::from_secs(125)), "02:05");

    // 100msで1コマ・10コマ周期（`harness-tui`の`SPINNER_FRAMES`と同じ速さ）。
    assert_eq!(spinner_frame(Duration::ZERO), '⠋');
    assert_ne!(
        spinner_frame(Duration::from_millis(100)),
        spinner_frame(Duration::ZERO)
    );
    assert_eq!(spinner_frame(Duration::from_millis(1000)), '⠋');

    assert_eq!(progress_bar(0.0, 4), "░░░░");
    assert_eq!(progress_bar(0.5, 4), "██░░");
    assert_eq!(progress_bar(1.0, 4), "████");
    assert_eq!(progress_bar(9.9, 4), "████", "1.0を超えても壊れない");
}

/// **測れる進捗だけを出す。** 合成した進捗を出すと、止まっているのに進んでいるように見える。
#[test]
fn progress_is_shown_only_where_it_can_be_measured() {
    let ws = workspace();
    let mut app = app_with(&ws);
    start_pass1(&mut app, "cargo build").expect("開始");

    // 収集器の起動待ち（UAC）は所要が分からない → 進捗は出さない。
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.phase, RunPhase::StartingCollector);
    assert!(run.phase_progress().is_none());
    assert!(run.phase_detail().is_none());

    // ウォームアップは所要が確定している（1500ms）→ 出す。
    app.on_worker(WorkerMsg::Pass1(RecordEvent::WarmingUp(
        std::time::Duration::from_millis(1500),
    )));
    let run = app.run.as_ref().unwrap();
    assert!(run.phase_progress().is_some());
    assert!(run.phase_detail().is_some_and(|d| d.contains("1.5秒")));

    // コマンド実行中は終わりが分からない → 出さない。
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    assert!(app.run.as_ref().unwrap().phase_progress().is_none());
}

/// ACE付与は**件数が分かる**ので、そのまま進捗として出す（合成ではない）。
///
/// **進捗の正本は`passthrough_progress`のセル**で、UIは`drain_worker`で毎ティック読む。
/// イベント（`PassthroughGranted`/`PassthroughDenied`）は`preflight`が返ってから
/// まとめて届くので、**カウンタをそちらで数えると付与中はずっと0のまま**張り付く
/// ——実際にそうなっていて、ユーザーに「1件目で固まった」と読まれた。
/// このテストは「付与の**最中に**カウンタが動く」ことを固定する。
///
/// **このテストは自分専用の進捗セルを使う**（[BUG-138](../../../../docs/bugs/BUG-138.md)）。
/// 製品共有のセルを読んで断言すると、同じテストバイナリの別のテストが並行に書いた値を
/// 拾って不定期に落ちる。いまは共有セルを読むテストがこの1本しかないので当たっていないが、
/// **2本目が書かれた日に黙って壊れる**形だった。
#[test]
fn the_ace_grant_phase_reports_how_many_of_how_many() {
    use crate::record_net::NetRecordEvent;
    use harness_sandbox::tier2a::win_appcontainer::passthrough_progress::ProgressCell;

    // 関数内`static`にできるのは`ProgressCell::new()`が`const fn`だから（leakも`Arc`も要らない）。
    static CELL: ProgressCell = ProgressCell::new();

    let ws = workspace();
    let mut app = app_with(&ws);
    app.pass = Pass::Two;
    app.run = Some(super::RunState::with_progress(Pass::Two, &CELL));

    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::GrantingPassthrough {
        outside_count: 3,
    }));

    // `preflight`が付与フェーズに入り、1件**実際に付与**したところ。
    // **まだ何のイベントも届いていない。**
    let phase = CELL.begin(3);
    CELL.advance();
    CELL.record_granted();
    app.drain_worker();

    let run = app.run.as_ref().unwrap();
    assert_eq!(run.phase, RunPhase::Preparing);
    assert_eq!(
        run.phase_detail().as_deref(),
        Some("ACE 1/3（新規1・既存のまま0）"),
        "the counter has to move while preflight is still running, not after it returns"
    );
    assert!((run.phase_progress().unwrap() - 1.0 / 3.0).abs() < 1e-9);

    // 2件目は既に十分だったので**Win32を1回も呼んでいない**。ここが1件目と区別されて
    // 見えることが、「毎回付け直している」という誤読を防ぐ唯一の手段である。
    CELL.advance();
    CELL.record_already_sufficient();
    app.drain_worker();
    assert_eq!(
        app.run.as_ref().unwrap().phase_detail().as_deref(),
        Some("ACE 2/3（新規1・既存のまま1）"),
        "新規と既存を分けて出さないと、2回目以降の実行が1回目と区別できない"
    );

    // `preflight`が返った後に届くイベントは**カウンタを動かさない**（正本は1つ、B-13）。
    drop(phase);
    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::PassthroughGranted {
        path: PathBuf::from(r"C:\Users\me\.cargo"),
        writable: false,
    }));
    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::PassthroughDenied {
        path: PathBuf::from(r"C:\Windows\System32"),
        access: "read".to_string(),
        reason: "ACCESS_DENIED".to_string(),
    }));
    assert_eq!(
        app.run.as_ref().unwrap().phase_detail().as_deref(),
        Some("ACE 2/3（新規1・既存のまま1）"),
        "counting in both places would end up reporting more done than total"
    );
}

/// 待ちの段階には**なぜ待つのか**を出す（無言の待ちは「壊れた」と読まれる）。
#[test]
fn every_phase_explains_what_it_is_waiting_for() {
    for phase in [
        RunPhase::StartingCollector,
        RunPhase::WarmingUp,
        RunPhase::Preparing,
        RunPhase::Running,
        RunPhase::Draining,
        RunPhase::Finishing,
    ] {
        assert!(!phase.hint().is_empty(), "{phase:?}");
    }
}

/// 既定の作業ディレクトリはworkspace（起動時に埋まっている）。
#[test]
fn the_working_directory_defaults_to_the_workspace() {
    let ws = workspace();
    let app = app_with(&ws);

    assert_eq!(
        PathBuf::from(app.cwd.text()),
        ws.path().to_path_buf(),
        "既定が空だと、毎回打たせることになる"
    );
}

/// **付与と撤収は同じUIを通る**（`PhaseWork`）。片方にだけゲージが付く非対称を作らない
/// ——対の操作なので、ユーザーが知りたいこと（あと何件か）も同じである。
#[test]
fn granting_and_revoking_share_the_same_progress_ui() {
    use crate::record_net::NetRecordEvent;
    use crate::tui::state::RunPhase;

    let ws = workspace();
    let mut policy = crate::policy_file::PolicyFile::default();
    let mut domain = crate::policy_file::PolicyDomain::new(crate::policy_file::ENTRY_DOMAIN);
    domain.fs.read.push("C:/Users/me/.cargo/**".to_string());
    policy.domains.push(domain);
    crate::policy_file::save(ws.path(), &policy).expect("policy.json");

    let mut app = app_with(&ws);
    app.pass = Pass::Two;
    app.record_focus = RecordField::Command;
    type_text(&mut app, "cargo test");
    app.on_key(key(KeyCode::Enter)).expect("パス2が始まる");

    // 付与: ゲージが立ち、内訳（新規／既存のまま）が出る。
    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::GrantingPassthrough {
        outside_count: 4,
    }));
    let run = app.run.as_ref().expect("run");
    assert_eq!(run.phase, RunPhase::Preparing);
    assert_eq!(run.phase_progress(), Some(0.0), "付与はゲージになる");
    let grant_detail = run.phase_detail().expect("付与の内訳");
    assert!(grant_detail.contains("ACE 0/4"), "{grant_detail}");
    assert!(
        grant_detail.contains("新規"),
        "付与は内訳を並べる: {grant_detail}"
    );

    // 撤収: **同じ経路**でゲージになる（内訳は無い＝剥がしたかどうかしかない）。
    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::RevokingUndeclared {
        total: 2,
    }));
    app.on_worker(WorkerMsg::Pass2(NetRecordEvent::UndeclaredRevoked {
        path: std::path::PathBuf::from("C:/x"),
        done: 1,
        total: 2,
    }));
    let run = app.run.as_ref().expect("run");
    assert_eq!(run.phase, RunPhase::Preparing);
    assert_eq!(
        run.phase_progress(),
        Some(0.5),
        "撤収も同じ`phase_progress`でゲージになる"
    );
    let revoke_detail = run.phase_detail().expect("撤収の内訳");
    assert!(revoke_detail.contains("撤収 1/2"), "{revoke_detail}");
    assert!(
        !revoke_detail.contains("新規"),
        "撤収に「新規／既存のまま」は無い: {revoke_detail}"
    );
}

// --- ホイールによるさかのぼり -------------------------------------------------
//
// **スクロール位置自体の振る舞い（クランプ・送り量・BUG-076の回帰）は
// `harness_term::scrollback`側のテストが持つ**――会話TUIのtranscriptと実装を
// 共有しているので、ここで同じことを確かめると複製になる（§5.0）。
// こちらに残すのは**この画面固有の配線**だけである。

/// **枠ごとに独立している。** 出力を遡っている間も進行ログは末尾に貼り付いたまま
/// ――１つの位置を共有すると、片方をスクロールしたらもう片方まで固まる。
#[test]
fn each_pane_scrolls_independently() {
    let mut app = App::new(PathBuf::from("C:/w"), harness_core::RequireSandbox::None);
    app.run = Some(RunState::new(Pass::One));
    let run = app.run.as_mut().unwrap();
    for i in 0..50 {
        run.output_line(format!("out {i}"));
        run.log_line(format!("log {i}"));
    }

    app.run.as_mut().unwrap().output_scroll.scroll_lines(5);

    let run = app.run.as_ref().unwrap();
    assert_eq!(run.output_scroll.offset(), 5);
    assert!(
        run.log_scroll.is_pinned(),
        "出力を遡っても進行ログは末尾追従のまま"
    );
    assert!(run.noise_scroll.is_pinned());
}

/// 行が積まれても**下端からの距離は変わらない**（transcriptと同じ意味論）。
/// 以前はここで位置を足し引きしていたが、会話TUIと振る舞いが食い違うのでやめた。
#[test]
fn appending_lines_does_not_touch_the_scroll_position() {
    let mut app = App::new(PathBuf::from("C:/w"), harness_core::RequireSandbox::None);
    app.run = Some(RunState::new(Pass::One));
    let run = app.run.as_mut().unwrap();
    run.output_scroll.scroll_lines(4);
    for i in 0..20 {
        run.output_line(format!("out {i}"));
    }
    assert_eq!(app.run.as_ref().unwrap().output_scroll.offset(), 4);
}

/// **一覧の表示開始位置はフレームをまたいで保たれる。**
///
/// 保たないと、ratatuiは毎フレーム「offset 0 から最小限スクロールして選択を見せる」計算を
/// することになり、**選択行が常に窓の端へ貼り付く**。カーソルが窓の中を動かず一覧の方が
/// 滑るので、直感に反する（ユーザーからの実機報告）。カーソルが窓の中を動き、
/// 端に達したときだけ窓が追従する、が正しい。
#[test]
fn a_list_keeps_its_view_position_across_frames() {
    let mut app = App::new(PathBuf::from("C:/w"), harness_core::RequireSandbox::None);
    // 描画側が「選択を見せるために 7 行目から表示した」と報告してきた、という状況。
    app.apply_draw_feedback(crate::tui::DrawFeedback {
        candidate_list_offset: Some(7),
        ..Default::default()
    });
    assert_eq!(app.candidate_list_offset, 7);

    // 次のフレームで別の一覧だけが報告してきても、候補一覧の位置は失われない。
    app.apply_draw_feedback(crate::tui::DrawFeedback {
        declared_list_offset: Some(2),
        ..Default::default()
    });
    assert_eq!(
        app.candidate_list_offset, 7,
        "報告の無い一覧の位置を0へ戻さない（戻すと毎フレームリセットと同じ壊れ方になる）"
    );
    assert_eq!(app.declared_list_offset, 2);
}

/// **選択を先頭へ戻す操作は、表示位置も戻す**（対の片方だけ書かない、B-01）。
/// 残すと、短い一覧へ切り替えたときに窓だけが下に取り残される。
#[test]
fn resetting_the_selection_also_resets_the_view_position() {
    let mut app = App::new(PathBuf::from("C:/w"), harness_core::RequireSandbox::None);
    app.apply_draw_feedback(crate::tui::DrawFeedback {
        candidate_list_offset: Some(20),
        ..Default::default()
    });

    app.cycle_filter();

    assert_eq!(app.selected_row, 0);
    assert_eq!(
        app.candidate_list_offset, 0,
        "選択を先頭へ戻したなら表示位置も先頭へ戻す"
    );
}
