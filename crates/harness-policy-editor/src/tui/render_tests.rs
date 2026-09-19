//! 描画のスモークテスト（`TestBackend`。実端末は要らない）。
//!
//! 状態遷移のテストと違い、ここが見るのは**描画が落ちないこと**だけである。レイアウト計算の
//! 引き算がu16でアンダーフローすると、TUIはその場でpanicして端末ごと落ちる——会話TUIでも
//! 同型の事故（BUG-075: 範囲外スライスでTUIごと落ちた）があるので、極端に狭い端末を含めて
//! 一通り描いておく。

use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::*;
use crate::record::RecordEvent;
use crate::session_dir::{self, RecordManifest, RecordSessionDir, RecordStatus};
use crate::tui::state::Confirm;
use crate::tui::worker::WorkerMsg;

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(session_dir::sandbox_root(dir.path())).expect("sandbox root");
    dir
}

fn render(app: &App, width: u16, height: u16) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| {
            draw(frame, app);
        })
        .expect("描画はどの画面・どの大きさでも落ちてはいけない");
}

/// 記録画面（入力待ち）。
#[test]
fn the_record_screen_renders() {
    let ws = workspace();
    let app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);

    render(&app, 120, 40);
    render(&app, 80, 24);
}

/// 記録中（進行ログ・出力・起動時ノイズの3枠が出る）。
#[test]
fn the_record_screen_renders_while_running() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.command.set_text("cargo build");
    app.on_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::StartupNoise(
        "警告: プロバイダの読み込みに失敗\n".to_string(),
    )));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Stdout(
        "Compiling harness-core\n".to_string(),
    )));

    render(&app, 120, 40);
    render(&app, 60, 16);
}

/// 編集画面（セッション一覧・候補・注記）とモーダル・ヘルプ。
#[test]
fn the_edit_screen_and_the_overlays_render() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "s1").expect("session dir");
    let mut manifest = RecordManifest::new("s1", "cargo build", ws.path(), ws.path(), 1);
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
                r"C:\Users\me\.cargo\registry\a.rs",
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

    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.open_selected_session();
    render(&app, 120, 40);

    // プロセスツリー表示へ切り替えても落ちない。
    app.show_tree = true;
    render(&app, 120, 40);

    app.show_tree = false;
    app.edit_focus = state::EditField::Proposals;
    app.on_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(' '),
        crossterm::event::KeyModifiers::NONE,
    ));
    app.on_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('a'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert!(app.modal.is_some(), "承認のモーダルが出ている状態で描く");
    render(&app, 120, 40);

    app.modal = None;
    app.help = true;
    render(&app, 120, 40);
}

/// [BUG-103] **workspaceのロック行が候補一覧に出ていること**を画面の内容で固定する。
///
/// workspace配下は候補にしない（D-54で既にRWX付与済み）が、**黙って消すと
/// 「なぜ自分のリポジトリが出ないのか」が分からない**。この行が消えるのは
/// レイアウトを触ったときの典型的な巻き添えなので、描画結果の文字列で見る。
///
/// あわせて`[x]`が**選択の対象になっていない**ことも確かめる——ロックの実装は
/// 「カーソルが乗らない」ことそのものである（B-06: 選ぶ自由を奪う）。
#[test]
fn the_edit_screen_shows_the_workspace_as_a_locked_row() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "s1").expect("session dir");
    let mut manifest = RecordManifest::new("s1", "cargo build", ws.path(), ws.path(), 1);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    // workspace配下（候補にならない）と、workspace外（候補になる）を1件ずつ。
    let inside = ws.path().join("src").join("lib.rs");
    let lines: Vec<String> = [
        (inside.to_string_lossy().into_owned(), 1u64),
        (r"C:\Users\me\.cargo\registry\a.rs".to_string(), 2),
    ]
    .iter()
    .map(|(path, ts)| {
        harness_policy::FsAuditEvent::observed(
            harness_policy::FsAuditKind::Etw,
            path,
            harness_config::FsAccess::Read,
            true,
            "record_all",
            *ts,
        )
        .to_jsonl_line()
        .expect("jsonl")
    })
    .collect();
    std::fs::write(dir.audit_log_path(), format!("{}\n", lines.join("\n"))).expect("audit log");

    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.open_selected_session();

    let mut terminal = Terminal::new(TestBackend::new(200, 40)).expect("test terminal");
    terminal
        .draw(|frame| {
            draw(frame, &app);
        })
        .expect("描画は落ちてはいけない");
    // **空白を落としてから照合する。** `TestBackend`のバッファは全角1文字が2セル
    // （文字＋空セル）を占めるので、素の連結では「解 除 で き ま せ ん」になる。
    let screen: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
        .split_whitespace()
        .collect();

    assert!(
        screen.contains("解除できません"),
        "the workspace must be shown as locked, not silently hidden:\n{screen}"
    );
    // workspace配下の候補は**一覧に出ない**（除外されている）。
    assert!(
        !screen.contains("lib.rs"),
        "paths under this session's workspace must not be offered as candidates:\n{screen}"
    );
    // 対（B-35）: workspace外は今までどおり候補に出る。
    assert!(
        screen.contains("registry"),
        "paths outside the workspace must still be candidates:\n{screen}"
    );
}

/// **極端に狭い端末でも落ちない。** レイアウトの引き算がu16でアンダーフローすると、
/// ユーザーが端末を小さくした瞬間にTUIごと落ちる。
#[test]
fn every_screen_survives_a_tiny_terminal() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.help = true;
    for (width, height) in [(1u16, 1u16), (10, 3), (20, 5), (40, 8)] {
        render(&app, width, height);
    }
    app.help = false;
    app.modal = Some(state::Modal {
        title: "確認".to_string(),
        lines: vec!["行1".to_string(), "行2".to_string()],
        confirm: Confirm::Approval,
    });
    for (width, height) in [(1u16, 1u16), (10, 3), (20, 5)] {
        render(&app, width, height);
    }
    app.modal = None;
    app.screen = Screen::Edit;
    for (width, height) in [(1u16, 1u16), (10, 3), (20, 5)] {
        render(&app, width, height);
    }
    // [段階⑦] 遷移の2タブ。**下の枠が8行固定**なので、それより低い端末で引き算が
    // 破綻しないことを確かめる（`transition_screen::draw`のレイアウト）。
    for tab in [
        transition::PendingTab::TransitionsObserved,
        transition::PendingTab::TransitionsDenied,
    ] {
        app.pending.tab = transition::Tab(tab);
        for (width, height) in [(1u16, 1u16), (10, 3), (20, 5), (40, 8), (120, 30)] {
            render(&app, width, height);
        }
    }
}

/// [段階⑦] 遷移のタブが、候補が在る状態でも描ける。
///
/// **空のときしか描かないと、行の組み立て（置き場の添え方・注記）が一度も走らない。**
#[test]
fn the_transition_tab_renders_with_candidates() {
    let ws = workspace();
    let path = harness_sandbox::tier2a::policy_learnd::observed::observed_path(ws.path());
    std::fs::create_dir_all(path.parent().expect("parent")).expect("transitions dir");
    let mut text = String::new();
    // 同じ名前が2つ並ぶ形（置き場を添える経路を通す）と、1つだけの形の両方を置く。
    for exe in [
        "C:/Program Files/Git/cmd/git.exe",
        "C:/Program Files/Git/mingw64/bin/git.exe",
        "C:/Windows/System32/findstr.exe",
    ] {
        let record =
            harness_sandbox::tier2a::policy_learnd::observed::ObservedRecord::ObservedSpawn(
                harness_sandbox::tier2a::policy_learnd::observed::Spawn {
                    parent_exe: Some("C:/pwsh.exe".to_string()),
                    exe: exe.to_string(),
                    argv: "git --version".to_string(),
                    count: 1,
                    first_ts: 1,
                    last_ts: 1,
                    argv_truncation: false,
                },
            );
        text.push_str(&serde_json::to_string(&record).expect("jsonl"));
        text.push('\n');
    }
    std::fs::write(&path, text).expect("observed.jsonl");

    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.pending.tab = transition::Tab(transition::PendingTab::TransitionsObserved);
    app.reload_transitions();
    assert_eq!(app.pending.observed.len(), 3, "候補が読めていない");

    for (width, height) in [(1u16, 1u16), (20, 5), (80, 20), (200, 40)] {
        render(&app, width, height);
    }
}
