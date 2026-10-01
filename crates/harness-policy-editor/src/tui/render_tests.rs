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

// ---------------------------------------------------------------------------
// キー案内の行（最下行）。**折り返さないので、幅が足りないと末尾から切れる。**
// ---------------------------------------------------------------------------

/// 空白を落とす。`TestBackend`は全角1文字を2セル（文字＋空セル）で持つので、
/// 素の連結だと「終 了」になる。区切りの`  |  `は`|`になる。
fn squash(text: &str) -> String {
    text.split_whitespace().collect()
}

/// `width`桁で描いたときの最下行（キー案内）を、空白を落として返す。
fn key_hint_row(app: &App, width: u16) -> String {
    let height = 30u16;
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| {
            draw(frame, app);
        })
        .expect("描画は落ちてはいけない");
    let start = usize::from(width) * usize::from(height - 1);
    squash(
        &terminal.backend().buffer().content()[start..]
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>(),
    )
}

/// キー案内の項目が違う画面を全部並べる（承認待ちは3タブそれぞれ）。
fn apps_on_every_screen(ws: &std::path::Path) -> Vec<(&'static str, App)> {
    let app = || App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    let record = app();
    let mut edit = app();
    edit.screen = Screen::Edit;
    let mut observed = app();
    observed.screen = Screen::Edit;
    observed.pending.tab = transition::Tab(transition::PendingTab::TransitionsObserved);
    let mut denied = app();
    denied.screen = Screen::Edit;
    denied.pending.tab = transition::Tab(transition::PendingTab::TransitionsDenied);
    let mut declared = app();
    declared.screen = Screen::Declared;
    vec![
        ("記録", record),
        ("承認待ち・FS/ネット", edit),
        ("承認待ち・遷移（観測から）", observed),
        ("承認待ち・遷移（拒否から）", denied),
        ("宣言", declared),
    ]
}

/// **禁止側**: 狭い端末でも、ヘルプと終了の案内は消えない。
///
/// # 壊れた状態を一文で
///
/// **画面ごとの項目が多いと、ヘルプと終了の案内から先に画面の外へ出る。** 共通の案内を
/// 末尾に足していたので、切れるのはいつもそこだった。実機（全画面に近い幅）の遷移タブで
/// `… | F2 タブ切替 | Esc 戻る | F4`と切れ、`Esc×2 終了`が見えなかった（2026-10-01）。
/// `Esc×2`は案内しないと見つけられない操作である（`COMMON_KEYS`のdoc）。
#[test]
fn the_help_and_quit_hints_survive_a_narrow_terminal_on_every_screen() {
    let ws = workspace();
    for (screen, app) in apps_on_every_screen(ws.path()) {
        for width in [80u16, 100, 120, 160] {
            let row = key_hint_row(&app, width);
            for hint in COMMON_KEYS {
                assert!(
                    row.contains(&squash(hint)),
                    "{screen}の画面を{width}桁で描くと「{hint}」が見えない:\n{row}"
                );
            }
        }
    }
}

/// **許可側**（`B-35`）: 全部収まる幅では、画面ごとの項目が**今までどおり全部・同じ順で**出る。
///
/// 「共通の案内を残す」は、画面ごとの項目を常に削る実装でも満たせてしまう。だから
/// 収まるときの1行が直す前と1文字も変わらないことを、行全体の一致で固定する。
#[test]
fn every_screen_hint_is_shown_in_order_when_the_terminal_is_wide_enough() {
    let ws = workspace();
    for (screen, app) in apps_on_every_screen(ws.path()) {
        let keys = screen_keys(&app);
        assert!(!keys.is_empty(), "{screen}の画面に固有の案内が1つも無い");
        let expected: Vec<&str> = keys.iter().map(String::as_str).chain(COMMON_KEYS).collect();
        assert_eq!(
            key_hint_row(&app, 400),
            squash(&expected.join(KEY_SEPARATOR)),
            "{screen}の画面: 収まる幅なのに案内が変わっている"
        );
    }
}

/// 収まらないときは**画面ごとの項目を後ろから丸ごと落とし、落とした件数を出す。**
///
/// 後ろから落とすのは、画面ごとの並びが「押す頻度と重要度」の順だからである
/// （遷移タブの並びのコメント）。**先頭（遷移タブなら`Space`）は残る**ことと、
/// 項目の途中で切れていないこと（行が「先頭からk件・`… 他N件`・共通の案内」の形に
/// ぴったり一致すること）を見る。件数を出すのは、省略したことを黙らないためである
/// （`record_screen`の警告枠の`… 他 N行`と同じ）。
#[test]
fn a_narrow_terminal_drops_screen_hints_from_the_tail_and_says_how_many() {
    let ws = workspace();
    for (screen, app) in apps_on_every_screen(ws.path()) {
        let keys = screen_keys(&app);
        let row = key_hint_row(&app, 100);
        let expected = |kept: usize| -> String {
            let omitted = format!("… 他{}件", keys.len() - kept);
            let line: Vec<&str> = keys[..kept]
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(omitted.as_str()))
                .chain(COMMON_KEYS)
                .collect();
            squash(&line.join(KEY_SEPARATOR))
        };
        let full: Vec<&str> = keys.iter().map(String::as_str).chain(COMMON_KEYS).collect();
        if row == squash(&full.join(KEY_SEPARATOR)) {
            // 100桁に全部収まる画面（今日の記録画面）は落とすものが無い。
            continue;
        }
        let kept = (0..keys.len()).find(|&kept| expected(kept) == row);
        assert!(
            matches!(kept, Some(k) if k >= 1),
            "{screen}の画面を100桁で描いた行が「先頭から1件以上・… 他N件・共通の案内」の形に\
             なっていない:\n{row}"
        );
    }
}
