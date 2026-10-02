//! 描画のスモークテスト（`TestBackend`。実端末は要らない）。
//!
//! 状態遷移のテストと違い、ここが見るのは**描画が落ちないこと**だけである。レイアウト計算の
//! 引き算がu16でアンダーフローすると、TUIはその場でpanicして端末ごと落ちる——会話TUIでも
//! 同型の事故（BUG-075: 範囲外スライスでTUIごと落ちた）があるので、極端に狭い端末を含めて
//! 一通り描いておく。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
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
    let app = edit_screen_with_a_locked_workspace(ws.path());

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

/// 編集画面で、workspace配下（候補にならない）と外（候補になる）を1件ずつ記録した記録を開いた状態。
fn edit_screen_with_a_locked_workspace(ws: &std::path::Path) -> App {
    let dir = RecordSessionDir::create(ws, "s1").expect("session dir");
    let mut manifest = RecordManifest::new("s1", "cargo build", ws, ws, 1);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    // workspace配下（候補にならない）と、workspace外（候補になる）を1件ずつ。
    let inside = ws.join("src").join("lib.rs");
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

    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.open_selected_session();
    app
}

/// [BUG-192] **ロック行の説明は、狭い端末でも最後まで読める。** 以前は2行固定で、2行目の説明
/// （約110桁）が候補の枠の幅で折り返すと、後ろの「配下 N件は候補にしません」——workspace配下が
/// 候補に出ない理由——が黙って切れていた。
#[test]
fn the_workspace_lock_row_is_not_cut_on_a_narrow_terminal() {
    let ws = workspace();
    let app = edit_screen_with_a_locked_workspace(ws.path());
    let failures: Vec<String> = [100u16, 120, 200]
        .into_iter()
        .filter_map(|width| {
            let candidates = box_inner(
                &paint_grid(width, 40, |f| {
                    draw(f, &app);
                }),
                " 候補:",
            );
            let text = flatten(&candidates);
            (!text.contains("配下1件は候補にしません") || !text.contains("registry"))
                .then(|| format!("{width}桁:\n{}", candidates.join("\n")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "ロック行の説明か候補が見えない:\n{}",
        failures.join("\n\n")
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

// ---------------------------------------------------------------------------
// 折り返す枠（確認ダイアログ・ヘルプ・知らせの行・説明欄）。[BUG-192]
//
// **行数は折り返した後で数える。** 日本語は1文字2桁なので、枠の幅を超える行はすぐ出る。
// 折り返す前の行数で高さや「続きがあるか」を決めると、折り返した分だけ下が黙って切れる。
// ---------------------------------------------------------------------------

/// 枠線の文字（`Borders::ALL`の既定の線）。本文の照合の前に落とす。
const BOX_CHARS: [char; 6] = ['─', '│', '┌', '┐', '└', '┘'];

fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

/// 空の`width`×`height`の端末へ`paint`だけを描き、セルの格子（行ごとに1セル1記号）を返す。
fn paint_grid(width: u16, height: u16, paint: impl FnOnce(&mut Frame)) -> Vec<Vec<String>> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal.draw(paint).expect("描画は落ちてはいけない");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect()
        })
        .collect()
}

/// [`paint_grid`]の行ごとの文字列。
fn paint_rows(width: u16, height: u16, paint: impl FnOnce(&mut Frame)) -> Vec<String> {
    paint_grid(width, height, paint)
        .into_iter()
        .map(|row| row.concat())
        .collect()
}

/// 見出しに`title`を含む、**描かれた**枠の矩形（枠線を含む）。描かれていなければ`None`。
///
/// 画面のセルから読み取る（レイアウトの関数を呼ばない）——描画と当たり判定が同じ計算を
/// 通っているかを確かめる試験で、その計算そのものを期待値に使うと何も測らないため。
fn drawn_box(grid: &[Vec<String>], title: &str) -> Option<ratatui::layout::Rect> {
    let title = squash(title);
    for (top, row) in grid.iter().enumerate() {
        // 見出しは左上の角の直後に描かれる。
        let Some(left) = (0..row.len())
            .find(|&x| row[x] == "┌" && squash(&row[x + 1..].concat()).starts_with(&title))
        else {
            continue;
        };
        let right = (left + 1..row.len())
            .find(|&x| row[x] == "┐")
            .expect("枠の右上の角が無い");
        let bottom = (top + 1..grid.len())
            .find(|&y| grid[y][left] == "└")
            .expect("枠の左下の角が無い");
        let cell = |n: usize| u16::try_from(n).expect("端末の大きさはu16に収まる");
        return Some(ratatui::layout::Rect::new(
            cell(left),
            cell(top),
            cell(right - left + 1),
            cell(bottom - top + 1),
        ));
    }
    None
}

/// 見出しに`title`を含む枠の**内側**（枠線を除いた行ごとの文字列）。
///
/// 左右に別の枠が並ぶ画面でも、その枠の列だけを切り出す（行全体をつなぐと隣の枠の文字が混ざる）。
fn box_inner(grid: &[Vec<String>], title: &str) -> Vec<String> {
    let area =
        drawn_box(grid, title).unwrap_or_else(|| panic!("見出しが「{}」の枠が無い", squash(title)));
    let (left, right) = (usize::from(area.x), usize::from(area.right() - 1));
    let (top, bottom) = (usize::from(area.y), usize::from(area.bottom() - 1));
    grid[top + 1..bottom]
        .iter()
        .map(|row| row[left + 1..right].concat())
        .collect()
}

/// 行を上から順につなぎ、空白と枠線を落とす。**折り返された1行は、これで元の1続きに戻る**
/// （間に挟まるのは枠の左右の線と行末の余白だけなので）。
fn flatten(rows: &[String]) -> String {
    rows.iter()
        .flat_map(|row| row.chars())
        .filter(|c| !c.is_whitespace() && !BOX_CHARS.contains(c))
        .collect()
}

/// 枠が占める行数（枠線を含む行の数。空の端末に枠を1つだけ描いたときに使う）。
fn box_height(rows: &[String]) -> usize {
    rows.iter()
        .filter(|row| row.chars().any(|c| BOX_CHARS.contains(&c)))
        .count()
}

/// 遷移タブ（観測から）に候補が1件ある状態。
fn transition_tab_with_one_candidate(ws: &std::path::Path) -> App {
    use harness_sandbox::tier2a::policy_learnd::observed::{observed_path, ObservedRecord, Spawn};

    let path = observed_path(ws);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("transitions dir");
    let record = ObservedRecord::ObservedSpawn(Spawn {
        parent_exe: Some("C:/pwsh.exe".to_string()),
        exe: "C:/Program Files/Git/cmd/git.exe".to_string(),
        argv: "git --version".to_string(),
        count: 1,
        first_ts: 1,
        last_ts: 1,
        argv_truncation: false,
    });
    let line = serde_json::to_string(&record).expect("jsonl");
    std::fs::write(&path, format!("{line}\n")).expect("observed.jsonl");

    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.pending.tab = transition::Tab(transition::PendingTab::TransitionsObserved);
    app.reload_transitions();
    assert_eq!(app.pending.observed.len(), 1, "候補が読めていない");
    app
}

/// 遷移タブで1件選び、遷移先を`destination`にして`a`を押した状態。
/// **実機で切れた確認ダイアログと同じ経路で組み立てる**（本文を試験の側で書かない）。
fn transition_confirmation_to(ws: &std::path::Path, destination: &str) -> App {
    let mut app = transition_tab_with_one_candidate(ws);
    press(&mut app, KeyCode::Char(' '));
    press(&mut app, KeyCode::Tab);
    for _ in 0..64 {
        press(&mut app, KeyCode::Backspace);
    }
    for ch in destination.chars() {
        press(&mut app, KeyCode::Char(ch));
    }
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('a'));
    assert!(
        matches!(
            app.modal.as_ref().map(|m| m.confirm),
            Some(Confirm::Transition)
        ),
        "確認ダイアログが出ていない: {}",
        app.status
    );
    app
}

/// `policy.json`に`domain`だけを書き、宣言画面（`F3`）を開いた状態。
fn declared_screen_with(ws: &std::path::Path, domain: crate::policy_file::PolicyDomain) -> App {
    crate::policy_file::save(
        ws,
        &crate::policy_file::PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![domain],
        },
    )
    .expect("policy.json");
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(3));
    assert_eq!(app.screen, Screen::Declared);
    app
}

/// 宣言画面で`**`を外す付け替えを予約して`a`を押した状態。**実機で権限の注意が切れた確認ダイアログ**
/// （`tools/**`に`R`、`data`に`c`。2026-10-02）と同じ形を、1行ずつ選んで作る。
fn reassignment_confirmation(ws: &std::path::Path) -> App {
    let mut domain = crate::policy_file::PolicyDomain::new("view-check");
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/data".to_string());
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/tools/**".to_string());
    let mut app = declared_screen_with(ws, domain);
    // 行0は2つの宣言の共通の親（`…/view-check-outside`。開いた状態で始まる）、その下に data・tools。
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('c'));
    assert!(
        app.status.contains("data") && app.status.contains("fs.read_write"),
        "台本の前提が崩れた（dataの付け替えを予約できていない）: {}",
        app.status
    );
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('R'));
    assert!(
        app.status.contains("tools") && app.status.contains("そのパス1つだけ"),
        "台本の前提が崩れた（tools の ** を外す予約ができていない）: {}",
        app.status
    );
    press(&mut app, KeyCode::Char('a'));
    assert!(
        matches!(
            app.modal.as_ref().map(|m| m.confirm),
            Some(Confirm::DeclaredChanges)
        ),
        "確認ダイアログが出ていない: {}",
        app.status
    );
    app
}

/// [BUG-192] **禁止側**: 確認ダイアログの最後の行が、黙って枠の外へ切れない。
///
/// # 壊れた状態を一文で
///
/// 枠の高さと「続きがあるか」を**折り返す前の行数**で数えていたので、枠より長い行が折り返した
/// 分だけ本文の下が枠の外へ出て切れ、`↑↓ PgUp/PgDn で送る`も出なかった。実機では
/// (1) 別ドメイン（`build`）への遷移の確認が「…だけでこのドメインを用意し」で止まり、
/// (2) 宣言の付け替え（`**`を外す）の確認が、**「配下へ付いた継承ACEは残って効き続けます」の
/// 注意ごと**枠の外にあった（どちらも2026-10-02）。
/// **最後の行まで見えているか、続きがあると言っているか**のどちらかでなければならない。
#[test]
fn the_last_line_of_a_confirmation_is_never_cut_off_silently() {
    let ws_transition = workspace();
    let ws_reassign = workspace();
    let transition = transition_confirmation_to(ws_transition.path(), "build");
    let reassign = reassignment_confirmation(ws_reassign.path());
    for (name, app, tail) in [
        ("遷移", &transition, "このドメインを用意します。"),
        ("付け替え", &reassign, "を実行してください）。"),
    ] {
        let modal = app.modal.as_ref().expect("確認ダイアログ");
        // 付け替えの明細は区切りの空行で終わるので、文字のある最後の行を見る。
        let last = squash(
            modal
                .lines
                .iter()
                .rev()
                .find(|line| !line.trim().is_empty())
                .expect("本文が空"),
        );
        assert!(
            last.ends_with(&squash(tail)),
            "{name}: 台本の前提が崩れた（最後の行が違う）: {last}"
        );
        // 1つ落ちたところで止めず、どの大きさで落ちるかを全部出す。
        let failures: Vec<String> = [(80u16, 24u16), (100, 30), (120, 30), (120, 40), (140, 30)]
            .into_iter()
            .filter_map(|(width, height)| {
                let rows = paint_rows(width, height, |f| {
                    draw_modal(f, f.area(), modal, 0);
                });
                let screen = flatten(&rows);
                (!screen.contains(&last) && !screen.contains("PgUp/PgDnで送る"))
                    .then(|| format!("{width}×{height}:\n{}", rows.join("\n")))
            })
            .collect();
        assert!(
            failures.is_empty(),
            "{name}の確認の最後の行が切れているのに、続きがあると言っていない:\n{}",
            failures.join("\n\n")
        );
    }
}

/// [BUG-192] **送った先で最後の行まで読める。** BUG-192の当時は送る量を`Modal::lines`の行で数えており、
/// 描く側が折り返した後の行へ直さないと、折り返しの多い本文では`End`を押しても末尾に届かなかった。
/// いまは送る量そのものを折り返した後の行で数え、上限は描画が返す（BUG-196）——描いて書き戻す経路
/// （[`frame`]）を通して、同じ「末尾に届く」を見る。
#[test]
fn the_end_key_reaches_the_last_line_even_when_every_line_wraps() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    let mut lines: Vec<String> = (0..40)
        .map(|i| format!("{i:02}{}", "折り返す長さの行".repeat(6)))
        .collect();
    lines.push("ここが最後の行です".to_string());
    app.modal = Some(state::Modal {
        title: "承認の確認".to_string(),
        lines,
        confirm: Confirm::Approval,
    });
    let modal_screen = |app: &mut App| {
        let rows: Vec<String> = frame(app, 80, 24)
            .into_iter()
            .map(|row| row.concat())
            .collect();
        flatten(&rows)
    };
    assert!(
        modal_screen(&mut app).contains("PgUp/PgDnで送る"),
        "収まらないのに送れると言っていない"
    );

    press(&mut app, KeyCode::End);
    let screen = modal_screen(&mut app);
    assert!(
        screen.contains("ここが最後の行です"),
        "End で末尾へ届かない:\n{screen}"
    );
}

/// [BUG-192] **許可側**（`B-35`）: 折り返さずに収まる本文は、枠の高さも今までどおりで、
/// 「送る」の案内も出さない（続きが無いのに送れと言わない、`B-32`）。
#[test]
fn a_confirmation_that_fits_is_drawn_as_before_and_does_not_offer_scrolling() {
    let modal = state::Modal {
        title: "承認の確認".to_string(),
        lines: (0..10).map(|i| format!("  + fs.read = C:/x/{i}")).collect(),
        confirm: Confirm::Approval,
    };
    let rows = paint_rows(120, 40, |f| {
        draw_modal(f, f.area(), &modal, 0);
    });
    assert_eq!(
        box_height(&rows),
        modal.lines.len() + 4,
        "収まる本文で枠の高さが変わった"
    );
    let screen = flatten(&rows);
    for line in &modal.lines {
        assert!(
            screen.contains(&squash(line)),
            "{line} が見えない:\n{screen}"
        );
    }
    assert!(
        !screen.contains("で送る"),
        "続きが無いのに送れと言っている:\n{screen}"
    );
}

/// [BUG-192] **許可側**: 折り返しても枠に収まる端末では、全部の行が見えて「送る」は出ない。
#[test]
fn a_wrapped_confirmation_that_fits_shows_every_line_without_a_scroll_hint() {
    let ws_transition = workspace();
    let ws_reassign = workspace();
    let transition = transition_confirmation_to(ws_transition.path(), "build");
    let reassign = reassignment_confirmation(ws_reassign.path());
    for (name, app) in [("遷移", &transition), ("付け替え", &reassign)] {
        let modal = app.modal.as_ref().expect("確認ダイアログ");
        let screen = flatten(&paint_rows(120, 60, |f| {
            draw_modal(f, f.area(), modal, 0);
        }));
        for line in &modal.lines {
            assert!(
                screen.contains(&squash(line)),
                "{name}: {line} が見えない:\n{screen}"
            );
        }
        assert!(
            !screen.contains("で送る"),
            "{name}: 収まっているのに送れと言っている:\n{screen}"
        );
    }
}

// ---------------------------------------------------------------------------
// 確認ダイアログを送る上限とスクロールバー。[BUG-196]
//
// **上限は「本文の最後の行が枠の一番下の行に来たところ」。** 以前は最後の行が枠の一番上に来るまで
// 送れたので、末尾では枠がほぼ空になり、どこまで読めば終わりかが分からなかった。上限は折り返した
// 後の行数で決まり、描くまで分からないので、キーを押したら必ず[`frame`]（描いて状態へ書き戻す）を通す。
// ---------------------------------------------------------------------------

/// 実際のイベントループ（`tui::run`）と同じく、1フレーム描いて**描画で判明したことを状態へ書き戻し**、
/// 描いたセルの格子を返す。描くだけで書き戻さないと、送りの上限が状態へ届かない形を測れない（BUG-076）。
fn frame(app: &mut App, width: u16, height: u16) -> Vec<Vec<String>> {
    let mut feedback = DrawFeedback::default();
    let grid = paint_grid(width, height, |f| feedback = draw(f, app));
    app.apply_draw_feedback(feedback);
    grid
}

/// 描かれた確認ダイアログの枠（枠線を含む）。
fn modal_box(grid: &[Vec<String>], app: &App) -> ratatui::layout::Rect {
    let title = &app.modal.as_ref().expect("確認ダイアログ").title;
    drawn_box(grid, title).unwrap_or_else(|| panic!("確認ダイアログ（{title}）が描かれていない"))
}

/// 確認ダイアログの右の枠線のうち、角を除いた部分（上から順）。スクロールバーはここに描く。
fn right_edge(grid: &[Vec<String>], area: ratatui::layout::Rect) -> Vec<String> {
    let x = usize::from(area.right() - 1);
    (usize::from(area.y) + 1..usize::from(area.bottom()) - 1)
        .map(|y| grid[y][x].clone())
        .collect()
}

/// スクロールバーのつまみの記号（`wrap::draw_scrolled`）。
const THUMB: &str = "█";

/// 確認ダイアログの下辺の「N〜M/T行」。出ていなければ`None`（＝本文が枠に収まっている）。
fn modal_position(
    grid: &[Vec<String>],
    area: ratatui::layout::Rect,
) -> Option<(usize, usize, usize)> {
    let row = &grid[usize::from(area.bottom() - 1)];
    let bottom = squash(&row[usize::from(area.x)..usize::from(area.right())].concat());
    let head = &bottom[..bottom.find("行↑↓")?];
    let digits = head
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '〜' || *c == '/')
        .last()
        .map(|(i, _)| i)?;
    let (first, rest) = head[digits..].split_once('〜')?;
    let (last, total) = rest.split_once('/')?;
    Some((first.parse().ok()?, last.parse().ok()?, total.parse().ok()?))
}

/// 本文のうち、文字のある最後の行（付け替えの明細は区切りの空行で終わる）。
fn last_written_line(app: &App) -> String {
    squash(
        app.modal
            .as_ref()
            .expect("確認ダイアログ")
            .lines
            .iter()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("本文が空"),
    )
}

/// [BUG-196] **`End`で送ると、本文の最後の行が枠の一番下の行に来て、そこで止まる。**
///
/// # 壊れた状態を一文で
///
/// 送る上限が「最後の行が枠の一番上に来る位置」だったので、`↓`を押し続けると本文の最後の行
/// （付け替えの確認では区切りの空行）だけが枠の一番上に残り、**枠がほぼ空になるまで送れた**。
/// 実機（2026-10-02、付け替えの確認・幅120）では下辺が`1〜16/19行`→…→`19〜19/19行`と進んだ。
///
/// 見るのは描いた画面のセルである——最下行に最後の行が見え、一番上の行も空でなく（枠が本文で
/// 詰まっている）、下辺の「N〜M/T行」が描いた行数と食い違わず、それ以上`↓`・`PgDn`・`End`を
/// 押しても画面も状態も動かないこと。
#[test]
fn the_end_key_stops_when_the_last_line_reaches_the_bottom_of_the_box() {
    // (120, 20)は実機で見た形（枠の中16行）。ほかは幅を変えて折り返し方を変えたもの。
    for (width, height) in [(120u16, 20u16), (80, 20), (100, 16)] {
        let ws = workspace();
        let mut app = reassignment_confirmation(ws.path());
        let last = last_written_line(&app);
        let before = frame(&mut app, width, height);
        let area = modal_box(&before, &app);
        assert!(
            modal_position(&before, area).is_some(),
            "{width}×{height}: 台本の前提が崩れた（本文が枠に収まっていて、送る試験にならない）"
        );

        press(&mut app, KeyCode::End);
        let grid = frame(&mut app, width, height);
        let inner = box_inner(&grid, &app.modal.as_ref().expect("modal").title);
        let screen = format!("{width}×{height}:\n{}", inner.join("\n"));
        let bottom = squash(inner.last().expect("枠の中が無い"));
        assert!(
            !bottom.is_empty() && last.ends_with(&bottom),
            "最後の行（{last}）が枠の一番下の行に無い:\n{screen}"
        );
        assert!(
            !squash(&inner[0]).is_empty(),
            "枠の一番上が空（本文で詰まっていない）:\n{screen}"
        );
        let (first, shown_last, total) =
            modal_position(&grid, area).unwrap_or_else(|| panic!("位置の表示が消えた:\n{screen}"));
        assert_eq!(
            shown_last, total,
            "末尾なのに下辺が末尾と言っていない:\n{screen}"
        );
        assert_eq!(
            shown_last - first + 1,
            inner.len(),
            "下辺の「{first}〜{shown_last}」が、枠の中の行数（{}）と食い違う:\n{screen}",
            inner.len()
        );

        let scroll = app.modal_scroll;
        for code in [KeyCode::Down, KeyCode::PageDown, KeyCode::End] {
            press(&mut app, code);
            let again = frame(&mut app, width, height);
            assert!(again == grid, "{code:?}で末尾より先へ動いた:\n{screen}");
            assert_eq!(app.modal_scroll, scroll, "{code:?}で状態だけが先へ進んだ");
        }
    }
}

/// [BUG-196] **許可側**（`B-35`）: 本文が枠に収まるなら、どのキーでも送れない（画面が1セルも動かない）。
///
/// 以前は収まっている本文でも`End`で最後の行が枠の一番上へ動き、枠がほぼ空になった（決定32の
/// 残課題に書いてあった形）。
#[test]
fn a_confirmation_that_fits_does_not_move_on_any_scroll_key() {
    let ws_transition = workspace();
    let ws_reassign = workspace();
    for (name, mut app) in [
        (
            "遷移",
            transition_confirmation_to(ws_transition.path(), "build"),
        ),
        ("付け替え", reassignment_confirmation(ws_reassign.path())),
    ] {
        let before = frame(&mut app, 120, 60);
        assert!(
            modal_position(&before, modal_box(&before, &app)).is_none(),
            "{name}: 台本の前提が崩れた（収まっていない）"
        );
        for code in [KeyCode::Down, KeyCode::PageDown, KeyCode::End] {
            press(&mut app, code);
            let after = frame(&mut app, 120, 60);
            assert!(
                after == before,
                "{name}: 収まっている本文が{code:?}で動いた"
            );
            assert_eq!(app.modal_scroll, 0, "{name}: {code:?}で状態だけが動いた");
        }
    }
}

/// [BUG-196] **末尾で押した`↓`の分を溜めない**（BUG-076と同じ形）。送りの上限は描くまで分からないので、
/// キーの側は上限を掛けずに進め、描いた後に状態を切り詰める。切り詰めを忘れると、末尾で押した分だけ
/// `↑`が空回りする。
#[test]
fn pressing_down_at_the_end_does_not_bank_up_rows_to_unwind() {
    let ws = workspace();
    let mut app = reassignment_confirmation(ws.path());
    frame(&mut app, 80, 20);
    press(&mut app, KeyCode::End);
    let grid = frame(&mut app, 80, 20);
    let area = modal_box(&grid, &app);
    let (first, _, _) = modal_position(&grid, area).expect("台本の前提が崩れた（収まっている）");
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
        frame(&mut app, 80, 20);
    }
    press(&mut app, KeyCode::Up);
    let grid = frame(&mut app, 80, 20);
    let (moved, _, _) = modal_position(&grid, area).expect("位置の表示が消えた");
    assert_eq!(moved + 1, first, "末尾で押した↓の分だけ↑が空回りした");
}

/// [BUG-196] **長い差分は1行ずつ・10行ずつ送れて、`Home`で先頭へ戻り、閉じたら次は先頭から。**
/// 送る単位は折り返した後の表示行で、下辺の「N〜M/T行」の数え方と同じである。
///
/// 以前は`edit_tests`が状態だけで「`End`で`lines.len() - 1`」を見ていた。上限が描画から来るようになった
/// ので、描いて書き戻す経路（[`frame`]）を通してここで見る。
#[test]
fn a_long_diff_scrolls_row_by_row_and_page_by_page_and_stops_at_the_end() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.modal = Some(state::Modal {
        title: "承認の確認".to_string(),
        lines: (0..50).map(|i| format!("  + fs.read = C:/x/{i}")).collect(),
        confirm: Confirm::Approval,
    });
    // 下辺の「N〜M/T行」と、枠の中の行数。
    let shown = |app: &mut App| {
        let grid = frame(app, 120, 40);
        let (first, last, total) =
            modal_position(&grid, modal_box(&grid, app)).expect("収まらない本文で位置が出ていない");
        (first, last, total, box_inner(&grid, "承認の確認").len())
    };
    assert_eq!(shown(&mut app).0, 1);
    press(&mut app, KeyCode::Down);
    assert_eq!(shown(&mut app).0, 2);
    press(&mut app, KeyCode::PageDown);
    assert_eq!(shown(&mut app).0, 12);
    press(&mut app, KeyCode::End);
    let at_end = shown(&mut app);
    let (first, last, total, rows) = at_end;
    assert_eq!((last, total), (50, 50), "End で末尾へ届かない");
    assert_eq!(
        last - first + 1,
        rows,
        "End で最後の行が枠の一番下に来ていない（{first}〜{last}を{rows}行の枠に見せている）"
    );
    press(&mut app, KeyCode::Down);
    assert_eq!(shown(&mut app), at_end, "末尾より先へ進んだ");
    press(&mut app, KeyCode::Home);
    assert_eq!(shown(&mut app).0, 1);

    // 送った状態から閉じても、次に開いたときは先頭から。
    press(&mut app, KeyCode::End);
    frame(&mut app, 120, 40);
    press(&mut app, KeyCode::Esc);
    assert!(app.modal.is_none());
    assert_eq!(app.modal_scroll, 0);
}

/// [BUG-196] **スクロールバーは本文が枠に収まらないときだけ出る。** 収まるときは右の枠線のまま。
#[test]
fn the_scrollbar_is_drawn_only_when_the_text_overflows() {
    for (size, overflows) in [((80u16, 20u16), true), ((120, 60), false)] {
        let ws = workspace();
        let mut app = reassignment_confirmation(ws.path());
        let grid = frame(&mut app, size.0, size.1);
        let area = modal_box(&grid, &app);
        assert_eq!(
            modal_position(&grid, area).is_some(),
            overflows,
            "{size:?}: 台本の前提が崩れた"
        );
        let edge = right_edge(&grid, area);
        if overflows {
            assert!(
                edge.iter().any(|cell| cell == THUMB),
                "{size:?}: 収まらないのにスクロールバーが無い: {edge:?}"
            );
        } else {
            assert!(
                edge.iter().all(|cell| cell == "│"),
                "{size:?}: 収まっているのに右の枠線が枠線でない: {edge:?}"
            );
        }
    }
}

/// [BUG-196] **つまみは先頭では一番上、末尾では一番下に付く。** どこを見ているかを、つまみの位置が
/// 下辺の「N〜M/T行」と同じ向きで言う。
#[test]
fn the_scrollbar_thumb_touches_the_top_at_the_start_and_the_bottom_at_the_end() {
    let ws = workspace();
    let mut app = reassignment_confirmation(ws.path());
    let grid = frame(&mut app, 80, 20);
    let edge = right_edge(&grid, modal_box(&grid, &app));
    assert_eq!(
        edge.first().map(String::as_str),
        Some(THUMB),
        "先頭でつまみが一番上に無い: {edge:?}"
    );
    assert_ne!(
        edge.last().map(String::as_str),
        Some(THUMB),
        "先頭でつまみが一番下まで伸びている: {edge:?}"
    );

    press(&mut app, KeyCode::End);
    let grid = frame(&mut app, 80, 20);
    let edge = right_edge(&grid, modal_box(&grid, &app));
    assert_eq!(
        edge.last().map(String::as_str),
        Some(THUMB),
        "末尾でつまみが一番下に無い: {edge:?}"
    );
    assert_ne!(
        edge.first().map(String::as_str),
        Some(THUMB),
        "末尾でつまみが一番上に残っている: {edge:?}"
    );
}

/// [BUG-196] **許可側**: スクロールバーは本文の右端の文字を隠さない。本文の幅をちょうど埋める行の
/// 最後の文字が、送れる状態でも見えている（スクロールバーを枠の内側へ描いたのに折り返しの幅を
/// 減らさない、という壊し方を止める）。本文の幅は枠の中から右端の1桁を空けた幅（BUG-200）。
#[test]
fn the_scrollbar_does_not_hide_the_last_character_of_a_full_width_line() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    // 80桁の端末では枠も80桁、中は78桁、本文は右端の1桁を空けた77桁（BUG-200）。
    // 各行をちょうど77桁にして、最後の1桁を`Z`にする。
    app.modal = Some(state::Modal {
        title: "承認の確認".to_string(),
        lines: (0..40)
            .map(|i| format!("{i:02}{}Z", "-".repeat(74)))
            .collect(),
        confirm: Confirm::Approval,
    });
    let grid = frame(&mut app, 80, 24);
    assert!(
        right_edge(&grid, modal_box(&grid, &app)).contains(&THUMB.to_string()),
        "台本の前提が崩れた（スクロールバーが出ていない）"
    );
    let inner = box_inner(&grid, "承認の確認");
    assert!(
        inner
            .iter()
            .all(|row| row.len() == 78 && row.ends_with("Z ")),
        "行の最後の文字が見えない（隠れたか、折り返した）:\n{}",
        inner.join("\n")
    );
}

// ---------------------------------------------------------------------------
// 後ろの画面の上に重ねる枠（確認ダイアログ・ヘルプ）の左の枠線。[BUG-198]
//
// 後ろの画面の全角文字が重ねる枠の左隣の桁から始まると、その2桁目が枠線の桁に掛かる。ratatuiは
// 前のフレームとの差分を端末へ送るとき、全角文字の2桁目に当たるセルを飛ばすので、枠線がそのセルに
// 置かれていても端末へは送られない。[`paint_grid`]が読むのは`TestBackend`が**受け取った差分**を
// 書き込んだ画面なので、端末と同じ形で欠ける。
// ---------------------------------------------------------------------------

/// 後ろの画面の代わりに、`symbol`を行ごとに1桁ずつずらして敷き詰める。全角なら、どの桁にも
/// 全角文字の前半が来る行と後半が来る行がある（重ねる枠の左隣の桁に前半が来る行が必ずある）。
fn fill_background(frame: &mut Frame, symbol: &str) {
    let area = frame.area();
    let rows: Vec<Line> = (0..area.height)
        .map(|y| {
            Line::raw(format!(
                "{}{}",
                " ".repeat(usize::from(y % 2)),
                symbol.repeat(usize::from(area.width))
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(rows), area);
}

/// 収まる短い確認ダイアログ（スクロールバーは出ない）。
fn paint_short_modal(frame: &mut Frame) {
    let modal = state::Modal {
        title: "承認の確認".to_string(),
        lines: (0..5).map(|i| format!("  + fs.read = C:/x/{i}")).collect(),
        confirm: Confirm::Approval,
    };
    draw_modal(frame, frame.area(), &modal, 0);
}

fn paint_help(frame: &mut Frame) {
    draw_help(frame, frame.area());
}

/// 画面へ重ねる枠を1つ描く手順。
type Paint = fn(&mut Frame);

/// 後ろの画面の上に重ねる枠のすべて（名前・見出し・描き方）。製品で`open_overlay`を通る枠と同じ組。
const OVERLAYS: [(&str, &str, Paint); 2] = [
    ("確認ダイアログ", "承認の確認", paint_short_modal),
    ("ヘルプ", "ヘルプ", paint_help),
];

/// `background`を敷いた上に`paint`で重ねた枠と、その画面。枠の位置は、半角だけを敷いて描いたときの
/// セルから読む（全角を敷いた画面では、位置を読むのに使う角の記号そのものが欠け得るため）。
fn overlay_over(
    width: u16,
    height: u16,
    title: &str,
    background: &str,
    paint: Paint,
) -> (ratatui::layout::Rect, Vec<Vec<String>>) {
    let plain = paint_grid(width, height, |f| {
        fill_background(f, "x");
        paint(f);
    });
    let area = drawn_box(&plain, title).unwrap_or_else(|| panic!("{title}の枠が描かれていない"));
    let grid = paint_grid(width, height, |f| {
        fill_background(f, background);
        paint(f);
    });
    (area, grid)
}

/// 枠の行ごとに、左の枠線の記号（上から`┌`・`│`…・`└`）が欠けていないか。欠けた行を返す。
///
/// **右の枠線はここでは見ない。** 後ろの画面は右の枠線に掛からない（枠の中から始まる全角文字は
/// `Clear`が消す）。右の枠線は別の形で欠けることがある——枠の中の折り返した本文が、行末の全角文字で
/// 1桁はみ出す（ratatuiの単語折り返しの性質。BUG-198の「残っているもの」）。それをここで混ぜると、
/// この試験が何で赤くなったのか分からなくなる。
fn broken_left_border_rows(grid: &[Vec<String>], area: ratatui::layout::Rect) -> Vec<String> {
    let left = usize::from(area.x);
    let (top, bottom) = (usize::from(area.y), usize::from(area.bottom() - 1));
    (top..=bottom)
        .filter_map(|y| {
            let want = match y {
                y if y == top => "┌",
                y if y == bottom => "└",
                _ => "│",
            };
            (grid[y][left] != want)
                .then(|| format!("{y}行目: 「{}」 / {}", grid[y][left], grid[y].concat()))
        })
        .collect()
}

/// [BUG-198] **後ろの画面に全角文字が並んでいても、重ねた枠の左の枠線はどの行でも欠けない。**
///
/// # 壊れた状態を一文で
///
/// 後ろの画面の全角文字が枠の左隣の桁から始まる行で、左の枠線が端末へ送られず、全角文字の2桁目が
/// そのまま見えていた（BUG-196の報告で、付け替えの確認画面を描いた画面から見つけた）。
/// 幅を変えて、枠の左隣の桁が偶数の場合と奇数の場合の両方を描く。
#[test]
fn an_overlay_keeps_its_left_border_over_wide_characters() {
    let mut failures = Vec::new();
    for (name, title, paint) in OVERLAYS {
        for (width, height) in [(120u16, 30u16), (119, 30), (100, 24)] {
            let (area, grid) = overlay_over(width, height, title, "あ", paint);
            assert!(
                area.x >= 2,
                "{name} {width}×{height}: 台本の前提が崩れた（枠が左端に付いている）"
            );
            let broken = broken_left_border_rows(&grid, area);
            if !broken.is_empty() {
                failures.push(format!("{name} {width}×{height}:\n{}", broken.join("\n")));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "重ねた枠の左の枠線が欠けた:\n{}",
        failures.join("\n\n")
    );
}

/// [BUG-198] **許可側**: 枠の左側の文字は、枠線に掛かる全角文字1つを除いて消さない。
///
/// 半角は1つも消えず、全角は枠線の桁に掛かるものだけが空白になる（重ねる枠を左右に1桁ずつ広く消す、
/// という直し方なら半角も消える——その壊し方を止める）。
#[test]
fn an_overlay_erases_only_the_wide_character_that_reaches_its_border() {
    for (name, title, paint) in OVERLAYS {
        let (width, height) = (120u16, 30u16);
        let (area, narrow) = overlay_over(width, height, title, "x", paint);
        let (_, wide) = overlay_over(width, height, title, "あ", paint);
        let left = usize::from(area.x);
        for y in usize::from(area.y)..usize::from(area.bottom()) {
            let offset = y % 2;
            assert_eq!(
                narrow[y][..left].concat(),
                format!("{}{}", " ".repeat(offset), "x".repeat(left - offset)),
                "{name}: {y}行目で、枠の左の半角が消えた"
            );
            // 枠の左に丸ごと入る全角文字は残り、枠線の桁に掛かるものは空白になる。
            let whole = (left - offset) / 2;
            assert_eq!(
                squash(&wide[y][..left].concat()),
                "あ".repeat(whole),
                "{name}: {y}行目で、枠の左の全角文字が想定と違う: {}",
                wide[y][..left].concat()
            );
        }
    }
}

/// [BUG-198] **重ねる枠はどれも`open_overlay`を通る。** 上の2本は[`OVERLAYS`]の組しか描かないので、
/// 重ねる枠を足したのに`open_overlay`を通さず消すと、その枠だけ欠けが戻っても気付けない。
/// 重ねる枠は`draw`（`tui/mod.rs`）が画面の後に描くので、そのファイルで数える。消し方そのものは
/// 会話TUIと共有する`harness_term::overlay::clear`が持ち、`Clear`を直接使う箇所が無いことは
/// [`every_wrapped_text_and_overlay_goes_through_harness_term`]が数える。
#[test]
fn every_overlay_goes_through_open_overlay() {
    let source = include_str!("mod.rs");
    assert_eq!(
        source.matches("harness_term::overlay::clear(").count(),
        1,
        "重ねる枠を消す箇所が`open_overlay`の外にもある"
    );
    assert_eq!(
        source.matches("open_overlay(frame,").count(),
        OVERLAYS.len(),
        "`open_overlay`を通る枠と、試験が描く枠の組（OVERLAYS）が食い違う"
    );
}

/// [BUG-198] **実際の画面でも**、付け替えの確認画面の左の枠線は、後ろの宣言画面の全角文字に欠けない。
/// BUG-196の報告で欠けを見つけた画面（宣言画面の上の付け替えの確認、120×20）を、描いて書き戻す経路で描く。
#[test]
fn the_reassignment_confirmation_keeps_its_left_border_over_the_declared_screen() {
    let ws = workspace();
    let mut app = reassignment_confirmation(ws.path());
    let grid = frame(&mut app, 120, 20);
    let area = modal_box(&grid, &app);
    let broken = broken_left_border_rows(&grid, area);
    assert!(
        broken.is_empty(),
        "確認画面の左の枠線が欠けた:\n{}",
        broken.join("\n")
    );
}

// ---------------------------------------------------------------------------
// 折り返して描く枠の右の枠線。[BUG-200]
//
// ratatuiの単語折り返しは、あふれるかどうかを「いまの文字を足す前の幅」で判定する。だから語の最後の
// 全角文字が行の最後の1桁から始まると、その行は1桁長くなり、全角文字の後半が右の枠線の桁に掛かる。
// 枠線のセルは全角文字の後半として端末へ送られない（BUG-198と同じ仕組み）。
// ---------------------------------------------------------------------------

/// ratatuiの単語折り返しが`width`桁の場所で1桁はみ出す1行。「短い語・空白・全角だけの語」で、
/// 全角の語の最後の文字がちょうど最後の1桁から始まる（ヘルプの1行目と同じ形。
/// `harness_term`の試験の同名の関数と同じ作り方）。
fn spilling_line(width: u16) -> String {
    let width = usize::from(width);
    let head = if width % 2 == 1 { "a" } else { "ab" };
    let wide = (width - head.len()) / 2;
    format!("{head} {}", "あ".repeat(wide))
}

/// 枠の行ごとに、右の枠線の記号（上から`┐`・`│`…・`┘`）が欠けていないか。欠けた行を返す。
/// 右の枠線の上はスクロールバーのつまみでもよい（BUG-196）。
fn broken_right_border_rows(grid: &[Vec<String>], area: ratatui::layout::Rect) -> Vec<String> {
    let right = usize::from(area.right() - 1);
    let (top, bottom) = (usize::from(area.y), usize::from(area.bottom() - 1));
    (top..=bottom)
        .filter_map(|y| {
            let ok = match y {
                y if y == top => grid[y][right] == "┐",
                y if y == bottom => grid[y][right] == "┘",
                _ => grid[y][right] == "│" || grid[y][right] == THUMB,
            };
            (!ok).then(|| format!("{y}行目: 「{}」 / {}", grid[y][right], grid[y].concat()))
        })
        .collect()
}

/// [BUG-200] **行の最後の文字が全角で、枠の中の最後の1桁から始まっても、右の枠線は欠けない。**
///
/// # 壊れた状態を一文で
///
/// ヘルプの1行目（`harness-policy-editor — LLMを介さずに「…」を決める道具`）は77桁で、枠の中は76桁
/// なので、ratatuiの折り返しは「道具」の「具」を最後の1桁に置き、その後半が右の枠線を覆っていた
/// （端末が78桁以上あればいつも）。確認ダイアログと説明欄も、同じ形の行が来れば同じように欠ける。
#[test]
fn a_wrapped_box_keeps_its_right_border_when_a_line_ends_with_a_wide_character() {
    // 説明欄と同じ部品（`wrap::draw_box`）で描く枠。中は38桁。
    let notes = |frame: &mut Frame| {
        wrap::draw_box(
            frame,
            ratatui::layout::Rect::new(0, 0, 40, 6),
            spilling_line(38),
            Block::default().borders(Borders::ALL).title("説明"),
        );
    };
    // 確認ダイアログ。枠は88桁（`MODAL_WIDTH`）で、中は86桁。
    let modal = |frame: &mut Frame| {
        let modal = state::Modal {
            title: "承認の確認".to_string(),
            lines: vec![spilling_line(86), "最後の行".to_string()],
            confirm: Confirm::Approval,
        };
        draw_modal(frame, frame.area(), &modal, 0);
    };
    let boxes: [(&str, &str, Paint); 3] = [
        ("ヘルプ", "ヘルプ", paint_help),
        ("確認ダイアログ", "承認の確認", modal),
        ("説明欄", "説明", notes),
    ];
    let mut failures = Vec::new();
    for (name, title, paint) in boxes {
        let grid = paint_grid(120, 100, paint);
        let area = drawn_box(&grid, title).unwrap_or_else(|| panic!("{name}の枠が無い"));
        let broken = broken_right_border_rows(&grid, area);
        if !broken.is_empty() {
            failures.push(format!("{name}:\n{}", broken.join("\n")));
        }
    }
    assert!(
        failures.is_empty(),
        "右の枠線が欠けた:\n{}",
        failures.join("\n\n")
    );
}

/// [BUG-200] **枠の無い知らせの行も、端末の右端より先へはみ出さない。** 右端の1桁に全角文字の前半が
/// 来ると、後半は端末の外になる（端末によっては次の行へ回り込み、画面が崩れる）。
#[test]
fn the_status_line_does_not_spill_past_the_right_edge() {
    use ratatui::buffer::CellWidth;

    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    let width = 100u16;
    app.status = spilling_line(width);
    let mut terminal = Terminal::new(TestBackend::new(width, 30)).expect("test terminal");
    terminal
        .draw(|f| {
            draw(f, &app);
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let spilled: Vec<u16> = (0..30)
        .filter(|&y| buffer[(width - 1, y)].cell_width() > 1)
        .collect();
    assert!(
        spilled.is_empty(),
        "右端の1桁に全角文字の前半がある行: {spilled:?}"
    );
}

/// [BUG-200] **折り返して描く本文は、どれも`harness_term::wrap`を通る。** 描く幅と数える幅を
/// 1か所で狭くしているので、`Wrap`や`line_count`を直接使う箇所が1つでもあると、そこだけ欠けが戻るか、
/// 数えた行数と描いた行数が食い違う。重ねる枠の消し方（BUG-198）も同じく`harness_term::overlay`だけが持つ。
#[test]
fn every_wrapped_text_and_overlay_goes_through_harness_term() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![root.clone()];
    let mut offenders = Vec::new();
    while let Some(path) = files.pop() {
        if path.is_dir() {
            files.extend(
                std::fs::read_dir(&path)
                    .expect("read_dir")
                    .map(|entry| entry.expect("entry").path()),
            );
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read");
        for needle in ["Wrap {", "line_count(", "render_widget(Clear"] {
            let count = source.matches(needle).count();
            if count > 0 {
                offenders.push(format!("{}: {needle} ×{count}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "harness_term を通さずに折り返す・重ねる箇所がある:\n{}",
        offenders.join("\n")
    );
}

/// [BUG-192] ヘルプの高さも折り返した後の行数で数える。**端末が十分に高ければ最後の行まで読める。**
///
/// 「高さは本文から数える」（B-09）はヘルプが先に直していたが、数えていたのは折り返す前の行だった。
#[test]
fn the_help_box_is_as_tall_as_its_wrapped_text() {
    let screen = flatten(&paint_rows(100, 400, |f| draw_help(f, f.area())));
    let last = squash(HELP_TEXT.lines().last().expect("ヘルプが空"));
    assert!(
        screen.contains(&last),
        "背の高い端末でもヘルプの最後の行が切れている:\n{screen}"
    );
    assert!(
        !screen.contains("収まっていません"),
        "収まっているのに切れたと言っている"
    );
}

/// [BUG-192] **端末が低くて収まらないときは、切れた行数を枠に出す**（黙って切らない、`B-09`）。
/// 行数は背の高い端末で描いたときの枠の中の行数から測る（描画と同じ数え方を試験に写さない）。
#[test]
fn a_help_taller_than_the_terminal_says_how_many_lines_are_cut() {
    let text_rows = box_height(&paint_rows(100, 400, |f| draw_help(f, f.area()))) - 2;
    let height = 40u16;
    let hidden = text_rows - usize::from(height - 2);
    let screen = flatten(&paint_rows(100, height, |f| draw_help(f, f.area())));
    assert!(
        screen.contains(&format!("下の{hidden}行")),
        "切れた行数（{hidden}行）を言っていない:\n{screen}"
    );
}

/// 知らせの行（`app.status`）。宣言画面の下の枠の下辺と、最下行（キー案内）の間にある。
fn status_rows(rows: &[String]) -> &[String] {
    let bottom = rows
        .iter()
        .rposition(|row| row.contains('└'))
        .expect("枠が無い");
    &rows[bottom + 1..rows.len() - 1]
}

/// [BUG-192] **知らせの行は、幅に収まらなくても最後まで読める。**
///
/// # 壊れた状態を一文で
///
/// 知らせの行は1行固定で折り返さず、右端で黙って切れていた。宣言画面で`c`（種類の付け替え）を
/// 押すと「…（そのパス1つだけ）にします。権限が広がり」で切れ、**付け替えでいちばん読ませたい
/// 「権限が広がります」が見えなかった**（2026-10-02、実機）。
#[test]
fn the_status_line_wraps_instead_of_being_cut_at_the_right_edge() {
    let ws = workspace();
    let mut domain = crate::policy_file::PolicyDomain::new("view-check");
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/data".to_string());
    let mut app = declared_screen_with(ws.path(), domain);
    press(&mut app, KeyCode::Char('c'));
    assert!(
        app.status.contains("権限が広がります"),
        "台本の前提が崩れた: {}",
        app.status
    );

    let failures: Vec<String> = [80u16, 100, 120, 142, 200]
        .into_iter()
        .filter_map(|width| {
            let rows = paint_rows(width, 30, |f| {
                draw(f, &app);
            });
            (flatten(status_rows(&rows)) != squash(&app.status))
                .then(|| format!("{width}桁:\n{}", status_rows(&rows).join("\n")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "知らせの行が切れている（全文: {}）:\n{}",
        app.status,
        failures.join("\n\n")
    );
}

/// [BUG-192] **許可側**: 1行に収まる知らせは今までどおり1行で、本文の枠を押し上げない。
#[test]
fn a_short_status_stays_on_one_row() {
    let ws = workspace();
    let mut domain = crate::policy_file::PolicyDomain::new("view-check");
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/data".to_string());
    let mut app = declared_screen_with(ws.path(), domain);
    app.status = "短い知らせ".to_string();
    let rows = paint_rows(120, 30, |f| {
        draw(f, &app);
    });
    assert_eq!(status_rows(&rows).len(), 1, "{}", rows.join("\n"));
    assert_eq!(flatten(status_rows(&rows)), "短い知らせ");
}

/// [BUG-192] **宣言画面の説明欄は、各文の最後まで読める。**
///
/// 実機（幅およそ120桁）で「…yで配下をまとめて承認を予約できま」の後ろが見えないと報告された
/// （2026-10-02）。描画を測ると、118〜134桁のどの幅でも続き（「す。」など）は次の行の頭に出ていた。
/// 描画の上で実際に切れていたのは、手で数えた固定の高さ（10行）に入り切らない80桁で、
/// **注記（`unapprove::ACE_NOTICE`）の末尾が黙って消える**形だった。両方の文の最後まで見る。
#[test]
fn the_declared_screen_notes_show_every_sentence_to_the_end() {
    let ws = workspace();
    let mut domain = crate::policy_file::PolicyDomain::new("view-check");
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/data".to_string());
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/more".to_string());
    let app = declared_screen_with(ws.path(), domain);
    assert_eq!(
        app.declared_approval.not_approved.len(),
        2,
        "台本の前提が崩れた（未承認の宣言が2件ではない）"
    );
    let unapproved =
        "このマシンで未承認の宣言が2件あります（リポジトリに同梱・手書き・以前の承認）。\
                      許可は付きません。yで配下をまとめて承認を予約できます。";
    let notice_tail = squash(
        crate::unapprove::ACE_NOTICE
            .lines()
            .last()
            .expect("注記が空"),
    );
    let failures: Vec<String> = [80u16, 100, 120, 130, 200]
        .into_iter()
        .filter_map(|width| {
            let notes = box_inner(
                &paint_grid(width, 40, |f| {
                    draw(f, &app);
                }),
                " この画面 ",
            );
            let text = flatten(&notes);
            (!text.contains(unapproved) || !text.contains(&notice_tail))
                .then(|| format!("{width}桁:\n{}", notes.join("\n")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "説明欄の文が途中で切れている:\n{}",
        failures.join("\n\n")
    );
}

/// [BUG-192] **許可側**: 折り返さずに収まる幅では、説明欄の高さは今までの10行のまま
/// （一覧の割り付けが変わらない）。
#[test]
fn the_declared_screen_notes_keep_their_height_when_they_fit() {
    let ws = workspace();
    let mut domain = crate::policy_file::PolicyDomain::new("view-check");
    domain
        .fs
        .read
        .push("C:/harness-e2e/view-check-outside/data".to_string());
    let app = declared_screen_with(ws.path(), domain);
    let notes = box_inner(
        &paint_grid(200, 40, |f| {
            draw(f, &app);
        }),
        " この画面 ",
    );
    assert_eq!(notes.len() + 2, 10, "{}", notes.join("\n"));
}

/// [BUG-192] **遷移タブの下の枠（「この画面」）も、狭い端末で注記を黙って切らない。**
/// 中身は「消えてはいけない順」（ACEの注記→予約→読めなかった事実→選択中のフルパス）に並んでおり、
/// 以前は8行固定だったので、狭い端末では末尾の「選択中」から黙って消えていた。
#[test]
fn the_transition_tab_notes_show_the_selected_program_on_a_narrow_terminal() {
    let ws = workspace();
    let app = transition_tab_with_one_candidate(ws.path());
    let last = squash("  観測された引数: git --version");
    let failures: Vec<String> = [80u16, 100, 120]
        .into_iter()
        .filter_map(|width| {
            let notes = box_inner(
                &paint_grid(width, 30, |f| {
                    draw(f, &app);
                }),
                " この画面 ",
            );
            (!flatten(&notes).contains(&last)).then(|| format!("{width}桁:\n{}", notes.join("\n")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "遷移タブの説明欄の末尾が切れている:\n{}",
        failures.join("\n\n")
    );

    // 許可側: 収まる幅では今までの8行のまま。
    let wide = box_inner(
        &paint_grid(200, 30, |f| {
            draw(f, &app);
        }),
        " この画面 ",
    );
    assert_eq!(wide.len() + 2, 8, "{}", wide.join("\n"));
}

/// [BUG-192] **送れない枠は、入り切らなかった行を黙って捨てない。** 編集画面の注記は
/// 記録の中身次第で長くなる（プロセスツリーは何十行にもなる）ので、伸ばせる高さに上限がある。
/// そこで止まったときは、入り切らなかった行数を枠の下辺に出す。
#[test]
fn a_notes_box_that_cannot_grow_any_further_says_how_many_lines_are_cut() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "s1").expect("session dir");
    let mut manifest = RecordManifest::new("s1", "cargo build", ws.path(), ws.path(), 1);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.screen = Screen::Edit;
    app.open_selected_session();
    let view = app.view.as_mut().expect("記録が開けていない");
    // 長い注記（プロセスツリーの代わり）。どの幅でも列の半分には入り切らない量にする。
    view.notes = (0..60)
        .map(|i| format!("注記の{i}行目です。"))
        .collect::<Vec<_>>()
        .join("\n");
    view.common_warnings.clear();

    let grid = paint_grid(120, 30, |f| {
        draw(f, &app);
    });
    let notes = box_inner(&grid, " 記録の読み方");
    let screen = grid.iter().map(|row| row.concat()).collect::<Vec<_>>();
    let shown = notes
        .iter()
        .filter(|row| squash(row).contains("注記の"))
        .count();
    assert!(shown < 60, "台本の前提が崩れた（全部入ってしまった）");
    let hidden = 60 - shown;
    assert!(
        flatten(&screen).contains(&format!("下の{hidden}行が枠に収まっていません")),
        "入り切らなかった{hidden}行を言っていない:\n{}",
        screen.join("\n")
    );
}

/// [BUG-192] **記録画面の見出し枠（いま待っているもの）は、段階の説明を最後まで出す。**
/// 以前は4行固定で、左の列（画面の45%）の幅で説明が折り返すと後ろが黙って切れていた——
/// 収集器を起動する段階では、その後ろが「UACのダイアログが別画面に出ていないか確認してください」だった。
#[test]
fn the_record_screen_header_shows_the_whole_hint() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.command.set_text("cargo build");
    press(&mut app, KeyCode::Enter);
    let hint = squash(app.run.as_ref().expect("記録が始まっていない").phase.hint());
    let failures: Vec<String> = [80u16, 100, 120]
        .into_iter()
        .filter_map(|width| {
            let header = box_inner(
                &paint_grid(width, 30, |f| {
                    draw(f, &app);
                }),
                " いま待っているもの ",
            );
            (!flatten(&header).contains(&hint))
                .then(|| format!("{width}桁:\n{}", header.join("\n")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "見出し枠の説明が途中で切れている:\n{}",
        failures.join("\n\n")
    );
}

/// [BUG-192] **警告枠の「… 他 N行」は、長い警告が折り返しても枠の中に残る。**
/// 以前は折り返す前の行数で「何行入るか」を数えていたので、折り返した分だけ下が押し出され、
/// 省略したことを言う行そのものが枠の外へ出ていた（省略が黙って起きる）。
#[test]
fn the_warning_box_still_says_how_many_lines_it_omitted_when_lines_wrap() {
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    app.command.set_text("cargo build");
    press(&mut app, KeyCode::Enter);
    let long = "実行ファイルへ届きません。宣言に read_exec が要ります。".repeat(2);
    let message = (0..12)
        .map(|i| format!("{i}: {long}"))
        .collect::<Vec<_>>()
        .join("\n");
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Warning(message)));

    let warnings = box_inner(
        &paint_grid(100, 30, |f| {
            draw(f, &app);
        }),
        " ⚠ 対応が要ります",
    );
    let text = flatten(&warnings);
    assert!(
        text.contains("…他") && text.contains("record-session.jsonのwarnings"),
        "省略したことを言う行が見えない:\n{}",
        warnings.join("\n")
    );
    assert!(
        text.contains(&squash(&format!("0: {long}"))),
        "先頭の警告（原因であることが多い）が見えない:\n{}",
        warnings.join("\n")
    );
}

// ---------------------------------------------------------------------------
// ホイールの当たり判定。[BUG-194]
//
// **期待値は描いた画面から読む。** 当たり判定と描画が同じ割り付けの関数を通っているかを
// 確かめるのに、その関数を期待値に使うと、ずれていても一致してしまう（直す前の試験
// `state_tests::the_wheel_hits_the_same_panes_that_are_drawn`がそうだった）。
// ---------------------------------------------------------------------------

/// 記録中の記録画面。さかのぼれる3枠（進行・出力・起動時ノイズ）と、送れない警告枠が全部出ている。
fn running_record_screen(ws: &std::path::Path) -> App {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    app.command.set_text("cargo build");
    press(&mut app, KeyCode::Enter);
    app.on_worker(WorkerMsg::Pass1(RecordEvent::StartupNoise(
        "警告: プロバイダの読み込みに失敗\n".to_string(),
    )));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Warning(
        "実行ファイルへ届きません".to_string(),
    )));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::ChildStarted));
    app.on_worker(WorkerMsg::Pass1(RecordEvent::Stdout(
        "Compiling harness-core\n".to_string(),
    )));
    app
}

/// `(x, y)`でホイールを上へ1刻み回したとき、さかのぼり位置が動いた枠（動かなければ`None`）。
/// **製品の入口（`App::on_scroll`）を通す。** 回した分は同じ位置で下へ回して戻す。
fn wheel_moves(
    app: &mut App,
    size: ratatui::layout::Size,
    x: u16,
    y: u16,
) -> Option<record_screen::ScrollPane> {
    use record_screen::ScrollPane;
    let offsets = |app: &App| {
        let run = app.run.as_ref().expect("記録中");
        [
            run.log_scroll.offset(),
            run.output_scroll.offset(),
            run.noise_scroll.offset(),
        ]
    };
    let before = offsets(app);
    app.on_scroll(size, x, y, true);
    let after = offsets(app);
    app.on_scroll(size, x, y, false);
    assert_eq!(offsets(app), before, "({x},{y}) 回した分が戻っていない");
    let moved: Vec<ScrollPane> = [ScrollPane::Log, ScrollPane::Output, ScrollPane::Noise]
        .into_iter()
        .zip(before.iter().zip(after.iter()))
        .filter(|(_, (b, a))| b != a)
        .map(|(pane, _)| pane)
        .collect();
    assert!(
        moved.len() <= 1,
        "({x},{y}) 2つの枠が同時に動いた: {moved:?}"
    );
    moved.first().copied()
}

/// [BUG-194] **ホイールが送る枠は、ポインタの下に描かれている枠である**（知らせの行が1行でも複数行でも）。
///
/// # 壊れた状態を一文で
///
/// 描画は画面を「タブ1行・本体・知らせ・キー案内1行」に割ってから本体に記録画面を描くが、
/// 当たり判定は**端末全体を本体として**記録画面の割り付けを計算していた。反応する枠は見えている枠より
/// 1行上にずれ、下は知らせの行とキー案内の行まで伸びていた——入力欄の枠の下辺で回すと進行の枠が送られ、
/// 知らせの行の上で回すとその上の枠が送られた。知らせの行が折り返して複数行になると、ずれはその分広がる。
///
/// 画面の全セルを1つずつ回して、描かれた枠（枠線を含む）の中なら**その枠だけ**が、外なら**どれも**
/// 動かないことを見る（許可側と禁止側を同じ走査で見る）。
#[test]
fn the_wheel_scrolls_the_pane_drawn_under_the_pointer() {
    use record_screen::ScrollPane;

    let (width, height) = (100u16, 30u16);
    let size = ratatui::layout::Size::new(width, height);
    let mut reports = Vec::new();
    for (case, status) in [
        ("知らせが1行", "短い知らせ".to_string()),
        (
            "知らせが複数行",
            "長い知らせが折り返して行を増やします。".repeat(8),
        ),
    ] {
        let ws = workspace();
        let mut app = running_record_screen(ws.path());
        app.status = status;
        let grid = paint_grid(width, height, |f| {
            draw(f, &app);
        });
        let rows: Vec<String> = grid.iter().map(|row| row.concat()).collect();
        let status_rows = status_rows(&rows).len();
        if case == "知らせが複数行" {
            assert!(
                status_rows > 1,
                "台本の前提が崩れた（知らせが1行に収まった）"
            );
        } else {
            assert_eq!(status_rows, 1, "台本の前提が崩れた");
        }
        let panes = [
            (ScrollPane::Log, " 進行 "),
            (ScrollPane::Output, " コマンドの出力"),
            (ScrollPane::Noise, " シェル起動時のノイズ"),
        ]
        .map(|(pane, title)| {
            let area = drawn_box(&grid, title)
                .unwrap_or_else(|| panic!("{case}: 「{title}」の枠が描かれていない"));
            (pane, area)
        });

        let mut wrong = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let drawn = panes
                    .iter()
                    .find(|(_, area)| area.contains(ratatui::layout::Position::new(x, y)))
                    .map(|(pane, _)| *pane);
                let moved = wheel_moves(&mut app, size, x, y);
                if drawn != moved {
                    wrong.push(format!(
                        "({x},{y}) 描かれた枠: {drawn:?} / 送られた枠: {moved:?}"
                    ));
                }
            }
        }
        if !wrong.is_empty() {
            reports.push(format!(
                "{case}（知らせ{status_rows}行）: {}セルで、送られる枠が描かれた枠と違う（先頭20件）:\n{}\n\n画面:\n{}",
                wrong.len(),
                wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"),
                rows.join("\n")
            ));
        }
    }
    assert!(reports.is_empty(), "{}", reports.join("\n\n"));
}

/// [BUG-194] **ヘルプや確認ダイアログを重ねている間は、どこで回しても後ろの枠は送られない。**
/// ポインタの下に見えているのは重ねた側で、キー入力もその間は重ねた側だけが受ける（`App::on_key`）。
/// 後ろの枠を送ると、見えないところで位置が変わり、閉じたときに読んでいた場所が失われる。
#[test]
fn the_wheel_does_not_scroll_panes_hidden_behind_an_overlay() {
    let (width, height) = (100u16, 30u16);
    let size = ratatui::layout::Size::new(width, height);
    for overlay in ["ヘルプ", "確認ダイアログ"] {
        let ws = workspace();
        let mut app = running_record_screen(ws.path());
        if overlay == "ヘルプ" {
            app.help = true;
        } else {
            app.modal = Some(state::Modal {
                title: "報告".to_string(),
                lines: vec!["読むだけ".to_string()],
                confirm: Confirm::ReadOnly,
            });
        }
        let moved: Vec<String> = (0..height)
            .flat_map(|y| (0..width).map(move |x| (x, y)))
            .filter_map(|(x, y)| {
                wheel_moves(&mut app, size, x, y).map(|pane| format!("({x},{y}) {pane:?}"))
            })
            .take(20)
            .collect();
        assert!(
            moved.is_empty(),
            "{overlay}を重ねているのに後ろの枠が送られた（先頭20件）:\n{}",
            moved.join("\n")
        );
    }
}
