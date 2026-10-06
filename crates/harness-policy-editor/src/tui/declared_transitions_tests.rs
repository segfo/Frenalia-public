//! 宣言画面（`F3`）の遷移タブの試験（`plans/position-domains/P4.md`のP4.2）。
//!
//! `policy.json`を一時ディレクトリへ書き、`App`へ製品と同じ入口（`App::on_key`）からキーを入れる。
//! 描いた見た目は`TestBackend`で1フレーム描いて、画面のセルから読む（レイアウトの関数を期待値に使わない）。

use harness_policy::transition::ChildOutput;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use harness_policy::policy_file::{
    self, PolicyDomain, PolicyFile, ENTRY_DOMAIN, POLICY_SCHEMA_VERSION,
};
use harness_policy::transition::{AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};

use super::*;
use crate::tui::key_hints::{common_keys, screen_keys, KEY_SEPARATOR};
use crate::tui::state::{Action, App, Confirm, Screen};

const PWSH: &str = "C:/Program Files/PowerShell/7/pwsh.exe";
const CALC: &str = "C:/Windows/System32/calc.exe";
const CMD: &str = "C:/Windows/System32/cmd.exe";
const WHOAMI: &str = "C:/Windows/System32/whoami.exe";
const HOSTNAME: &str = "C:/Windows/System32/HOSTNAME.EXE";

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(crate::session_dir::sandbox_root(dir.path())).expect("sandbox root");
    dir
}

/// エディタが書く形の辺（リテラルの exe・任意の引数）。
fn edge(exe: &str, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: to.to_string(),
        env: None,
        output: ChildOutput::Return,
    }
}

fn domain(name: &str, edges: Vec<TransitionEdge>, reads: &[&str]) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.process.transitions = edges;
    domain.fs.read = reads.iter().map(|r| r.to_string()).collect();
    domain
}

fn policy(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        schema_version: POLICY_SCHEMA_VERSION,
        domains,
    }
}

/// 検査に通る`policy.json`を製品の`save`で書く。
fn save(ws: &Path, domains: Vec<PolicyDomain>) {
    policy_file::save(ws, &policy(domains)).expect("policy.json");
}

/// **検査を通さずに**書く（手で書いた、検査に落ちる`policy.json`を作るため）。
fn write_unchecked(ws: &Path, domains: Vec<PolicyDomain>) {
    let path = policy_file::path(ws);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&policy(domains)).unwrap(),
    )
    .unwrap();
}

fn policy_bytes(ws: &Path) -> Vec<u8> {
    std::fs::read(policy_file::path(ws)).expect("policy.json")
}

fn key(app: &mut App, code: KeyCode) -> Option<Action> {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// 記録画面から`F3`を2回（宣言画面のファイル・通信のタブ → 遷移のタブ）。
fn transition_tab(ws: &Path) -> App {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    key(&mut app, KeyCode::F(3));
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.screen, Screen::Declared);
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Transitions);
    app
}

fn domain_names(app: &App) -> Vec<String> {
    app.declared_transitions
        .domains
        .iter()
        .map(|d| d.name.clone())
        .collect()
}

fn edges_of(ws: &Path, name: &str) -> Vec<TransitionEdge> {
    policy_file::load(ws)
        .expect("policy.json が読める")
        .domain(name)
        .map(|d| d.process.transitions.clone())
        .unwrap_or_default()
}

/// 遷移元`from`の、exe が`exe`の辺の行まで`↓`で移る（行の並びは状態の[`DeclaredTransitionsState::rows`]）。
fn move_to_edge(app: &mut App, from: &str, exe: &ExeMatcher) {
    let state = &app.declared_transitions;
    let target = state
        .rows()
        .iter()
        .position(|row| match row {
            ListedRow::Edge { domain, edge } => {
                let d = &state.domains[*domain];
                d.name == from && d.edges[*edge].edge.exe == *exe
            }
            ListedRow::Domain(_) => false,
        })
        .unwrap_or_else(|| panic!("{from} の {exe:?} の行が無い"));
    while app.declared_transitions.row > target {
        key(app, KeyCode::Up);
    }
    while app.declared_transitions.row < target {
        key(app, KeyCode::Down);
    }
}

fn literal(exe: &str) -> ExeMatcher {
    ExeMatcher::Literal(exe.to_string())
}

/// 1フレーム描いた画面の行（空白を落とす。`TestBackend`は全角1文字を2セルで持つので、素の連結だと字の間に空白が入る）。
fn screen_rows(app: &mut App, width: u16, height: u16) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    let mut feedback = crate::tui::DrawFeedback::default();
    terminal
        .draw(|frame| feedback = crate::tui::draw(frame, app))
        .expect("描画は落ちてはいけない");
    app.apply_draw_feedback(feedback);
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .split_whitespace()
                .collect()
        })
        .collect()
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect()
}

/// `needle`（空白を落とした綴り）を含む行。無ければ画面ごと出して落ちる。
fn row_with<'a>(rows: &'a [String], needle: &str) -> &'a str {
    let needle = squash(needle);
    rows.iter()
        .find(|row| row.contains(&needle))
        .unwrap_or_else(|| panic!("「{needle}」を含む行が無い:\n{}", rows.join("\n")))
}

/// **`F3`をもう一度押すと宣言画面のタブが切り替わる**（決定65 Q12。承認待ちの`F2`と同じ作り）。
/// 他の画面へ行って戻ると、**最後に居たタブ**へ戻り、そこで読み直す（承認待ちの`PendingState::tab`と同じ）。
/// 戻る入口は`F3`と`Ctrl+N`の2つで、どちらも同じ準備（`App::on_enter_screen`）を通る。
/// 対の側（タブの行をクリックしても同じ）は`pointer_tests`の`a_declared_tab_switches_to_that_tab`。
#[test]
fn f3_on_the_declared_screen_switches_to_the_transition_tab_and_back() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &["C:/data/a.txt"]),
            domain("pwsh", vec![], &[]),
        ],
    );
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);

    key(&mut app, KeyCode::F(3));
    assert_eq!(app.screen, Screen::Declared);
    assert_eq!(
        app.declared_transitions.tab,
        DeclaredTab::Declarations,
        "最初はファイル・通信のタブ"
    );
    assert_eq!(
        app.declared.len(),
        1,
        "ファイル・通信のタブが読まれていない"
    );
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Transitions);
    assert_eq!(domain_names(&app), vec!["pwsh", ENTRY_DOMAIN]);
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Declarations);
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Transitions);

    // 別の画面へ行き、その間に辺が増えた。`F3`で戻ると遷移のタブのまま、増えた辺が出る。
    key(&mut app, KeyCode::F(1));
    assert_eq!(app.screen, Screen::Record);
    save(
        ws.path(),
        vec![
            domain(
                ENTRY_DOMAIN,
                vec![edge(PWSH, "pwsh"), edge(CALC, "calc")],
                &["C:/data/a.txt"],
            ),
            domain("pwsh", vec![], &[]),
            domain("calc", vec![], &[]),
        ],
    );
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.screen, Screen::Declared);
    assert_eq!(
        app.declared_transitions.tab,
        DeclaredTab::Transitions,
        "最後に居たタブを覚えていない"
    );
    assert_eq!(
        domain_names(&app),
        vec!["calc", "pwsh", ENTRY_DOMAIN],
        "入り直したのに読み直していない"
    );

    // もう1つの入口（`Ctrl+N`で記録 → 承認待ち → 宣言）でも同じ。
    key(&mut app, KeyCode::F(1));
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &["C:/data/a.txt"]),
            domain("pwsh", vec![], &[]),
        ],
    );
    for _ in 0..2 {
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL));
    }
    assert_eq!(app.screen, Screen::Declared);
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Transitions);
    assert_eq!(
        domain_names(&app),
        vec!["pwsh", ENTRY_DOMAIN],
        "Ctrl+N の入口で読み直していない"
    );
}

/// **ドメインごとに、辺と遷移の形（届く範囲の権限・起動で届くドメイン・最長の連鎖）を見せる**（P3c の`shape`）。
/// 対の側: 閉路があれば最長の連鎖は「上限なし」で、その閉路を出す。
#[test]
fn each_domain_shows_its_edges_reach_and_longest_chain() {
    let ws = workspace();
    // 3つとも同じものを読む（呼び出し元より広い遷移にならないように。広げる遷移は検査に落ちる）。
    let data = ["C:/data/**"];
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &data),
            domain("pwsh", vec![edge(CALC, "calc")], &data),
            domain("calc", vec![], &data),
        ],
    );
    let mut app = transition_tab(ws.path());
    let rows = screen_rows(&mut app, 240, 40);

    let entry = row_with(&rows, &format!("[{ENTRY_DOMAIN}]"));
    assert!(entry.contains(&squash("起動で届く: calc, pwsh")), "{entry}");
    assert!(
        entry.contains(&squash("最長の連鎖: 2段（workspace-shell → pwsh → calc）")),
        "{entry}"
    );
    let pwsh = row_with(&rows, "[pwsh]");
    assert!(pwsh.contains(&squash("届く範囲: ファイル 1件")), "{pwsh}");
    assert!(
        pwsh.contains(&squash("最長の連鎖: 1段（pwsh → calc）")),
        "{pwsh}"
    );
    let calc = row_with(&rows, "[calc]");
    assert!(calc.contains(&squash("起動で届く: なし")), "{calc}");
    assert!(calc.contains(&squash("最長の連鎖: 0段")), "{calc}");
    let edge_row = row_with(&rows, "pwsh.exe");
    assert!(edge_row.contains(&squash("(any arguments)")), "{edge_row}");
    assert!(edge_row.contains(&squash("→ pwsh")), "{edge_row}");
    // 遷移先 pwsh のファイル宣言はこのマシンで承認していない（試験の台帳は空）ので、harness.exe は pwsh を用意しない。
    // **一覧に出ているのに撃つと断られる、を黙らせない**（承認待ちの遷移タブの「起こせない」と同じ表）。
    assert!(
        edge_row.contains(&squash("起こせません（用意されない: このマシンで未承認")),
        "{edge_row}"
    );

    // 閉路（pwsh → pwsh2 → pwsh）。
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![edge("C:/tools/a.exe", "pwsh2")], &[]),
            domain("pwsh2", vec![edge("C:/tools/b.exe", "pwsh")], &[]),
        ],
    );
    let mut app = transition_tab(ws.path());
    let rows = screen_rows(&mut app, 240, 40);
    let pwsh = row_with(&rows, "[pwsh]");
    assert!(
        pwsh.contains(&squash("最長の連鎖: 上限なし（閉路: pwsh → pwsh2 → pwsh）")),
        "{pwsh}"
    );
}

/// **手で書いた自己ループ辺に印を付ける**（決定65(3)。自己ループ辺は凍結中で、エディタは新しく書かない）。
/// 対の側: 別のドメインへの辺には出ない。
#[test]
fn a_hand_written_self_loop_is_marked() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(
                ENTRY_DOMAIN,
                vec![edge(CMD, ENTRY_DOMAIN), edge(PWSH, "pwsh")],
                &[],
            ),
            domain("pwsh", vec![], &[]),
        ],
    );
    let mut app = transition_tab(ws.path());
    let entry = app
        .declared_transitions
        .domains
        .iter()
        .find(|d| d.name == ENTRY_DOMAIN)
        .expect("入口のドメイン");
    let marks: Vec<bool> = entry.edges.iter().map(|e| e.self_loop).collect();
    assert_eq!(marks, vec![true, false]);

    let rows = screen_rows(&mut app, 240, 40);
    let cmd = row_with(&rows, "cmd.exe");
    assert!(
        cmd.contains(&squash(
            "⟲ 自己ループ辺（手書き。エディタは書きません——決定65）"
        )),
        "{cmd}"
    );
    let pwsh = row_with(&rows, "pwsh.exe");
    assert!(!pwsh.contains("自己ループ"), "{pwsh}");
    // 宣言を持たない遷移先は共通の土台だけで用意される見込みなので、起こせる。
    assert!(
        pwsh.contains("起こせる") && !pwsh.contains("起こせません"),
        "{pwsh}"
    );
}

/// **`Space`→`a`→`y`で、その行の遷移元のドメインから辺が消える。** 確認ダイアログを出した時点では
/// `policy.json`は1バイトも変わらない。対の側: `n`で閉じると何も変わらない。
#[test]
fn space_then_a_then_y_removes_the_edge_from_that_rows_domain() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![edge(CALC, "calc")], &[]),
            domain("calc", vec![], &[]),
        ],
    );
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    move_to_edge(&mut app, "pwsh", &literal(CALC));
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Char('a'));

    let modal = app.modal.as_ref().expect("確認ダイアログが出ていない");
    assert_eq!(modal.confirm, Confirm::DeclaredTransitions);
    let dialog = modal.lines.join("\n");
    assert!(dialog.contains("遷移元ドメイン pwsh"), "{dialog}");
    assert!(dialog.contains(&format!("- {CALC}")), "{dialog}");
    assert!(
        !dialog.contains(&format!("遷移元ドメイン {ENTRY_DOMAIN}")),
        "{dialog}"
    );
    assert_eq!(
        policy_bytes(ws.path()),
        before,
        "確認ダイアログを出しただけで書いた"
    );

    // `n`で閉じる。
    key(&mut app, KeyCode::Char('n'));
    assert!(app.modal.is_none());
    assert_eq!(policy_bytes(ws.path()), before, "n で閉じたのに書いた");

    // もう一度`a`→`y`。
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Char('y'));
    assert!(app.modal.is_none());
    assert!(edges_of(ws.path(), "pwsh").is_empty(), "{}", app.status);
    assert_eq!(
        edges_of(ws.path(), ENTRY_DOMAIN),
        vec![edge(PWSH, "pwsh")],
        "別の遷移元の辺まで消えた"
    );
    assert!(
        app.declared_transitions.remove.is_empty(),
        "書いた後に予約が残った"
    );
    assert!(app.status.contains("取り消しました"), "{}", app.status);
}

/// **2つのドメインの辺の取り消しを、1回の`y`で書く**（`plan_removals`が1つの`PolicyFile`に両方を当てる）。
/// 対の側: ダイアログを見ている間に片方が別の経路で消えていたら、残りは消え、消えなかったものを数えて言う。
#[test]
fn removals_from_two_domains_are_written_with_one_save() {
    let domains = || {
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![edge(CALC, "calc")], &[]),
            domain("calc", vec![], &[]),
        ]
    };
    let reserve_both = |app: &mut App| {
        move_to_edge(app, "pwsh", &literal(CALC));
        key(app, KeyCode::Char(' '));
        move_to_edge(app, ENTRY_DOMAIN, &literal(PWSH));
        key(app, KeyCode::Char(' '));
    };

    let ws = workspace();
    save(ws.path(), domains());
    let mut app = transition_tab(ws.path());
    reserve_both(&mut app);
    let plan = crate::transition_approve::plan_removals(
        ws.path(),
        &app.declared_transitions.reserved_edges(),
        &[],
        1,
    )
    .expect("plan");
    assert_eq!(plan.removed.len(), 2, "{:?}", plan.removed);
    for name in ["pwsh", ENTRY_DOMAIN] {
        assert!(
            plan.file
                .domain(name)
                .unwrap()
                .process
                .transitions
                .is_empty(),
            "1つの PolicyFile に {name} の取り消しが入っていない"
        );
    }
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Char('y'));
    assert!(edges_of(ws.path(), "pwsh").is_empty());
    assert!(edges_of(ws.path(), ENTRY_DOMAIN).is_empty());

    // ダイアログを見ている間に、pwsh の辺が別の経路で消えた。
    let ws = workspace();
    save(ws.path(), domains());
    let mut app = transition_tab(ws.path());
    reserve_both(&mut app);
    key(&mut app, KeyCode::Char('a'));
    assert!(app.modal.is_some());
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![], &[]),
            domain("calc", vec![], &[]),
        ],
    );
    key(&mut app, KeyCode::Char('y'));
    assert!(
        edges_of(ws.path(), ENTRY_DOMAIN).is_empty(),
        "{}",
        app.status
    );
    assert!(
        app.status.contains("宣言に無くて消えないもの 1件"),
        "{}",
        app.status
    );
}

/// **手で書いたパターンの辺も取り消せる**（承認待ちの遷移タブの指し方＝リテラルの exe だけでは指せない辺）。
#[test]
fn a_hand_written_pattern_edge_can_be_removed() {
    let ws = workspace();
    // パターンは小文字で書く（照合は小文字へ畳んでから行うので、大文字は一致しないと検査が断る）。
    let pattern = ExeMatcher::Pattern("c:/tools/*.exe".to_string());
    save(
        ws.path(),
        vec![
            domain(
                ENTRY_DOMAIN,
                vec![TransitionEdge {
                    exe: pattern.clone(),
                    ..edge("", "tools")
                }],
                &[],
            ),
            domain("tools", vec![], &[]),
        ],
    );
    let mut app = transition_tab(ws.path());
    move_to_edge(&mut app, ENTRY_DOMAIN, &pattern);
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Char('y'));
    assert!(
        edges_of(ws.path(), ENTRY_DOMAIN).is_empty(),
        "{}",
        app.status
    );
}

/// **遷移の検査に落ちる`policy.json`でも一覧は出る**（`shape`は答える）。直すための画面なので、検査に落ちたら
/// 何も見えない、では直しようがない。
///
/// 取り消した後もまだ検査に落ちるなら、`save`が断って何も書かれず、理由が出る。落ちる辺を取り消せば書け、
/// 他の画面と`harness.exe`がまた読めるようになる（対の側）。
///
/// 直すときは、**別のドメインの辺の取り消しも同じ1回の保存で書く**（`plan_removals`が1つの`PolicyFile`に当てる）。
/// 遷移元ごとに保存すると、先に保存する`who`の取り消しの時点では`workspace-shell`の落ちる辺が残っているので、
/// `save`が断る——この試験はその形を赤にする。
#[test]
fn a_policy_that_fails_the_check_is_still_listed() {
    let ws = workspace();
    // 葉の名前だけの exe（検査に落ちる）と、正しい辺。
    write_unchecked(
        ws.path(),
        vec![
            domain(
                ENTRY_DOMAIN,
                vec![edge("calc.exe", "calc"), edge(WHOAMI, "who")],
                &[],
            ),
            domain("calc", vec![], &[]),
            domain("who", vec![edge(HOSTNAME, "host")], &[]),
            domain("host", vec![], &[]),
        ],
    );
    policy_file::load(ws.path()).expect_err("前提: この policy.json は検査に落ちる");
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    assert_eq!(
        domain_names(&app),
        vec!["calc", "host", "who", ENTRY_DOMAIN]
    );
    let notes = app.declared_transitions.notes.join(
        "
",
    );
    assert!(
        notes.contains("この policy.json は遷移の検査に落ちます"),
        "{notes}"
    );
    assert!(notes.contains("is not a full path"), "{notes}");

    // 正しい辺だけ取り消しても、まだ落ちる——書かずに理由を言う。
    move_to_edge(&mut app, ENTRY_DOMAIN, &literal(WHOAMI));
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Char('a'));
    assert_eq!(
        app.modal.as_ref().map(|m| m.confirm),
        Some(Confirm::DeclaredTransitions)
    );
    key(&mut app, KeyCode::Char('y'));
    assert_eq!(
        policy_bytes(ws.path()),
        before,
        "検査に落ちる policy.json を書いた"
    );
    assert!(
        app.status.contains("policy.json を書いていません"),
        "{}",
        app.status
    );

    // 落ちる辺と、別のドメイン（who）の辺に付け替えて、1回で取り消すと書ける。
    key(&mut app, KeyCode::Char(' '));
    move_to_edge(&mut app, ENTRY_DOMAIN, &literal("calc.exe"));
    key(&mut app, KeyCode::Char(' '));
    move_to_edge(&mut app, "who", &literal(HOSTNAME));
    key(&mut app, KeyCode::Char(' '));
    key(&mut app, KeyCode::Char('a'));
    key(&mut app, KeyCode::Char('y'));
    assert_eq!(
        edges_of(ws.path(), ENTRY_DOMAIN),
        vec![edge(WHOAMI, "who")],
        "{}",
        app.status
    );
    assert!(edges_of(ws.path(), "who").is_empty(), "{}", app.status);
    assert!(
        app.declared_transitions.notes.is_empty(),
        "{:?}",
        app.declared_transitions.notes
    );
}

/// **ファイル・通信のタブのキー（`A`・`y`・`c`・`R`）は、遷移のタブでは何もせず理由を言う**
/// （決定62: 同じ画面のタブで同じキーに別の意味を持たせない。`B-32`: 何も起きないなら理由を言う）。
#[test]
fn keys_of_the_files_tab_say_why_they_do_nothing_here() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![], &[]),
        ],
    );
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    move_to_edge(&mut app, ENTRY_DOMAIN, &literal(PWSH));
    for letter in ['A', 'y', 'c', 'R'] {
        app.status.clear();
        key(&mut app, KeyCode::Char(letter));
        assert!(
            app.declared_transitions.remove.is_empty(),
            "{letter} が予約を変えた"
        );
        assert!(app.modal.is_none(), "{letter} でダイアログが出た");
        assert!(
            app.status.contains("ファイル・通信のタブ"),
            "{letter} が理由を言っていない: {}",
            app.status
        );
    }
    assert_eq!(policy_bytes(ws.path()), before);
}

/// **全部収まる幅では、遷移のタブのキー案内がこの順で出る**（`Space`と`a`を先頭に置く——幅が足りないと
/// 末尾から落ちるので、予約を変えるキーと書くキーを残す。承認待ちの遷移タブと同じ並べ方）。
/// ファイル・通信のタブにしか効かないキー（`A`・`y`・`c`・`R`）は出さない（`B-32`）。
#[test]
fn the_transition_tab_hints_are_shown_in_order_when_wide_enough() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![], &[]),
        ],
    );
    let mut app = transition_tab(ws.path());
    let labels =
        |app: &App| -> Vec<String> { screen_keys(app).into_iter().map(|h| h.label).collect() };
    assert_eq!(
        labels(&app),
        vec![
            "Space 取り消しを予約",
            "a 確定",
            "s Strict の付け外し",
            "↑↓ 選択",
            "r 読み直し",
            "F3 タブ切替",
            "Esc 記録画面へ"
        ]
    );
    let expected: Vec<String> = labels(&app)
        .into_iter()
        .chain(common_keys(false).into_iter().map(|h| h.label))
        .collect();
    let rows = screen_rows(&mut app, 400, 30);
    assert_eq!(rows[29], squash(&expected.join(KEY_SEPARATOR)));

    move_to_edge(&mut app, ENTRY_DOMAIN, &literal(PWSH));
    key(&mut app, KeyCode::Char(' '));
    assert_eq!(labels(&app)[1], "a 確定（1本を取り消し）");

    // [P5.5] 入る辺（固定していない）を取り消す予約があれば、その上で Strict を付けられる——印の検査は予約した
    // 取り消しを当てた宣言で行う。`a`の案内に印の件数も出る。
    move_to_domain(&mut app, "pwsh");
    key(&mut app, KeyCode::Char('s'));
    assert_eq!(labels(&app)[1], "a 確定（1本を取り消し・Strict 1件）", "{}", app.status);
}

// ---------------------------------------------------------------------------
// [P5.5] Strict の印（決定66の追記）——ドメインの見出しの`s`で付け外しを予約し、`a`で書く
// ---------------------------------------------------------------------------

fn move_to_domain(app: &mut App, name: &str) {
    let state = &app.declared_transitions;
    let target = state
        .rows()
        .iter()
        .position(|row| matches!(row, ListedRow::Domain(d) if state.domains[*d].name == name))
        .unwrap_or_else(|| panic!("{name} の見出しが無い"));
    app.declared_transitions.row = target;
}

/// 入力を固定した辺（引数はリテラル・作業ディレクトリを宣言。手で書いたもの——このエディタは書かない）。
fn fixed_edge(exe: &str, to: &str, cwd: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv: ArgvMatcher::Literal(format!("\"{exe}\" --report")),
        cwd: Some(cwd.to_string()),
        to: to.to_string(),
        env: None,
        output: ChildOutput::Return,
    }
}

fn strict_of(ws: &Path, name: &str) -> bool {
    policy_file::load(ws)
        .expect("policy.json が読める")
        .domain(name)
        .map(|d| d.strict)
        .expect("そのドメインがある")
}

/// **許可側**: 入る辺が入力を固定している（または入る辺が無い）ドメインの見出しで`s`を押すと Strict の印を付ける予約に
/// なり、見出しに予約が出る。`a`の確認に「Strict を付ける」と**スキーマ版が3へ上がる**ことが出て、`y`で書く。
/// 予約しただけ・`a`を押しただけでは1バイトも書かない。
#[test]
fn s_on_a_domain_header_reserves_the_strict_mark_and_a_then_y_writes_it() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![fixed_edge(CALC, "logs", "C:/work")], &[]),
            domain("logs", vec![], &["C:/logs/**"]),
        ],
    );
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    move_to_domain(&mut app, "logs");
    key(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("Strict を付けます"), "{}", app.status);
    assert_eq!(
        app.declared_transitions.strict.get("logs"),
        Some(&true),
        "予約されていない"
    );
    let rows = screen_rows(&mut app, 200, 30);
    assert!(row_with(&rows, "[logs]").contains(&squash("← Strict を付けます")));
    assert_eq!(policy_bytes(ws.path()), before, "予約しただけで書いた");

    key(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert_eq!(modal.confirm, Confirm::DeclaredTransitions);
    let text = modal.lines.join("\n");
    assert!(text.contains("Strict を付ける") && text.contains("logs"), "{text}");
    assert!(text.contains("スキーマ版") && text.contains("2→3"), "{text}");
    assert_eq!(policy_bytes(ws.path()), before, "ダイアログを出しただけで書いた");

    key(&mut app, KeyCode::Char('y'));
    assert!(strict_of(ws.path(), "logs"), "{}", app.status);
    assert!(!strict_of(ws.path(), ENTRY_DOMAIN));
    assert!(app.declared_transitions.strict.is_empty(), "書いた予約が残っている");
    let rows = screen_rows(&mut app, 200, 30);
    assert!(row_with(&rows, "[logs]").contains("Strict"), "{rows:?}");
}

/// **禁止側**: 入る辺が入力を固定していない（このエディタが書いた形）ドメインには Strict を付けられず、理由を言う
/// ——付けると、その辺が編集時検査（Strict のドメインへ入る辺は固定が要る）に落ちて`policy.json`を誰も読めなくなる
/// （BUG-188 と同じ「宣言の変更で既存の辺が検査に落ちるなら書かない」）。予約しないので`a`でも書かない。
#[test]
fn s_is_refused_with_the_reason_when_an_edge_into_the_domain_does_not_fix_its_inputs() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![], &["C:/logs/**"]),
        ],
    );
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    move_to_domain(&mut app, "pwsh");
    key(&mut app, KeyCode::Char('s'));
    assert!(app.declared_transitions.strict.is_empty(), "断るべき予約が立った");
    assert!(
        app.status.contains("Strict を付けられません") && app.status.contains("is strict"),
        "理由を言っていない: {}",
        app.status
    );
    key(&mut app, KeyCode::Char('a'));
    assert!(app.modal.is_none(), "予約が無いのにダイアログが出た");
    assert_eq!(policy_bytes(ws.path()), before);
}

/// **Strict を外すと、入る辺が呼び出し元へ渡す権限が増える**——確認に「Strict を外す」と、広がる遷移とその権限が出る
/// （外すと閉包がその辺を辿るようになる。決定66の追記）。`y`で印が消える。
#[test]
fn removing_the_strict_mark_shows_what_the_entering_edge_starts_to_hand_over() {
    let ws = workspace();
    let mut logs = domain("logs", vec![], &["C:/logs/**"]);
    logs.strict = true;
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![fixed_edge(CALC, "logs", "C:/work")], &[]),
            logs,
        ],
    );
    let mut app = transition_tab(ws.path());
    let rows = screen_rows(&mut app, 200, 30);
    assert!(row_with(&rows, "[logs]").contains("Strict"), "{rows:?}");
    move_to_domain(&mut app, "logs");
    key(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("Strict を外します"), "{}", app.status);

    key(&mut app, KeyCode::Char('a'));
    let text = app.modal.as_ref().expect("確認ダイアログ").lines.join("\n");
    assert!(text.contains("Strict を外す") && text.contains("logs"), "{text}");
    assert!(text.contains("広がる遷移") && text.contains("C:/logs/**"), "{text}");
    assert!(!text.contains("スキーマ版"), "版は下がるだけ: {text}");
    key(&mut app, KeyCode::Char('y'));
    assert!(!strict_of(ws.path(), "logs"), "{}", app.status);
}

/// **辺の行と入口のドメインの`s`は何もせず理由を言う**（`B-32`）。印はドメインに付けるもので、入口のドメインは
/// 遷移先にならない（`harness.exe`が用意しない）ので印が意味を持たない。
#[test]
fn s_on_an_edge_row_or_the_entry_domain_says_why_it_does_nothing() {
    let ws = workspace();
    save(
        ws.path(),
        vec![
            domain(ENTRY_DOMAIN, vec![edge(PWSH, "pwsh")], &[]),
            domain("pwsh", vec![], &[]),
        ],
    );
    let before = policy_bytes(ws.path());
    let mut app = transition_tab(ws.path());
    move_to_edge(&mut app, ENTRY_DOMAIN, &literal(PWSH));
    key(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("ドメインの見出し"), "{}", app.status);
    move_to_domain(&mut app, ENTRY_DOMAIN);
    key(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("入口のドメイン"), "{}", app.status);
    assert!(app.declared_transitions.strict.is_empty());
    assert_eq!(policy_bytes(ws.path()), before);
}

/// **ファイル・通信のタブの`s`は何もせず、遷移のタブのキーだと言う**（決定62の裏返し。`B-32`）。
#[test]
fn s_on_the_files_tab_says_it_is_a_key_of_the_transition_tab() {
    let ws = workspace();
    save(
        ws.path(),
        vec![domain(ENTRY_DOMAIN, vec![], &["C:/logs/a.txt"])],
    );
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    key(&mut app, KeyCode::F(3));
    assert_eq!(app.declared_transitions.tab, DeclaredTab::Declarations);
    key(&mut app, KeyCode::Char('s'));
    assert!(app.status.contains("遷移のタブ"), "{}", app.status);
    assert!(app.unapproved.is_empty());
}
