//! マウスのクリック（`tui::pointer`）の試験。`render_tests`の子として置き、描画の道具を共有する。
//!
//! # 押す位置は描いた画面のセルから取る
//!
//! 当たり判定と同じ計算で押す位置を作ると、ずれていても一致してしまう（BUG-194の教訓）。どの試験も、
//! 実際に描いた画面から文字を探して、その文字が描かれたセルを押す。
//!
//! # 期待する状態は、同じ画面でキーを押した状態
//!
//! クリックはキーの処理を呼ぶだけ（`tui::pointer`のモジュールdoc）なので、**同じ作り方の画面を2つ作り、
//! 片方はクリック、もう片方は対応するキーを押して、状態が一致する**ことを見る。押す側のイベントは
//! イベントループと同じ製品の入口（`handle_event`）から、押下（`Down`）と離す（`Up`）の両方を入れる。
//!
//! 許可側（`B-35`）として、押せない場所（枠線・説明欄・区切り・知らせの行）を押しても、重ねた枠が
//! 開いている間に後ろを押しても、状態が1つも変わらないことを見る。

use crossterm::event::{MouseButton, MouseEventKind};
use ratatui::layout::Rect;

use super::*;

/// 試験の端末の大きさ（キー案内が全部入る幅）。
const SIZE: (u16, u16) = (300, 40);

/// 比べるための状態の写し。作業ディレクトリの綴りは`<ws>`に置き換える（2つの画面は別の作業ディレクトリに作る）。
///
/// 描画が書き戻す値（一覧の表示開始位置・送りの上限・押せる場所）は入れない——クリックの側だけ余分に
/// 描くことはしていないが、比べたいのは入力が変えた状態である。
fn snapshot(app: &App) -> String {
    let sorted = |set: &std::collections::HashSet<String>| {
        let mut items: Vec<&String> = set.iter().collect();
        items.sort();
        format!("{items:?}")
    };
    let text = format!(
        "screen={:?} tab={:?} help={} status={}\n\
         modal={:?}\n\
         record: focus={:?} pass={:?} net={:?} command={} cwd={} domain={} running={}\n\
         edit: focus={:?} session={} row={} accepted={:?} expanded={} recursive={} hand={:?} \
         filter={:?} tree={} domain={} unapproved={:?}\n\
         pending: observed={} denied={} approve={:?} narrow={:?} remove={:?} dismiss={:?} \
         undismiss={:?} filter={:?} dest_focused={} dest={}\n\
         declared: row={} expanded={} approve={:?} reassign={:?}",
        app.screen,
        app.pending.tab.0,
        app.help,
        app.status,
        app.modal.as_ref().map(|m| (&m.title, m.confirm, &m.lines)),
        app.record_focus,
        app.pass,
        app.net_mode,
        app.command.text(),
        app.cwd.text(),
        app.run_domain.text(),
        app.run.is_some(),
        app.edit_focus,
        app.selected_session,
        app.selected_row,
        app.accepted,
        sorted(&app.expanded),
        sorted(&app.recursive),
        app.hand_changed,
        app.filter,
        app.show_tree,
        app.domain.text(),
        app.unapproved,
        app.pending.observed_row,
        app.pending.denied_row,
        app.pending.approve,
        app.pending.narrow,
        app.pending.remove,
        app.pending.dismiss,
        app.pending.undismiss,
        app.pending.filter,
        app.pending.destination.focused,
        app.pending.destination.input.text(),
        app.declared_row,
        sorted(&app.declared_expanded),
        app.declared_approval.reserved,
        app.declared_reassign.reserved,
    );
    // `{:?}`で書いた部分は`\`が`\\`になっているので、その綴りも置き換える。
    let ws = app.workspace_root.display().to_string();
    text.replace(&ws.replace('\\', "\\\\"), "<ws>")
        .replace(&ws, "<ws>")
        .replace(&ws.replace('\\', "/"), "<ws>")
}

/// 操作の種類（`Action`は比べられないので、種類だけを取り出す）。
fn action_kind(action: &Option<Action>) -> &'static str {
    match action {
        None => "なし",
        Some(Action::Quit) => "終了",
        Some(Action::StartPass1(_)) => "パス1を開始",
        Some(Action::StartPass2(_)) => "パス2を開始",
    }
}

/// 左クリック（押して離す）を製品の入口から入れ、押下の戻り値を返す。**離したときは何も起きない**
/// （同じ場所が2回押されたことにならない）ことも見る。
fn click(app: &mut App, at: (u16, u16)) -> Option<Action> {
    let action = mouse(app, MouseEventKind::Down(MouseButton::Left), at.0, at.1);
    let pressed = snapshot(app);
    assert!(
        mouse(app, MouseEventKind::Up(MouseButton::Left), at.0, at.1).is_none(),
        "離したときに操作が返った"
    );
    assert_eq!(snapshot(app), pressed, "離したときに状態が変わった");
    action
}

/// 画面の中で`needle`（空白を落とした綴り）が始まるセル。`area`の中だけ、`row_has`（空白を落とした綴り）を
/// 含む行だけを探す。見つからなければ画面ごと出して落ちる。
fn cell_of(
    grid: &[Vec<String>],
    area: Option<Rect>,
    needle: &str,
    row_has: Option<&str>,
) -> (u16, u16) {
    let area = area.unwrap_or(Rect::new(0, 0, SIZE.0, SIZE.1));
    let needle: Vec<char> = squash(needle).chars().collect();
    for y in area.top()..area.bottom() {
        let cells: Vec<(char, u16)> = (area.left()..area.right())
            .flat_map(|x| {
                grid[usize::from(y)][usize::from(x)]
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .map(move |c| (c, x))
            })
            .collect();
        let line: String = cells.iter().map(|(c, _)| *c).collect();
        if row_has.is_some_and(|has| !line.contains(&squash(has))) {
            continue;
        }
        if let Some(start) = (0..cells.len()).find(|&i| {
            cells[i..]
                .iter()
                .map(|(c, _)| *c)
                .take(needle.len())
                .eq(needle.iter().copied())
        }) {
            return (cells[start].1, y);
        }
    }
    let screen: Vec<String> = grid.iter().map(|row| row.concat()).collect();
    panic!(
        "「{}」が描かれていない（行の条件: {row_has:?}）:\n{}",
        needle.iter().collect::<String>(),
        screen.join("\n")
    );
}

/// 描いた画面（とその画面の状態）から、押す位置を探す手順。
type FindCell<'a> = dyn Fn(&[Vec<String>], &App) -> (u16, u16) + 'a;

/// 同じ作り方の画面を2つ作り、片方は描いて`find`が返す位置をクリックし、もう片方は描いて`keys`を押す。
/// **状態と、返った操作の種類が一致する**ことを見る。`find`は描いた画面と、その画面の状態を受ける。
fn assert_click_is_keys(
    case: &str,
    make: &dyn Fn(&std::path::Path) -> App,
    find: &FindCell<'_>,
    keys: &[KeyEvent],
) {
    let (ws_click, ws_keys) = (workspace(), workspace());
    let mut clicked = make(ws_click.path());
    let mut keyed = make(ws_keys.path());
    let grid = frame(&mut clicked, SIZE.0, SIZE.1);
    frame(&mut keyed, SIZE.0, SIZE.1);
    let before = snapshot(&clicked);
    let at = find(&grid, &clicked);
    let by_click = click(&mut clicked, at);
    let mut by_keys = None;
    for key in keys {
        by_keys = keyed.on_key(*key);
        if by_keys.is_some() {
            break;
        }
    }
    assert_eq!(
        action_kind(&by_click),
        action_kind(&by_keys),
        "{case}: クリックとキーで返った操作が違う"
    );
    assert_eq!(
        snapshot(&clicked),
        snapshot(&keyed),
        "{case}: {at:?}をクリックした状態が、キー{keys:?}を押した状態と違う"
    );
    if !keys.is_empty() {
        assert!(
            snapshot(&clicked) != before || by_click.is_some(),
            "{case}: 押しても何も変わっていない（試験の前提が崩れた）"
        );
    }
}

/// 描いた画面の、見出しに`title`を含む枠。
fn boxed(grid: &[Vec<String>], title: &str) -> Rect {
    drawn_box(grid, title).unwrap_or_else(|| panic!("見出しが「{title}」の枠が描かれていない"))
}

/// 一番下の行（キー案内）。
fn key_row(grid: &[Vec<String>]) -> Rect {
    Rect::new(0, u16::try_from(grid.len() - 1).expect("行数"), SIZE.0, 1)
}

/// 一番上の行（画面のタブ）。
fn top_row() -> Rect {
    Rect::new(0, 0, SIZE.0, 1)
}

/// キー1つ（修飾なし）。
fn k(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// `n`回同じキー。
fn ks(code: KeyCode, n: usize) -> Vec<KeyEvent> {
    vec![k(code); n]
}

// ---------------------------------------------------------------------------
// 画面の作り方
// ---------------------------------------------------------------------------

/// 記録セッションを1つ作る。`paths`をFSの観測として書く。
fn session(ws: &std::path::Path, id: &str, command: &str, started: u64, paths: &[&str]) {
    let dir = RecordSessionDir::create(ws, id).expect("session dir");
    let mut manifest = RecordManifest::new(id, command, ws, ws, started);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    let lines: Vec<String> = paths
        .iter()
        .enumerate()
        .map(|(i, path)| {
            harness_policy::FsAuditEvent::observed(
                harness_policy::FsAuditKind::Etw,
                *path,
                harness_config::FsAccess::Read,
                true,
                "record_all",
                i as u64 + 1,
            )
            .to_jsonl_line()
            .expect("jsonl")
        })
        .collect();
    std::fs::write(dir.audit_log_path(), format!("{}\n", lines.join("\n"))).expect("audit log");
}

/// 承認待ち（FS/ネット）。新しい記録（候補が木になる）と古い記録の2つがあり、新しい方を開いている。
fn edit_screen_with_a_tree(ws: &std::path::Path) -> App {
    session(
        ws,
        "s-new",
        "cargo build",
        2,
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
            r"C:\Users\me\.cargo\bin\cargo.exe",
            r"C:\tools\x\y.exe",
        ],
    );
    session(ws, "s-old", "cargo test", 1, &[r"C:\tools\only.exe"]);
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.screen, Screen::Edit);
    assert_eq!(app.edit_focus, state::EditField::Proposals);
    // 全部開いておく（どの行も画面に出ている）。
    let all = app.tree.paths_at_depth(16);
    app.expanded.extend(all);
    app
}

/// 木のラベルが`label`の行か（1本道を畳んだラベルは`…/label`になる）。
fn is_label(label: &str, wanted: &str) -> bool {
    let label = label.trim();
    label == wanted || label.ends_with(&format!("/{wanted}"))
}

/// 候補の木で、ラベルが`label`の行の位置（キーで何行下へ動かせばよいか）。
fn tree_row(app: &App, label: &str) -> usize {
    app.tree
        .rows(&app.expanded)
        .iter()
        .position(|row| is_label(&app.tree.node(row.node).label, label))
        .unwrap_or_else(|| panic!("候補の木に「{label}」の行が無い"))
}

/// 遷移タブ（観測から）に候補が3つある状態（同じ名前の`git.exe`が2つと`findstr.exe`）。
fn transition_tab_with_three_candidates(ws: &std::path::Path) -> App {
    use harness_sandbox::tier2a::policy_learnd::observed::{observed_path, ObservedRecord, Spawn};

    let path = observed_path(ws);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("transitions dir");
    let text: String = [
        "C:/Program Files/Git/cmd/git.exe",
        "C:/Program Files/Git/mingw64/bin/git.exe",
        "C:/Windows/System32/findstr.exe",
    ]
    .iter()
    .map(|exe| {
        let record = ObservedRecord::ObservedSpawn(Spawn {
            parent_exe: Some("C:/pwsh.exe".to_string()),
            exe: exe.to_string(),
            argv: "x --y".to_string(),
            count: 1,
            first_ts: 1,
            last_ts: 1,
            argv_truncation: false,
        });
        format!("{}\n", serde_json::to_string(&record).expect("jsonl"))
    })
    .collect();
    std::fs::write(&path, text).expect("observed.jsonl");
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::F(2));
    assert_eq!(
        app.pending.tab.0,
        transition::PendingTab::TransitionsObserved
    );
    assert_eq!(app.pending.visible().len(), 3, "候補が読めていない");
    app
}

/// 遷移タブの一覧で、実行ファイルの名前が`file`の行の位置。
fn transition_row(app: &App, file: &str) -> usize {
    app.pending
        .visible()
        .iter()
        .position(|c| c.exe.ends_with(file))
        .unwrap_or_else(|| panic!("遷移の一覧に「{file}」が無い"))
}

/// 宣言画面。1つのドメインに、共通の親を持つ2件と、別の場所の1件を宣言してある。
fn declared_screen_with_a_tree(ws: &std::path::Path) -> App {
    let mut domain = crate::policy_file::PolicyDomain::new("click-check");
    for value in [
        "C:/harness-e2e/click-check/data",
        "C:/harness-e2e/click-check/tools",
        "C:/elsewhere/file.txt",
    ] {
        domain.fs.read.push(value.to_string());
    }
    let mut app = declared_screen_with(ws, domain);
    let all = app.declared_tree.paths_at_depth(16);
    app.declared_expanded.extend(all);
    app
}

/// 宣言の木で、ラベルが`label`の行の位置。
fn declared_row(app: &App, label: &str) -> usize {
    app.declared_tree
        .rows(&app.declared_expanded)
        .iter()
        .position(|row| is_label(&app.declared_tree.node(row.node).label, label))
        .unwrap_or_else(|| panic!("宣言の木に「{label}」の行が無い"))
}

/// 記録画面（何も始めていない）。`policy.json`と記録が1つずつあり、どの画面へ移っても中身がある。
fn record_screen_with_content(ws: &std::path::Path) -> App {
    session(ws, "s1", "cargo build", 1, &[r"C:\tools\only.exe"]);
    let mut domain = crate::policy_file::PolicyDomain::new("click-check");
    domain.fs.read.push("C:/elsewhere/file.txt".to_string());
    crate::policy_file::save(
        ws,
        &crate::policy_file::PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![domain],
        },
    )
    .expect("policy.json");
    App::new(ws.to_path_buf(), harness_core::RequireSandbox::None)
}

// ---------------------------------------------------------------------------
// 1. タブ
// ---------------------------------------------------------------------------

/// **一番上のタブを押すと、その画面の`F`キーを押したのと同じになる。** いまの画面のタブは押しても何も変わらない
/// （`F2`をもう一度押すと承認待ちのタブが回るが、タブの見出しを押してそれが起きると驚くので）。
#[test]
fn a_screen_tab_does_what_its_function_key_does() {
    type Make = fn(&std::path::Path) -> App;
    let on_declared: Make = |ws| {
        let mut app = record_screen_with_content(ws);
        press(&mut app, KeyCode::F(3));
        app
    };
    let cases: [(&str, Make, &str, Vec<KeyEvent>); 6] = [
        (
            "記録→承認待ち",
            record_screen_with_content,
            " F2 承認待ち ",
            vec![k(KeyCode::F(2))],
        ),
        (
            "記録→宣言",
            record_screen_with_content,
            " F3 宣言 ",
            vec![k(KeyCode::F(3))],
        ),
        (
            "宣言→記録",
            on_declared,
            " F1 記録 ",
            vec![k(KeyCode::F(1))],
        ),
        (
            "宣言→承認待ち",
            on_declared,
            " F2 承認待ち ",
            vec![k(KeyCode::F(2))],
        ),
        (
            "記録で記録のタブ",
            record_screen_with_content,
            " F1 記録 ",
            vec![],
        ),
        // `F2`なら承認待ちのタブが回るところ。見出しを押しても回らない。
        (
            "承認待ちで承認待ちのタブ",
            edit_screen_with_a_tree,
            " F2 承認待ち ",
            vec![],
        ),
    ];
    for (case, make, tab, keys) in cases {
        assert_click_is_keys(
            case,
            &make,
            &|grid, _| cell_of(grid, Some(top_row()), tab, None),
            &keys,
        );
    }
}

/// **承認待ちのタブの行が描かれ、押すとそのタブへ移る**（`F2`で巡回して着くのと同じ）。いまのタブは何もしない。
#[test]
fn a_pending_tab_switches_to_that_tab() {
    type Make = fn(&std::path::Path) -> App;
    let on_observed: Make = |ws| {
        let mut app = edit_screen_with_a_tree(ws);
        press(&mut app, KeyCode::F(2));
        app
    };
    let cases: [(&str, Make, &str, Vec<KeyEvent>); 4] = [
        (
            "FS/ネット→拒否から",
            edit_screen_with_a_tree,
            "遷移・拒否から",
            ks(KeyCode::F(2), 2),
        ),
        (
            "FS/ネット→観測から",
            edit_screen_with_a_tree,
            "遷移・観測から",
            ks(KeyCode::F(2), 1),
        ),
        (
            "観測から→FS/ネット",
            on_observed,
            "FS/ネット",
            ks(KeyCode::F(2), 2),
        ),
        (
            "FS/ネットでFS/ネット",
            edit_screen_with_a_tree,
            "FS/ネット",
            vec![],
        ),
    ];
    for (case, make, tab, keys) in cases {
        assert_click_is_keys(
            case,
            &make,
            // タブの行は承認待ちの本体の一番上（タブの行の1つ下）。
            &|grid, _| cell_of(grid, Some(Rect::new(0, 1, SIZE.0, 1)), tab, None),
            &keys,
        );
    }
}

/// 製品と同じ形で1フレーム描き（描いて分かったことを状態へ書き戻す）、`rows`の各行を「見た目が同じセルの連なり」ごとに
/// `«文字色/背景/修飾»文字`と書き並べたものと、その行で押すと何が起きるか（押せる桁の連なりごとに`桁..桁=動き`）を返す。
/// 作業ディレクトリの綴りは`<ws>`に置き換え、行末の空白は落とす。
fn tab_rows(app: &mut App, width: u16, rows: &[u16]) -> Vec<(String, String)> {
    let mut terminal = Terminal::new(TestBackend::new(width, SIZE.1)).expect("test terminal");
    let mut feedback = DrawFeedback::default();
    terminal
        .draw(|f| feedback = draw(f, app))
        .expect("描画は落ちてはいけない");
    app.apply_draw_feedback(feedback);
    let buffer = terminal.backend().buffer();
    let ws = app.workspace_root.display().to_string();
    let name =
        |color: Option<ratatui::style::Color>| color.map_or("-".to_string(), |c| format!("{c:?}"));
    rows.iter()
        .map(|&y| {
            let mut looks = String::new();
            let mut current = None;
            let mut second_half = false;
            for x in 0..width {
                let cell = &buffer[(x, y)];
                // 全角文字の後ろのセル（2桁目）は読まない（ratatuiはそこを既定の見た目の空白にし、端末は前の文字で覆う）。
                if std::mem::take(&mut second_half) {
                    continue;
                }
                second_half = unicode_width::UnicodeWidthStr::width(cell.symbol()) == 2;
                let style = cell.style();
                if current != Some(style) {
                    looks.push_str(&format!(
                        "«{}/{}/{:?}»",
                        name(style.fg),
                        name(style.bg),
                        style.add_modifier
                    ));
                    current = Some(style);
                }
                looks.push_str(cell.symbol());
            }
            let mut clicks = Vec::new();
            let mut run: Option<(u16, Click)> = None;
            for x in 0..=width {
                let hit = (x < width).then(|| app.pointer.clicked(x, y)).flatten();
                if run.as_ref().map(|(_, click)| Some(click)) != Some(hit.as_ref()) {
                    if let Some((start, click)) = run.take() {
                        clicks.push(format!("{start}..{x}={click:?}"));
                    }
                    run = hit.map(|click| (x, click));
                }
            }
            (
                looks.replace(&ws, "<ws>").trim_end().to_string(),
                clicks.join(" "),
            )
        })
        .collect()
}

/// **一番上の画面のタブと承認待ちのタブの行は、描いた見た目（文字・色・太字）と押せる桁がこのとおり。**
/// タブを`harness_term`の部品へ切り出したとき（2026-10-03）に、切り出す前の画面を1セルも変えていないことを固定するため、
/// 切り出す**前**に描いた結果をそのまま期待値にした（`docs/CODE-STRUCTURE-RULES.md`§6の characterization test）。
/// 選ばれているタブ（シアンの背景に黒の太字）は画面とタブごとに動き、狭い端末では右端で切れる（切れたタブも描かれた
/// 桁だけ押せる）。
#[test]
fn the_tab_rows_look_and_press_exactly_as_before() {
    let ws = workspace();
    let mut app = record_screen_with_content(ws.path());
    let mut seen = Vec::new();
    seen.push(("記録", tab_rows(&mut app, SIZE.0, &[0])));
    press(&mut app, KeyCode::F(2));
    seen.push(("承認待ち・FS/ネット", tab_rows(&mut app, SIZE.0, &[0, 1])));
    press(&mut app, KeyCode::F(2));
    seen.push(("承認待ち・観測から", tab_rows(&mut app, SIZE.0, &[1])));
    press(&mut app, KeyCode::F(2));
    seen.push(("承認待ち・拒否から", tab_rows(&mut app, SIZE.0, &[1])));
    seen.push(("承認待ち・40桁", tab_rows(&mut app, 40, &[0, 1])));
    seen.push(("承認待ち・20桁", tab_rows(&mut app, 20, &[0, 1])));
    press(&mut app, KeyCode::F(3));
    seen.push(("宣言", tab_rows(&mut app, SIZE.0, &[0])));
    let shown: Vec<String> = seen
        .iter()
        .flat_map(|(case, rows)| {
            rows.iter()
                .map(move |(looks, clicks)| format!("{case}\n{looks}\n{clicks}"))
        })
        .collect();
    let want = [
        concat!(
            "記録\n",
            "«Black/Cyan/BOLD» F1 記録 «Reset/Reset/NONE» «Gray/Reset/NONE» F2 承認待ち «Reset/Reset/NONE» «Gray/Reset/NONE» F3 宣言 «DarkGray/Reset/NONE»  Ctrl+N で切替«Reset/Reset/NONE»   «DarkGray/Reset/NONE»workspace: <ws>«Reset/Reset/NONE»\n",
            "0..9=Screen(Record) 10..23=Screen(Edit) 24..33=Screen(Declared)",
        ),
        concat!(
            "承認待ち・FS/ネット\n",
            "«Gray/Reset/NONE» F1 記録 «Reset/Reset/NONE» «Black/Cyan/BOLD» F2 承認待ち «Reset/Reset/NONE» «Gray/Reset/NONE» F3 宣言 «DarkGray/Reset/NONE»  Ctrl+N で切替«Reset/Reset/NONE»   «DarkGray/Reset/NONE»workspace: <ws>«Reset/Reset/NONE»\n",
            "0..9=Screen(Record) 10..23=Screen(Edit) 24..33=Screen(Declared)",
        ),
        concat!(
            "承認待ち・FS/ネット\n",
            "«Black/Cyan/BOLD» FS/ネット «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・観測から «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・拒否から «DarkGray/Reset/NONE»  F2 で切替«Reset/Reset/NONE»\n",
            "0..11=PendingTab(FsNet) 12..28=PendingTab(TransitionsObserved) 29..45=PendingTab(TransitionsDenied)",
        ),
        concat!(
            "承認待ち・観測から\n",
            "«Gray/Reset/NONE» FS/ネット «Reset/Reset/NONE» «Black/Cyan/BOLD» 遷移・観測から «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・拒否から «DarkGray/Reset/NONE»  F2 で切替«Reset/Reset/NONE»\n",
            "0..11=PendingTab(FsNet) 12..28=PendingTab(TransitionsObserved) 29..45=PendingTab(TransitionsDenied)",
        ),
        concat!(
            "承認待ち・拒否から\n",
            "«Gray/Reset/NONE» FS/ネット «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・観測から «Reset/Reset/NONE» «Black/Cyan/BOLD» 遷移・拒否から «DarkGray/Reset/NONE»  F2 で切替«Reset/Reset/NONE»\n",
            "0..11=PendingTab(FsNet) 12..28=PendingTab(TransitionsObserved) 29..45=PendingTab(TransitionsDenied)",
        ),
        concat!(
            "承認待ち・40桁\n",
            "«Gray/Reset/NONE» F1 記録 «Reset/Reset/NONE» «Black/Cyan/BOLD» F2 承認待ち «Reset/Reset/NONE» «Gray/Reset/NONE» F3 宣言 «DarkGray/Reset/NONE»  Ctrl+\n",
            "0..9=Screen(Record) 10..23=Screen(Edit) 24..33=Screen(Declared)",
        ),
        concat!(
            "承認待ち・40桁\n",
            "«Gray/Reset/NONE» FS/ネット «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・観測から «Reset/Reset/NONE» «Black/Cyan/BOLD» 遷移・拒否\n",
            "0..11=PendingTab(FsNet) 12..28=PendingTab(TransitionsObserved) 29..40=PendingTab(TransitionsDenied)",
        ),
        concat!(
            "承認待ち・20桁\n",
            "«Gray/Reset/NONE» F1 記録 «Reset/Reset/NONE» «Black/Cyan/BOLD» F2 承認待\n",
            "0..9=Screen(Record) 10..20=Screen(Edit)",
        ),
        concat!(
            "承認待ち・20桁\n",
            "«Gray/Reset/NONE» FS/ネット «Reset/Reset/NONE» «Gray/Reset/NONE» 遷移・«Reset/Reset/NONE»\n",
            "0..11=PendingTab(FsNet) 12..19=PendingTab(TransitionsObserved)",
        ),
        concat!(
            "宣言\n",
            "«Gray/Reset/NONE» F1 記録 «Reset/Reset/NONE» «Gray/Reset/NONE» F2 承認待ち «Reset/Reset/NONE» «Black/Cyan/BOLD» F3 宣言 «DarkGray/Reset/NONE»  Ctrl+N で切替«Reset/Reset/NONE»   «DarkGray/Reset/NONE»workspace: <ws>«Reset/Reset/NONE»\n",
            "0..9=Screen(Record) 10..23=Screen(Edit) 24..33=Screen(Declared)",
        ),
    ];
    assert_eq!(shown, want, "\n{}", shown.join("\n\n"));
}

// ---------------------------------------------------------------------------
// 2. 一覧（行・[x]・▾/▸）
// ---------------------------------------------------------------------------

/// **承認待ち（FS/ネット）の候補の木**: 行を押すと選ばれ、`[x]`を押すと`Space`、`▸`は`→`、`▾`は`←`と同じ。
#[test]
fn a_candidate_row_its_mark_and_its_fold_do_what_the_keys_do() {
    let make = edit_screen_with_a_tree;
    let probe = {
        let ws = workspace();
        make(ws.path())
    };
    // `registry`は子を持つ（開いているかどうかは画面から読む）。`cargo.exe`は葉。
    let registry = tree_row(&probe, "registry");
    let leaf = tree_row(&probe, "cargo.exe");
    assert!(leaf > 0, "試験の前提: 葉が先頭の行ではない");
    let candidates = |grid: &[Vec<String>]| boxed(grid, " 候補:");

    assert_click_is_keys(
        "葉の行",
        &make,
        &|grid, _| cell_of(grid, Some(candidates(grid)), "cargo.exe", None),
        &ks(KeyCode::Down, leaf),
    );
    let mut space = ks(KeyCode::Down, leaf);
    space.push(k(KeyCode::Char(' ')));
    assert_click_is_keys(
        "葉の[ ]",
        &make,
        &|grid, _| cell_of(grid, Some(candidates(grid)), "[", Some("cargo.exe")),
        &space,
    );
    let mut space = ks(KeyCode::Down, registry);
    space.push(k(KeyCode::Char(' ')));
    assert_click_is_keys(
        "ディレクトリの[ ]（配下をまとめて）",
        &make,
        &|grid, _| cell_of(grid, Some(candidates(grid)), "[", Some("registry")),
        &space,
    );
    // 開閉は、描いた記号で向きが決まる。開いていれば`←`で閉じ、閉じていれば`→`で開く。
    for opened in [true, false] {
        let make = move |ws: &std::path::Path| {
            let mut app = edit_screen_with_a_tree(ws);
            let path = app
                .tree
                .node(app.tree.rows(&app.expanded)[registry].node)
                .path
                .clone();
            if opened {
                app.expanded.insert(path);
            } else {
                app.expanded.remove(&path);
            }
            app
        };
        let (glyph, key) = if opened {
            ("▾", KeyCode::Left)
        } else {
            ("▸", KeyCode::Right)
        };
        let mut keys = ks(KeyCode::Down, registry);
        keys.push(k(key));
        assert_click_is_keys(
            &format!("{glyph}（開閉）"),
            &make,
            &|grid, _| cell_of(grid, Some(candidates(grid)), glyph, Some("registry")),
            &keys,
        );
    }
}

/// **記録セッションの一覧**: 行を押すと、その記録を選んで開く（`Shift+Tab`で一覧へ移って`↓`と同じ）。
#[test]
fn a_session_row_selects_and_opens_that_session() {
    let probe = {
        let ws = workspace();
        edit_screen_with_a_tree(ws.path())
    };
    let old = probe
        .sessions
        .iter()
        .position(|s| s.manifest.command == "cargo test")
        .expect("古い記録");
    assert_eq!(old, 1, "試験の前提: 古い記録が2行目");
    let mut keys = vec![k(KeyCode::BackTab)];
    keys.extend(ks(KeyCode::Down, old));
    assert_click_is_keys(
        "古い記録の行",
        &edit_screen_with_a_tree,
        &|grid, _| {
            cell_of(
                grid,
                Some(boxed(grid, " 記録セッション")),
                "cargo test",
                None,
            )
        },
        &keys,
    );
}

/// **遷移タブの一覧**: 行を押すと選ばれ、`[ ]`を押すと`Space`（許可の予約）と同じ。
#[test]
fn a_transition_row_and_its_mark_do_what_the_keys_do() {
    let probe = {
        let ws = workspace();
        transition_tab_with_three_candidates(ws.path())
    };
    // 一番下の行を押す（いま選ばれている先頭の行とは違う行）。同じ名前の`git.exe`は置き場で見分けて描かれる。
    let row = probe.pending.visible().len() - 1;
    let exe = probe.pending.visible()[row].exe.clone();
    let label = if exe.ends_with("findstr.exe") {
        "findstr.exe"
    } else if exe.contains("/cmd/") {
        "git.exe (cmd)"
    } else {
        "git.exe (bin)"
    };
    assert_eq!(transition_row(&probe, &exe), row);
    let list = |grid: &[Vec<String>]| boxed(grid, " 遷移・観測から:");
    assert_click_is_keys(
        "行",
        &transition_tab_with_three_candidates,
        &|grid, _| cell_of(grid, Some(list(grid)), label, None),
        &ks(KeyCode::Down, row),
    );
    let mut keys = ks(KeyCode::Down, row);
    keys.push(k(KeyCode::Char(' ')));
    assert_click_is_keys(
        "[ ]",
        &transition_tab_with_three_candidates,
        &|grid, _| cell_of(grid, Some(list(grid)), "[", Some(label)),
        &keys,
    );
}

/// **宣言画面の木**: 行を押すと選ばれ、`[x]`は`Space`（取り消しの予約）、`▾`は`←`と同じ。
#[test]
fn a_declared_row_its_mark_and_its_fold_do_what_the_keys_do() {
    let probe = {
        let ws = workspace();
        declared_screen_with_a_tree(ws.path())
    };
    let data = declared_row(&probe, "data");
    let parent = declared_row(&probe, "click-check");
    assert!(data > 0, "試験の前提: 先頭の行ではない");
    let list = |grid: &[Vec<String>]| boxed(grid, " 承認済みの宣言");
    assert_click_is_keys(
        "行",
        &declared_screen_with_a_tree,
        &|grid, _| cell_of(grid, Some(list(grid)), "data", Some("[click-check]")),
        &ks(KeyCode::Down, data),
    );
    let mut keys = ks(KeyCode::Down, data);
    keys.push(k(KeyCode::Char(' ')));
    assert_click_is_keys(
        "[x]",
        &declared_screen_with_a_tree,
        &|grid, _| cell_of(grid, Some(list(grid)), "[", Some("data")),
        &keys,
    );
    let mut keys = ks(KeyCode::Down, parent);
    keys.push(k(KeyCode::Left));
    assert_click_is_keys(
        "▾",
        &declared_screen_with_a_tree,
        &|grid, _| cell_of(grid, Some(list(grid)), "▾", Some("harness-e2e/click-check")),
        &keys,
    );
}

// ---------------------------------------------------------------------------
// 3. 入力欄
// ---------------------------------------------------------------------------

/// **入力欄を押すと`Tab`で入ったのと同じ状態になり、続けて打った文字がその欄へ入る。**
#[test]
fn a_field_click_enters_it_like_tab_and_typing_goes_there() {
    type Make = fn(&std::path::Path) -> App;
    let record: Make = |ws| App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    let cases: [(&str, Make, &str, Vec<KeyEvent>); 4] = [
        (
            "記録・作業ディレクトリ",
            record,
            "作業ディレクトリ",
            vec![k(KeyCode::Tab)],
        ),
        ("記録・パス", record, "パス", vec![k(KeyCode::BackTab)]),
        (
            "承認待ち・ドメイン欄",
            edit_screen_with_a_tree,
            "ドメイン（このコマンドに何を許すか",
            vec![k(KeyCode::Tab)],
        ),
        (
            "遷移タブ・遷移先の欄",
            transition_tab_with_three_candidates,
            "遷移先ドメイン（Tab",
            vec![k(KeyCode::Tab)],
        ),
    ];
    for (case, make, label, keys) in cases {
        assert_click_is_keys(
            case,
            &make,
            &|grid, _| cell_of(grid, None, label, None),
            &keys,
        );
    }

    // 押した後に打った文字は、押した欄へ入る（「入力を始める」）。
    let ws = workspace();
    let mut app = App::new(ws.path().to_path_buf(), harness_core::RequireSandbox::None);
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    click(&mut app, cell_of(&grid, None, "作業ディレクトリ", None));
    press(&mut app, KeyCode::Char('Z'));
    assert!(
        app.cwd.text().ends_with('Z'),
        "作業ディレクトリに入っていない"
    );
    assert!(!app.command.text().contains('Z'), "コマンドの欄に入った");

    let ws = workspace();
    let mut app = edit_screen_with_a_tree(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    click(
        &mut app,
        cell_of(&grid, None, "ドメイン（このコマンドに何を許すか", None),
    );
    press(&mut app, KeyCode::Char('Z'));
    assert!(app.domain.text().ends_with('Z'), "ドメイン欄に入っていない");
}

// ---------------------------------------------------------------------------
// 4. キー案内と確認ダイアログのボタン
// ---------------------------------------------------------------------------

/// **キー案内の項目を押すと、そのキーを押したのと同じになる**（代表: 画面ごとの項目・ヘルプ・終了）。
/// 記録の開始・停止はキー案内から「記録」の枠の右のボタンへ移した（[`the_record_buttons_do_what_their_keys_do`]）。
#[test]
fn a_key_hint_does_what_its_key_does() {
    type Make = fn(&std::path::Path) -> App;
    let reserved_transition: Make = |ws| {
        let mut app = transition_tab_with_three_candidates(ws);
        press(&mut app, KeyCode::Char(' '));
        app
    };
    let cases: [(&str, Make, &str, Vec<KeyEvent>); 8] = [
        (
            "承認待ち・t",
            edit_screen_with_a_tree,
            "t プロセスツリー",
            vec![k(KeyCode::Char('t'))],
        ),
        (
            "承認待ち・a",
            edit_screen_with_a_tree,
            "a 承認",
            vec![k(KeyCode::Char('a'))],
        ),
        (
            "遷移・a（予約あり）",
            reserved_transition,
            "a 確定（1件）",
            vec![k(KeyCode::Char('a'))],
        ),
        (
            "遷移・f",
            transition_tab_with_three_candidates,
            "f 表示:",
            vec![k(KeyCode::Char('f'))],
        ),
        (
            "宣言・Space",
            declared_screen_with_a_tree,
            "Space 取り消しを予約",
            vec![k(KeyCode::Char(' '))],
        ),
        (
            "共通・F4",
            edit_screen_with_a_tree,
            "F4 ヘルプ",
            vec![k(KeyCode::F(4))],
        ),
        (
            "共通・Esc×2",
            declared_screen_with_a_tree,
            "Esc×2 終了",
            ks(KeyCode::Esc, 2),
        ),
        (
            "共通・Ctrl+C",
            record_screen_with_content,
            "Ctrl+C 終了",
            vec![KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)],
        ),
    ];
    for (case, make, hint, keys) in cases {
        assert_click_is_keys(
            case,
            &make,
            &|grid, _| cell_of(grid, Some(key_row(grid)), hint, None),
            &keys,
        );
    }
}

/// 「記録」の枠の右側（枠と同じ行の、枠より右の全部）。
fn right_of_record_box(grid: &[Vec<String>]) -> Rect {
    let form = boxed(grid, " 記録 ");
    let width = u16::try_from(grid[0].len()).expect("端末の幅");
    Rect::new(form.right(), form.y, width - form.right(), form.height)
}

/// 「記録」の枠の右の、文言が`label`の枠付きのボタン（枠線を含む）。**4つの角を描いたセルから読む**（当たり判定と
/// 同じ計算で作らない）。角がそろっていなければ落ちる。
fn record_button(grid: &[Vec<String>], label: &str) -> Rect {
    let (x, y) = cell_of(grid, Some(right_of_record_box(grid)), label, None);
    let (x, y) = (usize::from(x), usize::from(y));
    let row = &grid[y];
    let left = (0..x).rev().find(|&c| row[c] == "│").expect("左の枠線");
    let right = (x..row.len()).find(|&c| row[c] == "│").expect("右の枠線");
    let corners = [
        grid[y - 1][left].as_str(),
        grid[y - 1][right].as_str(),
        grid[y + 1][left].as_str(),
        grid[y + 1][right].as_str(),
    ];
    assert_eq!(
        corners,
        ["┌", "┐", "└", "┘"],
        "「{label}」が枠で囲まれていない:\n{}",
        grid.iter()
            .map(|r| r.concat())
            .collect::<Vec<_>>()
            .join("\n")
    );
    let cell = |n: usize| u16::try_from(n).expect("端末の大きさはu16に収まる");
    Rect::new(cell(left), cell(y - 1), cell(right - left + 1), 3)
}

/// 枠付きのボタンの下辺の、角を除いた文字（キーを添えていれば`──Enter───`のような形）。
fn button_bottom_edge(grid: &[Vec<String>], button: Rect) -> String {
    grid[usize::from(button.bottom() - 1)]
        [usize::from(button.x) + 1..usize::from(button.right()) - 1]
        .concat()
}

/// コマンドを入れた記録画面（押せば記録が始まる）。
fn record_screen_with_command(ws: &std::path::Path) -> App {
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    app.command.set_text("cargo build");
    app
}

/// **「記録」の枠の右隣の、枠で囲んだボタンは、そのキーを押したのと同じ**（2026-10-03、会話画面の入力欄の右の
/// 「送信」「中断」と同じ形・同じ部品）。実行前は「記録を開始」（下辺に`Enter`。コマンドが空でも押せて、キーと同じく
/// 理由が出る）、記録中は「停止」（下辺に`Esc`）。どちらもキー案内の行には無い（同じ操作を2か所に並べない）。
/// ボタンは枠の右隣で、枠の下端にそろい、画面の右端で終わる。
#[test]
fn the_record_buttons_do_what_their_keys_do() {
    type Make = fn(&std::path::Path) -> App;
    let empty: Make = |ws| App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    let cases: [(&str, Make, &str, &str, KeyCode); 3] = [
        (
            "開始",
            record_screen_with_command,
            "記録を開始",
            "Enter",
            KeyCode::Enter,
        ),
        ("コマンドが空", empty, "記録を開始", "Enter", KeyCode::Enter),
        (
            "記録中の停止",
            running_record_screen,
            "停止",
            "Esc",
            KeyCode::Esc,
        ),
    ];
    for (case, make, label, key_label, key) in cases {
        assert_click_is_keys(
            case,
            &make,
            &|grid, _| cell_of(grid, Some(right_of_record_box(grid)), label, None),
            &[k(key)],
        );

        let ws = workspace();
        let mut app = make(ws.path());
        let grid = frame(&mut app, SIZE.0, SIZE.1);
        let keys = squash(&grid[usize::from(key_row(&grid).y)].concat());
        assert!(
            !keys.contains(label),
            "{case}: キー案内の行にも「{label}」がある: {keys}"
        );
        let form = boxed(&grid, " 記録 ");
        let button = record_button(&grid, label);
        assert_eq!(button.x, form.right(), "{case}: 枠の右隣に無い");
        assert_eq!(
            button.bottom(),
            form.bottom(),
            "{case}: 枠の下端にそろっていない"
        );
        assert_eq!(button.right(), SIZE.0, "{case}: 右端で終わっていない");
        assert_eq!(
            button_bottom_edge(&grid, button).trim_matches('─'),
            key_label,
            "{case}: 下辺のキー"
        );
        // 枠線の上を押しても同じ（ボタンは枠ごと押せる）。
        assert_click_is_keys(
            &format!("{case}（枠線の上）"),
            &make,
            &|grid, _| {
                let button = record_button(grid, label);
                (button.x, button.y)
            },
            &[k(key)],
        );
    }
    // 空のコマンドで押すと、キーと同じく開始できない理由が出る（無反応にしない）。
    let ws = workspace();
    let mut app = empty(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let action = click(
        &mut app,
        cell_of(&grid, Some(right_of_record_box(&grid)), "記録を開始", None),
    );
    assert_eq!(action_kind(&action), "なし");
    assert!(app.status.contains("コマンドを入力"), "{}", app.status);
    // 押せば始まる（許可側）。
    let mut app = record_screen_with_command(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let action = click(
        &mut app,
        cell_of(&grid, Some(right_of_record_box(&grid)), "記録を開始", None),
    );
    assert_eq!(action_kind(&action), "パス1を開始");
}

/// **狭い端末では、「記録」の枠に34桁（ラベル12桁・値20桁・枠線2桁）を残せる形を選ぶ**——キーを添える形 → キーを
/// 落とした短い形 → 置かない（枠が幅いっぱい）。枠とボタンは重ならず、ボタンは途中で切れない。短い形でも押せば始まる。
/// 「記録を開始」のボタンは、キーを添える形で18桁、短い形で14桁（手で数えた値）。
#[test]
fn the_record_button_shrinks_and_then_disappears_on_a_narrow_terminal() {
    for (width, form_of_button) in [
        (120u16, "キー付き"),
        (52, "キー付き"),
        (51, "短い"),
        (48, "短い"),
        (47, "無し"),
    ] {
        let ws = workspace();
        let mut app = record_screen_with_command(ws.path());
        let grid = frame(&mut app, width, SIZE.1);
        let form = boxed(&grid, " 記録 ");
        if form_of_button == "無し" {
            assert_eq!(form.right(), width, "{width}桁: 枠が幅いっぱいでない");
            let rows: String = grid[usize::from(form.y)..usize::from(form.bottom())]
                .iter()
                .map(|row| row.concat())
                .collect();
            assert!(
                !rows.contains("記録を開始"),
                "{width}桁: 入らないボタンを描いた"
            );
            continue;
        }
        let button = record_button(&grid, "記録を開始");
        assert_eq!(
            button.x,
            form.right(),
            "{width}桁: 枠とボタンが重なるか離れた"
        );
        assert_eq!(button.right(), width, "{width}桁");
        assert!(form.width >= 34, "{width}桁: 枠が{}桁しかない", form.width);
        let edge = button_bottom_edge(&grid, button);
        match form_of_button {
            "キー付き" => assert_eq!(edge.trim_matches('─'), "Enter", "{width}桁"),
            _ => {
                assert!(
                    edge.chars().all(|c| c == '─'),
                    "{width}桁: 短い形にキーが残った: {edge}"
                );
                assert_eq!(button.width, 14, "{width}桁");
            }
        }
        let action = click(
            &mut app,
            cell_of(&grid, Some(right_of_record_box(&grid)), "記録を開始", None),
        );
        assert_eq!(action_kind(&action), "パス1を開始", "{width}桁");
    }
}

/// 終了の項目は、押すと終了の操作を返す（キーと同じ。上の試験は種類が一致することしか見ないので、ここで値を見る）。
#[test]
fn the_quit_hints_actually_quit() {
    for hint in ["Esc×2 終了", "Ctrl+C 終了"] {
        let ws = workspace();
        let mut app = declared_screen_with_a_tree(ws.path());
        let grid = frame(&mut app, SIZE.0, SIZE.1);
        let action = click(&mut app, cell_of(&grid, Some(key_row(&grid)), hint, None));
        assert_eq!(action_kind(&action), "終了", "{hint}");
    }
}

/// 狭い端末で項目が落ちたときの`… 他N件`は、押すとヘルプが開く（`F4`と同じ。落とした項目はヘルプに載っている）。
#[test]
fn the_omitted_count_opens_the_help() {
    let (ws_click, ws_keys) = (workspace(), workspace());
    let mut clicked = edit_screen_with_a_tree(ws_click.path());
    let mut keyed = edit_screen_with_a_tree(ws_keys.path());
    let grid = frame(&mut clicked, 100, 30);
    let row = Rect::new(0, 29, 100, 1);
    click(&mut clicked, cell_of(&grid, Some(row), "… 他", None));
    press(&mut keyed, KeyCode::F(4));
    assert!(clicked.help, "ヘルプが開いていない");
    assert_eq!(snapshot(&clicked), snapshot(&keyed));
}

/// **入力欄に居るときに文字キーの項目を押すと、先に欄から出て（`Enter`）からそのキーを押す**——
/// 名前に文字が入らない。
#[test]
fn a_letter_hint_leaves_the_field_before_pressing_the_key() {
    type Make = fn(&std::path::Path) -> App;
    let in_domain: Make = |ws| {
        let mut app = edit_screen_with_a_tree(ws);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.edit_focus, state::EditField::Domain);
        app
    };
    let in_destination: Make = |ws| {
        let mut app = transition_tab_with_three_candidates(ws);
        press(&mut app, KeyCode::Tab);
        assert!(app.pending.destination.focused);
        app
    };
    assert_click_is_keys(
        "ドメイン欄に居て t",
        &in_domain,
        &|grid, _| cell_of(grid, Some(key_row(grid)), "t プロセスツリー", None),
        &[k(KeyCode::Enter), k(KeyCode::Char('t'))],
    );
    assert_click_is_keys(
        "遷移先の欄に居て Space",
        &in_destination,
        &|grid, _| cell_of(grid, Some(key_row(grid)), "Space 選ぶ/外す", None),
        &[k(KeyCode::Enter), k(KeyCode::Char(' '))],
    );
}

/// **確認ダイアログの下辺の`y=書く`・`n / Esc=やめる`は、`y`・`n`を押したのと同じ。**読むだけのダイアログの
/// `Enter / Esc=閉じる`は`Enter`。`y`は書く——`policy.json`の中身もキーで書いたものと一致する。
#[test]
fn the_confirmation_buttons_do_what_their_keys_do() {
    type Make = fn(&std::path::Path) -> App;
    let confirmation: Make = |ws| transition_confirmation_to(ws, "workspace-shell");
    let read_only: Make = |ws| {
        let mut app = record_screen_with_content(ws);
        app.modal = Some(state::Modal {
            title: "報告".to_string(),
            lines: vec!["読むだけ".to_string()],
            confirm: Confirm::ReadOnly,
        });
        app
    };
    let modal_bottom = |grid: &[Vec<String>], app: &App| {
        let area = modal_box(grid, app);
        Rect::new(area.x, area.bottom() - 1, area.width, 1)
    };
    let cases: [(&str, Make, &str, KeyCode); 3] = [
        ("y=書く", confirmation, "y=書く", KeyCode::Char('y')),
        (
            "n / Esc=やめる",
            confirmation,
            "n / Esc=やめる",
            KeyCode::Char('n'),
        ),
        (
            "Enter / Esc=閉じる",
            read_only,
            "Enter / Esc=閉じる",
            KeyCode::Enter,
        ),
    ];
    for (case, make, button, key) in cases {
        assert_click_is_keys(
            case,
            &make,
            &|grid, app| cell_of(grid, Some(modal_bottom(grid, app)), button, None),
            &[k(key)],
        );
    }

    // 書いた中身（作業ディレクトリの綴りを除いて同じ）。
    let (ws_click, ws_keys) = (workspace(), workspace());
    let mut clicked = transition_confirmation_to(ws_click.path(), "workspace-shell");
    let mut keyed = transition_confirmation_to(ws_keys.path(), "workspace-shell");
    let grid = frame(&mut clicked, SIZE.0, SIZE.1);
    let bottom = modal_bottom(&grid, &clicked);
    click(&mut clicked, cell_of(&grid, Some(bottom), "y=書く", None));
    press(&mut keyed, KeyCode::Char('y'));
    // 書いた時刻（`updated_unix_ms`）の行は除く（2つを書いた時刻は違う）。
    let written = |ws: &std::path::Path| {
        std::fs::read_to_string(crate::policy_file::path(ws))
            .expect("policy.json")
            .replace(&ws.display().to_string().replace('\\', "/"), "<ws>")
            .replace(&ws.display().to_string().replace('\\', "\\\\"), "<ws>")
            .lines()
            .filter(|line| !line.contains("updated_unix_ms"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(clicked.modal.is_none(), "確認ダイアログが閉じていない");
    assert_eq!(written(ws_click.path()), written(ws_keys.path()));
    assert!(
        written(ws_click.path()).contains("git.exe"),
        "押した`y`で遷移が書かれていない"
    );
}

// ---------------------------------------------------------------------------
// 許可側: 押せない場所・重ねた枠の後ろ・左クリック以外
// ---------------------------------------------------------------------------

/// `case`の画面で`at`を押しても（右クリック・ドラッグも）、状態が1つも変わらないこと。
fn assert_nothing_happens(case: &str, app: &mut App, at: (u16, u16)) {
    let before = snapshot(app);
    assert_eq!(action_kind(&click(app, at)), "なし", "{case}");
    for kind in [
        MouseEventKind::Down(MouseButton::Right),
        MouseEventKind::Drag(MouseButton::Left),
        MouseEventKind::Moved,
    ] {
        assert!(mouse(app, kind, at.0, at.1).is_none(), "{case}: {kind:?}");
    }
    assert_eq!(
        snapshot(app),
        before,
        "{case}: {at:?}を押したら状態が変わった"
    );
}

/// **押せない場所を押しても、何も変わらない**——枠線・説明欄（ホイールだけ）・キー案内の区切り・
/// 押せない案内（`↑↓ 選択`）・知らせの行・作業ディレクトリの表示。
#[test]
fn clicking_where_nothing_is_drawn_to_press_changes_nothing() {
    let ws = workspace();
    let mut app = edit_screen_with_a_tree(ws.path());
    app.status = "知らせの行です".to_string();
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let candidates = boxed(&grid, " 候補:");
    let notes = boxed(&grid, " 記録の読み方");
    let keys = key_row(&grid);
    let spots = [
        ("候補の枠の左上の角", (candidates.x, candidates.y)),
        (
            "候補の枠の右下の角",
            (candidates.right() - 1, candidates.bottom() - 1),
        ),
        ("注記の中", (notes.x + 2, notes.y + 1)),
        ("キー案内の区切り", cell_of(&grid, Some(keys), "|", None)),
        (
            "押せない案内（↑↓ 選択）",
            cell_of(&grid, Some(keys), "↑↓ 選択", None),
        ),
        ("知らせの行", cell_of(&grid, None, "知らせの行です", None)),
        (
            "作業ディレクトリの表示",
            cell_of(&grid, Some(top_row()), "workspace:", None),
        ),
    ];
    for (case, at) in spots {
        assert_nothing_happens(case, &mut app, at);
    }

    // 一括の操作は押せない（決定51。`tui::pointer`のモジュールdoc）。
    let ws = workspace();
    let mut app = declared_screen_with_a_tree(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let at = cell_of(&grid, Some(key_row(&grid)), "A 全件", None);
    assert_nothing_happens("宣言・A 全件", &mut app, at);
    let ws = workspace();
    let mut app = transition_tab_with_three_candidates(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let at = cell_of(&grid, Some(key_row(&grid)), "X 表示中を却下", None);
    assert_nothing_happens("遷移・X 表示中を却下", &mut app, at);
}

/// **確認ダイアログが開いている間は、後ろの画面（タブ・一覧の行・`[x]`・キー案内）を押しても何も変わらない。**
/// ダイアログの枠の中でも、ボタン以外は押せない。
#[test]
fn nothing_behind_a_confirmation_can_be_clicked() {
    let (ws, ws_behind) = (workspace(), workspace());
    let mut behind = edit_screen_with_a_tree(ws_behind.path());
    let back = frame(&mut behind, SIZE.0, SIZE.1);
    let candidates = boxed(&back, " 候補:");
    let spots = [
        ("タブ", cell_of(&back, Some(top_row()), " F3 宣言 ", None)),
        (
            "承認待ちのタブ",
            cell_of(&back, None, "遷移・拒否から", None),
        ),
        (
            "候補の行",
            cell_of(&back, Some(candidates), "cargo.exe", None),
        ),
        (
            "候補の[ ]",
            cell_of(&back, Some(candidates), "[", Some("cargo.exe")),
        ),
        (
            "キー案内",
            cell_of(&back, Some(key_row(&back)), "F4 ヘルプ", None),
        ),
    ];
    let mut app = edit_screen_with_a_tree(ws.path());
    app.modal = Some(state::Modal {
        title: "承認の確認".to_string(),
        lines: (0..5).map(|i| format!("{i}行目")).collect(),
        confirm: Confirm::Approval,
    });
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let modal = modal_box(&grid, &app);
    for (case, at) in spots {
        if modal.contains(ratatui::layout::Position::new(at.0, at.1)) {
            continue; // ダイアログに隠れている場所は、下の「枠の中」で見る。
        }
        assert_nothing_happens(&format!("確認ダイアログの後ろの{case}"), &mut app, at);
    }
    assert_nothing_happens("確認ダイアログの本文", &mut app, (modal.x + 2, modal.y + 1));
    assert_nothing_happens(
        "確認ダイアログの左下の角",
        &mut app,
        (modal.x, modal.bottom() - 1),
    );
}

/// **ヘルプが開いている間は、どこを押しても閉じるだけで、後ろは押されない**（何かキーを押したのと同じ）。
#[test]
fn a_click_closes_the_help_and_does_not_reach_behind_it() {
    type Make = fn(&std::path::Path) -> App;
    let with_help: Make = |ws| {
        let mut app = edit_screen_with_a_tree(ws);
        press(&mut app, KeyCode::F(4));
        app
    };
    // 後ろのタブ（`F3 宣言`）の位置を押す。キーの側は、ヘルプを閉じるだけで何もしないキーを押す。
    let back = {
        let ws = workspace();
        let mut app = edit_screen_with_a_tree(ws.path());
        let grid = frame(&mut app, SIZE.0, SIZE.1);
        cell_of(&grid, Some(top_row()), " F3 宣言 ", None)
    };
    assert_click_is_keys(
        "ヘルプの後ろのタブ",
        &with_help,
        &|_, _| back,
        &[k(KeyCode::Char('x'))],
    );
    assert_click_is_keys(
        "ヘルプの中",
        &with_help,
        &|grid, _| {
            cell_of(
                grid,
                Some(boxed(grid, " ヘルプ")),
                "harness-policy-editor",
                None,
            )
        },
        &[k(KeyCode::Char('x'))],
    );
}

/// 押せる場所の登録は、描くたびに入れ替わる——画面を移った後は、前の画面の行の位置を押しても前の画面の操作は起きない。
#[test]
fn the_targets_of_a_screen_that_is_no_longer_drawn_are_gone() {
    let ws = workspace();
    let mut app = edit_screen_with_a_tree(ws.path());
    let grid = frame(&mut app, SIZE.0, SIZE.1);
    let mark = cell_of(&grid, Some(boxed(&grid, " 候補:")), "[", Some("cargo.exe"));
    press(&mut app, KeyCode::F(1));
    frame(&mut app, SIZE.0, SIZE.1);
    let accepted = app.accepted.clone();
    click(&mut app, mark);
    assert_eq!(
        app.accepted, accepted,
        "記録画面で、承認待ちの[ ]の位置が押された"
    );
    assert_eq!(app.screen, Screen::Record);
}
