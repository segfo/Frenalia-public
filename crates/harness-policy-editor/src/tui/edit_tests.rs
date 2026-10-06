//! 編集画面の状態遷移テスト（端末を使わない）。
//!
//! 承認は**実際に`policy.json`へ書くところまで**確かめる。「未選択なら書かない」だけを
//! 固定すると、承認経路が丸ごと死んでいても緑になる（B-35: 禁止側と許可側は対で書く）。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::session_dir::{self, NetMode, RecordManifest, RecordSessionDir, RecordStatus};
use crate::tui::state::{App, CandidateFilter, Confirm, EditField, Pass, Screen};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(session_dir::sandbox_root(dir.path())).expect("sandbox root");
    dir
}

/// パス1の記録セッションを1件作る（観測したパスは呼び出し側が決める）。すべて`read`で観測する。
fn seed_pass1(ws: &tempfile::TempDir, id: &str, command: &str, paths: &[&str]) {
    let observed: Vec<(&str, harness_config::FsAccess)> = paths
        .iter()
        .map(|p| (*p, harness_config::FsAccess::Read))
        .collect();
    seed_pass1_with_access(ws, id, command, &observed);
}

/// [`seed_pass1`]のaccess種別を指定できる版。**書込が観測されたケース**を作るために要る
/// （`**`＋`fs.read_write`の拒否を測るテストが使う）。
fn seed_pass1_with_access(
    ws: &tempfile::TempDir,
    id: &str,
    command: &str,
    observed: &[(&str, harness_config::FsAccess)],
) {
    let dir = RecordSessionDir::create(ws.path(), id).expect("session dir");
    let mut manifest = RecordManifest::new(id, command, ws.path(), ws.path(), 100);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).expect("manifest");

    let mut log = String::new();
    for (index, (path, access)) in observed.iter().enumerate() {
        let event = harness_policy::FsAuditEvent::observed(
            harness_policy::FsAuditKind::Etw,
            *path,
            *access,
            true,
            "record_all",
            index as u64 + 1,
        );
        log.push_str(&event.to_jsonl_line().expect("jsonl"));
        log.push('\n');
    }
    std::fs::write(dir.audit_log_path(), log).expect("audit log");
}

/// パス2（ドメイン記録）のセッションを1件作る。
fn seed_pass2(ws: &tempfile::TempDir, id: &str, command: &str, domain: &str, hosts: &[&str]) {
    let dir = RecordSessionDir::create(ws.path(), id).expect("session dir");
    let mut manifest = RecordManifest::new(id, command, ws.path(), ws.path(), 200);
    manifest.pass = 2;
    manifest.domain = Some(domain.to_string());
    manifest.status = RecordStatus::Finished;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).expect("manifest");

    let mut log = String::new();
    for host in hosts {
        log.push_str(&format!(
            r#"{{"source":"proxy","host":"{host}","allowed":true,"reason":"record_all","timestamp_unix_ms":1}}"#
        ));
        log.push('\n');
    }
    std::fs::write(dir.net_audit_log_path(), log).expect("net audit log");
}

fn open_edit(ws: &tempfile::TempDir) -> App {
    open_edit_with(ws, harness_core::RequireSandbox::None)
}

/// `--require-sandbox`の宣言を指定して編集画面を開く（[BUG-127](../../../../docs/bugs/BUG-127.md)）。
fn open_edit_with(ws: &tempfile::TempDir, require_sandbox: harness_core::RequireSandbox) -> App {
    let mut app = App::new(ws.path().to_path_buf(), require_sandbox);
    app.on_key(key(KeyCode::F(2)));
    app
}

/// ワークスペース外への**書込**が観測された記録を1件作る。
/// `fs.read_write`の提案になるので、`--require-sandbox=write-containment`と矛盾する。
fn seed_outside_write(ws: &tempfile::TempDir) {
    seed_pass1_with_access(
        ws,
        "s1",
        "cargo build",
        &[(
            r"C:\Users\me\.cargo\a.rs",
            harness_config::FsAccess::ReadWrite,
        )],
    );
}

/// **[BUG-127] 禁止側。** TUI（サブコマンド無しの既定経路）でも、`--require-sandbox`と
/// 矛盾する承認は拒否されること。
///
/// 直す前は`ApproveRequest.require_sandbox`に定数`RequireSandbox::None`を書いていたため、
/// **同じ提案がCLIでは拒否されTUIでは通る**という状態だった。ゲート自体は正しく、
/// 禁止側・許可側のテストも両方緑だったが、**それらが呼ぶのは`approve::plan`であって
/// TUIの呼び出し側ではない**——判定器の正しさと、判定器へ実値が届いているかは別の主張である。
#[test]
fn the_tui_refuses_an_approval_that_contradicts_require_sandbox() {
    let ws = workspace();
    seed_outside_write(&ws);
    let mut app = open_edit_with(&ws, harness_core::RequireSandbox::WriteContainment);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));

    app.on_key(key(KeyCode::Char('a')));

    let modal = app.modal.as_ref().expect("拒否のダイアログが出ている");
    assert!(
        modal.title.contains("承認できません"),
        "title={:?} lines={:?}",
        modal.title,
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("--require-sandbox")),
        "拒否の理由が宣言との矛盾だと分かること: {:?}",
        modal.lines
    );
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "拒否されたのに policy.json が書かれている"
    );
}

/// **[BUG-127] 許可側（対）。** 宣言が無い（`RequireSandbox::None`）なら、同じ承認は通る。
///
/// **この対が無いと、`request_approval`が常に失敗する実装でも禁止側テストが通る**（`B-35`）。
/// 種は禁止側とまったく同じで、違うのは`require_sandbox`の値だけにしてある。
#[test]
fn the_tui_still_approves_the_same_proposal_without_a_declaration() {
    let ws = workspace();
    seed_outside_write(&ws);
    let mut app = open_edit_with(&ws, harness_core::RequireSandbox::None);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));
    app.on_key(key(KeyCode::Char('y')));

    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    let domain = policy.domain("cargo").expect("ドメインが作られている");
    assert!(!domain.fs.is_empty(), "承認した値が入っていない");
}

/// 記録を開くと候補が出て、ドメイン名の既定値がコマンドから決まる。
#[test]
fn opening_a_recording_shows_candidates_and_a_default_domain_name() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me\.cargo\registry\a.rs"],
    );

    let app = open_edit(&ws);

    assert_eq!(app.screen, Screen::Edit);
    let view = app.view.as_ref().expect("記録が開いている");
    assert!(!view.proposals.is_empty());
    assert_eq!(app.domain.text(), "cargo");
    assert!(
        view.notes.contains("観測"),
        "注記（観測件数・除外件数）はCLIと同じ文言を出す: {}",
        view.notes
    );
}

/// 何も選ばずに承認しようとしても、何も起きない（全件受理のショートハンドは無い、D-42）。
#[test]
fn approving_without_a_selection_is_refused() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);

    app.on_key(key(KeyCode::Char('a')));

    assert!(app.modal.is_none());
    assert!(app.status.contains("スペースで選んで"), "{}", app.status);
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "policy.jsonを作ってはいけない"
    );
}

/// 承認は2段。`a`は差分を見せるだけで**まだ書かない**。
#[test]
fn pressing_approve_shows_the_diff_without_writing_anything() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));

    app.on_key(key(KeyCode::Char('a')));

    let modal = app.modal.as_ref().expect("差分のモーダルが出る");
    assert_eq!(
        modal.confirm,
        Confirm::Approval,
        "y/nを聞く形で、承認を書く確認になっている"
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("＋1件")),
        "何が増えるのかを見せる: {:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("workspace外")),
        "マシンに残る変更があるかどうかが承認の判断材料: {:?}",
        modal.lines
    );
    // 遷移が1本も無いので、広がる遷移は出ない（`approving_into_a_transition_destination_lists_the_widened_edge`の対）。
    assert!(
        !modal.lines.iter().any(|l| l.contains("広がる遷移")),
        "{:?}",
        modal.lines
    );
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "確認前に書いてはいけない"
    );
}

/// [P5.3、決定66] **遷移の遷移先になっているドメインへ承認すると、その遷移が呼び出し元へ新しく渡す権限が確認に出る**
/// （広げる遷移は書ける。書く前に、承認で何が呼び出し元の手に渡るかを読ませる）。
#[test]
fn approving_into_a_transition_destination_lists_the_widened_edge() {
    use harness_policy::policy_file::ENTRY_DOMAIN;
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut entry = crate::policy_file::PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions.push(editor_edge(
        "C:/Users/me/tools/cargo.exe",
        ArgvMatcher::Any(AnyMarker),
        "cargo",
    ));
    crate::policy_file::save(
        ws.path(),
        &crate::policy_file::PolicyFile {
            domains: vec![crate::policy_file::PolicyDomain::new("cargo"), entry],
            ..Default::default()
        },
    )
    .expect("setup");
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));

    app.on_key(key(KeyCode::Char('a')));

    let modal = app.modal.as_ref().expect("差分のモーダルが出る");
    assert_eq!(modal.confirm, Confirm::Approval);
    let text = modal.lines.join("\n");
    assert!(text.contains("広がる遷移 1本"), "{text}");
    assert!(text.contains(&format!("{ENTRY_DOMAIN} → cargo")), "{text}");
}

/// `y`で実際に`policy.json`が増える（許可側。B-35の対）。次はパス2、というガイドまで含めて固定する。
#[test]
fn confirming_the_diff_writes_the_policy_file_and_points_at_pass2() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    // 前の操作で強制モードを選んでいたことにする。既定値のままだと「記録へ戻す」を検査できない。
    app.net_mode = NetMode::Declared;
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));

    app.on_key(key(KeyCode::Char('y')));

    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    let domain = policy.domain("cargo").expect("ドメインが作られている");
    assert!(
        !domain.fs.is_empty(),
        "承認した値が入っていなければ、書けたと言えない"
    );
    assert_eq!(domain.commands, vec!["cargo build".to_string()]);
    assert_eq!(domain.provenance.record_sessions, vec!["s1".to_string()]);

    // ガイド: 次はパス2（ここで初めてACEが付く）。画面と入力欄が埋まっている。
    assert_eq!(app.screen, Screen::Record);
    assert_eq!(app.pass, Pass::Two);
    assert_eq!(
        app.net_mode,
        NetMode::RecordAll,
        "FSを承認した直後は通信先をまだ宣言していないので、記録で集める"
    );
    assert_eq!(app.run_domain.text(), "cargo");
    assert_eq!(app.command.text(), "cargo build");
    assert!(app.status.contains("パス2"), "{}", app.status);
}

/// 差分は**access種別ごとにまとめる**。`+ fs.read = <パス>`を1行ずつ出すと、687件では
/// 同じ`fs.read =`が687回並び、「どの種別を何件許すのか」が読み取れない。
#[test]
fn the_diff_groups_the_paths_under_each_access_kind() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));

    app.on_key(key(KeyCode::Char('a')));

    let lines = &app.modal.as_ref().expect("確認が出る").lines;
    let heading = lines
        .iter()
        .position(|l| l.contains("fs.read") && l.contains("＋2件"))
        .unwrap_or_else(|| panic!("種別の見出しが要る: {lines:#?}"));
    assert!(
        lines[heading + 1].trim().starts_with("C:/"),
        "見出しの下にパスがぶら下がる: {:?}",
        &lines[heading..]
    );
    assert!(
        !lines.iter().any(|l| l.contains("fs.read = C:/")),
        "パスごとに種別を繰り返さない: {lines:#?}"
    );
}

/// **判断材料（マシンに残る変更）は明細より前に置く。** 687件の後ろにあると、承認するか
/// どうかを決める材料を読むのに延々と送ることになる。
#[test]
fn what_stays_on_the_machine_comes_before_the_long_detail() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me\.cargo\registry\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));

    let lines = &app.modal.as_ref().expect("確認が出る").lines;
    let machine = lines
        .iter()
        .position(|l| l.contains("workspace外"))
        .expect("マシンに残る変更の行がある");
    let detail = lines
        .iter()
        .position(|l| l.contains("＋"))
        .expect("明細の見出しがある");

    assert!(machine < detail, "判断材料が明細より後ろにある: {lines:#?}");
}

/// **書き込みの確認はEnterでは閉じない。** 「Enterを押したら消えた。書かれたのか？」という
/// 状態を作らないため、`y`か`n`/`Esc`を選ばせる（実際にこの迷いが報告された）。
#[test]
fn enter_does_not_dismiss_the_write_confirmation() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));
    assert!(app.modal.is_some());

    app.on_key(key(KeyCode::Enter));

    assert!(app.modal.is_some(), "確認が消えてはいけない");
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "書いてもいけない"
    );
}

/// 読むだけのダイアログ（拒否の理由など）はEnterで閉じてよい。
#[test]
fn enter_closes_a_read_only_dialog() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    app.modal = Some(crate::tui::state::Modal {
        title: "報告".to_string(),
        lines: vec!["読むだけ".to_string()],
        confirm: Confirm::ReadOnly,
    });

    app.on_key(key(KeyCode::Enter));

    assert!(app.modal.is_none());
}

// 「長い差分は最後まで送れる」は、送りの上限が描画から来る（BUG-196）ので、描いて書き戻す経路を通す
// `render_tests::a_long_diff_scrolls_row_by_row_and_page_by_page_and_stops_at_the_end`が見る。

/// `n`で中止したら何も書かない。**中止したことも伝える**（黙って閉じない）。
#[test]
fn declining_the_diff_writes_nothing() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));

    app.on_key(key(KeyCode::Char('n')));

    assert!(app.modal.is_none());
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "何も書かない"
    );
    assert!(app.status.contains("中止"), "{}", app.status);
}

/// 広すぎる値（ユーザープロファイル全体）は**選ぶ時点で断る**。
///
/// `approve::plan`は広すぎる値が1件でも混ざると**何も書かずに全部を拒否する**ので、選べて
/// しまうと「10件選んで承認したら全部拒否された」になる。一覧からは消さない——観測した事実は
/// 隠さない（D-43）。承認経路側の拒否は`approve_tests::one_too_broad_value_refuses_the_whole_batch`
/// が別に固定している（こちらが緩んでも書かれることはない）。
#[test]
fn a_too_broad_candidate_cannot_be_selected_even_when_it_is_shown() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me"]);
    let mut app = open_edit(&ws);
    // 一般化すると値が変わるので、観測した値そのままの状況を作る。
    app.open_selected_session();
    app.filter = CandidateFilter::All;
    app.rebuild_tree();
    app.edit_focus = EditField::Proposals;
    assert!(
        !app.visible_proposals().is_empty(),
        "候補としては一覧に出る（観測した事実は隠さない）"
    );

    app.on_key(key(KeyCode::Char(' ')));

    assert!(app.accepted.is_empty(), "選択に入れてはいけない");
    assert!(
        app.status.contains("承認できません"),
        "なぜ選べないのかを出す: {}",
        app.status
    );
    assert!(
        app.status.contains("too broad"),
        "理由（幅の判定）が読めなければ直しようがない: {}",
        app.status
    );
    assert!(!crate::policy_file::path(ws.path()).exists());
}

/// 既定では承認できない候補を**出さない**。ただし件数は数えられる状態にしておく
/// ——「候補が少ない」のか「隠している」のかが区別できないと、無言で捨てているのと同じ（B-09）。
#[test]
fn blocked_candidates_are_hidden_by_default_but_still_counted() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me", r"C:\Users\me\.cargo\registry\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();

    assert_eq!(app.filter, CandidateFilter::Approvable, "既定");
    let view = app.view.as_ref().expect("記録が開いている");
    assert_eq!(view.proposals.len(), 2);
    assert_eq!(view.blocked_count(), 1, "C:/Users/me は承認できない");
    assert_eq!(
        app.visible_proposals().len(),
        1,
        "既定の一覧に出るのは承認できるものだけ"
    );
}

/// `f`で一覧の範囲を回せる（承認できるもの → できないもの → 全部）。
#[test]
fn the_filter_cycles_through_approvable_blocked_and_all() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me", r"C:\Users\me\.cargo\registry\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char('f')));
    assert_eq!(app.filter, CandidateFilter::Blocked);
    assert_eq!(app.visible_proposals().len(), 1);
    assert!(app.status.contains("承認できないもの"), "{}", app.status);

    app.on_key(key(KeyCode::Char('f')));
    assert_eq!(app.filter, CandidateFilter::All);
    assert_eq!(app.visible_proposals().len(), 2);

    app.on_key(key(KeyCode::Char('f')));
    assert_eq!(app.filter, CandidateFilter::Approvable);
}

/// **画面で選んだ行と、実際に承認される候補が一致する。** ここが食い違うのは最悪の形なので、
/// 木の行 → 候補 → `policy.json`まで通しで確かめる（フィルタで隠れている候補が混ざらないことも）。
#[test]
fn what_is_written_is_what_was_selected_on_screen() {
    let ws = workspace();
    // 承認不可（C:/Users/me）と承認可（.../registry/a.rs）が混在する。
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me", r"C:\Users\me\.cargo\registry\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    // 既定（承認できるものだけ）なので、木に出るのは承認できる候補だけ。
    assert_eq!(app.selected_row, 0);
    let node = app.selected_node().expect("行がある");
    assert_eq!(app.tree.node(node).path, "C:/Users/me/.cargo/registry/a.rs");

    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));
    app.on_key(key(KeyCode::Char('y')));

    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    assert_eq!(
        policy.domain("cargo").expect("ドメイン").fs.read,
        vec!["C:/Users/me/.cargo/registry/a.rs".to_string()]
    );
}

/// **スペースはその配下をまとめて選ぶ。** 「この下は全部許してよい」という判断をそのまま
/// 操作にできることが、849件の一覧を扱えるかどうかの分かれ目になる。
#[test]
fn space_on_a_directory_selects_everything_under_it() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
            r"C:\Users\me\.rustup\toolchains\x\bin\rustc.exe",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    // 根（C:/Users/me）を選んでスペース → 3件すべてが選択される。
    app.on_key(key(KeyCode::Char(' ')));

    assert_eq!(app.accepted.len(), 3, "配下すべて");
    assert!(app.status.contains("3件を選択"), "{}", app.status);

    // もう一度押すと解除（全部選ばれている状態からのトグル）。
    app.on_key(key(KeyCode::Char(' ')));
    assert!(app.accepted.is_empty());
    assert!(app.status.contains("解除"), "{}", app.status);
}

/// [D-62] **入れ子が何段でも、選ばれるのは観測されたファイルだけ**である。
///
/// 中間ディレクトリ（`sub1`・`sub1/sub2`）は`ensure_path`が作る**構造ノード**で、候補を持たない
/// ——だから一括選択で「ディレクトリをルートとして扱う」ことは起きない。画面に見えている
/// 候補の数と、承認される値の数が一致する。
#[test]
fn a_deep_bulk_selection_only_picks_the_observed_files_at_every_depth() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\proj\sub1\a.rs",
            r"C:\proj\sub1\sub2\b.rs",
            r"C:\proj\sub1\sub2\sub3\c.rs",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char(' ')));

    let view = app.view.as_ref().expect("記録が開いている");
    let chosen: Vec<&str> = view
        .proposals
        .iter()
        .filter(|p| app.accepted.contains(&p.id))
        .map(|p| p.value.as_str())
        .collect();
    assert_eq!(
        chosen,
        vec![
            "C:/proj/sub1/a.rs",
            "C:/proj/sub1/sub2/b.rs",
            "C:/proj/sub1/sub2/sub3/c.rs"
        ],
        "深さに関係なく、観測されたファイルだけが選ばれること"
    );
    // 中間ディレクトリが値として紛れ込んでいないこと。**ここが破れると、見えている3件のつもりで
    // サブツリー全体を開くことになる。**
    assert!(
        !chosen
            .iter()
            .any(|v| *v == "C:/proj/sub1" || *v == "C:/proj/sub1/sub2"),
        "中間ディレクトリを選んではならない: {chosen:?}"
    );
}

/// [D-62] ディレクトリ自身が観測されていたら、`d`で**明示的に**選べる（外した機能を
/// 取り上げてはいない）。B-35の対: スペースが入れないことと、`d`が入れられることの両方を測る。
#[test]
fn the_directory_itself_can_still_be_chosen_deliberately_with_d() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\proj\sub1", r"C:\proj\sub1\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.filter = CandidateFilter::All;
    app.rebuild_tree();
    app.edit_focus = EditField::Proposals;

    // スペースでは入らない。
    app.on_key(key(KeyCode::Char(' ')));
    let dir_id = {
        let view = app.view.as_ref().expect("記録が開いている");
        view.proposals
            .iter()
            .find(|p| p.value == "C:/proj/sub1")
            .expect("ディレクトリ自身も候補になっている")
            .id
            .clone()
    };
    assert!(
        !app.accepted.contains(&dir_id),
        "スペースはディレクトリ自身を入れない"
    );

    // `d`でなら入る。**そして何が起きるかを言う。**
    //
    // [D-63] 素の宣言が開くのは**そのオブジェクト1つだけ**になった（付与層が非継承ACEを書く）。
    // ここで「配下すべて」と言っていた頃の文面をそのまま残すと、**実際より広く伝える**
    // ことになる。範囲を言うこと自体は変えず、言う内容を実装に合わせる（B-32）。
    app.on_key(key(KeyCode::Char('d')));
    assert!(app.accepted.contains(&dir_id), "dで明示的に選べる");
    assert!(
        app.status.contains("この行のパスだけ"),
        "選んだ範囲を言う: {}",
        app.status
    );
    assert!(
        app.status.contains('R'),
        "配下も要るときの出口（R）を同時に出す: {}",
        app.status
    );

    // もう一度押すと外れる（対の操作）。
    app.on_key(key(KeyCode::Char('d')));
    assert!(!app.accepted.contains(&dir_id));
}

/// [D-63] `R`でディレクトリを再帰指定すると、`<path>/**`が実際に`policy.json`へ書かれる。
///
/// **観測されていない構造ノードにも付けられる**ことまで固定する——`.rustup/toolchains`のように
/// 中のファイルだけが観測されたケースがこの機能の主目的で、そこが押せないと意味が無い。
#[test]
fn marking_a_directory_recursive_writes_a_double_star_declaration() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\proj\tc\1.89.0\bin\rustc.exe",
            r"C:\proj\tc\1.90.0\bin\rustc.exe",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;
    // 根は `C:/proj/tc`（1本道が畳まれる）。ここ自身は観測されていない構造ノード。
    assert_eq!(
        app.tree.node(app.selected_node().expect("行")).path,
        "C:/proj/tc"
    );

    app.on_key(key(KeyCode::Char('R')));
    assert!(app.recursive.contains("C:/proj/tc"), "印が付く");
    assert!(
        app.status.contains("配下すべて"),
        "何が対象になるかを言う: {}",
        app.status
    );

    app.on_key(key(KeyCode::Char('a')));
    assert!(
        app.modal
            .as_ref()
            .is_some_and(|m| m.confirm == Confirm::Approval),
        "再帰の指定だけでも承認の確認が出ること（status={} modal={:?}）",
        app.status,
        app.modal.as_ref().map(|m| &m.title)
    );
    app.on_key(key(KeyCode::Char('y')));

    let raw = std::fs::read_to_string(crate::policy_file::path(ws.path())).unwrap_or_default();
    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    let domain = policy.domain("cargo").unwrap_or_else(|| {
        panic!(
            "domain cargo / ws={:?} / policy_path={:?} / exists={} / file={raw} ",
            ws.path(),
            crate::policy_file::path(ws.path()),
            crate::policy_file::path(ws.path()).exists(),
        )
    });
    assert!(
        domain.fs.read.contains(&"C:/proj/tc/**".to_string()),
        "再帰の宣言がそのまま書かれること: {:?}",
        domain.fs
    );

    // もう一度押せば外れる（対の操作）。
    let mut app2 = open_edit(&ws);
    app2.open_selected_session();
    app2.edit_focus = EditField::Proposals;
    app2.on_key(key(KeyCode::Char('R')));
    app2.on_key(key(KeyCode::Char('R')));
    assert!(app2.recursive.is_empty());
    assert!(app2.status.contains("外しました"), "{}", app2.status);
}

/// [D-63] 拒否側（B-35の対）: 葉には付けられず、`breadth`が拒否する広さにも付けられない。
/// **印を付ける時点で止める**——承認時まで黙っていると、選び直しが要ることに気付くのが遅れる。
#[test]
fn recursive_is_refused_on_a_leaf_and_on_a_too_broad_directory() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\proj\sub\a.rs"]);
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    // 葉（ファイル）まで降りる。
    app.on_key(key(KeyCode::Right));
    app.on_key(key(KeyCode::Right));
    let leaf = app.selected_node().expect("行");
    assert!(
        !app.tree.has_children(leaf),
        "葉に居ること: {:?}",
        app.tree.node(leaf).path
    );
    app.on_key(key(KeyCode::Char('R')));
    assert!(app.recursive.is_empty(), "葉は再帰にできない");
    assert!(
        app.status.contains("ディレクトリの行だけ"),
        "{}",
        app.status
    );

    // ユーザープロファイル全体のような広さは、印の段階で拒否される。
    // **2件必要**——1件だと1本道が畳まれて`C:/Users/me/a.rs`という葉1行になり、
    // ディレクトリ行が存在しなくなる（そうなると測りたい判定に到達しない）。
    let ws2 = workspace();
    seed_pass1(
        &ws2,
        "s1",
        "cargo build",
        &[r"C:\Users\me\a.rs", r"C:\Users\me\b.rs"],
    );
    let mut app2 = open_edit(&ws2);
    app2.open_selected_session();
    app2.filter = CandidateFilter::All;
    app2.rebuild_tree();
    app2.edit_focus = EditField::Proposals;
    app2.on_key(key(KeyCode::Char('R')));
    assert!(app2.recursive.is_empty(), "広すぎる再帰は付けられない");
    assert!(
        app2.status.contains("再帰にできません"),
        "理由を言う: {}",
        app2.status
    );
}

/// [D-62] 一括選択に**そのノード自身のディレクトリ候補は混ぜない**。混ぜると、画面には
/// 配下のファイルしか見えていないのにサブツリー全体が開く。外したことは必ず伝える（B-32）。
#[test]
fn a_subtree_selection_leaves_out_the_directory_itself_and_says_so() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\Users\me", r"C:\Users\me\.cargo\registry\a.rs"],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.filter = CandidateFilter::All;
    app.rebuild_tree();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char(' ')));

    assert_eq!(
        app.accepted.len(),
        1,
        "配下のファイルだけが入る（ディレクトリ自身は入らない）"
    );
    assert!(
        app.status.contains("自身は入れていません") && app.status.contains(" d "),
        "外したことと、要るときの出口の両方を言う: {}",
        app.status
    );
}

/// まとめて選んだあと、配下の1件だけ外せる（そして親は「一部選択」になる）。
#[test]
fn an_individual_candidate_can_be_deselected_after_a_bulk_selection() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char(' ')));
    assert_eq!(app.accepted.len(), 2);

    // 根を開いて子（a.rs）へ降り、そこだけ外す。
    app.on_key(key(KeyCode::Right));
    app.on_key(key(KeyCode::Right));
    let node = app.selected_node().expect("子の行");
    assert_eq!(app.tree.node(node).label, "a.rs");
    app.on_key(key(KeyCode::Char(' ')));

    assert_eq!(app.accepted.len(), 1, "1件だけ外れる");
}

/// `→`で開いて降り、`←`で閉じて戻る（展開状態は木を作り直しても残る）。
#[test]
fn right_expands_and_left_collapses_the_tree() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
            r"C:\Users\me\.cargo\bin\cargo.exe",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    // 既定では根（C:/Users/me/.cargo）だけが開いていて、子は `bin/cargo.exe` と `registry`。
    let rows_collapsed = app.tree.rows(&app.expanded).len();
    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Down));
    let node = app.selected_node().expect("registry の行");
    assert_eq!(app.tree.node(node).label, "registry");

    app.on_key(key(KeyCode::Right));
    assert!(
        app.tree.rows(&app.expanded).len() > rows_collapsed,
        "→で子が見える"
    );

    app.on_key(key(KeyCode::Left));
    assert_eq!(
        app.tree.rows(&app.expanded).len(),
        rows_collapsed,
        "←で畳む"
    );

    // 一般化の度合いを変えても、開いていた場所は保つ（比べる作業ができるように）。
    app.on_key(key(KeyCode::Right));
    let opened = app.expanded.clone();
    app.on_key(key(KeyCode::Char('g')));
    assert!(
        opened.iter().all(|path| app.expanded.contains(path)),
        "展開状態が消えている"
    );
}

/// **共通の警告は行ごとに繰り返さない。** OS監査由来の注記は全候補に付くので、候補の数だけ
/// 並べると（実測849件）個別の警告が埋もれる。
#[test]
fn a_warning_shared_by_every_candidate_is_hoisted_out_of_the_rows() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\Users\me\.cargo\registry\a.rs",
            r"C:\Users\me\.cargo\registry\b.rs",
            // 行に固有の警告を1つ作る。[D-62]で畳み込みを廃止したので「畳み込みの内訳」は
            // もう出ない——いま残っている行固有の警告はワイルドカード注意である。
            r"C:\Users\me\.rustup\toolchains\*\bin\rustc.exe",
        ],
    );
    let app = open_edit(&ws);

    let view = app.view.as_ref().expect("記録が開いている");
    assert!(
        view.common_warnings
            .iter()
            .any(|w| w.contains("OS auditing")),
        "全候補に付く注記が共通側へ移っている: {:?}",
        view.common_warnings
    );
    for proposal in &view.proposals {
        assert!(
            !view
                .row_warnings(proposal)
                .any(|w| w.contains("OS auditing")),
            "行には固有の警告だけを残す: {}",
            proposal.value
        );
    }
    // 1行にしか当てはまらない警告は行に残る——共通化で消してはいけない。
    assert!(
        view.proposals
            .iter()
            .any(|p| view.row_warnings(p).any(|w| w.contains("wildcard"))),
        "ワイルドカード注意はその行にしか当てはまらない: {:?}",
        view.proposals
    );
}

/// パス2の記録を開いたらネットワーク側の候補を見せる（`--net`を指定しなくても、CLIと同じ判断）。
#[test]
fn a_pass2_recording_shows_the_domain_candidates() {
    let ws = workspace();
    seed_pass2(&ws, "s2", "cargo build", "cargo", &["crates.io"]);

    let app = open_edit(&ws);

    let view = app.view.as_ref().expect("記録が開いている");
    assert!(
        view.proposals
            .iter()
            .any(|p| p.key == harness_policy::generalize::SettingsKey::NetAllowDomains),
        "パス2の候補は許可ドメインである: {:?}",
        view.proposals
    );
    assert_eq!(app.domain.text(), "cargo", "記録時のドメインを引き継ぐ");
}

/// [決定64] パス2の候補を承認したあとは、**同じドメインのパス2を強制モードで**用意する
/// （宣言した通信先だけで動くかを確かめるのが次の一手）。パス1の候補を承認したときは
/// 記録モード（`fs_approval_leads_to_pass2`の側）——モードを取り違えると、宣言をまだ持たない
/// ドメインを全部断る実行へ案内してしまう。
#[test]
fn approving_domains_leads_to_the_enforcing_pass2() {
    let ws = workspace();
    seed_pass2(&ws, "s2", "cargo build", "cargo", &["crates.io"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));

    app.on_key(key(KeyCode::Char('y')));

    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    assert_eq!(
        policy.domain("cargo").expect("ドメイン").net.allow_domains,
        vec!["crates.io".to_string()]
    );
    assert_eq!(app.screen, Screen::Record, "次の実行を記録画面に用意する");
    assert_eq!(app.pass, Pass::Two);
    assert_eq!(app.net_mode, NetMode::Declared, "強制モードへ案内する");
    assert_eq!(app.run_domain.text(), "cargo", "記録時のドメインを引き継ぐ");
    assert_eq!(app.command.text(), "cargo build", "記録時のコマンドを引き継ぐ");
    assert!(app.status.contains("強制"), "{}", app.status);
}

/// セッションを移ったら中身も入れ替わる（選択だけ動いて表示が古いまま、にしない）。
#[test]
fn moving_between_sessions_reloads_what_is_shown() {
    let ws = workspace();
    seed_pass1(&ws, "old", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    seed_pass2(&ws, "new", "gh pr list", "gh", &["api.github.com"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Sessions;

    // 新しい順に並ぶので、先頭はパス2の記録。
    assert_eq!(app.domain.text(), "gh");
    app.on_key(key(KeyCode::Down));

    assert_eq!(
        app.selected_session().map(|s| s.manifest.id.as_str()),
        Some("old")
    );
    assert_eq!(
        app.domain.text(),
        "cargo",
        "開いた記録に合わせて既定も変わる"
    );
}

/// ドメイン名の入力中は1文字キーが操作に取られない（`a`が承認になると名前が打てない）。
#[test]
fn typing_in_the_domain_field_does_not_trigger_the_action_keys() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Users\me\.cargo\a.rs"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Domain;
    app.domain.set_text("");

    for ch in "agt".chars() {
        app.on_key(key(KeyCode::Char(ch)));
    }

    assert_eq!(app.domain.text(), "agt");
    assert!(app.modal.is_none(), "承認モーダルが開いてはいけない");
    assert!(!app.show_tree, "ツリー表示が切り替わってはいけない");
}

/// **パス2の記録を開いたら、FSの拒否候補も出る。**
///
/// 実運用で詰まった形の回帰テスト——`cargo test`をパス2で走らせて`Access is denied`で
/// 落ちたとき、編集画面は**ネットワーク候補（0件）しか読んでいなかった**ので、
/// 「次に何を許可すればいいのか」を見る場所が1つも無かった。当時のパス2は
/// `fs-audit.jsonl`を書かなかったので0件表示は妥当だったが、段階4で収集器を配線してからは
/// **答えはFS側にある**。
#[test]
fn a_pass2_recording_shows_the_filesystem_denials_it_observed() {
    let ws = tempfile::tempdir().expect("tempdir");
    let id = "pass2-with-fs";
    seed_pass2(&ws, id, "cargo test", "cargo", &["crates.io"]);

    // 収集器が観測したFS拒否を同じセッションdirへ置く（段階4が実際に書く形）。
    let dir = RecordSessionDir::open(ws.path(), id).expect("session dir");
    let mut manifest = dir.read_manifest().expect("manifest");
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    let denial = harness_policy::FsAuditEvent::denied(
        harness_policy::FsAuditKind::Etw,
        "C:/Users/me/.cargo/bin/cargo.exe",
        harness_config::FsAccess::Read,
        "STATUS_ACCESS_DENIED (0xC0000022)",
        1,
    );
    std::fs::write(
        dir.audit_log_path(),
        format!("{}\n", denial.to_jsonl_line().expect("jsonl")),
    )
    .expect("fs audit log");

    let app = open_edit(&ws);

    let view = app.view.as_ref().expect("a view for the pass2 session");
    assert!(
        view.proposals
            .iter()
            .any(|p| p.value == "C:/Users/me/.cargo/bin/cargo.exe"),
        "the filesystem denial must be proposable from a pass2 recording: {:#?}",
        view.proposals
    );
    assert!(
        view.notes.contains("通信は全許可"),
        "the asymmetry has to be stated, or this reads as 'the sandbox allowed everything': {}",
        view.notes
    );
}

/// **対**（B-35）: ネットワーク候補が消えていないこと。FSを足したときに片方が
/// 落ちていないかを見る（「両方出す」が要件で、「FSに差し替える」ではない）。
#[test]
fn a_pass2_recording_still_shows_the_domains_it_reached() {
    let ws = tempfile::tempdir().expect("tempdir");
    seed_pass2(&ws, "pass2-net", "cargo test", "cargo", &["crates.io"]);

    let app = open_edit(&ws);

    let view = app.view.as_ref().expect("a view");
    assert!(
        view.proposals.iter().any(|p| p.value.contains("crates.io")),
        "{:#?}",
        view.proposals
    );
}

/// **収集器が起きなかったパス2の記録こそ、その事実を出す。**
///
/// 「観測していません」と「拒否は0件でした」は別の事実で、区別できなければfail-openは
/// 単なる隠蔽になる（D-43）。実運用では**逆になっていた**——`render_fs_denials`の呼び出しを
/// `collector_started`で囲んでいたため、起きなかったときだけ画面に何も出ず、ユーザーには
/// 「拒否の一覧が出てこない」としか見えなかった（BUG-093）。
#[test]
fn a_pass2_recording_without_a_collector_says_so_instead_of_showing_nothing() {
    let ws = tempfile::tempdir().expect("tempdir");
    // `seed_pass2`は`collector_started`を立てない（＝収集器が起きなかった記録）。
    seed_pass2(&ws, "pass2-no-collector", "cargo test", "cargo", &[]);

    let app = open_edit(&ws);

    let notes = &app.view.as_ref().expect("a view").notes;
    assert!(
        notes.contains("観測していません"),
        "the user must be able to tell 'not observed' from 'zero denials': {notes}"
    );
    assert!(
        notes.contains("ではありません"),
        "it has to say explicitly that this is not 'zero denials': {notes}"
    );
}

// ---------------------------------------------------------------------------
// `c`: 候補の access を手で変える
// ---------------------------------------------------------------------------

/// いま選んでいる行が持つ候補（無ければ`None`）。
fn selected_proposal(app: &App) -> Option<harness_policy::RuleProposal> {
    let node = app.selected_node()?;
    let index = *app.tree.node(node).proposals.first()?;
    Some(app.view.as_ref()?.proposals[index].clone())
}

/// **本体**: `read → read_write → read_exec`と巡回する。
///
/// これが無いと、OS監査が`fs.read`としか言えない実行ファイル（ETWは読取と実行を区別しない）を
/// `fs.read_exec`として承認する手段が1つも無い——`fs.read`をいくら足しても実行権は付かない。
#[test]
fn pressing_c_cycles_the_access_of_the_selected_candidate() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    assert_eq!(
        selected_proposal(&app).expect("a candidate row").key,
        harness_policy::SettingsKey::FsRead
    );

    app.on_key(key(KeyCode::Char('c')));
    assert_eq!(
        selected_proposal(&app).expect("still there").key,
        harness_policy::SettingsKey::FsReadWrite
    );

    app.on_key(key(KeyCode::Char('c')));
    let proposal = selected_proposal(&app).expect("still there");
    assert_eq!(proposal.key, harness_policy::SettingsKey::FsReadExec);
    assert_eq!(
        proposal.value, "C:/tools/bin/thing.exe",
        "値は動かさない（変えるのは access だけ）"
    );
    assert!(
        app.hand_changed.contains(&proposal.id),
        "手で変えたことを覚えていないと、承認前に見せられない"
    );
    assert!(app.status.contains("fs.read_exec"), "{}", app.status);
}

/// 警告は`key`に依存するので**作り直す**（表示側で足し引きしない）。
#[test]
fn changing_the_access_rebuilds_the_warnings_that_depend_on_it() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    let before = selected_proposal(&app).expect("a candidate");
    assert!(
        before
            .warnings
            .iter()
            .any(|w| w.contains("came from OS auditing")),
        "前提: fs.readには推測である旨が付いている: {before:#?}"
    );

    app.on_key(key(KeyCode::Char('c')));

    let after = selected_proposal(&app).expect("a candidate");
    assert!(
        !after
            .warnings
            .iter()
            .any(|w| w.contains("came from OS auditing")),
        "fs.read固有の注記は消える: {after:#?}"
    );
    assert!(
        after
            .warnings
            .iter()
            .any(|w| w.contains("weakens write containment")),
        "fs.read_write固有の注記が付く: {after:#?}"
    );
    assert!(
        after.warnings.iter().any(|w| w.contains("chosen by hand")),
        "観測ではないことが候補自身から読めること: {after:#?}"
    );
}

/// **広すぎて承認できなくなったら、選択から外して理由を出す。**
/// 1件でも混ざると`approve::plan`は何も書かずに全部を拒否するので、黙って残すと
/// 承認そのものが通らなくなる。`C:/Program Files`は読みは通るが書きは通らない値である。
#[test]
fn an_access_change_that_makes_a_candidate_unapprovable_unselects_it_and_says_so() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\Program Files"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    assert_eq!(app.accepted.len(), 1, "前提: fs.readとしては選べる");

    app.on_key(key(KeyCode::Char('c')));

    assert!(
        app.accepted.is_empty(),
        "承認できない候補を選択に残さない: {}",
        app.status
    );
    assert!(app.status.contains("広すぎ"), "{}", app.status);
    assert!(
        app.status.contains("f で切り替え"),
        "既定の一覧から消えたことも言う（探しても見つからなくなる）: {}",
        app.status
    );
}

/// ドメインの候補は変えられない。**何も起きない理由を言う**（B-32）。
#[test]
fn changing_the_access_of_a_domain_candidate_is_refused_with_a_reason() {
    let ws = workspace();
    seed_pass2(&ws, "s1", "curl example.com", "curl", &["example.com"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    let before = selected_proposal(&app).expect("a candidate row");
    assert_eq!(before.key, harness_policy::SettingsKey::NetAllowDomains);

    app.on_key(key(KeyCode::Char('c')));

    assert_eq!(
        selected_proposal(&app).expect("unchanged").key,
        harness_policy::SettingsKey::NetAllowDomains
    );
    assert!(app.hand_changed.is_empty());
    assert!(app.status.contains("FSの候補ではない"), "{}", app.status);
}

/// 同じ値に移動先のkeyが既にあるなら**作らない**（同じ設定値の候補が2行に割れる）。
#[test]
fn an_access_change_that_would_duplicate_an_existing_candidate_is_skipped_with_a_reason() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "s1").expect("session dir");
    let mut manifest = RecordManifest::new("s1", "cargo build", ws.path(), ws.path(), 100);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    dir.write_manifest(&manifest).expect("manifest");
    // 同じパスを read と read_write の両方で観測する（1つのノードが候補を2件持つ）。
    let mut log = String::new();
    for (index, access) in [
        harness_config::FsAccess::Read,
        harness_config::FsAccess::ReadWrite,
    ]
    .into_iter()
    .enumerate()
    {
        let event = harness_policy::FsAuditEvent::observed(
            harness_policy::FsAuditKind::Etw,
            r"C:\tools\bin\thing.exe",
            access,
            true,
            "record_all",
            index as u64 + 1,
        );
        log.push_str(&event.to_jsonl_line().expect("jsonl"));
        log.push('\n');
    }
    std::fs::write(dir.audit_log_path(), log).expect("audit log");

    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    let node = app.selected_node().expect("a row");
    assert_eq!(
        app.tree.node(node).proposals.len(),
        2,
        "前提: 同じ値に2つの候補がぶら下がっている"
    );

    app.on_key(key(KeyCode::Char('c')));

    let view = app.view.as_ref().expect("view");
    let keys: Vec<_> = view.proposals.iter().map(|p| p.key).collect();
    assert!(
        keys.contains(&harness_policy::SettingsKey::FsRead),
        "read→read_write は重複するので据え置き: {keys:?}"
    );
    assert!(
        keys.contains(&harness_policy::SettingsKey::FsReadExec),
        "read_write→read_exec は通る: {keys:?}"
    );
    assert_eq!(
        keys.iter()
            .filter(|k| **k == harness_policy::SettingsKey::FsReadWrite)
            .count(),
        0,
        "同じ値の候補が重複していないこと: {keys:?}"
    );
    assert!(app.status.contains("既に候補にあります"), "{}", app.status);
}

/// ディレクトリの行では何も起きない。**なぜ起きないのかを言う**（B-32）。
#[test]
fn pressing_c_on_a_directory_row_explains_why_nothing_happened() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[r"C:\tools\bin\a.exe", r"C:\tools\lib\b.dll"],
    );
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    let node = app.selected_node().expect("a row");
    assert!(
        app.tree.node(node).proposals.is_empty(),
        "前提: 先頭行は候補そのものではない（枝分かれの親）"
    );

    app.on_key(key(KeyCode::Char('c')));

    assert!(app.hand_changed.is_empty());
    assert!(app.status.contains("ディレクトリの行"), "{}", app.status);
}

/// **承認する前に「手で変えた」ことを見せる**（D-42: 何を書くのか読んでから`y`を押せる）。
#[test]
fn the_confirmation_shows_which_candidates_had_their_access_changed_by_hand() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char(' ')));

    app.on_key(key(KeyCode::Char('a')));

    let modal = app.modal.as_ref().expect("確認のモーダル");
    assert!(
        modal
            .lines
            .iter()
            .any(|l| l.contains("手で access を変えた候補 1件")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("観測ではなく")),
        "観測とユーザーの判断を混ぜない: {:?}",
        modal.lines
    );
}

/// **対（B-35）**: 変えたaccessで実際に`policy.json`が書かれる。
/// 「モーダルに出る」だけを固定すると、書き込み先が`fs.read`のままでも緑になる。
#[test]
fn approving_a_hand_changed_candidate_writes_it_into_the_read_exec_bucket() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::Char('a')));

    app.on_key(key(KeyCode::Char('y')));

    let policy = crate::policy_file::load(ws.path()).expect("policy.json");
    let domain = policy.domain("cargo").expect("domain cargo");
    assert_eq!(domain.fs.read_exec, vec!["C:/tools/bin/thing.exe"]);
    assert!(
        domain.fs.read.is_empty(),
        "観測どおりの fs.read で書いてはいけない（実行権が付かない）: {:?}",
        domain.fs
    );
}

/// [D-63] `r`（読み直し）は廃止した。代わりに**編集画面へ入るたびにセッション一覧を読み直す**
/// ——「画面を戻って入り直せば読み直される」を本当にするため。
///
/// **ただし開いている候補は作り直さない。** 作り直すと選択と手で変えたaccessが黙って消える。
/// 「新しい記録を拾う」と「いま選んでいるものを壊さない」の両方を1つのテストで固定する
/// （片方だけだと、もう片方が壊れても緑のままになる）。
#[test]
fn re_entering_the_edit_screen_picks_up_new_sessions_without_discarding_the_selection() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char(' ')));
    let hand_changed = app.hand_changed.clone();
    let accepted = app.accepted.clone();
    assert!(!hand_changed.is_empty() && !accepted.is_empty(), "前提");
    assert_eq!(app.sessions.len(), 1);

    // 別プロセスが作った記録を模す（このAppは関与していない）。
    seed_pass1(&ws, "s2", "cargo test", &[r"C:\tools\bin\other.exe"]);

    app.on_key(key(KeyCode::F(1)));
    app.on_key(key(KeyCode::F(2)));

    assert_eq!(
        app.sessions.len(),
        2,
        "外部で作られた記録も、画面へ入り直せば現れること"
    );
    assert_eq!(
        app.hand_changed, hand_changed,
        "手で変えたaccessを黙って捨ててはいけない"
    );
    assert_eq!(app.accepted, accepted, "選択を黙って捨ててはいけない");
}

/// **パス2の記録で`g`を押しても、FSの候補が消えないこと。**
///
/// 一覧にはFSとネットワークの両方を並べているのに、保持していたのはネットワークだけだった
/// ——`recompute_proposals`は保持している側からしか作り直せないので、**`g`を1回押すと
/// FSの候補（＝「次に何を許可すればコマンドが動くのか」の答え）が全部消えていた**。
#[test]
fn changing_the_generalization_keeps_the_fs_candidates_of_a_pass2_recording() {
    let ws = workspace();
    let dir = RecordSessionDir::create(ws.path(), "p2").expect("session dir");
    let mut manifest = RecordManifest::new("p2", "cargo test", ws.path(), ws.path(), 300);
    manifest.pass = 2;
    manifest.domain = Some("cargo".to_string());
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    // 実行前診断が名指しした実行ファイル（収集器の観測には出てこない側）。
    manifest.unreachable_exec = Some("C:/tools/bin/thing.exe".to_string());
    dir.write_manifest(&manifest).expect("manifest");
    std::fs::write(
        dir.net_audit_log_path(),
        "{\"source\":\"proxy\",\"host\":\"example.com\",\"allowed\":true,\"reason\":\"record_all\",\"timestamp_unix_ms\":1}\n",
    )
    .expect("net audit log");

    let mut app = open_edit(&ws);
    let has_exec = |app: &App| {
        app.view.as_ref().is_some_and(|view| {
            view.proposals
                .iter()
                .any(|p| p.value == "C:/tools/bin/thing.exe")
        })
    };
    assert!(has_exec(&app), "前提: 開いた直後は出ている");

    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char('g')));

    assert!(
        has_exec(&app),
        "一般化の度合いを変えただけでFSの候補が消えてはいけない: {:#?}",
        app.view.as_ref().map(|v| v.proposals.len())
    );
    assert!(
        app.view
            .as_ref()
            .expect("view")
            .proposals
            .iter()
            .any(|p| p.value == "example.com"),
        "ネットワーク側も残っていること"
    );
}

// --- 宣言済みの重ね（[x]）と、外して取り消す --------------------------------------

/// `policy.json`に宣言を1件書く（重ねのテスト用）。
fn seed_declaration(
    ws: &tempfile::TempDir,
    domain: &str,
    key: harness_policy::generalize::SettingsKey,
    value: &str,
) {
    let mut file = crate::policy_file::load(ws.path()).expect("load");
    if file.domain(domain).is_none() {
        file.domains.push(crate::PolicyDomain::new(domain));
    }
    let entry = file
        .domains
        .iter_mut()
        .find(|d| d.name == domain)
        .expect("just pushed");
    use harness_policy::generalize::SettingsKey;
    match key {
        SettingsKey::FsRead => entry.fs.read.push(value.to_string()),
        SettingsKey::FsReadWrite => entry.fs.read_write.push(value.to_string()),
        SettingsKey::FsReadExec => entry.fs.read_exec.push(value.to_string()),
        SettingsKey::NetAllowDomains => entry.net.allow_domains.push(value.to_string()),
    }
    crate::policy_file::save(ws.path(), &file).expect("save");
}

/// 候補と同じパスが**別のaccessで**宣言されていても`[x]`扱いになる。
///
/// ETWは読取と実行を区別しないので、`fs.read_exec`で承認した実行ファイルは次の記録でも
/// `fs.read`の候補として出てくる。ここで未選択に見えると、同じ場所へ二重にチェックを付ける。
#[test]
fn a_candidate_already_declared_under_another_access_is_shown_as_checked() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    // 候補の綴りは一般化（既定はディレクトリ）に依存するので、実際の候補値を使って宣言する。
    let app = open_edit(&ws);
    let value = app.view.as_ref().expect("view").proposals[0].value.clone();
    drop(app);
    seed_declaration(
        &ws,
        "cargo",
        harness_policy::generalize::SettingsKey::FsReadExec,
        &value,
    );

    let app = open_edit(&ws);
    let proposal = &app.view.as_ref().expect("view").proposals[0];
    assert!(
        app.proposal_is_on(proposal),
        "宣言済み（read_exec）なので候補（read）もチェック済みに見える"
    );
}

/// B-35の対。宣言が無ければチェックは入らない——上のテストだけなら
/// 「常にチェック済みと言う」実装でも緑になる。
#[test]
fn a_candidate_with_no_declaration_is_not_checked() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let app = open_edit(&ws);
    let proposal = &app.view.as_ref().expect("view").proposals[0];
    assert!(!app.proposal_is_on(proposal));
}

/// 宣言済みの行のチェックを外して確定すると、**`policy.json`からその宣言が消える**。
/// 消す対象は宣言側のキー（`read_exec`）であって候補のキー（`read`）ではない。
#[test]
fn unchecking_a_declared_row_removes_the_declaration_on_confirm() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let app = open_edit(&ws);
    let value = app.view.as_ref().expect("view").proposals[0].value.clone();
    drop(app);
    seed_declaration(
        &ws,
        "cargo",
        harness_policy::generalize::SettingsKey::FsReadExec,
        &value,
    );

    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    // 宣言済みなので`[x]`。Spaceで外す＝取り消しの予約。
    app.on_key(key(KeyCode::Char(' ')));
    assert!(
        !app.unapproved.is_empty(),
        "外した宣言が取り消し予約に入る: {}",
        app.status
    );
    assert!(
        app.unapproved
            .iter()
            .all(|t| { t.key == harness_policy::generalize::SettingsKey::FsReadExec }),
        "消す対象は宣言側のキー（read_exec）である"
    );

    app.on_key(key(KeyCode::Char('a')));
    assert!(app.modal.is_some(), "確認が出る");
    app.on_key(key(KeyCode::Char('y')));

    let after = crate::policy_file::load(ws.path()).expect("load");
    let domain = after.domain("cargo").expect("ドメインは残る");
    assert!(
        domain.fs.read_exec.is_empty(),
        "宣言が消えている: {:?}",
        domain.fs.read_exec
    );
}

/// **取り消しだけの確定も通る。** チェックを外す操作は`accepted`を増やさないので、
/// 「承認する候補が無い」で弾いてしまうと外したのに確定できない。
#[test]
fn a_confirmation_with_only_removals_is_accepted() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let app = open_edit(&ws);
    let value = app.view.as_ref().expect("view").proposals[0].value.clone();
    drop(app);
    seed_declaration(
        &ws,
        "cargo",
        harness_policy::generalize::SettingsKey::FsRead,
        &value,
    );

    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    assert!(app.accepted.is_empty(), "承認は1件も選んでいない");

    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("確認が出る");
    assert_eq!(modal.confirm, Confirm::Approval);
    assert!(
        modal.lines.iter().any(|l| l.contains("取り消す宣言")),
        "取り消す内容が確認画面に出る: {:?}",
        modal.lines
    );
}

/// ドメイン名を打ち替えたら重ねを作り直し、**取り消しの予約も捨てる**。
/// 捨てないと、打ち替える前のドメインの宣言を消しに行く。
#[test]
fn retyping_the_domain_name_drops_the_removal_reservations() {
    let ws = workspace();
    seed_pass1(&ws, "s1", "cargo build", &[r"C:\tools\bin\thing.exe"]);
    let app = open_edit(&ws);
    let value = app.view.as_ref().expect("view").proposals[0].value.clone();
    drop(app);
    seed_declaration(
        &ws,
        "cargo",
        harness_policy::generalize::SettingsKey::FsRead,
        &value,
    );

    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    app.on_key(key(KeyCode::Char(' ')));
    assert!(!app.unapproved.is_empty());

    app.edit_focus = EditField::Domain;
    app.on_key(key(KeyCode::Char('x')));

    assert!(
        app.unapproved.is_empty(),
        "別ドメインを指した状態で古い予約を残さない"
    );
}

/// **`R`だけを付けた状態も「選択」に数える**（表示とガードのずれ）。
///
/// 実運用で「x（チェック）マークが入っていないけど大丈夫？」と迷わせた——承認は通るのに
/// 見出しが「選択 0件」と出ていたためである。`request_approval`のガードは最初から
/// `recursive`を見ており、**表示だけが取り残されていた**（B-06: 選ぶ手段を増やしたら、
/// 選択の有無を見る場所を全部数える）。
#[test]
fn a_recursive_mark_counts_as_a_selection_even_without_a_checkbox() {
    let ws = workspace();
    seed_pass1(
        &ws,
        "s1",
        "cargo build",
        &[
            r"C:\proj\tc\1.89.0\bin\rustc.exe",
            r"C:\proj\tc\1.90.0\bin\rustc.exe",
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;
    assert_eq!(app.selected_count(), 0, "まだ何も選んでいない");

    app.on_key(key(KeyCode::Char('R')));

    assert!(app.accepted.is_empty(), "チェックは付かない（別の状態）");
    assert_eq!(
        app.selected_count(),
        1,
        "再帰指定は「選んだもの」である——承認はこれで通るのだから、表示も1件と言わなければ\
         ユーザーは承認できないと誤解する"
    );
}

/// **配下に書込が観測されているツリーは、`R` を押した時点で拒否する。**
///
/// `recursive_proposals`は**配下に観測されたaccess種別ごとに1本ずつ**`<path>/**`を作るので、
/// 奥の1ファイルが書込として観測されていれば`fs.read_write`の再帰宣言が生まれる。それは
/// `breadth`が拒否する値（将来そのツリーへ置かれた実行ファイルまで書き換えられるため）なので、
/// **印を付ける段階で止めなければ「印は付いたのに承認では弾かれる」**という形になる。
///
/// かつて`toggle_recursive`は`FsRead`固定で幅を見ており、この経路を素通しさせていた。
#[test]
fn marking_a_directory_recursive_is_refused_when_something_under_it_was_written() {
    let ws = workspace();
    seed_pass1_with_access(
        &ws,
        "s1",
        "cargo build",
        &[
            (
                r"C:\proj\tc\1.89.0\bin\rustc.exe",
                harness_config::FsAccess::Read,
            ),
            (
                r"C:\proj\tc\1.89.0\bin\out.tmp",
                harness_config::FsAccess::ReadWrite,
            ),
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char('R')));

    assert!(
        app.recursive.is_empty(),
        "書込が観測されているツリーに再帰の印を付けてはいけない: {}",
        app.status
    );
    assert!(
        app.status.contains("再帰にできません"),
        "なぜ付かなかったのかをその場で言う（B-32）: {}",
        app.status
    );
    assert!(
        app.status.contains("read_write"),
        "どのaccess種別が原因かを名指しする: {}",
        app.status
    );
}

/// **対になる許可側**（B-35）。読み取りしか観測されていないツリーは、従来どおり再帰にできる。
/// これが無いと「常に拒否する」実装でも上のテストが通り、`R`キー（D-63）が死んでいることに
/// 気付けない。
#[test]
fn marking_a_read_only_directory_recursive_is_still_allowed() {
    let ws = workspace();
    seed_pass1_with_access(
        &ws,
        "s1",
        "cargo build",
        &[
            (
                r"C:\proj\tc\1.89.0\bin\rustc.exe",
                harness_config::FsAccess::Read,
            ),
            (
                r"C:\proj\tc\1.90.0\bin\rustc.exe",
                harness_config::FsAccess::ReadExec,
            ),
        ],
    );
    let mut app = open_edit(&ws);
    app.open_selected_session();
    app.edit_focus = EditField::Proposals;

    app.on_key(key(KeyCode::Char('R')));

    assert!(
        !app.recursive.is_empty(),
        "read/read_exec だけなら再帰は従来どおり使える: {}",
        app.status
    );
}

/// 候補の木にドメインの見出しがあるとき（位置ごとのドメインの記録、決定65）、**見出しの行では`R`が何も印を付けない**。
/// 見出しのパスはドメイン名なので、通すと`<ドメイン名>/**`という宣言を作ってしまう。
/// 対の側: その下のフォルダの行では今までどおり印が付く。
#[test]
fn r_on_a_domain_header_marks_nothing() {
    let ws = workspace();
    let mut app = open_edit(&ws);
    let proposal = |id: &str, value: &str| harness_policy::RuleProposal {
        id: id.to_string(),
        key: harness_policy::generalize::SettingsKey::FsRead,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    };
    app.view = Some(crate::tui::state::SessionView::new(
        Default::default(),
        String::new(),
        String::new(),
        vec![
            proposal("fs-1", "C:/proj/tc/a.txt"),
            proposal("fs-2", "C:/proj/tc/b.txt"),
            proposal("fs-3", "C:/other/c.txt"),
        ],
        vec![
            Some("alpha".to_string()),
            Some("alpha".to_string()),
            Some("beta".to_string()),
        ],
    ));
    app.expanded.clear();
    app.rebuild_tree();
    app.edit_focus = EditField::Proposals;
    app.selected_row = 0;
    let header = app.selected_node().expect("見出しの行");
    assert!(app.tree.node(header).is_domain_header, "試験の前提: 1行目は見出し");

    app.on_key(key(KeyCode::Char('R')));
    assert!(app.recursive.is_empty(), "見出しの行に印は付かない: {:?}", app.recursive);
    assert!(
        app.status.contains("ドメインの見出しの行は再帰にできません"),
        "何も起きない理由を言う: {}",
        app.status
    );

    app.on_key(key(KeyCode::Down));
    assert_eq!(
        app.tree.node(app.selected_node().expect("行")).path,
        "C:/proj/tc",
        "試験の前提: 2行目は alpha の下のフォルダ"
    );
    app.on_key(key(KeyCode::Char('R')));
    // P4.4 から印は木の鍵（`Node::key`。段がある木では「ドメイン名＋区切り＋パス」）で持つ。
    let folder = app.selected_node().expect("行");
    assert!(
        app.recursive.contains(&app.tree.node(folder).key),
        "フォルダの行には付く: {}",
        app.status
    );
    assert!(!app.recursive.contains("C:/proj/tc"), "パスで持つと別のドメインの同じフォルダと区別できない");
}

// --- P4.4: 位置ごとのドメインの記録のファイルの候補 ------------------------------

/// 位置の情報がある記録を1件作り、`fs-audit.jsonl`を書く（補助は`position_view_tests`・`position_candidates_tests`）。
fn seed_position_record_with_fs(
    ws: &tempfile::TempDir,
    instances: &[harness_policy::process_event::ProcessInstance],
    events: &[harness_policy::FsAuditEvent],
) {
    let (dir, _) =
        crate::position_view::position_view_tests::seed_position_record(ws.path(), "s1", instances);
    crate::position_candidates::position_candidates_tests::write_fs_events(&dir, events);
}

/// **`[x]`の重ねは候補ごとのドメインで引く**（ドメイン欄の名前で引くと、別のドメインの宣言で`[x]`になる）。
/// `pwsh`ドメインが`C:/b/y`を読んでいるとき、`pwsh`の候補は`[x]`、入口のドメインの同じパスの候補は`[ ]`。
#[test]
fn the_declared_mark_follows_each_candidates_domain() {
    use crate::position_candidates::position_candidates_tests::fs_event;
    use crate::position_view::position_view_tests::{user_example, CMD, PWSH};
    use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

    let ws = workspace();
    // 入口のドメインは C:/b/** を読み、pwsh への辺を持つ（pwsh は C:/b/y だけ＝狭める向きなので検査に通る）。
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.fs.read.push("C:/b/**".to_string());
    entry
        .process
        .transitions
        .push(editor_edge(PWSH, ArgvMatcher::Any(AnyMarker), "pwsh"));
    let mut pwsh = PolicyDomain::new("pwsh");
    pwsh.fs.read.push("C:/b/y".to_string());
    let mut file = PolicyFile {
        domains: vec![pwsh, entry],
        ..Default::default()
    };
    file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    crate::policy_file::save(ws.path(), &file).expect("保存");
    seed_position_record_with_fs(
        &ws,
        &user_example(),
        &[fs_event("C:/b/y", Some(1), CMD), fs_event("C:/b/y", Some(2), PWSH)],
    );

    let app = open_edit(&ws);
    let view = app.view.as_ref().expect("view");
    let at = |domain: &str| {
        view.domains
            .iter()
            .position(|d| d.as_deref() == Some(domain))
            .unwrap_or_else(|| panic!("{domain} の候補: {:?}", view.domains))
    };
    assert!(app.candidate_is_on(at("pwsh")), "pwsh の宣言で [x]");
    assert!(
        !app.candidate_is_on(at(ENTRY_DOMAIN)),
        "入口のドメインは C:/b/y そのものを宣言していない"
    );
}

/// **`R`の印はドメインごと**: 2つのドメインが同じフォルダの下を触るとき、入口のドメインのフォルダで`R`を押すと
/// 入口のドメインの合成提案だけが作られる（対の側: pwsh の同じフォルダには付かない）。
#[test]
fn recursive_marks_are_per_domain() {
    use crate::position_candidates::position_candidates_tests::fs_event;
    use crate::position_view::position_view_tests::{user_example, CMD, PWSH};
    use harness_policy::policy_file::ENTRY_DOMAIN;

    let ws = workspace();
    seed_position_record_with_fs(
        &ws,
        &user_example(),
        &[
            fs_event("C:/data/s/d1", Some(1), CMD),
            fs_event("C:/data/s/d2", Some(1), CMD),
            fs_event("C:/data/s/d1", Some(2), PWSH),
            fs_event("C:/data/s/d2", Some(2), PWSH),
        ],
    );
    let mut app = open_edit(&ws);
    app.edit_focus = EditField::Proposals;
    let rows = app.tree.rows(&app.expanded);
    let row = rows
        .iter()
        .position(|r| {
            let node = app.tree.node(r.node);
            node.path == "C:/data/s" && node.domain.as_deref() == Some(ENTRY_DOMAIN)
        })
        .expect("入口のドメインの C:/data/s の行");
    app.selected_row = row;
    app.on_key(key(KeyCode::Char('R')));

    let made: Vec<(Option<String>, String)> = app
        .recursive_proposals()
        .into_iter()
        .map(|(domain, p)| (domain, p.value))
        .collect();
    assert_eq!(
        made,
        vec![(Some(ENTRY_DOMAIN.to_string()), "C:/data/s/**".to_string())],
        "{}",
        app.status
    );
}

/// 候補（値, ドメイン）の id。
fn candidate_id(app: &App, value: &str, domain: &str) -> String {
    let view = app.view.as_ref().expect("view");
    view.proposals
        .iter()
        .zip(&view.domains)
        .find(|(p, d)| p.value == value && d.as_deref() == Some(domain))
        .map(|(p, _)| p.id.clone())
        .expect("その候補")
}

/// **位置ごとのドメインの記録では、FS/ネットのタブの`a`が、ドメインごとのファイルの宣言と観測のタブで選んだ位置の辺を
/// 1つの確認ダイアログにまとめ、`y`で1回に書く**（P4.5。片方だけ書けた状態を作らない）。ダイアログを出しただけでは
/// 何も書かない。台帳には子のドメインの名前で載る。
/// 対の側: 位置の辺を選ばずに子のドメインのファイルを選ぶと、届く辺が無いので何も書かずに理由を言う。
#[test]
fn a_on_the_fs_tab_of_a_position_record_writes_files_and_edges_together() {
    use crate::position_candidates::position_candidates_tests::fs_event;
    use crate::position_view::position_view_tests::{child, root, CMD, PWSH};
    use harness_policy::policy_file::ENTRY_DOMAIN;
    use harness_sandbox::tier2a::policy_approval::DeclarationRef;

    let ws = workspace();
    // 入口のドメイン（cmd）と子の pwsh が同じファイルを読む（子の届く範囲を呼び出し元が覆う＝狭める向き）。
    seed_position_record_with_fs(
        &ws,
        &[root(1, CMD), child(2, 1, PWSH)],
        &[
            fs_event("C:/Users/x/b.txt", Some(1), CMD),
            fs_event("C:/Users/x/b.txt", Some(2), PWSH),
        ],
    );
    let mut app = open_edit(&ws);
    let entry_id = candidate_id(&app, "C:/Users/x/b.txt", ENTRY_DOMAIN);
    let pwsh_id = candidate_id(&app, "C:/Users/x/b.txt", "pwsh");
    app.accepted.insert(entry_id);
    app.accepted.insert(pwsh_id);
    app.edit_focus = EditField::Proposals;

    // 対の側: 位置の辺をまだ選んでいない。
    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("理由のダイアログ");
    assert_eq!(modal.confirm, Confirm::ReadOnly);
    assert!(
        modal.lines.iter().any(|l| l.contains("pwsh") && l.contains("届く辺")),
        "{:?}",
        modal.lines
    );
    assert!(!crate::policy_file::path(ws.path()).exists());
    app.on_key(key(KeyCode::Esc));

    // 観測のタブで pwsh の位置を選び、FS/ネットのタブへ戻って a。
    app.on_key(key(KeyCode::F(2)));
    app.on_key(key(KeyCode::Char(' ')));
    app.on_key(key(KeyCode::F(2)));
    app.on_key(key(KeyCode::F(2)));
    assert!(!app.pending.tab.0.is_transition());
    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("確認ダイアログ");
    assert_eq!(modal.confirm, Confirm::Position, "{:?}", modal.lines);
    assert!(
        modal.lines.iter().any(|l| l.contains("ファイルの宣言: ドメイン pwsh")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("遷移元ドメイン workspace-shell")),
        "{:?}",
        modal.lines
    );
    assert!(!crate::policy_file::path(ws.path()).exists(), "ダイアログを出しただけで書いた");

    app.on_key(key(KeyCode::Char('y')));
    let file = crate::policy_file::load(ws.path()).expect("load");
    assert_eq!(file.domain("pwsh").unwrap().fs.read, vec!["C:/Users/x/b.txt".to_string()]);
    let entry = file.domain(ENTRY_DOMAIN).unwrap();
    assert_eq!(entry.fs.read, vec!["C:/Users/x/b.txt".to_string()]);
    assert_eq!(entry.process.transitions.len(), 1);
    assert_eq!(entry.process.transitions[0].to, "pwsh");
    assert!(crate::approval_store::approval_store().load().is_approved(
        ws.path(),
        DeclarationRef {
            domain: "pwsh",
            value: "C:/Users/x/b.txt",
            access: harness_config::FsAccess::Read,
        },
    ));
    assert!(app.accepted.is_empty(), "書いた予約が残っている");
}

/// **ドメインが1つだけの位置ごとの記録では、木にドメインの段が無いので、`R`の印はそのドメインの合成提案になる**
/// （段が無い木のノードはドメインを持たない。黙って書く先の無い提案にしない）。
#[test]
fn a_recursive_mark_in_a_one_domain_position_record_goes_to_that_domain() {
    use crate::position_candidates::position_candidates_tests::fs_event;
    use crate::position_view::position_view_tests::{child, root, CMD, PWSH};

    let ws = workspace();
    seed_position_record_with_fs(
        &ws,
        &[root(1, CMD), child(2, 1, PWSH)],
        &[
            fs_event("C:/data/s/d1", Some(2), PWSH),
            fs_event("C:/data/s/d2", Some(2), PWSH),
        ],
    );
    let mut app = open_edit(&ws);
    assert!(!app.tree.has_domain_tier());
    app.edit_focus = EditField::Proposals;
    let rows = app.tree.rows(&app.expanded);
    app.selected_row = rows
        .iter()
        .position(|r| app.tree.node(r.node).path == "C:/data/s")
        .expect("C:/data/s の行");
    app.on_key(key(KeyCode::Char('R')));
    let made: Vec<(Option<String>, String)> = app
        .recursive_proposals()
        .into_iter()
        .map(|(domain, p)| (domain, p.value))
        .collect();
    assert_eq!(made, vec![(Some("pwsh".to_string()), "C:/data/s/**".to_string())], "{}", app.status);
}
