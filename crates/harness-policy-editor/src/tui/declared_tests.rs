//! 宣言画面の「このマシンでの承認」（D-112、`y`）のテスト。
//!
//! 守っているのは3つ——**未承認の宣言が行に見える**こと、**`y`→`a`→確認の`y`で台帳へ記録される**こと、
//! そして**同じ宣言を承認と取り消しの両方で予約したら、取り消しが勝つ**（権限を減らす側が後）こと。

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_policy::generalize::SettingsKey;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use crate::policy_file::{PolicyDomain, PolicyFile};
use crate::tui::state::{App, Confirm, Screen};
use crate::unapprove::UnapproveTarget;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// リポジトリに同梱されていた宣言が1件だけ入ったworkspaceで、宣言画面を開いた状態。
fn declared_screen_with_a_shipped_declaration() -> (tempfile::TempDir, App) {
    let ws = tempfile::tempdir().expect("tempdir");
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/x/.cargo/registry/**".to_string());
    crate::policy_file::save(
        ws.path(),
        &PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![domain],
        },
    )
    .expect("save");
    let mut app = App::new(PathBuf::from(ws.path()), harness_core::RequireSandbox::None);
    app.on_key(key(KeyCode::F(3)));
    assert_eq!(app.screen, Screen::Declared);
    (ws, app)
}

fn shipped_target() -> UnapproveTarget {
    UnapproveTarget {
        domain: "cargo".to_string(),
        key: SettingsKey::FsRead,
        value: "C:/Users/x/.cargo/registry/**".to_string(),
    }
}

fn is_approved(ws: &tempfile::TempDir) -> bool {
    crate::approval_store::approval_store().load().is_approved(
        ws.path(),
        DeclarationRef {
            domain: "cargo",
            value: "C:/Users/x/.cargo/registry/**",
            access: harness_config::FsAccess::Read,
        },
    )
}

/// 同梱された宣言は「このマシンで未承認」として数えられる。
#[test]
fn a_shipped_declaration_is_listed_as_not_approved_on_this_machine() {
    let (_ws, app) = declared_screen_with_a_shipped_declaration();
    assert!(app
        .declared_approval
        .not_approved
        .contains(&shipped_target()));
}

/// `y`で予約し、`a`で確認の画面を出し、そこで`y`を押すと**台帳へ記録される**。
/// 確認の画面を出した時点では**まだ書いていない**（対で固定する）。
#[test]
fn reserving_with_y_and_confirming_records_the_approval() {
    let (ws, mut app) = declared_screen_with_a_shipped_declaration();

    app.on_key(key(KeyCode::Char('y')));
    assert!(app.declared_approval.reserved.contains(&shipped_target()), "{}", app.status);

    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("a confirmation dialog");
    assert_eq!(modal.confirm, Confirm::DeclaredChanges);
    assert!(
        modal.lines.iter().any(|l| l.contains("このマシンで承認する宣言 1件")),
        "{:?}",
        modal.lines
    );
    assert!(!is_approved(&ws), "nothing is written before the dialog is confirmed");

    app.on_key(key(KeyCode::Char('y')));
    assert!(is_approved(&ws), "{}", app.status);
    assert!(app.declared_approval.not_approved.is_empty());
    assert!(app.declared_approval.reserved.is_empty());
}

/// 未承認の宣言が無い配下で`y`を押しても何も予約せず、**理由を言う**（B-32）。
#[test]
fn y_on_a_subtree_without_unapproved_declarations_explains_itself() {
    let (_ws, mut app) = declared_screen_with_a_shipped_declaration();
    app.on_key(key(KeyCode::Char('y')));
    app.on_key(key(KeyCode::Char('a')));
    app.on_key(key(KeyCode::Char('y')));
    assert!(app.declared_approval.not_approved.is_empty());

    app.on_key(key(KeyCode::Char('y')));
    assert!(app.declared_approval.reserved.is_empty());
    assert!(app.status.contains("未承認の宣言はありません"), "{}", app.status);
}

/// **同じ宣言を承認と取り消しの両方で予約したら、取り消しが勝つ。** 宣言は`policy.json`から消え、
/// 承認も残らない（承認を先に書き、取り消しが承認も消すので）。
#[test]
fn reserving_the_same_declaration_for_both_ends_with_it_removed() {
    let (ws, mut app) = declared_screen_with_a_shipped_declaration();
    app.on_key(key(KeyCode::Char('y')));
    app.on_key(key(KeyCode::Char(' ')));
    assert!(app.unapproved.contains(&shipped_target()));
    assert!(app.declared_approval.reserved.contains(&shipped_target()));

    app.on_key(key(KeyCode::Char('a')));
    app.on_key(key(KeyCode::Char('y')));

    let saved = crate::policy_file::load(ws.path()).expect("load");
    assert!(
        saved.domain("cargo").is_some_and(|d| d.fs.read.is_empty()),
        "the declaration is removed"
    );
    assert!(!is_approved(&ws), "and its approval does not survive");
}

/// [P5.3、決定66] **遷移元から宣言を取り消すと、その遷移元から出る辺が広がり得る**（遷移先の届く範囲から差し引く
/// 「遷移元が自分で宣言している権限」が減る）。確認の画面に広がる遷移と、呼び出し元が子を通して使えるようになる
/// 権限が出る。対の側: 遷移先の宣言を取り消しても広がらないので出ない。
#[test]
fn unapproving_from_a_transition_source_lists_the_widened_edge() {
    use harness_policy::policy_file::ENTRY_DOMAIN;
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

    let ws = tempfile::tempdir().expect("tempdir");
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.fs.read.push("C:/Users/x/proj/**".to_string());
    entry.process.transitions.push(editor_edge(
        "C:/Users/x/tools/tool.exe",
        ArgvMatcher::Any(AnyMarker),
        "tool",
    ));
    let mut tool = PolicyDomain::new("tool");
    tool.fs.read.push("C:/Users/x/proj/a.txt".to_string());
    crate::policy_file::save(
        ws.path(),
        &PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![tool, entry],
        },
    )
    .expect("save");
    let target = |domain: &str, value: &str| UnapproveTarget {
        domain: domain.to_string(),
        key: SettingsKey::FsRead,
        value: value.to_string(),
    };

    let mut app = App::new(PathBuf::from(ws.path()), harness_core::RequireSandbox::None);
    app.on_key(key(KeyCode::F(3)));
    app.unapproved.insert(target(ENTRY_DOMAIN, "C:/Users/x/proj/**"));
    app.on_key(key(KeyCode::Char('a')));
    let text = app.modal.as_ref().expect("a confirmation dialog").lines.join("\n");
    assert!(text.contains("広がる遷移 1本"), "{text}");
    assert!(text.contains("C:/Users/x/proj/a.txt"), "{text}");

    app.modal = None;
    app.unapproved.clear();
    app.unapproved.insert(target("tool", "C:/Users/x/proj/a.txt"));
    app.on_key(key(KeyCode::Char('a')));
    let text = app.modal.as_ref().expect("a confirmation dialog").lines.join("\n");
    assert!(!text.contains("広がる遷移"), "{text}");
}
