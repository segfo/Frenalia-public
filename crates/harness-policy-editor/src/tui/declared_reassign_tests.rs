//! 宣言画面の付け替え（`c`・`R`）のテスト。
//!
//! 守っているのは5つ——(1) **`c`→`a`→確認の`y`で書かれ、確認の画面を出した時点では何も書いていない**、
//! (2) **1行ずつしか付け替えられない**（ディレクトリの行・宣言が複数ある行では何も予約せず理由を言う。
//! 決定51）、(3) 承認と同じ検査で断られる値は**押した時点で**断る（`c`は飛ばして次の種類へ進む）、
//! (4) 取り消しと付け替えを同じ宣言に予約したら**取り消しが勝つ**、(5) `y`と`c`を同じ行に予約したら
//! 承認が付け替えた後の値へ引き継がれる。

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_config::FsAccess;
use harness_policy::generalize::SettingsKey;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use crate::policy_file::{PolicyDomain, PolicyFile};
use crate::tui::state::{App, Confirm, Screen};
use crate::unapprove::UnapproveTarget;

const REGISTRY: &str = "C:/Users/x/.cargo/registry/**";
const SSH: &str = "C:/Users/x/.ssh/**";

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// `domain`だけが入ったworkspaceで、宣言画面を開いた状態。
fn declared_screen_with(domain: PolicyDomain) -> (tempfile::TempDir, App) {
    let ws = tempfile::tempdir().expect("tempdir");
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

/// 宣言が1件だけ（木の行も1行）のworkspace。
fn one_declaration() -> PolicyDomain {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(REGISTRY.to_string());
    domain
}

fn registry() -> UnapproveTarget {
    UnapproveTarget {
        domain: "cargo".to_string(),
        key: SettingsKey::FsRead,
        value: REGISTRY.to_string(),
    }
}

fn approved(ws: &tempfile::TempDir, access: FsAccess, value: &str) -> bool {
    crate::approval_store::approval_store().load().is_approved(
        ws.path(),
        DeclarationRef {
            domain: "cargo",
            value,
            access,
        },
    )
}

fn approve_on_this_machine(ws: &tempfile::TempDir, access: FsAccess, value: &str) {
    let left = crate::approval_store::approval_store().approve(
        ws.path(),
        &[DeclarationRef {
            domain: "cargo",
            value,
            access,
        }],
    );
    assert!(left.is_empty());
}

fn declared_access(ws: &tempfile::TempDir, value: &str) -> Vec<FsAccess> {
    crate::policy_file::load(ws.path())
        .expect("load")
        .domain("cargo")
        .expect("cargo")
        .fs
        .entries()
        .into_iter()
        .filter(|(v, _)| *v == value)
        .map(|(_, access)| access)
        .collect()
}

/// `c`で予約し、`a`で確認の画面を出し、そこで`y`を押すと書かれる。確認の画面を出した時点では
/// **まだ書いていない**（対で固定する）。同梱された（未承認の）宣言なので、付け替えた後も未承認。
#[test]
fn c_then_a_then_y_writes_the_reassignment_and_nothing_before_the_confirmation() {
    let (ws, mut app) = declared_screen_with(one_declaration());

    app.on_key(key(KeyCode::Char('c')));
    assert_eq!(
        app.declared_reassign.reserved.get(&registry()),
        // `**`＋書込は幅の検査で断られるので、`read_write`を飛ばして`read_exec`になる。
        Some(&(SettingsKey::FsReadExec, REGISTRY.to_string())),
        "{}",
        app.status
    );
    assert!(app.status.contains("飛ばした種類"), "{}", app.status);

    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("a confirmation dialog");
    assert_eq!(modal.confirm, Confirm::DeclaredChanges);
    assert!(
        modal.lines.iter().any(|l| l.contains("付け替える宣言 1件")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("未承認のまま付け替えます")),
        "{:?}",
        modal.lines
    );
    assert_eq!(
        declared_access(&ws, REGISTRY),
        vec![FsAccess::Read],
        "nothing is written before the dialog is confirmed"
    );

    app.on_key(key(KeyCode::Char('y')));
    assert_eq!(declared_access(&ws, REGISTRY), vec![FsAccess::ReadExec], "{}", app.status);
    assert!(app.declared_reassign.reserved.is_empty());
    assert!(
        !approved(&ws, FsAccess::ReadExec, REGISTRY),
        "reassigning does not approve a shipped declaration"
    );
    assert!(app
        .declared_approval
        .not_approved
        .iter()
        .any(|t| t.key == SettingsKey::FsReadExec && t.value == REGISTRY));
}

/// 承認済みの宣言は、付け替えた後も承認済み（確認の画面もそう言う）。
#[test]
fn an_approved_declaration_is_reassigned_with_its_approval() {
    let (ws, mut app) = declared_screen_with(one_declaration());
    approve_on_this_machine(&ws, FsAccess::Read, REGISTRY);
    app.on_key(key(KeyCode::Char('r')));
    assert!(app.declared_approval.not_approved.is_empty());

    app.on_key(key(KeyCode::Char('R')));
    let narrowed = "C:/Users/x/.cargo/registry";
    assert_eq!(
        app.declared_reassign.reserved.get(&registry()),
        Some(&(SettingsKey::FsRead, narrowed.to_string())),
        "{}",
        app.status
    );
    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("a confirmation dialog");
    assert!(
        modal.lines.iter().any(|l| l.contains("このマシンで承認済みのまま")),
        "{:?}",
        modal.lines
    );
    assert!(
        modal.lines.iter().any(|l| l.contains("harness fs revoke")),
        "removing ** must explain that the inherited ACEs stay: {:?}",
        modal.lines
    );
    app.on_key(key(KeyCode::Char('y')));

    assert!(approved(&ws, FsAccess::Read, narrowed), "{}", app.status);
    assert!(!approved(&ws, FsAccess::Read, REGISTRY));
}

/// **まとめて付け替えるキーは無い（決定51）。** ディレクトリの行で`c`・`R`を押しても何も予約せず、
/// 理由を言う。宣言の行（許可側）なら予約できる。
#[test]
fn c_and_r_on_a_directory_row_reserve_nothing_and_explain_why() {
    let mut domain = one_declaration();
    domain.fs.read.push(SSH.to_string());
    let (_ws, mut app) = declared_screen_with(domain);
    // 行0は2つの宣言の共通の親（`C:/Users/x`）。
    assert!(app.declared_tree.node(app.declared_tree.rows(&app.declared_expanded)[0].node)
        .proposals
        .is_empty());

    app.on_key(key(KeyCode::Char('c')));
    assert!(app.declared_reassign.reserved.is_empty());
    assert!(app.status.contains("ディレクトリの行"), "{}", app.status);
    app.on_key(key(KeyCode::Char('R')));
    assert!(app.declared_reassign.reserved.is_empty());

    app.on_key(key(KeyCode::Down));
    app.on_key(key(KeyCode::Char('c')));
    assert_eq!(app.declared_reassign.reserved.len(), 1, "{}", app.status);
}

/// 同じパスに宣言が2件ある行（同じ値の`read`と`read_exec`）では、どれを付け替えるか選べないので断る。
#[test]
fn a_row_with_two_declarations_cannot_be_reassigned() {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/x/bin/tool.exe".to_string());
    domain.fs.read_exec.push("C:/Users/x/bin/tool.exe".to_string());
    let (_ws, mut app) = declared_screen_with(domain);
    app.on_key(key(KeyCode::Char('c')));
    assert!(app.declared_reassign.reserved.is_empty());
    assert!(app.status.contains("2件"), "{}", app.status);
}

/// `c`を押し続けると元の種類に戻り、そのとき予約は消える（戻ったのに予約が残ると、何も変えない
/// 書込を確定してしまう）。
#[test]
fn cycling_back_to_the_original_access_drops_the_reservation() {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/x/bin/tool.exe".to_string());
    let (_ws, mut app) = declared_screen_with(domain);
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char('c')));
    assert_eq!(app.declared_reassign.reserved.len(), 1, "{}", app.status);
    app.on_key(key(KeyCode::Char('c')));
    assert!(app.declared_reassign.reserved.is_empty(), "{}", app.status);
}

/// 承認と同じ検査で断られる値は、**押した時点で**断る（予約しない）。書込の宣言に`**`を付けると
/// 配下すべてへの書込になるので断られる。
#[test]
fn r_refuses_a_recursive_write_at_the_key_press() {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read_write.push("C:/Users/x/.cargo/git/db".to_string());
    let (_ws, mut app) = declared_screen_with(domain);
    app.on_key(key(KeyCode::Char('R')));
    assert!(app.declared_reassign.reserved.is_empty());
    assert!(app.status.contains("にはできません"), "{}", app.status);
}

/// **同じ宣言を取り消しと付け替えの両方で予約したら、取り消しが勝つ。** 宣言は消え、付け替えた後の
/// 値も書かれない。取り消しを予約した行では、そもそも`c`を受け付けない。
#[test]
fn removing_wins_over_reassigning_the_same_declaration() {
    let (ws, mut app) = declared_screen_with(one_declaration());
    app.on_key(key(KeyCode::Char('c')));
    assert_eq!(app.declared_reassign.reserved.len(), 1);
    app.on_key(key(KeyCode::Char(' ')));
    assert!(app.unapproved.contains(&registry()));

    app.on_key(key(KeyCode::Char('c')));
    assert!(app.status.contains("取り消しを予約中"), "{}", app.status);

    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("a confirmation dialog");
    assert!(
        !modal.lines.iter().any(|l| l.contains("付け替える宣言")),
        "a reassignment that will not be written must not be shown: {:?}",
        modal.lines
    );
    app.on_key(key(KeyCode::Char('y')));
    assert!(declared_access(&ws, REGISTRY).is_empty(), "{}", app.status);
    assert!(
        crate::policy_file::load(ws.path())
            .expect("load")
            .domain("cargo")
            .is_some_and(|d| d.fs.is_empty()),
        "the reassigned value must not be written either"
    );
}

/// `y`（このマシンで承認）と`c`を同じ行に予約したら、承認してから付け替えるので、付け替えた後の値が
/// 承認済みになる（確認の画面の時点でもそう見せる）。
#[test]
fn approving_and_reassigning_the_same_row_carries_the_new_approval() {
    let (ws, mut app) = declared_screen_with(one_declaration());
    app.on_key(key(KeyCode::Char('y')));
    app.on_key(key(KeyCode::Char('c')));
    app.on_key(key(KeyCode::Char('a')));
    let modal = app.modal.as_ref().expect("a confirmation dialog");
    assert!(
        modal.lines.iter().any(|l| l.contains("このマシンで承認済みのまま")),
        "{:?}",
        modal.lines
    );
    app.on_key(key(KeyCode::Char('y')));
    assert!(approved(&ws, FsAccess::ReadExec, REGISTRY), "{}", app.status);
    assert!(!approved(&ws, FsAccess::Read, REGISTRY));
}

/// [P5.3、決定66] **付け替えで遷移が広がるなら、確認に「広がる遷移」が出る**（`reassign_lines`が明細の材料
/// ＝`ReassignPlan::widening`を並べる。材料の計算は`reassign_tests`が固定する）。
#[test]
fn reassign_lines_list_the_transitions_a_reassignment_widens() {
    use crate::exposure_view::{WidenedEdge, Widening};
    use harness_policy::transition_listing::Rights;

    let plan = crate::reassign::ReassignPlan {
        widening: Widening {
            edges: vec![WidenedEdge {
                from: "shell".to_string(),
                exe: "C:/Users/x/tools/cargo.exe".to_string(),
                to: "cargo".to_string(),
                newly_usable: Rights {
                    fs: vec![(SSH.to_string(), "read")],
                    net: Vec::new(),
                },
                output: harness_policy::transition::ChildOutput::Return,
            }],
            uncounted: None,
        },
        ..Default::default()
    };
    let text = super::reassign_lines(&plan).join("\n");
    assert!(text.contains("広がる遷移 1本"), "{text}");
    assert!(text.contains("shell → cargo"), "{text}");
    assert!(
        !super::reassign_lines(&crate::reassign::ReassignPlan::default())
            .iter()
            .any(|l| l.contains("広がる遷移")),
        "広がらない付け替えでは出さない"
    );
}
