//! パス2の記録の候補を、拒否を起こしたドメインごとに承認待ちで確定する試験（P6.6。`plans/POLICY-EDITOR-TOMOYO-DIG.md`
//! 決定68の前例の(1)(7)）。
//!
//! 端末は要らない（状態は`App`）。記録は一時ディレクトリに作り、`fs-audit.jsonl`（通し番号つきの拒否）・`spawn-audit.jsonl`
//! （Daemon が書く許可した生成の記録）・`net-audit.jsonl`を実際に書く（補助は`position_candidates_tests`と共有する）。
//! パス2の記録には位置の木が無い（`current_positions()`が`None`）ので、確定は辺を持たずファイルと通信の宣言だけになる。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

use crate::position_candidates::position_candidates_tests::{
    denial, seed_pass2_record, spawn_audit_text, spawned, write_fs_events, POWERSHELL,
};
use crate::position_view::position_view_tests::workspace;
use crate::tui::state::{App, Confirm, Screen};

/// 子のドメイン（入口が`powershell.exe`で遷移する先）。
pub(crate) const CHILD: &str = "p6-child";

pub(crate) fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

/// 入口が`powershell.exe`で`p6-child`へ遷移する`policy.json`と、そのパス2の記録（入口の子 seq 10 が`C:/a/entry.txt`、
/// `p6-child`の子 seq 11 が`C:/b/child.txt`で断られ、`crates.io`へ繋いだ）を作り、承認待ち（`F2`）を開く。
pub(crate) fn open_pass2(ws: &std::path::Path) -> App {
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(editor_edge(POWERSHELL, ArgvMatcher::Any(AnyMarker), CHILD));
    policy_file::save(
        ws,
        &PolicyFile {
            schema_version: policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![entry, PolicyDomain::new(CHILD)],
        },
    )
    .expect("policy.json");
    let audit = spawn_audit_text(&[spawned(Some(10), ENTRY_DOMAIN), spawned(Some(11), CHILD)]);
    let (dir, _) = seed_pass2_record(ws, "p2", Some(&audit));
    write_fs_events(
        &dir,
        &[denial("C:/a/entry.txt", Some(10)), denial("C:/b/child.txt", Some(11))],
    );
    std::fs::write(
        dir.net_audit_log_path(),
        "{\"source\":\"proxy\",\"host\":\"crates.io\",\"allowed\":true,\"reason\":\"record_all\",\"timestamp_unix_ms\":1}\n",
    )
    .expect("net audit log");
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    assert_eq!(app.screen, Screen::Edit);
    app.edit_focus = crate::tui::state::EditField::Proposals;
    let all = app.tree.paths_at_depth(16);
    app.expanded.extend(all);
    app
}

/// 候補の木で、ドメイン`domain`の値`value`の行を選んで`Space`を押す。
pub(crate) fn select(app: &mut App, domain: &str, value: &str) {
    let view = app.view.as_ref().expect("候補");
    let index = view
        .proposals
        .iter()
        .zip(&view.domains)
        .position(|(p, d)| d.as_deref() == Some(domain) && p.value == value)
        .unwrap_or_else(|| panic!("候補が無い: [{domain}] {value}: {:?}", view.domains));
    let id = view.proposals[index].id.clone();
    let row = app
        .tree
        .rows(&app.expanded)
        .iter()
        .position(|row| app.tree.node(row.node).proposals.contains(&index))
        .unwrap_or_else(|| panic!("[{domain}] {value} の行が木に無い"));
    app.selected_row = row;
    press(app, KeyCode::Char(' '));
    assert!(app.accepted.contains(&id), "選べていない: {}", app.status);
}

/// **パス2の拒否を画面で選んで確定すると、断られたドメインへ書かれる**（決定68の前例の(1)）。`a`は位置の記録と同じ1回の確定
/// （`Confirm::Position`）へ進み、位置の木が無くても最後まで通る。通信の候補は同じ確定で入口へ（ドメインごとの通信は P7）。
/// 対の側: 選ばなかった入口の拒否はどこにも書かれず、子の拒否は入口へ書かれない。
#[test]
fn approving_a_pass2_denial_writes_it_to_the_domain_that_was_denied() {
    let ws = workspace();
    let mut app = open_pass2(ws.path());
    assert!(app.current_positions().is_none(), "パス2の記録に位置の木は無い");
    assert!(app.is_position_record(), "ドメインごとに分けた記録として扱う");
    select(&mut app, CHILD, "C:/b/child.txt");
    select(&mut app, ENTRY_DOMAIN, "crates.io");
    press(&mut app, KeyCode::Char('a'));
    let modal = app.modal.as_ref().unwrap_or_else(|| panic!("確認ダイアログが出ない: {}", app.status));
    assert_eq!(modal.confirm, Confirm::Position);
    press(&mut app, KeyCode::Char('y'));
    assert!(app.modal.is_none());

    let file = policy_file::load(ws.path()).expect("policy.json");
    let child = file.domain(CHILD).expect("子のドメイン");
    assert_eq!(child.fs.read, vec!["C:/b/child.txt".to_string()], "{}", app.status);
    assert!(child.net.allow_domains.is_empty(), "{:?}", child.net.allow_domains);
    let entry = file.domain(ENTRY_DOMAIN).expect("入口");
    assert_eq!(entry.net.allow_domains, vec!["crates.io".to_string()]);
    assert!(entry.fs.read.is_empty(), "選ばなかった入口の拒否・子の拒否が入口に入った: {:?}", entry.fs.read);
    assert_eq!(entry.process.transitions.len(), 1, "辺は増えない");
}
