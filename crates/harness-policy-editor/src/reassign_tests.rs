//! [`crate::reassign`]のテスト。
//!
//! 守っているのは4つ——(1) **付け替えで承認が生まれない**（未承認の宣言は未承認のまま。決定51の
//! 抜け道にならない）と、承認済みの宣言は承認済みのまま付け替わること、(2) **承認と同じ幅の検査**を
//! 通ること（禁止側と許可側を対にする、B-35）、(3) 元の値の承認が残らないこと、(4) `**`の付け外しと
//! 「広がるか」の判定の真理値表。

use std::path::Path;

use harness_config::FsAccess;
use harness_core::RequireSandbox;
use harness_policy::generalize::SettingsKey;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use super::*;
use crate::policy_file::{PolicyDomain, PolicyFile};

const REGISTRY: &str = "C:/Users/x/.cargo/registry/**";
const SSH: &str = "C:/Users/x/.ssh/**";
const GIT_DB: &str = "C:/Users/x/.cargo/git/db";
const CACHE: &str = "C:/Users/x/.cargo/registry/cache";

fn workspace_with(domain: PolicyDomain) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    crate::policy_file::save(
        dir.path(),
        &PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![domain],
        },
    )
    .expect("save");
    dir
}

fn cargo() -> PolicyDomain {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(REGISTRY.to_string());
    domain.fs.read.push(SSH.to_string());
    domain.fs.read.push(CACHE.to_string());
    domain.fs.read_write.push(GIT_DB.to_string());
    domain.net.allow_domains.push("crates.io".to_string());
    domain
}

fn target(key: SettingsKey, value: &str) -> UnapproveTarget {
    UnapproveTarget {
        domain: "cargo".to_string(),
        key,
        value: value.to_string(),
    }
}

fn reassignment(from: UnapproveTarget, key: SettingsKey, value: &str) -> Reassignment {
    Reassignment {
        from,
        key,
        value: value.to_string(),
    }
}

fn approve(ws: &Path, key: SettingsKey, value: &str) {
    let declaration = DeclarationRef {
        domain: "cargo",
        value,
        key,
    };
    let left = crate::approval_store::approval_store().approve(ws, &[declaration]);
    assert!(left.is_empty(), "the test setup could not approve {value}");
}

fn approved(ws: &Path, access: FsAccess, value: &str) -> bool {
    crate::approval_store::approval_store().load().is_approved(
        ws,
        DeclarationRef {
            domain: "cargo",
            value,
            key: harness_policy::generalize::SettingsKey::from_access(access),
        },
    )
}

fn plan_none(ws: &Path, reassignments: &[Reassignment]) -> ReassignPlan {
    plan(ws, reassignments, RequireSandbox::None, &[]).expect("plan")
}

fn bucket(ws: &Path, access: FsAccess) -> Vec<String> {
    let file = crate::policy_file::load(ws).expect("load");
    file.domain("cargo")
        .expect("cargo domain")
        .fs
        .entries()
        .into_iter()
        .filter(|(_, a)| *a == access)
        .map(|(v, _)| v.to_string())
        .collect()
}

/// **許可側**: 承認済みの宣言を付け替えると、付け替えた後の値が承認済みになり、元の値の承認は消える。
/// `policy.json`では元の行が消えて新しい行が入る（同じドメインの他の宣言はそのまま）。
#[test]
fn an_approved_declaration_stays_approved_under_its_new_access() {
    let ws = workspace_with(cargo());
    approve(ws.path(), SettingsKey::FsRead, REGISTRY);

    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, REGISTRY),
            SettingsKey::FsReadExec,
            REGISTRY,
        )],
    );
    assert_eq!(plan.changes.len(), 1, "{plan:?}");
    assert!(plan.changes[0].carries_approval);
    assert!(plan.changes[0].widens, "read -> read_exec adds execute");
    assert!(
        !approved(ws.path(), FsAccess::ReadExec, REGISTRY),
        "plan writes nothing"
    );

    assert_eq!(commit(ws.path(), &plan).expect("commit"), 1);
    assert!(approved(ws.path(), FsAccess::ReadExec, REGISTRY));
    assert!(
        !approved(ws.path(), FsAccess::Read, REGISTRY),
        "the approval of the value that is gone must not survive"
    );
    assert!(!bucket(ws.path(), FsAccess::Read).contains(&REGISTRY.to_string()));
    assert!(bucket(ws.path(), FsAccess::ReadExec).contains(&REGISTRY.to_string()));
    assert!(
        bucket(ws.path(), FsAccess::Read).contains(&SSH.to_string()),
        "other declarations stay in place"
    );
}

/// **禁止側（決定51）**: 未承認の宣言（リポジトリに同梱されていた等）を付け替えても、付け替えた後の値は
/// **未承認のまま**。同じファイルの他の未承認の宣言も未承認のまま——付け替えで承認は生まれない。
#[test]
fn reassigning_an_unapproved_declaration_does_not_approve_anything() {
    let ws = workspace_with(cargo());
    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, REGISTRY),
            SettingsKey::FsReadExec,
            REGISTRY,
        )],
    );
    assert_eq!(plan.changes.len(), 1, "{plan:?}");
    assert!(!plan.changes[0].carries_approval);
    commit(ws.path(), &plan).expect("commit");

    assert!(
        bucket(ws.path(), FsAccess::ReadExec).contains(&REGISTRY.to_string()),
        "the reassignment itself is written"
    );
    assert!(!approved(ws.path(), FsAccess::ReadExec, REGISTRY));
    assert!(!approved(ws.path(), FsAccess::Read, SSH));
    assert!(crate::approval_store::approval_store()
        .load()
        .approvals
        .is_empty());
}

/// 同じ確定で先に承認する宣言（宣言画面の`y`）は、付け替えた後の値へ承認を引き継ぐ扱いで見せる。
/// 渡さなければ未承認のまま（対で固定する）。
#[test]
fn an_approval_made_in_the_same_commit_is_carried_over() {
    let ws = workspace_with(cargo());
    let from = target(SettingsKey::FsRead, REGISTRY);
    let request = [reassignment(from.clone(), SettingsKey::FsReadExec, REGISTRY)];

    let without = plan(ws.path(), &request, RequireSandbox::None, &[]).expect("plan");
    assert!(!without.changes[0].carries_approval);

    let with = plan(ws.path(), &request, RequireSandbox::None, &[from]).expect("plan");
    assert!(with.changes[0].carries_approval);
}

/// **禁止側（幅の検査）**: `**`の値を書込にする付け替えは`breadth`が断り、何も書かない。
/// **許可側**: 同じ値を`read_exec`にするのは通る。
#[test]
fn the_breadth_check_refuses_a_recursive_write_and_lets_a_recursive_exec_through() {
    let ws = workspace_with(cargo());
    approve(ws.path(), SettingsKey::FsRead, REGISTRY);
    let before = std::fs::read(crate::policy_file::path(ws.path())).expect("read");

    let refused = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, REGISTRY),
            SettingsKey::FsReadWrite,
            REGISTRY,
        )],
    );
    assert!(refused.changes.is_empty(), "{refused:?}");
    assert_eq!(refused.refused.len(), 1);
    assert_eq!(commit(ws.path(), &refused).expect("commit"), 0);
    assert_eq!(
        std::fs::read(crate::policy_file::path(ws.path())).expect("read"),
        before,
        "a refused reassignment must not touch policy.json"
    );
    assert!(approved(ws.path(), FsAccess::Read, REGISTRY), "nor the ledger");

    let allowed = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, REGISTRY),
            SettingsKey::FsReadExec,
            REGISTRY,
        )],
    );
    assert_eq!(allowed.changes.len(), 1, "{allowed:?}");
}

/// **禁止側（幅の検査）**: 書込の宣言に`**`を付けると配下すべてへの書込になるので断る。
/// **許可側**: 読取の宣言に`**`を付けるのは通る（権限が広がる付け替えとして）。
#[test]
fn adding_double_star_is_refused_for_a_write_and_allowed_for_a_read() {
    let ws = workspace_with(cargo());
    let refused = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsReadWrite, GIT_DB),
            SettingsKey::FsReadWrite,
            &format!("{GIT_DB}/**"),
        )],
    );
    assert!(refused.changes.is_empty(), "{refused:?}");
    assert_eq!(refused.refused.len(), 1);

    let allowed = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, CACHE),
            SettingsKey::FsRead,
            &format!("{CACHE}/**"),
        )],
    );
    assert_eq!(allowed.changes.len(), 1, "{allowed:?}");
    assert!(allowed.changes[0].widens);
}

/// **禁止側（`--require-sandbox`）**: 書込への付け替えは`write-containment`と矛盾するので断る。
/// **許可側**: 同じ付け替えでも矛盾しない指定なら通る。
#[test]
fn the_require_sandbox_gate_applies_to_reassignments() {
    let ws = workspace_with(cargo());
    let request = [reassignment(
        target(SettingsKey::FsRead, CACHE),
        SettingsKey::FsReadWrite,
        CACHE,
    )];
    let refused =
        plan(ws.path(), &request, RequireSandbox::WriteContainment, &[]).expect("plan");
    assert!(refused.changes.is_empty(), "{refused:?}");
    assert_eq!(refused.refused.len(), 1);

    let allowed = plan(ws.path(), &request, RequireSandbox::None, &[]).expect("plan");
    assert_eq!(allowed.changes.len(), 1, "{allowed:?}");
}

/// 制御ディレクトリへの付け替えは、承認と同じく断る（承認台帳に残すこと自体を断る値）。
#[test]
fn a_control_directory_value_is_refused() {
    let mut domain = cargo();
    domain.fs.read.push("C:/other/.harness/x".to_string());
    let ws = workspace_with(domain);
    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, "C:/other/.harness/x"),
            SettingsKey::FsReadExec,
            "C:/other/.harness/x",
        )],
    );
    assert!(plan.changes.is_empty(), "{plan:?}");
    assert_eq!(plan.refused.len(), 1);
}

/// 付け替えた先に同じ宣言が既にあるなら断る（同じ設定値の宣言を2行に割らない）。
#[test]
fn a_reassignment_onto_an_existing_declaration_is_refused() {
    let mut domain = cargo();
    domain.fs.read_exec.push(CACHE.to_string());
    let ws = workspace_with(domain);
    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, CACHE),
            SettingsKey::FsReadExec,
            CACHE,
        )],
    );
    assert!(plan.changes.is_empty(), "{plan:?}");
    assert!(plan.refused[0].1.contains("既にあります"), "{plan:?}");
}

/// 2つの付け替えが同じ値へ行き着くなら、後の方を断る（書く順で結果が変わる形を作らない）。
#[test]
fn two_reassignments_onto_the_same_value_are_not_both_written() {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(CACHE.to_string());
    domain.fs.read_write.push(CACHE.to_string());
    let ws = workspace_with(domain);
    let plan = plan_none(
        ws.path(),
        &[
            reassignment(target(SettingsKey::FsRead, CACHE), SettingsKey::FsReadExec, CACHE),
            reassignment(
                target(SettingsKey::FsReadWrite, CACHE),
                SettingsKey::FsReadExec,
                CACHE,
            ),
        ],
    );
    assert_eq!(plan.changes.len(), 1, "{plan:?}");
    assert_eq!(plan.refused.len(), 1, "{plan:?}");
}

/// `policy.json`に無い宣言の付け替えは「無かった」と返す（綴りの間違いはここでしか気付けない）。
/// 指定の大文字小文字が違っても、`policy.json`に書いてある綴りで見つける。
#[test]
fn a_missing_declaration_is_not_found_and_a_case_variant_is_found() {
    let ws = workspace_with(cargo());
    let missing = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsReadExec, REGISTRY),
            SettingsKey::FsRead,
            REGISTRY,
        )],
    );
    assert!(missing.changes.is_empty());
    assert_eq!(missing.not_found.len(), 1);

    let case_variant = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, "c:/users/X/.CARGO/registry/**"),
            SettingsKey::FsReadExec,
            REGISTRY,
        )],
    );
    assert_eq!(case_variant.changes.len(), 1, "{case_variant:?}");
    assert_eq!(case_variant.changes[0].from.value, REGISTRY);
}

/// ネットワークの宣言は付け替えの対象外（理由を返す）。
#[test]
fn a_network_declaration_is_refused() {
    let ws = workspace_with(cargo());
    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::NetAllowDomains, "crates.io"),
            SettingsKey::FsRead,
            "crates.io",
        )],
    );
    assert!(plan.changes.is_empty());
    assert_eq!(plan.refused.len(), 1);
}

/// 狭める付け替え（`**`を外す）も承認を引き継ぎ、「広がる」には数えない。
#[test]
fn narrowing_an_approved_declaration_keeps_it_approved() {
    let ws = workspace_with(cargo());
    approve(ws.path(), SettingsKey::FsRead, REGISTRY);
    let narrowed = toggle_recursive(REGISTRY).expect("a trailing /** can be removed");
    let plan = plan_none(
        ws.path(),
        &[reassignment(
            target(SettingsKey::FsRead, REGISTRY),
            SettingsKey::FsRead,
            &narrowed,
        )],
    );
    assert_eq!(plan.changes.len(), 1, "{plan:?}");
    assert!(!plan.changes[0].widens);
    commit(ws.path(), &plan).expect("commit");
    assert!(approved(ws.path(), FsAccess::Read, &narrowed));
    assert!(!approved(ws.path(), FsAccess::Read, REGISTRY));
}

/// `**`の付け外しの真理値表。付け外しの仕方が決まらない形は`None`。
#[test]
fn toggling_double_star_round_trips_and_refuses_ambiguous_forms() {
    assert_eq!(toggle_recursive("C:/x/y").as_deref(), Some("C:/x/y/**"));
    assert_eq!(toggle_recursive("C:/x/y/**").as_deref(), Some("C:/x/y"));
    assert_eq!(toggle_recursive("C:/x/y/").as_deref(), Some("C:/x/y/**"));
    assert_eq!(toggle_recursive("C:/x/y/**/").as_deref(), Some("C:/x/y"));
    assert_eq!(toggle_recursive(r"C:\x\y").as_deref(), Some(r"C:\x\y\**"));
    assert_eq!(toggle_recursive(r"C:\x\y\**").as_deref(), Some(r"C:\x\y"));
    assert_eq!(toggle_recursive("C:/x/*/bin"), None, "a wildcard in the middle");
    assert_eq!(toggle_recursive("C:/x/a**"), None, "** inside a component");
    assert_eq!(toggle_recursive("**"), None);
    assert_eq!(toggle_recursive(""), None);
}

/// 「権限が広がるか」の真理値表。`read_write`と`read_exec`は互いを含まないので、その間は広がる側。
#[test]
fn widening_follows_the_inclusion_of_accesses_and_the_scope() {
    let read = target(SettingsKey::FsRead, "C:/x");
    let write = target(SettingsKey::FsReadWrite, "C:/x");
    let exec = target(SettingsKey::FsReadExec, "C:/x");
    assert!(widens(&read, SettingsKey::FsReadWrite, "C:/x"));
    assert!(widens(&read, SettingsKey::FsReadExec, "C:/x"));
    assert!(widens(&write, SettingsKey::FsReadExec, "C:/x"));
    assert!(widens(&exec, SettingsKey::FsReadWrite, "C:/x"));
    assert!(!widens(&write, SettingsKey::FsRead, "C:/x"));
    assert!(!widens(&exec, SettingsKey::FsRead, "C:/x"));
    assert!(widens(&read, SettingsKey::FsRead, "C:/x/**"));
    let recursive = target(SettingsKey::FsRead, "C:/x/**");
    assert!(!widens(&recursive, SettingsKey::FsRead, "C:/x"));
}

/// [P5.3、決定66] **遷移先の宣言を付け替えると、そこへの辺が広がり得る**。広がる辺は確定の明細の材料
/// （[`ReassignPlan::widening`]）に出る。対の側: 付け替えても遷移元が覆う範囲に収まるなら材料は空。
#[test]
fn reassigning_a_declaration_of_the_destination_shows_the_edge_it_widens() {
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

    let mut shell = PolicyDomain::new("shell");
    shell.fs.read.push(REGISTRY.to_string());
    shell.process.transitions.push(editor_edge(
        "C:/Users/x/tools/cargo.exe",
        ArgvMatcher::Any(AnyMarker),
        "cargo",
    ));
    let dir = tempfile::tempdir().expect("tempdir");
    crate::policy_file::save(
        dir.path(),
        &PolicyFile {
            schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
            domains: vec![cargo_without_widening(), shell],
        },
    )
    .expect("save");

    // CACHE（REGISTRY の配下）を REGISTRY の外のファイルへ付け替える: shell はそれを持たないので、shell → cargo が広がる。
    let widened = plan_none(
        dir.path(),
        &[reassignment(target(SettingsKey::FsRead, CACHE), SettingsKey::FsRead, OUTSIDE)],
    );
    assert_eq!(widened.widening.edges.len(), 1, "{:?}", widened.widening);
    assert_eq!(widened.widening.edges[0].from, "shell");
    assert_eq!(
        widened.widening.edges[0].newly_usable.fs,
        vec![(OUTSIDE.to_string(), "read")]
    );

    // 対: CACHE を REGISTRY の配下の別の場所へ付け替えるだけなら、shell が覆うので広がらない。
    let inside = plan_none(
        dir.path(),
        &[reassignment(
            target(SettingsKey::FsRead, CACHE),
            SettingsKey::FsRead,
            "C:/Users/x/.cargo/registry/index",
        )],
    );
    assert!(inside.widening.is_empty(), "{:?}", inside.widening);
}

/// `shell`の宣言（`REGISTRY`）の外にあるファイル。
const OUTSIDE: &str = "C:/Users/x/data/report.txt";

/// `shell`の宣言（`REGISTRY`）に覆われる宣言だけを持つ`cargo`（`shell → cargo`は狭める向き）。
fn cargo_without_widening() -> PolicyDomain {
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(CACHE.to_string());
    domain
}
