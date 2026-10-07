//! [`super`]（`policy.json`のファイル宣言から付ける許可を決め、結果を一覧ごとに振り分ける）のテスト。
//!
//! 守っているのは3つ——**入口の子に他ドメインの宛先が渡らない**こと、**書込の印が他の一覧へ移らない**
//! こと、**付与する範囲の条件（遷移先・通信なし・強制有効）**。どれも禁止側と許可側を対にする（`B-35`）。

use harness_policy::transition::ChildOutput;
use std::path::{Path, PathBuf};

use harness_core::GrantedPassthrough;
use harness_policy::normalize::GrantScope;
use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};
use crate::tier2a::policy_approval::DeclarationRef;
use crate::tier2a::policy_grants::GrantContext;
use crate::{FsAccess, FsPassthrough, WorkspaceWriteMode};

use super::*;

fn ctx() -> GrantContext {
    GrantContext::with_harness_user_dir(
        Path::new(r"C:\ws"),
        Some(Path::new("C:/Users/test/AppData/Roaming/harness")),
    )
}

fn all_approved(_: DeclarationRef<'_>) -> bool {
    true
}

fn edge_to(to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal("C:/bin/tool.exe".to_string()),
        argv: ArgvMatcher::Any(AnyMarker),
        cwd: None,
        to: to.to_string(),
        env: None,
        output: ChildOutput::Return,
    }
}

/// 入口（`C:/entry/**`を読む）と、入口から遷移する`cargo`（`C:/cargo/**`を読み書き）と、
/// どこからも遷移されない`npm`（`C:/npm/**`を読む）の3ドメイン。
fn three_domains() -> PolicyFile {
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.fs.read.push("C:/entry/**".to_string());
    entry.process.transitions = vec![edge_to("cargo")];
    let mut cargo = PolicyDomain::new("cargo");
    cargo.fs.read_write.push("C:/cargo/db".to_string());
    let mut npm = PolicyDomain::new("npm");
    npm.fs.read.push("C:/npm/**".to_string());
    PolicyFile {
        domains: vec![entry, cargo, npm],
        ..PolicyFile::default()
    }
}

fn paths(list: &[FsPassthrough]) -> Vec<String> {
    list.iter()
        .map(|fp| fp.path.to_string_lossy().replace('\\', "/"))
        .collect()
}

/// 入口ドメインの宣言は入口の一覧へ、遷移先の宣言は**そのドメインの一覧へだけ**入る。
/// 遷移先でない`npm`には付けない（使われないので、起動のたびに払う理由が無い）。
#[test]
fn the_entry_and_each_target_domain_get_their_own_lists() {
    let plan = plan(&three_domains(), &ctx(), &all_approved, true);
    assert_eq!(paths(&plan.entry), vec!["C:/entry"]);
    assert_eq!(plan.domains.len(), 1);
    assert_eq!(plan.domains[0].0, "cargo");
    assert_eq!(paths(&plan.domains[0].1), vec!["C:/cargo/db"]);
}

/// **自動撤収の宣言集合は全ドメインから作る**（遷移先でない`npm`も、強制が無効なときの`cargo`も）。
/// 付与する範囲の条件で付けなかった回に「もう宣言されていない」と数えると、次の回に付け直しになる。
#[test]
fn the_revoke_set_counts_every_approved_declaration_regardless_of_the_grant_scope() {
    let plan = plan(&three_domains(), &ctx(), &all_approved, false);
    let mut roots: Vec<String> = plan
        .declared_roots
        .iter()
        .map(|r| r.replace('\\', "/"))
        .collect();
    roots.sort();
    assert_eq!(roots, vec!["C:/cargo/db", "C:/entry", "C:/npm"]);
}

/// **遷移の強制が無効なら、遷移先ドメインの宣言には付けない**（子は自分で生成でき、Daemon経由の
/// 遷移が起きない）。理由は値で返る。
#[test]
fn without_enforced_transitions_target_domains_are_not_granted() {
    let plan = plan(&three_domains(), &ctx(), &all_approved, false);
    assert!(plan.domains.is_empty());
    assert_eq!(plan.not_granted_domains.len(), 1);
    assert_eq!(plan.not_granted_domains[0].0, "cargo");
    assert!(plan.not_granted_domains[0].1.contains("--enforce-transitions"));
    assert_eq!(paths(&plan.entry), vec!["C:/entry"], "the entry is granted regardless");
}

/// **対の側**: ファイル宣言を1件も持たない遷移先は、強制が無効でも今までどおり用意の対象に残る
/// （付ける費用が無いので、強制の有無で断る理由が無い）。ここを落とすと、宣言の無いドメインへの
/// 遷移が既定の起動で黙って用意されなくなる。
#[test]
fn a_target_domain_without_file_declarations_stays_provisionable_without_enforcement() {
    let mut policy = three_domains();
    policy
        .domains
        .iter_mut()
        .find(|d| d.name == "cargo")
        .unwrap()
        .fs = Default::default();
    let plan = plan(&policy, &ctx(), &all_approved, false);
    assert!(plan.not_granted_domains.is_empty(), "{:?}", plan.not_granted_domains);
    assert_eq!(plan.domains.len(), 1);
    assert_eq!(plan.domains[0].0, "cargo");
    assert!(plan.domains[0].1.is_empty());
}

/// 通信を宣言している遷移先ドメインには付けない（用意を断るので付けても使われない）。
#[test]
fn a_target_domain_that_declares_network_is_not_granted() {
    let mut policy = three_domains();
    policy
        .domains
        .iter_mut()
        .find(|d| d.name == "cargo")
        .unwrap()
        .net
        .allow_domains
        .push("crates.io".to_string());
    let plan = plan(&policy, &ctx(), &all_approved, true);
    assert!(plan.domains.is_empty());
    assert!(plan.not_granted_domains[0].1.contains("network"));
}

/// [D-112] **未承認の宣言は付けない。** 入口の分は理由ごと返り、遷移先は**1件でも付けない宣言が
/// あればドメインごと付けない**（付いた分だけで用意すると、確かめたより狭い権限で黙って動く）。
#[test]
fn unapproved_declarations_are_not_granted() {
    let only_entry = |d: DeclarationRef<'_>| d.domain == ENTRY_DOMAIN;
    let partly = plan(&three_domains(), &ctx(), &only_entry, true);
    assert_eq!(paths(&partly.entry), vec!["C:/entry"]);
    assert!(partly.domains.is_empty());
    assert!(
        partly.not_granted_domains[0].1.contains("not approved on this machine"),
        "{:?}",
        partly.not_granted_domains
    );

    let nothing = |_: DeclarationRef<'_>| false;
    let none = plan(&three_domains(), &ctx(), &nothing, true);
    assert!(none.entry.is_empty());
    assert_eq!(none.entry_skipped.len(), 1);
    assert!(none.declared_roots.is_empty(), "unapproved declarations are not 'declared'");
}

fn fp(path: &str, access: FsAccess) -> FsPassthrough {
    FsPassthrough {
        path: PathBuf::from(path),
        access,
        forced: false,
        scope: GrantScope::Recursive,
    }
}

fn granted(path: &str, writable: bool, sid: &str, access: &str) -> GrantedPassthrough {
    GrantedPassthrough {
        path: PathBuf::from(path),
        writable,
        subject_sid: sid.to_string(),
        used_restore_privilege: false,
        granted_access: access.to_string(),
    }
}

/// **同じパスに別の級が付いていても、一覧ごとに自分の級の宛先だけを受け取る。**
/// 入口が`read`、`cargo`が`read_write`で同じパスを宣言したとき、入口に`read_write`の宛先が渡ると
/// 入口の子が書ける（＝広がる）。
#[test]
fn each_list_receives_only_the_grant_of_its_own_access_class() {
    let results = vec![
        granted(r"C:\data", false, "S-READ", "read"),
        granted(r"C:\data", true, "S-RW", "read_write"),
    ];
    let (entry, missing) = granted_for(
        &[fp("C:/data", FsAccess::Read)],
        &results,
        &WorkspaceWriteMode::DirectRw,
    );
    assert!(missing.is_empty());
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].subject_sid, "S-READ");

    let (cargo, _) = granted_for(
        &[fp("C:/data", FsAccess::ReadWrite)],
        &results,
        &WorkspaceWriteMode::DirectRw,
    );
    assert_eq!(cargo[0].subject_sid, "S-RW");
}

/// **CoWでは書込の要求が読取へ下がって同じ宛先になる。それでも書込の印は一覧ごとに自分の要求のまま。**
/// まとめた結果（`writable=true`）をそのまま入口へ渡すと、読取しか宣言していない入口が
/// CoWの書込誘導の対象になる。
#[test]
fn the_writable_mark_is_rebuilt_per_list_under_cow() {
    let cow = WorkspaceWriteMode::Cow {
        diff_layer_dir: PathBuf::from(r"C:\diff"),
    };
    // 付与処理はCoWで(read_write→read)と(read)を1行に畳み、書込の要求をORで持つ。
    let results = vec![granted(r"C:\data", true, "S-READ", "read")];

    let (entry, _) = granted_for(&[fp("C:/data", FsAccess::Read)], &results, &cow);
    assert_eq!(entry[0].subject_sid, "S-READ");
    assert!(!entry[0].writable, "the entry only asked to read");

    let (cargo, _) = granted_for(&[fp("C:/data", FsAccess::ReadWrite)], &results, &cow);
    assert_eq!(cargo[0].subject_sid, "S-READ", "under CoW the ACE is a read ACE");
    assert!(cargo[0].writable, "cargo asked to write (the redirector captures it)");
}

/// 付与処理が付けられなかった宣言は「見つからない」として返る（呼び出し側が理由を出す）。
/// 綴りの違い（`\`と`/`・大小）では見失わない。
#[test]
fn a_grant_is_found_across_spellings_and_a_missing_one_is_reported() {
    let results = vec![granted(r"c:\DATA", false, "S-1", "read")];
    let (found, missing) = granted_for(
        &[fp("C:/data", FsAccess::Read), fp("C:/absent", FsAccess::Read)],
        &results,
        &WorkspaceWriteMode::DirectRw,
    );
    assert_eq!(found.len(), 1);
    assert_eq!(missing, vec![PathBuf::from("C:/absent")]);
}

/// ドメインごとの結果: 全部付いたら`Ok`、1件でも付かなければ`Err`（ドメインの用意が断る）。
#[test]
fn a_domain_with_a_missing_grant_is_reported_as_not_granted() {
    let plan = PolicyFsPlan {
        domains: vec![
            ("cargo".to_string(), vec![fp("C:/cargo", FsAccess::Read)]),
            ("npm".to_string(), vec![fp("C:/npm", FsAccess::Read)]),
        ],
        not_granted_domains: vec![("off".to_string(), "not enforced".to_string())],
        ..Default::default()
    };
    let results = vec![granted("C:/cargo", false, "S-CARGO", "read")];
    let grants = domain_fs_grants(&plan, &results, &WorkspaceWriteMode::DirectRw);
    assert_eq!(grants["cargo"].as_ref().unwrap()[0].subject_sid, "S-CARGO");
    assert!(grants["npm"].is_err());
    assert_eq!(grants["off"], Err("not enforced".to_string()));
}

/// 入口ドメインの宣言は手書きの一覧へ合流し、同じルートは1本に畳む（和を取る・範囲は再帰が勝つ）。
#[test]
fn entry_declarations_merge_into_the_manual_list() {
    let mut manual = vec![FsPassthrough {
        path: PathBuf::from(r"C:\data"),
        access: FsAccess::Read,
        forced: false,
        scope: GrantScope::Object,
    }];
    merge_into(
        &mut manual,
        &[fp("c:/DATA", FsAccess::ReadExec), fp("C:/other", FsAccess::Read)],
    );
    assert_eq!(manual.len(), 2);
    assert_eq!(manual[0].access, FsAccess::ReadExec);
    assert_eq!(manual[0].scope, GrantScope::Recursive);
}

/// 権限欄に載せてよい値は、**どれかのドメインで承認済み**のものだけ。
#[test]
fn only_approved_values_are_shown_to_the_model() {
    let only_cargo = |d: DeclarationRef<'_>| d.domain == "cargo";
    let shown = approved_fs_values(&three_domains(), &only_cargo);
    assert!(shown.contains(&("C:/cargo/db".to_string(), "read_write")));
    assert!(!shown.contains(&("C:/entry/**".to_string(), "read")));
}

fn passthrough(path: &str, access: crate::FsAccess) -> crate::FsPassthrough {
    crate::FsPassthrough {
        path: std::path::PathBuf::from(path),
        access,
        forced: false,
        scope: harness_policy::GrantScope::Recursive,
    }
}

/// [残課題 サンドボックス周辺 #65] **許可側**: 書込を含む穴は、遷移の検査へ
/// 「呼び出し元から書ける場所」として渡る。`ReadWriteExec`も書込を含む
/// ——ここが落ちると、`:rw`と実行の宣言を同じルートへ畳んだ瞬間に検査から消える。
#[test]
fn places_opened_for_writing_are_handed_to_the_transition_check() {
    let list = writable_outside_policy(&[
        passthrough(r"C:\tools", crate::FsAccess::ReadWrite),
        passthrough(r"C:\cache", crate::FsAccess::ReadWriteExec),
    ]);
    assert_eq!(list, vec![r"C:\tools".to_string(), r"C:\cache".to_string()]);
}

/// **禁止側（対）**: 読むだけ・読んで実行するだけの穴は入れない。入れると、
/// 読取専用で開けた場所にある固定したプログラムまで「書き換えられる」として拒否される。
#[test]
fn places_opened_only_for_reading_or_running_are_not_counted_as_writable() {
    let list = writable_outside_policy(&[
        passthrough(r"C:\sdk", crate::FsAccess::Read),
        passthrough(r"C:\bin", crate::FsAccess::ReadExec),
    ]);
    assert!(list.is_empty(), "read-only places leaked in: {list:?}");
}

// --- [P6.2・決定68 の前例の(9)] ドメインごとの判定（`domain_readiness`・`network_blocker`） ---

fn cargo_domain(policy: &PolicyFile) -> &PolicyDomain {
    policy.domain("cargo").expect("cargo")
}

/// **通信を宣言しているドメインは、付与の一覧を作る前に断る**（`grants`を呼ばない）。判定順を入れ替えると、
/// 使われない一覧のために台帳を読み、付かない宣言の理由で通信の理由が隠れる。
#[test]
fn a_domain_that_declares_network_is_refused_before_its_grants_are_computed() {
    let mut policy = three_domains();
    policy
        .domains
        .iter_mut()
        .find(|d| d.name == "cargo")
        .unwrap()
        .net
        .allow_domains
        .push("crates.io".to_string());
    let called = std::cell::Cell::new(false);
    let readiness = domain_readiness(cargo_domain(&policy), |_| {
        called.set(true);
        crate::tier2a::policy_grants::DomainGrants::default()
    });
    assert!(
        matches!(readiness, DomainReadiness::DeclaresNetwork { count: 1 }),
        "{readiness:?}"
    );
    assert!(!called.get(), "the grant list was computed for a domain that is refused anyway");
    assert_eq!(network_blocker(cargo_domain(&policy)), Some(1));
}

/// 許可が付かない宣言が1件でもあれば用意できない（付いた分だけで用意すると、確かめたより狭い権限で黙って動く）。
#[test]
fn a_domain_with_a_skipped_declaration_is_not_ready() {
    let policy = three_domains();
    let nothing = |_: DeclarationRef<'_>| false;
    let readiness = domain_readiness(cargo_domain(&policy), |d| ctx().domain_grants(d, &nothing));
    match readiness {
        DomainReadiness::NotGranted { skipped } => {
            assert_eq!(skipped.len(), 1);
            assert_eq!(skipped[0].value, "C:/cargo/db");
        }
        other => panic!("expected NotGranted, got {other:?}"),
    }
}

/// **対の側**: 通信を宣言せず、全部の宣言に許可が付くなら、付ける一覧ごと「用意できる」。
#[test]
fn a_ready_domain_carries_its_passthrough() {
    let policy = three_domains();
    assert_eq!(network_blocker(cargo_domain(&policy)), None);
    let readiness = domain_readiness(cargo_domain(&policy), |d| ctx().domain_grants(d, &all_approved));
    match readiness {
        DomainReadiness::Ready { passthrough } => assert_eq!(paths(&passthrough), vec!["C:/cargo/db"]),
        other => panic!("expected Ready, got {other:?}"),
    }
}
