//! [`crate::unapprove`]のテスト。
//!
//! # 何を測れば「取り消しが壊れた」と言えるか
//!
//! 撤収系の機構は**消しすぎ**でも**消し足りない**でも壊れる。したがって
//! 「消すべきものが消えた」と**同じ重さで**「消してはいけないものが残った」を固定する（B-35）。
//! 片方だけ書くと、`retain`の条件を逆にしても半分のテストは緑のままになる。

use std::path::Path;

use harness_policy::generalize::SettingsKey;

use super::*;
use crate::policy_file::{PolicyDomain, PolicyFile};

/// 宣言入りの`policy.json`を書いたworkspaceを作る。
fn workspace_with(domains: Vec<PolicyDomain>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = PolicyFile {
        schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
        domains,
    };
    policy_file::save(dir.path(), &file).expect("save");
    dir
}

fn cargo_domain() -> PolicyDomain {
    let mut domain = PolicyDomain::new("cargo");
    domain.commands.push("cargo test".to_string());
    domain
        .fs
        .read
        .push("C:/Users/segfo/.cargo/registry".to_string());
    domain
        .fs
        .read_write
        .push("C:/Users/segfo/.rustup/tmp".to_string());
    domain
        .fs
        .read_exec
        .push("C:/Users/segfo/.cargo/bin/cargo.exe".to_string());
    domain.net.allow_domains.push("crates.io".to_string());
    domain
}

fn target(domain: &str, key: SettingsKey, value: &str) -> UnapproveTarget {
    UnapproveTarget {
        domain: domain.to_string(),
        key,
        value: value.to_string(),
    }
}

fn load(root: &Path) -> PolicyFile {
    policy_file::load(root).expect("load")
}

#[test]
fn removing_one_declaration_leaves_every_other_declaration_in_place() {
    let ws = workspace_with(vec![cargo_domain()]);
    let plan = plan(
        ws.path(),
        &[target(
            "cargo",
            SettingsKey::FsReadExec,
            "C:/Users/segfo/.cargo/bin/cargo.exe",
        )],
    )
    .expect("plan");

    assert_eq!(plan.removed.len(), 1, "指定した1件が消える");
    assert!(plan.not_found.is_empty());
    assert!(commit(ws.path(), &plan).expect("commit"), "書いたと返る");

    let after = load(ws.path());
    let domain = after.domain("cargo").expect("domain残る");
    assert!(domain.fs.read_exec.is_empty(), "消すべきものが消えた");
    // B-35の対: **消してはいけないものが残った**ことを同じ重さで固定する。
    assert_eq!(
        domain.fs.read,
        vec!["C:/Users/segfo/.cargo/registry".to_string()],
        "他のバケットは触らない"
    );
    assert_eq!(
        domain.fs.read_write,
        vec!["C:/Users/segfo/.rustup/tmp".to_string()],
        "他のバケットは触らない"
    );
    assert_eq!(
        domain.net.allow_domains,
        vec!["crates.io".to_string()],
        "net宣言は触らない"
    );
    assert_eq!(
        domain.commands,
        vec!["cargo test".to_string()],
        "由来の記録は消さない"
    );
}

#[test]
fn the_same_path_declared_under_another_access_is_not_removed() {
    // `c`キーでaccessを変えて承認し直した結果、同じパスが2つのバケットに立つことがある。
    // **キーで指定した側だけ**が消えなければ、片方を消したつもりで両方消える。
    let mut domain = PolicyDomain::new("cargo");
    let path = "C:/Users/segfo/.cargo/bin/cargo.exe";
    domain.fs.read.push(path.to_string());
    domain.fs.read_exec.push(path.to_string());
    let ws = workspace_with(vec![domain]);

    let plan = plan(ws.path(), &[target("cargo", SettingsKey::FsRead, path)]).expect("plan");
    commit(ws.path(), &plan).expect("commit");

    let after = load(ws.path());
    let domain = after.domain("cargo").expect("domain");
    assert!(domain.fs.read.is_empty(), "指定したreadは消える");
    assert_eq!(
        domain.fs.read_exec,
        vec![path.to_string()],
        "同じ値でも別accessの宣言は残る"
    );
}

#[test]
fn a_value_that_is_not_declared_is_reported_as_not_found_and_nothing_is_written() {
    let ws = workspace_with(vec![cargo_domain()]);
    let plan = plan(
        ws.path(),
        &[target("cargo", SettingsKey::FsRead, "C:/nowhere")],
    )
    .expect("plan");

    assert!(plan.removed.is_empty());
    assert_eq!(plan.not_found.len(), 1, "元から無かったことを区別して返す");
    assert!(
        !commit(ws.path(), &plan).expect("commit"),
        "消えるものが無いなら書かない（B-09）"
    );
}

#[test]
fn an_unknown_domain_is_reported_as_not_found() {
    let ws = workspace_with(vec![cargo_domain()]);
    let plan = plan(
        ws.path(),
        &[target("no-such-domain", SettingsKey::FsRead, "C:/x")],
    )
    .expect("plan");
    assert!(plan.removed.is_empty());
    assert_eq!(plan.not_found.len(), 1);
}

#[test]
fn the_value_comparison_ignores_case_because_windows_paths_do() {
    let ws = workspace_with(vec![cargo_domain()]);
    // 画面に出ている綴りと大文字小文字だけが違う指定でも消える。
    let plan = plan(
        ws.path(),
        &[target(
            "cargo",
            SettingsKey::FsRead,
            "c:/users/segfo/.CARGO/registry",
        )],
    )
    .expect("plan");
    assert_eq!(plan.removed.len(), 1, "大文字小文字は無視して一致させる");
}

#[test]
fn emptying_a_domain_keeps_the_domain_itself() {
    // 「宣言を全部外してパス2を走らせ、本当に拒否されるか」を確かめる経路が要るので、
    // ドメイン自体は残さなければならない（残さないと`record-net --domain`が引けなくなる）。
    let ws = workspace_with(vec![cargo_domain()]);
    let file = load(ws.path());
    let targets = all_targets(&file);
    assert_eq!(targets.len(), 4, "fs 3件＋net 1件");

    let plan = plan(ws.path(), &targets).expect("plan");
    assert_eq!(plan.removed.len(), 4);
    assert_eq!(
        plan.emptied_domains,
        vec!["cargo".to_string()],
        "空になったことは報告する"
    );
    commit(ws.path(), &plan).expect("commit");

    let after = load(ws.path());
    let domain = after
        .domain("cargo")
        .expect("宣言が空になってもドメインは残る");
    assert!(domain.fs.is_empty());
    assert!(domain.net.allow_domains.is_empty());
    assert_eq!(
        domain.commands,
        vec!["cargo test".to_string()],
        "どのコマンドの記録だったかは残る"
    );
}

#[test]
fn other_domains_are_untouched_when_one_domains_declaration_is_removed() {
    let mut other = PolicyDomain::new("gh");
    other
        .fs
        .read
        .push("C:/Users/segfo/.cargo/registry".to_string());
    let ws = workspace_with(vec![cargo_domain(), other]);

    // **同じ値**が別ドメインにも宣言されている状況で、片方だけを消す。
    let plan = plan(
        ws.path(),
        &[target(
            "cargo",
            SettingsKey::FsRead,
            "C:/Users/segfo/.cargo/registry",
        )],
    )
    .expect("plan");
    commit(ws.path(), &plan).expect("commit");

    let after = load(ws.path());
    assert!(after.domain("cargo").expect("cargo").fs.read.is_empty());
    assert_eq!(
        after.domain("gh").expect("gh").fs.read,
        vec!["C:/Users/segfo/.cargo/registry".to_string()],
        "別ドメインの同じ値は残る"
    );
}

// --- 候補一覧へ重ねるための照会（`PolicyDomain`のメソッド） ---------------------

#[test]
fn a_path_declared_as_read_exec_is_reported_as_declared_even_when_asked_about_read() {
    // ETWは読取と実行を区別しないので、`read_exec`で承認した実行ファイルは次の記録でも
    // `read`の候補として現れる。ここでaccessまで一致を要求すると、承認済みの実行ファイルが
    // 毎回「未宣言」に見える（それが直したかった症状そのもの）。
    let domain = cargo_domain();
    let keys = domain.declared_keys_for_value("C:/Users/segfo/.cargo/bin/cargo.exe");
    assert_eq!(
        keys,
        vec![SettingsKey::FsReadExec],
        "accessが違っても宣言済みとして引ける"
    );
}

#[test]
fn a_path_with_no_declaration_at_all_is_reported_as_undeclared() {
    // B-35の対。上のテストだけだと、常に「宣言済み」を返す実装でも緑になる。
    let domain = cargo_domain();
    assert!(domain
        .declared_keys_for_value("C:/Users/segfo/AppData/Local/Temp/x")
        .is_empty());
}

#[test]
fn a_descendant_of_a_declaration_is_covered_but_not_itself_declared() {
    let domain = cargo_domain();
    let child = "C:/Users/segfo/.cargo/registry/cache/index";
    assert!(
        domain.declared_keys_for_value(child).is_empty(),
        "子孫は「宣言済み」ではない（外しても消せる宣言がその行に無い）"
    );
    assert_eq!(
        domain.covering_fs_declaration(child),
        Some((
            SettingsKey::FsRead,
            "C:/Users/segfo/.cargo/registry".to_string()
        )),
        "覆っている宣言は注記として引ける"
    );
}

#[test]
fn a_declaration_does_not_report_itself_as_covering_itself() {
    // 自分自身を「覆っている親」として返すと、宣言済みの行に
    // 「親Xに覆われています」という無意味な注記が出る。
    let domain = cargo_domain();
    assert_eq!(
        domain.covering_fs_declaration("C:/Users/segfo/.cargo/registry"),
        None
    );
}

#[test]
fn a_sibling_directory_sharing_a_prefix_is_not_treated_as_covered() {
    // `C:/x/.cargo` と `C:/x/.cargo-alt` のような兄弟を覆っていると誤判定すると、
    // 無関係なパスに「許可済み」の注記が出る（`covers`のコンポーネント境界判定）。
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/segfo/.cargo".to_string());
    assert_eq!(
        domain.covering_fs_declaration("C:/Users/segfo/.cargo-alt/x"),
        None
    );
}

// ---------------------------------------------------------------------------
// [BUG-103] `--excluded`（いまの規則なら候補にしなかった宣言の掃除）
// ---------------------------------------------------------------------------

/// 掃除の対象は**候補側とまったく同じ規則**で選ばれる（B-05）。
///
/// 実マシンの`policy.json`に実際に入っていた綴りを使う——`%TEMP%`配下の刹那パス、
/// `%TEMP%`ルートそのもの（`(OI)(CI)(R,W,D)`の出所）、harness自身のサンドボックス
/// プロファイル。
#[test]
fn excluded_targets_picks_exactly_what_the_candidate_side_would_now_drop() {
    let mut domain = PolicyDomain::new("cargo");
    domain
        .fs
        .read
        .push("C:/Users/segfo/AppData/Local/Temp/.tmpX3JiLI/ledger.json".to_string());
    domain
        .fs
        .read_write
        .push("C:/Users/segfo/AppData/Local/Temp".to_string());
    domain.fs.read.push(
        "C:/Users/segfo/AppData/Local/Packages/harness.shell.sandbox.1234-5678/AC/x".to_string(),
    );
    domain.fs.read.push("C:/ws/src/lib.rs".to_string());
    // 残すべきもの（承認の主対象）。
    domain
        .fs
        .read_exec
        .push("C:/Users/segfo/.cargo/bin/cargo.exe".to_string());
    domain.net.allow_domains.push("crates.io".to_string());

    let file = PolicyFile {
        schema_version: crate::policy_file::POLICY_SCHEMA_VERSION,
        domains: vec![domain],
    };
    let rules = crate::exclusion::ExclusionRules::with_temp_root(
        Path::new("C:/ws"),
        Some(Path::new("C:/Users/segfo/AppData/Local/Temp")),
    );

    let found = excluded_targets(&file, &rules);
    let values: Vec<&str> = found.iter().map(|(t, _)| t.value.as_str()).collect();

    assert_eq!(found.len(), 4, "{values:?}");
    assert!(values.contains(&"C:/Users/segfo/AppData/Local/Temp/.tmpX3JiLI/ledger.json"));
    assert!(values.contains(&"C:/Users/segfo/AppData/Local/Temp"));
    assert!(values
        .contains(&"C:/Users/segfo/AppData/Local/Packages/harness.shell.sandbox.1234-5678/AC/x"));
    assert!(values.contains(&"C:/ws/src/lib.rs"));

    // **対（B-35）**: 承認の主対象は掃除しない。ここが落ちると`--excluded`は
    // 「全部消す」と同じ危険な操作になる。
    assert!(
        !values.contains(&"C:/Users/segfo/.cargo/bin/cargo.exe"),
        "an ordinary out-of-workspace grant must survive the cleanup: {values:?}"
    );
    // ネットワーク宣言はパスではないので対象外。
    assert!(!values.contains(&"crates.io"), "{values:?}");
    // access種別は宣言のバケットから取る（`--fs`と`--access`の対応と同じ規則）。
    let temp_root = found
        .iter()
        .find(|(t, _)| t.value == "C:/Users/segfo/AppData/Local/Temp")
        .expect("the %TEMP% root declaration");
    assert_eq!(temp_root.0.key, SettingsKey::FsReadWrite);
    assert_eq!(temp_root.1, crate::exclusion::Excluded::EphemeralTemp);
}

/// 掃除しても`policy.json`の他の宣言・ドメイン自体は残る（既存の`plan`/`commit`を通る）。
#[test]
fn cleaning_excluded_declarations_leaves_the_domain_and_the_rest_intact() {
    let mut domain = cargo_domain();
    domain
        .fs
        .read
        .push("C:/Users/segfo/AppData/Local/Temp/.tmpQQ/a.txt".to_string());
    let ws = workspace_with(vec![domain]);

    let rules = crate::exclusion::ExclusionRules::with_temp_root(
        ws.path(),
        Some(Path::new("C:/Users/segfo/AppData/Local/Temp")),
    );
    let targets: Vec<UnapproveTarget> = excluded_targets(&load(ws.path()), &rules)
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    assert_eq!(targets.len(), 1, "{targets:?}");

    let plan = plan(ws.path(), &targets).expect("plan");
    assert!(commit(ws.path(), &plan).expect("commit"));

    let after = load(ws.path());
    let domain = after
        .domain("cargo")
        .expect("the domain itself must survive");
    assert!(domain
        .fs
        .read
        .contains(&"C:/Users/segfo/.cargo/registry".to_string()));
    assert!(domain
        .fs
        .read_exec
        .contains(&"C:/Users/segfo/.cargo/bin/cargo.exe".to_string()));
    assert!(!domain
        .fs
        .read
        .iter()
        .any(|v| v.contains("AppData/Local/Temp")));
    assert_eq!(domain.net.allow_domains, vec!["crates.io".to_string()]);
}

/// [D-112] 取り消した宣言の**このマシンでの承認も消える**。消えないと、同じ値が後で
/// リポジトリに同梱されて戻ってきたとき、承認済みとして許可が付く。対の側として、
/// 取り消していない宣言の承認は残る（`B-35`）。
#[test]
fn removing_a_declaration_also_revokes_its_approval_but_keeps_the_others() {
    use harness_sandbox::tier2a::policy_approval::DeclarationRef;
    let ws = workspace_with(vec![cargo_domain()]);
    let removed = DeclarationRef {
        domain: "cargo",
        value: "C:/Users/segfo/.cargo/bin/cargo.exe",
        key: harness_policy::generalize::SettingsKey::FsReadExec,
    };
    let kept = DeclarationRef {
        domain: "cargo",
        value: "C:/Users/segfo/.cargo/registry",
        key: harness_policy::generalize::SettingsKey::FsRead,
    };
    let store = crate::approval_store::approval_store();
    assert!(store.approve(ws.path(), &[removed, kept]).is_empty());

    // 大文字小文字だけ違う指定でも、`policy.json`から消えるのと同じ範囲で承認も消える。
    let plan = plan(
        ws.path(),
        &[target(
            "cargo",
            SettingsKey::FsReadExec,
            "c:/users/segfo/.cargo/bin/CARGO.exe",
        )],
    )
    .expect("plan");
    assert!(commit(ws.path(), &plan).expect("commit"));

    let approvals = store.load();
    assert!(!approvals.is_approved(ws.path(), removed));
    assert!(approvals.is_approved(ws.path(), kept));
}


/// [P5.3、決定66] **遷移元から宣言を取り消すと、その遷移元から出る辺が広がり得る**——遷移先の届く範囲から差し引く
/// 「遷移元が自分で宣言している権限」が減るためである。広がる辺は確定の明細の材料（[`UnapprovePlan::widening`]）に出る。
/// 対の側: 遷移先の宣言を取り消しても、辺は広がらない（材料は空）。
#[test]
fn unapproving_from_the_source_shows_the_edge_it_widens() {
    use harness_policy::policy_file::ENTRY_DOMAIN;
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.fs.read.push("C:/Users/x/proj/**".to_string());
    entry.process.transitions.push(editor_edge(
        "C:/Users/x/tools/tool.exe",
        ArgvMatcher::Any(AnyMarker),
        "tool",
    ));
    let mut tool = PolicyDomain::new("tool");
    tool.fs.read.push("C:/Users/x/proj/a.txt".to_string());
    let ws = workspace_with(vec![entry, tool]);

    let widening = plan(
        ws.path(),
        &[target(ENTRY_DOMAIN, SettingsKey::FsRead, "C:/Users/x/proj/**")],
    )
    .expect("plan")
    .widening;
    assert_eq!(widening.edges.len(), 1, "{widening:?}");
    assert_eq!(widening.edges[0].from, ENTRY_DOMAIN);
    assert_eq!(widening.edges[0].to, "tool");
    assert_eq!(
        widening.edges[0].newly_usable.fs,
        vec![("C:/Users/x/proj/a.txt".to_string(), "read")]
    );

    let narrowing = plan(
        ws.path(),
        &[target("tool", SettingsKey::FsRead, "C:/Users/x/proj/a.txt")],
    )
    .expect("plan")
    .widening;
    assert!(narrowing.is_empty(), "{narrowing:?}");
}
