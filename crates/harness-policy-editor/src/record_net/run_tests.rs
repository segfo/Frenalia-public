//! [決定68] パス2の付ける一覧の組み立て（[`pass2_lists`]）と、付与の結果の振り分け（[`split_granted`]）の試験。
//!
//! 守っているのは2つ——**入口と全部の遷移先の宣言が1回の付与処理（preflight）へ渡る**ことと、**入口の子のトークンへは
//! 入口の一覧の分だけが載る**こと（遷移先の宣言の宛先が入口の子へ渡ると、入口の子がそのドメインの権限で動く）。
//! どちらも`harness.exe`の`startup/sandbox.rs`と同じ形で、振り分けの本体は`harness_sandbox::tier2a::policy_fs`が持つ。
//! 実機で付けて起こすのは昇格の E2E（P6.8）。

use std::path::PathBuf;

use harness_core::GrantedPassthrough;
use harness_policy::normalize::GrantScope;
use harness_sandbox::tier2a::policy_fs::PolicyFsPlan;
use harness_sandbox::FsPassthrough;

use super::{domain_egress_requests, pass2_lists, split_granted};

fn fp(path: &str, access: harness_sandbox::FsAccess) -> FsPassthrough {
    FsPassthrough {
        path: PathBuf::from(path),
        access,
        forced: false,
        scope: GrantScope::Recursive,
    }
}

fn granted(path: &str, sid: &str, access: &str) -> GrantedPassthrough {
    GrantedPassthrough {
        path: PathBuf::from(path),
        writable: access != "read",
        subject_sid: sid.to_string(),
        used_restore_privilege: false,
        granted_access: access.to_string(),
    }
}

fn paths(list: &[FsPassthrough]) -> Vec<String> {
    list.iter()
        .map(|fp| fp.path.to_string_lossy().into_owned())
        .collect()
}

/// 入口が1件、遷移先が2つ（1件と2件）。
fn plan_with_two_destinations() -> PolicyFsPlan {
    use harness_sandbox::FsAccess;
    PolicyFsPlan {
        entry: vec![fp("C:/entry", FsAccess::Read)],
        domains: vec![
            ("cargo".to_string(), vec![fp("C:/cargo", FsAccess::ReadWrite)]),
            (
                "npm".to_string(),
                vec![fp("C:/npm/a", FsAccess::Read), fp("C:/npm/b", FsAccess::ReadExec)],
            ),
        ],
        ..PolicyFsPlan::default()
    }
}

/// **入口の一覧と全部の遷移先の一覧を、1本につないで1回の付与処理へ渡す**（UAC は今どおり最大1回）。
/// 先頭が入口で、入口の件数を一緒に返す——振り分けはこの件数で入口の分を切り出す。
///
/// 対の側: 遷移先が1つも無ければ入口の一覧そのままで、件数は全体と同じ（遷移先の分を取りこぼさない／作らない）。
#[test]
fn pass2_hands_the_entry_and_every_destination_to_one_preflight() {
    let (list, entry_len) = pass2_lists(&plan_with_two_destinations());

    assert_eq!(
        paths(&list),
        vec!["C:/entry", "C:/cargo", "C:/npm/a", "C:/npm/b"],
        "入口が先頭、遷移先は宣言の並びのまま全部"
    );
    assert_eq!(entry_len, 1, "入口の件数");

    let only_entry = PolicyFsPlan {
        entry: vec![fp("C:/entry", harness_sandbox::FsAccess::Read)],
        ..PolicyFsPlan::default()
    };
    let (list, entry_len) = pass2_lists(&only_entry);
    assert_eq!(paths(&list), vec!["C:/entry"]);
    assert_eq!(entry_len, 1);
}

/// **入口の子へ渡すのは入口の一覧の分だけ。** 遷移先の宣言に付いた宛先は、そのドメインの分（ドメインの用意が読む）へ回る。
///
/// 対の側（許可側）: 入口が宣言したものは入口の子へ渡る（全部を落として「広がらない」と言うのでは何も測らない）。
#[test]
fn only_the_entry_list_reaches_the_entry_child() {
    let plan = plan_with_two_destinations();
    let (list, entry_len) = pass2_lists(&plan);
    let results = vec![
        granted(r"C:\entry", "S-ENTRY", "read"),
        granted(r"C:\cargo", "S-CARGO", "read_write"),
        granted(r"C:\npm\a", "S-NPM-A", "read"),
        granted(r"C:\npm\b", "S-NPM-B", "read_exec"),
    ];

    let (entry, domains) = split_granted(&plan, &list[..entry_len], &results);

    let entry_sids: Vec<&str> = entry.iter().map(|g| g.subject_sid.as_str()).collect();
    assert_eq!(entry_sids, vec!["S-ENTRY"], "入口の子に遷移先の宛先が載った");
    let cargo = domains
        .get("cargo")
        .and_then(|r| r.as_ref().ok())
        .expect("cargo の分");
    assert_eq!(cargo.len(), 1);
    assert_eq!(cargo[0].subject_sid, "S-CARGO");
    let npm = domains
        .get("npm")
        .and_then(|r| r.as_ref().ok())
        .expect("npm の分");
    let npm_sids: Vec<&str> = npm.iter().map(|g| g.subject_sid.as_str()).collect();
    assert_eq!(npm_sids, vec!["S-NPM-A", "S-NPM-B"]);
}

// --- [決定69] ドメインごとの出口を立てる要求の組み立て ---

fn spec(policy_domain: &str) -> harness_sandbox::tier2a::spawnd::DomainSpec {
    harness_sandbox::tier2a::spawnd::DomainSpec {
        name: format!("harness.domain.1-2.{policy_domain}"),
        policy_domain: policy_domain.to_string(),
        container_sid: "S-1-15-2-1".to_string(),
        capability_sids: Vec::new(),
        identity: harness_sandbox::tier2a::spawnd::DomainIdentitySpec::OwnPackage,
        proxy_env: Vec::new(),
    }
}

fn declared(domain: &str, values: &[&str]) -> (String, harness_sandbox::tier2a::policy_fs::DomainNet) {
    (
        domain.to_string(),
        harness_sandbox::tier2a::policy_fs::DomainNet {
            allow_domains: values.iter().map(|v| v.to_string()).collect(),
            skipped: Vec::new(),
        },
    )
}

/// **強制モード**（決定64）: 承認済みの宣言を持つドメインだけに出口を立てる。
///
/// 宣言していないドメインへ出口を作ると、「宣言の外は断られる」を確かめる実行にならない。
#[test]
fn enforcing_pass2_gives_egress_only_to_domains_that_declared_destinations() {
    let domains = vec![spec("ssh"), spec("quiet")];
    let nets = vec![declared("ssh", &["example.com"])];

    let requests = domain_egress_requests(&domains, &nets, crate::session_dir::NetMode::Declared);

    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].domain, "ssh");
    assert_eq!(requests[0].profile, "harness.domain.1-2.ssh");
    assert_eq!(requests[0].allow_domains, vec!["example.com".to_string()]);
}

/// **記録モード**（決定64）: 用意できた遷移先の**全部**に出口を立てる（候補をドメインごとに集めるため）。
///
/// 宛先の判定は中継プロキシ側の`record_all`が持つので、宣言していないドメインにも立てる必要がある
/// ——立てないと、そのドメインの子が触った宛先が1件も記録に出ない（候補が永久に作れない）。
#[test]
fn recording_pass2_gives_egress_to_every_prepared_domain() {
    let domains = vec![spec("ssh"), spec("quiet")];
    let nets = vec![declared("ssh", &["example.com"])];

    let requests = domain_egress_requests(&domains, &nets, crate::session_dir::NetMode::RecordAll);

    let names: Vec<&str> = requests.iter().map(|r| r.domain.as_str()).collect();
    assert_eq!(names, vec!["ssh", "quiet"], "{requests:?}");
    assert!(
        requests
            .iter()
            .all(|r| !r.allow_domains.is_empty()),
        "宛先が空の要求は出口を作らない（`start_domain_egress`が飛ばす）: {requests:?}"
    );
}
