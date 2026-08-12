//! `grant_roots`（＝パス2が1件ずつ処理するworkspace外ルートの唯一の定義）と、
//! それが多いときの承認時警告のテスト。
//!
//! ここが守っているのは**「承認した結果が次のパス2の待ち時間になる」ことをその場で見せる**
//! という一点である。実運用で`cargo`ドメインが668件になり、パス2の準備が数分無反応になった
//! ——ユーザーから見ると「固まった」であり、承認の時点では何も知らされていなかった。

use harness_policy::{generalize::SettingsKey, RuleProposal};

use super::*;

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn proposal(id: &str, value: &str) -> RuleProposal {
    RuleProposal {
        id: id.to_string(),
        key: SettingsKey::FsRead,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }
}

/// ワイルドカードの手前まで畳み、**同じルートは1件に寄せる**。
/// `preflight`が回す件数はこの関数が返す件数そのものである。
#[test]
fn entries_under_the_same_root_collapse_to_one_grant_root() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    for value in [
        "C:/Users/me/.cargo/registry/**",
        "C:/Users/me/.cargo/registry/cache/**",
        "C:/Users/me/.cargo/bin/**",
    ] {
        domain.fs.read.push(value.to_string());
    }

    let roots = grant_roots(&domain, ws.path());
    let paths: Vec<String> = roots
        .iter()
        .map(|(p, _, _)| p.to_string_lossy().replace('\\', "/"))
        .collect();
    assert_eq!(
        paths,
        vec![
            "C:/Users/me/.cargo/registry",
            "C:/Users/me/.cargo/registry/cache",
            "C:/Users/me/.cargo/bin"
        ],
        "each distinct literal prefix is its own root; identical ones must not repeat"
    );
}

/// 同じルートにreadとread_writeが宣言されていたら**広い方**を採る
/// （読み取り穴と書込穴を2本張れないので、狭い方を採ると宣言と食い違う）。
#[test]
fn the_widest_access_wins_for_a_shared_root() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/me/.cargo/x/**".to_string());
    domain
        .fs
        .read_write
        .push("C:/Users/me/.cargo/x/**".to_string());

    let roots = grant_roots(&domain, ws.path());
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].1, harness_sandbox::FsAccess::ReadWrite);
}

/// **`read_write`と`read_exec`が同じルートに立ったら、和を取る。**
///
/// `ReadWrite`と`ReadExec`は互いに包含しない（`ReadWrite`に`FILE_GENERIC_EXECUTE`は無い）ので、
/// 「どちらかを選ぶ」規則ではどう選んでも片方の権限が消える。消えた側は実行時の
/// `Access is denied`として現れるのに、`policy.json`には許可が書いてあるように見える
/// ——このズレこそが直したかったものなので、ここで固定する。
#[test]
fn write_and_exec_on_the_same_root_are_combined_not_chosen_between() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    domain
        .fs
        .read_write
        .push("C:/Users/me/.cargo/x/**".to_string());
    domain
        .fs
        .read_exec
        .push("C:/Users/me/.cargo/x/**".to_string());

    let roots = grant_roots(&domain, ws.path());

    assert_eq!(roots.len(), 1, "one root means one ACE");
    assert_eq!(roots[0].1, harness_sandbox::FsAccess::ReadWriteExec);
    assert!(roots[0].1.is_read_write(), "the write must survive");
    assert!(roots[0].1.is_exec(), "the execute must survive");
}

/// 3つのバケツすべてに同じルートがあっても1本にまとまる（`read`は和に影響しない）。
#[test]
fn all_three_buckets_on_one_root_still_produce_a_single_grant() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    for bucket in [
        &mut domain.fs.read,
        &mut domain.fs.read_write,
        &mut domain.fs.read_exec,
    ] {
        bucket.push("C:/Users/me/.cargo/x/**".to_string());
    }

    let roots = grant_roots(&domain, ws.path());

    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].1, harness_sandbox::FsAccess::ReadWriteExec);
}

/// workspace配下は**ルートにしない**（Tier2aのworkspace grantが既に覆っている）。
#[test]
fn paths_inside_the_workspace_are_not_grant_roots() {
    let ws = workspace();
    let inside = format!("{}/src/**", ws.path().to_string_lossy().replace('\\', "/"));
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(inside);

    assert!(grant_roots(&domain, ws.path()).is_empty());
}

/// **件数が多いときは承認の瞬間に伝える。** 出さないと、次のパス2で数分待たされて初めて
/// 気付くことになり、しかもその時点では「何が原因か」が画面に無い。
#[test]
fn approving_many_outside_roots_warns_before_it_becomes_a_wait() {
    let ws = workspace();
    let proposals: Vec<RuleProposal> = (0..MANY_GRANT_ROOTS)
        .map(|i| proposal(&format!("fs-{i}"), &format!("C:/Users/me/.cargo/p{i}/**")))
        .collect();
    let accept: Vec<String> = proposals.iter().map(|p| p.id.clone()).collect();

    let plan = plan(&ApproveRequest {
        workspace_root: ws.path(),
        proposals: &proposals,
        accept_ids: &accept,
        require_sandbox: RequireSandbox::None,
        domain: "cargo",
        command: Some("cargo build"),
        cwd: None,
        record_session: Some("sess-1"),
        now_unix_ms: 1_700_000_000_000,
    })
    .expect("plan");

    let warning = plan
        .warnings
        .iter()
        .find(|w| w.contains("workspace外のルート"))
        .unwrap_or_else(|| {
            panic!(
                "{MANY_GRANT_ROOTS} outside roots must be called out at approval time: {:?}",
                plan.warnings
            )
        });
    assert!(
        warning.contains(&MANY_GRANT_ROOTS.to_string()),
        "the warning has to carry the actual count: {warning}"
    );
    assert!(
        warning.contains("一般化"),
        "a count without a way to act on it is only half a warning: {warning}"
    );
}

/// 少ない件数では黙っている（毎回出る警告は読まれなくなる）。
#[test]
fn a_handful_of_outside_roots_is_not_worth_a_warning() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", "C:/Users/me/.cargo/registry/**")];
    let accept = vec!["fs-1".to_string()];

    let plan = plan(&ApproveRequest {
        workspace_root: ws.path(),
        proposals: &proposals,
        accept_ids: &accept,
        require_sandbox: RequireSandbox::None,
        domain: "cargo",
        command: Some("cargo build"),
        cwd: None,
        record_session: Some("sess-1"),
        now_unix_ms: 1_700_000_000_000,
    })
    .expect("plan");

    assert!(
        !plan
            .warnings
            .iter()
            .any(|w| w.contains("workspace外のルート")),
        "warnings that fire every time stop being read: {:?}",
        plan.warnings
    );
}
