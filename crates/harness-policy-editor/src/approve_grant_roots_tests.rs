//! workspace外のルートが多いときの、承認時の警告のテスト。
//!
//! ルートの数え方そのもの（畳み方・和の取り方・範囲）は`harness_sandbox::tier2a::policy_grants`の
//! テストが持つ（`harness.exe`と共有する関数へ移した）。
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
