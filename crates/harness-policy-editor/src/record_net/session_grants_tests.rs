//! [`super`]（もう宣言されていない穴の判定と、残す集合の数え方）の試験（`record_net.rs`からそのまま移した。P6.1）。

use super::*;

fn wanted(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

/// [BUG-184] **残す集合は、記録中のドメインだけでなく全ドメインと`settings.json`の宣言を含む。**
/// 記録中のドメインだけで数えると、他ドメインの宣言と`harness.exe`が設定で付けた許可を取り消す。
#[test]
fn the_kept_set_covers_every_domain_and_the_settings_file() {
    use harness_sandbox::tier2a::policy_approval::{
        approval_workspace_key, FsDeclarationApproval, PolicyApprovalLedger,
        APPROVAL_FORMAT_VERSION,
    };
    let ws = tempfile::tempdir().expect("tempdir");
    let mut cargo = crate::PolicyDomain::new("cargo");
    cargo.fs.read.push("C:/cargo/**".to_string());
    let mut npm = crate::PolicyDomain::new("npm");
    npm.fs.read.push("C:/npm/**".to_string());
    npm.fs.read.push("C:/shipped/**".to_string());
    let policy = crate::PolicyFile {
        domains: vec![cargo, npm],
        ..Default::default()
    };
    let approve = |domain: &str, value: &str| FsDeclarationApproval {
        workspace: approval_workspace_key(ws.path()),
        domain: domain.to_string(),
        access: harness_config::FsAccess::Read,
        value: value.to_string(),
        approved_at_unix_secs: 0,
        format_version: Some(APPROVAL_FORMAT_VERSION),
    };
    // `C:/shipped/**`は承認していない（同梱された宣言）。
    let approvals = PolicyApprovalLedger {
        approvals: vec![approve("cargo", "C:/cargo/**"), approve("npm", "C:/npm/**")],
    };
    let settings = vec![("C:/from-settings/**".to_string(), harness_config::FsAccess::Read)];

    let kept = declared_roots_from(&policy, &settings, ws.path(), &approvals);
    let held = held(&["C:/cargo", "C:/npm", "C:/from-settings", "C:/shipped", "C:/gone"]);
    let stale = stale_roots(&held, &kept);
    assert_eq!(
        stale,
        held_of(&["C:/shipped", "C:/gone"]),
        "only the unapproved and the no-longer-declared roots are stale: kept={kept:?}"
    );
}

fn held_of(paths: &[&str]) -> Vec<PathBuf> {
    held(paths)
}

fn held(paths: &[&str]) -> Vec<PathBuf> {
    paths.iter().map(PathBuf::from).collect()
}

#[test]
fn a_root_that_is_no_longer_declared_is_stale() {
    let stale = stale_roots(
        &held(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
        &wanted(&["C:/Users/segfo/.cargo"]),
    );
    assert_eq!(stale, held(&["C:/Users/segfo/.rustup"]));
}

/// B-35の対。上のテストだけなら「常に全部staleと言う」実装でも緑になる——それは
/// **まだ要る穴を毎回剥がす**（付け直しの待ち時間が毎回乗る）という別の壊れ方である。
#[test]
fn a_root_that_is_still_declared_is_never_stale() {
    let stale = stale_roots(
        &held(&["C:/Users/segfo/.cargo"]),
        &wanted(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
    );
    assert!(stale.is_empty(), "宣言が増えた側は剥がす対象にならない");
}

#[test]
fn nothing_is_stale_when_the_declaration_did_not_change() {
    let same = ["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"];
    assert!(stale_roots(&held(&same), &wanted(&same)).is_empty());
}

/// Windowsのパスは大文字小文字を区別しないので、綴りの違いで「別物」と見ると
/// **まだ要る穴を剥がす**ことになる。
#[test]
fn the_comparison_ignores_case_because_windows_paths_do() {
    let stale = stale_roots(
        &held(&["C:/Users/segfo/.cargo"]),
        &wanted(&["c:/users/segfo/.CARGO"]),
    );
    assert!(stale.is_empty());
}

/// 前綴りを共有する別ルートを同一視すると、要る穴を剥がすか剥がし残す。
/// ここは**完全一致だけ**を見る（`covers`のような包含判定ではない）——`grant_roots`が
/// 返すのは畳み込み済みのルートそのものなので、比較すべきはルート同士の同一性である。
#[test]
fn a_sibling_root_sharing_a_prefix_is_a_different_root() {
    let stale = stale_roots(
        &held(&["C:/Users/segfo/.cargo"]),
        &wanted(&["C:/Users/segfo/.cargo-alt"]),
    );
    assert_eq!(
        stale,
        held(&["C:/Users/segfo/.cargo"]),
        "別ルートなのでstale（宣言されているのは .cargo-alt だけ）"
    );
}

/// [BUG-142] **`held`の出どころが台帳になったので、区切りの違いが日常的に混ざる。**
///
/// 台帳の綴りは`declaration_key`が畳んだ形（区切りは`\`）、`wanted`は`policy.json`由来で
/// `/`のことが多い。大文字小文字だけを無視する比較のままだと、この対が「別ルート」に見えて
/// **まだ宣言されている穴を剥がす**。剥がすのは再帰walkなので、気づいたときには
/// 付け直しの待ち時間が毎回乗っている。
#[test]
fn the_comparison_folds_separators_because_the_ledger_and_the_policy_file_spell_them_differently(
) {
    let stale = stale_roots(
        &held(&[r"c:\users\segfo\.cargo"]),
        &wanted(&["C:/Users/segfo/.cargo"]),
    );
    assert!(
        stale.is_empty(),
        "同じルートなので剥がしてはならない（区切りだけが違う）: {stale:?}"
    );
}

#[test]
fn every_held_root_is_stale_when_all_declarations_were_unapproved() {
    // 再現性の確認（宣言を全部取り消してからパス2を走らせる）でまさにこの形になる。
    let stale = stale_roots(
        &held(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
        &wanted(&[]),
    );
    assert_eq!(stale.len(), 2);
}
