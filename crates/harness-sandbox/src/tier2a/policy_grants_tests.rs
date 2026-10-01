//! `policy.json`のファイル宣言 → 許可を付ける一覧（[`GrantContext::domain_grants`]）のテスト。
//!
//! ここが守っているのは2つ——**エディタの試験実行と`harness.exe`が同じ一覧を作る**ことと、
//! **付けない値を理由ごと返す**こと。前者は関数が1つであることで、後者は下の禁止側の試験で固定する。

use std::path::{Path, PathBuf};

use harness_policy::normalize::GrantScope;
use harness_policy::policy_file::PolicyDomain;

use super::*;

const USER_DIR: &str = "C:/Users/test/AppData/Roaming/harness";

fn ctx(ws: &Path) -> GrantContext {
    GrantContext::with_harness_user_dir(ws, Some(Path::new(USER_DIR)))
}

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn root_strings(grants: &DomainGrants) -> Vec<String> {
    grants
        .passthrough
        .iter()
        .map(|fp| fp.path.to_string_lossy().replace('\\', "/"))
        .collect()
}

/// ワイルドカードの手前まで畳み、**同じルートは1件に寄せる**。
/// 付与処理が回す件数はこの関数が返す件数そのものである。
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

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert_eq!(
        root_strings(&grants),
        vec![
            "C:/Users/me/.cargo/registry",
            "C:/Users/me/.cargo/registry/cache",
            "C:/Users/me/.cargo/bin"
        ],
        "each distinct literal prefix is its own root; identical ones must not repeat"
    );
    assert!(grants.skipped.is_empty());
}

/// 同じルートにreadとread_writeが宣言されていたら**広い方**を採る。
#[test]
fn the_widest_access_wins_for_a_shared_root() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push("C:/Users/me/.cargo/x/**".to_string());
    domain
        .fs
        .read_write
        .push("C:/Users/me/.cargo/x/**".to_string());

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert_eq!(grants.passthrough.len(), 1);
    assert_eq!(grants.passthrough[0].access, FsAccess::ReadWrite);
}

/// **`read_write`と`read_exec`が同じルートに立ったら、和を取る。**
///
/// `ReadWrite`と`ReadExec`は互いに包含しない（`ReadWrite`に`FILE_GENERIC_EXECUTE`は無い）ので、
/// 「どちらかを選ぶ」規則ではどう選んでも片方の権限が消える。
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

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert_eq!(grants.passthrough.len(), 1, "one root means one ACE");
    let access = grants.passthrough[0].access;
    assert_eq!(access, FsAccess::ReadWriteExec);
    assert!(access.is_read_write(), "the write must survive");
    assert!(access.is_exec(), "the execute must survive");
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

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert_eq!(grants.passthrough.len(), 1);
    assert_eq!(grants.passthrough[0].access, FsAccess::ReadWriteExec);
}

/// [D-63] 素の宣言と`**`の宣言が同じルートに同居したら再帰を採る。素の宣言だけならオブジェクト単体。
#[test]
fn the_scope_comes_from_how_the_value_is_written() {
    let ws = workspace();
    let mut object_only = PolicyDomain::new("a");
    object_only
        .fs
        .read
        .push("C:/Users/me/.cargo/config.toml".to_string());
    let grants = ctx(ws.path()).domain_grants(&object_only);
    assert_eq!(grants.passthrough[0].scope, GrantScope::Object);

    let mut both = PolicyDomain::new("b");
    both.fs.read.push("C:/Users/me/.cargo".to_string());
    both.fs.read.push("C:/Users/me/.cargo/**".to_string());
    let grants = ctx(ws.path()).domain_grants(&both);
    assert_eq!(grants.passthrough.len(), 1);
    assert_eq!(
        grants.passthrough[0].scope,
        GrantScope::Recursive,
        "an explicit `/**` must not be narrowed by a bare line on the same root"
    );
}

/// **ドメインをまたいでは畳まない**——引数が1ドメインであることが、それを保証している。
/// 2つのドメインに同じルートがあっても、それぞれの一覧は自分の宣言の種類のままである。
#[test]
fn each_domain_keeps_its_own_access_for_a_shared_root() {
    let ws = workspace();
    let mut reader = PolicyDomain::new("reader");
    reader.fs.read.push("C:/data/**".to_string());
    let mut writer = PolicyDomain::new("writer");
    writer.fs.read_write.push("C:/data/**".to_string());

    let c = ctx(ws.path());
    assert_eq!(c.domain_grants(&reader).passthrough[0].access, FsAccess::Read);
    assert_eq!(
        c.domain_grants(&writer).passthrough[0].access,
        FsAccess::ReadWrite
    );
}

/// **ワークスペースの中はルートにしない**（Tier2aのworkspace grantが既に覆っている）。
/// しかも「付けなかった理由」にも数えない——付けられなかったのではなく、要らないからである。
#[test]
fn paths_inside_the_workspace_are_neither_granted_nor_reported() {
    let ws = workspace();
    let inside = format!("{}/src/**", ws.path().to_string_lossy().replace('\\', "/"));
    let mut domain = PolicyDomain::new("cargo");
    domain.fs.read.push(inside);

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert!(grants.passthrough.is_empty());
    assert!(grants.skipped.is_empty());
}

/// 接頭辞が一致するだけの別ディレクトリは**ワークスペースではない**（対の側）。
#[test]
fn a_sibling_that_only_shares_a_prefix_is_outside_the_workspace() {
    let c = ctx(Path::new(r"C:\ws"));
    assert_eq!(c.grant_root("C:/ws/src/**"), Ok(None));
    assert_eq!(c.grant_root(r"C:\ws\target\debug"), Ok(None));
    assert_eq!(
        c.grant_root("C:/ws2/src/**"),
        Ok(Some(PathBuf::from("C:/ws2/src")))
    );
}

/// `canonicalize`したワークスペース（`\\?\C:\...`）でも、中の値は中と判定する。
/// `harness.exe`は正規化した形を渡すので、ここが外れるとワークスペース全体へ別の宛先のACEを撒く。
#[test]
fn a_verbatim_workspace_root_still_contains_its_own_paths() {
    let c = ctx(Path::new(r"\\?\C:\ws"));
    assert_eq!(c.grant_root("C:/ws/src/**"), Ok(None));
    assert_eq!(
        c.grant_root("C:/elsewhere/**"),
        Ok(Some(PathBuf::from("C:/elsewhere")))
    );
}

/// ワイルドカードの無い値はそのままがルートになる。
#[test]
fn a_value_without_a_wildcard_is_its_own_root() {
    let c = ctx(Path::new(r"C:\ws"));
    assert_eq!(
        c.grant_root("C:/Users/x/.cargo/config.toml"),
        Ok(Some(PathBuf::from("C:/Users/x/.cargo/config.toml")))
    );
    assert_eq!(
        c.grant_root(r"C:\Users\x\.cargo\**"),
        Ok(Some(PathBuf::from("C:/Users/x/.cargo"))),
        "the backslash spelling must give the same root"
    );
}

/// [D-63] **途中のワイルドカードは付けない**（理由を添えて1件スキップ）。
///
/// 以前のエディタは確定部分（`toolchains`）へオブジェクト単体で付けていた。D-63は
/// 「付与しない」と決めており、`harness.exe`の`--fs-allow`も同じ値を名指しで落としている。
/// 2つの読み手が同じ値を別々に扱うと、エディタで通った宣言が`harness.exe`で通らない。
#[test]
fn a_wildcard_in_the_middle_is_skipped_with_its_reason() {
    let ws = workspace();
    let mut domain = PolicyDomain::new("cargo");
    domain
        .fs
        .read_exec
        .push("C:/Users/x/.rustup/toolchains/*/bin".to_string());

    let grants = ctx(ws.path()).domain_grants(&domain);
    assert!(grants.passthrough.is_empty(), "{:?}", grants.passthrough);
    assert_eq!(
        grants.skipped,
        vec![SkippedDeclaration {
            value: "C:/Users/x/.rustup/toolchains/*/bin".to_string(),
            access: harness_config::FsAccess::ReadExec,
            reason: SkipReason::MiddleWildcard,
        }]
    );
}

/// ドライブ直下まで戻る値は付けない（事実上ドライブ全体への付与になる）。
#[test]
fn a_value_that_reduces_to_a_drive_root_is_skipped() {
    let c = ctx(Path::new(r"C:\ws"));
    assert_eq!(c.grant_root("C:/**"), Err(SkipReason::DriveRoot));
    assert_eq!(c.grant_root("C:/"), Err(SkipReason::DriveRoot));
    assert!(
        c.grant_root("C:/*").is_err(),
        "`C:/*` must not open anything either"
    );
}

/// 相対パスは付けない。付与する側の作業ディレクトリ基準で別の場所を開くことになる。
#[test]
fn a_relative_value_is_skipped() {
    let c = ctx(Path::new(r"C:\ws"));
    assert_eq!(c.grant_root("target/**"), Err(SkipReason::RelativePath));
    assert_eq!(c.grant_root(r"..\other"), Err(SkipReason::RelativePath));
}

/// **制御ディレクトリは承認済みでも付けない**（P-08）。綴りは2つある。
#[test]
fn harness_control_directories_are_never_granted() {
    let c = ctx(Path::new(r"C:\ws"));
    assert_eq!(
        c.grant_root("C:/other-repo/.harness/**"),
        Err(SkipReason::ControlDirectory),
        "any workspace's .harness"
    );
    assert_eq!(
        c.grant_root("C:/ws/.HARNESS/settings.json"),
        Err(SkipReason::ControlDirectory),
        "even inside this workspace, it is reported rather than silently dropped"
    );
    assert_eq!(
        c.grant_root(&format!("{USER_DIR}/config/**")),
        Err(SkipReason::ControlDirectory),
        "the user-scope control directory"
    );
    assert_eq!(
        c.grant_root("C:/Users/test/AppData/Roaming/**"),
        Ok(Some(PathBuf::from("C:/Users/test/AppData/Roaming"))),
        "its parent is not the control directory itself (breadth is judged at approval time)"
    );
}

/// `.harness`の判定はパス要素で行う（前方一致や部分一致ではない）。
#[test]
fn the_control_path_check_matches_whole_components_only() {
    assert!(is_harness_control_path("C:/work/.harness/settings.json"));
    assert!(is_harness_control_path(r"C:\work\.HARNESS\settings.json"));
    assert!(!is_harness_control_path("C:/work/.harnessrc"));
    assert!(!is_harness_control_path("C:/work/harness/settings.json"));
}

/// 理由の文言はすべて空でない（網羅`match`の中身が抜けていないことの検算）。
#[test]
fn every_reason_has_a_description() {
    for reason in [
        SkipReason::ControlDirectory,
        SkipReason::RelativePath,
        SkipReason::MiddleWildcard,
        SkipReason::DriveRoot,
    ] {
        assert!(!reason.describe().is_empty(), "{reason:?}");
    }
}
