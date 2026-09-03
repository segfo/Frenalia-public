//! `--force-system-acl`（D-19）の絶対拒否ゲート`is_force_grant_forbidden`の単体テスト。
//! 実FS書込やAdministrator権限を要さない（`canonicalize`と環境変数のみ）ため`#[ignore]`しない。

use super::is_force_grant_forbidden;
use std::path::{Path, PathBuf};

fn windir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(PathBuf::from)
        .expect("SystemRoot/windir must be set on Windows")
}

#[test]
fn drive_root_is_forbidden() {
    // canonicalize(C:\)は`\\?\C:\`になり通常成分を持たない=ドライブルート判定。
    let reason = is_force_grant_forbidden(Path::new("C:\\"));
    assert!(reason.is_some(), "drive root must be forbidden: {reason:?}");
}

#[test]
fn windows_system_directory_is_forbidden() {
    let reason = is_force_grant_forbidden(&windir());
    assert!(
        reason.is_some(),
        "the Windows directory itself must be forbidden: {reason:?}"
    );
}

#[test]
fn registry_hive_directory_is_forbidden() {
    let config = windir().join("System32").join("config");
    if !config.exists() {
        return; // 通常存在するが、無い機種ではスキップ（誤検知を避ける）。
    }
    let reason = is_force_grant_forbidden(&config);
    assert!(
        reason.is_some(),
        "System32\\config (registry hives) must be forbidden: {reason:?}"
    );
}

#[test]
fn ordinary_temp_directory_is_allowed() {
    // %TEMP%配下の実在ディレクトリは`%SystemRoot%`外・非ドライブルートなので許可される。
    let dir = std::env::temp_dir();
    if !dir.exists() {
        return;
    }
    let reason = is_force_grant_forbidden(&dir);
    assert!(
        reason.is_none(),
        "an ordinary temp directory must be allowed, got: {reason:?}"
    );
}

#[test]
fn nonexistent_path_is_forbidden_fail_safe() {
    // canonicalizeできないパスは安全側（拒否）に倒す。
    let bogus = windir().join("this-path-should-not-exist-harness-d19-test");
    let reason = is_force_grant_forbidden(&bogus);
    assert!(
        reason.is_some(),
        "a non-canonicalizable path must be refused (fail-safe): {reason:?}"
    );
}

/// **[BUG-119 案C] 撤収も同じゲートを通る。**
///
/// D-19 不変条件4は「`SeRestorePrivilege`は全DACLをバイパスするため、書込の直前に
/// `is_force_grant_forbidden`を必ず通す」と定めている。付与側は3つの入口すべてで通していたが、
/// **撤収側にだけ無かった**——撤収も特権付きのDACL書換であり、対象パスは台帳から来る。
#[test]
fn a_forced_revoke_on_a_forbidden_path_does_not_get_the_privilege() {
    let bogus = windir().join("this-path-should-not-exist-harness-bug119-test");
    assert!(
        !super::forced_revoke_may_use_privilege(&bogus, true),
        "ゲートが拒否するパスで`SeRestorePrivilege`を有効化している"
    );
    // `%SystemRoot%`配下も同じ（ゲートの拒否対象）。
    assert!(!super::forced_revoke_may_use_privilege(&windir(), true));
}

/// **[BUG-119 案C] 許可側（対）。** ゲートを通るパスでは従来どおり特権を使う。
///
/// **この対が無いと「常に false」でも禁止側が通る**——それは
/// 「特権で付与したACEを特権無しで剥がそうとして失敗し続ける」形になる（`B-35`）。
#[test]
fn a_forced_revoke_on_an_allowed_path_still_gets_the_privilege() {
    let dir = std::env::temp_dir();
    if !dir.exists() {
        return;
    }
    assert!(super::forced_revoke_may_use_privilege(&dir, true));
}

/// **forcedでないエントリは、パスが何であれ特権を要求しない。**
#[test]
fn a_non_forced_revoke_never_asks_for_the_privilege() {
    let dir = std::env::temp_dir();
    assert!(!super::forced_revoke_may_use_privilege(&dir, false));
    assert!(!super::forced_revoke_may_use_privilege(
        Path::new("C:\\"),
        false
    ));
}
