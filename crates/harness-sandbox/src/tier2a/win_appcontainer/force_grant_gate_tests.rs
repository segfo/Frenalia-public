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
