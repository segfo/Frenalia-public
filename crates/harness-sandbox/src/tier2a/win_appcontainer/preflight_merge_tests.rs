//! [#30] 付与処理が「同じパスに複数の級」を扱う部分のテスト（純粋関数だけ。ACLには触らない）。
//!
//! `harness.exe`が入口とドメインの宣言をまとめて渡すようになったので、同じパスに別の級が並ぶ。
//! ここが守っているのは2つ——**昇格の結果をパスだけで照合しない**ことと、**CoWの降格で同じ宛先に
//! なった2行を1行に畳む**こと。

use std::path::PathBuf;

use harness_policy::GrantScope;

use super::*;
use crate::tier2a::privhelper::FsAllowGrant;

fn grant(path: &str, access: FsAccess) -> FsAllowGrant {
    FsAllowGrant {
        path: PathBuf::from(path),
        access,
        forced: false,
        scope: GrantScope::Object,
        secret_hex: "00".to_string(),
    }
}

fn fp(path: &str, access: FsAccess, scope: GrantScope, forced: bool) -> FsPassthrough {
    FsPassthrough {
        path: PathBuf::from(path),
        access,
        forced,
        scope,
    }
}

/// **同じパスの別の級の結果を、この要求の結果として読まない。**
/// 対の側として、同じ級なら一致する（`B-35`）。
#[test]
fn an_elevation_row_matches_only_its_own_access_class() {
    let read = grant(r"C:\data", FsAccess::Read);
    let write = grant(r"C:\data", FsAccess::ReadWrite);
    let row_path = PathBuf::from(r"C:\data");
    let read_row = Some("read".to_string());

    assert!(elevation_row_matches(&row_path, &read_row, &read));
    assert!(
        !elevation_row_matches(&row_path, &read_row, &write),
        "the read row must not be taken as the result of the read_write request"
    );
    assert!(!elevation_row_matches(
        &PathBuf::from(r"C:\other"),
        &read_row,
        &read
    ));
}

/// 級を返さない旧ヘルパーの応答（`None`）は、パスだけで照合する（同じパスに1つの級なら同じ結果）。
#[test]
fn a_row_without_an_access_class_falls_back_to_the_path() {
    let read = grant(r"C:\data", FsAccess::Read);
    assert!(elevation_row_matches(&PathBuf::from(r"C:\data"), &None, &read));
}

/// 級の列が行の列と同じ長さなら組にし、**長さが合わなければ級を捨てる**（ずれた組を作らない）。
#[test]
fn access_classes_are_attached_only_when_the_lengths_agree() {
    let rows = vec![PathBuf::from("a"), PathBuf::from("b")];
    let zipped = zip_access(rows.clone(), vec!["read".to_string(), "read_write".to_string()]);
    assert_eq!(zipped[1].1.as_deref(), Some("read_write"));

    let shorter = zip_access(rows, vec!["read".to_string()]);
    assert!(
        shorter.iter().all(|(_, access)| access.is_none()),
        "a misaligned column must not lend one row's class to another"
    );
}

/// **CoWで降格した結果、同じ（パス, 級）になった2行は1行に畳む。** 範囲は再帰が勝ち、
/// 「書込を要求したか」と`forced`はOR。
#[test]
fn rows_that_collapse_to_the_same_class_are_merged() {
    let merged = dedupe_resolved(vec![
        (fp(r"C:\data", FsAccess::Read, GrantScope::Object, false), false),
        (fp(r"C:\data", FsAccess::Read, GrantScope::Recursive, true), true),
    ]);
    assert_eq!(merged.len(), 1);
    let (row, requested_rw) = &merged[0];
    assert_eq!(row.scope, GrantScope::Recursive);
    assert!(row.forced);
    assert!(*requested_rw);
}

/// 対の側: **級が違えば別の行のまま**（宛先SIDが違うので両方要る）。
#[test]
fn rows_with_different_classes_stay_separate() {
    let kept = dedupe_resolved(vec![
        (fp(r"C:\data", FsAccess::Read, GrantScope::Object, false), false),
        (fp(r"C:\data", FsAccess::ReadWrite, GrantScope::Object, false), true),
    ]);
    assert_eq!(kept.len(), 2);
}

/// CoWでは書込を含む要求を読取（実行権があれば読取＋実行）へ下げ、直接書込モードでは変えない。
#[test]
fn the_effective_access_follows_the_write_mode() {
    use crate::shell_tier::effective_access;
    let cow = WorkspaceWriteMode::Cow {
        diff_layer_dir: PathBuf::from(r"C:\diff"),
    };
    assert_eq!(effective_access(FsAccess::ReadWrite, &cow), FsAccess::Read);
    assert_eq!(effective_access(FsAccess::ReadWriteExec, &cow), FsAccess::ReadExec);
    assert_eq!(effective_access(FsAccess::Read, &cow), FsAccess::Read);
    assert_eq!(effective_access(FsAccess::ReadExec, &cow), FsAccess::ReadExec);
    assert_eq!(
        effective_access(FsAccess::ReadWrite, &WorkspaceWriteMode::DirectRw),
        FsAccess::ReadWrite
    );
}
