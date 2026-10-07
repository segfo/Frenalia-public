//! `policy.json`のファイル宣言の承認台帳（D-112）のテスト。
//!
//! テンプレートは`harness_mcp::approval`のテストで、守る形は同じ——**承認したものだけが通り、
//! 鍵のどれか1つでも違えば通らず、読めない台帳は「何も承認されていない」**。

use std::path::Path;

use harness_config::FsAccess;
use harness_policy::generalize::SettingsKey;

use super::*;

fn store() -> (tempfile::TempDir, PolicyApprovalStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyApprovalStore::at_path(dir.path().join("policy-approval-ledger.json"));
    (dir, store)
}

fn decl<'a>(domain: &'a str, value: &'a str, access: FsAccess) -> DeclarationRef<'a> {
    DeclarationRef {
        domain,
        value,
        key: SettingsKey::from_access(access),
    }
}

/// [決定69(2)] 通信の宣言の鍵（`net.allow_domains`の値）。
fn net_decl<'a>(domain: &'a str, value: &'a str) -> DeclarationRef<'a> {
    DeclarationRef {
        domain,
        value,
        key: SettingsKey::NetAllowDomains,
    }
}

const WS: &str = r"C:\ws";

#[test]
fn an_unapproved_declaration_is_not_approved() {
    let (_dir, store) = store();
    assert!(!store
        .load()
        .is_approved(Path::new(WS), decl("cargo", "C:/x/**", FsAccess::Read)));
}

#[test]
fn approving_then_loading_recognises_the_same_declaration() {
    let (_dir, store) = store();
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    let not_recorded = store.approve(Path::new(WS), &[d]);
    assert!(not_recorded.is_empty(), "{not_recorded:?}");
    assert!(store.load().is_approved(Path::new(WS), d));
}

/// **鍵の4つのどれか1つでも違えば通らない。** 1つでも緩むと、同梱された宣言が
/// 承認済みの宣言の承認を借りられる。
#[test]
fn every_part_of_the_key_must_match() {
    let (_dir, store) = store();
    store.approve(Path::new(WS), &[decl("cargo", "C:/x/**", FsAccess::Read)]);
    let ledger = store.load();

    assert!(
        !ledger.is_approved(Path::new(WS), decl("npm", "C:/x/**", FsAccess::Read)),
        "another domain must not inherit the approval (a different child holds it)"
    );
    assert!(
        !ledger.is_approved(Path::new(WS), decl("cargo", "C:/x/**", FsAccess::ReadWrite)),
        "a wider access must not inherit the approval"
    );
    assert!(
        !ledger.is_approved(Path::new(WS), decl("cargo", "C:/y/**", FsAccess::Read)),
        "another value must not inherit the approval"
    );
    assert!(
        !ledger.is_approved(Path::new(r"C:\other"), decl("cargo", "C:/x/**", FsAccess::Read)),
        "another workspace must not inherit the approval"
    );
    assert!(
        !ledger.is_approved(Path::new(WS), decl("cargo", r"C:\x\**", FsAccess::Read)),
        "a respelled value is a different value (it falls on the not-granted side)"
    );
}

/// **書く側と読む側でワークスペースの綴りが違っても同じ鍵になる。** エディタは正規化した形を、
/// `harness.exe`はユーザーが渡した形を持っているので、ここがずれると全宣言が未承認になる。
#[test]
fn the_workspace_key_ignores_case_separators_and_the_verbatim_prefix() {
    let ws = tempfile::tempdir().unwrap();
    let canonical = ws.path().canonicalize().unwrap();
    let (_dir, store) = store();
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    store.approve(&canonical, &[d]);

    let plain = ws.path().to_string_lossy().to_string();
    for spelling in [
        plain.clone(),
        plain.to_uppercase(),
        plain.replace('\\', "/"),
        canonical.to_string_lossy().to_string(),
    ] {
        assert!(
            store.load().is_approved(Path::new(&spelling), d),
            "the same workspace spelled as {spelling:?} must find the approval"
        );
    }
}

#[test]
fn re_approving_replaces_rather_than_appends() {
    let (_dir, store) = store();
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    store.approve(Path::new(WS), &[d]);
    store.approve(Path::new(WS), &[d]);
    assert_eq!(store.load().approvals.len(), 1);
}

#[test]
fn revoke_removes_only_the_named_declarations() {
    let (_dir, store) = store();
    let keep = decl("cargo", "C:/keep/**", FsAccess::Read);
    let drop = decl("cargo", "C:/drop/**", FsAccess::Read);
    store.approve(Path::new(WS), &[keep, drop]);

    let left = store.revoke(Path::new(WS), &[drop]);
    assert!(left.is_empty(), "{left:?}");
    let ledger = store.load();
    assert!(!ledger.is_approved(Path::new(WS), drop));
    assert!(
        ledger.is_approved(Path::new(WS), keep),
        "revoking one declaration must not take the others with it"
    );
}

/// 古い版（または版の欄が無い）承認は、値が一致していても通さない。
#[test]
fn an_approval_from_another_format_is_ignored() {
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    for stale in [None, Some(APPROVAL_FORMAT_VERSION + 1)] {
        let ledger = PolicyApprovalLedger {
            approvals: vec![DeclarationApproval {
                workspace: approval_workspace_key(Path::new(WS)),
                domain: "cargo".to_string(),
                key: SettingsKey::FsRead,
                value: "C:/x/**".to_string(),
                approved_at_unix_secs: 0,
                format_version: stale,
            }],
        };
        assert!(
            !ledger.is_approved(Path::new(WS), d),
            "format {stale:?} must not be accepted"
        );
    }
}

/// **対の側**（`B-35`）: 現行の版で記録した承認は通る（上のテストが「常に偽」でも通らないように）。
#[test]
fn an_approval_in_the_current_format_is_accepted() {
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    let ledger = PolicyApprovalLedger {
        approvals: vec![DeclarationApproval {
            workspace: approval_workspace_key(Path::new(WS)),
            domain: "cargo".to_string(),
            key: SettingsKey::FsRead,
            value: "C:/x/**".to_string(),
            approved_at_unix_secs: 0,
            format_version: Some(APPROVAL_FORMAT_VERSION),
        }],
    };
    assert!(ledger.is_approved(Path::new(WS), d));
}

/// 台帳が壊れている／無いときは**何も承認されていない**（fail-closed）。
#[test]
fn a_corrupt_ledger_reads_as_no_approvals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy-approval-ledger.json");
    std::fs::write(&path, "{ this is not json").unwrap();
    let store = PolicyApprovalStore::at_path(path);
    assert!(store.load().approvals.is_empty());
    assert!(!store
        .load()
        .is_approved(Path::new(WS), decl("cargo", "C:/x/**", FsAccess::Read)));
}

/// **書けなかった承認を「書けた」と言わない。** 置き場が書けない（ここでは置き場の親が
/// ファイル）とき、`approve`は記録できなかった宣言をそのまま返す。
#[test]
fn approving_into_an_unwritable_place_reports_what_was_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_dir = dir.path().join("file");
    std::fs::write(&not_a_dir, "x").unwrap();
    let store = PolicyApprovalStore::at_path(not_a_dir.join("policy-approval-ledger.json"));
    let d = decl("cargo", "C:/x/**", FsAccess::Read);
    assert_eq!(store.approve(Path::new(WS), &[d]), vec![d]);
}

/// 台帳の名前は保護一覧に登録してある（未登録だと`Ledger::in_config_dir`がその場で落ちる）。
#[test]
fn the_ledger_is_registered_in_the_config_dir_list() {
    assert!(harness_grant_ledger::is_registered_config_dir_ledger(
        "policy-approval-ledger.json"
    ));
}

/// [決定69(2)] **通信の宣言も承認の対象である。** 台帳に無い通信の宣言は効かない
/// ——`policy.json`はリポジトリに同梱され得るので、ファイルの宣言と同じ理由で承認が要る。
#[test]
fn a_net_declaration_can_be_approved_and_matched() {
    let (_dir, store) = store();
    let d = net_decl("ssh", "example.com");
    assert!(
        !store.load().is_approved(Path::new(WS), d),
        "まだ承認していない通信の宣言が通ってはならない"
    );
    let not_recorded = store.approve(Path::new(WS), &[d]);
    assert!(not_recorded.is_empty(), "{not_recorded:?}");
    assert!(store.load().is_approved(Path::new(WS), d));
}

/// **禁止側の対**: 別のドメインは通信の承認を引き継がない（その宛先へ出られる子が違う）。
#[test]
fn a_net_declaration_of_another_domain_is_not_approved() {
    let (_dir, store) = store();
    store.approve(Path::new(WS), &[net_decl("ssh", "example.com")]);
    let ledger = store.load();
    assert!(!ledger.is_approved(Path::new(WS), net_decl("curl", "example.com")));
    assert!(!ledger.is_approved(Path::new(WS), net_decl("ssh", "other.example.net")));
}

/// **種類も鍵である。** 同じ値をファイルの宣言として承認しても、通信の宣言は未承認のまま
/// （逆も同じ）。混ざると、パスとして承認した値で外へ出られる。
#[test]
fn the_same_value_approved_as_a_file_declaration_does_not_approve_the_net_declaration() {
    let (_dir, fs_store) = store();
    fs_store.approve(Path::new(WS), &[decl("ssh", "example.com", FsAccess::Read)]);
    assert!(!fs_store
        .load()
        .is_approved(Path::new(WS), net_decl("ssh", "example.com")));

    let (_dir2, store2) = store();
    store2.approve(Path::new(WS), &[net_decl("ssh", "example.com")]);
    assert!(!store2
        .load()
        .is_approved(Path::new(WS), decl("ssh", "example.com", FsAccess::Read)));
}

/// 通信の宣言の承認も取り消せる（付与と撤収の対。`B-01`）。
#[test]
fn a_net_approval_can_be_revoked() {
    let (_dir, store) = store();
    let d = net_decl("ssh", "example.com");
    store.approve(Path::new(WS), &[d]);
    let left = store.revoke(Path::new(WS), &[d]);
    assert!(left.is_empty(), "{left:?}");
    assert!(!store.load().is_approved(Path::new(WS), d));
}

/// [決定69(2)] **形式の版は2である**（通信の宣言を鍵に入れたので上げた）。版1で記録した承認は、
/// ファイルの宣言のものも含めて通らない——D-112(g) と同じ扱いで、1回承認し直す。
#[test]
fn approvals_recorded_with_format_version_one_are_not_matched() {
    assert_eq!(APPROVAL_FORMAT_VERSION, 2);
    let ledger = PolicyApprovalLedger {
        approvals: vec![DeclarationApproval {
            workspace: approval_workspace_key(Path::new(WS)),
            domain: "cargo".to_string(),
            key: SettingsKey::FsRead,
            value: "C:/x/**".to_string(),
            approved_at_unix_secs: 0,
            format_version: Some(1),
        }],
    };
    assert!(!ledger.is_approved(Path::new(WS), decl("cargo", "C:/x/**", FsAccess::Read)));
}
