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

use super::{pass2_lists, split_granted};

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
