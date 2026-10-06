//! `fixed_inputs`の単体テスト。
//!
//! - 規則（[`verdict`]）は**OSを呼ばない**ので、権利の組み合わせを直接与えて固定する
//! - 鎖の組み立てと実際の判定は、**このテストプロセス自身のトークン**で測る（昇格もAppContainerも要らない）
//!
//! AppContainerのトークンで`AccessCheck`が実際と一致することは、`win_appcontainer::mac_spike_tests`の
//! `access_check_with_an_appcontainer_token_matches_what_the_child_can_open`が固定している。

use std::path::{Path, PathBuf};

use windows::Win32::System::Threading::GetCurrentProcess;

use super::*;

const ADD_FILE: u32 = FILE_WRITE_DATA;
const ADD_SUBDIRECTORY: u32 = FILE_APPEND_DATA;

fn own_token() -> CallerToken {
    CallerToken::from_process(unsafe { GetCurrentProcess() }, std::process::id())
        .expect("duplicate this test process's token")
}

/// 葉がファイルで、`depth`段の親を持つ鎖（リンク無し）。
fn file_chain(depth: usize) -> Chain {
    Chain {
        label: "test",
        links: (0..=depth)
            .map(|i| ChainLink {
                path: PathBuf::from(format!("level-{i}")),
                follow_last_link: true,
                is_link: false,
            })
            .collect(),
        leaf_is_the_fixed_path: true,
        leaf_is_dir: false,
    }
}

// --- 規則（権利の組み合わせ） ------------------------------------------------

/// 何も持たなければ通る（許可側の基準）。
#[test]
fn no_rights_anywhere_is_accepted() {
    assert_eq!(verdict(&file_chain(3), &[0, 0, 0, 0]), None);
}

/// 葉のファイルの中身を書ける → 断る。
#[test]
fn writing_the_fixed_file_itself_is_refused() {
    let hit = verdict(&file_chain(2), &[FILE_WRITE_DATA, 0, 0]).expect("refused");
    assert_eq!(hit.0, 0);
}

/// どの段でも、アクセス制御リストか所有者を書き換えられる → 断る（自分に何でも与え直せる）。
#[test]
fn rewriting_an_acl_anywhere_on_the_chain_is_refused() {
    for i in 0..3 {
        let mut granted = [0u32; 3];
        granted[i] = WRITE_DAC;
        assert_eq!(verdict(&file_chain(2), &granted).map(|h| h.0), Some(i));
    }
}

/// 直接の親にファイルを足せる → 断る。実行ファイルの隣のDLL・スクリプトの隣のモジュールは先に読まれる。
#[test]
fn placing_files_next_to_the_fixed_file_is_refused() {
    let hit = verdict(&file_chain(2), &[0, ADD_FILE, 0]).expect("refused");
    assert_eq!(hit.0, 1);
}

/// **上の段で「作れる」だけでは断らない**（対）。既に在る名前は取れないので差し替えにならない。
///
/// これが無いと、普通のユーザーのトークンが`C:\`に持つ「フォルダの作成」だけで
/// `C:\Windows\System32\cmd.exe`の固定辺まで断ることになる（実際にそう判定した版があった）。
#[test]
fn creating_entries_higher_up_without_removing_one_is_accepted() {
    assert_eq!(verdict(&file_chain(3), &[0, 0, 0, ADD_SUBDIRECTORY]), None);
}

/// 上の段で「消せる」**かつ**「作れる」 → 断る（消して同じ名前で作り直せる）。
/// 消す権利は子の`DELETE`でも親の`FILE_DELETE_CHILD`でもよい。
#[test]
fn removing_and_recreating_an_entry_higher_up_is_refused() {
    let via_child_delete = verdict(&file_chain(3), &[0, 0, DELETE, ADD_SUBDIRECTORY]);
    assert_eq!(via_child_delete.map(|h| h.0), Some(3));
    let via_parent_delete_child =
        verdict(&file_chain(3), &[0, 0, 0, FILE_DELETE_CHILD | ADD_SUBDIRECTORY]);
    assert_eq!(via_parent_delete_child.map(|h| h.0), Some(3));
}

/// 消せても作れなければ断らない（対）。置き直せないので中身は決められない。
#[test]
fn removing_without_recreating_is_accepted() {
    assert_eq!(verdict(&file_chain(3), &[0, 0, DELETE, FILE_DELETE_CHILD]), None);
}

/// 書いた綴りの鎖のリンクは、向け先を変えられる（`FILE_WRITE_ATTRIBUTES`等）だけで断る。
/// 同じ権利でもリンクでない親なら断らない（対）。
#[test]
fn a_link_that_can_be_retargeted_is_refused_but_a_plain_directory_is_not() {
    let mut chain = file_chain(2);
    assert_eq!(verdict(&chain, &[0, 0, FILE_WRITE_ATTRIBUTES]), None);
    chain.links[2].is_link = true;
    assert_eq!(
        verdict(&chain, &[0, 0, FILE_WRITE_ATTRIBUTES]).map(|h| h.0),
        Some(2)
    );
}

/// まだ無いパスは、一番深い祖先に「作れる」なら断る。消せるだけなら断らない（対）。
#[test]
fn a_missing_path_is_refused_only_if_the_caller_can_create_it() {
    let mut chain = file_chain(2);
    chain.leaf_is_the_fixed_path = false;
    chain.leaf_is_dir = true;
    assert_eq!(verdict(&chain, &[ADD_FILE, 0, 0]).map(|h| h.0), Some(0));
    assert_eq!(verdict(&chain, &[FILE_DELETE_CHILD, 0, 0]), None);
}

// --- 鎖の組み立てと実際の判定（このプロセスのトークン） ------------------------

/// ジャンクション（ディレクトリ用のリンク）を作る。**昇格は要らない**（シンボリックリンクと違う）。
fn junction(link: &Path, target: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run mklink");
    assert!(status.success(), "mklink /J {} {}", link.display(), target.display());
}

/// **禁止側**: 自分が作ったファイルは、自分のトークンで書き換えられる。
#[test]
fn a_file_this_process_created_is_rewritable_by_this_process() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("gen.exe");
    std::fs::write(&file, b"x").expect("write");
    let reason = rewritable(&file, &own_token()).expect("judge");
    assert!(reason.is_some(), "a file we own must be reported as rewritable");
}

/// **許可側（対）**: システムの実行ファイルは、非管理者のトークンでは書き換えられない。
/// 昇格して走らせると`Administrators`の権利が乗るので測れない（Tier3の同型テストと同じ扱い）。
#[test]
fn a_system_executable_is_not_rewritable_by_a_non_admin() {
    if crate::tier2a::privhelper::is_elevated() {
        eprintln!("skipped: elevated tokens can modify system directories");
        return;
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let cmd = PathBuf::from(system_root).join("System32").join("cmd.exe");
    let reason = rewritable(&cmd, &own_token()).expect("judge");
    assert_eq!(reason, None, "cmd.exe must not be rewritable by a non-admin");
}

/// [P5.4d] **禁止側**: 実行ファイルが書けない場所にあっても、**作業ディレクトリ**を呼び出し元が書けるなら断る
/// （決定66の追記の束「作業ディレクトリ: 呼び出し元が書ける場所なら断る」）。理由は作業ディレクトリを名指す。
///
/// 許可側（対）は[`a_strict_edge_whose_program_and_cwd_the_caller_cannot_write_is_not_refused`]で、違うのは
/// 作業ディレクトリだけ。昇格して走らせると`Administrators`の権利でシステムの場所も書けるので測れない。
#[test]
fn a_strict_edge_is_refused_when_the_caller_can_write_its_cwd() {
    if crate::tier2a::privhelper::is_elevated() {
        eprintln!("skipped: elevated tokens can modify system directories");
        return;
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let cmd = format!(r"{system_root}\System32\cmd.exe");
    let cwd = tempfile::tempdir().expect("tempdir");
    let cwd_str = cwd.path().to_string_lossy().into_owned();
    let reason = refusal(
        unsafe { GetCurrentProcess() },
        std::process::id(),
        &cmd,
        &format!("\"{cmd}\" /c ver"),
        &cwd_str,
    )
    .expect("a cwd this process created is writable by this process, so the edge must be refused");
    assert!(
        reason.contains(&cwd_str),
        "the reason should name the working directory: {reason}"
    );
}

/// [P5.4d] **許可側（上の対）**: 実行ファイルも作業ディレクトリも書けない場所なら断らない。
#[test]
fn a_strict_edge_whose_program_and_cwd_the_caller_cannot_write_is_not_refused() {
    if crate::tier2a::privhelper::is_elevated() {
        eprintln!("skipped: elevated tokens can modify system directories");
        return;
    }
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let cmd = format!(r"{system_root}\System32\cmd.exe");
    let cwd = format!(r"{system_root}\System32");
    assert_eq!(
        refusal(
            unsafe { GetCurrentProcess() },
            std::process::id(),
            &cmd,
            &format!("\"{cmd}\" /c ver"),
            &cwd,
        ),
        None,
        "neither cmd.exe nor System32 is writable by a non-admin"
    );
}

/// ジャンクション越しに書かれたパスでは、**リンクそのもの**（書いた綴りの鎖）と、
/// **リンク先の本当の親**（実体の鎖）の両方が判定の対象に入る。後者は書いた綴りの鎖に現れない。
#[test]
fn a_junction_puts_both_the_link_itself_and_the_real_parent_under_check() {
    let root = tempfile::tempdir().expect("tempdir");
    let real = root.path().join("real");
    std::fs::create_dir(&real).expect("real dir");
    std::fs::write(real.join("gen.exe"), b"x").expect("write");
    let link = root.path().join("link");
    junction(&link, &real);

    let chains = chains(&link.join("gen.exe")).expect("chains");
    assert_eq!(chains.len(), 2, "{chains:#?}");
    let written = &chains[0];
    let link_itself = written
        .links
        .iter()
        .find(|l| l.path == link)
        .unwrap_or_else(|| panic!("the junction must be on the written chain: {written:#?}"));
    assert!(link_itself.is_link && !link_itself.follow_last_link, "{link_itself:?}");

    let real_canonical = std::fs::canonicalize(&real).expect("canonical real dir");
    assert!(
        chains[1].links.iter().any(|l| l.path == real_canonical && l.follow_last_link),
        "the junction's real target must be on the resolved chain: {:#?}",
        chains[1]
    );
    assert!(written.leaf_is_the_fixed_path && !written.leaf_is_dir);
}

/// まだ無いパスは、**実在する一番深い祖先を葉にする**。自分の一時ディレクトリには作れるので断る。
#[test]
fn a_missing_path_is_judged_from_its_deepest_existing_ancestor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("not-yet").join("out.txt");
    let chains = chains(&missing).expect("chains");
    assert_eq!(chains[0].links[0].path, dir.path(), "{chains:#?}");
    assert!(!chains[0].leaf_is_the_fixed_path);
    assert!(
        rewritable(&missing, &own_token()).expect("judge").is_some(),
        "we can create files in our own tempdir"
    );
}

/// `..`は文字の上で先に解決する（`CreateProcessW`もそう開く）。解決しないと、
/// `\\?\`付きのパスは`..`をそのまま名前として探して開けず、判定できずに断ることになる。
#[test]
fn dot_dot_is_resolved_before_the_chain_is_built() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a")).expect("a");
    std::fs::write(dir.path().join("b.exe"), b"x").expect("b");
    let spelled = dir.path().join("a").join("..").join("b.exe");
    let chains = chains(&spelled).expect("chains");
    assert!(
        chains
            .iter()
            .flat_map(|c| &c.links)
            .all(|l| !l.path.to_string_lossy().contains("..")),
        "`..` must not reach CreateFileW: {chains:#?}"
    );
    assert!(rewritable(&spelled, &own_token()).expect("judge").is_some());
}
