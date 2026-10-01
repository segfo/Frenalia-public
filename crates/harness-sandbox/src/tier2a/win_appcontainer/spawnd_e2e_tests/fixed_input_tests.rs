//! 固定辺の起動直前の検査（`spawnd::fixed_inputs`）の受け入れ——**対で3本**。
//!
//! 固定辺（argvがリテラルでcwdを宣言した遷移）は、固定したファイルを呼び出し元が書き換えられない
//! ことが前提である（`plans/DESIGN-MAC.md` §19.1）。読み込み時の検査は**綴りで**比べるので、
//! 宣言の外で書込を許した場所や、別名（ジャンクション等）を挟んだパスを見逃す。Daemonは起こす直前に
//! 呼び出し元のトークンで実体のアクセス制御リストを評価して、それを補う。
//!
//! | # | 固定したプログラムの置き場所 | 読み込み時の検査 | 期待 |
//! |---|---|---|---|
//! | 1 | 宣言を通さず、呼び出し元へ**直接**書込ACEを付けたディレクトリ | 通る（宣言にもワークスペースにも無い） | **断る**（`fixed_input_writable`） |
//! | 2 | ワークスペースの**外のジャンクション**越しに、ワークスペースの中 | 通る（綴りはワークスペースの外） | **断る** |
//! | 3 | 2と同じ形のジャンクション越しに、呼び出し元が何の権利も持たない場所 | 通る | **起きる** |
//! | 4 | ワークスペースの中のプログラムへ、外から張った**ハードリンク**の名前 | 通る（パスをどう解決しても外） | **断る** |
//!
//! **3が無いと「固定辺を全部断る」実装で緑になる**（`B-35`）。2と3は、ジャンクションの先が
//! 書けるかどうか**だけ**が違う。3が起きることは、2の拒否が「判定できなかったので断った」
//! （同じ拒否理由になる）ではなく、実際に書込権を見つけた結果であることの裏付けにもなる
//! ——同じ形の鎖を、3では判定し切れているからである。
//!
//! **4はパスの解決では原理的に見つからない別名である**——1つのファイル実体に付いた名前はどれも
//! 対等で、`GetFinalPathNameByHandleW`は開くのに使った名前を返す。アクセス制御リストは実体に
//! 1つだけあるので、実体に聞く検査はどの名前で開いても同じ答えを返す。
//!
//! 起こすのは`tier2a_proc_probe.exe`の写し（`gen.exe`）で、`--emit`は常に終了コード0を返す。

use super::transition_acceptance_tests::{ask_daemon_as_a_hook, policy_with_fixed_edge};
use super::*;

/// プローブの写しを`dir\gen.exe`として置き、そのパスを返す。
fn place_probe(dir: &std::path::Path) -> std::path::PathBuf {
    let probe = super::super::mac_spike_tests::probe_exe();
    let target = dir.join("gen.exe");
    std::fs::copy(&probe, &target).expect("copy the probe as the fixed program");
    target
}

/// ジャンクション（ディレクトリ用のリンク）を作る。
fn junction(link: &std::path::Path, target: &std::path::Path) {
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run mklink");
    assert!(
        status.success(),
        "mklink /J {} {}",
        link.display(),
        target.display()
    );
}

/// `exe`を固定したプログラムとする固定辺を宣言し、呼び出し元にその辺を頼ませる。
/// 戻り値はプローブ（呼び出し元役）の報告。`prepare`は宣言の後・要求の前に呼ばれる
/// ——ファイルやACEの用意には、セッションのpackage SIDとワークスペースが要るため。
fn ask_for_fixed_edge(
    label: &str,
    exe: &std::path::Path,
    prepare: impl FnOnce(&OwnedContainerSid, &std::path::Path),
) -> String {
    let exe_str = exe.to_string_lossy().into_owned();
    let command_line = format!("\"{exe_str}\" --emit fixed-input");
    let declared_exe = exe_str.clone();
    let declared_line = command_line.clone();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        label,
        ChildProcessPolicy::Unrestricted,
        |workspace| policy_with_fixed_edge(&declared_exe, &declared_line, workspace),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    prepare(&profile, &workspace);
    let captured = workspace.join("fixed-input-stdout.txt");
    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &exe_str,
        &command_line,
        &captured,
        "not_needed",
        false,
    );
    drop(case);
    out
}

fn assert_refused(out: &str, what: &str) {
    assert_eq!(
        reply_kind(out).as_deref(),
        Some("denied"),
        "{what}: the fixed program is writable by the caller, so the daemon must refuse: {out}"
    );
    assert_eq!(
        deny_reason(out).as_deref(),
        Some("fixed_input_writable"),
        "{what}: the refusal must name the fixed-input check (not a declaration problem): {out}"
    );
    assert_eq!(
        report_field(out, "child_exit_code"),
        None,
        "{what}: a refused child must not have run: {out}"
    );
}

/// **1（禁止側）**: 宣言を通さず、呼び出し元のpackage SIDへ直接書込ACEを付けた場所。
///
/// 読み込み時の検査はこの場所を知らない（宣言にもワークスペースにも`writable_outside_policy`にも無い）。
/// 実体のアクセス制御リストを見る起動直前の検査だけが捕まえる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_fixed_program_in_a_place_the_caller_can_write_outside_any_declaration_is_refused() {
    let tools = TestDirGuard::create("fixedin-acl");
    let exe = tools.path().join("gen.exe");
    let tools_path = tools.path().to_path_buf();
    let out = ask_for_fixed_edge("fixedin-acl-case", &exe, |profile, _workspace| {
        super::super::grant_ace_inheritable_access(
            &tools_path,
            profile.as_psid(),
            crate::FsAccess::ReadWriteExec,
        )
        .expect("grant the caller write access to the tools dir");
        // 台帳へ載せておけば、テストがパニックしても次回起動のGCが剥がす。
        crate::tier2a::session_profile::record_granted_path(&tools_path);
        // 付与の**後**に置くので、プローブの写しはディレクトリのACEを継承する。
        place_probe(&tools_path);
    });
    // **剥がしてから記録を落とす**（`cow_containment_tests`の同じ後始末と同じ順序。BUG-101）。
    let sid = crate::tier2a::win_appcontainer::session_sid();
    if super::super::revoke_ace(tools.path(), sid.as_psid()).is_ok() {
        crate::tier2a::session_profile::forget_granted_paths(&[tools.path().to_path_buf()]);
    }
    assert_refused(&out, "an ACE granted outside any declaration");
}

/// **2（禁止側）**: ワークスペースの外のジャンクション越しに、ワークスペースの中のプログラム。
///
/// 宣言の綴りはワークスペースの外なので、**読み込み時の検査は通る**——これが別名の穴である。
/// 実体はワークスペースの中で、呼び出し元はworkspace capabilityで書ける。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_fixed_program_reached_through_a_junction_into_the_workspace_is_refused() {
    let links = TestDirGuard::create("fixedin-junction-ws");
    let link = links.path().join("link");
    let exe = link.join("gen.exe");
    let link_for_prepare = link.clone();
    let out = ask_for_fixed_edge("fixedin-junction-ws-case", &exe, |_profile, workspace| {
        let tools = workspace.join("tools");
        std::fs::create_dir_all(&tools).expect("tools dir in the workspace");
        place_probe(&tools);
        junction(&link_for_prepare, &tools);
    });
    assert_refused(&out, "a junction from outside the workspace into it");
}

/// **3（許可側。2の対）**: 同じ形のジャンクション越しに、呼び出し元が何の権利も持たない場所。
///
/// これが起きなければ、上の2本は「固定辺を全部断る」実装でも緑になる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_fixed_program_reached_through_a_junction_into_a_place_the_caller_cannot_write_runs() {
    let links = TestDirGuard::create("fixedin-junction-ro");
    let target = TestDirGuard::create("fixedin-target-ro");
    let link = links.path().join("link");
    let exe = link.join("gen.exe");
    let link_for_prepare = link.clone();
    let target_path = target.path().to_path_buf();
    let out = ask_for_fixed_edge("fixedin-junction-ro-case", &exe, |_profile, _workspace| {
        place_probe(&target_path);
        junction(&link_for_prepare, &target_path);
    });
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("spawned"),
        "the junction points somewhere the caller cannot write, so the fixed edge must run: {out}"
    );
    assert_eq!(
        report_field(&out, "child_exit_code").and_then(|v| v.as_u64()),
        Some(0),
        "the fixed program must actually have run: {out}"
    );
}

/// **4（禁止側）**: ワークスペースの中のプログラムへ、ワークスペースの外から**ハードリンク**を張った名前。
///
/// 宣言の綴りも、その綴りを解決した先もワークスペースの外である——ハードリンクはどの名前も対等で、
/// 「本当の場所」が無い。ファイル実体のアクセス制御リストはワークスペースで作られたときに継承した
/// ものなので、呼び出し元はworkspace capabilityでこの名前からも書ける。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_fixed_program_hard_linked_from_inside_the_workspace_is_refused() {
    let outside = TestDirGuard::create("fixedin-hardlink");
    let exe = outside.path().join("gen.exe");
    let exe_for_prepare = exe.clone();
    let out = ask_for_fixed_edge("fixedin-hardlink-case", &exe, |_profile, workspace| {
        let tools = workspace.join("tools");
        std::fs::create_dir_all(&tools).expect("tools dir in the workspace");
        let inside = place_probe(&tools);
        std::fs::hard_link(&inside, &exe_for_prepare)
            .expect("hard link the workspace program from outside the workspace");
    });
    assert_refused(&out, "a hard link to a program inside the workspace");
}
